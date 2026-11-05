"""0.6 seek arithmetic reference and read/close state replay; old fd rules frozen."""
import re
import fd_protocol as old
from log_parser import Record,number
PREFIXES=old.PREFIXES
def decode(line):
 if not line.startswith('FD_SEEK '):return old.decode(line)
 fields={}
 for t in line[8:].split():
  m=re.fullmatch(r'([a-z_]+)=([^\s=]+)',t)
  if not m or m[1] in fields:raise ValueError('bad seek field')
  fields[m[1]]=m[2]
 if set(fields)!=set('fd offset whence returned pos_before pos_after submitted completed notified allocated freed pages'.split()):raise ValueError('seek fields')
 values={}
 for k,v in fields.items():
  if k in ('offset','returned'):
   if not re.fullmatch(r'-?(0|[1-9][0-9]*)',v) or len(v)>20 or not -(1<<63)<=int(v)<1<<63:raise ValueError('seek signed range')
   values[k]=int(v)
  else:values[k]=number(v)
 return Record('fd_seek',fields,values)
def ordered(rs):
 return old.ordered([r for r in rs if r.kind!='fd_seek'])
def inspect(rs,disk,lo,hi):
 if not any(r.kind=='fd_seek' for r in rs):return old.inspect(rs,disk,lo,hi)
 errors=[];info={'reads':[],'writes':[],'seeks':[]};cursor=0;opened=True;rn=wn=cn=0;explicit=0;eio=0
 def need(ok,msg):
  if not ok:raise ValueError(msg)
 try:
  need(ordered(rs),'seek group structure')
  spec,err=old.extent(bytes.fromhex(disk['header_hex']),disk['capacity_bytes'],disk['offset'],disk['filled']);need(err is None and spec is not None,'extent')
  start,length=spec;load,access,op,begin=[r.values for r in rs[:4]]
  need(load['root']==disk['loader']['root'] and load['phase']==4 and op['offset']==start and op['length']==length and op['cursor']==0 and op['live_pages']==14 and op['max_read']==1024 and op['sie']==op['submitted']==0 and op['fd']==3,'seek open')
  need(len({op['ring'],op['bounce'],load['root']})==3 and all(p%4096==0 and lo+4*4096<=p<hi for p in (op['ring'],op['bounce'])),'DMA')
  need(begin=={'phase':4,'pid':1,'input_valid':0},'begin')
  trace=[];last=b''
  for r in rs[4:-4]:
   v=r.values
   if r.kind=='fd_seek':
    base={0:0,1:cursor,2:length}.get(v['whence']);total=None if base is None else base+v['offset']
    ret=-9 if v['fd']!=3 or not opened else -22 if base is None else -75 if not -(1<<63)<=total<(1<<63) else -22 if total<0 else total
    need(v['pos_before']==cursor and v['returned']==ret,'seek arithmetic/return')
    if ret>=0:cursor=ret
    need(v['pos_after']==cursor and all(v[k]==0 for k in ('submitted','completed','notified','allocated','freed')) and v['pages']==(14 if opened else 12),'seek side effects')
    trace.append(['s',v['fd'],v['offset'],v['whence'],ret]);info['seeks'].append(v)
   elif r.kind=='fd_read':
    rn+=1;count=v['requested'];need(opened and v['seq']==rn and v['fd']==3 and v['pointer']==0x20000 and 0<count<=64 and v['pos_before']==cursor,'read identity')
    before=bytes.fromhex(v['before']);after=bytes.fromhex(v['after']);need(before==b'\xa5'*count and len(after)==count and v['prefix_bytes']==count,'read snapshot')
    n=min(count,max(0,length-cursor));fail=v['returned']==-5
    need(v['returned']==(-5 if fail else n),'read return')
    if n:
     dma=((start+cursor)%512+n+511)//512*512
     need(v['submitted']==v['completed']==v['notified']==1 and 1<=v['polls']<=1000000 and (v['status']==1 and 1<=v['used_len']<=dma+1 if fail else v['status']==0 and v['used_len']==dma+1),'completion')
    else:need(not fail and v['status']==255 and all(v[k]==0 for k in ('submitted','completed','notified','used_len','polls','ticks')),'beyond EOF I/O')
    if fail:eio+=1;need(after==before,'EIO buffer');trace.append(['e',count])
    else:
     need(after[n:]==before[n:],'tail overwritten');last=after[:n]
     if n:info['reads'].append({'offset':start+cursor,'length':n,'data_hex':last.hex()})
     cursor+=n;trace.append(['r',count,n])
    need(v['pos_after']==cursor,'read cursor')
   elif r.kind=='fd_write':
    wn+=1;need(v=={'seq':wn,'pid':1,'fd':1,'requested':len(last),'returned':len(last),'hex':last.hex()} and last,'read/write correlation');info['writes'].append(v['hex']);last=b''
   elif r.kind=='fd_close':
    cn+=1;explicit+=v['origin']=='explicit';need(v['seq']==cn and v['fd']==3 and opened and v['returned']==0 and v['cursor']==cursor and v['had_handle']==v['reset_confirmed']==1 and v['dma_freed']==2 and v['used_before']==14 and v['used_after']==12 and 1<=v['reset_polls']<=1000000,'close');opened=False
   else:raise ValueError('unexpected seek runtime event')
  cleanup,task,mem,end=[r.values for r in rs[-4:]]
  need(not opened and cleanup['closed']==1 and cleanup['reads']==rn and cleanup['cursor']==cursor and cleanup['used_after']==12 and cleanup['dma_freed']==(2 if cleanup['had_handle'] else 0) and cleanup['used_before']==(14 if cleanup['had_handle'] else 12),'cleanup')
  close_event=next(r.values for r in rs if r.kind=='fd_close')
  need(close_event['origin']==('exit' if cleanup['had_handle'] else 'explicit'),'close origin')
  need(task['state']==2 and task['runs']==rn+wn+len(info['seeks'])+explicit+1 and task['writes']==wn and task['bytes']==sum(len(bytes.fromhex(w)) for w in info['writes']) and all(task[k]==0 for k in ('timers','yields','efault','enosys','fault')),'task counters')
  need(end=={'phase':4,'remaining_pages':4},'end')
  info.update(outcome='executed',error=None,output_hex=''.join(info['writes']),exit_code=task['exit'],device_errors=eio,trace=trace,explicit_close=not bool(cleanup['had_handle']))
  return [],info
 except (ValueError,KeyError,TypeError) as e:return [str(e)],info
def validate_image(info,disk,image,expected,eio):
 if 'expected_error' in expected:return old.validate_image(info,disk,image,expected,eio)
 header=bytes.fromhex(disk.get('header_hex',''));payload=bytes.fromhex(disk.get('payload_hex',''))
 trace=info.get('trace',[]);clean=[t for t in trace if t[0]!='e']
 expected_trace=[['r',1,1]]
 # Independent acceptance profile for the fixed assembly, arithmetic is checked above.
 for off,wh,ret,read in [(100,0,100,(17,17)),(-10,1,107,(9,9)),(-5,2,2300,(16,5)),(10,2,2315,(8,0)),(-2315,1,0,(13,13)),(-1,0,-22,None),(0,3,-22,None),(-100,1,-22,None),(-(1<<63),0,-22,None),(-2306,2,-22,None),((1<<63)-1,0,(1<<63)-1,None),(1,1,-75,None),((1<<63)-1,2,-75,(8,0)),(-((1<<63)-1),1,0,None),(0,0,-9,None),(512,0,512,(23,23)),(-23,1,512,(23,23)),(0,2,2305,(1,0)),(0,0,0,None),(1,1,1,(7,7)),(0,0,0,(1,1))]:
  expected_trace.append(['s',9 if ret==-9 else 3,off,wh,ret])
  if read:expected_trace.append(['r',*read])
 if expected['explicit_close']:expected_trace.append(['s',3,0,0,-9])
 return {'seek_blob_binding':header==image[:512] and len(payload)==16384 and payload==image[disk.get('offset',0):disk.get('offset',0)+len(payload)] and disk.get('outcome')=='loaded',
 'seek_required_operations':clean==expected_trace,'seek_actual_bytes':bool(info.get('reads')) and all(bytes.fromhex(r['data_hex'])==image[r['offset']:r['offset']+r['length']] for r in info.get('reads',[])),
 'seek_exit':info.get('exit_code')==92 and info.get('explicit_close')==expected['explicit_close'],'seek_eio':info.get('device_errors')==int(eio) and (not eio or trace[:1]==[['e',1]]),
 'seek_output':info.get('output_hex')==''.join(r['data_hex'] for r in info.get('reads',[]))}
