"""Strict 0.5 extent transaction, controlled program and byte/position checks."""
import re
import struct
from log_parser import Record, number

PREFIXES=('FD_',)
SPECS=(
 ('open','phase pid fd offset length cursor ring bounce live_pages submitted max_read sie',''),
 ('exec_begin','phase pid input_valid',''),
 ('read','seq fd pointer requested returned pos_before pos_after submitted completed notified status used_len polls ticks prefix_bytes before after','before after'),
 ('write','seq pid fd requested returned hex','hex'),
 ('close','seq fd origin returned cursor had_handle reset_confirmed reset_polls reset_ticks dma_freed used_before used_after','origin'),
 ('cleanup','pid had_handle dma_freed used_before used_after cursor reads closed',''),
 ('exec_end','phase remaining_pages',''),
 ('reject','error user_freed remaining_pages','error'),
)

def decode(line):
    for kind,keys,strings in SPECS:
        prefix='FD_'+kind.upper()+' '
        if not line.startswith(prefix):continue
        fields={}
        for token in line[len(prefix):].split():
            m=re.fullmatch(r'([a-z_]+)=([^\s=]+)',token)
            if not m or m[1] in fields:raise ValueError('malformed/repeated fd field')
            fields[m[1]]=m[2]
        if set(fields)!=set(keys.split()):raise ValueError('missing/unexpected fd field')
        values={k:v if k in strings.split() else number(v,signed=k=='returned') for k,v in fields.items()}
        for k in ('before','after','hex'):
            if k in values and not (k!='hex' and values[k]=='-') and re.fullmatch(r'(?:[0-9a-f]{2}){1,1024}',values[k]) is None:
                raise ValueError('invalid fd byte snapshot')
        return Record('fd_'+kind,fields,values)
    return None

def extent(header,capacity,elf_start,elf_length):
    raw=header[64:96]
    if raw==bytes(32):return None,None
    magic,version,size,start,length=struct.unpack('<8sIIQQ',raw)
    if magic!=b'ALVXDATA':return None,'magic'
    if version!=1:return None,'version'
    if size!=32:return None,'header_size'
    if not 1<=length<=8192:return None,'length'
    if start+length>=1<<64:return None,'overflow'
    if start<512 or start+length>capacity:return None,'range'
    if start<elf_start+elf_length and elf_start<start+length:return None,'overlap'
    return (start,length),None

def ordered(records):
    """Establish keys before common permission/accounting cross-lookups."""
    if [r.kind for r in records]==['fd_reject']:return True
    if len(records)<8:return False
    if [r.kind for r in records[:4]]!=['load','access','fd_open','fd_exec_begin']:return False
    if [r.kind for r in records[-4:]]!=['fd_cleanup','task','memory','fd_exec_end']:return False
    for r in records[:2]+records[-3:-1]:
        if r.values.get('phase')!=4 or r.kind!='memory' and r.values.get('pid')!=1:return False
    return all(r.kind in ('fd_read','fd_close','fd_write') for r in records[4:-4])

def inspect(records,disk,pool_start,pool_end):
    at=0;info={'reads':[],'writes':[],'device_errors':0};read_seq=close_seq=write_seq=0
    cursor=0;live=14;open_handle=True;explicit_closes=0
    def require(ok,message):
        if not ok:raise ValueError(message)
    def take(kind):
        nonlocal at
        require(at<len(records) and records[at].kind==kind,'fd sequence expected '+kind)
        v=records[at].values;at+=1;return v
    def frame(p):return p%4096==0 and pool_start+4*4096<=p and p+4096<=pool_end
    def snapshot(value):return b'' if value=='-' else bytes.fromhex(value)
    try:
        header=bytes.fromhex(disk['header_hex'])
        spec,error=extent(header,disk['capacity_bytes'],disk['offset'],disk['filled'])
        require(spec is not None or error is not None,'fd events without extent descriptor')
        if error:
            require(take('fd_reject')=={'error':error,'user_freed':8,'remaining_pages':4} and at==len(records),'extent rejection executed or leaked user space')
            return [],{'outcome':'rejected','error':error,'reads':[],'writes':[]}
        start,length=spec
        require(length==2305,'unsupported controlled fd workload length')
        load=take('load');access=take('access')
        require(load['phase']==access['phase']==4 and load['pid']==access['pid']==1
                and load['root']==disk['loader']['root'] and load['pc']==0x10000 and load['stack']==0x40000000
                and load['elf_bytes']==disk['filled'],'fd loaded space handoff')
        op=take('fd_open')
        require(op['phase']==4 and op['pid']==1 and op['fd']==3 and op['offset']==start and op['length']==length
                and op['cursor']==op['submitted']==op['sie']==0 and op['max_read']==1024 and op['live_pages']==14
                and frame(op['ring']) and frame(op['bounce']) and len({op['ring'],op['bounce'],load['root']})==3,'fd open ownership/layout')
        require(take('fd_exec_begin')=={'phase':4,'pid':1,'input_valid':0},'fd execution before input release')
        elf=bytes.fromhex(disk['payload_hex']);phoff=struct.unpack_from('<Q',elf,32)[0]
        text_offset=next(struct.unpack_from('<Q',elf,phoff+i*56+8)[0] for i in range(struct.unpack_from('<H',elf,56)[0])
            if struct.unpack_from('<I',elf,phoff+i*56)[0]==1 and struct.unpack_from('<Q',elf,phoff+i*56+16)[0]==0x10000)
        buf=bytearray(b'\xa5'*4096)

        def read(fd,ptr,count,expected,old,allow_eio=False):
            nonlocal read_seq,cursor
            v=take('fd_read');read_seq+=1
            require(v['seq']==read_seq and v['fd']==fd and v['pointer']==ptr and v['requested']==count
                    and v['pos_before']==cursor,'fd read identity/address/cursor')
            before,after=snapshot(v['before']),snapshot(v['after'])
            require(before==old and v['prefix_bytes']==len(old) and len(after)==len(old),'fd caller snapshot/coverage')
            returned=v['returned']
            eio=allow_eio and returned==-5
            require(returned==expected or eio,'fd syscall return disagrees')
            io=returned>0 or eio
            if io:
                n=min(count,length-cursor)
                dma=((start+cursor)%512+n+511)//512*512
                require(v['submitted']==v['completed']==v['notified']==1 and 1<=v['polls']<=1_000_000,'fd real queue completion')
                require((v['status']==1 and 1<=v['used_len']<=dma+1) if eio else
                        (returned==n and v['status']==0 and v['used_len']==dma+1),'fd device status/used length')
            else:
                require(v['submitted']==v['completed']==v['notified']==v['used_len']==v['polls']==v['ticks']==0
                        and v['status']==255,'preflight/zero/EOF/closed read submitted I/O')
            if returned>0:
                require(open_handle and fd==3 and after[returned:]==before[returned:],'short read overwrote caller tail')
                data=after[:returned]
                info['reads'].append({'offset':start+cursor,'length':returned,'data_hex':data.hex()})
                cursor+=returned
            else:
                require(before==after,'rejected/EOF/EIO read changed caller buffer')
                data=b''
            require(v['pos_after']==cursor,'read advanced cursor on failure or wrong amount')
            if eio:info['device_errors']+=1
            return data,eio

        def close(fd,origin,success):
            nonlocal close_seq,live,open_handle,explicit_closes
            v=take('fd_close');close_seq+=1
            if origin=='explicit':explicit_closes+=1
            require(v['seq']==close_seq and v['fd']==fd and v['origin']==origin and v['returned']==(0 if success else -9)
                    and v['cursor']==cursor and v['used_before']==live
                    and v['had_handle']==v['reset_confirmed']==int(success) and v['dma_freed']==(2 if success else 0),'fd close identity/reset/resources')
            if success:
                require(open_handle and fd==3 and 1<=v['reset_polls']<=1_000_000,'fd double release/unconfirmed reset')
                live-=2;open_handle=False
            else:require(v['reset_polls']==v['reset_ticks']==0,'bad close touched device')
            require(v['used_after']==live,'fd close page leak')

        def write(data):
            nonlocal write_seq
            v=take('fd_write');write_seq+=1
            require(v=={'seq':write_seq,'pid':1,'fd':1,'requested':len(data),'returned':len(data),'hex':data.hex()},'user write not equal to immediately read bytes')
            info['writes'].append(data.hex())

        read(9,0x20000,16,-9,bytes(buf[:16]));close(9,'explicit',False)
        read(3,(1<<64)-1,0,0,b'')
        read(3,0x20000,1025,-22,b'')
        read(3,0x10000,16,-14,elf[text_offset:text_offset+16])
        read(3,0x80200000,16,-14,b'');read(3,0x30000,16,-14,b'')
        read(3,0x20ff8,16,-14,bytes(buf[-8:]));read(3,(1<<64)-8,16,-14,b'')
        data,eio=read(3,0x20000,13,13,bytes(buf[:13]),True)
        if eio:data,_=read(3,0x20000,13,13,bytes(buf[:13]))
        mode=data[0];buf[:13]=data;write(data)
        data,_=read(3,0x20000,1000,1000,bytes(buf[:1000]));buf[:1000]=data;write(data)
        data,_=read(3,0x3fffefe0,1024,1024,b'\xa5'*1024);write(data)
        buf[:1024]=b'\xa5'*1024
        data,_=read(3,0x20000,1024,268,bytes(buf[:1024]));buf[:268]=data;write(data)
        read(3,0x20000,1024,0,bytes(buf[:1024]));read(3,0x20000,1024,0,bytes(buf[:1024]))
        read(3,0x10000,0,0,b'')
        if mode==0:
            close(3,'explicit',True);close(3,'explicit',False)
            read(3,0x20000,1,-9,bytes(buf[:1]));read(3,(1<<64)-1,0,-9,b'')
        else:close(3,'exit',True)
        require(take('fd_cleanup')=={'pid':1,'had_handle':int(mode!=0),'dma_freed':2 if mode else 0,
                'used_before':14 if mode else 12,'used_after':12,'cursor':2305,'reads':read_seq,'closed':1},'fd exit cleanup missing/double free')
        task=take('task');mem=take('memory')
        require(task['phase']==mem['phase']==4 and task['pid']==1 and task['state']==2
                and task['runs']==read_seq+explicit_closes+write_seq+1 and task['writes']==4 and task['bytes']==2305
                and task['efault']==5 and all(task[k]==0 for k in ('timers','yields','enosys','fault')),'fd task syscall counters/exit state')
        require(take('fd_exec_end')=={'phase':4,'remaining_pages':4} and at==len(records),'fd final sequence/reclamation')
        info.update(outcome='executed',error=None,output_hex=''.join(info['writes']),exit_code=task['exit'],
                    cursor=cursor,explicit_close=mode==0,read_calls=read_seq)
        return [],info
    except (ValueError,KeyError,struct.error,StopIteration,IndexError) as error:
        return [str(error)],info

def validate_image(info,disk,image,expected,eio):
    header=bytes.fromhex(disk.get('header_hex',''));payload=bytes.fromhex(disk.get('payload_hex',''))
    start=disk.get('offset',0)
    checks={'fd_disk_blob_binding':header==image[:512] and payload==image[start:start+len(payload)]
        and disk.get('capacity_bytes')==len(image) and disk.get('outcome')=='loaded'
        and disk.get('filled')==len(payload)==16384 and disk.get('loader_calls')==1}
    error=expected['expected_error']
    if error:
        checks['fd_expected_rejection']=info.get('outcome')=='rejected' and info.get('error')==error
        return checks
    checks['fd_actual_read_bytes']=bool(info.get('reads')) and all(bytes.fromhex(r['data_hex'])==image[r['offset']:r['offset']+r['length']] for r in info.get('reads',[]))
    checks['fd_actual_output_exit']=info.get('output_hex')==expected['expected_output_hex'] and info.get('exit_code')==expected['exit_code']
    checks['fd_close_mode']=info.get('explicit_close')==expected['explicit_close']
    checks['fd_backend_error_binding']=info.get('device_errors')==int(eio)
    return checks
