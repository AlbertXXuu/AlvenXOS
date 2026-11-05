"""Targeted host mutations for 0.6; never kernel executions."""
import json,sys
from pathlib import Path
from protocol import inspect_detailed
from seek_protocol import validate_image
from test_log_parser import replace_field
from provenance import digest
record=Path(sys.argv[1]);out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=False)
meta=json.loads(record.read_text());profile=next(s for s in meta['scenarios'] if s['name']=='seek-data-a')
base=(record.parent/'seek-data-a/run-1.log').read_text().splitlines();image=Path(profile['image']).read_bytes();cases=[]
def add(name,lines,parse=False,bound=False):cases.append((name,'\n'.join(lines)+'\n',parse,bound))
add('real',base,True,True)
for i,line in enumerate(base):
 if line.startswith(('FD_SEEK ','FD_READ ','FD_CLOSE ','FD_CLEANUP ')):
  add('missing_'+str(i),base[:i]+base[i+1:]);add('duplicate_'+str(i),base[:i]+[line]+base[i:])
  if line.startswith('FD_SEEK '):
   for field,value in [('returned',-123),('pos_after',9999),('submitted',1),('allocated',1),('freed',1),('pages',0),('offset',1<<63)]:
    changed=list(base);changed[i]=replace_field(line,field,value);add(str(i)+'_'+field,changed)
for i,line in enumerate(base):
 if line.startswith('TASK phase=4 '):
  changed=list(base);changed[i]=replace_field(line,'exit',93);add('wrong_exit_binding',changed,True,False)
add('reordered_fields',[l.split()[0]+' '+' '.join(reversed(l.split()[1:])) if l.startswith('FD_SEEK ') else l for l in base],True,True)
add('wrong_actual_disk',(record.parent/'seek-data-b/run-1.log').read_text().splitlines(),True,False)
results=[]
for i,(name,text,want,want_bound) in enumerate(cases):
 try:
  r=inspect_detailed(text);ok=bool(r.checks) and all(r.checks.values()) and not r.errors
  binding=validate_image(getattr(r,'fd',None) or {},getattr(r,'disk',None) or {},image,profile['expected'],False)
  bound=ok and all(binding.values());errors=r.errors
 except Exception as error:ok=bound=False;errors=['UNCAUGHT '+repr(error)]
 path=out/(str(i)+'-'+name+'.log');path.write_text(text)
 results.append({'name':name,'matched':ok==want and bound==want_bound and not any(e.startswith('UNCAUGHT') for e in errors),'parser':ok,'bound':bound,'errors':errors,'file':path.name,'sha256':digest(path)})
report={'role':'host synthetic and log replay, not QEMU','qemu_executed':False,'record_sha256':digest(record),'cases':results,'all_expectations_matched':all(c['matched'] for c in results)}
(out/'regression.json').write_text(json.dumps(report,indent=2)+'\n');print(len(results),report['all_expectations_matched'],[r['name'] for r in results if not r['matched']]);sys.exit(not report['all_expectations_matched'])
