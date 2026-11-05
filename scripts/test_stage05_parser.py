#!/usr/bin/env python3
"""03c host-only log/image adversaries. No additional kernel execution."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
from protocol import inspect_detailed
from fd_protocol import validate_image
from block_protocol import validate_image as bind_block
from provenance import ROOT,digest
from test_log_parser import replace_field

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--record',type=Path,required=True);ap.add_argument('--output',type=Path)
    args=ap.parse_args();record=json.loads(args.record.read_text())
    assert digest(Path(record['kernel']))==record['kernel_sha256']
    profiles={p['name']:p for p in record['scenarios']}
    out=args.output or ROOT/'results'/('stage03c-parser-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
    out.mkdir(parents=True,exist_ok=False);(out/'images').mkdir()
    p=profiles['fd-data-a'];image=Path(p['image']).read_bytes();expect=p['expected']
    original=(args.record.parent/'fd-data-a/run-1.log').read_text().splitlines();cases=[]
    def add(name,lines,parse=False,bound=False,img=image,expected=expect,eio=False,kind='synthetic mutation'):
        cases.append((name,'\n'.join(lines)+'\n',parse,bound,img,expected,eio,kind))
    for name,p in profiles.items():
        if not name.startswith('fd-'):continue
        path=args.record.parent/name/'run-1.log';assert digest(path)==p['runs'][0]['raw_log_sha256']
        add('real_replay_'+name,path.read_text().splitlines(),True,True,Path(p['image']).read_bytes(),p['expected'],name=='fd-ioerr','original real log replay')
    selected=[i for i,l in enumerate(original) if l.startswith(('FD_','LOAD phase=4 ','USER_ACCESS phase=4 ','TASK phase=4 ','MEMORY phase=4 '))]
    for i in selected:
        add('missing_'+str(i),original[:i]+original[i+1:])
        add('duplicate_'+str(i),original[:i]+[original[i]]+original[i:])
    def edit(name,prefix,field,value,parse=False,bound=False,base=original,eio=False):
        positions=[i for i,l in enumerate(base) if l.startswith(prefix)];assert len(positions)==1,prefix
        lines=list(base);i=positions[0];lines[i]=replace_field(lines[i],field,value)
        add(name,lines,parse,bound,eio=eio)
    changes=[('open_shared_root','FD_OPEN ','ring','0x0'),('open_bad_slot','FD_OPEN ','fd',4),
        ('open_cursor','FD_OPEN ','cursor',1),('open_SIE','FD_OPEN ','sie',1),
        ('open_not_1024','FD_OPEN ','max_read',2048),('open_DMA_pages','FD_OPEN ','live_pages',12),
        ('retained_elf_input','FD_EXEC_BEGIN ','input_valid',16384),
        ('badfd_io','FD_READ seq=1 ','submitted',1),('badfd_return','FD_READ seq=1 ','returned',0),
        ('zero_io','FD_READ seq=2 ','submitted',1),('zero_advances','FD_READ seq=2 ','pos_after',1),
        ('overlong_io','FD_READ seq=3 ','completed',1),('RX_io','FD_READ seq=4 ','submitted',1),
        ('kernel_io','FD_READ seq=5 ','submitted',1),('unmapped_io','FD_READ seq=6 ','submitted',1),
        ('guard_prefix_changed','FD_READ seq=7 ','after','00'*8),
        ('overflow_advances','FD_READ seq=8 ','pos_after',1),
        ('success_no_completion','FD_READ seq=9 ','completed',0),
        ('success_bad_length','FD_READ seq=9 ','returned',12),
        ('success_bad_status','FD_READ seq=9 ','status',1),
        ('success_partial_DMA','FD_READ seq=9 ','used_len',1),
        ('success_bad_prefix','FD_READ seq=9 ','prefix_bytes',12),
        ('success_cursor','FD_READ seq=9 ','pos_after',0),
        ('cross_page_skipped','FD_READ seq=11 ','pointer','0x20000'),
        ('short_read_not_short','FD_READ seq=12 ','returned',1024),
        ('EOF_io','FD_READ seq=13 ','submitted',1),('EOF_advances','FD_READ seq=14 ','pos_after',2306),
        ('wrong_write','FD_WRITE seq=1 ','hex','00'*13),
        ('close_without_reset','FD_CLOSE seq=2 ','reset_confirmed',0),
        ('close_leak','FD_CLOSE seq=2 ','dma_freed',0),
        ('double_close_frees','FD_CLOSE seq=3 ','dma_freed',2),
        ('closed_read_io','FD_READ seq=16 ','submitted',1),
        ('closed_zero_success','FD_READ seq=17 ','returned',0),
        ('cleanup_second_release','FD_CLEANUP ','dma_freed',2),
        ('cleanup_cursor','FD_CLEANUP ','cursor',0),('cleanup_handle','FD_CLEANUP ','closed',0),
        ('task_wrong_efault','TASK phase=4 ','efault',4),('task_wrong_runs','TASK phase=4 ','runs',24),
        ('user_memory_leak','MEMORY phase=4 ','allocated_pages',6),
        ('final_resident_drift','FD_EXEC_END ','remaining_pages',6)]
    for name,prefix,field,value in changes:edit(name,prefix,field,value)
    edit('exit_requires_host_binding','TASK phase=4 ','exit',92,True,False)
    other=(args.record.parent/'fd-data-b/run-1.log').read_text().splitlines()
    add('other_real_data_requires_actual_image_binding',other,True,False)
    late=(args.record.parent/'fd-ioerr/run-1.log').read_text().splitlines()
    edit('EIO_advances','FD_READ seq=9 ','pos_after',13,base=late,eio=True)
    edit('EIO_copies_data','FD_READ seq=9 ','after','00'*13,base=late,eio=True)
    edit('EIO_without_status','FD_READ seq=9 ','status',0,base=late,eio=True)
    edit('EIO_without_request','FD_READ seq=9 ','submitted',0,base=late,eio=True)
    exitlog=(args.record.parent/'fd-exit-cleanup/run-1.log').read_text().splitlines()
    edit('exit_close_skipped','FD_CLOSE seq=2 ','origin','explicit',base=exitlog)
    edit('exit_cleanup_leak','FD_CLEANUP ','used_after',14,base=exitlog)
    add('all_fd_activity_removed',[l for i,l in enumerate(original) if i not in selected])
    add('fd_before_boot',['FD_EXEC_END phase=4 remaining_pages=4']+original)
    for suffix in (' extra=1',' returned=0',' invalid'):
        lines=list(original);i=selected[2];lines[i]+=suffix;add('malformed_'+str(len(cases)),lines)
    add('old_version_cannot_accept_new_phase',[l.replace('version=0.5.0','version=0.4.0') for l in original])
    add('valid_reordered_fd_fields',[l.split()[0]+' '+' '.join(reversed(l.split()[1:])) if l.startswith('FD_') else l for l in original],True,True)
    edit('valid_reset_ticks_vary','FD_CLOSE seq=2 ','reset_ticks',123,True,True)
    results=[];image_paths={}
    for i,(name,text,want_parse,want_bound,img,expected,eio,kind) in enumerate(cases):
        parsed=inspect_detailed(text);accepted=bool(parsed.checks) and all(parsed.checks.values()) and not parsed.errors
        binding=validate_image(getattr(parsed,'fd',None) or {},getattr(parsed,'disk',None) or {},img,expected,eio)
        binding.update(bind_block(getattr(parsed,'block',None) or {},img,False))
        bound=accepted and all(binding.values())
        path=out/f'{i:03}-{name}.log';path.write_text(text)
        sha=hashlib.sha256(img).hexdigest()
        if sha not in image_paths:
            target=out/'images'/(sha+'.img');target.write_bytes(img);image_paths[sha]=str(target.relative_to(out))
        results.append({'name':name,'input_kind':kind,'expected_parser':want_parse,'parser':accepted,'expected_bound':want_bound,'bound':bound,
            'matched':accepted==want_parse and bound==want_bound,'errors':parsed.errors,'bindings':binding,'file':path.name,'sha256':digest(path),
            'image':image_paths[sha],'expected_effects':expected,'eio':eio})
    report={'role':'host-only fd protocol/input-binding tests, not QEMU runs','qemu_executed':False,'source_record':str(args.record),
        'source_record_sha256':digest(args.record),'cases':results,'all_expectations_matched':all(c['matched'] for c in results)}
    (out/'regression.json').write_text(json.dumps(report,indent=2)+'\n')
    print('cases=',len(results),'expectations_matched=',report['all_expectations_matched'])
    print('unexpected=',[c['name'] for c in results if not c['matched']]);print(out)
    return 0 if report['all_expectations_matched'] else 1

if __name__=='__main__':raise SystemExit(main())
