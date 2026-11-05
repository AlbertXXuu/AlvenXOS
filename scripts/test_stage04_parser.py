#!/usr/bin/env python3
"""Synthetic 0.4 protocol/input-binding adversaries; never additional kernel runs."""
import argparse
import datetime
import json
from pathlib import Path
import re

from block_protocol import validate_image as bind_block
from disk_protocol import validate_image as bind_disk
from protocol import inspect_detailed
from provenance import ROOT, digest
from test_log_parser import replace_field


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--record',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    record=json.loads(args.record.read_text())
    assert digest(Path(record['kernel'])) == record['kernel_sha256']
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    out=args.output or ROOT/'results'/f'stage03b-parser-{stamp}'
    out.mkdir(parents=True,exist_ok=False)
    profiles={p['name']:p for p in record['scenarios']}
    positive=profiles['disk-a']
    image=Path(positive['image']).read_bytes()
    expected=positive['expected']
    original=(args.record.parent/'disk-a/run-1.log').read_text().splitlines()
    cases=[]

    def add(name,lines,parser_ok=False,bound_ok=False,img=image,exp=expected,mid=False,old=False,kind='synthetic mutation'):
        cases.append((name,'\n'.join(lines)+'\n',parser_ok,bound_ok,img,exp,mid,old,kind))

    for p in profiles.values():
        path=args.record.parent/p['name']/'run-1.log'
        assert digest(path) == p['runs'][0]['raw_log_sha256']
        img=Path(p['image']).read_bytes() if p['image'] and p['name'] != 'legacy-transport' else None
        add('real_replay_'+p['name'],path.read_text().splitlines(),True,True,img,p['expected'],p['name']=='mid-ioerr',p['name']=='raw-ioerr','original real log replay')
    selected=[i for i,l in enumerate(original) if l.startswith(('DISK_','LOAD phase=3','USER_ACCESS phase=3','TASK phase=3','MEMORY phase=3'))]
    for index in selected:
        add(f'missing_{index}',original[:index]+original[index+1:])
        add(f'duplicate_{index}',original[:index]+[original[index]]+original[index:])

    def edit(name,prefix,field,value,parser_ok=False,bound_ok=False):
        positions=[i for i,l in enumerate(original) if l.startswith(prefix)]
        assert len(positions) == 1,prefix
        lines=list(original);i=positions[0]
        lines[i]=replace_field(lines[i],field,value)
        add(name,lines,parser_ok,bound_ok)

    changes=[('format','DISK_BEGIN ','format',2),('resident','DISK_BEGIN ','baseline_pages',3),
             ('DMA_alias','DISK_DEVICE ','bounce',re.search(r'ring=([^ ]+)',next(l for l in original if l.startswith('DISK_DEVICE ')))[1]),
             ('header_not_completed','DISK_IO kind=header ','completed',0),
             ('nonzero_header_unchanged','DISK_IO kind=header ','buffer_unchanged',1),
             ('header_metadata_lie','DISK_META ','length',8192),
             ('valid_before_read','DISK_INPUT ','begin_valid',16384),
             ('filled_before_read','DISK_INPUT ','begin_filled',8192),
             ('stale_injection_unlabelled','DISK_INPUT ','injection','none'),
             ('load_capacity_as_length','DISK_COMPLETE ','valid',8192),
             ('partial_valid','DISK_COMPLETE ','filled',8192),
             ('close_unconfirmed','DISK_DEVICE_CLOSE ','reset_confirmed',0),
             ('DMA_not_released','DISK_DEVICE_CLOSE ','dma_freed',0),
             ('double_loader','DISK_LOADER ','calls',2),
             ('loader_short_slice','DISK_LOADER ','input_length',8192),
             ('loader_leaks','DISK_LOADER ','used_after',17),
             ('clear_incomplete','DISK_INPUT_CLEAR ','valid',16384),
             ('clear_not_zero','DISK_INPUT_CLEAR ','zeroed',0),
             ('input_leak','DISK_INPUT_RELEASE ','freed',3),
             ('retained_input','DISK_END ','valid',16384),
             ('exec_before_clear','DISK_EXEC_BEGIN ','input_valid',16384),
             ('write_wrong_return','DISK_WRITE ','returned',1),
             ('write_wrong_fd','DISK_WRITE ','fd',2),
             ('user_ran_extra','TASK phase=3 ','runs',3),
             ('syscall_bytes_lie','TASK phase=3 ','bytes',1),
             ('user_memory_leak','MEMORY phase=3 ','allocated_pages',12),
             ('exec_memory_leak','DISK_EXEC_END ','remaining_pages',12)]
    for name,prefix,field,value in changes: edit(name,prefix,field,value)
    edit('different_exit_needs_host_binding','TASK phase=3 ','exit',72,True,False)
    write=next(l for l in original if l.startswith('DISK_WRITE '))
    marker=re.search(r'hex=([^ ]+)',write)[1]
    edit('different_write_needs_host_binding','DISK_WRITE ','hex','00'+marker[2:],True,False)
    add('wrong_host_disk',original,True,False,Path(profiles['disk-b']['image']).read_bytes(),profiles['disk-b']['expected'])
    lines=list(original)
    idx=next(i for i,l in enumerate(lines) if l.startswith('DISK_HEADER at=64 '))
    token=re.search(r'hex=([^ ]+)',lines[idx])[1]
    lines[idx]=replace_field(lines[idx],'hex','a5'+token[2:])
    add('reserved_header_byte_needs_host_binding',lines,True,False)
    # The full A/B source ELF fits in this prefix. Even a valid ELF prefix cannot
    # commit an interrupted, longer declared transaction or reuse old bytes.
    mid=(args.record.parent/'mid-ioerr/run-1.log').read_text().splitlines()
    for field,value in [('valid',8192),('loader_calls',1),('filled',16384)]:
        lines=[replace_field(l,field,value) if l.startswith('DISK_READ_ABORT ') else l for l in mid]
        add('partial_abort_'+field,lines,img=image,exp=expected,mid=True)
    lines=[replace_field(l,'valid',8192) if l.startswith('DISK_END ') else l for l in mid]
    add('partial_end_reuses_prefix',lines,img=image,exp=expected,mid=True)
    lines=[replace_field(l,'buffer_unchanged',0) if l.startswith('DISK_IO ') and 'outcome=ioerr' in l else l for l in mid]
    add('ioerr_modified_caller_buffer',lines,img=image,exp=expected,mid=True)
    # Syntactically malformed fields, unknown fields and pre-boot disk records.
    add('record_before_boot',['DISK_END outcome=rejected error=device_absent loader_calls=0 filled=0 valid=0 remaining_pages=4']+original)
    for suffix in (' extra=1',' valid=0',' malformed'):
        lines=list(original);idx=next(i for i,l in enumerate(lines) if l.startswith('DISK_COMPLETE '));lines[idx]+=suffix
        add('malformed_'+str(len(cases)),lines)
    add('valid_reordered_disk_fields',[l.split()[0]+' '+' '.join(reversed(l.split()[1:])) if l.startswith('DISK_') else l for l in original],True,True)
    lines=[]
    zero_image=bytearray(image);zero_image[12288:14336]=bytes(2048)
    for line in original:
        if line.startswith('DISK_DATA '):
            pos=int(re.search(r'at=([0-9]+)',line)[1])
            if 8192 <= pos < 10240: line=replace_field(line,'hex','00'*64)
        if line.startswith('DISK_IO kind=payload offset=12288 '): line=replace_field(line,'buffer_unchanged',1)
        lines.append(line)
    add('valid_zero_payload_read_unchanged',lines,True,True,bytes(zero_image))
    # Timing is allowed to vary; state and input bytes are not inferred from it.
    edit('valid_different_reset_ticks','DISK_DEVICE_CLOSE ','reset_ticks',123,True,True)
    results=[]
    (out/'images').mkdir()
    image_files={}
    for index,(name,text,parse_ok,bound_ok,img,exp,mid,old,kind) in enumerate(cases):
        parsed=inspect_detailed(text)
        accepted=bool(parsed.checks) and all(parsed.checks.values()) and not parsed.errors
        bindings=bind_disk(getattr(parsed,'disk',None) or {},img,exp,mid,getattr(parsed,'executed',None))
        bindings.update(bind_block(getattr(parsed,'block',None) or {},img,old))
        bound=accepted and all(bindings.values())
        path=out/f'{index:04}-{name}.log';path.write_text(text)
        image_file=None
        if img is not None:
            import hashlib
            image_sha=hashlib.sha256(img).hexdigest()
            if image_sha not in image_files:
                image_file=out/'images'/f'{image_sha}.img';image_file.write_bytes(img)
                image_files[image_sha]=str(image_file.relative_to(out))
            image_file=image_files[image_sha]
        results.append({'name':name,'input_kind':kind,'parser_expected':parse_ok,'parser_accepted':accepted,
                        'binding_expected':bound_ok,'bound_accepted':bound,'matched':accepted==parse_ok and bound==bound_ok,
                        'errors':parsed.errors,'checks':parsed.checks,'bindings':bindings,'file':path.name,'sha256':digest(path),
                        'image_file':image_file,'expected_effects':exp,'mid_ioerr':mid,'old_ioerr':old})
    report={'role':'host protocol/image-binding regression; synthetic logs are not kernel execution','qemu_executed':False,
            'source_record':str(args.record),'source_record_sha256':digest(args.record),'cases':results,
            'all_expectations_matched':all(r['matched'] for r in results)}
    (out/'regression.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'cases={len(cases)} expectations_matched={report["all_expectations_matched"]} qemu_executed=false')
    print(out)
    return 0 if report['all_expectations_matched'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
