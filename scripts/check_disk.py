#!/usr/bin/env python3
"""03b real QEMU development matrix. No official score or independent acceptance."""
import argparse
import datetime
import json
from pathlib import Path
import subprocess
import sys
import time

from block_protocol import validate_image as bind_block
from check_block import command
from disk_protocol import validate_image as bind_disk
from protocol import inspect_detailed
from provenance import ROOT, code_hashes, digest


def bound_inputs(kernel):
    build = kernel.parent
    required = {kernel,build/'inputs.json',*(build/'user').glob('*.elf'),
                *(build/'images').glob('*'),*(build/'blob').glob('*')}
    sums = {}
    for line in (build/'SHA256SUMS').read_text().splitlines():
        sha, filename = line.split('  ',1)
        path = Path(filename).resolve()
        if path in sums or not path.is_relative_to(build): raise ValueError('invalid/repeated artifact path')
        sums[path] = sha
    if set(sums) != required or any(digest(p) != sha for p,sha in sums.items()):
        raise ValueError('build artifact differs from checksum manifest')
    source = json.loads((build/'inputs.json').read_text())
    if source['code_sha256'] != code_hashes(): raise ValueError('code changed since build; rebuild before execution')
    old = json.loads((build/'images/inputs.json').read_text())
    if source['controlled_block_inputs'] != {'manifest_sha256':digest(build/'images/inputs.json'),
            'images':old['images'],'backend_injection':old['backend_injection']}:
        raise ValueError('old block manifest changed')
    blob = json.loads((build/'blob/inputs.json').read_text())
    if source['controlled_disk_inputs'] != {'manifest_sha256':digest(build/'blob/inputs.json'),'manifest':blob}:
        raise ValueError('disk manifest changed')
    for key,item in old['images'].items():
        if item['file'] != key+'.img': raise ValueError('unexpected raw image name')
        path = build/'images'/item['file']
        if digest(path) != item['sha256'] or path.stat().st_size != item['bytes']: raise ValueError('old raw image changed')
    if digest(build/'images/ioerr.conf') != old['backend_injection']['sha256']: raise ValueError('old EIO config changed')
    for key,item in blob['sources'].items():
        if item['file'] != f'user/disk_{key.lower()}.elf': raise ValueError('unexpected source ELF path')
        path = build/item['file']
        if digest(path) != item['sha256'] or path.stat().st_size != item['bytes']: raise ValueError('disk ELF changed')
        if bytes.fromhex(item['marker_hex']) not in path.read_bytes(): raise ValueError('marker absent from source ELF')
    for key,item in blob['images'].items():
        if item['file'] != key+'.img': raise ValueError('unexpected disk image name')
        path = build/'blob'/item['file']
        if digest(path) != item['sha256'] or path.stat().st_size != item['bytes']: raise ValueError('disk image changed')
        raw=path.read_bytes()
        import hashlib
        payload=raw[item['payload_storage_offset']:item['payload_storage_offset']+item['payload_storage_bytes']]
        if len(payload) != item['stored_payload_bytes'] or hashlib.sha256(payload).hexdigest() != item['stored_payload_sha256']:
            raise ValueError('derived stored payload provenance differs')
        src=blob['sources'][item['source']]
        if item['source_elf_sha256'] != src['sha256'] or hashlib.sha256(payload[:src['bytes']]).hexdigest() != item['derived_elf_sha256']:
            raise ValueError('derived ELF provenance differs')
    if digest(build/'blob/mid-ioerr.conf') != blob['mid_ioerr']['sha256']: raise ValueError('late EIO config changed')
    if (build/'blob/mid-ioerr.conf').read_bytes() != b'[inject-error]\nevent = "read_aio"\nerrno = "5"\nsector = "24"\nonce = "on"\n':
        raise ValueError('unexpected late EIO scenario')
    return source,old,blob,sums


def scenarios(build,blob):
    result = {}
    for name,item in blob['images'].items():
        result[name] = {'image':build/'blob'/item['file'],'expected':item['expected'],'mid':False,'old_inject':False}
    result['mid-ioerr'] = {**result['disk-a'],'mid':True}
    for name,image,inject in [('raw-a','A',False),('raw-b','B',False),('raw-ioerr','A',True)]:
        result[name] = {'image':build/'images'/f'{image}.img','expected':{'outcome':'rejected','error':'magic','loader_calls':0},
                        'mid':False,'old_inject':inject}
    result['absent'] = {'image':None,'expected':None,'mid':False,'old_inject':False}
    result['legacy-transport'] = {**result['disk-a'],'legacy':True}
    return result


def run_command(kernel,scenario):
    result=command(kernel,scenario['image'],scenario['old_inject'])
    if scenario['mid']:
        index=result.index('-drive')+1
        result[index]=result[index].replace('file='+str(scenario['image']),
            f'file=blkdebug:{kernel.parent}/blob/mid-ioerr.conf:{scenario["image"]}')
    if scenario.get('legacy'):
        index=result.index('virtio-mmio.force-legacy=false')
        result[index]='virtio-mmio.force-legacy=true'
    return result


def cross_checks(profiles):
    by_name={p['name']:p for p in profiles}
    if not {'disk-a','disk-b'} <= by_name.keys(): return {'applies':False}
    a,b=by_name['disk-a'],by_name['disk-b']
    return {'applies':True,'same_kernel_different_disk_and_user_effects':
            a['image_sha256'] != b['image_sha256']
            and a['runs'][0]['executed'] != b['runs'][0]['executed']
            and all(r['disk']['outcome'] == 'loaded' for p in (a,b) for r in p['runs'])}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--kernel',type=Path)
    parser.add_argument('--positive-repeat',type=int,choices=range(1,6),default=3)
    parser.add_argument('--negative-repeat',type=int,choices=range(1,6),default=1)
    parser.add_argument('--scenario',default='all')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    kernel=(args.kernel or Path((ROOT/'build/LAST_BUILD').read_text().strip())/'alvenx.elf').resolve()
    if not kernel.is_file() or not kernel.is_relative_to(ROOT/'build'): parser.error('existing native/build kernel required')
    try: source,old,blob,sums=bound_inputs(kernel)
    except (ValueError,KeyError,OSError) as error: parser.error(str(error))
    selected=scenarios(kernel.parent,blob)
    if args.scenario != 'all':
        if args.scenario not in selected: parser.error('unknown scenario')
        selected={args.scenario:selected[args.scenario]}
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    out=(args.output or ROOT/'results'/f'stage03b-run-{stamp}').resolve()
    if not out.is_relative_to(ROOT/'results'): parser.error('new native/results directory required')
    out.mkdir(parents=True,exist_ok=False)
    report={'role':'03b development system emulation; independent technical acceptance pending; user display acceptance pending',
            'kernel':str(kernel),'kernel_sha256':digest(kernel),'build_inputs':source,'scenarios':[],
            'controlled_disk_inputs':blob,'qemu_version':subprocess.check_output(['qemu-system-riscv64','--version'],text=True).strip(),
            'python_version':sys.version,'official_score':None,
            'measurement':'guest virtual yield workload only; disk loading is a functional experiment, not storage performance'}
    for name,scenario in selected.items():
        image=scenario['image']
        image_bytes=image.read_bytes() if image else None
        visible=None if scenario.get('legacy') else image_bytes
        cmd=run_command(kernel,scenario)
        profile={'name':name,'command':cmd,'image':str(image) if image else None,'image_sha256':digest(image) if image else None,
                 'image_bytes':len(image_bytes) if image_bytes else 0,'readonly':image is not None,
                 'transport':'legacy ignored, physical medium attached' if scenario.get('legacy') else 'modern',
                 'backend_error':'read_aio sector24 once, after 8192-byte valid ELF prefix' if scenario['mid'] else
                                 'read_aio sector7 once, old block regression' if scenario['old_inject'] else 'none',
                 'expected':scenario['expected'],'runs':[]}
        folder=out/name;folder.mkdir()
        repeats=args.positive_repeat if name in ('disk-a','disk-b') else args.negative_repeat
        for index in range(1,repeats+1):
            start=time.monotonic_ns()
            try:
                process=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
                code,raw=process.returncode,process.stdout
            except subprocess.TimeoutExpired as error: code,raw=124,error.stdout or b''
            wall=(time.monotonic_ns()-start)/1_000_000
            log=folder/f'run-{index}.log';log.write_bytes(raw)
            result=inspect_detailed(raw.decode('utf-8',errors='replace').replace('\r\n','\n'))
            checks=dict(result.checks)
            checks['parser_has_no_errors']=bool(checks) and not result.errors
            checks.update(bind_disk(getattr(result,'disk',None) or {},visible,scenario['expected'],scenario['mid'],getattr(result,'executed',None)))
            checks.update(bind_block(getattr(result,'block',None) or {},visible,scenario['old_inject']))
            checks['qemu_exit']=code == 0
            profile['runs'].append({'index':index,'exit_code':code,'host_wall_ms':wall,'raw_log_sha256':digest(log),
                'checks':checks,'parse_errors':result.errors,'metrics':result.metrics,'memory':result.memory,
                'block':getattr(result,'block',None),'disk':getattr(result,'disk',None),'executed':getattr(result,'executed',None)})
            print(f'scenario={name} run={index} exit={code} development_checks={all(checks.values())} host_wall_ms={wall:.3f}',flush=True)
        profile['image_unchanged']=image is None or digest(image) == profile['image_sha256']
        report['scenarios'].append(profile)
    report['all_build_artifacts_unchanged']=all(digest(p) == sha for p,sha in sums.items())
    report['source_unchanged']=code_hashes() == source['code_sha256']
    report['cross_image_check']=cross_checks(report['scenarios'])
    report['all_development_checks']=(report['all_build_artifacts_unchanged'] and report['source_unchanged']
        and (not report['cross_image_check']['applies'] or report['cross_image_check']['same_kernel_different_disk_and_user_effects'])
        and all(p['image_unchanged'] and all(all(r['checks'].values()) for r in p['runs']) for p in report['scenarios']))
    (out/'results.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    print(f'Evidence retained at {out}',flush=True)
    return 0 if report['all_development_checks'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
