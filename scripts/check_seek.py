#!/usr/bin/env python3
"""03c real QEMU development matrix. No official score or independent acceptance."""
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
from seek_protocol import validate_image as bind_fd
from protocol import inspect_detailed
from provenance import ROOT, code_hashes, digest


def bound_inputs(kernel):
    build = kernel.parent
    required = {kernel,build/'inputs.json',*(build/'user').glob('*.elf'),
                *(build/'images').glob('*'),*(build/'blob').glob('*'),*(build/'fd').glob('*'),*(build/'seek').glob('*')}
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
    fdmeta=json.loads((build/'fd/inputs.json').read_text())
    if source['controlled_fd_inputs'] != {'manifest_sha256':digest(build/'fd/inputs.json'),'manifest':fdmeta}:
        raise ValueError('fd manifest changed')
    elf=build/'user/fd_read.elf'
    if digest(elf) != fdmeta['source_elf']['sha256'] or fdmeta['source_elf']['file'] != 'user/fd_read.elf':
        raise ValueError('fd source ELF changed')
    for name,item in fdmeta['images'].items():
        if item['file'] != name+'.img': raise ValueError('unexpected fd image name')
        path=build/'fd'/item['file'];raw=path.read_bytes()
        if digest(path) != item['sha256'] or len(raw) != item['bytes']: raise ValueError('fd medium changed')
        if raw[4096:4096+elf.stat().st_size] != elf.read_bytes(): raise ValueError('fd disk ELF differs')
        data=raw[item['extent_offset']:item['extent_offset']+item['extent_bytes']]
        import hashlib
        if hashlib.sha256(data).hexdigest() != item['data_sha256']: raise ValueError('fd data extent differs')
        if item['expected_error'] is None and data.hex() != item['expected_output_hex']:
            raise ValueError('fd expected output differs from actual extent')
    config=build/'fd/ioerr.conf'
    if digest(config) != fdmeta['ioerr']['sha256'] or config.read_bytes() != b'[inject-error]\nevent = "read_aio"\nerrno = "5"\nsector = "48"\nonce = "on"\n':
        raise ValueError('fd EIO configuration changed')
    sm=json.loads((build/'seek/inputs.json').read_text())
    if source['controlled_seek_inputs']!={'manifest_sha256':digest(build/'seek/inputs.json'),'manifest':sm}:raise ValueError('seek manifest drift')
    if digest(build/'user/seek_read.elf')!=sm['source_elf_sha256']:raise ValueError('seek ELF drift')
    for v in sm['images'].values():
        if digest(build/'seek'/v['file'])!=v['sha256']:raise ValueError('seek input drift')
    if digest(build/'seek/ioerr.conf')!=sm['ioerr_sha256']:raise ValueError('seek injection drift')
    return source,old,blob,fdmeta,sums


def scenarios(build,blob,fdmeta):
    result = {}
    for name,item in blob['images'].items():
        result[name] = {'image':build/'blob'/item['file'],'expected':item['expected'],'mid':False,'old_inject':False}
    result['mid-ioerr'] = {**result['disk-a'],'mid':True}
    for name,image,inject in [('raw-a','A',False),('raw-b','B',False),('raw-ioerr','A',True)]:
        result[name] = {'image':build/'images'/f'{image}.img','expected':{'outcome':'rejected','error':'magic','loader_calls':0},
                        'mid':False,'old_inject':inject}
    result['absent'] = {'image':None,'expected':None,'mid':False,'old_inject':False}
    result['legacy-transport'] = {**result['disk-a'],'legacy':True}
    for name,item in fdmeta['images'].items():
        result['fd-'+name]={'image':build/'fd'/item['file'],'expected':item,'mid':False,'old_inject':False,'fd':True}
    result['fd-ioerr']={**result['fd-data-a'],'fd_inject':True}
    sm=json.loads((build/'seek/inputs.json').read_text())
    result={k:v for k,v in result.items() if k in ('fd-data-a','fd-exit-cleanup','fd-ioerr')}
    for n,v in sm['images'].items():result['seek-'+n]={'image':build/'seek'/v['file'],'expected':v,'mid':False,'old_inject':False,'fd':True,'seek':True}
    result['seek-ioerr']={**result['seek-data-a'],'fd_inject':True}
    return result


def run_command(kernel,scenario):
    result=command(kernel,scenario['image'],scenario['old_inject'])
    if scenario['mid']:
        index=result.index('-drive')+1
        result[index]=result[index].replace('file='+str(scenario['image']),
            f'file=blkdebug:{kernel.parent}/blob/mid-ioerr.conf:{scenario["image"]}')
    if scenario.get('fd_inject'):
        index=result.index('-drive')+1
        result[index]=result[index].replace('file='+str(scenario['image']),f'file=blkdebug:{kernel.parent}/{"seek" if scenario.get("seek") else "fd"}/ioerr.conf:{scenario["image"]}')
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
    try: source,old,blob,fdmeta,sums=bound_inputs(kernel)
    except (ValueError,KeyError,OSError) as error: parser.error(str(error))
    selected=scenarios(kernel.parent,blob,fdmeta)
    if args.scenario != 'all':
        if args.scenario not in selected: parser.error('unknown scenario')
        selected={args.scenario:selected[args.scenario]}
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    out=(args.output or ROOT/'results'/f'stage03d-run-{stamp}').resolve()
    if not out.is_relative_to(ROOT/'results'): parser.error('new native/results directory required')
    out.mkdir(parents=True,exist_ok=False)
    report={'role':'03d development system emulation; independent technical acceptance pending; user display acceptance pending',
            'kernel':str(kernel),'kernel_sha256':digest(kernel),'build_inputs':source,'scenarios':[],
            'controlled_disk_inputs':blob,'controlled_fd_inputs':fdmeta,'qemu_version':subprocess.check_output(['qemu-system-riscv64','--version'],text=True).strip(),
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
                 'backend_error':'read_aio sector48 once, user read syscall' if scenario.get('fd_inject') else
                                 'read_aio sector24 once, after 8192-byte valid ELF prefix' if scenario['mid'] else
                                 'read_aio sector7 once, old block regression' if scenario['old_inject'] else 'none',
                 'expected':scenario['expected'],'runs':[]}
        folder=out/name;folder.mkdir()
        repeats=args.positive_repeat if scenario.get('fd') and scenario['expected'].get('expected_error') is None else args.negative_repeat
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
            if scenario.get('fd'):
                checks.update(bind_fd(getattr(result,'fd',None) or {},getattr(result,'disk',None) or {},visible,scenario['expected'],scenario.get('fd_inject',False)))
            else:
                checks.update(bind_disk(getattr(result,'disk',None) or {},visible,scenario['expected'],scenario['mid'],getattr(result,'executed',None)))
                checks['no_unexpected_fd_phase']=getattr(result,'fd',None) is None
            checks.update(bind_block(getattr(result,'block',None) or {},visible,scenario['old_inject']))
            checks['qemu_exit']=code == 0
            profile['runs'].append({'index':index,'exit_code':code,'host_wall_ms':wall,'raw_log_sha256':digest(log),
                'checks':checks,'parse_errors':result.errors,'metrics':result.metrics,'memory':result.memory,
                'block':getattr(result,'block',None),'disk':getattr(result,'disk',None),'executed':getattr(result,'executed',None),'fd':getattr(result,'fd',None)})
            print(f'scenario={name} run={index} exit={code} development_checks={all(checks.values())} host_wall_ms={wall:.3f}',flush=True)
        profile['image_unchanged']=image is None or digest(image) == profile['image_sha256']
        report['scenarios'].append(profile)
    report['all_build_artifacts_unchanged']=all(digest(p) == sha for p,sha in sums.items())
    report['source_unchanged']=code_hashes() == source['code_sha256']
    report['cross_image_check']=cross_checks(report['scenarios'])
    profiles={p['name']:p for p in report['scenarios']}
    cross_fd={'applies':{'fd-data-a','fd-data-b'} <= profiles.keys()}
    if cross_fd['applies']:
        a,b=(Path(profiles[n]['image']).read_bytes() for n in ('fd-data-a','fd-data-b'))
        cross_fd['same_header_ELF_and_outside_extent']=a[:24576]==b[:24576] and a[26881:]==b[26881:]
        ao=(profiles['fd-data-a']['runs'][0].get('fd') or {}).get('output_hex')
        bo=(profiles['fd-data-b']['runs'][0].get('fd') or {}).get('output_hex')
        cross_fd['different_actual_read_and_write']=isinstance(ao,str) and isinstance(bo,str) and bool(ao) and bool(bo) and ao!=bo
    if {'seek-data-a','seek-data-b'} <= profiles.keys():
        a,b=(Path(profiles[n]['image']).read_bytes() for n in ('seek-data-a','seek-data-b'))
        cross_fd={'applies':True,'same_header_ELF_and_outside_extent':a[:24576]==b[:24576] and a[26881:]==b[26881:],
            'different_actual_read_and_write':bool((profiles['seek-data-a']['runs'][0].get('fd') or {}).get('output_hex')) and (profiles['seek-data-a']['runs'][0].get('fd') or {}).get('output_hex') != (profiles['seek-data-b']['runs'][0].get('fd') or {}).get('output_hex')}
    report['cross_fd']=cross_fd
    report['all_development_checks']=(report['all_build_artifacts_unchanged'] and report['source_unchanged']
        and (not cross_fd['applies'] or cross_fd['same_header_ELF_and_outside_extent'] and cross_fd['different_actual_read_and_write'])
        and (not report['cross_image_check']['applies'] or report['cross_image_check']['same_kernel_different_disk_and_user_effects'])
        and all(p['image_unchanged'] and all(all(r['checks'].values()) for r in p['runs']) for p in report['scenarios']))
    (out/'results.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    print(f'Evidence retained at {out}',flush=True)
    return 0 if report['all_development_checks'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
