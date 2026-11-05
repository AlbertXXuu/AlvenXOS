#!/usr/bin/env python3
"""Version-1 controlled single-ELF blob containers. This is not a filesystem."""
import hashlib
import json
from pathlib import Path
import struct
import sys

MAX_ELF, OFFSET = 16384, 4096


def headers(elf):
    phoff = struct.unpack_from('<Q', elf, 32)[0]
    count = struct.unpack_from('<H', elf, 56)[0]
    return [phoff + i * 56 for i in range(count) if struct.unpack_from('<I', elf, phoff + i * 56)[0] == 1]


def main():
    build = Path(sys.argv[1]).resolve()
    out = build / 'blob'
    out.mkdir(exist_ok=False)
    sources = {}
    for name, marker, exit_code in [('A', b'ALVENX_DISK_A_REAL_WRITE\n', 71),
                                     ('B', b'ALVENX_DISK_B_DIFFERENT_WRITE\n', 83)]:
        path = build / 'user' / f'disk_{name.lower()}.elf'
        raw = path.read_bytes()
        loads = headers(raw)
        assert len(loads) == 2 and all(struct.unpack_from('<Q', raw, p + 40)[0] > 0 for p in loads)
        assert marker in raw and len(raw) <= 8192
        sources[name] = {'file':str(path.relative_to(build)), 'bytes':len(raw),
                         'sha256':hashlib.sha256(raw).hexdigest(), 'marker_hex':marker.hex(), 'exit_code':exit_code}
    images = {}

    def make(case, source='A', mutate=None, length=MAX_ELF, offset=OFFSET, declared=None,
             magic=b'ALVXELF\0', version=1, header_bytes=512, truncate=None, expected=None):
        size = (64 if source == 'A' else 96) * 512
        data = bytearray(hashlib.shake_256(f'AlvenX03b container {source} v1'.encode()).digest(size))
        elf = bytearray((build / sources[source]['file']).read_bytes())
        if mutate: mutate(elf)
        payload = bytes(elf) + hashlib.shake_256(f'AlvenX03b ELF padding {source}'.encode()).digest(MAX_ELF - len(elf))
        data[OFFSET:OFFSET + MAX_ELF] = payload
        data[:512] = b'\0' * 512
        struct.pack_into('<8sIIQQQ', data, 0, magic, version, header_bytes, offset, length, size if declared is None else declared)
        if truncate is not None: data = data[:truncate]
        path = out / f'{case}.img'
        path.write_bytes(data)
        images[case] = {'file':path.name, 'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest(),
                        'source':source, 'source_elf_sha256':sources[source]['sha256'],
                        'derived_elf_sha256':hashlib.sha256(elf).hexdigest(),
                        'payload_storage_offset':OFFSET, 'payload_storage_bytes':MAX_ELF,
                        'stored_payload_sha256':hashlib.sha256(bytes(data[OFFSET:OFFSET+MAX_ELF])).hexdigest(),
                        'stored_payload_bytes':len(data[OFFSET:OFFSET+MAX_ELF]),
                        'payload_bytes':min(length, MAX_ELF) if offset == OFFSET else None,
                        'expected':expected or {'outcome':'executed', 'error':'none', 'loader_calls':1,
                                                'marker_hex':sources[source]['marker_hex'],'exit_code':sources[source]['exit_code']}}
    rejected = lambda error, calls=0: {'outcome':'rejected','error':error,'loader_calls':calls}
    make('disk-a')
    make('disk-b', source='B')
    make('bad-magic', magic=b'BADMAGIC', expected=rejected('magic'))
    make('bad-version', version=2, expected=rejected('version'))
    make('bad-header-size', header_bytes=64, expected=rejected('header_size'))
    make('zero-length', length=0, expected=rejected('zero_length'))
    make('overlong', length=MAX_ELF + 1, expected=rejected('too_long'))
    make('overflow', offset=(1 << 64) - 8, length=16, expected=rejected('overflow'))
    make('out-of-capacity', offset=64 * 512 - 8, length=16, expected=rejected('range'))
    make('header-overlap', offset=256, length=16, expected=rejected('header_overlap'))
    make('truncated-container', truncate=32 * 512, expected=rejected('truncated_container'))
    make('container-size', declared=63 * 512, expected=rejected('container_size'))
    make('elf-bad-magic', mutate=lambda elf: elf.__setitem__(0, 0), expected=rejected('ELF_identity', 1))
    make('elf-machine', mutate=lambda elf: struct.pack_into('<H', elf, 18, 62),
         expected=rejected('ELF_type_or_machine', 1))
    make('elf-permissions', mutate=lambda elf: struct.pack_into('<I', elf, headers(elf)[0]+4, 7),
         expected=rejected('ELF_permissions', 1))
    def overlap(elf):
        first, second = headers(elf)
        va = struct.unpack_from('<Q', elf, first + 16)[0]
        struct.pack_into('<Q', elf, second + 16, va)
    make('elf-overlap', mutate=overlap, expected=rejected('overlapping_user_segment', 1))
    elf_a = (build / sources['A']['file']).read_bytes()
    last_file_byte = max(struct.unpack_from('<Q', elf_a, p + 8)[0] + struct.unpack_from('<Q', elf_a, p + 32)[0]
                        for p in headers(elf_a))
    make('elf-effective-truncated', length=last_file_byte - 1, expected=rejected('ELF_file_range', 1))
    config = b'[inject-error]\nevent = "read_aio"\nerrno = "5"\nsector = "24"\nonce = "on"\n'
    (out / 'mid-ioerr.conf').write_bytes(config)
    manifest = {'role':'controlled single-ELF blob, not filesystem or official image compatibility',
                'format':{'magic_hex':b'ALVXELF\0'.hex(),'version':1,'header_bytes':512,'max_elf_bytes':MAX_ELF,'payload_offset':OFFSET},
                'sources':sources,'images':images,'mid_ioerr':{'file':'mid-ioerr.conf','sector':24,'errno':5,'once':True,
                    'sha256':hashlib.sha256(config).hexdigest(),'filled_before_failure':8192,'prefix_contains_complete_source_elf':True}}
    (out / 'inputs.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
