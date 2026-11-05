"""0.4 controlled ELF transaction checks; host image/expectation binding is separate."""
import re
import struct
from log_parser import Record, number

PREFIXES = ("DISK_",)
SPECS = (
    ("begin", "format header_bytes max_elf_bytes baseline_pages", ""),
    ("device", "capacity_bytes ring bounce live_pages", ""),
    ("io", "kind offset length outcome status used_len submitted completed notified buffer_unchanged", "kind outcome"),
    ("header", "at hex", "hex"),
    ("meta", "version header_bytes offset length container_bytes capacity_bytes", ""),
    ("input", "pages capacity base injection old_valid begin_valid begin_filled live_pages", "injection"),
    ("data", "at hex", "hex"),
    ("read_abort", "filled valid prefix_precheck loader_calls", "prefix_precheck"),
    ("complete", "filled valid", ""),
    ("device_close", "reset_confirmed reset_polls reset_ticks dma_freed used_before used_after", ""),
    ("loader", "calls outcome error allocated freed used_before used_after entry root input_length", "outcome error"),
    ("input_clear", "valid filled zeroed", ""),
    ("input_release", "pages freed used_before used_after", ""),
    ("end", "outcome error loader_calls filled valid remaining_pages", "outcome error"),
    ("exec_begin", "phase pid input_valid", ""),
    ("write", "pid fd requested returned hex", "hex"),
    ("exec_end", "phase remaining_pages", ""),
)


def decode(line):
    for kind, keys, strings in SPECS:
        prefix = f"DISK_{kind.upper()} "
        if not line.startswith(prefix):
            continue
        fields = {}
        for item in line[len(prefix):].split():
            match = re.fullmatch(r"([a-z_]+)=([^\s=]+)", item)
            if match is None or match[1] in fields:
                raise ValueError("malformed or repeated disk field")
            fields[match[1]] = match[2]
        if set(fields) != set(keys.split()):
            raise ValueError("missing or unexpected disk field")
        values = {k: v if k in strings.split() else number(v) for k, v in fields.items()}
        if 'hex' in values and re.fullmatch(r'(?:[0-9a-f]{2}){1,1024}', values['hex']) is None:
            raise ValueError("invalid disk byte encoding")
        return Record('disk_' + kind, fields, values)
    return None


def header_error(header, capacity):
    magic, version, size, offset, length, declared = struct.unpack_from('<8sIIQQQ', header)
    if magic != b'ALVXELF\0': return 'magic'
    if version != 1: return 'version'
    if size != 512: return 'header_size'
    if length == 0: return 'zero_length'
    if length > 16384: return 'too_long'
    if offset + length >= 1 << 64: return 'overflow'
    if declared > capacity: return 'truncated_container'
    if declared != capacity: return 'container_size'
    if offset < 512: return 'header_overlap'
    if offset + length > declared: return 'range'
    return None


def elf_error(raw):
    """Independent bounded checks for the three controlled ELF rejection fixtures."""
    if len(raw) < 64 or raw[:7] != b'\x7fELF\x02\x01\x01': return 'ELF_identity'
    if struct.unpack_from('<HH',raw,16) != (2,243): return 'ELF_type_or_machine'
    phoff = struct.unpack_from('<Q', raw, 32)[0]
    phsize, count = struct.unpack_from('<HH', raw, 54)
    if phsize != 56 or phoff + count * phsize > len(raw): return 'ELF_file_range'
    ranges = []
    for i in range(count):
        p = phoff + i * phsize
        kind, flags, off, va, _, filesz, memsz, _ = struct.unpack_from('<IIQQQQQQ', raw, p)
        if kind != 1 or memsz == 0: continue
        if off + filesz > len(raw): return 'ELF_file_range'
        if flags & 4 == 0 or flags & 3 == 3: return 'ELF_permissions'
        span = (va // 4096, (va + memsz + 4095) // 4096)
        if any(span[0] < end and start < span[1] for start, end in ranges):
            return 'overlapping_user_segment'
        ranges.append(span)
    return None


def inspect(records, pool_start, pool_end):
    """Consume exactly one transaction. Never accept a partial buffer as executable."""
    at, info, pending_io = 0, {}, {}

    def require(ok, message):
        if not ok: raise ValueError(message)

    def take(kind):
        nonlocal at
        require(at < len(records) and records[at].kind == 'disk_' + kind, f'disk order: expected {kind}')
        value = records[at].values
        at += 1
        return value

    def frame(address, pages=1):
        return address % 4096 == 0 and pool_start + 4 * 4096 <= address and address + pages * 4096 <= pool_end

    def chunks(kind, length):
        data = bytearray()
        for offset in range(0, length, 64):
            v = take(kind)
            raw = bytes.fromhex(v['hex'])
            require(v['at'] == offset and len(raw) == min(64, length - offset), 'disk byte coverage')
            data.extend(raw)
        return bytes(data)

    def close(with_input):
        v = take('device_close')
        require(v['reset_confirmed'] == 1 and 1 <= v['reset_polls'] <= 1_000_000
                and v['dma_freed'] == 2 and v['used_before'] == (10 if with_input else 6)
                and v['used_after'] == v['used_before'] - 2, 'disk reset/free ordering or accounting')

    def release(loaded):
        require(take('input_clear') == {'valid':0,'filled':0,'zeroed':1}, 'stale disk input remains valid')
        require(take('input_release') == {'pages':4,'freed':4,'used_before':16 if loaded else 8,
                                        'used_after':12 if loaded else 4}, 'disk input ownership/release')

    def finish(outcome, error, calls, filled, loaded=False):
        v = take('end')
        require(v == {'outcome':outcome,'error':error,'loader_calls':calls,'filled':filled,'valid':0,
                       'remaining_pages':12 if loaded else 4}, 'disk final validity, loader or resident pages')
        require(at == len(records), 'extra disk transaction event')
        info.update(v)
        return [], info

    def io(kind, offset, length):
        nonlocal pending_io
        v = take('io')
        pending_io = v
        require(v['kind'] == kind and v['offset'] == offset and v['length'] == length
                and v['submitted'] == v['completed'] == v['notified'] == 1,
                'disk I/O address, length or actual queue counters')
        require(v['outcome'] in ('ok','ioerr'), 'unexpected disk I/O outcome')
        dma_bytes = ((offset % 512 + length + 511)//512)*512
        # QEMU 8.2.2 reports its writable iov capacity even on backend IOERR.
        # A bounded used length never makes error data valid or copyable.
        require((v['status'] == 0 and v['used_len'] == dma_bytes+1 and v['buffer_unchanged'] in (0,1))
                if v['outcome'] == 'ok' else
                (v['status'] == 1 and 1 <= v['used_len'] <= dma_bytes+1 and v['buffer_unchanged'] == 1),
                'disk I/O status/completion size or error modified caller buffer')
        return v['outcome'] == 'ok'

    try:
        require(take('begin') == {'format':1,'header_bytes':512,'max_elf_bytes':16384,'baseline_pages':4}, 'disk protocol constants')
        if at < len(records) and records[at].kind == 'disk_end':
            info.update(present=False, header_hex='', payload_hex='')
            return finish('rejected','device_absent',0,0)
        dev = take('device')
        capacity = dev['capacity_bytes']
        require(capacity >= 30*512 and capacity % 512 == 0 and dev['live_pages'] == 6
                and dev['ring'] != dev['bounce'] and frame(dev['ring']) and frame(dev['bounce']), 'disk capacity or DMA owner')
        info.update(present=True,capacity_bytes=capacity)
        if not io('header',0,512):
            close(False)
            return finish('rejected','header_ioerr',0,0)
        header = chunks('header',512)
        require(pending_io['buffer_unchanged'] == int(not any(header)), 'header zero-buffer flag contradicts full readback')
        info['header_hex'] = header.hex()
        _, version, size, offset, length, declared = struct.unpack_from('<8sIIQQQ',header)
        require(take('meta') == {'version':version,'header_bytes':size,'offset':offset,'length':length,
                'container_bytes':declared,'capacity_bytes':capacity}, 'metadata differs from actual header')
        error = header_error(header,capacity)
        if error:
            close(False)
            return finish('rejected',error,0,0)
        inp = take('input')
        require(inp['pages'] == 4 and inp['capacity'] == inp['old_valid'] == 16384 and inp['injection'] == 'stale_sentinel'
                and inp['begin_valid'] == inp['begin_filled'] == 0 and inp['live_pages'] == 10
                and frame(inp['base'],4) and not any(inp['base'] <= p < inp['base']+16384 for p in (dev['ring'],dev['bounce'])), 'disk input reset/ownership')
        payload = bytearray()
        while len(payload) < length:
            filled = len(payload)
            count = min(2048,length-filled)
            if not io('payload',offset+filled,count):
                abort = take('read_abort')
                require(abort == {'filled':filled,'valid':0,'prefix_precheck':'ok' if elf_error(payload) is None else 'rejected',
                                  'loader_calls':0}, 'partial ELF became valid or prefix diagnostic disagrees')
                info.update(payload_hex=payload.hex(),aborted=True,offset=offset)
                close(True)
                release(False)
                return finish('rejected','payload_ioerr',0,filled)
            for pos in range(filled,filled+count,64):
                v = take('data')
                raw = bytes.fromhex(v['hex'])
                require(v['at'] == pos and len(raw) == min(64,filled+count-pos), 'payload gap, overlap or oversized chunk')
                payload.extend(raw)
            require(pending_io['buffer_unchanged'] == int(not any(payload[filled:])),
                    'payload zero-buffer flag contradicts full readback')
        info.update(payload_hex=payload.hex(),offset=offset,aborted=False)
        require(take('complete') == {'filled':length,'valid':length}, 'only fully read declared bytes may be valid')
        close(True)  # Loaded address space must not precede a fallible reset.
        loader = take('loader')
        error = elf_error(payload)
        loaded = error is None
        frames = 8 if loaded else (4 if error == 'overlapping_user_segment' else 0)
        require(loader['calls'] == 1 and loader['outcome'] == ('ok' if loaded else 'rejected')
                and loader['error'] == (error or 'none') and loader['allocated'] == frames
                and loader['freed'] == (0 if loaded else frames) and loader['used_before'] == 8
                and loader['used_after'] == (16 if loaded else 8) and loader['input_length'] == length
                and loader['entry'] == (0x10000 if loaded else 0)
                and (frame(loader['root']) and not inp['base'] <= loader['root'] < inp['base']+16384
                     if loaded else loader['root'] == 0), 'disk loader validity, partial rollback or space ownership')
        info['loader'] = loader
        release(loaded)
        return finish('loaded' if loaded else 'rejected',error or 'none',1,length,loaded)
    except (ValueError,struct.error,IndexError) as error:
        return [str(error)], info


def validate_image(info, image, expected, mid_ioerr=False, executed=None):
    """Bind observed input and U-mode effects to host-owned bytes/expectations."""
    if image is None:
        return {'disk_image_binding':info.get('present') is False and info.get('error') == 'device_absent',
                'disk_execution_binding':executed is None}
    header = bytes.fromhex(info.get('header_hex',''))
    payload = bytes.fromhex(info.get('payload_hex',''))
    start = info.get('offset',0)
    byte_ok = (info.get('present') is True and info.get('capacity_bytes') == len(image)
               and header == image[:512] and payload == image[start:start+len(payload)])
    expected_error = 'payload_ioerr' if mid_ioerr else expected['error']
    expected_calls = 0 if mid_ioerr else expected['loader_calls']
    outcome = 'loaded' if expected['outcome'] == 'executed' and not mid_ioerr else 'rejected'
    state_ok = info.get('error') == expected_error and info.get('loader_calls') == expected_calls and info.get('outcome') == outcome
    if mid_ioerr:
        state_ok &= info.get('filled') == len(payload) == 8192 and elf_error(payload) is None
    if outcome == 'loaded':
        exec_ok = (executed is not None and executed.get('hex') == expected['marker_hex']
                   and executed.get('exit') == expected['exit_code'])
    else:
        exec_ok = executed is None
    return {'disk_image_binding':byte_ok,'disk_expected_outcome':state_ok,'disk_execution_binding':exec_ok}
