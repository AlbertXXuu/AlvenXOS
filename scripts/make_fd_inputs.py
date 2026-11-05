#!/usr/bin/env python3
"""03c: same ELF and layout, only data extent differs for A/B."""
import hashlib
import json
from pathlib import Path
import struct
import sys

def main():
    build=Path(sys.argv[1]).resolve();out=build/'fd';out.mkdir(exist_ok=False)
    elf=(build/'user/fd_read.elf').read_bytes()
    assert len(elf)<=8192
    images={}
    payload=elf+hashlib.shake_256(b'AlvenX03c ELF padding').digest(16384-len(elf))
    base=bytearray(hashlib.shake_256(b'AlvenX03c medium').digest(65536))
    base[:512]=bytes(512)
    struct.pack_into('<8sIIQQQ',base,0,b'ALVXELF\0',1,512,4096,16384,65536)
    base[4096:20480]=payload
    for name,seed,mode,offset,mutation in [('data-a',b'A',0,24576,None),('data-b',b'B',0,24576,None),
            ('exit-cleanup',b'A',1,24576,None),('offset-control',b'A',0,28673,None),
            ('sentinel-data',b'sentinel',165,24576,None),
            ('extent-overflow',b'A',0,24576,'overflow'),('extent-overlap',b'A',0,24576,'overlap'),
            ('extent-range',b'A',0,24576,'range'),('extent-magic',b'A',0,24576,'magic'),
            ('extent-version',b'A',0,24576,'version'),('extent-size',b'A',0,24576,'header_size'),
            ('extent-zero',b'A',0,24576,'length'),('extent-long',b'A',0,24576,'length_long')]:
        data=bytearray(base)
        extent=bytes([mode])+hashlib.shake_256(b'AlvenX03c actual user data '+seed).digest(2304)
        if seed==b'sentinel':extent=b'\xa5'*2305
        data[offset:offset+len(extent)]=extent
        struct.pack_into('<8sIIQQ',data,64,b'ALVXDATA',1,32,offset,len(extent))
        if mutation=='overflow':struct.pack_into('<Q',data,80,(1<<64)-8)
        if mutation=='overlap':struct.pack_into('<Q',data,80,8192)
        if mutation=='range':struct.pack_into('<Q',data,80,65536-16)
        if mutation=='magic':data[64]=0
        if mutation=='version':struct.pack_into('<I',data,72,2)
        if mutation=='header_size':struct.pack_into('<I',data,76,16)
        if mutation=='length':struct.pack_into('<Q',data,88,0)
        if mutation=='length_long':struct.pack_into('<Q',data,88,8193)
        path=out/(name+'.img');path.write_bytes(data)
        images[name]={'file':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
            'extent_offset':offset,'extent_bytes':len(extent),'data_sha256':hashlib.sha256(extent).hexdigest(),
            'expected_error':'length' if mutation=='length_long' else mutation,'expected_output_hex':extent.hex() if mutation is None else None,
            'exit_code':91 if mutation is None else None,'explicit_close':mode==0}
    a=(out/'data-a.img').read_bytes();b=(out/'data-b.img').read_bytes()
    assert a[:24576]==b[:24576] and a[24576+2305:]==b[24576+2305:] and a!=b
    config=b'[inject-error]\nevent = "read_aio"\nerrno = "5"\nsector = "48"\nonce = "on"\n'
    (out/'ioerr.conf').write_bytes(config)
    record={'role':'controlled extent inputs, not filesystem','source_elf':{'file':'user/fd_read.elf','bytes':len(elf),
        'sha256':hashlib.sha256(elf).hexdigest()},'images':images,'ioerr':{'file':'ioerr.conf','sector':48,
        'sha256':hashlib.sha256(config).hexdigest(),'once':True},'a_b_only_extent_differs':True}
    (out/'inputs.json').write_text(json.dumps(record,indent=2)+'\n')

if __name__=='__main__':main()
