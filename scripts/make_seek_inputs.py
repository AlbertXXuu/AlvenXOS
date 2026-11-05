import hashlib,json,struct,sys
from pathlib import Path
b=Path(sys.argv[1]);out=b/'seek';out.mkdir(exist_ok=False)
elf=(b/'user/seek_read.elf').read_bytes();assert len(elf)<=8192
images={}
for name,seed,mode,start in [('data-a',b'A',0,24576),('data-b',b'B',0,24576),('exit-cleanup',b'A',1,24576),('offset',b'A',0,28673)]:
 raw=bytearray(hashlib.shake_256(b'seek medium').digest(65536));raw[:512]=bytes(512)
 struct.pack_into('<8sIIQQQ',raw,0,b'ALVXELF\0',1,512,4096,16384,65536)
 struct.pack_into('<8sIIQQ',raw,64,b'ALVXDATA',1,32,start,2305)
 raw[4096:20480]=elf+bytes(16384-len(elf))
 data=bytes([mode])+hashlib.shake_256(b'seek data '+seed).digest(2304);raw[start:start+2305]=data
 p=out/(name+'.img');p.write_bytes(raw)
 images[name]={'file':p.name,'sha256':hashlib.sha256(raw).hexdigest(),'start':start,'length':2305,'explicit_close':mode==0,'exit_code':92}
(out/'ioerr.conf').write_bytes(b'[inject-error]\nevent = "read_aio"\nerrno = "5"\nsector = "48"\nonce = "on"\n')
(out/'inputs.json').write_text(json.dumps({'source_elf_sha256':hashlib.sha256(elf).hexdigest(),'images':images,'ioerr_sha256':hashlib.sha256((out/'ioerr.conf').read_bytes()).hexdigest()},indent=2)+'\n')
