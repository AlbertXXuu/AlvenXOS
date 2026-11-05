#!/usr/bin/env python3
"""Create controlled raw block inputs. These are not a filesystem or OS image."""
import hashlib
import json
from pathlib import Path
import sys


def main():
    out = Path(sys.argv[1]).resolve()
    out.mkdir(exist_ok=False)
    images = {}
    for name, sectors in (("A", 64), ("B", 96)):
        data = hashlib.shake_256(f"AlvenX stage03a raw fixture {name} v1".encode()).digest(sectors * 512)
        (out / f"{name}.img").write_bytes(data)
        images[name] = {"file": f"{name}.img", "bytes": len(data), "sectors": sectors,
                        "sha256": hashlib.sha256(data).hexdigest()}
    config = b'[inject-error]\nevent = "read_aio"\nerrno = "5"\nsector = "7"\nonce = "on"\n'
    (out / "ioerr.conf").write_bytes(config)
    manifest = {"role": "controlled raw input; no filesystem; expected bytes never embedded in kernel",
                "sector_bytes": 512, "images": images,
                "backend_injection": {"file": "ioerr.conf", "sector": 7, "errno": 5,
                                      "once": True, "sha256": hashlib.sha256(config).hexdigest()}}
    (out / "inputs.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
