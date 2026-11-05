#!/usr/bin/env python3
"""Record code inputs and installed tool versions for one immutable build."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED = {".git", "build", "target", "results"}
CODE_SUFFIXES = {".rs", ".S", ".ld", ".toml", ".lock", ".sh", ".py"}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def code_hashes():
    # Prune the same excluded top-level trees before traversal. In particular,
    # immutable historical evidence must not add per-file /mnt/d latency here.
    paths = []
    for directory, children, names in os.walk(ROOT):
        if Path(directory) == ROOT:
            children[:] = [name for name in children if name not in EXCLUDED]
        paths.extend(Path(directory) / name for name in names
                     if Path(name).suffix in CODE_SUFFIXES)
    return {str(p.relative_to(ROOT)):digest(p) for p in sorted(paths) if p.is_file()}


def output(command):
    return subprocess.check_output(command, cwd=ROOT, text=True).strip()


def git_metadata(root=ROOT):
    """Do not borrow an enclosing repository's identity for a source export."""
    root = Path(root).resolve()
    marker = root / ".git"
    if not marker.exists() and not marker.is_symlink():
        return {"git_metadata_mode": "source-export", "git_metadata_available": False,
                "git_metadata_unavailable_reason": "repository .git marker absent",
                "git_revision_at_build": None, "git_status_at_build": None}

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, text=True,
                                       stderr=subprocess.PIPE).rstrip("\r\n")

    # A present but invalid marker is an error, not a reason to hide a broken
    # checkout as an export. Worktree .git files are supported by Git itself.
    if Path(git("rev-parse", "--show-toplevel")).resolve() != root:
        raise ValueError("Git metadata does not belong to this source root")
    return {"git_metadata_mode": "git-checkout", "git_metadata_available": True,
            "git_metadata_unavailable_reason": None,
            "git_revision_at_build": git("rev-parse", "--verify", "HEAD"),
            "git_status_at_build": git("status", "--porcelain=v1")}


if __name__ == "__main__":
    destination = Path(sys.argv[1]).resolve()
    assert destination.is_relative_to(ROOT / "build")
    record = {
        "code_sha256": code_hashes(),
        "rustc": output([str(Path.home() / ".cargo/bin/rustc"), "+nightly-2025-05-20", "-Vv"]),
        "assembler": output(["riscv64-linux-gnu-as", "--version"]),
        "linker": output(["riscv64-linux-gnu-ld", "--version"]),
        "cargo_args": "build --locked --offline --release --target riscv64gc-unknown-none-elf",
        "rustflags": "static relocation; native/linker.ld; --no-relax; opt-level=2; overflow checks enabled",
    }
    block_inputs = destination / "images/inputs.json"
    if block_inputs.is_file():
        manifest = json.loads(block_inputs.read_text())
        record["controlled_block_inputs"] = {
            "manifest_sha256": digest(block_inputs),
            "images": manifest["images"], "backend_injection": manifest["backend_injection"],
        }
    disk_inputs = destination / "blob/inputs.json"
    if disk_inputs.is_file():
        record["controlled_disk_inputs"] = {"manifest_sha256": digest(disk_inputs),
                                            "manifest": json.loads(disk_inputs.read_text())}
    fd_inputs = destination / "fd/inputs.json"
    if fd_inputs.is_file():
        record["controlled_fd_inputs"] = {"manifest_sha256":digest(fd_inputs),"manifest":json.loads(fd_inputs.read_text())}
    if (destination/'seek/inputs.json').is_file():
        record['controlled_seek_inputs']={'manifest_sha256':digest(destination/'seek/inputs.json'),'manifest':json.loads((destination/'seek/inputs.json').read_text())}
    record.update(git_metadata())
    with (destination / "inputs.json").open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
