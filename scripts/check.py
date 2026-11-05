#!/usr/bin/env python3
"""Development self-test of the native kernel in QEMU system emulation.

This records evidence for a separate reviewer; it is not independent acceptance.
"""
import argparse
import datetime
import json
from pathlib import Path
import statistics
import subprocess
import time
from provenance import code_hashes, digest
from protocol import inspect, inspect_detailed

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--repeat", type=int, choices=range(1, 6), default=3)
    args = parser.parse_args()
    kernel = (args.kernel or Path((ROOT / "build/LAST_BUILD").read_text().strip()) / "alvenx.elf").resolve()
    if not kernel.is_file() or not kernel.is_relative_to(ROOT / "build"):
        parser.error("kernel must be an existing local build artifact under native/build")
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    out = ROOT / "results" / run_id
    out.mkdir(parents=True, exist_ok=False)
    source_hashes = code_hashes()
    inputs_file = kernel.parent / "inputs.json"
    if not inputs_file.is_file():
        parser.error("build has no input provenance; create a new build with scripts/build.sh")
    build_inputs = json.loads(inputs_file.read_text())
    if source_hashes != build_inputs["code_sha256"]:
        parser.error("code changed since this build; build a new artifact before self-testing")
    command = [
        "qemu-system-riscv64", "-machine", "virt", "-cpu", "rv64", "-smp", "1",
        "-m", "128M", "-accel", "tcg,thread=single", "-icount", "shift=0,align=off,sleep=off",
        "-nographic", "-monitor", "none", "-nic", "none", "-no-reboot",
        "-bios", "default", "-kernel", str(kernel),
    ]
    version = subprocess.check_output(["qemu-system-riscv64", "--version"], text=True).strip()
    metadata = {
        "role": "development self-test; independent review pending",
        "kernel": str(kernel), "kernel_sha256": digest(kernel),
        "user_elf_sha256": {p.name: digest(p) for p in sorted((kernel.parent / "user").glob("*.elf"))},
        "source_sha256": source_hashes, "qemu_version": version, "command": command,
        "build_inputs": build_inputs,
        "measurement": "guest virtual time for whole user yield loop/trap/scheduling window; not real hardware latency",
        "runs": [],
    }
    for index in range(args.repeat):
        started = time.monotonic_ns()
        try:
            process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, timeout=30)
            code, raw = process.returncode, process.stdout
        except subprocess.TimeoutExpired as exc:
            code, raw = 124, exc.stdout or b""
        elapsed = (time.monotonic_ns() - started) / 1_000_000
        log_file = out / f"run-{index + 1}.log"
        log_file.write_bytes(raw)
        log = raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
        parsed = inspect_detailed(log)
        checks, metrics, memory = parsed.checks, parsed.metrics, parsed.memory
        checks["parser_has_no_errors"] = bool(checks) and not parsed.errors
        checks["qemu_exit"] = code == 0
        metadata["runs"].append({"index": index + 1, "exit_code": code,
                                 "raw_log_sha256": digest(log_file),
                                 "host_wall_ms": elapsed, "checks": checks,
                                 "metrics": metrics, "memory": memory, "parse_errors": parsed.errors})
        print(f"run={index + 1} exit={code} development_checks={all(checks.values())} host_wall_ms={elapsed:.3f}")
    metadata["all_development_checks"] = all(all(r["checks"].values()) for r in metadata["runs"])
    metadata["host_wall_ms"] = {
        "median": statistics.median(r["host_wall_ms"] for r in metadata["runs"]),
        "min": min(r["host_wall_ms"] for r in metadata["runs"]),
        "max": max(r["host_wall_ms"] for r in metadata["runs"]),
    }
    metadata["kernel_unchanged"] = digest(kernel) == metadata["kernel_sha256"]
    (out / "results.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n")
    print(f"Evidence retained at {out}")
    return 0 if metadata["all_development_checks"] and metadata["kernel_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
