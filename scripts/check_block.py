#!/usr/bin/env python3
"""03a development system-emulation checks, never independent acceptance."""
import argparse
import datetime
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time

from block_protocol import validate_image
from protocol import inspect_detailed
from provenance import ROOT, code_hashes, digest

SCENARIOS = {"image-a": ("A", False), "image-b": ("B", False),
             "absent": (None, False), "backend-ioerr": ("A", True)}


def cross_image_checks(scenarios):
    profiles = {s["name"]: s for s in scenarios}
    if not {"image-a", "image-b"} <= profiles.keys():
        return {"applies": False, "different_inputs_and_readback": None}
    a, b = profiles["image-a"], profiles["image-b"]
    def read_map(s):
        return {r["id"]: r for r in (s["runs"][0].get("block") or {}).get("reads", [])}
    ar, br = read_map(a), read_map(b)
    changed = [key for key in ar.keys() & br.keys() if ar[key]["offset"] == br[key]["offset"]
               and ar[key]["length"] == br[key]["length"] and ar[key]["data_hex"] != br[key]["data_hex"]]
    return {"applies": True, "different_inputs_and_readback": a["image_sha256"] != b["image_sha256"] and bool(changed),
            "same_address_read_ids_with_different_bytes": sorted(changed)}


def bound_inputs(kernel):
    build = kernel.parent
    source = json.loads((build / "inputs.json").read_text())
    if source["code_sha256"] != code_hashes():
        raise ValueError("code changed since this build; create a new artifact before execution")
    controlled = json.loads((build / "images/inputs.json").read_text())
    expected = source["controlled_block_inputs"]
    if expected != {"manifest_sha256": digest(build / "images/inputs.json"),
                    "images": controlled["images"], "backend_injection": controlled["backend_injection"]}:
        raise ValueError("controlled image metadata changed since build")
    required = {kernel, *(build / "user").glob("*.elf"), *(build / "images").glob("*")}
    sums = {}
    for line in (build / "SHA256SUMS").read_text().splitlines():
        sha, filename = line.split("  ", 1)
        path = Path(filename).resolve()
        if path in sums or not path.is_relative_to(build):
            raise ValueError("invalid or repeated checksum path")
        sums[path] = sha
    if set(sums) != required or any(digest(p) != sha for p, sha in sums.items()):
        raise ValueError("build artifact differs from original checksum manifest")
    for name, item in controlled["images"].items():
        if item["file"] != f"{name}.img":
            raise ValueError("invalid image basename")
        path = build / "images" / item["file"]
        if path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
            raise ValueError("controlled raw input changed")
    if digest(build / "images/ioerr.conf") != controlled["backend_injection"]["sha256"]:
        raise ValueError("backend injection configuration changed")
    return source, controlled, sums


def command(kernel, image, inject):
    result = ["qemu-system-riscv64", "-machine", "virt", "-cpu", "rv64", "-smp", "1",
              "-m", "128M", "-accel", "tcg,thread=single", "-icount", "shift=0,align=off,sleep=off",
              "-nographic", "-monitor", "none", "-nic", "none", "-no-reboot", "-bios", "default",
              "-kernel", str(kernel), "-global", "virtio-mmio.force-legacy=false"]
    if image is not None:
        filename = f"blkdebug:{kernel.parent}/images/ioerr.conf:{image}" if inject else str(image)
        result += ["-drive", f"if=none,id=blk0,file={filename},format=raw,readonly=on,rerror=report",
                   "-device", "virtio-blk-device,drive=blk0,bus=virtio-mmio-bus.0,num-queues=1,queue-size=8,request-merging=off"]
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--repeat", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--scenario", choices=("all", *SCENARIOS), default="all")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    kernel = (args.kernel or Path((ROOT / "build/LAST_BUILD").read_text().strip()) / "alvenx.elf").resolve()
    if not kernel.is_file() or not kernel.is_relative_to(ROOT / "build"):
        parser.error("kernel must be an existing artifact under native/build")
    try:
        inputs, controlled, original_sums = bound_inputs(kernel)
    except (ValueError, KeyError, OSError) as error:
        parser.error(str(error))
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    out = (args.output or ROOT / "results" / f"stage03a-run-{stamp}").resolve()
    if not out.is_relative_to(ROOT / "results"):
        parser.error("output must be a new directory under native/results")
    out.mkdir(parents=True, exist_ok=False)
    report = {"role": "03a development tests; independent technical acceptance pending; user display acceptance pending",
              "kernel": str(kernel), "kernel_sha256": digest(kernel), "build_inputs": inputs,
              "source_sha256": code_hashes(), "controlled_inputs": controlled,
              "user_elf_sha256": {p.name: digest(p) for p in sorted((kernel.parent / "user").glob("*.elf"))},
              "qemu_version": subprocess.check_output(["qemu-system-riscv64", "--version"], text=True).strip(),
              "python_version": sys.version, "new_official_score": None,
              "measurement": "read polling and existing yield counters use guest virtual ticks, not a storage benchmark or hardware latency",
              "scenarios": []}
    selected = SCENARIOS if args.scenario == "all" else {args.scenario: SCENARIOS[args.scenario]}
    for name, (image_id, injection) in selected.items():
        image = kernel.parent / "images" / f"{image_id}.img" if image_id else None
        expected_bytes = image.read_bytes() if image is not None else None
        cmd = command(kernel, image, injection)
        scenario = {"name": name, "command": cmd, "disk_readonly": image is not None,
                    "image": str(image) if image else None, "image_sha256": digest(image) if image else None,
                    "image_bytes": len(expected_bytes) if expected_bytes is not None else 0,
                    "device_error_origin": "QEMU blkdebug backend EIO injection on valid sector 7, once" if injection else "no backend injection",
                    "timeout_origin": "driver hides completion and reset acknowledgement; explicitly injected controls",
                    "runs": []}
        folder = out / name
        folder.mkdir()
        for index in range(1, args.repeat + 1):
            start = time.monotonic_ns()
            try:
                process = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, timeout=30)
                code, raw = process.returncode, process.stdout
            except subprocess.TimeoutExpired as error:
                code, raw = 124, error.stdout or b""
            wall_ms = (time.monotonic_ns() - start) / 1_000_000
            log = folder / f"run-{index}.log"
            log.write_bytes(raw)
            parsed = inspect_detailed(raw.decode("utf-8", errors="replace").replace("\r\n", "\n"))
            checks = dict(parsed.checks)
            checks["parser_has_no_errors"] = bool(checks) and not parsed.errors
            checks.update(validate_image(getattr(parsed, "block", None) or {}, expected_bytes, injection))
            checks["qemu_exit"] = code == 0
            scenario["runs"].append({"index": index, "exit_code": code, "host_wall_ms": wall_ms,
                                      "raw_log_sha256": digest(log), "checks": checks, "parse_errors": parsed.errors,
                                      "metrics": parsed.metrics, "memory": parsed.memory,
                                      "block": getattr(parsed, "block", None)})
            print(f"scenario={name} run={index} exit={code} development_checks={all(checks.values())} host_wall_ms={wall_ms:.3f}", flush=True)
        scenario["image_unchanged"] = image is None or digest(image) == scenario["image_sha256"]
        report["scenarios"].append(scenario)
    report["all_build_artifacts_unchanged"] = all(digest(p) == sha for p, sha in original_sums.items())
    report["source_unchanged"] = code_hashes() == inputs["code_sha256"]
    report["cross_image_check"] = cross_image_checks(report["scenarios"])
    report["all_development_checks"] = (report["all_build_artifacts_unchanged"] and report["source_unchanged"]
        and (not report["cross_image_check"]["applies"] or report["cross_image_check"]["different_inputs_and_readback"])
        and all(s["image_unchanged"] and s["runs"] and all(all(r["checks"].values()) for r in s["runs"])
                for s in report["scenarios"]))
    report["host_wall_ms_median"] = statistics.median(r["host_wall_ms"] for s in report["scenarios"] for r in s["runs"])
    (out / "results.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"Evidence retained at {out}")
    return 0 if report["all_development_checks"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
