#!/usr/bin/env python3
"""Recheck retained logs with the current parser; never build or launch QEMU."""
import argparse
import datetime
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from protocol import inspect_detailed
from provenance import ROOT, code_hashes, digest

VERIFIER_FILES = {"scripts/check.py", "scripts/log_parser.py", "scripts/test_log_parser.py",
                  "scripts/replay_logs.py", "scripts/protocol.py", "scripts/stage02_parser.py",
                  "scripts/test_stage02_parser.py"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=Path, required=True, help="original native results.json")
    parser.add_argument("--extra-log", type=Path, action="append", default=[],
                        help="additional retained real log expected to parse successfully")
    parser.add_argument("--expect-rejection", type=Path, action="append", default=[],
                        help="retained failed real log expected to be rejected")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    original = json.loads(args.record.read_text(encoding="utf-8"))
    kernel = Path(original["kernel"]).resolve()
    if not kernel.is_relative_to(ROOT / "build") or not kernel.is_file():
        parser.error("original kernel must still exist under native/build")
    inputs = kernel.parent / "inputs.json"
    build = json.loads(inputs.read_text(encoding="utf-8"))
    indices = [r["index"] for r in original["runs"]]
    if not indices or any(type(i) is not int for i in indices) or indices != list(range(1, len(indices) + 1)):
        parser.error("original run indices must be unique, ordered and complete")
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    out = args.output or ROOT / "results" / f"parser-replay-{run_id}"
    out.mkdir(parents=True, exist_ok=False)
    old_inputs = build["code_sha256"]
    current = code_hashes()
    changed = sorted(k for k in old_inputs.keys() | current.keys() if old_inputs.get(k) != current.get(k))
    non_verifier_changes = [k for k in changed if k not in VERIFIER_FILES]
    artifacts_ok = digest(kernel) == original["kernel_sha256"]
    user_hashes = {}
    for name, expected in original["user_elf_sha256"].items():
        if Path(name).name != name or not name.endswith(".elf"):
            parser.error("invalid user ELF basename in original record")
        artifact = kernel.parent / "user" / name
        user_hashes[name] = digest(artifact)
        artifacts_ok &= user_hashes[name] == expected
    binding = {
        "status": "verified" if (artifacts_ok and original["build_inputs"] == build
                                  and original["source_sha256"] == old_inputs) else "mismatch",
        "kernel": str(kernel), "kernel_sha256_at_replay": digest(kernel),
        "original_kernel_sha256": original["kernel_sha256"], "user_elf_sha256_at_replay": user_hashes,
        "original_build_inputs_sha256": digest(inputs),
        "original_build_commit": build["git_revision_at_build"],
        "original_build_status": build["git_status_at_build"],
        "original_checker_sha256": old_inputs.get("scripts/check.py"),
        "changed_verifier_inputs": changed, "non_verifier_code_changes": non_verifier_changes,
    }
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=ROOT, text=True).strip()
    report = {
        "mode": "replay", "role": "developer parser replay; not new kernel execution or independent acceptance",
        "qemu_executed": False, "kernel_rebuilt": False,
        "original_execution_role": original["role"],
        "original_record": str(args.record.resolve()), "original_results_json_sha256": digest(args.record),
        "original_qemu_version": original["qemu_version"], "original_command": original["command"],
        "artifact_binding": binding,
        "current_verifier_commit": revision, "current_verifier_status": status,
        "current_verifier_sha256": {name: digest(ROOT / name) for name in sorted(VERIFIER_FILES)},
        "log_hash_note": "Replay hashes are checked against original raw_log_sha256 where recorded; absent original hashes are not inferred.",
        "logs": [],
    }
    sources = [(args.record.parent / f"run-{r['index']}.log", True, r) for r in original["runs"]]
    sources += [(p, True, None) for p in args.extra_log]
    sources += [(p, False, None) for p in args.expect_rejection]
    resolved_paths = [p.resolve() for p, _, _ in sources]
    if len(set(resolved_paths)) != len(resolved_paths):
        parser.error("each retained log path must occur only once")
    for path, expected, prior in sources:
        path = path.resolve()
        if not path.is_relative_to(ROOT.parent) or path.suffix != ".log":
            parser.error("replay log must be an explicit .log under the project workspace")
        actual_log_hash = digest(path)
        original_log_hash = prior.get("raw_log_sha256") if prior is not None else None
        log_binding_ok = original_log_hash is None or original_log_hash == actual_log_hash
        parsed = inspect_detailed(path.read_text(encoding="utf-8"))
        accepted = bool(parsed.checks) and not parsed.errors and all(parsed.checks.values())
        if prior is not None:
            accepted &= prior["exit_code"] == 0 and log_binding_ok
        report["logs"].append({
            "path": str(path), "sha256_at_replay": actual_log_hash,
            "original_log_sha256": original_log_hash,
            "original_log_hash_matches": log_binding_ok if original_log_hash is not None else None,
            "input_kind": "retained real log; parser replay only",
            "expected_acceptance": expected, "accepted": accepted,
            "matched_expectation": accepted == expected, "checks": parsed.checks, "errors": parsed.errors,
            "metrics": parsed.metrics, "memory": parsed.memory,
            "original_run_index": prior["index"] if prior else None,
            "original_exit_code": prior["exit_code"] if prior else None,
            "original_host_wall_ms": prior["host_wall_ms"] if prior else None,
            "artifact_binding": ("original execution record verified"
                                 if binding["status"] == "verified" and log_binding_ok else "mismatch")
                                if prior else "not inferred from standalone log",
        })
    report["all_expectations_matched"] = (
        binding["status"] == "verified" and not non_verifier_changes
        and all(row["matched_expectation"] for row in report["logs"])
    )
    with (out / "replay.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    print(f"real_logs_replayed={len(sources)} expectations_matched={report['all_expectations_matched']} qemu_executed=false kernel_rebuilt=false")
    print(f"Retained replay evidence: {out}")
    return 0 if report["all_expectations_matched"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
