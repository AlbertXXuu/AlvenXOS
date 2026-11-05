#!/usr/bin/env python3
"""Synthetic Stage02 parser regression; never executes a kernel or QEMU."""
import argparse
import datetime
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
from protocol import inspect_detailed
from provenance import digest
from test_log_parser import replace_field


def build_cases(text, stage01):
    original = text.splitlines()
    cases = []

    def add(name, lines, expected=False):
        cases.append((name, "\n".join(lines) + "\n", expected))

    def edit(name, prefix, field, value):
        found = [i for i, line in enumerate(original) if line.startswith(prefix)]
        assert len(found) == 1, prefix
        lines = list(original)
        lines[found[0]] = replace_field(lines[found[0]], field, value)
        add(name, lines)

    def field_value(line, field):
        return int(re.search(rf"\b{field}=([^\s]+)", line)[1], 0)

    add("original_stage02_real_log_replayed", original, True)
    add("original_stage01_real_log_replayed", stage01.splitlines(), True)
    start = next(i for i, line in enumerate(original) if line.startswith("ALVENX native "))
    # Every event is mandatory and unique, including each fault/access/rollback.
    for index in range(start, len(original)):
        if not original[index]:
            continue
        add(f"missing_event_{index - start:02}", original[:index] + original[index + 1:])
        add(f"duplicate_event_{index - start:02}", original[:index] + [original[index]] + original[index:])
    for field, value in {"permanent_pages": 0, "text_start": "0x80200002", "text_flags": 14,
                         "rodata_flags": 6, "data_flags": 14, "wx_leaves": 1,
                         "text_write_aliases": 1, "data_end": "0x80400000"}.items():
        edit(f"bad_kernel_layout_{field}", "KERNEL_LAYOUT ", field, value)
    # Mutate the entire ledger together. Field-at-a-time negatives cannot
    # expose a checker that lets a transcript redefine its resident baseline.
    for baseline in (1, 2, 3, 4, 5, 8):
        lines = []
        for line in original:
            if line.startswith("KERNEL_LAYOUT "):
                line = replace_field(line, "permanent_pages", baseline)
            elif line.startswith("ELF_ROLLBACK "):
                for field in ("used_before", "used_after", "recovered_used"):
                    line = replace_field(line, field, baseline)
            elif line.startswith("MEMORY "):
                total, high = field_value(line, "total_pages"), field_value(line, "high_water_pages")
                line = replace_field(line, "allocated_pages", baseline)
                line = replace_field(line, "free_pages", total - baseline)
                line = replace_field(line, "high_water_pages", high + baseline - 3)
            lines.append(line)
        add(f"coordinated_resident_baseline_{baseline}", lines, baseline == 3)
    for name in ("write_text", "write_rodata", "execute_data"):
        for field, value in {"cause": 2, "stval": "0x40000000", "pc": "0x10000", "spp": 0}.items():
            edit(f"bad_s_probe_{name}_{field}", f"KERNEL_PROBE name={name} ", field, value)
    edit("supervisor_nx_pc_must_be_data_not_resume_text", "KERNEL_PROBE name=execute_data ", "pc", "0x80200000")
    for pid in (4, 5, 6):
        for field, value in {"cause": 2, "stval": "0x40000000", "pc": "0x40000000"}.items():
            edit(f"bad_u_fault_{pid}_{field}", f"USER_FAULT pid={pid} ", field, value)
    for pid in range(1, 7):
        for field, value in {"text_flags": 30, "stack_flags": 30, "guard_mapped": 1,
                             "wx_leaves": 1, "kernel_text_write_aliases": 1}.items():
            edit(f"bad_user_access_{pid}_{field}", f"USER_ACCESS phase=0 pid={pid} ", field, value)
    for case in ("overlap", "quota", "permissions"):
        for field, value in {"error": "wrong_error", "used_before": 1, "used_after": 1,
                             "freed": 63, "recovery_allocated": 0, "recovery_freed": 0,
                             "recovered_used": 1, "reject_ticks": 0, "recovery_ticks": 0,
                             "timebase_hz": 1}.items():
            edit(f"bad_rollback_{case}_{field}", f"ELF_ROLLBACK case={case} ", field, value)
    for case in ("overlap", "quota"):
        lines = [replace_field(replace_field(l, "allocated", 0), "freed", 0)
                 if l.startswith(f"ELF_ROLLBACK case={case} ") else l for l in original]
        add(f"preflight_only_cannot_claim_partial_{case}_rollback", lines)
    for case in ("overlap", "quota", "permissions"):
        lines = [replace_field(replace_field(l, "recovery_allocated", 1), "recovery_freed", 1)
                 if l.startswith(f"ELF_ROLLBACK case={case} ") else l for l in original]
        add(f"impossible_single_frame_recovery_{case}", lines)
    lines = [replace_field(replace_field(l, "allocated", 1), "freed", 1)
             if l.startswith("ELF_ROLLBACK case=overlap ") else l for l in original]
    add("impossible_single_frame_overlap_allocation", lines)
    for phase in (0, 1, 2):
        for field, value in {"allocated_pages": 1, "free_pages": 0, "high_water_pages": 3,
                             "total_pages": 0, "page_bytes": 8192}.items():
            edit(f"bad_memory_{phase}_{field}", f"MEMORY phase={phase} ", field, value)
    for phase in (1, 2):
        for field, value in {"iterations_per_task": 42, "yield_calls": 2, "switches": 0,
                             "guest_time_ticks": 0, "guest_virtual_ns": 0, "timebase_hz": 0}.items():
            edit(f"bad_metric_{phase}_{field}", f"METRIC yield phase={phase} ", field, value)
        edit(f"benchmark_timer_on_{phase}", f"BENCH_BEGIN phase={phase} ", "timer", "on")
    edit("unknown_version", "ALVENX native ", "version", "99.0.0")
    edit("new_protocol_with_old_banner", "ALVENX native ", "version", "0.1.0")
    add("old_protocol_with_new_banner", [replace_field(l, "version", "0.2.0")
                                       if l.startswith("ALVENX native ") else l for l in stage01.splitlines()])
    add("mixed_versions", original + stage01.splitlines())
    for prefix in ("KERNEL_LAYOUT ", "KERNEL_PROBE name=execute_data ", "ELF_ROLLBACK case=quota ",
                   "USER_ACCESS phase=0 pid=6 "):
        line = next(l for l in original if l.startswith(prefix))
        label = prefix.split()[0].lower()
        add(f"before_boot_{label}", [line] + original)
        add(f"indented_before_boot_{label}", [" " + line] + original)
        add(f"repeated_field_{label}", [l + " impossible=1 impossible=2" if l == line else l for l in original])
        add(f"huge_integer_{label}", [l + " impossible=18446744073709551616" if l == line else l for l in original])
    add("failure_after_success", original + ["KERNEL FAIL synthetic regression"])
    add("indented_failure_after_success", original + ["  KERNEL FAIL synthetic regression"])
    add("indented_boot", [" " + l if l.startswith("ALVENX native ") else l for l in original])
    # Old masking failure: omit phase2 task/metric rows and duplicate phase1.
    lines = []
    for line in original:
        if line.startswith(("TASK phase=2 ", "METRIC yield phase=2 ")):
            continue
        lines.append(line)
        if line.startswith("METRIC yield phase=1 "):
            lines.append(line)
    add("missing_phase2_duplicate_phase1_metric", lines)
    fault5 = next(l for l in original if l.startswith("USER_FAULT pid=5 "))
    add("fault5_replaces_fault6", [fault5 if l.startswith("USER_FAULT pid=6 ") else l for l in original])
    lines = list(original)
    at = next(i for i, l in enumerate(lines) if l.startswith("USER_FAULT pid=5 "))
    lines.insert(at, replace_field(lines[at], "cause", 2))
    add("bad_fault_shadowed_by_good_duplicate", lines)
    root = next(l for l in original if l.startswith("KERNEL_LAYOUT ")).split("root=", 1)[1].split()[0]
    edit("isolation_data_aliases_kernel_root", "ISOLATION ", "pa_a", root)
    positions = [i for i, l in enumerate(original) if l.startswith(("USER worker=", "USER_FAULT "))]
    lines = list(original)
    for at, value in zip(positions, [original[i] for i in positions][::-1]):
        lines[at] = value
    add("valid_runtime_event_reordering", lines, True)
    add("valid_key_field_reordering", ["KERNEL_LAYOUT " + " ".join(reversed(l.split()[1:]))
                                      if l.startswith("KERNEL_LAYOUT ") else l for l in original], True)
    lines = []
    for line in original:
        if line.startswith("METRIC yield "):
            ticks, hz = field_value(line, "guest_time_ticks") + 123, field_value(line, "timebase_hz")
            line = replace_field(line, "guest_time_ticks", ticks)
            line = replace_field(line, "guest_virtual_ns", ticks * 1_000_000_000 // hz)
        elif line.startswith("ELF_ROLLBACK "):
            for field in ("reject_ticks", "recovery_ticks"):
                line = replace_field(line, field, field_value(line, field) + 7)
        lines.append(line)
    add("valid_alternative_measured_timing", lines, True)
    add("valid_higher_cumulative_high_water", [replace_field(l, "high_water_pages", field_value(l, "high_water_pages") + 7)
                                             if l.startswith("MEMORY ") else l for l in original], True)
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--stage01-log", type=Path, required=True)
    parser.add_argument("--rejected-log", type=Path)
    parser.add_argument("--baseline-counterexample", type=Path,
                        help="retained independent synthetic baseline-drift counterexample")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    out = args.output or Path(__file__).resolve().parent.parent / "results" / f"stage02-parser-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    cases = build_cases(args.log.read_text(), args.stage01_log.read_text())
    if args.rejected_log:
        cases.append(("historical_prototype_log_rejected", args.rejected_log.read_text(), False))
    if args.baseline_counterexample:
        cases.append(("independent_four_page_baseline_masks_extra_resident_frame",
                      args.baseline_counterexample.read_text(), False))
    report = {"role": "parser regression; synthetic mutations are not kernel tests",
              "qemu_executed": False, "kernel_rebuilt": False,
              "sources": {str(p.resolve()): digest(p) for p in (args.log, args.stage01_log, args.rejected_log,
                                                              args.baseline_counterexample) if p},
              "verifier_sha256": {p.name: digest(p) for p in (Path(__file__), Path(__file__).with_name("protocol.py"),
                                    Path(__file__).with_name("stage02_parser.py"), Path(__file__).with_name("log_parser.py"))},
              "git_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=Path(__file__).parent, text=True).strip(),
              "git_status": subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=Path(__file__).parent, text=True).strip(),
              "cases": []}
    for index, (name, text, expected) in enumerate(cases):
        result = inspect_detailed(text)
        accepted = bool(result.checks) and not result.errors and all(result.checks.values())
        path = out / f"{index:03}-{name}.log"
        path.write_text(text, encoding="utf-8")
        report["cases"].append({"name": name, "expected_acceptance": expected, "accepted": accepted,
                                "input_kind": "original log replay" if index < 2 or name == "historical_prototype_log_rejected" else "synthetic",
                                "matched_expectation": accepted == expected, "errors": result.errors,
                                "checks": result.checks, "input": path.name, "input_sha256": digest(path)})
    report["all_expectations_matched"] = all(c["matched_expectation"] for c in report["cases"])
    (out / "regression.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"cases={len(cases)} expectations_matched={report['all_expectations_matched']} qemu_executed=false")
    print(f"Retained parser evidence: {out}")
    return 0 if report["all_expectations_matched"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
