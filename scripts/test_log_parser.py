#!/usr/bin/env python3
"""Synthetic parser regression cases. These do not execute QEMU or a kernel."""
import argparse
import datetime
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
from log_parser import inspect_detailed
from provenance import digest


def replace_field(line, name, value):
    result, count = re.subn(rf"\b{re.escape(name)}=[^\s]+", f"{name}={value}", line)
    assert count == 1, (name, line)
    return result


def build_cases(text):
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

    add("original_real_log_replayed", original, True)
    lines = []
    for line in original:
        if line.startswith(("TASK phase=2 ", "METRIC yield phase=2 ")):
            continue
        lines.append(line)
        if line.startswith("METRIC yield phase=1 "):
            lines.append(line)
    add("acceptance_missing_phase2_duplicate_phase1_metric", lines)
    first_memory = next(l for l in original if l.startswith("MEMORY phase=0 "))
    add("acceptance_memory_phase0_repeated", [first_memory if l.startswith("MEMORY ") else l for l in original])

    for name, prefix in (
        ("missing_boot", "ALVENX native "), ("missing_platform", "PLATFORM "),
        ("missing_allocator_test", "TEST frame_allocator "),
        ("missing_elf_test", "TEST elf_reject "),
        ("missing_load", "LOAD phase=0 pid=4 "),
        ("missing_task", "TASK phase=2 pid=2 "),
        ("missing_benchmark_begin", "BENCH_BEGIN phase=2 "),
        ("missing_metric", "METRIC yield phase=2 "),
        ("missing_memory_phase", "MEMORY phase=1 "),
        ("missing_user_output", "USER worker=A "),
        ("missing_fault", "USER_FAULT "),
        ("missing_functional_summary", "TEST user_syscalls_registers_isolation_timer "),
        ("missing_result", "RESULT "),
    ):
        add(name, [l for l in original if not l.startswith(prefix)])

    for name, prefix in (
        ("duplicate_load", "LOAD phase=1 pid=1 "),
        ("duplicate_task", "TASK phase=0 pid=1 "),
        ("duplicate_begin", "BENCH_BEGIN phase=1 "),
        ("duplicate_metric", "METRIC yield phase=1 "),
        ("duplicate_memory", "MEMORY phase=1 "),
        ("duplicate_result", "RESULT "),
        ("duplicate_user_output", "USER worker=A "),
    ):
        lines = []
        for line in original:
            lines.append(line)
            if line.startswith(prefix):
                lines.append(line)
        add(name, lines)

    for before in (True, False):
        lines = []
        for line in original:
            if line.startswith("TASK phase=0 pid=1 "):
                failed = replace_field(replace_field(line, "state", 3), "exit", 99)
                lines.extend([failed, line] if before else [line, failed])
            else:
                lines.append(line)
        add(f"failure_task_shadowed_{'before' if before else 'after'}", lines)

    lines = [replace_field(replace_field(l, "pid", 1), "exit", 51)
             if l.startswith("TASK phase=1 pid=2 ") else l for l in original]
    add("duplicate_pid_with_individually_valid_benchmark_tasks", lines)
    load_one = next(l for l in original if l.startswith("LOAD phase=0 pid=1 "))
    add("duplicate_load_to_preserve_count", [load_one if l.startswith("LOAD phase=0 pid=2 ") else l for l in original])

    first = next(i for i, l in enumerate(original) if l.startswith("LOAD phase=1 "))
    second = next(i for i, l in enumerate(original) if l.startswith("LOAD phase=2 "))
    result_at = next(i for i, l in enumerate(original) if l.startswith("RESULT "))
    add("complete_benchmark_phases_reversed", original[:first] + original[second:result_at]
        + original[first:second] + original[result_at:])
    add("result_before_phase2", original[:second] + original[result_at:]
        + original[second:result_at])
    lines = list(original)
    task_at = next(i for i, l in enumerate(lines) if l.startswith("TASK phase=1 pid=1 "))
    metric_at = next(i for i, l in enumerate(lines) if l.startswith("METRIC yield phase=1 "))
    lines[task_at], lines[metric_at] = lines[metric_at], lines[task_at]
    add("metric_before_tasks", lines)

    mutations = (
        ("unknown_phase", "METRIC yield phase=2 ", "phase", 3),
        ("wrong_workload", "METRIC yield phase=2 ", "iterations_per_task", 1000),
        ("contradictory_begin", "BENCH_BEGIN phase=1 ", "iterations_per_task", 999),
        ("benchmark_timer_on", "BENCH_BEGIN phase=1 ", "timer", "on"),
        ("wrong_yield_calls", "METRIC yield phase=1 ", "yield_calls", 1999),
        ("wrong_switches", "METRIC yield phase=1 ", "switches", 1999),
        ("wrong_timebase", "METRIC yield phase=1 ", "timebase_hz", 20000000),
        ("zero_timebase", "METRIC yield phase=1 ", "timebase_hz", 0),
        ("zero_switches", "METRIC yield phase=1 ", "switches", 0),
        ("invented_positive_time", "METRIC yield phase=1 ", "guest_virtual_ns", 123456),
        ("zero_ticks", "METRIC yield phase=1 ", "guest_time_ticks", 0),
        ("invalid_number", "METRIC yield phase=1 ", "guest_time_ticks", "nan"),
        ("negative_number", "MEMORY phase=1 ", "free_pages", -1),
        ("oversized_number", "METRIC yield phase=1 ", "guest_time_ticks", 2**64),
        ("worker_wrong_runs", "TASK phase=0 pid=1 ", "runs", 1),
        ("worker_failure_exit", "TASK phase=0 pid=1 ", "exit", 99),
        ("wrong_task_yields", "TASK phase=1 pid=1 ", "yields", 999),
        ("wrong_benchmark_runs", "TASK phase=1 pid=1 ", "runs", 1001),
        ("timer_in_benchmark", "TASK phase=1 pid=1 ", "timers", 1),
        ("write_in_benchmark", "TASK phase=1 pid=1 ", "writes", 1),
        ("efault_with_output", "TASK phase=0 pid=3 ", "writes", 1),
        ("fault_summary_contradiction", "TASK phase=0 pid=4 ", "fault", 15),
        ("fault_address_contradiction", "USER_FAULT ", "stval", "0x10000"),
        ("wrong_timer_total", "TEST user_syscalls_registers_isolation_timer PASS ", "timer_traps", 999),
        ("zero_timer_switches", "TEST user_syscalls_registers_isolation_timer PASS ", "timer_switches", 0),
        ("memory_total_changes", "MEMORY phase=1 ", "total_pages", 99999),
        ("memory_free_mismatch", "MEMORY phase=1 ", "free_pages", 0),
        ("memory_page_size_changes", "MEMORY phase=1 ", "page_bytes", 8192),
        ("memory_high_exceeds_total", "MEMORY phase=1 ", "high_water_pages", 99999),
        ("memory_high_decreases", "MEMORY phase=1 ", "high_water_pages", 1),
        ("wrong_final_case_count", "RESULT ", "benchmark_cases", 1),
        ("reported_official_score", "RESULT ", "official_score", 100),
        ("failed_result", "RESULT ", "functional", "FAIL"),
        ("boot_hart_mismatch", "ALVENX native ", "hart", 1),
        ("dtb_boundary_mismatch", "PLATFORM ", "reserved_fdt_start", "0x87f00000"),
        ("unaligned_root", "LOAD phase=0 pid=1 ", "root", "0x80222001"),
    )
    for args in mutations:
        edit(*args)

    root_one = re.search(r"root=([^ ]+)", load_one)[1]
    edit("same_root_different_hex_spelling", "LOAD phase=0 pid=2 ", "root", f"0x{int(root_one, 16):016x}")
    for name, change in (
        ("missing_field", lambda l: re.sub(r" runs=[^ ]+", "", l)),
        ("extra_field", lambda l: l + " status=PASS"),
        ("duplicate_field_fail_then_pass", lambda l: l.replace("state=2", "state=3 state=2")),
        ("duplicate_field_pass_then_fail", lambda l: l.replace("state=2", "state=2 state=3")),
    ):
        add(name, [change(l) if l.startswith("TASK phase=0 pid=1 ") else l for l in original])

    for name, failure in (
        ("kernel_failure_then_success", "KERNEL FAIL synthetic diagnostic"),
        ("failed_test_then_success", "TEST frame_allocator FAIL synthetic"),
        ("extra_user_fault", "USER_FAULT pid=1 cause=13 pc=0x10000 stval=0x80200000"),
    ):
        add(name, original[:first] + [failure] + original[first:])
    add("fatal_after_success", original + ["FATAL SBI shutdown returned (-1, 0)"])
    add("failure_before_boot", ["KERNEL FAIL synthetic diagnostic"] + original)
    add("success_text_only", ["RESULT functional=PASS benchmark_cases=2 official_score=UNMEASURED"])
    add("success_and_invented_metrics_only", [l for l in original if l.startswith(("METRIC ", "RESULT ", "TEST "))])
    add("high_water_below_witnessed_live_frames", [replace_field(l, "high_water_pages", 1)
        if l.startswith("MEMORY ") else l for l in original])
    add("same_benchmark_elf_input_changes_between_phases", [replace_field(l, "elf_bytes", 9999)
        if l.startswith("LOAD phase=2 ") else l for l in original])
    add("indented_failure_before_boot", [" TEST frame_allocator FAIL synthetic"] + original)
    lines = []
    dtb = int(re.search(r"\bdtb=(\S+)", next(l for l in original if l.startswith("ALVENX native ")))[1], 16)
    for line in original:
        if line.startswith("ALVENX native "):
            line = replace_field(line, "dtb", hex(dtb + 8))
        if line.startswith("PLATFORM "):
            line = replace_field(line, "reserved_fdt_start", hex(dtb + 8))
        lines.append(line)
    add("synthetic_valid_dtb_partial_page_reservation", lines, True)
    add("root_page_overlaps_dtb_partial_page", [replace_field(l, "root", hex(dtb))
        if l.startswith("LOAD phase=0 pid=1 ") else l for l in lines])

    # Positive controls prove that timing values and concurrent event order
    # are not pinned to one historical transcript.
    lines = []
    for line in original:
        if line.startswith("METRIC yield "):
            hz = int(re.search(r"timebase_hz=(\d+)", line)[1])
            ticks = int(re.search(r"guest_time_ticks=(\d+)", line)[1]) + 123
            line = replace_field(replace_field(line, "guest_time_ticks", ticks),
                                 "guest_virtual_ns", ticks * 1_000_000_000 // hz)
        lines.append(line)
    add("synthetic_consistent_alternative_timing", lines, True)
    lines = list(original)
    positions = [i for i, l in enumerate(lines) if l.startswith(("USER worker=", "USER_FAULT "))]
    values = [lines[i] for i in positions][::-1]
    for i, value in zip(positions, values):
        lines[i] = value
    add("synthetic_valid_runtime_event_reordering", lines, True)
    lines = []
    for line in original:
        if line.startswith("TASK phase=0 pid=1 "):
            for key in ("timers", "runs"):
                old = int(re.search(rf"\b{key}=(\d+)", line)[1])
                line = replace_field(line, key, old + 1)
        if line.startswith("TEST user_syscalls_registers_isolation_timer PASS "):
            old = int(re.search(r"timer_traps=(\d+)", line)[1])
            line = replace_field(line, "timer_traps", old + 1)
        lines.append(line)
    add("synthetic_consistent_alternative_timer_count", lines, True)
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--legacy-parser", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = args.log.read_text(encoding="utf-8").replace("\r\n", "\n")
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    out = args.output or Path(__file__).resolve().parent.parent / "results" / f"parser-regression-{run_id}"
    out.mkdir(parents=True, exist_ok=False)
    cases = build_cases(text)
    report = {
        "role": "parser regression; mutated cases are synthetic, not QEMU executions",
        "qemu_executed": False, "kernel_rebuilt": False,
        "source_log": str(args.log.resolve()), "source_log_sha256": digest(args.log),
        "parser_sha256": digest(Path(__file__).with_name("log_parser.py")),
        "test_script_sha256": digest(Path(__file__)), "cases": [],
        "checker_sha256": digest(Path(__file__).with_name("check.py")),
        "normalization": "logical lines replayed with LF; original source bytes remain unchanged",
        "verifier_commit_at_run": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parent.parent, text=True).strip(),
        "verifier_status_at_run": subprocess.check_output(
            ["git", "status", "--porcelain=v1"], cwd=Path(__file__).resolve().parent.parent, text=True).strip(),
    }
    for index, (name, mutated, expected) in enumerate(cases):
        parsed = inspect_detailed(mutated)
        accepted = all(parsed.checks.values())
        path = out / f"{index:02d}-{name}.log"
        path.write_text(mutated, encoding="utf-8")
        report["cases"].append({"name": name, "input_kind": "original real log replay" if index == 0 else "synthetic",
                                "expected_acceptance": expected, "accepted": accepted,
                                "matched_expectation": accepted == expected,
                                "checks": parsed.checks, "errors": parsed.errors,
                                "input": path.name, "input_sha256": digest(path)})
    if args.legacy_parser:
        spec = importlib.util.spec_from_file_location("historical_development_checker", args.legacy_parser)
        legacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(legacy)
        report["legacy_reproduction"] = {
            "parser": str(args.legacy_parser.resolve()), "sha256": digest(args.legacy_parser),
            "original_accepted": all(legacy.inspect(text)[0].values()),
            "known_counterexamples": {name: all(legacy.inspect(value)[0].values())
                                      for name, value, _ in cases if name.startswith("acceptance_")},
        }
    report["all_expectations_matched"] = all(c["matched_expectation"] for c in report["cases"])
    with (out / "regression.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    print(f"cases={len(cases)} expectations_matched={report['all_expectations_matched']} qemu_executed=false")
    print(f"Retained regression evidence: {out}")
    return 0 if report["all_expectations_matched"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
