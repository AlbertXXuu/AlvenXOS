#!/usr/bin/env python3
"""03a synthetic protocol/image-binding regression, never kernel execution."""
import argparse
import copy
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
from block_protocol import validate_image
from check_block import cross_image_checks
from protocol import inspect_detailed
from provenance import ROOT, digest
from test_log_parser import replace_field


def build_cases(logs, images, old02, old01):
    original = logs["image-a"].splitlines()
    cases = []

    def add(name, lines, parser_ok=False, bound_ok=False, image=images["A"], inject=False, kind="synthetic"):
        cases.append((name, "\n".join(lines) + "\n", image, inject, parser_ok, bound_ok, kind))

    def edit(name, prefix, field, value):
        found = [i for i, line in enumerate(original) if line.startswith(prefix)]
        assert len(found) == 1, prefix
        lines = list(original)
        lines[found[0]] = replace_field(lines[found[0]], field, value)
        add(name, lines)

    def value(line, field):
        return int(re.search(rf"\b{field}=([^\s]+)", line)[1], 0)

    for name, image, inject in (("image-a", images["A"], False), ("image-b", images["B"], False),
                                 ("absent", None, False), ("backend-ioerr", images["A"], True)):
        add(f"original_real_{name}_replay", logs[name].splitlines(), True, True, image, inject, "original real log replay")
    add("old02_protocol_still_valid_but_not_stage03", old02.splitlines(), True, False, None,
        kind="original real log replay")
    add("old01_protocol_still_valid_but_not_stage03", old01.splitlines(), True, False, None,
        kind="original real log replay")
    start = next(i for i, l in enumerate(original) if l.startswith("ALVENX "))
    for index in range(start, len(original)):
        if original[index]:
            add(f"missing_event_{index - start:03}", original[:index] + original[index + 1:])
            add(f"duplicate_event_{index - start:03}", original[:index] + [original[index]] + original[index:])
    for baseline in (2, 3, 4, 5, 6):
        lines = []
        for line in original:
            if line.startswith(("KERNEL_LAYOUT ", "MMIO_LAYOUT ")):
                line = replace_field(line, "permanent_pages", baseline)
            elif line.startswith("ELF_ROLLBACK "):
                for field in ("used_before", "used_after", "recovered_used"):
                    line = replace_field(line, field, baseline)
            elif line.startswith("MEMORY "):
                high, total = value(line, "high_water_pages"), value(line, "total_pages")
                line = replace_field(replace_field(line, "allocated_pages", baseline), "free_pages", total - baseline)
                line = replace_field(line, "high_water_pages", high + baseline - 4)
            elif line.startswith(("BLOCK_OPEN ", "BLOCK_RESET_TIMEOUT ")):
                line = replace_field(line, "live_pages", baseline + 2)
            elif line.startswith(("BLOCK_CLOSE ", "BLOCK_SUMMARY ")):
                line = replace_field(line, "remaining_pages", baseline)
            lines.append(line)
        add(f"coordinated_baseline_{baseline}", lines, baseline == 4, baseline == 4)
    changes = (
        ("mmio_user_bit", "MMIO_LAYOUT ", "flags", 22),
        ("mmio_executable", "MMIO_LAYOUT ", "flags", 14),
        ("mmio_alias_wrong", "MMIO_LAYOUT ", "virtual_start", "0x10001000"),
        ("open_wrong_features", "BLOCK_OPEN generation=0 ", "features", 32),
        ("open_wrong_capacity", "BLOCK_OPEN generation=1 ", "capacity_bytes", 512),
        ("open_unbounded_polls", "BLOCK_OPEN generation=0 ", "poll_limit", 0),
        ("open_wrong_live_pages", "BLOCK_OPEN generation=0 ", "live_pages", 4),
        ("read_wrong_address", "BLOCK_READ id=far_b attempt=1 ", "offset", 7 * 512),
        ("read_wrong_length", "BLOCK_READ id=cross attempt=1 ", "length", 512),
        ("read_missing_completion", "BLOCK_READ id=head attempt=1 ", "completed", 0),
        ("read_no_notification", "BLOCK_READ id=head attempt=1 ", "notified", 0),
        ("read_failed_status_as_success", "BLOCK_READ id=head attempt=1 ", "device_status", 1),
        ("read_partial_dma", "BLOCK_READ id=max_window attempt=1 ", "used_len", 513),
        ("read_sentinel_flag_contradicts_data", "BLOCK_READ id=head attempt=1 ", "buffer_unchanged", 1),
        ("timeout_not_injected", "BLOCK_TIMEOUT ", "injection", "none"),
        ("timeout_completed_count", "BLOCK_TIMEOUT ", "completed", 1),
        ("timeout_wrote_caller", "BLOCK_TIMEOUT ", "buffer_unchanged", 0),
        ("reset_not_injected", "BLOCK_RESET_TIMEOUT ", "injection", "none"),
        ("reset_freed_early", "BLOCK_RESET_TIMEOUT ", "retained_pages", 0),
        ("reset_live_pages_missing", "BLOCK_RESET_TIMEOUT ", "live_pages", 4),
        ("close_unconfirmed", "BLOCK_CLOSE generation=0 ", "reset_confirmed", 0),
        ("close_leaks", "BLOCK_CLOSE generation=1 ", "remaining_pages", 6),
        ("summary_fake_read_count", "BLOCK_SUMMARY ", "reads_ok", 1),
        ("summary_missing_free", "BLOCK_SUMMARY ", "freed", 2),
        ("summary_relabels_quarantine", "BLOCK_SUMMARY ", "quarantined", 2),
        ("summary_omits_reset_failure_control", "BLOCK_SUMMARY ", "injected_reset_timeouts", 0),
    )
    for args in changes:
        edit(*args)
    ring = next(re.search(r"\bring=([^\s]+)", l)[1] for l in original if l.startswith("BLOCK_OPEN generation=0 "))
    edit("dma_aliases_ring", "BLOCK_OPEN generation=0 ", "bounce", ring)
    root = next(re.search(r"\broot=([^\s]+)", l)[1] for l in original if l.startswith("KERNEL_LAYOUT "))
    edit("dma_aliases_kernel_table", "BLOCK_OPEN generation=0 ", "ring", root)
    for case in ("zero_start", "zero_end", "zero_oob", "oob", "cross_capacity", "overflow", "too_long", "poisoned", "quarantined"):
        for field, replacement in (("submitted", 1), ("completed", 1), ("notified", 1), ("buffer_unchanged", 0)):
            edit(f"parameter_{case}_{field}", f"BLOCK_PARAMETER id={case} ", field, replacement)
    for case in ("live", "after_closed_drop", "quarantined"):
        for field in ("allocated", "freed", "submitted", "completed", "notified"):
            edit(f"owner_{case}_{field}", f"BLOCK_OWNER id={case} ", field, 1)
    for prefix, name in (("BLOCK_TIMEOUT ", "read"), ("BLOCK_RESET_TIMEOUT ", "reset")):
        lines = []
        for line in original:
            if line.startswith(prefix):
                line = replace_field(replace_field(line, "polls", 1), "ticks", 0)
            lines.append(line)
        add(f"{name}_timeout_without_reaching_limit", lines)
    for prefix in ("MMIO_LAYOUT ", "BLOCK_OPEN generation=0 ", "BLOCK_READ id=head attempt=1 ",
                   "BLOCK_DATA id=head attempt=1 at=0 ", "BLOCK_TIMEOUT ", "BLOCK_RESET_TIMEOUT ", "BLOCK_SUMMARY "):
        found = next(i for i, l in enumerate(original) if l.startswith(prefix))
        line = original[found]
        name = prefix.split()[0].lower()
        first_field = line[len(prefix.split()[0]) + 1:].split()[0].split("=")[0]
        add(f"before_boot_{name}", [line] + original)
        add(f"before_old02_boot_{name}", [line] + old02.splitlines())
        add(f"indented_before_boot_{name}", [" " + line] + original)
        changed = list(original)
        changed[found] += " " + line.split()[1]
        add(f"repeated_field_{name}", changed)
        changed = list(original)
        changed[found] = re.sub(rf"\b{first_field}=[^\s]+ ?", "", line, count=1).strip()
        add(f"missing_field_{name}", changed)
    edit("unknown_protocol", "ALVENX native ", "version", "0.3.1")
    edit("new_log_old02_banner", "ALVENX native ", "version", "0.2.0")
    add("old02_log_new_banner", [replace_field(l, "version", "0.3.0") if l.startswith("ALVENX ") else l for l in old02.splitlines()])
    add("mixed_versions", original + old02.splitlines())
    add("kernel_failure_after_pass", original + ["KERNEL FAIL synthetic"])
    add("success_text_only", ["RESULT functional=PASS benchmark_cases=2 official_score=UNMEASURED"])
    # Text may be internally valid but still false about disk bytes or backend.
    data_at = next(i for i, l in enumerate(original) if l.startswith("BLOCK_DATA id=head "))
    changed = list(original)
    hex_data = re.search(r"\bhex=([^\s]+)", changed[data_at])[1]
    changed[data_at] = replace_field(changed[data_at], "hex", ("00" if hex_data[:2] != "00" else "ff") + hex_data[2:])
    add("valid_hex_but_wrong_disk_byte", changed, True, False)
    add("hardcoded_zero_disk_output", [replace_field(l, "hex", "00" * (len(re.search(r"\bhex=([^\s]+)", l)[1]) // 2))
                                      if l.startswith("BLOCK_DATA ") else l for l in original], True, False)
    add("wrong_image_bound_to_real_log", original, True, False, images["B"])
    add("present_log_as_missing_device", original, True, False, None)
    add("missing_device_log_as_present", logs["absent"].splitlines(), True, False)
    add("backend_injection_not_disclosed", logs["backend-ioerr"].splitlines(), True, False)
    add("declared_injection_without_ioerr", original, True, False, inject=True)
    add("missing_device_cannot_supply_injected_ioerr", logs["absent"].splitlines(), True, False, None, True)
    unchanged_data = []
    for line in original:
        if line.startswith("BLOCK_DATA "):
            length = len(re.search(r"\bhex=([^\s]+)", line)[1]) // 2
            line = replace_field(line, "hex", "a5" * length)
        elif line.startswith("BLOCK_READ "):
            line = replace_field(line, "buffer_unchanged", 1)
        unchanged_data.append(line)
    add("valid_image_bytes_equal_caller_sentinel", unchanged_data, True, True, b"\xa5" * len(images["A"]))
    positions = [i for i, l in enumerate(original) if l.startswith(("USER worker=", "USER_FAULT "))]
    changed = list(original)
    for at, line in zip(positions, [original[i] for i in positions][::-1]):
        changed[at] = line
    add("valid_runtime_event_reordering", changed, True, True)
    add("valid_field_reordering", [l.split()[0] + " " + " ".join(reversed(l.split()[1:]))
                                  if l.startswith(("BLOCK_", "MMIO_LAYOUT ")) else l for l in original], True, True)
    changed = []
    for line in original:
        if line.startswith("METRIC yield "):
            ticks, hz = value(line, "guest_time_ticks") + 123, value(line, "timebase_hz")
            line = replace_field(replace_field(line, "guest_time_ticks", ticks), "guest_virtual_ns", ticks * 1_000_000_000 // hz)
        elif line.startswith("BLOCK_READ "):
            line = replace_field(line, "ticks", value(line, "ticks") + 7)
        elif line.startswith("MEMORY "):
            line = replace_field(line, "high_water_pages", value(line, "high_water_pages") + 1)
        changed.append(line)
    add("valid_alternative_timing_and_highwater", changed, True, True)
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=Path, required=True, help="four-scenario original check_block results.json")
    parser.add_argument("--stage02-log", type=Path, required=True)
    parser.add_argument("--stage01-log", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    original = json.loads(args.record.read_text())
    kernel = Path(original["kernel"])
    assert digest(kernel) == original["kernel_sha256"]
    logs, images = {}, {}
    for scenario in original["scenarios"]:
        source = args.record.parent / scenario["name"] / "run-1.log"
        assert digest(source) == scenario["runs"][0]["raw_log_sha256"]
        logs[scenario["name"]] = source.read_text()
        if scenario["name"] in ("image-a", "image-b"):
            image = Path(scenario["image"])
            assert digest(image) == scenario["image_sha256"]
            images["A" if scenario["name"] == "image-a" else "B"] = image.read_bytes()
    assert set(logs) == {"image-a", "image-b", "absent", "backend-ioerr"}
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    out = args.output or ROOT / "results" / f"stage03a-parser-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    (out / "images").mkdir()
    report = {"role": "host protocol/image-binding regression; mutated inputs are synthetic, never QEMU runs",
              "qemu_executed": False, "kernel_rebuilt": False, "original_record": str(args.record.resolve()),
              "original_record_sha256": digest(args.record), "kernel_sha256": original["kernel_sha256"],
              "verifier_sha256": {p.name: digest(p) for p in (Path(__file__), ROOT / "scripts/protocol.py",
                                      ROOT / "scripts/stage03_parser.py", ROOT / "scripts/block_protocol.py",
                                      ROOT / "scripts/check_block.py")},
              "git_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "git_status": subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=ROOT, text=True).strip(), "cases": []}
    cases = build_cases(logs, images, args.stage02_log.read_text(), args.stage01_log.read_text())
    for index, (name, text, image, inject, expected_parser, expected_bound, kind) in enumerate(cases):
        image_sha = hashlib.sha256(image).hexdigest() if image is not None else None
        if image is not None and not (out / "images" / f"{image_sha}.img").exists():
            (out / "images" / f"{image_sha}.img").write_bytes(image)
        parsed = inspect_detailed(text)
        parser_ok = bool(parsed.checks) and not parsed.errors and all(parsed.checks.values())
        bound = validate_image(getattr(parsed, "block", None) or {}, image, inject)
        bound_ok = parser_ok and all(bound.values())
        path = out / f"{index:03}-{name}.log"
        path.write_text(text)
        report["cases"].append({"name": name, "input_kind": kind, "input": path.name, "input_sha256": digest(path),
                                "expected_parser_acceptance": expected_parser, "parser_accepted": parser_ok,
                                "expected_bound_acceptance": expected_bound, "bound_accepted": bound_ok,
                                "matched_expectation": parser_ok == expected_parser and bound_ok == expected_bound,
                                "image_sha256": image_sha,
                                "image_input": f"images/{image_sha}.img" if image is not None else None,
                                "backend_injected": inject, "checks": parsed.checks, "image_checks": bound, "errors": parsed.errors})
    original_cross = cross_image_checks(original["scenarios"])
    repeated = copy.deepcopy(original["scenarios"])
    a = next(s for s in repeated if s["name"] == "image-a")
    b = next(s for s in repeated if s["name"] == "image-b")
    b["runs"][0]["block"]["reads"] = copy.deepcopy(a["runs"][0]["block"]["reads"])
    repeated_input = out / "synthetic-repeated-readback-scenarios.json"
    repeated_input.write_text(json.dumps(repeated, indent=2) + "\n")
    repeated_cross = cross_image_checks(repeated)
    report["cross_scenario_controls"] = {"original": original_cross, "synthetic_repeated_readback": repeated_cross,
        "synthetic_input": repeated_input.name, "synthetic_input_sha256": digest(repeated_input),
        "matched_expectation": original_cross["different_inputs_and_readback"] and not repeated_cross["different_inputs_and_readback"]}
    report["all_expectations_matched"] = (report["cross_scenario_controls"]["matched_expectation"]
                                         and all(c["matched_expectation"] for c in report["cases"]))
    report["unexpected"] = [c["name"] for c in report["cases"] if not c["matched_expectation"]]
    (out / "regression.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"cases={len(cases)} expectations_matched={report['all_expectations_matched']} qemu_executed=false")
    print(f"unexpected={report['unexpected']}")
    print(f"Evidence retained at {out}")
    return 0 if report["all_expectations_matched"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
