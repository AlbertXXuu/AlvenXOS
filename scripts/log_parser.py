"""Strict semantic parser for the fixed stage-01 serial protocol.

Text consistency is checked here; actual execution and artifact identity must
come from the retained runner/acceptance evidence, not from a PASS string.
"""
from dataclasses import dataclass
import re

PAGE = 4096
WORKLOADS = {1: 1000, 2: 10000}
PIDS = {0: (1, 2, 3, 4), 1: (1, 2), 2: (1, 2)}
CHECK_NAMES = (
    "record_schema_and_order", "native_boot_and_allocator",
    "write_exit_and_user_registers", "timer_preemption",
    "pointer_failure_and_fault_containment", "separate_user_address_spaces",
    "measured_yield_workloads", "page_accounting_and_reclamation",
    "completed_without_kernel_failure",
)
TASK_KEYS = "phase pid state exit runs timers yields writes bytes efault enosys fault".split()
SPECS = (
    ("boot", "ALVENX native ", "version hart dtb".split(), {"version"}),
    ("platform", "PLATFORM ", "timebase_hz ram_end reserved_fdt_start".split(), set()),
    ("load", "LOAD ", "phase pid elf_bytes root pc stack".split(), set()),
    ("isolation", "ISOLATION ", "shared_va pa_a pa_b".split(), set()),
    ("fault", "USER_FAULT ", "pid cause pc stval".split(), set()),
    ("task", "TASK ", TASK_KEYS, set()),
    ("functional", "TEST user_syscalls_registers_isolation_timer PASS ",
     "timer_traps timer_switches".split(), set()),
    ("begin", "BENCH_BEGIN ", "phase iterations_per_task timer".split(), {"timer"}),
    ("metric", "METRIC yield ",
     "phase iterations_per_task yield_calls switches guest_time_ticks timebase_hz guest_virtual_ns".split(), set()),
    ("memory", "MEMORY ",
     "phase total_pages allocated_pages free_pages high_water_pages page_bytes".split(), set()),
    ("result", "RESULT ", "functional benchmark_cases official_score".split(), {"functional", "official_score"}),
)
LITERALS = {
    "TEST frame_allocator PASS aligned_unique_zeroed_reuse_double_free": "allocator",
    "TEST elf_reject PASS magic_file_range_header_overflow_no_frame_leak": "elf",
    "USER worker=A state=valid": "user_a",
    "USER worker=B state=valid": "user_b",
}
KERNEL_PREFIXES = ("ALVENX", "PLATFORM", "TEST", "LOAD", "ISOLATION", "USER",
                   "TASK", "BENCH_BEGIN", "METRIC", "MEMORY", "RESULT", "KERNEL", "FATAL")


@dataclass
class Record:
    kind: str
    fields: dict
    values: dict

    def token(self):
        if self.kind in {"load", "task"}:
            return self.kind, self.values["phase"], self.values["pid"]
        if self.kind in {"begin", "metric", "memory"}:
            return self.kind, self.values["phase"]
        return (self.kind,)


@dataclass
class Inspection:
    checks: dict
    metrics: list
    memory: list
    errors: list


def number(text, signed=False):
    pattern = r"-?(?:0|[1-9][0-9]*)" if signed else r"(?:0|[1-9][0-9]*|0x[0-9a-fA-F]+)"
    if len(text) > 21 or re.fullmatch(pattern, text) is None:
        raise ValueError("invalid integer")
    result = int(text, 16 if text.startswith("0x") else 10)
    if not (-(1 << 31) <= result < (1 << 31) if signed else 0 <= result < (1 << 64)):
        raise ValueError("integer outside protocol range")
    return result


def decode(line):
    if line in LITERALS:
        return Record(LITERALS[line], {}, {})
    for kind, prefix, keys, strings in SPECS:
        if not line.startswith(prefix):
            continue
        fields = {}
        for token in line[len(prefix):].split():
            match = re.fullmatch(r"([a-z_]+)=([^\s=]+)", token)
            if match is None or match[1] in fields:
                raise ValueError("malformed or repeated field")
            fields[match[1]] = match[2]
        if set(fields) != set(keys):
            raise ValueError("missing or unexpected field")
        values = {k: (v if k in strings else number(v, signed=k == "exit")) for k, v in fields.items()}
        return Record(kind, fields, values)
    raise ValueError("unknown or failed kernel record")


def ordered(records):
    expected = [(k,) for k in ("boot", "platform", "allocator", "elf")]
    expected += [("load", 0, pid) for pid in PIDS[0]]
    expected += [("isolation",), ("runtime_group",)]
    expected += [("task", 0, pid) for pid in PIDS[0]]
    expected += [("functional",), ("memory", 0)]
    for phase in WORKLOADS:
        expected += [("load", phase, pid) for pid in PIDS[phase]]
        expected += [("begin", phase)]
        expected += [("task", phase, pid) for pid in PIDS[phase]]
        expected += [("metric", phase), ("memory", phase)]
    expected += [("result",)]
    actual = [r.token() for r in records]
    at = 0
    for token in expected:
        if token == ("runtime_group",):
            if set(actual[at:at + 3]) != {("user_a",), ("user_b",), ("fault",)}:
                return False
            at += 3
        elif at >= len(actual) or actual[at] != token:
            return False
        else:
            at += 1
    return at == len(actual)


def inspect_detailed(log):
    checks = dict.fromkeys(CHECK_NAMES, False)
    errors = []
    records = []
    started = False
    for line_no, line in enumerate(log.splitlines(), 1):
        if not line.strip():
            continue
        if "KERNEL FAIL" in line or "FATAL SBI shutdown returned" in line:
            errors.append(f"line {line_no}: explicit kernel failure")
        if line.startswith("ALVENX"):
            started = True
        if not started:
            if line.lstrip().startswith(KERNEL_PREFIXES):
                errors.append(f"line {line_no}: kernel record before boot")
            continue  # OpenSBI preamble is not a kernel event.
        try:
            records.append(decode(line))
        except ValueError as error:
            errors.append(f"line {line_no}: {error}")
    if errors or not ordered(records):
        if not ordered(records):
            errors.append("incomplete, repeated, unexpected or out-of-order stage/PID event sequence")
        return Inspection(checks, [], [], errors)

    checks["record_schema_and_order"] = True
    one = {r.kind: r.values for r in records if r.kind not in {"load", "task", "begin", "metric", "memory"}}
    loads = {(r.values["phase"], r.values["pid"]): r.values for r in records if r.kind == "load"}
    tasks = {(r.values["phase"], r.values["pid"]): r.values for r in records if r.kind == "task"}
    begins = {r.values["phase"]: r.values for r in records if r.kind == "begin"}
    metrics = [r for r in records if r.kind == "metric"]
    memories = [r for r in records if r.kind == "memory"]

    def check(name, condition, message):
        checks[name] = bool(condition)
        if not condition:
            errors.append(message)

    boot, platform = one["boot"], one["platform"]
    check("native_boot_and_allocator",
          boot["version"] == "0.1.0" and boot["hart"] == 0
          and 0x8020_0000 <= boot["dtb"] == platform["reserved_fdt_start"] < platform["ram_end"]
          and platform["ram_end"] == 0x8800_0000 and platform["timebase_hz"] > 0,
          "boot/platform fields are inconsistent with the fixed virt scenario")

    workers_ok = True
    for pid, exit_code in ((1, 37), (2, 41)):
        t = tasks[0, pid]
        workers_ok &= (t["state"] == 2 and t["exit"] == exit_code and t["writes"] == 1
                       and t["bytes"] == len("USER worker=A state=valid\n")
                       and t["yields"] == t["enosys"] == 1 and t["efault"] == t["fault"] == 0
                       and t["runs"] == t["timers"] + 5)
    check("write_exit_and_user_registers", workers_ok, "worker task counters or exit states contradict the user workload")
    timer = one["functional"]
    check("timer_preemption",
          all(tasks[0, pid]["timers"] > 0 for pid in (1, 2))
          and timer["timer_traps"] == sum(tasks[0, pid]["timers"] for pid in PIDS[0])
          and 0 < timer["timer_switches"] <= timer["timer_traps"],
          "functional timer totals do not agree with per-task counters")

    bad, fault, event = tasks[0, 3], tasks[0, 4], one["fault"]
    check("pointer_failure_and_fault_containment",
          bad["state"] == 2 and bad["exit"] == 43 and bad["efault"] == 2
          and all(bad[k] == 0 for k in ("writes", "bytes", "yields", "enosys", "fault"))
          and bad["runs"] == bad["timers"] + 3
          and fault["state"] == 3 and fault["exit"] == 0 and fault["fault"] == 13
          and all(fault[k] == 0 for k in ("writes", "bytes", "yields", "efault", "enosys"))
          and fault["runs"] == fault["timers"] + 1
          and event["pid"] == 4 and event["cause"] == fault["fault"]
          and event["stval"] == 0x8020_0000
          and loads[0, 4]["pc"] <= event["pc"] < loads[0, 4]["pc"] + loads[0, 4]["elf_bytes"]
          and event["pc"] % 2 == 0,
          "bad-pointer or protection-fault records contradict their task outcomes")

    total = memories[0].values["total_pages"]
    high = [r.values["high_water_pages"] for r in memories]
    witnessed_frames = {loads[0, pid]["root"] for pid in PIDS[0]}
    witnessed_frames.update((one["isolation"]["pa_a"], one["isolation"]["pa_b"]))
    # These concurrently live pages are explicitly recorded. The retained
    # kernel root is an additional frame, without pinning the old high of 31.
    minimum_high = len(witnessed_frames) + 1
    memory_ok = total > 0 and all(
        m.values["total_pages"] == total and m.values["page_bytes"] == PAGE
        and m.values["allocated_pages"] == 1 and m.values["free_pages"] == total - 1
        and 1 <= m.values["high_water_pages"] <= total for m in memories
    ) and high == sorted(high) and high[0] >= minimum_high
    check("page_accounting_and_reclamation", memory_ok, "memory phase totals, reclamation or cumulative high-water marks are inconsistent")
    pool_end = platform["reserved_fdt_start"] & ~(PAGE - 1)
    pool_start = pool_end - total * PAGE

    def frame_in_pool(address):
        return address % PAGE == 0 and 0x8020_0000 <= pool_start <= address and address + PAGE <= pool_end

    isolation = one["isolation"]
    spaces_ok = (isolation["shared_va"] == 0x20000 and isolation["pa_a"] != isolation["pa_b"]
                 and frame_in_pool(isolation["pa_a"]) and frame_in_pool(isolation["pa_b"]))
    for phase, pids in PIDS.items():
        roots = [loads[phase, pid]["root"] for pid in pids]
        spaces_ok &= len(set(roots)) == len(pids) and all(frame_in_pool(root) for root in roots)
        for pid in pids:
            load = loads[phase, pid]
            spaces_ok &= load["elf_bytes"] >= 64 and load["pc"] == 0x10000 and load["stack"] == 0x4000_0000
        if phase == 0:
            spaces_ok &= isolation["pa_a"] not in roots and isolation["pa_b"] not in roots
        spaces_ok &= loads[phase, 1]["elf_bytes"] == loads[phase, 2]["elf_bytes"]
    spaces_ok &= len({loads[phase, pid]["elf_bytes"] for phase in WORKLOADS for pid in PIDS[phase]}) == 1
    check("separate_user_address_spaces", spaces_ok, "LOAD/isolation addresses or user inputs are inconsistent")

    metrics_ok = True
    parsed_metrics = []
    for record in metrics:
        m = record.values
        phase = m["phase"]
        iterations = WORKLOADS[phase]
        begin = begins[phase]
        valid = (begin["iterations_per_task"] == m["iterations_per_task"] == iterations
                 and begin["timer"] == "off"
                 and m["yield_calls"] == m["switches"] == sum(tasks[phase, pid]["yields"] for pid in PIDS[phase]) == 2 * iterations
                 and m["timebase_hz"] == platform["timebase_hz"] > 0 and m["guest_time_ticks"] > 0)
        for pid in PIDS[phase]:
            t = tasks[phase, pid]
            valid &= (t["state"] == 2 and t["exit"] == 50 + pid and t["yields"] == iterations
                      and t["runs"] == iterations + 2
                      and all(t[k] == 0 for k in ("timers", "writes", "bytes", "efault", "enosys", "fault")))
        if m["timebase_hz"] > 0:
            valid &= m["guest_virtual_ns"] == m["guest_time_ticks"] * 1_000_000_000 // m["timebase_hz"]
        else:
            valid = False
        metrics_ok &= valid
        rendered = dict(record.fields)
        if valid:
            rendered["guest_virtual_ns_per_switch"] = m["guest_virtual_ns"] / m["switches"]
        parsed_metrics.append(rendered)
    check("measured_yield_workloads", metrics_ok, "benchmark inputs, task counts or timing conversion disagree")
    result = one["result"]
    check("completed_without_kernel_failure",
          result["functional"] == "PASS" and result["benchmark_cases"] == len(WORKLOADS)
          and result["official_score"] == "UNMEASURED", "final result is not the expected unscored completed scenario")
    return Inspection(checks, parsed_metrics, [dict(r.fields) for r in memories], errors)


def inspect(log):
    """Compatibility API used by the runner and older read-only review scripts."""
    result = inspect_detailed(log)
    return result.checks, result.metrics, result.memory
