"""Strict 0.5.0: disk ELF plus per-task fd, retaining frozen regression rules.

Common permission/task checks are copied from our own frozen 0.3 parser, not
implemented by removing or rewriting 0.4 events into another protocol.
"""
from dataclasses import dataclass
import re
import log_parser as stage01
import block_protocol as block
import disk_protocol as disk
import seek_protocol as fd

PAGE = 4096
# Protocol 0.3.0 adds one permanent MMIO L0 to the prior root/RAM L1/L0.
# A different resident layout requires an explicit protocol/expectation update.
EXPECTED_PERMANENT_PAGES = 4
PIDS = {0: (1, 2, 3, 4, 5, 6), 1: (1, 2), 2: (1, 2)}
WORKLOADS = {1: 1000, 2: 10000}
PROBES = ("write_text", "write_rodata", "execute_data")
ROLLBACKS = {"overlap": "overlapping_user_segment", "quota": "address_space_page_limit",
             "permissions": "ELF_permissions"}
CHECK_NAMES = stage01.CHECK_NAMES + ("kernel_permissions", "user_page_permissions", "elf_failure_rollback",
                                    "mmio_mapping", "block_transport_controls", "disk_transaction", "disk_user_execution", "fd_transaction")
SPECS = (
    ("layout", "KERNEL_LAYOUT ",
     "root permanent_pages text_start text_end rodata_start rodata_end data_start data_end text_flags rodata_flags data_flags wx_leaves text_write_aliases".split(), set()),
    ("probe", "KERNEL_PROBE ", "name cause pc stval spp".split(), {"name"}),
    ("rollback", "ELF_ROLLBACK ",
     "case error used_before used_after allocated freed recovery_allocated recovery_freed recovered_used reject_ticks recovery_ticks timebase_hz".split(), {"case", "error"}),
    ("access", "USER_ACCESS ",
     "phase pid text_va text_flags stack_va stack_flags guard_va guard_mapped wx_leaves kernel_text_write_aliases".split(), set()),
)
LITERALS = {
    "TEST kernel_permissions PASS rx_r_rw_nx_hardware": "permissions_test",
    "TEST elf_rollback PASS overlap_quota_permissions_recovery": "rollback_test",
}
KERNEL_PREFIXES = stage01.KERNEL_PREFIXES + ("ELF_ROLLBACK",) + block.PREFIXES + disk.PREFIXES + fd.PREFIXES


@dataclass
class Inspection(stage01.Inspection):
    block: dict | None = None
    disk: dict | None = None
    executed: dict | None = None
    fd: dict | None = None


@dataclass
class Record(stage01.Record):
    def token(self):
        if self.kind.startswith("block_"):
            return block.token(self)
        if self.kind == "fault":
            return self.kind, self.values["pid"]
        if self.kind == "probe":
            return self.kind, self.values["name"]
        if self.kind == "rollback":
            return self.kind, self.values["case"]
        if self.kind == "access":
            return self.kind, self.values["phase"], self.values["pid"]
        return super().token()


def decode(line):
    parsed_fd = fd.decode(line)
    if parsed_fd is not None:
        return Record(parsed_fd.kind, parsed_fd.fields, parsed_fd.values)
    parsed_disk = disk.decode(line)
    if parsed_disk is not None:
        return Record(parsed_disk.kind, parsed_disk.fields, parsed_disk.values)
    parsed_block = block.decode(line)
    if parsed_block is not None:
        return Record(parsed_block.kind, parsed_block.fields, parsed_block.values)
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
        values = {k: v if k in strings else stage01.number(v) for k, v in fields.items()}
        return Record(kind, fields, values)
    parsed = stage01.decode(line)
    return Record(parsed.kind, parsed.fields, parsed.values)


def fd_mode(records):
    return any(r.kind == "disk_header" and r.values["at"] == 64 and bytes.fromhex(r.values["hex"])[:32] != bytes(32) for r in records)


def ordered(records):
    expected = [(k,) for k in ("boot", "platform", "allocator", "layout")]
    expected += [("probe", name) for name in PROBES]
    expected += [("permissions_test",), ("mmio",), ("elf",)]
    expected += [("rollback", case) for case in ROLLBACKS]
    expected += [("rollback_test",), ("disk_group",)]
    endings = [r for r in records if r.kind == "disk_end"]
    if len(endings) == 1 and endings[0].values["outcome"] == "loaded" and fd_mode(records):
        expected += [("fd_group",)]
    elif len(endings) == 1 and endings[0].values["outcome"] == "loaded":
        expected += [("load",3,1), ("access",3,1), ("disk_exec_begin",), ("disk_write",),
                     ("task",3,1), ("memory",3), ("disk_exec_end",)]
    expected += [("block_group",)]
    for pid in PIDS[0]:
        expected += [("load", 0, pid), ("access", 0, pid)]
    expected += [("isolation",), ("runtime_group",)]
    expected += [("task", 0, pid) for pid in PIDS[0]]
    expected += [("functional",), ("memory", 0)]
    for phase in WORKLOADS:
        for pid in PIDS[phase]:
            expected += [("load", phase, pid), ("access", phase, pid)]
        expected += [("begin", phase)]
        expected += [("task", phase, pid) for pid in PIDS[phase]]
        expected += [("metric", phase), ("memory", phase)]
    expected += [("result",)]
    actual = [r.token() for r in records]
    at = 0
    for token in expected:
        if token == ("disk_group",):
            stop = at
            while stop < len(records) and records[stop].kind.startswith("disk_"):
                stop += 1
            if stop == at or records[stop-1].kind != "disk_end":
                return False
            at = stop
        elif token == ("fd_group",):
            stop = at
            while stop < len(records) and not records[stop].kind.startswith("block_"):
                stop += 1
            if stop == at or not fd.ordered(records[at:stop]):
                return False
            at = stop
        elif token == ("block_group",):
            stop = at
            while stop < len(records) and records[stop].kind.startswith("block_"):
                stop += 1
            if stop == at or not block.ordered(records[at:stop]):
                return False
            at = stop
        elif token == ("runtime_group",):
            if set(actual[at:at + 5]) != {("user_a",), ("user_b",), ("fault", 4), ("fault", 5), ("fault", 6)}:
                return False
            at += 5
        elif at >= len(actual) or actual[at] != token:
            return False
        else:
            at += 1
    return at == len(actual)


def inspect_detailed(log):
    checks = dict.fromkeys(CHECK_NAMES, False)
    errors, records = [], []
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
            continue
        try:
            records.append(decode(line))
        except ValueError as error:
            errors.append(f"line {line_no}: {error}")
    if not ordered(records):
        errors.append("incomplete, repeated, unexpected or out-of-order stage/PID event sequence")
    if errors:
        return Inspection(checks, [], [], errors, {})
    checks["record_schema_and_order"] = True
    repeated = {"load", "task", "begin", "metric", "memory", "access", "probe", "rollback", "fault"}
    one = {r.kind: r.values for r in records if r.kind not in repeated and not r.kind.startswith(("block_", "disk_", "fd_"))}
    keyed = lambda kind: {(r.values["phase"], r.values["pid"]): r.values for r in records if r.kind == kind}
    loads, tasks, access = keyed("load"), keyed("task"), keyed("access")
    probes = {r.values["name"]: r.values for r in records if r.kind == "probe"}
    faults = {r.values["pid"]: r.values for r in records if r.kind == "fault"}
    begins = {r.values["phase"]: r.values for r in records if r.kind == "begin"}
    metrics = [r for r in records if r.kind == "metric"]
    memories = [r for r in records if r.kind == "memory"]
    rollbacks = [r.values for r in records if r.kind == "rollback"]

    def check(name, condition, message):
        checks[name] = bool(condition)
        if not condition:
            errors.append(message)

    boot, platform, layout = one["boot"], one["platform"], one["layout"]
    hz = platform["timebase_hz"]
    check("native_boot_and_allocator", boot["version"] == "0.6.0" and boot["hart"] == 0
          and boot["dtb"] == platform["reserved_fdt_start"] == 0x87e0_0000
          and platform["ram_end"] == 0x8800_0000 and hz > 0,
          "boot/platform fields disagree with the supported fixed virt layout")
    text, text_end = layout["text_start"], layout["text_end"]
    ro, ro_end, data, end = (layout[k] for k in ("rodata_start", "rodata_end", "data_start", "data_end"))
    permission_ok = (text == 0x8020_0000 < text_end == ro < ro_end == data < end < 0x8040_0000
                     and all(v % PAGE == 0 for v in (text, text_end, ro, ro_end, data, end))
                     and (layout["text_flags"], layout["rodata_flags"], layout["data_flags"]) == (10, 2, 6)
                     and layout["wx_leaves"] == layout["text_write_aliases"] == 0
                     and layout["permanent_pages"] == EXPECTED_PERMANENT_PAGES)
    for name, cause, low, high in (("write_text", 15, text, text_end), ("write_rodata", 15, ro, ro_end),
                                    ("execute_data", 12, data, end)):
        p = probes[name]
        permission_ok &= (p["cause"] == cause and p["spp"] == 1 and low <= p["stval"] < high
                          and p["pc"] % 2 == 0)
        permission_ok &= p["pc"] == p["stval"] if name == "execute_data" else text <= p["pc"] < text_end
    check("kernel_permissions", permission_ok,
          "kernel layout (including the fixed 4-page baseline), PTE audit or controlled S-mode faults disagree")
    check("user_page_permissions", all(
        a["text_va"] == loads[key]["pc"] == 0x10000 and a["text_flags"] == 26
        and a["stack_va"] == 0x3fff_f000 and a["stack_flags"] == 22
        and a["guard_va"] == 0x3fff_d000 and a["guard_mapped"] == 0
        and a["wx_leaves"] == a["kernel_text_write_aliases"] == 0 for key, a in access.items()),
        "user RX/NX/guard mapping or physical text alias audit disagrees")
    rollback_ok = True
    for r in rollbacks:
        rollback_ok &= (r["error"] == ROLLBACKS[r["case"]]
                        and r["used_before"] == r["used_after"] == r["recovered_used"] == EXPECTED_PERMANENT_PAGES
                        and r["allocated"] == r["freed"] <= 64
                        # Fixed worker: two LOAD pages + two stack pages,
                        # root + L1 + distinct code/stack L0 tables (8 frames).
                        and 8 <= r["recovery_allocated"] == r["recovery_freed"] <= 64
                        and r["timebase_hz"] == hz and r["reject_ticks"] > 0 and r["recovery_ticks"] > 0)
        rollback_ok &= (r["allocated"] == 0 if r["case"] == "permissions" else r["allocated"] > 0)
        if r["case"] == "quota":
            rollback_ok &= r["allocated"] == 64
        if r["case"] == "overlap":
            rollback_ok &= r["allocated"] >= 4  # root + L1 + L0 + first RX page
    rollback_ok &= len({r["recovery_allocated"] for r in rollbacks}) == 1
    check("elf_failure_rollback", rollback_ok, "loader rejection, partial allocation, rollback or recovery counters disagree")
    workers_ok = True
    for pid, exit_code in ((1, 37), (2, 41)):
        t = tasks[0, pid]
        workers_ok &= (t["state"] == 2 and t["exit"] == exit_code and t["writes"] == 1
                       and t["bytes"] == len("USER worker=A state=valid\n")
                       and t["yields"] == t["enosys"] == 1 and t["efault"] == t["fault"] == 0
                       and t["runs"] == t["timers"] + 5)
    check("write_exit_and_user_registers", workers_ok, "worker counters or exit states disagree")
    timer = one["functional"]
    check("timer_preemption", all(tasks[0, pid]["timers"] > 0 for pid in (1, 2))
          and timer["timer_traps"] == sum(tasks[0, pid]["timers"] for pid in PIDS[0])
          and 0 < timer["timer_switches"] <= timer["timer_traps"], "timer totals disagree")
    bad = tasks[0, 3]
    faults_ok = (bad["state"] == 2 and bad["exit"] == 43 and bad["efault"] == 2
                 and all(bad[k] == 0 for k in ("writes", "bytes", "yields", "enosys", "fault"))
                 and bad["runs"] == bad["timers"] + 3)
    for pid, cause, va in ((4, 13, 0x8020_0000), (5, 15, 0x10000), (6, 12, 0x3fff_fff0)):
        t, event = tasks[0, pid], faults[pid]
        faults_ok &= (t["state"] == 3 and t["exit"] == 0 and t["fault"] == event["cause"] == cause
                      and all(t[k] == 0 for k in ("writes", "bytes", "yields", "efault", "enosys"))
                      and t["runs"] == t["timers"] + 1 and event["stval"] == va and event["pc"] % 2 == 0)
        faults_ok &= (event["pc"] == va if pid == 6 else
                      loads[0, pid]["pc"] <= event["pc"] < loads[0, pid]["pc"] + loads[0, pid]["elf_bytes"])
    check("pointer_failure_and_fault_containment", faults_ok, "fault/pointer events disagree with task counters or expected mapped targets")
    total = memories[0].values["total_pages"]
    highs = [r.values["high_water_pages"] for r in memories]
    witnessed = {loads[0, pid]["root"] for pid in PIDS[0]}
    witnessed.update((one["isolation"]["pa_a"], one["isolation"]["pa_b"]))
    memory_ok = total > EXPECTED_PERMANENT_PAGES and all(
        m.values["total_pages"] == total and m.values["page_bytes"] == PAGE
        and m.values["allocated_pages"] == EXPECTED_PERMANENT_PAGES
        and m.values["free_pages"] == total - EXPECTED_PERMANENT_PAGES
        and EXPECTED_PERMANENT_PAGES <= m.values["high_water_pages"] <= total for m in memories)
    memory_ok &= highs == sorted(highs) and highs[0] >= EXPECTED_PERMANENT_PAGES + max(len(witnessed), 64)
    pool_end = platform["reserved_fdt_start"]
    pool_start = pool_end - total * PAGE
    memory_ok &= pool_start == end
    check("page_accounting_and_reclamation", memory_ok, "pool bounds, page totals, reclamation or high-water marks disagree")

    def frame_in_pool(address):
        return address % PAGE == 0 and 0x8020_0000 <= pool_start <= address and address + PAGE <= pool_end

    isolation = one["isolation"]
    spaces_ok = (frame_in_pool(layout["root"]) and isolation["shared_va"] == 0x20000
                 and isolation["pa_a"] != isolation["pa_b"]
                 and layout["root"] not in (isolation["pa_a"], isolation["pa_b"])
                 and frame_in_pool(isolation["pa_a"]) and frame_in_pool(isolation["pa_b"]))
    for phase, pids in PIDS.items():
        roots = [loads[phase, pid]["root"] for pid in pids]
        spaces_ok &= len(set(roots)) == len(pids) and all(frame_in_pool(root) for root in roots)
        spaces_ok &= layout["root"] not in roots
        for pid in pids:
            load = loads[phase, pid]
            spaces_ok &= load["elf_bytes"] >= 64 and load["pc"] == 0x10000 and load["stack"] == 0x4000_0000
        if phase == 0:
            spaces_ok &= isolation["pa_a"] not in roots and isolation["pa_b"] not in roots
        spaces_ok &= loads[phase, 1]["elf_bytes"] == loads[phase, 2]["elf_bytes"]
    spaces_ok &= len({loads[phase, pid]["elf_bytes"] for phase in WORKLOADS for pid in PIDS[phase]}) == 1
    check("separate_user_address_spaces", spaces_ok, "LOAD/isolation addresses or user inputs disagree")
    mmio = one["mmio"]
    check("mmio_mapping", mmio == {"virtual_start": 0x90001000, "physical_start": 0x10001000,
          "pages": 8, "flags": 6, "permanent_pages": EXPECTED_PERMANENT_PAGES}
          and layout["root"] == pool_start, "MMIO alias or fixed resident root disagrees")
    block_errors, block_info = block.inspect([r for r in records if r.kind.startswith("block_")], hz, pool_start, pool_end)
    check("block_transport_controls", not block_errors, "; ".join(block_errors) or "block controls disagree")
    metrics_ok, parsed_metrics = True, []
    for record in metrics:
        m = record.values
        phase = m["phase"]
        iterations, begin = WORKLOADS[phase], begins[phase]
        valid = (begin["iterations_per_task"] == m["iterations_per_task"] == iterations
                 and begin["timer"] == "off"
                 and m["yield_calls"] == m["switches"] == sum(tasks[phase, pid]["yields"] for pid in PIDS[phase]) == 2 * iterations
                 and m["timebase_hz"] == hz > 0 and m["guest_time_ticks"] > 0)
        for pid in PIDS[phase]:
            t = tasks[phase, pid]
            valid &= (t["state"] == 2 and t["exit"] == 50 + pid and t["yields"] == iterations
                      and t["runs"] == iterations + 2
                      and all(t[k] == 0 for k in ("timers", "writes", "bytes", "efault", "enosys", "fault")))
        valid &= hz > 0 and m["guest_virtual_ns"] == m["guest_time_ticks"] * 1_000_000_000 // max(hz, 1)
        metrics_ok &= valid
        rendered = dict(record.fields)
        if valid:
            rendered["guest_virtual_ns_per_switch"] = m["guest_virtual_ns"] / m["switches"]
        parsed_metrics.append(rendered)
    check("measured_yield_workloads", metrics_ok, "yield workload counters or timing conversion disagree")
    result = one["result"]
    check("completed_without_kernel_failure", result["functional"] == "PASS"
          and result["benchmark_cases"] == 2 and result["official_score"] == "UNMEASURED", "unexpected final result")
    transaction = [r for r in records if r.kind.startswith("disk_") and r.kind not in
                   ("disk_exec_begin","disk_write","disk_exec_end")]
    disk_errors, disk_info = disk.inspect(transaction,pool_start,pool_end)
    check("disk_transaction", not disk_errors, "; ".join(disk_errors) or "disk transaction disagrees")
    execution = [r for r in records if r.kind in ("disk_exec_begin","disk_write","disk_exec_end")]
    loaded = disk_info.get("outcome") == "loaded"
    phase3 = {key for key in loads if key[0] == 3}
    executed = None
    exec_ok = not execution and not phase3 and (3,1) not in tasks and not any(r.values["phase"] == 3 for r in memories)
    if loaded and len(execution) == 3 and phase3 == {(3,1)} and (3,1) in tasks:
        begin, write, end_exec = [r.values for r in execution]
        task, load = tasks[3,1], loads[3,1]
        byte_count = len(bytes.fromhex(write["hex"]))
        exec_ok = (begin == {"phase":3,"pid":1,"input_valid":0}
                   and end_exec == {"phase":3,"remaining_pages":4}
                   and write["pid"] == write["fd"] == 1 and write["requested"] == write["returned"] == byte_count > 0
                   and task["state"] == 2 and task["runs"] == 2 and task["writes"] == 1 and task["bytes"] == byte_count
                   and all(task[k] == 0 for k in ("timers","yields","efault","enosys","fault"))
                   and load["root"] == disk_info.get("loader",{}).get("root")
                   and load["pc"] == 0x10000 and load["stack"] == 0x40000000
                   and load["elf_bytes"] == disk_info["filled"]
                   and len([r for r in memories if r.values["phase"] == 3]) == 1)
        executed = {"hex":write["hex"],"exit":task["exit"]}
    check("disk_user_execution", exec_ok, "disk U-mode write/exit, loader handoff or reclamation disagrees")
    fd_info = None
    fd_errors = []
    if fd_mode(records) and disk_info.get("outcome") == "loaded":
        start = next(i for i,r in enumerate(records) if r.kind == "disk_end") + 1
        stop = next(i for i,r in enumerate(records[start:],start) if r.kind.startswith("block_"))
        fd_errors,fd_info = fd.inspect(records[start:stop],disk_info,pool_start,pool_end)
    elif any(r.kind.startswith("fd_") or r.kind in ("load","task","memory","access") and r.values.get("phase") == 4 for r in records):
        fd_errors = ["fd activity without a loaded extent container"]
    check("fd_transaction",not fd_errors,"; ".join(fd_errors) or "fd state/bytes disagree")
    return Inspection(checks, parsed_metrics, [dict(r.fields) for r in memories], errors, block_info, disk_info, executed, fd_info)
