"""Stage03a block serial schema and bounded control/data consistency checks.

Device status is evidence about the emulated transport. Image-byte binding is a
separate host check; no expected image payload is trusted from the log itself.
"""
import re
from log_parser import Record, number

PREFIXES = ("MMIO_LAYOUT", "BLOCK")
PAGE, BASELINE, POLL_LIMIT = 4096, 4, 1_000_000
READS = (("head", 32), ("far_a", 512), ("far_b", 512), ("cross", 800),
         ("max_window", 2048), ("last_sector", 512), ("last_byte", 1), ("after_timeout", 64))
PARAMETERS = ("zero_start", "zero_end", "zero_oob", "oob", "cross_capacity", "overflow", "too_long")
SPECS = (
    ("mmio", "MMIO_LAYOUT ", "virtual_start physical_start pages flags permanent_pages", ()),
    ("block_open", "BLOCK_OPEN ", "generation physical capacity_bytes sector_bytes queue_size features ring bounce budget_ticks poll_limit live_pages", ()),
    ("block_read", "BLOCK_READ ", "id attempt offset length outcome device_status used_len submitted completed notified polls ticks buffer_unchanged", ("id", "outcome")),
    ("block_data", "BLOCK_DATA ", "id attempt at hex", ("id", "hex")),
    ("block_parameter", "BLOCK_PARAMETER ", "id offset length outcome submitted completed notified buffer_unchanged", ("id", "outcome")),
    ("block_owner", "BLOCK_OWNER ", "id outcome allocated freed submitted completed notified", ("id", "outcome")),
    ("block_timeout", "BLOCK_TIMEOUT ", "injection outcome offset length submitted completed notified polls ticks budget_ticks poll_limit buffer_unchanged", ("injection", "outcome")),
    ("block_reset_timeout", "BLOCK_RESET_TIMEOUT ", "injection outcome polls ticks budget_ticks poll_limit retained_pages live_pages", ("injection", "outcome")),
    ("block_close", "BLOCK_CLOSE ", "generation reset_confirmed reset_polls reset_ticks remaining_pages", ()),
    ("block_summary", "BLOCK_SUMMARY ", "reads_ok device_errors injected_timeouts injected_reset_timeouts submitted completed notified allocated freed remaining_pages quarantined", ()),
    ("block_absent", "BLOCK_ABSENT ", "scanned_slots submitted allocated freed remaining_pages", ()),
)
LITERALS = {"TEST block_transport PASS absent_contained": "block_test_absent",
            "TEST block_transport PASS reads_controls_reset_recovery": "block_test_present"}


def decode(line):
    if line in LITERALS:
        return Record(LITERALS[line], {}, {})
    for kind, prefix, fields, strings in SPECS:
        if not line.startswith(prefix):
            continue
        parsed = {}
        for token in line[len(prefix):].split():
            match = re.fullmatch(r"([a-z_]+)=([^\s=]+)", token)
            if not match or match[1] in parsed:
                raise ValueError("malformed or repeated block field")
            parsed[match[1]] = match[2]
        if set(parsed) != set(fields.split()):
            raise ValueError("missing or unexpected block field")
        values = {k: v if k in strings else number(v) for k, v in parsed.items()}
        if kind == "block_data" and re.fullmatch(r"(?:[0-9a-f]{2}){1,64}", values["hex"]) is None:
            raise ValueError("invalid block data hex")
        return Record(kind, parsed, values)
    return None


def token(record):
    k, v = record.kind, record.values
    if k in ("block_open", "block_close"):
        return k, v["generation"]
    if k == "block_read":
        return k, v["id"], v["attempt"]
    if k == "block_data":
        return k, v["id"], v["attempt"], v["at"]
    if k in ("block_parameter", "block_owner"):
        return k, v["id"]
    return (k,)


def ordered(records):
    if [r.kind for r in records] == ["block_absent", "block_test_absent"]:
        return True
    at = 0

    def take(expected):
        nonlocal at
        if at >= len(records) or token(records[at]) != expected:
            return None
        result = records[at]
        at += 1
        return result

    def read(name, length):
        first = take(("block_read", name, 1))
        if first is None:
            return False
        attempt = 1
        if name == "far_a" and first.values["outcome"] == "ioerr":
            attempt = 2
            first = take(("block_read", name, 2))
        if first is None or first.values["outcome"] != "ok":
            return False
        for offset in range(0, length, 64):
            data = take(("block_data", name, attempt, offset))
            if data is None or len(data.values["hex"]) != 2 * min(64, length - offset):
                return False
        return True

    if not take(("block_open", 0)):
        return False
    if not take(("block_owner", "live")):
        return False
    for name, length in READS[:-1]:
        if not read(name, length):
            return False
    for name in PARAMETERS:
        if not take(("block_parameter", name)):
            return False
    for expected in (("block_timeout",), ("block_parameter", "poisoned"),
                     ("block_close", 0), ("block_open", 1), ("block_owner", "after_closed_drop")):
        if not take(expected):
            return False
    if not read(*READS[-1]):
        return False
    for expected in (("block_owner", "quarantined"), ("block_reset_timeout",), ("block_parameter", "quarantined"),
                     ("block_close", 1), ("block_summary",), ("block_test_present",)):
        if not take(expected):
            return False
    return at == len(records)


def inspect(records, hz, pool_start, pool_end):
    """Called only after the complete event order/schema passed."""
    errors = []

    def require(condition, message):
        if not condition:
            errors.append(message)

    if records[0].kind == "block_absent":
        a = records[0].values
        require(a == {"scanned_slots": 8, "submitted": 0, "allocated": 0, "freed": 0, "remaining_pages": BASELINE},
                "absent device performed I/O or changed resident accounting")
        return errors, {"present": False, "reads": [], "device_errors": 0}
    opens = [r.values for r in records if r.kind == "block_open"]
    capacity = opens[0]["capacity_bytes"]
    budget = max(1, (hz + 19) // 20)
    require(capacity >= 30 * 512 and capacity % 512 == 0, "invalid controlled scenario capacity")
    for o in opens:
        require(o["physical"] == 0x10001000 and o["capacity_bytes"] == capacity
                and o["sector_bytes"] == 512 and o["queue_size"] == 8 and o["features"] == 0x100000020
                and o["budget_ticks"] == budget and o["poll_limit"] == POLL_LIMIT and o["live_pages"] == BASELINE + 2,
                "block negotiation, capacity, budget or live frames disagree")
        require(o["ring"] != o["bounce"] and all(p % PAGE == 0 and pool_start + BASELINE * PAGE <= p
                and p + PAGE <= pool_end for p in (o["ring"], o["bounce"])), "DMA pages alias or lie outside owned pool")
    offsets = {"head": 0, "far_a": 7 * 512, "far_b": 29 * 512, "cross": 509,
               "max_window": 1, "last_sector": capacity - 512, "last_byte": capacity - 1, "after_timeout": 0}
    lengths = dict(READS)
    reads, device_errors = [], 0
    for index, record in enumerate(records):
        v = record.values
        if record.kind == "block_read":
            require(v["offset"] == offsets[v["id"]] and v["length"] == lengths[v["id"]]
                    and v["offset"] + v["length"] <= capacity, "read address/length disagrees with scenario")
            require(v["submitted"] == v["completed"] == v["notified"] == 1
                    and 1 <= v["polls"] <= POLL_LIMIT, "read did not have one real queue completion")
            dma_bytes = ((v["offset"] % 512 + v["length"] + 511) // 512) * 512
            if v["outcome"] == "ioerr":
                device_errors += 1
                require(v["id"] == "far_a" and v["attempt"] == 1 and v["device_status"] == 1
                        and 1 <= v["used_len"] <= dma_bytes + 1 and v["buffer_unchanged"] == 1,
                        "device error was fabricated or caller data exposed on error")
            else:
                require(v["device_status"] == 0 and v["used_len"] == dma_bytes + 1
                        and v["buffer_unchanged"] in (0, 1), "successful read status/used length disagree")
                chunks = []
                cursor = index + 1
                while cursor < len(records) and records[cursor].kind == "block_data":
                    chunks.append(records[cursor].values["hex"])
                    cursor += 1
                payload = bytes.fromhex("".join(chunks))
                require(v["buffer_unchanged"] == int(all(b == 0xa5 for b in payload)),
                        "caller-buffer sentinel flag contradicts full readback data")
                reads.append({"id": v["id"], "attempt": v["attempt"], "offset": v["offset"],
                              "length": v["length"], "data_hex": "".join(chunks)})
        elif record.kind == "block_owner":
            require(v["outcome"] == "busy" and all(v[k] == 0 for k in
                    ("allocated", "freed", "submitted", "completed", "notified")),
                    "device ownership gate performed I/O or changed resources")
        elif record.kind == "block_parameter":
            expected = {
                "zero_start": (0, 0, "ok"), "zero_end": (capacity, 0, "ok"),
                "zero_oob": (capacity + 1, 0, "range"), "oob": (capacity, 1, "range"),
                "cross_capacity": (capacity - 16, 32, "range"), "overflow": ((1 << 64) - 8, 16, "overflow"),
                "too_long": (0, 2049, "too_long"), "poisoned": (0, 16, "poisoned"),
                "quarantined": (0, 16, "poisoned"),
            }[v["id"]]
            require((v["offset"], v["length"], v["outcome"]) == expected
                    and v["submitted"] == v["completed"] == v["notified"] == 0 and v["buffer_unchanged"] == 1,
                    "preflight/poison/quarantine rejection performed I/O or changed caller bytes")
        elif record.kind in ("block_timeout", "block_reset_timeout"):
            require(v["budget_ticks"] == budget and v["poll_limit"] == POLL_LIMIT
                    and 1 <= v["polls"] <= POLL_LIMIT and (v["ticks"] >= budget or v["polls"] == POLL_LIMIT),
                    "injected wait did not reach a finite declared limit")
            if record.kind == "block_timeout":
                require(v["injection"] == "hide_used" and v["outcome"] == "timeout"
                        and v["offset"] == 0 and v["length"] == 16
                        and v["submitted"] == v["notified"] == 1 and v["completed"] == 0
                        and v["buffer_unchanged"] == 1, "timeout injection or DMA ownership is inconsistent")
            else:
                require(v["injection"] == "hide_reset_ack" and v["outcome"] == "reset_timeout"
                        and v["retained_pages"] == 2 and v["live_pages"] == BASELINE + 2,
                        "unconfirmed reset did not quarantine both DMA pages")
        elif record.kind == "block_close":
            require(v["reset_confirmed"] == 1 and 1 <= v["reset_polls"] <= POLL_LIMIT
                    and v["remaining_pages"] == BASELINE, "DMA freed without confirmed reset or leaked")
    s = next(r.values for r in records if r.kind == "block_summary")
    require(s == {"reads_ok": 8, "device_errors": device_errors, "injected_timeouts": 1,
                  "injected_reset_timeouts": 1, "submitted": 9 + device_errors, "completed": 8 + device_errors,
                  "notified": 9 + device_errors, "allocated": 4, "freed": 4, "remaining_pages": BASELINE,
                  "quarantined": 0}, "block summary disagrees with individual controls or resource ownership")
    return errors, {"present": True, "capacity_bytes": capacity, "reads": reads, "device_errors": device_errors}


def validate_image(info, image, expect_ioerr=False):
    """Bind parsed readback to actual host input; never trust log-reported bytes."""
    if image is None:
        return {"block_presence_matches_input": info.get("present") is False,
                "all_read_bytes_match_image": info.get("reads") == [],
                "backend_error_matches_injection": info.get("device_errors") == int(expect_ioerr)}
    reads = info.get("reads", [])
    return {"block_presence_matches_input": info.get("present") is True,
            "capacity_matches_image": info.get("capacity_bytes") == len(image),
            "all_read_bytes_match_image": len(reads) == len(READS) and all(
                bytes.fromhex(r["data_hex"]) == image[r["offset"]:r["offset"] + r["length"]]
                and len(bytes.fromhex(r["data_hex"])) == r["length"] for r in reads),
            "backend_error_matches_injection": info.get("device_errors") == int(expect_ioerr)}
