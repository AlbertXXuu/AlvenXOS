"""Select one complete serial protocol version; never infer or rewrite events."""
import log_parser
import stage02_parser
import stage03_parser
import stage04_parser
import stage05_parser
import stage06_parser


def inspect_detailed(log):
    boots = [line for line in log.splitlines() if line.lstrip().startswith("ALVENX")]
    try:
        if len(boots) != 1:
            raise ValueError("exactly one unindented complete boot record is required")
        boot = log_parser.decode(boots[0])
        if boot.kind != "boot":
            raise ValueError("invalid boot record")
        parser = {"0.1.0": log_parser, "0.2.0": stage02_parser, "0.3.0": stage03_parser,
                  "0.4.0": stage04_parser, "0.5.0": stage05_parser, "0.6.0": stage06_parser}.get(boot.values["version"])
        if parser is None:
            raise ValueError("unknown serial protocol version")
        before_boot = log.splitlines()[:log.splitlines().index(boots[0])]
        if any(line.lstrip().startswith(stage06_parser.KERNEL_PREFIXES) for line in before_boot):
            raise ValueError("kernel record before boot")
        return parser.inspect_detailed(log)
    except ValueError as error:
        return log_parser.Inspection({"protocol_version": False}, [], [], [str(error)])


def inspect(log):
    """Compatibility tuple API for existing read-only review tools."""
    result = inspect_detailed(log)
    return result.checks, result.metrics, result.memory
