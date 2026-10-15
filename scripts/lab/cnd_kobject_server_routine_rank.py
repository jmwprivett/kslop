#!/usr/bin/env python3
"""Rank reconstructed ipc_kobject_server routines by call/PAC behavior.

Consumes the JSONL produced by ``cnd_kobject_server_table_census.py --offline``
and disassembles only the function ranges named by that evidence.  The output
is triage, not a safety claim: MIG stubs validate message layouts and routinely
dereference ports, objects, and reply buffers before reaching their calls.
"""

from __future__ import annotations

import argparse
import bisect
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence


INSTRUCTION_RE = re.compile(
    r"^([0-9a-f]{16}):\s+[0-9a-f]{8}\s+([.a-zA-Z0-9_]+)(?:\s+(.*))?$"
)
FUNCTION_START_RE = re.compile(r"^[0-9a-f]{16}$")
AUTH_INDIRECT = {
    "blraa", "blrab", "blraaz", "blrabz",
    "braa", "brab", "braaz", "brabz",
}
RAW_INDIRECT = {"blr", "br"}
CODE_PAC_SIGN = {
    "pacia", "pacib", "paciza", "pacizb", "pacia1716", "pacib1716",
}
DATA_PAC_SIGN = {"pacda", "pacdb", "pacdza", "pacdzb"}
MEMORY_WRITE_PREFIXES = (
    "str", "stp", "stur", "cas", "swp", "ldadd", "ldclr", "ldeor", "ldset",
)


class RankError(RuntimeError):
    """The input evidence or disassembly boundary contract failed."""


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _run(command: Sequence[str], label: str) -> str:
    completed = subprocess.run(
        command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise RankError(
            f"{label} failed ({completed.returncode}): {completed.stderr[-2000:]}"
        )
    return completed.stdout


def load_entries(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    header: dict[str, Any] | None = None
    entries: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise RankError(f"cannot read census {path}: {error}") from error
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise RankError(f"invalid JSON at {path}:{line_number}: {error}") from error
        if record.get("kind") == "header":
            if header is not None:
                raise RankError("census has multiple headers")
            header = record
        elif record.get("kind") == "offline-routine-entry":
            target = record.get("staticTarget")
            if not isinstance(target, str) or not re.fullmatch(r"0x[0-9a-f]{16}", target):
                raise RankError(f"invalid static target at line {line_number}")
            entries.append(record)
    if header is None or not entries:
        raise RankError("census is missing its header or offline routine entries")
    if header.get("pointerDiscriminator") != "0x3a83":
        raise RankError("census discriminator is not 0x3a83")
    targets = [entry["staticTarget"] for entry in entries]
    if len(targets) != len(set(targets)):
        raise RankError("census contains duplicate routine targets")
    return header, entries


def function_ranges(kernel: Path, entries: Sequence[dict[str, Any]]) -> dict[int, int]:
    report = _run(
        ["xcrun", "llvm-objdump", "--macho", "--function-starts", str(kernel)],
        "function-start inventory",
    )
    starts = sorted(
        int(line, 16) for line in report.splitlines()
        if FUNCTION_START_RE.fullmatch(line)
    )
    if len(starts) < 2:
        raise RankError("function-start inventory is empty")
    result: dict[int, int] = {}
    start_set = set(starts)
    for entry in entries:
        target = int(entry["staticTarget"], 16)
        if target not in start_set:
            raise RankError(f"routine target {_hex(target)} is not a function start")
        index = bisect.bisect_right(starts, target)
        if index == len(starts):
            raise RankError(f"routine target {_hex(target)} has no bounded function end")
        end = starts[index]
        if end <= target or end - target > 0x10000:
            raise RankError(f"implausible function range {_hex(target)}..{_hex(end)}")
        result[target] = end
    return result


def _clusters(ranges: dict[int, int], gap: int = 0x1000) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for start, end in sorted(ranges.items()):
        if not result or start > result[-1][1] + gap:
            result.append((start, end))
        else:
            result[-1] = (result[-1][0], max(result[-1][1], end))
    return result


def disassemble(
    kernel: Path, ranges: dict[int, int],
) -> dict[int, list[tuple[int, str, str]]]:
    instructions: dict[int, list[tuple[int, str, str]]] = {
        target: [] for target in ranges
    }
    targets = sorted(ranges)
    for cluster_start, cluster_end in _clusters(ranges):
        report = _run([
            "xcrun", "llvm-objdump", "-d", "--arch-name=arm64",
            f"--start-address={cluster_start:#x}",
            f"--stop-address={cluster_end:#x}", str(kernel),
        ], f"disassembly {_hex(cluster_start)}..{_hex(cluster_end)}")
        for line in report.splitlines():
            match = INSTRUCTION_RE.match(line)
            if match is None:
                continue
            address = int(match.group(1), 16)
            index = bisect.bisect_right(targets, address) - 1
            if index < 0:
                continue
            target = targets[index]
            if address >= ranges[target]:
                continue
            instructions[target].append(
                (address, match.group(2).lower(), (match.group(3) or "").strip())
            )
    missing = [_hex(target) for target, values in instructions.items() if not values]
    if missing:
        raise RankError(f"no instructions decoded for: {', '.join(missing[:8])}")
    return instructions


def analyze_instructions(
    start: int, end: int, instructions: Iterable[tuple[int, str, str]],
) -> dict[str, Any]:
    values = list(instructions)
    auth_indirect = [
        f"{_hex(address)}: {mnemonic} {operands}".rstrip()
        for address, mnemonic, operands in values if mnemonic in AUTH_INDIRECT
    ]
    raw_indirect = [
        f"{_hex(address)}: {mnemonic} {operands}".rstrip()
        for address, mnemonic, operands in values if mnemonic in RAW_INDIRECT
    ]
    code_sign = [
        f"{_hex(address)}: {mnemonic} {operands}".rstrip()
        for address, mnemonic, operands in values if mnemonic in CODE_PAC_SIGN
    ]
    data_sign = [
        f"{_hex(address)}: {mnemonic} {operands}".rstrip()
        for address, mnemonic, operands in values if mnemonic in DATA_PAC_SIGN
    ]
    direct_calls = sum(mnemonic == "bl" for _, mnemonic, _ in values)
    memory_writes = sum(
        mnemonic.startswith(MEMORY_WRITE_PREFIXES)
        for _, mnemonic, _ in values
    )
    x3_references = [
        f"{_hex(address)}: {mnemonic} {operands}".rstrip()
        for address, mnemonic, operands in values
        if re.search(r"(?<![a-zA-Z0-9_])(?:x3|w3)(?![0-9])", operands)
    ]
    x3_aliases = {"x3"}
    writes_through_x3: list[str] = []
    for address, mnemonic, operands in values:
        parts = [part.strip() for part in operands.split(",")]
        if mnemonic == "mov" and len(parts) >= 2 and re.fullmatch(r"x[0-9]+", parts[0]):
            if parts[1] in x3_aliases:
                x3_aliases.add(parts[0])
        elif mnemonic in {"add", "sub"} and len(parts) >= 3 \
                and re.fullmatch(r"x[0-9]+", parts[0]):
            if parts[1] in x3_aliases:
                x3_aliases.add(parts[0])
        # Aliases are deliberately may-alias, not linear register state.  A
        # write on a branch that bypasses a later reassignment must still make
        # the candidate fail closed.
        if mnemonic.startswith(MEMORY_WRITE_PREFIXES) and any(
            re.search(rf"\[{alias}(?:,|\])", operands) for alias in x3_aliases
        ):
            writes_through_x3.append(
                f"{_hex(address)}: {mnemonic} {operands}".rstrip()
            )
    size = end - start
    # Authenticated/raw call-through and code-signing behavior dominate.  Data
    # signing is retained but scores lower because it cannot directly produce
    # an instruction pointer.  Smaller routines receive a modest tie-breaker.
    score = (
        80 * len(auth_indirect)
        + 140 * len(raw_indirect)
        + 180 * len(code_sign)
        + 25 * len(data_sign)
        + min(memory_writes, 20)
        + max(0, 32 - size // 32)
        - 300 * bool(writes_through_x3)
        + 60 * (not x3_references)
    )
    return {
        "functionStart": _hex(start),
        "functionEnd": _hex(end),
        "size": size,
        "instructionCount": len(values),
        "directCalls": direct_calls,
        "memoryWrites": memory_writes,
        "authenticatedIndirectBranches": auth_indirect,
        "rawIndirectBranches": raw_indirect,
        "codePACSigners": code_sign,
        "dataPACSigners": data_sign,
        "constrainedX3References": x3_references,
        "writesThroughConstrainedX3": writes_through_x3,
        "constrainedX3SafeCandidate": not writes_through_x3,
        "rankScore": score,
    }


def rank(kernel: Path, census: Path) -> list[dict[str, Any]]:
    header, entries = load_entries(census)
    ranges = function_ranges(kernel, entries)
    instruction_map = disassemble(kernel, ranges)
    ranked: list[dict[str, Any]] = []
    for entry in entries:
        target = int(entry["staticTarget"], 16)
        ranked.append({
            **entry,
            "kind": "routine-rank",
            **analyze_instructions(target, ranges[target], instruction_map[target]),
        })
    ranked.sort(key=lambda item: (-item["rankScore"], item["size"], item["staticTarget"]))
    for position, record in enumerate(ranked, 1):
        record["rank"] = position
    return [{
        "kind": "header",
        "schema": "cnd-kobject-server-routine-rank-v1",
        "sourceSchema": header.get("schema"),
        "kernelUUID": header.get("kernelUUID"),
        "pointerDiscriminator": header.get("pointerDiscriminator"),
        "routineCount": len(ranked),
        "readOnly": True,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }, *ranked, {
        "kind": "summary",
        "routines": len(ranked),
        "withAuthenticatedIndirectBranch": sum(
            bool(item["authenticatedIndirectBranches"]) for item in ranked
        ),
        "withRawIndirectBranch": sum(bool(item["rawIndirectBranches"]) for item in ranked),
        "withCodePACSigner": sum(bool(item["codePACSigners"]) for item in ranked),
        "withDataPACSigner": sum(bool(item["dataPACSigners"]) for item in ranked),
        "withoutObservedWriteThroughConstrainedX3": sum(
            item["constrainedX3SafeCandidate"] for item in ranked
        ),
        "readOnly": True,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("census", type=Path)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.kernel.is_file():
        raise RankError(f"kernel does not exist: {args.kernel}")
    records = rank(args.kernel, args.census)
    lines = "\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n"
    if args.output is None:
        sys.stdout.write(lines)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(lines, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RankError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
