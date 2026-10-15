#!/usr/bin/env python3
"""Read a bounded callback field from known live IOKit objects through KDP.

The input is the JSONL emitted by ``cnd_iokit_pm_vtable_census --graph``.
Only objects already validated by that inventory are inspected, and exactly one
eight-byte field is read from each object.  KDP performs the reads while the VM
is stopped, avoiding an in-kernel read that could cross a GZAlloc boundary.

The default ``+0x10`` field is the address-diversified callback consumed by the
exact-build bridges at 0xfffffe00081d46f4 and 0xfffffe00082f6458.  A candidate
record means the PAC-independent 47-bit code identity falls in the live kernel
fileset address range; it does not establish that invoking the callback is safe.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"
STATIC_TEXT = 0xFFFFFE0007008000
STATIC_BASE = 0xFFFFFE0007004000
FILES_MAX_SPAN = 0x40000000
ADDRESS_RE = re.compile(
    r"^(0x[0-9a-f]{16}):\s+(0x[0-9a-f]{16})\s*$", re.MULTILINE
)


class CensusError(RuntimeError):
    """The graph, debugger identity, or bounded read contract failed."""


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _parse_hex(value: Any, field: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
        raise CensusError(f"invalid {field}: {value!r}")
    return int(value, 16)


def _load_graph(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    header: dict[str, Any] | None = None
    nodes: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise CensusError(f"cannot read graph {path}: {error}") from error
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise CensusError(
                f"invalid graph JSON at {path}:{line_number}: {error}"
            ) from error
        if not isinstance(record, dict):
            raise CensusError(f"non-object graph record at {path}:{line_number}")
        if record.get("kind") == "header":
            if header is not None:
                raise CensusError("graph has more than one header")
            header = record
        elif record.get("kind") == "graph-node":
            _parse_hex(record.get("object"), "graph object")
            nodes.append(record)
    if header is None or not nodes:
        raise CensusError("graph is missing its header or nodes")
    objects = [_parse_hex(node["object"], "graph object") for node in nodes]
    if len(objects) != len(set(objects)):
        raise CensusError("graph contains duplicate objects")
    return header, nodes


def _lldb_report(
    kernel: Path, port: int, addresses: Sequence[int], timeout: int,
) -> str:
    commands = [
        f'target create "{kernel}"',
        "platform select remote-ios",
        f"gdb-remote 127.0.0.1:{port}",
        "settings set interpreter.stop-command-source-on-error false",
    ]
    commands.extend(
        f"memory read --size 8 --format x --count 1 {_hex(address)}"
        for address in addresses
    )
    commands.append("process detach")
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix="cnd-callback-census-",
        suffix=".lldb", delete=True,
    ) as command_file:
        command_file.write("\n".join(commands) + "\n")
        command_file.flush()
        try:
            completed = subprocess.run(
                ["xcrun", "lldb", "--batch", "-s", command_file.name],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise CensusError(f"LLDB callback census timed out after {timeout}s") from error
    if completed.returncode != 0:
        raise CensusError(
            f"LLDB callback census failed ({completed.returncode}):\n"
            f"{completed.stdout[-4000:]}"
        )
    if "Process 1 detached" not in completed.stdout:
        raise CensusError("LLDB callback census did not detach")
    return completed.stdout


def _debugger_identity(report: str) -> tuple[int, str]:
    loads = re.findall(r"^Load Address:\s*(0x[0-9a-fA-F]{16})\s*$", report,
                       re.MULTILINE)
    uuids = re.findall(r"^Kernel UUID:\s*([0-9A-Fa-f-]{36})\s*$", report,
                       re.MULTILINE)
    if len(loads) != 1 or len(uuids) != 1:
        raise CensusError("LLDB did not report one kernel load address and UUID")
    uuid = uuids[0].upper()
    if uuid != KERNEL_UUID:
        raise CensusError(f"live kernel UUID {uuid} does not match {KERNEL_UUID}")
    return int(loads[0], 16), uuid


def _code_pointer(raw: int) -> int:
    # Exact build uses a 47-bit VA identity for PAC-protected code pointers.
    return (raw & 0x00007FFFFFFFFFFF) | 0xFFFF800000000000


def census(
    graph: Path, kernel: Path, port: int, offset: int, timeout: int,
) -> list[dict[str, Any]]:
    header, nodes = _load_graph(graph)
    addresses = [_parse_hex(node["object"], "graph object") + offset
                 for node in nodes]
    report = _lldb_report(kernel, port, addresses, timeout)
    live_text, uuid = _debugger_identity(report)
    if live_text < STATIC_TEXT:
        raise CensusError("live kernel text precedes static text")
    slide = live_text - STATIC_TEXT
    graph_base = _parse_hex(header.get("kernelBase"), "graph kernel base")
    if graph_base != STATIC_BASE + slide:
        raise CensusError(
            f"graph boot identity drifted: graph={_hex(graph_base)}, "
            f"live={_hex(STATIC_BASE + slide)}"
        )

    reads = {int(address, 16): int(value, 16)
             for address, value in ADDRESS_RE.findall(report)}
    live_base = STATIC_BASE + slide
    output: list[dict[str, Any]] = []
    candidates = 0
    failed = 0
    for node, address in zip(nodes, addresses):
        raw = reads.get(address)
        if raw is None:
            failed += 1
            output.append({
                "kind": "read-failure",
                "index": node.get("index"),
                "object": node["object"],
                "field": _hex(address),
            })
            continue
        target = _code_pointer(raw)
        executable_identity = (
            raw != 0 and target & 3 == 0
            and live_base <= target < live_base + FILES_MAX_SPAN
        )
        if not executable_identity:
            continue
        candidates += 1
        output.append({
            "kind": "callback-candidate",
            "index": node.get("index"),
            "depth": node.get("depth"),
            "rootName": node.get("rootName"),
            "object": node["object"],
            "parent": node.get("parent"),
            "parentOffset": node.get("parentOffset"),
            "fieldOffset": _hex(offset),
            "field": _hex(address),
            "rawTarget": _hex(raw),
            "target": _hex(target),
            "staticTarget": _hex(target - slide),
        })
    output.append({
        "kind": "summary",
        "kernelUUID": uuid,
        "liveText": _hex(live_text),
        "slide": _hex(slide),
        "objects": len(nodes),
        "reads": len(nodes) - failed,
        "readFailures": failed,
        "candidates": candidates,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    })
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph", type=Path)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--offset", type=lambda value: int(value, 0), default=0x10)
    parser.add_argument("--timeout", type=int, default=180)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.kernel.is_file():
        raise CensusError(f"kernel does not exist: {args.kernel}")
    if not 6000 <= args.port <= 65535:
        raise CensusError("--port must be between 6000 and 65535")
    if args.offset < 0 or args.offset > 0x1000 or args.offset & 7:
        raise CensusError("--offset must be an aligned value from 0 to 0x1000")
    if args.timeout < 1 or args.timeout > 900:
        raise CensusError("--timeout must be from 1 to 900 seconds")
    for record in census(
        args.graph, args.kernel, args.port, args.offset, args.timeout,
    ):
        print(json.dumps(record, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CensusError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
