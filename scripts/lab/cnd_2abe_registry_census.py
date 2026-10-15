#!/usr/bin/env python3
"""Inventory the exact-build IA/0x2abe callback registry through KDP.

Ten persistent kernel Blocks in the 23A341 vPhone kernel walk the registry at
``0xfffffe0007789170``.  Each Block loads an entry pointer from ``registry+0x18``,
loads the callback owner from ``entry+0x20``, then authenticates one callback
field with the IA key and constant discriminator ``0x2abe``.  This probe reads
that live structure and correlates stripped callback identities with the
REA-produced ``pac-dispatch-graph-2abe.jsonl`` inventory.

The probe is deliberately read-only.  It does not invoke a Block, change a
registry entry, write kernel memory, or use the VM provider kcall.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"
BUILD = "23A341"
PRODUCT = "iPhone17,3"
STATIC_TEXT = 0xFFFFFE0007008000
STATIC_REGISTRY = 0xFFFFFE0007789170
MAX_REGISTRY_ENTRIES = 256
ADDRESS_RE = re.compile(
    r"^(0x[0-9a-fA-F]{16}):\s+(0x[0-9a-fA-F]{16})\s*$",
    re.MULTILINE,
)
LOAD_RE = re.compile(
    r"^Load Address:\s*(0x[0-9a-fA-F]{16})\s*$", re.MULTILINE,
)
UUID_RE = re.compile(
    r"^Kernel UUID:\s*([0-9A-Fa-f-]{36})\s*$", re.MULTILINE,
)


@dataclass(frozen=True)
class CallbackSlot:
    offset: int
    block: int
    invoke: int


CALLBACK_SLOTS = (
    CallbackSlot(0x0C0, 0xFFFFFE0007788D28, 0xFFFFFE00082D6B28),
    CallbackSlot(0x0B8, 0xFFFFFE0007788D68, 0xFFFFFE00082D6C20),
    CallbackSlot(0x2F8, 0xFFFFFE0007788DA8, 0xFFFFFE00082D6D18),
    CallbackSlot(0x2E8, 0xFFFFFE0007788DE8, 0xFFFFFE00082D6E10),
    CallbackSlot(0x948, 0xFFFFFE0007788E28, 0xFFFFFE00082D6F08),
    CallbackSlot(0x498, 0xFFFFFE0007789088, 0xFFFFFE00082E64BC),
    CallbackSlot(0x490, 0xFFFFFE00077890C8, 0xFFFFFE00082E65B4),
    CallbackSlot(0x4E0, 0xFFFFFE0007789108, 0xFFFFFE00082E73A4),
    CallbackSlot(0x4D8, 0xFFFFFE0007789148, 0xFFFFFE00082E749C),
    CallbackSlot(0x420, 0xFFFFFE00077891B0, 0xFFFFFE00082F0174),
)


class CensusError(RuntimeError):
    """The exact-build identity, graph, or live registry contract failed."""


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _parse_hex(value: Any, field: str) -> int:
    if not isinstance(value, str) or re.fullmatch(
        r"0x[0-9a-fA-F]+", value,
    ) is None:
        raise CensusError(f"invalid {field}: {value!r}")
    return int(value, 16)


def _kernel_data_pointer(value: int) -> bool:
    return 0xFFFFFE0000000000 <= value < 0xFFFFFFFFFFFFFFF8 and value & 7 == 0


def _code_pointer(raw: int) -> int:
    return (raw & 0x00007FFFFFFFFFFF) | 0xFFFF800000000000


def _load_graph(path: Path) -> dict[int, dict[str, Any]]:
    targets: dict[int, dict[str, Any]] = {}
    summary: dict[str, Any] | None = None
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
        if record.get("kind") == "dispatch-target":
            target = _parse_hex(record.get("target"), "graph target")
            domains = record.get("domains")
            if not isinstance(domains, list) or \
                    "0x0000000000002abe" not in domains:
                raise CensusError(f"graph target at line {line_number} is not 0x2abe")
            if target in targets:
                raise CensusError(f"duplicate graph target {_hex(target)}")
            targets[target] = record
        elif record.get("kind") == "summary":
            if summary is not None:
                raise CensusError("graph has more than one summary")
            summary = record
    if summary is None or not targets:
        raise CensusError("graph is missing its summary or targets")
    if summary.get("schema") != "cyanide.pac-dispatch-graph.v1" or \
            summary.get("build") != BUILD or summary.get("product") != PRODUCT or \
            str(summary.get("kernelUUID", "")).upper() != KERNEL_UUID or \
            summary.get("domains") != ["0x0000000000002abe"] or \
            summary.get("failures") != [] or \
            summary.get("usedKernelWrite") is not False or \
            summary.get("usedKernelCall") is not False:
        raise CensusError("graph summary does not match the exact-build contract")
    if summary.get("signedTargets") != len(targets):
        raise CensusError("graph target count does not match its summary")
    return targets


def _identity(kernel: Path, port: int, timeout: int) -> tuple[int, str]:
    completed = subprocess.run(
        [
            "xcrun", "lldb", "--batch",
            "-o", f'target create "{kernel}"',
            "-o", "platform select remote-ios",
            "-o", f"gdb-remote 127.0.0.1:{port}",
            "-o", "process detach",
        ],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=min(timeout, 60),
    )
    return _parse_identity(completed.returncode, completed.stdout)


def _parse_identity(returncode: int, report: str) -> tuple[int, str]:
    if returncode != 0 or "Process 1 detached" not in report:
        raise CensusError("KDP identity handshake failed or did not detach")
    loads = LOAD_RE.findall(report)
    uuids = UUID_RE.findall(report)
    if len(loads) != 1 or len(uuids) != 1:
        raise CensusError("KDP identity handshake was ambiguous")
    uuid = uuids[0].upper()
    if uuid != KERNEL_UUID:
        raise CensusError(f"live kernel UUID {uuid} does not match {KERNEL_UUID}")
    live_text = int(loads[0], 16)
    if live_text < STATIC_TEXT or (live_text - STATIC_TEXT) & 0x3FFF:
        raise CensusError("live kernel text produced an invalid exact-build slide")
    return live_text - STATIC_TEXT, uuid


def _read_words(
    kernel: Path, port: int, addresses: Iterable[int], timeout: int,
    expected_slide: int,
) -> dict[int, int]:
    unique = sorted(set(addresses))
    commands = [
        f'target create "{kernel}"',
        "platform select remote-ios",
        f"gdb-remote 127.0.0.1:{port}",
        "settings set interpreter.stop-command-source-on-error false",
    ]
    commands.extend(
        f"memory read --size 8 --format x --count 1 {_hex(address)}"
        for address in unique
    )
    commands.append("process detach")
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix="cnd-2abe-registry-",
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
            raise CensusError(f"KDP registry read timed out after {timeout}s") from error
    slide, _ = _parse_identity(completed.returncode, completed.stdout)
    if slide != expected_slide:
        raise CensusError("live kernel slide changed during registry census")
    values = {
        int(address, 16): int(value, 16)
        for address, value in ADDRESS_RE.findall(completed.stdout)
    }
    missing = [address for address in unique if address not in values]
    if missing:
        rendered = ", ".join(_hex(address) for address in missing[:8])
        raise CensusError(f"KDP omitted {len(missing)} requested reads: {rendered}")
    return values


def _decode_header(packed_counts: int, array: int) -> tuple[int, int, int]:
    lower_count = packed_counts & 0xFFFFFFFF
    dispatch_count = packed_counts >> 32
    if lower_count > MAX_REGISTRY_ENTRIES or \
            dispatch_count > MAX_REGISTRY_ENTRIES:
        raise CensusError(
            f"registry counts exceed bound: lower={lower_count}, "
            f"dispatch={dispatch_count}"
        )
    if dispatch_count and not _kernel_data_pointer(array):
        raise CensusError(f"invalid registry array pointer {_hex(array)}")
    return lower_count, dispatch_count, array


def _records(
    slide: int,
    entry_owners: Sequence[tuple[int, int, int]],
    callback_values: dict[int, int],
    graph: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, entry, owner in entry_owners:
        for slot in CALLBACK_SLOTS:
            field = owner + slot.offset
            raw = callback_values[field]
            if raw == 0:
                continue
            target = _code_pointer(raw)
            static_target = target - slide
            graph_record = graph.get(static_target)
            result.append({
                "kind": "callback",
                "index": index,
                "entry": _hex(entry),
                "owner": _hex(owner),
                "fieldOffset": _hex(slot.offset),
                "field": _hex(field),
                "rawTarget": _hex(raw),
                "target": _hex(target),
                "staticTarget": _hex(static_target),
                "signed": raw != target,
                "graphKnown": graph_record is not None,
                "targetImage": graph_record.get("image")
                    if graph_record is not None else None,
                "targetInstructions": graph_record.get("instructions")
                    if graph_record is not None else None,
                "block": _hex(slot.block + slide),
                "staticBlock": _hex(slot.block),
                "invoke": _hex(slot.invoke + slide),
                "staticInvoke": _hex(slot.invoke),
                "domain": "IA/0x2abe",
            })
    result.sort(key=lambda row: (row["fieldOffset"], row["index"]))
    return result


def census(
    kernel: Path, graph_path: Path, port: int, timeout: int,
) -> list[dict[str, Any]]:
    graph = _load_graph(graph_path)
    slide, uuid = _identity(kernel, port, timeout)
    registry = STATIC_REGISTRY + slide
    header_addresses = (registry + 0x8, registry + 0x18)
    header = _read_words(kernel, port, header_addresses, timeout, slide)
    lower_count, dispatch_count, array = _decode_header(
        header[registry + 0x8], header[registry + 0x18],
    )

    array_addresses = [array + index * 8 for index in range(dispatch_count)]
    array_values = _read_words(
        kernel, port, array_addresses, timeout, slide,
    ) if array_addresses else {}
    entries = [
        (index, array_values[array + index * 8])
        for index in range(dispatch_count)
        if array_values[array + index * 8] != 0
    ]
    for index, entry in entries:
        if not _kernel_data_pointer(entry):
            raise CensusError(f"entry {index} has invalid pointer {_hex(entry)}")

    owner_addresses = [entry + 0x20 for _, entry in entries]
    owner_values = _read_words(
        kernel, port, owner_addresses, timeout, slide,
    ) if owner_addresses else {}
    entry_owners: list[tuple[int, int, int]] = []
    for index, entry in entries:
        owner = owner_values[entry + 0x20]
        if not _kernel_data_pointer(owner):
            raise CensusError(
                f"entry {index} has invalid callback owner {_hex(owner)}"
            )
        entry_owners.append((index, entry, owner))

    callback_addresses = [
        owner + slot.offset
        for _, _, owner in entry_owners
        for slot in CALLBACK_SLOTS
    ]
    final_addresses = [*header_addresses, *array_addresses, *callback_addresses]
    final = _read_words(kernel, port, final_addresses, timeout, slide)
    if final[registry + 0x8] != header[registry + 0x8] or \
            final[registry + 0x18] != header[registry + 0x18]:
        raise CensusError("registry header changed during census")
    for address in array_addresses:
        if final[address] != array_values[address]:
            raise CensusError(f"registry array changed at {_hex(address)}")

    callbacks = _records(slide, entry_owners, final, graph)
    slot_counts = {
        _hex(slot.offset): sum(
            record["fieldOffset"] == _hex(slot.offset) for record in callbacks
        )
        for slot in CALLBACK_SLOTS
    }
    output: list[dict[str, Any]] = [{
        "kind": "header",
        "schema": "cyanide.2abe-registry-census.v1",
        "build": BUILD,
        "product": PRODUCT,
        "kernelUUID": uuid,
        "slide": _hex(slide),
        "staticRegistry": _hex(STATIC_REGISTRY),
        "registry": _hex(registry),
        "lowerCount": lower_count,
        "dispatchCount": dispatch_count,
        "array": _hex(array),
    }]
    output.extend(callbacks)
    output.append({
        "kind": "summary",
        "schema": "cyanide.2abe-registry-census.v1",
        "kernelUUID": uuid,
        "entries": dispatch_count,
        "nonNullEntries": len(entries),
        "callbacks": len(callbacks),
        "signedCallbacks": sum(bool(record["signed"]) for record in callbacks),
        "graphKnownCallbacks": sum(
            bool(record["graphKnown"]) for record in callbacks
        ),
        "slotCounts": slot_counts,
        "stableSnapshot": True,
        "readOnly": True,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    })
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--graph", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--timeout", type=int, default=180)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.kernel.is_file():
        raise CensusError(f"kernel does not exist: {args.kernel}")
    if not args.graph.is_file():
        raise CensusError(f"graph does not exist: {args.graph}")
    if not 6000 <= args.port <= 65535:
        raise CensusError("--port must be between 6000 and 65535")
    if not 1 <= args.timeout <= 900:
        raise CensusError("--timeout must be from 1 to 900 seconds")
    for record in census(
        args.kernel, args.graph, args.port, args.timeout,
    ):
        print(json.dumps(record, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CensusError, OSError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
