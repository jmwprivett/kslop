#!/usr/bin/env python3
"""Read the exact-build ipc_kobject_server routine table through KDP.

The iOS 26.0 23A341 kernel populates a 0x407-slot hash table at boot.  Each
occupied 0x18-byte slot contains a Mach message ID and a routine pointer signed
for the constant IA discriminator 0x3a83.  ``ipc_kobject_server`` authenticates
that pointer at 0xfffffe0007b0007c and invokes it with five arguments.

This tool performs a bounded, read-only KDP dump of that table.  It strips PAC
only to recover code identity for triage; it does not write kernel memory,
invoke any entry, or claim that an entry is safe to call outside its MIG ABI.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"
STATIC_TEXT = 0xFFFFFE0007008000
STATIC_BASE = 0xFFFFFE0007004000
FILES_MAX_SPAN = 0x40000000

STATIC_TABLE = 0xFFFFFE000767C340
STATIC_MAX_PROBE_COUNT = 0xFFFFFE00076823E8
STATIC_SUBSYSTEM_ARRAY = 0xFFFFFE0009790B38
SUBSYSTEM_COUNT = 0x11
STATIC_TABLE_CONSTRUCTOR = 0xFFFFFE00082FA964
TABLE_SLOTS = 0x407
ENTRY_SIZE = 0x18
TABLE_SIZE = TABLE_SLOTS * ENTRY_SIZE
POINTER_DISCRIMINATOR = 0x3A83
STATIC_DISPATCH_CALLSITE = 0xFFFFFE0007B0007C

LOAD_RE = re.compile(r"^Load Address:\s*(0x[0-9a-fA-F]{16})\s*$", re.MULTILINE)
UUID_RE = re.compile(r"^Kernel UUID:\s*([0-9A-Fa-f-]{36})\s*$", re.MULTILINE)


class CensusError(RuntimeError):
    """The exact-build identity, bounded read, or table contract failed."""


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _canonical_code_pointer(raw: int) -> int:
    """Recover the 47-bit kernel VA identity without authenticating ``raw``."""

    return (raw & 0x00007FFFFFFFFFFF) | 0xFFFF800000000000


def parse_table(data: bytes, slide: int) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Parse one complete table dump and partition valid entries/anomalies."""

    if len(data) != TABLE_SIZE:
        raise CensusError(
            f"table dump is {len(data):#x} bytes; expected exactly {TABLE_SIZE:#x}"
        )
    if slide < 0 or slide & 0xFFF:
        raise CensusError(f"invalid kernel slide {slide:#x}")

    live_base = STATIC_BASE + slide
    records: list[dict[str, Any]] = []
    occupied = 0
    valid = 0
    malformed = 0
    message_ids: set[int] = set()
    duplicate_ids = 0

    for slot in range(TABLE_SLOTS):
        offset = slot * ENTRY_SIZE
        message_id, padding, raw_target, metadata_word_10, metadata_word_14 = struct.unpack_from(
            "<IIQII", data, offset
        )
        if message_id == 0 and raw_target == 0:
            if padding != 0 or metadata_word_10 != 0 or metadata_word_14 != 0:
                malformed += 1
                records.append({
                    "kind": "slot-anomaly",
                    "slot": slot,
                    "reason": "empty slot has nonzero metadata",
                    "messageID": message_id,
                    "padding": f"0x{padding:08x}",
                    "rawTarget": _hex(raw_target),
                    "metadataWord10": metadata_word_10,
                    "metadataWord14": metadata_word_14,
                })
            continue

        occupied += 1
        target = _canonical_code_pointer(raw_target) if raw_target else 0
        reasons: list[str] = []
        if message_id == 0:
            reasons.append("zero message ID")
        if padding != 0:
            reasons.append("nonzero alignment word")
        if raw_target == 0:
            reasons.append("null routine pointer")
        elif target & 3:
            reasons.append("unaligned routine identity")
        elif not live_base <= target < live_base + FILES_MAX_SPAN:
            reasons.append("routine identity outside kernel fileset span")
        if message_id in message_ids:
            duplicate_ids += 1
            reasons.append("duplicate message ID")
        else:
            message_ids.add(message_id)

        if reasons:
            malformed += 1
            records.append({
                "kind": "slot-anomaly",
                "slot": slot,
                "reason": "; ".join(reasons),
                "messageID": message_id,
                "padding": f"0x{padding:08x}",
                "rawTarget": _hex(raw_target),
                "target": _hex(target) if target else None,
                "metadataWord10": metadata_word_10,
                "metadataWord14": metadata_word_14,
            })
            continue

        valid += 1
        records.append({
            "kind": "routine-entry",
            "slot": slot,
            "slotAddress": _hex(STATIC_TABLE + slide + offset),
            "messageID": message_id,
            "messageIDHex": f"0x{message_id:08x}",
            "rawTarget": _hex(raw_target),
            "target": _hex(target),
            "staticTarget": _hex(target - slide),
            "metadataWord10": metadata_word_10,
            "metadataWord14": metadata_word_14,
            "pointerDiscriminator": f"0x{POINTER_DISCRIMINATOR:04x}",
        })

    return records, {
        "slots": TABLE_SLOTS,
        "occupied": occupied,
        "validEntries": valid,
        "malformedEntries": malformed,
        "duplicateMessageIDs": duplicate_ids,
    }


class MachOImage:
    """Minimal fail-closed VM-address reader for one little-endian Mach-O 64."""

    def __init__(self, path: Path) -> None:
        try:
            self.data = path.read_bytes()
        except OSError as error:
            raise CensusError(f"cannot read Mach-O {path}: {error}") from error
        if len(self.data) < 32 or struct.unpack_from("<I", self.data)[0] != 0xFEEDFACF:
            raise CensusError(f"{path} is not a little-endian Mach-O 64 image")
        ncmds, sizeofcmds = struct.unpack_from("<II", self.data, 16)
        if ncmds > 4096 or 32 + sizeofcmds > len(self.data):
            raise CensusError("Mach-O load-command bounds are invalid")
        self.mappings: list[tuple[int, int, int]] = []
        cursor = 32
        for _ in range(ncmds):
            if cursor + 8 > 32 + sizeofcmds:
                raise CensusError("truncated Mach-O load command")
            command, command_size = struct.unpack_from("<II", self.data, cursor)
            if command_size < 8 or cursor + command_size > 32 + sizeofcmds:
                raise CensusError("invalid Mach-O load-command size")
            if command == 0x19:
                if command_size < 72:
                    raise CensusError("truncated LC_SEGMENT_64")
                vm_address, _vm_size, file_offset, file_size = struct.unpack_from(
                    "<QQQQ", self.data, cursor + 24
                )
                if file_size and file_offset + file_size <= len(self.data):
                    self.mappings.append((vm_address, vm_address + file_size, file_offset))
            cursor += command_size
        if not self.mappings:
            raise CensusError("Mach-O has no file-backed LC_SEGMENT_64 mappings")

    def read_vm(self, address: int, size: int) -> bytes:
        for start, end, file_offset in self.mappings:
            if start <= address and address + size <= end:
                offset = file_offset + address - start
                return self.data[offset:offset + size]
        raise CensusError(f"VM range {_hex(address)}+{size:#x} is not file backed")


def _decode_chained_rebase(raw: int, field: str) -> int:
    """Decode the target offset used by this kernel's chained rebase words."""

    target = STATIC_BASE + (raw & 0xFFFFFFFF)
    if raw == 0 or not STATIC_BASE <= target < STATIC_BASE + FILES_MAX_SPAN:
        raise CensusError(f"invalid {field} chained rebase {_hex(raw)}")
    return target


def _hash_slot(message_id: int) -> int:
    return message_id % TABLE_SLOTS


def reconstruct_offline(
    read_vm: Any, subsystem_count: int = SUBSYSTEM_COUNT,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Reproduce the table constructor from exact-build static descriptors."""

    if subsystem_count < 1 or subsystem_count > 0x100:
        raise CensusError("invalid subsystem count")
    slots: list[dict[str, Any] | None] = [None] * TABLE_SLOTS
    records: list[dict[str, Any]] = []
    routines_seen = 0
    null_routines = 0
    max_probe = 0

    array = read_vm(STATIC_SUBSYSTEM_ARRAY, subsystem_count * 8)
    if len(array) != subsystem_count * 8:
        raise CensusError("short subsystem-array read")
    for subsystem_index in range(subsystem_count):
        raw_descriptor = struct.unpack_from("<Q", array, subsystem_index * 8)[0]
        descriptor = _decode_chained_rebase(
            raw_descriptor, f"subsystem[{subsystem_index}]"
        )
        header = read_vm(descriptor, 0x20)
        if len(header) != 0x20:
            raise CensusError(f"short subsystem[{subsystem_index}] header")
        start_id, end_id, max_message_size = struct.unpack_from("<III", header, 8)
        if end_id < start_id or end_id - start_id > 0x4000:
            raise CensusError(
                f"subsystem[{subsystem_index}] has invalid ID range "
                f"{start_id:#x}..{end_id:#x}"
            )
        routine_count = end_id - start_id
        routines = read_vm(descriptor + 0x20, routine_count * 0x20)
        if len(routines) != routine_count * 0x20:
            raise CensusError(f"short subsystem[{subsystem_index}] routine array")

        for routine_index in range(routine_count):
            routine_offset = routine_index * 0x20
            raw_target = struct.unpack_from("<Q", routines, routine_offset + 8)[0]
            if raw_target == 0:
                null_routines += 1
                continue
            routines_seen += 1
            discriminator = (raw_target >> 32) & 0xFFFF
            authenticated = bool(raw_target >> 63)
            if not authenticated or discriminator != POINTER_DISCRIMINATOR:
                raise CensusError(
                    f"subsystem[{subsystem_index}] routine[{routine_index}] "
                    f"is not an authenticated 0x{POINTER_DISCRIMINATOR:04x} rebase"
                )
            target = _decode_chained_rebase(
                raw_target, f"subsystem[{subsystem_index}] routine[{routine_index}]"
            )
            metadata_word_14, metadata_word_10 = struct.unpack_from(
                "<II", routines, routine_offset + 0x18
            )
            message_id = start_id + routine_index
            slot = _hash_slot(message_id)
            probe_count = 1
            while slots[slot] is not None:
                if slots[slot]["messageID"] == message_id:
                    raise CensusError(f"duplicate message ID {message_id:#x}")
                slot = (slot + 1) % TABLE_SLOTS
                probe_count += 1
                if probe_count > TABLE_SLOTS:
                    raise CensusError("reconstructed routine table is full")
            max_probe = max(max_probe, probe_count)
            record = {
                "kind": "offline-routine-entry",
                "slot": slot,
                "staticSlotAddress": _hex(STATIC_TABLE + slot * ENTRY_SIZE),
                "subsystemIndex": subsystem_index,
                "subsystemDescriptor": _hex(descriptor),
                "routineIndex": routine_index,
                "messageID": message_id,
                "messageIDHex": f"0x{message_id:08x}",
                "chainedTarget": _hex(raw_target),
                "staticTarget": _hex(target),
                "metadataWord10": metadata_word_10,
                "metadataWord14": metadata_word_14,
                "maxMessageSize": max_message_size,
                "probeCount": probe_count,
                "pointerDiscriminator": f"0x{POINTER_DISCRIMINATOR:04x}",
            }
            slots[slot] = record
            records.append(record)

    records.sort(key=lambda record: record["slot"])
    return records, {
        "subsystems": subsystem_count,
        "routines": routines_seen,
        "nullRoutines": null_routines,
        "maxProbeCount": max_probe,
    }


def offline_census(kernel: Path) -> list[dict[str, Any]]:
    image = MachOImage(kernel)
    records, counts = reconstruct_offline(image.read_vm)
    return [{
        "kind": "header",
        "schema": "cnd-kobject-server-table-census-v1",
        "mode": "offline-constructor-reconstruction",
        "kernelUUID": KERNEL_UUID,
        "staticTable": _hex(STATIC_TABLE),
        "subsystemArray": _hex(STATIC_SUBSYSTEM_ARRAY),
        "tableConstructor": _hex(STATIC_TABLE_CONSTRUCTOR),
        "slots": TABLE_SLOTS,
        "entrySize": ENTRY_SIZE,
        "pointerDiscriminator": f"0x{POINTER_DISCRIMINATOR:04x}",
        "dispatchCallsite": _hex(STATIC_DISPATCH_CALLSITE),
        "readOnly": True,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }, *records, {
        "kind": "summary",
        **counts,
        "readOnly": True,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }]


def _run_lldb(commands: Sequence[str], timeout: int, label: str) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix="cnd-kobject-table-",
        suffix=".lldb", delete=True,
    ) as command_file:
        command_file.write("\n".join(commands) + "\n")
        command_file.flush()
        try:
            completed = subprocess.run(
                ["xcrun", "lldb", "--batch", "-s", command_file.name],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise CensusError(f"{label} timed out after {timeout}s") from error
    if completed.returncode != 0:
        raise CensusError(
            f"{label} failed ({completed.returncode}):\n{completed.stdout[-4000:]}"
        )
    if "Process 1 detached" not in completed.stdout:
        raise CensusError(f"{label} did not detach from the VM")
    return completed.stdout


def _identity(kernel: Path, port: int, timeout: int) -> tuple[int, str]:
    report = _run_lldb([
        f'target create "{kernel}"',
        "platform select remote-ios",
        f"gdb-remote 127.0.0.1:{port}",
        "process detach",
    ], min(timeout, 60), "KDP identity handshake")
    loads = LOAD_RE.findall(report)
    uuids = UUID_RE.findall(report)
    if len(loads) != 1 or len(uuids) != 1:
        raise CensusError("KDP did not report one kernel load address and UUID")
    uuid = uuids[0].upper()
    if uuid != KERNEL_UUID:
        raise CensusError(f"live kernel UUID {uuid} does not match {KERNEL_UUID}")
    live_text = int(loads[0], 16)
    if live_text < STATIC_TEXT:
        raise CensusError("live kernel text precedes exact-build static text")
    slide = live_text - STATIC_TEXT
    if slide & 0xFFF:
        raise CensusError(f"live kernel slide is not page aligned: {slide:#x}")
    return slide, uuid


def census(kernel: Path, port: int, timeout: int) -> list[dict[str, Any]]:
    slide, uuid = _identity(kernel, port, timeout)
    live_table = STATIC_TABLE + slide
    live_max_probe_count = STATIC_MAX_PROBE_COUNT + slide

    with tempfile.TemporaryDirectory(prefix="cnd-kobject-table-") as directory:
        root = Path(directory)
        table_path = root / "table.bin"
        max_probe_path = root / "max-probe-count.bin"
        _run_lldb([
            f'target create "{kernel}"',
            "platform select remote-ios",
            f"gdb-remote 127.0.0.1:{port}",
            "settings set interpreter.stop-command-source-on-error false",
            (
                f'memory read --force --binary --outfile "{table_path}" '
                f"{live_table:#x} {live_table + TABLE_SIZE:#x}"
            ),
            (
                f'memory read --force --binary --outfile "{max_probe_path}" '
                f"{live_max_probe_count:#x} {live_max_probe_count + 4:#x}"
            ),
            "process detach",
        ], timeout, "KDP kobject table census")
        try:
            data = table_path.read_bytes()
        except OSError as error:
            raise CensusError(f"cannot read LLDB table dump: {error}") from error
        records, counts = parse_table(data, slide)
        max_probe_count: int | None = None
        try:
            max_probe_data = max_probe_path.read_bytes()
            if len(max_probe_data) == 4:
                max_probe_count = struct.unpack("<I", max_probe_data)[0]
        except OSError:
            pass

    header = {
        "kind": "header",
        "schema": "cnd-kobject-server-table-census-v1",
        "kernelUUID": uuid,
        "staticText": _hex(STATIC_TEXT),
        "liveText": _hex(STATIC_TEXT + slide),
        "slide": _hex(slide),
        "staticTable": _hex(STATIC_TABLE),
        "liveTable": _hex(live_table),
        "slots": TABLE_SLOTS,
        "entrySize": ENTRY_SIZE,
        "pointerDiscriminator": f"0x{POINTER_DISCRIMINATOR:04x}",
        "dispatchCallsite": _hex(STATIC_DISPATCH_CALLSITE),
        "readOnly": True,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }
    summary: dict[str, Any] = {
        "kind": "summary",
        **counts,
        "reportedMaxProbeCount": max_probe_count,
        "readOnly": True,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }
    return [header, *records, summary]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--port", type=int)
    parser.add_argument(
        "--offline", action="store_true",
        help="reconstruct entries from the exact-build MIG descriptors without KDP",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=int, default=180)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.kernel.is_file():
        raise CensusError(f"kernel does not exist: {args.kernel}")
    if args.offline and args.port is not None:
        raise CensusError("--offline and --port are mutually exclusive")
    if not args.offline and args.port is None:
        raise CensusError("--port is required unless --offline is selected")
    if args.port is not None and not 6000 <= args.port <= 65535:
        raise CensusError("--port must be between 6000 and 65535")
    if not 1 <= args.timeout <= 900:
        raise CensusError("--timeout must be from 1 to 900 seconds")
    lines = "\n".join(
        json.dumps(record, separators=(",", ":"))
        for record in (
            offline_census(args.kernel) if args.offline
            else census(args.kernel, args.port, args.timeout)
        )
    ) + "\n"
    if args.output is None:
        sys.stdout.write(lines)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(lines, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CensusError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
