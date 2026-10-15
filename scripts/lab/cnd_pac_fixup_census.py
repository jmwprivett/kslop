#!/usr/bin/env python3
"""Census an exact kernel collection's authenticated chained fixups.

This walks ``LC_DYLD_CHAINED_FIXUPS`` rather than treating every pointer-like
word in data as a fixup.  The immediate use is to test whether the IOKit
notification virtual-call contract (IA, address diversified, diversity
``0xface``) has any cross-class substitution candidate in a 23A341 kernel
collection.

The tool is read-only.  It emits one JSON evidence document and can fail closed
on an expected count, field address, target, or raw encoded pointer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


MH_MAGIC_64 = 0xFEEDFACF
MH_FILESET = 0xC
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_DYLD_CHAINED_FIXUPS = 0x80000034

DYLD_CHAINED_PTR_ARM64E_KERNEL = 7
DYLD_CHAINED_PTR_64_KERNEL_CACHE = 8
DYLD_CHAINED_PTR_START_NONE = 0xFFFF
DYLD_CHAINED_PTR_START_MULTI = 0x8000
DYLD_CHAINED_PTR_START_LAST = 0x8000

KEY_NAMES = {0: "IA", 1: "IB", 2: "DA", 3: "DB"}
KEY_VALUES = {value.lower(): key for key, value in KEY_NAMES.items()}


class CensusError(RuntimeError):
    """The Mach-O, chained-fixup, or requested evidence contract failed."""


@dataclass(frozen=True)
class Segment:
    index: int
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


@dataclass(frozen=True)
class MachO:
    path: Path
    data: bytes
    filetype: int
    uuid: str | None
    segments: tuple[Segment, ...]
    fixups_offset: int
    fixups_size: int


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _cstring(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("ascii", errors="strict")


def _require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise CensusError(
            f"{label} is outside the file: offset={offset:#x} size={size:#x}"
        )


def parse_macho(path: Path) -> MachO:
    data = path.read_bytes()
    _require_range(data, 0, 32, "Mach-O header")
    magic, _cpu, _subtype, filetype, ncmds, sizeofcmds, _flags, _reserved = (
        struct.unpack_from("<IiiIIIII", data, 0)
    )
    if magic != MH_MAGIC_64:
        raise CensusError(f"{path}: not a little-endian 64-bit Mach-O")
    _require_range(data, 32, sizeofcmds, "Mach-O load commands")

    cursor = 32
    end = cursor + sizeofcmds
    segments: list[Segment] = []
    uuid: str | None = None
    fixups: tuple[int, int] | None = None
    for _ in range(ncmds):
        _require_range(data, cursor, 8, "load command")
        command, command_size = struct.unpack_from("<II", data, cursor)
        if command_size < 8 or cursor + command_size > end:
            raise CensusError(f"{path}: malformed load command at {cursor:#x}")
        if command == LC_SEGMENT_64:
            if command_size < 72:
                raise CensusError(f"{path}: short LC_SEGMENT_64")
            (_cmd, _size, raw_name, vmaddr, vmsize, fileoff, filesize,
             _maxprot, _initprot, _nsects, _segflags) = struct.unpack_from(
                "<II16sQQQQiiII", data, cursor
            )
            _require_range(data, fileoff, filesize, f"segment {_cstring(raw_name)}")
            segments.append(Segment(
                index=len(segments),
                name=_cstring(raw_name),
                vmaddr=vmaddr,
                vmsize=vmsize,
                fileoff=fileoff,
                filesize=filesize,
            ))
        elif command == LC_UUID:
            if command_size < 24:
                raise CensusError(f"{path}: short LC_UUID")
            raw = data[cursor + 8:cursor + 24].hex().upper()
            uuid = f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}"
        elif command == LC_DYLD_CHAINED_FIXUPS:
            if command_size < 16:
                raise CensusError(f"{path}: short LC_DYLD_CHAINED_FIXUPS")
            if fixups is not None:
                raise CensusError(f"{path}: multiple chained-fixup commands")
            fixups = struct.unpack_from("<II", data, cursor + 8)
        cursor += command_size
    if cursor != end:
        raise CensusError(f"{path}: load-command size drift")
    if not segments:
        raise CensusError(f"{path}: no segments")
    if fixups is None:
        raise CensusError(f"{path}: no LC_DYLD_CHAINED_FIXUPS")
    _require_range(data, fixups[0], fixups[1], "chained-fixup payload")
    return MachO(
        path=path,
        data=data,
        filetype=filetype,
        uuid=uuid,
        segments=tuple(segments),
        fixups_offset=fixups[0],
        fixups_size=fixups[1],
    )


def decode_arm64e_auth_rebase(raw: int, base: int) -> dict[str, Any] | None:
    auth = (raw >> 63) & 1
    bind = (raw >> 62) & 1
    if not auth or bind:
        return None
    target_offset = raw & 0xFFFFFFFF
    key = (raw >> 49) & 0x3
    return {
        "targetOffset": _hex(target_offset),
        "target": _hex(base + target_offset),
        "diversity": f"0x{(raw >> 32) & 0xffff:04x}",
        "addressDiversity": bool((raw >> 48) & 1),
        "key": KEY_NAMES[key],
        "next": (raw >> 51) & 0x7FF,
        "bind": False,
        "authenticated": True,
    }


def decode_kernel_cache_auth_rebase(raw: int, base: int) -> dict[str, Any] | None:
    if not (raw >> 63) & 1:
        return None
    target_offset = raw & 0x3FFFFFFF
    cache_level = (raw >> 30) & 0x3
    key = (raw >> 49) & 0x3
    # The primary collection is cache level zero.  Other levels require the
    # loader's basePointers[] array, so do not fabricate a canonical target.
    target = _hex(base + target_offset) if cache_level == 0 else None
    return {
        "targetOffset": _hex(target_offset),
        "target": target,
        "cacheLevel": cache_level,
        "diversity": f"0x{(raw >> 32) & 0xffff:04x}",
        "addressDiversity": bool((raw >> 48) & 1),
        "key": KEY_NAMES[key],
        "next": (raw >> 51) & 0xFFF,
        "authenticated": True,
    }


def _page_starts(data: bytes, segment_info: int, page_count: int,
                 page_index: int) -> list[int]:
    page_array = segment_info + 22
    entry = struct.unpack_from("<H", data, page_array + page_index * 2)[0]
    if entry == DYLD_CHAINED_PTR_START_NONE:
        return []
    if not entry & DYLD_CHAINED_PTR_START_MULTI:
        return [entry]

    overflow_index = entry & ~DYLD_CHAINED_PTR_START_MULTI
    overflow_base = page_array + page_count * 2
    starts: list[int] = []
    while True:
        value = struct.unpack_from("<H", data, overflow_base + overflow_index * 2)[0]
        starts.append(value & ~DYLD_CHAINED_PTR_START_LAST)
        overflow_index += 1
        if value & DYLD_CHAINED_PTR_START_LAST:
            return starts


def walk_fixups(macho: MachO, base: int) -> list[dict[str, Any]]:
    data = macho.data
    payload = macho.fixups_offset
    _require_range(data, payload, 28, "chained-fixup header")
    (version, starts_offset, _imports_offset, _symbols_offset, _imports_count,
     _imports_format, _symbols_format) = struct.unpack_from("<7I", data, payload)
    if version != 0:
        raise CensusError(f"unsupported chained-fixup version {version}")
    starts = payload + starts_offset
    _require_range(data, starts, 4, "chained starts-in-image")
    segment_count = struct.unpack_from("<I", data, starts)[0]
    if segment_count != len(macho.segments):
        raise CensusError(
            f"fixup segment count {segment_count} != Mach-O segment count "
            f"{len(macho.segments)}"
        )
    _require_range(data, starts + 4, segment_count * 4, "segment info offsets")

    records: list[dict[str, Any]] = []
    for segment_index, segment in enumerate(macho.segments):
        relative = struct.unpack_from("<I", data, starts + 4 + segment_index * 4)[0]
        if relative == 0:
            continue
        info = starts + relative
        _require_range(data, info, 22, "starts-in-segment")
        size, page_size, pointer_format, segment_offset, _max_valid, page_count = (
            struct.unpack_from("<IHHQIH", data, info)
        )
        _require_range(data, info, size, "starts-in-segment body")
        if size < 22 + page_count * 2:
            raise CensusError("starts-in-segment page array exceeds its body")
        if pointer_format not in {
            DYLD_CHAINED_PTR_ARM64E_KERNEL,
            DYLD_CHAINED_PTR_64_KERNEL_CACHE,
        }:
            raise CensusError(
                f"unsupported chained pointer format {pointer_format} in "
                f"{segment.name}"
            )
        if segment_offset != segment.vmaddr - base:
            raise CensusError(
                f"segment offset mismatch for {segment.name}: "
                f"{segment_offset:#x} != {segment.vmaddr - base:#x}"
            )
        for page_index in range(page_count):
            for start in _page_starts(data, info, page_count, page_index):
                chain_offset = segment.fileoff + page_index * page_size + start
                visited: set[int] = set()
                while True:
                    if chain_offset in visited:
                        raise CensusError(f"fixup chain cycle at {chain_offset:#x}")
                    visited.add(chain_offset)
                    _require_range(data, chain_offset, 8, "chained pointer")
                    raw = struct.unpack_from("<Q", data, chain_offset)[0]
                    if pointer_format == DYLD_CHAINED_PTR_ARM64E_KERNEL:
                        decoded = decode_arm64e_auth_rebase(raw, base)
                        next_delta = (raw >> 51) & 0x7FF
                        pointer_format_name = "DYLD_CHAINED_PTR_ARM64E_KERNEL"
                    else:
                        decoded = decode_kernel_cache_auth_rebase(raw, base)
                        next_delta = (raw >> 51) & 0xFFF
                        pointer_format_name = "DYLD_CHAINED_PTR_64_KERNEL_CACHE"
                    if decoded is not None:
                        location = segment.vmaddr + (chain_offset - segment.fileoff)
                        records.append({
                            "location": _hex(location),
                            "fileOffset": _hex(chain_offset),
                            "segment": segment.name,
                            "pointerFormat": pointer_format_name,
                            "raw": _hex(raw),
                            **decoded,
                        })
                    if next_delta == 0:
                        break
                    chain_offset += next_delta * 4
                    page_file_end = segment.fileoff + (page_index + 1) * page_size
                    if chain_offset >= page_file_end:
                        raise CensusError("fixup chain escaped its page")
    return records


def _owner(segments: Sequence[Segment], address: int) -> str | None:
    owners = [segment.name for segment in segments
              if segment.vmaddr <= address < segment.vmaddr + segment.vmsize]
    return owners[0] if len(owners) == 1 else None


def build_evidence(
    macho: MachO,
    base: int,
    diversity: int,
    key: int,
    address_diversity: bool,
) -> dict[str, Any]:
    all_auth = walk_fixups(macho, base)
    matches = [record for record in all_auth if (
        int(record["diversity"], 16) == diversity
        and record["key"] == KEY_NAMES[key]
        and record["addressDiversity"] is address_diversity
    )]
    for record in matches:
        target = record["target"]
        record["targetSegment"] = (
            _owner(macho.segments, int(target, 16)) if target is not None else None
        )
    return {
        "schema": "cyanide.pac-fixup-census.v1",
        "target": {
            "path": str(macho.path),
            "sha256": _sha256(macho.data),
            "uuid": macho.uuid,
            "filetype": "MH_FILESET" if macho.filetype == MH_FILESET else macho.filetype,
            "base": _hex(base),
        },
        "query": {
            "pointerFormats": sorted({
                record["pointerFormat"] for record in all_auth
            }),
            "diversity": f"0x{diversity:04x}",
            "key": KEY_NAMES[key],
            "addressDiversity": address_diversity,
            "bind": False,
            "authenticated": True,
        },
        "matches": matches,
        "summary": {
            "authenticatedRebases": len(all_auth),
            "matches": len(matches),
            "usedKernelRead": False,
            "usedKernelWrite": False,
            "usedKernelCall": False,
            "interpretation": (
                "singleton-compatible-target" if len(matches) == 1
                else "multiple-or-no-compatible-targets"
            ),
        },
    }


def verify_expectations(document: dict[str, Any], args: argparse.Namespace) -> None:
    matches = document["matches"]
    if args.expect_count is not None and len(matches) != args.expect_count:
        raise CensusError(
            f"match count {len(matches)} != expected {args.expect_count}"
        )
    expectations = {
        "location": args.expect_location,
        "target": args.expect_target,
        "raw": args.expect_raw,
    }
    for field, expected in expectations.items():
        if expected is None:
            continue
        values = {int(record[field], 16) for record in matches}
        if values != {expected}:
            rendered = ", ".join(_hex(value) for value in sorted(values)) or "none"
            raise CensusError(
                f"{field} values ({rendered}) != expected {_hex(expected)}"
            )


def _integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel_collection", type=Path)
    parser.add_argument("--base", required=True, type=_integer,
                        help="unslid kernel-collection base address")
    parser.add_argument("--diversity", type=_integer, default=0xFACE)
    parser.add_argument("--key", choices=sorted(KEY_VALUES), default="ia")
    parser.add_argument("--no-address-diversity", action="store_true")
    parser.add_argument("--expect-count", type=int)
    parser.add_argument("--expect-location", type=_integer)
    parser.add_argument("--expect-target", type=_integer)
    parser.add_argument("--expect-raw", type=_integer)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not 0 <= args.diversity <= 0xFFFF:
        raise CensusError("--diversity must fit in 16 bits")
    if args.expect_count is not None and args.expect_count < 0:
        raise CensusError("--expect-count cannot be negative")
    macho = parse_macho(args.kernel_collection)
    document = build_evidence(
        macho=macho,
        base=args.base,
        diversity=args.diversity,
        key=KEY_VALUES[args.key],
        address_diversity=not args.no_address_diversity,
    )
    verify_expectations(document, args)
    rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(rendered)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CensusError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
