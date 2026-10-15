#!/usr/bin/env python3
"""Enumerate exact kernel global Block literals from chained fixups.

The Block ABI fields at offsets 0, 0x10, and 0x18 are authenticated chained
rebases in the 23A341 kernel collections.  Requiring those real fixup records,
the canonical global/signature flags word, and the invoke field's IA/address
contract avoids the packed-data false positives produced by byte-only scans.

This is an offline, read-only inventory.  Invoke bodies still require Ghidra
review before any block is considered a dispatch primitive.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import Any, Sequence

import cnd_pac_fixup_census as fixups


BLOCK_IS_GLOBAL = 1 << 28
BLOCK_HAS_SIGNATURE = 1 << 30
EXPECTED_FLAGS = BLOCK_IS_GLOBAL | BLOCK_HAS_SIGNATURE


class BlockCensusError(RuntimeError):
    """The Block layout or requested exact-build expectation failed."""


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _file_offset(macho: fixups.MachO, address: int) -> tuple[fixups.Segment, int]:
    owners = [segment for segment in macho.segments if (
        segment.vmaddr <= address < segment.vmaddr + segment.filesize
    )]
    if len(owners) != 1:
        raise BlockCensusError(
            f"address {_hex(address)} has {len(owners)} file-backed segment owners"
        )
    segment = owners[0]
    return segment, segment.fileoff + address - segment.vmaddr


def scan_global_blocks(
    macho: fixups.MachO,
    authenticated_rebases: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_location = {
        int(record["location"], 16): record for record in authenticated_rebases
    }
    candidates: list[dict[str, Any]] = []
    for address in sorted(by_location):
        isa = by_location[address]
        invoke = by_location.get(address + 0x10)
        descriptor = by_location.get(address + 0x18)
        if invoke is None or descriptor is None:
            continue
        segment, file_offset = _file_offset(macho, address)
        if file_offset + 0x20 > len(macho.data):
            raise BlockCensusError(f"truncated Block candidate at {_hex(address)}")
        flags_word = struct.unpack_from("<Q", macho.data, file_offset + 8)[0]
        if flags_word != EXPECTED_FLAGS:
            continue
        if not (
            invoke["key"] == "IA"
            and invoke["addressDiversity"] is True
            and invoke["diversity"] == "0x0000"
            and invoke["target"] is not None
        ):
            continue
        candidates.append({
            "address": _hex(address),
            "fileOffset": _hex(file_offset),
            "segment": segment.name,
            "writable": segment.name in {"__DATA", "__AUTH"},
            "flags": f"0x{EXPECTED_FLAGS:08x}",
            "isa": isa,
            "invoke": invoke,
            "descriptor": descriptor,
        })
    return candidates


def build_evidence(macho: fixups.MachO, base: int) -> dict[str, Any]:
    authenticated = fixups.walk_fixups(macho, base)
    candidates = scan_global_blocks(macho, authenticated)
    return {
        "schema": "cyanide.kernel-global-block-census.v1",
        "target": {
            "path": str(macho.path),
            "sha256": fixups._sha256(macho.data),
            "uuid": macho.uuid,
            "base": _hex(base),
        },
        "abiContract": {
            "flags": f"0x{EXPECTED_FLAGS:08x}",
            "invokeOffset": "0x10",
            "invokeKey": "IA",
            "invokeAddressDiversity": True,
            "invokeDiversity": "0x0000",
        },
        "blocks": candidates,
        "summary": {
            "authenticatedRebases": len(authenticated),
            "blocks": len(candidates),
            "uniqueInvokes": len({
                candidate["invoke"]["target"] for candidate in candidates
            }),
            "writableBlocks": sum(
                bool(candidate["writable"]) for candidate in candidates
            ),
            "usedKernelRead": False,
            "usedKernelWrite": False,
            "usedKernelCall": False,
        },
    }


def verify_expectations(document: dict[str, Any], args: argparse.Namespace) -> None:
    blocks = document["blocks"]
    if args.expect_count is not None and len(blocks) != args.expect_count:
        raise BlockCensusError(
            f"Block count {len(blocks)} != expected {args.expect_count}"
        )
    if args.expect_writable is not None:
        actual = document["summary"]["writableBlocks"]
        if actual != args.expect_writable:
            raise BlockCensusError(
                f"writable Block count {actual} != expected {args.expect_writable}"
            )
    if args.expect_block is not None:
        matches = [block for block in blocks
                   if int(block["address"], 16) == args.expect_block]
        if len(matches) != 1:
            raise BlockCensusError(
                f"expected Block {_hex(args.expect_block)} was not unique"
            )
        if (args.expect_invoke is not None
                and int(matches[0]["invoke"]["target"], 16) != args.expect_invoke):
            raise BlockCensusError(
                f"Block {_hex(args.expect_block)} invoke did not match "
                f"{_hex(args.expect_invoke)}"
            )
    elif args.expect_invoke is not None:
        raise BlockCensusError("--expect-invoke requires --expect-block")


def _integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel_collection", type=Path)
    parser.add_argument("--base", required=True, type=_integer)
    parser.add_argument("--expect-count", type=int)
    parser.add_argument("--expect-writable", type=int)
    parser.add_argument("--expect-block", type=_integer)
    parser.add_argument("--expect-invoke", type=_integer)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    macho = fixups.parse_macho(args.kernel_collection)
    document = build_evidence(macho, args.base)
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
    except (BlockCensusError, fixups.CensusError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
