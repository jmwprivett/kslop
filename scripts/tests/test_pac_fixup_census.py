"""Offline tests for authenticated kernel chained-fixup census."""

from __future__ import annotations

import argparse
import struct
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_pac_fixup_census as census  # noqa: E402


def auth_rebase(target: int, diversity: int, address_diversity: bool,
                key: int, next_delta: int) -> int:
    return (
        target
        | diversity << 32
        | int(address_diversity) << 48
        | key << 49
        | next_delta << 51
        | 1 << 63
    )


def fixture(path: Path) -> tuple[int, int, int]:
    base = 0xFFFFFE0007004000
    segment_vmaddr = base + 0x4000
    target_offset = 0x01248DFC
    raw = auth_rebase(target_offset, 0xFACE, True, 0, 0)

    data = bytearray(0x5000)
    # mach_header_64, then __TEXT and __DATA_CONST, UUID, chained fixups.
    commands = bytearray()
    for name, vmaddr, fileoff, filesize, protection in (
        (b"__TEXT", base, 0, 0x1000, 1),
        (b"__DATA_CONST", segment_vmaddr, 0x4000, 0x1000, 1),
    ):
        commands.extend(struct.pack(
            "<II16sQQQQiiII", census.LC_SEGMENT_64, 72,
            name.ljust(16, b"\0"), vmaddr, filesize, fileoff, filesize,
            protection, protection, 0, 0,
        ))
    commands.extend(struct.pack(
        "<II16s", census.LC_UUID, 24, bytes.fromhex(
            "03A9337364983F25897504DED251AF1F"
        )
    ))
    fixups_offset = 0x3000
    commands.extend(struct.pack(
        "<IIII", census.LC_DYLD_CHAINED_FIXUPS, 16, fixups_offset, 0x80
    ))
    struct.pack_into(
        "<IiiIIIII", data, 0, census.MH_MAGIC_64, 0x100000C, 2,
        census.MH_FILESET, 4, len(commands), 0, 0,
    )
    data[32:32 + len(commands)] = commands

    # fixups header; starts-in-image at +0x20 with two segment entries; only
    # __DATA_CONST has starts-in-segment, one page, one chain at page offset 0.
    struct.pack_into("<7I", data, fixups_offset, 0, 0x20, 0, 0, 0, 0, 0)
    starts = fixups_offset + 0x20
    struct.pack_into("<III", data, starts, 2, 0, 12)
    info = starts + 12
    struct.pack_into(
        "<IHHQIHH", data, info, 24, 0x1000,
        census.DYLD_CHAINED_PTR_ARM64E_KERNEL, 0x4000, 0, 1, 0,
    )
    struct.pack_into("<Q", data, 0x4000, raw)
    path.write_bytes(data)
    return base, segment_vmaddr, raw


class PACFixupCensusTests(unittest.TestCase):
    def test_walks_real_chain_metadata_and_matches_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kernelcache"
            base, location, raw = fixture(path)
            macho = census.parse_macho(path)
            document = census.build_evidence(macho, base, 0xFACE, 0, True)

        self.assertEqual(document["summary"]["authenticatedRebases"], 1)
        self.assertEqual(document["summary"]["matches"], 1)
        match = document["matches"][0]
        self.assertEqual(int(match["location"], 16), location)
        self.assertEqual(int(match["raw"], 16), raw)
        self.assertEqual(match["target"], "0xfffffe000824cdfc")
        self.assertEqual(match["targetSegment"], None)
        self.assertEqual(document["summary"]["interpretation"],
                         "singleton-compatible-target")

    def test_decode_rejects_bind_and_unauthenticated_words(self) -> None:
        base = 0xFFFFFE0007004000
        unauthenticated = 0x1234
        authenticated_bind = (1 << 63) | (1 << 62) | 0x1234
        self.assertIsNone(census.decode_arm64e_auth_rebase(unauthenticated, base))
        self.assertIsNone(census.decode_arm64e_auth_rebase(authenticated_bind, base))

    def test_kernel_cache_format_decodes_primary_cache_target(self) -> None:
        base = 0xFFFFFE0007004000
        raw = auth_rebase(0x01248DFC, 0xFACE, True, 0, 8)
        decoded = census.decode_kernel_cache_auth_rebase(raw, base)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["target"], "0xfffffe000824cdfc")
        self.assertEqual(decoded["cacheLevel"], 0)
        self.assertEqual(decoded["next"], 8)

    def test_expectations_fail_closed(self) -> None:
        document = {"matches": [{
            "location": "0x0000000000001000",
            "target": "0x0000000000002000",
            "raw": "0x0000000000003000",
        }]}
        args = argparse.Namespace(
            expect_count=2,
            expect_location=None,
            expect_target=None,
            expect_raw=None,
        )
        with self.assertRaisesRegex(census.CensusError, "match count"):
            census.verify_expectations(document, args)

    def test_parser_rejects_non_macho(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad"
            path.write_bytes(b"not a Mach-O")
            with self.assertRaises(census.CensusError):
                census.parse_macho(path)


if __name__ == "__main__":
    unittest.main()
