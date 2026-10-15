"""Offline tests for the authenticated global Block census."""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_global_block_census as census  # noqa: E402
import cnd_pac_fixup_census as fixups  # noqa: E402


def record(location: int, target: int, key: str, diversity: int = 0,
           address_diversity: bool = True) -> dict[str, object]:
    return {
        "location": census._hex(location),
        "target": census._hex(target),
        "key": key,
        "diversity": f"0x{diversity:04x}",
        "addressDiversity": address_diversity,
    }


class GlobalBlockCensusTests(unittest.TestCase):
    def test_requires_three_fixups_and_exact_flags(self) -> None:
        base = 0xFFFFFE0007004000
        address = base + 0x100
        data = bytearray(0x400)
        data[0x108:0x110] = census.EXPECTED_FLAGS.to_bytes(8, "little")
        macho = fixups.MachO(
            path=Path("fixture"), data=bytes(data), filetype=fixups.MH_FILESET,
            uuid=None,
            segments=(fixups.Segment(0, "__DATA_CONST", base, 0x400, 0, 0x400),),
            fixups_offset=0, fixups_size=0,
        )
        records = [
            record(address, base + 0x300, "DA", 0x1234),
            record(address + 0x10, base + 0x200, "IA"),
            record(address + 0x18, base + 0x180, "DA", 0x5678),
        ]
        blocks = census.scan_global_blocks(macho, records)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["invoke"]["target"], census._hex(base + 0x200))
        self.assertFalse(blocks[0]["writable"])

        missing_descriptor = census.scan_global_blocks(macho, records[:-1])
        self.assertEqual(missing_descriptor, [])

    def test_wrong_invoke_contract_is_rejected(self) -> None:
        base = 0xFFFFFE0007004000
        data = bytearray(0x100)
        data[8:16] = census.EXPECTED_FLAGS.to_bytes(8, "little")
        macho = fixups.MachO(
            Path("fixture"), bytes(data), fixups.MH_FILESET, None,
            (fixups.Segment(0, "__DATA", base, 0x100, 0, 0x100),), 0, 0,
        )
        records = [
            record(base, base + 0x80, "DA"),
            record(base + 0x10, base + 0x90, "IB"),
            record(base + 0x18, base + 0xA0, "DA"),
        ]
        self.assertEqual(census.scan_global_blocks(macho, records), [])

    def test_expectations_fail_closed(self) -> None:
        document = {"blocks": [], "summary": {"writableBlocks": 0}}
        args = argparse.Namespace(
            expect_count=1, expect_writable=None,
            expect_block=None, expect_invoke=None,
        )
        with self.assertRaisesRegex(census.BlockCensusError, "Block count"):
            census.verify_expectations(document, args)


if __name__ == "__main__":
    unittest.main()
