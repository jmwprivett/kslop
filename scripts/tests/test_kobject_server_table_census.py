"""Offline tests for the exact-build ipc_kobject_server table census."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_kobject_server_table_census as census  # noqa: E402


def _signed(pointer: int, pac: int) -> int:
    return (pointer & 0x00007FFFFFFFFFFF) | (pac << 48)


class KobjectServerTableCensusTests(unittest.TestCase):
    def fixture(self, slide: int = 0x2100000) -> bytearray:
        data = bytearray(census.TABLE_SIZE)
        first = census.STATIC_TEXT + slide + 0x1200
        second = census.STATIC_TEXT + slide + 0x3400
        struct.pack_into(
            "<IIQII", data, 3 * census.ENTRY_SIZE,
            0x1234, 0, _signed(first, 0xA123), 0x40, 0x60,
        )
        struct.pack_into(
            "<IIQII", data, 19 * census.ENTRY_SIZE,
            0x5678, 0, _signed(second, 0xB456), 0x80, 0xA0,
        )
        return data

    def test_recovers_static_identities_from_signed_runtime_entries(self) -> None:
        slide = 0x2100000
        records, counts = census.parse_table(self.fixture(slide), slide)
        entries = [record for record in records if record["kind"] == "routine-entry"]

        self.assertEqual(counts["occupied"], 2)
        self.assertEqual(counts["validEntries"], 2)
        self.assertEqual(counts["malformedEntries"], 0)
        self.assertEqual(entries[0]["slot"], 3)
        self.assertEqual(entries[0]["messageID"], 0x1234)
        self.assertEqual(
            entries[0]["staticTarget"],
            f"0x{census.STATIC_TEXT + 0x1200:016x}",
        )
        self.assertEqual(entries[0]["pointerDiscriminator"], "0x3a83")

    def test_reports_malformed_and_duplicate_slots(self) -> None:
        slide = 0x2100000
        data = self.fixture(slide)
        target = census.STATIC_TEXT + slide + 0x5600
        struct.pack_into(
            "<IIQII", data, 20 * census.ENTRY_SIZE,
            0x1234, 1, _signed(target, 0xCAFE), 0x40, 0x60,
        )
        records, counts = census.parse_table(data, slide)
        anomalies = [record for record in records if record["kind"] == "slot-anomaly"]

        self.assertEqual(counts["occupied"], 3)
        self.assertEqual(counts["validEntries"], 2)
        self.assertEqual(counts["malformedEntries"], 1)
        self.assertEqual(counts["duplicateMessageIDs"], 1)
        self.assertIn("nonzero alignment word", anomalies[0]["reason"])
        self.assertIn("duplicate message ID", anomalies[0]["reason"])

    def test_rejects_partial_dump(self) -> None:
        with self.assertRaisesRegex(census.CensusError, "expected exactly"):
            census.parse_table(bytes(census.TABLE_SIZE - 1), 0)

    def test_rejects_unaligned_slide(self) -> None:
        with self.assertRaisesRegex(census.CensusError, "slide"):
            census.parse_table(bytes(census.TABLE_SIZE), 1)

    def test_exact_build_constants_match_dispatch_evidence(self) -> None:
        self.assertEqual(census.TABLE_SLOTS, 0x407)
        self.assertEqual(census.ENTRY_SIZE, 0x18)
        self.assertEqual(census.STATIC_TABLE, 0xFFFFFE000767C340)
        self.assertEqual(census.STATIC_DISPATCH_CALLSITE, 0xFFFFFE0007B0007C)
        self.assertEqual(census.POINTER_DISCRIMINATOR, 0x3A83)

    def test_reconstructs_boot_table_from_mig_descriptor(self) -> None:
        descriptor = census.STATIC_BASE + 0x680000
        target = census.STATIC_TEXT + 0x1234
        array = struct.pack("<Q", (1 << 52) | (descriptor - census.STATIC_BASE))
        body = bytearray(0x40)
        struct.pack_into("<III", body, 8, 0x1234, 0x1235, 0x400)
        chained_target = (
            (1 << 63)
            | census.POINTER_DISCRIMINATOR << 32
            | (target - census.STATIC_BASE)
        )
        struct.pack_into("<Q", body, 0x28, chained_target)
        struct.pack_into("<II", body, 0x38, 7, 0x80)

        def read_vm(address: int, size: int) -> bytes:
            if address == census.STATIC_SUBSYSTEM_ARRAY:
                return array[:size]
            if descriptor <= address and address + size <= descriptor + len(body):
                offset = address - descriptor
                return bytes(body[offset:offset + size])
            raise AssertionError(f"unexpected read {address:#x}+{size:#x}")

        records, counts = census.reconstruct_offline(read_vm, subsystem_count=1)
        self.assertEqual(counts["routines"], 1)
        self.assertEqual(counts["maxProbeCount"], 1)
        self.assertEqual(records[0]["messageID"], 0x1234)
        self.assertEqual(records[0]["staticTarget"], f"0x{target:016x}")
        self.assertEqual(records[0]["metadataWord10"], 0x80)
        self.assertEqual(records[0]["metadataWord14"], 7)

    def test_offline_reconstruction_rejects_wrong_discriminator(self) -> None:
        descriptor = census.STATIC_BASE + 0x680000
        array = struct.pack("<Q", descriptor - census.STATIC_BASE)
        body = bytearray(0x40)
        struct.pack_into("<III", body, 8, 1, 2, 0x100)
        bad_target = (1 << 63) | 0x1111 << 32 | 0x1000
        struct.pack_into("<Q", body, 0x28, bad_target)

        def read_vm(address: int, size: int) -> bytes:
            if address == census.STATIC_SUBSYSTEM_ARRAY:
                return array[:size]
            offset = address - descriptor
            return bytes(body[offset:offset + size])

        with self.assertRaisesRegex(census.CensusError, "0x3a83"):
            census.reconstruct_offline(read_vm, subsystem_count=1)


if __name__ == "__main__":
    unittest.main()
