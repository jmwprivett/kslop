"""Offline tests for the exact-build IOKit notification action harvester."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_iokit_notification_action_harvest as harvest  # noqa: E402


def _signed(pointer: int, pac: int) -> int:
    return (pointer & 0x00007FFFFFFFFFFF) | (pac << 48)


class Memory:
    def __init__(self) -> None:
        self.ranges: list[tuple[int, bytes]] = []

    def add(self, address: int, data: bytes | bytearray) -> None:
        self.ranges.append((address, bytes(data)))

    def read(self, address: int, length: int) -> bytes:
        for start, data in self.ranges:
            offset = address - start
            if offset >= 0 and offset + length <= len(data):
                return data[offset:offset + length]
        raise AssertionError(f"unexpected read {address:#x}+{length:#x}")


class IOKitNotificationActionHarvestTests(unittest.TestCase):
    def fixture(self, *, callback_matches: bool = True) -> tuple[Memory, int]:
        live_text = harvest.STATIC_TEXT
        dictionary = 0xFFFFFE1111110000
        entries = 0xFFFFFE1111120000
        publish_symbol = 0xFFFFFE1111130000
        publish_table = 0xFFFFFE1111138000
        collection = 0xFFFFFE1111140000
        array = 0xFFFFFE1111150000
        decoy = 0xFFFFFE1111160000
        donor = 0xFFFFFE1111170000
        matching = 0xFFFFFE1111180000

        memory = Memory()
        memory.add(
            harvest.STATIC_NOTIFICATION_DICTIONARY_GLOBAL,
            struct.pack("<Q", _signed(dictionary, 0x1234)),
        )
        memory.add(
            harvest.STATIC_PUBLISH_SYMBOL_TABLE_POINTER,
            struct.pack("<Q", _signed(publish_table, 0x4321)),
        )
        memory.add(publish_table, struct.pack("<Q", publish_symbol))
        dictionary_body = bytearray(0x28)
        struct.pack_into("<I", dictionary_body, harvest.DICTIONARY_COUNT_OFFSET, 2)
        struct.pack_into(
            "<Q", dictionary_body, harvest.DICTIONARY_ENTRIES_OFFSET,
            _signed(entries, 0x1111),
        )
        memory.add(dictionary, dictionary_body)
        memory.add(entries, struct.pack(
            "<QQQQ",
            0xFFFFFE1111190000, 0xFFFFFE11111A0000,
            publish_symbol, _signed(collection, 0x2222),
        ))
        collection_body = bytearray(0x40)
        struct.pack_into(
            "<Q", collection_body, harvest.ORDERED_SET_ARRAY_OFFSET,
            _signed(array, 0x3333),
        )
        struct.pack_into(
            "<I", collection_body, harvest.ORDERED_SET_COUNT_OFFSET, 2,
        )
        memory.add(collection, collection_body)
        memory.add(array, struct.pack("<QQ", decoy, donor))
        memory.add(decoy, bytes(harvest.NOTIFIER_SIZE))

        donor_body = bytearray(harvest.NOTIFIER_SIZE)
        struct.pack_into(
            "<Q", donor_body, harvest.NOTIFIER_COLLECTION_OFFSET,
            _signed(collection, 0x4444),
        )
        struct.pack_into(
            "<Q", donor_body, harvest.NOTIFIER_MATCHING_OFFSET, matching,
        )
        struct.pack_into(
            "<Q", donor_body, harvest.NOTIFIER_TYPE_OFFSET, publish_symbol,
        )
        struct.pack_into(
            "<Q", donor_body, harvest.NOTIFIER_ACTION_OFFSET,
            _signed(harvest.STATIC_SANDBOX_BRIDGE, 0x0AD3),
        )
        callback = harvest.STATIC_SANDBOX_PUBLISH_CALLBACK if callback_matches \
            else harvest.STATIC_SANDBOX_PUBLISH_CALLBACK + 4
        struct.pack_into(
            "<Q", donor_body, harvest.NOTIFIER_CALLBACK_OFFSET,
            _signed(callback, 0x0DD0),
        )
        struct.pack_into("<Q", donor_body, harvest.NOTIFIER_REFCON_OFFSET, 0)
        struct.pack_into("<I", donor_body, harvest.NOTIFIER_ENABLED_OFFSET, 1)
        memory.add(donor, donor_body)
        return memory, live_text

    def test_harvests_unique_exact_rea_bound_donor(self) -> None:
        memory, live_text = self.fixture()
        result = harvest.harvest(memory.read, live_text, harvest.KERNEL_UUID)
        self.assertEqual(result["donor"]["index"], 1)
        self.assertEqual(
            result["donor"]["action_stripped"],
            f"0x{harvest.STATIC_SANDBOX_BRIDGE:016x}",
        )
        self.assertTrue(result["evidence"]["readOnly"])
        self.assertFalse(result["evidence"]["heapScanUsed"])
        self.assertFalse(result["evidence"]["usedKernelWrite"])
        self.assertFalse(result["evidence"]["usedKernelCall"])

    def test_rejects_wrong_uuid(self) -> None:
        memory, live_text = self.fixture()
        with self.assertRaisesRegex(harvest.HarvestError, "UUID"):
            harvest.harvest(
                memory.read, live_text,
                "00000000-0000-0000-0000-000000000000",
            )

    def test_rejects_callback_identity_drift(self) -> None:
        memory, live_text = self.fixture(callback_matches=False)
        with self.assertRaisesRegex(harvest.HarvestError, "callback"):
            harvest.harvest(memory.read, live_text, harvest.KERNEL_UUID)


if __name__ == "__main__":
    unittest.main()
