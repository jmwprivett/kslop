"""Offline tests for the exact-kernel IA-zero target census."""

from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_ia_zero_target_census as census  # noqa: E402


def encode_adrp(register: int, pc: int, target: int) -> int:
    delta_pages = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    immediate = delta_pages & ((1 << 21) - 1)
    return (
        0x90000000
        | (immediate & 0x3) << 29
        | (immediate >> 2) << 5
        | register
    )


def encode_add(register: int, immediate: int) -> int:
    return 0x91000000 | immediate << 10 | register << 5 | register


class IAZeroTargetCensusTests(unittest.TestCase):
    def test_scan_partitions_fixed_and_translator_sites(self) -> None:
        base = census.TEXT_EXEC_VMADDR
        target = base + 0x1238
        fixed_words = [
            encode_adrp(16, base, target),
            encode_add(16, target & 0xFFF),
            census.PACIZA_VALUE | 16,
            0xF9000000 | (0x60 // 8) << 10 | 0 << 5 | 16,
        ]
        translator_words = [
            0xD2800000 | 0xE4FE << 5 | 17,
            census.AUTIA_X16_X17,
            0xAA1003F1,  # mov x17, x16
            0xDAC143F1,  # xpaci x17
            0xEB11021F,  # cmp x16, x17
            0x54000040,  # b.eq +8
            0xD4388E00,  # brk 0xc470
            census.PACIZA_VALUE | 16,
            0xF9000000 | (0x98 // 8) << 10 | 26 << 5 | 16,
        ]
        sites = census.scan_text_exec(struct.pack(
            f"<{len(fixed_words + translator_words)}I",
            *(fixed_words + translator_words),
        ))

        self.assertEqual(len(sites), 2)
        self.assertEqual(sites[0]["classification"], "fixed_target")
        self.assertEqual(sites[0]["target"], target)
        self.assertEqual(sites[0]["stores"][0]["slot_offset"], 0x60)
        self.assertEqual(sites[1]["classification"], "authenticate_then_resign")
        self.assertEqual(sites[1]["source_modifier"], "constant 0x000000000000e4fe")
        self.assertEqual(sites[1]["stores"][0]["base_register"], 26)

    def test_stp_second_register_uses_second_slot(self) -> None:
        word = (
            0xA9000000
            | 3 << 15
            | 16 << 10
            | 1 << 5
            | 20
        )
        self.assertEqual(
            census.decode_store(word, 16),
            ("stp_second", 1, 0x20),
        )

    def test_incomplete_partition_fails_closed(self) -> None:
        with self.assertRaisesRegex(census.CensusError, "partition drifted"):
            census.verify_profile([{
                "site": census.TEXT_EXEC_VMADDR,
                "classification": "unclassified",
                "stores": [],
            }])

    def test_rea_snapshot_contract_checks_semantics(self) -> None:
        profile = census.REA_PROFILES[2]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps({
                "target": {"sha256": census.KERNEL_SHA256},
                "evidence_bundle": {"records": [{
                    "operation": "analyze_function",
                    "parameters": {
                        "procedure": census._hex(profile["procedure"]),
                    },
                    "evidence_id": profile["evidence_id"],
                    "normalized_result": {
                        "assembly": list(profile["assembly"]),
                        "pseudocode": "\n".join(profile["pseudocode"]),
                        "callers": [
                            {"address": address}
                            for address in profile["callers"]
                        ],
                    },
                }]},
            }), encoding="utf-8")
            with mock.patch.object(census, "sha256", return_value=profile["sha256"]):
                result = census.verify_rea_snapshot(path, profile)
            self.assertTrue(result["reconciled"])

    def test_rea_snapshot_missing_witness_fails_closed(self) -> None:
        profile = dict(census.REA_PROFILES[0])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps({
                "target": {"sha256": census.KERNEL_SHA256},
                "evidence_bundle": {"records": [{
                    "operation": "analyze_function",
                    "parameters": {
                        "procedure": census._hex(profile["procedure"]),
                    },
                    "evidence_id": profile["evidence_id"],
                    "normalized_result": {
                        "assembly": [],
                        "pseudocode": "",
                    },
                }]},
            }), encoding="utf-8")
            with mock.patch.object(census, "sha256", return_value=profile["sha256"]):
                with self.assertRaisesRegex(census.CensusError, "assembly witness"):
                    census.verify_rea_snapshot(path, profile)

    def test_action_done_profile_pins_pm_busy_bit_clear(self) -> None:
        profile = census.REA_PROFILES[-1]
        self.assertEqual(
            profile["name"],
            "io_service_pm_action_driver_callout_done_81df254",
        )
        self.assertIn("0xfdff", profile["pseudocode"][0])
        self.assertEqual((~0xFDFF) & 0xFFFF, 0x0200)


if __name__ == "__main__":
    unittest.main()
