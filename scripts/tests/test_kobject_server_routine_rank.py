"""Offline tests for ipc_kobject_server routine ranking."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_kobject_server_routine_rank as ranker  # noqa: E402


class KobjectServerRoutineRankTests(unittest.TestCase):
    def test_rank_record_kind_cannot_be_overridden_by_source(self) -> None:
        source = {"kind": "offline-routine-entry", "messageID": 1}
        record = {**source, "kind": "routine-rank"}
        self.assertEqual(record["kind"], "routine-rank")

    def test_classifies_authenticated_call_and_pac_signers(self) -> None:
        start = 0xFFFFFE0007009000
        result = ranker.analyze_instructions(start, start + 0x20, [
            (start, "ldr", "x8, [x0]"),
            (start + 4, "pacia", "x9, x10"),
            (start + 8, "pacda", "x11, x12"),
            (start + 12, "blraa", "x8, x17"),
            (start + 16, "str", "x9, [x1]"),
            (start + 20, "ret", ""),
        ])
        self.assertEqual(len(result["authenticatedIndirectBranches"]), 1)
        self.assertEqual(len(result["codePACSigners"]), 1)
        self.assertEqual(len(result["dataPACSigners"]), 1)
        self.assertEqual(result["memoryWrites"], 1)

    def test_does_not_count_return_address_pac_as_code_oracle(self) -> None:
        start = 0xFFFFFE0007009000
        result = ranker.analyze_instructions(start, start + 0x10, [
            (start, "pacibsp", ""),
            (start + 4, "autibsp", ""),
            (start + 8, "ret", ""),
        ])
        self.assertEqual(result["codePACSigners"], [])
        self.assertEqual(result["dataPACSigners"], [])

    def test_raw_indirect_branch_is_visible(self) -> None:
        start = 0xFFFFFE0007009000
        result = ranker.analyze_instructions(start, start + 8, [
            (start, "br", "x8"),
            (start + 4, "ret", ""),
        ])
        self.assertEqual(len(result["rawIndirectBranches"]), 1)

    def test_tracks_direct_and_simple_aliased_writes_through_x3(self) -> None:
        start = 0xFFFFFE0007009000
        result = ranker.analyze_instructions(start, start + 0x14, [
            (start, "mov", "x19, x3"),
            (start + 4, "str", "w8, [x19, #0x28]"),
            (start + 8, "add", "x20, x3, #0x20"),
            (start + 12, "stp", "x8, x9, [x20]"),
            (start + 16, "ret", ""),
        ])
        self.assertEqual(len(result["writesThroughConstrainedX3"]), 2)
        self.assertFalse(result["constrainedX3SafeCandidate"])

    def test_x3_reassignment_does_not_hide_write_on_another_branch(self) -> None:
        start = 0xFFFFFE0007009000
        result = ranker.analyze_instructions(start, start + 0x10, [
            (start, "b.eq", f"{start + 8:#x}"),
            (start + 4, "mov", "x3, sp"),
            (start + 8, "str", "w8, [x3, #0x28]"),
            (start + 12, "ret", ""),
        ])
        self.assertFalse(result["constrainedX3SafeCandidate"])

    def test_routine_without_x3_use_is_safe_candidate_only(self) -> None:
        start = 0xFFFFFE0007009000
        result = ranker.analyze_instructions(start, start + 8, [
            (start, "mov", "x0, x1"),
            (start + 4, "ret", ""),
        ])
        self.assertTrue(result["constrainedX3SafeCandidate"])
        self.assertEqual(result["constrainedX3References"], [])


if __name__ == "__main__":
    unittest.main()
