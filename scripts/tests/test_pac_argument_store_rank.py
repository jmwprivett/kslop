import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "scripts/lab"
sys.path.insert(0, str(LAB))
MODULE_PATH = LAB / "cnd_pac_argument_store_rank.py"
SPEC = importlib.util.spec_from_file_location(
    "cnd_pac_argument_store_rank", MODULE_PATH,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
GRAPH = MODULE.graph


def ins(address, mnemonic, operands=""):
    return GRAPH.Instruction(address, mnemonic, operands)


def record():
    return {
        "target": "0x0000000000001000",
        "image": "com.apple.kernel",
        "entryDomains": ["0x00000000000073d8"],
        "fixupsByDomain": {},
        "functionStart": "0x0000000000001000",
        "functionEnd": "0x0000000000001020",
        "instructions": 8,
    }


class PACArgumentStoreRankTests(unittest.TestCase):
    def test_ranks_precall_store_through_incoming_x1(self):
        instructions = [
            ins(0x1000, "mov", "x8, #0x0"),
            ins(0x1004, "str", "x8, [x1, #0x10]"),
            ins(0x1008, "ret"),
        ]
        values = MODULE.scan_body(record(), instructions)
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]["destinationArgument"], "x1")
        self.assertEqual(values[0]["offset"], 0x10)
        self.assertEqual(values[0]["width"], 8)
        self.assertEqual(values[0]["callsBefore"], 0)
        self.assertEqual(values[0]["valueOrigin"]["kind"], "constant")
        self.assertEqual(values[0]["valueOrigin"]["value"], "0x0000000000000000")

    def test_penalizes_store_after_call(self):
        before = MODULE.scan_body(record(), [
            ins(0x1000, "str", "x2, [x1, #0x18]"),
        ])[0]
        after = MODULE.scan_body(record(), [
            ins(0x1000, "bl", "0x2000"),
            ins(0x1004, "str", "x2, [x1, #0x18]"),
        ])[0]
        self.assertGreater(before["score"], after["score"])
        self.assertEqual(after["callsBefore"], 1)

    def test_ignores_stack_and_non_argument_destinations(self):
        values = MODULE.scan_body(record(), [
            ins(0x1000, "str", "x0, [sp, #0x8]"),
            ins(0x1004, "adrp", "x8, 0x4000"),
            ins(0x1008, "str", "x0, [x8]"),
        ])
        self.assertEqual(values, [])

    def test_splits_pair_store_offsets(self):
        values = MODULE.scan_body(record(), [
            ins(0x1000, "stp", "x2, x3, [x1, #0x8]"),
        ])
        self.assertEqual([item["offset"] for item in values], [8, 16])

    def test_records_vector_pair_stores(self):
        values = MODULE.scan_body(record(), [
            ins(0x1000, "stp", "q0, q1, [x0, #0x20]"),
        ])
        self.assertEqual([item["offset"] for item in values], [0x20, 0x30])
        self.assertEqual([item["width"] for item in values], [16, 16])
        self.assertEqual(values[0]["valueOrigin"]["kind"], "vector-untracked")

    def test_ranks_small_return_that_changes_x1(self):
        values = MODULE.scan_returns(record(), [
            ins(0x1000, "adrp", "x1, 0x4000"),
            ins(0x1004, "ret"),
        ])
        self.assertEqual(len(values), 1)
        self.assertTrue(values[0]["changesX1"])
        self.assertEqual(
            values[0]["registerOrigins"]["x1"]["kind"], "static-page",
        )
        self.assertGreater(values[0]["score"], 0)

    def test_marks_preserved_x1_at_return(self):
        values = MODULE.scan_returns(record(), [ins(0x1000, "ret")])
        self.assertFalse(values[0]["changesX1"])

    def test_reports_bounded_direct_tail_copy_shape(self):
        values = MODULE.scan_direct_tail_calls(record(), [
            ins(0x1000, "mov", "x2, #0x40"),
            ins(0x1004, "b", "0x2000"),
        ])
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]["destination"], "0x0000000000002000")
        self.assertTrue(values[0]["externalToFunction"])
        self.assertEqual(values[0]["preservedArguments"], ["x0", "x1"])
        self.assertEqual(
            values[0]["registerOrigins"]["x2"]["value"],
            "0x0000000000000040",
        )

    def test_marks_internal_unconditional_branch_as_control_flow(self):
        values = MODULE.scan_direct_tail_calls(record(), [
            ins(0x1000, "b", "0x1010"),
        ])
        self.assertEqual(len(values), 1)
        self.assertFalse(values[0]["externalToFunction"])
        self.assertIn("internal-control-flow:-100", values[0]["scoreReasons"])

    def test_rejects_invalid_function_bounds(self):
        invalid = record()
        invalid["functionEnd"] = "not-an-address"
        with self.assertRaises(MODULE.StoreRankError):
            MODULE.scan_direct_tail_calls(invalid, [ins(0x1000, "b", "0x2000")])


if __name__ == "__main__":
    unittest.main()
