import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/lab/cnd_2abe_registry_census.py"
SPEC = importlib.util.spec_from_file_location("cnd_2abe_registry_census", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class RegistryCensusTests(unittest.TestCase):
    def test_graph_contract_and_target_map(self):
        records = [
            {
                "kind": "dispatch-target",
                "image": "com.apple.kernel",
                "target": "0xfffffe0008123450",
                "domains": ["0x0000000000002abe"],
                "instructions": 3,
            },
            {
                "kind": "summary",
                "schema": "cyanide.pac-dispatch-graph.v1",
                "build": MODULE.BUILD,
                "product": MODULE.PRODUCT,
                "kernelUUID": MODULE.KERNEL_UUID,
                "domains": ["0x0000000000002abe"],
                "signedTargets": 1,
                "failures": [],
                "usedKernelWrite": False,
                "usedKernelCall": False,
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "graph.jsonl"
            path.write_text(
                "\n".join(json.dumps(record) for record in records) + "\n",
                encoding="utf-8",
            )
            graph = MODULE._load_graph(path)
        self.assertEqual(list(graph), [0xFFFFFE0008123450])
        self.assertEqual(graph[0xFFFFFE0008123450]["instructions"], 3)

    def test_header_is_bounded_and_decoded(self):
        packed = (7 << 32) | 5
        array = 0xFFFFFE2FA0001000
        self.assertEqual(MODULE._decode_header(packed, array), (5, 7, array))
        with self.assertRaises(MODULE.CensusError):
            MODULE._decode_header((257 << 32), array)
        with self.assertRaises(MODULE.CensusError):
            MODULE._decode_header((1 << 32), 0x1234)

    def test_records_correlate_signed_target(self):
        slide = 0x40000000
        owner = 0xFFFFFE2FA0002000
        slot = MODULE.CALLBACK_SLOTS[0]
        static_target = 0xFFFFFE0008123450
        live_target = static_target + slide
        raw_target = 0xABCD000000000000 | (live_target & 0x00007FFFFFFFFFFF)
        callback_values = {
            owner + item.offset: 0 for item in MODULE.CALLBACK_SLOTS
        }
        callback_values[owner + slot.offset] = raw_target
        graph = {
            static_target: {
                "image": "com.apple.kernel",
                "instructions": 3,
            }
        }
        records = MODULE._records(
            slide,
            [(2, 0xFFFFFE2FA0001800, owner)],
            callback_values,
            graph,
        )
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertTrue(record["signed"])
        self.assertTrue(record["graphKnown"])
        self.assertEqual(record["staticTarget"], MODULE._hex(static_target))
        self.assertEqual(record["fieldOffset"], MODULE._hex(slot.offset))
        self.assertEqual(record["domain"], "IA/0x2abe")

    def test_identity_requires_exact_uuid_and_slide(self):
        report = (
            f"Load Address: {MODULE.STATIC_TEXT + 0x40000000:#018x}\n"
            f"Kernel UUID: {MODULE.KERNEL_UUID}\n"
            "Process 1 detached\n"
        )
        self.assertEqual(
            MODULE._parse_identity(0, report),
            (0x40000000, MODULE.KERNEL_UUID),
        )
        with self.assertRaises(MODULE.CensusError):
            MODULE._parse_identity(1, report)


if __name__ == "__main__":
    unittest.main()
