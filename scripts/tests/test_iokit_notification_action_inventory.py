"""Offline tests for IOKit notification action inventory graph binding."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_iokit_notification_action_inventory as inventory  # noqa: E402


class IOKitNotificationActionInventoryTests(unittest.TestCase):
    def test_load_graph_binds_complete_61de_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "graph.jsonl"
            path.write_text("\n".join((
                json.dumps({
                    "kind": "dispatch-target",
                    "target": "0xfffffe0008000000",
                    "image": "com.apple.kernel",
                    "signers": ["0xfffffe0008000100"],
                    "indirectBranches": [],
                }),
                json.dumps({
                    "kind": "summary",
                    "kernelUUID": inventory.KERNEL_UUID,
                    "domains": ["0x00000000000061de"],
                    "failures": [],
                }),
            )) + "\n", encoding="utf-8")
            graph = inventory.load_graph(path)
        self.assertEqual(list(graph), [0xFFFFFE0008000000])

    def test_load_graph_rejects_wrong_domain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "graph.jsonl"
            path.write_text("\n".join((
                json.dumps({
                    "kind": "dispatch-target",
                    "target": "0xfffffe0008000000",
                }),
                json.dumps({
                    "kind": "summary",
                    "kernelUUID": inventory.KERNEL_UUID,
                    "domains": ["0x0000000000000000"],
                    "failures": [],
                }),
            )) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(inventory.InventoryError, "identity"):
                inventory.load_graph(path)


if __name__ == "__main__":
    unittest.main()
