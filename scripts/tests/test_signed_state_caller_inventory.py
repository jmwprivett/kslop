"""Offline tests for the exact signed-state caller inventory."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_signed_state_caller_inventory as inventory  # noqa: E402


class SignedStateCallerInventoryTests(unittest.TestCase):
    def fixture(self, directory: str) -> tuple[Path, Path, Path, str]:
        root = Path(directory)
        kernel = root / "com.apple.kernel"
        signer = root / "signer.json"
        copyio = root / "copyio.json"
        kernel.write_bytes(b"exact-kernel-fixture")

        callers = []
        references = []
        disassembly_lines = []
        for caller in inventory.CALLERS:
            callers.append({
                "address": caller["address"],
                "body": {"ranges": [{"end": caller["end"]}]},
            })
            for call in caller["calls"]:
                references.append({
                    "source_address": call,
                    "source_procedure": {"address": caller["address"]},
                    "target_address": inventory.SIGNER_ADDRESS,
                    "kind": {"call": True},
                })
                disassembly_lines.append(
                    f"com.apple.kernel[{call}] <+0>: bl {inventory.SIGNER_ADDRESS}"
                )
            disassembly_lines.extend(caller["witnesses"])

        signer.write_text(json.dumps({
            "target": {"sha256": inventory.KERNEL_SHA256},
            "evidence_bundle": {"records": [{
                "operation": "analyze_function",
                "parameters": {"procedure": inventory.SIGNER_ADDRESS},
                "evidence_id": inventory.SIGNER_EVIDENCE_ID,
                "normalized_result": {
                    "callers": callers,
                    "incoming_references": references,
                },
            }]},
        }), encoding="utf-8")
        copyio.write_text(json.dumps({
            "evidence_bundle": {"records": [{
                "operation": "analyze_function",
                "parameters": {"procedure": "0xfffffe0007c53bc0"},
                "evidence_id": inventory.COPYIO_EVIDENCE_ID,
            }]},
        }), encoding="utf-8")
        return kernel, signer, copyio, "\n".join(disassembly_lines)

    @staticmethod
    def exact_hash(path: Path) -> str:
        if path.name == "com.apple.kernel":
            return inventory.KERNEL_SHA256
        if path.name == "signer.json":
            return inventory.SIGNER_SNAPSHOT_SHA256
        if path.name == "copyio.json":
            return inventory.COPYIO_SNAPSHOT_SHA256
        raise AssertionError(path)

    def test_complete_fixture_classifies_every_direct_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kernel, signer, copyio, disassembly = self.fixture(directory)
            with mock.patch.object(inventory, "sha256", side_effect=self.exact_hash):
                result = inventory.build_inventory(
                    kernel, signer, copyio, disassembly_text=disassembly,
                )
        self.assertEqual(result["coverage"]["direct_call_count"], 21)
        self.assertEqual(result["coverage"]["caller_count"], 14)
        self.assertTrue(result["coverage"]["all_direct_calls_classified"])
        self.assertFalse(result["kdp_register_import"]["compiled_route_observed"])
        self.assertEqual(
            result["conclusion"]["attacker_controlled_el1_pc_signer_callers"],
            [],
        )

    def test_unexpected_direct_call_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kernel, signer, copyio, disassembly = self.fixture(directory)
            payload = json.loads(signer.read_text(encoding="utf-8"))
            payload["evidence_bundle"]["records"][0]["normalized_result"][
                "incoming_references"
            ].append({
                "source_address": "0xfffffe0000000004",
                "source_procedure": {"address": "0xfffffe0000000000"},
                "target_address": inventory.SIGNER_ADDRESS,
                "kind": {"call": True},
            })
            signer.write_text(json.dumps(payload), encoding="utf-8")
            with mock.patch.object(inventory, "sha256", side_effect=self.exact_hash):
                with self.assertRaisesRegex(inventory.InventoryError, "coverage drifted"):
                    inventory.build_inventory(
                        kernel, signer, copyio, disassembly_text=disassembly,
                    )

    def test_missing_instruction_witness_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kernel, signer, copyio, disassembly = self.fixture(directory)
            disassembly = disassembly.replace("mrs x22, ELR_EL1", "mrs x22, ELR_EL2")
            with mock.patch.object(inventory, "sha256", side_effect=self.exact_hash):
                with self.assertRaisesRegex(inventory.InventoryError, "witness drifted"):
                    inventory.build_inventory(
                        kernel, signer, copyio, disassembly_text=disassembly,
                    )

    def test_artifact_drift_fails_before_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kernel, signer, copyio, disassembly = self.fixture(directory)
            with mock.patch.object(inventory, "sha256", return_value="0" * 64):
                with self.assertRaisesRegex(inventory.InventoryError, "kernel SHA-256"):
                    inventory.build_inventory(
                        kernel, signer, copyio, disassembly_text=disassembly,
                    )


if __name__ == "__main__":
    unittest.main()
