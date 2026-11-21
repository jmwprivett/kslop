#!/usr/bin/env python3
"""Static safety contract for the C50 AGX firmware read-only preflight."""

from pathlib import Path
import unittest

from scripts.lab import cnd_live_probe


ROOT = Path(__file__).resolve().parents[2]


class AGXFirmwarePreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = (
            ROOT / "Cyanide/probes/CNDAGXFirmwarePreflightProbe.h"
        ).read_text()
        cls.source = (
            ROOT / "Cyanide/probes/CNDAGXFirmwarePreflightProbe.m"
        ).read_text()
        cls.app = (ROOT / "Cyanide/AppDelegate.m").read_text()
        cls.host = (ROOT / "scripts/lab/cnd_live_probe.py").read_text()

    def test_separate_existing_only_command_is_wired(self) -> None:
        self.assertIn("CNDAGXFirmwarePreflightRun", self.header)
        self.assertIn('@"uat-agx-firmware-preflight"', self.app)
        runner = self.app[
            self.app.index("static void CNDCmdRun("):
            self.app.index("// Legacy in-container command pickup")
        ]
        self.assertIn(
            '[cmd isEqualToString:@"uat-agx-firmware-preflight"]', runner
        )
        self.assertIn(
            "CNDAGXFirmwarePreflightRun(requestID, finish)", runner
        )
        self.assertIn('"uat-agx-firmware-preflight"', self.host)

    def test_report_names_open_joins_and_never_claims_command_read(self) -> None:
        for marker in (
            '@"resourceMapJoin": @"unproved"',
            '@"firmwareAddressDomainJoin": @"unproved"',
            '@"outputAliasEstablished": @NO',
            '@"exclusiveProducerOwnership": @"unproved"',
            '@"command20ReadClaimed": @NO',
            '@"firmwareCommandInserted": @NO',
            '@"firmwareKickAttempted": @NO',
            '@"firmwareOutputReadAttempted": @NO',
        ):
            self.assertIn(marker, self.source)

    def test_buffer_baseline_is_owned_and_gpu_observed(self) -> None:
        self.assertIn("newBufferWithLength:CNDAGXPageSize", self.source)
        self.assertGreaterEqual(
            self.source.count("newBufferWithLength:CNDAGXPageSize"), 2
        )
        self.assertIn("copyFromBuffer:source", self.source)
        self.assertIn("cpuValue == nonce && gpuValue == nonce", self.source)
        self.assertIn('@"sourceModifiedByGPU": @NO', self.source)

    def test_resource_paths_are_kept_distinct(self) -> None:
        self.assertIn('@"wrapperAndResourceRefJoined"', self.source)
        self.assertIn('@"kernelResourceHandleRelationshipProved": @NO', self.source)
        self.assertIn('@"selector8ClientJoinedToMetalTaskClient": @NO', self.source)
        self.assertIn('@"selector8ResourceClient": @"not-joined"', self.source)
        self.assertNotIn("resourceID++", self.source)

    def test_ring_and_output_pointers_are_not_followed(self) -> None:
        self.assertIn('@"fieldPACRederived": @NO', self.source)
        self.assertIn('@"indexBlockFieldRead": @NO', self.source)
        self.assertIn('@"recordBufferFieldRead": @NO', self.source)
        self.assertIn('@"backingPointerStripped": @NO', self.source)
        self.assertIn('@"backingDereferenceAttempted": @NO', self.source)
        self.assertNotIn("CNDAGXFirmwareHostRing + 0x8", self.source)
        self.assertNotIn("CNDAGXFirmwareHostRing + 0x10", self.source)

    def test_no_kernel_or_firmware_write_primitive_is_resolved(self) -> None:
        forbidden = (
            "kwrite",
            "kexploit_early_kwrite",
            "kcall",
            "write64",
            "write32",
            "IOConnectCallStructMethod",
            "IOConnectCallMethod",
        )
        for symbol in forbidden:
            self.assertNotIn(symbol, self.source)
        self.assertIn('"kexploit_krw_read_checked"', self.source)

    def test_generation_is_checked_at_both_ends(self) -> None:
        self.assertIn("krw_persistence_current_generation_id()", self.source)
        self.assertGreaterEqual(
            self.source.count(
                "krw_persistence_verify_current_generation_anchor"
            ),
            2,
        )
        self.assertIn('@"krwGenerationUnchanged"', self.source)

    def test_host_requires_the_exact_c50_terminal_path(self) -> None:
        request_id = "request-123"
        result = {
            "schema": "com.zeroxjf.cyanide.agx-firmware-preflight",
            "state": "finished",
            "result": "read-only-preflight-observed",
            "requestID": request_id,
            "reportPersistence": "atomic-write-completed",
            "krwGenerationUnchanged": True,
            "firmwareCommandInserted": False,
            "firmwareKickAttempted": False,
            "firmwareOutputReadAttempted": False,
            "command20ReadClaimed": False,
            "deviceIdentity": {
                "productType": "iPhone17,2",
                "productBuildVersion": "23A341",
            },
            "openJoins": [
                "command20-active-firmware-EL1-TTBR0-TTBR1-TCR",
                "firmware-load-translation-to-owned-frame",
                "fixed-output-table-CPU-alias",
                "exclusive-producer-ownership",
            ],
        }
        cnd_live_probe.validate_intended_result(
            "uat-agx-firmware-preflight", request_id, result
        )
        for key, bad_value in (
            ("requestID", "stale-request"),
            ("result", "refused-generation-anchor-unproved"),
            ("reportPersistence", "atomic-write-failed"),
            ("firmwareKickAttempted", True),
        ):
            bad = dict(result)
            bad[key] = bad_value
            with self.assertRaises(ValueError, msg=key):
                cnd_live_probe.validate_intended_result(
                    "uat-agx-firmware-preflight", request_id, bad
                )


if __name__ == "__main__":
    unittest.main()
