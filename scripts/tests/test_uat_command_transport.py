#!/usr/bin/env python3
"""Static contract for the in-process physical UAT command transport."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class UATCommandTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app_header = (ROOT / "Cyanide/AppDelegate.h").read_text()
        cls.app = (ROOT / "Cyanide/AppDelegate.m").read_text()
        cls.scene = (ROOT / "Cyanide/SceneDelegate.m").read_text()
        cls.host = (ROOT / "scripts/lab/cnd_live_probe.py").read_text()
        cls.bridge_header = (ROOT / "Cyanide/CyanideLabBridge.h").read_text()
        cls.bridge = (ROOT / "Cyanide/CyanideLabBridge.m").read_text()
        cls.hardware_header = (ROOT / "Cyanide/CNDUatHardwareProbe.h").read_text()
        cls.hardware = (ROOT / "Cyanide/CNDUatHardwareProbe.m").read_text()
        cls.kcall_header = (
            ROOT / "Cyanide/CNDPhysicalKCall1Probe.h"
        ).read_text()
        cls.kcall = (ROOT / "Cyanide/CNDPhysicalKCall1Probe.m").read_text()

    def test_url_transport_is_exported_and_pid_local(self) -> None:
        self.assertIn("BOOL CNDHandleCommandURL", self.app_header)
        self.assertIn('isEqualToString:@"com.zeroxjf.ios-cyanide1"', self.app)
        self.assertIn('isEqualToString:@"probe"', self.app)
        self.assertIn('@"uat-binding-read"', self.app)
        self.assertIn('@"uat-binding-write"', self.app)
        self.assertIn('@"uat-record-state"', self.app)
        self.assertIn('@"uat-signer-inventory"', self.app)
        self.assertIn("CNDCmdRun(cmd, source", self.app)

    def test_running_and_cold_scene_deliveries_are_handled(self) -> None:
        self.assertIn("connectionOptions.URLContexts", self.scene)
        self.assertIn("openURLContexts:", self.scene)
        self.assertGreaterEqual(self.scene.count("CNDHandleCommandURL("), 2)

    def test_url_command_only_consumes_existing_krw(self) -> None:
        start = self.app.index("static void CNDCmdRun(")
        end = self.app.index("// Legacy in-container command pickup", start)
        runner = self.app[start:end]
        self.assertIn("kexploit_krw_ready()", runner)
        self.assertNotIn("kexploit_opa334()", runner)
        self.assertIn('@"pid": @(getpid())', runner)

    def test_host_helper_never_opens_or_replaces_the_app_container(self) -> None:
        self.assertIn('"--payload-url"', self.host)
        self.assertIn('"uat-binding-read"', self.host)
        self.assertIn('"uat-binding-write"', self.host)
        self.assertIn('"uat-record-state"', self.host)
        self.assertIn('"uat-signer-inventory"', self.host)
        self.assertNotIn('"appDataContainer"', self.host)
        self.assertNotIn('"--terminate-existing"', self.host)

    def test_live_result_uses_single_use_authenticated_bridge(self) -> None:
        self.assertIn("cyanide_lab_bridge_start_with_token", self.bridge_header)
        self.assertIn("requireIdle", self.bridge)
        self.assertIn('@"Another bridge already owns the listener."', self.bridge)
        self.assertIn('@"probe.result"', self.app)
        self.assertIn('@"probe.ack"', self.app)
        self.assertIn('@"request-mismatch"', self.app)
        self.assertIn("CNDCmdCompleteLiveReply", self.app)
        self.assertIn("replyToken", self.host)
        self.assertIn("requestID", self.host)
        self.assertIn("secrets.token_hex(32)", self.host)
        self.assertIn('"command": "probe.result"', self.host)
        self.assertIn('"command": "probe.ack"', self.host)

    def test_live_result_bridge_does_not_acquire_or_cleanup_krw(self) -> None:
        start = self.app.index("static BOOL CNDCmdStartLiveReply(")
        end = self.app.index("static void CNDCmdRun(", start)
        bridge_runner = self.app[start:end]
        self.assertNotIn("kexploit_", bridge_runner)
        self.assertNotIn("settings_best_effort_termination_cleanup", bridge_runner)
        self.assertNotIn('"--domain-type"', self.host)
        self.assertNotIn('"copy", "from"', self.host)

    def test_record_state_probe_is_bounded_and_read_only(self) -> None:
        self.assertIn(
            "void CNDUatHardwareRecordStateProbeRun(", self.hardware_header
        )
        start = self.hardware.index("void CNDUatHardwareRecordStateProbeRun(")
        body = self.hardware[start:]
        self.assertIn("CNDUatHWExpectedRecordTag", body)
        self.assertIn("0xbee5000000010004ull", self.hardware)
        self.assertIn("recordOffset % 0x28 == 0", body)
        self.assertIn("CNDUatHWGPhysBase", body)
        self.assertIn("CNDUatHWGPhysSize", body)
        self.assertIn("statePagePA - physBase", body)
        self.assertIn('@"statePageReadAttempted"] = @NO', body)
        self.assertIn("physmap-range-membership-does-not-prove", body)
        self.assertNotIn("statePageVA", body)
        self.assertNotIn("CNDUatHWRead(&api, statePageVA", body)
        self.assertNotIn("api.write64", body)
        self.assertNotIn("kwrite", body)
        self.assertIn('@"pointerSubstitution": @NO', body)
        self.assertIn("[CND_UAT_HW_RESULT]", self.hardware)

    def test_signer_inventory_is_wired_to_its_read_only_runner(self) -> None:
        self.assertIn(
            "void CNDPhysicalKCall1UatSignerInventoryRun(",
            self.kcall_header,
        )
        self.assertIn(
            "CNDPhysicalKCall1UatSignerInventoryRun(finish)", self.app
        )
        start = self.kcall.index(
            "CNDPhysicalKCall1RunSignerInventoryOnce(void)"
        )
        end = self.kcall.index(
            "static NSDictionary<NSString *, id> *CNDPhysicalKCall1RunOnce",
            start,
        )
        body = self.kcall[start:end]
        self.assertIn("CNDPhysicalKCall1ResolveReadOnlyKernelAPI", body)
        self.assertIn("CNDPhysicalKCall1ResolveReadOnlyIOKitAPI", body)
        self.assertIn("kernel.krwReady()", body)
        self.assertIn("CNDPhysicalKCall1InventoryClass", body)
        self.assertIn('@"kernelWriteUsed": @NO', body)
        self.assertIn('@"kernelCallUsed": @NO', body)
        self.assertIn('@"krwAcquisitionAttempted": @NO', body)
        self.assertIn('@"globalSlotWriteAttempted": @NO', body)
        for forbidden in (
            "kwrite",
            "write32BytesChecked",
            "kernel.kexploit",
            "kernel.krwCleanup(",
            "iokit.serviceOpen(",
            "iokit->serviceOpen(",
            "iokit.connectCallMethod(",
            "iokit->connectCallMethod(",
            "ioctl(",
            "CNDPhysicalKCall1PrepareBorrow",
            "CNDPhysicalKCall1RunUatPTE",
            "CNDPhysicalKCall1Trigger",
        ):
            self.assertNotIn(forbidden, body)

    def test_signer_inventory_interface_walk_only_reads_fields(self) -> None:
        start = self.kcall.index("static void CNDPhysicalKCall1InventoryClass(")
        end = self.kcall.index(
            "static int CNDPhysicalKCall1PrepareCanary(", start
        )
        body = self.kcall[start:end]
        self.assertIn("CNDPhysicalKCall1ReadU64", body)
        self.assertIn("CNDPhysicalKCall1ResolveInterface", body)
        self.assertIn("objectRelease", body)
        for forbidden in (
            "Write",
            "kwrite",
            "serviceOpen",
            "connectCallMethod",
            "ioctl(",
            "callback(",
        ):
            self.assertNotIn(forbidden, body)


if __name__ == "__main__":
    unittest.main()
