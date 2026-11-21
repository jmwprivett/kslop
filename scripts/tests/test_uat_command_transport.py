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
        cls.bridge_header = (ROOT / "Cyanide/probes/CyanideLabBridge.h").read_text()
        cls.bridge = (ROOT / "Cyanide/probes/CyanideLabBridge.m").read_text()
        cls.hardware_header = (ROOT / "Cyanide/probes/CNDUatHardwareProbe.h").read_text()
        cls.hardware = (ROOT / "Cyanide/probes/CNDUatHardwareProbe.m").read_text()
        cls.kcall_header = (
            ROOT / "Cyanide/probes/CNDPhysicalKCall1Probe.h"
        ).read_text()
        cls.kcall = (ROOT / "Cyanide/probes/CNDPhysicalKCall1Probe.m").read_text()
        cls.settings_header = (
            ROOT / "Cyanide/SettingsViewController.h"
        ).read_text()
        cls.settings = (
            ROOT / "Cyanide/SettingsViewController.m"
        ).read_text()
        cls.persistence = (
            ROOT / "Cyanide/kexploit/persistence.m"
        ).read_text()
        cls.exploit = (
            ROOT / "Cyanide/kexploit/kexploit_opa334.m"
        ).read_text()

    def test_url_transport_is_exported_and_pid_local(self) -> None:
        self.assertIn("BOOL CNDHandleCommandURL", self.app_header)
        self.assertIn('isEqualToString:@"com.zeroxjf.ios-cyanide1"', self.app)
        self.assertIn('isEqualToString:@"probe"', self.app)
        self.assertIn('@"uat-binding-read"', self.app)
        self.assertIn('@"uat-binding-write"', self.app)
        self.assertIn('@"uat-record-state"', self.app)
        self.assertIn('@"uat-agx-bootstrap-root"', self.app)
        self.assertIn('@"uat-agx-rtbuddy-alias"', self.app)
        self.assertIn('@"uat-agx-firmware-preflight"', self.app)
        self.assertIn('@"uat-signer-inventory"', self.app)
        self.assertIn('@"uat-signer-oracle"', self.app)
        self.assertIn("CNDCmdRun(cmd, source", self.app)

    def test_running_and_cold_scene_deliveries_are_handled(self) -> None:
        self.assertIn("connectionOptions.URLContexts", self.scene)
        self.assertIn("openURLContexts:", self.scene)
        self.assertGreaterEqual(self.scene.count("CNDHandleCommandURL("), 2)

    def test_all_krw_url_probes_use_shared_tweak_lifecycle(self) -> None:
        start = self.app.index("static void CNDCmdRun(")
        end = self.app.index("// Legacy in-container command pickup", start)
        runner = self.app[start:end]
        self.assertIn("settings_ensure_krw_for_probe()", runner)
        self.assertIn(
            "BOOL krwReady = !requiresKrw ? YES :\n"
            "                (existingKrwOnly",
            runner,
        )
        self.assertIn("settings_ensure_existing_krw_for_probe()", runner)
        self.assertIn(
            'BOOL requiresKrw = !([cmd isEqualToString:@"krw-import-recovery-handoff"]',
            runner,
        )
        self.assertIn('[cmd isEqualToString:@"uat-agx-bootstrap-root"]', runner)
        self.assertIn("CNDUatAGXBootstrapRootRun(finish)", runner)
        self.assertIn('[cmd isEqualToString:@"uat-agx-rtbuddy-alias"]', runner)
        self.assertIn("CNDUatAGXRTBuddyAliasRun(finish)", runner)
        self.assertIn('[cmd isEqualToString:@"uat-agx-firmware-preflight"]', runner)
        self.assertIn("CNDAGXFirmwarePreflightRun(requestID, finish)", runner)
        self.assertNotIn("kexploit_opa334()", runner)
        self.assertIn('@"pid": @(getpid())', runner)

    def test_host_krw_commands_are_serialized_for_their_full_async_lifetime(self) -> None:
        start = self.app.index("static void CNDCmdRun(")
        end = self.app.index("// Legacy in-container command pickup", start)
        runner = self.app[start:end]
        self.assertIn("CNDCmdExecutionQueue()", runner)
        self.assertIn("BOOL requiresExternalLifecycleLock = requiresKrw ||", runner)
        acquire = runner.index("settings_begin_external_krw_action(cmd.UTF8String)")
        ensure = runner.index("settings_ensure_krw_for_probe()", acquire)
        release = runner.index("settings_end_external_krw_action(cmd.UTF8String)", acquire)
        finish = runner.index("void (^finish)", acquire)
        self.assertLess(acquire, finish)
        self.assertLess(finish, ensure)
        self.assertLess(acquire, release)
        self.assertIn('@"refused-lifecycle-action-in-progress"', runner)
        self.assertIn("if (completionDelivered) return;", runner)
        self.assertIn("completionDelivered = YES;", runner)
        self.assertIn(
            "settings_begin_external_krw_action", self.settings_header
        )
        self.assertIn(
            "settings_end_external_krw_action", self.settings_header
        )

    def test_e1_uses_shared_existing_generation_only_lifecycle(self) -> None:
        start = self.app.index("static void CNDCmdRun(")
        end = self.app.index("// Legacy in-container command pickup", start)
        runner = self.app[start:end]
        self.assertIn('@"shared-tweak-lifecycle"', runner)
        self.assertIn("existingKrwOnly", runner)
        self.assertIn('@"shared-tweak-lifecycle-existing-only"', runner)
        self.assertIn("settings_ensure_existing_krw_for_probe()", runner)
        self.assertIn('@"refused-existing-krw-unavailable"', runner)
        self.assertIn(
            "bool settings_ensure_existing_krw_for_probe(void)",
            self.settings_header,
        )
        owner_start = self.settings.index(
            "bool settings_ensure_existing_krw_for_probe(void)"
        )
        owner_end = self.settings.index(
            "static BOOL settings_ensure_kexploit(void)", owner_start
        )
        owner = self.settings[owner_start:owner_end]
        self.assertIn("settings_ensure_kexploit_recovery_only()", owner)
        self.assertNotIn("settings_ensure_kexploit()", owner)
        self.assertNotIn("kexploit_opa334()", owner)

    def test_host_helper_never_opens_or_replaces_the_app_container(self) -> None:
        self.assertIn('"--payload-url"', self.host)
        self.assertIn('"uat-binding-read"', self.host)
        self.assertIn('"uat-binding-write"', self.host)
        self.assertIn('"uat-record-state"', self.host)
        self.assertIn('"uat-agx-bootstrap-root"', self.host)
        self.assertIn('"uat-agx-rtbuddy-alias"', self.host)
        self.assertIn('"uat-agx-firmware-preflight"', self.host)
        self.assertIn('"uat-signer-inventory"', self.host)
        self.assertIn('"uat-signer-oracle"', self.host)
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

    def test_krw_diagnostic_is_authenticated_read_only_cached_evidence(self) -> None:
        self.assertIn('"krw-diagnostic"', self.host)
        self.assertIn('@"krw-diagnostic"', self.app)
        start = self.app.index("static void CNDCmdRun(")
        end = self.app.index("UIBackgroundTaskIdentifier task", start)
        diagnostic = self.app[start:end]
        self.assertLess(
            diagnostic.index('[cmd isEqualToString:@"krw-diagnostic"]'),
            diagnostic.index('@"termination":'),
        )
        for forbidden in (
            "settings_ensure_krw_for_probe", "settings_ensure_existing_krw_for_probe",
            "settings_begin_external_krw_action", "kexploit_opa334",
            "kexploit_krw_ready", "krw_persistence_recover", "park",
            "termination_cleanup", "CNDCmdBeginProbeTask",
        ):
            self.assertNotIn(forbidden, diagnostic)
        self.assertIn("krw_persistence_diagnostic_snapshot()", diagnostic)
        self.assertIn("kexploit_krw_socket_diagnostic_snapshot()", diagnostic)
        self.assertIn("resultHandler == nil", diagnostic)
        self.assertNotIn("log_inapp_buffer_snapshot", self.app[start:self.app.index(
            "// Legacy in-container command pickup", start)])
        url = self.app[self.app.index("BOOL CNDHandleCommandURL("):
                       self.app.index("// File-scope, deliberately.")]
        self.assertIn("authenticatedLive", url)
        self.assertIn("!requestedLiveReply", url)
        self.assertIn("replyToken.length == 0", url)
        self.assertIn("requestID.length == 0", url)
        self.assertNotIn('"appDataContainer"', self.host)

        snapshot_start = self.persistence.index(
            "NSDictionary<NSString *, id> *krw_persistence_diagnostic_snapshot(void)"
        )
        snapshot_end = self.persistence.index(
            "static NSString *persist_termination_evidence_name", snapshot_start
        )
        snapshot = self.persistence[snapshot_start:snapshot_end]
        for forbidden in (
            "persist_consume_saved_token", "sandbox_extension_consume",
            "bootstrap_look_up", "kexploit_krw_ready", "getsockopt", "setsockopt",
            "persist_forget_saved_primitive", "log_inapp_buffer_snapshot",
            "removeObjectForKey", "ControlPortToken", "RWPortToken",
            "ControlSocketPcb", "RWSocketPcb", "KernelBase",
        ):
            self.assertNotIn(forbidden, snapshot)
        self.assertIn("persist_redacted_socket_diagnostic", snapshot)
        self.assertIn("persist_redacted_generation_id", snapshot)
        self.assertIn(
            "persist_redacted_socket_diagnostic(NSDictionary *socket)",
            self.persistence,
        )

    def test_update_handoff_is_authenticated_and_exact(self) -> None:
        self.assertIn('"krw-update-handoff"', self.host)
        self.assertIn('@"krw-update-handoff"', self.app)
        self.assertIn("kexploit_prepare_recoverable_termination", self.app)
        for evidence in (
            "parkVerified", "defunctProtected", "controlLinkExact",
            "controlChecksumExact", "rwStateExact", "anchorVerified",
            "currentGenerationExact", "nextProcessArmed", "handoffSerial",
            "generationID", "requestID",
        ):
            self.assertIn(evidence, self.app)
            self.assertIn(evidence, self.host)
        url = self.app[self.app.index("BOOL CNDHandleCommandURL("):
                       self.app.index("// File-scope, deliberately.")]
        self.assertIn('[cmd isEqualToString:@"krw-update-handoff"]', url)
        self.assertIn("authenticatedLive", url)

    def test_socket_evidence_separates_write_read_length_and_comparison(self) -> None:
        verify = self.exploit[self.exploit.index(
            "static bool krw_verify_rw_socket_readback_locked(void)"):
            self.exploit.index("static bool krw_verify_rw_socket_parked_locked(void)")]
        for field in (
            "controlWriteObserved", "controlWriteErrno", "readbackObserved",
            "readbackErrno", "readbackLengthObserved", "readbackLength",
            "comparisonObserved", "comparisonExact",
        ):
            self.assertIn(field, self.exploit)
        self.assertIn("observedLength == compareLength", verify)
        self.assertIn("observedControlLink", verify)
        self.assertIn("observedControlChecksum", verify)
        self.assertIn("krw_read_locked_no_park", verify)
        self.assertIn('@"ReadbackSemantics": @"unproven-target"', self.exploit)
        self.assertLess(
            self.exploit.index("krw_socket_diagnostic_publish();",
                               self.exploit.index("static int set_target_kaddr_locked")),
            self.exploit.index("static bool krw_park_rw_socket_locked(void)"),
        )
        target = self.exploit[self.exploit.index("static int set_target_kaddr_locked"):
                              self.exploit.index("static pthread_mutex_t krwLock")]
        read = self.exploit[self.exploit.index("static bool early_kread_checked"):
                            self.exploit.index("bool kexploit_krw_read_checked(")]
        for field in (
            "rwReadObserved", "rwReadErrno",
            "rwReadLengthObserved", "rwReadLength",
        ):
            self.assertIn(field, read)
        for field in ("targetWriteObserved", "targetWriteErrno"):
            self.assertIn(field, target)

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
        self.assertIn("CNDPhysicalKCall1InventoryIfnetCheckMultiOffset", body)
        self.assertIn(
            "CNDPhysicalKCall1InventoryIfnetCheckMultiOffset = 0x2a8",
            self.kcall,
        )
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

    def test_interface_port_wrapper_is_dereferenced_not_used_inline(self) -> None:
        start = self.kcall.index(
            "static bool CNDPhysicalKCall1ResolveInterface("
        )
        end = self.kcall.index(
            "static NSArray<NSDictionary<NSString *, id> *> *"
            "CNDPhysicalKCall1Interfaces(",
            start,
        )
        body = self.kcall[start:end]
        self.assertIn("wrappedObjectRaw", body)
        self.assertIn("CNDPhysicalKCall1StripDataPointer", body)
        self.assertNotIn("candidate +=", body)

    def test_signer_oracle_is_single_interface_and_non_triggering(self) -> None:
        self.assertIn(
            "void CNDPhysicalKCall1UatSignerOracleRun(",
            self.kcall_header,
        )
        self.assertIn("CNDPhysicalKCall1UatSignerOracleRun(finish)", self.app)
        start = self.kcall.index("static int CNDPhysicalKCall1RunSignerOracle(")
        end = self.kcall.index("static int CNDPhysicalKCall1RunCanary(", start)
        body = self.kcall[start:end]
        self.assertEqual(body.count("CNDPhysicalKCall1CreateSignedIfnet("), 1)
        self.assertIn("CNDPhysicalKCall1StaticEnoexecReturn", body)
        self.assertIn("CNDPhysicalKCall1InventoryIfnetCheckMultiOffset", body)
        self.assertIn('signerOracleInterfaceFieldWriteAttempted\"] = @NO', body)
        self.assertIn('signerOracleIoctlInvoked\"] = @NO', body)
        self.assertIn('signerOracleCallbackInvoked\"] = @NO', body)
        for forbidden in (
            "CNDPhysicalKCall1Trigger",
            "ioctl(",
            "CNDPhysicalKCall1WriteU64Verify",
            "CNDPhysicalKCall1RunUatPTE",
        ):
            self.assertNotIn(forbidden, body)

    def test_signer_oracle_restores_got_before_registry_polling(self) -> None:
        start = self.kcall.index("static int CNDPhysicalKCall1CreateSignedIfnet(")
        end = self.kcall.index("static int CNDPhysicalKCall1RunSignerOracle(", start)
        body = self.kcall[start:end]
        call = body.index("iokit->connectCallMethod(")
        restore = body.index("CNDPhysicalKCall1RestoreCanary(", call)
        poll = body.index("for (unsigned int attempt", restore)
        self.assertLess(call, restore)
        self.assertLess(restore, poll)
        self.assertIn("created->backingIfnet +\n                    callbackOffset", body)

    def test_signer_oracle_requires_and_preserves_preexisting_krw(self) -> None:
        start = self.kcall.index(
            "static NSDictionary<NSString *, id> *CNDPhysicalKCall1RunOnce"
        )
        end = self.kcall.index("BOOL CNDPhysicalKCall1ProbeIsSupported", start)
        body = self.kcall[start:end]
        self.assertIn('refused-preexisting-krw-required', body)
        self.assertIn('krwAcquisitionAttempted\"] = @YES', body)
        self.assertIn('krwCleanupAttempted\"] = @YES', body)
        self.assertIn('krwLeftOpenBecausePreexisting\"] = @YES', body)
        self.assertIn("signerOracleTeardownObserved", body)
        self.assertIn("iokit.serviceClose(connection)", body)


if __name__ == "__main__":
    unittest.main()
