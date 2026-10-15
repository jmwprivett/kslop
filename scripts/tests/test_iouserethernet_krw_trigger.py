import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))
MODULE_PATH = ROOT / "scripts/lab/cnd_iouserethernet_krw_trigger.py"
SPEC = importlib.util.spec_from_file_location(
    "iouserethernet_krw_trigger", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class IOUserEthernetKRWTriggerTests(unittest.TestCase):
    def test_kdp_register_parser_reads_exact_canary_tuple(self) -> None:
        transcript = """
            pc = 0xfffffe00123bac64
            x0 = 0xfffffe000fa59288
            x1 = 0xfffffe1000001000
            x2 = 0xfffffe1000002000
            x3 = 0x0000000000000000
            x4 = 0xfffffe000fa59298
            x5 = 0xabcdfe00123bac64
        """
        self.assertEqual(
            MODULE._registers(transcript),
            {
                "pc": 0xFFFFFE00123BAC64,
                "x0": 0xFFFFFE000FA59288,
                "x1": 0xFFFFFE1000001000,
                "x2": 0xFFFFFE1000002000,
                "x3": 0,
                "x4": 0xFFFFFE000FA59298,
                "x5": 0xABCDFE00123BAC64,
            },
        )
        self.assertTrue(MODULE._kernel_object(0xFFFFFE1000001000))
        self.assertFalse(MODULE._kernel_object(0xFFFFFE000FA59288))

    def test_exact_process_pid_accepts_one_exact_path(self) -> None:
        report = "  10 /usr/libexec/other\n 554 /usr/sbin/bluetoothd\n"
        self.assertEqual(
            MODULE.exact_process_pid(report, "/usr/sbin/bluetoothd"), 554
        )

    def test_exact_process_pid_rejects_ambiguous_path(self) -> None:
        report = " 554 /usr/sbin/bluetoothd\n 555 /usr/sbin/bluetoothd\n"
        with self.assertRaises(MODULE.LabError):
            MODULE.exact_process_pid(report, "/usr/sbin/bluetoothd")

    def test_validate_accepts_restored_krw_only_trigger(self) -> None:
        report = {
            "schema": "com.zeroxjf.cyanide.iouserethernet-krw-trigger",
            "schemaVersion": 1,
            "kernelReadUsed": True,
            "kernelWriteUsed": True,
            "kernelCallUsed": False,
            "providerOperations": ["Capabilities", "KBase", "Read", "Write"],
            "baselineOpenKR": "0x00000000e00002e2",
            "borrowInstalled": True,
            "borrowedOpenKR": "0x0000000000000000",
            "borrowRestored": True,
            "restoreWholeLabelExact": True,
            "selectorInvokedAfterRestore": True,
            "callKR": "0x0000000000000000",
            "createdInterfaces": [{"registryID": "0x1", "bsdName": "cnd0"}],
            "result": "krw-borrow-triggered-normal-signer-path",
        }
        self.assertIs(MODULE.validate_result(report), report)

    def test_validate_rejects_kcall(self) -> None:
        report = {
            "schema": "com.zeroxjf.cyanide.iouserethernet-krw-trigger",
            "schemaVersion": 1,
            "kernelReadUsed": True,
            "kernelWriteUsed": True,
            "kernelCallUsed": False,
            "providerOperations": ["Read", "Write", "KernelCall"],
            "baselineOpenKR": "0x00000000e00002e2",
            "borrowInstalled": True,
            "borrowedOpenKR": "0x0000000000000000",
            "borrowRestored": True,
            "restoreWholeLabelExact": True,
            "selectorInvokedAfterRestore": True,
            "callKR": "0x0000000000000000",
            "createdInterfaces": [{"bsdName": "cnd0"}],
            "result": "krw-borrow-triggered-normal-signer-path",
        }
        with self.assertRaises(MODULE.LabError):
            MODULE.validate_result(report)

    def test_validate_accepts_stock_notifier_target_swap(self) -> None:
        report = {
            "schema": "com.zeroxjf.cyanide.iouserethernet-krw-trigger",
            "schemaVersion": 1,
            "kernelReadUsed": True,
            "kernelWriteUsed": True,
            "kernelCallUsed": False,
            "providerOperations": ["Capabilities", "KBase", "Read", "Write"],
            "baselineOpenKR": "0x00000000e00002e2",
            "borrowInstalled": True,
            "borrowedOpenKR": "0x0000000000000000",
            "borrowRestored": True,
            "restoreWholeLabelExact": True,
            "selectorInvokedAfterRestore": True,
            "callKR": "0x0000000000000000",
            "createdInterfaces": [{"registryID": "0x1", "bsdName": "cnd0"}],
            "notificationTargetSwapRequested": True,
            "notificationTargetSwapReady": True,
            "notificationTargetInstalled": True,
            "notificationTargetRestored": True,
            "notificationSetupResult": 0,
            "notificationACallbacks": 0,
            "notificationBCallbacks": 1,
            "notificationBServices": 1,
            "notificationBCallbacksOnQueueB": 1,
            "notificationBLastIterator": "0x0000000000001234",
            "notificationBExpectedIterator": "0x0000000000001234",
            "result": "krw-notifier-target-swap-triggered-stock-61de-dispatch",
        }
        self.assertIs(
            MODULE.validate_result(
                report, require_notification_target_swap=True
            ),
            report,
        )

    def test_validate_accepts_restored_block_canary(self) -> None:
        report = {
            "schema": "com.zeroxjf.cyanide.iouserethernet-krw-trigger",
            "schemaVersion": 1,
            "kernelReadUsed": True,
            "kernelWriteUsed": True,
            "kernelCallUsed": False,
            "providerOperations": ["Capabilities", "KBase", "Read", "Write"],
            "baselineOpenKR": "0x00000000e00002e2",
            "borrowInstalled": True,
            "borrowedOpenKR": "0x0000000000000000",
            "borrowRestored": True,
            "restoreWholeLabelExact": True,
            "selectorInvokedAfterRestore": True,
            "callKR": "0x0000000000000000",
            "createdInterfaces": [{"registryID": "0x1", "bsdName": "cnd0"}],
            "notificationBlockCanaryRequested": True,
            "notificationTargetSwapReady": True,
            "notificationBlockInstalled": True,
            "notificationBlockRestored": True,
            "notificationSetupResult": 0,
            "notificationACallbacks": 0,
            "result": "krw-notifier-block-noop-dispatch-survived",
        }
        self.assertIs(
            MODULE.validate_result(
                report, require_notification_block_canary=True
            ),
            report,
        )

    def test_validate_accepts_restored_sandbox_canary(self) -> None:
        report = {
            "schema": "com.zeroxjf.cyanide.iouserethernet-krw-trigger",
            "schemaVersion": 1,
            "kernelReadUsed": True,
            "kernelWriteUsed": True,
            "kernelCallUsed": False,
            "providerOperations": ["Capabilities", "KBase", "Read", "Write"],
            "baselineOpenKR": "0x00000000e00002e2",
            "borrowInstalled": True,
            "borrowedOpenKR": "0x0000000000000000",
            "borrowRestored": True,
            "restoreWholeLabelExact": True,
            "selectorInvokedAfterRestore": True,
            "callKR": "0x0000000000000000",
            "createdInterfaces": [{"registryID": "0x1", "bsdName": "cnd0"}],
            "notificationSandboxCanaryRequested": True,
            "notificationTargetSwapReady": True,
            "notificationSandboxInstalled": True,
            "notificationSandboxRestored": True,
            "notificationSetupResult": 0,
            "notificationACallbacks": 0,
            "result": "krw-notifier-sandbox-iazero-dispatch-survived",
        }
        self.assertIs(
            MODULE.validate_result(
                report, require_notification_sandbox_canary=True
            ),
            report,
        )

    def test_validate_accepts_restored_2abe_73d8_canary(self) -> None:
        report = {
            "schema": "com.zeroxjf.cyanide.iouserethernet-krw-trigger",
            "schemaVersion": 1,
            "kernelReadUsed": True,
            "kernelWriteUsed": True,
            "kernelCallUsed": False,
            "providerOperations": ["Capabilities", "KBase", "Read", "Write"],
            "baselineOpenKR": "0x00000000e00002e2",
            "borrowInstalled": True,
            "borrowedOpenKR": "0x0000000000000000",
            "borrowRestored": True,
            "restoreWholeLabelExact": True,
            "selectorInvokedAfterRestore": True,
            "callKR": "0x0000000000000000",
            "createdInterfaces": [{"registryID": "0x1", "bsdName": "cnd0"}],
            "notification2ABE73D8CanaryRequested": True,
            "notificationTargetSwapReady": True,
            "notification2ABE73D8Prepared": True,
            "notification2ABE73D8Installed": True,
            "notificationBlockRestored": True,
            "notification2ABE73D8Restored": True,
            "notification2ABECallbackCount": 2,
            "notificationSetupResult": 0,
            "notificationACallbacks": 0,
            "result": "krw-notifier-2abe-73d8-dispatch-survived",
        }
        self.assertIs(
            MODULE.validate_result(
                report, require_notification_2abe_73d8_canary=True
            ),
            report,
        )

    def test_validate_accepts_read_only_sysctl_pac_census(self) -> None:
        records = [{
            "readResult": 0,
            "handlerTargetMatches": True,
            "listMalformed": False,
            "listCycle": False,
        } for _ in range(5)]
        report = {
            "schema": "com.zeroxjf.cyanide.iouserethernet-krw-trigger",
            "schemaVersion": 1,
            "kernelReadUsed": True,
            "kernelWriteUsed": False,
            "kernelCallUsed": False,
            "providerOperations": ["Capabilities", "KBase", "Read", "Write"],
            "sysctlPACCensusRequested": True,
            "sysctlPACReadOnly": True,
            "sysctlPACCandidateCount": 5,
            "sysctlPACConditionReadResult": 0,
            "sysctlPACRecords": records,
            "result": "sysctl-pac-census-complete",
        }
        self.assertIs(
            MODULE.validate_result(report, require_sysctl_pac_census=True),
            report,
        )

    def test_validate_accepts_ifnet_check_multi_pac_canary(self) -> None:
        report = {
            "schema": "com.zeroxjf.cyanide.iouserethernet-krw-trigger",
            "schemaVersion": 1,
            "kernelReadUsed": True,
            "kernelWriteUsed": True,
            "kernelCallUsed": False,
            "providerOperations": ["Capabilities", "KBase", "Read", "Write"],
            "baselineOpenKR": "0x00000000e00002e2",
            "borrowInstalled": True,
            "borrowedOpenKR": "0x0000000000000000",
            "borrowRestored": True,
            "restoreWholeLabelExact": True,
            "selectorInvokedAfterRestore": True,
            "callKR": "0x0000000000000000",
            "createdInterfaces": [{"registryID": "0x1", "bsdName": "cnd0"}],
            "ifnetCheckMultiPACCanaryRequested": True,
            "ifnetPACGOTReady": True,
            "ifnetPACGOTInstalled": True,
            "ifnetPACGOTRestored": True,
            "ifnetPACSetupResult": 0,
            "ifnetPACGOTInstallResult": 0,
            "ifnetPACDiscriminator": "0xe4fe",
            "ifnetPACCanaryTarget": "0xfffffe00082f6a38",
            "ifnetPACCallbackTarget": "0xfffffe00082f6a38",
            "ifnetPACReadbackResult": 0,
            "ifnetPACBSDName": "cnd0",
            "ifnetPACTriggerResult": -1,
            "ifnetPACTriggerErrno": 8,
            "ifnetPACTriggerErrnoName": "ENOEXEC",
            "result": "krw-ifnet-check-multi-arbitrary-target-pac-executed",
        }
        self.assertIs(
            MODULE.validate_result(
                report, require_ifnet_check_multi_pac_canary=True
            ),
            report,
        )

    def _ifnet_kcall1_report(self) -> dict:
        stock = "0xfffffe0007d293fc"
        load = "0xfffffe00082f6590"
        dispatcher = "0xfffffe0008f94a8c"
        got = "0xfffffe0007e1a0c0"
        stock_signed = "0x1a2bfe0007d293fc"
        original_x0 = "0xfffffe1000a00000"
        original_target = "0xfffffe1000a00100"
        report = {
            "schema": "com.zeroxjf.cyanide.iouserethernet-krw-trigger",
            "schemaVersion": 1,
            "kernelReadUsed": True,
            "kernelWriteUsed": True,
            "kernelCallUsed": False,
            "providerOperations": ["Capabilities", "KBase", "Read", "Write"],
            "baselineOpenKR": "0x00000000e00002e2",
            "borrowInstalled": True,
            "borrowedOpenKR": "0x0000000000000000",
            "borrowRestored": True,
            "restoreWholeLabelExact": True,
            "selectorInvokedAfterRestore": True,
            "callKR": "0x0000000000000000",
            "createdInterfaces": [
                {"registryID": "0x1", "bsdName": "kcl0"},
                {"registryID": "0x2", "bsdName": "kcl1"},
                {"registryID": "0x3", "bsdName": "kcl2"},
            ],
            "ifnetKCall1PACCanaryRequested": True,
            "ifnetKCall1SetupResult": 0,
            "ifnetKCall1SignerStagesResult": 0,
            "ifnetKCall1Result": 0,
            "ifnetKCall1ConstructedArity": 1,
            "ifnetKCall1ProviderKCallUsed": False,
            "ifnetKCall1CallbackQuiesced": True,
            "ifnetKCall1ChainInstalled": True,
            "ifnetKCall1TriggerResult": -1,
            "ifnetKCall1TriggerErrno": 36,
            "ifnetKCall1TriggerErrnoName": "EINPROGRESS",
            "ifnetKCall1CallbackSanitized": True,
            "ifnetKCall1X0Restored": True,
            "ifnetKCall1TargetRestored": True,
            "ifnetKCall1GOTRestored": True,
            "ifnetKCall1FinalReadResult": 0,
            "ifnetKCall1Success": True,
            "ifnetKCall1StockTarget": stock,
            "ifnetKCall1LoadTarget": load,
            "ifnetKCall1DispatcherTarget": dispatcher,
            "ifnetKCall1StockBSDName": "kcl0",
            "ifnetKCall1LoadBSDName": "kcl1",
            "ifnetKCall1DispatcherBSDName": "kcl2",
            "ifnetKCall1StockReadbackResult": 0,
            "ifnetKCall1LoadReadbackResult": 0,
            "ifnetKCall1DispatcherReadbackResult": 0,
            "ifnetKCall1StockCallbackTarget": stock,
            "ifnetKCall1LoadCallbackTarget": load,
            "ifnetKCall1DispatcherCallbackTarget": dispatcher,
            "ifnetKCall1FinalCallbackTarget": stock,
            "ifnetPACGOTOriginalRaw": stock,
            "ifnetKCall1FinalGOT": stock,
            "ifnetPACGOTAddress": got,
            "ifnetKCall1MarkerAddress": got,
            "ifnetKCall1MarkerValue": 36,
            "ifnetKCall1X0Field": "0xfffffe1000a00090",
            "ifnetKCall1TargetField": "0xfffffe1000a000b0",
            "ifnetKCall1CallbackField": "0xfffffe1000a000d8",
            "ifnetKCall1OriginalX0": original_x0,
            "ifnetKCall1OriginalTarget": original_target,
            "ifnetKCall1StockSignedCallback": stock_signed,
            "ifnetKCall1FinalCallback": stock_signed,
            "ifnetKCall1FinalX0": original_x0,
            "ifnetKCall1FinalTarget": original_target,
            "ifnetKCall1CleanupResult": -1,
            "ifnetKCall1CleanupErrno": 0,
            "result": "krw-ifnet-kcall1-chosen-pc-x0-executed",
        }
        return report

    def test_validate_accepts_ifnet_kcall1_pac_canary(self) -> None:
        report = self._ifnet_kcall1_report()
        self.assertIs(
            MODULE.validate_result(
                report, require_ifnet_kcall1_pac_canary=True
            ),
            report,
        )

    def test_validate_rejects_ifnet_kcall1_final_state_mismatch(self) -> None:
        report = self._ifnet_kcall1_report()
        report["ifnetKCall1FinalX0"] = "0xfffffe000fa59288"
        self.assertNotEqual(
            report["ifnetKCall1FinalX0"], report["ifnetKCall1OriginalX0"]
        )
        self.assertTrue(report["ifnetKCall1Success"])
        with self.assertRaisesRegex(
                MODULE.LabError, "ifnet kcall1 final X0 not restored"):
            MODULE.validate_result(
                report, require_ifnet_kcall1_pac_canary=True
            )

    def test_validate_rejects_ifnet_kcall1_missing_or_mistyped_field(
            self) -> None:
        report = self._ifnet_kcall1_report()
        del report["ifnetKCall1FinalGOT"]
        del report["ifnetPACGOTOriginalRaw"]
        # Both sides absent: the old `.get(a) != .get(b)` idiom passed this.
        self.assertEqual(
            report.get("ifnetKCall1FinalGOT"),
            report.get("ifnetPACGOTOriginalRaw"),
        )
        with self.assertRaisesRegex(
                MODULE.LabError,
                "ifnet kcall1 field missing or mistyped: "
                "ifnetPACGOTOriginalRaw"):
            MODULE.validate_result(
                report, require_ifnet_kcall1_pac_canary=True
            )
        report = self._ifnet_kcall1_report()
        report["ifnetKCall1LoadReadbackResult"] = "0"
        with self.assertRaisesRegex(
                MODULE.LabError,
                "ifnet kcall1 field missing or mistyped: "
                "ifnetKCall1LoadReadbackResult"):
            MODULE.validate_result(
                report, require_ifnet_kcall1_pac_canary=True
            )

    def test_validate_rejects_ifnet_kcall1_failed_stage_marker(self) -> None:
        for marker in (True, False):
            report = self._ifnet_kcall1_report()
            report["ifnetKCall1FailedStageSanitized"] = marker
            self.assertTrue(report["ifnetKCall1Success"])
            with self.assertRaisesRegex(
                    MODULE.LabError,
                    "ifnet kcall1 success report carries a failed-stage "
                    "marker"):
                MODULE.validate_result(
                    report, require_ifnet_kcall1_pac_canary=True
                )

    def test_validate_rejects_ifnet_kcall1_marker_desync(self) -> None:
        report = self._ifnet_kcall1_report()
        report["ifnetKCall1MarkerValue"] = 35
        self.assertEqual(report["ifnetKCall1TriggerErrno"], 36)
        with self.assertRaisesRegex(
                MODULE.LabError,
                "ifnet kcall1 trigger errno did not match marker value"):
            MODULE.validate_result(
                report, require_ifnet_kcall1_pac_canary=True
            )
        report = self._ifnet_kcall1_report()
        report["ifnetPACGOTAddress"] = "0xfffffe0007e1a0c8"
        self.assertNotEqual(
            report["ifnetPACGOTAddress"], report["ifnetKCall1MarkerAddress"]
        )
        with self.assertRaisesRegex(
                MODULE.LabError,
                "ifnet kcall1 marker address did not match GOT address"):
            MODULE.validate_result(
                report, require_ifnet_kcall1_pac_canary=True
            )

    def test_validate_rejects_ifnet_kcall1_stage_name_reuse_or_orphan(
            self) -> None:
        report = self._ifnet_kcall1_report()
        report["ifnetKCall1LoadBSDName"] = report["ifnetKCall1StockBSDName"]
        with self.assertRaisesRegex(
                MODULE.LabError,
                "ifnet kcall1 stage interfaces are not distinct"):
            MODULE.validate_result(
                report, require_ifnet_kcall1_pac_canary=True
            )
        report = self._ifnet_kcall1_report()
        report["ifnetKCall1DispatcherBSDName"] = "kcl9"
        created = {item["bsdName"] for item in report["createdInterfaces"]}
        self.assertNotIn("kcl9", created)
        with self.assertRaisesRegex(
                MODULE.LabError,
                "ifnet kcall1 Dispatcher interface was not created"):
            MODULE.validate_result(
                report, require_ifnet_kcall1_pac_canary=True
            )

    def test_source_has_no_kernel_call_operation(self) -> None:
        source = MODULE.TRIGGER_SOURCE.read_text()
        self.assertNotIn("CNDLabKRWOperationKernelCall", source)
        self.assertIn("CNDLabKRWOperationRead", source)
        self.assertIn("CNDLabKRWOperationWrite", source)
        self.assertIn("selectorInvokedAfterRestore", source)
        self.assertIn("labelResolvedAfterBaseline", source)
        self.assertIn("CNDStaticUserNotificationAction", source)
        self.assertIn("CNDStaticBlockNotificationAction", source)
        self.assertIn("CNDStaticSandboxNotificationAction", source)
        self.assertIn("CNDStaticSandboxPublishCallback", source)
        self.assertIn("CNDStaticNoOpBlockInvoke", source)
        self.assertIn("CNDStatic2ABEBlockInvoke", source)
        self.assertIn("CNDStatic2ABEAdapterFixup", source)
        self.assertIn("CNDStatic73D8ReturnFixup", source)
        self.assertIn("CNDStaticIOEthernetCheckMultiGOT", source)
        self.assertIn("CNDStaticIOEthernetCheckMultiSigner", source)
        self.assertIn("CNDStaticENOEXECReturn", source)
        self.assertIn("CNDStaticLoadW0FromX0", source)
        self.assertIn("CNDStaticIfnetX0Dispatcher", source)
        self.assertIn("CNDInstallIfnetPACCanary", source)
        self.assertIn("CNDRestoreIfnetPACCanary", source)
        self.assertIn("CNDRunIfnetKCall1PACCanary", source)
        self.assertIn("--ifnet-kcall1-pac-canary", source)
        self.assertIn("CNDIONetworkInterfaceBackingIfnetOffset = 0x90", source)
        self.assertIn("CNDIfnetCheckMultiOffset = 0x238", source)
        self.assertIn("SIOCADDMULTI", source)
        self.assertIn("CNDNotifierTargetOffset", source)
        self.assertIn("CNDIOMachPortObjectOffset = 0x20", source)
        self.assertIn("CNDIOObjectForPort", source)
        self.assertIn("CNDRestoreNotificationTarget", source)
        self.assertIn("CNDRestoreNotificationBlock", source)
        self.assertIn("CNDRestoreNotificationSandboxBridge", source)
        self.assertIn("CNDRestore2ABE73D8Fields", source)
        self.assertIn("CNDRunSysctlPACCensus", source)
        self.assertIn("static0E2EDonorCandidate", source)
        self.assertIn("offset <= 0x20", source)
        self.assertNotIn("offset <= 0x28", source)
        self.assertLess(
            source.index('report[@"baselineOpenKR"]'),
            source.index('report[@"labelResolvedAfterBaseline"]'),
        )


if __name__ == "__main__":
    unittest.main()
