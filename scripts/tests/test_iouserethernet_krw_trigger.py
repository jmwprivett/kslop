import argparse
import copy
import errno
import importlib.util
import re
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


# Fixtures mirror the producer's success-path emissions for each mode
# (scripts/lab/cnd_iouserethernet_krw_trigger.m). Keys beyond what the
# validator pins are the ones the round-4 drift table flagged as emitted
# by the producer but absent from the old fixtures.

def _common_report() -> dict:
    return {
        "schema": "com.zeroxjf.cyanide.iouserethernet-krw-trigger",
        "schemaVersion": 1,
        "observedKernelBase": "0xfffffe0007004000",
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
        "createdInterfaces": [{
            "registryID": "0x1",
            "kernelObject": "0xfffffe1000001000",
            "bsdName": "cnd0",
        }],
        "result": "krw-borrow-triggered-normal-signer-path",
    }


def _target_swap_report() -> dict:
    report = _common_report()
    report.update({
        "notificationTargetSwapRequested": True,
        "notificationTargetSwapReady": True,
        "notificationTargetInstallResult": 0,
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
    })
    return report


def _block_canary_report() -> dict:
    report = _common_report()
    report.update({
        "notificationBlockCanaryRequested": True,
        "notificationTargetSwapReady": True,
        "notificationTargetInstallResult": 0,
        "notificationBlockInstalled": True,
        "notificationBlockRestored": True,
        "notificationSetupResult": 0,
        "notificationACallbacks": 0,
        "notificationANotifier": "0xfffffe1000002000",
        "notificationBlockAddress": "0xfffffe000fa59288",
        "notificationBlockInvoke": "0xfffffe00113bac64",
        "result": "krw-notifier-block-noop-dispatch-survived",
    })
    return report


def _sandbox_canary_report() -> dict:
    report = _common_report()
    report.update({
        "notificationSandboxCanaryRequested": True,
        "notificationTargetSwapReady": True,
        "notificationTargetInstallResult": 0,
        "notificationSandboxInstalled": True,
        "notificationSandboxRestored": True,
        "notificationSetupResult": 0,
        "notificationACallbacks": 0,
        "notificationANotifier": "0xfffffe1000002000",
        "notificationSandboxActionRaw": "0x1a2bfe0011398e6c",
        "notificationSandboxCallback": "0xfffffe00113ae0d8",
        "result": "krw-notifier-sandbox-iazero-dispatch-survived",
    })
    return report


def _pac_2abe_73d8_report() -> dict:
    report = _common_report()
    report.update({
        "notification2ABE73D8CanaryRequested": True,
        "notificationTargetSwapReady": True,
        "notificationTargetInstallResult": 0,
        "notification2ABE73D8Prepared": True,
        "notification2ABE73D8Installed": True,
        "notificationBlockRestored": True,
        "notification2ABE73D8Restored": True,
        "notification2ABECallbackCount": 2,
        "notificationSetupResult": 0,
        "notificationACallbacks": 0,
        "notification2ABEAdapterRaw": "0x2abefe001018a05c",
        "notification73D8ReturnRaw": "0x73d8fe000fc55354",
        "result": "krw-notifier-2abe-73d8-dispatch-survived",
    })
    return report


def _check_multi_report() -> dict:
    report = _common_report()
    report.update({
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
        "ifnetPACCleanupResult": -1,
        "ifnetPACCleanupErrno": 0,
        "result": "krw-ifnet-check-multi-arbitrary-target-pac-executed",
    })
    return report


def _kcall1_report() -> dict:
    stock = "0xfffffe0007d293fc"
    load = "0xfffffe00082f6590"
    dispatcher = "0xfffffe0008f94a8c"
    got = "0xfffffe0007e1a0c0"
    stock_signed = "0x1a2bfe0007d293fc"
    original_x0 = "0xfffffe1000a00000"
    original_target = "0xfffffe1000a00100"
    report = _common_report()
    report.update({
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
    })
    return report


def _census_report() -> dict:
    records = [{
        "readResult": 0,
        "handlerTargetMatches": True,
        "listMalformed": False,
        "listCycle": False,
    } for _ in range(5)]
    return {
        "schema": "com.zeroxjf.cyanide.iouserethernet-krw-trigger",
        "schemaVersion": 1,
        "observedKernelBase": "0xfffffe0007004000",
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


FIXTURES = {
    MODULE.MODE_BORROW: _common_report,
    MODULE.MODE_TARGET_SWAP: _target_swap_report,
    MODULE.MODE_BLOCK_CANARY: _block_canary_report,
    MODULE.MODE_SANDBOX_CANARY: _sandbox_canary_report,
    MODULE.MODE_2ABE_73D8_CANARY: _pac_2abe_73d8_report,
    MODULE.MODE_CHECK_MULTI: _check_multi_report,
    MODULE.MODE_KCALL1: _kcall1_report,
    MODULE.MODE_SYSCTL_CENSUS: _census_report,
}


def _validate(mode: str, report: dict) -> dict:
    flag = MODULE.MODE_FLAGS[mode]
    return MODULE.validate_result(report, **({flag: True} if flag else {}))


def _pinned_for(mode: str) -> dict:
    pinned = {}
    if mode == MODULE.MODE_SYSCTL_CENSUS:
        pinned.update(MODULE.CENSUS_PINNED)
        return pinned
    pinned.update(MODULE.COMMON_PINNED)
    pinned.update({
        MODULE.MODE_BORROW: {},
        MODULE.MODE_TARGET_SWAP: MODULE.TARGET_SWAP_PINNED,
        MODULE.MODE_BLOCK_CANARY: MODULE.BLOCK_PINNED,
        MODULE.MODE_SANDBOX_CANARY: MODULE.SANDBOX_PINNED,
        MODULE.MODE_2ABE_73D8_CANARY: MODULE.PAC_2ABE_PINNED,
        MODULE.MODE_CHECK_MULTI: MODULE.CHECK_MULTI_PINNED,
        MODULE.MODE_KCALL1: MODULE.KCALL1_PINNED,
    }[mode])
    return pinned


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
        report = _common_report()
        self.assertIs(MODULE.validate_result(report), report)

    def test_validate_rejects_kcall(self) -> None:
        report = _common_report()
        report["providerOperations"] = ["Read", "Write", "KernelCall"]
        report["createdInterfaces"] = [{"bsdName": "cnd0"}]
        with self.assertRaises(MODULE.LabError):
            MODULE.validate_result(report)

    def test_validate_accepts_stock_notifier_target_swap(self) -> None:
        report = _target_swap_report()
        self.assertIs(
            MODULE.validate_result(
                report, require_notification_target_swap=True
            ),
            report,
        )

    def test_validate_accepts_restored_block_canary(self) -> None:
        report = _block_canary_report()
        self.assertIs(
            MODULE.validate_result(
                report, require_notification_block_canary=True
            ),
            report,
        )

    def test_validate_accepts_restored_sandbox_canary(self) -> None:
        report = _sandbox_canary_report()
        self.assertIs(
            MODULE.validate_result(
                report, require_notification_sandbox_canary=True
            ),
            report,
        )

    def test_validate_accepts_restored_2abe_73d8_canary(self) -> None:
        report = _pac_2abe_73d8_report()
        self.assertIs(
            MODULE.validate_result(
                report, require_notification_2abe_73d8_canary=True
            ),
            report,
        )

    def test_validate_accepts_read_only_sysctl_pac_census(self) -> None:
        report = _census_report()
        self.assertIs(
            MODULE.validate_result(report, require_sysctl_pac_census=True),
            report,
        )

    def test_validate_accepts_ifnet_check_multi_pac_canary(self) -> None:
        report = _check_multi_report()
        self.assertIs(
            MODULE.validate_result(
                report, require_ifnet_check_multi_pac_canary=True
            ),
            report,
        )

    def _ifnet_kcall1_report(self) -> dict:
        return _kcall1_report()

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

    # ------------------------------------------------------------ round 5

    def test_report_check_helpers_enforce_presence_and_exact_type(
            self) -> None:
        where = "helper"
        value = {"s": "x", "i": 1, "z": 0, "b": True, "f": False, "e": ""}
        self.assertEqual(MODULE.require_str(value, "s", where), "x")
        self.assertEqual(MODULE.require_int(value, "i", where), 1)
        self.assertIs(MODULE.require_bool(value, "b", where), True)
        for key, helper in (
                ("missing", MODULE.require_str),
                ("missing", MODULE.require_int),
                ("missing", MODULE.require_bool),
                ("e", MODULE.require_str),
                ("i", MODULE.require_str),
                ("s", MODULE.require_int),
                ("b", MODULE.require_int),   # True is not 1
                ("f", MODULE.require_int),   # False is not 0
                ("i", MODULE.require_bool),  # 1 is not True
                ("z", MODULE.require_bool),  # 0 is not False
        ):
            with self.subTest(key=key, helper=helper.__name__):
                with self.assertRaisesRegex(
                        MODULE.LabError,
                        f"helper field missing or mistyped: {key}"):
                    helper(value, key, where)
        self.assertIs(
            MODULE.require_int(value, "b", where, bool_is_error=False), True)
        with self.assertRaisesRegex(
                MODULE.LabError, "helper invariant failed: i"):
            MODULE.require_int(value, "i", where, expected=2)
        with self.assertRaisesRegex(
                MODULE.LabError, "helper invariant failed: z"):
            MODULE.require_int(value, "z", where, minimum=1)
        with self.assertRaisesRegex(
                MODULE.LabError, "helper invariant failed: b"):
            MODULE.require_bool(value, "b", where, expected=False)
        with self.assertRaisesRegex(
                MODULE.LabError, "helper invariant failed: s"):
            MODULE.require_str(value, "s", where, expected="y")

    def test_bound_equals_rejects_absent_pair_and_type_crossing(
            self) -> None:
        where = "helper"
        MODULE.bound_equals({"a": "0x1", "b": "0x1"}, "a", "b", where)
        MODULE.bound_equals({"a": 36, "b": 36}, "a", "b", where)
        with self.assertRaisesRegex(
                MODULE.LabError, "helper field missing or mistyped: a"):
            MODULE.bound_equals({}, "a", "b", where)
        with self.assertRaisesRegex(
                MODULE.LabError, "helper field missing or mistyped: b"):
            MODULE.bound_equals({"a": "0x1"}, "a", "b", where)
        with self.assertRaisesRegex(
                MODULE.LabError, "helper a did not match b"):
            MODULE.bound_equals({"a": "0x1", "b": "0x2"}, "a", "b", where)
        with self.assertRaisesRegex(MODULE.LabError, "custom"):
            MODULE.bound_equals({"a": 1, "b": "1"}, "a", "b", where,
                                message="custom")
        with self.assertRaisesRegex(
                MODULE.LabError, "helper field missing or mistyped: a"):
            MODULE.bound_equals({"a": True, "b": True}, "a", "b", where)

    def test_distinct_members_and_no_contradiction_helpers(self) -> None:
        where = "helper"
        keys = {"One": "k1", "Two": "k2"}
        value = {"k1": "a", "k2": "b"}
        self.assertEqual(
            MODULE.distinct_members(value, keys, where, created={"a", "b"},
                                    plural="names", singular="name"),
            ["a", "b"])
        with self.assertRaisesRegex(
                MODULE.LabError, "helper names are not distinct"):
            MODULE.distinct_members({"k1": "a", "k2": "a"}, keys, where,
                                    plural="names")
        with self.assertRaisesRegex(
                MODULE.LabError, "helper Two name was not created"):
            MODULE.distinct_members(value, keys, where, created={"a"},
                                    singular="name")
        with self.assertRaisesRegex(
                MODULE.LabError, "helper field missing or mistyped: k2"):
            MODULE.distinct_members({"k1": "a"}, keys, where)
        pairs = [("flag", True, "code", 0)]
        MODULE.no_contradiction({"flag": True, "code": 0}, pairs, where)
        MODULE.no_contradiction({"flag": False, "code": 7}, pairs, where)
        MODULE.no_contradiction({"flag": True}, pairs, where)  # absent
        MODULE.no_contradiction({"flag": 1, "code": 7}, pairs, where)
        with self.assertRaisesRegex(
                MODULE.LabError, "helper flag contradicts code"):
            MODULE.no_contradiction({"flag": True, "code": 7}, pairs, where)
        with self.assertRaisesRegex(
                MODULE.LabError, "helper flag contradicts code"):
            MODULE.no_contradiction(
                {"flag": True, "code": False}, pairs, where)

    def test_every_mode_accepts_its_fixture_and_requires_its_keys(
            self) -> None:
        """Class 5: required keys derive from the validator's own tables and
        every one must be (a) in the fixture and (b) a literal the producer
        emits. Implemented-level: the .m is read as text, not executed."""
        source = MODULE.TRIGGER_SOURCE.read_text()
        literals = set(re.findall(r'@"([A-Za-z0-9.-]+)"', source))
        stage_prefixes = {f"ifnetKCall1{stage}"
                          for stage in MODULE.KCALL1_STAGES}
        self.assertTrue(stage_prefixes <= literals)

        def emitted(key: str) -> bool:
            if key in literals:
                return True
            return any(key.startswith(prefix) and
                       key[len(prefix):] in literals
                       for prefix in stage_prefixes)

        for mode in MODULE.MODES:
            with self.subTest(mode=mode):
                fixture = FIXTURES[mode]()
                self.assertIs(_validate(mode, fixture), fixture)
                required = MODULE.required_report_keys(mode)
                self.assertEqual(sorted(required - fixture.keys()), [])
                self.assertIn(MODULE.MODE_RESULTS[mode], literals)
                paired = MODULE.contradiction_keys(mode)
                for key in sorted(required | paired):
                    self.assertTrue(emitted(key),
                                    f"{mode}: producer never emits {key}")
                for key in sorted(required):
                    report = FIXTURES[mode]()
                    del report[key]
                    with self.assertRaises(MODULE.LabError, msg=key):
                        _validate(mode, report)

    def test_every_mode_rejects_bool_int_crossing_on_pinned_keys(
            self) -> None:
        """Class 2 across all eight modes: True must not pass as 1 and 0
        must not pass as False on any pinned key."""
        for mode in MODULE.MODES:
            for key, expected in _pinned_for(mode).items():
                if isinstance(expected, bool):
                    crossed = int(expected)
                elif isinstance(expected, int) and expected in (0, 1):
                    crossed = bool(expected)
                else:
                    continue
                with self.subTest(mode=mode, key=key):
                    report = FIXTURES[mode]()
                    report[key] = crossed
                    with self.assertRaisesRegex(
                            MODULE.LabError,
                            f"field missing or mistyped: {key}"):
                        _validate(mode, report)

    def test_counts_reject_bool_and_zero(self) -> None:
        """Class 2 on the former isinstance(x, int) checks (B and E)."""
        cases = (
            (MODULE.MODE_TARGET_SWAP, MODULE.TARGET_SWAP_COUNTS),
            (MODULE.MODE_2ABE_73D8_CANARY, MODULE.PAC_2ABE_COUNTS),
        )
        for mode, keys in cases:
            for key in keys:
                with self.subTest(mode=mode, key=key):
                    report = FIXTURES[mode]()
                    report[key] = True
                    with self.assertRaisesRegex(
                            MODULE.LabError,
                            f"field missing or mistyped: {key}"):
                        _validate(mode, report)
                    report = FIXTURES[mode]()
                    report[key] = 0
                    with self.assertRaisesRegex(
                            MODULE.LabError, f"invariant failed: {key}"):
                        _validate(mode, report)

    def test_bound_pairs_reject_absence_on_both_sides(self) -> None:
        """Class 1 on the target-swap and check-multi pairs: both keys
        absent used to satisfy `.get(a) != .get(b)`."""
        cases = (
            (MODULE.MODE_TARGET_SWAP, MODULE.TARGET_SWAP_BOUND),
            (MODULE.MODE_CHECK_MULTI, MODULE.CHECK_MULTI_BOUND),
        )
        for mode, (key_a, key_b) in cases:
            with self.subTest(mode=mode):
                report = FIXTURES[mode]()
                del report[key_a]
                del report[key_b]
                self.assertEqual(report.get(key_a), report.get(key_b))
                with self.assertRaisesRegex(
                        MODULE.LabError,
                        f"field missing or mistyped: {key_a}"):
                    _validate(mode, report)
                report = FIXTURES[mode]()
                report[key_b] = "0x0000000000009999"
                with self.assertRaises(MODULE.LabError):
                    _validate(mode, report)

    def test_common_block_rejects_absent_provider_operations_and_baseline(
            self) -> None:
        """Class 1 in Common: absent providerOperations defaulted to [] and
        absent baselineOpenKR compared unequal to the zero string."""
        report = _common_report()
        del report["providerOperations"]
        with self.assertRaisesRegex(
                MODULE.LabError,
                "field missing or mistyped: providerOperations"):
            MODULE.validate_result(report)
        report = _common_report()
        report["providerOperations"] = "Read"
        with self.assertRaises(MODULE.LabError):
            MODULE.validate_result(report)
        report = _common_report()
        del report["baselineOpenKR"]
        with self.assertRaisesRegex(
                MODULE.LabError, "field missing or mistyped: baselineOpenKR"):
            MODULE.validate_result(report)
        report = _common_report()
        report["baselineOpenKR"] = "0x0000000000000000"
        with self.assertRaisesRegex(
                MODULE.LabError, "baseline was already authorized"):
            MODULE.validate_result(report)

    def test_observed_kernel_base_missing_is_lab_error_in_every_mode(
            self) -> None:
        for mode in MODULE.MODES:
            with self.subTest(mode=mode):
                report = FIXTURES[mode]()
                del report["observedKernelBase"]
                with self.assertRaisesRegex(
                        MODULE.LabError,
                        "field missing or mistyped: observedKernelBase"):
                    _validate(mode, report)
                report = FIXTURES[mode]()
                report["observedKernelBase"] = ""
                with self.assertRaises(MODULE.LabError):
                    _validate(mode, report)

    def test_census_records_reject_bool_int_crossing(self) -> None:
        for key, expected in MODULE.CENSUS_RECORD_PINNED.items():
            with self.subTest(key=key):
                report = _census_report()
                report["sysctlPACRecords"][2][key] = (
                    int(expected) if isinstance(expected, bool)
                    else bool(expected))
                with self.assertRaisesRegex(
                        MODULE.LabError,
                        f"sysctl PAC census record field missing or "
                        f"mistyped: {key}"):
                    _validate(MODULE.MODE_SYSCTL_CENSUS, report)
        report = _census_report()
        report["sysctlPACRecords"].pop()
        with self.assertRaisesRegex(
                MODULE.LabError, "records failed validation"):
            _validate(MODULE.MODE_SYSCTL_CENSUS, report)

    def test_declared_contradictions_fire_only_when_both_sides_present(
            self) -> None:
        """Class 4 pairs as declared by the audit: Installed => InstallResult
        == 0 (B/C/D/E) and TriggerResult == -1 => CleanupResult == -1 (F/G).
        An absent paired key is accepted by design (permissive rule)."""
        for mode, pairs in MODULE.INSTALL_CONTRADICTION.items():
            for key_a, _, key_b, expected_b in pairs:
                with self.subTest(mode=mode, pair=(key_a, key_b)):
                    report = FIXTURES[mode]()
                    self.assertIn(key_b, report)
                    report[key_b] = expected_b + 5
                    with self.assertRaisesRegex(
                            MODULE.LabError,
                            f"{key_a} contradicts {key_b}"):
                        _validate(mode, report)
                    report = FIXTURES[mode]()
                    report[key_b] = bool(expected_b) if expected_b in (0, 1) \
                        else str(expected_b)
                    with self.assertRaises(MODULE.LabError):
                        _validate(mode, report)
                    report = FIXTURES[mode]()
                    del report[key_b]
                    self.assertIs(_validate(mode, report), report)

    # ------------------------------------------ KDP correlation seams (C/D/E)
    # Pure functions over synthetic reports: implemented-level only. They
    # say the inputs agree; they are not a VM witness.

    def test_block_canary_correlation_extracts_and_matches(self) -> None:
        report = _block_canary_report()
        block = 0xFFFFFE000FA59288
        invoke = 0xFFFFFE00113BAC64
        self.assertEqual(
            MODULE.block_canary_correlation(report),
            (0xFFFFFE1000002000, block, invoke, [0xFFFFFE1000001000]),
        )
        registers = {"pc": invoke, "x0": block, "x1": 0xFFFFFE1000001000,
                     "x2": 0xFFFFFE1000002000}
        transcript = "stop reason = breakpoint\nProcess 1 detached\n"
        witness = MODULE.block_canary_witness(
            report, registers, transcript, block=block, invoke=invoke,
            debugger_exit=0)
        self.assertEqual(witness["newService"], "0xfffffe1000001000")
        self.assertEqual(witness["notifier"], "0xfffffe1000002000")
        self.assertEqual(witness["liveBlock"], "0xfffffe000fa59288")
        bad = [
            dict(registers, x2=0xFFFFFE1000002008),
            dict(registers, x1=0xFFFFFE1000009000),
            dict(registers, x0=block + 8),
        ]
        for wrong in bad:
            with self.assertRaisesRegex(
                    MODULE.LabError, "did not match the trigger"):
                MODULE.block_canary_witness(
                    report, wrong, transcript, block=block, invoke=invoke,
                    debugger_exit=0)
        with self.assertRaisesRegex(
                MODULE.LabError, "did not match the trigger"):
            MODULE.block_canary_witness(
                report, registers, transcript, block=block, invoke=invoke,
                debugger_exit=1)
        with self.assertRaisesRegex(
                MODULE.LabError, "did not match the trigger"):
            MODULE.block_canary_witness(
                report, registers, "stop reason = breakpoint\n",
                block=block, invoke=invoke, debugger_exit=0)
        duplicated = _block_canary_report()
        duplicated["createdInterfaces"].append(
            dict(duplicated["createdInterfaces"][0], bsdName="cnd1"))
        with self.assertRaisesRegex(
                MODULE.LabError, "did not match the trigger"):
            MODULE.block_canary_witness(
                duplicated, registers, transcript, block=block,
                invoke=invoke, debugger_exit=0)
        missing = _block_canary_report()
        del missing["notificationBlockAddress"]
        with self.assertRaisesRegex(
                MODULE.LabError, "omitted its KDP correlation fields"):
            MODULE.block_canary_correlation(missing)
        self.assertEqual(
            MODULE.created_kernel_objects(
                {"createdInterfaces": [{"kernelObject": "zz"}, 3, {}]}),
            [])

    def test_sandbox_canary_correlation_extracts_and_matches(self) -> None:
        report = _sandbox_canary_report()
        callback = 0xFFFFFE00113AE0D8
        action = 0xFFFFFE0011398E6C
        self.assertEqual(
            MODULE.sandbox_canary_correlation(report),
            (0xFFFFFE1000002000, 0x1A2BFE0011398E6C, callback,
             [0xFFFFFE1000001000]),
        )
        registers = {"pc": callback, "x0": 0xFFFFFE1000001000, "x1": 0,
                     "x2": 0xFFFFFE1000001000, "x3": 0xFFFFFE1000002000}
        transcript = "stop reason = breakpoint\nProcess 1 detached\n"
        witness = MODULE.sandbox_canary_witness(
            report, registers, transcript, action=action,
            callback=callback, debugger_exit=0)
        self.assertEqual(witness["rawSignedAction"], "0x1a2bfe0011398e6c")
        self.assertEqual(witness["newService"], "0xfffffe1000001000")
        for wrong in (dict(registers, x1=1),
                      dict(registers, x2=0xFFFFFE1000001008),
                      dict(registers, x3=0),
                      dict(registers, pc=callback + 4)):
            with self.assertRaisesRegex(
                    MODULE.LabError, "did not match the trigger"):
                MODULE.sandbox_canary_witness(
                    report, wrong, transcript, action=action,
                    callback=callback, debugger_exit=0)
        zero_action = _sandbox_canary_report()
        zero_action["notificationSandboxActionRaw"] = "0x0"
        with self.assertRaisesRegex(
                MODULE.LabError, "did not match the trigger"):
            MODULE.sandbox_canary_witness(
                zero_action, registers, transcript, action=action,
                callback=callback, debugger_exit=0)
        missing = _sandbox_canary_report()
        missing["notificationSandboxCallback"] = "not-hex"
        with self.assertRaisesRegex(
                MODULE.LabError, "omitted its KDP correlation fields"):
            MODULE.sandbox_canary_correlation(missing)

    def test_2abe_73d8_correlation_strips_and_matches(self) -> None:
        report = _pac_2abe_73d8_report()
        adapter = 0xFFFFFE001018A05C
        return_target = 0xFFFFFE000FC55354
        self.assertEqual(
            MODULE.pac_2abe_73d8_correlation(report),
            (adapter, return_target, [0xFFFFFE1000001000]),
        )
        registers = {"pc": return_target, "x1": 0xFFFFFE1000001000,
                     "x2": 0x73D8FE000FC55354}
        transcript = "stop reason = breakpoint\nProcess 1 detached\n"
        witness = MODULE.pac_2abe_73d8_witness(
            report, registers, transcript, adapter=adapter,
            return_target=return_target, debugger_exit=0)
        self.assertEqual(witness["liveReturn"], "0xfffffe000fc55354")
        self.assertEqual(witness["liveAdapter"], "0xfffffe001018a05c")
        for wrong in (dict(registers, x2=0x73D8FE000FC55358),
                      dict(registers, x1=0xFFFFFE1000001008),
                      dict(registers, pc=return_target + 4)):
            with self.assertRaisesRegex(
                    MODULE.LabError, "did not match the trigger"):
                MODULE.pac_2abe_73d8_witness(
                    report, wrong, transcript, adapter=adapter,
                    return_target=return_target, debugger_exit=0)
        with self.assertRaisesRegex(
                MODULE.LabError, "did not match the trigger"):
            MODULE.pac_2abe_73d8_witness(
                report, registers, transcript, adapter=adapter + 4,
                return_target=return_target, debugger_exit=0)
        missing = copy.deepcopy(report)
        del missing["notification2ABEAdapterRaw"]
        with self.assertRaisesRegex(
                MODULE.LabError, "omitted signed-pointer evidence"):
            MODULE.pac_2abe_73d8_correlation(missing)

    # ------------------------------------------------------------ round 6

    def test_producer_constants_match_cited_source_lines(self) -> None:
        """Class 3: every pinned literal lives once, in PRODUCER_CONSTANTS,
        and its cited .m line really holds the anchor text. Direct entries
        are the same literal on both sides; derived entries are checked
        against what the note says they are tied to. Implemented-level:
        text against text, same pattern as the source-grep test below."""
        lines = MODULE.TRIGGER_SOURCE.read_text().splitlines()
        py_source = MODULE_PATH.read_text()
        # Everything outside the PRODUCER_CONSTANTS block must be free of
        # the literals; inside it a value and its anchor may both appear.
        block_start = py_source.index("PRODUCER_CONSTANTS: dict")
        block_end = py_source.index("def _hex(")
        outside = py_source[:block_start] + py_source[block_end:]
        table = MODULE.PRODUCER_CONSTANTS
        self.assertGreaterEqual(len(table), 30)
        for name, constant in table.items():
            with self.subTest(name=name):
                self.assertIs(getattr(MODULE, name), constant.value) \
                    if isinstance(constant.value, str) else \
                    self.assertEqual(getattr(MODULE, name), constant.value)
                for line in constant.lines:
                    self.assertIn(constant.anchor, lines[line - 1],
                                  f"{name}: .m:{line} lost its anchor")
                if not constant.direct:
                    continue
                anchor = constant.anchor
                if match := re.fullmatch(
                        r"(?:UINT64_C\()?(0x[0-9a-f]+)\)?", anchor):
                    self.assertEqual(int(match.group(1), 16), constant.value)
                elif match := re.fullmatch(r'@"(.*)"', anchor):
                    self.assertEqual(match.group(1), constant.value)
                elif match := re.fullmatch(r"@(\d+)", anchor):
                    self.assertEqual(int(match.group(1)), constant.value)
                else:
                    self.fail(f"{name}: unrecognised direct anchor {anchor}")
                # The literal must not be spelled anywhere else in the .py.
                if isinstance(constant.value, str):
                    pattern = re.escape(f'"{constant.value}"')
                elif constant.value >= 0x1000:
                    pattern = rf"0x0*{constant.value:x}\b"
                else:
                    continue  # 1 is not a traceable literal
                self.assertEqual(
                    re.findall(pattern, outside, re.IGNORECASE), [],
                    f"{name}: literal spelled outside PRODUCER_CONSTANTS")

        # Derived entries: tied to what the note names, not to a literal.
        self.assertEqual(MODULE.STATIC_TEXT,
                         MODULE.STATIC_KERNEL_BASE + MODULE.STATIC_PAGE_SIZE)
        self.assertEqual(MODULE.ZERO_KR, f"0x{0:016x}")
        self.assertIn("%016", table["ZERO_KR"].anchor)
        for stage, name in ((MODULE.KCALL1_STAGE_STOCK, "KCALL1_STAGE_STOCK"),
                            (MODULE.KCALL1_STAGE_LOAD, "KCALL1_STAGE_LOAD"),
                            (MODULE.KCALL1_STAGE_DISPATCHER,
                             "KCALL1_STAGE_DISPATCHER")):
            self.assertTrue(table[name].anchor.endswith(f'{stage}"'))
        # Candidate count = initialisers between the anchor and the `};`.
        first = table["CENSUS_CANDIDATE_COUNT"].lines[0]
        body = []
        for line in lines[first:]:
            if line.strip() == "};":
                break
            body.append(line)
        self.assertEqual(
            sum(1 for line in body if line.strip().startswith('{"')),
            MODULE.CENSUS_CANDIDATE_COUNT)
        # xpaci masks: the .m holds the instruction, not a mask; the two
        # halves must at least partition the word.
        self.assertEqual(MODULE.XPACI_ADDRESS_BITS ^ MODULE.XPACI_KERNEL_FILL,
                         0xFFFFFFFFFFFFFFFF)
        # errno values: the producer uses symbols; Darwin's header is the
        # source and the host errno module agrees only on Darwin.
        if sys.platform == "darwin":
            self.assertEqual(errno.ENOEXEC, MODULE.ENOEXEC_VALUE)
            self.assertEqual(errno.EINPROGRESS, MODULE.EINPROGRESS_VALUE)
        # The tables read from the one source.
        self.assertIs(MODULE.CHECK_MULTI_PINNED["ifnetPACDiscriminator"],
                      MODULE.CHECK_MULTI_DISCRIMINATOR)
        self.assertEqual(MODULE.CHECK_MULTI_PINNED["ifnetPACTriggerErrno"],
                         MODULE.ENOEXEC_VALUE)
        self.assertEqual(MODULE.KCALL1_PINNED["ifnetKCall1TriggerErrno"],
                         MODULE.EINPROGRESS_VALUE)
        self.assertEqual(MODULE.CENSUS_RECORD_COUNT,
                         MODULE.CENSUS_CANDIDATE_COUNT)
        self.assertEqual(set(MODULE.MODE_RESULTS.values()),
                         {c.value for n, c in table.items()
                          if n.startswith("RESULT_")})

    def test_sandbox_witness_rejects_raw_action_that_strips_elsewhere(
            self) -> None:
        """D strip-compare: notificationSandboxActionRaw must strip to the
        live action (producer predicate .m:771, .m:1172-1173). Implemented-
        level; synthetic report."""
        report = _sandbox_canary_report()
        callback = 0xFFFFFE00113AE0D8
        action = 0xFFFFFE0011398E6C
        registers = {"pc": callback, "x0": 0xFFFFFE1000001000, "x1": 0,
                     "x2": 0xFFFFFE1000001000, "x3": 0xFFFFFE1000002000}
        transcript = "stop reason = breakpoint\nProcess 1 detached\n"
        self.assertEqual(
            MODULE._code_pointer(int(report["notificationSandboxActionRaw"],
                                     16)), action)
        MODULE.sandbox_canary_witness(
            report, registers, transcript, action=action,
            callback=callback, debugger_exit=0)
        report["notificationSandboxActionRaw"] = "0x1a2bfe0011398e70"
        with self.assertRaisesRegex(
                MODULE.LabError,
                "raw signed action did not strip to the live action"):
            MODULE.sandbox_canary_witness(
                report, registers, transcript, action=action,
                callback=callback, debugger_exit=0)

    def test_parse_2abe_backtrace_present_absent_corrupt(self) -> None:
        """E backtrace parse: capability only, not wired into any witness.
        Whether the adapter frame appears in a real run is a .m-owner/VM
        question; these transcripts are synthetic."""
        adapter = 0xFFFFFE001018A05C
        present = (
            "* thread #1, stop reason = breakpoint 1.1\n"
            "  * frame #0: 0xfffffe000fc55354\n"
            "    frame #1: 0x2abefe001018a070\n"
            "    frame #2: 0xfffffe0010000000\n"
        )
        self.assertEqual(
            MODULE.parse_2abe_backtrace(present, adapter),
            {"frame": 1, "pc": "0xfffffe001018a070",
             "raw": "0x2abefe001018a070"})
        self.assertIsNone(
            MODULE.parse_2abe_backtrace(present, adapter, span=0x10))
        absent = (
            "  * frame #0: 0xfffffe000fc55354\n"
            "    frame #1: 0xfffffe0010000000\n"
        )
        self.assertIsNone(MODULE.parse_2abe_backtrace(absent, adapter))
        self.assertIsNone(MODULE.parse_2abe_backtrace("", adapter))
        corrupt = (
            "    frame #x: 0xfffffe001018a060\n"
            "    frame #1: not-an-address\n"
            "    frame 2: 0xfffffe001018a060\n"
            "    frame #3: 0xfffffe001018a064 trailing text\n"
        )
        self.assertEqual(
            MODULE.parse_2abe_backtrace(corrupt, adapter)["frame"], 3)
        # Not consulted by the witness: a transcript without any frames
        # still correlates exactly as before.
        report = _pac_2abe_73d8_report()
        registers = {"pc": 0xFFFFFE000FC55354, "x1": 0xFFFFFE1000001000,
                     "x2": 0x73D8FE000FC55354}
        witness = MODULE.pac_2abe_73d8_witness(
            report, registers,
            "stop reason = breakpoint\nProcess 1 detached\n",
            adapter=adapter, return_target=0xFFFFFE000FC55354,
            debugger_exit=0)
        self.assertNotIn("adapterFrame", witness)

    def test_driver_conclusions_claim_nothing_above_implemented_without_kdp(
            self) -> None:
        """Claim rewording: modes without a KDP witness say implemented and
        never VM-proved; KDP modes scope VM-proved to the attached witness;
        no mode claims physical. Also checks the argparse-to-mode seam."""
        for mode in MODULE.MODES:
            text = MODULE.conclusion_for(mode)
            with self.subTest(mode=mode):
                self.assertNotIn("physical-proved", text)
                if mode in MODULE.KDP_WITNESS_MODES:
                    self.assertIn("VM-proved for exactly the attached "
                                  "kdpWitness", text)
                else:
                    self.assertNotIn("VM-proved", text)
                    self.assertIn("Level: implemented", text)
                attribute = MODULE.MODE_ARGS[mode]
                namespace = argparse.Namespace(**{
                    name: name == attribute
                    for name in MODULE.MODE_ARGS.values() if name})
                self.assertEqual(MODULE._mode_from_args(namespace), mode)
        self.assertEqual(MODULE.KDP_WITNESS_MODES, {
            MODULE.MODE_BLOCK_CANARY, MODULE.MODE_SANDBOX_CANARY,
            MODULE.MODE_2ABE_73D8_CANARY})
        self.assertIn("errno propagation",
                      MODULE.conclusion_for(MODULE.MODE_KCALL1))
        self.assertIn("not an arbitrary one",
                      MODULE.conclusion_for(MODULE.MODE_CHECK_MULTI))
        two = argparse.Namespace(notification_target_swap=True,
                                 sysctl_pac_census=True)
        with self.assertRaises(MODULE.LabError):
            MODULE._mode_from_args(two)

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
