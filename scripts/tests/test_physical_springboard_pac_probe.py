import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "Cyanide/CNDPhysicalSpringBoardPACProbe.m"
REMOTE_CALL = ROOT / "Cyanide/TaskRop/RemoteCall.m"
APP_DELEGATE = ROOT / "Cyanide/AppDelegate.m"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"
RX_PROBE = ROOT / "scripts/lab/cnd_physical_cs_allow_invalid_probe.m"


class PhysicalSpringBoardPACProbeTests(unittest.TestCase):
    def test_probe_is_exact_build_marker_only(self) -> None:
        source = PROBE.read_text()
        self.assertIn('CND_SPRINGBOARD_PAC_PRODUCT "iPhone17,2"', source)
        self.assertIn('CND_SPRINGBOARD_PAC_BUILD "23A341"', source)
        self.assertIn('CND_SPRINGBOARD_PAC_PROCESS "SpringBoard"', source)
        self.assertIn('@"markerFunction": @"getpid"', source)
        self.assertIn('@"kernelCallUsed": @NO', source)
        self.assertIn('@"dylibInjected": @NO', source)
        self.assertNotIn('"dlopen"', source)

    def test_probe_uses_proven_identity_krw_signer(self) -> None:
        source = PROBE.read_text()
        self.assertIn(
            "init_remote_call_identity_bootstrap_original_thread_only(",
            source,
        )
        self.assertIn("afterDispatch.identityConverterUnavailable", source)
        self.assertIn("afterDispatch.identityConversionFailures == 1", source)
        self.assertIn("afterDispatch.identityPACFallbackCount >= 3", source)
        self.assertIn("afterDispatch.identityPACFallbackFailures == 0", source)
        self.assertIn("uint64_t selfTask = task_self();", REMOTE_CALL.read_text())

    def test_cleanup_is_exact_self_kill_and_replacement_proof(self) -> None:
        source = PROBE.read_text()
        self.assertIn("remote_call_dispatch_self_sigkill(", source)
        self.assertIn("targetPID, targetProc, targetTask", source)
        self.assertIn("CNDSpringBoardPACWaitForReplacement(", source)
        self.assertIn("oldSpringBoardIdentityExited", source)
        self.assertIn("replacementSpringBoardObserved", source)
        self.assertIn("exceptionPolicyClearedByReplacement", source)
        self.assertIn("abandon_remote_call();", source)

    def test_headless_launch_action_is_wired(self) -> None:
        self.assertIn("--springboard-pac-probe", APP_DELEGATE.read_text())
        settings = SETTINGS.read_text()
        self.assertIn(
            "settings_run_physical_springboard_pac_probe_action", settings
        )
        self.assertIn("CNDPhysicalSpringBoardPACProbeRun(", settings)

    def test_existing_dylib_probe_uses_proven_springboard_transport(self) -> None:
        source = RX_PROBE.read_text()
        self.assertIn(
            'initWithIdentityBootstrapProcess:@"SpringBoard"', source
        )
        self.assertNotIn(
            'initWithProcess:@"SpringBoard"\n'
            "        useMigFilterBypass:NO\n"
            "        firstExceptionTimeoutMS:10000",
            source,
        )
        self.assertIn(
            "dispatchSelfSIGKILLForExpectedPID:pid", source
        )
        self.assertIn("identityStableBeforeCleanup && reset", source)
        self.assertIn('CNDRecord(@"springBoardFinalResetProven", @(reset))', source)

    def test_dylib_probe_uses_in_process_self_trace_without_amfi_borrow(self) -> None:
        source = RX_PROBE.read_text()
        self.assertIn('CNDRecord(@"amfiBorrowSkipped", @YES)', source)
        self.assertIn('CNDRecord(@"state", @"springboard-identity-self-trace")', source)
        self.assertIn('"ptrace",\n                            CND_PT_TRACE_ME', source)
        direct_probe = source.index(
            "bool injected = CNDRunSpringBoardDylibProbe("
        )
        baseline = source.index(
            'CNDRecord(@"baselineAttachDetachCompleted", @(attached))'
        )
        self.assertGreater(direct_probe, baseline)
        between = source[baseline:direct_probe]
        self.assertNotIn("CNDPrepareAMFIEntitlementBorrow", between)
        self.assertNotIn("if (!attached) return", between)

    def test_signed_vnode_boundary_is_not_gated_by_cs_debugged(self) -> None:
        source = RX_PROBE.read_text()
        start = source.index(
            'CNDRecord(@"signedVnodeAttemptWithoutCSDebugged"'
        )
        gate = source.rfind("if (!handle &&", 0, start)
        self.assertGreaterEqual(gate, 0)
        condition = source[gate:start]
        self.assertIn("pathWritten && executableGrantConsumed", condition)
        self.assertNotIn("selfTraceAllowed &&", condition)
        self.assertIn(
            '@"failed-springboard-signed-vnode-rx-denied"', source
        )


if __name__ == "__main__":
    unittest.main()
