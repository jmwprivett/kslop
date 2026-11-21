import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "Cyanide/probes/CNDPhysicalCalculatorPACProbe.m"
REMOTE_CALL = ROOT / "Cyanide/TaskRop/RemoteCall.m"
APP_DELEGATE = ROOT / "Cyanide/AppDelegate.m"


class PhysicalCalculatorPACProbeTests(unittest.TestCase):
    def test_probe_is_exact_physical_calculator_marker(self) -> None:
        source = PROBE.read_text()
        self.assertIn('CND_CALCULATOR_PAC_PRODUCT "iPhone17,2"', source)
        self.assertIn('CND_CALCULATOR_PAC_BUILD "23A341"', source)
        self.assertIn('CND_CALCULATOR_PAC_PROCESS "Calculator"', source)
        self.assertIn('CND_CALCULATOR_PAC_BUNDLE "com.apple.calculator"', source)
        self.assertIn('@"markerFunction": @"getpid"', source)
        self.assertIn('@"forgedTaskPortUsed": @NO', source)
        self.assertIn('@"kernelCallUsed": @NO', source)

    def test_identity_bootstrap_uses_one_kernel_minted_thread_right(self) -> None:
        source = REMOTE_CALL.read_text()
        self.assertIn("EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES", source)
        self.assertIn("remote_call_identity_request_is_valid", source)
        self.assertIn("identityThreadRightExact", source)
        self.assertIn("identityTaskRightExact", source)
        self.assertIn(
            "init_remote_call_configured(process, false, 1, nil)", source
        )
        self.assertIn("identity-oldest-main-first-with-fallback", source)
        self.assertIn("[candidateIndices addObject:@0]", source)

    def test_identity_thread_right_drives_converter_and_is_released(self) -> None:
        source = REMOTE_CALL.read_text()
        self.assertIn("thread_convert_sign_state_for_target(\n"
                      "                    g_RC_identityThreadPort", source)
        self.assertIn("g_RC_identityTaskPort", source)
        self.assertGreaterEqual(
            source.count("remote_call_release_identity_rights();"), 3
        )
        self.assertIn("g_RC_identityConversionFailures++", source)

    def test_identity_mode_uses_validated_executable_trap(self) -> None:
        source = REMOTE_CALL.read_text()
        self.assertIn("CND_RC_GETPID_TO_BRK1_DELTA", source)
        self.assertIn("CND_RC_BRK1_INSTRUCTION", source)
        self.assertIn("remote_call_resolve_identity_trap_address", source)
        self.assertIn("g_RC_identityTrapAddress", source)

    def test_handler_retains_identity_and_releases_duplicate_rights(self) -> None:
        source = REMOTE_CALL.read_text()
        self.assertIn("g_RC_identityHandlerRetained = true", source)
        self.assertIn("remote_call_wait_original_thread_exception", source)
        self.assertIn("remote_call_reply_original_thread_exception", source)
        self.assertIn("uint64_t selfTask = task_self();", source)
        self.assertNotIn(
            "task_get_ipc_port_kobject(\n"
            "        mach_task_self_, event->identityRequest", source
        )
        self.assertIn(
            "remote_call_release_identity_request_rights(\n"
            "        &event->identityRequest, false)", source
        )

    def test_success_requires_marker_restore_and_three_signing_operations(self) -> None:
        source = PROBE.read_text()
        self.assertIn("markerPID == (uint64_t)targetPID", source)
        self.assertIn("afterMarker.identityConversionCount +", source)
        self.assertIn("afterMarker.identityPACFallbackCount) >= 2", source)
        self.assertIn("afterRestore.identityConversionCount >= 3", source)
        self.assertIn("afterRestore.identityPACFallbackCount >= 3", source)
        self.assertIn("afterRestore.identityPACFallbackFailures == 0", source)
        self.assertIn("signerPathValid", source)
        self.assertIn("destroyResult == 0", source)
        self.assertIn("targetIdentityStable", source)

    def test_public_converter_rejection_uses_recorded_krw_pac_fallback(self) -> None:
        source = REMOTE_CALL.read_text()
        self.assertIn("g_RC_identityConverterUnavailable = true", source)
        self.assertIn("remote_pac(signingThread", source)
        self.assertIn("g_RC_identityPACFallbackCount++", source)
        self.assertIn("g_RC_identityPACFallbackFailures++", source)

    def test_launch_argument_is_headless(self) -> None:
        source = APP_DELEGATE.read_text()
        self.assertIn('--calculator-pac-probe', source)
        self.assertIn(
            "settings_run_physical_calculator_pac_probe_action();", source
        )


if __name__ == "__main__":
    unittest.main()
