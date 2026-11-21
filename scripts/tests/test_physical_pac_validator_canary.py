import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Cyanide/probes/CNDPhysicalPACIdentityCanary.m"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"
APP_DELEGATE = ROOT / "Cyanide/AppDelegate.m"


class PhysicalPACValidatorCanaryTests(unittest.TestCase):
    def test_canary_is_exact_target_read_only_krw(self) -> None:
        source = SOURCE.read_text()
        self.assertIn('CND_PAC_CANARY_PRODUCT "iPhone17,2"', source)
        self.assertIn('CND_PAC_CANARY_BUILD "23A341"', source)
        self.assertIn('@"kernelReadUsed": @YES', source)
        self.assertIn('@"kernelWriteUsed": @NO', source)
        self.assertIn('@"kernelCallUsed": @NO', source)
        self.assertNotIn("kwrite", source)

    def test_canary_checks_physical_saved_state_layout(self) -> None:
        source = SOURCE.read_text()
        for token in (
            "CND_PAC_CANARY_THREAD_CONTEXT_DATA_OFFSET UINT32_C(0x100)",
            "CND_PAC_CANARY_THREAD_UPCB_OFFSET UINT32_C(0x108)",
            "CND_PAC_CANARY_SAVED_STATE_X16_OFFSET UINT32_C(0x88)",
            "CND_PAC_CANARY_SAVED_STATE_X17_OFFSET UINT32_C(0x90)",
            "CND_PAC_CANARY_SAVED_STATE_PC_OFFSET UINT32_C(0x108)",
            "CND_PAC_CANARY_SAVED_STATE_JOP_HASH_OFFSET UINT32_C(0x128)",
        ):
            self.assertIn(token, source)
        self.assertIn("snapshot->contextData != snapshot->savedState", source)
        self.assertIn("snapshot->uNeon != snapshot->savedState +", source)

    def test_resume_gate_captures_before_any_post_resume_syscall(self) -> None:
        source = SOURCE.read_text()
        resumed = source.index("resumed:\n    __asm__ volatile(")
        captured = source.index('"stp x16, x17', resumed)
        released = source.index('"cbz w9, 1b', captured)
        function_return = source.index("return NULL;", released)
        self.assertLess(resumed, captured)
        self.assertLess(captured, released)
        self.assertLess(released, function_return)
        self.assertIn('@"postResumeSyscallBeforeSnapshot": @NO', source)

    def test_success_requires_saved_state_and_resumed_tuple(self) -> None:
        source = SOURCE.read_text()
        self.assertIn("beforeSnapshot.jopHash != afterSnapshot.jopHash", source)
        self.assertIn("afterSnapshot.x16 == CND_PAC_CANARY_VALIDATOR_X16", source)
        self.assertIn("resumeGate.resumedX16 == CND_PAC_CANARY_VALIDATOR_X16", source)
        self.assertIn("physicalValidatorConsumption", source)
        self.assertIn("exactPhysicalPACValidatorCanary", source)
        self.assertIn("CNDPhysicalPACValidatorCanary.json", source)

    def test_saved_state_pc_must_be_in_exact_no_syscall_spin(self) -> None:
        source = SOURCE.read_text()
        self.assertIn(
            "CND_PAC_CANARY_RESUME_SPIN_LDAR_OFFSET UINT64_C(0x14)",
            source,
        )
        self.assertIn(
            "CND_PAC_CANARY_RESUME_SPIN_CBZ_OFFSET UINT64_C(0x18)",
            source,
        )
        self.assertIn("savedStatePCInResumeSpin", source)
        self.assertIn('@"savedStateResumePCOffset"', source)
        self.assertNotIn(
            "(afterSnapshot.pc & CND_PAC_CANARY_USER_POINTER_MASK) ==\n"
            "            ready.resumePC",
            source,
        )

    def test_launch_argument_runs_without_settings_button(self) -> None:
        app_delegate = APP_DELEGATE.read_text()
        settings = SETTINGS.read_text()
        self.assertIn('--physical-pac-validator', app_delegate)
        self.assertIn("settings_run_physical_pac_identity_canary_action();",
                      app_delegate)
        self.assertIn("void settings_run_physical_pac_identity_canary_action",
                      settings)


if __name__ == "__main__":
    unittest.main()
