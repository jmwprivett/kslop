"""Contracts for the bounded physical CC Theming mutation gate."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class CCThemingApplyRestoreCanaryTests(unittest.TestCase):
    def read(self, relative_path: str) -> str:
        return (ROOT / relative_path).read_text(encoding="utf-8")

    def test_mutation_is_isolated_from_the_read_only_inventory(self) -> None:
        probe = self.read("Cyanide/tweaks/CNDCCThemingProbe.m")
        canary = self.read("Cyanide/tweaks/CNDCCThemingCanary.m")
        self.assertIn("CNDCCThemingResolveLiveTemplate", probe)
        self.assertIn(
            'CNDCCThemingResolveLiveTemplate(@"flashlight", &metadata)', canary
        )
        mutator_dispatch = re.compile(
            r"r_msg2(?:_main|_main_raw|_raw)?\s*\([^;]*"
            r'"(?:setGlyph|sendAction|buttonTapped|toggle|activate)',
            re.DOTALL,
        )
        self.assertIsNone(mutator_dispatch.search(probe))
        self.assertIn('"setGlyphImage:"', canary)
        self.assertIn('"setSelectedGlyphImage:"', canary)
        self.assertIn("CNDCCCanarySetAndVerify", canary)

    def test_canary_has_exact_abi_pid_readback_and_restore_guards(self) -> None:
        canary = self.read("Cyanide/tweaks/CNDCCThemingCanary.m")
        for contract in (
            '"glyphImage", "@16@0:8"',
            '"selectedGlyphImage", "@16@0:8"',
            '"setGlyphImage:", "v24@0:8@16"',
            '"setSelectedGlyphImage:", "v24@0:8@16"',
        ):
            self.assertIn(contract, canary)
        self.assertIn("targetPIDAtEntry = remote_call_current_pid()", canary)
        self.assertIn("remote_call_current_pid() == targetPIDAtEntry", canary)
        self.assertIn('target, "setGlyphImage:", "glyphImage", offImage', canary)
        self.assertIn(
            'target, "setSelectedGlyphImage:", "selectedGlyphImage", onImage',
            canary,
        )
        self.assertIn(
            'target, "setGlyphImage:", "glyphImage", originalImage', canary
        )
        self.assertIn("@\"rollbackAttempted\"", canary)
        self.assertIn("@\"restoreVerified\"", canary)
        self.assertIn("applyVerified && restoreVerified && pidStable", canary)

    def test_canary_does_not_invoke_controls_radios_or_target_file_apis(self) -> None:
        canary = self.read("Cyanide/tweaks/CNDCCThemingCanary.m")
        for forbidden in (
            "sendAction",
            "buttonTapped",
            "toggleState",
            "setTorchMode",
            "setEnabled:",
            "writeToFile",
            "createDirectoryAtURL",
            "NSFileManager",
        ):
            self.assertNotIn(forbidden, canary)
        self.assertIn('@"controlActions": @0', canary)
        self.assertIn('@"radioWrites": @0', canary)
        self.assertIn('@"targetFileWrites": @0', canary)

    def test_settings_exposes_delayed_physical_only_canary_and_report(self) -> None:
        settings = self.read("Cyanide/SettingsViewController.m")
        rows = settings.split("- (NSArray<NSDictionary *> *)ccThemingRows", 1)[1]
        rows = rows.split("- (NSArray<NSDictionary *> *)liveWPRows", 1)[0]
        self.assertIn('action": @"cc-theming-flashlight-canary"', rows)
        self.assertIn('action": @"cc-theming-share-canary"', rows)
        action = settings.split(
            "if (indexPath.section == SectionCCTheming)", 1
        )[1].split("if (indexPath.section == SectionFontChanger)", 1)[0]
        self.assertIn("settings_run_cc_theming_flashlight_apply_restore_canary", action)
        self.assertIn("5 * NSEC_PER_SEC", action)
        runner = settings.split(
            "static void settings_run_cc_theming_flashlight_apply_restore_canary", 1
        )[1].split("\n#if 0", 1)[0]
        self.assertIn("remote_call_lab_backend_opted_in()", runner)
        self.assertIn("cnd_lab_vphone_guest()", runner)
        self.assertIn("CNDCCThemingRunFlashlightApplyRestoreCanary", runner)
        self.assertIn("CNDPulsarFlashlightOffPNGData()", runner)
        self.assertIn("CNDPulsarFlashlightOnPNGData()", runner)
        self.assertIn("physical-apply-restore-canary.json", settings)


if __name__ == "__main__":
    unittest.main()
