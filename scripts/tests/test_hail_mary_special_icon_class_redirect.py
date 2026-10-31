#!/usr/bin/env python3
import json
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Cyanide" / "CNDHailMarySpecialIconClassRedirect.m"
HEADER = ROOT / "Cyanide" / "CNDHailMarySpecialIconClassRedirect.h"
SETTINGS = ROOT / "Cyanide" / "SettingsViewController.m"
SETTINGS_HEADER = ROOT / "Cyanide" / "SettingsViewController.h"
APP_DELEGATE = ROOT / "Cyanide" / "AppDelegate.m"
MANIFEST = (ROOT / "docs" / "research" /
            "special-icon-class-got-redirect-23A341-iphone17,2.json")
LEGACY_WRITER = ROOT / "Cyanide" / "CNDHailMaryImpRedirect.m"
LEGACY_PROBE = ROOT / "Cyanide" / "CNDHailMaryReadOnlyDataPage.m"


class HailMarySpecialIconClassRedirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()
        cls.header = HEADER.read_text()
        cls.manifest = json.loads(MANIFEST.read_text())

    def test_constants_match_the_offline_manifest(self):
        def canonical(value):
            return f"0x{int(value, 16):x}"

        source_hex = {
            canonical(token)
            for token in re.findall(r"0x[0-9a-fA-F]+", self.source)
        }
        for target in self.manifest["targets"]:
            for token in (
                target["slotUnslid"],
                target["originalClassUnslid"],
                target["redirectedClassUnslid"],
                target["classCacheSlotUnslid"],
            ):
                self.assertIn(canonical(token), source_hex, token)
        replacement = self.manifest["replacement"]
        for token in (
            replacement["classUnslid"],
        ):
            self.assertIn(canonical(token), source_hex, token)

        lower = self.source.lower()
        self.assertIn(self.manifest["cache"]["dataSubcache"]["uuid"].lower(),
                      lower)
        self.assertNotIn("0x1be1ef2f4", lower)
        self.assertNotIn("0x1be1ef2ec", lower)
        self.assertNotIn("kCNDHailMarySpecialClassOriginalWord", self.source)

    def test_module_names_its_own_journals_and_target(self):
        for token in (
            "CNDHailMarySpecialIconClassPermission.json",
            "CNDHailMarySpecialIconClassRedirect.json",
            "SBHIconModel",
            "iconClassForApplicationWithBundleIdentifier:",
            "SBHApplicationIcon",
            "SBHClockApplicationIcon",
            "SBHCalendarApplicationIcon",
            ".33.dylddata",
            "__got",
            "com.apple.mobiletimer",
            "com.apple.mobilecal",
        ):
            self.assertIn(token, self.source, token)

    def test_legacy_writer_and_probe_are_untouched_by_this_target(self):
        legacy_writer = LEGACY_WRITER.read_text().lower()
        legacy_probe = LEGACY_PROBE.read_text().lower()
        for token in (
            "0x1ffc330a8",
            "0x22440b400be18d3b",
            "0x22440b400be18d90",
            "e495c955bec6fd68c5dfd23b4a7e181e"
            "c006832a2aa5ba389dd40a912232f9e8",
        ):
            self.assertNotIn(token, legacy_writer, token)
            self.assertNotIn(token, legacy_probe, token)
        self.assertNotIn("CNDHailMarySpecialIconClassRedirectRun",
                         legacy_writer)
        self.assertIn("0x1ffc27458", legacy_writer)

    def test_module_does_not_invoke_any_legacy_writer(self):
        for banned in (
            "CNDHailMaryPatchRun(",
            "CNDHailMaryDataPageRun(",
            "CNDHailMaryReadOnlyDataPageRun(",
            "CNDHailMaryImpRedirectRun(",
            "CNDHailMaryPageWireRun(",
        ):
            self.assertNotIn(banned, self.source, banned)

    def test_permission_probe_is_read_only(self):
        probe = self.source.split(
            "void CNDHailMarySpecialIconClassPermissionRunWithMode", 1
        )[1].split(
            "void CNDHailMarySpecialIconClassPermissionRun(", 1
        )[0]
        self.assertIn("CNDHailMarySpecialClassResolveAll", probe)
        self.assertIn("kread64(windowKernelVirtualAddress)", self.source)
        self.assertIn(
            "special-class-got-probe-confirmed", probe)
        self.assertIn('report[@"confirmed"] = @YES;', probe)
        for banned in (
            "kwrite32(",
            "kwrite64(",
            "kwritebuf(",
            "mach_vm_write",
            "CNDHailMaryImpRedirectRun",
            "CNDHailMaryReadOnlyDataPageRun",
        ):
            self.assertNotIn(banned, probe, banned)

    def test_redirect_requires_the_same_boot_ticket_then_writes_two_slots(self):
        run = self.source.split(
            "void CNDHailMarySpecialIconClassRedirectRunWithMode", 1
        )[1]
        self.assertIn("CNDHailMarySpecialClassPermissionTicketMatches",
                      run)
        self.assertIn("CNDHailMarySpecialClassAllInState", run)
        self.assertIn("special-class-got-redirect-permission-required", run)
        self.assertIn('@"stage"] = apply', run)
        self.assertIn('@"armed-got-apply"', run)
        self.assertIn('@"armed-got-restore"', run)
        self.assertIn("CNDHailMarySpecialClassSaveDurably", run)
        self.assertEqual(run.count("kwrite64("), 1)
        self.assertIn("kwrite64(windowKVA, desired);", run)
        self.assertIn("for (NSUInteger index = 0;",
                      run)
        self.assertIn("index < resolved.count", run)
        self.assertIn("kread64(windowKVA)", run)
        self.assertIn("CNDHailMarySpecialClassTranslateAgain", run)
        self.assertIn("special-class-got-redirect-readback-mismatch", run)
        self.assertIn("special-class-got-apply-confirmed", run)
        self.assertIn("special-class-got-restore-confirmed", run)
        self.assertIn('@"consumerRebuildRequired"] = @YES', run)

    def test_no_process_lifecycle_or_target_process_mutation(self):
        for banned in (
            "SIGKILL",
            "killall(",
            "reboot(",
            "respring(",
            "respring_now",
            "respringSpringBoard",
            "posix_spawn",
            "execv(",
            "RemoteCallSession",
            "dispatchSelfSIGKILLForExpectedPID",
            "CNDIconServicesConsumerHookPresentSpotlight",
        ):
            self.assertNotIn(banned, self.source, banned)
        self.assertIn('@"consumerRebuildRequired": @NO',
                      self.source)
        self.assertIn('@"targetProcessDirectMutationCount": @0',
                      self.source)

    def test_other_hail_mary_experiments_are_refused(self):
        for token in (
            "CNDHailMaryProbeIsRunning()",
            "CNDHailMaryPatchIsRunning()",
            "CNDHailMaryDataPageIsRunning()",
            "CNDHailMaryReadOnlyDataPageIsRunning()",
            "CNDHailMaryImpRedirectIsRunning()",
            "CNDHailMaryPageWireIsRunning()",
        ):
            self.assertIn(token, self.source, token)
        self.assertIn("another-experiment-running", self.source)

    def test_header_and_entry_points_are_wired(self):
        for token in (
            "CNDHailMarySpecialIconClassPermissionRun",
            "CNDHailMarySpecialIconClassRedirectRun",
            "CNDHailMarySpecialIconClassOperation",
            "CNDHailMarySpecialIconClassPermissionIsRunning",
            "CNDHailMarySpecialIconClassRedirectIsRunning",
            "__got",
            ".33.dylddata",
            "SBHApplicationIcon",
        ):
            self.assertIn(token, self.header, token)
        settings_header = SETTINGS_HEADER.read_text()
        for name in (
            "settings_run_hail_mary_special_icon_class_probe_action",
            "settings_run_hail_mary_special_icon_class_apply_action",
            "settings_run_hail_mary_special_icon_class_restore_action",
            "settings_run_hail_mary_special_icon_class_verify_redirected_action",
            "settings_run_hail_mary_special_icon_class_verify_original_action",
        ):
            self.assertIn(name, settings_header, name)
            self.assertIn(name, SETTINGS.read_text(), name)
        app_delegate = APP_DELEGATE.read_text()
        for flag in (
            "--hail-mary-special-icon-class-probe",
            "--hail-mary-special-icon-class-apply",
            "--hail-mary-special-icon-class-restore",
            "--hail-mary-special-icon-class-verify-redirected",
            "--hail-mary-special-icon-class-verify-original",
        ):
            self.assertIn(flag, app_delegate, flag)
        self.assertIn("CNDHailMarySpecialIconClassRedirectRun(operation",
                      SETTINGS.read_text())

    def test_settings_probes_expose_the_special_class_controls(self):
        settings = SETTINGS.read_text()
        self.assertIn("case RootSectionProbes:         return 17;", settings)
        for title in (
            "Run Special-Class GOT Probe",
            "Apply Static Clock + Calendar Icons",
            "Restore Live Clock + Calendar Icons",
            "Verify Static Clock + Calendar State",
            "Verify Original Clock + Calendar State",
            "Audit Clock/Calendar Icon Classes",
        ):
            self.assertIn(title, settings, title)
        self.assertIn(
            "settings_run_hail_mary_special_icon_class_action_with_hook(",
            settings)
        self.assertIn("settings_run_icon_class_audit_action(", settings)
        self.assertIn("[ICON_CLASS_AUDIT]", settings)

    def test_manifest_is_data_only(self):
        self.assertEqual(
            self.manifest["kind"],
            "data-only-clock-calendar-class-got-redirect")
        redirect = self.manifest["redirect"]
        self.assertFalse(redirect["executableTextWritten"])
        self.assertFalse(redirect["methodListWritten"])
        self.assertFalse(redirect["perBoot"])
        self.assertTrue(redirect["perProcess"])
        self.assertFalse(redirect["survivesRespring"])
        self.assertFalse(redirect["survivesReboot"])
        self.assertTrue(redirect["respringRevertsPatch"])
        self.assertFalse(redirect["staticThemeRecordsTouched"])
        observation = redirect["postRespringObservation"]
        self.assertEqual(observation["kernelSlideBefore"],
                         observation["kernelSlideAfter"])
        self.assertEqual(observation["clockValueAfter"], "0x1ee45a180")
        self.assertEqual(observation["calendarValueAfter"], "0x1ee45a568")
        boundary = self.manifest["boundary"]
        self.assertTrue(boundary["targetIsNonExecutableData"])
        self.assertEqual(boundary["targetSubcache"], ".33.dylddata")
        self.assertEqual(boundary["targetMaxProt"], "rw-")
        for target in self.manifest["targets"]:
            self.assertEqual(target["slotMapping"]["initProt"], 1)
            self.assertEqual(target["slotMapping"]["maxProt"], 3)
            self.assertEqual(target["classCacheMapping"]["initProt"], 3)
            self.assertEqual(target["classCacheMapping"]["maxProt"], 3)
            self.assertEqual(target["classCacheInitialValue"],
                             "0x0000000000000000")
        self.assertEqual(
            self.manifest["replacement"]["classUnslid"],
            "0x1eda021a8")


if __name__ == "__main__":
    unittest.main()
