import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (
    ROOT / "Cyanide/probes/CNDSpecialIconPresentationDispatchProbe.m"
)
HEADER = (
    ROOT / "Cyanide/probes/CNDSpecialIconPresentationDispatchProbe.h"
)
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"
SETTINGS_HEADER = ROOT / "Cyanide/SettingsViewController.h"
APP_DELEGATE = ROOT / "Cyanide/AppDelegate.m"
MANIFEST = (
    ROOT
    / "docs/research/special-icon-presentation-dispatch-23A341-iphone17,2.json"
)


class SpecialIconPresentationDispatchProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()
        cls.header = HEADER.read_text()
        cls.settings = SETTINGS.read_text()
        cls.settings_header = SETTINGS_HEADER.read_text()
        cls.app_delegate = APP_DELEGATE.read_text()
        cls.manifest = json.loads(MANIFEST.read_text())

    def test_exact_targets_match_reviewed_static_manifest(self):
        redirects = (
            self.manifest["clock"]["redirects"]
            + self.manifest["calendar"]["redirects"]
        )
        self.assertEqual(len(redirects), 4)
        for redirect in redirects:
            dispatch = redirect["dispatch"]
            for key in (
                "entryUnslid",
                "entryFileOffset",
                "frameUnslid",
            ):
                value = int(dispatch[key], 16)
                self.assertIn(f"0x{value:x}", self.source.lower())
            for state in ("original", "redirected"):
                word = int(dispatch[state]["packedWord"], 16)
                guard = dispatch[state]["guardHex"]
                self.assertIn(f"0x{word:016x}", self.source.lower())
                self.assertIn(guard[:32], self.source)
                self.assertIn(guard[32:], self.source)

    def test_probe_is_springboard_only_and_has_no_consumer_contact(self):
        self.assertIn(
            "CNDHailMaryProofModeSpringBoardOnly", self.source
        )
        self.assertIn(
            "CNDHailMaryProbeTranslateRuntimeAddressInProcessWithPhysical",
            self.source,
        )
        self.assertIn('@"SpringBoard"', self.source)
        for forbidden in (
            "CNDIconServicesConsumerHookPresentSpotlight",
            "RemoteCall",
            "r_msg",
            "task_for_pid",
            "removeIcon",
            "addIcon",
        ):
            self.assertNotIn(forbidden, self.source)
        self.assertIn('@"processInjectionCount": @0', self.source)
        self.assertIn('@"remoteCallCount": @0', self.source)
        self.assertIn('@"iconObjectMutationCount": @0', self.source)
        self.assertIn('@"homeVisibilityPrecondition": @NO', self.source)

    def test_probe_uses_checked_transfer_and_not_compatibility_writer(self):
        self.assertIn(
            "kexploit_early_kwrite32bytes_checked", self.source
        )
        self.assertNotIn("kwrite32(", self.source)
        self.assertIn(
            "_Static_assert(EARLY_KRW_LENGTH == "
            "kCNDSpecialPresentationGuardLength",
            self.source,
        )

    def test_runtime_cache_identity_is_proved_from_springboard_mapping(self):
        self.assertNotIn(
            'probeReport[@"runtimeCacheUUIDVerified"]', self.source
        )
        self.assertIn(
            "CNDSpecialPresentationVerifyRuntimeCacheIdentity", self.source
        )
        self.assertIn("UINT32_C(0x41818)", self.source)
        self.assertIn("UINT32_C(77)", self.source)
        self.assertIn("UINT32_C(33)", self.source)
        self.assertIn("UINT64_C(0x78354000)", self.source)
        self.assertIn('@".34.dyldreadonly"', self.source)
        self.assertIn('@"runtimeCacheIdentity"', self.source)
        self.assertIn(
            'ticket[@"runtimeCacheIdentity"][@"verified"]', self.source
        )
        self.assertIn(
            "CNDSpecialPresentationReadPhysicalWindow", self.source
        )
        self.assertIn('@"translationStable": @YES', self.source)

    def test_probe_does_not_own_krw_lifecycle(self):
        for forbidden in (
            "kexploit_krw_ready(",
            "kexploit_opa334(",
            "krw_persistence_recover",
            "krw_persistence_has_saved_recovery",
        ):
            self.assertNotIn(forbidden, self.source)
        action = self.settings.split(
            "static void settings_run_special_icon_presentation_action_with_hook",
            1,
        )[1].split(
            "static void settings_run_special_icon_presentation_action(", 1
        )[0]
        self.assertIn("settings_ensure_krw_for_probe()", action)
        self.assertNotIn("settings_ensure_kexploit()", action)
        self.assertNotIn("settings_hail_mary_spotlight_identity", action)
        self.assertNotIn("CNDIconServicesConsumerHookPresentSpotlight", action)

    def test_calendar_route_has_bounded_failure_restoration(self):
        self.assertIn(
            "CNDSpecialPresentationRestoreAttemptedWrites", self.source
        )
        self.assertGreaterEqual(
            self.source.count(
                "CNDSpecialPresentationRestoreAttemptedWrites("
            ),
            5,
        )
        self.assertIn('@"cleanup"', self.source)
        self.assertIn('@"rollbackWritePrimitiveInvocationCount"', self.source)
        self.assertIn('@"restored"', self.source)
        self.assertIn("CNDSpecialPresentationSaveDurably", self.source)
        self.assertIn("presentation-final-journal-failed", self.source)
        self.assertIn(
            "CNDSpecialPresentationIsLegacyCalendarGreyPair", self.source
        )
        self.assertIn(
            '@"inverseGuardHex": one[@"currentGuardHex"]', self.source
        )
        self.assertIn(
            '@"restore each target\'s exact captured before-state guard"',
            self.source,
        )

    def test_permission_ticket_covers_all_four_exact_entries(self):
        self.assertEqual(self.source.count('@"name": @"clock-view-class"'), 1)
        self.assertEqual(
            self.source.count('@"name": @"calendar-bundle-identifier"'), 1
        )
        self.assertEqual(self.source.count('@"name": @"calendar-image"'), 1)
        self.assertEqual(self.source.count('@"name": @"calendar-layer"'), 1)
        self.assertIn(
            "expectedTargetCount =", self.source
        )
        self.assertIn(
            "CNDSpecialPresentationAllTargets().count",
            self.source,
        )
        self.assertIn('@"identicalToBefore": @YES', self.source)
        self.assertIn('@"postWriteTranslation"', self.source)

    def test_calendar_candidate_restores_bundle_source_before_factories(self):
        redirects = self.manifest["calendar"]["redirects"]
        self.assertEqual(len(redirects), 3)
        self.assertEqual(redirects[0]["name"], "calendarBundleIdentifier")
        self.assertEqual(
            redirects[0]["target"]["selector"],
            "applicationBundleIdentifierForImage",
        )
        self.assertEqual(redirects[0]["target"]["impUnslid"], "0x1be044d28")
        self.assertEqual(
            redirects[0]["replacement"]["impUnslid"], "0x1bdebbf58"
        )
        self.assertEqual(
            self.manifest["calendar"]["retainedTwoFactoryGreyEvidence"][
                "observation"
            ],
            "grey generic plate",
        )

    def test_evidence_stays_implemented_until_a_device_report_exists(self):
        self.assertIn('@"evidenceClass": @"Implemented"', self.source)
        self.assertIn('@"appearanceEvidenceClass": @"not-run"', self.source)
        self.assertIn(
            'report[@"evidenceClass"] = @"Physical-proved"',
            self.source,
        )
        self.assertIn('report[@"mutationConfirmed"] = @YES', self.source)
        self.assertIn(
            '@"bounded exact-entry dispatch state only; not icon appearance"',
            self.source,
        )

    def test_settings_retains_old_controls_and_exposes_switcher_probe(self):
        self.assertIn("case RootSectionProbes:         return 12;", self.settings)
        self.assertIn(
            "settings_root_probe_underlying_row(indexPath.row)", self.settings
        )
        for row in (17, 18, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37):
            self.assertRegex(self.settings, rf"\b{row}\b")
        for label in (
            "Probe Static Presentation Entries",
            "Apply Static Clock Presentation",
            "Restore Live Clock Presentation",
            "Verify Static Clock Presentation",
            "Verify Original Clock Presentation",
            "Apply Static Calendar Presentation",
            "Restore Live Calendar Presentation",
            "Verify Static Calendar Presentation",
            "Verify Original Calendar Presentation",
            "Probe Switcher Transparency Route",
            "Apply Switcher Transparency",
            "Restore Switcher Presentation",
            "Verify Switcher Transparency",
            "Verify Original Switcher State",
        ):
            self.assertIn(label, self.settings)
        for function in (
            "settings_run_special_icon_presentation_probe_action",
            "settings_run_clock_static_presentation_apply_action",
            "settings_run_clock_static_presentation_restore_action",
            "settings_run_calendar_static_presentation_apply_action",
            "settings_run_calendar_static_presentation_restore_action",
        ):
            self.assertIn(function, self.settings)
            self.assertIn(function, self.settings_header)

    def test_launch_arguments_cover_probe_apply_restore_and_verification(self):
        arguments = (
            "--special-icon-presentation-probe",
            "--special-icon-clock-presentation-apply",
            "--special-icon-clock-presentation-restore",
            "--special-icon-clock-presentation-verify-redirected",
            "--special-icon-clock-presentation-verify-original",
            "--special-icon-calendar-presentation-apply",
            "--special-icon-calendar-presentation-restore",
            "--special-icon-calendar-presentation-verify-redirected",
            "--special-icon-calendar-presentation-verify-original",
        )
        for argument in arguments:
            self.assertIn(argument, self.app_delegate)


if __name__ == "__main__":
    unittest.main()
