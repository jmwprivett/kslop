import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Cyanide/probes/CNDSpecialIconPresentationDispatchProbe.m"
HEADER = ROOT / "Cyanide/probes/CNDSpecialIconPresentationDispatchProbe.h"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"
SETTINGS_HEADER = ROOT / "Cyanide/SettingsViewController.h"
APP_DELEGATE = ROOT / "Cyanide/AppDelegate.m"
MANIFEST = (
    ROOT
    / "docs/research/switcher-imp-redirect-23A341-iphone17,2.json"
)


class SwitcherPresentationDispatchProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()
        cls.header = HEADER.read_text()
        cls.settings = SETTINGS.read_text()
        cls.settings_header = SETTINGS_HEADER.read_text()
        cls.app_delegate = APP_DELEGATE.read_text()
        cls.manifest = json.loads(MANIFEST.read_text())

    def test_exact_targets_match_reviewed_switcher_manifest(self):
        redirects = self.manifest["redirects"]
        self.assertEqual(
            [item["label"] for item in redirects],
            [
                "switcher-flat-image-storage",
                "switcher-flat-image-provider",
            ],
        )
        for redirect in redirects:
            target = redirect["targetDispatchEntry"]
            replacement = redirect["replacementEncoding"]
            for key in (
                "unslidVMAddress",
                "subcacheFileOffset",
                "frameUnslidVMAddress",
            ):
                value = int(target[key], 16)
                self.assertIn(f"0x{value:x}", self.source.lower())
            original_word = int(target["originalValue"], 16)
            redirected_word = int(replacement["redirectedValue"], 16)
            self.assertIn(f"0x{original_word:016x}", self.source.lower())
            self.assertIn(f"0x{redirected_word:016x}", self.source.lower())
            guard = target["guard"]
            for state in ("originalBytesHex", "redirectedBytesHex"):
                self.assertIn(guard[state][:32], self.source)
                self.assertIn(guard[state][32:], self.source)

    def test_switcher_permission_ticket_is_separate_and_exactly_two_targets(self):
        self.assertIn(
            '"switcher-presentation-dispatch-permission"', self.source
        )
        self.assertIn(
            '@"CNDSwitcherPresentationDispatchPermission.json"',
            self.source,
        )
        self.assertIn(
            "CNDSwitcherPresentationTargets().count", self.source
        )
        self.assertIn(
            "CNDSwitcherPresentationDispatchPermissionRun", self.header
        )
        self.assertIn(
            "YES, NO, completion",
            self.source,
        )
        self.assertIn(
            '@"pid", @"proc", @"task", @"map", @"sharedCacheSlide"',
            self.source,
        )
        self.assertIn(
            "permission-ticket-process-identity-mismatch", self.source
        )

    def test_apply_and_restore_preserve_matched_pair_order(self):
        storage = self.source.index(
            '@"name": @"switcher-flat-image-storage"'
        )
        provider = self.source.index(
            '@"name": @"switcher-flat-image-provider"'
        )
        self.assertLess(storage, provider)
        self.assertEqual(
            self.manifest["transaction"]["applyOrder"],
            [
                "switcher-flat-image-storage",
                "switcher-flat-image-provider",
            ],
        )
        self.assertEqual(
            self.manifest["transaction"]["restoreOrder"],
            [
                "switcher-flat-image-provider",
                "switcher-flat-image-storage",
            ],
        )
        self.assertIn(
            "operation == CNDSpecialIconPresentationOperationRestore",
            self.source,
        )
        self.assertIn(
            "targets = targets.reverseObjectEnumerator.allObjects;",
            self.source,
        )
        self.assertIn('report[@"requiresSwitcherQuiescence"]', self.source)

    def test_route_uses_shared_lifecycle_and_no_process_contact(self):
        self.assertIn("settings_ensure_krw_for_probe()", self.settings)
        self.assertIn("CNDHailMaryProofModeSpringBoardOnly", self.source)
        self.assertIn('kexploit_early_kwrite32bytes_checked', self.source)
        for forbidden in (
            "kexploit_krw_ready(",
            "kexploit_opa334(",
            "krw_persistence_recover",
            "CNDIconServicesConsumerHookPresentSpotlight",
            "r_msg",
            "task_for_pid",
        ):
            self.assertNotIn(forbidden, self.source)
        self.assertIn('@"processInjectionCount": @0', self.source)
        self.assertIn('@"remoteCallCount": @0', self.source)
        self.assertIn('@"homeVisibilityPrecondition": @NO', self.source)

    def test_probe_exposes_permission_apply_restore_and_verify_controls(self):
        self.assertIn(
            "CNDSpecialIconPresentationRouteSwitcher = 2", self.header
        )
        functions = (
            "settings_run_switcher_presentation_probe_action",
            "settings_run_switcher_static_presentation_apply_action",
            "settings_run_switcher_static_presentation_restore_action",
            "settings_run_switcher_static_presentation_verify_redirected_action",
            "settings_run_switcher_static_presentation_verify_original_action",
        )
        for function in functions:
            self.assertIn(function, self.settings)
            self.assertIn(function, self.settings_header)
        labels = (
            "Probe Switcher Transparency Route",
            "Apply Switcher Transparency",
            "Restore Switcher Presentation",
            "Verify Switcher Transparency",
            "Verify Original Switcher State",
        )
        for label in labels:
            self.assertIn(label, self.settings)
        self.assertIn("case RootSectionProbes:         return 12;", self.settings)

    def test_launch_arguments_cover_all_switcher_operations(self):
        for argument in (
            "--switcher-presentation-probe",
            "--switcher-presentation-apply",
            "--switcher-presentation-restore",
            "--switcher-presentation-verify-redirected",
            "--switcher-presentation-verify-original",
        ):
            self.assertIn(argument, self.app_delegate)

    def test_claim_stays_dispatch_only_until_appearance_is_observed(self):
        self.assertIn('@"evidenceClass": @"Implemented"', self.source)
        self.assertIn('@"appearanceEvidenceClass": @"not-run"', self.source)
        self.assertIn(
            '@"bounded exact-entry dispatch state only; not icon appearance"',
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
