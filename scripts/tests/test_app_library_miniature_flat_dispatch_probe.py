import hashlib
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
    / "docs/research/app-library-miniature-flat-dispatch-23A341-iphone17,2.json"
)


class AppLibraryMiniatureFlatDispatchProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()
        cls.header = HEADER.read_text()
        cls.settings = SETTINGS.read_text()
        cls.settings_header = SETTINGS_HEADER.read_text()
        cls.app_delegate = APP_DELEGATE.read_text()
        cls.manifest = json.loads(MANIFEST.read_text())

    def test_exact_target_matches_ghidra_manifest(self):
        redirect = self.manifest["redirect"]
        target = redirect["target"]
        replacement = redirect["replacement"]
        dispatch = redirect["dispatch"]
        self.assertEqual(target["types"], replacement["types"])
        self.assertEqual(target["types"], "B16@0:8")
        self.assertEqual(self.manifest["analysis"]["tool"], "Ghidra 12.1.4")
        self.assertFalse(self.manifest["analysis"]["hopperUsed"])
        for value in (
            target["impUnslidVMAddress"],
            replacement["impUnslidVMAddress"],
            dispatch["entryUnslidVMAddress"],
            dispatch["frameUnslidVMAddress"],
            dispatch["subcacheFileOffset"],
        ):
            self.assertIn(value.lower(), self.source.lower())
        for key in ("originalPackedWord", "redirectedPackedWord"):
            self.assertIn(dispatch[key].lower(), self.source.lower())
        for key in ("originalGuardHex", "redirectedGuardHex"):
            guard = dispatch[key]
            self.assertIn(guard[:32], self.source)
            self.assertIn(guard[32:], self.source)
        self.assertIn('@"types": @"B16@0:8"', self.source)
        self.assertIn('@"className": @"SBHIconManager"', self.source)
        self.assertIn('@"selector": @"prefersFlatImageLayers"', self.source)
        self.assertIn('@"replacementClass": @"SBIconImageView"', self.source)
        self.assertIn('@"replacementSelector": @"hasOpaqueImage"', self.source)

    def test_guard_hashes_and_low_word_only_encoding_are_consistent(self):
        dispatch = self.manifest["redirect"]["dispatch"]
        original = bytes.fromhex(dispatch["originalGuardHex"])
        redirected = bytes.fromhex(dispatch["redirectedGuardHex"])
        self.assertEqual(len(original), 32)
        self.assertEqual(len(redirected), 32)
        self.assertEqual(original[4:], redirected[4:])
        self.assertNotEqual(original[:4], redirected[:4])
        self.assertEqual(
            hashlib.sha256(original).hexdigest(),
            dispatch["originalGuardSHA256"],
        )
        self.assertEqual(
            hashlib.sha256(redirected).hexdigest(),
            dispatch["redirectedGuardSHA256"],
        )
        original_word = int(dispatch["originalPackedWord"], 16)
        redirected_word = int(dispatch["redirectedPackedWord"], 16)
        self.assertEqual(original_word >> 32, redirected_word >> 32)

    def test_permission_ticket_is_separate_and_one_target(self):
        self.assertIn(
            '"app-library-miniature-presentation-dispatch-permission"',
            self.source,
        )
        self.assertIn(
            '@"CNDAppLibraryMiniaturePresentationDispatchPermission.json"',
            self.source,
        )
        self.assertIn(
            "CNDAppLibraryMiniaturePresentationTargets().count", self.source
        )
        self.assertIn(
            "CNDAppLibraryMiniaturePresentationDispatchPermissionRun",
            self.header,
        )
        self.assertIn("NO, YES, completion", self.source)
        self.assertEqual(
            self.source.count(
                '@"name": @"app-library-miniature-flat-image-policy"'
            ),
            1,
        )
        self.assertIn(
            '@"pid", @"proc", @"task", @"map", @"sharedCacheSlide"',
            self.source,
        )

    def test_route_uses_guarded_shared_lifecycle_without_process_contact(self):
        self.assertIn("settings_ensure_krw_for_probe()", self.settings)
        self.assertIn("CNDHailMaryProofModeSpringBoardOnly", self.source)
        self.assertIn("kexploit_early_kwrite32bytes_checked", self.source)
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

    def test_controls_and_launch_arguments_cover_all_operations(self):
        self.assertIn(
            "CNDSpecialIconPresentationRouteAppLibraryMiniatures = 3",
            self.header,
        )
        functions = (
            "settings_run_app_library_miniature_presentation_probe_action",
            "settings_run_app_library_miniature_static_presentation_apply_action",
            "settings_run_app_library_miniature_static_presentation_restore_action",
            "settings_run_app_library_miniature_static_presentation_verify_redirected_action",
            "settings_run_app_library_miniature_static_presentation_verify_original_action",
        )
        for function in functions:
            self.assertIn(function, self.settings)
            self.assertIn(function, self.settings_header)
        for label in (
            "Probe App Library Mini Route",
            "Apply Flat App Library Minis",
            "Restore App Library Mini Policy",
            "Verify Flat App Library Minis",
            "Verify Original App Library Policy",
        ):
            self.assertIn(label, self.settings)
        for argument in (
            "--app-library-miniature-presentation-probe",
            "--app-library-miniature-presentation-apply",
            "--app-library-miniature-presentation-restore",
            "--app-library-miniature-presentation-verify-redirected",
            "--app-library-miniature-presentation-verify-original",
        ):
            self.assertIn(argument, self.app_delegate)
        self.assertIn("case RootSectionProbes:         return 12;", self.settings)

    def test_claim_stays_dispatch_only_until_physical_appearance_test(self):
        self.assertFalse(self.manifest["runtimeVerified"])
        self.assertFalse(self.manifest["appearanceVerified"])
        self.assertEqual(
            self.manifest["ghidraBehavioralRoute"]["miniatureDecision"],
            "-[SBHLibraryCategoryStackView _innerIconImageOptions] returns 0x11 when prefersFlatImageLayers is true and 0x1 otherwise",
        )
        self.assertIn('@"evidenceClass": @"Implemented"', self.source)
        self.assertIn('@"appearanceEvidenceClass": @"not-run"', self.source)
        self.assertIn(
            '@"bounded exact-entry dispatch state only; not icon appearance"',
            self.source,
        )
        self.assertIn('report[@"mutationConfirmed"] = @YES', self.source)


if __name__ == "__main__":
    unittest.main()
