#!/usr/bin/env python3
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Cyanide" / "CNDHailMarySpecialIconClassRedirect.m"
HEADER = (
    ROOT / "Cyanide" /
    "CNDHailMarySpecialIconClassDispatchRedirect.h"
)
SETTINGS = ROOT / "Cyanide" / "SettingsViewController.m"
SETTINGS_HEADER = ROOT / "Cyanide" / "SettingsViewController.h"
APP_DELEGATE = ROOT / "Cyanide" / "AppDelegate.m"
DERIVE = ROOT / "scripts" / (
    "derive_special_icon_class_dispatch_redirect.py"
)
MANIFEST = ROOT / "docs" / "research" / (
    "special-icon-class-dispatch-redirect-23A341-iphone17,2.json"
)


def signed_38(value):
    raw = value & ((1 << 38) - 1)
    return raw - (1 << 38) if raw & (1 << 37) else raw


class HailMarySpecialIconClassDispatchRedirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()
        cls.header = HEADER.read_text()
        cls.settings = SETTINGS.read_text()
        cls.manifest = json.loads(MANIFEST.read_text())
        cls.dispatch_source = cls.source.split(
            "#pragma mark - Per-boot preoptimized dispatch redirect", 1
        )[1]

    def test_manifest_entries_decode_to_the_pinned_imps(self):
        replacement = int(
            self.manifest["replacement"]["impUnslid"], 16
        )
        original = int(
            self.manifest["selector"]["originalIMPUnslid"], 16
        )
        for target in self.manifest["targets"]:
            class_address = int(target["classUnslid"], 16)
            original_word = int(
                target["original"]["packedWord"], 16
            )
            redirected_word = int(
                target["redirected"]["packedWord"], 16
            )
            self.assertEqual(
                class_address - signed_38(original_word) * 4,
                original,
            )
            self.assertEqual(
                class_address - signed_38(redirected_word) * 4,
                replacement,
            )
            self.assertEqual(
                original_word >> 32, redirected_word >> 32
            )
            self.assertEqual(target["slot"], 68)

    def test_compiled_constants_match_the_manifest(self):
        lower = self.dispatch_source.lower()
        self.assertIn(
            self.manifest["cache"]["readonlySubcache"]["uuid"].lower(),
            lower,
        )
        for target in self.manifest["targets"]:
            for token in (
                target["classUnslid"],
                target["preoptimizedCacheUnslid"],
                target["entryUnslid"],
                target["entryFileOffset"],
                target["frameUnslid"],
                target["original"]["packedWord"],
                target["redirected"]["packedWord"],
            ):
                self.assertIn(token.lower(), lower, token)
            for guard in (
                target["original"]["guardHex"],
                target["redirected"]["guardHex"],
            ):
                self.assertIn(guard[:32].lower(), lower, guard)
                self.assertIn(guard[32:].lower(), lower, guard)

    def test_permission_probe_is_identical_low_word_only(self):
        probe = self.dispatch_source.split(
            "void CNDHailMarySpecialIconClassDispatchPermissionRunWithMode",
            1,
        )[1].split(
            "void CNDHailMarySpecialIconClassDispatchPermissionRun(", 1
        )[0]
        self.assertIn("kwrite32(windowKVA, (uint32_t)currentWord)", probe)
        self.assertIn("identicalToBefore", probe)
        self.assertIn("CNDHailMarySpecialClassSaveDurably", probe)
        self.assertIn("CNDHailMarySpecialDispatchTranslateAgain", probe)
        self.assertIn("special-dispatch-probe-confirmed", probe)
        self.assertNotIn("kwrite64(", probe)
        self.assertNotIn(
            'dispatchEntrySemanticMutationCount"] =', probe
        )

    def test_mutation_requires_ticket_and_exact_guards(self):
        run = self.dispatch_source.split(
            "void CNDHailMarySpecialIconClassDispatchRedirectRunWithMode",
            1,
        )[1]
        self.assertIn(
            "CNDHailMarySpecialDispatchPermissionMatches", run
        )
        self.assertIn("CNDHailMarySpecialDispatchAllInState", run)
        self.assertIn("CNDHailMarySpecialClassSaveDurably", run)
        self.assertIn("kwrite32(windowKVA, desiredLowWord)", run)
        self.assertIn("[readback isEqual:desiredGuard]", run)
        self.assertIn("CNDHailMarySpecialDispatchTranslateAgain", run)
        self.assertIn("special-dispatch-apply-confirmed", run)
        self.assertIn("special-dispatch-restore-confirmed", run)
        self.assertNotIn("kwrite64(", run)

    def test_ticket_binds_the_live_translation(self):
        body = self.dispatch_source.split(
            "static BOOL CNDHailMarySpecialDispatchPermissionMatches", 1
        )[1].split(
            "BOOL CNDHailMarySpecialIconClassDispatchRedirectIsSupported",
            1,
        )[0]
        for key in (
            "entryRuntime",
            "physicalFrame",
            "physicalAddress",
            "windowKernelVirtualAddress",
        ):
            self.assertIn(key, body)
        self.assertIn("permission-ticket-translation-mismatch", body)

    def test_no_process_lifecycle_or_target_process_write(self):
        for banned in (
            "SIGKILL",
            "killall(",
            "reboot(",
            "respring(",
            "posix_spawn",
            "mach_vm_write",
            "RemoteCallSession",
        ):
            self.assertNotIn(banned, self.dispatch_source, banned)
        self.assertIn(
            '@"targetProcessDirectMutationCount": @0',
            self.dispatch_source,
        )

    def test_public_api_and_ui_are_wired(self):
        for token in (
            "CNDHailMarySpecialIconClassDispatchPermissionRun",
            "CNDHailMarySpecialIconClassDispatchRedirectRun",
            "CNDHailMarySpecialIconClassDispatchOperation",
            ".34.dyldreadonly",
            "SBHIconModel",
            "SBIconModel",
        ):
            self.assertIn(token, self.header, token)
        self.assertIn(
            "case RootSectionProbes:         return 17;",
            self.settings,
        )
        for title in (
            "Run Per-Boot Static-Icon Dispatch Probe",
            "Apply Per-Boot Static Clock + Calendar",
            "Restore Per-Boot Live Clock + Calendar",
            "Verify Per-Boot Static-Icon Dispatch",
            "Verify Original Per-Boot Dispatch",
        ):
            self.assertIn(title, self.settings)
        settings_header = SETTINGS_HEADER.read_text()
        for action in (
            "dispatch_probe_action",
            "dispatch_apply_action",
            "dispatch_restore_action",
            "dispatch_verify_redirected_action",
            "dispatch_verify_original_action",
        ):
            self.assertIn(action, settings_header)
            self.assertIn(action, self.settings)

    def test_launch_arguments_are_wired(self):
        app = APP_DELEGATE.read_text()
        for flag in (
            "--hail-mary-special-icon-dispatch-probe",
            "--hail-mary-special-icon-dispatch-apply",
            "--hail-mary-special-icon-dispatch-restore",
            "--hail-mary-special-icon-dispatch-verify-redirected",
            "--hail-mary-special-icon-dispatch-verify-original",
        ):
            self.assertIn(flag, app)

    def test_manifest_records_per_boot_boundary(self):
        redirect = self.manifest["redirect"]
        self.assertTrue(redirect["perBoot"])
        self.assertFalse(redirect["perProcess"])
        self.assertTrue(redirect["survivesRespringExpected"])
        self.assertFalse(redirect["survivesRespringPhysicalProof"])
        self.assertFalse(redirect["survivesReboot"])
        self.assertFalse(redirect["executableTextWritten"])
        self.assertFalse(redirect["methodListWritten"])
        boundary = self.manifest["boundary"]
        self.assertEqual(boundary["targetSubcache"], ".34.dyldreadonly")
        self.assertEqual(boundary["targetInitProt"], "r--")
        self.assertEqual(boundary["targetMaxProt"], "r--")
        self.assertTrue(
            boundary["sameBootIdenticalWriteTicketRequired"]
        )

    def test_derivation_is_offline_and_read_only(self):
        derive = DERIVE.read_text()
        self.assertIn("CacheReader", derive)
        self.assertIn("signed_38", derive)
        self.assertIn("reader.read(entry, 32)", derive)
        for banned in (
            "kwrite",
            "kread",
            "mach_vm_write",
            "ssh",
            "pymobiledevice",
        ):
            self.assertNotIn(banned, derive)


if __name__ == "__main__":
    unittest.main()
