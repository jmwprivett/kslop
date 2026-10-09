#!/usr/bin/env python3
import json
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Cyanide" / "CNDHailMaryProbe.m"
HEADER = ROOT / "Cyanide" / "CNDHailMaryProbe.h"
SETTINGS = ROOT / "Cyanide" / "SettingsViewController.m"
SETTINGS_HEADER = ROOT / "Cyanide" / "SettingsViewController.h"
APP_DELEGATE = ROOT / "Cyanide" / "AppDelegate.m"
MANIFEST = ROOT / "docs" / "research" / "flat-icon-patch-23A341-iphone17,2.json"
PHYSICAL_MANIFEST = ROOT / "docs" / "research" / "hail-mary-physical-page-proof-23A341-iphone17,2.json"


class HailMaryProbeTests(unittest.TestCase):
    def test_probe_is_observation_only(self):
        source = SOURCE.read_text()
        forbidden = (
            "kwrite", "early_kwrite", "mach_vm_write", "vm_protect(",
            "mach_vm_protect", "ptrace(", "method_setImplementation",
            "vm_map_remote_page", "overwrite_system_file", "RemoteCall",
        )
        for token in forbidden:
            self.assertNotIn(token, source, token)
        self.assertIn('@"kernelMutationCount": @0', source)
        self.assertIn("KRW acquisition is external and excluded", source)
        self.assertIn('@"targetProcessMutationCount": @0', source)

    def test_exact_patch_identity_matches_manifest(self):
        source = SOURCE.read_text()
        manifest = json.loads(MANIFEST.read_text())
        expected = {
            "CND_HAIL_MARY_BUILD": manifest["os"]["productBuildVersion"],
            "CND_HAIL_MARY_PRODUCT": manifest["os"]["productType"],
            "CND_HAIL_MARY_CACHE_UUID": manifest["cache"]["uuid"],
            "CND_HAIL_MARY_SUBCACHE_UUID": manifest["cache"]["subcache"]["uuid"],
            "CND_HAIL_MARY_IMAGE_UUID": manifest["image"]["uuid"],
            "CND_HAIL_MARY_CONTEXT_SHA256": manifest["guard"]["sha256"],
        }
        for macro, value in expected.items():
            self.assertRegex(source, rf'#define {macro} "{re.escape(value)}"')

        numeric = (
            manifest["patch"]["unslidVMAddress"],
            manifest["patch"]["sharedRegionOffset"],
            manifest["patch"]["subcacheFileOffset"],
            manifest["patch"]["originalWord"],
            manifest["patch"]["replacementWord"],
        )
        for value in numeric:
            self.assertIn(value.lower(), source.lower())

    def test_probe_reports_proof_boundary(self):
        source = SOURCE.read_text()
        self.assertIn("confirmed-shared-backing-page-slot", source)
        self.assertIn("confirmed-shared-physical-frame-and-bytes", source)
        self.assertIn("CNDHailMaryTranslateVirtualAddress", source)
        self.assertIn("postReadTranslationStable", source)
        self.assertIn("CC_SHA256", source)
        self.assertIn('@"runtimeCacheUUIDVerified": @NO', source)

    def test_exact_kernel_and_pmap_derivation_matches_manifest(self):
        source = SOURCE.read_text()
        manifest = json.loads(PHYSICAL_MANIFEST.read_text())
        self.assertEqual(manifest["mode"], "observation-only")
        expected_macros = {
            "CND_HAIL_MARY_KERNEL_UUID": manifest["kernel"]["uuid"],
            "CND_HAIL_MARY_KERNEL_SHA256": manifest["kernel"]["sha256"],
        }
        for macro, value in expected_macros.items():
            self.assertRegex(source, rf'#define {macro} "{re.escape(value)}"')
        exact_values = (
            manifest["kernel"]["unslidBase"],
            manifest["symbols"]["gVirtBase"],
            manifest["symbols"]["gPhysBase"],
            manifest["symbols"]["gPhysSize"],
            manifest["symbols"]["physmapRangeState"],
            manifest["symbols"]["physmapRangeCountPointer"],
            manifest["symbols"]["physmapRangeRecordsPointer"],
            manifest["structureOffsets"]["vmMapPmap"],
            manifest["geometry"]["subpageRootAlignment"],
            manifest["geometry"]["validUserAddressMask"],
            manifest["guard"]["guardFileOffset"],
            manifest["guard"]["originalInstructionWord"],
            manifest["guard"]["sha256"],
        )
        for value in exact_values:
            self.assertIn(value.lower(), source.lower())

    def test_public_api_and_settings_wiring_exist(self):
        header = HEADER.read_text()
        settings = SETTINGS.read_text()
        settings_header = SETTINGS_HEADER.read_text()
        app_delegate = APP_DELEGATE.read_text()
        self.assertIn("CNDHailMaryProbeRun", header)
        self.assertIn('#import "CNDHailMaryProbe.h"', settings)
        self.assertIn("Run Hail Mary Physical Proof", settings)
        self.assertIn("settings_run_hail_mary_probe_action", settings)
        self.assertIn("settings_run_hail_mary_probe_action", settings_header)
        self.assertIn('@"--hail-mary-probe"', app_delegate)


if __name__ == "__main__":
    unittest.main()
