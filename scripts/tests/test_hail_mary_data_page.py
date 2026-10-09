#!/usr/bin/env python3
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Cyanide" / "CNDHailMaryDataPage.m"
HEADER = ROOT / "Cyanide" / "CNDHailMaryDataPage.h"
PROBE = ROOT / "Cyanide" / "CNDHailMaryProbe.m"
PROBE_HEADER = ROOT / "Cyanide" / "CNDHailMaryProbe.h"
SETTINGS = ROOT / "Cyanide" / "SettingsViewController.m"
SETTINGS_HEADER = ROOT / "Cyanide" / "SettingsViewController.h"


class HailMaryDataPageTests(unittest.TestCase):
    def test_module_exists_and_is_a_separate_experiment(self):
        source = SOURCE.read_text()
        header = HEADER.read_text()
        self.assertIn('#import "CNDHailMaryProbe.h"', source)
        self.assertIn('@"hail-mary-data-page-aperture-writability"', source)
        self.assertIn('@"identical-bytes-noop"', source)
        self.assertIn("CNDHailMaryDataPageRun", header)

    def test_probe_stays_observation_only_and_helper_is_read_only(self):
        probe = PROBE.read_text()
        for token in ("kwrite", "early_kwrite", "mach_vm_write"):
            self.assertNotIn(token, probe, token)
        self.assertIn("CNDHailMaryProbeTranslateSharedRuntimeAddress",
                      probe)
        self.assertIn("CNDHailMaryProbeTranslateSharedRuntimeAddress",
                      PROBE_HEADER.read_text())

    def test_exactly_one_narrow_identical_write_dispatch(self):
        source = SOURCE.read_text()
        self.assertEqual(
            source.count("kwrite32(slotKernelVirtualAddress, existingWord);"),
            1,
        )
        self.assertEqual(source.count("kwrite32("), 1)
        self.assertNotIn("kwrite64(", source)
        self.assertNotIn("kwritebuf(", source)
        self.assertNotIn("kwrite_zone_element", source)

    def test_slot_is_decoded_from_the_exact_original_guard(self):
        source = SOURCE.read_text()
        expected = (
            "kCNDHailMaryDataPageAdrpOffsetWithinGuard = 0x60",
            "kCNDHailMaryDataPageLdrOffsetWithinGuard = 0x64",
            "kCNDHailMaryDataPageAdrpRegister = 8",
            "kCNDHailMaryDataPageLdrBaseRegister = 8",
            "kCNDHailMaryDataPageLdrTargetRegister = 0",
            "kCNDHailMaryDataPageLdr64OpcodeBits = UINT32_C(0x3e5)",
            "kCNDHailMaryDataPageUnslidPatchAddress =\n"
            "    UINT64_C(0x1be102ef0)",
            "kCNDHailMaryDataPageOriginalWord =\n"
            "    UINT32_C(0x1a9f17f4)",
            "kCNDHailMaryDataPageGuardLength = 188",
            "kCNDHailMaryDataPageWordOffsetWithinGuard = 148",
            "542063d6c8ea82afbe734ace1895ba0f2b7ab15160c6053176604644741f20d5",
        )
        for value in expected:
            self.assertIn(value, source)

    def test_no_live_address_or_frame_is_ever_hard_coded(self):
        source = SOURCE.read_text().lower()
        for banned in (
            "0x1bfadeef0",
            "0x1bebcaef0",
            "0x1e9b6ed20",
            "0x1009acec000",
            "0x10191654000",
            "0xfffffff1dc40",
            "0xfffffff0d451",
        ):
            self.assertNotIn(banned, source, banned)

    def test_slot_must_differ_from_and_never_touch_the_guarded_frame(self):
        source = SOURCE.read_text()
        self.assertIn("slotRuntimeFrame == guardedRuntimeFrame", source)
        self.assertIn("slotPhysicalFrame == guardFrame", source)
        self.assertIn("slotFrameUnslid == guardFrameUnslid", source)
        self.assertIn("slotUnslid < kCNDHailMaryDataPageSharedRegionBase",
                      source)

    def test_identical_bytes_and_full_journals_surround_the_dispatch(self):
        source = SOURCE.read_text()
        run = source.split("void CNDHailMaryDataPageRun", 1)[1]
        self.assertIn('@"armed-identical-bytes-noop-write"', run)
        arming = run.index('@"armed-identical-bytes-noop-write"')
        dispatch = run.index(
            "kwrite32(slotKernelVirtualAddress, existingWord);")
        journal = run.index("CNDHailMaryDataPageSaveDurably", arming)
        self.assertLess(arming, dispatch)
        self.assertLess(journal, dispatch)
        self.assertIn('@"dataPageSemanticMutationCount": @0', run)
        self.assertIn('report[@"kernelWritePrimitiveInvocationCount"] = @1;',
                      run)
        self.assertIn('report[@"dataPageSemanticMutationCount"] = @0;',
                      run)
        self.assertIn('@"semanticMutationPlanned": @NO', run)
        self.assertIn('@"bytesIdenticalByConstruction": @YES', run)
        self.assertIn('report[@"physicalReadbackPerformed"] = @YES;',
                      run)
        self.assertIn('report[@"postflightTranslationPerformed"] = @YES;',
                      run)

    def test_transport_window_stays_inside_one_physical_frame(self):
        source = SOURCE.read_text()
        self.assertIn(
            "slotOffsetWithinFrame >\n"
            "            kCNDHailMaryDataPagePageSize - EARLY_KRW_LENGTH",
            source,
        )
        self.assertIn(
            "slotPhysicalAddress - slotPhysicalFrame !=\n"
            "                    slotOffsetWithinFrame",
            source,
        )

    def test_settings_retains_the_data_page_diagnostic_without_exposing_it(self):
        settings = SETTINGS.read_text()
        header = SETTINGS_HEADER.read_text()
        self.assertIn("case RootSectionActions:        return 4;", settings)
        self.assertIn('#import "CNDHailMaryDataPage.h"', settings)
        self.assertIn("Hail Mary Data-Page Write Probe", settings)
        self.assertIn("Hail Mary Data-Page Write Probe?", settings)
        self.assertIn("settings_run_hail_mary_data_page_action", settings)
        self.assertIn("void settings_run_hail_mary_data_page_action(void);",
                      header)
        self.assertIn("CNDHailMaryDataPageIsRunning()", settings)

    def test_data_page_action_binds_spotlight_and_releases_the_lock(self):
        settings = SETTINGS.read_text()
        action = settings.split(
            "void settings_run_hail_mary_data_page_action", 1)[1]
        action = action.split("static void", 1)[0]
        for token in (
            "settings_try_claim_actions_lock",
            "settings_ensure_kexploit()",
            "settings_hail_mary_spotlight_identity",
            "CNDHailMaryDataPageRun",
            "settings_release_actions_lock()",
            "log_session_end()",
        ):
            self.assertIn(token, action)
        self.assertIn("Hail Mary Data-Page Probe blocked", settings)
        self.assertIn("Hail Mary Data-Page Probe failed to acquire",
                      settings)
        self.assertIn("Hail Mary Data-Page Probe could not open and bind",
                      settings)


if __name__ == "__main__":
    unittest.main()
