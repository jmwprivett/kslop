#!/usr/bin/env python3
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Cyanide" / "CNDHailMaryReadOnlyDataPage.m"
HEADER = ROOT / "Cyanide" / "CNDHailMaryReadOnlyDataPage.h"
SETTINGS = ROOT / "Cyanide" / "SettingsViewController.m"
SETTINGS_HEADER = ROOT / "Cyanide" / "SettingsViewController.h"


class HailMaryReadOnlyDataPageTests(unittest.TestCase):
    def test_separate_permission_probe_remains_noop_only(self):
        source = SOURCE.read_text()
        header = HEADER.read_text()
        self.assertIn(
            '@"hail-mary-read-only-data-page-aperture-writability"',
            source,
        )
        self.assertIn('@"identical-bytes-noop"', source)
        self.assertIn("CNDHailMaryReadOnlyDataPageRun", header)
        self.assertIn('@"fallbackAttempted": @NO', source)
        run = source.split("void CNDHailMaryReadOnlyDataPageRun", 1)[1]
        self.assertNotIn("kCNDHailMaryRODataRedirectedEntry", run)
        self.assertNotIn("CND_HAIL_MARY_RO_DATA_REDIRECTED_GUARD_HEX", run)
        self.assertIn("kwrite32(windowKVA, existingWord);", run)

    def test_exact_offline_identity_is_pinned(self):
        source = SOURCE.read_text().lower()
        for token in (
            "ceeb0d68-9ba9-3cc8-aeb1-8f23bac92b58",
            "0x1ffc27458",
            "0x78d3458",
            "0x02c408000be3f5c7",
            "0x0be3f5c7",
            "c7f5e30b0008c40200000000c0ffffff"
            "0323ed0b0000cc1600000000c0ffffff",
            "81c8a106d2a9e37a93d17d78dc7c54ea"
            "3b0ec4f036458a15e2ec1e4403d33677",
            "542063d6c8ea82afbe734ace1895ba0f2"
            "b7ab15160c6053176604644741f20d5",
            "k cndhailmaryrodatainitprotection".replace(" ", ""),
            "k cndhailmaryrodatamaximumprotection".replace(" ", ""),
        ):
            self.assertIn(token, source, token)

    def test_slide_scan_uses_only_live_proof_anchors(self):
        source = SOURCE.read_text()
        for token in (
            'probeReport[@"springBoard"][@"sharedCacheSlide"]',
            'probeReport[@"spotlight"][@"sharedCacheSlide"]',
            'objectProof[@"springBoard"][@"slide"]',
            'objectProof[@"spotlight"][@"slide"]',
            '@"deduplicated-live-proof-anchors"',
            '@"exactGuardRequired": @YES',
            "matches.count != 1",
            "CNDHailMaryProbeTranslateSharedRuntimeAddress",
        ):
            self.assertIn(token, source, token)
        self.assertNotIn("runtimeVerified: false", source)
        self.assertIn('@"runtimeVerified": @YES', source)
        self.assertIn("physicalFrame == guardedTextPhysicalFrame", source)

    def test_guard_is_rechecked_after_scan_and_before_write(self):
        source = SOURCE.read_text()
        run = source.split("void CNDHailMaryReadOnlyDataPageRun", 1)[1]
        scan = run.index('@"scanning-live-slide-candidates"')
        final_check = run.index('@"final-prewrite-identity-check"')
        armed = run.index('@"armed-identical-bytes-noop-write"')
        dispatch = run.index("kwrite32(windowKVA, existingWord);")
        self.assertLess(scan, final_check)
        self.assertLess(final_check, armed)
        self.assertLess(armed, dispatch)
        self.assertIn("[beforeData isEqualToData:expectedGuard]", run)
        self.assertIn("existingEntry != kCNDHailMaryRODataOriginalEntry", run)
        self.assertIn(
            "existingWord != kCNDHailMaryRODataOriginalFirstWord", run
        )

    def test_exactly_one_identical_transport_dispatch(self):
        source = SOURCE.read_text()
        self.assertEqual(source.count("kwrite32(windowKVA, existingWord);"), 1)
        self.assertEqual(source.count("kwrite32("), 1)
        for banned in ("kwrite64(", "kwritebuf(", "mach_vm_write"):
            self.assertNotIn(banned, source)
        self.assertIn('@"bytesIdenticalByConstruction": @YES', source)
        self.assertIn('@"semanticMutationPlanned": @NO', source)
        self.assertIn('report[@"semanticMutationCount"] = @0;', source)

    def test_durable_armed_journal_records_unreturned_dispatch(self):
        source = SOURCE.read_text()
        run = source.split("void CNDHailMaryReadOnlyDataPageRun", 1)[1]
        armed = run.index('@"armed-identical-bytes-noop-write"')
        durable = run.index("CNDHailMaryRODataSaveDurably", armed)
        dispatch = run.index("kwrite32(windowKVA, existingWord);")
        returned_false = run.index('@"dispatchReturned": @NO', armed)
        returned_true = run.index('@"dispatchReturned": @YES', dispatch)
        self.assertLess(armed, returned_false)
        self.assertLess(returned_false, durable)
        self.assertLess(durable, dispatch)
        self.assertLess(dispatch, returned_true)
        self.assertIn('@"automaticRollbackEnabled": @NO', run)
        self.assertIn('@"panicRecoveryMechanismInstalled": @NO', run)

    def test_survival_requires_readback_and_stable_translation(self):
        source = SOURCE.read_text()
        self.assertIn('report[@"physicalReadbackPerformed"] = @YES;', source)
        self.assertIn('report[@"postflightTranslationPerformed"] = @YES;', source)
        self.assertIn("readbackIdentical && postTranslationStable", source)
        self.assertIn(
            '@"aperture-read-only-data-page-write-confirmed"', source
        )

    def test_settings_keeps_the_permission_diagnostic_hidden(self):
        settings = SETTINGS.read_text()
        header = SETTINGS_HEADER.read_text()
        for token in (
            'case RootSectionActions:        return 4;',
            '#import "CNDHailMaryReadOnlyDataPage.h"',
            'Hail Mary .34 RO-Data Write Probe',
            'settings_run_hail_mary_read_only_data_page_action',
            'CNDHailMaryReadOnlyDataPageIsRunning()',
        ):
            self.assertIn(token, settings)
        self.assertIn(
            "void settings_run_hail_mary_read_only_data_page_action(void);",
            header,
        )


if __name__ == "__main__":
    unittest.main()
