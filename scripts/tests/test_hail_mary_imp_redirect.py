#!/usr/bin/env python3
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Cyanide" / "probes" / "CNDHailMaryImpRedirect.m"
HEADER = ROOT / "Cyanide" / "probes" / "CNDHailMaryImpRedirect.h"
RESOLVER = ROOT / "Cyanide" / "probes" / "CNDHailMaryReadOnlyDataPage.m"
RESOLVER_HEADER = ROOT / "Cyanide" / "probes" / "CNDHailMaryReadOnlyDataPage.h"
SETTINGS = ROOT / "Cyanide" / "SettingsViewController.m"
SETTINGS_HEADER = ROOT / "Cyanide" / "SettingsViewController.h"
APP_DELEGATE = ROOT / "Cyanide" / "AppDelegate.m"
LEGACY_WRITERS = (
    ROOT / "Cyanide" / "probes" / "CNDHailMaryPatch.m",
    ROOT / "Cyanide" / "probes" / "CNDHailMaryDataPage.m",
    ROOT / "Cyanide" / "probes" / "CNDHailMaryReadOnlyDataPage.m",
)


class HailMaryImpRedirectTests(unittest.TestCase):
    def test_exact_packed_entry_and_both_guards_are_pinned(self):
        source = SOURCE.read_text().lower()
        for token in (
            "0x1ffc27458",
            "0x02c408000be3f5c7",
            "0x02c408000be3ecba",
            "0x0be3f5c7",
            "0x0be3ecba",
            "c7f5e30b0008c40200000000c0ffffff"
            "0323ed0b0000cc1600000000c0ffffff",
            "baece30b0008c40200000000c0ffffff"
            "0323ed0b0000cc1600000000c0ffffff",
            "81c8a106d2a9e37a93d17d78dc7c54ea"
            "3b0ec4f036458a15e2ec1e4403d33677",
            "4ed8147447733303d0ae8043da89d2634f"
            "01af11c671540f8268a22d4dba906f",
        ):
            self.assertIn(token, source, token)
        self.assertIn("26-bit selector offset", SOURCE.read_text())
        self.assertIn("signed 38-bit class-relative IMP", SOURCE.read_text())

    def test_shared_resolver_accepts_only_one_exact_original_or_redirected_entry(self):
        source = RESOLVER.read_text()
        header = RESOLVER_HEADER.read_text()
        self.assertIn(
            "CNDHailMaryReadOnlyDataPageResolveDispatchEntry", header
        )
        helper = source.split(
            "BOOL CNDHailMaryReadOnlyDataPageResolveDispatchEntry", 1
        )[1].split(
            "BOOL CNDHailMaryReadOnlyDataPageIsSupported", 1
        )[0]
        for token in (
            "BOOL expectRedirected",
            "matches.count != 1",
            "CNDHailMaryProbeTranslateSharedRuntimeAddress",
            "finalFrame != physicalFrame",
            "finalPhysical != physicalAddress",
            "finalFrameKVA != frameKVA",
            "finalEntry != expectedEntry",
        ):
            self.assertIn(token, helper, token)
        for writer in ("kwrite32(", "kwrite64(", "kwritebuf(", "mach_vm_write"):
            self.assertNotIn(writer, helper, writer)

    def test_mutation_requires_same_boot_successful_noop_permission_proof(self):
        source = SOURCE.read_text()
        run = source.split("void CNDHailMaryImpRedirectRun", 1)[1]
        permission = source.split(
            "CNDHailMaryImpLoadPermissionEvidence", 1
        )[1].split(
            "CNDHailMaryImpPermissionMatchesContext", 1
        )[0]
        self.assertIn('CNDHailMaryReadOnlyDataPage.json', source)
        for token in (
            'aperture-read-only-data-page-write-confirmed',
            'NSProcessInfo.processInfo.systemUptime',
            'started < bootEpoch - 5.0',
            'permission[@"kernelWritePrimitiveInvocationCount"]',
            'permission[@"semanticMutationCount"]',
            'write[@"bytesIdenticalByConstruction"]',
            'write[@"dispatchReturned"]',
            'readback[@"identicalToBefore"]',
            'post[@"stable"]',
        ):
            self.assertIn(token, permission, token)
        self.assertLess(
            run.index("CNDHailMaryImpLoadPermissionEvidence"),
            run.index("CNDHailMaryProbeRun"),
        )
        for identity in (
            'sharedCacheSlide',
            'physicalFrame',
            'physicalAddress',
            'windowKernelVirtualAddress',
        ):
            self.assertIn(identity, source)
        self.assertIn(
            "CNDHailMaryImpPermissionMatchesContext", run
        )

    def test_one_low_word_write_is_surrounded_by_durable_inverse_journals(self):
        source = SOURCE.read_text()
        run = source.split("void CNDHailMaryImpRedirectRun", 1)[1]
        self.assertEqual(source.count("kwrite32(windowKVA, desiredWord);"), 1)
        self.assertEqual(source.count("kwrite32("), 1)
        for writer in ("kwrite64(", "kwritebuf(", "mach_vm_write"):
            self.assertNotIn(writer, source, writer)

        armed = run.index('report[@"recovery"] = @{')
        returned_false = run.index('@"dispatchReturned": @NO', armed)
        durable_before = run.index("CNDHailMaryImpSaveDurably", armed)
        write = run.index("kwrite32(windowKVA, desiredWord);")
        returned_true = run.index('@"dispatchReturned": @YES', write)
        durable_after = run.index("CNDHailMaryImpSaveDurably", write)
        self.assertLess(armed, returned_false)
        self.assertLess(returned_false, durable_before)
        self.assertLess(durable_before, write)
        self.assertLess(write, returned_true)
        self.assertLess(returned_true, durable_after)
        self.assertIn('@"inverseLowWord"', run)
        self.assertIn('@"inverseEntryValue"', run)
        self.assertIn('@"automaticRollbackEnabled": @NO', run)
        self.assertIn('@"panicRecoveryMechanismInstalled": @NO', run)

    def test_readback_translation_end_automation_without_process_restart(self):
        source = SOURCE.read_text()
        run = source.split("void CNDHailMaryImpRedirectRun", 1)[1]
        write = run.index("kwrite32(windowKVA, desiredWord);")
        readback = run.index("exactReadback", write)
        translation = run.index("postWriteTranslation", readback)
        manual = run.index(
            '@"mutation-confirmed-awaiting-manual-visual-check"',
            translation,
        )
        durable = run.index("CNDHailMaryImpSaveDurably", manual)
        finish = run.index("CNDHailMaryImpFinish", durable)
        self.assertLess(write, readback)
        self.assertLess(readback, translation)
        self.assertLess(translation, manual)
        self.assertLess(manual, durable)
        self.assertLess(durable, finish)
        self.assertEqual(run.count("CNDHailMaryProbeRun"), 1)
        for banned in (
            "CNDHailMaryImpRestartSpotlight",
            "dispatchSelfSIGKILLForExpectedPID",
            "CNDIconServicesConsumerHookPresentSpotlight",
            "RemoteCallSession",
            "SIGKILL",
            "killall(",
            "reboot(",
            "settings_begin_respring",
        ):
            self.assertNotIn(banned, source, banned)
        for token in (
            '@"automaticSpotlightRestartAttempted": @NO',
            '@"automaticSpotlightPresentationAttemptedPostwrite": @NO',
            '@"secondProcessProofAttempted": @NO',
            '@"springBoardRestarted": @NO',
            '@"visualBehaviorRequiresOperatorObservation": @YES',
            'dispatch-entry-redirect-applied-manual-visual-check-required',
        ):
            self.assertIn(token, run, token)

    def test_transparency_fix_is_consolidated_into_manual_icon_fix(self):
        settings = SETTINGS.read_text()
        header = SETTINGS_HEADER.read_text()
        app_delegate = APP_DELEGATE.read_text()
        remix = (ROOT / "Cyanide/installer/CNDSnowBoardRemix.m").read_text()
        catalog = (ROOT / "Cyanide/installer/CNDQueuedActionCatalog.m").read_text()
        queue = (ROOT / "Cyanide/installer/PackageQueue.m").read_text()

        self.assertIn('case RootSectionActions:        return 6;', settings)
        self.assertIn('action": @"sbl-manual-icon-fix"', settings)
        self.assertIn('@"title": @"Manual Icon Fix"', settings)
        self.assertNotIn('action": @"sbl-queue-transparency-fix"', settings)
        self.assertNotIn(
            'action": @"sbl-queue-transparency-fix-restore"', settings
        )
        self.assertIn("[CNDSnowBoardRemix applyIconFixes]", settings)
        self.assertIn("setTransparencyFixEnabled", remix)
        self.assertIn("CNDHailMaryImpRedirectRun", remix)
        self.assertIn("CNDQueuedActionKindTransparencyFix", catalog)
        self.assertIn("executeTransparencyFixAction", queue)
        self.assertIn("automaticProcessKillOrRestartCount", remix)
        self.assertIn("postwriteProcessLifecycleMutationCount", remix)
        self.assertIn('@"manualVisualCheckRequired": @YES', remix)
        self.assertIn(
            "void settings_run_hail_mary_imp_redirect_apply_action(void);",
            header,
        )
        self.assertIn(
            "void settings_run_hail_mary_imp_redirect_restore_action(void);",
            header,
        )
        self.assertIn('--hail-mary-imp-apply', app_delegate)
        self.assertIn('--hail-mary-imp-restore', app_delegate)

    def test_transparency_fix_uses_springboard_only_proof(self):
        remix = (ROOT / "Cyanide/installer/CNDSnowBoardRemix.m").read_text()
        source = SOURCE.read_text()
        resolver = RESOLVER.read_text()
        probe = (ROOT / "Cyanide/probes/CNDHailMaryProbe.m").read_text()
        header = RESOLVER_HEADER.read_text()

        fix = remix.split(
            "CNDRemixRunTransparencyFixOperation", 1
        )[1].split(
            "@implementation CNDSnowBoardRemix", 1
        )[0]
        for banned in (
            "spotlight-identity",
            "spotlight-presentation",
            'CNDKernelTaskBridgeResolveProcessPID(\n        @"Spotlight"',
            "CNDIconServicesConsumerHookPresentSpotlight",
        ):
            self.assertNotIn(banned, fix, banned)
        self.assertIn("CNDHailMaryProofModeSpringBoardOnly", fix)
        self.assertIn(
            "CNDHailMaryImpRedirectRunWithMode", fix
        )
        self.assertIn("CNDHailMaryReadOnlyDataPageRunWithMode", fix)

        self.assertIn("CNDHailMaryProofModeSpringBoardOnly", header)
        self.assertIn(
            "CNDHailMaryReadOnlyDataPageResolveDispatchEntryWithMode",
            resolver,
        )
        single = probe.split(
            "CNDHailMaryProvePhysicalPageSpringBoardOnly", 1
        )[1].split(
            "void CNDHailMaryProbeRunWithMode", 1
        )[0]
        self.assertNotIn("Spotlight", single)
        self.assertIn("singleProcess", single)
        run = probe.split("void CNDHailMaryProbeRunWithMode", 1)[1]
        self.assertIn("CNDHailMaryProofModeSpringBoardOnly", run)
        self.assertIn("CNDHailMaryCompareSpringBoardOnly", run)

        # The shared-pair experiment stays the default for every other caller.
        self.assertIn(
            "CNDHailMaryProbeRunWithMode(CNDHailMaryProofModeSharedPair",
            probe,
        )
        self.assertIn(
            "CNDHailMaryProofModeSharedPair, operation, completion",
            source,
        )

    def test_other_hail_mary_writers_refuse_while_redirect_runs(self):
        for path in LEGACY_WRITERS:
            source = path.read_text()
            self.assertIn('#import "CNDHailMaryImpRedirect.h"', source)
            self.assertIn("CNDHailMaryImpRedirectIsRunning()", source)


if __name__ == "__main__":
    unittest.main()
