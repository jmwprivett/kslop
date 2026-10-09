#!/usr/bin/env python3
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Cyanide" / "CNDHailMaryPatch.m"
HEADER = ROOT / "Cyanide" / "CNDHailMaryPatch.h"
PROBE = ROOT / "Cyanide" / "CNDHailMaryProbe.m"
SETTINGS = ROOT / "Cyanide" / "SettingsViewController.m"
SETTINGS_HEADER = ROOT / "Cyanide" / "SettingsViewController.h"
APP_DELEGATE = ROOT / "Cyanide" / "AppDelegate.m"


class HailMaryPatchTests(unittest.TestCase):
    def test_writer_is_separate_and_probe_stays_observation_only(self):
        source = SOURCE.read_text()
        probe = PROBE.read_text()
        self.assertIn('#import "CNDHailMaryProbe.h"', source)
        for token in ("kwrite", "early_kwrite", "mach_vm_write"):
            self.assertNotIn(token, probe, token)
        self.assertIn('@"kernelMutationCount": @0', probe)

    def test_exact_target_guard_and_words_are_fixed(self):
        source = SOURCE.read_text().lower()
        expected = (
            'cnd_hail_mary_patch_build "23a341"',
            'cnd_hail_mary_patch_product "iphone17,2"',
            "0x1be102ef0",
            "0x2e5c",
            "0x2ef0",
            "0x1a9f17f4",
            "0x52800034",
            "542063d6c8ea82afbe734ace1895ba0f2b7ab15160c6053176604644741f20d5",
            "5d11085e066693f14771fea0c97d55ab593bd6468856bfbed2463224dd01569f",
        )
        for value in expected:
            self.assertIn(value, source)

    def test_only_one_narrow_mutation_primitive_exists(self):
        source = SOURCE.read_text()
        header = HEADER.read_text()
        self.assertEqual(source.count("kwrite32(targetKVA, desiredWord);"), 1)
        self.assertNotIn("kexploit_early_kwrite32bytes_checked(", source)
        self.assertNotIn("kwrite64(", source)
        self.assertNotIn("kwritebuf(", source)
        self.assertNotRegex(
            header,
            re.compile(r"(?:address|value|word)\s*[,)]", re.IGNORECASE),
        )
        # The live proof result is never accepted as a hard-coded frame/KVA.
        self.assertNotIn("0x1009acec000", source.lower())
        self.assertNotIn("0xfffffff0d4510000", source.lower())
        self.assertNotIn("0x1bfadeef0", source.lower())

    def test_runtime_target_is_proven_from_the_current_shared_cache_slide(self):
        source = SOURCE.read_text()
        self.assertIn('springObject[@"runtimeAddress"]', source)
        self.assertIn('spotlightObject[@"runtimeAddress"]', source)
        self.assertIn('springObject[@"slide"]', source)
        self.assertIn('spotlightObject[@"slide"]', source)
        self.assertIn("springVirtual < springSlide", source)
        self.assertIn(
            "springVirtual - springSlide !=\n"
            "            kCNDHailMaryPatchUnslidTargetVirtualAddress",
            source,
        )
        self.assertIn(
            '@"targetVirtualAddress": CNDHailMaryPatchHex(springVirtual)',
            source,
        )

    def test_split_leaf_addresses_require_same_proven_backing_and_value(self):
        source = SOURCE.read_text()
        validate = source.split("CNDHailMaryPatchValidateProof", 1)[1]
        validate = validate.split("CNDHailMaryPatchWireSpringBoardPage", 1)[0]
        self.assertNotIn(
            "[springEntryAddress isEqual:spotlightEntryAddress]", validate
        )
        for token in (
            'objectProof[@"sameBackingObject"]',
            'objectProof[@"sameObjectOffset"]',
            'objectProof[@"sameBackingObjectPageSlot"]',
            'physicalProof[@"samePhysicalFrame"]',
            'physicalProof[@"samePhysicalAddress"]',
            'physicalProof[@"postReadTranslationStable"]',
            "springEntryValue != spotlightEntryValue",
            '@"springBoardLeafEntryAddress"',
            '@"spotlightLeafEntryAddress"',
            '@"leafEntryAddressesShared"',
        ):
            self.assertIn(token, validate)

    def test_wire_rechecks_full_springboard_translation_path(self):
        source = SOURCE.read_text()
        wire = source.split("CNDHailMaryPatchWireSpringBoardPage", 1)[1]
        wire = wire.split("CNDHailMaryPatchReadGuard", 1)[0]
        self.assertIn('context[@"springBoardTranslationPath"]', wire)
        self.assertGreaterEqual(
            wire.count("CNDHailMaryPatchTranslationPathMatches("), 2
        )
        self.assertIn("initialPathStable", wire)
        self.assertIn("translationPathStable", wire)
        self.assertIn(
            "finalPathTerminalAddress == springBoardLeafEntryAddress", wire
        )

    def test_legacy_landing_and_durable_journals_precede_single_write(self):
        run = SOURCE.read_text().split("void CNDHailMaryPatchRun", 1)[1]
        self.assertIn(
            "static const BOOL kCNDHailMaryPatchAttemptSpringBoardMlock = NO;",
            SOURCE.read_text(),
        )
        arming = run.index('@"arming-legacy-landing-no-mlock"')
        first_journal = run.index("CNDHailMaryPatchSaveDurably(", arming)
        bypass = run.index('@"skipped-for-legacy-landing"', first_journal)
        armed = run.index('@"armed-legacy-landing-no-readback"', bypass)
        second_journal = run.index("CNDHailMaryPatchSaveDurably(", armed)
        write = run.index(
            "CNDHailMaryPatchWriteWordLegacyLanding(", second_journal
        )
        self.assertLess(arming, first_journal)
        self.assertLess(first_journal, bypass)
        self.assertLess(bypass, armed)
        self.assertLess(armed, second_journal)
        self.assertLess(second_journal, write)
        self.assertEqual(run.count("CNDHailMaryProbeRun("), 1)
        self.assertIn('@"physicalReadbackPerformed": @NO', run)
        self.assertIn('@"postflightProbePerformed": @NO', run)
        self.assertIn('@"automaticRollbackEnabled": @NO', run)
        self.assertNotIn("sameTargetAfterWrite", run)
        self.assertNotIn("apply-postflight-failed-rolled-back", run)

    def test_springboard_wire_uses_exact_pid_bound_mlock(self):
        source = SOURCE.read_text()
        wire = source.split("CNDHailMaryPatchWireSpringBoardPage", 1)[1]
        wire = wire.split("CNDHailMaryPatchReadGuard", 1)[0]
        self.assertIn('initWithProcess:@"SpringBoard"', wire)
        self.assertIn("g_RC_targetProcOverride = expectedProc", wire)
        self.assertIn('R_TIMEOUT, "mlock", pageBase', wire)
        self.assertIn("kCNDHailMaryPatchPageSize", wire)
        self.assertIn(
            "finalLeafEntryValue == provenLeafEntryValue", wire
        )
        self.assertIn("session.taskAddr == expectedTask", wire)

    def test_springboard_wire_captures_remote_errno_immediately(self):
        source = SOURCE.read_text()
        wire = source.split("CNDHailMaryPatchWireSpringBoardPage", 1)[1]
        wire = wire.split("CNDHailMaryPatchReadGuard", 1)[0]
        errno_address = wire.index('R_TIMEOUT, "__error"')
        mlock = wire.index('R_TIMEOUT, "mlock", pageBase')
        errno_read = wire.index(
            "remote_read(\n                        remoteErrnoAddress",
            mlock,
        )
        self.assertLess(errno_address, mlock)
        self.assertLess(mlock, errno_read)
        self.assertIn('@"mlockErrnoCaptured": @(mlockErrnoCaptured)', wire)
        self.assertIn('@"mlockErrno": @(mlockErrno)', wire)
        self.assertIn(
            '@"mlockErrnoDescription": mlockErrnoDescription', wire
        )

    def test_mutation_tail_never_reenters_krw_or_remotecall(self):
        run = SOURCE.read_text().split("void CNDHailMaryPatchRun", 1)[1]
        run = run.split("&writeInvoked,\n                    &writeError);", 1)[1]
        for token in (
            "kreadbuf(",
            "kread32(",
            "kread64(",
            "kwrite32(",
            "kwrite64(",
            "kwritebuf(",
            "CNDHailMaryProbeRun(",
            "RemoteCallSession ",
            "remote_call_(",
            "r_dlsym_call(",
        ):
            self.assertNotIn(token, run, token)

    def test_legacy_prewrite_conditioning_is_exact_and_has_no_readback(self):
        source = SOURCE.read_text()
        writer = source.split(
            "static BOOL CNDHailMaryPatchWriteWordLegacyLanding", 1
        )[1]
        writer = writer.split("static void CNDHailMaryPatchFinish", 1)[0]
        guard = writer.index("CNDHailMaryPatchReadGuard(context)")
        compare = writer.index("isEqualToData:expectedBefore", guard)
        invoke = writer.index("*writeInvokedOut = YES", compare)
        write = writer.index("kwrite32(targetKVA, desiredWord);", invoke)
        self.assertLess(guard, compare)
        self.assertLess(compare, invoke)
        self.assertLess(invoke, write)
        tail = writer[write:]
        self.assertNotIn("kread", tail)
        self.assertNotIn("CNDHailMaryPatchReadGuard", tail)
        self.assertNotIn("CNDHailMaryProbeRun", tail)

    def test_armed_journal_syncs_file_and_parent_directory(self):
        source = SOURCE.read_text()
        durable = source.split("CNDHailMaryPatchSaveDurably", 1)[1]
        durable = durable.split("CNDHailMaryPatchOperationName", 1)[0]
        self.assertIn("NSDataWritingAtomic", durable)
        self.assertIn("CNDHailMaryPatchSyncFileDescriptor", durable)
        self.assertIn("fsync(directoryDescriptor)", durable)

    def test_report_distinguishes_attempted_writes_from_direct_target_writes(self):
        source = SOURCE.read_text()
        for key in (
            "kernelWritePrimitiveInvocationCount",
            "sharedPhysicalCodeWordMutationCount",
            "targetProcessDirectMutationCount",
        ):
            self.assertIn(key, source)
        self.assertIn("if (writeInvokedOut) *writeInvokedOut = YES;", source)
        self.assertIn("@(writeInvoked ? 1 : 0)", source)

    def test_settings_retains_hidden_launch_diagnostics(self):
        settings = SETTINGS.read_text()
        settings_header = SETTINGS_HEADER.read_text()
        self.assertIn('#import "CNDHailMaryPatch.h"', settings)
        self.assertIn('#import "installer/CNDIconServicesConsumerHook.h"', settings)
        self.assertIn("CNDIconServicesConsumerHookPresentSpotlight()", settings)
        self.assertIn("settings_hail_mary_spotlight_identity", settings)
        self.assertIn("settings_hail_mary_patch_preflight_is_retryable", settings)
        self.assertIn("kMaximumAttempts = 3", settings)
        self.assertIn('invalid-or-unstable-entry-list', settings)
        self.assertIn("Apply Once (Legacy Landing)", settings)
        self.assertIn("may cause a userspace restart or kernel panic", settings)
        self.assertIn("does not respring automatically", settings)
        self.assertIn("Apply Hail Mary Patch", settings)
        self.assertIn("Restore Hail Mary Patch", settings)
        self.assertIn("case RootSectionActions:        return 4;", settings)
        self.assertIn("settings_run_hail_mary_patch_apply_action", settings_header)
        self.assertIn("settings_run_hail_mary_patch_restore_action", settings_header)

    def test_launch_arguments_cover_apply_restore_and_nonmutating_verification(self):
        app_delegate = APP_DELEGATE.read_text()
        for argument in (
            "--hail-mary-apply",
            "--hail-mary-restore",
            "--hail-mary-verify-patched",
            "--hail-mary-verify-original",
        ):
            self.assertIn(f'@"{argument}"', app_delegate)


if __name__ == "__main__":
    unittest.main()
