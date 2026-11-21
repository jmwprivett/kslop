"""Host-only recovery proof fixtures; never connects to a device or daemon."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REMIX = ROOT / "Cyanide/installer/CNDSnowBoardRemix.m"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"

HARNESS = r'''
static NSMutableDictionary *untouchedReport(void) {
    return [@{
        @"transactionStarted": @NO, @"directStoreRemoveIssued": @NO,
        @"directStoreWriteIssued": @NO,
        @"persistentIndexTokenWriteIssued": @NO,
        @"replacementPublished": @NO,
        @"installed": @NO, @"stockGenerationPersisted": @NO,
        @"hookStillInstalledAtCleanup": @NO,
        @"hookRestored": @YES, @"hookQuiescent": @YES,
    } mutableCopy];
}

static NSMutableDictionary *untouchedVariant(void) {
    return [@{@"state": @"recovery-required",
              @"publication": untouchedReport()} mutableCopy];
}

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "recovery fixture failed at line %d: %s\n", \
            __LINE__, #condition); return 1; } } while (0)

int main(void) {
    @autoreleasepool {
        CHECK(CNDRemixVariantProvesNoIconServicesMutation(untouchedVariant()));
        for (NSString *state in @[@"prepared", @"dispatch-possible",
                                 @"recovery-required", @"unmutated-skipped"]) {
            NSMutableDictionary *variant = untouchedVariant();
            variant[@"state"] = state;
            CHECK(CNDRemixVariantProvesNoIconServicesMutation(variant));
            [variant removeObjectForKey:@"publication"];
            CHECK(!CNDRemixVariantProvesNoIconServicesMutation(variant));
            variant[@"publication"] = @{};
            CHECK(!CNDRemixVariantProvesNoIconServicesMutation(variant));
        }
        for (NSString *state in @[@"active", @"restoring",
                @"published-pending-session-close", @"persistent-stock-verified"]) {
            NSMutableDictionary *variant = untouchedVariant();
            variant[@"state"] = state;
            CHECK(!CNDRemixVariantProvesNoIconServicesMutation(variant));
        }
        for (NSString *key in untouchedReport()) {
            NSMutableDictionary *report = untouchedReport();
            [report removeObjectForKey:key];
            CHECK(!CNDRemixReportProvesNoIconServicesMutation(report));
            report[key] = @"0";
            CHECK(!CNDRemixReportProvesNoIconServicesMutation(report));
            report[key] = @(![untouchedReport()[key] boolValue]);
            CHECK(!CNDRemixReportProvesNoIconServicesMutation(report));
        }
        for (NSString *key in @[@"ok", @"transactionInstalled", @"stockCaptured",
                @"stockGenerationInitiallyPersisted", @"replacementCreated",
                @"replacementReturned", @"directStoreRemoveVerified",
                @"directStoreWriteVerified", @"immediateStoreRollbackAttempted",
                @"immediateStoreRollbackSucceeded", @"operationCompleted",
                @"triggerVerified", @"agentCacheReadbackVerified",
                @"persistentStoreReadbackVerified"]) {
            NSMutableDictionary *report = untouchedReport();
            report[key] = @YES;
            CHECK(!CNDRemixReportProvesNoIconServicesMutation(report));
        }
        NSMutableDictionary *retry = untouchedVariant();
        retry[@"restoration"] = @{};
        CHECK(!CNDRemixVariantProvesNoIconServicesMutation(retry));
        retry[@"restoration"] = untouchedReport();
        CHECK(CNDRemixVariantProvesNoIconServicesMutation(retry));
        retry[@"restoration"][@"transactionStarted"] = @YES;
        CHECK(!CNDRemixVariantProvesNoIconServicesMutation(retry));

        NSMutableDictionary *journal = [@{
            @"schemaVersion": @2, @"state": @"recovery-required",
            @"variants": @[untouchedVariant(), untouchedVariant()],
        } mutableCopy];
        CHECK(CNDRemixJournalProvesNoIconServicesMutation(journal));
        for (NSNumber *schema in @[@0, @1, @3]) {
            journal[@"schemaVersion"] = schema;
            CHECK(!CNDRemixJournalProvesNoIconServicesMutation(journal));
        }
        journal[@"schemaVersion"] = @2;
        journal[@"variants"] = @[];
        CHECK(!CNDRemixJournalProvesNoIconServicesMutation(journal));
        NSMutableDictionary *mutated = untouchedVariant();
        mutated[@"publication"][@"directStoreWriteIssued"] = @YES;
        journal[@"variants"] = @[untouchedVariant(), mutated];
        CHECK(!CNDRemixJournalProvesNoIconServicesMutation(journal));
        journal[@"variants"] = @[untouchedVariant(),
            @{@"state": @"dispatch-possible"}];
        CHECK(!CNDRemixJournalProvesNoIconServicesMutation(journal));
        journal[@"variants"] = @[untouchedVariant()];
        journal[@"state"] = @"active";
        CHECK(!CNDRemixJournalProvesNoIconServicesMutation(journal));

        NSMutableDictionary *prepared = [@{
            @"state": @"prepared", @"publicationDispatchPossible": @NO,
        } mutableCopy];
        CHECK(CNDRemixVariantProvesNoIconServicesMutation(prepared));
        journal[@"state"] = @"prepared";
        journal[@"variants"] = @[prepared];
        CHECK(CNDRemixJournalProvesNoIconServicesMutation(journal));
        prepared[@"state"] = @"dispatch-possible";
        prepared[@"publicationDispatchPossible"] = @YES;
        CHECK(!CNDRemixJournalProvesNoIconServicesMutation(journal));
        prepared[@"publication"] = untouchedReport();
        CHECK(CNDRemixJournalProvesNoIconServicesMutation(journal));
        prepared[@"restorationDispatchPossible"] = @YES;
        CHECK(!CNDRemixJournalProvesNoIconServicesMutation(journal));
        prepared[@"restoration"] = untouchedReport();
        CHECK(CNDRemixJournalProvesNoIconServicesMutation(journal));
        [prepared removeObjectForKey:@"publication"];
        prepared[@"publicationDispatchPossible"] = @"0";
        CHECK(!CNDRemixJournalProvesNoIconServicesMutation(journal));
    }
    return 0;
}
'''


ALIAS_HARNESS = r'''
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "index alias fixture failed at line %d: %s\n", \
            __LINE__, #condition); return 1; } } while (0)
static NSString *hex64(unichar c) {
    return [NSString stringWithCharacters:&c length:1];
}
static NSString *token(void) {
    return [@"" stringByPaddingToLength:64 withString:@"c" startingAtIndex:0];
}
static NSDictionary *journalVariant(NSString *identity, NSString *uuid) {
    return @{
        @"descriptorIdentity": identity,
        @"publication": @{@"stockResponse": @{@"uuid": uuid}},
    };
}
static NSMutableDictionary *restoration(void) {
    return [@{
        @"mode": @"stock",
        @"transactionStarted": @YES, @"stockCaptured": @YES,
        @"persistentIndexIdentitySettled": @YES,
        @"persistentIndexScratchLifecycleVerified": @YES,
        @"directStoreRemoveVerified": @YES, @"directStoreWriteIssued": @YES,
        @"directStoreWriteAcknowledged": @YES,
        @"sourceRegistrationRequired": @NO,
        @"deferredStoreProof": @"stock-class-identity",
        @"stockResponse": @{@"uuid": @"own-unit"},
        @"agentCacheResponse": @{@"validationTokenSHA256": token()},
        @"deferredVerificationAudit": [@{
            @"ok": @YES, @"storeUnitPresent": @YES, @"storeUnitValid": @YES,
            @"storeIndexEntryPresent": @YES,
            @"storeIdentifier": @"own-unit", @"indexedIdentifier": @"sibling-unit",
            @"storeValidationTokenSHA256": token(),
            @"storeIndexUnitIdentifierEqual": @NO,
        } mutableCopy],
    } mutableCopy];
}
int main(void) {
    @autoreleasepool {
        NSArray *journal = @[
            journalVariant(@"27x27@3:a0:v0:o0", @"own-unit"),
            journalVariant(@"28x28@3:a0:v0:o0", @"sibling-unit"),
        ];
        NSDictionary *saved = journal[0];
        NSString *alias = nil;
        CHECK(CNDRemixRestorationIndexAliasesSiblingUnit(
            restoration(), saved, journal, &alias));
        CHECK([alias isEqualToString:@"28x28@3:a0:v0:o0"]);
        /* The variant's own unit is not an alias, whatever the index says. */
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            restoration(), saved, @[journalVariant(@"27x27@3:a0:v0:o0", @"own-unit"),
                                    journalVariant(@"28x28@3:a0:v0:o0", @"other-unit")],
            &alias));
        /* An index UUID that no variant of this journal recorded is rejected. */
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            restoration(), saved, @[journalVariant(@"28x28@3:a0:v0:o0", @"other-unit")],
            &alias));
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            restoration(), saved, @[journalVariant(@"27x27@3:a0:v0:o0", @"own-unit")],
            &alias));
        for (NSString *key in @[
                @"transactionStarted", @"stockCaptured",
                @"persistentIndexIdentitySettled",
                @"persistentIndexScratchLifecycleVerified",
                @"directStoreRemoveVerified", @"directStoreWriteIssued",
                @"directStoreWriteAcknowledged"]) {
            NSMutableDictionary *report = restoration();
            report[key] = @NO;
            CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
                report, saved, journal, &alias));
            [report removeObjectForKey:key];
            CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
                report, saved, journal, &alias));
        }
        for (NSString *proof in @[@"none", @"", @"byte-exact-ish"]) {
            NSMutableDictionary *report = restoration();
            report[@"deferredStoreProof"] = proof;
            CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
                report, saved, journal, &alias));
        }
        for (NSString *key in @[@"ok", @"storeUnitPresent", @"storeUnitValid",
                                @"storeIndexEntryPresent"]) {
            NSMutableDictionary *report = restoration();
            report[@"deferredVerificationAudit"][key] = @NO;
            CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
                report, saved, journal, &alias));
        }
        /* A replacement is never an alias, and neither is an already
         * publisher-verified restoration. */
        NSMutableDictionary *replacing = restoration();
        replacing[@"mode"] = @"replace";
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            replacing, saved, journal, &alias));
        /* The store proof must be anchored on this variant's recorded write. */
        NSMutableDictionary *foreignStore = restoration();
        foreignStore[@"deferredVerificationAudit"][@"storeIdentifier"] = @"other-unit";
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            foreignStore, saved, journal, &alias));
        /* The index record must still carry this variant's token. */
        NSMutableDictionary *wrongToken = restoration();
        wrongToken[@"deferredVerificationAudit"][@"storeValidationTokenSHA256"] =
            [@"d" stringByPaddingToLength:64 withString:@"d" startingAtIndex:0];
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            wrongToken, saved, journal, &alias));
        NSMutableDictionary *noToken = restoration();
        noToken[@"deferredVerificationAudit"][@"storeValidationTokenSHA256"] = @"";
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            noToken, saved, journal, &alias));
        NSMutableDictionary *noExpectedToken = restoration();
        noExpectedToken[@"agentCacheResponse"] = @{};
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            noExpectedToken, saved, journal, &alias));
        /* An index that agrees with the unit is the publisher's own verdict. */
        NSMutableDictionary *agreeing = restoration();
        agreeing[@"deferredVerificationAudit"][@"indexedIdentifier"] = @"own-unit";
        agreeing[@"deferredVerificationAudit"][@"storeIndexUnitIdentifierEqual"] = @YES;
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            agreeing, saved, journal, &alias));
        NSMutableDictionary *emptyIndex = restoration();
        emptyIndex[@"deferredVerificationAudit"][@"indexedIdentifier"] = @"";
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            emptyIndex, saved, journal, &alias));
        /* Source proof is required whenever the restoration required it. */
        NSMutableDictionary *sourceRequired = restoration();
        sourceRequired[@"sourceRegistrationRequired"] = @YES;
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            sourceRequired, saved, journal, &alias));
        sourceRequired[@"deferredVerificationAudit"]
            [@"sourceIdentityMatchesCurrentRecord"] = @YES;
        sourceRequired[@"deferredVerificationAudit"][@"sourceRegistryDataSHA256"] =
            [hex64('a') stringByPaddingToLength:64 withString:@"a" startingAtIndex:0];
        CHECK(CNDRemixRestorationIndexAliasesSiblingUnit(
            sourceRequired, saved, journal, &alias));
        /* A sibling's restored stock unit counts as journaled evidence too. */
        NSArray *restoredJournal = @[
            journalVariant(@"27x27@3:a0:v0:o0", @"own-unit"),
            @{@"descriptorIdentity": @"28x28@3:a0:v0:o0",
              @"restoration": @{@"stockResponse": @{@"uuid": @"sibling-unit"}}},
        ];
        CHECK(CNDRemixRestorationIndexAliasesSiblingUnit(
            restoration(), saved, restoredJournal, &alias));
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            restoration(), saved, @[], &alias));
        CHECK(!CNDRemixRestorationIndexAliasesSiblingUnit(
            restoration(), saved, (NSArray *)@{}, &alias));
    }
    return 0;
}
'''


class RemixRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = REMIX.read_text(encoding="utf-8")
        start = cls.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals("
        )
        end = cls.source.index("\n@implementation CNDSnowBoardRemix", start)
        cls.restore = cls.source[start:end]

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"),
                         "requires macOS Foundation and clang")
    def test_compiled_negative_proof_and_crash_ambiguity(self) -> None:
        start = self.source.index("static BOOL CNDRemixReportProvesNoIconServicesMutation(")
        end = self.source.index("static BOOL CNDRemixJournalIsCompleteActiveMatrix(", start)
        with tempfile.TemporaryDirectory(prefix="cyanide-recovery-proof-") as directory:
            source = Path(directory) / "recovery.m"
            executable = Path(directory) / "recovery"
            source.write_text(
                "#import <Foundation/Foundation.h>\n#include <stdio.h>\n"
                "static const NSUInteger CNDRemixIconServicesJournalSchemaVersion = 2;\n"
                + self.source[start:end] + HARNESS, encoding="utf-8"
            )
            subprocess.run(
                ["clang", "-fobjc-arc", "-framework", "Foundation",
                 str(source), "-o", str(executable)], check=True, capture_output=True,
            )
            subprocess.run([str(executable)], check=True, capture_output=True)

    def test_restore_skips_proven_variant_before_descriptor_generation(self) -> None:
        start = self.restore.index("if (currentSchema &&")
        generation = self.restore.index("CNDIconServicesPublisherRestoreStockVariantsInBatch(")
        skip = self.restore[start:generation]
        self.assertIn("CNDRemixVariantProvesNoIconServicesMutation(", skip)
        self.assertIn("skippedUnmutatedVariants++;", skip)
        self.assertIn("continue;", skip)
        self.assertIn('@"stage": @"unmutated-skipped"', skip)
        self.assertIn("variantResults.count == savedVariants.count", self.restore)

    def test_cleanup_does_not_change_persistent_recovery_success(self) -> None:
        self.assertIn(
            "BOOL persistentRecoveryOK = persistentDataClean && !cancelled && failed == 0;",
            self.restore,
        )
        self.assertIn("CNDRemixCoordinatorResult(persistentRecoveryOK,", self.restore)
        self.assertIn('@"persistent-restored-cleanup-partial"', self.restore)
        finalization = self.restore.index("CNDIconServicesPublisherFinishBatch()")
        self.assertNotIn("CNDRemixWriteIconServicesJournal", self.restore[finalization:])

    def test_failed_untouched_journal_removal_is_cleanup_not_dirty_data(self) -> None:
        early = self.restore[:self.restore.index("CNDIconServicesPublisherBeginBatch(")]
        self.assertIn('BOOL ok = YES;', early)
        self.assertIn('@"persistentDataClean": @YES', early)
        self.assertIn('@"persistentRecoveryOK": @(ok)', early)
        self.assertIn('discardFailures == 0 &&', early)
        self.assertIn('verifiedStockCleanupFailures == 0', early)
        self.assertIn('NSUInteger failed = 0, plannedVariants = 0;', self.restore)
        self.assertIn(
            "persistentClean = discardedUnmutated + discardFailures +",
            self.restore,
        )

    def test_restore_arms_the_dispatch_matrix_before_mutation(self) -> None:
        audit = self.restore.index("CNDIconServicesPublisherAuditVariantsInBatch(")
        restoring = self.restore.index('dispatchVariant[@"state"] = @"restoring";')
        checkpoint = self.restore.index(
            "CNDRemixWriteIconServicesJournal(journal);", restoring
        )
        generation = self.restore.index("CNDIconServicesPublisherRestoreStockVariantsInBatch(")
        self.assertLess(audit, restoring)
        self.assertLess(restoring, checkpoint)
        self.assertLess(checkpoint, generation)
        self.assertNotIn(
            "CNDRemixAppendIconServicesJournalCheckpoint(",
            self.restore[restoring:generation],
        )
        self.assertNotIn('journal[@"state"] = @"restoring";', self.restore[:audit])

    def test_verified_stock_journal_cleanup_does_not_count_as_dirty_failure(self) -> None:
        self.assertIn("else if (appVerified) {\n                        journalCleanupFailures++;", self.restore)
        self.assertIn('@"ok": @(appVerified)', self.restore)
        self.assertIn('@"journalCleanupOK": @(journalCleanupFailures == 0)', self.restore)

    def test_restore_defers_springboard_cleanup_to_respring(self) -> None:
        helper_start = self.source.index(
            "CNDRemixDeferredSpringBoardPresentationRestore("
        )
        helper_end = self.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals(",
            helper_start,
        )
        helper = self.source[helper_start:helper_end]
        self.assertIn('@"stage": @"deferred-to-respring"', helper)
        self.assertIn('@"deferredToRespring": @YES', helper)
        self.assertIn('@"remoteCallUsed": @NO', helper)
        self.assertNotIn("CNDIconServicesConsumerLifecycleRepair", helper)
        self.assertNotIn("CNDKernelTaskBridgeResolveProcessPID", helper)
        self.assertNotIn("CNDRemixRestoreSpringBoardPresentationIfNeeded", self.source)
        self.assertNotIn("CNDIconServicesConsumerLifecycleRepair", self.restore)

    def test_process_local_presentation_needs_no_durable_restore_marker(self) -> None:
        self.assertNotIn('@"SpringBoardDynamicPresentation.plist"', self.source)
        self.assertNotIn("CNDRemixWriteSpringBoardDynamicPresentationState", self.source)
        self.assertNotIn("CNDRemixRemoveSpringBoardDynamicPresentationState", self.source)
        apply_start = self.source.index(
            "+ (NSDictionary<NSString *, id> *)applySpringBoardTweaks"
        )
        apply_end = self.source.index(
            "+ (NSDictionary<NSString *, id> *)repairSpotlightPresentation",
            apply_start,
        )
        apply = self.source[apply_start:apply_end]
        self.assertIn('@"dynamicPresentationStateRequired"', apply)
        self.assertIn('@"dynamicPresentationStateRecorded"', apply)
        self.assertIn('@"presentationRestorePolicy"] = @"natural-respring"', apply)
        restore_all_start = self.source.index(
            "+ (NSDictionary<NSString *, id> *)restoreAllWithProgress:"
        )
        restore_all = self.source[restore_all_start:]
        self.assertNotIn("hasLiveDynamicPresentation", restore_all)
        self.assertIn("if (hasIconServicesJournals)", restore_all)

    def test_restore_reuses_verified_stock_checkpoints(self) -> None:
        helper_start = self.source.index(
            "static BOOL CNDRemixVariantHasVerifiedStockCheckpoint("
        )
        helper_end = self.source.index(
            "static BOOL CNDRemixJournalHasVerifiedStockCheckpoint(", helper_start
        )
        helper = self.source[helper_start:helper_end]
        self.assertIn('isEqualToString:@"persistent-stock-verified"', helper)
        self.assertIn("CNDIconServicesPublisherRestorationResultIsVerified", helper)
        self.assertIn("CNDRemixAuditProvesSavedStock", helper)
        skip = self.restore.index("skippedVerifiedStockVariants++;")
        generation = self.restore.index(
            "CNDIconServicesPublisherRestoreStockVariantsInBatch("
        )
        self.assertLess(skip, generation)
        self.assertIn('@"stage": @"verified-stock-checkpoint"', self.restore)
        begin = self.restore.index("CNDIconServicesPublisherBeginBatch(")
        cleanup = self.restore.index(
            "CNDRemixJournalHasVerifiedStockCheckpoint(journal)"
        )
        self.assertLess(cleanup, begin)

    def test_full_apply_is_not_debug_limited_by_default(self) -> None:
        settings = SETTINGS.read_text(encoding="utf-8")
        self.assertIn(
            "kSettingsSnowBoardRemixDebugThreeAppLimit: @NO,", settings
        )

    def test_apply_cleanup_does_not_manufacture_a_persistent_retry(self) -> None:
        start = self.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        end = self.source.index(
            "CNDRemixDeferredSpringBoardPresentationRestore(", start
        )
        apply = self.source[start:end]
        self.assertIn(
            "BOOL persistentApplyOK = sessionClosed && !cancelled && failed == 0;",
            apply,
        )
        self.assertIn("BOOL cleanupOK = presentationOK && indexOK;", apply)
        self.assertIn("CNDRemixCoordinatorResult(persistentApplyOK,", apply)
        self.assertIn('@"complete-cleanup-partial"', apply)

    def test_apply_arms_whole_matrix_in_one_predispatch_checkpoint(self) -> None:
        apply_start = self.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        arm = self.source.index(
            'dispatchVariant[@"publicationDispatchPossible"]', apply_start
        )
        arm_loop = self.source.index(
            'journal[@"state"] = @"dispatch-possible";', arm
        )
        checkpoint = self.source.index(
            "CNDRemixAppendIconServicesJournalCheckpoint(", arm_loop
        )
        publish = self.source.index(
            "CNDIconServicesPublisherPublishVariantsInBatch(", checkpoint
        )
        self.assertLess(arm, arm_loop)
        self.assertLess(arm_loop, checkpoint)
        self.assertLess(checkpoint, publish)
        self.assertIn("dispatchIndexes", self.source[arm:checkpoint])

    def test_restore_commits_each_verified_variant_without_an_app_level_veto(
        self,
    ) -> None:
        helper_start = self.source.index(
            "static BOOL CNDRemixCommitRestoreVariantState("
        )
        helper_end = self.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals(",
            helper_start,
        )
        helper = self.source[helper_start:helper_end]
        # One variant commits through the bounded append checkpoint only.
        self.assertIn("CNDRemixAppendIconServicesJournalCheckpoint(", helper)
        self.assertNotIn("CNDRemixWriteIconServicesJournal(", helper)
        self.assertIn("@[@(variantIndex)]", helper)

        # Both the already-stock classification and the matrix result commit
        # the variant's own state before the application-level verdict exists.
        app_verified = self.restore.index("BOOL appVerified = allVerified &&")
        self.assertEqual(
            self.restore.count("CNDRemixCommitRestoreVariantState("), 2
        )
        for marker in (
            'variantJournal[@"state"] =\n'
            '                                @"persistent-stock-verified";',
            'variantJournal[@"state"] = verified',
        ):
            committed = self.restore.index(marker)
            commit = self.restore.index(
                "CNDRemixCommitRestoreVariantState(", committed
            )
            self.assertLess(committed, commit)
            self.assertLess(commit, app_verified)
            self.assertIn("allVerified = NO;", self.restore[commit:commit + 400])

        # The application record never rewrites a variant's own state: a
        # partial restore keeps its journal under its own partial state, and
        # only a fully verified matrix retires it.
        self.assertIn(
            'journal[@"state"] = appVerified\n'
            '                        ? @"persistent-stock-verified"\n'
            '                        : @"restore-partial";',
            self.restore,
        )
        self.assertIn("BOOL journalCleared = appVerified &&", self.restore)
        self.assertIn(
            'journal[@"state"] = appVerified\n'
            '                        ? @"persistent-stock-verified"\n'
            '                        : @"restore-partial";',
            self.restore[:self.restore.index("BOOL journalCleared = appVerified &&")],
        )

    def test_restore_accepts_only_a_journaled_sibling_index_alias(self) -> None:
        # IconServices aliases renditions onto one unit, so an index naming a
        # sibling variant's unit is legitimate. Nothing else about the
        # publisher's proof may be relaxed to reach that verdict.
        helper_start = self.source.index(
            "static BOOL CNDRemixRestorationIndexAliasesSiblingUnit("
        )
        helper_end = self.source.index(
            "static BOOL CNDRemixReconcileAirDropJournalToCurrentStockInBatch(",
            helper_start,
        )
        helper = self.source[helper_start:helper_end]
        for term in (
            'restoration[@"deferredVerificationAudit"]',
            '@"storeUnitPresent"', '@"storeUnitValid"',
            '@"deferredStoreProof"', '@"byte-exact"', '@"stock-class-identity"',
            '@"storeIndexEntryPresent"', '@"storeValidationTokenSHA256"',
            '@"storeIndexUnitIdentifierEqual"', '@"transactionStarted"',
            '@"stockCaptured"', '@"persistentIndexIdentitySettled"',
            '@"persistentIndexScratchLifecycleVerified"',
            '@"directStoreRemoveVerified"', '@"directStoreWriteIssued"',
            '@"directStoreWriteAcknowledged"',
            '@"sourceIdentityMatchesCurrentRecord"',
        ):
            self.assertIn(term, helper)
        # The aliased unit must belong to a different variant of this journal,
        # and never to the variant being restored.
        self.assertIn("savedVariants", helper)
        self.assertIn(
            "siblingIdentity.length == 0 ||\n"
            "            [siblingIdentity isEqualToString:ownIdentity]) continue;",
            helper,
        )
        self.assertIn("[indexedIdentifier isEqualToString:storeIdentifier]", helper)

        # The themed-payload veto still runs first and still forces failure:
        # the alias acceptance is gated on it and cannot undo it.
        veto = self.restore.index("BOOL themedReadback =")
        call = self.restore.index("CNDRemixRestorationIndexAliasesSiblingUnit(")
        commit = self.restore.index("CNDRemixCommitRestoreVariantState(", call)
        self.assertLess(veto, call)
        self.assertLess(call, commit)
        self.assertIn(
            "if (themedReadback) {\n"
            "                            verified = NO;",
            self.restore[veto:call],
        )
        self.assertIn(
            "BOOL aliasedSibling = !verified && !themedReadback &&",
            self.restore[veto:call],
        )
        self.assertIn('variantJournal[@"indexProof"] = indexProof;',
                      self.restore[call:commit])
        result = self.restore.index("resultByIndex[@(variantIndex)] = @{", commit)
        counted = self.restore.index("restoredVariants++;", result)
        self.assertIn('@"indexProof": indexProof ?: @"none",',
                      self.restore[result:counted])

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"),
                         "requires macOS Foundation and clang")
    def test_index_alias_helper_rejects_everything_but_a_journaled_sibling(
        self,
    ) -> None:
        catalog = self.source[
            self.source.index("static NSString *CNDRemixCatalogText("):
            self.source.index("/* AirDrop's activity identity")
        ]
        sha = self.source[
            self.source.index("static BOOL CNDRemixIsSHA256String(NSString *value)\n{"):
            self.source.index("static NSString *CNDRemixPayloadPlatformIdentifier(")
        ]
        helper = self.source[
            self.source.index("static BOOL CNDRemixRestorationIndexAliasesSiblingUnit("):
            self.source.index(
                "static BOOL CNDRemixReconcileAirDropJournalToCurrentStockInBatch(")
        ]
        with tempfile.TemporaryDirectory(prefix="cyanide-index-alias-") as directory:
            source = Path(directory) / "alias.m"
            executable = Path(directory) / "alias"
            source.write_text(
                "#import <Foundation/Foundation.h>\n#include <stdio.h>\n"
                "static BOOL CNDIconServicesPublisherRestorationResultIsVerified("
                "NSDictionary *report) { return NO; }\n"
                + catalog + sha + helper + ALIAS_HARNESS,
                encoding="utf-8",
            )
            subprocess.run(
                ["clang", "-fobjc-arc", "-framework", "Foundation",
                 str(source), "-o", str(executable)], check=True, capture_output=True,
            )
            subprocess.run([str(executable)], check=True, capture_output=True)

    def test_readback_of_the_themed_payload_is_never_stock(self) -> None:
        # IconServices aliases renditions onto one unit, so a styled unit can
        # satisfy a stock-class identity check. A readback equal to the
        # journaled themed payload is rejected before the variant commits.
        self.assertIn(
            "static BOOL CNDRemixReadbackCarriesThemedPayload(\n"
            "    id readbackSHA256, NSDictionary *variant)",
            self.source,
        )
        self.assertIn('CNDRemixCatalogText(variant, @"structuredImageSHA256")',
                      self.source)
        # Already-stock classification: the pre-dispatch audit's unit bytes
        # veto the classification, which is what the variant commits on.
        already_stock = self.restore.index("BOOL alreadyStock = validatedSpec &&")
        commit = self.restore.index(
            "CNDRemixCommitRestoreVariantState(", already_stock
        )
        self.assertIn(
            "if (CNDRemixReadbackCarriesThemedPayload(\n"
            '                                stockAudit[@"storeDataSHA256"],\n'
            "                                savedVariant)) {\n"
            "                            alreadyStock = NO;",
            self.restore[already_stock:commit],
        )
        # Matrix result: the restore report's own store readback, or the
        # post-restore audit's, vetoes the verdict before the commit.
        guard = self.restore.index(
            'restoration[@"persistentStoreDataSHA256"] ?:'
        )
        commit = self.restore.index("CNDRemixCommitRestoreVariantState(", guard)
        self.assertIn("verified = NO;", self.restore[guard:commit])

    def test_apply_uses_bounded_deltas_and_restore_uses_one_atomic_matrix_write(self) -> None:
        apply_start = self.source.index("for (NSUInteger variantIndex = 0;", self.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        ))
        apply_end = self.source.index("BOOL appVerified =", apply_start)
        apply_loop = self.source[apply_start:apply_end]
        self.assertIn("CNDRemixAppendIconServicesJournalCheckpoint(", apply_loop)
        self.assertNotIn("CNDRemixWriteIconServicesJournal(", apply_loop)

        restore_start = self.restore.index("for (NSUInteger variantIndex = 0;")
        restore_end = self.restore.index("BOOL appVerified = allVerified &&", restore_start)
        restore_loop = self.restore[restore_start:restore_end]
        self.assertNotIn("CNDRemixAppendIconServicesJournalCheckpoint(", restore_loop)
        self.assertEqual(
            restore_loop.count("CNDRemixWriteIconServicesJournal(journal);"),
            1,
        )

        helper_start = self.source.index(
            "static BOOL CNDRemixAppendIconServicesJournalCheckpoint("
        )
        helper_end = self.source.index(
            "static BOOL CNDRemixRemoveIconServicesJournal(", helper_start
        )
        helper = self.source[helper_start:helper_end]
        self.assertIn("CNDRemixIconServicesCheckpointMaximumVariantUpdates", helper)
        self.assertIn("variantIndexes.count", helper)


if __name__ == "__main__":
    unittest.main()
