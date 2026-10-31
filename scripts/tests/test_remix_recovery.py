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
        generation = self.restore.index("CNDIconServicesPublisherRestoreStockVariantInBatch(")
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

    def test_restore_checkpoints_only_the_descriptor_about_to_mutate(self) -> None:
        audit = self.restore.index("CNDIconServicesPublisherAuditVariantInBatch(")
        restoring = self.restore.index('dispatchVariant[@"state"] = @"restoring";')
        checkpoint = self.restore.index(
            "CNDRemixAppendIconServicesJournalCheckpoint(", restoring
        )
        generation = self.restore.index("CNDIconServicesPublisherRestoreStockVariantInBatch(")
        self.assertLess(audit, restoring)
        self.assertLess(restoring, checkpoint)
        self.assertLess(checkpoint, generation)
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
            "CNDIconServicesPublisherRestoreStockVariantInBatch("
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

    def test_apply_coalesces_result_and_next_dispatch_checkpoint(self) -> None:
        start = self.source.index("BOOL currentDispatchCheckpointed = NO;")
        end = self.source.index(
            "BOOL failedPublicationVerifiedStock", start
        )
        publication_loop = self.source[start:end]
        self.assertIn("if (!currentDispatchCheckpointed)", publication_loop)
        result = publication_loop.index(
            'variantJournal[@"publication"] ='
        )
        next_dispatch = publication_loop.index(
            "NSMutableDictionary *nextDispatch", result
        )
        checkpoint = publication_loop.index(
            "CNDRemixAppendIconServicesJournalCheckpoint(", next_dispatch
        )
        self.assertLess(result, next_dispatch)
        self.assertLess(next_dispatch, checkpoint)
        self.assertIn(
            "currentDispatchCheckpointed =\n"
            "                            batchHealthy && hasNext;",
            publication_loop,
        )

    def test_descriptor_loops_use_bounded_deltas_not_full_journal_rewrites(self) -> None:
        apply_start = self.source.index("for (NSUInteger variantIndex = 0;", self.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        ))
        apply_end = self.source.index("BOOL appVerified =", apply_start)
        apply_loop = self.source[apply_start:apply_end]
        self.assertIn("CNDRemixAppendIconServicesJournalCheckpoint(", apply_loop)
        self.assertNotIn("CNDRemixWriteIconServicesJournal(", apply_loop)

        restore_start = self.restore.index("for (NSUInteger variantIndex = 0;")
        restore_end = self.restore.index('journal[@"state"] = allVerified &&', restore_start)
        restore_loop = self.restore[restore_start:restore_end]
        self.assertIn("CNDRemixAppendIconServicesJournalCheckpoint(", restore_loop)
        self.assertNotIn("CNDRemixWriteIconServicesJournal(", restore_loop)

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
