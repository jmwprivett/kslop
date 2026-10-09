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
        self.assertIn('@"journalCleanupOK": @(discardFailures == 0)', early)
        self.assertIn('NSUInteger failed = 0, plannedVariants = 0;', self.restore)
        self.assertIn("persistentClean = discardedUnmutated + discardFailures;", self.restore)

    def test_restore_checkpoints_only_the_descriptor_about_to_mutate(self) -> None:
        audit = self.restore.index("CNDIconServicesPublisherAuditVariantInBatch(")
        restoring = self.restore.index('dispatchVariant[@"state"] = @"restoring";')
        checkpoint = self.restore.index("CNDRemixWriteIconServicesJournal(journal)", restoring)
        generation = self.restore.index("CNDIconServicesPublisherRestoreStockVariantInBatch(")
        self.assertLess(audit, restoring)
        self.assertLess(restoring, checkpoint)
        self.assertLess(checkpoint, generation)
        self.assertNotIn('journal[@"state"] = @"restoring";', self.restore[:audit])

    def test_verified_stock_journal_cleanup_does_not_count_as_dirty_failure(self) -> None:
        self.assertIn("else if (appVerified) {\n                        journalCleanupFailures++;", self.restore)
        self.assertIn('@"ok": @(appVerified)', self.restore)
        self.assertIn('@"journalCleanupOK": @(journalCleanupFailures == 0)', self.restore)

    def test_restore_springboard_session_is_not_skipped(self) -> None:
        helper_start = self.source.index(
            "CNDRemixRestoreSpringBoardPresentationIfNeeded("
        )
        helper_end = self.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals(",
            helper_start,
        )
        helper = self.source[helper_start:helper_end]
        repair = helper.index(
            "CNDIconServicesConsumerLifecycleRepairProcess("
        )
        self.assertGreater(repair, 0)
        self.assertNotIn("springboard-session-not-required", helper)
        self.assertIn("CNDRemixEnableSpringBoardCacheInvalidation", helper)
        self.assertIn("CNDRemixRemoveSpringBoardDynamicPresentationState()", helper)
        self.assertIn(
            "CNDRemixRestoreSpringBoardPresentationIfNeeded(YES)",
            self.restore,
        )

    def test_dynamic_presentation_marker_is_pid_bound_and_durable(self) -> None:
        self.assertIn(
            '@"SpringBoardDynamicPresentation.plist"', self.source
        )
        self.assertIn(
            'CNDKernelTaskBridgeResolveProcessPID(\n        @"SpringBoard"',
            self.source,
        )
        self.assertIn("livePID == recordedPID", self.source)
        apply_start = self.source.index(
            "+ (NSDictionary<NSString *, id> *)applySpringBoardTweaks"
        )
        apply_end = self.source.index(
            "+ (NSDictionary<NSString *, id> *)repairSpotlightPresentation",
            apply_start,
        )
        apply = self.source[apply_start:apply_end]
        self.assertIn(
            "CNDRemixWriteSpringBoardDynamicPresentationState(", apply
        )
        self.assertIn('@"dynamicPresentationStateRecorded"', apply)
        restore_all_start = self.source.index(
            "+ (NSDictionary<NSString *, id> *)restoreAllWithProgress:"
        )
        restore_all = self.source[restore_all_start:]
        self.assertIn("hasLiveDynamicPresentation", restore_all)
        self.assertIn(
            "if (hasIconServicesJournals || hasLiveDynamicPresentation)",
            restore_all,
        )


if __name__ == "__main__":
    unittest.main()
