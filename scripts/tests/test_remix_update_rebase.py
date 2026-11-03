"""Static safety checks for SnowBoard Remix's app-update journal rebase."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REMIX = ROOT / "Cyanide/installer/CNDSnowBoardRemix.m"
REMIX_HEADER = ROOT / "Cyanide/installer/CNDSnowBoardRemix.h"
ADAPTER = ROOT / "Cyanide/installer/CNDIconServicesPublisherRemoteTransport.m"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"
SNOWBOARD = ROOT / "Cyanide/tweaks/snowboardlite.m"


class RemixUpdateRebaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.remix = REMIX.read_text(encoding="utf-8")
        cls.remix_header = REMIX_HEADER.read_text(encoding="utf-8")
        cls.adapter = ADAPTER.read_text(encoding="utf-8")
        cls.settings = SETTINGS.read_text(encoding="utf-8")
        cls.snowboard = SNOWBOARD.read_text(encoding="utf-8")

    def test_catalog_uses_same_pinned_session_and_returns_update_metadata(self) -> None:
        start = self.adapter.index(
            "- (NSDictionary<NSString *, id> *)copyInstalledBundleIdentifiersInBatch"
        )
        end = self.adapter.index(
            "\n- (NSDictionary<NSString *, id> *)publishBundleIdentifier:", start
        )
        catalog = self.adapter[start:end]
        self.assertIn("cnd_publisher_batch_state()", catalog)
        self.assertIn("state.session", catalog)
        self.assertNotIn("cnd_publisher_open_agent_session", catalog)
        for field in (
            '"bundleIdentifier"', '"bundleURL"', '"shortVersionString"',
            '"bundleVersion"', '"externalVersionIdentifier"',
        ):
            self.assertIn(field, catalog)
        self.assertIn('@"applicationRecords": applicationRecords', catalog)

    def test_active_shortcut_requires_current_application_fingerprint(self) -> None:
        start = self.remix.index("static BOOL CNDRemixJournalMatchesCurrentApplication(")
        end = self.remix.index("\n}\n", start)
        matcher = self.remix[start:end]
        self.assertIn("CNDRemixJournalIsCompleteActiveMatrix(", matcher)
        self.assertIn("CNDRemixApplicationFingerprintMatches(", matcher)
        self.assertIn('journal[@"applicationFingerprint"]', matcher)

    def test_changed_install_restores_stock_before_new_journal_and_publish(self) -> None:
        helper_start = self.remix.index(
            "static NSDictionary *CNDRemixRebaseActiveJournalToCurrentStock("
        )
        helper_end = self.remix.index(
            "\nstatic NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme(",
            helper_start,
        )
        helper = self.remix[helper_start:helper_end]
        self.assertIn("CNDIconServicesPublisherRestoreStockVariantInBatch(", helper)
        self.assertIn('journal[@"state"] = @"update-rebase-restoring";', helper)
        self.assertIn('journal[@"state"] = @"persistent-stock-verified";', helper)
        self.assertLess(
            helper.index('journal[@"state"] = @"persistent-stock-verified";'),
            helper.index("CNDRemixRemoveIconServicesJournal(bundleIdentifier)"),
        )
        restore_loop = helper[
            helper.index("for (NSUInteger index = 0;"):
            helper.index("BOOL complete =", helper.index("for (NSUInteger index = 0;"))
        ]
        self.assertIn("CNDRemixAppendIconServicesJournalCheckpoint(", restore_loop)
        self.assertNotIn("CNDRemixWriteIconServicesJournal(", restore_loop)

        apply_start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        apply_end = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals(",
            apply_start,
        )
        apply = self.remix[apply_start:apply_end]
        rebase_call = apply.index("CNDRemixRebaseActiveJournalToCurrentStock(")
        new_journal = apply.index(
            "NSMutableDictionary *journal = retainedJournal.count",
            rebase_call,
        )
        publish = apply.index("CNDIconServicesPublisherPublishVariantInBatch(", new_journal)
        self.assertLess(rebase_call, new_journal)
        self.assertLess(new_journal, publish)
        self.assertIn('journal[@"applicationFingerprint"]', apply[new_journal:publish])

    def test_legacy_journal_adoption_is_metadata_only(self) -> None:
        start = self.remix.index("BOOL lacksSavedFingerprint =")
        end = self.remix.index(
            "BOOL journalMatchesCurrentApplication =", start
        )
        adoption = self.remix[start:end]
        self.assertIn('migrated[@"applicationFingerprint"]', adoption)
        self.assertIn("CNDRemixWriteIconServicesJournal(migrated)", adoption)
        self.assertNotIn("CNDIconServicesPublisherRestore", adoption)
        self.assertNotIn("CNDIconServicesPublisherPublish", adoption)

    def test_update_repair_enables_live_persistence_audit(self) -> None:
        selector = "repairInstalledApplicationUpdatesWithProgress:"
        self.assertIn(selector, self.remix_header)
        start = self.remix.index(f"+ (NSDictionary<NSString *, id> *){selector}")
        end = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)applySelectedThemeForBundleIdentifiers:",
            start,
        )
        repair = self.remix[start:end]
        self.assertIn(
            "CNDRemixApplyIconServicesTheme(\n"
            "            nil, YES, NO, YES, progress, cancellation)",
            repair,
        )
        self.assertIn('@"operationMode"] = @"update-repair"', repair)
        self.assertIn('@"liveRepairApplications"]', repair)
        self.assertIn("substantialApplicationThreshold = 8U", repair)
        self.assertIn("substantialVariantThreshold = 48U", repair)
        self.assertIn('@"substantialRepairPerformed"]', repair)
        self.assertIn('@"respringRecommended"]', repair)
        self.assertIn('[repair[@"applied"] unsignedIntegerValue]', repair)
        self.assertIn(
            '[repair[@"publishedVariants"] unsignedIntegerValue]', repair
        )
        self.assertIn('[repair[@"ok"] boolValue] &&', repair)
        self.assertNotIn("elapsedMilliseconds", repair)
        self.assertNotIn("CNDIconServicesPublisherBeginBatch(", repair)
        self.assertNotIn("CNDIconServicesPublisherPublishVariantInBatch(", repair)

    def test_normal_apply_does_not_pay_for_live_persistence_audit(self) -> None:
        start = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)applySelectedThemeWithProgress:"
        )
        end = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)repairInstalledApplicationUpdatesWithProgress:",
            start,
        )
        apply = self.remix[start:end]
        self.assertIn(
            "CNDRemixApplyIconServicesTheme(\n"
            "            nil, YES, NO, NO, progress, cancellation)",
            apply,
        )

    def test_live_repair_is_read_only_fail_closed_and_selective(self) -> None:
        start = self.remix.index(
            "static BOOL CNDRemixAuditIsStrictReadOnlyObservation("
        )
        end = self.remix.index(
            "static NSDictionary *CNDRemixCompareAppliedAuditRecords(", start
        )
        repair = self.remix[start:end]
        for field in (
            '@"transportHealthy", YES',
            '@"persistentMutationsIssued", NO',
            '@"presentationMutationsIssued", NO',
            '@"mutationsIssued", NO',
            '@"generationIssued", NO',
            '@"cachePurgeIssued", NO',
            '@"storeWriteIssued", NO',
        ):
            self.assertIn(field, repair)
        for missing_field in (
            '@"storeIndexEntryPresent", NO',
            '@"storeUnitPresent", NO',
        ):
            self.assertIn(missing_field, repair)
        missing_start = repair.index(
            "static BOOL CNDRemixAuditProvesPersistentRecordMissing("
        )
        missing_end = repair.index(
            "static NSDictionary *CNDRemixAuditActiveJournalForRepairInBatch(",
            missing_start,
        )
        self.assertNotIn(
            '@"cacheResponsePresent", NO', repair[missing_start:missing_end]
        )
        self.assertIn("CNDRemixAppliedAuditRecordProvesThemedPersistence", repair)
        self.assertIn('isEqualToString:@"stock"', repair)
        self.assertIn('@"live-persistence-ambiguous"', repair)
        self.assertIn('@"retainedVariants": retainedVariants', repair)
        self.assertIn('@"repairSpecifications": repairSpecifications', repair)
        self.assertIn("CNDIconServicesPublisherAuditVariantsInBatch(", repair)
        self.assertIn('@"transportMatrix": matrixSummary', repair)
        self.assertNotIn("CNDIconServicesPublisherAuditVariantInBatch(", repair)

    def test_live_repair_prunes_only_repair_targets_before_publication(self) -> None:
        apply_start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        apply_end = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals(",
            apply_start,
        )
        apply = self.remix[apply_start:apply_end]
        audit = apply.index("CNDRemixAuditActiveJournalForRepairInBatch(")
        prune = apply.index(
            'retainedJournal[@"variants"] =\n'
            '                                liveRepairAudit[@"retainedVariants"]',
            audit,
        )
        checkpoint = apply.index(
            "CNDRemixWriteIconServicesJournal(journal)", prune
        )
        publish = apply.index(
            "CNDIconServicesPublisherPublishVariantInBatch(", checkpoint
        )
        self.assertLess(audit, prune)
        self.assertLess(prune, checkpoint)
        self.assertLess(checkpoint, publish)
        self.assertIn(
            "publicationSpecifications =\n"
            "                            liveRepairSpecifications.count > 0",
            apply,
        )

    def test_descriptor_matrix_reuses_per_application_source_hash(self) -> None:
        apply_start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        apply_end = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals(",
            apply_start,
        )
        apply = self.remix[apply_start:apply_end]
        self.assertIn("NSString *variantSourceHash = sourceHash;", apply)
        self.assertNotIn("CNDRemixSHA256(variantSource)", apply)

    def test_update_repair_button_uses_bounded_public_entry_point(self) -> None:
        self.assertIn('@"title": @"Update Repair"', self.settings)
        self.assertIn('@"action": @"sbl-update-repair"', self.settings)
        self.assertIn("settings_update_repair_snowboard_remix()", self.settings)
        self.assertIn(
            "repairInstalledApplicationUpdatesWithProgress:", self.snowboard
        )

    def test_automatic_repair_is_coalesced_and_reuses_existing_krw(self) -> None:
        self.assertIn('@"title": @"Automatic Repair"', self.settings)
        self.assertNotIn(
            'notify_register_dispatch("com.apple.mobile.application_updated"',
            self.settings,
        )
        self.assertNotIn(
            'notify_register_dispatch("com.apple.LaunchServices.ApplicationsChanged"',
            self.settings,
        )
        start = self.settings.index(
            "static BOOL settings_run_snowboard_automatic_repair("
        )
        end = self.settings.index(
            "static void settings_schedule_snowboard_automatic_repair_internal(",
            start,
        )
        automatic = self.settings[start:end]
        self.assertIn("kexploit_krw_ready()", automatic)
        self.assertNotIn("settings_ensure_kexploit()", automatic)
        self.assertIn("settings_update_repair_snowboard_remix()", automatic)
        self.assertIn("setTransparencyFixEnabled:YES", automatic)
        self.assertIn("packageQueue.commitInFlight", automatic)


if __name__ == "__main__":
    unittest.main()
