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
            "NSMutableDictionary *journal = profileExpansionJournal.count",
            rebase_call,
        )
        publish = apply.index("CNDIconServicesPublisherPublishVariantInBatch(", new_journal)
        self.assertLess(rebase_call, new_journal)
        self.assertLess(new_journal, publish)
        self.assertIn('journal[@"applicationFingerprint"]', apply[new_journal:publish])

    def test_legacy_journal_adoption_is_metadata_only(self) -> None:
        start = self.remix.index("BOOL lacksSavedFingerprint =")
        end = self.remix.index(
            "if (CNDRemixJournalMatchesCurrentApplication(", start
        )
        adoption = self.remix[start:end]
        self.assertIn('migrated[@"applicationFingerprint"]', adoption)
        self.assertIn("CNDRemixWriteIconServicesJournal(migrated)", adoption)
        self.assertNotIn("CNDIconServicesPublisherRestore", adoption)
        self.assertNotIn("CNDIconServicesPublisherPublish", adoption)

    def test_manual_update_repair_reuses_fingerprint_aware_publisher(self) -> None:
        selector = "repairInstalledApplicationUpdatesWithProgress:"
        self.assertIn(selector, self.remix_header)
        start = self.remix.index(f"+ (NSDictionary<NSString *, id> *){selector}")
        end = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)applySelectedThemeForBundleIdentifiers:",
            start,
        )
        repair = self.remix[start:end]
        self.assertIn("CNDRemixApplyIconServicesTheme(progress, cancellation)", repair)
        self.assertIn('@"operationMode"] = @"update-repair"', repair)
        self.assertNotIn("CNDIconServicesPublisherBeginBatch(", repair)
        self.assertNotIn("CNDIconServicesPublisherPublishVariantInBatch(", repair)

    def test_update_repair_button_uses_bounded_public_entry_point(self) -> None:
        self.assertIn('@"title": @"Update Repair"', self.settings)
        self.assertIn('@"action": @"sbl-update-repair"', self.settings)
        self.assertIn("settings_update_repair_snowboard_remix()", self.settings)
        self.assertIn(
            "repairInstalledApplicationUpdatesWithProgress:", self.snowboard
        )


if __name__ == "__main__":
    unittest.main()
