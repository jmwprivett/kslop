"""Deep live repair can classify conclusive stock-cache/themed-store drift."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REMIX = ROOT / "Cyanide/installer/CNDSnowBoardRemix.m"
ADAPTER = ROOT / "Cyanide/installer/CNDIconServicesPublisherRemoteTransport.m"


class RemixCacheStockRepairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.remix = REMIX.read_text(encoding="utf-8")
        cls.adapter = ADAPTER.read_text(encoding="utf-8")

    def test_conclusive_stock_cache_drift_is_a_selective_repair_target(self) -> None:
        start = self.remix.rindex(
            "static NSDictionary *CNDRemixAuditActiveJournalForRepairInBatch("
        )
        end = self.remix.index(
            "static NSDictionary *CNDRemixCompareAppliedAuditRecords(", start
        )
        audit = self.remix[start:end]

        self.assertIn("BOOL cacheStockMismatch = themed &&", audit)
        self.assertIn('audit, @"cacheResponsePresent", YES', audit)
        self.assertIn('isEqualToString:@"stock"', audit)
        self.assertIn('audit, @"cacheStoreEqual", NO', audit)
        self.assertIn('? @"cache-stock-mismatch"', audit)
        self.assertIn(
            "if (cacheStockMismatch) {\n"
            '            [repairSpecifications addObject:record[@"specification"]];',
            audit,
        )
        self.assertLess(
            audit.index("if (cacheStockMismatch) {"),
            audit.index("} else if (themed) {"),
        )
        self.assertIn(
            '@"cacheStockMismatchVariantCount": @(cacheStockMismatchCount)',
            audit,
        )

    def test_cache_drift_uses_existing_audit_without_an_extra_remote_pass(self) -> None:
        start = self.remix.rindex(
            "static NSDictionary *CNDRemixAuditActiveJournalForRepairInBatch("
        )
        end = self.remix.index(
            "static NSDictionary *CNDRemixCompareAppliedAuditRecords(", start
        )
        audit = self.remix[start:end]

        self.assertEqual(
            audit.count("CNDIconServicesPublisherAuditVariantsInBatch("), 1
        )
        self.assertNotIn("CNDIconServicesPublisherAuditVariantInBatch(", audit)

    def test_cache_drift_count_survives_publication_result_and_summary(self) -> None:
        for field in (
            '@"livePersistenceRepairCacheStockMismatchVariants"',
            '@"liveRepairCacheStockMismatchVariants"',
            '@"liveRepairCacheStockMismatchVariants":',
        ):
            self.assertIn(field, self.remix)

    def test_byte_different_unmarked_store_is_a_selective_repair_target(self) -> None:
        start = self.remix.rindex(
            "static NSDictionary *CNDRemixAuditActiveJournalForRepairInBatch("
        )
        end = self.remix.index(
            "static NSDictionary *CNDRemixCompareAppliedAuditRecords(", start
        )
        audit = self.remix[start:end]

        self.assertIn("BOOL unmarkedStore = readOnly &&", audit)
        self.assertIn('isEqualToString:@"other"', audit)
        self.assertIn('audit, @"storeThemeMarkerPresent", NO', audit)
        self.assertIn('? @"unmarked-store"', audit)
        self.assertIn(
            "} else if (unmarkedStore) {\n"
            '            [repairSpecifications addObject:record[@"specification"]];',
            audit,
        )
        self.assertIn(
            '@"unmarkedStoreVariantCount": @(unmarkedStoreCount)', audit
        )

    def test_unmarked_store_count_survives_publication_result_and_summary(self) -> None:
        for field in (
            '@"livePersistenceRepairUnmarkedStoreVariants"',
            '@"liveRepairUnmarkedStoreVariants"',
            '@"liveRepairUnmarkedStoreVariants":',
        ):
            self.assertIn(field, self.remix)

    def test_transport_checks_the_existing_readback_for_the_theme_marker(self) -> None:
        self.assertIn("NSData *themeMarker = [CNDIconServicesThemeMarker", self.adapter)
        self.assertIn("storeThemeMarkerPresent = storeData.length", self.adapter)
        self.assertIn('@"storeThemeMarkerPresent": @(storeThemeMarkerPresent)', self.adapter)

    def test_empty_current_journal_matrix_does_not_invent_a_legacy_variant(self) -> None:
        start = self.remix.index(
            "static NSArray<NSDictionary *> *CNDRemixJournalVariants("
        )
        end = self.remix.index("\n}\n", start)
        helper = self.remix[start:end]
        self.assertIn("return variants ?: @[];", helper)
        self.assertNotIn("variants.count > 0", helper)

    def test_known_empty_retention_duplicate_has_an_exact_migration(self) -> None:
        start = self.remix.index(
            "static NSDictionary *CNDRemixRepairEmptyRetentionDuplicateJournal("
        )
        end = self.remix.index("\n}\n", start)
        migration = self.remix[start:end]
        self.assertIn("variants.count != specifications.count + 1U", migration)
        self.assertIn("legacyCount != 2U", migration)
        self.assertIn("latestByIdentity[identity] = variant;", migration)
        self.assertIn("CNDRemixWriteIconServicesJournal(corrected)", migration)

    def test_update_repair_reports_pending_instead_of_refreshing_or_respringing(self) -> None:
        self.assertNotIn("CNDRemixRunUpdateRepairCacheRefresh", self.remix)
        self.assertIn('@"stage": @"presentation-pending"', self.remix)
        self.assertIn('@"presentationPending": @YES', self.remix)
        self.assertIn('@"respringRequired": @NO', self.remix)
        self.assertIn('@"presentation-pending-no-live-refresh"', self.remix)
        self.assertIn(
            "successfullyPublishedIdentifiers.allObjects", self.remix
        )
        self.assertIn(
            '@"presentationPendingBundleIdentifiers":', self.remix
        )
        self.assertNotIn('@"bounded-update-repair-refresh"', self.remix)
        self.assertNotIn('@"full-respring-required"', self.remix)

    def test_one_verified_repair_reports_pending_even_if_run_is_partial(self) -> None:
        start = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)repairInstalledApplicationUpdatesWithProgress:"
        )
        end = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)applySelectedThemeForBundleIdentifiers:",
            start,
        )
        repair = self.remix[start:end]
        self.assertIn("BOOL presentationPending = repairedApplications > 0;", repair)
        self.assertIn('repair[@"presentationPending"] = @(presentationPending);', repair)
        self.assertIn('repair[@"respringRecommended"] = @NO;', repair)
        self.assertIn('repair[@"respringRequired"] = @NO;', repair)
        self.assertIn('@"update-repair-partial-presentation-pending"', repair)


if __name__ == "__main__":
    unittest.main()
