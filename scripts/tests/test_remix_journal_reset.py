"""Host-only contract checks for the explicit IconServices journal reset."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "Cyanide/installer/CNDSnowBoardRemix.h"
REMIX = ROOT / "Cyanide/installer/CNDSnowBoardRemix.m"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"


class RemixJournalResetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = HEADER.read_text(encoding="utf-8")
        cls.source = REMIX.read_text(encoding="utf-8")
        cls.settings = SETTINGS.read_text(encoding="utf-8")
        start = cls.source.index(
            "+ (NSDictionary<NSString *, id> *)resetIconServicesJournals"
        )
        end = cls.source.index("\n+ (BOOL)hasRecoveryData", start)
        cls.operation = cls.source[start:end]

    def test_public_api_and_button_are_explicitly_manual(self) -> None:
        self.assertIn("resetIconServicesJournals", self.header)
        self.assertIn('"title": @"Reset IconServices Journals"', self.settings)
        self.assertIn('"action": @"sbl-reset-journals"', self.settings)
        self.assertIn(
            "Use after you have confirmed the live icons are stock",
            self.settings,
        )

    def test_reset_only_removes_local_iconservices_journals(self) -> None:
        self.assertIn("CNDRemixIconServicesJournals()", self.operation)
        self.assertIn(
            "CNDRemixRemoveIconServicesJournal(bundleIdentifier)",
            self.operation,
        )
        self.assertIn('"stockAuditPerformed": @NO', self.operation)
        self.assertIn('"operatorStockAssertionRequired": @YES', self.operation)
        self.assertIn('"iconServicesMutationsIssued": @NO', self.operation)

        for forbidden in (
            "CNDRemixAuditProvesSavedStock(",
            "CNDIconServicesPublisherBeginBatch(",
            "CNDIconServicesPublisherAudit",
            "CNDIconServicesPublisherPublish",
            "CNDIconServicesPublisherRestore",
        ):
            self.assertNotIn(forbidden, self.operation)

    def test_button_does_not_require_krw_and_serializes_with_apply_restore(self) -> None:
        action_start = self.settings.index(
            '[action isEqualToString:@"sbl-reset-journals"]'
        )
        action_end = self.settings.index(
            '[action isEqualToString:@"sbl-airdrop-test-apply"]', action_start
        )
        action = self.settings[action_start:action_end]
        self.assertIn('settings_run_snowboard_remix_operation(\n'
                      '                    @"Reset IconServices Journals", NO, ^{',
                      action)
        gate = action.index("settings_begin_snowboard_mutation(YES);")
        reset = action.index("resetIconServicesJournals")
        release = action.index("settings_end_snowboard_mutation();")
        self.assertLess(gate, reset)
        self.assertLess(reset, release)

    def test_next_apply_will_not_see_reset_journals_as_active(self) -> None:
        remove = self.operation.index(
            "CNDRemixRemoveIconServicesJournal(bundleIdentifier)"
        )
        self.assertIn('"removed": @(removed)', self.operation[remove:])
        self.assertIn('"localJournalMutationsIssued": @(clearedCount > 0)',
                      self.operation)
        self.assertNotIn("CNDRemixWriteIconServicesJournal(", self.operation)


if __name__ == "__main__":
    unittest.main()
