"""Safety checks for reusing inherited SnowBoard Remix Apply journals."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REMIX = ROOT / "Cyanide/installer/CNDSnowBoardRemix.m"


class RemixApplyJournalReuseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = REMIX.read_text(encoding="utf-8")
        matcher_start = cls.source.index(
            "static BOOL CNDRemixInheritedJournalMatchesRequestedTransaction("
        )
        rebase_start = cls.source.index(
            "static NSDictionary *CNDRemixRebaseActiveJournalToCurrentStock("
        )
        apply_start = cls.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        restore_start = cls.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals("
        )
        cls.matcher = cls.source[matcher_start:rebase_start]
        cls.apply = cls.source[apply_start:restore_start]

    def test_only_the_exact_requested_journal_is_reused(self) -> None:
        for required in (
            'journal[@"schemaVersion"]',
            "CNDRemixIconServicesJournalSchemaVersion",
            'journal[@"storePreservationPolicyVersion"]',
            "CNDRemixStorePreservationPolicyVersion",
            'journal[@"state"] isEqualToString:@"recovery-required"',
            'journal[@"themeSourceSHA256"] isEqualToString:sourceHash',
            "CNDRemixDescriptorProfileIdentity(",
            "CNDRemixApplicationFingerprintMatches(",
            "variants.count != specifications.count",
            "savedSpecification.canonicalIdentity",
        ):
            self.assertIn(required, self.matcher)

    def test_reuse_performs_no_stock_restore_or_republication(self) -> None:
        admission = self.apply.index("if (canReuseInheritedJournal) {")
        pending = self.apply.index(
            "[inheritedJournalPending addObject:", admission
        )
        stop = self.apply.index("continue;", pending)
        block = self.apply[admission:stop]
        self.assertNotIn("CNDIconServicesPublisherRestore", block)
        self.assertNotIn("CNDIconServicesPublisherPublish", block)
        self.assertNotIn("structuredImageData", block)
        self.assertNotIn("replay", self.apply.lower())

    def test_inherited_journals_finalize_only_after_clean_batch_close(self) -> None:
        finish = self.apply.index("CNDIconServicesPublisherFinishBatch()")
        loop = self.apply.index(
            "for (NSDictionary *pending in inheritedJournalPending)", finish
        )
        allowed = self.apply.index(
            "BOOL inheritedFinalizationAllowed = sessionClosed && !cancelled &&",
            finish,
        )
        session_gate = self.apply.index("if (!inheritedFinalizationAllowed)", loop)
        active = self.apply.index('updated[@"state"] = @"active";', session_gate)
        write = self.apply.index("CNDRemixWriteIconServicesJournal(journal)", active)
        self.assertLess(finish, loop)
        self.assertLess(allowed, loop)
        self.assertLess(session_gate, active)
        self.assertLess(active, write)
        self.assertIn('journal[@"batchSessionFinish"] = batchFinish', self.apply)

    def test_successful_reuse_counts_as_complete_without_apply_work(self) -> None:
        self.assertIn("alreadyActive++;", self.apply)
        self.assertIn("reusedInheritedApplications++;", self.apply)
        self.assertIn(' @"stage": @"inherited-journal-reused"'.strip(), self.apply)
        self.assertIn(
            "BOOL persistentApplyOK = sessionClosed && !cancelled && failed == 0;",
            self.apply,
        )
        self.assertIn(
            '@"reusedInheritedApplications": @(reusedInheritedApplications)',
            self.apply,
        )
        self.assertIn('@"state": persistentApplyOK ? @"complete" : @"partial"', self.apply)

    def test_failed_finalization_remains_a_real_failure(self) -> None:
        failure = self.apply.index("if (finalized) {")
        block = self.apply[failure:self.apply.index("NSDictionary *airDropResult", failure)]
        self.assertIn("failed++;", block)
        self.assertIn("inheritedJournalFinalizationFailures++;", block)
        self.assertIn('@"reason": @"inherited-journal-finalization"', block)


if __name__ == "__main__":
    unittest.main()
