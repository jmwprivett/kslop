"""Host-only fixtures for the already-applied / already-stock skip matrix."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REMIX = ROOT / "Cyanide/installer/CNDSnowBoardRemix.m"

APPLY = "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
RESTORE = "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals("
PROOF = "static BOOL CNDRemixAppliedAuditRecordHasValidPersistentStoreEvidence("
PROOF_END = "\nstatic NSDictionary *CNDRemixCompareAppliedAuditRecords"
STRICT = "static BOOL CNDRemixAuditHasExplicitBoolean("
STRICT_END = "static BOOL CNDRemixAuditProvesPersistentRecordMissing("

HARNESS = r'''
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "already-applied fixture failed at line %d: %s\n", \
            __LINE__, #condition); return 1; } } while (0)

static NSString *hashOf(unichar character) {
    return [@"" stringByPaddingToLength:64
        withString:[NSString stringWithFormat:@"%C", character]
        startingAtIndex:0];
}
static NSString *themedDigest(void) { return hashOf('b'); }
static NSString *otherThemedDigest(void) { return hashOf('e'); }
static NSString *stockDigest(void) { return hashOf('a'); }
static NSString *tokenDigest(void) { return hashOf('c'); }
static NSString *sourceDigest(void) { return hashOf('d'); }

static NSMutableDictionary *specification(void) {
    return [@{@"pointWidth": @68, @"pointHeight": @68, @"scale": @3,
              @"appearance": @0, @"iconVariant": @0, @"options": @0,
              @"canonicalIdentity": @"68x68@3:a0:v0:o0"} mutableCopy];
}

static NSMutableDictionary *themedAudit(void) {
    return [@{
        @"ok": @YES, @"stage": @"audited", @"transportHealthy": @YES,
        @"persistentMutationsIssued": @NO, @"presentationMutationsIssued": @NO,
        @"mutationsIssued": @NO, @"generationIssued": @NO,
        @"cachePurgeIssued": @NO, @"storeWriteIssued": @NO,
        @"storeIndexLookupReady": @YES, @"storeIndexEntryPresent": @YES,
        @"storeUnitPresent": @YES, @"storeUnitValid": @YES,
        @"storeIndexUnitIdentifierEqual": @YES,
        @"storeDataSHA256": themedDigest(),
        @"storeIdentifier": @"unit-uuid",
        @"indexedIdentifier": @"unit-uuid",
        @"storeValidationTokenSHA256": tokenDigest(),
        @"sourceIdentityAuditReady": @YES,
        @"sourceRegistryDataPresent": @YES,
        @"currentSourceIdentifierPresent": @YES,
        @"sourceIdentityMatchesCurrentRecord": @YES,
        @"sourceRegistryDataSHA256": sourceDigest(),
        @"currentSourceIdentifierSHA256": sourceDigest(),
    } mutableCopy];
}

static BOOL proves(NSDictionary *audit) {
    return CNDRemixAuditProvesPreparedThemedPayload(
        audit, @"com.example.app", specification(), themedDigest());
}

int main(void) {
    @autoreleasepool {
        CHECK(proves(themedAudit()));
        /* The process cache is deliberately not part of the proof. */
        CHECK(proves(themedAudit()));

        /* Only the exact prepared payload in the store counts. */
        NSMutableDictionary *audit = themedAudit();
        audit[@"storeDataSHA256"] = otherThemedDigest();
        CHECK(!proves(audit));
        audit = themedAudit();
        audit[@"storeDataSHA256"] = stockDigest();
        CHECK(!proves(audit));
        audit = themedAudit();
        audit[@"storeDataSHA256"] = @"";
        CHECK(!proves(audit));
        audit = themedAudit();
        [audit removeObjectForKey:@"storeDataSHA256"];
        CHECK(!proves(audit));
        CHECK(!proves(nil));
        CHECK(!proves(@{}));

        /* Every store identity must be present and agree. */
        for (NSString *flag in @[@"storeIndexLookupReady",
                @"storeIndexEntryPresent", @"storeUnitPresent",
                @"storeUnitValid", @"storeIndexUnitIdentifierEqual",
                @"sourceIdentityAuditReady", @"sourceRegistryDataPresent",
                @"currentSourceIdentifierPresent",
                @"sourceIdentityMatchesCurrentRecord"]) {
            audit = themedAudit();
            audit[flag] = @NO;
            CHECK(!proves(audit));
        }
        audit = themedAudit();
        audit[@"storeIdentifier"] = @"";
        CHECK(!proves(audit));
        audit = themedAudit();
        audit[@"indexedIdentifier"] = @"";
        CHECK(!proves(audit));
        audit = themedAudit();
        audit[@"indexedIdentifier"] = @"other-unit";
        CHECK(!proves(audit));
        audit = themedAudit();
        audit[@"storeValidationTokenSHA256"] = @"";
        CHECK(!proves(audit));
        audit = themedAudit();
        audit[@"storeValidationTokenSHA256"] = @"not-a-hash";
        CHECK(!proves(audit));
        audit = themedAudit();
        audit[@"sourceRegistryDataSHA256"] = hashOf('f');
        CHECK(!proves(audit));
        audit = themedAudit();
        [audit removeObjectForKey:@"sourceIdentityMatchesCurrentRecord"];
        CHECK(!proves(audit));

        /* A partial, failed, or mutating observation never skips. */
        audit = themedAudit();
        audit[@"ok"] = @NO;
        CHECK(!proves(audit));
        audit = themedAudit();
        audit[@"stage"] = @"audit-matrix-partial";
        CHECK(proves(audit));  /* the transport already reports ok=NO there */
        audit = themedAudit();
        [audit removeObjectForKey:@"ok"];
        CHECK(!proves(audit));
        audit = themedAudit();
        audit[@"transportHealthy"] = @NO;
        CHECK(!proves(audit));
        for (NSString *flag in @[@"persistentMutationsIssued",
                @"presentationMutationsIssued", @"mutationsIssued",
                @"generationIssued", @"cachePurgeIssued",
                @"storeWriteIssued"]) {
            audit = themedAudit();
            audit[flag] = @YES;
            CHECK(!proves(audit));
            [audit removeObjectForKey:flag];
            CHECK(!proves(audit));
        }

        /* The expectation itself must be a bound hash and a real target. */
        CHECK(!CNDRemixAuditProvesPreparedThemedPayload(
            themedAudit(), @"com.example.app", specification(), @""));
        CHECK(!CNDRemixAuditProvesPreparedThemedPayload(
            themedAudit(), @"com.example.app", specification(),
            @"not-a-hash"));
        CHECK(!CNDRemixAuditProvesPreparedThemedPayload(
            themedAudit(), @"", specification(), themedDigest()));
        CHECK(!CNDRemixAuditProvesPreparedThemedPayload(
            themedAudit(), @"com.example.app", nil, themedDigest()));
    }
    return 0;
}
'''


class RemixAlreadyAppliedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = REMIX.read_text(encoding="utf-8")
        start = cls.source.index(APPLY)
        cls.apply = cls.source[start:cls.source.index(
            "CNDRemixDeferredSpringBoardPresentationRestore(", start
        )]
        restore_start = cls.source.index(RESTORE)
        cls.restore = cls.source[restore_start:cls.source.index(
            "\n@implementation CNDSnowBoardRemix", restore_start
        )]

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"),
                         "requires macOS Foundation and clang")
    def test_compiled_skip_predicate_requires_exact_hash_and_identity(self) -> None:
        def section(start: str, end: str) -> str:
            begin = self.source.index(start)
            return self.source[begin:self.source.index(end, begin)]

        sha_string = section(
            "static BOOL CNDRemixIsSHA256String(NSString *value)\n{",
            "static NSString *CNDRemixPayloadPlatformIdentifier(",
        )
        classification = section(
            "static NSString *CNDRemixAuditHashClassification(",
            "static NSString *CNDRemixAppliedAuditRecordKey(",
        )
        audit_text = section(
            "static NSString *CNDRemixAppliedAuditText(NSDictionary *record,",
            PROOF,
        )
        proofs = section(PROOF, PROOF_END)
        strict = section(STRICT, STRICT_END)
        self.assertIn("CNDRemixAuditProvesPreparedThemedPayload(", proofs)
        with tempfile.TemporaryDirectory(prefix="cyanide-already-applied-") as directory:
            source = Path(directory) / "applied.m"
            executable = Path(directory) / "applied"
            source.write_text(
                "#import <Foundation/Foundation.h>\n#include <stdio.h>\n"
                + sha_string + strict + classification + audit_text + proofs
                + HARNESS,
                encoding="utf-8",
            )
            subprocess.run(["clang", "-fobjc-arc", "-framework", "Foundation",
                            str(source), "-o", str(executable)],
                           check=True, capture_output=True)
            subprocess.run([str(executable)], check=True, capture_output=True)

    def test_apply_audits_once_before_arming_and_publishing(self) -> None:
        audit = self.apply.index("CNDIconServicesPublisherAuditVariantsInBatch(")
        arm = self.apply.index('dispatchVariant[@"publicationDispatchPossible"]')
        checkpoint = self.apply.index("CNDRemixAppendIconServicesJournalCheckpoint(")
        publish = self.apply.index("CNDIconServicesPublisherPublishVariantsInBatch(")
        self.assertLess(audit, arm)
        self.assertLess(arm, checkpoint)
        self.assertLess(checkpoint, publish)
        # The audit covers exactly the prepared descriptors, in order.
        self.assertIn(
            "variantIndex < preparedVariants.count &&\n"
            "                             variantIndex < appliedAudits.count",
            self.apply,
        )
        # One matrix per application, and the mutation matrix is the subset
        # that still has to dispatch.
        self.assertEqual(
            self.apply.count("CNDIconServicesPublisherAuditVariantsInBatch("), 1
        )
        self.assertEqual(
            self.apply.count("CNDIconServicesPublisherPublishVariantsInBatch("), 1
        )
        self.assertIn("dispatchCheckpointed && dispatchVariants.count > 0", self.apply)
        self.assertIn("CNDRemixAuditProvesPreparedThemedPayload(", self.apply)

    def test_apply_skip_never_arms_and_never_counts_a_mutation(self) -> None:
        skip = self.apply.index("[alreadyAppliedIndexes containsObject:")
        arm = self.apply.index("NSMutableDictionary *dispatchVariant =", skip)
        branch = self.apply[skip:arm]
        self.assertIn("continue;", branch)
        self.assertIn('variantJournal[@"publication"] = appliedEvidence;', branch)
        self.assertIn('@"state"] =\n                                @"published-pending-session-close";',
                      branch)
        self.assertIn("alreadyAppliedVariants++;", branch)
        # A skipped descriptor is never armed, never published, and never
        # counted as a mutation; only its own counter moves.
        self.assertNotIn("dispatchVariant", branch)
        self.assertNotIn("publishedVariants++", branch)
        self.assertNotIn("dispatchIndexes", branch)
        self.assertEqual(self.apply.count("publishedVariants++;"), 1)
        self.assertIn("CNDRemixSaveStockOriginal(", self.apply)
        published = self.apply.index("publishedVariants++;")
        self.assertNotIn("alreadyAppliedIndexes", self.apply[published:published + 200])
        # Skipped variants are not "no themed mutation" records either: their
        # store does hold the themed payload, this run simply did not write it.
        self.assertIn('@"noThemedPublicationMutationVerified": @NO,', branch)

    def test_apply_mixed_set_checkpoints_skipped_and_dispatched(self) -> None:
        self.assertIn(
            "[checkpointIndexes addObjectsFromArray:dispatchIndexes];",
            self.apply,
        )
        self.assertIn(
            "[checkpointIndexes addObject:\n"
            "                            @(newVariantOffset +\n"
            "                              indexNumber.unsignedIntegerValue)];",
            self.apply,
        )
        self.assertIn("if (checkpointIndexes.count > 0) {", self.apply)
        # A skipped descriptor must never replay as never-dispatched.
        self.assertIn("failedVariants += dispatchIndexes.count;", self.apply)

    def test_apply_all_skip_verifies_without_a_mutation_matrix(self) -> None:
        self.assertIn(
            "NSDictionary *publicationMatrix =\n"
            "                        dispatchCheckpointed && dispatchVariants.count > 0\n"
            "                        ? CNDIconServicesPublisherPublishVariantsInBatch(\n"
            "                            bundleIdentifier, dispatchVariants)\n"
            "                        : nil;",
            self.apply,
        )
        # A skipped variant still contributes a verified per-variant result,
        # so an all-skip application verifies with no matrix at all.
        self.assertIn("appVerified = allVerified &&", self.apply)
        self.assertIn("variantResults.count == preparedVariants.count", self.apply)
        self.assertIn('@"stage": @"already-applied-readback"', self.apply)
        self.assertIn('@"ok": @YES,', self.apply)
        self.assertIn('@"alreadyAppliedVariants": @(alreadyAppliedVariants)', self.source)

    def test_apply_audit_failure_dispatches_every_descriptor(self) -> None:
        # Only a positive proof removes a descriptor from the dispatch set.
        classify = self.apply.index("if (!CNDRemixAuditProvesPreparedThemedPayload(")
        add = self.apply.index("[alreadyAppliedIndexes addObject:@(variantIndex)];")
        self.assertLess(classify, add)
        self.assertIn("continue;", self.apply[classify:add])
        # A missing or short matrix leaves every unproven descriptor dispatching.
        self.assertIn("isKindOfClass:NSArray.class]\n"
                      "                                ? appliedAuditMatrix[@\"audits\"] : @[]",
                      self.apply)
        self.assertIn("CNDIconServicesPublisherBatchIsHealthy()", self.apply)
        self.assertIn("preparedVariants.count > 0 &&", self.apply)

    def test_restore_audits_and_skips_every_dispatch_candidate(self) -> None:
        audit_start = self.restore.index(
            "NSMutableArray<NSNumber *> *auditIndexes ="
        )
        matrix = self.restore.index("CNDIconServicesPublisherAuditVariantsInBatch(")
        audit_loop = self.restore[audit_start:matrix]
        self.assertIn("[auditIndexes addObject:@(variantIndex)];", audit_loop)
        self.assertNotIn("if (isAirDrop) [auditIndexes", self.restore)
        # The already-stock classification is not AirDrop-gated any more.
        self.assertIn(
            "BOOL alreadyStock = validatedSpec &&\n"
            "                            CNDRemixAuditProvesSavedStock(\n"
            "                                stockAudit, savedVariant);",
            self.restore,
        )
        self.assertNotIn("validatedSpec && isAirDrop &&", self.restore)
        self.assertIn('@"stage": @"already-stock-readback"', self.restore)
        self.assertIn("alreadyStockVariants++;", self.restore)
        # The AirDrop post-restore fallback is unchanged.
        self.assertIn("if (!verified && validatedSpec && isAirDrop) {", self.restore)
        self.assertIn('restoration[@"deferredVerificationAudit"]', self.restore)
        # The expected stock bytes come from the journaled stock hash; a
        # descriptor without one is never classified as already stock.
        proof_start = self.source.index("static BOOL CNDRemixAuditProvesSavedStock(")
        proof_end = self.source.index(
            "static NSDictionary *CNDRemixCompactStockReadbackAudit(", proof_start
        )
        proof = self.source[proof_start:proof_end]
        self.assertIn('CNDRemixCatalogText(stock, @"dataSHA256")', proof)
        self.assertIn("CNDRemixIsSHA256String(expectedStockHash)", proof)


if __name__ == "__main__":
    unittest.main()
