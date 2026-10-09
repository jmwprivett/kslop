"""Host-only fixtures for live store evidence overriding stale Remix metadata."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REMIX = ROOT / "Cyanide/installer/CNDSnowBoardRemix.m"
TRANSPORT = ROOT / "Cyanide/installer/CNDIconServicesPublisherRemoteTransport.m"

MOCKS = r'''
static const NSUInteger CNDRemixIconServicesJournalSchemaVersion = 2;
static BOOL healthy = YES, writeOK = YES, removeOK = YES;
static NSDictionary *savedCheckpoint;
static NSUInteger removals;
static NSMutableDictionary *audits;
#define log_user(...) ((void)0)

@interface CNDIconServicesDescriptorSpec : NSObject
@property(nonatomic, strong) NSDictionary *dictionaryRepresentation;
+ (instancetype)specWithDictionary:(NSDictionary *)dictionary error:(NSError **)error;
@end
@implementation CNDIconServicesDescriptorSpec
+ (instancetype)specWithDictionary:(NSDictionary *)dictionary error:(NSError **)error {
    if (![dictionary isKindOfClass:NSDictionary.class] || !dictionary[@"id"]) return nil;
    CNDIconServicesDescriptorSpec *spec = [self new];
    spec.dictionaryRepresentation = dictionary;
    return spec;
}
@end
static BOOL CNDRemixIsSupportedPseudoBundleIdentifier(NSString *identifier) {
    return [identifier isEqualToString:@"com.apple.Sharing.AirDrop"];
}
static NSArray *CNDRemixJournalVariants(NSDictionary *journal) {
    return journal[@"variants"];
}
static BOOL CNDIconServicesPublisherBatchIsHealthy(void) { return healthy; }
static NSDictionary *CNDIconServicesPublisherAuditVariantInBatch(
    NSString *identifier, NSDictionary *specification) {
    return audits[specification[@"id"]];
}
static BOOL CNDRemixWriteIconServicesJournal(NSDictionary *journal) {
    if (writeOK) savedCheckpoint = [journal copy];
    return writeOK;
}
static BOOL CNDRemixRemoveIconServicesJournal(NSString *identifier) {
    if (removeOK) removals++;
    return removeOK;
}
'''

HARNESS = r'''
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "journal fixture failed at line %d: %s\n", \
            __LINE__, #condition); return 1; } } while (0)
static NSString *stockHash(void) { return [@"a" stringByPaddingToLength:64 withString:@"a" startingAtIndex:0]; }
static NSString *themeHash(void) { return [@"b" stringByPaddingToLength:64 withString:@"b" startingAtIndex:0]; }
static NSString *stockToken(void) { return [@"c" stringByPaddingToLength:64 withString:@"c" startingAtIndex:0]; }
static NSString *themeToken(void) { return [@"d" stringByPaddingToLength:64 withString:@"d" startingAtIndex:0]; }
static NSMutableDictionary *stockAudit(void) {
    return [@{
        @"ok": @NO, @"stage": @"audit-source-registry-readback",
        @"transportHealthy": @YES,
        @"persistentMutationsIssued": @NO, @"generationIssued": @NO,
        @"canonicalCacheReadReady": @YES, @"cacheResponsePresent": @YES,
        @"storeIndexLookupReady": @YES, @"storeIndexEntryPresent": @YES,
        @"storeUnitPresent": @YES, @"storeUnitValid": @YES,
        @"cacheStoreEqual": @YES, @"cacheStoreIdentifierEqual": @YES,
        @"cacheStoreValidationTokenEqual": @YES,
        @"storeIndexUnitIdentifierEqual": @YES,
        @"cacheDataSHA256": stockHash(), @"storeDataSHA256": stockHash(),
        @"indexedIdentifier": @"stock-unit", @"storeIdentifier": @"stock-unit",
        @"storeValidationTokenSHA256": stockToken(),
        @"sourceIdentityAuditReady": @NO,
    } mutableCopy];
}
static NSMutableDictionary *failedSourceVariant(NSString *identity) {
    return [@{
        @"state": @"recovery-required", @"publicationDispatchPossible": @YES,
        @"descriptorSpecification": @{@"id": identity},
        @"structuredImageSHA256": themeHash(),
        @"publication": @{
            @"ok": @NO, @"stage": @"stock-api-source-registry-readback",
            @"transactionStarted": @YES, @"stockCaptured": @YES,
            @"stockGenerationInitiallyPersisted": @YES,
            @"stockGenerationPersisted": @YES,
            @"persistentIndexIdentitySettled": @YES,
            @"directStoreRemoveIssued": @NO, @"directStoreWriteIssued": @NO,
            @"directStoreRemoveVerified": @NO, @"directStoreWriteVerified": @NO,
            @"persistentIndexTokenWriteIssued": @NO, @"replacementPublished": @NO,
            @"installed": @NO, @"hookStillInstalledAtCleanup": @NO,
            @"hookRestored": @YES, @"hookQuiescent": @YES,
            @"transportHealthy": @YES, @"transportLifecycleVerified": @YES,
            @"stockResponse": @{@"dataSHA256": stockHash(), @"uuid": @"stock-unit",
                @"validationTokenSHA256": stockToken()},
            @"agentCacheResponse": @{@"validationTokenSHA256": themeToken()},
        },
    } mutableCopy];
}
int main(void) {
    @autoreleasepool {
        NSMutableDictionary *variant = failedSourceVariant(@"64");
        CHECK(!CNDRemixVariantProvesNoIconServicesMutation(variant));
        CHECK(CNDRemixReportProvesNoThemedIconServicesMutation(variant[@"publication"]));
        for (NSString *flag in variant[@"publication"]) {
            id original = variant[@"publication"][flag];
            if (![original isKindOfClass:NSNumber.class] || [flag isEqualToString:@"transactionStarted"]) continue;
            NSMutableDictionary *report = [variant[@"publication"] mutableCopy];
            [report removeObjectForKey:flag];
            CHECK(!CNDRemixReportProvesNoThemedIconServicesMutation(report));
            report[flag] = @(![original boolValue]);
            CHECK(!CNDRemixReportProvesNoThemedIconServicesMutation(report));
        }
        CHECK(CNDRemixAuditProvesSavedStock(stockAudit(), variant));
        for (NSString *flag in @[@"transportHealthy",
                @"storeIndexLookupReady", @"storeIndexEntryPresent",
                @"storeUnitPresent", @"storeUnitValid",
                @"storeIndexUnitIdentifierEqual"]) {
            NSMutableDictionary *audit = stockAudit();
            audit[flag] = @NO;
            CHECK(!CNDRemixAuditProvesSavedStock(audit, variant));
        }
        NSMutableDictionary *cacheEmpty = stockAudit();
        cacheEmpty[@"cacheResponsePresent"] = @NO;
        cacheEmpty[@"cacheDataSHA256"] = @"";
        cacheEmpty[@"cacheStoreEqual"] = @NO;
        cacheEmpty[@"cacheStoreIdentifierEqual"] = @NO;
        cacheEmpty[@"cacheStoreValidationTokenEqual"] = @NO;
        CHECK(CNDRemixAuditProvesSavedStock(cacheEmpty, variant));
        NSMutableDictionary *changedVariant = [variant mutableCopy];
        NSMutableDictionary *changedReport = [variant[@"publication"] mutableCopy];
        changedReport[@"directStoreWriteIssued"] = @YES;
        changedVariant[@"publication"] = changedReport;
        CHECK(!CNDRemixAuditProvesSavedStock(cacheEmpty, changedVariant));
        changedReport = [variant[@"publication"] mutableCopy];
        changedReport[@"stockResponse"] = @{@"dataSHA256": stockHash(),
            @"uuid": @"different-unit", @"validationTokenSHA256": stockToken()};
        changedVariant[@"publication"] = changedReport;
        CHECK(!CNDRemixAuditProvesSavedStock(cacheEmpty, changedVariant));
        for (NSString *flag in @[@"persistentMutationsIssued", @"generationIssued"]) {
            NSMutableDictionary *audit = stockAudit();
            audit[flag] = @YES;
            CHECK(!CNDRemixAuditProvesSavedStock(audit, variant));
            [audit removeObjectForKey:flag];
            CHECK(!CNDRemixAuditProvesSavedStock(audit, variant));
        }
        NSMutableDictionary *themed = stockAudit();
        themed[@"storeDataSHA256"] = themeHash();
        CHECK(!CNDRemixAuditProvesSavedStock(themed, variant));
        themed = stockAudit();
        themed[@"storeValidationTokenSHA256"] = themeToken();
        CHECK(!CNDRemixAuditProvesSavedStock(themed, variant));

        NSMutableDictionary *old = failedSourceVariant(@"64");
        old[@"publication"] = @{}; // Earlier failures omitted the stock hash.
        CHECK(!CNDRemixAuditProvesSavedStock(stockAudit(), old));
        old[@"restoration"] = @{@"stockCaptured": @YES,
            @"stockGenerationPersisted": @YES,
            @"stockResponse": @{@"dataSHA256": stockHash()}};
        CHECK(CNDRemixAuditProvesSavedStock(stockAudit(), old));
        old[@"restoration"] = @{@"stockCaptured": @NO,
            @"stockGenerationPersisted": @YES,
            @"stockResponse": @{@"dataSHA256": stockHash()}};
        CHECK(!CNDRemixAuditProvesSavedStock(stockAudit(), old));

        audits = [@{@"64": stockAudit(), @"28": stockAudit()} mutableCopy];
        NSDictionary *journal = @{@"schemaVersion": @2, @"state": @"recovery-required",
            @"variants": @[variant, failedSourceVariant(@"28")]};
        CHECK(CNDRemixReconcileAirDropJournalToCurrentStockInBatch(
            @"com.apple.Sharing.AirDrop", journal));
        CHECK(removals == 1);
        CHECK([savedCheckpoint[@"state"] isEqualToString:@"persistent-stock-verified"]);
        CHECK([savedCheckpoint[@"variants"][0][@"state"] isEqualToString:@"persistent-stock-verified"]);
        writeOK = NO; removeOK = NO;
        CHECK(CNDRemixReconcileAirDropJournalToCurrentStockInBatch(
            @"com.apple.Sharing.AirDrop", journal));
        CHECK(removals == 1); // Cleanup does not change verified persistent state.
        audits[@"28"] = themed;
        CHECK(!CNDRemixReconcileAirDropJournalToCurrentStockInBatch(
            @"com.apple.Sharing.AirDrop", journal));
        CHECK(removals == 1); // Mixed stock/themed data retains recovery metadata.
        audits[@"28"] = stockAudit();
        healthy = NO;
        CHECK(!CNDRemixReconcileAirDropJournalToCurrentStockInBatch(
            @"com.apple.Sharing.AirDrop", journal));
    }
    return 0;
}
'''


class RemixJournalStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = REMIX.read_text(encoding="utf-8")
        cls.transport = TRANSPORT.read_text(encoding="utf-8")

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"),
                         "requires macOS Foundation and clang")
    def test_live_stock_reconciliation_and_cleanup_failure(self) -> None:
        def section(start: str, end: str) -> str:
            begin = self.source.index(start)
            return self.source[begin:self.source.index(end, begin)]

        proof = section("static BOOL CNDRemixReportProvesNoIconServicesMutation(",
                        "static BOOL CNDRemixJournalIsCompleteActiveMatrix(")
        catalog = section("static NSString *CNDRemixCatalogText(",
                          "/* AirDrop's activity identity")
        sha = section("static BOOL CNDRemixIsSHA256String(NSString *value)\n{",
                      "static NSString *CNDRemixPayloadPlatformIdentifier(")
        stock = section("static BOOL CNDRemixAuditProvesSavedStock(",
                        "static void CNDRemixLogIconServicesTransaction(")
        with tempfile.TemporaryDirectory(prefix="cyanide-journal-state-") as directory:
            source = Path(directory) / "journal.m"
            executable = Path(directory) / "journal"
            source.write_text(
                "#import <Foundation/Foundation.h>\n#include <stdio.h>\n" +
                MOCKS + catalog + sha + proof + stock + HARNESS, encoding="utf-8",
            )
            subprocess.run(["clang", "-fobjc-arc", "-framework", "Foundation",
                            str(source), "-o", str(executable)],
                           check=True, capture_output=True)
            subprocess.run([str(executable)], check=True, capture_output=True)

    def test_capture_stock_identity_precedes_source_gate_and_themed_write(self) -> None:
        start = self.transport.index("__block NSString *stockHash =")
        capture = self.transport.index("stockHash = cnd_publisher_sha256(stockBytes);", start)
        source_gate = self.transport.index("if (sourceRegistrationRequired)", start)
        replacement = self.transport.index("replacementCreated = replacement != 0", start)
        remove = self.transport.index("directStoreRemoveIssued = YES;", start)
        self.assertLess(capture, source_gate)
        self.assertLess(capture, replacement)
        self.assertLess(capture, remove)

    def test_stock_uuid_uses_owned_scratch_before_the_source_gate(self) -> None:
        start = self.transport.index("__block NSString *stockHash =")
        settle = self.transport.index("persistentIndexIdentitySettled = persistentIndexScratch", start)
        capture = self.transport.index(
            "stockUUIDText = cnd_publisher_audit_copy_indexed_identifier(", settle
        )
        gate = self.transport.index("if (stockUUIDText.length == 0)", capture)
        source_gate = self.transport.index("if (sourceRegistrationRequired)", settle)
        self.assertLess(settle, capture)
        self.assertLess(capture, gate)
        self.assertLess(gate, source_gate)
        self.assertIn("stockUUID, persistentIndexScratch", self.transport[capture:gate])
        self.assertNotIn("cnd_publisher_copy_remote_indexed_identifier(stockUUID)",
                         self.transport[start:source_gate])

    def test_failed_apply_reconciles_live_stock_before_batch_closes(self) -> None:
        start = self.source.index("BOOL failedPublicationVerifiedStock =")
        reconcile = self.source.index("CNDRemixReconcileAirDropJournalToCurrentStockInBatch(", start)
        finish = self.source.index("CNDIconServicesPublisherFinishBatch()", start)
        self.assertLess(reconcile, finish)
        self.assertIn('!appVerified &&', self.source[start:reconcile])

    def test_apply_reconciles_before_existing_journal_admission(self) -> None:
        start = self.source.index("NSDictionary *existing =")
        reconcile = self.source.index("CNDRemixReconcileAirDropJournalToCurrentStockInBatch(", start)
        block = self.source.index('BOOL predatesStorePreservation =', start)
        self.assertLess(reconcile, block)

    def test_each_publication_has_a_durable_dispatch_checkpoint_and_result(self) -> None:
        start = self.source.index('dispatchVariant[@"publicationDispatchPossible"] = @YES;')
        checkpoint = self.source.index("CNDRemixWriteIconServicesJournal(journal)", start)
        publish = self.source.index("CNDIconServicesPublisherPublishVariantInBatch(", start)
        result = self.source.index('variantJournal[@"publication"] =', publish)
        result_checkpoint = self.source.index("CNDRemixWriteIconServicesJournal(journal)", result)
        self.assertLess(checkpoint, publish)
        self.assertLess(result, result_checkpoint)
        self.assertIn('@"publicationDispatchPossible": @NO', self.source[:start])

    def test_airdrop_diagnostics_read_the_nested_publication_report(self) -> None:
        start = self.source.index("for (NSDictionary *variantResult in airDropVariantResults)")
        end = self.source.index('log_user("[SBR_SHARE] airdrop active=', start)
        summary = self.source[start:end]
        self.assertIn('variantResult[@"publication"]', summary)
        for field in ("sourceIdentifiersResolved", "sourceRegistryFreshReadbackVerified",
                      "sourceRegistryEntryCountBefore", "sourceRegistryEntryCountAfter",
                      "sourceRegistryWriteIssued"):
            self.assertIn(f'publication[@"{field}"]', summary)
            self.assertNotIn(f'variantResult[@"{field}"]', summary)


if __name__ == "__main__":
    unittest.main()
