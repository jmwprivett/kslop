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


STOCK_ORIGINAL_HARNESS = r'''
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "stock-original fixture failed at line %d: %s\n", \
            __LINE__, #condition); return 1; } } while (0)
static NSArray *filesIn(NSURL *directory) {
    return [NSFileManager.defaultManager
        contentsOfDirectoryAtURL:directory includingPropertiesForKeys:nil
        options:NSDirectoryEnumerationSkipsHiddenFiles error:nil];
}
int main(void) {
    @autoreleasepool {
        NSString *bundle = @"com.example.stock.originals";
        NSString *identity = @"68x68@3:a0:v0:o0";
        NSString *uuid = @"6D4A0F7C-2E33-4C41-9A6E-2E5C8B9A1234";
        NSData *bytes = [@"stock-original-bytes" dataUsingEncoding:NSUTF8StringEncoding];
        NSString *hash = CNDRemixSHA256(bytes);
        NSURL *directory = CNDRemixIconServicesStockOriginalDirectoryURL(bundle);

        /* The sidecars live inside the existing journal tree. */
        CHECK([directory.path hasPrefix:CNDRemixIconServicesRootURL().path]);
        CHECK(![directory.path hasPrefix:
            CNDRemixIconServicesTransactionsURL().path]);

        /* Write, then require an exact byte readback. */
        CHECK(CNDRemixWriteStockOriginal(bundle, identity, uuid, hash, bytes));
        NSString *filename = CNDRemixStockOriginalFilename(identity, uuid, hash);
        CHECK(filename.length > 0);
        CHECK([filename containsString:@"68x68-3-a0-v0-o0"]);
        CHECK([filename containsString:uuid.lowercaseString]);
        CHECK([filename containsString:hash]);
        NSDictionary *variant = @{@"stockOriginalPath": filename,
                                  @"stockOriginalSHA256": hash};
        CHECK([CNDRemixLoadStockOriginal(bundle, variant) isEqualToData:bytes]);

        /* One descriptor owns one file: a new UUID or hash replaces the old
         * entry instead of accumulating beside it. */
        NSData *replacement = [@"second-stock-original"
            dataUsingEncoding:NSUTF8StringEncoding];
        NSString *replacementHash = CNDRemixSHA256(replacement);
        CHECK(CNDRemixWriteStockOriginal(
            bundle, identity, uuid, replacementHash, replacement));
        CHECK([filesIn(directory) count] == 1);
        CHECK(CNDRemixLoadStockOriginal(bundle, variant) == nil);

        NSDictionary *current = @{
            @"stockOriginalPath": CNDRemixStockOriginalFilename(
                identity, uuid, replacementHash),
            @"stockOriginalSHA256": replacementHash,
        };
        CHECK([CNDRemixLoadStockOriginal(bundle, current)
            isEqualToData:replacement]);

        /* A tampered file fails closed on its recorded hash. */
        NSURL *file = [directory
            URLByAppendingPathComponent:current[@"stockOriginalPath"]
                            isDirectory:NO];
        CHECK([[@"tampered" dataUsingEncoding:NSUTF8StringEncoding]
            writeToURL:file options:NSDataWritingAtomic error:nil]);
        CHECK(CNDRemixLoadStockOriginal(bundle, current) == nil);

        /* So does a missing file, an unrecorded entry, and a path escape. */
        CHECK([NSFileManager.defaultManager removeItemAtURL:file error:nil]);
        CHECK(CNDRemixLoadStockOriginal(bundle, current) == nil);
        CHECK(CNDRemixLoadStockOriginal(bundle, @{}) == nil);
        CHECK(CNDRemixLoadStockOriginal(bundle,
            @{@"stockOriginalPath": @"anything.isdata"}) == nil);
        CHECK(CNDRemixLoadStockOriginal(bundle, @{
            @"stockOriginalPath": @"../escape.isdata",
            @"stockOriginalSHA256": replacementHash}) == nil);

        /* The bounded write refuses an oversize original. */
        NSData *oversize = [NSMutableData dataWithLength:
            CNDIconServicesPublisherMaximumStructuredDataLength + 1];
        CHECK(!CNDRemixWriteStockOriginal(
            bundle, identity, uuid, CNDRemixSHA256(oversize), oversize));
        CHECK(!CNDRemixWriteStockOriginal(bundle, identity, uuid, hash, nil));
        CHECK(!CNDRemixWriteStockOriginal(bundle, identity, uuid, @"", bytes));
        CHECK(!CNDRemixWriteStockOriginal(bundle, @"", uuid, hash, bytes));
        CHECK(!CNDRemixWriteStockOriginal(bundle, identity, @"", hash, bytes));

        /* A publication records only what survived exact readback. */
        NSDictionary *variantRecord = @{@"descriptorIdentity": identity};
        NSDictionary *captured = @{@"originalData": replacement,
                                   @"uuid": uuid,
                                   @"dataSHA256": replacementHash};
        NSDictionary *saved = CNDRemixSaveStockOriginal(bundle, variantRecord,
            @{@"stockResponse": captured});
        CHECK([saved count] == 2);
        CHECK([saved[@"stockOriginalSHA256"] isEqualToString:replacementHash]);
        CHECK([CNDRemixLoadStockOriginal(bundle, saved)
            isEqualToData:replacement]);
        NSDictionary *noBytes = @{@"uuid": uuid,
                                  @"dataSHA256": replacementHash};
        CHECK([CNDRemixSaveStockOriginal(bundle, variantRecord,
            @{@"stockResponse": noBytes}) count] == 0);
        CHECK([CNDRemixSaveStockOriginal(bundle, variantRecord, @{}) count] == 0);
        CHECK([CNDRemixSaveStockOriginal(bundle, @{},
            @{@"stockResponse": captured}) count] == 0);
        NSDictionary *badHash = @{@"originalData": replacement, @"uuid": uuid,
                                  @"dataSHA256": @"not-a-hash"};
        CHECK([CNDRemixSaveStockOriginal(bundle, variantRecord,
            @{@"stockResponse": badHash}) count] == 0);
        /* An oversize capture is not persisted and so is not recorded. */
        NSDictionary *oversizeCapture = @{@"originalData": oversize,
            @"uuid": uuid, @"dataSHA256": CNDRemixSHA256(oversize)};
        CHECK([CNDRemixSaveStockOriginal(bundle, variantRecord,
            @{@"stockResponse": oversizeCapture}) count] == 0);

        /* Retiring the journal retires this app's originals with it. */
        NSMutableDictionary *journal = [@{
            @"schemaVersion": @2,
            @"bundleIdentifier": bundle,
            @"state": @"persistent-stock-verified",
            @"variants": @[],
            @"updatedAt": NSDate.date,
        } mutableCopy];
        CHECK(CNDRemixWriteIconServicesJournal(journal));
        CHECK(CNDRemixWriteStockOriginal(
            bundle, identity, uuid, replacementHash, replacement));
        CHECK([filesIn(directory) count] == 1);
        CHECK(CNDRemixRemoveIconServicesJournal(bundle));
        CHECK(![NSFileManager.defaultManager
            fileExistsAtPath:directory.path]);
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
        stock_proof = section(
            "static BOOL CNDRemixAuditProvesSavedStock(",
            "static BOOL CNDRemixVariantHasVerifiedStockCheckpoint(",
        )
        reconcile = section(
            "static BOOL CNDRemixReconcileAirDropJournalToCurrentStockInBatch(",
            "static void CNDRemixLogIconServicesTransaction(",
        )
        with tempfile.TemporaryDirectory(prefix="cyanide-journal-state-") as directory:
            source = Path(directory) / "journal.m"
            executable = Path(directory) / "journal"
            source.write_text(
                "#import <Foundation/Foundation.h>\n#include <stdio.h>\n" +
                MOCKS + catalog + sha + proof + stock_proof + reconcile + HARNESS,
                encoding="utf-8",
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
        settle = self.transport.index("persistentIndexIdentitySettled = ", start)
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

    def test_publication_matrix_has_one_predispatch_checkpoint_and_results(self) -> None:
        apply_start = self.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        arm = self.source.index(
            'dispatchVariant[@"publicationDispatchPossible"]', apply_start
        )
        checkpoint = self.source.index(
            "CNDRemixAppendIconServicesJournalCheckpoint(", arm
        )
        publish = self.source.index(
            "CNDIconServicesPublisherPublishVariantsInBatch(", checkpoint
        )
        result = self.source.index('variantJournal[@"publication"] =', publish)
        self.assertLess(checkpoint, publish)
        self.assertLess(publish, result)
        self.assertIn('@"publicationDispatchPossible": @NO', self.source[:arm])
        self.assertNotIn("CNDIconServicesPublisherPublishVariantInBatch(",
                         self.source[apply_start:])

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"),
                         "requires macOS Foundation and clang")
    def test_compiled_stock_original_write_readback_invalidate_and_delete(self) -> None:
        def section(start: str, end: str) -> str:
            begin = self.source.index(start)
            return self.source[begin:self.source.index(end, begin)]

        sha256_function = section(
            "static NSString *CNDRemixSHA256(NSData *data)",
            "static NSString *CNDRemixCanonicalRGBAHashForPNG(",
        )
        sha_string = section(
            "static BOOL CNDRemixIsSHA256String(NSString *value)\n{",
            "static NSString *CNDRemixPayloadPlatformIdentifier(",
        )
        journal_helpers = section(
            "static NSURL *CNDRemixIconServicesJournalURL(",
            "static NSDictionary<NSString *, NSData *> *CNDRemixNormalizedThemeLookup(",
        )
        originals = section(
            "static NSString *CNDRemixStockOriginalFilename(",
            "static NSArray<CNDIconServicesDescriptorSpec *> *\n"
            "CNDRemixDescriptorSpecificationsForBundleIdentifier(",
        )
        self.assertIn("CNDRemixIconServicesStockOriginalDirectoryURL(", journal_helpers)
        with tempfile.TemporaryDirectory(prefix="cyanide-stock-originals-") as directory:
            source = Path(directory) / "originals.m"
            executable = Path(directory) / "originals"
            root_literal = (
                Path(directory).as_posix().replace("\\", "\\\\").replace('"', '\\"')
            )
            source.write_text(
                "#import <Foundation/Foundation.h>\n"
                "#include <stdio.h>\n"
                "#import <CommonCrypto/CommonDigest.h>\n"
                "const NSUInteger CNDIconServicesPublisherMaximumStructuredDataLength"
                " = 64;\n"
                "static const NSUInteger CNDRemixIconServicesCheckpointSchemaVersion = 1;\n"
                "static const NSUInteger CNDRemixIconServicesCheckpointMaximumRecords = 256;\n"
                "static const NSUInteger "
                "CNDRemixIconServicesCheckpointMaximumVariantUpdates = 64;\n"
                f'static NSString * const TestRoot = @"{root_literal}/store";\n'
                "static NSURL *CNDRemixIconServicesRootURL(void) {\n"
                "    return [NSURL fileURLWithPath:TestRoot isDirectory:YES];\n"
                "}\n"
                "static NSURL *CNDRemixIconServicesTransactionsURL(void) {\n"
                "    return [CNDRemixIconServicesRootURL() "
                "URLByAppendingPathComponent:@\"Transactions\" isDirectory:YES];\n"
                "}\n"
                + sha256_function + sha_string + journal_helpers + originals
                + STOCK_ORIGINAL_HARNESS,
                encoding="utf-8",
            )
            subprocess.run(["clang", "-fobjc-arc", "-framework", "Foundation",
                            str(source), "-o", str(executable)],
                           check=True, capture_output=True)
            subprocess.run([str(executable)], check=True, capture_output=True)

    def test_transport_saved_original_falls_back_to_generation(self) -> None:
        start = self.transport.index("if (savedStockOriginal) {")
        end = self.transport.index(
            "triggerFinishedAt = CFAbsoluteTimeGetCurrent();", start
        )
        branch = self.transport[start:end]
        self.assertIn(
            '"findStoreUnitForIcon:descriptor:UUID:validationToken:"', branch
        )
        self.assertIn("managerCache,", branch)
        # The journaled original is only used when the live index still carries
        # this descriptor's record; otherwise the run generates its own stock.
        self.assertIn("stockUsedSavedOriginal = stockUUID && stockToken;",
                      branch)
        self.assertIn("if (stockUsedSavedOriginal) {", branch)
        self.assertIn("if (!stockUsedSavedOriginal) {", branch)
        resolve = branch.index("stockUsedSavedOriginal = stockUUID && stockToken;")
        generate = branch.index('"generateImageWithDescriptor:"')
        self.assertLess(resolve, generate)
        self.assertIn("? @\"stock-api-saved-original-identity\"\n"
                      "                        : @\"stock-api-generation-response\"",
                      self.transport)
        # The daemon copy must equal the journaled bytes before any write, and
        # a mismatch falls back to generation rather than failing the run.
        readback = branch.index("![staged isEqualToData:savedStockOriginal]")
        self.assertIn("NSData *staged = stockData", branch)
        self.assertLess(readback, branch.index("if (!stockUsedSavedOriginal) {"))
        self.assertIn("stockUsedSavedOriginal = NO;", branch[readback:])
        remove = self.transport.index("directStoreRemoveIssued = YES;")
        self.assertLess(self.transport.index("![staged isEqualToData:", 0), remove)
        # The report never claims a journaled original it fell back from.
        self.assertIn('report[@"stockOriginalUsed"] = @(stockUsedSavedOriginal);',
                      self.transport)
        self.assertIn("report[@\"stockIdentitySource\"] = stockUsedSavedOriginal",
                      self.transport)
        # The saved bytes are supplied only for the bundle that recorded them.
        self.assertIn(
            "!replacing && [batch.savedStockOriginalsBundleIdentifier\n"
            "            isEqualToString:bundleIdentifier]",
            self.transport,
        )

    def test_restore_supplies_only_hash_verified_originals(self) -> None:
        start = self.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals("
        )
        end = self.source.index("\n@implementation CNDSnowBoardRemix", start)
        restore = self.source[start:end]
        load = restore.index("CNDRemixLoadStockOriginal(")
        supply = restore.index(
            "CNDIconServicesPublisherSetSavedStockOriginalsInBatch("
        )
        matrix = restore.index(
            "CNDIconServicesPublisherRestoreStockVariantsInBatch("
        )
        clear = restore.index(
            "CNDIconServicesPublisherSetSavedStockOriginalsInBatch(\n"
            "                        nil, bundleIdentifier);",
            supply,
        )
        self.assertLess(load, supply)
        self.assertLess(supply, matrix)
        self.assertLess(matrix, clear)
        self.assertIn("[identity isKindOfClass:NSString.class]", restore)
        # An updated application must never reuse pre-update saved bytes.
        fingerprint = restore.index(
            "BOOL originalsMatchCurrentInstallation ="
        )
        self.assertIn("CNDRemixApplicationFingerprintMatches(", restore)
        self.assertIn('saved[@"applicationFingerprint"]', restore)
        self.assertLess(fingerprint, load)
        # A restored app clears the whole app's originals with its journal.
        self.assertIn("CNDRemixRemoveIconServicesJournal(bundleIdentifier)", restore)

    def test_apply_captures_and_records_the_stock_original(self) -> None:
        start = self.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        end = self.source.index(
            "CNDRemixDeferredSpringBoardPresentationRestore(", start
        )
        apply = self.source[start:end]
        capture = apply.index(
            "CNDIconServicesPublisherSetCapturesStockOriginalsInBatch("
        )
        publish = apply.index("CNDIconServicesPublisherPublishVariantsInBatch(")
        released = apply.index(
            "CNDIconServicesPublisherSetCapturesStockOriginalsInBatch(\n"
            "                        NO);"
        )
        self.assertLess(capture, publish)
        self.assertLess(publish, released)
        self.assertIn("CNDRemixSaveStockOriginal(", apply)
        self.assertIn("[variantJournal\n                                addEntriesFromDictionary:stockOriginal];",
                      apply)

    def test_update_rebase_regenerates_stock_instead_of_reusing_originals(self) -> None:
        start = self.source.index(
            "static NSDictionary *CNDRemixRebaseActiveJournalToCurrentStock("
        )
        end = self.source.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme(",
            start,
        )
        rebase = self.source[start:end]
        self.assertNotIn("CNDRemixLoadStockOriginal(", rebase)
        self.assertNotIn("SetSavedStockOriginalsInBatch", rebase)
        self.assertIn("CNDRemixRemoveIconServicesJournal(", rebase)

    def test_journal_retirement_removes_the_app_originals(self) -> None:
        start = self.source.index(
            "static BOOL CNDRemixRemoveIconServicesJournal(NSString *bundleIdentifier)"
        )
        end = self.source.index(
            "static NSArray<NSDictionary *> *CNDRemixIconServicesJournals(void)",
            start,
        )
        retirement = self.source[start:end]
        journal_removal = retirement.index("if (!removed) return NO;")
        originals = retirement.index(
            "CNDRemixIconServicesStockOriginalDirectoryURL(bundleIdentifier)"
        )
        self.assertLess(journal_removal, originals)

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
