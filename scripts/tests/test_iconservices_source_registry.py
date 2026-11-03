"""Execute the production source-registry reader against host-only map fixtures."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TRANSPORT = ROOT / "Cyanide/installer/CNDIconServicesPublisherRemoteTransport.m"
REMIX = ROOT / "Cyanide/installer/CNDSnowBoardRemix.m"

MOCKS = r'''
#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const NSUInteger CNDIconServicesPublisherMaximumPersistentIndexLength = 64U << 20;
static const uint64_t CNDIconServicesPublisherMaximumSourceRegistryMappedLength = 512ULL << 20;
static const NSUInteger CNDIconServicesPublisherMaximumPersistentIdentifierLength = 128U;
static const NSUInteger CNDIconServicesPublisherAuditMaximumSourceIdentifiers = 32U;
static const uint64_t R_TIMEOUT = 1;
static NSMutableData *mapData;
static BOOL abiOK = YES, mapValid = YES, uuidOK = YES;
static NSUInteger copyNumber, rejectCopyNumber;
static NSUInteger headerCopyNumber, changeHeaderCopyNumber;
static NSUInteger nodeHeaderReadNumber, changeNodeHeaderReadNumber;
static int64_t reportedStatSize = -1;
static int64_t reportedMappedLength = -1;
static NSUInteger mappedHeaderCopyCount;
static NSDictionary *lastReferenceDiagnostics;
static uint8_t scratchBytes[4096], wantedUUID[16];

static BOOL remote_call_current_success(void) { return YES; }
static BOOL remote_read(uint64_t address, void *bytes, size_t length) {
    memcpy(bytes, (const void *)(uintptr_t)address, length);
    return YES;
}
static uint64_t cnd_publisher_audit_object_ivar(
    uint64_t object, const char *name, uint64_t offset, uint64_t scratch) {
    (void)object; (void)name; (void)offset; (void)scratch;
    return 1;
}
static BOOL cnd_publisher_remote_method_has_types(
    uint64_t cls, const char *selector, const char *types, const char *other) {
    (void)cls; (void)selector; (void)types; (void)other;
    return abiOK;
}
static uint64_t r_msg2(uint64_t object, const char *selector,
                        uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    (void)object; (void)a; (void)b; (void)c; (void)d;
    if (!strcmp(selector, "_ISStoreIndex_isValid")) return mapValid;
    if (!strcmp(selector, "length")) return reportedMappedLength >= 0
        ? (uint64_t)reportedMappedLength : mapData.length;
    if (!strcmp(selector, "bytes")) return (uintptr_t)mapData.bytes;
    return 0;
}
static uint64_t r_dlsym_call(uint64_t timeout, const char *symbol,
    uint64_t a, uint64_t b, uint64_t c, uint64_t d,
    uint64_t e, uint64_t f, uint64_t g, uint64_t h) {
    (void)timeout; (void)e; (void)f; (void)g; (void)h;
    if (!strcmp(symbol, "object_getClass")) return 1;
    if (!strcmp(symbol, "fstat")) {
        struct stat status = {0};
        status.st_mode = S_IFREG | 0600;
        status.st_size = reportedStatSize >= 0
            ? reportedStatSize : (int64_t)mapData.length;
        memcpy((void *)(uintptr_t)b, &status, sizeof(status));
        return 0;
    }
    if (!strcmp(symbol, "memcpy")) {
        mappedHeaderCopyCount++;
        memcpy((void *)(uintptr_t)a, (const void *)(uintptr_t)b, c);
        return a;
    }
    if (strcmp(symbol, "pread")) return 0;
    (void)a;
    if (++copyNumber == rejectCopyNumber) return 0;
    if (d > mapData.length || c > mapData.length - d) return 0;
    memcpy((void *)(uintptr_t)b,
           (const uint8_t *)mapData.bytes + d, c);
    if (c == 0x14 && d == 0 &&
        ++headerCopyNumber == changeHeaderCopyNumber) {
        uint32_t changedNodeBytes = 0;
        memcpy(&changedNodeBytes,
               (const void *)(uintptr_t)(b + 0x10),
               sizeof(changedNodeBytes));
        changedNodeBytes++;
        memcpy((void *)(uintptr_t)(b + 0x10),
               &changedNodeBytes, sizeof(changedNodeBytes));
    }
    if (c == 0x24 &&
        ++nodeHeaderReadNumber == changeNodeHeaderReadNumber) {
        uint64_t changedReference = 0;
        memcpy(&changedReference, (const void *)(uintptr_t)b,
               sizeof(changedReference));
        changedReference++;
        memcpy((void *)(uintptr_t)b, &changedReference,
               sizeof(changedReference));
    }
    return c;
}
static BOOL cnd_publisher_copy_remote_uuid_bytes(
    uint64_t uuid, uint64_t scratch, uint8_t bytes[16]) {
    (void)uuid; (void)scratch;
    memcpy(bytes, wantedUUID, 16);
    return uuidOK;
}
'''

HARNESS = r'''
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "source-registry fixture failed at line %d: %s\n", \
            __LINE__, #condition); return 1; } } while (0)
static void set32(NSUInteger offset, uint32_t value) {
    memcpy((uint8_t *)mapData.mutableBytes + offset, &value, sizeof(value));
}
static void set64(NSUInteger offset, uint64_t value) {
    memcpy((uint8_t *)mapData.mutableBytes + offset, &value, sizeof(value));
}
static NSUInteger nodesStart(void) { return 0x14 + 4000 * 8; }
static void resetMap(NSUInteger nodeLength) {
    mapData = [NSMutableData dataWithLength:nodesStart() + nodeLength];
    set32(0, 11); set32(4, 1); set32(0x0c, 4000); set32(0x10, (uint32_t)nodeLength);
    memset(wantedUUID, 0, 16);
    abiOK = YES; mapValid = YES; uuidOK = YES;
    copyNumber = 0; rejectCopyNumber = 0;
    headerCopyNumber = 0; changeHeaderCopyNumber = 0;
    nodeHeaderReadNumber = 0; changeNodeHeaderReadNumber = 0;
    reportedStatSize = -1;
    reportedMappedLength = -1;
    mappedHeaderCopyCount = 0;
    lastReferenceDiagnostics = nil;
}
static uint64_t addNode(uint32_t offset, const uint8_t uuid[16],
    NSData *payload, uint64_t next, BOOL active) {
    CNDIconServicesSourceRegistryNodeHeader23A341 header = {0};
    header.reference = ((uint64_t)(sizeof(header) + payload.length) << 32) | offset;
    memcpy(header.uuid, uuid, 16); header.nextReference = next; header.active = active;
    memcpy((uint8_t *)mapData.mutableBytes + nodesStart() + offset,
           &header, sizeof(header));
    memcpy((uint8_t *)mapData.mutableBytes + nodesStart() + offset + sizeof(header),
           payload.bytes, payload.length);
    return header.reference;
}
static NSArray *readEntries(NSString **failure) {
    NSDictionary *diagnostics = nil;
    NSArray *entries = cnd_publisher_source_registry_entries(
        1, 1, (uintptr_t)scratchBytes,
        1, mapData.length, failure, &diagnostics);
    lastReferenceDiagnostics = diagnostics;
    return entries;
}
static BOOL failedAt(NSString *expected) {
    NSString *failure = nil;
    NSArray *entries = readEntries(&failure);
    NSString *prefix = [@"stock-api-source-registry-readback-"
        stringByAppendingString:expected];
    return !entries && [failure hasPrefix:prefix];
}
int main(void) {
    @autoreleasepool {
        NSData *source = [@"source" dataUsingEncoding:NSUTF8StringEncoding];
        NSString *failure = nil;
        resetMap(0);
        CHECK(readEntries(&failure).count == 0 && !failure);

        // A real map starts its first packed node at 0x14 + capacity * 8.
        // Offset zero is a valid initial reference when its size word is set.
        resetMap(42);
        set64(0x14, addNode(0, wantedUUID, source, 0, YES));
        CHECK([readEntries(&failure) isEqualToArray:@[source]] && !failure);

        // The physical transport may copy an implausible fstat st_size. The
        // validated mapped NSData and independent descriptor probes own length.
        reportedStatSize = 0;
        CHECK([readEntries(&failure) isEqualToArray:@[source]] && !failure);
        reportedStatSize = -1;

        // Apple's map reserves page-aligned growth capacity beyond used nodes.
        // The mapped length is physical EOF; logicalLength is only a lower bound.
        CNDIconServicesSourceRegistryExtent extent = {0};
        NSString *extentStage = nil;
        copyNumber = 0; headerCopyNumber = 0;
        CHECK(cnd_publisher_source_registry_extent(
            1, 1, (uintptr_t)scratchBytes, &extent, &extentStage));
        CHECK(extent.mappedLength == mapData.length);
        CHECK(extent.logicalLength == mapData.length);
        CHECK([extentStage isEqualToString:@"verified-file"]);
        [mapData increaseLengthBy:4096];
        copyNumber = 0; headerCopyNumber = 0;
        CHECK(cnd_publisher_source_registry_extent(
            1, 1, (uintptr_t)scratchBytes, &extent, &extentStage));
        CHECK(extent.mappedLength == mapData.length);
        CHECK(extent.logicalLength + 4096 == extent.mappedLength);
        CHECK([readEntries(&failure) isEqualToArray:@[source]] && !failure);
        [mapData setLength:mapData.length - 4096];

        // Physical evidence carried a page-aligned 0x56b0000-byte map. It is
        // native growth padding, not a reason to reuse the store index's
        // unrelated 64 MiB ceiling.
        NSUInteger compactLength = mapData.length;
        [mapData setLength:0x56b0000];
        copyNumber = 0; headerCopyNumber = 0;
        CHECK(cnd_publisher_source_registry_extent(
            1, 1, (uintptr_t)scratchBytes, &extent, &extentStage));
        CHECK(extent.mappedLength == 0x56b0000);
        CHECK(extent.logicalLength == compactLength);
        CHECK(extent.mappedLength >
            CNDIconServicesPublisherMaximumPersistentIndexLength);
        CHECK([readEntries(&failure) isEqualToArray:@[source]] && !failure);
        [mapData setLength:compactLength];

        // The dedicated ceiling remains fail-closed, but only after the
        // fixed header was copied and classified.
        reportedMappedLength =
            CNDIconServicesPublisherMaximumSourceRegistryMappedLength + 1;
        mappedHeaderCopyCount = 0;
        CHECK(!cnd_publisher_source_registry_extent(
            1, -1, (uintptr_t)scratchBytes, &extent, &extentStage));
        CHECK(mappedHeaderCopyCount == 1);
        CHECK([extentStage isEqualToString:@"mapped-physical-limit"]);
        reportedMappedLength = -1;

        // Adding a node grows the used extent without requiring allocation EOF
        // to coincide with it. A genuinely truncated logical extent fails.
        NSUInteger originalNodeLength = mapData.length - nodesStart();
        set32(0x10, (uint32_t)(originalNodeLength + 42));
        copyNumber = 0; headerCopyNumber = 0;
        CHECK(!cnd_publisher_source_registry_extent(
            1, 1, (uintptr_t)scratchBytes, &extent, &extentStage));
        CHECK([extentStage isEqualToString:@"mapped-logical-extent"]);
        set32(0x10, (uint32_t)originalNodeLength);

        // A changed header-derived length during the read invalidates the
        // snapshot even when fstat's copied scalar size is untrustworthy.
        copyNumber = 0; headerCopyNumber = 0; changeHeaderCopyNumber = 2;
        CHECK(failedAt(@"changed:"));
        changeHeaderCopyNumber = 0;

        // Native termination checks only the next-reference offset word.
        set64(nodesStart() + 0x18, (uint64_t)42 << 32);
        CHECK([readEntries(&failure) isEqualToArray:@[source]] && !failure);

        // Match the observed simulator map's first two node sizes (72/64)
        // without retaining its LaunchServices identities in the fixture.
        resetMap(136);
        NSData *source36 = [NSMutableData dataWithLength:36];
        NSData *source28 = [NSMutableData dataWithLength:28];
        uint64_t second = addNode(72, wantedUUID, source28, 0, YES);
        set64(0x14, addNode(0, wantedUUID, source36, second, YES));
        NSArray *twoSources = @[source36, source28];
        CHECK([readEntries(&failure) isEqualToArray:twoSources] && !failure);

        // Ignore inactive and colliding UUID nodes, preserving chain traversal.
        resetMap(126);
        uint8_t collisionUUID[16] = {1, 0, 0, 0, 0, 0, 0, 0,
                                     1, 0, 0, 0, 0, 0, 0, 0};
        uint64_t tail = addNode(84, wantedUUID, source, 0, YES);
        uint64_t middle = addNode(42, collisionUUID, source, tail, YES);
        set64(0x14, addNode(0, wantedUUID, source, middle, NO));
        CHECK([readEntries(&failure) isEqualToArray:@[source]] && !failure);

        resetMap(42);
        set64(0x14, addNode(0, wantedUUID, source, 0, YES));
        abiOK = NO; CHECK(failedAt(@"abi")); abiOK = YES;
        mapValid = NO; CHECK(failedAt(@"map")); mapValid = YES;
        uuidOK = NO; CHECK(failedAt(@"uuid")); uuidOK = YES;

        resetMap(42);
        set64(0x14, addNode(0, wantedUUID, source, 0, YES));
        NSUInteger rejectedCopies[] = {1, 4, 5, 6};
        for (NSUInteger copy = 0; copy < 4; copy++) {
            copyNumber = 0; rejectCopyNumber = rejectedCopies[copy];
            CHECK(failedAt(@[@"extent:", @"bucket-copy",
                             @"node-copy", @"payload-copy"][copy]));
        }
        rejectCopyNumber = 0;

        resetMap(42); set32(0, 12); CHECK(failedAt(@"extent:mapped-header"));
        resetMap(42); set32(4, 2); CHECK(failedAt(@"extent:mapped-header"));
        resetMap(42); set32(0x0c, 0); CHECK(failedAt(@"extent:mapped-capacity"));
        resetMap(42); set32(0x10, 43); CHECK(failedAt(@"extent:mapped-logical-extent"));
        resetMap(42); set64(0x14, ((uint64_t)43 << 32));
        CHECK(failedAt(@"node-bounds"));

        resetMap(42);
        uint64_t reference = addNode(0, wantedUUID, source, 0, YES);
        set64(0x14, reference); set64(nodesStart(), reference + 1);
        CHECK(failedAt(@"node-reference"));
        CHECK([lastReferenceDiagnostics[@"classification"]
            isEqualToString:@"stable-reference-invariant-mismatch"]);
        CHECK([lastReferenceDiagnostics[@"diagnosticReadsComplete"] boolValue]);
        CHECK([lastReferenceDiagnostics[@"linkStable"] boolValue]);
        CHECK([lastReferenceDiagnostics[@"nodeStable"] boolValue]);
        CHECK([lastReferenceDiagnostics[@"metadataStable"] boolValue]);
        CHECK(![lastReferenceDiagnostics[@"expectedReference"]
            isEqual:lastReferenceDiagnostics[@"observedNodeReference"]]);

        resetMap(42);
        reference = addNode(0, wantedUUID, source, 0, YES);
        set64(0x14, reference); set64(nodesStart(), reference + 1);
        changeNodeHeaderReadNumber = 2;
        CHECK(failedAt(@"node-reference"));
        CHECK([lastReferenceDiagnostics[@"classification"]
            isEqualToString:@"live-map-churn"]);
        CHECK([lastReferenceDiagnostics[@"diagnosticReadsComplete"] boolValue]);
        CHECK([lastReferenceDiagnostics[@"linkStable"] boolValue]);
        CHECK(![lastReferenceDiagnostics[@"nodeStable"] boolValue]);
        CHECK([lastReferenceDiagnostics[@"metadataStable"] boolValue]);

        resetMap(42);
        reference = addNode(0, wantedUUID, source, 0, YES);
        set64(0x14, reference); set64(nodesStart(), reference + 1);
        rejectCopyNumber = 6;
        CHECK(failedAt(@"node-reference"));
        CHECK([lastReferenceDiagnostics[@"classification"]
            isEqualToString:@"diagnostic-read-incomplete"]);
        CHECK(![lastReferenceDiagnostics[@"diagnosticReadsComplete"] boolValue]);
        CHECK(![lastReferenceDiagnostics[@"linkRereadSucceeded"] boolValue]);
        rejectCopyNumber = 0;

        resetMap(126);
        tail = addNode(84, wantedUUID, source, ((uint64_t)42 << 32) | 42, YES);
        middle = addNode(42, wantedUUID, source, tail, YES);
        set64(0x14, addNode(0, wantedUUID, source, middle, YES));
        CHECK(failedAt(@"chain"));

        resetMap(165);
        NSData *oversize = [NSMutableData dataWithLength:129];
        set64(0x14, addNode(0, wantedUUID, oversize, 0, YES));
        CHECK(failedAt(@"payload-bounds"));

        resetMap(36);
        set64(0x14, addNode(0, wantedUUID, [NSData data], 0, YES));
        CHECK(failedAt(@"payload-bounds"));

        resetMap(33 * 42);
        uint64_t next = 0;
        for (int node = 32; node >= 0; node--)
            next = addNode((uint32_t)node * 42, wantedUUID, source, next, YES);
        set64(0x14, next); CHECK(failedAt(@"payload-bounds"));

        resetMap(0); [mapData setLength:19]; CHECK(failedAt(@"length"));
        fprintf(stdout, "source-registry host fixtures passed\n");
    }
    return 0;
}
'''


class IconServicesSourceRegistryTests(unittest.TestCase):
    def test_mapped_data_access_uses_separate_bounded_file_mapping(self) -> None:
        source = TRANSPORT.read_text(encoding="utf-8")
        reader_start = source.index(
            "static NSArray<NSData *> *cnd_publisher_source_registry_entries("
        )
        reader_end = source.index(
            "static BOOL cnd_publisher_source_array_contains_all(", reader_start
        )
        reader = source[reader_start:reader_end]
        self.assertIn("int fileDescriptor, uint64_t fileLength", reader)
        self.assertIn('"pread", (uint64_t)fileDescriptor', reader)
        self.assertEqual(
            reader.count("cnd_publisher_source_registry_extent("), 2
        )
        self.assertNotIn("statusAfter.st_size == statusBefore.st_size", reader)
        self.assertNotIn("statusBefore.st_size", reader)
        self.assertNotIn("statusAfter.st_size", reader)
        self.assertNotIn('"CFDataGetLength"', reader)
        self.assertNotIn('"CFDataGetBytePtr"', reader)
        self.assertNotIn('r_msg2(mapData, "length"', reader)
        self.assertNotIn('r_msg2(mapData, "bytes"', reader)

        mapper_start = source.index(
            "static uint64_t cnd_publisher_source_registry_map("
        )
        mapper = source[mapper_start:reader_start]
        self.assertIn('"CFURLGetFileSystemRepresentation"', mapper)
        self.assertIn("memchr(pathBytes, '\\0', sizeof(pathBytes))", mapper)
        self.assertIn('(writableFile ? O_RDWR : O_RDONLY) | O_CLOEXEC', mapper)
        self.assertIn('"fstat", (uint64_t)fileDescriptor, scratch', mapper)
        self.assertIn("cnd_publisher_source_registry_extent(", mapper)
        self.assertIn("cnd_publisher_record_source_registry_extent(", mapper)
        self.assertNotIn('"mmap"', mapper)

        extent_start = source.index(
            "static BOOL cnd_publisher_source_registry_extent("
        )
        extent_proof = source[extent_start:mapper_start]
        self.assertGreaterEqual(
            extent_proof.count('"pread", (uint64_t)fileDescriptor'), 3
        )
        self.assertIn('mappedData, "length"', extent_proof)
        self.assertIn('mappedData, "bytes"', extent_proof)
        self.assertIn('"memcpy", scratch, mappedBytes, 0x14', extent_proof)
        self.assertIn("mappedHeader[0x4]", extent_proof)
        self.assertIn(
            "CNDIconServicesPublisherMaximumSourceRegistryMappedLength",
            extent_proof,
        )
        self.assertIn('@"mapped-physical-limit"', extent_proof)
        self.assertNotIn(
            "CNDIconServicesPublisherMaximumPersistentIndexLength",
            extent_proof,
        )
        self.assertIn("logicalLength > mappedLength", extent_proof)
        self.assertIn("memcmp(fileHeader, mappedHeader", extent_proof)
        self.assertIn("scratch + 0x40, 1, mappedLength - 1", extent_proof)
        self.assertIn("scratch + 0x41, 1, mappedLength", extent_proof)
        self.assertIn("eofRead != 0", extent_proof)
        self.assertNotIn('"lseek"', extent_proof)
        self.assertNotIn("st_size", extent_proof)
        self.assertNotIn("logicalLength - 1", extent_proof)

        repair_start = source.index(
            "static BOOL cnd_publisher_repair_airdrop_source_registry(",
            reader_end,
        )
        repair_end = source.index(
            "static NSDictionary<NSString *, id> *cnd_publisher_audit_variant(",
            repair_start,
        )
        repair = source[repair_start:repair_end]
        self.assertNotIn('"CFDataGetLength"', repair)
        self.assertNotIn('"CFDataGetBytePtr"', repair)
        self.assertNotIn('r_msg2(mapData, "length"', repair)
        self.assertNotIn('r_msg2(mapData, "bytes"', repair)
        self.assertIn("batch.auditSourceRegistryFileDescriptor", repair)
        self.assertIn("cnd_publisher_close_source_registry_file(batch)", repair)
        self.assertIn('registry, "_data", 0x10, scratch', repair)
        self.assertIn("writeMapData, -1, scratch", repair)
        self.assertIn('"msync", writeExtent.mappedBytes', repair)
        self.assertIn("writeExtent.mappedLength, MS_SYNC", repair)
        add_data = repair.index('registry, "addData:forUUID:"')
        post_write_extent = repair.index(
            "cnd_publisher_source_registry_extent(", add_data
        )
        release = repair.index('r_msg2(registry, "release"', post_write_extent)
        fresh_map = repair.index("uint64_t freshRegistry", release)
        descriptor_sync = repair.index('"fsync"', fresh_map)
        fresh_readback = repair.index(
            "freshValues = freshRegistry", descriptor_sync
        )
        self.assertLess(add_data, post_write_extent)
        self.assertLess(post_write_extent, release)
        self.assertLess(release, fresh_map)
        self.assertLess(fresh_map, descriptor_sync)
        self.assertLess(descriptor_sync, fresh_readback)
        self.assertNotIn('"mmap"', repair)
        self.assertNotIn('"munmap"', repair)
        self.assertNotIn("immediate", repair)
        self.assertIn(
            "result.writeVerified = result.freshReadbackVerified", repair
        )
        self.assertIn(
            "batch, managerCache, scratch, YES, &mapFailure", repair
        )
        self.assertIn(
            "batch, managerCache, scratch, YES, &freshMapFailure", repair
        )
        self.assertEqual(
            repair.count('@"stock-api-source-registry-open:"'),
            2,
        )
        self.assertNotIn(
            "batch, managerCache, scratch, YES, NULL", repair
        )

        self.assertIn(
            '@"audit-source-registry-file-"', mapper
        )
        self.assertNotIn("file-length-proof", mapper)
        self.assertIn(
            '@"audit-source-registry-map-alloc"', mapper
        )
        self.assertIn(
            '@"audit-source-registry-map-init"', mapper
        )

    def test_precise_readback_failure_survives_publication_reporting(self) -> None:
        source = TRANSPORT.read_text(encoding="utf-8")
        self.assertIn('report[@"sourceRegistryReadbackStage"]', source)
        self.assertIn(
            'report[@"sourceRegistryReferenceDiagnostics"]', source
        )
        start = source.index("static BOOL cnd_publisher_source_array_contains_all(")
        repair = source[start:source.index(
            "static NSDictionary<NSString *, id> *cnd_publisher_audit_variant(", start
        )]
        self.assertIn("freshRegistry && freshValues &&", repair)
        self.assertIn("failure = readbackFailure ?: (freshRegistry", repair)
        self.assertIn(
            "result.writeVerified = result.freshReadbackVerified", repair
        )
        self.assertNotIn("immediate &&", repair)

    def test_reference_mismatch_telemetry_classifies_race_or_invariant(self) -> None:
        source = TRANSPORT.read_text(encoding="utf-8")
        diagnostics_start = source.index(
            "cnd_publisher_source_registry_reference_diagnostics("
        )
        reader_start = source.index(
            "static NSArray<NSData *> *cnd_publisher_source_registry_entries("
        )
        diagnostics = source[diagnostics_start:reader_start]
        self.assertIn('"pread", (uint64_t)fileDescriptor', diagnostics)
        self.assertIn("referenceSourceOffset", diagnostics)
        self.assertIn("nodeOffset", diagnostics)
        self.assertIn("statusAfter.st_mtimespec", diagnostics)
        self.assertIn("extentAfter.nodeBytes == extentBefore->nodeBytes", diagnostics)
        self.assertIn('@"live-map-churn"', diagnostics)
        self.assertIn('@"stable-reference-invariant-mismatch"', diagnostics)
        self.assertIn('@"diagnostic-read-incomplete"', diagnostics)
        self.assertIn('@"expectedReference"', diagnostics)
        self.assertIn('@"observedNodeReference"', diagnostics)
        self.assertIn('@"rereadLinkReference"', diagnostics)
        self.assertIn('@"rereadNodeReference"', diagnostics)

        remix = REMIX.read_text(encoding="utf-8")
        logger_start = remix.index(
            "static void CNDRemixLogIconServicesTransaction("
        )
        logger_end = remix.index(
            "static BOOL CNDRemixPublisherResultIsLegacyAcceptable(",
            logger_start,
        )
        logger = remix[logger_start:logger_end]
        self.assertIn('report[@"sourceRegistryReferenceDiagnostics"]', logger)
        self.assertIn("source-ref=%s expected=%s observed=%s", logger)
        self.assertIn("reread=%s/%s stable=%d/%d/%d reads=%d", logger)

    def test_precise_readback_failure_survives_applied_state_audit(self) -> None:
        source = TRANSPORT.read_text(encoding="utf-8")
        audit_start = source.index(
            "static NSDictionary<NSString *, id> *cnd_publisher_audit_variant("
        )
        audit_end = source.index(
            "@implementation CNDIconServicesPublisherRemoteTransport", audit_start
        )
        audit = source[audit_start:audit_end]
        self.assertIn(
            'failure = sourceFailure ?:\n'
            '                            @"audit-source-registry-readback";',
            audit,
        )
        self.assertNotIn(
            'failure = @"audit-source-registry-readback";',
            audit,
        )

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"),
                         "requires macOS Foundation and clang")
    def test_production_reader_with_host_map_fixtures(self) -> None:
        source = TRANSPORT.read_text(encoding="utf-8")
        node_type_start = source.index(
            "typedef struct __attribute__((packed)) {\n    uint64_t reference;"
        )
        reader_end = source.index(
            "static BOOL cnd_publisher_source_array_contains_all(", node_type_start
        )
        extent_type_start = source.index(
            "typedef struct {\n    uint64_t mappedBytes;"
        )
        extent_type_end = source.index(
            "static void cnd_publisher_record_source_registry_extent(",
            extent_type_start,
        )
        extent_start = source.index(
            "static BOOL cnd_publisher_source_registry_extent("
        )
        mapper_start = source.index(
            "static uint64_t cnd_publisher_source_registry_map(", extent_start
        )
        extent_type = source[extent_type_start:extent_type_end]
        extent_proof = source[extent_start:mapper_start]
        reader = source[node_type_start:reader_end]
        with tempfile.TemporaryDirectory(prefix="cyanide-source-registry-") as directory:
            fixture = Path(directory) / "source_registry.m"
            executable = Path(directory) / "source_registry"
            fixture.write_text(
                MOCKS + extent_type + extent_proof + reader + HARNESS,
                encoding="utf-8",
            )
            compiled = subprocess.run(
                ["clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
                 "-framework", "Foundation", str(fixture), "-o", str(executable)],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()
