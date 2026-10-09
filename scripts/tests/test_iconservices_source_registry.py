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

MOCKS = r'''
#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const NSUInteger CNDIconServicesPublisherMaximumPersistentIndexLength = 64U << 20;
static const NSUInteger CNDIconServicesPublisherMaximumPersistentIdentifierLength = 128U;
static const NSUInteger CNDIconServicesPublisherAuditMaximumSourceIdentifiers = 32U;
static const uint64_t R_TIMEOUT = 1;
static NSMutableData *mapData;
static BOOL abiOK = YES, mapValid = YES, uuidOK = YES;
static NSUInteger copyNumber, rejectCopyNumber;
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
    if (!strcmp(selector, "length")) return mapData.length;
    if (!strcmp(selector, "bytes")) return (uintptr_t)mapData.bytes;
    return 0;
}
static uint64_t r_dlsym_call(uint64_t timeout, const char *symbol,
    uint64_t a, uint64_t b, uint64_t c, uint64_t d,
    uint64_t e, uint64_t f, uint64_t g, uint64_t h) {
    (void)timeout; (void)d; (void)e; (void)f; (void)g; (void)h;
    if (!strcmp(symbol, "object_getClass")) return 1;
    if (!strcmp(symbol, "CFDataGetLength")) return mapData.length;
    if (!strcmp(symbol, "CFDataGetBytePtr")) return (uintptr_t)mapData.bytes;
    if (strcmp(symbol, "memcpy")) return 0;
    if (++copyNumber == rejectCopyNumber) return 0;
    uintptr_t mapStart = (uintptr_t)mapData.bytes;
    if (b < mapStart || b - mapStart > mapData.length ||
        c > mapData.length - (b - mapStart)) abort();
    memcpy((void *)(uintptr_t)a, (const void *)(uintptr_t)b, c);
    return a;
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
    return cnd_publisher_source_registry_entries(
        1, 1, (uintptr_t)scratchBytes, failure);
}
static BOOL failedAt(NSString *expected) {
    NSString *failure = nil;
    NSArray *entries = readEntries(&failure);
    return !entries && [failure isEqualToString:
        [@"stock-api-source-registry-readback-" stringByAppendingString:expected]];
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
        for (NSUInteger copy = 1; copy <= 4; copy++) {
            copyNumber = 0; rejectCopyNumber = copy;
            CHECK(failedAt(@[@"header-copy", @"bucket-copy",
                             @"node-copy", @"payload-copy"][copy - 1]));
        }
        rejectCopyNumber = 0;

        resetMap(42); set32(0x0c, 0); CHECK(failedAt(@"capacity"));
        resetMap(42); set32(0x10, 43); CHECK(failedAt(@"extent"));
        resetMap(42); set64(0x14, ((uint64_t)43 << 32));
        CHECK(failedAt(@"node-bounds"));

        resetMap(42);
        uint64_t reference = addNode(0, wantedUUID, source, 0, YES);
        set64(0x14, reference); set64(nodesStart(), reference + 1);
        CHECK(failedAt(@"node-reference"));

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
    def test_mapped_data_access_stays_inside_target_corefoundation(self) -> None:
        source = TRANSPORT.read_text(encoding="utf-8")
        reader_start = source.index(
            "static NSArray<NSData *> *cnd_publisher_source_registry_entries("
        )
        reader_end = source.index(
            "static BOOL cnd_publisher_source_array_contains_all(", reader_start
        )
        reader = source[reader_start:reader_end]
        self.assertIn('"CFDataGetLength", mapData', reader)
        self.assertIn('"CFDataGetBytePtr", mapData', reader)
        self.assertNotIn('r_msg2(mapData, "length"', reader)
        self.assertNotIn('r_msg2(mapData, "bytes"', reader)

        repair_start = source.index(
            "static BOOL cnd_publisher_repair_airdrop_source_registry("
        )
        repair_end = source.index(
            "static NSDictionary<NSString *, id> *cnd_publisher_audit_variant(",
            repair_start,
        )
        repair = source[repair_start:repair_end]
        self.assertIn('"CFDataGetLength", mapData', repair)
        self.assertIn('"CFDataGetBytePtr", mapData', repair)
        self.assertNotIn('r_msg2(mapData, "length"', repair)
        self.assertNotIn('r_msg2(mapData, "bytes"', repair)

    def test_precise_readback_failure_survives_publication_reporting(self) -> None:
        source = TRANSPORT.read_text(encoding="utf-8")
        self.assertIn('report[@"sourceRegistryReadbackStage"]', source)
        start = source.index("static BOOL cnd_publisher_source_array_contains_all(")
        repair = source[start:source.index(
            "static NSDictionary<NSString *, id> *cnd_publisher_audit_variant(", start
        )]
        self.assertIn("immediate && !readbackFailure &&", repair)
        self.assertIn("freshRegistry && freshValues &&", repair)
        self.assertIn("failure = readbackFailure ?: (freshRegistry", repair)

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
        reader = source[node_type_start:reader_end]
        with tempfile.TemporaryDirectory(prefix="cyanide-source-registry-") as directory:
            fixture = Path(directory) / "source_registry.m"
            executable = Path(directory) / "source_registry"
            fixture.write_text(MOCKS + reader + HARNESS, encoding="utf-8")
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
