//
//  CNDHailMaryImpRedirect.m
//  Cyanide
//

#import "CNDHailMaryImpRedirect.h"

#import "CNDHailMaryDataPage.h"
#import "CNDHailMaryPatch.h"
#import "CNDHailMaryProbe.h"
#import "CNDHailMaryReadOnlyDataPage.h"
#import "kexploit/kexploit_opa334.h"
#import "kexploit/krw.h"
#import "kexploit/kutils.h"

#import <CommonCrypto/CommonDigest.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define CND_HAIL_MARY_IMP_BUILD "23A341"
#define CND_HAIL_MARY_IMP_PRODUCT "iPhone17,2"
#define CND_HAIL_MARY_IMP_ORIGINAL_GUARD_SHA256 \
    "81c8a106d2a9e37a93d17d78dc7c54ea3b0ec4f036458a15e2ec1e4403d33677"
#define CND_HAIL_MARY_IMP_REDIRECTED_GUARD_SHA256 \
    "4ed8147447733303d0ae8043da89d2634f01af11c671540f8268a22d4dba906f"
#define CND_HAIL_MARY_IMP_ORIGINAL_GUARD_HEX \
    "c7f5e30b0008c40200000000c0ffffff0323ed0b0000cc1600000000c0ffffff"
#define CND_HAIL_MARY_IMP_REDIRECTED_GUARD_HEX \
    "baece30b0008c40200000000c0ffffff0323ed0b0000cc1600000000c0ffffff"

static const uint64_t kCNDHailMaryImpEntryUnslid =
    UINT64_C(0x1ffc27458);
static const uint64_t kCNDHailMaryImpOriginalEntry =
    UINT64_C(0x02c408000be3f5c7);
static const uint64_t kCNDHailMaryImpRedirectedEntry =
    UINT64_C(0x02c408000be3ecba);
static const uint32_t kCNDHailMaryImpOriginalWord =
    UINT32_C(0x0be3f5c7);
static const uint32_t kCNDHailMaryImpRedirectedWord =
    UINT32_C(0x0be3ecba);
static const size_t kCNDHailMaryImpGuardLength = 32;

static volatile int gCNDHailMaryImpRedirectRunning;

static NSString *CNDHailMaryImpHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static BOOL CNDHailMaryImpParseHex(NSString *text, uint64_t *valueOut)
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

static NSData *CNDHailMaryImpDataFromHex(NSString *text)
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

static NSString *CNDHailMaryImpBytesHex(const void *bytes, size_t length)
{
    if (!bytes || length == 0) return @"";
    const uint8_t *cursor = bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    for (size_t index = 0; index < length; index++) {
        [hex appendFormat:@"%02x", cursor[index]];
    }
    return hex;
}

static NSString *CNDHailMaryImpSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class] || data.length == 0 ||
        data.length > UINT32_MAX) {
        return @"";
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    return CNDHailMaryImpBytesHex(digest, sizeof(digest));
}

static NSString *CNDHailMaryImpOperationName(
    CNDHailMaryImpRedirectOperation operation)
{
    switch (operation) {
        case CNDHailMaryImpRedirectOperationApply: return @"apply";
        case CNDHailMaryImpRedirectOperationRestore: return @"restore";
        case CNDHailMaryImpRedirectOperationVerifyRedirected:
            return @"verify-redirected";
        case CNDHailMaryImpRedirectOperationVerifyOriginal:
            return @"verify-original";
    }
    return @"unknown";
}

static BOOL CNDHailMaryImpIsMutation(
    CNDHailMaryImpRedirectOperation operation)
{
    return operation == CNDHailMaryImpRedirectOperationApply ||
        operation == CNDHailMaryImpRedirectOperationRestore;
}

static BOOL CNDHailMaryImpExpectedRedirectedBefore(
    CNDHailMaryImpRedirectOperation operation)
{
    return operation == CNDHailMaryImpRedirectOperationRestore ||
        operation == CNDHailMaryImpRedirectOperationVerifyRedirected;
}

static NSString *CNDHailMaryImpReportPath(void)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    return [directory stringByAppendingPathComponent:
        @"CNDHailMaryImpRedirect.json"];
}

static NSString *CNDHailMaryImpPermissionReportPath(void)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    return [directory stringByAppendingPathComponent:
        @"CNDHailMaryReadOnlyDataPage.json"];
}

static BOOL CNDHailMaryImpSyncFileDescriptor(int descriptor)
{
    if (descriptor < 0) return NO;
#ifdef F_FULLFSYNC
    if (fcntl(descriptor, F_FULLFSYNC) == 0) return YES;
#endif
    return fsync(descriptor) == 0;
}

static BOOL CNDHailMaryImpSaveDurably(
    NSDictionary<NSString *, id> *report,
    NSString *path,
    NSString **errorOut)
{
    NSError *serializationError = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
                                                    options:NSJSONWritingPrettyPrinted |
                                                            NSJSONWritingSortedKeys
                                                      error:&serializationError];
    if (!data || path.length == 0) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-serialization-failed:%@",
            serializationError.localizedDescription ?: @"invalid-path"];
        return NO;
    }
    NSError *writeError = nil;
    if (![data writeToFile:path options:NSDataWritingAtomic
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
    BOOL fileSynced = CNDHailMaryImpSyncFileDescriptor(fileDescriptor);
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

static void CNDHailMaryImpFinish(
    NSMutableDictionary<NSString *, id> *report,
    CNDHailMaryImpRedirectCompletion completion)
{
    report[@"finishedAtUnixTime"] = @([[NSDate date]
        timeIntervalSince1970]);
    NSString *persistenceError = nil;
    if (!CNDHailMaryImpSaveDurably(
            report, report[@"reportPath"], &persistenceError)) {
        report[@"finalReportPersistenceError"] = persistenceError ?:
            @"final-report-durable-save-failed";
    }
    NSDictionary<NSString *, id> *finished = [report copy];
    __sync_lock_release(&gCNDHailMaryImpRedirectRunning);
    dispatch_async(dispatch_get_main_queue(), ^{
        completion(finished);
    });
}

static NSDictionary<NSString *, id> *CNDHailMaryImpLoadPermissionEvidence(
    NSString **errorOut)
{
    NSString *path = CNDHailMaryImpPermissionReportPath();
    NSData *data = [NSData dataWithContentsOfFile:path];
    NSError *jsonError = nil;
    id decoded = data.length > 0
        ? [NSJSONSerialization JSONObjectWithData:data
                                         options:0 error:&jsonError]
        : nil;
    NSDictionary<NSString *, id> *permission =
        [decoded isKindOfClass:NSDictionary.class] ? decoded : nil;
    NSDictionary<NSString *, id> *expected = permission[@"expected"];
    NSDictionary<NSString *, id> *identity = permission[@"runtimeIdentity"];
    NSDictionary<NSString *, id> *write = permission[@"write"];
    NSDictionary<NSString *, id> *readback = permission[@"readback"];
    NSDictionary<NSString *, id> *post = permission[@"postWriteTranslation"];
    BOOL sectionsValid =
        [expected isKindOfClass:NSDictionary.class] &&
        [identity isKindOfClass:NSDictionary.class] &&
        [write isKindOfClass:NSDictionary.class] &&
        [readback isKindOfClass:NSDictionary.class] &&
        [post isKindOfClass:NSDictionary.class];
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    NSTimeInterval bootEpoch = now - NSProcessInfo.processInfo.systemUptime;
    NSTimeInterval started = [permission[@"startedAtUnixTime"] doubleValue];
    if (![permission isKindOfClass:NSDictionary.class] ||
        !sectionsValid ||
        [permission[@"schemaVersion"] unsignedIntegerValue] != 1 ||
        ![permission[@"experiment"]
            isEqual:@"hail-mary-read-only-data-page-aperture-writability"] ||
        ![permission[@"productType"] isEqual:@CND_HAIL_MARY_IMP_PRODUCT] ||
        ![permission[@"productBuildVersion"]
            isEqual:@CND_HAIL_MARY_IMP_BUILD] ||
        ![permission[@"confirmed"] boolValue] ||
        ![permission[@"result"]
            isEqual:@"aperture-read-only-data-page-write-confirmed"] ||
        [permission[@"kernelWritePrimitiveInvocationCount"]
            unsignedIntegerValue] != 1 ||
        [permission[@"semanticMutationCount"] unsignedIntegerValue] != 0 ||
        [permission[@"fallbackAttempted"] boolValue] ||
        ![write[@"bytesIdenticalByConstruction"] boolValue] ||
        ![write[@"dispatchReturned"] boolValue] ||
        ![readback[@"identicalToBefore"] boolValue] ||
        ![readback[@"exactOfflineGuard"] boolValue] ||
        ![post[@"stable"] boolValue] ||
        ![identity[@"runtimeVerified"] boolValue] ||
        ![expected[@"unslidEntryVirtualAddress"]
            isEqual:CNDHailMaryImpHex(kCNDHailMaryImpEntryUnslid)] ||
        ![[expected[@"originalGuardSHA256"] lowercaseString]
            isEqual:@CND_HAIL_MARY_IMP_ORIGINAL_GUARD_SHA256] ||
        started < bootEpoch - 5.0 || started > now + 5.0) {
        if (errorOut) {
            *errorOut = data.length == 0
                ? @"same-boot-read-only-data-permission-probe-required"
                : (jsonError
                    ? @"read-only-data-permission-report-invalid-json"
                    : @"same-boot-read-only-data-permission-proof-invalid");
        }
        return nil;
    }
    return @{
        @"reportPath": path,
        @"startedAtUnixTime": @(started),
        @"bootEpochUnixTime": @(bootEpoch),
        @"result": permission[@"result"],
        @"sharedCacheSlide": identity[@"sharedCacheSlide"] ?: @"",
        @"physicalFrame": identity[@"physicalFrame"] ?: @"",
        @"physicalAddress": identity[@"physicalAddress"] ?: @"",
        @"windowKernelVirtualAddress":
            identity[@"windowKernelVirtualAddress"] ?: @"",
        @"guardSHA256": readback[@"sha256"] ?: @"",
        @"sameBoot": @YES,
    };
}

static BOOL CNDHailMaryImpPermissionMatchesContext(
    NSDictionary<NSString *, id> *permission,
    NSDictionary<NSString *, id> *context)
{
    return [permission[@"sharedCacheSlide"]
                isEqual:context[@"sharedCacheSlide"]] &&
        [permission[@"physicalFrame"] isEqual:context[@"physicalFrame"]] &&
        [permission[@"physicalAddress"]
            isEqual:context[@"physicalAddress"]] &&
        [permission[@"windowKernelVirtualAddress"]
            isEqual:context[@"windowKernelVirtualAddress"]] &&
        [[permission[@"guardSHA256"] lowercaseString]
            isEqual:@CND_HAIL_MARY_IMP_ORIGINAL_GUARD_SHA256];
}

BOOL CNDHailMaryImpRedirectIsSupported(NSString **reasonOut)
{
    return CNDHailMaryProbeIsSupported(reasonOut);
}

BOOL CNDHailMaryImpRedirectIsRunning(void)
{
    return __sync_fetch_and_add(&gCNDHailMaryImpRedirectRunning, 0) != 0;
}

void CNDHailMaryImpRedirectRun(
    CNDHailMaryImpRedirectOperation operation,
    CNDHailMaryImpRedirectCompletion completion)
{
    if (!completion) return;
    if (!__sync_bool_compare_and_swap(
            &gCNDHailMaryImpRedirectRunning, 0, 1)) {
        completion(@{
            @"confirmed": @NO,
            @"result": @"refused-already-running",
            @"message": @"The Hail Mary dispatch redirect is already running.",
        });
        return;
    }

    NSString *reportPath = CNDHailMaryImpReportPath();
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schemaVersion": @1,
        @"experiment": @"hail-mary-preoptimized-dispatch-cache-redirect",
        @"operation": CNDHailMaryImpOperationName(operation),
        @"productType": @CND_HAIL_MARY_IMP_PRODUCT,
        @"productBuildVersion": @CND_HAIL_MARY_IMP_BUILD,
        @"reportPath": reportPath,
        @"startedAtUnixTime": @([[NSDate date] timeIntervalSince1970]),
        @"confirmed": @NO,
        @"mutationConfirmed": @NO,
        @"automaticSpotlightRestartAttempted": @NO,
        @"postwriteProcessLifecycleMutationCount": @0,
        @"kernelWritePrimitiveInvocationCount": @0,
        @"kernelWritePrimitiveInvocationCountPlanned": @(
            CNDHailMaryImpIsMutation(operation) ? 1 : 0),
        @"dispatchEntrySemanticMutationCount": @0,
        @"targetProcessDirectMutationCount": @0,
        @"fallbackAttempted": @NO,
        @"expected": @{
            @"class": @"SBIconImageView",
            @"selector": @"effectivelyPrefersFlatImageLayers",
            @"unslidEntryVirtualAddress": CNDHailMaryImpHex(
                kCNDHailMaryImpEntryUnslid),
            @"originalEntryValue": CNDHailMaryImpHex(
                kCNDHailMaryImpOriginalEntry),
            @"redirectedEntryValue": CNDHailMaryImpHex(
                kCNDHailMaryImpRedirectedEntry),
            @"originalLowWord": CNDHailMaryImpHex(
                kCNDHailMaryImpOriginalWord),
            @"redirectedLowWord": CNDHailMaryImpHex(
                kCNDHailMaryImpRedirectedWord),
            @"originalGuardBytesHex": @CND_HAIL_MARY_IMP_ORIGINAL_GUARD_HEX,
            @"redirectedGuardBytesHex": @CND_HAIL_MARY_IMP_REDIRECTED_GUARD_HEX,
            @"originalGuardSHA256": @CND_HAIL_MARY_IMP_ORIGINAL_GUARD_SHA256,
            @"redirectedGuardSHA256": @CND_HAIL_MARY_IMP_REDIRECTED_GUARD_SHA256,
            @"guardByteLength": @(kCNDHailMaryImpGuardLength),
            @"transportWindowBytes": @(EARLY_KRW_LENGTH),
            @"encoding": @"preopt_cache_entry_t packed 26-bit selector offset + signed 38-bit class-relative IMP; no pointer or PAC bits",
        },
    } mutableCopy];

    if (operation > CNDHailMaryImpRedirectOperationVerifyOriginal) {
        report[@"result"] = @"refused-invalid-operation";
        report[@"message"] = @"The requested dispatch redirect operation is invalid.";
        CNDHailMaryImpFinish(report, completion);
        return;
    }

    NSString *supportReason = nil;
    if (!CNDHailMaryImpRedirectIsSupported(&supportReason)) {
        report[@"result"] = @"refused-unsupported-device";
        report[@"message"] = supportReason ?: @"Unsupported device.";
        CNDHailMaryImpFinish(report, completion);
        return;
    }
    if (CNDHailMaryProbeIsRunning() || CNDHailMaryPatchIsRunning() ||
        CNDHailMaryDataPageIsRunning() ||
        CNDHailMaryReadOnlyDataPageIsRunning()) {
        report[@"result"] = @"refused-conflicting-hail-mary-experiment";
        report[@"message"] = @"Another Hail Mary proof or mutation experiment is already running.";
        CNDHailMaryImpFinish(report, completion);
        return;
    }
    if (!kexploit_krw_ready()) {
        report[@"result"] = @"refused-krw-unavailable";
        report[@"message"] = @"Validated KRW is required.";
        CNDHailMaryImpFinish(report, completion);
        return;
    }

    NSDictionary<NSString *, id> *permissionEvidence = nil;
    if (CNDHailMaryImpIsMutation(operation)) {
        NSString *permissionError = nil;
        permissionEvidence = CNDHailMaryImpLoadPermissionEvidence(
            &permissionError);
        if (!permissionEvidence) {
            report[@"result"] = @"refused-permission-proof-required";
            report[@"message"] = permissionError ?:
                @"Run the .34 identical-bytes permission probe on this boot first.";
            CNDHailMaryImpFinish(report, completion);
            return;
        }
        report[@"permissionEvidence"] = permissionEvidence;
    }

    BOOL expectRedirectedBefore =
        CNDHailMaryImpExpectedRedirectedBefore(operation);
    CNDHailMaryProbeRun(^(NSDictionary<NSString *, id> *preflightProbe) {
        dispatch_async(dispatch_get_global_queue(
            QOS_CLASS_USER_INITIATED, 0), ^{
            report[@"preflightProbe"] = preflightProbe ?: @{};
            NSDictionary<NSString *, id> *beforeContext = nil;
            NSData *beforeGuard = nil;
            NSString *resolveError = nil;
            if (!CNDHailMaryReadOnlyDataPageResolveDispatchEntry(
                    preflightProbe, expectRedirectedBefore,
                    &beforeContext, &beforeGuard, &resolveError)) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = resolveError ?:
                    @"The exact dispatch-entry guard was not proven.";
                CNDHailMaryImpFinish(report, completion);
                return;
            }
            report[@"preflight"] = beforeContext;

            if (CNDHailMaryImpIsMutation(operation) &&
                !CNDHailMaryImpPermissionMatchesContext(
                    permissionEvidence, beforeContext)) {
                report[@"result"] = @"refused-permission-proof-identity-mismatch";
                report[@"message"] = @"The same-boot .34 permission proof did not identify the fresh preflight's exact slide, frame, physical address, and aperture KVA.";
                CNDHailMaryImpFinish(report, completion);
                return;
            }

            if (!CNDHailMaryImpIsMutation(operation)) {
                report[@"confirmed"] = @YES;
                report[@"result"] = expectRedirectedBefore
                    ? @"dispatch-entry-redirect-confirmed"
                    : @"dispatch-entry-original-confirmed";
                report[@"message"] = expectRedirectedBefore
                    ? @"The exact redirected dispatch entry and 32-byte guard are present through one stable shared physical frame."
                    : @"The exact original dispatch entry and 32-byte guard are present through one stable shared physical frame.";
                CNDHailMaryImpFinish(report, completion);
                return;
            }

            BOOL apply = operation == CNDHailMaryImpRedirectOperationApply;
            BOOL desiredRedirected = apply;
            uint32_t desiredWord = desiredRedirected
                ? kCNDHailMaryImpRedirectedWord
                : kCNDHailMaryImpOriginalWord;
            uint64_t desiredEntry = desiredRedirected
                ? kCNDHailMaryImpRedirectedEntry
                : kCNDHailMaryImpOriginalEntry;
            NSString *desiredHex = desiredRedirected
                ? @CND_HAIL_MARY_IMP_REDIRECTED_GUARD_HEX
                : @CND_HAIL_MARY_IMP_ORIGINAL_GUARD_HEX;
            NSString *desiredSHA = desiredRedirected
                ? @CND_HAIL_MARY_IMP_REDIRECTED_GUARD_SHA256
                : @CND_HAIL_MARY_IMP_ORIGINAL_GUARD_SHA256;
            NSData *desiredGuard = CNDHailMaryImpDataFromHex(desiredHex);
            uint64_t compiledDesiredEntry = 0;
            uint64_t windowKVA = 0;
            if (beforeGuard.length != kCNDHailMaryImpGuardLength ||
                desiredGuard.length != kCNDHailMaryImpGuardLength ||
                ![[CNDHailMaryImpSHA256(desiredGuard) lowercaseString]
                    isEqual:desiredSHA] ||
                !CNDHailMaryImpParseHex(
                    beforeContext[@"windowKernelVirtualAddress"],
                    &windowKVA) ||
                !is_kaddr_valid(windowKVA) || (windowKVA & 7U) != 0) {
                report[@"result"] = @"prewrite-self-check-failed";
                report[@"message"] = @"The desired guard or proven aperture target failed its final compiled identity check.";
                CNDHailMaryImpFinish(report, completion);
                return;
            }
            memcpy(&compiledDesiredEntry, desiredGuard.bytes,
                   sizeof(compiledDesiredEntry));
            if (compiledDesiredEntry != desiredEntry) {
                report[@"result"] = @"prewrite-self-check-failed";
                report[@"message"] = @"The desired packed entry did not match the compiled guard.";
                CNDHailMaryImpFinish(report, completion);
                return;
            }

            uint8_t finalBeforeBytes[EARLY_KRW_LENGTH] = {0};
            kreadbuf(windowKVA, finalBeforeBytes,
                     sizeof(finalBeforeBytes));
            NSData *finalBefore = [NSData dataWithBytes:finalBeforeBytes
                                                  length:sizeof(finalBeforeBytes)];
            if (![finalBefore isEqualToData:beforeGuard]) {
                report[@"result"] = @"final-prewrite-guard-changed";
                report[@"message"] = @"The exact dispatch guard changed after preflight. No write was attempted.";
                CNDHailMaryImpFinish(report, completion);
                return;
            }

            report[@"stage"] = apply
                ? @"armed-dispatch-cache-redirect"
                : @"armed-dispatch-cache-restore";
            report[@"recovery"] = @{
                @"automaticRollbackEnabled": @NO,
                @"panicRecoveryMechanismInstalled": @NO,
                @"separateRestoreRequired": @YES,
                @"beforeGuardBytesHex": CNDHailMaryImpBytesHex(
                    finalBeforeBytes, sizeof(finalBeforeBytes)),
                @"beforeGuardSHA256": CNDHailMaryImpSHA256(finalBefore),
                @"desiredGuardBytesHex": desiredHex,
                @"desiredGuardSHA256": desiredSHA,
                @"inverseLowWord": CNDHailMaryImpHex(
                    apply ? kCNDHailMaryImpOriginalWord
                          : kCNDHailMaryImpRedirectedWord),
                @"inverseEntryValue": CNDHailMaryImpHex(
                    apply ? kCNDHailMaryImpOriginalEntry
                          : kCNDHailMaryImpRedirectedEntry),
                @"reason": @"The exact inverse is a separately guarded one-write operation; no second write is attempted automatically.",
            };
            report[@"write"] = @{
                @"route": @"kwrite32-packed-dispatch-low-word",
                @"windowKernelVirtualAddress": CNDHailMaryImpHex(windowKVA),
                @"logicalByteCount": @4,
                @"transportByteCount": @(EARLY_KRW_LENGTH),
                @"beforeEntryValue": CNDHailMaryImpHex(
                    expectRedirectedBefore
                        ? kCNDHailMaryImpRedirectedEntry
                        : kCNDHailMaryImpOriginalEntry),
                @"desiredEntryValue": CNDHailMaryImpHex(desiredEntry),
                @"desiredLowWord": CNDHailMaryImpHex(desiredWord),
                @"neighborBytesPreserved": @YES,
                @"dispatchReturned": @NO,
            };
            NSString *journalError = nil;
            if (!CNDHailMaryImpSaveDurably(
                    report, reportPath, &journalError)) {
                report[@"result"] = @"prewrite-journal-sync-failed";
                report[@"message"] = journalError ?:
                    @"The exact inverse journal could not be made durable.";
                CNDHailMaryImpFinish(report, completion);
                return;
            }

            report[@"kernelWritePrimitiveInvocationCount"] = @1;
            report[@"dispatchEntrySemanticMutationCount"] = @1;
            kwrite32(windowKVA, desiredWord);

            uint8_t afterBytes[EARLY_KRW_LENGTH] = {0};
            kreadbuf(windowKVA, afterBytes, sizeof(afterBytes));
            NSData *afterData = [NSData dataWithBytes:afterBytes
                                                length:sizeof(afterBytes)];
            BOOL exactReadback = [afterData isEqualToData:desiredGuard] &&
                [[CNDHailMaryImpSHA256(afterData) lowercaseString]
                    isEqual:desiredSHA];
            report[@"write"] = @{
                @"route": @"kwrite32-packed-dispatch-low-word",
                @"windowKernelVirtualAddress": CNDHailMaryImpHex(windowKVA),
                @"logicalByteCount": @4,
                @"transportByteCount": @(EARLY_KRW_LENGTH),
                @"beforeEntryValue": CNDHailMaryImpHex(
                    expectRedirectedBefore
                        ? kCNDHailMaryImpRedirectedEntry
                        : kCNDHailMaryImpOriginalEntry),
                @"desiredEntryValue": CNDHailMaryImpHex(desiredEntry),
                @"desiredLowWord": CNDHailMaryImpHex(desiredWord),
                @"neighborBytesPreserved": @YES,
                @"dispatchReturned": @YES,
            };
            report[@"physicalReadbackPerformed"] = @YES;
            report[@"readback"] = @{
                @"bytesHex": CNDHailMaryImpBytesHex(
                    afterBytes, sizeof(afterBytes)),
                @"sha256": CNDHailMaryImpSHA256(afterData),
                @"exactDesiredGuard": @(exactReadback),
            };
            if (!exactReadback) {
                report[@"result"] = @"postwrite-guard-mismatch";
                report[@"message"] = @"The single write returned, but the exact desired 32-byte guard did not read back. No rollback or Spotlight restart was attempted.";
                CNDHailMaryImpFinish(report, completion);
                return;
            }

            NSDictionary<NSString *, id> *postWriteContext = nil;
            NSData *postWriteGuard = nil;
            NSString *postWriteError = nil;
            BOOL postWriteTranslation =
                CNDHailMaryReadOnlyDataPageResolveDispatchEntry(
                    preflightProbe, desiredRedirected,
                    &postWriteContext, &postWriteGuard, &postWriteError) &&
                [postWriteContext[@"physicalFrame"]
                    isEqual:beforeContext[@"physicalFrame"]] &&
                [postWriteContext[@"physicalAddress"]
                    isEqual:beforeContext[@"physicalAddress"]] &&
                [postWriteContext[@"windowKernelVirtualAddress"]
                    isEqual:beforeContext[@"windowKernelVirtualAddress"]];
            report[@"postWriteTranslation"] = postWriteTranslation
                ? @{
                    @"performed": @YES,
                    @"stable": @YES,
                    @"context": postWriteContext,
                }
                : @{
                    @"performed": @YES,
                    @"stable": @NO,
                    @"error": postWriteError ?:
                        @"postwrite-dispatch-translation-changed",
                };
            if (!postWriteTranslation) {
                report[@"result"] = @"postwrite-translation-unconfirmed";
                report[@"message"] = @"The desired guard read back exactly, but the original two-process translation proof did not remain stable. No Spotlight restart was attempted.";
                CNDHailMaryImpFinish(report, completion);
                return;
            }

            report[@"mutationConfirmed"] = @YES;
            report[@"confirmed"] = @YES;
            report[@"stage"] =
                @"mutation-confirmed-awaiting-manual-visual-check";
            report[@"behavioralCheck"] = @{
                @"automaticSpotlightRestartAttempted": @NO,
                @"automaticSpotlightPresentationAttemptedPostwrite": @NO,
                @"secondProcessProofAttempted": @NO,
                @"springBoardRestarted": @NO,
                @"visualBehaviorRequiresOperatorObservation": @YES,
                @"operatorObservationRecorded": @NO,
                @"reason": @"Postwrite process lifecycle automation is intentionally disabled. Judge the already-live UI manually.",
            };
            report[@"result"] = apply
                ? @"dispatch-entry-redirect-applied-manual-visual-check-required"
                : @"dispatch-entry-original-restored-manual-visual-check-required";
            report[@"message"] = apply
                ? @"The packed dispatch entry was redirected with one write, read back exactly, and retained its stable two-process translation. No process was restarted or reopened. Inspect the live UI manually."
                : @"The original packed dispatch entry was restored with one write, read back exactly, and retained its stable two-process translation. No process was restarted or reopened. Inspect the live UI manually.";
            journalError = nil;
            if (!CNDHailMaryImpSaveDurably(
                    report, reportPath, &journalError)) {
                report[@"result"] = @"postwrite-journal-sync-failed";
                report[@"message"] = journalError ?:
                    @"The mutation is confirmed, but the postwrite recovery journal could not be synced. No process was restarted.";
                CNDHailMaryImpFinish(report, completion);
                return;
            }
            CNDHailMaryImpFinish(report, completion);
        });
    });
}
