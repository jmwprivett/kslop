//
//  CNDHailMaryPageWire.m
//  Cyanide
//
//  SpringBoard mlock feasibility probe for the exact .34 read-only-data page
//  that carries SBIconImageView's preoptimized dispatch entry.
//
//  Evidence discipline: this probe never invokes a kernel write primitive and
//  never mutates the page. It only asks SpringBoard to mlock one already
//  proven shared-cache frame, and it records two self-owned control mlocks so
//  a refusal can be attributed to the page class instead of the caller.
//

#import "CNDHailMaryPageWire.h"

#import "CNDHailMaryDataPage.h"
#import "CNDHailMaryImpRedirect.h"
#import "CNDHailMaryPatch.h"
#import "CNDHailMaryProbe.h"
#import "CNDHailMaryReadOnlyDataPage.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/krw.h"

#import <CommonCrypto/CommonDigest.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define CND_HAIL_MARY_PAGE_WIRE_BUILD "23A341"
#define CND_HAIL_MARY_PAGE_WIRE_PRODUCT "iPhone17,2"
#define CND_HAIL_MARY_PAGE_WIRE_SUBCACHE_UUID \
    "CEEB0D68-9BA9-3CC8-AEB1-8F23BAC92B58"

/* The exact .34 dispatch entry, pinned offline. Only the derived runtime
 * identity is used for translation; these values are invariants, never a
 * runtime address. */
static const uint64_t kCNDHailMaryPageWirePageSize = UINT64_C(0x4000);
static const uint64_t kCNDHailMaryPageWireEntryUnslid =
    UINT64_C(0x1ffc27458);
static const uint64_t kCNDHailMaryPageWireEntryOffsetWithinFrame =
    UINT64_C(0x3458);
/* An enum keeps the guard length a compile-time array bound as well as the
 * value recorded in the report. */
enum { kCNDHailMaryPageWireGuardLength = 0x20 };

static volatile int gCNDHailMaryPageWireRunning;

static NSString *CNDHailMaryPageWireHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static BOOL CNDHailMaryPageWireParseHex(NSString *text, uint64_t *valueOut)
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

static NSString *CNDHailMaryPageWireBytesHex(const void *bytes, size_t length)
{
    if (!bytes || length == 0) return @"";
    const uint8_t *cursor = bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    for (size_t index = 0; index < length; index++) {
        [hex appendFormat:@"%02x", cursor[index]];
    }
    return hex;
}

static NSString *CNDHailMaryPageWireSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class] || data.length == 0 ||
        data.length > UINT32_MAX) {
        return @"";
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    return CNDHailMaryPageWireBytesHex(digest, sizeof(digest));
}

static NSString *CNDHailMaryPageWireReportPath(void)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    return [directory stringByAppendingPathComponent:
        @"CNDHailMaryPageWire.json"];
}

static void CNDHailMaryPageWireSave(
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

static BOOL CNDHailMaryPageWireSyncFileDescriptor(int descriptor)
{
    if (descriptor < 0) return NO;
#ifdef F_FULLFSYNC
    if (fcntl(descriptor, F_FULLFSYNC) == 0) return YES;
#endif
    return fsync(descriptor) == 0;
}

/* Durable pre-arm checkpoint: file contents, then the containing directory,
 * so a device that does not come back still leaves the exact armed identity. */
static BOOL CNDHailMaryPageWireSaveDurably(
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
    BOOL fileSynced = CNDHailMaryPageWireSyncFileDescriptor(fileDescriptor);
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

static void CNDHailMaryPageWireFinish(
    NSMutableDictionary<NSString *, id> *report,
    CNDHailMaryPageWireCompletion completion)
{
    NSString *path = report[@"reportPath"];
    CNDHailMaryPageWireSave(report, path);
    NSDictionary<NSString *, id> *finished = [report copy];
    __sync_lock_release(&gCNDHailMaryPageWireRunning);
    dispatch_async(dispatch_get_main_queue(), ^{
        completion(finished);
    });
}

/* Classify a refusal from the two control beats. The controls are the reason
 * this probe is worth running again: without them a repeat EPERM cannot be
 * told apart from "mlock is unavailable to SpringBoard here at all". */
static NSString *CNDHailMaryPageWireInterpretation(
    NSDictionary<NSString *, id> *wireReport,
    BOOL wireLanded,
    BOOL postStable)
{
    if (wireLanded) {
        return postStable
            ? @"springboard-wire-accepted"
            : @"wire-landed-but-identity-unstable";
    }
    /* Anything other than a refused target call never reached the control
     * beats, so it says nothing about the page class. */
    NSString *stage = [wireReport[@"stage"] isKindOfClass:NSString.class]
        ? wireReport[@"stage"] : @"";
    if (![stage isEqual:@"springboard-page-wire-failed"]) {
        return [stage isEqual:@"springboard-page-wired"]
            ? @"wire-landed-but-identity-unstable"
            : @"wire-preflight-refused";
    }
    NSDictionary<NSString *, id> *controls =
        [wireReport[@"diagnosticControls"] isKindOfClass:NSDictionary.class]
            ? wireReport[@"diagnosticControls"] : @{};
    NSDictionary<NSString *, id> *readWrite =
        [controls[@"anonymousReadWrite"] isKindOfClass:NSDictionary.class]
            ? controls[@"anonymousReadWrite"] : @{};
    NSDictionary<NSString *, id> *readOnly =
        [controls[@"anonymousReadOnly"] isKindOfClass:NSDictionary.class]
            ? controls[@"anonymousReadOnly"] : @{};
    BOOL readWriteWired = [readWrite[@"mlockWired"] boolValue];
    BOOL readOnlyWired = [readOnly[@"mlockWired"] boolValue];
    if (![readWrite[@"mlockCallHealthy"] boolValue]) {
        BOOL mapUsable = [readWrite[@"mapCallHealthy"] boolValue] &&
            [readWrite[@"mapAligned"] boolValue];
        return mapUsable
            ? @"mlock-unavailable-in-springboard"
            : @"mlock-control-mapping-failed";
    }
    if (!readWriteWired) return @"anonymous-writable-page-refused";
    if (!readOnlyWired) return @"read-only-mapping-cannot-be-mlocked";
    return @"shared-cache-page-refused-despite-writable-controls";
}

/* Human-readable outcome of one control beat, used only for the log-facing
 * message; the full beat dictionaries stay in the JSON report. */
static NSString *CNDHailMaryPageWireControlText(
    NSDictionary<NSString *, id> *wireReport,
    NSString *key)
{
    NSDictionary<NSString *, id> *controls =
        [wireReport[@"diagnosticControls"] isKindOfClass:NSDictionary.class]
            ? wireReport[@"diagnosticControls"] : nil;
    NSDictionary<NSString *, id> *control =
        [controls[key] isKindOfClass:NSDictionary.class]
            ? controls[key] : nil;
    if (!control) return @"not-run";
    return [control[@"mlockWired"] boolValue] ? @"wired" : @"refused";
}

void CNDHailMaryPageWireRun(
    CNDHailMaryPageWireCompletion completion)
{
    if (!completion) return;
    if (!__sync_bool_compare_and_swap(&gCNDHailMaryPageWireRunning, 0, 1)) {
        completion(@{
            @"confirmed": @NO,
            @"result": @"refused-already-running",
            @"message": @"The Hail Mary .34 page wire probe is already running.",
        });
        return;
    }

    NSString *reportPath = CNDHailMaryPageWireReportPath();
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schemaVersion": @1,
        @"experiment": @"hail-mary-read-only-data-page-wire-probe",
        @"mode": @"springboard-mlock-no-mutation",
        @"productType": @CND_HAIL_MARY_PAGE_WIRE_PRODUCT,
        @"productBuildVersion": @CND_HAIL_MARY_PAGE_WIRE_BUILD,
        @"reportPath": reportPath,
        @"startedAtUnixTime": @([[NSDate date] timeIntervalSince1970]),
        @"confirmed": @NO,
        @"kernelWritePrimitiveInvocationCount": @0,
        @"semanticMutationCount": @0,
        @"targetProcessDirectMutationCount": @0,
        @"fallbackAttempted": @NO,
        @"expected": @{
            @"subcacheFileName":
                @"dyld_shared_cache_arm64e.34.dyldreadonly",
            @"subcacheUUID": @CND_HAIL_MARY_PAGE_WIRE_SUBCACHE_UUID,
            @"unslidEntryVirtualAddress": CNDHailMaryPageWireHex(
                kCNDHailMaryPageWireEntryUnslid),
            @"entryOffsetWithinFrame": CNDHailMaryPageWireHex(
                kCNDHailMaryPageWireEntryOffsetWithinFrame),
            @"pageSize": @(kCNDHailMaryPageWirePageSize),
            @"guardByteLength": @(kCNDHailMaryPageWireGuardLength),
            @"mappingInitProtection": @1,
            @"mappingMaximumProtection": @1,
            @"wireRange": @"one-16KiB-shared-cache-frame",
            @"controls": @[
                @"anonymous-read-write-16KiB-mlock",
                @"anonymous-read-only-16KiB-mlock",
            ],
        },
    } mutableCopy];

    NSString *supportReason = nil;
    if (!CNDHailMaryPageWireIsSupported(&supportReason)) {
        report[@"result"] = @"refused-unsupported-device";
        report[@"message"] = supportReason ?: @"Unsupported device.";
        CNDHailMaryPageWireFinish(report, completion);
        return;
    }
    if (CNDHailMaryProbeIsRunning() || CNDHailMaryPatchIsRunning() ||
        CNDHailMaryDataPageIsRunning() ||
        CNDHailMaryReadOnlyDataPageIsRunning() ||
        CNDHailMaryImpRedirectIsRunning()) {
        report[@"result"] = @"refused-conflicting-hail-mary-experiment";
        report[@"message"] = @"Another Hail Mary proof or mutation experiment is already running.";
        CNDHailMaryPageWireFinish(report, completion);
        return;
    }
    if (!kexploit_krw_ready()) {
        report[@"result"] = @"refused-krw-unavailable";
        report[@"message"] = @"Validated KRW is required to prove the .34 page identity before the wire probe.";
        CNDHailMaryPageWireFinish(report, completion);
        return;
    }

    CNDHailMaryProbeRunWithMode(
        CNDHailMaryProofModeSpringBoardOnly,
        ^(NSDictionary<NSString *, id> *probeReport) {
        dispatch_async(dispatch_get_global_queue(
            QOS_CLASS_USER_INITIATED, 0), ^{
            report[@"preflightProbe"] = probeReport ?: @{};

            /* Reuse the already-proven .34 resolver rather than restating its
             * slide scan. The helper validates the confirmed live text proof,
             * every live slide anchor, the pmap walk, the exact 32-byte guard
             * and a final re-read; it never writes. The wire targets
             * SpringBoard's mapping, so no second process is consulted. */
            report[@"stage"] = @"resolving-read-only-data-page";
            NSDictionary<NSString *, id> *context = nil;
            NSData *guardData = nil;
            NSDictionary<NSString *, id> *originalDiagnostics = nil;
            NSDictionary<NSString *, id> *redirectedDiagnostics = nil;
            NSString *originalError = nil;
            NSString *pageState = @"original";
            BOOL resolved =
                CNDHailMaryReadOnlyDataPageResolveDispatchEntryWithMode(
                    CNDHailMaryProofModeSpringBoardOnly, probeReport, NO,
                    &context, &guardData,
                    &originalDiagnostics, &originalError);
            NSString *redirectedError = nil;
            if (!resolved) {
                NSDictionary<NSString *, id> *redirectedContext = nil;
                NSData *redirectedGuard = nil;
                resolved =
                    CNDHailMaryReadOnlyDataPageResolveDispatchEntryWithMode(
                        CNDHailMaryProofModeSpringBoardOnly, probeReport, YES,
                        &redirectedContext, &redirectedGuard,
                        &redirectedDiagnostics, &redirectedError);
                if (resolved) {
                    context = redirectedContext;
                    guardData = redirectedGuard;
                    pageState = @"redirected";
                }
            }
            if (!resolved || !context || guardData.length !=
                    kCNDHailMaryPageWireGuardLength) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = [NSString stringWithFormat:
                    @"The exact .34 dispatch-entry identity could not be proven "
                    @"(original: %@; redirected: %@). No wire was attempted.",
                    originalError ?: @"resolved",
                    redirectedError ?: @"not-tried"];
                report[@"resolveErrors"] = @{
                    @"original": originalError ?: @"none",
                    @"redirected": redirectedError ?: @"not-tried",
                };
                report[@"resolveDiagnostics"] = @{
                    @"original": originalDiagnostics ?: @{},
                    @"redirected": redirectedDiagnostics ?: @{},
                };
                CNDHailMaryPageWireFinish(report, completion);
                return;
            }
            report[@"pageState"] = pageState;
            report[@"resolvedPage"] = context;

            uint64_t frame = 0;
            uint64_t physicalAddress = 0;
            uint64_t frameKVA = 0;
            uint64_t windowKVA = 0;
            uint64_t runtimeAddress = 0;
            uint64_t offsetWithinFrame = 0;
            uint64_t sharedCacheSlide = 0;
            uint64_t guardedTextPhysicalFrame = 0;
            BOOL parsed =
                CNDHailMaryPageWireParseHex(
                    context[@"physicalFrame"], &frame) &&
                CNDHailMaryPageWireParseHex(
                    context[@"physicalAddress"], &physicalAddress) &&
                CNDHailMaryPageWireParseHex(
                    context[@"frameKernelVirtualAddress"], &frameKVA) &&
                CNDHailMaryPageWireParseHex(
                    context[@"windowKernelVirtualAddress"], &windowKVA) &&
                CNDHailMaryPageWireParseHex(
                    context[@"runtimeEntryVirtualAddress"],
                    &runtimeAddress) &&
                CNDHailMaryPageWireParseHex(
                    context[@"offsetWithinFrame"], &offsetWithinFrame) &&
                CNDHailMaryPageWireParseHex(
                    context[@"sharedCacheSlide"], &sharedCacheSlide) &&
                CNDHailMaryPageWireParseHex(
                    context[@"guardedTextPhysicalFrame"],
                    &guardedTextPhysicalFrame);
            uint64_t pageBase = parsed
                ? (runtimeAddress & ~(kCNDHailMaryPageWirePageSize - 1))
                : 0;
            BOOL identityInvariantsHold = parsed &&
                frame != 0 && pageBase != 0 &&
                is_kaddr_valid(frameKVA) && is_kaddr_valid(windowKVA) &&
                physicalAddress >= frame &&
                physicalAddress - frame == offsetWithinFrame &&
                offsetWithinFrame ==
                    kCNDHailMaryPageWireEntryOffsetWithinFrame &&
                frame != guardedTextPhysicalFrame &&
                frameKVA + offsetWithinFrame == windowKVA &&
                pageBase + offsetWithinFrame == runtimeAddress &&
                runtimeAddress >= sharedCacheSlide &&
                runtimeAddress - sharedCacheSlide ==
                    kCNDHailMaryPageWireEntryUnslid &&
                (frameKVA & (kCNDHailMaryPageWirePageSize - 1)) == 0 &&
                (frame & (kCNDHailMaryPageWirePageSize - 1)) == 0;
            if (!identityInvariantsHold) {
                report[@"result"] = @"preflight-identity-invariant-failed";
                report[@"message"] = @"The resolved .34 identity broke a pinned invariant (frame, offset, aperture mapping, or slide identity). No wire was attempted.";
                CNDHailMaryPageWireFinish(report, completion);
                return;
            }

            /* One last guard read against the same aperture window the write
             * probes use, immediately before arming. */
            uint8_t beforeBytes[kCNDHailMaryPageWireGuardLength] = {0};
            kreadbuf(windowKVA, beforeBytes, sizeof(beforeBytes));
            NSData *beforeData = [NSData dataWithBytes:beforeBytes
                                                length:sizeof(beforeBytes)];
            BOOL guardStillResolved = [beforeData isEqualToData:guardData];
            report[@"finalGuard"] = @{
                @"bytesHex": CNDHailMaryPageWireBytesHex(
                    beforeBytes, sizeof(beforeBytes)),
                @"sha256": CNDHailMaryPageWireSHA256(beforeData),
                @"resolvedSHA256": context[@"guardSHA256"] ?: @"",
                @"matchesResolvedState": @(guardStillResolved),
            };
            if (!guardStillResolved) {
                report[@"result"] = @"final-prewire-guard-changed";
                report[@"message"] = @"The .34 guard changed after the identity proof. No wire was attempted.";
                CNDHailMaryPageWireFinish(report, completion);
                return;
            }

            report[@"runtimeIdentity"] = @{
                @"runtimeVerified": @YES,
                @"pageState": pageState,
                @"sharedCacheSlide":
                    CNDHailMaryPageWireHex(sharedCacheSlide),
                @"runtimeEntryVirtualAddress":
                    CNDHailMaryPageWireHex(runtimeAddress),
                @"unslidInvariant": CNDHailMaryPageWireHex(
                    runtimeAddress - sharedCacheSlide),
                @"wiredPageBase": CNDHailMaryPageWireHex(pageBase),
                @"wiredByteLength": @(kCNDHailMaryPageWirePageSize),
                @"physicalFrame": CNDHailMaryPageWireHex(frame),
                @"physicalAddress":
                    CNDHailMaryPageWireHex(physicalAddress),
                @"frameKernelVirtualAddress":
                    CNDHailMaryPageWireHex(frameKVA),
                @"windowKernelVirtualAddress":
                    CNDHailMaryPageWireHex(windowKVA),
                @"offsetWithinFrame":
                    CNDHailMaryPageWireHex(offsetWithinFrame),
                @"guardedTextPhysicalFrame": CNDHailMaryPageWireHex(
                    guardedTextPhysicalFrame),
                @"differsFromGuardedTextPhysicalFrame": @(
                    frame != guardedTextPhysicalFrame),
                @"springBoardPID": context[@"springBoardPID"] ?: @0,
                @"translationMode": @"springboard-only",
            };

            NSDictionary<NSString *, id> *springBoard =
                [context[@"springBoard"] isKindOfClass:NSDictionary.class]
                    ? context[@"springBoard"] : nil;
            if (!springBoard ||
                ![springBoard[@"path"] isKindOfClass:NSArray.class] ||
                [springBoard[@"path"] count] != 3) {
                report[@"result"] = @"preflight-translation-path-invalid";
                report[@"message"] = @"The proven SpringBoard translation path was not a complete three-level walk. No wire was attempted.";
                CNDHailMaryPageWireFinish(report, completion);
                return;
            }

            NSDictionary<NSString *, id> *wireContext = @{
                @"targetVirtualAddress":
                    context[@"runtimeEntryVirtualAddress"] ?: @"",
                @"springBoardPID": context[@"springBoardPID"] ?: @0,
                @"springBoardProc": context[@"springBoardProc"] ?: @"",
                @"springBoardTask": context[@"springBoardTask"] ?: @"",
                @"springBoardLeafEntryAddress":
                    springBoard[@"terminalEntryAddress"] ?: @"",
                @"provenLeafEntryValue":
                    springBoard[@"terminalEntryValue"] ?: @"",
                @"springBoardTranslationPath": springBoard[@"path"],
            };

            report[@"stage"] = @"armed-springboard-page-wire";
            report[@"wire"] = @{
                @"route": @"springboard-remote-call-mlock",
                @"process": @"SpringBoard",
                @"pageBase": CNDHailMaryPageWireHex(pageBase),
                @"byteLength": @(kCNDHailMaryPageWirePageSize),
                @"targetVirtualAddress":
                    context[@"runtimeEntryVirtualAddress"] ?: @"",
                @"physicalFrame": CNDHailMaryPageWireHex(frame),
                @"kernelWritePrimitivePlanned": @NO,
                @"semanticMutationPlanned": @NO,
                @"pageBytesPlannedToChange": @NO,
                @"controlBeatsPlanned": @YES,
                @"returned": @NO,
            };
            report[@"inverse"] = @{
                @"operation": @"munlock",
                @"process": @"SpringBoard",
                @"pageBase": CNDHailMaryPageWireHex(pageBase),
                @"byteLength": @(kCNDHailMaryPageWirePageSize),
                @"releasedAutomaticallyOnSpringBoardExit": @YES,
                @"pageContentInverseRequired": @NO,
                @"reason": @"The wire probe changes no memory, so the only state to undo is the mlock range.",
            };
            NSString *journalError = nil;
            if (!CNDHailMaryPageWireSaveDurably(
                    report, reportPath, &journalError)) {
                report[@"result"] = @"prewire-journal-sync-failed";
                report[@"message"] = journalError ?:
                    @"The pre-arm journal could not be made durable.";
                CNDHailMaryPageWireFinish(report, completion);
                return;
            }

            /* The single target beat. No retry, no fallback, no write. */
            NSDictionary<NSString *, id> *wireReport =
                CNDHailMaryPatchWireSpringBoardPage(
                    wireContext,
                    @{ @"diagnosticControls": @YES });
            report[@"springBoardPageWire"] = wireReport ?: @{};
            report[@"stage"] = @"wire-beat-returned";
            BOOL wireLanded = [wireReport[@"mlockLanded"] boolValue];
            BOOL wired = [wireReport[@"wired"] boolValue];
            BOOL remoteHealthy =
                [wireReport[@"remoteCallHealthy"] boolValue];
            report[@"wire"] = @{
                @"route": @"springboard-remote-call-mlock",
                @"process": @"SpringBoard",
                @"pageBase": CNDHailMaryPageWireHex(pageBase),
                @"byteLength": @(kCNDHailMaryPageWirePageSize),
                @"targetVirtualAddress":
                    context[@"runtimeEntryVirtualAddress"] ?: @"",
                @"physicalFrame": CNDHailMaryPageWireHex(frame),
                @"kernelWritePrimitivePlanned": @NO,
                @"semanticMutationPlanned": @NO,
                @"pageBytesPlannedToChange": @NO,
                @"controlBeatsPlanned": @YES,
                @"returned": @YES,
                @"mlockLanded": @(wireLanded),
                @"wired": @(wired),
                @"mlockReturn": wireReport[@"mlockReturn"] ?: @"",
                @"mlockErrno": wireReport[@"mlockErrno"] ?: @0,
                @"mlockErrnoDescription":
                    wireReport[@"mlockErrnoDescription"] ?: @"unavailable",
                @"stage": wireReport[@"stage"] ?: @"unknown",
            };
            BOOL postTranslationStable = NO;
            BOOL postGuardStable = NO;
            BOOL postWiredGuardStable = NO;
            BOOL privateCopy = NO;
            uint64_t postWindowKVA = 0;
            if (wireLanded) {
                report[@"stage"] = @"post-wire-identity-check";
                NSDictionary<NSString *, id> *postSpring = nil;
                NSString *postError = nil;
                uint64_t postFrame = 0;
                uint64_t postPhysical = 0;

                /* Wiring is a property of one pmap, so the kernel may give
                 * SpringBoard a private leaf entry for a page whose tables
                 * were shared. Re-prove SpringBoard on its own and compare the
                 * physical frame instead of the raw descriptor. */
                if (CNDHailMaryProbeTranslateRuntimeAddressInProcess(
                        probeReport, @"SpringBoard", runtimeAddress,
                        &postSpring, &postError) &&
                    CNDHailMaryPageWireParseHex(
                        postSpring[@"physicalFrame"], &postFrame) &&
                    CNDHailMaryPageWireParseHex(
                        postSpring[@"physicalAddress"], &postPhysical) &&
                    postFrame == frame &&
                    postPhysical == physicalAddress) {
                    postTranslationStable = YES;
                }
                privateCopy = postFrame != 0 && postFrame != frame;
                /* The kernel's physical aperture is a linear mapping, so the
                 * window for a moved frame is the same physmap base plus the
                 * new physical address. Re-reading the old window after a move
                 * would only prove the *old* page still holds the guard, which
                 * is not the question: the page SpringBoard wired is the new
                 * one, and only its bytes decide whether the redirect survived
                 * the copy. */
                if (postPhysical != 0 && is_kaddr_valid(frameKVA) &&
                    frameKVA >= frame) {
                    uint64_t candidate = frameKVA - frame + postPhysical;
                    if (is_kaddr_valid(candidate)) postWindowKVA = candidate;
                }
                uint8_t afterBytes[kCNDHailMaryPageWireGuardLength] = {0};
                kreadbuf(windowKVA, afterBytes, sizeof(afterBytes));
                NSData *afterData = [NSData dataWithBytes:afterBytes
                                                    length:sizeof(afterBytes)];
                postGuardStable = [afterData isEqualToData:beforeData];
                NSData *wiredData = nil;
                if (postWindowKVA != 0 && postWindowKVA != windowKVA) {
                    uint8_t wiredBytes[kCNDHailMaryPageWireGuardLength] = {0};
                    kreadbuf(postWindowKVA, wiredBytes, sizeof(wiredBytes));
                    wiredData = [NSData dataWithBytes:wiredBytes
                                               length:sizeof(wiredBytes)];
                    postWiredGuardStable =
                        [wiredData isEqualToData:beforeData];
                } else {
                    /* No move: the proven window is the wired window. */
                    postWiredGuardStable = postGuardStable;
                    wiredData = afterData;
                }
                report[@"postWireIdentity"] = @{
                    @"performed": @YES,
                    @"translationStable": @(postTranslationStable),
                    @"translationError": postError ?: @"none",
                    @"translationMode": @"springboard-only",
                    @"expectedPhysicalFrame":
                        CNDHailMaryPageWireHex(frame),
                    @"expectedPhysicalAddress":
                        CNDHailMaryPageWireHex(physicalAddress),
                    @"frameMoved": @(privateCopy),
                    @"privateCopy": @(privateCopy),
                    @"guardStable": @(postGuardStable),
                    @"guardSHA256": CNDHailMaryPageWireSHA256(afterData),
                    @"wiredFrameWindowKernelVirtualAddress":
                        CNDHailMaryPageWireHex(postWindowKVA),
                    @"wiredFrameGuardStable": @(postWiredGuardStable),
                    @"wiredFrameGuardSHA256":
                        wiredData
                            ? CNDHailMaryPageWireSHA256(wiredData) : @"",
                    @"physicalFrame": CNDHailMaryPageWireHex(postFrame),
                    @"physicalAddress":
                        CNDHailMaryPageWireHex(postPhysical),
                    @"springBoardLeafEntryValue":
                        postSpring[@"terminalEntryValue"] ?: @"",
                    @"springBoardLeafEntryAddress":
                        postSpring[@"terminalEntryAddress"] ?: @"",
                };
            } else {
                report[@"postWireIdentity"] = @{
                    @"performed": @NO,
                    @"reason": @"The target mlock did not land, so there is no wire to re-prove.",
                };
            }

            /* Keeping the address pinned is stricter than the question the
             * probe asks. Wiring may force a private copy, and that is still a
             * retained wire when the *wired* frame carries the exact guard.
             * Without that read, a move cannot be told apart from a re-fault
             * that silently dropped the redirect. */
            BOOL postStable = postWiredGuardStable &&
                (postTranslationStable || privateCopy);
            /* The patch wire's own verdict also requires the page not to have
             * moved, so it cannot be the whole answer here. Keep only its
             * safety conditions: the session must have closed cleanly and the
             * RemoteCall must still have been healthy. */
            BOOL sessionClean =
                [wireReport[@"remoteCallHealthy"] boolValue] &&
                [wireReport[@"sessionClosed"] boolValue] &&
                ![wireReport[@"teardownDeferred"] boolValue];
            BOOL confirmed = wireLanded && sessionClean && postStable;
            NSMutableDictionary<NSString *, id> *wireOut =
                [report[@"wire"] mutableCopy];
            wireOut[@"rawWired"] = @(wired);
            wireOut[@"retained"] = @(postStable);
            report[@"wire"] = wireOut;
            /* "Retained" means the mlock landed *and* the page SpringBoard
             * now resolves still carries the proven guard — either on the
             * proven frame or on the private copy the kernel wired. */
            report[@"springBoardWireRetained"] = @(postStable);
            NSString *interpretation =
                CNDHailMaryPageWireInterpretation(
                    wireReport, wireLanded, postStable);
            if (postStable && privateCopy) {
                interpretation = @"springboard-wire-accepted-private-copy";
            }
            report[@"interpretation"] = interpretation;
            report[@"confirmed"] = @(confirmed);
            report[@"result"] = confirmed
                ? @"read-only-data-page-wire-confirmed"
                : (wireLanded
                    ? @"read-only-data-page-wire-landed-unverified"
                    : (remoteHealthy
                        ? @"read-only-data-page-wire-refused"
                        : @"read-only-data-page-wire-preflight-refused"));
            NSString *controlSummary = [NSString stringWithFormat:
                @"anon-rw=%@ anon-ro=%@",
                CNDHailMaryPageWireControlText(
                    wireReport, @"anonymousReadWrite"),
                CNDHailMaryPageWireControlText(
                    wireReport, @"anonymousReadOnly")];
            NSString *leafDetail = [wireReport[@"privateLeafEntry"] boolValue]
                ? @" and forced a private leaf entry (either way the output "
                  @"address did not move)"
                : @"";
            NSDictionary<NSString *, id> *postIdentity =
                [report[@"postWireIdentity"] isKindOfClass:
                    NSDictionary.class]
                    ? report[@"postWireIdentity"] : @{};
            NSString *frameDetail = ([postIdentity[@"frameMoved"] boolValue] &&
                                     !confirmed)
                ? [NSString stringWithFormat:
                    @" SpringBoard now resolves %@ instead of the proven %@, "
                    @"and that frame does not carry the proven guard, so the "
                    @"wire did not retain the redirected page.",
                    postIdentity[@"physicalFrame"] ?: @"unknown",
                    postIdentity[@"expectedPhysicalFrame"] ?: @"unknown"]
                : @"";
            report[@"message"] = confirmed
                ? (privateCopy
                    ? [NSString stringWithFormat:
                        @"SpringBoard's mlock wired the page on a private "
                        @"copy: the mapping moved from %@ to %@ and the wired "
                        @"frame still carries the exact redirected guard "
                        @"(%@). The wire is retained until SpringBoard exits; "
                        @"only a longitudinal guard check can show that it "
                        @"holds the page against the clean-page purge.",
                        CNDHailMaryPageWireHex(frame),
                        postIdentity[@"physicalFrame"] ?: @"unknown",
                        controlSummary]
                    : [NSString stringWithFormat:
                        @"SpringBoard's mlock accepted the exact .34 frame%@ "
                        @"and the identity stayed stable (%@). The wire is "
                        @"retained until SpringBoard exits; only a "
                        @"longitudinal guard check can show that it holds the "
                        @"page against the clean-page purge.",
                        leafDetail, controlSummary])
                : (wireLanded
                    ? [NSString stringWithFormat:
                        @"SpringBoard's mlock returned success but the page "
                        @"identity or its guard did not re-prove (%@).%@ "
                        @"Treat the wire as unproven.",
                        controlSummary, frameDetail]
                    : [NSString stringWithFormat:
                        @"SpringBoard's mlock did not wire the .34 frame "
                        @"(errno %@: %@; %@). No memory was changed.",
                        wireReport[@"mlockErrno"] ?: @0,
                        wireReport[@"mlockErrnoDescription"] ?:
                            @"unavailable",
                        controlSummary]);
            report[@"followUp"] = @{
                @"longitudinalGuardCheckRequired": @YES,
                @"guardSHA256": context[@"guardSHA256"] ?: @"",
                @"windowKernelVirtualAddress":
                    CNDHailMaryPageWireHex(
                        postWindowKVA != 0 ? postWindowKVA : windowKVA),
                @"windowIsWiredFrame": @(postWindowKVA != 0),
                @"note": @"A successful wire only defers the silent clean-page purge. Re-read the provider window after the next heavy-usage cycle: the guard returning to the pinned original proves the wire did not hold. If SpringBoard restarted, re-resolve the page first; the recorded window belongs to that process lifetime.",
            };
            CNDHailMaryPageWireFinish(report, completion);
        });
    });
}

BOOL CNDHailMaryPageWireIsSupported(NSString **reasonOut)
{
    return CNDHailMaryProbeIsSupported(reasonOut);
}

BOOL CNDHailMaryPageWireIsRunning(void)
{
    return __sync_fetch_and_add(&gCNDHailMaryPageWireRunning, 0) != 0;
}
