//
//  CNDHailMarySpecialIconClassRedirect.m
//  Cyanide
//
//  Data-only Clock/Calendar class selection redirect.
//
//  SBHIconModel's -iconClassForApplicationWithBundleIdentifier: helper
//  special-cases com.apple.mobiletimer and com.apple.mobilecal by loading the
//  SBHClockApplicationIcon / SBHCalendarApplicationIcon class pointers from
//  two __got slots in SpringBoardHome. Those slots live in the shared cache's
//  .33.dylddata subcache (a non-executable data mapping), and the same
//  subcache family already accepted an identical-bytes aperture write in the
//  Hail Mary data-page experiment. Redirecting both slots to
//  SBHApplicationIcon makes the helper take its ordinary application-icon
//  path for Clock and Calendar without touching executable text.
//
//  The patch is per-process. It is visible to the SpringBoard and Spotlight
//  instances that were alive when it was applied, but a respring starts fresh
//  processes with a fresh .33 GOT page and the original class pointers. The
//  live helper also keeps a warm per-process class cache, so reapplying the
//  GOT pointer alone does not change the live icons after a respring. The
//  persistent SnowBoard IconServices records for the two bundle identifiers
//  are never touched.
//

#import "CNDHailMarySpecialIconClassRedirect.h"
#import "CNDHailMarySpecialIconClassDispatchRedirect.h"
#import "CNDSpecialIconPresentationDispatchProbe.h"

#import "CNDHailMaryDataPage.h"
#import "CNDHailMaryImpRedirect.h"
#import "CNDHailMaryPageWire.h"
#import "CNDHailMaryPatch.h"
#import "CNDHailMaryProbe.h"
#import "CNDHailMaryReadOnlyDataPage.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/krw.h"
#import "../kexploit/kutils.h"

#import <CommonCrypto/CommonDigest.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define CND_HAIL_MARY_SPECIAL_CLASS_BUILD "23A341"
#define CND_HAIL_MARY_SPECIAL_CLASS_PRODUCT "iPhone17,2"
#define CND_HAIL_MARY_SPECIAL_CLASS_SUBCACHE_UUID \
    "F193189E-840D-3569-816A-2102BCB0FFE5"
#define CND_HAIL_MARY_SPECIAL_CLASS_EXPERIMENT \
    "hail-mary-special-icon-class-got-redirect"

static const uint64_t kCNDHailMarySpecialClassPageSize = UINT64_C(0x4000);
static const uint64_t kCNDHailMarySpecialClassMaximumSlide =
    UINT64_C(0x40000000);

/* SpringBoardHome __got slots for the two special class pointers. Both are
 * in the .33.dylddata subcache, segment base 0x1e6b5c000, file offset 0x4000,
 * initProt=r--, maxProt=rw-. */
static const uint64_t kCNDHailMarySpecialClassClockSlotUnslid =
    UINT64_C(0x1e8278298);
static const uint64_t kCNDHailMarySpecialClassCalendarSlotUnslid =
    UINT64_C(0x1e8278270);
static const uint64_t kCNDHailMarySpecialClassClockSlotFileOffset =
    UINT64_C(0x1720298);
static const uint64_t kCNDHailMarySpecialClassCalendarSlotFileOffset =
    UINT64_C(0x1720270);

/* Class objects resolved by those slots. */
static const uint64_t kCNDHailMarySpecialClassClockClassUnslid =
    UINT64_C(0x1eda02180);
static const uint64_t kCNDHailMarySpecialClassCalendarClassUnslid =
    UINT64_C(0x1eda02568);
static const uint64_t kCNDHailMarySpecialClassApplicationClassUnslid =
    UINT64_C(0x1eda021a8);

/* The helper's per-process class caches. They are recorded for diagnostics;
 * the operation deliberately does not write them because they are process
 * private once SpringBoard has cached a class. A respring starts them at zero
 * and the patched __got slots are what the fresh helper reads. */
static const uint64_t kCNDHailMarySpecialClassClockCacheUnslid =
    UINT64_C(0x1ebf517d8);
static const uint64_t kCNDHailMarySpecialClassCalendarCacheUnslid =
    UINT64_C(0x1ebf51640);

static volatile int gCNDHailMarySpecialClassPermissionRunning;
static volatile int gCNDHailMarySpecialClassRedirectRunning;
static volatile int gCNDHailMarySpecialClassDispatchPermissionRunning;
static volatile int gCNDHailMarySpecialClassDispatchRedirectRunning;

static NSString *CNDHailMarySpecialClassHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static BOOL CNDHailMarySpecialClassParseHex(
    NSString *text, uint64_t *valueOut)
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

static NSString *CNDHailMarySpecialClassOperationName(
    CNDHailMarySpecialIconClassOperation operation)
{
    switch (operation) {
        case CNDHailMarySpecialIconClassOperationApply: return @"apply";
        case CNDHailMarySpecialIconClassOperationRestore: return @"restore";
        case CNDHailMarySpecialIconClassOperationVerifyRedirected:
            return @"verify-redirected";
        case CNDHailMarySpecialIconClassOperationVerifyOriginal:
            return @"verify-original";
    }
    return @"unknown";
}

static BOOL CNDHailMarySpecialClassIsMutation(
    CNDHailMarySpecialIconClassOperation operation)
{
    return operation == CNDHailMarySpecialIconClassOperationApply ||
        operation == CNDHailMarySpecialIconClassOperationRestore;
}

static BOOL CNDHailMarySpecialClassExpectedRedirected(
    CNDHailMarySpecialIconClassOperation operation)
{
    return operation == CNDHailMarySpecialIconClassOperationRestore ||
        operation == CNDHailMarySpecialIconClassOperationVerifyRedirected;
}

static NSString *CNDHailMarySpecialClassDocumentsPath(NSString *name)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    return [directory stringByAppendingPathComponent:name];
}

static NSString *CNDHailMarySpecialClassPermissionPath(void)
{
    return CNDHailMarySpecialClassDocumentsPath(
        @"CNDHailMarySpecialIconClassPermission.json");
}

static NSString *CNDHailMarySpecialClassReportPath(void)
{
    return CNDHailMarySpecialClassDocumentsPath(
        @"CNDHailMarySpecialIconClassRedirect.json");
}

static BOOL CNDHailMarySpecialClassSyncFileDescriptor(int descriptor)
{
    if (descriptor < 0) return NO;
#ifdef F_FULLFSYNC
    if (fcntl(descriptor, F_FULLFSYNC) == 0) return YES;
#endif
    return fsync(descriptor) == 0;
}

static BOOL CNDHailMarySpecialClassSaveDurably(
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
    BOOL fileSynced = CNDHailMarySpecialClassSyncFileDescriptor(fileDescriptor);
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

static void CNDHailMarySpecialClassFinish(
    NSMutableDictionary<NSString *, id> *report,
    BOOL permissionReport,
    CNDHailMarySpecialIconClassCompletion completion)
{
    report[@"finishedAtUnixTime"] = @([[NSDate date] timeIntervalSince1970]);
    NSString *persistenceError = nil;
    if (!CNDHailMarySpecialClassSaveDurably(
            report, report[@"reportPath"], &persistenceError)) {
        report[@"finalReportPersistenceError"] = persistenceError ?:
            @"final-report-durable-save-failed";
    }
    NSDictionary<NSString *, id> *finished = [report copy];
    volatile int *running = permissionReport
        ? &gCNDHailMarySpecialClassPermissionRunning
        : &gCNDHailMarySpecialClassRedirectRunning;
    __sync_lock_release(running);
    dispatch_async(dispatch_get_main_queue(), ^{
        completion(finished);
    });
}

static BOOL CNDHailMarySpecialClassOtherExperimentRunning(
    BOOL includePermission)
{
    if (CNDHailMaryProbeIsRunning() || CNDHailMaryPatchIsRunning() ||
        CNDHailMaryDataPageIsRunning() ||
        CNDHailMaryReadOnlyDataPageIsRunning() ||
        CNDHailMaryImpRedirectIsRunning() ||
        CNDHailMaryPageWireIsRunning() ||
        CNDHailMarySpecialIconClassDispatchPermissionIsRunning() ||
        CNDHailMarySpecialIconClassDispatchRedirectIsRunning() ||
        CNDSpecialIconPresentationDispatchPermissionIsRunning() ||
        CNDSpecialIconPresentationDispatchRedirectIsRunning() ||
        (includePermission &&
            __sync_fetch_and_add(
                &gCNDHailMarySpecialClassPermissionRunning, 0) != 0)) {
        return YES;
    }
    return NO;
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDHailMarySpecialClassTargets(void)
{
    return @[
        @{
            @"bundle": @"com.apple.mobiletimer",
            @"label": @"Clock",
            @"slotUnslid": @(kCNDHailMarySpecialClassClockSlotUnslid),
            @"slotFileOffset":
                @(kCNDHailMarySpecialClassClockSlotFileOffset),
            @"originalClassUnslid":
                @(kCNDHailMarySpecialClassClockClassUnslid),
            @"redirectedClassUnslid":
                @(kCNDHailMarySpecialClassApplicationClassUnslid),
            @"cacheSlotUnslid":
                @(kCNDHailMarySpecialClassClockCacheUnslid),
        },
        @{
            @"bundle": @"com.apple.mobilecal",
            @"label": @"Calendar",
            @"slotUnslid": @(kCNDHailMarySpecialClassCalendarSlotUnslid),
            @"slotFileOffset":
                @(kCNDHailMarySpecialClassCalendarSlotFileOffset),
            @"originalClassUnslid":
                @(kCNDHailMarySpecialClassCalendarClassUnslid),
            @"redirectedClassUnslid":
                @(kCNDHailMarySpecialClassApplicationClassUnslid),
            @"cacheSlotUnslid":
                @(kCNDHailMarySpecialClassCalendarCacheUnslid),
        },
    ];
}

static NSMutableDictionary<NSString *, id> *
CNDHailMarySpecialClassBaseReport(NSString *reportPath)
{
    return [@{
        @"schemaVersion": @1,
        @"experiment": @CND_HAIL_MARY_SPECIAL_CLASS_EXPERIMENT,
        @"build": @CND_HAIL_MARY_SPECIAL_CLASS_BUILD,
        @"product": @CND_HAIL_MARY_SPECIAL_CLASS_PRODUCT,
        @"subcacheUUID": @CND_HAIL_MARY_SPECIAL_CLASS_SUBCACHE_UUID,
        @"startedAtUnixTime": @([[NSDate date] timeIntervalSince1970]),
        @"reportPath": reportPath ?: @"",
        @"targetProcessDirectMutationCount": @0,
        @"consumerRebuildRequired": @NO,
        @"kernelWritePrimitiveInvocationCount": @0,
        @"dispatchEntrySemanticMutationCount": @0,
    } mutableCopy];
}

static BOOL CNDHailMarySpecialClassSlideFromProbe(
    NSDictionary<NSString *, id> *probeReport,
    uint64_t *slideOut,
    NSString **errorOut)
{
    if (slideOut) *slideOut = 0;
    if (errorOut) *errorOut = nil;
    if (![probeReport isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = @"confirmed-hail-mary-proof-required";
        return NO;
    }
    /* The shared proof is schema v2 and records its verdict in
     * `result`/`physicalPageProof.confirmed`, not in a top-level
     * `confirmed` flag. Accept either shape so the module follows the
     * proof that is actually on disk. */
    id physicalProof = probeReport[@"physicalPageProof"];
    BOOL physicalProofConfirmed =
        [physicalProof isKindOfClass:NSDictionary.class] &&
        [physicalProof[@"confirmed"] boolValue] &&
        [physicalProof[@"verdict"] isEqual:
            @"confirmed-shared-physical-frame-and-bytes"];
    BOOL resultConfirmed =
        [probeReport[@"result"] isKindOfClass:NSString.class] &&
        [probeReport[@"result"] hasPrefix:@"confirmed-"];
    if (!physicalProofConfirmed && !resultConfirmed &&
        ![probeReport[@"confirmed"] boolValue]) {
        if (errorOut) *errorOut = @"confirmed-hail-mary-proof-required";
        return NO;
    }
    if ([probeReport[@"schemaVersion"] unsignedIntegerValue] != 2 ||
        ![probeReport[@"probe"] isEqual:@"hail-mary-physical-page-proof"] ||
        ![probeReport[@"productType"] isEqual:
            @CND_HAIL_MARY_SPECIAL_CLASS_PRODUCT] ||
        ![probeReport[@"productBuildVersion"] isEqual:
            @CND_HAIL_MARY_SPECIAL_CLASS_BUILD]) {
        if (errorOut) *errorOut = @"hail-mary-proof-identity-mismatch";
        return NO;
    }
    if ([probeReport[@"kernelMutationCount"] unsignedLongLongValue] != 0 ||
        [probeReport[@"targetProcessMutationCount"]
            unsignedLongLongValue] != 0) {
        if (errorOut) *errorOut = @"hail-mary-proof-was-not-read-only";
        return NO;
    }
    id springBoard = probeReport[@"springBoard"];
    id spotlight = probeReport[@"spotlight"];
    if (![springBoard isKindOfClass:NSDictionary.class] ||
        ![spotlight isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = @"shared-pair-proof-required";
        return NO;
    }
    uint64_t springBoardSlide = 0;
    uint64_t spotlightSlide = 0;
    if (!CNDHailMarySpecialClassParseHex(
            springBoard[@"sharedCacheSlide"], &springBoardSlide) ||
        !CNDHailMarySpecialClassParseHex(
            spotlight[@"sharedCacheSlide"], &spotlightSlide) ||
        springBoardSlide == 0 ||
        springBoardSlide != spotlightSlide ||
        springBoardSlide > kCNDHailMarySpecialClassMaximumSlide ||
        (springBoardSlide &
            (kCNDHailMarySpecialClassPageSize - 1)) != 0) {
        if (errorOut) *errorOut = @"shared-cache-slide-mismatch";
        return NO;
    }
    if (slideOut) *slideOut = springBoardSlide;
    return YES;
}

static BOOL CNDHailMarySpecialClassResolveGOTTarget(
    NSDictionary<NSString *, id> *probeReport,
    NSDictionary<NSString *, id> *target,
    uint64_t slide,
    NSDictionary<NSString *, id> * _Nullable * _Nullable resolvedOut,
    NSString * _Nullable * _Nullable errorOut)
{
    if (resolvedOut) *resolvedOut = nil;
    if (errorOut) *errorOut = nil;

    uint64_t slotUnslid = [target[@"slotUnslid"] unsignedLongLongValue];
    uint64_t slotRuntime = slotUnslid + slide;
    NSDictionary<NSString *, id> *springBoardTranslation = nil;
    NSDictionary<NSString *, id> *spotlightTranslation = nil;
    uint64_t physicalFrame = 0;
    uint64_t physicalAddress = 0;
    uint64_t frameKernelVirtualAddress = 0;
    if (!CNDHailMaryProbeTranslateSharedRuntimeAddress(
            probeReport,
            slotRuntime,
            &springBoardTranslation,
            &spotlightTranslation,
            &physicalFrame,
            &physicalAddress,
            &frameKernelVirtualAddress,
            errorOut)) {
        return NO;
    }

    uint64_t pageOffset =
        slotRuntime & (kCNDHailMarySpecialClassPageSize - 1);
    uint64_t windowKernelVirtualAddress =
        frameKernelVirtualAddress + pageOffset;
    uint64_t currentValue = kread64(windowKernelVirtualAddress);
    uint64_t originalValue =
        [target[@"originalClassUnslid"] unsignedLongLongValue] + slide;
    uint64_t redirectedValue =
        [target[@"redirectedClassUnslid"] unsignedLongLongValue] + slide;
    NSString *state = currentValue == originalValue
        ? @"original"
        : (currentValue == redirectedValue ? @"redirected" : @"unexpected");

    /* The helper checks its per-process class-cache slot before it reads the
     * __got pointer. The cache page is writable and may be process-private, so
     * audit it through SpringBoard's own pmap instead of the shared-pair walk.
     * This is read-only diagnostic state; the mutation path does not write it
     * yet. */
    uint64_t cacheSlotUnslid =
        [target[@"cacheSlotUnslid"] unsignedLongLongValue];
    uint64_t cacheSlotRuntime = cacheSlotUnslid + slide;
    NSDictionary<NSString *, id> *cacheTranslation = nil;
    uint64_t cachePhysicalFrame = 0;
    uint64_t cachePhysicalAddress = 0;
    uint64_t cacheFrameKernelVirtualAddress = 0;
    NSString *cacheError = nil;
    BOOL cacheResolved =
        CNDHailMaryProbeTranslateRuntimeAddressInProcessWithPhysical(
            probeReport,
            @"SpringBoard",
            cacheSlotRuntime,
            &cacheTranslation,
            &cachePhysicalFrame,
            &cachePhysicalAddress,
            &cacheFrameKernelVirtualAddress,
            &cacheError);
    uint64_t cacheValue = 0;
    uint64_t cacheWindowKernelVirtualAddress = 0;
    if (cacheResolved) {
        uint64_t cachePageOffset =
            cacheSlotRuntime & (kCNDHailMarySpecialClassPageSize - 1);
        cacheWindowKernelVirtualAddress =
            cacheFrameKernelVirtualAddress + cachePageOffset;
        cacheValue = kread64(cacheWindowKernelVirtualAddress);
    }

    if (resolvedOut) {
        *resolvedOut = @{
            @"bundle": target[@"bundle"],
            @"label": target[@"label"],
            @"slotUnslid":
                CNDHailMarySpecialClassHex(slotUnslid),
            @"slotRuntime":
                CNDHailMarySpecialClassHex(slotRuntime),
            @"slotFileOffset":
                CNDHailMarySpecialClassHex(
                    [target[@"slotFileOffset"] unsignedLongLongValue]),
            @"cacheSlotUnslid":
                CNDHailMarySpecialClassHex(
                    [target[@"cacheSlotUnslid"] unsignedLongLongValue]),
            @"currentValue":
                CNDHailMarySpecialClassHex(currentValue),
            @"originalValue":
                CNDHailMarySpecialClassHex(originalValue),
            @"redirectedValue":
                CNDHailMarySpecialClassHex(redirectedValue),
            @"state": state,
            @"physicalFrame":
                CNDHailMarySpecialClassHex(physicalFrame),
            @"physicalAddress":
                CNDHailMarySpecialClassHex(physicalAddress),
            @"windowKernelVirtualAddress":
                CNDHailMarySpecialClassHex(
                    windowKernelVirtualAddress),
            @"springBoardTranslation":
                springBoardTranslation ?: @{},
            @"spotlightTranslation":
                spotlightTranslation ?: @{},
            @"classCacheSlotRuntime":
                CNDHailMarySpecialClassHex(cacheSlotRuntime),
            @"classCacheSlotResolved": @(cacheResolved),
            @"classCacheSlotCurrentValue":
                CNDHailMarySpecialClassHex(cacheValue),
            @"classCacheSlotPhysicalFrame":
                CNDHailMarySpecialClassHex(cachePhysicalFrame),
            @"classCacheSlotPhysicalAddress":
                CNDHailMarySpecialClassHex(cachePhysicalAddress),
            @"classCacheSlotWindowKernelVirtualAddress":
                CNDHailMarySpecialClassHex(
                    cacheWindowKernelVirtualAddress),
            @"classCacheSlotTranslation":
                cacheTranslation ?: @{},
            @"classCacheSlotError": cacheError ?: @"",
        };
    }
    return YES;
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDHailMarySpecialClassResolveAll(
    NSDictionary<NSString *, id> *probeReport,
    uint64_t slide,
    NSString **errorOut)
{
    NSMutableArray<NSDictionary<NSString *, id> *> *resolved =
        [NSMutableArray array];
    for (NSDictionary<NSString *, id> *target in
            CNDHailMarySpecialClassTargets()) {
        NSDictionary<NSString *, id> *one = nil;
        if (!CNDHailMarySpecialClassResolveGOTTarget(
                probeReport, target, slide, &one, errorOut)) {
            return nil;
        }
        [resolved addObject:one];
    }
    return resolved;
}

static BOOL CNDHailMarySpecialClassAllInState(
    NSArray<NSDictionary<NSString *, id> *> *resolved,
    NSString *state)
{
    if (resolved.count != 2) return NO;
    for (NSDictionary<NSString *, id> *one in resolved) {
        if (![one[@"state"] isEqual:state]) return NO;
    }
    return YES;
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDHailMarySpecialClassTranslateAgain(
    NSDictionary<NSString *, id> *probeReport,
    NSArray<NSDictionary<NSString *, id> *> *resolved)
{
    NSMutableArray<NSDictionary<NSString *, id> *> *translations =
        [NSMutableArray array];
    for (NSDictionary<NSString *, id> *one in resolved) {
        uint64_t slotRuntime = 0;
        if (!CNDHailMarySpecialClassParseHex(
                one[@"slotRuntime"], &slotRuntime)) {
            return nil;
        }
        NSDictionary<NSString *, id> *springBoardTranslation = nil;
        NSDictionary<NSString *, id> *spotlightTranslation = nil;
        uint64_t physicalFrame = 0;
        uint64_t physicalAddress = 0;
        uint64_t frameKernelVirtualAddress = 0;
        NSString *error = nil;
        if (!CNDHailMaryProbeTranslateSharedRuntimeAddress(
                probeReport,
                slotRuntime,
                &springBoardTranslation,
                &spotlightTranslation,
                &physicalFrame,
                &physicalAddress,
                &frameKernelVirtualAddress,
                &error)) {
            return nil;
        }
        uint64_t expectedFrame = 0;
        uint64_t expectedPhysical = 0;
        if (!CNDHailMarySpecialClassParseHex(
                one[@"physicalFrame"], &expectedFrame) ||
            !CNDHailMarySpecialClassParseHex(
                one[@"physicalAddress"], &expectedPhysical) ||
            physicalFrame != expectedFrame ||
            physicalAddress != expectedPhysical) {
            return nil;
        }
        [translations addObject:@{
            @"bundle": one[@"bundle"] ?: @"",
            @"slotRuntime": one[@"slotRuntime"] ?: @"",
            @"physicalFrame":
                CNDHailMarySpecialClassHex(physicalFrame),
            @"physicalAddress":
                CNDHailMarySpecialClassHex(physicalAddress),
            @"stable": @YES,
        }];
    }
    return translations;
}

static NSDictionary<NSString *, id> *CNDHailMarySpecialClassReadPermission(void)
{
    NSData *data = [NSData dataWithContentsOfFile:
        CNDHailMarySpecialClassPermissionPath()];
    if (!data) return nil;
    id object = [NSJSONSerialization JSONObjectWithData:data
                                                options:0
                                                  error:nil];
    return [object isKindOfClass:NSDictionary.class] ? object : nil;
}

static BOOL CNDHailMarySpecialClassPermissionTicketMatches(
    NSDictionary<NSString *, id> *ticket,
    uint64_t slide,
    NSString **errorOut)
{
    if (![ticket isKindOfClass:NSDictionary.class] ||
        ![ticket[@"confirmed"] boolValue] ||
        ![ticket[@"experiment"] isEqual:
            @CND_HAIL_MARY_SPECIAL_CLASS_EXPERIMENT] ||
        ![ticket[@"build"] isEqual:
            @CND_HAIL_MARY_SPECIAL_CLASS_BUILD] ||
        ![ticket[@"product"] isEqual:
            @CND_HAIL_MARY_SPECIAL_CLASS_PRODUCT]) {
        if (errorOut) *errorOut =
            @"same-boot-special-class-got-probe-required";
        return NO;
    }
    uint64_t ticketSlide = 0;
    if (!CNDHailMarySpecialClassParseHex(
            ticket[@"slide"], &ticketSlide) ||
        ticketSlide != slide) {
        if (errorOut) *errorOut = @"permission-ticket-slide-mismatch";
        return NO;
    }
    return YES;
}

BOOL CNDHailMarySpecialIconClassRedirectIsSupported(NSString **reasonOut)
{
    return CNDHailMaryProbeIsSupported(reasonOut);
}

BOOL CNDHailMarySpecialIconClassPermissionIsRunning(void)
{
    return __sync_fetch_and_add(
        &gCNDHailMarySpecialClassPermissionRunning, 0) != 0;
}

BOOL CNDHailMarySpecialIconClassRedirectIsRunning(void)
{
    return __sync_fetch_and_add(
        &gCNDHailMarySpecialClassRedirectRunning, 0) != 0;
}

void CNDHailMarySpecialIconClassPermissionRunWithMode(
    CNDHailMaryProofMode mode,
    CNDHailMarySpecialIconClassCompletion completion)
{
    if (!completion) return;
    if (!__sync_bool_compare_and_swap(
            &gCNDHailMarySpecialClassPermissionRunning, 0, 1)) {
        completion(@{
            @"confirmed": @NO,
            @"result": @"special-class-got-probe-already-running",
            @"message": @"The special-class GOT probe is already running.",
        });
        return;
    }
    if (CNDHailMarySpecialClassOtherExperimentRunning(NO)) {
        NSMutableDictionary<NSString *, id> *report =
            CNDHailMarySpecialClassBaseReport(
                CNDHailMarySpecialClassPermissionPath());
        report[@"result"] = @"special-class-got-probe-another-experiment-running";
        report[@"message"] =
            @"Another Hail Mary experiment is running. No read or write was attempted.";
        CNDHailMarySpecialClassFinish(report, YES, completion);
        return;
    }

    CNDHailMaryProbeRunWithMode(mode,
        ^(NSDictionary<NSString *, id> *probeReport) {
        NSMutableDictionary<NSString *, id> *report =
            CNDHailMarySpecialClassBaseReport(
                CNDHailMarySpecialClassPermissionPath());
        report[@"preflightProbe"] = probeReport ?: @{};

        uint64_t slide = 0;
        NSString *error = nil;
        if (!CNDHailMarySpecialClassSlideFromProbe(
                probeReport, &slide, &error)) {
            report[@"result"] = @"special-class-got-probe-proof-failed";
            report[@"message"] = error ?:
                @"The shared Hail Mary proof did not confirm this boot.";
            CNDHailMarySpecialClassFinish(report, YES, completion);
            return;
        }
        report[@"slide"] = CNDHailMarySpecialClassHex(slide);

        NSArray<NSDictionary<NSString *, id> *> *resolved =
            CNDHailMarySpecialClassResolveAll(
                probeReport, slide, &error);
        if (!resolved) {
            report[@"result"] =
                @"special-class-got-probe-translation-failed";
            report[@"message"] = error ?:
                @"The .33.dylddata __got slots did not resolve through both live pmaps.";
            CNDHailMarySpecialClassFinish(report, YES, completion);
            return;
        }
        report[@"targets"] = resolved;
        BOOL original = CNDHailMarySpecialClassAllInState(
            resolved, @"original");
        BOOL redirected = CNDHailMarySpecialClassAllInState(
            resolved, @"redirected");
        report[@"state"] = original ? @"original" :
            (redirected ? @"redirected" : @"mixed-or-unexpected");
        report[@"readback"] = @{
            @"exactOriginal": @(original),
            @"exactRedirected": @(redirected),
            @"exactDesiredGuard": @(original || redirected),
            @"exactOfflineGuard": @(original || redirected),
        };
        report[@"slideScan"] = @{
            @"candidateCount": @1,
            @"matchingCandidateCount": @1,
        };
        report[@"postWriteTranslation"] = @{@"stable": @YES};

        if (!original && !redirected) {
            report[@"result"] =
                @"special-class-got-probe-unexpected-slot-value";
            report[@"message"] =
                @"At least one __got slot did not contain either the original special class or SBHApplicationIcon. No write was attempted.";
            CNDHailMarySpecialClassFinish(report, YES, completion);
            return;
        }

        report[@"result"] = @"special-class-got-probe-confirmed";
        report[@"confirmed"] = @YES;
        report[@"message"] = original
            ? @"Both SpringBoardHome __got slots currently select the special Clock/Calendar classes. The data-only GOT redirect is available for the current processes; no write was attempted."
            : @"Both SpringBoardHome __got slots already select SBHApplicationIcon. The data-only redirect is present for this boot; no write was attempted.";
        CNDHailMarySpecialClassFinish(report, YES, completion);
    });
}

void CNDHailMarySpecialIconClassPermissionRun(
    CNDHailMarySpecialIconClassCompletion completion)
{
    CNDHailMarySpecialIconClassPermissionRunWithMode(
        CNDHailMaryProofModeSharedPair, completion);
}

void CNDHailMarySpecialIconClassRedirectRunWithMode(
    CNDHailMaryProofMode mode,
    CNDHailMarySpecialIconClassOperation operation,
    CNDHailMarySpecialIconClassCompletion completion)
{
    if (!completion) return;
    if (!CNDHailMarySpecialClassIsMutation(operation)) {
        /* Verify operations are read-only and do not need the mutation lock,
         * but they still refuse concurrent mutation experiments. */
        if (!__sync_bool_compare_and_swap(
                &gCNDHailMarySpecialClassRedirectRunning, 0, 1)) {
            completion(@{
                @"confirmed": @NO,
                @"result": @"special-class-got-verify-already-running",
                @"message": @"The special-class GOT verify operation is already running.",
            });
            return;
        }
        if (CNDHailMarySpecialClassOtherExperimentRunning(NO)) {
            NSMutableDictionary<NSString *, id> *report =
                CNDHailMarySpecialClassBaseReport(
                    CNDHailMarySpecialClassReportPath());
            report[@"result"] =
                @"special-class-got-verify-another-experiment-running";
            report[@"message"] =
                @"Another Hail Mary experiment is running. No read was attempted.";
            CNDHailMarySpecialClassFinish(report, NO, completion);
            return;
        }
        CNDHailMaryProbeRunWithMode(mode,
            ^(NSDictionary<NSString *, id> *probeReport) {
            NSMutableDictionary<NSString *, id> *report =
                CNDHailMarySpecialClassBaseReport(
                    CNDHailMarySpecialClassReportPath());
            report[@"operation"] =
                CNDHailMarySpecialClassOperationName(operation);
            report[@"preflightProbe"] = probeReport ?: @{};
            uint64_t slide = 0;
            NSString *error = nil;
            if (!CNDHailMarySpecialClassSlideFromProbe(
                    probeReport, &slide, &error)) {
                report[@"result"] =
                    @"special-class-got-verify-proof-failed";
                report[@"message"] = error ?:
                    @"The shared Hail Mary proof did not confirm this boot.";
                CNDHailMarySpecialClassFinish(report, NO, completion);
                return;
            }
            report[@"slide"] = CNDHailMarySpecialClassHex(slide);
            NSArray<NSDictionary<NSString *, id> *> *resolved =
                CNDHailMarySpecialClassResolveAll(
                    probeReport, slide, &error);
            if (!resolved) {
                report[@"result"] =
                    @"special-class-got-verify-translation-failed";
                report[@"message"] = error ?:
                    @"The .33.dylddata __got slots did not resolve through both live pmaps.";
                CNDHailMarySpecialClassFinish(report, NO, completion);
                return;
            }
            report[@"targets"] = resolved;
            BOOL expectRedirected =
                CNDHailMarySpecialClassExpectedRedirected(operation);
            NSString *desiredState = expectRedirected
                ? @"redirected" : @"original";
            BOOL matches = CNDHailMarySpecialClassAllInState(
                resolved, desiredState);
            report[@"state"] = matches ? desiredState :
                (CNDHailMarySpecialClassAllInState(resolved, @"original")
                    ? @"original" : @"mixed-or-unexpected");
            report[@"readback"] = @{
                @"exactDesiredGuard": @(matches),
                @"exactOfflineGuard": @(matches),
                @"exactOriginal":
                    @(CNDHailMarySpecialClassAllInState(
                        resolved, @"original")),
                @"exactRedirected":
                    @(CNDHailMarySpecialClassAllInState(
                        resolved, @"redirected")),
            };
            report[@"slideScan"] = @{
                @"candidateCount": @1,
                @"matchingCandidateCount": @1,
            };
            report[@"postWriteTranslation"] = @{@"stable": @YES};
            report[@"confirmed"] = @(matches);
            report[@"result"] = matches
                ? (expectRedirected
                    ? @"special-class-got-verify-redirected-confirmed"
                    : @"special-class-got-verify-original-confirmed")
                : (expectRedirected
                    ? @"special-class-got-verify-redirected-mismatch"
                    : @"special-class-got-verify-original-mismatch");
            report[@"message"] = matches
                ? (expectRedirected
                    ? @"Both __got slots select SBHApplicationIcon in the current processes. The data-only redirect is per-process; a respring reverts it and the live class cache is warm."
                    : @"Both __got slots select the original special Clock/Calendar classes.")
                : @"The live __got slot state does not match the requested verification state. No write was attempted.";
            CNDHailMarySpecialClassFinish(report, NO, completion);
        });
        return;
    }

    if (!__sync_bool_compare_and_swap(
            &gCNDHailMarySpecialClassRedirectRunning, 0, 1)) {
        completion(@{
            @"confirmed": @NO,
            @"result": @"special-class-got-redirect-already-running",
            @"message": @"The special-class GOT redirect is already running.",
        });
        return;
    }
    if (CNDHailMarySpecialClassOtherExperimentRunning(YES)) {
        NSMutableDictionary<NSString *, id> *report =
            CNDHailMarySpecialClassBaseReport(
                CNDHailMarySpecialClassReportPath());
        report[@"operation"] =
            CNDHailMarySpecialClassOperationName(operation);
        report[@"result"] =
            @"special-class-got-redirect-another-experiment-running";
        report[@"message"] =
            @"Another Hail Mary experiment is running. No write was attempted.";
        CNDHailMarySpecialClassFinish(report, NO, completion);
        return;
    }

    NSDictionary<NSString *, id> *ticket =
        CNDHailMarySpecialClassReadPermission();
    CNDHailMaryProbeRunWithMode(mode,
        ^(NSDictionary<NSString *, id> *probeReport) {
        NSMutableDictionary<NSString *, id> *report =
            CNDHailMarySpecialClassBaseReport(
                CNDHailMarySpecialClassReportPath());
        report[@"operation"] =
            CNDHailMarySpecialClassOperationName(operation);
        report[@"preflightProbe"] = probeReport ?: @{};
        uint64_t slide = 0;
        NSString *error = nil;
        if (!CNDHailMarySpecialClassSlideFromProbe(
                probeReport, &slide, &error)) {
            report[@"result"] =
                @"special-class-got-redirect-proof-failed";
            report[@"message"] = error ?:
                @"The shared Hail Mary proof did not confirm this boot.";
            CNDHailMarySpecialClassFinish(report, NO, completion);
            return;
        }
        if (!CNDHailMarySpecialClassPermissionTicketMatches(
                ticket, slide, &error)) {
            report[@"result"] =
                @"special-class-got-redirect-permission-required";
            report[@"message"] = error ?:
                @"A same-boot read-only special-class GOT probe is required first.";
            CNDHailMarySpecialClassFinish(report, NO, completion);
            return;
        }
        report[@"slide"] = CNDHailMarySpecialClassHex(slide);

        NSArray<NSDictionary<NSString *, id> *> *resolved =
            CNDHailMarySpecialClassResolveAll(
                probeReport, slide, &error);
        if (!resolved) {
            report[@"result"] =
                @"special-class-got-redirect-translation-failed";
            report[@"message"] = error ?:
                @"The .33.dylddata __got slots did not resolve through both live pmaps.";
            CNDHailMarySpecialClassFinish(report, NO, completion);
            return;
        }
        report[@"targets"] = resolved;

        BOOL apply = operation ==
            CNDHailMarySpecialIconClassOperationApply;
        NSString *requiredState = apply ? @"original" : @"redirected";
        if (!CNDHailMarySpecialClassAllInState(resolved, requiredState)) {
            report[@"result"] = apply
                ? @"special-class-got-redirect-original-state-required"
                : @"special-class-got-redirect-redirected-state-required";
            report[@"message"] = apply
                ? @"At least one __got slot is not the original special class. Apply refuses mixed or already-redirected state."
                : @"At least one __got slot is not SBHApplicationIcon. Restore refuses mixed or original state.";
            CNDHailMarySpecialClassFinish(report, NO, completion);
            return;
        }

        NSMutableArray<NSDictionary<NSString *, id> *> *writes =
            [NSMutableArray array];
        for (NSDictionary<NSString *, id> *one in resolved) {
            uint64_t desired = 0;
            if (!CNDHailMarySpecialClassParseHex(
                    apply ? one[@"redirectedValue"] : one[@"originalValue"],
                    &desired)) {
                report[@"result"] =
                    @"special-class-got-redirect-desired-value-invalid";
                report[@"message"] =
                    @"The compiled desired class value could not be decoded. No write was attempted.";
                CNDHailMarySpecialClassFinish(report, NO, completion);
                return;
            }
            [writes addObject:@{
                @"bundle": one[@"bundle"] ?: @"",
                @"slotRuntime": one[@"slotRuntime"] ?: @"",
                @"windowKernelVirtualAddress":
                    one[@"windowKernelVirtualAddress"] ?: @"",
                @"inverseValue":
                    apply ? one[@"originalValue"] : one[@"redirectedValue"],
                @"desiredValue":
                    CNDHailMarySpecialClassHex(desired),
                @"dispatchReturned": @NO,
            }];
        }
        report[@"stage"] = apply
            ? @"armed-got-apply" : @"armed-got-restore";
        report[@"writes"] = writes;
        report[@"inverseState"] = apply
            ? @"run Restore to return both __got slots to the special classes"
            : @"run Apply to return both __got slots to SBHApplicationIcon";
        NSString *journalError = nil;
        if (!CNDHailMarySpecialClassSaveDurably(
                report, report[@"reportPath"], &journalError)) {
            report[@"result"] =
                @"special-class-got-redirect-journal-failed";
            report[@"message"] = journalError ?:
                @"The armed journal could not be written durably. No write was attempted.";
            CNDHailMarySpecialClassFinish(report, NO, completion);
            return;
        }

        uint64_t primitiveInvocations = 0;
        for (NSUInteger index = 0; index < resolved.count; index++) {
            NSDictionary<NSString *, id> *one = resolved[index];
            NSDictionary<NSString *, id> *write = writes[index];
            uint64_t windowKVA = 0;
            uint64_t desired = 0;
            if (!CNDHailMarySpecialClassParseHex(
                    write[@"windowKernelVirtualAddress"], &windowKVA) ||
                !CNDHailMarySpecialClassParseHex(
                    write[@"desiredValue"], &desired)) {
                report[@"result"] =
                    @"special-class-got-redirect-write-target-invalid";
                report[@"message"] =
                    @"An armed write target could not be decoded. No further write was attempted.";
                report[@"kernelWritePrimitiveInvocationCount"] =
                    @(primitiveInvocations);
                CNDHailMarySpecialClassFinish(report, NO, completion);
                return;
            }
            kwrite64(windowKVA, desired);
            primitiveInvocations++;
            uint64_t readback = kread64(windowKVA);
            if (readback != desired) {
                report[@"result"] =
                    @"special-class-got-redirect-readback-mismatch";
                report[@"message"] = [NSString stringWithFormat:
                    @"The %@ __got write returned but readback did not match the desired class. No automatic rollback was attempted.",
                    one[@"label"] ?: one[@"bundle"] ?: @"target"];
                report[@"kernelWritePrimitiveInvocationCount"] =
                    @(primitiveInvocations);
                CNDHailMarySpecialClassFinish(report, NO, completion);
                return;
            }
            write = [write mutableCopy];
            [(NSMutableDictionary *)write setObject:@YES
                                             forKey:@"dispatchReturned"];
            [(NSMutableDictionary *)write setObject:
                CNDHailMarySpecialClassHex(readback)
                                             forKey:@"readbackValue"];
            writes[index] = write;
        }

        NSArray<NSDictionary<NSString *, id> *> *postTranslations =
            CNDHailMarySpecialClassTranslateAgain(
                probeReport, resolved);
        if (!postTranslations) {
            report[@"result"] =
                @"special-class-got-redirect-post-translation-changed";
            report[@"message"] =
                @"Both writes returned and read back, but a post-write pmap translation changed. No automatic rollback was attempted.";
            report[@"kernelWritePrimitiveInvocationCount"] =
                @(primitiveInvocations);
            CNDHailMarySpecialClassFinish(report, NO, completion);
            return;
        }

        report[@"writes"] = writes;
        report[@"postWriteTranslation"] = @{
            @"stable": @YES,
            @"translations": postTranslations,
        };
        report[@"readback"] = @{
            @"exactDesiredGuard": @YES,
            @"exactOfflineGuard": @YES,
            @"exactOriginal": @(apply ? NO : YES),
            @"exactRedirected": @(apply ? YES : NO),
        };
        report[@"slideScan"] = @{
            @"candidateCount": @1,
            @"matchingCandidateCount": @1,
        };
        report[@"kernelWritePrimitiveInvocationCount"] =
            @(primitiveInvocations);
        report[@"dispatchEntrySemanticMutationCount"] =
            @(primitiveInvocations);
        report[@"targetProcessDirectMutationCount"] = @0;
        report[@"consumerRebuildRequired"] = @YES;
        report[@"confirmed"] = @YES;
        report[@"mutationConfirmed"] = @YES;
        report[@"stage"] = apply ? @"got-applied" : @"got-restored";
        report[@"result"] = apply
            ? @"special-class-got-apply-confirmed"
            : @"special-class-got-restore-confirmed";
        report[@"message"] = apply
            ? @"Both SpringBoardHome __got slots now select SBHApplicationIcon. A controlled respring is required before SpringBoard rebuilds the Clock/Calendar icons; the static themed records are unchanged. Clock hands and the Calendar date stop updating."
            : @"Both SpringBoardHome __got slots select the original special classes again. A controlled respring is required to rebuild the live Clock face and Calendar date. No automatic restart was performed.";
        CNDHailMarySpecialClassFinish(report, NO, completion);
    });
}

void CNDHailMarySpecialIconClassRedirectRun(
    CNDHailMarySpecialIconClassOperation operation,
    CNDHailMarySpecialIconClassCompletion completion)
{
    CNDHailMarySpecialIconClassRedirectRunWithMode(
        CNDHailMaryProofModeSharedPair, operation, completion);
}

#pragma mark - Per-boot preoptimized dispatch redirect

#define CND_HAIL_MARY_SPECIAL_DISPATCH_SUBCACHE_UUID \
    "CEEB0D68-9BA9-3CC8-AEB1-8F23BAC92B58"
#define CND_HAIL_MARY_SPECIAL_DISPATCH_EXPERIMENT \
    "hail-mary-special-icon-class-dispatch-redirect"

enum { kCNDHailMarySpecialDispatchGuardLength = 32 };

static NSString *CNDHailMarySpecialDispatchOperationName(
    CNDHailMarySpecialIconClassDispatchOperation operation)
{
    switch (operation) {
        case CNDHailMarySpecialIconClassDispatchOperationApply:
            return @"apply";
        case CNDHailMarySpecialIconClassDispatchOperationRestore:
            return @"restore";
        case CNDHailMarySpecialIconClassDispatchOperationVerifyRedirected:
            return @"verify-redirected";
        case CNDHailMarySpecialIconClassDispatchOperationVerifyOriginal:
            return @"verify-original";
    }
    return @"unknown";
}

static BOOL CNDHailMarySpecialDispatchIsMutation(
    CNDHailMarySpecialIconClassDispatchOperation operation)
{
    return operation ==
            CNDHailMarySpecialIconClassDispatchOperationApply ||
        operation ==
            CNDHailMarySpecialIconClassDispatchOperationRestore;
}

static NSString *CNDHailMarySpecialDispatchPermissionPath(void)
{
    return CNDHailMarySpecialClassDocumentsPath(
        @"CNDHailMarySpecialIconClassDispatchPermission.json");
}

static NSString *CNDHailMarySpecialDispatchReportPath(void)
{
    return CNDHailMarySpecialClassDocumentsPath(
        @"CNDHailMarySpecialIconClassDispatchRedirect.json");
}

static NSData *CNDHailMarySpecialDispatchDataFromHex(NSString *text)
{
    if (![text isKindOfClass:NSString.class] ||
        (text.length & 1) != 0) {
        return nil;
    }
    NSMutableData *data = [NSMutableData dataWithLength:text.length / 2];
    uint8_t *bytes = data.mutableBytes;
    for (NSUInteger index = 0; index < text.length; index += 2) {
        NSString *pair = [text substringWithRange:NSMakeRange(index, 2)];
        NSScanner *scanner = [NSScanner scannerWithString:pair];
        unsigned int value = 0;
        if (![scanner scanHexInt:&value] || !scanner.isAtEnd ||
            value > UINT8_MAX) {
            return nil;
        }
        bytes[index / 2] = (uint8_t)value;
    }
    return data;
}

static NSString *CNDHailMarySpecialDispatchHexForData(NSData *data)
{
    const uint8_t *bytes = data.bytes;
    NSMutableString *text = [NSMutableString stringWithCapacity:
        data.length * 2];
    for (NSUInteger index = 0; index < data.length; index++) {
        [text appendFormat:@"%02x", bytes[index]];
    }
    return text;
}

static NSString *CNDHailMarySpecialDispatchSHA256(NSData *data)
{
    uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    return CNDHailMarySpecialDispatchHexForData(
        [NSData dataWithBytes:digest length:sizeof(digest)]);
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDHailMarySpecialDispatchTargets(void)
{
    return @[
        @{
            @"className": @"SBHIconModel",
            @"consumer": @"Spotlight",
            @"classUnslid": @(UINT64_C(0x1eda01028)),
            @"preoptimizedCacheUnslid":
                @(UINT64_C(0x1ffc32e78)),
            @"entryUnslid": @(UINT64_C(0x1ffc330a8)),
            @"entryFileOffset": @(UINT64_C(0x78df0a8)),
            @"frameUnslid": @(UINT64_C(0x1ffc30000)),
            @"originalWord": @(UINT64_C(0x22440b400be18d3b)),
            @"redirectedWord": @(UINT64_C(0x22440b400be18d90)),
            @"originalGuardHex":
                @"3b8de10b400b44228f90ec0b80054503"
                 "d370e10b000046229c70e10b00204720",
            @"redirectedGuardHex":
                @"908de10b400b44228f90ec0b80054503"
                 "d370e10b000046229c70e10b00204720",
        },
        @{
            @"className": @"SBIconModel",
            @"consumer": @"SpringBoard",
            @"classUnslid": @(UINT64_C(0x281548678)),
            @"preoptimizedCacheUnslid":
                @(UINT64_C(0x1ffd52c88)),
            @"entryUnslid": @(UINT64_C(0x1ffd52eb8)),
            @"entryFileOffset": @(UINT64_C(0x79feeb8)),
            @"frameUnslid": @(UINT64_C(0x1ffd50000)),
            @"originalWord": @(UINT64_C(0x22440b4030ceaacf)),
            @"redirectedWord": @(UINT64_C(0x22440b4030ceab24)),
            @"originalGuardHex":
                @"cfaace30400b442223aed93080054503"
                 "678ece3000004622308ece3000204720",
            @"redirectedGuardHex":
                @"24abce30400b442223aed93080054503"
                 "678ece3000004622308ece3000204720",
        },
    ];
}

static NSMutableDictionary<NSString *, id> *
CNDHailMarySpecialDispatchBaseReport(NSString *reportPath)
{
    return [@{
        @"schemaVersion": @1,
        @"experiment": @CND_HAIL_MARY_SPECIAL_DISPATCH_EXPERIMENT,
        @"build": @CND_HAIL_MARY_SPECIAL_CLASS_BUILD,
        @"product": @CND_HAIL_MARY_SPECIAL_CLASS_PRODUCT,
        @"subcacheUUID":
            @CND_HAIL_MARY_SPECIAL_DISPATCH_SUBCACHE_UUID,
        @"startedAtUnixTime": @([[NSDate date] timeIntervalSince1970]),
        @"reportPath": reportPath ?: @"",
        @"targetProcessDirectMutationCount": @0,
        @"kernelWritePrimitiveInvocationCount": @0,
        @"dispatchEntrySemanticMutationCount": @0,
        @"consumerRebuildRequired": @NO,
    } mutableCopy];
}

static void CNDHailMarySpecialDispatchFinish(
    NSMutableDictionary<NSString *, id> *report,
    BOOL permissionReport,
    CNDHailMarySpecialIconClassDispatchCompletion completion)
{
    report[@"finishedAtUnixTime"] =
        @([[NSDate date] timeIntervalSince1970]);
    NSString *persistenceError = nil;
    if (!CNDHailMarySpecialClassSaveDurably(
            report, report[@"reportPath"], &persistenceError)) {
        report[@"finalReportPersistenceError"] = persistenceError ?:
            @"final-report-durable-save-failed";
    }
    NSDictionary<NSString *, id> *finished = [report copy];
    volatile int *running = permissionReport
        ? &gCNDHailMarySpecialClassDispatchPermissionRunning
        : &gCNDHailMarySpecialClassDispatchRedirectRunning;
    __sync_lock_release(running);
    dispatch_async(dispatch_get_main_queue(), ^{
        completion(finished);
    });
}

static BOOL CNDHailMarySpecialDispatchOtherExperimentRunning(
    BOOL includePermission)
{
    return CNDHailMaryProbeIsRunning() ||
        CNDHailMaryPatchIsRunning() ||
        CNDHailMaryDataPageIsRunning() ||
        CNDHailMaryReadOnlyDataPageIsRunning() ||
        CNDHailMaryImpRedirectIsRunning() ||
        CNDHailMaryPageWireIsRunning() ||
        CNDHailMarySpecialIconClassPermissionIsRunning() ||
        CNDHailMarySpecialIconClassRedirectIsRunning() ||
        CNDSpecialIconPresentationDispatchPermissionIsRunning() ||
        CNDSpecialIconPresentationDispatchRedirectIsRunning() ||
        (includePermission &&
            CNDHailMarySpecialIconClassDispatchPermissionIsRunning());
}

static BOOL CNDHailMarySpecialDispatchResolveTarget(
    NSDictionary<NSString *, id> *probeReport,
    NSDictionary<NSString *, id> *target,
    uint64_t slide,
    NSDictionary<NSString *, id> **resolvedOut,
    NSString **errorOut)
{
    if (resolvedOut) *resolvedOut = nil;
    if (errorOut) *errorOut = nil;
    uint64_t entryUnslid =
        [target[@"entryUnslid"] unsignedLongLongValue];
    uint64_t entryRuntime = entryUnslid + slide;
    NSDictionary<NSString *, id> *springBoardTranslation = nil;
    NSDictionary<NSString *, id> *spotlightTranslation = nil;
    uint64_t physicalFrame = 0;
    uint64_t physicalAddress = 0;
    uint64_t frameKernelVirtualAddress = 0;
    if (!CNDHailMaryProbeTranslateSharedRuntimeAddress(
            probeReport,
            entryRuntime,
            &springBoardTranslation,
            &spotlightTranslation,
            &physicalFrame,
            &physicalAddress,
            &frameKernelVirtualAddress,
            errorOut)) {
        return NO;
    }

    uint64_t pageOffset =
        entryRuntime & (kCNDHailMarySpecialClassPageSize - 1);
    uint64_t windowKernelVirtualAddress =
        frameKernelVirtualAddress + pageOffset;
    uint8_t bytes[kCNDHailMarySpecialDispatchGuardLength] = {0};
    kreadbuf(windowKernelVirtualAddress, bytes, sizeof(bytes));
    NSData *currentGuard =
        [NSData dataWithBytes:bytes length:sizeof(bytes)];
    NSData *originalGuard = CNDHailMarySpecialDispatchDataFromHex(
        target[@"originalGuardHex"]);
    NSData *redirectedGuard = CNDHailMarySpecialDispatchDataFromHex(
        target[@"redirectedGuardHex"]);
    if (originalGuard.length != sizeof(bytes) ||
        redirectedGuard.length != sizeof(bytes)) {
        if (errorOut) *errorOut = @"compiled-dispatch-guard-invalid";
        return NO;
    }
    NSString *state = [currentGuard isEqual:originalGuard]
        ? @"original"
        : ([currentGuard isEqual:redirectedGuard]
            ? @"redirected" : @"unexpected");
    uint64_t currentWord = 0;
    memcpy(&currentWord, bytes, sizeof(currentWord));
    if (resolvedOut) {
        *resolvedOut = @{
            @"className": target[@"className"] ?: @"",
            @"consumer": target[@"consumer"] ?: @"",
            @"classUnslid": CNDHailMarySpecialClassHex(
                [target[@"classUnslid"] unsignedLongLongValue]),
            @"preoptimizedCacheUnslid":
                CNDHailMarySpecialClassHex(
                    [target[@"preoptimizedCacheUnslid"]
                        unsignedLongLongValue]),
            @"entryUnslid": CNDHailMarySpecialClassHex(entryUnslid),
            @"entryRuntime":
                CNDHailMarySpecialClassHex(entryRuntime),
            @"entryFileOffset": CNDHailMarySpecialClassHex(
                [target[@"entryFileOffset"] unsignedLongLongValue]),
            @"frameUnslid": CNDHailMarySpecialClassHex(
                [target[@"frameUnslid"] unsignedLongLongValue]),
            @"currentWord":
                CNDHailMarySpecialClassHex(currentWord),
            @"originalWord": CNDHailMarySpecialClassHex(
                [target[@"originalWord"] unsignedLongLongValue]),
            @"redirectedWord": CNDHailMarySpecialClassHex(
                [target[@"redirectedWord"] unsignedLongLongValue]),
            @"currentGuardHex":
                CNDHailMarySpecialDispatchHexForData(currentGuard),
            @"currentGuardSHA256":
                CNDHailMarySpecialDispatchSHA256(currentGuard),
            @"originalGuardHex": target[@"originalGuardHex"],
            @"redirectedGuardHex": target[@"redirectedGuardHex"],
            @"state": state,
            @"physicalFrame":
                CNDHailMarySpecialClassHex(physicalFrame),
            @"physicalAddress":
                CNDHailMarySpecialClassHex(physicalAddress),
            @"frameKernelVirtualAddress":
                CNDHailMarySpecialClassHex(
                    frameKernelVirtualAddress),
            @"windowKernelVirtualAddress":
                CNDHailMarySpecialClassHex(
                    windowKernelVirtualAddress),
            @"springBoardTranslation":
                springBoardTranslation ?: @{},
            @"spotlightTranslation":
                spotlightTranslation ?: @{},
        };
    }
    return YES;
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDHailMarySpecialDispatchResolveAll(
    NSDictionary<NSString *, id> *probeReport,
    uint64_t slide,
    NSString **errorOut)
{
    NSMutableArray<NSDictionary<NSString *, id> *> *resolved =
        [NSMutableArray array];
    for (NSDictionary<NSString *, id> *target in
            CNDHailMarySpecialDispatchTargets()) {
        NSDictionary<NSString *, id> *one = nil;
        if (!CNDHailMarySpecialDispatchResolveTarget(
                probeReport, target, slide, &one, errorOut)) {
            return nil;
        }
        [resolved addObject:one];
    }
    return resolved;
}

static BOOL CNDHailMarySpecialDispatchAllInState(
    NSArray<NSDictionary<NSString *, id> *> *resolved,
    NSString *state)
{
    if (resolved.count != 2) return NO;
    for (NSDictionary<NSString *, id> *one in resolved) {
        if (![one[@"state"] isEqual:state]) return NO;
    }
    return YES;
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDHailMarySpecialDispatchTranslateAgain(
    NSDictionary<NSString *, id> *probeReport,
    NSArray<NSDictionary<NSString *, id> *> *resolved)
{
    NSMutableArray<NSDictionary<NSString *, id> *> *translations =
        [NSMutableArray array];
    for (NSDictionary<NSString *, id> *one in resolved) {
        uint64_t entryRuntime = 0;
        uint64_t expectedFrame = 0;
        uint64_t expectedAddress = 0;
        uint64_t expectedKVA = 0;
        if (!CNDHailMarySpecialClassParseHex(
                one[@"entryRuntime"], &entryRuntime) ||
            !CNDHailMarySpecialClassParseHex(
                one[@"physicalFrame"], &expectedFrame) ||
            !CNDHailMarySpecialClassParseHex(
                one[@"physicalAddress"], &expectedAddress) ||
            !CNDHailMarySpecialClassParseHex(
                one[@"windowKernelVirtualAddress"], &expectedKVA)) {
            return nil;
        }
        NSDictionary<NSString *, id> *springBoardTranslation = nil;
        NSDictionary<NSString *, id> *spotlightTranslation = nil;
        uint64_t physicalFrame = 0;
        uint64_t physicalAddress = 0;
        uint64_t frameKVA = 0;
        NSString *error = nil;
        if (!CNDHailMaryProbeTranslateSharedRuntimeAddress(
                probeReport,
                entryRuntime,
                &springBoardTranslation,
                &spotlightTranslation,
                &physicalFrame,
                &physicalAddress,
                &frameKVA,
                &error)) {
            return nil;
        }
        uint64_t windowKVA = frameKVA +
            (entryRuntime & (kCNDHailMarySpecialClassPageSize - 1));
        if (physicalFrame != expectedFrame ||
            physicalAddress != expectedAddress ||
            windowKVA != expectedKVA) {
            return nil;
        }
        [translations addObject:@{
            @"className": one[@"className"] ?: @"",
            @"entryRuntime": one[@"entryRuntime"] ?: @"",
            @"physicalFrame":
                CNDHailMarySpecialClassHex(physicalFrame),
            @"physicalAddress":
                CNDHailMarySpecialClassHex(physicalAddress),
            @"windowKernelVirtualAddress":
                CNDHailMarySpecialClassHex(windowKVA),
            @"stable": @YES,
        }];
    }
    return translations;
}

static NSDictionary<NSString *, id> *
CNDHailMarySpecialDispatchReadPermission(void)
{
    NSData *data = [NSData dataWithContentsOfFile:
        CNDHailMarySpecialDispatchPermissionPath()];
    if (!data) return nil;
    id object = [NSJSONSerialization JSONObjectWithData:data
                                                options:0
                                                  error:nil];
    return [object isKindOfClass:NSDictionary.class] ? object : nil;
}

static BOOL CNDHailMarySpecialDispatchPermissionMatches(
    NSDictionary<NSString *, id> *ticket,
    uint64_t slide,
    NSArray<NSDictionary<NSString *, id> *> *resolved,
    NSString **errorOut)
{
    if (![ticket isKindOfClass:NSDictionary.class] ||
        ![ticket[@"confirmed"] boolValue] ||
        ![ticket[@"experiment"] isEqual:
            @CND_HAIL_MARY_SPECIAL_DISPATCH_EXPERIMENT] ||
        ![ticket[@"build"] isEqual:
            @CND_HAIL_MARY_SPECIAL_CLASS_BUILD] ||
        ![ticket[@"product"] isEqual:
            @CND_HAIL_MARY_SPECIAL_CLASS_PRODUCT]) {
        if (errorOut) *errorOut =
            @"same-boot-special-dispatch-probe-required";
        return NO;
    }
    uint64_t ticketSlide = 0;
    if (!CNDHailMarySpecialClassParseHex(
            ticket[@"slide"], &ticketSlide) ||
        ticketSlide != slide) {
        if (errorOut) *errorOut =
            @"permission-ticket-slide-mismatch";
        return NO;
    }
    NSArray *ticketTargets = ticket[@"targets"];
    if (![ticketTargets isKindOfClass:NSArray.class] ||
        ticketTargets.count != resolved.count) {
        if (errorOut) *errorOut =
            @"permission-ticket-target-count-mismatch";
        return NO;
    }
    NSArray<NSString *> *keys = @[
        @"className",
        @"entryRuntime",
        @"physicalFrame",
        @"physicalAddress",
        @"windowKernelVirtualAddress",
    ];
    for (NSUInteger index = 0; index < resolved.count; index++) {
        NSDictionary *before = ticketTargets[index];
        NSDictionary *now = resolved[index];
        for (NSString *key in keys) {
            if (![before[key] isEqual:now[key]]) {
                if (errorOut) *errorOut =
                    @"permission-ticket-translation-mismatch";
                return NO;
            }
        }
    }
    return YES;
}

BOOL CNDHailMarySpecialIconClassDispatchRedirectIsSupported(
    NSString **reasonOut)
{
    return CNDHailMaryProbeIsSupported(reasonOut);
}

BOOL CNDHailMarySpecialIconClassDispatchPermissionIsRunning(void)
{
    return __sync_fetch_and_add(
        &gCNDHailMarySpecialClassDispatchPermissionRunning, 0) != 0;
}

BOOL CNDHailMarySpecialIconClassDispatchRedirectIsRunning(void)
{
    return __sync_fetch_and_add(
        &gCNDHailMarySpecialClassDispatchRedirectRunning, 0) != 0;
}

void CNDHailMarySpecialIconClassDispatchPermissionRunWithMode(
    CNDHailMaryProofMode mode,
    CNDHailMarySpecialIconClassDispatchCompletion completion)
{
    if (!completion) return;
    if (!__sync_bool_compare_and_swap(
            &gCNDHailMarySpecialClassDispatchPermissionRunning, 0, 1)) {
        completion(@{
            @"confirmed": @NO,
            @"result": @"special-dispatch-probe-already-running",
            @"message": @"The special dispatch probe is already running.",
        });
        return;
    }
    if (CNDHailMarySpecialDispatchOtherExperimentRunning(NO)) {
        NSMutableDictionary *report =
            CNDHailMarySpecialDispatchBaseReport(
                CNDHailMarySpecialDispatchPermissionPath());
        report[@"result"] =
            @"special-dispatch-probe-another-experiment-running";
        report[@"message"] =
            @"Another Hail Mary experiment is running. No write was attempted.";
        CNDHailMarySpecialDispatchFinish(report, YES, completion);
        return;
    }

    CNDHailMaryProbeRunWithMode(mode,
        ^(NSDictionary<NSString *, id> *probeReport) {
        NSMutableDictionary *report =
            CNDHailMarySpecialDispatchBaseReport(
                CNDHailMarySpecialDispatchPermissionPath());
        report[@"preflightProbe"] = probeReport ?: @{};
        uint64_t slide = 0;
        NSString *error = nil;
        if (!CNDHailMarySpecialClassSlideFromProbe(
                probeReport, &slide, &error)) {
            report[@"result"] =
                @"special-dispatch-probe-proof-failed";
            report[@"message"] = error ?:
                @"The shared Hail Mary proof did not confirm this boot.";
            CNDHailMarySpecialDispatchFinish(
                report, YES, completion);
            return;
        }
        report[@"slide"] = CNDHailMarySpecialClassHex(slide);
        NSArray *resolved = CNDHailMarySpecialDispatchResolveAll(
            probeReport, slide, &error);
        if (!resolved) {
            report[@"result"] =
                @"special-dispatch-probe-translation-failed";
            report[@"message"] = error ?:
                @"The two .34 dispatch entries did not resolve through both live pmaps.";
            CNDHailMarySpecialDispatchFinish(
                report, YES, completion);
            return;
        }
        report[@"targets"] = resolved;
        BOOL original =
            CNDHailMarySpecialDispatchAllInState(
                resolved, @"original");
        BOOL redirected =
            CNDHailMarySpecialDispatchAllInState(
                resolved, @"redirected");
        if (!original && !redirected) {
            report[@"result"] =
                @"special-dispatch-probe-guard-mismatch";
            report[@"message"] =
                @"At least one packed dispatch entry did not match either pinned 32-byte guard. No write was attempted.";
            CNDHailMarySpecialDispatchFinish(
                report, YES, completion);
            return;
        }

        report[@"state"] = original ? @"original" : @"redirected";
        report[@"stage"] = @"armed-identical-dispatch-writes";
        report[@"writes"] = @[];
        NSString *journalError = nil;
        if (!CNDHailMarySpecialClassSaveDurably(
                report, report[@"reportPath"], &journalError)) {
            report[@"result"] =
                @"special-dispatch-probe-journal-failed";
            report[@"message"] = journalError ?:
                @"The permission journal could not be saved. No write was attempted.";
            CNDHailMarySpecialDispatchFinish(
                report, YES, completion);
            return;
        }

        NSMutableArray *writes = [NSMutableArray array];
        uint64_t primitiveInvocations = 0;
        for (NSDictionary *one in resolved) {
            uint64_t windowKVA = 0;
            uint64_t currentWord = 0;
            if (!CNDHailMarySpecialClassParseHex(
                    one[@"windowKernelVirtualAddress"], &windowKVA) ||
                !CNDHailMarySpecialClassParseHex(
                    one[@"currentWord"], &currentWord)) {
                report[@"result"] =
                    @"special-dispatch-probe-write-target-invalid";
                report[@"message"] =
                    @"A proven identical-write target could not be decoded.";
                report[@"kernelWritePrimitiveInvocationCount"] =
                    @(primitiveInvocations);
                CNDHailMarySpecialDispatchFinish(
                    report, YES, completion);
                return;
            }
            kwrite32(windowKVA, (uint32_t)currentWord);
            primitiveInvocations++;
            uint8_t bytes[kCNDHailMarySpecialDispatchGuardLength] = {0};
            kreadbuf(windowKVA, bytes, sizeof(bytes));
            NSData *readback =
                [NSData dataWithBytes:bytes length:sizeof(bytes)];
            if (![[CNDHailMarySpecialDispatchHexForData(readback)
                    lowercaseString]
                    isEqual:[one[@"currentGuardHex"] lowercaseString]]) {
                report[@"result"] =
                    @"special-dispatch-probe-readback-mismatch";
                report[@"message"] =
                    @"An identical low-word write returned, but its exact 32-byte guard changed.";
                report[@"kernelWritePrimitiveInvocationCount"] =
                    @(primitiveInvocations);
                CNDHailMarySpecialDispatchFinish(
                    report, YES, completion);
                return;
            }
            [writes addObject:@{
                @"className": one[@"className"] ?: @"",
                @"route": @"kwrite32-identical-low-word",
                @"dispatchReturned": @YES,
                @"identicalToBefore": @YES,
                @"readbackGuardHex":
                    CNDHailMarySpecialDispatchHexForData(readback),
            }];
        }
        NSArray *translations =
            CNDHailMarySpecialDispatchTranslateAgain(
                probeReport, resolved);
        if (!translations) {
            report[@"result"] =
                @"special-dispatch-probe-post-translation-changed";
            report[@"message"] =
                @"Both identical writes returned, but a translation changed.";
            report[@"kernelWritePrimitiveInvocationCount"] =
                @(primitiveInvocations);
            CNDHailMarySpecialDispatchFinish(
                report, YES, completion);
            return;
        }
        report[@"writes"] = writes;
        report[@"kernelWritePrimitiveInvocationCount"] =
            @(primitiveInvocations);
        report[@"postWriteTranslation"] = @{
            @"stable": @YES,
            @"translations": translations,
        };
        report[@"readback"] = @{
            @"exactDesiredGuard": @YES,
            @"exactOfflineGuard": @YES,
            @"identicalToBefore": @YES,
        };
        report[@"stage"] =
            @"identical-dispatch-writes-confirmed";
        report[@"confirmed"] = @YES;
        report[@"result"] =
            @"special-dispatch-probe-confirmed";
        report[@"message"] =
            @"Both pinned .34 dispatch-entry guards accepted an identical low-word aperture write and retained stable translations. This report is the same-boot permission ticket.";
        CNDHailMarySpecialDispatchFinish(
            report, YES, completion);
    });
}

void CNDHailMarySpecialIconClassDispatchPermissionRun(
    CNDHailMarySpecialIconClassDispatchCompletion completion)
{
    CNDHailMarySpecialIconClassDispatchPermissionRunWithMode(
        CNDHailMaryProofModeSharedPair, completion);
}

void CNDHailMarySpecialIconClassDispatchRedirectRunWithMode(
    CNDHailMaryProofMode mode,
    CNDHailMarySpecialIconClassDispatchOperation operation,
    CNDHailMarySpecialIconClassDispatchCompletion completion)
{
    if (!completion) return;
    if (!__sync_bool_compare_and_swap(
            &gCNDHailMarySpecialClassDispatchRedirectRunning, 0, 1)) {
        completion(@{
            @"confirmed": @NO,
            @"result": @"special-dispatch-operation-already-running",
            @"message": @"A special dispatch operation is already running.",
        });
        return;
    }
    if (CNDHailMarySpecialDispatchOtherExperimentRunning(YES)) {
        NSMutableDictionary *report =
            CNDHailMarySpecialDispatchBaseReport(
                CNDHailMarySpecialDispatchReportPath());
        report[@"operation"] =
            CNDHailMarySpecialDispatchOperationName(operation);
        report[@"result"] =
            @"special-dispatch-operation-another-experiment-running";
        report[@"message"] =
            @"Another Hail Mary experiment is running. No read or write was attempted.";
        CNDHailMarySpecialDispatchFinish(report, NO, completion);
        return;
    }

    NSDictionary *ticket =
        CNDHailMarySpecialDispatchIsMutation(operation)
            ? CNDHailMarySpecialDispatchReadPermission() : nil;
    CNDHailMaryProbeRunWithMode(mode,
        ^(NSDictionary<NSString *, id> *probeReport) {
        NSMutableDictionary *report =
            CNDHailMarySpecialDispatchBaseReport(
                CNDHailMarySpecialDispatchReportPath());
        report[@"operation"] =
            CNDHailMarySpecialDispatchOperationName(operation);
        report[@"preflightProbe"] = probeReport ?: @{};
        uint64_t slide = 0;
        NSString *error = nil;
        if (!CNDHailMarySpecialClassSlideFromProbe(
                probeReport, &slide, &error)) {
            report[@"result"] =
                @"special-dispatch-operation-proof-failed";
            report[@"message"] = error ?:
                @"The shared Hail Mary proof did not confirm this boot.";
            CNDHailMarySpecialDispatchFinish(
                report, NO, completion);
            return;
        }
        report[@"slide"] = CNDHailMarySpecialClassHex(slide);
        NSArray *resolved = CNDHailMarySpecialDispatchResolveAll(
            probeReport, slide, &error);
        if (!resolved) {
            report[@"result"] =
                @"special-dispatch-operation-translation-failed";
            report[@"message"] = error ?:
                @"The two .34 dispatch entries did not resolve through both live pmaps.";
            CNDHailMarySpecialDispatchFinish(
                report, NO, completion);
            return;
        }
        report[@"targets"] = resolved;

        BOOL expectRedirected =
            operation ==
                CNDHailMarySpecialIconClassDispatchOperationRestore ||
            operation ==
                CNDHailMarySpecialIconClassDispatchOperationVerifyRedirected;
        NSString *requiredState =
            expectRedirected ? @"redirected" : @"original";
        BOOL stateMatches =
            CNDHailMarySpecialDispatchAllInState(
                resolved, requiredState);
        if (!CNDHailMarySpecialDispatchIsMutation(operation)) {
            report[@"state"] = stateMatches
                ? requiredState : @"mixed-or-unexpected";
            report[@"confirmed"] = @(stateMatches);
            report[@"readback"] = @{
                @"exactDesiredGuard": @(stateMatches),
                @"exactOfflineGuard": @(stateMatches),
            };
            report[@"postWriteTranslation"] =
                @{@"stable": @YES};
            report[@"result"] = stateMatches
                ? (expectRedirected
                    ? @"special-dispatch-verify-redirected-confirmed"
                    : @"special-dispatch-verify-original-confirmed")
                : (expectRedirected
                    ? @"special-dispatch-verify-redirected-mismatch"
                    : @"special-dispatch-verify-original-mismatch");
            report[@"message"] = stateMatches
                ? (expectRedirected
                    ? @"Both shared .34 entries redirect class selection to the ordinary application icon path."
                    : @"Both shared .34 entries contain their original special-class helper dispatch.")
                : @"The two dispatch entries do not match the requested state. No write was attempted.";
            CNDHailMarySpecialDispatchFinish(
                report, NO, completion);
            return;
        }

        if (!CNDHailMarySpecialDispatchPermissionMatches(
                ticket, slide, resolved, &error)) {
            report[@"result"] =
                @"special-dispatch-operation-permission-required";
            report[@"message"] = error ?:
                @"A matching same-boot dispatch permission ticket is required.";
            CNDHailMarySpecialDispatchFinish(
                report, NO, completion);
            return;
        }
        if (!stateMatches) {
            report[@"result"] = expectRedirected
                ? @"special-dispatch-restore-redirected-state-required"
                : @"special-dispatch-apply-original-state-required";
            report[@"message"] =
                @"Both entries must be in the exact required state; mixed, unexpected, or already-transitioned state is refused.";
            CNDHailMarySpecialDispatchFinish(
                report, NO, completion);
            return;
        }

        BOOL apply = operation ==
            CNDHailMarySpecialIconClassDispatchOperationApply;
        NSMutableArray *writes = [NSMutableArray array];
        for (NSDictionary *one in resolved) {
            NSString *desiredGuardHex = apply
                ? one[@"redirectedGuardHex"]
                : one[@"originalGuardHex"];
            NSData *desiredGuard =
                CNDHailMarySpecialDispatchDataFromHex(
                    desiredGuardHex);
            uint32_t desiredLowWord = 0;
            if (desiredGuard.length !=
                    kCNDHailMarySpecialDispatchGuardLength) {
                report[@"result"] =
                    @"special-dispatch-desired-guard-invalid";
                report[@"message"] =
                    @"A compiled desired guard is invalid. No write was attempted.";
                CNDHailMarySpecialDispatchFinish(
                    report, NO, completion);
                return;
            }
            memcpy(&desiredLowWord,
                   desiredGuard.bytes,
                   sizeof(desiredLowWord));
            [writes addObject:@{
                @"className": one[@"className"] ?: @"",
                @"entryRuntime": one[@"entryRuntime"] ?: @"",
                @"windowKernelVirtualAddress":
                    one[@"windowKernelVirtualAddress"] ?: @"",
                @"inverseGuardHex": apply
                    ? one[@"originalGuardHex"]
                    : one[@"redirectedGuardHex"],
                @"desiredGuardHex": desiredGuardHex,
                @"desiredLowWord":
                    [NSString stringWithFormat:@"0x%08x",
                        desiredLowWord],
                @"dispatchReturned": @NO,
            }];
        }
        report[@"stage"] = apply
            ? @"armed-dispatch-apply"
            : @"armed-dispatch-restore";
        report[@"writes"] = writes;
        report[@"inverseState"] = apply
            ? @"run dispatch Restore to recover both original entries"
            : @"run dispatch Apply to restore both redirects";
        NSString *journalError = nil;
        if (!CNDHailMarySpecialClassSaveDurably(
                report, report[@"reportPath"], &journalError)) {
            report[@"result"] =
                @"special-dispatch-operation-journal-failed";
            report[@"message"] = journalError ?:
                @"The armed inverse journal could not be saved. No write was attempted.";
            CNDHailMarySpecialDispatchFinish(
                report, NO, completion);
            return;
        }

        uint64_t primitiveInvocations = 0;
        for (NSUInteger index = 0;
             index < resolved.count;
             index++) {
            NSDictionary *one = resolved[index];
            NSMutableDictionary *write =
                [writes[index] mutableCopy];
            uint64_t windowKVA = 0;
            NSData *desiredGuard =
                CNDHailMarySpecialDispatchDataFromHex(
                    write[@"desiredGuardHex"]);
            uint32_t desiredLowWord = 0;
            if (!CNDHailMarySpecialClassParseHex(
                    write[@"windowKernelVirtualAddress"], &windowKVA) ||
                desiredGuard.length !=
                    kCNDHailMarySpecialDispatchGuardLength) {
                report[@"result"] =
                    @"special-dispatch-write-target-invalid";
                report[@"message"] =
                    @"An armed write target could not be decoded. No further write was attempted.";
                report[@"kernelWritePrimitiveInvocationCount"] =
                    @(primitiveInvocations);
                CNDHailMarySpecialDispatchFinish(
                    report, NO, completion);
                return;
            }
            memcpy(&desiredLowWord,
                   desiredGuard.bytes,
                   sizeof(desiredLowWord));
            kwrite32(windowKVA, desiredLowWord);
            primitiveInvocations++;
            uint8_t bytes[kCNDHailMarySpecialDispatchGuardLength] = {0};
            kreadbuf(windowKVA, bytes, sizeof(bytes));
            NSData *readback =
                [NSData dataWithBytes:bytes length:sizeof(bytes)];
            if (![readback isEqual:desiredGuard]) {
                report[@"result"] =
                    @"special-dispatch-postwrite-guard-mismatch";
                report[@"message"] = [NSString stringWithFormat:
                    @"The %@ low-word write returned, but the exact desired 32-byte guard did not read back. No automatic rollback was attempted.",
                    one[@"className"] ?: @"dispatch-entry"];
                report[@"kernelWritePrimitiveInvocationCount"] =
                    @(primitiveInvocations);
                CNDHailMarySpecialDispatchFinish(
                    report, NO, completion);
                return;
            }
            write[@"dispatchReturned"] = @YES;
            write[@"readbackGuardHex"] =
                CNDHailMarySpecialDispatchHexForData(readback);
            writes[index] = write;
        }

        NSArray *translations =
            CNDHailMarySpecialDispatchTranslateAgain(
                probeReport, resolved);
        if (!translations) {
            report[@"result"] =
                @"special-dispatch-post-translation-changed";
            report[@"message"] =
                @"Both low-word writes returned and read back, but a translation changed. No automatic rollback was attempted.";
            report[@"kernelWritePrimitiveInvocationCount"] =
                @(primitiveInvocations);
            CNDHailMarySpecialDispatchFinish(
                report, NO, completion);
            return;
        }
        report[@"writes"] = writes;
        report[@"postWriteTranslation"] = @{
            @"stable": @YES,
            @"translations": translations,
        };
        report[@"readback"] = @{
            @"exactDesiredGuard": @YES,
            @"exactOfflineGuard": @YES,
            @"exactOriginal": @(!apply),
            @"exactRedirected": @(apply),
        };
        report[@"kernelWritePrimitiveInvocationCount"] =
            @(primitiveInvocations);
        report[@"dispatchEntrySemanticMutationCount"] =
            @(primitiveInvocations);
        report[@"consumerRebuildRequired"] = @YES;
        report[@"mutationConfirmed"] = @YES;
        report[@"confirmed"] = @YES;
        report[@"stage"] = apply
            ? @"dispatch-applied" : @"dispatch-restored";
        report[@"result"] = apply
            ? @"special-dispatch-apply-confirmed"
            : @"special-dispatch-restore-confirmed";
        report[@"message"] = apply
            ? @"Both shared .34 preoptimized-cache entries now dispatch to +[SBHIconModel applicationIconClass]. Archived Clock/Calendar canonical objects survive a respring, so run the bounded Static Clock + Calendar Object Rebuild to replace exactly those objects in SpringBoard and Spotlight while preserving SpringBoard positions."
            : @"Both shared .34 preoptimized-cache entries contain their original dispatch words. Run the bounded Live Clock + Calendar Object Rebuild to replace the archived ordinary objects with Apple's live subclasses. No automatic restart was performed.";
        CNDHailMarySpecialDispatchFinish(
            report, NO, completion);
    });
}

void CNDHailMarySpecialIconClassDispatchRedirectRun(
    CNDHailMarySpecialIconClassDispatchOperation operation,
    CNDHailMarySpecialIconClassDispatchCompletion completion)
{
    CNDHailMarySpecialIconClassDispatchRedirectRunWithMode(
        CNDHailMaryProofModeSharedPair, operation, completion);
}
