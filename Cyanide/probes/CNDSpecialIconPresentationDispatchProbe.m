//
//  CNDSpecialIconPresentationDispatchProbe.m
//  Cyanide
//
//  Exact shared-cache presentation dispatch probes for existing special
//  Clock/Calendar icon objects, SpringBoard's switcher title icons, and the
//  App Library category miniature flat-image policy. This uses SpringBoard's
//  current mapping only; Spotlight is neither a prerequisite nor a mutation
//  target.
//

#import "CNDSpecialIconPresentationDispatchProbe.h"

#import "CNDHailMaryDataPage.h"
#import "CNDHailMaryImpRedirect.h"
#import "CNDHailMaryPageWire.h"
#import "CNDHailMaryPatch.h"
#import "CNDHailMaryProbe.h"
#import "CNDHailMaryReadOnlyDataPage.h"
#import "CNDHailMarySpecialIconClassDispatchRedirect.h"
#import "CNDHailMarySpecialIconClassRedirect.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/krw.h"

#import <CommonCrypto/CommonDigest.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define CND_SPECIAL_PRESENTATION_BUILD "23A341"
#define CND_SPECIAL_PRESENTATION_PRODUCT "iPhone17,2"
#define CND_SPECIAL_PRESENTATION_MAIN_CACHE_UUID \
    "DC5F2F67-1FC8-3905-873B-35D17D1A44E8"
#define CND_SPECIAL_PRESENTATION_READONLY_UUID \
    "CEEB0D68-9BA9-3CC8-AEB1-8F23BAC92B58"
#define CND_SPECIAL_PRESENTATION_PERMISSION_EXPERIMENT \
    "special-icon-presentation-dispatch-permission"
#define CND_SWITCHER_PRESENTATION_PERMISSION_EXPERIMENT \
    "switcher-presentation-dispatch-permission"
#define CND_APP_LIBRARY_MINIATURE_PRESENTATION_PERMISSION_EXPERIMENT \
    "app-library-miniature-presentation-dispatch-permission"

enum {
    kCNDSpecialPresentationGuardLength = 32,
};

_Static_assert(EARLY_KRW_LENGTH == kCNDSpecialPresentationGuardLength,
    "presentation guard must match the checked KRW transfer width");

static const uint64_t kCNDSpecialPresentationPageSize = UINT64_C(0x4000);
static const uint64_t kCNDSpecialPresentationMaximumSlide =
    UINT64_C(0x40000000);
static const uint64_t kCNDSpecialPresentationSharedRegionBase =
    UINT64_C(0x180000000);
static const uint64_t kCNDSpecialPresentationReadonlyCacheVMOffset =
    UINT64_C(0x78354000);
static const uint32_t kCNDSpecialPresentationSubcacheArrayOffset =
    UINT32_C(0x41818);
static const uint32_t kCNDSpecialPresentationSubcacheCount = UINT32_C(77);
static const uint32_t kCNDSpecialPresentationReadonlySubcacheIndex =
    UINT32_C(33);

enum {
    kCNDSpecialPresentationCacheHeaderLength = 0x1d8,
    kCNDSpecialPresentationCacheUUIDOffset = 0x58,
    kCNDSpecialPresentationSharedRegionStartOffset = 0xe0,
    kCNDSpecialPresentationOSVersionOffset = 0x16c,
    kCNDSpecialPresentationSubcacheArrayOffsetField = 0x188,
    kCNDSpecialPresentationSubcacheCountField = 0x18c,
    kCNDSpecialPresentationSubcacheEntrySize = 56,
    kCNDSpecialPresentationSubcacheSuffixOffset = 24,
    kCNDSpecialPresentationSubcacheSuffixLength = 32,
};

static const uint8_t kCNDSpecialPresentationCacheMagic[16] = {
    'd', 'y', 'l', 'd', '_', 'v', '1', ' ', ' ',
    'a', 'r', 'm', '6', '4', 'e', 0,
};
static const uint8_t kCNDSpecialPresentationMainCacheUUID[16] = {
    0xdc, 0x5f, 0x2f, 0x67, 0x1f, 0xc8, 0x39, 0x05,
    0x87, 0x3b, 0x35, 0xd1, 0x7d, 0x1a, 0x44, 0xe8,
};
static const uint8_t kCNDSpecialPresentationReadonlyCacheUUID[16] = {
    0xce, 0xeb, 0x0d, 0x68, 0x9b, 0xa9, 0x3c, 0xc8,
    0xae, 0xb1, 0x8f, 0x23, 0xba, 0xc9, 0x2b, 0x58,
};

static volatile int gCNDSpecialPresentationPermissionRunning;
static volatile int gCNDSpecialPresentationRedirectRunning;

static NSString *CNDSpecialPresentationHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static BOOL CNDSpecialPresentationParseHex(
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

static NSData *CNDSpecialPresentationDataFromHex(NSString *text)
{
    if (![text isKindOfClass:NSString.class] || (text.length & 1) != 0) {
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

static NSString *CNDSpecialPresentationHexForData(NSData *data)
{
    const uint8_t *bytes = data.bytes;
    NSMutableString *text = [NSMutableString stringWithCapacity:
        data.length * 2];
    for (NSUInteger index = 0; index < data.length; index++) {
        [text appendFormat:@"%02x", bytes[index]];
    }
    return text;
}

static NSString *CNDSpecialPresentationSHA256(NSData *data)
{
    uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    return CNDSpecialPresentationHexForData(
        [NSData dataWithBytes:digest length:sizeof(digest)]);
}

static BOOL CNDSpecialPresentationCheckedWriteGuard(
    uint64_t address, NSData *guard)
{
    if (guard.length != EARLY_KRW_LENGTH) return NO;
    uint8_t bytes[EARLY_KRW_LENGTH] = {0};
    memcpy(bytes, guard.bytes, sizeof(bytes));
    return kexploit_early_kwrite32bytes_checked(address, bytes);
}

static NSString *CNDSpecialPresentationDocumentsPath(NSString *name)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    return [directory stringByAppendingPathComponent:name];
}

static NSString *CNDSpecialPresentationPermissionPath(void)
{
    return CNDSpecialPresentationDocumentsPath(
        @"CNDSpecialIconPresentationDispatchPermission.json");
}

static NSString *CNDSwitcherPresentationPermissionPath(void)
{
    return CNDSpecialPresentationDocumentsPath(
        @"CNDSwitcherPresentationDispatchPermission.json");
}

static NSString *CNDAppLibraryMiniaturePresentationPermissionPath(void)
{
    return CNDSpecialPresentationDocumentsPath(
        @"CNDAppLibraryMiniaturePresentationDispatchPermission.json");
}

static NSString *CNDSpecialPresentationReportPath(
    CNDSpecialIconPresentationRoute route)
{
    NSString *name = nil;
    switch (route) {
        case CNDSpecialIconPresentationRouteClock:
            name = @"CNDClockStaticPresentationDispatch.json";
            break;
        case CNDSpecialIconPresentationRouteCalendar:
            name = @"CNDCalendarStaticPresentationDispatch.json";
            break;
        case CNDSpecialIconPresentationRouteSwitcher:
            name = @"CNDSwitcherStaticPresentationDispatch.json";
            break;
        case CNDSpecialIconPresentationRouteAppLibraryMiniatures:
            name = @"CNDAppLibraryMiniaturePresentationDispatch.json";
            break;
    }
    return CNDSpecialPresentationDocumentsPath(name ?: @"invalid.json");
}

static BOOL CNDSpecialPresentationSyncDescriptor(int descriptor)
{
    if (descriptor < 0) return NO;
#ifdef F_FULLFSYNC
    if (fcntl(descriptor, F_FULLFSYNC) == 0) return YES;
#endif
    return fsync(descriptor) == 0;
}

static BOOL CNDSpecialPresentationSaveDurably(
    NSDictionary<NSString *, id> *report,
    NSString *path,
    NSString **errorOut)
{
    if (errorOut) *errorOut = nil;
    if (!report || path.length == 0) {
        if (errorOut) *errorOut = @"journal-path-invalid";
        return NO;
    }
    NSError *serializationError = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:&serializationError];
    if (!data) {
        if (errorOut) {
            *errorOut = [NSString stringWithFormat:
                @"journal-serialization-failed:%@",
                serializationError.localizedDescription ?: @"unknown"];
        }
        return NO;
    }
    NSError *writeError = nil;
    if (![data writeToFile:path options:NSDataWritingAtomic error:&writeError]) {
        if (errorOut) {
            *errorOut = [NSString stringWithFormat:
                @"journal-atomic-write-failed:%@",
                writeError.localizedDescription ?: @"unknown"];
        }
        return NO;
    }
    int descriptor = open(path.fileSystemRepresentation,
                          O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-open-failed:%d", errno];
        return NO;
    }
    BOOL fileSynced = CNDSpecialPresentationSyncDescriptor(descriptor);
    int fileError = fileSynced ? 0 : errno;
    close(descriptor);
    if (!fileSynced) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-file-sync-failed:%d", fileError];
        return NO;
    }
    NSString *directory = path.stringByDeletingLastPathComponent;
    descriptor = open(directory.fileSystemRepresentation,
                      O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-directory-open-failed:%d", errno];
        return NO;
    }
    BOOL directorySynced = fsync(descriptor) == 0;
    int directoryError = directorySynced ? 0 : errno;
    close(descriptor);
    if (!directorySynced) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-directory-sync-failed:%d", directoryError];
        return NO;
    }
    return YES;
}

static NSString *CNDSpecialPresentationRouteName(
    CNDSpecialIconPresentationRoute route)
{
    switch (route) {
        case CNDSpecialIconPresentationRouteClock:
            return @"clock";
        case CNDSpecialIconPresentationRouteCalendar:
            return @"calendar";
        case CNDSpecialIconPresentationRouteSwitcher:
            return @"switcher";
        case CNDSpecialIconPresentationRouteAppLibraryMiniatures:
            return @"app-library-miniatures";
    }
    return @"invalid";
}

static NSString *CNDSpecialPresentationOperationName(
    CNDSpecialIconPresentationOperation operation)
{
    switch (operation) {
        case CNDSpecialIconPresentationOperationApply:
            return @"apply";
        case CNDSpecialIconPresentationOperationRestore:
            return @"restore";
        case CNDSpecialIconPresentationOperationVerifyRedirected:
            return @"verify-redirected";
        case CNDSpecialIconPresentationOperationVerifyOriginal:
            return @"verify-original";
    }
    return @"unknown";
}

static BOOL CNDSpecialPresentationIsMutation(
    CNDSpecialIconPresentationOperation operation)
{
    return operation == CNDSpecialIconPresentationOperationApply ||
        operation == CNDSpecialIconPresentationOperationRestore;
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDSpecialPresentationAllTargets(void)
{
    return @[
        @{
            @"route": @"clock",
            @"name": @"clock-view-class",
            @"className": @"SBHClockApplicationIcon",
            @"selector": @"iconImageViewClassForLocation:",
            @"replacementClass": @"SBIcon",
            @"replacementSelector": @"iconImageViewClassForLocation:",
            @"entryUnslid": @(UINT64_C(0x1ffc00120)),
            @"entryFileOffset": @(UINT64_C(0x78ac120)),
            @"frameUnslid": @(UINT64_C(0x1ffc00000)),
            @"originalWord": @(UINT64_C(0x390460000bebb2ba)),
            @"redirectedWord": @(UINT64_C(0x390460000be5e55a)),
            @"originalGuardHex":
                @"bab2eb0b0060043900000000c0ffffff"
                 "00000000c0ffffff346be80b00c56401",
            @"redirectedGuardHex":
                @"5ae5e50b0060043900000000c0ffffff"
                 "00000000c0ffffff346be80b00c56401",
        },
        @{
            @"route": @"calendar",
            @"name": @"calendar-bundle-identifier",
            @"className": @"SBHCalendarApplicationIcon",
            @"selector": @"applicationBundleIdentifierForImage",
            @"replacementClass": @"SBLeafIcon",
            @"replacementSelector":
                @"applicationBundleIdentifierForImage",
            @"entryUnslid": @(UINT64_C(0x1ffc18618)),
            @"entryFileOffset": @(UINT64_C(0x78c4618)),
            @"frameUnslid": @(UINT64_C(0x1ffc18000)),
            @"originalWord": @(UINT64_C(0x05468a400be6f610)),
            @"redirectedWord": @(UINT64_C(0x05468a400bed1984)),
            @"originalGuardHex":
                @"10f6e60b408a4605fa63ec0b00a0e611"
                 "926be80b00c73615b56ae80b40e9ae2d",
            @"redirectedGuardHex":
                @"8419ed0b408a4605fa63ec0b00a0e611"
                 "926be80b00c73615b56ae80b40e9ae2d",
        },
        @{
            @"route": @"calendar",
            @"name": @"calendar-image",
            @"className": @"SBHCalendarApplicationIcon",
            @"selector":
                @"makeIconImageWithInfo:traitCollection:context:options:",
            @"replacementClass": @"SBLeafIcon",
            @"replacementSelector":
                @"makeIconImageWithInfo:traitCollection:context:options:",
            @"entryUnslid": @(UINT64_C(0x1ffc18590)),
            @"entryFileOffset": @(UINT64_C(0x78c4590)),
            @"frameUnslid": @(UINT64_C(0x1ffc18000)),
            @"originalWord": @(UINT64_C(0x290460000be6f60e)),
            @"redirectedWord": @(UINT64_C(0x290460000be6b924)),
            @"originalGuardHex":
                @"0ef6e60b0060042900000000c0ffffff"
                 "3ef6e60b00a0543a2e6ce80b00c56401",
            @"redirectedGuardHex":
                @"24b9e60b0060042900000000c0ffffff"
                 "3ef6e60b00a0543a2e6ce80b00c56401",
        },
        @{
            @"route": @"calendar",
            @"name": @"calendar-layer",
            @"className": @"SBHCalendarApplicationIcon",
            @"selector":
                @"makeIconLayerWithInfo:traitCollection:context:options:",
            @"replacementClass": @"SBLeafIcon",
            @"replacementSelector":
                @"makeIconLayerWithInfo:traitCollection:context:options:",
            @"entryUnslid": @(UINT64_C(0x1ffc18658)),
            @"entryFileOffset": @(UINT64_C(0x78c4658)),
            @"frameUnslid": @(UINT64_C(0x1ffc18000)),
            @"originalWord": @(UINT64_C(0x079f90800be6f5e5)),
            @"redirectedWord": @(UINT64_C(0x079f90800be6b804)),
            @"originalGuardHex":
                @"e5f5e60b80909f07936be80b00a06724"
                 "ba6ae80b80cf0720666be80bc0e9d710",
            @"redirectedGuardHex":
                @"04b8e60b80909f07936be80b00a06724"
                 "ba6ae80b80cf0720666be80bc0e9d710",
        },
    ];
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDSwitcherPresentationTargets(void)
{
    return @[
        @{
            @"route": @"switcher",
            @"name": @"switcher-flat-image-storage",
            @"className": @"SBFluidSwitcherSpaceTitleItem",
            @"selector": @"setImageView:",
            @"replacementClass": @"SBFluidSwitcherSpaceTitleItem",
            @"replacementSelector": @"setImage:",
            @"entryUnslid": @(UINT64_C(0x1ffd55c98)),
            @"entryFileOffset": @(UINT64_C(0x7a01c98)),
            @"frameUnslid": @(UINT64_C(0x1ffd54000)),
            @"originalWord": @(UINT64_C(0x1622200018f3969f)),
            @"redirectedWord": @(UINT64_C(0x1622200018f396a4)),
            @"originalGuardHex":
                @"9f96f31800202216c6c4fd1880276316"
                 "55c4fd18401004029c96f31880096528",
            @"redirectedGuardHex":
                @"a496f31800202216c6c4fd1880276316"
                 "55c4fd18401004029c96f31880096528",
        },
        @{
            @"route": @"switcher",
            @"name": @"switcher-flat-image-provider",
            @"className": @"SBFluidSwitcherSpaceTitleItemController",
            @"selector": @"_iconViewForDisplayItem:",
            @"replacementClass":
                @"SBFluidSwitcherSpaceTitleItemController",
            @"replacementSelector": @"_iconImageForDisplayItem:",
            @"entryUnslid": @(UINT64_C(0x1ffd8b488)),
            @"entryFileOffset": @(UINT64_C(0x7a37488)),
            @"frameUnslid": @(UINT64_C(0x1ffd88000)),
            @"originalWord": @(UINT64_C(0x1a81d10018daa06b)),
            @"redirectedWord": @(UINT64_C(0x1a81d10018daa0ad)),
            @"originalGuardHex":
                @"6ba0da1800d1811a7da1da184027f002"
                 "eba1da1800fc012bf3a0da1880cb412b",
            @"redirectedGuardHex":
                @"ada0da1800d1811a7da1da184027f002"
                 "eba1da1800fc012bf3a0da1880cb412b",
        },
    ];
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDAppLibraryMiniaturePresentationTargets(void)
{
    return @[
        @{
            @"route": @"app-library-miniatures",
            @"name": @"app-library-miniature-flat-image-policy",
            @"className": @"SBHIconManager",
            @"selector": @"prefersFlatImageLayers",
            @"types": @"B16@0:8",
            @"originalIMPUnslid": @(UINT64_C(0x1be0f1cd0)),
            @"replacementClass": @"SBIconImageView",
            @"replacementSelector": @"hasOpaqueImage",
            @"replacementIMPUnslid": @(UINT64_C(0x1be1052a0)),
            @"entryUnslid": @(UINT64_C(0x1ffc24f78)),
            @"entryFileOffset": @(UINT64_C(0x78d0f78)),
            @"frameUnslid": @(UINT64_C(0x1ffc24000)),
            @"originalWord": @(UINT64_C(0x1fe320000be44244)),
            @"redirectedWord": @(UINT64_C(0x1fe320000be3f4d0)),
            @"originalGuardHex":
                @"4442e40b0020e31f3562e40b0040e31e"
                 "1385e40b0080e31c43d4e40b00c0e31e",
            @"redirectedGuardHex":
                @"d0f4e30b0020e31f3562e40b0040e31e"
                 "1385e40b0080e31c43d4e40b00c0e31e",
            @"originalBehavior": @"manager-stored-flat-image-policy",
            @"redirectedBehavior":
                @"constant-true-app-library-flat-image-policy",
        },
    ];
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDSpecialPresentationTargetsForRoute(
    CNDSpecialIconPresentationRoute route)
{
    if (route == CNDSpecialIconPresentationRouteSwitcher) {
        return CNDSwitcherPresentationTargets();
    }
    if (route == CNDSpecialIconPresentationRouteAppLibraryMiniatures) {
        return CNDAppLibraryMiniaturePresentationTargets();
    }
    NSString *routeName = CNDSpecialPresentationRouteName(route);
    NSPredicate *predicate = [NSPredicate predicateWithBlock:
        ^BOOL(NSDictionary<NSString *, id> *target,
              NSDictionary<NSString *, id> *bindings) {
            (void)bindings;
            return [target[@"route"] isEqual:routeName];
        }];
    return [CNDSpecialPresentationAllTargets()
        filteredArrayUsingPredicate:predicate];
}

static NSMutableDictionary<NSString *, id> *
CNDSpecialPresentationBaseReport(
    NSString *experiment, NSString *reportPath)
{
    return [@{
        @"schemaVersion": @1,
        @"evidenceClass": @"Implemented",
        @"appearanceEvidenceClass": @"not-run",
        @"claimScope":
            @"bounded exact-entry dispatch state only; not icon appearance",
        @"experiment": experiment ?: @"",
        @"build": @CND_SPECIAL_PRESENTATION_BUILD,
        @"product": @CND_SPECIAL_PRESENTATION_PRODUCT,
        @"mainCacheUUID": @CND_SPECIAL_PRESENTATION_MAIN_CACHE_UUID,
        @"readonlySubcacheUUID": @CND_SPECIAL_PRESENTATION_READONLY_UUID,
        @"proofMode": @"springboard-only",
        @"krwLifecyclePolicy": @"shared-tweak-lifecycle",
        @"callerPID": @(getpid()),
        @"startedAtUnixTime": @([[NSDate date] timeIntervalSince1970]),
        @"reportPath": reportPath ?: @"",
        @"processInjectionCount": @0,
        @"remoteCallCount": @0,
        @"iconObjectMutationCount": @0,
        @"homeVisibilityPrecondition": @NO,
        @"kernelWritePrimitiveInvocationCount": @0,
        @"dispatchEntrySemanticMutationCount": @0,
        @"rollbackWritePrimitiveInvocationCount": @0,
    } mutableCopy];
}

static void CNDSpecialPresentationFinish(
    NSMutableDictionary<NSString *, id> *report,
    BOOL permission,
    CNDSpecialIconPresentationDispatchCompletion completion)
{
    report[@"finishedAtUnixTime"] =
        @([[NSDate date] timeIntervalSince1970]);
    NSString *error = nil;
    if (!CNDSpecialPresentationSaveDurably(
            report, report[@"reportPath"], &error)) {
        report[@"finalReportPersistenceError"] = error ?:
            @"final-report-durable-save-failed";
    }
    NSDictionary<NSString *, id> *finished = [report copy];
    volatile int *running = permission
        ? &gCNDSpecialPresentationPermissionRunning
        : &gCNDSpecialPresentationRedirectRunning;
    __sync_lock_release(running);
    dispatch_async(dispatch_get_main_queue(), ^{
        completion(finished);
    });
}

static BOOL CNDSpecialPresentationOtherExperimentRunning(
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
        CNDHailMarySpecialIconClassDispatchPermissionIsRunning() ||
        CNDHailMarySpecialIconClassDispatchRedirectIsRunning() ||
        (includePermission &&
            CNDSpecialIconPresentationDispatchPermissionIsRunning());
}

static NSData *CNDSpecialPresentationReadPhysicalWindow(
    NSDictionary<NSString *, id> *probeReport,
    uint64_t runtimeAddress,
    NSUInteger length,
    NSDictionary<NSString *, id> **evidenceOut,
    NSString **errorOut)
{
    if (evidenceOut) *evidenceOut = nil;
    if (errorOut) *errorOut = nil;
    if (runtimeAddress == 0 || length == 0 ||
        length > kCNDSpecialPresentationPageSize) {
        if (errorOut) *errorOut = @"runtime-cache-window-invalid";
        return nil;
    }
    NSDictionary<NSString *, id> *translation = nil;
    uint64_t physicalFrame = 0;
    uint64_t physicalAddress = 0;
    uint64_t frameKVA = 0;
    if (!CNDHailMaryProbeTranslateRuntimeAddressInProcessWithPhysical(
            probeReport, @"SpringBoard", runtimeAddress, &translation,
            &physicalFrame, &physicalAddress, &frameKVA, errorOut)) {
        return nil;
    }
    if (physicalAddress < physicalFrame) {
        if (errorOut) *errorOut = @"runtime-cache-window-before-frame";
        return nil;
    }
    uint64_t frameOffset = physicalAddress - physicalFrame;
    if (frameOffset > kCNDSpecialPresentationPageSize ||
        length > kCNDSpecialPresentationPageSize - frameOffset) {
        if (errorOut) *errorOut = @"runtime-cache-window-crosses-frame";
        return nil;
    }
    uint64_t windowKVA = frameKVA + frameOffset;
    NSMutableData *bytes = [NSMutableData dataWithLength:length];
    kreadbuf(windowKVA, bytes.mutableBytes, length);

    NSDictionary<NSString *, id> *postReadTranslation = nil;
    uint64_t postReadFrame = 0;
    uint64_t postReadAddress = 0;
    uint64_t postReadFrameKVA = 0;
    NSString *postReadError = nil;
    if (!CNDHailMaryProbeTranslateRuntimeAddressInProcessWithPhysical(
            probeReport, @"SpringBoard", runtimeAddress,
            &postReadTranslation, &postReadFrame, &postReadAddress,
            &postReadFrameKVA, &postReadError) ||
        postReadFrame != physicalFrame ||
        postReadAddress != physicalAddress ||
        postReadFrameKVA != frameKVA) {
        if (errorOut) {
            *errorOut = postReadError ?:
                @"runtime-cache-window-translation-changed";
        }
        return nil;
    }
    NSData *result = [bytes copy];
    if (evidenceOut) {
        *evidenceOut = @{
            @"runtimeAddress": CNDSpecialPresentationHex(runtimeAddress),
            @"byteLength": @(length),
            @"sha256": CNDSpecialPresentationSHA256(result),
            @"physicalFrame": CNDSpecialPresentationHex(physicalFrame),
            @"physicalAddress": CNDSpecialPresentationHex(physicalAddress),
            @"frameKernelVirtualAddress":
                CNDSpecialPresentationHex(frameKVA),
            @"windowKernelVirtualAddress":
                CNDSpecialPresentationHex(windowKVA),
            @"translation": translation ?: @{},
            @"postReadTranslation": postReadTranslation ?: @{},
            @"translationStable": @YES,
        };
    }
    return result;
}

static BOOL CNDSpecialPresentationVerifyRuntimeCacheIdentity(
    NSDictionary<NSString *, id> *probeReport,
    uint64_t slide,
    NSDictionary<NSString *, id> **identityOut,
    NSString **errorOut)
{
    if (identityOut) *identityOut = nil;
    if (errorOut) *errorOut = nil;
    if (slide > UINT64_MAX - kCNDSpecialPresentationSharedRegionBase) {
        if (errorOut) *errorOut = @"runtime-cache-header-overflow";
        return NO;
    }
    uint64_t mainRuntime =
        kCNDSpecialPresentationSharedRegionBase + slide;
    NSDictionary<NSString *, id> *mainRead = nil;
    NSData *mainHeader = CNDSpecialPresentationReadPhysicalWindow(
        probeReport, mainRuntime,
        kCNDSpecialPresentationCacheHeaderLength,
        &mainRead, errorOut);
    if (mainHeader.length !=
        kCNDSpecialPresentationCacheHeaderLength) {
        if (errorOut && !*errorOut) {
            *errorOut = @"runtime-main-cache-header-read-failed";
        }
        return NO;
    }
    const uint8_t *mainBytes = mainHeader.bytes;
    uint64_t sharedRegionStart = 0;
    uint32_t osVersion = 0;
    uint32_t subcacheOffset = 0;
    uint32_t subcacheCount = 0;
    memcpy(&sharedRegionStart,
        mainBytes + kCNDSpecialPresentationSharedRegionStartOffset,
        sizeof(sharedRegionStart));
    memcpy(&osVersion,
        mainBytes + kCNDSpecialPresentationOSVersionOffset,
        sizeof(osVersion));
    memcpy(&subcacheOffset,
        mainBytes + kCNDSpecialPresentationSubcacheArrayOffsetField,
        sizeof(subcacheOffset));
    memcpy(&subcacheCount,
        mainBytes + kCNDSpecialPresentationSubcacheCountField,
        sizeof(subcacheCount));
    if (memcmp(mainBytes, kCNDSpecialPresentationCacheMagic,
            sizeof(kCNDSpecialPresentationCacheMagic)) != 0 ||
        memcmp(mainBytes + kCNDSpecialPresentationCacheUUIDOffset,
            kCNDSpecialPresentationMainCacheUUID,
            sizeof(kCNDSpecialPresentationMainCacheUUID)) != 0 ||
        sharedRegionStart != kCNDSpecialPresentationSharedRegionBase ||
        osVersion != UINT32_C(0x1a0000) ||
        subcacheOffset != kCNDSpecialPresentationSubcacheArrayOffset ||
        subcacheCount != kCNDSpecialPresentationSubcacheCount) {
        if (errorOut) *errorOut =
            @"runtime-main-cache-exact-header-mismatch";
        return NO;
    }

    const NSUInteger membershipLength =
        (NSUInteger)subcacheCount *
        kCNDSpecialPresentationSubcacheEntrySize;
    if (subcacheOffset > UINT64_MAX - mainRuntime) {
        if (errorOut) *errorOut =
            @"runtime-subcache-membership-overflow";
        return NO;
    }
    uint64_t membershipRuntime = mainRuntime + subcacheOffset;
    NSDictionary<NSString *, id> *membershipRead = nil;
    NSData *membership = CNDSpecialPresentationReadPhysicalWindow(
        probeReport, membershipRuntime, membershipLength,
        &membershipRead, errorOut);
    if (membership.length != membershipLength) {
        if (errorOut && !*errorOut) {
            *errorOut = @"runtime-subcache-membership-read-failed";
        }
        return NO;
    }
    uint8_t expectedSuffix[kCNDSpecialPresentationSubcacheSuffixLength] = {0};
    static const char kReadonlySuffix[] = ".34.dyldreadonly";
    _Static_assert(sizeof(kReadonlySuffix) <=
        kCNDSpecialPresentationSubcacheSuffixLength,
        "read-only subcache suffix must fit its cache entry");
    memcpy(expectedSuffix, kReadonlySuffix, sizeof(kReadonlySuffix));
    const uint8_t *membershipBytes = membership.bytes;
    NSUInteger matchCount = 0;
    NSUInteger matchIndex = NSNotFound;
    uint64_t readonlyVMOffset = 0;
    for (NSUInteger index = 0; index < subcacheCount; index++) {
        const uint8_t *entry = membershipBytes +
            index * kCNDSpecialPresentationSubcacheEntrySize;
        if (memcmp(entry, kCNDSpecialPresentationReadonlyCacheUUID,
                sizeof(kCNDSpecialPresentationReadonlyCacheUUID)) != 0) {
            continue;
        }
        matchCount++;
        matchIndex = index;
        memcpy(&readonlyVMOffset, entry + 16,
            sizeof(readonlyVMOffset));
        if (memcmp(entry + kCNDSpecialPresentationSubcacheSuffixOffset,
                expectedSuffix, sizeof(expectedSuffix)) != 0) {
            if (errorOut) *errorOut =
                @"runtime-readonly-subcache-suffix-mismatch";
            return NO;
        }
    }
    if (matchCount != 1 ||
        matchIndex != kCNDSpecialPresentationReadonlySubcacheIndex ||
        readonlyVMOffset !=
            kCNDSpecialPresentationReadonlyCacheVMOffset) {
        if (errorOut) *errorOut =
            @"runtime-readonly-subcache-membership-mismatch";
        return NO;
    }
    if (readonlyVMOffset > UINT64_MAX - mainRuntime) {
        if (errorOut) *errorOut =
            @"runtime-readonly-subcache-header-overflow";
        return NO;
    }
    uint64_t readonlyRuntime = mainRuntime + readonlyVMOffset;
    NSDictionary<NSString *, id> *readonlyRead = nil;
    NSData *readonlyHeader = CNDSpecialPresentationReadPhysicalWindow(
        probeReport, readonlyRuntime,
        kCNDSpecialPresentationCacheHeaderLength,
        &readonlyRead, errorOut);
    if (readonlyHeader.length !=
        kCNDSpecialPresentationCacheHeaderLength) {
        if (errorOut && !*errorOut) {
            *errorOut = @"runtime-readonly-cache-header-read-failed";
        }
        return NO;
    }
    const uint8_t *readonlyBytes = readonlyHeader.bytes;
    if (memcmp(readonlyBytes, kCNDSpecialPresentationCacheMagic,
            sizeof(kCNDSpecialPresentationCacheMagic)) != 0 ||
        memcmp(readonlyBytes + kCNDSpecialPresentationCacheUUIDOffset,
            kCNDSpecialPresentationReadonlyCacheUUID,
            sizeof(kCNDSpecialPresentationReadonlyCacheUUID)) != 0) {
        if (errorOut) *errorOut =
            @"runtime-readonly-cache-exact-header-mismatch";
        return NO;
    }
    if (identityOut) {
        *identityOut = @{
            @"verified": @YES,
            @"mainCacheUUID":
                @CND_SPECIAL_PRESENTATION_MAIN_CACHE_UUID,
            @"readonlySubcacheUUID":
                @CND_SPECIAL_PRESENTATION_READONLY_UUID,
            @"sharedRegionBase":
                CNDSpecialPresentationHex(sharedRegionStart),
            @"slide": CNDSpecialPresentationHex(slide),
            @"mainHeader": mainRead ?: @{},
            @"osVersion": [NSString stringWithFormat:
                @"0x%08x", osVersion],
            @"subcacheArrayOffset":
                CNDSpecialPresentationHex(subcacheOffset),
            @"subcacheCount": @(subcacheCount),
            @"subcacheMembership": membershipRead ?: @{},
            @"readonlySubcacheIndex": @(matchIndex),
            @"readonlySubcacheSuffix": @".34.dyldreadonly",
            @"readonlySubcacheVMOffset":
                CNDSpecialPresentationHex(readonlyVMOffset),
            @"readonlyHeader": readonlyRead ?: @{},
        };
    }
    return YES;
}

static BOOL CNDSpecialPresentationSlideFromProbe(
    NSDictionary<NSString *, id> *probeReport,
    uint64_t *slideOut,
    NSString **errorOut)
{
    if (slideOut) *slideOut = 0;
    if (errorOut) *errorOut = nil;
    NSDictionary *physicalProof = probeReport[@"physicalPageProof"];
    if (![probeReport isKindOfClass:NSDictionary.class] ||
        [probeReport[@"schemaVersion"] unsignedIntegerValue] != 2 ||
        ![probeReport[@"probe"] isEqual:@"hail-mary-physical-page-proof"] ||
        ![probeReport[@"proofMode"] isEqual:@"springboard-only"] ||
        ![probeReport[@"productType"] isEqual:
            @CND_SPECIAL_PRESENTATION_PRODUCT] ||
        ![probeReport[@"productBuildVersion"] isEqual:
            @CND_SPECIAL_PRESENTATION_BUILD] ||
        [probeReport[@"kernelMutationCount"] unsignedLongLongValue] != 0 ||
        [probeReport[@"targetProcessMutationCount"] unsignedLongLongValue] != 0 ||
        ![physicalProof isKindOfClass:NSDictionary.class] ||
        ![physicalProof[@"confirmed"] boolValue] ||
        ![physicalProof[@"verdict"] isEqual:
            @"confirmed-springboard-only-physical-frame-and-bytes"]) {
        if (errorOut) *errorOut =
            @"confirmed-springboard-only-hail-mary-proof-required";
        return NO;
    }
    NSDictionary *springBoard = probeReport[@"springBoard"];
    uint64_t slide = 0;
    if (![springBoard isKindOfClass:NSDictionary.class] ||
        !CNDSpecialPresentationParseHex(
            springBoard[@"sharedCacheSlide"], &slide) ||
        slide == 0 || slide > kCNDSpecialPresentationMaximumSlide ||
        (slide & (kCNDSpecialPresentationPageSize - 1)) != 0) {
        if (errorOut) *errorOut = @"springboard-shared-cache-slide-invalid";
        return NO;
    }
    if (slideOut) *slideOut = slide;
    return YES;
}

static BOOL CNDSpecialPresentationResolveTarget(
    NSDictionary<NSString *, id> *probeReport,
    NSDictionary<NSString *, id> *target,
    uint64_t slide,
    NSDictionary<NSString *, id> **resolvedOut,
    NSString **errorOut)
{
    if (resolvedOut) *resolvedOut = nil;
    if (errorOut) *errorOut = nil;
    uint64_t entryUnslid = [target[@"entryUnslid"] unsignedLongLongValue];
    uint64_t frameUnslid = [target[@"frameUnslid"] unsignedLongLongValue];
    if ((entryUnslid & ~(kCNDSpecialPresentationPageSize - 1)) !=
            frameUnslid ||
        entryUnslid + kCNDSpecialPresentationGuardLength >
            frameUnslid + kCNDSpecialPresentationPageSize) {
        if (errorOut) *errorOut = @"compiled-target-frame-invalid";
        return NO;
    }
    uint64_t entryRuntime = entryUnslid + slide;
    NSDictionary<NSString *, id> *translation = nil;
    uint64_t physicalFrame = 0;
    uint64_t physicalAddress = 0;
    uint64_t frameKVA = 0;
    if (!CNDHailMaryProbeTranslateRuntimeAddressInProcessWithPhysical(
            probeReport, @"SpringBoard", entryRuntime, &translation,
            &physicalFrame, &physicalAddress, &frameKVA, errorOut)) {
        return NO;
    }
    if (physicalAddress < physicalFrame) {
        if (errorOut) *errorOut = @"physical-address-before-frame";
        return NO;
    }
    uint64_t physicalOffset = physicalAddress - physicalFrame;
    uint64_t expectedOffset = entryRuntime &
        (kCNDSpecialPresentationPageSize - 1);
    if (physicalOffset != expectedOffset ||
        physicalOffset + kCNDSpecialPresentationGuardLength >
            kCNDSpecialPresentationPageSize) {
        if (errorOut) *errorOut = @"physical-frame-offset-mismatch";
        return NO;
    }
    uint64_t windowKVA = frameKVA + physicalOffset;
    uint8_t bytes[kCNDSpecialPresentationGuardLength] = {0};
    kreadbuf(windowKVA, bytes, sizeof(bytes));
    NSData *currentGuard = [NSData dataWithBytes:bytes length:sizeof(bytes)];
    NSData *originalGuard = CNDSpecialPresentationDataFromHex(
        target[@"originalGuardHex"]);
    NSData *redirectedGuard = CNDSpecialPresentationDataFromHex(
        target[@"redirectedGuardHex"]);
    if (originalGuard.length != sizeof(bytes) ||
        redirectedGuard.length != sizeof(bytes)) {
        if (errorOut) *errorOut = @"compiled-target-guard-invalid";
        return NO;
    }
    uint64_t currentWord = 0;
    memcpy(&currentWord, bytes, sizeof(currentWord));
    NSString *state = [currentGuard isEqual:originalGuard]
        ? @"original"
        : ([currentGuard isEqual:redirectedGuard]
            ? @"redirected" : @"unexpected");
    if (resolvedOut) {
        *resolvedOut = @{
            @"route": target[@"route"] ?: @"",
            @"name": target[@"name"] ?: @"",
            @"className": target[@"className"] ?: @"",
            @"selector": target[@"selector"] ?: @"",
            @"types": target[@"types"] ?: @"",
            @"originalIMPUnslid": CNDSpecialPresentationHex(
                [target[@"originalIMPUnslid"] unsignedLongLongValue]),
            @"replacementClass": target[@"replacementClass"] ?: @"",
            @"replacementSelector":
                target[@"replacementSelector"] ?: @"",
            @"replacementIMPUnslid": CNDSpecialPresentationHex(
                [target[@"replacementIMPUnslid"] unsignedLongLongValue]),
            @"originalBehavior": target[@"originalBehavior"] ?: @"",
            @"redirectedBehavior":
                target[@"redirectedBehavior"] ?: @"",
            @"entryUnslid": CNDSpecialPresentationHex(entryUnslid),
            @"entryRuntime": CNDSpecialPresentationHex(entryRuntime),
            @"entryFileOffset": CNDSpecialPresentationHex(
                [target[@"entryFileOffset"] unsignedLongLongValue]),
            @"frameUnslid": CNDSpecialPresentationHex(frameUnslid),
            @"currentWord": CNDSpecialPresentationHex(currentWord),
            @"originalWord": CNDSpecialPresentationHex(
                [target[@"originalWord"] unsignedLongLongValue]),
            @"redirectedWord": CNDSpecialPresentationHex(
                [target[@"redirectedWord"] unsignedLongLongValue]),
            @"currentGuardHex":
                CNDSpecialPresentationHexForData(currentGuard),
            @"currentGuardSHA256":
                CNDSpecialPresentationSHA256(currentGuard),
            @"originalGuardHex": target[@"originalGuardHex"],
            @"redirectedGuardHex": target[@"redirectedGuardHex"],
            @"originalGuardSHA256":
                CNDSpecialPresentationSHA256(originalGuard),
            @"redirectedGuardSHA256":
                CNDSpecialPresentationSHA256(redirectedGuard),
            @"state": state,
            @"physicalFrame": CNDSpecialPresentationHex(physicalFrame),
            @"physicalAddress": CNDSpecialPresentationHex(physicalAddress),
            @"frameKernelVirtualAddress":
                CNDSpecialPresentationHex(frameKVA),
            @"windowKernelVirtualAddress":
                CNDSpecialPresentationHex(windowKVA),
            @"springBoardTranslation": translation ?: @{},
        };
    }
    return YES;
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDSpecialPresentationResolveTargets(
    NSDictionary<NSString *, id> *probeReport,
    NSArray<NSDictionary<NSString *, id> *> *targets,
    uint64_t slide,
    NSString **errorOut)
{
    NSMutableArray *resolved = [NSMutableArray arrayWithCapacity:targets.count];
    for (NSDictionary *target in targets) {
        NSDictionary *one = nil;
        if (!CNDSpecialPresentationResolveTarget(
                probeReport, target, slide, &one, errorOut)) {
            return nil;
        }
        [resolved addObject:one];
    }
    return resolved;
}

static BOOL CNDSpecialPresentationAllInState(
    NSArray<NSDictionary<NSString *, id> *> *resolved,
    NSUInteger expectedCount,
    NSString *state)
{
    if (resolved.count != expectedCount || expectedCount == 0) return NO;
    for (NSDictionary *one in resolved) {
        if (![one[@"state"] isEqual:state]) return NO;
    }
    return YES;
}

static BOOL CNDSpecialPresentationIsLegacyCalendarGreyPair(
    NSArray<NSDictionary<NSString *, id> *> *resolved)
{
    if (resolved.count != 3) return NO;
    NSDictionary<NSString *, NSString *> *expected = @{
        @"calendar-bundle-identifier": @"original",
        @"calendar-image": @"redirected",
        @"calendar-layer": @"redirected",
    };
    NSMutableSet<NSString *> *observed = [NSMutableSet set];
    for (NSDictionary<NSString *, id> *one in resolved) {
        NSString *name = one[@"name"];
        NSString *state = one[@"state"];
        if (![name isKindOfClass:NSString.class] ||
            ![state isEqual:expected[name]] ||
            [observed containsObject:name]) {
            return NO;
        }
        [observed addObject:name];
    }
    return observed.count == expected.count;
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDSpecialPresentationTranslateAgain(
    NSDictionary<NSString *, id> *probeReport,
    NSArray<NSDictionary<NSString *, id> *> *resolved)
{
    NSMutableArray *translations = [NSMutableArray array];
    for (NSDictionary *one in resolved) {
        uint64_t runtime = 0;
        uint64_t expectedFrame = 0;
        uint64_t expectedAddress = 0;
        uint64_t expectedKVA = 0;
        if (!CNDSpecialPresentationParseHex(one[@"entryRuntime"], &runtime) ||
            !CNDSpecialPresentationParseHex(
                one[@"physicalFrame"], &expectedFrame) ||
            !CNDSpecialPresentationParseHex(
                one[@"physicalAddress"], &expectedAddress) ||
            !CNDSpecialPresentationParseHex(
                one[@"windowKernelVirtualAddress"], &expectedKVA)) {
            return nil;
        }
        NSDictionary *translation = nil;
        uint64_t frame = 0;
        uint64_t address = 0;
        uint64_t frameKVA = 0;
        NSString *error = nil;
        if (!CNDHailMaryProbeTranslateRuntimeAddressInProcessWithPhysical(
                probeReport, @"SpringBoard", runtime, &translation,
                &frame, &address, &frameKVA, &error)) {
            return nil;
        }
        if (address < frame) return nil;
        uint64_t windowKVA = frameKVA + (address - frame);
        if (frame != expectedFrame || address != expectedAddress ||
            windowKVA != expectedKVA) {
            return nil;
        }
        [translations addObject:@{
            @"name": one[@"name"] ?: @"",
            @"entryRuntime": one[@"entryRuntime"] ?: @"",
            @"physicalFrame": CNDSpecialPresentationHex(frame),
            @"physicalAddress": CNDSpecialPresentationHex(address),
            @"windowKernelVirtualAddress":
                CNDSpecialPresentationHex(windowKVA),
            @"stable": @YES,
        }];
    }
    return translations;
}

static NSDictionary<NSString *, id> *
CNDSpecialPresentationReadPermission(
    CNDSpecialIconPresentationRoute route)
{
    NSString *path = CNDSpecialPresentationPermissionPath();
    if (route == CNDSpecialIconPresentationRouteSwitcher) {
        path = CNDSwitcherPresentationPermissionPath();
    } else if (route ==
               CNDSpecialIconPresentationRouteAppLibraryMiniatures) {
        path = CNDAppLibraryMiniaturePresentationPermissionPath();
    }
    NSData *data = [NSData dataWithContentsOfFile:
        path];
    if (!data) return nil;
    id object = [NSJSONSerialization JSONObjectWithData:data
                                                options:0
                                                  error:nil];
    return [object isKindOfClass:NSDictionary.class] ? object : nil;
}

static BOOL CNDSpecialPresentationPermissionMatches(
    NSDictionary<NSString *, id> *ticket,
    CNDSpecialIconPresentationRoute route,
    uint64_t slide,
    NSDictionary<NSString *, id> *springBoardIdentity,
    NSArray<NSDictionary<NSString *, id> *> *resolved,
    NSString **errorOut)
{
    if (errorOut) *errorOut = nil;
    NSString *expectedExperiment =
        @CND_SPECIAL_PRESENTATION_PERMISSION_EXPERIMENT;
    if (route == CNDSpecialIconPresentationRouteSwitcher) {
        expectedExperiment =
            @CND_SWITCHER_PRESENTATION_PERMISSION_EXPERIMENT;
    } else if (route ==
               CNDSpecialIconPresentationRouteAppLibraryMiniatures) {
        expectedExperiment =
            @CND_APP_LIBRARY_MINIATURE_PRESENTATION_PERMISSION_EXPERIMENT;
    }
    if (![ticket isKindOfClass:NSDictionary.class] ||
        ![ticket[@"confirmed"] boolValue] ||
        ![ticket[@"experiment"] isEqual:expectedExperiment] ||
        ![ticket[@"build"] isEqual:@CND_SPECIAL_PRESENTATION_BUILD] ||
        ![ticket[@"product"] isEqual:@CND_SPECIAL_PRESENTATION_PRODUCT] ||
        ![ticket[@"proofMode"] isEqual:@"springboard-only"] ||
        ![ticket[@"runtimeCacheIdentity"][@"verified"] boolValue] ||
        ![ticket[@"postWriteTranslation"][@"stable"] boolValue] ||
        ![ticket[@"readback"][@"identicalToBefore"] boolValue]) {
        if (errorOut) *errorOut = @"same-boot-presentation-ticket-required";
        return NO;
    }
    uint64_t ticketSlide = 0;
    if (!CNDSpecialPresentationParseHex(ticket[@"slide"], &ticketSlide) ||
        ticketSlide != slide) {
        if (errorOut) *errorOut = @"permission-ticket-slide-mismatch";
        return NO;
    }
    NSDictionary *ticketIdentity = ticket[@"springBoardIdentity"];
    NSArray<NSString *> *identityKeys = @[
        @"pid", @"proc", @"task", @"map", @"sharedCacheSlide",
    ];
    if (![ticketIdentity isKindOfClass:NSDictionary.class] ||
        ![springBoardIdentity isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut =
            @"permission-ticket-process-identity-missing";
        return NO;
    }
    for (NSString *key in identityKeys) {
        if (!ticketIdentity[key] ||
            ![ticketIdentity[key] isEqual:springBoardIdentity[key]]) {
            if (errorOut) *errorOut =
                @"permission-ticket-process-identity-mismatch";
            return NO;
        }
    }
    NSArray *ticketTargets = ticket[@"targets"];
    NSUInteger expectedTargetCount = CNDSpecialPresentationAllTargets().count;
    if (route == CNDSpecialIconPresentationRouteSwitcher) {
        expectedTargetCount = CNDSwitcherPresentationTargets().count;
    } else if (route ==
               CNDSpecialIconPresentationRouteAppLibraryMiniatures) {
        expectedTargetCount =
            CNDAppLibraryMiniaturePresentationTargets().count;
    }
    if (![ticketTargets isKindOfClass:NSArray.class] ||
        ticketTargets.count != expectedTargetCount) {
        if (errorOut) *errorOut = @"permission-ticket-target-set-mismatch";
        return NO;
    }
    NSArray<NSString *> *keys = @[
        @"entryUnslid", @"entryRuntime", @"physicalFrame",
        @"physicalAddress", @"windowKernelVirtualAddress",
    ];
    for (NSDictionary *now in resolved) {
        NSPredicate *predicate = [NSPredicate predicateWithBlock:
            ^BOOL(NSDictionary *before, NSDictionary *bindings) {
                (void)bindings;
                return [before[@"entryUnslid"]
                    isEqual:now[@"entryUnslid"]];
            }];
        NSArray *matches = [ticketTargets filteredArrayUsingPredicate:predicate];
        if (matches.count != 1) {
            if (errorOut) *errorOut = @"permission-ticket-target-missing";
            return NO;
        }
        NSDictionary *before = matches.firstObject;
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

static NSDictionary<NSString *, id> *
CNDSpecialPresentationRestoreAttemptedWrites(
    NSArray<NSDictionary<NSString *, id> *> *resolved,
    NSUInteger attemptedCount,
    NSString *guardKeyOrNil)
{
    NSMutableArray *restorations = [NSMutableArray array];
    BOOL allRestored = YES;
    uint64_t invocations = 0;
    NSUInteger boundedCount = MIN(attemptedCount, resolved.count);
    for (NSUInteger index = 0; index < boundedCount; index++) {
        NSDictionary *one = resolved[index];
        NSString *guardKey = guardKeyOrNil;
        if (guardKey.length == 0) {
            guardKey = [one[@"state"] isEqual:@"original"]
                ? @"originalGuardHex" : @"redirectedGuardHex";
        }
        uint64_t windowKVA = 0;
        NSData *guard = CNDSpecialPresentationDataFromHex(one[guardKey]);
        if (!CNDSpecialPresentationParseHex(
                one[@"windowKernelVirtualAddress"], &windowKVA) ||
            guard.length != kCNDSpecialPresentationGuardLength) {
            allRestored = NO;
            [restorations addObject:@{
                @"name": one[@"name"] ?: @"",
                @"restored": @NO,
                @"error": @"rollback-target-invalid",
            }];
            continue;
        }
        BOOL dispatched = CNDSpecialPresentationCheckedWriteGuard(
            windowKVA, guard);
        invocations++;
        uint8_t bytes[kCNDSpecialPresentationGuardLength] = {0};
        kreadbuf(windowKVA, bytes, sizeof(bytes));
        NSData *readback = [NSData dataWithBytes:bytes length:sizeof(bytes)];
        BOOL restored = dispatched && [readback isEqual:guard];
        allRestored = allRestored && restored;
        [restorations addObject:@{
            @"name": one[@"name"] ?: @"",
            @"restored": @(restored),
            @"desiredGuardHex": one[guardKey] ?: @"",
            @"readbackGuardHex":
                CNDSpecialPresentationHexForData(readback),
        }];
    }
    return @{
        @"attempted": @YES,
        @"restored": @(allRestored && restorations.count == boundedCount),
        @"writePrimitiveInvocationCount": @(invocations),
        @"targets": restorations,
    };
}

BOOL CNDSpecialIconPresentationDispatchProbeIsSupported(
    NSString **reasonOut)
{
    return CNDHailMaryProbeIsSupported(reasonOut);
}

BOOL CNDSpecialIconPresentationDispatchPermissionIsRunning(void)
{
    return __sync_fetch_and_add(
        &gCNDSpecialPresentationPermissionRunning, 0) != 0;
}

BOOL CNDSpecialIconPresentationDispatchRedirectIsRunning(void)
{
    return __sync_fetch_and_add(
        &gCNDSpecialPresentationRedirectRunning, 0) != 0;
}

static void CNDSpecialPresentationDispatchPermissionRunInternal(
    BOOL switcherOnly,
    BOOL appLibraryMiniatureOnly,
    CNDSpecialIconPresentationDispatchCompletion completion)
{
    if (!completion) return;
    if (!__sync_bool_compare_and_swap(
            &gCNDSpecialPresentationPermissionRunning, 0, 1)) {
        completion(@{
            @"confirmed": @NO,
            @"result": @"presentation-permission-already-running",
            @"message": @"The presentation permission probe is already running.",
        });
        return;
    }
    NSString *experiment = @CND_SPECIAL_PRESENTATION_PERMISSION_EXPERIMENT;
    NSString *reportPath = CNDSpecialPresentationPermissionPath();
    NSString *scopeName = @"clock-calendar";
    NSString *scopeLabel = @"Clock/Calendar";
    NSArray<NSDictionary<NSString *, id> *> *permissionTargets =
        CNDSpecialPresentationAllTargets();
    if (switcherOnly) {
        experiment = @CND_SWITCHER_PRESENTATION_PERMISSION_EXPERIMENT;
        reportPath = CNDSwitcherPresentationPermissionPath();
        scopeName = @"switcher";
        scopeLabel = @"switcher";
        permissionTargets = CNDSwitcherPresentationTargets();
    } else if (appLibraryMiniatureOnly) {
        experiment =
            @CND_APP_LIBRARY_MINIATURE_PRESENTATION_PERMISSION_EXPERIMENT;
        reportPath = CNDAppLibraryMiniaturePresentationPermissionPath();
        scopeName = @"app-library-miniatures";
        scopeLabel = @"App Library miniature";
        permissionTargets = CNDAppLibraryMiniaturePresentationTargets();
    }
    if (CNDSpecialPresentationOtherExperimentRunning(NO) ||
        CNDSpecialIconPresentationDispatchRedirectIsRunning()) {
        NSMutableDictionary *report = CNDSpecialPresentationBaseReport(
            experiment, reportPath);
        report[@"routeScope"] = scopeName;
        report[@"result"] = @"presentation-permission-conflict";
        report[@"message"] =
            @"Another shared-cache experiment is running. No write was attempted.";
        CNDSpecialPresentationFinish(report, YES, completion);
        return;
    }

    CNDHailMaryProbeRunWithMode(CNDHailMaryProofModeSpringBoardOnly,
        ^(NSDictionary<NSString *, id> *probeReport) {
        NSMutableDictionary *report = CNDSpecialPresentationBaseReport(
            experiment, reportPath);
        report[@"routeScope"] = scopeName;
        report[@"preflightProbe"] = probeReport ?: @{};
        report[@"springBoardIdentity"] =
            probeReport[@"springBoard"] ?: @{};
        uint64_t slide = 0;
        NSString *error = nil;
        if (!CNDSpecialPresentationSlideFromProbe(
                probeReport, &slide, &error)) {
            report[@"result"] = @"presentation-permission-proof-failed";
            report[@"message"] = error ?:
                @"The SpringBoard-only Hail Mary proof did not confirm this boot.";
            CNDSpecialPresentationFinish(report, YES, completion);
            return;
        }
        report[@"slide"] = CNDSpecialPresentationHex(slide);
        NSDictionary<NSString *, id> *cacheIdentity = nil;
        if (!CNDSpecialPresentationVerifyRuntimeCacheIdentity(
                probeReport, slide, &cacheIdentity, &error)) {
            report[@"result"] =
                @"presentation-permission-cache-identity-failed";
            report[@"message"] = error ?:
                @"The live main cache and .34 subcache identities did not match the exact offline cache.";
            CNDSpecialPresentationFinish(report, YES, completion);
            return;
        }
        report[@"runtimeCacheIdentity"] = cacheIdentity;
        NSArray *resolved = CNDSpecialPresentationResolveTargets(
            probeReport, permissionTargets, slide, &error);
        if (!resolved) {
            report[@"result"] = @"presentation-permission-resolve-failed";
            report[@"message"] = error ?: [NSString stringWithFormat:
                @"The %lu exact presentation entries did not resolve.",
                (unsigned long)permissionTargets.count];
            CNDSpecialPresentationFinish(report, YES, completion);
            return;
        }
        for (NSDictionary *one in resolved) {
            if ([one[@"state"] isEqual:@"unexpected"]) {
                report[@"targets"] = resolved;
                report[@"result"] = @"presentation-permission-guard-mismatch";
                report[@"message"] =
                    @"At least one exact 32-byte entry guard is neither original nor redirected. No write was attempted.";
                CNDSpecialPresentationFinish(report, YES, completion);
                return;
            }
        }
        report[@"targets"] = resolved;
        report[@"stage"] = @"armed-identical-low-word-writes";
        report[@"writes"] = @[];
        NSString *journalError = nil;
        if (!CNDSpecialPresentationSaveDurably(
                report, reportPath, &journalError)) {
            report[@"result"] = @"presentation-permission-journal-failed";
            report[@"message"] = journalError ?:
                @"The permission journal could not be saved.";
            CNDSpecialPresentationFinish(report, YES, completion);
            return;
        }

        NSMutableArray *writes = [NSMutableArray array];
        uint64_t primitiveInvocations = 0;
        for (NSUInteger index = 0; index < resolved.count; index++) {
            NSDictionary *one = resolved[index];
            uint64_t windowKVA = 0;
            uint64_t currentWord = 0;
            if (!CNDSpecialPresentationParseHex(
                    one[@"windowKernelVirtualAddress"], &windowKVA) ||
                !CNDSpecialPresentationParseHex(
                    one[@"currentWord"], &currentWord)) {
                report[@"result"] = @"presentation-permission-target-invalid";
                report[@"message"] =
                    @"An exact identical-write target could not be decoded.";
                report[@"kernelWritePrimitiveInvocationCount"] =
                    @(primitiveInvocations);
                CNDSpecialPresentationFinish(report, YES, completion);
                return;
            }
            NSData *before = CNDSpecialPresentationDataFromHex(
                one[@"currentGuardHex"]);
            uint64_t beforeWord = 0;
            if (before.length == kCNDSpecialPresentationGuardLength) {
                memcpy(&beforeWord, before.bytes, sizeof(beforeWord));
            }
            if (beforeWord != currentWord) {
                report[@"result"] =
                    @"presentation-permission-current-word-mismatch";
                report[@"message"] =
                    @"The recorded packed word does not match its exact guard.";
                report[@"kernelWritePrimitiveInvocationCount"] =
                    @(primitiveInvocations);
                CNDSpecialPresentationFinish(report, YES, completion);
                return;
            }
            BOOL dispatched = CNDSpecialPresentationCheckedWriteGuard(
                windowKVA, before);
            primitiveInvocations++;
            uint8_t bytes[kCNDSpecialPresentationGuardLength] = {0};
            kreadbuf(windowKVA, bytes, sizeof(bytes));
            NSData *readback = [NSData dataWithBytes:bytes length:sizeof(bytes)];
            if (!dispatched || ![readback isEqual:before]) {
                NSDictionary *cleanup =
                    CNDSpecialPresentationRestoreAttemptedWrites(
                        resolved, index + 1, nil);
                report[@"cleanup"] = cleanup;
                report[@"rollbackWritePrimitiveInvocationCount"] =
                    cleanup[@"writePrimitiveInvocationCount"] ?: @0;
                report[@"result"] =
                    @"presentation-permission-readback-mismatch";
                report[@"message"] = [cleanup[@"restored"] boolValue]
                    ? @"An identical write changed its guard; all attempted low words were restored."
                    : @"An identical write changed its guard and exact restoration failed.";
                report[@"kernelWritePrimitiveInvocationCount"] =
                    @(primitiveInvocations);
                CNDSpecialPresentationFinish(report, YES, completion);
                return;
            }
            [writes addObject:@{
                @"name": one[@"name"] ?: @"",
                @"route": @"checked-32-byte-window-identical",
                @"dispatchReturned": @YES,
                @"identicalToBefore": @YES,
                @"readbackGuardHex":
                    CNDSpecialPresentationHexForData(readback),
            }];
            report[@"writes"] = writes;
            report[@"kernelWritePrimitiveInvocationCount"] =
                @(primitiveInvocations);
            if (!CNDSpecialPresentationSaveDurably(
                    report, reportPath, &journalError)) {
                report[@"result"] =
                    @"presentation-permission-progress-journal-failed";
                report[@"message"] = journalError ?:
                    @"Progress could not be journaled after an identical write.";
                CNDSpecialPresentationFinish(report, YES, completion);
                return;
            }
        }
        NSArray *translations = CNDSpecialPresentationTranslateAgain(
            probeReport, resolved);
        if (!translations) {
            report[@"result"] =
                @"presentation-permission-post-translation-changed";
            report[@"message"] =
                @"All identical writes read back, but a SpringBoard translation changed.";
            CNDSpecialPresentationFinish(report, YES, completion);
            return;
        }
        report[@"postWriteTranslation"] = @{
            @"stable": @YES,
            @"translations": translations,
        };
        report[@"readback"] = @{
            @"exactDesiredGuard": @YES,
            @"exactOfflineGuard": @YES,
            @"identicalToBefore": @YES,
        };
        report[@"stage"] = @"identical-low-word-writes-confirmed";
        report[@"evidenceClass"] = @"Physical-proved";
        report[@"confirmed"] = @YES;
        report[@"result"] = @"presentation-permission-confirmed";
        report[@"message"] = [NSString stringWithFormat:
            @"All %lu exact %@ presentation entries accepted identical low-word writes with exact readback and stable SpringBoard translations. This is the same-boot permission ticket.",
            (unsigned long)permissionTargets.count,
            scopeLabel];
        CNDSpecialPresentationFinish(report, YES, completion);
    });
}

void CNDSpecialIconPresentationDispatchPermissionRun(
    CNDSpecialIconPresentationDispatchCompletion completion)
{
    CNDSpecialPresentationDispatchPermissionRunInternal(
        NO, NO, completion);
}

void CNDSwitcherPresentationDispatchPermissionRun(
    CNDSpecialIconPresentationDispatchCompletion completion)
{
    CNDSpecialPresentationDispatchPermissionRunInternal(
        YES, NO, completion);
}

void CNDAppLibraryMiniaturePresentationDispatchPermissionRun(
    CNDSpecialIconPresentationDispatchCompletion completion)
{
    CNDSpecialPresentationDispatchPermissionRunInternal(
        NO, YES, completion);
}

void CNDSpecialIconPresentationDispatchRedirectRun(
    CNDSpecialIconPresentationRoute route,
    CNDSpecialIconPresentationOperation operation,
    CNDSpecialIconPresentationDispatchCompletion completion)
{
    if (!completion) return;
    if (route != CNDSpecialIconPresentationRouteClock &&
        route != CNDSpecialIconPresentationRouteCalendar &&
        route != CNDSpecialIconPresentationRouteSwitcher &&
        route != CNDSpecialIconPresentationRouteAppLibraryMiniatures) {
        completion(@{
            @"confirmed": @NO,
            @"result": @"presentation-route-invalid",
            @"message": @"The requested presentation route is invalid.",
        });
        return;
    }
    if (!__sync_bool_compare_and_swap(
            &gCNDSpecialPresentationRedirectRunning, 0, 1)) {
        completion(@{
            @"confirmed": @NO,
            @"result": @"presentation-redirect-already-running",
            @"message": @"A presentation redirect operation is already running.",
        });
        return;
    }
    NSString *routeName = CNDSpecialPresentationRouteName(route);
    NSString *experiment = [NSString stringWithFormat:
        @"special-icon-%@-presentation-dispatch", routeName];
    NSString *reportPath = CNDSpecialPresentationReportPath(route);
    if (CNDSpecialPresentationOtherExperimentRunning(YES)) {
        NSMutableDictionary *report = CNDSpecialPresentationBaseReport(
            experiment, reportPath);
        report[@"route"] = routeName;
        report[@"operation"] =
            CNDSpecialPresentationOperationName(operation);
        report[@"result"] = @"presentation-redirect-conflict";
        report[@"message"] =
            @"Another shared-cache experiment is running. No write was attempted.";
        CNDSpecialPresentationFinish(report, NO, completion);
        return;
    }
    NSDictionary *ticket = CNDSpecialPresentationIsMutation(operation)
        ? CNDSpecialPresentationReadPermission(route) : nil;

    CNDHailMaryProbeRunWithMode(CNDHailMaryProofModeSpringBoardOnly,
        ^(NSDictionary<NSString *, id> *probeReport) {
        NSMutableDictionary *report = CNDSpecialPresentationBaseReport(
            experiment, reportPath);
        report[@"route"] = routeName;
        report[@"operation"] =
            CNDSpecialPresentationOperationName(operation);
        report[@"preflightProbe"] = probeReport ?: @{};
        report[@"springBoardIdentity"] =
            probeReport[@"springBoard"] ?: @{};
        uint64_t slide = 0;
        NSString *error = nil;
        if (!CNDSpecialPresentationSlideFromProbe(
                probeReport, &slide, &error)) {
            report[@"result"] = @"presentation-redirect-proof-failed";
            report[@"message"] = error ?:
                @"The SpringBoard-only Hail Mary proof did not confirm this boot.";
            CNDSpecialPresentationFinish(report, NO, completion);
            return;
        }
        report[@"slide"] = CNDSpecialPresentationHex(slide);
        NSDictionary<NSString *, id> *cacheIdentity = nil;
        if (!CNDSpecialPresentationVerifyRuntimeCacheIdentity(
                probeReport, slide, &cacheIdentity, &error)) {
            report[@"result"] =
                @"presentation-redirect-cache-identity-failed";
            report[@"message"] = error ?:
                @"The live main cache and .34 subcache identities did not match the exact offline cache.";
            CNDSpecialPresentationFinish(report, NO, completion);
            return;
        }
        report[@"runtimeCacheIdentity"] = cacheIdentity;
        NSArray *targets = CNDSpecialPresentationTargetsForRoute(route);
        if (route == CNDSpecialIconPresentationRouteSwitcher &&
            operation == CNDSpecialIconPresentationOperationRestore) {
            targets = targets.reverseObjectEnumerator.allObjects;
        }
        NSArray *resolved = CNDSpecialPresentationResolveTargets(
            probeReport, targets, slide, &error);
        if (!resolved) {
            report[@"result"] = @"presentation-redirect-resolve-failed";
            report[@"message"] = error ?:
                @"The exact presentation entries did not resolve.";
            CNDSpecialPresentationFinish(report, NO, completion);
            return;
        }
        report[@"targets"] = resolved;
        report[@"writeOrder"] = [resolved valueForKey:@"name"] ?: @[];
        report[@"requiresSwitcherQuiescence"] =
            @(route == CNDSpecialIconPresentationRouteSwitcher &&
              CNDSpecialPresentationIsMutation(operation));
        BOOL expectRedirected =
            operation == CNDSpecialIconPresentationOperationRestore ||
            operation ==
                CNDSpecialIconPresentationOperationVerifyRedirected;
        NSString *requiredState = expectRedirected
            ? @"redirected" : @"original";
        BOOL stateMatches = CNDSpecialPresentationAllInState(
            resolved, targets.count, requiredState);
        BOOL legacyCalendarGreyPair =
            route == CNDSpecialIconPresentationRouteCalendar &&
            CNDSpecialPresentationIsLegacyCalendarGreyPair(resolved);
        if (!CNDSpecialPresentationIsMutation(operation)) {
            report[@"state"] = stateMatches
                ? requiredState : @"mixed-or-unexpected";
            if (stateMatches) {
                report[@"evidenceClass"] = @"Physical-proved";
            }
            report[@"confirmed"] = @(stateMatches);
            report[@"readback"] = @{
                @"exactDesiredGuard": @(stateMatches),
                @"exactOfflineGuard": @(stateMatches),
            };
            report[@"result"] = stateMatches
                ? (expectRedirected
                    ? @"presentation-verify-redirected-confirmed"
                    : @"presentation-verify-original-confirmed")
                : (expectRedirected
                    ? @"presentation-verify-redirected-mismatch"
                    : @"presentation-verify-original-mismatch");
            report[@"message"] = stateMatches
                ? [NSString stringWithFormat:
                    @"The %@ presentation entries match the exact %@ guards.",
                    routeName, requiredState]
                : @"The route does not match the requested exact state. No write was attempted.";
            CNDSpecialPresentationFinish(report, NO, completion);
            return;
        }
        if (!CNDSpecialPresentationPermissionMatches(
                ticket, route, slide, probeReport[@"springBoard"],
                resolved, &error)) {
            report[@"result"] = @"presentation-redirect-permission-required";
            report[@"message"] = error ?:
                @"A matching same-boot presentation permission ticket is required.";
            CNDSpecialPresentationFinish(report, NO, completion);
            return;
        }
        if (!stateMatches && !legacyCalendarGreyPair) {
            report[@"state"] = @"mixed-or-unexpected";
            report[@"result"] = expectRedirected
                ? @"presentation-restore-redirected-state-required"
                : @"presentation-apply-original-state-required";
            report[@"message"] =
                route == CNDSpecialIconPresentationRouteCalendar
                    ? @"Every route entry must match the exact required guard. The only accepted mixed recovery state is the retained Calendar grey pair with its new bundle-identifier entry still original."
                    : @"Every route entry must match the exact required guard. No mixed state is accepted.";
            CNDSpecialPresentationFinish(report, NO, completion);
            return;
        }
        if (legacyCalendarGreyPair) {
            report[@"acceptedBeforeState"] =
                @"retained-calendar-grey-pair";
        }

        BOOL apply =
            operation == CNDSpecialIconPresentationOperationApply;
        NSString *desiredKey = apply
            ? @"redirectedGuardHex" : @"originalGuardHex";
        NSMutableArray *writes = [NSMutableArray array];
        uint64_t semanticMutationsPlanned = 0;
        for (NSDictionary *one in resolved) {
            NSData *desired = CNDSpecialPresentationDataFromHex(
                one[desiredKey]);
            NSData *before = CNDSpecialPresentationDataFromHex(
                one[@"currentGuardHex"]);
            if (desired.length != kCNDSpecialPresentationGuardLength ||
                before.length != kCNDSpecialPresentationGuardLength) {
                report[@"result"] = @"presentation-desired-guard-invalid";
                report[@"message"] =
                    @"A compiled desired or exact before-state guard is invalid. No write was attempted.";
                CNDSpecialPresentationFinish(report, NO, completion);
                return;
            }
            BOOL semanticMutation = ![before isEqual:desired];
            semanticMutationsPlanned += semanticMutation ? 1 : 0;
            uint32_t lowWord = 0;
            memcpy(&lowWord, desired.bytes, sizeof(lowWord));
            [writes addObject:@{
                @"name": one[@"name"] ?: @"",
                @"entryRuntime": one[@"entryRuntime"] ?: @"",
                @"windowKernelVirtualAddress":
                    one[@"windowKernelVirtualAddress"] ?: @"",
                @"desiredGuardHex": one[desiredKey] ?: @"",
                @"inverseGuardHex": one[@"currentGuardHex"] ?: @"",
                @"semanticMutation": @(semanticMutation),
                @"desiredLowWord":
                    [NSString stringWithFormat:@"0x%08x", lowWord],
                @"dispatchReturned": @NO,
            }];
        }
        report[@"stage"] = apply
            ? @"armed-presentation-apply"
            : @"armed-presentation-restore";
        report[@"writes"] = writes;
        report[@"inverseState"] =
            @"restore each target's exact captured before-state guard";
        report[@"dispatchEntrySemanticMutationsPlanned"] =
            @(semanticMutationsPlanned);
        NSString *journalError = nil;
        if (!CNDSpecialPresentationSaveDurably(
                report, reportPath, &journalError)) {
            report[@"result"] = @"presentation-inverse-journal-failed";
            report[@"message"] = journalError ?:
                @"The exact inverse could not be journaled. No write was attempted.";
            CNDSpecialPresentationFinish(report, NO, completion);
            return;
        }

        uint64_t primitiveInvocations = 0;
        for (NSUInteger index = 0; index < resolved.count; index++) {
            NSMutableDictionary *write = [writes[index] mutableCopy];
            uint64_t windowKVA = 0;
            NSData *desired = CNDSpecialPresentationDataFromHex(
                write[@"desiredGuardHex"]);
            if (!CNDSpecialPresentationParseHex(
                    write[@"windowKernelVirtualAddress"], &windowKVA) ||
                desired.length != kCNDSpecialPresentationGuardLength) {
                report[@"result"] = @"presentation-write-target-invalid";
                report[@"message"] =
                    @"An armed target became invalid. Completed writes are being restored.";
                NSDictionary *cleanup =
                    CNDSpecialPresentationRestoreAttemptedWrites(
                        resolved, index, nil);
                report[@"cleanup"] = cleanup;
                report[@"rollbackWritePrimitiveInvocationCount"] =
                    cleanup[@"writePrimitiveInvocationCount"] ?: @0;
                CNDSpecialPresentationFinish(report, NO, completion);
                return;
            }
            BOOL dispatched = CNDSpecialPresentationCheckedWriteGuard(
                windowKVA, desired);
            primitiveInvocations++;
            uint8_t bytes[kCNDSpecialPresentationGuardLength] = {0};
            kreadbuf(windowKVA, bytes, sizeof(bytes));
            NSData *readback = [NSData dataWithBytes:bytes length:sizeof(bytes)];
            if (!dispatched || ![readback isEqual:desired]) {
                NSDictionary *cleanup =
                    CNDSpecialPresentationRestoreAttemptedWrites(
                        resolved, index + 1, nil);
                report[@"cleanup"] = cleanup;
                report[@"rollbackWritePrimitiveInvocationCount"] =
                    cleanup[@"writePrimitiveInvocationCount"] ?: @0;
                report[@"kernelWritePrimitiveInvocationCount"] =
                    @(primitiveInvocations);
                report[@"result"] = @"presentation-postwrite-guard-mismatch";
                report[@"message"] = [cleanup[@"restored"] boolValue]
                    ? @"A desired guard did not read back; all attempted entries were restored exactly."
                    : @"A desired guard did not read back and exact restoration failed.";
                CNDSpecialPresentationFinish(report, NO, completion);
                return;
            }
            write[@"dispatchReturned"] = @YES;
            write[@"readbackGuardHex"] =
                CNDSpecialPresentationHexForData(readback);
            writes[index] = write;
            report[@"writes"] = writes;
            report[@"kernelWritePrimitiveInvocationCount"] =
                @(primitiveInvocations);
            if (!CNDSpecialPresentationSaveDurably(
                    report, reportPath, &journalError)) {
                NSDictionary *cleanup =
                    CNDSpecialPresentationRestoreAttemptedWrites(
                        resolved, index + 1, nil);
                report[@"cleanup"] = cleanup;
                report[@"rollbackWritePrimitiveInvocationCount"] =
                    cleanup[@"writePrimitiveInvocationCount"] ?: @0;
                report[@"result"] =
                    @"presentation-progress-journal-failed";
                report[@"message"] = [cleanup[@"restored"] boolValue]
                    ? @"Progress journaling failed; all completed writes were restored exactly."
                    : @"Progress journaling failed and exact restoration failed.";
                CNDSpecialPresentationFinish(report, NO, completion);
                return;
            }
        }

        NSArray *translations = CNDSpecialPresentationTranslateAgain(
            probeReport, resolved);
        if (!translations) {
            NSDictionary *cleanup =
                CNDSpecialPresentationRestoreAttemptedWrites(
                    resolved, resolved.count, nil);
            report[@"cleanup"] = cleanup;
            report[@"rollbackWritePrimitiveInvocationCount"] =
                cleanup[@"writePrimitiveInvocationCount"] ?: @0;
            report[@"result"] = @"presentation-post-translation-changed";
            report[@"message"] = [cleanup[@"restored"] boolValue]
                ? @"A post-write translation changed; every route entry was restored exactly."
                : @"A post-write translation changed and exact restoration failed.";
            CNDSpecialPresentationFinish(report, NO, completion);
            return;
        }
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
            @(semanticMutationsPlanned);
        report[@"consumerRestartRequired"] = @YES;
        report[@"mutationConfirmed"] = @YES;
        report[@"evidenceClass"] = @"Physical-proved";
        report[@"confirmed"] = @YES;
        report[@"stage"] = apply
            ? @"presentation-applied" : @"presentation-restored";
        report[@"result"] = apply
            ? @"presentation-apply-confirmed"
            : @"presentation-restore-confirmed";
        report[@"message"] = apply
            ? [NSString stringWithFormat:
                @"The exact %@ presentation dispatch entries are redirected. Kill/restart the consumers before judging appearance; no injection, icon migration, or visibility precondition was used.",
                routeName]
            : [NSString stringWithFormat:
                @"The exact %@ presentation dispatch entries contain their original guards. Kill/restart the consumers before judging restored live behavior.",
                routeName];
        NSString *confirmationJournalError = nil;
        if (!CNDSpecialPresentationSaveDurably(
                report, reportPath, &confirmationJournalError)) {
            NSDictionary *cleanup =
                CNDSpecialPresentationRestoreAttemptedWrites(
                    resolved, resolved.count, nil);
            report[@"cleanup"] = cleanup;
            report[@"rollbackWritePrimitiveInvocationCount"] =
                cleanup[@"writePrimitiveInvocationCount"] ?: @0;
            report[@"consumerRestartRequired"] = @NO;
            report[@"mutationConfirmed"] = @NO;
            report[@"evidenceClass"] = @"Implemented";
            report[@"confirmed"] = @NO;
            report[@"stage"] = @"presentation-final-journal-failed";
            report[@"result"] = @"presentation-final-journal-failed";
            report[@"message"] = [cleanup[@"restored"] boolValue]
                ? [NSString stringWithFormat:
                    @"The final %@ confirmation could not be journaled; every route entry was restored exactly.",
                    routeName]
                : [NSString stringWithFormat:
                    @"The final %@ confirmation could not be journaled and exact restoration failed.",
                    routeName];
            report[@"confirmationJournalError"] =
                confirmationJournalError ?:
                    @"final-confirmation-durable-save-failed";
        }
        CNDSpecialPresentationFinish(report, NO, completion);
    });
}
