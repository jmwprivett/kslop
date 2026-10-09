#import "CNDSnowBoardRemix.h"

#import "CNDDockAppCatalog.h"
#import "CNDIconServicesConsumerHook.h"
#import "CNDIconServicesConsumerLifecycleCoordinator.h"
#import "CNDIconServicesDescriptorSpec.h"
#import "CNDIconServicesInterceptProof.h"
#import "CNDIconServicesPublisher.h"
#import "CNDIconServicesStructuredPayload.h"
#import "CNDIconThemeImageProcessor.h"
#import "CNDIconThemeTransaction.h"
#import "CNDLaunchServicesRegistration.h"
#import "../TaskRop/CNDKernelTaskBridge.h"
#import "../TaskRop/RemoteCall.h"
#import "../CNDHailMaryImpRedirect.h"
#import "../CNDHailMaryReadOnlyDataPage.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/kutils.h"
#import "../map_app.h"
#import "../tweaks/remote_objc.h"
#import "../tweaks/snowboardlite.h"
#import "../tweaks/themer.h"
#import "../LogTextView.h"

#import <CommonCrypto/CommonDigest.h>
#import <math.h>
#import <UIKit/UIKit.h>

static const NSUInteger CNDRemixTestApplicationLimit = 4;
static const NSUInteger CNDRemixPayloadCacheSchemaVersion = 3;
static const NSUInteger CNDRemixIconServicesJournalSchemaVersion = 2;
static const NSUInteger CNDRemixStorePreservationPolicyVersion = 1;
static const NSUInteger CNDRemixApplicationFingerprintSchemaVersion = 1;
/* Temporary controlled experiment. Keep the bounded SpringBoard cache and
 * consumer refresh disabled while persistent-store behavior is isolated. */
static const BOOL CNDRemixEnableSpringBoardCacheInvalidation = NO;
/* Schemas before 3 were captured through ISImageCache's process-local-only
 * getter and can contain a false "missing equals missing" baseline. Schema 3
 * cannot represent multiple descriptors sharing one indexed store unit. */
static const NSUInteger CNDRemixAppliedAuditSnapshotSchemaVersion = 4;
static const NSUInteger CNDRemixAppliedAuditMaximumTargets = 2048;
static NSString * const CNDRemixPayloadPipelineIdentifier =
    @"CNDIconServicesStructuredImage.matrix.v3";
/* RemoteCall still accepts a bundle-shaped label for its bounded batch, but
 * the physical bootstrap now uses only IconServices' read-only cache-
 * configuration request. It must never use the bundle-clear API: even an
 * unowned identifier schedules the daemon's global garbage collector. */
static NSString * const CNDRemixIconServicesWakeIdentifier =
    @"com.zeroxjf.cyanide.iconservices-wake";
/* UIAirDropActivity returns this exact IconServices identity from
 * -_bundleIdentifierForActivityImageCreation. It is intentionally not an
 * installed application and must never broaden into arbitrary pseudo-bundle
 * publication. */
static NSString * const CNDRemixAirDropPseudoBundleIdentifier =
    @"com.apple.Sharing.AirDrop";

NSString * const CNDSnowBoardRemixStatusesDidRefreshNotification =
    @"CNDSnowBoardRemixStatusesDidRefreshNotification";

static NSArray<NSString *> *CNDRemixDebugApplicationBundleIdentifiers(void)
{
    return @[
        @"com.toyopagroup.picaboo",
        @"com.apple.MobileSMS",
        @"com.zhiliaoapp.musically",
        @"com.8bit.bitwarden",
    ];
}

static NSArray<NSString *> *CNDRemixDebugSelectionFromBundleIdentifiers(
    NSArray<NSString *> *bundleIdentifiers)
{
    NSMutableDictionary<NSString *, NSString *> *identifierByFoldedIdentifier =
        [NSMutableDictionary dictionary];
    for (NSString *bundleIdentifier in bundleIdentifiers) {
        if (![bundleIdentifier isKindOfClass:NSString.class] ||
            bundleIdentifier.length == 0) {
            continue;
        }
        NSString *foldedIdentifier = bundleIdentifier.lowercaseString;
        if (!identifierByFoldedIdentifier[foldedIdentifier]) {
            identifierByFoldedIdentifier[foldedIdentifier] = bundleIdentifier;
        }
    }

    NSMutableArray<NSString *> *selection = [NSMutableArray array];
    for (NSString *targetIdentifier in
         CNDRemixDebugApplicationBundleIdentifiers()) {
        NSString *matchedIdentifier =
            identifierByFoldedIdentifier[targetIdentifier.lowercaseString];
        if (matchedIdentifier) [selection addObject:matchedIdentifier];
    }
    return selection;
}

static NSObject *CNDRemixStatusCacheLock(void)
{
    static NSObject *lock;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        lock = [[NSObject alloc] init];
    });
    return lock;
}

static NSArray<NSDictionary<NSString *, id> *> *g_remixStatusCache;
static BOOL g_remixStatusRefreshInFlight;
static NSMutableArray<CNDSnowBoardRemixStatusesCompletion> *g_remixStatusCompletions;

static NSData *CNDRemixThemeIconData(NSDictionary<NSString *, NSData *> *theme,
                                     NSString *bundleIdentifier)
{
    NSData *data = theme[bundleIdentifier];
    if (data || bundleIdentifier.length == 0) return data;
    for (NSString *candidate in theme) {
        if ([candidate caseInsensitiveCompare:bundleIdentifier] == NSOrderedSame) {
            return theme[candidate];
        }
    }
    return nil;
}

static NSString *CNDRemixSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class]) return @"";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *text = [NSMutableString stringWithCapacity:64];
    for (NSUInteger index = 0; index < sizeof(digest); index++) {
        [text appendFormat:@"%02x", digest[index]];
    }
    return text;
}

static NSArray<NSString *> *CNDRemixSupportedPseudoBundleIdentifiers(void)
{
    return @[CNDRemixAirDropPseudoBundleIdentifier];
}

static BOOL CNDRemixIsSupportedPseudoBundleIdentifier(NSString *identifier)
{
    return [identifier isKindOfClass:NSString.class] &&
        [identifier caseInsensitiveCompare:
            CNDRemixAirDropPseudoBundleIdentifier] == NSOrderedSame;
}

static BOOL CNDRemixIsSHA256String(NSString *value);

static NSString *CNDRemixCatalogText(NSDictionary *record, NSString *key)
{
    id value = [record isKindOfClass:NSDictionary.class] ? record[key] : nil;
    if ([value isKindOfClass:NSString.class]) {
        return [(NSString *)value
            stringByTrimmingCharactersInSet:
                NSCharacterSet.whitespaceAndNewlineCharacterSet];
    }
    if ([value isKindOfClass:NSNumber.class]) return [value stringValue];
    return @"";
}

/* AirDrop's activity identity has a normal IconServices source record but no
 * installed LSApplicationRecord catalog row. Bind its recovery baseline to
 * the current OS identity instead: an OS update must rebase this Apple-owned
 * pseudo-bundle before Cyanide can publish it again. */
static NSDictionary *CNDRemixPseudoBundleFingerprint(
    NSString *bundleIdentifier)
{
    if (!CNDRemixIsSupportedPseudoBundleIdentifier(bundleIdentifier))
        return nil;
    NSProcessInfo *processInfo = NSProcessInfo.processInfo;
    NSOperatingSystemVersion version = processInfo.operatingSystemVersion;
    NSString *versionString = processInfo.operatingSystemVersionString ?: @"";
    NSString *material = [NSString stringWithFormat:
        @"schema=%lu\npseudo=%@\nos=%ld.%ld.%ld\n%lu:%@",
        (unsigned long)CNDRemixApplicationFingerprintSchemaVersion,
        CNDRemixAirDropPseudoBundleIdentifier,
        (long)version.majorVersion, (long)version.minorVersion,
        (long)version.patchVersion,
        (unsigned long)[versionString
            lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
        versionString];
    NSString *identity = CNDRemixSHA256(
        [material dataUsingEncoding:NSUTF8StringEncoding]);
    if (!CNDRemixIsSHA256String(identity)) return nil;
    return @{
        @"schemaVersion": @(CNDRemixApplicationFingerprintSchemaVersion),
        @"identity": identity,
        @"bundleIdentifier": CNDRemixAirDropPseudoBundleIdentifier,
        @"pseudoBundle": @YES,
        @"operatingSystemVersion": versionString,
        @"operatingSystemMajorVersion": @(version.majorVersion),
        @"operatingSystemMinorVersion": @(version.minorVersion),
        @"operatingSystemPatchVersion": @(version.patchVersion),
    };
}

/* The path catches replacement installs/container rotation, while the three
 * version sources cover in-place updates which retain that path.  The
 * fingerprint comes from the same privileged iconservicesagent catalog used
 * by the batch; Cyanide never guesses by reading another app's bundle. */
static NSDictionary *CNDRemixApplicationFingerprint(
    NSDictionary *catalogRecord)
{
    NSString *bundleIdentifier =
        CNDRemixCatalogText(catalogRecord, @"bundleIdentifier");
    NSString *bundlePath =
        CNDRemixCatalogText(catalogRecord, @"bundlePath").stringByStandardizingPath;
    NSString *shortVersion =
        CNDRemixCatalogText(catalogRecord, @"shortVersionString");
    NSString *bundleVersion =
        CNDRemixCatalogText(catalogRecord, @"bundleVersion");
    NSString *externalVersion =
        CNDRemixCatalogText(catalogRecord, @"externalVersionIdentifier");
    NSString *applicationVersion =
        CNDRemixCatalogText(catalogRecord, @"applicationVersion");
    if (bundleIdentifier.length == 0 ||
        (bundlePath.length == 0 && shortVersion.length == 0 &&
         bundleVersion.length == 0 && externalVersion.length == 0 &&
         applicationVersion.length == 0)) {
        return nil;
    }
    NSArray<NSString *> *values = @[
        bundleIdentifier, bundlePath ?: @"", shortVersion ?: @"",
        bundleVersion ?: @"", externalVersion ?: @"",
        applicationVersion ?: @""
    ];
    NSMutableString *material = [NSMutableString stringWithFormat:
        @"schema=%lu", (unsigned long)CNDRemixApplicationFingerprintSchemaVersion];
    for (NSString *value in values) {
        NSData *bytes = [value dataUsingEncoding:NSUTF8StringEncoding];
        [material appendFormat:@"\n%lu:%@", (unsigned long)bytes.length, value];
    }
    NSString *identity = CNDRemixSHA256(
        [material dataUsingEncoding:NSUTF8StringEncoding]);
    if (!CNDRemixIsSHA256String(identity)) return nil;
    return @{
        @"schemaVersion": @(CNDRemixApplicationFingerprintSchemaVersion),
        @"identity": identity,
        @"bundleIdentifier": bundleIdentifier,
        @"bundlePath": bundlePath ?: @"",
        @"shortVersionString": shortVersion ?: @"",
        @"bundleVersion": bundleVersion ?: @"",
        @"externalVersionIdentifier": externalVersion ?: @"",
        @"applicationVersion": applicationVersion ?: @"",
    };
}

static BOOL CNDRemixApplicationFingerprintMatches(
    NSDictionary *saved, NSDictionary *current)
{
    NSString *savedIdentity = [saved[@"identity"] isKindOfClass:NSString.class]
        ? saved[@"identity"] : nil;
    NSString *currentIdentity = [current[@"identity"] isKindOfClass:NSString.class]
        ? current[@"identity"] : nil;
    return CNDRemixIsSHA256String(savedIdentity) &&
        CNDRemixIsSHA256String(currentIdentity) &&
        [savedIdentity isEqualToString:currentIdentity];
}

static NSURL *CNDRemixIconServicesRootURL(void)
{
    NSURL *support = [NSFileManager.defaultManager URLsForDirectory:
        NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject;
    return [[support URLByAppendingPathComponent:@"SnowBoardRemix"
                                      isDirectory:YES]
        URLByAppendingPathComponent:@"IconServices-v1" isDirectory:YES];
}

static NSURL *CNDRemixIconServicesTransactionsURL(void)
{
    return [CNDRemixIconServicesRootURL()
        URLByAppendingPathComponent:@"Transactions" isDirectory:YES];
}

static NSURL *CNDRemixSpringBoardDynamicPresentationStateURL(void)
{
    return [CNDRemixIconServicesRootURL()
        URLByAppendingPathComponent:@"SpringBoardDynamicPresentation.plist"
                     isDirectory:NO];
}

static NSDictionary *CNDRemixReadSpringBoardDynamicPresentationState(void)
{
    NSDictionary *state = [NSDictionary dictionaryWithContentsOfURL:
        CNDRemixSpringBoardDynamicPresentationStateURL()];
    return [state isKindOfClass:NSDictionary.class] ? state : nil;
}

static BOOL CNDRemixWriteSpringBoardDynamicPresentationState(
    pid_t springBoardPID, BOOL clockInstalled, BOOL calendarInstalled)
{
    if (springBoardPID <= 1 || (!clockInstalled && !calendarInstalled)) {
        return NO;
    }
    NSDictionary *state = @{
        @"schemaVersion": @1,
        @"springBoardPID": @(springBoardPID),
        @"clockInstalled": @(clockInstalled),
        @"calendarInstalled": @(calendarInstalled),
        @"updatedAt": NSDate.date,
    };
    NSURL *url = CNDRemixSpringBoardDynamicPresentationStateURL();
    NSError *error = nil;
    if (![NSFileManager.defaultManager createDirectoryAtURL:
            url.URLByDeletingLastPathComponent withIntermediateDirectories:YES
            attributes:@{NSFileProtectionKey: NSFileProtectionNone}
            error:&error]) return NO;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:state
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
    if (!data || ![data writeToURL:url options:NSDataWritingAtomic
                                  error:&error]) return NO;
    NSDictionary *readback = [NSDictionary dictionaryWithContentsOfURL:url];
    return [readback isEqualToDictionary:state];
}

static BOOL CNDRemixRemoveSpringBoardDynamicPresentationState(void)
{
    NSURL *url = CNDRemixSpringBoardDynamicPresentationStateURL();
    NSError *error = nil;
    BOOL removed = ![NSFileManager.defaultManager fileExistsAtPath:url.path] ||
        [NSFileManager.defaultManager removeItemAtURL:url error:&error];
    return removed &&
        ![NSFileManager.defaultManager fileExistsAtPath:url.path];
}

static NSDictionary *CNDRemixLiveSpringBoardDynamicPresentationState(void)
{
    NSDictionary *state = CNDRemixReadSpringBoardDynamicPresentationState();
    NSString *source = @"persistent-marker";
    pid_t recordedPID = [state[@"springBoardPID"] intValue];
    BOOL clockInstalled = [state[@"clockInstalled"] boolValue];
    BOOL calendarInstalled = [state[@"calendarInstalled"] boolValue];
    BOOL candidate = [state[@"schemaVersion"] unsignedIntegerValue] == 1 &&
        recordedPID > 1 && (clockInstalled || calendarInstalled);

    /* Compatibility for a presentation installed earlier in this same app
     * process, before its durable marker could be written. */
    if (!candidate) {
        NSDictionary *status = CNDIconServicesConsumerLifecycleStatus();
        NSDictionary *host = [status[@"hosts"][@"SpringBoard"]
            isKindOfClass:NSDictionary.class]
            ? status[@"hosts"][@"SpringBoard"] : nil;
        NSDictionary *install = [host[@"lastResult"]
            isKindOfClass:NSDictionary.class] ? host[@"lastResult"] : nil;
        NSDictionary *dynamic = [install[@"staticIcons"]
            isKindOfClass:NSDictionary.class] ? install[@"staticIcons"] : nil;
        BOOL verified = [install[@"staticIconsAttempted"] boolValue] &&
            [install[@"staticIconsVerified"] boolValue] &&
            [dynamic[@"ok"] boolValue];
        clockInstalled = verified && [dynamic[@"clockRequested"] boolValue];
        calendarInstalled = verified &&
            [dynamic[@"calendarRequested"] boolValue];
        recordedPID = [host[@"installedPID"] intValue];
        candidate = recordedPID > 1 &&
            (clockInstalled || calendarInstalled);
        source = @"lifecycle-memory";
    }

    if (!candidate) {
        return @{
            @"installed": @NO,
            @"source": @"none",
            @"springBoardPID": @0,
            @"clockInstalled": @NO,
            @"calendarInstalled": @NO,
        };
    }

    NSError *identityError = nil;
    pid_t livePID = CNDKernelTaskBridgeResolveProcessPID(
        @"SpringBoard", &identityError);
    BOOL installed = livePID > 1 && livePID == recordedPID;
    if (!installed && [source isEqualToString:@"persistent-marker"]) {
        (void)CNDRemixRemoveSpringBoardDynamicPresentationState();
    }
    return @{
        @"installed": @(installed),
        @"source": source,
        @"springBoardPID": @(recordedPID),
        @"liveSpringBoardPID": @(livePID),
        @"clockInstalled": @(clockInstalled),
        @"calendarInstalled": @(calendarInstalled),
        @"identityError": identityError.localizedDescription ?: @"",
    };
}

static NSURL *CNDRemixIconServicesPayloadCacheURL(void)
{
    return [CNDRemixIconServicesRootURL()
        URLByAppendingPathComponent:@"StructuredPayloadCache-v3"
                     isDirectory:YES];
}

static NSURL *CNDRemixAppliedAuditSnapshotURL(void)
{
    return [[CNDRemixIconServicesRootURL()
        URLByAppendingPathComponent:@"AuditSnapshots" isDirectory:YES]
        URLByAppendingPathComponent:@"AppliedIconState.plist"
                     isDirectory:NO];
}

static BOOL CNDRemixIsSHA256String(NSString *value)
{
    if (![value isKindOfClass:NSString.class] || value.length != 64) return NO;
    static NSCharacterSet *notLowercaseHex;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        notLowercaseHex = [[NSCharacterSet
            characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet];
    });
    return [value rangeOfCharacterFromSet:notLowercaseHex].location == NSNotFound;
}

static NSString *CNDRemixPayloadPlatformIdentifier(void)
{
    // IFImage's archive is private ABI. Never carry it across an OS update,
    // even when Cyanide's Application Support directory survives the update.
    return NSProcessInfo.processInfo.operatingSystemVersionString ?: @"unknown-os";
}

static NSString *CNDRemixPayloadCacheKey(
    NSString *sourceSHA256, CNDIconServicesDescriptorSpec *specification)
{
    if (!CNDRemixIsSHA256String(sourceSHA256) || !specification) return @"";
    NSString *material = [NSString stringWithFormat:
        @"cache-schema=%lu\npipeline=%@\nplatform=%@\nsource=%@\n"
         "descriptor=%@\nmarker=%@\n",
        (unsigned long)CNDRemixPayloadCacheSchemaVersion,
        CNDRemixPayloadPipelineIdentifier,
        CNDRemixPayloadPlatformIdentifier(), sourceSHA256,
        specification.canonicalIdentity, CNDIconServicesThemeMarker];
    return CNDRemixSHA256([material dataUsingEncoding:NSUTF8StringEncoding]);
}

static NSURL *CNDRemixPayloadCacheEntryURL(NSString *cacheKey)
{
    if (!CNDRemixIsSHA256String(cacheKey)) return nil;
    return [CNDRemixIconServicesPayloadCacheURL()
        URLByAppendingPathComponent:[cacheKey stringByAppendingPathExtension:@"plist"]
                     isDirectory:NO];
}

static BOOL CNDRemixPayloadDiagnosticsAreValid(
    NSDictionary *diagnostics,
    CNDIconServicesDescriptorSpec *specification)
{
    NSUInteger pixelWidth = specification.targetPixelWidth;
    NSUInteger pixelHeight = specification.targetPixelHeight;
    return specification && [diagnostics isKindOfClass:NSDictionary.class] &&
        [diagnostics[@"marker"] isEqualToString:CNDIconServicesThemeMarker] &&
        [diagnostics[@"markerPresent"] boolValue] &&
        [diagnostics[@"serializedWithHiddenChiclet"] boolValue] &&
        [diagnostics[@"imageLayerDataRoundTrip"] boolValue] &&
        [diagnostics[@"imageGeometryRoundTrip"] boolValue] &&
        [diagnostics[@"imageMarkerRoundTrip"] boolValue] &&
        [diagnostics[@"pixelWidth"] unsignedIntegerValue] == pixelWidth &&
        [diagnostics[@"pixelHeight"] unsignedIntegerValue] == pixelHeight &&
        fabs([diagnostics[@"pointWidth"] doubleValue] -
             specification.pointWidth) < 0.001 &&
        fabs([diagnostics[@"pointHeight"] doubleValue] -
             specification.pointHeight) < 0.001 &&
        fabs([diagnostics[@"scale"] doubleValue] -
             specification.scale) < 0.001;
}

static BOOL CNDRemixPayloadCacheEntryIsValid(NSDictionary *entry,
                                               NSString *sourceSHA256,
                                               NSString *cacheKey,
                                               CNDIconServicesDescriptorSpec *
                                                   specification)
{
    NSUInteger pixelWidth = specification.targetPixelWidth;
    NSUInteger pixelHeight = specification.targetPixelHeight;
    if (![entry isKindOfClass:NSDictionary.class] ||
        !specification ||
        [entry[@"schemaVersion"] unsignedIntegerValue] !=
            CNDRemixPayloadCacheSchemaVersion ||
        ![entry[@"pipelineIdentifier"]
            isEqualToString:CNDRemixPayloadPipelineIdentifier] ||
        ![entry[@"platformIdentifier"]
            isEqualToString:CNDRemixPayloadPlatformIdentifier()] ||
        ![entry[@"cacheKey"] isEqualToString:cacheKey] ||
        ![entry[@"themeSourceSHA256"] isEqualToString:sourceSHA256] ||
        ![entry[@"themeMarker"] isEqualToString:CNDIconServicesThemeMarker] ||
        ![entry[@"descriptorIdentity"]
            isEqualToString:specification.canonicalIdentity] ||
        ![entry[@"descriptorSpecification"]
            isEqualToDictionary:specification.dictionaryRepresentation] ||
        [entry[@"pixelWidth"] unsignedIntegerValue] != pixelWidth ||
        [entry[@"pixelHeight"] unsignedIntegerValue] != pixelHeight ||
        fabs([entry[@"pointWidth"] doubleValue] -
             specification.pointWidth) >= 0.001 ||
        fabs([entry[@"pointHeight"] doubleValue] -
             specification.pointHeight) >= 0.001 ||
        fabs([entry[@"scale"] doubleValue] - specification.scale) >= 0.001 ||
        ![entry[@"completeDecodeVerified"] boolValue] ||
        ![entry[@"alphaClassesPreserved"] boolValue]) {
        return NO;
    }

    NSData *processedPNG = [entry[@"processedPNGData"]
        isKindOfClass:NSData.class] ? entry[@"processedPNGData"] : nil;
    NSData *structured = [entry[@"structuredImageData"]
        isKindOfClass:NSData.class] ? entry[@"structuredImageData"] : nil;
    NSDictionary *diagnostics = [entry[@"structuredDiagnostics"]
        isKindOfClass:NSDictionary.class] ? entry[@"structuredDiagnostics"] : nil;
    if (!processedPNG.length || !structured.length ||
        processedPNG.length != [entry[@"processedPNGLength"] unsignedIntegerValue] ||
        structured.length != [entry[@"structuredImageLength"] unsignedIntegerValue] ||
        ![CNDRemixSHA256(processedPNG)
            isEqualToString:entry[@"processedPNGSHA256"]] ||
        ![CNDRemixSHA256(structured)
            isEqualToString:entry[@"structuredImageSHA256"]] ||
        !CNDRemixPayloadDiagnosticsAreValid(diagnostics, specification)) {
        return NO;
    }
    return YES;
}

static NSDictionary *CNDRemixReadPayloadCacheEntry(NSString *sourceSHA256,
                                                    NSString *cacheKey,
                                                    CNDIconServicesDescriptorSpec *
                                                        specification,
                                                    BOOL *invalidOut)
{
    if (invalidOut) *invalidOut = NO;
    NSURL *url = CNDRemixPayloadCacheEntryURL(cacheKey);
    if (!url || ![NSFileManager.defaultManager fileExistsAtPath:url.path]) return nil;
    NSDictionary *entry = [NSDictionary dictionaryWithContentsOfURL:url];
    if (!CNDRemixPayloadCacheEntryIsValid(
            entry, sourceSHA256, cacheKey, specification)) {
        if (invalidOut) *invalidOut = YES;
        return nil;
    }
    return entry;
}

static NSDictionary *CNDRemixCreatePayloadCacheEntry(
    NSString *sourceSHA256,
    NSString *cacheKey,
    CNDIconServicesDescriptorSpec *specification,
    NSData *processedPNG,
    NSData *structured,
    NSDictionary *structuredDiagnostics)
{
    if (!processedPNG.length || !structured.length || !specification ||
        !CNDRemixPayloadDiagnosticsAreValid(
            structuredDiagnostics, specification)) return nil;
    NSUInteger pixelWidth = specification.targetPixelWidth;
    NSUInteger pixelHeight = specification.targetPixelHeight;
    return @{
        @"schemaVersion": @(CNDRemixPayloadCacheSchemaVersion),
        @"pipelineIdentifier": CNDRemixPayloadPipelineIdentifier,
        @"platformIdentifier": CNDRemixPayloadPlatformIdentifier(),
        @"cacheKey": cacheKey,
        @"themeSourceSHA256": sourceSHA256,
        @"themeMarker": CNDIconServicesThemeMarker,
        @"descriptorIdentity": specification.canonicalIdentity,
        @"descriptorSpecification": specification.dictionaryRepresentation,
        @"pixelWidth": @(pixelWidth),
        @"pixelHeight": @(pixelHeight),
        @"pointWidth": @(specification.pointWidth),
        @"pointHeight": @(specification.pointHeight),
        @"scale": @(specification.scale),
        @"completeDecodeVerified": @YES,
        @"alphaClassesPreserved": @YES,
        @"processedPNGData": processedPNG,
        @"processedPNGLength": @(processedPNG.length),
        @"processedPNGSHA256": CNDRemixSHA256(processedPNG),
        @"structuredImageData": structured,
        @"structuredImageLength": @(structured.length),
        @"structuredImageSHA256": CNDRemixSHA256(structured),
        @"structuredDiagnostics": structuredDiagnostics,
        @"createdAt": NSDate.date,
    };
}

static BOOL CNDRemixWritePayloadCacheEntry(NSDictionary *entry)
{
    NSString *cacheKey = [entry[@"cacheKey"] isKindOfClass:NSString.class]
        ? entry[@"cacheKey"] : nil;
    NSString *sourceSHA256 = [entry[@"themeSourceSHA256"]
        isKindOfClass:NSString.class] ? entry[@"themeSourceSHA256"] : nil;
    CNDIconServicesDescriptorSpec *specification =
        [CNDIconServicesDescriptorSpec specWithDictionary:
            entry[@"descriptorSpecification"] error:nil];
    NSURL *url = CNDRemixPayloadCacheEntryURL(cacheKey);
    if (!url || !CNDRemixPayloadCacheEntryIsValid(
            entry, sourceSHA256, cacheKey, specification)) return NO;
    NSError *error = nil;
    if (![NSFileManager.defaultManager createDirectoryAtURL:
            url.URLByDeletingLastPathComponent withIntermediateDirectories:YES
            attributes:@{NSFileProtectionKey: NSFileProtectionNone}
            error:&error]) return NO;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:entry
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
    if (!data || ![data writeToURL:url options:NSDataWritingAtomic error:&error]) {
        return NO;
    }
    NSDictionary *readback = [NSDictionary dictionaryWithContentsOfURL:url];
    return [readback isEqualToDictionary:entry] &&
        CNDRemixPayloadCacheEntryIsValid(
            readback, sourceSHA256, cacheKey, specification);
}

static NSURL *CNDRemixIconServicesJournalURL(NSString *bundleIdentifier)
{
    if (bundleIdentifier.length == 0 ||
        [bundleIdentifier rangeOfString:@"/"].location != NSNotFound ||
        [bundleIdentifier containsString:@".."] ||
        [bundleIdentifier hasPrefix:@"."] ||
        [bundleIdentifier hasSuffix:@"."]) return nil;
    return [CNDRemixIconServicesTransactionsURL()
        URLByAppendingPathComponent:
            [bundleIdentifier stringByAppendingPathExtension:@"plist"]
                     isDirectory:NO];
}

static NSDictionary *CNDRemixReadIconServicesJournal(
    NSString *bundleIdentifier)
{
    NSURL *url = CNDRemixIconServicesJournalURL(bundleIdentifier);
    NSDictionary *journal = url
        ? [NSDictionary dictionaryWithContentsOfURL:url] : nil;
    return [journal isKindOfClass:NSDictionary.class] ? journal : nil;
}

static BOOL CNDRemixWriteIconServicesJournal(NSDictionary *journal)
{
    NSString *bundleIdentifier = [journal[@"bundleIdentifier"]
        isKindOfClass:NSString.class] ? journal[@"bundleIdentifier"] : nil;
    NSURL *url = CNDRemixIconServicesJournalURL(bundleIdentifier);
    if (!url) return NO;
    NSError *error = nil;
    if (![NSFileManager.defaultManager createDirectoryAtURL:
            url.URLByDeletingLastPathComponent withIntermediateDirectories:YES
            attributes:@{NSFileProtectionKey: NSFileProtectionNone}
            error:&error]) return NO;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:journal
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
    if (!data || ![data writeToURL:url options:NSDataWritingAtomic error:&error]) {
        return NO;
    }
    NSDictionary *readback = [NSDictionary dictionaryWithContentsOfURL:url];
    return [readback isEqualToDictionary:journal];
}

static BOOL CNDRemixRemoveIconServicesJournal(NSString *bundleIdentifier)
{
    NSURL *url = CNDRemixIconServicesJournalURL(bundleIdentifier);
    if (!url) return NO;
    NSError *error = nil;
    BOOL removed = ![NSFileManager.defaultManager fileExistsAtPath:url.path] ||
        [NSFileManager.defaultManager removeItemAtURL:url error:&error];
    return removed &&
        ![NSFileManager.defaultManager fileExistsAtPath:url.path];
}

static NSArray<NSDictionary *> *CNDRemixIconServicesJournals(void)
{
    NSURL *directory = CNDRemixIconServicesTransactionsURL();
    NSArray<NSURL *> *files = [NSFileManager.defaultManager
        contentsOfDirectoryAtURL:directory
        includingPropertiesForKeys:nil
        options:NSDirectoryEnumerationSkipsHiddenFiles error:nil];
    files = [files sortedArrayUsingComparator:^NSComparisonResult(
        NSURL *left, NSURL *right) {
        return [left.lastPathComponent compare:right.lastPathComponent];
    }];
    NSMutableArray<NSDictionary *> *journals = [NSMutableArray array];
    for (NSURL *file in files) {
        if (![file.pathExtension.lowercaseString isEqualToString:@"plist"])
            continue;
        NSDictionary *journal = [NSDictionary dictionaryWithContentsOfURL:file];
        if ([journal isKindOfClass:NSDictionary.class] &&
            [journal[@"bundleIdentifier"] isKindOfClass:NSString.class]) {
            [journals addObject:journal];
        }
    }
    return journals;
}

static NSDictionary<NSString *, NSData *> *CNDRemixNormalizedThemeLookup(
    NSDictionary<NSString *, NSData *> *theme)
{
    NSArray<NSString *> *keys = [theme.allKeys
        sortedArrayUsingComparator:^NSComparisonResult(NSString *left,
                                                        NSString *right) {
        NSComparisonResult folded = [left caseInsensitiveCompare:right];
        return folded != NSOrderedSame ? folded : [left compare:right];
    }];
    NSMutableDictionary<NSString *, NSData *> *result =
        [NSMutableDictionary dictionary];
    for (NSString *key in keys) {
        NSData *data = theme[key];
        if (![key isKindOfClass:NSString.class] || data.length == 0) continue;
        BOOL usedAlias = NO;
        NSArray<NSString *> *targets = CNDMappedIOSBundleIDsForIconName(
            key, &usedAlias);
        (void)usedAlias;
        if (targets.count == 0) targets = @[key];
        for (NSString *target in targets) {
            NSString *folded = target.lowercaseString;
            if (folded.length > 0 && !result[folded]) result[folded] = data;
        }
    }
    return result;
}

static NSArray<CNDIconServicesDescriptorSpec *> *
CNDRemixDescriptorSpecificationsForBundleIdentifier(
    NSString *bundleIdentifier)
{
    if (CNDRemixIsSupportedPseudoBundleIdentifier(bundleIdentifier)) {
        /* UIAirDropActivity uses its pseudo-bundle for two bounded consumers:
         * HomeScreen/64pt in the horizontal activity strip, and TableUIName
         * 28pt with drawBorder=YES (variantOptions 0x4) in the Apps list. */
        CNDIconServicesDescriptorSpec *activityStrip =
            [CNDIconServicesDescriptorSpec specWithPointWidth:64
                pointHeight:64 scale:3 appearance:0
                iconVariant:0 options:0];
        CNDIconServicesDescriptorSpec *moreList =
            [CNDIconServicesDescriptorSpec specWithPointWidth:28
                pointHeight:28 scale:3 appearance:0
                iconVariant:0x4 options:0];
        return activityStrip && moreList
            ? @[activityStrip, moreList] : @[];
    }
    /* The 20-point response remains specific to Safari-backed SnippetUI
     * badges. The 64-point response is part of the core profile because
     * SearchUI's vertical Apps results request it for ordinary applications. */
    BOOL includeSnippet = [bundleIdentifier.lowercaseString
        isEqualToString:@"com.apple.mobilesafari"];
    return [CNDIconServicesDescriptorProfile
        specsForIPhoneIOS26At3xIncludingSnippetExtras:includeSnippet];
}

static NSString *CNDRemixDescriptorProfileIdentity(
    NSArray<CNDIconServicesDescriptorSpec *> *specifications)
{
    CNDIconServicesDescriptorProfile *profile =
        [CNDIconServicesDescriptorProfile
            profileWithSpecifications:specifications ?: @[]];
    return profile.canonicalIdentity ?: @"";
}

static NSString *CNDRemixRasterIdentity(
    CNDIconServicesDescriptorSpec *specification)
{
    return [NSString stringWithFormat:@"%lux%lu",
        (unsigned long)specification.targetPixelWidth,
        (unsigned long)specification.targetPixelHeight];
}

/* A response raster is not the complete identity of its structured IFImage.
 * iOS 26 maps both 27pt and 28pt descriptors onto an observed 87x87 response
 * canvas, while IconRendering still serializes the distinct point geometry
 * and IFImage minimum size.  Share the expensive structured payload only when
 * both the point geometry and response raster match.  Appearance may continue
 * to share because it is carried by the descriptor rather than the IFImage. */
static NSString *CNDRemixStructuredPayloadIdentity(
    CNDIconServicesDescriptorSpec *specification)
{
    return [NSString stringWithFormat:@"%lux%lu@%lu:%@",
        (unsigned long)specification.pointWidth,
        (unsigned long)specification.pointHeight,
        (unsigned long)specification.scale,
        CNDRemixRasterIdentity(specification)];
}

static NSArray<NSDictionary *> *CNDRemixJournalVariants(
    NSDictionary *journal)
{
    NSArray *variants = [journal[@"variants"] isKindOfClass:NSArray.class]
        ? journal[@"variants"] : nil;
    if ([journal[@"schemaVersion"] unsignedIntegerValue] >=
            CNDRemixIconServicesJournalSchemaVersion && variants.count > 0) {
        return variants;
    }
    /* Schema 1 represents only the historical 68a0 record. Keep it
     * restorable, but never reinterpret it as complete matrix coverage. */
    CNDIconServicesDescriptorSpec *legacy =
        [CNDIconServicesDescriptorSpec specWithPointWidth:68
            pointHeight:68 scale:3 appearance:0 iconVariant:0 options:0];
    return legacy ? @[@{
        @"descriptorIdentity": legacy.canonicalIdentity,
        @"descriptorSpecification": legacy.dictionaryRepresentation,
        @"state": journal[@"state"] ?: @"legacy-recovery-required",
    }] : @[];
}

/* Only an explicit, complete negative publication report proves that a
 * descriptor never entered a mutation. Missing flags are legacy/ambiguous
 * evidence, not false. In particular, dispatch-possible without a report may
 * represent a crash after dispatch but before the outcome was journaled. */
static BOOL CNDRemixReportProvesNoIconServicesMutation(
    NSDictionary *publication)
{
    if (![publication isKindOfClass:NSDictionary.class]) return NO;
    for (NSString *key in @[
        @"transactionStarted", @"directStoreRemoveIssued",
        @"directStoreWriteIssued", @"persistentIndexTokenWriteIssued",
        @"replacementPublished", @"installed",
        @"stockGenerationPersisted", @"hookStillInstalledAtCleanup"
    ]) {
        id value = publication[key];
        if (![value isKindOfClass:NSNumber.class] ||
            ![value isEqualToNumber:@NO]) return NO;
    }
    for (NSString *key in @[@"hookRestored", @"hookQuiescent"]) {
        id value = publication[key];
        if (![value isKindOfClass:NSNumber.class] ||
            ![value isEqualToNumber:@YES]) return NO;
    }
    /* Contradictory success/mutation evidence must also fail closed, even
     * when the required flags above claim that dispatch never started. */
    for (NSString *key in @[
        @"ok", @"transactionInstalled", @"stockCaptured",
        @"stockGenerationInitiallyPersisted", @"replacementCreated",
        @"replacementReturned", @"directStoreRemoveVerified",
        @"directStoreWriteVerified", @"immediateStoreRollbackAttempted",
        @"immediateStoreRollbackSucceeded", @"operationCompleted",
        @"triggerVerified", @"agentCacheReadbackVerified",
        @"persistentStoreReadbackVerified"
    ]) {
        id value = publication[key];
        if (value && (![value isKindOfClass:NSNumber.class] ||
                      ![value isEqualToNumber:@NO])) return NO;
    }
    return YES;
}

static BOOL CNDRemixVariantProvesNoIconServicesMutation(
    NSDictionary *variant)
{
    if (![variant isKindOfClass:NSDictionary.class]) return NO;
    NSString *state = variant[@"state"];
    if (![@[@"prepared", @"dispatch-possible", @"recovery-required",
            @"unmutated-skipped"] containsObject:state ?: @""]) return NO;
    /* New journals checkpoint dispatch independently for each descriptor.
     * Only the durable, explicit NO proves a prepared variant was never
     * sent. Older dispatch-possible records remain crash-ambiguous. */
    id dispatchPossible = variant[@"publicationDispatchPossible"];
    BOOL neverDispatched = [dispatchPossible isKindOfClass:NSNumber.class] &&
        [dispatchPossible isEqualToNumber:@NO] &&
        variant[@"publication"] == nil;
    if (!neverDispatched && !CNDRemixReportProvesNoIconServicesMutation(
            variant[@"publication"])) return NO;
    /* An earlier failed Restore may itself have generated or written stock.
     * It is safe to skip only if that attempt independently proves untouched
     * too. A crash checkpoint in state restoring is never accepted above. */
    if (variant[@"restoration"] != nil) {
        return CNDRemixReportProvesNoIconServicesMutation(
            variant[@"restoration"]);
    }
    id restoreDispatchPossible = variant[@"restorationDispatchPossible"];
    return restoreDispatchPossible == nil ||
        ([restoreDispatchPossible isKindOfClass:NSNumber.class] &&
         [restoreDispatchPossible isEqualToNumber:@NO]);
}

static BOOL CNDRemixJournalProvesNoIconServicesMutation(
    NSDictionary *journal)
{
    if ([journal[@"schemaVersion"] unsignedIntegerValue] !=
            CNDRemixIconServicesJournalSchemaVersion ||
        ![@[@"prepared", @"dispatch-possible", @"recovery-required",
            @"unmutated-skipped"] containsObject:journal[@"state"] ?: @""]) {
        return NO;
    }
    NSArray<NSDictionary *> *variants = [journal[@"variants"]
        isKindOfClass:NSArray.class] ? journal[@"variants"] : nil;
    if (variants.count == 0) return NO;
    for (NSDictionary *variant in variants) {
        if (!CNDRemixVariantProvesNoIconServicesMutation(variant)) return NO;
    }
    return YES;
}

/* Native stock generation is not a themed publication. A source admission
 * failure after that generation must remain a failed Apply, but cannot by
 * itself claim themed data needs recovery. Live stock readback still decides
 * whether the recovery journal can be cleared. */
static BOOL CNDRemixReportProvesNoThemedIconServicesMutation(
    NSDictionary *publication)
{
    if (![publication isKindOfClass:NSDictionary.class]) return NO;
    for (NSString *key in @[
            @"ok", @"directStoreRemoveIssued", @"directStoreRemoveVerified",
            @"directStoreWriteIssued", @"directStoreWriteVerified",
            @"persistentIndexTokenWriteIssued", @"replacementPublished",
            @"installed", @"hookStillInstalledAtCleanup"]) {
        id value = publication[key];
        if (![value isKindOfClass:NSNumber.class] ||
            ![value isEqualToNumber:@NO]) return NO;
    }
    for (NSString *key in @[
            @"stockCaptured", @"stockGenerationInitiallyPersisted",
            @"stockGenerationPersisted", @"persistentIndexIdentitySettled",
            @"transportHealthy", @"transportLifecycleVerified",
            @"hookRestored", @"hookQuiescent"]) {
        id value = publication[key];
        if (![value isKindOfClass:NSNumber.class] ||
            ![value isEqualToNumber:@YES]) return NO;
    }
    return YES;
}

static BOOL CNDRemixJournalIsCompleteActiveMatrix(
    NSDictionary *journal, NSString *sourceHash,
    NSArray<CNDIconServicesDescriptorSpec *> *specifications)
{
    if ([journal[@"schemaVersion"] unsignedIntegerValue] !=
            CNDRemixIconServicesJournalSchemaVersion ||
        [journal[@"storePreservationPolicyVersion"] unsignedIntegerValue] !=
            CNDRemixStorePreservationPolicyVersion ||
        ![journal[@"state"] isEqualToString:@"active"] ||
        ![journal[@"themeSourceSHA256"] isEqualToString:sourceHash] ||
        ![journal[@"descriptorProfileIdentity"]
            isEqualToString:CNDRemixDescriptorProfileIdentity(
                specifications)]) return NO;
    NSArray *variants = CNDRemixJournalVariants(journal);
    if (variants.count != specifications.count) return NO;
    NSMutableSet *active = [NSMutableSet set];
    for (NSDictionary *variant in variants) {
        if (![variant[@"state"] isEqualToString:@"active"] ||
            ![variant[@"descriptorIdentity"] isKindOfClass:NSString.class])
            return NO;
        [active addObject:variant[@"descriptorIdentity"]];
    }
    for (CNDIconServicesDescriptorSpec *specification in specifications) {
        if (![active containsObject:specification.canonicalIdentity]) return NO;
    }
    return YES;
}

/* Permit a production descriptor-profile addition without forcing users to
 * restore every already-themed application first.  Expansion is safe only
 * when the active journal is an exact subset of the requested matrix: its
 * existing variants retain their original stock recovery reports, and the
 * publisher captures stock only for the newly missing descriptors. */
static BOOL CNDRemixJournalIsExpandableActiveMatrixSubset(
    NSDictionary *journal, NSString *sourceHash,
    NSArray<CNDIconServicesDescriptorSpec *> *specifications)
{
    if ([journal[@"schemaVersion"] unsignedIntegerValue] !=
            CNDRemixIconServicesJournalSchemaVersion ||
        [journal[@"storePreservationPolicyVersion"] unsignedIntegerValue] !=
            CNDRemixStorePreservationPolicyVersion ||
        ![journal[@"state"] isEqualToString:@"active"] ||
        ![journal[@"themeSourceSHA256"] isEqualToString:sourceHash]) return NO;
    NSArray<NSDictionary *> *variants = CNDRemixJournalVariants(journal);
    if (variants.count == 0 || variants.count >= specifications.count)
        return NO;
    NSMutableSet<NSString *> *requested = [NSMutableSet set];
    for (CNDIconServicesDescriptorSpec *specification in specifications) {
        [requested addObject:specification.canonicalIdentity];
    }
    NSMutableSet<NSString *> *active = [NSMutableSet set];
    for (NSDictionary *variant in variants) {
        NSString *identity = [variant[@"descriptorIdentity"]
            isKindOfClass:NSString.class]
            ? variant[@"descriptorIdentity"] : nil;
        if (![variant[@"state"] isEqualToString:@"active"] ||
            identity.length == 0 || ![requested containsObject:identity] ||
            [active containsObject:identity]) return NO;
        [active addObject:identity];
    }
    return active.count == variants.count;
}

static BOOL CNDRemixJournalMatchesCurrentApplication(
    NSDictionary *journal, NSString *sourceHash,
    NSArray<CNDIconServicesDescriptorSpec *> *specifications,
    NSDictionary *applicationFingerprint)
{
    return CNDRemixJournalIsCompleteActiveMatrix(
            journal, sourceHash, specifications) &&
        CNDRemixApplicationFingerprintMatches(
            journal[@"applicationFingerprint"], applicationFingerprint);
}

/* AirDrop journals created before source-registry verification can contain
 * perfectly themed store units that IconServices does not associate with the
 * pseudo-bundle's native provider.  They must not take the ordinary
 * already-active fast path: rotate the two-record journal through stock and
 * republish it once so Apply repairs and records both UUID -> source links. */
static BOOL CNDRemixAirDropJournalHasVerifiedSourceRegistry(
    NSDictionary *journal,
    NSArray<CNDIconServicesDescriptorSpec *> *specifications)
{
    NSArray<NSDictionary *> *variants = CNDRemixJournalVariants(journal);
    if (variants.count == 0 || variants.count != specifications.count) {
        return NO;
    }
    for (NSDictionary *variant in variants) {
        NSDictionary *publication = [variant[@"publication"]
            isKindOfClass:NSDictionary.class]
            ? variant[@"publication"] : nil;
        if (![variant[@"state"] isEqualToString:@"active"] ||
            ![publication[@"sourceRegistrationRequired"] boolValue] ||
            ![publication[@"sourceIdentifiersResolved"] boolValue] ||
            [publication[@"sourceIdentifierCount"] unsignedIntegerValue] == 0 ||
            ![publication[@"sourceRegistryFreshReadbackVerified"] boolValue]) {
            return NO;
        }
    }
    return YES;
}

static BOOL CNDRemixJournalProvesNoIconServicesMutation(
    NSDictionary *journal);

static BOOL CNDRemixJournalRepresentsDirtyPersistentData(
    NSDictionary *journal)
{
    if (![journal isKindOfClass:NSDictionary.class]) return NO;
    if (CNDRemixJournalProvesNoIconServicesMutation(journal)) return NO;
    /* A cleanup failure after exact stock readback may leave the checkpoint
     * file behind. Its presence is not evidence that the persistent store is
     * still themed. */
    return ![journal[@"state"]
        isEqualToString:@"persistent-stock-verified"];
}

static NSArray<NSString *> *CNDRemixActiveIconServicesBundleIdentifiers(void)
{
    NSMutableOrderedSet<NSString *> *identifiers =
        [NSMutableOrderedSet orderedSet];
    for (NSDictionary *journal in CNDRemixIconServicesJournals()) {
        /* A failed descriptor admission never changed a cache or store unit.
         * Do not arm consumer mappings merely because its conservative local
         * journal still awaits cleanup. */
        if (!CNDRemixJournalRepresentsDirtyPersistentData(journal)) continue;
        NSString *bundleIdentifier = [journal[@"bundleIdentifier"]
            isKindOfClass:NSString.class] ? journal[@"bundleIdentifier"] : nil;
        if (bundleIdentifier.length > 0) [identifiers addObject:bundleIdentifier];
    }
    return [identifiers.array sortedArrayUsingSelector:
        @selector(localizedCaseInsensitiveCompare:)];
}

/* Return the exact serialized 68-point response for one appearance that the
 * verified Calendar journal says is active.  The presentation repair uses
 * both appearance 0 and 1 as acceptance identities after it evicts Calendar's
 * process-local source cache; the raw theme PNG is not comparable with
 * IFCacheImage.data. Keep the payloads out of the journal itself and recover
 * them from the already validated, content-addressed payload cache. */
static NSData *CNDRemixActiveCalendar68StructuredResponse(
    NSInteger appearance)
{
    if (appearance != 0 && appearance != 1) return nil;
    NSString *bundleIdentifier = @"com.apple.mobilecal";
    NSDictionary *journal =
        CNDRemixReadIconServicesJournal(bundleIdentifier);
    if (![journal[@"state"] isEqualToString:@"active"] ||
        !CNDRemixJournalRepresentsDirtyPersistentData(journal)) {
        return nil;
    }

    CNDIconServicesDescriptorSpec *specification =
        [CNDIconServicesDescriptorSpec specWithPointWidth:68
            pointHeight:68 scale:3 appearance:appearance
            iconVariant:0 options:0];
    if (!specification) return nil;

    NSDictionary *matchedVariant = nil;
    for (NSDictionary *variant in CNDRemixJournalVariants(journal)) {
        if ([variant[@"state"] isEqualToString:@"active"] &&
            [variant[@"descriptorIdentity"]
                isEqualToString:specification.canonicalIdentity]) {
            matchedVariant = variant;
            break;
        }
    }
    NSString *sourceSHA256 = [matchedVariant[@"themeSourceSHA256"]
        isKindOfClass:NSString.class]
        ? matchedVariant[@"themeSourceSHA256"] : nil;
    if (sourceSHA256.length == 0) {
        sourceSHA256 = [journal[@"themeSourceSHA256"]
            isKindOfClass:NSString.class]
            ? journal[@"themeSourceSHA256"] : nil;
    }
    NSString *cacheKey = [matchedVariant[@"payloadCacheKey"]
        isKindOfClass:NSString.class]
        ? matchedVariant[@"payloadCacheKey"] : nil;
    NSString *expectedSHA256 = [matchedVariant[@"structuredImageSHA256"]
        isKindOfClass:NSString.class]
        ? matchedVariant[@"structuredImageSHA256"] : nil;
    if (!matchedVariant || sourceSHA256.length == 0 ||
        cacheKey.length == 0 || !CNDRemixIsSHA256String(expectedSHA256)) {
        return nil;
    }

    BOOL invalid = NO;
    NSDictionary *entry = CNDRemixReadPayloadCacheEntry(
        sourceSHA256, cacheKey, specification, &invalid);
    NSData *structured = [entry[@"structuredImageData"]
        isKindOfClass:NSData.class] ? entry[@"structuredImageData"] : nil;
    return !invalid && structured.length > 0 &&
        [CNDRemixSHA256(structured) isEqualToString:expectedSHA256]
        ? structured : nil;
}

static NSDictionary<NSString *, id> *
CNDRemixStaticDynamicIconDataFromThemeLookup(
    NSDictionary<NSString *, NSData *> *themeLookup,
    NSArray<NSString *> *active)
{
    NSMutableSet<NSString *> *foldedActive = [NSMutableSet set];
    for (NSString *identifier in active ?: @[]) {
        if ([identifier isKindOfClass:NSString.class] &&
            identifier.length > 0) {
            [foldedActive addObject:identifier.lowercaseString];
        }
    }
    BOOL wantsClock = [foldedActive containsObject:
        @"com.apple.mobiletimer"];
    BOOL wantsCalendar = [foldedActive containsObject:
        @"com.apple.mobilecal"];
    BOOL wantsFiles = [foldedActive containsObject:
        @"com.apple.DocumentsApp".lowercaseString];
    if (!wantsClock && !wantsCalendar && !wantsFiles) return @{};

    NSMutableDictionary<NSString *, NSData *> *result =
        [NSMutableDictionary dictionaryWithCapacity:8];
    if (wantsClock &&
        themeLookup[@"com.apple.mobiletimer"].length > 0) {
        result[@"com.apple.mobiletimer"] =
            themeLookup[@"com.apple.mobiletimer"];
    }
    if (wantsCalendar &&
        themeLookup[@"com.apple.mobilecal"].length > 0) {
        result[@"com.apple.mobilecal"] =
            themeLookup[@"com.apple.mobilecal"];
        NSData *structured68Appearance0 =
            CNDRemixActiveCalendar68StructuredResponse(0);
        NSData *structured68Appearance1 =
            CNDRemixActiveCalendar68StructuredResponse(1);
        if (structured68Appearance0.length > 0) {
            result[@"__cnd_calendar_68_structured"] =
                structured68Appearance0;
        }
        if (structured68Appearance1.length > 0) {
            result[@"__cnd_calendar_68_structured_a1"] =
                structured68Appearance1;
        }
        /* The exact Calendar provider bridge consumes the same canonical
         * com.apple.mobilecal descriptor matrix published by Apply. Do not
         * stage a separate face: the two serialized responses above are
         * verification inputs only. Apple's provider still owns the outer
         * presentation size and layer conversion. */
    }
    if (wantsFiles &&
        themeLookup[@"com.apple.DocumentsApp"].length > 0) {
        /* Spotlight presents the local File Provider root as a Quick Look
         * folder thumbnail. Its SearchUIDetailedRowModel already carries a
         * Files SearchUIAppIconImage fallback, so pass only an activation
         * marker; the target process resolves the persistent themed icon. */
        result[@"com.apple.DocumentsApp"] =
            themeLookup[@"com.apple.DocumentsApp"];
    }
    if (wantsClock) {
        for (NSString *componentKey in @[
                @"__cnd_clock_hours",
                @"__cnd_clock_minutes",
                @"__cnd_clock_seconds",
                @"__cnd_clock_hour_minute_dot",
                @"__cnd_clock_second_dot",
            ]) {
            NSData *component = themeLookup[componentKey];
            if (component.length > 0) result[componentKey] = component;
        }

        /* Keep the live Clock face separate from its normal application icon.
         * The five hand images are independent, already supported inputs;
         * staging a face is not verification of clock.base replacement. */
        NSData *rawBackground = themeLookup[@"__cnd_clock_background"];
        CGFloat scale = UIScreen.mainScreen.scale;
        NSUInteger pixels = (NSUInteger)llround(68.0 * scale);
        if (rawBackground.length > 0 && pixels > 0) {
            NSError *renderError = nil;
            NSDictionary<NSString *, id> *processed =
                CNDProcessIconThemePNG(rawBackground, pixels, pixels, 0,
                                       &renderError);
            NSData *scaledPNG = [processed[@"unpaddedBytes"]
                isKindOfClass:NSData.class]
                ? processed[@"unpaddedBytes"] : nil;
            BOOL renderVerified = scaledPNG.length > 0 &&
                [processed[@"completeDecodeVerified"] boolValue] &&
                [processed[@"alphaClassesPreserved"] boolValue];
            if (renderVerified) {
                result[@"__cnd_clock_background"] = scaledPNG;
            } else {
                log_user("[SBR_DYNAMIC_ICONS] Clock background staging failed render=%s reason=%s\n",
                         renderVerified ? "yes" : "no",
                         (renderError.localizedDescription ?:
                          @"validation failed").UTF8String ?: "-");
            }
        }
    }
    return result;
}

static NSDictionary<NSString *, id> *
CNDRemixReconcilePresentationLifecycle(void)
{
    NSArray<NSString *> *active =
        CNDRemixActiveIconServicesBundleIdentifiers();
    themer_set_springboard_iconservices_refresh_bundle_identifiers(active);
    BOOL enabled = [NSUserDefaults.standardUserDefaults
        boolForKey:kSettingsSnowBoardRemixInstallConsumerMappings];
    return @{
        @"ok": @YES,
        @"stage": @"queued-repair-required",
        @"message": @"Persistent icon publication is independent of presentation repair. Queue SpringBoard Fixes and Spotlight Fixes separately to install their process-local repairs and the retained Spotlight assertion.",
        @"desired": @(enabled && active.count > 0),
        @"enabled": @(enabled),
        @"activeBundleIdentifiers": active,
        @"springBoardWatcherEnabled": @NO,
        @"watcherAutoStart": @NO,
        @"spotlightReady": @NO,
        @"watcherStatus": @{},
        @"remoteCallUsed": @NO,
    };
}

static NSDictionary<NSString *, id> *
CNDRemixRunInitialCacheRefresh(void)
{
    if (!CNDRemixEnableSpringBoardCacheInvalidation) {
        log_user("[SBR_PRESENTATION] post-publication cache refresh "
                 "springboard=disabled-experiment transparency=no "
                 "dynamic-icons=no watcher-started=no completed=yes\n");
        return @{
            @"ok": @YES,
            @"stage": @"cache-invalidation-disabled-experiment",
            @"message": @"Persistent publication completed; SpringBoard cache invalidation is disabled for the current experiment.",
            @"queued": @NO,
            @"completed": @YES,
            @"springBoard": @{
                @"ok": @YES,
                @"stage": @"cache-invalidation-disabled-experiment",
                @"remoteCallUsed": @NO,
            },
            @"spotlight": @{
                @"ok": @YES, @"stage": @"manual-action-required",
                @"remoteCallUsed": @NO,
            },
            @"cacheInvalidationIssued": @NO,
            @"springBoardCacheRefreshQueued": @NO,
            @"springBoardCacheRefreshCompleted": @NO,
            @"transparencyRepairQueued": @NO,
            @"transparencyRepairCompleted": @NO,
            @"dynamicIconRepairCompleted": @NO,
            @"watcherStarted": @NO,
            @"remoteCallUsed": @NO,
        };
    }
    NSDictionary<NSString *, id> *springBoard =
        CNDIconServicesConsumerLifecycleRefreshSpringBoardCaches();
    BOOL ok = [springBoard[@"ok"] boolValue];
    log_user("[SBR_PRESENTATION] post-publication cache refresh "
             "springboard=%s/%s transparency=no dynamic-icons=no "
             "watcher-started=no completed=yes\n",
             ok ? "ok" : "failed",
             [springBoard[@"stage"] UTF8String] ?: "unknown");
    return @{
        @"ok": @(ok),
        @"stage": ok ? @"cache-refresh-complete" : @"cache-refresh-failed",
        @"message": ok
            ? @"Persistent publication and the SpringBoard cache refresh completed. Presentation tweaks remain separate manual actions."
            : @"The post-publication SpringBoard cache refresh did not complete.",
        @"queued": @NO,
        @"completed": @YES,
        @"springBoard": springBoard ?: @{},
        @"spotlight": @{
            @"ok": @YES, @"stage": @"manual-action-required",
            @"remoteCallUsed": @NO,
        },
        @"springBoardCacheRefreshQueued": @NO,
        @"springBoardCacheRefreshCompleted": @(ok),
        @"cacheInvalidationIssued": @YES,
        @"transparencyRepairQueued": @NO,
        @"transparencyRepairCompleted": @NO,
        @"dynamicIconRepairCompleted": @NO,
        @"watcherStarted": @NO,
        @"remoteCallUsed": springBoard[@"remoteCallUsed"] ?: @NO,
    };
}

static NSDictionary<NSString *, id> *
CNDRemixRefreshAirDropPresentationIfNeeded(BOOL required)
{
    if (!required) {
        return @{
            @"ok": @YES,
            @"stage": @"not-required",
            @"message": @"No verified AirDrop pseudo-bundle mutation requires a Share sheet consumer refresh.",
            @"remoteCallUsed": @NO,
        };
    }
    return CNDIconServicesConsumerHookRetireSharingUIService() ?: @{
        @"ok": @NO,
        @"stage": @"sharing-ui-refresh",
        @"message": @"The Share sheet cache-owner refresh returned no report.",
        @"remoteCallUsed": @NO,
    };
}

static NSURL *CNDRemixIndexURL(void)
{
    NSURL *root = [CNDIconThemeTransaction transactionsDirectoryURL]
        .URLByDeletingLastPathComponent;
    return [root URLByAppendingPathComponent:@"BatchIndex.plist"
                                 isDirectory:NO];
}

static NSDictionary *CNDRemixCoordinatorResult(BOOL ok, NSString *stage,
                                                NSString *message,
                                                NSDictionary *details)
{
    NSMutableDictionary *result = details ? [details mutableCopy] :
        [NSMutableDictionary dictionary];
    result[@"ok"] = @(ok);
    result[@"stage"] = stage ?: @"unknown";
    result[@"message"] = message ?: @"";
    result[@"recoveryRequired"] = @([CNDSnowBoardRemix hasRecoveryData]);
    return result;
}

static NSDictionary *CNDRemixResultByAddingElapsedTime(
    NSDictionary *result,
    NSTimeInterval startedAt,
    NSString *operation)
{
    NSTimeInterval elapsed = MAX(0.0,
        NSProcessInfo.processInfo.systemUptime - startedAt);
    unsigned long long elapsedMilliseconds =
        (unsigned long long)llround(elapsed * 1000.0);
    NSMutableDictionary *timed = [result isKindOfClass:NSDictionary.class]
        ? [result mutableCopy] : [NSMutableDictionary dictionary];
    timed[@"elapsedSeconds"] = @(elapsed);
    timed[@"elapsedMilliseconds"] = @(elapsedMilliseconds);
    timed[@"elapsedDisplay"] = [NSString stringWithFormat:@"%.3f seconds", elapsed];
    timed[@"timedOperation"] = operation ?: @"operation";
    log_user("[SBR_TIME] %s finished in %.3f seconds (%llu ms) result=%s stage=%s\n",
             operation.UTF8String ?: "operation",
             elapsed,
             elapsedMilliseconds,
             [timed[@"ok"] boolValue] ? "success" : "failed",
             [timed[@"stage"] UTF8String] ?: "unknown");
    return timed;
}

static void CNDRemixLogAlphaSnapshot(NSString *bundleIdentifier,
                                      NSDictionary *result,
                                      NSDictionary *journal,
                                      NSMutableSet<NSString *> *loggedKeys)
{
    NSDictionary *file = [journal[@"fileMutation"] isKindOfClass:NSDictionary.class]
        ? journal[@"fileMutation"] : @{};
    NSDictionary *processing = [file[@"processing"] isKindOfClass:NSDictionary.class]
        ? file[@"processing"] : @{};
    NSDictionary *decodedAlpha = [processing[@"alphaDecodedMetrics"]
        isKindOfClass:NSDictionary.class] ? processing[@"alphaDecodedMetrics"] : @{};
    NSDictionary *expectedAlpha = [processing[@"alphaExpectedMetrics"]
        isKindOfClass:NSDictionary.class] ? processing[@"alphaExpectedMetrics"] : @{};
    NSDictionary *canonical = [result[@"canonicalIconServicesVerification"]
        isKindOfClass:NSDictionary.class]
        ? result[@"canonicalIconServicesVerification"]
        : ([journal[@"canonicalIconServicesVerification"]
            isKindOfClass:NSDictionary.class]
            ? journal[@"canonicalIconServicesVerification"] : @{});
    if (decodedAlpha.count == 0 && canonical.count == 0) return;
    NSString *alphaLogKey = [@"alpha:" stringByAppendingString:bundleIdentifier ?: @""];
    if ([loggedKeys containsObject:alphaLogKey]) return;
    [loggedKeys addObject:alphaLogKey];
    NSString *canonicalStage = [canonical[@"stage"] isKindOfClass:NSString.class]
        ? canonical[@"stage"] : @"not-run";
    log_user("[SBR_ALPHA] app=%s staged=%lu/%lu/%lu expected=%lu/%lu/%lu preserved=%d iconservices=%lu/%lu/%lu verified=%d stage=%s\n",
             bundleIdentifier.UTF8String ?: "?",
             (unsigned long)[decodedAlpha[@"transparentPixelCount"] unsignedIntegerValue],
             (unsigned long)[decodedAlpha[@"partialAlphaPixelCount"] unsignedIntegerValue],
             (unsigned long)[decodedAlpha[@"opaquePixelCount"] unsignedIntegerValue],
             (unsigned long)[expectedAlpha[@"transparentPixelCount"] unsignedIntegerValue],
             (unsigned long)[expectedAlpha[@"partialAlphaPixelCount"] unsignedIntegerValue],
             (unsigned long)[expectedAlpha[@"opaquePixelCount"] unsignedIntegerValue],
             [processing[@"alphaClassesPreserved"] boolValue],
             (unsigned long)[canonical[@"transparentPixelCount"] unsignedIntegerValue],
             (unsigned long)[canonical[@"partialAlphaPixelCount"] unsignedIntegerValue],
             (unsigned long)[canonical[@"opaquePixelCount"] unsignedIntegerValue],
             [canonical[@"ok"] boolValue],
             canonicalStage.UTF8String ?: "not-run");
}

static void CNDRemixLogTransactionResult(NSString *bundleIdentifier,
                                          NSDictionary *result,
                                          NSDictionary *journal,
                                          NSMutableSet<NSString *> *loggedKeys)
{
    if (![bundleIdentifier isKindOfClass:NSString.class] ||
        bundleIdentifier.length == 0 || ![result isKindOfClass:NSDictionary.class]) {
        return;
    }
    NSDictionary *file = [journal[@"fileMutation"] isKindOfClass:NSDictionary.class]
        ? journal[@"fileMutation"] : @{};
    NSDictionary *diagnostic = [result[@"remixDiagnostic"] isKindOfClass:NSDictionary.class]
        ? result[@"remixDiagnostic"] : @{};
    CNDRemixLogAlphaSnapshot(bundleIdentifier, result, journal, loggedKeys);
    NSString *mode = [file[@"mode"] isKindOfClass:NSString.class]
        ? file[@"mode"] : result[@"fileMode"];
    if (![mode isKindOfClass:NSString.class] || mode.length == 0) mode = @"unknown";
    NSString *base = [file[@"declaredBaseName"] isKindOfClass:NSString.class]
        ? file[@"declaredBaseName"] : result[@"declaredBaseName"];
    NSString *leaf = [file[@"relativePath"] isKindOfClass:NSString.class]
        ? file[@"relativePath"] : result[@"relativePath"];
    if (![base isKindOfClass:NSString.class]) base = diagnostic[@"chosenBase"];
    if (![leaf isKindOfClass:NSString.class]) leaf = diagnostic[@"chosenLeaf"];
    if (![base isKindOfClass:NSString.class]) base = @"-";
    if (![leaf isKindOfClass:NSString.class]) leaf = @"-";
    NSUInteger width = [file[@"width"] unsignedIntegerValue];
    NSUInteger height = [file[@"height"] unsignedIntegerValue];
    if (width == 0) width = [result[@"width"] unsignedIntegerValue];
    if (height == 0) height = [result[@"height"] unsignedIntegerValue];
    NSString *dimensionsSource = [file[@"dimensionsSource"] isKindOfClass:NSString.class]
        ? file[@"dimensionsSource"] : diagnostic[@"dimensionsSource"];
    if (![dimensionsSource isKindOfClass:NSString.class] ||
        dimensionsSource.length == 0) dimensionsSource = @"-";

    NSString *plistFit = [diagnostic[@"plistFit"] isKindOfClass:NSString.class]
        ? diagnostic[@"plistFit"] : nil;
    if (plistFit.length == 0) {
        NSUInteger originalLength = [result[@"infoOriginalLength"] unsignedIntegerValue];
        NSUInteger replacementLength = [result[@"infoReplacementLength"] unsignedIntegerValue];
        if (originalLength > 0 && replacementLength > 0 &&
            replacementLength <= originalLength) {
            plistFit = @"fit";
        } else if ([result[@"stage"] hasPrefix:@"plist"] ||
                   [result[@"stage"] isEqual:@"registration-guard"]) {
            plistFit = @"no-fit";
        } else {
            plistFit = @"unknown";
        }
    }

    NSString *creation = [diagnostic[@"creationResult"] isKindOfClass:NSString.class]
        ? diagnostic[@"creationResult"] : nil;
    if (creation.length == 0) {
        if (![mode isEqual:@"create"]) {
            creation = @"not-applicable";
        } else if ([result[@"ok"] boolValue] ||
                   [result[@"stage"] isEqual:@"pending"] ||
                   [result[@"stage"] isEqual:@"active"]) {
            creation = @"created";
        } else if ([result[@"stage"] isEqual:@"target-discovery"] ||
                   [result[@"stage"] isEqual:@"theme-fit"] ||
                   [result[@"stage"] hasSuffix:@"stage"]) {
            creation = @"not-run";
        } else {
            creation = @"failed";
        }
    }

    NSString *registration = nil;
    NSDictionary *registrationResult = [result[@"registration"] isKindOfClass:NSDictionary.class]
        ? result[@"registration"] : nil;
    if (registrationResult) {
        registration = [registrationResult[@"ok"] boolValue] ? @"accepted" : @"failed";
    } else if ([result[@"stage"] isEqual:@"active"] ||
               [result[@"stage"] isEqual:@"pending"]) {
        registration = @"accepted";
    } else if ([result[@"stage"] isEqual:@"registration"]) {
        registration = @"failed";
    } else {
        registration = diagnostic[@"registrationResult"];
        if (![registration isKindOfClass:NSString.class] || registration.length == 0) {
            registration = @"not-run";
        }
    }

    NSString *rollback = nil;
    for (NSString *key in @[ @"fileRollbackFailure", @"infoRollbackFailure",
                             @"effectiveRegistrationFailure" ]) {
        NSString *candidate = [result[key] isKindOfClass:NSString.class]
            ? result[key] : nil;
        if (candidate.length > 0) {
            rollback = candidate;
            break;
        }
    }
    if (rollback.length == 0) {
        if ([result[@"ok"] boolValue]) {
            rollback = @"none";
        } else if (result[@"fileRollbackSucceeded"] != nil ||
                   result[@"infoRollbackSucceeded"] != nil ||
                   result[@"rollbackRegistrationSucceeded"] != nil) {
            BOOL fileOK = result[@"fileRollbackSucceeded"] == nil ||
                [result[@"fileRollbackSucceeded"] boolValue];
            BOOL infoOK = result[@"infoRollbackSucceeded"] == nil ||
                [result[@"infoRollbackSucceeded"] boolValue];
            BOOL registrationOK = result[@"rollbackRegistrationSucceeded"] == nil ||
                [result[@"rollbackRegistrationSucceeded"] boolValue];
            rollback = fileOK && infoOK && registrationOK ? @"verified" : @"failed";
        } else {
            rollback = diagnostic[@"rollbackReason"] ?: @"not-attempted";
        }
    }
    NSString *reason = [result[@"message"] isKindOfClass:NSString.class]
        ? result[@"message"] : @"unknown";
    NSString *stage = [result[@"stage"] isKindOfClass:NSString.class]
        ? result[@"stage"] : @"unknown";
    BOOL successfulCreation = [result[@"ok"] boolValue] && [mode isEqual:@"create"];
    if ([result[@"ok"] boolValue] && !successfulCreation) return;
    NSString *logKey = successfulCreation ? @"created-fallback" : stage;
    if ([loggedKeys containsObject:logKey]) return;
    [loggedKeys addObject:logKey];
    log_user("[SBR] app=%s stage=%s mode=%s base=%s leaf=%s dims=%lux%lu source=%s plist=%s create=%s register=%s reason=%s rollback=%s\n",
             bundleIdentifier.UTF8String ?: "?",
             stage.UTF8String ?: "unknown",
             mode.UTF8String ?: "unknown",
             base.UTF8String ?: "-",
             leaf.UTF8String ?: "-",
             (unsigned long)width,
             (unsigned long)height,
             dimensionsSource.UTF8String ?: "-",
             plistFit.UTF8String ?: "unknown",
             creation.UTF8String ?: "unknown",
             registration.UTF8String ?: "unknown",
             reason.UTF8String ?: "unknown",
             rollback.UTF8String ?: "none");
}

static BOOL CNDRemixWriteIndex(NSDictionary *summary, NSError **errorOut)
{
    NSURL *url = CNDRemixIndexURL();
    if (![NSFileManager.defaultManager createDirectoryAtURL:
            url.URLByDeletingLastPathComponent withIntermediateDirectories:YES
            attributes:@{NSFileProtectionKey: NSFileProtectionNone} error:errorOut]) {
        return NO;
    }
    NSMutableDictionary *index = [summary mutableCopy];
    index[@"schemaVersion"] = @1;
    index[@"updatedAt"] = NSDate.date;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:index
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:errorOut];
    if (!data || ![data writeToURL:url options:NSDataWritingAtomic error:errorOut]) return NO;
    NSDictionary *readback = [NSDictionary dictionaryWithContentsOfURL:url];
    return [readback isEqual:index];
}

static NSDictionary *CNDRemixCompactResponseIdentity(NSDictionary *response)
{
    if (![response isKindOfClass:NSDictionary.class]) return @{};
    NSMutableDictionary *compact = [NSMutableDictionary dictionary];
    for (NSString *key in @[
        @"dataLength", @"dataSHA256", @"uuid", @"validationTokenLength",
        @"validationTokenSHA256", @"themeMarkerPresent"
    ]) {
        if (response[key]) compact[key] = response[key];
    }
    return compact;
}

static NSDictionary *CNDRemixCompactPublisherReport(NSDictionary *report)
{
    if (![report isKindOfClass:NSDictionary.class]) return @{};
    NSMutableDictionary *compact = [report mutableCopy];
    compact[@"stockResponse"] = CNDRemixCompactResponseIdentity(
        report[@"stockResponse"]);
    compact[@"agentCacheResponse"] = CNDRemixCompactResponseIdentity(
        report[@"agentCacheResponse"]);
    return compact;
}

/* A failed AirDrop publication can roll its pixels back to stock while
 * leaving a recovery journal behind because the pseudo-bundle source map was
 * not yet repairable.  Do not strand that journal forever.  Accept the
 * current record as clean only when a getter-only audit proves the exact
 * indexed store unit contains the captured stock bytes. For a rejected
 * publication with no themed writes, its captured stock UUID and token bind
 * that proof even if the process cache is empty. Otherwise require cache and
 * store to agree and no longer carry the themed token. Source proof is not part
 * of stock cleanliness: it is required before publishing themed bytes, but a
 * missing association cannot make byte-exact stock data dirty. */
static BOOL CNDRemixAuditProvesSavedStock(
    NSDictionary *audit, NSDictionary *savedVariant)
{
    if (![audit isKindOfClass:NSDictionary.class] ||
        ![savedVariant isKindOfClass:NSDictionary.class]) return NO;
    NSDictionary *publication = [savedVariant[@"publication"]
        isKindOfClass:NSDictionary.class] ? savedVariant[@"publication"] : @{};
    NSDictionary *stock = [publication[@"stockResponse"]
        isKindOfClass:NSDictionary.class] ? publication[@"stockResponse"] : @{};
    NSDictionary *restoration = [savedVariant[@"restoration"]
        isKindOfClass:NSDictionary.class] ? savedVariant[@"restoration"] : @{};
    /* A prior Restore may have captured and persisted fresh stock before a
     * source-association check failed. Keep that byte baseline usable even
     * when the original publication failed before capturing any stock. */
    NSDictionary *restoredStock = [restoration[@"stockResponse"]
        isKindOfClass:NSDictionary.class]
        ? restoration[@"stockResponse"] : @{};
    NSDictionary *themed = [publication[@"agentCacheResponse"]
        isKindOfClass:NSDictionary.class]
        ? publication[@"agentCacheResponse"] : @{};
    NSString *expectedStockHash = CNDRemixCatalogText(stock, @"dataSHA256");
    NSString *expectedStockIdentifier = CNDRemixCatalogText(stock, @"uuid");
    NSString *expectedStockToken =
        CNDRemixCatalogText(stock, @"validationTokenSHA256");
    NSString *restoredStockHash =
        [restoration[@"stockCaptured"] boolValue] &&
        [restoration[@"stockGenerationPersisted"] boolValue]
            ? CNDRemixCatalogText(restoredStock, @"dataSHA256") : @"";
    NSString *expectedThemedHash = CNDRemixCatalogText(
        savedVariant, @"structuredImageSHA256");
    NSString *themedTokenHash = CNDRemixCatalogText(
        themed, @"validationTokenSHA256");
    NSString *cacheHash = CNDRemixCatalogText(audit, @"cacheDataSHA256");
    NSString *storeHash = CNDRemixCatalogText(audit, @"storeDataSHA256");
    NSString *storeTokenHash = CNDRemixCatalogText(
        audit, @"storeValidationTokenSHA256");
    NSString *indexedIdentifier = CNDRemixCatalogText(
        audit, @"indexedIdentifier");
    NSString *storeIdentifier = CNDRemixCatalogText(
        audit, @"storeIdentifier");
    NSString *stage = CNDRemixCatalogText(audit, @"stage");
    BOOL observationReachedOnlyTheSourceBoundary =
        [audit[@"ok"] boolValue] ||
        [stage hasPrefix:@"audit-source-"] ||
        [stage isEqualToString:@"audit-current-source-provider"];
    BOOL matchesCapturedStock =
        (CNDRemixIsSHA256String(expectedStockHash) &&
         [cacheHash caseInsensitiveCompare:expectedStockHash] ==
            NSOrderedSame &&
         [storeHash caseInsensitiveCompare:expectedStockHash] ==
            NSOrderedSame) ||
        (CNDRemixIsSHA256String(restoredStockHash) &&
         [cacheHash caseInsensitiveCompare:restoredStockHash] ==
            NSOrderedSame &&
         [storeHash caseInsensitiveCompare:restoredStockHash] ==
            NSOrderedSame);
    BOOL persistentReadbackComplete = observationReachedOnlyTheSourceBoundary &&
        [audit[@"transportHealthy"] boolValue] &&
        audit[@"persistentMutationsIssued"] &&
        ![audit[@"persistentMutationsIssued"] boolValue] &&
        audit[@"generationIssued"] && ![audit[@"generationIssued"] boolValue] &&
        [audit[@"storeIndexLookupReady"] boolValue] &&
        [audit[@"storeIndexEntryPresent"] boolValue] &&
        [audit[@"storeUnitPresent"] boolValue] &&
        [audit[@"storeUnitValid"] boolValue] &&
        [audit[@"storeIndexUnitIdentifierEqual"] boolValue] &&
        CNDRemixIsSHA256String(expectedThemedHash) &&
        [storeHash caseInsensitiveCompare:expectedThemedHash] !=
            NSOrderedSame &&
        CNDRemixIsSHA256String(storeHash) &&
        indexedIdentifier.length > 0 && storeIdentifier.length > 0 &&
        [indexedIdentifier isEqualToString:storeIdentifier] &&
        CNDRemixIsSHA256String(storeTokenHash) &&
        (!CNDRemixIsSHA256String(themedTokenHash) ||
         [storeTokenHash caseInsensitiveCompare:themedTokenHash] !=
            NSOrderedSame);
    if (!persistentReadbackComplete) return NO;
    BOOL unpublishedStock =
        CNDRemixReportProvesNoThemedIconServicesMutation(publication) &&
        CNDRemixIsSHA256String(expectedStockHash) &&
        CNDRemixIsSHA256String(expectedStockToken) &&
        expectedStockIdentifier.length > 0 &&
        [indexedIdentifier isEqualToString:expectedStockIdentifier] &&
        [storeHash caseInsensitiveCompare:expectedStockHash] == NSOrderedSame &&
        [storeTokenHash caseInsensitiveCompare:expectedStockToken] == NSOrderedSame;
    BOOL cacheAndStoreStock =
        [audit[@"canonicalCacheReadReady"] boolValue] &&
        [audit[@"cacheResponsePresent"] boolValue] &&
        [audit[@"cacheStoreEqual"] boolValue] &&
        [audit[@"cacheStoreIdentifierEqual"] boolValue] &&
        [audit[@"cacheStoreValidationTokenEqual"] boolValue] &&
        CNDRemixIsSHA256String(cacheHash) && matchesCapturedStock;
    return unpublishedStock || cacheAndStoreStock;
}

static NSDictionary *CNDRemixCompactStockReadbackAudit(NSDictionary *audit)
{
    if (![audit isKindOfClass:NSDictionary.class]) return @{};
    NSMutableDictionary *compact = [NSMutableDictionary dictionary];
    for (NSString *key in @[
            @"ok", @"stage", @"transportHealthy",
            @"canonicalCacheReadReady", @"cacheResponsePresent",
            @"cacheDataSHA256", @"cacheIdentifier",
            @"storeIndexLookupReady", @"storeIndexEntryPresent",
            @"indexedIdentifier", @"storeValidationTokenSHA256",
            @"storeUnitPresent", @"storeUnitValid", @"storeDataSHA256",
            @"storeIdentifier", @"cacheStoreEqual",
            @"cacheStoreIdentifierEqual",
            @"cacheStoreValidationTokenEqual",
            @"storeIndexUnitIdentifierEqual", @"sourceIdentityAuditReady",
            @"sourceRegistryEntryCount", @"persistentMutationsIssued",
            @"generationIssued", @"mutationsIssued"]) {
        if (audit[key]) compact[key] = audit[key];
    }
    return compact;
}

/* Apply may encounter a failed/rolled-back AirDrop journal or a stock
 * checkpoint whose local deletion failed. Reconcile against live readers
 * before that recovery metadata can block another publication. A partial
 * observation never removes the recovery record. */
static BOOL CNDRemixReconcileAirDropJournalToCurrentStockInBatch(
    NSString *bundleIdentifier, NSDictionary *savedJournal)
{
    if (!CNDRemixIsSupportedPseudoBundleIdentifier(bundleIdentifier) ||
        [savedJournal[@"schemaVersion"] unsignedIntegerValue] !=
            CNDRemixIconServicesJournalSchemaVersion) return NO;
    NSArray<NSDictionary *> *savedVariants =
        CNDRemixJournalVariants(savedJournal);
    if (savedVariants.count == 0) return NO;
    NSMutableArray<NSDictionary *> *updatedVariants = [NSMutableArray array];
    for (NSDictionary *savedVariant in savedVariants) {
        NSMutableDictionary *updated = [savedVariant mutableCopy];
        if (CNDRemixVariantProvesNoIconServicesMutation(savedVariant)) {
            updated[@"state"] = @"unmutated-skipped";
        } else {
            CNDIconServicesDescriptorSpec *specification =
                [CNDIconServicesDescriptorSpec specWithDictionary:
                    savedVariant[@"descriptorSpecification"] error:nil];
            if (!specification || !CNDIconServicesPublisherBatchIsHealthy()) {
                return NO;
            }
            NSDictionary *audit = CNDIconServicesPublisherAuditVariantInBatch(
                bundleIdentifier, specification.dictionaryRepresentation);
            if (!CNDRemixAuditProvesSavedStock(audit, savedVariant)) return NO;
            updated[@"stockReadbackAudit"] =
                CNDRemixCompactStockReadbackAudit(audit);
            updated[@"state"] = @"persistent-stock-verified";
        }
        updated[@"updatedAt"] = NSDate.date;
        [updatedVariants addObject:updated];
    }
    NSMutableDictionary *journal = [savedJournal mutableCopy];
    journal[@"variants"] = updatedVariants;
    journal[@"state"] = @"persistent-stock-verified";
    journal[@"updatedAt"] = NSDate.date;
    BOOL saved = CNDRemixWriteIconServicesJournal(journal);
    BOOL removed = CNDRemixRemoveIconServicesJournal(bundleIdentifier);
    log_user("[SBR_AIRDROP_RECOVERY] reconciled-stock variants=%lu "
             "checkpoint=%d journal-cleared=%d mutations=0\n",
             (unsigned long)updatedVariants.count, saved, removed);
    /* Live readback is the truth. The next pre-publication checkpoint must
     * survive exact readback before Apply can issue any write, even if this
     * clean old journal could not be saved or removed. */
    return YES;
}

static void CNDRemixLogIconServicesTransaction(
    const char *action,
    NSString *bundleIdentifier,
    NSDictionary *report,
    BOOL verified)
{
    if (![report isKindOfClass:NSDictionary.class]) report = @{};
    /* Successful transactions already have one ordered progress line. Avoid
     * repeating the service's long explanatory message and a dozen internal
     * booleans for every app; retain the full report in the journal/index and
     * emit the detailed line only when a transaction needs diagnosis. */
    if (verified) return;
    NSString *stage = report[@"stage"] ?: @"unknown";
    NSString *reason = report[@"message"] ?: @"";
    NSDictionary *descriptor = [report[@"descriptorSpecification"]
        isKindOfClass:NSDictionary.class]
        ? report[@"descriptorSpecification"] : @{};
    NSDictionary *descriptorDiagnostics = [report[@"descriptorDiagnostics"]
        isKindOfClass:NSDictionary.class]
        ? report[@"descriptorDiagnostics"] : @{};
    NSString *factoryTypes = [descriptorDiagnostics[@"factoryTypes"]
        isKindOfClass:NSString.class]
        ? descriptorDiagnostics[@"factoryTypes"] : @"-";
    log_user("[SBR_%s] app=%s verified=%d stage=%s reason=%s "
             "descriptor=%lux%lu@%lu:a%lu:v%lu:o%lu factory-abi=%s "
             "stock=%d initial-stock=%d remove=%d/%d write=%d/%d "
             "rollback=%d/%d index=%d/%d/%d index-attempts=%lu "
             "cache=%d store=%d transport=%d lifecycle=%d\n",
             action ?: "TRANSACTION",
             bundleIdentifier.UTF8String ?: "?",
             verified,
             stage.UTF8String ?: "unknown",
             reason.UTF8String ?: "",
             (unsigned long)[descriptor[@"pointWidth"] unsignedIntegerValue],
             (unsigned long)[descriptor[@"pointHeight"] unsignedIntegerValue],
             (unsigned long)[descriptor[@"scale"] unsignedIntegerValue],
             (unsigned long)[descriptor[@"appearance"] unsignedIntegerValue],
             (unsigned long)[descriptor[@"iconVariant"] unsignedIntegerValue],
             (unsigned long)[descriptor[@"options"] unsignedIntegerValue],
             factoryTypes.UTF8String ?: "-",
             [report[@"stockCaptured"] boolValue],
             [report[@"stockGenerationInitiallyPersisted"] boolValue],
             [report[@"directStoreRemoveIssued"] boolValue],
             [report[@"directStoreRemoveVerified"] boolValue],
             [report[@"directStoreWriteIssued"] boolValue],
             [report[@"directStoreWriteVerified"] boolValue],
             [report[@"immediateStoreRollbackAttempted"] boolValue],
             [report[@"immediateStoreRollbackSucceeded"] boolValue],
             [report[@"persistentIndexIdentitySettled"] boolValue],
             [report[@"persistentIndexTokenWriteVerified"] boolValue],
             [report[@"persistentIndexTokenLookupVerified"] boolValue],
             (unsigned long)[report[@"persistentIndexIdentityAttempts"]
                 unsignedIntegerValue],
             [report[@"agentCacheReadbackVerified"] boolValue],
             [report[@"persistentStoreReadbackVerified"] boolValue],
             [report[@"transportHealthy"] boolValue],
             [report[@"transportLifecycleVerified"] boolValue]);
}

/*
 * Preserve the established RemoteCall publisher behavior while the strict
 * cache/store verifier is still unavailable. This is deliberately separate
 * from CNDIconServicesPublisher*ResultIsVerified(): provisional acceptance
 * remains visible in the journal and cannot masquerade as deep proof.
 */
static BOOL CNDRemixPublisherResultIsLegacyAcceptable(
    NSDictionary *result, NSString *expectedMode)
{
    if (![result isKindOfClass:NSDictionary.class] ||
        ![result[@"acceptancePolicy"]
            isEqual:@"legacy-remote-call-provisional"] ||
        ![result[@"legacyAcceptanceEligible"] boolValue] ||
        ![result[@"verificationStatus"] isEqual:@"unverified-benchmark"] ||
        ![result[@"deepVerificationSkippedForBenchmark"] boolValue] ||
        ![result[@"mode"] isEqual:expectedMode] ||
        ![result[@"ok"] boolValue] ||
        ![result[@"operationCompleted"] boolValue] ||
        ![result[@"transportHealthy"] boolValue] ||
        ![result[@"transportLifecycleVerified"] boolValue] ||
        [result[@"transportAbandoned"] boolValue] ||
        ![result[@"hookRestored"] boolValue] ||
        ![result[@"hookQuiescent"] boolValue] ||
        [result[@"hookStillInstalledAtCleanup"] boolValue] ||
        ![result[@"payloadLifecycleVerified"] boolValue] ||
        ![result[@"transactionCleaned"] boolValue] ||
        ![result[@"stockCaptured"] boolValue] ||
        ![result[@"triggerVerified"] boolValue]) {
        return NO;
    }
    BOOL replacing = [expectedMode isEqual:@"replace"];
    return [result[@"replacementCreated"] boolValue] == replacing &&
        [result[@"replacementReturned"] boolValue] == replacing;
}

/* An application update invalidates the old recovery baseline even when the
 * selected theme image is unchanged.  First force every journaled descriptor
 * back through stock generation for the *current* installation.  Only after
 * exact transaction acceptance do we delete the stale journal and let the
 * normal publisher create a fresh one.  If publication subsequently fails,
 * the app is either safely stock or protected by the new journal; Restore can
 * never resurrect bytes from the pre-update installation. */
static NSDictionary *CNDRemixRebaseActiveJournalToCurrentStock(
    NSString *bundleIdentifier,
    NSDictionary *savedJournal,
    NSDictionary *targetFingerprint)
{
    NSArray<NSDictionary *> *savedVariants =
        CNDRemixJournalVariants(savedJournal);
    if (bundleIdentifier.length == 0 || savedVariants.count == 0 ||
        ![savedJournal[@"state"] isEqualToString:@"active"]) {
        return @{
            @"ok": @NO,
            @"stage": @"update-rebase-journal",
            @"message": @"The active application journal could not be rebased.",
        };
    }

    NSMutableDictionary *journal = [savedJournal mutableCopy];
    NSMutableArray<NSDictionary *> *checkpointVariants =
        [NSMutableArray arrayWithCapacity:savedVariants.count];
    for (NSDictionary *variant in savedVariants) {
        NSMutableDictionary *updated = [variant mutableCopy];
        updated[@"state"] = @"update-rebase-restoring";
        updated[@"updatedAt"] = NSDate.date;
        [checkpointVariants addObject:updated];
    }
    journal[@"state"] = @"update-rebase-restoring";
    journal[@"variants"] = checkpointVariants;
    if (targetFingerprint.count > 0) {
        journal[@"rebaseTargetApplicationFingerprint"] = targetFingerprint;
    }
    journal[@"rebaseStartedAt"] = NSDate.date;
    journal[@"updatedAt"] = NSDate.date;
    if (!CNDRemixWriteIconServicesJournal(journal)) {
        return @{
            @"ok": @NO,
            @"stage": @"update-rebase-checkpoint",
            @"message": @"The update rebase checkpoint did not survive exact readback.",
        };
    }

    NSMutableArray<NSDictionary *> *updatedVariants =
        [checkpointVariants mutableCopy];
    NSMutableArray<NSDictionary *> *variantResults =
        [NSMutableArray arrayWithCapacity:savedVariants.count];
    BOOL allVerified = YES;
    for (NSUInteger index = 0; index < savedVariants.count; index++) {
        NSDictionary *savedVariant = savedVariants[index];
        CNDIconServicesDescriptorSpec *specification =
            [CNDIconServicesDescriptorSpec specWithDictionary:
                savedVariant[@"descriptorSpecification"] error:nil];
        NSDictionary *restoration = specification
            ? CNDIconServicesPublisherRestoreStockVariantInBatch(
                bundleIdentifier, specification.dictionaryRepresentation)
            : @{
                @"ok": @NO,
                @"stage": @"descriptor-specification",
                @"message": @"The saved descriptor specification is invalid.",
            };
        BOOL verified = specification &&
            (CNDIconServicesPublisherRestorationResultIsVerified(restoration) ||
             CNDRemixPublisherResultIsLegacyAcceptable(restoration, @"stock"));
        CNDRemixLogIconServicesTransaction(
            "UPDATE_REBASE", bundleIdentifier, restoration, verified);
        NSMutableDictionary *variantJournal =
            [updatedVariants[index] mutableCopy];
        variantJournal[@"updateRebaseRestoration"] =
            CNDRemixCompactPublisherReport(restoration);
        variantJournal[@"state"] = verified
            ? @"persistent-stock-verified" : @"recovery-required";
        variantJournal[@"updatedAt"] = NSDate.date;
        updatedVariants[index] = variantJournal;
        [variantResults addObject:@{
            @"descriptorIdentity":
                savedVariant[@"descriptorIdentity"] ?: @"",
            @"ok": @(verified),
            @"stage": verified ? @"persistent-stock-verified"
                : restoration[@"stage"] ?: @"update-rebase-restore",
        }];
        if (!verified) allVerified = NO;

        journal[@"variants"] = updatedVariants;
        journal[@"state"] = allVerified
            ? @"update-rebase-restoring" : @"recovery-required";
        journal[@"updatedAt"] = NSDate.date;
        if (!CNDRemixWriteIconServicesJournal(journal)) {
            allVerified = NO;
            break;
        }
        if (!CNDIconServicesPublisherBatchIsHealthy()) {
            allVerified = NO;
            break;
        }
    }

    BOOL complete = allVerified &&
        variantResults.count == savedVariants.count;
    if (!complete) {
        journal[@"variants"] = updatedVariants;
        journal[@"state"] = @"recovery-required";
        journal[@"updatedAt"] = NSDate.date;
        (void)CNDRemixWriteIconServicesJournal(journal);
        return @{
            @"ok": @NO,
            @"stage": @"update-rebase-restore",
            @"message": @"The current installation could not be restored to stock before rebasing.",
            @"variantResults": variantResults,
        };
    }

    journal[@"variants"] = updatedVariants;
    journal[@"state"] = @"persistent-stock-verified";
    journal[@"rebaseStockVerifiedAt"] = NSDate.date;
    journal[@"updatedAt"] = NSDate.date;
    BOOL checkpointSaved = CNDRemixWriteIconServicesJournal(journal);
    BOOL journalRemoved = checkpointSaved &&
        CNDRemixRemoveIconServicesJournal(bundleIdentifier);
    return @{
        @"ok": @(journalRemoved),
        @"stage": journalRemoved ? @"update-rebase-stock-ready"
            : @"update-rebase-journal-cleanup",
        @"message": journalRemoved
            ? @"The updated app's current stock matrix is ready for a fresh theme baseline."
            : @"Current stock verified, but the stale recovery journal could not be removed.",
        @"persistentDataVerified": @YES,
        @"journalRemoved": @(journalRemoved),
        @"variantResults": variantResults,
    };
}

static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme(
    NSSet<NSString *> *bundleFilter,
    BOOL refreshSpringBoardConsumers,
    BOOL forceMatchedTargetRepublish,
    CNDSnowBoardRemixProgress progress,
    CNDSnowBoardRemixCancellation cancellation)
{
    if (CNDIconServicesInterceptProofIsActive()) {
        return CNDRemixCoordinatorResult(NO, @"phase2-recovery-pending",
            @"Restore the retained single-app IconServices proof before starting the multi-app engine.", nil);
    }
    if ([CNDIconThemeTransaction journaledTransactions].count > 0) {
        return CNDRemixCoordinatorResult(NO, @"legacy-recovery-pending",
            @"Restore the retained legacy app-bundle transactions before starting the IconServices engine.", nil);
    }
    NSDictionary<NSString *, NSData *> *theme =
        settings_sbl_selected_theme_data();
    NSDictionary<NSString *, NSData *> *themeLookup =
        CNDRemixNormalizedThemeLookup(theme);
    if (themeLookup.count == 0) {
        return CNDRemixCoordinatorResult(NO, @"theme",
            @"Select or import a SnowBoard Remix theme first.", nil);
    }
    NSData *airDropThemeSource = themeLookup[
        CNDRemixAirDropPseudoBundleIdentifier.lowercaseString];
    BOOL airDropThemeAssetPresent = airDropThemeSource.length > 0;
    NSMutableSet<NSString *> *foldedBundleFilter = nil;
    if (bundleFilter) {
        foldedBundleFilter = [NSMutableSet setWithCapacity:bundleFilter.count];
        for (NSString *identifier in bundleFilter) {
            if ([identifier isKindOfClass:NSString.class] &&
                identifier.length > 0) {
                [foldedBundleFilter addObject:identifier.lowercaseString];
            }
        }
    }

    if (progress) progress(@"cataloging", 0, 0, nil);
    NSDictionary *batchStart =
        CNDIconServicesPublisherBeginBatch(
            CNDRemixIconServicesWakeIdentifier);
    if (![batchStart[@"ok"] boolValue]) {
        return CNDRemixCoordinatorResult(NO, @"iconservices-session",
            batchStart[@"message"] ?: @"The IconServices batch could not start.",
            @{ @"batchSessionStart": batchStart ?: @{} });
    }

    NSDictionary *catalog = nil;
    NSDictionary *batchFinish = nil;
    NSMutableArray<NSString *> *matched = [NSMutableArray array];
    NSMutableArray<NSString *> *verifiedPending = [NSMutableArray array];
    NSMutableArray<NSString *> *activeIdentifiers = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *preparedTargets = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *results = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *unthemed = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSDictionary *> *memoryPayloadCache =
        [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSDictionary *> *
        applicationFingerprintByFoldedIdentifier =
            [NSMutableDictionary dictionary];
    NSUInteger applied = 0, alreadyActive = 0, failed = 0, skipped = 0;
    NSUInteger payloadCacheDiskHits = 0, payloadCacheMemoryHits = 0;
    NSUInteger payloadCacheMisses = 0, payloadCacheWrites = 0;
    NSUInteger payloadCacheWriteFailures = 0, payloadCacheInvalidEntries = 0;
    NSUInteger plannedVariants = 0, publishedVariants = 0;
    NSUInteger failedVariants = 0;
    NSUInteger rebasedApplications = 0, rebaseFailures = 0;
    NSUInteger adoptedLegacyFingerprints = 0, updatedApplicationRebases = 0;
    BOOL payloadCacheColdStartLogged = NO;
    BOOL cancelled = NO;
    @try {
        catalog = CNDIconServicesPublisherCopyInstalledBundleIdentifiersInBatch();
        NSArray<NSString *> *installed = [catalog[@"bundleIdentifiers"]
            isKindOfClass:NSArray.class] ? catalog[@"bundleIdentifiers"] : nil;
        if (![catalog[@"ok"] boolValue] || !installed) {
            failed++;
        } else {
            NSArray<NSDictionary *> *applicationRecords =
                [catalog[@"applicationRecords"] isKindOfClass:NSArray.class]
                    ? catalog[@"applicationRecords"] : @[];
            for (NSDictionary *record in applicationRecords) {
                NSDictionary *fingerprint =
                    CNDRemixApplicationFingerprint(record);
                NSString *identifier = [fingerprint[@"bundleIdentifier"]
                    isKindOfClass:NSString.class]
                    ? fingerprint[@"bundleIdentifier"] : nil;
                if (identifier.length > 0 && fingerprint.count > 0) {
                    applicationFingerprintByFoldedIdentifier[
                        identifier.lowercaseString] = fingerprint;
                }
            }
            for (NSString *pseudoBundleIdentifier in
                 CNDRemixSupportedPseudoBundleIdentifiers()) {
                NSDictionary *fingerprint =
                    CNDRemixPseudoBundleFingerprint(
                        pseudoBundleIdentifier);
                if (fingerprint.count > 0) {
                    applicationFingerprintByFoldedIdentifier[
                        pseudoBundleIdentifier.lowercaseString] =
                            fingerprint;
                }
            }
            NSMutableSet<NSString *> *seenFolded = [NSMutableSet set];
            for (NSString *bundleIdentifier in installed) {
                NSString *folded = bundleIdentifier.lowercaseString;
                if (folded.length == 0 || [seenFolded containsObject:folded])
                    continue;
                if (CNDRemixIsSupportedPseudoBundleIdentifier(bundleIdentifier) &&
                    ![foldedBundleFilter containsObject:folded]) continue;
                [seenFolded addObject:folded];
                if ((!foldedBundleFilter ||
                     [foldedBundleFilter containsObject:folded]) &&
                    themeLookup[folded]) {
                    [matched addObject:bundleIdentifier];
                }
            }
            BOOL debugApplicationLimit = [NSUserDefaults.standardUserDefaults
                boolForKey:kSettingsSnowBoardRemixDebugThreeAppLimit];
            if (debugApplicationLimit && !foldedBundleFilter) {
                NSArray<NSString *> *debugSelection =
                    CNDRemixDebugSelectionFromBundleIdentifiers(matched);
                NSSet<NSString *> *selectedFoldedIdentifiers = [NSSet setWithArray:
                    [debugSelection valueForKey:@"lowercaseString"]];
                for (NSString *bundleIdentifier in matched) {
                    if ([selectedFoldedIdentifiers containsObject:
                         bundleIdentifier.lowercaseString]) {
                        continue;
                    }
                    [unthemed addObject:@{
                        @"bundleIdentifier": bundleIdentifier,
                        @"reason": @"test-limit",
                        @"message": @"Not attempted because the named four-app debug selection is enabled.",
                    }];
                }
                skipped += matched.count - debugSelection.count;
                [matched setArray:debugSelection];
            }
            /* Pseudo-bundles are not part of the installed-app debug count.
             * AirDrop is temporarily isolated from normal Apply/Update Repair.
             * Admit it only through an explicit filter and matching asset. */
            for (NSString *pseudoBundleIdentifier in
                 CNDRemixSupportedPseudoBundleIdentifiers()) {
                NSString *folded = pseudoBundleIdentifier.lowercaseString;
                if (themeLookup[folded] &&
                    [foldedBundleFilter containsObject:folded] &&
                    ![seenFolded containsObject:folded]) {
                    [seenFolded addObject:folded];
                    [matched addObject:pseudoBundleIdentifier];
                }
            }
            log_user("[SBR_SHARE] airdrop asset=%s bytes=%lu admitted=%d filename=com.apple.Sharing.AirDrop.png\n",
                     airDropThemeAssetPresent ? "present" : "missing",
                     (unsigned long)airDropThemeSource.length,
                     [matched containsObject:
                         CNDRemixAirDropPseudoBundleIdentifier]);
            if (progress) progress(@"matching", matched.count,
                                   matched.count, nil);

            /*
             * Finish every local CoreUI/IconFoundation serialization before
             * installing the first service-side publisher hook.  Interleaving
             * local IFImage construction with a live publisher transaction
             * made a later allocation observe an unrelated class instance on
             * iOS 26.  The pinned agent session remains the same session for
             * catalog and all publications; only the local preparation order
             * changes.
             */
            for (NSUInteger index = 0; index < matched.count; index++) {
                @autoreleasepool {
                    NSString *bundleIdentifier = matched[index];
                    if (cancellation && cancellation()) {
                        cancelled = YES;
                        skipped += matched.count - index;
                        break;
                    }
                    if (progress) progress(@"rendering", index, matched.count,
                                           bundleIdentifier);
                    NSData *source = themeLookup[bundleIdentifier.lowercaseString];
                    /* The VM source trace proved the live Clock face is the
                     * separate com.apple.application-icon.clock.base graphic
                     * source. Keep every ordinary com.apple.mobiletimer
                     * descriptor, including 68pt/v0, backed by the complete
                     * application icon. The process-local Clock source repair
                     * consumes __cnd_clock_background independently. */
                    NSString *sourceHash = CNDRemixSHA256(source);
                    NSArray<CNDIconServicesDescriptorSpec *> *specifications =
                        CNDRemixDescriptorSpecificationsForBundleIdentifier(
                            bundleIdentifier);
                    NSString *profileIdentity =
                        CNDRemixDescriptorProfileIdentity(specifications);
                    NSDictionary *applicationFingerprint =
                        applicationFingerprintByFoldedIdentifier[
                            bundleIdentifier.lowercaseString];
                    if (applicationFingerprint.count == 0) {
                        failed++;
                        skipped++;
                        [unthemed addObject:@{
                            @"bundleIdentifier": bundleIdentifier,
                            @"reason": @"application-fingerprint-unavailable",
                            @"message": @"iconservicesagent did not expose a stable path or version identity for this app; Cyanide refused to create an update-blind recovery journal.",
                        }];
                        continue;
                    }
                    NSDictionary *existing =
                        CNDRemixReadIconServicesJournal(bundleIdentifier);
                    if (CNDRemixJournalProvesNoIconServicesMutation(existing)) {
                        (void)CNDRemixRemoveIconServicesJournal(bundleIdentifier);
                        existing = nil;
                    } else if (existing.count > 0 &&
                        CNDRemixReconcileAirDropJournalToCurrentStockInBatch(
                            bundleIdentifier, existing)) {
                        existing = nil;
                    }
                    BOOL hasCompleteActiveMatrix =
                        CNDRemixJournalIsCompleteActiveMatrix(
                            existing, sourceHash, specifications);
                    BOOL hasExpandableActiveMatrixSubset =
                        CNDRemixJournalIsExpandableActiveMatrixSubset(
                            existing, sourceHash, specifications);
                    BOOL hasCompatibleActiveMatrix =
                        hasCompleteActiveMatrix ||
                        hasExpandableActiveMatrixSubset;
                    BOOL lacksSavedFingerprint = hasCompatibleActiveMatrix &&
                        ![existing[@"applicationFingerprint"]
                            isKindOfClass:NSDictionary.class];
                    if (lacksSavedFingerprint &&
                        applicationFingerprint.count > 0) {
                        NSMutableDictionary *migrated = [existing mutableCopy];
                        migrated[@"applicationFingerprint"] =
                            applicationFingerprint;
                        migrated[@"applicationFingerprintAdoptedAt"] =
                            NSDate.date;
                        migrated[@"updatedAt"] = NSDate.date;
                        if (CNDRemixWriteIconServicesJournal(migrated)) {
                            existing = migrated;
                            adoptedLegacyFingerprints++;
                            log_user("[SBR_UPDATE] adopted current install fingerprint app=%s\n",
                                     bundleIdentifier.UTF8String ?: "?");
                        } else {
                            failed++;
                            skipped++;
                            [unthemed addObject:@{
                                @"bundleIdentifier": bundleIdentifier,
                                @"reason": @"application-fingerprint-journal",
                                @"message": @"The current install fingerprint could not be added to the active journal.",
                            }];
                            continue;
                        }
                    }
                    BOOL applicationFingerprintMatches =
                        CNDRemixApplicationFingerprintMatches(
                            existing[@"applicationFingerprint"],
                            applicationFingerprint);
                    BOOL airDropSourceRegistryUpgradeRequired =
                        [bundleIdentifier caseInsensitiveCompare:
                            CNDRemixAirDropPseudoBundleIdentifier] ==
                                NSOrderedSame &&
                        hasCompleteActiveMatrix &&
                        applicationFingerprintMatches &&
                        !CNDRemixAirDropJournalHasVerifiedSourceRegistry(
                            existing, specifications);
                    BOOL forcedTargetRepublish =
                        forceMatchedTargetRepublish &&
                        (!foldedBundleFilter ||
                         [foldedBundleFilter containsObject:
                            bundleIdentifier.lowercaseString]) &&
                        hasCompatibleActiveMatrix &&
                        applicationFingerprintMatches;
                    if (CNDRemixJournalMatchesCurrentApplication(
                            existing, sourceHash, specifications,
                            applicationFingerprint) &&
                        !airDropSourceRegistryUpgradeRequired &&
                        !forcedTargetRepublish) {
                        alreadyActive++;
                        [activeIdentifiers addObject:bundleIdentifier];
                        [results addObject:@{
                            @"bundleIdentifier": bundleIdentifier,
                            @"ok": @YES, @"stage": @"already-active"
                        }];
                        continue;
                    }
                    BOOL needsProfileExpansion =
                        hasExpandableActiveMatrixSubset &&
                        applicationFingerprintMatches;
                    BOOL needsUpdateRebase = hasCompatibleActiveMatrix &&
                        (!applicationFingerprintMatches ||
                         airDropSourceRegistryUpgradeRequired ||
                         forcedTargetRepublish);
                    if (existing.count > 0) {
                        if (needsUpdateRebase || needsProfileExpansion) {
                            /* The publication loop first rotates the current
                             * installation to stock for an app update, or
                             * appends only missing records for a compatible
                             * descriptor-profile expansion. */
                        } else {
                            /* This is a blocked application, not a successful
                             * no-op. Otherwise an entire batch of stale
                             * recovery journals can be skipped while Apply
                             * reports success. */
                            BOOL predatesStorePreservation =
                                [existing[@"state"] isEqualToString:@"active"] &&
                                [existing[@"storePreservationPolicyVersion"]
                                    unsignedIntegerValue] !=
                                    CNDRemixStorePreservationPolicyVersion;
                            failed++;
                            skipped++;
                            [unthemed addObject:@{
                                @"bundleIdentifier": bundleIdentifier,
                                @"reason": predatesStorePreservation
                                    ? @"legacy-store-invalidation-recovery"
                                    : @"recovery-required",
                                @"message": predatesStorePreservation
                                    ? @"This active journal predates the persistent-store preservation fix. Restore All Icons once before applying again."
                                    : @"A different or incomplete IconServices transaction must be restored first.",
                            }];
                            continue;
                        }
                    }

                    NSArray<CNDIconServicesDescriptorSpec *> *
                        publicationSpecifications = specifications;
                    if (needsProfileExpansion) {
                        NSMutableSet<NSString *> *existingIdentities =
                            [NSMutableSet set];
                        for (NSDictionary *variant in
                             CNDRemixJournalVariants(existing)) {
                            NSString *identity =
                                [variant[@"descriptorIdentity"]
                                    isKindOfClass:NSString.class]
                                ? variant[@"descriptorIdentity"] : nil;
                            if (identity.length > 0)
                                [existingIdentities addObject:identity];
                        }
                        NSMutableArray<CNDIconServicesDescriptorSpec *> *missing =
                            [NSMutableArray array];
                        for (CNDIconServicesDescriptorSpec *specification in
                             specifications) {
                            if (![existingIdentities containsObject:
                                    specification.canonicalIdentity]) {
                                [missing addObject:specification];
                            }
                        }
                        publicationSpecifications = missing;
                    }

                    NSMutableDictionary<NSString *, NSDictionary *> *
                        productsByDescriptor = [NSMutableDictionary dictionary];
                    NSMutableDictionary<NSString *, NSDictionary *> *
                        structuredByGeometry = [NSMutableDictionary dictionary];
                    NSMutableArray<CNDIconServicesDescriptorSpec *> *missing =
                        [NSMutableArray array];
                    NSMutableDictionary<NSString *, NSData *> *sourceByHash =
                        [NSMutableDictionary dictionary];
                    NSMutableDictionary<NSString *, NSString *> *
                        sourceHashByDescriptor = [NSMutableDictionary dictionary];
                    for (CNDIconServicesDescriptorSpec *specification in
                         publicationSpecifications) {
                        NSData *variantSource = source;
                        NSString *variantSourceHash =
                            CNDRemixSHA256(variantSource);
                        if (!variantSource.length ||
                            !CNDRemixIsSHA256String(variantSourceHash)) {
                            continue;
                        }
                        sourceByHash[variantSourceHash] = variantSource;
                        sourceHashByDescriptor[
                            specification.canonicalIdentity] =
                                variantSourceHash;
                        NSString *cacheKey = CNDRemixPayloadCacheKey(
                            variantSourceHash, specification);
                        NSDictionary *entry = memoryPayloadCache[cacheKey];
                        BOOL hit = NO;
                        if (entry && CNDRemixPayloadCacheEntryIsValid(
                                entry, variantSourceHash, cacheKey,
                                specification)) {
                            payloadCacheMemoryHits++;
                            hit = YES;
                        } else {
                            if (entry) {
                                payloadCacheInvalidEntries++;
                                [memoryPayloadCache removeObjectForKey:cacheKey];
                            }
                            BOOL invalidDiskEntry = NO;
                            entry = CNDRemixReadPayloadCacheEntry(
                                variantSourceHash, cacheKey, specification,
                                &invalidDiskEntry);
                            if (entry) {
                                payloadCacheDiskHits++;
                                hit = YES;
                                memoryPayloadCache[cacheKey] = entry;
                            } else {
                                payloadCacheMisses++;
                                if (invalidDiskEntry)
                                    payloadCacheInvalidEntries++;
                                [missing addObject:specification];
                            }
                        }
                        if (hit) {
                            NSMutableDictionary *product = [entry mutableCopy];
                            product[@"payloadCacheHit"] = @YES;
                            productsByDescriptor[
                                specification.canonicalIdentity] = product;
                            NSString *structuredIdentity =
                                [NSString stringWithFormat:@"%@:%@",
                                    variantSourceHash,
                                    CNDRemixStructuredPayloadIdentity(
                                        specification)];
                            if (!structuredByGeometry[structuredIdentity]) {
                                structuredByGeometry[structuredIdentity] = entry;
                            }
                        }
                    }

                    if (missing.count > 0) {
                        if (!payloadCacheColdStartLogged) {
                            payloadCacheColdStartLogged = YES;
                            log_user("[COLD START] SnowBoard Remix is rendering and caching its first uncached descriptor matrix.\n");
                        }
                        NSMutableDictionary<NSString *, NSMutableArray<
                            CNDIconServicesDescriptorSpec *> *> *missingBySource =
                                [NSMutableDictionary dictionary];
                        for (CNDIconServicesDescriptorSpec *specification in
                             missing) {
                            NSString *variantSourceHash =
                                sourceHashByDescriptor[
                                    specification.canonicalIdentity];
                            if (!variantSourceHash) continue;
                            NSMutableArray<CNDIconServicesDescriptorSpec *> *group =
                                missingBySource[variantSourceHash];
                            if (!group) {
                                group = [NSMutableArray array];
                                missingBySource[variantSourceHash] = group;
                            }
                            [group addObject:specification];
                        }
                        NSMutableDictionary<NSString *, NSDictionary *> *
                            processedBySourceAndRaster =
                                [NSMutableDictionary dictionary];

                        BOOL localFailure = NO;
                        NSString *localFailureReason = nil;
                        for (NSString *variantSourceHash in missingBySource) {
                            NSArray<CNDIconServicesDescriptorSpec *> *group =
                                missingBySource[variantSourceHash];
                            NSMutableOrderedSet<NSString *> *rasterOrder =
                                [NSMutableOrderedSet orderedSet];
                            NSMutableDictionary<NSString *, NSDictionary *> *
                                targetByRaster = [NSMutableDictionary dictionary];
                            for (CNDIconServicesDescriptorSpec *specification
                                 in group) {
                                NSString *raster = CNDRemixRasterIdentity(
                                    specification);
                                if (![rasterOrder containsObject:raster]) {
                                    [rasterOrder addObject:raster];
                                    targetByRaster[raster] = @{
                                        @"width": @(
                                            specification.targetPixelWidth),
                                        @"height": @(
                                            specification.targetPixelHeight),
                                        @"capacity": @0,
                                    };
                                }
                            }
                            NSMutableArray *targets = [NSMutableArray array];
                            for (NSString *raster in rasterOrder) {
                                [targets addObject:targetByRaster[raster]];
                            }
                            NSError *processingError = nil;
                            NSArray<NSDictionary *> *processedTargets =
                                CNDProcessIconThemePNGForTargets(
                                    sourceByHash[variantSourceHash], targets,
                                    &processingError);
                            if (processedTargets.count != targets.count) {
                                localFailure = YES;
                                localFailureReason =
                                    processingError.localizedDescription ?:
                                    @"A theme source did not pass decode-once matrix rendering validation.";
                                break;
                            }
                            for (NSUInteger rasterIndex = 0;
                                 rasterIndex < rasterOrder.count;
                                 rasterIndex++) {
                                processedBySourceAndRaster[
                                    [NSString stringWithFormat:@"%@:%@",
                                        variantSourceHash,
                                        rasterOrder[rasterIndex]]] =
                                            processedTargets[rasterIndex];
                            }
                        }
                        for (CNDIconServicesDescriptorSpec *specification in
                             (localFailure ? @[] : missing)) {
                            NSString *variantSourceHash =
                                sourceHashByDescriptor[
                                    specification.canonicalIdentity];
                            NSString *raster = CNDRemixRasterIdentity(
                                specification);
                            NSString *structuredIdentity =
                                [NSString stringWithFormat:@"%@:%@",
                                    variantSourceHash,
                                    CNDRemixStructuredPayloadIdentity(
                                        specification)];
                            NSDictionary *processed =
                                processedBySourceAndRaster[
                                    [NSString stringWithFormat:@"%@:%@",
                                        variantSourceHash, raster]];
                            NSData *scaledPNG = [processed[@"unpaddedBytes"]
                                isKindOfClass:NSData.class]
                                ? processed[@"unpaddedBytes"] : nil;
                            if (!scaledPNG.length ||
                                ![processed[@"completeDecodeVerified"] boolValue] ||
                                ![processed[@"alphaClassesPreserved"] boolValue]) {
                                localFailure = YES;
                                localFailureReason =
                                    @"A rendered matrix PNG failed exact alpha/geometry validation.";
                                break;
                            }
                            NSDictionary *shared =
                                structuredByGeometry[structuredIdentity];
                            NSData *structured = [shared[@"structuredImageData"]
                                isKindOfClass:NSData.class]
                                ? shared[@"structuredImageData"] : nil;
                            NSDictionary *diagnostics =
                                [shared[@"structuredDiagnostics"]
                                    isKindOfClass:NSDictionary.class]
                                ? shared[@"structuredDiagnostics"] : nil;
                            if (!structured.length) {
                                NSError *structuredError = nil;
                                structured =
                                    CNDIconServicesCreateStructuredImageDataWithPixelSize(
                                        scaledPNG,
                                        CGSizeMake(specification.pointWidth,
                                                   specification.pointHeight),
                                        specification.scale,
                                        CGSizeMake(
                                            specification.targetPixelWidth,
                                            specification.targetPixelHeight),
                                        &diagnostics,
                                        &structuredError);
                                if (!structured.length ||
                                    !CNDRemixPayloadDiagnosticsAreValid(
                                        diagnostics, specification)) {
                                    localFailure = YES;
                                    localFailureReason =
                                        structuredError.localizedDescription ?:
                                        @"A marked IconServices matrix response could not be serialized.";
                                    break;
                                }
                                structuredByGeometry[structuredIdentity] = @{
                                    @"structuredImageData": structured,
                                    @"structuredDiagnostics": diagnostics ?: @{},
                                };
                            }
                            NSString *cacheKey = CNDRemixPayloadCacheKey(
                                variantSourceHash, specification);
                            NSDictionary *entry =
                                CNDRemixCreatePayloadCacheEntry(
                                    variantSourceHash, cacheKey, specification,
                                    scaledPNG, structured, diagnostics);
                            if (!entry) {
                                localFailure = YES;
                                localFailureReason =
                                    @"A validated matrix payload could not be cached.";
                                break;
                            }
                            memoryPayloadCache[cacheKey] = entry;
                            NSMutableDictionary *product = [entry mutableCopy];
                            product[@"payloadCacheHit"] = @NO;
                            productsByDescriptor[
                                specification.canonicalIdentity] = product;
                            if (CNDRemixWritePayloadCacheEntry(entry)) {
                                payloadCacheWrites++;
                            } else {
                                payloadCacheWriteFailures++;
                            }
                        }
                        if (localFailure) {
                            failed++;
                            [unthemed addObject:@{
                                @"bundleIdentifier": bundleIdentifier,
                                @"reason": @"structured-payload-matrix",
                                @"message": localFailureReason ?:
                                    @"The descriptor matrix could not be prepared.",
                            }];
                            continue;
                        }
                    }

                    NSMutableArray<NSDictionary *> *preparedVariants =
                        [NSMutableArray arrayWithCapacity:
                            publicationSpecifications.count];
                    for (CNDIconServicesDescriptorSpec *specification in
                         publicationSpecifications) {
                        NSDictionary *product = productsByDescriptor[
                            specification.canonicalIdentity];
                        NSData *structured = product[@"structuredImageData"];
                        NSString *structuredHash =
                            product[@"structuredImageSHA256"];
                        if (!structured.length ||
                            !CNDRemixIsSHA256String(structuredHash)) {
                            [preparedVariants removeAllObjects];
                            break;
                        }
                        [preparedVariants addObject:@{
                            @"descriptorIdentity":
                                specification.canonicalIdentity,
                            @"descriptorSpecification":
                                specification.dictionaryRepresentation,
                            @"structuredImageData": structured,
                            @"structuredImageSHA256": structuredHash,
                            @"structuredImageLength": @(structured.length),
                            @"structuredDiagnostics":
                                product[@"structuredDiagnostics"] ?: @{},
                            @"payloadCacheKey": product[@"cacheKey"] ?: @"",
                            @"payloadCacheHit":
                                product[@"payloadCacheHit"] ?: @NO,
                            @"themeSourceSHA256":
                                product[@"themeSourceSHA256"] ?: @"",
                        }];
                    }
                    if (preparedVariants.count !=
                            publicationSpecifications.count) {
                        failed++;
                        [unthemed addObject:@{
                            @"bundleIdentifier": bundleIdentifier,
                            @"reason": @"payload-cache-readback-matrix",
                            @"message": @"The cached descriptor matrix failed final in-memory validation.",
                        }];
                        continue;
                    }
                    NSMutableDictionary *preparedTarget = [@{
                        @"bundleIdentifier": bundleIdentifier,
                        @"themeSourceSHA256": sourceHash,
                        @"descriptorProfileIdentity": profileIdentity,
                        @"variants": preparedVariants,
                    } mutableCopy];
                    if (applicationFingerprint.count > 0) {
                        preparedTarget[@"applicationFingerprint"] =
                            applicationFingerprint;
                    }
                    if (needsUpdateRebase) {
                        preparedTarget[@"updateRebaseJournal"] = existing;
                        preparedTarget[@"updateRebaseReason"] =
                            airDropSourceRegistryUpgradeRequired
                                ? @"airdrop-source-registry-upgrade"
                                : (forcedTargetRepublish
                                    ? @"isolated-target-republish"
                                    : @"installed-application-changed");
                    } else if (needsProfileExpansion) {
                        preparedTarget[@"profileExpansionJournal"] = existing;
                    }
                    [preparedTargets addObject:preparedTarget];
                }
            }

            for (NSUInteger index = 0;
                 !cancelled && index < preparedTargets.count; index++) {
                @autoreleasepool {
                    NSDictionary *prepared = preparedTargets[index];
                    NSString *bundleIdentifier = prepared[@"bundleIdentifier"];
                    NSString *sourceHash = prepared[@"themeSourceSHA256"];
                    NSArray<NSDictionary *> *preparedVariants =
                        prepared[@"variants"];
                    if (cancellation && cancellation()) {
                        cancelled = YES;
                        skipped += preparedTargets.count - index;
                        break;
                    }
                    if (!CNDIconServicesPublisherBatchIsHealthy()) {
                        failed += preparedTargets.count - index;
                        break;
                    }
                    NSDictionary *updateRebaseJournal =
                        [prepared[@"updateRebaseJournal"]
                            isKindOfClass:NSDictionary.class]
                            ? prepared[@"updateRebaseJournal"] : nil;
                    NSDictionary *profileExpansionJournal =
                        [prepared[@"profileExpansionJournal"]
                            isKindOfClass:NSDictionary.class]
                            ? prepared[@"profileExpansionJournal"] : nil;
                    if (updateRebaseJournal.count > 0) {
                        NSString *rebaseReason =
                            [prepared[@"updateRebaseReason"]
                                isKindOfClass:NSString.class]
                                ? prepared[@"updateRebaseReason"]
                                : @"installed-application-changed";
                        if (progress) progress(@"rebasing-update", index,
                                               preparedTargets.count,
                                               bundleIdentifier);
                        log_user("[SBR_UPDATE] rebasing app=%s reason=%s\n",
                                 bundleIdentifier.UTF8String ?: "?",
                                 rebaseReason.UTF8String ?: "unknown");
                        NSDictionary *rebase =
                            CNDRemixRebaseActiveJournalToCurrentStock(
                                bundleIdentifier, updateRebaseJournal,
                                prepared[@"applicationFingerprint"]);
                        if (![rebase[@"ok"] boolValue]) {
                            failed++;
                            rebaseFailures++;
                            [unthemed addObject:@{
                                @"bundleIdentifier": bundleIdentifier,
                                @"reason": @"update-rebase",
                                @"message": rebase[@"message"] ?:
                                    @"The updated application baseline could not be rotated safely.",
                            }];
                            [results addObject:@{
                                @"bundleIdentifier": bundleIdentifier,
                                @"ok": @NO,
                                @"stage": rebase[@"stage"] ?:
                                    @"update-rebase",
                                @"updateRebase": rebase,
                            }];
                            continue;
                        }
                        rebasedApplications++;
                        updatedApplicationRebases++;
                    }
                    NSMutableArray<NSDictionary *> *journalVariants =
                        [NSMutableArray arrayWithCapacity:
                            preparedVariants.count +
                            CNDRemixJournalVariants(
                                profileExpansionJournal).count];
                    if (profileExpansionJournal.count > 0) {
                        for (NSDictionary *variant in
                             CNDRemixJournalVariants(
                                profileExpansionJournal)) {
                            [journalVariants addObject:[variant copy]];
                        }
                    }
                    NSUInteger newVariantOffset = journalVariants.count;
                    for (NSDictionary *variant in preparedVariants) {
                        [journalVariants addObject:@{
                            @"descriptorIdentity":
                                variant[@"descriptorIdentity"] ?: @"",
                            @"descriptorSpecification":
                                variant[@"descriptorSpecification"] ?: @{},
                            @"state": @"prepared",
                            @"publicationDispatchPossible": @NO,
                            @"structuredImageSHA256":
                                variant[@"structuredImageSHA256"] ?: @"",
                            @"structuredImageLength":
                                variant[@"structuredImageLength"] ?: @0,
                            @"structuredDiagnostics":
                                variant[@"structuredDiagnostics"] ?: @{},
                            @"payloadCacheKey":
                                variant[@"payloadCacheKey"] ?: @"",
                            @"payloadCacheHit":
                                variant[@"payloadCacheHit"] ?: @NO,
                            @"themeSourceSHA256":
                                variant[@"themeSourceSHA256"] ?: @"",
                        }];
                    }
                    plannedVariants += preparedVariants.count;
                    NSMutableDictionary *journal = profileExpansionJournal.count
                        ? [profileExpansionJournal mutableCopy]
                        : [NSMutableDictionary dictionary];
                    journal[@"schemaVersion"] =
                        @(CNDRemixIconServicesJournalSchemaVersion);
                    journal[@"storePreservationPolicyVersion"] =
                        @(CNDRemixStorePreservationPolicyVersion);
                    journal[@"engine"] = @"iconservices-publisher";
                    journal[@"bundleIdentifier"] = bundleIdentifier;
                    journal[@"state"] = @"prepared";
                    journal[@"themeSourceSHA256"] = sourceHash;
                    journal[@"descriptorProfileIdentity"] =
                        prepared[@"descriptorProfileIdentity"] ?: @"";
                    journal[@"variants"] = journalVariants;
                    if (!journal[@"createdAt"])
                        journal[@"createdAt"] = NSDate.date;
                    journal[@"agentPID"] = batchStart[@"agentPID"] ?: @0;
                    if (profileExpansionJournal.count > 0) {
                        journal[@"profileExpansionFromDescriptorProfileIdentity"] =
                            profileExpansionJournal[
                                @"descriptorProfileIdentity"] ?: @"";
                        journal[@"profileExpansionStartedAt"] = NSDate.date;
                        log_user("[SBR_PROFILE] expanding app=%s existing=%lu missing=%lu\n",
                                 bundleIdentifier.UTF8String ?: "?",
                                 (unsigned long)newVariantOffset,
                                 (unsigned long)preparedVariants.count);
                    }
                    NSDictionary *applicationFingerprint =
                        [prepared[@"applicationFingerprint"]
                            isKindOfClass:NSDictionary.class]
                            ? prepared[@"applicationFingerprint"] : nil;
                    if (applicationFingerprint.count > 0) {
                        journal[@"applicationFingerprint"] =
                            applicationFingerprint;
                    }
                    if (updateRebaseJournal.count > 0) {
                        journal[@"rebasedForApplicationUpdate"] = @YES;
                        journal[@"updateRebaseReason"] =
                            prepared[@"updateRebaseReason"] ?:
                                @"installed-application-changed";
                        journal[@"previousApplicationFingerprint"] =
                            updateRebaseJournal[@"applicationFingerprint"] ?:
                                @{};
                    }
                    if (!CNDRemixWriteIconServicesJournal(journal)) {
                        failed++;
                        [unthemed addObject:@{
                            @"bundleIdentifier": bundleIdentifier,
                            @"reason": @"journal",
                            @"message": @"The pre-publication journal did not survive exact readback.",
                        }];
                        continue;
                    }
                    if (progress) progress(@"publishing", index,
                                           preparedTargets.count,
                                           bundleIdentifier);
                    NSMutableArray<NSDictionary *> *variantResults =
                        [NSMutableArray arrayWithCapacity:
                            preparedVariants.count];
                    NSMutableArray<NSDictionary *> *updatedVariants =
                        [journalVariants mutableCopy];
                    BOOL allVerified = YES;
                    for (NSUInteger variantIndex = 0;
                         variantIndex < preparedVariants.count;
                         variantIndex++) {
                        NSDictionary *variant =
                            preparedVariants[variantIndex];
                        NSData *structured = variant[@"structuredImageData"];
                        NSDictionary *specification =
                            variant[@"descriptorSpecification"];
                        /* Persist possible dispatch for this descriptor
                         * before issuing it. Later prepared variants retain
                         * an explicit never-dispatched proof on interruption. */
                        NSMutableDictionary *dispatchVariant =
                            [updatedVariants[
                                newVariantOffset + variantIndex] mutableCopy];
                        dispatchVariant[@"state"] = @"dispatch-possible";
                        dispatchVariant[@"publicationDispatchPossible"] = @YES;
                        dispatchVariant[@"updatedAt"] = NSDate.date;
                        updatedVariants[newVariantOffset + variantIndex] =
                            dispatchVariant;
                        journal[@"variants"] = updatedVariants;
                        journal[@"state"] = @"dispatch-possible";
                        journal[@"updatedAt"] = NSDate.date;
                        if (!CNDRemixWriteIconServicesJournal(journal)) {
                            allVerified = NO;
                            failedVariants +=
                                preparedVariants.count - variantIndex;
                            break;
                        }
                        NSDictionary *publication =
                            CNDIconServicesPublisherPublishVariantInBatch(
                                bundleIdentifier, structured, specification);
                        NSDictionary *compactPublication =
                            CNDRemixCompactPublisherReport(publication);
                        BOOL noThemedMutation =
                            CNDRemixReportProvesNoThemedIconServicesMutation(
                                publication);
                        BOOL verified =
                            CNDIconServicesPublisherPublicationResultIsVerified(
                                publication) ||
                            CNDRemixPublisherResultIsLegacyAcceptable(
                                publication, @"replace");
                        CNDRemixLogIconServicesTransaction(
                            "PUBLISH", bundleIdentifier, publication,
                            verified);
                        NSMutableDictionary *variantJournal =
                            [updatedVariants[
                                newVariantOffset + variantIndex] mutableCopy];
                        variantJournal[@"publication"] =
                            compactPublication;
                        variantJournal[@"noThemedPublicationMutationVerified"] =
                            @(noThemedMutation);
                        variantJournal[@"state"] = verified
                            ? @"published-pending-session-close"
                            : @"recovery-required";
                        variantJournal[@"updatedAt"] = NSDate.date;
                        updatedVariants[newVariantOffset + variantIndex] =
                            variantJournal;
                        [variantResults addObject:@{
                            @"descriptorIdentity":
                                variant[@"descriptorIdentity"] ?: @"",
                            @"ok": @(verified),
                            @"stage": verified
                                ? @"published-pending-session-close"
                                : publication[@"stage"] ?: @"publication",
                            @"publication": compactPublication,
                            @"noThemedPublicationMutationVerified":
                                @(noThemedMutation),
                        }];
                        if (verified) {
                            publishedVariants++;
                        } else {
                            failedVariants++;
                            allVerified = NO;
                        }
                        /* Save the result and captured stock baseline before
                         * advancing to the next possible write. */
                        journal[@"variants"] = updatedVariants;
                        journal[@"state"] = allVerified
                            ? @"dispatch-possible" : @"recovery-required";
                        journal[@"updatedAt"] = NSDate.date;
                        if (!CNDRemixWriteIconServicesJournal(journal)) {
                            allVerified = NO;
                            failedVariants +=
                                preparedVariants.count - variantIndex - 1;
                            break;
                        }
                        if (!CNDIconServicesPublisherBatchIsHealthy()) {
                            allVerified = NO;
                            failedVariants +=
                                preparedVariants.count - variantIndex - 1;
                            break;
                        }
                    }
                    journal[@"variants"] = updatedVariants;
                    journal[@"state"] = allVerified &&
                        variantResults.count == preparedVariants.count
                        ? @"published-pending-session-close"
                        : @"recovery-required";
                    journal[@"updatedAt"] = NSDate.date;
                    BOOL journalSaved = CNDRemixWriteIconServicesJournal(journal);
                    BOOL appVerified = allVerified &&
                        variantResults.count == preparedVariants.count;
                    BOOL failedPublicationVerifiedStock = !appVerified &&
                        CNDRemixReconcileAirDropJournalToCurrentStockInBatch(
                            bundleIdentifier, journal);
                    if (appVerified && journalSaved) {
                        [verifiedPending addObject:bundleIdentifier];
                    } else {
                        failed++;
                    }
                    [results addObject:@{
                        @"bundleIdentifier": bundleIdentifier,
                        @"ok": @(appVerified && journalSaved),
                        @"stage": appVerified
                            ? @"published-pending-session-close"
                            : @"publication-matrix",
                        @"descriptorProfileIdentity":
                            prepared[@"descriptorProfileIdentity"] ?: @"",
                        @"variantResults": variantResults,
                        @"failedPublicationVerifiedStock":
                            @(failedPublicationVerifiedStock),
                        @"recoveryJournalRequired":
                            @(!failedPublicationVerifiedStock),
                    }];
                }
            }
        }
    } @finally {
        if (progress) progress(@"finalizing-session", matched.count,
                               matched.count, nil);
        batchFinish = CNDIconServicesPublisherFinishBatch();
    }

    if (![catalog[@"ok"] boolValue]) {
        return CNDRemixCoordinatorResult(NO, @"application-catalog",
            catalog[@"message"] ?: @"iconservicesagent application discovery failed.",
            @{
                @"catalog": catalog ?: @{},
                @"batchSessionStart": batchStart ?: @{},
                @"batchSessionFinish": batchFinish ?: @{},
            });
    }

    BOOL sessionClosed = [batchFinish[@"ok"] boolValue];
    for (NSString *bundleIdentifier in verifiedPending) {
        NSMutableDictionary *journal =
            [CNDRemixReadIconServicesJournal(bundleIdentifier) mutableCopy];
        NSMutableArray *activeVariants = [NSMutableArray array];
        for (NSDictionary *variant in CNDRemixJournalVariants(journal)) {
            NSMutableDictionary *updated = [variant mutableCopy];
            updated[@"state"] = sessionClosed
                ? @"active" : @"recovery-required";
            updated[@"updatedAt"] = NSDate.date;
            [activeVariants addObject:updated];
        }
        journal[@"variants"] = activeVariants;
        journal[@"state"] = sessionClosed
            ? @"active"
            : @"recovery-required";
        journal[@"batchSessionFinish"] = batchFinish ?: @{};
        journal[@"updatedAt"] = NSDate.date;
        if (CNDRemixWriteIconServicesJournal(journal) && sessionClosed) {
            applied++;
            [activeIdentifiers addObject:bundleIdentifier];
        } else if (sessionClosed) {
            failed++;
        }
    }

    NSDictionary *airDropResult = nil;
    NSDictionary *airDropUnthemed = nil;
    for (NSDictionary *entry in results) {
        NSString *identifier = [entry[@"bundleIdentifier"]
            isKindOfClass:NSString.class] ? entry[@"bundleIdentifier"] : nil;
        if (identifier.length > 0 && [identifier caseInsensitiveCompare:
                CNDRemixAirDropPseudoBundleIdentifier] == NSOrderedSame) {
            airDropResult = entry;
            break;
        }
    }
    if (!airDropResult) {
        for (NSDictionary *entry in unthemed) {
            NSString *identifier = [entry[@"bundleIdentifier"]
                isKindOfClass:NSString.class] ? entry[@"bundleIdentifier"] : nil;
            if (identifier.length > 0 && [identifier caseInsensitiveCompare:
                    CNDRemixAirDropPseudoBundleIdentifier] == NSOrderedSame) {
                airDropUnthemed = entry;
                break;
            }
        }
    }
    BOOL airDropActive = [activeIdentifiers containsObject:
        CNDRemixAirDropPseudoBundleIdentifier];
    NSString *airDropStage = airDropResult[@"stage"] ?:
        airDropUnthemed[@"reason"] ?:
        (airDropThemeAssetPresent ? @"not-admitted" : @"asset-missing");
    NSArray *airDropVariantResults = [airDropResult[@"variantResults"]
        isKindOfClass:NSArray.class] ? airDropResult[@"variantResults"] : @[];
    BOOL airDropFailedPublicationVerifiedStock =
        [airDropResult[@"failedPublicationVerifiedStock"] boolValue];
    BOOL airDropRecoveryJournalRequired =
        [airDropResult[@"recoveryJournalRequired"] boolValue];
    NSUInteger airDropVerifiedVariants = 0;
    NSUInteger airDropResolvedSourceVariants = 0;
    NSUInteger airDropVerifiedSourceVariants = 0;
    NSUInteger airDropSourceEntriesBefore = 0;
    NSUInteger airDropSourceEntriesAfter = 0;
    BOOL airDropSourceWriteIssued = NO;
    for (NSDictionary *variantResult in airDropVariantResults) {
        NSDictionary *publication = [variantResult[@"publication"]
            isKindOfClass:NSDictionary.class]
            ? variantResult[@"publication"] : @{};
        if ([variantResult[@"ok"] boolValue]) airDropVerifiedVariants++;
        if ([publication[@"sourceIdentifiersResolved"] boolValue]) {
            airDropResolvedSourceVariants++;
        }
        if ([publication[@"sourceRegistryFreshReadbackVerified"]
                boolValue]) {
            airDropVerifiedSourceVariants++;
        }
        airDropSourceEntriesBefore +=
            [publication[@"sourceRegistryEntryCountBefore"]
                unsignedIntegerValue];
        airDropSourceEntriesAfter +=
            [publication[@"sourceRegistryEntryCountAfter"]
                unsignedIntegerValue];
        airDropSourceWriteIssued = airDropSourceWriteIssued ||
            [publication[@"sourceRegistryWriteIssued"] boolValue];
    }
    log_user("[SBR_SHARE] airdrop active=%d verified=%lu/%lu "
             "source=%lu/%lu registry=%lu->%lu write=%d "
             "stage=%s session-closed=%d stock-reconciled=%d "
             "journal-required=%d\n",
             airDropActive, (unsigned long)airDropVerifiedVariants,
             (unsigned long)airDropVariantResults.count,
             (unsigned long)airDropVerifiedSourceVariants,
             (unsigned long)airDropResolvedSourceVariants,
             (unsigned long)airDropSourceEntriesBefore,
             (unsigned long)airDropSourceEntriesAfter,
             airDropSourceWriteIssued,
             airDropStage.UTF8String ?: "unknown", sessionClosed,
             airDropFailedPublicationVerifiedStock,
             airDropRecoveryJournalRequired);
    NSDictionary *airDropPresentation =
        CNDRemixRefreshAirDropPresentationIfNeeded(
            airDropActive && sessionClosed);
    BOOL airDropPresentationOK =
        [airDropPresentation[@"ok"] boolValue];

    NSArray<NSString *> *presentationBundleIdentifiers =
        refreshSpringBoardConsumers
            ? CNDRemixActiveIconServicesBundleIdentifiers()
            : [activeIdentifiers copy];
    /* Initial Apply owns persistent records and cache eviction only. Dynamic
     * inputs are staged when the user explicitly requests presentation work. */
    NSDictionary *oneShotPresentation = @{
        @"ok": @YES,
        @"stage": @"isolated-airdrop-not-required",
        @"message": @"The isolated AirDrop test does not refresh any SpringBoard icon consumer.",
        @"cacheInvalidationIssued": @NO,
        @"springBoardCacheRefreshCompleted": @NO,
        @"remoteCallUsed": @NO,
    };
    if (refreshSpringBoardConsumers) {
        themer_set_springboard_iconservices_refresh_bundle_identifiers(
            presentationBundleIdentifiers);
        oneShotPresentation = CNDRemixRunInitialCacheRefresh();
    }
    BOOL presentationOK = [oneShotPresentation[@"ok"] boolValue] &&
        airDropPresentationOK;
    NSDictionary *presentationLifecycle = refreshSpringBoardConsumers
        ? CNDRemixReconcilePresentationLifecycle()
        : @{
            @"ok": @YES,
            @"stage": @"isolated-airdrop-not-required",
            @"message": @"No process-wide presentation lifecycle was changed.",
        };
    NSDictionary *presentationStatus =
        presentationLifecycle[@"watcherStatus"] ?: @{};
    NSDictionary *spotlightPresentation =
        presentationStatus[@"hosts"][@"Spotlight"] ?: @{};
    BOOL spotlightReady = !refreshSpringBoardConsumers ||
        [spotlightPresentation[@"installedPID"] intValue] > 1;

    NSDictionary *summary = @{
        @"state": (!sessionClosed || failed || cancelled ||
                     !presentationOK)
            ? @"partial" : @"complete",
        @"engine": @"iconservices-publisher",
        @"totalApplicationsDiscovered": catalog[@"applicationCount"] ?: @0,
        @"themeEntriesLoaded": @(themeLookup.count),
        @"matchedApplications": @(matched.count),
        @"airDropThemeAssetPresent": @(airDropThemeAssetPresent),
        @"airDropTargetActive": @(airDropActive),
        @"airDropTargetStage": airDropStage,
        @"airDropFailedPublicationVerifiedStock":
            @(airDropFailedPublicationVerifiedStock),
        @"airDropVerifiedVariants": @(airDropVerifiedVariants),
        @"airDropResolvedSourceVariants":
            @(airDropResolvedSourceVariants),
        @"airDropVerifiedSourceVariants":
            @(airDropVerifiedSourceVariants),
        @"airDropSourceEntriesBefore": @(airDropSourceEntriesBefore),
        @"airDropSourceEntriesAfter": @(airDropSourceEntriesAfter),
        @"airDropSourceWriteIssued": @(airDropSourceWriteIssued),
        @"airDropPresentation": airDropPresentation ?: @{},
        @"airDropPresentationOK": @(airDropPresentationOK),
        @"applied": @(applied),
        @"alreadyActive": @(alreadyActive),
        @"plannedVariants": @(plannedVariants),
        @"publishedVariants": @(publishedVariants),
        @"failedVariants": @(failedVariants),
        @"rebasedApplications": @(rebasedApplications),
        @"updateRebaseFailures": @(rebaseFailures),
        @"adoptedLegacyFingerprints": @(adoptedLegacyFingerprints),
        @"updatedApplicationRebases": @(updatedApplicationRebases),
        @"failed": @(failed),
        @"skipped": @(skipped),
        @"cancelled": @(cancelled),
        @"activeBundleIdentifiers": activeIdentifiers,
        @"results": results,
        @"unthemedApplications": unthemed,
        @"catalog": catalog ?: @{},
        @"batchSessionStart": batchStart ?: @{},
        @"batchSessionFinish": batchFinish ?: @{},
        @"oneShotPresentation": oneShotPresentation ?: @{},
        @"presentationCompleted": @NO,
        @"presentationDeferredToManualActions": @YES,
        @"presentationOK": @(presentationOK),
        @"presentationLifecycle": presentationLifecycle ?: @{},
        @"spotlightPresentation": spotlightPresentation ?: @{},
        @"presentationAutoStart": @NO,
        @"springBoardWatcherEnabled": @NO,
        @"presentationBundleIdentifiers": presentationBundleIdentifiers,
        @"bundleFilter": foldedBundleFilter.allObjects ?: @[],
        @"isolatedAirDropOnly": @(!refreshSpringBoardConsumers &&
            foldedBundleFilter.count == 1 &&
            [foldedBundleFilter containsObject:
                CNDRemixAirDropPseudoBundleIdentifier.lowercaseString]),
        @"springBoardPresentationSkipped": @(!refreshSpringBoardConsumers),
        @"spotlightPresentationPending": @(!spotlightReady),
        @"cacheInvalidationIssued":
            oneShotPresentation[@"cacheInvalidationIssued"] ?: @NO,
        @"cacheInvalidationPolicy":
            (refreshSpringBoardConsumers &&
             CNDRemixEnableSpringBoardCacheInvalidation)
                ? @"bounded-springboard-refresh"
                : (refreshSpringBoardConsumers
                    ? @"disabled-experiment"
                    : @"isolated-share-sheet-only"),
        @"springBoardCacheRefreshCompleted":
            oneShotPresentation[@"springBoardCacheRefreshCompleted"] ?: @NO,
        @"iconServicesStorePreserved": @YES,
        @"presentationRemoteCallUsed":
            @([oneShotPresentation[@"remoteCallUsed"] boolValue] ||
              [airDropPresentation[@"remoteCallUsed"] boolValue]),
        @"structuredPayloadCache": @{
            @"schemaVersion": @(CNDRemixPayloadCacheSchemaVersion),
            @"pipelineIdentifier": CNDRemixPayloadPipelineIdentifier,
            @"diskHits": @(payloadCacheDiskHits),
            @"memoryHits": @(payloadCacheMemoryHits),
            @"hits": @(payloadCacheDiskHits + payloadCacheMemoryHits),
            @"misses": @(payloadCacheMisses),
            @"writes": @(payloadCacheWrites),
            @"writeFailures": @(payloadCacheWriteFailures),
            @"invalidEntriesIgnored": @(payloadCacheInvalidEntries),
            @"coldStart": @(payloadCacheColdStartLogged),
        },
    };
    log_user("[SBR_CACHE] structured payloads hits=%lu disk=%lu memory=%lu "
             "misses=%lu writes=%lu write-failures=%lu invalid=%lu\n",
             (unsigned long)(payloadCacheDiskHits + payloadCacheMemoryHits),
             (unsigned long)payloadCacheDiskHits,
             (unsigned long)payloadCacheMemoryHits,
             (unsigned long)payloadCacheMisses,
             (unsigned long)payloadCacheWrites,
             (unsigned long)payloadCacheWriteFailures,
             (unsigned long)payloadCacheInvalidEntries);
    NSError *indexError = nil;
    BOOL indexOK = CNDRemixWriteIndex(summary, &indexError);
    BOOL ok = sessionClosed && !cancelled && failed == 0 &&
        presentationOK && indexOK;
    return CNDRemixCoordinatorResult(ok,
        ok ? @"complete" : @"partial",
        ok
            ? (!refreshSpringBoardConsumers
                ? @"The isolated AirDrop test published and verified exactly two persistent records, verified their source associations, and refreshed only SharingUIService."
                : (CNDRemixEnableSpringBoardCacheInvalidation
                ? @"SnowBoard Remix published and verified every matched persistent IconServices response, then refreshed SpringBoard's icon caches. Use the separate presentation actions to apply tweaks."
                : @"SnowBoard Remix published and verified every matched persistent IconServices response. SpringBoard cache invalidation was intentionally skipped for the current experiment."))
            : (!refreshSpringBoardConsumers &&
                airDropFailedPublicationVerifiedStock
                ? @"AirDrop publication did not verify. Both persistent records are verified stock; no recovery write is required."
                : @"The complete apply operation did not verify. Persistent per-app journal state still reflects each app's actual store state."),
        summary);
}

static NSDictionary<NSString *, id> *
CNDRemixRestoreSpringBoardPresentationIfNeeded(
    BOOL persistentThemeMutationWasRestored)
{
    NSDictionary *dynamicState =
        CNDRemixLiveSpringBoardDynamicPresentationState();
    BOOL dynamicCleanupRequired = [dynamicState[@"installed"] boolValue];
    BOOL cacheRefreshRequired =
        CNDRemixEnableSpringBoardCacheInvalidation &&
        persistentThemeMutationWasRestored;

    CNDIconServicesConsumerLifecycleSetStaticDynamicIconData(@{});
    NSDictionary *repair =
        (cacheRefreshRequired
            ? CNDIconServicesConsumerLifecycleRepairAfterThemeMutation(
                @"SpringBoard", UIScreen.mainScreen.scale)
            : CNDIconServicesConsumerLifecycleRepairProcess(
                @"SpringBoard", UIScreen.mainScreen.scale)) ?: @{};
    NSMutableDictionary *result = [repair mutableCopy];
    result[@"dynamicPresentationCleanupRequired"] =
        @(dynamicCleanupRequired);
    result[@"dynamicPresentationState"] = dynamicState ?: @{};
    result[@"cacheInvalidationIssued"] = @(cacheRefreshRequired);
    result[@"cacheInvalidationPolicy"] = cacheRefreshRequired
        ? @"bounded-springboard-refresh"
        : (CNDRemixEnableSpringBoardCacheInvalidation
            ? @"not-required" : @"disabled-experiment");
    if ([repair[@"ok"] boolValue] && dynamicCleanupRequired) {
        BOOL markerCleared =
            CNDRemixRemoveSpringBoardDynamicPresentationState();
        result[@"dynamicPresentationStateCleared"] = @(markerCleared);
        if (!markerCleared) {
            result[@"ok"] = @NO;
            result[@"stage"] = @"dynamic-presentation-state-cleanup";
            result[@"message"] =
                @"Clock/Calendar presentation was restored, but its durable state marker could not be cleared.";
        }
    }
    return result;
}

static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals(
    NSSet<NSString *> *bundleFilter,
    BOOL refreshAirDropConsumer,
    CNDSnowBoardRemixProgress progress,
    CNDSnowBoardRemixCancellation cancellation)
{
    BOOL isolatedAirDropOnly = bundleFilter.count == 1 &&
        [bundleFilter containsObject:CNDRemixAirDropPseudoBundleIdentifier];
    BOOL airDropRefreshRequested = refreshAirDropConsumer &&
        [bundleFilter containsObject:CNDRemixAirDropPseudoBundleIdentifier];
    NSArray<NSDictionary *> *allJournals = CNDRemixIconServicesJournals();
    NSMutableArray<NSDictionary *> *journals = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *discardResults =
        [NSMutableArray array];
    NSUInteger selectedJournalCount = 0;
    NSUInteger discardedUnmutated = 0;
    NSUInteger discardFailures = 0;
    for (NSDictionary *journal in allJournals) {
        NSString *bundleIdentifier = journal[@"bundleIdentifier"];
        /* Restore All leaves the isolated AirDrop transaction untouched,
         * including its recovery journal. Its dedicated Restore owns it. */
        if (!bundleFilter &&
            CNDRemixIsSupportedPseudoBundleIdentifier(bundleIdentifier)) continue;
        if (!bundleFilter || [bundleFilter containsObject:bundleIdentifier]) {
            selectedJournalCount++;
            if (CNDRemixJournalProvesNoIconServicesMutation(journal)) {
                BOOL removed =
                    CNDRemixRemoveIconServicesJournal(bundleIdentifier);
                if (removed) {
                    discardedUnmutated++;
                } else {
                    discardFailures++;
                }
                [discardResults addObject:@{
                    @"bundleIdentifier": bundleIdentifier ?: @"",
                    @"ok": @(removed),
                    @"stage": removed
                        ? @"discarded-unmutated-preflight"
                        : @"discard-unmutated-preflight-failed",
                }];
                continue;
            }
            [journals addObject:journal];
        }
    }
    if (journals.count == 0) {
        BOOL ok = YES;
        NSDictionary *restorePresentation = isolatedAirDropOnly
            ? @{
                @"ok": @YES,
                @"stage": @"isolated-airdrop-not-required",
                @"message": @"The isolated AirDrop restore does not repair any SpringBoard icon consumer.",
                @"completed": @YES,
                @"remoteCallUsed": @NO,
            }
            : CNDRemixRestoreSpringBoardPresentationIfNeeded(NO);
        NSDictionary *airDropPresentation =
            CNDRemixRefreshAirDropPresentationIfNeeded(
                airDropRefreshRequested);
        BOOL presentationOK = [restorePresentation[@"ok"] boolValue] &&
            [airDropPresentation[@"ok"] boolValue];
        NSDictionary *summary = @{
            @"engine": @"iconservices-publisher",
            @"journaled": @(selectedJournalCount),
            @"restored": @0,
            @"discardedUnmutatedPreflight": @(discardedUnmutated),
            @"discardFailures": @(discardFailures),
            @"results": discardResults,
            @"persistentDataClean": @YES,
            @"persistentCleanApplications": @(selectedJournalCount),
            @"persistentDirtyApplications": @0,
            @"persistentRecoveryOK": @(ok),
            @"journalCleanupOK": @(discardFailures == 0),
            @"presentationOK": @(presentationOK),
            @"presentationCompleted": @YES,
            @"restorePresentation": restorePresentation ?: @{},
            @"airDropPresentation": airDropPresentation ?: @{},
            @"isolatedAirDropOnly": @(isolatedAirDropOnly),
            @"springBoardPresentationSkipped": @(isolatedAirDropOnly),
            @"presentationAutoStart": @NO,
            @"springBoardWatcherEnabled": @NO,
            @"presentationRemoteCallUsed":
                @([restorePresentation[@"remoteCallUsed"] boolValue] ||
                  [airDropPresentation[@"remoteCallUsed"] boolValue]),
        };
        NSError *indexError = nil;
        (void)CNDRemixWriteIndex(summary, &indexError);
        return CNDRemixCoordinatorResult(ok,
            discardFailures > 0 ? @"persistent-restored-journal-cleanup"
                : (discardedUnmutated > 0
                    ? @"discarded-unmutated-preflight" : @"already-restored"),
            discardFailures == 0
                ? (discardedUnmutated > 0
                    ? @"The failed descriptor preflight journals were cleared; no IconServices data had been modified."
                    : @"No IconServices theme transaction requires restoration.")
                : @"Persistent IconServices data is clean, but some untouched preflight journals could not be removed.",
            summary);
    }

    NSDictionary *batchStart =
        CNDIconServicesPublisherBeginBatch(
            CNDRemixIconServicesWakeIdentifier);
    if (![batchStart[@"ok"] boolValue]) {
        return CNDRemixCoordinatorResult(NO, @"restore-session",
            batchStart[@"message"] ?: @"The IconServices restore batch could not start.",
            @{ @"batchSessionStart": batchStart ?: @{} });
    }

    NSDictionary *catalog = nil;
    NSDictionary *batchFinish = nil;
    NSMutableArray<NSDictionary *> *results =
        [discardResults mutableCopy];
    NSUInteger failed = 0, plannedVariants = 0;
    NSUInteger journalCleanupFailures = discardFailures;
    NSUInteger restoredVariants = 0, failedVariants = 0;
    NSUInteger alreadyStockVariants = 0;
    NSUInteger skippedUnmutatedVariants = 0;
    NSUInteger restored = 0;
    NSUInteger persistentClean = discardedUnmutated + discardFailures;
    BOOL cancelled = NO;
    @try {
        catalog = CNDIconServicesPublisherCopyInstalledBundleIdentifiersInBatch();
        NSMutableSet<NSString *> *installed = [NSMutableSet set];
        for (NSString *identifier in catalog[@"bundleIdentifiers"] ?: @[]) {
            [installed addObject:identifier.lowercaseString];
        }
        if (![catalog[@"ok"] boolValue]) {
            failed++;
        } else {
            for (NSUInteger index = 0; index < journals.count; index++) {
                @autoreleasepool {
                    NSDictionary *saved = journals[index];
                    NSString *bundleIdentifier = saved[@"bundleIdentifier"];
                    if (cancellation && cancellation()) {
                        cancelled = YES;
                        break;
                    }
                    BOOL targetAvailable =
                        [installed containsObject:
                            bundleIdentifier.lowercaseString] ||
                        CNDRemixIsSupportedPseudoBundleIdentifier(
                            bundleIdentifier);
                    if (!targetAvailable) {
                        failed++;
                        [results addObject:@{
                            @"bundleIdentifier": bundleIdentifier,
                            @"ok": @NO, @"stage": @"uninstalled-orphan",
                        }];
                        continue;
                    }
                    if (!CNDIconServicesPublisherBatchIsHealthy()) {
                        failed += journals.count - index;
                        break;
                    }
                    NSMutableDictionary *journal = [saved mutableCopy];
                    NSArray<NSDictionary *> *savedVariants =
                        CNDRemixJournalVariants(saved);
                    plannedVariants += savedVariants.count;
                    NSMutableArray<NSDictionary *> *restoringVariants =
                        [NSMutableArray arrayWithCapacity:savedVariants.count];
                    BOOL currentSchema = [saved[@"schemaVersion"]
                        unsignedIntegerValue] ==
                            CNDRemixIconServicesJournalSchemaVersion;
                    for (NSDictionary *variant in savedVariants) {
                        NSMutableDictionary *updated = [variant mutableCopy];
                        if (currentSchema &&
                            CNDRemixVariantProvesNoIconServicesMutation(variant)) {
                            updated[@"state"] = @"unmutated-skipped";
                        }
                        [restoringVariants addObject:updated];
                    }
                    if (progress) progress(@"restoring", index,
                                           journals.count, bundleIdentifier);
                    NSMutableArray<NSDictionary *> *variantResults =
                        [NSMutableArray arrayWithCapacity:savedVariants.count];
                    NSMutableArray<NSDictionary *> *updatedVariants =
                        [restoringVariants mutableCopy];
                    BOOL allVerified = savedVariants.count > 0;
                    for (NSUInteger variantIndex = 0;
                         variantIndex < savedVariants.count;
                         variantIndex++) {
                        NSDictionary *savedVariant =
                            savedVariants[variantIndex];
                        if (currentSchema &&
                            CNDRemixVariantProvesNoIconServicesMutation(
                                savedVariant)) {
                            /* Preserve the original negative report so a
                             * retry can independently verify this proof. No
                             * descriptor construction or stock generation is
                             * needed for a variant that never mutated data. */
                            skippedUnmutatedVariants++;
                            [variantResults addObject:@{
                                @"descriptorIdentity":
                                    savedVariant[@"descriptorIdentity"] ?: @"",
                                @"ok": @YES,
                                @"stage": @"unmutated-skipped",
                                @"noMutationVerified": @YES,
                            }];
                            continue;
                        }
                        NSDictionary *specification =
                            savedVariant[@"descriptorSpecification"];
                        CNDIconServicesDescriptorSpec *validatedSpec =
                            [CNDIconServicesDescriptorSpec
                                specWithDictionary:specification error:nil];
                        BOOL isAirDrop =
                            CNDRemixIsSupportedPseudoBundleIdentifier(
                                bundleIdentifier);
                        NSDictionary *stockAudit = validatedSpec && isAirDrop
                            ? CNDIconServicesPublisherAuditVariantInBatch(
                                bundleIdentifier,
                                validatedSpec.dictionaryRepresentation)
                            : nil;
                        BOOL alreadyStock = validatedSpec && isAirDrop &&
                            CNDRemixAuditProvesSavedStock(
                                stockAudit, savedVariant);
                        if (isAirDrop) {
                            log_user("[SBR_AIRDROP_RECOVERY] descriptor=%s "
                                     "already-stock=%d audit-stage=%s "
                                     "source-ready=%d mutations=0\n",
                                     [savedVariant[@"descriptorIdentity"]
                                        UTF8String] ?: "?",
                                     alreadyStock,
                                     [stockAudit[@"stage"] UTF8String] ?:
                                        "not-audited",
                                     [stockAudit[@"sourceIdentityAuditReady"]
                                        boolValue]);
                        }
                        if (alreadyStock) {
                            alreadyStockVariants++;
                            NSMutableDictionary *variantJournal =
                                [updatedVariants[variantIndex] mutableCopy];
                            variantJournal[@"stockReadbackAudit"] =
                                CNDRemixCompactStockReadbackAudit(stockAudit);
                            variantJournal[@"state"] =
                                @"persistent-stock-verified";
                            variantJournal[@"updatedAt"] = NSDate.date;
                            updatedVariants[variantIndex] = variantJournal;
                            journal[@"variants"] = updatedVariants;
                            journal[@"updatedAt"] = NSDate.date;
                            (void)CNDRemixWriteIconServicesJournal(journal);
                            [variantResults addObject:@{
                                @"descriptorIdentity":
                                    savedVariant[@"descriptorIdentity"] ?: @"",
                                @"ok": @YES,
                                @"stage": @"already-stock-readback",
                                @"persistentDataVerified": @YES,
                                @"mutationsIssued": @NO,
                                @"stockAudit":
                                    CNDRemixCompactStockReadbackAudit(
                                        stockAudit),
                            }];
                            continue;
                        }
                        /* Getter audits do not enter recovery dispatch. Only
                         * checkpoint this one descriptor as restoring when a
                         * stock generation/write is actually about to run. */
                        NSMutableDictionary *dispatchVariant =
                            [updatedVariants[variantIndex] mutableCopy];
                        dispatchVariant[@"state"] = @"restoring";
                        dispatchVariant[@"restorationDispatchPossible"] = @YES;
                        dispatchVariant[@"updatedAt"] = NSDate.date;
                        updatedVariants[variantIndex] = dispatchVariant;
                        journal[@"variants"] = updatedVariants;
                        journal[@"state"] = @"restoring";
                        journal[@"updatedAt"] = NSDate.date;
                        if (!CNDRemixWriteIconServicesJournal(journal)) {
                            allVerified = NO;
                            failedVariants +=
                                savedVariants.count - variantIndex;
                            break;
                        }
                        NSDictionary *restoration = validatedSpec
                            ? CNDIconServicesPublisherRestoreStockVariantInBatch(
                                bundleIdentifier,
                                validatedSpec.dictionaryRepresentation)
                            : @{
                                @"ok": @NO,
                                @"stage": @"descriptor-specification",
                                @"message": @"The saved descriptor specification is invalid.",
                            };
                        BOOL verified = validatedSpec &&
                            (CNDIconServicesPublisherRestorationResultIsVerified(
                                restoration) ||
                             CNDRemixPublisherResultIsLegacyAcceptable(
                                restoration, @"stock"));
                        NSDictionary *postRestoreStockAudit = nil;
                        if (!verified && validatedSpec && isAirDrop &&
                            CNDIconServicesPublisherBatchIsHealthy()) {
                            NSMutableDictionary *currentVariant =
                                [savedVariant mutableCopy];
                            currentVariant[@"restoration"] =
                                CNDRemixCompactPublisherReport(restoration);
                            postRestoreStockAudit =
                                CNDIconServicesPublisherAuditVariantInBatch(
                                    bundleIdentifier,
                                    validatedSpec.dictionaryRepresentation);
                            verified = CNDRemixAuditProvesSavedStock(
                                postRestoreStockAudit, currentVariant);
                        }
                        CNDRemixLogIconServicesTransaction(
                            "RESTORE", bundleIdentifier, restoration,
                            verified);
                        NSMutableDictionary *variantJournal =
                            [updatedVariants[variantIndex] mutableCopy];
                        variantJournal[@"restoration"] =
                            CNDRemixCompactPublisherReport(restoration);
                        if (verified && postRestoreStockAudit) {
                            variantJournal[@"stockReadbackAudit"] =
                                CNDRemixCompactStockReadbackAudit(
                                    postRestoreStockAudit);
                        }
                        variantJournal[@"state"] = verified
                            ? @"persistent-stock-verified"
                            : @"recovery-required";
                        variantJournal[@"updatedAt"] = NSDate.date;
                        updatedVariants[variantIndex] = variantJournal;
                        [variantResults addObject:@{
                            @"descriptorIdentity":
                                savedVariant[@"descriptorIdentity"] ?: @"",
                            @"ok": @(verified),
                            @"stage": verified
                                ? @"persistent-stock-verified"
                                : restoration[@"stage"] ?: @"restore",
                            @"restoration":
                                CNDRemixCompactPublisherReport(restoration),
                            @"stockAudit":
                                CNDRemixCompactStockReadbackAudit(
                                    postRestoreStockAudit),
                        }];
                        if (verified) {
                            restoredVariants++;
                        } else {
                            failedVariants++;
                            allVerified = NO;
                        }
                        journal[@"variants"] = updatedVariants;
                        journal[@"updatedAt"] = NSDate.date;
                        if (!CNDRemixWriteIconServicesJournal(journal) &&
                            variantIndex + 1 < savedVariants.count) {
                            allVerified = NO;
                            break;
                        }
                        if (!CNDIconServicesPublisherBatchIsHealthy()) {
                            allVerified = NO;
                            failedVariants +=
                                savedVariants.count - variantIndex - 1;
                            break;
                        }
                    }
                    journal[@"variants"] = updatedVariants;
                    journal[@"state"] = allVerified &&
                        variantResults.count == savedVariants.count
                        ? @"persistent-stock-verified"
                        : @"recovery-required";
                    journal[@"updatedAt"] = NSDate.date;
                    BOOL savedJournal = CNDRemixWriteIconServicesJournal(journal);
                    BOOL appVerified = allVerified &&
                        variantResults.count == savedVariants.count;
                    /* Persistent store/cache readback is the recovery
                     * boundary. Once every indexed descriptor is stock and
                     * verified, clear this app's journal immediately. A
                     * later batch close or presentation failure must not
                     * re-dirty already-restored persistent data. */
                    BOOL journalCleared = appVerified &&
                        CNDRemixRemoveIconServicesJournal(bundleIdentifier);
                    if (appVerified) persistentClean++;
                    if (journalCleared) {
                        restored++;
                    } else if (appVerified) {
                        journalCleanupFailures++;
                    } else {
                        failed++;
                    }
                    [results addObject:@{
                        @"bundleIdentifier": bundleIdentifier,
                        @"ok": @(appVerified),
                        @"stage": journalCleared
                            ? @"persistent-restored"
                            : (appVerified
                                ? @"persistent-restored-journal-cleanup"
                                : @"restoration-matrix"),
                        @"persistentDataVerified": @(appVerified),
                        @"journalCheckpointSaved": @(savedJournal),
                        @"journalCleared": @(journalCleared),
                        @"variantResults": variantResults,
                    }];
                }
            }
        }
    } @finally {
        if (progress) progress(@"finalizing-session", journals.count,
                               journals.count, nil);
        batchFinish = CNDIconServicesPublisherFinishBatch();
    }

    BOOL sessionClosed = [batchFinish[@"ok"] boolValue];
    NSDictionary<NSString *, id> *restorePresentation = @{
        @"ok": @YES,
        @"stage": @"not-required",
        @"completed": @YES,
        @"remoteCallUsed": @NO,
    };
    BOOL persistentThemeMutationWasRestored =
        persistentClean > discardedUnmutated + discardFailures;
    if (persistentThemeMutationWasRestored && !isolatedAirDropOnly) {
        /* Persistent state is already clean at this point. Finish the
         * operation by restoring Clock/Calendar sources and rebuilding the
         * current SpringBoard consumers synchronously. Report this optional
         * presentation cleanup independently from persistent recovery; it
         * never re-creates a cleared recovery journal. */
        restorePresentation =
            CNDRemixRestoreSpringBoardPresentationIfNeeded(YES);
    }
    NSDictionary *airDropPresentation =
        CNDRemixRefreshAirDropPresentationIfNeeded(
            airDropRefreshRequested);
    BOOL presentationOK = [restorePresentation[@"ok"] boolValue] &&
        [airDropPresentation[@"ok"] boolValue];
    BOOL persistentDataClean = persistentClean == selectedJournalCount;
    BOOL persistentRecoveryOK = persistentDataClean && !cancelled && failed == 0;
    BOOL cleanupOK = sessionClosed && presentationOK &&
        journalCleanupFailures == 0;
    NSDictionary *summary = @{
        @"engine": @"iconservices-publisher",
        @"journaled": @(selectedJournalCount),
        @"restored": @(restored),
        @"discardedUnmutatedPreflight": @(discardedUnmutated),
        @"discardFailures": @(discardFailures),
        @"journalCleanupFailures": @(journalCleanupFailures),
        @"journalCleanupOK": @(journalCleanupFailures == 0),
        @"plannedVariants": @(plannedVariants),
        @"restoredVariants": @(restoredVariants),
        @"alreadyStockVariants": @(alreadyStockVariants),
        @"skippedUnmutatedVariants": @(skippedUnmutatedVariants),
        @"failedVariants": @(failedVariants),
        @"failed": @(failed),
        @"cancelled": @(cancelled),
        @"results": results,
        @"catalog": catalog ?: @{},
        @"batchSessionStart": batchStart ?: @{},
        @"batchSessionFinish": batchFinish ?: @{},
        @"cacheInvalidationIssued": @(
            CNDRemixEnableSpringBoardCacheInvalidation &&
            persistentThemeMutationWasRestored && !isolatedAirDropOnly),
        @"cacheInvalidationPolicy": isolatedAirDropOnly
            ? @"isolated-share-sheet-only"
            : (CNDRemixEnableSpringBoardCacheInvalidation
                ? @"bounded-springboard-refresh"
                : @"disabled-experiment"),
        @"iconServicesStorePreserved": @YES,
        @"restoreStrategy":
            @"per-descriptor-stock-generation-exact-readback",
        @"bundleWideInvalidationIssued": @NO,
        @"persistentRestoreCommittedBeforeBatchFinalization": @YES,
        @"batchSessionClosed": @(sessionClosed),
        @"persistentDataClean": @(persistentDataClean),
        @"persistentRecoveryOK": @(persistentRecoveryOK),
        @"cleanupOK": @(cleanupOK),
        @"persistentCleanApplications": @(persistentClean),
        @"persistentDirtyApplications": @(
            selectedJournalCount - MIN(selectedJournalCount,
                                        persistentClean)),
        @"presentationCompleted": @YES,
        @"presentationOK": @(presentationOK),
        @"restorePresentation": restorePresentation ?: @{},
        @"airDropPresentation": airDropPresentation ?: @{},
        @"isolatedAirDropOnly": @(isolatedAirDropOnly),
        @"springBoardPresentationSkipped": @(isolatedAirDropOnly),
        @"presentationAutoStart": @NO,
        @"springBoardWatcherEnabled": @NO,
        @"presentationRemoteCallUsed":
            @([restorePresentation[@"remoteCallUsed"] boolValue] ||
              [airDropPresentation[@"remoteCallUsed"] boolValue]),
    };
    NSError *indexError = nil;
    (void)CNDRemixWriteIndex(summary, &indexError);
    return CNDRemixCoordinatorResult(persistentRecoveryOK,
        persistentRecoveryOK
            ? (cleanupOK ? @"restored" : @"persistent-restored-cleanup-partial")
            : (persistentDataClean
                ? @"persistent-restored-journal-cleanup" : @"restore-partial"),
        persistentRecoveryOK
            ? (cleanupOK
                ? @"Persistent IconServices recovery completed: every changed descriptor verified stock, untouched descriptors were skipped, and presentation cleanup completed."
                : @"Every selected persistent record is clean. Journal, session, or presentation cleanup is incomplete; this does not require another stock write.")
            : (persistentDataClean
                ? @"Persistent IconServices data is clean, but recovery journal cleanup is incomplete."
                : @"Some persistent IconServices responses still require recovery. Apps already verified stock remain clean and do not regain recovery journals."),
        summary);
}

static NSDictionary<NSString *, id> *CNDRemixRunTransparencyFixOperation(
    CNDHailMaryImpRedirectOperation operation)
{
    if (NSThread.isMainThread) {
        return CNDRemixCoordinatorResult(
            NO, @"main-thread-refused",
            @"Transparency Fix must run on the queue worker, not the main thread.",
            nil);
    }

    NSString *supportReason = nil;
    if (!CNDHailMaryImpRedirectIsSupported(&supportReason)) {
        return CNDRemixCoordinatorResult(
            NO, @"unsupported", supportReason ?: @"Transparency Fix is unsupported on this device.", nil);
    }
    if (!kexploit_krw_ready()) {
        return CNDRemixCoordinatorResult(
            NO, @"krw-unavailable",
            @"Validated kernel read/write is required for Transparency Fix.",
            nil);
    }

    NSError *identityError = nil;
    pid_t spotlightPID = CNDKernelTaskBridgeResolveProcessPID(
        @"Spotlight", &identityError);
    NSDictionary<NSString *, id> *presentation = @{};
    if (spotlightPID <= 1) {
        log_user("[TRANSPARENCY_FIX] Spotlight is absent; presenting it for the guarded two-process proof.\n");
        presentation = CNDIconServicesConsumerHookPresentSpotlight() ?: @{};
        if (![presentation[@"ok"] boolValue]) {
            NSString *message = [presentation[@"message"]
                isKindOfClass:NSString.class]
                ? presentation[@"message"]
                : @"Spotlight could not be presented for the guarded proof.";
            return CNDRemixCoordinatorResult(
                NO, @"spotlight-presentation", message,
                @{ @"presentation": presentation });
        }
        identityError = nil;
        spotlightPID = CNDKernelTaskBridgeResolveProcessPID(
            @"Spotlight", &identityError);
    }
    if (spotlightPID <= 1) {
        return CNDRemixCoordinatorResult(
            NO, @"spotlight-identity",
            identityError.localizedDescription ?:
                @"Spotlight did not settle to one live identity for the guarded proof.",
            @{ @"presentation": presentation });
    }

    NSDictionary<NSString *, id> *(^runRedirect)(
        CNDHailMaryImpRedirectOperation) =
        ^NSDictionary<NSString *, id> *(
            CNDHailMaryImpRedirectOperation requestedOperation) {
        __block NSDictionary<NSString *, id> *finished = nil;
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        CNDHailMaryImpRedirectRun(requestedOperation,
            ^(NSDictionary<NSString *, id> *report) {
                finished = [report copy];
                dispatch_semaphore_signal(done);
            });
        dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
        return finished ?: @{};
    };

    NSDictionary<NSString *, id> *mutationReport = runRedirect(operation);
    NSDictionary<NSString *, id> *permissionProbeReport = @{};
    NSString *mutationResult = [mutationReport[@"result"]
        isKindOfClass:NSString.class] ? mutationReport[@"result"] : @"";
    BOOL permissionProofNeedsRefresh =
        [mutationResult isEqualToString:@"refused-permission-proof-required"] ||
        [mutationResult isEqualToString:
            @"refused-permission-proof-identity-mismatch"];
    if (permissionProofNeedsRefresh &&
        [mutationReport[@"kernelWritePrimitiveInvocationCount"]
            unsignedIntegerValue] == 0) {
        log_user("[TRANSPARENCY_FIX] Refreshing the same-boot .34 identical-bytes permission proof before the guarded redirect.\n");
        __block NSDictionary<NSString *, id> *finishedPermissionProbe = nil;
        dispatch_semaphore_t permissionProbeDone =
            dispatch_semaphore_create(0);
        CNDHailMaryReadOnlyDataPageRun(
            ^(NSDictionary<NSString *, id> *report) {
                finishedPermissionProbe = [report copy];
                dispatch_semaphore_signal(permissionProbeDone);
            });
        dispatch_semaphore_wait(
            permissionProbeDone, DISPATCH_TIME_FOREVER);
        permissionProbeReport = finishedPermissionProbe ?: @{};
        if ([permissionProbeReport[@"confirmed"] boolValue]) {
            mutationReport = runRedirect(operation);
        }
    }

    BOOL ok = [mutationReport[@"confirmed"] boolValue] ||
        [mutationReport[@"mutationConfirmed"] boolValue];
    NSDictionary<NSString *, id> *verificationReport = @{};
    if (!ok && [mutationReport[@"kernelWritePrimitiveInvocationCount"]
                    unsignedIntegerValue] == 0) {
        CNDHailMaryImpRedirectOperation verifyOperation =
            operation == CNDHailMaryImpRedirectOperationApply
                ? CNDHailMaryImpRedirectOperationVerifyRedirected
                : CNDHailMaryImpRedirectOperationVerifyOriginal;
        __block NSDictionary<NSString *, id> *verified = nil;
        dispatch_semaphore_t verifyDone = dispatch_semaphore_create(0);
        CNDHailMaryImpRedirectRun(verifyOperation,
            ^(NSDictionary<NSString *, id> *report) {
                verified = [report copy];
                dispatch_semaphore_signal(verifyDone);
            });
        dispatch_semaphore_wait(verifyDone, DISPATCH_TIME_FOREVER);
        verificationReport = verified ?: @{};
        ok = [verificationReport[@"confirmed"] boolValue];
    }

    BOOL apply = operation == CNDHailMaryImpRedirectOperationApply;
    NSString *message = nil;
    if (ok) {
        message = apply
            ? @"Transparency Fix is active for this boot. No process was killed or restarted; inspect the UI manually."
            : @"Transparency Fix was restored to stock. No process was killed or restarted; inspect the UI manually.";
    } else {
        message = [mutationReport[@"message"] isKindOfClass:NSString.class]
            ? mutationReport[@"message"]
            : @"Transparency Fix did not complete.";
    }
    log_user("[TRANSPARENCY_FIX] operation=%s ok=%s spotlight-pid=%d result=%s\n",
        apply ? "apply" : "restore", ok ? "yes" : "no", spotlightPID,
        [mutationReport[@"result"] UTF8String] ?: "unknown");
    return CNDRemixCoordinatorResult(
        ok, ok ? (apply ? @"active" : @"restored") : @"failed",
        message,
        @{
            @"spotlightPID": @(spotlightPID),
            @"presentation": presentation,
            @"permissionProbeReport": permissionProbeReport,
            @"mutationReport": mutationReport,
            @"verificationReport": verificationReport,
            @"automaticProcessKillOrRestartCount": @0,
            @"postwriteProcessLifecycleMutationCount": @0,
            @"spotlightPresentedForPreflight": @([presentation[@"ok"] boolValue]),
            @"manualVisualCheckRequired": @YES,
        });
}

@implementation CNDSnowBoardRemix

+ (NSDictionary<NSString *, id> *)setTransparencyFixEnabled:(BOOL)enabled
{
    return CNDRemixRunTransparencyFixOperation(
        enabled ? CNDHailMaryImpRedirectOperationApply
                : CNDHailMaryImpRedirectOperationRestore);
}

+ (NSDictionary<NSString *, id> *)reconcilePresentationLifecycle
{
    return CNDRemixReconcilePresentationLifecycle();
}

+ (NSDictionary<NSString *, id> *)applySpringBoardTweaks
{
    NSArray<NSString *> *active =
        CNDRemixActiveIconServicesBundleIdentifiers();
    NSDictionary<NSString *, NSData *> *themeLookup =
        CNDRemixNormalizedThemeLookup(
            settings_sbl_selected_theme_data());
    NSDictionary<NSString *, NSData *> *staticIcons =
        CNDRemixStaticDynamicIconDataFromThemeLookup(
            themeLookup, active);
    CNDIconServicesConsumerLifecycleSetStaticDynamicIconData(staticIcons);
    BOOL clockRequested = staticIcons[@"com.apple.mobiletimer"].length > 0;
    BOOL calendarRequested = staticIcons[@"com.apple.mobilecal"].length > 0;
    BOOL clockBackgroundAvailable =
        staticIcons[@"__cnd_clock_background"].length > 0;
    NSUInteger clockComponentCount = 0;
    for (NSString *key in @[
            @"__cnd_clock_hours", @"__cnd_clock_minutes",
            @"__cnd_clock_seconds", @"__cnd_clock_hour_minute_dot",
            @"__cnd_clock_second_dot"]) {
        if (staticIcons[key].length > 0) clockComponentCount++;
    }
    log_user("[SBR_DYNAMIC_ICONS] explicit SpringBoard repair active=%lu "
             "staged=%lu clock=%s calendar=%s background=%s "
             "calendar-provider-source=%s components=%lu/5\n",
             (unsigned long)active.count,
             (unsigned long)staticIcons.count,
             clockRequested ? "yes" : "no",
             calendarRequested ? "yes" : "no",
             clockBackgroundAvailable ? "yes" : "no",
             calendarRequested ? "yes" : "no",
             (unsigned long)clockComponentCount);
    NSDictionary<NSString *, id> *repair =
        CNDIconServicesConsumerLifecycleRepairProcess(
        @"SpringBoard", UIScreen.mainScreen.scale);
    NSMutableDictionary<NSString *, id> *result =
        [repair isKindOfClass:NSDictionary.class]
            ? [repair mutableCopy] : [NSMutableDictionary dictionary];
    NSDictionary *sourceResult = [result[@"install"][@"staticIcons"]
        isKindOfClass:NSDictionary.class]
        ? result[@"install"][@"staticIcons"] : @{};
    result[@"clockCalendarSourcesRequested"] = @YES;
    result[@"dynamicIconSourcesSupported"] = @YES;
    result[@"dynamicIconSourcesVerified"] =
        @((!clockRequested && !calendarRequested) ||
          [sourceResult[@"ok"] boolValue]);
    result[@"clockRequested"] = @(clockRequested);
    result[@"calendarRequested"] = @(calendarRequested);
    result[@"clockBackgroundAvailable"] = @(clockBackgroundAvailable);
    result[@"calendarProviderSourceAvailable"] = @(calendarRequested);
    result[@"clockComponentCount"] = @(clockComponentCount);
    result[@"clockComponentsComplete"] =
        @(!clockRequested || clockComponentCount == 5);
    BOOL dynamicPresentationRequested = clockRequested || calendarRequested;
    BOOL dynamicPresentationInstalled = [repair[@"ok"] boolValue] &&
        [sourceResult[@"ok"] boolValue] && dynamicPresentationRequested;
    BOOL dynamicPresentationStateRecorded =
        !dynamicPresentationRequested;
    BOOL staleDynamicPresentationStateCleared = NO;
    if (dynamicPresentationInstalled) {
        dynamicPresentationStateRecorded =
            CNDRemixWriteSpringBoardDynamicPresentationState(
                [repair[@"pid"] intValue],
                clockRequested, calendarRequested);
    } else if ([repair[@"ok"] boolValue] &&
               !dynamicPresentationRequested) {
        staleDynamicPresentationStateCleared =
            CNDRemixRemoveSpringBoardDynamicPresentationState();
    }
    result[@"dynamicPresentationInstalled"] =
        @(dynamicPresentationInstalled);
    result[@"dynamicPresentationStateRecorded"] =
        @(dynamicPresentationStateRecorded);
    result[@"staleDynamicPresentationStateCleared"] =
        @(staleDynamicPresentationStateCleared);
    if (dynamicPresentationInstalled &&
        !dynamicPresentationStateRecorded) {
        result[@"ok"] = @NO;
        result[@"stage"] = @"dynamic-presentation-state-journal";
        result[@"message"] =
            @"Clock/Calendar presentation was installed, but its durable SpringBoard PID marker could not be verified.";
    }
    if ([result[@"ok"] boolValue]) {
        result[@"message"] =
            @"SpringBoard transparency, the exact live Clock face/hand source, and Calendar's exact provider source were installed and verified.";
    }
    return result;
}

+ (NSDictionary<NSString *, id> *)presentSpotlight
{
    return CNDIconServicesConsumerHookPresentSpotlight();
}

+ (NSDictionary<NSString *, id> *)repairSpotlightPresentation
{
    NSDictionary<NSString *, NSData *> *themeLookup =
        CNDRemixNormalizedThemeLookup(settings_sbl_selected_theme_data());
    NSArray<NSString *> *active = CNDRemixActiveIconServicesBundleIdentifiers();
    NSDictionary<NSString *, NSData *> *staticIcons =
        CNDRemixStaticDynamicIconDataFromThemeLookup(themeLookup, active);
    CNDIconServicesConsumerLifecycleSetStaticDynamicIconData(staticIcons);
    BOOL clockRequested = staticIcons[@"com.apple.mobiletimer"].length > 0;
    BOOL calendarRequested = staticIcons[@"com.apple.mobilecal"].length > 0;
    BOOL filesThumbnailRequested =
        staticIcons[@"com.apple.DocumentsApp"].length > 0;
    NSDictionary<NSString *, id> *repair =
        CNDIconServicesConsumerLifecycleRepairProcess(
            @"Spotlight", UIScreen.mainScreen.scale);
    NSMutableDictionary<NSString *, id> *result =
        [repair mutableCopy] ?: [NSMutableDictionary dictionary];
    NSDictionary *sourceResult = [result[@"install"][@"staticIcons"]
        isKindOfClass:NSDictionary.class]
        ? result[@"install"][@"staticIcons"] : @{};
    BOOL transparencyVerified = [repair[@"transparencyVerified"] boolValue];
    BOOL dynamicIconSourcesVerified =
        (!clockRequested && !calendarRequested && !filesThumbnailRequested) ||
        [sourceResult[@"ok"] boolValue];
    result[@"transparencyVerified"] = @(transparencyVerified);
    result[@"clockRequested"] = @(clockRequested);
    result[@"calendarRequested"] = @(calendarRequested);
    result[@"filesThumbnailRequested"] = @(filesThumbnailRequested);
    result[@"dynamicIconSourcesVerified"] =
        @(dynamicIconSourcesVerified);
    result[@"dynamicIconSourcesAttempted"] =
        @(clockRequested || calendarRequested || filesThumbnailRequested);
    result[@"dynamicIconSourcesSupported"] = @YES;
    if ([repair[@"ok"] boolValue]) {
        result[@"message"] = @"Spotlight transparency, static Clock selection, Calendar's provider source, and the requested Files root thumbnail presentation are verified for this process.";
    } else if (transparencyVerified && !dynamicIconSourcesVerified) {
        NSDictionary *calendarResult =
            [sourceResult[@"calendarProviderSource"]
                isKindOfClass:NSDictionary.class]
                ? sourceResult[@"calendarProviderSource"] : @{};
        NSString *calendarStage =
            [calendarResult[@"stage"] isKindOfClass:NSString.class]
                ? calendarResult[@"stage"] : nil;
        result[@"stage"] = @"spotlight-transparency-ready-dynamic-icons-failed";
        result[@"message"] = calendarRequested &&
            ![sourceResult[@"calendarProviderSourceVerified"] boolValue]
            ? [NSString stringWithFormat:
                @"Spotlight transparency verified, but Calendar's Spotlight provider source did not (%@). Open Spotlight, then retry.",
                calendarStage ?: @"calendar-provider-source-verify"]
            : (filesThumbnailRequested &&
               ![sourceResult[@"filesThumbnailVerified"] boolValue]
                ? @"Spotlight transparency verified, but the Files root thumbnail was not materialized or did not verify. Open Spotlight, search for “files” until “File Provider Storage” appears, then retry."
                : @"Spotlight transparency verified, but its requested Clock source update did not verify.");
    }
    return result;
}

static NSString *CNDRemixAuditHashClassification(
    NSString *observed, NSString *themed, NSString *stock)
{
    if (![observed isKindOfClass:NSString.class] || observed.length == 0)
        return @"missing";
    if ([themed isKindOfClass:NSString.class] && themed.length > 0 &&
        [observed caseInsensitiveCompare:themed] == NSOrderedSame)
        return @"themed";
    if ([stock isKindOfClass:NSString.class] && stock.length > 0 &&
        [observed caseInsensitiveCompare:stock] == NSOrderedSame)
        return @"stock";
    return @"other";
}

static NSString *CNDRemixAppliedAuditSurface(
    NSDictionary<NSString *, NSNumber *> *specification)
{
    NSUInteger width = [specification[@"pointWidth"] unsignedIntegerValue];
    NSUInteger height = [specification[@"pointHeight"] unsignedIntegerValue];
    NSUInteger variantOptions =
        [specification[@"iconVariant"] unsignedIntegerValue];
    if (width != height) return @"other";
    if (width == 13) return @"home-folder-preview-child";
    if (width == 20) return @"spotlight-snippet-badge";
    if (width == 27) return @"app-library-miniature";
    if (width == 28) return @"switcher-transition";
    if (width == 38) return @"notification";
    if (width == 48) return @"app-library-list";
    if (width == 64) return @"spotlight-apps-list";
    if (width == 68 && variantOptions == 0x20000u)
        return @"launch-return-transition";
    if (width == 68) return @"home-app-library-large";
    return @"other";
}

static NSString *CNDRemixAppliedAuditRecordKey(NSDictionary *record)
{
    NSString *bundleIdentifier = [record[@"bundleIdentifier"]
        isKindOfClass:NSString.class] ? record[@"bundleIdentifier"] : @"";
    NSString *descriptorIdentity = [record[@"descriptorIdentity"]
        isKindOfClass:NSString.class] ? record[@"descriptorIdentity"] : @"";
    if (bundleIdentifier.length == 0 || descriptorIdentity.length == 0)
        return @"";
    return [NSString stringWithFormat:@"%lu:%@%lu:%@",
        (unsigned long)bundleIdentifier.length, bundleIdentifier,
        (unsigned long)descriptorIdentity.length, descriptorIdentity];
}

static NSDictionary *CNDRemixCompactAppliedAuditRecord(NSDictionary *record)
{
    if (![record isKindOfClass:NSDictionary.class]) return @{};
    NSDictionary *audit = [record[@"audit"] isKindOfClass:NSDictionary.class]
        ? record[@"audit"] : @{};
    NSMutableDictionary *compactAudit = [NSMutableDictionary dictionary];
    for (NSString *key in @[
            @"ok", @"stage", @"canonicalIconPointer",
            @"canonicalImageCachePointer", @"canonicalCacheReadReady",
            @"cacheResponsePresent", @"cacheDataLength",
            @"cacheDataSHA256", @"cacheIdentifier",
            @"validationTokenLength", @"validationTokenSHA256",
            @"storeIndexLookupReady", @"storeIndexEntryPresent",
            @"indexedIdentifier", @"storeValidationTokenLength",
            @"storeValidationTokenSHA256",
            @"storeUnitPresent", @"storeUnitValid", @"storeDataLength",
            @"storeDataSHA256", @"storeIdentifier", @"cacheStoreEqual",
            @"cacheStoreIdentifierEqual",
            @"cacheStoreValidationTokenEqual",
            @"storeIndexUnitIdentifierEqual",
            @"sourceIdentityAuditReady", @"sourceRegistryEntryCount",
            @"sourceRegistryDataPresent", @"sourceRegistryDataLength",
            @"sourceRegistryDataSHA256",
            @"currentSourceIdentifierPresent",
            @"currentSourceIdentifierLength",
            @"currentSourceIdentifierSHA256",
            @"sourceIdentityMatchesCurrentRecord"]) {
        if (audit[key]) compactAudit[key] = audit[key];
    }
    NSMutableDictionary *compact = [NSMutableDictionary dictionary];
    for (NSString *key in @[
            @"bundleIdentifier", @"surface", @"descriptorIdentity",
            @"descriptorSpecification", @"expectedThemedSHA256",
            @"expectedStockSHA256", @"cacheState", @"storeState",
            @"storeAliasDescriptorIdentity", @"storeAliasSurface",
            @"storeAliasExpectedThemedSHA256"]) {
        if (record[key]) compact[key] = record[key];
    }
    compact[@"audit"] = compactAudit;
    return compact;
}

static NSDictionary *CNDRemixCurrentInstallationIdentity(void)
{
    NSBundle *bundle = NSBundle.mainBundle;
    NSString *executable = bundle.executablePath ?: @"";
    NSDictionary *attributes = executable.length > 0
        ? [NSFileManager.defaultManager attributesOfItemAtPath:executable
                                                        error:nil] : nil;
    return @{
        @"bundleIdentifier": bundle.bundleIdentifier ?: @"",
        @"bundlePath": bundle.bundleURL.path ?: @"",
        @"shortVersion": [bundle objectForInfoDictionaryKey:
            @"CFBundleShortVersionString"] ?: @"",
        @"bundleVersion": [bundle objectForInfoDictionaryKey:
            @"CFBundleVersion"] ?: @"",
        @"executableSize": attributes[NSFileSize] ?: @0,
        @"executableModifiedAt": attributes[NSFileModificationDate] ?:
            NSDate.distantPast,
    };
}

static NSDictionary *CNDRemixReadAppliedAuditSnapshot(void)
{
    NSDictionary *snapshot = [NSDictionary dictionaryWithContentsOfURL:
        CNDRemixAppliedAuditSnapshotURL()];
    NSArray *records = [snapshot[@"records"] isKindOfClass:NSArray.class]
        ? snapshot[@"records"] : nil;
    if (![snapshot isKindOfClass:NSDictionary.class] ||
        [snapshot[@"schemaVersion"] unsignedIntegerValue] !=
            CNDRemixAppliedAuditSnapshotSchemaVersion ||
        !records || records.count > CNDRemixAppliedAuditMaximumTargets) {
        return nil;
    }
    for (id record in records) {
        if (![record isKindOfClass:NSDictionary.class] ||
            CNDRemixAppliedAuditRecordKey(record).length == 0) return nil;
    }
    return snapshot;
}

static BOOL CNDRemixWriteAppliedAuditSnapshot(NSDictionary *snapshot)
{
    NSArray *records = [snapshot[@"records"] isKindOfClass:NSArray.class]
        ? snapshot[@"records"] : nil;
    if (![snapshot isKindOfClass:NSDictionary.class] || !records ||
        records.count > CNDRemixAppliedAuditMaximumTargets) return NO;
    NSURL *url = CNDRemixAppliedAuditSnapshotURL();
    NSError *error = nil;
    if (![NSFileManager.defaultManager createDirectoryAtURL:
            url.URLByDeletingLastPathComponent withIntermediateDirectories:YES
            attributes:@{NSFileProtectionKey: NSFileProtectionNone}
            error:&error]) return NO;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:snapshot
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
    if (!data || ![data writeToURL:url options:NSDataWritingAtomic
                             error:&error]) return NO;
    NSDictionary *readback = [NSDictionary dictionaryWithContentsOfURL:url];
    return [readback isEqualToDictionary:snapshot];
}

static NSString *CNDRemixAppliedAuditText(NSDictionary *record,
                                           NSString *key)
{
    id value = record[key];
    return [value isKindOfClass:NSString.class] ? value : @"";
}

static BOOL CNDRemixAppliedAuditRecordHasValidPersistentStoreEvidence(
    NSDictionary *record)
{
    if (![record isKindOfClass:NSDictionary.class]) return NO;
    NSDictionary *audit = [record[@"audit"] isKindOfClass:NSDictionary.class]
        ? record[@"audit"] : @{};
    NSString *storeHash = CNDRemixAppliedAuditText(
        audit, @"storeDataSHA256");
    NSString *indexedIdentifier = CNDRemixAppliedAuditText(
        audit, @"indexedIdentifier");
    NSString *storeIdentifier = CNDRemixAppliedAuditText(
        audit, @"storeIdentifier");
    NSString *tokenHash = CNDRemixAppliedAuditText(
        audit, @"storeValidationTokenSHA256");
    NSString *sourceHash = CNDRemixAppliedAuditText(
        audit, @"sourceRegistryDataSHA256");
    NSString *currentSourceHash = CNDRemixAppliedAuditText(
        audit, @"currentSourceIdentifierSHA256");
    return [audit[@"ok"] boolValue] &&
        [audit[@"storeIndexLookupReady"] boolValue] &&
        [audit[@"storeIndexEntryPresent"] boolValue] &&
        [audit[@"storeUnitPresent"] boolValue] &&
        [audit[@"storeUnitValid"] boolValue] &&
        [audit[@"storeIndexUnitIdentifierEqual"] boolValue] &&
        CNDRemixIsSHA256String(storeHash) &&
        indexedIdentifier.length > 0 && storeIdentifier.length > 0 &&
        [indexedIdentifier isEqualToString:storeIdentifier] &&
        CNDRemixIsSHA256String(tokenHash) &&
        [audit[@"sourceIdentityAuditReady"] boolValue] &&
        [audit[@"sourceRegistryDataPresent"] boolValue] &&
        [audit[@"currentSourceIdentifierPresent"] boolValue] &&
        [audit[@"sourceIdentityMatchesCurrentRecord"] boolValue] &&
        CNDRemixIsSHA256String(sourceHash) &&
        CNDRemixIsSHA256String(currentSourceHash) &&
        [sourceHash isEqualToString:currentSourceHash];
}

static BOOL CNDRemixAppliedAuditStoreStateIsThemed(NSDictionary *record)
{
    NSString *state = CNDRemixAppliedAuditText(record, @"storeState");
    return [state isEqualToString:@"themed"] ||
        [state isEqualToString:@"themed-alias"];
}

static BOOL CNDRemixAppliedAuditRecordProvesThemedPersistence(
    NSDictionary *record)
{
    if (!CNDRemixAppliedAuditRecordHasValidPersistentStoreEvidence(record) ||
        !CNDRemixAppliedAuditStoreStateIsThemed(record)) return NO;
    NSDictionary *audit = [record[@"audit"] isKindOfClass:NSDictionary.class]
        ? record[@"audit"] : @{};
    NSString *storeHash = CNDRemixAppliedAuditText(
        audit, @"storeDataSHA256");
    NSString *expectedThemedHash = CNDRemixAppliedAuditText(
        record, @"expectedThemedSHA256");
    if ([CNDRemixAppliedAuditText(record, @"storeState")
            isEqualToString:@"themed"]) {
        return CNDRemixIsSHA256String(expectedThemedHash) &&
            [storeHash caseInsensitiveCompare:expectedThemedHash] ==
                NSOrderedSame;
    }
    NSString *aliasDescriptor = CNDRemixAppliedAuditText(
        record, @"storeAliasDescriptorIdentity");
    NSString *aliasHash = CNDRemixAppliedAuditText(
        record, @"storeAliasExpectedThemedSHA256");
    return aliasDescriptor.length > 0 &&
        ![aliasDescriptor isEqualToString:
            CNDRemixAppliedAuditText(record, @"descriptorIdentity")] &&
        CNDRemixIsSHA256String(aliasHash) &&
        [storeHash caseInsensitiveCompare:aliasHash] == NSOrderedSame;
}

static NSString *CNDRemixAppliedAuditStoreAliasKey(NSDictionary *record)
{
    if (!CNDRemixAppliedAuditRecordHasValidPersistentStoreEvidence(record))
        return @"";
    NSString *bundleIdentifier = CNDRemixAppliedAuditText(
        record, @"bundleIdentifier");
    NSDictionary *audit = [record[@"audit"] isKindOfClass:NSDictionary.class]
        ? record[@"audit"] : @{};
    NSString *indexedIdentifier = CNDRemixAppliedAuditText(
        audit, @"indexedIdentifier");
    if (bundleIdentifier.length == 0 || indexedIdentifier.length == 0)
        return @"";
    return [NSString stringWithFormat:@"%lu:%@%lu:%@",
        (unsigned long)bundleIdentifier.length, bundleIdentifier,
        (unsigned long)indexedIdentifier.length, indexedIdentifier];
}

static NSUInteger CNDRemixResolveAppliedAuditStoreAliases(
    NSArray<NSMutableDictionary *> *records)
{
    NSMutableDictionary<NSString *, NSMutableArray<NSMutableDictionary *> *>
        *groups = [NSMutableDictionary dictionary];
    for (NSMutableDictionary *record in records) {
        NSString *key = CNDRemixAppliedAuditStoreAliasKey(record);
        if (key.length == 0) continue;
        NSMutableArray<NSMutableDictionary *> *group = groups[key];
        if (!group) {
            group = [NSMutableArray array];
            groups[key] = group;
        }
        [group addObject:record];
    }

    NSUInteger resolvedCount = 0;
    for (NSArray<NSMutableDictionary *> *group in groups.allValues) {
        if (group.count < 2) continue;
        for (NSMutableDictionary *record in group) {
            if (![CNDRemixAppliedAuditText(record, @"storeState")
                    isEqualToString:@"other"]) continue;
            NSDictionary *audit = [record[@"audit"]
                isKindOfClass:NSDictionary.class] ? record[@"audit"] : @{};
            NSString *storeHash = CNDRemixAppliedAuditText(
                audit, @"storeDataSHA256");
            for (NSDictionary *peer in group) {
                if (peer == record ||
                    ![CNDRemixAppliedAuditText(peer, @"storeState")
                        isEqualToString:@"themed"] ||
                    !CNDRemixAppliedAuditRecordHasValidPersistentStoreEvidence(
                        peer)) continue;
                NSString *peerExpectedHash = CNDRemixAppliedAuditText(
                    peer, @"expectedThemedSHA256");
                NSDictionary *peerAudit = [peer[@"audit"]
                    isKindOfClass:NSDictionary.class] ? peer[@"audit"] : @{};
                NSString *peerStoreHash = CNDRemixAppliedAuditText(
                    peerAudit, @"storeDataSHA256");
                if (!CNDRemixIsSHA256String(peerExpectedHash) ||
                    [storeHash caseInsensitiveCompare:peerExpectedHash] !=
                        NSOrderedSame ||
                    [peerStoreHash caseInsensitiveCompare:storeHash] !=
                        NSOrderedSame) continue;
                NSString *peerDescriptor = CNDRemixAppliedAuditText(
                    peer, @"descriptorIdentity");
                if (peerDescriptor.length == 0 ||
                    [peerDescriptor isEqualToString:
                        CNDRemixAppliedAuditText(
                            record, @"descriptorIdentity")]) continue;
                record[@"storeState"] = @"themed-alias";
                record[@"storeAliasDescriptorIdentity"] = peerDescriptor;
                record[@"storeAliasSurface"] =
                    CNDRemixAppliedAuditText(peer, @"surface");
                record[@"storeAliasExpectedThemedSHA256"] = peerExpectedHash;
                resolvedCount++;
                break;
            }
        }
    }
    return resolvedCount;
}

static NSDictionary *CNDRemixCompareAppliedAuditRecords(
    NSDictionary *before, NSDictionary *after)
{
    NSDictionary *beforeAudit = [before[@"audit"]
        isKindOfClass:NSDictionary.class] ? before[@"audit"] : @{};
    NSDictionary *afterAudit = [after[@"audit"]
        isKindOfClass:NSDictionary.class] ? after[@"audit"] : @{};
    BOOL baselinePresent = before.count > 0;
    BOOL beforeStorePresent = [beforeAudit[@"storeUnitPresent"] boolValue];
    BOOL afterStorePresent = [afterAudit[@"storeUnitPresent"] boolValue];
    BOOL beforeThemed = CNDRemixAppliedAuditStoreStateIsThemed(before);
    BOOL afterThemed = CNDRemixAppliedAuditStoreStateIsThemed(after);
    BOOL afterStock = [CNDRemixAppliedAuditText(after, @"storeState")
        isEqualToString:@"stock"];
    NSString *beforeCacheHash = CNDRemixAppliedAuditText(
        beforeAudit, @"cacheDataSHA256");
    NSString *afterCacheHash = CNDRemixAppliedAuditText(
        afterAudit, @"cacheDataSHA256");
    NSString *beforeStoreHash = CNDRemixAppliedAuditText(
        beforeAudit, @"storeDataSHA256");
    NSString *afterStoreHash = CNDRemixAppliedAuditText(
        afterAudit, @"storeDataSHA256");
    NSString *beforeCacheIdentifier = CNDRemixAppliedAuditText(
        beforeAudit, @"cacheIdentifier");
    NSString *afterCacheIdentifier = CNDRemixAppliedAuditText(
        afterAudit, @"cacheIdentifier");
    NSString *beforeStoreIdentifier = CNDRemixAppliedAuditText(
        beforeAudit, @"storeIdentifier");
    NSString *afterStoreIdentifier = CNDRemixAppliedAuditText(
        afterAudit, @"storeIdentifier");
    NSString *beforeIndexedIdentifier = CNDRemixAppliedAuditText(
        beforeAudit, @"indexedIdentifier");
    NSString *afterIndexedIdentifier = CNDRemixAppliedAuditText(
        afterAudit, @"indexedIdentifier");
    NSString *beforeTokenHash = CNDRemixAppliedAuditText(
        beforeAudit, @"storeValidationTokenSHA256");
    NSString *afterTokenHash = CNDRemixAppliedAuditText(
        afterAudit, @"storeValidationTokenSHA256");
    NSString *beforeSourceHash = CNDRemixAppliedAuditText(
        beforeAudit, @"sourceRegistryDataSHA256");
    NSString *afterSourceHash = CNDRemixAppliedAuditText(
        afterAudit, @"sourceRegistryDataSHA256");
    NSString *beforeCurrentSourceHash = CNDRemixAppliedAuditText(
        beforeAudit, @"currentSourceIdentifierSHA256");
    NSString *afterCurrentSourceHash = CNDRemixAppliedAuditText(
        afterAudit, @"currentSourceIdentifierSHA256");
    BOOL cacheHashUnchanged = beforeCacheHash.length > 0 &&
        [beforeCacheHash isEqualToString:afterCacheHash];
    BOOL storeHashUnchanged = beforeStoreHash.length > 0 &&
        [beforeStoreHash isEqualToString:afterStoreHash];
    BOOL cacheIdentifierUnchanged = beforeCacheIdentifier.length > 0 &&
        [beforeCacheIdentifier isEqualToString:afterCacheIdentifier];
    BOOL storeIdentifierUnchanged = beforeStoreIdentifier.length > 0 &&
        [beforeStoreIdentifier isEqualToString:afterStoreIdentifier];
    BOOL indexIdentifierUnchanged = beforeIndexedIdentifier.length > 0 &&
        [beforeIndexedIdentifier isEqualToString:afterIndexedIdentifier];
    BOOL tokenUnchanged = beforeTokenHash.length > 0 &&
        [beforeTokenHash isEqualToString:afterTokenHash];
    BOOL sourceIdentityUnchanged = beforeSourceHash.length > 0 &&
        beforeCurrentSourceHash.length > 0 &&
        [beforeSourceHash isEqualToString:afterSourceHash] &&
        [beforeCurrentSourceHash isEqualToString:afterCurrentSourceHash];
    BOOL beforeSourceMatched =
        [beforeAudit[@"sourceIdentityMatchesCurrentRecord"] boolValue];
    BOOL afterSourceMatched =
        [afterAudit[@"sourceIdentityMatchesCurrentRecord"] boolValue];

    NSString *classification = @"changed";
    if (!baselinePresent) classification = @"not-in-baseline";
    else if (![afterAudit[@"ok"] boolValue]) classification = @"audit-failed";
    else if (![beforeAudit[@"ok"] boolValue])
        classification = @"baseline-incomplete";
    else if (beforeStorePresent && !afterStorePresent)
        classification = @"missing-after-reinstall";
    else if (!beforeSourceMatched)
        classification = @"baseline-source-incomplete";
    else if (!afterSourceMatched)
        classification = @"source-identity-mismatch";
    else if (beforeThemed && afterStock)
        classification = @"themed-to-stock";
    else if (beforeThemed && !afterThemed)
        classification = @"themed-replaced";
    else if (storeHashUnchanged && storeIdentifierUnchanged &&
             indexIdentifierUnchanged && tokenUnchanged &&
             sourceIdentityUnchanged)
        classification = @"unchanged";
    else if (storeHashUnchanged && sourceIdentityUnchanged)
        classification = @"reindexed-data-unchanged";

    return @{
        @"classification": classification,
        @"baselinePresent": @(baselinePresent),
        @"beforeThemed": @(beforeThemed),
        @"afterThemed": @(afterThemed),
        @"cacheHashUnchanged": @(cacheHashUnchanged),
        @"storeHashUnchanged": @(storeHashUnchanged),
        @"cacheIdentifierUnchanged": @(cacheIdentifierUnchanged),
        @"indexIdentifierUnchanged": @(indexIdentifierUnchanged),
        @"storeIdentifierUnchanged": @(storeIdentifierUnchanged),
        @"validationTokenUnchanged": @(tokenUnchanged),
        @"sourceIdentityUnchanged": @(sourceIdentityUnchanged),
        @"beforeSourceMatched": @(beforeSourceMatched),
        @"afterSourceMatched": @(afterSourceMatched),
        @"before": before ?: @{},
        @"after": after ?: @{},
    };
}

+ (NSDictionary<NSString *, id> *)auditAppliedIconState
{
    NSArray<NSDictionary *> *journals = CNDRemixIconServicesJournals();
    NSMutableArray<NSDictionary *> *targets = [NSMutableArray array];
    NSMutableOrderedSet<NSString *> *bundleIdentifiers =
        [NSMutableOrderedSet orderedSet];
    BOOL targetLimitExceeded = NO;
    for (NSDictionary *journal in journals) {
        if (CNDRemixJournalProvesNoIconServicesMutation(journal)) continue;
        NSString *bundleIdentifier = [journal[@"bundleIdentifier"]
            isKindOfClass:NSString.class] ? journal[@"bundleIdentifier"] : nil;
        if (bundleIdentifier.length == 0) continue;
        for (NSDictionary *variant in CNDRemixJournalVariants(journal)) {
            NSDictionary *specification = [variant[@"descriptorSpecification"]
                isKindOfClass:NSDictionary.class]
                ? variant[@"descriptorSpecification"] : nil;
            if (!specification) continue;
            if (targets.count >= CNDRemixAppliedAuditMaximumTargets) {
                targetLimitExceeded = YES;
                break;
            }
            [targets addObject:@{
                @"bundleIdentifier": bundleIdentifier,
                @"surface": CNDRemixAppliedAuditSurface(specification),
                @"descriptorIdentity":
                    variant[@"descriptorIdentity"] ?: @"",
                @"descriptorSpecification": specification,
                @"expectedThemedSHA256":
                    variant[@"structuredImageSHA256"] ?: @"",
                @"expectedStockSHA256":
                    [variant[@"publication"][@"stockResponse"][@"dataSHA256"]
                        isKindOfClass:NSString.class]
                        ? variant[@"publication"][@"stockResponse"][@"dataSHA256"]
                        : @"",
            }];
            [bundleIdentifiers addObject:bundleIdentifier];
        }
        if (targetLimitExceeded) break;
    }
    if (targetLimitExceeded) {
        return CNDRemixCoordinatorResult(
            NO, @"audit-target-limit",
            @"The applied-state audit exceeded its bounded descriptor limit.",
            @{
                @"targetLimit": @(CNDRemixAppliedAuditMaximumTargets),
                @"mutationsIssued": @NO,
                @"localSnapshotWritten": @NO,
            });
    }
    if (targets.count == 0) {
        return CNDRemixCoordinatorResult(
            NO, @"audit-no-active-records",
            @"No journaled IconServices descriptor records are available to inspect.",
            @{
                @"mutationsIssued": @NO,
                @"localSnapshotWritten": @NO,
            });
    }

    NSDictionary *previousSnapshot = CNDRemixReadAppliedAuditSnapshot();
    NSArray<NSDictionary *> *previousRecords =
        [previousSnapshot[@"records"] isKindOfClass:NSArray.class]
            ? previousSnapshot[@"records"] : @[];
    NSMutableDictionary<NSString *, NSDictionary *> *previousByKey =
        [NSMutableDictionary dictionaryWithCapacity:previousRecords.count];
    for (NSDictionary *record in previousRecords) {
        NSString *key = CNDRemixAppliedAuditRecordKey(record);
        if (key.length > 0 && !previousByKey[key]) previousByKey[key] = record;
    }

    log_user("[SBR_AUDIT] begin apps=%lu variants=%lu baseline=%s "
             "baseline-records=%lu mutations=0\n",
             (unsigned long)bundleIdentifiers.count,
             (unsigned long)targets.count,
             previousSnapshot ? "yes" : "no",
             (unsigned long)previousRecords.count);
    NSDictionary *batchStart = CNDIconServicesPublisherBeginBatch(
        CNDRemixIconServicesWakeIdentifier);
    if (![batchStart[@"ok"] boolValue]) {
        return CNDRemixCoordinatorResult(
            NO, @"audit-iconservices-session",
            batchStart[@"message"] ?:
                @"The read-only IconServices audit session could not start.",
            @{
                @"batchSessionStart": batchStart ?: @{},
                @"mutationsIssued": @NO,
                @"localSnapshotWritten": @NO,
            });
    }

    NSMutableArray<NSMutableDictionary *> *records =
        [NSMutableArray arrayWithCapacity:targets.count];
    NSUInteger themedStoreCount = 0;
    NSUInteger nonThemedStoreCount = 0;
    NSUInteger missingStoreCount = 0;
    NSUInteger cacheStoreMismatchCount = 0;
    NSUInteger failedCount = 0;
    NSDictionary *batchFinish = nil;
    @try {
        for (NSDictionary *target in targets) {
            if (!CNDIconServicesPublisherBatchIsHealthy()) {
                failedCount += targets.count - records.count;
                break;
            }
            NSDictionary *audit =
                CNDIconServicesPublisherAuditVariantInBatch(
                    target[@"bundleIdentifier"],
                    target[@"descriptorSpecification"]);
            NSString *cacheHash = [audit[@"cacheDataSHA256"]
                isKindOfClass:NSString.class] ? audit[@"cacheDataSHA256"] : @"";
            NSString *storeHash = [audit[@"storeDataSHA256"]
                isKindOfClass:NSString.class] ? audit[@"storeDataSHA256"] : @"";
            NSString *cacheState = CNDRemixAuditHashClassification(
                cacheHash, target[@"expectedThemedSHA256"],
                target[@"expectedStockSHA256"]);
            NSString *storeState = CNDRemixAuditHashClassification(
                storeHash, target[@"expectedThemedSHA256"],
                target[@"expectedStockSHA256"]);
            if ([audit[@"cacheResponsePresent"] boolValue] &&
                [audit[@"storeUnitPresent"] boolValue] &&
                ![audit[@"cacheStoreEqual"] boolValue]) {
                cacheStoreMismatchCount++;
            }
            if (![audit[@"ok"] boolValue]) failedCount++;
            NSMutableDictionary *record = [target mutableCopy];
            record[@"audit"] = audit ?: @{};
            record[@"cacheState"] = cacheState;
            record[@"storeState"] = storeState;
            [records addObject:record];
        }
    } @finally {
        batchFinish = CNDIconServicesPublisherFinishBatch();
    }

    NSUInteger aliasedThemedStoreCount =
        CNDRemixResolveAppliedAuditStoreAliases(records);
    for (NSDictionary *record in records) {
        NSDictionary *audit = [record[@"audit"]
            isKindOfClass:NSDictionary.class] ? record[@"audit"] : @{};
        NSString *cacheState = CNDRemixAppliedAuditText(
            record, @"cacheState");
        NSString *storeState = CNDRemixAppliedAuditText(
            record, @"storeState");
        if ([storeState isEqualToString:@"themed"]) themedStoreCount++;
        else if ([storeState isEqualToString:@"themed-alias"]) {
            /* Counted separately by the bounded alias resolver. */
        }
        else if ([storeState isEqualToString:@"missing"])
            missingStoreCount++;
        else nonThemedStoreCount++;
        log_user("[SBR_AUDIT_STORE] app=%s surface=%s descriptor=%s "
                 "audit-stage=%s "
                 "cache=%s store=%s alias-descriptor=%s "
                 "alias-surface=%s equal=%s cache-id=%s index-ready=%s "
                 "index-present=%s index-id=%s store-id=%s "
                 "persistent-token=%s cache-hash=%s store-hash=%s "
                 "source-count=%llu source-match=%s source-hash=%s "
                 "current-source-hash=%s expected-theme=%s "
                 "alias-expected-theme=%s expected-stock=%s\n",
                 [CNDRemixAppliedAuditText(
                    record, @"bundleIdentifier") UTF8String] ?: "?",
                 [CNDRemixAppliedAuditText(record, @"surface") UTF8String]
                    ?: "?",
                 [CNDRemixAppliedAuditText(
                    record, @"descriptorIdentity") UTF8String] ?: "?",
                 [CNDRemixAppliedAuditText(audit, @"stage") UTF8String]
                    ?: "?",
                 cacheState.UTF8String ?: "?",
                 storeState.UTF8String ?: "?",
                 [CNDRemixAppliedAuditText(record,
                    @"storeAliasDescriptorIdentity") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(record,
                    @"storeAliasSurface") UTF8String] ?: "",
                 [audit[@"cacheStoreEqual"] boolValue] ? "yes" : "no",
                 [CNDRemixAppliedAuditText(audit,
                    @"cacheIdentifier") UTF8String] ?: "",
                 [audit[@"storeIndexLookupReady"] boolValue] ? "yes" : "no",
                 [audit[@"storeIndexEntryPresent"] boolValue] ? "yes" : "no",
                 [CNDRemixAppliedAuditText(audit,
                    @"indexedIdentifier") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(audit,
                    @"storeIdentifier") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(audit,
                    @"storeValidationTokenSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(audit,
                    @"cacheDataSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(audit,
                    @"storeDataSHA256") UTF8String] ?: "",
                 (unsigned long long)[audit[@"sourceRegistryEntryCount"]
                    unsignedLongLongValue],
                 [audit[@"sourceIdentityMatchesCurrentRecord"] boolValue]
                    ? "yes" : "no",
                 [CNDRemixAppliedAuditText(audit,
                    @"sourceRegistryDataSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(audit,
                    @"currentSourceIdentifierSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(record,
                    @"expectedThemedSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(record,
                    @"storeAliasExpectedThemedSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(record,
                    @"expectedStockSHA256") UTF8String] ?: "");
    }

    BOOL iconServicesOK = failedCount == 0 &&
        [batchFinish[@"ok"] boolValue];
    BOOL currentThemedEvidenceComplete = iconServicesOK &&
        records.count == targets.count;
    if (currentThemedEvidenceComplete) {
        for (NSDictionary *record in records) {
            if (!CNDRemixAppliedAuditRecordProvesThemedPersistence(record)) {
                currentThemedEvidenceComplete = NO;
                break;
            }
        }
    }
    NSMutableArray<NSDictionary *> *comparisons =
        [NSMutableArray arrayWithCapacity:
            MAX(records.count, previousRecords.count)];
    NSMutableArray<NSDictionary *> *currentSnapshotRecords =
        [NSMutableArray arrayWithCapacity:records.count];
    NSMutableSet<NSString *> *observedKeys = [NSMutableSet set];
    NSUInteger comparisonUnchangedCount = 0;
    NSUInteger comparisonChangedCount = 0;
    NSUInteger comparisonMissingCount = 0;
    NSUInteger comparisonThemedToStockCount = 0;
    NSUInteger comparisonNewCount = 0;
    for (NSMutableDictionary *record in records) {
        NSDictionary *compact = CNDRemixCompactAppliedAuditRecord(record);
        NSString *key = CNDRemixAppliedAuditRecordKey(compact);
        NSDictionary *before = key.length > 0 ? previousByKey[key] : nil;
        NSDictionary *comparison = CNDRemixCompareAppliedAuditRecords(
            before ?: @{}, compact);
        NSString *classification = comparison[@"classification"];
        record[@"reinstallComparison"] = comparison;
        [currentSnapshotRecords addObject:compact];
        if (key.length > 0) [observedKeys addObject:key];
        if ([classification isEqualToString:@"unchanged"])
            comparisonUnchangedCount++;
        else if ([classification isEqualToString:@"not-in-baseline"])
            comparisonNewCount++;
        else {
            comparisonChangedCount++;
            if ([classification isEqualToString:@"missing-after-reinstall"])
                comparisonMissingCount++;
            if ([classification isEqualToString:@"themed-to-stock"])
                comparisonThemedToStockCount++;
        }
        NSDictionary *beforeAudit = [before[@"audit"]
            isKindOfClass:NSDictionary.class] ? before[@"audit"] : @{};
        NSDictionary *afterAudit = compact[@"audit"];
        log_user("[SBR_AUDIT_REINSTALL] app=%s surface=%s descriptor=%s "
                 "result=%s before-cache-id=%s after-cache-id=%s "
                 "before-index-id=%s after-index-id=%s "
                 "before-store-id=%s after-store-id=%s before-token=%s "
                 "after-token=%s before-store=%s after-store=%s "
                 "before-cache=%s after-cache=%s before-source=%s "
                 "after-source=%s before-source-match=%s "
                 "after-source-match=%s\n",
                 [compact[@"bundleIdentifier"] UTF8String] ?: "?",
                 [compact[@"surface"] UTF8String] ?: "?",
                 [compact[@"descriptorIdentity"] UTF8String] ?: "?",
                 classification.UTF8String ?: "?",
                 [CNDRemixAppliedAuditText(beforeAudit,
                    @"cacheIdentifier") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(afterAudit,
                    @"cacheIdentifier") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(beforeAudit,
                    @"indexedIdentifier") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(afterAudit,
                    @"indexedIdentifier") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(beforeAudit,
                    @"storeIdentifier") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(afterAudit,
                    @"storeIdentifier") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(beforeAudit,
                    @"storeValidationTokenSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(afterAudit,
                    @"storeValidationTokenSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(beforeAudit,
                    @"storeDataSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(afterAudit,
                    @"storeDataSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(beforeAudit,
                    @"cacheDataSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(afterAudit,
                    @"cacheDataSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(beforeAudit,
                    @"sourceRegistryDataSHA256") UTF8String] ?: "",
                 [CNDRemixAppliedAuditText(afterAudit,
                    @"sourceRegistryDataSHA256") UTF8String] ?: "",
                 [beforeAudit[@"sourceIdentityMatchesCurrentRecord"] boolValue]
                    ? "yes" : "no",
                 [afterAudit[@"sourceIdentityMatchesCurrentRecord"] boolValue]
                    ? "yes" : "no");
        [comparisons addObject:@{
            @"key": key ?: @"",
            @"bundleIdentifier": compact[@"bundleIdentifier"] ?: @"",
            @"surface": compact[@"surface"] ?: @"",
            @"descriptorIdentity": compact[@"descriptorIdentity"] ?: @"",
            @"comparison": comparison,
        }];
    }
    for (NSString *key in previousByKey) {
        if ([observedKeys containsObject:key]) continue;
        NSDictionary *before = previousByKey[key];
        comparisonChangedCount++;
        comparisonMissingCount++;
        [comparisons addObject:@{
            @"key": key,
            @"bundleIdentifier": before[@"bundleIdentifier"] ?: @"",
            @"surface": before[@"surface"] ?: @"",
            @"descriptorIdentity": before[@"descriptorIdentity"] ?: @"",
            @"comparison": @{
                @"classification": @"missing-current-target",
                @"baselinePresent": @YES,
                @"before": before,
                @"after": @{},
            },
        }];
    }
    NSDictionary *currentInstallation =
        CNDRemixCurrentInstallationIdentity();
    NSDictionary *currentSnapshot = @{
        @"schemaVersion": @(CNDRemixAppliedAuditSnapshotSchemaVersion),
        @"capturedAt": NSDate.date,
        @"installation": currentInstallation,
        @"records": currentSnapshotRecords,
    };
    NSDictionary *springBoard = iconServicesOK
        ? CNDIconServicesConsumerHookAuditSpringBoard(bundleIdentifiers.array)
        : @{
            @"ok": @NO,
            @"stage": @"iconservices-audit-incomplete",
            @"message": @"SpringBoard was not opened because the IconServices audit did not close cleanly.",
            @"mutationsIssued": @NO,
            @"remoteCallUsed": @NO,
    };
    BOOL springBoardOK = [springBoard[@"ok"] boolValue];
    BOOL comparisonStable = previousSnapshot &&
        comparisonChangedCount == 0 && comparisonNewCount == 0 &&
        previousRecords.count == currentSnapshotRecords.count;
    BOOL snapshotAdvanceEligible = currentThemedEvidenceComplete &&
        (!previousSnapshot || comparisonStable);
    BOOL snapshotWriteAttempted = iconServicesOK && springBoardOK &&
        snapshotAdvanceEligible;
    BOOL snapshotWritten = snapshotWriteAttempted &&
        CNDRemixWriteAppliedAuditSnapshot(currentSnapshot);
    BOOL comparisonCompleted = previousSnapshot &&
        iconServicesOK && springBoardOK;
    BOOL ok = comparisonCompleted || snapshotWritten;
    NSString *message = nil;
    if (comparisonCompleted && comparisonStable && snapshotWritten) {
        message = [NSString stringWithFormat:
            @"Compared %lu current descriptor records with the saved pre-reinstall audit: %lu unchanged and no differences. The verified themed state is now the next rolling baseline.",
            (unsigned long)records.count,
            (unsigned long)comparisonUnchangedCount];
    } else if (comparisonCompleted) {
        message = [NSString stringWithFormat:
            @"Compared %lu current descriptor records with the saved pre-reinstall audit: %lu unchanged, %lu changed, %lu missing, and %lu changed from themed to stock. The pre-reinstall baseline was preserved for diagnosis.",
            (unsigned long)records.count,
            (unsigned long)comparisonUnchangedCount,
            (unsigned long)comparisonChangedCount,
            (unsigned long)comparisonMissingCount,
            (unsigned long)comparisonThemedToStockCount];
    } else if (snapshotWritten) {
        message = [NSString stringWithFormat:
            @"Captured the pre-reinstall baseline for %lu descriptor records. Reinstall Cyanide as an update, then run this audit again to compare current-index UUIDs, persistent validation tokens, source identities, and cache/store hashes.",
            (unsigned long)records.count];
    } else if (iconServicesOK && springBoardOK &&
               !currentThemedEvidenceComplete) {
        message = @"The read-only audit completed, but not every descriptor had an internally consistent themed persistent index/store/source record. The process cache is supplementary and is not required. No baseline was written; reapply the theme before capturing it.";
    } else if (snapshotWriteAttempted && !snapshotWritten) {
        message = @"The read-only target audits completed, but the local reinstall baseline could not be persisted; do not reinstall until the snapshot error is resolved.";
    } else {
        message = @"The applied-state audit did not complete both read-only sessions; the rolling reinstall baseline was not advanced. Inspect the SBR_AUDIT lines.";
    }
    log_user("[SBR_AUDIT] complete ok=%s themed-store=%lu "
             "aliased-store=%lu non-themed-store=%lu missing-store=%lu "
             "cache-store-mismatch=%lu "
             "failed=%lu springboard=%s baseline=%s unchanged=%lu changed=%lu "
             "missing-after=%lu themed-to-stock=%lu new=%lu evidence=%s "
             "snapshot=%s mutations=0\n",
             ok ? "yes" : "no",
             (unsigned long)themedStoreCount,
             (unsigned long)aliasedThemedStoreCount,
             (unsigned long)nonThemedStoreCount,
             (unsigned long)missingStoreCount,
             (unsigned long)cacheStoreMismatchCount,
             (unsigned long)failedCount,
             springBoardOK ? "yes" : "no",
             previousSnapshot ? "yes" : "no",
             (unsigned long)comparisonUnchangedCount,
             (unsigned long)comparisonChangedCount,
             (unsigned long)comparisonMissingCount,
             (unsigned long)comparisonThemedToStockCount,
             (unsigned long)comparisonNewCount,
             currentThemedEvidenceComplete ? "complete" : "incomplete",
             snapshotWritten ? "written" : "not-written");
    return CNDRemixCoordinatorResult(ok,
        comparisonCompleted
            ? (comparisonStable
                ? @"audit-reinstall-unchanged"
                : @"audit-reinstall-difference-detected")
            : (snapshotWritten ? @"audit-baseline-captured"
                               : @"audit-partial"), message, @{
            @"records": records,
            @"themedStoreCount": @(themedStoreCount),
            @"aliasedThemedStoreCount": @(aliasedThemedStoreCount),
            @"nonThemedStoreCount": @(nonThemedStoreCount),
            @"missingStoreCount": @(missingStoreCount),
            @"cacheStoreMismatchCount": @(cacheStoreMismatchCount),
            @"failedCount": @(failedCount),
            @"batchSessionStart": batchStart ?: @{},
            @"batchSessionFinish": batchFinish ?: @{},
            @"springBoardConsumers": springBoard ?: @{},
            @"reinstallBaselinePresent": @(previousSnapshot != nil),
            @"reinstallBaselineCapturedAt":
                previousSnapshot[@"capturedAt"] ?: NSNull.null,
            @"reinstallBaselineInstallation":
                previousSnapshot[@"installation"] ?: @{},
            @"currentInstallation": currentInstallation,
            @"reinstallComparisons": comparisons,
            @"reinstallUnchangedCount": @(comparisonUnchangedCount),
            @"reinstallChangedCount": @(comparisonChangedCount),
            @"reinstallMissingCount": @(comparisonMissingCount),
            @"reinstallThemedToStockCount":
                @(comparisonThemedToStockCount),
            @"reinstallNewCount": @(comparisonNewCount),
            @"currentThemedEvidenceComplete":
                @(currentThemedEvidenceComplete),
            @"comparisonStable": @(comparisonStable),
            @"snapshotAdvanceEligible": @(snapshotAdvanceEligible),
            @"localSnapshotWriteAttempted": @(snapshotWriteAttempted),
            @"localSnapshotWritten": @(snapshotWritten),
            @"localSnapshotPath":
                CNDRemixAppliedAuditSnapshotURL().path ?: @"",
            @"mutationsIssued": @NO,
        });
}

+ (BOOL)hasRecoveryData
{
    if ([CNDIconThemeTransaction journaledTransactions].count > 0 ||
        CNDIconServicesInterceptProofIsActive()) return YES;
    for (NSDictionary *journal in CNDRemixIconServicesJournals()) {
        if (CNDRemixJournalRepresentsDirtyPersistentData(journal)) return YES;
    }
    return NO;
}

+ (NSDictionary<NSString *, id> *)applyIsolatedAirDropTest
{
    NSTimeInterval startedAt = NSProcessInfo.processInfo.systemUptime;
    NSDictionary<NSString *, NSData *> *themeLookup =
        CNDRemixNormalizedThemeLookup(settings_sbl_selected_theme_data());
    NSData *source = themeLookup[
        CNDRemixAirDropPseudoBundleIdentifier.lowercaseString];
    if (source.length == 0) {
        return CNDRemixResultByAddingElapsedTime(
            CNDRemixCoordinatorResult(NO, @"airdrop-test-asset-missing",
                @"The selected theme does not contain IconBundles/com.apple.Sharing.AirDrop.png; the isolated test made no target changes.", @{
                    @"operationMode": @"isolated-airdrop-apply",
                    @"targetBundleIdentifier":
                        CNDRemixAirDropPseudoBundleIdentifier,
                    @"themeAssetPresent": @NO,
                    @"ordinaryApplicationTargets": @0,
                    @"springBoardPresentationSkipped": @YES,
                }), startedAt, @"AirDrop Test Apply");
    }

    NSSet<NSString *> *target = [NSSet setWithObject:
        CNDRemixAirDropPseudoBundleIdentifier];
    NSDictionary *existingJournal = CNDRemixReadIconServicesJournal(
        CNDRemixAirDropPseudoBundleIdentifier);
    BOOL preflightRestorePerformed = existingJournal.count > 0;
    NSDictionary<NSString *, id> *preflightRestore = @{
        @"ok": @YES,
        @"stage": @"not-required",
        @"message": @"No existing AirDrop recovery journal required a targeted restore.",
        @"persistentDataClean": @YES,
        @"presentationRemoteCallUsed": @NO,
    };
    uint32_t previousSettleUS = r_settle_us(0);
    NSDictionary<NSString *, id> *raw = nil;
    @try {
        if (preflightRestorePerformed) {
            preflightRestore = CNDRemixRestoreIconServicesJournals(
                target, NO, nil, nil);
            BOOL clean = [preflightRestore[@"ok"] boolValue] &&
                [preflightRestore[@"persistentDataClean"] boolValue];
            log_user("[SBR_AIRDROP_TEST] preflight-restore ok=%d "
                     "prior-state=%s persistent-clean=%d "
                     "presentation-remote=%d\n",
                     [preflightRestore[@"ok"] boolValue],
                     [existingJournal[@"state"] UTF8String] ?: "unknown",
                     [preflightRestore[@"persistentDataClean"] boolValue],
                     [preflightRestore[@"presentationRemoteCallUsed"]
                        boolValue]);
            if (!clean) {
                return CNDRemixResultByAddingElapsedTime(
                    CNDRemixCoordinatorResult(NO,
                        @"airdrop-test-preflight-restore",
                        @"The existing AirDrop recovery journal could not be restored to verified stock. The isolated test stopped before publishing new records; use its Restore action and inspect the saved log.", @{
                            @"operationMode": @"isolated-airdrop-apply",
                            @"targetBundleIdentifier":
                                CNDRemixAirDropPseudoBundleIdentifier,
                            @"preflightRestorePerformed": @YES,
                            @"preflightRestore": preflightRestore ?: @{},
                            @"ordinaryApplicationTargets": @0,
                            @"springBoardPresentationSkipped": @YES,
                        }), startedAt, @"AirDrop Test Apply");
            }
        }
        raw = CNDRemixApplyIconServicesTheme(
            target, NO, YES, nil, nil);
    } @finally {
        r_settle_us(previousSettleUS);
    }
    NSMutableDictionary<NSString *, id> *result =
        [raw mutableCopy] ?: [NSMutableDictionary dictionary];
    NSArray<NSString *> *active = [result[@"activeBundleIdentifiers"]
        isKindOfClass:NSArray.class] ? result[@"activeBundleIdentifiers"] : @[];
    BOOL exactTarget = active.count == 1 &&
        [active.firstObject isEqualToString:
            CNDRemixAirDropPseudoBundleIdentifier];
    BOOL exactRecords = [result[@"airDropVerifiedVariants"]
            unsignedIntegerValue] == 2 &&
        [result[@"airDropResolvedSourceVariants"]
            unsignedIntegerValue] == 2 &&
        [result[@"airDropVerifiedSourceVariants"]
            unsignedIntegerValue] == 2;
    NSDictionary *sharingUI = [result[@"airDropPresentation"]
        isKindOfClass:NSDictionary.class] ? result[@"airDropPresentation"] : @{};
    BOOL sharingUIVerified = exactTarget &&
        [result[@"airDropPresentationOK"] boolValue];
    BOOL sharingUIRemoteCallUsed = [sharingUI[@"remoteCallUsed"] boolValue];
    BOOL springBoardSkipped =
        [result[@"springBoardPresentationSkipped"] boolValue] &&
        ![result[@"oneShotPresentation"][@"remoteCallUsed"] boolValue];
    BOOL ok = [result[@"ok"] boolValue] && exactTarget && exactRecords &&
        sharingUIVerified && springBoardSkipped;
    result[@"ok"] = @(ok);
    result[@"stage"] = ok ? @"airdrop-test-themed"
                            : @"airdrop-test-apply-incomplete";
    result[@"message"] = ok
        ? @"The isolated AirDrop test verified both themed records and their source associations, then refreshed only SharingUIService. Open a Share sheet now, run the isolated audit, and use the separate Restore action when finished."
        : (result[@"message"] ?:
            @"The isolated AirDrop apply did not verify every bounded requirement; inspect the SBR_AIRDROP_TEST and SBR_SHARE lines before retrying or restoring.");
    result[@"operationMode"] = @"isolated-airdrop-apply";
    result[@"targetBundleIdentifier"] =
        CNDRemixAirDropPseudoBundleIdentifier;
    result[@"themeAssetPresent"] = @YES;
    result[@"preflightRestorePerformed"] = @(preflightRestorePerformed);
    result[@"preflightRestore"] = preflightRestore ?: @{};
    result[@"expectedDescriptorCount"] = @2;
    result[@"exactTargetSetVerified"] = @(exactTarget);
    result[@"exactDescriptorSetVerified"] = @(exactRecords);
    result[@"sharingUIRefreshVerified"] = @(sharingUIVerified);
    result[@"sharingUIRemoteCallUsed"] = @(sharingUIRemoteCallUsed);
    result[@"sharingUIRefreshStage"] = sharingUI[@"stage"] ?: @"missing";
    result[@"ordinaryApplicationTargets"] = @0;
    result[@"manualVisibleCheckRequired"] = @YES;
    log_user("[SBR_AIRDROP_TEST] apply ok=%d exact-target=%d "
             "records=%lu/2 source=%lu/2 sharing-ui-ready=%d "
             "sharing-ui-remote=%d sharing-ui-stage=%s "
             "springboard-skipped=%d ordinary-targets=0\n",
             ok, exactTarget,
             (unsigned long)[result[@"airDropVerifiedVariants"]
                unsignedIntegerValue],
             (unsigned long)[result[@"airDropVerifiedSourceVariants"]
                unsignedIntegerValue],
             sharingUIVerified, sharingUIRemoteCallUsed,
             [sharingUI[@"stage"] UTF8String] ?: "missing",
             springBoardSkipped);
    return CNDRemixResultByAddingElapsedTime(
        result, startedAt, @"AirDrop Test Apply");
}

+ (NSDictionary<NSString *, id> *)auditIsolatedAirDropTest
{
    NSTimeInterval startedAt = NSProcessInfo.processInfo.systemUptime;
    NSDictionary *journal = CNDRemixReadIconServicesJournal(
        CNDRemixAirDropPseudoBundleIdentifier);
    NSArray<CNDIconServicesDescriptorSpec *> *specifications =
        CNDRemixDescriptorSpecificationsForBundleIdentifier(
            CNDRemixAirDropPseudoBundleIdentifier);
    NSArray<NSDictionary *> *variants = CNDRemixJournalVariants(journal);
    if (![journal[@"state"] isEqualToString:@"active"] ||
        specifications.count != 2 || variants.count != 2) {
        return CNDRemixResultByAddingElapsedTime(
            CNDRemixCoordinatorResult(NO, @"airdrop-test-not-active",
                @"The isolated AirDrop test does not have one active two-record journal to audit. Run its Apply action first.", @{
                    @"operationMode": @"isolated-airdrop-audit",
                    @"targetBundleIdentifier":
                        CNDRemixAirDropPseudoBundleIdentifier,
                    @"journalState": journal[@"state"] ?: @"missing",
                    @"journalVariantCount": @(variants.count),
                    @"mutationsIssued": @NO,
                }), startedAt, @"AirDrop Test Audit");
    }

    NSMutableDictionary<NSString *, NSDictionary *> *variantByIdentity =
        [NSMutableDictionary dictionaryWithCapacity:variants.count];
    for (NSDictionary *variant in variants) {
        NSString *identity = [variant[@"descriptorIdentity"]
            isKindOfClass:NSString.class]
            ? variant[@"descriptorIdentity"] : nil;
        if (identity.length > 0 && !variantByIdentity[identity]) {
            variantByIdentity[identity] = variant;
        }
    }
    NSMutableArray<NSDictionary *> *targets = [NSMutableArray arrayWithCapacity:2];
    for (CNDIconServicesDescriptorSpec *specification in specifications) {
        NSDictionary *variant = variantByIdentity[
            specification.canonicalIdentity];
        NSDictionary *savedSpecification = [variant[@"descriptorSpecification"]
            isKindOfClass:NSDictionary.class]
            ? variant[@"descriptorSpecification"] : nil;
        if (!variant || ![savedSpecification isEqualToDictionary:
                specification.dictionaryRepresentation]) {
            return CNDRemixResultByAddingElapsedTime(
                CNDRemixCoordinatorResult(NO,
                    @"airdrop-test-descriptor-profile",
                    @"The AirDrop recovery journal does not contain exactly the two measured Share-sheet descriptors; no audit session was opened.", @{
                        @"operationMode": @"isolated-airdrop-audit",
                        @"targetBundleIdentifier":
                            CNDRemixAirDropPseudoBundleIdentifier,
                        @"mutationsIssued": @NO,
                    }), startedAt, @"AirDrop Test Audit");
        }
        [targets addObject:@{
            @"bundleIdentifier": CNDRemixAirDropPseudoBundleIdentifier,
            @"surface": specification.pointWidth == 64
                ? @"airdrop-activity-strip" : @"airdrop-apps-list",
            @"descriptorIdentity": specification.canonicalIdentity,
            @"descriptorSpecification":
                specification.dictionaryRepresentation,
            @"expectedThemedSHA256":
                variant[@"structuredImageSHA256"] ?: @"",
            @"expectedStockSHA256":
                variant[@"publication"][@"stockResponse"][@"dataSHA256"]
                    ?: @"",
        }];
    }

    NSDictionary *batchStart = CNDIconServicesPublisherBeginBatch(
        CNDRemixIconServicesWakeIdentifier);
    if (![batchStart[@"ok"] boolValue]) {
        return CNDRemixResultByAddingElapsedTime(
            CNDRemixCoordinatorResult(NO, @"airdrop-test-audit-session",
                batchStart[@"message"] ?:
                    @"The isolated AirDrop audit session could not start.", @{
                    @"operationMode": @"isolated-airdrop-audit",
                    @"batchSessionStart": batchStart ?: @{},
                    @"mutationsIssued": @NO,
                }), startedAt, @"AirDrop Test Audit");
    }

    NSMutableArray<NSDictionary *> *records =
        [NSMutableArray arrayWithCapacity:targets.count];
    NSUInteger verifiedCount = 0;
    NSDictionary *batchFinish = nil;
    @try {
        for (NSDictionary *target in targets) {
            if (!CNDIconServicesPublisherBatchIsHealthy()) break;
            NSDictionary *audit =
                CNDIconServicesPublisherAuditVariantInBatch(
                    CNDRemixAirDropPseudoBundleIdentifier,
                    target[@"descriptorSpecification"]);
            NSString *cacheState = CNDRemixAuditHashClassification(
                CNDRemixAppliedAuditText(audit, @"cacheDataSHA256"),
                target[@"expectedThemedSHA256"],
                target[@"expectedStockSHA256"]);
            NSString *storeState = CNDRemixAuditHashClassification(
                CNDRemixAppliedAuditText(audit, @"storeDataSHA256"),
                target[@"expectedThemedSHA256"],
                target[@"expectedStockSHA256"]);
            NSMutableDictionary *record = [target mutableCopy];
            record[@"audit"] = audit ?: @{};
            record[@"cacheState"] = cacheState;
            record[@"storeState"] = storeState;
            BOOL verified =
                CNDRemixAppliedAuditRecordProvesThemedPersistence(record);
            record[@"verified"] = @(verified);
            if (verified) verifiedCount++;
            [records addObject:record];
            log_user("[SBR_AIRDROP_TEST] audit surface=%s ok=%d "
                     "store=%s source-count=%llu source-match=%d stage=%s\n",
                     [target[@"surface"] UTF8String] ?: "?", verified,
                     storeState.UTF8String ?: "?",
                     (unsigned long long)[audit[@"sourceRegistryEntryCount"]
                        unsignedLongLongValue],
                     [audit[@"sourceIdentityMatchesCurrentRecord"] boolValue],
                     [CNDRemixAppliedAuditText(audit, @"stage") UTF8String]
                        ?: "?");
        }
    } @finally {
        batchFinish = CNDIconServicesPublisherFinishBatch();
    }
    BOOL ok = verifiedCount == 2 && records.count == 2 &&
        [batchFinish[@"ok"] boolValue];
    log_user("[SBR_AIRDROP_TEST] audit-complete ok=%d verified=%lu/2 "
             "session-closed=%d mutations=0\n", ok,
             (unsigned long)verifiedCount,
             [batchFinish[@"ok"] boolValue]);
    return CNDRemixResultByAddingElapsedTime(
        CNDRemixCoordinatorResult(ok,
            ok ? @"airdrop-test-audit-verified"
               : @"airdrop-test-audit-incomplete",
            ok
                ? @"Both isolated AirDrop records retain their themed bytes, exact indexed units, validation tokens, and current native source association. Confirm the visible tile manually before Restore."
                : @"The isolated AirDrop persistent audit did not verify both records. Inspect the per-surface SBR_AIRDROP_TEST lines and restore before another Apply if recovery is pending.", @{
                @"operationMode": @"isolated-airdrop-audit",
                @"targetBundleIdentifier":
                    CNDRemixAirDropPseudoBundleIdentifier,
                @"expectedDescriptorCount": @2,
                @"verifiedDescriptorCount": @(verifiedCount),
                @"records": records,
                @"batchSessionStart": batchStart ?: @{},
                @"batchSessionFinish": batchFinish ?: @{},
                @"ordinaryApplicationTargets": @0,
                @"springBoardPresentationSkipped": @YES,
                @"sharingUIRefreshAttempted": @NO,
                @"manualVisibleCheckRequired": @YES,
                @"mutationsIssued": @NO,
            }), startedAt, @"AirDrop Test Audit");
}

+ (NSDictionary<NSString *, id> *)restoreIsolatedAirDropTest
{
    NSTimeInterval startedAt = NSProcessInfo.processInfo.systemUptime;
    uint32_t previousSettleUS = r_settle_us(0);
    NSDictionary<NSString *, id> *raw = nil;
    @try {
        raw = CNDRemixRestoreIconServicesJournals(
            [NSSet setWithObject:CNDRemixAirDropPseudoBundleIdentifier],
            YES, nil, nil);
    } @finally {
        r_settle_us(previousSettleUS);
    }
    NSMutableDictionary<NSString *, id> *result =
        [raw mutableCopy] ?: [NSMutableDictionary dictionary];
    BOOL springBoardSkipped =
        [result[@"springBoardPresentationSkipped"] boolValue] &&
        ![result[@"restorePresentation"][@"remoteCallUsed"] boolValue];
    BOOL sharingUIVerified =
        [result[@"airDropPresentation"][@"ok"] boolValue];
    BOOL persistentClean = result[@"persistentDataClean"]
        ? [result[@"persistentDataClean"] boolValue]
        : [result[@"ok"] boolValue];
    BOOL ok = [result[@"ok"] boolValue] && persistentClean &&
        springBoardSkipped && sharingUIVerified;
    result[@"ok"] = @(ok);
    result[@"stage"] = ok ? @"airdrop-test-restored"
                            : @"airdrop-test-restore-incomplete";
    result[@"message"] = ok
        ? @"The isolated AirDrop records verified stock and only SharingUIService was refreshed. A fresh Share sheet should now show the stock AirDrop tile."
        : (result[@"message"] ?:
            @"The isolated AirDrop restore did not verify persistent stock plus Share-sheet refresh; inspect the saved operation log before retrying.");
    result[@"operationMode"] = @"isolated-airdrop-restore";
    result[@"targetBundleIdentifier"] =
        CNDRemixAirDropPseudoBundleIdentifier;
    result[@"ordinaryApplicationTargets"] = @0;
    result[@"sharingUIRefreshVerified"] = @(sharingUIVerified);
    log_user("[SBR_AIRDROP_TEST] restore ok=%d persistent-clean=%d "
             "sharing-ui=%d springboard-skipped=%d ordinary-targets=0\n",
             ok, persistentClean, sharingUIVerified, springBoardSkipped);
    return CNDRemixResultByAddingElapsedTime(
        result, startedAt, @"AirDrop Test Restore");
}

+ (NSDictionary<NSString *, id> *)scanInstalledApplications
{
    NSDictionary<NSString *, NSData *> *theme =
        CNDRemixNormalizedThemeLookup(settings_sbl_selected_theme_data());
    NSDictionary *start = CNDIconServicesPublisherBeginBatch(
        CNDRemixIconServicesWakeIdentifier);
    if (![start[@"ok"] boolValue]) {
        return CNDRemixCoordinatorResult(NO, @"iconservices-session",
            start[@"message"] ?: @"The IconServices catalog session could not start.",
            @{ @"batchSessionStart": start ?: @{} });
    }
    NSDictionary *catalog = nil;
    NSDictionary *finish = nil;
    @try {
        catalog = CNDIconServicesPublisherCopyInstalledBundleIdentifiersInBatch();
    } @finally {
        finish = CNDIconServicesPublisherFinishBatch();
    }
    NSArray<NSString *> *identifiers = [catalog[@"bundleIdentifiers"]
        isKindOfClass:NSArray.class] ? catalog[@"bundleIdentifiers"] : @[];
    NSUInteger matched = 0;
    for (NSString *bundleIdentifier in identifiers) {
        if (theme[bundleIdentifier.lowercaseString]) matched++;
    }
    BOOL ok = [catalog[@"ok"] boolValue] && [finish[@"ok"] boolValue];
    return CNDRemixCoordinatorResult(ok,
        ok ? @"cataloged" : @"application-catalog",
        ok
            ? @"The pinned iconservicesagent cataloged installed applications and closed cleanly."
            : catalog[@"message"] ?: finish[@"message"] ?:
                @"IconServices application cataloging failed.", @{
            @"totalApplicationsDiscovered": @(identifiers.count),
            @"themeEntriesLoaded": @(theme.count),
            @"matchedApplications": @(matched),
            @"noThemeIcon": @(identifiers.count - matched),
            @"catalog": catalog ?: @{},
            @"batchSessionStart": start ?: @{},
            @"batchSessionFinish": finish ?: @{},
        });
}

+ (NSDictionary<NSString *, id> *)applySelectedThemeWithProgress:
    (CNDSnowBoardRemixProgress)progress
    cancellation:(CNDSnowBoardRemixCancellation)cancellation
{
    NSTimeInterval startedAt = NSProcessInfo.processInfo.systemUptime;
    uint32_t previousSettleUS = r_settle_us(0);
    NSDictionary<NSString *, id> *result = nil;
    @try {
        result = CNDRemixApplyIconServicesTheme(
            nil, YES, NO, progress, cancellation);
    } @finally {
        r_settle_us(previousSettleUS);
    }
    result = result ?: CNDRemixCoordinatorResult(
        NO, @"iconservices", @"The IconServices batch ended without a result.", nil);
    return CNDRemixResultByAddingElapsedTime(result, startedAt, @"Apply");
}

+ (NSDictionary<NSString *, id> *)repairInstalledApplicationUpdatesWithProgress:
    (CNDSnowBoardRemixProgress)progress
    cancellation:(CNDSnowBoardRemixCancellation)cancellation
{
    NSTimeInterval startedAt = NSProcessInfo.processInfo.systemUptime;
    uint32_t previousSettleUS = r_settle_us(0);
    NSDictionary<NSString *, id> *result = nil;
    @try {
        /* The normal durable publisher is already update-selective: an exact
         * source/profile/install-fingerprint match exits as already-active;
         * a changed install is rebased to its current stock records before
         * publication; and a matching app without a journal is newly
         * published. Keep one implementation for both Apply and repair. */
        result = CNDRemixApplyIconServicesTheme(
            nil, YES, NO, progress, cancellation);
    } @finally {
        r_settle_us(previousSettleUS);
    }
    result = result ?: CNDRemixCoordinatorResult(
        NO, @"update-repair", @"Update Repair ended without a result.", nil);
    NSMutableDictionary<NSString *, id> *repair = [result mutableCopy];
    repair[@"operationMode"] = @"update-repair";
    if ([repair[@"ok"] boolValue]) {
        NSUInteger published = [repair[@"applied"] unsignedIntegerValue];
        NSUInteger updated =
            [repair[@"updatedApplicationRebases"] unsignedIntegerValue];
        NSUInteger newlyEligible = published >= updated
            ? published - updated : 0;
        NSUInteger unchanged =
            [repair[@"alreadyActive"] unsignedIntegerValue];
        repair[@"stage"] = @"update-repair-complete";
        repair[@"message"] = [NSString stringWithFormat:
            @"Update Repair completed: %lu new or missing app%@ and %lu updated app%@ were republished; %lu current app%@ were left untouched.%@",
            (unsigned long)newlyEligible,
            newlyEligible == 1 ? @"" : @"s",
            (unsigned long)updated,
            updated == 1 ? @"" : @"s",
            (unsigned long)unchanged,
            unchanged == 1 ? @"" : @"s",
            CNDRemixEnableSpringBoardCacheInvalidation
                ? @""
                : @" SpringBoard cache invalidation was intentionally skipped."];
    }
    return CNDRemixResultByAddingElapsedTime(
        repair, startedAt, @"Update Repair");
}

+ (NSDictionary<NSString *, id> *)applySelectedThemeForBundleIdentifiers:
    (NSArray<NSString *> *)bundleIdentifiers
    progress:(CNDSnowBoardRemixProgress)progress
    cancellation:(CNDSnowBoardRemixCancellation)cancellation
{
    if (progress) progress(@"cataloging", 0, 0, nil);
    NSArray<CNDDockApplication *> *applications =
        [CNDDockAppCatalog applicationsForBundleIdentifiers:bundleIdentifiers];
    [CNDDockAppCatalog recordSnowBoardBundleIdentifiers:
        [applications valueForKey:@"bundleIdentifier"]];
    NSDictionary<NSString *, NSData *> *theme = settings_sbl_selected_theme_data();
    if (theme.count == 0) return CNDRemixCoordinatorResult(NO, @"theme",
        @"Select or import a SnowBoard Remix theme first.", @{
            @"totalApplicationsDiscovered": @(applications.count),
            @"themeEntriesLoaded": @0,
        });

    NSMutableArray<CNDDockApplication *> *matched = [NSMutableArray array];
    for (CNDDockApplication *application in applications) {
        if (CNDRemixThemeIconData(theme, application.bundleIdentifier)) {
            [matched addObject:application];
        }
    }
    NSUInteger matchedApplicationCount = matched.count;
    if (progress) progress(@"matching", matchedApplicationCount,
                           matchedApplicationCount, nil);
    NSMutableArray<NSDictionary *> *unthemedApplications = [NSMutableArray array];
    BOOL debugApplicationLimit = [NSUserDefaults.standardUserDefaults
        boolForKey:kSettingsSnowBoardRemixDebugThreeAppLimit];
    if (debugApplicationLimit) {
        NSArray<NSString *> *debugSelection =
            CNDRemixDebugSelectionFromBundleIdentifiers(
                [matched valueForKey:@"bundleIdentifier"]);
        NSSet<NSString *> *selectedFoldedIdentifiers = [NSSet setWithArray:
            [debugSelection valueForKey:@"lowercaseString"]];
        NSMutableDictionary<NSString *, CNDDockApplication *>
            *applicationByFoldedIdentifier = [NSMutableDictionary dictionary];
        for (CNDDockApplication *application in matched) {
            NSString *foldedIdentifier =
                application.bundleIdentifier.lowercaseString;
            if (foldedIdentifier.length > 0 &&
                !applicationByFoldedIdentifier[foldedIdentifier]) {
                applicationByFoldedIdentifier[foldedIdentifier] = application;
            }
            if ([selectedFoldedIdentifiers containsObject:foldedIdentifier]) {
                continue;
            }
            [unthemedApplications addObject:@{
                @"bundleIdentifier": application.bundleIdentifier,
                @"displayName": application.displayName ?: application.bundleIdentifier,
                @"reason": @"test-limit",
                @"message": @"Not attempted because the named four-app debug selection is enabled.",
            }];
        }
        NSMutableArray<CNDDockApplication *> *debugApplications =
            [NSMutableArray arrayWithCapacity:debugSelection.count];
        for (NSString *bundleIdentifier in debugSelection) {
            CNDDockApplication *application =
                applicationByFoldedIdentifier[bundleIdentifier.lowercaseString];
            if (application) [debugApplications addObject:application];
        }
        [matched setArray:debugApplications];
    }
    NSUInteger applied = 0, active = 0, pending = 0, failed = 0, skipped =
        unthemedApplications.count;
    NSUInteger processedWithoutQuantization = 0;
    NSUInteger processedWithQuantization = 0;
    BOOL cancelled = NO;
    BOOL sessionFailed = NO;
    NSMutableDictionary<NSString *, NSNumber *> *skipReasons =
        [NSMutableDictionary dictionary];
    if (unthemedApplications.count > 0) {
        skipReasons[@"test-limit"] = @(unthemedApplications.count);
    }
    NSMutableArray<NSDictionary *> *results = [NSMutableArray array];
    NSMutableSet<NSString *> *pendingBundleIdentifiers = [NSMutableSet set];
    NSMutableSet<NSString *> *loggedTransactionDiagnostics = [NSMutableSet set];
    // The retained installd session is thread-owned.  This coordinator is a
    // synchronous sequential loop, so keep one bounded session on the current
    // worker thread for the whole batch on both physical devices and the VM.
    BOOL batchSession = matched.count > 0;
    uint32_t previousSettleUS = batchSession ? r_settle_us(0) : 0;
    NSDictionary *batchSessionStart = batchSession
        ? CNDLaunchServicesBeginBatchInstalldSession(
            matched.firstObject.bundleIdentifier) : @{};
    if (batchSession && ![batchSessionStart[@"ok"] boolValue]) {
        r_settle_us(previousSettleUS);
        return CNDRemixCoordinatorResult(NO, @"batch-session",
            batchSessionStart[@"message"] ?: @"The bounded installd session could not start.",
            @{@"batchSessionStart": batchSessionStart ?: @{}});
    }
    for (NSUInteger index = 0; index < matched.count; index++) {
        CNDDockApplication *application = matched[index];
        if (cancellation && cancellation()) {
            skipped += matched.count - index;
            skipReasons[@"cancelled"] = @(matched.count - index);
            for (NSUInteger remainingIndex = index;
                 remainingIndex < matched.count; remainingIndex++) {
                CNDDockApplication *remainingApplication = matched[remainingIndex];
                [unthemedApplications addObject:@{
                    @"bundleIdentifier": remainingApplication.bundleIdentifier,
                    @"displayName": remainingApplication.displayName ?:
                        remainingApplication.bundleIdentifier,
                    @"reason": @"cancelled",
                    @"message": @"Not attempted because the batch was cancelled.",
                }];
            }
            cancelled = YES;
            break;
        }
        if (progress) progress(@"preflighting", index, matched.count,
                               application.bundleIdentifier);
        CNDIconThemeTransaction *transaction = [[CNDIconThemeTransaction alloc]
            initWithBundleIdentifier:application.bundleIdentifier];
        if ([NSFileManager.defaultManager fileExistsAtPath:transaction.journalURL.path]) {
            NSDictionary *status = [transaction
                statusWithInstalledApplications:applications];
            NSDictionary *existingJournal = [NSDictionary
                dictionaryWithContentsOfURL:transaction.journalURL];
            CNDRemixLogTransactionResult(application.bundleIdentifier,
                                         status ?: @{},
                                         existingJournal ?: @{},
                                         loggedTransactionDiagnostics);
            if ([status[@"ok"] boolValue] &&
                [status[@"stage"] isEqual:@"active"]) {
                active++;
            } else {
                skipped++;
                NSString *reason = status[@"stage"] ?: @"recovery-required";
                skipReasons[reason] = @([skipReasons[reason] unsignedIntegerValue] + 1);
                [unthemedApplications addObject:@{
                    @"bundleIdentifier": application.bundleIdentifier,
                    @"displayName": application.displayName ?: application.bundleIdentifier,
                    @"reason": reason,
                    @"message": status[@"message"] ?: @"Recovery is required before this app can be themed.",
                }];
            }
            [results addObject:@{@"bundleIdentifier": application.bundleIdentifier,
                                 @"status": status ?: @{}}];
            continue;
        }
        if (progress) progress(@"processing", index, matched.count,
                               application.bundleIdentifier);
        if (progress) progress(@"applying", index, matched.count,
                               application.bundleIdentifier);
        NSDictionary *result = [transaction applySourcePNGData:
            CNDRemixThemeIconData(theme, application.bundleIdentifier)];
        NSDictionary *transactionJournal = [NSDictionary
            dictionaryWithContentsOfURL:transaction.journalURL];
        CNDRemixLogTransactionResult(application.bundleIdentifier,
                                     result ?: @{},
                                     transactionJournal ?: @{},
                                     loggedTransactionDiagnostics);
        [results addObject:@{@"bundleIdentifier": application.bundleIdentifier,
            @"displayName": application.displayName ?: application.bundleIdentifier,
            @"result": result ?: @{}}];
        BOOL resultPending = batchSession &&
            ([result[@"batchSessionPending"] boolValue] ||
             [result[@"transactionState"] isEqual:@"pending"]);
        if ([result[@"ok"] boolValue]) {
            if (resultPending) {
                pending++;
                [pendingBundleIdentifiers addObject:application.bundleIdentifier];
            } else {
                applied++;
            }
            NSDictionary *journal = [NSDictionary dictionaryWithContentsOfURL:
                transaction.journalURL];
            NSString *mode = journal[@"fileMutation"][ @"processing"][ @"mode"];
            if ([mode isKindOfClass:NSString.class] &&
                [mode hasPrefix:@"indexed-"]) {
                processedWithQuantization++;
            } else {
                processedWithoutQuantization++;
            }
            if (progress) progress(@"registering", index + 1, matched.count,
                                   application.bundleIdentifier);
            if (progress) progress(@"verifying", index + 1, matched.count,
                                   application.bundleIdentifier);
        } else {
            failed++;
            NSString *reason = result[@"stage"] ?: @"unknown";
            [unthemedApplications addObject:@{
                @"bundleIdentifier": application.bundleIdentifier,
                @"displayName": application.displayName ?: application.bundleIdentifier,
                @"reason": reason,
                @"message": result[@"message"] ?: @"The application was not themed.",
            }];
            skipped++;
            skipReasons[reason] = @([skipReasons[reason] unsignedIntegerValue] + 1);
        }
        if (progress) progress(
            [result[@"ok"] boolValue] ? @"completed" : @"not-themed",
            index + 1, matched.count, application.bundleIdentifier);
        if (batchSession && !CNDLaunchServicesBatchInstalldSessionIsHealthy()) {
            NSUInteger remaining = matched.count - index - 1;
            skipped += remaining;
            if (remaining > 0) skipReasons[@"batch-transport"] = @(remaining);
            for (NSUInteger remainingIndex = index + 1;
                 remainingIndex < matched.count; remainingIndex++) {
                CNDDockApplication *remainingApplication = matched[remainingIndex];
                [unthemedApplications addObject:@{
                    @"bundleIdentifier": remainingApplication.bundleIdentifier,
                    @"displayName": remainingApplication.displayName ?:
                        remainingApplication.bundleIdentifier,
                    @"reason": @"batch-transport",
                    @"message": @"Not attempted after the bounded installd session became unhealthy.",
                }];
            }
            sessionFailed = YES;
            break;
        }
    }
    if (progress) progress(@"finalizing", matched.count, matched.count, nil);
    NSDictionary *batchSessionFinish = batchSession
        ? CNDLaunchServicesFinishBatchInstalldSession() : @{};
    NSDictionary *batchPromotion = @{};
    if (batchSession && [batchSessionFinish[@"ok"] boolValue]) {
        batchPromotion = [CNDIconThemeTransaction
            promotePendingBatchTransactions] ?: @{};
        if (![batchPromotion[@"ok"] boolValue]) sessionFailed = YES;
        NSMutableDictionary *promotionByBundle = [NSMutableDictionary dictionary];
        for (NSDictionary *promotionResult in batchPromotion[@"results"]) {
            NSString *bundleIdentifier = promotionResult[@"bundleIdentifier"];
            if (bundleIdentifier.length > 0) {
                promotionByBundle[bundleIdentifier] = promotionResult;
            }
        }
        for (NSUInteger resultIndex = 0; resultIndex < results.count; resultIndex++) {
            NSMutableDictionary *entry = [results[resultIndex] mutableCopy];
            NSString *bundleIdentifier = entry[@"bundleIdentifier"];
            if (![pendingBundleIdentifiers containsObject:bundleIdentifier]) continue;
            NSDictionary *originalResult = entry[@"result"];
            NSDictionary *promotion = promotionByBundle[bundleIdentifier];
            NSMutableDictionary *updatedResult = [originalResult mutableCopy] ?: [NSMutableDictionary dictionary];
            updatedResult[@"batchPromotion"] = promotion ?: @{};
            if ([promotion[@"ok"] boolValue]) {
                updatedResult[@"stage"] = @"active";
                updatedResult[@"transactionState"] = @"active";
                updatedResult[@"batchSessionPending"] = @NO;
                applied++;
                pending--;
            } else {
                failed++;
                updatedResult[@"ok"] = @NO;
                updatedResult[@"stage"] = @"batch-promotion";
                updatedResult[@"message"] = promotion[@"message"] ?:
                    @"The shared installd batch closed, but this transaction remains pending recovery.";
                skipReasons[@"batch-promotion"] =
                    @([skipReasons[@"batch-promotion"] unsignedIntegerValue] + 1);
                skipped++;
            }
            entry[@"result"] = updatedResult;
            results[resultIndex] = entry;
        }
    } else if (batchSession) {
        sessionFailed = YES;
        failed += pending > 0 ? pending : 1;
        for (NSUInteger resultIndex = 0; resultIndex < results.count; resultIndex++) {
            NSMutableDictionary *entry = [results[resultIndex] mutableCopy];
            NSString *bundleIdentifier = entry[@"bundleIdentifier"];
            if (![pendingBundleIdentifiers containsObject:bundleIdentifier]) continue;
            NSMutableDictionary *updatedResult =
                [entry[@"result"] mutableCopy] ?: [NSMutableDictionary dictionary];
            updatedResult[@"ok"] = @NO;
            updatedResult[@"stage"] = @"batch-session";
            updatedResult[@"message"] = batchSessionFinish[@"message"] ?:
                @"The shared installd batch did not close cleanly; this transaction remains pending recovery.";
            updatedResult[@"batchSessionPending"] = @YES;
            updatedResult[@"batchSessionFinish"] = batchSessionFinish ?: @{};
            entry[@"result"] = updatedResult;
            results[resultIndex] = entry;
        }
    }
    if (batchSession && ![batchSessionFinish[@"ok"] boolValue]) sessionFailed = YES;
    NSDictionary *summary = @{
        @"state": (cancelled || sessionFailed) ? @"partial" :
            (unthemedApplications.count > 0 ? @"complete-with-unthemed" : @"complete"),
        @"bundleIdentifiers": [matched valueForKey:@"bundleIdentifier"] ?: @[],
        @"totalApplicationsDiscovered": @(applications.count),
        @"themeEntriesLoaded": @(theme.count),
        @"matchedApplications": @(matchedApplicationCount),
        @"attemptedApplications": @(matched.count),
        @"testApplicationLimit": @(CNDRemixTestApplicationLimit),
        @"applied": @(applied), @"alreadyActive": @(active),
        @"pending": @(pending),
        @"processedWithoutQuantization": @(processedWithoutQuantization),
        @"processedWithQuantization": @(processedWithQuantization),
        @"noThemeIcon": @(applications.count - matchedApplicationCount),
        @"cancelled": @(cancelled),
        @"skipped": @(skipped), @"skippedByReason": skipReasons,
        @"failed": @(failed), @"results": results,
        @"unthemedApplications": unthemedApplications,
        @"sessionFailed": @(sessionFailed),
        @"batchSessionStart": batchSessionStart ?: @{},
        @"batchSessionFinish": batchSessionFinish ?: @{},
        @"batchPromotion": batchPromotion ?: @{},
    };
    NSError *indexError = nil;
    BOOL indexOK = CNDRemixWriteIndex(summary, &indexError);
    BOOL operationOK = !cancelled && !sessionFailed && indexOK;
    if (skipped > 0) {
        log_user("[SBR] not-themed=%lu reasons=%s\n",
                 (unsigned long)skipped,
                 skipReasons.description.UTF8String ?: "{}");
    }
    NSString *finishedMessage = unthemedApplications.count > 0
        ? [NSString stringWithFormat:
            @"SnowBoard Remix finished. %lu applications were not themed.",
            (unsigned long)unthemedApplications.count]
        : @"SnowBoard Remix finished applying the selected theme.";
    NSDictionary *coordinatorResult = CNDRemixCoordinatorResult(operationOK,
        cancelled || sessionFailed ? @"partial" :
            (indexOK ? (unthemedApplications.count > 0
                ? @"complete-with-unthemed" : @"complete") : @"batch-index"),
        cancelled ? @"SnowBoard Remix was cancelled; completed app transactions remain recoverable." :
        sessionFailed ? @"The bounded installd session failed; completed app transactions remain recoverable." :
            (indexOK ? finishedMessage :
             indexError.localizedDescription), summary);
    if (batchSession) r_settle_us(previousSettleUS);
    return coordinatorResult;
}

+ (NSDictionary<NSString *, id> *)restoreBundleIdentifier:(NSString *)bundleIdentifier
{
    NSTimeInterval startedAt = NSProcessInfo.processInfo.systemUptime;
    NSDictionary *result = nil;
    if (CNDRemixReadIconServicesJournal(bundleIdentifier)) {
        result = CNDRemixRestoreIconServicesJournals(
            [NSSet setWithObject:bundleIdentifier], YES, nil, nil);
    } else if ([bundleIdentifier isEqualToString:@"com.ebay.iphone"] &&
               CNDIconServicesInterceptProofIsActive()) {
        result = CNDIconServicesInterceptProofRestore();
    } else {
        CNDIconThemeTransaction *transaction = [[CNDIconThemeTransaction alloc]
            initWithBundleIdentifier:bundleIdentifier];
        result = transaction ? [transaction restore] :
            CNDRemixCoordinatorResult(NO, @"bundle-identifier",
                @"The selected recovery record has an invalid bundle identifier.", nil);
    }
    return CNDRemixResultByAddingElapsedTime(
        result, startedAt, @"Restore One");
}

+ (NSDictionary<NSString *, id> *)restoreAllWithProgress:
    (CNDSnowBoardRemixProgress)progress
    cancellation:(CNDSnowBoardRemixCancellation)cancellation
{
    NSTimeInterval startedAt = NSProcessInfo.processInfo.systemUptime;
    BOOL hasIconServicesJournals =
        CNDRemixIconServicesJournals().count > 0;
    BOOL hasLiveDynamicPresentation =
        [CNDRemixLiveSpringBoardDynamicPresentationState()[@"installed"]
            boolValue];
    if (hasIconServicesJournals || hasLiveDynamicPresentation) {
        uint32_t previousSettleUS = r_settle_us(0);
        NSDictionary *result = nil;
        @try {
            result = CNDRemixRestoreIconServicesJournals(
                nil, YES, progress, cancellation);
        } @finally {
            r_settle_us(previousSettleUS);
        }
        return CNDRemixResultByAddingElapsedTime(
            result, startedAt, @"Restore");
    }
    if (CNDIconServicesInterceptProofIsActive()) {
        if (progress) progress(@"restoring", 0, 1, @"com.ebay.iphone");
        NSDictionary *result = CNDIconServicesInterceptProofRestore();
        if (progress) progress([result[@"ok"] boolValue]
            ? @"restored" : @"restore-failed", 1, 1,
            @"com.ebay.iphone");
        return CNDRemixResultByAddingElapsedTime(
            result, startedAt, @"Restore");
    }
    NSArray<CNDIconThemeTransaction *> *transactions =
        [CNDIconThemeTransaction journaledTransactions];
    NSUInteger restored = 0, pending = 0, failed = 0;
    NSMutableArray *results = [NSMutableArray array];
    NSMutableSet<NSString *> *pendingBundleIdentifiers = [NSMutableSet set];
    NSMutableSet<NSString *> *loggedAlphaSnapshots = [NSMutableSet set];
    for (CNDIconThemeTransaction *transaction in transactions) {
        NSDictionary *journal = [NSDictionary dictionaryWithContentsOfURL:
            transaction.journalURL] ?: @{};
        CNDRemixLogAlphaSnapshot(transaction.bundleIdentifier, @{}, journal,
                                 loggedAlphaSnapshots);
    }
    if (progress) progress(@"preparing-restore", 0, transactions.count, nil);
    // Restore uses the same bounded, current-thread installd session as Apply.
    BOOL batchSession = transactions.count > 0;
    uint32_t previousSettleUS = batchSession ? r_settle_us(0) : 0;
    NSDictionary *batchSessionStart = batchSession
        ? CNDLaunchServicesBeginBatchInstalldSession(
            transactions.firstObject.bundleIdentifier) : @{};
    if (batchSession && ![batchSessionStart[@"ok"] boolValue]) {
        r_settle_us(previousSettleUS);
        NSDictionary *failure = CNDRemixCoordinatorResult(
            NO, @"restore-batch-session",
            batchSessionStart[@"message"] ?:
                @"The bounded restore session could not start.",
            @{@"batchSessionStart": batchSessionStart ?: @{}});
        return CNDRemixResultByAddingElapsedTime(
            failure, startedAt, @"Restore");
    }
    for (NSUInteger index = 0; index < transactions.count; index++) {
        CNDIconThemeTransaction *transaction = transactions[index];
        if (cancellation && cancellation()) break;
        if (progress) progress(@"restoring", index, transactions.count,
                               transaction.bundleIdentifier);
        NSDictionary *result = [transaction restore];
        [results addObject:@{@"bundleIdentifier": transaction.bundleIdentifier,
                             @"result": result ?: @{}}];
        BOOL resultPending = batchSession &&
            ([result[@"batchSessionPending"] boolValue] ||
             [result[@"transactionState"] isEqual:@"restore-pending"]);
        if ([result[@"ok"] boolValue]) {
            if (resultPending) {
                pending++;
                [pendingBundleIdentifiers addObject:transaction.bundleIdentifier];
            } else {
                restored++;
            }
        } else {
            failed++;
            NSString *stage = [result[@"stage"] isKindOfClass:NSString.class]
                ? result[@"stage"] : @"restore-failed";
            NSString *message = [result[@"message"] isKindOfClass:NSString.class]
                ? result[@"message"] : @"The application was not restored.";
            log_user("[SBR] restore-failure app=%s stage=%s reason=%s\n",
                     transaction.bundleIdentifier.UTF8String ?: "?",
                     stage.UTF8String ?: "restore-failed",
                     message.UTF8String ?: "unknown");
        }
        if (progress) progress(
            [result[@"ok"] boolValue] ? @"restored" : @"restore-failed",
            index + 1, transactions.count, transaction.bundleIdentifier);
        if (batchSession && !CNDLaunchServicesBatchInstalldSessionIsHealthy()) {
            failed += transactions.count - index - 1;
            break;
        }
    }
    if (progress) progress(@"finalizing", transactions.count, transactions.count, nil);
    NSDictionary *batchSessionFinish = batchSession
        ? CNDLaunchServicesFinishBatchInstalldSession() : @{};
    NSDictionary *restorePromotion = @{};
    if (batchSession && [batchSessionFinish[@"ok"] boolValue]) {
        restorePromotion = [CNDIconThemeTransaction
            finalizePendingRestoreTransactions] ?: @{};
        NSMutableDictionary *promotionByBundle = [NSMutableDictionary dictionary];
        for (NSDictionary *promotionResult in restorePromotion[@"results"]) {
            NSString *bundleIdentifier = promotionResult[@"bundleIdentifier"];
            if (bundleIdentifier.length > 0) {
                promotionByBundle[bundleIdentifier] = promotionResult;
            }
        }
        for (NSUInteger resultIndex = 0; resultIndex < results.count; resultIndex++) {
            NSMutableDictionary *entry = [results[resultIndex] mutableCopy];
            NSString *bundleIdentifier = entry[@"bundleIdentifier"];
            if (![pendingBundleIdentifiers containsObject:bundleIdentifier]) continue;
            NSDictionary *promotion = promotionByBundle[bundleIdentifier];
            NSMutableDictionary *updatedResult =
                [entry[@"result"] mutableCopy] ?: [NSMutableDictionary dictionary];
            updatedResult[@"batchPromotion"] = promotion ?: @{};
            if ([promotion[@"ok"] boolValue]) {
                updatedResult[@"stage"] = @"restored";
                updatedResult[@"transactionState"] = @"restored";
                updatedResult[@"batchSessionPending"] = @NO;
                restored++;
                pending--;
            } else {
                updatedResult[@"ok"] = @NO;
                updatedResult[@"stage"] = @"restore-promotion";
                updatedResult[@"message"] = promotion[@"message"] ?:
                    @"The shared installd batch closed, but this restoration remains pending recovery.";
                failed++;
            }
            entry[@"result"] = updatedResult;
            results[resultIndex] = entry;
        }
    } else if (batchSession) {
        failed += pending;
        for (NSUInteger resultIndex = 0; resultIndex < results.count; resultIndex++) {
            NSMutableDictionary *entry = [results[resultIndex] mutableCopy];
            NSString *bundleIdentifier = entry[@"bundleIdentifier"];
            if (![pendingBundleIdentifiers containsObject:bundleIdentifier]) continue;
            NSMutableDictionary *updatedResult =
                [entry[@"result"] mutableCopy] ?: [NSMutableDictionary dictionary];
            updatedResult[@"ok"] = @NO;
            updatedResult[@"stage"] = @"restore-batch-session";
            updatedResult[@"message"] = batchSessionFinish[@"message"] ?:
                @"The shared installd batch did not close cleanly; this restoration remains pending recovery.";
            updatedResult[@"batchSessionPending"] = @YES;
            updatedResult[@"batchSessionFinish"] = batchSessionFinish ?: @{};
            entry[@"result"] = updatedResult;
            results[resultIndex] = entry;
        }
    }
    if (batchSession && ![batchSessionFinish[@"ok"] boolValue] && pending == 0) {
        failed++;
    }
    NSDictionary *summary = @{@"journaled": @(transactions.count),
        @"restored": @(restored), @"pending": @(pending), @"failed": @(failed),
        @"results": results,
        @"batchSessionStart": batchSessionStart ?: @{},
        @"batchSessionFinish": batchSessionFinish ?: @{},
        @"restorePromotion": restorePromotion ?: @{}};
    NSError *indexError = nil;
    (void)CNDRemixWriteIndex(summary, &indexError);
    NSDictionary *coordinatorResult = CNDRemixCoordinatorResult(
        failed == 0, failed ? @"restore-partial" : @"restored",
        failed ? @"Some applications still require recovery." :
            @"Every journaled application was restored and verified.", summary);
    if (batchSession) r_settle_us(previousSettleUS);
    return CNDRemixResultByAddingElapsedTime(
        coordinatorResult, startedAt, @"Restore");
}

+ (NSArray<NSDictionary<NSString *, id> *> *)applicationStatuses
{
    // This is the exact, synchronous API used by recovery and diagnostics.
    // Callers that are servicing UI should use cachedApplicationStatuses and
    // refreshApplicationStatusesInBackgroundWithCompletion: instead.
    NSArray<CNDIconThemeTransaction *> *legacyTransactions =
        [CNDIconThemeTransaction journaledTransactions];
    // The IconServices journals already contain the authoritative bundle IDs.
    // Only old filesystem journals need the expensive legacy application
    // catalog for path/version drift classification.
    NSArray<CNDDockApplication *> *applications = legacyTransactions.count > 0
        ? [CNDDockAppCatalog installedApplications] : @[];
    NSMutableDictionary<NSString *, NSString *> *displayNames =
        [NSMutableDictionary dictionaryWithCapacity:applications.count];
    for (CNDDockApplication *application in applications) {
        if (application.bundleIdentifier.length > 0 &&
            application.displayName.length > 0) {
            displayNames[application.bundleIdentifier] = application.displayName;
        }
    }
    NSMutableArray *statuses = [NSMutableArray array];
    for (NSDictionary *journal in CNDRemixIconServicesJournals()) {
        NSString *bundleIdentifier = journal[@"bundleIdentifier"];
        NSString *state = [journal[@"state"] isKindOfClass:NSString.class]
            ? journal[@"state"] : @"unknown";
        BOOL persistentDataClean =
            !CNDRemixJournalRepresentsDirtyPersistentData(journal);
        NSMutableDictionary *status = [@{
            @"ok": @YES,
            @"engine": @"iconservices-publisher",
            @"bundleIdentifier": bundleIdentifier ?: @"",
            @"stage": state,
            @"active": @([state isEqualToString:@"active"]),
            @"persistentDataClean": @(persistentDataClean),
            @"recoveryRequired": @(!persistentDataClean),
            @"message": [state isEqualToString:@"active"]
                ? @"The marked IconServices response is active."
                : (persistentDataClean
                    ? @"Persistent data is clean; local journal metadata awaits cleanup."
                    : @"This IconServices response retains recovery state."),
        } mutableCopy];
        NSString *displayName = bundleIdentifier.length > 0
            ? displayNames[bundleIdentifier] : nil;
        if (displayName.length > 0) status[@"displayName"] = displayName;
        [statuses addObject:status];
    }
    if (CNDIconServicesInterceptProofIsActive()) {
        [statuses addObject:@{
            @"ok": @YES,
            @"engine": @"iconservices-single-proof",
            @"bundleIdentifier": @"com.ebay.iphone",
            @"stage": @"phase2-recovery-pending",
            @"active": @YES,
            @"message": @"The retained single-app IconServices proof must be restored before multi-app apply.",
        }];
    }
    for (CNDIconThemeTransaction *transaction in legacyTransactions) {
        NSDictionary *status = [transaction
            statusWithInstalledApplications:applications];
        if (![status isKindOfClass:NSDictionary.class]) continue;
        NSMutableDictionary *enriched = [status mutableCopy];
        NSString *displayName = displayNames[transaction.bundleIdentifier];
        if (displayName.length > 0) enriched[@"displayName"] = displayName;
        [statuses addObject:enriched];
    }
    NSArray *snapshot = [statuses copy];
    @synchronized (CNDRemixStatusCacheLock()) {
        g_remixStatusCache = snapshot;
    }
    return snapshot;
}

+ (NSArray<NSDictionary<NSString *, id> *> *)cachedApplicationStatuses
{
    @synchronized (CNDRemixStatusCacheLock()) {
        return g_remixStatusCache ?: @[];
    }
}

+ (void)invalidateCachedApplicationStatuses
{
    @synchronized (CNDRemixStatusCacheLock()) {
        g_remixStatusCache = nil;
    }
}

+ (void)refreshApplicationStatusesInBackgroundWithCompletion:
    (CNDSnowBoardRemixStatusesCompletion)completion
{
    NSObject *lock = CNDRemixStatusCacheLock();
    BOOL shouldStart = NO;
    NSArray<NSDictionary<NSString *, id> *> *cached = nil;
    @synchronized (lock) {
        if (g_remixStatusCache != nil && !g_remixStatusRefreshInFlight) {
            cached = g_remixStatusCache;
        } else if (completion) {
            if (!g_remixStatusCompletions) {
                g_remixStatusCompletions = [NSMutableArray array];
            }
            [g_remixStatusCompletions addObject:[completion copy]];
        }
        if (!g_remixStatusRefreshInFlight && g_remixStatusCache == nil) {
            g_remixStatusRefreshInFlight = YES;
            shouldStart = YES;
        }
    }
    if (cached) {
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(cached);
            });
        }
        return;
    }
    if (!shouldStart) return;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSArray<NSDictionary<NSString *, id> *> *snapshot =
            [self applicationStatuses];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSArray<CNDSnowBoardRemixStatusesCompletion> *completions = nil;
            @synchronized (lock) {
                completions = [g_remixStatusCompletions copy] ?: @[];
                [g_remixStatusCompletions removeAllObjects];
                g_remixStatusRefreshInFlight = NO;
            }
            [[NSNotificationCenter defaultCenter]
                postNotificationName:CNDSnowBoardRemixStatusesDidRefreshNotification
                              object:snapshot ?: @[]];
            for (CNDSnowBoardRemixStatusesCompletion callback in completions) {
                callback(snapshot ?: @[]);
            }
        });
    });
}

@end
