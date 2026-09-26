//
//  CNDDockAppCatalog.m
//  Cyanide
//

#import "CNDDockAppCatalog.h"

#import <dlfcn.h>
#import <objc/message.h>

static NSString * const kCNDSnowBoardBundleIdentifiersDefaultsKey =
    @"CNDDockAppCatalog.snowBoardBundleIdentifiers.v1";

@interface CNDDockApplication ()

- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier
                              displayName:(NSString *)displayName
                                bundleURL:(nullable NSURL *)bundleURL
                               bundlePath:(nullable NSString *)bundlePath
                        systemApplication:(BOOL)systemApplication
                              placeholder:(BOOL)placeholder
                                   hidden:(BOOL)hidden
                                launchable:(BOOL)launchable
                          applicationType:(NSString *)applicationType
                                  version:(nullable NSString *)version
                           updateIdentity:(nullable NSString *)updateIdentity NS_DESIGNATED_INITIALIZER;

@end


@implementation CNDDockApplication

- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier
                              displayName:(NSString *)displayName
                                bundleURL:(NSURL *)bundleURL
                               bundlePath:(NSString *)bundlePath
                        systemApplication:(BOOL)systemApplication
                              placeholder:(BOOL)placeholder
                                   hidden:(BOOL)hidden
                                launchable:(BOOL)launchable
                          applicationType:(NSString *)applicationType
                                  version:(NSString *)version
                           updateIdentity:(NSString *)updateIdentity
{
    self = [super init];
    if (!self) return nil;

    _bundleIdentifier = [bundleIdentifier copy] ?: @"";
    NSString *copiedDisplayName = [displayName copy];
    _displayName = copiedDisplayName.length > 0 ? copiedDisplayName : _bundleIdentifier;
    _bundleURL = [bundleURL copy];
    NSString *copiedBundlePath = [bundlePath copy];
    _bundlePath = copiedBundlePath.length > 0 ? copiedBundlePath : bundleURL.path;
    _systemApplication = systemApplication;
    _placeholder = placeholder;
    _hidden = hidden;
    _launchable = launchable;
    NSString *copiedApplicationType = [applicationType copy];
    _applicationType = copiedApplicationType.length > 0 ? copiedApplicationType : @"Unknown";
    _version = [version copy];
    _updateIdentity = [updateIdentity copy];
    return self;
}

- (NSString *)path
{
    return self.bundlePath;
}

- (BOOL)isSystemOwned
{
    return self.systemApplication;
}

- (NSString *)updateIdentifier
{
    return self.updateIdentity;
}

@end

static NSComparisonResult CNDApplicationDeterministicCompare(
    CNDDockApplication *left, CNDDockApplication *right);


static id CNDObjectMessage0(id target, SEL selector)
{
    if (!target || !selector || ![target respondsToSelector:selector]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(target, selector);
}

static NSString *CNDStringProperty(id object, NSArray<NSString *> *selectorNames)
{
    for (NSString *selectorName in selectorNames) {
        id value = CNDObjectMessage0(object, NSSelectorFromString(selectorName));
        if ([value isKindOfClass:NSString.class] && [(NSString *)value length] > 0) {
            return value;
        }
    }
    return nil;
}

static NSURL *CNDURLProperty(id object, NSArray<NSString *> *selectorNames)
{
    for (NSString *selectorName in selectorNames) {
        id value = CNDObjectMessage0(object, NSSelectorFromString(selectorName));
        if ([value isKindOfClass:NSURL.class]) return value;
        if ([value isKindOfClass:NSString.class] && [(NSString *)value length] > 0) {
            return [NSURL fileURLWithPath:value isDirectory:YES];
        }
    }
    return nil;
}

static BOOL CNDOptionalBoolProperty(id object,
                                    NSArray<NSString *> *selectorNames,
                                    BOOL fallback,
                                    BOOL *knownOut)
{
    if (knownOut) *knownOut = NO;
    for (NSString *selectorName in selectorNames) {
        SEL selector = NSSelectorFromString(selectorName);
        if (!object || ![object respondsToSelector:selector]) continue;
        if (knownOut) *knownOut = YES;
        return ((BOOL (*)(id, SEL))objc_msgSend)(object, selector);
    }
    return fallback;
}

static NSString *CNDDescriptionProperty(id object, NSArray<NSString *> *selectorNames)
{
    for (NSString *selectorName in selectorNames) {
        id value = CNDObjectMessage0(object, NSSelectorFromString(selectorName));
        if ([value isKindOfClass:NSString.class] && [(NSString *)value length] > 0) {
            return value;
        }
        if ([value isKindOfClass:NSNumber.class]) return [(NSNumber *)value stringValue];
    }
    return nil;
}

static NSString *CNDNormalizedBundlePath(NSURL *bundleURL)
{
    NSString *path = bundleURL.path;
    if (path.length == 0) return nil;
    return path.stringByStandardizingPath.stringByResolvingSymlinksInPath;
}

static NSDictionary *CNDInfoDictionaryForBundleURL(NSURL *bundleURL)
{
    NSString *path = CNDNormalizedBundlePath(bundleURL);
    if (path.length == 0) return nil;
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
        [path stringByAppendingPathComponent:@"Info.plist"]];
    return [info isKindOfClass:NSDictionary.class] ? info : nil;
}

static NSString *CNDInfoString(NSDictionary *info, NSArray<NSString *> *keys)
{
    for (NSString *key in keys) {
        id value = info[key];
        if ([value isKindOfClass:NSString.class] && [(NSString *)value length] > 0) {
            return value;
        }
    }
    return nil;
}

static BOOL CNDInfoBool(NSDictionary *info, NSArray<NSString *> *keys)
{
    for (NSString *key in keys) {
        id value = info[key];
        if ([value respondsToSelector:@selector(boolValue)]) return [value boolValue];
    }
    return NO;
}

static BOOL CNDValueContainsHiddenApplicationTag(id value)
{
    if ([value isKindOfClass:NSString.class]) {
        NSString *tag = [(NSString *)value lowercaseString];
        return [@[@"hidden", @"restricted", @"non-launchable",
                  @"nonlaunchable", @"system-hidden"] containsObject:tag];
    }
    if ([value isKindOfClass:NSArray.class] ||
        [value isKindOfClass:NSSet.class]) {
        for (id item in value) {
            if (CNDValueContainsHiddenApplicationTag(item)) return YES;
        }
    }
    return NO;
}

static BOOL CNDInfoIsHiddenApplication(NSDictionary *info)
{
    if (CNDInfoBool(info, @[
        @"LSIsHidden", @"IsHidden", @"Hidden", @"SBIsHidden",
        @"LSApplicationIsHidden", @"SBHideApplicationIcon"
    ])) return YES;
    id defaultVisible = info[@"SBIconVisibilityDefaultVisible"];
    if ([defaultVisible respondsToSelector:@selector(boolValue)] &&
        ![defaultVisible boolValue]) return YES;
    for (NSString *key in @[@"SBAppTags", @"LSApplicationTags", @"AppTags"]) {
        if (CNDValueContainsHiddenApplicationTag(info[key])) return YES;
    }
    return NO;
}

static BOOL CNDPathIsSystemOwned(NSString *path)
{
    NSString *lower = path.lowercaseString ?: @"";
    for (NSString *prefix in @[
        @"/system/", @"/private/preboot/", @"/private/var/staged_system_apps/",
        @"/var/staged_system_apps/", @"/applications/"
    ]) {
        if ([lower hasPrefix:prefix]) return YES;
    }
    return NO;
}

static BOOL CNDBundleIdentifierLooksSystemOwned(NSString *bundleIdentifier);

static BOOL CNDResolvedSystemOwnership(NSString *applicationType,
                                       NSString *bundlePath,
                                       NSString *bundleIdentifier,
                                       BOOL fallback)
{
    if ([applicationType caseInsensitiveCompare:@"System"] == NSOrderedSame) {
        return YES;
    }
    if ([applicationType caseInsensitiveCompare:@"User"] == NSOrderedSame) {
        return NO;
    }
    return fallback || CNDPathIsSystemOwned(bundlePath) ||
        CNDBundleIdentifierLooksSystemOwned(bundleIdentifier);
}

static BOOL CNDPathLooksLikePluginOrExtension(NSString *path)
{
    NSString *lower = path.lowercaseString ?: @"";
    if ([lower hasSuffix:@".appex"] || [lower containsString:@".appex/"]) return YES;
    for (NSString *component in @[@"/plugins/", @"/plug-ins/", @"/extensions/", @"/watch/"]) {
        if ([lower containsString:component]) return YES;
    }
    return NO;
}

static BOOL CNDTypeLooksLikePluginOrWatch(NSString *type)
{
    NSString *lower = type.lowercaseString ?: @"";
    for (NSString *token in @[@"plugin", @"extension", @"watchkit", @"watchapp", @"watch app"]) {
        if ([lower containsString:token]) return YES;
    }
    return NO;
}

static BOOL CNDInfoIsWatchApplication(NSDictionary *info, NSString *path)
{
    if (CNDPathLooksLikePluginOrExtension(path)) return YES;
    if (CNDInfoBool(info, @[
        @"WKWatchKitApp", @"WKApplication", @"LSIsWatchApp", @"IsWatchApp",
        @"WatchKitApp", @"LSIsWatchKitApp"
    ])) return YES;
    NSString *type = CNDInfoString(info, @[
        @"LSApplicationType", @"ApplicationType", @"CFBundlePackageType"
    ]);
    if (CNDTypeLooksLikePluginOrWatch(type)) return YES;
    id platforms = info[@"CFBundleSupportedPlatforms"];
    if ([platforms isKindOfClass:NSArray.class]) {
        for (id platform in (NSArray *)platforms) {
            if (CNDTypeLooksLikePluginOrWatch([platform isKindOfClass:NSString.class]
                                               ? platform : nil)) return YES;
        }
    }
    id families = info[@"UIDeviceFamily"];
    if ([families isKindOfClass:NSArray.class] && [(NSArray *)families count] > 0) {
        BOOL hasWatch = NO;
        BOOL hasOther = NO;
        for (id family in (NSArray *)families) {
            NSInteger value = [family respondsToSelector:@selector(integerValue)]
                ? [family integerValue] : 0;
            hasWatch |= value == 4;
            hasOther |= value != 4;
        }
        if (hasWatch && !hasOther) return YES;
    }
    return NO;
}

static BOOL CNDInfoIsNonLaunchable(NSDictionary *info)
{
    if (CNDInfoBool(info, @[
        @"LSApplicationProhibited", @"LSNoLaunch", @"SBApplicationProhibited",
        @"LSBackgroundOnly", @"LSUIElement", @"IsLaunchProhibited", @"LSNoLaunchServices"
    ])) return YES;
    NSString *packageType = CNDInfoString(info, @[@"CFBundlePackageType"]);
    if (packageType.length > 0 &&
        [packageType caseInsensitiveCompare:@"APPL"] != NSOrderedSame) return YES;
    return info[@"NSExtension"] != nil;
}

static NSString *CNDVersionFromInfo(NSDictionary *info)
{
    return CNDInfoString(info, @[
        @"CFBundleShortVersionString", @"CFBundleVersion", @"ApplicationVersion"
    ]);
}

static NSString *CNDUpdateIdentityFromInfo(NSDictionary *info,
                                           NSString *bundleIdentifier,
                                           NSString *version)
{
    NSString *shortVersion = CNDInfoString(info, @[@"CFBundleShortVersionString"]);
    NSString *buildVersion = CNDInfoString(info, @[@"CFBundleVersion"]);
    NSString *external = CNDInfoString(info, @[
        @"ExternalVersionIdentifier", @"LSExternalVersionIdentifier",
        @"ApplicationVersionIdentifier", @"StoreVersionIdentifier"
    ]);
    if (shortVersion.length == 0 && buildVersion.length == 0 && external.length == 0) {
        return version.length > 0 ? version : nil;
    }
    return [NSString stringWithFormat:@"%@|%@|%@|%@",
            bundleIdentifier ?: @"", shortVersion ?: @"", buildVersion ?: @"",
            external ?: @""];
}

static NSString *CNDUpdateIdentityFromProxy(id proxy,
                                           NSString *bundleIdentifier,
                                           NSString *version)
{
    NSString *external = CNDDescriptionProperty(proxy, @[
        @"externalVersionIdentifier", @"applicationDSID", @"storeItemIdentifier",
        @"itemID", @"itemIdentifier", @"updateIdentifier"
    ]);
    NSString *build = CNDDescriptionProperty(proxy, @[
        @"bundleVersion", @"applicationVersion", @"version"
    ]);
    if (external.length == 0 && build.length == 0) return version;
    return [NSString stringWithFormat:@"%@|%@|%@",
            bundleIdentifier ?: @"", version ?: @"", external ?: build ?: @""];
}

static BOOL CNDApplicationIsEligible(NSString *bundleIdentifier,
                                     NSString *path,
                                     NSDictionary *info,
                                     NSString *applicationType,
                                     BOOL placeholder,
                                     BOOL hidden,
                                     BOOL launchable)
{
    if (bundleIdentifier.length == 0 || !launchable || placeholder || hidden) return NO;
    return !CNDPathLooksLikePluginOrExtension(path) &&
           !CNDTypeLooksLikePluginOrWatch(applicationType) &&
           !CNDInfoIsWatchApplication(info, path) &&
           !CNDInfoIsNonLaunchable(info);
}

static void CNDLoadLaunchServicesImages(void)
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Handles intentionally remain open for the lifetime of the process.
        // Depending on the OS build, LSApplicationWorkspace lives in one of
        // these images or has already been loaded by UIKit.
        NSArray<NSString *> *paths = @[
            @"/System/Library/Frameworks/CoreServices.framework/CoreServices",
            @"/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices",
            @"/System/Library/PrivateFrameworks/MobileCoreServices.framework/MobileCoreServices",
            @"/System/Library/PrivateFrameworks/LaunchServices.framework/LaunchServices",
        ];
        for (NSString *path in paths) {
            if (NSClassFromString(@"LSApplicationWorkspace")) break;
            (void)dlopen(path.fileSystemRepresentation, RTLD_LAZY | RTLD_LOCAL);
        }
    });
}

static NSObject *CNDSnowBoardBundleIdentifierCacheLock(void)
{
    static NSObject *lock;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        lock = [[NSObject alloc] init];
    });
    return lock;
}

static NSString *CNDSanitizedBundleIdentifier(id value)
{
    if (![value isKindOfClass:NSString.class]) return nil;

    NSString *identifier = [(NSString *)value
        stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (identifier.length == 0 || identifier.length > 255 ||
        [identifier hasPrefix:@"."] || [identifier hasSuffix:@"."] ||
        [identifier containsString:@".."]) {
        return nil;
    }

    static NSCharacterSet *invalidCharacters;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSCharacterSet *allowed = [NSCharacterSet
            characterSetWithCharactersInString:
                @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"];
        invalidCharacters = allowed.invertedSet;
    });
    if ([identifier rangeOfCharacterFromSet:invalidCharacters].location != NSNotFound) {
        return nil;
    }
    return identifier;
}

static NSArray<NSString *> *CNDSanitizedBundleIdentifiers(id values)
{
    if (![values conformsToProtocol:@protocol(NSFastEnumeration)]) return @[];

    NSMutableOrderedSet<NSString *> *identifiers = [NSMutableOrderedSet orderedSet];
    for (id value in values) {
        NSString *identifier = CNDSanitizedBundleIdentifier(value);
        if (identifier) [identifiers addObject:identifier];
    }
    return [identifiers.array sortedArrayUsingSelector:@selector(compare:)];
}

static BOOL CNDBundleIdentifierLooksSystemOwned(NSString *bundleIdentifier)
{
    return [bundleIdentifier.lowercaseString hasPrefix:@"com.apple."];
}

static CNDDockApplication *CNDApplicationFromProxy(id proxy)
{
    if (!proxy) return nil;

    BOOL known = NO;
    if (!CNDOptionalBoolProperty(proxy, @[@"isInstalled"], YES, &known) && known) {
        return nil;
    }

    BOOL placeholder = CNDOptionalBoolProperty(
        proxy, @[@"isPlaceholder", @"isPlaceholderApp", @"isApplicationPlaceholder",
                 @"isPlaceholderApplication"],
        NO, &known);
    BOOL hidden = CNDOptionalBoolProperty(
        proxy, @[@"isHidden", @"isHiddenApp", @"isRestricted",
                 @"isHiddenFromSpringBoard"],
        NO, &known);
    // `isVisibleToUser`, `isAppVisible`, `isVisible`, and `isLaunchable` are
    // context-sensitive private selectors. On physical devices they can all
    // report false to a sideloaded caller even for Safari, Notes, and other
    // Home Screen apps. LaunchServices membership plus the durable metadata
    // checks below is the stable eligibility source.
    BOOL launchable = YES;
    if (CNDOptionalBoolProperty(proxy, @[@"isLaunchProhibited", @"isLaunchRestricted"],
                                NO, NULL)) {
        launchable = NO;
    }
    if (CNDOptionalBoolProperty(proxy, @[@"isWatchApp", @"isWatchKitApp",
                                         @"isPlugin", @"isExtension"], NO, NULL)) {
        return nil;
    }

    NSURL *bundleURL = CNDURLProperty(proxy, @[
        @"bundleURL",
        @"applicationBundleURL",
        @"resourcesDirectoryURL"
    ]);
    NSString *bundlePath = CNDNormalizedBundlePath(bundleURL);
    NSDictionary *info = CNDInfoDictionaryForBundleURL(bundleURL);
    // `applicationIdentifier` can be the signing identifier on physical
    // devices (for example TEAMID.com.example.app). Theme entries and
    // LaunchServices bundle identity use CFBundleIdentifier, so prefer the
    // proxy's bundleIdentifier and then the bundle's actual Info.plist.
    NSString *bundleIdentifier = CNDSanitizedBundleIdentifier(
        CNDObjectMessage0(proxy, NSSelectorFromString(@"bundleIdentifier")) ?:
        info[@"CFBundleIdentifier"] ?:
        CNDObjectMessage0(proxy, NSSelectorFromString(@"applicationIdentifier")));
    if (bundleIdentifier.length == 0) return nil;
    id proxyTags = CNDObjectMessage0(proxy, NSSelectorFromString(@"appTags")) ?:
        CNDObjectMessage0(proxy, NSSelectorFromString(@"applicationTags")) ?:
        CNDObjectMessage0(proxy, NSSelectorFromString(@"tags"));
    if (CNDValueContainsHiddenApplicationTag(proxyTags) ||
        CNDInfoIsHiddenApplication(info)) hidden = YES;
    NSString *rawType = CNDDescriptionProperty(proxy, @[
        @"applicationType", @"applicationTypeString"
    ]);
    BOOL isSystem = CNDResolvedSystemOwnership(rawType, bundlePath,
                                                bundleIdentifier, NO);
    if (bundlePath.length > 0 && CNDPathLooksLikePluginOrExtension(bundlePath)) return nil;
    if (CNDTypeLooksLikePluginOrWatch(rawType)) return nil;
    if (!CNDApplicationIsEligible(bundleIdentifier, bundlePath, info, rawType,
                                  placeholder, hidden, launchable)) return nil;

    NSString *displayName = CNDStringProperty(proxy, @[
        @"localizedName",
        @"localizedShortName",
        @"itemName",
        @"bundleExecutable",
    ]);
    if (displayName.length == 0) displayName = bundleIdentifier;

    NSString *applicationType = rawType.length > 0
        ? rawType : (isSystem ? @"System" : @"User");
    NSString *version = CNDDescriptionProperty(proxy, @[
        @"shortVersionString", @"bundleShortVersionString", @"applicationVersion", @"version"
    ]);
    if (version.length == 0) version = CNDVersionFromInfo(info);
    NSString *updateIdentity = CNDUpdateIdentityFromProxy(proxy, bundleIdentifier, version);
    if (updateIdentity.length == 0) {
        updateIdentity = CNDUpdateIdentityFromInfo(info, bundleIdentifier, version);
    }

    return [[CNDDockApplication alloc] initWithBundleIdentifier:bundleIdentifier
                                                    displayName:displayName
                                                      bundleURL:bundleURL
                                                     bundlePath:bundlePath
                                              systemApplication:isSystem
                                                    placeholder:placeholder
                                                         hidden:hidden
                                                      launchable:launchable
                                                applicationType:applicationType
                                                        version:version
                                                 updateIdentity:updateIdentity];
}

static NSArray<CNDDockApplication *> *CNDLaunchServicesApplications(void)
{
    CNDLoadLaunchServicesImages();
    Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
    if (!workspaceClass) return @[];

    id workspace = CNDObjectMessage0(workspaceClass, NSSelectorFromString(@"defaultWorkspace"));
    if (!workspace) return @[];

    id proxies = nil;
    for (NSString *selectorName in @[@"allApplications", @"allInstalledApplications"]) {
        proxies = CNDObjectMessage0(workspace, NSSelectorFromString(selectorName));
        if ([proxies isKindOfClass:NSArray.class]) break;
    }
    if (![proxies isKindOfClass:NSArray.class]) return @[];

    NSMutableArray<CNDDockApplication *> *applications = [NSMutableArray array];
    for (id proxy in (NSArray *)proxies) {
        @autoreleasepool {
            CNDDockApplication *application = CNDApplicationFromProxy(proxy);
            if (application) [applications addObject:application];
        }
    }
    [applications sortUsingComparator:^NSComparisonResult(CNDDockApplication *left,
                                                           CNDDockApplication *right) {
        return CNDApplicationDeterministicCompare(left, right);
    }];
    return applications;
}

static NSString *CNDLocalizedBundleName(NSURL *bundleURL, NSDictionary *info)
{
    NSBundle *bundle = [NSBundle bundleWithURL:bundleURL];
    NSDictionary *localizedInfo = bundle.localizedInfoDictionary;
    for (NSString *key in @[@"CFBundleDisplayName", @"CFBundleName"]) {
        id value = localizedInfo[key];
        if ([value isKindOfClass:NSString.class] && [(NSString *)value length] > 0) {
            return value;
        }
        value = info[key];
        if ([value isKindOfClass:NSString.class] && [(NSString *)value length] > 0) {
            return value;
        }
    }
    return nil;
}

static CNDDockApplication *CNDApplicationAtBundleURL(NSURL *bundleURL, BOOL isSystem)
{
    NSString *bundlePath = CNDNormalizedBundlePath(bundleURL);
    if (![bundlePath.pathExtension.lowercaseString isEqualToString:@"app"]) return nil;

    NSDictionary *info = CNDInfoDictionaryForBundleURL(bundleURL);
    if (![info isKindOfClass:NSDictionary.class]) return nil;

    NSString *bundleIdentifier = CNDSanitizedBundleIdentifier(info[@"CFBundleIdentifier"]);
    if (bundleIdentifier.length == 0) return nil;

    NSString *applicationType = CNDInfoString(info, @[
        @"LSApplicationType", @"ApplicationType"
    ]);
    if (applicationType.length == 0) applicationType = isSystem ? @"System" : @"User";
    BOOL placeholder = CNDInfoBool(info, @[
        @"LSIsPlaceholder", @"IsPlaceholder", @"Placeholder", @"ApplicationIsPlaceholder",
        @"_LSApplicationIsPlaceholder", @"LSApplicationIsPlaceholder"
    ]);
    BOOL hidden = CNDInfoIsHiddenApplication(info);
    BOOL launchable = !CNDInfoIsNonLaunchable(info);
    if (!CNDApplicationIsEligible(bundleIdentifier, bundlePath, info, applicationType,
                                  placeholder, hidden, launchable)) return nil;

    NSString *displayName = CNDLocalizedBundleName(bundleURL, info);
    if (displayName.length == 0) {
        displayName = bundlePath.stringByDeletingPathExtension.lastPathComponent;
    }
    if (displayName.length == 0) displayName = bundleIdentifier;
    NSString *version = CNDVersionFromInfo(info);
    NSString *updateIdentity = CNDUpdateIdentityFromInfo(info, bundleIdentifier, version);

    BOOL systemOwned = CNDResolvedSystemOwnership(applicationType, bundlePath,
                                                  bundleIdentifier, isSystem);
    return [[CNDDockApplication alloc] initWithBundleIdentifier:bundleIdentifier
                                                    displayName:displayName
                                                      bundleURL:[NSURL fileURLWithPath:bundlePath
                                                                            isDirectory:YES]
                                                     bundlePath:bundlePath
                                              systemApplication:systemOwned
                                                    placeholder:placeholder
                                                         hidden:hidden
                                                      launchable:launchable
                                                applicationType:applicationType
                                                        version:version
                                                 updateIdentity:updateIdentity];
}

static void CNDScanApplicationRoot(NSString *rootPath,
                                   NSUInteger maximumDepth,
                                   BOOL isSystem,
                                   NSMutableArray<CNDDockApplication *> *applications)
{
    NSFileManager *fileManager = NSFileManager.defaultManager;
    BOOL isDirectory = NO;
    if (![fileManager fileExistsAtPath:rootPath isDirectory:&isDirectory] || !isDirectory) return;

    NSURL *rootURL = [NSURL fileURLWithPath:rootPath isDirectory:YES];
    NSUInteger rootComponentCount = rootURL.pathComponents.count;
    NSArray<NSURLResourceKey> *keys = @[NSURLIsDirectoryKey, NSURLIsPackageKey];
    NSDirectoryEnumerator<NSURL *> *enumerator =
        [fileManager enumeratorAtURL:rootURL
          includingPropertiesForKeys:keys
                             options:(NSDirectoryEnumerationSkipsHiddenFiles |
                                      NSDirectoryEnumerationSkipsPackageDescendants)
                        errorHandler:^BOOL(__unused NSURL *url, __unused NSError *error) {
        return YES;
    }];

    for (NSURL *url in enumerator) {
        @autoreleasepool {
            NSUInteger componentCount = url.pathComponents.count;
            NSUInteger depth = componentCount >= rootComponentCount
                ? componentCount - rootComponentCount : 0;
            NSNumber *directoryValue = nil;
            [url getResourceValue:&directoryValue forKey:NSURLIsDirectoryKey error:nil];
            if (!directoryValue.boolValue) continue;

            if ([url.pathExtension.lowercaseString isEqualToString:@"app"]) {
                CNDDockApplication *application = CNDApplicationAtBundleURL(url, isSystem);
                if (application) [applications addObject:application];
                [enumerator skipDescendants];
            } else if (depth >= maximumDepth) {
                [enumerator skipDescendants];
            }
        }
    }
}

static NSArray<CNDDockApplication *> *CNDFilesystemApplications(void)
{
    NSMutableArray<CNDDockApplication *> *applications = [NSMutableArray array];

    NSDictionary<NSString *, NSNumber *> *systemRoots = @{
        @"/Applications": @2,
        @"/System/Applications": @2,
        @"/System/Library/CoreServices": @2,
        @"/System/Cryptexes/App/System/Applications": @2,
        @"/private/preboot/Cryptexes/OS/System/Applications": @2,
        @"/private/var/staged_system_apps": @2,
        @"/var/staged_system_apps": @2,
    };
    [systemRoots enumerateKeysAndObjectsUsingBlock:^(NSString *path, NSNumber *depth, BOOL *stop) {
        (void)stop;
        CNDScanApplicationRoot(path, depth.unsignedIntegerValue, YES, applications);
    }];

    for (NSString *path in @[
        @"/var/containers/Bundle/Application",
        @"/private/var/containers/Bundle/Application",
        @"/var/mobile/Containers/Bundle/Application",
    ]) {
        CNDScanApplicationRoot(path, 3, NO, applications);
    }

    [applications sortUsingComparator:^NSComparisonResult(CNDDockApplication *left,
                                                           CNDDockApplication *right) {
        return CNDApplicationDeterministicCompare(left, right);
    }];
    return applications;
}

static BOOL CNDApplicationHasFriendlyName(CNDDockApplication *application)
{
    return application.displayName.length > 0 &&
        ![application.displayName isEqualToString:application.bundleIdentifier];
}

static NSComparisonResult CNDStableStringCompare(NSString *left, NSString *right)
{
    left = left ?: @"";
    right = right ?: @"";
    NSComparisonResult result = [left localizedCaseInsensitiveCompare:right];
    if (result != NSOrderedSame) return result;
    return [left compare:right];
}

static NSComparisonResult CNDApplicationDeterministicCompare(
    CNDDockApplication *left, CNDDockApplication *right)
{
    NSComparisonResult result = CNDStableStringCompare(left.displayName, right.displayName);
    if (result != NSOrderedSame) return result;
    result = CNDStableStringCompare(left.bundleIdentifier, right.bundleIdentifier);
    if (result != NSOrderedSame) return result;
    result = CNDStableStringCompare(left.bundlePath, right.bundlePath);
    if (result != NSOrderedSame) return result;
    result = CNDStableStringCompare(left.applicationType, right.applicationType);
    if (result != NSOrderedSame) return result;
    result = CNDStableStringCompare(left.version, right.version);
    if (result != NSOrderedSame) return result;
    result = CNDStableStringCompare(left.updateIdentity, right.updateIdentity);
    if (result != NSOrderedSame) return result;
    if (left.isSystemApplication != right.isSystemApplication) {
        return left.isSystemApplication ? NSOrderedAscending : NSOrderedDescending;
    }
    if (left.isLaunchable != right.isLaunchable) {
        return left.isLaunchable ? NSOrderedAscending : NSOrderedDescending;
    }
    return NSOrderedSame;
}

static CNDDockApplication *CNDMergeApplications(CNDDockApplication *existing,
                                                CNDDockApplication *incoming)
{
    if (!existing) return incoming;
    if (!incoming) return existing;

    CNDDockApplication *nameSource = CNDApplicationHasFriendlyName(existing)
        ? existing : (CNDApplicationHasFriendlyName(incoming) ? incoming : existing);
    NSURL *bundleURL = existing.bundleURL ?: incoming.bundleURL;
    NSString *bundlePath = existing.bundlePath ?: incoming.bundlePath;
    NSString *applicationType = ![existing.applicationType isEqualToString:@"Unknown"]
        ? existing.applicationType : incoming.applicationType;
    NSString *version = existing.version.length > 0 ? existing.version : incoming.version;
    NSString *updateIdentity = existing.updateIdentity.length > 0
        ? existing.updateIdentity : incoming.updateIdentity;
    return [[CNDDockApplication alloc] initWithBundleIdentifier:existing.bundleIdentifier
                                                    displayName:nameSource.displayName
                                                      bundleURL:bundleURL
                                                     bundlePath:bundlePath
                                              systemApplication:(existing.isSystemApplication ||
                                                                  incoming.isSystemApplication)
                                                    placeholder:(existing.isPlaceholder ||
                                                                 incoming.isPlaceholder)
                                                         hidden:(existing.isHidden ||
                                                                 incoming.isHidden)
                                                      launchable:(existing.isLaunchable &&
                                                                  incoming.isLaunchable)
                                                applicationType:applicationType
                                                        version:version
                                                 updateIdentity:updateIdentity];
}


@implementation CNDDockAppCatalog

+ (void)recordSnowBoardBundleIdentifiers:(NSArray<NSString *> *)bundleIdentifiers
{
    NSArray<NSString *> *incoming = CNDSanitizedBundleIdentifiers(bundleIdentifiers);
    @synchronized (CNDSnowBoardBundleIdentifierCacheLock()) {
        NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
        id stored = [defaults objectForKey:kCNDSnowBoardBundleIdentifiersDefaultsKey];
        NSArray<NSString *> *existing = CNDSanitizedBundleIdentifiers(stored);
        NSMutableOrderedSet<NSString *> *merged =
            [NSMutableOrderedSet orderedSetWithArray:existing];
        [merged addObjectsFromArray:incoming];
        NSArray<NSString *> *normalized =
            [merged.array sortedArrayUsingSelector:@selector(compare:)];
        if (![stored isKindOfClass:NSArray.class] ||
            ![(NSArray *)stored isEqualToArray:normalized]) {
            [defaults setObject:normalized
                         forKey:kCNDSnowBoardBundleIdentifiersDefaultsKey];
        }
    }
}

static NSArray<CNDDockApplication *> *CNDInstalledApplications(void)
{
    NSMutableDictionary<NSString *, CNDDockApplication *> *byBundleIdentifier =
        [NSMutableDictionary dictionary];

    NSArray<CNDDockApplication *> *launchServicesApplications =
        CNDLaunchServicesApplications();
    for (CNDDockApplication *application in launchServicesApplications) {
        byBundleIdentifier[application.bundleIdentifier] = application;
    }

    /* Filesystem discovery fills metadata only for records LaunchServices
     * already identifies as applications. If LaunchServices is wholly
     * unavailable it remains a fallback, but it must not promote every .app
     * beneath CoreServices into a user-launchable Home Screen application. */
    for (CNDDockApplication *application in CNDFilesystemApplications()) {
        CNDDockApplication *registered =
            byBundleIdentifier[application.bundleIdentifier];
        if (registered || launchServicesApplications.count == 0) {
            byBundleIdentifier[application.bundleIdentifier] =
                CNDMergeApplications(registered, application);
        }
    }

    NSMutableArray<CNDDockApplication *> *result = [NSMutableArray array];
    for (CNDDockApplication *application in byBundleIdentifier.allValues) {
        if (application.isLaunchable && !application.isPlaceholder && !application.isHidden) {
            [result addObject:application];
        }
    }
    [result sortUsingComparator:^NSComparisonResult(CNDDockApplication *left,
                                                    CNDDockApplication *right) {
        return CNDApplicationDeterministicCompare(left, right);
    }];
    return result;
}

+ (NSArray<CNDDockApplication *> *)installedApplications
{
    return CNDInstalledApplications();
}

+ (NSArray<CNDDockApplication *> *)applicationsForBundleIdentifiers:
    (NSArray<NSString *> *)bundleIdentifiers
{
    NSArray<NSString *> *identifiers = CNDSanitizedBundleIdentifiers(bundleIdentifiers);
    NSMutableArray<CNDDockApplication *> *result = [NSMutableArray array];
    for (NSString *bundleIdentifier in identifiers) {
        CNDDockApplication *application = [[CNDDockApplication alloc]
            initWithBundleIdentifier:bundleIdentifier
                         displayName:bundleIdentifier
                           bundleURL:nil
                          bundlePath:nil
                   systemApplication:NO
                         placeholder:NO
                              hidden:NO
                          launchable:YES
                     applicationType:@"Unknown"
                             version:nil
                      updateIdentity:nil];
        [result addObject:application];
    }
    [result sortUsingComparator:^NSComparisonResult(CNDDockApplication *left,
                                                    CNDDockApplication *right) {
        return CNDApplicationDeterministicCompare(left, right);
    }];
    return result;
}

+ (void)loadInstalledApplicationsWithCompletion:(CNDDockAppCatalogCompletion)completion
{
    if (!completion) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSArray<CNDDockApplication *> *applications = [self installedApplications];
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(applications);
        });
    });
}

@end
