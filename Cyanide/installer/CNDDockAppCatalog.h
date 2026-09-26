//
//  CNDDockAppCatalog.h
//  Cyanide
//
//  Installed-application discovery for the SBCustomizer dock picker.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Immutable metadata for an installed application that can be placed in the
/// SpringBoard dock.
@interface CNDDockApplication : NSObject

@property (nonatomic, copy, readonly) NSString *bundleIdentifier;
@property (nonatomic, copy, readonly) NSString *displayName;
@property (nonatomic, strong, readonly, nullable) NSURL *bundleURL;
/// The normalized filesystem path for `bundleURL`, when LaunchServices or
/// filesystem discovery exposed one.
@property (nonatomic, copy, readonly, nullable) NSString *bundlePath;
/// Alias for bundlePath for callers that do not need URL semantics.
@property (nonatomic, copy, readonly, nullable) NSString *path;
@property (nonatomic, assign, readonly, getter=isSystemApplication) BOOL systemApplication;
@property (nonatomic, assign, readonly, getter=isSystemOwned) BOOL systemOwned;
@property (nonatomic, assign, readonly, getter=isPlaceholder) BOOL placeholder;
@property (nonatomic, assign, readonly, getter=isHidden) BOOL hidden;
@property (nonatomic, assign, readonly, getter=isLaunchable) BOOL launchable;
/// LaunchServices' application type (normally `User` or `System`).
@property (nonatomic, copy, readonly) NSString *applicationType;
/// CFBundleShortVersionString, falling back to CFBundleVersion.
@property (nonatomic, copy, readonly, nullable) NSString *version;
/// Stable identity used to notice an installed-app update. This combines the
/// short version/build and any LaunchServices store version identity.
@property (nonatomic, copy, readonly, nullable) NSString *updateIdentity;
/// Compatibility alias for updateIdentity.
@property (nonatomic, copy, readonly, nullable) NSString *updateIdentifier;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

typedef void (^CNDDockAppCatalogCompletion)(NSArray<CNDDockApplication *> *applications);

/// Discovers user-launchable user and system applications without statically
/// linking private LaunchServices APIs. Filesystem discovery fills metadata
/// for registered records and is a fallback only when LaunchServices is absent.
@interface CNDDockAppCatalog : NSObject

/// Remembers bundle identifiers observed during a successful SnowBoard apply.
/// Subsequent discovery uses them as fallbacks when LaunchServices and the
/// filesystem do not expose the corresponding application.
+ (void)recordSnowBoardBundleIdentifiers:(NSArray<NSString *> *)bundleIdentifiers;

/// Performs discovery synchronously. Call from a background queue.
+ (NSArray<CNDDockApplication *> *)installedApplications;

/// Resolves a bounded SpringBoard-visible bundle-ID snapshot into catalog
/// records. Identifiers missing from the jailed LaunchServices view receive a
/// minimal record; the per-app transaction resolves their authoritative path
/// and identity through installd.
+ (NSArray<CNDDockApplication *> *)applicationsForBundleIdentifiers:
    (NSArray<NSString *> *)bundleIdentifiers;

/// Performs discovery on a utility queue and invokes completion on the main
/// queue. The returned array is sorted by localized display name, then bundle
/// identifier.
+ (void)loadInstalledApplicationsWithCompletion:(CNDDockAppCatalogCompletion)completion;

@end

NS_ASSUME_NONNULL_END
