//
//  Package.h
//  Cyanide
//
//  Model object representing one tweak in the Installer-style packages tab.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSNotificationName const PackageFavoritesDidChangeNotification;

/// Favorites are UI-only Installer metadata keyed by the package's stable
/// identifier. They do not change install/activation state.
FOUNDATION_EXPORT NSSet<NSString *> *PackageFavoriteIdentifiers(void);
FOUNDATION_EXPORT BOOL PackageIdentifierIsFavorite(NSString *identifier);
FOUNDATION_EXPORT void PackageSetIdentifierFavorite(NSString *identifier, BOOL favorite);

typedef NS_ENUM(NSInteger, PackageInstallKind) {
    // Master enable is a BOOL in NSUserDefaults under enabledKey. Installing
    // sets it to YES; uninstalling sets NO. settings_run_actions() applies.
    PackageInstallKindToggle = 0,

    // Persistent system tweak that does not use settings_run_actions().
    // Installing calls darksword_ota_set_disabled(true); uninstalling calls
    // darksword_ota_set_disabled(false). State tracked in a defaults intent key.
    PackageInstallKindOTA = 1,

    // One-shot plist edit gated by kexploit + sandbox patch (NanoRegistry
    // watchOS pairing-compatibility override). Installing calls
    // settings_apply_nano_registry_now(YES) which writes the four
    // compatibility keys from the Settings bundle; uninstalling clears them.
    // No live RC loop, doesn't run settings_run_actions.
    PackageInstallKindNanoRegistry = 2,

    // One-shot CallServices audio replacement gated by kexploit + sandbox
    // patch. Installing writes bundled silent disclosure sounds and stores
    // the first originals in Cyanide's app container; uninstalling restores
    // those backups when present.
    PackageInstallKindCallRecordingSound = 3,

    // One-shot DirtyZero-style MaterialKit asset page zero. Installing hides
    // the home bar after respring; restoring needs a respring.
    PackageInstallKindHideHomeBar = 4,

    // One-shot system font replacement. Installing writes the imported local
    // font family after backing up stock fonts; uninstalling restores backups.
    // Respring required after either direction.
    PackageInstallKindFontChanger = 5,

    // Direct settings tool. It has a Settings bundle but no install queue,
    // active state, or PackageQueue commit step.
    PackageInstallKindDirectTool = 6,

    // Direct live lock-screen camera/flashlight glyph control. Apply and
    // Restore are manual RemoteCall actions and never enter PackageQueue.
    PackageInstallKindLockscreenGlyphs = 7,

    // Transactional Control Center resource replacement. Apply and Restore
    // run from the durable queue before its automatic shared respring.
    PackageInstallKindControlCenterTheming = 8,
};

@interface Package : NSObject

@property (nonatomic, readonly, copy)     NSString *identifier;
@property (nonatomic, readonly, copy)     NSString *name;
@property (nonatomic, readonly, copy)     NSString *shortDescription;
@property (nonatomic, readonly, copy)     NSString *longDescription;
@property (nonatomic, readonly, copy)     NSString *version;
@property (nonatomic, readonly, copy)     NSString *author;
@property (nonatomic, readonly, copy)     NSString *category;
@property (nonatomic, readonly, copy)     NSString *symbolName;
@property (nonatomic, readonly, assign)   PackageInstallKind kind;
@property (nonatomic, readonly, copy, nullable) NSString *enabledKey;
@property (nonatomic, readonly, assign)   BOOL isNew;

// SettingsSection enum value that corresponds to this package's bundle in the
// Settings tab. NSIntegerMax means the package has no Settings bundle
// (install/uninstall is its only operation).
@property (nonatomic, assign) NSInteger settingsSection;

// If non-nil, the detail view renders this text as a red disclaimer banner
// above the Information card. Use for packages that are known to be unstable
// (SpringBoard crashes, dropped events, layout glitches, etc.) so users can't
// miss the warning.
@property (nonatomic, copy, nullable) NSString *unstableWarning;

// Non-nil means users can view the package and uninstall an existing install,
// but cannot queue a fresh install until the reason is cleared.
@property (nonatomic, copy, nullable) NSString *installDisabledReason;

// YES means the package is gated behind kSettingsExperimentalTweaksEnabled.
// When the master experimental switch is off, +[PackageCatalog allPackages]
// filters experimental packages out entirely so they don't appear in the
// Installer list or the Settings tweak-bundle list.
@property (nonatomic, assign) BOOL experimental;

// YES means the package is only installable by the campaign creator.
// Non-creators see the package but cannot queue it.
@property (nonatomic, assign) BOOL creatorOnly;

// Non-nil means the package detail view shows a prominent "Known Issues" card.
// Each string is one bullet. Set in PackageCatalog.
@property (nonatomic, copy, nullable) NSArray<NSString *> *knownIssues;

@property (nonatomic, readonly, assign) BOOL isInstalled;
@property (nonatomic, readonly, assign) BOOL isQueuedForApply;
@property (nonatomic, readonly, assign) BOOL isInstallDisabled;
/// Ephemeral applied marker for durable mutations whose UI state is valid for
/// one explicitly-authorized SpringBoard epoch (currently SnowBoard Remix and
/// Font Changer). This is intentionally distinct from `isInstalled`.
@property (nonatomic, readonly, assign) BOOL isAppliedForCurrentSystemEpoch;

- (instancetype)initWithIdentifier:(NSString *)identifier
                              name:(NSString *)name
                  shortDescription:(NSString *)shortDescription
                   longDescription:(NSString *)longDescription
                           version:(NSString *)version
                            author:(NSString *)author
                          category:(NSString *)category
                        symbolName:(NSString *)symbolName
                              kind:(PackageInstallKind)kind
                        enabledKey:(nullable NSString *)enabledKey
                             isNew:(BOOL)isNew NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

- (void)install;
- (void)uninstall;
- (BOOL)applyCommittedState:(BOOL)installed;

@end

NS_ASSUME_NONNULL_END
