#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Returns whether Cyanide has a durable eBay icon/registration recovery
/// journal. This state survives a Cyanide process restart and must be restored
/// before Cyanide is reinstalled or deleted.
BOOL CNDIconDeclarationRedirectIsActive(void);

/// The effective target for the current operation. In the vPhone lab a
/// pending journal wins so an older eBay transaction can always be restored;
/// otherwise the lab targets Cyanide while physical-device builds target eBay.
NSString *CNDIconDeclarationRedirectTargetBundleIdentifier(void);

/// Captures eBay's identity and declared fallback icon plus the actual
/// bundle Info.plist, journals the original bytes/vnode metadata, updates both
/// existing vnodes through overwrite_system_file(), and asks stock installd to
/// select the fallback by removing only the phone primary CFBundleIconName.
/// If no usable legacy file exists, creates one transaction-owned bundle file.
NSDictionary<NSString *, id> *CNDIconDeclarationRedirectApply(void);

/// Attempts exact Info.plist and icon restoration before rebuilding stock
/// registration from the on-disk bundle. The journal is removed only after
/// both files and registration are verified, clean installd teardown completes,
/// and the IconServices invalidation request has been issued.
NSDictionary<NSString *, id> *CNDIconDeclarationRedirectRestore(void);

/// Emergency recovery for the legacy registration-only/create-file test.
/// Removes only its journaled bundle-relative PNG without requiring a fresh
/// content read, then rebuilds registration from the unchanged on-disk bundle.
/// Refuses transactions that include an Info.plist mutation.
NSDictionary<NSString *, id> *CNDIconDeclarationRedirectEmergencyClear(void);

/// Forgets only Cyanide's local icon-redirect journal and staging file. This
/// deliberately performs no target-file, Info.plist, registration, cache, or
/// process operation and does not claim that a pending mutation was restored.
NSDictionary<NSString *, id> *CNDIconDeclarationRedirectResetRecoveryState(void);

/// Parameterized entry points used by SnowBoard Remix. The diagnostic methods
/// above remain wrappers around the same transaction implementation.
NSDictionary<NSString *, id> *CNDIconDeclarationRedirectApplyThemeData(
    NSString *bundleIdentifier,
    NSData *sourcePNGData,
    NSURL *journalURL);
NSDictionary<NSString *, id> *CNDIconDeclarationRedirectRestoreJournal(
    NSString *bundleIdentifier,
    NSURL *journalURL);

NS_ASSUME_NONNULL_END
