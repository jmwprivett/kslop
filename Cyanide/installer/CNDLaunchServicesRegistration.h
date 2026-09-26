#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Wakes the stock installd Mach service when it is not already resident.
/// The returned dictionary always contains `ok`, `stage`, and `message`.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesEnsureInstalldRunning(void);

/// Captures detached application and plug-in proxies inside stock installd,
/// archives them there, and copies the archive back through RemoteCall. On
/// success the result contains `proxyArchive` (NSData). It does not register or
/// modify the app.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesCopyApplicationProxyArchiveViaInstalld(
    NSString *bundleIdentifier);

/// Copies only the registered application bundle identifiers from stock
/// installd. The remote side asks LaunchServices once and archives the compact
/// NSString array; application proxy objects and their metadata are never
/// copied. The result contains `bundleIdentifiers` on success.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesCopyInstalledBundleIdentifiersViaInstalld(void);

/// Catalog variant for a coordinator that will immediately begin a batch on
/// the same worker thread. The caller must finish or promote the retained
/// session even when later matching finds no work.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesCopyInstalledBundleIdentifiersViaInstalldRetainingSession(void);

/// Capture variant used by one scoped transaction. On success the trapped
/// installd RemoteCall session remains attached to the current thread so the
/// caller can create/register without trapping installd again. The caller must
/// always call CNDLaunchServicesFinishRetainedInstalldSession on that thread.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesCopyApplicationProxyArchiveViaInstalldRetainingSession(
    NSString *bundleIdentifier);

/// Closes and clears the current thread's retained installd session. A result
/// with ok=yes guarantees healthy transport, clean teardown, and no remaining
/// local RemoteCall state. It is harmless when no retained session exists.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesFinishRetainedInstalldSession(void);

/// Opens one bounded batch-owned installd session on the current thread. While
/// batch ownership is active, ordinary per-transaction finalization calls keep
/// the healthy session retained. The coordinator must always call the matching
/// finish function on the same thread.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesBeginBatchInstalldSession(NSString *bundleIdentifier);

FOUNDATION_EXPORT BOOL
CNDLaunchServicesBatchInstalldSessionIsHealthy(void);

FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesFinishBatchInstalldSession(void);

/// Registers an existing application dictionary from inside stock installd.
/// This is the privileged equivalent of uicache's final
/// -[LSApplicationWorkspace registerApplicationDictionary:] operation; it
/// does not depend on a jailbreak executable being present.
///
/// The caller is responsible for supplying a complete registration dictionary
/// which preserves the existing app's identity, containers, signing metadata,
/// plug-ins, and classification.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesRegisterViaInstalld(
    NSDictionary<NSString *, id> *registrationDictionary);

/// Asks stock installd's LSApplicationWorkspace to rebuild an already
/// installed application's registration from its existing bundle URL. This
/// preserves LaunchServices' own container, plug-in, signing, and entitlement
/// discovery instead of synthesizing a registration dictionary.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesRegisterBundleURLViaInstalld(NSString *bundlePath);

/// VM-lab support for the same existing-vnode operation used by the device
/// proof. The authenticated root-injected installd endpoint opens the existing
/// regular leaf without truncation, writes exactly `contents.length` bytes,
/// fsyncs, and performs same-descriptor readback. Production callers continue
/// to use overwrite_system_file(); this helper fails closed unless a retained
/// installd session is available or one can be opened.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesOverwriteExistingBundleFileViaInstalld(
    NSString *targetPath,
    NSData *contents);

/// Creates one absent, bundle-relative PNG through stock installd. This is
/// intentionally limited to the icon proof's missing-file fallback: the path
/// must be a direct child of an installed application bundle, and O_EXCL plus
/// O_NOFOLLOW prevent replacement or symlink traversal.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesCreateAbsentBundleIconViaInstalld(
    NSString *targetPath,
    NSData *contents);

/// Reads one direct bundle-icon PNG through stock installd. This is used only
/// to verify a transaction-created file when Cyanide's own sandbox cannot
/// reopen the new bundle leaf. The returned dictionary contains `data` only
/// after an exact expected-length read and EOF check.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesReadBundleIconViaInstalld(
    NSString *targetPath,
    NSUInteger expectedLength);

/// Removes one transaction-created bundle icon through stock installd. Callers
/// must verify the exact expected bytes and vnode identity before requesting
/// removal; this helper repeats the strict bundle-relative path validation.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesRemoveCreatedBundleIconViaInstalld(NSString *targetPath);

NS_ASSUME_NONNULL_END
