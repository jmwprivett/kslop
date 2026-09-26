#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Builds the identity-preserving LaunchServices registration dictionary for
/// the currently running Cyanide installation. This function is read-only: it
/// does not establish KRW, contact installd, or modify the application bundle.
///
/// The result always contains `ok`, `stage`, and `message`. On success it also
/// contains `registrationDictionary`; callers may pass that dictionary to
/// CNDLaunchServicesRegisterViaInstalld only after establishing live KRW.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesCopySelfRegistrationDictionary(void);

/// Captures the currently registered identity of another installed user app.
/// This is read-only: stock installd resolves the supplied bundle identifier
/// and supplies detached application and plug-in proxies through RemoteCall.
/// The returned registration dictionary includes the app's existing data
/// container, entitlements, group containers, signing identity, and plug-in
/// records; it fails closed rather than guessing when an identity-bearing field
/// cannot be recovered.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesCopyRegistrationDictionaryForBundleIdentifier(
    NSString *bundleIdentifier);

/// Identical capture, but retains the single successful installd RemoteCall
/// session on the current thread for the caller's subsequent filesystem and
/// registration operations. The caller must finish it with
/// CNDLaunchServicesFinishRetainedInstalldSession.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDLaunchServicesCopyRegistrationDictionaryForBundleIdentifierRetainingSession(
    NSString *bundleIdentifier);

NS_ASSUME_NONNULL_END
