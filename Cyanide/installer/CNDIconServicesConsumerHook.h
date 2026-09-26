#import <Foundation/Foundation.h>
#import <sys/types.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, CNDIconServicesConsumerHookResult) {
    CNDIconServicesConsumerHookFailed = 0,
    CNDIconServicesConsumerHookInstalled = 1,
    CNDIconServicesConsumerHookAlreadyInstalled = 2,
    CNDIconServicesConsumerHookUnsupportedTransport = 3,
};

typedef struct {
    CNDIconServicesConsumerHookResult result;
    bool abiValidated;
    bool payloadCopied;
    bool payloadReadbackVerified;
    bool executableProtectionApplied;
    bool libraryValidationAccepted;
    bool libraryValidationPolicyFallbackUsed;
    int libraryValidationErrno;
    bool executionProbeVerified;
    bool methodsInstalled;
    bool methodsReadbackVerified;
    bool rollbackAttempted;
    bool rollbackVerified;
    bool mappingCleanupAttempted;
    bool mappingCleanupVerified;
    bool transportClean;
    int pid;
    uint64_t mappingAddress;
    uint64_t mappingLength;
    char host[32];
    char reason[192];
} CNDIconServicesConsumerHookReport;

/// Installs the marker-aware transparent IconRendering consumer into the
/// currently active RemoteCall target. The caller must keep one session open;
/// payload delivery and verification reuse that session on both the vPhone
/// lab backend and the physical-device RemoteCall transport.
CNDIconServicesConsumerHookResult
CNDIconServicesConsumerHookInstallInCurrentSession(
    const char *host,
    double displayScale,
    CNDIconServicesConsumerHookReport * _Nullable reportOut);

NSDictionary<NSString *, id> *CNDIconServicesConsumerHookReportDictionary(
    const CNDIconServicesConsumerHookReport *report);

/// Opens one scoped session to a consumer process, installs or verifies its
/// process-wide presentation route, and closes the channel. The VM route is
/// marker-aware; the physical route selects the stock flat-image branch. This
/// is called once per consumer PID, never once per icon. It does not purge or
/// reload SpringBoard's icon caches.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerHookInstallForProcess(NSString *processName,
                                             double displayScale);

/// Physical-device path used by the lifecycle watcher. The exact kernel proc
/// identity is bound before one RemoteCall opens. The target then receives a
/// data-only Objective-C method-table redirects to ABI-identical Apple-signed
/// implementations; no executable payload is mapped. Both consumers select
/// SBIconImageView's stock flat-image branch. SpringBoard additionally routes
/// the app-switcher title's matched provider/setter pair through its existing
/// UIImage path so its published 28-point response retains alpha.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerHookInstallForPID(pid_t pid,
                                         NSString *expectedProcessName,
                                         double displayScale);

/// Theme-mutation variant of the single-session physical installer. It
/// configures bounded Clock/Calendar source redirects; SpringBoard can also
/// purge/rebuild visible icon caches in the same session.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerHookInstallForPIDWithStaticIcons(
    pid_t pid,
    NSString *expectedProcessName,
    double displayScale,
    NSDictionary<NSString *, NSData *> *staticIconDataByBundle);

/// Explicit single-session policy used by the lifecycle coordinator. The
/// manual SpringBoard/Spotlight repairs enable static sources but leave cache
/// refresh disabled; the post-publication SpringBoard repair can enable both.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerHookInstallForPIDWithOptions(
    pid_t pid,
    NSString *expectedProcessName,
    double displayScale,
    NSDictionary<NSString *, NSData *> *staticIconDataByBundle,
    BOOL refreshSpringBoardCaches,
    BOOL updateStaticDynamicIcons);

/// Opens one scoped SpringBoard session and performs only the bounded icon
/// cache purge/reload used after persistent IconServices publication. It does
/// not install presentation redirects, configure Clock/Calendar sources, or
/// start a watcher.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerHookRefreshSpringBoardForPID(pid_t pid);

/// Opens one scoped SpringBoard session and returns a read-only snapshot of
/// canonical, live-leaf, and materialized switcher icon identities for the
/// supplied journaled bundles. No presentation redirect, cache refresh,
/// reload, purge, relayout, or update handler is invoked.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerHookAuditSpringBoard(
    NSArray<NSString *> *bundleIdentifiers);

NS_ASSUME_NONNULL_END
