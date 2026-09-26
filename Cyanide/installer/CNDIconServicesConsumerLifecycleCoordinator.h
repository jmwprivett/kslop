#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Posted after the direct installer has verified the process-local
/// presentation redirect in one exact process incarnation and closed its
/// temporary channel. `userInfo` contains `process`, `pid`, `payloadVersion`,
/// and the complete installer `result` dictionary.
FOUNDATION_EXPORT NSString * const
    CNDIconServicesConsumerLifecycleDidInstallNotification;

/// Explicitly arms the Spotlight-only lifecycle watcher. SpringBoard is never
/// polled by this watcher; its repair action remains a one-shot operation.
/// The VM installs through its direct root-task bridge. Physical arm64e uses
/// one PID-bound Apple-signed IMP RemoteCall per Spotlight incarnation.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerLifecycleStart(double displayScale);

/// Stops observing future process incarnations. Existing process-local method
/// redirects remain until their host exits.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerLifecycleStop(void);

NSDictionary<NSString *, id> *
CNDIconServicesConsumerLifecycleStatus(void);

BOOL CNDIconServicesConsumerLifecycleIsRunning(void);

/// Replaces the bounded dynamic-icon source payloads carried into the next
/// SpringBoard or Spotlight repair. Clock/Calendar icons plus Clock's five
/// optional hand/dot images and the live face are retained. An empty
/// dictionary restores stock sources during the next target repair.
void CNDIconServicesConsumerLifecycleSetStaticDynamicIconData(
    NSDictionary<NSString *, NSData *> *imageDataByBundle);

/// Forces exactly one install/verification attempt for the current PID of one
/// presentation consumer. State reservation/commit is serialized, but the
/// bounded target operation never holds the lifecycle queue. Valid process
/// names are `SpringBoard` and `Spotlight`. Both repair transparency plus the
/// staged Clock/Calendar sources without purging icon caches.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerLifecycleRepairProcess(NSString *processName,
                                               double displayScale);

/// Explicit repair after persistent IconServices responses changed (Restore
/// uses this path; Initial Apply uses the cache-only function below).
/// SpringBoard rebuilds its ordinary consumers, then configures Clock/Calendar
/// sources in the same scoped session so the final dynamic face is not
/// overwritten by the rebuild.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerLifecycleRepairAfterThemeMutation(
    NSString *processName, double displayScale);

/// Performs only the post-publication SpringBoard cache purge/reload. This is
/// does not install transparency, configure Clock/Calendar, or start either
/// watcher.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerLifecycleRefreshSpringBoardCaches(void);

/// Accelerates the next resident-Spotlight identity check after a known
/// foreground transition. Foreground state is not an installation gate.
void CNDIconServicesConsumerLifecycleNoteForegroundTransition(void);

NS_ASSUME_NONNULL_END
