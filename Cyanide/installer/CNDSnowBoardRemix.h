#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDSnowBoardRemixProgress)(NSString *phase,
                                          NSUInteger completed,
                                          NSUInteger total,
                                          NSString *_Nullable bundleIdentifier);
typedef BOOL (^CNDSnowBoardRemixCancellation)(void);
typedef void (^CNDSnowBoardRemixStatusesCompletion)(NSArray<NSDictionary<NSString *, id> *> *statuses);

FOUNDATION_EXPORT NSString * const CNDSnowBoardRemixStatusesDidRefreshNotification;

/// Sequential coordinator. Every application remains an independent durable
/// transaction; a failure never invalidates already verified applications.
@interface CNDSnowBoardRemix : NSObject

+ (NSDictionary<NSString *, id> *)scanInstalledApplications;
+ (NSDictionary<NSString *, id> *)applySelectedThemeWithProgress:
    (nullable CNDSnowBoardRemixProgress)progress
    cancellation:(nullable CNDSnowBoardRemixCancellation)cancellation;
+ (NSDictionary<NSString *, id> *)repairInstalledApplicationUpdatesWithProgress:
    (nullable CNDSnowBoardRemixProgress)progress
    cancellation:(nullable CNDSnowBoardRemixCancellation)cancellation;
+ (NSDictionary<NSString *, id> *)applySelectedThemeForBundleIdentifiers:
    (NSArray<NSString *> *)bundleIdentifiers
    progress:(nullable CNDSnowBoardRemixProgress)progress
    cancellation:(nullable CNDSnowBoardRemixCancellation)cancellation;
+ (NSDictionary<NSString *, id> *)restoreAllWithProgress:
    (nullable CNDSnowBoardRemixProgress)progress
    cancellation:(nullable CNDSnowBoardRemixCancellation)cancellation;
+ (NSDictionary<NSString *, id> *)restoreBundleIdentifier:
    (NSString *)bundleIdentifier;

/// Reconciles the process-wide transparent presentation mappings with the
/// durable IconServices journals and the user's presentation toggle. This
/// never launches the exploit. If KRW is not already available it reports a
/// pending state. The VM uses its root task bridge; physical arm64e may open
/// one signed-vnode RemoteCall for each new consumer PID.
+ (NSDictionary<NSString *, id> *)reconcilePresentationLifecycle;
/// Apply SpringBoard Tweaks: explicit transparency, Clock hand assets, and
/// bounded Clock/Calendar face-source redirects. No one-shot view paint is
/// used; the redirects remain active for the current SpringBoard process.
+ (NSDictionary<NSString *, id> *)applySpringBoardTweaks;
/// Independent Spotlight transparency and Clock/Calendar source repair for
/// the current Spotlight process.
+ (NSDictionary<NSString *, id> *)repairSpotlightPresentation;
/// Target-state read-only applied-state audit. Compares every journaled
/// IconServices descriptor cache/store record with its themed hash, including
/// Home, folder-preview, switcher, App Library, notification, and transition
/// descriptors, then snapshots SpringBoard's canonical, live-leaf, and
/// materialized switcher identities. A successful run atomically stores only
/// a local rolling diagnostic baseline in Application Support; the next run
/// compares UUIDs, validation tokens, and hashes before advancing it. No
/// IconServices/SpringBoard publication, restore, invalidation, purge, reload,
/// relayout, or presentation change is performed.
+ (NSDictionary<NSString *, id> *)auditAppliedIconState;
+ (NSArray<NSDictionary<NSString *, id> *> *)applicationStatuses;
/// Returns the last exact status snapshot without doing catalog or hash I/O.
/// The first caller should request a background refresh; an empty array means
/// that no snapshot has been published in this process yet.
+ (NSArray<NSDictionary<NSString *, id> *> *)cachedApplicationStatuses;
/// Drops the published UI snapshot. It does not alter any journal or target
/// file; the next background refresh repopulates it from exact state.
+ (void)invalidateCachedApplicationStatuses;
/// Performs one exact catalog walk and all journal hash checks on a utility
/// queue, then invokes completion on the main queue. Concurrent requests are
/// coalesced so navigation/reloads cannot start duplicate scans.
+ (void)refreshApplicationStatusesInBackgroundWithCompletion:
    (nullable CNDSnowBoardRemixStatusesCompletion)completion;
+ (BOOL)hasRecoveryData;

@end

NS_ASSUME_NONNULL_END
