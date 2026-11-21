#import <Foundation/Foundation.h>

#import "CNDQueuedTransaction.h"

NS_ASSUME_NONNULL_BEGIN

/// Stable presentation phases. These describe what the user can do next; they
/// do not replace the durable transaction state or the queue's callback guards.
typedef NS_ENUM(NSInteger, CNDQueueExecutionPhase) {
    CNDQueueExecutionPhaseEmpty = 0,
    CNDQueueExecutionPhaseCollecting,
    CNDQueueExecutionPhaseRunning,
    CNDQueueExecutionPhaseWaitingForSettings,
    CNDQueueExecutionPhaseAwaitingRespring,
    CNDQueueExecutionPhaseReadyAfterRespring,
    CNDQueueExecutionPhaseRetryable,
    CNDQueueExecutionPhaseCompleted,
    CNDQueueExecutionPhaseUnreadable,
};

typedef NS_ENUM(NSInteger, CNDQueuePrimaryAction) {
    CNDQueuePrimaryActionNone = 0,
    CNDQueuePrimaryActionConfirm,
    CNDQueuePrimaryActionContinueAfterRespring,
    CNDQueuePrimaryActionRetry,
    CNDQueuePrimaryActionWait,
    CNDQueuePrimaryActionRespring,
};

FOUNDATION_EXPORT NSString *CNDQueueExecutionPhaseName(
    CNDQueueExecutionPhase phase);
FOUNDATION_EXPORT NSString *CNDQueuePrimaryActionName(
    CNDQueuePrimaryAction action);

/// Immutable, read-only projection of PackageQueue's durable and process-local
/// lifecycle. `agentRepresentation` contains only plist values, making the same
/// state available to UI clients, diagnostics, and automation without a second
/// mutable store.
@interface CNDQueueExecutionSnapshot : NSObject <NSCopying>

@property (nonatomic, readonly, assign) CNDQueueExecutionPhase phase;
@property (nonatomic, readonly, copy) NSString *phaseName;
@property (nonatomic, readonly, copy) NSString *reason;
@property (nonatomic, readonly, assign) CNDQueuePrimaryAction primaryAction;
@property (nonatomic, readonly, copy) NSString *primaryActionName;
@property (nonatomic, readonly, copy) NSString *title;
@property (nonatomic, readonly, copy) NSString *detail;
@property (nonatomic, readonly, copy) NSString *recoveryGuidance;
@property (nonatomic, readonly, copy) NSString *accessibilitySummary;

/// pendingActionCount counts unfinished records. legacyPendingCount preserves
/// the existing popup/inset API, including its one-step continuation sentinel.
@property (nonatomic, readonly, assign) NSInteger pendingActionCount;
@property (nonatomic, readonly, assign) NSInteger legacyPendingCount;
@property (nonatomic, readonly, assign) NSInteger installCount;
@property (nonatomic, readonly, assign) NSInteger uninstallCount;
@property (nonatomic, readonly, assign) NSInteger standaloneActionCount;
@property (nonatomic, readonly, assign) NSInteger completedActionCount;
@property (nonatomic, readonly, assign) NSInteger failedActionCount;
@property (nonatomic, readonly, assign) NSInteger remainingAfterRespringCount;
@property (nonatomic, readonly, assign) BOOL showsContinuation;
@property (nonatomic, readonly, assign) BOOL requiresRespring;
/// A presentation hint that the saved SpringBoard/boot boundary is no longer
/// current. Execution still performs its authoritative identity verification.
@property (nonatomic, readonly, assign) BOOL restartBoundaryObserved;
@property (nonatomic, readonly, assign) BOOL executionStarted;
@property (nonatomic, readonly, assign) BOOL durableStoreUnavailable;
@property (nonatomic, readonly, copy, nullable) NSString *transactionIdentifier;
@property (nonatomic, readonly, copy, nullable) NSString *lastError;

@property (nonatomic, readonly, assign) BOOL canCommit;
@property (nonatomic, readonly, assign) BOOL canEdit;
@property (nonatomic, readonly, assign) BOOL canClear;
@property (nonatomic, readonly, copy) NSString *commitTitle;
@property (nonatomic, readonly, copy) NSString *popupTitle;
@property (nonatomic, readonly, copy) NSString *popupSubtitle;
@property (nonatomic, readonly, copy) NSString *activityStatus;

- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithTransaction:(nullable CNDQueuedTransaction *)transaction
                    commitInFlight:(BOOL)commitInFlight
       waitingForSettingsCompletion:(BOOL)waitingForSettingsCompletion
waitingForCoordinatedSettingsCompletion:(BOOL)waitingForCoordinatedSettingsCompletion
resumeCoordinatorBeforeRespringAfterSettings:(BOOL)resumeBeforeRespring
              restartBoundaryObserved:(BOOL)restartBoundaryObserved
            durableStoreUnavailable:(BOOL)durableStoreUnavailable
    NS_DESIGNATED_INITIALIZER;

- (NSDictionary<NSString *, id> *)agentRepresentation;

@end

NS_ASSUME_NONNULL_END
