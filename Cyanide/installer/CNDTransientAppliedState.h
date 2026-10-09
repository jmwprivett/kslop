#import <Foundation/Foundation.h>
#import <sys/types.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString * const CNDTransientAppliedStateSnowBoardRemix;
FOUNDATION_EXPORT NSString * const CNDTransientAppliedStateFontChanger;
FOUNDATION_EXPORT NSString * const CNDTransientAppliedStateSBCustomizer;
FOUNDATION_EXPORT NSString * const CNDTransientAppliedStateSpringBoardFixes;
FOUNDATION_EXPORT NSString * const CNDTransientAppliedStateSpotlightFixes;

/// Returns the disk-cached state for the current boot so it survives an
/// ordinary Cyanide exit. This UI query never performs KRW work. A full boot
/// mismatch is rejected immediately; exact SpringBoard identity is reconciled
/// separately whenever KRW is successfully established.
FOUNDATION_EXPORT BOOL CNDTransientAppliedStateIsActive(NSString *stateKey);

/// Records a one-shot tweak against the currently verified SpringBoard when
/// no coordinator-owned respring is involved. Existing current-epoch state is
/// preserved. A pending process transition or an unverifiable PID fails
/// closed.
FOUNDATION_EXPORT BOOL CNDTransientAppliedStateSetActiveForCurrentEpoch(
    NSString *stateKey,
    BOOL active);

/// Revalidates the durable marker against the current boot and, when KRW is
/// available, the exact SpringBoard PID. Returns YES only when persisted state
/// changed (normally because a stale epoch was cleared).
FOUNDATION_EXPORT BOOL CNDTransientAppliedStateReconcileCurrentEpoch(void);

/// Clears process-bound ACTIVE markers when the prior parked KRW generation
/// cannot be recovered. SnowBoard is retained because its persistent records
/// outlive KRW and process epochs; only a successful manual Restore clears it.
/// A newly acquired primitive must still start a fresh process-state epoch.
FOUNDATION_EXPORT BOOL CNDTransientAppliedStateResetAfterKRWLoss(void);

/// Arms exactly one coordinator-owned SpringBoard transition. Existing active
/// bits remain attached to `fromPID` until Finalize commits the new PID.
FOUNDATION_EXPORT BOOL CNDTransientAppliedStatePrepareTransition(
    NSString *transactionIdentifier,
    pid_t fromPID,
    NSTimeInterval bootEpoch);

/// Completes a coordinator transaction that has no after-respring actions.
/// The requested persistent states are committed before the respring, while
/// one bounded marker authorizes the next SpringBoard PID to adopt them when
/// KRW is next available. SBCustomizer is always cleared because its mutation
/// is process-local and this transaction has no post-respring reapply step.
FOUNDATION_EXPORT BOOL CNDTransientAppliedStatePrepareBoundaryOnlyTransition(
    NSString *transactionIdentifier,
    pid_t fromPID,
    NSTimeInterval bootEpoch,
    NSString *krwGenerationIdentifier,
    NSNumber * _Nullable snowBoardActive,
    NSNumber * _Nullable fontChangerActive);

/// Cancels only the matching unconsumed transition marker.
FOUNDATION_EXPORT void CNDTransientAppliedStateCancelPreparedTransition(
    NSString *transactionIdentifier);

/// Commits the coordinator-owned PID transition and optional state deltas.
/// Passing nil preserves that state; @YES/@NO records Apply/Restore.
FOUNDATION_EXPORT BOOL CNDTransientAppliedStateFinalizeTransition(
    NSString *transactionIdentifier,
    pid_t fromPID,
    pid_t toPID,
    NSTimeInterval bootEpoch,
    NSString *krwGenerationIdentifier,
    NSNumber * _Nullable snowBoardActive,
    NSNumber * _Nullable fontChangerActive,
    NSNumber * _Nullable sbCustomizerActive);

NS_ASSUME_NONNULL_END
