#import "CNDQueueExecutionSnapshot.h"

NSString *CNDQueueExecutionPhaseName(CNDQueueExecutionPhase phase)
{
    switch (phase) {
        case CNDQueueExecutionPhaseEmpty: return @"empty";
        case CNDQueueExecutionPhaseCollecting: return @"collecting";
        case CNDQueueExecutionPhaseRunning: return @"running";
        case CNDQueueExecutionPhaseWaitingForSettings:
            return @"waiting-for-settings";
        case CNDQueueExecutionPhaseAwaitingRespring:
            return @"awaiting-respring";
        case CNDQueueExecutionPhaseReadyAfterRespring:
            return @"ready-after-respring";
        case CNDQueueExecutionPhaseRetryable: return @"retryable";
        case CNDQueueExecutionPhaseCompleted: return @"completed";
        case CNDQueueExecutionPhaseUnreadable: return @"unreadable";
    }
    return @"unknown";
}

NSString *CNDQueuePrimaryActionName(CNDQueuePrimaryAction action)
{
    switch (action) {
        case CNDQueuePrimaryActionNone: return @"none";
        case CNDQueuePrimaryActionConfirm: return @"confirm";
        case CNDQueuePrimaryActionContinueAfterRespring:
            return @"continue-after-respring";
        case CNDQueuePrimaryActionRetry: return @"retry";
        case CNDQueuePrimaryActionWait: return @"wait";
        case CNDQueuePrimaryActionRespring: return @"respring";
    }
    return @"unknown";
}

static NSString *CNDQueueChangeCountString(NSInteger count)
{
    return count == 1
        ? @"1 pending change"
        : [NSString stringWithFormat:@"%ld pending changes", (long)count];
}

static NSString *CNDQueueCommitCountString(NSInteger count)
{
    return count == 1
        ? @"Confirm 1 Change"
        : [NSString stringWithFormat:@"Confirm %ld Changes", (long)count];
}

@interface CNDQueueExecutionSnapshot ()
@property (nonatomic, readwrite, assign) CNDQueueExecutionPhase phase;
@property (nonatomic, readwrite, copy) NSString *reason;
@property (nonatomic, readwrite, assign) CNDQueuePrimaryAction primaryAction;
@property (nonatomic, readwrite, copy) NSString *title;
@property (nonatomic, readwrite, copy) NSString *detail;
@property (nonatomic, readwrite, copy) NSString *recoveryGuidance;
@property (nonatomic, readwrite, assign) NSInteger pendingActionCount;
@property (nonatomic, readwrite, assign) NSInteger legacyPendingCount;
@property (nonatomic, readwrite, assign) NSInteger installCount;
@property (nonatomic, readwrite, assign) NSInteger uninstallCount;
@property (nonatomic, readwrite, assign) NSInteger standaloneActionCount;
@property (nonatomic, readwrite, assign) NSInteger completedActionCount;
@property (nonatomic, readwrite, assign) NSInteger failedActionCount;
@property (nonatomic, readwrite, assign) NSInteger remainingAfterRespringCount;
@property (nonatomic, readwrite, assign) BOOL showsContinuation;
@property (nonatomic, readwrite, assign) BOOL requiresRespring;
@property (nonatomic, readwrite, assign) BOOL restartBoundaryObserved;
@property (nonatomic, readwrite, assign) BOOL executionStarted;
@property (nonatomic, readwrite, assign) BOOL durableStoreUnavailable;
@property (nonatomic, readwrite, copy, nullable) NSString *transactionIdentifier;
@property (nonatomic, readwrite, copy, nullable) NSString *lastError;
@property (nonatomic, readwrite, assign) BOOL canCommit;
@property (nonatomic, readwrite, assign) BOOL canEdit;
@property (nonatomic, readwrite, assign) BOOL canClear;
@property (nonatomic, readwrite, copy) NSString *commitTitle;
@property (nonatomic, readwrite, copy) NSString *popupTitle;
@property (nonatomic, readwrite, copy) NSString *popupSubtitle;
@property (nonatomic, readwrite, copy) NSString *activityStatus;
@end

@implementation CNDQueueExecutionSnapshot

- (id)copyWithZone:(NSZone *)zone
{
    return self;
}

- (NSString *)phaseName
{
    return CNDQueueExecutionPhaseName(self.phase);
}

- (NSString *)primaryActionName
{
    return CNDQueuePrimaryActionName(self.primaryAction);
}

- (instancetype)initWithTransaction:(CNDQueuedTransaction *)transaction
                    commitInFlight:(BOOL)commitInFlight
       waitingForSettingsCompletion:(BOOL)waitingForSettingsCompletion
waitingForCoordinatedSettingsCompletion:(BOOL)waitingForCoordinatedSettingsCompletion
resumeCoordinatorBeforeRespringAfterSettings:(BOOL)resumeBeforeRespring
              restartBoundaryObserved:(BOOL)restartBoundaryObserved
            durableStoreUnavailable:(BOOL)durableStoreUnavailable
{
    if ((self = [super init])) {
        _durableStoreUnavailable = durableStoreUnavailable;
        _restartBoundaryObserved = restartBoundaryObserved;
        _transactionIdentifier = [transaction.transactionIdentifier copy];
        _lastError = [transaction.lastError copy];
        _executionStarted = transaction &&
            transaction.state != CNDQueuedTransactionStateCollecting;
        _requiresRespring = transaction.preRespringSpringBoardPID > 1 ||
            transaction.state == CNDQueuedTransactionStateAwaitingRespring ||
            transaction.state == CNDQueuedTransactionStateReadyAfterRespring ||
            transaction.state == CNDQueuedTransactionStateRunningAfterRespring;

        for (CNDQueuedAction *action in transaction.actions) {
            if (action.phase != CNDQueuedActionPhaseAutomatic) {
                _requiresRespring = YES;
            }
            if (action.state == CNDQueuedActionStateSucceeded) {
                _completedActionCount++;
                continue;
            }
            _pendingActionCount++;
            if (action.state == CNDQueuedActionStateFailed) {
                _failedActionCount++;
            }
            if ([action.kind isEqualToString:@"package"]) {
                if ([action.operation isEqualToString:@"install"]) {
                    _installCount++;
                } else if ([action.operation isEqualToString:@"uninstall"]) {
                    _uninstallCount++;
                }
            } else {
                _standaloneActionCount++;
            }
            if (action.phase == CNDQueuedActionPhaseAfterRespring ||
                (action.phase == CNDQueuedActionPhaseAutomatic &&
                 _requiresRespring)) {
                _remainingAfterRespringCount++;
            }
        }

        BOOL continuation = transaction.preRespringSpringBoardPID > 1 &&
            transaction.state != CNDQueuedTransactionStateCompleted &&
            transaction.state != CNDQueuedTransactionStateCollecting;
        _showsContinuation = continuation;
        _legacyPendingCount = _pendingActionCount;
        if (_legacyPendingCount == 0 && (continuation || durableStoreUnavailable)) {
            _legacyPendingCount = 1;
        }

        _canEdit = !commitInFlight && !durableStoreUnavailable &&
            (!transaction || transaction.state == CNDQueuedTransactionStateCollecting);
        _canClear = !commitInFlight && !durableStoreUnavailable &&
            _legacyPendingCount > 0;
        BOOL canResumeContinuation = !commitInFlight &&
            !durableStoreUnavailable && continuation &&
            _remainingAfterRespringCount > 0 &&
            transaction.state != CNDQueuedTransactionStateCompleted;
        _canCommit = !commitInFlight && !durableStoreUnavailable &&
            (_pendingActionCount > 0 || canResumeContinuation) &&
            transaction.state != CNDQueuedTransactionStateCompleted;
        _primaryAction = CNDQueuePrimaryActionNone;
        if (durableStoreUnavailable) {
            _phase = CNDQueueExecutionPhaseUnreadable;
            _reason = @"durable-store-unavailable";
            _title = @"Saved Queue Needs Attention";
            _detail = @"Cyanide left the saved queue untouched because it could not be read safely.";
            _recoveryGuidance = @"Preserve the queue file for diagnosis before trying another change.";
            _activityStatus = @"Saved queue unavailable — no changes were started.";
            _popupTitle = @"Queue needs attention";
            _popupSubtitle = @"Saved state was left untouched";
            _commitTitle = @"Confirm";
        } else if (commitInFlight &&
                   (waitingForSettingsCompletion ||
                    waitingForCoordinatedSettingsCompletion)) {
            _phase = CNDQueueExecutionPhaseWaitingForSettings;
            _primaryAction = CNDQueuePrimaryActionWait;
            if (waitingForCoordinatedSettingsCompletion) {
                _reason = resumeBeforeRespring
                    ? @"coordinated-settings-before-respring"
                    : @"coordinated-settings-after-respring";
                _title = resumeBeforeRespring
                    ? @"Applying Changes Before Respring"
                    : @"Applying Changes After Respring";
                _detail = @"The saved queue is waiting for its token-matched runtime completion.";
            } else {
                _reason = @"ordinary-settings-completion";
                _title = @"Applying Queued Changes";
                _detail = @"The queue is waiting for the current settings run to finish.";
            }
            _recoveryGuidance = @"Keep Cyanide open until this step completes.";
            _activityStatus = @"Running — waiting for queued runtime changes.";
            _commitTitle = @"Applying…";
        } else if (commitInFlight) {
            _phase = CNDQueueExecutionPhaseRunning;
            _primaryAction = CNDQueuePrimaryActionWait;
            switch (transaction.state) {
                case CNDQueuedTransactionStateRunningAfterRespring:
                    _reason = @"after-respring-work";
                    _title = @"Finishing After Respring";
                    break;
                case CNDQueuedTransactionStateReadyAfterRespring:
                    _reason = @"verifying-respring-boundary";
                    _title = @"Verifying Respring";
                    break;
                case CNDQueuedTransactionStateAwaitingRespring:
                    _reason = @"preparing-respring-continuation";
                    _title = @"Preparing Respring";
                    break;
                default:
                    _reason = @"synchronous-work";
                    _title = @"Applying Queued Changes";
                    break;
            }
            _detail = @"Durable checkpoints are updated around each queued action.";
            _recoveryGuidance = @"Stay on Activity until the queue reaches a saved stopping point.";
            _activityStatus = @"Running — stay here until complete.";
            _commitTitle = @"Applying…";
        } else if (!transaction) {
            _phase = CNDQueueExecutionPhaseEmpty;
            _reason = @"no-saved-transaction";
            _title = @"No Pending Changes";
            _detail = @"Queue packages or system actions to begin.";
            _recoveryGuidance = @"";
            _activityStatus = @"No queued changes.";
            _commitTitle = @"Confirm";
        } else {
            switch (transaction.state) {
                case CNDQueuedTransactionStateCollecting:
                    _phase = CNDQueueExecutionPhaseCollecting;
                    _reason = @"awaiting-confirmation";
                    _title = CNDQueueChangeCountString(_pendingActionCount).capitalizedString;
                    _detail = @"Review the saved plan, then confirm when ready.";
                    _primaryAction = CNDQueuePrimaryActionConfirm;
                    _commitTitle = _canCommit
                        ? CNDQueueCommitCountString(_pendingActionCount) : @"Confirm";
                    _activityStatus = @"Ready to apply the saved queue.";
                    break;
                case CNDQueuedTransactionStateAwaitingRespring:
                    if (restartBoundaryObserved) {
                        _phase = CNDQueueExecutionPhaseReadyAfterRespring;
                        _reason = @"restart-boundary-observed";
                        _title = @"Continue After Respring";
                        _detail = @"SpringBoard restarted. The saved queue is ready to verify the new process and finish its remaining work.";
                        _primaryAction = CNDQueuePrimaryActionContinueAfterRespring;
                        _commitTitle = @"Continue After Respring";
                        _activityStatus = @"Ready to continue the saved queue.";
                        _recoveryGuidance = @"Continue to verify the new SpringBoard identity and run only unfinished actions.";
                    } else {
                        _phase = CNDQueueExecutionPhaseAwaitingRespring;
                        _reason = @"pre-respring-checkpoint-saved";
                        _title = @"Respring Required";
                        _detail = @"Pre-respring changes are saved. Respring before continuing the remaining work.";
                        _primaryAction = CNDQueuePrimaryActionRespring;
                        _commitTitle = @"Continue After Respring";
                        _activityStatus = @"Pre-respring changes saved. Respring to continue.";
                    }
                    break;
                case CNDQueuedTransactionStateReadyAfterRespring:
                    _phase = CNDQueueExecutionPhaseReadyAfterRespring;
                    _reason = @"restart-boundary-ready";
                    _title = @"Continue After Respring";
                    _detail = @"The saved queue is ready to verify the restart and finish its remaining work.";
                    _primaryAction = CNDQueuePrimaryActionContinueAfterRespring;
                    _commitTitle = @"Continue After Respring";
                    _activityStatus = @"Ready to continue the saved queue.";
                    break;
                case CNDQueuedTransactionStateCompleted:
                    _phase = CNDQueueExecutionPhaseCompleted;
                    _reason = transaction.lastError.length > 0
                        ? @"completion-cleanup-unresolved" : @"completed";
                    _title = transaction.lastError.length > 0
                        ? @"Completion Needs Attention" : @"Queue Complete";
                    _detail = transaction.lastError.length > 0
                        ? transaction.lastError : @"Every queued action has a successful checkpoint.";
                    _primaryAction = CNDQueuePrimaryActionNone;
                    _commitTitle = @"Completed";
                    _activityStatus = @"Queued changes completed.";
                    break;
                case CNDQueuedTransactionStateFailed:
                    _phase = CNDQueueExecutionPhaseRetryable;
                    _reason = continuation
                        ? @"continuation-retryable" : @"execution-failed";
                    _title = continuation ? @"Continue Saved Queue" : @"Queue Ready to Retry";
                    _detail = transaction.lastError.length > 0
                        ? transaction.lastError
                        : @"The saved queue stopped before every action completed.";
                    _primaryAction = continuation
                        ? CNDQueuePrimaryActionContinueAfterRespring
                        : CNDQueuePrimaryActionRetry;
                    _commitTitle = continuation ? @"Continue After Respring" : @"Retry Saved Queue";
                    _activityStatus = @"Stopped — the unfinished saved queue can be retried.";
                    break;
                case CNDQueuedTransactionStateRunningBeforeRespring:
                case CNDQueuedTransactionStateRunningAfterRespring:
                    /* A live Running state is handled by commitInFlight above.
                     * Reaching this branch means execution stopped without a
                     * terminal checkpoint, so expose a conservative retry. */
                    _phase = CNDQueueExecutionPhaseRetryable;
                    _reason = @"interrupted-execution";
                    _title = @"Saved Queue Needs Review";
                    _detail = transaction.lastError.length > 0
                        ? transaction.lastError
                        : @"Execution is no longer active. Review the saved checkpoints before retrying unfinished work.";
                    _primaryAction = continuation
                        ? CNDQueuePrimaryActionContinueAfterRespring
                        : CNDQueuePrimaryActionRetry;
                    _commitTitle = continuation ? @"Continue After Respring" : @"Retry Saved Queue";
                    _activityStatus = @"Stopped — review the saved queue before retrying.";
                    break;
            }
            if (_recoveryGuidance.length == 0) {
                if (_phase == CNDQueueExecutionPhaseAwaitingRespring) {
                    _recoveryGuidance = @"Use Activity to respring. Afterward, reopen Cyanide and continue the saved queue.";
                } else if (_canCommit && continuation) {
                    _recoveryGuidance = @"Continue only after SpringBoard has restarted; completed actions will not be replayed.";
                } else if (_canCommit) {
                    _recoveryGuidance = @"Retry runs only unfinished actions; successful checkpoints are preserved.";
                } else {
                    _recoveryGuidance = @"Review the saved queue and diagnostic log before making another change.";
                }
            }
        }

        if (_popupTitle.length == 0) {
            _popupTitle = _showsContinuation && !_canCommit && !commitInFlight
                ? _title : CNDQueueChangeCountString(_legacyPendingCount);
        }
        if (_popupSubtitle.length == 0) {
            if (_showsContinuation && !commitInFlight &&
                _primaryAction != CNDQueuePrimaryActionConfirm) {
                _popupSubtitle = _primaryAction == CNDQueuePrimaryActionRespring
                    ? @"Respring to finish saved work"
                    : _recoveryGuidance;
            } else {
                NSMutableArray<NSString *> *parts = [NSMutableArray array];
                if (_installCount > 0) {
                    [parts addObject:[NSString stringWithFormat:
                        @"%ld activate", (long)_installCount]];
                }
                if (_uninstallCount > 0) {
                    [parts addObject:[NSString stringWithFormat:
                        @"%ld deactivate", (long)_uninstallCount]];
                }
                if (_standaloneActionCount > 0) {
                    [parts addObject:[NSString stringWithFormat:
                        @"%ld system action%@", (long)_standaloneActionCount,
                        _standaloneActionCount == 1 ? @"" : @"s"]];
                }
                if (_showsContinuation && _remainingAfterRespringCount > 0) {
                    [parts addObject:@"after respring"];
                }
                _popupSubtitle = [parts componentsJoinedByString:@" · "];
            }
        }
    }
    return self;
}

- (NSString *)accessibilitySummary
{
    NSMutableString *summary = [NSMutableString stringWithString:self.title];
    if (self.detail.length > 0) {
        [summary appendFormat:@". %@", self.detail];
    }
    if (self.recoveryGuidance.length > 0) {
        [summary appendFormat:@" %@", self.recoveryGuidance];
    }
    return summary;
}

- (NSDictionary<NSString *, id> *)agentRepresentation
{
    return @{
        @"schemaVersion": @1,
        @"phase": self.phaseName,
        @"reason": self.reason,
        @"primaryAction": self.primaryActionName,
        @"title": self.title,
        @"detail": self.detail,
        @"recoveryGuidance": self.recoveryGuidance,
        @"pendingActionCount": @(self.pendingActionCount),
        @"legacyPendingCount": @(self.legacyPendingCount),
        @"installCount": @(self.installCount),
        @"uninstallCount": @(self.uninstallCount),
        @"standaloneActionCount": @(self.standaloneActionCount),
        @"completedActionCount": @(self.completedActionCount),
        @"failedActionCount": @(self.failedActionCount),
        @"remainingAfterRespringCount": @(self.remainingAfterRespringCount),
        @"showsContinuation": @(self.showsContinuation),
        @"requiresRespring": @(self.requiresRespring),
        @"restartBoundaryObserved": @(self.restartBoundaryObserved),
        @"executionStarted": @(self.executionStarted),
        @"durableStoreUnavailable": @(self.durableStoreUnavailable),
        @"transactionIdentifier": self.transactionIdentifier ?: @"",
        @"lastError": self.lastError ?: @"",
        @"canCommit": @(self.canCommit),
        @"canEdit": @(self.canEdit),
        @"canClear": @(self.canClear),
        @"commitTitle": self.commitTitle,
        @"activityStatus": self.activityStatus,
    };
}

@end
