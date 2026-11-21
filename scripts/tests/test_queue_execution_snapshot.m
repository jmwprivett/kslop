#import <Foundation/Foundation.h>
#import "../../Cyanide/installer/CNDQueueExecutionSnapshot.h"

static void Check(BOOL condition, NSString *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message.UTF8String);
        exit(1);
    }
}

static CNDQueuedAction *Action(NSString *identifier,
                               NSString *kind,
                               NSString *operation,
                               CNDQueuedActionPhase phase,
                               CNDQueuedActionState state)
{
    NSDate *now = [NSDate dateWithTimeIntervalSince1970:1234];
    return [[CNDQueuedAction alloc] initWithRecordIdentifier:identifier
        kind:kind subjectIdentifier:identifier operation:operation phase:phase
        state:state parameters:@{} createdAt:now updatedAt:now lastError:nil];
}

static CNDQueuedTransaction *Transaction(CNDQueuedTransactionState state,
                                         NSArray<CNDQueuedAction *> *actions,
                                         pid_t oldPID,
                                         NSString *error)
{
    return [[CNDQueuedTransaction alloc] initWithSchemaVersion:1
        transactionIdentifier:@"transaction-fixture" state:state actions:actions
        createdAt:[NSDate dateWithTimeIntervalSince1970:1234]
        updatedAt:[NSDate dateWithTimeIntervalSince1970:1235]
        preRespringSpringBoardPID:oldPID bootEpoch:100
        krwGenerationIdentifier:oldPID > 1 ? @"generation" : @"" lastError:error];
}

static CNDQueueExecutionSnapshot *Snapshot(CNDQueuedTransaction *transaction,
                                           BOOL running,
                                           BOOL ordinaryWait,
                                           BOOL coordinatedWait,
                                           BOOL resumeBefore,
                                           BOOL unreadable)
{
    return [[CNDQueueExecutionSnapshot alloc] initWithTransaction:transaction
        commitInFlight:running waitingForSettingsCompletion:ordinaryWait
        waitingForCoordinatedSettingsCompletion:coordinatedWait
        resumeCoordinatorBeforeRespringAfterSettings:resumeBefore
        restartBoundaryObserved:NO
        durableStoreUnavailable:unreadable];
}

static CNDQueueExecutionSnapshot *SnapshotAfterRestart(
    CNDQueuedTransaction *transaction)
{
    return [[CNDQueueExecutionSnapshot alloc] initWithTransaction:transaction
        commitInFlight:NO waitingForSettingsCompletion:NO
        waitingForCoordinatedSettingsCompletion:NO
        resumeCoordinatorBeforeRespringAfterSettings:NO
        restartBoundaryObserved:YES durableStoreUnavailable:NO];
}

static void CheckPhase(CNDQueueExecutionSnapshot *snapshot,
                       CNDQueueExecutionPhase phase,
                       NSString *reason,
                       CNDQueuePrimaryAction action)
{
    Check(snapshot.phase == phase, snapshot.phaseName);
    Check([snapshot.reason isEqualToString:reason],
          [NSString stringWithFormat:@"reason=%@", snapshot.reason]);
    Check(snapshot.primaryAction == action, snapshot.primaryActionName);
    Check(snapshot.agentRepresentation.count >= 20,
          @"agent projection includes the lifecycle and controls");
    Check([snapshot.agentRepresentation[@"phase"] isEqual:snapshot.phaseName] &&
          [snapshot.agentRepresentation[@"reason"] isEqual:snapshot.reason] &&
          [snapshot.agentRepresentation[@"primaryAction"]
              isEqual:snapshot.primaryActionName],
          @"typed and agent-facing names agree");
}

int main(void)
{
    @autoreleasepool {
        CNDQueuedAction *package = Action(@"package-one", @"package", @"install",
            CNDQueuedActionPhaseAutomatic, CNDQueuedActionStatePending);
        CNDQueueExecutionSnapshot *empty = Snapshot(nil, NO, NO, NO, NO, NO);
        CheckPhase(empty, CNDQueueExecutionPhaseEmpty, @"no-saved-transaction",
                   CNDQueuePrimaryActionNone);
        Check(!empty.canCommit && empty.canEdit && !empty.canClear &&
              empty.legacyPendingCount == 0, @"empty queue controls");

        CNDQueuedTransaction *collecting = Transaction(
            CNDQueuedTransactionStateCollecting, @[package], 0, nil);
        CNDQueueExecutionSnapshot *review = Snapshot(collecting, NO, NO, NO, NO, NO);
        CheckPhase(review, CNDQueueExecutionPhaseCollecting, @"awaiting-confirmation",
                   CNDQueuePrimaryActionConfirm);
        Check(review.canCommit && review.canEdit && review.canClear &&
              review.pendingActionCount == 1 && review.legacyPendingCount == 1,
              @"collecting queue is editable and committable");
        Check([review.popupSubtitle isEqual:@"1 activate"],
              @"popup keeps package category wording");

        CNDQueuedTransaction *running = Transaction(
            CNDQueuedTransactionStateRunningBeforeRespring, @[package], 0, nil);
        CNDQueueExecutionSnapshot *work = Snapshot(running, YES, NO, NO, NO, NO);
        CheckPhase(work, CNDQueueExecutionPhaseRunning, @"synchronous-work",
                   CNDQueuePrimaryActionWait);
        Check(!work.canCommit && !work.canEdit && !work.canClear,
              @"running work rejects duplicate commit, editing, and clear");

        CNDQueueExecutionSnapshot *ordinary = Snapshot(running, YES, YES, NO, NO, NO);
        CheckPhase(ordinary, CNDQueueExecutionPhaseWaitingForSettings,
                   @"ordinary-settings-completion", CNDQueuePrimaryActionWait);
        CNDQueueExecutionSnapshot *before = Snapshot(running, YES, NO, YES, YES, NO);
        CheckPhase(before, CNDQueueExecutionPhaseWaitingForSettings,
                   @"coordinated-settings-before-respring", CNDQueuePrimaryActionWait);
        CNDQueuedTransaction *runningAfter = Transaction(
            CNDQueuedTransactionStateRunningAfterRespring, @[package], 42, nil);
        CNDQueueExecutionSnapshot *after = Snapshot(runningAfter, YES, NO, YES, NO, NO);
        CheckPhase(after, CNDQueueExecutionPhaseWaitingForSettings,
                   @"coordinated-settings-after-respring", CNDQueuePrimaryActionWait);

        CNDQueuedAction *post = Action(@"package-post", @"package", @"install",
            CNDQueuedActionPhaseAfterRespring, CNDQueuedActionStatePending);
        CNDQueuedTransaction *awaiting = Transaction(
            CNDQueuedTransactionStateAwaitingRespring, @[post], 42, nil);
        CNDQueueExecutionSnapshot *boundary = Snapshot(awaiting, NO, NO, NO, NO, NO);
        CheckPhase(boundary, CNDQueueExecutionPhaseAwaitingRespring,
                   @"pre-respring-checkpoint-saved", CNDQueuePrimaryActionRespring);
        Check(boundary.canCommit && boundary.canClear && !boundary.canEdit &&
              boundary.showsContinuation && boundary.remainingAfterRespringCount == 1,
              @"saved boundary asks for respring, not premature continuation");
        Check([boundary.popupSubtitle isEqual:@"Respring to finish saved work"],
              @"boundary popup names the next action");

        CNDQueueExecutionSnapshot *observedBoundary =
            SnapshotAfterRestart(awaiting);
        CheckPhase(observedBoundary,
                   CNDQueueExecutionPhaseReadyAfterRespring,
                   @"restart-boundary-observed",
                   CNDQueuePrimaryActionContinueAfterRespring);
        Check(observedBoundary.canCommit &&
              observedBoundary.restartBoundaryObserved &&
              [observedBoundary.commitTitle isEqual:@"Continue After Respring"],
              @"observed restart continues instead of requesting another respring");

        CNDQueuedAction *done = Action(@"package-done", @"package", @"install",
            CNDQueuedActionPhaseAfterRespring, CNDQueuedActionStateSucceeded);
        CNDQueuedTransaction *ready = Transaction(
            CNDQueuedTransactionStateReadyAfterRespring, @[done, post], 42, nil);
        CNDQueueExecutionSnapshot *continuation = Snapshot(ready, NO, NO, NO, NO, NO);
        CheckPhase(continuation, CNDQueueExecutionPhaseReadyAfterRespring,
                   @"restart-boundary-ready", CNDQueuePrimaryActionContinueAfterRespring);
        Check(continuation.canCommit && continuation.pendingActionCount == 1 &&
              continuation.completedActionCount == 1,
              @"continuation retains successful checkpoints");

        CNDQueuedTransaction *zeroAction = Transaction(
            CNDQueuedTransactionStateAwaitingRespring, @[], 42, nil);
        CNDQueueExecutionSnapshot *sentinel = Snapshot(zeroAction, NO, NO, NO, NO, NO);
        Check(sentinel.pendingActionCount == 0 && sentinel.legacyPendingCount == 1 &&
              sentinel.popupSubtitle.length > 0 &&
              ![sentinel.popupSubtitle containsString:@"pending"],
              @"legacy continuation sentinel gets actionable wording, not a blank subtitle");

        CNDQueuedTransaction *failed = Transaction(CNDQueuedTransactionStateFailed,
            @[package], 0, @"Synthetic failure");
        CNDQueueExecutionSnapshot *retry = Snapshot(failed, NO, NO, NO, NO, NO);
        CheckPhase(retry, CNDQueueExecutionPhaseRetryable, @"execution-failed",
                   CNDQueuePrimaryActionRetry);
        Check(retry.canCommit && retry.canClear && !retry.canEdit &&
              [retry.detail isEqual:@"Synthetic failure"],
              @"failed queue preserves its error and retry/clear controls");

        CNDQueueExecutionSnapshot *interrupted = Snapshot(running, NO, NO, NO, NO, NO);
        CheckPhase(interrupted, CNDQueueExecutionPhaseRetryable,
                   @"interrupted-execution", CNDQueuePrimaryActionRetry);
        Check(interrupted.canCommit, @"inactive running state is not presented as live");

        CNDQueueExecutionSnapshot *unreadable = Snapshot(nil, NO, NO, NO, NO, YES);
        CheckPhase(unreadable, CNDQueueExecutionPhaseUnreadable,
                   @"durable-store-unavailable", CNDQueuePrimaryActionNone);
        Check(!unreadable.canCommit && !unreadable.canEdit && !unreadable.canClear &&
              unreadable.legacyPendingCount == 1,
              @"unreadable durable state fails closed but remains visible");

        CNDQueueExecutionSnapshot *completed = Snapshot(
            Transaction(CNDQueuedTransactionStateCompleted, @[done], 0, nil),
            NO, NO, NO, NO, NO);
        CheckPhase(completed, CNDQueueExecutionPhaseCompleted, @"completed",
                   CNDQueuePrimaryActionNone);
        Check(!completed.canCommit && !completed.canClear,
              @"terminal cleanup is not another runnable queue");

        Check([NSPropertyListSerialization
            propertyList:retry.agentRepresentation isValidForFormat:
                NSPropertyListBinaryFormat_v1_0], @"agent projection is plist-safe");
        Check((id)retry == [retry copyWithZone:NULL],
              @"snapshots are immutable copies");
        printf("PASS: queue lifecycle phases, waits, boundary, retry, controls, wording, agent schema\n");
    }
    return 0;
}
