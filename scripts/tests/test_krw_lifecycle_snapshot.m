#import <Foundation/Foundation.h>
#import "../../Cyanide/kexploit/CNDKRWLifecycleSnapshot.h"

static void Check(BOOL condition, NSString *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message.UTF8String);
        exit(1);
    }
}

static NSMutableDictionary *Fixture(void)
{
    return [@{
        @"deviceSupported": @YES,
        @"actionInFlight": @NO,
        @"cleanupInFlight": @NO,
        @"respringInFlight": @NO,
        @"terminationState": @0,
        @"terminationDisposition": @"unknown",
        @"primitiveReadiness": @(CNDKRWPrimitiveReadinessNotReady),
        @"primitiveOwnershipRecorded": @NO,
        @"labProviderActive": @NO,
        @"nextProcessArmed": @NO,
        @"savedRecoveryPresent": @NO,
        @"recoveredThisProcess": @NO,
        @"launchdHolderRecorded": @NO,
        @"sameBootAnchorProven": @NO,
        @"lastRecoveryResult": @(CNDKRWRecoveryObservationNone),
        @"lastRecoveryStage": @"unknown",
        @"recoveryTokenBurned": @NO,
        @"lastAcquisitionOutcome": @"none",
        @"remoteCallReady": @NO,
        @"springBoardSandboxEscaped": @NO,
        @"generationIdentifier": @"generation-fixture",
        @"handoffSerial": @7,
        @"controlLinkExact": [NSNull null],
        @"controlChecksumExact": [NSNull null],
        @"rwStateExact": [NSNull null],
        @"fullParkVerified": [NSNull null],
        @"currentGenerationAnchorExact": [NSNull null],
        @"observedAt": @1234.5,
    } mutableCopy];
}

static NSNumber *NullableNumber(NSDictionary *fixture, NSString *key)
{
    id value = fixture[key];
    return value == [NSNull null] ? nil : value;
}

static CNDKRWLifecycleSnapshot *Snapshot(NSDictionary *fixture)
{
    return [[CNDKRWLifecycleSnapshot alloc]
        initWithDeviceSupported:[fixture[@"deviceSupported"] boolValue]
        actionInFlight:[fixture[@"actionInFlight"] boolValue]
        cleanupInFlight:[fixture[@"cleanupInFlight"] boolValue]
        respringInFlight:[fixture[@"respringInFlight"] boolValue]
        terminationState:[fixture[@"terminationState"] integerValue]
        terminationDisposition:fixture[@"terminationDisposition"]
        primitiveReadiness:[fixture[@"primitiveReadiness"] integerValue]
        primitiveOwnershipRecorded:[fixture[@"primitiveOwnershipRecorded"] boolValue]
        labProviderActive:[fixture[@"labProviderActive"] boolValue]
        nextProcessArmed:[fixture[@"nextProcessArmed"] boolValue]
        savedRecoveryPresent:[fixture[@"savedRecoveryPresent"] boolValue]
        recoveredThisProcess:[fixture[@"recoveredThisProcess"] boolValue]
        launchdHolderRecorded:[fixture[@"launchdHolderRecorded"] boolValue]
        sameBootAnchorProven:[fixture[@"sameBootAnchorProven"] boolValue]
        lastRecoveryResult:[fixture[@"lastRecoveryResult"] integerValue]
        lastRecoveryStage:fixture[@"lastRecoveryStage"]
        recoveryTokenBurned:[fixture[@"recoveryTokenBurned"] boolValue]
        lastAcquisitionOutcome:fixture[@"lastAcquisitionOutcome"]
        remoteCallReady:[fixture[@"remoteCallReady"] boolValue]
        springBoardSandboxEscaped:[fixture[@"springBoardSandboxEscaped"] boolValue]
        generationIdentifier:fixture[@"generationIdentifier"]
        handoffSerial:[fixture[@"handoffSerial"] unsignedLongLongValue]
        controlLinkExact:NullableNumber(fixture, @"controlLinkExact")
        controlChecksumExact:NullableNumber(fixture, @"controlChecksumExact")
        rwStateExact:NullableNumber(fixture, @"rwStateExact")
        fullParkVerified:NullableNumber(fixture, @"fullParkVerified")
        currentGenerationAnchorExact:NullableNumber(fixture, @"currentGenerationAnchorExact")
        observedAt:[fixture[@"observedAt"] doubleValue]];
}

static void CheckPhase(CNDKRWLifecycleSnapshot *snapshot,
                       CNDKRWLifecyclePhase phase,
                       NSString *reason,
                       CNDKRWLifecycleNextAction action)
{
    Check(snapshot.phase == phase, snapshot.phaseName);
    Check([snapshot.reason isEqualToString:reason],
          [NSString stringWithFormat:@"reason=%@", snapshot.reason]);
    Check(snapshot.nextAction == action, snapshot.nextActionName);
    NSDictionary *agent = snapshot.agentRepresentation;
    Check([agent[@"schemaVersion"] isEqual:@1], @"stable schema version");
    Check([agent[@"phase"] isEqual:snapshot.phaseName] &&
          [agent[@"reason"] isEqual:snapshot.reason] &&
          [agent[@"nextAction"] isEqual:snapshot.nextActionName],
          @"typed and agent-facing lifecycle names agree");
    Check(agent[@"operation"] != nil && agent[@"primitive"] != nil &&
          agent[@"recovery"] != nil && agent[@"parkEvidence"] != nil &&
          agent[@"remoteCall"] != nil && agent[@"controls"] != nil,
          @"independent evidence groups remain structured");
}

static void SetExactPark(NSMutableDictionary *fixture)
{
    fixture[@"controlLinkExact"] = @YES;
    fixture[@"controlChecksumExact"] = @YES;
    fixture[@"rwStateExact"] = @YES;
    fixture[@"fullParkVerified"] = @YES;
    fixture[@"currentGenerationAnchorExact"] = @YES;
}

int main(void)
{
    @autoreleasepool {
        CNDKRWLifecycleSnapshot *unknown;
        NSMutableDictionary *unknownFixture = Fixture();
        unknownFixture[@"primitiveReadiness"] =
            @(CNDKRWPrimitiveReadinessUnknown);
        unknown = Snapshot(unknownFixture);
        CheckPhase(unknown, CNDKRWLifecyclePhaseNeedsAttention,
                   @"readiness-unobserved", CNDKRWLifecycleNextActionAcquire);
        Check(!unknown.canRespring,
              @"unknown readiness is not proof that no primitive exists");
        Check([unknown.agentRepresentation[@"primitive"][@"readiness"]
                  isEqual:@"unknown"], @"unknown readiness reaches AX unchanged");

        CNDKRWLifecycleSnapshot *none = Snapshot(Fixture());
        CheckPhase(none, CNDKRWLifecyclePhaseNoPrimitive,
                   @"no-live-or-saved-primitive", CNDKRWLifecycleNextActionAcquire);
        Check(none.canStartKRWAction && none.freshAcquisitionAllowed &&
              none.canRespring, @"checked absent primitive permits explicit acquisition");

        NSMutableDictionary *busyFixture = Fixture();
        busyFixture[@"actionInFlight"] = @YES;
        CNDKRWLifecycleSnapshot *busy = Snapshot(busyFixture);
        CheckPhase(busy, CNDKRWLifecyclePhaseBusy, @"exclusive-action-owner",
                   CNDKRWLifecycleNextActionWait);
        Check(!busy.canStartKRWAction && !busy.canRespring,
              @"busy ownership rejects duplicate lifecycle actions");

        NSMutableDictionary *liveFixture = Fixture();
        liveFixture[@"primitiveReadiness"] = @(CNDKRWPrimitiveReadinessReady);
        liveFixture[@"primitiveOwnershipRecorded"] = @YES;
        liveFixture[@"nextProcessArmed"] = @YES;
        liveFixture[@"launchdHolderRecorded"] = @YES;
        CNDKRWLifecycleSnapshot *live = Snapshot(liveFixture);
        CheckPhase(live, CNDKRWLifecyclePhaseLive, @"live-next-process-armed",
                   CNDKRWLifecycleNextActionNone);
        Check(!live.canRespring,
              @"live and armed does not substitute for exact park and anchor proof");
        Check([live.agentRepresentation[@"parkEvidence"][@"fullPark"]
                  isEqual:@"unknown"], @"park evidence remains unobserved");

        NSMutableDictionary *unarmedFixture = [liveFixture mutableCopy];
        unarmedFixture[@"nextProcessArmed"] = @NO;
        unarmedFixture[@"savedRecoveryPresent"] = @YES;
        CNDKRWLifecycleSnapshot *unarmed = Snapshot(unarmedFixture);
        CheckPhase(unarmed, CNDKRWLifecyclePhaseNeedsAttention,
                   @"live-next-process-not-armed", CNDKRWLifecycleNextActionRearm);
        Check(!unarmed.canRespring, @"unarmed live KRW cannot promise respring continuity");

        NSMutableDictionary *savedFixture = Fixture();
        savedFixture[@"savedRecoveryPresent"] = @YES;
        savedFixture[@"launchdHolderRecorded"] = @YES;
        CNDKRWLifecycleSnapshot *saved = Snapshot(savedFixture);
        CheckPhase(saved, CNDKRWLifecyclePhaseRecoveryAvailable,
                   @"saved-launchd-recovery", CNDKRWLifecycleNextActionRecover);
        Check(saved.recoveryOnlyAllowed &&
              !saved.fullParkVerified && !saved.currentGenerationAnchorExact,
              @"an unrecovered same-boot generation permits recovery, not a park or acquisition claim");

        NSMutableDictionary *recoveredFixture = [liveFixture mutableCopy];
        recoveredFixture[@"savedRecoveryPresent"] = @YES;
        recoveredFixture[@"recoveredThisProcess"] = @YES;
        recoveredFixture[@"lastRecoveryResult"] =
            @(CNDKRWRecoveryObservationRecovered);
        recoveredFixture[@"lastRecoveryStage"] = @"recovered";
        CNDKRWLifecycleSnapshot *recovered = Snapshot(recoveredFixture);
        CheckPhase(recovered, CNDKRWLifecyclePhaseLive, @"live-next-process-armed",
                   CNDKRWLifecycleNextActionNone);
        Check([recovered.agentRepresentation[@"recovery"][@"lastResult"]
                  isEqual:@"recovered"] &&
              [recovered.agentRepresentation[@"recovery"][@"recoveredThisProcess"]
                  boolValue], @"recovered generation stays independent evidence");

        NSMutableDictionary *retryFixture = [savedFixture mutableCopy];
        retryFixture[@"lastRecoveryResult"] =
            @(CNDKRWRecoveryObservationRetryableFailure);
        retryFixture[@"lastRecoveryStage"] = @"sandbox-token-consume";
        CNDKRWLifecycleSnapshot *retry = Snapshot(retryFixture);
        CheckPhase(retry, CNDKRWLifecyclePhaseNeedsAttention,
                   @"saved-recovery-unproven", CNDKRWLifecycleNextActionRetryRecovery);
        Check(!retry.freshAcquisitionAllowed && retry.recoveryOnlyAllowed,
              @"retryable recovery preserves its generation and blocks fresh acquisition");

        /* Historical release evidence is no longer authority to acquire. A
         * socket-option rejection did not prove launchd released fileports. */
        NSMutableDictionary *releasedFixture = [savedFixture mutableCopy];
        releasedFixture[@"lastRecoveryResult"] =
            @(CNDKRWRecoveryObservationForStage(@"unusable-pair-released"));
        releasedFixture[@"lastRecoveryStage"] = @"unusable-pair-released";
        releasedFixture[@"savedRecoveryPresent"] = @NO;
        releasedFixture[@"launchdHolderRecorded"] = @NO;
        releasedFixture[@"sameBootAnchorProven"] = @YES;
        CNDKRWLifecycleSnapshot *released = Snapshot(releasedFixture);
        Check(releasedFixture[@"lastRecoveryResult"] != nil &&
              [releasedFixture[@"lastRecoveryResult"] integerValue] ==
                  CNDKRWRecoveryObservationRetryableFailure,
              @"the historical release stage classifies conservatively");
        CheckPhase(released, CNDKRWLifecyclePhaseNeedsAttention,
                   @"anchored-generation-recovery-record-missing",
                   CNDKRWLifecycleNextActionReboot);
        Check(!released.freshAcquisitionAllowed,
              @"historical release evidence blocks fresh acquisition");
        Check([released.agentRepresentation[@"recovery"][@"lastResult"]
                  isEqual:@"retryable-failure"],
              @"the unsafe historical release is projected as retryable");

        NSMutableDictionary *burnedFixture = [savedFixture mutableCopy];
        burnedFixture[@"lastRecoveryResult"] =
            @(CNDKRWRecoveryObservationRetryableFailure);
        burnedFixture[@"lastRecoveryStage"] =
            @"sandbox-token-consume-exhausted-preserved";
        burnedFixture[@"recoveryTokenBurned"] = @YES;
        CNDKRWLifecycleSnapshot *burned = Snapshot(burnedFixture);
        CheckPhase(burned, CNDKRWLifecyclePhaseNeedsAttention,
                   @"saved-recovery-unproven",
                   CNDKRWLifecycleNextActionRetryRecovery);
        Check(!burned.freshAcquisitionAllowed && !burned.recoveryOnlyAllowed,
              @"historical token failures preserve the generation and block acquisition and token-consuming retries");

        NSMutableDictionary *historicalFixture = [burnedFixture mutableCopy];
        historicalFixture[@"lastRecoveryResult"] =
            @(CNDKRWRecoveryObservationForStage(
                @"dead-recovered-pair-forgotten"));
        CNDKRWLifecycleSnapshot *historical = Snapshot(historicalFixture);
        Check(!historical.freshAcquisitionAllowed,
              @"a historical destructive stage is not permission to acquire again");

        NSMutableDictionary *incompleteFixture = [liveFixture mutableCopy];
        incompleteFixture[@"currentGenerationAnchorExact"] = @YES;
        CNDKRWLifecycleSnapshot *incomplete = Snapshot(incompleteFixture);
        CheckPhase(incomplete, CNDKRWLifecyclePhaseNeedsAttention,
                   @"live-park-evidence-incomplete", CNDKRWLifecycleNextActionReview);
        Check(!incomplete.canRespring,
              @"an isolated anchor observation is not a complete park transaction");

        NSMutableDictionary *partialFixture = [liveFixture mutableCopy];
        partialFixture[@"controlLinkExact"] = @YES;
        partialFixture[@"controlChecksumExact"] = @NO;
        partialFixture[@"rwStateExact"] = @YES;
        partialFixture[@"fullParkVerified"] = @NO;
        partialFixture[@"currentGenerationAnchorExact"] = @YES;
        CNDKRWLifecycleSnapshot *partial = Snapshot(partialFixture);
        CheckPhase(partial, CNDKRWLifecyclePhaseNeedsAttention,
                   @"live-partial-park-evidence", CNDKRWLifecycleNextActionReview);
        Check(!partial.canRespring, @"partial park evidence fails closed");
        Check([partial.agentRepresentation[@"parkEvidence"][@"controlChecksum"]
                  isEqual:@"not-exact"], @"partial park evidence is not flattened");

        NSMutableDictionary *exactFixture = [liveFixture mutableCopy];
        SetExactPark(exactFixture);
        CNDKRWLifecycleSnapshot *exact = Snapshot(exactFixture);
        CheckPhase(exact, CNDKRWLifecyclePhaseLive, @"live-next-process-armed",
                   CNDKRWLifecycleNextActionNone);
        Check(exact.canRespring,
              @"live exact park plus exact current-generation anchor and arming satisfies the presentation gate");

        NSMutableDictionary *unsafeFixture = Fixture();
        unsafeFixture[@"lastAcquisitionOutcome"] = @"unsafe-unverified";
        CNDKRWLifecycleSnapshot *unsafe = Snapshot(unsafeFixture);
        CheckPhase(unsafe, CNDKRWLifecyclePhaseNeedsAttention,
                   @"unsafe-unverified-acquisition-state",
                   CNDKRWLifecycleNextActionReview);
        Check(!unsafe.canStartKRWAction && !unsafe.freshAcquisitionAllowed &&
              !unsafe.recoveryOnlyAllowed && !unsafe.canRespring,
              @"unsafe-unverified acquisition is a process-wide admission barrier");

        NSMutableDictionary *terminatingFixture = [exactFixture mutableCopy];
        terminatingFixture[@"terminationState"] = @1;
        CNDKRWLifecycleSnapshot *terminating = Snapshot(terminatingFixture);
        CheckPhase(terminating, CNDKRWLifecyclePhaseTerminating,
                   @"termination-cleanup-running", CNDKRWLifecycleNextActionWait);
        Check(!terminating.canStartKRWAction, @"termination owns cleanup");

        NSMutableDictionary *terminatedFixture = [exactFixture mutableCopy];
        terminatedFixture[@"primitiveReadiness"] =
            @(CNDKRWPrimitiveReadinessNotReady);
        terminatedFixture[@"terminationState"] = @2;
        terminatedFixture[@"terminationDisposition"] = @"recoverable-anchored";
        CNDKRWLifecycleSnapshot *terminated = Snapshot(terminatedFixture);
        CheckPhase(terminated, CNDKRWLifecyclePhaseTerminated,
                   @"termination-cleanup-complete", CNDKRWLifecycleNextActionRecover);
        Check(!terminated.canStartKRWAction,
              @"terminal process state is not a new operation admission point");

        NSMutableDictionary *remoteFixture = [Fixture() mutableCopy];
        remoteFixture[@"remoteCallReady"] = @YES;
        remoteFixture[@"springBoardSandboxEscaped"] = @YES;
        CNDKRWLifecycleSnapshot *remote = Snapshot(remoteFixture);
        CheckPhase(remote, CNDKRWLifecyclePhaseNoPrimitive,
                   @"no-live-or-saved-primitive", CNDKRWLifecycleNextActionAcquire);
        Check([remote.agentRepresentation[@"remoteCall"][@"ready"] boolValue] &&
              [remote.agentRepresentation[@"remoteCall"][@"springBoardSandboxEscaped"] boolValue],
              @"RemoteCall state does not manufacture KRW readiness");

        Check([NSPropertyListSerialization
            propertyList:partial.agentRepresentation
            isValidForFormat:NSPropertyListBinaryFormat_v1_0],
            @"agent projection is plist-safe with tri-state evidence");
        Check((id)partial == [partial copyWithZone:NULL],
              @"snapshots are immutable copies");
        Check(partial.accessibilitySummary.length > partial.title.length &&
              [partial.statusFooter containsString:partial.recoveryGuidance],
              @"UX text includes actionable guidance");
        Check(CNDKRWRecoveryObservationForStage(@"unknown") ==
                  CNDKRWRecoveryObservationNone &&
              CNDKRWRecoveryObservationForStage(@"recovered") ==
                  CNDKRWRecoveryObservationRecovered &&
              CNDKRWRecoveryObservationForStage(
                  @"recovered-local-unarmed:launchd-remote-call-init") ==
                  CNDKRWRecoveryObservationRecovered &&
              CNDKRWRecoveryObservationForStage(@"sandbox-token-consume-dead") ==
                  CNDKRWRecoveryObservationRetryableFailure &&
              CNDKRWRecoveryObservationForStage(@"sandbox-token-consume") ==
                  CNDKRWRecoveryObservationRetryableFailure,
              @"bounded recovery stages map without hiding transient failures");
        printf("PASS: KRW lifecycle evidence, admission, recovery, parking, handoff, termination, RemoteCall, agent schema\n");
    }
    return 0;
}
