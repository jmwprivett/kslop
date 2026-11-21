#import "CNDDiscordAudioModeProbe.h"

#import "../TaskRop/RemoteCall.h"
#import "../kexploit/CNDLabKernelProvider.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/krw.h"
#import "../kexploit/offsets.h"
#import "../tweaks/remote_objc.h"

#include <mach-o/loader.h>
#include <stdint.h>
#include <string.h>
#include <sys/sysctl.h>

#define CND_DISCORD_AUDIO_PRODUCT "iPhone17,2"
#define CND_DISCORD_AUDIO_BUILD "23A341"
#define CND_DISCORD_AUDIO_PROCESS "Discord"
#define CND_DISCORD_AUDIO_BUNDLE "com.hammerandchisel.discord"
#define CND_DISCORD_AUDIO_TIMEOUT_MS 15000
#define CND_DISCORD_AUDIO_DEFAULT_MODE "AVAudioSessionModeDefault"
#define CND_DISCORD_AUDIO_JOURNAL_SCHEMA \
    "com.zeroxjf.cyanide.discord-audio-mode-journal"

extern uint64_t g_kernel_base;
extern uint64_t g_kernel_slide;

static volatile int32_t gCNDDiscordAudioModeProbeRunning;

static NSString *CNDDiscordAudioSysctlString(const char *name)
{
    char value[128] = {0};
    size_t length = sizeof(value);
    if (sysctlbyname(name, value, &length, NULL, 0) != 0 || !value[0]) {
        return @"";
    }
    return [NSString stringWithUTF8String:value] ?: @"";
}

static NSString *CNDDiscordAudioHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static NSString *CNDDiscordAudioJournalPath(void)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    return [directory stringByAppendingPathComponent:
        @"CNDDiscordAudioModeRecovery.json"];
}

static NSDictionary<NSString *, id> *CNDDiscordAudioLoadJournal(void)
{
    NSData *data = [NSData dataWithContentsOfFile:CNDDiscordAudioJournalPath()];
    if (!data) return nil;
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![object isKindOfClass:NSDictionary.class] ||
        ![object[@"schema"] isEqualToString:
            @CND_DISCORD_AUDIO_JOURNAL_SCHEMA]) {
        return nil;
    }
    return object;
}

static BOOL CNDDiscordAudioSaveJournal(NSDictionary<NSString *, id> *journal,
                                       NSString **errorOut)
{
    if (errorOut) *errorOut = @"";
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:journal
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:&error];
    BOOL saved = data && [data writeToFile:CNDDiscordAudioJournalPath()
        options:NSDataWritingAtomic error:&error];
    if (!saved && errorOut) *errorOut = error.localizedDescription ?: @"unknown";
    return saved;
}

static BOOL CNDDiscordAudioRemoveJournal(NSString **errorOut)
{
    if (errorOut) *errorOut = @"";
    NSString *path = CNDDiscordAudioJournalPath();
    if (![NSFileManager.defaultManager fileExistsAtPath:path]) return YES;
    NSError *error = nil;
    BOOL removed = [NSFileManager.defaultManager removeItemAtPath:path
                                                            error:&error];
    if (!removed && errorOut) {
        *errorOut = error.localizedDescription ?: @"unknown";
    }
    return removed;
}

BOOL CNDDiscordAudioModeProbeHasRecoveryJournal(void)
{
    return CNDDiscordAudioLoadJournal() != nil;
}

BOOL CNDDiscordAudioModeProbeIsSupported(
    NSString * _Nullable * _Nullable reasonOut)
{
    NSString *product = CNDDiscordAudioSysctlString("hw.machine");
    NSString *build = CNDDiscordAudioSysctlString("kern.osversion");
    BOOL physical = !cnd_lab_vphone_guest();
    BOOL supported = physical &&
        [product isEqualToString:@CND_DISCORD_AUDIO_PRODUCT] &&
        [build isEqualToString:@CND_DISCORD_AUDIO_BUILD];
    if (reasonOut) {
        if (!physical) {
            *reasonOut = @"Physical-device Discord audio action; vPhone is refused.";
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

BOOL CNDDiscordAudioModeProbeIsRunning(void)
{
    return __sync_fetch_and_add(&gCNDDiscordAudioModeProbeRunning, 0) != 0;
}

static NSString *CNDDiscordAudioRemoteString(uint64_t object)
{
    char value[512] = {0};
    if (!r_is_objc_ptr(object) ||
        !r_read_nsstring(object, value, sizeof(value))) {
        return @"";
    }
    return [NSString stringWithUTF8String:value] ?: @"";
}

static NSString *CNDDiscordAudioRemotePropertyString(
    uint64_t object, const char *selector)
{
    if (!r_is_objc_ptr(object) || !selector) return @"";
    return CNDDiscordAudioRemoteString(
        r_msg2(object, selector, 0, 0, 0, 0));
}

static NSDictionary<NSString *, id> *CNDDiscordAudioSnapshotDictionary(
    const RemoteCallDebugSnapshot *snapshot)
{
    if (!snapshot) return @{};
    return @{
        @"hasLocalState": @(snapshot->hasLocalState),
        @"success": @(snapshot->success),
        @"pid": @(snapshot->pid),
        @"proc": CNDDiscordAudioHex(snapshot->procAddr),
        @"task": CNDDiscordAudioHex(snapshot->taskAddr),
        @"stableCalls": @(snapshot->stableCalls),
        @"stableFailures": @(snapshot->stableFailures),
        @"ioFailures": @(snapshot->ioFailures),
        @"identityMessageValid": @(snapshot->identityMessageValid),
        @"identityThreadRightExact": @(snapshot->identityThreadRightExact),
        @"identityTaskRightExact": @(snapshot->identityTaskRightExact),
        @"identityHandlerRetained": @(snapshot->identityHandlerRetained),
        @"identityInitialConversionSucceeded":
            @(snapshot->identityInitialConversionSucceeded),
        @"identityInitialReplySucceeded":
            @(snapshot->identityInitialReplySucceeded),
        @"identityConversionCount": @(snapshot->identityConversionCount),
        @"identityConversionFailures":
            @(snapshot->identityConversionFailures),
        @"identityPACFallbackCount": @(snapshot->identityPACFallbackCount),
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

static NSDictionary<NSString *, id> *CNDDiscordAudioCheckedIdentity(
    const RemoteCallDebugSnapshot *snapshot)
{
    offsets_init();
    BOOL offsetsReady = off_proc_p_pid && off_proc_p_name &&
        off_proc_p_proc_ro && off_proc_ro_pr_task && t1sz_boot;
    uint32_t pid = 0;
    char processName[32] = {0};
    uint64_t procRO = 0;
    uint64_t task = 0;
    struct mach_header_64 kernelHeader = {0};

    BOOL pidRead = offsetsReady && snapshot &&
        kexploit_krw_read_checked(
            snapshot->procAddr + off_proc_p_pid, &pid, sizeof(pid));
    BOOL nameRead = offsetsReady && snapshot &&
        kexploit_krw_read_checked(
            snapshot->procAddr + off_proc_p_name,
            processName, sizeof(processName));
    BOOL procRORead = offsetsReady && snapshot &&
        kexploit_krw_read_checked(
            snapshot->procAddr + off_proc_p_proc_ro,
            &procRO, sizeof(procRO));
    BOOL taskRead = procRORead && is_kaddr_valid(procRO) &&
        kexploit_krw_read_checked(
            procRO + off_proc_ro_pr_task, &task, sizeof(task));
    BOOL kernelHeaderRead = g_kernel_base && is_kaddr_valid(g_kernel_base) &&
        kexploit_krw_read_checked(
            g_kernel_base, &kernelHeader, sizeof(kernelHeader));
    BOOL kernelHeaderExact = kernelHeaderRead &&
        kernelHeader.magic == MH_MAGIC_64 &&
        kernelHeader.cputype == CPU_TYPE_ARM64 &&
        (kernelHeader.filetype == MH_FILESET ||
         kernelHeader.filetype == MH_EXECUTE);
    BOOL exact = snapshot && offsetsReady && pidRead && nameRead &&
        procRORead && taskRead && kernelHeaderExact &&
        pid == (uint32_t)snapshot->pid &&
        strcmp(processName, CND_DISCORD_AUDIO_PROCESS) == 0 &&
        task == snapshot->taskAddr;

    return @{
        @"offsetsInitialized": @(offsetsReady),
        @"pidReadChecked": @(pidRead),
        @"processNameReadChecked": @(nameRead),
        @"procROReadChecked": @(procRORead),
        @"taskReadChecked": @(taskRead),
        @"kernelHeaderReadChecked": @(kernelHeaderRead),
        @"kernelHeaderExact": @(kernelHeaderExact),
        @"kernelMagic": @((unsigned int)kernelHeader.magic),
        @"kernelCPUType": @((int)kernelHeader.cputype),
        @"kernelFileType": @((unsigned int)kernelHeader.filetype),
        @"kernelBase": CNDDiscordAudioHex(g_kernel_base),
        @"kernelSlide": CNDDiscordAudioHex(g_kernel_slide),
        @"t1sz": @(t1sz_boot),
        @"pid": @(pid),
        @"processName": [NSString stringWithUTF8String:processName] ?: @"",
        @"procRO": CNDDiscordAudioHex(procRO),
        @"task": CNDDiscordAudioHex(task),
        @"exact": @(exact),
    };
}

static NSArray<NSDictionary<NSString *, NSString *> *> *
CNDDiscordAudioPorts(uint64_t ports)
{
    if (!r_is_objc_ptr(ports)) return @[];
    uint64_t count = r_msg2(ports, "count", 0, 0, 0, 0);
    if (!remote_call_current_success() || count > 16) return @[];

    NSMutableArray *result = [NSMutableArray arrayWithCapacity:(NSUInteger)count];
    for (uint64_t index = 0; index < count; index++) {
        uint64_t port = r_msg2(ports, "objectAtIndex:", index, 0, 0, 0);
        if (!r_is_objc_ptr(port) || !remote_call_current_success()) break;
        [result addObject:@{
            @"type": CNDDiscordAudioRemotePropertyString(port, "portType"),
            @"name": CNDDiscordAudioRemotePropertyString(port, "portName"),
            @"uid": CNDDiscordAudioRemotePropertyString(port, "UID"),
        }];
    }
    return result;
}

static BOOL CNDDiscordAudioPortTypeContains(
    NSArray<NSDictionary<NSString *, NSString *> *> *ports,
    NSString *needle)
{
    for (NSDictionary<NSString *, NSString *> *port in ports) {
        if ([port[@"type"] rangeOfString:needle
                                 options:NSCaseInsensitiveSearch].location !=
                NSNotFound) {
            return YES;
        }
    }
    return NO;
}

static NSDictionary<NSString *, id> *CNDDiscordAudioPreferredInput(
    uint64_t audioSession)
{
    uint64_t input = r_msg2(audioSession, "preferredInput", 0, 0, 0, 0);
    if (!r_is_objc_ptr(input)) {
        return @{ @"isNil": @YES, @"uid": @"", @"type": @"", @"name": @"" };
    }
    return @{
        @"isNil": @NO,
        @"uid": CNDDiscordAudioRemotePropertyString(input, "UID"),
        @"type": CNDDiscordAudioRemotePropertyString(input, "portType"),
        @"name": CNDDiscordAudioRemotePropertyString(input, "portName"),
    };
}

static uint64_t CNDDiscordAudioFindInput(uint64_t audioSession,
                                         NSString *uid,
                                         BOOL builtIn)
{
    uint64_t availableInputs = r_msg2(
        audioSession, "availableInputs", 0, 0, 0, 0);
    if (!r_is_objc_ptr(availableInputs)) return 0;
    uint64_t count = r_msg2(availableInputs, "count", 0, 0, 0, 0);
    if (!remote_call_current_success() || count > 16) return 0;
    for (uint64_t index = 0; index < count; index++) {
        uint64_t input = r_msg2(
            availableInputs, "objectAtIndex:", index, 0, 0, 0);
        if (!r_is_objc_ptr(input)) continue;
        NSString *candidateUID = CNDDiscordAudioRemotePropertyString(input, "UID");
        NSString *type = CNDDiscordAudioRemotePropertyString(input, "portType");
        BOOL typeMatches = [type rangeOfString:@"BuiltInMic"
                                      options:NSCaseInsensitiveSearch].location !=
                NSNotFound ||
            [type rangeOfString:@"MicrophoneBuiltIn"
                        options:NSCaseInsensitiveSearch].location != NSNotFound;
        if ((builtIn && typeMatches) ||
            (!builtIn && uid.length > 0 && [candidateUID isEqualToString:uid])) {
            return input;
        }
    }
    return 0;
}

static NSDictionary<NSString *, id> *CNDDiscordAudioSessionSample(
    uint64_t audioSession, NSTimeInterval elapsed)
{
    NSString *mode = CNDDiscordAudioRemotePropertyString(audioSession, "mode");
    NSString *category = CNDDiscordAudioRemotePropertyString(
        audioSession, "category");
    uint64_t route = r_msg2(audioSession, "currentRoute", 0, 0, 0, 0);
    NSArray *inputs = r_is_objc_ptr(route)
        ? CNDDiscordAudioPorts(r_msg2(route, "inputs", 0, 0, 0, 0)) : @[];
    NSArray *outputs = r_is_objc_ptr(route)
        ? CNDDiscordAudioPorts(r_msg2(route, "outputs", 0, 0, 0, 0)) : @[];
    double sampleRate = 0.0;
    BOOL sampleRateRead = r_msg2_struct_ret(
        audioSession, "sampleRate", &sampleRate, sizeof(sampleRate),
        NULL, 0, NULL, 0, NULL, 0, NULL, 0);

    return @{
        @"elapsedSeconds": @(elapsed),
        @"mode": mode,
        @"category": category,
        @"preferredInput": CNDDiscordAudioPreferredInput(audioSession),
        @"inputs": inputs,
        @"outputs": outputs,
        @"sampleRateRead": @(sampleRateRead),
        @"sampleRate": @(sampleRate),
        @"inputChannels": @(r_msg2(
            audioSession, "inputNumberOfChannels", 0, 0, 0, 0)),
        @"outputChannels": @(r_msg2(
            audioSession, "outputNumberOfChannels", 0, 0, 0, 0)),
        @"builtInMic": @(CNDDiscordAudioPortTypeContains(
            inputs, @"BuiltInMic") || CNDDiscordAudioPortTypeContains(
            inputs, @"MicrophoneBuiltIn")),
        @"bluetoothA2DP": @(CNDDiscordAudioPortTypeContains(outputs, @"A2DP")),
        @"bluetoothHFP": @(CNDDiscordAudioPortTypeContains(outputs, @"HFP")),
        @"transportHealthy": @(remote_call_current_success()),
    };
}

static BOOL CNDDiscordAudioSetObjectProperty(uint64_t audioSession,
                                             const char *selector,
                                             uint64_t value,
                                             NSString **errorOut)
{
    if (errorOut) *errorOut = @"";
    uint64_t errorSlot = r_dlsym_call(
        R_TIMEOUT, "calloc", 1, sizeof(uint64_t), 0, 0, 0, 0, 0, 0);
    BOOL accepted = NO;
    if (errorSlot && remote_write64(errorSlot, 0)) {
        accepted = (r_msg2(audioSession, selector, value, errorSlot, 0, 0) &
            0xff) != 0 && remote_call_current_success();
        uint64_t remoteError = remote_read64(errorSlot);
        if (errorOut && r_is_objc_ptr(remoteError)) {
            *errorOut = CNDDiscordAudioRemotePropertyString(
                remoteError, "localizedDescription");
        }
    }
    if (errorSlot && remote_call_current_success()) r_free(errorSlot);
    return accepted;
}

static BOOL CNDDiscordAudioSetMode(uint64_t audioSession,
                                   NSString *mode,
                                   NSString **errorOut)
{
    uint64_t remoteMode = r_nsstr_retained(mode.UTF8String);
    BOOL accepted = remoteMode && CNDDiscordAudioSetObjectProperty(
        audioSession, "setMode:error:", remoteMode, errorOut);
    if (remoteMode && remote_call_current_success()) {
        r_msg2(remoteMode, "release", 0, 0, 0, 0);
    }
    return accepted;
}

static BOOL CNDDiscordAudioSetPreferredInput(uint64_t audioSession,
                                             uint64_t input,
                                             NSString **errorOut)
{
    return CNDDiscordAudioSetObjectProperty(
        audioSession, "setPreferredInput:error:", input, errorOut);
}

static NSString *CNDDiscordAudioBundleIdentifier(void)
{
    uint64_t bundleClass = r_class("NSBundle");
    uint64_t bundle = r_is_objc_ptr(bundleClass)
        ? r_msg2(bundleClass, "mainBundle", 0, 0, 0, 0) : 0;
    return CNDDiscordAudioRemotePropertyString(bundle, "bundleIdentifier");
}

static NSMutableDictionary<NSString *, id> *CNDDiscordAudioBaseReport(
    NSString *operation)
{
    return [@{
        @"schema": @"com.zeroxjf.cyanide.discord-audio-mode-probe",
        @"schemaVersion": @2,
        @"operation": operation,
        @"productType": CNDDiscordAudioSysctlString("hw.machine"),
        @"productBuildVersion": CNDDiscordAudioSysctlString("kern.osversion"),
        @"kernelUUID": CNDDiscordAudioSysctlString("kern.uuid"),
        @"bootSessionUUID": CNDDiscordAudioSysctlString("kern.bootsessionuuid"),
        @"cyanidePID": @(getpid()),
        @"targetProcess": @CND_DISCORD_AUDIO_PROCESS,
        @"targetBundleIdentifierExpected": @CND_DISCORD_AUDIO_BUNDLE,
        @"requestedMode": @CND_DISCORD_AUDIO_DEFAULT_MODE,
        @"krwPolicy": @"shared-tweak-lifecycle",
        @"kernelReadUsed": @YES,
        @"kernelWriteUsedByRemoteCall": @YES,
        @"kernelCallUsed": @NO,
        @"forgedTaskPortUsed": @NO,
        @"newExecutableMappingUsed": @NO,
        @"dylibInjected": @NO,
        @"persistentAudioMutationRequested": @([operation isEqualToString:@"apply"]),
        @"startedAt": @([[NSDate date] timeIntervalSince1970]),
    } mutableCopy];
}

static BOOL CNDDiscordAudioPrepareSession(
    NSMutableDictionary<NSString *, id> *report,
    RemoteCallDebugSnapshot *initializedOut,
    uint64_t *audioSessionOut,
    uint64_t *autoreleasePoolOut)
{
    NSString *supportReason = nil;
    if (!CNDDiscordAudioModeProbeIsSupported(&supportReason)) {
        report[@"result"] = @"refused-unsupported-environment";
        report[@"message"] = supportReason ?: @"Unsupported environment.";
        return NO;
    }

    int initResult = init_remote_call_identity_bootstrap_original_thread_only(
        CND_DISCORD_AUDIO_PROCESS, CND_DISCORD_AUDIO_TIMEOUT_MS);
    report[@"remoteCallInitResult"] = @(initResult);
    report[@"remoteCallInitFailure"] = @(remote_call_last_init_failure());
    report[@"remoteCallInitFailureDescription"] =
        [NSString stringWithUTF8String:remote_call_init_failure_description(
            remote_call_last_init_failure())] ?: @"unknown";
    RemoteCallDebugSnapshot initialized = {0};
    (void)remote_call_copy_debug_snapshot(&initialized);
    report[@"afterInitialize"] = CNDDiscordAudioSnapshotDictionary(&initialized);
    if (initializedOut) *initializedOut = initialized;
    if (initResult != 0) {
        report[@"result"] = @"failed-remotecall-initialize";
        return NO;
    }

    NSDictionary *checkedIdentity = CNDDiscordAudioCheckedIdentity(&initialized);
    report[@"checkedIdentity"] = checkedIdentity;
    if (![checkedIdentity[@"exact"] boolValue]) {
        report[@"result"] = @"refused-target-kernel-identity-mismatch";
        return NO;
    }

    uint64_t markerPID = do_remote_call_stable(
        2000, "getpid", 0, 0, 0, 0, 0, 0, 0, 0);
    report[@"markerPID"] = @(markerPID);
    report[@"markerMatchedTargetPID"] = @(
        markerPID == (uint64_t)initialized.pid);
    if (markerPID != (uint64_t)initialized.pid) {
        report[@"result"] = @"refused-target-marker-mismatch";
        return NO;
    }

    uint64_t pool = r_autorelease_pool_push();
    if (autoreleasePoolOut) *autoreleasePoolOut = pool;
    NSString *bundleIdentifier = CNDDiscordAudioBundleIdentifier();
    report[@"targetBundleIdentifierObserved"] = bundleIdentifier;
    if (![bundleIdentifier isEqualToString:@CND_DISCORD_AUDIO_BUNDLE]) {
        report[@"result"] = @"refused-target-bundle-mismatch";
        return NO;
    }

    uint64_t audioSessionClass = r_class("AVAudioSession");
    uint64_t audioSession = r_is_objc_ptr(audioSessionClass)
        ? r_msg2(audioSessionClass, "sharedInstance", 0, 0, 0, 0) : 0;
    BOOL apiExact = r_is_objc_ptr(audioSession) &&
        r_responds(audioSession, "mode") &&
        r_responds(audioSession, "setMode:error:") &&
        r_responds(audioSession, "preferredInput") &&
        r_responds(audioSession, "setPreferredInput:error:") &&
        r_responds(audioSession, "availableInputs") &&
        r_responds(audioSession, "currentRoute");
    report[@"audioSessionAPIExact"] = @(apiExact);
    if (!apiExact || !remote_call_current_success()) {
        report[@"result"] = @"refused-audio-session-api-unavailable";
        return NO;
    }
    if (audioSessionOut) *audioSessionOut = audioSession;
    return YES;
}

static void CNDDiscordAudioFinishRemoteCall(
    NSMutableDictionary<NSString *, id> *report,
    const RemoteCallDebugSnapshot *initialized,
    uint64_t autoreleasePool,
    BOOL remoteCallInitialized)
{
    if (autoreleasePool && remote_call_current_success()) {
        report[@"autoreleasePoolPopped"] = @(
            r_autorelease_pool_pop(autoreleasePool));
    } else {
        report[@"autoreleasePoolPopped"] = @(autoreleasePool == 0);
    }
    int destroyResult = remoteCallInitialized ? destroy_remote_call() : -1;
    report[@"remoteCallDestroyResult"] = @(destroyResult);
    report[@"threadRestored"] = @(remoteCallInitialized && destroyResult == 0);
    RemoteCallDebugSnapshot afterRestore = {0};
    (void)remote_call_copy_debug_snapshot(&afterRestore);
    report[@"afterRemoteCallRestore"] =
        CNDDiscordAudioSnapshotDictionary(&afterRestore);
    if (remoteCallInitialized && initialized) {
        NSDictionary *identityAfter = CNDDiscordAudioCheckedIdentity(initialized);
        report[@"checkedIdentityAfter"] = identityAfter;
        report[@"targetIdentityStable"] = identityAfter[@"exact"] ?: @NO;
    } else {
        report[@"targetIdentityStable"] = @NO;
    }
}

static NSString *CNDDiscordAudioWriteReport(
    NSMutableDictionary<NSString *, id> *report, NSString *name)
{
    report[@"completedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *path = [directory stringByAppendingPathComponent:name];
    report[@"reportPath"] = path;
    report[@"reportSaved"] = @NO;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:nil];
    BOOL saved = data && [data writeToFile:path
        options:NSDataWritingAtomic error:nil];
    if (saved) {
        report[@"reportSaved"] = @YES;
        NSData *finalData = [NSJSONSerialization dataWithJSONObject:report
            options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
            error:nil];
        saved = finalData && [finalData writeToFile:path
            options:NSDataWritingAtomic error:nil];
        if (!saved) report[@"reportSaved"] = @NO;
    }
    return path;
}

static NSDictionary<NSString *, id> *CNDDiscordAudioModeApplyOnce(void)
{
    NSMutableDictionary<NSString *, id> *report =
        CNDDiscordAudioBaseReport(@"apply");
    RemoteCallDebugSnapshot initialized = {0};
    BOOL remoteCallInitialized = NO;
    uint64_t audioSession = 0;
    uint64_t autoreleasePool = 0;
    BOOL mutationStarted = NO;
    BOOL journalSaved = NO;
    NSString *originalMode = @"";
    NSDictionary *originalPreferred = @{};

    BOOL prepared = CNDDiscordAudioPrepareSession(
        report, &initialized, &audioSession, &autoreleasePool);
    remoteCallInitialized = initialized.hasLocalState;
    if (prepared) {
        NSDictionary *existingJournal = CNDDiscordAudioLoadJournal();
    if (existingJournal &&
        [existingJournal[@"bootSessionUUID"] isEqualToString:
            report[@"bootSessionUUID"]] &&
        [existingJournal[@"targetPID"] intValue] == initialized.pid) {
        report[@"result"] = @"refused-active-recovery-journal";
        report[@"message"] = @"Restore the saved Discord audio state before applying again.";
        goto finish;
    }
    if (existingJournal) {
        NSString *removeError = @"";
        report[@"staleJournalRemoved"] = @(
            CNDDiscordAudioRemoveJournal(&removeError));
        report[@"staleJournalRemoveError"] = removeError;
    }

    originalMode = CNDDiscordAudioRemotePropertyString(audioSession, "mode");
    originalPreferred = CNDDiscordAudioPreferredInput(audioSession);
    NSDictionary *before = CNDDiscordAudioSessionSample(audioSession, 0.0);
    report[@"originalMode"] = originalMode;
    report[@"originalPreferredInput"] = originalPreferred;
    report[@"before"] = before;
    if (originalMode.length == 0 || !remote_call_current_success()) {
        report[@"result"] = @"refused-original-audio-state-unavailable";
        goto finish;
    }

    NSMutableDictionary *journal = [@{
        @"schema": @CND_DISCORD_AUDIO_JOURNAL_SCHEMA,
        @"schemaVersion": @1,
        @"stage": @"prepared",
        @"bootSessionUUID": report[@"bootSessionUUID"] ?: @"",
        @"productType": report[@"productType"] ?: @"",
        @"productBuildVersion": report[@"productBuildVersion"] ?: @"",
        @"targetProcess": @CND_DISCORD_AUDIO_PROCESS,
        @"targetBundleIdentifier": @CND_DISCORD_AUDIO_BUNDLE,
        @"targetPID": @(initialized.pid),
        @"targetProc": CNDDiscordAudioHex(initialized.procAddr),
        @"targetTask": CNDDiscordAudioHex(initialized.taskAddr),
        @"originalMode": originalMode,
        @"originalPreferredInput": originalPreferred,
        @"before": before,
        @"preparedAt": @([[NSDate date] timeIntervalSince1970]),
    } mutableCopy];
    NSString *journalError = @"";
    journalSaved = CNDDiscordAudioSaveJournal(journal, &journalError);
    report[@"recoveryJournalPrepared"] = @(journalSaved);
    report[@"recoveryJournalError"] = journalError;
    report[@"recoveryJournalPath"] = CNDDiscordAudioJournalPath();
    if (!journalSaved) {
        report[@"result"] = @"refused-recovery-journal-unavailable";
        goto finish;
    }

    mutationStarted = YES;
    NSString *modeError = @"";
    BOOL modeAccepted = CNDDiscordAudioSetMode(
        audioSession, @CND_DISCORD_AUDIO_DEFAULT_MODE, &modeError);
    uint64_t builtInInput = CNDDiscordAudioFindInput(audioSession, @"", YES);
    NSString *inputError = @"";
    BOOL inputAccepted = builtInInput && CNDDiscordAudioSetPreferredInput(
        audioSession, builtInInput, &inputError);
    report[@"defaultModeRequestAccepted"] = @(modeAccepted);
    report[@"defaultModeRequestError"] = modeError;
    report[@"builtInInputFound"] = @(builtInInput != 0);
    report[@"builtInInputRequestAccepted"] = @(inputAccepted);
    report[@"builtInInputRequestError"] = inputError;

    NSMutableArray *samples = [NSMutableArray array];
    [samples addObject:CNDDiscordAudioSessionSample(audioSession, 0.0)];
    [NSThread sleepForTimeInterval:2.0];
    [samples addObject:CNDDiscordAudioSessionSample(audioSession, 2.0)];
    [NSThread sleepForTimeInterval:4.0];
    NSDictionary *finalSample = CNDDiscordAudioSessionSample(audioSession, 6.0);
    [samples addObject:finalSample];
    report[@"afterApplySamples"] = samples;

    NSDictionary *finalPreferred = finalSample[@"preferredInput"];
    BOOL defaultModeActive = [finalSample[@"mode"]
        isEqualToString:@CND_DISCORD_AUDIO_DEFAULT_MODE];
    BOOL builtInInputActive = [finalSample[@"builtInMic"] boolValue] &&
        [finalPreferred[@"isNil"] boolValue] == NO &&
        [finalPreferred[@"type"] rangeOfString:@"BuiltIn"
                                        options:NSCaseInsensitiveSearch].location !=
            NSNotFound;
    BOOL configurationActive = modeAccepted && inputAccepted &&
        defaultModeActive && builtInInputActive;
    report[@"defaultModeActive"] = @(defaultModeActive);
    report[@"builtInInputActive"] = @(builtInInputActive);
    report[@"bluetoothA2DPObserved"] = finalSample[@"bluetoothA2DP"] ?: @NO;
    report[@"bluetoothHFPObserved"] = finalSample[@"bluetoothHFP"] ?: @NO;
    report[@"configurationActive"] = @(configurationActive);

    if (configurationActive) {
        journal[@"stage"] = @"applied";
        journal[@"appliedAt"] = @([[NSDate date] timeIntervalSince1970]);
        journal[@"afterApply"] = finalSample;
        NSString *updateError = @"";
        BOOL journalUpdated = CNDDiscordAudioSaveJournal(journal, &updateError);
        report[@"recoveryJournalUpdated"] = @(journalUpdated);
        report[@"recoveryJournalUpdateError"] = updateError;
        report[@"automaticAudioRestorePerformed"] = @NO;
        report[@"persistentAudioMutationActive"] = @YES;
    } else {
        NSString *restoreModeError = @"";
        BOOL modeRestored = CNDDiscordAudioSetMode(
            audioSession, originalMode, &restoreModeError);
        BOOL preferredWasNil = [originalPreferred[@"isNil"] boolValue];
        uint64_t originalInput = preferredWasNil ? 0 :
            CNDDiscordAudioFindInput(
                audioSession, originalPreferred[@"uid"], NO);
        NSString *restoreInputError = @"";
        BOOL inputRestored = (preferredWasNil || originalInput) &&
            CNDDiscordAudioSetPreferredInput(
                audioSession, originalInput, &restoreInputError);
        NSDictionary *rollback = CNDDiscordAudioSessionSample(audioSession, 6.0);
        NSDictionary *rollbackPreferred = rollback[@"preferredInput"];
        BOOL preferredRestored = inputRestored && (preferredWasNil
            ? [rollbackPreferred[@"isNil"] boolValue]
            : [rollbackPreferred[@"uid"]
                isEqualToString:originalPreferred[@"uid"]]);
        BOOL rollbackVerified = modeRestored &&
            [rollback[@"mode"] isEqualToString:originalMode] &&
            preferredRestored;
        report[@"failureRollbackModeError"] = restoreModeError;
        report[@"failureRollbackInputError"] = restoreInputError;
        report[@"failureRollbackVerified"] = @(rollbackVerified);
        if (rollbackVerified) {
            NSString *removeError = @"";
            report[@"recoveryJournalRemovedAfterRollback"] = @(
                CNDDiscordAudioRemoveJournal(&removeError));
            report[@"recoveryJournalRemoveError"] = removeError;
        }
        report[@"persistentAudioMutationActive"] = @NO;
        report[@"result"] = rollbackVerified
            ? @"failed-configuration-not-active-rolled-back"
            : @"failed-configuration-and-rollback-unverified";
    }
    }

finish:
    CNDDiscordAudioFinishRemoteCall(
        report, &initialized, autoreleasePool, remoteCallInitialized);
    BOOL configurationActive = [report[@"configurationActive"] boolValue];
    BOOL transportClean = [report[@"threadRestored"] boolValue] &&
        [report[@"targetIdentityStable"] boolValue];
    BOOL applyCompleted = configurationActive && journalSaved && transportClean;
    BOOL fullQualityAirPodsRouteVerified = applyCompleted &&
        [report[@"bluetoothA2DPObserved"] boolValue];
    report[@"applyCompleted"] = @(applyCompleted);
    report[@"fullQualityAirPodsRouteVerified"] =
        @(fullQualityAirPodsRouteVerified);
    if (report[@"result"] == nil) {
        if (!transportClean) {
            report[@"result"] = @"failed-remotecall-cleanup-unverified";
        } else if (applyCompleted &&
                   [report[@"bluetoothA2DPObserved"] boolValue]) {
            report[@"result"] = @"applied-built-in-mic-a2dp-observed";
        } else if (applyCompleted) {
            report[@"result"] = @"applied-built-in-mic-without-a2dp";
        } else if (!mutationStarted) {
            report[@"result"] = @"refused-before-mutation";
        }
    }
    (void)CNDDiscordAudioWriteReport(
        report, @"CNDDiscordAudioModeApplyReport.json");
    return [report copy];
}

static NSDictionary<NSString *, id> *CNDDiscordAudioModeRestoreOnce(void)
{
    NSMutableDictionary<NSString *, id> *report =
        CNDDiscordAudioBaseReport(@"restore");
    NSDictionary *journal = CNDDiscordAudioLoadJournal();
    RemoteCallDebugSnapshot initialized = {0};
    BOOL remoteCallInitialized = NO;
    uint64_t audioSession = 0;
    uint64_t autoreleasePool = 0;
    BOOL prepared = NO;
    NSString *originalMode = nil;
    NSDictionary *originalPreferred = nil;
    BOOL preferredWasNil = NO;
    NSString *modeError = nil;
    BOOL modeAccepted = NO;
    uint64_t originalInput = 0;
    NSString *inputError = nil;
    BOOL inputAccepted = NO;
    NSDictionary *afterRestore = nil;
    NSDictionary *afterPreferred = nil;
    BOOL modeRestored = NO;
    BOOL preferredRestored = NO;
    BOOL transportClean = NO;
    BOOL stateRestored = NO;
    NSString *journalRemoveError = nil;
    BOOL journalRemoved = NO;
    report[@"recoveryJournalPath"] = CNDDiscordAudioJournalPath();
    if (!journal) {
        report[@"result"] = @"refused-no-recovery-journal";
        goto save;
    }
    report[@"journalStage"] = journal[@"stage"] ?: @"unknown";
    report[@"journalTargetPID"] = journal[@"targetPID"] ?: @0;
    if (![journal[@"bootSessionUUID"] isEqualToString:
            report[@"bootSessionUUID"]]) {
        NSString *removeError = @"";
        BOOL removed = CNDDiscordAudioRemoveJournal(&removeError);
        report[@"staleJournalRemoved"] = @(removed);
        report[@"staleJournalRemoveError"] = removeError;
        report[@"restoreCompleted"] = @(removed);
        report[@"result"] = removed
            ? @"restore-unneeded-after-boot-change"
            : @"failed-stale-journal-removal";
        goto save;
    }

    prepared = CNDDiscordAudioPrepareSession(
        report, &initialized, &audioSession, &autoreleasePool);
    remoteCallInitialized = initialized.hasLocalState;
    if (!prepared) {
        CNDDiscordAudioFinishRemoteCall(
            report, &initialized, autoreleasePool, remoteCallInitialized);
        goto save;
    }

    if ([journal[@"targetPID"] intValue] != initialized.pid) {
        NSString *removeError = @"";
        BOOL removed = CNDDiscordAudioRemoveJournal(&removeError);
        report[@"staleJournalRemoved"] = @(removed);
        report[@"staleJournalRemoveError"] = removeError;
        report[@"restoreCompleted"] = @(removed);
        report[@"result"] = removed
            ? @"restore-unneeded-after-discord-relaunch"
            : @"failed-stale-journal-removal";
        CNDDiscordAudioFinishRemoteCall(
            report, &initialized, autoreleasePool, remoteCallInitialized);
        goto save;
    }

    report[@"beforeRestore"] = CNDDiscordAudioSessionSample(audioSession, 0.0);
    originalMode = journal[@"originalMode"];
    originalPreferred = journal[@"originalPreferredInput"];
    preferredWasNil = [originalPreferred[@"isNil"] boolValue];
    modeError = @"";
    modeAccepted = originalMode.length > 0 && CNDDiscordAudioSetMode(
        audioSession, originalMode, &modeError);
    originalInput = preferredWasNil ? 0 :
        CNDDiscordAudioFindInput(audioSession, originalPreferred[@"uid"], NO);
    inputError = @"";
    inputAccepted = (preferredWasNil || originalInput) &&
        CNDDiscordAudioSetPreferredInput(audioSession, originalInput, &inputError);
    [NSThread sleepForTimeInterval:1.0];
    afterRestore = CNDDiscordAudioSessionSample(audioSession, 1.0);
    afterPreferred = afterRestore[@"preferredInput"];
    modeRestored = modeAccepted &&
        [afterRestore[@"mode"] isEqualToString:originalMode];
    preferredRestored = inputAccepted && (preferredWasNil
        ? [afterPreferred[@"isNil"] boolValue]
        : [afterPreferred[@"uid"] isEqualToString:originalPreferred[@"uid"]]);
    report[@"modeRestoreAccepted"] = @(modeAccepted);
    report[@"modeRestoreError"] = modeError;
    report[@"preferredInputRestoreAccepted"] = @(inputAccepted);
    report[@"preferredInputRestoreError"] = inputError;
    report[@"modeRestored"] = @(modeRestored);
    report[@"preferredInputRestored"] = @(preferredRestored);
    report[@"afterRestore"] = afterRestore;

    CNDDiscordAudioFinishRemoteCall(
        report, &initialized, autoreleasePool, remoteCallInitialized);
    transportClean = [report[@"threadRestored"] boolValue] &&
        [report[@"targetIdentityStable"] boolValue];
    stateRestored = modeRestored && preferredRestored && transportClean;
    journalRemoveError = @"";
    journalRemoved = stateRestored &&
        CNDDiscordAudioRemoveJournal(&journalRemoveError);
    report[@"recoveryJournalRemoved"] = @(journalRemoved);
    report[@"recoveryJournalRemoveError"] = journalRemoveError;
    report[@"restoreCompleted"] = @(stateRestored && journalRemoved);
    report[@"result"] = stateRestored
        ? (journalRemoved ? @"restored-original-discord-audio-state"
                          : @"restored-audio-state-journal-remains")
        : @"failed-original-audio-state-not-restored";

save:
    (void)CNDDiscordAudioWriteReport(
        report, @"CNDDiscordAudioModeRestoreReport.json");
    return [report copy];
}

static void CNDDiscordAudioRun(BOOL restore,
                               CNDDiscordAudioModeProbeCompletion completion)
{
    if (!completion) return;
    if (!__sync_bool_compare_and_swap(
            &gCNDDiscordAudioModeProbeRunning, 0, 1)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-already-running",
                @"message": @"A Discord audio action is already running.",
            });
        });
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary<NSString *, id> *report = restore
            ? CNDDiscordAudioModeRestoreOnce()
            : CNDDiscordAudioModeApplyOnce();
        __sync_lock_release(&gCNDDiscordAudioModeProbeRunning);
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}

void CNDDiscordAudioModeProbeApply(
    CNDDiscordAudioModeProbeCompletion completion)
{
    CNDDiscordAudioRun(NO, completion);
}

void CNDDiscordAudioModeProbeRestore(
    CNDDiscordAudioModeProbeCompletion completion)
{
    CNDDiscordAudioRun(YES, completion);
}
