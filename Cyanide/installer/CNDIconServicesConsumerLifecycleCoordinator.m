#import "CNDIconServicesConsumerLifecycleCoordinator.h"

#import "CNDIconServicesConsumerHook.h"
#import "CNDIconServicesConsumerKernelInstaller.h"
#import "CNDIconServicesConsumerPayload.h"
#import "../LogTextView.h"
#import "../TaskRop/CNDKernelTaskBridge.h"
#import "../TaskRop/RemoteCall.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/CNDLabKernelProvider.h"
#import "../tweaks/snowboardlite.h"

#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <math.h>
#import <notify.h>
#import <os/lock.h>
#import <stdatomic.h>

NSString * const CNDIconServicesConsumerLifecycleDidInstallNotification =
    @"CNDIconServicesConsumerLifecycleDidInstallNotification";

static const uint64_t CNDConsumerLifecycleTickNanoseconds =
    250ULL * NSEC_PER_MSEC;
static const NSTimeInterval CNDConsumerLifecyclePIDSettleSeconds = 0.20;
static const NSTimeInterval CNDConsumerLifecycleInstalledPollSeconds = 2.0;

@interface CNDConsumerLifecycleHostState : NSObject
@property(nonatomic, copy) NSString *name;
@property(nonatomic) pid_t observedPID;
@property(nonatomic) pid_t installedPID;
@property(nonatomic) pid_t blockedPID;
@property(nonatomic) pid_t deferredPID;
@property(nonatomic) NSUInteger stableSamples;
@property(nonatomic) NSUInteger attempts;
@property(nonatomic) NSTimeInterval firstSeen;
@property(nonatomic, copy) NSString *lastStage;
@property(nonatomic, copy) NSString *lastMessage;
@property(nonatomic, copy) NSDictionary<NSString *, id> *lastResult;
@end

@implementation CNDConsumerLifecycleHostState
@end

static dispatch_queue_t gCNDConsumerLifecycleQueue;
static dispatch_source_t gCNDConsumerLifecycleTimer;
static NSMutableDictionary<NSString *, CNDConsumerLifecycleHostState *> *
    gCNDConsumerLifecycleHosts;
/*
 * Application/scene callbacks query this flag from the main thread. They
 * must never synchronously wait behind a process RemoteCall on the lifecycle
 * queue: doing so can exhaust FrontBoard's scene-update watchdog while the
 * target still owns our exception channel. Keep the authoritative running
 * bit atomic and publish richer status through a separately locked snapshot.
 */
static atomic_bool gCNDConsumerLifecycleRunning = ATOMIC_VAR_INIT(false);
static os_unfair_lock gCNDConsumerLifecycleStatusLock = OS_UNFAIR_LOCK_INIT;
static os_unfair_lock gCNDConsumerLifecycleStaticIconLock =
    OS_UNFAIR_LOCK_INIT;
static NSDictionary<NSString *, id> *gCNDConsumerLifecycleStatusSnapshot;
static BOOL gCNDConsumerLifecycleMappingsEnabled;
static double gCNDConsumerLifecycleDisplayScale;
static NSTimeInterval gCNDConsumerLifecycleNextSpotlightPoll;
static int gCNDConsumerLifecycleFrontmostToken = NOTIFY_TOKEN_INVALID;
static NSDictionary<NSString *, NSData *> *
    gCNDConsumerLifecycleStaticDynamicIconData = @{};

static NSDictionary<NSString *, NSData *> *
CNDConsumerLifecycleStaticDynamicIconData(void)
{
    os_unfair_lock_lock(&gCNDConsumerLifecycleStaticIconLock);
    NSDictionary<NSString *, NSData *> *data =
        gCNDConsumerLifecycleStaticDynamicIconData;
    os_unfair_lock_unlock(&gCNDConsumerLifecycleStaticIconLock);
    return data ?: @{};
}

static BOOL CNDConsumerLifecycleRunning(void)
{
    return atomic_load_explicit(&gCNDConsumerLifecycleRunning,
                                memory_order_acquire);
}

static void CNDConsumerLifecycleSetRunning(BOOL running)
{
    atomic_store_explicit(&gCNDConsumerLifecycleRunning, running,
                          memory_order_release);
}

static dispatch_queue_t CNDConsumerLifecycleQueue(void)
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gCNDConsumerLifecycleQueue = dispatch_queue_create(
            "com.zeroxjf.cyanide.icon-consumer-lifecycle",
            DISPATCH_QUEUE_SERIAL);
    });
    return gCNDConsumerLifecycleQueue;
}

static NSTimeInterval CNDConsumerLifecycleNow(void)
{
    return NSProcessInfo.processInfo.systemUptime;
}

static BOOL CNDConsumerLifecycleUsesRemoteCall(void)
{
    /* A vPhone boot can expose the injected RemoteCall backends without
     * granting root task_for_pid. Prefer that verified route whenever its
     * explicit lab credentials are armed; use the VM direct-task installer
     * only when the helper actually advertised that separate capability. */
    return remote_call_lab_backend_opted_in() ||
        !cnd_lab_direct_task_active();
}

static CNDConsumerLifecycleHostState *
CNDConsumerLifecycleState(NSString *name)
{
    CNDConsumerLifecycleHostState *state = gCNDConsumerLifecycleHosts[name];
    if (!state) {
        state = [[CNDConsumerLifecycleHostState alloc] init];
        state.name = name;
        state.lastStage = @"waiting";
        state.lastMessage = @"Waiting for a stable process incarnation.";
        gCNDConsumerLifecycleHosts[name] = state;
    }
    return state;
}

static NSDictionary<NSString *, id> *
CNDConsumerLifecycleHostSnapshot(CNDConsumerLifecycleHostState *state)
{
    if (!state) return @{};
    return @{
        @"process": state.name ?: @"",
        @"observedPID": @(state.observedPID),
        @"installedPID": @(state.installedPID),
        @"attemptedPID": @(state.blockedPID),
        @"deferredPID": @(state.deferredPID),
        @"stableSamples": @(state.stableSamples),
        @"attempts": @(state.attempts),
        @"lastStage": state.lastStage ?: @"",
        @"lastMessage": state.lastMessage ?: @"",
        @"lastResult": state.lastResult ?: @{},
    };
}

static NSDictionary<NSString *, id> *CNDConsumerLifecycleSnapshotLocked(void)
{
    NSMutableDictionary<NSString *, id> *hosts =
        [NSMutableDictionary dictionary];
    [gCNDConsumerLifecycleHosts enumerateKeysAndObjectsUsingBlock:^(
        NSString *name, CNDConsumerLifecycleHostState *state, BOOL *stop) {
        (void)stop;
        hosts[name] = CNDConsumerLifecycleHostSnapshot(state);
    }];
    BOOL running = CNDConsumerLifecycleRunning();
    return @{
        @"ok": @YES,
        @"stage": running ? @"watching" : @"stopped",
        @"message": running
            ? (gCNDConsumerLifecycleMappingsEnabled
                ? (CNDConsumerLifecycleUsesRemoteCall()
                    ? @"The Spotlight-only watcher is armed with one PID-bound Apple-signed flat-image redirect per Spotlight incarnation."
                    : @"The direct VM Spotlight watcher is armed.")
                : @"The Spotlight watcher is armed but presentation mappings are disabled by the toggle.")
            : @"The Spotlight watcher is stopped.",
        @"running": @(running),
        @"mappingsEnabled": @(gCNDConsumerLifecycleMappingsEnabled),
        @"payloadVersion": @(CND_ICON_CONSUMER_PAYLOAD_VERSION),
        @"displayScale": @(gCNDConsumerLifecycleDisplayScale),
        @"spotlightContinuousMonitoring": @YES,
        @"staticDynamicIconCount":
            @(CNDConsumerLifecycleStaticDynamicIconData().count),
        @"hosts": hosts,
        @"remoteCallUsed": @(CNDConsumerLifecycleUsesRemoteCall()),
    };
}

static void CNDConsumerLifecyclePublishSnapshotLocked(void)
{
    NSDictionary<NSString *, id> *snapshot =
        CNDConsumerLifecycleSnapshotLocked();
    os_unfair_lock_lock(&gCNDConsumerLifecycleStatusLock);
    gCNDConsumerLifecycleStatusSnapshot = snapshot;
    os_unfair_lock_unlock(&gCNDConsumerLifecycleStatusLock);
}

static NSDictionary<NSString *, id> *CNDConsumerLifecycleCachedSnapshot(void)
{
    os_unfair_lock_lock(&gCNDConsumerLifecycleStatusLock);
    NSDictionary<NSString *, id> *snapshot =
        gCNDConsumerLifecycleStatusSnapshot;
    os_unfair_lock_unlock(&gCNDConsumerLifecycleStatusLock);
    if (snapshot) return snapshot;

    return @{
        @"ok": @YES,
        @"stage": @"stopped",
        @"message": @"The presentation lifecycle watcher is stopped.",
        @"running": @NO,
        @"mappingsEnabled": @NO,
        @"payloadVersion": @(CND_ICON_CONSUMER_PAYLOAD_VERSION),
        @"displayScale": @0,
        @"spotlightContinuousMonitoring": @YES,
        @"hosts": @{},
        @"remoteCallUsed": @NO,
    };
}

static void CNDConsumerLifecycleResetObserved(
    CNDConsumerLifecycleHostState *state)
{
    state.observedPID = 0;
    state.stableSamples = 0;
    state.attempts = 0;
    state.firstSeen = 0;
    state.lastResult = @{};
    state.deferredPID = 0;
}

static void CNDConsumerLifecycleAttemptInstall(
    CNDConsumerLifecycleHostState *state,
    BOOL afterThemeMutation)
{
    pid_t pid = state.observedPID;
    if (pid <= 1 || pid == state.installedPID || pid == state.blockedPID) {
        return;
    }

    state.attempts++;
    BOOL usesRemoteCall = CNDConsumerLifecycleUsesRemoteCall();
    BOOL targetUsesRemoteCall = usesRemoteCall;
    log_user("[SBR_WATCHER] installing target=%s pid=%d version=%llu "
             "attempt=%lu transport=%s remote-call=%s\n",
             state.name.UTF8String ?: "", pid,
             (unsigned long long)CND_ICON_CONSUMER_PAYLOAD_VERSION,
             (unsigned long)state.attempts,
             usesRemoteCall
                ? "apple-signed-imp-remotecall"
                : "vm-direct-task",
             targetUsesRemoteCall ? "yes" : "no");
    BOOL isSpringBoard = [state.name isEqualToString:@"SpringBoard"];
    NSDictionary<NSString *, NSData *> *staticDynamicIcons =
        CNDConsumerLifecycleStaticDynamicIconData();
    NSDictionary<NSString *, id> *result = usesRemoteCall
        ? CNDIconServicesConsumerHookInstallForPIDWithOptions(
            pid, state.name, gCNDConsumerLifecycleDisplayScale,
            staticDynamicIcons,
            afterThemeMutation && isSpringBoard,
            isSpringBoard || staticDynamicIcons.count > 0)
        : CNDIconServicesConsumerKernelInstallForPID(
            pid, state.name, gCNDConsumerLifecycleDisplayScale);
    BOOL ok = [result[@"ok"] boolValue];
    NSString *stage = [result[@"stage"] isKindOfClass:NSString.class]
        ? result[@"stage"] : @"unknown";
    NSString *message = [result[@"message"] isKindOfClass:NSString.class]
        ? result[@"message"] : @"The installer returned no message.";
    state.lastStage = stage;
    state.lastMessage = message;
    state.lastResult = result ?: @{};

    /* The process can disappear while the task channel is in flight. Never
     * credit the result to a replacement process that reused the name. */
    NSError *identityError = nil;
    pid_t livePID = CNDKernelTaskBridgeResolveProcessPID(
        state.name, &identityError);
    if (ok && livePID == pid) {
        state.installedPID = pid;
        state.blockedPID = 0;
        log_user("[SBR_WATCHER] ready target=%s pid=%d stage=%s "
                 "redirects=%d transport=%s time=%.3fms\n",
                 state.name.UTF8String ?: "", pid,
                 stage.UTF8String ?: "",
                 [result[@"installedCount"] intValue],
                 [result[@"mappingTransport"] UTF8String] ?: "unknown",
                 [result[@"elapsedMilliseconds"] doubleValue]);
        [[NSNotificationCenter defaultCenter]
            postNotificationName:
                CNDIconServicesConsumerLifecycleDidInstallNotification
                          object:nil
                        userInfo:@{
                            @"process": state.name ?: @"",
                            @"pid": @(pid),
                            @"payloadVersion": @(
                                CND_ICON_CONSUMER_PAYLOAD_VERSION),
                            @"result": result ?: @{},
                        }];
        return;
    }
    if (ok && livePID != pid) {
        state.lastStage = @"post-install-identity";
        state.lastMessage = @"The target PID changed immediately after installation.";
        CNDConsumerLifecycleResetObserved(state);
        return;
    }

    BOOL safeDormantRetry = !usesRemoteCall &&
        [state.name isEqualToString:@"Spotlight"] &&
        [result[@"mappingAddress"] unsignedLongLongValue] == 0 &&
        ![result[@"targetExecutionObserved"] boolValue] &&
        ([result[@"targetExecutionProvenAbsent"] boolValue] ||
         [stage isEqualToString:@"task-open"]);
    if (safeDormantRetry) {
        state.blockedPID = 0;
        state.deferredPID = pid;
        state.lastStage = @"sleeping-pending";
        state.lastMessage =
            @"Resident Spotlight did not execute the bootstrap while idle; no payload mapping remains, and foreground activation will retry safely.";
        log_user("[SBR_WATCHER] deferred target=Spotlight pid=%d "
                 "target-execution=no mapping-retained=no retry=foreground\n",
                 pid);
        return;
    }

    /* One process incarnation receives at most one installer channel. An
     * explicit watcher restart can retry the same PID after inspection; the
     * automatic loop waits for a genuinely new PID. */
    state.blockedPID = pid;
    log_user("[SBR_WATCHER] install failed target=%s pid=%d stage=%s "
             "attempted-once=yes message=%s\n",
             state.name.UTF8String ?: "", pid,
             stage.UTF8String ?: "",
             message.UTF8String ?: "");
}

static void CNDConsumerLifecyclePollHost(
    CNDConsumerLifecycleHostState *state, NSTimeInterval now)
{
    NSError *error = nil;
    pid_t pid = CNDKernelTaskBridgeResolveProcessPID(state.name, &error);
    if (pid <= 1) {
        if (state.observedPID > 1) {
            log_user("[SBR_WATCHER] departed target=%s old-pid=%d\n",
                     state.name.UTF8String ?: "", state.observedPID);
            CNDConsumerLifecycleResetObserved(state);
            state.installedPID = 0;
            state.blockedPID = 0;
            state.lastStage = @"process-unavailable";
            state.lastMessage = @"Waiting for the next process incarnation.";
        }
        return;
    }
    if (state.observedPID != pid) {
        pid_t oldPID = state.observedPID;
        state.observedPID = pid;
        state.installedPID = state.installedPID == pid
            ? state.installedPID : 0;
        state.blockedPID = state.blockedPID == pid ? state.blockedPID : 0;
        state.deferredPID = state.deferredPID == pid ? state.deferredPID : 0;
        state.stableSamples = 1;
        state.attempts = 0;
        state.firstSeen = now;
        state.lastStage = @"pid-observed";
        state.lastMessage = @"A new process incarnation is settling.";
        log_user("[SBR_WATCHER] observed target=%s old-pid=%d new-pid=%d\n",
                 state.name.UTF8String ?: "", oldPID, pid);
    } else if (state.stableSamples < NSUIntegerMax) {
        state.stableSamples++;
    }

    if (state.installedPID == pid || state.blockedPID == pid ||
        state.deferredPID == pid ||
        state.stableSamples < 2 ||
        now - state.firstSeen < CNDConsumerLifecyclePIDSettleSeconds) return;
    CNDConsumerLifecycleAttemptInstall(state, NO);
}

static void CNDConsumerLifecycleTick(void)
{
    if (!CNDConsumerLifecycleRunning()) return;
    BOOL mappingsEnabled = [NSUserDefaults.standardUserDefaults
        boolForKey:kSettingsSnowBoardRemixInstallConsumerMappings];
    if (mappingsEnabled != gCNDConsumerLifecycleMappingsEnabled) {
        gCNDConsumerLifecycleMappingsEnabled = mappingsEnabled;
        if (mappingsEnabled) {
            gCNDConsumerLifecycleNextSpotlightPoll = 0;
        }
        log_user("[SBR_WATCHER] presentation mappings %s; watcher %s.\n",
                 mappingsEnabled ? "enabled" : "disabled",
                 mappingsEnabled ? "resumed" : "paused");
    }
    if (!mappingsEnabled || !kexploit_krw_ready()) {
        CNDConsumerLifecyclePublishSnapshotLocked();
        return;
    }

    @autoreleasepool {
        NSTimeInterval now = CNDConsumerLifecycleNow();
        if (now >= gCNDConsumerLifecycleNextSpotlightPoll) {
            CNDConsumerLifecycleHostState *spotlight =
                CNDConsumerLifecycleState(@"Spotlight");
            CNDConsumerLifecyclePollHost(spotlight, now);
            gCNDConsumerLifecycleNextSpotlightPoll =
                (spotlight.installedPID > 1 || spotlight.blockedPID > 1 ||
                 spotlight.deferredPID > 1)
                    ? now + CNDConsumerLifecycleInstalledPollSeconds
                    : now + 0.25;
        }
    }
    CNDConsumerLifecyclePublishSnapshotLocked();
}

static void CNDConsumerLifecycleAccelerateSpotlightLocked(void)
{
    if (!CNDConsumerLifecycleRunning()) return;
    gCNDConsumerLifecycleNextSpotlightPoll = 0;
    CNDConsumerLifecycleHostState *spotlight =
        CNDConsumerLifecycleState(@"Spotlight");
    if (spotlight.deferredPID == spotlight.observedPID) {
        spotlight.deferredPID = 0;
        spotlight.lastStage = @"foreground-retry";
        spotlight.lastMessage =
            @"Foreground activation requested a safe retry for the resident PID.";
    }
    log_user("[SBR_WATCHER] Spotlight foreground transition observed; "
             "accelerating resident PID verification (not an eligibility "
             "gate).\n");
    CNDConsumerLifecyclePublishSnapshotLocked();
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerLifecycleStart(double displayScale)
{
    __block NSDictionary<NSString *, id> *result = nil;
    dispatch_sync(CNDConsumerLifecycleQueue(), ^{
        if (CNDConsumerLifecycleRunning()) {
            result = CNDConsumerLifecycleSnapshotLocked();
            return;
        }
        if (!isfinite(displayScale) || displayScale < 1.0 ||
            displayScale > 4.0) {
            result = @{
                @"ok": @NO, @"stage": @"display-scale",
                @"message": @"A valid display scale is required.",
                @"remoteCallUsed": @NO,
            };
            return;
        }
        if (!kexploit_krw_ready()) {
            result = @{
                @"ok": @NO, @"stage": @"krw-unavailable",
            @"message": @"Kernel read/write must already be armed before starting the Spotlight watcher.",
                @"remoteCallUsed": @NO,
            };
            return;
        }

        gCNDConsumerLifecycleHosts = [NSMutableDictionary dictionary];
        CNDConsumerLifecycleState(@"Spotlight");
        gCNDConsumerLifecycleDisplayScale = displayScale;
        gCNDConsumerLifecycleMappingsEnabled =
            [NSUserDefaults.standardUserDefaults
                boolForKey:kSettingsSnowBoardRemixInstallConsumerMappings];
        gCNDConsumerLifecycleNextSpotlightPoll = 0;

        int frontmostStatus = notify_register_dispatch(
            "com.apple.springboard.frontmostApplicationChanged",
            &gCNDConsumerLifecycleFrontmostToken,
            CNDConsumerLifecycleQueue(), ^(int token) {
                (void)token;
                CNDConsumerLifecycleAccelerateSpotlightLocked();
            });
        if (frontmostStatus != NOTIFY_STATUS_OK) {
            if (gCNDConsumerLifecycleFrontmostToken != NOTIFY_TOKEN_INVALID) {
                notify_cancel(gCNDConsumerLifecycleFrontmostToken);
                gCNDConsumerLifecycleFrontmostToken = NOTIFY_TOKEN_INVALID;
            }
            result = @{
                @"ok": @NO, @"stage": @"lifecycle-notifications",
                @"message": @"The Spotlight foreground notification could not be registered safely.",
                @"frontmostStatus": @(frontmostStatus),
                @"remoteCallUsed": @NO,
            };
            return;
        }

        CNDConsumerLifecycleSetRunning(YES);
        gCNDConsumerLifecycleTimer = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
            CNDConsumerLifecycleQueue());
        dispatch_source_set_timer(
            gCNDConsumerLifecycleTimer, DISPATCH_TIME_NOW,
            CNDConsumerLifecycleTickNanoseconds,
            20ULL * NSEC_PER_MSEC);
        dispatch_source_set_event_handler(
            gCNDConsumerLifecycleTimer, ^{
                CNDConsumerLifecycleTick();
            });
        dispatch_resume(gCNDConsumerLifecycleTimer);
        result = CNDConsumerLifecycleSnapshotLocked();
        CNDConsumerLifecyclePublishSnapshotLocked();
        log_user("[SBR_WATCHER] Spotlight-only watcher armed interval=250ms "
                 "pid-settle=200ms spotlight=resident-continuous "
                 "version=%llu mappings=%s transport=%s remote-call=%s.\n",
                 (unsigned long long)CND_ICON_CONSUMER_PAYLOAD_VERSION,
                 gCNDConsumerLifecycleMappingsEnabled ? "enabled" : "disabled",
                 CNDConsumerLifecycleUsesRemoteCall()
                    ? "apple-signed-imp-remotecall" : "vm-direct-task",
                 CNDConsumerLifecycleUsesRemoteCall() ? "yes" : "no");
    });
    return result;
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerLifecycleStop(void)
{
    __block NSDictionary<NSString *, id> *result = nil;
    dispatch_sync(CNDConsumerLifecycleQueue(), ^{
        if (gCNDConsumerLifecycleTimer) {
            dispatch_source_cancel(gCNDConsumerLifecycleTimer);
            gCNDConsumerLifecycleTimer = nil;
        }
        if (gCNDConsumerLifecycleFrontmostToken != NOTIFY_TOKEN_INVALID) {
            notify_cancel(gCNDConsumerLifecycleFrontmostToken);
            gCNDConsumerLifecycleFrontmostToken = NOTIFY_TOKEN_INVALID;
        }
        BOOL wasRunning = CNDConsumerLifecycleRunning();
        CNDConsumerLifecycleSetRunning(NO);
        result = @{
            @"ok": @YES, @"stage": @"stopped",
            @"message": wasRunning
                ? @"The watcher stopped. Existing process-local presentation redirects remain until their host exits."
                : @"The watcher was already stopped.",
            @"running": @NO,
            @"remoteCallUsed": @NO,
        };
        if (wasRunning) {
            log_user("[SBR_WATCHER] Spotlight watcher stopped; existing "
                     "process-local method redirects remain until host exit.\n");
        }
        CNDConsumerLifecyclePublishSnapshotLocked();
    });
    return result;
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerLifecycleStatus(void)
{
    return CNDConsumerLifecycleCachedSnapshot();
}

BOOL CNDIconServicesConsumerLifecycleIsRunning(void)
{
    return CNDConsumerLifecycleRunning();
}

void CNDIconServicesConsumerLifecycleSetStaticDynamicIconData(
    NSDictionary<NSString *, NSData *> *imageDataByBundle)
{
    NSMutableDictionary<NSString *, NSData *> *sanitized =
        [NSMutableDictionary dictionaryWithCapacity:8];
    for (NSString *bundleIdentifier in @[
            @"com.apple.mobiletimer", @"com.apple.mobilecal",
            @"__cnd_calendar_68_structured",
            @"__cnd_calendar_68_structured_a1",
            @"__cnd_clock_hours", @"__cnd_clock_minutes",
            @"__cnd_clock_seconds", @"__cnd_clock_hour_minute_dot",
            @"__cnd_clock_second_dot", @"__cnd_clock_background"]) {
        NSData *data = [imageDataByBundle[bundleIdentifier]
            isKindOfClass:NSData.class]
            ? imageDataByBundle[bundleIdentifier] : nil;
        if (data.length > 0) sanitized[bundleIdentifier] = data;
    }
    NSDictionary<NSString *, NSData *> *staged = [sanitized copy];
    os_unfair_lock_lock(&gCNDConsumerLifecycleStaticIconLock);
    gCNDConsumerLifecycleStaticDynamicIconData = staged;
    os_unfair_lock_unlock(&gCNDConsumerLifecycleStaticIconLock);
    NSUInteger clockComponents = 0;
    for (NSString *componentKey in @[
            @"__cnd_clock_hours", @"__cnd_clock_minutes",
            @"__cnd_clock_seconds", @"__cnd_clock_hour_minute_dot",
            @"__cnd_clock_second_dot"]) {
        if (staged[componentKey]) clockComponents++;
    }
    log_user("[SBR_DYNAMIC_ICONS] staged payloads=%lu clock=%s calendar=%s "
             "calendar-68=%s/%s clock-components=%lu/5 background=%s\n",
             (unsigned long)staged.count,
             staged[@"com.apple.mobiletimer"] ? "yes" : "no",
             staged[@"com.apple.mobilecal"] ? "yes" : "no",
             staged[@"__cnd_calendar_68_structured"] ? "a0" : "-",
             staged[@"__cnd_calendar_68_structured_a1"] ? "a1" : "-",
             (unsigned long)clockComponents,
             staged[@"__cnd_clock_background"] ? "yes" : "no");
    /* Snapshot publication is informational. Never synchronously wait on the
     * lifecycle queue here: Apply/Restore can be called from a notification
     * emitted while that queue owns a target process session. */
    dispatch_async(CNDConsumerLifecycleQueue(), ^{
        CNDConsumerLifecyclePublishSnapshotLocked();
    });
}

static NSDictionary<NSString *, id> *
CNDConsumerLifecycleRepairProcess(NSString *processName,
                                  double displayScale,
                                  BOOL afterThemeMutation)
{
    BOOL allowed = [processName isEqualToString:@"SpringBoard"] ||
        [processName isEqualToString:@"Spotlight"];
    if (!allowed) {
        return @{
            @"ok": @NO,
            @"stage": @"invalid-process",
            @"message": @"Only SpringBoard or Spotlight can receive a manual presentation repair.",
            @"process": processName ?: @"",
            @"remoteCallUsed": @NO,
        };
    }
    if (!isfinite(displayScale) || displayScale < 1.0 ||
        displayScale > 4.0) {
        return @{
            @"ok": @NO,
            @"stage": @"display-scale",
            @"message": @"A valid display scale is required.",
            @"process": processName,
            @"remoteCallUsed": @NO,
        };
    }
    if (!kexploit_krw_ready()) {
        return @{
            @"ok": @NO,
            @"stage": @"krw-unavailable",
            @"message": @"Kernel read/write is unavailable for the manual presentation repair.",
            @"process": processName,
            @"remoteCallUsed": @NO,
        };
    }

    NSError *identityError = nil;
    pid_t pid = CNDKernelTaskBridgeResolveProcessPID(
        processName, &identityError);
    if (pid <= 1) {
        return @{
            @"ok": @NO,
            @"stage": @"process-unavailable",
            @"message": identityError.localizedDescription ?:
                [NSString stringWithFormat:
                    @"%@ is not currently resident.", processName],
            @"process": processName,
            @"remoteCallUsed": @NO,
        };
    }

    /* Reserve this PID using only a short lifecycle-queue critical section.
     * The old implementation kept the serial queue locked across the entire
     * RemoteCall. A completed SpringBoard repair could therefore leave the
     * Spotlight button blocked behind teardown/status publication, which
     * looked like an immediate hang. The target operation must never own the
     * watcher/state queue. */
    dispatch_sync(CNDConsumerLifecycleQueue(), ^{
        if (!gCNDConsumerLifecycleHosts) {
            gCNDConsumerLifecycleHosts = [NSMutableDictionary dictionary];
        }
        gCNDConsumerLifecycleDisplayScale = displayScale;
        CNDConsumerLifecycleHostState *state =
            CNDConsumerLifecycleState(processName);
        state.observedPID = pid;
        state.installedPID = 0;
        state.blockedPID = pid;
        state.deferredPID = 0;
        state.stableSamples = 2;
        state.attempts = 1;
        state.firstSeen = CNDConsumerLifecycleNow() -
            CNDConsumerLifecyclePIDSettleSeconds;
        state.lastStage = @"manual-repair-running";
        state.lastMessage = [NSString stringWithFormat:
            @"A bounded manual %@ presentation repair is running.",
            processName];
        state.lastResult = @{};
        CNDConsumerLifecyclePublishSnapshotLocked();
    });

    BOOL usesRemoteCall = CNDConsumerLifecycleUsesRemoteCall();
    BOOL isSpringBoard = [processName isEqualToString:@"SpringBoard"];
    NSDictionary<NSString *, NSData *> *staticDynamicIcons =
        CNDConsumerLifecycleStaticDynamicIconData();
    log_user("[SBR_PRESENTATION] manual repair target=%s pid=%d "
             "queue-held=no transport=%s\n",
             processName.UTF8String ?: "", pid,
             usesRemoteCall ? "apple-signed-imp-remotecall" :
                 "vm-direct-task");
    NSDictionary<NSString *, id> *install = usesRemoteCall
        ? CNDIconServicesConsumerHookInstallForPIDWithOptions(
            pid, processName, displayScale,
            staticDynamicIcons,
            afterThemeMutation && isSpringBoard,
            YES)
        : CNDIconServicesConsumerKernelInstallForPID(
            pid, processName, displayScale);
    install = install ?: @{};

    NSError *liveIdentityError = nil;
    pid_t livePID = CNDKernelTaskBridgeResolveProcessPID(
        processName, &liveIdentityError);
    BOOL installOK = [install[@"ok"] boolValue];
    BOOL ok = installOK && livePID == pid;
    BOOL transparencyReady = livePID == pid &&
        (installOK || [install[@"transparencyVerified"] boolValue]);
    NSString *installStage = [install[@"stage"] isKindOfClass:NSString.class]
        ? install[@"stage"] : @"manual-presentation-repair";
    NSString *installMessage =
        [install[@"message"] isKindOfClass:NSString.class]
            ? install[@"message"]
            : @"The manual presentation repair did not verify.";

    dispatch_sync(CNDConsumerLifecycleQueue(), ^{
        CNDConsumerLifecycleHostState *state =
            CNDConsumerLifecycleState(processName);
        state.lastResult = install;
        if (transparencyReady) {
            state.observedPID = pid;
            state.installedPID = pid;
            state.blockedPID = 0;
            state.lastStage = ok ? installStage : @"presentation-ready-tweaks-partial";
            state.lastMessage = ok ? installMessage :
                @"Transparency is verified; the requested dynamic-icon work is incomplete.";
        } else if (livePID != pid) {
            state.installedPID = 0;
            state.blockedPID = 0;
            state.observedPID = livePID > 1 ? livePID : 0;
            state.stableSamples = 0;
            state.lastStage = @"post-install-identity";
            state.lastMessage = liveIdentityError.localizedDescription ?:
                @"The target PID changed during manual repair.";
        } else {
            state.installedPID = 0;
            state.blockedPID = pid;
            state.lastStage = installStage;
            state.lastMessage = installMessage;
        }
        CNDConsumerLifecyclePublishSnapshotLocked();
    });

    if (transparencyReady) {
        [[NSNotificationCenter defaultCenter]
            postNotificationName:
                CNDIconServicesConsumerLifecycleDidInstallNotification
                      object:nil
                    userInfo:@{
                        @"process": processName,
                        @"pid": @(pid),
                        @"payloadVersion": @(
                            CND_ICON_CONSUMER_PAYLOAD_VERSION),
                        @"result": install,
                    }];
    }

    return @{
        @"ok": @(ok),
        @"stage": ok ? @"manual-presentation-ready" :
            @"manual-presentation-repair",
        @"message": ok
            ? [NSString stringWithFormat:
                @"%@ presentation repair is installed and verified for PID %d.",
                processName, pid]
            : (livePID != pid
                ? @"The target process changed during manual repair."
                : installMessage),
        @"process": processName,
        @"pid": @(pid),
        @"install": install,
        @"transparencyVerified": @(transparencyReady),
        @"remoteCallUsed": install[@"remoteCallUsed"] ?: @(usesRemoteCall),
    };
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerLifecycleRepairProcess(NSString *processName,
                                               double displayScale)
{
    return CNDConsumerLifecycleRepairProcess(processName, displayScale, NO);
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerLifecycleRepairAfterThemeMutation(
    NSString *processName, double displayScale)
{
    return CNDConsumerLifecycleRepairProcess(
        processName, displayScale, YES);
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerLifecycleRefreshSpringBoardCaches(void)
{
    __block NSDictionary<NSString *, id> *result = nil;
    dispatch_sync(CNDConsumerLifecycleQueue(), ^{
        if (!kexploit_krw_ready()) {
            result = @{
                @"ok": @NO,
                @"stage": @"krw-unavailable",
                @"message": @"Kernel read/write is unavailable for the SpringBoard cache refresh.",
                @"process": @"SpringBoard",
                @"remoteCallUsed": @NO,
            };
            return;
        }
        NSError *identityError = nil;
        pid_t pid = CNDKernelTaskBridgeResolveProcessPID(
            @"SpringBoard", &identityError);
        if (pid <= 1) {
            result = @{
                @"ok": @NO,
                @"stage": @"process-unavailable",
                @"message": identityError.localizedDescription ?:
                    @"SpringBoard is not currently resident.",
                @"process": @"SpringBoard",
                @"remoteCallUsed": @NO,
            };
            return;
        }
        log_user("[SBR_PRESENTATION] post-publication cache refresh "
                 "target=SpringBoard pid=%d redirects=no watcher=no\n", pid);
        result = CNDIconServicesConsumerHookRefreshSpringBoardForPID(pid);
    });
    return result ?: @{
        @"ok": @NO,
        @"stage": @"cache-refresh",
        @"message": @"The SpringBoard cache refresh returned no result.",
        @"process": @"SpringBoard",
        @"remoteCallUsed": @NO,
    };
}

void CNDIconServicesConsumerLifecycleNoteForegroundTransition(void)
{
    dispatch_async(CNDConsumerLifecycleQueue(), ^{
        CNDConsumerLifecycleAccelerateSpotlightLocked();
    });
}
