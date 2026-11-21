//
//  AppDelegate.m
//  Cyanide
//
//  Created by seo on 3/24/26.
//

#import "AppDelegate.h"
#import "SettingsViewController.h"
#import "LogTextView.h"
#import "probes/CNDPhysicalEntitlementAuditProbe.h"
#import "probes/CNDPhysicalIOUserEthernetSignerProbe.h"
#import "probes/CNDAudioCodecs86969Probe.h"
#import "probes/CNDPhysicalKCall1Probe.h"
#import "probes/CNDUatObserverProbe.h"
#import "probes/CNDUatContextProbe.h"
#import "probes/CNDUatQueueProbe.h"
#import "probes/CNDUatHardwareProbe.h"
#import "probes/CNDUatE1ObserveProbe.h"
#import "probes/CNDAGXFirmwarePreflightProbe.h"
#import "probes/CNDDiscordAudioModeProbe.h"
#import "probes/CyanideLabBridge.h"
#import "kexploit/kexploit_opa334.h"
#import "kexploit/persistence.h"
#import <notify.h>
#import <signal.h>
#import <sys/stat.h>
#import <sys/utsname.h>
#import <unistd.h>

@interface AppDelegate ()

@end

static dispatch_source_t g_sigterm_source;
static int g_lab_pm_cross_class_notification_token;
static int g_lab_pm_m68_notification_token;
static NSString *g_updateHandoffRequestID;

@implementation AppDelegate



#pragma mark - host-driven command watcher

// Runs a probe inside the *live* process instead of relaunching it. The supported
// host path opens com.zeroxjf.ios-cyanide1://probe/<command>, which UIKit delivers
// to this process through SceneDelegate. Do not use CoreDevice appDataContainer
// transfer as a command channel: opening that file service terminates the app,
// parks its socket-backed KRW, and defeats same-process reuse.
static NSString *CNDCmdPath(NSString *name)
{
    NSString *dir = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return dir != nil ? [dir stringByAppendingPathComponent:name] : nil;
}

static void CNDCmdWriteJSON(NSString *name, NSDictionary *payload)
{
    NSString *path = CNDCmdPath(name);
    if (path == nil || payload == nil) {
        return;
    }
    NSData *data = [NSJSONSerialization dataWithJSONObject:payload
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:nil];
    if (data != nil) {
        (void)[data writeToFile:path options:NSDataWritingAtomic error:nil];
    }
}

// Host state never calls checked readiness. The additive lifecycle evidence is
// the latest immutable observation published by an actual lifecycle owner.
// Lock-free: never call KRW helpers from a timer handler that other work depends
// on, because they take the lock a running probe holds.
static void CNDCmdPublishStateNoKrw(void)
{
    CNDCmdWriteJSON(@"cnd-state.json", @{
        @"krwReady": @(-1),
        @"krwLifecycle":
            settings_current_krw_lifecycle_snapshot().agentRepresentation,
        @"pid": @(getpid()),
        @"at": @([[NSDate date] timeIntervalSince1970]),
    });
}

// A probe must survive the screen locking mid-run; without this the app can be
// suspended between reads.
static UIBackgroundTaskIdentifier CNDCmdBeginProbeTask(NSString *name)
{
    UIApplication *app = [UIApplication sharedApplication];
    if (app == nil) {
        return UIBackgroundTaskInvalid;
    }
    return [app beginBackgroundTaskWithName:name expirationHandler:^{
        log_user("[CND_CMD] background task %s expired\n", name.UTF8String);
    }];
}

static void CNDCmdEndProbeTask(UIBackgroundTaskIdentifier task)
{
    if (task != UIBackgroundTaskInvalid) {
        [[UIApplication sharedApplication] endBackgroundTask:task];
    }
}

typedef void (^CNDCmdResultHandler)(NSDictionary<NSString *, id> *report);

static dispatch_queue_t CNDCmdExecutionQueue(void)
{
    static dispatch_queue_t queue;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        queue = dispatch_queue_create(
            "com.zeroxjf.cyanide.host-krw-commands",
            DISPATCH_QUEUE_SERIAL);
    });
    return queue;
}

static NSObject *CNDCmdReplyLock(void)
{
    static NSObject *lock;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSObject new]; });
    return lock;
}

static NSString *CNDCmdCurrentUpdateHandoffRequestID(void)
{
    @synchronized (CNDCmdReplyLock()) {
        return [g_updateHandoffRequestID copy] ?: @"";
    }
}

static NSDictionary *CNDCmdTerminationPayload(
    NSString *reason, CNDKRWTerminationDisposition disposition)
{
    return @{
        @"reason": reason ?: @"unknown",
        @"pid": @(getpid()),
        @"disposition":
            @(kexploit_termination_disposition_name(disposition)),
        @"handoffRequestID": CNDCmdCurrentUpdateHandoffRequestID(),
        @"recoveryStage": @(krw_persistence_last_recovery_stage()),
        @"tokenBurn": @(krw_persistence_last_recovery_token_burn()),
        @"nextProcessArmed": @(krw_persistence_next_process_armed()),
        @"handoffSerial": @(krw_persistence_current_handoff_serial()),
        @"generationID": krw_persistence_current_generation_id() ?: @"",
        @"at": @([[NSDate date] timeIntervalSince1970]),
    };
}

static NSString *g_cmdReplyRequestID;
static NSString *g_cmdReplyCommand;
static NSDictionary<NSString *, id> *g_cmdReplyResult;
static BOOL g_cmdReplyComplete;
static NSUInteger g_cmdReplyGeneration;

static BOOL CNDCmdValidHexCredential(NSString *value,
                                     NSUInteger minimum,
                                     NSUInteger maximum)
{
    if (![value isKindOfClass:NSString.class] ||
        value.length < minimum || value.length > maximum) {
        return NO;
    }
    NSCharacterSet *notHex = [[NSCharacterSet
        characterSetWithCharactersInString:@"0123456789abcdefABCDEF"]
        invertedSet];
    return [value rangeOfCharacterFromSet:notHex].location == NSNotFound;
}

static void CNDCmdCompleteLiveReply(NSString *requestID,
                                    NSDictionary<NSString *, id> *report)
{
    @synchronized (CNDCmdReplyLock()) {
        if (![g_cmdReplyRequestID isEqualToString:requestID] ||
            g_cmdReplyComplete) {
            return;
        }
        g_cmdReplyResult = [report copy] ?: @{};
        g_cmdReplyComplete = YES;
    }
}

static BOOL CNDCmdStartLiveReply(NSString *requestID,
                                 NSString *token,
                                 NSString *command)
{
    if (!CNDCmdValidHexCredential(requestID, 32, 64) ||
        !CNDCmdValidHexCredential(token, 64, 128)) {
        log_user("[CND_CMD] refused invalid live-reply credentials\n");
        return NO;
    }

    __block NSUInteger generation = 0;
    @synchronized (CNDCmdReplyLock()) {
        if (g_cmdReplyRequestID != nil) {
            log_user("[CND_CMD] refused overlapping live-reply request\n");
            return NO;
        }
        g_cmdReplyRequestID = [requestID copy];
        g_cmdReplyCommand = [command copy];
        g_cmdReplyResult = nil;
        g_cmdReplyComplete = NO;
        generation = ++g_cmdReplyGeneration;
    }

    NSError *error = nil;
    BOOL started = cyanide_lab_bridge_start_with_token(
        ^NSDictionary *(NSDictionary *request) {
            NSString *incomingID = [request[@"requestID"]
                isKindOfClass:NSString.class] ? request[@"requestID"] : @"";
            NSString *operation = [request[@"command"]
                isKindOfClass:NSString.class] ? request[@"command"] : @"";
            NSDictionary *result = nil;
            NSString *registeredCommand = nil;
            BOOL complete = NO;
            @synchronized (CNDCmdReplyLock()) {
                if (![g_cmdReplyRequestID isEqualToString:incomingID]) {
                    return @{ @"ok": @NO,
                              @"error": @"request-mismatch",
                              @"message": @"The live-reply request ID did not match.",
                              @"protocolVersion": @1 };
                }
                result = g_cmdReplyResult;
                registeredCommand = g_cmdReplyCommand;
                complete = g_cmdReplyComplete;
            }
            if ([operation isEqualToString:@"probe.result"]) {
                NSMutableDictionary *response = [@{
                    @"ok": @YES,
                    @"status": complete ? @"complete" : @"pending",
                    @"requestID": incomingID,
                    @"command": registeredCommand ?: @"",
                    @"pid": @(getpid()),
                    @"protocolVersion": @1,
                } mutableCopy];
                if (complete) response[@"result"] = result ?: @{};
                return response;
            }
            if ([operation isEqualToString:@"probe.ack"] && complete) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                    (int64_t)(250 * NSEC_PER_MSEC)),
                    dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                        cyanide_lab_bridge_stop();
                    });
                return @{ @"ok": @YES, @"status": @"acknowledged",
                          @"requestID": incomingID,
                          @"protocolVersion": @1 };
            }
            return @{ @"ok": @NO, @"error": @"invalid-probe-request",
                      @"message": @"Use probe.result, then probe.ack after completion.",
                      @"protocolVersion": @1 };
        }, ^{
            @synchronized (CNDCmdReplyLock()) {
                if ([g_cmdReplyRequestID isEqualToString:requestID]) {
                    g_cmdReplyRequestID = nil;
                    g_cmdReplyCommand = nil;
                    g_cmdReplyResult = nil;
                    g_cmdReplyComplete = NO;
                }
            }
        }, token, &error);
    if (!started) {
        @synchronized (CNDCmdReplyLock()) {
            if ([g_cmdReplyRequestID isEqualToString:requestID]) {
                g_cmdReplyRequestID = nil;
                g_cmdReplyCommand = nil;
                g_cmdReplyResult = nil;
                g_cmdReplyComplete = NO;
            }
        }
        log_user("[CND_CMD] live-reply bridge refused: %s\n",
                 error.localizedDescription.UTF8String ?: "unknown error");
        return NO;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
        (int64_t)(120 * NSEC_PER_SEC)),
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            BOOL expired = NO;
            @synchronized (CNDCmdReplyLock()) {
                expired = g_cmdReplyGeneration == generation &&
                    [g_cmdReplyRequestID isEqualToString:requestID];
            }
            if (expired) {
                log_user("[CND_CMD] live-reply bridge expired request=%s\n",
                         requestID.UTF8String);
                cyanide_lab_bridge_stop();
            }
        });
    return YES;
}

static void CNDCmdRun(NSString *command, const char *source,
                      NSString *requestID,
                      CNDCmdResultHandler resultHandler)
{
    NSString *cmd = [command stringByTrimmingCharactersInSet:
        [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (cmd.length == 0) {
        return;
    }
    NSString *sourceName = source != NULL
        ? [NSString stringWithUTF8String:source] : @"unknown";
    log_user("[CND_CMD] accepted %s via %s in pid=%d\n",
             cmd.UTF8String, sourceName.UTF8String, getpid());

    if ([cmd isEqualToString:@"krw-diagnostic"]) {
        /* This path must remain usable precisely when KRW is not ready. It
         * returns cached/persisted evidence only, on the caller's thread;
         * no probe task, lifecycle lease, readiness, recovery, or cleanup. */
        if (resultHandler == nil) {
            log_user("[CND_CMD] refused diagnostic without live reply\n");
            return;
        }
        resultHandler(@{
            @"command": cmd,
            @"result": @"pass-read-only-evidence",
            @"evidenceOnly": @YES,
            @"recoveryRan": @NO,
            @"acquisitionRan": @NO,
            @"readinessChecked": @NO,
            @"socketOperationPerformed": @NO,
            @"pid": @(getpid()),
            @"at": @([[NSDate date] timeIntervalSince1970]),
            @"krwLifecycle":
                settings_current_krw_lifecycle_snapshot().agentRepresentation,
            @"persistence": krw_persistence_diagnostic_snapshot(),
            @"processSocket": kexploit_krw_socket_diagnostic_snapshot(),
            @"termination":
                krw_persistence_termination_diagnostic_snapshot(),
        });
        return;
    }
    UIBackgroundTaskIdentifier task = CNDCmdBeginProbeTask(@"cnd-probe");
    dispatch_async(CNDCmdExecutionQueue(), ^{
        @autoreleasepool {
            BOOL requiresKrw = !([cmd isEqualToString:@"krw-import-recovery-handoff"] ||
                                 [cmd isEqualToString:@"a86969-playback-benign"] ||
                                 [cmd isEqualToString:@"a86969-raw"]);
            BOOL existingKrwOnly =
                [cmd isEqualToString:@"krw-update-handoff"] ||
                [cmd isEqualToString:@"uat-e1-observe"] ||
                [cmd isEqualToString:@"uat-agx-bootstrap-root"] ||
                [cmd isEqualToString:@"uat-agx-rtbuddy-alias"] ||
                [cmd isEqualToString:@"uat-agx-firmware-preflight"] ||
                [cmd isEqualToString:@"uat-e2-retire"] ||
                [cmd isEqualToString:@"uat-e4-inflight"] ||
                [cmd isEqualToString:@"uat-e5-owner-release"] ||
                [cmd isEqualToString:@"uat-e5-device-release"] ||
                [cmd isEqualToString:@"uat-e5-connection-release"] ||
                [cmd isEqualToString:@"uat-e5-raw-queue-release"] ||
                [cmd isEqualToString:@"uat-e5-raw-queue-bind-release"];
            BOOL requiresExternalLifecycleLock = requiresKrw ||
                [cmd isEqualToString:@"krw-import-recovery-handoff"];
            __block BOOL externalLifecycleLockHeld = NO;
            if (requiresExternalLifecycleLock) {
                externalLifecycleLockHeld =
                    settings_begin_external_krw_action(cmd.UTF8String);
                if (!externalLifecycleLockHeld) {
                    NSMutableDictionary<NSString *, id> *busy = [@{
                        @"command": cmd,
                        @"result": @"refused-lifecycle-action-in-progress",
                        @"krwLifecycle":
                            settings_current_krw_lifecycle_snapshot().agentRepresentation,
                        @"pid": @(getpid()), @"source": sourceName,
                        @"at": @([[NSDate date] timeIntervalSince1970]) } mutableCopy];
                    CNDCmdWriteJSON(@"cnd-result.json", busy);
                    if (resultHandler) resultHandler(busy);
                    CNDCmdEndProbeTask(task);
                    return;
                }
            }
            NSObject *completionLock = [NSObject new];
            __block BOOL completionDelivered = NO;
            void (^finish)(NSDictionary<NSString *, id> *) =
                ^(NSDictionary<NSString *, id> *report) {
                    @synchronized (completionLock) {
                        if (completionDelivered) return;
                        completionDelivered = YES;
                        if (externalLifecycleLockHeld) {
                            settings_end_external_krw_action(cmd.UTF8String);
                            externalLifecycleLockHeld = NO;
                        }
                    }
                    NSMutableDictionary<NSString *, id> *finished =
                        [(report ?: @{}) mutableCopy];
                    // This is cached boundary evidence only. Do not turn result
                    // publication into another readiness or recovery operation.
                    finished[@"krwLifecycle"] =
                        settings_current_krw_lifecycle_snapshot().agentRepresentation;
                    CNDCmdWriteJSON(@"cnd-result.json", finished);
                    if (resultHandler) resultHandler(finished);
                    CNDCmdEndProbeTask(task);
                };
            NSString *krwPolicy = requiresKrw
                ? (existingKrwOnly
                    ? @"shared-tweak-lifecycle-existing-only"
                    : @"shared-tweak-lifecycle") : @"none";
            CNDCmdWriteJSON(@"cnd-stage.json", @{
                @"stage": requiresKrw ? @"checking-krw" :
                    @"preflight-no-krw",
                @"requiresKrw": @(requiresKrw), @"command": cmd,
                @"krwPolicy": krwPolicy,
                @"pid": @(getpid()), @"source": sourceName,
                @"at": @([[NSDate date] timeIntervalSince1970]) });
            // Probe URLs are explicit KRW actions. A cold URL launch may have
            // a valid parked generation but no process-local socket state yet,
            // so recover through the same single owner as the UI's Run action.
            // All KRW-backed commands use a shared lifecycle owner rather than
            // implementing policy inside a probe. E1 is stricter: it may reuse
            // or recover an existing generation, but its explicit observer
            // contract forbids the shared owner from falling through to fresh
            // acquisition. It still performs its own pinned checked-read
            // witness before following any kernel object edge.
            BOOL krwReady = !requiresKrw ? YES :
                (existingKrwOnly
                    ? settings_ensure_existing_krw_for_probe()
                    : settings_ensure_krw_for_probe());
            if (!krwReady) {
                NSDictionary *report = @{
                    @"command": cmd,
                    @"result": existingKrwOnly
                        ? @"refused-existing-krw-unavailable"
                        : @"refused-krw-not-ready",
                    @"krwPolicy": krwPolicy,
                    @"pid": @(getpid()), @"source": sourceName,
                    @"at": @([[NSDate date] timeIntervalSince1970]) };
                log_user("[CND_CMD] refused %s: KRW not ready\n", cmd.UTF8String);
                finish(report);
                return;
            }
            log_user("[CND_CMD] running %s in pid=%d\n", cmd.UTF8String, getpid());
            CNDCmdWriteJSON(@"cnd-stage.json", @{
                @"stage": @"running", @"command": cmd, @"pid": @(getpid()),
                @"at": @([[NSDate date] timeIntervalSince1970]) });
            if ([cmd isEqualToString:@"krw-update-handoff"]) {
                NSString *terminationPath = CNDCmdPath(@"cnd-termination.json");
                if (terminationPath.length > 0) {
                    [NSFileManager.defaultManager
                        removeItemAtPath:terminationPath error:nil];
                }
                CNDKRWTerminationPreparation preparation = {0};
                BOOL armed = kexploit_prepare_recoverable_termination(
                    &preparation);
                NSString *generationID =
                    krw_persistence_current_generation_id() ?: @"";
                BOOL exact = armed && preparation.parkVerified &&
                    preparation.defunctProtected &&
                    preparation.controlLinkExact &&
                    preparation.controlChecksumExact &&
                    preparation.rwStateExact &&
                    preparation.anchorVerified &&
                    preparation.currentGenerationExact &&
                    preparation.nextProcessArmed &&
                    preparation.handoffSerial > 0 &&
                    generationID.length > 0 && requestID.length > 0;
                if (exact) {
                    @synchronized (CNDCmdReplyLock()) {
                        g_updateHandoffRequestID = [requestID copy];
                    }
                }
                finish(@{
                    @"schema": @"com.zeroxjf.cyanide.krw-update-handoff",
                    @"command": cmd,
                    @"requestID": requestID ?: @"",
                    @"result": exact ? @"armed-exact" : @"refused-unproven",
                    @"parkVerified": @(preparation.parkVerified),
                    @"defunctProtected": @(preparation.defunctProtected),
                    @"controlLinkExact": @(preparation.controlLinkExact),
                    @"controlChecksumExact":
                        @(preparation.controlChecksumExact),
                    @"rwStateExact": @(preparation.rwStateExact),
                    @"anchorVerified": @(preparation.anchorVerified),
                    @"currentGenerationExact":
                        @(preparation.currentGenerationExact),
                    @"nextProcessArmed": @(preparation.nextProcessArmed),
                    @"handoffSerial": @(preparation.handoffSerial),
                    @"generationID": generationID,
                    @"pid": @(getpid()),
                    @"at": @([[NSDate date] timeIntervalSince1970]),
                });
            } else if ([cmd isEqualToString:@"krw-import-recovery-handoff"]) {
                NSString *handoffPath = CNDCmdPath(@"CNDKRWRecoveryHandoff.plist");
                NSError *readError = nil;
                NSDictionary *handoff = handoffPath.length > 0
                    ? [NSDictionary dictionaryWithContentsOfURL:
                        [NSURL fileURLWithPath:handoffPath]
                        error:&readError]
                    : nil;
                NSString *stage = @"handoff-file-read";
                BOOL imported = handoff != nil &&
                    krw_persistence_import_recovery_handoff(handoff, &stage);
                log_user("[KRW] recovery handoff import result=%s stage=%s; no recovery or acquisition ran\n",
                         imported ? "pass" : "fail-clean",
                         stage.UTF8String ?: "unknown");
                finish(@{
                    @"command": cmd,
                    @"result": imported ? @"pass-imported-exact" : @"fail-clean",
                    @"stage": stage ?: @"unknown",
                    @"fileRead": @(handoff != nil),
                    @"readError": readError.localizedDescription ?: @"",
                    @"recoveryRan": @NO,
                    @"acquisitionRan": @NO,
                    @"pid": @(getpid()),
                });
            } else if ([cmd isEqualToString:@"control"]) {
                CNDUatPhysControlRun(finish);
            } else if ([cmd isEqualToString:@"image"]) {
                CNDUatImageProbeRun(finish);
            } else if ([cmd isEqualToString:@"queue"]) {
                CNDUatQueueProbeRun(NO, finish);
            } else if ([cmd isEqualToString:@"uat-binding-read"]) {
                CNDUatHardwareBindingProbeRun(NO, finish);
            } else if ([cmd isEqualToString:@"uat-binding-write"]) {
                CNDUatHardwareBindingProbeRun(YES, finish);
            } else if ([cmd isEqualToString:@"uat-record-state"]) {
                CNDUatHardwareRecordStateProbeRun(finish);
            } else if ([cmd isEqualToString:@"uat-e1-observe"]) {
                CNDUatE1ObserveRun(finish);
            } else if ([cmd isEqualToString:@"uat-agx-bootstrap-root"]) {
                CNDUatAGXBootstrapRootRun(finish);
            } else if ([cmd isEqualToString:@"uat-agx-rtbuddy-alias"]) {
                CNDUatAGXRTBuddyAliasRun(finish);
            } else if ([cmd isEqualToString:@"uat-agx-firmware-preflight"]) {
                CNDAGXFirmwarePreflightRun(requestID, finish);
            } else if ([cmd isEqualToString:@"uat-e2-retire"]) {
                CNDUatE2RetireRun(finish);
            } else if ([cmd isEqualToString:@"uat-e4-inflight"]) {
                CNDUatE4InflightRun(finish);
            } else if ([cmd isEqualToString:@"uat-e5-owner-release"]) {
                CNDUatE5OwnerReleaseRun(finish);
            } else if ([cmd isEqualToString:@"uat-e5-device-release"]) {
                CNDUatE5DeviceReleaseRun(finish);
            } else if ([cmd isEqualToString:@"uat-e5-connection-release"]) {
                CNDUatE5ConnectionReleaseRun(finish);
            } else if ([cmd isEqualToString:@"uat-e5-raw-queue-release"]) {
                CNDUatE5RawQueueReleaseRun(finish);
            } else if ([cmd isEqualToString:@"uat-e5-raw-queue-bind-release"]) {
                CNDUatE5RawQueueBindReleaseRun(finish);
            } else if ([cmd isEqualToString:@"uat-signer-inventory"]) {
                CNDPhysicalKCall1UatSignerInventoryRun(finish);
            } else if ([cmd isEqualToString:@"uat-signer-oracle"]) {
                CNDPhysicalKCall1UatSignerOracleRun(finish);
            } else if ([cmd isEqualToString:@"krw-scratch-write"]) {
                CNDPhysicalKCall1ScratchWriteOracleRun(finish);
            } else if ([cmd isEqualToString:@"uat-get-pte"]) {
                finish(@{
                    @"command": cmd,
                    @"result": @"disabled-after-device-panic",
                    @"reason": @"The mediated GET_PT_ENTRY chain is quarantined pending panic-log analysis.",
                });
            } else if ([cmd isEqualToString:@"a86969-playback-benign"]) {
                CNDAudioCodecs86969PlaybackTraceRun(finish);
            } else if ([cmd isEqualToString:@"a86969-raw"]) {
                CNDAudioCodecs86969ProbeRun(NO, finish);
            } else if ([cmd isEqualToString:@"discord-audio-apply"]) {
                CNDDiscordAudioModeProbeApply(finish);
            } else if ([cmd isEqualToString:@"discord-audio-restore"]) {
                CNDDiscordAudioModeProbeRestore(finish);
            } else {
                finish(@{
                    @"command": cmd, @"result": @"unknown-command",
                    @"at": @([[NSDate date] timeIntervalSince1970]) });
            }
        }
    });
}

// Legacy in-container command pickup. Do not use CoreDevice's appDataContainer
// file-transfer service to populate this while Cyanide is alive: opening that
// service terminates the app and therefore closes the process-local KRW fds.
// Host-driven commands use CNDHandleCommandURL() below instead.
static void CNDCmdRunPendingIfAny(const char *source)
{
    NSString *cmdPath = CNDCmdPath(@"cnd-cmd.txt");
    NSString *cmd = cmdPath != nil
        ? [NSString stringWithContentsOfFile:cmdPath
                                    encoding:NSUTF8StringEncoding
                                       error:nil] : nil;
    cmd = [cmd stringByTrimmingCharactersInSet:
        [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (cmd.length == 0) {
        return;
    }
    // Consume first: a probe that faults must not re-run on reboot.
    [[NSFileManager defaultManager] removeItemAtPath:cmdPath error:nil];
    CNDCmdRun(cmd, source, nil, nil);
}

BOOL CNDHandleCommandURL(NSURL *url, const char *source)
{
    if (url == nil ||
        ![url.scheme isEqualToString:@"com.zeroxjf.ios-cyanide1"] ||
        ![url.host isEqualToString:@"probe"]) {
        return NO;
    }

    NSString *cmd = url.path.lastPathComponent.lowercaseString;
    if (![@[ @"krw-diagnostic", @"krw-update-handoff",
             @"krw-import-recovery-handoff",
             @"control", @"image", @"queue", @"uat-binding-read",
             @"uat-binding-write", @"uat-record-state",
             @"uat-e1-observe", @"uat-agx-bootstrap-root",
             @"uat-agx-rtbuddy-alias", @"uat-agx-firmware-preflight",
             @"uat-e2-retire", @"uat-e4-inflight",
             @"uat-e5-owner-release",
             @"uat-e5-device-release",
             @"uat-e5-connection-release",
             @"uat-e5-raw-queue-release",
             @"uat-e5-raw-queue-bind-release",
             @"uat-signer-inventory", @"uat-signer-oracle", @"krw-scratch-write",
             @"uat-get-pte", @"a86969-playback-benign",
             @"discord-audio-apply", @"discord-audio-restore" ]
            containsObject:cmd]) {
        log_user("[CND_CMD] refused unknown URL command %s in pid=%d\n",
                 cmd.UTF8String ?: "(missing)", getpid());
        return NO;
    }

    NSString *replyToken = nil;
    NSString *requestID = nil;
    NSURLComponents *components = [NSURLComponents
        componentsWithURL:url resolvingAgainstBaseURL:NO];
    for (NSURLQueryItem *item in components.queryItems ?: @[]) {
        if ([item.name isEqualToString:@"replyToken"]) replyToken = item.value;
        if ([item.name isEqualToString:@"requestID"]) requestID = item.value;
    }
    BOOL requestedLiveReply = replyToken.length > 0 || requestID.length > 0;
    BOOL authenticatedLive =
        [cmd isEqualToString:@"krw-diagnostic"] ||
        [cmd isEqualToString:@"krw-update-handoff"];
    if (authenticatedLive &&
        (!requestedLiveReply || replyToken.length == 0 || requestID.length == 0)) {
        log_user("[CND_CMD] refused unauthenticated authenticated-live command in pid=%d\n",
                 getpid());
        return NO;
    }
    if (requestedLiveReply &&
        !CNDCmdStartLiveReply(requestID, replyToken, cmd)) {
        return NO;
    }
    CNDCmdResultHandler reply = requestedLiveReply
        ? ^(NSDictionary<NSString *, id> *report) {
            CNDCmdCompleteLiveReply(requestID, report);
          }
        : nil;
    CNDCmdRun(cmd, source ?: "url", requestID, reply);
    return YES;
}

// File-scope, deliberately.  A dispatch_source_t held only in a local variable is
// released when the enclosing block returns (ARC manages dispatch objects), and a
// released source stops firing -- which presents exactly as "the watcher armed
// once and then froze".
static dispatch_source_t g_cmdTimer;

static void CNDCmdStartWatcher(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // Keep the screen awake while the watcher is armed.  Without this the
        // device auto-locks within seconds, the app is suspended, and the timers
        // stop -- which reads identically to a wedged probe: state frozen, command
        // file unconsumed, process still listed as running.
        dispatch_async(dispatch_get_main_queue(), ^{
            [UIApplication sharedApplication].idleTimerDisabled = YES;
        });
        CNDCmdPublishStateNoKrw();
        log_user("[CND_CMD] watcher armed in pid=%d idleTimerDisabled=1 docs=%s\n", getpid(),
                 [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                     NSUserDomainMask, YES).firstObject UTF8String] ?: "?");

        // Two independent timers, deliberately.
        //
        // kexploit_krw_ready() takes the KRW lock, and a probe holds that lock
        // while it runs. A dispatch timer on a serial queue runs its handler
        // inline, so ONE blocking call there stops every later tick: the loop
        // goes silent, the command file is never seen, and the host reads it as
        // "no result". So the poll loop never touches KRW, and the readiness
        // query stays on a queue of its own.
        dispatch_queue_t cmdQueue = dispatch_queue_create("cnd.cmd.watch",
            DISPATCH_QUEUE_SERIAL);
        g_cmdTimer = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_TIMER, 0, 0, cmdQueue);
        dispatch_source_t cmdTimer = g_cmdTimer;
        dispatch_source_set_timer(cmdTimer, dispatch_time(DISPATCH_TIME_NOW, 0),
            2ull * NSEC_PER_SEC, 1ull * NSEC_PER_SEC);
        dispatch_source_set_event_handler(cmdTimer, ^{
            @autoreleasepool { CNDCmdRunPendingIfAny("timer"); }
        });
        dispatch_resume(cmdTimer);

        // No readiness poll here on purpose: kexploit_krw_ready() prints
        // "[KRW] not ready: ..." on every call that returns false, so polling it
        // floods the log exactly while the user is acquiring KRW.
    });
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    [self logBootIdentity];
    settings_register_defaults();
    log_set_verbose(YES);
    // Match the original KRW lifecycle: cold launch must not touch a parked
    // kernel primitive. Recovery happens only from an explicit KRW action.
    // Establish Automatic Repair's audio/power lifetime now. The scene's
    // did-become-active callback consumes the pending "Cyanide opened" repair
    // once UIKit is foreground, without duplicating the cold-launch request.
    settings_reconcile_snowboard_automatic_repair_lifetime();
    [self installTerminationHandlers];
    // Keeps the live process awake and retains legacy local command pickup. Host
    // commands arrive through the URL scene callback without touching appData.
    CNDCmdStartWatcher();
    [self installBarAppearances];
    int labNotifyStatus = notify_register_dispatch(
        "com.zeroxjf.cyanide.lab.pm-cross-class",
        &g_lab_pm_cross_class_notification_token,
        dispatch_get_main_queue(), ^(int token) {
            (void)token;
            settings_run_lab_pm_cross_class_action();
        });
    if (labNotifyStatus != NOTIFY_STATUS_OK) {
        log_user("[LAB_PM_CROSS_CLASS] notification registration failed status=%d\n",
            labNotifyStatus);
    }
    labNotifyStatus = notify_register_dispatch(
        "com.zeroxjf.cyanide.lab.pm-m68",
        &g_lab_pm_m68_notification_token,
        dispatch_get_main_queue(), ^(int token) {
            (void)token;
            settings_run_lab_pm_m68_action();
        });
    if (labNotifyStatus != NOTIFY_STATUS_OK) {
        log_user("[LAB_PM_M68] notification registration failed status=%d\n",
            labNotifyStatus);
    }
    NSArray<NSString *> *arguments = NSProcessInfo.processInfo.arguments;
    void (^physicalLaunchAction)(void) = nil;
    if ([arguments containsObject:@"--snowboard-remix-reapply"]) {
        physicalLaunchAction = ^{
            settings_run_snowboard_remix_reapply_action();
        };
    } else if ([arguments containsObject:@"--hail-mary-apply"]) {
        physicalLaunchAction = ^{ settings_run_hail_mary_patch_apply_action(); };
    } else if ([arguments containsObject:@"--hail-mary-restore"]) {
        physicalLaunchAction = ^{ settings_run_hail_mary_patch_restore_action(); };
    } else if ([arguments containsObject:@"--hail-mary-verify-patched"]) {
        physicalLaunchAction = ^{ settings_run_hail_mary_patch_verify_patched_action(); };
    } else if ([arguments containsObject:@"--hail-mary-verify-original"]) {
        physicalLaunchAction = ^{ settings_run_hail_mary_patch_verify_original_action(); };
    } else if ([arguments containsObject:@"--hail-mary-probe"]) {
        physicalLaunchAction = ^{ settings_run_hail_mary_probe_action(); };
    } else if ([arguments containsObject:@"--hail-mary-imp-apply"]) {
        physicalLaunchAction = ^{ settings_run_hail_mary_imp_redirect_apply_action(); };
    } else if ([arguments containsObject:@"--hail-mary-imp-restore"]) {
        physicalLaunchAction = ^{ settings_run_hail_mary_imp_redirect_restore_action(); };
    } else if ([arguments containsObject:
                @"--hail-mary-special-icon-class-probe"]) {
        physicalLaunchAction = ^{
            settings_run_hail_mary_special_icon_class_probe_action();
        };
    } else if ([arguments containsObject:
                @"--hail-mary-special-icon-class-apply"]) {
        physicalLaunchAction = ^{
            settings_run_hail_mary_special_icon_class_apply_action();
        };
    } else if ([arguments containsObject:
                @"--hail-mary-special-icon-class-restore"]) {
        physicalLaunchAction = ^{
            settings_run_hail_mary_special_icon_class_restore_action();
        };
    } else if ([arguments containsObject:
                @"--hail-mary-special-icon-class-verify-redirected"]) {
        physicalLaunchAction = ^{
            settings_run_hail_mary_special_icon_class_verify_redirected_action();
        };
    } else if ([arguments containsObject:
                @"--hail-mary-special-icon-class-verify-original"]) {
        physicalLaunchAction = ^{
            settings_run_hail_mary_special_icon_class_verify_original_action();
        };
    } else if ([arguments containsObject:
                @"--hail-mary-special-icon-dispatch-probe"]) {
        physicalLaunchAction = ^{
            settings_run_hail_mary_special_icon_class_dispatch_probe_action();
        };
    } else if ([arguments containsObject:
                @"--hail-mary-special-icon-dispatch-apply"]) {
        physicalLaunchAction = ^{
            settings_run_hail_mary_special_icon_class_dispatch_apply_action();
        };
    } else if ([arguments containsObject:
                @"--hail-mary-special-icon-dispatch-restore"]) {
        physicalLaunchAction = ^{
            settings_run_hail_mary_special_icon_class_dispatch_restore_action();
        };
    } else if ([arguments containsObject:
                @"--hail-mary-special-icon-dispatch-verify-redirected"]) {
        physicalLaunchAction = ^{
            settings_run_hail_mary_special_icon_class_dispatch_verify_redirected_action();
        };
    } else if ([arguments containsObject:
                @"--hail-mary-special-icon-dispatch-verify-original"]) {
        physicalLaunchAction = ^{
            settings_run_hail_mary_special_icon_class_dispatch_verify_original_action();
        };
    } else if ([arguments containsObject:
                @"--special-icon-presentation-probe"]) {
        physicalLaunchAction = ^{
            settings_run_special_icon_presentation_probe_action();
        };
    } else if ([arguments containsObject:
                @"--special-icon-clock-presentation-apply"]) {
        physicalLaunchAction = ^{
            settings_run_clock_static_presentation_apply_action();
        };
    } else if ([arguments containsObject:
                @"--special-icon-clock-presentation-restore"]) {
        physicalLaunchAction = ^{
            settings_run_clock_static_presentation_restore_action();
        };
    } else if ([arguments containsObject:
                @"--special-icon-clock-presentation-verify-redirected"]) {
        physicalLaunchAction = ^{
            settings_run_clock_static_presentation_verify_redirected_action();
        };
    } else if ([arguments containsObject:
                @"--special-icon-clock-presentation-verify-original"]) {
        physicalLaunchAction = ^{
            settings_run_clock_static_presentation_verify_original_action();
        };
    } else if ([arguments containsObject:
                @"--special-icon-calendar-presentation-apply"]) {
        physicalLaunchAction = ^{
            settings_run_calendar_static_presentation_apply_action();
        };
    } else if ([arguments containsObject:
                @"--special-icon-calendar-presentation-restore"]) {
        physicalLaunchAction = ^{
            settings_run_calendar_static_presentation_restore_action();
        };
    } else if ([arguments containsObject:
                @"--special-icon-calendar-presentation-verify-redirected"]) {
        physicalLaunchAction = ^{
            settings_run_calendar_static_presentation_verify_redirected_action();
        };
    } else if ([arguments containsObject:
                @"--special-icon-calendar-presentation-verify-original"]) {
        physicalLaunchAction = ^{
            settings_run_calendar_static_presentation_verify_original_action();
        };
    } else if ([arguments containsObject:
                @"--switcher-presentation-probe"]) {
        physicalLaunchAction = ^{
            settings_run_switcher_presentation_probe_action();
        };
    } else if ([arguments containsObject:
                @"--switcher-presentation-apply"]) {
        physicalLaunchAction = ^{
            settings_run_switcher_static_presentation_apply_action();
        };
    } else if ([arguments containsObject:
                @"--switcher-presentation-restore"]) {
        physicalLaunchAction = ^{
            settings_run_switcher_static_presentation_restore_action();
        };
    } else if ([arguments containsObject:
                @"--switcher-presentation-verify-redirected"]) {
        physicalLaunchAction = ^{
            settings_run_switcher_static_presentation_verify_redirected_action();
        };
    } else if ([arguments containsObject:
                @"--switcher-presentation-verify-original"]) {
        physicalLaunchAction = ^{
            settings_run_switcher_static_presentation_verify_original_action();
        };
    } else if ([arguments containsObject:
                @"--app-library-miniature-presentation-probe"]) {
        physicalLaunchAction = ^{
            settings_run_app_library_miniature_presentation_probe_action();
        };
    } else if ([arguments containsObject:
                @"--app-library-miniature-presentation-apply"]) {
        physicalLaunchAction = ^{
            settings_run_app_library_miniature_static_presentation_apply_action();
        };
    } else if ([arguments containsObject:
                @"--app-library-miniature-presentation-restore"]) {
        physicalLaunchAction = ^{
            settings_run_app_library_miniature_static_presentation_restore_action();
        };
    } else if ([arguments containsObject:
                @"--app-library-miniature-presentation-verify-redirected"]) {
        physicalLaunchAction = ^{
            settings_run_app_library_miniature_static_presentation_verify_redirected_action();
        };
    } else if ([arguments containsObject:
                @"--app-library-miniature-presentation-verify-original"]) {
        physicalLaunchAction = ^{
            settings_run_app_library_miniature_static_presentation_verify_original_action();
        };
    } else if ([arguments containsObject:@"--icon-class-audit"]) {
        physicalLaunchAction = ^{
            settings_run_icon_class_audit_action();
        };
    } else if ([arguments containsObject:
                @"--special-icon-object-preflight"]) {
        physicalLaunchAction = ^{
            settings_run_special_icon_object_preflight_action();
        };
    } else if ([arguments containsObject:
                @"--special-icon-object-rebuild-static"]) {
        physicalLaunchAction = ^{
            settings_run_special_icon_object_rebuild_static_action();
        };
    } else if ([arguments containsObject:
                @"--special-icon-object-rebuild-live"]) {
        physicalLaunchAction = ^{
            settings_run_special_icon_object_rebuild_live_action();
        };
    } else if ([arguments containsObject:@"--hail-mary-page-wire"]) {
        physicalLaunchAction = ^{ settings_run_hail_mary_page_wire_action(); };
    } else if ([arguments containsObject:@"--springboard-rx-probe"]) {
        physicalLaunchAction = ^{ settings_run_physical_rx_probe_action(); };
    } else if ([arguments containsObject:@"--physical-pac-validator"]) {
        physicalLaunchAction = ^{
            settings_run_physical_pac_identity_canary_action();
        };
    } else if ([arguments containsObject:@"--calculator-pac-probe"]) {
        physicalLaunchAction = ^{
            settings_run_physical_calculator_pac_probe_action();
        };
    } else if ([arguments containsObject:@"--springboard-pac-probe"]) {
        physicalLaunchAction = ^{
            settings_run_physical_springboard_pac_probe_action();
        };
    } else if ([arguments containsObject:
                @"--iouserethernet-signer-probe"]) {
        physicalLaunchAction = ^{
            CNDPhysicalIOUserEthernetSignerProbeRun(
                ^(NSDictionary<NSString *, id> *report) {
                    log_user("[IOUSERETHERNET_SIGNER] result=%s report=%s\n",
                        [report[@"result"] UTF8String] ?: "unknown-result",
                        [report[@"reportPath"] UTF8String] ?: "unavailable");
                });
        };
    } else if ([arguments containsObject:@"--kcall1-probe"]) {
        physicalLaunchAction = ^{
            CNDPhysicalKCall1ProbeRun(
                ^(NSDictionary<NSString *, id> *report) {
                    log_user("[KCALL1] result=%s success=%s report=%s\n",
                        [report[@"result"] UTF8String] ?: "unknown-result",
                        [report[@"ifnetKCall1Success"] boolValue]
                            ? "yes" : "no",
                        [report[@"reportPath"] UTF8String] ?: "unavailable");
                });
        };
    } else if ([arguments containsObject:@"--uat-observer"] ||
               [arguments containsObject:@"--uat-observer-off"]) {
        BOOL restore = [arguments containsObject:@"--uat-observer-off"];
        physicalLaunchAction = ^{
            void (^done)(NSDictionary<NSString *, id> *) =
                ^(NSDictionary<NSString *, id> *report) {
                    log_user("[UAT_OBSERVER] result=%s before=%s after=%s "
                             "addr=%s report=%s\n",
                        [report[@"result"] UTF8String] ?: "unknown-result",
                        [report[@"debugByteBefore"] UTF8String] ?: "-",
                        [report[@"debugByteAfter"] UTF8String] ?: "-",
                        [[report[@"debugByteAddress"] description] UTF8String] ?: "-",
                        [report[@"reportPath"] UTF8String] ?: "unavailable");
                };
            if (restore) {
                CNDUatObserverProbeRestoreRun(done);
            } else {
                CNDUatObserverProbeRun(done);
            }
        };
    } else if ([arguments containsObject:@"--uat-context-probe"]) {
        physicalLaunchAction = ^{
            CNDUatContextProbeRun(
                ^(NSDictionary<NSString *, id> *report) {
                    log_user("[UAT_CTX] result=%s changed=%s before=%s after=%s "
                             "table=%s report=%s\n",
                        [report[@"result"] UTF8String] ?: "unknown-result",
                        [[report[@"actionsWithChanges"] description] UTF8String] ?: "-",
                        [[report[@"validBefore"] description] UTF8String] ?: "-",
                        [[report[@"validAfter"] description] UTF8String] ?: "-",
                        [[[report[@"iouatGlobal"] objectForKey:@"tablePointer"]
                            description] UTF8String] ?: "-",
                        [report[@"reportPath"] UTF8String] ?: "unavailable");
                });
        };
    } else if ([arguments containsObject:@"--uat-phys-control"]) {
        physicalLaunchAction = ^{
            CNDUatPhysControlRun(^(NSDictionary<NSString *, id> *report) {
                log_user("[UAT_PHYS] done result=%s\n",
                    [report[@"result"] UTF8String] ?: "unknown");
            });
        };
    } else if ([arguments containsObject:@"--uat-image-probe"]) {
        physicalLaunchAction = ^{
            CNDUatImageProbeRun(^(NSDictionary<NSString *, id> *report) {
                log_user("[UAT_IMG] result=%s phys=%s report=%s\n",
                    [report[@"result"] UTF8String] ?: "unknown-result",
                    [[report[@"walk"] description] UTF8String] ?: "-",
                    [report[@"reportPath"] UTF8String] ?: "unavailable");
            });
        };
    } else if ([arguments containsObject:@"--uat-queue-probe"]) {
        // The page-table walk only runs with an explicit second flag: a wrong root
        // makes the walk follow arbitrary entries, and the point of this run is to
        // look at the slot values before anything acts on them.
        BOOL walk = [arguments containsObject:@"--uat-walk"];
        physicalLaunchAction = ^{
            CNDUatQueueProbeRun(walk,
                ^(NSDictionary<NSString *, id> *report) {
                    log_user("[UAT_QUEUE] result=%s qid=%s createKR=%s submit0=%s "
                             "client=%s report=%s\n",
                        [report[@"result"] UTF8String] ?: "unknown-result",
                        [[report[@"queueID"] description] UTF8String] ?: "-",
                        [[report[@"queueCreateKR"] description] UTF8String] ?: "-",
                        [[report[@"submitCount0KR"] description] UTF8String] ?: "-",
                        [[report[@"clientObject"] description] UTF8String] ?: "-",
                        [report[@"reportPath"] UTF8String] ?: "unavailable");
                });
        };
    } else if ([arguments containsObject:@"--entitlement-audit-probe"]) {
        physicalLaunchAction = ^{
            CNDPhysicalEntitlementAuditProbeRun(
                ^(NSDictionary<NSString *, id> *report) {
                    NSString *holders = [report[@"processesWithEntitlement"]
                        componentsJoinedByString:@","];
                    log_user("[ENTITLEMENT_AUDIT] result=%s donor=%s "
                        "holders=%s report=%s\n",
                        [report[@"result"] UTF8String] ?: "unknown-result",
                        [report[@"donorHasEntitlement"] boolValue]
                            ? "yes" : "no",
                        holders.UTF8String ?: "none",
                        [report[@"reportPath"] UTF8String] ?: "unavailable");
                });
        };
    }
    if (physicalLaunchAction) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            physicalLaunchAction();
        });
    }
    return YES;
}

- (void)logBootIdentity {
    NSBundle *b = [NSBundle mainBundle];
    NSDictionary *info = b.infoDictionary;
    NSString *shortVer = info[@"CFBundleShortVersionString"] ?: @"?";
    NSString *build    = info[@"CFBundleVersion"] ?: @"?";

    struct utsname u = {0};
    const char *machine = "device";
    if (uname(&u) == 0 && u.machine[0])
        machine = u.machine;
    NSString *ios = UIDevice.currentDevice.systemVersion ?: @"?";

    fprintf(stdout,
        "\n"
        "     ╭───────────╮\n"
        "     │ ▄▄▄▄▄▄▄▄▄ │\n"
        "     ├───────────┤\n"
        "     │ ░░░░░░░░░ │   K S L O P\n"
        "     │ ░░░ K ░░░ │   %s (%s)\n"
        "     │ ░░░░░░░░░ │   %s • iOS %s\n"
        "     │ ░░░░░░░░░ │\n"
        "     ╰───────────╯\n"
        "\n",
        shortVer.UTF8String, build.UTF8String,
        machine, ios.UTF8String);
}

- (void)applicationDidBecomeActive:(UIApplication *)application
{
    // The reliable trigger.  A devicectl launch does not foreground the app, so
    // the poll timer may never tick; coming to the foreground always happens.
    CNDCmdRunPendingIfAny("foreground");
}

- (void)installTerminationHandlers {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(applicationWillTerminateNotification:)
                                                     name:UIApplicationWillTerminateNotification
                                                   object:nil];

        signal(SIGTERM, SIG_IGN);
        g_sigterm_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,
                                                  SIGTERM,
                                                  0,
                                                  dispatch_get_main_queue());
        dispatch_source_set_event_handler(g_sigterm_source, ^{
            log_user("[CLEANUP] SIGTERM received; starting best-effort termination cleanup.\n");
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                CNDKRWTerminationDisposition disposition =
                    settings_best_effort_termination_cleanup("SIGTERM");
                const char *name =
                    kexploit_termination_disposition_name(disposition);
                /* Persist the disposition for the next launch's post-mortem;
                 * stdout dies with the process. A SIGTERM cannot be vetoed
                 * here (the installer gate runs before it is sent), so an
                 * unsafe disposition is recorded loudly and exits non-zero. */
                CNDCmdWriteJSON(@"cnd-termination.json",
                    CNDCmdTerminationPayload(@"SIGTERM", disposition));
                log_user("[CLEANUP] termination disposition=%s\n", name);
                _Exit(disposition == CNDKRWTerminationUnsafe ? 3 : 0);
            });
        });
        dispatch_resume(g_sigterm_source);
    });
}

- (void)applicationWillTerminateNotification:(NSNotification *)note {
    CNDKRWTerminationDisposition disposition =
        settings_best_effort_termination_cleanup("UIApplicationWillTerminateNotification");
    CNDCmdWriteJSON(@"cnd-termination.json", CNDCmdTerminationPayload(
        @"UIApplicationWillTerminateNotification", disposition));
}

- (void)installBarAppearances {
    // Use the system's default glass material for ALL appearance states so the
    // bar never crossfades between transparent and blurred when content
    // scrolls past the edge. This is what UIKit's own apps do post-iOS 15.
    UINavigationBarAppearance *nav = [[UINavigationBarAppearance alloc] init];
    [nav configureWithDefaultBackground];
    UINavigationBar.appearance.standardAppearance = nav;
    UINavigationBar.appearance.scrollEdgeAppearance = nav;
    UINavigationBar.appearance.compactAppearance = nav;
    UINavigationBar.appearance.compactScrollEdgeAppearance = nav;

    UITabBarAppearance *tab = [[UITabBarAppearance alloc] init];
    [tab configureWithDefaultBackground];
    UITabBar.appearance.standardAppearance = tab;
    UITabBar.appearance.scrollEdgeAppearance = tab;
}


#pragma mark - UISceneSession lifecycle


- (UISceneConfiguration *)application:(UIApplication *)application configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession options:(UISceneConnectionOptions *)options {
    // Called when a new scene session is being created.
    // Use this method to select a configuration to create the new scene with.
    return [[UISceneConfiguration alloc] initWithName:@"Default Configuration" sessionRole:connectingSceneSession.role];
}


- (void)application:(UIApplication *)application didDiscardSceneSessions:(NSSet<UISceneSession *> *)sceneSessions {
    // Called when the user discards a scene session.
    // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
    // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
}

- (void)applicationWillTerminate:(UIApplication *)application {
    CNDKRWTerminationDisposition disposition =
        settings_best_effort_termination_cleanup("applicationWillTerminate");
    CNDCmdWriteJSON(@"cnd-termination.json", CNDCmdTerminationPayload(
        @"applicationWillTerminate", disposition));
}

@end
