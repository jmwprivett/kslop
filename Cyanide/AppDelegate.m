//
//  AppDelegate.m
//  Cyanide
//
//  Created by seo on 3/24/26.
//

#import "AppDelegate.h"
#import "SettingsViewController.h"
#import "LogTextView.h"
#import "CNDPhysicalEntitlementAuditProbe.h"
#import "CNDPhysicalIOUserEthernetSignerProbe.h"
#import "CNDPhysicalKCall1Probe.h"
#import "CNDUatObserverProbe.h"
#import "CNDUatContextProbe.h"
#import "CNDUatQueueProbe.h"
#import "kexploit/kexploit_opa334.h"
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

// kexploit_krw_ready() is the only global readiness signal that is not
// file-static inside SettingsViewController.m.
// Lock-free: never call KRW helpers from a timer handler that other work depends
// on, because they take the lock a running probe holds.
static void CNDCmdPublishStateNoKrw(void)
{
    CNDCmdWriteJSON(@"cnd-state.json", @{
        @"krwReady": @(-1),
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

static void CNDCmdRun(NSString *command, const char *source)
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

    UIBackgroundTaskIdentifier task = CNDCmdBeginProbeTask(@"cnd-probe");
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            CNDCmdWriteJSON(@"cnd-stage.json", @{
                @"stage": @"checking-krw", @"command": cmd,
                @"pid": @(getpid()), @"source": sourceName,
                @"at": @([[NSDate date] timeIntervalSince1970]) });
            if (!kexploit_krw_ready()) {
                CNDCmdWriteJSON(@"cnd-result.json", @{
                    @"command": cmd, @"result": @"refused-krw-not-ready",
                    @"pid": @(getpid()), @"source": sourceName,
                    @"at": @([[NSDate date] timeIntervalSince1970]) });
                log_user("[CND_CMD] refused %s: KRW not ready\n", cmd.UTF8String);
                CNDCmdEndProbeTask(task);
                return;
            }
            log_user("[CND_CMD] running %s in pid=%d\n", cmd.UTF8String, getpid());
            CNDCmdWriteJSON(@"cnd-stage.json", @{
                @"stage": @"running", @"command": cmd, @"pid": @(getpid()),
                @"at": @([[NSDate date] timeIntervalSince1970]) });
            void (^finish)(NSDictionary<NSString *, id> *) =
                ^(NSDictionary<NSString *, id> *report) {
                    CNDCmdWriteJSON(@"cnd-result.json", report ?: @{});
                    CNDCmdEndProbeTask(task);
                };
            if ([cmd isEqualToString:@"control"]) {
                CNDUatPhysControlRun(finish);
            } else if ([cmd isEqualToString:@"image"]) {
                CNDUatImageProbeRun(finish);
            } else if ([cmd isEqualToString:@"queue"]) {
                CNDUatQueueProbeRun(NO, finish);
            } else {
                CNDCmdWriteJSON(@"cnd-result.json", @{
                    @"command": cmd, @"result": @"unknown-command",
                    @"at": @([[NSDate date] timeIntervalSince1970]) });
                CNDCmdEndProbeTask(task);
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
    CNDCmdRun(cmd, source);
}

BOOL CNDHandleCommandURL(NSURL *url, const char *source)
{
    if (url == nil ||
        ![url.scheme isEqualToString:@"com.zeroxjf.ios-cyanide1"] ||
        ![url.host isEqualToString:@"probe"]) {
        return NO;
    }

    NSString *cmd = url.path.lastPathComponent.lowercaseString;
    if (![@[ @"control", @"image", @"queue" ] containsObject:cmd]) {
        log_user("[CND_CMD] refused unknown URL command %s in pid=%d\n",
                 cmd.UTF8String ?: "(missing)", getpid());
        return NO;
    }

    CNDCmdRun(cmd, source ?: "url");
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
    // This is intentionally launch-only, not a foreground callback. A living
    // Cyanide process keeps its current state; a new process must prove that
    // it recovered the old parked KRW generation before trusting process-local
    // ACTIVE bits. SnowBoard's persistent state survives independently.
    settings_reconcile_persisted_applied_state_on_launch();
    settings_apply_snowboard_automatic_repair_enabled(
        [[NSUserDefaults standardUserDefaults] boolForKey:kSettingsKeepAlive]);
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
                settings_best_effort_termination_cleanup("SIGTERM");
                _Exit(0);
            });
        });
        dispatch_resume(g_sigterm_source);
    });
}

- (void)applicationWillTerminateNotification:(NSNotification *)note {
    settings_best_effort_termination_cleanup("UIApplicationWillTerminateNotification");
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
    settings_best_effort_termination_cleanup("applicationWillTerminate");
}

@end
