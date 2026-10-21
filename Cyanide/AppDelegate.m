//
//  AppDelegate.m
//  Cyanide
//
//  Created by seo on 3/24/26.
//

#import "AppDelegate.h"
#import "SettingsViewController.h"
#import "DSKeepAlive.h"
#import "LogTextView.h"
#import "CNDPhysicalEntitlementAuditProbe.h"
#import "CNDPhysicalIOUserEthernetSignerProbe.h"
#import "CNDPhysicalKCall1Probe.h"
#import "CNDUatObserverProbe.h"
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


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    [self logBootIdentity];
    settings_register_defaults();
    log_set_verbose(YES);
    // This is intentionally launch-only, not a foreground callback. A living
    // Cyanide process keeps its current state; a new process must prove that
    // it recovered the old parked KRW generation before trusting process-local
    // ACTIVE bits. SnowBoard's persistent state survives independently.
    settings_reconcile_persisted_applied_state_on_launch();
    ds_keepalive_apply_enabled([[NSUserDefaults standardUserDefaults] boolForKey:kSettingsKeepAlive]);
    [self installTerminationHandlers];
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
