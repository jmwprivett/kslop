"""Lifetime contracts and deterministic production Automatic Repair scheduling."""

from __future__ import annotations

import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
KEEPALIVE = ROOT / "Cyanide/DSKeepAlive.m"
INFO = ROOT / "Cyanide/Info.plist"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"
QUEUE = ROOT / "Cyanide/installer/PackageQueue.m"


def body(source: str, signature: str) -> str:
    """Extract a definition, skipping any earlier declaration."""
    start = source.rindex(signature)
    return source[start:source.index("\n}\n", start)]


class KeepAliveAutomaticRepairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.keepalive = KEEPALIVE.read_text(encoding="utf-8")
        cls.settings = SETTINGS.read_text(encoding="utf-8")
        cls.queue = QUEUE.read_text(encoding="utf-8")
        with INFO.open("rb") as stream:
            cls.info = plistlib.load(stream)

    def test_session_mixes_and_requests_fewer_system_alert_interruptions(self) -> None:
        self.assertIn("AVAudioSessionCategoryPlayback", self.keepalive)
        self.assertIn("AVAudioSessionCategoryOptionMixWithOthers", self.keepalive)
        self.assertIn(
            "setPrefersNoInterruptionsFromSystemAlerts:YES", self.keepalive
        )

    def test_interruption_recovery_is_forced_and_bounded(self) -> None:
        self.assertIn("AVAudioSessionInterruptionTypeBegan", self.keepalive)
        self.assertIn("AVAudioSessionInterruptionTypeEnded", self.keepalive)
        self.assertIn('ds_keepalive_schedule_recovery(@"interruption ended"', self.keepalive)
        self.assertIn("250LL * NSEC_PER_MSEC", self.keepalive)
        self.assertIn("1LL * NSEC_PER_SEC", self.keepalive)
        self.assertIn("5LL * NSEC_PER_SEC", self.keepalive)
        self.assertIn("ds_keepalive_revive(reason, YES)", self.keepalive)

    def test_background_modes_do_not_claim_unimplemented_bluetooth_peripheral(self) -> None:
        self.assertEqual(self.info.get("UIBackgroundModes"), ["audio"])

    def test_active_predicate_requires_preference_applied_state_and_recovery(self) -> None:
        active = body(self.settings, "static BOOL settings_snowboard_automatic_repair_is_active(")
        self.assertIn("boolForKey:kSettingsKeepAlive] &&", active)
        self.assertIn(
            "CNDTransientAppliedStateIsActive(CNDTransientAppliedStateSnowBoardRemix) &&",
            active,
        )
        self.assertIn("[CNDSnowBoardRemix hasAutomaticRepairData]", active)

    def test_audio_and_timer_share_fresh_main_thread_lifetime_decision(self) -> None:
        lifetime = body(self.settings, "void settings_reconcile_snowboard_automatic_repair_lifetime(")
        self.assertLess(lifetime.index("dispatch_block_t reconcile = ^{"),
                        lifetime.index("BOOL active = settings_snowboard_automatic_repair_is_active();"))
        self.assertIn("active || substantialHandoff || queueHandoff", lifetime)
        self.assertIn("g_queue_post_respring_foreground_armed", lifetime)
        inactive = lifetime[lifetime.index("if (!active)"):lifetime.index("if (!g_sbl_automatic_repair_power_observer)")]
        self.assertIn("dispatch_source_cancel(g_sbl_automatic_repair_timer)", inactive)
        self.assertIn("settings_cancel_pending_snowboard_automatic_repair();", inactive)
        self.assertIn("g_sbl_automatic_hail_mary_confirmed, 0", inactive)
        self.assertIn("return;", inactive)
        self.assertIn("if (NSThread.isMainThread) reconcile();", lifetime)
        self.assertIn("dispatch_async(dispatch_get_main_queue(), reconcile)", lifetime)
        # One centralized decision owns audio for Automatic Repair and both
        # bounded respring handoffs; unrelated background entry cannot revive it.
        self.assertEqual(self.settings.count("ds_keepalive_apply_enabled("), 1)

    def test_launch_toggle_and_background_reconcile_lifetime(self) -> None:
        app = (ROOT / "Cyanide/AppDelegate.m").read_text(encoding="utf-8")
        self.assertIn("settings_reconcile_snowboard_automatic_repair_lifetime();", app)
        self.assertNotIn("settings_apply_snowboard_automatic_repair_enabled(", app)
        toggle = body(self.settings, "void settings_apply_snowboard_automatic_repair_enabled(")
        self.assertIn("settings_reconcile_snowboard_automatic_repair_lifetime();", toggle)
        self.assertIn("settings_schedule_snowboard_automatic_repair_immediately(", toggle)
        self.assertNotIn("ds_keepalive_apply_enabled(enabled)", toggle)
        background = body(self.settings, "void settings_application_did_enter_background(")
        self.assertIn("settings_reconcile_snowboard_automatic_repair_lifetime();", background)
        self.assertIn("settings_apply_snowboard_automatic_repair_enabled(sender.isOn)", self.settings)

    def test_notifications_and_delayed_work_require_active_snowboard(self) -> None:
        scheduler = body(self.settings, "static void settings_enqueue_snowboard_automatic_repair(")
        self.assertIn("if (!settings_snowboard_automatic_repair_is_active())", scheduler)
        arm = body(self.settings, "static void settings_arm_snowboard_automatic_repair(")
        self.assertEqual(arm.count("settings_snowboard_automatic_repair_is_active()"), 2)
        self.assertIn("if (wakeup != g_sbl_automatic_repair_wakeup) return;", arm)
        self.assertIn("g_sbl_automatic_repair_running = YES;", arm)
        self.assertIn("g_sbl_automatic_repair_running = NO;", arm)
        self.assertIn("NSTimeInterval completedAt = NSProcessInfo.processInfo.systemUptime;", arm)
        self.assertIn("if (attempted)", arm)
        self.assertIn("kSBLAutomaticRepairCooldown;", arm)
        self.assertIn("DISPATCH_TIME_FOREVER", arm)
        self.assertNotIn("dispatch_after(", scheduler)

    def test_all_trigger_families_use_the_shared_scheduler(self) -> None:
        self.assertRegex(self.settings,
                         r'settings_schedule_snowboard_automatic_repair_immediately\(\s+@"Automatic Repair enabled"')
        foreground = body(
            self.settings, "void settings_application_will_enter_foreground("
        )
        self.assertLess(foreground.index("g_sbl_automatic_repair_open_pending = YES;"),
                        foreground.index("if (!settings_app_state_is_foreground()) return;"))
        active = body(self.settings, "void settings_application_did_become_active(")
        self.assertIn("if (g_sbl_automatic_repair_open_pending)", active)
        self.assertIn("settings_reconcile_snowboard_automatic_repair_lifetime();", active)
        self.assertIn("settings_enqueue_snowboard_automatic_repair(", active)
        self.assertIn('@"Cyanide opened", 3.0, 0, YES', active)
        self.assertEqual(self.settings.count('@"Cyanide opened"'), 1)
        for channel in (
            "com.apple.mobile.application_installed", "com.apple.mobile.application_updated",
            "com.apple.LaunchServices.applicationRegistered", "com.apple.LaunchServices.ApplicationsChanged",
            "com.apple.mobile.installation_proxy.installed",
        ):
            self.assertNotIn(f'notify_register_dispatch("{channel}"', self.settings)
        request = body(self.settings, "void settings_request_snowboard_automatic_repair(")
        self.assertIn("settings_schedule_snowboard_automatic_repair(", request)
        self.assertIn('@"completed SnowBoard operation", 5.0', request)

    def test_periodic_worker_rechecks_external_power(self) -> None:
        automatic = body(self.settings, "static BOOL settings_run_snowboard_automatic_repair(")
        guard = automatic[:automatic.index("PackageQueue *packageQueue")]
        self.assertIn('[reason isEqualToString:@"periodic integrity audit"]', guard)
        self.assertIn("UIDevice.currentDevice.batteryState)) return NO;", guard)

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"),
                         "requires macOS Foundation and clang")
    def test_production_scheduler_coalesces_with_monotonic_completion_cooldown(self) -> None:
        self.run_production_scheduler_harness(SCHEDULER_HARNESS)

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"),
                         "requires macOS Foundation and clang")
    def test_production_scene_open_edges_survive_background_application_state(self) -> None:
        self.run_production_scheduler_harness(LIFECYCLE_HARNESS)

    def run_production_scheduler_harness(self, harness: str) -> None:
        start = self.settings.index("static dispatch_source_t g_sbl_automatic_repair_wakeup;")
        end = self.settings.index("static volatile int g_sbl_automatic_hail_mary_confirmed", start)
        globals_source = self.settings[start:end]
        power_start = self.settings.index("static dispatch_source_t g_sbl_automatic_repair_timer;")
        power_end = self.settings.index("// Scheduler state belongs", power_start)
        globals_source = self.settings[power_start:power_end] + globals_source
        lifecycle_start = self.settings.index("static volatile int g_app_in_background = 0;")
        lifecycle_end = self.settings.index("static volatile int g_screen_awake", lifecycle_start)
        globals_source += self.settings[lifecycle_start:lifecycle_end]
        functions = "\n".join(
            body(self.settings, signature) + "\n}\n"
            for signature in (
                "static void settings_cancel_pending_snowboard_automatic_repair(",
                "static void settings_arm_snowboard_automatic_repair(",
                "static void settings_enqueue_snowboard_automatic_repair(",
                "static void settings_schedule_snowboard_automatic_repair_internal(",
                "static void settings_schedule_snowboard_automatic_repair_immediately(",
                "static void settings_schedule_snowboard_automatic_repair(\n",
                "static BOOL settings_snowboard_automatic_repair_uses_external_power(",
                "void settings_reconcile_snowboard_automatic_repair_lifetime(",
                "void settings_apply_snowboard_automatic_repair_enabled(",
            )
        )
        functions += body(self.settings, "static BOOL settings_app_state_is_foreground(") + "\n}\n"
        # Compile the production lifecycle entry paths through the repair
        # scheduling decisions; unrelated live tweak refreshes are outside this
        # harness and start at the explicit boundaries below.
        for signature, boundary in (
            ("void settings_application_did_enter_background(", "    NSUserDefaults *d ="),
            ("void settings_application_will_enter_foreground(", "    settings_apply_statbar_once_async("),
            ("void settings_application_did_become_active(", "    settings_apply_statbar_once_async("),
        ):
            lifecycle = body(self.settings, signature)
            functions += lifecycle[:lifecycle.index(boundary)] + "\n}\n"
        functions = functions.replace("NSProcessInfo.processInfo.systemUptime", "fakeNow").replace(
            "NSThread.isMainThread", "fakeOnMainThread"
        )
        with tempfile.TemporaryDirectory(prefix="cyanide-automatic-repair-") as directory:
            fixture = Path(directory) / "scheduler.m"
            executable = Path(directory) / "scheduler"
            fixture.write_text(SCHEDULER_MOCKS + globals_source + functions +
                               harness, encoding="utf-8")
            compiled = subprocess.run(
                ["clang", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra", "-Werror",
                 "-framework", "Foundation", str(fixture), "-o", str(executable)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(executable)], capture_output=True,
                                      text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stderr)

    def test_gate_is_one_atomic_semaphore_for_try_and_wait_callers(self) -> None:
        gate = body(self.settings, "static dispatch_semaphore_t settings_snowboard_mutation_gate(")
        self.assertIn("dispatch_once(&onceToken", gate)
        self.assertIn("dispatch_semaphore_create(1)", gate)
        acquire = body(self.settings, "BOOL settings_begin_snowboard_mutation(")
        release = body(self.settings, "void settings_end_snowboard_mutation(")
        self.assertIn("dispatch_semaphore_wait(settings_snowboard_mutation_gate()", acquire)
        self.assertIn("wait ? DISPATCH_TIME_FOREVER : DISPATCH_TIME_NOW", acquire)
        self.assertIn("!wait || !NSThread.isMainThread", acquire)
        self.assertIn("dispatch_semaphore_signal(settings_snowboard_mutation_gate())", release)

    def test_automatic_pass_defers_when_queue_owns_gate_and_rechecks_active_state(self) -> None:
        automatic = body(self.settings, "static BOOL settings_run_snowboard_automatic_repair(")
        self.assertIn("settings_substantial_repair_respring_marker()", automatic)
        self.assertLess(
            automatic.index("settings_substantial_repair_respring_marker()"),
            automatic.index("kexploit_krw_ready()"),
        )
        busy = automatic[automatic.index("if (!settings_begin_snowboard_mutation(NO))"):automatic.index("__block BOOL hailMaryApplicable")]
        self.assertIn("settings_release_actions_lock();", busy)
        self.assertIn("settings_schedule_snowboard_automatic_repair_internal(", busy)
        self.assertIn("reason, 30.0, attempt + 1", busy)
        protected = automatic[automatic.index("@try {"):automatic.index("} @finally {")]
        self.assertLess(protected.index("if (!settings_snowboard_automatic_repair_is_active()) return NO;"),
                        protected.index("setTransparencyFixEnabled:YES"))
        self.assertIn("return NO;", busy)
        self.assertIn("BOOL attempted = NO;", automatic)
        self.assertIn("return attempted;", automatic)
        for mutation in ("setTransparencyFixEnabled:YES", "settings_update_repair_snowboard_remix()"):
            before_mutation = protected[:protected.index(mutation)]
            self.assertIn("attempted = YES;", before_mutation)
        self.assertIn("settings_update_repair_snowboard_remix()", protected)
        cleanup = automatic[automatic.index("} @finally {"):]
        self.assertIn("settings_end_snowboard_mutation();", cleanup)
        self.assertIn("settings_release_actions_lock();", cleanup)
        self.assertLess(cleanup.index("settings_end_snowboard_mutation();"), cleanup.index("log_session_end();"))

    def test_substantial_update_repair_uses_durable_foreground_respring_handoff(self) -> None:
        schedule = body(
            self.settings,
            "static void settings_schedule_substantial_update_repair_respring(",
        )
        self.assertIn('[result[@"ok"] boolValue]', schedule)
        self.assertIn('[result[@"respringRecommended"] boolValue]', schedule)
        self.assertIn(
            "settings_record_substantial_repair_respring_marker(", schedule
        )
        self.assertIn(
            "settings_attempt_substantial_repair_respring_if_ready();", schedule
        )

        record = body(
            self.settings,
            "static BOOL settings_record_substantial_repair_respring_marker(",
        )
        self.assertIn(
            "settings_reconcile_snowboard_automatic_repair_lifetime();", record
        )
        self.assertIn('current[@"handoffIdentifier"]', record)
        self.assertIn(
            "kSBLSubstantialRepairRespringMaximumAge +", record
        )
        self.assertIn(
            '@"the bounded handoff window expired"', record
        )
        clear = body(
            self.settings,
            "static void settings_clear_substantial_repair_respring_marker(",
        )
        self.assertIn(
            "settings_reconcile_snowboard_automatic_repair_lifetime();", clear
        )

        admission = body(
            self.settings,
            "static void settings_attempt_substantial_repair_respring_if_ready(",
        )
        self.assertIn("UIApplicationStateActive", admission)
        self.assertIn(
            "settings_schedule_pre_respring_cyanide_activation();", admission
        )
        self.assertIn("g_sbl_substantial_repair_respring_start_attempt >= 3U", admission)
        self.assertIn(
            "settings_begin_system_edit_respring_with_completion(", admission
        )

        automatic = body(
            self.settings, "static BOOL settings_run_snowboard_automatic_repair("
        )
        self.assertIn(
            'settings_schedule_substantial_update_repair_respring(\n'
            '            updateRepairResult, @"automatic-update-repair")',
            automatic,
        )
        explicit = body(
            self.settings,
            "static void settings_run_snowboard_remix_operation_with_completion(",
        )
        self.assertIn(
            "settings_schedule_substantial_update_repair_respring(result, name);",
            explicit,
        )

    def test_post_respring_activation_is_recovery_only_pid_bound_and_bounded(self) -> None:
        activation = body(
            self.settings,
            "static BOOL settings_attempt_post_respring_cyanide_activation(",
        )
        self.assertIn("krw_persistence_has_saved_recovery()", activation)
        self.assertIn("krw_persistence_recover()", activation)
        self.assertNotIn("settings_ensure_kexploit()", activation)
        self.assertNotIn("kexploit_opa334()", activation)
        self.assertIn("currentPID == substantialPreviousPID", activation)
        self.assertIn("currentPID == queuePreviousPID", activation)
        self.assertIn(
            "settings_request_cyanide_foreground_through_springboard(",
            activation,
        )
        self.assertIn(
            '@"post-respring presentation repair", 2.0', activation
        )

        foreground = body(
            self.settings,
            "static BOOL settings_request_cyanide_foreground_through_springboard(",
        )
        self.assertIn('"SBSLaunchApplicationWithIdentifier"', foreground)
        self.assertIn("NSBundle.mainBundle.bundleIdentifier", foreground)

        pre_respring = body(
            self.settings,
            "static void settings_schedule_pre_respring_cyanide_activation(",
        )
        self.assertIn("kexploit_krw_ready()", pre_respring)
        self.assertNotIn("krw_persistence_recover()", pre_respring)
        self.assertNotIn("settings_ensure_kexploit()", pre_respring)
        self.assertIn("attempt < 3U", pre_respring)
        self.assertIn(
            "settings_request_cyanide_foreground_through_springboard(",
            pre_respring,
        )

        scheduler = body(
            self.settings,
            "static void settings_schedule_post_respring_cyanide_activation(",
        )
        for delay in (
            "500LL * NSEC_PER_MSEC",
            "1LL * NSEC_PER_SEC",
            "2LL * NSEC_PER_SEC",
            "5LL * NSEC_PER_SEC",
            "10LL * NSEC_PER_SEC",
        ):
            self.assertIn(delay, scheduler)
        self.assertIn(
            "g_post_respring_activation_running, 0, 1", scheduler
        )
        self.assertIn(
            '@"bounded post-respring activation attempts were exhausted"',
            scheduler,
        )
        self.assertIn(
            "settings_clear_queued_post_respring_foreground_handoff(", scheduler
        )

        restart = body(self.settings, "static void settings_handle_springboard_restart(")
        self.assertIn("g_sbl_automatic_hail_mary_confirmed, 0", restart)
        self.assertIn(
            "settings_schedule_post_respring_cyanide_activation();", restart
        )

    def test_queue_post_respring_handoff_reuses_durable_authority(self) -> None:
        header = (ROOT / "Cyanide/SettingsViewController.h").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "settings_arm_queued_post_respring_foreground_handoff", header
        )
        transaction = body(
            self.settings,
            "static CNDQueuedTransaction *\nsettings_queued_post_respring_handoff_transaction(",
        )
        self.assertIn("CNDQueuedTransactionStateAwaitingRespring", transaction)
        self.assertIn("CNDQueuedActionPhaseAfterRespring", transaction)
        self.assertIn("remaining.count > 0", transaction)

        arm = body(
            self.settings,
            "void settings_arm_queued_post_respring_foreground_handoff(",
        )
        self.assertIn("g_queue_post_respring_foreground_armed, 1", arm)
        self.assertIn(
            "settings_reconcile_snowboard_automatic_repair_lifetime();", arm
        )
        self.assertIn("kQueuedPostRespringForegroundMaximumAge", arm)

        resume = body(
            self.settings,
            "static void settings_resume_queued_post_respring_actions_if_ready(",
        )
        self.assertIn("UIApplicationStateActive", resume)
        self.assertIn("settings_prepare_queued_system_actions", resume)
        self.assertIn("currentPID == transaction.preRespringSpringBoardPID", resume)
        self.assertIn("resumePendingPostRespringActionsIfReady", resume)
        self.assertIn(
            "settings_clear_queued_post_respring_foreground_handoff(", resume
        )

        observer = self.settings[self.settings.index(
            "UIApplicationDidBecomeActiveNotification"
        ):self.settings.index(
            '(void)settings_refresh_screen_awake_state("startup")'
        )]
        self.assertIn(
            "settings_resume_queued_post_respring_actions_if_ready();", observer
        )

    def test_queued_apply_restore_wait_and_release_on_success_failure_or_exception(self) -> None:
        queued = body(self.queue, "- (BOOL)executeSnowBoardAction:")
        self.assertLess(queued.index("settings_begin_snowboard_mutation(YES);"), queued.index("@try {"))
        protected = queued[queued.index("@try {"):queued.index("} @finally {")]
        self.assertIn("settings_apply_snowboard_remix()", protected)
        self.assertIn("settings_restore_all_snowboard_remix()", protected)
        self.assertIn("return NO;", protected)  # stale theme also releases ownership
        self.assertIn("return ok;", protected)
        self.assertIn("settings_end_snowboard_mutation();", queued[queued.index("} @finally {"):])
        # Ownership is local to this executor, never held across other actions.
        self.assertEqual(self.queue.count("settings_begin_snowboard_mutation("), 1)
        coordinator = body(self.queue, "- (void)beginOrResumeCoordinator")
        self.assertIn("dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0)", coordinator)

    def test_queue_reconciles_after_both_applied_state_commit_paths(self) -> None:
        for signature, commit, success in (
            ("- (BOOL)finalizeTransientAppliedStateForTransaction:",
             "CNDTransientAppliedStateFinalizeTransition(", "finalized"),
            ("- (BOOL)prepareBoundaryOnlyTransientAppliedStateForTransaction:",
             "CNDTransientAppliedStatePrepareBoundaryOnlyTransition(", "prepared"),
        ):
            with self.subTest(signature=signature):
                finalize = body(self.queue, signature)
                self.assertIn(f"if ({success} && snowBoardActive != nil)", finalize)
                self.assertLess(finalize.index(commit), finalize.index("settings_reconcile_snowboard_automatic_repair_lifetime();"))
                self.assertIn("CNDQueuedActionOperationApplyTheme", finalize)
        completed = body(self.queue, "- (void)completeCoordinator")
        self.assertIn("if (finalized && completedSnowBoardAction)", completed)
        self.assertIn("settings_request_snowboard_automatic_repair(", completed)


SCHEDULER_MOCKS = r'''
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <assert.h>

typedef NS_ENUM(NSInteger, UIDeviceBatteryState) {
    UIDeviceBatteryStateUnknown, UIDeviceBatteryStateUnplugged,
    UIDeviceBatteryStateCharging, UIDeviceBatteryStateFull
};
static NSString * const UIDeviceBatteryStateDidChangeNotification = @"battery state changed";
@interface UIDevice : NSObject
@property BOOL batteryMonitoringEnabled;
@property UIDeviceBatteryState batteryState;
+ (instancetype)currentDevice;
@end
@implementation UIDevice
+ (instancetype)currentDevice {
    static UIDevice *device;
    if (!device) device = [UIDevice new];
    return device;
}
@end

typedef NS_ENUM(NSInteger, UIApplicationState) {
    UIApplicationStateActive, UIApplicationStateInactive, UIApplicationStateBackground
};
@interface UIApplication : NSObject
@property UIApplicationState applicationState;
+ (instancetype)sharedApplication;
@end
@implementation UIApplication
+ (instancetype)sharedApplication {
    static UIApplication *application;
    if (!application) application = [UIApplication new];
    return application;
}
@end

@interface FakeTimer : NSObject
@property (nonatomic, copy) dispatch_block_t handler;
@property (nonatomic) double deadline;
@property (nonatomic) BOOL canceled;
@property (nonatomic) uint64_t interval;
@end
@implementation FakeTimer
@end

static double fakeNow;
static BOOL fakeOnMainThread = YES;
static BOOL fakeActive = YES;
static BOOL fakeAttempted = YES;
static BOOL fakeCleanup;
static BOOL settings_cleanup_in_progress(void) { return fakeCleanup; }
static void settings_end_statbar_background_task_async(const char *reason) { (void)reason; }
static NSMutableArray<FakeTimer *> *timers;
static NSMutableArray<dispatch_block_t> *mainBlocks;
static NSMutableArray<dispatch_block_t> *workerBlocks;
static dispatch_block_t duringRun;
static NSUInteger runCount;
static NSUInteger lastAttempt;
static volatile int g_sbl_automatic_hail_mary_confirmed;
static volatile int g_sbl_substantial_repair_respring_armed;
static volatile int g_queue_post_respring_foreground_armed;
static NSDictionary *settings_substantial_repair_respring_marker(void) { return nil; }
static BOOL fakeAudioEnabled;
static void ds_keepalive_apply_enabled(BOOL enabled) { fakeAudioEnabled = enabled; }
void settings_reconcile_snowboard_automatic_repair_lifetime(void);

static FakeTimer *fake_create(dispatch_source_type_t type, uintptr_t handle,
                              unsigned long mask, dispatch_queue_t queue)
{
    (void)type; (void)handle; (void)mask;
    assert(queue == dispatch_get_main_queue());
    FakeTimer *timer = [FakeTimer new];
    [timers addObject:timer];
    return timer;
}
static void fake_cancel(FakeTimer *timer) { timer.canceled = YES; }
static void fake_handler(FakeTimer *timer, dispatch_block_t handler) { timer.handler = handler; }
static void fake_resume(FakeTimer *timer) { (void)timer; }
static dispatch_time_t fake_time(dispatch_time_t when, int64_t delta)
{
    assert(when == DISPATCH_TIME_NOW);
    return (dispatch_time_t)(fakeNow * NSEC_PER_SEC) + delta;
}
static void fake_timer(FakeTimer *timer, dispatch_time_t when,
                       uint64_t interval, uint64_t leeway)
{
    (void)leeway;
    timer.interval = interval;
    timer.deadline = (double)when / NSEC_PER_SEC;
}
static void fake_async(dispatch_queue_t queue, dispatch_block_t block)
{
    [(queue == dispatch_get_main_queue() ? mainBlocks : workerBlocks) addObject:[block copy]];
}
static dispatch_queue_t settings_snowboard_automatic_repair_queue(void)
{
    return dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
}
static BOOL settings_snowboard_automatic_repair_is_active(void) { return fakeActive; }
static BOOL settings_run_snowboard_automatic_repair(NSString *reason, NSUInteger attempt)
{
    assert(reason.length > 0);
    runCount++;
    lastAttempt = attempt;
    if (duringRun) duringRun();
    return fakeAttempted;
}
static void settings_arm_snowboard_automatic_repair(void);

#define dispatch_source_t FakeTimer *
#define dispatch_source_create fake_create
#define dispatch_source_cancel fake_cancel
#define dispatch_source_set_event_handler fake_handler
#define dispatch_resume fake_resume
#define dispatch_time fake_time
#define dispatch_source_set_timer fake_timer
#define dispatch_async fake_async
'''

SCHEDULER_HARNESS = r'''
static NSUInteger liveTimers(void)
{
    NSUInteger result = 0;
    for (FakeTimer *timer in timers) if (!timer.canceled) result++;
    return result;
}
static void fireDueTimers(void)
{
    for (FakeTimer *timer in [timers copy]) {
        if (!timer.canceled && timer.deadline <= fakeNow) timer.handler();
    }
}
static void finishWorker(void)
{
    assert(workerBlocks.count == 1);
    dispatch_block_t worker = workerBlocks.firstObject;
    [workerBlocks removeObjectAtIndex:0];
    @try { worker(); } @catch (NSException *exception) { (void)exception; }
    while (mainBlocks.count) {
        dispatch_block_t block = mainBlocks.firstObject;
        [mainBlocks removeObjectAtIndex:0];
        block();
    }
}
static void changePower(UIDeviceBatteryState state)
{
    UIDevice.currentDevice.batteryState = state;
    [NSNotificationCenter.defaultCenter
        postNotificationName:UIDeviceBatteryStateDidChangeNotification object:nil];
}
int main(void)
{
    @autoreleasepool {
        timers = [NSMutableArray new];
        mainBlocks = [NSMutableArray new];
        workerBlocks = [NSMutableArray new];
        // Preflight deferral never starts a cooldown or stretches its 30s retry.
        fakeNow = 50;
        fakeAttempted = NO;
        settings_schedule_snowboard_automatic_repair_internal(@"deferred preflight", 0, 0);
        fireDueTimers();
        duringRun = ^{
            settings_schedule_snowboard_automatic_repair_internal(@"gate retry", 30, 1);
            fakeNow = 55;
        };
        finishWorker();
        assert(!g_sbl_automatic_repair_running && g_sbl_automatic_repair_not_before == 0);
        assert(liveTimers() == 1 && g_sbl_automatic_repair_wakeup.deadline == 80);
        assert(g_sbl_automatic_repair_pending_attempt == 1);
        settings_cancel_pending_snowboard_automatic_repair();
        fakeAttempted = YES;
        runCount = 0;
        duringRun = nil;
        fakeNow = 100;
        settings_schedule_snowboard_automatic_repair_internal(@"queue completed", 5, 0);
        settings_schedule_snowboard_automatic_repair_internal(@"foreground", 20, 0);
        for (int i = 0; i < 100; i++)
            settings_schedule_snowboard_automatic_repair_internal(@"watch notification", 20, 0);
        settings_schedule_snowboard_automatic_repair_internal(@"bounded retry", 60, 2);
        assert(liveTimers() == 1 && g_sbl_automatic_repair_wakeup.deadline == 105);
        assert(g_sbl_automatic_repair_pending_attempt == 0);
        fakeNow = 104;
        fireDueTimers();
        assert(workerBlocks.count == 0);
        fakeNow = 105;
        fireDueTimers();
        assert(g_sbl_automatic_repair_running && workerBlocks.count == 1);
        assert(liveTimers() == 0);

        // All events received while work is running occupy one pending slot.
        duringRun = ^{
            fakeNow = 110;
            settings_schedule_snowboard_automatic_repair_internal(@"watch during run", 20, 0);
            settings_schedule_snowboard_automatic_repair_internal(@"foreground during run", 20, 0);
            settings_schedule_snowboard_automatic_repair_internal(@"urgent queue state changed", 0, 0);
            settings_schedule_snowboard_automatic_repair_internal(@"bounded retry", 60, 1);
            assert(liveTimers() == 0 && workerBlocks.count == 0);
            fakeNow = 115;
        };
        finishWorker();
        assert(runCount == 1 && lastAttempt == 0);
        assert(!g_sbl_automatic_repair_running && liveTimers() == 1);
        assert([g_sbl_automatic_repair_pending_reason isEqual:@"urgent queue state changed"]);
        assert(g_sbl_automatic_repair_wakeup.deadline == 235);
        fakeNow = 234;
        fireDueTimers();
        assert(workerBlocks.count == 0);
        fakeNow = 235;
        fireDueTimers();
        duringRun = ^{ fakeNow = 240; };
        finishWorker();
        assert(runCount == 2 && liveTimers() == 0);

        // Launch/enable, foreground, timer, and retries obey the same floor.
        fakeNow = 250;
        settings_schedule_snowboard_automatic_repair_internal(@"enabled", 5, 0);
        settings_schedule_snowboard_automatic_repair_internal(@"foreground", 20, 0);
        settings_schedule_snowboard_automatic_repair_internal(@"periodic integrity audit", 0, 0);
        assert(liveTimers() == 1 && g_sbl_automatic_repair_wakeup.deadline == 360);
        FakeTimer *oldWakeup = g_sbl_automatic_repair_wakeup;
        fakeActive = NO;
        settings_cancel_pending_snowboard_automatic_repair();
        assert(liveTimers() == 0 && !g_sbl_automatic_repair_pending_reason);
        fakeActive = YES;
        settings_schedule_snowboard_automatic_repair_internal(@"enabled again", 5, 0);
        oldWakeup.handler(); // Already-enqueued canceled handler must be inert.
        assert(liveTimers() == 1 && workerBlocks.count == 0);
        assert(g_sbl_automatic_repair_wakeup.deadline == 360);

        // Disable/re-enable cannot clear ownership or bypass completion cooldown.
        fakeNow = 360;
        fireDueTimers();
        duringRun = ^{
            fakeActive = NO;
            settings_cancel_pending_snowboard_automatic_repair();
            assert(g_sbl_automatic_repair_running);
            fakeActive = YES;
            settings_schedule_snowboard_automatic_repair_internal(@"enabled during run", 5, 0);
            assert(liveTimers() == 0);
            fakeNow = 370;
        };
        finishWorker();
        assert(runCount == 3 && g_sbl_automatic_repair_wakeup.deadline == 490);

        // Even an unexpected preflight exception releases scheduler ownership
        // and retains a state-change event without claiming completed work.
        fakeNow = 490;
        fireDueTimers();
        duringRun = ^{
            settings_schedule_snowboard_automatic_repair_internal(@"state changed", 0, 0);
            fakeNow = 500;
            @throw [NSException exceptionWithName:@"fixture" reason:nil userInfo:nil];
        };
        finishWorker();
        assert(runCount == 4 && !g_sbl_automatic_repair_running);
        assert(liveTimers() == 1 && g_sbl_automatic_repair_wakeup.deadline == 500);

        // A retry alone keeps its bounded budget; a fresh event resets it.
        settings_cancel_pending_snowboard_automatic_repair();
        settings_schedule_snowboard_automatic_repair_internal(@"bounded retry", 60, 2);
        assert(g_sbl_automatic_repair_pending_attempt == 2);
        settings_schedule_snowboard_automatic_repair_internal(@"new notification", 120, 0);
        assert(g_sbl_automatic_repair_pending_attempt == 0);
        fakeActive = NO;
        fakeNow = 620;
        fireDueTimers();
        assert(workerBlocks.count == 0 && liveTimers() == 0);
        assert(!g_sbl_automatic_repair_pending_reason);

        // A caller off-main must enqueue its state change, preserving its
        // original arrival deadline while the main queue catches up.
        fakeActive = YES;
        fakeNow = 1000;
        fakeOnMainThread = NO;
        settings_schedule_snowboard_automatic_repair_internal(@"off-main queue completed", 20, 0);
        assert(mainBlocks.count == 1 && liveTimers() == 0);
        fakeNow = 1010;
        fakeOnMainThread = YES;
        dispatch_block_t request = mainBlocks.firstObject;
        [mainBlocks removeObjectAtIndex:0];
        request();
        assert(g_sbl_automatic_repair_pending_deadline == 1020);
        assert(liveTimers() == 1 && g_sbl_automatic_repair_wakeup.deadline == 1020);

        // Opening/enabling on battery is immediate, even inside a cooldown.
        settings_cancel_pending_snowboard_automatic_repair();
        duringRun = nil;
        fakeNow = 1100;
        g_sbl_automatic_repair_not_before = 1500;
        UIDevice.currentDevice.batteryState = UIDeviceBatteryStateUnplugged;
        settings_apply_snowboard_automatic_repair_enabled(YES);
        assert(fakeAudioEnabled && UIDevice.currentDevice.batteryMonitoringEnabled);
        assert(g_sbl_automatic_repair_power_observer && !g_sbl_automatic_repair_timer);
        assert(g_sbl_automatic_repair_wakeup.deadline == 1100);
        fireDueTimers();
        finishWorker();
        assert(!g_sbl_automatic_repair_wakeup);
        settings_reconcile_snowboard_automatic_repair_lifetime();
        assert(liveTimers() == 0); // Completion/lifetime reconciliation never loops.

        // Connecting starts one immediate pass plus a 30-minute powered timer.
        fakeNow = 1110;
        changePower(UIDeviceBatteryStateCharging);
        assert(g_sbl_automatic_repair_wakeup.deadline == 1110);
        assert(g_sbl_automatic_repair_timer.deadline == 2910);
        assert(g_sbl_automatic_repair_timer.interval == 30ULL * 60ULL * NSEC_PER_SEC);
        FakeTimer *poweredTimer = g_sbl_automatic_repair_timer;
        fireDueTimers();
        duringRun = ^{
            // Charging -> Full is the same power source and does not add work.
            changePower(UIDeviceBatteryStateFull);
            assert(!g_sbl_automatic_repair_pending_reason);
            // A disconnect during a pass coalesces to one follow-up, never parallel work.
            fakeNow = 1111;
            changePower(UIDeviceBatteryStateUnplugged);
            changePower(UIDeviceBatteryStateUnplugged);
            assert(!g_sbl_automatic_repair_timer && poweredTimer.canceled);
            assert(g_sbl_automatic_repair_pending_immediate && !g_sbl_automatic_repair_wakeup);
            assert(workerBlocks.count == 0);
        };
        finishWorker();
        assert(g_sbl_automatic_repair_wakeup.deadline == 1111);
        duringRun = nil;
        fireDueTimers();
        finishWorker();
        assert(liveTimers() == 0);
        poweredTimer.handler(); // Canceled/enqueued power timer cannot audit on battery.
        assert(liveTimers() == 0);

        // Unknown readings stop periodic work without inventing power edges.
        fakeNow = 1120;
        changePower(UIDeviceBatteryStateUnknown);
        assert(liveTimers() == 0);
        changePower(UIDeviceBatteryStateUnplugged);
        assert(liveTimers() == 0);
        changePower(UIDeviceBatteryStateFull);
        assert(g_sbl_automatic_repair_timer && g_sbl_automatic_repair_wakeup);
        fireDueTimers();
        finishWorker();
        FakeTimer *fullTimer = g_sbl_automatic_repair_timer;
        changePower(UIDeviceBatteryStateUnknown);
        assert(fullTimer.canceled && liveTimers() == 0);
        changePower(UIDeviceBatteryStateFull);
        assert(g_sbl_automatic_repair_timer && !g_sbl_automatic_repair_wakeup);

        // The periodic timer fires only after thirty minutes on external power.
        fakeNow = 2920;
        fireDueTimers();
        assert(g_sbl_automatic_repair_wakeup.deadline == 2920);
        fireDueTimers();
        assert(workerBlocks.count == 1);
        finishWorker();
        assert(!g_sbl_automatic_repair_wakeup);
        fakeActive = NO;
        settings_reconcile_snowboard_automatic_repair_lifetime();
        assert(!fakeAudioEnabled && !UIDevice.currentDevice.batteryMonitoringEnabled);
        assert(!g_sbl_automatic_repair_power_observer && liveTimers() == 0);
        changePower(UIDeviceBatteryStateUnplugged);
        assert(liveTimers() == 0);

        // An unavailable initial reading cannot invent a first disconnect.
        UIDevice.currentDevice.batteryMonitoringEnabled = YES;
        UIDevice.currentDevice.batteryState = UIDeviceBatteryStateUnknown;
        fakeActive = YES;
        settings_reconcile_snowboard_automatic_repair_lifetime();
        changePower(UIDeviceBatteryStateUnplugged);
        assert(liveTimers() == 0);
        fakeActive = NO;
        settings_reconcile_snowboard_automatic_repair_lifetime();
        assert(UIDevice.currentDevice.batteryMonitoringEnabled); // Prior owner preserved.
    }
    return 0;
}
'''

LIFECYCLE_HARNESS = SCHEDULER_HARNESS[:SCHEDULER_HARNESS.index("int main(void)")] + r'''
int main(void)
{
    @autoreleasepool {
        timers = [NSMutableArray new];
        mainBlocks = [NSMutableArray new];
        workerBlocks = [NSMutableArray new];
        UIApplication *app = UIApplication.sharedApplication;
        UIDevice.currentDevice.batteryState = UIDeviceBatteryStateUnplugged;

        // Cold launch: willEnterForeground can still observe Background.
        // Launch reconciliation alone must not schedule; activation owns one
        // three-second repair, bypassing a prior completion's cooldown.
        fakeNow = 100;
        g_sbl_automatic_repair_not_before = 1000;
        app.applicationState = UIApplicationStateBackground;
        settings_reconcile_snowboard_automatic_repair_lifetime();
        settings_application_will_enter_foreground();
        assert(g_sbl_automatic_repair_open_pending && liveTimers() == 0);
        app.applicationState = UIApplicationStateActive;
        settings_application_did_become_active();
        assert(!g_sbl_automatic_repair_open_pending);
        assert(liveTimers() == 1 && g_sbl_automatic_repair_wakeup.deadline == 103);
        assert(g_sbl_automatic_repair_pending_immediate);
        settings_application_did_become_active();
        fakeNow = 102;
        fireDueTimers();
        assert(workerBlocks.count == 0);
        fakeNow = 103;
        fireDueTimers();
        finishWorker();
        assert(runCount == 1 && liveTimers() == 0);

        // An interruption returns Inactive -> Active without a foreground edge.
        app.applicationState = UIApplicationStateInactive;
        app.applicationState = UIApplicationStateActive;
        settings_application_did_become_active();
        assert(runCount == 1 && liveTimers() == 0);

        // A warm reopen has the same ordering and one urgent delayed pass.
        app.applicationState = UIApplicationStateBackground;
        settings_application_did_enter_background();
        fakeNow = 110;
        settings_application_will_enter_foreground();
        assert(g_sbl_automatic_repair_open_pending && liveTimers() == 0);
        app.applicationState = UIApplicationStateActive;
        settings_application_did_become_active();
        settings_application_did_become_active();
        assert(g_sbl_automatic_repair_wakeup.deadline == 113);
        fakeNow = 113;
        fireDueTimers();
        finishWorker();
        assert(runCount == 2 && liveTimers() == 0);

        // Cleanup cannot consume an open. Returning to the background abandons
        // that edge, so a later activation alone cannot resurrect it.
        app.applicationState = UIApplicationStateBackground;
        settings_application_did_enter_background();
        settings_application_will_enter_foreground();
        app.applicationState = UIApplicationStateActive;
        fakeCleanup = YES;
        settings_application_did_become_active();
        assert(g_sbl_automatic_repair_open_pending && liveTimers() == 0);
        app.applicationState = UIApplicationStateBackground;
        settings_application_did_enter_background();
        assert(!g_sbl_automatic_repair_open_pending);
        fakeCleanup = NO;
        app.applicationState = UIApplicationStateActive;
        settings_application_did_become_active();
        assert(liveTimers() == 0);

        // If UIKit already reports Inactive at willEnterForeground, the work
        // still belongs to activation. An active pass retains one follow-up.
        app.applicationState = UIApplicationStateBackground;
        settings_application_did_enter_background();
        fakeNow = 120;
        app.applicationState = UIApplicationStateInactive;
        settings_application_will_enter_foreground();
        assert(liveTimers() == 0);
        app.applicationState = UIApplicationStateActive;
        settings_application_did_become_active();
        fakeNow = 123;
        fireDueTimers();
        assert(workerBlocks.count == 1);
        duringRun = ^{
            app.applicationState = UIApplicationStateBackground;
            settings_application_did_enter_background();
            settings_application_will_enter_foreground();
            fakeNow = 125;
            app.applicationState = UIApplicationStateActive;
            settings_application_did_become_active();
            settings_application_did_become_active();
            assert(g_sbl_automatic_repair_pending_immediate);
            assert(!g_sbl_automatic_repair_wakeup && workerBlocks.count == 0);
        };
        finishWorker();
        assert(runCount == 3 && g_sbl_automatic_repair_wakeup.deadline == 128);
        duringRun = nil;
        fakeNow = 128;
        fireDueTimers();
        finishWorker();
        assert(runCount == 4 && liveTimers() == 0);

        // Disabled/unapplied SnowBoard still blocks every lifecycle request.
        fakeActive = NO;
        app.applicationState = UIApplicationStateBackground;
        settings_application_did_enter_background();
        settings_application_will_enter_foreground();
        app.applicationState = UIApplicationStateActive;
        settings_application_did_become_active();
        changePower(UIDeviceBatteryStateUnplugged);
        assert(!fakeAudioEnabled && liveTimers() == 0 && runCount == 4);
    }
    return 0;
}
'''


if __name__ == "__main__":
    unittest.main()
