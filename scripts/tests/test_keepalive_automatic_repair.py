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
        self.assertIn("ds_keepalive_apply_enabled(active);", lifetime)
        inactive = lifetime[lifetime.index("if (!active)"):lifetime.index("if (!g_sbl_automatic_repair_timer)")]
        self.assertIn("dispatch_source_cancel(g_sbl_automatic_repair_timer)", inactive)
        self.assertIn("settings_cancel_pending_snowboard_automatic_repair();", inactive)
        self.assertIn("g_sbl_automatic_hail_mary_confirmed, 0", inactive)
        self.assertIn("return;", inactive)
        self.assertIn("if (NSThread.isMainThread) reconcile();", lifetime)
        self.assertIn("dispatch_async(dispatch_get_main_queue(), reconcile)", lifetime)
        # Background entry must never revive audio solely for unrelated tweaks.
        self.assertEqual(self.settings.count("ds_keepalive_apply_enabled("), 1)

    def test_launch_toggle_and_background_reconcile_lifetime(self) -> None:
        app = (ROOT / "Cyanide/AppDelegate.m").read_text(encoding="utf-8")
        self.assertIn("settings_apply_snowboard_automatic_repair_enabled(", app)
        toggle = body(self.settings, "void settings_apply_snowboard_automatic_repair_enabled(")
        self.assertIn("settings_reconcile_snowboard_automatic_repair_lifetime();", toggle)
        self.assertNotIn("ds_keepalive_apply_enabled(enabled)", toggle)
        background = body(self.settings, "void settings_application_did_enter_background(")
        self.assertIn("settings_reconcile_snowboard_automatic_repair_lifetime();", background)
        self.assertIn("settings_apply_snowboard_automatic_repair_enabled(sender.isOn)", self.settings)

    def test_notifications_and_delayed_work_require_active_snowboard(self) -> None:
        scheduler = body(self.settings, "static void settings_schedule_snowboard_automatic_repair_internal(")
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
        for reason in (
            "mobile application installed", "mobile application updated",
            "launchservices application registered", "launchservices applications changed",
            "mobile installation proxy installed", "app became active",
            "periodic integrity audit", "Automatic Repair enabled",
        ):
            with self.subTest(reason=reason):
                self.assertRegex(self.settings,
                                 r'settings_schedule_snowboard_automatic_repair\(\s+@"' + reason + '"')
        request = body(self.settings, "void settings_request_snowboard_automatic_repair(")
        self.assertIn("settings_schedule_snowboard_automatic_repair(", request)

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"),
                         "requires macOS Foundation and clang")
    def test_production_scheduler_coalesces_with_monotonic_completion_cooldown(self) -> None:
        start = self.settings.index("static dispatch_source_t g_sbl_automatic_repair_wakeup;")
        end = self.settings.index("static volatile int g_sbl_automatic_hail_mary_confirmed", start)
        globals_source = self.settings[start:end]
        functions = "\n".join(
            body(self.settings, signature) + "\n}\n"
            for signature in (
                "static void settings_cancel_pending_snowboard_automatic_repair(",
                "static void settings_arm_snowboard_automatic_repair(",
                "static void settings_schedule_snowboard_automatic_repair_internal(",
            )
        ).replace("NSProcessInfo.processInfo.systemUptime", "fakeNow").replace(
            "NSThread.isMainThread", "fakeOnMainThread"
        )
        with tempfile.TemporaryDirectory(prefix="cyanide-automatic-repair-") as directory:
            fixture = Path(directory) / "scheduler.m"
            executable = Path(directory) / "scheduler"
            fixture.write_text(SCHEDULER_MOCKS + globals_source + functions +
                               SCHEDULER_HARNESS, encoding="utf-8")
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

@interface FakeTimer : NSObject
@property (nonatomic, copy) dispatch_block_t handler;
@property (nonatomic) double deadline;
@property (nonatomic) BOOL canceled;
@end
@implementation FakeTimer
@end

static double fakeNow;
static BOOL fakeOnMainThread = YES;
static BOOL fakeActive = YES;
static BOOL fakeAttempted = YES;
static NSMutableArray<FakeTimer *> *timers;
static NSMutableArray<dispatch_block_t> *mainBlocks;
static NSMutableArray<dispatch_block_t> *workerBlocks;
static dispatch_block_t duringRun;
static NSUInteger runCount;
static NSUInteger lastAttempt;

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
    assert(interval == DISPATCH_TIME_FOREVER);
    (void)leeway;
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
    }
    return 0;
}
'''


if __name__ == "__main__":
    unittest.main()
