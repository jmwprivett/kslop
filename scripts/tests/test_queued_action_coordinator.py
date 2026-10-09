"""Structural checks for the durable pre/post-respring coordinator."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class QueuedActionCoordinatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.queue = (ROOT / "Cyanide/installer/PackageQueue.m").read_text()
        cls.queue_h = (ROOT / "Cyanide/installer/PackageQueue.h").read_text()
        cls.progress = (ROOT / "Cyanide/installer/InstallProgressViewController.m").read_text()
        cls.review = (ROOT / "Cyanide/installer/QueueReviewViewController.m").read_text()
        cls.transaction_h = (ROOT / "Cyanide/installer/CNDQueuedTransaction.h").read_text()
        cls.transaction_m = (ROOT / "Cyanide/installer/CNDQueuedTransaction.m").read_text()
        cls.hook = (ROOT / "Cyanide/installer/CNDIconServicesConsumerHook.m").read_text()
        cls.remix = (ROOT / "Cyanide/installer/CNDSnowBoardRemix.m").read_text()
        cls.settings_h = (ROOT / "Cyanide/SettingsViewController.h").read_text()
        cls.settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()

    def queue_method(self, marker: str, next_marker: str) -> str:
        start = self.queue.index(marker)
        end = self.queue.index(next_marker, start)
        return self.queue[start:end]

    def test_boundary_metadata_has_an_atomic_transaction_updater(self) -> None:
        signature = "preRespringSpringBoardPID:(pid_t)preRespringSpringBoardPID"
        self.assertIn(signature, self.transaction_h)
        self.assertIn(signature, self.transaction_m)
        self.assertIn("krwGenerationIdentifier:krwGenerationIdentifier", self.transaction_m)

    def test_before_phase_checkpoints_each_action_around_real_work(self) -> None:
        body = self.queue_method(
            "- (void)runCoordinatorBeforeRespring",
            "- (BOOL)executeSpringBoardFixesAction:",
        )
        running = body.index("CNDQueuedActionStateRunning")
        mutation = body.index("executeSynchronousQueuedAction", running)
        succeeded = body.index("CNDQueuedActionStateSucceeded", mutation)
        self.assertLess(running, mutation)
        self.assertLess(mutation, succeeded)
        self.assertIn("CNDQueuedActionPhaseBeforeRespring", body)

    def test_adaptive_fixes_run_now_or_after_a_real_boundary(self) -> None:
        body = self.queue_method(
            "- (void)runCoordinatorBeforeRespring",
            "- (BOOL)executeSpringBoardFixesAction:",
        )
        self.assertIn("transactionRequiresRespring", body)
        self.assertIn("CNDQueuedActionsRequireRespring", body)
        self.assertIn("executePresentationFixesAction:action", body)
        self.assertIn("if (!transactionRequiresRespring)", body)
        direct = body.index("if (!transactionRequiresRespring)")
        completed = body.index("[self completeCoordinator]", direct)
        pid = body.index("settings_current_springboard_pid", completed)
        self.assertLess(completed, pid)

    def test_adaptive_fixes_wait_for_live_toggle_completion(self) -> None:
        before = self.queue_method(
            "- (void)runCoordinatorBeforeRespring",
            "- (BOOL)executeSpringBoardFixesAction:",
        )
        toggle = before.index("PackageInstallKindToggle")
        staged = before.index("applyCommittedState:", toggle)
        flag = before.index(
            "resumeCoordinatorBeforeRespringAfterSettings = YES", staged
        )
        tokened = before.index(
            "beginPendingSettingsRunForCoordinator:YES", flag
        )
        self.assertLess(toggle, staged)
        self.assertLess(staged, flag)
        self.assertLess(flag, tokened)

        completion = self.queue_method(
            "- (void)settingsActionsDidComplete:",
            "- (void)finishWithFailure:",
        )
        self.assertIn("resumeBeforeRespring", completion)
        checkpoint = completion.index("CNDQueuedActionStateSucceeded")
        resume_before = completion.index(
            "runCoordinatorBeforeRespring", checkpoint
        )
        resume_after = completion.index(
            "continueCoordinatorAfterRespring", resume_before
        )
        self.assertLess(checkpoint, resume_before)
        self.assertLess(resume_before, resume_after)

        complete = self.queue_method(
            "- (void)completeCoordinator",
            "- (void)continueCoordinatorAfterRespring",
        )
        self.assertIn("recordOrdinaryCurrentEpochStateForTransaction", complete)

    def test_boundary_only_plan_completes_without_empty_continuation(self) -> None:
        body = self.queue_method(
            "- (void)runCoordinatorBeforeRespring",
            "- (BOOL)executeSpringBoardFixesAction:",
        )
        self.assertIn("postRespringActions.count == 0", body)
        self.assertIn(
            "prepareBoundaryOnlyTransientAppliedStateForTransaction", body
        )
        completed = body.index("CNDQueuedTransactionStateCompleted")
        awaiting = body.index("CNDQueuedTransactionStateAwaitingRespring")
        persisted = body.index("persistDurableTransaction", awaiting)
        notified = body.index("PackageQueueReadyForRespringNotification", persisted)
        self.assertLess(completed, persisted)
        self.assertLess(awaiting, persisted)
        self.assertLess(persisted, notified)
        self.assertIn("will not create an empty continuation", body)

        needs = self.queue_method(
            "- (BOOL)transactionNeedsCoordinator",
            "- (CNDQueuedAction *)existingActionWithRecordIdentifier:",
        )
        terminal = needs.index("CNDQueuedTransactionStateCompleted")
        boundary = needs.index("preRespringSpringBoardPID", terminal)
        self.assertLess(terminal, boundary)

    def test_boundary_is_persisted_before_respring_notification(self) -> None:
        body = self.queue_method(
            "- (void)runCoordinatorBeforeRespring",
            "- (BOOL)executeSpringBoardFixesAction:",
        )
        awaiting = body.index("CNDQueuedTransactionStateAwaitingRespring")
        persist = body.index("persistDurableTransaction", awaiting)
        notify = body.index("PackageQueueReadyForRespringNotification", persist)
        self.assertLess(awaiting, persist)
        self.assertLess(persist, notify)
        self.assertIn("settings_current_springboard_pid", body)
        self.assertIn("settings_current_boot_epoch", body)

    def test_ui_runs_exact_three_second_countdown_then_shared_respring(self) -> None:
        self.assertIn("PackageQueueReadyForRespringNotification", self.queue_h)
        body = self.progress[self.progress.index(
            "- (void)didReceiveReadyForRespringNotification:"
        ):self.progress.index("- (void)scheduleHideHomeBarRespringPrompt")]
        self.assertIn("runRespringCountdownValue:3", body)
        self.assertIn("NSEC_PER_SEC", body)
        self.assertIn("value - 1", body)
        self.assertIn("settings_begin_system_edit_respring_with_completion", body)
        self.assertIn("if (!self || started) return", body)
        self.assertIn("self.respringCountdownActive = NO", body)
        self.assertIn('self.hideOrDoneButton.title = @"Retry"', body)

    def test_resume_requires_krw_and_a_verified_process_or_boot_boundary(self) -> None:
        body = self.queue_method(
            "- (void)resumeCoordinatorAfterVerifiedRespring",
            "- (void)beginOrResumeCoordinator",
        )
        self.assertIn("settings_prepare_queued_system_actions", body)
        self.assertIn("settings_current_springboard_pid", body)
        self.assertIn("settings_current_boot_epoch", body)
        self.assertIn("CNDQueuedBootEpochMatches", body)
        self.assertIn(
            "currentPID != previousPID || fullBootChanged", body
        )
        boundary = body.index("processBoundaryObserved")
        ready = body.index("CNDQueuedTransactionStateReadyAfterRespring")
        running = body.index("CNDQueuedTransactionStateRunningAfterRespring")
        self.assertLess(boundary, ready)
        self.assertLess(ready, running)

    def test_after_phase_waits_for_runtime_completion_before_fixes(self) -> None:
        body = self.queue_method(
            "- (void)continueCoordinatorAfterRespring",
            "- (void)resumeCoordinatorAfterVerifiedRespring",
        )
        self.assertIn("CNDQueuedActionPhaseAfterRespring", body)
        self.assertIn("beginPendingSettingsRunForCoordinator:YES", body)
        completion = self.queue_method(
            "- (void)settingsActionsDidComplete:",
            "- (void)finishWithFailure:",
        )
        checkpoint = completion.index("CNDQueuedActionStateSucceeded")
        resume = completion.index("continueCoordinatorAfterRespring", checkpoint)
        self.assertLess(checkpoint, resume)
        self.assertIn("PackageQueueExecutionDidCompleteNotification", self.progress)
        self.assertIn("expectsPackageQueueCompletion = YES", self.review)

    def test_queue_runtime_completion_is_token_scoped(self) -> None:
        self.assertIn("kSettingsQueuedRunDidCompleteNotification", self.queue)
        self.assertIn("kSettingsQueuedRunCompletionTokenKey", self.queue)
        self.assertIn("settingsCompletionToken", self.queue)
        self.assertIn("settings_run_pending_actions_for_queue_token", self.queue)
        completion = self.queue_method(
            "- (void)settingsActionsDidComplete:",
            "- (void)finishWithFailure:",
        )
        self.assertIn("observedToken", completion)
        self.assertIn("expectedToken", completion)
        self.assertIn("isEqualToString:expectedToken", completion)
        self.assertNotIn("successValue == nil", completion)

        self.assertIn(
            "settings_run_pending_actions_for_queue_token",
            self.settings_h,
        )
        self.assertIn(
            "kSettingsQueuedRunDidCompleteNotification",
            self.settings_h,
        )
        runner_start = self.settings.index(
            "static void settings_run_actions_internal"
        )
        runner_end = self.settings.index(
            "typedef NS_ENUM(NSInteger, SettingsSection)", runner_start
        )
        runner = self.settings[runner_start:runner_end]
        self.assertIn("queueCompletionToken", runner)
        self.assertIn("tokened queue run rejected", runner)
        self.assertIn("kSettingsQueuedRunCompletionTokenKey", runner)
        self.assertIn("settings_post_queued_run_complete_async", runner)

    def test_queue_and_direct_activity_completion_channels_are_separate(self) -> None:
        self.assertIn("expectsPackageQueueCompletion", self.progress)
        self.assertIn("PackageQueueExecutionDidCompleteNotification", self.progress)
        self.assertIn("kSettingsActionsDidCompleteNotification", self.progress)
        self.assertIn("expectsPackageQueueCompletion = YES", self.review)

    def test_respring_start_failure_unlocks_a_retryable_activity(self) -> None:
        self.assertIn(
            "settings_begin_system_edit_respring_with_completion",
            self.settings_h,
        )
        start = self.settings.index(
            "void settings_begin_system_edit_respring_with_completion"
        )
        end = self.settings.index(
            "void settings_present_system_edit_respring_prompt", start
        )
        body = self.settings[start:end]
        self.assertIn("completion(NO", body)
        self.assertIn("settings_show_respring_overlay_now", body)
        self.assertIn("completion(started", body)
        self.assertIn("respringRetryAvailable = YES", self.progress)
        self.assertIn('hideOrDoneButton.title = @"Retry"', self.progress)

    def test_target_fixes_have_independent_executors_and_active_state(self) -> None:
        springboard = self.queue_method(
            "- (BOOL)executeSpringBoardFixesAction:",
            "- (BOOL)executeSpotlightFixesAction:",
        )
        self.assertIn("applySpringBoardTweaks", springboard)
        self.assertIn("CNDTransientAppliedStateSpringBoardFixes", springboard)
        self.assertNotIn("repairSpotlightPresentation", springboard)
        self.assertNotIn("acquireSpotlightLifetimeAssertion", springboard)

        spotlight = self.queue_method(
            "- (BOOL)executeSpotlightFixesAction:",
            "- (BOOL)executePresentationFixesAction:",
        )
        launch = spotlight.index("presentSpotlight")
        repair = spotlight.index("repairSpotlightPresentation")
        self.assertLess(launch, repair)
        self.assertNotIn("acquireSpotlightLifetimeAssertion", spotlight)
        self.assertIn("CNDTransientAppliedStateSpotlightFixes", spotlight)
        self.assertIn("failures.count == 0", spotlight)
        self.assertNotIn("applySpringBoardTweaks", spotlight)
        self.assertNotIn("CNDIconServicesConsumerLifecycleStart", spotlight)

    def test_spotlight_repair_uses_bounded_springboard_presentation(self) -> None:
        body = self.queue_method(
            "- (BOOL)executeSpotlightFixesAction:",
            "- (BOOL)executePresentationFixesAction:",
        )
        launch = body.index("[CNDSnowBoardRemix presentSpotlight]")
        state = body.index("application.applicationState", launch)
        stable = body.index("stableSpotlightSamples >= 2", state)
        repair = body.index("repairSpotlightPresentation", stable)
        self.assertLess(launch, state)
        self.assertLess(state, stable)
        self.assertLess(stable, repair)
        self.assertIn("CNDKernelTaskBridgeResolveProcessPID", body)
        self.assertIn("systemUptime + 5.0", body)
        self.assertNotIn("OPEN SPOTLIGHT NOW", body)
        self.assertNotIn("sleep(3);", body)

        log_view = (ROOT / "Cyanide/LogTextView.m").read_text()
        self.assertIn('[content hasPrefix:@"[SPOTLIGHT]"]', log_view)

        obsolete_gate_symbols = (
            "PackageQueueRequiresSpotlightOpenNotification",
            "waitingForSpotlightUserConfirmation",
            "spotlightUserConfirmationGranted",
            "postSpotlightOpenPrompt",
            "continueAfterOpeningSpotlight",
            "deferSpotlightRepair",
            "didReceiveSpotlightOpenNotification",
        )
        combined = self.queue_h + self.queue + self.progress
        for symbol in obsolete_gate_symbols:
            with self.subTest(symbol=symbol):
                self.assertNotIn(symbol, combined)

    def test_spotlight_remotecall_does_not_wait_for_background_state(self) -> None:
        body = self.queue_method(
            "- (BOOL)executeSpotlightFixesAction:",
            "- (BOOL)executePresentationFixesAction:",
        )
        begin = body.index("beginBackgroundTaskWithName:")
        launch = body.index("[CNDSnowBoardRemix presentSpotlight]", begin)
        state = body.index("application.applicationState", launch)
        stable = body.index("stableSpotlightSamples >= 2", state)
        repair = body.index("repairSpotlightPresentation", stable)
        cleanup = body.index("@finally", repair)
        end = body.index("endBackgroundTask:task", cleanup)
        self.assertLess(begin, launch)
        self.assertLess(launch, state)
        self.assertLess(state, stable)
        self.assertLess(stable, repair)
        self.assertLess(repair, cleanup)
        self.assertLess(cleanup, end)
        self.assertNotIn("acquireSpotlightLifetimeAssertion", body)
        self.assertIn("backgroundTimeRemaining >= 15.0", body)
        self.assertIn("remoteCallsSafe && backgroundTaskIsLive", body)
        self.assertIn("applicationIsBackgrounded", body)
        self.assertNotIn("transitionCompleted", body)
        self.assertNotIn("remoteCallsSafe && applicationIsBackgrounded", body)
        self.assertIn("__atomic_store_n(&backgroundTaskExpired", body)
        self.assertIn("__atomic_load_n(&backgroundTaskExpired", body)
        self.assertIn("if (remoteCallsSafe)", body)

    def test_assertion_uses_exact_abi_one_session_and_associated_retention(self) -> None:
        helper_start = self.hook.index(
            "cnd_consumer_acquire_spotlight_assertion_in_current_session("
        )
        launch_start = self.hook.index(
            "CNDIconServicesConsumerHookPresentSpotlight(void)", helper_start
        )
        helper = self.hook[helper_start:launch_start]
        launch = self.hook[launch_start:self.hook.index(
            "CNDIconServicesConsumerHookRetireSharingUIService(void)",
            launch_start,
        )]
        self.assertEqual(launch.count("initWithProcess:@\"SpringBoard\""), 1)
        self.assertEqual(launch.count("remote_call_with_session(session"), 1)
        toggle = launch.index('springBoardClass, "_toggleSearch", NO,')
        assertion = launch.index(
            "cnd_consumer_acquire_spotlight_assertion_in_current_session(",
            toggle,
        )
        teardown = launch.index("[session destroyRemoteCall]", assertion)
        self.assertLess(toggle, assertion)
        self.assertLess(assertion, teardown)
        for encoding in (
            "@40@0:8@16@24@32",
            "B24@0:8o^@16",
            "B16@0:8",
            "Q16@0:8",
            "@20@0:8i16",
            "@20@0:8C16",
            "@16@0:8",
        ):
            with self.subTest(encoding=encoding):
                self.assertIn(encoding, helper)
        self.assertIn("grantWithResistance:", helper)
        self.assertIn('r_class("RBSJetsamPriorityGrant")', helper)
        self.assertIn("grantWithBackgroundPriority", helper)
        self.assertIn("30U", helper)
        self.assertIn('"arrayByAddingObject:"', helper)
        self.assertNotIn("RBSCPUAccessGrant", helper)
        self.assertNotIn("RBSRunningReasonAttribute", helper)
        self.assertIn("objc_setAssociatedObject", helper)
        self.assertIn("objc_getAssociatedObject", helper)
        self.assertIn("observedState == 1U", helper)
        acquire = helper.index('assertion, "acquireWithError:"')
        associate = helper.index('"objc_setAssociatedObject"', acquire)
        invalidate_previous = helper.index(
            'existing, "invalidateSyncWithError:"', associate
        )
        self.assertLess(acquire, associate)
        self.assertLess(associate, invalidate_previous)
        self.assertIn("previousPreservedUntilReplacement", helper)
        failed_candidate = helper.index("if (!report->retained", associate)
        rollback = helper.index('"objc_setAssociatedObject"', failed_candidate)
        invalidate_candidate = helper.index(
            'assertion, "invalidateSyncWithError:"', rollback
        )
        self.assertLess(rollback, invalidate_candidate)

    def test_completion_is_checkpointed_before_queue_file_removal(self) -> None:
        body = self.queue_method(
            "- (void)completeCoordinator",
            "- (void)continueCoordinatorAfterRespring",
        )
        completed = body.index("CNDQueuedTransactionStateCompleted")
        persisted = body.index("persistDurableTransaction", completed)
        cleared = body.index("self.transaction = nil", persisted)
        removed = body.index("persistDurableTransaction", cleared)
        self.assertLess(completed, persisted)
        self.assertLess(persisted, cleared)
        self.assertLess(cleared, removed)

    def test_review_exposes_manual_resume_and_no_phase_three_placeholder(self) -> None:
        self.assertIn("Continue After Respring", self.review)
        self.assertNotIn("Shared Respring Plan Saved", self.review)
        self.assertNotIn("execution coordinator is not active", self.queue)


if __name__ == "__main__":
    unittest.main()
