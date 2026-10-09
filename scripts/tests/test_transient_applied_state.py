"""Structural checks for SnowBoard/Font/SBC active-state epochs."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class TransientAppliedStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = (ROOT / "Cyanide/installer/CNDTransientAppliedState.h").read_text()
        cls.source = (ROOT / "Cyanide/installer/CNDTransientAppliedState.m").read_text()
        cls.queue = (ROOT / "Cyanide/installer/PackageQueue.m").read_text()
        cls.package_h = (ROOT / "Cyanide/installer/Package.h").read_text()
        cls.package_m = (ROOT / "Cyanide/installer/Package.m").read_text()
        cls.list_ui = (ROOT / "Cyanide/installer/PackagesViewController.m").read_text()
        cls.detail_ui = (ROOT / "Cyanide/installer/PackageDetailViewController.m").read_text()
        cls.settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()
        cls.persistence = (ROOT / "Cyanide/kexploit/persistence.m").read_text()
        cls.app_delegate = (ROOT / "Cyanide/AppDelegate.m").read_text()
        cls.scene_delegate = (ROOT / "Cyanide/SceneDelegate.m").read_text()

    def method(self, source: str, start_marker: str, end_marker: str) -> str:
        start = source.index(start_marker)
        end = source.index(end_marker, start)
        return source[start:end]

    def test_state_is_atomic_application_support_data_not_a_defaults_flag(self) -> None:
        self.assertIn("NSApplicationSupportDirectory", self.source)
        self.assertIn('TransientAppliedState.v1.plist', self.source)
        self.assertIn("NSPropertyListBinaryFormat_v1_0", self.source)
        self.assertIn("NSDataWritingAtomic", self.source)
        self.assertNotIn("NSUserDefaults", self.source)

    def test_state_records_target_pids_generation_and_five_active_keys(self) -> None:
        for field in (
            "schemaVersion",
            "springBoardPID",
            "spotlightPID",
            "bootEpoch",
            "krwGenerationIdentifier",
            "states",
        ):
            with self.subTest(field=field):
                self.assertIn(f'@"{field}"', self.source)
        self.assertIn('@"snowboard-remix"', self.source)
        self.assertIn('@"font-changer"', self.source)
        self.assertIn('@"sbcustomizer"', self.source)
        self.assertIn('@"springboard-fixes"', self.source)
        self.assertIn('@"spotlight-fixes"', self.source)
        self.assertIn("states.count > 5", self.source)
        self.assertIn("allowedStateKeys", self.source)

    def test_unplanned_springboard_change_preserves_persistent_states(self) -> None:
        body = self.method(
            self.source,
            "BOOL CNDTransientAppliedStateReconcileCurrentEpoch",
            "BOOL CNDTransientAppliedStateIsActive",
        )
        self.assertIn("CNDTransientAppliedStateCurrentBootEpoch", body)
        self.assertIn("CNDTransientAppliedStateCurrentSpringBoardPID", body)
        self.assertIn("CNDTransientAppliedStateRemoveProcessLocalStates", body)
        self.assertIn('updated[@"springBoardPID"] = @(currentPID)', body)
        self.assertIn("preserved persistent SnowBoard/Font state", body)
        self.assertIn("pendingTransactionIdentifier", body)
        self.assertIn("pendingFromSpringBoardPID", body)
        self.assertIn("CNDTransientAppliedStateCurrentSpotlightPID", body)
        self.assertIn("cleared only Spotlight Fixes", body)
        self.assertIn(
            "CNDTransientAppliedStatePreserveSnowBoardOnlyLocked", body
        )

    def test_snowboard_state_outlives_boot_and_krw_epochs(self) -> None:
        helper = self.method(
            self.source,
            "static BOOL CNDTransientAppliedStatePreserveSnowBoardOnlyLocked",
            "static pid_t CNDTransientAppliedStateCurrentSpringBoardPID",
        )
        self.assertIn("CNDTransientAppliedStateSnowBoardRemix: @YES", helper)
        self.assertNotIn("CNDTransientAppliedStateFontChanger: @YES", helper)
        self.assertNotIn("pendingTransactionIdentifier", helper)
        self.assertIn("CNDTransientAppliedStateWriteLocked(nil)", helper)

        reset = self.method(
            self.source,
            "BOOL CNDTransientAppliedStateResetAfterKRWLoss",
            "BOOL CNDTransientAppliedStateIsActive",
        )
        self.assertIn(
            "CNDTransientAppliedStatePreserveSnowBoardOnlyLocked", reset
        )
        self.assertIn("preserved durable SnowBoard state", reset)

        active = self.method(
            self.source,
            "BOOL CNDTransientAppliedStateIsActive",
            "BOOL CNDTransientAppliedStateSetActiveForCurrentEpoch",
        )
        self.assertIn(
            "CNDTransientAppliedStatePreserveSnowBoardOnlyLocked", active
        )
        self.assertIn("CNDTransientAppliedStateSnowBoardRemix] &&", active)

    def test_boundary_only_state_is_adopted_and_never_carries_sbc(self) -> None:
        prepare = self.method(
            self.source,
            "BOOL CNDTransientAppliedStatePrepareBoundaryOnlyTransition",
            "void CNDTransientAppliedStateCancelPreparedTransition",
        )
        self.assertIn('pendingAdoptNextSpringBoardPID', prepare)
        self.assertIn("krwGenerationIdentifier", prepare)
        self.assertIn("CNDTransientAppliedStateRemoveProcessLocalStates", prepare)
        reconcile = self.method(
            self.source,
            "BOOL CNDTransientAppliedStateReconcileCurrentEpoch",
            "BOOL CNDTransientAppliedStateIsActive",
        )
        self.assertIn("adoptNextPID", reconcile)
        self.assertIn('adopted[@"springBoardPID"] = @(currentPID)', reconcile)
        self.assertIn("removeObjectForKey:", reconcile)
        self.assertIn('@"pendingAdoptNextSpringBoardPID"', reconcile)

        finalize = self.source[self.source.index(
            "BOOL CNDTransientAppliedStateFinalizeTransition"
        ):]
        cleared = finalize.index(
            "CNDTransientAppliedStateRemoveProcessLocalStates"
        )
        reapplied = finalize.index(
            "states[CNDTransientAppliedStateSBCustomizer] = @YES", cleared
        )
        self.assertLess(cleared, reapplied)

    def test_active_badges_are_deterministic_disk_reads_without_krw(self) -> None:
        body = self.method(
            self.source,
            "BOOL CNDTransientAppliedStateIsActive",
            "BOOL CNDTransientAppliedStateSetActiveForCurrentEpoch",
        )
        self.assertIn("CNDTransientAppliedStateCurrentBootEpoch", body)
        self.assertIn("CNDTransientAppliedStateBootMatches", body)
        self.assertIn(
            "CNDTransientAppliedStatePreserveSnowBoardOnlyLocked", body
        )
        self.assertNotIn("CNDTransientAppliedStateReconcileCurrentEpoch", body)
        self.assertNotIn("CNDTransientAppliedStateCurrentSpringBoardPID", body)
        self.assertNotIn("kexploit_krw_ready", body)
        self.assertLess(body.index("CNDTransientAppliedStateBootMatches"),
                        body.index("states[stateKey]"))

    def test_coordinator_prepares_authorized_transition_before_awaiting(self) -> None:
        body = self.method(
            self.queue,
            "- (void)runCoordinatorBeforeRespring",
            "- (BOOL)executeSpringBoardFixesAction:",
        )
        prepared = body.index("CNDTransientAppliedStatePrepareTransition")
        awaiting = body.index("CNDQueuedTransactionStateAwaitingRespring")
        persisted = body.index("persistDurableTransaction", awaiting)
        notified = body.index("PackageQueueReadyForRespringNotification", persisted)
        self.assertLess(prepared, awaiting)
        self.assertLess(awaiting, persisted)
        self.assertLess(persisted, notified)
        self.assertIn("CNDTransientAppliedStateCancelPreparedTransition", body)

        prepare = self.method(
            self.source,
            "BOOL CNDTransientAppliedStatePrepareTransition",
            "BOOL CNDTransientAppliedStatePrepareBoundaryOnlyTransition",
        )
        self.assertIn("CNDTransientAppliedStateRemoveProcessLocalStates", prepare)

    def test_coordinator_finalizes_state_before_transaction_completion(self) -> None:
        helper = self.method(
            self.queue,
            "- (BOOL)finalizeTransientAppliedStateForTransaction:\n"
            "    (CNDQueuedTransaction *)snapshot\n{",
            "- (BOOL)recordOrdinaryCurrentEpochStateForTransaction:\n"
            "    (CNDQueuedTransaction *)snapshot\n{",
        )
        self.assertIn("CNDTransientAppliedStateFinalizeTransition", helper)
        self.assertIn("CNDQueuedActionKindSnowBoardRemix", helper)
        self.assertIn('com.darksword.font-changer', helper)
        self.assertIn("kSBCustomizerPackageIdentifier", helper)
        self.assertIn("CNDQueuedActionOperationApplyTheme", helper)
        self.assertIn("CNDQueuedActionOperationInstall", helper)

        body = self.method(
            self.queue,
            "- (void)completeCoordinator",
            "- (void)continueCoordinatorAfterRespring",
        )
        finalize = body.index("finalizeTransientAppliedStateForTransaction")
        completed = body.index("CNDQueuedTransactionStateCompleted")
        self.assertLess(finalize, completed)

    def test_state_is_checkpointed_before_optional_presentation_repair(self) -> None:
        body = self.method(
            self.queue,
            "- (void)continueCoordinatorAfterRespring",
            "- (void)resumeCoordinatorAfterVerifiedRespring",
        )
        finalized = body.index("finalizeTransientAppliedStateForTransaction")
        execute = body.index("executePresentationFixesAction")
        self.assertLess(finalized, execute)

    def test_finalize_is_retryable_and_full_reboot_keeps_snowboard(self) -> None:
        body = self.source[self.source.index(
            "BOOL CNDTransientAppliedStateFinalizeTransition"
        ):]
        self.assertIn("alreadyFinalized", body)
        self.assertIn("krwGenerationIdentifier", body)
        reboot = body.index("The queue crossed a full reboot")
        same_pid = body.index("fromPID == toPID", reboot)
        self.assertLess(reboot, same_pid)
        before_log = body[:reboot]
        self.assertIn(
            "CNDTransientAppliedStatePreserveSnowBoardOnlyLocked",
            before_log,
        )
        self.assertIn("state, snowBoardActive, toPID, currentBoot", before_log)

    def test_boot_epoch_match_does_not_mask_a_quick_reboot(self) -> None:
        body = self.method(
            self.source,
            "static BOOL CNDTransientAppliedStateBootMatches",
            "static NSMutableDictionary<NSString *, id> *",
        )
        self.assertIn("<= 5.0", body)

    def test_package_model_exposes_epoch_applied_state(self) -> None:
        self.assertIn("isAppliedForCurrentSystemEpoch", self.package_h)
        body = self.package_m[self.package_m.index(
            "- (BOOL)isAppliedForCurrentSystemEpoch"
        ):self.package_m.index("- (void)install")]
        self.assertIn("CNDTransientAppliedStateSnowBoardRemix", body)
        self.assertIn("CNDTransientAppliedStateFontChanger", body)
        self.assertIn("CNDTransientAppliedStateSBCustomizer", body)

    def test_snowboard_font_and_sbc_render_active_with_pending_precedence(self) -> None:
        list_body = self.method(
            self.list_ui,
            "- (UIView *)accessoryViewForPackage:",
            "- (UIView *)pillWithText:",
        )
        self.assertIn("CNDQueuedActionConflictKeySnowBoardRemix", list_body)
        self.assertGreaterEqual(list_body.count('pillWithText:@"ACTIVE"'), 3)
        self.assertGreaterEqual(list_body.count("isAppliedForCurrentSystemEpoch"), 3)
        self.assertIn('com.darksword.sbcustomizer', list_body)
        self.assertIn("Apply Pending", self.detail_ui)
        self.assertIn("Restore Pending", self.detail_ui)
        self.assertIn('return @"Active"', self.detail_ui)
        self.assertIn("UIColor.systemGreenColor", self.detail_ui)

    def test_font_detail_top_right_action_queues_apply_directly(self) -> None:
        title = self.method(
            self.detail_ui,
            "- (NSString *)manualActionTitleForIntent:",
            "- (NSString *)manualStateText",
        )
        self.assertIn(
            'PackageInstallKindFontChanger) return @"Apply"', title
        )
        self.assertNotRegex(
            title,
            r'PackageInstallKindFontChanger\) return @"Apply/Restore"',
        )

        menu = self.method(
            self.detail_ui,
            "- (UIMenu *)manualActionMenu",
            "- (instancetype)initWithPackage:",
        )
        self.assertNotIn("PackageInstallKindFontChanger", menu)
        self.assertNotIn('@"Restore Stock Fonts"', menu)

        button = self.method(
            self.detail_ui,
            "- (void)updateActionButton",
            "- (UIBarButtonItem *)favoriteBarButtonItem",
        )
        self.assertIn("BOOL directFontApply", button)
        self.assertIn("manual && !directFontApply", button)

        tap = self.method(
            self.detail_ui,
            "- (void)didTapAction",
            "- (void)promptSelectThemeBeforeInstall",
        )
        direct = tap.index("PackageInstallKindFontChanger")
        queued = tap.index(
            "queueManualIntent:PackageQueueIntentInstall", direct
        )
        generic_manual = tap.index("if ([self isManualPackage])", queued)
        self.assertLess(direct, queued)
        self.assertLess(queued, generic_manual)

    def test_sbc_ordinary_queue_persists_current_epoch_state(self) -> None:
        helper = self.method(
            self.queue,
            "- (BOOL)recordOrdinaryCurrentEpochStateForTransaction:\n"
            "    (CNDQueuedTransaction *)snapshot\n{",
            "- (void)completeCoordinator",
        )
        self.assertIn("kSBCustomizerPackageIdentifier", helper)
        self.assertIn("CNDTransientAppliedStateSetActiveForCurrentEpoch", helper)
        completion = self.method(
            self.queue,
            "- (void)settingsActionsDidComplete:",
            "- (void)finishWithFailure:",
        )
        recorded = completion.index("recordOrdinaryCurrentEpochStateForTransaction")
        finished = completion.index("finishSuccessfullyPostingCompletion:YES", recorded)
        self.assertLess(recorded, finished)

    def test_settings_applied_query_uses_sbc_epoch_fallback(self) -> None:
        body = self.method(
            self.settings,
            "BOOL settings_tweak_is_applied",
            "static BOOL settings_clear_all_applied_locked",
        )
        self.assertIn("kSettingsSBCEnabled", body)
        self.assertIn("CNDTransientAppliedStateSBCustomizer", body)

    def test_sbc_completion_does_not_wait_for_one_shot_channel_teardown(self) -> None:
        helper = self.method(
            self.settings,
            "static void settings_release_sbc_one_shot_channel_async",
            "static void settings_prepare_for_respring_sync",
        )
        self.assertIn("dispatch_async", helper)
        self.assertIn("settings_rc_lock", helper)
        self.assertIn("settings_has_persistent_springboard_remote_call_user", helper)
        self.assertIn(
            "settings_destroy_springboard_remote_call_locked_internal_ex",
            helper,
        )

        live_start = self.settings.index(
            "uint64_t generation = __sync_add_and_fetch(&g_sbc_live_apply_generation"
        )
        live_end = self.settings.index(
            "void settings_register_defaults", live_start
        )
        live = self.settings[live_start:live_end]
        completed = live.index("settings_post_actions_complete_async")
        released = live.index("settings_release_sbc_one_shot_channel_async")
        self.assertLess(completed, released)

        runner_start = self.settings.index(
            "static void settings_run_actions_internal"
        )
        runner_end = self.settings.index(
            "typedef NS_ENUM(NSInteger, SettingsSection)", runner_start
        )
        runner = self.settings[runner_start:runner_end]
        queued_completion = runner.index(
            "kSettingsQueuedRunDidCompleteNotification"
        )
        deferred_release = runner.index(
            "settings_release_sbc_one_shot_channel_async", queued_completion
        )
        self.assertLess(queued_completion, deferred_release)

    def test_app_launch_recovery_reconciles_or_resets_without_fresh_exploit(self) -> None:
        launch = self.method(
            self.settings,
            "void settings_reconcile_persisted_applied_state_on_launch(void)",
            "static void settings_reset_springboard_remote_call_health_locked",
        )
        self.assertIn("krw_persistence_recover", launch)
        self.assertIn("CNDTransientAppliedStateReconcileCurrentEpoch", launch)
        self.assertIn("CNDTransientAppliedStateResetAfterKRWLoss", launch)
        self.assertNotIn("kexploit_opa334", launch)
        self.assertIn(
            "settings_reconcile_persisted_applied_state_on_launch();",
            self.app_delegate,
        )
        self.assertNotIn(
            "settings_reconcile_persisted_applied_state_on_launch",
            self.scene_delegate,
        )

        reset = self.method(
            self.source,
            "BOOL CNDTransientAppliedStateResetAfterKRWLoss",
            "BOOL CNDTransientAppliedStateIsActive",
        )
        self.assertIn("fileExistsAtPath", reset)
        self.assertIn(
            "CNDTransientAppliedStatePreserveSnowBoardOnlyLocked", reset
        )
        self.assertIn("CNDTransientAppliedStateWriteLocked(nil)", reset)

    def test_cold_launch_initializes_offsets_before_consuming_recovery_tokens(self) -> None:
        launch = self.method(
            self.settings,
            "void settings_reconcile_persisted_applied_state_on_launch(void)",
            "static void settings_reset_springboard_remote_call_health_locked",
        )
        recover = self.persistence[
            self.persistence.index("bool krw_persistence_recover(void)") :
        ]
        self.assertIn("krw_persistence_recover()", launch)
        self.assertIn("if (!off_proc_p_pid)", recover)
        self.assertIn('SYSTEM_VERSION_LESS_THAN(@"26.1")', recover)
        self.assertLess(recover.index("offsets_init();"),
                        recover.index("persist_consume_saved_token("))
        self.assertLess(recover.index("off_thread_t_tro"),
                        recover.index("kutils_recover_self_proc_from("))

    def test_process_fix_actions_save_independent_active_states(self) -> None:
        self.assertIn("CNDTransientAppliedStateSpringBoardFixes", self.queue)
        self.assertIn("CNDTransientAppliedStateSpotlightFixes", self.queue)
        self.assertIn("executeSpringBoardFixesAction", self.queue)
        self.assertIn("executeSpotlightFixesAction", self.queue)

    def test_fresh_krw_generation_never_counts_as_continuity(self) -> None:
        ensure = self.method(
            self.settings,
            "static BOOL settings_ensure_kexploit(void)",
            "static void settings_run_lsreg_baseline_action",
        )
        acquisition = ensure[ensure.index("int res = kexploit_opa334()") :]
        before_acquisition = ensure[: ensure.index("int res = kexploit_opa334()")]
        self.assertIn("CNDTransientAppliedStateResetAfterKRWLoss", before_acquisition)
        self.assertNotIn("CNDTransientAppliedStateReconcileCurrentEpoch", acquisition)
        self.assertNotIn("CNDTransientAppliedStateReconcileCurrentEpoch", ensure)
        self.assertIn("settings_notify_package_queue_changed_async", ensure)


if __name__ == "__main__":
    unittest.main()
