"""Structural checks for mixed queue admission and presentation."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class QueuedActionAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.queue_h = (ROOT / "Cyanide/installer/PackageQueue.h").read_text()
        cls.queue_m = (ROOT / "Cyanide/installer/PackageQueue.m").read_text()
        cls.settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()
        cls.review = (ROOT / "Cyanide/installer/QueueReviewViewController.m").read_text()
        cls.popup = (ROOT / "Cyanide/installer/QueuePopupBar.m").read_text()
        cls.snapshot = (ROOT / "Cyanide/installer/CNDQueueExecutionSnapshot.m").read_text()
        cls.snowboard = (ROOT / "Cyanide/tweaks/snowboardlite.m").read_text()
        cls.detail = (ROOT / "Cyanide/installer/PackageDetailViewController.m").read_text()

    def queue_method(self, marker: str, next_marker: str) -> str:
        start = self.queue_m.index(marker)
        end = self.queue_m.index(next_marker, start)
        return self.queue_m[start:end]

    def settings_method(self, marker: str, next_marker: str) -> str:
        start = self.settings.index(marker)
        end = self.settings.index(next_marker, start)
        return self.settings[start:end]

    def test_public_queue_exposes_standalone_admission_and_removal(self) -> None:
        for api in (
            "queuedStandaloneActions",
            "queueStandaloneAction",
            "standaloneActionForConflictKey",
            "removeStandaloneActionForConflictKey",
        ):
            with self.subTest(api=api):
                self.assertIn(api, self.queue_h)

    def test_admission_validates_catalog_shape_and_replaces_conflict(self) -> None:
        body = self.queue_method(
            "- (BOOL)queueStandaloneAction:",
            "- (BOOL)removeStandaloneActionForConflictKey:",
        )
        self.assertIn("CNDQueuedActionHasSupportedShape", body)
        self.assertIn("CNDQueuedActionConflictKey(action)", body)
        self.assertIn("CNDQueuedActionConflictKey(existing)", body)
        self.assertIn("transactionByUpdatingState:executing", body)
        self.assertIn("CNDQueuedTransactionStateCollecting", body)
        self.assertIn("hasExecutingTransaction", body)
        self.assertIn("self.transaction = oldTransaction", body)
        self.assertIn("persistDurableTransaction", body)

    def test_restore_atomically_drops_stale_post_respring_theme_fixes(self) -> None:
        body = self.queue_method(
            "- (BOOL)queueStandaloneAction:",
            "- (BOOL)removeStandaloneActionForConflictKey:",
        )
        restore = body.index("CNDQueuedActionOperationRestoreTheme")
        stale = body.index("staleThemePresentation", restore)
        fixes = body.index("CNDQueuedActionIsPresentationFix", stale)
        rewrite = body.index("transactionByUpdatingState", fixes)
        persist = body.index("persistDurableTransaction", rewrite)
        self.assertLess(restore, stale)
        self.assertLess(stale, fixes)
        self.assertLess(fixes, rewrite)
        self.assertLess(rewrite, persist)

    def test_pending_count_and_popup_include_standalone_actions(self) -> None:
        pending = self.queue_method(
            "- (NSInteger)pendingCount",
            "- (PackageQueueIntent)intentForPackage:",
        )
        self.assertIn("self.queuedStandaloneActions.count", pending)
        self.assertIn("snapshot.popupSubtitle", self.popup)
        self.assertIn("_standaloneActionCount", self.snapshot)
        self.assertIn("system action", self.snapshot)

    def test_system_file_packages_are_no_longer_forced_to_run_alone(self) -> None:
        self.assertNotIn("PackageRequiresExclusiveRespringEdit", self.queue_m)
        self.assertNotIn("hasExplicitExclusiveRespringEditQueued", self.queue_m)
        self.assertNotIn("Run System Edit Alone", self.review)
        self.assertNotIn("One shared respring", self.review)
        self.assertNotIn("sharedRespringHeaderView", self.review)

    def test_saved_run_reopens_for_new_queue_items(self) -> None:
        helper = self.queue_method(
            "- (BOOL)prepareTransactionForQueueEditing:",
            "- (BOOL)transactionNeedsCoordinator",
        )
        self.assertIn("boundaryObserved", helper)
        self.assertIn("finalizeTransientAppliedStateForTransaction", helper)
        self.assertIn("CNDQueuedActionStateSucceeded", helper)
        self.assertIn("CNDQueuedActionStatePending", helper)
        self.assertIn("collectingTransactionWithActions", helper)
        self.assertIn("CNDTransientAppliedStateCancelPreparedTransition", helper)

        package_admission = self.queue_method(
            "- (BOOL)canQueueIntent:",
            "- (void)toggleForPackage:",
        )
        standalone_admission = self.queue_method(
            "- (BOOL)queueStandaloneAction:",
            "- (BOOL)removeStandaloneActionForConflictKey:",
        )
        # Admission no longer gates on the saved plan; the reopen happens in
        # the enqueue path, where a stopped plan joins the new item.
        self.assertNotIn("prepareTransactionForQueueEditing", package_admission)
        self.assertIn("prepareTransactionForQueueEditing", standalone_admission)
        self.assertNotIn("Finish or retry the saved respring plan", self.queue_m)

    def test_admission_never_blocks_and_defers_conflicts_to_execution(self) -> None:
        admission = self.queue_method(
            "- (BOOL)canQueueIntent:",
            "- (BOOL)hasExecutingTransaction",
        )
        # Queueing is refused only by a durable store that cannot be written.
        self.assertIn("durableStoreUnavailable", admission)
        self.assertNotIn("commitInFlight", admission)
        self.assertNotIn("still applying", admission)

        enqueue = self.queue_method(
            "- (BOOL)queueIntent:",
            "- (void)queueIntent:",
        )
        # A stopped plan is reopened and an executing plan is appended to in
        # place instead of being replaced or dropped.
        self.assertIn("prepareTransactionForQueueEditing", enqueue)
        self.assertIn("hasExecutingTransaction", enqueue)
        self.assertIn("saveCollectingTransaction", enqueue)
        # The one remaining refusal is a failed durable write, and it reports.
        self.assertIn("The queued change could not be saved.", enqueue)

        collecting = self.queue_method(
            "- (BOOL)saveCollectingTransaction",
            "- (BOOL)prepareTransactionForInstalls:",
        )
        # An executing transaction keeps its state and boundary metadata.
        self.assertIn("self.commitInFlight", collecting)
        self.assertIn("executing", collecting)
        self.assertIn("CNDQueuedTransactionStateCollecting", collecting)

    def test_finished_pass_never_swallows_work_queued_during_it(self) -> None:
        for marker, next_marker in (
            ("- (void)completeCoordinator",
             "- (void)continueCoordinatorAfterRespring"),
            ("- (void)finishSuccessfullyPostingCompletion:",
             "- (void)postCompletionWithSuccess:"),
        ):
            with self.subTest(method=marker):
                body = self.queue_method(marker, next_marker)
                # An action queued while the pass ran stays Pending and durable
                # for the next pass instead of being cleared away.
                self.assertIn("CNDQueuedActionStatePending", body)
                self.assertIn("retainUnstartedActions", body)

    def test_package_admission_reports_a_failed_durable_write(self) -> None:
        self.assertIn("- (BOOL)queueIntent:(PackageQueueIntent)intent", self.queue_h)
        self.assertIn("presentQueueFailure", self.detail)
        self.assertIn("queueIntent:intent\n                                      forPackage:self.package\n                                          reason:&reason", self.detail)

    def test_snowboard_buttons_admit_durable_actions(self) -> None:
        rows = self.settings_method(
            "- (NSArray<NSDictionary *> *)snowboardLiteRows",
            "- (NSArray<NSDictionary *> *)fontChangerRows",
        )
        self.assertIn('CNDQueuedActionConflictKeySnowBoardRemix', rows)
        self.assertIn('action": @"sbl-queue-apply"', rows)
        self.assertIn('action": @"sbl-queue-restore"', rows)
        self.assertIn('@"title": @"Manual Icon Fix"', rows)
        self.assertIn('action": @"sbl-manual-icon-fix"', rows)
        self.assertNotIn('action": @"sbl-queue-transparency-fix"', rows)
        self.assertNotIn(
            'action": @"sbl-queue-transparency-fix-restore"', rows
        )
        self.assertNotIn('action": @"sbl-queue-springboard-fixes"', rows)
        self.assertNotIn('action": @"sbl-queue-spotlight-fixes"', rows)
        self.assertNotIn('action": @"sbl-test-calendar-repair"', rows)
        self.assertNotIn('action": @"sbl-start-kernel-consumer-watcher"', rows)
        self.assertNotIn('action": @"sbl-repair-springboard-transparency"', rows)
        self.assertNotIn('action": @"sbl-repair-spotlight-transparency"', rows)

        selection = self.settings[self.settings.index(
            "if (indexPath.section == SectionSnowBoardLite)"
        ):self.settings.index(
            "if (indexPath.section == SectionFontChanger)"
        )]
        self.assertIn("CNDQueuedSnowBoardRemixAction(YES", selection)
        self.assertIn("CNDQueuedSnowBoardRemixAction(NO", selection)
        self.assertIn('settings_run_snowboard_remix_operation(\n'
                      '                    @"Manual Icon Fix", YES', selection)
        self.assertIn("[CNDSnowBoardRemix applyIconFixes]", selection)
        self.assertNotIn("CNDQueuedTransparencyFixAction", selection)
        self.assertNotIn("CNDQueuedSpringBoardFixesAction", selection)
        self.assertNotIn("CNDQueuedSpotlightFixesAction", selection)
        self.assertNotIn("repairSpringBoardCalendarForTesting", selection)
        self.assertNotIn("settings_apply_snowboard_remix()", selection)
        self.assertNotIn("settings_restore_all_snowboard_remix()", selection)

    def test_transparency_toggle_refreshes_existing_snapshot(self) -> None:
        toggle = self.settings_method(
            "- (void)toggleChanged:",
            "- (void)sliderChanged:",
        )
        self.assertIn("CNDQueuedActionConflictKeySpringBoardFixes", toggle)
        self.assertIn("CNDQueuedActionConflictKeySpotlightFixes", toggle)
        self.assertIn("CNDQueuedSpringBoardFixesAction(YES)", toggle)
        self.assertIn("CNDQueuedSpotlightFixesAction(sender.isOn)", toggle)
        self.assertGreaterEqual(toggle.count("queueStandaloneAction:"), 2)
        self.assertIn("removeStandaloneActionForConflictKey", toggle)
        self.assertNotIn("CNDIconServicesConsumerLifecycleStop", toggle)

    def test_font_settings_buttons_queue_package_intents(self) -> None:
        helper = self.settings_method(
            "- (BOOL)queueFontChangerIntent:",
            "- (void)presentSBCDockAppPicker",
        )
        self.assertIn("queueIntent:intent forPackage:package", helper)
        font_selection = self.settings[self.settings.index(
            "if (indexPath.section == SectionFontChanger)"
        ):self.settings.index(
            "if (indexPath.section == SectionLiveWP)"
        )]
        self.assertIn("queueFontChangerIntent:PackageQueueIntentInstall", font_selection)
        self.assertIn("queueFontChangerIntent:PackageQueueIntentUninstall", font_selection)
        self.assertNotIn("settings_apply_font_changer_now", font_selection)

    def test_control_center_settings_buttons_queue_package_intents(self) -> None:
        rows = self.settings_method(
            "- (NSArray<NSDictionary *> *)ccThemingRows",
            "- (NSArray<NSDictionary *> *)liveWPRows",
        ).split("#if 0", 1)[0]
        self.assertIn('action": @"cc-theming-queue-apply"', rows)
        self.assertIn('action": @"cc-theming-queue-restore"', rows)
        self.assertEqual(rows.count('@"kind": @"button"'), 2)
        selection = self.settings[self.settings.index(
            "if (indexPath.section == SectionCCTheming)"
        ):].split("#if 0", 1)[0]
        self.assertIn("PackageQueueIntentInstall", selection)
        self.assertIn("PackageQueueIntentUninstall", selection)
        self.assertIn("queueIntent:intent forPackage:package", selection)
        self.assertNotIn("settings_run_cc_theming_", selection)

    def test_review_lists_and_can_remove_standalone_actions(self) -> None:
        self.assertIn("QueueReviewSectionStandalone", self.review)
        self.assertIn("queuedStandaloneActions", self.review)
        self.assertIn("removeStandaloneActionForConflictKey", self.review)
        self.assertIn("SpringBoard Fixes", self.review)
        self.assertIn("Spotlight Fixes", self.review)

    def test_respring_plans_route_into_the_durable_coordinator(self) -> None:
        commit = self.queue_method("- (void)commit", "- (void)settingsActionsDidComplete:")
        gate = commit.index("[self transactionNeedsCoordinator]")
        mutation = commit.index("prepareTransactionForInstalls")
        self.assertLess(gate, mutation)
        self.assertIn("[self beginOrResumeCoordinator]", commit)
        self.assertNotIn("execution coordinator is not active", commit)
        self.assertNotIn("Shared Respring Plan Saved", self.review)

    def test_rendering_progress_is_displayed_one_based(self) -> None:
        start = self.snowboard.index(
            "static void settings_sbl_log_remix_progress("
        )
        end = self.snowboard.index(
            "bool settings_apply_snowboardlite_from_defaults_locked", start
        )
        logger = self.snowboard[start:end]
        self.assertIn('@"rendering"', logger)
        self.assertIn("displayed++", logger)
        self.assertIn("completed < total", logger)


if __name__ == "__main__":
    unittest.main()
