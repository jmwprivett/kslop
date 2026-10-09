"""Structural checks for the durable installer transaction queue."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class PackageQueuePersistenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.model_h = (ROOT / "Cyanide/installer/CNDQueuedTransaction.h").read_text()
        cls.model_m = (ROOT / "Cyanide/installer/CNDQueuedTransaction.m").read_text()
        cls.queue_h = (ROOT / "Cyanide/installer/PackageQueue.h").read_text()
        cls.queue_m = (ROOT / "Cyanide/installer/PackageQueue.m").read_text()
        cls.package_h = (ROOT / "Cyanide/installer/Package.h").read_text()
        cls.package_m = (ROOT / "Cyanide/installer/Package.m").read_text()
        cls.review = (ROOT / "Cyanide/installer/QueueReviewViewController.m").read_text()

    def method_body(self, start_marker: str, end_marker: str) -> str:
        start = self.queue_m.index(start_marker)
        end = self.queue_m.index(end_marker, start)
        return self.queue_m[start:end]

    def test_schema_records_action_and_respring_recovery_fields(self) -> None:
        self.assertIn("CNDQueuedTransactionSchemaVersion = 1", self.model_m)
        for field in (
            "recordIdentifier",
            "kind",
            "subjectIdentifier",
            "operation",
            "phase",
            "state",
            "createdAt",
            "updatedAt",
            "lastError",
            "preRespringSpringBoardPID",
            "bootEpoch",
            "krwGenerationIdentifier",
        ):
            with self.subTest(field=field):
                self.assertIn(field, self.model_h)
                self.assertIn(f'@"{field}"', self.model_m)

    def test_queue_is_an_atomic_application_support_property_list(self) -> None:
        self.assertIn("NSApplicationSupportDirectory", self.queue_m)
        self.assertIn('kQueuedTransactionFilename = @"QueuedChanges.v1.plist"',
                      self.queue_m)
        self.assertIn("NSPropertyListBinaryFormat_v1_0", self.queue_m)
        self.assertIn("NSDataWritingAtomic", self.queue_m)
        self.assertIn("withIntermediateDirectories:YES", self.queue_m)

    def test_invalid_or_unknown_schema_is_left_untouched(self) -> None:
        decoder = self.model_m[self.model_m.index(
            "+ (instancetype)transactionFromPropertyList"
        ):]
        self.assertIn("schemaVersion != CNDQueuedTransactionSchemaVersion", decoder)
        hydrate = self.method_body(
            "- (void)hydrateDurableTransaction",
            "- (CNDQueuedTransaction *)durableTransaction",
        )
        invalid = hydrate.index("if (!loaded)")
        tail = hydrate[invalid:hydrate.index("\n    }", invalid) + 6]
        self.assertIn("self.durableStoreUnavailable = YES", tail)
        self.assertNotIn("removeItemAtURL", tail)

    def test_relaunch_hydrates_against_complete_catalog(self) -> None:
        hydrate = self.method_body(
            "- (void)hydrateDurableTransaction",
            "- (CNDQueuedTransaction *)durableTransaction",
        )
        self.assertIn("[PackageCatalog allPackagesIncludingExperimental]", hydrate)
        self.assertIn("CNDQueuedActionStateRunning", hydrate)
        self.assertIn("CNDQueuedActionStatePending", hydrate)
        self.assertIn("Recovered after an interrupted queue run", hydrate)
        self.assertIn("CNDQueuedTransactionStateFailed", hydrate)
        self.assertIn("allActionsSucceeded", hydrate)
        self.assertIn("CNDQueuedTransactionStateCompleted", hydrate)

    def test_hydration_migrates_adaptive_fixes_and_empty_boundaries(self) -> None:
        hydrate = self.method_body(
            "- (void)hydrateDurableTransaction",
            "- (CNDQueuedTransaction *)durableTransaction",
        )
        self.assertIn("migratedAdaptiveAction", hydrate)
        self.assertIn("CNDQueuedActionKindSpringBoardSpotlightFixes", hydrate)
        self.assertIn("CNDQueuedSpringBoardFixesAction", hydrate)
        self.assertIn("CNDQueuedSpotlightFixesAction", hydrate)
        self.assertIn("CNDQueuedActionPhaseAfterRespring", hydrate)
        self.assertIn("CNDQueuedActionPhaseAutomatic", hydrate)
        self.assertIn("staleBoundaryOnlyContinuation", hydrate)
        self.assertIn(
            "prepareBoundaryOnlyTransientAppliedStateForTransaction", hydrate
        )
        boundary = hydrate.index("staleBoundaryOnlyContinuation")
        completed = hydrate.index(
            "CNDQueuedTransactionStateCompleted", boundary
        )
        persisted = hydrate.index("persistDurableTransaction", completed)
        removed = hydrate.index("self.transaction = nil", persisted)
        self.assertLess(completed, persisted)
        self.assertLess(persisted, removed)

    def test_coordinated_success_is_not_discarded_before_state_finalization(self) -> None:
        hydrate = self.method_body(
            "- (void)hydrateDurableTransaction",
            "- (CNDQueuedTransaction *)durableTransaction",
        )
        pending = hydrate.index("coordinatorCompletionPending")
        explicit_phase = hydrate.index(
            "action.phase != CNDQueuedActionPhaseAutomatic", pending
        )
        ordinary_only = hydrate.index(
            "allActionsSucceeded && !coordinatorCompletionPending",
            explicit_phase,
        )
        completed = hydrate.index(
            "CNDQueuedTransactionStateCompleted", ordinary_only
        )
        self.assertLess(pending, explicit_phase)
        self.assertLess(explicit_phase, ordinary_only)
        self.assertLess(ordinary_only, completed)
        self.assertIn("loaded.preRespringSpringBoardPID > 1", hydrate)
        self.assertIn("completeCoordinator", hydrate)

    def test_unrecognized_recovery_actions_fail_closed(self) -> None:
        hydrate = self.method_body(
            "- (void)hydrateDurableTransaction",
            "- (CNDQueuedTransaction *)durableTransaction",
        )
        self.assertIn("unresolvedAction = YES", hydrate)
        self.assertIn("self.durableStoreUnavailable = YES", hydrate)
        unavailable = hydrate.index("if (unresolvedAction)")
        self.assertIn("return;", hydrate[unavailable:unavailable + 260])

    def test_successful_checkpoints_are_preserved_and_not_reexecuted(self) -> None:
        actions = self.method_body(
            "- (NSArray<CNDQueuedAction *> *)actionsForInstalls:",
            "- (BOOL)saveCollectingTransaction",
        )
        self.assertIn("action.state != CNDQueuedActionStateSucceeded", actions)
        commit = self.method_body("- (void)commit", "- (void)settingsActionsDidComplete:")
        self.assertGreaterEqual(
            commit.count("actionAlreadySucceededForPackage"), 3
        )
        self.assertIn("CNDQueuedActionStateSucceeded", commit)

    def test_every_heavy_action_is_checkpointed_around_the_mutation(self) -> None:
        commit = self.method_body("- (void)commit", "- (void)settingsActionsDidComplete:")
        running = commit.index("state:CNDQueuedActionStateRunning",
                               commit.index("for (NSDictionary"))
        mutation = commit.index("applyCommittedState:installed", running)
        succeeded = commit.index("CNDQueuedActionStateSucceeded", mutation)
        self.assertLess(running, mutation)
        self.assertLess(mutation, succeeded)

    def test_commit_does_not_clear_intent_before_work_completes(self) -> None:
        commit = self.method_body("- (void)commit", "- (void)settingsActionsDidComplete:")
        self.assertNotIn("[self.installs removeAllObjects]", commit)
        self.assertNotIn("[self.uninstalls removeAllObjects]", commit)
        finish = self.method_body(
            "- (void)finishSuccessfullyPostingCompletion:",
            "- (void)postCompletionWithSuccess:",
        )
        completed = finish.index("CNDQueuedTransactionStateCompleted")
        saved = finish.index("persistDurableTransaction", completed)
        cleared = finish.index("removeAllObjects", saved)
        self.assertLess(completed, saved)
        self.assertLess(saved, cleared)

    def test_runtime_actions_wait_for_the_actual_completion_notification(self) -> None:
        commit = self.method_body("- (void)commit", "- (void)settingsActionsDidComplete:")
        self.assertIn("beginPendingSettingsRunForCoordinator:NO", commit)
        self.assertIn("settingsCompletionToken", commit)
        self.assertIn("settings_run_pending_actions_for_queue_token", commit)
        completion = self.method_body(
            "- (void)settingsActionsDidComplete:",
            "- (void)finishWithFailure:",
        )
        self.assertIn("kSettingsQueuedRunCompletionTokenKey", completion)
        self.assertIn("isEqualToString:expectedToken", completion)
        self.assertIn("kSettingsActionsDidCompleteSuccessKey", completion)
        self.assertIn("finishSuccessfullyPostingCompletion:YES", completion)
        self.assertIn("finishWithFailure:", completion)

    def test_queue_terminal_notification_is_not_the_generic_settings_signal(self) -> None:
        finish = self.method_body(
            "- (void)postCompletionWithSuccess:",
            "- (void)notifyChange",
        )
        self.assertIn("PackageQueueExecutionDidCompleteNotification", finish)
        self.assertNotIn("kSettingsActionsDidCompleteNotification", finish)

    def test_stopped_or_failed_queue_can_be_cleared_without_undoing_work(self) -> None:
        self.assertIn("@property (nonatomic, readonly) BOOL canClear", self.queue_h)
        can_clear = self.method_body("- (BOOL)canClear", "- (PackageQueueIntent)intentForPackage:")
        self.assertIn("self.commitInFlight", can_clear)
        self.assertIn("self.durableStoreUnavailable", can_clear)
        self.assertNotIn("transactionExecutionHasStarted", can_clear)

        clear = self.method_body("- (void)clear", "#pragma mark - Commit and checkpoints")
        self.assertIn("executionStarted", clear)
        self.assertIn("executionStarted\n        ? @[] : self.queuedInstalls", clear)
        revert = clear.index("applyCommittedState:NO")
        remove_transaction = clear.index("self.transaction = nil", revert)
        self.assertLess(revert, remove_transaction)
        self.assertIn("revertedPreferencePackages", clear)
        self.assertIn("applyCommittedState:YES", clear)
        self.assertIn("the complete queue was retained", clear)
        removed = clear.index("persistDurableTransaction")
        cancel = clear.index("CNDTransientAppliedStateCancelPreparedTransition")
        self.assertLess(removed, cancel)

    def test_review_exposes_clear_for_stopped_transactions_with_warning(self) -> None:
        self.assertIn("[PackageQueue sharedQueue].canClear", self.review)
        self.assertIn("Changes that already completed will not be undone", self.review)

    def test_package_mutations_report_real_success(self) -> None:
        self.assertIn("- (BOOL)applyCommittedState:(BOOL)installed", self.package_h)
        self.assertIn("- (BOOL)applyCommittedState:(BOOL)installed", self.package_m)
        for operation in (
            "settings_apply_ota_disabled",
            "settings_apply_nano_registry_now",
            "settings_apply_call_recording_sound_disabled",
            "settings_apply_hide_home_bar_hidden",
            "settings_apply_font_changer_now",
        ):
            with self.subTest(operation=operation):
                self.assertIn(f"BOOL success = {operation}", self.package_m)

    def test_phase_one_keeps_public_queue_compatibility(self) -> None:
        for api in (
            "queuedInstalls",
            "queuedUninstalls",
            "pendingCount",
            "toggleForPackage",
            "queueIntent",
            "removePackage",
            "clear",
            "commit",
        ):
            with self.subTest(api=api):
                self.assertIn(api, self.queue_h)
        self.assertIn("PackageQueueDidChangeNotification", self.queue_m)


if __name__ == "__main__":
    unittest.main()
