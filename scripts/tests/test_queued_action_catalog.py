"""Structural checks for durable queue action classification and ordering."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class QueuedActionCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = (ROOT / "Cyanide/installer/CNDQueuedActionCatalog.h").read_text()
        cls.source = (ROOT / "Cyanide/installer/CNDQueuedActionCatalog.m").read_text()
        cls.queue = (ROOT / "Cyanide/installer/PackageQueue.m").read_text()

    def function_body(self, marker: str, next_marker: str) -> str:
        start = self.source.index(marker)
        end = self.source.index(next_marker, start)
        return self.source[start:end]

    def test_action_kinds_and_operations_are_stable_constants(self) -> None:
        expected = {
            "CNDQueuedActionKindPackage": "package",
            "CNDQueuedActionKindSnowBoardRemix": "snowboard-remix",
            "CNDQueuedActionKindTransparencyFix": "transparency-fix",
            "CNDQueuedActionKindSpringBoardFixes": "springboard-fixes",
            "CNDQueuedActionKindSpotlightFixes": "spotlight-fixes",
            "CNDQueuedActionKindSpringBoardSpotlightFixes":
                "springboard-spotlight-fixes",
            "CNDQueuedActionOperationInstall": "install",
            "CNDQueuedActionOperationUninstall": "uninstall",
            "CNDQueuedActionOperationApplyTheme": "apply-theme",
            "CNDQueuedActionOperationRestoreTheme": "restore-theme",
            "CNDQueuedActionOperationApplyTransparencyFix":
                "apply-transparency-fix",
            "CNDQueuedActionOperationRestoreTransparencyFix":
                "restore-transparency-fix",
            "CNDQueuedActionOperationApplyFixes": "apply-fixes",
        }
        for symbol, value in expected.items():
            with self.subTest(symbol=symbol):
                self.assertIn(f"NSString * const {symbol}", self.source)
                self.assertIn(f'@"{value}"', self.source)

    def test_system_file_packages_are_pre_respring(self) -> None:
        classifier = self.function_body(
            "static CNDQueuedActionPhase CNDQueuedPackagePhaseForKind",
            "CNDQueuedAction *CNDQueuedActionForPackage",
        )
        before = classifier.index("CNDQueuedActionPhaseBeforeRespring")
        self.assertLess(classifier.index("PackageInstallKindHideHomeBar"), before)
        self.assertLess(classifier.index("PackageInstallKindFontChanger"), before)
        self.assertLess(classifier.index("PackageInstallKindControlCenterTheming"), before)
        self.assertIn("PackageInstallKindToggle", classifier[before:])
        self.assertIn("CNDQueuedActionPhaseAutomatic", classifier[before:])

    def test_control_center_apply_restore_is_supported_and_automatically_resprings(self) -> None:
        self.assertIn("PackageInstallKindControlCenterTheming", self.source)
        supported = self.function_body(
            "static BOOL CNDQueuedPackageKindIsSupported",
            "CNDQueuedAction *CNDQueuedActionForPackage",
        )
        self.assertIn("case PackageInstallKindControlCenterTheming:", supported)
        self.assertIn("return YES;", supported)
        progress = (ROOT / "Cyanide/installer/InstallProgressViewController.m").read_text()
        self.assertIn("PackageQueueReadyForRespringNotification", progress)
        self.assertIn("runRespringCountdownValue:3", progress)
        self.assertIn("settings_begin_system_edit_respring_with_completion", progress)

    def test_snowboard_apply_and_restore_are_pre_respring(self) -> None:
        factory = self.function_body(
            "CNDQueuedAction *CNDQueuedSnowBoardRemixAction",
            "CNDQueuedAction *CNDQueuedSpringBoardFixesAction",
        )
        self.assertIn("CNDQueuedActionOperationApplyTheme", factory)
        self.assertIn("CNDQueuedActionOperationRestoreTheme", factory)
        self.assertIn("CNDQueuedActionPhaseBeforeRespring", factory)
        self.assertIn("CNDQueuedActionParameterThemeIdentifier", factory)
        conflicts = self.function_body(
            "NSString *CNDQueuedActionConflictKey",
            "CNDQueuedActionPhase CNDQueuedActionResolvedPhase",
        )
        self.assertIn("return CNDQueuedActionConflictKeySnowBoardRemix",
                      conflicts)

    def test_explicit_post_respring_action_also_establishes_boundary(self) -> None:
        detector = self.function_body(
            "BOOL CNDQueuedActionsRequireRespring",
            "static NSInteger CNDQueuedActionExecutionPriority",
        )
        self.assertIn("action.phase != CNDQueuedActionPhaseAutomatic", detector)

    def test_transparency_fix_is_mutually_exclusive_and_adaptive(self) -> None:
        factory = self.function_body(
            "CNDQueuedAction *CNDQueuedTransparencyFixAction",
            "CNDQueuedAction *CNDQueuedSpringBoardFixesAction",
        )
        self.assertIn("CNDQueuedActionOperationApplyTransparencyFix", factory)
        self.assertIn("CNDQueuedActionOperationRestoreTransparencyFix", factory)
        self.assertIn("CNDQueuedActionPhaseAutomatic", factory)
        self.assertIn("CNDQueuedActionConflictKeyTransparencyFix", self.source)
        validator = self.function_body(
            "BOOL CNDQueuedActionHasSupportedShape",
            "NSString *CNDQueuedActionConflictKey",
        )
        self.assertIn("CNDQueuedActionKindTransparencyFix", validator)
        self.assertIn("action.parameters.count == 0", validator)
        self.assertIn("executeTransparencyFixAction", self.queue)
        self.assertIn("setTransparencyFixEnabled:apply", self.queue)

    def test_target_fixes_are_independent_adaptive_actions(self) -> None:
        factories = self.function_body(
            "CNDQueuedAction *CNDQueuedSpringBoardFixesAction",
            "static BOOL CNDQueuedCatalogReject",
        )
        self.assertIn("CNDQueuedActionKindSpringBoardFixes", factories)
        self.assertIn("CNDQueuedActionKindSpotlightFixes", factories)
        self.assertGreaterEqual(factories.count("CNDQueuedActionPhaseAutomatic"), 2)
        self.assertNotIn("CNDQueuedActionPhaseAfterRespring", factories)
        self.assertIn("CNDQueuedActionParameterTransparencyEnabled", factories)
        self.assertIn("CNDQueuedActionParameterSpotlightAssertionRequired: @YES",
                      factories)
        validator = self.function_body(
            "BOOL CNDQueuedActionHasSupportedShape",
            "NSString *CNDQueuedActionConflictKey",
        )
        self.assertIn("CNDQueuedActionKindSpringBoardFixes", validator)
        self.assertIn("CNDQueuedActionKindSpotlightFixes", validator)
        self.assertIn("[assertion boolValue]", validator)
        self.assertIn("action.phase == CNDQueuedActionPhaseAutomatic", validator)

    def test_adaptive_actions_move_after_a_shared_respring(self) -> None:
        resolver = self.function_body(
            "CNDQueuedActionPhase CNDQueuedActionResolvedPhase",
            "BOOL CNDQueuedActionsRequireRespring",
        )
        self.assertIn("action.phase != CNDQueuedActionPhaseAutomatic", resolver)
        self.assertIn("transactionRequiresRespring", resolver)
        self.assertIn("CNDQueuedActionPhaseAfterRespring", resolver)
        self.assertIn("CNDQueuedActionPhaseBeforeRespring", resolver)

    def test_execution_plan_is_deterministic_and_orders_snowboard_first(self) -> None:
        planner = self.source[self.source.index(
            "static NSInteger CNDQueuedActionExecutionPriority"
        ):]
        snowboard = planner.index("CNDQueuedActionKindSnowBoardRemix")
        snowboard_priority = planner.index("return 100", snowboard)
        package = planner.index("CNDQueuedActionKindPackage", snowboard_priority)
        package_priority = planner.index("return 200", package)
        transparency = planner.index("CNDQueuedActionKindTransparencyFix",
                                     package_priority)
        transparency_priority = planner.index("return 250", transparency)
        fixes = planner.index("CNDQueuedActionKindSpringBoardFixes",
                              transparency_priority)
        fixes_priority = planner.index("return 300", fixes)
        spotlight = planner.index("CNDQueuedActionKindSpotlightFixes",
                                  fixes_priority)
        spotlight_priority = planner.index("return 400", spotlight)
        self.assertLess(snowboard_priority, package_priority)
        self.assertLess(package_priority, transparency_priority)
        self.assertLess(transparency_priority, fixes_priority)
        self.assertLess(fixes_priority, spotlight_priority)
        self.assertIn("left.createdAt compare:right.createdAt", planner)
        self.assertIn("left.recordIdentifier compare:right.recordIdentifier",
                      planner)
        self.assertIn("CNDQueuedActionStateSucceeded", planner)

    def test_queue_hydration_validates_shapes_and_preserves_standalone_actions(self) -> None:
        self.assertIn("CNDQueuedActionHasSupportedShape(normalized", self.queue)
        self.assertIn("CNDQueuedActionForPackage(package, installed)", self.queue)
        actions_start = self.queue.index(
            "- (NSArray<CNDQueuedAction *> *)actionsForInstalls:"
        )
        actions_end = self.queue.index("- (BOOL)saveCollectingTransaction",
                                       actions_start)
        actions = self.queue[actions_start:actions_end]
        self.assertIn("BOOL standalone", actions)
        self.assertIn("CNDQueuedActionKindPackage", actions)

    def test_phase_two_does_not_start_the_respring_coordinator(self) -> None:
        self.assertNotIn("settings_begin_system_edit_respring", self.source)
        self.assertNotIn("settings_begin_system_edit_respring", self.queue)
        self.assertNotIn('action": @"sbl-queue', self.source)


if __name__ == "__main__":
    unittest.main()
