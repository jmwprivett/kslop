"""Structural checks for base SnowBoard Icon Fixes integration."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class SnowBoardIconFixesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = (
            ROOT / "Cyanide/installer/CNDSnowBoardRemix.h"
        ).read_text()
        cls.source = (
            ROOT / "Cyanide/installer/CNDSnowBoardRemix.m"
        ).read_text()
        cls.queue = (
            ROOT / "Cyanide/installer/PackageQueue.m"
        ).read_text()
        cls.settings = (
            ROOT / "Cyanide/SettingsViewController.m"
        ).read_text()

    @staticmethod
    def body(source: str, start_marker: str, end_marker: str) -> str:
        start = source.index(start_marker)
        end = source.index(end_marker, start)
        return source[start:end]

    def test_public_coordinator_runs_all_five_static_fixes(self) -> None:
        self.assertIn("+ (NSDictionary<NSString *, id> *)applyIconFixes;",
                      self.header)
        self.assertIn("+ (NSDictionary<NSString *, id> *)restoreIconFixes;",
                      self.header)
        body = self.body(
            self.source,
            "static NSDictionary<NSString *, id> *CNDRemixRunIconFixesApply",
            "static NSDictionary<NSString *, id> *CNDRemixRunIconFixesRestore",
        )
        transparency = body.index("CNDHailMaryImpRedirectOperationApply")
        permission = body.index(
            "CNDRemixRunSpecialIconPresentationPermission", transparency
        )
        clock_apply = body.index(
            "CNDSpecialIconPresentationRouteClock", permission
        )
        calendar_apply = body.index(
            "CNDSpecialIconPresentationRouteCalendar", clock_apply
        )
        switcher_permission = body.index(
            "CNDRemixRunSwitcherPresentationPermission", calendar_apply
        )
        switcher_apply = body.index(
            "CNDSpecialIconPresentationRouteSwitcher", switcher_permission
        )
        app_library_permission = body.index(
            "CNDRemixRunAppLibraryMiniaturePresentationPermission",
            switcher_apply,
        )
        app_library_apply = body.index(
            "CNDSpecialIconPresentationRouteAppLibraryMiniatures",
            app_library_permission,
        )
        self.assertLess(transparency, permission)
        self.assertLess(permission, clock_apply)
        self.assertLess(clock_apply, calendar_apply)
        self.assertLess(calendar_apply, switcher_permission)
        self.assertLess(switcher_permission, switcher_apply)
        self.assertLess(switcher_apply, app_library_permission)
        self.assertLess(app_library_permission, app_library_apply)
        self.assertIn(
            '@"switcher", @"app-library-miniatures"',
            body,
        )
        self.assertIn('components[@"switcherPermission"]', body)
        self.assertIn('components[@"switcher"]', body)
        self.assertIn(
            'components[@"appLibraryMiniaturesPermission"]', body
        )
        self.assertIn('components[@"appLibraryMiniatures"]', body)
        permission_helper = self.body(
            self.source,
            "CNDRemixRunSwitcherPresentationPermission(void)",
            "static NSDictionary<NSString *, id> *CNDRemixIconFixesFailure",
        )
        self.assertIn(
            "CNDSwitcherPresentationDispatchPermissionRun(",
            permission_helper,
        )
        self.assertIn(
            "CNDAppLibraryMiniaturePresentationDispatchPermissionRun(",
            permission_helper,
        )

    def test_coordinator_reuses_shared_lifecycle_and_has_no_consumer_contact(self) -> None:
        body = self.body(
            self.source,
            "static NSDictionary<NSString *, id> *CNDRemixRunIconFixesApply",
            "@implementation CNDSnowBoardRemix",
        )
        self.assertIn("kexploit_krw_ready()", body)
        self.assertIn('@"shared-tweak-lifecycle"', body)
        self.assertNotIn("settings_ensure_", body)
        self.assertNotIn("kexploit_opa334", body)
        self.assertIn('@"consumerInjectionCount": @0', body)
        self.assertIn('@"consumerRemoteCallCount": @0', body)
        self.assertIn('@"iconObjectMutationCount": @0', body)
        self.assertIn('@"homeVisibilityPrecondition": @NO', body)

    def test_partial_success_is_preserved_for_explicit_restore(self) -> None:
        helper = self.body(
            self.source,
            "static NSDictionary<NSString *, id> *CNDRemixIconFixesFailure",
            "static NSDictionary<NSString *, id> *CNDRemixRunIconFixesApply",
        )
        body = self.body(
            self.source,
            "static NSDictionary<NSString *, id> *CNDRemixRunIconFixesApply",
            "static NSDictionary<NSString *, id> *CNDRemixRunIconFixesRestore",
        )
        self.assertIn('@"coordinatorRollbackAttempted": @NO', helper)
        self.assertIn(
            '@"successfulComponentsRemainAsCompleted": @YES', helper
        )
        self.assertIn(
            '@"restorePolicy": @"blanket-or-traditional-restore-only"',
            helper + body,
        )
        self.assertIn("BOOL restoring", helper)
        self.assertEqual(body.count("components, NO);"), 8)
        self.assertNotIn("components, YES);", body)
        self.assertNotIn("CNDHailMaryImpRedirectOperationRestore", body)
        self.assertNotIn("CNDSpecialIconPresentationOperationRestore", body)

    def test_blanket_restore_runs_reverse_static_fix_order(self) -> None:
        body = self.body(
            self.source,
            "static NSDictionary<NSString *, id> *CNDRemixRunIconFixesRestore",
            "@implementation CNDSnowBoardRemix",
        )
        app_library_permission = body.index(
            "CNDRemixRunAppLibraryMiniaturePresentationPermission"
        )
        app_library = body.index(
            "CNDSpecialIconPresentationRouteAppLibraryMiniatures",
            app_library_permission,
        )
        switcher_permission = body.index(
            "CNDRemixRunSwitcherPresentationPermission", app_library
        )
        switcher = body.index(
            "CNDSpecialIconPresentationRouteSwitcher", switcher_permission
        )
        calendar_block = body.index("if (!calendarReady) {", switcher)
        calendar = body.index(
            "CNDSpecialIconPresentationRouteCalendar", calendar_block
        )
        clock = body.index(
            "CNDSpecialIconPresentationRouteClock", calendar
        )
        transparency = body.index(
            "CNDHailMaryImpRedirectOperationRestore", clock
        )
        self.assertLess(app_library_permission, app_library)
        self.assertLess(app_library, switcher_permission)
        self.assertLess(switcher_permission, switcher)
        self.assertLess(switcher, calendar)
        self.assertLess(calendar, clock)
        self.assertLess(clock, transparency)
        self.assertIn('components[@"switcherPermission"]', body)
        self.assertIn('components[@"switcher"]', body)
        self.assertIn(
            'components[@"appLibraryMiniaturesPermission"]', body
        )
        self.assertIn('components[@"appLibraryMiniatures"]', body)
        self.assertIn(
            '@"app-library-miniatures", @"switcher", @"calendar"',
            body,
        )
        self.assertIn('@"coordinatorRollbackAttempted": @NO', body)
        self.assertEqual(body.count("components, YES);"), 8)
        self.assertNotIn("components, NO);", body)

    def test_enabled_toggle_runs_icon_fixes_after_persistent_apply(self) -> None:
        method = self.body(
            self.queue,
            "- (BOOL)executeSnowBoardAction:",
            "- (BOOL)executeTransparencyFixAction:",
        )
        persistent_apply = method.index("settings_apply_snowboard_remix()")
        enabled = method.index(
            "kSettingsSnowBoardRemixInstallConsumerMappings", persistent_apply
        )
        icon_fixes = method.index("[CNDSnowBoardRemix applyIconFixes]", enabled)
        self.assertLess(persistent_apply, enabled)
        self.assertLess(enabled, icon_fixes)
        self.assertIn("if (ok && applyingTheme", method)
        persistent_restore = method.index(
            "settings_restore_all_snowboard_remix()"
        )
        blanket_restore = method.index(
            "[CNDSnowBoardRemix restoreIconFixes]", persistent_restore
        )
        self.assertLess(persistent_restore, blanket_restore)
        self.assertIn("if (ok && restoringTheme)", method)

    def test_manual_icon_fix_runs_in_place_without_theme_or_queue(self) -> None:
        rows = self.body(
            self.settings,
            "- (NSArray<NSDictionary *> *)snowboardLiteRows",
            "- (NSArray<NSDictionary *> *)fontChangerRows",
        )
        self.assertIn('@"title": @"Manual Icon Fix"', rows)
        self.assertIn('action": @"sbl-manual-icon-fix"', rows)
        self.assertNotIn('action": @"sbl-queue-transparency-fix"', rows)
        self.assertNotIn('action": @"sbl-queue-springboard-fixes"', rows)

        selection = self.body(
            self.settings,
            "if (indexPath.section == SectionSnowBoardLite)",
            "if (indexPath.section == SectionFontChanger)",
        )
        manual = self.body(
            selection,
            'else if ([action isEqualToString:@"sbl-manual-icon-fix"])',
            'else if ([action isEqualToString:@"sbl-update-repair"])',
        )
        self.assertIn("settings_run_snowboard_remix_operation(", manual)
        self.assertIn('@"Manual Icon Fix", YES', manual)
        self.assertIn("[CNDSnowBoardRemix applyIconFixes]", manual)
        self.assertNotIn("queueStandaloneActionFromSettings", manual)
        self.assertNotIn("settings_apply_snowboard_remix", manual)

    def test_settings_renames_toggle_and_keeps_curated_probe_list(self) -> None:
        self.assertIn('@"title": @"Icon Fixes"', self.settings)
        self.assertNotIn('@"title": @"Transparent Icon Presentation"',
                         self.settings)
        self.assertIn(
            "Hail Mary transparency, Clock, Calendar, Switcher, and App "
            "Library miniature shared-cache fixes",
            self.settings,
        )
        self.assertIn(
            "blanket-restore App Library miniatures, Switcher, Calendar, "
            "Clock, and Hail Mary transparency",
            self.settings,
        )
        self.assertIn("case RootSectionProbes:         return 12;", self.settings)
        for row in (17, 18, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37):
            self.assertRegex(self.settings, rf"\b{row}\b")
        self.assertIn("settings_root_probe_underlying_row", self.settings)


if __name__ == "__main__":
    unittest.main()
