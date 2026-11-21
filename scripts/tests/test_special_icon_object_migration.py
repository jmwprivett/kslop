#!/usr/bin/env python3
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
THEMER = (ROOT / "Cyanide" / "tweaks" / "themer.m").read_text()
THEMER_HEADER = (ROOT / "Cyanide" / "tweaks" / "themer.h").read_text()
CONSUMER = (
    ROOT / "Cyanide" / "installer" / "CNDIconServicesConsumerHook.m"
).read_text()
CONSUMER_HEADER = (
    ROOT / "Cyanide" / "installer" / "CNDIconServicesConsumerHook.h"
).read_text()
SETTINGS = (ROOT / "Cyanide" / "SettingsViewController.m").read_text()
SETTINGS_HEADER = (
    ROOT / "Cyanide" / "SettingsViewController.h"
).read_text()
APP_DELEGATE = (ROOT / "Cyanide" / "AppDelegate.m").read_text()


class SpecialIconObjectMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body = THEMER.split(
            "themer_rebuild_special_icon_class_objects_in_session", 1
        )[1].split(
            "themer_inspect_springboard_app_library_miniature_pipeline_in_session",
            1,
        )[0]
        cls.wrapper = CONSUMER.split(
            "CNDIconServicesConsumerHookRebuildSpecialIconClassesForPID", 1
        )[1]

    def test_public_api_is_wired_through_both_layers(self):
        self.assertIn(
            "themer_rebuild_special_icon_class_objects_in_session",
            THEMER_HEADER,
        )
        self.assertIn(
            "CNDIconServicesConsumerHookRebuildSpecialIconClassesForPID",
            CONSUMER_HEADER,
        )
        self.assertIn("useStaticClasses", THEMER_HEADER)
        self.assertIn("dryRun", THEMER_HEADER)
        self.assertIn("spotlight", THEMER_HEADER)

    def test_scope_is_exactly_clock_and_calendar(self):
        self.assertIn('"com.apple.mobiletimer"', self.body)
        self.assertIn('"com.apple.mobilecal"', self.body)
        self.assertIn('"SBHApplicationIcon"', self.body)
        self.assertIn('"SBHClockApplicationIcon"', self.body)
        self.assertIn('"SBHCalendarApplicationIcon"', self.body)
        self.assertIn("ThemerSpecialIconObjectMigrationTarget targets[2]", self.body)

    def test_all_private_mutation_abis_are_exactly_gated(self):
        for selector, encoding in (
            ("applicationIconForBundleIdentifier:", "@24@0:8@16"),
            ("iconClassForApplicationWithBundleIdentifier:", "#24@0:8@16"),
            ("sharedInstance", "@16@0:8"),
            (
                "removeApplicationWithBundleIdentifier:pruneEmptyIcons:",
                "@28@0:8@16B24",
            ),
            ("addApplication:", "@24@0:8@16"),
            ("applicationWithBundleIdentifier:", "@24@0:8@16"),
            ("bundleIdentifier", "@16@0:8"),
            ("setDesiredIconRelativePath:forIconWithIdentifier:", "v32@0:8@16@24"),
            ("relativePathForIcon:listGridCellInfoOptions:", "@32@0:8@16Q24"),
            ("leafIdentifier", "@16@0:8"),
            ("isEqual:", "B24@0:8@16"),
            ("desiredIndexPathForIconWithIdentifier:", "@24@0:8@16"),
        ):
            self.assertIn(f'"{selector}"', self.body)
            self.assertIn(f'"{encoding}"', self.body)

    def test_preflight_finishes_before_first_remove(self):
        preflight_comment = self.body.index(
            "Finish every lookup before the first remove"
        )
        mutation_gate = self.body.index("if (!failure && !dryRun)")
        remove_call = self.body.index(
            '"removeApplicationWithBundleIdentifier:pruneEmptyIcons:"',
            mutation_gate,
        )
        self.assertLess(preflight_comment, mutation_gate)
        self.assertLess(mutation_gate, remove_call)
        self.assertIn('if (!failure && !dryRun)', self.body)
        self.assertIn('@"mutationsIssued": @(mutationsIssued)', self.body)

    def test_absent_spotlight_canonical_is_selection_verified_noop(self):
        self.assertIn(
            "target->canonicalAbsent = spotlight && !iconMaterialized",
            self.body,
        )
        self.assertIn(
            "target->canonicalAbsent ||\n            (bundleMatches && currentClassKnown)",
            self.body,
        )
        self.assertIn(
            "if (target->alreadyDesired || target->canonicalAbsent) continue;",
            self.body,
        )
        self.assertIn(
            "if (target->canonicalAbsent) {\n"
            "            absentCanonicalCount++;\n"
            "            continue;",
            self.body,
        )
        absent_skip = self.body.index("if (target->canonicalAbsent) {")
        application_lookup = self.body.index(
            'applicationDataSource, "applicationWithBundleIdentifier:"'
        )
        self.assertLess(absent_skip, application_lookup)
        self.assertIn('if (!canonicalMatches || !selectionMatches)', self.body)
        self.assertIn('if (!applicationABIReady || !applicationMatches)', self.body)
        self.assertIn('@"absentCanonicalCount": @(absentCanonicalCount)', self.body)

    def test_springboard_path_is_preserved_and_verified(self):
        desired = self.body.index(
            '"setDesiredIconRelativePath:forIconWithIdentifier:"',
            self.body.index("if (!failure && !dryRun)"),
        )
        remove = self.body.index(
            '"removeApplicationWithBundleIdentifier:pruneEmptyIcons:"',
            desired,
        )
        add = self.body.index('"addApplication:"', remove)
        equality = self.body.index('"isEqual:"', add)
        self.assertLess(desired, remove)
        self.assertLess(remove, add)
        self.assertLess(add, equality)
        self.assertIn('@"pathPreserved": @(pathMatches)', self.body)
        self.assertIn('[SPECIAL_ICON_OBJECTS_PREFLIGHT]', self.body)
        self.assertIn('[SPECIAL_ICON_OBJECTS_LAYOUT_PREFLIGHT]', self.body)
        self.assertIn('if (!spotlight) {', self.body)
        self.assertNotIn('if (!spotlight && !target->alreadyDesired)', self.body)
        self.assertIn('[SPECIAL_ICON_OBJECTS_POST]', self.body)
        self.assertIn('new-path=0x%llx path-match=%d transport=%d', self.body)
        self.assertIn('rebuild postcondition failed: bundle=%@ class=%@ path=%@', self.body)
        self.assertIn('themer_log_special_icon_layout_surface("model", iconModel)', self.body)
        self.assertIn('themer_log_special_icon_layout_surface("root-folder", rootFolder)', self.body)
        self.assertIn('[SPECIAL_ICON_LAYOUT_SURFACE]', THEMER)
        self.assertIn('invoked=0', THEMER)

    def test_wrapper_binds_exact_pid_and_closes_session(self):
        self.assertIn('isEqualToString:@"SpringBoard"', self.wrapper)
        self.assertIn('isEqualToString:@"Spotlight"', self.wrapper)
        self.assertIn("proc_find(pid) == expectedProc", self.wrapper)
        self.assertIn("proc_task(expectedProc) == expectedTask", self.wrapper)
        self.assertIn("session.pid == pid", self.wrapper)
        self.assertIn("destroyRemoteCall", self.wrapper)
        self.assertIn("finalIdentityStable", self.wrapper)

    def test_settings_preflight_both_consumers_before_mutation(self):
        action = SETTINGS.split(
            "settings_run_special_icon_object_migration_action_with_hook", 1
        )[1].split(
            "void settings_run_hail_mary_app_library_miniature_refresh_action",
            1,
        )[0]
        self.assertIn("springBoardPreflight", action)
        self.assertIn("spotlightPreflight", action)
        self.assertIn("usleep(1000000)", action)
        self.assertIn("preflight-detail SpringBoard=%s Spotlight=%s", action)
        self.assertIn("preflight-refused", action)
        self.assertIn("spotlightMigration", action)
        self.assertIn("springBoardMigration", action)
        self.assertLess(
            action.index("spotlightMigration"),
            action.index("springBoardMigration"),
        )
        self.assertIn("CNDIconServicesConsumerHookAuditSpringBoard", action)

    def test_launch_arguments_remain_wired_while_old_rows_stay_hidden(self):
        self.assertIn("case RootSectionProbes:         return 7;", SETTINGS)
        self.assertIn(
            "static const NSInteger rows[] = {17, 18, 28, 29, 30, 31, 32};",
            SETTINGS,
        )
        self.assertIn("settings_root_probe_underlying_row", SETTINGS)
        self.assertIn("Rebuild Static Clock + Calendar Objects", SETTINGS)
        self.assertIn("Rebuild Live Clock + Calendar Objects", SETTINGS)
        for action in (
            "settings_run_special_icon_object_preflight_action",
            "settings_run_special_icon_object_rebuild_static_action",
            "settings_run_special_icon_object_rebuild_live_action",
        ):
            self.assertIn(action, SETTINGS_HEADER)
            self.assertIn(action, SETTINGS)
        for flag in (
            "--special-icon-object-preflight",
            "--special-icon-object-rebuild-static",
            "--special-icon-object-rebuild-live",
        ):
            self.assertIn(flag, APP_DELEGATE)

    def test_no_process_lifecycle_or_shared_cache_write_in_migration(self):
        for banned in (
            "SIGKILL",
            "killall(",
            "reboot(",
            "respring(",
            "kwrite",
            "mach_vm_write",
            "object_setClass",
        ):
            self.assertNotIn(banned, self.body, banned)
        self.assertIn('@"processLifecycleMutationCount": @0', self.body)
        self.assertIn('@"sharedCacheWriteCount": @0', self.body)


if __name__ == "__main__":
    unittest.main()
