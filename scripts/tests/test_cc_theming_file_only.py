"""Keep production Apply isolated from removed in-process glyph painters."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class CCThemingFileOnlyTests(unittest.TestCase):
    def test_painter_sources_are_removed(self):
        for stem, suffixes in (
            ("Runtime", ("h", "m")),
            ("Persistent", ("h", "m")),
            ("Delivery", ("h", "m")),
            ("Payload", ("h", "c", "S")),
        ):
            for suffix in suffixes:
                with self.subTest(source=f"{stem}.{suffix}"):
                    self.assertFalse((ROOT / "Cyanide/tweaks" /
                                      f"CNDCCTheming{stem}.{suffix}").exists())

    def test_apply_and_restore_only_dispatch_file_transactions(self):
        settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()
        runner = settings.split(
            "BOOL settings_apply_cc_theming_now(BOOL apply)", 1
        )[1].split(
            "\n#if 0", 1
        )[0]
        self.assertIn("CNDCCThemingFileBackingApply()", runner)
        self.assertIn("CNDCCThemingFileBackingRestore()", runner)
        for forbidden in (
            "CNDCCThemingPersistent", "CNDCCThemingApplyPulsarArtwork",
            "CNDCCThemingDelivery", "settings_ensure_springboard_remote_call_locked",
            "r_autorelease_pool_push", "object_setClass", "setImage:",
            "loadViewIfNeeded", "CNDCCThemingMaterializeExactRouteOwners",
            "settings_post_actions_complete_async", "PackageQueue",
        ):
            with self.subTest(operation=forbidden):
                self.assertNotIn(forbidden, runner)

    def test_installer_shows_cc_resource_state_instead_of_beta_badge(self):
        packages = (ROOT / "Cyanide/installer/PackagesViewController.m").read_text()
        detail = (ROOT / "Cyanide/installer/PackageDetailViewController.m").read_text()

        accessory = packages.split(
            "- (UIView *)accessoryViewForPackage:", 1
        )[1].split("- (UIView *)pillWithText:", 1)[0]
        cc = accessory.split(
            "if (pkg.kind == PackageInstallKindControlCenterTheming)", 1
        )[1].split("if (pkg.kind == PackageInstallKindDirectTool)", 1)[0]
        # The pill reads live target bytes, not the journal's claim alone: after a
        # respring the journal survives while the resources revert to stock.
        self.assertIn("CNDCCThemingFileBackingLiveStateNow", cc)
        self.assertIn("CNDCCThemingFileBackingLiveStateApplied", cc)
        self.assertNotIn("HasJournaledState", cc)
        self.assertIn('pillWithText:@"ACTIVE"', cc)
        self.assertIn('pillWithText:@"STOCK"', cc)
        self.assertIn('@"APPLY PENDING"', cc)
        self.assertIn('@"RESTORE PENDING"', cc)
        self.assertLess(
            accessory.index("PackageInstallKindControlCenterTheming"),
            accessory.index('caseInsensitiveCompare:@"Beta"'),
        )

        manual_state = detail.split("- (NSString *)manualStateText", 1)[1]
        manual_state = manual_state.split("- (NSString *)toggleStateText", 1)[0]
        self.assertIn("CNDCCThemingFileBackingLiveStateNow", manual_state)
        self.assertIn('@"Active"', manual_state)
        self.assertIn('@"Stock"', manual_state)
        # Only applied evidence is Active; a partial mix stays distinguishable.
        self.assertIn("CNDCCThemingFileBackingLiveStatePartial", manual_state)
        self.assertIn('@"Partial"', manual_state)
        self.assertNotIn("HasJournaledState", manual_state)

        manual_color = detail.split("- (UIColor *)manualStateColor", 1)[1]
        manual_color = manual_color.split("- (BOOL)presentQueueConflictIfNeededForIntent:", 1)[0]
        self.assertIn("CNDCCThemingFileBackingLiveStateApplied", manual_color)
        self.assertNotIn("HasJournaledState", manual_color)

    def test_control_center_detail_has_one_state_dependent_action(self):
        detail = (ROOT / "Cyanide/installer/PackageDetailViewController.m").read_text()

        # No submenu: the CC detail screen carries a single Apply/Restore button.
        menu = detail.split("- (UIMenu *)manualActionMenu", 1)[1].split(
            "- (instancetype)initWithPackage:", 1)[0]
        self.assertNotIn("ControlCenterTheming", menu)
        for title in ("Apply Pulsar Resources", "Restore Stock Resources",
                      "Control Center Resources"):
            self.assertNotIn(title, detail)

        cc_flag = detail.split("BOOL ccTheming =", 1)[1].split(";", 1)[0]
        self.assertIn("PackageInstallKindControlCenterTheming", cc_flag)
        use_menu = detail.split("BOOL useMenu =", 1)[1].split(";", 1)[0]
        self.assertIn("!ccTheming", use_menu)

        # The one button queues Apply, or Restore when the theme is live.
        tap = detail.split("- (void)didTapAction", 1)[1].split(
            "- (void)promptSelectThemeBeforeInstall", 1)[0]
        action = tap.split(
            "if (self.package.kind == PackageInstallKindControlCenterTheming)", 1
        )[1].split("return;", 1)[0]
        self.assertIn("CNDCCThemingFileBackingLiveStateNow", action)
        self.assertIn("CNDCCThemingFileBackingLiveStateApplied", action)
        self.assertIn("PackageQueueIntentUninstall", action)
        self.assertIn("PackageQueueIntentInstall", action)

        title = detail.split("- (NSString *)manualActionTitleForIntent:", 1)[1].split(
            "- (NSString *)manualStateText", 1)[0]
        cc_titles = title.split(
            "if (self.package.kind == PackageInstallKindControlCenterTheming)")
        self.assertEqual(len(cc_titles), 3)
        self.assertIn('@"Cancel Apply"', cc_titles[1])
        self.assertIn('? @"Restore" : @"Apply"', cc_titles[2])
        self.assertNotIn("Apply/Restore", cc_titles[2].split(";", 1)[0])

    def test_live_state_probe_is_read_only_and_bounded(self):
        backing = (ROOT / "Cyanide/tweaks/CNDCCThemingFileBacking.m").read_text()
        probe = backing.split(
            "CNDCCThemingFileBackingLiveStateInDirectory(\n    NSURL *journalDirectory", 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn("CNDCCFileRead", probe)
        self.assertIn("CNDCCFileSHA", probe)
        self.assertIn("CNDCCLiveProbeCount", probe)
        self.assertIn("CNDCCLiveProbeLength", probe)
        for writer in ("CNDCCFileSave", "CNDCCFileSaveJSON", "overwrite_system_file"):
            self.assertNotIn(writer, probe)
        self.assertIn("CNDCCLiveProbeCount = 4", backing)
        self.assertIn("CNDCCLiveProbeLength = 2U << 20", backing)

        header = (ROOT / "Cyanide/tweaks/CNDCCThemingFileBacking.h").read_text()
        self.assertIn("CNDCCThemingFileBackingLiveStateUnknown = 0", header)
        for state in ("Stock", "Applied", "Partial"):
            self.assertIn(f"CNDCCThemingFileBackingLiveState{state}", header)


if __name__ == "__main__":
    unittest.main()
