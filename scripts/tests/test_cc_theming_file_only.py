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
        self.assertIn("CNDCCThemingFileBackingHasJournaledState", cc)
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
        self.assertIn("CNDCCThemingFileBackingHasJournaledState", manual_state)
        self.assertIn('? @"Active" : @"Stock"', manual_state)


if __name__ == "__main__":
    unittest.main()
