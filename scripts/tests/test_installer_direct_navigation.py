"""Structural checks for direct package navigation."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ROOT / "Cyanide/installer/PackagesViewController.m"


class InstallerDirectNavigationTests(unittest.TestCase):
    def test_cc_theming_is_in_the_curated_new_section(self) -> None:
        source = PACKAGES.read_text(encoding="utf-8")
        self.assertIn(
            'kNewCCThemingIdentifier = @"com.darksword.cc-theming"',
            source,
        )
        curated = source.split("NSSet<NSString *> *newIdentifiers", 1)[1]
        curated = curated.split("for (Package *package in filtered)", 1)[0]
        self.assertIn("kNewCCThemingIdentifier", curated)

    def test_glyph_swipe_opens_live_controls_without_queueing(self) -> None:
        source = PACKAGES.read_text(encoding="utf-8")
        swipe = source.split(
            "if (pkg.kind == PackageInstallKindLockscreenGlyphs && intent == PackageQueueIntentNone)", 1
        )[1].split("\n    NSString *title;", 1)[0]
        self.assertIn('title:@"Controls"', swipe)
        self.assertIn("PackageDetailViewController alloc] initWithPackage:pkg", swipe)
        self.assertIn("pushViewController:detail", swipe)
        self.assertIn("performsFirstActionWithFullSwipe = NO", swipe)
        self.assertNotIn("queueIntent:", swipe)
        self.assertNotIn("settings_apply_lockscreen_glyphs", swipe)

    def test_snowboard_remix_bypasses_package_detail_gate(self) -> None:
        source = PACKAGES.read_text(encoding="utf-8")
        start = source.index(
            "- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:"
        )
        end = source.index(
            "- (UISwipeActionsConfiguration *)tableView:", start
        )
        selection = source[start:end]

        identifier = (
            '[pkg.identifier isEqualToString:@"com.darksword.snowboardlite"]'
        )
        direct_navigation = "[self navigateToSettingsSectionForPackage:pkg];"
        detail_gate = "PackageDetailViewController *detail"

        self.assertIn(identifier, selection)
        self.assertIn(direct_navigation, selection)
        self.assertIn(detail_gate, selection)
        self.assertLess(selection.index(identifier), selection.index(detail_gate))
        self.assertLess(
            selection.index(direct_navigation), selection.index(detail_gate)
        )


if __name__ == "__main__":
    unittest.main()
