"""Compatibility contracts for the former media/Focus diagnostic entry point."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class CCSemanticTraceTests(unittest.TestCase):
    def test_old_entry_point_is_a_nonrecursive_lifecycle_trace_alias(self):
        probe = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.m").read_text()
        alias = probe.split(
            "NSDictionary<NSString *, id> *CNDCCThemingCopyMediaFocusSemanticTrace(void)", 1
        )[1].split("CNDCCThemingCopyMediaConnectivityTrace(void)", 1)[0]
        self.assertIn("return CNDCCThemingCopyLifecycleOwnerTrace();", alias)
        self.assertNotIn("subviews", alias)
        header = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.h").read_text()
        self.assertIn("CNDCCThemingCopyLifecycleOwnerTrace", header)
        self.assertIn("CNDCCThemingCopyMediaFocusSemanticTrace", header)

    def test_existing_archive_and_share_actions_are_preserved(self):
        settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()
        for expected in (
            "physical-media-focus-semantic-trace.json",
            "physical-media-focus-semantic-trace-%@.json",
            'action": @"cc-theming-trace-semantic"',
            'action": @"cc-theming-share-semantic-trace"',
            "settings_run_cc_theming_media_focus_semantic_trace();",
            "CNDCCThemingCopyLifecycleOwnerTrace()",
            "Trace CC Lifecycle Owners",
            "Share CC Lifecycle Owner Trace",
        ):
            self.assertIn(expected, settings)
        self.assertNotIn("A one-time discovery walk is reported separately", settings)


if __name__ == "__main__":
    unittest.main()
