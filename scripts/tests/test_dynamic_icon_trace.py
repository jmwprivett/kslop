import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/lab/cnd_dynamic_icon_trace.m"
DRIVER = ROOT / "scripts/lab/cnd_dynamic_icon_trace.py"
sys.path.insert(0, str(DRIVER.parent))
import cnd_dynamic_icon_trace as tracer


class DynamicIconTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.driver = DRIVER.read_text(encoding="utf-8")

    def test_targets_only_known_dynamic_icon_classes(self) -> None:
        for name in (
            "SBHClockApplicationIconImageView",
            "SBHCalendarApplicationIcon",
            "SBCalendarIconImageProvider",
        ):
            self.assertIn(f'"{name}"', self.source)

    def test_probe_has_no_window_or_recursive_view_discovery(self) -> None:
        self.assertNotIn('sel_registerName("windows")', self.source)
        self.assertNotIn('sel_registerName("keyWindow")', self.source)
        self.assertNotIn("sb_collect_views", self.source)
        self.assertNotIn("objectAtIndex:", self.source)
        self.assertIn("no-window-walk=1", self.source)

    def test_inherited_hook_does_not_save_our_wrapper_as_original(self) -> None:
        self.assertIn("CNDOriginalBelowInstalledWrapper", self.source)
        self.assertIn("already-wrapped-without-original", self.source)

    def test_trace_hooks_lifecycle_and_dynamic_update_boundaries(self) -> None:
        for selector in (
            '"didMoveToWindow"',
            '"layoutSubviews"',
            '"updateUnanimated"',
            '"setClockBackgroundIcon:"',
            '"setHandsHidden:animated:"',
            '"setDate:"',
            '"setDisplayedImage:"',
            '"calendarIconImageProviderHasChanged:"',
            '"iconImageWithInfo:"',
            '"iconLayerWithInfo:traitCollection:options:"',
            '"controller:didChangeOverrideDateFromDate:"',
        ):
            self.assertIn(selector, self.source)

    def test_calendar_trace_records_returned_image_info(self) -> None:
        self.assertIn("CNDTraceObjectImageInfo", self.source)
        self.assertIn("CNDLogReturnedObject", self.source)
        self.assertIn("continuousCornerRadius", self.source)

    def test_clock_trace_follows_graphic_leaf_to_iconservices(self) -> None:
        self.assertIn('"iconForImage"', self.source)
        self.assertIn('"iconServicesIconForImage"', self.source)
        self.assertIn('"SBLeafIcon", "iconServicesIconForImage"', self.source)
        self.assertIn("CNDTrackClockLeaf(result)", self.source)
        self.assertIn('CNDTrackISIcon("clock", result)', self.source)
        self.assertIn("CLOCK_LEAF root=%llu leaf=", self.source)

    def test_calendar_trace_captures_prepared_icon_and_initializer(self) -> None:
        self.assertIn('"_preparedISIcon"', self.source)
        self.assertIn('CNDTrackISIcon("calendar", result)', self.source)
        self.assertIn('"initWithDate:calendar:format:"', self.source)
        self.assertIn("CALENDAR_INIT object=", self.source)
        self.assertIn("CALENDAR_PROVIDER root=%llu provider=", self.source)
        self.assertIn('@"com.apple.mobilecal"', self.source)
        self.assertIn('return "calendar-bundle";', self.source)
        self.assertIn('"bundle=%s type=%s "', self.source)

    def test_source_trace_records_descriptor_and_cache_store_returns(self) -> None:
        for selector in (
            '"imageForDescriptor:"',
            '"imageForImageDescriptor:"',
            '"_cachedImageForDescriptor:"',
            '"_imageFromStoreForDescriptor:"',
            '"generateImageWithDescriptor:"',
        ):
            self.assertIn(selector, self.source)
        for field in (
            '"appearance"', '"appearanceVariant"', '"variantOptions"',
            '"graphicVariant"', '"ignoreCache"',
        ):
            self.assertIn(field, self.source)
        self.assertIn('"uuid"', self.source)
        self.assertIn("CND_SOURCE_EVENT_CAP", self.source)
        self.assertIn("CNDISIconKind(self)", self.source)

    def test_trace_records_passive_pixel_format_at_source_and_view(self) -> None:
        self.assertIn("CGImageGetAlphaInfo", self.source)
        self.assertIn("CGImageGetBitmapInfo", self.source)
        self.assertIn("CGImageGetBitsPerComponent", self.source)
        self.assertIn("CGImageGetBitsPerPixel", self.source)
        self.assertIn("CGImageGetBytesPerRow", self.source)
        self.assertIn("CNDLayerContentsCGImage", self.source)
        self.assertIn('"clock-background-leaf"', self.source)
        self.assertIn(
            '"makeIconImageWithInfo:traitCollection:context:options:"',
            self.source,
        )
        self.assertIn("CNDLogPixelMetadata(image", self.source)
        self.assertIn("CNDCanonicalRGBA", self.source)
        self.assertIn("data-sha256=%s pixel-sha256=%s", self.source)

    def test_calendar_order_trace_captures_generation_and_cache_boundaries(self) -> None:
        self.assertIn('"imageGeneration"', self.source)
        self.assertIn("image-generation=%d/%lld", self.source)
        self.assertIn("image-provider=%p/%s", self.source)
        for class_name, selector in (
            ("SBHIconManager", "resetAllIconImageCaches"),
            ("SBHIconManager", "iconImageCache"),
            ("SBHIconManager", "folderIconImageCache"),
            ("SBHIconManager", "relayout"),
            ("SBIconController", "notificationIconImageCache"),
            ("SBIconController", "tableUIIconImageCache"),
            ("SBIconController", "appSwitcherHeaderIconImageCache"),
            ("SBLibraryViewController", "iconImageCache"),
            ("SBHIconLibraryTableViewController", "iconImageCache"),
        ):
            self.assertIn(f'{{"{class_name}", "{selector}"}}', self.source)
        self.assertIn("CACHE_BOUNDARY us=%llu phase=%s", self.source)
        self.assertIn('CNDLogIconManagerCacheBoundary("reset-enter"', self.source)
        self.assertIn('CNDLogIconManagerCacheBoundary("reset-return"', self.source)

    def test_normal_updates_correlate_stock_source_and_view_results(self) -> None:
        self.assertIn("gCNDRootSequence = sequence", self.source)
        self.assertIn("SOURCE_REQUEST event=%u root=%llu", self.source)
        self.assertIn("CLOCK_LEAF root=%llu", self.source)
        self.assertIn("RESULT root=%llu", self.source)
        self.assertIn("clock-background-leaf", self.source)
        self.assertIn("bool clockLeaf = CNDContainsPointer", self.source)
        self.assertIn("bool provider = CNDClassIsOrInherits", self.source)

    def test_clock_leaf_scopes_first_iconservices_descriptor_request(self) -> None:
        leaf_wrapper = self.source.split(
            "static id CNDTraceObjectImageInfoObjectObjectOptions(", 1
        )[1].split("static bool CNDTypeIsObject", 1)[0]
        source_wrapper = self.source.split(
            "static id CNDTraceObjectObject(", 1
        )[1].split("static id CNDTraceCalendarInitObjects", 1)[0]

        self.assertIn("static __thread bool gCNDClockSourceScope;", self.source)
        self.assertIn("if (clockLeaf) gCNDClockSourceScope = true;", leaf_wrapper)
        self.assertIn("previousClockScope = gCNDClockSourceScope", leaf_wrapper)
        self.assertIn("@finally {\n        gCNDClockSourceScope = previousClockScope;", leaf_wrapper)
        self.assertLess(
            leaf_wrapper.index("if (clockLeaf) gCNDClockSourceScope = true;"),
            leaf_wrapper.index("hook->original)(self, selector, info"),
        )
        self.assertIn("if (gCNDSourceLogging)", source_wrapper)
        self.assertIn("if (!kind && gCNDClockSourceScope)", source_wrapper)
        self.assertIn('CNDTrackISIcon("clock", self);', source_wrapper)
        self.assertLess(
            source_wrapper.index('CNDTrackISIcon("clock", self);'),
            source_wrapper.index("CNDLogSourceRequest(hook->selectorName"),
        )

    def test_driver_can_inventory_trace_and_map_theme_assets(self) -> None:
        self.assertIn('"inventory"', self.driver)
        self.assertIn('"inject"', self.driver)
        self.assertIn('"theme-assets"', self.driver)
        self.assertIn("ClockIcon", self.driver)
        self.assertIn("png_dimensions", self.driver)

    def test_trace_paths_keep_springboard_and_spotlight_separate(self) -> None:
        self.assertEqual(tracer.trace_paths("SpringBoard"),
                         (tracer.REPORT, tracer.INJECT_LOG))
        self.assertEqual(tracer.trace_paths("Spotlight"),
                         (tracer.SPOTLIGHT_REPORT, tracer.SPOTLIGHT_INJECT_LOG))
        self.assertNotEqual(tracer.REPORT, tracer.SPOTLIGHT_REPORT)
        self.assertNotEqual(tracer.INJECT_LOG, tracer.SPOTLIGHT_INJECT_LOG)

    def test_build_embeds_target_report_and_uses_distinct_payload(self) -> None:
        with patch.object(tracer, "run") as run:
            spotlight = tracer.build("token", target="Spotlight")
            spotlight_command = run.call_args_list[0].args[0]
            springboard = tracer.build("token")
            springboard_command = run.call_args_list[2].args[0]
        self.assertNotEqual(spotlight, springboard)
        self.assertIn(
            f'-DCND_DYNAMIC_TRACE_OUTPUT_PATH="{tracer.SPOTLIGHT_REPORT}"',
            spotlight_command,
        )
        self.assertIn(f'-DCND_DYNAMIC_TRACE_OUTPUT_PATH="{tracer.REPORT}"',
                      springboard_command)
        self.assertIn("-Werror", spotlight_command)

    def test_spotlight_injection_checks_identity_and_uses_own_logs(self) -> None:
        ssh = Mock()
        pid = 650
        expected = tracer.TARGETS["Spotlight"]
        with patch.object(tracer, "resolve_target",
                          side_effect=[(pid, expected), (pid, expected)]) as resolve, \
             patch.object(tracer, "issue_file_extension", return_value="token"), \
             patch.object(tracer, "build", return_value=SOURCE) as build, \
             patch.object(tracer, "read_report",
                          return_value=f"TRACE_READY pid={pid} classes=6 hooks=1 ") as read:
            actual_pid, _ = tracer.inject(ssh, False, "Spotlight")
        self.assertEqual(actual_pid, pid)
        self.assertEqual(resolve.call_count, 2)
        build.assert_called_once_with("token", False, "Spotlight")
        read.assert_called_once_with(ssh, "Spotlight")
        inject_command = ssh.command.call_args_list[-1].args[0]
        self.assertIn(tracer.SPOTLIGHT_REPORT, inject_command)
        self.assertIn(tracer.SPOTLIGHT_INJECT_LOG, inject_command)
        self.assertNotIn(tracer.REPORT + " ", inject_command)

    def test_spotlight_read_and_mark_use_spotlight_report(self) -> None:
        ssh = Mock()
        ssh.command.return_value = "trace\n"
        self.assertEqual(tracer.read_report(ssh, "Spotlight"), "trace\n")
        self.assertIn(tracer.SPOTLIGHT_REPORT, ssh.command.call_args.args[0])
        tracer.mark(ssh, "clock-results", "Spotlight")
        self.assertIn(tracer.SPOTLIGHT_REPORT, ssh.command.call_args.args[0])
        self.assertIn("MARK clock-results", ssh.command.call_args.args[0])

    def test_spotlight_rejects_changed_identity_before_injection(self) -> None:
        ssh = Mock()
        with patch.object(tracer, "resolve_target",
                          side_effect=[(650, tracer.TARGETS["Spotlight"]),
                                       (651, tracer.TARGETS["Spotlight"])]), \
             patch.object(tracer, "issue_file_extension", return_value="token"), \
             patch.object(tracer, "build", return_value=SOURCE):
            with self.assertRaisesRegex(tracer.LabError,
                                        "Spotlight identity changed"):
                tracer.inject(ssh, False, "Spotlight")
        self.assertFalse(any("opainject" in call.args[0]
                             for call in ssh.command.call_args_list))

    def test_spotlight_readiness_requires_the_target_pid(self) -> None:
        ssh = Mock()
        with patch.object(tracer, "resolve_target",
                          return_value=(650, tracer.TARGETS["Spotlight"])), \
             patch.object(tracer, "issue_file_extension", return_value="token"), \
             patch.object(tracer, "build", return_value=SOURCE), \
             patch.object(tracer, "read_report",
                          return_value="TRACE_READY pid=651 classes=6 hooks=1 "), \
             patch.object(tracer.time, "monotonic", side_effect=[0, 0, 11]), \
             patch.object(tracer.time, "sleep"):
            with self.assertRaisesRegex(tracer.LabError,
                                        "Spotlight Clock/Calendar trace did not become ready"):
                tracer.inject(ssh, False, "Spotlight")


if __name__ == "__main__":
    unittest.main()
