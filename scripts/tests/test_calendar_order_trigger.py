import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/lab/cnd_calendar_order_trigger.m"
DRIVER = ROOT / "scripts/lab/cnd_calendar_order_trigger.py"
sys.path.insert(0, str(DRIVER.parent))
import cnd_calendar_order_trigger as trigger


class CalendarOrderTriggerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.driver = DRIVER.read_text(encoding="utf-8")

    def test_exposes_the_independent_ordering_sequences(self) -> None:
        self.assertEqual(
            trigger.ACTIONS,
            (
                "springboard-refresh-then-calendar",
                "springboard-calendar-then-refresh",
                "springboard-combined-current",
                "springboard-fast-path",
                "springboard-restore-only",
                "springboard-fast-path-only",
                "springboard-reload-only",
                "springboard-source-cache-reload",
                "springboard-source-cache-refill-barrier",
                "springboard-source-prepare-reload",
                "spotlight-calendar",
                "spotlight-restore-only",
                "spotlight-fast-path-only",
                "spotlight-reload-only",
                "spotlight-source-cache-reload",
                "spotlight-source-cache-refill-barrier",
                "spotlight-source-prepare-reload",
            ),
        )
        for action in trigger.ACTIONS:
            self.assertIn(f'@"{action}"', self.source)

    def test_each_sequence_restores_the_dynamic_source_first(self) -> None:
        branch = self.source.index(
            'if ([action isEqualToString:'
            '@"springboard-refresh-then-calendar"])'
        )
        end = self.source.index("} else if", branch)
        body = self.source[branch:end]
        self.assertLess(
            body.index('@"restore-dynamic-source"'),
            body.index('@"refresh-before-calendar"'),
        )

    def test_refresh_then_calendar_keeps_calendar_terminal(self) -> None:
        start = self.source.index(
            '[action isEqualToString:@"springboard-refresh-then-calendar"]'
        )
        end = self.source.index("} else if", start)
        body = self.source[start:end]
        self.assertLess(
            body.index('@"refresh-before-calendar"'),
            body.index('@"calendar-terminal"'),
        )

    def test_calendar_then_refresh_matches_the_regression_candidate(self) -> None:
        start = self.source.index(
            '@"springboard-calendar-then-refresh"'
        )
        end = self.source.index("} else if", start)
        body = self.source[start:end]
        self.assertLess(
            body.index('@"calendar-before-refresh"'),
            body.index('@"refresh-after-calendar"'),
        )

    def test_trigger_is_a_direct_target_dylib_without_cyanide_symbols(self) -> None:
        self.assertIn("CNDCalendarOrderProviderSubclass", self.source)
        self.assertIn("CNDCalendarOrderBroadRefresh", self.source)
        self.assertIn(
            'CNDCalendarOrderBoolNoArgument(manager, "relayout")',
            self.source,
        )
        self.assertIn("objc_getAssociatedObject", self.source)
        self.assertIn('@"directTargetDylib": @YES', self.source)
        self.assertIn('@"cyanideSymbolsUsed": @NO', self.source)
        for symbol in (
            "settings_sbl_selected_theme_data",
            "CNDIconServicesConsumerLifecycleRepairProcess",
            "CNDIconServicesConsumerLifecycleRefreshSpringBoardCaches",
        ):
            self.assertNotIn(symbol, self.source)
        self.assertNotIn("windows", self.source)
        self.assertNotIn("subviews", self.source)
        self.assertNotIn("setActive:", self.source)

    def test_build_pins_the_sequence_and_enables_warnings_as_errors(self) -> None:
        with patch.object(trigger, "run") as run:
            output = trigger.build(
                "springboard-refresh-then-calendar", "token", "nonce"
            )
        command = run.call_args_list[0].args[0]
        self.assertEqual(
            output,
            trigger.BUILD_DIR /
            "cnd_calendar_order_springboard-refresh-then-calendar.dylib",
        )
        self.assertIn(
            '-DCND_CALENDAR_ORDER_ACTION="springboard-refresh-then-calendar"',
            command,
        )
        self.assertIn("-Werror", command)

    def test_injection_refuses_a_changed_target_identity(self) -> None:
        ssh = Mock()
        with patch.object(
            trigger,
            "resolve_target",
            side_effect=[
                (100, trigger.TARGETS["SpringBoard"]),
                (101, trigger.TARGETS["SpringBoard"]),
            ],
        ), patch.object(
            trigger, "issue_file_extension", return_value="token"
        ), patch.object(
            trigger, "build", return_value=SOURCE
        ):
            with self.assertRaisesRegex(trigger.LabError, "identity changed"):
                trigger.inject(
                    ssh,
                    "springboard-refresh-then-calendar",
                    "SpringBoard",
                )
        self.assertFalse(any(
            "opainject" in call.args[0] for call in ssh.command.call_args_list
        ))

    def test_spotlight_action_resolves_spotlight_directly(self) -> None:
        self.assertEqual(
            trigger.target_for_action("spotlight-calendar"), "Spotlight"
        )
        self.assertEqual(
            trigger.target_for_action("springboard-fast-path"), "SpringBoard"
        )

    def test_direct_lifecycle_controls_do_not_hide_a_store_mutation(self) -> None:
        restore = self.source.index(
            '[action isEqualToString:@"springboard-restore-only"]'
        )
        fast = self.source.index(
            '[action isEqualToString:@"springboard-fast-path-only"]'
        )
        self.assertIn('@"restore-dynamic-source"', self.source[restore:fast])
        self.assertIn(
            '@"calendar-fast-path-only"',
            self.source[fast:self.source.index("} else {", fast)],
        )
        self.assertEqual(
            trigger.target_for_action("spotlight-restore-only"), "Spotlight"
        )
        self.assertEqual(
            trigger.target_for_action("spotlight-fast-path-only"),
            "Spotlight",
        )

    def test_reload_only_preserves_the_retained_source_and_advances_generation(self) -> None:
        self.assertIn("CNDCalendarOrderReloadRetained", self.source)
        self.assertIn('@"calendar-retained-reload-only"', self.source)
        self.assertIn('@"retainedSource": @YES', self.source)
        self.assertIn("after == before + 1U", self.source)
        self.assertEqual(
            trigger.target_for_action("spotlight-reload-only"),
            "Spotlight",
        )

    def test_source_cache_reload_uses_the_exact_isimagecache_setter_abi(self) -> None:
        self.assertIn(
            "CNDCalendarOrderPurgeSourceCachesAndReload", self.source
        )
        self.assertIn('sel_registerName("imageCache"), "@16@0:8"', self.source)
        self.assertIn(
            'sel_registerName("setImageBagsByDescriptor:"),\n'
            '                "v24@0:8@16"',
            self.source,
        )
        self.assertIn('@"calendar-source-cache-reload"', self.source)
        self.assertEqual(
            trigger.target_for_action("spotlight-source-cache-reload"),
            "Spotlight",
        )

    def test_source_cache_refill_barrier_observes_async_completion(self) -> None:
        self.assertIn("CNDCalendarOrderSourceCacheSnapshot", self.source)
        self.assertIn(
            '@"calendar-source-cache-immediate"', self.source
        )
        self.assertIn(
            '@"calendar-source-cache-after-20ms"', self.source
        )
        self.assertIn("20 * NSEC_PER_MSEC", self.source)
        self.assertIn(
            '@"allSourceCachesPopulated"', self.source
        )
        self.assertEqual(
            trigger.target_for_action(
                "spotlight-source-cache-refill-barrier"
            ),
            "Spotlight",
        )

    def test_source_prepare_forces_a_store_read_before_provider_reload(self) -> None:
        self.assertIn("CNDCalendarOrderPrepareRetainedSources", self.source)
        self.assertIn(
            'sel_registerName("prepareImageForDescriptor:"),\n'
            '                "@24@0:8@16"',
            self.source,
        )
        start = self.source.index(
            '@"springboard-source-prepare-reload"'
        )
        end = self.source.index("} else {", start)
        body = self.source[start:end]
        self.assertLess(
            body.index('@"calendar-source-cache-purge"'),
            body.index('@"calendar-source-prepare"'),
        )
        self.assertLess(
            body.index('@"calendar-source-prepare"'),
            body.index('@"calendar-provider-reload"'),
        )
        self.assertEqual(
            trigger.target_for_action("spotlight-source-prepare-reload"),
            "Spotlight",
        )


if __name__ == "__main__":
    unittest.main()
