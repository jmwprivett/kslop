import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "scripts/lab/cnd_calendar_order_experiment.py"
sys.path.insert(0, str(DRIVER.parent))
import cnd_calendar_order_experiment as experiment


class CalendarOrderExperimentTests(unittest.TestCase):
    def test_trace_slice_requires_both_exact_outer_markers(self) -> None:
        report = "\n".join((
            "old",
            "[CND_DYNAMIC] MARK experiment-1-a-begin",
            "wanted",
            "[CND_DYNAMIC] MARK experiment-1-a-end",
            "new",
        ))
        self.assertEqual(
            experiment.bounded_trace_slice(report, "experiment-1-a"),
            "[CND_DYNAMIC] MARK experiment-1-a-begin\n"
            "wanted\n"
            "[CND_DYNAMIC] MARK experiment-1-a-end\n",
        )
        with self.assertRaises(experiment.LabError):
            experiment.bounded_trace_slice(report, "missing")

    def test_summary_records_order_hashes_generation_and_sources(self) -> None:
        pixel_hash = "a" * 64
        trace = "\n".join((
            "[CND_CALENDAR_ORDER] MARK us=1 process=SpringBoard "
            "label=refresh-before-calendar phase=begin",
            "[CND_DYNAMIC] CACHE_BOUNDARY us=2 phase=reset-enter "
            "manager=0x1/SBHIconManager icon-cache=0x2/X folder-cache=0x3/Y",
            "[CND_DYNAMIC] CACHE_BOUNDARY us=3 phase=reset-return "
            "manager=0x1/SBHIconManager icon-cache=0x4/X folder-cache=0x5/Y",
            "[CND_CALENDAR_ORDER] MARK us=4 process=SpringBoard "
            "label=refresh-before-calendar phase=end",
            "[CND_CALENDAR_ORDER] MARK us=5 process=SpringBoard "
            "label=calendar-terminal phase=begin",
            "[CND_DYNAMIC] SOURCE_REQUEST kind=calendar-bundle "
            "bundle=com.apple.mobilecal pixel-sha256=" + pixel_hash,
            "[CND_DYNAMIC] EVENT class=SBHCalendarApplicationIcon "
            "id=com.apple.mobilecal image-generation=1/12",
            "[CND_CALENDAR_ORDER] MARK us=6 process=SpringBoard "
            "label=calendar-terminal phase=end",
        ))
        summary = experiment.summarize_trace(trace)
        self.assertTrue(summary["resetObserved"])
        self.assertTrue(summary["calendarBundleSourceObserved"])
        self.assertEqual(summary["calendarPixelHashes"], [pixel_hash])
        self.assertEqual(summary["calendarGenerations"], [12])
        self.assertEqual(
            summary["operationRanges"]["refresh-before-calendar"],
            {"begin": 0, "end": 3},
        )
        self.assertEqual(
            summary["operationRanges"]["calendar-terminal"],
            {"begin": 4, "end": 7},
        )

    def test_session_write_is_atomic_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = {"target": "SpringBoard", "pid": 42}
            experiment.write_json(root / experiment.SESSION_NAME, value)
            self.assertEqual(experiment.read_session(root), value)
            self.assertFalse((root / "session.json.tmp").exists())

    def test_trigger_result_requires_one_machine_readable_completion(self) -> None:
        report = (
            "[CND_CALENDAR_ORDER] START nonce=1\n"
            "[CND_CALENDAR_ORDER] COMPLETE nonce=1 ok=1 "
            'result={"ok":true,"action":"a"}\n'
        )
        self.assertEqual(
            experiment.parse_trigger_result(report),
            {"ok": True, "action": "a"},
        )
        with self.assertRaises(experiment.LabError):
            experiment.parse_trigger_result("incomplete")

    def test_source_has_no_recursive_view_or_search_activation(self) -> None:
        source = DRIVER.read_text(encoding="utf-8")
        self.assertNotIn("setActive:", source)
        self.assertNotIn("subviews", source)
        self.assertIn("targetPIDStable", source)
        self.assertIn("refusing to overwrite", source)
        self.assertIn('"directTargetDylib": True', source)
        self.assertIn('"cyanideProcessUsed": False', source)
        self.assertNotIn("DEFAULT_PROCESS_SUFFIX", source)

    def test_persistent_snapshot_covers_the_proven_calendar_matrix(self) -> None:
        ssh = Mock()
        responses = []
        for point_size, appearance in (
            (27, 0), (27, 1), (48, 0), (68, 0), (68, 1),
        ):
            responses.append(
                "CND_ICON_TRIGGER start digest=DIGEST description=x\n"
                "CND_ICON_TRIGGER complete image=0x1/IFCacheImage "
                f"uuid=UUID-{point_size}-{appearance} "
                f"data=4/{'a' * 64} token=4/{'b' * 64} "
                f"pixels={point_size * 3}x{point_size * 3} "
                f"rgba={'c' * 64} referenceRGBA=- pixelMatch=0\n"
            )
        ssh.command.side_effect = responses
        with patch.object(experiment, "build_trigger", return_value=DRIVER), \
             patch.object(
                 experiment,
                 "copy_executable",
                 return_value="/var/tmp/trigger",
             ):
            records, raw = experiment.persistent_calendar_snapshot(ssh)
        self.assertEqual(
            [record["descriptor"] for record in records],
            [
                "27x27@3:a0:v0:o0",
                "27x27@3:a1:v0:o0",
                "48x48@3:a0:v0:o0",
                "68x68@3:a0:v0:o0",
                "68x68@3:a1:v0:o0",
            ],
        )
        self.assertEqual(len(ssh.command.call_args_list), 5)
        self.assertIn("--- 68x68@3:a1:v0:o0 ---", raw)


if __name__ == "__main__":
    unittest.main()
