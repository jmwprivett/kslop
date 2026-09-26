import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))
import cnd_home_return_trace as trace
from cnd_remotecall_lab import LabError


class HomeReturnTraceTests(unittest.TestCase):
    def test_build_requires_one_explicit_bundle_and_warns_on_bad_input(self) -> None:
        for bundle in ("", "*", "com.example.app;touch /tmp/x", "a" * 201):
            with self.subTest(bundle=bundle), self.assertRaises(LabError):
                trace.build(bundle)

    def test_build_uses_werror_and_exact_bundle(self) -> None:
        with patch.object(trace, "run") as run:
            trace.build("com.example.app")
        command = run.call_args_list[0].args[0]
        self.assertIn("-Werror", command)
        self.assertIn('-DCND_HOME_BUNDLE="com.example.app"', command)
        self.assertEqual(command[command.index("-arch") + 1], "arm64e")

    def test_mark_requires_ready_report_and_allowlisted_label(self) -> None:
        ssh = Mock()
        with self.assertRaises(LabError):
            trace.mark(ssh, "unexpected")
        ssh.command.assert_not_called()
        with patch.object(trace, "read", return_value="[CND_HOME] TRACE_READY"):
            trace.mark(ssh, "return-home")
        command = ssh.command.call_args.args[0]
        self.assertEqual(
            command,
            "printf '%s\\n' '[CND_HOME] MARK return-home' "
            ">> /var/tmp/cyanide-home-return-trace.log",
        )
        self.assertNotIn("/iosbinpack64/bin/printf", command)

    def test_probe_stays_bounded_to_target_objects(self) -> None:
        source = trace.SOURCE.read_text(encoding="utf-8")
        self.assertIn("CNDHomeTarget(CNDHomeViewIcon(self))", source)
        self.assertIn("CNDHomeTarget(icon)", source)
        self.assertIn("depth > 2U", source)
        self.assertIn("MIN(layer.sublayers.count, 8U)", source)
        self.assertIn("event-cap=2500", source)
        self.assertNotIn("sharedApplication", source)
        self.assertNotIn("view.subviews", source)


if __name__ == "__main__":
    unittest.main()
