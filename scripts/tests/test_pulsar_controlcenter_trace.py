"""Offline contracts for the Pulsar Control Center route tracer."""

from __future__ import annotations

import importlib.util
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


LAB_DIR = Path(__file__).resolve().parents[1] / "lab"
sys.path.insert(0, str(LAB_DIR))
SPEC = importlib.util.spec_from_file_location(
    "cnd_pulsar_controlcenter_trace",
    LAB_DIR / "cnd_pulsar_controlcenter_trace.py",
)
assert SPEC and SPEC.loader
trace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trace)


class BuildTests(unittest.TestCase):
    def test_build_is_arm64e_bounded_and_warning_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(trace, "BUILD_DIR", Path(directory)), \
                patch.object(trace, "run") as run:
            output = trace.build(duration=240)
        command = run.call_args_list[0].args[0]
        self.assertEqual(output.name, "cnd_pulsar_controlcenter_trace.dylib")
        self.assertIn("arm64e", command)
        self.assertIn("-Werror", command)
        self.assertIn("-fobjc-arc", command)
        self.assertIn("-DCND_PULSAR_TRACE_DURATION=240", command)
        self.assertEqual(run.call_args_list[1].args[0][:3],
                         ["codesign", "-s", "-"])

    def test_duration_is_bounded(self) -> None:
        for duration in (29, 601):
            with self.subTest(duration=duration), self.assertRaises(trace.LabError):
                trace.build(duration=duration)

    def test_connectivity_build_uses_isolated_report_and_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(trace, "BUILD_DIR", Path(directory)), \
                patch.object(trace, "run") as run:
            output = trace.build(duration=180, focus="connectivity")
        command = run.call_args_list[0].args[0]
        self.assertEqual(output.name, "cnd_pulsar_connectivity_trace.dylib")
        self.assertIn("-DCND_PULSAR_TRACE_CONNECTIVITY=1", command)
        self.assertIn(
            f'-DCND_PULSAR_TRACE_REPORT_PATH="{trace.CONNECTIVITY_REPORT}"',
            command,
        )

    def test_source_targets_pulsar_delivery_routes(self) -> None:
        source = trace.SOURCE.read_text()
        for token in (
            "packageWithContentsOfURL:type:options:error:",
            "imageNamed:inBundle:",
            "systemImageNamed:",
            "descriptionForPackageNamed:inBundle:",
            "setGlyphImage:",
            "setGlyphPackageDescription:",
            "CCUIControlHostViewController",
            "CCUIControlIconElement",
            "MediaControlsRuntimeClass",
            "MediaControlsModule",
            "Mirroring",
            "CNDMediaHookSelectorName",
        ):
            self.assertIn(token, source)
        self.assertIn("CNDEventCap = 12000", source)
        self.assertIn("CND_PULSAR_TRACE_DURATION", source)
        self.assertIn("CONNECTIVITY_IMAGE", source)
        self.assertIn("CONNECTIVITY_STACK", source)
        self.assertIn("CC_SHA256", source)
        self.assertIn("class_getImageName", source)
        self.assertIn("/var/tmp/cyanide-pulsar-connectivity-assets", source)

    def test_probe_has_no_system_file_mutation_primitive(self) -> None:
        source = trace.SOURCE.read_text()
        for forbidden in (
            "overwrite_system_file", "rename(", "unlink(", "removeItemAtPath",
            "writeToFile", "setObject:forKey:", "object_setIvar",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("method_setImplementation", source)
        self.assertIn("mode=ephemeral-observation", source)
        self.assertIn("noSystemWrite=1", source)


class SummaryTests(unittest.TestCase):
    def test_summary_reports_routes_and_legacy_correlations(self) -> None:
        report = "\n".join((
            "[CND_PULSAR]\tTRACE_READY\tpid=39\thooks=9\tduration=180",
            "[CND_PULSAR]\tHOOK\tclass=CAPackage\tselector=packageWithContentsOfURL:type:options:error:",
            "[CND_PULSAR]\\tMARK\\tlabel=open-control-center",
            "[CND_PULSAR]\tCONTROLLER\ttick=1\tclass=CCUIContentModuleContainerViewController\tidentity=moduleIdentifier=com.apple.control-center.DisplayModule",
            "[CND_PULSAR]\tEVENT\tseq=1\troute=package-load\ta0=/System/Library/ControlCenter/Bundles/LowPowerModule.bundle/LowPower.ca/main.caml",
            "[CND_PULSAR]\tEVENT\tseq=2\troute=asset-lookup\ta0=CalculatorModule\ta1=com.apple.control-center.CalculatorModule",
            "[CND_PULSAR]\tTRACE_COMPLETE\tpid=39\tevents=2",
        ))
        summary = trace.summarize(report)
        self.assertIn("ready=true complete=true hooks=1 events=2", summary)
        self.assertIn("route package-load: 1", summary)
        self.assertIn("CalculatorModule", summary)
        self.assertIn("LowPowerModule/LowPower.ca", summary)
        self.assertIn("controller-classes=1 module-identifiers=1 markers=1",
                      summary)
        self.assertIn("com.apple.control-center.DisplayModule", summary)
        self.assertIn("open-control-center", summary)

    def test_mark_writes_structured_tabs(self) -> None:
        ssh = MagicMock()
        trace.mark(ssh, "open control center")
        command = ssh.command.call_args.args[0]
        self.assertIn("[CND_PULSAR]\tMARK\tlabel=open-control-center", command)
        self.assertNotIn(r"[CND_PULSAR]\tMARK", command)

    def test_summary_reports_connectivity_fingerprints_and_states(self) -> None:
        report = "\n".join((
            "[CND_PULSAR]\tTRACE_READY\tpid=39\thooks=12",
            "[CND_PULSAR]\tCONNECTIVITY_IMAGE\tevent=3\towner=0x1/CCUIWiFiModuleViewController\tscalars=isSelected=1\tpoints=27.67x21.00\tpixels=73x53\tsha256=abc123",
            "[CND_PULSAR]\tCONNECTIVITY_STATE\tevent=2\towner=0x1/CCUIWiFiModuleViewController\tselector=setSelected:\tvalue=1",
            "[CND_PULSAR]\tTRACE_COMPLETE\tpid=39\tevents=0",
        ))
        summary = trace.summarize(report)
        self.assertIn("connectivity images: 1 unique fingerprints", summary)
        self.assertIn("CCUIWiFiModuleViewController", summary)
        self.assertIn("sha256=abc123", summary)
        self.assertIn("setSelected:=1 (1)", summary)


class CaptureTests(unittest.TestCase):
    def test_capture_is_atomic_and_private(self) -> None:
        ssh = MagicMock()
        data = b"[CND_PULSAR]\tSTART\tpid=39\npartial:\xff\x00\n"
        ssh.read_file.return_value = data
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(trace, "LOCAL_REPORT", Path(directory) / "trace.log"):
            path = trace.capture_report(ssh)
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        ssh.read_file.assert_called_once_with(trace.REPORT)

    def test_connectivity_assets_are_validated_and_private(self) -> None:
        ssh = MagicMock()
        remote = (
            f"{trace.CONNECTIVITY_ASSET_REMOTE_DIR}/"
            "CCUIWiFiModuleViewController-abc.png"
        )
        ssh.command.return_value = remote + "\n"
        ssh.read_file.return_value = b"\x89PNG\r\n\x1a\nfixture"
        with tempfile.TemporaryDirectory() as directory, patch.object(
            trace, "CONNECTIVITY_LOCAL_ASSET_DIR", Path(directory)
        ):
            paths = trace.capture_connectivity_assets(ssh)
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0].read_bytes(), ssh.read_file.return_value)
            self.assertEqual(paths[0].stat().st_mode & 0o777, 0o600)

    def test_connectivity_asset_rejects_unexpected_path(self) -> None:
        ssh = MagicMock()
        ssh.command.return_value = "/var/tmp/not-the-export/asset.png\n"
        with tempfile.TemporaryDirectory() as directory, patch.object(
            trace, "CONNECTIVITY_LOCAL_ASSET_DIR", Path(directory)
        ), self.assertRaisesRegex(trace.LabError, "unexpected connectivity"):
            trace.capture_connectivity_assets(ssh)


class InjectionSafetyTests(unittest.TestCase):
    def test_injection_rechecks_exact_springboard_identity(self) -> None:
        ssh = MagicMock()
        command = trace.TARGETS["SpringBoard"]
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "trace.dylib"
            payload.write_bytes(b"fixture")
            with patch.object(trace, "resolve_target",
                              side_effect=[(39, command), (39, command)]), \
                    patch.object(trace, "issue_file_extension",
                                 return_value="token"), \
                    patch.object(trace, "build", return_value=payload), \
                    patch.object(trace, "read_report", return_value=(
                        "[CND_PULSAR]\tTRACE_READY\tpid=39\thooks=8\t"
                        "duration=180\n")):
                pid, remote, _ = trace.inject(ssh, 180)
        self.assertEqual(pid, 39)
        self.assertTrue(remote.startswith(
            "/var/tmp/cnd-pulsar-controlcenter-trace-"))
        command_text = ssh.command.call_args_list[-1].args[0]
        self.assertIn(f'test "$current" != {shlex.quote(command)}', command_text)
        self.assertIn("/iosbinpack64/bin/opainject 39", command_text)
        self.assertIn(trace.INJECT_LOG, command_text)

    def test_changed_pid_is_rejected_before_opainject(self) -> None:
        ssh = MagicMock()
        command = trace.TARGETS["SpringBoard"]
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "trace.dylib"
            payload.write_bytes(b"fixture")
            with patch.object(trace, "resolve_target",
                              side_effect=[(39, command), (40, command)]), \
                    patch.object(trace, "issue_file_extension",
                                 return_value="token"), \
                    patch.object(trace, "build", return_value=payload):
                with self.assertRaisesRegex(trace.LabError, "identity changed"):
                    trace.inject(ssh, 180)
        self.assertFalse(any(
            "opainject" in call.args[0] for call in ssh.command.call_args_list
        ))


if __name__ == "__main__":
    unittest.main()
