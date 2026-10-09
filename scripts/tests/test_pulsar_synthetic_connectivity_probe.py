"""Offline contracts for the VM-only synthetic connectivity probe."""

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
    "cnd_pulsar_synthetic_connectivity_probe",
    LAB_DIR / "cnd_pulsar_synthetic_connectivity_probe.py",
)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class BuildTests(unittest.TestCase):
    def test_build_is_arm64e_bounded_and_pid_locked(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "BUILD_DIR", Path(directory)), \
                patch.object(probe, "run") as run:
            output = probe.build(
                token="token",
                expected_pid=39,
                hold_seconds=45,
                asset_directory=(
                    "/var/tmp/cyanide-pulsar-synthetic-connectivity-abc123"
                ),
            )
        command = run.call_args_list[0].args[0]
        self.assertEqual(
            output.name, "cnd_pulsar_synthetic_connectivity_probe.dylib"
        )
        self.assertIn("arm64e", command)
        self.assertIn("-Werror", command)
        self.assertIn("-DCND_SYNTHETIC_CONNECTIVITY_EXPECTED_PID=39", command)
        self.assertIn("-DCND_SYNTHETIC_CONNECTIVITY_HOLD_SECONDS=45", command)
        self.assertEqual(run.call_args_list[1].args[0][:3],
                         ["codesign", "-s", "-"])

    def test_duration_and_asset_directory_are_bounded(self) -> None:
        for duration in (14, 181):
            with self.subTest(duration=duration), self.assertRaises(
                probe.LabError
            ):
                probe.build(hold_seconds=duration)
        with self.assertRaisesRegex(probe.LabError, "unsafe asset directory"):
            probe.build(asset_directory="/var/mobile")

    def test_source_uses_ui_only_routes_and_restores(self) -> None:
        source = probe.SOURCE.read_text()
        for required in (
            "CCUIConnectivityCellularDataViewController",
            "_glyphImageForDisplayBars:",
            "_glyphImageForState:",
            "_updateWithState:",
            "setCellularDataButtonViewController:",
            "setExpandedCellularDataButtonViewController:",
            "CNDRestore",
            "noRadioSpoof=1",
            "userInteractionEnabled = NO",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "#import <CoreTelephony", "dlopen(\"/System/Library/PrivateFrameworks/CoreTelephony",
            "CommCenter.framework", "BluetoothManager.framework",
            "setRadio", "setCellularDataEnabled", "object_setIvar",
        ):
            self.assertNotIn(forbidden, source)


class CaptureTests(unittest.TestCase):
    def test_asset_capture_validates_remote_names_and_png(self) -> None:
        ssh = MagicMock()
        directory = "/var/tmp/cyanide-pulsar-synthetic-connectivity-abc123"
        remote = f"{directory}/cellular-4-{'a' * 64}.png"
        ssh.command.return_value = remote + "\n"
        ssh.read_file.return_value = b"\x89PNG\r\n\x1a\nfixture"
        with tempfile.TemporaryDirectory() as local, patch.object(
            probe, "LOCAL_ASSET_DIR", Path(local)
        ):
            paths = probe.capture_assets(ssh, directory)
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0].read_bytes(), ssh.read_file.return_value)
            self.assertEqual(paths[0].stat().st_mode & 0o777, 0o600)

    def test_asset_capture_rejects_wrong_parent(self) -> None:
        ssh = MagicMock()
        directory = "/var/tmp/cyanide-pulsar-synthetic-connectivity-abc123"
        ssh.command.return_value = f"/var/tmp/cellular-4-{'a' * 64}.png\n"
        with self.assertRaisesRegex(probe.LabError, "unexpected probe asset"):
            probe.capture_assets(ssh, directory)


class InjectionTests(unittest.TestCase):
    def test_injection_rechecks_exact_springboard_identity(self) -> None:
        ssh = MagicMock()
        command = probe.TARGETS["SpringBoard"]
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "probe.dylib"
            payload.write_bytes(b"fixture")
            with patch.object(
                probe, "resolve_target",
                side_effect=[(39, command), (39, command)],
            ), patch.object(
                probe, "issue_file_extension", return_value="token"
            ), patch.object(
                probe, "build", return_value=payload
            ), patch.object(
                probe, "read_report",
                return_value=(
                    "[CND_SYNTHETIC_CONNECTIVITY] VISIBLE_READY pid=39\n"
                ),
            ):
                pid, remote, assets, _ = probe.inject(ssh, 45)
        self.assertEqual(pid, 39)
        self.assertTrue(remote.startswith(
            "/var/tmp/cnd-pulsar-synthetic-connectivity-"
        ))
        self.assertTrue(assets.startswith(
            "/var/tmp/cyanide-pulsar-synthetic-connectivity-"
        ))
        command_text = ssh.command.call_args_list[-1].args[0]
        self.assertIn(f'test "$current" != {shlex.quote(command)}', command_text)
        self.assertIn("/iosbinpack64/bin/opainject 39", command_text)

    def test_changed_pid_is_rejected_before_opainject(self) -> None:
        ssh = MagicMock()
        command = probe.TARGETS["SpringBoard"]
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "probe.dylib"
            payload.write_bytes(b"fixture")
            with patch.object(
                probe, "resolve_target",
                side_effect=[(39, command), (40, command)],
            ), patch.object(
                probe, "issue_file_extension", return_value="token"
            ), patch.object(probe, "build", return_value=payload):
                with self.assertRaisesRegex(probe.LabError, "identity changed"):
                    probe.inject(ssh, 45)
        self.assertFalse(any(
            "opainject" in call.args[0] for call in ssh.command.call_args_list
        ))


if __name__ == "__main__":
    unittest.main()
