"""Offline safety contracts for the VM synthetic Flashlight control."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch


LAB_DIR = Path(__file__).resolve().parents[1] / "lab"
sys.path.insert(0, str(LAB_DIR))
SPEC = importlib.util.spec_from_file_location(
    "cnd_vm_flashlight_control_probe",
    LAB_DIR / "cnd_vm_flashlight_control_probe.py",
)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class BuildTests(unittest.TestCase):
    def test_build_is_arm64e_bounded_and_warning_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "BUILD_DIR", Path(directory)), \
                patch.object(probe, "run") as run:
            output = probe.build(expected_pid=3136, hold_seconds=180)
        command = run.call_args_list[0].args[0]
        self.assertEqual(output.name, "cnd_vm_flashlight_control_probe.dylib")
        for token in (
            "arm64e", "-fobjc-arc", "-Werror",
            "-DCND_VM_FLASHLIGHT_EXPECTED_PID=3136",
            "-DCND_VM_FLASHLIGHT_HOLD_SECONDS=180",
        ):
            self.assertIn(token, command)
        self.assertEqual(run.call_args_list[1].args[0][:3],
                         ["codesign", "-s", "-"])

    def test_hold_duration_is_bounded(self) -> None:
        for seconds in (29, 601):
            with self.subTest(seconds=seconds), self.assertRaises(probe.LabError):
                probe.validate_hold_seconds(seconds)

    def test_source_is_noninteractive_and_auto_restoring(self) -> None:
        source = probe.SOURCE.read_text(encoding="utf-8")
        for token in (
            "CCUIButtonModuleViewController",
            "com.cyanide.vm.synthetic.flashlight",
            "mount.userInteractionEnabled = NO",
            "UIBlurEffectStyleSystemUltraThinMaterialDark",
            "CNDTargetFrame",
            "CNDRestore",
            "hardwareSpoof=0",
            "noSystemWrite=1",
        ):
            self.assertIn(token, source)
        for forbidden in (
            "AVCaptureDevice", "setTorchMode", "UIRequiredDeviceCapabilities",
            "writeToFile", "removeItemAtPath",
        ):
            self.assertNotIn(forbidden, source)


class CaptureTests(unittest.TestCase):
    def test_capture_is_atomic_and_private(self) -> None:
        ssh = MagicMock()
        data = b"[CND_VM_FLASHLIGHT] COMPLETE status=success\n"
        ssh.read_file.return_value = data
        with tempfile.TemporaryDirectory() as directory, patch.object(
            probe, "LOCAL_REPORT", Path(directory) / "report.log"
        ):
            path = probe.capture_report(ssh)
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        ssh.read_file.assert_called_once_with(probe.REPORT)


if __name__ == "__main__":
    unittest.main()
