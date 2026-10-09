"""Offline contracts for the additional official-Pulsar VM canary."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


LAB = Path(__file__).resolve().parents[1] / "lab"
sys.path.insert(0, str(LAB))
SCRIPT = LAB / "cnd_pulsar_additional_controls_canary.py"
SPEC = importlib.util.spec_from_file_location(
    "cnd_pulsar_additional_controls_canary", SCRIPT
)
assert SPEC and SPEC.loader
canary = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = canary
SPEC.loader.exec_module(canary)


class AdditionalControlsCanaryTests(unittest.TestCase):
    def test_port_caml_rewrites_only_to_nonce_scoped_staged_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "main.caml"
            source.write_text(
                '<contents src="/var/mobile/Documents/PhucDo/PhucDoUI/'
                'pin_off.png" />',
                encoding="utf-8",
            )
            remote = "/var/tmp/cyanide-pulsar-additional-controls-a1"
            result = canary.port_caml(source, remote)
            self.assertIn(remote + "/pin_off.png", result)
            self.assertNotIn(canary.UPSTREAM_IMAGE_ROOT, result)

    def test_port_caml_rejects_unstaged_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "main.caml"
            source.write_text(
                '<contents src="/var/mobile/Documents/PhucDo/PhucDoUI/'
                'unknown.png" />',
                encoding="utf-8",
            )
            with self.assertRaises(canary.LabError):
                canary.port_caml(
                    source,
                    "/var/tmp/cyanide-pulsar-additional-controls-a1",
                )

    def test_remote_directory_is_nonce_scoped(self) -> None:
        self.assertEqual(
            canary.validate_remote_directory(
                "/var/tmp/cyanide-pulsar-additional-controls-deadbeef"
            ),
            "/var/tmp/cyanide-pulsar-additional-controls-deadbeef",
        )
        with self.assertRaises(canary.LabError):
            canary.validate_remote_directory("/var/tmp")

    def test_build_has_inactive_presentation_safety_contract(self) -> None:
        source = canary.SOURCE.read_text(encoding="utf-8")
        self.assertIn('@"disabled"', source)
        self.assertIn("controlActions=0", source)
        self.assertIn("hardwareSpoof=0", source)
        self.assertIn("interaction=disabled", source)
        self.assertIn("CNDFindTemplateView", source)
        self.assertIn("gLowPowerTarget", source)
        self.assertIn("gReplayKitTarget", source)
        self.assertNotIn("handleTap", source)

    def test_load_assets_accepts_staged_official_manifest(self) -> None:
        assets = canary.load_assets()
        self.assertIn("low_power_motion_enabled.caml", assets)
        self.assertIn("replaykit.caml", assets)
        self.assertIn("FlashlightAssets.car", assets)
        self.assertEqual(set(canary.RAW_NAMES).issubset(assets), True)

    def test_build_rejects_negative_pid_before_tool_invocation(self) -> None:
        with mock.patch.object(canary, "run") as run:
            with self.assertRaises(canary.LabError):
                canary.build(expected_pid=-1)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
