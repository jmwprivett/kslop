"""Offline contracts for the extended Pulsar connectivity VM canary."""

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
    "cnd_pulsar_extended_connectivity_canary",
    LAB_DIR / "cnd_pulsar_extended_connectivity_canary.py",
)
assert SPEC and SPEC.loader
canary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(canary)


class PortTests(unittest.TestCase):
    def test_port_caml_uses_only_nonce_scoped_staged_images(self) -> None:
        remote = "/var/tmp/cyanide-pulsar-extended-connectivity-a1"
        fixture = (
            '<contents src="/var/mobile/Documents/PhucDo/PhucDoUI/'
            'wifi_white1.png"/>\n'
            '<contents src="/var/mobile/Documents/PhucDo/PhucDoUI/'
            'wifi_white2.png"/>\n'
            '<contents src="/var/mobile/Documents/PhucDo/PhucDoUI/'
            'wifi.png"/>\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "main.caml"
            source.write_text(fixture)
            result = canary.port_caml(source, remote, "wifi")
        self.assertNotIn("/var/mobile/Documents", result)
        self.assertIn(remote + "/wifi_white.png", result)
        self.assertIn(remote + "/wifi_white1.png", result)
        self.assertIn(remote + "/wifi_white2.png", result)

    def test_port_caml_rejects_unscoped_remote_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "main.caml"
            source.write_text("fixture")
            with self.assertRaises(canary.LabError):
                canary.port_caml(source, "/var/tmp/not-scoped", "wifi")


class BuildTests(unittest.TestCase):
    def test_build_enables_extended_mode_and_quartzcore(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(
            canary, "BUILD_DIR", Path(directory)
        ), patch.object(canary, "run") as run:
            output = canary.build(
                token="token", expected_pid=39, hold_seconds=45,
                theme_directory=(
                    "/var/tmp/cyanide-pulsar-extended-connectivity-a1"
                ),
            )
        command = run.call_args_list[0].args[0]
        self.assertEqual(
            output.name, "cnd_pulsar_extended_connectivity_canary.dylib"
        )
        self.assertIn("-DCND_PULSAR_CONNECTIVITY_CANARY=1", command)
        self.assertIn(
            "-DCND_PULSAR_EXTENDED_CONNECTIVITY_CANARY=1", command
        )
        self.assertIn("QuartzCore", command)
        self.assertIn("-DCND_SYNTHETIC_CONNECTIVITY_EXPECTED_PID=39", command)

    def test_stage_wraps_legacy_caml_entry_point_for_ios26(self) -> None:
        source = Path(canary.__file__).read_text()
        index = canary.MOTION_PACKAGE_INDEX.read_text()
        self.assertIn('package + "/index.xml"', source)
        self.assertIn('package + "/main.caml"', source)
        self.assertIn("<string>main.caml</string>", index)
        self.assertIn("<key>rootDocument</key>", index)

    def test_source_has_static_motion_and_restoration_contracts(self) -> None:
        source = canary.SOURCE.read_text()
        for required in (
            'CNDThemeCatalogImage(@"AirDropGlyph")',
            'CNDThemeCatalogImage(@"HotspotGlyph")',
            "packageWithContentsOfURL:type:options:error:",
            'CNDApplyMotionDescription(',
            'CNDRestoreMotionDescription(',
            "SOURCE_GAP vpn=1 satellite=1",
            "startObservingStateChangesIfNecessary",
            "presentationHost=CCUIConnectivityCellularDataViewController",
        ):
            self.assertIn(required, source)


class InjectionTests(unittest.TestCase):
    def test_injection_rechecks_exact_springboard_identity(self) -> None:
        ssh = MagicMock()
        command = canary.TARGETS["SpringBoard"]
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "extended.dylib"
            payload.write_bytes(b"fixture")
            with patch.object(
                canary, "resolve_target",
                side_effect=[(39, command), (39, command)],
            ), patch.object(
                canary, "issue_file_extension", return_value="token"
            ), patch.object(
                canary, "build", return_value=payload
            ), patch.object(canary, "stage_assets"), patch.object(
                canary, "read_report",
                return_value=(
                    "[CND_SYNTHETIC_CONNECTIVITY] VISIBLE_READY pid=39 "
                    "themeApplied=1 extended=1 holdSeconds=45\n"
                ),
            ):
                pid, remote, assets, _ = canary.inject(ssh, 45)
        self.assertEqual(pid, 39)
        self.assertTrue(remote.startswith(
            "/var/tmp/cnd-pulsar-extended-connectivity-"
        ))
        self.assertRegex(assets, canary.REMOTE_PATTERN)
        command_text = ssh.command.call_args_list[-1].args[0]
        self.assertIn(f'test "$current" != {shlex.quote(command)}', command_text)
        self.assertIn("/iosbinpack64/bin/opainject 39", command_text)


if __name__ == "__main__":
    unittest.main()
