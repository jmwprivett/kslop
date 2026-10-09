"""Offline contracts for the official-Pulsar connectivity canary."""

from __future__ import annotations

import importlib.util
import json
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


LAB_DIR = Path(__file__).resolve().parents[1] / "lab"
sys.path.insert(0, str(LAB_DIR))
SPEC = importlib.util.spec_from_file_location(
    "cnd_pulsar_connectivity_canary",
    LAB_DIR / "cnd_pulsar_connectivity_canary.py",
)
assert SPEC and SPEC.loader
canary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(canary)


class BuildTests(unittest.TestCase):
    def test_build_enables_canary_and_binds_asset_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(
            canary, "BUILD_DIR", Path(directory)
        ), patch.object(canary, "run") as run:
            output = canary.build(
                token="token",
                expected_pid=39,
                hold_seconds=45,
                theme_directory=(
                    "/var/tmp/cyanide-pulsar-connectivity-canary-a1"
                ),
            )
        command = run.call_args_list[0].args[0]
        self.assertEqual(output.name, "cnd_pulsar_connectivity_canary.dylib")
        self.assertIn("-DCND_PULSAR_CONNECTIVITY_CANARY=1", command)
        self.assertIn("-DCND_SYNTHETIC_CONNECTIVITY_EXPECTED_PID=39", command)
        self.assertTrue(any(
            "CND_PULSAR_THEME_DIRECTORY" in argument for argument in command
        ))
        self.assertEqual(run.call_args_list[1].args[0][:3],
                         ["codesign", "-s", "-"])

    def test_asset_manifest_enforces_provenance_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "raw").mkdir()
            (root / "catalog").mkdir()
            wifi = root / "raw/wifi_white.png"
            bluetooth = root / "raw/bluetooth_white.png"
            car = root / "catalog/Assets.car"
            wifi.write_bytes(b"wifi")
            bluetooth.write_bytes(b"bluetooth")
            car.write_bytes(b"car")
            manifest = {
                "package": {
                    "id": canary.EXPECTED_PACKAGE_ID,
                    "upstream_commit": canary.EXPECTED_UPSTREAM_COMMIT,
                    "upstream_archive_sha256": (
                        canary.EXPECTED_ARCHIVE_SHA256
                    ),
                },
                "raw_images": [
                    {"name": "wifi_white.png", "path": "raw/wifi_white.png",
                     "sha256": canary.file_sha256(wifi)},
                    {"name": "bluetooth_white.png",
                     "path": "raw/bluetooth_white.png",
                     "sha256": canary.file_sha256(bluetooth)},
                ],
                "connectivity_catalog": {
                    "path": "catalog/Assets.car",
                    "sha256": canary.file_sha256(car),
                    "renditions": [
                        {"Name": "AirplaneGlyph"},
                        {"Name": "CellularDataGlyph"},
                    ],
                },
            }
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            info = root / "Info.plist"
            info.write_text("plist")
            with patch.object(canary, "ASSET_ROOT", root), patch.object(
                canary, "MANIFEST", manifest_path
            ), patch.object(canary, "INFO_PLIST", info):
                assets = canary.load_assets()
            self.assertEqual(assets["Assets.car"], car.resolve())

    def test_source_restores_every_themed_controller(self) -> None:
        source = canary.SOURCE.read_text()
        for required in (
            "CND_PULSAR_CONNECTIVITY_CANARY",
            "CNDThemeCatalogImage(@\"AirplaneGlyph\")",
            "CNDThemeCatalogImage(@\"CellularDataGlyph\")",
            "CNDApplyThemeGlyph",
            "CNDRestoreThemeGlyph",
            "themeApplied=%d",
        ):
            self.assertIn(required, source)


class InjectionTests(unittest.TestCase):
    def test_injection_rechecks_exact_springboard_identity(self) -> None:
        ssh = MagicMock()
        command = canary.TARGETS["SpringBoard"]
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "canary.dylib"
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
                    "themeApplied=1 holdSeconds=45\n"
                ),
            ):
                pid, remote, assets, _ = canary.inject(ssh, 45)
        self.assertEqual(pid, 39)
        self.assertTrue(remote.startswith(
            "/var/tmp/cnd-pulsar-connectivity-canary-"
        ))
        self.assertRegex(assets, canary.REMOTE_PATTERN)
        command_text = ssh.command.call_args_list[-1].args[0]
        self.assertIn(f'test "$current" != {shlex.quote(command)}', command_text)
        self.assertIn("/iosbinpack64/bin/opainject 39", command_text)


if __name__ == "__main__":
    unittest.main()
