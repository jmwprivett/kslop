"""Offline contracts for the vPhone Control Center configuration helper."""

from __future__ import annotations

import importlib.util
import plistlib
import sys
import unittest
from pathlib import Path


LAB_DIR = Path(__file__).resolve().parents[1] / "lab"
sys.path.insert(0, str(LAB_DIR))
SPEC = importlib.util.spec_from_file_location(
    "cnd_vm_controlcenter_config",
    LAB_DIR / "cnd_vm_controlcenter_config.py",
)
assert SPEC and SPEC.loader
config = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = config
SPEC.loader.exec_module(config)


def fixture_icon_state() -> dict[str, object]:
    return {
        "displayName": "Control Center Root",
        "iconLists": [[{
            "displayIdentifier": "EXISTING-DISPLAY",
            "elements": [{
                "containerBundleIdentifier": "com.apple.springboard",
                "dataSourceUniqueIdentifier": "EXISTING-DATA-SOURCE",
                "elementType": "module",
                "moduleIdentifier": "com.apple.control-center.ConnectivityModule",
            }],
            "gridSize": "medium",
            "iconType": "custom",
        }]],
        "listMetadata": {
            "PRIMARY-LIST": {"rotatedOrder": ["EXISTING-DISPLAY"]},
        },
        "listUniqueIdentifiers": ["PRIMARY-LIST"],
        "uniqueIdentifier": "control-center-root",
        "widgetVersion": 1000,
    }


class MutationTests(unittest.TestCase):
    def test_adds_three_modules_to_primary_page_and_rotated_order(self) -> None:
        original = fixture_icon_state()
        result, added = config.add_controls_to_icon_state(original)
        self.assertEqual(tuple(spec.label for spec in added), (
            "Low Power Mode", "Screen Recording", "Flashlight",
        ))
        self.assertEqual(len(result["iconLists"][0]), 4)
        self.assertEqual(
            len(result["listMetadata"]["PRIMARY-LIST"]["rotatedOrder"]),
            4,
        )
        self.assertEqual(
            config.module_identifiers(result),
            {"com.apple.control-center.ConnectivityModule", *(
                spec.module_identifier for spec in config.CONTROL_SPECS
            )},
        )
        self.assertEqual(len(original["iconLists"][0]), 1)

    def test_mutation_is_idempotent_and_identifiers_are_stable(self) -> None:
        first, added_first = config.add_controls_to_icon_state(fixture_icon_state())
        second, added_second = config.add_controls_to_icon_state(first)
        self.assertEqual(len(added_first), 3)
        self.assertEqual(added_second, ())
        self.assertEqual(first, second)
        display_ids = [item["displayIdentifier"] for item in first["iconLists"][0][1:]]
        self.assertEqual(len(display_ids), len(set(display_ids)))

    def test_updates_legacy_module_registration_without_duplicates(self) -> None:
        original = {
            "module-identifiers": ["com.apple.control-center.FlashlightModule"],
            "disabled-module-identifiers": [],
            "userenabled-fixed-module-identifiers": [],
            "version": 3,
        }
        first = config.add_controls_to_module_configuration(original)
        second = config.add_controls_to_module_configuration(first)
        self.assertEqual(first, second)
        for spec in config.CONTROL_SPECS:
            self.assertEqual(first["module-identifiers"].count(spec.module_identifier), 1)
        self.assertEqual(original["module-identifiers"], [
            "com.apple.control-center.FlashlightModule",
        ])

    def test_binary_plist_round_trip(self) -> None:
        value, _ = config.add_controls_to_icon_state(fixture_icon_state())
        encoded = config.dump_plist(value)
        self.assertEqual(encoded[:8], b"bplist00")
        self.assertEqual(plistlib.loads(encoded), value)


class SafetyTests(unittest.TestCase):
    def test_only_exact_managed_paths_can_be_staged_or_backed_up(self) -> None:
        for path in config.MANAGED_PATHS:
            self.assertTrue(config.backup_path(path, "20261004T221600Z").startswith(path))
            self.assertTrue(config.staged_path(path, "a" * 16).startswith(
                config.CONTROL_CENTER_DIR + "/.cyanide-"
            ))
        with self.assertRaises(config.LabError):
            config.backup_path("/var/mobile/Library/Preferences/evil.plist", "20261004T221600Z")
        with self.assertRaises(config.LabError):
            config.staged_path(config.ICON_STATE_PATH, "../escape")

    def test_control_specs_use_installed_bundle_identifiers(self) -> None:
        self.assertEqual(
            tuple(spec.module_identifier for spec in config.CONTROL_SPECS),
            (
                "com.apple.control-center.LowPowerModule",
                "com.apple.replaykit.controlcenter.screencapture",
                "com.apple.control-center.FlashlightModule",
            ),
        )
        self.assertEqual(config.PERSISTENT_CONTROL_SPECS, config.CONTROL_SPECS[:2])
        self.assertEqual(config.DEVICE_GATED_CONTROL_SPECS, config.CONTROL_SPECS[2:])


if __name__ == "__main__":
    unittest.main()
