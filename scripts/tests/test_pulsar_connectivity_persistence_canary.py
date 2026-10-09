"""Offline contracts for the event-driven connectivity persistence canary."""

from pathlib import Path
import importlib.util
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
LAB_DIR = ROOT / "scripts/lab"
SCRIPT = ROOT / "scripts/lab/cnd_pulsar_connectivity_persistence_canary.py"
SOURCE = ROOT / "scripts/lab/cnd_pulsar_connectivity_persistence_canary.m"
sys.path.insert(0, str(LAB_DIR))


def load_script():
    spec = importlib.util.spec_from_file_location(
        "cnd_pulsar_connectivity_persistence_canary", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class PulsarConnectivityPersistenceCanaryTests(unittest.TestCase):
    def test_uses_stable_delivery_hooks_and_exact_abis(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        for selector in (
            "setGlyphImage:", "setSelectedGlyphImage:", "setEnabled:"
        ):
            self.assertIn(selector, source)
        self.assertIn('"v24@0:8@16"', source)
        self.assertIn('"v20@0:8B16"', source)
        self.assertIn("method_setImplementation", source)
        self.assertIn("method_getImplementation", source)
        self.assertIn("objectReadback=%d", source)

    def test_never_invokes_a_control_or_radio_action(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        for forbidden in (
            "sendAction", "buttonTapped", "toggleState", "setTorchMode",
            "setAirplaneMode", "setBluetoothEnabled", "setWiFiEnabled",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("controlActions=0 radioWrites=0 targetFileWrites=0", source)

    def test_driver_exercises_full_control_center_lifecycle(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        for phase in (
            "initial-compact", "closed", "reopened", "expanded",
            "collapsed", "closed-again", "reopened-again",
        ):
            self.assertIn(f'"{phase}"', script)
        self.assertIn("no fully themed connectivity verification", script)

    def test_generated_assets_cover_every_pulsar_connectivity_kind(self) -> None:
        module = load_script()
        assets = module.validate_assets()
        self.assertEqual(len(assets), 12)
        self.assertEqual(
            set(assets),
            {
                f"{kind}-{state}.png"
                for kind in (
                    "wifi", "bluetooth", "airdrop", "airplane",
                    "cellular", "hotspot",
                )
                for state in ("standard", "selected")
            },
        )

    def test_lifecycle_validator_requires_post_reopen_theme_and_restore(self) -> None:
        module = load_script()
        report = "\n".join([
            "phase=closed", "phase=reopened", "phase=expanded",
            "phase=collapsed", "phase=closed-again", "phase=reopened-again",
            "VERIFY tag=tick-9 found=5 themed=5",
            " RESTORED methods=1 objects=5 objectReadback=1",
            " COMPLETE status=success ",
        ])
        module.validate_lifecycle_report(report)


if __name__ == "__main__":
    unittest.main()
