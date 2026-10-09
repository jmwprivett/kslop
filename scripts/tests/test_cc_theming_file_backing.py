"""Run the file transaction against local fixtures; never access a device."""

from pathlib import Path
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]


class CCFileBackingTests(unittest.TestCase):
    def test_file_backed_motion_packages_keep_their_authored_loops(self):
        low_power_path = ROOT / "Cyanide/PulsarControlCenter.bundle/LowPower.ca/main.caml"
        low_power_text = low_power_path.read_text(encoding="utf-8")
        low_power = ET.fromstring(low_power_text)
        low_power_loops = [
            animation for animation in low_power.iter()
            if animation.tag.endswith("}animation")
            if animation.get("type") == "CAKeyframeAnimation"
            and animation.get("repeatCount") == "Inf"
            and animation.get("duration") == "2"
        ]
        self.assertEqual(len(low_power_loops), 2)
        self.assertIn('src="pin_on1.png"', low_power_text)
        self.assertIn('src="pin_on2.png"', low_power_text)
        self.assertEqual(
            {state.get("name") for state in low_power.iter()
             if state.tag.endswith("}LKState")},
            {"enabled", "disabled"},
        )

        recognition_path = ROOT / "Cyanide/PulsarControlCenter.bundle/MusicRecognition.ca/main.caml"
        recognition = ET.parse(recognition_path).getroot()
        recognition_loops = [
            animation for animation in recognition.iter()
            if animation.tag.endswith("}animation")
            if animation.get("type") == "CAKeyframeAnimation"
            and animation.get("repeatCount") == "Inf"
            and animation.get("duration") == "1"
        ]
        self.assertEqual(
            {animation.get("keyPath") for animation in recognition_loops},
            {"opacity", "transform.scale.xy"},
        )
        self.assertEqual(
            {state.get("name") for state in recognition.iter()
             if state.tag.endswith("}LKState")},
            {"On", "Off"},
        )

    def test_manifest_covers_proven_routes_and_preserves_exceptions(self):
        manifest = json.loads((ROOT / "Cyanide/PulsarControlCenter.bundle/FileBacking.json").read_text())
        self.assertEqual(len(manifest["packageRoutes"]), 29)
        paths = [route["packagePath"] for route in manifest["packageRoutes"]]
        self.assertEqual(len(paths), len(set(paths)))
        for name in ("VolumeRTL.ca", "VolumeSemibold.ca", "VolumeSemiboldRTL.ca", "VolumeBold.ca",
                     "Mirroring_IC.ca", "MirroringLeading.ca", "Timer_IC.ca", "LowPower_IC.ca",
                     "Mute_IC.ca", "OrientationLock_IC.ca", "replaykit-v2_IC.ca"):
            self.assertTrue(any(path.endswith("/" + name) for path in paths), name)
        self.assertTrue(any(path.endswith("/ShazamModule.bundle/Shazam.ca") for path in paths))
        self.assertEqual(set(manifest["excludedKinds"]),
                         {"focusReduceInterruptions", "focusCustom", "hearing"})
        catalog = (ROOT / "Cyanide/installer/PackageCatalog.m").read_text()
        self.assertIn("durable queue and automatically respring", catalog)
        self.assertIn("The operation is file-backed only", catalog)
        self.assertIn("no live glyph adapter, view override, trace", catalog)
        backing = (ROOT / "Cyanide/tweaks/CNDCCThemingFileBacking.m").read_text()
        self.assertIn('@"qrCode", @"airPlay"', backing)
        for route in manifest["packageRoutes"]:
            if route["kind"] in ("sound", "display"):
                self.assertEqual(route["artworkColorContract"], "native-white-template-preserve-authored-opacity")
                self.assertEqual(route["staticStateContract"], "explicit-visible-Pulsar-artwork-at-every-native-level")

    def test_manifest_reproducible_from_artwork_and_stock(self):
        spec = importlib.util.spec_from_file_location("file_manifest", ROOT / "scripts/generate_cc_file_backing_manifest.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.manifest(module.DEFAULT_STOCK), json.loads(
            (ROOT / "Cyanide/PulsarControlCenter.bundle/FileBacking.json").read_text()))

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("xcrun"), "requires macOS Foundation")
    def test_native_resource_transactions_and_fault_recovery(self):
        with tempfile.TemporaryDirectory(prefix="cnd-cc-file-fixture-") as directory:
            binary = Path(directory) / "test-file-backing"
            compiled = subprocess.run([
                "xcrun", "clang", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra", "-Werror",
                "-Wno-deprecated-declarations", "-DCND_CC_FILE_BACKING_TESTING=1",
                "-framework", "Foundation", "-framework", "QuartzCore", "-framework", "CoreGraphics",
                str(ROOT / "Cyanide/tweaks/CNDCCThemingFileBacking.m"),
                str(ROOT / "scripts/tests/test_cc_theming_file_backing.m"), "-o", str(binary),
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            tested = subprocess.run([str(binary), str(ROOT), directory], capture_output=True, text=True, timeout=30)
            self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)
            self.assertIn("partial rollback", tested.stdout)

    def test_production_apply_only_changes_native_resource_files(self):
        settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()
        apply = settings.split("BOOL settings_apply_cc_theming_now(BOOL apply)", 1)[1].split(
            "\n#if 0", 1)[0]
        self.assertIn("CNDCCThemingFileBackingApply()", apply)
        self.assertIn("CNDCCThemingFileBackingRestore()", apply)
        for operation in ("CNDCCThemingApplyPulsarArtwork",
                          "CNDCCThemingPersistentInstallVerifiedRoutesInCurrentSession",
                          "settings_ensure_springboard_remote_call_locked", "r_autorelease_pool_push",
                          "settings_post_actions_complete_async", "PackageQueue"):
            self.assertNotIn(operation, apply)
        self.assertIn("return success;", apply)
        resource = (ROOT / "Cyanide/tweaks/CNDCCThemingFileBacking.m").read_text()
        for operation in ("object_setClass", "r_msg2", "remote_write", "kwrite", "subviews", "sendAction"):
            self.assertNotIn(operation, resource)
        self.assertIn("overwrite_system_file", resource)

    def test_queue_owned_apply_returns_failure_without_posting_ui_completion(self):
        settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()
        catalog = (ROOT / "Cyanide/installer/PackageCatalog.m").read_text()
        for message in ("Control Center may remain closed", "Control Center does not need to be open",
                        "Control Center need not be open", "Installation needs no open Control Center"):
            self.assertNotIn(message, settings)
            self.assertNotIn(message, catalog)
        runner = settings.split("BOOL settings_apply_cc_theming_now(BOOL apply)", 1)[1].split(
            "\n#if 0", 1)[0]
        self.assertIn('result[@"failureReason"]', runner)
        self.assertIn("settings_release_actions_lock();", runner)
        self.assertNotIn("settings_post_actions_complete_async", runner)


if __name__ == "__main__":
    unittest.main()
