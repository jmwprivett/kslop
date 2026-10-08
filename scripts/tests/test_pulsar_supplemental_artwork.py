"""Validate supplemental import boundaries, state preservation and routing scope."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


IMPORTER = load_script("import_pulsar_supplemental_artwork")
GENERATOR = load_script("generate_pulsar_controlcenter_artwork")


class PulsarSupplementalArtworkTests(unittest.TestCase):
    def test_import_rejects_unsafe_members_before_writing_any_image(self):
        png = (GENERATOR.SUPPLEMENTAL / "vpn_stock.png").read_bytes()
        for bad_name in ("../escape.png", "/absolute.png", "folder/inner.png", "folder\\escape.png"):
            with self.subTest(name=bad_name), tempfile.TemporaryDirectory() as directory:
                archive, output = Path(directory) / "input.zip", Path(directory) / "out"
                with zipfile.ZipFile(archive, "w") as source:
                    source.writestr("valid.png", png)
                    source.writestr(bad_name, png)
                with self.assertRaises(ValueError):
                    IMPORTER.import_archive(archive, output)
                self.assertFalse(output.exists())

    def test_import_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "input.zip"
            with zipfile.ZipFile(archive, "w") as source:
                link = zipfile.ZipInfo("symlink.png")
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                source.writestr(link, "outside.png")
            with self.assertRaises(ValueError):
                IMPORTER.inventory_archive(archive)

    def test_import_preserves_submitted_images_and_unrelated_assets(self):
        original = (GENERATOR.SUPPLEMENTAL / "focus_sleep_active.png").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            archive, output = Path(directory) / "input.zip", Path(directory) / "out"
            output.mkdir()
            (output / "unrelated.png").write_bytes(b"untouched")
            with zipfile.ZipFile(archive, "w") as source:
                source.writestr("focus_sleep_active.png", original)
            manifest = IMPORTER.import_archive(archive, output)
            self.assertEqual((output / "focus_sleep_active.png").read_bytes(), original)
            self.assertEqual((output / "unrelated.png").read_bytes(), b"untouched")
            self.assertEqual(manifest["assets"][0]["width"], 100)
            self.assertEqual(manifest["artworkRole"], "supplemental")

    def test_reimport_preserves_separate_sources_and_validates_retained_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, output = Path(directory) / "input.zip", Path(directory) / "out"
            output.mkdir()
            existing = json.loads((GENERATOR.SUPPLEMENTAL / "source-manifest.json").read_text())
            for record in existing["assets"]:
                name = record["filename"]
                (output / name).write_bytes((GENERATOR.SUPPLEMENTAL / name).read_bytes())
            manifest_path = output / "source-manifest.json"
            manifest_path.write_text(json.dumps(existing))
            with zipfile.ZipFile(archive, "w") as source:
                for record in existing["assets"]:
                    if record["filename"] not in ("nightshift.png", "truetone.png"):
                        source.write(output / record["filename"], record["filename"])
            actual = IMPORTER.import_archive(archive, output)
            self.assertEqual(actual["additionalSources"], existing["additionalSources"])
            self.assertEqual({row["filename"]: row for row in actual["assets"]},
                             {row["filename"]: row for row in existing["assets"]})
            original_manifest = manifest_path.read_bytes()
            (output / "nightshift.png").write_bytes(b"tampered")
            imported = output / "vpn_stock.png"
            original_imported = imported.read_bytes()
            with zipfile.ZipFile(archive, "w") as source:
                source.write(GENERATOR.SUPPLEMENTAL / "truetone.png", "vpn_stock.png")
            with self.assertRaisesRegex(ValueError, "does not match manifest"):
                IMPORTER.import_archive(archive, output)
            self.assertEqual(imported.read_bytes(), original_imported)
            self.assertEqual(manifest_path.read_bytes(), original_manifest)

    def test_complete_original_set_and_timer_fallback_are_preserved(self):
        self.assertEqual(len(GENERATOR.ARTWORK), 49)
        self.assertEqual(len(GENERATOR.SUPPLEMENTAL_ARTWORK), 11)
        timer = GENERATOR.ARTWORK["timer"]
        self.assertEqual(timer[:2], GENERATOR.ARTWORK["stopwatch"][:2])
        self.assertIn("compatibility fallback", timer[3])
        self.assertNotIn("focusDriving", GENERATOR.ARTWORK)
        self.assertTrue((GENERATOR.SUPPLEMENTAL / "focus_driving_inactive.png").is_file())

    def test_state_exports_have_equal_logical_size_and_keep_active_colour(self):
        for kind, pair in GENERATOR.SUPPLEMENTAL_ARTWORK.items():
            with self.subTest(kind=kind):
                package = GENERATOR.MOTION_BUNDLE / (GENERATOR.static_package_name(kind) + ".ca")
                for state in ("standard", "selected"):
                    data = (package / f"{state}.png").read_bytes()
                    self.assertEqual(struct.unpack(">II", data[16:24]), (220, 220))
                if kind.startswith("focus"):
                    for state, name in zip(("standard", "selected"), pair):
                        source = (GENERATOR.SUPPLEMENTAL / name).read_bytes()
                        if struct.unpack(">II", source[16:24]) == (220, 220):
                            self.assertEqual((package / f"{state}.png").read_bytes(), source)

    def test_routes_are_exact_and_pending_physical_surfaces_are_explicit(self):
        manifest = json.loads((GENERATOR.MOTION_BUNDLE / "SupplementalRoutes.json").read_text())
        self.assertTrue(manifest["existingArtworkPreserved"])
        expected = {"satelliteUnavailable": "satellite.slash.fill",
                    "satelliteAvailable": "satellite.wave.2",
                    "satelliteConnected": "satellite.wave.2.fill"}
        for kind, symbol in expected.items():
            self.assertEqual(manifest["routes"][kind]["symbolNames"], [symbol])
        for kind in ("focusCustom", "focusReduceInterruptions"):
            route = manifest["routes"][kind]
            self.assertEqual(route["symbolNames"], [])
            self.assertEqual(route["packageSourcePaths"], [])
            self.assertEqual(route["localRoutingStatus"], "pending-focus-row-raster-adapter")
        self.assertEqual(manifest["routes"]["vpn"]["physicalRoutingStatus"],
                         "implemented-controller-redirect")
        for kind, route in manifest["routes"].items():
            if kind.startswith("satellite"):
                self.assertEqual(
                    route["physicalRoutingStatus"],
                    "implemented-current-state-controller-redirect",
                )
            elif kind != "vpn":
                expected = ("implemented-file-backing-awaiting-device-validation"
                            if kind in GENERATOR.SUPPLEMENTAL_CATALOGS
                            else "pending-device-resolver-validation")
                self.assertEqual(route["physicalRoutingStatus"], expected)
        for kind, name in (("nightShift", "NightShift"), ("trueTone", "TrueTone")):
            route = manifest["routes"][kind]
            self.assertEqual(route["catalogRenditionName"], name)
            self.assertEqual(route["catalogSourcePath"],
                             "/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Assets.car")
            self.assertEqual(route["localRoutingStatus"], "implemented")
        self.assertIn("Not supplied", manifest["deferredArtwork"]["airpodsListeningModes"])

    @unittest.skipUnless(sys.platform == "darwin", "normalization requires macOS sips")
    def test_resizing_the_same_original_is_reproducible(self):
        GEN = GENERATOR
        with tempfile.TemporaryDirectory() as directory, patch.object(GEN, "NORMALIZED", Path(directory)):
            GEN.prepare_supplemental_artwork()
            first = {path.name: path.read_bytes() for path in GEN.NORMALIZED.glob("*.png")}
            GEN.prepare_supplemental_artwork()
            second = {path.name: path.read_bytes() for path in GEN.NORMALIZED.glob("*.png")}
            self.assertEqual(first, second)
            for kind, pair in GEN.SUPPLEMENTAL_ARTWORK.items():
                if kind.startswith("focus"):
                    package = GEN.MOTION_BUNDLE / (GEN.static_package_name(kind) + ".ca")
                    for state, name in zip(("standard", "selected"), pair):
                        self.assertEqual((package / f"{state}.png").read_bytes(), first[name])


if __name__ == "__main__":
    unittest.main()
