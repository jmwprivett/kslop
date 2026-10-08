"""Offline contracts for the Pulsar Control Center asset extractor."""

from __future__ import annotations

import importlib.util
import json
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "extract_pulsar_controlcenter_assets.py"
SPEC = importlib.util.spec_from_file_location(
    "extract_pulsar_controlcenter_assets", SCRIPT
)
assert SPEC and SPEC.loader
extractor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = extractor
SPEC.loader.exec_module(extractor)


def png(width: int, height: int) -> bytes:
    signature = b"\x89PNG\r\n\x1a\n"
    data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    chunk = b"IHDR" + data
    return signature + struct.pack(">I", len(data)) + chunk + struct.pack(
        ">I", zlib.crc32(chunk) & 0xFFFFFFFF
    )


class ExtractorTests(unittest.TestCase):
    def test_png_dimensions_rejects_non_png(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.png"
            path.write_bytes(b"not-png")
            with self.assertRaises(extractor.ExtractionError):
                extractor.png_dimensions(path)

    def test_stage_hashes_assets_and_requires_catalog_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / extractor.PACKAGE_ID
            raw = root / "Overwrite/var/mobile/Documents/PhucDo/PhucDoUI"
            connectivity = (
                root / "Overwrite/System/Library/ControlCenter/Bundles/"
                "ConnectivityModule.bundle"
            )
            raw.mkdir(parents=True)
            connectivity.mkdir(parents=True)
            for name in extractor.RAW_NAMES:
                (raw / name).write_bytes(png(96, 96))
            for name in extractor.ADDITIONAL_RAW_NAMES:
                (raw / name).write_bytes(png(220, 220))
            (connectivity / "Assets.car").write_bytes(b"CAR")
            for relative in extractor.CAML_VARIANTS.values():
                path = connectivity / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode())
            bundles = connectivity.parent
            flashlight = bundles / "FlashlightModule.bundle"
            flashlight.mkdir()
            (flashlight / "Assets.car").write_bytes(b"FLASHLIGHT-CAR")
            for relative in extractor.ADDITIONAL_CAML_VARIANTS.values():
                path = bundles / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode())
            info = base / "assetutil"
            records = [
                {
                    "Name": name,
                    "RenditionName": name + ".pdf",
                    "PixelWidth": 84,
                    "PixelHeight": 120,
                    "Scale": 3,
                    "Template Mode": "automatic",
                    "SHA1Digest": name,
                }
                for name in (
                    extractor.CATALOG_NAMES
                    + extractor.FLASHLIGHT_CATALOG_NAMES
                )
            ]
            info.write_text(
                "#!/bin/sh\nprintf '%s' '" + json.dumps(records) + "'\n"
            )
            info.chmod(0o700)
            output = base / "output"
            manifest_path = extractor.stage(root, output, str(info))
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(len(manifest["raw_images"]), 8)
            self.assertEqual(len(manifest["additional_raw_images"]), 9)
            self.assertEqual(
                len(manifest["connectivity_catalog"]["renditions"]), 9
            )
            self.assertEqual(manifest["package"]["upstream_commit"], "bd13799")
            self.assertEqual(
                len(manifest["flashlight_catalog"]["renditions"]), 2
            )
            self.assertEqual(len(manifest["additional_caml_variants"]), 4)
            self.assertEqual(
                manifest["canary_selection"]["cellular"],
                "CellularDataGlyph",
            )
            self.assertEqual(
                manifest["extended_canary_selection"]["hotspot"],
                "HotspotGlyph",
            )
            self.assertEqual(
                manifest["additional_canary_selection"]["flashlight_off"],
                "FlashlightOff",
            )
            self.assertIn("vpn", manifest["source_gaps"])


if __name__ == "__main__":
    unittest.main()
