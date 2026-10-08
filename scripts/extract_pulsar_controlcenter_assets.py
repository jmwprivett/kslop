#!/usr/bin/env python3
"""Stage and inventory the official Pulsar Control Center v2.0 assets.

The input is the root of an already extracted Misaka package.  Third-party
artwork remains a generated build artifact; this script records hashes and
upstream provenance so VM canaries can prove exactly what they loaded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "build/pulsar-controlcenter-v2-assets"
PACKAGE_ID = "com.dobabaophuc.pulsarcc2.0"
UPSTREAM_REPOSITORY = "https://github.com/dobabaophuc1706/misakarepo"
UPSTREAM_COMMIT = "bd13799"
UPSTREAM_ARCHIVE_SHA256 = (
    "2acdf365649ff1fb94bbc73201be4ce1df4ae902c5adfa1a90dfd016369d66aa"
)

RAW_NAMES = (
    "wifi_black.png",
    "wifi_white.png",
    "wifi_white1.png",
    "wifi_white2.png",
    "bluetooth_black.png",
    "bluetooth_white.png",
    "bluetooth_white1.png",
    "bluetooth_white2.png",
)

ADDITIONAL_RAW_NAMES = (
    "pin_off.png",
    "pin_on.png",
    "pin_on1.png",
    "pin_on2.png",
    "record_off.png",
    "record_on.png",
    "1.png",
    "2.png",
    "3.png",
)

CAML_VARIANTS = {
    "wifi_motion_enabled.caml": (
        "WiFi.ca/%Misaka_Segment{Name: 'main.caml', "
        "[(Identifier: 'motion', Value: 'YES')]}%"
    ),
    "wifi_motion_disabled.caml": (
        "WiFi.ca/%Misaka_Segment{Name: 'main.caml', "
        "[(Identifier: 'motion', Value: 'NO')]}%"
    ),
    "bluetooth_motion_enabled.caml": (
        "Bluetooth.ca/%Misaka_Segment{Name: 'main.caml', "
        "[(Identifier: 'motion', Value: 'YES')]}%"
    ),
    "bluetooth_motion_disabled.caml": (
        "Bluetooth.ca/%Misaka_Segment{Name: 'main.caml', "
        "[(Identifier: 'motion', Value: 'NO')]}%"
    ),
}

ADDITIONAL_CAML_VARIANTS = {
    "low_power_motion_enabled.caml": (
        "LowPowerModule.bundle/LowPower.ca/"
        "%Misaka_Segment{Name: 'main.caml', "
        "[(Identifier: 'motion', Value: 'YES')]}%"
    ),
    "low_power_motion_disabled.caml": (
        "LowPowerModule.bundle/LowPower.ca/"
        "%Misaka_Segment{Name: 'main.caml', "
        "[(Identifier: 'motion', Value: 'NO')]}%"
    ),
    "replaykit.caml": "ReplayKitModule.bundle/replaykit.ca/main.caml",
    "replaykit_v2.caml": (
        "ReplayKitModule.bundle/%Optional%replaykit-v2.ca/main.caml"
    ),
}

CATALOG_NAMES = (
    "AirDropGlyph",
    "AirplaneGlyph",
    "CellularDataGlyph",
    "HotspotGlyph",
    "WiFiHotspotGlyph",
    "WiFiSecureGlyph",
    "WiFiSignalHighGlyph",
    "WiFiSignalLowGlyph",
    "WiFiSignalMediumGlyph",
)

FLASHLIGHT_CATALOG_NAMES = (
    "FlashlightOff",
    "FlashlightOn",
)


class ExtractionError(RuntimeError):
    """Raised when the source payload does not match the Pulsar contract."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def png_dimensions(path: Path) -> tuple[int, int]:
    with path.open("rb") as stream:
        header = stream.read(24)
    if len(header) != 24 or header[:8] != b"\x89PNG\r\n\x1a\n":
        raise ExtractionError(f"not a PNG: {path}")
    return struct.unpack(">II", header[16:24])


def require_package_root(root: Path) -> tuple[Path, Path, Path]:
    overwrite = root / "Overwrite"
    if root.name != PACKAGE_ID or not overwrite.is_dir():
        raise ExtractionError(
            f"expected extracted {PACKAGE_ID} package root, got: {root}"
        )
    raw = overwrite / "var/mobile/Documents/PhucDo/PhucDoUI"
    connectivity = (
        overwrite
        / "System/Library/ControlCenter/Bundles/ConnectivityModule.bundle"
    )
    bundles = overwrite / "System/Library/ControlCenter/Bundles"
    required_modules = (
        bundles / "FlashlightModule.bundle",
        bundles / "LowPowerModule.bundle",
        bundles / "ReplayKitModule.bundle",
    )
    if (not raw.is_dir() or not connectivity.is_dir() or
            not all(path.is_dir() for path in required_modules)):
        raise ExtractionError("Pulsar Control Center payload is incomplete")
    return raw, connectivity, bundles


def catalog_inventory(
    car: Path,
    assetutil: str,
    required_names: tuple[str, ...] = CATALOG_NAMES,
    label: str = "Connectivity",
) -> list[dict[str, object]]:
    result = subprocess.run(
        [assetutil, "--info", str(car)],
        check=True,
        capture_output=True,
        text=True,
    )
    records = json.loads(result.stdout)
    by_name = {
        item.get("Name"): item
        for item in records
        if isinstance(item, dict) and item.get("Name") in required_names
    }
    missing = sorted(set(required_names) - set(by_name))
    if missing:
        raise ExtractionError(
            f"{label} Assets.car is missing: " + ", ".join(missing)
        )
    fields = (
        "Name",
        "RenditionName",
        "PixelWidth",
        "PixelHeight",
        "Scale",
        "Template Mode",
        "SHA1Digest",
    )
    return [
        {field: by_name[name].get(field) for field in fields}
        for name in required_names
    ]


def stage(package_root: Path, output: Path, assetutil: str) -> Path:
    raw_source, connectivity, bundles = require_package_root(
        package_root.resolve()
    )
    raw_output = output / "raw"
    catalog_output = output / "catalog"
    caml_output = output / "caml"
    for directory in (raw_output, catalog_output, caml_output):
        directory.mkdir(parents=True, exist_ok=True)

    raw_manifest: list[dict[str, object]] = []
    for name in RAW_NAMES:
        source = raw_source / name
        if not source.is_file():
            raise ExtractionError(f"missing Pulsar artwork: {source}")
        destination = raw_output / name
        shutil.copy2(source, destination)
        width, height = png_dimensions(destination)
        raw_manifest.append({
            "name": name,
            "path": str(destination.relative_to(output)),
            "bytes": destination.stat().st_size,
            "pixel_width": width,
            "pixel_height": height,
            "sha256": sha256(destination),
        })

    additional_raw_manifest: list[dict[str, object]] = []
    for name in ADDITIONAL_RAW_NAMES:
        source = raw_source / name
        if not source.is_file():
            raise ExtractionError(f"missing Pulsar artwork: {source}")
        destination = raw_output / name
        shutil.copy2(source, destination)
        width, height = png_dimensions(destination)
        additional_raw_manifest.append({
            "name": name,
            "path": str(destination.relative_to(output)),
            "bytes": destination.stat().st_size,
            "pixel_width": width,
            "pixel_height": height,
            "sha256": sha256(destination),
        })

    source_car = connectivity / "Assets.car"
    if not source_car.is_file():
        raise ExtractionError(f"missing Pulsar catalog: {source_car}")
    destination_car = catalog_output / "Assets.car"
    shutil.copy2(source_car, destination_car)

    flashlight_source_car = bundles / "FlashlightModule.bundle/Assets.car"
    if not flashlight_source_car.is_file():
        raise ExtractionError(
            f"missing Pulsar Flashlight catalog: {flashlight_source_car}"
        )
    flashlight_catalog_output = catalog_output / "FlashlightModule.bundle"
    flashlight_catalog_output.mkdir(parents=True, exist_ok=True)
    flashlight_destination_car = flashlight_catalog_output / "Assets.car"
    shutil.copy2(flashlight_source_car, flashlight_destination_car)

    caml_manifest: list[dict[str, object]] = []
    for output_name, relative in CAML_VARIANTS.items():
        source = connectivity / relative
        if not source.is_file():
            raise ExtractionError(f"missing Pulsar CAML variant: {source}")
        destination = caml_output / output_name
        shutil.copy2(source, destination)
        caml_manifest.append({
            "name": output_name,
            "path": str(destination.relative_to(output)),
            "bytes": destination.stat().st_size,
            "sha256": sha256(destination),
        })

    additional_caml_manifest: list[dict[str, object]] = []
    for output_name, relative in ADDITIONAL_CAML_VARIANTS.items():
        source = bundles / relative
        if not source.is_file():
            raise ExtractionError(f"missing Pulsar CAML variant: {source}")
        destination = caml_output / output_name
        shutil.copy2(source, destination)
        additional_caml_manifest.append({
            "name": output_name,
            "path": str(destination.relative_to(output)),
            "bytes": destination.stat().st_size,
            "sha256": sha256(destination),
        })

    manifest = {
        "schema": 1,
        "package": {
            "id": PACKAGE_ID,
            "display_name": "Pulsar Control Center UI",
            "version": "2.0",
            "upstream_repository": UPSTREAM_REPOSITORY,
            "upstream_commit": UPSTREAM_COMMIT,
            "upstream_archive_sha256": UPSTREAM_ARCHIVE_SHA256,
        },
        "raw_images": raw_manifest,
        "additional_raw_images": additional_raw_manifest,
        "connectivity_catalog": {
            "path": str(destination_car.relative_to(output)),
            "bytes": destination_car.stat().st_size,
            "sha256": sha256(destination_car),
            "renditions": catalog_inventory(destination_car, assetutil),
        },
        "flashlight_catalog": {
            "path": str(flashlight_destination_car.relative_to(output)),
            "bytes": flashlight_destination_car.stat().st_size,
            "sha256": sha256(flashlight_destination_car),
            "renditions": catalog_inventory(
                flashlight_destination_car,
                assetutil,
                FLASHLIGHT_CATALOG_NAMES,
                "Flashlight",
            ),
        },
        "caml_variants": caml_manifest,
        "additional_caml_variants": additional_caml_manifest,
        "canary_selection": {
            "wifi": "raw/wifi_white.png",
            "bluetooth": "raw/bluetooth_white.png",
            "airplane": "AirplaneGlyph",
            "cellular": "CellularDataGlyph",
        },
        "extended_canary_selection": {
            "airdrop": "AirDropGlyph",
            "hotspot": "HotspotGlyph",
            "wifi_motion": "caml/wifi_motion_enabled.caml",
            "bluetooth_motion": "caml/bluetooth_motion_enabled.caml",
        },
        "additional_canary_selection": {
            "low_power": "caml/low_power_motion_enabled.caml",
            "screen_recording": "caml/replaykit.caml",
            "flashlight_off": "FlashlightOff",
            "flashlight_on": "FlashlightOn",
        },
        "source_gaps": {
            "vpn": "No dedicated VPN rendition or CAML package in Pulsar v2.0",
            "satellite": (
                "No dedicated Satellite rendition or CAML package in "
                "Pulsar v2.0"
            ),
        },
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_root", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--assetutil", default="/usr/bin/assetutil")
    args = parser.parse_args()
    print(stage(args.package_root, args.output.resolve(), args.assetutil))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
