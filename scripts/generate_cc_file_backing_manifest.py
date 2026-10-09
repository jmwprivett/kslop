#!/usr/bin/env python3
"""Inventory proven iOS 26 CC resource routes and the bundled Pulsar packages.

This is a host build step. It records available IPSW baselines and never writes
to a device. Routes without an exported baseline are checked against the device's
native package before installation. The installer preserves that package's index,
document geometry, and state names.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ARTWORK = ROOT / "Cyanide/PulsarControlCenter.bundle"
DEFAULT_STOCK = ROOT / "build/iOS26-23A341-CC-assets/23A341__iPhone17,2"
BUILD = "23A341"
CA_NAMESPACE = "http://www.apple.com/CoreAnimation/1.0"
GEOMETRY_FILE = ARTWORK / "FileBacking/ArtworkGeometry-23A341.json"
GEOMETRY_STATES = {
    "display": (("base",), "mid"),
    "sound": (("base",), "full"),
    "focusSleep": (("OFF", "ON"), "OFF"),
    "focusPersonal": (("OFF", "ON"), "OFF"),
    "focusWork": (("OFF", "ON"), "OFF"),
}


def package_routes() -> list[tuple[str, str, str]]:
    cc = "/System/Library/ControlCenter/Bundles/"
    media = "/System/Library/PrivateFrameworks/MediaControls.framework/"
    focus = "/System/Library/PrivateFrameworks/FocusUI.framework/"
    routes = [
        ("display", "Brightness", cc + "DisplayModule.bundle/Brightness.ca"),
        ("appearance", "Appearance", cc + "DisplayModule.bundle/StyleMode.ca"),
        ("mediaPlayPause", "PlayPauseStop", media + "PlayPauseStop.ca"),
        ("mediaNext", "ForwardBackward", media + "ForwardBackward.ca"),
    ]
    routes += [("sound", "Volume", media + name + ".ca") for name in
               ("Volume", "VolumeRTL", "VolumeSemibold", "VolumeSemiboldRTL", "VolumeBold")]
    routes += [("screenMirroring", "ScreenMirroring", media + name + ".ca") for name in
               ("Mirroring", "Mirroring_IC", "MirroringLeading")]
    for kind, source, module, names in (
        ("timer", "StaticTimer", "Timer", ("Timer", "Timer_IC")),
        ("lowPower", "LowPower", "LowPower", ("LowPower", "LowPower_IC")),
        ("mute", "Mute", "Mute", ("Mute", "Mute_IC")),
        ("orientationLock", "OrientationLock", "OrientationLock", ("OrientationLock", "OrientationLock_IC")),
        ("screenRecording", "ScreenRecording", "ReplayKit",
         ("replaykit", "replaykit_IC", "replaykit-v2", "replaykit-v2_IC")),
    ):
        routes += [(kind, source, cc + module + "Module.bundle/" + name + ".ca")
                   for name in names]
    routes += [(kind, source, focus + native + ".ca") for kind, source, native in (
        ("focus", "Focus", "dnd_cg_02"),
        ("focusSleep", "StaticFocusSleep", "sleep_cg_02"),
        ("focusPersonal", "StaticFocusPersonal", "personal_cg_02"),
        ("focusWork", "StaticFocusWork", "work_cg_02"),
    )]
    routes.append(("musicRecognition", "MusicRecognition",
                   cc + "ShazamModule.bundle/Shazam.ca"))
    return routes


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def states(data: bytes) -> list[str]:
    document = ET.fromstring(data)
    return [state.attrib["name"] for state in
            document.findall(f"./{{{CA_NAMESPACE}}}CALayer/{{{CA_NAMESPACE}}}states/{{{CA_NAMESPACE}}}LKState")]


def generate_geometry(stock: Path, artwork: Path = ARTWORK) -> dict:
    """Measure pinned local resource coordinates; never inspect a live view."""
    records = []
    with tempfile.TemporaryDirectory(prefix="cnd-cc-file-geometry-") as directory:
        work = Path(directory)
        renderer = work / "renderer"
        subprocess.run(["xcrun", "clang", "-fobjc-arc", "-framework", "AppKit",
                        "-framework", "QuartzCore",
                        str(ROOT / "scripts/render_stock_controlcenter_reference.m"),
                        "-o", str(renderer)], check=True)

        def layout(package: Path, state: str) -> dict:
            output = work / "layout.json"
            subprocess.run([str(renderer), "--layout", str(package), state, str(output)], check=True)
            return json.loads(output.read_text())

        for kind, source, target in package_routes():
            if kind not in GEOMETRY_STATES:
                continue
            native = stock / target.removeprefix("/")
            source_package = artwork / (source + ".ca")
            source_states, native_state = GEOMETRY_STATES[kind]
            measurements = [layout(source_package, state) for state in source_states]
            boxes = [measurement["contentBoundsRelativeToRootPosition"] for measurement in measurements]
            left, top = min(box[0] for box in boxes), min(box[1] for box in boxes)
            right, bottom = max(box[0] + box[2] for box in boxes), max(box[1] + box[3] for box in boxes)
            native_layout = layout(native, native_state)
            native_box = native_layout["contentBoundsRelativeToRootPosition"]
            document = native_layout["documentBounds"]
            source_main = (source_package / "main.caml").read_bytes()
            image_names = {image.attrib["src"] for image in
                           ET.fromstring(source_main).iter(f"{{{CA_NAMESPACE}}}contents")
                           if image.attrib.get("type") == "CGImage"}
            records.append({
                "packagePath": target, "kind": kind,
                "sourceMainSHA256": digest(source_main),
                "sourceImageSHA256": {name: digest((source_package / name).read_bytes())
                                      for name in sorted(image_names)},
                "nativeMainSHA256": digest((native / "main.caml").read_bytes()),
                "sourceContentBounds": [left, top, right - left, bottom - top],
                "nativeContentBounds": [native_box[0] + document[0] + document[2] / 2,
                                        native_box[1] + document[1] + document[3] / 2,
                                        native_box[2], native_box[3]],
                "nativeDocumentBounds": document,
                "sourceStatesMeasured": list(source_states), "nativeStateMeasured": native_state,
            })
    return {"schemaVersion": 1, "productBuildVersion": BUILD,
            "measurement": "local-CAPackage-vector-path-and-PNG-alpha-bounds-through-layer-transforms",
            "alphaThreshold": 24, "usesLiveViews": False, "routes": records}


def manifest(stock: Path, artwork: Path = ARTWORK) -> dict:
    routes = []
    geometry_path = artwork / "FileBacking/ArtworkGeometry-23A341.json"
    geometry_records = {record["packagePath"]: record for record in
                        json.loads(geometry_path.read_text())["routes"]}
    for kind, source, target in package_routes():
        source_directory = artwork / (source + ".ca")
        source_main = (source_directory / "main.caml").read_bytes()
        source_index = (source_directory / "index.xml").read_bytes()
        if plistlib.loads(source_index).get("rootDocument") != "main.caml":
            raise ValueError(f"Unexpected Pulsar package index: {source}")
        ET.fromstring(source_main)
        images = {}
        for image in ET.fromstring(source_main).iter(f"{{{CA_NAMESPACE}}}contents"):
            if image.attrib.get("type") != "CGImage":
                continue
            relative = image.attrib.get("src", "")
            if not relative or Path(relative).name != relative or not relative.endswith(".png"):
                raise ValueError(f"Nonlocal Pulsar image: {source}/{relative}")
            data = (source_directory / relative).read_bytes()
            if data[:8] != b"\x89PNG\r\n\x1a\n":
                raise ValueError(f"Invalid Pulsar PNG: {source}/{relative}")
            images[relative] = {"length": len(data), "sha256": digest(data)}
        route = {"kind": kind, "packagePath": target,
                 "sourcePackage": source + ".ca",
                 "sourceMainSHA256": digest(source_main),
                 "sourceIndexSHA256": digest(source_index), "images": images}
        if kind in ("sound", "display"):
            route["artworkColorContract"] = "native-white-template-preserve-authored-opacity"
            route["staticStateContract"] = "explicit-visible-Pulsar-artwork-at-every-native-level"
        original = stock / target.removeprefix("/")
        main = original / "main.caml"
        index = original / "index.xml"
        if main.is_file() and index.is_file():
            native = main.read_bytes()
            ET.fromstring(native)
            route["stockMainSHA256"] = digest(native)
            route["stockMainLength"] = len(native)
            route["stockIndexSHA256"] = digest(index.read_bytes())
            route["stockStates"] = states(native)
            route["baseline"] = "IPSW-23A341-iPhone17,2"
            if kind in GEOMETRY_STATES:
                geometry = geometry_records.get(target)
                if not geometry or geometry["sourceMainSHA256"] != route["sourceMainSHA256"] or \
                        geometry["nativeMainSHA256"] != route["stockMainSHA256"] or \
                        geometry["sourceImageSHA256"] != {name: image["sha256"] for name, image in images.items()}:
                    raise ValueError(f"Missing or stale offline artwork geometry: {target}")
                route["artworkGeometry"] = geometry
        else:
            route["baseline"] = "device-package-preflight-required"
        routes.append(route)
    return {"schemaVersion": 1, "productBuildVersion": BUILD, "packageRoutes": routes,
            "excludedKinds": ["focusReduceInterruptions", "focusCustom", "hearing"],
            "catalogPayloadManifest": "CatalogFileBacking.json"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-root", type=Path, default=DEFAULT_STOCK)
    parser.add_argument("--output", type=Path, default=ARTWORK / "FileBacking.json")
    parser.add_argument("--generate-geometry", action="store_true",
                        help="Measure the reviewed native/Pulsar files before inventorying them.")
    arguments = parser.parse_args()
    if arguments.generate_geometry:
        geometry = generate_geometry(arguments.stock_root)
        GEOMETRY_FILE.parent.mkdir(parents=True, exist_ok=True)
        GEOMETRY_FILE.write_text(json.dumps(geometry, indent=2, sort_keys=True) + "\n")
    result = manifest(arguments.stock_root)
    arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"Inventoried {len(result['packageRoutes'])} proven package routes; "
          f"{sum('stockMainSHA256' in r for r in result['packageRoutes'])} exported IPSW baselines.")


if __name__ == "__main__":
    main()
