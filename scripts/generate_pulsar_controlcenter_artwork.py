#!/usr/bin/env python3
"""Generate Pulsar Control Center artwork and stateful CAML resources.

The official package is kept under build/ as a provenance-pinned research
artifact. This generator turns its raw PNGs plus locally rendered catalog
renditions into Objective-C string literals, and repackages stateful CAML into
an app resource bundle. Production builds do not rely on host paths or target-
process file writes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import plistlib
import re
import shutil
import struct
import subprocess
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = (
    ROOT
    / "build/pulsar-controlcenter-v2-source/extracted-original"
    / "com.dobabaophuc.pulsarcc2.0/Overwrite"
)
RAW = PACKAGE / "var/mobile/Documents/PhucDo/PhucDoUI"
RENDERED = ROOT / "build/pulsar-catalog-rendered-png"
MANIFEST = ROOT / "build/pulsar-controlcenter-v2-assets/manifest.json"
OUTPUT = ROOT / "Cyanide/tweaks/CNDPulsarControlCenterArtwork.inc"
MOTION_BUNDLE = ROOT / "Cyanide/PulsarControlCenter.bundle"
SUPPLEMENTAL = ROOT / "assets/pulsar-controlcenter-supplemental"
NORMALIZED = ROOT / "build/pulsar-supplemental-normalized"

# The attached set supplements the complete upstream set. Keep incomplete
# states (Driving) out of active mappings and preserve Timer's clock fallback.
SUPPLEMENTAL_ARTWORK = {
    "nightShift": ("nightshift.png", "nightshift.png"),
    "trueTone": ("truetone.png", "truetone.png"),
    "vpn": ("vpn_stock.png", "vpn_stock.png"),
    "satelliteUnavailable": ("icons8-satellite-220.png",) * 2,
    "satelliteAvailable": ("icons8-satellite-220 (1).png",) * 2,
    "satelliteConnected": ("icons8-satellite-signal-100.png",) * 2,
    "focusSleep": ("focus_sleep_inactive.png", "focus_sleep_active.png"),
    "focusPersonal": ("focus_personal_inactive.png", "focus_personal_active.png"),
    "focusWork": ("focus_work_inactive.png", "focus_work_active.png"),
    "focusReduceInterruptions": (
        "focus_reduce_interruptions.png", "focus_reduce_interruptions_active.png"),
    "focusCustom": ("focus_custom_inactive.png", "focus_custom_active.png"),
}
SUPPLEMENTAL_SYMBOLS = {
    "vpn": ["network.connected.to.line.below.fill"],
    "satelliteUnavailable": ["satellite.slash.fill"],
    "satelliteAvailable": ["satellite.wave.2"],
    "satelliteConnected": ["satellite.wave.2.fill"],
}
SUPPLEMENTAL_PACKAGES = {
    "focusSleep": ["/System/Library/PrivateFrameworks/FocusUI.framework/sleep_cg_02.ca"],
    "focusPersonal": ["/System/Library/PrivateFrameworks/FocusUI.framework/personal_cg_02.ca"],
    "focusWork": ["/System/Library/PrivateFrameworks/FocusUI.framework/work_cg_02.ca"],
}
SUPPLEMENTAL_CATALOGS = {
    "nightShift": ("/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Assets.car", "NightShift"),
    "trueTone": ("/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Assets.car", "TrueTone"),
}

# Exact system-symbol identities captured by the VM/physical ownership traces.
# These names are metadata for exact provider interception; they are not used
# to classify a live view and do not authorize a recursive hierarchy walk.
SYMBOL_NAMES = {
    "wifi": ["wifi", "wifi.slash", "wifi.badge.lock"],
    "bluetooth": ["bluetooth", "bluetooth.slash"],
    "cellular": ["cellularbars"],
    "airDrop": ["airdrop"],
    "hotspot": ["personalhotspot", "personalhotspot.slash"],
    "flashlight": ["flashlight.off.fill", "flashlight.on.fill"],
    "qrCode": ["qrcode.viewfinder"],
    "mediaAirPlay": ["airplay.audio"],
    **SUPPLEMENTAL_SYMBOLS,
}
SELECTED_SYMBOL_NAMES = {
    "flashlight": ["flashlight.on.fill"],
}

MUTE_CAML = (
    PACKAGE
    / "System/Library/ControlCenter/Bundles/MuteModule.bundle/Mute.ca"
    / "%Misaka_Segment{Name: 'main.caml', [(Identifier: 'motion', Value: 'YES')]}%"
)
ORIENTATION_CAML = (
    PACKAGE
    / "System/Library/ControlCenter/Bundles/OrientationLockModule.bundle/OrientationLock.ca"
    / "%Misaka_Segment{Name: 'main.caml', [(Identifier: 'motion', Value: 'YES')]}%"
)
WIFI_CAML = (
    PACKAGE
    / "System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/WiFi.ca"
    / "%Misaka_Segment{Name: 'main.caml', [(Identifier: 'motion', Value: 'YES')]}%"
)
BLUETOOTH_CAML = (
    PACKAGE
    / "System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/Bluetooth.ca"
    / "%Misaka_Segment{Name: 'main.caml', [(Identifier: 'motion', Value: 'YES')]}%"
)
LOW_POWER_CAML = (
    PACKAGE
    / "System/Library/ControlCenter/Bundles/LowPowerModule.bundle/LowPower.ca"
    / "%Misaka_Segment{Name: 'main.caml', [(Identifier: 'motion', Value: 'YES')]}%"
)
APPEARANCE_CAML = (
    PACKAGE
    / "System/Library/ControlCenter/Bundles/AppearanceModule.bundle/StyleMode.ca"
    / "%Misaka_Segment{Name: 'main.caml', [(Identifier: 'motion', Value: 'YES')]}%"
)
SCREEN_MIRRORING_CAML = (
    PACKAGE
    / "System/Library/PrivateFrameworks/MediaControls.framework/%Optional%Mirroring.ca"
    / "%Misaka_Segment{Name: 'main.caml', [(Identifier: 'motion', Value: 'YES')]}%"
)


# name: official Pulsar CAML source. Referenced images are discovered and
# repackaged automatically so every generated package is self-contained.
MOTION_PACKAGES: dict[str, Path] = {
    "Mute": MUTE_CAML,
    "OrientationLock": ORIENTATION_CAML,
    "WiFi": WIFI_CAML,
    "Bluetooth": BLUETOOTH_CAML,
    "LowPower": LOW_POWER_CAML,
    "Appearance": APPEARANCE_CAML,
    "Focus": (
        PACKAGE
        / "System/Library/PrivateFrameworks/FocusUI.framework/%Optional%dnd_cg_02.ca/main.caml"
    ),
    "ScreenRecording": (
        PACKAGE
        / "System/Library/ControlCenter/Bundles/ReplayKitModule.bundle/replaykit.ca/main.caml"
    ),
    "ScreenMirroring": SCREEN_MIRRORING_CAML,
    "MusicRecognition": (
        PACKAGE
        / "System/Library/ControlCenter/Bundles/ShazamModule.bundle/Shazam.ca/main.caml"
    ),
    "Hearing": (
        PACKAGE
        / "System/Library/ControlCenter/Bundles/HearingAidsModule.bundle/HAE_1_x_1.ca/main.caml"
    ),
    "Brightness": (
        PACKAGE
        / "System/Library/ControlCenter/Bundles/DisplayModule.bundle/Brightness.ca/main.caml"
    ),
    "Volume": (
        PACKAGE
        / "System/Library/PrivateFrameworks/MediaControls.framework/Volume.ca/main.caml"
    ),
    "PlayPauseStop": (
        PACKAGE
        / "System/Library/PrivateFrameworks/MediaControls.framework/%Optional%PlayPauseStop.ca/main.caml"
    ),
    "ForwardBackward": (
        PACKAGE
        / "System/Library/PrivateFrameworks/MediaControls.framework/%Optional%ForwardBackward.ca/main.caml"
    ),
}


# kind: (standard path, selected path, UIKit image scale, source note)
ARTWORK: dict[str, tuple[Path, Path, float, str]] = {
    "wifi": (RAW / "wifi_black.png", RAW / "wifi_white.png", 3.0,
             "ConnectivityModule/WiFi.ca"),
    "bluetooth": (RAW / "bluetooth_black.png", RAW / "bluetooth_white.png", 3.0,
                  "ConnectivityModule/Bluetooth.ca"),
    "airplaneMode": (RENDERED / "Connectivity-AirplaneGlyph.png",) * 2
        + (3.0, "ConnectivityModule/AirplaneGlyph"),
    "cellular": (RENDERED / "Connectivity-CellularDataGlyph.png",) * 2
        + (3.0, "ConnectivityModule/CellularDataGlyph"),
    "airDrop": (RENDERED / "Connectivity-AirDropGlyph.png",) * 2
        + (3.0, "ConnectivityModule/AirDropGlyph"),
    "hotspot": (RENDERED / "Connectivity-HotspotGlyph.png",) * 2
        + (3.0, "ConnectivityModule/HotspotGlyph"),
    "flashlight": (RENDERED / "Flashlight-FlashlightOff.png",
                   RENDERED / "Flashlight-FlashlightOn.png", 3.0,
                   "FlashlightModule/FlashlightOff+FlashlightOn"),
    "lowPower": (RAW / "pin_off.png", RAW / "pin_on.png", 5.5,
                 "LowPowerModule/LowPower.ca"),
    "screenRecording": (RAW / "record_off.png", RAW / "record_on.png", 5.5,
                        "ReplayKitModule/replaykit.ca"),
    "orientationLock": (RAW / "rotation_off.png", RAW / "rotation_on.png", 5.5,
                        "OrientationLockModule/OrientationLock.ca"),
    "mute": (RAW / "ringer_off.png", RAW / "ringer_on.png", 5.5,
             "MuteModule/Mute.ca"),
    "screenMirroring": (RAW / "mirror_off.png", RAW / "mirror_on.png", 5.5,
                        "MediaControls/Mirroring.ca"),
    "musicRecognition": (RAW / "shazam_off.png", RAW / "shazam_on.png", 5.5,
                         "ShazamModule/Shazam.ca"),
    "appearance": (RAW / "light.png", RAW / "dark.png", 5.5,
                   "AppearanceModule/StyleMode.ca"),
    "focus": (RAW / "focus_off.png", RAW / "focus_on.png", 5.5,
              "FocusUI/dnd_cg_02.ca"),
    "hearing": (RAW / "ear.png",) * 2 + (5.5, "HearingAidsModule/HAE_1_x_1.ca"),
    "sound": (RAW / "mute.png",) * 2 + (3.0, "MediaControls/Volume.ca"),
    "display": (RAW / "brightness.png",) * 2 + (3.0, "DisplayModule/Brightness.ca"),
    "mediaPlayPause": (
        RENDERED / "Media-Play.png", RENDERED / "Media-Pause.png", 3.0,
        "MediaControls/PlayPauseStop.ca (host-rendered states)",
    ),
    "mediaPrevious": (RENDERED / "Media-Previous.png",) * 2
        + (3.0, "MediaControls/ForwardBackward.ca (host-rendered, mirrored)"),
    "mediaNext": (RENDERED / "Media-Next.png",) * 2
        + (3.0, "MediaControls/ForwardBackward.ca (host-rendered)"),
    "mediaAirPlay": (MOTION_BUNDLE / "MediaAirPlay.png",) * 2
        + (3.0, "MediaControls/AirPlayControlAudioLight+Dark.ca"),
    "calculator": (RENDERED / "Calculator-AppIcon.png",) * 2
        + (3.0, "CalculatorModule/AppIcon"),
    "camera": (RENDERED / "Camera-AppIcon.png",) * 2
        + (3.0, "CameraModule/AppIcon"),
    "qrCode": (RENDERED / "QRCode-AppIcon.png",) * 2
        + (3.0, "QRCodeModule/AppIcon"),
    "alarm": (RENDERED / "Alarm-AppIcon.png",) * 2
        + (3.0, "AlarmModule/AppIcon"),
    "stopwatch": (RENDERED / "Stopwatch-AppIcon.png",) * 2
        + (3.0, "StopwatchModule/AppIcon"),
    # Pulsar v2 has no TimerModule payload. Its clock-family Stopwatch artwork
    # is the intentional compatibility fallback for the iOS 26 Timer control.
    "timer": (RENDERED / "Stopwatch-AppIcon.png",) * 2
        + (3.0, "StopwatchModule/AppIcon (Timer compatibility fallback)"),
    "wallet": (RENDERED / "Wallet-AppIcon.png",) * 2
        + (3.0, "WalletModule/AppIcon"),
    "voiceMemos": (RENDERED / "VoiceMemos-AppIcon.png",) * 2
        + (3.0, "VoiceMemosModule/AppIcon"),
    "tvRemote": (RENDERED / "TVRemote-ModuleIcon.png",) * 2
        + (3.0, "TVRemoteModule/ModuleIcon"),
    "magnifier": (RENDERED / "Magnifier-AppIcon.png",) * 2
        + (3.0, "MagnifierModule/AppIcon (Default)"),
    "guidedAccess": (RENDERED / "GuidedAccess-GuidedAccess.png",) * 2
        + (3.0, "AccessibilityGuidedAccess/GuidedAccess"),
    "accessibilityShortcuts": (
        RENDERED / "AccessibilityShortcuts-AccessibilityIcon.png",
    ) * 2 + (3.0, "AccessibilityShortcuts/AccessibilityIcon"),
    "soundDetection": (RENDERED / "SoundDetection-SoundDetectionIcon.png",) * 2
        + (3.0, "AccessibilitySoundDetection/SoundDetectionIcon"),
    "textSize": (RENDERED / "TextSize-TextSize.png",) * 2
        + (3.0, "AccessibilityTextSize/TextSize"),
    "nfc": (RENDERED / "NFC-ModuleGlyph.png",) * 2
        + (3.0, "NFCControlCenterModule/ModuleGlyph"),
    "performanceTrace": (RENDERED / "PerformanceTrace-AppIcon.png",) * 2
        + (3.0, "PerformanceTraceModule/AppIcon"),
}

for _kind, (_standard, _selected) in SUPPLEMENTAL_ARTWORK.items():
    ARTWORK[_kind] = (NORMALIZED / _standard, NORMALIZED / _selected, 5.5,
                      "User-supplied supplemental Pulsar artwork")


# The iOS 26 trace found four distinct artwork delivery boundaries.  Keeping
# this in generated metadata prevents the runtime from treating every glyph as
# a CCUICAPackageDescription (the cause of the invisible connectivity glyphs
# and the layered WidgetKit icons).
DELIVERY_ADAPTERS: dict[str, str] = {
    # ConnectivityModule's one confirmed active catalog route.
    "airplaneMode": "catalogImage",

    # SFSymbols/CoreGlyphs-backed controls are delivered through the live
    # glyph-image setters.  Their themed PNG replaces that delivered UIImage.
    "wifi": "generatedSymbolImage",
    "bluetooth": "generatedSymbolImage",
    "cellular": "generatedSymbolImage",
    "airDrop": "generatedSymbolImage",
    "hotspot": "generatedSymbolImage",
    "flashlight": "generatedSymbolImage",
    "mediaAirPlay": "generatedSymbolImage",

    # These three controls are WidgetKit/ControlHost controls on iOS 26.  The
    # active icon surface is CHUISControlIconView, not the legacy module CAR.
    "calculator": "hostedControlIcon",
    "camera": "hostedControlIcon",
    "qrCode": "hostedControlIcon",
}
for _kind in SUPPLEMENTAL_ARTWORK:
    DELIVERY_ADAPTERS[_kind] = (
        "catalogImage" if _kind in SUPPLEMENTAL_CATALOGS else
        "generatedSymbolImage" if _kind in SUPPLEMENTAL_SYMBOLS else
        "caPackage" if _kind in SUPPLEMENTAL_PACKAGES else "focusModeRaster"
    )

# Every traced CA route stays package-backed.  The remaining legacy/static
# controls use the catalog-image adapter at their controller delivery boundary.
for _kind in ARTWORK:
    if _kind in DELIVERY_ADAPTERS:
        continue
    DELIVERY_ADAPTERS[_kind] = (
        "caPackage" if _kind in {
            "lowPower", "screenRecording", "orientationLock", "mute",
            "screenMirroring", "musicRecognition", "appearance", "focus",
            "hearing", "sound", "display", "mediaPlayPause",
            "mediaPrevious", "mediaNext", "timer",
        } else "catalogImage"
    )


PACKAGE_ARTWORK: dict[str, tuple[str, str, str | None]] = {
    "wifi": ("WiFi", "ConnectivityModule/WiFi.ca", "poweron"),
    "bluetooth": ("Bluetooth", "ConnectivityModule/Bluetooth.ca", "poweron"),
    "lowPower": ("LowPower", "LowPowerModule/LowPower.ca", "disabled"),
    "screenRecording": (
        "ScreenRecording", "ReplayKitModule/replaykit.ca", "disabled"
    ),
    "orientationLock": (
        "OrientationLock", "OrientationLockModule/OrientationLock.ca", None
    ),
    "mute": ("Mute", "MuteModule/Mute.ca", None),
    "screenMirroring": (
        "ScreenMirroring", "MediaControls/Mirroring.ca", "off"
    ),
    "musicRecognition": (
        "MusicRecognition", "ShazamModule/Shazam.ca", "Off"
    ),
    "appearance": ("Appearance", "AppearanceModule/StyleMode.ca", "light"),
    "focus": ("Focus", "FocusUI/dnd_cg_02.ca", "OFF"),
    "hearing": ("Hearing", "HearingAidsModule/HAE_1_x_1.ca", "default"),
    "display": ("Brightness", "DisplayModule/Brightness.ca", "light"),
    "sound": ("Volume", "MediaControls/Volume.ca", "mid"),
    "mediaPlayPause": (
        "PlayPauseStop", "MediaControls/PlayPauseStop.ca", "play"
    ),
    "mediaPrevious": (
        "ForwardBackward", "MediaControls/ForwardBackward.ca", None
    ),
    "mediaNext": (
        "ForwardBackward", "MediaControls/ForwardBackward.ca", None
    ),
}


def static_package_name(kind: str) -> str:
    return "Static" + kind[:1].upper() + kind[1:]


SINGLE_GLYPH_PACKAGE_ARTWORK = {
    kind: static_package_name(kind)
    for kind in (
        "wifi", "bluetooth", "airplaneMode", "cellular", "airDrop", "hotspot"
    )
}

# Package-local optical scaling for file-backed static controls. Timer's
# Stopwatch-derived source has generous transparent padding, so 1.4x enlarges
# the visible glyph while keeping the native Timer/Timer_IC canvases intact.
STATIC_PACKAGE_ARTWORK_SCALES = {
    "timer": 1.4,
}


# Asset-only modules still get a real CAPackage. This makes the custom package
# the sole glyph source instead of layering a raster over a stock package.
for _kind, (_, _, _, _source) in ARTWORK.items():
    PACKAGE_ARTWORK.setdefault(
        _kind, (static_package_name(_kind), _source + " (generated CAML)", "off")
    )


INDEX_PLIST = {
    "documentResizesToView": False,
    "geometryFlipped": False,
    "loopingEnabled": True,
    "rootDocument": "main.caml",
}


def write_package(package_dir: Path, caml: str) -> None:
    (package_dir / "main.caml").write_text(caml, encoding="utf-8")
    (package_dir / "index.xml").write_bytes(
        plistlib.dumps(INDEX_PLIST, fmt=plistlib.FMT_XML, sort_keys=True)
    )


def write_white_template_png(source: Path, destination: Path) -> None:
    """Write an RGBA PNG whose visible pixels are white with source alpha."""
    data = source.read_bytes()
    signature = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(signature):
        raise SystemExit(f"not a PNG: {source}")

    offset = len(signature)
    ihdr = None
    idat = bytearray()
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        payload = data[offset + 8:offset + 8 + length]
        offset += 12 + length
        if chunk_type == b"IHDR":
            ihdr = payload
        elif chunk_type == b"IDAT":
            idat.extend(payload)
        elif chunk_type == b"IEND":
            break
    if ihdr is None or len(ihdr) != 13:
        raise SystemExit(f"missing PNG IHDR: {source}")
    width, height, depth, color_type, compression, filtering, interlace = (
        struct.unpack(">IIBBBBB", ihdr)
    )
    if (depth, color_type, compression, filtering, interlace) != (8, 6, 0, 0, 0):
        raise SystemExit(
            f"unsupported PNG layout for template conversion: {source}"
        )

    stride = width * 4
    encoded = zlib.decompress(bytes(idat))
    if len(encoded) != height * (stride + 1):
        raise SystemExit(f"unexpected PNG scanline size: {source}")
    rows: list[bytearray] = []
    cursor = 0
    previous = bytearray(stride)
    for _ in range(height):
        filter_type = encoded[cursor]
        cursor += 1
        scanline = bytearray(encoded[cursor:cursor + stride])
        cursor += stride
        reconstructed = bytearray(stride)
        for index, value in enumerate(scanline):
            left = reconstructed[index - 4] if index >= 4 else 0
            up = previous[index]
            upper_left = previous[index - 4] if index >= 4 else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = up
            elif filter_type == 3:
                predictor = (left + up) // 2
            elif filter_type == 4:
                estimate = left + up - upper_left
                distances = (
                    abs(estimate - left), abs(estimate - up),
                    abs(estimate - upper_left),
                )
                predictor = (left, up, upper_left)[distances.index(min(distances))]
            else:
                raise SystemExit(f"unknown PNG filter {filter_type}: {source}")
            reconstructed[index] = (value + predictor) & 0xFF
        template_row = bytearray(reconstructed)
        for index in range(0, stride, 4):
            template_row[index:index + 3] = b"\xff\xff\xff"
        rows.append(template_row)
        previous = reconstructed

    raw = b"".join(b"\0" + bytes(row) for row in rows)

    def chunk(chunk_type: bytes, payload: bytes) -> bytes:
        checksum = binascii.crc32(chunk_type + payload) & 0xFFFFFFFF
        return (struct.pack(">I", len(payload)) + chunk_type + payload +
                struct.pack(">I", checksum))

    destination.write_bytes(
        signature + chunk(b"IHDR", ihdr) +
        chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    )


def copy_caml_dependencies(source: Path, package_dir: Path, caml: str) -> str:
    aliases = {
        "wifi.png": RAW / "wifi_black.png",
        "bluetooth.png": RAW / "bluetooth_black.png",
    }
    for reference in sorted(set(re.findall(r'src="([^"]+)"', caml))):
        basename = Path(reference).name
        dependency = RAW / basename
        if not dependency.is_file():
            dependency = aliases.get(basename, source.parent / basename)
        if not dependency.is_file():
            raise SystemExit(
                f"missing Pulsar CAML dependency {reference!r} for {source}"
            )
        shutil.copy2(dependency, package_dir / basename)
        caml = caml.replace(reference, basename)
    return caml


def static_caml(*, consumer_positioned_root: bool = False,
                artwork_scale: float = 1.0) -> str:
    # CAPackage glyph documents use centered coordinates. The consumer positions
    # the root layer; offsetting its children by half their bounds shifts icons
    # outside the button in ControlCenterUIKit (the legacy Pulsar roots use 0 0).
    # Timer's CCUICAPackageView places the document origin at the glyph
    # center. A bounded root contributes its own half-bounds anchor offset,
    # moving the origin-centered child artwork 20 points out of the button.
    # Match the unbounded roots in the upstream Pulsar packages for this
    # consumer, without changing the other existing static package contracts.
    root_bounds = "" if consumer_positioned_root else ' bounds="0 0 40 40"'
    artwork_size = 40 * artwork_scale
    artwork_bounds = f"0 0 {artwork_size:g} {artwork_size:g}"
    off_states = ("off", "OFF", "disabled", "inactive", "unselected",
                  "normal", "disconnected", "poweroff", "0")
    on_states = ("on", "ON", "enabled", "active", "selected", "connected",
                 "associated", "poweron", "recording", "1")

    def state(name: str, selected: bool) -> str:
        standard_hidden = 1 if selected else 0
        selected_hidden = 0 if selected else 1
        return f'''\n      <LKState name="{name}">\n        <elements>\n          <LKStateSetValue targetId="#standard" keyPath="hidden"><value type="integer" value="{standard_hidden}"/></LKStateSetValue>\n          <LKStateSetValue targetId="#selected" keyPath="hidden"><value type="integer" value="{selected_hidden}"/></LKStateSetValue>\n        </elements>\n      </LKState>'''

    states = "".join(state(name, False) for name in off_states)
    states += "".join(state(name, True) for name in on_states)
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<caml xmlns="http://www.apple.com/CoreAnimation/1.0">
  <CALayer{root_bounds} position="-0.5 0">
    <sublayers>
      <CALayer id="#standard" bounds="{artwork_bounds}" position="0 0" hidden="0" contentsGravity="resizeAspect">
        <contents type="CGImage" src="standard.png"/>
      </CALayer>
      <CALayer id="#selected" bounds="{artwork_bounds}" position="0 0" hidden="1" contentsGravity="resizeAspect">
        <contents type="CGImage" src="selected.png"/>
      </CALayer>
    </sublayers>
    <states>{states}
    </states>
    <animations/>
  </CALayer>
</caml>
'''


def generate_motion_bundle() -> int:
    # Catalog payloads and pinned native geometry are generated independently.
    # Regenerating artwork must preserve those reviewed file-backed resources.
    MOTION_BUNDLE.mkdir(parents=True, exist_ok=True)
    info = {
        "CFBundleDevelopmentRegion": "en",
        "CFBundleIdentifier": "com.zeroxjf.cyanide.pulsar-control-center",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "PulsarControlCenter",
        "CFBundlePackageType": "BNDL",
        "CFBundleShortVersionString": "2.0",
        "CFBundleVersion": "1",
    }
    (MOTION_BUNDLE / "Info.plist").write_bytes(
        plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=True)
    )
    for name, source in MOTION_PACKAGES.items():
        if not source.is_file():
            raise SystemExit(f"missing Pulsar CAML source: {source}")
        package_dir = MOTION_BUNDLE / f"{name}.ca"
        package_dir.mkdir(exist_ok=True)
        caml = source.read_text(encoding="utf-8")
        caml = copy_caml_dependencies(source, package_dir, caml)
        if "/var/mobile/Documents/PhucDo/PhucDoUI/" in caml:
            raise SystemExit(f"unresolved absolute CAML dependency in {source}")
        write_package(package_dir, caml)

    static_count = 0
    official_names = set(MOTION_PACKAGES)
    for kind, (standard, selected, _, _) in ARTWORK.items():
        package_name = PACKAGE_ARTWORK[kind][0]
        static_names = [] if package_name in official_names else [package_name]
        compact_name = SINGLE_GLYPH_PACKAGE_ARTWORK.get(kind)
        if compact_name and compact_name not in static_names:
            static_names.append(compact_name)
        for static_name in static_names:
            package_dir = MOTION_BUNDLE / f"{static_name}.ca"
            package_dir.mkdir(exist_ok=True)
            if kind.startswith("focus") and kind in SUPPLEMENTAL_ARTWORK:
                # Preserve the user's coloured active state. Converting this
                # artwork to a white template would erase the state design.
                shutil.copy2(standard, package_dir / "standard.png")
                shutil.copy2(selected, package_dir / "selected.png")
            else:
                write_white_template_png(standard, package_dir / "standard.png")
                write_white_template_png(selected, package_dir / "selected.png")
            write_package(package_dir, static_caml(
                consumer_positioned_root=kind == "timer",
                artwork_scale=STATIC_PACKAGE_ARTWORK_SCALES.get(kind, 1.0)))
            static_count += 1
    return len(MOTION_PACKAGES) + static_count


def supplemental_physical_status(kind: str) -> str:
    if kind in SUPPLEMENTAL_CATALOGS:
        return "implemented-file-backing-awaiting-device-validation"
    if kind == "vpn":
        return "implemented-controller-redirect"
    if kind.startswith("satellite"):
        return "implemented-current-state-controller-redirect"
    return "pending-device-resolver-validation"


def prepare_supplemental_artwork() -> dict:
    manifest = json.loads((SUPPLEMENTAL / "source-manifest.json").read_text())
    records = {row["filename"]: row for row in manifest["assets"]}
    filenames = sorted({name for pair in SUPPLEMENTAL_ARTWORK.values() for name in pair})
    # Verify all submitted hashes before producing any normalized resource.
    for name in filenames:
        source = SUPPLEMENTAL / name
        if hashlib.sha256(source.read_bytes()).hexdigest() != records[name]["sha256"]:
            raise SystemExit(f"supplemental artwork hash mismatch: {name}")
    NORMALIZED.mkdir(parents=True, exist_ok=True)
    for name in filenames:
        source, target = SUPPLEMENTAL / name, NORMALIZED / name
        if (records[name]["width"], records[name]["height"]) == (220, 220):
            shutil.copy2(source, target)
        else:
            subprocess.run(["sips", "-m", "/System/Library/ColorSync/Profiles/sRGB Profile.icc",
                            "-z", "220", "220", str(source), "--out", str(target)],
                           check=True, capture_output=True)
            canonicalize_resized_png(target)
    return {
        "schemaVersion": 1,
        "sourceArchiveSHA256": manifest["sourceSHA256"],
        "role": "supplemental",
        "existingArtworkPreserved": True,
        "timerArtwork": "Existing Stopwatch compatibility fallback",
        "routes": {
            kind: {"standardSource": pair[0], "selectedSource": pair[1],
                   "symbolNames": SUPPLEMENTAL_SYMBOLS.get(kind, []),
                   "packageSourcePaths": SUPPLEMENTAL_PACKAGES.get(kind, []),
                   **({"catalogSourcePath": SUPPLEMENTAL_CATALOGS[kind][0],
                       "catalogRenditionName": SUPPLEMENTAL_CATALOGS[kind][1]}
                      if kind in SUPPLEMENTAL_CATALOGS else {}),
                   "localRoutingStatus": "implemented" if kind in SUPPLEMENTAL_SYMBOLS or
                       kind in SUPPLEMENTAL_PACKAGES or kind in SUPPLEMENTAL_CATALOGS
                       else "pending-focus-row-raster-adapter",
                   "physicalRoutingStatus": supplemental_physical_status(kind)}
            for kind, pair in SUPPLEMENTAL_ARTWORK.items()
        },
        "deferredArtwork": {
            "focusDriving": "Active state not supplied; inactive source retained only",
            "focusFitness": "Not supplied", "focusGaming": "Not supplied",
            "focusMindful": "Not supplied", "focusReading": "Not supplied",
            "airpodsListeningModes": "Not supplied", "airpodsSpatialAudio": "Not supplied",
            "airpodsConversationAwareness": "Not supplied",
        },
    }


def canonicalize_resized_png(path: Path) -> None:
    """Keep sRGB pixels while removing sips' timestamped ICC/EXIF metadata.

    Colorsync can generate a fresh ICC creation timestamp on each resize. A
    fixed sRGB rendering-intent chunk gives identical output from identical
    pixel data, without modifying the submitted original.
    """
    data = path.read_bytes()
    result = bytearray(data[:8])
    offset = 8
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        chunk = data[offset:offset + 12 + length]
        if kind in (b"IHDR", b"IDAT", b"IEND"):
            result.extend(chunk)
        if kind == b"IHDR":
            payload = b"sRGB\0"
            result.extend(struct.pack(">I", 1) + payload +
                          struct.pack(">I", binascii.crc32(payload) & 0xFFFFFFFF))
        offset += 12 + length
    path.write_bytes(result)


def objc_string(data: bytes, indent: str = "        ") -> str:
    encoded = base64.b64encode(data).decode("ascii")
    chunks = [encoded[i:i + 96] for i in range(0, len(encoded), 96)]
    return ("\n" + indent).join(f'@"{chunk}"' for chunk in chunks)


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    package = manifest["package"]
    if package.get("id") != "com.dobabaophuc.pulsarcc2.0" or (
        package.get("upstream_commit") != "bd13799"
    ):
        raise SystemExit("Pulsar provenance mismatch")

    supplemental_manifest = prepare_supplemental_artwork()
    package_count = generate_motion_bundle()
    (MOTION_BUNDLE / "SupplementalRoutes.json").write_text(
        json.dumps(supplemental_manifest, indent=2) + "\n", encoding="utf-8")

    paths = sorted({path for standard, selected, _, _ in ARTWORK.values()
                    for path in (standard, selected)}, key=str)
    variables: dict[Path, str] = {}
    lines = [
        "// Generated by scripts/generate_pulsar_controlcenter_artwork.py.",
        "// Official Pulsar v2.0 source commit bd13799 + pinned user supplements; do not hand edit.",
        "",
        "NSDictionary<NSString *, NSDictionary<NSString *, id> *> *",
        "CNDPulsarControlCenterArtwork(void)",
        "{",
        "    static NSDictionary<NSString *, NSDictionary<NSString *, id> *> *artwork;",
        "    static dispatch_once_t onceToken;",
        "    dispatch_once(&onceToken, ^{",
    ]
    for index, path in enumerate(paths):
        if not path.is_file():
            raise SystemExit(f"missing rendered Pulsar asset: {path}")
        variable = f"asset{index}"
        variables[path] = variable
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.extend([
            f"        // {path.name}: sha256 {digest}",
            f"        NSString *{variable}Base64 =",
            f"        {objc_string(path.read_bytes())};",
            f"        NSData *{variable} = CNDPulsarDecode({variable}Base64);",
        ])
    lines.append("        artwork = @{")
    for kind, (standard, selected, scale, source) in ARTWORK.items():
        fallback = "@YES" if "fallback" in source else "@NO"
        clear_custom = "@YES" if kind == "focus" else "@NO"
        original_rendering = (
            "@YES" if kind.startswith("media") or
            (kind.startswith("focus") and kind in SUPPLEMENTAL_ARTWORK) else "@NO"
        )
        package = PACKAGE_ARTWORK.get(kind)
        lines.extend([
            f'            @"{kind}": @{{',
            f'                @"deliveryAdapter": @"{DELIVERY_ADAPTERS[kind]}",',
            f'                @"standardPNG": {variables[standard]},',
            f'                @"selectedPNG": {variables[selected]},',
            f'                @"scale": @{scale:.1f},',
            f'                @"source": @"{source}",',
            f'                @"compatibilityFallback": {fallback},',
            f'                @"clearCustomGlyphView": {clear_custom},',
            f'                @"originalRendering": {original_rendering},',
            *(
                ['                @"preserveImageViewVisibility": @YES,']
                if kind == "mediaAirPlay" else []
            ),
            *(
                [f'                @"supplementalArtwork": @YES,',
                 f'                @"physicalRoutingStatus": @"'
                 f'{supplemental_physical_status(kind)}",',
                 f'                @"packageSourcePaths": @[{", ".join(chr(64) + json.dumps(name) for name in SUPPLEMENTAL_PACKAGES.get(kind, []))}],']
                if kind in SUPPLEMENTAL_ARTWORK else []
            ),
            *(
                [
                    f'                @"packageName": @"{package[0]}",',
                    f'                @"packageState": '
                    + (f'@"{package[2]}",' if package[2] else "[NSNull null],"),
                ]
                if package
                else []
            ),
            *(
                [f'                @"symbolNames": @[{", ".join(chr(64) + json.dumps(name) for name in SYMBOL_NAMES[kind])}],']
                if kind in SYMBOL_NAMES else []
            ),
            *(
                [f'                @"selectedSymbolNames": @[{", ".join(chr(64) + json.dumps(name) for name in SELECTED_SYMBOL_NAMES[kind])}],']
                if kind in SELECTED_SYMBOL_NAMES else []
            ),
            *(
                [
                    f'                @"singleGlyphPackageName": '
                    f'@"{SINGLE_GLYPH_PACKAGE_ARTWORK[kind]}",',
                ]
                if kind in SINGLE_GLYPH_PACKAGE_ARTWORK
                else []
            ),
            "            },",
        ])
    lines.extend([
        "        };",
        "    });",
        "    return artwork;",
        "}",
        "",
    ])
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(
        f"{OUTPUT.relative_to(ROOT)}: {len(ARTWORK)} mappings, "
        f"{len(paths)} unique assets; "
        f"{MOTION_BUNDLE.relative_to(ROOT)}: {package_count} packages"
    )


if __name__ == "__main__":
    main()
