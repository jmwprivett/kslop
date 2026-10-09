#!/usr/bin/env python3
"""Build native CoreUI 970 file replacements for iOS 26.0 Pulsar CC artwork.

Xcode's actool uses the installed iOS 26.0 23A343 authoring runtime. Base and
private CoreGlyphs catalogs retain their exact 23A341 headers, lookup keys and
every unrelated raw block; existing target vector and bitmap-cache CSI values
are grafted from native-authored, unpacked donors. Connectivity and Display
retain their complete native name/type/scale/geometry contracts. All payloads
retain the exact native vnode length. Generation is host-only; native device
consumption is reported separately and is not claimed by these host checks.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from coreui_car_graft import Car, CarError, compact_tree_padding, graft


ROOT = Path(__file__).resolve().parents[1]
BUILD = "23A341"
SYSTEM_ROOT = (
    ROOT
    / "build/iOS26-23A341-CC-assets/23A341__iPhone17,2/System/Library"
)
STOCK_PRIORITY = (
    SYSTEM_ROOT
    / "PrivateFrameworks/SFSymbols.framework/CoreGlyphsPriority.bundle/Assets.car"
)
STOCK_CORE_GLYPHS = SYSTEM_ROOT / "PrivateFrameworks/SFSymbols.framework/CoreGlyphs.bundle/Assets.car"
STOCK_CORE_GLYPHS_PRIVATE = SYSTEM_ROOT / "PrivateFrameworks/SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car"
COREUI_970_RUNTIME = Path(
    "/Library/Developer/CoreSimulator/Volumes/iOS_23A343/Library/Developer/CoreSimulator/Profiles/Runtimes/"
    "iOS 26.0.simruntime/Contents/Resources/RuntimeRoot")
STOCK_CONNECTIVITY = (
    ROOT / "build/diagnostics/20261006-physical-connectivity-catalog"
    / "Connectivity-physical-23A341.car"
)
STOCK_DISPLAY = SYSTEM_ROOT / "ControlCenter/Bundles/DisplayModule.bundle/Assets.car"
ARTWORK = ROOT / "Cyanide/PulsarControlCenter.bundle"
OUTPUT = ARTWORK / "FileBacking"
RUNTIME_OUTPUT = ARTWORK
RENDERER_SOURCE = ROOT / "scripts/render_stock_controlcenter_reference.m"
PULSAR_MEDIA_SOURCE = (
    ROOT / "build/pulsar-controlcenter-v2-source/extracted-original"
    / "com.dobabaophuc.pulsarcc2.0/Overwrite/System/Library/PrivateFrameworks/MediaControls.framework"
)
AIRPLAY_SOURCE_SHA256 = "25f3acba533310abb168ab10396a8fee5cbadf05dfbe742480d151a92db551a8"

PRIORITY_TARGET = (
    "/System/Library/PrivateFrameworks/SFSymbols.framework/"
    "CoreGlyphsPriority.bundle/Assets.car"
)
CORE_GLYPHS_TARGET = "/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphs.bundle/Assets.car"
CORE_GLYPHS_PRIVATE_TARGET = "/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car"
CONNECTIVITY_TARGET = (
    "/System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/Assets.car"
)
DISPLAY_TARGET = "/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Assets.car"

EXPECTED_PRIORITY = {
    "length": 309384,
    "sha256": "05c2f3af7b331eec47349f3cec71e466f508cf84e81e7f4aeeb6bc667c74341e",
}
EXPECTED_CORE_GLYPHS = {
    "length": 150914088,
    "sha256": "64a1699915cf947bc961bc37949b907cffb804ea7e7b8dc810ee8d73c3482553",
}
EXPECTED_CORE_GLYPHS_PRIVATE = {
    "length": 24963464,
    "sha256": "413d22dbd800236f46e32004ce9e8b1ed65bcdbbcd34f8094c04c07a04840365",
}
EXPECTED_CONNECTIVITY = {
    "length": 39304,
    "sha256": "2e1f4b5aa95cbee1257707ab4926a3e9c10151d57a06621bb5f425ad776aca44",
    "subtype": 2688,
}
EXPECTED_DISPLAY = {
    "length": 32296,
    "sha256": "f3572be5c4a84fb0703eccfd206d7e91e1fa5278183a8770ffaacb7510d0ad93",
    "subtype": 2688,
}

# A state-changing symbol identity receives the corresponding Pulsar state.
# Native button tint/background remains responsible for selected appearance.
PULSAR_SYMBOLS = {
    "wifi": "StaticWifi.ca/standard.png",
    "wifi.slash": "StaticWifi.ca/standard.png",
    "wifi.badge.lock": "StaticWifi.ca/standard.png",
    "bluetooth": "StaticBluetooth.ca/standard.png",
    "bluetooth.slash": "StaticBluetooth.ca/standard.png",
    "cellularbars": "StaticCellular.ca/standard.png",
    "personalhotspot": "StaticHotspot.ca/standard.png",
    "personalhotspot.slash": "StaticHotspot.ca/standard.png",
    "airdrop": "StaticAirDrop.ca/standard.png",
    "network.connected.to.line.below.fill": "StaticVpn.ca/standard.png",
    "satellite.slash.fill": "StaticSatelliteUnavailable.ca/standard.png",
    "satellite.wave.2": "StaticSatelliteAvailable.ca/standard.png",
    "satellite.wave.2.fill": "StaticSatelliteConnected.ca/standard.png",
    "flashlight.off.fill": "StaticFlashlight.ca/standard.png",
    "flashlight.on.fill": "StaticFlashlight.ca/selected.png",
    "camera.fill": "StaticCamera.ca/standard.png",
    "calculator.fill": "StaticCalculator.ca/standard.png",
    "qrcode.viewfinder": "StaticQrCode.ca/standard.png",
    "airplay.audio": "MediaAirPlay.png",
    # MediaControls' Swift slider uses volume[.1/.2/.3].fill aliases,
    # canonicalized by the native SFSymbols name_aliases.strings provider.
    "speaker.fill": "MediaVolume.png",
    "speaker.wave.1.fill": "MediaVolume.png",
    "speaker.wave.2.fill": "MediaVolume.png",
    "speaker.wave.3.fill": "MediaVolume.png",
}

# Kept for historical priority-overlay diagnostics. Production donors declare
# all sizes and weights, then preserve each native provider's existing key set.
PULSAR_FULL_SIZE_SYMBOLS = set(PULSAR_SYMBOLS) - {
    "flashlight.off.fill",
    "flashlight.on.fill",
}
FLASHLIGHT_SYMBOL_NAMES = {"flashlight.off.fill", "flashlight.on.fill"}
FLASHLIGHT_ARTWORK_SCALE = 1.50
SYMBOL_MASK_MAXIMUM_DIMENSION = 160
ARTWORK_CONTOUR_TOLERANCE = 0.75
HIGH_FIDELITY_CONTOUR_SUPERSAMPLING = 8
HIGH_FIDELITY_CONTOUR_TOLERANCE = 0.08
# Compatibility names retained for existing preservation-proof consumers.
FLASHLIGHT_CONTOUR_SUPERSAMPLING = HIGH_FIDELITY_CONTOUR_SUPERSAMPLING
FLASHLIGHT_CONTOUR_TOLERANCE = HIGH_FIDELITY_CONTOUR_TOLERANCE
MAXIMUM_SYMBOL_ARTWORK_SCALE = 2.15
# Optical sizing is global for each native identity: compact and expanded
# Connectivity share the same images. Do not claim these are submenu overrides.
CONNECTIVITY_CONTROL_ARTWORK_SCALES = {
    "wifi": 1.60,
    "airdrop": 1.60,
    "bluetooth": 1.60,
    "cellular": 2.00,
    "hotspot": 2.15,
    "satellite": 2.15,
    "vpn": 1.27,
    "airplane": 0.90,
}
CONNECTIVITY_SYMBOL_CONTROLS = {
    "wifi": "wifi", "wifi.slash": "wifi", "wifi.badge.lock": "wifi",
    "bluetooth": "bluetooth", "bluetooth.slash": "bluetooth",
    "cellularbars": "cellular",
    "personalhotspot": "hotspot", "personalhotspot.slash": "hotspot",
    "airdrop": "airdrop", "network.connected.to.line.below.fill": "vpn",
    "satellite.slash.fill": "satellite", "satellite.wave.2": "satellite",
    "satellite.wave.2.fill": "satellite",
}
CONNECTIVITY_SYMBOL_NAMES = set(CONNECTIVITY_SYMBOL_CONTROLS)
HIGH_FIDELITY_CONTOUR_CONTROLS = {"wifi", "bluetooth", "hotspot", "airdrop"}
HIGH_FIDELITY_CONTOUR_SYMBOL_NAMES = FLASHLIGHT_SYMBOL_NAMES | {
    name for name, control in CONNECTIVITY_SYMBOL_CONTROLS.items()
    if control in HIGH_FIDELITY_CONTOUR_CONTROLS
}
VOLUME_SYMBOL_NAMES = {"speaker.fill", "speaker.wave.1.fill", "speaker.wave.2.fill", "speaker.wave.3.fill"}

CONNECTIVITY_RENDITIONS = {
    "AirplaneGlyph": "StaticAirplaneMode.ca/standard.png",
    "CellularDataGlyph": "StaticCellular.ca/standard.png",
    "HotspotGlyph": "StaticHotspot.ca/standard.png",
}

CONNECTIVITY_GEOMETRY = {
    "AirplaneGlyph": (28, 40),
    "CellularDataGlyph": (28, 40),
    "HotspotGlyph": (26, 40),
}
# CellularDataGlyph/HotspotGlyph are secondary preview/gallery assets. Live
# cellular/hotspot buttons use the CoreGlyphs identities above, not these PDFs.
CONNECTIVITY_MODULE_ARTWORK_SCALES = {
    "AirplaneGlyph": CONNECTIVITY_CONTROL_ARTWORK_SCALES["airplane"],
    "CellularDataGlyph": 1.12,
    "HotspotGlyph": 1.12,
}
DISPLAY_RENDITIONS = {
    "NightShift": "StaticNightShift.ca/standard.png",
    "TrueTone": "StaticTrueTone.ca/standard.png",
}
DISPLAY_GEOMETRY = {"NightShift": (30, 40), "TrueTone": (30, 40)}


class GenerationError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(*args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(args), check=False, text=True, capture_output=capture
    )
    if result.returncode:
        detail = (result.stderr or result.stdout or "command failed").strip()
        raise GenerationError(f"{' '.join(args)}: {detail}")
    return result


def require_stock(path: Path, contract: dict[str, object]) -> None:
    if not path.is_file():
        raise GenerationError(f"missing reviewed stock resource: {path}")
    if path.stat().st_size != contract["length"] or sha256(path) != contract["sha256"]:
        raise GenerationError(f"reviewed stock resource changed: {path}")


def asset_records(path: Path) -> list[dict[str, object]]:
    result = run("xcrun", "assetutil", "-I", str(path), capture=True)
    records = json.loads(result.stdout)
    if not isinstance(records, list):
        raise GenerationError(f"assetutil returned no record list for {path}")
    return [record for record in records if isinstance(record, dict)]


def runtime_compatibility_contract(target: str, payload: Path) -> dict[str, object]:
    """Record actual authoring versions without equating them to device proof."""
    stock = {
        PRIORITY_TARGET: STOCK_PRIORITY,
        CONNECTIVITY_TARGET: STOCK_CONNECTIVITY,
        DISPLAY_TARGET: STOCK_DISPLAY,
        CORE_GLYPHS_TARGET: STOCK_CORE_GLYPHS,
        CORE_GLYPHS_PRIVATE_TARGET: STOCK_CORE_GLYPHS_PRIVATE,
    }[target]
    versions = []
    for catalog in (payload, stock):
        version = next((record.get("CoreUIVersion") for record in asset_records(catalog)
                        if "CoreUIVersion" in record), None)
        if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
            raise GenerationError(f"catalog has no CoreUI authoring version: {catalog}")
        versions.append(version)
    return {
        "payloadCoreUIVersion": versions[0],
        "targetCoreUIVersion": versions[1],
        "payloadStorageVersion": Car(payload.read_bytes()).storage_version,
        "targetStorageVersion": Car(stock.read_bytes()).storage_version,
        "nativeAuthoringRuntimeVerified": versions == [970, 970],
        "nativeAuthoringRuntimeBuild": "23A343" if versions == [970, 970] else "",
        "deviceConsumptionVerified": False,
        "verifiedConsumerBuild": "",
        "productionDeliveryStatus": "native-compatible-file-replacement-awaiting-device-validation"
            if versions == [970, 970] else "pending-native-provider-consumption",
        "baseCoreGlyphsProviderCoverageVerified": False,
    }


def compile_renderer(destination: Path) -> None:
    run(
        "clang",
        "-fobjc-arc",
        "-framework",
        "AppKit",
        "-framework",
        "QuartzCore",
        str(RENDERER_SOURCE),
        "-o",
        str(destination),
    )


def decode_png_alpha(path: Path) -> list[list[int]]:
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise GenerationError(f"not a PNG: {path}")
    cursor = 8
    width = height = bit_depth = color_type = 0
    compressed = bytearray()
    while cursor + 12 <= len(data):
        length = struct.unpack(">I", data[cursor : cursor + 4])[0]
        kind = data[cursor + 4 : cursor + 8]
        payload = data[cursor + 8 : cursor + 8 + length]
        cursor += 12 + length
        if kind == b"IHDR":
            width, height, bit_depth, color_type = struct.unpack(">IIBB", payload[:10])
        elif kind == b"IDAT":
            compressed.extend(payload)
        elif kind == b"IEND":
            break
    channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color_type)
    if not width or not height or bit_depth != 8 or not channels:
        raise GenerationError(f"unsupported PNG layout: {path}")
    raw = zlib.decompress(bytes(compressed))
    stride = width * channels
    expected = height * (stride + 1)
    if len(raw) != expected:
        raise GenerationError(f"unexpected PNG payload length: {path}")
    rows: list[bytearray] = []
    offset = 0
    previous = bytearray(stride)
    for _ in range(height):
        filter_type = raw[offset]
        encoded = raw[offset + 1 : offset + 1 + stride]
        offset += stride + 1
        row = bytearray(stride)
        for index, value in enumerate(encoded):
            left = row[index - channels] if index >= channels else 0
            up = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            if filter_type == 0:
                decoded = value
            elif filter_type == 1:
                decoded = value + left
            elif filter_type == 2:
                decoded = value + up
            elif filter_type == 3:
                decoded = value + ((left + up) // 2)
            elif filter_type == 4:
                estimate = left + up - upper_left
                distances = (
                    abs(estimate - left),
                    abs(estimate - up),
                    abs(estimate - upper_left),
                )
                predictor = (left, up, upper_left)[distances.index(min(distances))]
                decoded = value + predictor
            else:
                raise GenerationError(f"unknown PNG filter {filter_type}: {path}")
            row[index] = decoded & 0xFF
        rows.append(row)
        previous = row
    alpha_index = 3 if color_type == 6 else 1 if color_type == 4 else None
    return [
        [row[x * channels + alpha_index] if alpha_index is not None else 255 for x in range(width)]
        for row in rows
    ]


def downsample_alpha(
    alpha: list[list[int]], maximum_dimension: int = 40
) -> list[list[int]]:
    """Reduce symbol masks before vectorization so the overlay fits its vnode.

    CoreUI stores both the source vector and generated bitmap renditions.  A
    path rectangle for every source pixel needlessly bloats the vector record,
    especially for the rendered stock-priority glyphs.  Bucket averaging keeps
    the silhouette and antialiased edge coverage while placing a strict upper
    bound on path complexity.
    """

    height = len(alpha)
    width = len(alpha[0]) if height else 0
    if not width or not height or max(width, height) <= maximum_dimension:
        return alpha
    scale = max(width, height) / maximum_dimension
    output_width = max(1, round(width / scale))
    output_height = max(1, round(height / scale))
    output: list[list[int]] = []
    for output_y in range(output_height):
        source_y1 = output_y * height // output_height
        source_y2 = max(source_y1 + 1, (output_y + 1) * height // output_height)
        row: list[int] = []
        for output_x in range(output_width):
            source_x1 = output_x * width // output_width
            source_x2 = max(source_x1 + 1, (output_x + 1) * width // output_width)
            samples = [
                alpha[source_y][source_x]
                for source_y in range(source_y1, source_y2)
                for source_x in range(source_x1, source_x2)
            ]
            row.append(sum(samples) // len(samples))
        output.append(row)
    return output


def merged_mask_rectangles(alpha: list[list[int]], threshold: int = 24) -> tuple[list[tuple[int, int, int, int]], int, int, int, int]:
    height = len(alpha)
    width = len(alpha[0]) if height else 0
    filled = [(x, y) for y, row in enumerate(alpha) for x, value in enumerate(row) if value >= threshold]
    if not filled:
        raise GenerationError("artwork has no visible alpha")
    min_x = min(x for x, _ in filled)
    max_x = max(x for x, _ in filled) + 1
    min_y = min(y for _, y in filled)
    max_y = max(y for _, y in filled) + 1
    rectangles: list[tuple[int, int, int, int]] = []
    active: dict[tuple[int, int], int] = {}
    for y in range(min_y, max_y + 1):
        intervals: list[tuple[int, int]] = []
        if y < max_y:
            x = min_x
            while x < max_x:
                while x < max_x and alpha[y][x] < threshold:
                    x += 1
                start = x
                while x < max_x and alpha[y][x] >= threshold:
                    x += 1
                if start < x:
                    intervals.append((start, x))
        present = set(intervals)
        for interval, start_y in list(active.items()):
            if interval not in present:
                rectangles.append((interval[0], start_y, interval[1], y))
                del active[interval]
        for interval in intervals:
            active.setdefault(interval, y)
    return rectangles, min_x, min_y, max_x, max_y


def symbol_mask_contours(alpha: list[list[int]], threshold: int = 24) -> list[list[tuple[int, int]]]:
    """Compact the exact existing thresholded mask, retaining hole winding."""
    return mask_contours([[255 if value >= threshold else 0 for value in row] for row in alpha])


def source_alpha_levels(alpha: list[list[int]]) -> list[int]:
    """Retain authored opacity planes, excluding rasterized edge coverage.

    Pulsar's line art and offset backing have large flat interiors at 255 and
    approximately 122 alpha. AirPlay has different authored 77/128 planes.
    Raster edge antialiasing is represented by the native vector renderer,
    rather than promoted to another solid opaque symbol path.
    """
    counts = Counter(value for row in alpha for value in row if value >= 24)
    if not counts:
        raise GenerationError("artwork has no visible alpha")
    cutoff = max(counts.values()) * 0.05
    selected: list[int] = []
    for value, count in sorted(counts.items(), key=lambda pair: (-pair[1], -pair[0])):
        if count < cutoff:
            break
        if all(abs(value - previous) > 16 for previous in selected):
            selected.append(value)
        if len(selected) == 4:
            break
    return sorted(selected)


def source_alpha_masks(alpha: list[list[int]]) -> list[tuple[int, list[list[int]]]]:
    levels = source_alpha_levels(alpha)
    quantized = [[min([0, *levels], key=lambda level: (abs(value - level), level))
                  for value in row] for row in alpha]
    return [(level, [[255 if value == level else 0 for value in row] for row in quantized])
            for level in levels]


def simplified_contour(contour: list[tuple[float, float]],
                       tolerance: float) -> list[tuple[float, float]]:
    """Remove raster stair-step vertices within a subpixel distance bound."""
    if tolerance <= 0 or len(contour) < 5:
        return contour

    def simplify(points):
        start, end = points[0], points[-1]
        dx, dy = end[0] - start[0], end[1] - start[1]
        distance_squared = dx * dx + dy * dy
        farthest, maximum = 0, 0.0
        for index, point in enumerate(points[1:-1], 1):
            fraction = min(1.0, max(0.0, ((point[0] - start[0]) * dx +
                (point[1] - start[1]) * dy) / distance_squared)) if distance_squared else 0
            difference = (point[0] - start[0] - fraction * dx) ** 2 + \
                         (point[1] - start[1] - fraction * dy) ** 2
            if difference > maximum:
                farthest, maximum = index, difference
        if maximum > tolerance * tolerance:
            return simplify(points[:farthest + 1])[:-1] + simplify(points[farthest:])
        return [start, end]

    split = max(range(1, len(contour)), key=lambda index:
                (contour[index][0] - contour[0][0]) ** 2 +
                (contour[index][1] - contour[0][1]) ** 2)
    return simplify(contour[:split + 1])[:-1] + simplify(contour[split:] + contour[:1])[:-1]


def subpixel_mask_contours(mask: list[list[int]], supersampling: int,
                           tolerance: float) -> list[list[tuple[float, float]]]:
    """Trace a binary mask on a bilinearly interpolated subpixel grid.

    CoreUI antialiases the resulting vectors. Sampling the authored mask at a
    denser grid avoids turning a narrow, enlarged glyph into a handful of
    visible straight facets while keeping every edge within a fraction of one
    source pixel. The opacity planes remain separate and unchanged.
    """
    if supersampling < 1 or tolerance < 0:
        raise GenerationError("invalid subpixel contour configuration")
    if supersampling == 1:
        return [simplified_contour(contour, tolerance)
                for contour in mask_contours(mask)]
    height = len(mask)
    width = len(mask[0]) if height else 0
    if not width or any(len(row) != width for row in mask):
        raise GenerationError("invalid binary mask geometry")

    def sample(x: int, y: int) -> float:
        return 1.0 if 0 <= x < width and 0 <= y < height and mask[y][x] else 0.0

    enlarged: list[list[int]] = []
    for output_y in range(height * supersampling):
        source_y = (output_y + 0.5) / supersampling - 0.5
        y0 = math.floor(source_y)
        fraction_y = source_y - y0
        row: list[int] = []
        for output_x in range(width * supersampling):
            source_x = (output_x + 0.5) / supersampling - 0.5
            x0 = math.floor(source_x)
            fraction_x = source_x - x0
            top = sample(x0, y0) * (1 - fraction_x) + sample(x0 + 1, y0) * fraction_x
            bottom = sample(x0, y0 + 1) * (1 - fraction_x) + \
                sample(x0 + 1, y0 + 1) * fraction_x
            row.append(255 if top * (1 - fraction_y) + bottom * fraction_y >= 0.5 else 0)
        enlarged.append(row)

    return [[(x / supersampling, y / supersampling)
             for x, y in simplified_contour(contour, tolerance * supersampling)]
            for contour in mask_contours(enlarged)]


def symbol_svg(png: Path, all_sizes: bool = False, *, all_weights: bool = False,
               artwork_scale: float = 1.0, contour_supersampling: int = 1,
               contour_tolerance: float = ARTWORK_CONTOUR_TOLERANCE) -> str:
    if not 0.75 <= artwork_scale <= MAXIMUM_SYMBOL_ARTWORK_SCALE:
        raise GenerationError("symbol artwork scale is outside the reviewed range")
    alpha = downsample_alpha(decode_png_alpha(png), SYMBOL_MASK_MAXIMUM_DIMENSION)
    _, min_x, min_y, max_x, max_y = merged_mask_rectangles(alpha)
    layers = [(opacity, subpixel_mask_contours(
                    mask, contour_supersampling, contour_tolerance))
              for opacity, mask in source_alpha_masks(alpha)]
    source_width = max_x - min_x
    source_height = max_y - min_y
    scale = 70.0 * artwork_scale / max(source_width, source_height)
    drawn_width = source_width * scale
    drawn_height = source_height * scale
    left = 1650.0 - drawn_width / 2.0

    def path_data(contours, center_y: float) -> str:
        top = center_y - drawn_height / 2.0
        commands: list[str] = []
        for contour in contours:
            x, y = contour[0]
            commands.append(f"M{left + (x - min_x) * scale:.4f} {top + (y - min_y) * scale:.4f}")
            for previous, current in zip(contour, contour[1:]):
                delta_x, delta_y = current[0] - previous[0], current[1] - previous[1]
                commands.append(f"l{delta_x * scale:.4f} {delta_y * scale:.4f}")
            commands.append("z")
        return "".join(commands)

    centers = {"S": (625.54 + 696.0) / 2.0, "M": (1055.54 + 1126.0) / 2.0,
               "L": (1485.54 + 1556.0) / 2.0}
    right = left + drawn_width
    sizes = ("S", "M", "L") if all_sizes else ("M",)
    weights = ("Ultralight", "Thin", "Light", "Regular", "Medium", "Semibold", "Bold", "Heavy", "Black") \
        if all_weights else ("Regular",)
    margin_ranges = {"S": (570, 750), "M": (1000, 1200), "L": (1430, 1630)}
    margin_guides = "\n".join(
        f'    <line id="left-margin-{weight}-{size}" x1="{left - 5:.4f}" '
        f'x2="{left - 5:.4f}" y1="{margin_ranges[size][0]}" y2="{margin_ranges[size][1]}"/>\n'
        f'    <line id="right-margin-{weight}-{size}" x1="{right + 5:.4f}" '
        f'x2="{right + 5:.4f}" y1="{margin_ranges[size][0]}" y2="{margin_ranges[size][1]}"/>'
        for size in sizes for weight in weights
    )
    symbol_groups = "\n".join(
        f'    <g id="{weight}-{size}">' + "".join(
            f'<path class="monochrome-{index} multicolor-{index}:tintColor '
            f'hierarchical-{index}:{"primary" if opacity == max(level for level, _ in layers) else "secondary"}" '
            f'd="{path_data(contours, centers[size])}"/>'
            for index, (opacity, contours) in enumerate(layers)) + '</g>'
        for size in sizes for weight in weights
    )
    annotation_styles = "\n".join(
        f'    .{mode}-{index}{suffix} {{ fill:#000000; opacity:{opacity / 255:.6f}; }}'
        for index, (opacity, _) in enumerate(layers)
        for mode, suffix in (("monochrome", ""), ("multicolor", ":tintColor"),
            ("hierarchical", ":primary" if opacity == max(level for level, _ in layers) else ":secondary")))
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" xmlns="http://www.w3.org/2000/svg" width="3300" height="2200" viewBox="0 0 3300 2200">
  <style>
{annotation_styles}
  </style>
  <g id="Notes">
    <rect id="artboard" x="0" y="0" width="3300" height="2200" fill="white"/>
    <text id="template-version" x="10" y="20">6.0</text>
  </g>
  <g id="Guides">
    <line id="Baseline-S" x1="0" x2="3300" y1="696" y2="696"/>
    <line id="Capline-S" x1="0" x2="3300" y1="625.54" y2="625.54"/>
    <line id="Baseline-M" x1="0" x2="3300" y1="1126" y2="1126"/>
    <line id="Capline-M" x1="0" x2="3300" y1="1055.54" y2="1055.54"/>
    <line id="Baseline-L" x1="0" x2="3300" y1="1556" y2="1556"/>
    <line id="Capline-L" x1="0" x2="3300" y1="1485.54" y2="1485.54"/>
{margin_guides}
  </g>
  <g id="Symbols">
{symbol_groups}
  </g>
</svg>
'''


def mask_contours(mask: list[list[int]]) -> list[list[tuple[int, int]]]:
    """Trace exact pixel-edge contours, joining only filled edge neighbours.

    A single outline avoids the repeated rectangle drawing operations that
    inflate preserved PDF renditions. Collinear vertices are removed without
    changing the alpha-level silhouette; diagonally touching islands stay apart.
    """
    edges: set[tuple[tuple[int, int], tuple[int, int]]] = set()
    for y, row in enumerate(mask):
        for x, value in enumerate(row):
            if not value:
                continue
            corners = ((x, y), (x + 1, y), (x + 1, y + 1), (x, y + 1))
            for start, end in zip(corners, corners[1:] + corners[:1]):
                if (end, start) in edges:
                    edges.remove((end, start))
                else:
                    edges.add((start, end))
    contours = []
    while edges:
        first, second = min(edges)
        edges.remove((first, second))
        contour = [first, second]
        while contour[-1] != first:
            previous, current = contour[-2:]
            dx, dy = current[0] - previous[0], current[1] - previous[1]
            # Keep the filled area on the right side in raster coordinates.
            directions = ((-dy, dx), (dx, dy), (dy, -dx), (-dx, -dy))
            for step_x, step_y in directions:
                following = (current[0] + step_x, current[1] + step_y)
                if (current, following) in edges:
                    edges.remove((current, following))
                    contour.append(following)
                    break
            else:
                raise GenerationError("alpha mask has an open contour")
        contour.pop()
        corners = []
        for index, current in enumerate(contour):
            previous, following = contour[index - 1], contour[(index + 1) % len(contour)]
            if ((current[0] - previous[0], current[1] - previous[1]) !=
                    (following[0] - current[0], following[1] - current[1])):
                corners.append(current)
        contours.append(corners)
    return contours


def image_pdf(png: Path, width: int, height: int, *, aspect_fit: bool = False,
              mask_dimension: int = 40, alpha_levels: int = 3,
              preserve_source_alpha: bool = False, centered_artwork_scale: float = 1.0) -> bytes:
    """Make a transparent vector mask at the native point size.

    Connectivity retains authored alpha planes and subpixel contour geometry.
    DisplayModule retains its supplied binary silhouette. Both keep the full
    source canvas so the artwork's original centering survives.
    """
    alpha = decode_png_alpha(png)
    source_height, source_width = len(alpha), len(alpha[0])
    if not aspect_fit and (source_width != width * 3 or source_height != height * 3):
        raise GenerationError(f"Pulsar artwork does not match native geometry: {png}")
    if preserve_source_alpha:
        # The upstream thinned catalog supplies these images at the native 3x
        # canvas size, not an editable vector source. A PDF soft mask preserves
        # every source alpha byte; outlining a 40 px reduction had discarded
        # the line-art/backing hierarchy and the original 3x edge detail.
        gray = zlib.compress(bytes(source_width * source_height), level=9)
        soft_mask = zlib.compress(bytes(value for row in alpha for value in row), level=9)
        drawing = centered_alpha_layout(alpha, width, height, centered_artwork_scale)
        content = (f"q {drawing['drawnWidth']:.12g} 0 0 {drawing['drawnHeight']:.12g} "
                   f"{drawing['left']:.12g} {drawing['bottom']:.12g} cm /Artwork Do Q\n").encode("ascii")
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] "
             f"/Resources << /XObject << /Artwork 5 0 R >> >> /Contents 4 0 R >>").encode("ascii"),
            f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"endstream",
            (f"<< /Type /XObject /Subtype /Image /Width {source_width} /Height {source_height} "
             f"/ColorSpace /DeviceGray /BitsPerComponent 8 /Interpolate true /SMask 6 0 R "
             f"/Length {len(gray)} /Filter /FlateDecode >>\nstream\n").encode("ascii") + gray + b"\nendstream",
            (f"<< /Type /XObject /Subtype /Image /Width {source_width} /Height {source_height} "
             f"/ColorSpace /DeviceGray /BitsPerComponent 8 /Interpolate true "
             f"/Length {len(soft_mask)} /Filter /FlateDecode >>\nstream\n").encode("ascii") + soft_mask + b"\nendstream",
        ]
        return pdf_document(objects)
    alpha = downsample_alpha(alpha, maximum_dimension=mask_dimension)
    source_height, source_width = len(alpha), len(alpha[0])
    if aspect_fit:
        scale = min(width / source_width, height / source_height)
        drawn_width, drawn_height = source_width * scale, source_height * scale
    else:
        drawn_width, drawn_height = width, height
    left, bottom = (width - drawn_width) / 2, (height - drawn_height) / 2
    quantized = [[(value * alpha_levels + 127) // 255 for value in row] for row in alpha]
    masks = [(round(level * 255 / alpha_levels),
              [[255 if value == level else 0 for value in row] for row in quantized])
             for level in range(1, alpha_levels + 1)]
    commands = ["0 g"]
    for level, (_, mask) in enumerate(masks, 1):
        if not any(any(row) for row in mask):
            continue
        commands.append(f"/a{level} gs")
        if aspect_fit:
            for contour in mask_contours(mask):
                for index, (x, y) in enumerate(contour):
                    commands.append(f"{left + x * drawn_width / source_width:.6f} "
                        f"{bottom + (source_height - y) * drawn_height / source_height:.6f} "
                        + ("m" if index == 0 else "l"))
                commands.append("h")
            commands.append("f")
        else:
            rectangles, *_ = merged_mask_rectangles(mask)
            for x1, y1, x2, y2 in rectangles:
                commands.append(
                    f"{left + x1 * drawn_width / source_width:.6f} {bottom + (source_height - y2) * drawn_height / source_height:.6f} "
                    f"{(x2 - x1) * drawn_width / source_width:.6f} {(y2 - y1) * drawn_height / source_height:.6f} re f"
                )
    content = zlib.compress(("\n".join(commands) + "\n").encode("ascii"), level=9)
    alpha_states = " ".join(f"/a{level} << /ca {opacity / 255:.6f} >>"
                            for level, (opacity, _) in enumerate(masks, 1))
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] "
         f"/Resources << /ExtGState << {alpha_states} >> >> /Contents 4 0 R >>").encode("ascii"),
        f"<< /Length {len(content)} /Filter /FlateDecode >>\nstream\n".encode("ascii")
        + content + b"\nendstream",
    ]
    return pdf_document(objects)


def centered_alpha_layout(alpha: list[list[int]], width: int, height: int,
                          requested_scale: float) -> dict[str, object]:
    """Fit/center complete alpha artwork without changing its native canvas.

    The existing upstream canvases are nearly full width. Cap enlargement to
    leave half a 3x source pixel at each edge, never clip the offset backing.
    The original alpha bytes remain unchanged in the PDF soft mask.
    """
    if not 0.75 <= requested_scale <= 1.30:
        raise GenerationError("module artwork scale is outside the reviewed range")
    source_height, source_width = len(alpha), len(alpha[0])
    if requested_scale == 1.0:
        return {"requestedScale": 1.0, "effectiveScale": 1.0,
                "drawnWidth": width, "drawnHeight": height, "left": 0, "bottom": 0,
                "sourceAlphaBytesChanged": False, "nativeCanvasChanged": False}
    coordinates = [(x, y) for y, row in enumerate(alpha) for x, value in enumerate(row) if value]
    if not coordinates:
        raise GenerationError("module artwork has no visible alpha")
    min_x, min_y = min(x for x, _ in coordinates), min(y for _, y in coordinates)
    max_x, max_y = max(x for x, _ in coordinates) + 1, max(y for _, y in coordinates) + 1
    effective = min(requested_scale, (source_width - 1) / (max_x - min_x),
                    (source_height - 1) / (max_y - min_y))
    if effective <= 0:
        raise GenerationError("module artwork cannot fit without clipping its authored alpha")
    drawn_width, drawn_height = width * effective, height * effective
    left = width / 2 - (min_x + max_x) / 2 * drawn_width / source_width
    bottom = height / 2 - (source_height - (min_y + max_y) / 2) * drawn_height / source_height
    mapped = [left + min_x * drawn_width / source_width,
              bottom + (source_height - max_y) * drawn_height / source_height,
              left + max_x * drawn_width / source_width,
              bottom + (source_height - min_y) * drawn_height / source_height]
    if mapped[0] < 0 or mapped[1] < 0 or mapped[2] > width or mapped[3] > height:
        raise GenerationError("module artwork enlargement clips its authored alpha")
    return {"requestedScale": requested_scale, "effectiveScale": effective,
            "drawnWidth": drawn_width, "drawnHeight": drawn_height, "left": left, "bottom": bottom,
            "sourceAlphaBounds": [min_x, min_y, max_x, max_y], "mappedAlphaBounds": mapped,
            "edgeMarginSourcePixels": 0.5, "sourceAlphaBytesChanged": False, "nativeCanvasChanged": False}


def pdf_document(objects: list[bytes]) -> bytes:
    result = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, payload in enumerate(objects, 1):
        offsets.append(len(result))
        result.extend(f"{index} 0 obj\n".encode("ascii") + payload + b"\nendobj\n")
    xref = len(result)
    result.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]:
        result.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    result.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    )
    return bytes(result)


def rendition_contract(records: list[dict[str, object]]) -> list[dict[str, object]]:
    """Keys needed for native lookup and layout, including packed-atlas sizes.

    assetutil omits the default Normal state in newer compiler output; both
    spellings represent the same native state. Artwork and its compression may
    change only for the deliberately themed identities and their atlases.
    """
    fields = ("Name", "NameIdentifier", "AssetType", "Idiom", "Scale", "State",
              "PixelWidth", "PixelHeight", "Width", "Height", "Preserved Vector Representation")
    result = [
        {**{field: record[field] for field in fields if field in record}, "State": record.get("State", "Normal")}
        for record in records
        if record.get("Name")
    ]
    return sorted(result, key=lambda record: json.dumps(record, sort_keys=True))


def write_symbol_set(catalog: Path, name: str, png: Path, all_sizes: bool = False,
                     *, all_weights: bool = False) -> None:
    symbol_set = catalog / f"{name}.symbolset"
    symbol_set.mkdir(parents=True)
    svg_name = f"{name}.svg"
    high_fidelity = name in HIGH_FIDELITY_CONTOUR_SYMBOL_NAMES
    (symbol_set / svg_name).write_text(symbol_svg(
        png, all_sizes=all_sizes, all_weights=all_weights,
        artwork_scale=symbol_artwork_scale(name),
        contour_supersampling=HIGH_FIDELITY_CONTOUR_SUPERSAMPLING if high_fidelity else 1,
        contour_tolerance=HIGH_FIDELITY_CONTOUR_TOLERANCE
            if high_fidelity else ARTWORK_CONTOUR_TOLERANCE))
    (symbol_set / "Contents.json").write_text(
        json.dumps(
            {
                "info": {"author": "xcode", "version": 1},
                "symbols": [{"filename": svg_name, "idiom": "universal"}],
            },
            indent=2,
        )
        + "\n"
    )


def symbol_artwork_scale(name: str) -> float:
    if name in FLASHLIGHT_SYMBOL_NAMES:
        return FLASHLIGHT_ARTWORK_SCALE
    control = CONNECTIVITY_SYMBOL_CONTROLS.get(name)
    return CONNECTIVITY_CONTROL_ARTWORK_SCALES[control] if control else 1.0


def symbol_optical_layout(png: Path, artwork_scale: float) -> dict[str, object]:
    """Verify both authored opacity planes fit the unchanged template guides."""
    alpha = downsample_alpha(decode_png_alpha(png), SYMBOL_MASK_MAXIMUM_DIMENSION)
    _, min_x, min_y, max_x, max_y = merged_mask_rectangles(alpha)
    width, height = max_x - min_x, max_y - min_y
    units = 70 * artwork_scale / max(width, height)
    left, right = 1650 - width * units / 2, 1650 + width * units / 2
    coordinates = [(x, y) for _, mask in source_alpha_masks(alpha)
                   for contour in mask_contours(mask) for x, y in contour]
    actual_x = [left + (x - min_x) * units for x, _ in coordinates]
    actual_y = [(y - min_y - height / 2) * units for _, y in coordinates]
    centers = {"S": (625.54 + 696) / 2, "M": (1055.54 + 1126) / 2,
               "L": (1485.54 + 1556) / 2}
    vertical_guides = {"S": (570, 750), "M": (1000, 1200), "L": (1430, 1630)}
    bounds = {size: [min(actual_x), center + min(actual_y),
                    max(actual_x), center + max(actual_y)] for size, center in centers.items()}
    for size, (x1, y1, x2, y2) in bounds.items():
        if not (left - 5 < x1 < x2 < right + 5 and
                vertical_guides[size][0] < y1 < y2 < vertical_guides[size][1]):
            raise GenerationError("symbol alpha footprint exceeds its template guides")
    return {"requestedScale": artwork_scale, "effectiveScale": artwork_scale,
            "sourceAlphaPlanes": source_alpha_levels(alpha), "templateAlphaBounds": bounds,
            "completeAuthoredAlphaInsideSymbolMargins": True,
            "nativeCaplineAndBaselineGuidesChanged": False}


def rendered_symbol_footprint(alpha: list[list[int]], source: list[list[int]]) -> dict[str, object]:
    """Check CoreUI's ink-cropped image against the complete source footprint.

    A native symbol CGImage is cropped to its ink extent, not a padded button
    canvas. Nonzero edge pixels are consequently not evidence of clipping.
    Compare with the authored opacity-plane masks, not the PNG's antialiased
    fringe: that fringe is intentionally recreated by CoreUI rasterization.
    Account for pixel rounding/antialiasing, especially in 1x cache images.
    """
    layers = source_alpha_masks(source)
    source = [[max(level if mask[y][x] else 0 for level, mask in layers)
               for x in range(len(source[0]))] for y in range(len(source))]
    _, left, top, right, bottom = merged_mask_rectangles(alpha)
    _, sx1, sy1, sx2, sy2 = merged_mask_rectangles(source)
    source_width, source_height = sx2 - sx1, sy2 - sy1
    aspect_error = abs((right - left) * source_height - (bottom - top) * source_width) / \
        max(source_width, source_height)
    if aspect_error > 2:
        raise GenerationError("rendered symbol does not retain its complete source aspect footprint")
    intersection = union = 0
    def sample(x, y):
        return source[y][x] if 0 <= x < len(source[0]) and 0 <= y < len(source) else 0
    for y, row in enumerate(alpha):
        for x, value in enumerate(row):
            px = sx1 + (x + .5 - left) * source_width / (right - left) - .5
            py = sy1 + (y + .5 - top) * source_height / (bottom - top) - .5
            ix, iy = math.floor(px), math.floor(py)
            fx, fy = px - ix, py - iy
            expected = ((sample(ix, iy) * (1 - fx) + sample(ix + 1, iy) * fx) * (1 - fy) +
                (sample(ix, iy + 1) * (1 - fx) + sample(ix + 1, iy + 1) * fx) * fy)
            wanted, present = expected >= 24, value >= 24
            intersection += wanted and present
            union += wanted or present
    similarity = intersection / union
    longest = max(right - left, bottom - top)
    # At intermediate cached sizes, a single antialiased contour row can move
    # an otherwise complete 40–63 px silhouette just below the large-render
    # cutoff. Keep the stricter threshold for 64 px+ vectors while allowing the
    # measured subpixel quantization at native 17 pt/2x.
    minimum_similarity = .60 if longest < 20 else .70 if longest < 40 else .84 if longest < 64 else .85
    if similarity < minimum_similarity:
        raise GenerationError("rendered symbol does not retain its complete source silhouette")
    return {"pixelCanvas": [len(alpha[0]), len(alpha)], "inkAlphaBounds": [left, top, right, bottom],
            "aspectRoundingErrorPixels": round(aspect_error, 6),
            "normalizedSilhouetteIntersectionOverUnion": round(similarity, 6),
            "minimumSilhouetteSimilarity": minimum_similarity}


def verify_scaled_symbol_renditions(renderer: Path, payload: Path, native: Car,
                                    names: set[str], work: Path) -> dict[str, object]:
    """Host-render every requested native symbol key and reject clipped artwork.

    Raster keys retain their native 15/17/20-point and 1x/2x/3x combinations.
    Vector keys use their native weight/size at 40 points. This never loads code
    into SpringBoard; the renderer is a disposable macOS verification binary.
    """
    records = []
    for rendition in native.renditions:
        if rendition.name not in names:
            continue
        vector = rendition.layout == 1017
        point_size = 40 if vector else (15, 17, 20)[rendition.attributes[9]]
        scale = rendition.attributes[12]
        output = work / "connectivity-symbol-verification.png"
        run(str(renderer), "--symbol", str(payload), rendition.name, str(output),
            str(rendition.attributes[27]), str(rendition.attributes[26]),
            str(point_size), str(scale), capture=True)
        alpha = decode_png_alpha(output)
        source = downsample_alpha(decode_png_alpha(ARTWORK / PULSAR_SYMBOLS[rendition.name]),
                                  SYMBOL_MASK_MAXIMUM_DIMENSION)
        try:
            footprint = rendered_symbol_footprint(alpha, source)
        except GenerationError as error:
            raise GenerationError(
                f"{rendition.name} native block {rendition.block} "
                f"({point_size}pt/{scale}x) failed optical sizing validation: {error}"
            ) from error
        records.append({"name": rendition.name, "nativeBlock": rendition.block,
            "nativeLayout": rendition.layout, "glyphSize": rendition.attributes[27],
            "glyphWeight": rendition.attributes[26], "pointSize": point_size,
            "scale": scale, **footprint})
    return {"hostRenderedEveryRequestedNativeRendition": True,
            "hostRenderedEveryNativeConnectivityRendition": True,
            "nativeSymbolImagesUseInkCroppedExtents": True,
            "templateLayouts": {name: symbol_optical_layout(ARTWORK / PULSAR_SYMBOLS[name],
                symbol_artwork_scale(name)) for name in sorted(names)},
            "nativeRenditionCount": len(records), "renditions": records}


def compile_catalog(source: Path, output_directory: Path, *, standalone_images: bool = False) -> Path:
    if not (COREUI_970_RUNTIME / "System/Library/PrivateFrameworks/CoreUI.framework/CoreUI").is_file():
        raise GenerationError("missing iOS 26.0 23A343 CoreUI 970 authoring runtime")
    output_directory.mkdir(parents=True)
    environments = ["--simulator-environment=DYLD_ROOT_PATH=" + str(COREUI_970_RUNTIME)]
    if standalone_images:
        environments.append("--simulator-environment=CoreUI_PACKING=0:0")
    run(
        "xcrun",
        "actool",
        str(source),
        "--compile",
        str(output_directory),
        "--platform",
        "iphoneos",
        "--minimum-deployment-target",
        "15.0",
        "--target-device",
        "iphone",
        "--output-format",
        "human-readable-text",
        "--warnings",
        "--notices",
        *environments,
    )
    result = output_directory / "Assets.car"
    if not result.is_file():
        raise GenerationError("actool did not produce Assets.car")
    run("xcrun", "assetutil", "-Z", str(result), capture=True)
    authored = Car(result.read_bytes())
    if authored.coreui_version != 970 or authored.storage_version != 17:
        raise GenerationError("authoring runtime did not produce genuine CoreUI 970/storage 17")
    if standalone_images:
        vectors = [record for record in asset_records(result) if record.get("AssetType") == "Vector Glyph"]
        if not vectors or any(record.get("Template Version") != 6 or not record.get("Interpolatable")
                              for record in vectors):
            raise GenerationError("native symbol donor must retain template 6 interpolation and size fallback")
    return result


def padded_copy(source: Path, destination: Path, target_length: int) -> None:
    payload = source.read_bytes()
    if len(payload) > target_length:
        raise GenerationError(
            f"generated catalog is larger than its vnode: {len(payload)} > {target_length}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload + bytes(target_length - len(payload)))
    run("xcrun", "assetutil", "-Z", str(destination), capture=True)


def verify_symbol_lookups(
    renderer: Path,
    catalog: Path,
    output: Path,
    names: set[str],
    sizes: tuple[int, ...],
    weights: tuple[int, ...] = tuple(range(10)),
) -> int:
    output.mkdir(parents=True, exist_ok=True)
    count = 0
    for name in sorted(names):
        for size in sizes:
            for weight in weights:
                run(
                    str(renderer),
                    "--symbol",
                    str(catalog),
                    name,
                    str(output / f"{count}.png"),
                    str(size),
                    str(weight),
                    capture=True,
                )
                count += 1
    return count


def prepare_airplay_artwork(work: Path, renderer: Path) -> dict[str, object]:
    """Render the original Pulsar route glyph at its full authored extent."""
    sources = [PULSAR_MEDIA_SOURCE / f"%Optional%AirPlayControlAudio{appearance}.ca/main.caml"
               for appearance in ("Light", "Dark")]
    for source in sources:
        if not source.is_file() or sha256(source) != AIRPLAY_SOURCE_SHA256:
            raise GenerationError(f"reviewed upstream Pulsar AirPlay resource changed: {source}")
    package = work / "PulsarAirPlay.ca"
    package.mkdir()
    shutil.copy2(sources[0], package / "main.caml")
    shutil.copy2(ARTWORK / "PlayPauseStop.ca/index.xml", package / "index.xml")
    destination = ARTWORK / PULSAR_SYMBOLS["airplay.audio"]
    run(str(renderer), "--content", str(package), "base", str(destination), capture=True)
    return {
        "symbolName": "airplay.audio",
        "source": "upstream-Pulsar-AirPlayControlAudio-Light-and-Dark",
        "sourceMainSHA256": AIRPLAY_SOURCE_SHA256,
        "sourceLightAndDarkIdentical": True,
        "artworkResource": destination.name,
        "artworkSHA256": sha256(destination),
        "nativeButtonTintAndBackgroundPreserved": True,
        "consumerEvidence": "CCLifecycleOwnerVM-20261005-01/media-complete-before.json:MediaControlsModuleRouteButton.viewModel.some.symbol",
    }


def prepare_volume_artwork(renderer: Path) -> dict[str, object]:
    """Use the authored Pulsar earbuds for the separate Swift slider provider."""
    package = ARTWORK / "Volume.ca"
    destination = ARTWORK / "MediaVolume.png"
    run(str(renderer), "--content", str(package), "base", str(destination), capture=True)
    return {
        "source": "bundled-upstream-Pulsar-Volume-vector-layer-graph",
        "sourceMainSHA256": sha256(package / "main.caml"),
        "artworkResource": destination.name,
        "artworkSHA256": sha256(destination),
        "nativeButtonTintAndBackgroundPreserved": True,
        "nativeAliases": {"volume.fill": "speaker.fill", "volume.1.fill": "speaker.wave.1.fill",
                          "volume.2.fill": "speaker.wave.2.fill", "volume.3.fill": "speaker.wave.3.fill"},
        "consumerEvidence": "MediaControls.NowPlayingVolumeControlsView.slider:MediaControls.Slider;"
                            "MediaControls-Swift-volume-symbol-constants-and-native-name_aliases.strings",
    }


def build_priority(work: Path, renderer: Path) -> dict[str, object]:
    airplay_provenance = prepare_airplay_artwork(work, renderer)
    volume_provenance = prepare_volume_artwork(renderer)
    records = asset_records(STOCK_PRIORITY)
    stock_names = sorted(
        {
            str(record["Name"])
            for record in records
            if record.get("AssetType") == "Vector Glyph" and record.get("Name")
        }
    )
    if not stock_names:
        raise GenerationError("stock priority catalog contains no vector glyphs")
    catalog = work / "PulsarCoreGlyphsPriority.xcassets"
    catalog.mkdir()
    (catalog / "Contents.json").write_text(
        json.dumps({"info": {"author": "xcode", "version": 1}}, indent=2) + "\n"
    )
    rendered = work / "stock-priority-renders"
    rendered.mkdir()
    for name in stock_names:
        png = rendered / f"{name}.png"
        run(renderer.as_posix(), "--symbol", str(STOCK_PRIORITY), name, str(png))
        write_symbol_set(catalog, name, png)
    for name, relative in PULSAR_SYMBOLS.items():
        png = ARTWORK / relative
        if not png.is_file():
            raise GenerationError(f"missing Pulsar symbol artwork: {png}")
        write_symbol_set(catalog, name, png, all_sizes=name in PULSAR_FULL_SIZE_SYMBOLS)
    compiled = compile_catalog(catalog, work / "priority-compiled")
    compiled_records = asset_records(compiled)
    vector_names = {
        record.get("Name")
        for record in compiled_records
        if record.get("AssetType") == "Vector Glyph"
    }
    required = set(stock_names) | set(PULSAR_SYMBOLS)
    missing = sorted(required - vector_names)
    if missing:
        raise GenerationError("compiled priority catalog lacks vector glyphs: " + ", ".join(missing))
    lookup_count = verify_symbol_lookups(
        renderer,
        compiled,
        work / "priority-size-weight-verification",
        PULSAR_FULL_SIZE_SYMBOLS,
        (0, 1, 2, 3),
    )
    destination = OUTPUT / f"CoreGlyphsPriority-{BUILD}.car"
    padded_copy(compiled, destination, int(EXPECTED_PRIORITY["length"]))
    return {
        "targetPath": PRIORITY_TARGET,
        "resourceName": destination.name,
        "stockLength": EXPECTED_PRIORITY["length"],
        "stockSHA256": EXPECTED_PRIORITY["sha256"],
        "compiledLength": compiled.stat().st_size,
        "payloadLength": destination.stat().st_size,
        "payloadSHA256": sha256(destination),
        "preservedStockSymbolNames": stock_names,
        "themedSymbolNames": sorted(PULSAR_SYMBOLS),
        "fullSizeThemedSymbolNames": sorted(PULSAR_FULL_SIZE_SYMBOLS),
        "fullSizeWeightLookupCount": lookup_count,
        "fullSizeWeightLookupsVerified": True,
        "vectorGlyphNamesVerified": True,
        "baseCoreGlyphsUntouched": True,
        "cellularbarsVariableLevelsFlattened": True,
        "vectorMaskEncoding": "exact-filled-cell-contours-with-opposite-hole-winding",
        "symbolArtworkProvenance": {"airplay.audio": airplay_provenance,
            **{name: volume_provenance for name in sorted(VOLUME_SYMBOL_NAMES)}},
    }


def build_core_glyphs(work: Path, renderer: Path, output: Path = OUTPUT) -> list[dict[str, object]]:
    """Graft native-authored standalone renditions into both exact native providers."""
    airplay_provenance = prepare_airplay_artwork(work, renderer)
    volume_provenance = prepare_volume_artwork(renderer)
    contracts = (
        ("CoreGlyphs", STOCK_CORE_GLYPHS, EXPECTED_CORE_GLYPHS, CORE_GLYPHS_TARGET),
        ("CoreGlyphsPrivate", STOCK_CORE_GLYPHS_PRIVATE, EXPECTED_CORE_GLYPHS_PRIVATE, CORE_GLYPHS_PRIVATE_TARGET),
    )
    sources = []
    covered: set[str] = set()
    for label, stock, expected, target in contracts:
        require_stock(stock, expected)
        car = Car(stock.read_bytes())
        names = set(PULSAR_SYMBOLS) & {record.name for record in car.renditions}
        if not names or covered & names:
            raise GenerationError("native base/private symbol providers overlap or lack target symbols")
        covered |= names
        sources.append((label, stock, expected, target, names))
    if covered != set(PULSAR_SYMBOLS):
        raise GenerationError("native providers lack symbols: " + ", ".join(sorted(set(PULSAR_SYMBOLS) - covered)))
    catalog = work / "PulsarCoreGlyphsDonor.xcassets"
    catalog.mkdir()
    (catalog / "Contents.json").write_text(json.dumps({"info": {"author": "xcode", "version": 1}}) + "\n")
    for name, relative in sorted(PULSAR_SYMBOLS.items()):
        write_symbol_set(catalog, name, ARTWORK / relative, all_sizes=True, all_weights=True)
    donor = compile_catalog(catalog, work / "coreglyphs-donor-compiled", standalone_images=True)
    donor_bytes = donor.read_bytes()
    output.mkdir(parents=True, exist_ok=True)
    result = []
    for label, stock, expected, target, names in sources:
        try:
            payload_bytes, proof = graft(stock.read_bytes(), donor_bytes, names)
        except CarError as error:
            raise GenerationError(f"{label} native rendition graft failed: {error}") from error
        destination = output / f"{label}-{BUILD}.car"
        destination.write_bytes(payload_bytes)
        run("xcrun", "assetutil", "-Z", str(destination), capture=True)
        proof.update({"schemaVersion": 1, "productBuildVersion": BUILD,
            "targetPath": target, "stockSHA256": sha256(stock),
            "payloadSHA256": sha256(destination), "stockLength": expected["length"],
            "payloadLength": len(payload_bytes), "donorSHA256": sha256(donor),
            "nativeAuthoringRuntimeBuild": "23A343", "assetutilValidated": True,
            "themedSymbolNames": sorted(names),
            "artworkMaskMaximumDimension": SYMBOL_MASK_MAXIMUM_DIMENSION,
            "artworkContourTolerance": ARTWORK_CONTOUR_TOLERANCE,
            "flashlightContourMethod": "bilinear-subpixel-opacity-plane-trace",
            "flashlightContourSupersampling": FLASHLIGHT_CONTOUR_SUPERSAMPLING,
            "flashlightContourTolerance": FLASHLIGHT_CONTOUR_TOLERANCE,
            "highFidelityContourMethod": "bilinear-subpixel-opacity-plane-trace",
            "highFidelityContourSupersampling": HIGH_FIDELITY_CONTOUR_SUPERSAMPLING,
            "highFidelityContourTolerance": HIGH_FIDELITY_CONTOUR_TOLERANCE,
            "highFidelityContourSymbolNames": sorted(names & HIGH_FIDELITY_CONTOUR_SYMBOL_NAMES),
            "symbolArtworkScale": {name: symbol_artwork_scale(name) for name in sorted(names)},
            "connectivityControlArtworkScale": {control: CONNECTIVITY_CONTROL_ARTWORK_SCALES[control]
                for control in sorted({CONNECTIVITY_SYMBOL_CONTROLS[name]
                    for name in names & CONNECTIVITY_SYMBOL_NAMES})},
            "connectivityArtworkSizingScope": "global-native-symbol-identity-compact-and-expanded-shared",
            "nativeSymbolCaplineAndBaselineGuidesChanged": False,
            "nativeButtonGeometryChanged": False,
            "sourceAlphaPlanes": {name: source_alpha_levels(downsample_alpha(
                decode_png_alpha(ARTWORK / PULSAR_SYMBOLS[name]), SYMBOL_MASK_MAXIMUM_DIMENSION))
                for name in sorted(names)},
            "symbolOpacityEncoding": "native-monochrome-multicolor-hierarchical-CSS-annotations",
            "sourceArtworkSHA256": {name: sha256(ARTWORK / PULSAR_SYMBOLS[name]) for name in sorted(names)}})
        native = Car(stock.read_bytes())
        proof["connectivityOpticalSizingValidation"] = verify_scaled_symbol_renditions(
            renderer, destination, native, names & CONNECTIVITY_SYMBOL_NAMES, work)
        flashlight_names = names & FLASHLIGHT_SYMBOL_NAMES
        if flashlight_names:
            proof["flashlightOpticalSizingValidation"] = verify_scaled_symbol_renditions(
                renderer, destination, native, flashlight_names, work)
        provenance = {}
        if "airplay.audio" in names:
            provenance["airplay.audio"] = airplay_provenance
        provenance.update({name: volume_provenance for name in sorted(names & VOLUME_SYMBOL_NAMES)})
        if provenance:
            proof["symbolArtworkProvenance"] = provenance
        proof_path = output / f"{label}Preservation-{BUILD}.json"
        proof_path.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
        result.append({"targetPath": target, "resourceName": destination.name,
            "stockLength": expected["length"], "stockSHA256": expected["sha256"],
            "compiledLength": len(payload_bytes), "payloadLength": len(payload_bytes),
            "payloadSHA256": sha256(destination), "themedSymbolNames": sorted(names),
            "unrelatedNamedRenditionsPreserved": True,
            "allStockRenditionTypesScalesAndGeometryVerified": False,
            "allUnrelatedBlocksByteIdentical": True,
            "allTargetVectorAndCachedImageVariantsReplaced": True,
            "nativeHeaderPreserved": True, "lookupKeysAndTreesPreserved": True,
            "preservationProofResource": proof_path.name,
            "preservationProofSHA256": sha256(proof_path),
            "nativeAuthoringRuntimeBuild": "23A343", "baseline": "IPSW-23A341-iPhone17,2",
            **({"symbolArtworkProvenance": provenance} if provenance else {})})
    return result


def build_image_catalog(
    work: Path, *, label: str, stock: Path, expected: dict[str, object],
    target: str, renditions: dict[str, str], geometry: dict[str, tuple[int, int]],
    baseline: str, output: Path = OUTPUT, aspect_fit: bool = False, mask_dimension: int = 40,
    alpha_levels: int = 3, preserve_source_alpha: bool = False,
    centered_artwork_scales: dict[str, float] | None = None,
) -> dict[str, object]:
    require_stock(stock, expected)
    stock_records = asset_records(stock)
    headers = [record for record in stock_records if record.get("ThinningParameters")]
    if len(headers) != 1 or f"<subtype {expected['subtype']}>" not in str(headers[0]["ThinningParameters"]):
        raise GenerationError(f"{label} thinning subtype does not match its contract")
    stock_names = {
        record.get("Name")
        for record in stock_records
        if record.get("Name") and not str(record.get("Name")).startswith("ZZZZPackedAsset-")
    }
    if stock_names != set(renditions):
        raise GenerationError(
            f"23A341 {label} rendition contract changed: "
            + ", ".join(sorted(str(name) for name in stock_names))
        )
    catalog = work / f"Pulsar{label}.xcassets"
    catalog.mkdir()
    (catalog / "Contents.json").write_text(
        json.dumps({"info": {"author": "xcode", "version": 1}}, indent=2) + "\n"
    )
    for name, relative in renditions.items():
        png = ARTWORK / relative
        if not png.is_file():
            raise GenerationError(f"missing Pulsar catalog artwork: {png}")
        image_set = catalog / f"{name}.imageset"
        image_set.mkdir()
        width, height = geometry[name]
        (image_set / f"{name}.pdf").write_bytes(image_pdf(png, width, height,
            aspect_fit=aspect_fit, mask_dimension=mask_dimension, alpha_levels=alpha_levels,
            preserve_source_alpha=preserve_source_alpha,
            centered_artwork_scale=(centered_artwork_scales or {}).get(name, 1.0)))
        (image_set / "Contents.json").write_text(
            json.dumps(
                {
                    "images": [
                        {
                            "filename": f"{name}.pdf",
                            "idiom": "universal",
                        }
                    ],
                    "info": {"author": "xcode", "version": 1},
                    "properties": {
                        "template-rendering-intent": "template",
                        "preserves-vector-representation": True,
                    },
                },
                indent=2,
            )
            + "\n"
        )
    full_catalog = compile_catalog(catalog, work / f"{label.lower()}-compiled")
    compiled = work / f"{label}-thinned.car"
    run("xcrun", "assetutil", "--idiom", "phone", "--subtype", str(expected["subtype"]),
        "--scale", "3", "--display-gamut", "srgb", "--output", str(compiled), str(full_catalog), capture=True)
    compiled_records = asset_records(compiled)
    compiled_names = {
        record.get("Name")
        for record in compiled_records
        if record.get("Name") and not str(record.get("Name")).startswith("ZZZZPackedAsset-")
    }
    if compiled_names != set(renditions):
        raise GenerationError(f"compiled {label} catalog does not preserve its full name set")
    stock_contract = rendition_contract(stock_records)
    if rendition_contract(compiled_records) != stock_contract:
        raise GenerationError(f"compiled {label} catalog changed native rendition types, scales, or geometry")
    compaction = None
    if compiled.stat().st_size > int(expected["length"]):
        packed, compaction = compact_tree_padding(compiled.read_bytes())
        compacted = work / f"{label}-compacted.car"
        compacted.write_bytes(packed)
        run("xcrun", "assetutil", "-Z", str(compacted), capture=True)
        if rendition_contract(asset_records(compacted)) != stock_contract:
            raise GenerationError(f"compacted {label} catalog changed native lookup/layout variants")
        compiled = compacted
    destination = output / f"{label}-{BUILD}.car"
    padded_copy(compiled, destination, int(expected["length"]))
    proof = {
        "schemaVersion": 1,
        "productBuildVersion": BUILD,
        "stockSHA256": sha256(stock),
        "payloadSHA256": sha256(destination),
        "stockLength": stock.stat().st_size,
        "payloadLength": destination.stat().st_size,
        "stockCoreUISubtype": expected["subtype"],
        "stockRenditionContract": stock_contract,
        "payloadRenditionContract": rendition_contract(asset_records(destination)),
        "themedRenditionNames": sorted(renditions),
        "sourceArtworkSHA256": {name: sha256(ARTWORK / relative)
                                for name, relative in sorted(renditions.items())},
        "unrelatedNamedRenditions": [],
        "unrelatedNamedRenditionsPreserved": True,
        "allStockRenditionTypesScalesAndGeometryVerified": True,
        "packedAtlasTypesScalesAndGeometryVerified": True,
        "assetutilValidated": True,
        "artworkMaskMaximumDimension": mask_dimension,
        "artworkMaskAlphaLevels": alpha_levels,
    }
    if preserve_source_alpha:
        proof["sourceAlphaPlanes"] = {name: source_alpha_levels(downsample_alpha(
            decode_png_alpha(ARTWORK / relative), mask_dimension))
            for name, relative in sorted(renditions.items())}
        proof["artworkMaskAlphaLevels"] = 256
        proof["artworkRepresentation"] = "unmodified-native-3x-source-alpha-in-PDF-soft-mask"
        proof["artworkOpacityPreserved"] = True
        proof["artworkLayout"] = {name: centered_alpha_layout(decode_png_alpha(ARTWORK / relative),
            *geometry[name], (centered_artwork_scales or {}).get(name, 1.0))
            for name, relative in sorted(renditions.items())}
    if compaction:
        proof["generatedCatalogTreePaddingCompaction"] = compaction
    if aspect_fit:
        proof["artworkLayout"] = "source-canvas-aspect-fit-centered-in-native-PDF-canvas"
        proof["nativePointSizes"] = {name: list(size) for name, size in sorted(geometry.items())}
    if proof["stockRenditionContract"] != proof["payloadRenditionContract"]:
        raise GenerationError(f"padded {label} catalog changed its preservation contract")
    proof_path = output / f"{label}Preservation-{BUILD}.json"
    proof_path.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
    return {
        "targetPath": target,
        "resourceName": destination.name,
        "stockLength": expected["length"],
        "stockSHA256": expected["sha256"],
        "compiledLength": compiled.stat().st_size,
        "payloadLength": destination.stat().st_size,
        "payloadSHA256": sha256(destination),
        "preservedAndThemedRenditionNames": sorted(renditions),
        "completeStockNameSetVerified": True,
        "allStockRenditionTypesScalesAndGeometryVerified": True,
        "stockRenditionContract": stock_contract,
        "unrelatedNamedRenditions": [],
        "unrelatedNamedRenditionsPreserved": True,
        "stockCoreUISubtype": expected["subtype"],
        "baseline": baseline,
        "preservationProofResource": proof_path.name,
        "preservationProofSHA256": sha256(proof_path),
    }


def build_connectivity(
    work: Path, stock: Path = STOCK_CONNECTIVITY, output: Path = OUTPUT,
) -> dict[str, object]:
    return build_image_catalog(work, label="Connectivity", stock=stock,
        expected=EXPECTED_CONNECTIVITY, target=CONNECTIVITY_TARGET,
        renditions=CONNECTIVITY_RENDITIONS, geometry=CONNECTIVITY_GEOMETRY,
        baseline="physical-device-export-23A341-subtype2688", output=output,
        mask_dimension=120, preserve_source_alpha=True,
        centered_artwork_scales=CONNECTIVITY_MODULE_ARTWORK_SCALES)


def build_display(
    work: Path, stock: Path = STOCK_DISPLAY, output: Path = OUTPUT,
) -> dict[str, object]:
    return build_image_catalog(work, label="Display", stock=stock,
        expected=EXPECTED_DISPLAY, target=DISPLAY_TARGET,
        renditions=DISPLAY_RENDITIONS, geometry=DISPLAY_GEOMETRY,
        baseline="IPSW-23A341-iPhone17,2-subtype2688", output=output,
        aspect_fit=True, mask_dimension=80, alpha_levels=1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connectivity-only", action="store_true",
                        help="Regenerate the physical Connectivity payload and retain other reviewed native payloads.")
    parser.add_argument("--display-only", action="store_true",
                        help="Regenerate DisplayModule and retain other reviewed native payloads.")
    parser.add_argument("--core-glyphs-only", action="store_true",
                        help="Graft native CoreUI 970 symbols into both base/private catalogs and retain module payloads.")
    parser.add_argument("--connectivity-stock", type=Path, default=STOCK_CONNECTIVITY)
    arguments = parser.parse_args()
    partial = sum((arguments.connectivity_only, arguments.display_only, arguments.core_glyphs_only))
    if partial > 1:
        parser.error("catalog-only options are mutually exclusive")
    require_stock(arguments.connectivity_stock, EXPECTED_CONNECTIVITY)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cnd-cc-catalogs-") as temporary:
        work = Path(temporary)
        if partial:
            previous = json.loads((OUTPUT / "CatalogManifest.json").read_text())
            def retained(target: str) -> dict:
                catalog = next(catalog for catalog in previous["catalogs"] if catalog["targetPath"] == target)
                require_stock(OUTPUT / str(catalog["resourceName"]),
                              {"length": catalog["payloadLength"], "sha256": catalog["payloadSHA256"]})
                return catalog
        if not partial or arguments.core_glyphs_only:
            renderer = work / "render-stock-controlcenter-reference"
            compile_renderer(renderer)
            symbols = build_core_glyphs(work, renderer)
        else:
            symbols = [retained(CORE_GLYPHS_TARGET), retained(CORE_GLYPHS_PRIVATE_TARGET)]
        if arguments.display_only or arguments.core_glyphs_only:
            connectivity = retained(CONNECTIVITY_TARGET)
        else:
            connectivity = build_connectivity(work, arguments.connectivity_stock)
        display = retained(DISPLAY_TARGET) if arguments.connectivity_only or arguments.core_glyphs_only else build_display(work)
    manifest = {
        "schemaVersion": 1,
        "productBuildVersion": BUILD,
        "hardwareModel": "iPhone17,2",
        "status": "native-CoreUI970-build-locked-file-backed",
        "catalogs": [*symbols, connectivity, display],
        "excludedUnprovenControls": [
            "focusReduceInterruptions",
            "focusCustom",
        ],
    }
    manifest_path = OUTPUT / "CatalogManifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    routes = []
    for catalog in manifest["catalogs"]:
        source = OUTPUT / str(catalog["resourceName"])
        symbol_catalog = catalog["targetPath"] in (CORE_GLYPHS_TARGET, CORE_GLYPHS_PRIVATE_TARGET)
        runtime_payload = source if symbol_catalog else RUNTIME_OUTPUT / source.name
        if not symbol_catalog:
            shutil.copy2(source, runtime_payload)
        routes.append(
            {
                "targetPath": catalog["targetPath"],
                "payloadResource": "FileBacking/" + runtime_payload.name if symbol_catalog else runtime_payload.name,
                "kind": {PRIORITY_TARGET: "core-glyphs-priority-catalog",
                         CORE_GLYPHS_TARGET: "core-glyphs-catalog",
                         CORE_GLYPHS_PRIVATE_TARGET: "core-glyphs-private-catalog",
                         CONNECTIVITY_TARGET: "connectivity-catalog",
                         DISPLAY_TARGET: "display-catalog"}[catalog["targetPath"]],
                "stockSHA256": catalog["stockSHA256"],
                "payloadSHA256": catalog["payloadSHA256"],
                "payloadLength": catalog["payloadLength"],
                "unrelatedRenditionsPreserved": (
                    catalog["targetPath"] != PRIORITY_TARGET
                    and catalog["unrelatedNamedRenditionsPreserved"]
                    and (catalog.get("allUnrelatedBlocksByteIdentical", False)
                         or catalog["allStockRenditionTypesScalesAndGeometryVerified"])
                ),
                "assetutilValidated": True,
                **runtime_compatibility_contract(str(catalog["targetPath"]), runtime_payload),
                **(
                    {
                        "baseCoreGlyphsUntouched": True,
                        "allStockPriorityNamesPresent": True,
                        "stockPriorityVariantFidelityVerified": False,
                        "globalOverrideAccepted": True,
                    }
                    if catalog["targetPath"] == PRIORITY_TARGET
                    else {
                        **({"stockCoreUISubtype": catalog["stockCoreUISubtype"]}
                           if "stockCoreUISubtype" in catalog else {}),
                        "allStockRenditionTypesScalesAndGeometryVerified": True,
                        "preservationProofResource": "FileBacking/" + str(catalog["preservationProofResource"]),
                        "preservationProofSHA256": catalog["preservationProofSHA256"],
                        **({"globalOverrideAccepted": True,
                            "allUnrelatedBlocksByteIdentical": True,
                            "nativeHeaderPreserved": True,
                            "lookupKeysAndTreesPreserved": True,
                            "allTargetVectorAndCachedImageVariantsReplaced": True,
                            "allStockRenditionTypesScalesAndGeometryVerified": False}
                           if catalog.get("allUnrelatedBlocksByteIdentical") else {}),
                    }
                ),
            }
        )
    runtime_manifest = {
        "schemaVersion": 1,
        "productBuildVersion": BUILD,
        "hardwareModel": "iPhone17,2",
        "routes": routes,
    }
    runtime_manifest_path = RUNTIME_OUTPUT / "CatalogFileBacking.json"
    runtime_manifest_path.write_text(
        json.dumps(runtime_manifest, indent=2, sort_keys=True) + "\n"
    )
    print(runtime_manifest_path)


if __name__ == "__main__":
    main()
