"""Prove contour compaction retains each symbol's exact binary mask."""

from pathlib import Path
import importlib.util
import json
import random
import xml.etree.ElementTree as ET
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "cc_symbol_contours", ROOT / "scripts/generate_pulsar_cc_catalog_payloads.py"
)
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


def winding_at(contours, x, y):
    winding = 0
    for contour in contours:
        for start, end in zip(contour, contour[1:] + contour[:1]):
            cross = (end[0] - start[0]) * (y - start[1]) - (x - start[0]) * (end[1] - start[1])
            if start[1] <= y < end[1] and cross > 0:
                winding += 1
            elif end[1] <= y < start[1] and cross < 0:
                winding -= 1
    return winding


class PulsarSymbolContourTests(unittest.TestCase):
    def assert_mask_preserved(self, alpha):
        contours = GENERATOR.symbol_mask_contours(alpha)
        self.assertEqual(contours, GENERATOR.symbol_mask_contours(alpha))
        for y in range(-1, len(alpha) + 1):
            for x in range(-1, len(alpha[0]) + 1):
                expected = 0 <= y < len(alpha) and 0 <= x < len(alpha[0]) and alpha[y][x] >= 24
                self.assertEqual(bool(winding_at(contours, x + .5, y + .5)), expected,
                                 f"mask changed at ({x}, {y})")

    def test_holes_diagonal_contacts_and_threshold_boundaries(self):
        for alpha in (
            [[255, 255, 255], [255, 0, 255], [255, 255, 255]],
            [[255, 0], [0, 255]],
            [[0, 255], [255, 0]],
            [[23, 24, 25], [0, 255, 0]],
            [[255] * 8 for _ in range(6)],
        ):
            self.assert_mask_preserved(alpha)
        randomizer = random.Random(23)
        for _ in range(80):
            self.assert_mask_preserved([[randomizer.choice((0, 23, 24, 255))
                                         for _ in range(9)] for _ in range(7)])

    def test_existing_pulsar_masks_preserve_every_filled_cell(self):
        for symbol, resource in GENERATOR.PULSAR_SYMBOLS.items():
            if symbol == "airplay.audio":
                continue
            with self.subTest(symbol=symbol):
                self.assert_mask_preserved(GENERATOR.downsample_alpha(
                    GENERATOR.decode_png_alpha(GENERATOR.ARTWORK / resource)))

    def test_airplay_retains_upstream_art_and_all_size_weight_coverage(self):
        manifest = json.loads((GENERATOR.OUTPUT / "CatalogManifest.json").read_text())
        catalog = next(catalog for catalog in manifest["catalogs"]
                        if catalog["targetPath"] == GENERATOR.CORE_GLYPHS_TARGET)
        provenance = catalog["symbolArtworkProvenance"]["airplay.audio"]
        self.assertEqual(provenance["sourceMainSHA256"], GENERATOR.AIRPLAY_SOURCE_SHA256)
        self.assertTrue(provenance["sourceLightAndDarkIdentical"])
        self.assertTrue(provenance["nativeButtonTintAndBackgroundPreserved"])
        self.assertEqual(provenance["artworkSHA256"],
                         GENERATOR.sha256(GENERATOR.ARTWORK / provenance["artworkResource"]))
        self.assertIn("airplay.audio", catalog["themedSymbolNames"])
        self.assertTrue(catalog["allTargetVectorAndCachedImageVariantsReplaced"])
        self.assertEqual(catalog["compiledLength"], catalog["stockLength"])
        self.assert_mask_preserved(GENERATOR.downsample_alpha(GENERATOR.decode_png_alpha(
            GENERATOR.ARTWORK / provenance["artworkResource"])))

    def test_authored_alpha_planes_are_not_flattened_to_one_opaque_symbol(self):
        alpha = [[0] * 20 + [122] * 40 + [255] * 40]
        self.assertEqual(GENERATOR.source_alpha_levels(alpha), [122, 255])
        layers = GENERATOR.source_alpha_masks(alpha)
        self.assertEqual([level for level, _ in layers], [122, 255])
        self.assertEqual(layers[0][1][0], [0] * 20 + [255] * 40 + [0] * 40)
        self.assertEqual(layers[1][1][0], [0] * 60 + [255] * 40)
        for name in ("wifi", "bluetooth", "qrcode.viewfinder", "flashlight.off.fill"):
            png = GENERATOR.ARTWORK / GENERATOR.PULSAR_SYMBOLS[name]
            svg = GENERATOR.symbol_svg(png, all_sizes=True, all_weights=True)
            document = ET.fromstring(svg)
            namespace = {"svg": "http://www.w3.org/2000/svg"}
            style = document.find("svg:style", namespace).text
            self.assertIn("opacity:0.478431", style)
            groups = document.findall("svg:g[@id='Symbols']/svg:g", namespace)
            self.assertEqual(len(groups), 27)
            for group in groups:
                self.assertGreaterEqual(len(group.findall("svg:path", namespace)), 2)

    def test_flashlight_preserves_full_native_source_resolution(self):
        source = GENERATOR.decode_png_alpha(
            GENERATOR.ARTWORK / GENERATOR.PULSAR_SYMBOLS["flashlight.off.fill"])
        self.assertEqual(max(len(source), len(source[0])), 144)
        self.assertEqual(GENERATOR.downsample_alpha(source, GENERATOR.SYMBOL_MASK_MAXIMUM_DIMENSION), source)

    def test_low_poly_symbols_use_dense_subpixel_contours_without_changing_their_masks(self):
        self.assertEqual(GENERATOR.HIGH_FIDELITY_CONTOUR_SUPERSAMPLING, 8)
        self.assertEqual(GENERATOR.HIGH_FIDELITY_CONTOUR_TOLERANCE, 0.08)
        self.assertEqual(GENERATOR.FLASHLIGHT_CONTOUR_SUPERSAMPLING, 8)
        self.assertEqual(GENERATOR.FLASHLIGHT_CONTOUR_TOLERANCE, 0.08)
        expected = GENERATOR.FLASHLIGHT_SYMBOL_NAMES | {
            name for name, control in GENERATOR.CONNECTIVITY_SYMBOL_CONTROLS.items()
            if control in {"wifi", "bluetooth", "hotspot", "airdrop"}
        }
        self.assertEqual(GENERATOR.HIGH_FIDELITY_CONTOUR_SYMBOL_NAMES, expected)
        for name in expected:
            alpha = GENERATOR.decode_png_alpha(
                GENERATOR.ARTWORK / GENERATOR.PULSAR_SYMBOLS[name])
            legacy_vertices = refined_vertices = 0
            for _, mask in GENERATOR.source_alpha_masks(alpha):
                legacy = [GENERATOR.simplified_contour(
                    contour, GENERATOR.ARTWORK_CONTOUR_TOLERANCE)
                    for contour in GENERATOR.mask_contours(mask)]
                refined = GENERATOR.subpixel_mask_contours(
                    mask, GENERATOR.HIGH_FIDELITY_CONTOUR_SUPERSAMPLING,
                    GENERATOR.HIGH_FIDELITY_CONTOUR_TOLERANCE)
                legacy_vertices += sum(map(len, legacy))
                refined_vertices += sum(map(len, refined))
                self.assertTrue(any(
                    coordinate % 1 for contour in refined for point in contour
                    for coordinate in point))
                for y, row in enumerate(mask):
                    for x, value in enumerate(row):
                        self.assertEqual(
                            bool(winding_at(refined, x + 0.5, y + 0.5)),
                            bool(value),
                            f"{name} opacity plane changed at ({x}, {y})",
                        )
            self.assertGreater(refined_vertices, legacy_vertices * 1.9)

        with self.assertRaises(GENERATOR.GenerationError):
            GENERATOR.subpixel_mask_contours([[255]], 0, 0.2)
        with self.assertRaises(GENERATOR.GenerationError):
            GENERATOR.subpixel_mask_contours([[255]], 4, -0.1)

    def test_connectivity_artwork_scale_does_not_change_native_symbol_guides(self):
        namespace = {"svg": "http://www.w3.org/2000/svg"}
        def guides(svg):
            return {node.attrib["id"]: node.attrib for node in ET.fromstring(svg).findall(
                "svg:g[@id='Guides']/svg:line", namespace) if "margin" not in node.attrib["id"]}
        for name in GENERATOR.CONNECTIVITY_SYMBOL_NAMES:
            with self.subTest(name=name):
                png = GENERATOR.ARTWORK / GENERATOR.PULSAR_SYMBOLS[name]
                base = GENERATOR.symbol_svg(png, all_sizes=True, all_weights=True)
                enlarged = GENERATOR.symbol_svg(png, all_sizes=True, all_weights=True,
                    artwork_scale=GENERATOR.symbol_artwork_scale(name))
                self.assertEqual(guides(base), guides(enlarged))
                self.assertNotEqual(base, enlarged)
                self.assertEqual(ET.fromstring(base).find("svg:style", namespace).text,
                    ET.fromstring(enlarged).find("svg:style", namespace).text)
                layout = GENERATOR.symbol_optical_layout(png, GENERATOR.symbol_artwork_scale(name))
                self.assertTrue(layout["completeAuthoredAlphaInsideSymbolMargins"])
                self.assertEqual(layout["effectiveScale"], GENERATOR.symbol_artwork_scale(name))
        for invalid in (0.74, 2.16):
            with self.assertRaises(GENERATOR.GenerationError):
                GENERATOR.symbol_svg(png, artwork_scale=invalid)

    def test_explicit_control_scales_cover_all_states_and_leave_nonconnectivity_unchanged(self):
        expected = {"wifi": 1.60, "airdrop": 1.60, "bluetooth": 1.60,
                    "cellular": 2.00, "hotspot": 2.15, "satellite": 2.15,
                    "vpn": 1.27, "airplane": .90}
        self.assertEqual(GENERATOR.CONNECTIVITY_CONTROL_ARTWORK_SCALES, expected)
        self.assertEqual(set(GENERATOR.CONNECTIVITY_SYMBOL_CONTROLS), GENERATOR.CONNECTIVITY_SYMBOL_NAMES)
        for name, control in GENERATOR.CONNECTIVITY_SYMBOL_CONTROLS.items():
            self.assertEqual(GENERATOR.symbol_artwork_scale(name), expected[control])
        for name in (set(GENERATOR.PULSAR_SYMBOLS) - GENERATOR.CONNECTIVITY_SYMBOL_NAMES -
                     GENERATOR.FLASHLIGHT_SYMBOL_NAMES):
            self.assertEqual(GENERATOR.symbol_artwork_scale(name), 1.0)
        for name in GENERATOR.FLASHLIGHT_SYMBOL_NAMES:
            self.assertEqual(GENERATOR.symbol_artwork_scale(name), 1.50)
            layout = GENERATOR.symbol_optical_layout(
                GENERATOR.ARTWORK / GENERATOR.PULSAR_SYMBOLS[name], 1.50)
            self.assertTrue(layout["completeAuthoredAlphaInsideSymbolMargins"])

    def test_ink_cropping_is_not_confused_with_truncated_artwork(self):
        source = [[255] * 20 for _ in range(30)]
        self.assertEqual(GENERATOR.rendered_symbol_footprint(source, source)["aspectRoundingErrorPixels"], 0)
        with self.assertRaisesRegex(GENERATOR.GenerationError, "aspect footprint"):
            GENERATOR.rendered_symbol_footprint(source[:15], source)
        # The PNG's sparse antialiased fringe is not an authored opacity plane;
        # the compiler recreates it around the quantized contour. Do not treat
        # its removal from the ink bounds as missing/clipped artwork.
        antialiased = [[0, 0, *row] for row in source]
        antialiased[15][0] = 32
        self.assertEqual(GENERATOR.rendered_symbol_footprint(source, antialiased)["aspectRoundingErrorPixels"], 0)

    def test_connectivity_module_scaling_is_centered_and_capped_before_clipping(self):
        expected = {"AirplaneGlyph": .90, "CellularDataGlyph": 83 / 76, "HotspotGlyph": 77 / 76}
        for name, relative in GENERATOR.CONNECTIVITY_RENDITIONS.items():
            width, height = GENERATOR.CONNECTIVITY_GEOMETRY[name]
            layout = GENERATOR.centered_alpha_layout(GENERATOR.decode_png_alpha(GENERATOR.ARTWORK / relative),
                width, height, GENERATOR.CONNECTIVITY_MODULE_ARTWORK_SCALES[name])
            self.assertEqual(layout["requestedScale"], GENERATOR.CONNECTIVITY_MODULE_ARTWORK_SCALES[name])
            self.assertAlmostEqual(layout["effectiveScale"], expected[name])
            left, bottom, right, top = layout["mappedAlphaBounds"]
            self.assertGreater(left, 0)
            self.assertGreater(bottom, 0)
            self.assertLess(right, width)
            self.assertLess(top, height)
            self.assertAlmostEqual((left + right) / 2, width / 2)
            self.assertAlmostEqual((bottom + top) / 2, height / 2)
            self.assertFalse(layout["sourceAlphaBytesChanged"])
            self.assertFalse(layout["nativeCanvasChanged"])


if __name__ == "__main__":
    unittest.main()
