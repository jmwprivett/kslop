"""Check exact physical catalog provenance, native variants, and regeneration."""

from pathlib import Path
import importlib.util
import json
import math
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "cc_catalog_payloads", ROOT / "scripts/generate_pulsar_cc_catalog_payloads.py"
)
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)
ARTWORK = ROOT / "Cyanide/PulsarControlCenter.bundle"
PHYSICAL_SHA256 = "2e1f4b5aa95cbee1257707ab4926a3e9c10151d57a06621bb5f425ad776aca44"
VM_BASELINE = ROOT / "build/ios26-cc-disk-map/files/connectivity-assets.car"
HOST_ASSETS = sys.platform == "darwin" and shutil.which("xcrun")


class PulsarCCCatalogPayloadTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((ARTWORK / "CatalogFileBacking.json").read_text())
        self.route = next(route for route in self.manifest["routes"]
                          if route["kind"] == "connectivity-catalog")
        self.catalog_manifest = json.loads((GENERATOR.OUTPUT / "CatalogManifest.json").read_text())
        self.catalog = next(catalog for catalog in self.catalog_manifest["catalogs"]
                            if catalog["targetPath"] == GENERATOR.CONNECTIVITY_TARGET)

    def test_production_accepts_only_the_pulled_physical_baseline_and_pinned_payload(self):
        GENERATOR.require_stock(GENERATOR.STOCK_CONNECTIVITY, GENERATOR.EXPECTED_CONNECTIVITY)
        self.assertEqual(self.route["stockSHA256"], PHYSICAL_SHA256)
        self.assertEqual(self.catalog["stockSHA256"], PHYSICAL_SHA256)
        self.assertEqual(self.route["stockCoreUISubtype"], 2688)
        for payload in (ARTWORK / self.route["payloadResource"],
                        GENERATOR.OUTPUT / self.catalog["resourceName"]):
            self.assertEqual(payload.stat().st_size, 39304)
            self.assertEqual(GENERATOR.sha256(payload), self.route["payloadSHA256"])
        self.assertEqual(self.catalog["payloadSHA256"], self.route["payloadSHA256"])
        self.assertTrue(self.route["unrelatedRenditionsPreserved"])
        self.assertTrue(self.route["allStockRenditionTypesScalesAndGeometryVerified"])

    @unittest.skipUnless(HOST_ASSETS, "requires macOS assetutil")
    def test_runtime_contract_records_versions_without_claiming_device_consumption(self):
        for route in self.manifest["routes"]:
            with self.subTest(route=route["kind"]):
                expected = GENERATOR.runtime_compatibility_contract(
                    route["targetPath"], ARTWORK / route["payloadResource"])
                self.assertEqual({key: route[key] for key in expected}, expected)
                self.assertEqual(expected["payloadCoreUIVersion"], 970)
                self.assertEqual(expected["targetCoreUIVersion"], 970)
                self.assertEqual(expected["payloadStorageVersion"], 17)
                self.assertEqual(expected["targetStorageVersion"], 17)
                self.assertTrue(expected["nativeAuthoringRuntimeVerified"])
                self.assertEqual(expected["nativeAuthoringRuntimeBuild"], "23A343")
                self.assertFalse(expected["deviceConsumptionVerified"])
                self.assertFalse(expected["baseCoreGlyphsProviderCoverageVerified"])
                self.assertEqual(expected["verifiedConsumerBuild"], "")

    def test_vm_thinned_and_tampered_baselines_are_rejected(self):
        self.assertEqual(VM_BASELINE.stat().st_size, 39304)
        with self.assertRaisesRegex(GENERATOR.GenerationError, "reviewed stock resource changed"):
            GENERATOR.require_stock(VM_BASELINE, GENERATOR.EXPECTED_CONNECTIVITY)
        with tempfile.TemporaryDirectory(prefix="cnd-cc-catalog-pin-") as temporary:
            changed = Path(temporary) / "changed.car"
            data = bytearray(GENERATOR.STOCK_CONNECTIVITY.read_bytes())
            data[-1] ^= 1
            changed.write_bytes(data)
            with self.assertRaisesRegex(GENERATOR.GenerationError, "reviewed stock resource changed"):
                GENERATOR.build_connectivity(Path(temporary), stock=changed)

    def test_native_providers_cover_every_symbol_without_priority_overlay(self):
        routes = {route["targetPath"] for route in self.manifest["routes"]}
        self.assertNotIn(GENERATOR.PRIORITY_TARGET, routes)
        covered = set()
        for catalog in self.catalog_manifest["catalogs"]:
            if "themedSymbolNames" in catalog:
                self.assertFalse(covered & set(catalog["themedSymbolNames"]))
                covered.update(catalog["themedSymbolNames"])
                self.assertTrue(catalog["nativeHeaderPreserved"])
                self.assertTrue(catalog["allUnrelatedBlocksByteIdentical"])
        self.assertEqual(covered, set(GENERATOR.PULSAR_SYMBOLS))

    def test_hosted_camera_and_calculator_use_their_traced_native_catalogs(self):
        public = next(catalog for catalog in self.catalog_manifest["catalogs"]
                      if catalog["targetPath"] == GENERATOR.CORE_GLYPHS_TARGET)
        private = next(catalog for catalog in self.catalog_manifest["catalogs"]
                       if catalog["targetPath"] == GENERATOR.CORE_GLYPHS_PRIVATE_TARGET)
        self.assertIn("camera.fill", public["themedSymbolNames"])
        self.assertNotIn("camera.fill", private["themedSymbolNames"])
        self.assertIn("calculator.fill", private["themedSymbolNames"])
        self.assertNotIn("calculator.fill", public["themedSymbolNames"])
        backing = json.loads((ARTWORK / "FileBacking.json").read_text())
        self.assertNotIn("camera", backing["excludedKinds"])
        self.assertNotIn("calculator", backing["excludedKinds"])

    def test_preservation_proof_is_hash_pinned_and_covers_every_physical_variant(self):
        path = ARTWORK / self.route["preservationProofResource"]
        self.assertEqual(GENERATOR.sha256(path), self.route["preservationProofSHA256"])
        self.assertEqual(self.catalog["preservationProofSHA256"], self.route["preservationProofSHA256"])
        proof = json.loads(path.read_text())
        self.assertEqual(proof["stockSHA256"], PHYSICAL_SHA256)
        self.assertEqual(proof["payloadSHA256"], self.route["payloadSHA256"])
        self.assertEqual(proof["stockRenditionContract"], proof["payloadRenditionContract"])
        self.assertEqual(len(proof["stockRenditionContract"]), 11)
        self.assertEqual(proof["unrelatedNamedRenditions"], [])
        for name, (width, height) in GENERATOR.CONNECTIVITY_GEOMETRY.items():
            variants = [record for record in proof["stockRenditionContract"] if record["Name"] == name]
            self.assertEqual(len(variants), 3)
            self.assertEqual({(record["AssetType"], record["Scale"]) for record in variants},
                             {("Image", 1), ("Image", 3), ("Vector", 1)})
            for record in variants:
                if record["AssetType"] == "Vector":
                    self.assertEqual((record["Width"], record["Height"]), (width, height))
                else:
                    scale = record["Scale"]
                    self.assertEqual((record["PixelWidth"], record["PixelHeight"]),
                                     (width * scale, height * scale))
                    self.assertTrue(record["Preserved Vector Representation"])
        self.assertEqual({(record["Scale"], record["PixelWidth"], record["PixelHeight"])
                          for record in proof["stockRenditionContract"]
                          if record["AssetType"] == "PackedImage"}, {(1, 90, 44), (3, 254, 124)})
        for name, relative in GENERATOR.CONNECTIVITY_RENDITIONS.items():
            self.assertEqual(proof["sourceArtworkSHA256"][name], GENERATOR.sha256(ARTWORK / relative))
        self.assertEqual(proof["artworkMaskMaximumDimension"], 120)
        self.assertEqual(proof["artworkMaskAlphaLevels"], 256)
        self.assertTrue(proof["artworkOpacityPreserved"])
        self.assertTrue(proof["generatedCatalogTreePaddingCompaction"]["allTreeEntriesPreserved"])

    @unittest.skipUnless(HOST_ASSETS, "requires macOS CoreUI")
    def test_connectivity_catalog_scales_alpha_without_clipping_or_changing_canvas(self):
        with tempfile.TemporaryDirectory(prefix="cnd-cc-alpha-fidelity-") as temporary:
            work = Path(temporary)
            renderer = work / "renderer"
            GENERATOR.compile_renderer(renderer)
            for name, relative in GENERATOR.CONNECTIVITY_RENDITIONS.items():
                with self.subTest(name=name):
                    output = work / f"{name}.png"
                    GENERATOR.run(str(renderer), "--image", str(ARTWORK / self.route["payloadResource"]),
                                  name, str(output), "3", capture=True)
                    expected = GENERATOR.decode_png_alpha(ARTWORK / relative)
                    actual = GENERATOR.decode_png_alpha(output)
                    self.assertEqual((len(actual), len(actual[0])), (len(expected), len(expected[0])))
                    layout = GENERATOR.centered_alpha_layout(expected, *GENERATOR.CONNECTIVITY_GEOMETRY[name],
                        GENERATOR.CONNECTIVITY_MODULE_ARTWORK_SCALES[name])
                    # Compare native rendering against the authored alpha under
                    # the exact reviewed affine map. CoreUI/PDF edge filtering
                    # differs slightly, so use silhouette intersection/union.
                    intersection = union = 0
                    errors = []
                    source_h, source_w = len(expected), len(expected[0])
                    scale = layout["effectiveScale"]
                    offset_x = 3 * layout["left"]
                    offset_y = source_h - source_h * scale - 3 * layout["bottom"]
                    def sample(px, py):
                        return expected[py][px] if 0 <= px < source_w and 0 <= py < source_h else 0
                    for y, row in enumerate(actual):
                        for x, value in enumerate(row):
                            source_x, source_y = (x + .5 - offset_x) / scale - .5, (y + .5 - offset_y) / scale - .5
                            ix, iy = math.floor(source_x), math.floor(source_y)
                            fx, fy = source_x - ix, source_y - iy
                            interpolated = ((sample(ix, iy) * (1 - fx) + sample(ix + 1, iy) * fx) * (1 - fy) +
                                (sample(ix, iy + 1) * (1 - fx) + sample(ix + 1, iy + 1) * fx) * fy)
                            errors.append(abs(interpolated - value))
                            wanted = interpolated >= 24
                            present = value >= 24
                            intersection += wanted and present
                            union += wanted or present
                    self.assertGreater(intersection / union, .95)
                    self.assertLess(sum(errors) / len(errors), 2.5)
                    self.assertFalse(any(actual[0]) or any(actual[-1]))
                    self.assertTrue(any(110 <= value <= 130 for row in actual for value in row))

    def test_swift_volume_symbols_and_connectivity_scale_are_file_backed(self):
        public = next(catalog for catalog in self.catalog_manifest["catalogs"]
                      if catalog["targetPath"] == GENERATOR.CORE_GLYPHS_TARGET)
        proof = json.loads((GENERATOR.OUTPUT / public["preservationProofResource"]).read_text())
        self.assertTrue(GENERATOR.VOLUME_SYMBOL_NAMES <= set(public["themedSymbolNames"]))
        for name in GENERATOR.VOLUME_SYMBOL_NAMES:
            provenance = public["symbolArtworkProvenance"][name]
            self.assertEqual(provenance["sourceMainSHA256"], GENERATOR.sha256(ARTWORK / "Volume.ca/main.caml"))
            self.assertEqual(provenance["artworkSHA256"], GENERATOR.sha256(ARTWORK / "MediaVolume.png"))
            self.assertEqual(proof["symbolArtworkScale"][name], 1.0)
        self.assertEqual(proof["symbolArtworkScale"]["wifi"], 1.60)
        self.assertEqual(proof["symbolArtworkScale"]["flashlight.off.fill"], 1.50)
        self.assertFalse(proof["nativeButtonGeometryChanged"])

    def test_per_control_optical_sizing_proofs_cover_every_native_connectivity_rendition(self):
        for catalog in self.catalog_manifest["catalogs"]:
            if catalog["targetPath"] not in (GENERATOR.CORE_GLYPHS_TARGET, GENERATOR.CORE_GLYPHS_PRIVATE_TARGET):
                continue
            proof = json.loads((GENERATOR.OUTPUT / catalog["preservationProofResource"]).read_text())
            names = set(catalog["themedSymbolNames"]) & GENERATOR.CONNECTIVITY_SYMBOL_NAMES
            self.assertEqual(proof["connectivityControlArtworkScale"],
                {GENERATOR.CONNECTIVITY_SYMBOL_CONTROLS[name]: GENERATOR.symbol_artwork_scale(name)
                 for name in names})
            self.assertEqual(proof["connectivityArtworkSizingScope"],
                "global-native-symbol-identity-compact-and-expanded-shared")
            self.assertFalse(proof["nativeSymbolCaplineAndBaselineGuidesChanged"])
            for name in names:
                self.assertEqual(proof["symbolArtworkScale"][name], GENERATOR.symbol_artwork_scale(name))
            native_path = (GENERATOR.STOCK_CORE_GLYPHS if catalog["targetPath"] == GENERATOR.CORE_GLYPHS_TARGET
                           else GENERATOR.STOCK_CORE_GLYPHS_PRIVATE)
            native = GENERATOR.Car(native_path.read_bytes())
            native_records = [record for record in native.renditions if record.name in names]
            validation = proof["connectivityOpticalSizingValidation"]
            self.assertTrue(validation["hostRenderedEveryNativeConnectivityRendition"])
            self.assertTrue(validation["nativeSymbolImagesUseInkCroppedExtents"])
            for name, layout in validation["templateLayouts"].items():
                self.assertEqual(layout["effectiveScale"], GENERATOR.symbol_artwork_scale(name))
                self.assertTrue(layout["completeAuthoredAlphaInsideSymbolMargins"])
                self.assertFalse(layout["nativeCaplineAndBaselineGuidesChanged"])
            self.assertEqual(validation["nativeRenditionCount"], len(native_records))
            self.assertEqual({record["nativeBlock"] for record in validation["renditions"]},
                             {record.block for record in native_records})
            for record in validation["renditions"]:
                left, top, right, bottom = record["inkAlphaBounds"]
                width, height = record["pixelCanvas"]
                self.assertGreaterEqual(min(left, top), 0)
                self.assertLessEqual(right, width)
                self.assertLessEqual(bottom, height)
                self.assertLessEqual(record["aspectRoundingErrorPixels"], 2)
                self.assertGreaterEqual(record["normalizedSilhouetteIntersectionOverUnion"],
                                        record["minimumSilhouetteSimilarity"])

    def test_flashlight_optical_sizing_proof_covers_every_native_rendition(self):
        public = next(catalog for catalog in self.catalog_manifest["catalogs"]
                      if catalog["targetPath"] == GENERATOR.CORE_GLYPHS_TARGET)
        proof = json.loads((GENERATOR.OUTPUT / public["preservationProofResource"]).read_text())
        native = GENERATOR.Car(GENERATOR.STOCK_CORE_GLYPHS.read_bytes())
        native_records = [record for record in native.renditions
                          if record.name in GENERATOR.FLASHLIGHT_SYMBOL_NAMES]
        validation = proof["flashlightOpticalSizingValidation"]
        self.assertEqual(proof["flashlightContourMethod"],
                         "bilinear-subpixel-opacity-plane-trace")
        self.assertEqual(proof["flashlightContourSupersampling"], 8)
        self.assertEqual(proof["flashlightContourTolerance"], 0.08)
        self.assertEqual(proof["highFidelityContourMethod"],
                         "bilinear-subpixel-opacity-plane-trace")
        self.assertEqual(proof["highFidelityContourSupersampling"], 8)
        self.assertEqual(proof["highFidelityContourTolerance"], 0.08)
        self.assertEqual(set(proof["highFidelityContourSymbolNames"]),
                         set(public["themedSymbolNames"]) &
                         GENERATOR.HIGH_FIDELITY_CONTOUR_SYMBOL_NAMES)
        self.assertTrue(validation["hostRenderedEveryRequestedNativeRendition"])
        self.assertEqual(validation["nativeRenditionCount"], len(native_records))
        self.assertEqual({record["nativeBlock"] for record in validation["renditions"]},
                         {record.block for record in native_records})
        self.assertEqual(set(validation["templateLayouts"]), GENERATOR.FLASHLIGHT_SYMBOL_NAMES)
        for layout in validation["templateLayouts"].values():
            self.assertEqual(layout["effectiveScale"], 1.50)
            self.assertTrue(layout["completeAuthoredAlphaInsideSymbolMargins"])

    @unittest.skipUnless(HOST_ASSETS, "requires macOS CoreUI")
    def test_native_symbol_rendering_retains_pulsar_backing_opacity_at_cached_and_vector_sizes(self):
        with tempfile.TemporaryDirectory(prefix="cnd-cc-symbol-alpha-") as temporary:
            work = Path(temporary)
            renderer = work / "renderer"
            GENERATOR.compile_renderer(renderer)
            public = ARTWORK / next(route["payloadResource"] for route in self.manifest["routes"]
                                   if route["targetPath"] == GENERATOR.CORE_GLYPHS_TARGET)
            for name in ("wifi", "cellularbars", "personalhotspot", "flashlight.off.fill", "qrcode.viewfinder"):
                for point_size in (15, 17, 20, 40):
                    with self.subTest(name=name, point_size=point_size):
                        output = work / "symbol.png"
                        GENERATOR.run(str(renderer), "--symbol", str(public), name, str(output),
                                      "2", "4", str(point_size), capture=True)
                        alpha = GENERATOR.decode_png_alpha(output)
                        pixels = [value for row in alpha for value in row]
                        self.assertGreater(sum(120 <= value <= 124 for value in pixels), 0)
                        self.assertGreater(sum(value >= 250 for value in pixels), 0)

    @unittest.skipUnless(HOST_ASSETS, "requires macOS assetutil")
    def test_assetutil_validates_both_catalogs_and_the_recorded_preservation_proof(self):
        payload = ARTWORK / self.route["payloadResource"]
        for path in (GENERATOR.STOCK_CONNECTIVITY, payload):
            GENERATOR.run("xcrun", "assetutil", "-Z", str(path), capture=True)
        stock = GENERATOR.rendition_contract(GENERATOR.asset_records(GENERATOR.STOCK_CONNECTIVITY))
        themed = GENERATOR.rendition_contract(GENERATOR.asset_records(payload))
        proof = json.loads((ARTWORK / self.route["preservationProofResource"]).read_text())
        self.assertEqual(stock, themed)
        self.assertEqual(stock, proof["stockRenditionContract"])

    @unittest.skipUnless(HOST_ASSETS, "requires macOS actool and assetutil")
    def test_physical_payload_and_proof_regenerate_byte_for_byte_in_independent_directories(self):
        with tempfile.TemporaryDirectory(prefix="cnd-cc-catalog-repro-") as temporary:
            for name in ("first", "second"):
                work = Path(temporary) / name
                work.mkdir()
                generated = GENERATOR.build_connectivity(work, output=work / "payloads")
                self.assertEqual(generated, self.catalog)
                for resource in (generated["resourceName"], generated["preservationProofResource"]):
                    self.assertEqual((work / "payloads" / resource).read_bytes(),
                                     (GENERATOR.OUTPUT / resource).read_bytes())

    @unittest.skipUnless(HOST_ASSETS, "requires macOS CoreUI")
    def test_native_payloads_preserve_every_native_size_and_weight_lookup(self):
        with tempfile.TemporaryDirectory(prefix="cnd-cc-priority-lookups-") as temporary:
            temporary = Path(temporary)
            renderer = temporary / "renderer"
            GENERATOR.compile_renderer(renderer)
            for route in self.manifest["routes"]:
                if route["kind"] not in ("core-glyphs-catalog", "core-glyphs-private-catalog"):
                    continue
                catalog = next(catalog for catalog in self.catalog_manifest["catalogs"]
                               if catalog["targetPath"] == route["targetPath"])
                stock = {GENERATOR.CORE_GLYPHS_TARGET: GENERATOR.STOCK_CORE_GLYPHS,
                         GENERATOR.CORE_GLYPHS_PRIVATE_TARGET: GENERATOR.STOCK_CORE_GLYPHS_PRIVATE}[route["targetPath"]]
                output = temporary / route["kind"]
                output.mkdir()
                supported = 0
                for name in catalog["themedSymbolNames"]:
                    for size in (0, 1, 2, 3):
                        for weight in range(10):
                            with self.subTest(name=name, size=size, weight=weight):
                                args = [str(renderer), "--symbol", str(stock), name,
                                        str(output / "stock.png"), str(size), str(weight)]
                                native = subprocess.run(args, capture_output=True, text=True)
                                args[2], args[4] = str(ARTWORK / route["payloadResource"]), str(output / "payload.png")
                                themed = subprocess.run(args, capture_output=True, text=True)
                                self.assertEqual(themed.returncode, native.returncode, themed.stderr)
                                if native.returncode == 0:
                                    supported += 1
                                    alpha = GENERATOR.decode_png_alpha(output / "payload.png")
                                    self.assertTrue(any(value >= 24 for row in alpha for value in row))
                                    if name in (GENERATOR.CONNECTIVITY_SYMBOL_NAMES |
                                                GENERATOR.FLASHLIGHT_SYMBOL_NAMES):
                                        source = GENERATOR.downsample_alpha(GENERATOR.decode_png_alpha(
                                            ARTWORK / GENERATOR.PULSAR_SYMBOLS[name]),
                                            GENERATOR.SYMBOL_MASK_MAXIMUM_DIMENSION)
                                        footprint = GENERATOR.rendered_symbol_footprint(alpha, source)
                                        self.assertLessEqual(footprint["aspectRoundingErrorPixels"], 2)
                self.assertGreaterEqual(supported, len(catalog["themedSymbolNames"]) * 20)


class PulsarDisplayCatalogPayloadTests(unittest.TestCase):
    def setUp(self):
        runtime = json.loads((ARTWORK / "CatalogFileBacking.json").read_text())
        self.route = next(route for route in runtime["routes"] if route["kind"] == "display-catalog")
        manifest = json.loads((GENERATOR.OUTPUT / "CatalogManifest.json").read_text())
        self.catalog = next(catalog for catalog in manifest["catalogs"]
                            if catalog["targetPath"] == GENERATOR.DISPLAY_TARGET)
        self.proof = json.loads((ARTWORK / self.route["preservationProofResource"]).read_text())

    def test_display_payload_preserves_every_native_lookup_and_layout_variant(self):
        GENERATOR.require_stock(GENERATOR.STOCK_DISPLAY, GENERATOR.EXPECTED_DISPLAY)
        self.assertLessEqual(self.catalog["compiledLength"], 32296)
        self.assertEqual(self.route["payloadLength"], 32296)
        payload = ARTWORK / self.route["payloadResource"]
        self.assertEqual(payload.stat().st_size, 32296)
        self.assertEqual(GENERATOR.sha256(payload), self.route["payloadSHA256"])
        self.assertEqual(GENERATOR.sha256(ARTWORK / self.route["preservationProofResource"]),
                         self.route["preservationProofSHA256"])
        self.assertEqual(self.proof["stockRenditionContract"], self.proof["payloadRenditionContract"])
        self.assertEqual(len(self.proof["stockRenditionContract"]), 8)
        self.assertEqual(self.proof["nativePointSizes"], {"NightShift": [30, 40], "TrueTone": [30, 40]})
        self.assertEqual(self.proof["artworkMaskMaximumDimension"], 80)
        self.assertEqual(self.proof["artworkMaskAlphaLevels"], 1)
        self.assertEqual(self.proof["unrelatedNamedRenditions"], [])
        for name in GENERATOR.DISPLAY_RENDITIONS:
            records = [record for record in self.proof["stockRenditionContract"] if record["Name"] == name]
            self.assertEqual({(record["AssetType"], record["Scale"]) for record in records},
                             {("Image", 1), ("Image", 3), ("Vector", 1)})
        self.assertEqual({(record["Scale"], record["PixelWidth"], record["PixelHeight"])
                          for record in self.proof["stockRenditionContract"]
                          if record["AssetType"] == "PackedImage"}, {(1, 66, 44), (3, 186, 124)})
        backing = json.loads((ARTWORK / "FileBacking.json").read_text())
        self.assertNotIn("nightShift", backing["excludedKinds"])
        self.assertNotIn("trueTone", backing["excludedKinds"])

    @unittest.skipUnless(HOST_ASSETS, "requires macOS CoreUI")
    def test_display_catalog_retrieves_both_names_with_centered_visible_artwork(self):
        with tempfile.TemporaryDirectory(prefix="cnd-display-lookups-") as temporary:
            work = Path(temporary)
            renderer = work / "renderer"
            GENERATOR.compile_renderer(renderer)
            for name, relative in GENERATOR.DISPLAY_RENDITIONS.items():
                source_alpha = GENERATOR.downsample_alpha(
                    GENERATOR.decode_png_alpha(ARTWORK / relative), 80)
                for scale in (1, 3):
                    output = work / f"{name}-{scale}.png"
                    subprocess.run([str(renderer), "--image", str(ARTWORK / self.route["payloadResource"]),
                                    name, str(output), str(scale)], check=True, capture_output=True)
                    self.assertEqual(struct.unpack(">II", output.read_bytes()[16:24]), (30 * scale, 40 * scale))
                    alpha = GENERATOR.decode_png_alpha(output)
                    _, left, top, right, bottom = GENERATOR.merged_mask_rectangles(alpha)
                    self.assertLessEqual(abs((left + right) / 2 - 15 * scale), scale)
                    self.assertLessEqual(abs((top + bottom) / 2 - 20 * scale), scale)
                    self.assertGreater(top, 0)
                    self.assertLess(bottom, 40 * scale)
                    if scale == 3:
                        # Compare the actual CoreUI-rendered silhouette with the
                        # submitted image after the documented aspect-fit map.
                        intersection = union = 0
                        for y, row in enumerate(alpha):
                            for x, value in enumerate(row):
                                source_y = int((y + 0.5 - 15) * 80 / 90)
                                source_x = int((x + 0.5) * 80 / 90)
                                expected = (0 <= source_y < 80 and source_alpha[source_y][source_x] >= 128)
                                visible = value >= 128
                                intersection += expected and visible
                                union += expected or visible
                        self.assertGreater(intersection / union, 0.95, name)

    @unittest.skipUnless(HOST_ASSETS, "requires macOS actool and assetutil")
    def test_display_payload_and_proof_regenerate_without_changing_other_catalogs(self):
        other_catalogs = {name: GENERATOR.sha256(ARTWORK / name)
                          for name in ("CoreGlyphsPriority-23A341.car", "Connectivity-23A341.car")}
        with tempfile.TemporaryDirectory(prefix="cnd-display-repro-") as temporary:
            for name in ("first", "second"):
                work = Path(temporary) / name
                work.mkdir()
                result = GENERATOR.build_display(work, output=work / "payloads")
                self.assertEqual(result, self.catalog)
                for resource in (result["resourceName"], result["preservationProofResource"]):
                    self.assertEqual((work / "payloads" / resource).read_bytes(),
                                     (GENERATOR.OUTPUT / resource).read_bytes())
        self.assertEqual(other_catalogs, {name: GENERATOR.sha256(ARTWORK / name) for name in other_catalogs})


if __name__ == "__main__":
    unittest.main()
