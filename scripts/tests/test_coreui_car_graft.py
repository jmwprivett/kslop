"""Verify native CoreUI authoring and preservation at the raw CAR block boundary."""

from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
import unittest

from scripts.coreui_car_graft import Car, CarError, compact_tree_padding, graft


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("native_cc_catalogs", ROOT / "scripts/generate_pulsar_cc_catalog_payloads.py")
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)
ARTWORK = ROOT / "Cyanide/PulsarControlCenter.bundle"


class CoreUICarGraftTests(unittest.TestCase):
    def test_native_header_lookup_keys_and_every_unrelated_block_are_preserved(self):
        manifest = json.loads((ARTWORK / "CatalogFileBacking.json").read_text())
        stock_paths = {GENERATOR.CORE_GLYPHS_TARGET: GENERATOR.STOCK_CORE_GLYPHS,
                       GENERATOR.CORE_GLYPHS_PRIVATE_TARGET: GENERATOR.STOCK_CORE_GLYPHS_PRIVATE}
        for route in manifest["routes"]:
            if route["targetPath"] not in stock_paths:
                continue
            with self.subTest(target=route["targetPath"]):
                stock = Car(stock_paths[route["targetPath"]].read_bytes())
                payload = Car((ARTWORK / route["payloadResource"]).read_bytes())
                proof_path = ARTWORK / route["preservationProofResource"]
                self.assertEqual(GENERATOR.sha256(proof_path), route["preservationProofSHA256"])
                proof = json.loads(proof_path.read_text())
                targets = {record["block"] for record in proof["targetRenditions"]}
                self.assertEqual(len(stock.data), len(payload.data))
                self.assertEqual(stock.coreui_version, 970)
                self.assertEqual(payload.coreui_version, 970)
                self.assertEqual(stock.storage_version, payload.storage_version)
                self.assertEqual(stock.block(stock.variables["CARHEADER"]),
                                 payload.block(payload.variables["CARHEADER"]))
                self.assertEqual(stock.variables, payload.variables)
                self.assertEqual(list(stock.tree_entries("RENDITIONS")),
                                 list(payload.tree_entries("RENDITIONS")))
                self.assertEqual(stock.unused_blocks, payload.unused_blocks)
                digest = hashlib.sha256()
                count = 0
                for index in range(1, len(stock.blocks)):
                    if index in stock.unused_blocks:
                        self.assertEqual(stock.blocks[index], payload.blocks[index])
                        continue
                    original, changed = stock.block(index), payload.block(index)
                    if index in targets:
                        self.assertNotEqual(original, changed)
                        self.assertIn(struct.unpack_from("<H", changed, 36)[0], (0, 1017))
                    else:
                        self.assertEqual(original, changed, f"unrelated block {index}")
                        digest.update(struct.pack(">I", index))
                        digest.update(hashlib.sha256(original).digest())
                        count += 1
                self.assertEqual(proof["unrelatedBlockCount"], count)
                self.assertEqual(proof["unrelatedBlocksSHA256"], digest.hexdigest())
                self.assertEqual(proof["targetRenditionCount"], len(targets))
                self.assertTrue(proof["allTargetVectorAndCachedImageVariantsReplaced"])
                self.assertFalse(route["deviceConsumptionVerified"])

    def test_wrong_authoring_version_is_rejected_before_graft(self):
        stock = Car(GENERATOR.STOCK_CORE_GLYPHS_PRIVATE.read_bytes())
        donor = bytearray(stock.data)
        offset, _ = stock.blocks[stock.variables["CARHEADER"]]
        struct.pack_into("<I", donor, offset + 4, 975)
        with self.assertRaisesRegex(CarError, "genuine CoreUI 970"):
            graft(stock.data, bytes(donor), {"bluetooth"})

    def test_tree_page_compaction_preserves_lookup_entries_and_every_value(self):
        stock = Car(GENERATOR.STOCK_CONNECTIVITY.read_bytes())
        packed_bytes, proof = compact_tree_padding(stock.data)
        packed = Car(packed_bytes)
        self.assertLess(len(packed_bytes), len(stock.data))
        self.assertTrue(proof["allTreeEntriesPreserved"])
        self.assertTrue(proof["allValueBlocksByteIdentical"])
        self.assertEqual(stock.variables, packed.variables)
        for name, block in stock.variables.items():
            if stock.block(block)[:4] == b"tree":
                self.assertEqual(list(stock.tree_entries(name)), list(packed.tree_entries(name)))
        for record in stock.renditions:
            self.assertEqual(stock.block(record.block), packed.block(record.block))
            self.assertEqual(stock.block(record.key_block), packed.block(record.key_block))

    def test_unknown_nonzero_tree_page_data_is_not_discarded(self):
        stock = Car(GENERATOR.STOCK_CONNECTIVITY.read_bytes())
        tree = stock.block(stock.variables["RENDITIONS"])
        block = struct.unpack_from(">I", tree, 8)[0]
        value = stock.block(block)
        leaf, count = struct.unpack_from(">HH", value)
        self.assertEqual(leaf, 1)
        offset, length = stock.blocks[block]
        used = 12 + count * 8
        candidate = next(position for position in reversed(range(offset + used, offset + length))
                         if stock.data[position] == 0 and not any(
                             other != block and other not in stock.unused_blocks and
                             start <= position < start + extent
                             for other, (start, extent) in enumerate(stock.blocks)))
        altered = bytearray(stock.data)
        altered[candidate] = 1
        packed_bytes, proof = compact_tree_padding(bytes(altered))
        packed = Car(packed_bytes)
        self.assertTrue(proof["allNonzeroTreePageBytesPreserved"])
        self.assertEqual(packed.block(block), bytes(altered)[offset:offset + length])

    @unittest.skipUnless(sys.platform == "darwin", "requires native iOS 26.0 authoring runtime")
    def test_native_graft_regenerates_both_payloads_and_proofs_byte_for_byte(self):
        expected = json.loads((GENERATOR.OUTPUT / "CatalogManifest.json").read_text())
        expected = [catalog for catalog in expected["catalogs"]
                    if catalog["targetPath"] in (GENERATOR.CORE_GLYPHS_TARGET, GENERATOR.CORE_GLYPHS_PRIVATE_TARGET)]
        with tempfile.TemporaryDirectory(prefix="cnd-native-car-repro-") as temporary:
            work = Path(temporary)
            renderer = work / "renderer"
            GENERATOR.compile_renderer(renderer)
            actual = GENERATOR.build_core_glyphs(work, renderer, output=work / "payloads")
            self.assertEqual(actual, expected)
            for catalog in actual:
                for resource in (catalog["resourceName"], catalog["preservationProofResource"]):
                    self.assertEqual((work / "payloads" / resource).read_bytes(),
                                     (GENERATOR.OUTPUT / resource).read_bytes())


if __name__ == "__main__":
    unittest.main()
