import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/lab/cnd_pac_fixup_dispatch_graph.py"
SPEC = importlib.util.spec_from_file_location(
    "cnd_pac_fixup_dispatch_graph", MODULE_PATH,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FixupDispatchGraphTests(unittest.TestCase):
    def _document(self):
        match = {
            "authenticated": True,
            "key": "IA",
            "diversity": "0x2abe",
            "addressDiversity": False,
            "location": "0xfffffe0007701000",
            "target": "0xfffffe0008123450",
            "raw": "0x80102abe0111f450",
        }
        return {
            "schema": "cyanide.pac-fixup-census.v1",
            "target": {
                "sha256": MODULE.COLLECTION_SHA256,
                "base": MODULE._hex(MODULE.STATIC_BASE),
                "filetype": "MH_FILESET",
            },
            "query": {
                "authenticated": True,
                "bind": False,
                "key": "IA",
                "diversity": "0x2abe",
                "addressDiversity": False,
                "pointerFormats": ["DYLD_CHAINED_PTR_64_KERNEL_CACHE"],
            },
            "matches": [match],
            "summary": {
                "matches": 1,
                "usedKernelRead": False,
                "usedKernelWrite": False,
                "usedKernelCall": False,
            },
        }

    def test_exact_fixup_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixups.json"
            path.write_text(json.dumps(self._document()), encoding="utf-8")
            grouped = MODULE._load_fixups(path)
        self.assertEqual(list(grouped), [0xFFFFFE0008123450])
        self.assertEqual(len(grouped[0xFFFFFE0008123450]), 1)

    def test_wrong_domain_fails(self):
        document = self._document()
        document["query"]["diversity"] = "0x307a"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixups.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(MODULE.GraphError):
                MODULE._load_fixups(path)

    def test_explicit_domain_accepts_matching_census(self):
        document = self._document()
        document["query"]["diversity"] = "0x12f7"
        document["matches"][0]["diversity"] = "0x12f7"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixups.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            grouped = MODULE._load_fixups(path, 0x12F7)
        self.assertEqual(list(grouped), [0xFFFFFE0008123450])

    def test_candidate_requires_exact_instruction(self):
        starts = [0x1000, 0x1020]
        addresses = list(range(0x1000, 0x1040, 4))
        image = Path("com.apple.kernel")
        self.assertEqual(
            MODULE._candidate(0x1010, image, starts, addresses),
            (0x20, "com.apple.kernel"),
        )
        self.assertIsNone(MODULE._candidate(0x1012, image, starts, addresses))


if __name__ == "__main__":
    unittest.main()
