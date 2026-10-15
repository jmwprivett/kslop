import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/lab/cnd_pac_fixup_domain_closure.py"
SPEC = importlib.util.spec_from_file_location(
    "cnd_pac_fixup_domain_closure", MODULE_PATH,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FixupDomainClosureTests(unittest.TestCase):
    def test_accepts_and_normalizes_pinned_sha256(self):
        value = "A5" * 32
        self.assertEqual(MODULE._parse_sha256(value), value.lower())

    def test_rejects_malformed_pinned_sha256(self):
        for value in ("a5", "g" * 64, "a" * 65):
            with self.subTest(value=value):
                with self.assertRaises(Exception):
                    MODULE._parse_sha256(value)

    def test_direct_only_cli_switch(self):
        args = MODULE._parser().parse_args([
            "collection", "image", "--output", "closure.json",
            "--direct-only",
        ])
        self.assertTrue(args.direct_only)

    def test_cli_accepts_explicit_physical_product_and_base(self):
        args = MODULE._parser().parse_args([
            "collection", "image", "--output", "closure.json",
            "--product", "iPhone17,2", "--base", "0xfffffff007004000",
        ])
        self.assertEqual(args.product, "iPhone17,2")
        self.assertEqual(args.base, 0xFFFFFFF007004000)

    def test_groups_only_ia_constant_domain_fixups(self):
        records = [
            {
                "key": "IA", "addressDiversity": False,
                "diversity": "0x2abe", "target": "0x1000",
                "location": "0x2000",
            },
            {
                "key": "DA", "addressDiversity": False,
                "diversity": "0x2abe", "target": "0x1008",
                "location": "0x2008",
            },
            {
                "key": "IA", "addressDiversity": True,
                "diversity": "0x2abe", "target": "0x1010",
                "location": "0x2010",
            },
        ]
        grouped = MODULE._group_fixups(records)
        self.assertEqual(list(grouped), [0x2ABE])
        self.assertEqual(list(grouped[0x2ABE]), [0x1000])

    def test_extracts_constant_destination_domains(self):
        records = [{
            "indirectBranches": [
                {"destinationDomain": "0x00000000000012f7"},
                {"modifierOrigin": {"kind": "address-blended"}},
            ],
        }]
        self.assertEqual(MODULE._next_domains(records), {0x12F7})

    def test_extracts_only_raw_branch_candidates(self):
        records = [{
            "target": "0x1000",
            "image": "com.apple.kernel",
            "functionStart": "0x1000",
            "functionEnd": "0x1040",
            "entryDomains": ["0xbcad"],
            "fixupsByDomain": {"0xbcad": {"count": 1}},
            "indirectBranches": [
                {"site": "0x1020", "authenticated": True},
                {
                    "site": "0x1010", "authenticated": False,
                    "targetOrigin": {"kind": "load", "baseRegister": "x1"},
                },
            ],
        }]
        candidates = MODULE._raw_branch_candidates(records)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["branch"]["site"], "0x1010")
        self.assertEqual(candidates[0]["entryDomains"], ["0xbcad"])

    def test_rejects_duplicate_fixup_location(self):
        record = {
            "key": "IA", "addressDiversity": False,
            "diversity": "0x2abe", "target": "0x1000",
            "location": "0x2000",
        }
        with self.assertRaises(MODULE.ClosureError):
            MODULE._group_fixups([record, dict(record)])


if __name__ == "__main__":
    unittest.main()
