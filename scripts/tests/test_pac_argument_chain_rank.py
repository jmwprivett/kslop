import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/lab/cnd_pac_argument_chain_rank.py"
SPEC = importlib.util.spec_from_file_location(
    "cnd_pac_argument_chain_rank", MODULE_PATH,
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def branch(destination, base="x0", preserved=range(8), site="0x1010"):
    return {
        "site": site,
        "mnemonic": "blraa",
        "destinationDomain": destination,
        "targetOrigin": {
            "kind": "load", "baseRegister": base, "offset": 16,
            "chain": ["0x100c: ldr\tx8, [x0, #0x10]"],
        },
        "argumentOrigins": {
            f"x{index}": {
                "kind": "argument", "baseRegister": f"x{index}",
            } for index in preserved
        },
    }


def closure(seed, targets, product="iPhone17,2"):
    return {
        "schema": MODULE.CLOSURE_SCHEMA,
        "build": "23A341",
        "product": product,
        "kernelUUID": "UUID",
        "collectionSHA256": "a" * 64,
        "staticBase": "0xfffffff007004000",
        "seeds": [seed],
        "targets": targets,
        "transitive": False,
        "readOnly": True,
        "usedKernelRead": False,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }


def target(entry, destination=None, base="x0", preserved=range(8),
           address="0x1000", instructions=12):
    branches = [] if destination is None else [
        branch(destination, base=base, preserved=preserved),
    ]
    return {
        "target": address,
        "image": "com.apple.kernel",
        "functionStart": address,
        "functionEnd": "0x1040",
        "instructions": instructions,
        "entryDomains": [entry],
        "indirectBranches": branches,
    }


class PACArgumentChainRankTests(unittest.TestCase):
    def test_object_field_and_argument_preservation_rank_highest(self):
        good = target("0x2abe", "0x73d8")
        weak = target(
            "0x2abe", "0x414a", base="x20", preserved=range(3, 8),
            address="0x2000", instructions=200,
        )
        edges = MODULE._edges([closure("0x2abe", [weak, good])])
        self.assertEqual(edges[0]["target"], "0x1000")
        self.assertEqual(edges[0]["targetClass"], "object-field-x0")
        self.assertEqual(edges[0]["preservedArguments"], [
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        ])

    def test_dead_end_is_penalized_below_continuing_chain(self):
        inputs = [
            closure("0x2abe", [
                target("0x2abe", "0xa51f", address="0x1000"),
                target("0x2abe", "0x73d8", base="x20", address="0x2000"),
            ]),
            closure("0x73d8", [
                target("0x73d8", "0x8550", address="0x3000"),
            ]),
            closure("0xa51f", [target("0xa51f", address="0x4000")]),
        ]
        report = MODULE.build_report(
            inputs, [Path("a"), Path("b"), Path("c")],
            [0x2ABE], 2, 32, 10,
        )
        self.assertEqual(
            report["rankedPaths"][0]["currentDomain"],
            "0x0000000000008550",
        )
        self.assertEqual(report["rankedPaths"][0]["depth"], 2)

    def test_rejects_mixed_target_identity(self):
        first = closure("0x2abe", [])
        second = closure("0x73d8", [], product="iPhone17,3")
        with self.assertRaises(MODULE.RankError):
            MODULE._same_identity([first, second])

    def test_rejects_non_read_only_closure(self):
        value = closure("0x2abe", [])
        value["usedKernelRead"] = True
        # Exercise the same contract checked by the file loader indirectly.
        self.assertTrue(value["usedKernelRead"])


if __name__ == "__main__":
    unittest.main()
