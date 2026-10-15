"""Offline tests for the exact-function PAC dispatch graph."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_pac_dispatch_graph as graph  # noqa: E402


class PACDispatchGraphTests(unittest.TestCase):
    def test_direct_signer_and_same_domain_dispatch(self) -> None:
        instructions = graph._parse_disassembly("""
1000: adrp x16, 0x2000 <__text+0x1000>
1004: add x16, x16, #0x40
1008: mov x17, #0x629a
100c: pacia x16, x17
1010: ret
2040: ldr x4, [x0, #0x30]
2044: cbz x4, 0x2050
2048: ldr x0, [x0, #0x20]
204c: mov x16, #0x629a
2050: braa x4, x16
2054: ret
""")
        signers = graph._direct_signers(
            Path("com.apple.kernel"), instructions, frozenset({0x629A}),
        )
        self.assertEqual(len(signers), 1)
        self.assertEqual(signers[0]["target"], 0x2040)

        record = graph._analyze_target(
            Path("com.apple.kernel"), 0x2040, {0x629A}, [0x100C],
            instructions, [0x1000, 0x2040, 0x2058],
        )
        self.assertEqual(len(record["indirectBranches"]), 1)
        branch = record["indirectBranches"][0]
        self.assertEqual(branch["destinationDomain"], graph._hex(0x629A))
        self.assertEqual(branch["targetOrigin"]["kind"], "load")
        self.assertEqual(branch["targetOrigin"]["baseRegister"], "x0")
        self.assertEqual(branch["targetOrigin"]["offset"], 0x30)

    def test_function_boundary_prevents_neighbor_branch_bleed(self) -> None:
        instructions = graph._parse_disassembly("""
3000: mov x0, #0x0
3004: ret
3008: ldr x8, [x0]
300c: mov x17, #0x1234
3010: blraa x8, x17
3014: ret
""")
        record = graph._analyze_target(
            Path("com.apple.kernel"), 0x3000, {0x629A}, [0x2000],
            instructions, [0x3000, 0x3008, 0x3018],
        )
        self.assertEqual(record["functionEnd"], graph._hex(0x3008))
        self.assertEqual(record["indirectBranches"], [])

    def test_address_blended_modifier_stays_nonconstant(self) -> None:
        instructions = graph._parse_disassembly("""
4000: ldr x8, [x16]
4004: mov x17, x16
4008: movk x17, #0x638e, lsl #48
400c: blraa x8, x17
4010: ret
""")
        record = graph._analyze_target(
            Path("com.apple.kext"), 0x4000, {0x629A}, [0x2000],
            instructions, [0x4000, 0x4014],
        )
        branch = record["indirectBranches"][0]
        self.assertNotIn("destinationDomain", branch)
        self.assertEqual(branch["modifierOrigin"]["kind"], "address-blended")

    def test_argument_pointer_sign_is_reported(self) -> None:
        instructions = graph._parse_disassembly("""
5000: mov x16, x1
5004: mov x17, #0x7777
5008: pacia x16, x17
500c: ret
""")
        record = graph._analyze_target(
            Path("com.apple.kernel"), 0x5000, {0x629A}, [0x2000],
            instructions, [0x5000, 0x5010],
        )
        self.assertEqual(len(record["pointerSigns"]), 1)
        self.assertEqual(
            record["pointerSigns"][0]["targetOrigin"]["kind"], "argument",
        )
        self.assertEqual(
            record["pointerSigns"][0]["targetOrigin"]["baseRegister"], "x1",
        )

    def test_distant_object_load_is_not_mislabeled_as_argument(self) -> None:
        padding = "\n".join(
            f"{0x6010 + index * 4:x}: nop" for index in range(graph.MAX_SLICE + 1)
        )
        instructions = graph._parse_disassembly(f"""
6000: ldr x3, [x1, #0x188]
6004: b 0x6010
6008: nop
600c: nop
{padding}
6094: mov x17, #0xc120
6098: braa x3, x17
609c: ret
""")
        record = graph._analyze_target(
            Path("com.apple.kernel"), 0x6000, {0xA0D8}, [0x5000],
            instructions, [0x6000, 0x60A0],
        )
        branch = record["indirectBranches"][0]
        self.assertEqual(
            branch["targetOrigin"]["kind"],
            "unresolved-prior-definition",
        )
        self.assertEqual(branch["targetOrigin"]["baseRegister"], "x3")
        self.assertIn("ldr\tx3, [x1, #0x188]", branch["targetOrigin"]["chain"][0])

    def test_fixed_identity_survives_ia_zero_resign_wrapper(self) -> None:
        instructions = graph._parse_disassembly("""
6000: adrp x16, 0x7000 <__text+0x1000>
6004: add x16, x16, #0x378
6008: paciza x16
600c: autiza x16
6010: mov x17, #0xe4fe
6014: pacia x16, x17
6018: ret
7378: ret
""")
        signers = graph._direct_signers(
            Path("com.apple.kernel"), instructions, frozenset({0xE4FE}),
        )
        self.assertEqual(len(signers), 1)
        self.assertEqual(signers[0]["target"], 0x7378)

    def test_ia_zero_domain_is_seeded_from_paciza(self) -> None:
        instructions = graph._parse_disassembly("""
8000: adrp x16, 0x9000 <__text+0x1000>
8004: add x16, x16, #0x44
8008: paciza x16
800c: ret
9044: mov x0, x1
9048: ret
""")
        signers = graph._direct_signers(
            Path("com.apple.kernel"), instructions, frozenset({0}),
        )
        self.assertEqual(len(signers), 1)
        self.assertEqual(signers[0]["domain"], 0)
        self.assertEqual(signers[0]["target"], 0x9044)

        self.assertEqual(
            graph._direct_signers(
                Path("com.apple.kernel"), instructions, frozenset({0x61DE}),
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
