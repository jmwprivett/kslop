#!/usr/bin/env python3

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lab"))

import cnd_pac_signer_census as census  # noqa: E402


class PACSignerCensusTests(unittest.TestCase):
    def test_static_load_source_and_section_are_recovered(self) -> None:
        instructions = census._parse_disassembly("""
fffffe0008f87b94: adrp x16, 0xfffffe000799f000
fffffe0008f87b98: ldr x16, [x16, #0x598]
fffffe0008f87b9c: mov x17, #0x61de
fffffe0008f87ba0: pacia x16, x17
""")
        sections = [census.Section(
            segment="__DATA_CONST", section="__got",
            start=0xFFFFFE000799F4D8, size=0x100,
        )]

        records = census._candidate_records(
            Path("com.apple.iokit.IONetworkingFamily"),
            instructions, sections,
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["sourceAddress"], "0xfffffe000799f598")
        self.assertEqual(records[0]["sourceSegment"], "__DATA_CONST")
        self.assertEqual(records[0]["sourceSection"], "__got")
        self.assertFalse(records[0]["sourceWritable"])
        self.assertEqual(records[0]["sourceMutationClass"], "protected-const")
        self.assertEqual(len(records[0]["targetChain"]), 2)

    def test_writable_static_load_is_classified(self) -> None:
        instructions = census._parse_disassembly("""
fffffe0008001000: adrp x8, 0xfffffe0009800000
fffffe0008001004: ldr x0, [x8, #0x120]
fffffe0008001008: paciza x0
""")
        sections = [census.Section(
            segment="__DATA", section="__data",
            start=0xFFFFFE0009800000, size=0x1000,
        )]

        records = census._candidate_records(Path("kernel"), instructions, sections)

        self.assertEqual(records[0]["sourceAddress"], "0xfffffe0009800120")
        self.assertTrue(records[0]["sourceWritable"])
        self.assertEqual(records[0]["sourceMutationClass"], "runtime-writable")

    def test_argument_loaded_pointer_has_no_static_source(self) -> None:
        instructions = census._parse_disassembly("""
fffffe0008002000: ldr x8, [x0, #0x20]
fffffe0008002004: paciza x8
""")

        records = census._candidate_records(Path("kernel"), instructions)

        self.assertEqual(records[0]["targetOrigin"], "load")
        self.assertNotIn("sourceAddress", records[0])

    def test_section_parser_reads_macho_report(self) -> None:
        sections = census._parse_sections("""
Section
  sectname __got
   segname __DATA_CONST
      addr 0xfffffe000799f4d8
      size 0x0000000000000100
""")

        self.assertEqual(sections, [census.Section(
            segment="__DATA_CONST", section="__got",
            start=0xFFFFFE000799F4D8, size=0x100,
        )])


if __name__ == "__main__":
    unittest.main()
