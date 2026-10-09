"""Exercise actual guarded instructions across all stock policy branches."""

import itertools
import hashlib
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from scripts import derive_flat_icon_patch as patch


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def execute(method, *, flat, square, glass, low_power, thermal):
    """Interpret this method's instruction words; model its external getters.

    This checks control flow and call/release order, not CPU execution or PAC.
    PAC/frame instructions are byte-guarded separately. Calls are identified by
    reviewed instruction offsets; no executable code is mapped or invoked.
    """
    registers = [0] * 32
    registers[0] = 0x1000
    equal = False
    calls = []
    getters = {0x14: ("prefersFlatImageLayers", int(flat)),
               0x28: ("showsSquareCorners", int(square)),
               0x34: ("effectiveIconImageAppearance", 0x2000),
               0x40: ("hasGlass", int(glass)),
               0x58: ("processInfo", 0x3000),
               0x64: ("isLowPowerModeEnabled", int(low_power)),
               0x78: ("thermalState", thermal)}
    frame = {0x00, 0x04, 0x08, 0x0C, 0x90, 0x94}
    pc = 0
    for _ in range(80):
        word = struct.unpack_from("<I", method, pc)[0]
        following = pc + 4
        if pc in frame:
            pass
        elif word == 0xD65F0FFF:  # retab
            return registers[0], calls
        elif word >> 26 == 0b100101:  # bl
            if pc in getters:
                name, result = getters[pc]
                calls.append((name, registers[0]))
                registers[0] = result
            elif pc in (0x38, 0x5C):
                calls.append(("claimAutoreleasedReturnValue", registers[0]))
            elif pc in (0x48, 0x88):
                calls.append(("release", registers[19]))
                registers[0] = 0xBAD0  # ensure returned value survives caller clobber
            else:
                raise AssertionError(f"unexpected external call at {pc:#x}")
        elif word >> 26 == 0b000101:  # b
            following = pc + signed(word & 0x3FFFFFF, 26) * 4
        elif word & 0x7F000000 == 0x36000000:  # tbz
            bit = ((word >> 19) & 31) | ((word >> 26) & 32)
            if not registers[word & 31] & (1 << bit):
                following = pc + signed((word >> 5) & 0x3FFF, 14) * 4
        elif word & 0x7F000000 == 0x34000000:  # cbz
            if registers[word & 31] == 0:
                following = pc + signed((word >> 5) & 0x7FFFF, 19) * 4
        elif word & 0xFFE0FFE0 == 0xAA0003E0:  # mov Xd, Xm
            registers[word & 31] = registers[(word >> 16) & 31]
        elif word & 0xFF800000 == 0x52800000:  # movz Wd, #imm16
            registers[word & 31] = ((word >> 5) & 0xFFFF) << (((word >> 21) & 3) * 16)
        elif word == 0x90145368:  # adrp x8 (NSProcessInfo class page)
            registers[8] = 0x4000
        elif word == 0xF9469100:  # ldr x0 (NSProcessInfo class)
            registers[0] = 0x5000
        elif word == 0x927FF808:  # and x8, x0, #~1
            registers[8] = registers[0] & 0xFFFFFFFFFFFFFFFE
        elif word == 0xF100091F:  # cmp x8, #2
            equal = registers[8] == 2
        elif word == patch.ORIGINAL_WORD:  # cset w20, eq
            registers[20] = int(equal)
        else:
            raise AssertionError(f"unmodeled word {word:#x} at {pc:#x}")
        if following % 4 or not 0 <= following < len(method):
            raise AssertionError("branch escapes method")
        pc = following
    raise AssertionError("method did not terminate")


class FlatIconPatchTests(unittest.TestCase):
    def test_signed_page_corruption_and_wrong_trustcache_are_rejected(self):
        page = bytes(128)
        directory = bytearray(44)
        directory.extend(hashlib.sha256(page).digest())
        struct.pack_into(">II", directory, 0, 0xFADE0C02, len(directory))
        struct.pack_into(">IIIII", directory, 16, 44, 0, 0, 1, len(page))
        struct.pack_into("4B", directory, 36, 32, 2, 0, 14)
        signature = struct.pack(">IIIII", 0xFADE0CC0, 20 + len(directory), 1, 0, 20) + directory
        header = {"signatureOffset": len(page), "signatureSize": len(signature)}
        trusted = {(hashlib.sha256(directory).digest()[:20], 2)}
        with tempfile.TemporaryDirectory(prefix="cnd-flat-icon-signature-test-") as temporary:
            cache = Path(temporary) / "synthetic-cache"
            cache.write_bytes(page + signature)
            verified = patch.verify_code_directory(cache, header, trusted)
            self.assertEqual(verified["verifiedCodePages"], 1)
            with self.assertRaisesRegex(patch.DerivationError, "absent from the exact IPSW"):
                patch.verify_code_directory(cache, header, set())
            changed = bytearray(page + signature)
            changed[0] ^= 1
            cache.write_bytes(changed)
            with self.assertRaisesRegex(patch.DerivationError, "signed code page 0 does not match"):
                patch.verify_code_directory(cache, header, trusted)

    def test_actual_instruction_paths_return_true_and_preserve_calls(self):
        original = patch.validate_context(bytes.fromhex(patch.CONTEXT_HEX))
        changed = bytearray(original)
        struct.pack_into("<I", changed, patch.PATCH_VM - patch.METHOD_VM, patch.REPLACEMENT_WORD)
        original_true = original_false = 0
        for flat, square, glass, low_power, thermal in itertools.product(
                (False, True), (False, True), (False, True), (False, True), (-1, 0, 1, 2, 3, 4)):
            flags = dict(flat=flat, square=square, glass=glass, low_power=low_power, thermal=thermal)
            with self.subTest(**flags):
                before, calls_before = execute(original, **flags)
                after, calls_after = execute(changed, **flags)
                expected = flat or (square and not glass) or low_power or thermal in (2, 3)
                self.assertEqual(before, int(expected))
                self.assertEqual(after, 1)
                self.assertEqual(calls_before, calls_after)
                original_true += bool(before)
                original_false += not bool(before)
        self.assertEqual((original_true, original_false), (84, 12))
        offset = patch.PATCH_VM - patch.METHOD_VM
        self.assertEqual(original[:offset], changed[:offset])
        self.assertEqual(original[offset + 4:], changed[offset + 4:])

    def test_every_surrounding_byte_is_guarded(self):
        context = bytes.fromhex(patch.CONTEXT_HEX)
        self.assertEqual(len(context), patch.CONTEXT_SIZE)
        for index in range(len(context)):
            changed = bytearray(context)
            changed[index] ^= 1
            with self.subTest(index=index), self.assertRaisesRegex(patch.DerivationError, "original-byte guard"):
                patch.validate_context(changed)

    def test_already_patched_input_is_refused(self):
        changed = bytearray.fromhex(patch.CONTEXT_HEX)
        struct.pack_into("<I", changed, patch.PATCH_VM - patch.CONTEXT_VM, patch.REPLACEMENT_WORD)
        with self.assertRaises(patch.DerivationError):
            patch.validate_context(changed)

    @unittest.skipUnless(shutil.which("clang"), "requires clang with an Apple arm64e target")
    def test_independent_assembler_verifies_both_words(self):
        result = patch.verify_encoding(shutil.which("clang"))
        self.assertEqual(result["textHex"], "f4179f1a34008052")


if __name__ == "__main__":
    unittest.main()
