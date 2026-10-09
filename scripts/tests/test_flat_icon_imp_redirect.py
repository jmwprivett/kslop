import hashlib
import json
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = (ROOT / "docs" / "research" /
            "flat-icon-imp-redirect-23A341-iphone17,2.json")
DERIVER = ROOT / "scripts" / "derive_flat_icon_imp_redirect.py"


class FlatIconIMPRedirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text())

    def test_compact_method_entry_is_not_misidentified_as_a_pointer(self):
        method = self.manifest["compactMethodEntry"]
        self.assertEqual(method["methodListHeader"]["entrySize"], 12)
        self.assertEqual(method["impFieldEncoding"],
                         "signed 32-bit field-relative offset")
        self.assertEqual(method["mapping"]["initProt"], 5)
        self.assertEqual(method["mapping"]["maxProt"], 5)
        field = int(method["impFieldUnslidVMAddress"], 16)
        offset = int(method["impFieldRawWord"], 16)
        if offset & (1 << 31):
            offset -= 1 << 32
        self.assertEqual(field + offset,
                         int(method["decodedIMPUnslidVMAddress"], 16))

    def test_preoptimized_entry_decodes_to_both_imps(self):
        cls = int(self.manifest["class"]["unslidVMAddress"], 16)
        dispatch = self.manifest["preoptimizedDispatchEntry"]
        replacement = self.manifest["replacement"]
        mask = (1 << 38) - 1

        def decode(text):
            value = int(text, 16) & mask
            if value & (1 << 37):
                value -= 1 << 38
            return cls - value * 4

        self.assertEqual(decode(dispatch["originalValue"]),
                         int(dispatch["decodedOriginalIMPUnslidVMAddress"], 16))
        self.assertEqual(decode(replacement["redirectedEntryValue"]),
                         int(replacement["unslidVMAddress"], 16))
        original_selector = int(dispatch["originalValue"], 16) >> 38
        redirected_selector = int(replacement["redirectedEntryValue"], 16) >> 38
        self.assertEqual(original_selector, redirected_selector)

    def test_guard_changes_only_the_first_eight_bytes(self):
        dispatch = self.manifest["preoptimizedDispatchEntry"]
        guard = dispatch["guard"]
        original = bytes.fromhex(guard["originalBytesHex"])
        redirected = bytes.fromhex(guard["redirectedBytesHex"])
        self.assertEqual(len(original), 32)
        self.assertEqual(len(redirected), 32)
        self.assertEqual(original[8:], redirected[8:])
        self.assertEqual(original[:8],
                         bytes.fromhex(dispatch["originalBytesLE"]))
        self.assertEqual(redirected[:8], bytes.fromhex(
            self.manifest["replacement"]["redirectedEntryBytesLE"]))
        self.assertEqual(hashlib.sha256(original).hexdigest(),
                         guard["originalSHA256"])
        self.assertEqual(hashlib.sha256(redirected).hexdigest(),
                         guard["redirectedSHA256"])

    def test_replacement_is_exact_true_leaf_and_same_subcache(self):
        replacement = self.manifest["replacement"]
        self.assertEqual(bytes.fromhex(replacement["bytesHex"]),
                         struct.pack("<II", 0x52800020, 0xD65F03C0))
        self.assertEqual(replacement["types"], "B16@0:8")
        self.assertTrue(replacement["sameSubcacheAsOriginalIMP"])
        self.assertTrue(replacement["appleSignedCodePageVerified"])

    def test_read_only_data_requires_a_separate_permission_probe(self):
        dispatch = self.manifest["preoptimizedDispatchEntry"]["mapping"]
        boundary = self.manifest["writabilityBoundary"]
        previous = boundary["priorConfirmedProbe"]
        self.assertTrue(dispatch["readOnlyData"])
        self.assertEqual((dispatch["initProt"], dispatch["maxProt"]), (1, 1))
        self.assertEqual((previous["initProt"], previous["maxProt"]), (1, 3))
        self.assertEqual(boundary["status"], "unproven-for-read-only-data")

    def test_deriver_is_offline_and_contains_no_kernel_writer(self):
        source = DERIVER.read_text()
        self.assertIn("This tool is deliberately read-only", source)
        self.assertNotIn("kwrite", source)
        self.assertNotIn("kexploit", source)


if __name__ == "__main__":
    unittest.main()
