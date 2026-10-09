import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = (ROOT / "docs" / "research" /
            "special-icon-class-redirect-23A341-iphone17,2.json")
DERIVER = ROOT / "scripts" / "derive_special_icon_class_redirect.py"


class SpecialIconClassRedirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text())

    def test_special_helper_is_limited_to_clock_and_calendar(self):
        special = self.manifest["specialSelection"]
        self.assertEqual(special["hardCodedBundleIdentifiers"], [
            "com.apple.mobiletimer",
            "com.apple.mobilecal",
        ])
        self.assertEqual(
            special["ordinaryTail"],
            "+[SBHIconModel applicationIconClass]")

    def test_target_and_replacement_have_a_safe_machine_call_shape(self):
        target = self.manifest["targetMethod"]
        replacement = self.manifest["replacementMethod"]
        compatibility = replacement["machineCallCompatibility"]
        self.assertEqual(target["types"], "#24@0:8@16")
        self.assertEqual(replacement["types"], "#16@0:8")
        self.assertTrue(compatibility["compatible"])
        self.assertFalse(compatibility["exactObjectiveCTypeEncodingMatch"])
        self.assertEqual(
            replacement["semantics"],
            "returns the ordinary SBApplicationIcon class")
        self.assertTrue(replacement["sameSubcacheAsOriginalIMP"])
        self.assertTrue(replacement["appleSignedCodePageVerified"])

    def test_packed_entry_decodes_to_both_imps(self):
        class_address = int(
            self.manifest["class"]["unslidVMAddress"], 16)
        target = self.manifest["preoptimizedDispatchEntry"]
        replacement = self.manifest["replacementMethod"]
        mask = (1 << 38) - 1

        def decode(text):
            raw = int(text, 16) & mask
            if raw & (1 << 37):
                raw -= 1 << 38
            return class_address - raw * 4

        original = target["originalValue"]
        redirected = replacement["redirectedEntryValue"]
        self.assertEqual(
            decode(original),
            int(target["decodedOriginalIMPUnslidVMAddress"], 16))
        self.assertEqual(
            decode(redirected),
            int(replacement["unslidVMAddress"], 16))
        self.assertEqual(int(original, 16) >> 38,
                         int(redirected, 16) >> 38)

    def test_redirect_changes_only_one_low_word(self):
        dispatch = self.manifest["preoptimizedDispatchEntry"]
        replacement = self.manifest["replacementMethod"]
        guard = dispatch["guard"]
        original = bytes.fromhex(guard["originalBytesHex"])
        redirected = bytes.fromhex(guard["redirectedBytesHex"])
        self.assertEqual(len(original), 32)
        self.assertEqual(len(redirected), 32)
        self.assertNotEqual(original[:4], redirected[:4])
        self.assertEqual(original[4:], redirected[4:])
        self.assertEqual(
            int.from_bytes(original[:4], "little"),
            int(dispatch["originalLowWord"], 16))
        self.assertEqual(
            int.from_bytes(redirected[:4], "little"),
            int(replacement["redirectedLowWord"], 16))
        self.assertEqual(hashlib.sha256(original).hexdigest(),
                         guard["originalSHA256"])
        self.assertEqual(hashlib.sha256(redirected).hexdigest(),
                         guard["redirectedSHA256"])
        self.assertEqual(
            self.manifest["writeShape"]["semanticWriteCount"], 1)

    def test_new_page_needs_its_own_permission_and_shared_frame_proof(self):
        dispatch = self.manifest["preoptimizedDispatchEntry"]
        mapping = dispatch["mapping"]
        boundary = self.manifest["runtimeBoundary"]
        self.assertTrue(mapping["readOnlyData"])
        self.assertEqual((mapping["initProt"], mapping["maxProt"]), (1, 1))
        self.assertFalse(boundary["samePageAsPriorPermissionProof"])
        self.assertNotEqual(boundary["priorConfirmed16KPage"],
                            boundary["target16KPage"])
        self.assertEqual(boundary["target16KPage"],
                         dispatch["frameUnslidVMAddress"])
        self.assertEqual(boundary["status"],
                         "offline-derived-runtime-unverified")

    def test_deriver_is_offline_and_contains_no_kernel_writer(self):
        source = DERIVER.read_text()
        self.assertIn("This tool is deliberately read-only", source)
        self.assertNotIn("kwrite", source)
        self.assertNotIn("kexploit", source)


if __name__ == "__main__":
    unittest.main()
