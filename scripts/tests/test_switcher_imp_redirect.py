import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = (ROOT / "docs" / "research" /
            "switcher-imp-redirect-23A341-iphone17,2.json")
DERIVER = ROOT / "scripts" / "derive_switcher_imp_redirect.py"


class SwitcherIMPRedirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text())

    def test_exact_matched_pair_and_required_order(self):
        redirects = self.manifest["redirects"]
        labels = [item["label"] for item in redirects]
        self.assertEqual(labels, [
            "switcher-flat-image-storage",
            "switcher-flat-image-provider",
        ])
        transaction = self.manifest["transaction"]
        self.assertEqual(transaction["semanticWriteCount"], 2)
        self.assertEqual(transaction["applyOrder"], labels)
        self.assertEqual(transaction["restoreOrder"], list(reversed(labels)))
        self.assertTrue(transaction["intermediateStateIsTypeMismatched"])
        self.assertTrue(transaction["requiresSwitcherQuiescence"])

    def test_target_and_replacement_abis_match(self):
        for redirect in self.manifest["redirects"]:
            self.assertEqual(redirect["targetMethod"]["types"],
                             redirect["replacementMethod"]["types"])
            encoding = redirect["replacementEncoding"]
            self.assertTrue(encoding["sameSubcacheAsOriginalIMP"])
            self.assertTrue(encoding["appleSignedCodePageVerified"])

    def test_packed_entries_decode_to_both_imps(self):
        mask = (1 << 38) - 1

        def decode(class_address, value):
            raw = value & mask
            if raw & (1 << 37):
                raw -= 1 << 38
            return class_address - raw * 4

        for redirect in self.manifest["redirects"]:
            class_address = int(redirect["class"]["unslidVMAddress"], 16)
            target = redirect["targetDispatchEntry"]
            replacement = redirect["replacementEncoding"]
            original_value = int(target["originalValue"], 16)
            redirected_value = int(replacement["redirectedValue"], 16)
            self.assertEqual(
                decode(class_address, original_value),
                int(target["decodedOriginalIMPUnslidVMAddress"], 16))
            self.assertEqual(
                decode(class_address, redirected_value),
                int(replacement["sourceIMPUnslidVMAddress"], 16))
            self.assertEqual(original_value >> 38, redirected_value >> 38)

    def test_each_guard_changes_only_one_low_word(self):
        for redirect in self.manifest["redirects"]:
            target = redirect["targetDispatchEntry"]
            guard = target["guard"]
            original = bytes.fromhex(guard["originalBytesHex"])
            redirected = bytes.fromhex(guard["redirectedBytesHex"])
            self.assertEqual(len(original), 32)
            self.assertEqual(len(redirected), 32)
            self.assertNotEqual(original[:4], redirected[:4])
            self.assertEqual(original[4:], redirected[4:])
            self.assertEqual(
                int.from_bytes(original[:4], "little"),
                int(target["originalLowWord"], 16))
            self.assertEqual(
                int.from_bytes(redirected[:4], "little"),
                int(redirect["replacementEncoding"]["redirectedLowWord"], 16))
            self.assertEqual(hashlib.sha256(original).hexdigest(),
                             guard["originalSHA256"])
            self.assertEqual(hashlib.sha256(redirected).hexdigest(),
                             guard["redirectedSHA256"])

    def test_distinct_read_only_pages_require_distinct_permission_proofs(self):
        frames = {
            item["targetDispatchEntry"]["frameUnslidVMAddress"]
            for item in self.manifest["redirects"]
        }
        self.assertEqual(len(frames), 2)
        for redirect in self.manifest["redirects"]:
            mapping = redirect["targetDispatchEntry"]["mapping"]
            self.assertTrue(mapping["readOnlyData"])
            self.assertEqual((mapping["initProt"], mapping["maxProt"]),
                             (1, 1))
        transaction = self.manifest["transaction"]
        self.assertEqual(transaction["distinct16KTargetPages"], 2)
        self.assertTrue(
            transaction["requiresExactIdenticalBytesPermissionProofPerPage"])

    def test_app_library_composite_remains_a_separate_open_problem(self):
        finding = self.manifest["appLibraryMiniatureFinding"]
        self.assertEqual(finding["consumer"], "SBFolderIconImageCache")
        self.assertEqual(
            finding["status"],
            "separate-composite-route-no-dispatch-redirect-selected")
        self.assertIn("27-point", finding["conclusion"])

    def test_deriver_is_offline_and_contains_no_kernel_writer(self):
        source = DERIVER.read_text()
        self.assertIn("This tool is deliberately read-only", source)
        self.assertNotIn("kwrite", source)
        self.assertNotIn("kexploit", source)


if __name__ == "__main__":
    unittest.main()
