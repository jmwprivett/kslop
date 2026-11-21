import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/derive_special_icon_presentation_dispatch_redirect.py"
MANIFEST = (
    ROOT
    / "docs/research/special-icon-presentation-dispatch-23A341-iphone17,2.json"
)
CACHE = (
    ROOT
    / ".research/cve-2026-86950/23A341-extracted/23A341__iPhone17,2"
    / "dyld_shared_cache_arm64e"
)


class SpecialIconPresentationDispatchTests(unittest.TestCase):
    def test_manifest_keeps_static_and_runtime_evidence_separate(self):
        manifest = json.loads(MANIFEST.read_text())

        self.assertEqual(manifest["build"], "23A341")
        self.assertEqual(manifest["product"], "iPhone17,2")
        self.assertEqual(manifest["evidenceClass"], "static-derived")
        self.assertFalse(manifest["runtimeVerified"])
        self.assertEqual(manifest["clock"]["status"], "static-candidate")
        self.assertEqual(
            manifest["calendar"]["status"],
            "candidate-for-bounded-runtime-probe-only",
        )
        self.assertEqual(
            manifest["calendar"]["negativeEvidence"]["status"],
            "rejected-by-retained-runtime-evidence",
        )
        self.assertEqual(
            manifest["calendar"]["retainedTwoFactoryGreyEvidence"]["status"],
            "rejected-by-user-observed-physical-appearance",
        )

    def test_route_has_no_visibility_injection_or_object_migration_precondition(self):
        boundary = json.loads(MANIFEST.read_text())["runtimeBoundary"]

        self.assertFalse(boundary["writerIncluded"])
        self.assertFalse(boundary["deviceOperationPerformed"])
        self.assertFalse(boundary["processInjectionRequiredByDesign"])
        self.assertFalse(boundary["remoteCallRequiredByDesign"])
        self.assertFalse(boundary["homeVisibilityPreconditionByDesign"])
        self.assertFalse(boundary["canonicalObjectMigrationRequiredByDesign"])
        self.assertTrue(boundary["processRestartAfterApplyRequired"])
        self.assertEqual(
            boundary["targetFrames"],
            ["0x1ffc00000", "0x1ffc18000"],
        )
        self.assertTrue(
            boundary["sameBootIdenticalWriteTicketRequiredPerFrame"]
        )

    def test_all_candidate_redirects_are_low_word_only_and_abi_exact(self):
        manifest = json.loads(MANIFEST.read_text())
        redirects = (
            manifest["clock"]["redirects"]
            + manifest["calendar"]["redirects"]
        )

        self.assertEqual(len(redirects), 4)
        for redirect in redirects:
            original = int(
                redirect["dispatch"]["original"]["packedWord"], 16
            )
            redirected = int(
                redirect["dispatch"]["redirected"]["packedWord"], 16
            )
            self.assertEqual(original >> 32, redirected >> 32)
            self.assertNotEqual(original & 0xFFFFFFFF, redirected & 0xFFFFFFFF)
            self.assertTrue(redirect["replacement"]["abiExact"])
            self.assertTrue(redirect["replacement"]["appleSharedCacheCode"])

    @unittest.skipUnless(
        CACHE.is_file() and shutil.which("ipsw"),
        "exact retained cache and ipsw tool are required",
    )
    def test_reviewed_manifest_rederives_from_exact_cache(self):
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--cache",
                str(CACHE),
                "--verify-manifest",
                str(MANIFEST),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Verified 23A341/iPhone17,2", result.stdout)


if __name__ == "__main__":
    unittest.main()
