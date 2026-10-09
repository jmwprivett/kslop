"""Execute truthful coverage reporting against local installation records."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class CCThemingCoverageTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("xcrun"),
                         "requires macOS Foundation")
    def test_captured_receivers_never_imply_expanded_or_reconstruction_coverage(self):
        with tempfile.TemporaryDirectory(prefix="cyanide-cc-coverage-") as directory:
            binary = Path(directory) / "test-coverage"
            compiled = subprocess.run([
                "xcrun", "clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
                "-framework", "Foundation",
                str(ROOT / "scripts/tests/test_cc_theming_coverage.m"),
                "-o", str(binary),
            ], capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            tested = subprocess.run([str(binary)], capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)
            self.assertIn("captured coverage assertions passed", tested.stdout)

    def test_reporting_helper_performs_no_remote_operations(self):
        source = (ROOT / "Cyanide/tweaks/CNDCCThemingCoverage.h").read_text()
        for forbidden in ("remote_call", "remote_write", "r_msg", "r_ivar",
                          "object_setClass", "TaskRop", "method_setImplementation"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
