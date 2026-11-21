"""Exercise the pure KRW lifecycle projection with synthetic observations."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class KRWLifecycleSnapshotTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("xcrun"),
                         "requires macOS Foundation")
    def test_native_projection_contract(self):
        with tempfile.TemporaryDirectory(prefix="cnd-krw-snapshot-") as directory:
            binary = Path(directory) / "test-krw-snapshot"
            compiled = subprocess.run([
                "xcrun", "--sdk", "macosx", "clang", "-fobjc-arc",
                "-Wall", "-Wextra", "-Werror", "-framework", "Foundation",
                str(ROOT / "Cyanide/kexploit/CNDKRWLifecycleSnapshot.m"),
                str(ROOT / "scripts/tests/test_krw_lifecycle_snapshot.m"),
                "-o", str(binary),
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            tested = subprocess.run([str(binary)], capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(tested.returncode, 0,
                             tested.stdout + tested.stderr)
            self.assertIn("PASS:", tested.stdout)


if __name__ == "__main__":
    unittest.main()
