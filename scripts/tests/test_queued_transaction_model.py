"""Exercise only the offline Foundation transaction model with synthetic data."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class QueuedTransactionModelTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("xcrun"), "requires macOS Foundation")
    def test_native_model_contract(self):
        with tempfile.TemporaryDirectory(prefix="cnd-queued-model-") as directory:
            binary = Path(directory) / "test-queued-model"
            compiled = subprocess.run([
                "xcrun", "--sdk", "macosx", "clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
                "-framework", "Foundation",
                str(ROOT / "Cyanide/installer/CNDQueuedTransaction.m"),
                str(ROOT / "scripts/tests/test_queued_transaction_model.m"),
                "-o", str(binary),
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            tested = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)
            self.assertIn("PASS:", tested.stdout)


if __name__ == "__main__":
    unittest.main()
