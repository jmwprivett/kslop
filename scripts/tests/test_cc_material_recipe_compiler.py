"""Compile and exercise the offline material recipe API against synthetic plists."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CCMaterialRecipeCompilerTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("xcrun"), "requires macOS Foundation")
    def test_native_compiler_contract_and_process_determinism(self):
        with tempfile.TemporaryDirectory(prefix="cnd-material-recipe-") as directory:
            binary = Path(directory) / "test-material-recipe"
            compiled = subprocess.run([
                "xcrun", "clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
                "-framework", "Foundation",
                str(ROOT / "Cyanide/tweaks/CNDCCMaterialRecipeCompiler.m"),
                str(ROOT / "scripts/tests/test_cc_material_recipe_compiler.m"),
                "-o", str(binary),
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            outputs = []
            for _ in range(3):
                tested = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)
                self.assertIn("PASS:", tested.stdout)
                outputs.append(tested.stdout.split("DETERMINISM:", 1)[1].strip())
            self.assertEqual(len(set(outputs)), 1, "recipe bytes must match across independent processes")


if __name__ == "__main__":
    unittest.main()
