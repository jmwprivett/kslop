import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "lab" / "cnd_iosurface_panic_symbolicate.py"
SPEC = importlib.util.spec_from_file_location("cnd_iosurface_panic_symbolicate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class IOSurfacePanicSymbolicateTests(unittest.TestCase):
    def test_normalizes_panic_and_iosurface_frames(self):
        panic_string = """panic(cpu 1 caller 0xfffffe0000000000): Kernel data abort. at pc 0xfffffe0048fa0284, lr 0xfffffe004a536544 (saved state: 0x1)
\t pc: 0xfffffe0048fa0284 esr: 0x96000006 far: 0x0000000000000008
Fileset Kernelcache UUID: 10C76B412BAD52CA8217AB748064C02B
Kernel UUID: 03A93373-6498-3F25-8975-04DED251AF1F
KernelCache slide: 0x0000000041490000
Panicked thread:
\t\t  lr: 0xfffffe004a52d268  fp: 0x1
\t\t  lr: 0xfffffe004a51b644  fp: 0x2
\t\t  lr: 0xfffffe004a534134  fp: 0x3
Kernel Extensions in backtrace:
 com.apple.iokit.IOSurface(393.2.9)[8132EC95-DE46-3731-9931-024187C84DD2]@0xfffffe004a50e2b0->0xfffffe004a53fadb
"""
        header = {
            "incident_id": "F0BAB6CF-BB6B-4056-B758-7C5CB98C2FEA",
            "os_version": "iPhone OS 26.0 (23A341)",
        }
        body = {"incident": header["incident_id"], "panicString": panic_string}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "panic.ips"
            path.write_text(json.dumps(header) + "\n" + json.dumps(body), encoding="utf-8")
            result = MODULE.parse_panic(path)

        self.assertEqual(result["normalized"]["pc"], "0xfffffe0007b10284")
        self.assertEqual(result["normalized"]["lr"], "0xfffffe00090a6544")
        self.assertEqual(
            result["normalized"]["iosurface_text_exec_base"],
            "0xfffffe000907e2b0",
        )
        self.assertEqual(result["normalized"]["iosurface_lr_offset"], "0x28294")
        self.assertEqual(
            result["normalized"]["iosurface_backtrace_frame_offsets"],
            ["0x1efb8", "0xd394", "0x25e84"],
        )
        self.assertEqual(result["runtime"]["far"], "0x0000000000000008")


if __name__ == "__main__":
    unittest.main()
