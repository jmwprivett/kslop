import importlib.util
import plistlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))
MODULE_PATH = ROOT / "scripts/lab/cnd_iouserethernet_signer_trigger.py"
SPEC = importlib.util.spec_from_file_location("iouserethernet_trigger", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class IOUserEthernetSignerTriggerTests(unittest.TestCase):
    def test_entitlement_is_narrow(self) -> None:
        with MODULE.TRIGGER_ENTITLEMENTS.open("rb") as stream:
            self.assertEqual(plistlib.load(stream), {
                "com.apple.networking.ethernet.user-access": True,
            })

    def test_validate_accepts_new_bsd_interface(self) -> None:
        report = {
            "schema": "com.zeroxjf.cyanide.iouserethernet-signer-trigger",
            "schemaVersion": 1,
            "openKR": "0x0000000000000000",
            "callKR": "0x0000000000000000",
            "kernelReadUsed": False,
            "kernelWriteUsed": False,
            "kernelCallUsed": False,
            "createdInterfaces": [{"registryID": "0x1", "bsdName": "cnd0"}],
        }
        self.assertIs(MODULE.validate_result(report), report)

    def test_validate_rejects_missing_bsd_interface(self) -> None:
        report = {
            "schema": "com.zeroxjf.cyanide.iouserethernet-signer-trigger",
            "schemaVersion": 1,
            "openKR": "0x0000000000000000",
            "callKR": "0x0000000000000000",
            "kernelReadUsed": False,
            "kernelWriteUsed": False,
            "kernelCallUsed": False,
            "createdInterfaces": [],
        }
        with self.assertRaises(MODULE.LabError):
            MODULE.validate_result(report)

    def test_source_never_imports_kernel_protocol(self) -> None:
        source = MODULE.TRIGGER_SOURCE.read_text()
        self.assertNotIn("CNDLabKernelProtocol", source)
        self.assertIn("IOUserEthernetResource", source)
        self.assertIn("IOCFSerialize", source)

    def test_harness_links_only_required_frameworks(self) -> None:
        source = MODULE_PATH.read_text()
        self.assertIn('frameworks=("Foundation", "IOKit")', source)


if __name__ == "__main__":
    unittest.main()
