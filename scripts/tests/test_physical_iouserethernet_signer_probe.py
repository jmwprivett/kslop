import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Cyanide/CNDPhysicalIOUserEthernetSignerProbe.m"
APP_DELEGATE = ROOT / "Cyanide/AppDelegate.m"


class PhysicalIOUserEthernetSignerProbeTests(unittest.TestCase):
    def test_probe_uses_physical_whole_label_writer_without_kcall(self) -> None:
        source = SOURCE.read_text()
        self.assertIn("kexploit_early_kwrite32bytes_checked", source)
        self.assertIn("CNDPhysicalSignerLabelSize = 0x20", source)
        self.assertNotIn("kernel_call", source.lower())
        self.assertNotIn("CNDLabKRWOperationKernelCall", source)

    def test_probe_borrows_both_gate_policies(self) -> None:
        source = SOURCE.read_text()
        self.assertIn('"off_label_l_perpolicy_amfi"', source)
        self.assertIn('"off_label_l_perpolicy_sandbox"', source)
        self.assertIn("donorAMFIObject", source)
        self.assertIn("donorSandboxObject", source)

    def test_probe_restores_before_selector(self) -> None:
        source = SOURCE.read_text()
        restore = source.index(
            "bool restored = CNDPhysicalSignerRestore(&kernel, &borrow);"
        )
        selector = source.index("iokit.connectCallMethod(")
        self.assertLess(restore, selector)
        self.assertIn('report[@"selectorInvokedAfterRestore"] = @YES;', source)

    def test_probe_resolves_labels_after_negative_baseline(self) -> None:
        source = SOURCE.read_text()
        baseline = source.index('report[@"baselineOpenKR"]')
        labels = source.index('report[@"labelResolvedAfterBaseline"]')
        self.assertLess(baseline, labels)

    def test_launch_argument_runs_without_settings_button(self) -> None:
        source = APP_DELEGATE.read_text()
        self.assertIn('--iouserethernet-signer-probe', source)
        self.assertIn("CNDPhysicalIOUserEthernetSignerProbeRun", source)


if __name__ == "__main__":
    unittest.main()
