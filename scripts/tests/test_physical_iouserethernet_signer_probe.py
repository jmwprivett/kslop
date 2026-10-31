import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "Cyanide/CNDPhysicalIOUserEthernetSignerProbe.m"
APP_DELEGATE = ROOT / "Cyanide/AppDelegate.m"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"


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

    def test_launch_argument_also_runs_the_probe(self) -> None:
        source = APP_DELEGATE.read_text()
        self.assertIn('--iouserethernet-signer-probe', source)
        self.assertIn("CNDPhysicalIOUserEthernetSignerProbeRun", source)

    def test_settings_exposes_the_probe_row(self) -> None:
        settings = SETTINGS.read_text()
        self.assertIn('"CNDPhysicalIOUserEthernetSignerProbe.h"', settings)
        self.assertIn(
            "CNDPhysicalIOUserEthernetSignerProbeIsSupported(&reason)", settings
        )
        self.assertIn("Run IOUserEthernet Signer Probe", settings)
        # The Quick Actions row count stays pinned.
        self.assertIn("case RootSectionActions:        return 6;", settings)

    def test_finished_probe_does_not_read_as_still_running(self) -> None:
        source = SOURCE.read_text()
        # The flag is cleared and the run is over before completion fires, so
        # the report must not keep its last in-flight state on disk.
        run_once = source.index("CNDPhysicalSignerRunOnce();")
        released = source.index(
            "__sync_lock_release(&gCNDPhysicalSignerProbeRunning);")
        terminal = source.index('@"state", @"finished"')
        self.assertLess(run_once, released)
        self.assertLess(released, terminal)

        # And the completion has to stop the Activity sheet's footer, which
        # only ends on the installer's completion notification, and rebuild the
        # row, whose title otherwise keeps reading "… Running…".
        settings = SETTINGS.read_text()
        self.assertIn("- (void)finishProbeActivityForRow:(NSInteger)row",
                      settings)
        self.assertIn("settings_post_actions_complete_async(", settings)
        self.assertIn('@"physical-krw-triggered-normal-signer-path";',
                      settings)
        self.assertRegex(
            settings,
            r"- \(void\)reloadProbeRows\s*\{[^}]*RootSectionProbes",
        )
        logged = settings.index('"[IOUSERETHERNET_SIGNER] result=%s report=%s\\n"')
        finished = settings.index(
            "[strongSelf finishProbeActivityForRow:row", logged)
        self.assertLess(logged, finished)


if __name__ == "__main__":
    unittest.main()
