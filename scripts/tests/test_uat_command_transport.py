#!/usr/bin/env python3
"""Static contract for the in-process physical UAT command transport."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class UATCommandTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app_header = (ROOT / "Cyanide/AppDelegate.h").read_text()
        cls.app = (ROOT / "Cyanide/AppDelegate.m").read_text()
        cls.scene = (ROOT / "Cyanide/SceneDelegate.m").read_text()
        cls.host = (ROOT / "scripts/lab/cnd_live_probe.py").read_text()

    def test_url_transport_is_exported_and_pid_local(self) -> None:
        self.assertIn("BOOL CNDHandleCommandURL", self.app_header)
        self.assertIn('isEqualToString:@"com.zeroxjf.ios-cyanide1"', self.app)
        self.assertIn('isEqualToString:@"probe"', self.app)
        self.assertIn('@[ @"control", @"image", @"queue" ]', self.app)
        self.assertIn("CNDCmdRun(cmd, source", self.app)

    def test_running_and_cold_scene_deliveries_are_handled(self) -> None:
        self.assertIn("connectionOptions.URLContexts", self.scene)
        self.assertIn("openURLContexts:", self.scene)
        self.assertGreaterEqual(self.scene.count("CNDHandleCommandURL("), 2)

    def test_url_command_only_consumes_existing_krw(self) -> None:
        start = self.app.index("static void CNDCmdRun(")
        end = self.app.index("// Legacy in-container command pickup", start)
        runner = self.app[start:end]
        self.assertIn("kexploit_krw_ready()", runner)
        self.assertNotIn("kexploit_opa334()", runner)
        self.assertIn('@"pid": @(getpid())', runner)

    def test_host_helper_never_opens_or_replaces_the_app_container(self) -> None:
        self.assertIn('"--payload-url"', self.host)
        self.assertNotIn('"appDataContainer"', self.host)
        self.assertNotIn('"--terminate-existing"', self.host)


if __name__ == "__main__":
    unittest.main()
