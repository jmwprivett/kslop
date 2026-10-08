"""Validate the checked-in Pulsar package geometry."""

from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]


class CCThemingDeliveryTests(unittest.TestCase):
    def test_every_generated_static_package_uses_pulsar_centered_coordinates(self):
        packages = sorted((ROOT / "Cyanide/PulsarControlCenter.bundle").glob("Static*.ca"))
        self.assertGreaterEqual(len(packages), 32)
        self.assertTrue({"StaticTimer.ca", "StaticNightShift.ca", "StaticTrueTone.ca"}
                        <= {package.name for package in packages})
        ns = {"ca": "http://www.apple.com/CoreAnimation/1.0"}
        for package in packages:
            with self.subTest(package=package.name):
                document = ET.parse(package / "main.caml")
                root = document.find("ca:CALayer", ns)
                self.assertEqual(root.attrib["position"], "-0.5 0")
                children = root.findall("ca:sublayers/ca:CALayer", ns)
                self.assertEqual(len(children), 2)
                self.assertEqual([layer.attrib["position"] for layer in children], ["0 0", "0 0"])


if __name__ == "__main__":
    unittest.main()
