"""Host-side geometry checks for the Timer's Stopwatch artwork package."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "generate_pulsar_controlcenter_artwork",
    ROOT / "scripts/generate_pulsar_controlcenter_artwork.py",
)
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)
NS = {"ca": "http://www.apple.com/CoreAnimation/1.0"}


class PulsarTimerArtworkTests(unittest.TestCase):
    def test_timer_document_origin_keeps_both_states_at_consumer_center(self):
        caml = GENERATOR.static_caml(
            consumer_positioned_root=True, artwork_scale=1.4)
        root = ET.fromstring(caml).find("ca:CALayer", NS)
        self.assertNotIn("bounds", root.attrib)
        self.assertEqual(root.attrib["position"], "-0.5 0")
        self.assertNotIn("transform", root.attrib)

        # After the consumer positions the root at its glyph center, a child
        # at (0, 0) is offset by root.bounds.origin + anchor * root.bounds.size.
        # The former 40x40 root therefore shifted both image centers by -20.
        root_bounds = tuple(float(x) for x in root.get(
            "bounds", "0 0 0 0").split())
        anchor = tuple(float(x) for x in root.get(
            "anchorPoint", "0.5 0.5").split())
        images = root.findall("ca:sublayers/ca:CALayer", NS)
        self.assertEqual(len(images), 2)
        for image in images:
            with self.subTest(state=image.attrib["id"]):
                position = tuple(float(x) for x in image.attrib["position"].split())
                offset = tuple(position[i] - root_bounds[i] -
                               anchor[i] * root_bounds[i + 2] for i in range(2))
                self.assertEqual(offset, (0.0, 0.0))
                self.assertEqual(image.attrib["bounds"], "0 0 56 56")

    def test_bundled_timer_matches_generated_document(self):
        bundled = (ROOT / "Cyanide/PulsarControlCenter.bundle/StaticTimer.ca/main.caml"
                   ).read_text(encoding="utf-8")
        self.assertEqual(bundled, GENERATOR.static_caml(
            consumer_positioned_root=True, artwork_scale=1.4))

    def test_other_packages_and_stopwatch_artwork_are_preserved(self):
        root = ET.fromstring(GENERATOR.static_caml()).find("ca:CALayer", NS)
        self.assertEqual(root.attrib["bounds"], "0 0 40 40")
        self.assertNotIn("transform", root.attrib)
        self.assertEqual(GENERATOR.STATIC_PACKAGE_ARTWORK_SCALES, {"timer": 1.4})
        self.assertEqual(GENERATOR.ARTWORK["timer"][:2],
                         GENERATOR.ARTWORK["stopwatch"][:2])


if __name__ == "__main__":
    unittest.main()
