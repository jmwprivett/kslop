"""Offline checks for the benign Spotlight PDF reachability probe."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "scripts" / "lab"
sys.path.insert(0, str(LAB))

import cnd_spotlight_pdf_reachability as probe  # noqa: E402


class SpotlightPDFReachabilityTests(unittest.TestCase):
    def test_build_is_read_only_and_query_is_explicit(self) -> None:
        with mock.patch.object(probe, "run") as run:
            probe.build("eBay", True)
        compiler = run.call_args_list[0].args[0]
        self.assertIn('-DCND_PDF_TRACE_QUERY="eBay"', compiler)
        self.assertIn("-DCND_PDF_TRACE_SET_QUERY=1", compiler)

    def test_source_hooks_only_pdf_materialization_boundaries(self) -> None:
        source = probe.SOURCE.read_text(encoding="utf-8")
        self.assertIn("_CUIThemePDFRendition", source)
        self.assertIn("_initWithCSIHeader:version:", source)
        self.assertIn("createImageFromPDFRenditionWithScale:", source)
        self.assertIn("CUINamedVectorPDFImage", source)
        self.assertIn("CND_SPOTLIGHT_PDF_CANARY_V1", source)
        self.assertNotIn("effectivelyPrefersFlatImageLayers", source)

    def test_query_rejects_multiline_input(self) -> None:
        with self.assertRaises(probe.LabError):
            probe.build("eBay\nother")

    def test_pass_requires_init_and_render_in_same_report(self) -> None:
        probe.validate_pass(
            "TRACE_READY\nCANARY_PDF_INIT\nCANARY_PDF_RENDER\n"
        )
        with self.assertRaises(probe.LabError):
            probe.validate_pass("TRACE_READY\nCANARY_PDF_RENDER\n")


if __name__ == "__main__":
    unittest.main()
