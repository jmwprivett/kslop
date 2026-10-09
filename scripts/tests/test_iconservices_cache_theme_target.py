"""Offline checks for targeting one IconServices test record."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab"))
import cnd_iconservices_cache_theme as theme  # noqa: E402
import cnd_iconservices_inspection as inspection  # noqa: E402
import cnd_springboard_refresh_probe as refresh  # noqa: E402


FILES = "com.apple.DocumentsApp"


class ExplicitBundleTargetTests(unittest.TestCase):
    def test_pdf_canary_builds_direct_coreui_archive(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "lab" /
                  "cnd_iconservices_cache_theme.m").read_text()
        self.assertIn("static NSData *CNDThemeBuildDirectPDFArchive", source)
        self.assertIn("0x50444620U", source)
        self.assertIn('"@32@0:8@16I24s28"', source)
        self.assertIn("addLayerReference:forGroupToLayerStackWithName:",
                      source)
        self.assertIn("PDF_DIRECT_ARCHIVE", source)

    def test_validates_bundle_before_compiling(self) -> None:
        for bundle in ("", "ebay", "com..bad", "com.bad;touch /tmp/x",
                       'com.bad"-DOTHER', "com.bad\n", "com.bäd",
                       "com." + "a" * 200):
            with self.subTest(bundle=bundle), self.assertRaises(
                inspection.LabError
            ):
                inspection.validate_bundle(bundle)
        self.assertEqual(inspection.validate_bundle(FILES), FILES)
        self.assertEqual(inspection.validate_bundle("com.ebay.iphone"),
                         "com.ebay.iphone")

    def test_mutator_compiles_selected_target(self) -> None:
        with mock.patch.object(theme, "run") as run:
            theme.build_mutator(bundle=FILES)
        compiler_args = run.call_args_list[0].args[0]
        self.assertIn('-DCND_ICON_THEME_TARGET_BUNDLE="' + FILES + '"',
                      compiler_args)
        with mock.patch.object(theme, "run") as run:
            theme.build_mutator()
        self.assertIn('-DCND_ICON_THEME_TARGET_BUNDLE="com.ebay.iphone"',
                      run.call_args_list[0].args[0])

    def test_mutator_flat_payload_is_explicit_and_defaults_off(self) -> None:
        with mock.patch.object(theme, "run") as run:
            theme.build_mutator(bundle=FILES)
        self.assertIn("-DCND_ICON_THEME_FLAT_PAYLOAD=0",
                      run.call_args_list[0].args[0])

        with mock.patch.object(theme, "run") as run:
            theme.build_mutator(bundle=FILES, flat_payload=True)
        self.assertIn("-DCND_ICON_THEME_FLAT_PAYLOAD=1",
                      run.call_args_list[0].args[0])

    def test_pdf_canary_is_benign_deterministic_and_explicit(self) -> None:
        first = theme.pdf_canary_bytes()
        second = theme.pdf_canary_bytes()
        self.assertEqual(first, second)
        self.assertTrue(first.startswith(b"%PDF-1.4\n"))
        self.assertIn(theme.PDF_CANARY_SUBJECT.encode("ascii"), first)
        self.assertIn(b"/Count 1", first)
        self.assertNotIn(b"/JBIG2Decode", first)

        with mock.patch.object(theme, "run") as run:
            theme.build_mutator(
                bundle=FILES,
                pdf_canary_path="/var/tmp/canary.pdf",
                expected_pdf_canary_hash="c" * 64,
            )
        compiler_args = run.call_args_list[0].args[0]
        self.assertIn("-DCND_ICON_THEME_PDF_CANARY=1", compiler_args)
        self.assertIn(
            '-DCND_ICON_THEME_PDF_CANARY_PATH="/var/tmp/canary.pdf"',
            compiler_args,
        )
        self.assertIn(
            '-DCND_ICON_THEME_EXPECTED_PDF_SHA256="' + "c" * 64 + '"',
            compiler_args,
        )

    def test_restore_trigger_uses_selected_target(self) -> None:
        with mock.patch.object(sys, "argv", ["cache_theme", "restore",
                                             "--bundle", FILES]), \
             mock.patch.object(theme, "make_ssh") as make_ssh, \
             mock.patch.object(theme, "build_trigger") as build_trigger, \
             mock.patch.object(theme, "copy_executable",
                               return_value="/var/tmp/trigger"), \
             mock.patch.object(theme, "restore_stock") as restore_stock:
            build_trigger.return_value = Path("/tmp/trigger")
            self.assertEqual(theme.main(), 0)
        restore_stock.assert_called_once_with(
            make_ssh.return_value,
            ("/var/tmp/trigger --bundle com.apple.DocumentsApp "
             "--variant 0 --variant-options 0 "
             "--point-size 68 --appearance 0"),
        )

    def test_run_uses_selected_target_for_mutator_and_trigger(self) -> None:
        response = ("CND_ICON_TRIGGER complete image=0x1/IFCacheImage "
                    "uuid=AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE data=3/" +
                    "a" * 64)
        with mock.patch.object(sys, "argv", ["cache_theme", "run",
                                             "--bundle", FILES]), \
             mock.patch.object(theme, "make_ssh") as make_ssh, \
             mock.patch.object(theme, "build_trigger"), \
             mock.patch.object(theme, "copy_executable",
                               return_value="/var/tmp/trigger"), \
             mock.patch.object(theme, "terminate_exact_agent"), \
             mock.patch.object(theme, "copy_theme",
                               return_value=("/var/tmp/theme.png", "b" * 64)), \
             mock.patch.object(theme, "issue_file_extension",
                               return_value="token"), \
             mock.patch.object(theme, "build_mutator") as build_mutator, \
             mock.patch.object(theme, "build_hold"), \
             mock.patch.object(theme, "start_hold", return_value=7), \
             mock.patch.object(theme, "stop_hold"), \
             mock.patch.object(theme, "resolve_target",
                               return_value=(42, "iconservicesagent")), \
             mock.patch.object(theme, "inject", return_value="/var/tmp/mutator"), \
             mock.patch.object(theme, "wait_ready"), \
             mock.patch.object(theme, "read_report",
                               return_value="THEME_APPLIED"), \
             mock.patch.object(theme.time, "sleep"):
            make_ssh.return_value.command.return_value = response
            self.assertEqual(theme.main(), 0)
        self.assertEqual(build_mutator.call_args.kwargs["bundle"], FILES)
        self.assertEqual(
            build_mutator.call_args.kwargs["expected_theme_hash"], "b" * 64
        )
        self.assertEqual(make_ssh.return_value.command.call_args_list[0].args[0],
                         ("/var/tmp/trigger --bundle com.apple.DocumentsApp "
                          "--variant 0 --variant-options 0 "
                          "--point-size 68 --appearance 0 --ignore-cache"))
        self.assertEqual(make_ssh.return_value.command.call_args_list[1].args[0],
                         ("/var/tmp/trigger --bundle com.apple.DocumentsApp "
                          "--variant 0 --variant-options 0 "
                          "--point-size 68 --appearance 0"))

    def test_refresh_compiles_selected_target(self) -> None:
        with mock.patch.object(refresh, "run") as run:
            refresh.build("target-cache", bundle=FILES)
        compiler_args = run.call_args_list[0].args[0]
        self.assertIn('-DCND_REFRESH_PROBE_TARGET_BUNDLE="' + FILES + '"',
                      compiler_args)


if __name__ == "__main__":
    unittest.main()
