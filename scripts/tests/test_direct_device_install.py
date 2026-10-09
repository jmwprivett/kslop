"""Structural safety checks for the direct physical-device scripts."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = ROOT / "scripts/build-device.sh"
INSTALL_SCRIPT = ROOT / "scripts/install-device.sh"


class DirectDeviceScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build_source = BUILD_SCRIPT.read_text(encoding="utf-8")
        cls.install_source = INSTALL_SCRIPT.read_text(encoding="utf-8")

    def test_both_scripts_are_executable_and_have_separate_jobs(self) -> None:
        self.assertTrue(BUILD_SCRIPT.stat().st_mode & 0o111)
        self.assertTrue(INSTALL_SCRIPT.stat().st_mode & 0o111)
        self.assertIn("xcodebuild", self.build_source)
        self.assertNotIn("devicectl device install app", self.build_source)
        self.assertNotIn("xcodebuild", self.install_source)
        self.assertNotIn("codesign --force", self.install_source)

    def test_every_build_uses_current_sources_and_fresh_output(self) -> None:
        self.assertIn("DirectDeviceUpdate-$STAMP", self.build_source)
        self.assertIn('mkdir "$UPDATE_DIR"', self.build_source)
        self.assertIn("ARCHS='arm64 arm64e'", self.build_source)
        self.assertIn("ONLY_ACTIVE_ARCH=NO", self.build_source)
        self.assertIn("CODE_SIGNING_ALLOWED=NO", self.build_source)
        self.assertIn("-sdk iphoneos", self.build_source)
        self.assertNotIn("IPA_OUT", self.build_source)

    def test_build_signs_nested_code_before_app_and_verifies_both(self) -> None:
        dylib_sign = self.build_source.index(
            'codesign --force --sign "$IDENTITY" --timestamp=none "$XPF_DYLIB"'
        )
        app_sign = self.build_source.index(
            '--entitlements "$ENTITLEMENTS" --generate-entitlement-der "$APP"',
            dylib_sign,
        )
        dylib_verify = self.build_source.index(
            'codesign --verify --strict --verbose=2 "$XPF_DYLIB"',
            app_sign,
        )
        app_verify = self.build_source.index(
            'codesign --verify --deep --strict --verbose=2 "$APP"',
            dylib_verify,
        )
        self.assertLess(dylib_sign, app_sign)
        self.assertLess(app_sign, dylib_verify)
        self.assertLess(dylib_verify, app_verify)

    def test_build_publishes_latest_marker_only_after_verification(self) -> None:
        app_verify = self.build_source.index(
            'codesign --verify --deep --strict --verbose=2 "$APP"'
        )
        marker_write = self.build_source.index(
            "LATEST_ARTIFACT_TMP=", app_verify
        )
        marker_publish = self.build_source.index(
            'mv "$LATEST_ARTIFACT_TMP" "$LATEST_ARTIFACT_FILE"', marker_write
        )
        self.assertLess(app_verify, marker_write)
        self.assertLess(marker_write, marker_publish)
        self.assertIn("DirectDeviceUpdate-latest.txt", self.build_source)

    def test_install_selects_and_validates_latest_successful_build(self) -> None:
        self.assertIn("Usage: ./scripts/install-device.sh", self.install_source)
        self.assertIn("DirectDeviceUpdate-latest.txt", self.install_source)
        self.assertIn(
            'IFS= read -r APP < "$LATEST_ARTIFACT_FILE"', self.install_source
        )
        marker_read = self.install_source.index(
            'IFS= read -r APP < "$LATEST_ARTIFACT_FILE"'
        )
        bundle_check = self.install_source.index('APP_IDENTIFIER="$(', marker_read)
        profile_check = self.install_source.index(
            'cmp -s "$PROFILE" "$APP/embedded.mobileprovision"', bundle_check
        )
        signature_check = self.install_source.index(
            'codesign --verify --deep --strict --verbose=2 "$APP"', profile_check
        )
        install = self.install_source.index(
            "xcrun devicectl device install app", signature_check
        )
        self.assertLess(bundle_check, profile_check)
        self.assertLess(profile_check, signature_check)
        self.assertLess(signature_check, install)

    def test_xpf_contract_is_checked_during_both_phases(self) -> None:
        for source in (self.build_source, self.install_source):
            with self.subTest(script="build" if source is self.build_source else "install"):
                self.assertIn('otool -L "$APP_EXECUTABLE"', source)
                self.assertIn("@loader_path/libxpf.dylib", source)
                self.assertIn('require_architectures "$XPF_DYLIB"', source)

    def test_install_is_graceful_direct_and_does_not_launch_or_uninstall(self) -> None:
        self.assertIn("828515D1-88C1-5CEB-A16F-5AD0AE3E3641", self.install_source)
        self.assertIn("iPinky Max", self.install_source)
        self.assertIn("available (paired)", self.install_source)
        self.assertIn("device process terminate", self.install_source)
        self.assertNotIn("--kill", self.install_source)
        self.assertNotIn("device process launch", self.install_source)
        self.assertNotIn("device uninstall", self.install_source)
        self.assertIn("device info apps", self.install_source)
        self.assertIn('grep -F "$BUNDLE_ID" "$REGISTRATION_LOG"', self.install_source)


if __name__ == "__main__":
    unittest.main()
