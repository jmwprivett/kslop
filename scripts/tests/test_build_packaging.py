"""Structural checks for IPA packaging and sideload signing compatibility."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class BuildPackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build = (ROOT / "scripts/build.sh").read_text()

    def test_embedded_xpf_is_presigned_before_ipa_staging(self) -> None:
        dylib = self.build.index('XPF_DYLIB_PATH="$APP_PATH/libxpf.dylib"')
        sign = self.build.index(
            '/usr/bin/codesign --force --sign - --timestamp=none', dylib
        )
        verify = self.build.index(
            '/usr/bin/codesign --verify --strict "$XPF_DYLIB_PATH"', sign
        )
        stage = self.build.index('STAGE="$(mktemp -d -t cyanide-ipa)"', verify)
        copy = self.build.index('cp -R "$APP_PATH" "$STAGE/Payload/"', stage)
        self.assertLess(dylib, sign)
        self.assertLess(sign, verify)
        self.assertLess(verify, stage)
        self.assertLess(stage, copy)

    def test_xpf_presign_requires_both_device_architectures_and_signature_commands(self) -> None:
        self.assertIn('XPF_ARCHS="$(xcrun lipo -archs "$XPF_DYLIB_PATH")"', self.build)
        self.assertIn('*" arm64 "*', self.build)
        self.assertIn('*" arm64e "*', self.build)
        self.assertIn('for XPF_ARCH in arm64 arm64e', self.build)
        self.assertIn('xcrun otool -arch "$XPF_ARCH" -l', self.build)
        self.assertIn('grep -q "LC_CODE_SIGNATURE"', self.build)

    def test_sideloadly_070_workaround_stores_every_info_plist(self) -> None:
        compressed = self.build.index(
            'zip -qry "$IPA_OUT" Payload -x \'*/Info.plist\''
        )
        discover = self.build.index(
            'find Payload -type f -name Info.plist -print0', compressed
        )
        stored = self.build.index(
            'zip -0 -q "$IPA_OUT" "${INFO_PLIST_ENTRIES[@]}"', discover
        )
        verify = self.build.index(
            'entry.compress_type != zipfile.ZIP_STORED', stored
        )
        self.assertLess(compressed, discover)
        self.assertLess(discover, stored)
        self.assertLess(stored, verify)
        self.assertIn('if [ "${#INFO_PLIST_ENTRIES[@]}" -eq 0 ]', self.build)
        self.assertIn('compressed Info.plist entries remain', self.build)


if __name__ == "__main__":
    unittest.main()
