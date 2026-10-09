"""Production contract checks for the live Lockscreen Glyphs feature."""

from pathlib import Path
import base64
import hashlib
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class LockscreenGlyphsContractTests(unittest.TestCase):
    def read(self, relative_path: str) -> str:
        return (ROOT / relative_path).read_text(encoding="utf-8")

    def test_catalog_describes_the_live_temporary_feature(self) -> None:
        catalog = self.read("Cyanide/installer/PackageCatalog.m")
        package = catalog.split(
            'initWithIdentifier:@"com.darksword.lockscreen-glyphs"', 1
        )[1].split("lockscreenGlyphs.unstableWarning", 1)[0]
        self.assertIn('name:@"Lockscreen Glyphs"', package)
        self.assertIn('shortDescription:@"Pulsar camera and flashlight artwork"', package)
        self.assertIn("separate off and on states", package)
        self.assertIn("Restore rebuilds both native stock glyphs", package)
        self.assertIn("respring or reboot", package)
        self.assertIn("No system asset file is overwritten", package)
        self.assertNotIn("Assets.car", package)

    def test_detail_menu_exposes_only_apply_and_restore(self) -> None:
        detail = self.read("Cyanide/installer/PackageDetailViewController.m")
        menu_method = detail.split("- (UIMenu *)manualActionMenu", 1)[1]
        menu = menu_method.split(
            "if (self.package.kind == PackageInstallKindLockscreenGlyphs)", 1
        )[1].split(
            "if (self.package.kind == PackageInstallKindNanoRegistry)", 1
        )[0]
        self.assertIn('actionWithTitle:@"Apply"', menu)
        self.assertIn('actionWithTitle:@"Restore"', menu)
        self.assertIn("runLockscreenGlyphRuntimeOperation:YES", menu)
        self.assertIn("runLockscreenGlyphRuntimeOperation:NO", menu)
        self.assertIn("children:@[apply, restore]", menu)
        for retired in (
            "Compatibility Details",
            "Export Device Catalogs",
            "Inspect Live Buttons",
            "Apply Live",
        ):
            self.assertNotIn(retired, menu)

    def test_runtime_operation_opens_log_then_dispatches_apply_or_restore(self) -> None:
        detail = self.read("Cyanide/installer/PackageDetailViewController.m")
        operation = detail.split(
            "- (void)runLockscreenGlyphRuntimeOperation:(BOOL)apply", 1
        )[1].split("- (UIMenu *)manualActionMenu", 1)[0]
        self.assertIn("settings_apply_lockscreen_pulsar_runtime(apply, &error)", operation)
        self.assertIn("presentActivityLogWithCompletion:startOperation", operation)
        self.assertLess(
            operation.index("dispatch_block_t startOperation"),
            operation.index("presentActivityLogWithCompletion:startOperation"),
        )
        self.assertIn("until a respring or reboot", operation)
        self.assertIn("native camera and flashlight glyphs were rebuilt", operation)

    def test_lockscreen_glyphs_never_enter_the_queue(self) -> None:
        queue = self.read("Cyanide/installer/PackageQueue.m")
        self.assertIn(
            "package.kind == PackageInstallKindLockscreenGlyphs) return NO;",
            queue,
        )
        self.assertIn("Use the Lockscreen Glyphs Apply or Restore control.", queue)

        catalog = self.read("Cyanide/installer/CNDQueuedActionCatalog.m")
        supported = catalog.split("BOOL CNDQueuedPackageKindIsSupported", 1)[1]
        unsupported = supported.split("case PackageInstallKindLockscreenGlyphs:", 1)[1]
        self.assertLess(unsupported.index("return NO;"), unsupported.index("return YES;"))

        package = self.read("Cyanide/installer/Package.m")
        execution = package.split("- (BOOL)applyCommittedState:(BOOL)installed", 1)[1]
        lockscreen = execution.split("case PackageInstallKindLockscreenGlyphs:", 1)[1]
        self.assertIn("case PackageInstallKindDirectTool:", lockscreen)
        self.assertIn("return NO;", lockscreen)

    def test_runtime_discovery_is_bounded_and_action_specific(self) -> None:
        runtime = self.read("Cyanide/tweaks/CNDLockscreenQuickActionProbe.m")
        for name, cap in (("Window", 32), ("Controller", 128), ("Button", 4)):
            self.assertIn(f"CNDQuickAction{name}Cap = {cap}", runtime)
        self.assertIn('r_class("CSFlashlightQuickAction")', runtime)
        self.assertIn('r_class("CSCameraSystemQuickAction")', runtime)
        self.assertIn('CNDQuickActionGetter(controller,\n                                                  "quickActionsViewIfLoaded")', runtime)
        self.assertIn('CNDQuickActionGetter(view, "buttons")', runtime)
        self.assertIn('r_ivar_value(button, "_glyphView")', runtime)
        self.assertNotIn('"subviews"', runtime)
        self.assertNotIn("CNDLockscreenQuickActionReadOnlySnapshot", runtime)

    def test_apply_uses_direct_strong_ivars_and_30_point_artwork(self) -> None:
        runtime = self.read("Cyanide/tweaks/CNDLockscreenQuickActionProbe.m")
        apply = runtime.split("CNDLockscreenQuickActionApplyArtwork(", 1)[1]
        self.assertIn("double scale = 3.0", runtime)
        self.assertIn('result[@"artworkPointSize"] = @30;', apply)
        self.assertIn('"object_setIvarWithStrongDefault"', runtime)
        self.assertIn('CNDQuickActionInstanceIvar(glyph, "_image")', runtime)
        self.assertIn('glyph, "_updateImageAppearance"', runtime)
        self.assertIn('targets.cameraButton, "setGlyphView:"', runtime)
        self.assertIn("r_settle_us(0)", apply)
        self.assertIn('@"rolledBack"', runtime)

    def test_restore_uses_coversheet_native_factories_and_rolls_back(self) -> None:
        runtime = self.read("Cyanide/tweaks/CNDLockscreenQuickActionProbe.m")
        restore = runtime.split("CNDQuickActionCreateNativeGlyph", 1)[1]
        self.assertIn('"_createButtonGlyphForAction:"', restore)
        self.assertIn('r_class("CSQuickActionImageGlyphView")', restore)
        self.assertIn('r_class("CSQuickActionControlGlyphView")', restore)
        self.assertGreaterEqual(restore.count('"setGlyphView:"'), 4)
        self.assertIn("oldFlashlightGlyph", restore)
        self.assertIn("oldCameraGlyph", restore)
        self.assertIn('@"rolledBack"', restore)

    def test_settings_dispatches_apply_and_restore_over_one_runtime_session(self) -> None:
        settings = self.read("Cyanide/SettingsViewController.m")
        runtime = settings.split(
            "BOOL settings_apply_lockscreen_pulsar_runtime", 1
        )[1].split("\n#if 0", 1)[0]
        self.assertIn("settings_ensure_springboard_remote_call_locked", runtime)
        self.assertIn("CNDLockscreenQuickActionApplyArtwork", runtime)
        self.assertIn("CNDLockscreenQuickActionRestoreStock", runtime)
        self.assertIn("CNDPulsarCameraPNGData()", runtime)
        self.assertIn("CNDPulsarFlashlightOffPNGData()", runtime)
        self.assertIn("CNDPulsarFlashlightOnPNGData()", runtime)
        self.assertIn("r_autorelease_pool_push", runtime)
        self.assertIn("r_autorelease_pool_pop", runtime)

    def test_embedded_artwork_is_the_original_pulsar_payload(self) -> None:
        artwork = self.read("Cyanide/tweaks/CNDPulsarArtwork.m")
        expected = {
            "CameraPNGData": (
                3317,
                "2ebed053f84dd51d29217f290f7a343fab5b0d201cc0e68aab5edc74df390fb3",
            ),
            "FlashlightOffPNGData": (
                3775,
                "793c995cb2114c1343dedec4aff5848b25d5a9aa467a9d959b03e940c4727dab",
            ),
            "FlashlightOnPNGData": (
                6242,
                "e7c4891d5d095efe2eb358f112edf3aacbf633c437cb551a46da110c59184b76",
            ),
        }
        for function, (length, digest) in expected.items():
            block = artwork.split(f"NSData *CNDPulsar{function}(void)", 1)[1].split(
                "\n}", 1
            )[0]
            encoded = "".join(re.findall(r'@"([A-Za-z0-9+/=]+)"', block))
            payload = base64.b64decode(encoded, validate=True)
            self.assertEqual(len(payload), length)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)

    def test_experimental_car_and_probe_exports_are_not_shipped(self) -> None:
        self.assertFalse((ROOT / "Cyanide/tweaks/CNDLockscreenGlyphs.h").exists())
        self.assertFalse((ROOT / "Cyanide/tweaks/CNDLockscreenGlyphs.m").exists())
        self.assertFalse((ROOT / "Cyanide/Resources/LockscreenGlyphs").exists())
        header = self.read("Cyanide/SettingsViewController.h")
        self.assertNotIn("settings_export_lockscreen_quick_action_runtime_report", header)
        self.assertNotIn("settings_apply_lockscreen_glyphs", header)


if __name__ == "__main__":
    unittest.main()
