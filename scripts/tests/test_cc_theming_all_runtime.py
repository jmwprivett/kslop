"""Contracts for Pulsar artwork and the file-only production installer."""

from pathlib import Path
import re
import struct
import unittest
import zlib


ROOT = Path(__file__).resolve().parents[2]


class CCThemingAllRuntimeTests(unittest.TestCase):
    def read(self, relative_path: str) -> str:
        return (ROOT / relative_path).read_text(encoding="utf-8")

    def test_artwork_table_has_all_supported_mappings_and_provenance(self) -> None:
        generator = self.read("scripts/generate_pulsar_controlcenter_artwork.py")
        table = generator.split("ARTWORK:", 1)[1].split(
            "\n\n# The iOS 26 trace", 1
        )[0]
        kinds = re.findall(r'^    "([A-Za-z0-9]+)":', table, re.MULTILINE)
        self.assertEqual(len(kinds), 38)
        for kind in (
            "wifi", "bluetooth", "airplaneMode", "cellular", "airDrop",
            "hotspot", "flashlight", "lowPower", "screenRecording",
            "orientationLock", "calculator", "camera", "timer",
            "mediaPlayPause", "mediaPrevious", "mediaNext",
            "mediaAirPlay",
        ):
            self.assertIn(kind, kinds)
        self.assertNotIn("vpn", kinds)
        self.assertNotIn("satellite", kinds)
        supplements = generator.split("SUPPLEMENTAL_ARTWORK =", 1)[1].split(
            "\nSUPPLEMENTAL_SYMBOLS", 1
        )[0]
        for kind in (
            "vpn", "satelliteUnavailable", "satelliteAvailable",
            "satelliteConnected", "focusSleep", "focusPersonal",
            "focusWork", "focusReduceInterruptions", "focusCustom",
        ):
            self.assertIn(f'"{kind}"', supplements)
        self.assertIn("Timer compatibility fallback", table)
        self.assertIn('package.get("id") != "com.dobabaophuc.pulsarcc2.0"', generator)
        self.assertIn('package.get("upstream_commit") != "bd13799"', generator)
        self.assertIn('RENDERED / "Media-Play.png"', generator)
        self.assertIn('RENDERED / "Media-Pause.png"', generator)
        self.assertIn('RENDERED / "Media-Previous.png"', generator)
        self.assertIn('RENDERED / "Media-Next.png"', generator)
        for adapter in (
            "catalogImage", "generatedSymbolImage", "caPackage",
            "hostedControlIcon",
        ):
            self.assertIn(f'"{adapter}"', generator)

        packages = generator.split("PACKAGE_ARTWORK:", 1)[1].split(
            "\n\nINDEX_PLIST", 1
        )[0]
        for kind in (
            "wifi", "bluetooth", "lowPower", "screenRecording",
            "orientationLock", "mute", "screenMirroring",
            "musicRecognition", "appearance", "focus", "hearing",
            "display", "sound",
            "mediaPlayPause", "mediaPrevious", "mediaNext",
        ):
            self.assertIn(f'"{kind}"', packages)
        self.assertIn("PACKAGE_ARTWORK.setdefault", generator)
        self.assertIn('consumer_positioned_root=kind == "timer"', generator)
        self.assertIn("generate_motion_bundle()", generator)

        generated = self.read("Cyanide/tweaks/CNDPulsarControlCenterArtwork.inc")
        self.assertIn("Official Pulsar v2.0 source commit bd13799", generated)
        self.assertIn("CNDPulsarControlCenterArtwork(void)", generated)
        self.assertIn('@"packageName": @"Mute"', generated)
        self.assertIn('@"packageName": @"OrientationLock"', generated)
        self.assertIn('@"packageName": @"StaticCalculator"', generated)
        self.assertIn('@"packageName": @"StaticCamera"', generated)
        self.assertIn('@"packageName": @"StaticQrCode"', generated)
        self.assertIn('@"packageName": @"PlayPauseStop"', generated)
        self.assertIn('@"originalRendering": @YES', generated)
        self.assertEqual(generated.count('@"packageName":'), 49)
        self.assertEqual(generated.count('@"deliveryAdapter":'), 49)
        self.assertIn('@"deliveryAdapter": @"catalogImage"', generated)
        self.assertIn('@"deliveryAdapter": @"generatedSymbolImage"', generated)
        self.assertIn('@"deliveryAdapter": @"caPackage"', generated)
        self.assertIn('@"deliveryAdapter": @"hostedControlIcon"', generated)
        self.assertEqual(generated.count('@"singleGlyphPackageName":'), 6)
        self.assertIn(
            '@"singleGlyphPackageName": @"StaticWifi"', generated
        )
        self.assertIn(
            '@"singleGlyphPackageName": @"StaticBluetooth"', generated
        )
        self.assertIn('@"mediaAirPlay": @{', generated)
        self.assertIn('@"symbolNames": @[@"airplay.audio"]', generated)
        self.assertIn('@"preserveImageViewVisibility": @YES', generated)
        self.assertIn(
            '@"selectedSymbolNames": @[@"flashlight.on.fill"]', generated
        )

    def test_generated_motion_bundle_is_self_contained(self) -> None:
        bundle = ROOT / "Cyanide/PulsarControlCenter.bundle"
        for package in (
            "Mute", "OrientationLock", "WiFi", "Bluetooth", "LowPower",
            "Appearance", "Focus", "ScreenRecording", "ScreenMirroring",
            "MusicRecognition", "Hearing", "Brightness", "Volume",
            "PlayPauseStop", "ForwardBackward", "StaticCalculator",
            "StaticCamera", "StaticQrCode", "StaticCellular",
            "StaticHotspot", "StaticWifi", "StaticBluetooth",
            "StaticVpn", "StaticSatelliteUnavailable",
            "StaticSatelliteAvailable", "StaticSatelliteConnected",
            "StaticFocusSleep", "StaticFocusPersonal", "StaticFocusWork",
            "StaticFocusReduceInterruptions", "StaticFocusCustom",
        ):
            package_dir = bundle / f"{package}.ca"
            self.assertTrue((package_dir / "index.xml").is_file())
            caml = (package_dir / "main.caml").read_text(encoding="utf-8")
            self.assertNotIn("/var/mobile/Documents/PhucDo/PhucDoUI/", caml)
        self.assertIn(
            '<string>main.caml</string>',
            (bundle / "Mute.ca/index.xml").read_text(encoding="utf-8"),
        )

    def test_screen_mirroring_uses_authored_colour_cycle(self) -> None:
        package = ROOT / "Cyanide/PulsarControlCenter.bundle/ScreenMirroring.ca"
        caml = (package / "main.caml").read_text(encoding="utf-8")
        self.assertIn('src="mirror_off1.png"', caml)
        self.assertIn('src="mirror_off2.png"', caml)
        self.assertIn('src="mirror_on.png"', caml)
        self.assertNotIn('src="mirror_off.png"', caml)
        self.assertEqual(caml.count('type="CAKeyframeAnimation"'), 2)
        self.assertEqual(caml.count('repeatCount="Inf" duration="2"'), 2)

        raw = (
            ROOT
            / "build/pulsar-controlcenter-v2-source/extracted-original"
            / "com.dobabaophuc.pulsarcc2.0/Overwrite/var/mobile/Documents"
            / "PhucDo/PhucDoUI"
        )
        for name in ("mirror_off1.png", "mirror_off2.png", "mirror_on.png"):
            self.assertEqual((package / name).read_bytes(), (raw / name).read_bytes())

    def test_media_caml_renderer_preserves_all_four_pulsar_states(self) -> None:
        renderer = self.read("scripts/render_pulsar_media_artwork.m")
        for name in (
            "Media-Play.png", "Media-Pause.png",
            "Media-Previous.png", "Media-Next.png",
        ):
            self.assertIn(name, renderer)
        self.assertIn("CNDSetPlayPauseState", renderer)
        self.assertIn("flipHorizontally", renderer)
        self.assertIn("CAPackage", renderer)

    def test_generated_static_packages_use_centered_white_alpha_artwork(self) -> None:
        package = ROOT / "Cyanide/PulsarControlCenter.bundle/StaticCamera.ca"
        caml = (package / "main.caml").read_text(encoding="utf-8")
        self.assertIn(
            '<CALayer bounds="0 0 40 40" position="-0.5 0">', caml
        )
        self.assertEqual(caml.count('position="0 0"'), 2)
        self.assertNotIn('position="20 20"', caml)
        self.assertEqual(caml.count('contentsGravity="resizeAspect"'), 2)

        data = (package / "standard.png").read_bytes()
        offset = 8
        dimensions = None
        compressed = bytearray()
        while offset < len(data):
            length = struct.unpack(">I", data[offset:offset + 4])[0]
            chunk_type = data[offset + 4:offset + 8]
            payload = data[offset + 8:offset + 8 + length]
            offset += length + 12
            if chunk_type == b"IHDR":
                dimensions = struct.unpack(">II", payload[:8])
            elif chunk_type == b"IDAT":
                compressed.extend(payload)
            elif chunk_type == b"IEND":
                break
        self.assertIsNotNone(dimensions)
        width, height = dimensions
        raw = zlib.decompress(bytes(compressed))
        visible = 0
        for y in range(height):
            row = raw[y * (1 + width * 4):(y + 1) * (1 + width * 4)]
            self.assertEqual(row[0], 0)
            for x in range(width):
                red, green, blue, alpha = row[1 + x * 4:1 + x * 4 + 4]
                if alpha:
                    visible += 1
                    self.assertEqual((red, green, blue), (255, 255, 255))
        self.assertGreater(visible, 0)

    def test_research_resolver_keeps_the_traced_named_routes(self) -> None:
        probe = self.read("Cyanide/tweaks/CNDCCThemingProbe.m")
        self.assertIn('@"hostedControlIcon"', probe)
        self.assertIn('@"vpn": @[@"vpnModuleViewController"]', probe)
        self.assertIn('@"satellite": @[@"satelliteModuleViewController"]', probe)
        self.assertIn("CNDCCSatelliteArtworkKind", probe)
        for kind in (
            "satelliteUnavailable", "satelliteAvailable", "satelliteConnected",
            "mediaPlayPause", "mediaPrevious", "mediaNext",
        ):
            self.assertIn(f'@"{kind}"', probe)
        self.assertIn('@"_mainDisplayControlCenterController"', probe)
        self.assertIn('@"_enabledModuleInstanceByUniqueIdentifer"', probe)
        self.assertIn('@"__rootFolderController"', probe)
        self.assertIn('@"exactLifecycleRoute"', probe)
        self.assertIn('@"named-ownership-no-recursive-view-walk"', probe)
        self.assertIn('@"recursiveViewWalkUsed": @NO', probe)
        self.assertIn('@"nowPlayingView"', probe)
        self.assertIn('@"transportControlsView"', probe)
        self.assertIn('@"leftButton"', probe)
        self.assertIn('@"centerButton"', probe)
        self.assertIn('@"rightButton"', probe)
        self.assertIn('@"MediaControls.NowPlayingTransportControlsView"', probe)
        self.assertIn('@"mruPackageView"', probe)
        self.assertNotIn('@"mediaStockPackageView"', probe)
        self.assertNotIn('@"mediaImageView"', probe)

    def test_settings_exposes_only_queued_apply_restore_in_production(self) -> None:
        settings = self.read("Cyanide/SettingsViewController.m")
        rows = settings.split("- (NSArray<NSDictionary *> *)ccThemingRows", 1)[1]
        rows = rows.split("#if 0", 1)[0]
        self.assertIn('action": @"cc-theming-queue-apply"', rows)
        self.assertIn('action": @"cc-theming-queue-restore"', rows)
        self.assertEqual(rows.count('@"kind": @"button"'), 2)

        runner = settings.split(
            "BOOL settings_apply_cc_theming_now(BOOL apply)", 1
        )[1].split(
            "\n#if 0", 1
        )[0]
        self.assertIn("remote_call_lab_backend_opted_in()", runner)
        self.assertIn("cnd_lab_vphone_guest()", runner)
        self.assertIn("CNDCCThemingFileBackingApply()", runner)
        self.assertIn("CNDCCThemingFileBackingRestore()", runner)
        for provider_apply in (
            "CNDCCThemingApplyPulsarArtwork",
            "CNDCCThemingPersistentInstallVerifiedRoutesInCurrentSession",
            "settings_ensure_springboard_remote_call_locked()",
        ):
            self.assertNotIn(provider_apply, runner)
        self.assertNotIn("settings_post_actions_complete_async", runner)
        self.assertIn("return success;", runner)

        actions = settings.split(
            "if (indexPath.section == SectionCCTheming)", 1
        )[1].split("#if 0", 1)[0]
        self.assertIn("PackageQueueIntentInstall", actions)
        self.assertIn("PackageQueueIntentUninstall", actions)
        self.assertIn("queueIntent:intent forPackage:package", actions)
        self.assertNotIn("dispatch_after", actions)
        self.assertNotIn("presentActivityLogWithCompletion", actions)

        self.assertNotIn("settings_stop_cc_theming_registered", settings)
        self.assertNotIn("CNDCCThemingPersistent", settings)
        self.assertNotIn("CNDCCThemingRuntime.h", settings)
        live_loop_check = settings.split(
            "static BOOL settings_any_registered_live_loop_running", 1
        )[1].split(
            "static NSString *settings_registered_live_loop_status_string", 1
        )[0]
        self.assertIn("entry->requestStop && entry->isRunning", live_loop_check)


if __name__ == "__main__":
    unittest.main()
