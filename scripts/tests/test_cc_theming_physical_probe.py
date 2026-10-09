"""Production contracts for the read-only CC Theming physical canary."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class CCThemingPhysicalProbeTests(unittest.TestCase):
    def read(self, relative_path: str) -> str:
        return (ROOT / relative_path).read_text(encoding="utf-8")

    def test_package_and_queue_settings_are_wired_without_renumbering(self) -> None:
        catalog = self.read("Cyanide/installer/PackageCatalog.m")
        settings = self.read("Cyanide/SettingsViewController.m")
        self.assertNotIn("kSecCCTheming", catalog)
        self.assertRegex(
            settings,
            r"SectionFontChanger,\s+SectionCCTheming,\s+SectionCount,",
        )
        package = catalog.split(
            'initWithIdentifier:@"com.darksword.cc-theming"', 1
        )[1].split("ccTheming.unstableWarning", 1)[0]
        self.assertIn('name:@"CC Theming"', package)
        self.assertIn("PackageInstallKindControlCenterTheming", package)
        self.assertNotIn("PackageInstallKindDirectTool", package)
        self.assertNotIn("ccTheming.settingsSection", catalog)

    def test_production_controls_only_offer_queued_apply_and_restore(self) -> None:
        settings = self.read("Cyanide/SettingsViewController.m")
        rows = settings.split("- (NSArray<NSDictionary *> *)ccThemingRows", 1)[1]
        rows = rows.split("#if 0", 1)[0]
        self.assertEqual(rows.count('@"kind": @"button"'), 2)
        self.assertIn('action": @"cc-theming-queue-apply"', rows)
        self.assertIn('action": @"cc-theming-queue-restore"', rows)
        for retired in ("discover", "trace", "canary", "share", "countdown"):
            self.assertNotIn(retired, rows.lower())
        action = settings.split(
            "if (indexPath.section == SectionCCTheming)", 1
        )[1].split("#if 0", 1)[0]
        self.assertIn("queueIntent:intent forPackage:package", action)
        self.assertIn("canQueueIntent:intent forPackage:package", action)
        self.assertNotIn("5 * NSEC_PER_SEC", action)
        self.assertNotIn("settings_run_cc_theming_physical_inventory", action)

    def test_probe_and_canary_implementations_are_excluded_from_production(self) -> None:
        settings = self.read("Cyanide/SettingsViewController.m")
        project = self.read("Cyanide.xcodeproj/project.pbxproj")
        self.assertNotIn('#import "tweaks/CNDCCThemingProbe.h"', settings)
        self.assertNotIn('#import "tweaks/CNDCCThemingCanary.h"', settings)
        self.assertIn("tweaks/CNDCCThemingProbe.m", project)
        self.assertIn("tweaks/CNDCCThemingCanary.m", project)

    def test_dedicated_media_connectivity_trace_is_read_only_and_bounded(self) -> None:
        header = self.read("Cyanide/tweaks/CNDCCThemingProbe.h")
        probe = self.read("Cyanide/tweaks/CNDCCThemingProbe.m")
        settings = self.read("Cyanide/SettingsViewController.m")
        self.assertIn("CNDCCThemingCopyMediaConnectivityTrace", header)
        trace = probe.split(
            "CNDCCThemingCopyMediaConnectivityTrace(void)", 1
        )[1].split(
            "CNDCCThemingCopyPhysicalInventory(void)", 1
        )[0]
        self.assertIn("CNDCCTraceObjectCapPerController = 512", probe)
        for contract in (
            '@"physical-read-only-expanded-control-center-trace"',
            '@"transportControlsView"',
            '@"playPauseButton"',
            '@"previousButton"',
            '@"nextButton"',
            '@"packageView"',
            '@"setPackage:"',
            '@"setGlyphPackageDescription:"',
            '@"mediaButtonCandidateCount"',
            '@"connectivityButtonCandidateCount"',
            '@"hostedIconCandidateCount"',
            '@"sliderCandidateCount"',
            '@"focusCandidateCount"',
            '@"_controlIconView"',
            '@"brightnessSlider"',
            '@"volumeSlider"',
            '@"focusViewController"',
            '@"geometry"',
            '@"getterEdges"',
        ):
            self.assertIn(contract, trace)
        self.assertIn('CNDCCGetter(controller, "presentedViewController")', trace)
        self.assertIn('@"viewIfLoaded"', trace)
        self.assertIn("seenTraceObjects", trace)
        self.assertNotIn('return @"controlCenter"', trace)
        self.assertNotIn('CNDCCGetter(childController, "view")', trace)
        self.assertIn('@"controlActions": @0', trace)
        self.assertIn('@"presentationWrites": @0', trace)
        self.assertIn('@"radioWrites": @0', trace)

        rows = settings.split(
            "- (NSArray<NSDictionary *> *)ccThemingRows", 1
        )[1].split("- (NSArray<NSDictionary *> *)liveWPRows", 1)[0]
        self.assertIn('action": @"cc-theming-trace-media"', rows)
        self.assertIn('action": @"cc-theming-share-media-trace"', rows)
        self.assertIn("physical-media-connectivity-trace.json", settings)
        actions = settings.split(
            "if (indexPath.section == SectionCCTheming)", 1
        )[1].split("if (indexPath.section == SectionFontChanger)", 1)[0]
        self.assertIn("settings_run_cc_theming_media_connectivity_trace", actions)

    def test_media_trace_uses_one_pid_bound_session(self) -> None:
        settings = self.read("Cyanide/SettingsViewController.m")
        runner = settings.split(
            "static void settings_run_cc_theming_media_connectivity_trace", 1
        )[1].split(
            "static void settings_run_cc_theming_physical_inventory", 1
        )[0]
        self.assertEqual(
            runner.count("settings_ensure_springboard_remote_call_locked()"), 1
        )
        self.assertIn("CNDCCThemingCopyMediaConnectivityTrace()", runner)
        self.assertIn("r_autorelease_pool_push", runner)
        self.assertIn("r_autorelease_pool_pop", runner)
        self.assertIn("if (!hadSpringBoardSession && transportHealthy", runner)
        self.assertIn(
            "settings_destroy_springboard_remote_call_locked_internal_ex",
            runner,
        )

    def test_probe_is_bounded_and_inventories_bluetooth_and_cellular(self) -> None:
        probe = self.read("Cyanide/tweaks/CNDCCThemingProbe.m")
        for contract in (
            "CNDCCWindowCap = 32",
            "CNDCCControllerCap = 256",
            "CNDCCViewCapPerController = 128",
            'r_class("CCUIControlTemplateView")',
            '@"bluetoothModuleViewController"',
            '@"cellularDataButtonViewController"',
            '@"wifiModuleViewController"',
            '@"airplaneButtonViewController"',
            '@"hotspotButtonViewController"',
            '@"airDropModuleViewController"',
        ):
            self.assertIn(contract, probe)
        for kind in (
            '@"flashlight"',
            '@"lowPower"',
            '@"screenRecording"',
            '@"calculator"',
            '@"camera"',
            '@"display"',
            '@"sound"',
            '@"guidedAccess"',
            '@"accessibilityShortcuts"',
            '@"soundDetection"',
            '@"textSize"',
            '@"screenMirroring"',
            '@"tvRemote"',
            '@"nfc"',
            '@"performanceTrace"',
        ):
            self.assertIn(kind, probe)
        self.assertIn('@"missingPulsarModuleKinds"', probe)
        self.assertIn('@"connectivityContracts"', probe)
        self.assertIn('@"expandedWiFiButtonViewController"', probe)
        self.assertIn('@"expandedBluetoothButtonViewController"', probe)

    def test_probe_enumerates_and_classifies_every_nested_template(self) -> None:
        probe = self.read("Cyanide/tweaks/CNDCCThemingProbe.m")
        self.assertIn("CNDCCCopyTemplateViews", probe)
        self.assertNotIn("CNDCCFindTemplateView", probe)
        self.assertIn('@"templateEnumerationMode"] = @"all-descendants"', probe)
        self.assertIn('@"truncatedTemplateTraversalCount"', probe)
        self.assertIn('@"controlSurfacesByKind"', probe)
        self.assertIn('"accessibilityIdentifier"', probe)
        self.assertIn('"accessibilityLabel"', probe)
        self.assertIn(
            "CNDCCControlKind(controllerClass, identifier, label, source,",
            probe,
        )
        self.assertIn('@[@"barcode", @"qrCode"]', probe)

    def test_production_resolver_uses_traced_connectivity_targets(self) -> None:
        probe = self.read("Cyanide/tweaks/CNDCCThemingProbe.m")
        for contract in (
            '@"_enabledModuleInstanceByUniqueIdentifer"',
            '@"__rootFolderController"',
            '@"contentModule"',
            '@"compactConnectivity"',
            '@"expandedConnectivity"',
            '@"connectivity."',
            'CNDCCExactGlyphTargetForController(child)',
            '@"airplaneButtonViewController"',
            '@"expandedAirplaneButtonViewController"',
            '@"wifiModuleViewController"',
            '@"expandedWiFiButtonViewController"',
            '@"bluetoothModuleViewController"',
            '@"expandedBluetoothButtonViewController"',
            '@"airDropModuleViewController"',
            '@"hotspotButtonViewController"',
            '@"satelliteModuleViewController"',
            '@"singleGlyph"',
        ):
            self.assertIn(contract, probe)
        # Media image/package flattening was intentionally removed after it
        # displaced the stock transport layout. Media remains a package-load
        # or descriptor-cache concern, not an address-seeded image target.
        self.assertNotIn('@"mediaImageView"', probe)
        self.assertNotIn('@"mediaStockPackageView"', probe)
        self.assertIn('@"CHUISControlIconView"', probe)
        self.assertIn('@"suppressedView"', probe)
        resolver = probe.split(
            "CNDCCThemingCopyResolvedLiveTemplates(void)", 1
        )[1].split("CNDCCThemingResolveLiveTemplate(", 1)[0]
        self.assertNotIn("CNDCCCopyViewsMatchingClassNames(", resolver)
        self.assertNotIn("CNDCCThemingCopyPhysicalInventory(", resolver)
        self.assertIn('@"recursiveViewWalkUsed": @NO', probe)

    def test_probe_maps_module_identity_and_string_glyph_state(self) -> None:
        probe = self.read("Cyanide/tweaks/CNDCCThemingProbe.m")
        for selector in (
            '"moduleIdentifier"',
            '"bundleIdentifier"',
            '"containerBundleIdentifier"',
            '"applicationBundleIdentifier"',
            '"uniqueIdentifier"',
            '"identifier"',
        ):
            self.assertIn(selector, probe)
        self.assertIn('@[@"rpcontrolcenter", @"screenRecording"]', probe)
        self.assertIn('@[@"screencapture", @"screenRecording"]', probe)
        self.assertIn('@[@"orientation", @"orientationLock"]', probe)
        self.assertIn('@[@"timer", @"timer"]', probe)
        self.assertIn('@"glyphStateString"', probe)
        priority = probe.split("NSArray<NSString *> *priorityKinds", 1)[1]
        priority = priority.split("NSMutableArray<NSString *> *missing", 1)[0]
        self.assertIn('@"timer"', priority)

    def test_probe_reports_abi_contracts_without_invoking_mutators(self) -> None:
        probe = self.read("Cyanide/tweaks/CNDCCThemingProbe.m")
        for selector in (
            "glyphImage",
            "setGlyphImage:",
            "selectedGlyphImage",
            "setSelectedGlyphImage:",
            "glyphPackageDescription",
            "setGlyphPackageDescription:",
            "glyphState",
            "setGlyphState:",
        ):
            self.assertIn(f'"{selector}"', probe)
        mutator_dispatch = re.compile(
            r"r_msg2(?:_main|_main_raw|_raw)?\s*\([^;]*"
            r'"(?:set|sendAction|buttonTapped|toggle|activate)',
            re.DOTALL,
        )
        self.assertIsNone(mutator_dispatch.search(probe))
        self.assertNotIn("object_setIvar", probe)
        self.assertIn('@"controlActions": @0', probe)
        self.assertIn('@"presentationWrites": @0', probe)
        self.assertIn('@"radioWrites": @0', probe)
        self.assertIn('@"fileWrites": @0', probe)
        self.assertIn("targetPIDAtEntry = remote_call_current_pid()", probe)
        self.assertIn('@"pidStable"', probe)
        self.assertIn("pidStable &&", probe)

    def test_settings_uses_one_pid_bound_session_and_closes_owned_session(self) -> None:
        settings = self.read("Cyanide/SettingsViewController.m")
        action = settings.split(
            "static void settings_run_cc_theming_physical_inventory", 1
        )[1].split(
            "static void settings_run_cc_theming_file_resources", 1
        )[0]
        self.assertEqual(
            action.count("settings_ensure_springboard_remote_call_locked()"), 1
        )
        self.assertIn("remote_call_lab_backend_opted_in()", action)
        self.assertIn("cnd_lab_vphone_guest()", action)
        self.assertLess(
            action.index("remote_call_lab_backend_opted_in()"),
            action.index("settings_ensure_kexploit()"),
        )
        self.assertIn("CNDCCThemingCopyPhysicalInventory()", action)
        self.assertIn("r_autorelease_pool_push", action)
        self.assertIn("r_autorelease_pool_pop", action)
        self.assertIn("if (!hadSpringBoardSession && transportHealthy", action)
        self.assertIn(
            "settings_destroy_springboard_remote_call_locked_internal_ex", action
        )


if __name__ == "__main__":
    unittest.main()
