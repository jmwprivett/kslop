import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class ControlCenterExactRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.probe = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.m").read_text()
        start = cls.probe.index("CNDCCThemingCopyResolvedLiveTemplates(void)")
        end = cls.probe.index("uint64_t CNDCCThemingResolveLiveTemplate", start)
        cls.resolver = cls.probe[start:end]

    def test_production_resolver_uses_exact_lifecycle_root(self) -> None:
        for member in (
            "_mainDisplayControlCenterController",
            "_viewController",
            "_moduleInstanceManager",
            "_enabledModuleInstanceByUniqueIdentifer",
            "_pagingViewController",
            "__rootFolderController",
            "childViewControllers",
        ):
            self.assertIn(member, self.resolver)
        self.assertIn('metadata, @"moduleIdentifier", @"_moduleIdentifier"', self.resolver)
        self.assertIn('container, @"contentModule", @"_contentModule"', self.resolver)

    def test_production_resolver_does_not_use_recursive_inventory(self) -> None:
        self.assertNotIn("CNDCCThemingCopyPhysicalInventory(", self.resolver)
        self.assertNotIn("CNDCCCopyViewsMatchingClassNames(", self.resolver)
        self.assertIn('@"recursiveViewWalkUsed": @NO', self.probe)

    def test_traced_named_control_routes_are_wired(self) -> None:
        for member in (
            "wifiModuleViewController",
            "expandedWiFiButtonViewController",
            "bluetoothModuleViewController",
            "expandedBluetoothButtonViewController",
            "_sliderView",
            "_backgroundViewController",
            "_primarySlider",
            "_activityPickerViewController",
            "_allActivitiesByIdentifier",
            "activityViews",
            "_contentViewController",
            "sessionsView",
            "nowPlayingView",
            "transportControlsView",
            "leftButton",
            "centerButton",
            "rightButton",
            "upperRouteButton",
            "lowerRouteButton",
            '@"MediaControls.MediaControlsModuleRouteButton"',
            '@"imageView", @"UIImageView"',
            '@"mediaAirPlay", @"imageView"',
        ):
            self.assertIn(member, self.resolver)

    def test_only_media_uses_a_bounded_direct_child_bridge(self) -> None:
        self.assertEqual(self.resolver.count("CNDCCExactDirectSubviews("), 1)
        self.assertIn("Media sessionViews on iOS 26", self.probe)
        self.assertIn('@"MediaControls.NowPlayingTransportControlsView"', self.resolver)


if __name__ == "__main__":
    unittest.main()
