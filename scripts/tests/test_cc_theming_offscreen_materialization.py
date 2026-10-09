import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class ControlCenterOffscreenMaterializationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.h").read_text()
        cls.probe = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.m").read_text()
        start = cls.probe.index("CNDCCThemingMaterializeExactRouteOwners(void)")
        end = cls.probe.index("CNDCCThemingCopyResolvedLiveTemplates(void)", start)
        cls.materializer = cls.probe[start:end]
        kind_start = cls.probe.index("static NSString *CNDCCExactModuleKind")
        kind_end = cls.probe.index("static NSString *CNDCCExactHostedKind", kind_start)
        cls.exact_module_kind = cls.probe[kind_start:kind_end]

    def test_research_materializer_has_an_explicit_nonpresenting_preparation_phase(self) -> None:
        self.assertIn("CNDCCThemingMaterializeExactRouteOwners", self.header)
        self.assertIn('@"presentationActions": @0', self.materializer)
        self.assertIn('@"controlActions": @0', self.materializer)
        self.assertIn('@"radioWrites": @0', self.materializer)
        self.assertIn('@"recursiveViewWalkUsed": @NO', self.materializer)
        for forbidden in (
            "presentAnimated:",
            "expandModuleWithIdentifier:",
            "willTransitionToExpandedContentMode:",
            "didTransitionToExpandedContentMode:",
            "CNDCCCopyViewsMatchingClassNames(",
            "CNDCCThemingCopyPhysicalInventory(",
        ):
            self.assertNotIn(forbidden, self.materializer)

    def test_materialization_uses_only_traced_lifecycle_routes(self) -> None:
        for contract in (
            '@"v16@0:8"',
            '@"@24@0:8@16"',
            '"loadViewIfNeeded"',
            '@"contentViewControllerForContext:"',
            '@"backgroundViewControllerForContext:"',
            '"_initializeExpandedView"',
            '"isExpandedViewInitialized"',
            '@"_activityPickerViewController"',
            '@"contentViewController"',
        ):
            self.assertIn(contract, self.probe)
        self.assertIn('@"loadedOffscreen"', self.probe)
        self.assertIn('@"ABIRejected"', self.probe)
        self.assertIn('@"viewStillMissing"', self.probe)

    def test_materialization_never_heuristically_promotes_unmapped_modules(self) -> None:
        self.assertIn('return kind.length ? kind : @"unclassified";', self.exact_module_kind)
        self.assertNotIn("CNDCCControlKind(", self.exact_module_kind)
        self.assertNotIn("VideoConferenceControlCenterModule", self.exact_module_kind)
        self.assertNotIn("AudioConferenceControlCenterModule", self.exact_module_kind)


if __name__ == "__main__":
    unittest.main()
