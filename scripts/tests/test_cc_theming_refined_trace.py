"""Contracts for the bounded refined physical follow-up (never apply paths)."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CCRefinedTraceTests(unittest.TestCase):
    def test_named_slots_and_unknown_swift_values_are_checked_not_guessed(self):
        source = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.m").read_text()
        for expected in (
            '"class_getInstanceVariable"', '"ivar_getOffset"',
            'actualClass == expectedClass', '@"runtimeReferenceClassMatched"',
            '@"_mainDisplayControlCenterController"', '@"_pagingViewController"',
            '@"_enabledModuleInstanceByUniqueIdentifer"', '@"_controlCenterController"',
            '@"leftButton"', '@"centerButton"', '@"rightButton"', '@"packageView"',
            '@"structLayoutRead": @NO', '@"swiftABICalled": @NO',
            '@"processOwnerEvidence"', '@"mediaNamedSlotEvidence"',
            '@"flashlightEvidence"', '@"hostedControlEvidence"', '@"imageProviderEvidence"',
        ):
            self.assertIn(expected, source)

    def test_discovery_is_separate_bounded_and_not_an_ownership_route(self):
        source = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.m").read_text()
        discovery = source.split("// BEGIN EXPLICIT REFINED DISCOVERY", 1)[1].split(
            "// END EXPLICIT REFINED DISCOVERY", 1)[0]
        self.assertIn('@"subviews"', discovery)
        self.assertIn("context->discoveryObjects < 128", discovery)
        self.assertIn('@"productionRoute": @NO', discovery)
        direct = source.split("static NSDictionary *CNDCCSemanticDirectPaths", 1)[1].split(
            "static NSDictionary *CNDCCLifecycleAnchorEvidence", 1)[0]
        self.assertNotIn('@"diagnosticDiscovery"', direct)
        self.assertNotIn("CNDCCGeometry", discovery)
        self.assertNotIn("accessibility", discovery)

    def test_capture_share_archives_and_comparison_preserve_existing_diagnostics(self):
        settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()
        for expected in (
            "physical-refined-controlcenter-routes.json", "physical-refined-controlcenter-routes-%@.json",
            "Trace Refined Physical CC Routes", "Share Refined Physical CC Routes",
            "cc-theming-trace-refined", "cc-theming-share-refined-trace",
            "CNDCCThemingCopyRefinedPhysicalRouteTrace()", "CNDCCThemingCompareRefinedPhysicalRoutes(report",
            '@"priorSamePIDComparison"', '@"capturePhase"', 'report[@"phaseIsUserDeclared"] = @YES',
            'physical-media-focus-semantic-trace.json', 'settings_run_cc_theming_media_focus_semantic_trace();',
        ):
            self.assertIn(expected, settings)

    def test_device_wrapper_words_require_independent_classification(self):
        source = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.m").read_text()
        for expected in (
            '@"_TtGC13MediaControls23RoutePickerSessionsViewCS_30MediaControlsModuleSessionView_"',
            '@[@"contentView", @"sessionViews"]', '@"wrapperSlotClassifications"',
            '@"rawWordHex"', 'snapshot[@"valueDereferenced"] = @NO',
            'classification[@"slotTypeVerified"] = @NO',
            '@"mediaMaterializationEvidence"', '@"presentationStateInferred": @NO',
        ):
            self.assertIn(expected, source)
        classification = source.split("static NSArray *CNDCCRefinedWrapperWordClassifications", 1)[1].split(
            "NSDictionary<NSString *, id> *CNDCCThemingCopyRefinedPhysicalRouteTrace", 1)[0]
        self.assertNotIn("CNDCCSemanticCall(", classification)
        self.assertNotIn("CNDCCSemanticGetter(", classification)
        self.assertNotIn("remote_read(", classification)
        raw_read = source.split('if (refined && [ivar[@"diagnosticUntypedWord"] boolValue])', 1)[1].split(
            'if (![ivar[@"safeObjectSlot"] boolValue]', 1)[0]
        self.assertIn("remote_read(object +", raw_read)
        self.assertNotIn('"object_getClass"', raw_read)
        self.assertNotIn("CNDCCSemanticEnqueue", raw_read)

    def test_priority_contracts_do_not_spend_generic_class_budget(self):
        source = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.m").read_text()
        priority = source.index("for (NSString *name in exactPriorityNames)")
        bootstrap = source.index("// Begin at process/container and registry owners")
        self.assertLess(priority, bootstrap)
        for expected in (
            "genericClassCount < classCap", "dynamicPriorityClassCap = 32",
            '@"classBudgetExempt": @YES', '@"metadataComplete"', '@"priorityInspection"',
            '@"genericClassBudgetReached"', '@"priorityClassBudgetReached"',
            '@"CHUISControlInstanceButton"', '@"CHUISControlIconView"',
            "[queue exchangeObjectAtIndex:i withObjectAtIndex:next]",
        ):
            self.assertIn(expected, source)

    def test_discovery_has_independent_frontier_and_reserved_object_allowance(self):
        source = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.m").read_text()
        discovery = source.split("// BEGIN EXPLICIT REFINED DISCOVERY", 1)[1].split(
            "// END EXPLICIT REFINED DISCOVERY", 1)[0]
        for expected in ("discoverySeen", "[frontier addObject:", "depth >= CNDCCSemanticDepthCap"):
            self.assertIn(expected, discovery)
        self.assertNotIn("queue.count > priorCount", discovery)
        self.assertIn("CNDCCRefinedDiscoveryObjectCap = 128", source)
        self.assertIn('@"diagnosticDiscoveryObjects"', source)
        validation = source.split("static void CNDCCRefinedValidateWrapperWords", 1)[1].split(
            "static NSDictionary *CNDCCThemingCopyLifecycleOwnerTraceImpl", 1)[0]
        self.assertIn('context->objectClasses[@(word)]', validation)
        self.assertIn('@"diagnosticWrapperReference"', validation)
        for forbidden in ("remote_read(", "object_getClass", "CNDCCSemanticGetter("):
            self.assertNotIn(forbidden, validation)
        self.assertIn('report[@"mediaSessionChains"]', source)

    def test_hosted_keys_include_kind_and_duplicate_keys_never_overwrite(self):
        source = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.m").read_text()
        for expected in (
            'object[@"machineIdentities"][@"kind"]', 'object[@"getters"][@"identity"][@"valueAddress"]',
            '@"|hostKind=%@"', '@"comparisonEligible"',
            '@"unpairedRouteObservations"', '@"ambiguousRouteReceiverGroups"',
            "before.count == 1 && after.count == 1", "[groups[key] addObject:observation]",
        ):
            self.assertIn(expected, source)
        self.assertNotIn('prior[row[@"key"]] = row', source)


if __name__ == "__main__":
    unittest.main()
