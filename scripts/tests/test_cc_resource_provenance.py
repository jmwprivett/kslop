import importlib.util
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "lab/cnd_cc_owner_analysis.py"
spec = importlib.util.spec_from_file_location("cc_resource_analysis", SOURCE)
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)


def event(sequence, cls, selector, arguments=(), result=None, parent=0, phase="before"):
    return {"sequence": sequence, "phase": phase, "receiver": {"className": cls},
            "selector": selector, "classMethod": cls in ("MRUAssetsProvider", "CAPackage", "FCUICAPackageView", "UIImage"),
            "arguments": list(arguments), "result": result, "parentSequence": parent,
            "stockArgumentsUnchanged": True, "stockReturnUnchanged": True}


def report(events=(), objects=(), edges=()):
    return {"objects": list(objects), "edges": list(edges), "truncated": False,
            "resourceProvenanceTrace": {"events": list(events), "methodContracts": [{"installed": True}],
                                        "active": True, "droppedEvents": 0}}


class ResourceProvenanceTests(unittest.TestCase):
    def test_metadata_getter_invocation_is_not_natural_factory_evidence(self):
        result = analysis.resource_provenance({"objects": [], "edges": [], "staticProviderGetters": [
            {"className": "MRUAssetsProvider", "invoked": True, "value": "PlayPauseStop"}]})
        self.assertEqual(result["factoryCalls"], [])
        self.assertFalse(result["captureComplete"])

    def test_package_url_root_layer_joins_only_verified_named_media_consumer(self):
        button = {"address": "button", "className": "MediaControls.TransportButton", "swiftFields": [
            {"path": "viewModel.some.asset.symbolName", "value": "play.fill"},
            {"path": "viewModel.some.asset.package.some.file", "enumCase": "playPauseStop"}]}
        package_view = {"address": "view", "className": "MediaControls.PackageView", "swiftFields": [
            {"name": "packageLayer", "objectAddress": "layer", "namedSlotVerified": True}]}
        events = [event(1, "MRUAssetsProvider", "packageWithName:", [{"value": "PlayPauseStop"}], {"address": "package"}),
                  event(2, "CAPackage", "packageWithContentsOfURL:type:options:error:",
                        [{"value": "file:///System/Library/PrivateFrameworks/MediaControls.framework/PlayPauseStop.ca"}],
                        {"address": "package", "rootLayer": {"address": "layer"}}, parent=1)]
        edge = {"from": "button", "to": "view", "name": "packageView", "kind": "verified-swift-object-ivar"}
        result = analysis.resource_provenance(report(events, [button, package_view], [edge]))
        self.assertEqual(result["packageLoads"][0]["factoryLineage"][0]["selector"], "packageWithName:")
        self.assertEqual(result["packageLoads"][0]["namedConsumerMatches"][0]["role"], "media.playPause")
        edge["kind"] = "recursive-discovery"
        result = analysis.resource_provenance(report(events, [button, package_view], [edge]))
        self.assertEqual(result["packageLoads"][0]["namedConsumerMatches"], [])

    def test_focus_symbol_and_cache_calls_keep_activity_and_parent_factory(self):
        events = [event(1, "FCUIActivityControl", "_updateActivityIcon"),
                  event(2, "FCUICAPackageView", "packageViewForActivity:",
                        [{"activityIdentifier": "com.apple.focus.personal"}], {"address": "view"}, parent=1),
                  event(3, "NSCache", "objectForKey:", [{"value": "personal"}], None, parent=2),
                  event(4, "UIImage", "systemImageNamed:", [{"value": "person.fill"}], {"address": "image"}, parent=1)]
        events[0]["receiverAfter"] = {"activityIdentifier": "com.apple.focus.personal"}
        result = analysis.resource_provenance(report(events))
        self.assertEqual(result["symbolCalls"][0]["activityIdentifier"], "com.apple.focus.personal")
        self.assertEqual(result["cacheCalls"][0]["factoryLineage"][0]["selector"], "packageViewForActivity:")

    def test_multiple_phase_calls_do_not_assert_reconstruction_or_persistence(self):
        events = [event(1, "MRUAssetsProvider", "packageWithName:", phase="compact"),
                  event(2, "MRUAssetsProvider", "packageWithName:", phase="expanded")]
        result = analysis.resource_provenance(report(events))
        self.assertTrue(result["boundaryConsultations"][0]["consultedInMultiplePhases"])
        self.assertTrue(result["boundaryConsultations"][0]["newReceiverGenerationStillRequiresSnapshotComparison"])
        source = report(events); source["resourceProvenanceTrace"]["droppedEvents"] = 1
        self.assertFalse(analysis.resource_provenance(source)["captureComplete"])

    def test_comparison_joins_new_focus_row_to_new_factory_call_only(self):
        earlier = {"pid": 625, "phase": "before", "truncated": False, "anchors": {}, "transport": [],
                   "focusRows": [{"address": "old", "activityIdentifier": "personal"}],
                   "resourceProvenance": {"factoryCalls": [{"sequence": 1}]}}
        later = {**earlier, "phase": "after", "focusRows": [{"address": "new", "activityIdentifier": "personal"}],
                 "resourceProvenance": {"factoryCalls": [
                     {"sequence": 1}, {"sequence": 2, "className": "FCUICAPackageView", "selector": "packageViewForActivity:",
                      "namedConsumerMatches": [{"row": "new", "activityIdentifier": "personal", "packageView": "view"}]}]}}
        comparison = analysis.compare(earlier, later)
        self.assertEqual([call["sequence"] for call in comparison["resourceFactoryCallsDuringInterval"]], [2])
        self.assertEqual(comparison["newFocusRowsWithFactoryReturnMatch"][0]["row"], "new")


if __name__ == "__main__": unittest.main()
