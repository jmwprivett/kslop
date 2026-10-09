import importlib.util
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "lab/cnd_cc_owner_analysis.py"
spec = importlib.util.spec_from_file_location("cc_owner_analysis", SOURCE)
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)


class OwnerEvidenceTests(unittest.TestCase):
    def button(self, symbol, package, flipped):
        return {"className": "MediaControls.TransportButton", "swiftFields": [
            {"path": "viewModel.some.asset.symbolName", "value": symbol},
            {"path": "viewModel.some.asset.package.some.file", "enumCase": package},
            {"path": "viewModel.some.asset.package.some.isHorizontallyFlipped", "value": flipped}]}

    def test_role_requires_machine_model_evidence(self):
        self.assertEqual(analysis.transport_role(self.button("backward.fill", "nextPrevious", True))["role"], "media.previous")
        self.assertEqual(analysis.transport_role(self.button("forward.fill", "nextPrevious", False))["role"], "media.next")
        self.assertIsNone(analysis.transport_role(self.button("backward.fill", "nextPrevious", False)))
        self.assertIsNone(analysis.transport_role({"className": "MediaControls.TransportButton", "accessibilityLabel": "Previous"}))

    def test_recursive_discovery_does_not_become_named_route(self):
        report = {"edges": [{"from": "owner", "to": "leaf", "kind": "recursive-discovery", "name": "subviews"}]}
        self.assertNotIn("leaf", analysis.shortest_paths(report, "owner"))
        self.assertIn("leaf", analysis.shortest_paths(report, "owner", True))

    def test_same_pid_gate_and_actual_generations(self):
        before = {"pid": 1, "phase": "before", "truncated": False, "anchors": {"manager": ["A"]},
                  "transport": [], "focusRows": [{"activityIdentifier": "work", "address": "old"}]}
        after = {**before, "phase": "after", "focusRows": [{"activityIdentifier": "work", "address": "new"}]}
        result = analysis.compare(before, after)
        self.assertEqual(result["anchors"]["manager"]["persisted"], ["A"])
        self.assertEqual(result["roles"]["work"]["created"], ["new"])
        with self.assertRaises(ValueError): analysis.compare(before, {**after, "pid": 2})


if __name__ == "__main__": unittest.main()
