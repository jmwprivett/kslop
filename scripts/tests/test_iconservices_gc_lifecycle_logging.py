"""Structural checks for the resident IconServices lifecycle/GC logger."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "scripts/lab"
SOURCE = LAB / "cnd_iconservices_inspector.m"
sys.path.insert(0, str(LAB))
import cnd_iconservices_inspection as inspection  # noqa: E402


class IconServicesGarbageCollectionLoggingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE.read_text()

    def test_hooks_complete_invalidation_and_gc_boundaries(self) -> None:
        required = (
            "clearCachedItemsForBundeID:reply:",
            "clearAllCachedItemsWithReply:",
            "scheduleCacheOperation:",
            "collectGarbage",
            "registerRecordIdentifiers:asSourceForUnit:",
            "removeUnitForUUID:",
            "initWithPersistentIdentifier:",
            '"ClearCacheOperation", "run"',
        )
        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source)

    def test_logs_caller_identity_and_pairs_source_with_deleted_uuid(self) -> None:
        self.assertIn("currentConnection", self.source)
        self.assertIn("processIdentifier", self.source)
        self.assertIn("gc-invalid-source", self.source)
        self.assertIn("gc-remove-source", self.source)
        self.assertIn("sourcePresent=%d", self.source)
        self.assertIn("mode=%s", self.source)

    def test_classifies_database_guid_separately_from_record_identity(self) -> None:
        self.assertIn('"database-guid"', self.source)
        self.assertIn('"unit-or-record-identity"', self.source)
        self.assertIn("currentDatabaseGUID", self.source)
        self.assertIn("identifier.bytes + 12U", self.source)
        self.assertIn("CNDIconInspectReadUInt32(identifier, 4U", self.source)
        self.assertIn("CNDIconInspectReadUInt32(identifier, 8U", self.source)
        self.assertIn("CNDIconInspectReadUInt64(identifier, 28U", self.source)

    def test_identifier_capture_is_strictly_bounded(self) -> None:
        self.assertIn(
            "CNDIconInspectMaximumPersistentIdentifierLength = 128U",
            self.source,
        )
        self.assertIn("lastInvalidIdentifier[128]", self.source)
        self.assertIn("if (observed >= 8U) break", self.source)

    def test_inspector_build_embeds_only_validated_target_bundle(self) -> None:
        with mock.patch.object(inspection, "run") as run:
            inspection.build_inspector(target_bundle="com.apple.MobileSMS")
        compiler_args = run.call_args_list[0].args[0]
        self.assertIn(
            '-DCND_ICON_INSPECT_TARGET_BUNDLE="com.apple.MobileSMS"',
            compiler_args,
        )
        with self.assertRaises(inspection.LabError):
            inspection.build_inspector(target_bundle="com.bad;touch /tmp/no")

    def test_watch_requires_every_lifecycle_hook(self) -> None:
        self.assertEqual(inspection.EXPECTED_HOOKS, 27)
        report = "[CND_ICON_AGENT] TRACE_READY pid=10 hooks=26 expected=27"
        with mock.patch.object(inspection, "read_report", return_value=report), \
             mock.patch.object(inspection.time, "monotonic",
                               side_effect=(0.0, 0.0, 9.0)):
            with self.assertRaises(inspection.LabError):
                inspection.wait_ready(mock.Mock(), timeout=1.0)

    def test_trigger_uses_the_same_explicit_bundle(self) -> None:
        ssh = mock.Mock()
        ssh.command.return_value = "ok"
        result = inspection.run_trigger(
            ssh, "/var/tmp/trigger", "com.apple.MobileSMS", True
        )
        self.assertEqual(result, "ok")
        ssh.command.assert_called_once_with(
            "/var/tmp/trigger --bundle com.apple.MobileSMS --ignore-cache"
        )

    def test_lifecycle_report_removes_large_runtime_inventory(self) -> None:
        report = "\n".join((
            "[CND_ICON_AGENT] START pid=10",
            "[CND_ICON_AGENT] method class=ISStore name=removeUnitForUUID:",
            "[CND_ICON_AGENT] lifecycle gc-enter cycle=1",
            "[CND_ICON_AGENT] TRACE_READY pid=10 hooks=27 expected=27",
        ))
        filtered = inspection.lifecycle_report(report)
        self.assertIn("START pid=10", filtered)
        self.assertIn("lifecycle gc-enter", filtered)
        self.assertIn("TRACE_READY", filtered)
        self.assertNotIn("method class=", filtered)


if __name__ == "__main__":
    unittest.main()
