"""Exercise the pure queue lifecycle projection with synthetic durable state."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class QueueExecutionSnapshotTests(unittest.TestCase):
    def test_admission_is_not_gated_by_the_presentation_snapshot(self):
        # The snapshot's edit gate exists to protect a saved or executing plan
        # from being rewritten (swipe-to-remove). Adding to the queue must not
        # consult it, or a new item would be refused by a running plan.
        queue = (ROOT / "Cyanide/installer/PackageQueue.m").read_text()
        admission = queue[queue.index("- (BOOL)canQueueIntent:"):
                          queue.index("- (BOOL)hasExecutingTransaction")]
        self.assertNotIn("executionSnapshot", admission)
        self.assertNotIn("canEdit", admission)
        self.assertIn("durableStoreUnavailable", admission)

    def test_saved_respring_boundary_is_projected_as_continuable(self):
        queue = (ROOT / "Cyanide/installer/PackageQueue.m").read_text()
        helper_start = queue.index(
            "static BOOL CNDQueuedRestartBoundaryAppearsObserved")
        helper_end = queue.index(
            "static CNDQueuedAction *CNDQueuedActionByCopyingExecutionState")
        helper = queue[helper_start:helper_end]
        self.assertIn("settings_current_boot_epoch()", helper)
        self.assertIn("CNDQueuedBootEpochMatches", helper)
        self.assertIn("kill(transaction.preRespringSpringBoardPID, 0)", helper)
        self.assertIn("errno == ESRCH", helper)

        snapshot = (ROOT /
                    "Cyanide/installer/CNDQueueExecutionSnapshot.m").read_text()
        awaiting = snapshot.index(
            "case CNDQueuedTransactionStateAwaitingRespring:",
            snapshot.index("switch (transaction.state)"))
        completed = snapshot.index(
            "case CNDQueuedTransactionStateCompleted:", awaiting)
        branch = snapshot[awaiting:completed]
        self.assertIn("if (restartBoundaryObserved)", branch)
        self.assertIn("CNDQueuePrimaryActionContinueAfterRespring", branch)
        self.assertIn("CNDQueuePrimaryActionRespring", branch)

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("xcrun"),
                         "requires macOS Foundation")
    def test_native_projection_contract(self):
        with tempfile.TemporaryDirectory(prefix="cnd-queue-snapshot-") as directory:
            binary = Path(directory) / "test-queue-snapshot"
            compiled = subprocess.run([
                "xcrun", "--sdk", "macosx", "clang", "-fobjc-arc",
                "-Wall", "-Wextra", "-Werror", "-framework", "Foundation",
                str(ROOT / "Cyanide/installer/CNDQueuedTransaction.m"),
                str(ROOT / "Cyanide/installer/CNDQueueExecutionSnapshot.m"),
                str(ROOT / "scripts/tests/test_queue_execution_snapshot.m"),
                "-o", str(binary),
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            tested = subprocess.run([str(binary)], capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(tested.returncode, 0,
                             tested.stdout + tested.stderr)
            self.assertIn("PASS:", tested.stdout)


if __name__ == "__main__":
    unittest.main()
