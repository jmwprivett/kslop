"""Verify queue-owned CC transactions and their automatic respring boundary."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def active_runner(settings):
    return settings.split(
        "BOOL settings_apply_cc_theming_now(BOOL apply)", 1
    )[1].split("\n#if 0", 1)[0]


class CCThemingCompletionTests(unittest.TestCase):
    def test_queue_owned_runner_releases_its_lock_and_returns_status(self):
        settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()
        body = active_runner(settings)
        self.assertIn("BOOL success = NO;", body)
        self.assertIn("settings_try_claim_actions_lock", body)
        self.assertIn("@finally", body)
        self.assertIn("settings_release_actions_lock();", body)
        self.assertIn("return success;", body)
        self.assertNotIn("settings_post_actions_complete_async", body)
        self.assertNotIn("pendingCount", body)
        self.assertNotIn("commitInFlight", body)

    def test_queue_posts_respring_boundary_and_progress_runs_countdown(self):
        queue = (ROOT / "Cyanide/installer/PackageQueue.m").read_text()
        progress = (ROOT / "Cyanide/installer/InstallProgressViewController.m").read_text()
        self.assertIn("PackageQueueReadyForRespringNotification", queue)
        self.assertIn("PackageQueueReadyForRespringNotification", progress)
        self.assertIn("runRespringCountdownValue:3", progress)
        self.assertIn("settings_begin_system_edit_respring_with_completion", progress)


if __name__ == "__main__":
    unittest.main()
