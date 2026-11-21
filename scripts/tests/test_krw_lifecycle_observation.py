"""Structural boundaries between KRW execution and its read-only projection."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def executable_source(source: str) -> str:
    """Strip comments before checking for executable calls, not documentation."""
    lines = []
    in_block_comment = False
    for line in source.splitlines():
        if in_block_comment:
            if "*/" in line:
                line = line.split("*/", 1)[1]
                in_block_comment = False
            else:
                continue
        if "/*" in line:
            before, after = line.split("/*", 1)
            if "*/" in after:
                line = before + after.split("*/", 1)[1]
            else:
                line = before
                in_block_comment = True
        lines.append(line.split("//", 1)[0])
    return "\n".join(lines)


class KRWLifecycleObservationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()
        cls.settings_header = (
            ROOT / "Cyanide/SettingsViewController.h"
        ).read_text()
        cls.app = (ROOT / "Cyanide/AppDelegate.m").read_text()
        cls.scene = (ROOT / "Cyanide/SceneDelegate.m").read_text()

    def settings_body(self, start: str, end: str) -> str:
        begin = self.settings.index(start)
        return self.settings[begin:self.settings.index(end, begin)]

    def app_body(self, start: str, end: str) -> str:
        begin = self.app.index(start)
        return self.app[begin:self.app.index(end, begin)]

    def test_cold_getter_never_checks_or_changes_krw(self) -> None:
        getter = self.settings_body(
            "CNDKRWLifecycleSnapshot *settings_current_krw_lifecycle_snapshot(void)",
            "static void settings_progress(",
        )
        capture = self.settings_body(
            "static CNDKRWLifecycleSnapshot *settings_capture_krw_lifecycle_locked(",
            "static void settings_publish_krw_lifecycle_observation(",
        )
        for body in (getter, capture):
            executable = executable_source(body)
            for forbidden in (
                "kexploit_opa334(",
                "krw_persistence_recover(",
                "krw_persistence_recover_with_status(",
                "kexploit_prepare_recoverable_termination(",
                "kexploit_terminal_cleanup",
                "kexploit_quiesce_for_process_termination(",
            ):
                self.assertNotIn(forbidden, executable)
        self.assertNotIn("kexploit_krw_ready()", executable_source(getter))
        self.assertIn("settings_capture_krw_lifecycle_locked(NO)", getter)
        self.assertIn("if (readinessObserved)", capture)
        readiness_call = capture.index("kexploit_krw_ready()")
        self.assertLess(capture.index("if (readinessObserved)"), readiness_call)
        self.assertLess(readiness_call, capture.index("CNDKRWRecoveryObservation recovery"))
        self.assertIn("g_settings_krw_preparation_serial == recoverySerial",
                      capture)
        self.assertNotIn("g_settings_krw_preparation_serial == preparation.handoffSerial",
                         capture)
        self.assertIn("recovery = CNDKRWRecoveryObservationForStage(", capture)
        self.assertIn("CNDKRWLifecycleSnapshot *settings_current_krw_lifecycle_snapshot(void);",
                      self.settings_header)

    def test_readiness_is_published_only_from_explicit_owner_boundaries(self) -> None:
        publisher = self.settings_body(
            "static void settings_publish_krw_lifecycle_observation(BOOL readinessObserved)\n{",
            "CNDKRWLifecycleSnapshot *settings_current_krw_lifecycle_snapshot(void)",
        )
        self.assertIn("settings_capture_krw_lifecycle_locked(readinessObserved)", publisher)
        self.assertNotIn("kexploit_krw_ready()", publisher)
        observer = self.settings_body(
            "static BOOL settings_observe_krw_generation_usable(void)",
            "bool settings_ensure_krw_for_probe(void)",
        )
        self.assertIn("settings_krw_generation_usable()", observer)
        self.assertIn("settings_publish_krw_lifecycle_observation(YES)", observer)
        probe_owner = self.settings_body(
            "bool settings_ensure_krw_for_probe(void)",
            "static BOOL settings_ensure_kexploit(void)",
        )
        self.assertIn("settings_ensure_kexploit()", probe_owner)
        self.assertNotIn("kexploit_opa334()", probe_owner)

    def test_command_timer_remains_nonblocking_and_legacy_state_is_preserved(self) -> None:
        timer = self.app_body(
            "dispatch_source_set_event_handler(cmdTimer, ^{",
            "dispatch_resume(cmdTimer);",
        )
        self.assertNotIn("kexploit_", timer)
        self.assertNotIn("settings_current_krw_lifecycle_snapshot", timer)
        self.assertIn("CNDCmdRunPendingIfAny(\"timer\")", timer)
        state = self.app_body(
            "static void CNDCmdPublishStateNoKrw(void)",
            "// A probe must survive",
        )
        self.assertIn('@"krwReady": @(-1)', state)
        self.assertIn('@"krwLifecycle":', state)
        self.assertIn("settings_current_krw_lifecycle_snapshot().agentRepresentation", state)
        self.assertNotIn("kexploit_krw_ready()", state)

    def test_result_and_busy_payloads_expose_cached_evidence_without_executing_krw(self) -> None:
        runner = self.app_body(
            "static void CNDCmdRun(NSString *command",
            "// Legacy in-container command pickup",
        )
        self.assertGreaterEqual(runner.count('@"krwLifecycle"'), 2)
        self.assertIn('@"refused-lifecycle-action-in-progress"', runner)
        self.assertIn("settings_ensure_krw_for_probe()", runner)
        self.assertIn("settings_ensure_existing_krw_for_probe()", runner)
        self.assertNotIn("kexploit_krw_ready()", runner)
        self.assertNotIn("kexploit_opa334()", runner)
        self.assertNotIn("kexploit_terminal_cleanup", runner)
        self.assertNotIn("krw_persistence_recover", runner)
        release = runner.index("settings_end_external_krw_action(cmd.UTF8String)")
        evidence = runner.index("finished[@\"krwLifecycle\"]", release)
        result = runner.index("CNDCmdWriteJSON(@\"cnd-result.json\", finished)", evidence)
        self.assertLess(release, evidence)
        self.assertLess(evidence, result)

    def test_settings_footer_is_observational_and_does_not_add_rows(self) -> None:
        self.assertIn("case RootSectionActions:        return 6;", self.settings)
        self.assertIn("settings_current_krw_lifecycle_snapshot().statusFooter",
                      self.settings)
        self.assertIn("name:kSettingsKRWLifecycleDidChangeNotification",
                      self.settings)
        footer = self.settings_body(
            "- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section\n{",
            "    if (s == SectionLaunch)",
        )
        self.assertNotIn("kexploit_", footer)
        self.assertNotIn("krw_persistence_recover", footer)

    def test_scene_transitions_never_close_the_live_krw_session(self) -> None:
        background = self.settings_body(
            "void settings_application_did_enter_background(void)",
            "void settings_application_will_enter_foreground(void)",
        )
        executable = executable_source(background)
        self.assertIn("if (anyLiveLoopNeeded)", executable)
        self.assertIn("settings_reconcile_snowboard_automatic_repair_lifetime()", executable)
        self.assertNotIn("settings_queue_background_krw_park", executable)
        self.assertNotIn("settings_terminal_kexploit_cleanup", executable)
        self.assertNotIn("kexploit_terminal_cleanup", executable)
        self.assertNotIn("krw_persistence_recover", executable)
        self.assertNotIn("settings_queue_background_krw_park", self.settings)

        predicate = executable_source(self.settings_body(
            "static BOOL settings_background_live_loops_needed(NSUserDefaults *d)",
            "void settings_application_did_enter_background(void)",
        ))
        self.assertIn("CNDIconServicesConsumerLifecycleIsRunning()", predicate)
        self.assertIn("settings_background_live_loops_needed(d)", executable)
        self.assertNotIn("settings_application_will_resign_active",
                         self.settings_header)

        scene_resign = executable_source(self.scene[
            self.scene.index("- (void)sceneWillResignActive:"):
            self.scene.index("sceneWillEnterForeground")])
        self.assertNotIn("settings_", scene_resign)

    def test_failed_snowboard_run_does_not_close_krw(self) -> None:
        runner = executable_source(self.settings[
            self.settings.index(
                "static void settings_run_snowboard_remix_operation_with_completion("
            ):
            self.settings.index(
                "static void settings_run_snowboard_remix_operation("
            )
        ])
        # An operation result must not turn a recoverable live session into a
        # process boundary. Cleanup remains explicit or termination-only.
        ok_index = runner.index("BOOL ok = [result[@\"ok\"] boolValue];")
        completion_index = runner.rindex("kSettingsActionsDidCompleteNotification")
        self.assertLess(ok_index, completion_index)
        self.assertNotIn("settings_queue_background_krw_park", runner)
        self.assertNotIn("kexploit_terminal_cleanup", runner)


if __name__ == "__main__":
    unittest.main()
