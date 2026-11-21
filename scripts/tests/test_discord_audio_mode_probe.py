import unittest
from pathlib import Path
import runpy


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "Cyanide/probes/CNDDiscordAudioModeProbe.m"
APP_DELEGATE = ROOT / "Cyanide/AppDelegate.m"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"
LIVE_PROBE = ROOT / "scripts/lab/cnd_live_probe.py"


class DiscordAudioModeProbeTests(unittest.TestCase):
    def test_probe_is_exact_bounded_discord_experiment(self) -> None:
        source = PROBE.read_text()
        self.assertIn('CND_DISCORD_AUDIO_PRODUCT "iPhone17,2"', source)
        self.assertIn('CND_DISCORD_AUDIO_BUILD "23A341"', source)
        self.assertIn('CND_DISCORD_AUDIO_PROCESS "Discord"', source)
        self.assertIn(
            'CND_DISCORD_AUDIO_BUNDLE "com.hammerandchisel.discord"',
            source,
        )
        self.assertIn(
            'CND_DISCORD_AUDIO_DEFAULT_MODE "AVAudioSessionModeDefault"',
            source,
        )
        self.assertIn('@"kernelCallUsed": @NO', source)
        self.assertIn('@"dylibInjected": @NO', source)

    def test_target_identity_and_audio_effect_are_read_back(self) -> None:
        source = PROBE.read_text()
        self.assertIn("kexploit_krw_read_checked", source)
        self.assertIn("CNDDiscordAudioBundleIdentifier", source)
        self.assertIn('"setMode:error:"', source)
        self.assertIn('"currentRoute"', source)
        self.assertIn('@"defaultModeActive"', source)
        self.assertIn('@"bluetoothA2DPObserved"', source)
        self.assertIn('@"builtInInputActive"', source)
        self.assertIn('@"fullQualityAirPodsRouteVerified"', source)

    def test_apply_journals_and_leaves_configuration_active(self) -> None:
        source = PROBE.read_text()
        self.assertIn("CNDDiscordAudioSaveJournal", source)
        self.assertIn("CNDDiscordAudioFindInput", source)
        self.assertIn('"setPreferredInput:error:"', source)
        self.assertIn('@"persistentAudioMutationActive"', source)
        self.assertIn('@"automaticAudioRestorePerformed"', source)
        self.assertIn("CNDDiscordAudioModeProbeApply", source)

    def test_restore_replays_journal_and_restores_target_thread(self) -> None:
        source = PROBE.read_text()
        self.assertIn("CNDDiscordAudioModeProbeRestore", source)
        self.assertIn('@"modeRestored"', source)
        self.assertIn('@"preferredInputRestored"', source)
        self.assertIn("CNDDiscordAudioRemoveJournal", source)
        self.assertIn("destroy_remote_call()", source)
        self.assertIn('@"threadRestored"', source)
        self.assertIn('@"targetIdentityStable"', source)

    def test_live_command_is_wired(self) -> None:
        app_delegate = APP_DELEGATE.read_text()
        self.assertIn(
            'isEqualToString:@"discord-audio-apply"',
            app_delegate,
        )
        self.assertIn(
            'isEqualToString:@"discord-audio-restore"',
            app_delegate,
        )
        self.assertIn('@"discord-audio-apply", @"discord-audio-restore"', app_delegate)
        self.assertIn(
            '"discord-audio-apply"', LIVE_PROBE.read_text()
        )
        self.assertIn(
            '"discord-audio-restore"', LIVE_PROBE.read_text()
        )
    def test_settings_has_separate_apply_and_restore_buttons(self) -> None:
        source = SETTINGS.read_text()
        self.assertIn('@"Discord: Use iPhone Mic + AirPods"', source)
        self.assertIn('@"Restore Discord Audio Route"', source)
        self.assertIn("CNDDiscordAudioModeProbeApply(finished)", source)
        self.assertIn("CNDDiscordAudioModeProbeRestore(finished)", source)

    def test_live_harness_requires_a2dp_for_apply_success(self) -> None:
        validate = runpy.run_path(str(LIVE_PROBE))["validate_intended_result"]
        result = {
            "schema": "com.zeroxjf.cyanide.discord-audio-mode-probe",
            "operation": "apply",
            "result": "applied-built-in-mic-a2dp-observed",
            "applyCompleted": True,
            "defaultModeActive": True,
            "builtInInputActive": True,
            "bluetoothA2DPObserved": True,
            "fullQualityAirPodsRouteVerified": True,
            "persistentAudioMutationActive": True,
            "automaticAudioRestorePerformed": False,
            "threadRestored": True,
            "targetIdentityStable": True,
            "reportSaved": True,
        }
        validate("discord-audio-apply", "request", result)
        result["bluetoothA2DPObserved"] = False
        with self.assertRaisesRegex(ValueError, "full-quality route"):
            validate("discord-audio-apply", "request", result)


if __name__ == "__main__":
    unittest.main()
