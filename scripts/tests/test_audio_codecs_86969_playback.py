#!/usr/bin/env python3
"""Static safety and wiring checks for the benign IOAudioCodecs trace."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class AudioCodecs86969PlaybackTests(unittest.TestCase):
    def test_only_playback_trace_is_live_url_runnable(self) -> None:
        app = (ROOT / "Cyanide/AppDelegate.m").read_text(encoding="utf-8")
        host = (ROOT / "scripts/lab/cnd_live_probe.py").read_text(
            encoding="utf-8"
        )
        url_handler = app[app.index("BOOL CNDHandleCommandURL(") :]
        self.assertIn('a86969-playback-benign', app)
        self.assertIn('a86969-playback-benign', host)
        for unsafe in (
            'a86969-benign',
            'a86969-raw',
            'a86969-krw-benign',
            'a86969-krw-raw',
        ):
            self.assertNotIn(unsafe, url_handler)
            self.assertNotIn(unsafe, host)

    def test_playback_trace_explicitly_bypasses_krw(self) -> None:
        app = (ROOT / "Cyanide/AppDelegate.m").read_text(encoding="utf-8")
        self.assertIn(
            '[cmd isEqualToString:@"a86969-playback-benign"]', app
        )
        self.assertIn(
            'BOOL krwReady = !requiresKrw ? YES :', app
        )
        self.assertIn('CNDAudioCodecs86969PlaybackTraceRun(finish)', app)

    def test_trace_uses_valid_media_and_read_only_observation(self) -> None:
        source = (
            ROOT / "Cyanide/probes/CNDAudioCodecs86969Probe.m"
        ).read_text(encoding="utf-8")
        start = source.index('void CNDAudioCodecs86969PlaybackTraceRun(')
        trace_entry = source[start:source.index('// Shared core:', start)]
        self.assertIn('AVPlayer', source)
        self.assertIn('IOServiceGetBusyState', source)
        self.assertIn('prog_index.m3u8', trace_entry)
        self.assertIn('@"krwAcquisitionAttempted": @NO', trace_entry)
        self.assertIn('@"kernelWriteUsed": @NO', trace_entry)
        self.assertIn('@"malformedInputUsed": @NO', trace_entry)


if __name__ == "__main__":
    unittest.main()
