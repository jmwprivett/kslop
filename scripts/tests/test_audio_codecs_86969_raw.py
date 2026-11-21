#!/usr/bin/env python3
"""Static capability and wiring checks for the 24A446 raw trigger probe."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "Cyanide/probes/CNDAudioCodecs86969Probe.m"
APP = ROOT / "Cyanide/AppDelegate.m"
HOST = ROOT / "scripts/lab/cnd_live_probe.py"


class AudioCodecs86969RawTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PROBE.read_text(encoding="utf-8")
        cls.app = APP.read_text(encoding="utf-8")
        cls.host = HOST.read_text(encoding="utf-8")
        cls.raw = cls.source[
            cls.source.index("static NSString *CNDA86969SysctlString"):
            cls.source.index("// KRW-assisted variant")
        ]

    def test_selector_abi_matches_24a446_dispatch_table(self) -> None:
        self.assertIn("CND_A86969_SELECTOR_INITIALIZE 2", self.source)
        self.assertIn("CND_A86969_SELECTOR_PACKET 5", self.source)
        self.assertIn("uint64_t scalarInput[3] = { 0, inSize, 0 };", self.raw)
        self.assertIn("uint64_t scalarOutput[2] = { 0, 0 };", self.raw)
        self.assertIn("IOConnectCallScalarMethod(", self.raw)
        self.assertIn("sizeof(CNDA86969InitializeRequest) == 0x50", self.source)
        self.assertIn("IOConnectCallStructMethod(", self.raw)

    def test_header_format_and_input_mapping_are_exact(self) -> None:
        for fragment in (
            "CND_A86969_HEADER_FORMAT UINT32_C(0x63616333)",
            "asbd.mSampleRate = 48000.0",
            "asbd.mFormatFlags = 0x0c",
            "asbd.mBytesPerPacket = 0x1800",
            "asbd.mFramesPerPacket = 0x600",
            "asbd.mBytesPerFrame = 4",
            "asbd.mChannelsPerFrame = 2",
            "asbd.mBitsPerChannel = 16",
            "IOConnectMapMemory64(conn, 0",
            "input[8] = 0x0b",
            "input[9] = 0x77",
        ):
            self.assertIn(fragment, self.source)

    def test_controls_precede_descending_raw_sweep(self) -> None:
        controls = self.raw.index("const uint64_t controlSizes[] = { 10, 0x20 };")
        sweep = self.raw.index("for (NSInteger inSize = 7; inSize >= 0; inSize--)")
        self.assertLess(controls, sweep)
        self.assertIn('@"phase": phase', self.raw)
        self.assertIn('@"status": @"calling"', self.raw)
        self.assertIn('@"a86969-raw-attempt.json"', self.raw)
        self.assertIn('@"cleanupVerdict"] = @"not-reached-trigger-call"', self.raw)
        packet_call = self.raw[
            self.raw.index("static kern_return_t CNDA86969CallPacket"):
            self.raw.index("static void CNDA86969Cleanup")
        ]
        self.assertLess(
            packet_call.index("CNDA86969PersistRawAttempt(rep);"),
            packet_call.index("IOConnectCallScalarMethod("),
        )

    def test_raw_probe_is_exact_target_gated_and_plain_app_only(self) -> None:
        self.assertIn('#define CND_A86969_RAW_PRODUCT @"iPhone14,5"', self.source)
        self.assertIn('#define CND_A86969_RAW_BUILD @"24A446"', self.source)
        self.assertIn('@"refused-exact-target-mismatch"', self.raw)
        for forbidden in (
            "kexploit_krw_ready",
            "kread64",
            "kreadbuf",
            "kwrite64",
            "kcall",
        ):
            self.assertNotIn(forbidden, self.raw)
        self.assertIn('@"activePrimitiveGeneration": @"none"', self.raw)
        self.assertIn('CNDA86969SysctlString("kern.bootsessionuuid")', self.raw)
        self.assertIn('@"selectorCorpusSHA256"', self.raw)

    def test_open_denial_stops_before_initialization(self) -> None:
        open_failure_start = self.raw.index("if (kr != KERN_SUCCESS) {")
        open_failure = self.raw[
            open_failure_start:
            self.raw.index("kr = IOConnectCallScalarMethod(", open_failure_start)
        ]
        self.assertIn('@"open-failed-sandbox-not-permitted"', open_failure)
        self.assertIn('rep[@"stoppedBeforeInitialization"] = @YES', open_failure)

    def test_manual_command_only_not_live_url_or_host(self) -> None:
        command_runner = self.app[
            self.app.index("static void CNDCmdRun("):
            self.app.index("static void CNDCmdRunPendingIfAny(")
        ]
        url_handler = self.app[self.app.index("BOOL CNDHandleCommandURL(") :]
        self.assertIn('[cmd isEqualToString:@"a86969-raw"]', command_runner)
        self.assertIn("CNDAudioCodecs86969ProbeRun(NO, finish)", command_runner)
        self.assertNotIn("a86969-raw", url_handler)
        self.assertNotIn("a86969-raw", self.host)


if __name__ == "__main__":
    unittest.main()
