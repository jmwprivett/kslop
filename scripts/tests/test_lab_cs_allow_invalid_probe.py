"""Structural tests for the exact-build VM cs_allow_invalid experiment."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_vphone_krw  # noqa: E402


class LabCSAllowInvalidProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (
            ROOT / "scripts/lab/cnd_lab_cs_allow_invalid_probe.c"
        ).read_text()
        cls.harness = (
            ROOT / "scripts/lab/cnd_vphone_krw.py"
        ).read_text()

    def test_probe_is_exact_build_and_rea_bound(self) -> None:
        for required in (
            "0xfffffe0007004000",
            "0xfffffe0009813020",
            "0xfffffe0007f821fc",
            "03A93373-6498-3F25-8975-04DED251AF1F",
            "ev_c2b765cbfdf0ac852cfc4ec2100d56b68ac3fd5a20e67d5d8efd2f7a7d9496e2",
            "ev_de49f3f966d4609eab464b1d729deaca0caa3393c1efe189ec19b010c2545afd",
            "CNDCSAllowInvalidPrologue",
            "memcmp(prologue, CNDCSAllowInvalidPrologue",
        ):
            self.assertIn(required, self.source)

    def test_probe_requires_every_vm_provider_capability(self) -> None:
        for required in (
            "CNDLabKRWCapabilityKernelReadWrite",
            "CNDLabKRWCapabilityDirectTask",
            "CNDLabKRWCapabilityProcessResolve",
            "CNDLabKRWCapabilityKernelCall",
        ):
            self.assertIn(required, self.source)

    def test_probe_uses_exact_springboard_proc_as_the_only_argument(self) -> None:
        self.assertIn('static char name[] = "SpringBoard"', self.source)
        self.assertIn("find_process(fd, allproc_head", self.source)
        self.assertIn(".argument_count = 1", self.source)
        self.assertIn(".arguments = { argument }", self.source)
        self.assertIn(
            "fd, cs_allow_invalid, process, &call_result",
            self.source,
        )

    def test_probe_distinguishes_return_from_executable_admission(self) -> None:
        self.assertEqual(self.source.count("rx_attempt(fd,"), 3)
        self.assertIn("CNDLabKRWOperationTaskProtectRX", self.source)
        self.assertIn("CNDLabKRWOperationTaskThreadStart", self.source)
        self.assertIn("CNDExecutionNonce", self.source)
        self.assertIn("!baseline.executed && call_status == 0", self.source)
        self.assertIn("call_result != 0 && after.executed", self.source)
        self.assertIn("pmap-sptm-transition-denied", self.source)
        self.assertIn("pmapTransitionProven", self.source)
        self.assertIn("experimentInfrastructureHealthy", self.source)

    def test_probe_resets_the_mutated_springboard_identity(self) -> None:
        self.assertIn("kill((pid_t)pid, SIGKILL)", self.source)
        self.assertIn("replacement_pid != pid", self.source)
        self.assertIn("springBoardResetVerified", self.source)

    def test_harness_persists_schema_checked_evidence(self) -> None:
        self.assertIn('"standalone-cs-allow-invalid"', self.harness)
        self.assertIn("build_cs_allow_invalid_probe", self.harness)
        self.assertIn("build_cs_allow_invalid_provider", self.harness)
        self.assertIn('architecture="arm64e"', self.harness)
        self.assertIn("run_cs_allow_invalid_probe", self.harness)
        self.assertIn("com.zeroxjf.cyanide.vm-cs-allow-invalid", self.harness)
        self.assertIn("CS_ALLOW_INVALID_OBSERVATION.write_text", self.harness)

    def test_harness_rejects_wrong_probe_schema(self) -> None:
        class FakeSSH:
            def command(self, _command: str) -> str:
                return '{"schema":"wrong","schemaVersion":1}'

        with self.assertRaises(cnd_vphone_krw.LabError):
            cnd_vphone_krw.run_cs_allow_invalid_probe(
                FakeSSH(), "/tmp/probe", "/tmp/provider.sock"
            )


if __name__ == "__main__":
    unittest.main()
