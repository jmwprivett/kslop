"""Structural checks for the capability-separated vPhone lab provider."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class LabKernelProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.protocol = (ROOT / "Cyanide/kexploit/CNDLabKernelProtocol.h").read_text()
        cls.provider = (ROOT / "Cyanide/kexploit/CNDLabKernelProvider.m").read_text()
        cls.bridge = (ROOT / "Cyanide/TaskRop/CNDKernelTaskBridge.m").read_text()
        cls.server = (ROOT / "scripts/lab/cnd_provide_tfp0.c").read_text()
        cls.harness = (ROOT / "scripts/lab/cnd_vphone_krw.py").read_text()
        cls.exploit = (ROOT / "Cyanide/kexploit/kexploit_opa334.m").read_text()

    def test_protocol_separates_resolve_task_and_kernel_capabilities(self) -> None:
        self.assertIn("CNDLabKRWCapabilityKernelReadWrite", self.protocol)
        self.assertIn("CNDLabKRWCapabilityDirectTask", self.protocol)
        self.assertIn("CNDLabKRWCapabilityProcessResolve", self.protocol)
        self.assertIn("CNDLabKRWOperationCapabilities", self.protocol)

    def test_server_does_not_infer_task_for_pid_from_root(self) -> None:
        capability = self.server.index(
            "request.operation == CNDLabKRWOperationCapabilities"
        )
        task_open = self.server.index("CNDLabKRWOperationTaskOpen", capability)
        body = self.server[capability:task_open]
        self.assertIn("CNDLabKRWCapabilityProcessResolve", body)
        self.assertIn("MACH_PORT_VALID(kernel_task)", body)
        self.assertNotIn(
            "geteuid() == 0\n                ? CNDLabKRWCapabilityDirectTask",
            body,
        )

    def test_server_resolves_names_longer_than_darwin_p_comm(self) -> None:
        self.assertIn("KERN_PROCARGS2", self.server)
        self.assertIn("process_executable_name_matches", self.server)
        self.assertIn("strcmp(basename, name) == 0", self.server)
        self.assertIn('"iconservicesagent"', self.harness)

    def test_client_accepts_resolver_without_claiming_kernel_rw(self) -> None:
        self.assertIn(
            "capabilities & CNDLabKRWCapabilityProcessResolve",
            self.provider,
        )
        self.assertIn("kernel-rw=no", self.provider)
        self.assertIn("cnd_lab_process_resolve_active", self.provider)
        self.assertIn("cnd_lab_direct_task_active", self.provider)
        self.assertIn("cnd_lab_kernel_rw_active", self.provider)

    def test_kernel_primitives_require_kernel_capability(self) -> None:
        self.assertEqual(
            self.exploit.count("if (cnd_lab_kernel_rw_active())"), 2
        )
        self.assertNotIn("if (cnd_lab_krw_active()) {", self.exploit)

    def test_process_resolution_precedes_any_kernel_walk(self) -> None:
        start = self.bridge.index("CNDKernelTaskBridgeResolveProcessPID(")
        end = self.bridge.index("typedef struct {", start)
        resolver = self.bridge[start:end]
        self.assertLess(
            resolver.index("cnd_lab_process_resolve_active()"),
            resolver.index("proc_self()"),
        )

    def test_harness_builds_root_helpers_as_arm64(self) -> None:
        self.assertIn('"-arch", "arm64"', self.harness)
        self.assertNotIn('"-arch", "arm64e"', self.harness)
        self.assertIn("APP_HOME_PATTERN", self.harness)
        self.assertIn("len(socket_path.encode()) >= 104", self.harness)


if __name__ == "__main__":
    unittest.main()
