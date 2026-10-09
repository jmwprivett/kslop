"""Structural checks for the capability-separated vPhone lab provider."""

from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_vphone_krw  # noqa: E402


class LabKernelProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.protocol = (ROOT / "Cyanide/kexploit/CNDLabKernelProtocol.h").read_text()
        cls.provider = (ROOT / "Cyanide/kexploit/CNDLabKernelProvider.m").read_text()
        cls.bridge = (ROOT / "Cyanide/TaskRop/CNDKernelTaskBridge.m").read_text()
        cls.server = (ROOT / "scripts/lab/cnd_provide_tfp0.c").read_text()
        cls.harness = (ROOT / "scripts/lab/cnd_vphone_krw.py").read_text()
        cls.probe = (ROOT / "scripts/lab/cnd_lab_krw_probe.c").read_text()
        cls.exploit = (ROOT / "Cyanide/kexploit/kexploit_opa334.m").read_text()

    def test_protocol_separates_resolve_task_and_kernel_capabilities(self) -> None:
        self.assertIn("CNDLabKRWCapabilityKernelReadWrite", self.protocol)
        self.assertIn("CNDLabKRWCapabilityDirectTask", self.protocol)
        self.assertIn("CNDLabKRWCapabilityProcessResolve", self.protocol)
        self.assertIn("CNDLabKRWCapabilityKernelCall", self.protocol)
        self.assertIn("CNDLabKRWOperationCapabilities", self.protocol)
        self.assertIn("CNDLabKRWOperationKernelCall", self.protocol)

    def test_kernel_call_uses_a_separately_versioned_fixed_abi(self) -> None:
        self.assertIn("#define CND_LAB_KRW_VERSION 3U", self.protocol)
        self.assertIn("#define CND_LAB_KCALL_ABI_VERSION 1U", self.protocol)
        self.assertIn("#define CND_LAB_KCALL_MAX_ARGUMENTS 8U", self.protocol)
        self.assertIn("uint32_t argument_count;", self.protocol)
        self.assertIn(
            "uint64_t arguments[CND_LAB_KCALL_MAX_ARGUMENTS]",
            self.protocol,
        )
        self.assertIn("sizeof(CNDLabKernelCallRequest) == 80", self.protocol)

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

    def test_server_advertises_kernel_call_only_from_validated_handler(self) -> None:
        capability = self.server.index(
            "request.operation == CNDLabKRWOperationCapabilities"
        )
        kbase = self.server.index("CNDLabKRWOperationKBase", capability)
        body = self.server[capability:kbase]
        self.assertIn("active_kernel_call()", body)
        kernel_call_capability = body.index(
            "CNDLabKRWCapabilityKernelCall"
        )
        capability_guard = body[max(0, kernel_call_capability - 100):
                                kernel_call_capability]
        self.assertIn("active_kernel_call() && base != 0", capability_guard)

    def test_vm_syscall_backend_is_probed_fail_closed(self) -> None:
        self.assertIn("CND_VPHONE_KCALL_SYSCALL = 439", self.server)
        self.assertIn("CND_VPHONE_KCALL_MAX_ARGUMENTS = 7", self.server)
        self.assertIn("vphone_kcall_syscall_available", self.server)
        self.assertIn("return result == EINVAL;", self.server)
        self.assertIn('"svc #0x80', self.server)

    def test_server_validates_kernel_call_request_before_dispatch(self) -> None:
        start = self.server.index(
            "request.operation == CNDLabKRWOperationKernelCall"
        )
        end = self.server.index(
            "request.operation == CNDLabKRWOperationResolvePID", start
        )
        body = self.server[start:end]
        for required in (
            "request.address != 0",
            "request.length != sizeof(CNDLabKernelCallRequest)",
            "call.version != CND_LAB_KCALL_ABI_VERSION",
            "call.argument_count > CND_LAB_KCALL_MAX_ARGUMENTS",
            "kernel_call_target_valid(base, call.function)",
            "active_kernel_call()(",
        ):
            self.assertIn(required, body)

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

    def test_client_kernel_call_is_capability_gated_and_lab_only(self) -> None:
        self.assertIn("cnd_lab_socket_kcall", self.provider)
        self.assertIn("cnd_lab_kernel_call_active", self.provider)
        self.assertIn("cnd_lab_kernel_call(", self.provider)
        self.assertIn("return ENOTSUP;", self.provider)
        self.assertIn(
            "capabilities & CNDLabKRWCapabilityKernelCall",
            self.provider,
        )
        self.assertNotIn("cnd_lab_kernel_call(", self.exploit)

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

    def test_vm_provider_uses_the_existing_tfp0_entitlements(self) -> None:
        self.assertIn(
            'TFP0_ENTITLEMENTS = REPO_ROOT / '
            '"scripts/lab/cnd_tfp0_entitlements.plist"',
            self.harness,
        )
        self.assertIn(
            'build_binary(PROVIDER_SOURCE, "cnd_provide_tfp0", '
            'TFP0_ENTITLEMENTS)',
            self.harness,
        )
        self.assertIn(
            'sign.extend(["--entitlements", str(entitlements)])',
            self.harness,
        )

    def test_harness_accepts_only_canonical_debugger_kernel_addresses(self) -> None:
        self.assertIn('"--kernel-address"', self.harness)
        self.assertIn('r"0x[0-9A-Fa-f]{16}"', self.harness)
        self.assertIn("address & 0x3fff", self.harness)
        self.assertIn('return f"0x{address:016x}"', self.harness)
        self.assertIn("argument=%s", self.server)

    def test_debugger_capture_requires_a_unique_address_uuid_and_detach(self) -> None:
        report = b"""Kernel UUID: 03A93373-6498-3F25-8975-04DED251AF1F
Load Address: 0xfffffe0041ac4000
Process 1 detached
"""
        completed = mock.Mock(stdout=report, stderr=b"")
        with mock.patch.object(cnd_vphone_krw, "run", return_value=completed):
            address, uuid = cnd_vphone_krw.debugger_kernel_address(62139)
        self.assertEqual(address, "0xfffffe0041ac4000")
        self.assertEqual(uuid, "03A93373-6498-3F25-8975-04DED251AF1F")

    def test_kernel_address_validation_rejects_noncanonical_or_unaligned_input(self) -> None:
        self.assertEqual(
            cnd_vphone_krw.canonical_kernel_address("0xFFFFFE0041AC4000"),
            "0xfffffe0041ac4000",
        )
        for invalid in (
            "fffffe0041ac4000",
            "0x0000000041ac4000",
            "0xfffffe0041ac4001",
            "0xfffffe0041ac400000",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(cnd_vphone_krw.LabError):
                    cnd_vphone_krw.canonical_kernel_address(invalid)

    def test_debugger_capture_refuses_missing_detach(self) -> None:
        report = b"""Kernel UUID: 03A93373-6498-3F25-8975-04DED251AF1F
Load Address: 0xfffffe0041ac4000
"""
        completed = mock.Mock(stdout=report, stderr=b"")
        with mock.patch.object(cnd_vphone_krw, "run", return_value=completed):
            with self.assertRaises(cnd_vphone_krw.LabError):
                cnd_vphone_krw.debugger_kernel_address(62139)

    def test_debugger_capture_refuses_ambiguous_addresses(self) -> None:
        report = b"""Kernel UUID: 03A93373-6498-3F25-8975-04DED251AF1F
Load Address: 0xfffffe0041ac4000
Load Address: 0xfffffe0041acc000
Process 1 detached
"""
        completed = mock.Mock(stdout=report, stderr=b"")
        with mock.patch.object(cnd_vphone_krw, "run", return_value=completed):
            with self.assertRaises(cnd_vphone_krw.LabError):
                cnd_vphone_krw.debugger_kernel_address(62139)

    def test_live_kcall_smoke_uses_only_verified_executable_return_stubs(self) -> None:
        self.assertIn('strcmp(argv[3], "--kcall-smoke-only") == 0',
                      self.probe)
        self.assertIn('strcmp(name, "com.apple.kernel") == 0', self.probe)
        self.assertIn('strncmp(segment->segname, "__TEXT_EXEC", 16)',
                      self.probe)
        self.assertIn("0xaa0003e0U", self.probe)
        self.assertIn("0x52800000U", self.probe)
        self.assertIn("second == return_x30", self.probe)
        self.assertIn("*observed != expected", self.probe)
        self.assertIn("run_kcall_smoke(ssh, probe_remote, socket_path)",
                      self.harness)


if __name__ == "__main__":
    unittest.main()
