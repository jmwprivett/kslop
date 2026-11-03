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
        cls.pac_header = (
            ROOT / "Cyanide/kexploit/CNDLabKernelPAC.h"
        ).read_text()
        cls.pac_provider = (
            ROOT / "Cyanide/kexploit/CNDLabKernelPAC.m"
        ).read_text()
        cls.taskrop_pac = (ROOT / "Cyanide/TaskRop/PAC.m").read_text()
        cls.offsets = (ROOT / "Cyanide/kexploit/offsets.m").read_text()
        cls.pac_integration_probe = (
            ROOT / "scripts/lab/cnd_lab_pac_integration_probe.c"
        ).read_text()
        cls.bridge = (ROOT / "Cyanide/TaskRop/CNDKernelTaskBridge.m").read_text()
        cls.server = (ROOT / "scripts/lab/cnd_provide_tfp0.c").read_text()
        cls.harness = (ROOT / "scripts/lab/cnd_vphone_krw.py").read_text()
        cls.probe = (ROOT / "scripts/lab/cnd_lab_krw_probe.c").read_text()
        cls.signer_caller_probe = (
            ROOT / "scripts/lab/cnd_thread_state_signer_caller_probe.c"
        ).read_text()
        cls.signer_caller_harness = (
            ROOT / "scripts/lab/cnd_thread_state_signer_caller_probe.py"
        ).read_text()
        cls.signer_caller_entitlements = (
            ROOT / "scripts/lab/cnd_thread_state_signer_caller.entitlements"
        ).read_text()
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

    def test_thread_state_signer_canary_is_exact_and_disposable(self) -> None:
        for required in (
            "--thread-state-signer-only",
            "static_signer = 0xfffffe0007ab9344ULL",
            "static_validator = 0xfffffe0007ab9394ULL",
            "static_after_check = 0xfffffe0007ab81e4ULL",
            "static_kalloc = 0xfffffe0007b0acacULL",
            "static_kfree = 0xfffffe0007b0b46cULL",
            'fd, "ml_sign_thread_state", signer, signer_words',
            "binds_state_address",
            "binds_mode_and_control_state",
            "validator_invoked\\\":false",
            "persistent_mutation\\\":false",
        ):
            self.assertIn(required, self.probe)
        self.assertIn("run_thread_state_signer_canary", self.harness)
        self.assertIn('"signer-canary"', self.harness)

    def test_thread_state_pac_discovery_is_not_bad_recovery_gated(self) -> None:
        xpf = (ROOT / "Cyanide/XPF/src/xpf.c").read_text()
        recovery = (ROOT / "Cyanide/XPF/src/bad_recovery.c").read_text()
        self.assertIn('.name="threadStatePAC"', xpf)
        self.assertIn("kernelSymbol.ml_check_signed_state", xpf)
        pac_registration = recovery.index(
            "if (xpf_thread_state_pac_supported())"
        )
        old_gate = recovery.index(
            "if (gXPF.kernelIsArm64e && xpf_bad_recovery_supported())",
            pac_registration,
        )
        self.assertLess(pac_registration, old_gate)
        self.assertIn("xnu12377Inst", recovery)

    def test_standalone_signer_canary_does_not_require_a_live_app(self) -> None:
        action = self.harness.index(
            'if args.action == "standalone-signer-canary":'
        )
        app_lookup = self.harness.index(
            "app_pid, app_home, socket_path = current_cyanide(", action
        )
        standalone = self.harness[action:app_lookup]
        self.assertIn("STANDALONE_SIGNER_SOCKET_PATH", standalone)
        self.assertIn("start_provider(", standalone)
        self.assertIn("run_thread_state_signer_canary(", standalone)
        self.assertIn("finally:", standalone)
        self.assertIn("stop_exact_provider(", standalone)

    def test_standalone_provider_does_not_require_a_live_app(self) -> None:
        action = self.harness.index(
            'if args.action == "standalone-enable":'
        )
        app_lookup = self.harness.index(
            "app_pid, app_home, socket_path = current_cyanide(", action
        )
        standalone = self.harness[action:app_lookup]
        self.assertIn("STANDALONE_KRW_SOCKET_PATH", standalone)
        self.assertIn("start_provider(", standalone)
        self.assertNotIn("current_cyanide(", standalone)

    def test_lab_app_bundle_selector_is_exact_and_defaults_to_production(self) -> None:
        class FakeSSH:
            def command(self, command: str) -> str:
                self.command_text = command
                return (
                    "410 /private/var/containers/Bundle/Application/AAAA/"
                    "Cyanide.app/Cyanide XPC_SERVICE_NAME=UIKitApplication:"
                    "com.zeroxjf.ios-cyanide1.labthreadcall[410] "
                    "CFFIXED_USER_HOME=/private/var/mobile/Containers/Data/"
                    "Application/01234567-89AB-CDEF-0123-456789ABCDEF\n"
                )

        pid, home, socket_path = cnd_vphone_krw.current_cyanide(
            FakeSSH(), "com.zeroxjf.ios-cyanide1.labthreadcall")
        self.assertEqual(pid, 410)
        self.assertEqual(
            home,
            "/private/var/mobile/Containers/Data/Application/"
            "01234567-89AB-CDEF-0123-456789ABCDEF",
        )
        self.assertEqual(
            socket_path,
            "/var/mobile/Containers/Data/Application/"
            "01234567-89AB-CDEF-0123-456789ABCDEF/tmp/"
            "cyanide-lab-krw.sock",
        )
        self.assertEqual(
            cnd_vphone_krw.DEFAULT_APP_BUNDLE_ID,
            "com.zeroxjf.ios-cyanide1",
        )

    def test_lab_app_bundle_selector_rejects_shell_syntax(self) -> None:
        with self.assertRaises(cnd_vphone_krw.LabError):
            cnd_vphone_krw.current_cyanide(
                mock.Mock(), "com.example.bad;touch-/var/tmp/nope")

    def test_normal_signer_caller_probe_is_suspended_and_fail_closed(self) -> None:
        for required in (
            "target_thread_suspended\\\":true",
            "target_thread_resumed_only_after_restore\\\":%s",
            "test_state_executed\\\":false",
            "kernel_call_used\\\":false",
            "krw_used\\\":false",
            "persistent_mutation\\\":false",
            "arbitrary_el1_state_signed\\\":false",
            "thread_suspend(",
            "thread_convert_thread_state(",
            "thread_set_state(",
            "thread_get_state(",
            "thread_resume(",
            "restore_after_kernel",
            "final_restore",
        ):
            self.assertIn(required, self.signer_caller_probe)
        self.assertIn(
            'EXPECTED_KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"',
            self.signer_caller_harness,
        )
        self.assertIn(
            "STATIC_EXCEPTION_RETURN_AFTER_CHECK = 0xfffffe0007ab81e4",
            self.signer_caller_harness,
        )
        self.assertIn(
            "com.apple.private.thread-set-state",
            self.signer_caller_entitlements,
        )
        self.assertIn(
            "entitlements=PROBE_ENTITLEMENTS",
            self.signer_caller_harness,
        )

    def test_vm_pac_profile_is_exact_identity_and_stub_gated(self) -> None:
        self.assertIn(
            '"03A93373-6498-3F25-8975-04DED251AF1F"',
            self.pac_header,
        )
        for required in (
            "MH_FILESET",
            "LC_FILESET_ENTRY",
            'strcmp(name, "com.apple.kernel") == 0',
            "LC_UUID",
            "CNDExpectedKernelUUID",
            "CNDExpectedSignStub",
            "CNDExpectedAuthStub",
            "CNDExpectedCurrentThread",
            "cnd_lab_pac_verify_words",
        ):
            self.assertIn(required, self.pac_provider)
        self.assertIn("off_thread_machine_jop_pid = 0x1c0", self.offsets)
        self.assertNotIn("off_thread_machine_jop_pid = 0x1b0", self.offsets)

    def test_vm_pac_adapter_uses_target_context_and_exact_consumer_test(self) -> None:
        self.assertIn(
            "CNDThreadMachineJopPIDOffset = 0x1b0ULL",
            self.pac_provider,
        )
        self.assertIn("cnd_lab_pac_thread_jop_pid", self.pac_provider)
        self.assertIn("profile.pmap_sign_user_ptr", self.pac_provider)
        self.assertIn("profile.pmap_auth_user_ptr", self.pac_provider)
        self.assertIn("CNDLabPACKeyInstructionA", self.pac_provider)
        self.assertIn("CNDLabPACKeyDataA", self.pac_provider)
        self.assertIn(
            "signed_pointer != expected_signed_pointer",
            self.pac_provider,
        )
        self.assertIn(
            "authenticated_pointer == raw_pointer",
            self.pac_provider,
        )

    def test_taskrop_prefers_vm_pmap_pac_without_changing_physical_path(self) -> None:
        route = self.taskrop_pac.index("cnd_lab_pac_sign_user_pointer(")
        legacy = self.taskrop_pac.index("if(!g_RC_gadgetPacia)", route)
        self.assertLess(route, legacy)
        self.assertIn("cnd_lab_krw_ready()", self.taskrop_pac)
        self.assertIn("cnd_lab_kernel_call_active()", self.taskrop_pac)
        self.assertIn("return UINT64_MAX;", self.taskrop_pac[route:legacy])

    def test_live_integration_probe_links_the_app_adapter(self) -> None:
        self.assertIn("extra_sources: tuple[Path, ...]", self.harness)
        self.assertIn("cnd_lab_pac_profile(&profile)",
                      self.pac_integration_probe)
        self.assertIn("cnd_lab_pac_consumer_self_test(",
                      self.pac_integration_probe)
        self.assertIn("exact_consumer_match\\\":true",
                      self.pac_integration_probe)

    def test_kernel_primitives_require_kernel_capability(self) -> None:
        # read, write, and the termination quiesce path all route through the
        # lab kernel provider when it is active.
        self.assertEqual(
            self.exploit.count("if (cnd_lab_kernel_rw_active())"), 3
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
        self.assertIn('architecture: str = "arm64"', self.harness)
        self.assertIn('"-arch", architecture', self.harness)
        self.assertIn('architecture not in {"arm64", "arm64e"}', self.harness)
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

    def test_debugger_capture_retries_a_detached_identity_free_handshake(self) -> None:
        empty = mock.Mock(stdout=b"Process 1 detached\n", stderr=b"")
        complete = mock.Mock(
            stdout=(
                b"Kernel UUID: 03A93373-6498-3F25-8975-04DED251AF1F\n"
                b"Load Address: 0xfffffe0041ac4000\n"
                b"Process 1 detached\n"
            ),
            stderr=b"",
        )
        with mock.patch.object(
            cnd_vphone_krw, "run", side_effect=(empty, complete)
        ) as run_mock, mock.patch.object(cnd_vphone_krw.time, "sleep"):
            address, uuid = cnd_vphone_krw.debugger_kernel_address(62139)
        self.assertEqual(address, "0xfffffe0041ac4000")
        self.assertEqual(uuid, "03A93373-6498-3F25-8975-04DED251AF1F")
        self.assertEqual(run_mock.call_count, 2)

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
