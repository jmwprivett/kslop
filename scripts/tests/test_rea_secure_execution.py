"""Offline checks for the exact-artifact REA secure-execution interface."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/lab"))

import cnd_rea_secure_execution as secure  # noqa: E402
import cnd_sptm_pac_probe as pac_probe  # noqa: E402
import cnd_thread_state_pac_oracle as thread_oracle  # noqa: E402


def macho(uuid: str, text: int = 0xFFFFFE0007008000) -> dict:
    return {
        "header": {"cpu": "AARCH64", "subcpu": "ARM64e"},
        "loads": [
            {"load_cmd": "LC_SEGMENT_64", "name": "__TEXT", "addr": text},
            {"load_cmd": "LC_UUID", "uuid": uuid},
            {"load_cmd": "LC_SOURCE_VERSION", "version": "1.2.3.0.0"},
        ],
    }


class SecureExecutionInterfaceTests(unittest.TestCase):
    def observation_fixture(self) -> tuple[dict, dict, dict]:
        profile_path = (
            ROOT / "scripts/lab/profiles" /
            "rea-secure-execution-23A341-iphone17,3-trustcache.json"
        )
        profile = secure.load_observation_profile(profile_path)
        identity = profile["identity"]
        bundle = {
            "build": identity["build"],
            "product": identity["product"],
            "artifacts": {
                "kernel": {
                    "sha256": identity["kernel_sha256"],
                    "macho": {
                        "uuid": identity["kernel_uuid"],
                        "text_address": "0xfffffe0007008000",
                    },
                },
                "txm": {"sha256": identity["txm_sha256"]},
                "sptm": {"sha256": identity["sptm_sha256"]},
            },
        }
        runtime = {
            "kernel_debug_port": 62139,
            "kernel_uuid": identity["kernel_uuid"],
            "slide": "0x30c10000",
            "verified": True,
        }
        return bundle, profile, runtime

    def test_byte_assertions_bind_runtime_patch_state(self) -> None:
        assertion = secure.parse_byte_assertion("0x2=0080d2")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "txm"
            path.write_bytes(bytes.fromhex("ffff0080d2ffff"))
            secure.verify_byte_assertions(path, [assertion])
            path.write_bytes(bytes.fromhex("ffff0180d2ffff"))
            with self.assertRaisesRegex(secure.LabError, "assertion failed"):
                secure.verify_byte_assertions(path, [assertion])

    def test_byte_assertion_parser_rejects_odd_hex(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            secure.parse_byte_assertion("0x20=abc")

    def test_live_assertions_translate_by_slide_and_read_exact_bytes(self) -> None:
        binding = {"slide": "0x30c10000"}
        assertion = secure.parse_live_assertion(
            "0xfffffe0008637880=200080d2420000b4"
        )
        with mock.patch.object(
            secure, "debugger_kernel_bytes",
            return_value=bytes.fromhex(assertion["bytes_hex"]),
        ) as read:
            result = secure.verify_live_assertions(binding, 62139, [assertion])
        read.assert_called_once_with(62139, "0xfffffe0039247880", 8)
        self.assertTrue(result[0]["verified"])

    def test_live_assertions_fail_closed_on_different_bytes(self) -> None:
        assertion = secure.parse_live_assertion("0xfffffe0008637880=200080d2")
        with mock.patch.object(
            secure, "debugger_kernel_bytes", return_value=b"\x00" * 4,
        ):
            with self.assertRaisesRegex(secure.LabError, "live kernel assertion"):
                secure.verify_live_assertions(
                    {"slide": "0x30c10000"}, 62139, [assertion],
                )

    def test_kernel_identity_selects_inner_fileset_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "kernel"
            target.write_bytes(b"kernel")
            with mock.patch.object(secure, "command_json", return_value=macho("A" * 36)) as call:
                identity = secure.macho_identity(target, Path("/opt/ipsw"), "com.apple.kernel")
        self.assertEqual(identity["uuid"], "A" * 36)
        self.assertEqual(identity["text_address"], "0xfffffe0007008000")
        self.assertIn("--fileset-entry", call.call_args.args[0])
        self.assertIn("com.apple.kernel", call.call_args.args[0])

    def test_runtime_binding_requires_exact_live_uuid_and_computes_slide(self) -> None:
        kernel = {"macho": {
            "uuid": "03A93373-6498-3F25-8975-04DED251AF1F",
            "text_address": "0xfffffe0007008000",
        }}
        with mock.patch.object(
            secure, "debugger_kernel_address",
            return_value=("0xfffffe0037c18000", kernel["macho"]["uuid"]),
        ):
            result = secure.runtime_binding(kernel, 62139)
        self.assertTrue(result["verified"])
        self.assertEqual(result["slide"], "0x30c10000")

    def test_runtime_binding_refuses_a_different_kernel(self) -> None:
        kernel = {"macho": {"uuid": "A" * 36, "text_address": "0xfffffe0007008000"}}
        with mock.patch.object(
            secure, "debugger_kernel_address",
            return_value=("0xfffffe0037c18000", "B" * 36),
        ):
            with self.assertRaisesRegex(secure.LabError, "does not match"):
                secure.runtime_binding(kernel, 62139)

    def test_verify_rejects_artifact_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifacts = {}
            for role in secure.TARGETS:
                path = Path(directory) / role
                path.write_bytes(role.encode())
                artifacts[role] = {
                    "path": str(path), "sha256": secure.sha256(path),
                    "size": path.stat().st_size,
                    "macho": {"uuid": "A" * 36, "text_address": "0xfffffe0007008000"},
                    "rea_snapshot": {"path": str(path) + ".json", "present": False},
                    "byte_assertions": [],
                }
            bundle = {"artifacts": artifacts}
            Path(artifacts["txm"]["path"]).write_bytes(b"changed")
            with self.assertRaisesRegex(secure.LabError, "txm artifact"):
                secure.verify_bundle(bundle, None)

    def test_rea_plan_is_typed_argv_without_shell_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rea"
            (root / "scripts").mkdir(parents=True)
            (root / "scripts/rea.mjs").write_text("", encoding="utf-8")
            ghidra = Path(directory) / "ghidra"
            ghidra.mkdir()
            bundle = {
                "artifacts": {
                    role: {
                        "path": f"/{role}",
                        "rea_snapshot": {"path": f"/{role}.json"},
                    } for role in secure.TARGETS
                },
                "analysis": {"queries": [
                    {"id": "txm-search", "artifact": "txm", "operation": "search",
                     "kind": "strings", "mode": "regex", "pattern": "trust.?cache"},
                ]},
            }
            plan = secure.rea_plan(bundle, root, ghidra)
        operation = plan["operations"][0]
        self.assertIsInstance(operation["argv"], list)
        self.assertEqual(operation["argv"][2:5], ["search", "/txm", "--pattern=trust.?cache"])
        self.assertIn("/txm-search-rea-snapshot.json", operation["argv"])
        self.assertNotIn("shell", operation)
        self.assertEqual(
            operation["environment"]["REA_GHIDRA_STARTUP_TIMEOUT_MS"],
            "1200000",
        )

    def test_observation_plan_binds_rea_addresses_to_exact_live_kernel(self) -> None:
        bundle, profile, runtime = self.observation_fixture()
        plan = secure.observation_plan(bundle, profile, runtime)
        self.assertEqual(
            plan["breakpoints"][0]["live_address"],
            "0xfffffe0039242afc",
        )
        dispatch = plan["breakpoints"][3]
        self.assertEqual(dispatch["condition"], "$w0 == 12")
        self.assertEqual(dispatch["capture"]["memory"][0]["count"], 7)
        self.assertFalse(plan["limits"]["persistent_mutation"])
        self.assertEqual(plan["reconciliation"]["txm_dispatch_case"], 12)

    def test_observation_plan_refuses_cross_build_profile(self) -> None:
        bundle, profile, runtime = self.observation_fixture()
        bundle["build"] = "23A999"
        with self.assertRaisesRegex(secure.LabError, "build.*exact bundle"):
            secure.observation_plan(bundle, profile, runtime)

    def test_observation_plan_refuses_cross_sptm_profile(self) -> None:
        bundle, profile, runtime = self.observation_fixture()
        bundle["artifacts"]["sptm"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(secure.LabError, "sptm_sha256.*exact bundle"):
            secure.observation_plan(bundle, profile, runtime)

    def test_observation_plan_rejects_unbounded_capture(self) -> None:
        bundle, profile, runtime = self.observation_fixture()
        profile = json.loads(json.dumps(profile))
        profile["points"][0]["capture"]["memory"][0]["count"] = 65
        with self.assertRaisesRegex(secure.LabError, "bounded limits"):
            secure.observation_plan(bundle, profile, runtime)

    def test_observation_plan_requires_current_verified_uuid(self) -> None:
        bundle, profile, runtime = self.observation_fixture()
        runtime["kernel_uuid"] = "A" * 36
        with self.assertRaisesRegex(secure.LabError, "verified exact live kernel"):
            secure.observation_plan(bundle, profile, runtime)

    def test_targeted_rea_plan_emits_exact_typed_operations(self) -> None:
        bundle, profile, _ = self.observation_fixture()
        profile = json.loads(json.dumps(profile))
        profile["analysis_targets"] = profile["analysis_targets"][:2]
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            rea_root = directory_path / "rea"
            (rea_root / "scripts").mkdir(parents=True)
            (rea_root / "scripts/rea.mjs").write_text("", encoding="utf-8")
            ghidra = directory_path / "ghidra"
            ghidra.mkdir()
            snapshots = directory_path / "snapshots"
            snapshots.mkdir()
            for role in secure.TARGETS:
                artifact = directory_path / role
                artifact.write_bytes(role.encode())
                bundle["artifacts"][role]["path"] = str(artifact)
                bundle["artifacts"][role]["rea_snapshot"] = {
                    "path": str(snapshots / f"{role}.json")
                }
            plan = secure.targeted_rea_plan(
                bundle, profile, rea_root, ghidra,
            )
        self.assertEqual(plan["schema"], secure.RESEARCH_PLAN_SCHEMA)
        self.assertEqual(len(plan["operations"]), 2)
        operation = plan["operations"][1]
        self.assertEqual(operation["operation"], "function")
        self.assertEqual(
            operation["argv"][2:5],
            ["function", str(Path(bundle["artifacts"]["kernel"]["path"]).resolve()),
             "0xfffffe00082f3788"],
        )
        self.assertTrue(any(
            value.endswith("/kernel-sptm-sign-stub-rea-snapshot.json")
            for value in operation["argv"]
        ))
        self.assertNotIn("shell", operation)
        self.assertEqual(plan["sptm_services"][0]["selector"], 16)

    def test_targeted_rea_plan_accepts_only_hash_bound_artifact_variant(
            self) -> None:
        bundle, profile, _ = self.observation_fixture()
        profile = json.loads(json.dumps(profile))
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            rea_root = directory_path / "rea"
            (rea_root / "scripts").mkdir(parents=True)
            (rea_root / "scripts/rea.mjs").write_text("", encoding="utf-8")
            ghidra = directory_path / "ghidra"
            ghidra.mkdir()
            snapshots = directory_path / "snapshots"
            filesets = snapshots / "kernel-filesets"
            filesets.mkdir(parents=True)
            variant = filesets / "com.apple.kernel"
            variant.write_bytes(b"exact extracted kernel")
            for role in secure.TARGETS:
                artifact = directory_path / role
                artifact.write_bytes(role.encode())
                bundle["artifacts"][role]["path"] = str(artifact)
                bundle["artifacts"][role]["rea_snapshot"] = {
                    "path": str(snapshots / f"{role}.json")
                }
            profile["analysis_targets"] = [{
                "id": "kernel_consumer",
                "artifact": "kernel",
                "artifact_file": "kernel-filesets/com.apple.kernel",
                "artifact_sha256": secure.sha256(variant),
                "operation": "function",
                "address": "0xfffffe0007c5de48",
            }]
            plan = secure.targeted_rea_plan(
                bundle, profile, rea_root, ghidra,
            )
            self.assertEqual(
                plan["operations"][0]["argv"][3], str(variant.resolve()))
            self.assertEqual(
                plan["operations"][0]["artifact_sha256"],
                secure.sha256(variant),
            )
            profile["analysis_targets"][0]["artifact_sha256"] = "0" * 64
            with self.assertRaisesRegex(secure.LabError, "exact binding"):
                secure.targeted_rea_plan(
                    bundle, profile, rea_root, ghidra,
                )

    def test_targeted_rea_plan_rejects_malformed_target(self) -> None:
        bundle, profile, _ = self.observation_fixture()
        profile = json.loads(json.dumps(profile))
        profile["analysis_targets"] = [{
            "id": "bad", "artifact": "sptm", "operation": "function",
            "address": "0x1234",
        }]
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            rea_root = directory_path / "rea"
            (rea_root / "scripts").mkdir(parents=True)
            (rea_root / "scripts/rea.mjs").write_text("", encoding="utf-8")
            ghidra = directory_path / "ghidra"
            ghidra.mkdir()
            snapshots = directory_path / "snapshots"
            snapshots.mkdir()
            for role in secure.TARGETS:
                artifact = directory_path / role
                artifact.write_bytes(role.encode())
                bundle["artifacts"][role]["path"] = str(artifact)
                bundle["artifacts"][role]["rea_snapshot"] = {
                    "path": str(snapshots / f"{role}.json")
                }
            with self.assertRaisesRegex(secure.LabError, "not canonical"):
                secure.targeted_rea_plan(bundle, profile, rea_root, ghidra)

    def test_load_bundle_rejects_unversioned_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.json"
            path.write_text(json.dumps({"schema": secure.SCHEMA}), encoding="utf-8")
            with self.assertRaisesRegex(secure.LabError, "unsupported"):
                secure.load_bundle(path)

    def test_pac_probe_validation_binds_fileset_and_service_stubs(self) -> None:
        bundle, profile, runtime = self.observation_fixture()
        runtime["load_address"] = "0xfffffe00481d4000"
        runtime["slide"] = "0x411cc000"
        value = {
            "schema": "com.zeroxjf.cyanide.sptm-pac-probe",
            "schema_version": 1,
            "persistent_mutation": False,
            "kernel_base": "0xfffffe00481d0000",
            "slide": "0x411cc000",
            "sign_stub": "0xfffffe00494bf788",
            "auth_stub": "0xfffffe00494bf7a0",
            "pointer": "0x0000000100000000",
            "discriminator": "0x0000000000434e44",
            "key_0_signed": "0xb302800100000000",
            "key_0_authenticated": "0x0000000100000000",
            "wrong_discriminator_result": "0xffffffffffffffff",
            "key_2_signed": "0x0005000100000000",
            "key_2_authenticated": "0x0000000100000000",
            "pmap_sign_wrapper": "0xfffffe0048e0d8fc",
            "pmap_auth_wrapper": "0xfffffe0048e0dc08",
            "explicit_jop_key_a": "0x434e440100000001",
            "explicit_jop_key_a_signed": "0x3b30000100000000",
            "explicit_jop_key_a_authenticated": "0x0000000100000000",
            "explicit_jop_key_b": "0x434e440200000001",
            "explicit_jop_key_b_signed": "0x9e5f000100000000",
            "key_a_signature_auth_with_key_b": "0x3b30000100000000",
        }
        self.assertEqual(
            pac_probe.expected_provider_base(bundle, profile, runtime),
            0xfffffe00481d0000,
        )
        self.assertIs(
            pac_probe.validate_probe_result(value, bundle, profile, runtime),
            value,
        )

    def test_pac_probe_validation_rejects_wrong_discriminator_success(self) -> None:
        bundle, profile, runtime = self.observation_fixture()
        runtime["load_address"] = "0xfffffe00481d4000"
        runtime["slide"] = "0x411cc000"
        value = {
            "schema": "com.zeroxjf.cyanide.sptm-pac-probe",
            "schema_version": 1,
            "persistent_mutation": False,
            "kernel_base": "0xfffffe00481d0000",
            "slide": "0x411cc000",
            "sign_stub": "0xfffffe00494bf788",
            "auth_stub": "0xfffffe00494bf7a0",
            "pointer": "0x0000000100000000",
            "discriminator": "0x0000000000434e44",
            "key_0_signed": "0xb302800100000000",
            "key_0_authenticated": "0x0000000100000000",
            "wrong_discriminator_result": "0x0000000100000000",
            "key_2_signed": "0x0005000100000000",
            "key_2_authenticated": "0x0000000100000000",
            "pmap_sign_wrapper": "0xfffffe0048e0d8fc",
            "pmap_auth_wrapper": "0xfffffe0048e0dc08",
            "explicit_jop_key_a": "0x434e440100000001",
            "explicit_jop_key_a_signed": "0x3b30000100000000",
            "explicit_jop_key_a_authenticated": "0x0000000100000000",
            "explicit_jop_key_b": "0x434e440200000001",
            "explicit_jop_key_b_signed": "0x9e5f000100000000",
            "key_a_signature_auth_with_key_b": "0x3b30000100000000",
        }
        with self.assertRaisesRegex(secure.LabError, "invariants failed"):
            pac_probe.validate_probe_result(value, bundle, profile, runtime)

    def test_thread_state_consumer_validation_requires_exact_match(self) -> None:
        value = {
            "schema": "com.zeroxjf.cyanide.sptm-pac-process-probe",
            "schema_version": 1,
            "mode": "thread-state",
            "persistent_mutation": False,
            "thread_state_flags": "0x0000000c",
            "thread_state_signed_pc": "0x1234000100004000",
            "thread_state_raw_pc": "0x0000000100004000",
            "thread_state_api_authenticated_pc": "0x0000000100004000",
            "worker_start": "0x0000000100003f00",
            "kernel_thread": "0xfffffe1000010000",
            "current_thread_stub": "0xfffffe0048e22714",
            "pc_discriminator": "0x0000000000007481",
            "sptm_signed_pc": "0x1234000100004000",
            "sptm_authenticated_pc": "0x0000000100004000",
            "raw_selector_matches_thread_state": True,
        }
        self.assertIs(pac_probe.validate_thread_state_result(value), value)
        value["thread_state_api_authenticated_pc"] = "0x0000000100005000"
        with self.assertRaisesRegex(
            secure.LabError, "thread-state PAC consumer invariants",
        ):
            pac_probe.validate_thread_state_result(value)

    def test_target_context_validation_binds_consumer_and_pmap(self) -> None:
        thread_state = {
            "kernel_thread": "0xfffffe1000010000",
            "thread_state_signed_pc": "0x1234000100004000",
            "thread_state_raw_pc": "0x0000000100004000",
            "current_thread_stub": "0xfffffe0048e22714",
            "pc_discriminator": "0x0000000000007481",
        }
        probe = {
            "slide": "0x411cc000",
            "pmap_sign_wrapper": "0xfffffe0048e0d8fc",
            "pmap_auth_wrapper": "0xfffffe0048e0dc08",
        }
        profile = {
            "thread_state_consumer": {
                "current_thread_accessor": "0xfffffe0007c56714",
                "machine_jop_pid_offset": 0x1b0,
                "pc_discriminator": "0x0000000000007481",
            },
        }
        value = {
            "schema": "com.zeroxjf.cyanide.sptm-pac-target-context-probe",
            "schema_version": 1,
            "persistent_mutation": False,
            "kernel_thread": "0xfffffe1000010000",
            "thread_jop_pid_offset": "0x00000000000001b0",
            "jop_pid": "0x434e440100000001",
            "raw_pc": "0x0000000100004000",
            "expected_signed_pc": "0x1234000100004000",
            "context_signed_pc": "0x1234000100004000",
            "context_authenticated_pc": "0x0000000100004000",
            "current_thread_stub": "0xfffffe0048e22714",
            "pmap_sign_wrapper": "0xfffffe0048e0d8fc",
            "pmap_auth_wrapper": "0xfffffe0048e0dc08",
            "exact_match": True,
        }
        self.assertIs(
            pac_probe.validate_target_context_result(
                value, thread_state, probe, profile),
            value,
        )
        value["context_signed_pc"] = "0x5678000100004000"
        with self.assertRaisesRegex(
            secure.LabError, "equivalence invariants failed",
        ):
            pac_probe.validate_target_context_result(
                value, thread_state, probe, profile)

    def test_lab_pac_integration_binds_profile_and_live_consumer(self) -> None:
        marker = {
            "kernel_thread": "0xfffffe1000010000",
            "signed_pc": "0x1234000100004000",
            "raw_pc": "0x0000000100004000",
        }
        probe = {
            "pmap_sign_wrapper": "0xfffffe0048e0d8fc",
            "pmap_auth_wrapper": "0xfffffe0048e0dc08",
        }
        profile = {
            "identity": {
                "kernel_uuid": "03A93373-6498-3F25-8975-04DED251AF1F",
            },
            "thread_state_consumer": {
                "machine_jop_pid_offset": 0x1b0,
            },
        }
        value = {
            "schema": "com.zeroxjf.cyanide.lab-pac-integration-probe",
            "schema_version": 1,
            "persistent_mutation": False,
            "kernel_uuid": "03A93373-6498-3F25-8975-04DED251AF1F",
            "kernel_base": "0xfffffe00481d0000",
            "kernel_slide": "0x411cc000",
            "kernel_thread": marker["kernel_thread"],
            "thread_jop_pid_offset": "0x00000000000001b0",
            "jop_pid": "0x434e440100000001",
            "raw_pc": marker["raw_pc"],
            "expected_signed_pc": marker["signed_pc"],
            "pmap_sign_wrapper": probe["pmap_sign_wrapper"],
            "pmap_auth_wrapper": probe["pmap_auth_wrapper"],
            "exact_consumer_match": True,
        }
        self.assertIs(
            pac_probe.validate_integration_result(
                value, marker, 0xfffffe00481d0000, probe, profile),
            value,
        )
        value["kernel_uuid"] = "00000000-0000-0000-0000-000000000000"
        with self.assertRaisesRegex(
            secure.LabError, "does not match the exact consumer",
        ):
            pac_probe.validate_integration_result(
                value, marker, 0xfffffe00481d0000, probe, profile)

    def test_thread_state_oracle_probe_has_no_krw_or_kcall_dependency(self) -> None:
        source = (ROOT / "scripts/lab/cnd_thread_state_pac_oracle_probe.c").read_text()
        self.assertIn("THREAD_CONVERT_THREAD_STATE_FROM_SELF", source)
        self.assertIn("thread_convert_thread_state(", source)
        self.assertIn('ptrauth_string_discriminator("pc")', source)
        self.assertIn("CNDUserDiversifier", source)
        self.assertIn('"kernel_call_used\\\":false', source)
        self.assertIn('"krw_used\\\":false', source)
        self.assertNotIn("CNDLabKernelProvider", source)
        self.assertNotIn("CNDLabKRWOperationKernelCall", source)
        self.assertNotIn("svc #0x80", source)

    def test_cross_task_thread_state_probe_transfers_a_real_thread_port(self) -> None:
        source = (
            ROOT / "scripts/lab/cnd_thread_state_pac_cross_task_probe.c"
        ).read_text()
        self.assertIn("bootstrap_look_up", source)
        self.assertIn("MACH_MSG_PORT_DESCRIPTOR", source)
        self.assertIn("THREAD_CONVERT_THREAD_STATE_FROM_SELF", source)
        self.assertIn("target_process_authenticated_pc", source)
        self.assertIn('"kernel_call_used\\\":false', source)
        self.assertIn('"krw_used\\\":false', source)
        self.assertNotIn("CNDLabKernelProvider", source)
        self.assertNotIn("CNDLabKRWOperationKernelCall", source)

    def test_exception_identity_probe_converts_the_delivered_thread_right(self) -> None:
        source = (
            ROOT /
            "scripts/lab/cnd_thread_state_pac_exception_identity_probe.c"
        ).read_text()
        self.assertIn("EXCEPTION_STATE_IDENTITY", source)
        self.assertIn("request.thread.name", source)
        self.assertIn("THREAD_CONVERT_THREAD_STATE_FROM_SELF", source)
        self.assertIn("reply_identity_exception", source)
        self.assertIn('"kernel_call_used\\\":false', source)
        self.assertIn('"krw_used\\\":false', source)
        self.assertNotIn("CNDLabKernelProvider", source)
        self.assertNotIn("CNDLabKRWOperationKernelCall", source)

    def test_taskrop_exposes_fail_closed_thread_port_converter(self) -> None:
        header = (ROOT / "Cyanide/TaskRop/Thread.h").read_text()
        implementation = (ROOT / "Cyanide/TaskRop/Thread.m").read_text()
        self.assertIn("thread_convert_sign_state_for_target", header)
        start = implementation.index("thread_convert_sign_state_for_target")
        converter = implementation[start:]
        self.assertIn("THREAD_CONVERT_THREAD_STATE_FROM_SELF", converter)
        self.assertIn("output.__opaque_flags != input.__opaque_flags", converter)
        self.assertIn("CND_USER_POINTER_MASK", converter)
        self.assertNotIn("cnd_lab_kernel_call", converter)
        self.assertNotIn("cnd_lab_krw", converter)

    def test_thread_state_oracle_result_requires_no_kcall_exact_conversion(self) -> None:
        value = {
            "schema": "com.zeroxjf.cyanide.thread-state-pac-oracle-probe",
            "schema_version": 1,
            "persistent_mutation": False,
            "kernel_call_used": False,
            "krw_used": False,
            "same_task_target": True,
            "requires_thread_control_port": True,
            "direction_from_self": 2,
            "user_diversifier": "0x5a000000",
            "convert_kr": 0,
            "output_count": 68,
            "raw_pc": "0x0000000100004000",
            "raw_lr": "0x0000000100005000",
            "local_plain_signed_pc": "0x1111800100004000",
            "local_plain_signed_lr": "0x2222800100005000",
            "target_diversified_signed_pc": "0x3333800100004000",
            "target_diversified_signed_lr": "0x4444800100005000",
            "target_authenticated_pc": "0x0000000100004000",
            "target_authenticated_lr": "0x0000000100005000",
            "output_flags": "0x5a000000",
            "exception_reply_compatible_shape": True,
            "exact_target_context_conversion": True,
        }
        self.assertIs(thread_oracle.validate_result(value), value)
        value["kernel_call_used"] = True
        with self.assertRaisesRegex(secure.LabError, "invariants failed"):
            thread_oracle.validate_result(value)

    def test_cross_task_oracle_result_requires_child_authentication(self) -> None:
        value = {
            "schema": "com.zeroxjf.cyanide.thread-state-pac-cross-task-probe",
            "schema_version": 1,
            "persistent_mutation": False,
            "kernel_call_used": False,
            "krw_used": False,
            "cross_task_target": True,
            "thread_port_transferred": True,
            "requires_thread_control_port": True,
            "direction_from_self": 2,
            "user_diversifier": "0x5a000000",
            "convert_kr": 0,
            "output_count": 68,
            "raw_pc": "0x0000000100004000",
            "raw_lr": "0x0000000100005000",
            "local_plain_signed_pc": "0x1111800100004000",
            "local_plain_signed_lr": "0x2222800100005000",
            "target_diversified_signed_pc": "0x3333800100004000",
            "target_diversified_signed_lr": "0x4444800100005000",
            "target_process_authenticated_pc": "0x0000000100004000",
            "target_process_authenticated_lr": "0x0000000100005000",
            "output_flags": "0x5a000000",
            "exact_cross_task_conversion": True,
        }
        self.assertIs(thread_oracle.validate_cross_task_result(value), value)
        value["target_process_authenticated_pc"] = "0x0000000100006000"
        with self.assertRaisesRegex(
            secure.LabError, "did not preserve PC/LR",
        ):
            thread_oracle.validate_cross_task_result(value)

    def test_identity_oracle_result_requires_a_successful_resume(self) -> None:
        value = {
            "schema": (
                "com.zeroxjf.cyanide."
                "thread-state-pac-exception-identity-probe"
            ),
            "schema_version": 1,
            "persistent_mutation": False,
            "kernel_call_used": False,
            "krw_used": False,
            "exception_state_identity": True,
            "mach_exception_codes": True,
            "identity_message_received": True,
            "thread_port_received": True,
            "task_port_received": True,
            "direction_from_self": 2,
            "receive_kr": 0,
            "message_id": 2407,
            "message_size": 364,
            "descriptor_count": 2,
            "thread_descriptor_type": 0,
            "task_descriptor_type": 0,
            "flavor": 6,
            "old_state_count": 68,
            "convert_kr": 0,
            "reply_kr": 0,
            "output_count": 68,
            "output_flags": "0x1e000000",
            "raw_resume_pc": "0x0000000100004000",
            "raw_fallback_lr": "0x0000000100005000",
            "converted_pc": "0x3333800100004000",
            "converted_lr": "0x4444800100005000",
            "child_resumed": True,
            "exact_exception_identity_conversion": True,
        }
        self.assertIs(thread_oracle.validate_identity_result(value), value)
        value["child_resumed"] = False
        with self.assertRaisesRegex(secure.LabError, "invariants failed"):
            thread_oracle.validate_identity_result(value)


if __name__ == "__main__":
    unittest.main()
