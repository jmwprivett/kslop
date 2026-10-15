#!/usr/bin/env python3
"""Run the no-kcall arm64e thread-state PAC context-conversion probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Any

from cnd_remotecall_lab import LabError, SSH, require_vphone
from cnd_rea_secure_execution import write_json
from cnd_vphone_krw import build_binary


REPO_ROOT = Path(__file__).resolve().parents[2]
PROBE_SOURCE = REPO_ROOT / "scripts/lab/cnd_thread_state_pac_oracle_probe.c"
CROSS_TASK_PROBE_SOURCE = (
    REPO_ROOT / "scripts/lab/cnd_thread_state_pac_cross_task_probe.c"
)
IDENTITY_PROBE_SOURCE = (
    REPO_ROOT / "scripts/lab/cnd_thread_state_pac_exception_identity_probe.c"
)
DEFAULT_KNOWN_HOSTS = Path.home() / ".ssh/known_hosts"
USER_POINTER_MASK = 0x0000007FFFFFFFFF


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hex_value(value: Any, name: str, digits: int) -> int:
    if not isinstance(value, str) or not re.fullmatch(
            rf"0x[0-9a-f]{{{digits}}}", value):
        raise LabError(f"thread-state PAC probe returned invalid {name}")
    return int(value, 16)


def validate_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != \
            "com.zeroxjf.cyanide.thread-state-pac-oracle-probe" or \
            value.get("schema_version") != 1:
        raise LabError("thread-state PAC probe returned an unsupported result")
    required_false = ("persistent_mutation", "kernel_call_used", "krw_used")
    if any(value.get(name) is not False for name in required_false) or \
            value.get("same_task_target") is not True or \
            value.get("requires_thread_control_port") is not True or \
            value.get("direction_from_self") != 2 or \
            value.get("convert_kr") != 0 or value.get("output_count") != 68 or \
            value.get("exception_reply_compatible_shape") is not True or \
            value.get("exact_target_context_conversion") is not True:
        raise LabError("thread-state PAC probe invariants failed")

    diversifier = hex_value(value.get("user_diversifier"), "diversifier", 8)
    flags = hex_value(value.get("output_flags"), "output flags", 8)
    raw_pc = hex_value(value.get("raw_pc"), "raw PC", 16)
    raw_lr = hex_value(value.get("raw_lr"), "raw LR", 16)
    local_pc = hex_value(
        value.get("local_plain_signed_pc"), "local signed PC", 16)
    local_lr = hex_value(
        value.get("local_plain_signed_lr"), "local signed LR", 16)
    target_pc = hex_value(
        value.get("target_diversified_signed_pc"), "target signed PC", 16)
    target_lr = hex_value(
        value.get("target_diversified_signed_lr"), "target signed LR", 16)
    authenticated_pc = hex_value(
        value.get("target_authenticated_pc"), "authenticated PC", 16)
    authenticated_lr = hex_value(
        value.get("target_authenticated_lr"), "authenticated LR", 16)
    if diversifier != 0x5A000000 or flags != diversifier or \
            not raw_pc or not raw_lr or local_pc == raw_pc or local_lr == raw_lr or \
            target_pc == raw_pc or target_lr == raw_lr or \
            target_pc & USER_POINTER_MASK != raw_pc or \
            target_lr & USER_POINTER_MASK != raw_lr or \
            authenticated_pc != raw_pc or authenticated_lr != raw_lr:
        raise LabError("thread-state PAC conversion did not preserve PC/LR")
    return value


def validate_cross_task_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != \
            "com.zeroxjf.cyanide.thread-state-pac-cross-task-probe" or \
            value.get("schema_version") != 1:
        raise LabError(
            "cross-task thread-state PAC probe returned an unsupported result"
        )
    required_false = ("persistent_mutation", "kernel_call_used", "krw_used")
    if any(value.get(name) is not False for name in required_false) or \
            value.get("cross_task_target") is not True or \
            value.get("thread_port_transferred") is not True or \
            value.get("requires_thread_control_port") is not True or \
            value.get("direction_from_self") != 2 or \
            value.get("convert_kr") != 0 or value.get("output_count") != 68 or \
            value.get("exact_cross_task_conversion") is not True:
        raise LabError("cross-task thread-state PAC probe invariants failed")

    diversifier = hex_value(value.get("user_diversifier"), "diversifier", 8)
    flags = hex_value(value.get("output_flags"), "output flags", 8)
    raw_pc = hex_value(value.get("raw_pc"), "raw PC", 16)
    raw_lr = hex_value(value.get("raw_lr"), "raw LR", 16)
    local_pc = hex_value(
        value.get("local_plain_signed_pc"), "local signed PC", 16)
    local_lr = hex_value(
        value.get("local_plain_signed_lr"), "local signed LR", 16)
    target_pc = hex_value(
        value.get("target_diversified_signed_pc"), "target signed PC", 16)
    target_lr = hex_value(
        value.get("target_diversified_signed_lr"), "target signed LR", 16)
    authenticated_pc = hex_value(
        value.get("target_process_authenticated_pc"), "authenticated PC", 16)
    authenticated_lr = hex_value(
        value.get("target_process_authenticated_lr"), "authenticated LR", 16)
    if diversifier != 0x5A000000 or flags != diversifier or \
            not raw_pc or not raw_lr or local_pc == raw_pc or local_lr == raw_lr or \
            target_pc == raw_pc or target_lr == raw_lr or \
            target_pc & USER_POINTER_MASK != raw_pc or \
            target_lr & USER_POINTER_MASK != raw_lr or \
            authenticated_pc != raw_pc or authenticated_lr != raw_lr:
        raise LabError(
            "cross-task thread-state PAC conversion did not preserve PC/LR"
        )
    return value


def validate_identity_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != \
            "com.zeroxjf.cyanide.thread-state-pac-exception-identity-probe" or \
            value.get("schema_version") != 1:
        raise LabError(
            "exception-identity PAC probe returned an unsupported result"
        )
    required_false = ("persistent_mutation", "kernel_call_used", "krw_used")
    if any(value.get(name) is not False for name in required_false) or \
            value.get("exception_state_identity") is not True or \
            value.get("mach_exception_codes") is not True or \
            value.get("identity_message_received") is not True or \
            value.get("thread_port_received") is not True or \
            value.get("task_port_received") is not True or \
            value.get("direction_from_self") != 2 or \
            value.get("receive_kr") != 0 or value.get("convert_kr") != 0 or \
            value.get("reply_kr") != 0 or value.get("output_count") != 68 or \
            value.get("message_id") != 2407 or \
            value.get("message_size") != 364 or \
            value.get("descriptor_count") != 2 or \
            value.get("thread_descriptor_type") != 0 or \
            value.get("task_descriptor_type") != 0 or \
            value.get("flavor") != 6 or value.get("old_state_count") != 68 or \
            value.get("child_resumed") is not True or \
            value.get("exact_exception_identity_conversion") is not True:
        raise LabError("exception-identity PAC probe invariants failed")

    flags = hex_value(value.get("output_flags"), "output flags", 8)
    raw_pc = hex_value(value.get("raw_resume_pc"), "raw resume PC", 16)
    raw_lr = hex_value(value.get("raw_fallback_lr"), "raw fallback LR", 16)
    converted_pc = hex_value(value.get("converted_pc"), "converted PC", 16)
    converted_lr = hex_value(value.get("converted_lr"), "converted LR", 16)
    if not flags or not raw_pc or not raw_lr or converted_pc == raw_pc or \
            converted_lr == raw_lr or \
            converted_pc & USER_POINTER_MASK != raw_pc or \
            converted_lr & USER_POINTER_MASK != raw_lr:
        raise LabError(
            "exception-identity PAC conversion did not preserve PC/LR"
        )
    return value


def run_probe(ssh: SSH, source: Path, name: str,
              remote_prefix: str) -> tuple[str, dict[str, Any]]:
    local = build_binary(source, name, architecture="arm64e")
    digest = sha256(local)
    remote = f"/var/tmp/{remote_prefix}-{digest[:16]}"
    ssh.copy(local, remote)
    command = (
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)} && "
        f"{shlex.quote(remote)}"
    )
    try:
        value = json.loads(ssh.command(command))
    except json.JSONDecodeError as error:
        raise LabError(f"{name} did not return JSON") from error
    return digest, value


def run_live(args: argparse.Namespace) -> dict[str, Any]:
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    same_digest, same_value = run_probe(
        ssh, PROBE_SOURCE, "cnd_thread_state_pac_oracle_probe",
        "cnd-thread-state-pac-oracle-probe",
    )
    cross_digest, cross_value = run_probe(
        ssh, CROSS_TASK_PROBE_SOURCE,
        "cnd_thread_state_pac_cross_task_probe",
        "cnd-thread-state-pac-cross-task-probe",
    )
    identity_digest, identity_value = run_probe(
        ssh, IDENTITY_PROBE_SOURCE,
        "cnd_thread_state_pac_exception_identity_probe",
        "cnd-thread-state-pac-exception-identity-probe",
    )
    same_result = validate_result(same_value)
    cross_result = validate_cross_task_result(cross_value)
    identity_result = validate_identity_result(identity_value)
    return {
        "schema": "com.zeroxjf.cyanide.thread-state-pac-oracle-observation",
        "schema_version": 3,
        "classification": "runtime-observed",
        "same_task_probe_sha256": same_digest,
        "cross_task_probe_sha256": cross_digest,
        "exception_identity_probe_sha256": identity_digest,
        "same_task_result": same_result,
        "cross_task_result": cross_result,
        "exception_identity_result": identity_result,
        "conclusion": (
            "XNU converted locally plain-signed PC/LR values into the "
            "user-diversified PAC representation for supplied same-task and "
            "cross-task thread control ports without KRW or a kernel call; "
            "an EXCEPTION_STATE_IDENTITY-delivered right also converted and "
            "resumed the target through a state reply."
        ),
        "limits": {
            "establishes_same_task_target_conversion": True,
            "establishes_cross_task_target_conversion": True,
            "establishes_exception_identity_right_on_vphone": True,
            "establishes_physical_device_behavior": False,
            "requires_target_thread_control_port": True,
            "establishes_control_port_acquisition_on_stock": False,
            "persistent_mutation": False,
        },
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--host", required=True)
    result.add_argument("--port", type=int, default=22)
    result.add_argument("--user", default="mobile")
    result.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    result.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    result.add_argument("--output", type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    write_json(args.output, run_live(args))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
