#!/usr/bin/env python3
"""Exercise the normal thread_set_state saved-state signer boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
from pathlib import Path
from typing import Any

from cnd_rea_secure_execution import write_json
from cnd_remotecall_lab import DEFAULT_KNOWN_HOSTS, LabError, SSH, require_vphone
from cnd_vphone_krw import build_binary, debugger_kernel_address


REPO_ROOT = Path(__file__).resolve().parents[2]
PROBE_SOURCE = REPO_ROOT / \
    "scripts/lab/cnd_thread_state_signer_caller_probe.c"
PROBE_ENTITLEMENTS = REPO_ROOT / \
    "scripts/lab/cnd_thread_state_signer_caller.entitlements"
EXPECTED_KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"
STATIC_KERNEL_INNER_TEXT = 0xfffffe0007008000
STATIC_EXCEPTION_RETURN_AFTER_CHECK = 0xfffffe0007ab81e4


def validate_result(value: Any, expected_pc: int) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != \
            "com.zeroxjf.cyanide.thread-state-signer-caller-probe" or \
            value.get("schema_version") != 1:
        raise LabError("signer-caller probe returned an unsupported result")
    required_false = (
        "test_state_executed", "kernel_call_used", "krw_used",
        "persistent_mutation", "arbitrary_el1_state_signed",
    )
    if any(value.get(name) is not False for name in required_false) or \
            value.get("normal_trigger") != "thread_set_state" or \
            value.get("private_thread_set_state_entitlement") is not True or \
            value.get("target_thread_suspended") is not True or \
            value.get("target_thread_resumed_only_after_restore") is not True or \
            value.get("boundary_classified") is not True or \
            value.get("requested_kernel_pc") != f"0x{expected_pc:016x}" or \
            value.get("restore_after_kernel_kr") != 0 or \
            value.get("final_restore_kr") != 0 or \
            value.get("resume_kr") != 0 or value.get("join_result") != 0:
        raise LabError("signer-caller probe safety invariants failed")
    baseline = value.get("baseline")
    kernel_el1 = value.get("kernel_pc_el1")
    if not isinstance(baseline, dict) or baseline.get("passed") is not True or \
            not isinstance(kernel_el1, dict) or \
            kernel_el1.get("preserved") is not False or \
            (kernel_el1.get("sanitized_to_el0") is not True and
             kernel_el1.get("rejected") is not True):
        raise LabError("signer-caller boundary result is inconsistent")
    return value


def run_live(args: argparse.Namespace) -> dict[str, Any]:
    inner_text, kernel_uuid = debugger_kernel_address(args.kernel_debug_port)
    if kernel_uuid != EXPECTED_KERNEL_UUID:
        raise LabError(
            f"unexpected kernel UUID: {kernel_uuid}"
        )
    inner_text_value = int(inner_text, 16)
    if inner_text_value < STATIC_KERNEL_INNER_TEXT:
        raise LabError("live inner kernel text precedes the static profile")
    slide = inner_text_value - STATIC_KERNEL_INNER_TEXT
    if slide & 0x3fff:
        raise LabError("live kernel slide is not 16K aligned")
    kernel_pc = STATIC_EXCEPTION_RETURN_AFTER_CHECK + slide

    probe = build_binary(
        PROBE_SOURCE, "cnd_thread_state_signer_caller_probe",
        entitlements=PROBE_ENTITLEMENTS, architecture="arm64e",
    )
    digest = hashlib.sha256(probe.read_bytes()).hexdigest()
    remote = f"/var/tmp/cnd-thread-state-signer-caller-{digest[:16]}"
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    ssh.copy(probe, remote)
    output = ssh.command(
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)} && "
        f"{shlex.quote(remote)} 0x{kernel_pc:016x}"
    )
    try:
        result = validate_result(json.loads(output), kernel_pc)
    except json.JSONDecodeError as error:
        raise LabError("signer-caller probe did not return JSON") from error
    return {
        "schema": "com.zeroxjf.cyanide.thread-state-signer-caller-observation",
        "schema_version": 1,
        "classification": "runtime-observed",
        "kernel_uuid": kernel_uuid,
        "kernel_inner_text": inner_text,
        "kernel_slide": f"0x{slide:016x}",
        "signer_caller_static": "0xfffffe0007c5db28",
        "candidate_pc_static":
            f"0x{STATIC_EXCEPTION_RETURN_AFTER_CHECK:016x}",
        "candidate_pc_live": f"0x{kernel_pc:016x}",
        "probe_sha256": digest,
        "vm_private_entitlement_required":
            "com.apple.private.thread-set-state",
        "result": result,
        "conclusion": (
            "The normal thread_set_state path reached its saved-state "
            "mutation boundary, but did not preserve a requested EL1 CPSR. "
            "It therefore cannot directly mint an arbitrary EL1 exception "
            "return state."
        ),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--host", required=True)
    result.add_argument("--port", type=int, default=22222)
    result.add_argument("--user", default="root")
    result.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    result.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    result.add_argument("--kernel-debug-port", type=int, required=True)
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
