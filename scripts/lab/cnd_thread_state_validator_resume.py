#!/usr/bin/env python3
"""Prove a marked state reaches and returns from the 23A341 validator."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import select
import shlex
import signal
import struct
import subprocess
import time
from pathlib import Path
from typing import Any, BinaryIO

from cnd_remotecall_lab import DEFAULT_KNOWN_HOSTS, LabError, SSH, require_vphone
from cnd_thread_state_pac_oracle import validate_identity_result
from cnd_vphone_krw import (
    STANDALONE_KRW_SOCKET_PATH,
    build_binary,
    copy_binary,
    debugger_kernel_address,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build/thread-state-validator-resume"
PROBE_SOURCE = (
    REPO_ROOT / "scripts/lab/cnd_thread_state_pac_exception_identity_probe.c"
)
KRW_READER_SOURCE = REPO_ROOT / "scripts/lab/cnd_lab_provider_krw.c"
STATE_RESOLVER_SOURCE = REPO_ROOT / "scripts/lab/cnd_thread_saved_state_resolve.c"
LLDB_CALLBACKS = REPO_ROOT / "scripts/lab/cnd_lldb_validator_breakpoints.py"

EXPECTED_OS_BUILD = "23A341"
EXPECTED_KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"
STATIC_FILESET_BASE = 0xFFFFFE0007004000
STATIC_KERNEL_TEXT = 0xFFFFFE0007008000
STATIC_VALIDATOR = 0xFFFFFE0007AB9394
STATIC_PRE_VALIDATOR = 0xFFFFFE0007C5DDD4
STATIC_AFTER_CHECK = 0xFFFFFE0007C5DDD8
MARKER_X16 = 0x434E4456414C3136
MARKER_X17 = 0x434E4456414C3137
EXPECTED_VALIDATOR_WORDS = (
    0xD53B4230,
    0x363805B0,
    0xD5384210,
    0x36000570,
    0xF9409410,
    0xF27E045F,
)
EXPECTED_PRE_VALIDATOR_WORDS = (
    0x97F96D70,
)
EXPECTED_AFTER_CHECK_WORDS = (
    0xAA0703E1,
    0x2A0803E2,
    0x121E0446,
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wait_for_line(stream: BinaryIO, expected: bytes,
                  timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    observed = bytearray()
    while time.monotonic() < deadline:
        ready, _, _ = select.select(
            [stream], [], [], min(0.25, deadline - time.monotonic()))
        if not ready:
            continue
        line = stream.readline()
        if not line:
            break
        observed.extend(line)
        if expected in line:
            return bytes(observed)
    detail = observed.decode("utf-8", "replace").strip()
    raise LabError(
        f"timed out waiting for {expected.decode()!r}"
        f"{': ' + detail if detail else ''}"
    )


def read_kernel_words(ssh: SSH, reader: str, kernel_base: int,
                      address: int, expected: tuple[int, ...],
                      name: str) -> dict[str, Any]:
    output = ssh.command(
        f"{shlex.quote(reader)} {shlex.quote(STANDALONE_KRW_SOCKET_PATH)} "
        f"{kernel_base:#x} read {address:#x} {len(expected) * 4}"
    ).strip()
    try:
        report = json.loads(output)
        observed = bytes.fromhex(report["bytes"])
    except (json.JSONDecodeError, KeyError, ValueError) as error:
        raise LabError(f"{name} KRW read returned invalid JSON") from error
    expected_bytes = struct.pack(f"<{len(expected)}I", *expected)
    if report.get("operation") != "read" or \
            report.get("usedKernelWrite") is not False or \
            report.get("usedKernelCall") is not False or \
            observed != expected_bytes:
        raise LabError(f"{name} live instruction identity mismatch")
    return {
        "address": f"{address:#018x}",
        "wordCount": len(expected),
        "bytes": observed.hex(),
        "sha256": hashlib.sha256(observed).hexdigest(),
        "exact": True,
    }


def start_gated_probe(ssh: SSH, remote_probe: str) -> subprocess.Popen[bytes]:
    if not re.fullmatch(
            r"/var/tmp/cnd-validator-resume-probe-[0-9a-f]{16}",
            remote_probe):
        raise LabError("validator probe path is not content-addressed")
    return subprocess.Popen(
        [*ssh.base, f"{remote_probe} --validator-gate"],
        env=ssh.environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )


def parse_ready_marker(data: bytes) -> tuple[int, int, int]:
    matches = re.findall(
        rb"CND_VALIDATOR_READY pid=([0-9]+) thread_port=(0x[0-9a-f]+) "
        rb"x17=(0x[0-9a-f]{16})",
        data,
    )
    if len(matches) != 1:
        raise LabError("validator probe returned an ambiguous ready marker")
    pid = int(matches[0][0], 10)
    port = int(matches[0][1], 16)
    marker_x17 = int(matches[0][2], 16)
    if pid <= 1 or port == 0 or port > 0xffffffff:
        raise LabError("validator probe returned an invalid pid or thread port")
    return pid, port, marker_x17


def resolve_saved_state(ssh: SSH, resolver: str, kernel_base: int,
                        slide: int, pid: int, port: int) -> dict[str, Any]:
    output = ssh.command(
        f"{shlex.quote(resolver)} {shlex.quote(STANDALONE_KRW_SOCKET_PATH)} "
        f"{kernel_base:#x} {slide:#x} {pid} {port:#x}"
    ).strip()
    try:
        report = json.loads(output)
    except json.JSONDecodeError as error:
        raise LabError("saved-state resolver returned invalid JSON") from error
    if report.get("schema") != \
            "com.zeroxjf.cyanide.thread-saved-state-resolve" or \
            report.get("pid") != pid or \
            int(report.get("portName", "0"), 16) != port or \
            int(report.get("kernelBase", "0"), 16) != kernel_base or \
            report.get("layoutExact") is not True or \
            report.get("usedKernelRead") is not True or \
            report.get("usedKernelWrite") is not False or \
            report.get("usedKernelCall") is not False:
        raise LabError("saved-state resolver identity mismatch")
    try:
        saved_state = int(report["savedState"], 16)
        x16_address = int(report["x16Address"], 16)
        x17_address = int(report["x17Address"], 16)
        pc_address = int(report["pcAddress"], 16)
        jop_hash_address = int(report["jopHashAddress"], 16)
        context_data = int(report["contextData"], 16)
        u_neon = int(report["uNeon"], 16)
    except (KeyError, TypeError, ValueError) as error:
        raise LabError("saved-state resolver omitted an exact address") from error
    if saved_state & 0xffff000000000000 != 0xffff000000000000 or \
            context_data != saved_state or u_neon != saved_state + 0x130 or \
            x16_address != saved_state + 0x88 or \
            x17_address != saved_state + 0x90 or \
            pc_address != saved_state + 0x108 or \
            jop_hash_address != saved_state + 0x128:
        raise LabError("saved-state resolver returned inconsistent offsets")
    return report


def lldb_command_file(port: int, pre_validator: int, validator: int,
                      after_check: int, marker_x17: int,
                      saved_state: int, event_path: Path) -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    event_path.unlink(missing_ok=True)
    command_path = BUILD_DIR / "validator-resume.lldb"
    lab_path = os.fspath(LLDB_CALLBACKS.parent)
    commands = (
        "platform select remote-ios\n"
        f"gdb-remote 127.0.0.1:{port}\n"
        "script import sys\n"
        "script lldb.debugger.SetAsync(False)\n"
        f"script sys.path.insert(0, {lab_path!r})\n"
        "script import cnd_lldb_validator_breakpoints as cnd_validator_bp\n"
        "script cnd_validator_bp.install(lldb.debugger, "
        f"{pre_validator}, {validator}, {after_check}, "
        f"{MARKER_X16}, {marker_x17}, "
        f"{saved_state}, {os.fspath(event_path)!r})\n"
        "script cnd_validator_bp.capture_targeted(lldb.debugger)\n"
        "process detach\n"
        "quit\n"
    )
    command_path.write_text(commands, encoding="utf-8")
    return command_path


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def run_debugger(port: int, pre_validator: int, validator: int,
                 after_check: int, marker_x17: int, saved_state: int,
                 probe: subprocess.Popen[bytes]) -> tuple[str, list[dict[str, Any]]]:
    event_path = BUILD_DIR / "validator-events.jsonl"
    command_path = lldb_command_file(
        port, pre_validator, validator, after_check,
        marker_x17, saved_state, event_path)
    debugger = subprocess.Popen(
        ["xcrun", "lldb", "--batch", "-s", os.fspath(command_path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    if debugger.stdout is None or probe.stdin is None:
        stop_process(debugger)
        raise LabError("debugger/probe pipes were not created")
    prefix = b""
    try:
        prefix = wait_for_line(debugger.stdout, b"CND_LLDB_ARMED", 10)
        probe.stdin.write(b"G")
        probe.stdin.flush()
        try:
            remainder, _ = debugger.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            debugger.send_signal(signal.SIGINT)
            try:
                remainder, _ = debugger.communicate(timeout=5)
            except subprocess.TimeoutExpired as error:
                stop_process(debugger)
                raise LabError("LLDB validator capture timed out") from error
    except Exception:
        stop_process(debugger)
        raise
    transcript = (prefix + remainder).decode("utf-8", "replace")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    (BUILD_DIR / "validator-resume-lldb.txt").write_text(
        transcript, encoding="utf-8")
    if debugger.returncode != 0 or "Process 1 detached" not in transcript:
        raise LabError(
            "LLDB validator capture did not detach cleanly:\n" +
            transcript[-4000:]
        )
    if not event_path.is_file():
        raise LabError(
            "LLDB produced no validator breakpoint evidence:\n" +
            transcript[-4000:]
        )
    try:
        events = [json.loads(line) for line in
                  event_path.read_text(encoding="utf-8").splitlines()
                  if line]
    except json.JSONDecodeError as error:
        raise LabError("LLDB breakpoint evidence is not valid JSON") from error
    return transcript, events


def finish_probe(probe: subprocess.Popen[bytes]) -> tuple[dict[str, Any], str]:
    try:
        stdout, stderr = probe.communicate(timeout=10)
    except subprocess.TimeoutExpired as error:
        stop_process(probe)
        raise LabError("validator resume probe did not finish") from error
    detail = stderr.decode("utf-8", "replace").strip()
    if probe.returncode != 0:
        raise LabError(
            f"validator resume probe exited with {probe.returncode}"
            f"{': ' + detail if detail else ''}"
        )
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise LabError("validator resume probe did not return JSON") from error
    return validate_identity_result(result), detail


def validate_events(events: list[dict[str, Any]], pre_validator: int,
                    validator: int, after_check: int, marker_x17: int,
                    saved_state: int,
                    probe: dict[str, Any]) -> None:
    if len(events) != 3 or [event.get("stage") for event in events] != \
            ["pre-validator", "validator", "after-check"]:
        raise LabError(
            f"expected pre-validator, validator, and after-check events: {events}")
    pre_event, validator_event, after_event = events
    if int(pre_event.get("pc", "0"), 16) != pre_validator or \
            int(validator_event.get("pc", "0"), 16) != validator or \
            int(after_event.get("pc", "0"), 16) != after_check:
        raise LabError("validator breakpoint addresses did not match profile")
    if len({event.get("savedState") for event in events}) != 1 or \
            int(pre_event.get("savedState", "0"), 16) != saved_state or \
            len({event.get("jopHash") for event in events}) != 1:
        raise LabError("validator return did not retain the marked saved state")
    for event in events:
        if int(event.get("stateX16", "0"), 16) != MARKER_X16 or \
                int(event.get("stateX17", "0"), 16) != marker_x17 or \
                not event.get("jopHash"):
            raise LabError("validator breakpoint marker/state evidence failed")
    if validator_event.get("irqMasked") is not True or \
            validator_event.get("spsel") != 1:
        raise LabError("validator did not run under IRQ-masked SPSel=1 context")
    if int(validator_event["statePC"], 16) != \
            int(probe["raw_resume_pc"], 16) or \
            int(validator_event["stateLR"], 16) != \
            int(probe["raw_fallback_lr"], 16):
        raise LabError("validator arguments do not match the resumed tuple")


def validate_probe_markers(probe: dict[str, Any], marker_x17: int) -> None:
    values: dict[str, int] = {}
    for name in (
        "validator_marker_x16", "validator_marker_x17",
        "resumed_x16", "resumed_x17",
    ):
        text = probe.get(name)
        if not isinstance(text, str) or not re.fullmatch(
                r"0x[0-9a-f]{16}", text):
            raise LabError(f"validator probe returned invalid {name}")
        values[name] = int(text, 16)
    if probe.get("debug_gate_used") is not True or \
            probe.get("validator_gate_used") is not True or \
            probe.get("retained_x17") is not True or \
            probe.get("validator_markers_restored") is not True or \
            values["validator_marker_x16"] != MARKER_X16 or \
            values["validator_marker_x17"] != marker_x17 or \
            values["resumed_x16"] != MARKER_X16 or \
            values["resumed_x17"] != marker_x17:
        raise LabError("validator probe did not resume with exact markers")


def run_live(args: argparse.Namespace) -> dict[str, Any]:
    if args.kernel_debug_port < 6000 or args.kernel_debug_port > 65535:
        raise LabError("kernel debug port must be between 6000 and 65535")
    ssh = SSH(args.host, args.port, args.user,
              args.known_hosts.expanduser().resolve(), args.password_env)
    require_vphone(ssh)
    os_build = ssh.command(
        "/iosbinpack64/usr/sbin/sysctl -n kern.osversion"
    ).strip()
    if os_build != EXPECTED_OS_BUILD:
        raise LabError(
            f"OS build mismatch: expected {EXPECTED_OS_BUILD}, "
            f"observed {os_build or 'missing'}"
        )
    if ssh.file_kind(STANDALONE_KRW_SOCKET_PATH) != "socket":
        raise LabError("standalone KRW provider socket is missing")

    inner_text_text, kernel_uuid = debugger_kernel_address(
        args.kernel_debug_port)
    inner_text = int(inner_text_text, 16)
    if kernel_uuid != EXPECTED_KERNEL_UUID or inner_text < STATIC_KERNEL_TEXT:
        raise LabError("kernel debugger identity does not match 23A341")
    slide = inner_text - STATIC_KERNEL_TEXT
    kernel_base = STATIC_FILESET_BASE + slide
    validator = STATIC_VALIDATOR + slide
    pre_validator = STATIC_PRE_VALIDATOR + slide
    after_check = STATIC_AFTER_CHECK + slide

    reader = build_binary(KRW_READER_SOURCE, "cnd_lab_provider_krw")
    remote_reader = copy_binary(ssh, reader, "cnd-validator-krw-reader")
    resolver = build_binary(
        STATE_RESOLVER_SOURCE, "cnd_thread_saved_state_resolve")
    remote_resolver = copy_binary(
        ssh, resolver, "cnd-thread-saved-state-resolve")
    instruction_checks = {
        "validator": read_kernel_words(
            ssh, remote_reader, kernel_base, validator,
            EXPECTED_VALIDATOR_WORDS, "validator"),
        "preValidator": read_kernel_words(
            ssh, remote_reader, kernel_base, pre_validator,
            EXPECTED_PRE_VALIDATOR_WORDS, "pre-validator"),
        "afterCheck": read_kernel_words(
            ssh, remote_reader, kernel_base, after_check,
            EXPECTED_AFTER_CHECK_WORDS, "after-check"),
    }

    local_probe = build_binary(
        PROBE_SOURCE, "cnd_thread_state_validator_resume_probe",
        architecture="arm64e")
    remote_probe = copy_binary(
        ssh, local_probe, "cnd-validator-resume-probe")
    gated_probe = start_gated_probe(ssh, remote_probe)
    if gated_probe.stderr is None:
        stop_process(gated_probe)
        raise LabError("validator probe has no stderr pipe")
    try:
        ready = wait_for_line(
            gated_probe.stderr, b"CND_VALIDATOR_READY", 8)
        probe_pid, thread_port, marker_x17 = parse_ready_marker(ready)
        state_resolution = resolve_saved_state(
            ssh, remote_resolver, kernel_base, slide,
            probe_pid, thread_port)
        saved_state = int(state_resolution["savedState"], 16)
        transcript, events = run_debugger(
            args.kernel_debug_port, pre_validator, validator, after_check,
            marker_x17, saved_state, gated_probe)
        probe_result, probe_stderr = finish_probe(gated_probe)
    except Exception:
        stop_process(gated_probe)
        raise
    validate_probe_markers(probe_result, marker_x17)
    validate_events(
        events, pre_validator, validator, after_check,
        marker_x17, saved_state, probe_result)

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    transcript_path = BUILD_DIR / "validator-resume-lldb.txt"
    transcript_path.write_text(transcript, encoding="utf-8")
    return {
        "schema": "com.zeroxjf.cyanide.thread-state-validator-resume",
        "schemaVersion": 1,
        "classification": "VM-proved",
        "result": "marked-state-validated-and-resumed",
        "target": {
            "environment": "vPhone VRESEARCH VM",
            "osBuild": os_build,
            "kernelUUID": kernel_uuid,
            "kernelFilesetBase": f"{kernel_base:#018x}",
            "kernelText": f"{inner_text:#018x}",
            "kernelSlide": f"{slide:#018x}",
        },
        "anchors": {
            "preValidator": f"{pre_validator:#018x}",
            "validator": f"{validator:#018x}",
            "afterCheck": f"{after_check:#018x}",
            "instructionChecks": instruction_checks,
        },
        "debugger": {
            "port": args.kernel_debug_port,
            "events": events,
            "transcriptSHA256": hashlib.sha256(
                transcript.encode("utf-8")).hexdigest(),
            "detachedCleanly": True,
        },
        "probe": {
            "binarySHA256": sha256(local_probe),
            "resolverBinarySHA256": sha256(resolver),
            "readyMarker": ready.decode("utf-8", "replace").strip(),
            "stateResolution": state_resolution,
            "stderr": probe_stderr,
            "result": probe_result,
        },
        "invariants": {
            "targetSavedStateResolvedByReadOnlyKRW": True,
            "converterValidatorCallSiteMatched": True,
            "validatorEnteredWithMarkedTuple": True,
            "validatorIRQMasked": True,
            "validatorSPSelOne": True,
            "validatorReturnedToExpectedContinuation": True,
            "sameSavedStateAtEntryAndReturn": True,
            "jopHashStableAcrossValidation": True,
            "childResumedWithMarkedRegisters": True,
        },
        "safety": {
            "usedKernelRead": True,
            "usedKernelWrite": False,
            "usedKernelCall": False,
            "persistentKernelMutation": False,
            "disposableChildOnly": True,
            "springBoardThreadModified": False,
        },
        "limits": [
            "This proves legitimate exception-state application, validator acceptance, and subsequent EL0 resume; it does not prove an EL1 return or arbitrary kernel PC.",
            "The LLDB observation and provider are VM facilities and do not transfer kcall or debugger access to physical hardware.",
            "No SpringBoard thread was suspended, modified, or resumed by this experiment.",
        ],
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    destination = path.expanduser().resolve()
    if REPO_ROOT not in destination.parents:
        raise LabError("evidence output must remain inside the repository")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".new")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    temporary.replace(destination)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--host", required=True)
    result.add_argument("--port", type=int, default=22222)
    result.add_argument("--user", default="root")
    result.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    result.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    result.add_argument("--kernel-debug-port", type=int, default=62139)
    result.add_argument("--confirm-vm-validator", default=None)
    result.add_argument("--output", type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.port != 22222 or args.user != "root":
        raise SystemExit("error: validator canary requires root SSH port 22222")
    if args.confirm_vm_validator != EXPECTED_OS_BUILD:
        raise SystemExit(
            "error: validator canary requires --confirm-vm-validator 23A341")
    try:
        report = run_live(args)
        if args.output is not None:
            write_report(args.output, report)
    except (LabError, OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
