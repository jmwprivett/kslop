#!/usr/bin/env python3
"""Correlate a Frida SpringBoard checkpoint with bounded VM kernel reads."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import struct
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from cnd_frida_vm import (
    FRIDA_VERSION,
    LOCAL_ENDPOINT,
    VENV_DIR,
    ensure_server,
    ensure_tunnel,
    installed_server_version,
)
from cnd_remotecall_lab import DEFAULT_KNOWN_HOSTS, LabError, SSH, require_vphone
from cnd_thread_state_validator_resume import run_live as run_validator_resume
from cnd_vphone_krw import (
    PROBE_SOURCE,
    build_binary,
    copy_binary,
    parse_marker,
    run_kcall_smoke,
    run_thread_state_signer_canary,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
AGENT_PATH = REPO_ROOT / "scripts/lab/cnd_frida_krw_agent.js"
RELAY_SOURCE = REPO_ROOT / "scripts/lab/cnd_frida_krw_read_relay.c"
EVIDENCE_DIR = REPO_ROOT / "docs/research"

EXPECTED_OS_BUILD = "23A341"
EXPECTED_KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"
EXPECTED_STATIC_FILESET_BASE = 0xFFFFFE0007004000
EXPECTED_KERNEL_FILE_OFFSET = 0x4000
PROVIDER_SOCKET = "/var/tmp/cyanide-kcall-research.sock"
PROVIDER_MARKER = "/var/tmp/cyanide-enable-libkrw-lab"

CND_MAGIC = 0x434E444B
CND_VERSION = 3
CND_OPERATION_KBASE = 1
CND_OPERATION_READ = 2
CND_OPERATION_CAPABILITIES = 15
CND_CAPABILITY_KRW = 1 << 0
CND_CAPABILITY_DIRECT_TASK = 1 << 1
CND_CAPABILITY_PROCESS_RESOLVE = 1 << 2
CND_CAPABILITY_KCALL = 1 << 3
CND_MAX_TRANSFER = 0x4000

MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 0x2
MH_FILESET = 0xC
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_FILESET_ENTRY = 0x80000035

MAX_REGIONS = 16
MAX_REGION_BYTES = 0x4000
MAX_TOTAL_REGION_BYTES = 0x10000
MAX_LOAD_COMMAND_BYTES = 0x100000
MAX_CHANGED_OFFSETS = 512

REQUEST = struct.Struct("<IIIIQ")
RESPONSE = struct.Struct("<IiIIQ")
MACH_HEADER_64 = struct.Struct("<IiiIIIII")


@dataclass(frozen=True)
class RegionRequest:
    expression: str
    base_name: str
    offset: int
    absolute: int | None
    length: int
    label: str

    def resolve(self, kernel_base: int, kernel_text: int) -> int:
        if self.absolute is not None:
            return self.absolute
        base = kernel_base if self.base_name == "kbase" else kernel_text
        if base > (1 << 64) - 1 - self.offset:
            raise LabError(f"region {self.label} address overflows uint64")
        return base + self.offset


class ReadOnlyProvider:
    """CNDLabKernelProtocol client over the guarded SSH stdio relay."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        if process.stdin is None or process.stdout is None:
            raise LabError("read-only relay has no stdio pipes")
        self.process = process
        self.input: BinaryIO = process.stdin
        self.output: BinaryIO = process.stdout
        self.closed = False

    @staticmethod
    def _read_exact(stream: BinaryIO, length: int) -> bytes:
        chunks: list[bytes] = []
        remaining = length
        while remaining:
            chunk = stream.read(remaining)
            if not chunk:
                raise LabError("read-only provider relay closed unexpectedly")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _request(self, operation: int, address: int = 0,
                 length: int = 0) -> tuple[int, bytes]:
        if self.closed:
            raise LabError("read-only provider relay is closed")
        if operation not in {
            CND_OPERATION_CAPABILITIES,
            CND_OPERATION_KBASE,
            CND_OPERATION_READ,
        }:
            raise LabError("the bridge client only permits read operations")
        self.input.write(REQUEST.pack(
            CND_MAGIC, CND_VERSION, operation, length, address))
        self.input.flush()
        raw = self._read_exact(self.output, RESPONSE.size)
        magic, status, response_length, reserved, value = RESPONSE.unpack(raw)
        if magic != CND_MAGIC or reserved != 0:
            raise LabError("provider returned a malformed response header")
        if status != 0:
            detail = os.strerror(status) if status > 0 else str(status)
            raise LabError(f"provider operation {operation} failed: {detail}")
        expected_length = length if operation == CND_OPERATION_READ else 0
        if response_length != expected_length:
            raise LabError(
                "provider response length mismatch: "
                f"expected={expected_length} observed={response_length}"
            )
        payload = self._read_exact(self.output, response_length) \
            if response_length else b""
        return value, payload

    def capabilities(self) -> int:
        return self._request(CND_OPERATION_CAPABILITIES)[0]

    def kernel_base(self) -> int:
        return self._request(CND_OPERATION_KBASE)[0]

    def read(self, address: int, length: int) -> bytes:
        if length <= 0:
            raise LabError("kernel read length must be positive")
        if address < 0 or address > (1 << 64) - length:
            raise LabError("kernel read range overflows uint64")
        result = bytearray()
        while len(result) < length:
            amount = min(CND_MAX_TRANSFER, length - len(result))
            _, payload = self._request(
                CND_OPERATION_READ, address + len(result), amount)
            result.extend(payload)
        return bytes(result)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.input.close()
        try:
            return_code = self.process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            self.process.terminate()
            self.process.wait(timeout=2)
            raise LabError("read-only relay did not exit after EOF") from error
        stderr = b""
        if self.process.stderr is not None:
            stderr = self.process.stderr.read()
        if return_code != 0:
            detail = stderr.decode("utf-8", "replace").strip()
            raise LabError(
                f"read-only relay exited with {return_code}"
                f"{': ' + detail if detail else ''}"
            )

    def __enter__(self) -> ReadOnlyProvider:
        return self

    def __exit__(self, exc_type: object, exc: object,
                 traceback: object) -> None:
        try:
            self.close()
        except LabError:
            if exc is None:
                raise


def start_read_only_provider(ssh: SSH, remote_relay: str) -> ReadOnlyProvider:
    if not re.fullmatch(r"/var/tmp/cnd-frida-krw-relay-[0-9a-f]{16}",
                        remote_relay):
        raise LabError("read-only relay path is not content-addressed")
    process = subprocess.Popen(
        [*ssh.base, remote_relay],
        env=ssh.environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    return ReadOnlyProvider(process)


def parse_region(text: str) -> RegionRequest:
    address_text, separator, rest = text.partition(":")
    length_text, second_separator, label = rest.partition(":")
    if not separator or not second_separator or not label or \
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", label):
        raise argparse.ArgumentTypeError(
            "region must be BASE:LENGTH:LABEL with a short safe label"
        )
    base_name = ""
    offset = 0
    absolute: int | None = None
    symbolic = re.fullmatch(r"(kbase|kernel)(?:\+(0x[0-9A-Fa-f]+))?",
                            address_text)
    if symbolic:
        base_name = symbolic.group(1)
        offset = int(symbolic.group(2) or "0", 0)
    elif re.fullmatch(r"0x[0-9A-Fa-f]{16}", address_text):
        absolute = int(address_text, 16)
        base_name = "absolute"
    else:
        raise argparse.ArgumentTypeError(
            "region base must be kbase, kernel, or a 16-digit hex address"
        )
    try:
        length = int(length_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("region length is not an integer") \
            from error
    if length <= 0 or length > MAX_REGION_BYTES:
        raise argparse.ArgumentTypeError(
            f"region length must be between 1 and {MAX_REGION_BYTES:#x}"
        )
    return RegionRequest(text, base_name, offset, absolute, length, label)


def validate_regions(regions: list[RegionRequest]) -> None:
    if not regions or len(regions) > MAX_REGIONS:
        raise LabError(f"specify between 1 and {MAX_REGIONS} regions")
    total = sum(region.length for region in regions)
    if total > MAX_TOTAL_REGION_BYTES:
        raise LabError(
            f"total region bytes exceed {MAX_TOTAL_REGION_BYTES:#x}"
        )
    labels = [region.label for region in regions]
    if len(labels) != len(set(labels)):
        raise LabError("region labels must be unique")


def parse_load_commands(data: bytes, ncmds: int) -> list[tuple[int, bytes]]:
    commands: list[tuple[int, bytes]] = []
    offset = 0
    for _ in range(ncmds):
        if len(data) - offset < 8:
            raise LabError("Mach-O load commands ended early")
        command, command_size = struct.unpack_from("<II", data, offset)
        if command_size < 8 or command_size > len(data) - offset:
            raise LabError("Mach-O load command size is invalid")
        commands.append((command, data[offset:offset + command_size]))
        offset += command_size
    if offset != len(data):
        raise LabError("Mach-O load command byte count is inconsistent")
    return commands


def read_macho(client: ReadOnlyProvider, address: int,
               expected_filetype: int) -> tuple[dict[str, int],
                                                list[tuple[int, bytes]]]:
    header_data = client.read(address, MACH_HEADER_64.size)
    values = MACH_HEADER_64.unpack(header_data)
    header = {
        "magic": values[0],
        "cpuType": values[1],
        "cpuSubtype": values[2],
        "filetype": values[3],
        "ncmds": values[4],
        "sizeofcmds": values[5],
        "flags": values[6],
        "reserved": values[7],
    }
    if header["magic"] != MH_MAGIC_64 or \
            header["filetype"] != expected_filetype or \
            header["ncmds"] <= 0 or header["ncmds"] > 8192 or \
            header["sizeofcmds"] < 8 or \
            header["sizeofcmds"] > MAX_LOAD_COMMAND_BYTES:
        raise LabError(
            f"kernel Mach-O identity rejected at {address:#x}: {header}"
        )
    command_data = client.read(
        address + MACH_HEADER_64.size, header["sizeofcmds"])
    return header, parse_load_commands(command_data, header["ncmds"])


def kernel_identity(client: ReadOnlyProvider, kernel_base: int) -> dict[str, Any]:
    if kernel_base & 0x3FFF or \
            kernel_base & 0xFFFF000000000000 != 0xFFFF000000000000:
        raise LabError(f"provider returned noncanonical kbase {kernel_base:#x}")
    outer_header, commands = read_macho(client, kernel_base, MH_FILESET)
    unslid_base = 0
    kernel_vmaddr = 0
    kernel_fileoff = 0
    for command, data in commands:
        if command == LC_SEGMENT_64 and len(data) >= 72:
            vmaddr, _, fileoff, _ = struct.unpack_from("<QQQQ", data, 24)
            if fileoff == 0 and unslid_base == 0:
                unslid_base = vmaddr
        elif command == LC_FILESET_ENTRY and len(data) >= 32:
            _, _, vmaddr, fileoff, name_offset, _ = \
                struct.unpack_from("<IIQQII", data)
            if name_offset >= len(data):
                continue
            end = data.find(b"\0", name_offset)
            if end == -1:
                continue
            if data[name_offset:end] == b"com.apple.kernel":
                kernel_vmaddr = vmaddr
                kernel_fileoff = fileoff
    if not unslid_base or not kernel_vmaddr or not kernel_fileoff or \
            kernel_base < EXPECTED_STATIC_FILESET_BASE:
        raise LabError("fileset does not describe one com.apple.kernel image")
    slide = kernel_base - EXPECTED_STATIC_FILESET_BASE
    expected_kernel_text = kernel_base + EXPECTED_KERNEL_FILE_OFFSET
    commands_are_static = (
        unslid_base == EXPECTED_STATIC_FILESET_BASE and
        kernel_vmaddr ==
        EXPECTED_STATIC_FILESET_BASE + EXPECTED_KERNEL_FILE_OFFSET
    )
    commands_are_slid = (
        unslid_base == kernel_base and
        kernel_vmaddr == expected_kernel_text
    )
    if not commands_are_static and not commands_are_slid:
        raise LabError("fileset load-command address mode is inconsistent")
    if kernel_fileoff != EXPECTED_KERNEL_FILE_OFFSET:
        raise LabError(
            f"kernel fileset offset mismatch: {kernel_fileoff:#x}"
        )
    kernel_text = kernel_vmaddr + slide if commands_are_static \
        else kernel_vmaddr
    if kernel_text > (1 << 64) - 1 or \
            kernel_text != kernel_base + kernel_fileoff:
        raise LabError("fileset kernel mapping is inconsistent")

    inner_header, inner_commands = read_macho(
        client, kernel_text, MH_EXECUTE)
    uuids = [data[8:24] for command, data in inner_commands
             if command == LC_UUID and len(data) == 24]
    if len(uuids) != 1:
        raise LabError(f"expected one inner kernel UUID, observed {len(uuids)}")
    observed_uuid = str(uuid.UUID(bytes=uuids[0])).upper()
    if observed_uuid != EXPECTED_KERNEL_UUID:
        raise LabError(
            f"kernel UUID mismatch: expected {EXPECTED_KERNEL_UUID}, "
            f"observed {observed_uuid}"
        )
    return {
        "filesetBase": f"{kernel_base:#018x}",
        "filesetCommandBase": f"{unslid_base:#018x}",
        "loadCommandsMode": "static" if commands_are_static else "slid",
        "staticFilesetBase": f"{EXPECTED_STATIC_FILESET_BASE:#018x}",
        "slide": f"{slide:#018x}",
        "kernelText": f"{kernel_text:#018x}",
        "kernelFileOffset": f"{kernel_fileoff:#x}",
        "kernelUUID": observed_uuid,
        "outerFiletype": outer_header["filetype"],
        "innerFiletype": inner_header["filetype"],
    }


def capability_names(capabilities: int) -> list[str]:
    known = (
        (CND_CAPABILITY_KRW, "kernel-read-write"),
        (CND_CAPABILITY_DIRECT_TASK, "direct-task"),
        (CND_CAPABILITY_PROCESS_RESOLVE, "process-resolve"),
        (CND_CAPABILITY_KCALL, "kernel-call"),
    )
    return [name for bit, name in known if capabilities & bit]


def run_frida_checkpoint(label: str) -> dict[str, Any]:
    try:
        import frida  # type: ignore
    except ModuleNotFoundError as error:
        raise LabError("Frida Python bindings are unavailable") from error
    manager = frida.get_device_manager()
    device = manager.add_remote_device(LOCAL_ENDPOINT)
    matches = [process for process in device.enumerate_processes()
               if process.name == "SpringBoard"]
    if len(matches) != 1:
        raise LabError(
            f"expected one SpringBoard process, observed {len(matches)}"
        )
    process = matches[0]
    session = device.attach(process.pid)
    script = session.create_script(AGENT_PATH.read_text(encoding="utf-8"))
    try:
        script.load()
        checkpoint = script.exports_sync.checkpoint(label)
        if not isinstance(checkpoint, dict) or \
                checkpoint.get("schema") != \
                "com.zeroxjf.cyanide.frida-krw-checkpoint" or \
                checkpoint.get("pid") != process.pid or \
                checkpoint.get("arch") != "arm64" or \
                checkpoint.get("pointerSize") != 8:
            raise LabError("Frida checkpoint identity was rejected")
        return {
            "version": frida.__version__,
            "endpoint": LOCAL_ENDPOINT,
            "target": "SpringBoard",
            "targetPid": process.pid,
            "checkpoint": checkpoint,
        }
    finally:
        try:
            script.unload()
        finally:
            session.detach()


def snapshot_regions(client: ReadOnlyProvider,
                     requests: list[RegionRequest], kernel_base: int,
                     kernel_text: int) -> list[tuple[RegionRequest, int, bytes]]:
    snapshots: list[tuple[RegionRequest, int, bytes]] = []
    for request in requests:
        address = request.resolve(kernel_base, kernel_text)
        if address & 0xFFFF000000000000 != 0xFFFF000000000000 or \
                address > (1 << 64) - request.length:
            raise LabError(f"region {request.label} is not a kernel range")
        snapshots.append((request, address, client.read(address, request.length)))
    return snapshots


def word_report(offset: int, before: bytes, after: bytes) -> dict[str, Any]:
    before_value = int.from_bytes(before, "little")
    after_value = int.from_bytes(after, "little")

    def canonical(value: int) -> bool:
        return value & 0xFFFF000000000000 == 0xFFFF000000000000

    def noncanonical_high(value: int) -> bool:
        high = value >> 48
        return value != 0 and high not in {0, 0xFFFF}

    return {
        "offset": f"{offset:#x}",
        "before": f"{before_value:#018x}",
        "after": f"{after_value:#018x}",
        "beforeCanonicalKernelPointer": canonical(before_value),
        "afterCanonicalKernelPointer": canonical(after_value),
        "possiblePACOrTaggedValue": (
            noncanonical_high(before_value) or noncanonical_high(after_value)
        ),
    }


def diff_region(request: RegionRequest, address: int,
                before: bytes, after: bytes) -> dict[str, Any]:
    if len(before) != len(after) or len(before) != request.length:
        raise LabError(f"region {request.label} snapshot sizes differ")
    changed = [index for index, pair in enumerate(zip(before, after))
               if pair[0] != pair[1]]
    changed_words = sorted({index & ~7 for index in changed})
    words = [word_report(offset, before[offset:offset + 8],
                         after[offset:offset + 8])
             for offset in changed_words if offset + 8 <= len(before)]
    report: dict[str, Any] = {
        "expression": request.expression,
        "label": request.label,
        "address": f"{address:#018x}",
        "length": request.length,
        "beforeSHA256": hashlib.sha256(before).hexdigest(),
        "afterSHA256": hashlib.sha256(after).hexdigest(),
        "unchanged": not changed,
        "changedByteCount": len(changed),
        "changedByteOffsets": [f"{item:#x}"
                               for item in changed[:MAX_CHANGED_OFFSETS]],
        "changedByteOffsetsTruncated": len(changed) > MAX_CHANGED_OFFSETS,
        "changedAlignedWords": words[:MAX_CHANGED_OFFSETS],
        "changedAlignedWordsTruncated": len(words) > MAX_CHANGED_OFFSETS,
    }
    if request.length <= 512:
        report["beforeHex"] = before.hex()
        report["afterHex"] = after.hex()
    else:
        report["beforeEdgeHex"] = (before[:64] + before[-64:]).hex()
        report["afterEdgeHex"] = (after[:64] + after[-64:]).hex()
    return report


def build_and_copy_relay(ssh: SSH) -> str:
    relay = build_binary(RELAY_SOURCE, "cnd_frida_krw_read_relay")
    return copy_binary(ssh, relay, "cnd-frida-krw-relay")


def run_boundary_probe(
        ssh: SSH, action: str,
        args: argparse.Namespace | None = None) -> dict[str, Any] | None:
    if action == "snapshot":
        return None
    probe = build_binary(PROBE_SOURCE, "cnd_lab_krw_probe")
    remote_probe = copy_binary(ssh, probe, "cnd-lab-krw-probe")
    if action == "kcall-smoke":
        output = run_kcall_smoke(ssh, remote_probe, PROVIDER_SOCKET)
        match = re.fullmatch(
            r"ready capabilities=(0x[0-9a-f]+) kernelCall=available "
            r"smoke=passed gadget=(0x[0-9a-f]+) "
            r"result=(0x[0-9a-f]+|0)",
            output,
        )
        if not match:
            raise LabError("kernel-call smoke returned an unexpected report")
        return {
            "kind": "safe-return-stub-kcall",
            "result": "passed",
            "capabilities": match.group(1),
            "gadget": match.group(2),
            "returnValue": match.group(3),
            "raw": output,
            "persistentKernelMutation": False,
        }
    if action == "pac-signer-canary":
        output = run_thread_state_signer_canary(
            ssh, remote_probe, PROVIDER_SOCKET)
        try:
            report = json.loads(output)
        except json.JSONDecodeError as error:
            raise LabError("PAC signer canary did not return JSON") from error
        if report.get("schema") != \
                "com.zeroxjf.cyanide.thread-state-signer-canary" or \
                report.get("deterministic") is not True or \
                report.get("binds_state_address") is not True or \
                report.get("binds_mode_and_control_state") is not True or \
                report.get("persistent_mutation") is not False:
            raise LabError("PAC signer canary report failed its invariants")
        return {
            "kind": "thread-state-pac-signer-canary",
            "result": "passed",
            "report": report,
            "persistentKernelMutation": False,
            "validatorInvoked": report.get("validator_invoked") is True,
        }
    if action == "validator-resume-canary":
        if args is None:
            raise LabError("validator/resume canary requires bridge arguments")
        report = run_validator_resume(argparse.Namespace(
            host=args.host,
            port=args.port,
            user=args.user,
            known_hosts=args.known_hosts,
            password_env=args.password_env,
            kernel_debug_port=args.kernel_debug_port,
        ))
        invariants = report.get("invariants", {})
        safety = report.get("safety", {})
        required_invariants = {
            "targetSavedStateResolvedByReadOnlyKRW",
            "converterValidatorCallSiteMatched",
            "validatorEnteredWithMarkedTuple",
            "validatorIRQMasked",
            "validatorSPSelOne",
            "validatorReturnedToExpectedContinuation",
            "sameSavedStateAtEntryAndReturn",
            "jopHashStableAcrossValidation",
            "childResumedWithMarkedRegisters",
        }
        if report.get("schema") != \
                "com.zeroxjf.cyanide.thread-state-validator-resume" or \
                report.get("classification") != "VM-proved" or \
                report.get("result") != "marked-state-validated-and-resumed" or \
                any(invariants.get(name) is not True
                    for name in required_invariants) or \
                safety.get("usedKernelWrite") is not False or \
                safety.get("usedKernelCall") is not False or \
                safety.get("persistentKernelMutation") is not False:
            raise LabError("validator/resume canary report failed its invariants")
        return {
            "kind": "thread-state-validator-resume-canary",
            "result": "passed",
            "report": report,
            "persistentKernelMutation": False,
            "validatorInvoked": True,
            "childResumed": True,
        }
    raise LabError(f"unsupported boundary probe: {action}")


def ensure_frida_runtime() -> None:
    expected_python = VENV_DIR / "bin/python"
    try:
        import frida  # type: ignore
        if frida.__version__ == FRIDA_VERSION:
            return
    except ModuleNotFoundError:
        pass
    if not expected_python.is_file():
        raise LabError("run cnd_frida_vm.py setup before using the bridge")
    if os.environ.get("CND_FRIDA_KRW_REEXEC") == "1":
        raise LabError("the locked Frida environment could not be loaded")
    environment = dict(os.environ)
    environment["CND_FRIDA_KRW_REEXEC"] = "1"
    os.execve(
        str(expected_python),
        [str(expected_python), str(Path(__file__).resolve()), *sys.argv[1:]],
        environment,
    )


def execute_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    validate_regions(args.region)
    known_hosts = args.known_hosts.expanduser().resolve()
    ssh = SSH(args.host, args.port, args.user, known_hosts, args.password_env)
    require_vphone(ssh)
    os_build = ssh.command(
        "/usr/sbin/sysctl -n kern.osversion 2>/dev/null || "
        "/iosbinpack64/usr/sbin/sysctl -n kern.osversion"
    ).strip()
    if os_build != EXPECTED_OS_BUILD:
        raise LabError(
            f"OS build mismatch: expected {EXPECTED_OS_BUILD}, "
            f"observed {os_build or 'missing'}"
        )
    if ssh.file_kind(PROVIDER_SOCKET) != "socket":
        raise LabError(f"standalone provider socket is missing: {PROVIDER_SOCKET}")
    if ssh.file_kind(PROVIDER_MARKER) != "file":
        raise LabError("standalone provider marker is missing")
    marker = parse_marker(ssh.read_file(PROVIDER_MARKER))
    if marker.get("version") != "1" or marker.get("socket") != PROVIDER_SOCKET:
        raise LabError("standalone provider marker identity was rejected")

    server_version = installed_server_version(ssh)
    if server_version != FRIDA_VERSION:
        raise LabError(
            f"VM Frida version mismatch: expected {FRIDA_VERSION}, "
            f"observed {server_version or 'missing'}"
        )
    server_pid = ensure_server(ssh)
    tunnel_started = ensure_tunnel(
        args.host, args.port, args.user, known_hosts, args.password_env)
    remote_relay = build_and_copy_relay(ssh)

    with start_read_only_provider(ssh, remote_relay) as provider:
        capabilities = provider.capabilities()
        if capabilities & CND_CAPABILITY_KRW == 0:
            raise LabError("provider does not advertise kernel read/write")
        kernel_base = provider.kernel_base()
        identity = kernel_identity(provider, kernel_base)
        kernel_text = int(identity["kernelText"], 16)
        before = snapshot_regions(
            provider, args.region, kernel_base, kernel_text)
    checkpoint = run_frida_checkpoint(args.label)
    boundary_probe = run_boundary_probe(ssh, args.action, args)
    with start_read_only_provider(ssh, remote_relay) as provider:
        after_capabilities = provider.capabilities()
        after_kernel_base = provider.kernel_base()
        after_identity = kernel_identity(provider, after_kernel_base)
        if after_capabilities != capabilities or \
                after_kernel_base != kernel_base or \
                after_identity != identity:
            raise LabError("provider identity changed across the checkpoint")
        after = snapshot_regions(
            provider, args.region, kernel_base, kernel_text)

    region_reports = [
        diff_region(request, address, before_bytes, after_bytes)
        for (request, address, before_bytes),
            (_, after_address, after_bytes) in zip(before, after)
        if address == after_address
    ]
    if len(region_reports) != len(before):
        raise LabError("region addresses changed between snapshots")
    used_kernel_call = args.action in {"kcall-smoke", "pac-signer-canary"}
    used_kernel_write = args.action == "pac-signer-canary"
    return {
        "schema": "com.zeroxjf.cyanide.frida-krw-correlation",
        "schemaVersion": 1,
        "result": (
            "read-only-frida-krw-checkpoint-proved"
            if args.action == "snapshot"
            else f"frida-krw-{args.action}-proved"
        ),
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "target": {
            "kind": "vPhone-VRESEARCH",
            "host": args.host,
            "sshPort": args.port,
            "osBuild": os_build,
        },
        "provider": {
            "socket": PROVIDER_SOCKET,
            "markerPid": int(marker["pid"]),
            "capabilities": f"{capabilities:#x}",
            "capabilityNames": capability_names(capabilities),
            "readOnlyRelay": remote_relay,
            "identity": identity,
        },
        "frida": {
            **checkpoint,
            "serverPid": server_pid,
            "tunnelStartedNow": tunnel_started,
        },
        "boundaryProbe": boundary_probe,
        "regions": region_reports,
        "summary": {
            "regionCount": len(region_reports),
            "changedRegionCount": sum(
                not item["unchanged"] for item in region_reports),
            "changedByteCount": sum(
                item["changedByteCount"] for item in region_reports),
        },
        "safety": {
            "bridgeAllowedOperations": ["capabilities", "kbase", "read"],
            "boundaryProbeUsesSeparateExistingHarness": boundary_probe is not None,
            "usedKernelRead": True,
            "usedKernelWrite": used_kernel_write,
            "usedKernelCall": used_kernel_call,
            "persistentKernelMutation": False,
            "installedHooks": False,
            "fridaMemoryWrites": False,
            "possiblePACOrTaggedValueIsHeuristicOnly": True,
        },
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    if REPO_ROOT not in path.parents:
        raise LabError("evidence output must remain inside the repository")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "action", choices=(
            "snapshot", "kcall-smoke", "pac-signer-canary",
            "validator-resume-canary"))
    result.add_argument("--host", required=True)
    result.add_argument("--port", type=int, default=22222)
    result.add_argument("--user", default="root")
    result.add_argument(
        "--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    result.add_argument(
        "--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    result.add_argument("--kernel-debug-port", type=int, default=62139)
    result.add_argument(
        "--label", default="springboard-module-enumeration",
        choices=("springboard-module-enumeration",),
    )
    result.add_argument(
        "--region", type=parse_region, action="append", default=None,
        help="BASE:LENGTH:LABEL; BASE is kbase, kernel, or absolute hex",
    )
    result.add_argument("--output", type=Path, default=None)
    result.add_argument(
        "--confirm-vm-boundary", default=None,
        help="must equal 23A341 for a kcall or PAC boundary probe",
    )
    return result


def main() -> int:
    args = parser().parse_args()
    if args.port != 22222 or args.user != "root":
        raise SystemExit("error: this VM bridge requires root on SSH port 22222")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.password_env):
        raise SystemExit("error: password environment variable name is invalid")
    if args.action != "snapshot" and \
            args.confirm_vm_boundary != EXPECTED_OS_BUILD:
        raise SystemExit(
            "error: boundary probes require --confirm-vm-boundary 23A341"
        )
    if args.region is None:
        args.region = [
            parse_region("kbase:0x100:fileset-header"),
            parse_region("kernel:0x100:kernel-header"),
        ]
    try:
        ensure_frida_runtime()
        report = execute_snapshot(args)
        if args.output is not None:
            write_report(args.output, report)
    except (LabError, OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
