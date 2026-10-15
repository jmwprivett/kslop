#!/usr/bin/env python3
"""Fail-closed inventory of direct ml_sign_thread_state callers.

This is intentionally bound to the extracted iOS 26.0 (23A341) vPhone
``com.apple.kernel`` image.  It reconciles REA's complete incoming-reference
set with small, exact LLDB disassembly witnesses.  It is an audit tool, not a
generic patchfinder and not a kernel mutation harness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any


KERNEL_SHA256 = "c32c7005fd8f702bf7f34730a512af5cb896a8c61b4a80b8400401f3897060ea"
SIGNER_SNAPSHOT_SHA256 = "0126c0b48c6b421eda97ad4b7af21ddc695e89d039cc0e6c8a316945a0e76189"
COPYIO_SNAPSHOT_SHA256 = "bbf4734bf0506ff7673c04637b6ff22acc29a005e65ff5b1a41c8ea2b6df6157"
SIGNER_ADDRESS = "0xfffffe0007ab9344"
SIGNER_EVIDENCE_ID = "ev_8094f868c3d2c457309d5f86ac1c94ae49674620d14faf2912dc03b3e9eb484f"
COPYIO_EVIDENCE_ID = "ev_9013248cfaf0a44bcc0d41f09243a503f896442045650b533a6f3dca3ef63e08"


class InventoryError(RuntimeError):
    """The exact-artifact inventory no longer satisfies its evidence contract."""


CALLERS: tuple[dict[str, Any], ...] = (
    {
        "address": "0xfffffe0007ab7b5c",
        "end": "0xfffffe0007ab7ceb",
        "calls": ("0xfffffe0007ab7c18",),
        "classification": "hardware_exception_capture",
        "tuple_source": "ELR_EL1/SPSR_EL1 and live exception-entry registers",
        "pc_control": "hardware_exception_return_address",
        "el1_arbitrary_pc": False,
        "witnesses": (
            "[0xfffffe0007ab7be8] <+140>: mrs x22, ELR_EL1",
            "[0xfffffe0007ab7bec] <+144>: mrs x23, SPSR_EL1",
        ),
    },
    {
        "address": "0xfffffe0007c53bc0",
        "end": "0xfffffe0007c5402f",
        "calls": ("0xfffffe0007c53ec4", "0xfffffe0007c53fc8"),
        "classification": "copyio_recovery",
        "tuple_source": "validated immutable copyio_recover_table entry",
        "pc_control": "table_entry_only",
        "el1_arbitrary_pc": False,
        "witnesses": (
            "[0xfffffe0007c53ea0] <+736>: udiv x8, x7, x11",
            "[0xfffffe0007c53eb8] <+760>: ldr x1, [x22, #0x10]",
            "[0xfffffe0007c53fa4] <+996>: udiv x8, x7, x11",
            "[0xfffffe0007c53fbc] <+1020>: ldr x1, [x22, #0x10]",
        ),
    },
    {
        "address": "0xfffffe0007c54030",
        "end": "0xfffffe0007c5424b",
        "calls": ("0xfffffe0007c54184",),
        "classification": "kdp_trap_advance",
        "tuple_source": "authenticated saved state after a recognized debugger trap",
        "pc_control": "existing_pc_plus_4",
        "el1_arbitrary_pc": False,
        "witnesses": (
            "[0xfffffe0007c5415c] <+300>: mov w7, #0xdefe",
            "[0xfffffe0007c5416c] <+316>: mov w7, #0xdeff",
            "[0xfffffe0007c5417c] <+332>: add x1, x1, #0x4",
        ),
    },
    {
        "address": "0xfffffe0007c548d0",
        "end": "0xfffffe0007c549d3",
        "calls": ("0xfffffe0007c549a0",),
        "classification": "user_cpsr_mutator",
        "tuple_source": "authenticated user saved state with old/new EL0 guards",
        "pc_control": "unchanged_user_pc",
        "el1_arbitrary_pc": False,
        "witnesses": (
            "[0xfffffe0007c54960] <+144>: and w6, w2, #0xc",
            "[0xfffffe0007c54984] <+180>: and w6, w2, #0xc",
        ),
    },
    {
        "address": "0xfffffe0007c5c014",
        "end": "0xfffffe0007c5c64b",
        "calls": ("0xfffffe0007c5c544",),
        "classification": "user_cpsr_flag_mutator",
        "tuple_source": "authenticated user saved state with old/new EL0 guards",
        "pc_control": "unchanged_user_pc",
        "el1_arbitrary_pc": False,
        "witnesses": (
            "[0xfffffe0007c5c504] <+1264>: and w6, w2, #0xc",
            "[0xfffffe0007c5c528] <+1300>: and w6, w2, #0xc",
        ),
    },
    {
        "address": "0xfffffe0007c5c6c8",
        "end": "0xfffffe0007c5ccff",
        "calls": ("0xfffffe0007c5cbf8",),
        "classification": "user_cpsr_flag_mutator",
        "tuple_source": "authenticated user saved state with old/new EL0 guards",
        "pc_control": "unchanged_user_pc",
        "el1_arbitrary_pc": False,
        "witnesses": (
            "[0xfffffe0007c5cbb8] <+1264>: and w6, w2, #0xc",
            "[0xfffffe0007c5cbdc] <+1300>: and w6, w2, #0xc",
        ),
    },
    {
        "address": "0xfffffe0007c5db28",
        "end": "0xfffffe0007c5de47",
        "calls": (
            "0xfffffe0007c5dbb4",
            "0xfffffe0007c5dc4c",
            "0xfffffe0007c5dcdc",
            "0xfffffe0007c5dd98",
            "0xfffffe0007c5ddfc",
        ),
        "classification": "thread_state64_to_saved_state",
        "tuple_source": "user thread state after forced EL0 mode sanitization",
        "pc_control": "arbitrary_pc_but_el0_only",
        "el1_arbitrary_pc": False,
        "witnesses": (
            "[0xfffffe0007c5db8c] <+100>: and w6, w2, #0xc",
            "[0xfffffe0007c5dba0] <+120>: and w2, w2, #0xfffffe0",
            "[0xfffffe0007c5dc30] <+264>: and w6, w2, #0xc",
            "[0xfffffe0007c5dcc0] <+408>: and w6, w2, #0xc",
            "[0xfffffe0007c5dd7c] <+596>: and w6, w2, #0xc",
            "[0xfffffe0007c5dde0] <+696>: and w6, w2, #0xc",
        ),
    },
    {
        "address": "0xfffffe0007c617c8",
        "end": "0xfffffe0007c618ab",
        "calls": ("0xfffffe0007c61880",),
        "classification": "user_pc_setter",
        "tuple_source": "authenticated saved state guarded as EL0",
        "pc_control": "arbitrary_pc_but_el0_only",
        "el1_arbitrary_pc": False,
        "witnesses": ("[0xfffffe0007c61864] <+156>: and w6, w2, #0xc",),
    },
    {
        "address": "0xfffffe0007c618ac",
        "end": "0xfffffe0007c61a2b",
        "calls": ("0xfffffe0007c61a00",),
        "classification": "user_state_initializer",
        "tuple_source": "new zeroed state initialized with EL0 CPSR",
        "pc_control": "zero_user_pc",
        "el1_arbitrary_pc": False,
        "witnesses": ("[0xfffffe0007c619e8] <+316>: and w6, w2, #0xc",),
    },
    {
        "address": "0xfffffe0007c61a2c",
        "end": "0xfffffe0007c61bcb",
        "calls": ("0xfffffe0007c61b34",),
        "classification": "copied_user_state_signer",
        "tuple_source": "copied state guarded as EL0",
        "pc_control": "copied_user_pc_only",
        "el1_arbitrary_pc": False,
        "witnesses": ("[0xfffffe0007c61b1c] <+240>: and w6, w2, #0xc",),
    },
    {
        "address": "0xfffffe0007c61bcc",
        "end": "0xfffffe0007c61cc3",
        "calls": ("0xfffffe0007c61c8c",),
        "classification": "user_pc_setter",
        "tuple_source": "authenticated saved state guarded as EL0",
        "pc_control": "arbitrary_pc_but_el0_only",
        "el1_arbitrary_pc": False,
        "witnesses": ("[0xfffffe0007c61c70] <+164>: and w6, w2, #0xc",),
    },
    {
        "address": "0xfffffe0007c61dc4",
        "end": "0xfffffe0007c61f4f",
        "calls": ("0xfffffe0007c61ee8",),
        "classification": "user_cpsr_setter",
        "tuple_source": "authenticated saved state with old/new EL0 guards",
        "pc_control": "unchanged_user_pc",
        "el1_arbitrary_pc": False,
        "witnesses": (
            "[0xfffffe0007c61eb4] <+240>: and w6, w2, #0xc",
            "[0xfffffe0007c61ecc] <+264>: and w6, w2, #0xc",
        ),
    },
    {
        "address": "0xfffffe0007c6212c",
        "end": "0xfffffe0007c623ef",
        "calls": (
            "0xfffffe0007c621b8",
            "0xfffffe0007c622cc",
            "0xfffffe0007c62364",
        ),
        "classification": "user_state_converter",
        "tuple_source": "converted state guarded as EL0",
        "pc_control": "converted_user_pc_only",
        "el1_arbitrary_pc": False,
        "witnesses": (
            "[0xfffffe0007c6219c] <+112>: and w6, w2, #0xc",
            "[0xfffffe0007c622b0] <+388>: and w6, w2, #0xc",
            "[0xfffffe0007c62330] <+516>: and w6, w2, #0xc",
            "[0xfffffe0007c62348] <+540>: and w6, w2, #0xc",
        ),
    },
    {
        "address": "0xfffffe0008127df4",
        "end": "0xfffffe0008127fd7",
        "calls": ("0xfffffe0008127eac",),
        "classification": "syscall_restart",
        "tuple_source": "authenticated user syscall state",
        "pc_control": "existing_pc_minus_4",
        "el1_arbitrary_pc": False,
        "witnesses": (
            "[0xfffffe0008127e58] <+100>: mov w11, #-0x4",
            "[0xfffffe0008127e8c] <+152>: and w6, w2, #0xc",
            "[0xfffffe0008127ea4] <+176>: add x1, x1, w6, sxtw",
        ),
    },
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalized(text: str) -> str:
    return "\n".join(" ".join(line.split()) for line in text.splitlines())


def disassemble_call_windows(kernel: Path) -> str:
    argv = ["xcrun", "lldb", "--batch", "-o", f'target create "{kernel}"']
    for caller in CALLERS:
        for call in caller["calls"]:
            address = int(call, 16)
            argv.extend((
                "-o",
                f"disassemble -s {address - 0x60:#x} -e {address + 8:#x}",
            ))
    completed = subprocess.run(
        argv, check=False, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.returncode != 0:
        raise InventoryError(
            f"LLDB disassembly failed ({completed.returncode}):\n{completed.stdout}"
        )
    return completed.stdout


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InventoryError(f"cannot load {path}: {error}") from error


def _signer_record(snapshot: dict[str, Any]) -> dict[str, Any]:
    records = snapshot.get("evidence_bundle", {}).get("records", [])
    matches = [
        record for record in records
        if record.get("operation") == "analyze_function"
        and record.get("parameters", {}).get("procedure") == SIGNER_ADDRESS
    ]
    if len(matches) != 1:
        raise InventoryError(
            f"expected one REA signer record for {SIGNER_ADDRESS}, got {len(matches)}"
        )
    record = matches[0]
    if record.get("evidence_id") != SIGNER_EVIDENCE_ID:
        raise InventoryError("REA signer evidence ID drifted")
    return record


def _expected_calls() -> set[tuple[str, str, str]]:
    return {
        (call, caller["address"], SIGNER_ADDRESS)
        for caller in CALLERS for call in caller["calls"]
    }


def _observed_calls(record: dict[str, Any]) -> set[tuple[str, str, str]]:
    references = record.get("normalized_result", {}).get("incoming_references", [])
    return {
        (
            reference.get("source_address"),
            reference.get("source_procedure", {}).get("address"),
            reference.get("target_address"),
        )
        for reference in references
        if reference.get("kind", {}).get("call") is True
    }


def _verify_callers(record: dict[str, Any]) -> None:
    normalized = record.get("normalized_result", {})
    expected = {
        (caller["address"], caller["end"])
        for caller in CALLERS
    }
    observed: set[tuple[str, str | None]] = set()
    for caller in normalized.get("callers", []):
        ranges = caller.get("body", {}).get("ranges", [])
        observed.add((caller.get("address"), ranges[0].get("end") if ranges else None))
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise InventoryError(f"REA signer caller coverage drifted: missing={missing}, extra={extra}")

    expected_calls = _expected_calls()
    observed_calls = _observed_calls(record)
    if observed_calls != expected_calls:
        missing = sorted(expected_calls - observed_calls)
        extra = sorted(observed_calls - expected_calls)
        raise InventoryError(
            f"REA direct signer call coverage drifted: missing={missing}, extra={extra}"
        )


def _verify_copyio_snapshot(path: Path) -> None:
    if sha256(path) != COPYIO_SNAPSHOT_SHA256:
        raise InventoryError("copyio recovery REA snapshot SHA-256 drifted")
    snapshot = _load_json(path)
    records = snapshot.get("evidence_bundle", {}).get("records", [])
    matches = [
        record for record in records
        if record.get("operation") == "analyze_function"
        and record.get("parameters", {}).get("procedure") == "0xfffffe0007c53bc0"
        and record.get("evidence_id") == COPYIO_EVIDENCE_ID
    ]
    if len(matches) != 1:
        raise InventoryError("copyio recovery REA evidence is missing or changed")


def _verify_disassembly(text: str) -> None:
    observed = _normalized(text)
    for caller in CALLERS:
        for call in caller["calls"]:
            expected_call = _normalized(
                f"[{call}] bl {SIGNER_ADDRESS}"
            )
            # LLDB includes an offset field between the address and mnemonic.
            if f"[{call}]" not in observed or SIGNER_ADDRESS not in observed:
                raise InventoryError(f"missing exact signer call disassembly at {call}")
            del expected_call
        for witness in caller["witnesses"]:
            if _normalized(witness) not in observed:
                raise InventoryError(
                    f"instruction witness drifted for {caller['address']}: {witness}"
                )


def build_inventory(
    kernel: Path,
    signer_snapshot_path: Path,
    copyio_snapshot_path: Path,
    *,
    disassembly_text: str | None = None,
) -> dict[str, Any]:
    if sha256(kernel) != KERNEL_SHA256:
        raise InventoryError("exact com.apple.kernel SHA-256 does not match 23A341 profile")
    if sha256(signer_snapshot_path) != SIGNER_SNAPSHOT_SHA256:
        raise InventoryError("signer REA snapshot SHA-256 drifted")

    snapshot = _load_json(signer_snapshot_path)
    if snapshot.get("target", {}).get("sha256") != KERNEL_SHA256:
        raise InventoryError("REA signer snapshot is bound to a different kernel")
    signer_record = _signer_record(snapshot)
    _verify_callers(signer_record)
    _verify_copyio_snapshot(copyio_snapshot_path)

    disassembly = (
        disassembly_text if disassembly_text is not None
        else disassemble_call_windows(kernel)
    )
    _verify_disassembly(disassembly)

    kernel_bytes = kernel.read_bytes()
    absent_kdp_markers = (
        b"kdp_writeregs THREAD_STATE64",
        b"kdp_setintegerstate",
        b"kdp_machine_write_regs",
    )
    marker_presence = {
        marker.decode("ascii"): marker in kernel_bytes
        for marker in absent_kdp_markers
    }
    categories = Counter(caller["classification"] for caller in CALLERS)
    callers = [
        {
            key: value
            for key, value in caller.items()
            if key != "witnesses"
        }
        | {"instruction_witnesses": list(caller["witnesses"])}
        for caller in CALLERS
    ]

    return {
        "schema": "cyanide.signed-state-caller-inventory.v1",
        "build": "23A341",
        "product": "iPhone17,3",
        "artifact": {
            "path": str(kernel),
            "sha256": KERNEL_SHA256,
        },
        "rea": {
            "signer_address": SIGNER_ADDRESS,
            "signer_evidence_id": SIGNER_EVIDENCE_ID,
            "signer_snapshot": str(signer_snapshot_path),
            "signer_snapshot_sha256": SIGNER_SNAPSHOT_SHA256,
            "copyio_evidence_id": COPYIO_EVIDENCE_ID,
            "copyio_snapshot": str(copyio_snapshot_path),
            "copyio_snapshot_sha256": COPYIO_SNAPSHOT_SHA256,
        },
        "coverage": {
            "direct_call_count": sum(len(caller["calls"]) for caller in CALLERS),
            "caller_count": len(CALLERS),
            "all_direct_calls_classified": True,
            "unknown_callers": [],
            "classification_counts": dict(sorted(categories.items())),
        },
        "kdp_register_import": {
            "compiled_route_observed": False,
            "required_direct_signer_calls_observed": False,
            "diagnostic_string_presence": marker_presence,
            "reason": (
                "The source kdp_setintegerstate route necessarily invokes the external "
                "ml_sign_thread_state routine through two non-user CPSR mutations. REA's "
                "complete exact-address incoming-reference set contains no unclassified "
                "caller with that shape. The present KDP signer caller is only the fixed "
                "recognized-trap PC + 4 path."
            ),
        },
        "callers": callers,
        "conclusion": {
            "attacker_controlled_el1_pc_signer_callers": [],
            "direct_signer_route_to_arbitrary_el1_pc": False,
            "strongest_non_user_route": "hardware_exception_capture",
            "strongest_non_user_constraint": (
                "PC and CPSR are sourced from ELR_EL1/SPSR_EL1 at exception entry"
            ),
            "next_pivot": (
                "Stop searching direct signer xrefs on this image. A stock-relevant path "
                "must control a legitimate EL1 exception tuple before signing, or use a "
                "different PAC-protected kernel dispatch object reachable with physical KRW."
            ),
        },
        "limitations": [
            "This inventory is exact-build evidence and must not be rebased by slide alone.",
            "Absence of diagnostic strings is corroborative; complete REA call references are the primary evidence.",
            "The local XNU source is source-assisted reconciliation, not the shipped kernel itself.",
            "This audit performs no kernel writes and establishes no physical kcall or PAC bypass.",
        ],
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--signer-snapshot", required=True, type=Path)
    parser.add_argument("--copyio-snapshot", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = build_inventory(
            args.kernel,
            args.signer_snapshot,
            args.copyio_snapshot,
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
