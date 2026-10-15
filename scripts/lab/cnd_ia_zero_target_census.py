#!/usr/bin/env python3
"""Build the exact-kernel IA-zero instruction-pointer census.

The scanner is pinned to the extracted iOS 26.0 (23A341) iPhone17,3
``com.apple.kernel`` image.  It partitions every ``paciza`` instruction in
``__TEXT_EXEC`` into either a fixed target materialization or an
authenticate-then-resign translator, identifies results that are stored
outside the stack, and reconciles the three persistent lanes reviewed with
REA/Ghidra.

This is an inventory, not a signing oracle.  A translator accepts only a
pointer that already authenticates under its source PAC contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


KERNEL_SHA256 = "c32c7005fd8f702bf7f34730a512af5cb896a8c61b4a80b8400401f3897060ea"
KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"
BUILD = "23A341"
PRODUCT = "iPhone17,3"

TEXT_EXEC_VMADDR = 0xFFFFFE0007AB4000
TEXT_EXEC_FILEOFF = 2_424_832
TEXT_EXEC_SIZE = 0x856490

PACIZA_MASK = 0xFFFFFFE0
PACIZA_VALUE = 0xDAC123E0
AUTIA_X16_X17 = 0xDAC11230

EXPECTED_PACIZA_COUNT = 194
EXPECTED_FIXED_COUNT = 114
EXPECTED_TRANSLATOR_COUNT = 80
EXPECTED_UNIQUE_FIXED_TARGETS = 25
EXPECTED_DIRECT_STORE_COUNT = 14
EXPECTED_STACK_STORE_COUNT = 7

# (PAC site, store site, base register, effective x16 slot offset)
EXPECTED_PERSISTENT_STORES = {
    (0xFFFFFE0007C82A08, 0xFFFFFE0007C82A10, 26, 0x98),
    (0xFFFFFE0007E35EC0, 0xFFFFFE0007E35EC8, 0, 0x60),
    (0xFFFFFE0007E3619C, 0xFFFFFE0007E361A4, 0, 0x60),
    (0xFFFFFE0007E4B91C, 0xFFFFFE0007E4B924, 0, 0x60),
    (0xFFFFFE0007F21E30, 0xFFFFFE0007F21E38, 0, 0x60),
    (0xFFFFFE0007F2210C, 0xFFFFFE0007F22114, 0, 0x60),
    (0xFFFFFE00081DF4F8, 0xFFFFFE00081DF504, 1, 0x20),
}

CALLER_INSTRUCTION_WITNESSES = {
    0xFFFFFE00081DDFCC: 0x52800022,  # mov w2, #1
    0xFFFFFE00081DDFD8: 0x940004BC,  # bl translator
    0xFFFFFE00081DE7B4: 0xB941E109,  # ldr w9, [x8, #0x1e0]
    0xFFFFFE00081DE7BC: 0x52800049,  # mov w9, #2
    0xFFFFFE00081DE7C0: 0x1A89053C,  # cinc w28, w9, ne (2 or 3)
    0xFFFFFE00081DE850: 0xAA1C03E2,  # mov x2, x28
    0xFFFFFE00081DE85C: 0x9400029B,  # bl translator
    0xFFFFFE00082A6910: 0x528000A2,  # mov w2, #5 (no translated method)
    0xFFFFFE00082A691C: 0x97FCE26B,  # bl translator
    0xFFFFFE00082A6C20: 0x528000A2,  # mov w2, #5 (no translated method)
    0xFFFFFE00082A6C2C: 0x97FCE1A7,  # bl translator
}

REA_PROFILES: tuple[dict[str, Any], ...] = (
    {
        "name": "fixed_target_7e4ba38",
        "filename": "ia-zero-target-7e4ba38-rea-snapshot.json",
        "sha256": "d1777ea81774cc4a8007a5c01a1f17c18f3a140aa80ceaf533362ea4f04bdf5c",
        "procedure": 0xFFFFFE0007E4BA38,
        "evidence_id": "ev_bca5c7f4ff30f736b9a8617ec09ef58e8ef6c39ac53045a0f3c9d424e8b7e13c",
        "assembly": (
            "0xfffffe0007e4ba38: pacibsp",
            "0xfffffe0007e4ba5c: mov x24, x0",
        ),
        "pseudocode": (
            "if (param_1 != 0)",
            "DAT_fffffe000983fa4c = 0;",
        ),
        "referenced_string": "inpcb_timeout_run >= 0 && inpcb_timeout_run < 2",
    },
    {
        "name": "cluster_io_translator_7c81d6c",
        "filename": "ia-zero-translator-7c81d6c-rea-snapshot.json",
        "sha256": "be22c8dad27c88c69fbc39fddc7c680ed74832b22ec4f5ef666b7ab9bf47f8a0",
        "procedure": 0xFFFFFE0007C81D6C,
        "evidence_id": "ev_5db72c0835bcb40659993a76bdd0b250b0f6f2a236dceac3f004b6491689b34f",
        "assembly": (
            "0xfffffe0007c829ec: mov x17, #0xe4fe",
            "0xfffffe0007c829f0: autia x16, x17",
            "0xfffffe0007c82a08: paciza x16",
            "0xfffffe0007c82a10: str x16, [x26, #0x98]",
        ),
        "pseudocode": (
            "*(undefined8 *)(lVar26 + 0x98) = param_9;",
            '"BUSY bp found in cluster_io @%s:%d"',
        ),
        "referenced_string": "cluster_io",
    },
    {
        "name": "object_method_translator_81df2c8",
        "filename": "ia-zero-translator-81df2c8-rea-snapshot.json",
        "sha256": "ea409233dd66c24d1123481fbd14ab1bfb6a46ea200f87636e2d53a6174e38da",
        "procedure": 0xFFFFFE00081DF2C8,
        "evidence_id": "ev_1674d15a4df421c90317d8f18a5e364f2e5425cff50441eaff1886cb00656a5d",
        "assembly": (
            "0xfffffe00081df468: add x8, x16, #0x4d8",
            "0xfffffe00081df49c: add x8, x16, #0x4f8",
            "0xfffffe00081df4d0: add x8, x16, #0x500",
            "0xfffffe00081df4e0: autia x16, x17",
            "0xfffffe00081df4f8: paciza x16",
            "0xfffffe00081df504: stp x20, x16, [x1, #0x18]",
        ),
        "pseudocode": (
            "param_2[4] = lVar7;",
            "*(long **)(lVar7 + 0x238) = param_2;",
        ),
        "callers": {
            "0xfffffe00081ddf18",
            "0xfffffe00081de780",
            "0xfffffe00082a6828",
            "0xfffffe00082a6a0c",
        },
    },
    {
        "name": "object_method_selector_1_caller_81ddf18",
        "filename": "ia-zero-object-callers-ghidra-snapshot.json",
        "sha256": "a77ad42b471f0fc8c61e6e2da2dd72015b4cbb27e066c70008f80d0dfcc76623",
        "procedure": 0xFFFFFE00081DDF18,
        "evidence_id": "ev_b8284057cbeeec8ba04c80f48cb45cf28be5fc96e7a6a45ffdcf1c2356a32924",
        "assembly": (
            "0xfffffe00081ddfcc: mov w2, #0x1",
            "0xfffffe00081ddfd8: bl 0xfffffe00081df2c8",
            "0xfffffe00081de2c4: mov x17, #0x4d8",
            "0xfffffe00081de2e4: blraa x8, x17",
        ),
        "pseudocode": (
            "iVar7 = FUN_fffffe00081df2c8(param_1,&local_90,1,0,0);",
            "**(long **)(param_1[0xc] + 0x158) + 0x4d8",
            "*puVar3 = plStack_88;",
        ),
    },
    {
        "name": "object_method_selector_2_3_caller_81de780",
        "filename": "ia-zero-object-callers-ghidra-snapshot.json",
        "sha256": "a77ad42b471f0fc8c61e6e2da2dd72015b4cbb27e066c70008f80d0dfcc76623",
        "procedure": 0xFFFFFE00081DE780,
        "evidence_id": "ev_114bd426b0248c03a6413287032828cd54861aec3a093d1519bebef1b7cf1195",
        "assembly": (
            "0xfffffe00081de7b4: ldr w9, [x8, #0x1e0]",
            "0xfffffe00081de7bc: mov w9, #0x2",
            "0xfffffe00081de7c0: cinc w28, w9, ne",
            "0xfffffe00081de85c: bl 0xfffffe00081df2c8",
            "0xfffffe00081dec48: mov x17, #0x500",
            "0xfffffe00081ded94: mov x17, #0x4f8",
        ),
        "pseudocode": (
            "uVar18 = 2;",
            "uVar18 = 3;",
            "FUN_fffffe00081df2c8(param_1,&local_90,uVar18,lVar28,0);",
            "*plVar27 + 0x4f8",
            "*plVar27 + 0x500",
        ),
    },
    {
        "name": "io_service_pm_driver_callout_parent_81ddc40",
        "filename": "ia-zero-object-parent-ghidra-snapshot.json",
        "sha256": "80c0a1a48bc192df9ad4f662bc734b4d32e08e7e18d24d7ac091cb5813a33b1a",
        "procedure": 0xFFFFFE00081DDC40,
        "evidence_id": "ev_fcc0459e89625f87574fb94b187eb76212f7cac77918b2de8e1a8c93853537dc",
        "assembly": (
            "0xfffffe00081ddd78: ldr w9, [x8, #0x1e0]",
            "0xfffffe00081ddda8: bl 0xfffffe00081ddf18",
            "0xfffffe00081dddcc: bl 0xfffffe00081de780",
            "0xfffffe00081ddf10: add x0, x0, #0x13",
        ),
        "pseudocode": (
            "FUN_fffffe00081de780(param_1);",
            "FUN_fffffe00081ddf18(param_1);",
            'FUN_fffffe00082fa814("IOService::pmDriverCallout bad machine state %x @%s:%d")',
        ),
        "referenced_string": "IOServicePM.cpp",
    },
    {
        "name": "io_service_pm_action_driver_callout_done_81df254",
        "filename": "io-service-pm-action-done-ghidra-snapshot.json",
        "sha256": "50285b870a1256d01e970539b22720b78e85233d656f40739835369ecb8c9ff2",
        "procedure": 0xFFFFFE00081DF254,
        "evidence_id": "ev_c0a00b677a7368577edb69fb8785fd9822a52a284cb9370670c1a15bcb64c951",
        "assembly": (
            "0xfffffe00081df254: pacibsp",
        ),
        "pseudocode": (
            "*(ushort *)(param_2 + 0xe0) = *(ushort *)(param_2 + 0xe0) & 0xfdff;",
        ),
    },
)


class CensusError(RuntimeError):
    """The exact-build census or one of its evidence contracts drifted."""


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def decode_adrp(word: int, pc: int) -> tuple[int, int] | None:
    if word & 0x9F000000 != 0x90000000:
        return None
    register = word & 0x1F
    immediate = ((word >> 5) & 0x7FFFF) << 2 | ((word >> 29) & 0x3)
    page = (pc & ~0xFFF) + (_sign_extend(immediate, 21) << 12)
    return register, page & 0xFFFFFFFFFFFFFFFF


def decode_add_immediate(word: int) -> tuple[int, int, int] | None:
    if word & 0xFF000000 != 0x91000000:
        return None
    destination = word & 0x1F
    source = (word >> 5) & 0x1F
    immediate = (word >> 10) & 0xFFF
    if word & (1 << 22):
        immediate <<= 12
    return destination, source, immediate


def decode_fixed_target(words: list[int], index: int, pc: int) -> int | None:
    if index < 2:
        return None
    register = words[index] & 0x1F
    adrp = decode_adrp(words[index - 2], pc - 8)
    add = decode_add_immediate(words[index - 1])
    if adrp is None or add is None:
        return None
    adrp_register, page = adrp
    destination, source, immediate = add
    if (adrp_register, destination, source) != (register, register, register):
        return None
    return (page + immediate) & 0xFFFFFFFFFFFFFFFF


def decode_store(word: int, register: int) -> tuple[str, int, int] | None:
    """Return (kind, base register, effective slot offset)."""

    if word & 0xFFC00000 == 0xF9000000 and word & 0x1F == register:
        return "str", (word >> 5) & 0x1F, ((word >> 10) & 0xFFF) * 8

    if word & 0xFFC00000 == 0xA9000000:
        first = word & 0x1F
        second = (word >> 10) & 0x1F
        if register not in (first, second):
            return None
        immediate = _sign_extend((word >> 15) & 0x7F, 7) * 8
        if second == register:
            immediate += 8
            kind = "stp_second"
        else:
            kind = "stp_first"
        return kind, (word >> 5) & 0x1F, immediate
    return None


def _previous_auth_site(words: list[int], index: int) -> int | None:
    for candidate in range(index - 1, max(-1, index - 17), -1):
        if words[candidate] == AUTIA_X16_X17:
            return candidate
    return None


def _source_modifier(words: list[int], auth_index: int) -> str:
    # Record a constant MOVZ source when present.  Address-diversified paths
    # deliberately remain descriptive instead of pretending to be constants.
    for candidate in range(auth_index - 1, max(-1, auth_index - 5), -1):
        word = words[candidate]
        if word & 0xFF80001F == 0xD2800011:
            immediate = (word >> 5) & 0xFFFF
            shift = ((word >> 21) & 0x3) * 16
            return f"constant {_hex(immediate << shift)}"
    return "runtime/address-diversified x17"


def scan_text_exec(text: bytes) -> list[dict[str, Any]]:
    if len(text) % 4:
        raise CensusError("__TEXT_EXEC byte length is not instruction aligned")
    words = list(struct.unpack(f"<{len(text) // 4}I", text))
    sites: list[dict[str, Any]] = []
    for index, word in enumerate(words):
        if word & PACIZA_MASK != PACIZA_VALUE:
            continue
        address = TEXT_EXEC_VMADDR + index * 4
        register = word & 0x1F
        fixed_target = decode_fixed_target(words, index, address)
        auth_index = _previous_auth_site(words, index)
        if fixed_target is not None and auth_index is not None:
            raise CensusError(f"ambiguous PACIZA class at {_hex(address)}")
        if fixed_target is not None:
            classification = "fixed_target"
        elif auth_index is not None:
            classification = "authenticate_then_resign"
        else:
            classification = "unclassified"

        stores = []
        for distance in range(1, min(7, len(words) - index)):
            decoded = decode_store(words[index + distance], register)
            if decoded is None:
                continue
            kind, base_register, offset = decoded
            stores.append({
                "site": TEXT_EXEC_VMADDR + (index + distance) * 4,
                "kind": kind,
                "base_register": base_register,
                "slot_offset": offset,
                "scope": "stack" if base_register == 31 else "persistent",
            })

        site: dict[str, Any] = {
            "site": address,
            "register": register,
            "classification": classification,
            "stores": stores,
        }
        if fixed_target is not None:
            site["target"] = fixed_target
        if auth_index is not None:
            site["auth_site"] = TEXT_EXEC_VMADDR + auth_index * 4
            site["source_modifier"] = _source_modifier(words, auth_index)
        sites.append(site)
    return sites


def _format_site(site: dict[str, Any]) -> dict[str, Any]:
    result = dict(site)
    for key in ("site", "target", "auth_site"):
        if key in result:
            result[key] = _hex(int(result[key]))
    formatted_stores = []
    for store in result["stores"]:
        formatted = dict(store)
        formatted["site"] = _hex(int(formatted["site"]))
        formatted["base_register"] = (
            "sp" if formatted["base_register"] == 31
            else f"x{formatted['base_register']}"
        )
        formatted["slot_offset"] = _hex(int(formatted["slot_offset"]))
        formatted_stores.append(formatted)
    result["stores"] = formatted_stores
    result["register"] = f"x{result['register']}"
    return result


def verify_profile(sites: list[dict[str, Any]]) -> None:
    fixed = [site for site in sites if site["classification"] == "fixed_target"]
    translators = [
        site for site in sites
        if site["classification"] == "authenticate_then_resign"
    ]
    unclassified = [site for site in sites if site["classification"] == "unclassified"]
    direct = [site for site in sites if site["stores"]]
    stack = [
        site for site in direct
        if any(store["scope"] == "stack" for store in site["stores"])
    ]
    persistent = [
        site for site in direct
        if any(store["scope"] == "persistent" for store in site["stores"])
    ]
    counts = (
        len(sites), len(fixed), len(translators),
        len({site["target"] for site in fixed}), len(direct), len(stack),
    )
    expected = (
        EXPECTED_PACIZA_COUNT, EXPECTED_FIXED_COUNT,
        EXPECTED_TRANSLATOR_COUNT, EXPECTED_UNIQUE_FIXED_TARGETS,
        EXPECTED_DIRECT_STORE_COUNT, EXPECTED_STACK_STORE_COUNT,
    )
    if counts != expected or unclassified:
        raise CensusError(
            "PACIZA partition drifted: "
            f"observed={counts}, expected={expected}, "
            f"unclassified={len(unclassified)}"
        )

    observed_stores = {
        (site["site"], store["site"], store["base_register"], store["slot_offset"])
        for site in persistent
        for store in site["stores"]
        if store["scope"] == "persistent"
    }
    if observed_stores != EXPECTED_PERSISTENT_STORES:
        raise CensusError(
            "persistent PACIZA store set drifted: "
            f"observed={sorted(observed_stores)!r}"
        )


def _load_json(path: Path) -> dict[str, Any]:
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CensusError(f"cannot load REA snapshot {path}: {error}") from error
    if not isinstance(result, dict):
        raise CensusError(f"REA snapshot is not an object: {path}")
    return result


def verify_rea_snapshot(path: Path, profile: dict[str, Any]) -> dict[str, Any]:
    if sha256(path) != profile["sha256"]:
        raise CensusError(f"REA snapshot SHA-256 drifted: {profile['name']}")
    snapshot = _load_json(path)
    if snapshot.get("target", {}).get("sha256") != KERNEL_SHA256:
        raise CensusError(f"REA snapshot kernel drifted: {profile['name']}")
    expected_procedure = _hex(profile["procedure"])
    records = [
        record for record in snapshot.get("evidence_bundle", {}).get("records", [])
        if record.get("operation") == "analyze_function"
        and record.get("parameters", {}).get("procedure") == expected_procedure
    ]
    if len(records) != 1:
        raise CensusError(
            f"expected one REA record for {expected_procedure}: {profile['name']}"
        )
    record = records[0]
    if record.get("evidence_id") != profile["evidence_id"]:
        raise CensusError(f"REA evidence ID drifted: {profile['name']}")
    normalized = record.get("normalized_result", {})
    assembly = set(normalized.get("assembly", []))
    for witness in profile.get("assembly", ()):
        if witness not in assembly:
            raise CensusError(
                f"REA assembly witness missing for {profile['name']}: {witness}"
            )
    pseudocode = normalized.get("pseudocode", "")
    for witness in profile.get("pseudocode", ()):
        if witness not in pseudocode:
            raise CensusError(
                f"REA pseudocode witness missing for {profile['name']}: {witness}"
            )
    if "referenced_string" in profile:
        strings = {
            item.get("value") for item in normalized.get("referenced_strings", [])
            if isinstance(item, dict)
        }
        if profile["referenced_string"] not in strings:
            raise CensusError(f"REA semantic string drifted: {profile['name']}")
    if "callers" in profile:
        callers = {
            caller.get("address") for caller in normalized.get("callers", [])
            if isinstance(caller, dict)
        }
        if callers != profile["callers"]:
            raise CensusError(f"REA caller set drifted: {profile['name']}")
    return {
        "name": profile["name"],
        "snapshot": str(path),
        "snapshot_sha256": profile["sha256"],
        "procedure": expected_procedure,
        "evidence_id": profile["evidence_id"],
        "reconciled": True,
    }


def _by_site(sites: Iterable[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    return {int(site["site"]): site for site in sites}


def build_census(kernel: Path, rea_snapshots: list[Path]) -> dict[str, Any]:
    if sha256(kernel) != KERNEL_SHA256:
        raise CensusError("exact com.apple.kernel SHA-256 does not match profile")
    kernel_bytes = kernel.read_bytes()
    end = TEXT_EXEC_FILEOFF + TEXT_EXEC_SIZE
    if end > len(kernel_bytes):
        raise CensusError("exact __TEXT_EXEC range exceeds kernel artifact")
    sites = scan_text_exec(kernel_bytes[TEXT_EXEC_FILEOFF:end])
    verify_profile(sites)

    for address, expected_word in CALLER_INSTRUCTION_WITNESSES.items():
        offset = TEXT_EXEC_FILEOFF + address - TEXT_EXEC_VMADDR
        if offset < 0 or offset + 4 > len(kernel_bytes):
            raise CensusError(f"caller witness is outside __TEXT_EXEC: {_hex(address)}")
        observed_word = struct.unpack_from("<I", kernel_bytes, offset)[0]
        if observed_word != expected_word:
            raise CensusError(
                f"caller instruction drifted at {_hex(address)}: "
                f"expected={expected_word:#010x}, observed={observed_word:#010x}"
            )

    paths_by_name = {path.name: path for path in rea_snapshots}
    expected_names = {profile["filename"] for profile in REA_PROFILES}
    if set(paths_by_name) != expected_names:
        raise CensusError(
            "exactly the expected REA snapshots are required: "
            f"{sorted(expected_names)!r}"
        )
    rea = [
        verify_rea_snapshot(paths_by_name[profile["filename"]], profile)
        for profile in REA_PROFILES
    ]

    fixed_targets: dict[int, list[int]] = defaultdict(list)
    for site in sites:
        if site["classification"] == "fixed_target":
            fixed_targets[int(site["target"])].append(int(site["site"]))
    indexed = _by_site(sites)
    persistent_sites = sorted(site for site, *_ in EXPECTED_PERSISTENT_STORES)

    return {
        "schema": "cyanide.ia-zero-target-census.v1",
        "build": BUILD,
        "product": PRODUCT,
        "kernel_uuid": KERNEL_UUID,
        "artifact": {"path": str(kernel), "sha256": KERNEL_SHA256},
        "text_exec": {
            "vmaddr": _hex(TEXT_EXEC_VMADDR),
            "fileoff": _hex(TEXT_EXEC_FILEOFF),
            "size": _hex(TEXT_EXEC_SIZE),
        },
        "summary": {
            "paciza_sites": len(sites),
            "fixed_target_signings": sum(
                site["classification"] == "fixed_target" for site in sites
            ),
            "unique_fixed_targets": len(fixed_targets),
            "authenticate_then_resign_translators": sum(
                site["classification"] == "authenticate_then_resign"
                for site in sites
            ),
            "direct_store_sites": sum(bool(site["stores"]) for site in sites),
            "stack_only_store_sites": EXPECTED_STACK_STORE_COUNT,
            "persistent_store_sites": len(persistent_sites),
            "partition_complete": True,
        },
        "fixed_targets": [
            {
                "target": _hex(target),
                "sign_sites": [_hex(site) for site in sorted(sign_sites)],
                "persistent": any(site in persistent_sites for site in sign_sites),
            }
            for target, sign_sites in sorted(fixed_targets.items())
        ],
        "persistent_lanes": [_format_site(indexed[site]) for site in persistent_sites],
        "all_sites": [_format_site(site) for site in sites],
        "rea": rea,
        "semantic_review": [
            {
                "target": "0xfffffe0007e4ba38",
                "source_object_global": "0xfffffe000983fa38",
                "source_field_offset": "0x0000000000000060",
                "decision": "reject_as_dispatch_target",
                "reason": (
                    "inpcb timeout runner mutates broad network timeout state and "
                    "performs authenticated indirect callbacks; x0 is only a late boolean"
                ),
            },
            {
                "pac_site": "0xfffffe0007c82a08",
                "store": "cluster_io buffer + 0x98",
                "translation": "IA/e4fe-valid callback -> IA/zero",
                "decision": "retain_as_constrained_translator",
                "constraint": (
                    "input must already authenticate under discriminator 0xe4fe; "
                    "ordinary UI/Tips launch did not exercise this site"
                ),
            },
            {
                "pac_site": "0xfffffe00081df4f8",
                "store": "operation node + 0x20",
                "translation": (
                    "authenticated address-diversified vtable slot +0x4d8/+0x4f8/+0x500 "
                    "-> IA/zero"
                ),
                "decision": "resolved_io_service_pm_runtime_harvest_candidate",
                "constraint": (
                    "the node is temporary and all three IOService PM methods normally "
                    "need x1-x2 or x1-x3; the proven braaz-x1 transport controls only "
                    "x0 and occupies x1 with the IA-zero target"
                ),
                "parent": {
                    "procedure": "0xfffffe00081ddc40",
                    "symbol": "IOService::pmDriverCallout",
                    "reason_field": "pwrMgt + 0x1e0 (low 32 bits)",
                    "evidence": "REA/Ghidra plus IOServicePM.cpp strings",
                },
                "caller_routing": [
                    {
                        "caller": "0xfffffe00081ddf18",
                        "pm_reason": 2,
                        "selector": 1,
                        "method_slot": "0x4d8",
                        "method": "IOService::setPowerState(powerState, provider)",
                        "required_registers": "x0-x2",
                        "evidence": "REA/Ghidra and Apple XNU IOServicePM.cpp",
                    },
                    {
                        "caller": "0xfffffe00081de780",
                        "pm_reason": "0 or 1",
                        "selector": "2 for reason 0, 3 for reason 1",
                        "method_slot": "0x4f8 or 0x500",
                        "method": (
                            "IOService::powerStateWillChangeTo(flags, state, provider) "
                            "or powerStateDidChangeTo(flags, state, provider)"
                        ),
                        "required_registers": "x0-x3",
                        "evidence": "REA/Ghidra and Apple XNU IOServicePM.cpp",
                    },
                    {
                        "caller": "0xfffffe00082a6828",
                        "selector": 5,
                        "method_slot": None,
                        "evidence": "exact instruction witness",
                    },
                    {
                        "caller": "0xfffffe00082a6a0c",
                        "selector": 5,
                        "method_slot": None,
                        "evidence": "exact instruction witness",
                    },
                ],
                "vm_runtime_observation": {
                    "kernel_slide": "0x0000000026940000",
                    "root_domain_global_static": "0xfffffe0009816ce0",
                    "root_domain_object": "0xfffffe2fa9f83c00",
                    "power_management_object": "0xfffffe1e45fa4d00",
                    "driver_call_entry": "0xfffffe29ddfea000",
                    "signed_callback": "0x45e27e002eb1dc40",
                    "stripped_callback": "0xfffffe002eb1dc40",
                    "callback_static": "0xfffffe00081ddc40",
                    "callback_param0": "0xfffffe2fa9f83c00",
                    "observed_reason": 1,
                    "staged_reason": 2,
                    "staged_parameter_count": 1,
                    "power_state": 4,
                    "translator_pac_site_live": "0xfffffe002eb1f4f8",
                    "translated_method_raw": "0xfffffe002eb35f70",
                    "translated_method_ia_zero": "0x1799fe002eb35f70",
                    "selector_1_call_site_live": "0xfffffe002eb1e2e4",
                    "selector_1_arguments": {
                        "x0": "0xfffffe2fa9f83c00",
                        "x1": "0x0000000000000004",
                        "x2": "0xfffffe2fa9f83c00",
                    },
                    "call_skipped": True,
                    "state_restored": True,
                    "witness": "io-service-pm-ia-zero-kdp-witness.json",
                    "status": (
                        "debugger-assisted callback transplant reached the selector-1 "
                        "translator and authenticated call boundary"
                    ),
                },
                "completion_callback": {
                    "procedure": "0xfffffe00081df254",
                    "semantic_name": "IOService::actionDriverCalloutDone",
                    "busy_flag_field": "pwrMgt + 0xe0 (16 bits)",
                    "busy_flag_mask": "0x0200",
                    "clear_operation": "flags &= 0xfdff",
                    "runtime_observation": "0x0710 -> 0x0510 before manual restoration",
                },
            },
        ],
        "capability": {
            "proven": (
                "complete exact-kernel census, a cross-object signed PM callback "
                "transplant, and deterministic selector-1 IA-zero method harvesting"
            ),
            "signing_oracle": False,
            "arbitrary_kcall": False,
            "general_pac_bypass": False,
        },
        "next_boundary": {
            "target": (
                "automate the proven PM callback transplant through the lab KRW path "
                "without debugger register redirection"
            ),
            "steps": [
                "add a distinct lab mode that resolves the root domain and validates every source field",
                "save busy flags, parameter count, reason, result, and every sacrificial timer field",
                "stage reason 2 and count 1, then install the already-signed pmDriverCallout callback plus root-domain param0",
                "arm once with the current power state so the real method receives a same-state request",
                "wait for the action-done busy-bit clear before restoring all fields and destroying the timer",
                "retain debugger breakpoints as an optional witness layer rather than a functional dependency",
            ],
        },
        "limitations": [
            "All addresses and counts are pinned to one exact kernel artifact.",
            "PACIZA occurrence does not imply attacker control of the unsigned input.",
            "Both translators reject an invalid source-domain pointer before re-signing.",
            "The cluster_io breakpoint non-hit is bounded negative evidence, not proof of unreachability.",
            "Ordinary VM UI, lock, radio, and drawing activity did not naturally reach the PM translator.",
            "The PM callback transplant is debugger-assisted; an autonomous app path is not yet proven.",
            "The first selector-1 witness skipped the real setPowerState call at its blraa boundary.",
            "The resolved PM targets are not directly compatible with the current one-argument transport.",
            "No new pointer signature, arbitrary kcall, or full PAC bypass is claimed.",
        ],
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument(
        "--rea-snapshot", required=True, type=Path, action="append",
        help="repeat for each pinned semantic-review snapshot",
    )
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = build_census(args.kernel, args.rea_snapshot)
    except CensusError as error:
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
