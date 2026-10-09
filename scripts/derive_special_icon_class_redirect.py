#!/usr/bin/env python3
"""Derive/verify the offline 23A341 Clock/Calendar class redirect.

This tool is deliberately read-only. It proves that SBHIconModel's hard-coded
Clock/Calendar selector has a packed preoptimized dispatch entry and encodes a
redirect to Apple's ordinary applicationIconClass implementation. It does not
connect to a device or perform a write.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import zipfile
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from derive_flat_icon_imp_redirect import (  # noqa: E402
    CacheReader,
    READONLY_SUFFIX,
    READONLY_UUID,
    compact_methods,
    decoded_qwords,
    exact_trustcache,
    mapping_metadata,
    signed_38,
    subcache_member,
)
from derive_flat_icon_patch import (  # noqa: E402
    BUILD,
    DEVICE,
    IMAGE,
    MAIN_UUID,
    SUB_UUID,
    cache_header,
    digest_file,
    require,
    verify_code_directory,
)


PAGE_SIZE = 0x4000
GUARD_SIZE = 32
FAST_DATA_MASK = 0x00007FFFFFFFFFF8
PREOPT_RAW_IMP_MASK = (1 << 38) - 1
READ_ONLY_DATA_FLAG = 1 << 5

CLASS_NAME = "SBHIconModel"
CLASS_VM = 0x1EDA01028
CLASS_RO_VM = 0x1EEBE3740
METHOD_LIST_VM = 0x1BE1EEE28
METACLASS_VM = 0x1EDA02670
METACLASS_RO_VM = 0x1F3FE2E20
CLASS_METHOD_LIST_VM = 0x1BE1DA830

TARGET_SELECTOR = "iconClassForApplicationWithBundleIdentifier:"
TARGET_TYPES = "#24@0:8@16"
TARGET_METHOD_VM = 0x1BE19DB3C
TARGET_ENTRY_VM = 0x1BE1EF2EC
TARGET_SELECTOR_OFFSET = 0x89102D

REPLACEMENT_SELECTOR = "applicationIconClass"
REPLACEMENT_TYPES = "#16@0:8"
REPLACEMENT_METHOD_VM = 0x1BE19D9E8
REPLACEMENT_ENTRY_VM = 0x1BE1DA85C
REPLACEMENT_METHOD_LENGTH = 0x3C
REPLACEMENT_METHOD_BYTES = bytes.fromhex(
    "7f2303d5fd7bbfa9fd030091a1ed169021801f91c20615f042000991000080d2"
    "b074f497fd7bc1a8ff2303d5d0071eca5000f0b6208e38d4346c9214"
)

SPECIAL_HELPER_VM = 0x1BE19DA24
SPECIAL_HELPER_LENGTH = TARGET_METHOD_VM - SPECIAL_HELPER_VM
SPECIAL_HELPER_SHA256 = (
    "96a4efb57027fed323e3b7f1b38bfa0618e0b17461720974f8fa07ee65f2dcef"
)
CLOCK_IDENTIFIER_VM = 0x1BE232EC0
CALENDAR_IDENTIFIER_VM = 0x1BE232EE0

SELECTOR_BASE_VM = 0x1FAC21900
PREOPT_CACHE_VM = 0x1FFC32E78
PREOPT_CACHE_SLOT = 68
PREOPT_ENTRY_VM = 0x1FFC330A8
PREOPT_ENTRY_VALUE = 0x22440B400BE18D3B
REPLACEMENT_ENTRY_VALUE = 0x22440B400BE18D90

# The already-confirmed .34 experiment is useful evidence about the mapping,
# but its ticket is page-specific and cannot authorize this different frame.
PRIOR_CONFIRMED_ENTRY_VM = 0x1FFC27458


def run(command: list[str]):
    import subprocess

    result = subprocess.run(command, text=True, capture_output=True)
    require(result.returncode == 0,
            f"command failed: {' '.join(command)}\n{result.stderr}")
    return result


def objc_metadata(ipsw_tool: str, cache: Path) -> tuple[str, int]:
    result = run([ipsw_tool, "dyld", "macho", str(cache), IMAGE,
                  "--objc", "--verbose", "--no-color"])
    blocks = re.findall(r"@interface SBHIconModel\s*:.*?@end",
                        result.stdout, re.DOTALL)
    require(len(blocks) == 1, "could not uniquely resolve SBHIconModel")
    block = blocks[0]
    class_matches = re.findall(
        r"@interface SBHIconModel\b[^\n]*// (0x[0-9a-f]+)", block)
    target_matches = re.findall(
        r"// (0x[0-9a-f]+)\s*\n- \(Class\)"
        r"iconClassForApplicationWithBundleIdentifier:\(id\)identifier;",
        block)
    replacement_matches = re.findall(
        r"// (0x[0-9a-f]+)\s*\n\+ \(Class\)applicationIconClass;",
        block)
    require(class_matches == [hex(CLASS_VM)] and
            target_matches == [hex(TARGET_METHOD_VM)] and
            replacement_matches == [hex(REPLACEMENT_METHOD_VM)],
            "Objective-C class or method identity changed")
    selector_base_matches = re.findall(
        r"rel method sel base off\s*:\s*(0x[0-9a-f]+)", result.stderr)
    require(len(selector_base_matches) == 1,
            "relative-method selector base was not reported")
    selector_base = (cache_header(cache)["sharedRegionStart"] +
                     int(selector_base_matches[0], 16))
    require(selector_base == SELECTOR_BASE_VM,
            "relative-method selector base changed")
    return block, selector_base


def derive(ipsw: Path, cache: Path, ipsw_tool: str) -> dict:
    require(cache_header(cache)["uuid"] == MAIN_UUID,
            "main cache UUID changed")
    readonly_cache = subcache_member(cache, READONLY_SUFFIX, READONLY_UUID)
    text_cache = cache.with_name(cache.name + ".19")
    require(cache_header(text_cache)["uuid"] == SUB_UUID,
            "text subcache UUID changed")
    reader = CacheReader([cache, text_cache, readonly_cache])

    _, selector_base = objc_metadata(ipsw_tool, cache)

    isa, superclass, cache_buckets, cache_properties, data_bits = \
        decoded_qwords(ipsw_tool, cache, CLASS_VM, 5)
    class_ro = data_bits & FAST_DATA_MASK
    class_ro_words = decoded_qwords(ipsw_tool, cache, class_ro, 9)
    require(isa == METACLASS_VM and class_ro == CLASS_RO_VM and
            reader.cstring(class_ro_words[3]) == CLASS_NAME and
            class_ro_words[4] == METHOD_LIST_VM,
            "SBHIconModel class metadata changed")

    _, _, _, _, metaclass_data_bits = decoded_qwords(
        ipsw_tool, cache, METACLASS_VM, 5)
    metaclass_ro = metaclass_data_bits & FAST_DATA_MASK
    metaclass_ro_words = decoded_qwords(
        ipsw_tool, cache, metaclass_ro, 9)
    require(metaclass_ro == METACLASS_RO_VM and
            reader.cstring(metaclass_ro_words[3]) == CLASS_NAME and
            metaclass_ro_words[4] == CLASS_METHOD_LIST_VM,
            "SBHIconModel metaclass metadata changed")

    method_header, methods = compact_methods(
        reader, selector_base, METHOD_LIST_VM)
    class_method_header, class_methods = compact_methods(
        reader, selector_base, CLASS_METHOD_LIST_VM)
    targets = [item for item in methods
               if item["selector"] == TARGET_SELECTOR]
    replacements = [item for item in class_methods
                    if item["selector"] == REPLACEMENT_SELECTOR]
    require(len(targets) == len(replacements) == 1,
            "target or replacement method is not unique")
    target = targets[0]
    replacement = replacements[0]
    require(target["entry"] == TARGET_ENTRY_VM and
            target["selectorOffset"] == TARGET_SELECTOR_OFFSET and
            target["types"] == TARGET_TYPES and
            target["imp"] == TARGET_METHOD_VM,
            "target compact method changed")
    require(replacement["entry"] == REPLACEMENT_ENTRY_VM and
            replacement["types"] == REPLACEMENT_TYPES and
            replacement["imp"] == REPLACEMENT_METHOD_VM,
            "replacement compact method changed")
    require(reader.cstring(CLOCK_IDENTIFIER_VM) == "com.apple.mobiletimer" and
            reader.cstring(CALENDAR_IDENTIFIER_VM) == "com.apple.mobilecal",
            "special bundle-identifier constants changed")

    require(cache_properties == PREOPT_CACHE_VM,
            "class preoptimized-cache pointer changed")
    fallback, hash_params, occupied_flags, unused = struct.unpack(
        "<qHHI", reader.read(PREOPT_CACHE_VM, 16))
    shift = hash_params & 0x1F
    mask = hash_params >> 5
    occupied = occupied_flags & 0x3FFF
    has_inlines = (occupied_flags >> 14) & 1
    require(unused >> 31 == 1 and mask + 1 <= 2048,
            "preoptimized-cache header changed")
    slot = (TARGET_SELECTOR_OFFSET >> shift) & mask
    entry_address = PREOPT_CACHE_VM + 16 + slot * 8
    entry_value = struct.unpack("<Q", reader.read(entry_address, 8))[0]
    selector_offset = entry_value >> 38
    raw_imp_offset = signed_38(entry_value)
    decoded_imp = CLASS_VM - raw_imp_offset * 4
    require(slot == PREOPT_CACHE_SLOT and entry_address == PREOPT_ENTRY_VM and
            entry_value == PREOPT_ENTRY_VALUE and
            selector_offset == TARGET_SELECTOR_OFFSET and
            decoded_imp == TARGET_METHOD_VM,
            "preoptimized target dispatch entry changed")

    replacement_delta = CLASS_VM - REPLACEMENT_METHOD_VM
    require(replacement_delta % 4 == 0,
            "replacement IMP is not word-aligned to the target class")
    replacement_raw = replacement_delta // 4
    require(-(1 << 37) <= replacement_raw < (1 << 37),
            "replacement IMP does not fit the 38-bit cache field")
    replacement_entry = ((selector_offset << 38) |
                         (replacement_raw & PREOPT_RAW_IMP_MASK))
    require(replacement_entry == REPLACEMENT_ENTRY_VALUE and
            CLASS_VM - signed_38(replacement_entry) * 4 ==
            REPLACEMENT_METHOD_VM,
            "replacement dispatch encoding changed")
    require((entry_value >> 32) == (replacement_entry >> 32),
            "redirect would require more than one low-word write")

    target_guard = reader.read(TARGET_ENTRY_VM, GUARD_SIZE)
    dispatch_guard = reader.read(PREOPT_ENTRY_VM, GUARD_SIZE)
    redirected_guard = bytearray(dispatch_guard)
    struct.pack_into("<Q", redirected_guard, 0, replacement_entry)
    require(dispatch_guard[4:] == redirected_guard[4:],
            "redirect modifies more than the first low word")

    target_method = reader.read(
        TARGET_METHOD_VM, 0x1BE19DBB0 - TARGET_METHOD_VM)
    replacement_method = reader.read(
        REPLACEMENT_METHOD_VM, REPLACEMENT_METHOD_LENGTH)
    helper = reader.read(SPECIAL_HELPER_VM, SPECIAL_HELPER_LENGTH)
    require(replacement_method == REPLACEMENT_METHOD_BYTES,
            "replacement implementation bytes changed")
    require(hashlib.sha256(helper).hexdigest() == SPECIAL_HELPER_SHA256,
            "special-selection helper bytes changed")

    target_mapping = reader.mapping_for(TARGET_METHOD_VM, len(target_method))
    replacement_mapping = reader.mapping_for(
        REPLACEMENT_METHOD_VM, len(replacement_method))
    dispatch_mapping = reader.mapping_for(PREOPT_ENTRY_VM, GUARD_SIZE)
    require(target_mapping["uuid"] == replacement_mapping["uuid"] ==
            SUB_UUID and
            target_mapping["initProt"] == target_mapping["maxProt"] == 5 and
            replacement_mapping["initProt"] ==
            replacement_mapping["maxProt"] == 5,
            "target or replacement is outside the pinned RX subcache")
    require(dispatch_mapping["uuid"] == READONLY_UUID and
            dispatch_mapping["initProt"] ==
            dispatch_mapping["maxProt"] == 1,
            "dispatch entry is outside the pinned read-only subcache")

    dispatch_info = mapping_metadata(
        ipsw_tool, cache, READONLY_UUID, PREOPT_ENTRY_VM, GUARD_SIZE)
    require(dispatch_info.get("flags", 0) & READ_ONLY_DATA_FLAG and
            dispatch_info["max_prot"] == dispatch_info["init_prot"] == 1,
            "dispatch page is not marked READ_ONLY_DATA")

    trusted = exact_trustcache(ipsw)
    text_code_directory = verify_code_directory(
        text_cache, cache_header(text_cache), trusted)
    readonly_code_directory = verify_code_directory(
        readonly_cache, cache_header(readonly_cache), trusted)

    return {
        "schemaVersion": 1,
        "purpose": (
            "Offline derivation of a shared SBHIconModel Clock/Calendar "
            "special-class dispatch redirect; no writer included"
        ),
        "runtimeVerified": False,
        "os": {
            "productVersion": "26.0",
            "productBuildVersion": BUILD,
            "productType": DEVICE,
            "architecture": "arm64e",
            "identitySource": "local IPSW; device not queried",
        },
        "cache": {
            "main": {
                "fileName": cache.name,
                "uuid": cache_header(cache)["uuid"],
                "sha256": digest_file(cache),
                "sharedRegionStart": hex(
                    cache_header(cache)["sharedRegionStart"]),
            },
            "textSubcache": {
                "fileName": text_cache.name,
                "uuid": SUB_UUID,
                "sha256": digest_file(text_cache),
                "codeDirectory": text_code_directory,
            },
            "readOnlySubcache": {
                "fileName": readonly_cache.name,
                "uuid": READONLY_UUID,
                "sha256": digest_file(readonly_cache),
                "codeDirectory": readonly_code_directory,
            },
        },
        "class": {
            "name": CLASS_NAME,
            "unslidVMAddress": hex(CLASS_VM),
            "isa": hex(isa),
            "superclass": hex(superclass),
            "initialCacheBuckets": hex(cache_buckets),
            "preoptimizedCache": hex(cache_properties),
            "classRO": hex(class_ro),
            "baseMethods": hex(class_ro_words[4]),
            "metaclass": hex(METACLASS_VM),
            "metaclassRO": hex(metaclass_ro),
            "classMethods": hex(metaclass_ro_words[4]),
        },
        "specialSelection": {
            "helperUnslidVMAddress": hex(SPECIAL_HELPER_VM),
            "helperByteLength": len(helper),
            "helperSHA256": hashlib.sha256(helper).hexdigest(),
            "hardCodedBundleIdentifiers": [
                "com.apple.mobiletimer",
                "com.apple.mobilecal",
            ],
            "ordinaryTail": "+[SBHIconModel applicationIconClass]",
            "conclusion": (
                "The exact-build helper has only the Clock and Calendar "
                "special cases; all other identifiers take the ordinary "
                "applicationIconClass tail."
            ),
        },
        "targetMethod": {
            "selector": TARGET_SELECTOR,
            "types": target["types"],
            "unslidVMAddress": hex(TARGET_METHOD_VM),
            "byteLength": len(target_method),
            "sha256": hashlib.sha256(target_method).hexdigest(),
            "methodListUnslidVMAddress": hex(METHOD_LIST_VM),
            "methodListHeader": {
                "entsizeAndFlags": hex(method_header["entsizeAndFlags"]),
                "count": method_header["count"],
                "entrySize": method_header["entrySize"],
                "relativeEntries": True,
                "directSelectors": True,
            },
            "entryIndex": target["index"],
            "entryUnslidVMAddress": hex(target["entry"]),
            "entrySubcacheFileOffset": hex(
                reader.file_offset(target["entry"], 12)),
            "entryBytesHex": reader.read(target["entry"], 12).hex(),
            "selectorBaseUnslidVMAddress": hex(selector_base),
            "selectorOffset": hex(target["selectorOffset"]),
            "selectorUnslidVMAddress": hex(target["selectorAddress"]),
            "impFieldUnslidVMAddress": hex(target["entry"] + 8),
            "impFieldRawWord": hex(target["impRelativeOffset"] & 0xFFFFFFFF),
            "mapping": {
                "subcacheUUID": target_mapping["uuid"],
                "initProt": target_mapping["initProt"],
                "maxProt": target_mapping["maxProt"],
            },
            "guard": {
                "unslidVMAddress": hex(TARGET_ENTRY_VM),
                "byteLength": GUARD_SIZE,
                "bytesHex": target_guard.hex(),
                "sha256": hashlib.sha256(target_guard).hexdigest(),
            },
        },
        "preoptimizedDispatchEntry": {
            "cacheHeaderUnslidVMAddress": hex(PREOPT_CACHE_VM),
            "cacheHeader": {
                "fallbackClassOffset": hex(fallback & ((1 << 64) - 1)),
                "shift": shift,
                "mask": mask,
                "capacity": mask + 1,
                "occupied": occupied,
                "hasInlines": bool(has_inlines),
            },
            "slot": slot,
            "entryUnslidVMAddress": hex(PREOPT_ENTRY_VM),
            "frameUnslidVMAddress": hex(
                PREOPT_ENTRY_VM & ~(PAGE_SIZE - 1)),
            "entryOffsetWithin16KFrame": hex(
                PREOPT_ENTRY_VM & (PAGE_SIZE - 1)),
            "entrySubcacheFileOffset": hex(
                reader.file_offset(PREOPT_ENTRY_VM, 8)),
            "encoding": {
                "kind": (
                    "preopt_cache_entry_t packed bitfields; no pointer or "
                    "PAC bits stored"
                ),
                "selectorOffsetBits": 26,
                "signedRawIMPOffsetBits": 38,
                "decodeFormula": (
                    "IMP = class - (signedRawIMPOffset << 2)"
                ),
            },
            "originalValue": hex(entry_value),
            "originalLowWord": hex(entry_value & 0xFFFFFFFF),
            "originalBytesLE": struct.pack("<Q", entry_value).hex(),
            "selectorOffset": hex(selector_offset),
            "signedRawIMPOffset": hex(raw_imp_offset),
            "decodedOriginalIMPUnslidVMAddress": hex(decoded_imp),
            "mapping": {
                "subcacheUUID": dispatch_mapping["uuid"],
                "name": dispatch_info["name"],
                "flags": dispatch_info.get("flags", 0),
                "readOnlyData": True,
                "initProt": dispatch_info["init_prot"],
                "maxProt": dispatch_info["max_prot"],
            },
            "guard": {
                "unslidVMAddress": hex(PREOPT_ENTRY_VM),
                "byteLength": GUARD_SIZE,
                "originalBytesHex": dispatch_guard.hex(),
                "originalSHA256": hashlib.sha256(
                    dispatch_guard).hexdigest(),
                "redirectedBytesHex": bytes(redirected_guard).hex(),
                "redirectedSHA256": hashlib.sha256(
                    redirected_guard).hexdigest(),
            },
        },
        "replacementMethod": {
            "class": CLASS_NAME,
            "kind": "class method",
            "selector": REPLACEMENT_SELECTOR,
            "types": replacement["types"],
            "machineCallCompatibility": {
                "compatible": True,
                "reason": (
                    "The replacement ignores self, _cmd, and the target's "
                    "extra x2 identifier argument and returns one Class in x0."
                ),
                "exactObjectiveCTypeEncodingMatch": False,
            },
            "semantics": "returns the ordinary SBApplicationIcon class",
            "unslidVMAddress": hex(REPLACEMENT_METHOD_VM),
            "byteLength": len(replacement_method),
            "bytesHex": replacement_method.hex(),
            "sha256": hashlib.sha256(replacement_method).hexdigest(),
            "methodListUnslidVMAddress": hex(CLASS_METHOD_LIST_VM),
            "methodListHeader": {
                "entsizeAndFlags": hex(
                    class_method_header["entsizeAndFlags"]),
                "count": class_method_header["count"],
                "entrySize": class_method_header["entrySize"],
                "relativeEntries": True,
                "directSelectors": True,
            },
            "entryIndex": replacement["index"],
            "entryUnslidVMAddress": hex(replacement["entry"]),
            "entryBytesHex": reader.read(replacement["entry"], 12).hex(),
            "subcacheUUID": replacement_mapping["uuid"],
            "appleSignedCodePageVerified": True,
            "sameSubcacheAsOriginalIMP": True,
            "signedRawIMPOffset": hex(replacement_raw),
            "redirectedEntryValue": hex(replacement_entry),
            "redirectedLowWord": hex(replacement_entry & 0xFFFFFFFF),
            "redirectedEntryBytesLE": struct.pack(
                "<Q", replacement_entry).hex(),
        },
        "writeShape": {
            "semanticWriteCount": 1,
            "widthBits": 32,
            "originalLowWord": hex(entry_value & 0xFFFFFFFF),
            "redirectedLowWord": hex(replacement_entry & 0xFFFFFFFF),
            "upperWordUnchanged": True,
        },
        "runtimeBoundary": {
            "status": "offline-derived-runtime-unverified",
            "priorConfirmedReadOnlyEntry": hex(PRIOR_CONFIRMED_ENTRY_VM),
            "priorConfirmed16KPage": hex(
                PRIOR_CONFIRMED_ENTRY_VM & ~(PAGE_SIZE - 1)),
            "target16KPage": hex(PREOPT_ENTRY_VM & ~(PAGE_SIZE - 1)),
            "samePageAsPriorPermissionProof": False,
            "requiredNextStep": (
                "Run an identical-bytes-only permission and shared-frame "
                "proof against this exact .34 page before a semantic write."
            ),
            "objectLifecycleCaveat": (
                "The dispatch redirect changes future class selection; it "
                "does not reclassify Clock/Calendar icon objects that already "
                "exist in a consumer process."
            ),
            "staticRouteHypothesis": (
                "After the redirect is installed and consumers rebuild their "
                "models, ordinary persistent mobiletimer/mobilecal "
                "IconServices records should supply static themed icons "
                "without per-PID source bridges. This remains a runtime test, "
                "not an offline proof."
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipsw", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--ipsw-tool", default="ipsw")
    parser.add_argument("--verify-manifest", type=Path)
    args = parser.parse_args()
    try:
        manifest = derive(args.ipsw, args.cache, args.ipsw_tool)
        if args.verify_manifest:
            expected = json.loads(args.verify_manifest.read_text())
            require(manifest == expected,
                    "derived manifest does not equal the reviewed manifest")
            print(
                f"Verified {BUILD}/{DEVICE}: SBHIconModel target, ordinary "
                "class replacement, packed dispatch entry, signed pages, "
                "one-word write shape, and guards."
            )
        else:
            print(json.dumps(manifest, indent=2))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, f"derivation refused: {error}\n")


if __name__ == "__main__":
    main()
