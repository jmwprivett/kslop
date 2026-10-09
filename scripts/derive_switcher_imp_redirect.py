#!/usr/bin/env python3
"""Derive/verify the offline 23A341 app-switcher dispatch redirects.

This tool is deliberately read-only. It proves the two ABI-matched Apple
implementations used by SpringBoard's existing flat switcher-title route,
decodes their preoptimized Objective-C cache entries, and emits exact guarded
bytes. It does not connect to a device or contain a kernel writer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from derive_flat_icon_imp_redirect import (  # noqa: E402
    CacheReader,
    FAST_DATA_MASK,
    GUARD_SIZE,
    PAGE_SIZE,
    PREOPT_RAW_IMP_MASK,
    READ_ONLY_DATA_FLAG,
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
    cache_header,
    derive as derive_text_profile,
    digest_file,
    read_at,
    require,
    verify_code_directory,
)


SELECTOR_BASE_VM = 0x1FAC21900
READONLY_CODE_SUFFIX = ".42"
READONLY_CODE_UUID = "A495BF0F-60DC-3D51-8419-191FB857CE31"


@dataclass(frozen=True)
class RedirectSpec:
    label: str
    class_name: str
    class_vm: int
    class_ro_vm: int
    method_list_vm: int
    preopt_cache_vm: int
    target_selector: str
    target_types: str
    target_method_entry_vm: int
    target_imp_vm: int
    target_slot: int
    target_dispatch_vm: int
    target_dispatch_value: int
    source_selector: str
    source_method_entry_vm: int
    source_imp_vm: int
    source_slot: int
    source_dispatch_vm: int
    source_dispatch_value: int
    redirected_dispatch_value: int


SPECS = (
    RedirectSpec(
        label="switcher-flat-image-storage",
        class_name="SBFluidSwitcherSpaceTitleItem",
        class_vm=0x281549AA0,
        class_ro_vm=0x2832B82A0,
        method_list_vm=0x21E029AB0,
        preopt_cache_vm=0x1FFD55C78,
        target_selector="setImageView:",
        target_types="v24@0:8@16",
        target_method_entry_vm=0x21E029B3C,
        target_imp_vm=0x21D864024,
        target_slot=2,
        target_dispatch_vm=0x1FFD55C98,
        target_dispatch_value=0x1622200018F3969F,
        source_selector="setImage:",
        source_method_entry_vm=0x21E029BB4,
        source_imp_vm=0x21D864010,
        source_slot=7,
        source_dispatch_vm=0x1FFD55CC0,
        source_dispatch_value=0x3C67A00018F396A4,
        redirected_dispatch_value=0x1622200018F396A4,
    ),
    RedirectSpec(
        label="switcher-flat-image-provider",
        class_name="SBFluidSwitcherSpaceTitleItemController",
        class_vm=0x281549A78,
        class_ro_vm=0x283474E40,
        method_list_vm=0x21E029BD8,
        preopt_cache_vm=0x1FFD8B428,
        target_selector="_iconViewForDisplayItem:",
        target_types="@24@0:8@16",
        target_method_entry_vm=0x21E029C64,
        target_imp_vm=0x21DEA18CC,
        target_slot=10,
        target_dispatch_vm=0x1FFD8B488,
        target_dispatch_value=0x1A81D10018DAA06B,
        source_selector="_iconImageForDisplayItem:",
        source_method_entry_vm=0x21E029C7C,
        source_imp_vm=0x21DEA17C4,
        source_slot=3,
        source_dispatch_vm=0x1FFD8B450,
        source_dispatch_value=0x20C0A00018DAA0AD,
        redirected_dispatch_value=0x1A81D10018DAA0AD,
    ),
)


def all_subcache_paths(cache: Path) -> list[Path]:
    header = cache_header(cache)
    entries = read_at(
        cache, header["subcacheOffset"], header["subcacheCount"] * 56)
    result = [cache]
    seen = {cache}
    for position in range(0, len(entries), 56):
        suffix = entries[position + 24:position + 56].rstrip(b"\0").decode()
        path = cache.with_name(cache.name + suffix)
        require(path.is_file(), f"missing subcache file: {path}")
        require(path not in seen, f"duplicate subcache path: {path}")
        result.append(path)
        seen.add(path)
    return result


def redirect_profile(reader: CacheReader, ipsw_tool: str, cache: Path,
                     spec: RedirectSpec) -> dict:
    isa, superclass, buckets, cache_properties, data_bits = decoded_qwords(
        ipsw_tool, cache, spec.class_vm, 5)
    class_ro = data_bits & FAST_DATA_MASK
    class_ro_words = decoded_qwords(ipsw_tool, cache, class_ro, 9)
    require(class_ro == spec.class_ro_vm and
            reader.cstring(class_ro_words[3]) == spec.class_name and
            class_ro_words[4] == spec.method_list_vm,
            f"{spec.class_name} identity or base methods changed")

    method_header, methods = compact_methods(
        reader, SELECTOR_BASE_VM, spec.method_list_vm)
    targets = [method for method in methods
               if method["selector"] == spec.target_selector]
    sources = [method for method in methods
               if method["selector"] == spec.source_selector]
    require(len(targets) == len(sources) == 1,
            f"{spec.label} target or source method is not unique")
    target, source = targets[0], sources[0]
    require(target["entry"] == spec.target_method_entry_vm and
            target["types"] == spec.target_types and
            target["imp"] == spec.target_imp_vm,
            f"{spec.label} target method changed")
    require(source["entry"] == spec.source_method_entry_vm and
            source["types"] == spec.target_types and
            source["imp"] == spec.source_imp_vm,
            f"{spec.label} source method changed")

    require(cache_properties == spec.preopt_cache_vm,
            f"{spec.label} preoptimized cache pointer changed")
    fallback, hash_params, occupied_flags, unused = struct.unpack(
        "<qHHI", reader.read(spec.preopt_cache_vm, 16))
    shift = hash_params & 0x1F
    mask = hash_params >> 5
    occupied = occupied_flags & 0x3FFF
    has_inlines = (occupied_flags >> 14) & 1
    require(unused >> 31 == 1 and mask + 1 <= 2048,
            f"{spec.label} preoptimized cache header changed")

    def resolve_dispatch(method: dict, expected_slot: int,
                         expected_address: int, expected_value: int) -> dict:
        slot = (method["selectorOffset"] >> shift) & mask
        address = spec.preopt_cache_vm + 16 + slot * 8
        value = struct.unpack("<Q", reader.read(address, 8))[0]
        selector_offset = value >> 38
        raw_imp_offset = signed_38(value)
        decoded_imp = spec.class_vm - raw_imp_offset * 4
        require(slot == expected_slot and address == expected_address and
                value == expected_value and
                selector_offset == method["selectorOffset"] and
                decoded_imp == method["imp"],
                f"{spec.label} dispatch entry changed")
        return {
            "slot": slot,
            "address": address,
            "value": value,
            "selectorOffset": selector_offset,
            "rawIMPOffset": raw_imp_offset,
            "decodedIMP": decoded_imp,
        }

    target_dispatch = resolve_dispatch(
        target, spec.target_slot, spec.target_dispatch_vm,
        spec.target_dispatch_value)
    source_dispatch = resolve_dispatch(
        source, spec.source_slot, spec.source_dispatch_vm,
        spec.source_dispatch_value)

    replacement_delta = spec.class_vm - spec.source_imp_vm
    require(replacement_delta % 4 == 0,
            f"{spec.label} replacement IMP is not word aligned")
    replacement_raw = replacement_delta // 4
    require(-(1 << 37) <= replacement_raw < (1 << 37),
            f"{spec.label} replacement IMP does not fit the cache field")
    redirected_value = ((target_dispatch["selectorOffset"] << 38) |
                        (replacement_raw & PREOPT_RAW_IMP_MASK))
    require(redirected_value == spec.redirected_dispatch_value and
            spec.class_vm - signed_38(redirected_value) * 4 ==
            spec.source_imp_vm,
            f"{spec.label} redirected entry encoding changed")
    require((target_dispatch["value"] >> 32) == (redirected_value >> 32),
            f"{spec.label} redirect is not a low-word-only change")

    guard = reader.read(spec.target_dispatch_vm, GUARD_SIZE)
    redirected_guard = bytearray(guard)
    struct.pack_into("<Q", redirected_guard, 0, redirected_value)
    mapping = reader.mapping_for(spec.target_dispatch_vm, GUARD_SIZE)
    target_code_mapping = reader.mapping_for(spec.target_imp_vm, 8)
    source_code_mapping = reader.mapping_for(spec.source_imp_vm, 8)
    require(mapping["uuid"] == READONLY_UUID and
            mapping["initProt"] == mapping["maxProt"] == 1,
            f"{spec.label} dispatch entry left the pinned .34 mapping")
    require(target_code_mapping["uuid"] == READONLY_CODE_UUID and
            source_code_mapping["uuid"] == READONLY_CODE_UUID and
            target_code_mapping["initProt"] ==
            target_code_mapping["maxProt"] == 5 and
            source_code_mapping["initProt"] ==
            source_code_mapping["maxProt"] == 5,
            f"{spec.label} code is outside the pinned signed RX subcache")

    dispatch_info = mapping_metadata(
        ipsw_tool, cache, READONLY_UUID, spec.target_dispatch_vm, GUARD_SIZE)
    require(dispatch_info.get("flags", 0) & READ_ONLY_DATA_FLAG and
            dispatch_info["init_prot"] == dispatch_info["max_prot"] == 1,
            f"{spec.label} dispatch mapping is not READ_ONLY_DATA")

    def method_profile(method: dict, mapping_info: dict) -> dict:
        return {
            "selector": method["selector"],
            "types": method["types"],
            "entryIndex": method["index"],
            "entryUnslidVMAddress": hex(method["entry"]),
            "entrySubcacheFileOffset": hex(
                reader.file_offset(method["entry"], 12)),
            "entryBytesHex": reader.read(method["entry"], 12).hex(),
            "selectorOffset": hex(method["selectorOffset"]),
            "selectorUnslidVMAddress": hex(method["selectorAddress"]),
            "decodedIMPUnslidVMAddress": hex(method["imp"]),
            "impSubcacheUUID": mapping_info["uuid"],
            "impSubcacheFileOffset": hex(
                reader.file_offset(method["imp"], 8)),
            "impBytesHex": reader.read(method["imp"], 16).hex(),
        }

    return {
        "label": spec.label,
        "class": {
            "name": spec.class_name,
            "unslidVMAddress": hex(spec.class_vm),
            "isa": hex(isa),
            "superclass": hex(superclass),
            "initialCacheBuckets": hex(buckets),
            "preoptimizedCache": hex(cache_properties),
            "classRO": hex(class_ro),
            "baseMethods": hex(spec.method_list_vm),
        },
        "methodListHeader": {
            "entsizeAndFlags": hex(method_header["entsizeAndFlags"]),
            "count": method_header["count"],
            "entrySize": method_header["entrySize"],
            "relativeEntries": True,
            "directSelectors": True,
        },
        "targetMethod": method_profile(target, target_code_mapping),
        "replacementMethod": method_profile(source, source_code_mapping),
        "preoptimizedCacheHeader": {
            "fallbackClassOffset": hex(fallback & ((1 << 64) - 1)),
            "shift": shift,
            "mask": mask,
            "capacity": mask + 1,
            "occupied": occupied,
            "hasInlines": bool(has_inlines),
        },
        "targetDispatchEntry": {
            "slot": target_dispatch["slot"],
            "unslidVMAddress": hex(target_dispatch["address"]),
            "frameUnslidVMAddress": hex(
                target_dispatch["address"] & ~(PAGE_SIZE - 1)),
            "offsetWithin16KFrame": hex(
                target_dispatch["address"] & (PAGE_SIZE - 1)),
            "subcacheFileOffset": hex(
                reader.file_offset(target_dispatch["address"], 8)),
            "originalValue": hex(target_dispatch["value"]),
            "originalLowWord": hex(target_dispatch["value"] & 0xFFFFFFFF),
            "selectorOffset": hex(target_dispatch["selectorOffset"]),
            "signedRawIMPOffset": hex(target_dispatch["rawIMPOffset"]),
            "decodedOriginalIMPUnslidVMAddress": hex(
                target_dispatch["decodedIMP"]),
            "mapping": {
                "subcacheUUID": mapping["uuid"],
                "name": dispatch_info["name"],
                "flags": dispatch_info.get("flags", 0),
                "readOnlyData": True,
                "initProt": dispatch_info["init_prot"],
                "maxProt": dispatch_info["max_prot"],
            },
            "guard": {
                "byteLength": GUARD_SIZE,
                "originalBytesHex": guard.hex(),
                "originalSHA256": hashlib.sha256(guard).hexdigest(),
                "redirectedBytesHex": bytes(redirected_guard).hex(),
                "redirectedSHA256": hashlib.sha256(
                    redirected_guard).hexdigest(),
            },
        },
        "replacementEncoding": {
            "sourceSelector": spec.source_selector,
            "sourceIMPUnslidVMAddress": hex(spec.source_imp_vm),
            "sourceDispatchSlot": source_dispatch["slot"],
            "sourceDispatchEntryUnslidVMAddress": hex(
                source_dispatch["address"]),
            "sourceDispatchValue": hex(source_dispatch["value"]),
            "signedRawIMPOffset": hex(replacement_raw),
            "redirectedValue": hex(redirected_value),
            "redirectedLowWord": hex(redirected_value & 0xFFFFFFFF),
            "lowWordOnly": True,
            "sameSubcacheAsOriginalIMP": True,
            "appleSignedCodePageVerified": True,
        },
    }


def derive(ipsw: Path, cache: Path, ipsw_tool: str, clang: str) -> dict:
    baseline = derive_text_profile(ipsw, cache, ipsw_tool, clang)
    readonly_cache = subcache_member(cache, READONLY_SUFFIX, READONLY_UUID)
    code_cache = subcache_member(
        cache, READONLY_CODE_SUFFIX, READONLY_CODE_UUID)
    reader = CacheReader(all_subcache_paths(cache))

    trusted = exact_trustcache(ipsw)
    readonly_code_directory = verify_code_directory(
        readonly_cache, cache_header(readonly_cache), trusted)
    executable_code_directory = verify_code_directory(
        code_cache, cache_header(code_cache), trusted)
    redirects = [
        redirect_profile(reader, ipsw_tool, cache, spec) for spec in SPECS]

    frames = [int(item["targetDispatchEntry"]["frameUnslidVMAddress"], 16)
              for item in redirects]
    require(len(set(frames)) == len(frames) == 2,
            "switcher redirect entries must remain on two distinct pages")

    return {
        "schemaVersion": 1,
        "purpose": "Offline derivation of the matched app-switcher flat-image dispatch redirects; no writer included",
        "runtimeVerified": False,
        "os": baseline["os"],
        "cache": {
            "main": baseline["cache"],
            "readOnlySubcache": {
                "fileName": readonly_cache.name,
                "uuid": READONLY_UUID,
                "sha256": digest_file(readonly_cache),
                "codeDirectory": readonly_code_directory,
            },
            "codeSubcache": {
                "fileName": code_cache.name,
                "uuid": READONLY_CODE_UUID,
                "sha256": digest_file(code_cache),
                "codeDirectory": executable_code_directory,
            },
        },
        "selectorBaseUnslidVMAddress": hex(SELECTOR_BASE_VM),
        "encoding": {
            "kind": "preopt_cache_entry_t packed 26-bit selector offset plus signed 38-bit class-relative IMP",
            "selectorOffsetBits": 26,
            "signedRawIMPOffsetBits": 38,
            "decodeFormula": "IMP = class - (signedRawIMPOffset << 2)",
            "storesPointerOrPAC": False,
        },
        "transaction": {
            "semanticWriteCount": 2,
            "applyOrder": [
                "switcher-flat-image-storage",
                "switcher-flat-image-provider",
            ],
            "restoreOrder": [
                "switcher-flat-image-provider",
                "switcher-flat-image-storage",
            ],
            "intermediateStateIsTypeMismatched": True,
            "requiresSwitcherQuiescence": True,
            "distinct16KTargetPages": 2,
            "requiresExactIdenticalBytesPermissionProofPerPage": True,
            "reason": "The provider and storage selectors must agree on UIImage versus SBHIconLayerView; the two cache entries are on different .34 pages and cannot be changed by one low-word write.",
        },
        "redirects": redirects,
        "appLibraryMiniatureFinding": {
            "status": "separate-composite-route-no-dispatch-redirect-selected",
            "consumer": "SBFolderIconImageCache",
            "entryMethod": "gridCellImageForIcon:imageAppearance:",
            "entryMethodUnslidVMAddress": "0x1bdfc4308",
            "rendererMethod": "gridCellImageOfSize:forIcon:iconImageInfo:imageAppearance:imageAttributes:",
            "rendererMethodUnslidVMAddress": "0x1bdfc40b0",
            "imageRequest": "-[SBIcon iconImageWithInfo:traitCollection:options:] with options=1",
            "compositor": "+[SBFolderIconImageCache gridCellImageOfSize:forIconImage:]",
            "compositorUnslidVMAddress": "0x1bdfc41cc",
            "conclusion": "The 27-point children are rasterized into a folder/category composite and do not consult SBIconImageView's flat-layer selector. Offline disassembly has not established one ABI-safe data-only redirect that removes the already-rendered plate.",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipsw", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--ipsw-tool", default="ipsw")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--verify-manifest", type=Path)
    args = parser.parse_args()
    try:
        manifest = derive(args.ipsw, args.cache, args.ipsw_tool, args.clang)
        if args.verify_manifest:
            expected = json.loads(args.verify_manifest.read_text())
            require(manifest == expected,
                    "derived manifest does not equal the reviewed manifest")
            print(
                f"Verified {BUILD}/{DEVICE}: both switcher dispatch entries, "
                "ABI-matched replacement IMPs, signed pages, and guards.")
        else:
            print(json.dumps(manifest, indent=2))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, f"derivation refused: {error}\n")


if __name__ == "__main__":
    main()
