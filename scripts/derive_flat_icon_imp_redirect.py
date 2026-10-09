#!/usr/bin/env python3
"""Derive/verify the offline 23A341 flat-icon ObjC dispatch redirect.

This tool is deliberately read-only. It identifies both the compact method-list
record and the preoptimized Objective-C dispatch-cache entry, verifies a
same-subcache Apple-signed always-true implementation, and emits guarded bytes.
It does not connect to a device or perform a write.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import re
import struct
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from derive_flat_icon_patch import (  # noqa: E402
    BOARD,
    BUILD,
    DEVICE,
    IMAGE,
    METHOD_VM,
    SUB_UUID,
    cache_header,
    derive as derive_text_profile,
    digest_file,
    read_at,
    require,
    trustcache_entries,
    verify_code_directory,
)


CLASS_VM = 0x1EDA00588
CLASS_RO_VM = 0x1F3FD3C08
METHOD_LIST_VM = 0x1BE200CF0
METHOD_ENTRY_VM = 0x1BE200D7C
METHOD_IMP_FIELD_VM = METHOD_ENTRY_VM + 8
METHOD_SELECTOR = "effectivelyPrefersFlatImageLayers"
METHOD_TYPES = "B16@0:8"

SELECTOR_BASE_VM = 0x1FAC21900
SELECTOR_OFFSET = 0xB1020

PREOPT_CACHE_VM = 0x1FFC26EC0
PREOPT_CACHE_SLOT = 177
PREOPT_ENTRY_VM = 0x1FFC27458
PREOPT_ENTRY_VALUE = 0x02C408000BE3F5C7

REPLACEMENT_SELECTOR = "hasOpaqueImage"
REPLACEMENT_VM = 0x1BE1052A0
REPLACEMENT_BYTES = bytes.fromhex("20008052c0035fd6")
REPLACEMENT_ENTRY_VALUE = 0x02C408000BE3ECBA

DATA_SUFFIX = ".33.dylddata"
DATA_UUID = "F193189E-840D-3569-816A-2102BCB0FFE5"
READONLY_SUFFIX = ".34.dyldreadonly"
READONLY_UUID = "CEEB0D68-9BA9-3CC8-AEB1-8F23BAC92B58"
PRIOR_WRITABLE_PROBE_VM = 0x1E6B6ED20

PAGE_SIZE = 0x4000
GUARD_SIZE = 32
FAST_DATA_MASK = 0x00007FFFFFFFFFF8
PREOPT_RAW_IMP_MASK = (1 << 38) - 1
READ_ONLY_DATA_FLAG = 1 << 5


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True)
    require(result.returncode == 0,
            f"command failed: {' '.join(command)}\n{result.stderr}")
    return result


def subcache_member(cache: Path, suffix: str, expected_uuid: str) -> Path:
    header = cache_header(cache)
    entries = read_at(cache, header["subcacheOffset"],
                      header["subcacheCount"] * 56)
    matching = [entries[pos:pos + 56]
                for pos in range(0, len(entries), 56)
                if entries[pos:pos + 16] == uuid.UUID(expected_uuid).bytes]
    require(len(matching) == 1, f"missing subcache UUID {expected_uuid}")
    require(matching[0][24:].rstrip(b"\0").decode() == suffix,
            f"subcache UUID {expected_uuid} has an unexpected suffix")
    path = cache.with_name(cache.name + suffix)
    require(path.is_file(), f"missing subcache file: {path}")
    require(cache_header(path)["uuid"] == expected_uuid,
            f"subcache file UUID mismatch: {path.name}")
    return path


class CacheReader:
    def __init__(self, paths: list[Path]):
        self.mappings: list[dict] = []
        for path in paths:
            header = cache_header(path)
            for mapping in header["mappings"]:
                self.mappings.append({**mapping, "path": path,
                                      "uuid": header["uuid"]})

    def mapping_for(self, address: int, size: int = 1) -> dict:
        matches = [mapping for mapping in self.mappings
                   if mapping["address"] <= address and
                   address + size <= mapping["address"] + mapping["size"]]
        require(len(matches) == 1,
                f"address/range is not in exactly one cache mapping: {address:#x}")
        return matches[0]

    def read(self, address: int, size: int) -> bytes:
        mapping = self.mapping_for(address, size)
        offset = (mapping["fileOffset"] + address - mapping["address"])
        return read_at(mapping["path"], offset, size)

    def file_offset(self, address: int, size: int = 1) -> int:
        mapping = self.mapping_for(address, size)
        return mapping["fileOffset"] + address - mapping["address"]

    def cstring(self, address: int, limit: int = 4096) -> str:
        mapping = self.mapping_for(address)
        offset = mapping["fileOffset"] + address - mapping["address"]
        available = min(limit, mapping["size"] - (address - mapping["address"]))
        data = read_at(mapping["path"], offset, available)
        end = data.find(b"\0")
        require(end >= 0, f"unterminated cache string at {address:#x}")
        return data[:end].decode("utf-8")


def exact_trustcache(ipsw: Path) -> set[tuple[bytes, int]]:
    with zipfile.ZipFile(ipsw) as archive:
        build = plistlib.loads(archive.read("BuildManifest.plist"))
        identities = [item for item in build["BuildIdentities"]
                      if item["Info"].get("DeviceClass") == BOARD and
                      item["Info"].get("Variant") ==
                      "Customer Erase Install (IPSW)"]
        require(len(identities) == 1, "exact IPSW identity is unavailable")
        entry = identities[0]["Manifest"]["Cryptex1,SystemTrustCache"]
        data = archive.read(entry["Info"]["Path"])
        require(hashlib.sha384(data).digest() == entry["Digest"],
                "IPSW trustcache digest mismatch")
    _, trusted = trustcache_entries(data)
    return trusted


def mapping_metadata(ipsw_tool: str, cache: Path, cache_uuid: str,
                     address: int, size: int) -> dict:
    info = json.loads(run([ipsw_tool, "dyld", "info", str(cache),
                           "--json", "--no-color"]).stdout)
    mappings = info["mappings"].get(cache_uuid, [])
    matches = [mapping for mapping in mappings
               if mapping["address"] <= address and
               address + size <= mapping["address"] + mapping["size"]]
    require(len(matches) == 1,
            f"ipsw mapping metadata unavailable for {address:#x}")
    return matches[0]


def decoded_qwords(ipsw_tool: str, cache: Path, address: int,
                   count: int) -> list[int]:
    """Read cache pointers after ipsw applies the exact cache slide encoding."""
    result = run([ipsw_tool, "dyld", "dump", str(cache), hex(address),
                  "--count", str(count), "--addr", "--no-color"])
    values = [int(line, 16) for line in result.stdout.splitlines()
              if re.fullmatch(r"0x[0-9a-f]+", line)]
    require(len(values) == count,
            f"could not decode {count} cache qwords at {address:#x}")
    return values


def objc_metadata(ipsw_tool: str, cache: Path) -> tuple[str, int]:
    result = run([ipsw_tool, "dyld", "macho", str(cache), IMAGE,
                  "--objc", "--verbose", "--no-color"])
    blocks = re.findall(r"@interface SBIconImageView\s*:.*?@end",
                        result.stdout, re.DOTALL)
    require(len(blocks) == 1, "could not uniquely resolve SBIconImageView")
    block = blocks[0]
    class_matches = re.findall(
        r"@interface SBIconImageView\b[^\n]*// (0x[0-9a-f]+)", block)
    target_matches = re.findall(
        r"// (0x[0-9a-f]+)\s*\n- \(_Bool\)effectivelyPrefersFlatImageLayers;",
        block)
    replacement_matches = re.findall(
        r"// (0x[0-9a-f]+)\s*\n- \(_Bool\)hasOpaqueImage;", block)
    require(class_matches == [hex(CLASS_VM)] and
            target_matches == [hex(METHOD_VM)] and
            replacement_matches == [hex(REPLACEMENT_VM)],
            "Objective-C class or method identity changed")
    selector_base_matches = re.findall(
        r"rel method sel base off\s*:\s*(0x[0-9a-f]+)", result.stderr)
    require(len(selector_base_matches) == 1,
            "relative-method selector base was not reported")
    shared_region = cache_header(cache)["sharedRegionStart"]
    selector_base = shared_region + int(selector_base_matches[0], 16)
    require(selector_base == SELECTOR_BASE_VM,
            "relative-method selector base changed")
    return block, selector_base


def compact_methods(reader: CacheReader, selector_base: int,
                    method_list: int) -> tuple[dict, list[dict]]:
    entsize_flags, count = struct.unpack("<II", reader.read(method_list, 8))
    entry_size = (entsize_flags & 0xFFFF) & ~3
    require((entsize_flags & 0xC0000000) == 0xC0000000 and
            entry_size == 12 and 0 < count < 4096,
            "unexpected compact direct-selector method-list encoding")
    methods = []
    for index in range(count):
        entry = method_list + 8 + index * entry_size
        name_offset, types_offset, imp_offset = struct.unpack(
            "<iii", reader.read(entry, entry_size))
        selector_address = selector_base + name_offset
        types_address = entry + 4 + types_offset
        imp_address = entry + 8 + imp_offset
        methods.append({
            "index": index,
            "entry": entry,
            "selector": reader.cstring(selector_address),
            "selectorAddress": selector_address,
            "selectorOffset": name_offset,
            "types": reader.cstring(types_address),
            "typesAddress": types_address,
            "imp": imp_address,
            "impRelativeOffset": imp_offset,
        })
    return ({"entsizeAndFlags": entsize_flags, "count": count,
             "entrySize": entry_size}, methods)


def signed_38(value: int) -> int:
    value &= PREOPT_RAW_IMP_MASK
    return value - (1 << 38) if value & (1 << 37) else value


def derive(ipsw: Path, cache: Path, ipsw_tool: str, clang: str) -> dict:
    baseline = derive_text_profile(ipsw, cache, ipsw_tool, clang)
    require(baseline["method"]["unslidVMAddress"] == hex(METHOD_VM),
            "baseline method derivation changed")

    data_cache = subcache_member(cache, DATA_SUFFIX, DATA_UUID)
    readonly_cache = subcache_member(cache, READONLY_SUFFIX, READONLY_UUID)
    text_cache = cache.with_name(cache.name + ".19")
    require(cache_header(text_cache)["uuid"] == SUB_UUID,
            "text subcache UUID changed")
    reader = CacheReader([cache, text_cache, data_cache, readonly_cache])

    _, selector_base = objc_metadata(ipsw_tool, cache)
    isa, superclass, cache_buckets, cache_properties, data_bits = \
        decoded_qwords(ipsw_tool, cache, CLASS_VM, 5)
    class_ro = data_bits & FAST_DATA_MASK
    class_ro_words = decoded_qwords(ipsw_tool, cache, class_ro, 9)
    require(class_ro == CLASS_RO_VM and
            reader.cstring(class_ro_words[3]) == "SBIconImageView",
            "SBIconImageView class_ro_t identity changed")
    base_methods = class_ro_words[4]
    require(base_methods == METHOD_LIST_VM, "base method-list address changed")

    method_header, methods = compact_methods(reader, selector_base,
                                             base_methods)
    targets = [method for method in methods
               if method["selector"] == METHOD_SELECTOR]
    replacements = [method for method in methods
                    if method["selector"] == REPLACEMENT_SELECTOR]
    require(len(targets) == 1 and len(replacements) == 1,
            "target or replacement method is not unique")
    target = targets[0]
    replacement = replacements[0]
    require(target["entry"] == METHOD_ENTRY_VM and
            target["selectorOffset"] == SELECTOR_OFFSET and
            target["types"] == METHOD_TYPES and target["imp"] == METHOD_VM,
            "compact target method entry changed")
    require(replacement["types"] == METHOD_TYPES and
            replacement["imp"] == REPLACEMENT_VM and
            reader.read(REPLACEMENT_VM, 8) == REPLACEMENT_BYTES,
            "same-ABI always-true replacement changed")

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
    slot = (SELECTOR_OFFSET >> shift) & mask
    entry_address = PREOPT_CACHE_VM + 16 + slot * 8
    entry_value = struct.unpack("<Q", reader.read(entry_address, 8))[0]
    selector_offset = entry_value >> 38
    raw_imp_offset = signed_38(entry_value)
    decoded_imp = CLASS_VM - raw_imp_offset * 4
    require(slot == PREOPT_CACHE_SLOT and entry_address == PREOPT_ENTRY_VM and
            entry_value == PREOPT_ENTRY_VALUE and
            selector_offset == SELECTOR_OFFSET and decoded_imp == METHOD_VM,
            "preoptimized dispatch entry changed")

    replacement_delta = CLASS_VM - REPLACEMENT_VM
    require(replacement_delta % 4 == 0,
            "replacement IMP is not word-aligned to the class")
    replacement_raw = replacement_delta // 4
    require(-(1 << 37) <= replacement_raw < (1 << 37),
            "replacement IMP does not fit the 38-bit cache field")
    replacement_entry = ((selector_offset << 38) |
                         (replacement_raw & PREOPT_RAW_IMP_MASK))
    require(replacement_entry == REPLACEMENT_ENTRY_VALUE and
            CLASS_VM - signed_38(replacement_entry) * 4 == REPLACEMENT_VM,
            "replacement dispatch entry encoding changed")

    method_guard = reader.read(METHOD_ENTRY_VM, GUARD_SIZE)
    dispatch_guard = reader.read(PREOPT_ENTRY_VM, GUARD_SIZE)
    redirected_guard = bytearray(dispatch_guard)
    struct.pack_into("<Q", redirected_guard, 0, replacement_entry)

    trusted = exact_trustcache(ipsw)
    data_header = cache_header(data_cache)
    readonly_header = cache_header(readonly_cache)
    data_code_directory = verify_code_directory(data_cache, data_header,
                                                trusted)
    readonly_code_directory = verify_code_directory(
        readonly_cache, readonly_header, trusted)

    text_mapping = reader.mapping_for(METHOD_ENTRY_VM, GUARD_SIZE)
    replacement_mapping = reader.mapping_for(REPLACEMENT_VM, 8)
    dispatch_mapping = reader.mapping_for(PREOPT_ENTRY_VM, GUARD_SIZE)
    require(text_mapping["uuid"] == SUB_UUID and
            replacement_mapping["uuid"] == SUB_UUID and
            text_mapping["initProt"] == text_mapping["maxProt"] == 5,
            "method metadata or replacement is outside the pinned RX subcache")
    require(dispatch_mapping["uuid"] == READONLY_UUID and
            dispatch_mapping["initProt"] == dispatch_mapping["maxProt"] == 1,
            "dispatch entry is not in the pinned read-only subcache mapping")

    dispatch_info = mapping_metadata(ipsw_tool, cache, READONLY_UUID,
                                     PREOPT_ENTRY_VM, GUARD_SIZE)
    prior_probe_info = mapping_metadata(ipsw_tool, cache, DATA_UUID,
                                       PRIOR_WRITABLE_PROBE_VM, GUARD_SIZE)
    require(dispatch_info.get("flags", 0) & READ_ONLY_DATA_FLAG and
            dispatch_info["max_prot"] == dispatch_info["init_prot"] == 1,
            "dispatch page is not marked READ_ONLY_DATA")
    require(prior_probe_info["max_prot"] == 3 and
            prior_probe_info["init_prot"] == 1 and
            not (prior_probe_info.get("flags", 0) & READ_ONLY_DATA_FLAG),
            "prior writable-probe mapping no longer has the expected profile")

    return {
        "schemaVersion": 1,
        "purpose": "Offline derivation of a shared ObjC dispatch-cache redirect; no writer included",
        "runtimeVerified": False,
        "os": baseline["os"],
        "cache": {
            "main": baseline["cache"],
            "dataSubcache": {
                "fileName": data_cache.name,
                "uuid": DATA_UUID,
                "sha256": digest_file(data_cache),
                "codeDirectory": data_code_directory,
            },
            "readOnlySubcache": {
                "fileName": readonly_cache.name,
                "uuid": READONLY_UUID,
                "sha256": digest_file(readonly_cache),
                "codeDirectory": readonly_code_directory,
            },
        },
        "class": {
            "name": "SBIconImageView",
            "unslidVMAddress": hex(CLASS_VM),
            "isa": hex(isa),
            "superclass": hex(superclass),
            "initialCacheBuckets": hex(cache_buckets),
            "preoptimizedCache": hex(cache_properties),
            "classRO": hex(class_ro),
            "baseMethods": hex(base_methods),
        },
        "compactMethodEntry": {
            "selector": METHOD_SELECTOR,
            "types": target["types"],
            "methodListUnslidVMAddress": hex(base_methods),
            "methodListHeader": {
                "entsizeAndFlags": hex(method_header["entsizeAndFlags"]),
                "count": method_header["count"],
                "entrySize": method_header["entrySize"],
                "relativeEntries": True,
                "directSelectors": True,
            },
            "entryIndex": target["index"],
            "entryUnslidVMAddress": hex(target["entry"]),
            "entrySubcacheFileOffset": hex(reader.file_offset(target["entry"], 12)),
            "entryBytesHex": reader.read(target["entry"], 12).hex(),
            "selectorBaseUnslidVMAddress": hex(selector_base),
            "selectorOffset": hex(target["selectorOffset"]),
            "selectorUnslidVMAddress": hex(target["selectorAddress"]),
            "impFieldUnslidVMAddress": hex(METHOD_IMP_FIELD_VM),
            "impFieldEncoding": "signed 32-bit field-relative offset",
            "impFieldRawWord": hex(target["impRelativeOffset"] & 0xFFFFFFFF),
            "decodedIMPUnslidVMAddress": hex(target["imp"]),
            "mapping": {
                "subcacheUUID": text_mapping["uuid"],
                "initProt": text_mapping["initProt"],
                "maxProt": text_mapping["maxProt"],
                "classification": "RX __TEXT; not an 8-byte writable IMP slot",
            },
            "guard": {
                "unslidVMAddress": hex(METHOD_ENTRY_VM),
                "byteLength": GUARD_SIZE,
                "bytesHex": method_guard.hex(),
                "sha256": hashlib.sha256(method_guard).hexdigest(),
            },
        },
        "preoptimizedDispatchEntry": {
            "selector": METHOD_SELECTOR,
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
            "entryOffsetWithin16KFrame": hex(PREOPT_ENTRY_VM & (PAGE_SIZE - 1)),
            "entrySubcacheFileOffset": hex(reader.file_offset(PREOPT_ENTRY_VM, 8)),
            "encoding": {
                "kind": "preopt_cache_entry_t packed bitfields; no pointer or PAC bits stored",
                "selectorOffsetBits": 26,
                "signedRawIMPOffsetBits": 38,
                "decodeFormula": "IMP = class - (signedRawIMPOffset << 2)",
            },
            "originalValue": hex(entry_value),
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
                "originalSHA256": hashlib.sha256(dispatch_guard).hexdigest(),
                "redirectedBytesHex": bytes(redirected_guard).hex(),
                "redirectedSHA256": hashlib.sha256(redirected_guard).hexdigest(),
            },
        },
        "replacement": {
            "class": "SBIconImageView",
            "selector": REPLACEMENT_SELECTOR,
            "types": replacement["types"],
            "semantics": "returns true without reading self or _cmd",
            "unslidVMAddress": hex(REPLACEMENT_VM),
            "subcacheUUID": replacement_mapping["uuid"],
            "subcacheFileOffset": hex(reader.file_offset(REPLACEMENT_VM, 8)),
            "bytesHex": REPLACEMENT_BYTES.hex(),
            "instructions": ["mov w0, #1", "ret"],
            "signedRawIMPOffset": hex(replacement_raw),
            "redirectedEntryValue": hex(replacement_entry),
            "redirectedEntryBytesLE": struct.pack("<Q", replacement_entry).hex(),
            "sameSubcacheAsOriginalIMP": True,
            "appleSignedCodePageVerified": True,
        },
        "writabilityBoundary": {
            "status": "unproven-for-read-only-data",
            "reason": "The confirmed aperture probe targeted .33 __DATA_CONST with maxProt rw-, but the 8-byte dispatch entry is in .34 READ_ONLY_DATA with initProt/maxProt r--.",
            "priorConfirmedProbe": {
                "unslidVMAddress": hex(PRIOR_WRITABLE_PROBE_VM),
                "subcacheUUID": DATA_UUID,
                "name": prior_probe_info["name"],
                "flags": prior_probe_info.get("flags", 0),
                "initProt": prior_probe_info["init_prot"],
                "maxProt": prior_probe_info["max_prot"],
            },
            "requiredNextStep": "Run an identical-bytes-only aperture permission probe against the exact .34 dispatch-entry page before any semantic redirect.",
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
            print(f"Verified {BUILD}/{DEVICE}: compact method entry, preoptimized dispatch entry, replacement IMP, signed pages, and guards.")
        else:
            print(json.dumps(manifest, indent=2))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, f"derivation refused: {error}\n")


if __name__ == "__main__":
    main()
