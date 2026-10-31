#!/usr/bin/env python3
"""Derive the per-boot Clock/Calendar class-dispatch redirect.

This tool is offline and read-only. It proves the packed preoptimized-cache
entry for -[SBHIconModel iconClassForApplicationWithBundleIdentifier:] in
both SBHIconModel (used directly by Spotlight) and SpringBoard's SBIconModel
subclass, then derives the low-word-only redirect to
+[SBHIconModel applicationIconClass].
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from derive_flat_icon_imp_redirect import (  # noqa: E402
    CacheReader,
    decoded_qwords,
    signed_38,
    subcache_member,
)
from derive_flat_icon_patch import cache_header, require  # noqa: E402


BUILD = "23A341"
PRODUCT = "iPhone17,2"
MAIN_UUID = "DC5F2F67-1FC8-3905-873B-35D17D1A44E8"
READONLY_SUFFIX = ".34.dyldreadonly"
READONLY_UUID = "CEEB0D68-9BA9-3CC8-AEB1-8F23BAC92B58"
SELECTOR = "iconClassForApplicationWithBundleIdentifier:"
SELECTOR_OFFSET = 0x89102D
ORIGINAL_IMP = 0x1BE19DB3C
REPLACEMENT_SYMBOL = "+[SBHIconModel applicationIconClass]"
REPLACEMENT_IMP = 0x1BE19D9E8
FAST_DATA_MASK = 0x00007FFFFFFFFFF8

TARGETS = (
    {
        "className": "SBHIconModel",
        "consumer": "Spotlight",
        "class": 0x1EDA01028,
        "preoptCache": 0x1FFC32E78,
        "entry": 0x1FFC330A8,
        "fileOffset": 0x78DF0A8,
        "originalWord": 0x22440B400BE18D3B,
        "redirectedWord": 0x22440B400BE18D90,
    },
    {
        "className": "SBIconModel",
        "consumer": "SpringBoard",
        "class": 0x281548678,
        "preoptCache": 0x1FFD52C88,
        "entry": 0x1FFD52EB8,
        "fileOffset": 0x79FEEB8,
        "originalWord": 0x22440B4030CEAACF,
        "redirectedWord": 0x22440B4030CEAB24,
    },
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cache_paths(cache: Path) -> list[Path]:
    pattern = re.compile(
        rf"^{re.escape(cache.name)}(?:\.\d+(?:\.dylddata|\.dyldreadonly)?)?$"
    )
    paths = [
        path
        for path in sorted(cache.parent.glob(cache.name + "*"))
        if pattern.match(path.name)
    ]
    require(cache in paths, "main cache was not selected")
    return paths


def derive_target(
    reader: CacheReader,
    cache: Path,
    readonly_cache: Path,
    target: dict,
) -> dict:
    class_words = decoded_qwords("ipsw", cache, target["class"], 5)
    _, _, _, preopt_cache, class_bits = class_words
    require(preopt_cache == target["preoptCache"],
            f"{target['className']} preoptimized cache moved")
    class_ro = class_bits & FAST_DATA_MASK
    ro_words = decoded_qwords("ipsw", cache, class_ro, 9)
    require(reader.cstring(ro_words[3]) == target["className"],
            f"{target['className']} class identity changed")

    fallback, hash_params, occupied_flags, unused = struct.unpack(
        "<qHHI", reader.read(preopt_cache, 16)
    )
    shift = hash_params & 0x1F
    mask = hash_params >> 5
    occupied = occupied_flags & 0x3FFF
    has_inlines = (occupied_flags >> 14) & 1
    slot = (SELECTOR_OFFSET >> shift) & mask
    entry = preopt_cache + 16 + slot * 8
    require(entry == target["entry"],
            f"{target['className']} selector entry moved")

    original_word = int.from_bytes(reader.read(entry, 8), "little")
    require(original_word == target["originalWord"],
            f"{target['className']} packed word changed")
    selector_offset = original_word >> 38
    require(selector_offset == SELECTOR_OFFSET,
            f"{target['className']} selector offset changed")
    original_imp = target["class"] - signed_38(original_word) * 4
    require(original_imp == ORIGINAL_IMP,
            f"{target['className']} original IMP changed")

    relative_bytes = target["class"] - REPLACEMENT_IMP
    require(relative_bytes % 4 == 0,
            f"{target['className']} replacement offset is unaligned")
    redirected_word = (
        (selector_offset << 38) |
        ((relative_bytes // 4) & ((1 << 38) - 1))
    )
    require(redirected_word == target["redirectedWord"],
            f"{target['className']} redirected word changed")
    require((original_word >> 32) == (redirected_word >> 32),
            f"{target['className']} redirect is not low-word-only")
    require(
        target["class"] - signed_38(redirected_word) * 4 ==
        REPLACEMENT_IMP,
        f"{target['className']} redirected word decodes incorrectly",
    )

    original_guard = reader.read(entry, 32)
    redirected_guard = bytearray(original_guard)
    struct.pack_into("<Q", redirected_guard, 0, redirected_word)
    redirected_guard = bytes(redirected_guard)

    mapping = reader.mapping_for(entry, 32)
    require(mapping["path"] == readonly_cache,
            f"{target['className']} entry is in the wrong subcache")
    require(mapping["uuid"] == READONLY_UUID,
            f"{target['className']} subcache UUID changed")
    require(mapping["initProt"] == 1 and mapping["maxProt"] == 1,
            f"{target['className']} mapping is no longer r--/r--")
    file_offset = reader.file_offset(entry, 32)
    require(file_offset == target["fileOffset"],
            f"{target['className']} file offset changed")

    return {
        "className": target["className"],
        "consumer": target["consumer"],
        "classUnslid": hex(target["class"]),
        "classROUnslid": hex(class_ro),
        "preoptimizedCacheUnslid": hex(preopt_cache),
        "fallbackClassUnslid": hex(
            (preopt_cache + fallback) & ((1 << 64) - 1)
        ),
        "hash": {
            "shift": shift,
            "mask": mask,
            "occupied": occupied,
            "hasInlines": bool(has_inlines),
            "unusedHighBit": bool(unused >> 31),
        },
        "selector": SELECTOR,
        "selectorOffset": hex(selector_offset),
        "slot": slot,
        "entryUnslid": hex(entry),
        "entryFileOffset": hex(file_offset),
        "frameUnslid": hex(entry & ~0x3FFF),
        "frameOffset": hex(entry & 0x3FFF),
        "original": {
            "packedWord": f"0x{original_word:016x}",
            "decodedIMPUnslid": hex(original_imp),
            "guardHex": original_guard.hex(),
            "guardSHA256": hashlib.sha256(original_guard).hexdigest(),
        },
        "redirected": {
            "packedWord": f"0x{redirected_word:016x}",
            "decodedIMPUnslid": hex(REPLACEMENT_IMP),
            "guardHex": redirected_guard.hex(),
            "guardSHA256": hashlib.sha256(redirected_guard).hexdigest(),
        },
        "write": {
            "kind": "one 32-bit low-word store",
            "originalLowWord": f"0x{original_word & 0xffffffff:08x}",
            "redirectedLowWord": f"0x{redirected_word & 0xffffffff:08x}",
            "upperWordPreserved": f"0x{original_word >> 32:08x}",
        },
        "mapping": {
            "subcache": readonly_cache.name,
            "uuid": mapping["uuid"],
            "segmentBase": hex(mapping["address"]),
            "segmentSize": hex(mapping["size"]),
            "segmentFileOffset": hex(mapping["fileOffset"]),
            "initProt": mapping["initProt"],
            "maxProt": mapping["maxProt"],
        },
    }


def derive(cache: Path) -> dict:
    require(cache_header(cache)["uuid"] == MAIN_UUID,
            "main cache UUID changed")
    readonly_cache = subcache_member(
        cache, READONLY_SUFFIX, READONLY_UUID
    )
    reader = CacheReader(cache_paths(cache))
    targets = [
        derive_target(reader, cache, readonly_cache, target)
        for target in TARGETS
    ]
    return {
        "schemaVersion": 1,
        "build": BUILD,
        "product": PRODUCT,
        "kind": "per-boot-clock-calendar-preoptimized-dispatch-redirect",
        "cache": {
            "main": {
                "fileName": cache.name,
                "uuid": MAIN_UUID,
            },
            "readonlySubcache": {
                "fileName": readonly_cache.name,
                "uuid": READONLY_UUID,
                "sha256": sha256_file(readonly_cache),
            },
        },
        "selector": {
            "name": SELECTOR,
            "offset": hex(SELECTOR_OFFSET),
            "originalIMPUnslid": hex(ORIGINAL_IMP),
        },
        "replacement": {
            "symbol": REPLACEMENT_SYMBOL,
            "impUnslid": hex(REPLACEMENT_IMP),
        },
        "targets": targets,
        "redirect": {
            "writeKind": "two 32-bit low-word stores",
            "executableTextWritten": False,
            "methodListWritten": False,
            "perBoot": True,
            "perProcess": False,
            "survivesRespringExpected": True,
            "survivesRespringPhysicalProof": False,
            "survivesReboot": False,
            "respringRequiredBeforeLiveIconRebuild": True,
            "staticThemeRecordsTouched": False,
        },
        "boundary": {
            "targetSubcache": READONLY_SUFFIX,
            "targetSegment": "__LINKEDIT",
            "targetInitProt": "r--",
            "targetMaxProt": "r--",
            "sameBootIdenticalWriteTicketRequired": True,
            "forbiddenTarget":
                ".19 method-list IMP text page",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manifest = derive(args.cache)
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
