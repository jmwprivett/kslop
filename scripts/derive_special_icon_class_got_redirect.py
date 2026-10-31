#!/usr/bin/env python3
"""Derive/verify the data-only Clock/Calendar class-selection redirect.

This is deliberately read-only. It proves that SBHIconModel's
-iconClassForApplicationWithBundleIdentifier: helper loads the two special
class pointers from SpringBoardHome __got slots in the non-executable
.33.dylddata subcache, and that those slots can be redirected to
SBHApplicationIcon without touching the .19 method-list text page.

The output is the pinned manifest consumed by the C module and its contract
tests. It does not connect to a device and performs no write.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from derive_flat_icon_imp_redirect import (  # noqa: E402
    CacheReader,
    decoded_qwords,
    run,
    subcache_member,
)
from derive_switcher_imp_redirect import all_subcache_paths  # noqa: E402
from derive_flat_icon_patch import (  # noqa: E402
    cache_header,
    require,
)


BUILD = "23A341"
PRODUCT = "iPhone17,2"
MAIN_UUID = "DC5F2F67-1FC8-3905-873B-35D17D1A44E8"
DATA_SUFFIX = ".33.dylddata"
DATA_UUID = "F193189E-840D-3569-816A-2102BCB0FFE5"
HELPER_VM = 0x1BE19DA24
HELPER_LENGTH = 0x150

TARGETS = (
    {
        "bundle": "com.apple.mobiletimer",
        "label": "Clock",
        "slot": 0x1E8278298,
        "slotFileOffset": 0x1720298,
        "originalSymbol": "_OBJC_CLASS_$_SBHClockApplicationIcon",
        "originalClass": 0x1EDA02180,
        "cacheSlot": 0x1EBF517D8,
        "cacheSlotFileOffset": 0x33F97D8,
    },
    {
        "bundle": "com.apple.mobilecal",
        "label": "Calendar",
        "slot": 0x1E8278270,
        "slotFileOffset": 0x1720270,
        "originalSymbol": "_OBJC_CLASS_$_SBHCalendarApplicationIcon",
        "originalClass": 0x1EDA02568,
        "cacheSlot": 0x1EBF51640,
        "cacheSlotFileOffset": 0x33F9640,
    },
)
REPLACEMENT_SYMBOL = "_OBJC_CLASS_$_SBHApplicationIcon"
REPLACEMENT_CLASS = 0x1EDA021A8
REPLACEMENT_GOT = 0x1E8278240
REPLACEMENT_GOT_FILE_OFFSET = 0x1720240


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def symbol_address(cache: Path, symbol: str) -> int:
    result = run(["ipsw", "dyld", "symaddr", str(cache), symbol, "-b",
                  "--no-color"])
    matches = re.findall(r"^(0x[0-9a-f]+):\s+.*\b" + re.escape(symbol) +
                         r"\b", result.stdout, re.MULTILINE)
    require(len(matches) == 1,
            f"symbol did not resolve exactly once: {symbol}")
    return int(matches[0], 16)


def verify_mapping(reader: CacheReader, address: int, expected_file_offset: int,
                   data_cache: Path, expected_init_prot: int = 1) -> dict:
    mapping = reader.mapping_for(address, 8)
    require(mapping["uuid"] == DATA_UUID,
            f"slot {address:#x} is not in the .33 data subcache")
    require(mapping["path"] == data_cache,
            f"slot {address:#x} resolved to an unexpected subcache file")
    require(mapping["initProt"] == expected_init_prot and
            mapping["maxProt"] == 3,
            f"slot {address:#x} has an unexpected permission profile")
    file_offset = mapping["fileOffset"] + (address - mapping["address"])
    require(file_offset == expected_file_offset,
            f"slot {address:#x} file offset changed")
    return {
        "subcache": data_cache.name,
        "uuid": mapping["uuid"],
        "segmentBase": hex(mapping["address"]),
        "segmentSize": hex(mapping["size"]),
        "segmentFileOffset": hex(mapping["fileOffset"]),
        "slotFileOffset": hex(file_offset),
        "initProt": mapping["initProt"],
        "maxProt": mapping["maxProt"],
    }


def derive(cache: Path) -> dict:
    require(cache_header(cache)["uuid"] == MAIN_UUID,
            "main cache UUID changed")
    data_cache = subcache_member(cache, DATA_SUFFIX, DATA_UUID)
    reader = CacheReader(all_subcache_paths(cache))

    targets = []
    for target in TARGETS:
        mapping = verify_mapping(reader, target["slot"],
                                 target["slotFileOffset"], data_cache)
        original = symbol_address(cache, target["originalSymbol"])
        require(original == target["originalClass"],
                f"{target['originalSymbol']} address changed")
        decoded = decoded_qwords("ipsw", cache, target["slot"], 1)[0]
        require(decoded == original,
                f"{target['label']} __got slot does not point at its class")
        cache_mapping = verify_mapping(
            reader, target["cacheSlot"], target["cacheSlotFileOffset"],
            data_cache, expected_init_prot=3)
        cache_raw = int.from_bytes(
            reader.read(target["cacheSlot"], 8), "little")
        require(cache_raw == 0,
                f"{target['label']} class-cache slot is not initially zero")
        targets.append({
            "bundle": target["bundle"],
            "label": target["label"],
            "slotUnslid": hex(target["slot"]),
            "originalClassSymbol": target["originalSymbol"],
            "originalClassUnslid": hex(original),
            "redirectedClassSymbol": REPLACEMENT_SYMBOL,
            "redirectedClassUnslid": hex(REPLACEMENT_CLASS),
            "slotMapping": mapping,
            "originalSlotValueUnslid": hex(decoded),
            "classCacheSlotUnslid": hex(target["cacheSlot"]),
            "classCacheInitialValue": "0x0000000000000000",
            "classCacheMapping": cache_mapping,
        })

    replacement = symbol_address(cache, REPLACEMENT_SYMBOL)
    require(replacement == REPLACEMENT_CLASS,
            "SBHApplicationIcon address changed")
    replacement_got_value = decoded_qwords(
        "ipsw", cache, REPLACEMENT_GOT, 1)[0]
    require(replacement_got_value == replacement,
            "SBHApplicationIcon __got slot does not point at its class")
    replacement_mapping = verify_mapping(
        reader, REPLACEMENT_GOT, REPLACEMENT_GOT_FILE_OFFSET, data_cache)

    helper = run(["ipsw", "dyld", "disass", str(cache),
                  "--vaddr", hex(HELPER_VM), "--no-color"]).stdout
    require("__got._OBJC_CLASS_$_SBHClockApplicationIcon" in helper,
            "helper no longer references the Clock __got slot")
    require("__got._OBJC_CLASS_$_SBHCalendarApplicationIcon" in helper,
            "helper no longer references the Calendar __got slot")
    require("applicationIconClass" in helper,
            "helper no longer has the ordinary applicationIconClass tail")
    require("add\tx2, x2, #0x298" in helper or
            "add x2, x2, #0x298" in helper,
            "helper Clock __got displacement changed")
    require("add\tx2, x2, #0x270" in helper or
            "add x2, x2, #0x270" in helper,
            "helper Calendar __got displacement changed")
    replacement_method = run(
        ["ipsw", "dyld", "disass", str(cache),
         "--vaddr", hex(0x1BE19D9E8), "--no-color"]).stdout
    require("__got._OBJC_CLASS_$_SBHApplicationIcon" in replacement_method,
            "applicationIconClass no longer references SBHApplicationIcon")
    require("add\tx2, x2, #0x240" in replacement_method or
            "add x2, x2, #0x240" in replacement_method,
            "applicationIconClass __got displacement changed")

    return {
        "schemaVersion": 1,
        "build": BUILD,
        "product": PRODUCT,
        "kind": "data-only-clock-calendar-class-got-redirect",
        "cache": {
            "main": {
                "fileName": cache.name,
                "uuid": MAIN_UUID,
            },
            "dataSubcache": {
                "fileName": data_cache.name,
                "uuid": DATA_UUID,
                "sha256": sha256_file(data_cache),
            },
        },
        "helper": {
            "symbol":
                "-[SBHIconModel iconClassForApplicationWithBundleIdentifier:]",
            "unslidVMAddress": hex(HELPER_VM),
            "length": hex(HELPER_LENGTH),
            "disassemblyEvidence": [
                "both special branches load x2 from SpringBoardHome __got",
                "__got._OBJC_CLASS_$_SBHClockApplicationIcon at #0x298",
                "__got._OBJC_CLASS_$_SBHCalendarApplicationIcon at #0x270",
                "the tail loads __got._OBJC_CLASS_$_SBHApplicationIcon at "
                "#0x240 and calls applicationIconClass",
            ],
            "classCacheSlots": [
                hex(TARGETS[0]["cacheSlot"]),
                hex(TARGETS[1]["cacheSlot"]),
            ],
        },
        "replacement": {
            "symbol": REPLACEMENT_SYMBOL,
            "classUnslid": hex(REPLACEMENT_CLASS),
            "gotSlotUnslid": hex(REPLACEMENT_GOT),
            "gotSlotValueUnslid": hex(replacement_got_value),
            "gotSlotMapping": replacement_mapping,
        },
        "targets": targets,
        "redirect": {
            "writeKind": "two 8-byte class-pointer stores",
            "slotValues": [
                {
                    "label": target["label"],
                    "from": hex(target["originalClass"]),
                    "to": hex(REPLACEMENT_CLASS),
                }
                for target in TARGETS
            ],
            "executableTextWritten": False,
            "methodListWritten": False,
            "perBoot": False,
            "perProcess": True,
            "survivesRespring": False,
            "survivesReboot": False,
            "respringRevertsPatch": True,
            "respringRequiredBeforeLiveIconRebuild": False,
            "postRespringObservation": {
                "kernelSlideBefore": "0x42ca0000",
                "kernelSlideAfter": "0x42ca0000",
                "springBoardPidBefore": 563,
                "springBoardPidAfter": 1264,
                "spotlightPidBefore": 580,
                "spotlightPidAfter": 1283,
                "clockPhysicalFrameBefore": "0x1016bf64000",
                "clockPhysicalFrameAfter": "0x1018e82c000",
                "clockValueAfter": "0x1ee45a180",
                "calendarValueAfter": "0x1ee45a568",
                "observedOn": "2026-10-21T01:04:02Z",
                "result": "GOT page re-created; both slots original after respring",
            },
            "staticThemeRecordsTouched": False,
        },
        "boundary": {
            "targetIsNonExecutableData": True,
            "targetSubcache": DATA_SUFFIX,
            "targetMaxProt": "rw-",
            "sameSubcacheFamilyPreviouslyProvedWritable":
                "docs/research/hail-mary-data-page-experiment.md",
            "forbiddenTarget":
                ".19 method-list IMP text page (level-3 write fault, "
                "panic 2026-10-20 23:18)",
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
