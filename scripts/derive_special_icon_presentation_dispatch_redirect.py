#!/usr/bin/env python3
"""Derive Clock/Calendar static-presentation dispatch candidates for 23A341.

This tool is deliberately offline and read-only.  It resolves compact
Objective-C method metadata and the corresponding preoptimized dispatch-cache
entries in the exact iPhone17,2 23A341 shared cache.  It emits guarded bytes
for review, but contains no device transport or writer.

Clock has a previously process-local-proven ordinary-view replacement.
Calendar's two-SBLeafIcon route is only a static candidate: the earlier mixed
SBLeafIcon/SBIcon route rendered a grey plate and is retained as negative
evidence rather than promoted to runtime proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
import uuid
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from derive_flat_icon_imp_redirect import (  # noqa: E402
    CacheReader,
    compact_methods,
    decoded_qwords,
    signed_38,
    subcache_member,
)
from derive_flat_icon_patch import (  # noqa: E402
    IMAGE,
    SUB_UUID,
    cache_header,
    read_at,
    require,
)
from derive_special_icon_class_dispatch_redirect import (  # noqa: E402
    cache_paths,
    sha256_file,
)


BUILD = "23A341"
PRODUCT = "iPhone17,2"
MAIN_UUID = "DC5F2F67-1FC8-3905-873B-35D17D1A44E8"
READONLY_SUFFIX = ".34.dyldreadonly"
READONLY_UUID = "CEEB0D68-9BA9-3CC8-AEB1-8F23BAC92B58"
SELECTOR_BASE = 0x1FAC21900
FAST_DATA_MASK = 0x00007FFFFFFFFFF8
RAW_IMP_MASK = (1 << 38) - 1
PAGE_SIZE = 0x4000
GUARD_SIZE = 32
SHARED_REGION_BASE = 0x180000000
OS_VERSION = 0x1A0000
SUBCACHE_ARRAY_OFFSET = 0x41818
SUBCACHE_COUNT = 77
SUBCACHE_ENTRY_SIZE = 56
READONLY_SUBCACHE_INDEX = 33
READONLY_CACHE_VM_OFFSET = 0x78354000
CACHE_UUID_OFFSET = 0x58

PRESENTATION_TYPES = (
    "@72@0:8{SBIconImageInfo={CGSize=dd}dd}16@48@56Q64"
)

CLASSES = {
    "SBHClockApplicationIcon": {
        "address": 0x1EDA02180,
        "superclass": 0x1EDA021A8,
        "classRO": 0x1F3F95D70,
        "methods": 0x1BE1E6D70,
        "preoptCache": 0x1FFBFFFF8,
    },
    "SBHCalendarApplicationIcon": {
        "address": 0x1EDA02568,
        "superclass": 0x1EDA021A8,
        "classRO": 0x1F3FBE7B8,
        "methods": 0x1BE1E6B38,
        "preoptCache": 0x1FFC18468,
    },
    "SBHApplicationIcon": {
        "address": 0x1EDA021A8,
        "superclass": 0x1EDA01ED8,
        "classRO": 0x1F3FB6868,
        "methods": 0x1BE1E6550,
        "preoptCache": 0x1FFC0F840,
    },
    "SBLeafIcon": {
        "address": 0x1EDA01ED8,
        "superclass": 0x1EDA01FC8,
        "classRO": 0x1F3FC0738,
        "methods": 0x1BE2094A8,
        "preoptCache": 0,
    },
    "SBIcon": {
        "address": 0x1EDA01FC8,
        "superclass": 0x1ED609A98,
        "classRO": 0x1F3FD4628,
        "methods": 0x1BE1FE4A0,
        "preoptCache": 0,
    },
}

REDIRECTS = {
    "clockViewClass": {
        "targetClass": "SBHClockApplicationIcon",
        "selector": "iconImageViewClassForLocation:",
        "types": "#24@0:8@16",
        "targetIMP": 0x1BDF15698,
        "selectorOffset": 0xE41180,
        "slot": 35,
        "entry": 0x1FFC00120,
        "originalWord": 0x390460000BEBB2BA,
        "replacementClass": "SBIcon",
        "replacementSelector": "iconImageViewClassForLocation:",
        "replacementIMP": 0x1BE088C18,
        "redirectedWord": 0x390460000BE5E55A,
    },
    "calendarBundleIdentifier": {
        "targetClass": "SBHCalendarApplicationIcon",
        "selector": "applicationBundleIdentifierForImage",
        "types": "@16@0:8",
        "targetIMP": 0x1BE044D28,
        "selectorOffset": 0x151A29,
        "slot": 52,
        "entry": 0x1FFC18618,
        "originalWord": 0x05468A400BE6F610,
        "replacementClass": "SBLeafIcon",
        "replacementSelector": "applicationBundleIdentifierForImage",
        "replacementIMP": 0x1BDEBBF58,
        "redirectedWord": 0x05468A400BED1984,
    },
    "calendarImage": {
        "targetClass": "SBHCalendarApplicationIcon",
        "selector": "makeIconImageWithInfo:traitCollection:context:options:",
        "types": PRESENTATION_TYPES,
        "targetIMP": 0x1BE044D30,
        "selectorOffset": 0xA41180,
        "slot": 35,
        "entry": 0x1FFC18590,
        "originalWord": 0x290460000BE6F60E,
        "replacementClass": "SBLeafIcon",
        "replacementSelector":
            "makeIconImageWithInfo:traitCollection:context:options:",
        "replacementIMP": 0x1BE0540D8,
        "redirectedWord": 0x290460000BE6B924,
    },
    "calendarLayer": {
        "targetClass": "SBHCalendarApplicationIcon",
        "selector": "makeIconLayerWithInfo:traitCollection:context:options:",
        "types": PRESENTATION_TYPES,
        "targetIMP": 0x1BE044DD4,
        "selectorOffset": 0x1E7E42,
        "slot": 60,
        "entry": 0x1FFC18658,
        "originalWord": 0x079F90800BE6F5E5,
        "replacementClass": "SBLeafIcon",
        "replacementSelector":
            "makeIconLayerWithInfo:traitCollection:context:options:",
        "replacementIMP": 0x1BE054558,
        "redirectedWord": 0x079F90800BE6B804,
    },
}

REJECTED_CALENDAR_LAYER = {
    "replacementClass": "SBIcon",
    "replacementSelector":
        "makeIconLayerFromImageWithInfo:traitCollection:context:options:",
    "replacementIMP": 0x1BE1081A8,
    "redirectedWord": 0x079F90800BE3E8F0,
}


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True)
    require(
        result.returncode == 0,
        f"command failed: {' '.join(command)}\n{result.stderr}",
    )
    return result


def derive_selector_base(ipsw_tool: str, cache: Path) -> int:
    result = run([
        ipsw_tool,
        "dyld",
        "macho",
        str(cache),
        IMAGE,
        "--objc",
        "--verbose",
        "--no-color",
    ])
    matches = re.findall(
        r"rel method sel base off\s*:\s*(0x[0-9a-f]+)", result.stderr
    )
    require(len(matches) == 1,
            "relative-method selector base was not reported exactly once")
    result_base = cache_header(cache)["sharedRegionStart"] + int(matches[0], 16)
    require(result_base == SELECTOR_BASE,
            "relative-method selector base changed")
    return result_base


def find_method(methods: list[dict], selector: str) -> dict:
    matches = [method for method in methods
               if method["selector"] == selector]
    require(len(matches) == 1, f"method is not unique: {selector}")
    return matches[0]


def derive_class(
    reader: CacheReader,
    cache: Path,
    ipsw_tool: str,
    selector_base: int,
    class_name: str,
) -> dict:
    expected = CLASSES[class_name]
    isa, superclass, cache_buckets, preopt_cache, data_bits = decoded_qwords(
        ipsw_tool, cache, expected["address"], 5
    )
    class_ro = data_bits & FAST_DATA_MASK
    require(superclass == expected["superclass"],
            f"{class_name} superclass changed")
    require(preopt_cache == expected["preoptCache"],
            f"{class_name} preoptimized cache changed")
    require(class_ro == expected["classRO"],
            f"{class_name} class_ro_t changed")

    ro_words = decoded_qwords(ipsw_tool, cache, class_ro, 9)
    require(reader.cstring(ro_words[3]) == class_name,
            f"{class_name} class name changed")
    require(ro_words[4] == expected["methods"],
            f"{class_name} method list changed")
    method_header, methods = compact_methods(
        reader, selector_base, expected["methods"]
    )
    return {
        "name": class_name,
        "address": expected["address"],
        "isa": isa,
        "superclass": superclass,
        "initialCacheBuckets": cache_buckets,
        "preoptCache": preopt_cache,
        "classRO": class_ro,
        "methodList": expected["methods"],
        "methodHeader": method_header,
        "methods": methods,
    }


def public_method(method: dict) -> dict:
    return {
        "selector": method["selector"],
        "types": method["types"],
        "entryUnslid": hex(method["entry"]),
        "selectorOffset": hex(method["selectorOffset"]),
        "impUnslid": hex(method["imp"]),
    }


def runtime_cache_identity_metadata(cache: Path) -> dict:
    header = cache_header(cache)
    require(header["uuid"] == MAIN_UUID,
            "main cache UUID changed")
    require(header["sharedRegionStart"] == SHARED_REGION_BASE and
            header["osVersion"] == OS_VERSION and
            header["subcacheOffset"] == SUBCACHE_ARRAY_OFFSET and
            header["subcacheCount"] == SUBCACHE_COUNT,
            "main cache runtime identity metadata changed")
    entries = read_at(
        cache,
        header["subcacheOffset"],
        header["subcacheCount"] * SUBCACHE_ENTRY_SIZE,
    )
    expected_uuid = uuid.UUID(READONLY_UUID).bytes
    matches = [
        (index, entries[index * SUBCACHE_ENTRY_SIZE:
                        (index + 1) * SUBCACHE_ENTRY_SIZE])
        for index in range(header["subcacheCount"])
        if entries[index * SUBCACHE_ENTRY_SIZE:
                   index * SUBCACHE_ENTRY_SIZE + 16] == expected_uuid
    ]
    require(len(matches) == 1,
            "read-only subcache UUID membership changed")
    index, entry = matches[0]
    vm_offset = struct.unpack_from("<Q", entry, 16)[0]
    suffix = entry[24:].rstrip(b"\0").decode()
    require(index == READONLY_SUBCACHE_INDEX and
            vm_offset == READONLY_CACHE_VM_OFFSET and
            suffix == READONLY_SUFFIX,
            "read-only subcache runtime membership changed")
    return {
        "sharedRegionBaseUnslid": hex(SHARED_REGION_BASE),
        "headerByteLength": 0x1D8,
        "uuidOffset": hex(CACHE_UUID_OFFSET),
        "osVersion": hex(OS_VERSION),
        "subcacheArrayOffset": hex(SUBCACHE_ARRAY_OFFSET),
        "subcacheEntryCount": SUBCACHE_COUNT,
        "subcacheEntrySize": SUBCACHE_ENTRY_SIZE,
        "readonlySubcacheIndex": index,
        "readonlySubcacheVMOffset": hex(vm_offset),
        "readonlySubcacheHeaderUnslid": hex(
            SHARED_REGION_BASE + vm_offset
        ),
        "readonlySubcacheSuffix": suffix,
    }


def encode_redirect(class_address: int, selector_offset: int,
                    replacement_imp: int) -> int:
    relative_bytes = class_address - replacement_imp
    require(relative_bytes % 4 == 0,
            "replacement IMP is not word-aligned to the class")
    raw_offset = relative_bytes // 4
    require(-(1 << 37) <= raw_offset < (1 << 37),
            "replacement IMP does not fit the signed 38-bit field")
    return ((selector_offset << 38) | (raw_offset & RAW_IMP_MASK))


def derive_redirect(
    reader: CacheReader,
    readonly_cache: Path,
    classes: dict[str, dict],
    name: str,
) -> dict:
    expected = REDIRECTS[name]
    target_class = classes[expected["targetClass"]]
    replacement_class = classes[expected["replacementClass"]]
    target = find_method(target_class["methods"], expected["selector"])
    replacement = find_method(
        replacement_class["methods"], expected["replacementSelector"]
    )
    require(target["types"] == expected["types"] and
            target["imp"] == expected["targetIMP"] and
            target["selectorOffset"] == expected["selectorOffset"],
            f"{name} target method identity changed")
    require(replacement["types"] == expected["types"] and
            replacement["imp"] == expected["replacementIMP"],
            f"{name} replacement method identity or ABI changed")

    preopt_cache = target_class["preoptCache"]
    fallback, hash_params, occupied_flags, unused = struct.unpack(
        "<qHHI", reader.read(preopt_cache, 16)
    )
    shift = hash_params & 0x1F
    mask = hash_params >> 5
    occupied = occupied_flags & 0x3FFF
    has_inlines = (occupied_flags >> 14) & 1
    require(unused >> 31 == 1 and mask + 1 <= 2048,
            f"{name} preoptimized cache header changed")
    slot = (target["selectorOffset"] >> shift) & mask
    entry = preopt_cache + 16 + slot * 8
    require(slot == expected["slot"] and entry == expected["entry"],
            f"{name} dispatch entry moved")

    original_word = struct.unpack("<Q", reader.read(entry, 8))[0]
    selector_offset = original_word >> 38
    original_imp = target_class["address"] - signed_38(original_word) * 4
    require(original_word == expected["originalWord"] and
            selector_offset == expected["selectorOffset"] and
            original_imp == expected["targetIMP"],
            f"{name} original dispatch word changed")

    redirected_word = encode_redirect(
        target_class["address"], selector_offset, replacement["imp"]
    )
    require(redirected_word == expected["redirectedWord"],
            f"{name} redirected dispatch word changed")
    require((original_word >> 32) == (redirected_word >> 32),
            f"{name} redirect is not low-word-only")
    require(target_class["address"] - signed_38(redirected_word) * 4 ==
            replacement["imp"],
            f"{name} redirected dispatch word decodes incorrectly")

    original_guard = reader.read(entry, GUARD_SIZE)
    redirected_guard = bytearray(original_guard)
    struct.pack_into("<Q", redirected_guard, 0, redirected_word)
    redirected_guard = bytes(redirected_guard)

    dispatch_mapping = reader.mapping_for(entry, GUARD_SIZE)
    target_mapping = reader.mapping_for(target["imp"], 16)
    replacement_mapping = reader.mapping_for(replacement["imp"], 16)
    require(dispatch_mapping["path"] == readonly_cache and
            dispatch_mapping["uuid"] == READONLY_UUID and
            dispatch_mapping["initProt"] == 1 and
            dispatch_mapping["maxProt"] == 1,
            f"{name} entry is not in the pinned read-only subcache")
    require(target_mapping["uuid"] == SUB_UUID and
            replacement_mapping["uuid"] == SUB_UUID and
            target_mapping["initProt"] == target_mapping["maxProt"] == 5 and
            replacement_mapping["initProt"] ==
            replacement_mapping["maxProt"] == 5,
            f"{name} IMP is outside the pinned RX text subcache")

    return {
        "name": name,
        "target": {
            "class": target_class["name"],
            "classUnslid": hex(target_class["address"]),
            **public_method(target),
        },
        "dispatch": {
            "cacheHeaderUnslid": hex(preopt_cache),
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
            "slot": slot,
            "entryUnslid": hex(entry),
            "entryFileOffset": hex(reader.file_offset(entry, 8)),
            "frameUnslid": hex(entry & ~(PAGE_SIZE - 1)),
            "frameOffset": hex(entry & (PAGE_SIZE - 1)),
            "original": {
                "packedWord": f"0x{original_word:016x}",
                "decodedIMPUnslid": hex(original_imp),
                "guardHex": original_guard.hex(),
                "guardSHA256": hashlib.sha256(original_guard).hexdigest(),
            },
            "redirected": {
                "packedWord": f"0x{redirected_word:016x}",
                "decodedIMPUnslid": hex(replacement["imp"]),
                "guardHex": redirected_guard.hex(),
                "guardSHA256": hashlib.sha256(redirected_guard).hexdigest(),
            },
            "writeShape": {
                "kind": "one 32-bit low-word store",
                "originalLowWord": f"0x{original_word & 0xffffffff:08x}",
                "redirectedLowWord":
                    f"0x{redirected_word & 0xffffffff:08x}",
                "upperWordPreserved": f"0x{original_word >> 32:08x}",
            },
            "mapping": {
                "subcache": dispatch_mapping["path"].name,
                "uuid": dispatch_mapping["uuid"],
                "initProt": dispatch_mapping["initProt"],
                "maxProt": dispatch_mapping["maxProt"],
            },
        },
        "replacement": {
            "class": replacement_class["name"],
            **public_method(replacement),
            "subcache": replacement_mapping["path"].name,
            "subcacheUUID": replacement_mapping["uuid"],
            "fileOffset": hex(reader.file_offset(replacement["imp"], 16)),
            "first16BytesHex": reader.read(replacement["imp"], 16).hex(),
            "abiExact": True,
            "appleSharedCacheCode": True,
        },
    }


def rejected_calendar_route(
    reader: CacheReader,
    classes: dict[str, dict],
    calendar_image: dict,
    calendar_layer: dict,
) -> dict:
    target_class = classes["SBHCalendarApplicationIcon"]
    replacement_class = classes[REJECTED_CALENDAR_LAYER["replacementClass"]]
    replacement = find_method(
        replacement_class["methods"],
        REJECTED_CALENDAR_LAYER["replacementSelector"],
    )
    require(replacement["types"] == PRESENTATION_TYPES and
            replacement["imp"] == REJECTED_CALENDAR_LAYER["replacementIMP"],
            "historical Calendar layer replacement identity changed")
    target_word = int(calendar_layer["dispatch"]["original"]["packedWord"], 16)
    selector_offset = target_word >> 38
    redirected_word = encode_redirect(
        target_class["address"], selector_offset, replacement["imp"]
    )
    require(redirected_word == REJECTED_CALENDAR_LAYER["redirectedWord"],
            "historical Calendar layer redirect word changed")
    mapping = reader.mapping_for(replacement["imp"], 16)
    require(mapping["uuid"] == SUB_UUID and
            mapping["initProt"] == mapping["maxProt"] == 5,
            "historical Calendar replacement left the pinned RX subcache")
    return {
        "status": "rejected-by-retained-runtime-evidence",
        "reason": (
            "The earlier process-local class-wide pair bypassed the exact "
            "Calendar provider path and rendered a grey generic plate."
        ),
        "imageRedirect": {
            "sameAsCandidate": calendar_image["name"],
            "replacement": calendar_image["replacement"],
        },
        "layerRedirect": {
            "target": calendar_layer["target"],
            "replacement": {
                "class": replacement_class["name"],
                **public_method(replacement),
                "subcache": mapping["path"].name,
                "subcacheUUID": mapping["uuid"],
                "fileOffset": hex(reader.file_offset(replacement["imp"], 16)),
                "first16BytesHex": reader.read(replacement["imp"], 16).hex(),
            },
            "redirectedWord": f"0x{redirected_word:016x}",
        },
        "differenceFromNewCandidate": (
            "The new static candidate uses SBLeafIcon's direct IconServices "
            "layer factory instead of SBIcon's image-backed layer factory."
        ),
    }


def derive(cache: Path, ipsw_tool: str) -> dict:
    runtime_identity = runtime_cache_identity_metadata(cache)
    readonly_cache = subcache_member(
        cache, READONLY_SUFFIX, READONLY_UUID
    )
    reader = CacheReader(cache_paths(cache))
    selector_base = derive_selector_base(ipsw_tool, cache)
    classes = {
        name: derive_class(
            reader, cache, ipsw_tool, selector_base, name
        )
        for name in CLASSES
    }

    ordinary = classes["SBHApplicationIcon"]
    image_selector = REDIRECTS["calendarImage"]["selector"]
    layer_selector = REDIRECTS["calendarLayer"]["selector"]
    require(not any(method["selector"] in (image_selector, layer_selector)
                    for method in ordinary["methods"]),
            "SBHApplicationIcon now directly overrides a presentation factory")
    require(ordinary["superclass"] == classes["SBLeafIcon"]["address"],
            "ordinary application icon no longer inherits SBLeafIcon")

    redirects = {
        name: derive_redirect(
            reader, readonly_cache, classes, name
        )
        for name in REDIRECTS
    }
    rejected = rejected_calendar_route(
        reader,
        classes,
        redirects["calendarImage"],
        redirects["calendarLayer"],
    )

    class_evidence = {}
    for name, item in classes.items():
        class_evidence[name] = {
            "classUnslid": hex(item["address"]),
            "superclassUnslid": hex(item["superclass"]),
            "classROUnslid": hex(item["classRO"]),
            "methodListUnslid": hex(item["methodList"]),
            "preoptimizedCacheUnslid": hex(item["preoptCache"]),
            "methodListHeader": {
                "entsizeAndFlags": hex(
                    item["methodHeader"]["entsizeAndFlags"]
                ),
                "count": item["methodHeader"]["count"],
                "entrySize": item["methodHeader"]["entrySize"],
            },
        }

    return {
        "schemaVersion": 1,
        "build": BUILD,
        "product": PRODUCT,
        "kind": "static-special-icon-presentation-dispatch-derivation",
        "evidenceClass": "static-derived",
        "runtimeVerified": False,
        "cache": {
            "main": {
                "fileName": cache.name,
                "uuid": MAIN_UUID,
                "runtimeIdentity": runtime_identity,
            },
            "relativeMethodSelectorBaseUnslid": hex(selector_base),
            "textSubcacheUUID": SUB_UUID,
            "readonlySubcache": {
                "fileName": readonly_cache.name,
                "uuid": READONLY_UUID,
                "sha256": sha256_file(readonly_cache),
            },
        },
        "classEvidence": class_evidence,
        "ordinaryApplicationIconEvidence": {
            "class": "SBHApplicationIcon",
            "superclass": "SBLeafIcon",
            "directImageFactoryOverride": False,
            "directLayerFactoryOverride": False,
            "meaning": (
                "The ordinary application-icon route inherits the two "
                "SBLeafIcon factories used by the Calendar candidate."
            ),
        },
        "clock": {
            "status": "static-candidate",
            "confidence": "high-static-low-runtime-until-tested",
            "redirects": [redirects["clockViewClass"]],
            "basis": (
                "The ABI-identical SBIcon view-class factory was already "
                "observed to produce ordinary static Clock presentation in "
                "the process-local route; this derivation only changes where "
                "that dispatch decision is stored."
            ),
        },
        "calendar": {
            "status": "candidate-for-bounded-runtime-probe-only",
            "confidence": "low-until-appearance-tested",
            "redirects": [
                redirects["calendarBundleIdentifier"],
                redirects["calendarImage"],
                redirects["calendarLayer"],
            ],
            "basis": (
                "The rejected two-factory route reached SBLeafIcon without "
                "an application bundle identifier because Calendar overrides "
                "applicationBundleIdentifierForImage to return nil. The new "
                "transaction first restores SBLeafIcon's inherited bundle-ID "
                "lookup, then redirects both factories to the exact methods "
                "inherited by ordinary SBHApplicationIcon."
            ),
            "negativeEvidence": rejected,
            "retainedTwoFactoryGreyEvidence": {
                "status": "rejected-by-user-observed-physical-appearance",
                "route": ["calendarImage", "calendarLayer"],
                "bundleIdentifierRedirectIncluded": False,
                "observation": "grey generic plate",
                "artifactRetainedByThisDerivation": False,
                "claimBoundary": (
                    "This rejects only the two-factory route. It does not "
                    "establish the new bundle-source candidate."
                ),
            },
            "notProved": [
                "that the Calendar load context is sufficient for both inherited factories",
                "that Calendar's active data source returns its stock bundle identifier",
                "that the result is the themed static Calendar rather than a grey plate",
                "that Home and Spotlight exercise both redirected entries after restart",
            ],
        },
        "runtimeBoundary": {
            "writerIncluded": False,
            "deviceOperationPerformed": False,
            "processInjectionRequiredByDesign": False,
            "remoteCallRequiredByDesign": False,
            "homeVisibilityPreconditionByDesign": False,
            "canonicalObjectMigrationRequiredByDesign": False,
            "processRestartAfterApplyRequired": True,
            "perBootNotRebootPersistent": True,
            "targetFrames": [
                redirects["clockViewClass"]["dispatch"]["frameUnslid"],
                redirects["calendarImage"]["dispatch"]["frameUnslid"],
            ],
            "sameBootIdenticalWriteTicketRequiredPerFrame": True,
            "reason": (
                "The entries occupy two previously unproved 16 KiB read-only "
                "frames; mapping-level success elsewhere in .34 is not a "
                "same-page aperture result."
            ),
        },
        "nextRuntimeGate": (
            "Run identical-bytes-only aperture probes for both exact frames, "
            "then test Clock alone before a separately reversible three-entry "
            "Calendar appearance trial."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--ipsw-tool", default="ipsw")
    parser.add_argument("--verify-manifest", type=Path)
    args = parser.parse_args()
    try:
        manifest = derive(args.cache, args.ipsw_tool)
        if args.verify_manifest:
            expected = json.loads(args.verify_manifest.read_text())
            require(manifest == expected,
                    "derived manifest does not equal the reviewed manifest")
            print(
                f"Verified {BUILD}/{PRODUCT}: Clock entry, Calendar image/"
                "layer/bundle-source entries, ABI-identical replacements, "
                "guards, and the retained rejected Calendar routes."
            )
        else:
            print(json.dumps(manifest, indent=2, sort_keys=True))
    except (OSError, KeyError, ValueError) as error:
        parser.exit(1, f"derivation refused: {error}\n")


if __name__ == "__main__":
    main()
