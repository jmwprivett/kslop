#!/usr/bin/env python3
"""Inventory every live 23A341 IOKit notification action through read-only KRW."""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from cnd_iokit_notification_action_harvest import (
    BUILD,
    DICTIONARY_COUNT_OFFSET,
    DICTIONARY_ENTRIES_OFFSET,
    DICTIONARY_ENTRY_SIZE,
    KERNEL_UUID,
    MAX_DICTIONARY_COUNT,
    MAX_NOTIFICATION_COUNT,
    NOTIFIER_ACTION_OFFSET,
    NOTIFIER_CALLBACK_OFFSET,
    NOTIFIER_COLLECTION_OFFSET,
    NOTIFIER_ENABLED_OFFSET,
    NOTIFIER_REFCON_OFFSET,
    NOTIFIER_SIZE,
    NOTIFIER_TYPE_OFFSET,
    ORDERED_SET_ARRAY_OFFSET,
    ORDERED_SET_COUNT_OFFSET,
    PRODUCT,
    ProviderReader,
    STATIC_FILESET_BASE,
    STATIC_NOTIFICATION_DICTIONARY_GLOBAL,
    STATIC_TEXT,
    _code_identity,
    _hex,
    _kernel_pointer,
    _u32,
    _u64,
)
from cnd_remotecall_lab import DEFAULT_KNOWN_HOSTS, LabError, SSH, require_vphone
from cnd_vphone_krw import debugger_kernel_address


SCHEMA = "com.zeroxjf.cyanide.iokit-notification-action-inventory"
SCHEMA_VERSION = 1
DEFAULT_GRAPH = (
    Path(__file__).resolve().parents[2]
    / "build/rea-secure-execution-23A341-iphone17,3"
    / "pac-dispatch-graph-61de.jsonl"
)
AUXILIARY_ACTION_OFFSET = 0x30
BLOCK_NOTIFICATION_ACTION = 0xFFFFFE00081C773C
BLOCK_INVOKE_OFFSET = 0x10
BLOCK_DESCRIPTOR_OFFSET = 0x18
BLOCK_CAPTURE_OFFSET = 0x20
BLOCK_MAX_SIZE = 0x400


class InventoryError(RuntimeError):
    pass


def _code_pointer(value: int) -> int:
    return _code_identity(value) | 0xFFFF800000000000


def load_graph(path: Path) -> dict[int, dict[str, Any]]:
    records: dict[int, dict[str, Any]] = {}
    summary = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise InventoryError(f"cannot read dispatch graph: {error}") from error
    for number, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise InventoryError(f"invalid graph JSON at line {number}") from error
        if record.get("kind") == "summary":
            summary += 1
            if record.get("kernelUUID") != KERNEL_UUID or \
                    record.get("domains") != ["0x00000000000061de"] or \
                    record.get("failures") != []:
                raise InventoryError("dispatch graph identity or completeness failed")
            continue
        if record.get("kind") != "dispatch-target":
            raise InventoryError(f"unknown graph record at line {number}")
        try:
            target = int(record["target"], 16)
        except (KeyError, TypeError, ValueError) as error:
            raise InventoryError(f"invalid graph target at line {number}") from error
        if target in records:
            raise InventoryError(f"duplicate graph target {_hex(target)}")
        records[target] = record
    if summary != 1 or not records:
        raise InventoryError("dispatch graph has no unique summary/targets")
    return records


def inventory(
    read: Callable[[int, int], bytes], live_text: int, kernel_uuid: str,
    graph: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    if kernel_uuid.upper() != KERNEL_UUID:
        raise InventoryError(
            f"live kernel UUID {kernel_uuid} does not match {KERNEL_UUID}"
        )
    if live_text < STATIC_TEXT or live_text & 0x3FFF:
        raise InventoryError("live kernel text has an invalid exact-build slide")
    slide = live_text - STATIC_TEXT
    live_base = STATIC_FILESET_BASE + slide
    dictionary_global = STATIC_NOTIFICATION_DICTIONARY_GLOBAL + slide
    dictionary = _kernel_pointer(
        _u64(read(dictionary_global, 8), 0), "notification dictionary",
    )
    dictionary_header = read(dictionary, 0x28)
    dictionary_count = _u32(dictionary_header, DICTIONARY_COUNT_OFFSET)
    if dictionary_count == 0 or dictionary_count > MAX_DICTIONARY_COUNT:
        raise InventoryError(
            f"notification dictionary count is out of bounds: {dictionary_count}"
        )
    entries = _kernel_pointer(
        _u64(dictionary_header, DICTIONARY_ENTRIES_OFFSET),
        "notification dictionary entries",
    )
    entry_data = read(entries, dictionary_count * DICTIONARY_ENTRY_SIZE)

    collections: list[dict[str, Any]] = []
    notifiers: list[dict[str, Any]] = []
    seen_objects: set[int] = set()
    for dictionary_index in range(dictionary_count):
        offset = dictionary_index * DICTIONARY_ENTRY_SIZE
        notification_type = _kernel_pointer(
            _u64(entry_data, offset), f"notification type {dictionary_index}",
        )
        collection = _kernel_pointer(
            _u64(entry_data, offset + 8), f"notification collection {dictionary_index}",
        )
        collection_header = read(collection, 0x40)
        count = _u32(collection_header, ORDERED_SET_COUNT_OFFSET)
        if count > MAX_NOTIFICATION_COUNT:
            raise InventoryError(
                f"notification collection {dictionary_index} count is out of bounds: {count}"
            )
        array = 0
        objects = b""
        if count:
            array = _kernel_pointer(
                _u64(collection_header, ORDERED_SET_ARRAY_OFFSET),
                f"notification collection {dictionary_index} array",
            )
            objects = read(array, count * 8)
        collections.append({
            "dictionaryIndex": dictionary_index,
            "notificationType": _hex(notification_type),
            "collection": _hex(collection),
            "array": _hex(array) if array else None,
            "count": count,
        })
        for collection_index in range(count):
            notifier = _kernel_pointer(
                _u64(objects, collection_index * 8),
                f"notification object {dictionary_index}:{collection_index}",
            )
            if notifier in seen_objects:
                raise InventoryError(f"duplicate notifier object {_hex(notifier)}")
            seen_objects.add(notifier)
            body = read(notifier, NOTIFIER_SIZE)
            owner = _kernel_pointer(
                _u64(body, NOTIFIER_COLLECTION_OFFSET), "notifier owner collection",
            )
            object_type = _kernel_pointer(
                _u64(body, NOTIFIER_TYPE_OFFSET), "notifier notification type",
            )
            if owner != collection or object_type != notification_type:
                raise InventoryError(
                    f"notifier ownership/type drift at {dictionary_index}:{collection_index}"
                )
            action = _u64(body, NOTIFIER_ACTION_OFFSET)
            if action == 0:
                raise InventoryError(
                    f"notifier action is null at {dictionary_index}:{collection_index}"
                )
            live_action = _code_pointer(action)
            if live_action < slide:
                raise InventoryError("notifier action precedes exact-build slide")
            static_action = live_action - slide
            graph_record = graph.get(static_action)
            auxiliary = _u64(body, AUXILIARY_ACTION_OFFSET)
            callback = _u64(body, NOTIFIER_CALLBACK_OFFSET)
            record: dict[str, Any] = {
                "dictionaryIndex": dictionary_index,
                "collectionIndex": collection_index,
                "notificationType": _hex(notification_type),
                "notifier": _hex(notifier),
                "actionIA61DE": _hex(action),
                "actionLive": _hex(live_action),
                "actionStatic": _hex(static_action),
                "auxiliaryRaw": _hex(auxiliary),
                "callbackRaw": _hex(callback),
                "refcon": _hex(_u64(body, NOTIFIER_REFCON_OFFSET)),
                "enabled": _u32(body, NOTIFIER_ENABLED_OFFSET),
                "graphMapped": graph_record is not None,
            }
            if auxiliary:
                record["auxiliaryIdentityLive"] = _hex(_code_pointer(auxiliary))
            if callback:
                record["callbackIdentityLive"] = _hex(_code_pointer(callback))
            if static_action == BLOCK_NOTIFICATION_ACTION:
                block = _kernel_pointer(
                    _u64(body, NOTIFIER_REFCON_OFFSET),
                    "block notification refcon",
                )
                block_header = read(block, BLOCK_CAPTURE_OFFSET)
                invoke_raw = _u64(block_header, BLOCK_INVOKE_OFFSET)
                descriptor = _kernel_pointer(
                    _u64(block_header, BLOCK_DESCRIPTOR_OFFSET),
                    "block descriptor",
                )
                descriptor_header = read(descriptor, 0x10)
                block_size = _u64(descriptor_header, 8)
                if block_size < BLOCK_CAPTURE_OFFSET or \
                        block_size > BLOCK_MAX_SIZE or block_size & 7:
                    raise InventoryError(
                        f"block notification size is invalid: {block_size:#x}"
                    )
                block_body = read(block, block_size)
                invoke_live = _code_pointer(invoke_raw)
                if invoke_live < slide:
                    raise InventoryError("block invoke precedes exact-build slide")
                record["block"] = {
                    "object": _hex(block),
                    "size": block_size,
                    "flags": _hex(_u32(block_header, 8)),
                    "invokeRaw": _hex(invoke_raw),
                    "invokeLive": _hex(invoke_live),
                    "invokeStatic": _hex(invoke_live - slide),
                    "descriptor": _hex(descriptor),
                    "captureWords": [
                        _hex(_u64(block_body, offset))
                        for offset in range(
                            BLOCK_CAPTURE_OFFSET, block_size, 8
                        )
                    ],
                }
            if graph_record is not None:
                record["image"] = graph_record["image"]
                record["signers"] = graph_record["signers"]
                record["indirectBranches"] = graph_record["indirectBranches"]
            notifiers.append(record)

    counts = Counter(record["actionStatic"] for record in notifiers)
    unique_actions: list[dict[str, Any]] = []
    for action, count in sorted(counts.items()):
        sample = next(record for record in notifiers if record["actionStatic"] == action)
        unique_actions.append({
            "actionStatic": action,
            "actionLive": sample["actionLive"],
            "count": count,
            "graphMapped": sample["graphMapped"],
            "image": sample.get("image"),
            "authenticatedIndirectBranches": len(sample.get("indirectBranches", [])),
        })

    return {
        "schema": SCHEMA,
        "schemaVersion": SCHEMA_VERSION,
        "classification": "vm-runtime-observed",
        "identity": {
            "build": BUILD,
            "product": PRODUCT,
            "kernelUUID": kernel_uuid.upper(),
            "liveFilesetBase": _hex(live_base),
            "liveText": _hex(live_text),
            "slide": _hex(slide),
        },
        "dictionary": {
            "global": _hex(dictionary_global),
            "object": _hex(dictionary),
            "entries": _hex(entries),
            "count": dictionary_count,
        },
        "summary": {
            "collections": len(collections),
            "notifiers": len(notifiers),
            "uniqueActions": len(unique_actions),
            "graphMappedNotifiers": sum(
                record["graphMapped"] for record in notifiers
            ),
            "actionsWithAuthenticatedIndirectBranches": sum(
                item["authenticatedIndirectBranches"] > 0
                for item in unique_actions
            ),
        },
        "collections": collections,
        "uniqueActions": unique_actions,
        "notifiers": notifiers,
        "evidence": {
            "readOnly": True,
            "heapScanUsed": False,
            "usedKernelRead": True,
            "usedKernelWrite": False,
            "usedKernelCall": False,
            "claim": (
                "Bounded ownership walk of every live notifier in the global "
                "IOKit notification dictionary, cross-referenced against the "
                "exact-build REA-derived IA/0x61de dispatch graph."
            ),
            "notProved": [
                "Reachability of any notifier trigger from an unprivileged app",
                "Safety of transplanting any signed notifier field",
                "An arbitrary-target kernel call or PAC bypass",
            ],
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", default="mobile")
    parser.add_argument("--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--kernel-debug-port", type=int, default=62139)
    parser.add_argument(
        "--provider-helper", default="/var/tmp/cnd_lab_provider_krw",
    )
    parser.add_argument("--provider-socket", default="/var/tmp/cnd-lab-krw.sock")
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.password_env):
        raise InventoryError("password environment variable name is invalid")
    if not os.environ.get(args.password_env):
        raise InventoryError(f"set {args.password_env} to the VM SSH password")
    graph = load_graph(args.graph.expanduser().resolve())
    ssh = SSH(
        args.host, args.port, args.user, args.known_hosts.expanduser(),
        args.password_env,
    )
    require_vphone(ssh)
    live_text_text, kernel_uuid = debugger_kernel_address(args.kernel_debug_port)
    live_text = int(live_text_text, 16)
    reader = ProviderReader(
        ssh, args.provider_helper, args.provider_socket,
        STATIC_FILESET_BASE + (live_text - STATIC_TEXT),
    )
    result = inventory(reader, live_text, kernel_uuid, graph)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    if args.summary_only:
        sys.stdout.write(json.dumps({
            "identity": result["identity"],
            "summary": result["summary"],
            "uniqueActions": result["uniqueActions"],
        }, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InventoryError, LabError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
