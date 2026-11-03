#!/usr/bin/env python3
"""Normalize IOSurface panic addresses and verify matching Mach-O UUIDs."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any


PANIC_RE = re.compile(
    r"panic\(cpu .*?Kernel data abort\. at pc (0x[0-9a-f]+), "
    r"lr (0x[0-9a-f]+)",
    re.IGNORECASE,
)
FAR_RE = re.compile(r"\bfar:\s*(0x[0-9a-f]+)", re.IGNORECASE)
SLIDE_RE = re.compile(r"^KernelCache slide:\s*(0x[0-9a-f]+)$", re.MULTILINE)
KERNEL_UUID_RE = re.compile(r"^Kernel UUID:\s*([0-9A-F-]+)$", re.MULTILINE)
FILESET_UUID_RE = re.compile(
    r"^Fileset Kernelcache UUID:\s*([0-9A-F]+)$", re.MULTILINE
)
IOSURFACE_RE = re.compile(
    r"com\.apple\.iokit\.IOSurface\(([^)]+)\)\[([0-9A-F-]+)\]"
    r"@(0x[0-9a-f]+)->(0x[0-9a-f]+)",
    re.IGNORECASE,
)
FRAME_RE = re.compile(r"\blr:\s*(0x[0-9a-f]+)", re.IGNORECASE)
UUID_RE = re.compile(r"UUID:\s*([0-9A-F-]+)", re.IGNORECASE)


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def decode_json_stream(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        if not isinstance(value, dict):
            raise ValueError(f"{path}: expected JSON objects, got {type(value).__name__}")
        objects.append(value)
    return objects


def _required(pattern: re.Pattern[str], text: str, label: str, path: Path) -> re.Match[str]:
    match = pattern.search(text)
    if match is None:
        raise ValueError(f"{path}: missing {label}")
    return match


def macho_uuid(path: Path) -> str:
    result = subprocess.run(
        ["dwarfdump", "--uuid", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    match = UUID_RE.search(result.stdout)
    if match is None:
        raise ValueError(f"{path}: dwarfdump did not report a UUID")
    return match.group(1).upper()


def parse_panic(path: Path) -> dict[str, Any]:
    objects = decode_json_stream(path)
    body = next((item for item in objects if isinstance(item.get("panicString"), str)), None)
    if body is None:
        raise ValueError(f"{path}: no panicString object")
    panic = body["panicString"]

    panic_match = _required(PANIC_RE, panic, "panic PC/LR", path)
    far_match = _required(FAR_RE, panic, "FAR", path)
    slide_match = _required(SLIDE_RE, panic, "KernelCache slide", path)
    kernel_uuid_match = _required(KERNEL_UUID_RE, panic, "kernel UUID", path)
    fileset_uuid_match = _required(FILESET_UUID_RE, panic, "fileset UUID", path)
    iosurface_match = _required(IOSURFACE_RE, panic, "IOSurface kext range", path)

    pc = int(panic_match.group(1), 16)
    lr = int(panic_match.group(2), 16)
    far = int(far_match.group(1), 16)
    slide = int(slide_match.group(1), 16)
    iosurface_start = int(iosurface_match.group(3), 16)
    iosurface_end = int(iosurface_match.group(4), 16)
    backtrace = panic.split("Panicked thread:", 1)[-1]
    backtrace = backtrace.split("Kernel Extensions in backtrace:", 1)[0]
    iosurface_frames = [
        int(match.group(1), 16)
        for match in FRAME_RE.finditer(backtrace)
        if iosurface_start <= int(match.group(1), 16) <= iosurface_end
    ]

    return {
        "path": str(path.resolve()),
        "incident": body.get("incident") or objects[0].get("incident_id"),
        "os_version": objects[0].get("os_version") or body.get("build"),
        "kernel_uuid": kernel_uuid_match.group(1).upper(),
        "fileset_kernelcache_uuid": fileset_uuid_match.group(1).upper(),
        "kernelcache_slide": _hex(slide),
        "runtime": {
            "pc": _hex(pc),
            "lr": _hex(lr),
            "far": _hex(far),
            "iosurface_start": _hex(iosurface_start),
            "iosurface_end": _hex(iosurface_end),
            "iosurface_backtrace_frames": [_hex(frame) for frame in iosurface_frames],
        },
        "normalized": {
            "pc": _hex(pc - slide),
            "lr": _hex(lr - slide),
            "iosurface_text_exec_base": _hex(iosurface_start - slide),
            "iosurface_lr_offset": f"0x{lr - iosurface_start:x}",
            "iosurface_backtrace_frame_offsets": [
                f"0x{frame - iosurface_start:x}" for frame in iosurface_frames
            ],
        },
        "iosurface": {
            "version": iosurface_match.group(1),
            "uuid": iosurface_match.group(2).upper(),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("panic", type=Path, nargs="+", help="panic-full IPS file")
    parser.add_argument("--kernel", type=Path, help="extracted com.apple.kernel Mach-O")
    parser.add_argument(
        "--iosurface", type=Path, help="extracted com.apple.iokit.IOSurface Mach-O"
    )
    args = parser.parse_args()

    panics = [parse_panic(path) for path in args.panic]
    signatures = {
        (
            panic["normalized"]["pc"],
            panic["normalized"]["lr"],
            panic["normalized"]["iosurface_text_exec_base"],
            panic["runtime"]["far"],
        )
        for panic in panics
    }
    result: dict[str, Any] = {
        "panics": panics,
        "same_normalized_signature": len(signatures) == 1,
    }

    if args.kernel is not None:
        observed = macho_uuid(args.kernel)
        expected = {panic["kernel_uuid"] for panic in panics}
        result["kernel_image"] = {
            "path": str(args.kernel.resolve()),
            "uuid": observed,
            "matches_panics": expected == {observed},
        }
    if args.iosurface is not None:
        observed = macho_uuid(args.iosurface)
        expected = {panic["iosurface"]["uuid"] for panic in panics}
        result["iosurface_image"] = {
            "path": str(args.iosurface.resolve()),
            "uuid": observed,
            "matches_panics": expected == {observed},
        }

    print(json.dumps(result, indent=2, sort_keys=True))
    image_checks = [
        value["matches_panics"]
        for key, value in result.items()
        if key.endswith("_image")
    ]
    return 0 if result["same_normalized_signature"] and all(image_checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
