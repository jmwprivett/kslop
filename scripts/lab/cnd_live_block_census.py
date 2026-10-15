#!/usr/bin/env python3
"""Inventory persistent exact-build kernel block literals through KDP.

The thread-call callback at 0xfffffe00081d46f4 consumes a block object whose
invoke pointer at ``block + 0x10`` is signed with that field address.  This tool
looks for already-signed persistent block literals in mapped kernel/fileset
sections; it never writes memory and never invokes a callback.

Mach-O section ranges are taken from the extracted exact-build images.  KDP
dumps those bounded ranges while the VM is stopped, then the host checks the
standard Block ABI layout (isa, flags/reserved, invoke, descriptor).  Results
remain candidates until the invoke function is reviewed with REA.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"
STATIC_TEXT = 0xFFFFFE0007008000
STATIC_BASE = 0xFFFFFE0007004000
FILES_MAX_SPAN = 0x40000000
BLOCK_IS_GLOBAL = 1 << 28
BLOCK_HAS_SIGNATURE = 1 << 30
SECTION_RE = re.compile(
    r"Section\n"
    r"\s+sectname\s+(\S+)\n"
    r"\s+segname\s+(\S+)\n"
    r"\s+addr\s+(?:0x)?([0-9a-fA-F]+)\n"
    r"\s+size\s+0x([0-9a-fA-F]+)",
)
ADDRESS_RE = re.compile(r"^Load Address:\s*(0x[0-9a-fA-F]{16})\s*$",
                        re.MULTILINE)
UUID_RE = re.compile(r"^Kernel UUID:\s*([0-9A-Fa-f-]{36})\s*$",
                     re.MULTILINE)


@dataclass(frozen=True)
class Section:
    image: str
    segment: str
    section: str
    start: int
    size: int
    writable: bool


class CensusError(RuntimeError):
    """The exact-build image or debugger census contract failed."""


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _run_objdump(image: Path) -> tuple[Path, str]:
    completed = subprocess.run(
        ["xcrun", "llvm-objdump", "--macho", "--all-headers", os.fspath(image)],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if completed.returncode != 0:
        raise CensusError(
            f"{image}: llvm-objdump failed ({completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    return image, completed.stdout


def _discover_sections(images: Iterable[Path], jobs: int) -> list[Section]:
    image_list = sorted(set(images))
    sections: list[Section] = []
    failures: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {executor.submit(_run_objdump, image): image
                   for image in image_list}
        for future in concurrent.futures.as_completed(futures):
            try:
                image, report = future.result()
            except CensusError as error:
                failures.append(str(error))
                continue
            for match in SECTION_RE.finditer(report):
                section, segment, start_text, size_text = match.groups()
                size = int(size_text, 16)
                if size == 0:
                    continue
                # Persistent Blocks normally live in __DATA_CONST.__const.
                # Writable data is included because a mutable captured field
                # is strictly more useful.  Executable and string sections are
                # excluded to keep the debugger read set bounded.
                if segment not in {
                    "__DATA", "__DATA_CONST", "__BOOTDATA", "__KLDDATA",
                    "__PRELINK_DATA", "__PLK_DATA_CONST",
                }:
                    continue
                sections.append(Section(
                    image=image.name,
                    segment=segment,
                    section=section,
                    start=int(start_text, 16),
                    size=size,
                    writable=segment in {
                        "__DATA", "__BOOTDATA", "__KLDDATA", "__PRELINK_DATA",
                    },
                ))
    if failures:
        raise CensusError("section discovery failed:\n" + "\n".join(failures))
    return sorted(sections, key=lambda item: (item.start, item.size, item.image))


def _dump_sections(
    kernel: Path, port: int, sections: Sequence[Section], timeout: int,
    directory: Path,
) -> tuple[int, str, dict[int, Path], list[int]]:
    commands = [
        f'target create "{kernel}"',
        "platform select remote-ios",
        f"gdb-remote 127.0.0.1:{port}",
        "settings set interpreter.stop-command-source-on-error false",
    ]
    paths: dict[int, Path] = {}
    for index, section in enumerate(sections):
        output = directory / f"section-{index:04d}.bin"
        paths[index] = output
        start = section.start
        end = start + section.size
        commands.append(
            f'memory read --force --binary --outfile "{output}" '
            f"CND_SLIDE+{start:#x} CND_SLIDE+{end:#x}"
        )
    commands.append("process detach")
    # The placeholder is replaced after the debug stub reports its exact slide;
    # LLDB command files cannot capture a custom Load Address record in a variable,
    # so obtain identity with a short detached handshake first.
    identity = subprocess.run(
        ["xcrun", "lldb", "--batch", "-o", f'target create "{kernel}"',
         "-o", "platform select remote-ios", "-o", f"gdb-remote 127.0.0.1:{port}",
         "-o", "process detach"],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        timeout=min(timeout, 60),
    )
    if identity.returncode != 0 or "Process 1 detached" not in identity.stdout:
        raise CensusError("KDP identity handshake failed or did not detach")
    loads = ADDRESS_RE.findall(identity.stdout)
    uuids = UUID_RE.findall(identity.stdout)
    if len(loads) != 1 or len(uuids) != 1:
        raise CensusError("KDP identity handshake was ambiguous")
    uuid = uuids[0].upper()
    if uuid != KERNEL_UUID:
        raise CensusError(f"live kernel UUID {uuid} does not match {KERNEL_UUID}")
    live_text = int(loads[0], 16)
    if live_text < STATIC_TEXT:
        raise CensusError("live kernel text precedes exact-build static text")
    slide = live_text - STATIC_TEXT
    commands = [command.replace("CND_SLIDE+", f"{slide:#x}+")
                for command in commands]

    command_file = directory / "census.lldb"
    command_file.write_text("\n".join(commands) + "\n", encoding="utf-8")
    try:
        completed = subprocess.run(
            ["xcrun", "lldb", "--batch", "-s", os.fspath(command_file)],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise CensusError(f"KDP section census timed out after {timeout}s") from error
    if completed.returncode != 0:
        raise CensusError(
            f"KDP section census failed ({completed.returncode}):\n"
            f"{completed.stdout[-4000:]}"
        )
    if "Process 1 detached" not in completed.stdout:
        raise CensusError("KDP section census did not detach")
    failed = [index for index, path in paths.items()
              if not path.is_file() or path.stat().st_size != sections[index].size]
    return slide, uuid, paths, failed


def _canonical_pointer(raw: int) -> int:
    return (raw & 0x00007FFFFFFFFFFF) | 0xFFFF800000000000


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 8], "little")


def _scan_section(
    section: Section, data: bytes, slide: int,
) -> list[dict[str, Any]]:
    live_base = STATIC_BASE + slide
    result: list[dict[str, Any]] = []
    for offset in range(0, max(0, len(data) - 0x20 + 1), 8):
        isa_raw = _u64(data, offset)
        flags_word = _u64(data, offset + 8)
        invoke_raw = _u64(data, offset + 0x10)
        descriptor_raw = _u64(data, offset + 0x18)
        flags = flags_word & 0xFFFFFFFF
        reserved = flags_word >> 32
        # The persistent literals in this build use the canonical global-block
        # flag word: BLOCK_IS_GLOBAL | BLOCK_HAS_SIGNATURE.  Merely testing the
        # global bit admits arbitrary packed data whose low word happens to set
        # bit 28, which produced two convincing-looking false positives in the
        # first census.
        expected_flags = BLOCK_IS_GLOBAL | BLOCK_HAS_SIGNATURE
        if reserved != 0 or flags != expected_flags:
            continue
        invoke = _canonical_pointer(invoke_raw)
        isa = _canonical_pointer(isa_raw)
        descriptor = _canonical_pointer(descriptor_raw)
        if (
            invoke_raw == 0 or invoke & 3 != 0
            or not live_base <= invoke < live_base + FILES_MAX_SPAN
            or isa_raw == 0 or isa & 7 != 0
            or not live_base <= isa < live_base + FILES_MAX_SPAN
            or descriptor_raw == 0 or descriptor & 7 != 0
            or not live_base <= descriptor < live_base + FILES_MAX_SPAN
        ):
            continue
        address = section.start + offset
        result.append({
            "kind": "block-candidate",
            "image": section.image,
            "segment": section.segment,
            "section": section.section,
            "writable": section.writable,
            "staticAddress": _hex(address),
            "address": _hex(address + slide),
            "flags": f"0x{flags:08x}",
            "hasSignature": bool(flags & BLOCK_HAS_SIGNATURE),
            "rawIsa": _hex(isa_raw),
            "isa": _hex(isa),
            "rawInvoke": _hex(invoke_raw),
            "invoke": _hex(invoke),
            "staticInvoke": _hex(invoke - slide),
            "rawDescriptor": _hex(descriptor_raw),
            "descriptor": _hex(descriptor),
        })
    return result


def _images(paths: Iterable[Path]) -> list[Path]:
    result: list[Path] = []
    for path in paths:
        if path.is_dir():
            result.extend(value for value in path.iterdir() if value.is_file())
        elif path.is_file():
            result.append(path)
        else:
            raise CensusError(f"input does not exist: {path}")
    return sorted(set(result))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path,
                        help="exact-build Mach-O images or directories")
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--jobs", type=int, default=min(6, os.cpu_count() or 1))
    parser.add_argument("--timeout", type=int, default=300)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.kernel.is_file():
        raise CensusError(f"kernel does not exist: {args.kernel}")
    if not 6000 <= args.port <= 65535:
        raise CensusError("--port must be between 6000 and 65535")
    if args.jobs < 1 or args.jobs > 32:
        raise CensusError("--jobs must be from 1 to 32")
    images = _images(args.paths)
    sections = _discover_sections(images, args.jobs)
    if not sections:
        raise CensusError("no persistent data sections found")
    with tempfile.TemporaryDirectory(prefix="cnd-live-block-census-") as temp:
        slide, uuid, dumps, failed = _dump_sections(
            args.kernel, args.port, sections, args.timeout, Path(temp),
        )
        records: list[dict[str, Any]] = []
        for index, section in enumerate(sections):
            if index in failed:
                continue
            records.extend(_scan_section(section, dumps[index].read_bytes(), slide))
    # The same mapped range can appear in more than one extracted image.  Keep
    # one record per live block address and prefer a writable attribution.
    by_address: dict[str, dict[str, Any]] = {}
    for record in records:
        prior = by_address.get(record["address"])
        if prior is None or record["writable"] and not prior["writable"]:
            by_address[record["address"]] = record
    records = sorted(by_address.values(), key=lambda item: int(item["address"], 16))
    for record in records:
        print(json.dumps(record, separators=(",", ":")))
    print(json.dumps({
        "kind": "summary",
        "kernelUUID": uuid,
        "slide": _hex(slide),
        "images": len(images),
        "sections": len(sections),
        "sectionReadFailures": len(failed),
        "candidates": len(records),
        "writableCandidates": sum(bool(record["writable"]) for record in records),
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }, separators=(",", ":")))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CensusError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
