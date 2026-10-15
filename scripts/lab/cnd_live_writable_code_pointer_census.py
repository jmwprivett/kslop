#!/usr/bin/env python3
"""Inventory live signed code pointers stored in writable kernel sections.

This exact-build, read-only probe complements ``cnd_live_block_census.py``.
Global Block literals are useful PAC-valid dispatch objects, but this tool
looks for the more valuable boundary: runtime code pointers in writable
``__DATA``/``__BOOTDATA``/``__KLDDATA`` storage.  A candidate is emitted only
when stripping its PAC-shaped upper bits lands on an aligned instruction in a
known executable section from the same extracted kernel collection.

The tool uses KDP only for bounded reads.  It does not write kernel memory and
does not invoke any kernel function.
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
ADDRESS_RE = re.compile(
    r"^Load Address:\s*(0x[0-9a-fA-F]{16})\s*$", re.MULTILINE)
UUID_RE = re.compile(
    r"^Kernel UUID:\s*([0-9A-Fa-f-]{36})\s*$", re.MULTILINE)
SECTION_RE = re.compile(
    r"Section\n"
    r"\s+sectname\s+(\S+)\n"
    r"\s+segname\s+(\S+)\n"
    r"\s+addr\s+(?:0x)?([0-9a-fA-F]+)\n"
    r"\s+size\s+0x([0-9a-fA-F]+)",
)
WRITABLE_SEGMENTS = {
    "__DATA", "__BOOTDATA", "__KLDDATA", "__PRELINK_DATA",
}
EXECUTABLE_SEGMENTS = {"__TEXT", "__TEXT_EXEC", "__PLK_TEXT_EXEC"}


@dataclass(frozen=True)
class Section:
    image: str
    segment: str
    section: str
    start: int
    size: int


class CensusError(RuntimeError):
    """The exact-build image or debugger census contract failed."""


def _hex(value: int) -> str:
    return f"0x{value:016x}"


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


def _run_objdump(image: Path) -> tuple[Path, str]:
    completed = subprocess.run(
        ["xcrun", "llvm-objdump", "--macho", "--all-headers",
         os.fspath(image)],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if completed.returncode != 0:
        raise CensusError(
            f"{image}: llvm-objdump failed ({completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    return image, completed.stdout


def _discover_sections(
    images: Iterable[Path], jobs: int,
) -> tuple[list[Section], list[Section]]:
    writable: list[Section] = []
    executable: list[Section] = []
    failures: list[str] = []
    image_list = sorted(set(images))
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
                item = Section(
                    image=image.name,
                    segment=segment,
                    section=section,
                    start=int(start_text, 16),
                    size=size,
                )
                if segment in WRITABLE_SEGMENTS:
                    writable.append(item)
                if segment in EXECUTABLE_SEGMENTS and section in {
                    "__text", "__stubs", "__auth_stubs",
                }:
                    executable.append(item)
    if failures:
        raise CensusError("section discovery failed:\n" + "\n".join(failures))
    key = lambda value: (value.start, value.size, value.image,
                         value.segment, value.section)
    return sorted(writable, key=key), sorted(executable, key=key)


def _identity(kernel: Path, port: int, timeout: int) -> tuple[int, str]:
    completed = subprocess.run(
        ["xcrun", "lldb", "--batch",
         "-o", f'target create "{kernel}"',
         "-o", "platform select remote-ios",
         "-o", f"gdb-remote 127.0.0.1:{port}",
         "-o", "process detach"],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=min(timeout, 60),
    )
    if completed.returncode != 0 or "Process 1 detached" not in completed.stdout:
        raise CensusError("KDP identity handshake failed or did not detach")
    loads = ADDRESS_RE.findall(completed.stdout)
    uuids = UUID_RE.findall(completed.stdout)
    if len(loads) != 1 or len(uuids) != 1:
        raise CensusError("KDP identity handshake was ambiguous")
    uuid = uuids[0].upper()
    if uuid != KERNEL_UUID:
        raise CensusError(f"live kernel UUID {uuid} does not match {KERNEL_UUID}")
    live_text = int(loads[0], 16)
    if live_text < STATIC_TEXT:
        raise CensusError("live kernel text precedes exact-build static text")
    return live_text - STATIC_TEXT, uuid


def _dump_sections(
    kernel: Path, port: int, sections: Sequence[Section], slide: int,
    timeout: int, directory: Path,
) -> tuple[dict[int, Path], list[int]]:
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
        start = section.start + slide
        end = start + section.size
        commands.append(
            f'memory read --force --binary --outfile "{output}" '
            f"{start:#x} {end:#x}"
        )
    commands.append("process detach")
    command_file = directory / "census.lldb"
    command_file.write_text("\n".join(commands) + "\n", encoding="utf-8")
    try:
        completed = subprocess.run(
            ["xcrun", "lldb", "--batch", "-s", os.fspath(command_file)],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise CensusError(f"KDP writable census timed out after {timeout}s") from error
    if completed.returncode != 0 or "Process 1 detached" not in completed.stdout:
        raise CensusError(
            f"KDP writable census failed ({completed.returncode}):\n"
            f"{completed.stdout[-4000:]}"
        )
    failed = [index for index, path in paths.items()
              if not path.is_file() or path.stat().st_size != sections[index].size]
    return paths, failed


def _canonical_pointer(raw: int) -> int:
    return (raw & 0x00007FFFFFFFFFFF) | 0xFFFF800000000000


def _target_section(
    target: int, executable: Sequence[Section],
) -> Section | None:
    # There are only a few hundred executable ranges in this collection; a
    # linear search keeps overlap handling explicit and deterministic.
    for section in executable:
        if section.start <= target < section.start + section.size:
            return section
    return None


def _scan_section(
    source: Section, data: bytes, slide: int,
    executable: Sequence[Section],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for offset in range(0, len(data) - 7, 8):
        raw = int.from_bytes(data[offset:offset + 8], "little")
        if raw == 0:
            continue
        live_target = _canonical_pointer(raw)
        if live_target & 3:
            continue
        static_target = live_target - slide
        target_section = _target_section(static_target, executable)
        if target_section is None:
            continue
        # An unsigned canonical pointer is still useful context, but this
        # census is specifically looking for already-signed replay material.
        # Keep the bit explicit so callers can demand signed-only records.
        signed = raw != live_target
        result.append({
            "kind": "writable-code-pointer",
            "sourceImage": source.image,
            "sourceSegment": source.segment,
            "sourceSection": source.section,
            "staticAddress": _hex(source.start + offset),
            "address": _hex(source.start + offset + slide),
            "rawValue": _hex(raw),
            "signed": signed,
            "target": _hex(live_target),
            "staticTarget": _hex(static_target),
            "targetImage": target_section.image,
            "targetSegment": target_section.segment,
            "targetSection": target_section.section,
        })
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", nargs="+", type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument(
        "--include-unsigned", action="store_true",
        help="also emit canonical, apparently unsigned text pointers",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        images = _images(args.images)
        writable, executable = _discover_sections(images, args.jobs)
        if not writable or not executable:
            raise CensusError("no writable or executable exact-build sections found")
        slide, uuid = _identity(args.kernel, args.port, args.timeout)
        candidates: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory(prefix="cnd-writable-pointers-") as tmp:
            paths, failed = _dump_sections(
                args.kernel, args.port, writable, slide, args.timeout,
                Path(tmp),
            )
            failed_set = set(failed)
            for index, section in enumerate(writable):
                if index in failed_set:
                    continue
                data = paths[index].read_bytes()
                candidates.extend(_scan_section(
                    section, data, slide, executable))
        emitted = [candidate for candidate in candidates
                   if candidate["signed"] or args.include_unsigned]
        emitted.sort(key=lambda row: (row["address"], row["rawValue"]))
        for candidate in emitted:
            print(json.dumps(candidate, separators=(",", ":")))
        print(json.dumps({
            "kind": "summary",
            "kernelUUID": uuid,
            "slide": _hex(slide),
            "images": len(images),
            "writableSections": len(writable),
            "writableBytes": sum(section.size for section in writable),
            "executableSections": len(executable),
            "sectionReadFailures": len(failed),
            "allCodePointers": len(candidates),
            "signedCodePointers": sum(bool(row["signed"])
                                      for row in candidates),
            "emitted": len(emitted),
            "usedKernelWrite": False,
            "usedKernelCall": False,
        }, separators=(",", ":")))
        return 0 if not failed else 2
    except (CensusError, OSError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
