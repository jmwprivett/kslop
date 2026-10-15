#!/usr/bin/env python3
"""Find exact-build PAC signer sites whose target has dynamic provenance.

This is a static, read-only triage tool for extracted arm64e Mach-O images.  It
asks llvm-objdump for executable-section disassembly, finds code-pointer PAC
instructions, and walks backward through a small register-definition slice.
The useful output is deliberately narrow: signer sites where the pointer being
signed appears to originate in a load, an argument register, or a computed
value without an intervening authentication instruction.

The analysis is a candidate generator, not a PAC proof.  Every emitted site
still needs REA/decompiler review before it is used in a live experiment.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


INSTRUCTION_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{8}\s+)?"
    r"([.a-zA-Z0-9_]+)(?:\s+(.*?))?\s*$"
)
REGISTER_RE = re.compile(r"\b([wx](?:[12]?[0-9]|3[01])|sp|xzr|wzr)\b")
IMMEDIATE_RE = re.compile(r"^#?(-?(?:0x[0-9a-fA-F]+|[0-9]+))$")
SECTION_RE = re.compile(
    r"Section\n"
    r"\s+sectname\s+(\S+)\n"
    r"\s+segname\s+(\S+)\n"
    r"\s+addr\s+(?:0x)?([0-9a-fA-F]+)\n"
    r"\s+size\s+0x([0-9a-fA-F]+)",
)
SIGN_MNEMONICS = frozenset(("pacia", "pacib", "paciza", "pacizb"))
AUTH_PREFIXES = ("auti", "autd")
MAX_BACKWARD_INSTRUCTIONS = 48
WRITABLE_SEGMENTS = frozenset({
    "__DATA", "__BOOTDATA", "__KLDDATA", "__PRELINK_DATA",
})


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    operands: str
    text: str


@dataclass(frozen=True)
class Origin:
    kind: str
    address: int | None
    text: str | None
    chain: tuple[str, ...]
    value: int | None = None


@dataclass(frozen=True)
class Section:
    segment: str
    section: str
    start: int
    size: int

    @property
    def writable(self) -> bool:
        return self.segment in WRITABLE_SEGMENTS


class CensusError(RuntimeError):
    """Disassembly or input discovery failed."""


def _register(value: str) -> str:
    value = value.strip().lower()
    if value == "wzr":
        return "xzr"
    if value.startswith("w") and value[1:].isdigit():
        return "x" + value[1:]
    return value


def _operand_registers(operands: str) -> list[str]:
    return [_register(match.group(1)) for match in REGISTER_RE.finditer(operands)]


def _split_operands(operands: str) -> list[str]:
    result: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(operands):
        if char in "[{(":
            depth += 1
        elif char in "]})":
            depth = max(depth - 1, 0)
        elif char == "," and depth == 0:
            result.append(operands[start:index].strip())
            start = index + 1
    result.append(operands[start:].partition(";")[0].strip())
    return [value for value in result if value]


def _immediate(value: str) -> int | None:
    match = IMMEDIATE_RE.fullmatch(value.strip())
    return int(match.group(1), 0) if match else None


def _memory_operand(operands: Sequence[str]) -> tuple[str, int] | None:
    for operand in operands:
        if "[" not in operand:
            continue
        registers = _operand_registers(operand)
        if not registers:
            return None
        match = re.search(r"#(-?(?:0x[0-9a-fA-F]+|[0-9]+))", operand)
        return registers[0], int(match.group(1), 0) if match else 0
    return None


def _destination_registers(instruction: Instruction) -> tuple[str, ...]:
    operands = _split_operands(instruction.operands)
    if not operands:
        return ()
    mnemonic = instruction.mnemonic
    if mnemonic.startswith(("b", "cb", "tb", "ret", "str", "stp", "prfm")):
        return ()
    if mnemonic in {"cmp", "cmn", "tst", "ccmp", "ccmn", "msr"}:
        return ()
    first = _operand_registers(operands[0])
    if not first:
        return ()
    destinations = [first[0]]
    if mnemonic in {"ldp", "ldpsw", "ldnp"} and len(operands) > 1:
        second = _operand_registers(operands[1])
        if second:
            destinations.append(second[0])
    return tuple(destinations)


def _parse_disassembly(text: str) -> list[Instruction]:
    instructions: list[Instruction] = []
    for line in text.splitlines():
        match = INSTRUCTION_RE.match(line)
        if not match:
            continue
        mnemonic = match.group(2).lower()
        operands = (match.group(3) or "").strip()
        instructions.append(
            Instruction(int(match.group(1), 16), mnemonic, operands,
                        f"{mnemonic}\t{operands}".rstrip())
        )
    return instructions


def _parse_sections(text: str) -> list[Section]:
    result: list[Section] = []
    for match in SECTION_RE.finditer(text):
        section, segment, start_text, size_text = match.groups()
        size = int(size_text, 16)
        if size:
            result.append(Section(
                segment=segment,
                section=section,
                start=int(start_text, 16),
                size=size,
            ))
    return result


def _is_control_flow(instruction: Instruction) -> bool:
    mnemonic = instruction.mnemonic
    return (
        mnemonic in {"ret", "eret", "br", "braa", "brab", "braaz", "brabz"}
        or mnemonic == "b"
    )


def _find_definition(
    instructions: Sequence[Instruction], before: int, register: str
) -> tuple[int, Instruction] | None:
    lower = max(0, before - MAX_BACKWARD_INSTRUCTIONS)
    for index in range(before - 1, lower - 1, -1):
        instruction = instructions[index]
        if register in _destination_registers(instruction):
            return index, instruction
        if _is_control_flow(instruction):
            break
    return None


def _origin(
    instructions: Sequence[Instruction], before: int, register: str,
    seen: frozenset[tuple[int, str]] = frozenset(),
) -> Origin:
    register = _register(register)
    key = (before, register)
    if key in seen:
        return Origin("cycle", None, None, ())
    if register in {"xzr", "sp"}:
        return Origin("constant", None, register, ())
    definition = _find_definition(instructions, before, register)
    if definition is None:
        kind = "argument" if register in {f"x{i}" for i in range(8)} else "unknown"
        return Origin(kind, None, register, ())

    index, instruction = definition
    chain = (f"{instruction.address:#x}: {instruction.text}",)
    mnemonic = instruction.mnemonic
    operands = _split_operands(instruction.operands)
    registers = _operand_registers(instruction.operands)

    if mnemonic.startswith(AUTH_PREFIXES):
        return Origin("authenticated", instruction.address, instruction.text, chain)
    if mnemonic in {"adr", "adrp"} and len(operands) >= 2:
        value = _immediate(operands[1])
        return Origin(
            "static-page" if mnemonic == "adrp" else "static-address",
            instruction.address, instruction.text, chain, value,
        )
    if mnemonic.startswith(("ldr", "ldur", "ldp", "ldnp")):
        memory = _memory_operand(operands)
        if memory is None:
            return Origin("load", instruction.address, instruction.text, chain)
        base, offset = memory
        nested = _origin(instructions, index, base, seen | {key})
        value = nested.value + offset if nested.value is not None and \
            nested.kind in {"static-address", "static-page"} else None
        return Origin(
            "load", instruction.address, instruction.text,
            chain + nested.chain, value,
        )
    if mnemonic in {"mov", "movz", "movn", "movk"}:
        if "#" in instruction.operands:
            return Origin("constant", instruction.address, instruction.text, chain)
        if len(registers) >= 2:
            nested = _origin(instructions, index, registers[-1], seen | {key})
            return Origin(nested.kind, instruction.address, instruction.text,
                          chain + nested.chain, nested.value)
    if mnemonic in {"add", "sub"} and len(registers) >= 2:
        source = registers[1]
        nested = _origin(instructions, index, source, seen | {key})
        immediate = _immediate(operands[2]) if len(operands) >= 3 else None
        value = nested.value
        if value is not None and immediate is not None:
            value = value + immediate if mnemonic == "add" else value - immediate
        else:
            value = None
        kind = "static-address" if nested.kind in {
            "static-address", "static-page",
        } else "computed"
        return Origin(
            kind, instruction.address, instruction.text,
            chain + nested.chain, value,
        )
    if mnemonic in {"orr", "and", "eor"} and len(registers) >= 2:
        sources = [value for value in registers[1:] if value != "xzr"]
        if len(sources) == 1:
            nested = _origin(instructions, index, sources[0], seen | {key})
            return Origin(nested.kind, instruction.address, instruction.text,
                          chain + nested.chain, nested.value)
    if mnemonic.startswith("pac"):
        return Origin("signed", instruction.address, instruction.text, chain)
    if mnemonic.startswith("xpac"):
        return Origin("stripped", instruction.address, instruction.text, chain)
    if operands:
        return Origin("computed", instruction.address, instruction.text, chain)
    return Origin("unknown", instruction.address, instruction.text, chain)


def _source_section(
    address: int, sections: Sequence[Section],
) -> Section | None:
    matches = [section for section in sections
               if section.start <= address < section.start + section.size]
    if len(matches) > 1:
        raise CensusError(f"overlapping sections contain {address:#x}")
    return matches[0] if matches else None


def _candidate_records(
    image: Path, instructions: Sequence[Instruction],
    sections: Sequence[Section] = (),
) -> list[dict]:
    result: list[dict] = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic not in SIGN_MNEMONICS:
            continue
        registers = _operand_registers(instruction.operands)
        if not registers:
            continue
        target = _origin(instructions, index, registers[0])
        if target.kind in {"static-address", "authenticated", "signed", "constant"}:
            continue
        record = {
            "image": image.name,
            "address": f"{instruction.address:#x}",
            "instruction": instruction.text,
            "targetRegister": registers[0],
            "targetOrigin": target.kind,
            "targetChain": list(target.chain),
        }
        if target.value is not None:
            record["sourceAddress"] = f"{target.value:#x}"
            section = _source_section(target.value, sections)
            if section is not None:
                record.update({
                    "sourceSegment": section.segment,
                    "sourceSection": section.section,
                    "sourceWritable": section.writable,
                    "sourceMutationClass": (
                        "runtime-writable" if section.writable
                        else "protected-const"
                    ),
                })
            else:
                record["sourceMutationClass"] = "unmapped"
        if instruction.mnemonic in {"pacia", "pacib"} and len(registers) >= 2:
            modifier = _origin(instructions, index, registers[1])
            record.update({
                "modifierRegister": registers[1],
                "modifierOrigin": modifier.kind,
                "modifierChain": list(modifier.chain),
            })
        result.append(record)
    return result


def _objdump_command(objdump: str, arguments: Sequence[str]) -> list[str]:
    return ([objdump, "llvm-objdump", *arguments]
            if Path(objdump).name == "xcrun"
            else [objdump, *arguments])


def _run_objdump(image: Path, objdump: str, arguments: Sequence[str]) -> str:
    completed = subprocess.run(
        _objdump_command(objdump, [*arguments, os.fspath(image)]),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise CensusError(
            f"{image}: llvm-objdump failed ({completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    return completed.stdout


def _scan_image(image: Path, objdump: str) -> tuple[Path, list[dict], int]:
    disassembly = _run_objdump(image, objdump, [
        "-d", "--no-show-raw-insn",
    ])
    headers = _run_objdump(image, objdump, ["--macho", "--all-headers"])
    instructions = _parse_disassembly(disassembly)
    sections = _parse_sections(headers)
    return image, _candidate_records(image, instructions, sections), len(instructions)


def _images(paths: Iterable[Path]) -> list[Path]:
    result: list[Path] = []
    for path in paths:
        if path.is_dir():
            result.extend(sorted(value for value in path.iterdir() if value.is_file()))
        elif path.is_file():
            result.append(path)
        else:
            raise CensusError(f"input does not exist: {path}")
    return sorted(set(result))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path,
                        help="Mach-O image or directory of images")
    parser.add_argument("--objdump", default="/usr/bin/xcrun",
                        help="llvm-objdump path, or /usr/bin/xcrun (default)")
    parser.add_argument("--jobs", type=int, default=min(6, os.cpu_count() or 1))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    images = _images(args.paths)
    if not images:
        raise CensusError("no input images")
    if args.jobs < 1:
        raise CensusError("--jobs must be positive")

    total_instructions = 0
    candidates: list[dict] = []
    failures: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {
            executor.submit(_scan_image, image, args.objdump): image
            for image in images
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                _, records, instruction_count = future.result()
                candidates.extend(records)
                total_instructions += instruction_count
            except CensusError as error:
                failures.append(str(error))

    candidates.sort(key=lambda item: (item["image"], int(item["address"], 16)))
    for record in candidates:
        print(json.dumps({"kind": "candidate", **record}, separators=(",", ":")))
    print(json.dumps({
        "kind": "summary",
        "images": len(images),
        "instructions": total_instructions,
        "candidates": len(candidates),
        "failures": failures,
    }, separators=(",", ":")))
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CensusError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
