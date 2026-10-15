#!/usr/bin/env python3
"""Build an exact-function PAC-reuse dispatch graph for extracted arm64e images.

The scanner is intentionally static and read-only.  It finds functions whose
addresses are materialized and signed with one of the selected constant IA-key
discriminators, then limits every secondary-control-flow inspection to the
Mach-O ``LC_FUNCTION_STARTS`` boundary for that target.  This avoids the common
false positive where a fixed-size disassembly window attributes an indirect
branch in a neighboring function to the signed target being reviewed.

Register provenance is deliberately fail-closed.  The compact backward slice
may stop at a control-flow boundary or its instruction budget, but a register
is classified as an entry argument only when no earlier write exists anywhere
in the signed target's inspected body.  A farther or cross-control-flow write
is reported as unresolved instead of being promoted to attacker control.

The output is a candidate graph, not a kcall claim.  A constant-domain edge
means that a PAC-valid target function contains another authenticated branch;
it does not prove that the object, arguments, or destination pointer can be
controlled safely at runtime.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


KERNEL_SHA256 = "c32c7005fd8f702bf7f34730a512af5cb896a8c61b4a80b8400401f3897060ea"
KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"
BUILD = "23A341"
PRODUCT = "iPhone17,3"

# Constant IA discriminator domains used by the exact-build nstat provider
# callback table.  Their runtime entry shapes still need separate validation.
DEFAULT_DOMAINS = frozenset({
    0x2ABE, 0x307A, 0x392E, 0x50C7, 0x61DE,
    0x629A, 0x6827, 0xBCAD, 0xE28A, 0xE4FE,
})

INSTRUCTION_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{8}\s+)?"
    r"([.a-zA-Z0-9_]+)(?:\s+(.*?))?\s*$"
)
REGISTER_RE = re.compile(r"\b([wx](?:[12]?[0-9]|3[01])|sp|xzr|wzr)\b")
IMMEDIATE_RE = re.compile(
    r"^#?(-?(?:0x[0-9a-fA-F]+|[0-9]+))(?:\s+<[^>]+>)?$"
)
FUNCTION_START_RE = re.compile(r"^[0-9a-fA-F]{16}$")

AUTH_BRANCHES = frozenset({
    "braa", "brab", "braaz", "brabz",
    "blraa", "blrab", "blraaz", "blrabz",
})
RAW_BRANCHES = frozenset({"br", "blr"})
SIGN_INSTRUCTIONS = frozenset({"pacia", "pacib", "paciza", "pacizb"})
MAX_SLICE = 32


class GraphError(RuntimeError):
    """The exact-build identity or disassembly contract failed."""


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    operands: str

    @property
    def text(self) -> str:
        return f"{self.mnemonic}\t{self.operands}".rstrip()


@dataclass(frozen=True)
class Origin:
    kind: str
    value: int | None = None
    base_register: str | None = None
    offset: int | None = None
    chain: tuple[str, ...] = ()


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _register(value: str) -> str:
    value = value.strip().lower()
    if value == "wzr":
        return "xzr"
    if value.startswith("w") and value[1:].isdigit():
        return "x" + value[1:]
    return value


def _registers(value: str) -> list[str]:
    return [_register(match.group(1)) for match in REGISTER_RE.finditer(value)]


def _split_operands(value: str) -> list[str]:
    result: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(value):
        if character in "[{(":
            depth += 1
        elif character in "]})":
            depth = max(depth - 1, 0)
        elif character == "," and depth == 0:
            result.append(value[start:index].strip())
            start = index + 1
    result.append(value[start:].partition(";")[0].strip())
    return [item for item in result if item]


def _immediate(value: str) -> int | None:
    match = IMMEDIATE_RE.fullmatch(value.strip())
    if match is None:
        return None
    return int(match.group(1), 0)


def _parse_disassembly(text: str) -> list[Instruction]:
    result: list[Instruction] = []
    for line in text.splitlines():
        match = INSTRUCTION_RE.match(line)
        if match is None:
            continue
        result.append(Instruction(
            address=int(match.group(1), 16),
            mnemonic=match.group(2).lower(),
            operands=(match.group(3) or "").strip(),
        ))
    return result


def _parse_function_starts(text: str) -> list[int]:
    starts = sorted({
        int(line.strip(), 16)
        for line in text.splitlines()
        if FUNCTION_START_RE.fullmatch(line.strip())
    })
    if not starts:
        raise GraphError("Mach-O has no LC_FUNCTION_STARTS records")
    return starts


def _destination_registers(instruction: Instruction) -> tuple[str, ...]:
    operands = _split_operands(instruction.operands)
    if not operands:
        return ()
    mnemonic = instruction.mnemonic
    if mnemonic.startswith(("b", "cb", "tb", "ret", "str", "stp", "prfm")):
        return ()
    if mnemonic in {"cmp", "cmn", "tst", "ccmp", "ccmn", "msr"}:
        return ()
    first = _registers(operands[0])
    if not first:
        return ()
    result = [first[0]]
    if mnemonic in {"ldp", "ldpsw", "ldnp"} and len(operands) > 1:
        second = _registers(operands[1])
        if second:
            result.append(second[0])
    return tuple(result)


def _definition(
    instructions: Sequence[Instruction], before: int, register: str,
) -> tuple[int, Instruction] | None:
    lower = max(0, before - MAX_SLICE)
    for index in range(before - 1, lower - 1, -1):
        instruction = instructions[index]
        if register in _destination_registers(instruction):
            return index, instruction
        if instruction.mnemonic in {"ret", "retab", "br", "braa", "brab",
                                    "braaz", "brabz", "b"}:
            break
    return None


def _prior_definition(
    instructions: Sequence[Instruction], before: int, register: str,
) -> tuple[int, Instruction] | None:
    """Return the nearest earlier write, ignoring slice and CFG boundaries.

    This is not used to claim a concrete origin.  It is a conservative fence
    against calling a register an entry argument when the compact local slice
    lost a definition across an unconditional branch or a long function.
    """

    for index in range(before - 1, -1, -1):
        instruction = instructions[index]
        if register in _destination_registers(instruction):
            return index, instruction
    return None


def _origin(
    instructions: Sequence[Instruction], before: int, register: str,
    seen: frozenset[tuple[int, str]] = frozenset(),
) -> Origin:
    register = _register(register)
    key = (before, register)
    if key in seen:
        return Origin("cycle")
    if register in {"sp", "xzr"}:
        return Origin("constant", value=0 if register == "xzr" else None)
    definition = _definition(instructions, before, register)
    if definition is None:
        prior = _prior_definition(instructions, before, register)
        if prior is not None:
            _, instruction = prior
            return Origin(
                "unresolved-prior-definition",
                base_register=register,
                chain=(f"{_hex(instruction.address)}: {instruction.text}",),
            )
        kind = "argument" if register in {f"x{index}" for index in range(8)} else "unknown"
        return Origin(kind, base_register=register)

    index, instruction = definition
    operands = _split_operands(instruction.operands)
    registers = _registers(instruction.operands)
    witness = (f"{_hex(instruction.address)}: {instruction.text}",)
    mnemonic = instruction.mnemonic

    if mnemonic == "adr" and len(operands) >= 2:
        immediate = _immediate(operands[1])
        return Origin("static-address", immediate, chain=witness)
    if mnemonic == "adrp" and len(operands) >= 2:
        immediate = _immediate(operands[1])
        return Origin("static-page", immediate, chain=witness)
    if mnemonic in {"mov", "movz", "movn"} and len(operands) >= 2:
        immediate = _immediate(operands[1])
        if immediate is not None:
            return Origin("constant", immediate, chain=witness)
        if len(registers) >= 2:
            nested = _origin(instructions, index, registers[-1], seen | {key})
            return Origin(
                nested.kind, nested.value, nested.base_register, nested.offset,
                witness + nested.chain,
            )
    if mnemonic == "movk" and len(operands) >= 2:
        immediate = _immediate(operands[1])
        shift = 0
        if len(operands) >= 3:
            match = re.fullmatch(r"lsl\s+#(0x[0-9a-fA-F]+|[0-9]+)", operands[2])
            if match:
                shift = int(match.group(1), 0)
        prior = _origin(instructions, index, register, seen | {key})
        if immediate is not None and prior.kind == "constant" and prior.value is not None:
            mask = 0xFFFF << shift
            value = (prior.value & ~mask) | ((immediate & 0xFFFF) << shift)
            return Origin("constant", value, chain=witness + prior.chain)
        # arm64e emits address diversity as ``mov modifier, address`` followed
        # by a high-half ``movk`` discriminator blend.  Even if the compact
        # backward slice cannot recover the address's own definition, this is
        # materially different from a constant discriminator.
        kind = "address-blended" if shift else "computed"
        return Origin(kind, base_register=prior.base_register or register,
                      chain=witness + prior.chain)
    if mnemonic in {"add", "sub"} and len(operands) >= 3 and len(registers) >= 2:
        immediate = _immediate(operands[2])
        source = registers[1]
        nested = _origin(instructions, index, source, seen | {key})
        if immediate is not None and nested.value is not None and nested.kind in {
            "static-address", "static-page", "constant",
        }:
            value = nested.value + immediate if mnemonic == "add" else nested.value - immediate
            kind = "static-address" if nested.kind.startswith("static") else "constant"
            return Origin(kind, value, chain=witness + nested.chain)
        return Origin("computed", base_register=source, chain=witness + nested.chain)
    if mnemonic.startswith(("ldr", "ldur")):
        memory = re.search(
            r"\[\s*([xw](?:[12]?[0-9]|3[01])|sp)"
            r"(?:\s*,\s*#(-?(?:0x[0-9a-fA-F]+|[0-9]+)))?",
            instruction.operands,
        )
        if memory:
            base = _register(memory.group(1))
            offset = int(memory.group(2), 0) if memory.group(2) else 0
            base_origin = _origin(instructions, index, base, seen | {key})
            return Origin(
                "load", base_register=base_origin.base_register or base,
                offset=offset, chain=witness + base_origin.chain,
            )
        return Origin("load", chain=witness)
    if mnemonic.startswith(("auti", "autd")):
        return Origin("authenticated", base_register=register, chain=witness)
    if mnemonic.startswith(("paci", "pacd")):
        return Origin("signed", base_register=register, chain=witness)
    if mnemonic.startswith("xpac"):
        return Origin("stripped", base_register=register, chain=witness)
    return Origin("computed", base_register=register, chain=witness)


def _origin_json(origin: Origin) -> dict[str, Any]:
    result: dict[str, Any] = {"kind": origin.kind}
    if origin.value is not None:
        result["value"] = _hex(origin.value & 0xFFFFFFFFFFFFFFFF)
    if origin.base_register is not None:
        result["baseRegister"] = origin.base_register
    if origin.offset is not None:
        result["offset"] = origin.offset
    if origin.chain:
        result["chain"] = list(origin.chain)
    return result


def _constant_domain(
    instructions: Sequence[Instruction], index: int, register: str,
) -> int | None:
    origin = _origin(instructions, index, register)
    if origin.kind != "constant" or origin.value is None:
        return None
    return origin.value & 0xFFFFFFFFFFFFFFFF


def _fixed_identity_origin(
    instructions: Sequence[Instruction], before: int, register: str,
    seen: frozenset[tuple[int, str]] = frozenset(),
) -> Origin:
    """Resolve a fixed code identity through same-register PAC wrappers.

    Some C++ initializers deliberately sign a fixed function IA-zero,
    authenticate it again, and then re-sign it for a callback domain.  Those
    operations change the PAC contract but not the underlying code identity.
    General provenance must still call them authenticated/signed, so this
    narrower resolver is used only for the direct fixed-target census.
    """

    register = _register(register)
    key = (before, register)
    if key in seen:
        return Origin("cycle")
    definition = _definition(instructions, before, register)
    if definition is None:
        return _origin(instructions, before, register, seen)
    index, instruction = definition
    if instruction.mnemonic in SIGN_INSTRUCTIONS or instruction.mnemonic.startswith(
        ("auti", "autd", "xpac")
    ):
        return _fixed_identity_origin(
            instructions, index, register, seen | {key},
        )
    return _origin(instructions, before, register, seen)


def _direct_signers(
    image: Path, instructions: Sequence[Instruction], domains: frozenset[int],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    executable_addresses = {instruction.address for instruction in instructions}
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic == "paciza":
            domain = 0
        elif instruction.mnemonic == "pacia":
            registers = _registers(instruction.operands)
            if len(registers) < 2:
                continue
            domain = _constant_domain(instructions, index, registers[1])
        else:
            continue
        registers = _registers(instruction.operands)
        if not registers:
            continue
        if domain not in domains:
            continue
        target = _fixed_identity_origin(instructions, index, registers[0])
        if target.kind != "static-address" or target.value is None:
            continue
        # PACIZA is also used for non-code data.  A fixed-address provenance
        # alone is therefore insufficient: only seed the dispatch graph when
        # the recovered identity names a decoded executable instruction.
        if target.value not in executable_addresses:
            continue
        result.append({
            "image": image.name,
            "signer": instruction.address,
            "domain": domain,
            "target": target.value,
            "targetChain": list(target.chain),
        })
    return result


def _modifier_origin(
    instructions: Sequence[Instruction], index: int, instruction: Instruction,
) -> Origin:
    if instruction.mnemonic.endswith("z"):
        return Origin("constant", value=0)
    registers = _registers(instruction.operands)
    if len(registers) < 2:
        return Origin("unknown")
    return _origin(instructions, index, registers[1])


def _analyze_target(
    image: Path, target: int, domains: set[int], signers: list[int],
    instructions: Sequence[Instruction], function_starts: Sequence[int],
    addresses_override: Sequence[int] | None = None,
) -> dict[str, Any]:
    addresses = (addresses_override if addresses_override is not None
                 else [instruction.address for instruction in instructions])
    function_index = bisect_right(function_starts, target) - 1
    if function_index < 0:
        raise GraphError(f"{image}: no function contains {_hex(target)}")
    function_start = function_starts[function_index]
    function_end = (
        function_starts[function_index + 1]
        if function_index + 1 < len(function_starts)
        else (addresses[-1] + 4 if addresses else target)
    )
    # A callback can legally name a secondary entry inside a function.  Begin
    # at the signed address, while still using the next LC_FUNCTION_STARTS
    # record as the hard upper boundary.
    body_start = bisect_left(addresses, target)
    body_end = bisect_left(addresses, function_end)
    body = list(instructions[body_start:body_end])

    branches: list[dict[str, Any]] = []
    signs: list[dict[str, Any]] = []
    for index, instruction in enumerate(body):
        registers = _registers(instruction.operands)
        if instruction.mnemonic in AUTH_BRANCHES | RAW_BRANCHES and registers:
            branch: dict[str, Any] = {
                "site": _hex(instruction.address),
                "mnemonic": instruction.mnemonic,
                "targetRegister": registers[0],
                "targetOrigin": _origin_json(_origin(body, index, registers[0])),
                "authenticated": instruction.mnemonic in AUTH_BRANCHES,
                "argumentOrigins": {
                    f"x{argument}": _origin_json(
                        _origin(body, index, f"x{argument}")
                    )
                    for argument in range(8)
                },
            }
            if instruction.mnemonic in AUTH_BRANCHES:
                modifier = _modifier_origin(body, index, instruction)
                branch["modifierOrigin"] = _origin_json(modifier)
                if modifier.kind == "constant" and modifier.value is not None:
                    branch["destinationDomain"] = _hex(modifier.value)
            branches.append(branch)
        if instruction.mnemonic in SIGN_INSTRUCTIONS and registers:
            sign: dict[str, Any] = {
                "site": _hex(instruction.address),
                "mnemonic": instruction.mnemonic,
                "targetRegister": registers[0],
                "targetOrigin": _origin_json(_origin(body, index, registers[0])),
            }
            if instruction.mnemonic not in {"paciza", "pacizb"} and len(registers) >= 2:
                sign["modifierOrigin"] = _origin_json(
                    _origin(body, index, registers[1]))
            signs.append(sign)

    return {
        "kind": "dispatch-target",
        "image": image.name,
        "target": _hex(target),
        "domains": [_hex(value) for value in sorted(domains)],
        "signers": [_hex(value) for value in sorted(signers)],
        "functionStart": _hex(function_start),
        "functionEnd": _hex(function_end),
        "secondaryEntry": target != function_start,
        "instructions": len(body),
        "indirectBranches": branches,
        "pointerSigns": signs,
    }


def _objdump_argv(objdump: str, *arguments: str) -> list[str]:
    if Path(objdump).name == "xcrun":
        return [objdump, "llvm-objdump", *arguments]
    return [objdump, *arguments]


def _run_objdump(objdump: str, image: Path) -> tuple[list[Instruction], list[int]]:
    disassembly = subprocess.run(
        _objdump_argv(objdump, "-d", "--no-show-raw-insn", os.fspath(image)),
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if disassembly.returncode != 0:
        raise GraphError(
            f"{image}: disassembly failed ({disassembly.returncode}): "
            f"{disassembly.stderr.strip()}"
        )
    functions = subprocess.run(
        _objdump_argv(
            objdump, "--macho", "--function-starts=addrs", os.fspath(image),
        ),
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if functions.returncode != 0:
        raise GraphError(
            f"{image}: function-start scan failed ({functions.returncode}): "
            f"{functions.stderr.strip()}"
        )
    instructions = _parse_disassembly(disassembly.stdout)
    if not instructions:
        raise GraphError(f"{image}: no executable instructions")
    return instructions, _parse_function_starts(functions.stdout)


def _images(paths: Iterable[Path]) -> list[Path]:
    result: list[Path] = []
    for path in paths:
        if path.is_dir():
            result.extend(sorted(candidate for candidate in path.iterdir()
                                 if candidate.is_file()))
        elif path.is_file():
            result.append(path)
        else:
            raise GraphError(f"input does not exist: {path}")
    return sorted(set(result))


def scan(
    images: Sequence[Path], objdump: str, domains: frozenset[int], jobs: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    decoded: dict[Path, tuple[list[Instruction], list[int]]] = {}
    failures: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {
            executor.submit(_run_objdump, objdump, image): image for image in images
        }
        for future in concurrent.futures.as_completed(futures):
            image = futures[future]
            try:
                decoded[image] = future.result()
            except GraphError as error:
                failures.append(str(error))

    signers: list[dict[str, Any]] = []
    for image, (instructions, _) in decoded.items():
        signers.extend(_direct_signers(image, instructions, domains))

    grouped: dict[tuple[str, int], dict[str, Any]] = {}
    path_by_name = {path.name: path for path in images}
    for signer in signers:
        key = (signer["image"], signer["target"])
        group = grouped.setdefault(key, {"domains": set(), "signers": []})
        group["domains"].add(signer["domain"])
        group["signers"].append(signer["signer"])

    records: list[dict[str, Any]] = []
    for (image_name, target), group in sorted(grouped.items()):
        image = path_by_name[image_name]
        instructions, function_starts = decoded[image]
        records.append(_analyze_target(
            image, target, group["domains"], group["signers"],
            instructions, function_starts,
        ))

    constant_edges = 0
    raw_edges = 0
    dynamic_signs = 0
    for record in records:
        for branch in record["indirectBranches"]:
            raw_edges += not branch["authenticated"]
            constant_edges += "destinationDomain" in branch
        for sign in record["pointerSigns"]:
            if sign["targetOrigin"]["kind"] not in {
                "static-address", "static-page", "constant", "authenticated", "signed",
            }:
                dynamic_signs += 1

    summary = {
        "kind": "summary",
        "schema": "cyanide.pac-dispatch-graph.v1",
        "build": BUILD,
        "product": PRODUCT,
        "kernelUUID": KERNEL_UUID,
        "domains": [_hex(value) for value in sorted(domains)],
        "images": len(images),
        "decodedImages": len(decoded),
        "directSigners": len(signers),
        "signedTargets": len(records),
        "constantDomainEdges": constant_edges,
        "rawBranchEdges": raw_edges,
        "dynamicPointerSigns": dynamic_signs,
        "failures": sorted(failures),
        "readOnly": True,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }
    return records, summary


def _parse_domain(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid discriminator: {value}") from error
    if parsed < 0 or parsed > 0xFFFF:
        raise argparse.ArgumentTypeError("discriminator must fit in 16 bits")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", nargs="+", type=Path,
                        help="extracted Mach-O image or directory")
    parser.add_argument("--kernel", type=Path, required=True,
                        help="exact com.apple.kernel used to bind the build")
    parser.add_argument("--domain", action="append", type=_parse_domain,
                        help="constant IA discriminator (repeatable)")
    parser.add_argument("--objdump", default="/usr/bin/xcrun")
    parser.add_argument("--jobs", type=int, default=min(6, os.cpu_count() or 1))
    parser.add_argument(
        "--output", type=Path,
        help="write the JSON-lines graph to this file as well as stdout",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.kernel.is_file():
        raise GraphError(f"kernel does not exist: {args.kernel}")
    if _sha256(args.kernel) != KERNEL_SHA256:
        raise GraphError("kernel SHA-256 does not match exact build 23A341")
    if args.jobs < 1 or args.jobs > 64:
        raise GraphError("--jobs must be from 1 to 64")
    images = _images(args.images)
    if not images:
        raise GraphError("no input images")
    domains = frozenset(args.domain or DEFAULT_DOMAINS)
    records, summary = scan(images, args.objdump, domains, args.jobs)
    lines = [json.dumps(record, separators=(",", ":")) for record in records]
    lines.append(json.dumps(summary, separators=(",", ":")))
    encoded = "\n".join(lines) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 1 if summary["failures"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GraphError, OSError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
