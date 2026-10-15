#!/usr/bin/env python3
"""Rank stores through incoming arguments in PAC-signed target functions.

This is a static, read-only gadget-shape census.  It consumes a PAC domain
closure, decodes only fileset images containing targets for the selected
domain, and reports stores whose destination still derives from entry x0-x7.
Stores before any call are ranked highest because their provenance is least
ambiguous and they are most suitable for a reversible runtime canary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from bisect import bisect_left
from pathlib import Path
from typing import Any, Sequence


LAB_DIR = Path(__file__).resolve().parent
if os.fspath(LAB_DIR) not in sys.path:
    sys.path.insert(0, os.fspath(LAB_DIR))

import cnd_pac_dispatch_graph as graph


SCHEMA = "cyanide.pac-argument-store-rank.v1"
CLOSURE_SCHEMA = "cyanide.pac-fixup-domain-closure.v1"
MEMORY_RE = re.compile(
    r"\[\s*([xw](?:[12]?[0-9]|3[01])|sp)"
    r"(?:\s*,\s*#(-?(?:0x[0-9a-fA-F]+|[0-9]+)))?"
)
CALLS = frozenset({"bl", "blr", "blraa", "blrab", "blraaz", "blrabz"})
VECTOR_REGISTER_RE = re.compile(r"\b([qvds](?:[12]?[0-9]|3[01]))\b")


class StoreRankError(RuntimeError):
    """Input evidence or disassembly failed its contract."""


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_closure(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise StoreRankError(f"cannot load closure {path}: {error}") from error
    if not isinstance(value, dict) or value.get("schema") != CLOSURE_SCHEMA:
        raise StoreRankError("input is not a PAC fixup-domain closure")
    if value.get("readOnly") is not True or any(
        value.get(key) is not False
        for key in ("usedKernelRead", "usedKernelWrite", "usedKernelCall")
    ):
        raise StoreRankError("closure is not static/read-only evidence")
    if not isinstance(value.get("targets"), list):
        raise StoreRankError("closure has no target records")
    return value


def _image_map(root: Path) -> dict[str, Path]:
    if not root.is_dir():
        raise StoreRankError(f"fileset image directory does not exist: {root}")
    result: dict[str, Path] = {}
    for path in root.iterdir():
        if not path.is_file():
            continue
        if path.name in result:
            raise StoreRankError(f"duplicate fileset image name: {path.name}")
        result[path.name] = path
    return result


def _store_sources(instruction: graph.Instruction) -> tuple[list[str], str] | None:
    operands = graph._split_operands(instruction.operands)
    if instruction.mnemonic.startswith(("stp", "stnp")):
        if len(operands) < 3:
            return None
        return operands[:2], operands[2]
    if instruction.mnemonic.startswith(("str", "stur")):
        if len(operands) < 2:
            return None
        return operands[:1], operands[1]
    return None


def _width(mnemonic: str, source: str) -> int | None:
    name = mnemonic.lower()
    raw = source.strip().lower()
    if name.startswith(("strb", "sturb")):
        return 1
    if name.startswith(("strh", "sturh")):
        return 2
    if raw.startswith(("q", "v")):
        return 16
    if raw.startswith("d"):
        return 8
    if raw.startswith("s"):
        return 4
    registers = graph._registers(source)
    if not registers:
        return None
    if raw.startswith("w"):
        return 4
    if raw.startswith("x"):
        return 8
    return None


def _source_register(source: str) -> tuple[str, bool] | None:
    registers = graph._registers(source)
    if registers:
        return registers[0], False
    match = VECTOR_REGISTER_RE.search(source.lower())
    if match is not None:
        return match.group(1), True
    return None


def _store_score(candidate: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    destination = candidate["destinationArgument"]
    argument_points = {"x0": 45, "x1": 55, "x2": 30}.get(destination, 10)
    score += argument_points
    reasons.append(f"destination-{destination}:+{argument_points}")
    calls = candidate["callsBefore"]
    if calls == 0:
        score += 50
        reasons.append("before-any-call:+50")
    else:
        penalty = min(calls * 20, 60)
        score -= penalty
        reasons.append(f"calls-before-{calls}:-{penalty}")
    offset = candidate.get("offset")
    if isinstance(offset, int) and 0 <= offset <= 0x1000:
        score += 15
        reasons.append("bounded-offset:+15")
    if candidate.get("width") == 8:
        score += 10
        reasons.append("pointer-width:+10")
    value = candidate.get("valueOrigin", {})
    if value.get("kind") == "constant" and value.get("value") == _hex(0):
        score += 20
        reasons.append("constant-zero:+20")
    instructions = candidate.get("functionInstructions")
    if isinstance(instructions, int):
        size_points = 15 if instructions <= 16 else 8 if instructions <= 32 else 0
        score += size_points
        if size_points:
            reasons.append(f"small-function:+{size_points}")
    return score, reasons


def scan_body(
    record: dict[str, Any], instructions: Sequence[graph.Instruction],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    calls = 0
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic in CALLS:
            calls += 1
        parsed = _store_sources(instruction)
        if parsed is None:
            continue
        sources, memory = parsed
        match = MEMORY_RE.search(memory)
        if match is None:
            continue
        base = graph._register(match.group(1))
        base_origin = graph._origin(instructions, index, base)
        if base_origin.kind != "argument" or base_origin.base_register not in {
            f"x{number}" for number in range(8)
        }:
            continue
        offset = int(match.group(2), 0) if match.group(2) else 0
        for source_index, source in enumerate(sources):
            source_register = _source_register(source)
            if source_register is None:
                continue
            register, vector = source_register
            width = _width(instruction.mnemonic, source)
            effective_offset = offset + source_index * (width or 8)
            value_origin = (
                {"kind": "vector-untracked", "baseRegister": register}
                if vector else graph._origin_json(
                    graph._origin(instructions, index, register)
                )
            )
            candidate = {
                "target": record.get("target"),
                "image": record.get("image"),
                "entryDomains": record.get("entryDomains", []),
                "fixupsByDomain": record.get("fixupsByDomain", {}),
                "functionStart": record.get("functionStart"),
                "functionEnd": record.get("functionEnd"),
                "functionInstructions": record.get("instructions"),
                "site": _hex(instruction.address),
                "instruction": instruction.text,
                "destinationArgument": base_origin.base_register,
                "destinationOrigin": graph._origin_json(base_origin),
                "offset": effective_offset,
                "width": width,
                "sourceRegister": register,
                "valueOrigin": value_origin,
                "callsBefore": calls,
            }
            score, reasons = _store_score(candidate)
            candidate["score"] = score
            candidate["scoreReasons"] = reasons
            result.append(candidate)
    return result


def scan_returns(
    record: dict[str, Any], instructions: Sequence[graph.Instruction],
) -> list[dict[str, Any]]:
    """Report argument-register state at explicit returns in a signed target."""
    result: list[dict[str, Any]] = []
    calls = 0
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic in CALLS:
            calls += 1
        if instruction.mnemonic not in {"ret", "retab"}:
            continue
        origins = {
            f"x{number}": graph._origin_json(
                graph._origin(instructions, index, f"x{number}")
            ) for number in range(3)
        }
        x1 = origins["x1"]
        changed_x1 = not (
            x1.get("kind") == "argument" and
            x1.get("baseRegister") == "x1"
        )
        score = 0
        reasons: list[str] = []
        if changed_x1:
            score += 80
            reasons.append("changes-x1:+80")
        else:
            score -= 40
            reasons.append("preserves-x1:-40")
        if x1.get("kind") in {"static-address", "static-page", "load"}:
            score += 40
            reasons.append(f"x1-{x1['kind']}:+40")
        if calls == 0:
            score += 50
            reasons.append("before-any-call:+50")
        else:
            penalty = min(calls * 20, 60)
            score -= penalty
            reasons.append(f"calls-before-{calls}:-{penalty}")
        function_instructions = record.get("instructions")
        if isinstance(function_instructions, int) and function_instructions <= 16:
            score += 15
            reasons.append("small-function:+15")
        result.append({
            "target": record.get("target"),
            "image": record.get("image"),
            "entryDomains": record.get("entryDomains", []),
            "fixupsByDomain": record.get("fixupsByDomain", {}),
            "functionStart": record.get("functionStart"),
            "functionEnd": record.get("functionEnd"),
            "functionInstructions": function_instructions,
            "site": _hex(instruction.address),
            "mnemonic": instruction.mnemonic,
            "callsBefore": calls,
            "registerOrigins": origins,
            "changesX1": changed_x1,
            "score": score,
            "scoreReasons": reasons,
        })
    return result


def scan_direct_tail_calls(
    record: dict[str, Any], instructions: Sequence[graph.Instruction],
) -> list[dict[str, Any]]:
    """Report direct tail branches and the x0-x2 state they receive."""
    result: list[dict[str, Any]] = []
    try:
        function_start = int(record["functionStart"], 0)
        function_end = int(record["functionEnd"], 0)
    except (KeyError, TypeError, ValueError) as error:
        raise StoreRankError("target record has invalid function bounds") from error
    calls = 0
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic in CALLS:
            calls += 1
        if instruction.mnemonic != "b":
            continue
        operands = graph._split_operands(instruction.operands)
        destination = graph._immediate(operands[0]) if operands else None
        if destination is None:
            continue
        external_to_function = not function_start <= destination < function_end
        origins = {
            f"x{number}": graph._origin_json(
                graph._origin(instructions, index, f"x{number}")
            ) for number in range(3)
        }
        preserved = [
            register for register, origin in origins.items()
            if origin.get("kind") == "argument" and
            origin.get("baseRegister") == register
        ]
        score = len(preserved) * 20
        reasons = [f"preserved-{register}:+20" for register in preserved]
        if external_to_function:
            score += 100
            reasons.append("external-tail:+100")
        else:
            score -= 100
            reasons.append("internal-control-flow:-100")
        x2 = origins["x2"]
        if x2.get("kind") == "constant" and x2.get("value") in {
            _hex(0x20), _hex(0x40), _hex(0x48), _hex(0x80),
        }:
            score += 50
            reasons.append(f"bounded-copy-size-{x2['value']}:+50")
        if calls == 0:
            score += 30
            reasons.append("before-any-call:+30")
        result.append({
            "target": record.get("target"),
            "image": record.get("image"),
            "entryDomains": record.get("entryDomains", []),
            "fixupsByDomain": record.get("fixupsByDomain", {}),
            "functionStart": record.get("functionStart"),
            "functionEnd": record.get("functionEnd"),
            "functionInstructions": record.get("instructions"),
            "site": _hex(instruction.address),
            "destination": _hex(destination),
            "externalToFunction": external_to_function,
            "callsBefore": calls,
            "registerOrigins": origins,
            "preservedArguments": preserved,
            "score": score,
            "scoreReasons": reasons,
        })
    return result


def build_report(
    closure_path: Path, image_root: Path, domain: int, objdump: str,
) -> dict[str, Any]:
    closure = _load_closure(closure_path)
    domain_text = _hex(domain)
    records = [
        record for record in closure["targets"]
        if isinstance(record, dict) and
        isinstance(record.get("entryDomains"), list) and
        domain_text in record["entryDomains"]
    ]
    if not records:
        raise StoreRankError(f"closure has no targets for {domain_text}")
    images = _image_map(image_root)
    needed = sorted({record.get("image") for record in records})
    if any(not isinstance(name, str) or name not in images for name in needed):
        missing = [name for name in needed if name not in images]
        raise StoreRankError(f"missing fileset images: {missing}")
    decoded: dict[str, list[graph.Instruction]] = {}
    for name in needed:
        try:
            decoded[name], _ = graph._run_objdump(objdump, images[name])
        except graph.GraphError as error:
            raise StoreRankError(str(error)) from error

    candidates: list[dict[str, Any]] = []
    return_candidates: list[dict[str, Any]] = []
    direct_tail_candidates: list[dict[str, Any]] = []
    for record in records:
        name = record["image"]
        instructions = decoded[name]
        addresses = [instruction.address for instruction in instructions]
        target = int(record["target"], 0)
        end = int(record["functionEnd"], 0)
        start_index = bisect_left(addresses, target)
        end_index = bisect_left(addresses, end)
        if start_index >= len(addresses) or addresses[start_index] != target:
            raise StoreRankError(f"target is not decoded: {record['target']}")
        body = instructions[start_index:end_index]
        candidates.extend(scan_body(record, body))
        return_candidates.extend(scan_returns(record, body))
        direct_tail_candidates.extend(scan_direct_tail_calls(record, body))
    candidates.sort(
        key=lambda item: (-item["score"], item["target"], item["site"]),
    )
    return_candidates.sort(
        key=lambda item: (-item["score"], item["target"], item["site"]),
    )
    direct_tail_candidates.sort(
        key=lambda item: (-item["score"], item["target"], item["site"]),
    )
    return {
        "schema": SCHEMA,
        "build": closure.get("build"),
        "product": closure.get("product"),
        "kernelUUID": closure.get("kernelUUID"),
        "collectionSHA256": closure.get("collectionSHA256"),
        "closure": os.fspath(closure_path.resolve()),
        "closureSHA256": _sha256(closure_path),
        "imageRoot": os.fspath(image_root.resolve()),
        "domain": domain_text,
        "targetCount": len(records),
        "decodedImages": needed,
        "candidateCount": len(candidates),
        "candidates": candidates,
        "returnCandidateCount": len(return_candidates),
        "returnCandidates": return_candidates,
        "directTailCandidateCount": len(direct_tail_candidates),
        "externalDirectTailCandidateCount": sum(
            bool(candidate["externalToFunction"])
            for candidate in direct_tail_candidates
        ),
        "directTailCandidates": direct_tail_candidates,
        "interpretation": {
            "staticOnly": True,
            "runtimeViabilityProved": False,
            "callBoundaryCaveat": (
                "Argument provenance is intraprocedural. Stores after a call "
                "are retained but penalized and require exact Ghidra review."
            ),
        },
        "readOnly": True,
        "usedKernelRead": False,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("closure", type=Path)
    parser.add_argument("images", type=Path)
    parser.add_argument("--domain", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--objdump", default="/usr/bin/xcrun")
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not 0 <= args.domain <= 0xFFFF:
        raise StoreRankError("domain must fit in 16 bits")
    report = build_report(
        args.closure.resolve(), args.images.resolve(), args.domain, args.objdump,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    print(json.dumps({
        "output": os.fspath(args.output.resolve()),
        "targets": report["targetCount"],
        "candidates": report["candidateCount"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except StoreRankError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
