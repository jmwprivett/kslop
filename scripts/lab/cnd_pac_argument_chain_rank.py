#!/usr/bin/env python3
"""Rank constant-domain PAC adapter chains by runtime controllability.

The fixup-domain closure proves only that a pointer with a compatible PAC
exists.  This tool adds the missing execution-oriented filter: it rewards
small adapters that load the next signed target from a controllable object,
preserve incoming arguments, and lead to another analyzed domain.  It never
claims runtime viability; the output is a bounded shortlist for exact Ghidra
review and a subsequent KRW-backed canary.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA = "cyanide.pac-argument-chain-rank.v1"
CLOSURE_SCHEMA = "cyanide.pac-fixup-domain-closure.v1"
IDENTITY_KEYS = (
    "build", "product", "kernelUUID", "collectionSHA256", "staticBase",
)


class RankError(RuntimeError):
    """The evidence inputs or ranking contract failed."""


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _int(value: Any, label: str) -> int:
    if not isinstance(value, str):
        raise RankError(f"{label} is not a hexadecimal string")
    try:
        return int(value, 0)
    except ValueError as error:
        raise RankError(f"{label} is not hexadecimal") from error


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RankError(f"cannot load closure {path}: {error}") from error
    if not isinstance(value, dict) or value.get("schema") != CLOSURE_SCHEMA:
        raise RankError(f"not a PAC fixup-domain closure: {path}")
    if value.get("transitive") is not False:
        raise RankError(f"closure must be direct-only: {path}")
    if value.get("readOnly") is not True or any(
        value.get(key) is not False
        for key in ("usedKernelRead", "usedKernelWrite", "usedKernelCall")
    ):
        raise RankError(f"closure is not static/read-only evidence: {path}")
    if not isinstance(value.get("targets"), list):
        raise RankError(f"closure has no target records: {path}")
    return value


def _same_identity(closures: Sequence[dict[str, Any]]) -> dict[str, str]:
    if not closures:
        raise RankError("at least one closure is required")
    identity = {key: closures[0].get(key) for key in IDENTITY_KEYS}
    if any(not isinstance(value, str) or not value for value in identity.values()):
        raise RankError("first closure has incomplete target identity")
    for closure in closures[1:]:
        observed = {key: closure.get(key) for key in IDENTITY_KEYS}
        if observed != identity:
            raise RankError("closure target identities do not match")
    return identity  # type: ignore[return-value]


def _preserved_arguments(branch: dict[str, Any]) -> list[str]:
    origins = branch.get("argumentOrigins")
    if not isinstance(origins, dict):
        return []
    result = []
    for index in range(8):
        register = f"x{index}"
        origin = origins.get(register)
        if isinstance(origin, dict) and origin.get("kind") == "argument" and \
                origin.get("baseRegister") == register:
            result.append(register)
    return result


def _target_class(origin: dict[str, Any]) -> str:
    kind = origin.get("kind")
    base = origin.get("baseRegister")
    chain = origin.get("chain")
    if kind == "load" and base == "x0":
        return "object-field-x0"
    if kind == "load" and base == "x1":
        return "object-field-x1"
    if isinstance(chain, list) and any(
        isinstance(item, str) and "adrp\t" in item for item in chain
    ):
        return "static-global"
    if kind == "load":
        return "register-relative-load"
    if kind in {"computed", "unresolved-prior-definition"}:
        return "computed-or-unresolved"
    return str(kind or "unknown")


def _edge_score(record: dict[str, Any], branch: dict[str, Any]) -> tuple[int, list[str]]:
    origin = branch.get("targetOrigin")
    if not isinstance(origin, dict):
        origin = {}
    target_class = _target_class(origin)
    preserved = _preserved_arguments(branch)
    reasons: list[str] = []
    score = 0

    class_scores = {
        "object-field-x0": 90,
        "object-field-x1": 65,
        "static-global": 30,
        "register-relative-load": 10,
        "computed-or-unresolved": -30,
    }
    class_score = class_scores.get(target_class, -10)
    score += class_score
    reasons.append(f"{target_class}:{class_score:+d}")

    for register, points in (("x0", 45), ("x1", 18), ("x2", 12)):
        if register in preserved:
            score += points
            reasons.append(f"preserves-{register}:+{points}")
    extra = len([item for item in preserved if item not in {"x0", "x1", "x2"}])
    if extra:
        score += extra * 2
        reasons.append(f"preserves-extra-{extra}:+{extra * 2}")

    instructions = record.get("instructions")
    if isinstance(instructions, int):
        if instructions <= 16:
            size_score = 24
        elif instructions <= 32:
            size_score = 14
        elif instructions <= 64:
            size_score = 5
        elif instructions <= 128:
            size_score = -5
        else:
            size_score = -20
        score += size_score
        reasons.append(f"instructions-{instructions}:{size_score:+d}")

    if branch.get("mnemonic") in {"braa", "brab"}:
        score += 8
        reasons.append("tail-branch:+8")
    offset = origin.get("offset")
    if isinstance(offset, int) and 0 <= offset <= 0x1000 and offset % 8 == 0:
        score += 8
        reasons.append("aligned-bounded-field:+8")
    return score, reasons


def _edges(closures: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for closure in closures:
        for record in closure["targets"]:
            if not isinstance(record, dict):
                continue
            entry_domains = record.get("entryDomains")
            branches = record.get("indirectBranches")
            if not isinstance(entry_domains, list) or not isinstance(branches, list):
                continue
            for branch in branches:
                if not isinstance(branch, dict):
                    continue
                destination = branch.get("destinationDomain")
                if not isinstance(destination, str):
                    continue
                for entry in entry_domains:
                    if not isinstance(entry, str):
                        continue
                    key = (
                        entry, str(record.get("target")),
                        str(branch.get("site")), destination,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    score, reasons = _edge_score(record, branch)
                    origin = branch.get("targetOrigin", {})
                    result.append({
                        "entryDomain": _hex(_int(entry, "entry domain")),
                        "target": record.get("target"),
                        "image": record.get("image"),
                        "functionStart": record.get("functionStart"),
                        "functionEnd": record.get("functionEnd"),
                        "instructions": record.get("instructions"),
                        "branchSite": branch.get("site"),
                        "mnemonic": branch.get("mnemonic"),
                        "destinationDomain": _hex(_int(
                            destination, "destination domain",
                        )),
                        "targetClass": _target_class(origin),
                        "targetOrigin": origin,
                        "preservedArguments": _preserved_arguments(branch),
                        "argumentOrigins": branch.get("argumentOrigins", {}),
                        "score": score,
                        "scoreReasons": reasons,
                    })
    return sorted(
        result,
        key=lambda item: (-item["score"], item["entryDomain"], item["target"]),
    )


def _rank_paths(
    edges: Sequence[dict[str, Any]], seeds: Sequence[int], max_depth: int,
    beam_width: int,
) -> list[dict[str, Any]]:
    by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    known_domains = set()
    for edge in edges:
        by_domain[edge["entryDomain"]].append(edge)
        known_domains.add(edge["entryDomain"])
    for values in by_domain.values():
        values.sort(key=lambda item: (-item["score"], item["target"]))

    active = [{
        "seedDomain": _hex(seed), "currentDomain": _hex(seed),
        "score": 0, "steps": [], "visitedDomains": [_hex(seed)],
    } for seed in seeds]
    completed: list[dict[str, Any]] = []
    for _ in range(max_depth):
        next_active: list[dict[str, Any]] = []
        for path in active:
            outgoing = by_domain.get(path["currentDomain"], [])
            if not outgoing:
                terminal = dict(path)
                terminal["terminal"] = "dead-end-in-analyzed-corpus"
                completed.append(terminal)
                continue
            for edge in outgoing:
                destination = edge["destinationDomain"]
                if destination in path["visitedDomains"]:
                    terminal = dict(path)
                    terminal["steps"] = [*path["steps"], edge]
                    terminal["score"] = path["score"] + edge["score"] - 40
                    terminal["currentDomain"] = destination
                    terminal["terminal"] = "domain-cycle"
                    completed.append(terminal)
                    continue
                next_active.append({
                    "seedDomain": path["seedDomain"],
                    "currentDomain": destination,
                    "score": path["score"] + edge["score"],
                    "steps": [*path["steps"], edge],
                    "visitedDomains": [*path["visitedDomains"], destination],
                })
        next_active.sort(
            key=lambda item: (-item["score"], len(item["steps"]),
                              item["currentDomain"]),
        )
        active = next_active[:beam_width]
        if not active:
            break
    for path in active:
        terminal = dict(path)
        terminal["terminal"] = (
            "depth-limit-known-domain"
            if path["currentDomain"] in known_domains
            else "unscanned-domain"
        )
        completed.append(terminal)

    for path in completed:
        if path["terminal"] == "dead-end-in-analyzed-corpus":
            path["score"] -= 80
        elif path["terminal"] == "unscanned-domain":
            path["score"] += 15
        path["depth"] = len(path["steps"])
        path.pop("visitedDomains", None)
    return sorted(
        completed,
        key=lambda item: (-item["score"], -item["depth"],
                          item["currentDomain"]),
    )


def build_report(
    closures: Sequence[dict[str, Any]], sources: Sequence[Path],
    seeds: Sequence[int], max_depth: int, beam_width: int, limit: int,
) -> dict[str, Any]:
    identity = _same_identity(closures)
    edges = _edges(closures)
    paths = _rank_paths(edges, seeds, max_depth, beam_width)
    domains_with_targets = sorted({
        domain for closure in closures for domain in closure.get("seeds", [])
        if isinstance(domain, str)
    })
    return {
        "schema": SCHEMA,
        **identity,
        "sources": [os.fspath(path.resolve()) for path in sources],
        "seedDomains": [_hex(value) for value in seeds],
        "limits": {
            "maxDepth": max_depth,
            "beamWidth": beam_width,
            "reportedPaths": limit,
        },
        "analyzedDomains": domains_with_targets,
        "constantDomainEdgeCount": len(edges),
        "rankedEdges": edges[:limit],
        "rankedPaths": paths[:limit],
        "interpretation": {
            "staticOnly": True,
            "runtimeViabilityProved": False,
            "nextStep": (
                "Exact Ghidra review of the highest-ranked non-dead-end path, "
                "then a reversible KRW-backed signed-pointer transplant canary."
            ),
        },
        "readOnly": True,
        "usedKernelRead": False,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    destination = path.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=destination.name + ".", dir=destination.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("closure", type=Path, nargs="+")
    parser.add_argument("--seed", action="append", default=["0x2abe"])
    parser.add_argument("--max-depth", type=int, default=4)
    parser.add_argument("--beam-width", type=int, default=512)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not 1 <= args.max_depth <= 8:
        raise RankError("max depth must be between one and eight")
    if not 1 <= args.beam_width <= 10000:
        raise RankError("beam width must be between one and 10000")
    if not 1 <= args.limit <= 1000:
        raise RankError("limit must be between one and 1000")
    seeds = [_int(value, "seed") for value in args.seed]
    closures = [_load(path.expanduser().resolve()) for path in args.closure]
    report = build_report(
        closures, args.closure, seeds, args.max_depth,
        args.beam_width, args.limit,
    )
    _write_json(args.output, report)
    print(json.dumps({
        "output": os.fspath(args.output.expanduser().resolve()),
        "edges": report["constantDomainEdgeCount"],
        "paths": len(report["rankedPaths"]),
        "topScore": report["rankedPaths"][0]["score"]
        if report["rankedPaths"] else None,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RankError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(2)
