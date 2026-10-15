#!/usr/bin/env python3
"""Build a transitive constant-domain PAC graph for a pinned 23A341 VM image.

The kernel collection contains authenticated chained fixups in many IA
diversity domains.  A useful callback can cross from one constant PAC domain
to another, so examining a single diversity misses multi-stage adapters.  This
tool walks the collection once, decodes every extracted fileset image once,
and follows constant-domain indirect branches from caller-selected seeds.

It is a static, read-only closure.  Reachability here means that compatible
signed pointers exist; it does not claim that argument or object preconditions
are satisfiable at runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from collections import deque
from pathlib import Path
from typing import Any, Iterable, Sequence


LAB_DIR = Path(__file__).resolve().parent
if os.fspath(LAB_DIR) not in sys.path:
    sys.path.insert(0, os.fspath(LAB_DIR))

import cnd_pac_fixup_census as census
import cnd_pac_fixup_dispatch_graph as fixup_graph


SCHEMA = "cyanide.pac-fixup-domain-closure.v1"
RAW_SUMMARY_SCHEMA = "cyanide.pac-fixup-raw-branch-summary.v1"
BUILD = fixup_graph.BUILD
PRODUCT = fixup_graph.PRODUCT
KERNEL_UUID = fixup_graph.KERNEL_UUID
COLLECTION_SHA256 = fixup_graph.COLLECTION_SHA256
STATIC_BASE = fixup_graph.STATIC_BASE


class ClosureError(RuntimeError):
    """The exact collection or closure contract failed."""


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _group_fixups(
    records: Iterable[dict[str, Any]],
) -> dict[int, dict[int, list[dict[str, Any]]]]:
    grouped: dict[int, dict[int, list[dict[str, Any]]]] = {}
    locations: set[str] = set()
    for record in records:
        if record.get("key") != "IA" or \
                record.get("addressDiversity") is not False:
            continue
        target_text = record.get("target")
        diversity_text = record.get("diversity")
        location = record.get("location")
        if not isinstance(target_text, str) or \
                not isinstance(diversity_text, str) or \
                not isinstance(location, str):
            continue
        if location in locations:
            raise ClosureError(f"duplicate fixup location {location}")
        locations.add(location)
        try:
            target = int(target_text, 0)
            diversity = int(diversity_text, 0)
        except ValueError as error:
            raise ClosureError("invalid fixup address or diversity") from error
        grouped.setdefault(diversity, {}).setdefault(target, []).append(record)
    return grouped


def _next_domains(records: Iterable[dict[str, Any]]) -> set[int]:
    result: set[int] = set()
    for record in records:
        for branch in record.get("indirectBranches", []):
            value = branch.get("destinationDomain")
            if isinstance(value, str):
                result.add(int(value, 0))
    return result


def _raw_branch_candidates(
    records: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for record in records:
        for branch in record.get("indirectBranches", []):
            if branch.get("authenticated") is not False:
                continue
            candidates.append({
                "target": record.get("target"),
                "image": record.get("image"),
                "functionStart": record.get("functionStart"),
                "functionEnd": record.get("functionEnd"),
                "entryDomains": record.get("entryDomains", []),
                "fixupsByDomain": record.get("fixupsByDomain", {}),
                "branch": branch,
            })
    return sorted(
        candidates,
        key=lambda item: (
            item["target"] or "",
            item["branch"].get("site", ""),
        ),
    )


def build_closure(
    images: Sequence[Path],
    grouped: dict[int, dict[int, list[dict[str, Any]]]],
    seeds: Sequence[int],
    objdump: str,
    jobs: int,
    max_domains: int,
    collection_sha256: str = COLLECTION_SHA256,
    kernel_uuid: str | None = KERNEL_UUID,
    follow_destinations: bool = True,
    product: str = PRODUCT,
    static_base: int = STATIC_BASE,
) -> dict[str, Any]:
    decoded, failures = fixup_graph._decode_images(images, objdump, jobs)
    if failures:
        raise ClosureError(
            f"failed to decode {len(failures)} extracted image(s)"
        )

    queue = deque(seeds)
    queued = set(seeds)
    analyzed: set[int] = set()
    missing: set[int] = set()
    domains: list[dict[str, Any]] = []
    target_cache: dict[int, dict[str, Any]] = {}
    target_domains: dict[int, set[int]] = {}
    target_fixups: dict[int, dict[int, list[dict[str, Any]]]] = {}
    unresolved: set[int] = set()
    while queue:
        domain = queue.popleft()
        if domain in analyzed:
            continue
        if len(analyzed) >= max_domains:
            raise ClosureError(
                f"constant-domain closure exceeded {max_domains} domains"
            )
        analyzed.add(domain)
        fixups = grouped.get(domain)
        if not fixups:
            missing.add(domain)
            domains.append({
                "domain": _hex(domain),
                "fixupMatches": 0,
                "uniqueFixupTargets": 0,
                "nextDomains": [],
                "missingFixupCorpus": True,
            })
            continue
        uncached = {
            target: matches for target, matches in fixups.items()
            if target not in target_cache and target not in unresolved
        }
        if uncached:
            new_records, new_summary = fixup_graph.scan_decoded(
                decoded, [], len(images), uncached, domain,
            )
            for record in new_records:
                target = int(record["target"], 0)
                for key in (
                    "domains", "fixupCount", "fixupLocations",
                    "fixupRawValues", "imageCandidates",
                ):
                    record.pop(key, None)
                target_cache[target] = record
            unresolved.update(
                int(value, 0) for value in new_summary["unresolvedTargets"]
            )
        records = [
            target_cache[target] for target in fixups
            if target in target_cache
        ]
        for target, matches in fixups.items():
            target_domains.setdefault(target, set()).add(domain)
            target_fixups.setdefault(target, {})[domain] = matches
        next_domains = _next_domains(records)
        constant_edges = sum(
            "destinationDomain" in branch
            for record in records for branch in record["indirectBranches"]
        )
        raw_edges = sum(
            not branch["authenticated"]
            for record in records for branch in record["indirectBranches"]
        )
        dynamic_signs = sum(
            sign["targetOrigin"]["kind"] not in {
                "static-address", "static-page", "constant",
                "authenticated", "signed",
            }
            for record in records for sign in record["pointerSigns"]
        )
        domains.append({
            "domain": _hex(domain),
            "fixupMatches": sum(len(value) for value in fixups.values()),
            "uniqueFixupTargets": len(fixups),
            "analyzedTargets": len(records),
            "unresolvedTargets": [
                _hex(value) for value in sorted(set(fixups) & unresolved)
            ],
            "constantDomainEdges": constant_edges,
            "rawBranchEdges": raw_edges,
            "dynamicPointerSigns": dynamic_signs,
            "nextDomains": [_hex(value) for value in sorted(next_domains)],
            "missingFixupCorpus": False,
        })
        if follow_destinations:
            for destination in sorted(next_domains):
                if destination not in queued:
                    queued.add(destination)
                    queue.append(destination)

    target_records: list[dict[str, Any]] = []
    for target, record in target_cache.items():
        record["entryDomains"] = [
            _hex(value) for value in sorted(target_domains[target])
        ]
        record["fixupsByDomain"] = {
            _hex(domain): {
                "count": len(matches),
                "locations": sorted(match["location"] for match in matches),
                "rawValues": sorted({match["raw"] for match in matches}),
            }
            for domain, matches in sorted(target_fixups[target].items())
        }
        target_records.append(record)
    unique_constant_edges = sum(
        "destinationDomain" in branch
        for record in target_records for branch in record["indirectBranches"]
    )
    unique_raw_edges = sum(
        not branch["authenticated"]
        for record in target_records for branch in record["indirectBranches"]
    )
    unique_dynamic_signs = sum(
        sign["targetOrigin"]["kind"] not in {
            "static-address", "static-page", "constant",
            "authenticated", "signed",
        }
        for record in target_records for sign in record["pointerSigns"]
    )
    return {
        "schema": SCHEMA,
        "build": BUILD,
        "product": product,
        "kernelUUID": kernel_uuid,
        "collectionSHA256": collection_sha256,
        "staticBase": _hex(static_base),
        "transitive": follow_destinations,
        "seeds": [_hex(value) for value in seeds],
        "reachableDomains": [_hex(value) for value in sorted(analyzed)],
        "missingDomains": [_hex(value) for value in sorted(missing)],
        "domainCount": len(analyzed),
        "domainsWithFixups": len(analyzed - missing),
        "targetRecords": len(target_records),
        "unresolvedTargets": [_hex(value) for value in sorted(unresolved)],
        "constantDomainEdges": unique_constant_edges,
        "rawBranchEdges": unique_raw_edges,
        "dynamicPointerSigns": unique_dynamic_signs,
        "domains": sorted(domains, key=lambda item: item["domain"]),
        "targets": sorted(target_records, key=lambda item: item["target"]),
        "readOnly": True,
        "usedKernelRead": False,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }


def _parse_domain(value: str) -> int:
    parsed = int(value, 0)
    if not 0 <= parsed <= 0xFFFF:
        raise argparse.ArgumentTypeError("PAC diversity must fit in 16 bits")
    return parsed


def _parse_sha256(value: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise argparse.ArgumentTypeError("SHA-256 must be exactly 64 hex digits")
    return normalized


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("collection", type=Path)
    parser.add_argument("images", nargs="+", type=Path)
    parser.add_argument(
        "--seed", action="append", type=_parse_domain, default=[],
        help="constant IA diversity seed (repeatable; default: 0x2abe)",
    )
    parser.add_argument("--base", type=lambda value: int(value, 0),
                        default=STATIC_BASE)
    parser.add_argument("--product", default=PRODUCT)
    parser.add_argument(
        "--expected-collection-sha256", type=_parse_sha256,
        default=COLLECTION_SHA256,
        help=(
            "fail closed unless the collection has this SHA-256; defaults to "
            "the research-vphone600 image"
        ),
    )
    parser.add_argument("--objdump", default="/usr/bin/xcrun")
    parser.add_argument("--jobs", type=int, default=min(6, os.cpu_count() or 1))
    parser.add_argument("--max-domains", type=int, default=4096)
    parser.add_argument(
        "--direct-only", action="store_true",
        help="analyze only the seed domain(s), without following domain edges",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--raw-summary-output", type=Path,
        help="also write a compact report containing only raw branch edges",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.collection.is_file():
        raise ClosureError("collection is not a file")
    collection_sha256 = _sha256(args.collection)
    if collection_sha256 != args.expected_collection_sha256:
        raise ClosureError(
            "collection SHA-256 does not match the caller-pinned artifact"
        )
    if args.expected_collection_sha256 == COLLECTION_SHA256 and \
            args.base != STATIC_BASE:
        raise ClosureError("default research collection requires its exact base")
    if not 1 <= args.jobs <= 64:
        raise ClosureError("--jobs must be from 1 to 64")
    if not 1 <= args.max_domains <= 0x10000:
        raise ClosureError("--max-domains must be from 1 to 65536")
    images = fixup_graph._images(args.images)
    if not images:
        raise ClosureError("no extracted images")
    macho = census.parse_macho(args.collection)
    records = census.walk_fixups(macho, args.base)
    grouped = _group_fixups(records)
    document = build_closure(
        images, grouped, args.seed or [fixup_graph.DOMAIN],
        args.objdump, args.jobs, args.max_domains,
        collection_sha256=collection_sha256,
        kernel_uuid=macho.uuid,
        follow_destinations=not args.direct_only,
        product=args.product,
        static_base=args.base,
    )
    encoded = json.dumps(document, separators=(",", ":")) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(encoded, encoding="utf-8")
    if args.raw_summary_output is not None:
        raw_candidates = _raw_branch_candidates(document["targets"])
        raw_summary = {
            "schema": RAW_SUMMARY_SCHEMA,
            "build": document["build"],
            "product": document["product"],
            "kernelUUID": document["kernelUUID"],
            "collectionSHA256": document["collectionSHA256"],
            "staticBase": document["staticBase"],
            "transitive": document["transitive"],
            "seeds": document["seeds"],
            "candidateCount": len(raw_candidates),
            "candidates": raw_candidates,
            "readOnly": True,
            "usedKernelRead": False,
            "usedKernelWrite": False,
            "usedKernelCall": False,
        }
        args.raw_summary_output.parent.mkdir(parents=True, exist_ok=True)
        args.raw_summary_output.write_text(
            json.dumps(raw_summary, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    summary = {key: document[key] for key in (
        "schema", "build", "product", "kernelUUID", "collectionSHA256",
        "staticBase",
        "transitive",
        "seeds", "reachableDomains",
        "missingDomains", "domainCount", "domainsWithFixups",
        "targetRecords", "unresolvedTargets", "constantDomainEdges", "rawBranchEdges",
        "dynamicPointerSigns", "readOnly", "usedKernelRead",
        "usedKernelWrite", "usedKernelCall",
    )}
    sys.stdout.write(json.dumps(summary, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        ClosureError, census.CensusError, fixup_graph.GraphError,
        OSError, subprocess.SubprocessError, ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
