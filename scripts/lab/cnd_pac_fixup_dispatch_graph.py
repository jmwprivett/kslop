#!/usr/bin/env python3
"""Analyze every target in an exact-build PAC chained-fixup corpus.

``cnd_pac_dispatch_graph.py`` starts from explicit PAC instructions and found
172 functions signed for IA/0x2abe.  Chained fixups are a second source of
legitimate signed pointers.  On the 23A341 vPhone collection, the exact
IA/0x2abe/no-address-diversity census contains thousands of entries.  This
tool maps their unique targets back to extracted fileset images and applies
the same function-bounded indirect-branch and pointer-sign analysis.

The output is a candidate graph, not a kcall claim.  It is completely static
and never contacts a VM or device.
"""

from __future__ import annotations

import argparse
import bisect
import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence


LAB_DIR = Path(__file__).resolve().parent
if os.fspath(LAB_DIR) not in sys.path:
    sys.path.insert(0, os.fspath(LAB_DIR))

import cnd_pac_dispatch_graph as dispatch_graph


BUILD = "23A341"
PRODUCT = "iPhone17,3"
KERNEL_UUID = "03A93373-6498-3F25-8975-04DED251AF1F"
KERNEL_SHA256 = "c32c7005fd8f702bf7f34730a512af5cb896a8c61b4a80b8400401f3897060ea"
COLLECTION_SHA256 = "7f363901ec119fc0f4ca4c48c938d468430eb3006d030a7eca0eb3afdde2ce5d"
STATIC_BASE = 0xFFFFFE0007004000
DOMAIN = 0x2ABE


class GraphError(RuntimeError):
    """The exact-build fixup or extracted-image contract failed."""


def _hex(value: int) -> str:
    return f"0x{value:016x}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_hex(value: Any, field: str) -> int:
    if not isinstance(value, str):
        raise GraphError(f"invalid {field}: {value!r}")
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise GraphError(f"invalid {field}: {value!r}") from error
    if parsed < 0 or parsed > 0xFFFFFFFFFFFFFFFF:
        raise GraphError(f"out-of-range {field}: {value!r}")
    return parsed


def _load_fixups(
    path: Path, domain: int = DOMAIN,
) -> dict[int, list[dict[str, Any]]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GraphError(f"cannot read fixup census {path}: {error}") from error
    if not isinstance(document, dict) or \
            document.get("schema") != "cyanide.pac-fixup-census.v1":
        raise GraphError("fixup census has an unsupported schema")
    target = document.get("target")
    query = document.get("query")
    summary = document.get("summary")
    matches = document.get("matches")
    if not isinstance(target, dict) or not isinstance(query, dict) or \
            not isinstance(summary, dict) or not isinstance(matches, list):
        raise GraphError("fixup census is incomplete")
    if target.get("sha256") != COLLECTION_SHA256 or \
            _parse_hex(target.get("base"), "collection base") != STATIC_BASE or \
            target.get("filetype") != "MH_FILESET":
        raise GraphError("fixup census does not name the exact VM collection")
    domain_text = f"0x{domain:04x}"
    if query != {
        "authenticated": True,
        "bind": False,
        "key": "IA",
        "diversity": domain_text,
        "addressDiversity": False,
        "pointerFormats": ["DYLD_CHAINED_PTR_64_KERNEL_CACHE"],
    }:
        raise GraphError(f"fixup census query is not exact IA/{domain_text}")
    if summary.get("matches") != len(matches) or \
            summary.get("usedKernelRead") is not False or \
            summary.get("usedKernelWrite") is not False or \
            summary.get("usedKernelCall") is not False:
        raise GraphError("fixup census summary does not match its records")

    grouped: dict[int, list[dict[str, Any]]] = {}
    locations: set[int] = set()
    for index, match in enumerate(matches):
        if not isinstance(match, dict):
            raise GraphError(f"fixup match {index} is not an object")
        if match.get("authenticated") is not True or \
                match.get("key") != "IA" or \
                match.get("diversity") != domain_text or \
                match.get("addressDiversity") is not False:
            raise GraphError(f"fixup match {index} violates the query")
        location = _parse_hex(match.get("location"), "fixup location")
        target_address = _parse_hex(match.get("target"), "fixup target")
        _parse_hex(match.get("raw"), "fixup raw value")
        if location in locations:
            raise GraphError(f"duplicate fixup location {_hex(location)}")
        locations.add(location)
        grouped.setdefault(target_address, []).append(match)
    if not grouped:
        raise GraphError("fixup census contains no targets")
    return grouped


def _images(paths: Iterable[Path]) -> list[Path]:
    result: list[Path] = []
    for path in paths:
        if path.is_dir():
            result.extend(candidate for candidate in path.iterdir()
                          if candidate.is_file())
        elif path.is_file():
            result.append(path)
        else:
            raise GraphError(f"input does not exist: {path}")
    return sorted(set(result))


def _decode_images(
    images: Sequence[Path], objdump: str, jobs: int,
) -> tuple[
    dict[Path, tuple[list[dispatch_graph.Instruction], list[int], list[int]]],
    list[str],
]:
    decoded: dict[
        Path, tuple[list[dispatch_graph.Instruction], list[int], list[int]]
    ] = {}
    failures: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {
            executor.submit(dispatch_graph._run_objdump, objdump, image): image
            for image in images
        }
        for future in concurrent.futures.as_completed(futures):
            image = futures[future]
            try:
                instructions, starts = future.result()
            except dispatch_graph.GraphError as error:
                failures.append(str(error))
                continue
            decoded[image] = (
                instructions, starts,
                [instruction.address for instruction in instructions],
            )
    return decoded, sorted(failures)


def _candidate(
    target: int,
    image: Path,
    starts: Sequence[int],
    addresses: Sequence[int],
) -> tuple[int, str] | None:
    instruction_index = bisect.bisect_left(addresses, target)
    if instruction_index >= len(addresses) or addresses[instruction_index] != target:
        return None
    function_index = bisect.bisect_right(starts, target) - 1
    if function_index < 0:
        return None
    end = starts[function_index + 1] if function_index + 1 < len(starts) \
        else addresses[-1] + 4
    if not starts[function_index] <= target < end:
        return None
    return end - starts[function_index], image.name


def scan(
    images: Sequence[Path], fixups: dict[int, list[dict[str, Any]]],
    objdump: str, jobs: int, domain: int = DOMAIN,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    decoded, failures = _decode_images(images, objdump, jobs)
    return scan_decoded(decoded, failures, len(images), fixups, domain)


def scan_decoded(
    decoded: dict[
        Path, tuple[
            list[dispatch_graph.Instruction], list[int], list[int],
        ]
    ],
    failures: Sequence[str],
    image_count: int,
    fixups: dict[int, list[dict[str, Any]]],
    domain: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Analyze one PAC domain against an already decoded image set."""
    records: list[dict[str, Any]] = []
    unresolved: list[int] = []
    ambiguous = 0
    for target, target_fixups in sorted(fixups.items()):
        candidates: list[tuple[int, str, Path]] = []
        for image, (_, starts, addresses) in decoded.items():
            score = _candidate(target, image, starts, addresses)
            if score is not None:
                candidates.append((*score, image))
        if not candidates:
            unresolved.append(target)
            continue
        candidates.sort(key=lambda item: (item[0], item[1]))
        if len(candidates) > 1:
            ambiguous += 1
        image = candidates[0][2]
        instructions, starts, addresses = decoded[image]
        record = dispatch_graph._analyze_target(
            image, target, {domain}, [], instructions, starts, addresses,
        )
        record["source"] = "LC_DYLD_CHAINED_FIXUPS"
        record["fixupCount"] = len(target_fixups)
        record["fixupLocations"] = sorted(
            match["location"] for match in target_fixups
        )
        record["fixupRawValues"] = sorted({
            match["raw"] for match in target_fixups
        })
        record["imageCandidates"] = [item[1] for item in candidates]
        records.append(record)

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
            "static-address", "static-page", "constant", "authenticated", "signed",
        }
        for record in records for sign in record["pointerSigns"]
    )
    summary = {
        "kind": "summary",
        "schema": "cyanide.pac-fixup-dispatch-graph.v1",
        "build": BUILD,
        "product": PRODUCT,
        "kernelUUID": KERNEL_UUID,
        "domain": _hex(domain),
        "images": image_count,
        "decodedImages": len(decoded),
        "fixupMatches": sum(len(value) for value in fixups.values()),
        "uniqueFixupTargets": len(fixups),
        "analyzedTargets": len(records),
        "unresolvedTargets": [_hex(value) for value in unresolved],
        "ambiguousImageTargets": ambiguous,
        "constantDomainEdges": constant_edges,
        "rawBranchEdges": raw_edges,
        "dynamicPointerSigns": dynamic_signs,
        "failures": failures,
        "readOnly": True,
        "usedKernelRead": False,
        "usedKernelWrite": False,
        "usedKernelCall": False,
    }
    return records, summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", nargs="+", type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--fixups", required=True, type=Path)
    parser.add_argument(
        "--domain", type=lambda value: int(value, 0), default=DOMAIN,
        help="IA constant diversity selected by the fixup census",
    )
    parser.add_argument("--objdump", default="/usr/bin/xcrun")
    parser.add_argument("--jobs", type=int, default=min(6, os.cpu_count() or 1))
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.kernel.is_file() or _sha256(args.kernel) != KERNEL_SHA256:
        raise GraphError("kernel does not match exact inner 23A341 image")
    if not args.fixups.is_file():
        raise GraphError(f"fixup census does not exist: {args.fixups}")
    if not 1 <= args.jobs <= 64:
        raise GraphError("--jobs must be from 1 to 64")
    if not 0 <= args.domain <= 0xffff:
        raise GraphError("--domain must fit in 16 bits")
    images = _images(args.images)
    if not images:
        raise GraphError("no extracted images")
    fixups = _load_fixups(args.fixups, args.domain)
    records, summary = scan(
        images, fixups, args.objdump, args.jobs, args.domain,
    )
    lines = [json.dumps(record, separators=(",", ":")) for record in records]
    lines.append(json.dumps(summary, separators=(",", ":")))
    encoded = "\n".join(lines) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 1 if summary["failures"] or summary["unresolvedTargets"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GraphError, OSError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
