#!/usr/bin/env python3
"""Safely inventory and import user-supplied supplemental Pulsar PNGs.

This preserves the submitted images byte-for-byte. Semantic mappings live in
the generator, separately from filenames chosen by an image download tool.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import struct
import zipfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "assets/pulsar-controlcenter-supplemental"
MAX_MEMBER_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


def inventory_archive(archive: Path) -> dict[str, bytes]:
    """Validate the complete archive before returning any importable content."""
    members: dict[str, bytes] = {}
    with zipfile.ZipFile(archive) as source:
        total = 0
        for member in source.infolist():
            name = member.filename
            path = PurePosixPath(name)
            mode = member.external_attr >> 16
            if (path.is_absolute() or ".." in path.parts or "\\" in name or
                    ":" in name or "\x00" in name or stat.S_ISLNK(mode)):
                raise ValueError(f"unsafe archive member: {name!r}")
            if member.is_dir():
                continue
            if len(path.parts) != 1 or path.suffix.lower() != ".png":
                raise ValueError(f"expected top-level PNG: {name!r}")
            if name in members:
                raise ValueError(f"duplicate archive member: {name!r}")
            total += member.file_size
            if member.file_size > MAX_MEMBER_BYTES or total > MAX_ARCHIVE_BYTES:
                raise ValueError("supplemental archive exceeds import size limit")
            data = source.read(member)
            if len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n":
                raise ValueError(f"invalid PNG signature: {name!r}")
            width, height, depth, color = struct.unpack(">IIBB", data[16:26])
            if not (0 < width <= 4096 and 0 < height <= 4096):
                raise ValueError(f"invalid PNG dimensions: {name!r}")
            if depth != 8 or color != 6 or data[28] != 0:
                raise ValueError(f"expected noninterlaced 8-bit RGBA PNG: {name!r}")
            members[name] = data
    if not members:
        raise ValueError("supplemental archive contains no PNGs")
    return members


def import_archive(archive: Path, output: Path) -> dict:
    members = inventory_archive(archive)
    # Resolve every overwrite before writing any member; unrelated assets and
    # the full original Pulsar set are never removed by this importer.
    manifest_path = output / "source-manifest.json"
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise ValueError(f"unsafe import destination: {output}")
    if manifest_path.is_symlink() or (manifest_path.exists() and not manifest_path.is_file()):
        raise ValueError(f"unsafe import destination: {manifest_path}")
    for name in members:
        target = output / name
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError(f"unsafe import destination: {target}")
    manifest = {}
    records = {}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1 or
                manifest.get("artworkRole") != "supplemental" or
                not isinstance(manifest.get("assets"), list)):
            raise ValueError("invalid existing supplemental manifest")
        for record in manifest["assets"]:
            name = record.get("filename") if isinstance(record, dict) else None
            if not isinstance(name, str):
                raise ValueError("invalid existing supplemental asset record")
            path = PurePosixPath(name)
            if (path.is_absolute() or len(path.parts) != 1 or path.suffix.lower() != ".png" or
                    ".." in path.parts or "\\" in name or ":" in name or "\x00" in name or
                    name in records):
                raise ValueError(f"unsafe or duplicate existing asset: {name!r}")
            target = output / name
            if target.is_symlink() or not target.is_file():
                raise ValueError(f"missing or unsafe retained asset: {target}")
            data = target.read_bytes()
            if (len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n" or
                    len(data) != record.get("bytes") or
                    hashlib.sha256(data).hexdigest() != record.get("sha256") or
                    struct.unpack(">II", data[16:24]) !=
                    (record.get("width"), record.get("height"))):
                raise ValueError(f"existing asset does not match manifest: {name}")
            records[name] = record
    for name, data in sorted(members.items()):
        width, height = struct.unpack(">II", data[16:24])
        records[name] = {"filename": name, "sha256": hashlib.sha256(data).hexdigest(),
                         "width": width, "height": height, "bytes": len(data)}
    manifest.update({"schemaVersion": 1, "sourceArchive": archive.name,
                     "sourceSHA256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                     "artworkRole": "supplemental",
                     "assets": [records[name] for name in sorted(records)]})
    output.mkdir(parents=True, exist_ok=True)
    for name, data in members.items():
        (output / name).write_bytes(data)
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    manifest = import_archive(args.archive, args.output)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
