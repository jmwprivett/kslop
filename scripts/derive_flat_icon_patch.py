#!/usr/bin/env python3
"""Derive/verify an offline, build-bound SBIconImageView flat-policy patch.

Reads a local IPSW and its existing extracted cache. Prints a manifest to stdout;
does not modify either input, connect to a device, or provide a patch writer.

Example (paths may be moved; identity and bytes, not directory names, are checked):
  python3 scripts/derive_flat_icon_patch.py --ipsw /path/to/restore.ipsw \
      --cache /path/to/dyld_shared_cache_arm64e
  python3 scripts/derive_flat_icon_patch.py --ipsw /path/to/restore.ipsw \
      --cache /path/to/dyld_shared_cache_arm64e --verify-manifest /path/to/patch.json

Requires Python 3, ipsw, and a clang supporting the arm64e Apple target. The
profile deliberately accepts only the independently reviewed iPhone17,2 23A341
cache. A new cache needs a separate derivation and control-flow review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import plistlib
import re
import shutil
import struct
import subprocess
import tempfile
import uuid
import zipfile
from pathlib import Path


BUILD = "23A341"
VERSION = "26.0"
DEVICE = "iPhone17,2"
BOARD = "d94ap"
IMAGE = "/System/Library/PrivateFrameworks/SpringBoardHome.framework/SpringBoardHome"
SYMBOL = "-[SBIconImageView effectivelyPrefersFlatImageLayers]"
MAIN_UUID = "DC5F2F67-1FC8-3905-873B-35D17D1A44E8"
SUB_UUID = "E5139123-79ED-3CC2-8E2F-40C980D82033"
IMAGE_UUID = "F3A89682-429D-3319-876B-46D2348E0DFD"
IMAGE_VM = 0x1BDEB2000
METHOD_VM = 0x1BE102E6C
METHOD_SIZE = 0x9C
PATCH_VM = 0x1BE102EF0
ORIGINAL_WORD = 0x1A9F17F4  # cset w20, eq
REPLACEMENT_WORD = 0x52800034  # mov w20, #1
CONTEXT_VM = METHOD_VM - 16
CONTEXT_SIZE = METHOD_SIZE + 32
CONTEXT_HEX = (
    "c0035fd60268283802008052969b09147f2303d5f44fbea9fd7b01a9fd430091"
    "f30300aad82c099460000036340080521b000014e00313aa2b88099420010034"
    "e00313aa70bb089457d59494f30300aaa5d20894f40300aaabd5949494feff34"
    "68531490009146f9c72f09944ed59494f30300aaf40509946000003634008052"
    "06000014e00313aaef93099408f87f921f0900f1f4179f1a9bd59494e00314aa"
    "fd7b41a9f44fc2a8ff0f5fd668f216d008758ab9096868383f01026b"
)


class DerivationError(ValueError):
    """An identity, provenance, encoding, or original-byte guard failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DerivationError(message)


def digest_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def read_at(path: Path, offset: int, size: int) -> bytes:
    with path.open("rb") as source:
        source.seek(offset)
        result = source.read(size)
    require(len(result) == size, f"truncated input: {path.name} at {offset:#x}")
    return result


def cache_header(path: Path) -> dict:
    header = read_at(path, 0, 0x1D8)
    require(header[:16].rstrip(b"\0") == b"dyld_v1  arm64e", "not an arm64e cache")
    mapping_offset, mapping_count = struct.unpack_from("<II", header, 0x10)
    require(0 < mapping_count <= 16, "unexpected cache mapping count")
    mapping_data = read_at(path, mapping_offset, mapping_count * 32)
    mappings = [dict(zip(("address", "size", "fileOffset", "maxProt", "initProt"),
                        struct.unpack_from("<QQQII", mapping_data, index * 32)))
                for index in range(mapping_count)]
    return {
        "uuid": str(uuid.UUID(bytes=header[0x58:0x68])).upper(),
        "sharedRegionStart": struct.unpack_from("<Q", header, 0xE0)[0],
        "osVersion": struct.unpack_from("<I", header, 0x16C)[0],
        "signatureOffset": struct.unpack_from("<Q", header, 0x28)[0],
        "signatureSize": struct.unpack_from("<Q", header, 0x30)[0],
        "subcacheOffset": struct.unpack_from("<I", header, 0x188)[0],
        "subcacheCount": struct.unpack_from("<I", header, 0x18C)[0],
        "mappings": mappings,
    }


def offset_for(header: dict, address: int, size: int = 1) -> int:
    matches = [m for m in header["mappings"]
               if m["address"] <= address and address + size <= m["address"] + m["size"]]
    require(len(matches) == 1, f"address/range is not in one mapping: {address:#x}")
    mapping = matches[0]
    require(mapping["initProt"] == 5 and mapping["maxProt"] == 5,
            "target mapping is not the expected RX mapping")
    return mapping["fileOffset"] + address - mapping["address"]


def der_item(data: bytes, offset: int) -> tuple[int, bytes, int]:
    require(offset + 2 <= len(data), "truncated DER item")
    tag, length = data[offset:offset + 2]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        require(0 < count <= 4 and offset + count <= len(data), "invalid DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    require(offset + length <= len(data), "DER value exceeds input")
    return tag, data[offset:offset + length], offset + length


def trustcache_entries(im4p: bytes) -> tuple[str, set[tuple[bytes, int]]]:
    tag, sequence, end = der_item(im4p, 0)
    require(tag == 0x30 and end == len(im4p), "trustcache is not an IM4P sequence")
    fields = []
    cursor = 0
    while cursor < len(sequence):
        tag, value, cursor = der_item(sequence, cursor)
        fields.append((tag, value))
    require(len(fields) >= 4 and fields[0] == (0x16, b"IM4P") and
            fields[1][0] == 0x16 and fields[1][1] in (b"trst", b"trcs") and fields[3][0] == 4,
            "unexpected trustcache IM4P payload")
    payload = fields[3][1]
    require(len(payload) >= 24, "truncated trustcache header")
    version = struct.unpack_from("<I", payload)[0]
    count = struct.unpack_from("<I", payload, 20)[0]
    require(version == 2 and len(payload) == 24 + 24 * count,
            "unexpected trustcache v2 layout")
    entries = {(payload[pos:pos + 20], payload[pos + 20])
               for pos in range(24, len(payload), 24)}
    return str(uuid.UUID(bytes=payload[4:20])).upper(), entries


def verify_code_directory(path: Path, header: dict,
                          trusted: set[tuple[bytes, int]]) -> dict:
    signature = read_at(path, header["signatureOffset"], header["signatureSize"])
    magic, length, count = struct.unpack_from(">III", signature)
    require(magic == 0xFADE0CC0 and length <= len(signature) and 12 + 8 * count <= length,
            "invalid code-signature superblob")
    directories = []
    for index in range(count):
        _, offset = struct.unpack_from(">II", signature, 12 + 8 * index)
        require(offset + 8 <= length, "code-signature item exceeds superblob")
        item_magic, item_size = struct.unpack_from(">II", signature, offset)
        require(offset + item_size <= length, "code-signature item is truncated")
        if item_magic == 0xFADE0C02:
            directories.append(signature[offset:offset + item_size])
    require(len(directories) == 1, "expected exactly one CodeDirectory")
    directory = directories[0]
    require(len(directory) >= 44, "truncated CodeDirectory")
    hash_offset, _, _, slots, code_limit = struct.unpack_from(">IIIII", directory, 16)
    hash_size, hash_type, _, page_power = struct.unpack_from("4B", directory, 36)
    require(hash_size == 32 and hash_type == 2 and page_power == 14,
            "expected SHA-256 CodeDirectory with 16 KiB pages")
    cd_hash = hashlib.sha256(directory).digest()
    require((cd_hash[:20], hash_type) in trusted,
            f"{path.name} CodeDirectory is absent from the exact IPSW system trustcache")
    page_size = 1 << page_power
    require(slots == (code_limit + page_size - 1) // page_size and
            hash_offset + slots * hash_size <= len(directory), "invalid code hash table")
    require(code_limit <= header["signatureOffset"], "CodeDirectory overlaps signature")
    with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for index in range(slots):
            begin = index * page_size
            expected = directory[hash_offset + index * hash_size:hash_offset + (index + 1) * hash_size]
            actual = hashlib.sha256(data[begin:min(begin + page_size, code_limit)]).digest()
            require(actual == expected, f"{path.name} signed code page {index} does not match")
    return {"sha256": cd_hash.hex(), "cdHash20": cd_hash[:20].hex(),
            "hashType": hash_type, "pageSize": page_size, "verifiedCodePages": slots}


def run(command: list[str], source: str | None = None) -> str:
    result = subprocess.run(command, input=source, text=True, capture_output=True)
    require(result.returncode == 0, f"command failed: {' '.join(command)}\n{result.stderr}")
    return result.stdout


def macho_text(data: bytes) -> bytes:
    require(len(data) >= 32 and struct.unpack_from("<I", data)[0] == 0xFEEDFACF,
            "assembler did not produce a little-endian 64-bit Mach-O")
    count, command_bytes = struct.unpack_from("<II", data, 16)
    require(32 + command_bytes <= len(data), "truncated Mach-O commands")
    cursor = 32
    for _ in range(count):
        command, size = struct.unpack_from("<II", data, cursor)
        require(size >= 8 and cursor + size <= 32 + command_bytes, "invalid Mach-O command")
        if command == 0x19:
            sections = struct.unpack_from("<I", data, cursor + 64)[0]
            require(72 + sections * 80 <= size, "invalid segment sections")
            for index in range(sections):
                section = cursor + 72 + index * 80
                if data[section:section + 16].rstrip(b"\0") == b"__text":
                    extent = struct.unpack_from("<Q", data, section + 40)[0]
                    offset = struct.unpack_from("<I", data, section + 48)[0]
                    require(offset + extent <= len(data), "truncated assembled text section")
                    return data[offset:offset + extent]
        cursor += size
    raise DerivationError("assembled object has no __text section")


def verify_encoding(clang: str) -> dict:
    source = ".text\n.p2align 2\ncset w20, eq\nmov w20, #1\n"
    with tempfile.TemporaryDirectory(prefix="cnd-flat-icon-encoding-") as temporary:
        output = Path(temporary) / "encoding.o"
        run([clang, "-target", "arm64e-apple-macos14.0", "-x", "assembler", "-c",
             "-o", str(output), "-"], source)
        actual = macho_text(output.read_bytes())
    require(actual == struct.pack("<II", ORIGINAL_WORD, REPLACEMENT_WORD),
            "independent clang assembly disagrees with instruction words")
    return {"assembler": "clang integrated assembler", "target": "arm64e-apple-macos14.0",
            "source": source, "textHex": actual.hex()}


def validate_context(context: bytes) -> bytes:
    require(context == bytes.fromhex(CONTEXT_HEX), "surrounding original-byte guard failed")
    method = context[16:16 + METHOD_SIZE]
    require(struct.unpack_from("<I", method, PATCH_VM - METHOD_VM)[0] == ORIGINAL_WORD,
            "original instruction word does not match")
    require(method[:4] == bytes.fromhex("7f2303d5") and
            method[-12:] == bytes.fromhex("fd7b41a9f44fc2a8ff0f5fd6"),
            "PAC entry/authenticated epilogue guard failed")
    return method


def derive(ipsw: Path, cache: Path, ipsw_tool: str, clang: str) -> dict:
    with zipfile.ZipFile(ipsw) as archive:
        build_data = archive.read("BuildManifest.plist")
        version_data = archive.read("SystemVersion.plist")
        build = plistlib.loads(build_data)
        system = plistlib.loads(version_data)
        require(build.get("ProductBuildVersion") == BUILD and build.get("ProductVersion") == VERSION and
                build.get("SupportedProductTypes") == [DEVICE], "IPSW build/device guard failed")
        require(system.get("ProductBuildVersion") == BUILD and system.get("ProductVersion") == VERSION,
                "IPSW SystemVersion guard failed")
        identities = [item for item in build["BuildIdentities"]
                      if item["Info"].get("DeviceClass") == BOARD and
                      item["Info"].get("Variant") == "Customer Erase Install (IPSW)"]
        require(len(identities) == 1, "IPSW board/erase identity guard failed")
        trust_entry = identities[0]["Manifest"]["Cryptex1,SystemTrustCache"]
        trust_path = trust_entry["Info"]["Path"]
        trust_data = archive.read(trust_path)
        trust_digest = hashlib.sha384(trust_data).digest()
        require(trust_digest == trust_entry["Digest"], "IPSW trustcache/BuildManifest digest mismatch")
        trust_uuid, trusted = trustcache_entries(trust_data)
    main = cache_header(cache)
    require(main["uuid"] == MAIN_UUID and main["osVersion"] == 0x1A0000,
            "cache UUID/OS version guard failed (VM and other builds are unsupported)")
    require(main["sharedRegionStart"] == 0x180000000, "unexpected shared-region base")
    subcache = cache.with_name(cache.name + ".19")
    sub = cache_header(subcache)
    require(sub["uuid"] == SUB_UUID, "subcache UUID guard failed")
    require(0 < main["subcacheCount"] <= 128, "unexpected subcache count")
    entries = read_at(cache, main["subcacheOffset"], main["subcacheCount"] * 56)
    matching = [entries[pos:pos + 56] for pos in range(0, len(entries), 56)
                if entries[pos:pos + 16] == uuid.UUID(SUB_UUID).bytes]
    require(len(matching) == 1 and matching[0][24:].rstrip(b"\0") == b".19",
            "main-cache subcache membership/filename guard failed")
    main_cd = verify_code_directory(cache, main, trusted)
    sub_cd = verify_code_directory(subcache, sub, trusted)
    toc = json.loads(run([ipsw_tool, "dyld", "macho", str(cache), IMAGE, "--json"]))
    image_uuids = [item["uuid"] for item in toc["loads"] if item["load_cmd"] == "LC_UUID"]
    text = [item for item in toc["loads"] if item["load_cmd"] == "LC_SEGMENT_64" and item["name"] == "__TEXT"]
    require(image_uuids == [IMAGE_UUID] and len(text) == 1 and text[0]["addr"] == IMAGE_VM,
            "SpringBoardHome UUID/load-address guard failed")
    objc = run([ipsw_tool, "dyld", "macho", str(cache), IMAGE, "--objc", "--verbose", "--no-color"])
    classes = re.findall(r"@interface SBIconImageView\s*:.*?@end", objc, re.DOTALL)
    require(len(classes) == 1, "could not uniquely resolve SBIconImageView metadata")
    matches = re.findall(r"// (0x[0-9a-f]+)\s*\n- \(_Bool\)effectivelyPrefersFlatImageLayers;", classes[0])
    require(matches == [hex(METHOD_VM)], "Objective-C method implementation guard failed")
    context_offset = offset_for(sub, CONTEXT_VM, CONTEXT_SIZE)
    context = read_at(subcache, context_offset, CONTEXT_SIZE)
    method = validate_context(context)
    disassembly = run([ipsw_tool, "dyld", "disass", str(cache), "--vaddr", hex(METHOD_VM),
                      "--count", str(METHOD_SIZE // 4), "--quiet", "--no-color"])
    rows = re.findall(r"^(0x[0-9a-f]+):\s+((?:[0-9a-f]{2} ){3}[0-9a-f]{2})\s+(.*)$",
                      disassembly, re.MULTILINE)
    require(len(rows) == METHOD_SIZE // 4, "unexpected disassembly extent")
    instructions = []
    for index, (address, encoded, operation) in enumerate(rows):
        require(int(address, 16) == METHOD_VM + 4 * index and
                bytes.fromhex(encoded) == method[4 * index:4 * index + 4],
                "disassembly does not match raw cache bytes")
        instructions.append({"address": address, "bytes": bytes.fromhex(encoded).hex(),
                             "instruction": " ".join(operation.split())})
    require(instructions[(PATCH_VM - METHOD_VM) // 4]["instruction"] == "cset w20, eq",
            "patch does not address the final thermal-result instruction")
    encoding = verify_encoding(clang)
    patched = bytearray(method)
    struct.pack_into("<I", patched, PATCH_VM - METHOD_VM, REPLACEMENT_WORD)
    return {
        "schemaVersion": 1,
        "purpose": "Offline derivation of always-true flat icon presentation policy; no writer included",
        "runtimeVerified": False,
        "os": {"productVersion": VERSION, "productBuildVersion": BUILD, "productType": DEVICE,
               "deviceClass": BOARD, "architecture": "arm64e", "identitySource": "local IPSW; device not queried"},
        "ipsw": {"fileName": ipsw.name, "sha256": digest_file(ipsw),
                 "buildManifestSHA256": hashlib.sha256(build_data).hexdigest(),
                 "systemVersionSHA256": hashlib.sha256(version_data).hexdigest(),
                 "systemTrustCache": {"path": trust_path, "uuid": trust_uuid,
                                      "sha384": trust_digest.hex(), "buildManifestDigestVerified": True}},
        "cache": {"fileName": cache.name, "uuid": MAIN_UUID, "sha256": digest_file(cache),
                  "sharedRegionStart": hex(main["sharedRegionStart"]), "codeDirectory": main_cd,
                  "subcache": {"fileName": subcache.name, "uuid": SUB_UUID,
                               "sha256": digest_file(subcache), "codeDirectory": sub_cd}},
        "image": {"path": IMAGE, "uuid": IMAGE_UUID, "unslidLoadAddress": hex(IMAGE_VM)},
        "method": {"symbol": SYMBOL, "returnType": "_Bool", "unslidVMAddress": hex(METHOD_VM),
                   "byteLength": METHOD_SIZE, "sha256": hashlib.sha256(method).hexdigest(),
                   "entryInstruction": "pacibsp", "returnInstruction": "retab",
                   "disassembly": instructions},
        "patch": {"unslidVMAddress": hex(PATCH_VM), "methodOffset": hex(PATCH_VM - METHOD_VM),
                  "imageOffset": hex(PATCH_VM - IMAGE_VM),
                  "sharedRegionOffset": hex(PATCH_VM - main["sharedRegionStart"]),
                  "subcacheFileOffset": hex(offset_for(sub, PATCH_VM, 4)), "alignment": 4, "byteLength": 4,
                  "originalWord": hex(ORIGINAL_WORD), "originalBytesLE": struct.pack("<I", ORIGINAL_WORD).hex(),
                  "originalInstruction": "cset w20, eq",
                  "replacementWord": hex(REPLACEMENT_WORD),
                  "replacementBytesLE": struct.pack("<I", REPLACEMENT_WORD).hex(),
                  "replacementInstruction": "mov w20, #1",
                  "patchedMethodSHA256": hashlib.sha256(patched).hexdigest(),
                  "semantics": "All existing true paths stay true; final nominal/fair thermal path becomes true",
                  "preserved": ["entry instruction", "branches", "calls", "object release", "frame restore", "authenticated return"]},
        "guard": {"unslidVMAddress": hex(CONTEXT_VM), "subcacheFileOffset": hex(context_offset),
                  "byteLength": CONTEXT_SIZE, "bytesHex": context.hex(),
                  "sha256": hashlib.sha256(context).hexdigest(), "methodOffset": 16,
                  "patchOffset": PATCH_VM - CONTEXT_VM},
        "independentEncodingCheck": encoding,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ipsw", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--ipsw-tool", default=shutil.which("ipsw") or "ipsw")
    parser.add_argument("--clang", default=shutil.which("clang") or "clang")
    parser.add_argument("--verify-manifest", type=Path)
    args = parser.parse_args()
    try:
        manifest = derive(args.ipsw, args.cache, args.ipsw_tool, args.clang)
        if args.verify_manifest:
            expected = json.loads(args.verify_manifest.read_text())
            require(manifest == expected, "derived manifest does not equal the reviewed manifest")
            print(f"Verified {BUILD}/{DEVICE}: cache identity, IPSW trustcache, signed pages, metadata, context, and encoding.")
        else:
            print(json.dumps(manifest, indent=2))
    except (DerivationError, OSError, KeyError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, f"derivation refused: {error}\n")


if __name__ == "__main__":
    main()
