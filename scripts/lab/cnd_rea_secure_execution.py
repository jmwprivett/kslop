#!/usr/bin/env python3
"""Bind an exact kernel/TXM/SPTM set to REA snapshots and a live vPhone."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from cnd_remotecall_lab import LabError, run
from cnd_vphone_krw import debugger_kernel_address


SCHEMA = "com.zeroxjf.cyanide.rea-secure-execution-bundle"
SCHEMA_VERSION = 1
OBSERVATION_SCHEMA = SCHEMA + ".observation-profile"
OBSERVATION_PLAN_SCHEMA = SCHEMA + ".observation-plan"
RESEARCH_PLAN_SCHEMA = SCHEMA + ".research-plan"
DEFAULT_IPSW = Path("/opt/homebrew/bin/ipsw")
TARGETS = ("kernel", "txm", "sptm")
SEARCHES = {
    "kernel": (
        r"(AppleMobileFileIntegrity|trust.?cache|cs_allow_invalid|pmap_cs|TXM)",
    ),
    "txm": (
        r"(trust.?cache|code.?sign|signature|entitlement|developer.?mode|pmap)",
    ),
    "sptm": (
        r"(trust.?cache|code.?sign|signature|pmap|dispatch.?permission)",
    ),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_byte_assertion(value: str) -> dict[str, Any]:
    match = re.fullmatch(r"(0x[0-9A-Fa-f]+)=([0-9A-Fa-f]{2,128})", value)
    if not match or len(match.group(2)) % 2:
        raise argparse.ArgumentTypeError(
            "byte assertion must be 0xOFFSET=EVEN_LENGTH_HEX (1-64 bytes)"
        )
    return {
        "offset": int(match.group(1), 16),
        "bytes_hex": match.group(2).lower(),
    }


def parse_live_assertion(value: str) -> dict[str, Any]:
    match = re.fullmatch(
        r"(0x[0-9A-Fa-f]{16})=([0-9A-Fa-f]{2,128})", value,
    )
    if not match or len(match.group(2)) % 2:
        raise argparse.ArgumentTypeError(
            "live assertion must be 0xSTATIC_ADDRESS=EVEN_LENGTH_HEX "
            "(1-64 bytes)"
        )
    address = int(match.group(1), 16)
    if address & 0xffff000000000000 != 0xffff000000000000:
        raise argparse.ArgumentTypeError("live assertion address is not canonical")
    return {
        "static_address": f"0x{address:016x}",
        "bytes_hex": match.group(2).lower(),
    }


def verify_byte_assertions(path: Path,
                           assertions: list[dict[str, Any]]) -> None:
    size = path.stat().st_size
    with path.open("rb") as stream:
        for assertion in assertions:
            offset = assertion.get("offset")
            expected_hex = assertion.get("bytes_hex")
            if not isinstance(offset, int) or offset < 0 or \
                    not isinstance(expected_hex, str):
                raise LabError("artifact byte assertion is malformed")
            try:
                expected = bytes.fromhex(expected_hex)
            except ValueError as error:
                raise LabError("artifact byte assertion has invalid hex") from error
            if not expected or offset + len(expected) > size:
                raise LabError("artifact byte assertion is outside the file")
            stream.seek(offset)
            observed = stream.read(len(expected))
            if observed != expected:
                raise LabError(
                    f"artifact byte assertion failed at 0x{offset:x}: "
                    f"expected {expected.hex()}, observed {observed.hex()}"
                )


def existing_file(path: Path, description: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise LabError(f"{description} is not a regular file: {resolved}")
    return resolved


def command_json(argv: list[str]) -> dict[str, Any]:
    completed = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise LabError(f"command failed ({completed.returncode}): {detail}")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LabError("command did not return one JSON object") from error
    if not isinstance(value, dict):
        raise LabError("command did not return one JSON object")
    return value


def load_command_value(info: dict[str, Any], command: str,
                       key: str) -> str:
    loads = info.get("loads")
    if not isinstance(loads, list):
        raise LabError("Mach-O inspection has no load-command list")
    values = [load.get(key) for load in loads
              if isinstance(load, dict) and load.get("load_cmd") == command]
    if len(values) != 1 or not isinstance(values[0], str) or not values[0]:
        raise LabError(f"Mach-O inspection has no unique {command} {key}")
    return values[0]


def text_address(info: dict[str, Any]) -> str:
    loads = info.get("loads")
    values = [load.get("addr") for load in loads or []
              if isinstance(load, dict) and
              load.get("load_cmd") == "LC_SEGMENT_64" and
              load.get("name") == "__TEXT"]
    if len(values) != 1 or not isinstance(values[0], int):
        raise LabError("Mach-O inspection has no unique __TEXT address")
    return f"0x{values[0]:016x}"


def macho_identity(path: Path, ipsw: Path,
                   fileset_entry: str | None = None) -> dict[str, str]:
    argv = [str(ipsw), "macho", "info"]
    if fileset_entry is not None:
        argv.extend(["--fileset-entry", fileset_entry])
    argv.extend(["--json", str(path)])
    info = command_json(argv)
    header = info.get("header")
    if not isinstance(header, dict):
        raise LabError("Mach-O inspection has no header")
    cpu = header.get("cpu")
    subtype = header.get("subcpu")
    if not isinstance(cpu, str) or not isinstance(subtype, str):
        raise LabError("Mach-O inspection has no CPU identity")
    return {
        "uuid": load_command_value(info, "LC_UUID", "uuid").upper(),
        "source_version": load_command_value(
            info, "LC_SOURCE_VERSION", "version"),
        "cpu": cpu,
        "subtype": subtype,
        "text_address": text_address(info),
    }


def artifact(role: str, path: Path, snapshot: Path, ipsw: Path,
             assertions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    resolved = existing_file(path, f"{role} artifact")
    snapshot = snapshot.expanduser().resolve()
    assertions = assertions or []
    verify_byte_assertions(resolved, assertions)
    identity = macho_identity(
        resolved, ipsw, "com.apple.kernel" if role == "kernel" else None,
    )
    result: dict[str, Any] = {
        "path": str(resolved),
        "sha256": sha256(resolved),
        "size": resolved.stat().st_size,
        "macho": identity,
        "rea_snapshot": {
            "path": str(snapshot),
            "present": snapshot.is_file(),
        },
        "byte_assertions": assertions,
    }
    if snapshot.is_file():
        result["rea_snapshot"]["sha256"] = sha256(snapshot)
        result["rea_snapshot"]["size"] = snapshot.stat().st_size
    return result


def runtime_binding(kernel: dict[str, Any], debug_port: int) -> dict[str, Any]:
    load_address, live_uuid = debugger_kernel_address(debug_port)
    static_uuid = kernel["macho"]["uuid"]
    if live_uuid != static_uuid:
        raise LabError(
            f"live kernel UUID {live_uuid} does not match artifact {static_uuid}"
        )
    static_text = int(kernel["macho"]["text_address"], 16)
    live_text = int(load_address, 16)
    if live_text < static_text:
        raise LabError("live kernel load address precedes static __TEXT")
    return {
        "kernel_debug_port": debug_port,
        "kernel_uuid": live_uuid,
        "load_address": load_address,
        "static_text_address": kernel["macho"]["text_address"],
        "slide": f"0x{live_text - static_text:x}",
        "verified": True,
    }


def debugger_kernel_bytes(port: int, address: str, length: int) -> bytes:
    if port < 6000 or port > 65535:
        raise LabError("kernel debug port must be between 6000 and 65535")
    if not re.fullmatch(r"0x[0-9a-f]{16}", address) or length < 1 or length > 64:
        raise LabError("invalid bounded kernel memory request")
    result = run([
        "xcrun", "lldb", "--batch",
        "-o", "platform select remote-ios",
        "-o", f"gdb-remote 127.0.0.1:{port}",
        "-o", f"memory read --size 1 --format x --count {length} {address}",
        "-o", "process detach",
    ])
    report = (result.stdout + result.stderr).decode("utf-8", "replace")
    if "Process 1 detached" not in report:
        raise LabError("kernel debugger memory read did not detach")
    observed = bytearray()
    for line in report.splitlines():
        if not re.match(r"^0x[0-9a-f]{16}:", line):
            continue
        observed.extend(
            int(value, 16) for value in re.findall(r"\b0x([0-9a-f]{2})\b", line)
        )
    if len(observed) != length:
        raise LabError(
            f"kernel debugger returned {len(observed)} of {length} requested bytes"
        )
    return bytes(observed)


def verify_live_assertions(binding: dict[str, Any], debug_port: int,
                           assertions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    slide = int(binding["slide"], 16)
    result = []
    for assertion in assertions:
        static_text = assertion.get("static_address")
        expected_hex = assertion.get("bytes_hex")
        if not isinstance(static_text, str) or not isinstance(expected_hex, str):
            raise LabError("kernel live assertion is malformed")
        try:
            static_address = int(static_text, 16)
            expected = bytes.fromhex(expected_hex)
        except ValueError as error:
            raise LabError("kernel live assertion is malformed") from error
        live_address = f"0x{static_address + slide:016x}"
        observed = debugger_kernel_bytes(debug_port, live_address, len(expected))
        if observed != expected:
            raise LabError(
                f"live kernel assertion failed at {live_address}: "
                f"expected {expected.hex()}, observed {observed.hex()}"
            )
        result.append({
            "static_address": static_text,
            "live_address": live_address,
            "bytes_hex": expected_hex,
            "verified": True,
        })
    return result


def create_bundle(args: argparse.Namespace) -> dict[str, Any]:
    ipsw = existing_file(args.ipsw, "ipsw executable")
    snapshots = args.snapshot_dir.expanduser().resolve()
    artifacts = {
        role: artifact(
            role, getattr(args, role), snapshots / f"{role}-vm-rea-snapshot.json",
            ipsw, getattr(args, f"{role}_assert"),
        )
        for role in TARGETS
    }
    bundle: dict[str, Any] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "build": args.build,
        "product": args.product,
        "environment": args.environment,
        "artifacts": artifacts,
        "analysis": {
            "provider": "ghidra",
            "queries": [
                {
                    "id": f"{role}-secure-strings",
                    "artifact": role,
                    "operation": "search",
                    "kind": "strings",
                    "mode": "regex",
                    "pattern": SEARCHES[role][0],
                }
                for role in TARGETS
            ],
        },
        "kernel_live_assertions": args.kernel_live_assert,
    }
    if args.kernel_debug_port is not None:
        binding = runtime_binding(artifacts["kernel"], args.kernel_debug_port)
        binding["kernel_byte_assertions"] = verify_live_assertions(
            binding, args.kernel_debug_port, args.kernel_live_assert,
        )
        bundle["runtime"] = binding
    return bundle


def load_bundle(path: Path) -> dict[str, Any]:
    source = existing_file(path, "bundle manifest")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise LabError("bundle manifest is not valid JSON") from error
    if not isinstance(value, dict) or value.get("schema") != SCHEMA or \
            value.get("schema_version") != SCHEMA_VERSION:
        raise LabError("unsupported secure-execution bundle schema")
    return value


def load_observation_profile(path: Path) -> dict[str, Any]:
    source = existing_file(path, "observation profile")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise LabError("observation profile is not valid JSON") from error
    if not isinstance(value, dict) or value.get("schema") != OBSERVATION_SCHEMA or \
            value.get("schema_version") != SCHEMA_VERSION:
        raise LabError("unsupported observation-profile schema")
    return value


def _kernel_static_address(value: Any) -> int:
    if not isinstance(value, str) or not re.fullmatch(
            r"0xfffffe[0-9a-f]{10}", value):
        raise LabError(f"invalid static kernel address: {value!r}")
    return int(value, 16)


def _capture_spec(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LabError("observation capture must be an object")
    registers = value.get("registers", [])
    if not isinstance(registers, list) or len(registers) > 16 or any(
        not isinstance(register, str) or not re.fullmatch(
            r"(?:[xw](?:[0-9]|[12][0-9]|30)|sp|pc|lr)", register,
        ) for register in registers
    ):
        raise LabError("observation registers are malformed or unbounded")
    memories = value.get("memory", [])
    if not isinstance(memories, list) or len(memories) > 4:
        raise LabError("observation memory captures are malformed or unbounded")
    normalized_memory = []
    for memory in memories:
        if not isinstance(memory, dict):
            raise LabError("observation memory capture must be an object")
        base = memory.get("base_register")
        size = memory.get("size")
        count = memory.get("count")
        if not isinstance(base, str) or not re.fullmatch(
                r"(?:x(?:[0-9]|[12][0-9]|30)|sp)", base):
            raise LabError("observation memory base register is invalid")
        if size not in (1, 2, 4, 8) or not isinstance(count, int) or \
                isinstance(count, bool) or count < 1 or count > 64:
            raise LabError("observation memory capture exceeds bounded limits")
        normalized_memory.append({
            "base_register": base,
            "size": size,
            "count": count,
        })
    return {"registers": registers, "memory": normalized_memory}


def _require_profile_identity(bundle: dict[str, Any],
                              profile: dict[str, Any]) -> dict[str, Any]:
    identity = profile.get("identity")
    artifacts = bundle.get("artifacts")
    if not isinstance(identity, dict) or not isinstance(artifacts, dict):
        raise LabError("observation profile or bundle identity is malformed")
    records = {role: artifacts.get(role) for role in TARGETS}
    if any(not isinstance(record, dict) for record in records.values()):
        raise LabError("bundle has no exact kernel/TXM/SPTM identity")
    kernel = records["kernel"]
    expected = {
        "build": bundle.get("build"),
        "product": bundle.get("product"),
        "kernel_uuid": kernel.get("macho", {}).get("uuid"),
        "kernel_sha256": kernel.get("sha256"),
        "txm_sha256": records["txm"].get("sha256"),
        "sptm_sha256": records["sptm"].get("sha256"),
    }
    for key, observed in expected.items():
        if identity.get(key) != observed:
            raise LabError(
                f"observation profile {key} does not match exact bundle"
            )
    return identity


def observation_plan(bundle: dict[str, Any], profile: dict[str, Any],
                     runtime: dict[str, Any]) -> dict[str, Any]:
    identity = _require_profile_identity(bundle, profile)
    expected_kernel_uuid = identity["kernel_uuid"]
    if runtime.get("verified") is not True or \
            runtime.get("kernel_uuid") != expected_kernel_uuid:
        raise LabError("observation plan requires a verified exact live kernel")
    try:
        slide = int(runtime["slide"], 16)
    except (KeyError, TypeError, ValueError) as error:
        raise LabError("verified runtime has no valid kernel slide") from error

    points = profile.get("points")
    if not isinstance(points, list) or not 1 <= len(points) <= 4:
        raise LabError("observation profile requires one to four breakpoints")
    identifiers: set[str] = set()
    breakpoints = []
    for point in points:
        if not isinstance(point, dict):
            raise LabError("observation point must be an object")
        identifier = point.get("id")
        if not isinstance(identifier, str) or not re.fullmatch(
                r"[a-z][a-z0-9_-]{0,47}", identifier) or \
                identifier in identifiers:
            raise LabError("observation point identifier is invalid or repeated")
        identifiers.add(identifier)
        static = _kernel_static_address(point.get("static_address"))
        condition = point.get("condition")
        if condition is not None and (
            not isinstance(condition, str) or not re.fullmatch(
                r"\$w(?:[0-9]|[12][0-9]|30) == (?:0x[0-9a-f]+|[0-9]+)",
                condition,
            )
        ):
            raise LabError("observation breakpoint condition is not bounded")
        entry = {
            "id": identifier,
            "static_address": f"0x{static:016x}",
            "live_address": f"0x{static + slide:016x}",
            "hardware": True,
            "one_shot": True,
            "auto_continue": True,
            "capture": _capture_spec(point.get("capture", {})),
        }
        if condition is not None:
            entry["condition"] = condition
        if isinstance(point.get("purpose"), str):
            entry["purpose"] = point["purpose"]
        breakpoints.append(entry)

    return {
        "schema": OBSERVATION_PLAN_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "identity": identity,
        "runtime": {
            "kernel_debug_port": runtime.get("kernel_debug_port"),
            "kernel_uuid": runtime["kernel_uuid"],
            "slide": runtime["slide"],
            "verified": True,
        },
        "limits": {
            "hardware_breakpoints": len(breakpoints),
            "maximum_hardware_breakpoints": 4,
            "persistent_mutation": False,
        },
        "breakpoints": breakpoints,
        "abi": profile.get("abi", {}),
        "reconciliation": profile.get("reconciliation", {}),
        "rea_evidence": profile.get("rea_evidence", []),
    }


def targeted_rea_plan(bundle: dict[str, Any], profile: dict[str, Any],
                      rea_root: Path, ghidra_install: Path) -> dict[str, Any]:
    identity = _require_profile_identity(bundle, profile)
    rea = existing_file(rea_root.expanduser().resolve() / "scripts/rea.mjs",
                        "REA CLI")
    ghidra = ghidra_install.expanduser().resolve()
    if not ghidra.is_dir():
        raise LabError(f"Ghidra install is not a directory: {ghidra}")
    targets = profile.get("analysis_targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 32:
        raise LabError("research profile requires one to 32 analysis targets")
    artifacts = bundle["artifacts"]
    identifiers: set[str] = set()
    operations = []
    for target in targets:
        if not isinstance(target, dict):
            raise LabError("analysis target must be an object")
        identifier = target.get("id")
        if not isinstance(identifier, str) or not re.fullmatch(
                r"[a-z][a-z0-9_-]{0,63}", identifier) or \
                identifier in identifiers:
            raise LabError("analysis target identifier is invalid or repeated")
        identifiers.add(identifier)
        role = target.get("artifact")
        operation = target.get("operation")
        if role not in TARGETS or operation not in ("function", "trace"):
            raise LabError("analysis target artifact or operation is invalid")
        item = artifacts[role]
        snapshot_root = Path(
            str(item.get("rea_snapshot", {}).get("path", ""))
        ).expanduser().resolve().parent
        artifact_file = target.get("artifact_file")
        if artifact_file is None:
            artifact_path = existing_file(Path(str(item.get("path", ""))),
                                          f"{role} artifact")
            artifact_digest = item.get("sha256")
        else:
            if not isinstance(artifact_file, str) or \
                    not re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:/"
                        r"[A-Za-z0-9][A-Za-z0-9_.-]*){0,3}", artifact_file):
                raise LabError("analysis target artifact variant is invalid")
            expected_digest = target.get("artifact_sha256")
            if not isinstance(expected_digest, str) or \
                    not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
                raise LabError("analysis target artifact variant has no digest")
            artifact_path = existing_file(
                (snapshot_root / artifact_file).resolve(),
                f"{role} artifact variant",
            )
            if not artifact_path.is_relative_to(snapshot_root) or \
                    sha256(artifact_path) != expected_digest:
                raise LabError(
                    "analysis target artifact variant failed exact binding")
            artifact_digest = expected_digest
        if operation == "function":
            value = target.get("address")
            if not isinstance(value, str) or not re.fullmatch(
                    r"0xffff[0-9a-f]{12}", value):
                raise LabError("analysis function address is not canonical")
        else:
            value = target.get("query")
            if not isinstance(value, str) or not 1 <= len(value) <= 128 or \
                    any(ord(character) < 0x20 for character in value):
                raise LabError("analysis trace query is malformed or unbounded")
        snapshot_name = target.get(
            "snapshot", f"{identifier}-rea-snapshot.json")
        if not isinstance(snapshot_name, str) or not re.fullmatch(
                r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\.json", snapshot_name):
            raise LabError("analysis target snapshot name is invalid")
        snapshot = snapshot_root / snapshot_name
        operation_record: dict[str, Any] = {
            "id": identifier,
            "artifact": role,
            "artifact_sha256": artifact_digest,
            "operation": operation,
            "purpose": target.get("purpose", ""),
            "environment": {
                "GHIDRA_INSTALL_DIR": str(ghidra),
                "REA_GHIDRA_STARTUP_TIMEOUT_MS": "1200000",
            },
            "argv": [
                "node", str(rea), operation, str(artifact_path), value,
                "--provider", "ghidra", "--snapshot", str(snapshot),
                "--format", "json", "--full-output",
            ],
        }
        operations.append(operation_record)
    return {
        "schema": RESEARCH_PLAN_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "identity": identity,
        "operations": operations,
        "dispatch_abi": profile.get("dispatch_abi", {}),
        "sptm_services": profile.get("sptm_services", []),
        "rea_evidence": profile.get("rea_evidence", []),
    }


def verify_bundle(bundle: dict[str, Any], debug_port: int | None) -> dict[str, Any]:
    artifacts = bundle.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(TARGETS):
        raise LabError("bundle must contain exactly kernel, TXM, and SPTM")
    verified: dict[str, Any] = {}
    for role in TARGETS:
        item = artifacts[role]
        if not isinstance(item, dict):
            raise LabError(f"invalid {role} artifact record")
        path = existing_file(Path(str(item.get("path", ""))), f"{role} artifact")
        observed = sha256(path)
        if observed != item.get("sha256") or path.stat().st_size != item.get("size"):
            raise LabError(f"{role} artifact digest or size changed")
        assertions = item.get("byte_assertions", [])
        if not isinstance(assertions, list):
            raise LabError(f"{role} artifact byte assertions are malformed")
        verify_byte_assertions(path, assertions)
        verified[role] = {"path": str(path), "sha256": observed, "verified": True}
        snapshot = item.get("rea_snapshot")
        if isinstance(snapshot, dict) and snapshot.get("present"):
            snapshot_path = existing_file(
                Path(str(snapshot.get("path", ""))), f"{role} REA snapshot",
            )
            if sha256(snapshot_path) != snapshot.get("sha256"):
                raise LabError(f"{role} REA snapshot digest changed")
            verified[role]["rea_snapshot_verified"] = True
    result: dict[str, Any] = {"artifacts": verified, "verified": True}
    if debug_port is not None:
        binding = runtime_binding(artifacts["kernel"], debug_port)
        live_assertions = bundle.get("kernel_live_assertions", [])
        if not isinstance(live_assertions, list):
            raise LabError("kernel live assertions are malformed")
        binding["kernel_byte_assertions"] = verify_live_assertions(
            binding, debug_port, live_assertions,
        )
        result["runtime"] = binding
    return result


def rea_plan(bundle: dict[str, Any], rea_root: Path,
             ghidra_install: Path) -> dict[str, Any]:
    rea = existing_file(rea_root.expanduser().resolve() / "scripts/rea.mjs",
                        "REA CLI")
    ghidra = ghidra_install.expanduser().resolve()
    if not ghidra.is_dir():
        raise LabError(f"Ghidra install is not a directory: {ghidra}")
    artifacts = bundle["artifacts"]
    operations = []
    for query in bundle["analysis"]["queries"]:
        role = query["artifact"]
        item = artifacts[role]
        query_snapshot = (
            Path(item["rea_snapshot"]["path"]).parent /
            f"{query['id']}-rea-snapshot.json"
        )
        operations.append({
            "id": query["id"],
            "environment": {
                "GHIDRA_INSTALL_DIR": str(ghidra),
                "REA_GHIDRA_STARTUP_TIMEOUT_MS": "1200000",
            },
            "argv": [
                "node", str(rea), query["operation"], item["path"],
                f"--pattern={query['pattern']}", "--kind", query["kind"],
                "--mode", query["mode"], "--provider", "ghidra",
                "--snapshot", str(query_snapshot),
                "--format", "json", "--full-output",
            ],
        })
    return {
        "schema": SCHEMA + ".rea-plan",
        "schema_version": SCHEMA_VERSION,
        "operations": operations,
    }


def write_json(path: Path | None, value: dict[str, Any]) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path is None:
        print(payload, end="")
        return
    destination = path.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=destination.name + ".", dir=destination.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="action", required=True)
    create = commands.add_parser("create", help="create an exact artifact bundle")
    create.add_argument("--kernel", type=Path, required=True)
    create.add_argument("--txm", type=Path, required=True)
    create.add_argument("--sptm", type=Path, required=True)
    create.add_argument("--snapshot-dir", type=Path, required=True)
    create.add_argument("--build", required=True)
    create.add_argument("--product", required=True)
    create.add_argument("--environment", default="vphone-jb")
    create.add_argument("--kernel-debug-port", type=int)
    create.add_argument(
        "--kernel-live-assert", type=parse_live_assertion,
        action="append", default=[], metavar="0xSTATIC_ADDRESS=HEX",
        help="require exact slid live-kernel bytes (repeatable, read-only)",
    )
    for role in TARGETS:
        create.add_argument(
            f"--{role}-assert", type=parse_byte_assertion,
            action="append", default=[], metavar="0xOFFSET=HEX",
            help=f"require exact {role} bytes (repeatable; records patch state)",
        )
    create.add_argument("--ipsw", type=Path, default=DEFAULT_IPSW)
    create.add_argument("--output", type=Path)

    verify = commands.add_parser("verify", help="rehash a bundle and optionally bind it live")
    verify.add_argument("manifest", type=Path)
    verify.add_argument("--kernel-debug-port", type=int)
    verify.add_argument("--output", type=Path)

    plan = commands.add_parser("rea-plan", help="emit bounded REA argv vectors")
    plan.add_argument("manifest", type=Path)
    plan.add_argument("--rea-root", type=Path, required=True)
    plan.add_argument("--ghidra-install", type=Path, required=True)
    plan.add_argument("--output", type=Path)

    research = commands.add_parser(
        "research-plan",
        help="emit exact targeted REA function/trace argv vectors",
    )
    research.add_argument("manifest", type=Path)
    research.add_argument("profile", type=Path)
    research.add_argument("--rea-root", type=Path, required=True)
    research.add_argument("--ghidra-install", type=Path, required=True)
    research.add_argument("--output", type=Path)

    observe = commands.add_parser(
        "observe-plan",
        help="bind exact REA findings to bounded live-kernel breakpoints",
    )
    observe.add_argument("manifest", type=Path)
    observe.add_argument("profile", type=Path)
    observe.add_argument("--kernel-debug-port", type=int, required=True)
    observe.add_argument("--output", type=Path)
    return root


def main() -> int:
    args = parser().parse_args()
    if args.action == "create":
        value = create_bundle(args)
    elif args.action == "verify":
        value = verify_bundle(load_bundle(args.manifest), args.kernel_debug_port)
    elif args.action == "rea-plan":
        value = rea_plan(
            load_bundle(args.manifest), args.rea_root, args.ghidra_install,
        )
    elif args.action == "research-plan":
        value = targeted_rea_plan(
            load_bundle(args.manifest), load_observation_profile(args.profile),
            args.rea_root, args.ghidra_install,
        )
    else:
        bundle = load_bundle(args.manifest)
        verified = verify_bundle(bundle, args.kernel_debug_port)
        value = observation_plan(
            bundle, load_observation_profile(args.profile), verified["runtime"],
        )
    write_json(args.output, value)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
