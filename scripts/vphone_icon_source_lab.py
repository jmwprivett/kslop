#!/usr/bin/env python3
"""Guarded, host-only harness for the Phase 6 vphone icon-source experiment.

This module deliberately has no knowledge of the on-device Cyanide code.  It
records a small, explicit allow-list in a durable journal and only a transport
implementation supplied by the operator can perform the guest file writes.
The command line is consequently useful for preflight and evidence review
even on a machine which is not connected to the vphone.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import plistlib
import posixpath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence


EXPECTED_UDID = os.environ.get("CND_VPHONE_UDID", "SET_CND_VPHONE_UDID")
EXPECTED_IOS_VERSION = "26.0"
EXPECTED_BUILD = "23A341"
EXPECTED_SSH_PORT = 22222
EXPECTED_BUNDLE_ID = "com.zeroxjf.ios-cyanide1"
EXPECTED_ECID = int(os.environ.get("CND_VPHONE_ECID", "10000000000000000001"))
EXPECTED_PLATFORM_TYPE = "vresearch101"
EXPECTED_DISK_IMAGE = "Disk.img"
EXPECTED_NVRAM_STORAGE = "nvram.bin"
EXPECTED_SEP_STORAGE = "SEPStorage"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE_ROOT = Path.home() / "Library/CyanideVPhoneLab/evidence/phase6"
DEFAULT_THEME_ARCHIVE = REPO_ROOT / "purple accent pulsar.theme.zip"
DEFAULT_THEME_ENTRY = "purple accent pulsar.theme/IconBundles/com.zeroxjf.ios-cyanide1-large.png"
DEFAULT_DIAGNOSTIC_IPA = REPO_ROOT / "build/Cyanide-1.6-spotlight.ipa"
DEFAULT_KNOWN_HOSTS = DEFAULT_EVIDENCE_ROOT / "ssh_known_hosts"
PROTECTED_IPA = REPO_ROOT / "build/Cyanide.ipa"
CONFIRM_TOKEN = "PHASE6-EXECUTE"
SCHEMA_VERSION = 1
VALID_ARMS = {"car", "png", "declaration-redirect"}
REMOTE_SYSTEM_VERSION_PLIST = "/System/Library/CoreServices/SystemVersion.plist"
REMOTE_TOOL_CANDIDATES: dict[str, tuple[str, ...]] = {
    "cat": ("/var/jb/bin/cat", "/iosbinpack64/bin/cat"),
    "cp": ("/var/jb/bin/cp", "/iosbinpack64/bin/cp"),
    "mv": ("/var/jb/bin/mv", "/iosbinpack64/bin/mv"),
    "rm": ("/var/jb/bin/rm", "/iosbinpack64/bin/rm"),
    "tee": ("/var/jb/usr/bin/tee", "/iosbinpack64/usr/bin/tee"),
    "stat": ("/var/jb/usr/bin/stat", "/iosbinpack64/usr/bin/stat"),
    "sha256sum": ("/var/jb/usr/bin/sha256sum",),
    "realpath": ("/var/jb/usr/bin/realpath", "/var/jb/bin/realpath"),
    "readlink": ("/var/jb/bin/readlink",),
    "xattr": ("/var/jb/usr/bin/xattr",),
}
INVALID_PATH_CHARS = re.compile(r"[*?\[\]{}$`]|\x00")


class HarnessError(RuntimeError):
    """A safe refusal or an invalid evidence artifact."""


class RefusalError(HarnessError):
    """The harness intentionally declined to continue."""


def refuse(message: str) -> None:
    raise RefusalError(message)


def _as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        refuse(f"{label} must be a JSON object")
    return value


def _first(mapping: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return None


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        refuse(f"{label} must be a non-empty string")
    return value


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        refuse(f"{label} must be true or false")
    return value


def _absolute_path(value: str | os.PathLike[str], label: str, *, allow_missing: bool = True) -> Path:
    raw = os.fspath(value)
    if not raw or not os.path.isabs(raw):
        refuse(f"{label} must be an absolute path")
    if INVALID_PATH_CHARS.search(raw) or ".." in Path(raw).parts:
        refuse(f"{label} contains an unsafe path")
    path = Path(raw)
    resolved = path.resolve(strict=False)
    if resolved == Path("/") or resolved == Path.home():
        refuse(f"{label} is a broad or dangerous path")
    if not allow_missing and not path.exists():
        refuse(f"{label} does not exist: {path}")
    return resolved


def _safe_child(root: Path, child: str | os.PathLike[str], label: str) -> Path:
    root = _absolute_path(root, f"{label} root")
    raw = os.fspath(child)
    if os.path.isabs(raw) or INVALID_PATH_CHARS.search(raw) or ".." in Path(raw).parts:
        refuse(f"{label} is not a safe child path")
    result = (root / raw).resolve(strict=False)
    try:
        result.relative_to(root)
    except ValueError:
        refuse(f"{label} escapes its root")
    return result


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_file_preserving_times(path: Path) -> bytes:
    before = os.lstat(path)
    data = path.read_bytes()
    try:
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns), follow_symlinks=False)
    except (OSError, TypeError):
        pass
    return data


def sha256_file(path: str | os.PathLike[str]) -> str:
    if Path(os.fspath(path)).is_symlink():
        refuse("refusing to hash through a symlink")
    source = _absolute_path(path, "file", allow_missing=False)
    if not source.is_file() or source.is_symlink():
        refuse(f"expected a regular file: {source}")
    before = os.lstat(source)
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    # Hashing an installed app must not itself alter the exact timestamp
    # inventory used for restore verification.
    try:
        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns), follow_symlinks=False)
    except (OSError, TypeError):
        pass
    return digest.hexdigest()


def _xattrs(path: Path, *, follow_symlinks: bool = False) -> dict[str, str]:
    if not hasattr(os, "listxattr"):
        return {}
    try:
        names = os.listxattr(path, follow_symlinks=follow_symlinks)
    except (OSError, TypeError):
        return {}
    result: dict[str, str] = {}
    for name in sorted(names):
        try:
            data = os.getxattr(path, name, follow_symlinks=follow_symlinks)
        except (OSError, TypeError):
            continue
        result[name] = base64.b64encode(data).decode("ascii")
    return result


def metadata(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Return metadata which is meaningful for exact restore comparisons."""
    # lstat must see a symlink itself, not the object it points to. Safety is
    # lexical here (unsafe path components were rejected by callers), while
    # inventory_tree separately refuses a symlink as its root.
    raw = os.fspath(path)
    if not os.path.isabs(raw) or INVALID_PATH_CHARS.search(raw) or ".." in Path(raw).parts:
        refuse("metadata path is unsafe")
    source = Path(os.path.abspath(raw))
    if source == Path("/") or source == Path.home():
        refuse("metadata path is broad or dangerous")
    if not source.exists() and not source.is_symlink():
        refuse(f"metadata path does not exist: {source}")
    st = os.lstat(source)
    item: dict[str, Any] = {
        "mode": stat.S_IMODE(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mtime_ns": st.st_mtime_ns,
        "atime_ns": st.st_atime_ns,
        "size": st.st_size,
        "xattrs": _xattrs(source),
        "flags": getattr(st, "st_flags", 0),
        # Read support is enough to prove an empty xattr set. Non-empty sets
        # still require setxattr in _set_metadata before a restore is allowed.
        "xattrs_supported": hasattr(os, "listxattr") and hasattr(os, "getxattr"),
        "flags_supported": hasattr(os, "chflags") or not getattr(st, "st_flags", 0),
    }
    if stat.S_ISLNK(st.st_mode):
        item["type"] = "symlink"
        item["target"] = os.readlink(source)
    elif stat.S_ISREG(st.st_mode):
        item["type"] = "file"
        item["sha256"] = sha256_file(source)
    elif stat.S_ISDIR(st.st_mode):
        item["type"] = "directory"
    else:
        item["type"] = "other"
    return item


def _metadata_equal(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    fields = ("type", "mode", "uid", "gid", "mtime_ns", "atime_ns", "size", "xattrs", "flags", "target", "sha256")
    if left.get("xattrs_supported") is False or right.get("xattrs_supported") is False:
        return False
    if left.get("flags_supported") is False or right.get("flags_supported") is False:
        return False
    return all(left.get(field) == right.get(field) for field in fields if field in left or field in right)


def inventory_tree(root: str | os.PathLike[str]) -> dict[str, dict[str, Any]]:
    """Inventory a tree without following symlinks."""
    raw_root = Path(os.fspath(root))
    if raw_root.is_symlink():
        refuse("inventory root must not be a symlink")
    base = _absolute_path(root, "inventory root", allow_missing=False)
    if not base.is_dir() or base.is_symlink():
        refuse(f"inventory root must be a directory: {base}")
    if base == Path.cwd() or base == Path.home() or base in {Path("/tmp"), Path("/private/tmp")}:
        refuse("inventory root is broad or dangerous")
    paths: list[tuple[str, Path]] = [(".", base)]
    for current, dirs, files in os.walk(base, topdown=True, followlinks=False):
        dirs[:] = sorted(dirs)
        files[:] = sorted(files)
        current_path = Path(current)
        for name in dirs + files:
            path = current_path / name
            relative = path.relative_to(base).as_posix()
            paths.append((relative, path))
    # Directory enumeration and file hashing can update atime on some host
    # filesystems, so collect metadata only after the walk has finished.
    result: dict[str, dict[str, Any]] = {relative: metadata(path) for relative, path in paths}
    return dict(sorted(result.items()))


def inventory_digest(inventory: Mapping[str, Mapping[str, Any]]) -> str:
    wire = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(wire)


def _set_metadata(path: Path, item: Mapping[str, Any], *, follow_symlinks: bool = False) -> None:
    if item.get("xattrs") and (item.get("xattrs_supported") is False or not hasattr(os, "setxattr")):
        refuse("cannot restore unsupported xattrs")
    if item.get("flags_supported") is False and item.get("flags"):
        refuse("cannot restore unsupported file flags")
    if item.get("type") != "symlink":
        try:
            os.chmod(path, int(item["mode"]), follow_symlinks=follow_symlinks)
        except (OSError, TypeError):
            pass
        try:
            if os.geteuid() == 0:
                os.chown(path, int(item["uid"]), int(item["gid"]), follow_symlinks=follow_symlinks)
        except (OSError, TypeError):
            pass
    for name, encoded in item.get("xattrs", {}).items():
        if hasattr(os, "setxattr"):
            try:
                os.setxattr(path, name, base64.b64decode(encoded), follow_symlinks=follow_symlinks)
            except (OSError, TypeError):
                pass
    flags = int(item.get("flags", 0) or 0)
    if flags and hasattr(os, "chflags") and item.get("type") != "symlink":
        try:
            os.chflags(path, flags, follow_symlinks=follow_symlinks)
        except (OSError, TypeError):
            pass
    try:
        os.utime(path, ns=(int(item["atime_ns"]), int(item["mtime_ns"])), follow_symlinks=follow_symlinks)
    except (OSError, TypeError):
        pass


def copy_tree_preserving_metadata(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> dict[str, dict[str, Any]]:
    """Copy one explicitly selected app tree, preserving listed metadata."""
    if Path(os.fspath(source)).is_symlink():
        refuse("app source must not be a symlink")
    source_path = _absolute_path(source, "app source", allow_missing=False)
    destination_path = _absolute_path(destination, "app backup destination")
    if not source_path.is_dir() or source_path.is_symlink():
        refuse("app source must be a real directory")
    if source_path == Path.cwd() or source_path == Path.home() or (source_path.name != "" and not source_path.name.endswith(".app") and not (source_path / "Info.plist").is_file()):
        refuse("app source is not an explicit installed-app bundle")
    if destination_path == source_path:
        refuse("app backup destination must differ from source")
    try:
        destination_path.relative_to(source_path)
    except ValueError:
        pass
    else:
        refuse("app backup destination must not be inside source")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if destination_path.exists() or destination_path.is_symlink():
        refuse(f"refusing to overwrite existing app backup: {destination_path}")
    destination_path.mkdir(mode=0o700)
    source_inventory = inventory_tree(source_path)
    copied_directories: list[tuple[str, dict[str, Any]]] = []
    for relative, item in source_inventory.items():
        if relative == ".":
            continue
        src = source_path / relative
        dst = destination_path / relative
        if item["type"] == "directory":
            dst.mkdir()
            copied_directories.append((relative, item))
        elif item["type"] == "symlink":
            dst.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(item["target"], dst)
        elif item["type"] == "file":
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst, follow_symlinks=False)
        else:
            refuse(f"unsupported app backup entry type at {relative}")
        if item["type"] != "directory":
            _set_metadata(dst, item)
    # Creating children changes directory mtime/atime. Restore directories
    # only after the complete tree exists, deepest-first, then restore root.
    for relative, item in sorted(copied_directories, key=lambda pair: len(Path(pair[0]).parts), reverse=True):
        _set_metadata(destination_path / relative, item)
    _set_metadata(destination_path, source_inventory["."])
    copied = inventory_tree(destination_path)
    if copied != source_inventory:
        refuse("app backup metadata/hash inventory does not match source")
    return copied


def write_json_atomic(path: str | os.PathLike[str], value: Any) -> None:
    target = _absolute_path(path, "JSON destination")
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = target.with_name(f".{target.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def read_json(path: str | os.PathLike[str], label: str = "JSON file") -> dict[str, Any]:
    target = _absolute_path(path, label, allow_missing=False)
    try:
        return _as_dict(json.loads(target.read_text(encoding="utf-8")), label)
    except (OSError, json.JSONDecodeError) as error:
        refuse(f"cannot read {label}: {error}")


def read_structured(path: str | os.PathLike[str], label: str = "configuration") -> dict[str, Any]:
    """Read a JSON or plist object without executing any configuration code."""
    target = _absolute_path(path, label, allow_missing=False)
    try:
        raw = target.read_bytes()
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            value = plistlib.loads(raw)
        return _as_dict(value, label)
    except (OSError, plistlib.InvalidFileException, ValueError) as error:
        refuse(f"cannot read {label}: {error}")


def parse_system_version_plist(data: bytes) -> dict[str, str]:
    """Parse the guest's ProductVersion plist on the host side."""
    try:
        value = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError) as error:
        refuse(f"guest SystemVersion.plist is invalid: {error}")
    plist = _as_dict(value, "guest SystemVersion.plist")
    version = plist.get("ProductVersion")
    build = plist.get("ProductBuildVersion")
    if not isinstance(version, str) or not isinstance(build, str):
        refuse("guest SystemVersion.plist lacks ProductVersion/ProductBuildVersion")
    return {"ios_version": version, "build": build}


def _validate_archive_name(name: str) -> None:
    if not name or name.startswith("/") or "\\" in name:
        refuse(f"theme archive contains unsafe entry: {name!r}")
    parts = Path(name).parts
    if any(part in ("", ".", "..") for part in parts) or ":" in parts[0]:
        refuse(f"theme archive contains traversal entry: {name!r}")


def validate_theme_archive(archive: str | os.PathLike[str], required_entry: str = DEFAULT_THEME_ENTRY) -> dict[str, Any]:
    if Path(os.fspath(archive)).is_symlink():
        refuse("theme archive must not be a symlink")
    path = _absolute_path(archive, "theme archive", allow_missing=False)
    _validate_archive_name(required_entry)
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            names: set[str] = set()
            for info in infos:
                _validate_archive_name(info.filename)
                if info.filename in names:
                    refuse(f"theme archive contains duplicate entry: {info.filename}")
                names.add(info.filename)
            if required_entry not in names:
                refuse(f"theme archive is missing exact entry: {required_entry}")
            selected = zf.getinfo(required_entry)
            if selected.is_dir():
                refuse("required theme entry is a directory")
            data = zf.read(selected)
    except zipfile.BadZipFile as error:
        refuse(f"invalid theme archive: {error}")
    return {"path": str(path), "entry": required_entry, "size": len(data), "sha256": sha256_bytes(data)}


def extract_theme_entry(archive: str | os.PathLike[str], entry: str, destination: str | os.PathLike[str]) -> dict[str, Any]:
    info = validate_theme_archive(archive, entry)
    destination_path = _absolute_path(destination, "staged replacement")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if destination_path.exists() or destination_path.is_symlink():
        refuse(f"refusing to overwrite staged replacement: {destination_path}")
    with zipfile.ZipFile(info["path"]) as zf:
        data = zf.read(entry)
    temporary = destination_path.with_name(f".{destination_path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination_path)
    return {**info, "staged_path": str(destination_path)}


def validate_diagnostic_ipa(path: str | os.PathLike[str] = DEFAULT_DIAGNOSTIC_IPA) -> dict[str, Any]:
    if Path(os.fspath(path)).is_symlink():
        refuse("diagnostic IPA must not be a symlink")
    ipa = _absolute_path(path, "diagnostic IPA", allow_missing=False)
    if ipa.name == PROTECTED_IPA.name or ipa.resolve() == PROTECTED_IPA.resolve():
        refuse("build/Cyanide.ipa is protected; use Cyanide-1.6-spotlight.ipa")
    if ipa.name != DEFAULT_DIAGNOSTIC_IPA.name:
        refuse(f"diagnostic IPA must be named {DEFAULT_DIAGNOSTIC_IPA.name}")
    try:
        with zipfile.ZipFile(ipa) as zf:
            names = set(zf.namelist())
            info_name = "Payload/Cyanide.app/Info.plist"
            if info_name not in names:
                refuse("diagnostic IPA lacks Payload/Cyanide.app/Info.plist")
            info = plistlib.loads(zf.read(info_name))
    except (zipfile.BadZipFile, plistlib.InvalidFileException, KeyError) as error:
        refuse(f"invalid diagnostic IPA: {error}")
    if info.get("CFBundleIdentifier") != EXPECTED_BUNDLE_ID:
        refuse("diagnostic IPA bundle identifier is not the expected Cyanide bundle")
    return {"path": str(ipa), "sha256": sha256_file(ipa), "bundle_id": info["CFBundleIdentifier"]}


@dataclass(frozen=True)
class GuestIdentity:
    udid: str
    ios_version: str
    build: str
    ssh_port: int
    bundle_id: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "GuestIdentity":
        try:
            return cls(
                str(_first(value, "udid", "UDID", "device_udid")),
                str(_first(value, "ios_version", "iOS_version", "iOSVersion", "version", "system_version")),
                str(_first(value, "build", "build_version", "buildVersion", "os_build")),
                int(_first(value, "ssh_port", "sshPort", "port") or 0),
                str(_first(value, "bundle_id", "bundle_identifier", "bundleId", "CFBundleIdentifier")),
            )
        except (AttributeError, TypeError, ValueError) as error:
            refuse(f"guest identity has invalid fields: {error}")

    def as_dict(self) -> dict[str, Any]:
        return {"udid": self.udid, "ios_version": self.ios_version, "build": self.build, "ssh_port": self.ssh_port, "bundle_id": self.bundle_id}


EXPECTED_IDENTITY = GuestIdentity(EXPECTED_UDID, EXPECTED_IOS_VERSION, EXPECTED_BUILD, EXPECTED_SSH_PORT, EXPECTED_BUNDLE_ID)


def _require_macos() -> None:
    if sys.platform != "darwin":
        refuse("Phase 6 harness is macOS-host-only")


def validate_guest_identity(value: Mapping[str, Any] | GuestIdentity) -> dict[str, Any]:
    if not isinstance(value, (Mapping, GuestIdentity)):
        refuse("guest identity must be a JSON object")
    identity = value if isinstance(value, GuestIdentity) else GuestIdentity.from_mapping(value)
    expected = EXPECTED_IDENTITY
    if identity != expected:
        refuse(f"guest identity mismatch/refusal: expected {expected.as_dict()}, got {identity.as_dict()}")
    return identity.as_dict()


def _find_identity(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, dict):
        keys = {str(key).lower() for key in value}
        if {"udid", "build"}.issubset(keys) and ({"ios_version", "iosversion", "version", "system_version"} & keys):
            return value
        for nested in value.values():
            found = _find_identity(nested)
            if found:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = _find_identity(nested)
            if found:
                return found
    return None


def _embedded_machine_ecid(value: Any) -> int:
    """Decode VZMacMachineIdentifier's embedded 68-byte binary plist."""
    if not isinstance(value, (bytes, bytearray)):
        refuse("VM machineIdentifier must be embedded plist bytes")
    if len(value) != 68:
        refuse("VM machineIdentifier is not the expected 68-byte plist")
    try:
        embedded = plistlib.loads(bytes(value))
    except (plistlib.InvalidFileException, ValueError) as error:
        refuse(f"VM machineIdentifier plist is invalid: {error}")
    ecid = _first(_as_dict(embedded, "machineIdentifier plist"), "ECID", "ecid")
    if isinstance(ecid, bool):
        refuse("VM machineIdentifier ECID has invalid type")
    try:
        return int(ecid)
    except (TypeError, ValueError) as error:
        refuse(f"VM machineIdentifier ECID is invalid: {error}")


def _validate_vm_manifest_fields(config_data: Mapping[str, Any], bundle_path: Path) -> dict[str, Any]:
    platform = _first(config_data, "platformType", "platform_type")
    if platform != EXPECTED_PLATFORM_TYPE:
        refuse(f"VM platformType mismatch: expected {EXPECTED_PLATFORM_TYPE}, got {platform!r}")
    machine = _first(config_data, "machineIdentifier", "machine_identifier")
    ecid = _embedded_machine_ecid(machine)
    if ecid != EXPECTED_ECID:
        refuse(f"VM machineIdentifier ECID mismatch: expected {EXPECTED_ECID}, got {ecid}")
    fields = {
        "disk_image": (_first(config_data, "diskImage", "disk_image"), EXPECTED_DISK_IMAGE),
        "nvram_storage": (_first(config_data, "nvramStorage", "nvram_storage"), EXPECTED_NVRAM_STORAGE),
        "sep_storage": (_first(config_data, "sepStorage", "sep_storage"), EXPECTED_SEP_STORAGE),
    }
    for name, (actual, expected) in fields.items():
        if actual != expected:
            refuse(f"VM {name} mismatch: expected {expected}, got {actual!r}")
        if not isinstance(actual, str) or not actual or Path(actual).name != actual or ".." in Path(actual).parts:
            refuse(f"VM {name} is not a narrow bundle-relative filename")
        if not (bundle_path / actual).is_file():
            refuse(f"VM bundle is missing pinned {name} file: {actual}")
    return {"platform_type": platform, "machine_ecid": ecid, **{name: actual for name, (actual, _) in fields.items()}}


def validate_vm_bundle_and_config(bundle: str | os.PathLike[str] | None, config: str | os.PathLike[str] | None, supplied_identity: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not bundle or not config:
        refuse("explicit VM bundle and VM config paths are required")
    bundle_path = _absolute_path(bundle, "VM bundle", allow_missing=False)
    config_path = _absolute_path(config, "VM config", allow_missing=False)
    if not bundle_path.is_dir() or bundle_path.is_symlink():
        refuse("VM bundle must be an existing directory")
    # The real lab bundle is named ``cyanide-ios26-base``; its basename does
    # not contain "vm" or the UDID. Pin the bundle structurally instead of
    # relying on a naming convention: the selected config must be the
    # bundle's own config.plist and the manifest below must name all three
    # required storage files.
    if config_path.parent != bundle_path or config_path.name != "config.plist":
        refuse("VM config must be the selected bundle's own config.plist")
    config_data = read_structured(config_path, "VM config")
    vm_manifest = _validate_vm_manifest_fields(config_data, bundle_path)
    # config.plist intentionally contains no UDID/iOS/build strings on this
    # guest. Require a separate, explicit operator pin for those values;
    # never infer them from an app-container UUID or an IP address.
    if supplied_identity is None:
        refuse("explicit pinned guest identity is required; config machineIdentifier is not a UDID")
    identity = validate_guest_identity(supplied_identity)
    # If the config records a bundle location, it must be the exact path the
    # operator supplied. This catches stale copies which happen to carry the
    # same guest identity metadata.
    for key in ("bundle", "bundle_path", "vm_bundle", "vm_bundle_path", "vmBundle", "vmBundlePath"):
        reference = _first(config_data, key)
        if reference is not None:
            if not isinstance(reference, str) or not reference.startswith("/"):
                refuse(f"VM config {key} must be an absolute pinned path")
            if _absolute_path(reference, f"VM config {key}") != bundle_path:
                refuse("VM bundle argument does not match the pinned config path")
    return {"bundle": str(bundle_path), "config": str(config_path), "identity": identity, "vm_manifest": vm_manifest}


def _checkpoint_metadata_path(path: Path) -> Path:
    if path.is_dir():
        for name in ("checkpoint.json", "metadata.json", "identity.json"):
            candidate = path / name
            if candidate.exists():
                return candidate
    for suffix in (".checkpoint.json", ".metadata.json", ".json"):
        candidate = Path(str(path) + suffix)
        if candidate.exists():
            return candidate
    refuse("cold checkpoint metadata sidecar is missing")


def validate_cold_checkpoint(path: str | os.PathLike[str], identity: Mapping[str, Any] | None = None) -> dict[str, Any]:
    checkpoint = _absolute_path(path, "cold checkpoint", allow_missing=False)
    if not checkpoint.is_dir() and not checkpoint.is_file():
        refuse("cold checkpoint must be an explicitly selected file or directory")
    sidecar = _checkpoint_metadata_path(checkpoint)
    data = read_json(sidecar, "checkpoint metadata")
    if not _bool(_first(data, "verified", "checkpoint_verified"), "checkpoint verified"):
        refuse("checkpoint is not marked verified")
    if not _bool(_first(data, "cold", "cold_full_vm", "full_vm"), "checkpoint cold/full-VM"):
        refuse("checkpoint is not an identity-preserving cold full-VM checkpoint")
    stopped = _first(data, "guest_stopped", "vm_stopped", "stopped")
    if stopped is not True:
        refuse("checkpoint gate requires proof that the guest is stopped")
    disk_open = _first(data, "disk_open", "disk_image_open", "open_handles", "disk_open_handles")
    if disk_open is not False:
        refuse("checkpoint gate requires proof that Disk.img has no open handles")
    if _first(data, "identity_preserved", "preserves_identity") is not True:
        refuse("checkpoint does not prove identity preservation")
    expected_identity = validate_guest_identity(identity or _as_dict(_first(data, "identity", "guest_identity"), "checkpoint identity"))
    checkpoint_digest = None
    if checkpoint.is_file():
        checkpoint_digest = sha256_file(checkpoint)
    return {"path": str(checkpoint), "metadata": str(sidecar), "sha256": checkpoint_digest, "identity": expected_identity, "verified": True}


def validate_app_backup(path: str | os.PathLike[str], identity: Mapping[str, Any] | None = None) -> dict[str, Any]:
    backup = _absolute_path(path, "app backup", allow_missing=False)
    if not backup.is_dir() or backup.is_symlink():
        refuse("app backup must be an explicit directory")
    manifest = backup / "inventory.json"
    if not manifest.is_file():
        refuse("app backup inventory.json is missing")
    data = read_json(manifest, "app backup inventory")
    if data.get("verified") is not True:
        refuse("app backup is not marked verified")
    if data.get("bundle_id") != EXPECTED_BUNDLE_ID:
        refuse("app backup bundle identifier mismatch")
    contents = backup / "contents"
    if not contents.is_dir() or contents.is_symlink():
        refuse("app backup contents directory is missing")
    expected_inventory = data.get("inventory")
    if not isinstance(expected_inventory, dict):
        refuse("app backup inventory has no inventory map")
    actual = inventory_tree(contents)
    if actual != expected_inventory or inventory_digest(actual) != data.get("inventory_sha256"):
        refuse("app backup hash/metadata inventory does not verify")
    return {"path": str(backup), "contents": str(contents), "inventory_sha256": inventory_digest(actual), "verified": True, "bundle_id": data.get("bundle_id", EXPECTED_BUNDLE_ID)}


def create_app_backup(source: str | os.PathLike[str], destination: str | os.PathLike[str], *, bundle_id: str = EXPECTED_BUNDLE_ID) -> dict[str, Any]:
    destination_path = _absolute_path(destination, "app backup destination")
    contents = destination_path / "contents"
    copied = copy_tree_preserving_metadata(source, contents)
    manifest = {"schema": SCHEMA_VERSION, "verified": True, "bundle_id": bundle_id, "inventory": copied, "inventory_sha256": inventory_digest(copied)}
    write_json_atomic(destination_path / "inventory.json", manifest)
    return validate_app_backup(destination_path)


def _normalize_arm(manifest: Mapping[str, Any]) -> dict[str, Any]:
    raw = _first(manifest, "resolved_arm", "resource_arm", "arm")
    if not isinstance(raw, dict):
        refuse("prepared manifest must explicitly name a resolved resource arm")
    kind_raw = _string(_first(raw, "kind", "type"), "resolved arm kind").lower()
    kind = {"redirect": "declaration-redirect", "canonical-declaration-redirect": "declaration-redirect", "declaration": "declaration-redirect"}.get(kind_raw, kind_raw)
    if kind not in VALID_ARMS:
        refuse(f"unsupported or ambiguous resource arm: {kind_raw}")
    resolved_path = _string(_first(raw, "resolved_path", "path", "target"), "resolved arm path")
    if not resolved_path.startswith("/"):
        refuse("resolved arm path must be absolute")
    return {"kind": kind, "path": str(_absolute_path(resolved_path, "resolved arm path")), **{key: value for key, value in raw.items() if key not in ("path", "target", "resolved_path", "kind", "type")}}


def _normalize_mappings(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = _first(manifest, "allowlisted_mapping", "allowlist", "mapping", "mappings")
    if not isinstance(raw, list) or not raw:
        refuse("prepared manifest must contain a non-empty exact mapping allow-list")
    result: list[dict[str, Any]] = []
    for index, entry in enumerate(raw):
        item = _as_dict(entry, f"mapping[{index}]")
        target = _string(_first(item, "target", "target_path", "live_path"), f"mapping[{index}] target")
        replacement = _string(_first(item, "replacement", "replacement_path", "staged_path"), f"mapping[{index}] replacement")
        if not target.startswith("/") or not replacement.startswith("/"):
            refuse(f"mapping[{index}] paths must be absolute")
        target_path = _absolute_path(target, f"mapping[{index}] target")
        replacement_path = _absolute_path(replacement, f"mapping[{index}] replacement")
        if target_path.name == PROTECTED_IPA.name or replacement_path.name == PROTECTED_IPA.name:
            refuse("mapping may not target or replace protected build/Cyanide.ipa")
        original_hash = _first(item, "original_sha256", "original_hash", "sha256")
        if not isinstance(original_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", original_hash):
            refuse(f"mapping[{index}] needs an exact original SHA-256")
        replacement_hash = _first(item, "replacement_sha256", "replacement_hash", "new_sha256")
        if not isinstance(replacement_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", replacement_hash):
            refuse(f"mapping[{index}] needs an exact replacement SHA-256")
        original_metadata = _first(item, "original_metadata", "metadata")
        if not isinstance(original_metadata, dict):
            refuse(f"mapping[{index}] needs original metadata")
        original_exists = item.get("original_exists", True)
        if not isinstance(original_exists, bool):
            refuse(f"mapping[{index}] original_exists must be true or false")
        replacement_metadata = _first(item, "replacement_metadata", "staged_metadata")
        if not original_exists and not isinstance(replacement_metadata, dict):
            refuse(f"mapping[{index}] needs replacement metadata for a newly introduced file")
        result.append({"target": str(target_path), "replacement": str(replacement_path), "original_sha256": original_hash.lower(), "replacement_sha256": replacement_hash.lower(), "original_metadata": copy.deepcopy(original_metadata), "replacement_metadata": copy.deepcopy(replacement_metadata) if isinstance(replacement_metadata, dict) else None, "original_exists": original_exists, "original_file": item.get("original_file")})
    targets = [entry["target"] for entry in result]
    if len(set(targets)) != len(targets):
        refuse("mapping allow-list contains duplicate targets")
    return result


def validate_prepared_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    data = _as_dict(manifest, "prepared manifest")
    if data.get("schema", SCHEMA_VERSION) != SCHEMA_VERSION:
        refuse("unsupported prepared manifest schema")
    identity = validate_guest_identity(_as_dict(_first(data, "identity", "guest_identity"), "manifest identity"))
    arm = _normalize_arm(data)
    mappings = _normalize_mappings(data)
    if data.get("manual_invalidation_acknowledged") is not True:
        refuse("required manual invalidation plan has not been acknowledged")
    recovery = _first(data, "recovery_command", "recovery_commands")
    if not isinstance(recovery, list) or not recovery or not all(isinstance(part, str) and part for part in recovery):
        refuse("prepared manifest needs a generated recovery command")
    return {**data, "schema": SCHEMA_VERSION, "identity": identity, "resolved_arm": arm, "allowlisted_mapping": mappings, "recovery_command": recovery}


class Transport(Protocol):
    def identity(self) -> Mapping[str, Any]: ...
    def resolve(self, path: str) -> str: ...
    def read_bytes(self, path: str) -> bytes: ...
    def stat(self, path: str) -> dict[str, Any]: ...
    def write_temp(self, target: str, data: bytes, item: Mapping[str, Any], token: str) -> str: ...
    def rename(self, source: str, target: str) -> None: ...
    def remove(self, path: str) -> None: ...


class LocalTransport:
    """Offline transport used by tests and explicit local fixture runs."""

    def __init__(self, identity: Mapping[str, Any], *, root: str | os.PathLike[str] | None = None, execute: bool = False):
        self._identity = dict(identity)
        self.root = _absolute_path(root, "local transport root") if root else None
        self.execute = execute

    def _path(self, path: str) -> Path:
        absolute = _absolute_path(path, "transport path")
        if self.root:
            try:
                absolute.relative_to(self.root)
            except ValueError:
                refuse(f"transport path is outside explicit local root: {absolute}")
        return absolute

    def identity(self) -> Mapping[str, Any]:
        return self._identity

    def resolve(self, path: str) -> str:
        target = self._path(path)
        if not target.exists() and not target.is_symlink():
            return str(target)
        return str(target.resolve(strict=True))

    def read_bytes(self, path: str) -> bytes:
        target = self._path(path)
        if not target.is_file() or target.is_symlink():
            refuse(f"transport target is not a regular file: {target}")
        return _read_file_preserving_times(target)

    def stat(self, path: str) -> dict[str, Any]:
        item = metadata(self._path(path))
        # Local fixture transport has no guest xattr tool to probe. An empty
        # fixture file has no xattrs to preserve; keep the explicit remote
        # transport refusal separate from this offline-only convenience.
        if not item.get("xattrs"):
            item["xattrs_supported"] = True
        return item

    def write_temp(self, target: str, data: bytes, item: Mapping[str, Any], token: str) -> str:
        if not self.execute:
            refuse("local transport write requires --execute")
        destination = self._path(target)
        temporary = destination.with_name(f".{destination.name}.{token}.{uuid.uuid4().hex}.tmp")
        if temporary.exists() or temporary.is_symlink():
            refuse("temporary sibling unexpectedly exists")
        temporary.parent.mkdir(parents=True, exist_ok=True)
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _set_metadata(temporary, item)
        if sha256_file(temporary) != sha256_bytes(data):
            refuse("staged temporary hash verification failed")
        return str(temporary)

    def rename(self, source: str, target: str) -> None:
        if not self.execute:
            refuse("local transport rename requires --execute")
        os.replace(self._path(source), self._path(target))

    def remove(self, path: str) -> None:
        if not self.execute:
            refuse("local transport remove requires --execute")
        target = self._path(path)
        if target.is_symlink() or target.is_file():
            target.unlink()
        else:
            refuse("refusing to recursively remove transport path")


class SSHTransport:
    """Narrow SSH transport; it exposes no arbitrary remote command API."""

    def __init__(self, host: str, *, port: int = EXPECTED_SSH_PORT, user: str = "root", execute: bool = False, timeout: float = 30.0, guest_identity: Mapping[str, Any] | None = None, known_hosts: str | os.PathLike[str] = DEFAULT_KNOWN_HOSTS, password: str | None = None):
        if not host or any(char in host for char in " \t\r\n'\";$`(){}[]"):
            refuse("unsafe SSH host")
        if int(port) != EXPECTED_SSH_PORT:
            refuse(f"SSH port must be {EXPECTED_SSH_PORT}")
        if user != "root":
            refuse("SSH transport requires root for exact metadata preservation")
        if guest_identity is None:
            refuse("SSH transport requires explicit pinned guest identity")
        self.host, self.port, self.user, self.execute, self.timeout = host, int(port), user, execute, timeout
        self._guest_identity = validate_guest_identity(guest_identity)
        self.known_hosts = _absolute_path(known_hosts, "SSH known-hosts file")
        self.known_hosts.parent.mkdir(parents=True, exist_ok=True)
        if password is not None and not password:
            refuse("SSH password must not be empty")
        self.password = password
        self._tool_cache: dict[str, str] = {}

    def _ssh(self, command: Sequence[str], *, input_data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        if not all(isinstance(part, str) and part and "\x00" not in part for part in command):
            refuse("invalid deterministic SSH command")
        # OpenSSH joins arguments after the destination with spaces before
        # handing them to the remote login shell. Pass one shell-quoted
        # command string so a stat format or xattr name remains one argument.
        remote_command = shlex.join(command)
        ssh_command = [
            "ssh", "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
            "-p", str(self.port), f"{self.user}@{self.host}", remote_command,
        ]
        environment = None
        if self.password is not None:
            sshpass = shutil.which("sshpass")
            if not sshpass:
                refuse("password-based SSH requires sshpass")
            ssh_command = [sshpass, "-e", *ssh_command]
            environment = dict(os.environ)
            environment["SSHPASS"] = self.password
        return subprocess.run(ssh_command, input=input_data, capture_output=True, timeout=self.timeout, check=False, env=environment)

    def _tool(self, name: str, *, require_gnu: bool = False) -> str:
        """Select one known jb tool, probing candidates without a shell."""
        cache_key = f"{name}:gnu" if require_gnu else name
        if cache_key in self._tool_cache:
            return self._tool_cache[cache_key]
        candidates = REMOTE_TOOL_CANDIDATES.get(name)
        if not candidates:
            refuse(f"no allowlisted guest tool named {name}")
        for candidate in candidates:
            probe_argument = "-h" if name == "xattr" else "--version"
            result = self._ssh([candidate, probe_argument])
            version = (getattr(result, "stdout", b"") or b"") + (getattr(result, "stderr", b"") or b"")
            if result.returncode == 0 and (not require_gnu or b"GNU coreutils" in version or b"coreutils" in version.lower()):
                self._tool_cache[cache_key] = candidate
                return candidate
        flavor = " GNU coreutils" if require_gnu else ""
        refuse(f"none of the allowlisted guest{flavor} {name} tools is available")

    def identity(self) -> Mapping[str, Any]:
        # The guest has no sw_vers/plutil. Identity pinning (UDID, bundle,
        # endpoint) comes from the explicit host-side VM evidence; the guest
        # independently contributes ProductVersion/ProductBuildVersion from
        # its fixed SystemVersion plist.
        cat = self._tool("cat")
        result = self._ssh([cat, "--", REMOTE_SYSTEM_VERSION_PLIST])
        if result.returncode != 0:
            refuse("guest SystemVersion.plist read failed")
        observed_version = parse_system_version_plist(result.stdout)
        observed = dict(self._guest_identity)
        observed.update(observed_version)
        observed["ssh_port"] = self.port
        return observed

    def _remote_path(self, path: str) -> str:
        raw = _string(path, "remote path")
        if not raw.startswith("/") or INVALID_PATH_CHARS.search(raw) or ".." in Path(raw).parts:
            refuse("unsafe remote path")
        return raw

    def resolve(self, path: str) -> str:
        remote = self._remote_path(path)
        try:
            tool = self._tool("realpath")
            result = self._ssh([tool, "--", remote])
        except RefusalError:
            tool = self._tool("readlink")
            result = self._ssh([tool, "-f", "--", remote])
        if result.returncode != 0:
            refuse("remote path could not be resolved")
        resolved = result.stdout.decode().strip()
        if not resolved.startswith("/") or INVALID_PATH_CHARS.search(resolved) or ".." in Path(resolved).parts:
            refuse("remote path resolver returned an unsafe path")
        return resolved

    def read_bytes(self, path: str) -> bytes:
        remote = self._remote_path(path)
        result = self._ssh([self._tool("cat"), "--", remote])
        if result.returncode:
            refuse("remote file read failed")
        return result.stdout

    def stat(self, path: str) -> dict[str, Any]:
        remote = self._remote_path(path)
        result = self._ssh([self._tool("stat", require_gnu=True), "-c", "%f|%a|%u|%g|%s|%X|%Y|%x|%y", "--", remote])
        if result.returncode:
            refuse("remote metadata stat failed")
        fields = result.stdout.decode().strip().split("|")
        if len(fields) != 9:
            refuse("remote metadata stat returned an unexpected format")
        try:
            file_mode, mode_text, uid, gid, size, atime, mtime, atime_text, mtime_text = fields
            mode_bits = int(file_mode, 16)
            mode = int(mode_text, 8)
            uid_i, gid_i, size_i = int(uid), int(gid), int(size)
            atime_fraction = re.search(r"\.(\d{1,9})(?:\s|$)", atime_text)
            mtime_fraction = re.search(r"\.(\d{1,9})(?:\s|$)", mtime_text)
            if not atime_fraction or not mtime_fraction:
                refuse("remote metadata stat did not report nanosecond timestamps")
            atime_ns = int(atime) * 1_000_000_000 + int(atime_fraction.group(1).ljust(9, "0"))
            mtime_ns = int(mtime) * 1_000_000_000 + int(mtime_fraction.group(1).ljust(9, "0"))
        except ValueError as error:
            refuse(f"remote metadata stat was not numeric: {error}")
        file_type = mode_bits & 0o170000
        type_name = {0o100000: "file", 0o040000: "directory", 0o120000: "symlink"}.get(file_type, "other")
        if type_name != "file":
            refuse(f"remote target is not a regular file: {remote}")
        digest_result = self._ssh([self._tool("sha256sum"), "--", remote])
        if digest_result.returncode:
            refuse("remote file hash failed")
        digest = digest_result.stdout.decode().strip().split()
        if not digest or not re.fullmatch(r"[0-9a-fA-F]{64}", digest[0]):
            refuse("remote file hash returned an unexpected format")
        xattr_tool = self._tool("xattr")
        names_result = self._ssh([xattr_tool, "--", remote])
        if names_result.returncode:
            refuse("remote xattr inventory failed")
        xattrs: dict[str, str] = {}
        for name in names_result.stdout.decode().splitlines():
            if not name or "\x00" in name:
                refuse("remote xattr inventory returned an invalid name")
            value_result = self._ssh([xattr_tool, "-px", name, "--", remote])
            if value_result.returncode:
                refuse(f"remote xattr read failed: {name}")
            encoded_hex = re.sub(rb"\s+", b"", value_result.stdout)
            if len(encoded_hex) % 2 or not re.fullmatch(rb"[0-9a-fA-F]*", encoded_hex):
                refuse(f"remote xattr read returned invalid hex: {name}")
            xattrs[name] = base64.b64encode(bytes.fromhex(encoded_hex.decode("ascii"))).decode("ascii")
        # GNU stat does not expose Darwin st_flags. The observed Procursus
        # cp was independently probed on this VM with a non-zero hidden flag
        # and an xattr; --preserve=all carried both to the sibling. The write
        # path always seeds from the live target and reapplies all attributes
        # after tee, so flags are preserved opaquely without guessing a value.
        return {"type": "file", "mode": mode, "uid": uid_i, "gid": gid_i, "size": size_i, "mtime_ns": mtime_ns, "atime_ns": atime_ns, "xattrs": xattrs, "xattrs_supported": True, "flags_supported": True, "flags_preservation": "opaque-cp-preserve-all", "sha256": digest[0].lower()}

    def write_temp(self, target: str, data: bytes, item: Mapping[str, Any], token: str) -> str:
        if not self.execute:
            refuse("SSH write requires --execute")
        if item.get("xattrs_supported") is not True or item.get("flags_supported") is not True:
            refuse("SSH write requires verified xattr and file-flag preservation support")
        remote = self._remote_path(target)
        sibling = posixpath.join(posixpath.dirname(remote), f".{posixpath.basename(remote)}.{token}.{uuid.uuid4().hex}.tmp")
        cp = self._tool("cp", require_gnu=True)
        tee = self._tool("tee")
        # Seed the sibling from the exact target, replace only its bytes, then
        # restore metadata *after* tee. cp --attributes-only is supported by
        # the guest's GNU coreutils and avoids the timestamp regression caused
        # by cp -p before tee alone.
        seed = self._ssh([cp, "--preserve=all", "--", remote, sibling])
        if seed.returncode:
            refuse("remote temporary metadata-preserving seed failed")
        result = self._ssh([tee, "--", sibling], input_data=data)
        if result.returncode:
            refuse("remote temporary write failed")
        restore_metadata = self._ssh([cp, "--attributes-only", "--preserve=all", "--", remote, sibling])
        if restore_metadata.returncode:
            refuse("remote temporary metadata restore failed")
        return sibling

    def rename(self, source: str, target: str) -> None:
        if not self.execute:
            refuse("SSH rename requires --execute")
        result = self._ssh([self._tool("mv"), "-f", "--", self._remote_path(source), self._remote_path(target)])
        if result.returncode:
            refuse("remote atomic rename failed")

    def remove(self, path: str) -> None:
        if not self.execute:
            refuse("SSH remove requires --execute")
        result = self._ssh([self._tool("rm"), "-f", "--", self._remote_path(path)])
        if result.returncode:
            refuse("remote file removal failed")


class Journal:
    STATES = {"new", "prepared", "applying", "applied", "rollback-required", "restoring", "restored", "verified-restored"}
    TRANSITIONS = {
        "new": {"new", "prepared"},
        "prepared": {"prepared", "applying"},
        "applying": {"applying", "applied", "rollback-required"},
        "applied": {"applied", "restoring"},
        "rollback-required": {"rollback-required", "restoring"},
        "restoring": {"restoring", "restored", "rollback-required"},
        "restored": {"restored", "verified-restored"},
        "verified-restored": {"verified-restored"},
    }

    def __init__(self, root: str | os.PathLike[str], *, run_id: str | None = None, data: Mapping[str, Any] | None = None):
        self.root = _absolute_path(root, "evidence run root")
        self.path = self.root / "journal.json"
        self.data: dict[str, Any] = dict(data or {"schema": SCHEMA_VERSION, "run_id": run_id or self.root.name, "state": "new", "events": [], "operations": []})
        if self.data.get("schema") != SCHEMA_VERSION or self.data.get("state") not in self.STATES:
            refuse("journal schema/state is invalid")
        if not isinstance(self.data.get("events"), list) or not isinstance(self.data.get("operations"), list):
            refuse("journal events/operations are invalid")

    @classmethod
    def load(cls, root: str | os.PathLike[str]) -> "Journal":
        base = _absolute_path(root, "evidence run root", allow_missing=False)
        return cls(base, data=read_json(base / "journal.json", "journal"))

    def save(self) -> None:
        if self.data.get("schema") != SCHEMA_VERSION or self.data.get("state") not in self.STATES:
            refuse("journal schema/state is invalid")
        self.root.mkdir(parents=True, exist_ok=True)
        write_json_atomic(self.path, self.data)

    @property
    def state(self) -> str:
        return str(self.data.get("state", ""))

    def transition(self, state: str, **evidence: Any) -> None:
        if state not in self.STATES:
            refuse(f"invalid journal state: {state}")
        if state not in self.TRANSITIONS.get(self.state, set()):
            refuse(f"invalid journal transition {self.state} -> {state}")
        self.data["state"] = state
        event = {"state": state, "time": time.time(), **evidence}
        self.data.setdefault("events", []).append(event)
        self.save()

    def append_operation(self, operation: Mapping[str, Any]) -> None:
        self.data.setdefault("operations", []).append(dict(operation))
        self.save()


def _load_identity_file(path: str | os.PathLike[str] | None) -> dict[str, Any] | None:
    return read_json(path, "guest identity") if path else None


def preflight(*, vm_bundle: str | os.PathLike[str] | None = None, vm_config: str | os.PathLike[str] | None = None, identity: Mapping[str, Any] | None = None, theme_archive: str | os.PathLike[str] = DEFAULT_THEME_ARCHIVE, diagnostic_ipa: str | os.PathLike[str] = DEFAULT_DIAGNOSTIC_IPA, checkpoint: str | os.PathLike[str] | None = None, app_backup: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Run all host-side checks without creating files or contacting a VM."""
    _require_macos()
    report: dict[str, Any] = {"host": {"platform": sys.platform, "ok": True}, "checks": {}}
    report["checks"]["vm"] = validate_vm_bundle_and_config(vm_bundle, vm_config, identity)
    report["checks"]["theme"] = validate_theme_archive(theme_archive)
    report["checks"]["ipa"] = validate_diagnostic_ipa(diagnostic_ipa)
    guest_identity = report["checks"]["vm"]["identity"]
    if checkpoint:
        report["checks"]["checkpoint"] = validate_cold_checkpoint(checkpoint, guest_identity)
    if app_backup:
        report["checks"]["app_backup"] = validate_app_backup(app_backup, guest_identity)
    report["ok"] = True
    return report


def _read_replacement(mapping: Mapping[str, Any]) -> bytes:
    if Path(os.fspath(mapping["replacement"])).is_symlink():
        refuse("staged replacement must not be a symlink")
    path = _absolute_path(mapping["replacement"], "replacement", allow_missing=False)
    data = path.read_bytes()
    if sha256_bytes(data) != mapping["replacement_sha256"]:
        refuse(f"staged replacement hash changed: {path}")
    return data


def prepare(*, run_root: str | os.PathLike[str], manifest: Mapping[str, Any], vm_bundle: str | os.PathLike[str] | None, vm_config: str | os.PathLike[str] | None, identity: Mapping[str, Any] | None, theme_archive: str | os.PathLike[str], diagnostic_ipa: str | os.PathLike[str], checkpoint: str | os.PathLike[str], app_backup: str | os.PathLike[str], transport: Transport | None = None, dry_run: bool = False) -> dict[str, Any]:
    """Validate and durably stage an explicit manifest; never writes the VM."""
    _require_macos()
    normalized = validate_prepared_manifest(manifest)
    report = preflight(vm_bundle=vm_bundle, vm_config=vm_config, identity=identity, theme_archive=theme_archive, diagnostic_ipa=diagnostic_ipa, checkpoint=checkpoint, app_backup=app_backup)
    validate_guest_identity(normalized["identity"])
    if normalized["identity"] != report["checks"]["vm"]["identity"]:
        refuse("manifest identity differs from current preflight identity")
    if transport is not None and _transport_identity(transport) != normalized["identity"]:
        refuse("manifest identity differs from transport identity")
    checkpoint_info = report["checks"]["checkpoint"]
    backup_info = report["checks"]["app_backup"]
    for index, mapping in enumerate(normalized["allowlisted_mapping"]):
        replacement = _read_replacement(mapping)
        if sha256_bytes(replacement) != mapping["replacement_sha256"]:
            refuse(f"replacement {index} hash changed")
        if mapping.get("original_exists", True):
            if transport is not None:
                current = transport.stat(mapping["target"])
            else:
                if not Path(mapping["target"]).exists():
                    refuse(f"prepared target is missing: {mapping['target']}")
                current = metadata(mapping["target"])
            if not current.get("xattrs") and not mapping["original_metadata"].get("xattrs"):
                current["xattrs_supported"] = mapping["original_metadata"].get("xattrs_supported", current.get("xattrs_supported"))
            if current.get("sha256") != mapping["original_sha256"] or not _metadata_equal(current, mapping["original_metadata"]):
                refuse(f"prepared target does not match declared original: {mapping['target']}")
        elif transport is not None:
            try:
                transport.stat(mapping["target"])
            except (HarnessError, FileNotFoundError, OSError):
                pass
            else:
                refuse(f"prepared newly introduced target already exists: {mapping['target']}")
    if dry_run:
        return {"dry_run": True, "manifest": normalized, "preflight": report}
    run = Journal(run_root, run_id=str(manifest.get("run_id") or Path(run_root).name))
    if run.path.exists():
        refuse("refusing to replace an existing evidence journal")
    run.root.mkdir(parents=True, exist_ok=True)
    originals_dir = run.root / "originals"
    originals_dir.mkdir(mode=0o700, exist_ok=True)
    # Keep exact bytes in this evidence run. This is deliberately a narrow
    # per-target capture rather than a recursive copy of a guessed path.
    for index, mapping in enumerate(normalized["allowlisted_mapping"]):
        if not mapping.get("original_exists", True):
            continue
        target = Path(mapping["target"])
        original_file = originals_dir / f"target-{index:03d}.bin"
        if transport is not None:
            data = transport.read_bytes(mapping["target"])
        elif target.is_file() and not target.is_symlink():
            data = _read_file_preserving_times(target)
        else:
            refuse(f"cannot capture original bytes for {mapping['target']}")
        if sha256_bytes(data) != mapping["original_sha256"]:
            refuse(f"original bytes changed while preparing: {mapping['target']}")
        with original_file.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        mapping["original_file"] = str(original_file)
    normalized["preflight"] = report
    normalized["theme_archive"] = report["checks"]["theme"]
    normalized["diagnostic_ipa"] = report["checks"]["ipa"]
    normalized["checkpoint"] = checkpoint_info
    normalized["app_backup"] = backup_info
    normalized["prepared_at"] = time.time()
    run.data["manifest"] = normalized
    run.data["manual_invalidation_required"] = ["LaunchServices equivalent invalidation", "IconServices equivalent invalidation", "Spotlight equivalent invalidation"]
    run.save()
    run.transition("prepared", checkpoint_verified=True, app_backup_verified=True, resource_arm=normalized["resolved_arm"]["kind"])
    return run.data


def _transport_identity(transport: Transport) -> dict[str, Any]:
    return validate_guest_identity(transport.identity())


def _manifest_current(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return validate_prepared_manifest(manifest)


def apply(*, run_root: str | os.PathLike[str], transport: Transport, execute: bool = False, confirmation: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    _require_macos()
    run = Journal.load(run_root)
    if run.state != "prepared":
        refuse(f"apply requires prepared journal, found {run.state}")
    manifest = _manifest_current(_as_dict(run.data.get("manifest"), "journal manifest"))
    _transport_identity(transport)
    if not execute or confirmation != CONFIRM_TOKEN:
        refuse(f"apply is visibly opt-in: pass --execute and --confirm {CONFIRM_TOKEN}")
    if dry_run:
        return {"dry_run": True, "state": run.state, "targets": [item["target"] for item in manifest["allowlisted_mapping"]]}
    operations = run.data.setdefault("operations", [])
    # Verify immutable evidence before entering the write transaction. A
    # changed gate leaves the run prepared and retryable, rather than making a
    # rollback-required state for an operation which never started.
    checkpoint_info = manifest.get("checkpoint")
    backup_info = manifest.get("app_backup")
    if not isinstance(checkpoint_info, dict) or checkpoint_info.get("verified") is not True:
        refuse("apply requires a verified cold checkpoint in the prepared journal")
    if not isinstance(backup_info, dict) or backup_info.get("verified") is not True:
        refuse("apply requires a verified app backup in the prepared journal")
    if not Path(str(backup_info.get("path", ""))).is_dir():
        refuse("prepared app backup path is no longer available")
    validate_cold_checkpoint(str(checkpoint_info.get("path", "")), manifest["identity"])
    validate_app_backup(str(backup_info.get("path", "")), manifest["identity"])
    try:
        # Every gate is checked immediately before the first write.
        for index, mapping in enumerate(manifest["allowlisted_mapping"]):
            resolved = transport.resolve(mapping["target"])
            if resolved != mapping["target"]:
                refuse(f"live target re-resolution changed target: {mapping['target']} -> {resolved}")
            if not mapping.get("original_exists", True):
                try:
                    transport.stat(mapping["target"])
                except (HarnessError, FileNotFoundError, OSError):
                    pass
                else:
                    refuse(f"newly introduced target unexpectedly exists: {mapping['target']}")
                _read_replacement(mapping)
                continue
            current = transport.stat(mapping["target"])
            if current.get("sha256") != mapping["original_sha256"] or not _metadata_equal(current, mapping["original_metadata"]):
                refuse(f"live original hash/metadata changed: {mapping['target']}")
            data = _read_replacement(mapping)
            if sha256_bytes(data) != mapping["replacement_sha256"]:
                refuse("replacement readback hash mismatch")
        run.transition("applying", first_guest_write=True, recovery_command=manifest["recovery_command"])
    except BaseException as error:
        # No guest write has happened if a gate failed above. Leave the
        # prepared journal intact so the operator can inspect and retry.
        if run.state == "applying":
            try:
                run.transition("rollback-required", error=f"{type(error).__name__}: {error}", writes=len(operations))
            except BaseException:
                pass
        raise
    try:
        for index, mapping in enumerate(manifest["allowlisted_mapping"]):
            data = _read_replacement(mapping)
            staged_metadata = mapping.get("replacement_metadata") or mapping["original_metadata"]
            temporary = transport.write_temp(mapping["target"], data, staged_metadata, f"phase6-{run.data['run_id']}-{index}")
            operation = {"target": mapping["target"], "temporary": temporary, "replacement_sha256": mapping["replacement_sha256"], "original_sha256": mapping["original_sha256"], "original_metadata": mapping["original_metadata"], "original_exists": mapping.get("original_exists", True), "renamed": False, "temporary_hash_verified": False}
            # Journal the temporary path before reading it back. If the
            # process is interrupted in the readback window, restore can
            # remove exactly this sibling and nothing broader.
            operations.append(operation)
            run.save()
            if sha256_bytes(transport.read_bytes(temporary)) != mapping["replacement_sha256"]:
                refuse(f"temporary readback hash mismatch: {temporary}")
            operation["temporary_hash_verified"] = True
            run.save()
            transport.rename(temporary, mapping["target"])
            operation["renamed"] = True
            run.save()
        run.transition("applied", writes=len(operations), manual_invalidation_required=True)
    except BaseException as error:
        # KeyboardInterrupt and process-level interruptions are deliberately
        # journaled as rollback-required; the operator can safely resume.
        try:
            run.transition("rollback-required", error=f"{type(error).__name__}: {error}", writes=len(operations))
        except BaseException:
            pass
        raise
    return run.data


def _original_bytes(run: Journal, mapping: Mapping[str, Any]) -> bytes:
    path = mapping.get("original_file")
    if not path:
        refuse(f"journal lacks original bytes for {mapping['target']}")
    original = _absolute_path(path, "journal original", allow_missing=False)
    data = original.read_bytes()
    if sha256_bytes(data) != mapping["original_sha256"]:
        refuse(f"journal original bytes changed: {original}")
    return data


def restore(*, run_root: str | os.PathLike[str], transport: Transport, execute: bool = False, confirmation: str | None = None, dry_run: bool = False, operator_evidence: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    _require_macos()
    run = Journal.load(run_root)
    if run.state in {"restored", "verified-restored"}:
        return run.data
    if run.state not in {"applied", "rollback-required", "restoring"}:
        refuse(f"restore requires applied or rollback-required journal, found {run.state}")
    manifest = _manifest_current(_as_dict(run.data.get("manifest"), "journal manifest"))
    _transport_identity(transport)
    if not execute or confirmation != CONFIRM_TOKEN:
        refuse(f"restore is visibly opt-in: pass --execute and --confirm {CONFIRM_TOKEN}")
    if dry_run:
        return {"dry_run": True, "state": run.state, "targets": [item["target"] for item in manifest["allowlisted_mapping"]]}
    try:
        run.transition("restoring", recovery_command=manifest["recovery_command"])
        # A crash can leave a staged sibling after it has been journaled but
        # before readback/rename. Remove only those exact journaled paths.
        for operation in run.data.get("operations", []):
            if not isinstance(operation, dict) or operation.get("renamed"):
                continue
            temporary = operation.get("temporary")
            if not isinstance(temporary, str):
                continue
            try:
                transport.remove(temporary)
            except (HarnessError, FileNotFoundError, OSError):
                pass
        for mapping in manifest["allowlisted_mapping"]:
            target = mapping["target"]
            resolved = transport.resolve(target)
            if resolved != target:
                refuse(f"restore target re-resolution changed target: {target} -> {resolved}")
            exists = True
            try:
                current = transport.stat(target)
            except (HarnessError, FileNotFoundError, OSError):
                exists = False
                current = {}
            if not mapping.get("original_exists", True):
                if exists:
                    if current.get("sha256") != mapping["replacement_sha256"]:
                        refuse(f"refusing to remove unexpected newly introduced file: {target}")
                    transport.remove(target)
                continue
            if not exists:
                # A missing original can only be repaired from the journal;
                # write_temp remains atomic and metadata-preserving.
                pass
            elif current.get("sha256") == mapping["original_sha256"] and _metadata_equal(current, mapping["original_metadata"]):
                continue  # already restored: idempotent path
            elif current.get("sha256") != mapping["replacement_sha256"]:
                refuse(f"refusing to overwrite unexpected restore target: {target}")
            data = _original_bytes(run, mapping)
            temporary = transport.write_temp(target, data, mapping["original_metadata"], f"restore-{run.data['run_id']}")
            if sha256_bytes(transport.read_bytes(temporary)) != mapping["original_sha256"]:
                refuse(f"restore temporary hash mismatch: {temporary}")
            transport.rename(temporary, target)
        evidence = str(operator_evidence) if operator_evidence else None
        run.data["operator_invalidation_evidence"] = evidence
        run.transition("restored", manual_invalidation_required=True, operator_evidence=evidence)
    except BaseException as error:
        try:
            run.transition("rollback-required", error=f"{type(error).__name__}: {error}")
        except BaseException:
            pass
        raise
    return run.data


def verify_restored(*, run_root: str | os.PathLike[str], transport: Transport, operator_evidence: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    _require_macos()
    run = Journal.load(run_root)
    if run.state not in {"restored", "verified-restored"}:
        refuse(f"verify-restored requires restored journal, found {run.state}")
    manifest = _manifest_current(_as_dict(run.data.get("manifest"), "journal manifest"))
    _transport_identity(transport)
    for mapping in manifest["allowlisted_mapping"]:
        target = mapping["target"]
        if mapping.get("original_exists", True):
            current = transport.stat(target)
            if current.get("sha256") != mapping["original_sha256"] or not _metadata_equal(current, mapping["original_metadata"]):
                refuse(f"restored target does not match original: {target}")
        else:
            try:
                transport.stat(target)
            except (HarnessError, FileNotFoundError, OSError):
                continue
            refuse(f"newly introduced target remains present: {target}")
    evidence_value = operator_evidence or run.data.get("operator_invalidation_evidence")
    if not evidence_value:
        refuse("operator evidence for equivalent LS/IconServices/Spotlight invalidation is required")
    evidence = _absolute_path(evidence_value, "operator evidence", allow_missing=False)
    if not evidence.is_file():
        refuse("operator evidence must be a file")
    data = dict(run.data)
    data["operator_invalidation_evidence"] = str(evidence)
    if run.state != "verified-restored":
        run.data = data
        run.transition("verified-restored", files_verified=True, operator_evidence=str(evidence))
    return run.data


def status(*, run_root: str | os.PathLike[str]) -> dict[str, Any]:
    run = Journal.load(run_root)
    return {"run_id": run.data.get("run_id"), "state": run.state, "events": run.data.get("events", []), "operations": run.data.get("operations", []), "manual_invalidation_required": run.data.get("manual_invalidation_required", [])}


# Stable, descriptive aliases make the small library convenient to exercise
# from offline test harnesses without changing the CLI vocabulary.
validate_manifest = validate_prepared_manifest
validate_archive = validate_theme_archive
load_journal = Journal.load
run_preflight = preflight
prepare_run = prepare
apply_run = apply
restore_run = restore
verify_restore = verify_restored


def _add_post_action_scope_options(parser: argparse.ArgumentParser) -> None:
    """Permit the read-only scope options after a subcommand too."""
    suppressed = argparse.SUPPRESS
    parser.add_argument("--root", "--evidence-root", "--journal-root", dest="root", default=suppressed)
    parser.add_argument("--run-id", dest="run_id", default=suppressed)
    parser.add_argument("--config", dest="config", default=suppressed)
    parser.add_argument("--vm-bundle", dest="vm_bundle", default=suppressed)
    parser.add_argument("--vm-config", dest="vm_config", default=suppressed)
    parser.add_argument("--identity-file", dest="identity_file", default=suppressed)
    parser.add_argument("--checkpoint", "--checkpoint-path", dest="checkpoint", default=suppressed)
    parser.add_argument("--app-backup", "--app-backup-path", dest="app_backup", default=suppressed)
    parser.add_argument("--theme", "--theme-archive", dest="theme", default=suppressed)
    parser.add_argument("--ipa", "--diagnostic-ipa", dest="ipa", default=suppressed)
    parser.add_argument("--json", action="store_true", default=suppressed)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", "--evidence-root", "--journal-root", dest="root", default=None, help=f"evidence run directory (default: {DEFAULT_EVIDENCE_ROOT}/<run-id>)")
    parser.add_argument("--run-id", help="run identifier when --root is omitted")
    parser.add_argument("--config", help="JSON/plist containing VM path and/or identity pins")
    parser.add_argument("--vm-bundle", help="explicit vphone VM bundle directory")
    parser.add_argument("--vm-config", help="explicit vphone VM config JSON")
    parser.add_argument("--identity-file", help="JSON file with pinned guest identity")
    parser.add_argument("--checkpoint", "--checkpoint-path", dest="checkpoint", help="explicit verified cold full-VM checkpoint")
    parser.add_argument("--app-backup", "--app-backup-path", dest="app_backup", help="explicit verified installed-app backup")
    parser.add_argument("--theme", "--theme-archive", dest="theme", default=str(DEFAULT_THEME_ARCHIVE), help="theme archive")
    parser.add_argument("--ipa", "--diagnostic-ipa", dest="ipa", default=str(DEFAULT_DIAGNOSTIC_IPA), help="diagnostic IPA (never build/Cyanide.ipa)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    sub = parser.add_subparsers(dest="action", required=True)
    preflight_parser = sub.add_parser("preflight", help="read-only host and identity checks")
    _add_post_action_scope_options(preflight_parser)
    prep = sub.add_parser("prepare", help="validate manifest/checkpoint/backup and journal prepared state")
    _add_post_action_scope_options(prep)
    prep.add_argument("--manifest", required=True)
    prep.add_argument("--dry-run", action="store_true")
    prep.add_argument("--host", help="SSH host for narrow read-only target capture")
    prep.add_argument("--port", type=int, default=EXPECTED_SSH_PORT)
    prep.add_argument("--known-hosts", default=str(DEFAULT_KNOWN_HOSTS), help="dedicated SSH known-hosts file")
    prep.add_argument("--ssh-password-env", help="environment variable containing the SSH password")
    prep.add_argument("--local-identity", help="identity JSON for an explicitly local fixture transport")
    prep.add_argument("--local-root", help="explicit local fixture root; no VM contact")
    for name in ("apply", "restore"):
        operation = sub.add_parser(name, help=f"guarded {name} with an explicit SSH/local transport opt-in")
        _add_post_action_scope_options(operation)
        operation.add_argument("--execute", action="store_true")
        operation.add_argument("--confirm", default=None)
        operation.add_argument("--dry-run", action="store_true")
        operation.add_argument("--host", help="SSH host (root only)")
        operation.add_argument("--port", type=int, default=EXPECTED_SSH_PORT)
        operation.add_argument("--known-hosts", default=str(DEFAULT_KNOWN_HOSTS), help="dedicated SSH known-hosts file")
        operation.add_argument("--ssh-password-env", help="environment variable containing the SSH password")
        operation.add_argument("--local-identity", help="identity JSON for an explicitly local fixture transport")
        operation.add_argument("--local-root", help="explicit local fixture root; no VM contact")
        operation.add_argument("--operator-evidence", help="operator evidence file recorded during restore")
    status_parser = sub.add_parser("status", help="show durable journal state")
    _add_post_action_scope_options(status_parser)
    verify = sub.add_parser("verify-restored", help="verify exact original files and operator invalidation evidence")
    verify.add_argument("--host", help="SSH host (root only)")
    verify.add_argument("--port", type=int, default=EXPECTED_SSH_PORT)
    verify.add_argument("--known-hosts", default=str(DEFAULT_KNOWN_HOSTS), help="dedicated SSH known-hosts file")
    verify.add_argument("--ssh-password-env", help="environment variable containing the SSH password")
    verify.add_argument("--local-identity", help="identity JSON for an explicitly local fixture transport")
    verify.add_argument("--local-root", help="explicit local fixture root; no VM contact")
    verify.add_argument("--operator-evidence")
    _add_post_action_scope_options(verify)
    return parser


def _run_root(args: argparse.Namespace) -> Path:
    if args.root:
        return _absolute_path(args.root, "evidence run root")
    if not args.run_id or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,80}", args.run_id):
        refuse("--run-id is required when --root is omitted and must be a simple identifier")
    return _safe_child(DEFAULT_EVIDENCE_ROOT, args.run_id, "run id")


def _transport_from_args(args: argparse.Namespace, *, execute: bool, guest_identity: Mapping[str, Any] | None = None) -> Transport:
    identity_path = getattr(args, "local_identity", None)
    local_root = getattr(args, "local_root", None)
    if bool(identity_path) != bool(local_root):
        refuse("local transport requires both --local-root and --local-identity")
    if identity_path and local_root:
        return LocalTransport(validate_guest_identity(read_json(identity_path, "local identity")), root=local_root, execute=execute)
    host = getattr(args, "host", None)
    if not host:
        refuse("live actions require --host or an explicit local fixture transport")
    password_env_name = getattr(args, "ssh_password_env", None)
    password = None
    if password_env_name:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", password_env_name):
            refuse("--ssh-password-env must be a valid environment variable name")
        password = os.environ.get(password_env_name)
        if not password:
            refuse(f"SSH password environment variable is missing or empty: {password_env_name}")
    return SSHTransport(host, port=getattr(args, "port", EXPECTED_SSH_PORT), execute=execute, guest_identity=guest_identity, known_hosts=getattr(args, "known_hosts", DEFAULT_KNOWN_HOSTS), password=password)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        config_data = read_structured(args.config, "lab config") if args.config else {}
        root = _run_root(args)
        identity = _load_identity_file(args.identity_file)
        if identity is None:
            candidate_identity = _first(config_data, "identity", "guest_identity")
            identity = candidate_identity if isinstance(candidate_identity, dict) else None
        vm_bundle = args.vm_bundle or _first(config_data, "vm_bundle", "vm_bundle_path", "vmBundle", "vmBundlePath", "bundle", "bundle_path")
        vm_config = args.vm_config or _first(config_data, "vm_config", "vm_config_path", "vmConfig", "vmConfigPath", "config_path")
        if vm_config is None and args.config:
            vm_config = args.config
        if args.action == "preflight":
            result = preflight(vm_bundle=vm_bundle, vm_config=vm_config, identity=identity, theme_archive=args.theme, diagnostic_ipa=args.ipa, checkpoint=args.checkpoint, app_backup=args.app_backup)
        elif args.action == "prepare":
            if not args.checkpoint or not args.app_backup or not vm_bundle or not vm_config:
                refuse("prepare requires explicit VM bundle/config, cold checkpoint, and app backup")
            prepare_transport = _transport_from_args(args, execute=False, guest_identity=identity) if (args.host or args.local_root or args.local_identity) else None
            result = prepare(run_root=root, manifest=read_json(args.manifest, "prepared manifest"), vm_bundle=vm_bundle, vm_config=vm_config, identity=identity, theme_archive=args.theme, diagnostic_ipa=args.ipa, checkpoint=args.checkpoint, app_backup=args.app_backup, transport=prepare_transport, dry_run=args.dry_run)
        elif args.action == "status":
            result = status(run_root=root)
        elif args.action in {"apply", "restore"}:
            transport = _transport_from_args(args, execute=args.execute and not args.dry_run, guest_identity=identity)
            if args.action == "apply":
                result = apply(run_root=root, transport=transport, execute=args.execute, confirmation=args.confirm, dry_run=args.dry_run)
            else:
                result = restore(run_root=root, transport=transport, execute=args.execute, confirmation=args.confirm, dry_run=args.dry_run, operator_evidence=args.operator_evidence)
        elif args.action == "verify-restored":
            result = verify_restored(run_root=root, transport=_transport_from_args(args, execute=False, guest_identity=identity), operator_evidence=args.operator_evidence)
        else:
            refuse(f"unsupported action: {args.action}")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (HarnessError, OSError, ValueError, zipfile.BadZipFile) as error:
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "error": str(error)}, indent=2, sort_keys=True))
        else:
            print(f"refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
