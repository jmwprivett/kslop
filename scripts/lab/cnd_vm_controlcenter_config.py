#!/usr/bin/env python3
"""Safely add the Pulsar tracing controls to an iOS 26 vPhone Control Center.

The iOS 26 control gallery can dismiss itself on the vPhone before presenting
its picker.  This VM-only helper updates the same two mobile-owned plists that
SpringBoard uses, after making timestamped adjacent backups, and then performs
an identity-checked SpringBoard restart.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
import plistlib
import re
import shlex
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cnd_remotecall_lab import (
    DEFAULT_KNOWN_HOSTS,
    LabError,
    SSH,
    TARGETS,
    require_vphone,
    resolve_target,
)


CONTROL_CENTER_DIR = "/var/mobile/Library/ControlCenter"
ICON_STATE_PATH = f"{CONTROL_CENTER_DIR}/ControlsIconState.plist"
MODULE_CONFIGURATION_PATH = f"{CONTROL_CENTER_DIR}/ModuleConfiguration.plist"
MANAGED_PATHS = (ICON_STATE_PATH, MODULE_CONFIGURATION_PATH)
BACKUP_STAMP_PATTERN = re.compile(r"[0-9]{8}T[0-9]{6}Z")
IDENTIFIER_NAMESPACE = uuid.UUID("5a93a5ec-e171-4e27-bae0-f7738b6eb6ed")


@dataclass(frozen=True)
class ControlSpec:
    label: str
    module_identifier: str

    def stable_uuid(self, role: str) -> str:
        value = uuid.uuid5(
            IDENTIFIER_NAMESPACE,
            f"cyanide-vphone-control-center:{self.module_identifier}:{role}",
        )
        return str(value).upper()


CONTROL_SPECS = (
    ControlSpec("Low Power Mode", "com.apple.control-center.LowPowerModule"),
    ControlSpec(
        "Screen Recording",
        "com.apple.replaykit.controlcenter.screencapture",
    ),
    ControlSpec("Flashlight", "com.apple.control-center.FlashlightModule"),
)
PERSISTENT_CONTROL_SPECS = CONTROL_SPECS[:2]
DEVICE_GATED_CONTROL_SPECS = CONTROL_SPECS[2:]


def load_plist(data: bytes, path: str) -> dict[str, object]:
    try:
        value = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError) as error:
        raise LabError(f"invalid plist at {path}: {error}") from error
    if not isinstance(value, dict):
        raise LabError(f"expected dictionary plist at {path}")
    return value


def dump_plist(value: dict[str, object]) -> bytes:
    return plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False)


def module_identifiers(icon_state: dict[str, object]) -> set[str]:
    identifiers: set[str] = set()
    icon_lists = icon_state.get("iconLists")
    if not isinstance(icon_lists, list):
        raise LabError("ControlsIconState iconLists is not an array")
    for page in icon_lists:
        if not isinstance(page, list):
            raise LabError("ControlsIconState page is not an array")
        for item in page:
            if not isinstance(item, dict):
                continue
            elements = item.get("elements")
            if not isinstance(elements, list):
                continue
            for element in elements:
                if not isinstance(element, dict):
                    continue
                identifier = element.get("moduleIdentifier")
                if isinstance(identifier, str):
                    identifiers.add(identifier)
    return identifiers


def add_controls_to_icon_state(
    original: dict[str, object],
) -> tuple[dict[str, object], tuple[ControlSpec, ...]]:
    state = copy.deepcopy(original)
    icon_lists = state.get("iconLists")
    list_identifiers = state.get("listUniqueIdentifiers")
    metadata = state.get("listMetadata")
    if not isinstance(icon_lists, list) or not icon_lists:
        raise LabError("ControlsIconState has no primary icon list")
    if not isinstance(icon_lists[0], list):
        raise LabError("ControlsIconState primary icon list is invalid")
    if not isinstance(list_identifiers, list) or not list_identifiers or not isinstance(
        list_identifiers[0], str
    ):
        raise LabError("ControlsIconState has no primary list identifier")
    if not isinstance(metadata, dict):
        raise LabError("ControlsIconState listMetadata is invalid")
    primary_metadata = metadata.get(list_identifiers[0])
    if not isinstance(primary_metadata, dict):
        raise LabError("ControlsIconState primary list metadata is missing")
    rotated_order = primary_metadata.get("rotatedOrder")
    if not isinstance(rotated_order, list):
        raise LabError("ControlsIconState primary rotatedOrder is invalid")

    existing = module_identifiers(state)
    added: list[ControlSpec] = []
    for spec in CONTROL_SPECS:
        if spec.module_identifier in existing:
            continue
        display_identifier = spec.stable_uuid("display")
        icon_lists[0].append(
            {
                "allowsExternalSuggestions": True,
                "allowsSuggestions": True,
                "displayIdentifier": display_identifier,
                "elements": [
                    {
                        "containerBundleIdentifier": "com.apple.springboard",
                        "dataSourceUniqueIdentifier": spec.stable_uuid("data-source"),
                        "elementType": "module",
                        "moduleIdentifier": spec.module_identifier,
                    }
                ],
                "gridSize": "small",
                "iconType": "custom",
            }
        )
        rotated_order.append(display_identifier)
        existing.add(spec.module_identifier)
        added.append(spec)
    return state, tuple(added)


def add_controls_to_module_configuration(
    original: dict[str, object],
) -> dict[str, object]:
    configuration = copy.deepcopy(original)
    identifiers = configuration.get("module-identifiers")
    if not isinstance(identifiers, list) or not all(
        isinstance(item, str) for item in identifiers
    ):
        raise LabError("ModuleConfiguration module-identifiers is invalid")
    for spec in CONTROL_SPECS:
        if spec.module_identifier not in identifiers:
            identifiers.append(spec.module_identifier)
    return configuration


def backup_path(path: str, stamp: str) -> str:
    if path not in MANAGED_PATHS or not BACKUP_STAMP_PATTERN.fullmatch(stamp):
        raise LabError("refusing invalid Control Center backup target")
    return f"{path}.cyanide-backup-{stamp}"


def staged_path(path: str, digest: str) -> str:
    if path not in MANAGED_PATHS or not re.fullmatch(r"[0-9a-f]{16}", digest):
        raise LabError("refusing invalid Control Center staging target")
    name = Path(path).name
    return f"{CONTROL_CENTER_DIR}/.cyanide-{name}-{digest}.tmp"


def upload_bytes(ssh: SSH, data: bytes, remote_path: str) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix="cyanide-vm-controlcenter-", suffix=".plist",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
        ssh.copy(temporary, remote_path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def install_plists(
    ssh: SSH,
    replacements: dict[str, bytes],
    stamp: str,
) -> dict[str, str]:
    if set(replacements) != set(MANAGED_PATHS):
        raise LabError("refusing incomplete Control Center configuration update")

    staged: dict[str, str] = {}
    backups: dict[str, str] = {}
    try:
        for target in MANAGED_PATHS:
            digest = hashlib.sha256(replacements[target]).hexdigest()[:16]
            remote_staged = staged_path(target, digest)
            staged[target] = remote_staged
            upload_bytes(ssh, replacements[target], remote_staged)
            observed = ssh.command(
                f"/var/jb/usr/bin/sha256sum {shlex.quote(remote_staged)}"
            ).split()[0]
            expected = hashlib.sha256(replacements[target]).hexdigest()
            if observed != expected:
                raise LabError(f"staged plist digest mismatch for {target}")
            backups[target] = backup_path(target, stamp)

        target_checks = " && ".join(
            f"test -f {shlex.quote(path)} && test ! -L {shlex.quote(path)}"
            for path in MANAGED_PATHS
        )
        backup_checks = " && ".join(
            f"test ! -e {shlex.quote(backups[path])}"
            for path in MANAGED_PATHS
        )
        backup_commands = " && ".join(
            f"/var/jb/bin/cp -p {shlex.quote(path)} "
            f"{shlex.quote(backups[path])}"
            for path in MANAGED_PATHS
        )
        install_commands = " && ".join(
            f"/var/jb/usr/bin/chown mobile:mobile {shlex.quote(staged[path])} && "
            f"/var/jb/usr/bin/chmod 0644 {shlex.quote(staged[path])} && "
            f"/var/jb/bin/mv {shlex.quote(staged[path])} {shlex.quote(path)}"
            for path in MANAGED_PATHS
        )
        ssh.command(
            f"{target_checks} && {backup_checks} && "
            f"{backup_commands} && {install_commands}"
        )
        staged.clear()
        return backups
    finally:
        for remote_staged in staged.values():
            ssh.command(f"/var/jb/bin/rm -f {shlex.quote(remote_staged)}")


def restart_springboard(ssh: SSH) -> tuple[int, int]:
    old_pid, command = resolve_target(ssh, "SpringBoard")
    if old_pid <= 1 or command != TARGETS["SpringBoard"]:
        raise LabError("refusing: SpringBoard identity mismatch")
    ssh.command(f"/iosbinpack64/bin/kill -9 {old_pid}")
    deadline = time.monotonic() + 20.0
    latest_pid = old_pid
    while time.monotonic() < deadline:
        time.sleep(0.5)
        try:
            latest_pid, latest_command = resolve_target(ssh, "SpringBoard")
        except LabError:
            continue
        if latest_pid != old_pid and latest_command == TARGETS["SpringBoard"]:
            return old_pid, latest_pid
    raise LabError(
        f"SpringBoard did not return with a new PID (last observed {latest_pid})"
    )


def read_managed_plists(ssh: SSH) -> dict[str, dict[str, object]]:
    return {
        path: load_plist(ssh.read_file(path), path)
        for path in MANAGED_PATHS
    }


def apply(ssh: SSH) -> tuple[tuple[ControlSpec, ...], dict[str, str], int, int]:
    current = read_managed_plists(ssh)
    icon_state, added = add_controls_to_icon_state(current[ICON_STATE_PATH])
    module_configuration = add_controls_to_module_configuration(
        current[MODULE_CONFIGURATION_PATH]
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    replacements = {
        ICON_STATE_PATH: dump_plist(icon_state),
        MODULE_CONFIGURATION_PATH: dump_plist(module_configuration),
    }
    backups = install_plists(ssh, replacements, stamp)
    old_pid, new_pid = restart_springboard(ssh)
    observed = read_managed_plists(ssh)
    missing = {
        spec.module_identifier
        for spec in PERSISTENT_CONTROL_SPECS
        if spec.module_identifier not in module_identifiers(observed[ICON_STATE_PATH])
    }
    if missing:
        raise LabError(
            "SpringBoard removed configured controls: " + ", ".join(sorted(missing))
        )
    return added, backups, old_pid, new_pid


def restore(ssh: SSH, stamp: str) -> tuple[int, int]:
    if not BACKUP_STAMP_PATTERN.fullmatch(stamp):
        raise LabError("restore stamp must use YYYYMMDDTHHMMSSZ")
    replacements = {
        path: ssh.read_file(backup_path(path, stamp))
        for path in MANAGED_PATHS
    }
    recovery_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    install_plists(ssh, replacements, recovery_stamp)
    return restart_springboard(ssh)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.64.70")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument(
        "--password-env", default="CND_VPHONE_ROOT_PASSWORD",
        help="environment variable containing the VM root password",
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--apply", action="store_true")
    action.add_argument("--restore-stamp")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ssh = SSH(args.host, args.port, args.user, args.known_hosts, args.password_env)
    require_vphone(ssh)
    if args.apply:
        added, backups, old_pid, new_pid = apply(ssh)
        labels = ", ".join(spec.label for spec in added) if added else "none (already present)"
        print(f"requested layout entries: {labels}")
        print(
            "device-gated trace controls: "
            + ", ".join(spec.label for spec in DEVICE_GATED_CONTROL_SPECS)
            + " (SpringBoard may prune these; use the synthetic VM probe)"
        )
        for target in MANAGED_PATHS:
            print(f"backup: {backups[target]}")
        print(f"SpringBoard: {old_pid} -> {new_pid}")
        return 0

    old_pid, new_pid = restore(ssh, args.restore_stamp)
    print(f"restored backup stamp: {args.restore_stamp}")
    print(f"SpringBoard: {old_pid} -> {new_pid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
