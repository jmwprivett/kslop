#!/usr/bin/env python3
"""Prove event-driven Pulsar connectivity persistence across CC rebuilds."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import socket
import tempfile
import time
from pathlib import Path

from cnd_remotecall_lab import (
    DEFAULT_KNOWN_HOSTS,
    LabError,
    SSH,
    TARGETS,
    issue_file_extension,
    require_vphone,
    resolve_target,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_pulsar_connectivity_persistence_canary.m"
BUILD_DIR = REPO_ROOT / "build/lab-pulsar-connectivity-persistence"
OUTPUT = BUILD_DIR / "cnd_pulsar_connectivity_persistence_canary.dylib"
LOCAL_REPORT = BUILD_DIR / "cyanide-pulsar-connectivity-persistence.log"
REPORT = "/var/tmp/cyanide-pulsar-connectivity-persistence.log"
INJECT_LOG = "/var/tmp/cyanide-pulsar-connectivity-persistence-inject.log"
VM_SOCKET = (
    Path.home()
    / "Library/CyanideVPhoneLab/VMs/cyanide-ios26-base/vphone.sock"
)
REMOTE_PATTERN = re.compile(
    r"/var/tmp/cyanide-pulsar-connectivity-persistence-[0-9a-f]+"
)

ASSETS = {
    "wifi-standard.png": "StaticWifi.ca/standard.png",
    "wifi-selected.png": "StaticWifi.ca/selected.png",
    "bluetooth-standard.png": "StaticBluetooth.ca/standard.png",
    "bluetooth-selected.png": "StaticBluetooth.ca/selected.png",
    "airdrop-standard.png": "StaticAirDrop.ca/standard.png",
    "airdrop-selected.png": "StaticAirDrop.ca/selected.png",
    "airplane-standard.png": "StaticAirplaneMode.ca/standard.png",
    "airplane-selected.png": "StaticAirplaneMode.ca/selected.png",
    "cellular-standard.png": "StaticCellular.ca/standard.png",
    "cellular-selected.png": "StaticCellular.ca/selected.png",
    "hotspot-standard.png": "StaticHotspot.ca/standard.png",
    "hotspot-selected.png": "StaticHotspot.ca/selected.png",
}


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def validate_hold_seconds(value: int) -> int:
    if value < 30 or value > 90:
        raise LabError("hold duration must be between 30 and 90 seconds")
    return value


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_assets() -> dict[str, Path]:
    root = REPO_ROOT / "Cyanide/PulsarControlCenter.bundle"
    selected: dict[str, Path] = {}
    for remote_name, relative in ASSETS.items():
        path = (root / relative).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as error:
            raise LabError(f"asset escapes Pulsar bundle: {relative}") from error
        if not path.is_file() or path.stat().st_size == 0:
            raise LabError(f"missing generated Pulsar asset: {path}")
        selected[remote_name] = path
    return selected


def build(*, expected_pid: int = 0, hold_seconds: int = 36,
          asset_directory: str | None = None) -> Path:
    validate_hold_seconds(hold_seconds)
    if expected_pid < 0:
        raise LabError("expected PID cannot be negative")
    asset_directory = asset_directory or (
        "/var/tmp/cyanide-pulsar-connectivity-persistence-a1"
    )
    if not REMOTE_PATTERN.fullmatch(asset_directory):
        raise LabError(f"refusing unsafe asset directory: {asset_directory}")
    validate_assets()
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_PULSAR_PERSISTENCE_REPORT_PATH="{c_literal(REPORT)}"',
        f'-DCND_PULSAR_PERSISTENCE_ASSET_DIRECTORY="{c_literal(asset_directory)}"',
        f"-DCND_PULSAR_PERSISTENCE_EXPECTED_PID={expected_pid}",
        f"-DCND_PULSAR_PERSISTENCE_HOLD_SECONDS={hold_seconds}",
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-o", str(OUTPUT),
    ])
    run(["codesign", "-s", "-", "--force", str(OUTPUT)])
    return OUTPUT


def stage_assets(ssh: SSH, remote_directory: str) -> None:
    if not REMOTE_PATTERN.fullmatch(remote_directory):
        raise LabError(f"refusing unsafe asset directory: {remote_directory}")
    assets = validate_assets()
    ssh.command(
        f"/iosbinpack64/bin/mkdir -p {shlex.quote(remote_directory)} && "
        f"/iosbinpack64/bin/chmod 0700 {shlex.quote(remote_directory)}"
    )
    for remote_name, local_path in assets.items():
        ssh.copy(local_path, f"{remote_directory}/{remote_name}")
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown -R mobile:mobile "
        f"{shlex.quote(remote_directory)} && "
        f"/iosbinpack64/bin/chmod 0600 "
        f"{shlex.quote(remote_directory)}/*.png"
    )


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT)}; "
        "else echo '[CND_PULSAR_PERSISTENCE] report-not-created'; fi"
    )


def mark(ssh: SSH, phase: str) -> None:
    if not re.fullmatch(r"[a-z0-9-]+", phase):
        raise LabError(f"unsafe phase marker: {phase}")
    line = f"[CND_PULSAR_PERSISTENCE] DRIVER phase={phase}"
    ssh.command(
        f"/iosbinpack64/usr/bin/printf '%s\\n' {shlex.quote(line)} "
        f">> {shlex.quote(REPORT)}"
    )


def host_control(request: dict[str, object]) -> None:
    if not VM_SOCKET.is_socket():
        raise LabError(f"vPhone control socket is unavailable: {VM_SOCKET}")
    request = dict(request)
    request["screen"] = False
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(VM_SOCKET))
        client.sendall((json.dumps(request) + "\n").encode())
        response = bytearray()
        while True:
            block = client.recv(65536)
            if not block:
                break
            response.extend(block)
    result = json.loads(response)
    if not result.get("ok"):
        raise LabError(f"vPhone control failed: {result}")


def inject(ssh: SSH, hold_seconds: int = 36) -> tuple[int, str, str, str]:
    validate_hold_seconds(hold_seconds)
    pid, command = resolve_target(ssh, "SpringBoard")
    if pid <= 1 or command != TARGETS["SpringBoard"]:
        raise LabError("refusing: SpringBoard identity mismatch")
    token = issue_file_extension(ssh, "/var/tmp")
    remote_assets = (
        f"/var/tmp/cyanide-pulsar-connectivity-persistence-{time.time_ns():x}"
    )
    payload = build(
        expected_pid=pid,
        hold_seconds=hold_seconds,
        asset_directory=remote_assets,
    )
    stage_assets(ssh, remote_assets)
    remote = (
        "/var/tmp/cnd-pulsar-connectivity-persistence-"
        f"{file_sha256(payload)[:16]}.dylib"
    )
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    if resolve_target(ssh, "SpringBoard") != (pid, command):
        raise LabError("refusing: SpringBoard identity changed before injection")
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT)} "
        f"{shlex.quote(INJECT_LOG)}; "
        f"current=$(/bin/ps -p {pid} -o command=); "
        f"if test \"$current\" != {shlex.quote(command)}; then "
        "echo 'target identity changed' >&2; exit 90; fi; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG)} 2>&1; status=$?; "
        'if test "$status" = 124 -o "$status" = 137; then '
        'exit 0; fi; exit "$status"'
    )
    deadline = time.monotonic() + 24.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if " READY " in latest and " installed=1 " in latest:
            return pid, remote, remote_assets, latest
        if " COMPLETE " in latest:
            raise LabError(
                "persistence canary completed before readiness:\n"
                + latest.rstrip()
            )
        time.sleep(0.25)
    raise LabError("persistence canary did not become ready:\n" + latest.rstrip())


def exercise_lifecycle(ssh: SSH) -> None:
    mark(ssh, "initial-compact")
    time.sleep(2.0)
    host_control({"t": "key", "name": "home"})
    mark(ssh, "closed")
    time.sleep(3.0)
    host_control({
        "t": "swipe", "x1": 1210, "y1": 20,
        "x2": 1210, "y2": 1250, "ms": 450,
    })
    mark(ssh, "reopened")
    time.sleep(4.0)
    host_control({"t": "tap", "x": 390, "y": 650})
    mark(ssh, "expanded")
    time.sleep(4.0)
    host_control({"t": "key", "name": "home"})
    mark(ssh, "collapsed")
    time.sleep(3.0)
    host_control({"t": "key", "name": "home"})
    mark(ssh, "closed-again")
    time.sleep(2.0)
    host_control({
        "t": "swipe", "x1": 1210, "y1": 20,
        "x2": 1210, "y2": 1250, "ms": 450,
    })
    mark(ssh, "reopened-again")


def wait_for_complete(ssh: SSH, hold_seconds: int) -> str:
    deadline = time.monotonic() + hold_seconds + 15.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if " COMPLETE " in latest:
            if " status=success " not in latest:
                raise LabError(
                    "persistence canary did not restore successfully:\n"
                    + latest
                )
            return latest
        time.sleep(0.25)
    raise LabError("persistence canary did not complete:\n" + latest)


def validate_lifecycle_report(report: str) -> None:
    required_markers = (
        "phase=closed", "phase=reopened", "phase=expanded",
        "phase=collapsed", "phase=closed-again", "phase=reopened-again",
    )
    missing = [marker for marker in required_markers if marker not in report]
    if missing:
        raise LabError("missing lifecycle markers: " + ", ".join(missing))
    reopened = report.rfind("phase=reopened-again")
    restored = report.rfind(" RESTORED ")
    if reopened < 0 or restored < reopened:
        raise LabError("canary restored before the final reopen")
    post_reopen = report[reopened:restored]
    matches = re.findall(
        r"VERIFY tag=[^ ]+ found=(\d+) themed=(\d+)", post_reopen
    )
    if not matches or not any(
        int(found) >= 3 and int(themed) == int(found)
        for found, themed in matches
    ):
        raise LabError(
            "no fully themed connectivity verification followed the final reopen"
        )


def atomic_write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.stem}-", suffix=path.suffix,
            dir=path.parent, delete=False,
        ) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return path


def run_canary(ssh: SSH, hold_seconds: int) -> Path:
    inject(ssh, hold_seconds)
    exercise_lifecycle(ssh)
    report = wait_for_complete(ssh, hold_seconds)
    validate_lifecycle_report(report)
    return atomic_write(LOCAL_REPORT, report.encode())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "inject", "read", "run"))
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--hold-seconds", type=int, default=36)
    args = parser.parse_args()

    if args.action == "build":
        print(build(hold_seconds=args.hold_seconds))
        return 0
    if args.port != 22222 or args.user != "root" or not args.host:
        raise LabError("live actions require vPhone root SSH on port 22222")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh), end="")
        return 0
    if args.action == "inject":
        pid, remote, assets, _ = inject(ssh, args.hold_seconds)
        print(
            f"Pulsar persistence canary ready pid={pid} payload={remote} "
            f"assets={assets} hold={args.hold_seconds}s"
        )
        return 0
    report = run_canary(ssh, args.hold_seconds)
    print(f"Pulsar persistence canary complete report={report}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LabError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}")
        raise SystemExit(1)
