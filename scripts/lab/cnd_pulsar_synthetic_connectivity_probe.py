#!/usr/bin/env python3
"""Build, inject, capture, and restore the VM-only connectivity UI probe."""

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
SOURCE = REPO_ROOT / "scripts/lab/cnd_pulsar_synthetic_connectivity_probe.m"
BUILD_DIR = REPO_ROOT / "build/lab-pulsar-synthetic-connectivity"
REPORT = "/var/tmp/cyanide-pulsar-synthetic-connectivity.log"
INJECT_LOG = "/var/tmp/cyanide-pulsar-synthetic-connectivity-inject.log"
LOCAL_REPORT = BUILD_DIR / "cyanide-pulsar-synthetic-connectivity.log"
LOCAL_ASSET_DIR = BUILD_DIR / "assets"
VISIBLE_SCREENSHOT = BUILD_DIR / "synthetic-connectivity-visible.png"
RESTORED_SCREENSHOT = BUILD_DIR / "synthetic-connectivity-restored.png"
VM_SOCKET = (
    Path.home() /
    "Library/CyanideVPhoneLab/VMs/cyanide-ios26-base/vphone.sock"
)


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def validate_hold_seconds(value: int) -> int:
    if value < 15 or value > 180:
        raise LabError("hold duration must be between 15 and 180 seconds")
    return value


def build(*, token: str = "", expected_pid: int = 0,
          hold_seconds: int = 45, asset_directory: str | None = None) -> Path:
    validate_hold_seconds(hold_seconds)
    if expected_pid < 0:
        raise LabError("expected PID cannot be negative")
    asset_directory = asset_directory or (
        "/var/tmp/cyanide-pulsar-synthetic-connectivity-assets"
    )
    if not re.fullmatch(
        r"/var/tmp/cyanide-pulsar-synthetic-connectivity-[A-Za-z0-9-]+",
        asset_directory,
    ):
        raise LabError(f"refusing unsafe asset directory: {asset_directory}")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_pulsar_synthetic_connectivity_probe.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_SYNTHETIC_CONNECTIVITY_OUTPUT_TOKEN="{c_literal(token)}"',
        f'-DCND_SYNTHETIC_CONNECTIVITY_REPORT_PATH="{REPORT}"',
        "-DCND_SYNTHETIC_CONNECTIVITY_ASSET_DIRECTORY="
        f'"{c_literal(asset_directory)}"',
        f"-DCND_SYNTHETIC_CONNECTIVITY_EXPECTED_PID={expected_pid}",
        f"-DCND_SYNTHETIC_CONNECTIVITY_HOLD_SECONDS={hold_seconds}",
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT)}; "
        "else echo '[CND_SYNTHETIC_CONNECTIVITY] report-not-created'; fi"
    )


def inject(ssh: SSH, hold_seconds: int = 45) -> tuple[int, str, str, str]:
    validate_hold_seconds(hold_seconds)
    pid, command = resolve_target(ssh, "SpringBoard")
    if pid <= 1 or command != TARGETS["SpringBoard"]:
        raise LabError("refusing: SpringBoard identity mismatch")
    token = issue_file_extension(ssh, "/var/tmp")
    nonce = f"{time.time_ns():x}"
    asset_directory = (
        f"/var/tmp/cyanide-pulsar-synthetic-connectivity-{nonce}"
    )
    payload = build(
        token=token,
        expected_pid=pid,
        hold_seconds=hold_seconds,
        asset_directory=asset_directory,
    )
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-pulsar-synthetic-connectivity-{digest}.dylib"
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
        if " VISIBLE_READY " in latest:
            return pid, remote, asset_directory, latest
        if " COMPLETE " in latest:
            raise LabError(
                "synthetic connectivity probe completed before becoming "
                "visible:\n" + latest.rstrip()
            )
        time.sleep(0.25)
    raise LabError(
        "synthetic connectivity probe did not become visible:\n"
        + latest.rstrip()
    )


def capture_screenshot(path: Path) -> None:
    if not VM_SOCKET.is_socket():
        raise LabError(f"vPhone control socket is unavailable: {VM_SOCKET}")
    path.parent.mkdir(parents=True, exist_ok=True)
    request = {"t": "screenshot", "path": str(path)}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(VM_SOCKET))
        client.sendall((json.dumps(request) + "\n").encode())
        response = bytearray()
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    result = json.loads(response)
    if not result.get("ok") or not path.is_file():
        raise LabError(f"VM screenshot failed: {result.get('error', result)}")
    path.chmod(0o600)


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


def capture_report(ssh: SSH) -> Path:
    return atomic_write(LOCAL_REPORT, ssh.read_file(REPORT))


def capture_assets(ssh: SSH, remote_directory: str) -> tuple[Path, ...]:
    if not re.fullmatch(
        r"/var/tmp/cyanide-pulsar-synthetic-connectivity-[A-Za-z0-9-]+",
        remote_directory,
    ):
        raise LabError(f"refusing unsafe remote asset directory: {remote_directory}")
    listing = ssh.command(
        f"/iosbinpack64/usr/bin/find {shlex.quote(remote_directory)} "
        "-maxdepth 1 -type f -name '*.png' -print"
    )
    paths: list[Path] = []
    for remote_path in sorted(filter(None, map(str.strip, listing.splitlines()))):
        remote = Path(remote_path)
        if str(remote.parent) != remote_directory or not re.fullmatch(
            r"(?:bluetooth|cellular)-[0-9]+-[0-9a-f]{64}\.png",
            remote.name,
        ):
            raise LabError(f"refusing unexpected probe asset: {remote_path}")
        data = ssh.read_file(remote_path)
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise LabError(f"probe asset is not PNG: {remote_path}")
        paths.append(atomic_write(LOCAL_ASSET_DIR / remote.name, data))
    return tuple(paths)


def wait_for_complete(ssh: SSH, hold_seconds: int) -> str:
    deadline = time.monotonic() + hold_seconds + 15.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if " COMPLETE " in latest:
            if " status=success " not in latest:
                raise LabError("probe did not complete successfully:\n" + latest)
            return latest
        time.sleep(0.25)
    raise LabError("probe did not restore before its deadline:\n" + latest)


def run_probe(ssh: SSH, hold_seconds: int) -> tuple[Path, tuple[Path, ...]]:
    _, _, remote_assets, _ = inject(ssh, hold_seconds)
    time.sleep(1.0)
    capture_screenshot(VISIBLE_SCREENSHOT)
    wait_for_complete(ssh, hold_seconds)
    capture_screenshot(RESTORED_SCREENSHOT)
    report = capture_report(ssh)
    assets = capture_assets(ssh, remote_assets)
    return report, assets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "inject", "read", "run"))
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--hold-seconds", type=int, default=45)
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
            f"synthetic connectivity visible pid={pid} payload={remote} "
            f"assets={assets} hold={args.hold_seconds}s restoration=scheduled"
        )
        return 0
    report, assets = run_probe(ssh, args.hold_seconds)
    print(
        f"synthetic connectivity run complete report={report} "
        f"assets={len(assets)} visible={VISIBLE_SCREENSHOT} "
        f"restored={RESTORED_SCREENSHOT}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
