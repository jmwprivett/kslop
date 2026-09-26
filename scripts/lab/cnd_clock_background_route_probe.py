#!/usr/bin/env python3
"""Prove a visibility-independent transparent live Clock background route."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import socket
import time
import zipfile
from pathlib import Path

from cnd_remotecall_lab import (
    LabError,
    SSH,
    TARGETS,
    issue_file_extension,
    require_vphone,
    resolve_target,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_clock_background_route_probe.m"
BUILD_DIR = REPO_ROOT / "build/lab-clock-background-route"
THEME = REPO_ROOT / "purple accent pulsar.theme.zip"
THEME_ENTRY = (
    "purple accent pulsar.theme/Bundles/com.apple.springboard/"
    "ClockIconBackgroundSquare@2x~iphone.png"
)
LOCAL_IMAGE = BUILD_DIR / "clock-background-transparent.png"
LOCAL_DYLIB = BUILD_DIR / "cnd_clock_background_route_probe.dylib"
LOCAL_REPORT = BUILD_DIR / "cnd-clock-background-route.log"
LOCAL_SCREENSHOT = BUILD_DIR / "clock-background-route.png"
REMOTE_IMAGE = "/var/tmp/cnd-clock-background-route.png"
REMOTE_REPORT = "/var/tmp/cnd-clock-background-route.log"
REMOTE_INJECT_LOG = "/var/tmp/cnd-clock-background-route-inject.log"
VM_SOCKET = Path.home() / "Library/CyanideVPhoneLab/VMs/cyanide-ios26-base/vphone.sock"
DEFAULT_KNOWN_HOSTS = REPO_ROOT / "build/lab-clock-base/ssh_known_hosts"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def extract_theme_image() -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    if not THEME.is_file():
        raise LabError(f"theme archive not found: {THEME}")
    with zipfile.ZipFile(THEME) as archive:
        try:
            data = archive.read(THEME_ENTRY)
        except KeyError as error:
            raise LabError(f"theme asset not found: {THEME_ENTRY}") from error
    expected = "a50be78a10d46ba4244937350f88fd78aa749cfdc02aed5fa9f20e5f5eaa91bc"
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise LabError(f"transparent Clock asset hash changed: {digest}")
    LOCAL_IMAGE.write_bytes(data)
    return LOCAL_IMAGE


def build(token: str) -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_CLOCK_ROUTE_OUTPUT_TOKEN="{c_literal(token)}"',
        f'-DCND_CLOCK_ROUTE_OUTPUT_PATH="{c_literal(REMOTE_REPORT)}"',
        f'-DCND_CLOCK_ROUTE_IMAGE_PATH="{c_literal(REMOTE_IMAGE)}"',
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-o", str(LOCAL_DYLIB),
    ])
    run(["codesign", "-s", "-", "--force", str(LOCAL_DYLIB)])
    return LOCAL_DYLIB


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REMOTE_REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REMOTE_REPORT)}; fi"
    )


def wait_for(ssh: SSH, pattern: str, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    latest = ""
    compiled = re.compile(pattern)
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if compiled.search(latest):
            return latest
        time.sleep(0.25)
    raise LabError(f"timed out waiting for {pattern!r}; report:\n{latest}")


def terminate_exact_agent(ssh: SSH) -> tuple[int, int]:
    old_pid, command = resolve_target(ssh, "iconservicesagent")
    if command != TARGETS["iconservicesagent"] or old_pid <= 1:
        raise LabError(f"refusing agent termination pid={old_pid} command={command}")
    ssh.command(f"kill -9 {old_pid}")
    ssh.command(
        "/var/jb/usr/bin/timeout -k 1 12 "
        "/var/tmp/cnd_clock_base_persistence_probe "
        ">/var/tmp/cnd-clock-route-agent-demand.log 2>&1 || true"
    )
    deadline = time.monotonic() + 12.0
    while time.monotonic() < deadline:
        try:
            new_pid, new_command = resolve_target(ssh, "iconservicesagent")
        except LabError:
            time.sleep(0.25)
            continue
        if new_command == TARGETS["iconservicesagent"] and new_pid != old_pid:
            return old_pid, new_pid
        time.sleep(0.25)
    raise LabError("iconservicesagent was not demand-launched with a new PID")


def capture_screenshot(path: Path) -> None:
    if not VM_SOCKET.exists():
        raise LabError(f"vPhone host-control socket is unavailable: {VM_SOCKET}")
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


def run_probe(ssh: SSH, restart_agent: bool) -> None:
    if restart_agent:
        raise LabError(
            "the isolated real-consumer route proof does not restart "
            "iconservicesagent"
        )
    image = extract_theme_image()
    token = issue_file_extension(ssh, "/var/tmp")
    payload = build(token)
    pid, command = resolve_target(ssh, "SpringBoard")
    if command != TARGETS["SpringBoard"]:
        raise LabError("SpringBoard identity mismatch")
    dylib_digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote_dylib = f"/var/tmp/cnd-clock-route-{dylib_digest}.dylib"
    ssh.copy(image, REMOTE_IMAGE)
    ssh.copy(payload, remote_dylib)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel "
        f"{shlex.quote(REMOTE_IMAGE)} {shlex.quote(remote_dylib)} && "
        f"/iosbinpack64/bin/chmod 0644 {shlex.quote(REMOTE_IMAGE)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote_dylib)}"
    )
    current_pid, current_command = resolve_target(ssh, "SpringBoard")
    if (current_pid != pid or current_command != TARGETS["SpringBoard"]):
        raise LabError("SpringBoard changed before injection")
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REMOTE_REPORT)} "
        f"{shlex.quote(REMOTE_INJECT_LOG)}; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote_dylib)} "
        f">{shlex.quote(REMOTE_INJECT_LOG)} 2>&1; status=$?; "
        f"if test \"$status\" = 124 -o \"$status\" = 137; then "
        f"exit 0; fi; exit \"$status\""
    )
    wait_for(ssh, r"READY pid=.*dedicatedReady=1 viewHook=1", 12.0)
    report = wait_for(
        ssh,
        r"REAL label=displayed-clock exact=1 .*delta=[1-9][0-9]*",
        12.0,
    )
    old_agent, _ = resolve_target(ssh, "iconservicesagent")
    new_agent = old_agent
    LOCAL_REPORT.write_text(report, encoding="utf-8")
    capture_screenshot(LOCAL_SCREENSHOT)
    springboard_after, _ = resolve_target(ssh, "SpringBoard")
    if springboard_after != pid:
        raise LabError("SpringBoard restarted during the route proof")
    print(
        "clock background route proved "
        f"springboard={pid} iconservicesagent={old_agent}->{new_agent} "
        f"agentRestart={str(restart_agent).lower()} "
        f"report={LOCAL_REPORT} screenshot={LOCAL_SCREENSHOT}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "run", "read"))
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument(
        "--restart-agent", action="store_true",
        help="replace iconservicesagent between the two reconstruction phases",
    )
    args = parser.parse_args()
    if args.action == "build":
        extract_theme_image()
        print(build(""))
        return 0
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh), end="")
        return 0
    run_probe(ssh, args.restart_agent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
