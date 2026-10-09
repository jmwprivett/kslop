#!/usr/bin/env python3
"""Build and inject the auto-restoring VM-only Flashlight grid control."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
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
SOURCE = REPO_ROOT / "scripts/lab/cnd_vm_flashlight_control_probe.m"
BUILD_DIR = REPO_ROOT / "build/lab-vm-flashlight-control"
REPORT = "/var/tmp/cyanide-vm-flashlight-control.log"
INJECT_LOG = "/var/tmp/cyanide-vm-flashlight-control-inject.log"
LOCAL_REPORT = BUILD_DIR / "cyanide-vm-flashlight-control.log"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def validate_hold_seconds(value: int) -> int:
    if value < 30 or value > 600:
        raise LabError("hold duration must be between 30 and 600 seconds")
    return value


def build(*, token: str = "", expected_pid: int = 0,
          hold_seconds: int = 120) -> Path:
    validate_hold_seconds(hold_seconds)
    if expected_pid < 0:
        raise LabError("expected PID cannot be negative")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_vm_flashlight_control_probe.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_VM_FLASHLIGHT_OUTPUT_TOKEN="{c_literal(token)}"',
        f'-DCND_VM_FLASHLIGHT_REPORT_PATH="{REPORT}"',
        f"-DCND_VM_FLASHLIGHT_EXPECTED_PID={expected_pid}",
        f"-DCND_VM_FLASHLIGHT_HOLD_SECONDS={hold_seconds}",
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-framework", "QuartzCore",
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT)}; "
        "else echo '[CND_VM_FLASHLIGHT] report-not-created'; fi"
    )


def capture_report(ssh: SSH) -> Path:
    LOCAL_REPORT.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".cyanide-vm-flashlight-", suffix=".log",
            dir=LOCAL_REPORT.parent, delete=False,
        ) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(ssh.read_file(REPORT))
        os.replace(temporary, LOCAL_REPORT)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return LOCAL_REPORT


def inject(ssh: SSH, hold_seconds: int = 120) -> tuple[int, str, str]:
    validate_hold_seconds(hold_seconds)
    pid, command = resolve_target(ssh, "SpringBoard")
    if pid <= 1 or command != TARGETS["SpringBoard"]:
        raise LabError("refusing: SpringBoard identity mismatch")
    token = issue_file_extension(ssh, "/var/tmp")
    payload = build(token=token, expected_pid=pid, hold_seconds=hold_seconds)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    if not re.fullmatch(r"[0-9a-f]{16}", digest):
        raise LabError("invalid payload digest")
    remote = f"/var/tmp/cnd-vm-flashlight-control-{digest}.dylib"
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
    deadline = time.monotonic() + 32.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if " VISIBLE_READY " in latest:
            return pid, remote, latest
        if " COMPLETE " in latest:
            raise LabError("Flashlight probe refused presentation:\n" + latest)
        time.sleep(0.25)
    raise LabError("Flashlight probe did not become visible:\n" + latest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "inject", "read", "capture"))
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--hold-seconds", type=int, default=120)
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
    if args.action == "capture":
        print(capture_report(ssh))
        return 0
    pid, remote, _ = inject(ssh, args.hold_seconds)
    print(
        f"synthetic Flashlight visible pid={pid} payload={remote} "
        f"hold={args.hold_seconds}s restoration=scheduled "
        "interaction=disabled hardware-spoof=no"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
