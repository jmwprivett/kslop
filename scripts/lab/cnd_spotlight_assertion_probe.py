#!/usr/bin/env python3
"""Build and inject the VM-only Spotlight assertion preflight probe."""

from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import time
from pathlib import Path

from cnd_remotecall_lab import (
    DEFAULT_KNOWN_HOSTS,
    LabError,
    SSH,
    TARGETS,
    require_vphone,
    resolve_target,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_spotlight_assertion_probe.m"
BUILD_DIR = REPO_ROOT / "build/lab-spotlight-assertion-probe"
REPORT_PATH = "/var/tmp/cyanide-spotlight-assertion-probe.log"
INJECT_LOG_PATH = "/var/tmp/cyanide-spotlight-assertion-inject.log"


PROBE_MODES = {
    "inspect": 0,
    "install": 1,
    "status": 2,
    "release": 3,
    "install-background": 4,
}


def build_probe(target_pid: int, mode: str) -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_spotlight_assertion_probe.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror", f"-DCND_SPOTLIGHT_ASSERTION_TARGET_PID={target_pid}",
        f"-DCND_SPOTLIGHT_ASSERTION_PROBE_MODE={PROBE_MODES[mode]}",
        str(SOURCE), "-framework", "Foundation", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT_PATH)}; "
        "else echo '[CND_ASSERTION] report-not-created'; fi"
    )


def inject(ssh: SSH, payload: Path, springboard_pid: int) -> str:
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-spotlight-assertion-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, command = resolve_target(ssh, "SpringBoard")
    if current_pid != springboard_pid or command != TARGETS["SpringBoard"]:
        raise LabError("SpringBoard identity changed before assertion preflight")
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT_PATH)} "
        f"{shlex.quote(INJECT_LOG_PATH)}; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {springboard_pid} "
        f"{shlex.quote(remote)} >{shlex.quote(INJECT_LOG_PATH)} 2>&1; "
        "status=$?; if test \"$status\" = 124 -o \"$status\" = 137; "
        "then exit 0; fi; exit \"$status\""
    )
    return remote


def wait_for_report(ssh: SSH, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    report = ""
    while time.monotonic() < deadline:
        report = read_report(ssh)
        if "[CND_ASSERTION] COMPLETE" in report:
            return report
        time.sleep(0.2)
    injection = ssh.command(
        f"if test -f {shlex.quote(INJECT_LOG_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(INJECT_LOG_PATH)}; fi"
    ).strip()
    raise LabError(
        f"assertion preflight did not complete:\n{report.rstrip()}\n"
        f"inject-log:\n{injection}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "run", "read"),
                        nargs="?", default="run")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--wait", type=float, default=10.0)
    parser.add_argument("--target-pid", type=int, default=0)
    parser.add_argument("--mode", choices=tuple(PROBE_MODES),
                        default="inspect")
    args = parser.parse_args()

    if args.action == "build":
        if args.target_pid <= 1:
            raise LabError("--target-pid is required for build")
        print(build_probe(args.target_pid, args.mode))
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this probe requires root on SSH port 22222")
    if not args.known_hosts.is_file():
        raise LabError(f"known-hosts file does not exist: {args.known_hosts}")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh), end="")
        return 0

    springboard_pid, command = resolve_target(ssh, "SpringBoard")
    spotlight_pid, spotlight_command = resolve_target(ssh, "Spotlight")
    payload = build_probe(spotlight_pid, args.mode)
    remote = inject(ssh, payload, springboard_pid)
    report = wait_for_report(ssh, args.wait)
    print(
        f"assertion preflight SpringBoard pid={springboard_pid} "
        f"command={command} Spotlight pid={spotlight_pid} "
        f"command={spotlight_command} mode={args.mode} payload={remote}"
    )
    print(report, end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
