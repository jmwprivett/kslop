#!/usr/bin/env python3
"""Build and inject the read-only resident Spotlight transition tracer."""

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
SOURCE = REPO_ROOT / "scripts/lab/cnd_spotlight_transition_trace.m"
BUILD_DIR = REPO_ROOT / "build/lab-spotlight-transition-trace"
REPORT_PATH = "/var/tmp/cyanide-spotlight-transition-trace.log"
INJECT_LOG_PATH = "/var/tmp/cyanide-spotlight-transition-inject.log"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_tracer(target_bundle: str = "com.ebay.iphone") -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_spotlight_transition_trace.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_TRACE_TARGET_BUNDLE="{c_literal(target_bundle)}"',
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-framework", "QuartzCore",
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def inject(ssh: SSH, payload: Path, pid: int) -> str:
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-spotlight-transition-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, command = resolve_target(ssh, "Spotlight")
    if current_pid != pid or command != TARGETS["Spotlight"] or pid <= 1:
        raise LabError("Spotlight identity changed before transition trace")
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT_PATH)} "
        f"{shlex.quote(INJECT_LOG_PATH)}; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG_PATH)} 2>&1; status=$?; "
        f"if test \"$status\" = 124 -o \"$status\" = 137; then "
        f"exit 0; fi; exit \"$status\""
    )
    return remote


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT_PATH)}; "
        f"else echo '[CND_TRANSITION] report-not-created'; fi"
    )


def wait_ready(ssh: SSH, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    report = ""
    while time.monotonic() < deadline:
        report = read_report(ssh)
        if "[CND_TRANSITION] TRACE_READY" in report:
            return report
        time.sleep(0.25)
    injection = ssh.command(
        f"if test -f {shlex.quote(INJECT_LOG_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(INJECT_LOG_PATH)}; fi"
    ).strip()
    raise LabError(
        f"transition tracer did not become ready:\n{report.rstrip()}\n"
        f"inject-log:\n{injection}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "run", "read"),
                        nargs="?", default="run")
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--bundle", default="com.ebay.iphone")
    parser.add_argument("--wait", type=float, default=10.0)
    args = parser.parse_args()

    if args.action == "build":
        print(build_tracer(args.bundle))
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this tracer requires root on SSH port 22222")
    if not args.known_hosts.is_file():
        raise LabError(f"known-hosts file does not exist: {args.known_hosts}")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh), end="")
        return 0

    pid, command = resolve_target(ssh, "Spotlight")
    payload = build_tracer(args.bundle)
    remote = inject(ssh, payload, pid)
    report = wait_ready(ssh, args.wait)
    print(
        f"Spotlight transition tracer resident pid={pid} command={command} "
        f"payload={remote}"
    )
    print(report, end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
