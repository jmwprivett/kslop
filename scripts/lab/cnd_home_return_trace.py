#!/usr/bin/env python3
"""Build, inject, mark, and read a bounded SpringBoard Home-return icon trace."""

from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import time
from pathlib import Path

from cnd_remotecall_lab import (
    DEFAULT_KNOWN_HOSTS, LabError, SSH, TARGETS,
    issue_file_extension, require_vphone, resolve_target, run,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_home_return_trace.m"
BUILD_DIR = REPO_ROOT / "build/lab-home-return-trace"
REPORT = "/var/tmp/cyanide-home-return-trace.log"
INJECT_LOG = "/var/tmp/cyanide-home-return-inject.log"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build(bundle: str, token: str = "") -> Path:
    if not bundle or len(bundle) > 200 or not all(
        char.isascii() and (char.isalnum() or char in ".-_") for char in bundle
    ):
        raise LabError("bundle must be one explicit bundle identifier")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_home_return_trace.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror", f'-DCND_HOME_BUNDLE="{c_literal(bundle)}"',
        f'-DCND_HOME_TOKEN="{c_literal(token)}"', str(SOURCE),
        "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-framework", "QuartzCore",
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def read(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT)}; "
        "else echo '[CND_HOME] report-not-created'; fi"
    )


def mark(ssh: SSH, label: str) -> None:
    if label not in {"app-open", "return-home", "observed-stock", "settled"}:
        raise LabError("invalid mark label")
    if "[CND_HOME] TRACE_READY" not in read(ssh):
        raise LabError("trace is not ready")
    ssh.command(
        "printf '%s\\n' "
        f"{shlex.quote('[CND_HOME] MARK ' + label)} "
        f">> {shlex.quote(REPORT)}"
    )


def inject(ssh: SSH, bundle: str) -> tuple[int, str]:
    pid, command = resolve_target(ssh, "SpringBoard")
    if command != TARGETS["SpringBoard"] or pid <= 1:
        raise LabError("SpringBoard identity mismatch")
    token = issue_file_extension(ssh, "/var/tmp")
    payload = build(bundle, token)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-home-return-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, current_command = resolve_target(ssh, "SpringBoard")
    if (current_pid, current_command) != (pid, command):
        raise LabError("SpringBoard identity changed before injection")
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT)} "
        f"{shlex.quote(INJECT_LOG)}; "
        f"current=$(/bin/ps -p {pid} -o command=); "
        f"case \"$current\" in {shlex.quote(command)}|"
        f"{shlex.quote(command + ' ')}*) ;; "
        f"*) echo 'target identity changed' >&2; exit 90;; esac; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG)} 2>&1; status=$?; "
        f"if test \"$status\" = 124 -o \"$status\" = 137; then "
        f"exit 0; fi; exit \"$status\""
    )
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        report = read(ssh)
        if f"TRACE_READY pid={pid}" in report:
            return pid, remote
        time.sleep(0.25)
    raise LabError("trace did not become ready:\n" + read(ssh).rstrip())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=(
        "build", "inject", "read", "app-open", "return-home",
        "observed-stock", "settled"))
    parser.add_argument("--bundle", default="com.ebay.iphone")
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    args = parser.parse_args()
    if args.action == "build":
        print(build(args.bundle))
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("this tracer requires vPhone root SSH")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read(ssh), end="")
    elif args.action == "inject":
        pid, remote = inject(ssh, args.bundle)
        print(f"Home-return trace ready pid={pid} payload={remote} report={REPORT}")
    else:
        mark(ssh, args.action)
        print(f"marked {args.action}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
