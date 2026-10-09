#!/usr/bin/env python3
"""Inject bounded Calendar refresh-order experiments into the target process."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
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
SOURCE = REPO_ROOT / "scripts/lab/cnd_calendar_order_trigger.m"
BUILD_DIR = REPO_ROOT / "build/lab-calendar-order"
REPORT = "/var/tmp/cyanide-calendar-order-trigger.log"
INJECT_LOG = "/var/tmp/cyanide-calendar-order-trigger-inject.log"
ACTIONS = (
    "springboard-refresh-then-calendar",
    "springboard-calendar-then-refresh",
    "springboard-combined-current",
    "springboard-fast-path",
    "springboard-restore-only",
    "springboard-fast-path-only",
    "springboard-reload-only",
    "springboard-source-cache-reload",
    "springboard-source-cache-refill-barrier",
    "springboard-source-prepare-reload",
    "spotlight-calendar",
    "spotlight-restore-only",
    "spotlight-fast-path-only",
    "spotlight-reload-only",
    "spotlight-source-cache-reload",
    "spotlight-source-cache-refill-barrier",
    "spotlight-source-prepare-reload",
)


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build(action: str, token: str = "", nonce: str = "0") -> Path:
    if action not in ACTIONS:
        raise LabError(f"unsupported Calendar order action: {action}")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / f"cnd_calendar_order_{action}.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_CALENDAR_ORDER_OUTPUT_TOKEN="{c_literal(token)}"',
        f'-DCND_CALENDAR_ORDER_NONCE="{c_literal(nonce)}"',
        f'-DCND_CALENDAR_ORDER_ACTION="{c_literal(action)}"',
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def target_for_action(action: str) -> str:
    if action not in ACTIONS:
        raise LabError(f"unsupported Calendar order action: {action}")
    return "Spotlight" if action.startswith("spotlight-") else "SpringBoard"


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT)}; "
        "else echo '[CND_CALENDAR_ORDER] report-not-created'; fi"
    )


def inject(ssh: SSH, action: str,
           expected_target: str | None = None) -> tuple[int, str, str]:
    target = target_for_action(action)
    if expected_target is not None and target != expected_target:
        raise LabError(
            f"Calendar action {action} targets {target}, not {expected_target}"
        )
    pid, command = resolve_target(ssh, target)
    if command != TARGETS[target] or pid <= 1:
        raise LabError(f"{target} identity mismatch before injection")
    token = issue_file_extension(ssh, "/var/tmp")
    nonce = str(time.time_ns())
    payload = build(action, token, nonce)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-calendar-order-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    if resolve_target(ssh, target) != (pid, command):
        raise LabError(
            f"{target} identity changed before Calendar trigger injection"
        )
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT)} "
        f"{shlex.quote(INJECT_LOG)}; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG)} 2>&1; status=$?; "
        'if test "$status" = 124 -o "$status" = 137; then '
        'exit 0; fi; exit "$status"'
    )
    deadline = time.monotonic() + 20.0
    latest = ""
    marker = f"COMPLETE nonce={nonce}"
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if marker in latest:
            return pid, remote, latest
        time.sleep(0.25)
    raise LabError("Calendar order trigger did not complete:\n" + latest.rstrip())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "inject", "read"))
    parser.add_argument("--sequence", choices=ACTIONS,
                        default=ACTIONS[0])
    parser.add_argument("--host", default=None,
                        help="vPhone host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--target", choices=("SpringBoard", "Spotlight"),
                        default=None)
    args = parser.parse_args()

    if args.action == "build":
        print(build(args.sequence))
        return 0

    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh), end="")
        return 0

    pid, remote, report = inject(ssh, args.sequence, args.target)
    print(
        f"Calendar order sequence complete target={target_for_action(args.sequence)} "
        f"pid={pid} payload={remote}"
    )
    print(report, end="" if report.endswith("\n") else "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
