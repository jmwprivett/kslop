#!/usr/bin/env python3
"""Trace construction of Spotlight's icon prominence backing in vPhone."""

from __future__ import annotations

import argparse
import hashlib
import os
import shlex
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
SOURCE = REPO_ROOT / "scripts/lab/cnd_spotlight_prominence_trace.m"
BUILD_DIR = REPO_ROOT / "build/lab-spotlight-prominence-trace"
REPORT_PATH = "/var/tmp/cyanide-spotlight-prominence-trace.log"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    args = parser.parse_args()
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    pid, command = resolve_target(ssh, "Spotlight")
    if command != TARGETS["Spotlight"]:
        raise LabError("Spotlight identity mismatch")
    token = issue_file_extension(ssh, "/var/tmp")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    payload = BUILD_DIR / "cnd_spotlight_prominence_trace.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
        f'-DCND_PROMINENCE_TRACE_OUTPUT_TOKEN="{c_literal(token)}"',
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-o", str(payload),
    ])
    run(["codesign", "-s", "-", "--force", str(payload)])
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-spotlight-prominence-trace-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT_PATH)} && "
        f"/var/jb/usr/bin/timeout -k 2 20 /iosbinpack64/bin/opainject "
        f"{pid} {shlex.quote(remote)} >/var/tmp/"
        f"cyanide-spotlight-prominence-trace-inject.log 2>&1; "
        f"status=$?; if test \"$status\" = 124 -o \"$status\" = 137; "
        f"then status=0; fi; exit \"$status\""
    )
    print(f"Spotlight prominence trace pid={pid} payload={remote}")
    print(ssh.command(
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT_PATH)}"), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
