#!/usr/bin/env python3
"""Build, inject, and read the vPhone-only SpringBoard surface trace."""

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
    issue_file_extension,
    require_vphone,
    resolve_target,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_springboard_surface_trace.m"
BUILD_DIR = REPO_ROOT / "build/lab-springboard-surface-trace"
REPORT = "/var/tmp/cyanide-springboard-surface-trace.log"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build(
    output_token: str = "",
    open_bundle: str = "",
    target_bundle: str = "com.ebay.iphone",
) -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_springboard_surface_trace.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_SURFACE_TRACE_OUTPUT_TOKEN="{c_literal(output_token)}"',
        f'-DCND_SURFACE_TRACE_OUTPUT_PATH="{c_literal(REPORT)}"',
        f'-DCND_SURFACE_TRACE_OPEN_BUNDLE="{c_literal(open_bundle)}"',
        f'-DCND_SURFACE_TRACE_TARGET_BUNDLE="{c_literal(target_bundle)}"',
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
        "else echo '[CND_SURFACE] report-not-created'; fi"
    )


def inject(
    ssh: SSH,
    open_bundle: str = "",
    target_bundle: str = "com.ebay.iphone",
) -> tuple[int, str]:
    pid, _ = resolve_target(ssh, "SpringBoard")
    token = issue_file_extension(ssh, "/var/tmp")
    payload = build(token, open_bundle, target_bundle)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-springboard-surface-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, _ = resolve_target(ssh, "SpringBoard")
    if current_pid != pid or pid <= 1:
        raise LabError(
            f"refusing: SpringBoard identity changed before injection "
            f"({pid} -> {current_pid})"
        )
    expected = TARGETS["SpringBoard"]
    inject_log = "/var/tmp/cyanide-springboard-surface-inject.log"
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT)} "
        f"{shlex.quote(inject_log)}; "
        f"current=$(/bin/ps -p {pid} -o command=); "
        f"case \"$current\" in "
        f"{shlex.quote(expected)}|{shlex.quote(expected + ' ')}*) ;; "
        f"*) echo 'target identity changed' >&2; exit 90;; esac; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(inject_log)} 2>&1; status=$?; "
        f"if test \"$status\" = 124 -o \"$status\" = 137; then "
        f"exit 0; fi; exit \"$status\""
    )
    deadline = time.monotonic() + 10.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if f"TRACE_READY pid={pid}" in latest:
            return pid, remote
        time.sleep(0.25)
    raise LabError(
        "SpringBoard surface trace did not become ready; report follows:\n"
        + latest.rstrip()
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "inject", "read"))
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument(
        "--open-bundle", default="",
        help="VM-only: ask SpringBoard to open this bundle after hooks install")
    parser.add_argument(
        "--target-bundle", default="com.ebay.iphone",
        help=(
            "also trace out-of-scope IconServices descriptors for this exact "
            "bundle; use '*' for every bundle"
        ),
    )
    args = parser.parse_args()

    if args.action == "build":
        print(build(
            open_bundle=args.open_bundle,
            target_bundle=args.target_bundle,
        ))
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this trace requires vPhone root SSH")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh), end="")
        return 0
    pid, remote = inject(ssh, args.open_bundle, args.target_bundle)
    print(
        f"SpringBoard surface trace ready pid={pid} "
        f"payload={remote} report={REPORT}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
