#!/usr/bin/env python3
"""Build and run the vPhone-only, read-only Spotlight object inspector."""

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
SOURCE = REPO_ROOT / "scripts/lab/cnd_spotlight_inspector.m"
BUILD_DIR = REPO_ROOT / "build/lab-spotlight-inspection"
OUTPUT_PATH = "/var/tmp/cyanide-spotlight-inspection.log"
INJECT_LOG_PATH = "/var/tmp/cyanide-spotlight-inspection-inject.log"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_inspector(output_token: str = "", root_token: str = "",
                    target_bundle: str = "com.ebay.iphone") -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_spotlight_inspector.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks",
        "-Wall", "-Wextra", "-Werror",
        f'-DCND_INSPECT_OUTPUT_TOKEN="{c_literal(output_token)}"',
        f'-DCND_INSPECT_ROOT_TOKEN="{c_literal(root_token)}"',
        f'-DCND_INSPECT_TARGET_BUNDLE="{c_literal(target_bundle)}"',
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-framework", "QuartzCore",
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def inject_inspector(ssh: SSH, payload: Path, pid: int) -> str:
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote_payload = f"/var/tmp/cnd-spotlight-inspector-{digest}.dylib"
    ssh.copy(payload, remote_payload)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel "
        f"{shlex.quote(remote_payload)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote_payload)}"
    )
    current_pid, _ = resolve_target(ssh, "Spotlight")
    if current_pid != pid or pid <= 1:
        raise LabError(
            f"refusing: Spotlight identity changed before injection "
            f"({pid} -> {current_pid})"
        )
    expected = TARGETS["Spotlight"]
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(OUTPUT_PATH)} "
        f"{shlex.quote(INJECT_LOG_PATH)}; "
        f"current=$(/bin/ps -p {pid} -o command=); "
        f"case \"$current\" in "
        f"{shlex.quote(expected)}|{shlex.quote(expected + ' ')}*) ;; "
        f"*) echo 'target identity changed' >&2; exit 90;; esac; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} "
        f"{shlex.quote(remote_payload)} "
        f">{shlex.quote(INJECT_LOG_PATH)} 2>&1; status=$?; "
        f"if test \"$status\" = 124 -o \"$status\" = 137; then "
        f"echo timed-out; exit 0; fi; exit \"$status\""
    )
    return remote_payload


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(OUTPUT_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(OUTPUT_PATH)}; "
        f"else echo '[CND_INSPECT] report-not-created'; fi"
    )


def wait_for_report(ssh: SSH, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        last = read_report(ssh)
        if "[CND_INSPECT] COMPLETE" in last:
            return last
        time.sleep(1.0)
    injection = ssh.command(
        f"if test -f {shlex.quote(INJECT_LOG_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(INJECT_LOG_PATH)}; fi"
    ).strip()
    detail = f"\ninject-log:\n{injection}" if injection else ""
    raise LabError(
        f"Spotlight inspector did not complete within {timeout:.0f}s; "
        f"current report follows:\n{last.rstrip()}{detail}"
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
    parser.add_argument("--wait", type=float, default=24.0)
    args = parser.parse_args()

    if args.action == "build":
        payload = build_inspector(target_bundle=args.bundle)
        print(payload)
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this harness requires root on SSH port 22222")
    if not args.known_hosts.is_file():
        raise LabError(f"known-hosts file does not exist: {args.known_hosts}")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh), end="")
        return 0

    pid, command = resolve_target(ssh, "Spotlight")
    output_token = issue_file_extension(ssh, "/var/tmp")
    root_token = issue_file_extension(ssh, "/private/var")
    payload = build_inspector(output_token, root_token, args.bundle)
    remote_payload = inject_inspector(ssh, payload, pid)
    print(
        f"Spotlight inspector injected pid={pid} command={command} "
        f"payload={remote_payload}"
    )
    print(wait_for_report(ssh, args.wait), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
