#!/usr/bin/env python3
"""Build, inject, and read a bounded vPhone SpringBoard refresh probe."""

from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import time
from pathlib import Path

from cnd_iconservices_inspection import validate_bundle

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
SOURCE = REPO_ROOT / "scripts/lab/cnd_springboard_refresh_probe.m"
BUILD_DIR = REPO_ROOT / "build/lab-springboard-refresh-probe"
REPORT = "/var/tmp/cyanide-springboard-refresh-probe.log"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build(action: str, output_token: str = "",
          bundle: str = "com.ebay.iphone") -> Path:
    bundle = validate_bundle(bundle)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / f"cnd_springboard_refresh_probe_{action}.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_REFRESH_PROBE_ACTION="{c_literal(action)}"',
        f'-DCND_REFRESH_PROBE_OUTPUT_TOKEN="{c_literal(output_token)}"',
        f'-DCND_REFRESH_PROBE_OUTPUT_PATH="{c_literal(REPORT)}"',
        f'-DCND_REFRESH_PROBE_TARGET_BUNDLE="{c_literal(bundle)}"',
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics",
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT)}; "
        "else echo '[CND_REFRESH] report-not-created'; fi"
    )


def inject(ssh: SSH, action: str,
           bundle: str = "com.ebay.iphone") -> tuple[int, str, str]:
    pid, _ = resolve_target(ssh, "SpringBoard")
    token = issue_file_extension(ssh, "/var/tmp")
    payload = build(action, token, bundle)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-springboard-refresh-{action}-{digest}.dylib"
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
    inject_log = "/var/tmp/cyanide-springboard-refresh-inject.log"
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
    marker = f"PROBE_COMPLETE pid={pid} action={action}"
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if marker in latest:
            return pid, remote, latest
        time.sleep(0.25)
    raise LabError(
        "SpringBoard refresh probe did not complete; report follows:\n"
        + latest.rstrip()
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=(
        "inventory", "notification-inventory", "notification-reload",
        "notification-cache-purge", "notification-consumers",
        "notification-recipe", "notification-sources",
        "reset", "cache-reset-inventory", "library-search-query",
        "library-table", "switcher-cache", "switcher-titles",
        "switcher-retained", "switcher-retained-repaint",
        "switcher-inventory", "reload",
        "folder", "folder-source", "layout", "relayout", "library",
        "bounded", "target-icon", "target-visible", "target-cache", "unlock",
        "target-consumers", "root-cache-rebind", "force-unlock", "read",
    ))
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--bundle", default="com.ebay.iphone")
    args = parser.parse_args()
    bundle = validate_bundle(args.bundle)
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this probe requires vPhone root SSH")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh), end="")
        return 0
    pid, remote, report = inject(ssh, args.action, bundle)
    print(
        f"SpringBoard refresh probe complete pid={pid} action={args.action} "
        f"payload={remote} report={REPORT}"
    )
    print(report, end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
