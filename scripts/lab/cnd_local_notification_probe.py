#!/usr/bin/env python3
"""Build, inject, and read the Files local-notification VM probe."""

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
    issue_file_extension,
    process_snapshot,
    require_vphone,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_local_notification_probe.m"
BUILD_DIR = REPO_ROOT / "build/lab-local-notification"
REPORT = "/var/tmp/cyanide-local-notification-probe.log"
DEFAULT_PROCESS_SUFFIX = "/Files.app/Files"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build(token: str = "", nonce: str = "0") -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / f"cnd_local_notification_probe_{nonce}.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_NOTIFICATION_PROBE_OUTPUT_TOKEN="{c_literal(token)}"',
        f'-DCND_NOTIFICATION_PROBE_NONCE="{c_literal(nonce)}"',
        str(SOURCE), "-framework", "Foundation",
        "-framework", "UserNotifications", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def application_process(ssh: SSH, process_suffix: str) -> tuple[int, str]:
    matches = [item for item in process_snapshot(ssh)
               if item[1].endswith(process_suffix)]
    if len(matches) != 1 or matches[0][0] <= 1:
        raise LabError(
            f"expected one process ending in {process_suffix!r}, "
            f"found {matches}"
        )
    return matches[0]


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT)}; "
        "else echo '[CND_NOTIFICATION_PROBE] report-not-created'; fi"
    )


def inject(ssh: SSH, process_suffix: str) -> tuple[int, str]:
    pid, command = application_process(ssh, process_suffix)
    token = issue_file_extension(ssh, "/var/tmp")
    nonce = str(time.time_ns())
    payload = build(token, nonce)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-local-notification-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, current_command = application_process(ssh, process_suffix)
    if (current_pid, current_command) != (pid, command):
        raise LabError("Files identity changed before injection")
    inject_log = "/var/tmp/cyanide-local-notification-inject.log"
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT)} "
        f"{shlex.quote(inject_log)}; "
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
        if f"nonce={nonce}" in latest:
            return pid, remote
        time.sleep(0.25)
    raise LabError("notification probe did not start:\n" + latest.rstrip())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "inject", "read"))
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--process-suffix", default=DEFAULT_PROCESS_SUFFIX)
    args = parser.parse_args()

    if args.action == "build":
        print(build())
        return 0

    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh).rstrip())
        return 0

    pid, remote = inject(ssh, args.process_suffix)
    print(f"notification probe ready pid={pid} payload={remote}")
    print(read_report(ssh).rstrip())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
