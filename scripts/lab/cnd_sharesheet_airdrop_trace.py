#!/usr/bin/env python3
"""Build, inject, or read the VM-only Share-sheet AirDrop consumer trace."""

from __future__ import annotations

import argparse
import hashlib
import re
import shlex
import time
from pathlib import Path

from cnd_remotecall_lab import (
    DEFAULT_KNOWN_HOSTS,
    LabError,
    SSH,
    issue_file_extension,
    require_vphone,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_sharesheet_airdrop_trace.m"
BUILD_DIR = REPO_ROOT / "build/lab-sharesheet-airdrop-trace"
REPORT_PATH = "/var/tmp/cyanide-sharesheet-airdrop-trace.log"
INJECT_LOG_PATH = "/var/tmp/cyanide-sharesheet-airdrop-inject.log"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build(output_token: str = "") -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_sharesheet_airdrop_trace.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_SHARE_TRACE_OUTPUT_TOKEN="{c_literal(output_token)}"',
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def resolve_sharing_ui_service(ssh: SSH) -> tuple[int, str]:
    matches: list[tuple[int, str]] = []
    for line in ssh.command("/bin/ps -A -o pid=,command=").splitlines():
        pid_text, separator, command = line.strip().partition(" ")
        if not separator or not pid_text.isdigit():
            continue
        command = command.strip()
        executable = command.split(" ", 1)[0]
        if executable == "/Applications/SharingUIService.app/SharingUIService":
            matches.append((int(pid_text), command))
    if len(matches) != 1 or matches[0][0] <= 1:
        raise LabError(
            "expected exactly one SharingUIService process, "
            f"observed {matches!r}"
        )
    return matches[0]


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT_PATH)}; "
        "else echo '[CND_SHARE_TRACE] report-not-created'; fi"
    )


def inject(ssh: SSH) -> tuple[int, str]:
    pid, command = resolve_sharing_ui_service(ssh)
    token = issue_file_extension(ssh, "/var/tmp")
    payload = build(token)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-sharesheet-airdrop-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, current_command = resolve_sharing_ui_service(ssh)
    if current_pid != pid or current_command != command:
        raise LabError(
            f"refusing: SharingUIService identity changed before injection "
            f"({pid} -> {current_pid})"
        )
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT_PATH)} "
        f"{shlex.quote(INJECT_LOG_PATH)}; "
        f"current=$(/bin/ps -p {pid} -o command=); "
        "case \"$current\" in "
        "/Applications/SharingUIService.app/SharingUIService|"
        "/Applications/SharingUIService.app/SharingUIService\\ *) ;; "
        "*) echo 'target identity changed' >&2; exit 90;; esac; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG_PATH)} 2>&1; status=$?; "
        "if test \"$status\" = 124 -o \"$status\" = 137; then "
        "exit 0; fi; exit \"$status\""
    )
    deadline = time.monotonic() + 10.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        match = re.search(rf"TRACE_READY pid={pid} hooks=([0-9]+)/8", latest)
        if match and int(match.group(1)) >= 6:
            return pid, remote
        time.sleep(0.25)
    raise LabError(
        "Share-sheet trace did not install enough hooks; report follows:\n"
        + latest.rstrip()
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "inject", "read"))
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    args = parser.parse_args()

    if args.action == "build":
        print(build())
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this trace requires vPhone root SSH")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh), end="")
        return 0
    pid, remote = inject(ssh)
    print(f"Share-sheet AirDrop trace ready pid={pid} payload={remote}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
