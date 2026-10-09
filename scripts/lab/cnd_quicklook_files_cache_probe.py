#!/usr/bin/env python3
"""Inspect or mutate the Files root entry through Quick Look's own cache writer."""

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
    require_vphone,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_quicklook_files_cache_probe.m"
TRIGGER_SOURCE = REPO_ROOT / "scripts/lab/cnd_quicklook_service_trigger.m"
BUILD_DIR = REPO_ROOT / "build/lab-quicklook-files-cache"
OUTPUT_PATH = "/var/tmp/cyanide-quicklook-files-cache.log"
INJECT_LOG_PATH = "/var/tmp/cyanide-quicklook-files-cache-inject.log"
TARGET = (
    "/System/Library/Frameworks/QuickLookThumbnailing.framework/Support/"
    "com.apple.quicklook.ThumbnailsAgent"
)


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def resolve_target(ssh: SSH) -> tuple[int, str]:
    output = ssh.command("/bin/ps -A -o pid=,command=")
    matches: list[tuple[int, str]] = []
    for line in output.splitlines():
        pid_text, separator, command = line.strip().partition(" ")
        if not separator or not pid_text.isdigit():
            continue
        command = command.strip()
        if command == TARGET or command.startswith(TARGET + " "):
            matches.append((int(pid_text), command))
    if len(matches) != 1 or matches[0][0] <= 1:
        raise LabError(
            f"expected exactly one Quick Look agent, observed {matches!r}"
        )
    return matches[0]


def build_probe(output_token: str = "", action: int = 0) -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_quicklook_files_cache_probe.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_QL_OUTPUT_TOKEN="{c_literal(output_token)}"',
        f"-DCND_QL_ACTION={action}",
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def build_trigger() -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_quicklook_service_trigger"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-fobjc-arc", "-fblocks", "-Wall", "-Wextra", "-Werror",
        str(TRIGGER_SOURCE), "-framework", "Foundation", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def ensure_target(ssh: SSH) -> tuple[int, str]:
    try:
        return resolve_target(ssh)
    except LabError:
        trigger = build_trigger()
        digest = hashlib.sha256(trigger.read_bytes()).hexdigest()[:16]
        remote = f"/var/tmp/cnd-quicklook-trigger-{digest}"
        ssh.copy(trigger, remote)
        ssh.command(
            f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
            f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)} && "
            f"{shlex.quote(remote)} >/var/tmp/cnd-quicklook-trigger.log 2>&1 "
            f"|| true; /iosbinpack64/bin/sleep 1"
        )
        return resolve_target(ssh)


def inject(ssh: SSH, payload: Path, expected_pid: int) -> str:
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-quicklook-files-cache-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, _ = resolve_target(ssh)
    if current_pid != expected_pid:
        raise LabError(
            f"Quick Look identity changed before injection "
            f"({expected_pid} -> {current_pid})"
        )
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(OUTPUT_PATH)} "
        f"{shlex.quote(INJECT_LOG_PATH)}; "
        f"current=$(/bin/ps -p {expected_pid} -o command=); "
        f"case \"$current\" in "
        f"{shlex.quote(TARGET)}|{shlex.quote(TARGET + ' ')}*) ;; "
        f"*) echo 'target identity changed' >&2; exit 90;; esac; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {expected_pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG_PATH)} 2>&1; status=$?; "
        f"if test \"$status\" = 124 -o \"$status\" = 137; then "
        f"echo timed-out; exit 0; fi; exit \"$status\""
    )
    return remote


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(OUTPUT_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(OUTPUT_PATH)}; "
        "else echo '[CND_QL] report-not-created'; fi"
    )


def wait_for_report(ssh: SSH, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        last = read_report(ssh)
        if "[CND_QL] COMPLETE" in last:
            return last
        time.sleep(0.5)
    injection = ssh.command(
        f"if test -f {shlex.quote(INJECT_LOG_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(INJECT_LOG_PATH)}; fi"
    ).strip()
    detail = f"\ninject-log:\n{injection}" if injection else ""
    raise LabError(
        f"Quick Look cache probe did not complete within {timeout:.0f}s; "
        f"current report follows:\n{last.rstrip()}{detail}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("build", "inspect", "apply", "restore", "read"),
        nargs="?", default="inspect",
    )
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--wait", type=float, default=20.0)
    args = parser.parse_args()

    action = {"inspect": 0, "apply": 1, "restore": 2}.get(args.action, 0)
    if args.action == "build":
        print(build_probe(action=action))
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

    pid, command = ensure_target(ssh)
    token = issue_file_extension(ssh, "/var/tmp")
    payload = build_probe(token, action)
    remote = inject(ssh, payload, pid)
    print(
        f"Quick Look Files cache probe injected pid={pid} command={command} "
        f"payload={remote}"
    )
    print(wait_for_report(ssh, args.wait), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
