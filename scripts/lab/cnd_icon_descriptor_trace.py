#!/usr/bin/env python3
"""Trace real app-icon descriptors in vPhone SpringBoard, Spotlight, or Files."""

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
SOURCE = REPO_ROOT / "scripts/lab/cnd_icon_descriptor_trace.m"
BUILD_DIR = REPO_ROOT / "build/lab-icon-descriptor-trace"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def safe_target(target: str) -> str:
    if target not in ("SpringBoard", "Spotlight", "Files"):
        raise LabError("target must be SpringBoard, Spotlight, or Files")
    return target


def resolve_files(ssh: SSH) -> tuple[int, str]:
    output = ssh.command("/bin/ps -A -o pid=,command=")
    matches: list[tuple[int, str]] = []
    for line in output.splitlines():
        pid_text, separator, command = line.strip().partition(" ")
        if not separator or not pid_text.isdigit():
            continue
        command = command.strip()
        executable = command.split(" ", 1)[0]
        if (executable.startswith("/var/containers/Bundle/Application/") and
                executable.endswith("/Files.app/Files")):
            matches.append((int(pid_text), command))
    if len(matches) != 1 or matches[0][0] <= 1:
        raise LabError(f"expected exactly one Files process, observed {matches!r}")
    return matches[0]


def resolve_trace_target(ssh: SSH, target: str) -> tuple[int, str]:
    return resolve_files(ssh) if target == "Files" else resolve_target(ssh, target)


def output_path(target: str) -> str:
    return f"/var/tmp/cyanide-icon-descriptor-{safe_target(target)}.log"


def build(target: str, bundle: str, output_token: str = "") -> Path:
    target = safe_target(target)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / f"cnd_icon_descriptor_trace_{target}.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_DESCRIPTOR_TRACE_OUTPUT_TOKEN="{c_literal(output_token)}"',
        f'-DCND_DESCRIPTOR_TRACE_OUTPUT_PATH="{c_literal(output_path(target))}"',
        f'-DCND_DESCRIPTOR_TRACE_TARGET_BUNDLE="{c_literal(bundle)}"',
        f'-DCND_DESCRIPTOR_TRACE_HOST="{c_literal(target)}"',
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def read_report(ssh: SSH, target: str) -> str:
    path = output_path(target)
    return ssh.command(
        f"if test -f {shlex.quote(path)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(path)}; "
        "else echo '[CND_DESCRIPTOR] report-not-created'; fi"
    )


def inject(ssh: SSH, target: str, bundle: str) -> tuple[int, str]:
    target = safe_target(target)
    pid, command = resolve_trace_target(ssh, target)
    token = issue_file_extension(ssh, "/var/tmp")
    payload = build(target, bundle, token)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-icon-descriptor-{target}-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, _ = resolve_trace_target(ssh, target)
    if current_pid != pid or pid <= 1:
        raise LabError(
            f"refusing: {target} identity changed before injection "
            f"({pid} -> {current_pid})"
        )
    report = output_path(target)
    inject_log = f"/var/tmp/cyanide-icon-descriptor-{target}-inject.log"
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(report)} "
        f"{shlex.quote(inject_log)}; "
        f"current=$(/bin/ps -p {pid} -o command=); "
        + (
            f"case \"$current\" in */Files.app/Files|*/Files.app/Files\\ *) ;; "
            f"*) echo 'target identity changed' >&2; exit 90;; esac; "
            if target == "Files" else
            f"case \"$current\" in "
            f"{shlex.quote(TARGETS[target])}|"
            f"{shlex.quote(TARGETS[target] + ' ')}*) ;; "
            f"*) echo 'target identity changed' >&2; exit 90;; esac; "
        )
        +
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(inject_log)} 2>&1; status=$?; "
        f"if test \"$status\" = 124 -o \"$status\" = 137; then "
        f"echo timed-out; exit 0; fi; exit \"$status\""
    )
    deadline = time.monotonic() + 10.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh, target)
        match = re.search(
            rf"TRACE_READY host={re.escape(target)} pid={pid} hooks=([0-9]+)",
            latest,
        )
        if match and int(match.group(1)) >= 2:
            return pid, remote
        time.sleep(0.25)
    raise LabError(
        f"{target} descriptor trace did not become ready; report follows:\n"
        + latest.rstrip()
    )


def mark(ssh: SSH, target: str, label: str) -> None:
    target = safe_target(target)
    clean = re.sub(r"[^A-Za-z0-9_.:-]+", "-", label).strip("-")
    if not clean:
        raise LabError("marker must contain at least one safe character")
    path = output_path(target)
    ssh.command(
        f"printf '%s\\n' "
        f"{shlex.quote('[CND_DESCRIPTOR] MARK ' + clean)} >>"
        f"{shlex.quote(path)}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "inject", "read", "mark"))
    parser.add_argument("target", choices=("SpringBoard", "Spotlight", "Files"))
    parser.add_argument("label", nargs="?", default="")
    parser.add_argument("--bundle", default="com.ebay.iphone")
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    args = parser.parse_args()

    if args.action == "build":
        print(build(args.target, args.bundle))
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this trace requires vPhone root SSH")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh, args.target), end="")
        return 0
    if args.action == "mark":
        mark(ssh, args.target, args.label)
        return 0
    pid, remote = inject(ssh, args.target, args.bundle)
    print(
        f"descriptor trace ready target={args.target} pid={pid} "
        f"payload={remote} report={output_path(args.target)}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
