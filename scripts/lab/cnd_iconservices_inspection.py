#!/usr/bin/env python3
"""Trace IconServices generation and lifecycle GC inside vPhone iconservicesagent."""

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
INSPECTOR_SOURCE = REPO_ROOT / "scripts/lab/cnd_iconservices_inspector.m"
HOLD_SOURCE = REPO_ROOT / "scripts/lab/cnd_iconservices_hold.c"
TRIGGER_SOURCE = REPO_ROOT / "scripts/lab/cnd_iconservices_trigger.m"
BUILD_DIR = REPO_ROOT / "build/lab-iconservices-inspection"
REPORT_PATH = "/var/tmp/cyanide-iconservices-inspection.log"
HOLD_LOG_PATH = "/var/tmp/cyanide-iconservices-hold.log"
INJECT_LOG_PATH = "/var/tmp/cyanide-iconservices-inject.log"
EXPECTED_HOOKS = 27


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def validate_bundle(bundle: str) -> str:
    if (len(bundle) > 200 or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)+",
        bundle,
    )):
        raise LabError("bundle must be one explicit bundle identifier")
    return bundle


def sign(path: Path) -> None:
    run(["codesign", "-s", "-", "--force", str(path)])


def build_hold() -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_iconservices_hold"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-Wall", "-Wextra", "-Werror", "-fblocks", str(HOLD_SOURCE),
        "-o", str(output),
    ])
    sign(output)
    return output


def build_trigger() -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_iconservices_trigger"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-Wall", "-Wextra", "-Werror", "-fobjc-arc", "-fblocks",
        str(TRIGGER_SOURCE), "-framework", "Foundation", "-framework",
        "CoreGraphics", "-framework", "ImageIO", "-o", str(output),
    ])
    sign(output)
    return output


def build_inspector(
    output_token: str = "",
    root_token: str = "",
    target_bundle: str = "com.apple.MobileSMS",
) -> Path:
    target_bundle = validate_bundle(target_bundle)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_iconservices_inspector.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-Wall", "-Wextra", "-Werror", "-fobjc-arc",
        "-fblocks",
        f'-DCND_ICON_INSPECT_OUTPUT_TOKEN="{c_literal(output_token)}"',
        f'-DCND_ICON_INSPECT_ROOT_TOKEN="{c_literal(root_token)}"',
        f'-DCND_ICON_INSPECT_TARGET_BUNDLE="{c_literal(target_bundle)}"',
        str(INSPECTOR_SOURCE), "-framework", "Foundation", "-framework",
        "CoreGraphics", "-o", str(output),
    ])
    sign(output)
    return output


def copy_executable(ssh: SSH, local: Path, prefix: str) -> str:
    digest = hashlib.sha256(local.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/{prefix}-{digest}"
    ssh.copy(local, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    return remote


def start_hold(ssh: SSH, executable: str) -> int:
    output = ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(HOLD_LOG_PATH)}; "
        f"/var/jb/usr/bin/nohup {shlex.quote(executable)} 60 "
        f">{shlex.quote(HOLD_LOG_PATH)} 2>&1 </dev/null & echo $!"
    ).strip()
    if not output.isdigit() or int(output) <= 1:
        raise LabError(f"could not start IconServices hold helper: {output}")
    pid = int(output)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        log = ssh.command(
            f"if test -f {shlex.quote(HOLD_LOG_PATH)}; then "
            f"/iosbinpack64/bin/cat {shlex.quote(HOLD_LOG_PATH)}; fi"
        )
        if "CND_ICON_HOLD_READY" in log:
            return pid
        time.sleep(0.25)
    command = ssh.command(f"/bin/ps -p {pid} -o command=").strip()
    if command == f"{executable} 60":
        ssh.command(f"kill {pid} 2>/dev/null || true")
    raise LabError("IconServices hold helper did not become ready")


def stop_hold(ssh: SSH, pid: int, executable: str) -> None:
    command = ssh.command(f"/bin/ps -p {pid} -o command=").strip()
    if command == f"{executable} 60":
        ssh.command(f"kill {pid} 2>/dev/null || true")


def inject(ssh: SSH, payload: Path, pid: int) -> str:
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-iconservices-inspector-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, _ = resolve_target(ssh, "iconservicesagent")
    if current_pid != pid or pid <= 1:
        raise LabError(
            f"refusing: iconservicesagent identity changed before injection "
            f"({pid} -> {current_pid})"
        )
    expected = TARGETS["iconservicesagent"]
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT_PATH)} "
        f"{shlex.quote(INJECT_LOG_PATH)}; "
        f"current=$(/bin/ps -p {pid} -o command=); "
        f"case \"$current\" in "
        f"{shlex.quote(expected)}|{shlex.quote(expected + ' ')}*) ;; "
        f"*) echo 'target identity changed' >&2; exit 90;; esac; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG_PATH)} 2>&1; status=$?; "
        f"if test \"$status\" = 124 -o \"$status\" = 137; then "
        f"echo timed-out; exit 0; fi; exit \"$status\""
    )
    return remote


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT_PATH)}; "
        "else echo '[CND_ICON_AGENT] report-not-created'; fi"
    )


def lifecycle_report(report: str) -> str:
    keep = (
        "[CND_ICON_AGENT] START ",
        "[CND_ICON_AGENT] TRACE_READY ",
        "[CND_ICON_AGENT] lifecycle ",
        "[CND_ICON_AGENT] registry-",
        "[CND_ICON_AGENT] local-cache ",
        "[CND_ICON_AGENT] descriptor ",
        "[CND_ICON_AGENT] image ",
    )
    lines = [line for line in report.splitlines()
             if line.startswith(keep)]
    return "\n".join(lines) + ("\n" if lines else "")


def wait_ready(ssh: SSH, timeout: float = 8.0) -> str:
    deadline = time.monotonic() + timeout
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        matches = re.findall(r"TRACE_READY .* hooks=([0-9]+)", latest)
        if matches and int(matches[-1]) >= EXPECTED_HOOKS:
            return latest
        time.sleep(0.25)
    raise LabError(
        "IconServices inspector did not install enough hooks; report follows:\n"
        + latest.rstrip()
    )


def run_trigger(
    ssh: SSH,
    executable: str,
    bundle: str,
    ignore_cache: bool,
) -> str:
    suffix = " --ignore-cache" if ignore_cache else ""
    return ssh.command(
        f"{shlex.quote(executable)} --bundle {shlex.quote(bundle)}{suffix}"
    )


def relevant_event_count(report: str) -> int:
    prefixes = (
        "[CND_ICON_AGENT] request label=",
        "[CND_ICON_AGENT] event ",
        "[CND_ICON_AGENT] store-unit label=",
        "[CND_ICON_AGENT] image label=",
        "[CND_ICON_AGENT] lifecycle ",
    )
    return sum(1 for line in report.splitlines()
               if line.startswith(prefixes))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "run", "watch", "read"),
                        nargs="?", default="run")
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--bundle", default="com.apple.MobileSMS",
                        type=validate_bundle,
                        help="bundle whose current LS identity is logged")
    parser.add_argument("--lifecycle-only", action="store_true",
                        help="print only lifecycle/GC events and readiness")
    args = parser.parse_args()

    if args.action == "build":
        print(build_hold())
        print(build_trigger())
        print(build_inspector(target_bundle=args.bundle))
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this harness requires root on SSH port 22222")
    if not args.known_hosts.is_file():
        raise LabError(f"known-hosts file does not exist: {args.known_hosts}")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        report = read_report(ssh)
        print(lifecycle_report(report) if args.lifecycle_only else report,
              end="")
        return 0

    hold = build_hold()
    trigger = build_trigger() if args.action == "run" else None
    output_token = issue_file_extension(ssh, "/var/tmp")
    root_token = issue_file_extension(ssh, "/private/var")
    inspector = build_inspector(output_token, root_token, args.bundle)
    remote_hold = copy_executable(ssh, hold, "cnd-iconservices-hold")
    remote_trigger = copy_executable(
        ssh, trigger, "cnd-iconservices-trigger") if trigger else None
    hold_pid = start_hold(ssh, remote_hold)
    try:
        deadline = time.monotonic() + 5.0
        while True:
            try:
                pid, command = resolve_target(ssh, "iconservicesagent")
                break
            except LabError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)
        remote_inspector = inject(ssh, inspector, pid)
        ready_report = wait_ready(ssh)
        if args.action == "watch":
            print(
                f"IconServices lifecycle watch target pid={pid} "
                f"command={command} payload={remote_inspector} "
                f"holdPID={hold_pid} bundle={args.bundle}"
            )
            print("--- agent report ---")
            print(lifecycle_report(ready_report), end="")
            return 0
        if remote_trigger is None:
            raise LabError("trigger was not built for run action")
        warm_output = run_trigger(ssh, remote_trigger, args.bundle, False)
        time.sleep(0.5)
        trace_output = run_trigger(ssh, remote_trigger, args.bundle, False)
        time.sleep(1.0)
        report = read_report(ssh)
        forced_output = ""
        forced = False
        if relevant_event_count(report) == 0:
            forced = True
            forced_output = run_trigger(
                ssh, remote_trigger, args.bundle, True)
            time.sleep(2.0)
            report = read_report(ssh)
        print(
            f"IconServices inspector target pid={pid} command={command} "
            f"payload={remote_inspector} holdPID={hold_pid} "
            f"forcedIgnoreCache={str(forced).lower()}"
        )
        print("--- warm trigger ---")
        print(warm_output.rstrip())
        print("--- trace trigger ---")
        print(trace_output.rstrip())
        if forced_output:
            print("--- forced trigger ---")
            print(forced_output.rstrip())
        print("--- agent report ---")
        print(report, end="")
    finally:
        stop_hold(ssh, hold_pid, remote_hold)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
