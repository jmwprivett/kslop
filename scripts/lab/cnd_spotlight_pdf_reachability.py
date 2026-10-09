#!/usr/bin/env python3
"""Build and inject the benign Spotlight CoreUI PDF reachability tracer."""

from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import sys
import time
from pathlib import Path

from cnd_iconservices_inspection import validate_bundle
from cnd_remotecall_lab import (
    DEFAULT_KNOWN_HOSTS,
    LabError,
    SSH,
    TARGETS,
    require_vphone,
    resolve_target,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_spotlight_pdf_reachability.m"
PUBLISHER = REPO_ROOT / "scripts/lab/cnd_iconservices_cache_theme.py"
BUILD_DIR = REPO_ROOT / "build/lab-spotlight-pdf-reachability"
REPORT = "/var/tmp/cyanide-spotlight-pdf-reachability.log"
INJECT_LOG = "/var/tmp/cyanide-spotlight-pdf-reachability-inject.log"
PASS_MARKERS = ("TRACE_READY", "CANARY_PDF_INIT", "CANARY_PDF_RENDER")


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build(query: str = "eBay", set_query: bool = True) -> Path:
    if not query or len(query) > 128 or "\n" in query or "\r" in query:
        raise LabError("query must be one nonempty line of at most 128 chars")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_spotlight_pdf_reachability.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_PDF_TRACE_QUERY="{c_literal(query)}"',
        f"-DCND_PDF_TRACE_SET_QUERY={int(set_query)}",
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def make_ssh(args: argparse.Namespace) -> SSH:
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this tracer requires vPhone root SSH:22222")
    if not args.known_hosts.is_file():
        raise LabError(f"known-hosts file missing: {args.known_hosts}")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    return ssh


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT)}; "
        "else echo '[CND_PDF_REACH] report-not-created'; fi"
    )


def inject(ssh: SSH, payload: Path, pid: int) -> str:
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-spotlight-pdf-reach-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, command = resolve_target(ssh, "Spotlight")
    if current_pid != pid or command != TARGETS["Spotlight"] or pid <= 1:
        raise LabError("Spotlight identity changed before tracer injection")
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT)} "
        f"{shlex.quote(INJECT_LOG)}; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG)} 2>&1; status=$?; "
        "if test \"$status\" = 124 -o \"$status\" = 137; then "
        "exit 0; fi; exit \"$status\""
    )
    return remote


def wait_for(ssh: SSH, marker: str, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    report = ""
    while time.monotonic() < deadline:
        report = read_report(ssh)
        if marker in report:
            return report
        time.sleep(0.25)
    injection = ssh.command(
        f"if test -f {shlex.quote(INJECT_LOG)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(INJECT_LOG)}; fi"
    ).strip()
    raise LabError(
        f"timed out waiting for {marker!r}:\n{report.rstrip()}\n"
        f"inject-log:\n{injection}"
    )


def validate_pass(report: str) -> None:
    missing = [marker for marker in PASS_MARKERS if marker not in report]
    if missing:
        raise LabError("PDF reachability did not pass; missing: " +
                       ", ".join(missing))


def publish_canary(args: argparse.Namespace) -> None:
    command = [
        sys.executable, str(PUBLISHER), "run",
        "--host", args.host,
        "--port", str(args.port),
        "--user", args.user,
        "--known-hosts", str(args.known_hosts),
        "--password-env", args.password_env,
        "--bundle", args.bundle,
        "--point-size", str(args.point_size),
        "--appearance", str(args.appearance),
        "--variant", str(args.variant),
        "--pdf-canary",
    ]
    result = run(command)
    print(result.stdout.decode("utf-8", "replace"), end="")


def restart_spotlight(ssh: SSH, timeout: float) -> tuple[int, int]:
    old_pid, command = resolve_target(ssh, "Spotlight")
    if command != TARGETS["Spotlight"] or old_pid <= 1:
        raise LabError("Spotlight identity mismatch before restart")
    ssh.command(
        f"current=$(/bin/ps -p {old_pid} -o command=); "
        f"case \"$current\" in {shlex.quote(command)}|"
        f"{shlex.quote(command + ' ')}*) ;; "
        "*) echo 'target identity changed' >&2; exit 90;; esac; "
        f"kill -9 {old_pid}"
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            new_pid, new_command = resolve_target(ssh, "Spotlight")
        except LabError:
            time.sleep(0.25)
            continue
        if new_pid != old_pid and new_command == command:
            return old_pid, new_pid
        time.sleep(0.25)
    raise LabError(
        f"Spotlight PID {old_pid} exited but did not relaunch within "
        f"{timeout:.0f}s; open Spotlight in the VM and rerun without --restart"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "run", "read", "wait"),
                        nargs="?", default="run")
    parser.add_argument("--host", default=None,
                        help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--bundle", default="com.ebay.iphone")
    parser.add_argument("--query", default="eBay")
    parser.add_argument("--no-set-query", action="store_true")
    parser.add_argument("--wait", type=float, default=60.0)
    parser.add_argument("--publish", action="store_true",
                        help="publish the benign persistent PDF canary first")
    parser.add_argument("--restart", action="store_true",
                        help="replace Spotlight and inject only into its new PID")
    parser.add_argument("--wait-for-render", action="store_true",
                        help="wait for the canary PDF render pass condition")
    parser.add_argument("--point-size", type=int, default=68)
    parser.add_argument("--appearance", type=int, choices=(0, 1), default=0)
    parser.add_argument("--variant", type=int, default=0)
    args = parser.parse_args()
    validate_bundle(args.bundle)
    if args.point_size <= 0 or args.point_size > 1024:
        raise LabError("point size must be in 1-1024")
    if args.variant < 0 or args.variant > 0x7fffffff:
        raise LabError("variant must be a nonnegative int32")

    if args.action == "build":
        print(build(args.query, not args.no_set_query))
        return 0
    ssh = make_ssh(args)
    if args.action == "read":
        print(read_report(ssh), end="")
        return 0
    if args.action == "wait":
        report = wait_for(ssh, "CANARY_PDF_RENDER", args.wait)
        validate_pass(report)
        print(report, end="")
        print("SPOTLIGHT_PDF_REACHABILITY_PASS")
        return 0

    if args.publish:
        if not args.host:
            raise LabError("--publish requires --host")
        publish_canary(args)
    if args.restart:
        old_pid, pid = restart_spotlight(ssh, args.wait)
        command = TARGETS["Spotlight"]
        print(f"Spotlight replaced oldPid={old_pid} newPid={pid}")
    else:
        pid, command = resolve_target(ssh, "Spotlight")
    payload = build(args.query, not args.no_set_query)
    remote = inject(ssh, payload, pid)
    report = wait_for(ssh, "TRACE_READY", 12.0)
    print(
        f"Spotlight PDF reachability tracer ready pid={pid} "
        f"command={command} payload={remote} bundle={args.bundle}"
    )
    print(report, end="")
    print(
        "Open Spotlight in the VM if it is not visible; the tracer will set "
        f"the query to {args.query!r} when its text field appears."
    )
    if args.wait_for_render:
        report = wait_for(ssh, "CANARY_PDF_RENDER", args.wait)
        validate_pass(report)
        print(report, end="")
        print("SPOTLIGHT_PDF_REACHABILITY_PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
