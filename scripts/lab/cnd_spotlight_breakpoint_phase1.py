#!/usr/bin/env python3
"""Build and inject the read-only Spotlight breakpoint Phase-1 probe."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import time
from collections import Counter
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
SOURCE = REPO_ROOT / "scripts/lab/cnd_spotlight_breakpoint_phase1.m"
BUILD_DIR = REPO_ROOT / "build/lab-spotlight-breakpoint-phase1"
REPORT_PATH = "/var/tmp/cyanide-spotlight-breakpoint-phase1.log"
INJECT_LOG_PATH = "/var/tmp/cyanide-spotlight-breakpoint-phase1-inject.log"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_probe(output_token: str = "") -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_spotlight_breakpoint_phase1.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
        f'-DCND_BP_PHASE1_OUTPUT_TOKEN="{c_literal(output_token)}"',
        f'-DCND_BP_PHASE1_REPORT_PATH="{c_literal(REPORT_PATH)}"',
        str(SOURCE), "-framework", "Foundation", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT_PATH)}; "
        "else echo '[CND_BP_PHASE1] report-not-created'; fi"
    )


def summarize(report: str) -> str:
    event_pattern = re.compile(
        r"\[CND_BP_PHASE1\] DESERIALIZE event=(\d+).*?"
        r"tid=(\d+) mach=0x([0-9a-fA-F]+).*?main=(\d+).*?"
        r"queue=([^ ]+)"
    )
    events = event_pattern.findall(report)
    contract_match = re.findall(
        r"\[CND_BP_PHASE1\] CONTRACT status=([^ ]+)", report
    )
    contract = contract_match[-1] if contract_match else "missing"
    if not events:
        return (
            "[CND_BP_PHASE1] SUMMARY contract=" + contract +
            " events=0 uniqueThreads=0 stable=unknown "
            "action=recreate-visible-Spotlight-rows\n"
        )
    threads = Counter(event[1] for event in events)
    main_threads = {event[1] for event in events if event[3] == "1"}
    queues = sorted({event[4] for event in events})
    dominant_tid, dominant_count = threads.most_common(1)[0]
    stable = "yes" if len(threads) == 1 else "no"
    distribution = ",".join(
        f"{thread_id}:{count}" for thread_id, count in threads.most_common()
    )
    return (
        f"[CND_BP_PHASE1] SUMMARY contract={contract} events={len(events)} "
        f"uniqueThreads={len(threads)} stable={stable} "
        f"dominantTid={dominant_tid} dominantEvents={dominant_count} "
        f"mainThreadHits={sum(1 for event in events if event[3] == '1')} "
        f"mainThreadIDs={','.join(sorted(main_threads)) or '-'} "
        f"queues={','.join(queues) or '-'} distribution={distribution}\n"
    )


def inject(ssh: SSH, payload: Path, pid: int) -> str:
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-spotlight-breakpoint-phase1-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, command = resolve_target(ssh, "Spotlight")
    if current_pid != pid or command != TARGETS["Spotlight"] or pid <= 1:
        raise LabError("Spotlight identity changed before Phase-1 injection")
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT_PATH)} "
        f"{shlex.quote(INJECT_LOG_PATH)}; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG_PATH)} 2>&1; status=$?; "
        'if test "$status" = 124 -o "$status" = 137; then '
        'exit 0; fi; exit "$status"'
    )
    return remote


def wait_ready(ssh: SSH, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    report = ""
    while time.monotonic() < deadline:
        report = read_report(ssh)
        if "[CND_BP_PHASE1] READY" in report:
            return report
        if "[CND_BP_PHASE1] LOAD_REJECTED" in report or \
                "[CND_BP_PHASE1] OBSERVER_REJECTED" in report:
            break
        time.sleep(0.25)
    injection = ssh.command(
        f"if test -f {shlex.quote(INJECT_LOG_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(INJECT_LOG_PATH)}; fi"
    ).strip()
    raise LabError(
        f"Phase-1 probe did not become ready:\n{report.rstrip()}\n"
        f"inject-log:\n{injection}"
    )


def make_ssh(args: argparse.Namespace) -> SSH:
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this probe requires vPhone root SSH")
    if not args.known_hosts.is_file():
        raise LabError(f"known-hosts file does not exist: {args.known_hosts}")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    return ssh


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "run", "read", "watch"),
                        nargs="?", default="run")
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--wait", type=float, default=8.0)
    parser.add_argument("--observe", type=float, default=20.0)
    args = parser.parse_args()

    if args.action == "build":
        print(build_probe())
        return 0
    ssh = make_ssh(args)
    if args.action == "read":
        report = read_report(ssh)
        print(report, end="")
        print(summarize(report), end="")
        return 0
    if args.action == "watch":
        deadline = time.monotonic() + max(args.observe, 0.0)
        initial = read_report(ssh)
        initial_events = initial.count("[CND_BP_PHASE1] DESERIALIZE")
        report = initial
        while time.monotonic() < deadline:
            time.sleep(0.25)
            report = read_report(ssh)
            if report.count("[CND_BP_PHASE1] DESERIALIZE") > initial_events:
                initial_events = report.count("[CND_BP_PHASE1] DESERIALIZE")
                print(summarize(report), end="")
        print(report, end="")
        print(summarize(report), end="")
        return 0

    pid, command = resolve_target(ssh, "Spotlight")
    output_token = issue_file_extension(ssh, "/var/tmp")
    payload = build_probe(output_token)
    remote = inject(ssh, payload, pid)
    report = wait_ready(ssh, args.wait)
    print(
        f"Spotlight breakpoint Phase-1 probe resident pid={pid} "
        f"command={command} payload={remote}"
    )
    print(report, end="")
    print(summarize(report), end="")
    print(
        "Recreate several visible Spotlight rows, dismiss/reopen Spotlight, "
        "then run this script with the 'read' action."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
