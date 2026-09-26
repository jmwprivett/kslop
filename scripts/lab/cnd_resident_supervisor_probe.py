#!/usr/bin/env python3
"""Build and exercise the VM-only SpringBoard resident-supervisor probe."""

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
SOURCE = REPO_ROOT / "scripts/lab/cnd_resident_supervisor_probe.m"
ANCHOR_SOURCE = REPO_ROOT / "scripts/lab/cnd_fileport_anchor_probe.c"
BUILD_DIR = REPO_ROOT / "build/lab-resident-supervisor"
REPORT = "/var/tmp/cyanide-resident-supervisor.log"
HEARTBEAT = "/var/tmp/cyanide-resident-supervisor.heartbeat"
STOP = "/var/tmp/cyanide-resident-supervisor.stop"
SIMULATE = "/var/tmp/cyanide-resident-supervisor.simulate"
RELAUNCH_SPOTLIGHT = "/var/tmp/cyanide-resident-supervisor.relaunch-spotlight"
FILEPORT = "/var/tmp/cyanide-resident-supervisor.fileport"
INJECT_LOG = "/var/tmp/cyanide-resident-supervisor-inject.log"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def validate_bundle_identifier(value: str) -> str:
    if not value or len(value) > 255 or not all(
        char.isascii() and (char.isalnum() or char in ".-_")
        for char in value
    ):
        raise LabError("bundle must be one explicit bundle identifier")
    return value


def build(token: str = "", nonce: str = "0") -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / f"cnd_resident_supervisor_{nonce}.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_RESIDENT_SUPERVISOR_OUTPUT_TOKEN="{c_literal(token)}"',
        f'-DCND_RESIDENT_SUPERVISOR_NONCE="{c_literal(nonce)}"',
        str(SOURCE), "-framework", "Foundation", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def build_anchor() -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_fileport_anchor_probe"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-Wall", "-Wextra", "-Werror", str(ANCHOR_SOURCE),
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def read_path(ssh: SSH, path: str, missing: str) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(path)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(path)}; "
        f"else echo {shlex.quote(missing)}; fi"
    )


def read_report(ssh: SSH) -> str:
    return read_path(ssh, REPORT, "[CND_RESIDENT] report-not-created")


def read_heartbeat(ssh: SSH) -> str:
    return read_path(ssh, HEARTBEAT, "[CND_RESIDENT] heartbeat-not-created")


def wait_for(ssh: SSH, predicate, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if predicate(latest):
            return latest
        time.sleep(0.25)
    raise LabError("probe condition timed out:\n" + latest.rstrip())


def inject(ssh: SSH) -> tuple[int, str, str]:
    pid, command = resolve_target(ssh, "SpringBoard")
    if command != TARGETS["SpringBoard"] or pid <= 1:
        raise LabError("SpringBoard identity mismatch")
    token = issue_file_extension(ssh, "/var/tmp")
    nonce = str(time.time_ns())
    payload = build(token, nonce)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-resident-supervisor-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, current_command = resolve_target(ssh, "SpringBoard")
    if (current_pid, current_command) != (pid, command):
        raise LabError("SpringBoard identity changed before injection")
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT)} "
        f"{shlex.quote(HEARTBEAT)} {shlex.quote(STOP)} "
        f"{shlex.quote(SIMULATE)} {shlex.quote(RELAUNCH_SPOTLIGHT)} "
        f"{shlex.quote(FILEPORT)} {shlex.quote(INJECT_LOG)}; "
        f"current=$(/bin/ps -p {pid} -o command=); "
        f"case \"$current\" in {shlex.quote(command)}|"
        f"{shlex.quote(command + ' ')}*) ;; "
        "*) echo 'target identity changed' >&2; exit 90;; esac; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG)} 2>&1; status=$?; "
        "if test \"$status\" = 124 -o \"$status\" = 137; then "
        "exit 0; fi; exit \"$status\""
    )
    wait_for(
        ssh,
        lambda text: f"READY pid={pid} nonce={nonce}" in text
        and "[CND_RESIDENT] THREAD create=0 detach=0" in text,
        12.0,
    )
    return pid, remote, nonce


def heartbeat_count(text: str) -> int:
    marker = "count="
    if marker not in text:
        return -1
    value = text.split(marker, 1)[1].split(None, 1)[0]
    try:
        return int(value)
    except ValueError:
        return -1


def verify_heartbeat(ssh: SSH, wait: float) -> tuple[int, int]:
    before = heartbeat_count(read_heartbeat(ssh))
    time.sleep(wait)
    after = heartbeat_count(read_heartbeat(ssh))
    if before < 0 or after <= before:
        raise LabError(f"heartbeat did not advance: {before} -> {after}")
    return before, after


def simulate_update(ssh: SSH, bundle: str) -> str:
    identifier = validate_bundle_identifier(bundle)
    ssh.command(
        f"printf '%s\\n' {shlex.quote(identifier)} > {shlex.quote(SIMULATE)}"
    )
    return wait_for(
        ssh,
        lambda text: (
            f"APP_FINGERPRINT source=simulated-update bundle={identifier} "
            "sample=2"
        ) in text,
        8.0,
    )


def restart_spotlight(ssh: SSH) -> tuple[int, int, str]:
    old_pid, command = resolve_target(ssh, "Spotlight")
    if command != TARGETS["Spotlight"] or old_pid <= 1:
        raise LabError("Spotlight identity mismatch")
    ssh.command(
        f"current=$(/bin/ps -p {old_pid} -o command=); "
        f"case \"$current\" in {shlex.quote(command)}|"
        f"{shlex.quote(command + ' ')}*) ;; "
        "*) echo 'target identity changed' >&2; exit 90;; esac; "
        f"kill -9 {old_pid}"
    )
    ssh.command(f"printf 'launch\n' > {shlex.quote(RELAUNCH_SPOTLIGHT)}")
    deadline = time.monotonic() + 12.0
    new_pid = 0
    while time.monotonic() < deadline:
        try:
            candidate, candidate_command = resolve_target(ssh, "Spotlight")
        except LabError:
            time.sleep(0.2)
            continue
        if candidate != old_pid and candidate_command == command:
            new_pid = candidate
            break
        time.sleep(0.2)
    if new_pid <= 1:
        raise LabError(f"Spotlight did not replace PID {old_pid}")
    marker = (
        f"SPOTLIGHT_SETTLED source=frontboard-add pid={new_pid} stable=1"
    )
    report = wait_for(ssh, lambda text: marker in text, 15.0)
    time.sleep(0.75)
    report = read_report(ssh)
    if report.count(marker) != 1:
        raise LabError(
            f"expected one settled event for Spotlight PID {new_pid}, got "
            f"{report.count(marker)}"
        )
    return old_pid, new_pid, report


def recover_fileport(ssh: SSH) -> str:
    nonce = f"{time.time_ns():x}"
    service = f"com.zeroxjf.cyanide.lab.fileport.{nonce}"
    marker = f"cnd-fileport-{nonce}"
    data_path = f"/var/tmp/cnd-fileport-anchor-{nonce}.data"
    anchor = build_anchor()
    remote_anchor = f"/var/tmp/cnd-fileport-anchor-{nonce}"
    ssh.copy(anchor, remote_anchor)
    ssh.command(
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote_anchor)}"
    )
    try:
        token = ssh.command(
            f"{shlex.quote(remote_anchor)} {shlex.quote(service)} "
            f"{shlex.quote(marker)} {shlex.quote(data_path)}"
        ).strip()
        if not token or "\n" in token:
            raise LabError("anchor did not return one Mach lookup token")
        ssh.command(
            f"printf '%s\\n%s\\n%s\\n' {shlex.quote(service)} "
            f"{shlex.quote(marker)} {shlex.quote(token)} > "
            f"{shlex.quote(FILEPORT)}"
        )
        expected = f"FILEPORT_RECOVERY service={service}"
        return wait_for(
            ssh,
            lambda text: expected in text and "match=1" in text.split(
                expected, 1)[1].split("\n", 1)[0],
            8.0,
        )
    finally:
        ssh.command(
            f"/iosbinpack64/bin/rm -f {shlex.quote(remote_anchor)} "
            f"{shlex.quote(data_path)} {shlex.quote(FILEPORT)}"
        )


def stop(ssh: SSH) -> str:
    ssh.command(f": > {shlex.quote(STOP)}")
    return wait_for(
        ssh,
        lambda text: "[CND_RESIDENT] STOPPED" in text,
        8.0,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "build", "inject", "read", "heartbeat", "simulate",
            "restart-spotlight", "fileport", "stop",
        ),
    )
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--bundle", default="com.ebay.iphone")
    parser.add_argument("--wait", type=float, default=3.0)
    args = parser.parse_args()

    if args.action == "build":
        print(build())
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("this proof requires vPhone root SSH")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh), end="")
    elif args.action == "heartbeat":
        before, after = verify_heartbeat(ssh, args.wait)
        print(f"heartbeat advanced {before} -> {after}")
        print(read_heartbeat(ssh), end="")
    elif args.action == "simulate":
        simulate_update(ssh, args.bundle)
        print(read_report(ssh), end="")
    elif args.action == "restart-spotlight":
        old_pid, new_pid, report = restart_spotlight(ssh)
        print(f"Spotlight replaced {old_pid} -> {new_pid}; one settled event")
        print(report, end="")
    elif args.action == "fileport":
        recover_fileport(ssh)
        print(read_report(ssh), end="")
    elif args.action == "stop":
        stop(ssh)
        print(read_report(ssh), end="")
    else:
        pid, remote, nonce = inject(ssh)
        before, after = verify_heartbeat(ssh, 2.0)
        print(
            f"resident supervisor ready pid={pid} nonce={nonce} "
            f"heartbeat={before}->{after} payload={remote}"
        )
        print(read_report(ssh), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
