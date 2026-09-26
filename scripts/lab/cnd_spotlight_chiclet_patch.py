#!/usr/bin/env python3
"""Apply the iOS 26 IconRendering hidden-chiclet patch to one UI process."""

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
SOURCE = REPO_ROOT / "scripts/lab/cnd_spotlight_chiclet_patch.m"
BUILD_DIR = REPO_ROOT / "build/lab-spotlight-chiclet-patch"
TARGET_ARTIFACTS = {
    "Spotlight": (
        "/var/tmp/cyanide-spotlight-chiclet-patch.log",
        "/var/tmp/cyanide-spotlight-chiclet-patch-inject.log",
    ),
    "SpringBoard": (
        "/var/tmp/cyanide-springboard-chiclet-patch.log",
        "/var/tmp/cyanide-springboard-chiclet-patch-inject.log",
    ),
}


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_patch(target: str, scope: str,
                output_token: str = "") -> Path:
    report_path, _ = TARGET_ARTIFACTS[target]
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / (
        f"cnd_{target.lower()}_{scope}_chiclet_patch.dylib"
    )
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-Wall", "-Wextra", "-Werror",
        f'-DCND_CHICLET_OUTPUT_TOKEN="{c_literal(output_token)}"',
        f'-DCND_CHICLET_REPORT_PATH="{c_literal(report_path)}"',
        f"-DCND_CHICLET_THEMED_ONLY={int(scope == 'themed')}",
        str(SOURCE), "-framework", "Foundation", "-framework",
        "QuartzCore", "-framework", "CoreGraphics", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def read_report(ssh: SSH, target: str) -> str:
    report_path, _ = TARGET_ARTIFACTS[target]
    return ssh.command(
        f"if test -f {shlex.quote(report_path)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(report_path)}; "
        "else echo '[CND_CHICLET_PATCH] report-not-created'; fi"
    )


def inject(ssh: SSH, payload: Path, pid: int, target: str) -> str:
    report_path, inject_log_path = TARGET_ARTIFACTS[target]
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = (
        f"/var/tmp/cnd-{target.lower()}-chiclet-patch-{digest}.dylib"
    )
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, command = resolve_target(ssh, target)
    if current_pid != pid or command != TARGETS[target] or pid <= 1:
        raise LabError(f"{target} identity changed before chiclet patch")
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(report_path)} "
        f"{shlex.quote(inject_log_path)}; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(inject_log_path)} 2>&1; status=$?; "
        'if test "$status" = 124 -o "$status" = 137; then '
        'exit 0; fi; exit "$status"'
    )
    return remote


def wait_ready(ssh: SSH, target: str, timeout: float) -> str:
    _, inject_log_path = TARGET_ARTIFACTS[target]
    deadline = time.monotonic() + timeout
    report = ""
    while time.monotonic() < deadline:
        report = read_report(ssh, target)
        if "[CND_CHICLET_PATCH] READY" in report:
            return report
        if "[CND_CHICLET_PATCH] PATCH_REJECTED" in report:
            break
        time.sleep(0.25)
    injection = ssh.command(
        f"if test -f {shlex.quote(inject_log_path)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(inject_log_path)}; fi"
    ).strip()
    raise LabError(
        f"chiclet patch did not become ready:\n{report.rstrip()}\n"
        f"inject-log:\n{injection}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "run", "read"),
                        nargs="?", default="run")
    parser.add_argument("--target", choices=tuple(TARGET_ARTIFACTS),
                        default="Spotlight")
    parser.add_argument("--scope", choices=("themed", "global"),
                        default="themed")
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--wait", type=float, default=8.0)
    args = parser.parse_args()

    if args.action == "build":
        print(build_patch(args.target, args.scope))
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this patch requires vPhone root SSH")
    if not args.known_hosts.is_file():
        raise LabError(f"known-hosts file does not exist: {args.known_hosts}")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh, args.target), end="")
        return 0

    pid, command = resolve_target(ssh, args.target)
    output_token = issue_file_extension(ssh, "/var/tmp")
    payload = build_patch(args.target, args.scope, output_token)
    remote = inject(ssh, payload, pid, args.target)
    report = wait_ready(ssh, args.target, args.wait)
    print(
        f"{args.target} chiclet patch active pid={pid} scope={args.scope} "
        f"command={command} "
        f"payload={remote}"
    )
    print(report, end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
