#!/usr/bin/env python3
"""Build, inject, and read the bounded SpringBoard app-install trace."""

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
SOURCE = REPO_ROOT / "scripts/lab/cnd_springboard_install_invalidation_trace.m"
BUILD_DIR = REPO_ROOT / "build/lab-springboard-install-invalidation"
REPORT = "/var/tmp/cyanide-springboard-install-invalidation.log"
INJECT_LOG = "/var/tmp/cyanide-springboard-install-invalidation-inject.log"
EXPECTED_HOOKS = 23


def validate_bundle(bundle: str) -> str:
    if len(bundle) > 200 or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)+",
        bundle,
    ):
        raise LabError("bundle must be one explicit bundle identifier")
    return bundle


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build(output_token: str = "", target_bundle: str = "com.apple.MobileSMS") -> Path:
    target_bundle = validate_bundle(target_bundle)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_springboard_install_invalidation_trace.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_INSTALL_TRACE_OUTPUT_TOKEN="{c_literal(output_token)}"',
        f'-DCND_INSTALL_TRACE_OUTPUT_PATH="{c_literal(REPORT)}"',
        f'-DCND_INSTALL_TRACE_TARGET_BUNDLE="{c_literal(target_bundle)}"',
        str(SOURCE), "-framework", "Foundation", "-framework",
        "CoreGraphics", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT)}; "
        "else echo '[CND_INSTALL] report-not-created'; fi"
    )


def inject(ssh: SSH, target_bundle: str) -> tuple[int, str, str]:
    pid, command = resolve_target(ssh, "SpringBoard")
    token = issue_file_extension(ssh, "/var/tmp")
    payload = build(token, target_bundle)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-springboard-install-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, _ = resolve_target(ssh, "SpringBoard")
    if current_pid != pid or pid <= 1:
        raise LabError(
            "refusing: SpringBoard identity changed before injection "
            f"({pid} -> {current_pid})"
        )
    expected = TARGETS["SpringBoard"]
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT)} "
        f"{shlex.quote(INJECT_LOG)}; "
        f"current=$(/bin/ps -p {pid} -o command=); "
        f"case \"$current\" in "
        f"{shlex.quote(expected)}|{shlex.quote(expected + ' ')}*) ;; "
        f"*) echo 'target identity changed' >&2; exit 90;; esac; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG)} 2>&1; status=$?; "
        f"if test \"$status\" = 124 -o \"$status\" = 137; then "
        "exit 0; fi; exit \"$status\""
    )
    deadline = time.monotonic() + 10.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        matches = re.findall(
            r"TRACE_READY .* hooks=([0-9]+) expected=([0-9]+) complete=([01])",
            latest,
        )
        if matches:
            hooks, expected_hooks, complete = matches[-1]
            if (int(hooks) != EXPECTED_HOOKS or
                    int(expected_hooks) != EXPECTED_HOOKS or complete != "1"):
                raise LabError(
                    "SpringBoard install trace rejected one or more runtime "
                    "method ABIs; report follows:\n" + latest.rstrip()
                )
            return pid, command, remote
        time.sleep(0.25)
    raise LabError(
        "SpringBoard install trace did not become ready; report follows:\n"
        + latest.rstrip()
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "inject", "read"))
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--bundle", default="com.apple.MobileSMS",
                        type=validate_bundle)
    args = parser.parse_args()

    if args.action == "build":
        print(build(target_bundle=args.bundle))
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this trace requires vPhone root SSH")
    if not args.known_hosts.is_file():
        raise LabError(f"known-hosts file does not exist: {args.known_hosts}")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh), end="")
        return 0
    pid, command, remote = inject(ssh, args.bundle)
    print(
        f"SpringBoard install trace ready pid={pid} command={command} "
        f"payload={remote} report={REPORT} bundle={args.bundle}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
