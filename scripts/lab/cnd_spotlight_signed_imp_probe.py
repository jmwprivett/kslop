#!/usr/bin/env python3
"""Dump signed IconRendering IMP candidates from the vPhone Spotlight host."""

from __future__ import annotations

import argparse
import hashlib
import os
import shlex
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
SOURCE = REPO_ROOT / "scripts/lab/cnd_spotlight_signed_imp_probe.m"
BUILD_DIR = REPO_ROOT / "build/lab-signed-imp-probe"
REPORT_PATH = "/var/tmp/cyanide-spotlight-signed-imp-probe.log"
INJECT_LOG_PATH = "/var/tmp/cyanide-spotlight-signed-imp-inject.log"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_probe(output_token: str, mutate: bool, flat_pref: bool,
                force_opaque_report: bool, remove_prominence: bool,
                set_query: bool, query_text: str) -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_spotlight_signed_imp_probe.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
        "-Wno-deprecated-declarations",
        f"-DCND_SIGNED_IMP_MUTATE={1 if mutate else 0}",
        f"-DCND_SIGNED_IMP_FLAT_PREF={1 if flat_pref else 0}",
        f"-DCND_SIGNED_IMP_FORCE_OPAQUE_REPORT="
        f"{1 if force_opaque_report else 0}",
        f"-DCND_SIGNED_IMP_REMOVE_PROMINENCE="
        f"{1 if remove_prominence else 0}",
        f"-DCND_SIGNED_IMP_SET_QUERY={1 if set_query else 0}",
        f'-DCND_SIGNED_IMP_QUERY_TEXT="{c_literal(query_text)}"',
        f'-DCND_SIGNED_IMP_OUTPUT_TOKEN="{c_literal(output_token)}"',
        str(SOURCE), "-framework", "Foundation", "-framework",
        "QuartzCore", "-framework", "UIKit", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--mutate", action="store_true")
    parser.add_argument("--flat-pref", action="store_true")
    parser.add_argument("--force-opaque-report", action="store_true")
    parser.add_argument("--remove-prominence", action="store_true")
    parser.add_argument("--set-query", action="store_true")
    parser.add_argument("--query", default="eBay")
    args = parser.parse_args()
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    pid, command = resolve_target(ssh, "Spotlight")
    if command != TARGETS["Spotlight"]:
        raise LabError("Spotlight identity mismatch")
    payload = build_probe(
        issue_file_extension(ssh, "/var/tmp"), args.mutate, args.flat_pref,
        args.force_opaque_report, args.remove_prominence, args.set_query,
        args.query)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-spotlight-signed-imp-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT_PATH)} "
        f"{shlex.quote(INJECT_LOG_PATH)} && "
        f"/var/jb/usr/bin/timeout -k 2 20 /iosbinpack64/bin/opainject "
        f"{pid} {shlex.quote(remote)} >{shlex.quote(INJECT_LOG_PATH)} 2>&1; "
        f"status=$?; if test \"$status\" = 124 -o \"$status\" = 137; "
        f"then status=0; fi; exit \"$status\""
    )
    if args.set_query:
        ssh.command("/iosbinpack64/bin/sleep 1")
    report = ssh.command(
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT_PATH)}"
    )
    print(f"Spotlight signed-IMP probe pid={pid} payload={remote}")
    print(report, end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
