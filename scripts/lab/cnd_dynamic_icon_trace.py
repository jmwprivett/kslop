#!/usr/bin/env python3
"""Build, inject, and read the vPhone Clock/Calendar lifecycle trace."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import struct
import time
import zipfile
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
SOURCE = REPO_ROOT / "scripts/lab/cnd_dynamic_icon_trace.m"
BUILD_DIR = REPO_ROOT / "build/lab-dynamic-icon-trace"
REPORT = "/var/tmp/cyanide-dynamic-icon-trace.log"
INJECT_LOG = "/var/tmp/cyanide-dynamic-icon-trace-inject.log"
TRACE_TARGETS = ("SpringBoard", "Spotlight")
SPOTLIGHT_REPORT = "/var/tmp/cyanide-dynamic-icon-trace-spotlight.log"
SPOTLIGHT_INJECT_LOG = "/var/tmp/cyanide-dynamic-icon-trace-spotlight-inject.log"
DEFAULT_THEME = REPO_ROOT / "purple accent pulsar.theme.zip"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def trace_paths(target: str) -> tuple[str, str]:
    if target == "SpringBoard":
        return REPORT, INJECT_LOG
    if target == "Spotlight":
        return SPOTLIGHT_REPORT, SPOTLIGHT_INJECT_LOG
    raise LabError(f"unsupported dynamic icon trace target: {target}")


def build(output_token: str = "", inventory_only: bool = False,
          target: str = "SpringBoard",
          clock_leaf_probe: bool = False) -> Path:
    report, _ = trace_paths(target)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    mode = "inventory" if inventory_only else "trace"
    target_suffix = "_spotlight" if target == "Spotlight" else ""
    output = BUILD_DIR / f"cnd_dynamic_icon{target_suffix}_{mode}.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_DYNAMIC_TRACE_OUTPUT_TOKEN="{c_literal(output_token)}"',
        f'-DCND_DYNAMIC_TRACE_OUTPUT_PATH="{c_literal(report)}"',
        f"-DCND_DYNAMIC_TRACE_INVENTORY_ONLY={1 if inventory_only else 0}",
        f"-DCND_DYNAMIC_TRACE_CLOCK_LEAF_PROBE="
        f"{1 if clock_leaf_probe else 0}",
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "QuartzCore", "-framework", "CoreGraphics",
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def read_report(ssh: SSH, target: str = "SpringBoard") -> str:
    report, _ = trace_paths(target)
    return ssh.command(
        f"if test -f {shlex.quote(report)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(report)}; "
        "else echo '[CND_DYNAMIC] report-not-created'; fi"
    )


def inject(ssh: SSH, inventory_only: bool,
           target: str = "SpringBoard",
           clock_leaf_probe: bool = False) -> tuple[int, str]:
    report, inject_log = trace_paths(target)
    pid, command = resolve_target(ssh, target)
    if command != TARGETS[target]:
        raise LabError(f"{target} identity mismatch")
    token = issue_file_extension(ssh, "/var/tmp")
    payload = (build(token, inventory_only, target, True)
               if clock_leaf_probe
               else build(token, inventory_only, target))
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    mode = "inventory" if inventory_only else "trace"
    remote = f"/var/tmp/cnd-dynamic-icon-{mode}-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, current_command = resolve_target(ssh, target)
    if current_pid != pid or current_command != TARGETS[target]:
        raise LabError(
            f"refusing: {target} identity changed before injection "
            f"({pid} -> {current_pid})"
        )
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(report)} "
        f"{shlex.quote(inject_log)}; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(inject_log)} 2>&1; status=$?; "
        f"if test \"$status\" = 124 -o \"$status\" = 137; then "
        f"exit 0; fi; exit \"$status\""
    )
    deadline = time.monotonic() + 10.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh, target)
        match = re.search(
            rf"TRACE_READY pid={pid} classes=[0-9]+ hooks=([0-9]+) ", latest
        )
        if match and (inventory_only or int(match.group(1)) > 0):
            return pid, remote
        time.sleep(0.25)
    raise LabError(
        f"{target} Clock/Calendar trace did not become ready; report follows:\n"
        + latest.rstrip()
    )


def mark(ssh: SSH, label: str, target: str = "SpringBoard") -> None:
    report, _ = trace_paths(target)
    clean = re.sub(r"[^A-Za-z0-9_.:-]+", "-", label).strip("-")
    if not clean:
        raise LabError("marker must contain at least one safe character")
    ssh.command(
        f"printf '%s\\n' "
        f"{shlex.quote('[CND_DYNAMIC] MARK ' + clean)} >>"
        f"{shlex.quote(report)}"
    )


def png_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return struct.unpack(">II", data[16:24])


def print_theme_assets(path: Path) -> None:
    if not path.is_file():
        raise LabError(f"theme archive not found: {path}")
    wanted = re.compile(
        r"(ClockIcon|com\.apple\.(mobiletimer|mobilecal))", re.IGNORECASE
    )
    with zipfile.ZipFile(path) as archive:
        entries = [name for name in archive.namelist() if wanted.search(name)]
        for name in sorted(entries, key=str.casefold):
            data = archive.read(name)
            dimensions = png_dimensions(data)
            size = f"{dimensions[0]}x{dimensions[1]}" if dimensions else "-"
            digest = hashlib.sha256(data).hexdigest()
            print(f"{name}\t{size}\t{len(data)}\t{digest}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("build", "inventory", "inject", "read", "mark",
                           "theme-assets")
    )
    parser.add_argument("label", nargs="?", default="")
    parser.add_argument("--target", choices=TRACE_TARGETS,
                        default="SpringBoard")
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--theme", type=Path, default=DEFAULT_THEME)
    parser.add_argument(
        "--clock-leaf-probe", action="store_true",
        help="issue one bounded 68pt request on the exact clock.base leaf",
    )
    args = parser.parse_args()

    if args.action == "build":
        print(build(target=args.target,
                    clock_leaf_probe=args.clock_leaf_probe))
        return 0
    if args.action == "theme-assets":
        print_theme_assets(args.theme)
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
        mark(ssh, args.label, args.target)
        return 0
    inventory_only = args.action == "inventory"
    pid, remote = inject(ssh, inventory_only, args.target,
                         args.clock_leaf_probe)
    report, _ = trace_paths(args.target)
    print(
        f"{args.target} Clock/Calendar "
        f"{'inventory' if inventory_only else 'trace'} ready "
        f"pid={pid} payload={remote} report={report} no-window-walk=yes"
        f" clock-leaf-probe={str(args.clock_leaf_probe).lower()}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
