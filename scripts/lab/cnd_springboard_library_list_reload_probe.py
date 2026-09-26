#!/usr/bin/env python3
"""Invoke the live App Library list's bounded visible-cell reload once."""

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
    require_vphone,
    resolve_target,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_springboard_library_list_reload_probe.m"
BUILD_DIR = REPO_ROOT / "build/lab-springboard-library-list-reload-probe"
TRACE_REPORT = "/var/tmp/cyanide-springboard-surface-trace.log"
CONTROLLER_PATTERN = re.compile(
    rb"event=library-list-configure-(?:begin|end).*?"
    rb"controller=(0x[0-9a-fA-F]+)/SBHIconLibraryTableViewController"
)


def read_trace(ssh: SSH) -> bytes:
    if ssh.file_kind(TRACE_REPORT) != "file":
        raise LabError("the SpringBoard surface trace is not present")
    return ssh.read_file(TRACE_REPORT)


def latest_controller(trace: bytes) -> int:
    matches = list(CONTROLLER_PATTERN.finditer(trace))
    if not matches:
        raise LabError(
            "no live SBHIconLibraryTableViewController was observed; "
            "open the App Library alphabetical/search list first"
        )
    return int(matches[-1].group(1), 16)


def count_event(trace: bytes, event: bytes) -> int:
    return trace.count(event)


def count_descriptor_returns(trace: bytes, bundle: str) -> int:
    bundle_field = f"bundle={bundle} ".encode("utf-8")
    return sum(
        1 for line in trace.splitlines()
        if b"event=descriptor-image-return" in line and
        bundle_field in line
    )


def latest_icon(trace: bytes, bundle: str) -> int:
    pattern = re.compile(
        rb"event=library-list-configure-(?:begin|end).*?"
        rb"icon=(0x[0-9a-fA-F]+)/SBApplicationIcon id=" +
        re.escape(bundle.encode("utf-8")) + rb"(?: |\n)"
    )
    matches = list(pattern.finditer(trace))
    if not matches:
        raise LabError(
            f"no live list row was observed for {bundle}; make that row "
            "visible and retry"
        )
    return int(matches[-1].group(1), 16)


def build(controller: int, purge_cache: bool, action: int, icon: int) -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_springboard_library_list_reload_probe.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f"-DCND_LIBRARY_LIST_CONTROLLER_ADDRESS=0x{controller:x}ULL",
        f"-DCND_LIBRARY_LIST_PURGE_CACHE={1 if purge_cache else 0}",
        f"-DCND_LIBRARY_LIST_ACTION={action}",
        f"-DCND_LIBRARY_LIST_ICON_ADDRESS=0x{icon:x}ULL",
        str(SOURCE), "-framework", "Foundation", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def inject_once(ssh: SSH, pid: int, payload: Path) -> str:
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-library-list-reload-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, _ = resolve_target(ssh, "SpringBoard")
    if current_pid != pid:
        raise LabError(
            f"SpringBoard changed before the one-shot reload ({pid} -> "
            f"{current_pid})"
        )
    expected = TARGETS["SpringBoard"]
    log = "/var/tmp/cyanide-library-list-reload-inject.log"
    ssh.command(
        f"current=$(/bin/ps -p {pid} -o command=); "
        f"case \"$current\" in "
        f"{shlex.quote(expected)}|{shlex.quote(expected + ' ')}*) ;; "
        f"*) echo 'target identity changed' >&2; exit 90;; esac; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(log)} 2>&1; status=$?; "
        f"if test \"$status\" = 124 -o \"$status\" = 137; then "
        f"exit 0; fi; exit \"$status\""
    )
    return remote


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument(
        "--purge-cache", action="store_true",
        help="purge the list controller's icon cache before the reload",
    )
    parser.add_argument(
        "--action", choices=(
            "reload-visible", "reload-apps", "refresh-icon", "reload-icon",
        ),
        default="reload-visible",
    )
    parser.add_argument("--bundle", default="com.apple.shortcuts")
    args = parser.parse_args()
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this probe requires vPhone root SSH")

    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    pid, _ = resolve_target(ssh, "SpringBoard")
    before = read_trace(ssh)
    ready = f"TRACE_READY pid={pid} ok=1".encode()
    if ready not in before:
        raise LabError("the active SpringBoard does not own the ready trace")
    controller = latest_controller(before)
    action_values = {
        "reload-visible": 0,
        "reload-apps": 1,
        "refresh-icon": 2,
        "reload-icon": 3,
    }
    action_events = {
        "reload-visible": b"event=library-list-reload-visible-begin",
        "reload-apps": b"event=library-list-reload-apps-begin",
        "refresh-icon": b"event=library-list-refresh-icon-begin",
        "reload-icon": b"event=icon-reload-begin",
    }
    action = action_values[args.action]
    icon = latest_icon(before, args.bundle) if action in (2, 3) else 0
    reload_event = action_events[args.action]
    reload_count = count_event(before, reload_event)
    descriptor_count = count_descriptor_returns(before, args.bundle)

    payload = build(controller, args.purge_cache, action, icon)
    remote = inject_once(ssh, pid, payload)
    deadline = time.monotonic() + 5.0
    after = before
    while time.monotonic() < deadline:
        after = read_trace(ssh)
        if count_event(after, reload_event) > reload_count:
            break
        time.sleep(0.1)
    else:
        raise LabError(
            f"the one-shot payload loaded, but {args.action} was not "
            "observed; the captured controller may no longer be live"
        )

    # Icon generation notifications refill their consumers asynchronously.
    # Allow that bounded work to finish before reporting descriptor rereads.
    time.sleep(0.75)
    after = read_trace(ssh)

    print(
        f"App Library list action observed action={args.action} pid={pid} "
        f"controller=0x{controller:x} payload={remote} "
        f"purged={1 if args.purge_cache else 0} "
        f"descriptor-returns="
        f"{count_descriptor_returns(after, args.bundle) - descriptor_count}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
