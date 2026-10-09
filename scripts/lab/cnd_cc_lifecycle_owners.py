#!/usr/bin/env python3
"""Explicit vPhone-only named ownership snapshots; optional VM discovery."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import time
from pathlib import Path

from cnd_remotecall_lab import (DEFAULT_KNOWN_HOSTS, LabError, SSH, TARGETS,
                              issue_file_extension, require_vphone, resolve_target, run)

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build/CCLifecycleOwnerVM-20261005-01"
SOURCE = ROOT / "scripts/lab/cnd_cc_lifecycle_owners.m"
SWIFT_SOURCE = ROOT / "scripts/lab/cnd_cc_owner_swift_reflection.swift"
REMOTE = "/var/tmp/cnd-cc-owner-traces"
REQUEST = "/var/tmp/cnd-cc-owner-request.json"


def build(pid: int = 0, token: str = "") -> Path:
    BUILD.mkdir(parents=True, exist_ok=True)
    output = BUILD / "cnd_cc_lifecycle_owners.dylib"
    sdk = run(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"]).stdout.decode().strip()
    objc = BUILD / "cnd_cc_lifecycle_owners.o"
    token = token.replace("\\", "\\\\").replace('"', '\\"')
    run(["xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e", "-c",
         "-fobjc-arc", "-fblocks", "-Wall", "-Wextra", "-Werror",
         f"-DCND_CC_OWNER_EXPECTED_PID={pid}", f'-DCND_CC_OWNER_OUTPUT_TOKEN="{token}"',
         str(SOURCE), "-o", str(objc)])
    run(["xcrun", "swiftc", "-emit-library", "-target", "arm64e-apple-ios26.0", "-sdk", sdk,
         str(SWIFT_SOURCE), str(objc), "-framework", "Foundation", "-framework", "UIKit",
         "-framework", "QuartzCore", "-o", str(output)])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def phase_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,95}", value):
        raise LabError("phase must be 1–95 ASCII letters, digits, underscore or hyphen")
    return value


def request(ssh: SSH, body: dict) -> None:
    ssh.command(f"/iosbinpack64/usr/bin/printf '%s' {shlex.quote(json.dumps(body))} >{REQUEST}; "
                f"/iosbinpack64/usr/sbin/chown mobile:mobile {REQUEST}")


def capture(ssh: SSH, phase: str) -> Path:
    phase_name(phase)
    data = ssh.read_file(f"{REMOTE}/{phase}.json")
    report = json.loads(data)
    pid, _ = resolve_target(ssh, "SpringBoard")
    if report.get("pid") != pid:
        raise LabError("snapshot belongs to a different SpringBoard PID")
    path = BUILD / f"{phase}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def main() -> None:
    global BUILD
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "inject", "snapshot", "capture", "stop",
                                           "present", "dismiss", "expand", "collapse", "invalidate-container", "reconstruct-views", "restore-brightness-view", "resource-start", "resource-stop"))
    parser.add_argument("--host", default="192.168.64.72")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--phase", default="initial", type=phase_name)
    parser.add_argument("--recursive-discovery", action="store_true",
                        help="explicit VM descendant discovery; marks non-production edges")
    parser.add_argument("--module-identifier", default="")
    parser.add_argument("--output-dir", type=Path, default=BUILD,
                        help="local artifact directory; use a fresh directory for a new observation run")
    args = parser.parse_args()
    BUILD = args.output_dir.resolve()
    if args.action == "build":
        print(build()); return
    if args.port != 22222:
        raise LabError("live tracing requires vPhone root SSH on port 22222")
    ssh = SSH(args.host, args.port, "root", args.known_hosts, args.password_env)
    require_vphone(ssh)
    if args.action == "inject":
        pid, command = resolve_target(ssh, "SpringBoard")
        if pid <= 1 or command != TARGETS["SpringBoard"]:
            raise LabError("SpringBoard identity mismatch")
        token = issue_file_extension(ssh, "/var/tmp")
        payload = build(pid, token)
        remote = f"/var/tmp/cnd-cc-owner-{hashlib.sha256(payload.read_bytes()).hexdigest()[:16]}.dylib"
        ssh.copy(payload, remote)
        ssh.command(f"/iosbinpack64/bin/chmod 0755 {remote}")
        if resolve_target(ssh, "SpringBoard") != (pid, command):
            raise LabError("SpringBoard changed before tracing")
        ssh.command(f"/iosbinpack64/bin/rm -f {REMOTE}/initial.json")
        ssh.command(f"/var/jb/usr/bin/timeout -k 2 20 /iosbinpack64/bin/opainject {pid} {remote} "
                    ">/var/tmp/cnd-cc-owner-inject.log 2>&1; status=$?; "
                    'if test "$status" = 124 -o "$status" = 137; then exit 0; fi; exit "$status"')
        print(f"VM ownership tracer loaded in SpringBoard PID {pid}; {remote}")
    elif args.action == "snapshot":
        ssh.command(f"/iosbinpack64/bin/rm -f {REMOTE}/{args.phase}.json")
        request(ssh, {"action": "snapshot", "phase": args.phase,
                      "recursiveDiscovery": args.recursive_discovery})
    elif args.action == "stop":
        ssh.command(f"/iosbinpack64/bin/rm -f {REMOTE}/stopped.txt")
        request(ssh, {"action": "stop"})
        deadline = time.monotonic() + 8
        while ssh.file_kind(f"{REMOTE}/stopped.txt") != "file":
            if time.monotonic() >= deadline: raise LabError("tracer did not acknowledge stop")
            time.sleep(0.25)
        BUILD.mkdir(parents=True, exist_ok=True)
        (BUILD / "stopped.txt").write_bytes(ssh.read_file(f"{REMOTE}/stopped.txt"))
        restoration = json.loads(ssh.read_file(f"{REMOTE}/resource-restoration.json"))
        (BUILD / "resource-restoration.json").write_text(json.dumps(restoration, indent=2) + "\n")
        if any(not row.get("restored") for row in restoration):
            raise LabError("resource observer restoration conflict; inspect resource-restoration.json")
        print("Tracer stopped; resource observers and reconstruction journal restored")
        return
    elif args.action in ("present", "dismiss", "expand", "collapse", "invalidate-container", "reconstruct-views", "restore-brightness-view", "resource-start", "resource-stop"):
        if args.action in ("expand", "invalidate-container", "reconstruct-views") and not args.module_identifier.startswith("com.apple."):
            raise LabError("module presentation requires a com.apple machine identifier")
        request(ssh, {"action": args.action, "moduleIdentifier": args.module_identifier,
                      "phase": args.phase})
        time.sleep(2)
        event = json.loads(ssh.read_file(f"{REMOTE}/driver-latest.json"))
        if event.get("action") != args.action or not event.get("invoked"):
            raise LabError(f"VM presentation driver did not invoke the checked ABI: {event}")
        if args.action == "resource-stop" and any(not row.get("restored") for row in event.get("resourceRestoration", [])):
            raise LabError("resource observer restoration conflict; inspect driver-latest.json")
        BUILD.mkdir(parents=True, exist_ok=True)
        destination = BUILD / f"driver-{args.action}-{time.time_ns()}.json"
        destination.write_text(json.dumps(event, indent=2) + "\n")
        print(destination)
        return
    if args.action != "capture":
        deadline = time.monotonic() + 35
        while ssh.file_kind(f"{REMOTE}/{args.phase}.json") != "file":
            if time.monotonic() >= deadline:
                raise LabError("snapshot did not complete within 35 seconds")
            time.sleep(0.5)
    path = capture(ssh, args.phase)
    report = json.loads(path.read_text())
    print(f"{path}: pid={report['pid']} objects={len(report['objects'])} "
          f"edges={len(report['edges'])} mode={report['mode']} truncated={report['truncated']}")


if __name__ == "__main__":
    main()
