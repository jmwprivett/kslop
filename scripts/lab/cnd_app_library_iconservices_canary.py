#!/usr/bin/env python3
"""Run a reversible one-bundle App Library IconServices canary in vPhone."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import socket
import tempfile
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
SOURCE = REPO_ROOT / "scripts/lab/cnd_app_library_iconservices_canary.m"
BUILD_DIR = REPO_ROOT / "build/lab-app-library-iconservices-canary"
REPORT = "/var/tmp/cyanide-app-library-iconservices-canary.log"
INJECT_LOG = "/var/tmp/cyanide-app-library-iconservices-canary-inject.log"
LOCAL_REPORT = BUILD_DIR / "cyanide-app-library-iconservices-canary.log"
BASELINE_SCREENSHOT = BUILD_DIR / "app-library-baseline.png"
VISIBLE_SCREENSHOT = BUILD_DIR / "app-library-preview-transparent.png"
RESTORED_SCREENSHOT = BUILD_DIR / "app-library-restored.png"
VM_SOCKET = (
    Path.home()
    / "Library/CyanideVPhoneLab/VMs/cyanide-ios26-base/vphone.sock"
)


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def validate_hold_seconds(value: int) -> int:
    if value < 15 or value > 180:
        raise LabError("hold duration must be between 15 and 180 seconds")
    return value


def validate_bundle(value: str) -> str:
    if not value or len(value) > 255:
        raise LabError("target bundle must be non-empty and at most 255 bytes")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    if any(character not in allowed for character in value):
        raise LabError(f"invalid target bundle: {value!r}")
    return value


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build(*, token: str = "", expected_pid: int = 0,
          hold_seconds: int = 45,
          target_bundle: str = "com.apple.Preview") -> Path:
    validate_hold_seconds(hold_seconds)
    target_bundle = validate_bundle(target_bundle)
    if expected_pid < 0:
        raise LabError("expected PID cannot be negative")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_app_library_iconservices_canary.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_APP_LIBRARY_CANARY_OUTPUT_TOKEN="{c_literal(token)}"',
        f'-DCND_APP_LIBRARY_CANARY_REPORT_PATH="{c_literal(REPORT)}"',
        f'-DCND_APP_LIBRARY_CANARY_TARGET_BUNDLE="{c_literal(target_bundle)}"',
        f"-DCND_APP_LIBRARY_CANARY_EXPECTED_PID={expected_pid}",
        f"-DCND_APP_LIBRARY_CANARY_HOLD_SECONDS={hold_seconds}",
        str(SOURCE), "-framework", "Foundation", "-framework",
        "CoreGraphics", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    run(["codesign", "--verify", "--strict", str(output)])
    return output


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT)}; "
        "else echo '[CND_APP_LIBRARY_CANARY] report-not-created'; fi"
    )


def vm_request(request: dict[str, object]) -> dict[str, object]:
    if not VM_SOCKET.is_socket():
        raise LabError(f"vPhone control socket is unavailable: {VM_SOCKET}")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(VM_SOCKET))
        client.sendall((json.dumps(request) + "\n").encode())
        response = bytearray()
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    result = json.loads(response)
    if not result.get("ok"):
        raise LabError(f"VM control failed for {request}: {result}")
    return result


def capture_screenshot(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    vm_request({"t": "screenshot", "path": str(path)})
    if not path.is_file():
        raise LabError(f"VM screenshot was not created: {path}")
    path.chmod(0o600)


def show_app_library() -> None:
    vm_request({"t": "key", "name": "home"})
    time.sleep(0.8)
    # This fixture has four Home pages. The extra fifth swipe is an inert
    # guard once App Library is visible and tolerates one dropped gesture.
    for _ in range(5):
        vm_request({
            "t": "swipe", "x1": 780, "y1": 1250,
            "x2": 120, "y2": 1250, "ms": 250,
        })
        time.sleep(0.65)
    time.sleep(1.0)


def atomic_write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.stem}-", suffix=path.suffix,
            dir=path.parent, delete=False,
        ) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return path


def inject(ssh: SSH, hold_seconds: int,
           target_bundle: str) -> tuple[int, str, str]:
    validate_hold_seconds(hold_seconds)
    target_bundle = validate_bundle(target_bundle)
    pid, command = resolve_target(ssh, "SpringBoard")
    if pid <= 1 or command != TARGETS["SpringBoard"]:
        raise LabError("refusing: SpringBoard identity mismatch")
    token = issue_file_extension(ssh, "/var/tmp")
    payload = build(
        token=token, expected_pid=pid, hold_seconds=hold_seconds,
        target_bundle=target_bundle,
    )
    remote = (
        "/var/tmp/cnd-app-library-iconservices-canary-"
        f"{file_sha256(payload)[:16]}.dylib"
    )
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    if resolve_target(ssh, "SpringBoard") != (pid, command):
        raise LabError("refusing: SpringBoard identity changed before injection")
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT)} "
        f"{shlex.quote(INJECT_LOG)}; "
        f"current=$(/bin/ps -p {pid} -o command=); "
        f"if test \"$current\" != {shlex.quote(command)}; then "
        "echo 'target identity changed' >&2; exit 90; fi; "
        f"/var/jb/usr/bin/timeout 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG)} 2>&1; status=$?; "
        'if test "$status" = 124; then exit 0; fi; exit "$status"'
    )
    deadline = time.monotonic() + 12.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if " ARMED " in latest:
            return pid, remote, latest
        if " REFUSED " in latest:
            raise LabError("canary preflight refused:\n" + latest.rstrip())
        time.sleep(0.25)
    raise LabError("canary did not arm:\n" + latest.rstrip())


def wait_for_replacement(ssh: SSH) -> str:
    deadline = time.monotonic() + 10.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if " REPLACED " in latest:
            return latest
        time.sleep(0.25)
    raise LabError("target replacement was not observed:\n" + latest.rstrip())


def wait_for_complete(ssh: SSH, hold_seconds: int) -> str:
    deadline = time.monotonic() + hold_seconds + 15.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if " COMPLETE " in latest:
            if " status=success " not in latest:
                raise LabError("canary restoration failed:\n" + latest.rstrip())
            return latest
        time.sleep(0.25)
    raise LabError("canary did not restore before deadline:\n" + latest.rstrip())


def run_canary(ssh: SSH, hold_seconds: int, target_bundle: str) -> Path:
    show_app_library()
    capture_screenshot(BASELINE_SCREENSHOT)
    inject(ssh, hold_seconds, target_bundle)
    show_app_library()
    wait_for_replacement(ssh)
    capture_screenshot(VISIBLE_SCREENSHOT)
    wait_for_complete(ssh, hold_seconds)
    show_app_library()
    capture_screenshot(RESTORED_SCREENSHOT)
    return atomic_write(LOCAL_REPORT, ssh.read_file(REPORT))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "inject", "read", "run"))
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--hold-seconds", type=int, default=45)
    parser.add_argument("--target-bundle", default="com.apple.Preview")
    args = parser.parse_args()

    if args.action == "build":
        print(build(
            hold_seconds=args.hold_seconds,
            target_bundle=args.target_bundle,
        ))
        return 0
    if args.port != 22222 or args.user != "root" or not args.host:
        raise LabError("live actions require vPhone root SSH on port 22222")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh), end="")
        return 0
    if args.action == "inject":
        pid, remote, _ = inject(
            ssh, args.hold_seconds, args.target_bundle,
        )
        print(
            f"App Library canary armed pid={pid} payload={remote} "
            f"target={args.target_bundle} hold={args.hold_seconds}s "
            "restoration=scheduled"
        )
        return 0
    report = run_canary(ssh, args.hold_seconds, args.target_bundle)
    print(
        f"App Library canary complete report={report} "
        f"baseline={BASELINE_SCREENSHOT} visible={VISIBLE_SCREENSHOT} "
        f"restored={RESTORED_SCREENSHOT}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
