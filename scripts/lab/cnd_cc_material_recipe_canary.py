#!/usr/bin/env python3
"""Run the reversible modulesBackground.materialrecipe canary in vPhone."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import socket
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
from cnd_vphone_krw import current_cyanide


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_cc_material_recipe_canary.m"
COMPILER = REPO_ROOT / "Cyanide/tweaks/CNDCCMaterialRecipeCompiler.m"
INCLUDE_DIRECTORY = REPO_ROOT / "Cyanide/tweaks"
BUILD_DIRECTORY = REPO_ROOT / "build/lab-cc-material-recipe-canary"
REMOTE_DIRECTORY = "/var/tmp/cnd-cc-material-recipe-canary"
REMOTE_REPORT = f"{REMOTE_DIRECTORY}/report.json"
REMOTE_JOURNAL = f"{REMOTE_DIRECTORY}/journal.json"
APP_CANARY_RELATIVE_DIRECTORY = (
    "Library/Application Support/CNDCCMaterialRecipeVMCanary"
)
VM_SOCKET = (
    Path.home()
    / "Library/CyanideVPhoneLab/VMs/cyanide-ios26-base/vphone.sock"
)
BUNDLE_IDENTIFIER = "com.zeroxjf.ios-cyanide1"
TARGET_PATH = (
    "/System/Library/PrivateFrameworks/CoreMaterial.framework/"
    "modulesBackground.materialrecipe"
)


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build(action: str, expected_pid: int, token: str) -> Path:
    if action not in {"apply", "restore"}:
        raise LabError(f"unsupported canary action: {action}")
    if expected_pid <= 1:
        raise LabError("expected Cyanide PID must be greater than one")
    if not token or "\n" in token:
        raise LabError("sandbox token is missing or malformed")
    BUILD_DIRECTORY.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIRECTORY / f"cnd_cc_material_recipe_{action}.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror", f"-DCND_CC_RECIPE_CANARY_ACTION={1 if action == 'apply' else 2}",
        f"-DCND_CC_RECIPE_CANARY_EXPECTED_PID={expected_pid}",
        "-DCND_CC_RECIPE_CANARY_OUTPUT_TOKEN="
        f'"{c_literal(token)}"',
        "-I", str(INCLUDE_DIRECTORY), str(SOURCE), str(COMPILER),
        "-framework", "Foundation", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


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


def launch_cyanide(ssh: SSH) -> tuple[int, str, str]:
    ssh.command(
        "/var/jb/usr/bin/uiopen --bundleid "
        + shlex.quote(BUNDLE_IDENTIFIER)
    )
    deadline = time.monotonic() + 10.0
    latest_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return current_cyanide(ssh)
        except LabError as error:
            latest_error = error
            time.sleep(0.25)
    raise LabError(f"Cyanide did not become launchable: {latest_error}")


def app_canary_directory(app_home: str) -> str:
    if not re.fullmatch(
        r"/private/var/mobile/Containers/Data/Application/[0-9A-F-]+",
        app_home,
    ):
        raise LabError(f"refusing unexpected Cyanide data container: {app_home}")
    return f"{app_home}/{APP_CANARY_RELATIVE_DIRECTORY}"


def read_report(ssh: SSH, report_path: str = REMOTE_REPORT) -> dict[str, object] | None:
    if ssh.file_kind(report_path) != "file":
        return None
    try:
        value = json.loads(ssh.read_file(report_path))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise LabError(f"the canary report is malformed: {error}") from error
    if not isinstance(value, dict):
        raise LabError("the canary report is not a dictionary")
    return value


def trigger_app_action(ssh: SSH, action: str) -> dict[str, object]:
    if action not in {"apply", "restore"}:
        raise LabError(f"unsupported canary action: {action}")
    pid, app_home, _ = launch_cyanide(ssh)
    directory = app_canary_directory(app_home)
    request_path = f"{directory}/request.json"
    report_path = f"{directory}/report.json"
    BUILD_DIRECTORY.mkdir(parents=True, exist_ok=True)
    nonce = os.urandom(16).hex()
    target_sandbox_token = issue_file_extension(ssh, TARGET_PATH)
    local_request = BUILD_DIRECTORY / f"request-{action}-{nonce}.json"
    local_request.write_text(
        json.dumps({
            "schemaVersion": 1,
            "action": action,
            "nonce": nonce,
            "targetSandboxToken": target_sandbox_token,
        }),
        encoding="utf-8",
    )
    remote_temporary = f"{request_path}.new"
    ssh.command(
        f"/iosbinpack64/bin/mkdir -p {shlex.quote(directory)} && "
        f"/iosbinpack64/usr/sbin/chown mobile:mobile {shlex.quote(directory)} && "
        f"/iosbinpack64/bin/chmod 0700 {shlex.quote(directory)} && "
        f"/iosbinpack64/bin/rm -f {shlex.quote(report_path)} "
        f"{shlex.quote(remote_temporary)}"
    )
    ssh.copy(local_request, remote_temporary)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown mobile:mobile {shlex.quote(remote_temporary)} && "
        f"/iosbinpack64/bin/chmod 0600 {shlex.quote(remote_temporary)} && "
        f"/iosbinpack64/bin/mv -f {shlex.quote(remote_temporary)} "
        f"{shlex.quote(request_path)}"
    )
    current_pid, current_home, _ = current_cyanide(ssh)
    if current_pid != pid or current_home != app_home:
        raise LabError("Cyanide changed identity while staging the canary request")
    ssh.command(f"/iosbinpack64/bin/kill -9 {pid}")
    new_pid, new_home, _ = launch_cyanide(ssh)
    if new_pid == pid or new_home != app_home:
        raise LabError("Cyanide did not relaunch in the same data container")
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        report = read_report(ssh, report_path)
        if report and report.get("phase"):
            if report.get("requestNonce") != nonce:
                raise LabError("the app-native canary report nonce did not match")
            local_report = BUILD_DIRECTORY / f"report-{action}-{nonce}.json"
            local_report.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if not report.get("success"):
                raise LabError(
                    f"canary {action} failed: "
                    f"{report.get('phase')}: {report.get('message')}"
                )
            return report
        time.sleep(0.25)
    raise LabError(f"app-native canary {action} did not produce a completed report")


def inject_action(ssh: SSH, action: str) -> dict[str, object]:
    pid, _, _ = launch_cyanide(ssh)
    token = issue_file_extension(ssh, "/var/tmp")
    payload = build(action, pid, token)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote_payload = f"/var/tmp/cnd-cc-material-recipe-{action}-{digest}.dylib"
    ssh.copy(payload, remote_payload)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote_payload)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote_payload)} && "
        f"/iosbinpack64/bin/rm -f {shlex.quote(REMOTE_REPORT)}"
    )
    current_pid, _, _ = current_cyanide(ssh)
    if current_pid != pid:
        raise LabError("Cyanide changed PID before canary injection")
    ssh.command(
        f"current=$(/bin/ps -p {pid} -o command=); "
        f"case \"$current\" in *'/Cyanide.app/Cyanide'*) ;; "
        "*) echo 'Cyanide identity changed' >&2; exit 90;; esac; "
        f"/var/jb/usr/bin/timeout -k 2 60 /iosbinpack64/bin/opainject "
        f"{pid} {shlex.quote(remote_payload)} >/var/tmp/cnd-cc-material-recipe-inject.log 2>&1; "
        "status=$?; if test \"$status\" = 124 -o \"$status\" = 137; "
        "then exit 0; fi; exit \"$status\""
    )
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        report = read_report(ssh)
        if report and report.get("phase"):
            if not report.get("success"):
                raise LabError(
                    f"canary {action} failed: "
                    f"{report.get('phase')}: {report.get('message')}"
                )
            return report
        time.sleep(0.25)
    raise LabError(f"canary {action} did not produce a completed report")


def restart_springboard(ssh: SSH) -> tuple[int, int]:
    old_pid, command = resolve_target(ssh, "SpringBoard")
    if old_pid <= 1 or command != TARGETS["SpringBoard"]:
        raise LabError("refusing: SpringBoard identity mismatch")
    ssh.command(f"/iosbinpack64/bin/kill -9 {old_pid}")
    deadline = time.monotonic() + 25.0
    while time.monotonic() < deadline:
        try:
            new_pid, new_command = resolve_target(ssh, "SpringBoard")
        except LabError:
            time.sleep(0.25)
            continue
        if new_pid != old_pid and new_command == TARGETS["SpringBoard"]:
            time.sleep(2.0)
            return old_pid, new_pid
        time.sleep(0.25)
    raise LabError("SpringBoard did not return with a new PID")


def show_control_center() -> None:
    vm_request({"t": "key", "name": "home"})
    time.sleep(0.8)
    vm_request({
        "t": "swipe", "x1": 1170, "y1": 35,
        "x2": 1170, "y2": 1850, "ms": 450,
    })
    time.sleep(1.0)
    # Control Center remembers its last full-page selection across launches.
    # Select Favorites explicitly so all three visual checkpoints show the
    # same surface. These are native 1290x2796 vPhone display coordinates.
    vm_request({"t": "tap", "x": 1218, "y": 1230})
    time.sleep(1.0)


def dismiss_overlays() -> None:
    for _ in range(2):
        vm_request({"t": "key", "name": "home", "delay": 500})
        time.sleep(0.4)


def capture_screenshot(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    vm_request({"t": "screenshot", "path": str(path)})
    if not path.is_file():
        raise LabError(f"VM screenshot was not created: {path}")
    path.chmod(0o600)


def run_canary(ssh: SSH) -> dict[str, object]:
    BUILD_DIRECTORY.mkdir(parents=True, exist_ok=True)
    screenshots = {
        "stockBefore": BUILD_DIRECTORY / "stock-before.png",
        "tinted": BUILD_DIRECTORY / "tinted.png",
        "stockRestored": BUILD_DIRECTORY / "stock-restored.png",
    }
    reports: dict[str, object] = {}
    show_control_center()
    capture_screenshot(screenshots["stockBefore"])
    apply_attempted = False
    try:
        dismiss_overlays()
        apply_attempted = True
        reports["apply"] = trigger_app_action(ssh, "apply")
        reports["applySpringBoardPIDs"] = restart_springboard(ssh)
        show_control_center()
        capture_screenshot(screenshots["tinted"])
    finally:
        dismiss_overlays()
        _, app_home, _ = launch_cyanide(ssh)
        journal_path = f"{app_canary_directory(app_home)}/journal.json"
        if apply_attempted and ssh.file_kind(journal_path) == "file":
            reports["restore"] = trigger_app_action(ssh, "restore")
            reports["restoreSpringBoardPIDs"] = restart_springboard(ssh)
            show_control_center()
            capture_screenshot(screenshots["stockRestored"])
    reports["screenshots"] = {key: str(value) for key, value in screenshots.items()}
    return reports


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "apply", "restore", "status", "run"))
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.action == "build":
        # Build-only uses a syntactically valid placeholder token/PID; live
        # identity checks still prevent either artifact from running elsewhere.
        print(build("apply", 2, "build-only-token"))
        print(build("restore", 2, "build-only-token"))
        return 0
    if args.port != 22222 or args.user != "root" or not args.host:
        raise LabError("live actions require vPhone root SSH on port 22222")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts, args.password_env)
    require_vphone(ssh)
    if args.action == "status":
        _, app_home, _ = launch_cyanide(ssh)
        directory = app_canary_directory(app_home)
        report = read_report(ssh, f"{directory}/report.json")
        journal = None
        journal_path = f"{directory}/journal.json"
        if ssh.file_kind(journal_path) == "file":
            journal = json.loads(ssh.read_file(journal_path))
        print(json.dumps({"report": report, "journal": journal}, indent=2, sort_keys=True))
        return 0
    if args.action in {"apply", "restore"}:
        print(json.dumps(trigger_app_action(ssh, args.action), indent=2, sort_keys=True))
        return 0
    print(json.dumps(run_canary(ssh), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
