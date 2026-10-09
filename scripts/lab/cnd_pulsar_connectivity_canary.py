#!/usr/bin/env python3
"""Run a reversible official-Pulsar connectivity canary in the vPhone VM."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
SOURCE = REPO_ROOT / "scripts/lab/cnd_pulsar_synthetic_connectivity_probe.m"
INFO_PLIST = REPO_ROOT / "scripts/lab/PulsarConnectivityCanaryInfo.plist"
ASSET_ROOT = REPO_ROOT / "build/pulsar-controlcenter-v2-assets"
MANIFEST = ASSET_ROOT / "manifest.json"
BUILD_DIR = REPO_ROOT / "build/lab-pulsar-connectivity-canary"
REPORT = "/var/tmp/cyanide-pulsar-connectivity-canary.log"
INJECT_LOG = "/var/tmp/cyanide-pulsar-connectivity-canary-inject.log"
LOCAL_REPORT = BUILD_DIR / "cyanide-pulsar-connectivity-canary.log"
VISIBLE_SCREENSHOT = BUILD_DIR / "pulsar-connectivity-visible.png"
RESTORED_SCREENSHOT = BUILD_DIR / "pulsar-connectivity-restored.png"
VM_SOCKET = (
    Path.home()
    / "Library/CyanideVPhoneLab/VMs/cyanide-ios26-base/vphone.sock"
)
EXPECTED_PACKAGE_ID = "com.dobabaophuc.pulsarcc2.0"
EXPECTED_UPSTREAM_COMMIT = "bd13799"
EXPECTED_ARCHIVE_SHA256 = (
    "2acdf365649ff1fb94bbc73201be4ce1df4ae902c5adfa1a90dfd016369d66aa"
)
REMOTE_PATTERN = re.compile(
    r"/var/tmp/cyanide-pulsar-connectivity-canary-[0-9a-f]+"
)


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def validate_hold_seconds(value: int) -> int:
    if value < 15 or value > 180:
        raise LabError("hold duration must be between 15 and 180 seconds")
    return value


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _resolved_asset(relative: str) -> Path:
    candidate = (ASSET_ROOT / relative).resolve()
    try:
        candidate.relative_to(ASSET_ROOT.resolve())
    except ValueError as error:
        raise LabError(f"asset escapes staged root: {relative}") from error
    if not candidate.is_file():
        raise LabError(f"staged Pulsar asset is missing: {candidate}")
    return candidate


def load_assets(*, include_motion: bool = False) -> dict[str, Path]:
    if not MANIFEST.is_file():
        raise LabError(
            "Pulsar asset manifest is missing; run "
            "scripts/extract_pulsar_controlcenter_assets.py first"
        )
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    package = manifest.get("package", {})
    expected = (
        package.get("id") == EXPECTED_PACKAGE_ID
        and package.get("upstream_commit") == EXPECTED_UPSTREAM_COMMIT
        and package.get("upstream_archive_sha256")
        == EXPECTED_ARCHIVE_SHA256
    )
    if not expected:
        raise LabError("Pulsar asset provenance does not match v2.0")
    images = {
        item.get("name"): item
        for item in manifest.get("raw_images", [])
        if isinstance(item, dict)
    }
    selected: dict[str, Path] = {}
    raw_names = ["wifi_white.png", "bluetooth_white.png"]
    if include_motion:
        raw_names.extend((
            "wifi_white1.png",
            "wifi_white2.png",
            "bluetooth_white1.png",
            "bluetooth_white2.png",
        ))
    for name in raw_names:
        record = images.get(name)
        if not record:
            raise LabError(f"manifest is missing {name}")
        path = _resolved_asset(str(record.get("path", "")))
        if file_sha256(path) != record.get("sha256"):
            raise LabError(f"Pulsar asset hash mismatch: {name}")
        selected[name] = path
    catalog = manifest.get("connectivity_catalog", {})
    car = _resolved_asset(str(catalog.get("path", "")))
    if file_sha256(car) != catalog.get("sha256"):
        raise LabError("Pulsar Assets.car hash mismatch")
    names = {
        record.get("Name") for record in catalog.get("renditions", [])
        if isinstance(record, dict)
    }
    required_catalog_names = {"AirplaneGlyph", "CellularDataGlyph"}
    if include_motion:
        required_catalog_names.update({"AirDropGlyph", "HotspotGlyph"})
    if not required_catalog_names.issubset(names):
        raise LabError(
            "Pulsar catalog lacks required connectivity artwork: "
            + ", ".join(sorted(required_catalog_names - names))
        )
    selected["Assets.car"] = car
    selected["Info.plist"] = INFO_PLIST
    if include_motion:
        caml = {
            item.get("name"): item
            for item in manifest.get("caml_variants", [])
            if isinstance(item, dict)
        }
        for name in (
            "wifi_motion_enabled.caml",
            "bluetooth_motion_enabled.caml",
        ):
            record = caml.get(name)
            if not record:
                raise LabError(f"manifest is missing {name}")
            path = _resolved_asset(str(record.get("path", "")))
            if file_sha256(path) != record.get("sha256"):
                raise LabError(f"Pulsar CAML hash mismatch: {name}")
            selected[name] = path
    return selected


def build(*, token: str = "", expected_pid: int = 0,
          hold_seconds: int = 45, theme_directory: str | None = None) -> Path:
    validate_hold_seconds(hold_seconds)
    if expected_pid < 0:
        raise LabError("expected PID cannot be negative")
    theme_directory = theme_directory or (
        "/var/tmp/cyanide-pulsar-connectivity-canary-a1"
    )
    if not REMOTE_PATTERN.fullmatch(theme_directory):
        raise LabError(f"refusing unsafe theme directory: {theme_directory}")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_pulsar_connectivity_canary.dylib"
    capture_directory = theme_directory + "/captured"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror", "-DCND_PULSAR_CONNECTIVITY_CANARY=1",
        f'-DCND_SYNTHETIC_CONNECTIVITY_OUTPUT_TOKEN="{c_literal(token)}"',
        f'-DCND_SYNTHETIC_CONNECTIVITY_REPORT_PATH="{REPORT}"',
        "-DCND_SYNTHETIC_CONNECTIVITY_ASSET_DIRECTORY="
        f'"{c_literal(capture_directory)}"',
        f'-DCND_PULSAR_THEME_DIRECTORY="{c_literal(theme_directory)}"',
        f"-DCND_SYNTHETIC_CONNECTIVITY_EXPECTED_PID={expected_pid}",
        f"-DCND_SYNTHETIC_CONNECTIVITY_HOLD_SECONDS={hold_seconds}",
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def stage_assets(ssh: SSH, remote_directory: str) -> None:
    if not REMOTE_PATTERN.fullmatch(remote_directory):
        raise LabError(f"refusing unsafe theme directory: {remote_directory}")
    assets = load_assets()
    bundle = remote_directory + "/PulsarConnectivity.bundle"
    captured = remote_directory + "/captured"
    ssh.command(
        f"/iosbinpack64/bin/mkdir -p {shlex.quote(bundle)} "
        f"{shlex.quote(captured)} && "
        f"/iosbinpack64/bin/chmod 0700 {shlex.quote(remote_directory)} "
        f"{shlex.quote(bundle)} {shlex.quote(captured)}"
    )
    ssh.copy(assets["wifi_white.png"], remote_directory + "/wifi_white.png")
    ssh.copy(
        assets["bluetooth_white.png"],
        remote_directory + "/bluetooth_white.png",
    )
    ssh.copy(assets["Assets.car"], bundle + "/Assets.car")
    ssh.copy(assets["Info.plist"], bundle + "/Info.plist")
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown -R mobile:mobile "
        f"{shlex.quote(remote_directory)} && "
        f"/iosbinpack64/bin/chmod 0600 "
        f"{shlex.quote(remote_directory + '/wifi_white.png')} "
        f"{shlex.quote(remote_directory + '/bluetooth_white.png')} "
        f"{shlex.quote(bundle + '/Assets.car')} "
        f"{shlex.quote(bundle + '/Info.plist')}"
    )


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT)}; "
        "else echo '[CND_SYNTHETIC_CONNECTIVITY] report-not-created'; fi"
    )


def inject(ssh: SSH, hold_seconds: int = 45) -> tuple[int, str, str, str]:
    validate_hold_seconds(hold_seconds)
    pid, command = resolve_target(ssh, "SpringBoard")
    if pid <= 1 or command != TARGETS["SpringBoard"]:
        raise LabError("refusing: SpringBoard identity mismatch")
    token = issue_file_extension(ssh, "/var/tmp")
    remote_assets = (
        f"/var/tmp/cyanide-pulsar-connectivity-canary-{time.time_ns():x}"
    )
    payload = build(
        token=token,
        expected_pid=pid,
        hold_seconds=hold_seconds,
        theme_directory=remote_assets,
    )
    stage_assets(ssh, remote_assets)
    digest = file_sha256(payload)[:16]
    remote = f"/var/tmp/cnd-pulsar-connectivity-canary-{digest}.dylib"
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
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG)} 2>&1; status=$?; "
        'if test "$status" = 124 -o "$status" = 137; then '
        'exit 0; fi; exit "$status"'
    )
    deadline = time.monotonic() + 24.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if " VISIBLE_READY " in latest and " themeApplied=1 " in latest:
            return pid, remote, remote_assets, latest
        if " COMPLETE " in latest:
            raise LabError(
                "Pulsar canary completed before becoming visible:\n"
                + latest.rstrip()
            )
        time.sleep(0.25)
    raise LabError("Pulsar canary did not become visible:\n" + latest.rstrip())


def capture_screenshot(path: Path) -> None:
    if not VM_SOCKET.is_socket():
        raise LabError(f"vPhone control socket is unavailable: {VM_SOCKET}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(VM_SOCKET))
        client.sendall((json.dumps({"t": "screenshot", "path": str(path)})
                        + "\n").encode())
        response = bytearray()
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    result = json.loads(response)
    if not result.get("ok") or not path.is_file():
        raise LabError(f"VM screenshot failed: {result.get('error', result)}")
    path.chmod(0o600)


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


def wait_for_complete(ssh: SSH, hold_seconds: int) -> str:
    deadline = time.monotonic() + hold_seconds + 15.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if " COMPLETE " in latest:
            if " status=success " not in latest:
                raise LabError("Pulsar canary did not restore successfully:\n" + latest)
            return latest
        time.sleep(0.25)
    raise LabError("Pulsar canary did not restore before deadline:\n" + latest)


def run_canary(ssh: SSH, hold_seconds: int) -> Path:
    inject(ssh, hold_seconds)
    time.sleep(1.0)
    capture_screenshot(VISIBLE_SCREENSHOT)
    wait_for_complete(ssh, hold_seconds)
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
    args = parser.parse_args()

    if args.action == "build":
        load_assets()
        print(build(hold_seconds=args.hold_seconds))
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
        pid, remote, assets, _ = inject(ssh, args.hold_seconds)
        print(
            f"Pulsar connectivity visible pid={pid} payload={remote} "
            f"assets={assets} hold={args.hold_seconds}s restoration=scheduled"
        )
        return 0
    report = run_canary(ssh, args.hold_seconds)
    print(
        f"Pulsar connectivity canary complete report={report} "
        f"visible={VISIBLE_SCREENSHOT} restored={RESTORED_SCREENSHOT}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LabError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}")
        raise SystemExit(1)
