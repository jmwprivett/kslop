#!/usr/bin/env python3
"""Run the reversible AirDrop/Hotspot/Pulsar-motion VM canary."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import tempfile
import time
from pathlib import Path

import cnd_pulsar_connectivity_canary as base
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
CONNECTIVITY_INFO_PLIST = (
    REPO_ROOT / "scripts/lab/PulsarConnectivityCanaryInfo.plist"
)
MOTION_INFO_PLIST = REPO_ROOT / "scripts/lab/PulsarMotionInfo.plist"
MOTION_PACKAGE_INDEX = (
    REPO_ROOT / "scripts/lab/PulsarMotionPackageIndex.xml"
)
BUILD_DIR = REPO_ROOT / "build/lab-pulsar-extended-connectivity-canary"
REPORT = "/var/tmp/cyanide-pulsar-extended-connectivity-canary.log"
INJECT_LOG = (
    "/var/tmp/cyanide-pulsar-extended-connectivity-canary-inject.log"
)
LOCAL_REPORT = BUILD_DIR / "cyanide-pulsar-extended-connectivity-canary.log"
FRAME_A_SCREENSHOT = BUILD_DIR / "pulsar-extended-frame-a.png"
FRAME_B_SCREENSHOT = BUILD_DIR / "pulsar-extended-frame-b.png"
RESTORED_SCREENSHOT = BUILD_DIR / "pulsar-extended-restored.png"
REMOTE_PATTERN = re.compile(
    r"/var/tmp/cyanide-pulsar-extended-connectivity-[0-9a-f]+"
)
UPSTREAM_IMAGE_ROOT = "/var/mobile/Documents/PhucDo/PhucDoUI"


def validate_remote_directory(remote_directory: str) -> str:
    if not REMOTE_PATTERN.fullmatch(remote_directory):
        raise LabError(f"refusing unsafe theme directory: {remote_directory}")
    return remote_directory


def port_caml(source: Path, remote_directory: str, kind: str) -> str:
    """Port one upstream CAML copy to nonce-scoped, staged image paths."""
    validate_remote_directory(remote_directory)
    if kind not in {"wifi", "bluetooth"}:
        raise LabError(f"unsupported motion package kind: {kind}")
    text = source.read_text(encoding="utf-8")
    old_prefix = UPSTREAM_IMAGE_ROOT + "/"
    if old_prefix not in text:
        raise LabError(f"upstream CAML image root is missing: {source}")
    text = text.replace(old_prefix, remote_directory + "/")
    unavailable_base = f'{remote_directory}/{kind}.png'
    staged_base = f'{remote_directory}/{kind}_white.png'
    if unavailable_base not in text:
        raise LabError(f"upstream CAML base image is missing: {kind}.png")
    text = text.replace(unavailable_base, staged_base)
    expected = {
        staged_base,
        f"{remote_directory}/{kind}_white1.png",
        f"{remote_directory}/{kind}_white2.png",
    }
    if old_prefix in text or not all(path in text for path in expected):
        raise LabError(f"ported CAML failed path validation: {source}")
    return text


def build(
    *, token: str = "", expected_pid: int = 0, hold_seconds: int = 45,
    theme_directory: str | None = None,
) -> Path:
    base.validate_hold_seconds(hold_seconds)
    if expected_pid < 0:
        raise LabError("expected PID cannot be negative")
    theme_directory = theme_directory or (
        "/var/tmp/cyanide-pulsar-extended-connectivity-a1"
    )
    validate_remote_directory(theme_directory)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_pulsar_extended_connectivity_canary.dylib"
    capture_directory = theme_directory + "/captured"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror", "-DCND_PULSAR_CONNECTIVITY_CANARY=1",
        "-DCND_PULSAR_EXTENDED_CONNECTIVITY_CANARY=1",
        "-DCND_SYNTHETIC_CONNECTIVITY_OUTPUT_TOKEN="
        f'"{base.c_literal(token)}"',
        f'-DCND_SYNTHETIC_CONNECTIVITY_REPORT_PATH="{REPORT}"',
        "-DCND_SYNTHETIC_CONNECTIVITY_ASSET_DIRECTORY="
        f'"{base.c_literal(capture_directory)}"',
        "-DCND_PULSAR_THEME_DIRECTORY="
        f'"{base.c_literal(theme_directory)}"',
        f"-DCND_SYNTHETIC_CONNECTIVITY_EXPECTED_PID={expected_pid}",
        f"-DCND_SYNTHETIC_CONNECTIVITY_HOLD_SECONDS={hold_seconds}",
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-framework", "QuartzCore",
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def stage_assets(ssh: SSH, remote_directory: str) -> None:
    validate_remote_directory(remote_directory)
    assets = base.load_assets(include_motion=True)
    connectivity_bundle = remote_directory + "/PulsarConnectivity.bundle"
    motion_bundle = remote_directory + "/PulsarMotion.bundle"
    wifi_package = motion_bundle + "/WiFi.ca"
    bluetooth_package = motion_bundle + "/Bluetooth.ca"
    captured = remote_directory + "/captured"
    directories = (
        remote_directory, connectivity_bundle, motion_bundle, wifi_package,
        bluetooth_package, captured,
    )
    quoted_directories = " ".join(shlex.quote(item) for item in directories)
    ssh.command(
        f"/iosbinpack64/bin/mkdir -p {quoted_directories} && "
        f"/iosbinpack64/bin/chmod 0700 {quoted_directories}"
    )
    raw_names = (
        "wifi_white.png", "wifi_white1.png", "wifi_white2.png",
        "bluetooth_white.png", "bluetooth_white1.png",
        "bluetooth_white2.png",
    )
    remote_files: list[str] = []
    for name in raw_names:
        destination = remote_directory + "/" + name
        ssh.copy(assets[name], destination)
        remote_files.append(destination)
    for source, destination in (
        (assets["Assets.car"], connectivity_bundle + "/Assets.car"),
        (CONNECTIVITY_INFO_PLIST, connectivity_bundle + "/Info.plist"),
        (MOTION_INFO_PLIST, motion_bundle + "/Info.plist"),
    ):
        ssh.copy(source, destination)
        remote_files.append(destination)
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        for kind, package_name in (("wifi", "WiFi"),
                                   ("bluetooth", "Bluetooth")):
            source = assets[f"{kind}_motion_enabled.caml"]
            ported = temporary / f"{package_name}-main.caml"
            ported.write_text(
                port_caml(source, remote_directory, kind), encoding="utf-8"
            )
            package = f"{motion_bundle}/{package_name}.ca"
            main_destination = package + "/main.caml"
            index_destination = package + "/index.xml"
            ssh.copy(ported, main_destination)
            ssh.copy(MOTION_PACKAGE_INDEX, index_destination)
            remote_files.extend((main_destination, index_destination))
    quoted_files = " ".join(shlex.quote(item) for item in remote_files)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown -R mobile:mobile "
        f"{shlex.quote(remote_directory)} && "
        f"/iosbinpack64/bin/chmod 0600 {quoted_files}"
    )


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT)}; "
        "else echo '[CND_SYNTHETIC_CONNECTIVITY] report-not-created'; fi"
    )


def inject(ssh: SSH, hold_seconds: int = 45) -> tuple[int, str, str, str]:
    base.validate_hold_seconds(hold_seconds)
    pid, command = resolve_target(ssh, "SpringBoard")
    if pid <= 1 or command != TARGETS["SpringBoard"]:
        raise LabError("refusing: SpringBoard identity mismatch")
    token = issue_file_extension(ssh, "/var/tmp")
    remote_assets = (
        f"/var/tmp/cyanide-pulsar-extended-connectivity-{time.time_ns():x}"
    )
    payload = build(
        token=token, expected_pid=pid, hold_seconds=hold_seconds,
        theme_directory=remote_assets,
    )
    stage_assets(ssh, remote_assets)
    digest = base.file_sha256(payload)[:16]
    remote = f"/var/tmp/cnd-pulsar-extended-connectivity-{digest}.dylib"
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
        if (
            " VISIBLE_READY " in latest
            and " themeApplied=1 " in latest
            and " extended=1 " in latest
        ):
            return pid, remote, remote_assets, latest
        if " COMPLETE " in latest:
            raise LabError(
                "extended canary completed before becoming visible:\n"
                + latest.rstrip()
            )
        time.sleep(0.25)
    raise LabError(
        "extended canary did not become visible:\n" + latest.rstrip()
    )


def wait_for_complete(ssh: SSH, hold_seconds: int) -> str:
    deadline = time.monotonic() + hold_seconds + 15.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if " COMPLETE " in latest:
            if " status=success " not in latest:
                raise LabError(
                    "extended canary did not restore successfully:\n" + latest
                )
            return latest
        time.sleep(0.25)
    raise LabError("extended canary did not restore before deadline:\n" + latest)


def run_canary(ssh: SSH, hold_seconds: int) -> Path:
    inject(ssh, hold_seconds)
    time.sleep(0.25)
    base.capture_screenshot(FRAME_A_SCREENSHOT)
    time.sleep(1.0)
    base.capture_screenshot(FRAME_B_SCREENSHOT)
    wait_for_complete(ssh, hold_seconds)
    base.capture_screenshot(RESTORED_SCREENSHOT)
    return base.atomic_write(LOCAL_REPORT, ssh.read_file(REPORT))


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
        base.load_assets(include_motion=True)
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
            f"extended connectivity visible pid={pid} payload={remote} "
            f"assets={assets} hold={args.hold_seconds}s restoration=scheduled"
        )
        return 0
    report = run_canary(ssh, args.hold_seconds)
    frame_a = hashlib.sha256(FRAME_A_SCREENSHOT.read_bytes()).hexdigest()
    frame_b = hashlib.sha256(FRAME_B_SCREENSHOT.read_bytes()).hexdigest()
    print(
        f"extended connectivity canary complete report={report} "
        f"frameA={FRAME_A_SCREENSHOT} frameB={FRAME_B_SCREENSHOT} "
        f"framesDiffer={frame_a != frame_b} restored={RESTORED_SCREENSHOT}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LabError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}")
        raise SystemExit(1)
