#!/usr/bin/env python3
"""Run the reversible official-Pulsar Low Power/ReplayKit/Flashlight canary."""

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
SOURCE = REPO_ROOT / "scripts/lab/cnd_pulsar_additional_controls_canary.m"
MOTION_INFO_PLIST = (
    REPO_ROOT / "scripts/lab/PulsarAdditionalControlsMotionInfo.plist"
)
FLASHLIGHT_INFO_PLIST = REPO_ROOT / "scripts/lab/PulsarFlashlightInfo.plist"
PACKAGE_INDEX = REPO_ROOT / "scripts/lab/PulsarMotionPackageIndex.xml"
BUILD_DIR = REPO_ROOT / "build/lab-pulsar-additional-controls-canary"
REPORT = "/var/tmp/cyanide-pulsar-additional-controls.log"
INJECT_LOG = "/var/tmp/cyanide-pulsar-additional-controls-inject.log"
LOCAL_REPORT = BUILD_DIR / "cyanide-pulsar-additional-controls.log"
VISIBLE_SCREENSHOT = BUILD_DIR / "pulsar-additional-controls-visible.png"
RESTORED_SCREENSHOT = BUILD_DIR / "pulsar-additional-controls-restored.png"
REMOTE_PATTERN = re.compile(
    r"/var/tmp/cyanide-pulsar-additional-controls-[0-9a-f]+"
)
UPSTREAM_IMAGE_ROOT = "/var/mobile/Documents/PhucDo/PhucDoUI"
RAW_NAMES = (
    "pin_off.png",
    "pin_on.png",
    "pin_on1.png",
    "pin_on2.png",
    "record_off.png",
    "record_on.png",
    "1.png",
    "2.png",
    "3.png",
)


def validate_remote_directory(remote_directory: str) -> str:
    if not REMOTE_PATTERN.fullmatch(remote_directory):
        raise LabError(f"refusing unsafe theme directory: {remote_directory}")
    return remote_directory


def _manifest_records(manifest: dict[str, object], key: str) -> dict[str, dict]:
    value = manifest.get(key, [])
    if not isinstance(value, list):
        raise LabError(f"Pulsar manifest field is not a list: {key}")
    return {
        str(item.get("name")): item
        for item in value
        if isinstance(item, dict) and item.get("name")
    }


def load_assets() -> dict[str, Path]:
    if not base.MANIFEST.is_file():
        raise LabError(
            "Pulsar asset manifest is missing; run "
            "scripts/extract_pulsar_controlcenter_assets.py first"
        )
    manifest = json.loads(base.MANIFEST.read_text(encoding="utf-8"))
    package = manifest.get("package", {})
    if not isinstance(package, dict) or not (
        package.get("id") == base.EXPECTED_PACKAGE_ID
        and package.get("upstream_commit") == base.EXPECTED_UPSTREAM_COMMIT
        and package.get("upstream_archive_sha256")
        == base.EXPECTED_ARCHIVE_SHA256
    ):
        raise LabError("Pulsar asset provenance does not match v2.0")

    selected: dict[str, Path] = {}
    images = _manifest_records(manifest, "additional_raw_images")
    for name in RAW_NAMES:
        record = images.get(name)
        if not record:
            raise LabError(f"manifest is missing {name}")
        path = base._resolved_asset(str(record.get("path", "")))
        if base.file_sha256(path) != record.get("sha256"):
            raise LabError(f"Pulsar asset hash mismatch: {name}")
        selected[name] = path

    caml = _manifest_records(manifest, "additional_caml_variants")
    for name in ("low_power_motion_enabled.caml", "replaykit.caml"):
        record = caml.get(name)
        if not record:
            raise LabError(f"manifest is missing {name}")
        path = base._resolved_asset(str(record.get("path", "")))
        if base.file_sha256(path) != record.get("sha256"):
            raise LabError(f"Pulsar CAML hash mismatch: {name}")
        selected[name] = path

    catalog = manifest.get("flashlight_catalog", {})
    if not isinstance(catalog, dict):
        raise LabError("manifest is missing Flashlight catalog metadata")
    car = base._resolved_asset(str(catalog.get("path", "")))
    if base.file_sha256(car) != catalog.get("sha256"):
        raise LabError("Pulsar Flashlight Assets.car hash mismatch")
    names = {
        record.get("Name")
        for record in catalog.get("renditions", [])
        if isinstance(record, dict)
    }
    required = {"FlashlightOff", "FlashlightOn"}
    if not required.issubset(names):
        raise LabError(
            "Pulsar Flashlight catalog lacks required artwork: "
            + ", ".join(sorted(required - names))
        )
    selected["FlashlightAssets.car"] = car
    selected["MotionInfo.plist"] = MOTION_INFO_PLIST
    selected["FlashlightInfo.plist"] = FLASHLIGHT_INFO_PLIST
    selected["PackageIndex.xml"] = PACKAGE_INDEX
    return selected


def port_caml(source: Path, remote_directory: str) -> str:
    validate_remote_directory(remote_directory)
    text = source.read_text(encoding="utf-8")
    old_prefix = UPSTREAM_IMAGE_ROOT + "/"
    if old_prefix not in text:
        raise LabError(f"upstream CAML image root is missing: {source}")
    text = text.replace(old_prefix, remote_directory + "/")
    references = set(re.findall(r'src="([^"]+)"', text))
    expected_prefix = remote_directory + "/"
    if not references or not all(
        path.startswith(expected_prefix) for path in references
    ):
        raise LabError(f"ported CAML failed path validation: {source}")
    staged_names = set(RAW_NAMES)
    missing = sorted(
        Path(path).name for path in references
        if Path(path).name not in staged_names
    )
    if missing:
        raise LabError(
            "ported CAML references unstaged artwork: " + ", ".join(missing)
        )
    return text


def build(
    *, token: str = "", expected_pid: int = 0, hold_seconds: int = 45,
    theme_directory: str | None = None,
) -> Path:
    base.validate_hold_seconds(hold_seconds)
    if expected_pid < 0:
        raise LabError("expected PID cannot be negative")
    theme_directory = theme_directory or (
        "/var/tmp/cyanide-pulsar-additional-controls-a1"
    )
    validate_remote_directory(theme_directory)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_pulsar_additional_controls_canary.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_PULSAR_ADDITIONAL_OUTPUT_TOKEN="{base.c_literal(token)}"',
        f'-DCND_PULSAR_ADDITIONAL_REPORT_PATH="{REPORT}"',
        "-DCND_PULSAR_ADDITIONAL_THEME_DIRECTORY="
        f'"{base.c_literal(theme_directory)}"',
        f"-DCND_PULSAR_ADDITIONAL_EXPECTED_PID={expected_pid}",
        f"-DCND_PULSAR_ADDITIONAL_HOLD_SECONDS={hold_seconds}",
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "CoreGraphics", "-framework", "QuartzCore",
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def stage_assets(ssh: SSH, remote_directory: str) -> None:
    validate_remote_directory(remote_directory)
    assets = load_assets()
    motion_bundle = remote_directory + "/PulsarAdditionalMotion.bundle"
    low_power_package = motion_bundle + "/LowPower.ca"
    replaykit_package = motion_bundle + "/ReplayKit.ca"
    flashlight_bundle = remote_directory + "/PulsarFlashlight.bundle"
    directories = (
        remote_directory,
        motion_bundle,
        low_power_package,
        replaykit_package,
        flashlight_bundle,
    )
    quoted_directories = " ".join(shlex.quote(item) for item in directories)
    ssh.command(
        f"/iosbinpack64/bin/mkdir -p {quoted_directories} && "
        f"/iosbinpack64/bin/chmod 0700 {quoted_directories}"
    )
    remote_files: list[str] = []
    for name in RAW_NAMES:
        destination = remote_directory + "/" + name
        ssh.copy(assets[name], destination)
        remote_files.append(destination)
    for source, destination in (
        (assets["MotionInfo.plist"], motion_bundle + "/Info.plist"),
        (assets["FlashlightInfo.plist"], flashlight_bundle + "/Info.plist"),
        (assets["FlashlightAssets.car"], flashlight_bundle + "/Assets.car"),
    ):
        ssh.copy(source, destination)
        remote_files.append(destination)
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        for source_name, package in (
            ("low_power_motion_enabled.caml", low_power_package),
            ("replaykit.caml", replaykit_package),
        ):
            ported = temporary / source_name
            ported.write_text(
                port_caml(assets[source_name], remote_directory),
                encoding="utf-8",
            )
            main_destination = package + "/main.caml"
            index_destination = package + "/index.xml"
            ssh.copy(ported, main_destination)
            ssh.copy(assets["PackageIndex.xml"], index_destination)
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
        "else echo '[CND_PULSAR_ADDITIONAL] report-not-created'; fi"
    )


def inject(ssh: SSH, hold_seconds: int = 45) -> tuple[int, str, str, str]:
    base.validate_hold_seconds(hold_seconds)
    pid, command = resolve_target(ssh, "SpringBoard")
    if pid <= 1 or command != TARGETS["SpringBoard"]:
        raise LabError("refusing: SpringBoard identity mismatch")
    token = issue_file_extension(ssh, "/var/tmp")
    remote_assets = (
        f"/var/tmp/cyanide-pulsar-additional-controls-{time.time_ns():x}"
    )
    payload = build(
        token=token,
        expected_pid=pid,
        hold_seconds=hold_seconds,
        theme_directory=remote_assets,
    )
    stage_assets(ssh, remote_assets)
    digest = base.file_sha256(payload)[:16]
    remote = f"/var/tmp/cnd-pulsar-additional-controls-{digest}.dylib"
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
    deadline = time.monotonic() + 32.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if " VISIBLE_READY " in latest and " themeApplied=1 " in latest:
            return pid, remote, remote_assets, latest
        if " COMPLETE " in latest:
            raise LabError(
                "additional-controls canary completed before becoming visible:\n"
                + latest.rstrip()
            )
        time.sleep(0.25)
    raise LabError(
        "additional-controls canary did not become visible:\n" + latest.rstrip()
    )


def wait_for_complete(ssh: SSH, hold_seconds: int) -> str:
    deadline = time.monotonic() + hold_seconds + 15.0
    latest = ""
    while time.monotonic() < deadline:
        latest = read_report(ssh)
        if " COMPLETE " in latest:
            if " status=success " not in latest:
                raise LabError(
                    "additional-controls canary did not restore successfully:\n"
                    + latest
                )
            return latest
        time.sleep(0.25)
    raise LabError(
        "additional-controls canary did not restore before deadline:\n"
        + latest
    )


def run_canary(ssh: SSH, hold_seconds: int) -> Path:
    inject(ssh, hold_seconds)
    time.sleep(1.0)
    base.capture_screenshot(VISIBLE_SCREENSHOT)
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
            f"Pulsar additional controls visible pid={pid} payload={remote} "
            f"assets={assets} hold={args.hold_seconds}s "
            "restoration=scheduled control-actions=0 hardware-spoof=no"
        )
        return 0
    report = run_canary(ssh, args.hold_seconds)
    visible_hash = hashlib.sha256(VISIBLE_SCREENSHOT.read_bytes()).hexdigest()
    restored_hash = hashlib.sha256(RESTORED_SCREENSHOT.read_bytes()).hexdigest()
    print(
        f"Pulsar additional-controls canary complete report={report} "
        f"visible={VISIBLE_SCREENSHOT} visibleSHA256={visible_hash} "
        f"restored={RESTORED_SCREENSHOT} restoredSHA256={restored_hash}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LabError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}")
        raise SystemExit(1)
