#!/usr/bin/env python3
"""Build, inject, capture, and summarize the vPhone Pulsar Control Center trace."""

from __future__ import annotations

import argparse
import collections
import hashlib
import os
import re
import shlex
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
SOURCE = REPO_ROOT / "scripts/lab/cnd_pulsar_controlcenter_trace.m"
BUILD_DIR = REPO_ROOT / "build/lab-pulsar-controlcenter-trace"
REPORT = "/var/tmp/cyanide-pulsar-controlcenter-trace.log"
INJECT_LOG = "/var/tmp/cyanide-pulsar-controlcenter-trace-inject.log"
LOCAL_REPORT = BUILD_DIR / "cyanide-pulsar-controlcenter-trace.log"
CONNECTIVITY_REPORT = "/var/tmp/cyanide-pulsar-connectivity-trace.log"
CONNECTIVITY_INJECT_LOG = "/var/tmp/cyanide-pulsar-connectivity-trace-inject.log"
CONNECTIVITY_LOCAL_REPORT = BUILD_DIR / "cyanide-pulsar-connectivity-trace.log"
CONNECTIVITY_ASSET_REMOTE_DIR = "/var/tmp/cyanide-pulsar-connectivity-assets"
CONNECTIVITY_LOCAL_ASSET_DIR = BUILD_DIR / "connectivity-assets"
FOCI = ("control-center", "connectivity")

# Canonical paths in Phuc Do's Pulsar Control Center UI v2.0 Misaka payload.
# They are reference names, not paths that this iOS 26 probe writes.
PULSAR_CAR_MODULES = (
    "AccessibilityGuidedAccessControlCenterModule",
    "AccessibilityShorcutsModule",
    "AccessibilitySoundDetectionControlCenterModule",
    "AccessibilityTextSizeModule",
    "AlarmModule",
    "CalculatorModule",
    "CameraModule",
    "ConnectivityModule",
    "DisplayModule",
    "FlashlightModule",
    "MagnifierModule",
    "NFCControlCenterModule",
    "PerformanceTraceModule",
    "QRCodeModule",
    "StopwatchModule",
    "TVRemoteModule",
    "VoiceMemosModule",
    "WalletModule",
)

PULSAR_CAML_TARGETS = (
    "AppearanceModule/StyleMode.ca",
    "ConnectivityModule/Bluetooth.ca",
    "ConnectivityModule/WiFi.ca",
    "DisplayModule/Brightness.ca",
    "HearingAidsModule/HAE_1_x_1.ca",
    "LowPowerModule/LowPower.ca",
    "MuteModule/Mute.ca",
    "OrientationLockModule/OrientationLock.ca",
    "ReplayKitModule/replaykit.ca",
    "ShazamModule/Shazam.ca",
    "AirPlayMirroringModule/MPAVScreenMirroring.ca",
)


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def trace_paths(focus: str) -> tuple[str, str, Path, str]:
    if focus == "control-center":
        return REPORT, INJECT_LOG, LOCAL_REPORT, "cnd_pulsar_controlcenter_trace"
    if focus == "connectivity":
        return (CONNECTIVITY_REPORT, CONNECTIVITY_INJECT_LOG,
                CONNECTIVITY_LOCAL_REPORT, "cnd_pulsar_connectivity_trace")
    raise LabError(f"unknown trace focus: {focus}")


def build(output_token: str = "", duration: int = 180,
          focus: str = "control-center") -> Path:
    if duration < 30 or duration > 600:
        raise LabError("trace duration must be between 30 and 600 seconds")
    report, _, _, output_name = trace_paths(focus)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / f"{output_name}.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra",
        "-Werror",
        f'-DCND_PULSAR_TRACE_OUTPUT_TOKEN="{c_literal(output_token)}"',
        f"-DCND_PULSAR_TRACE_DURATION={duration}",
        f'-DCND_PULSAR_TRACE_REPORT_PATH="{c_literal(report)}"',
        f"-DCND_PULSAR_TRACE_CONNECTIVITY={int(focus == 'connectivity')}",
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-framework", "QuartzCore", "-framework", "CoreGraphics",
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def read_report(ssh: SSH, report: str = REPORT) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(report)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(report)}; "
        "else echo '[CND_PULSAR] report-not-created'; fi"
    )


def capture_report(ssh: SSH, remote_report: str = REPORT,
                   local_report: Path | None = None) -> Path:
    if local_report is None:
        local_report = LOCAL_REPORT
    data = ssh.read_file(remote_report)
    local_report.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".cyanide-pulsar-controlcenter-trace-",
            suffix=".log", dir=local_report.parent, delete=False,
        ) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
        os.replace(temporary, local_report)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return local_report


def capture_connectivity_assets(ssh: SSH) -> tuple[Path, ...]:
    listing = ssh.command(
        f"/iosbinpack64/usr/bin/find "
        f"{shlex.quote(CONNECTIVITY_ASSET_REMOTE_DIR)} -maxdepth 1 "
        "-type f -name '*.png' -print"
    )
    remote_paths = sorted(
        (line.strip() for line in listing.splitlines() if line.strip()),
        key=str.casefold,
    )
    CONNECTIVITY_LOCAL_ASSET_DIR.mkdir(parents=True, exist_ok=True)
    captured: list[Path] = []
    for remote_path in remote_paths:
        remote = Path(remote_path)
        if (str(remote.parent) != CONNECTIVITY_ASSET_REMOTE_DIR or
                not re.fullmatch(r"[A-Za-z0-9_.-]+\.png", remote.name)):
            raise LabError(f"refusing unexpected connectivity asset: {remote_path}")
        data = ssh.read_file(remote_path)
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise LabError(f"connectivity export is not PNG: {remote_path}")
        local = CONNECTIVITY_LOCAL_ASSET_DIR / remote.name
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=f".{remote.stem}-", suffix=".png",
                dir=CONNECTIVITY_LOCAL_ASSET_DIR, delete=False,
            ) as stream:
                temporary = Path(stream.name)
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
            os.replace(temporary, local)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        captured.append(local)
    return tuple(captured)


def inject(ssh: SSH, duration: int,
           focus: str = "control-center") -> tuple[int, str, str]:
    report, inject_log, _, output_name = trace_paths(focus)
    pid, command = resolve_target(ssh, "SpringBoard")
    if pid <= 1 or command != TARGETS["SpringBoard"]:
        raise LabError("refusing: SpringBoard identity mismatch")
    token = issue_file_extension(ssh, "/var/tmp")
    payload = build(token, duration, focus)
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/{output_name.replace('_', '-')}-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, current_command = resolve_target(ssh, "SpringBoard")
    if current_pid != pid or current_command != TARGETS["SpringBoard"]:
        raise LabError(
            "refusing: SpringBoard identity changed before injection "
            f"({pid} -> {current_pid})"
        )
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(report)} "
        f"{shlex.quote(inject_log)}; "
        f"current=$(/bin/ps -p {pid} -o command=); "
        f"if test \"$current\" != {shlex.quote(command)}; then "
        "echo 'target identity changed' >&2; exit 90; fi; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(inject_log)} 2>&1; status=$?; "
        "if test \"$status\" = 124 -o \"$status\" = 137; then "
        "exit 0; fi; exit \"$status\""
    )
    deadline = time.monotonic() + 12.0
    latest = ""
    marker = f"TRACE_READY\tpid={pid}"
    while time.monotonic() < deadline:
        latest = read_report(ssh, report)
        if marker in latest:
            match = re.search(r"TRACE_READY\tpid=\d+\thooks=(\d+)", latest)
            if match and int(match.group(1)) >= 3:
                return pid, remote, latest
        time.sleep(0.25)
    raise LabError(
        "Pulsar Control Center trace did not become ready; report follows:\n"
        + latest.rstrip()
    )


def mark(ssh: SSH, label: str, report: str = REPORT) -> None:
    clean = re.sub(r"[^A-Za-z0-9_.:-]+", "-", label).strip("-")
    if not clean:
        raise LabError("marker must contain at least one safe character")
    ssh.command(
        f"printf '%s\\n' "
        f"{shlex.quote('[CND_PULSAR]\tMARK\tlabel=' + clean)} "
        f">>{shlex.quote(report)}"
    )


def parse_fields(line: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in line.split("\t")[2:]:
        key, separator, value = part.partition("=")
        if separator and key:
            fields[key] = value
    return fields


def summarize(report: str) -> str:
    route_counts: collections.Counter[str] = collections.Counter()
    hooks: set[tuple[str, str]] = set()
    values: dict[str, set[str]] = collections.defaultdict(set)
    controller_classes: set[str] = set()
    module_identifiers: set[str] = set()
    markers: list[str] = []
    connectivity_images: dict[str, set[str]] = collections.defaultdict(set)
    connectivity_states: collections.Counter[str] = collections.Counter()
    ready = False
    complete = False
    for raw_line in report.splitlines():
        # Captures made before the marker writer fix contain escaped tabs.
        line = raw_line.replace("\\t", "\t")
        if not line.startswith("[CND_PULSAR]\t"):
            continue
        fields = parse_fields(line)
        if "\tTRACE_READY\t" in line:
            ready = True
        elif "\tTRACE_COMPLETE\t" in line:
            complete = True
        elif "\tHOOK\t" in line:
            hooks.add((fields.get("class", "-"), fields.get("selector", "-")))
        elif "\tCONTROLLER\t" in line:
            class_name = fields.get("class", "-")
            if class_name != "-":
                controller_classes.add(class_name)
            identity = fields.get("identity", "-")
            prefix = "moduleIdentifier="
            if identity.startswith(prefix):
                module_identifiers.add(identity[len(prefix):])
        elif "\tMARK\t" in line:
            label = fields.get("label", "-")
            if label != "-" and label not in markers:
                markers.append(label)
        elif "\tCONNECTIVITY_IMAGE\t" in line:
            owner = fields.get("owner", "-").partition("/")[2] or "-"
            detail = (
                f"state={fields.get('scalars', '-')} "
                f"points={fields.get('points', '-')} "
                f"pixels={fields.get('pixels', '-')} "
                f"sha256={fields.get('sha256', '-')}"
            )
            connectivity_images[owner].add(detail)
        elif "\tCONNECTIVITY_STATE\t" in line:
            owner = fields.get("owner", "-").partition("/")[2] or "-"
            transition = (
                f"{fields.get('selector', '-')}={fields.get('value', '-')}"
            )
            connectivity_states[f"{owner} {transition}"] += 1
        elif "\tEVENT\t" in line:
            route = fields.get("route", "unknown")
            route_counts[route] += 1
            for key in ("a0", "a1", "a2", "identity", "resultValue"):
                value = fields.get(key, "-")
                if value and value != "-":
                    values[route].add(value)

    # Misaka paths insert `.bundle` between the module and CAML directory,
    # while the canonical manifest uses the logical module-relative path.
    lower = report.lower().replace(".bundle/", "/")
    car_hits = [name for name in PULSAR_CAR_MODULES
                if name.lower() in lower]
    caml_hits = [target for target in PULSAR_CAML_TARGETS
                 if target.lower() in lower]
    lines = [
        "Pulsar Control Center trace summary",
        f"ready={str(ready).lower()} complete={str(complete).lower()} "
        f"hooks={len(hooks)} events={sum(route_counts.values())}",
        f"controller-classes={len(controller_classes)} "
        f"module-identifiers={len(module_identifiers)} markers={len(markers)}",
    ]
    if controller_classes:
        lines.append("controller classes:")
        lines.extend(f"  {name}" for name in sorted(
            controller_classes, key=str.casefold))
    if module_identifiers:
        lines.append("module identifiers:")
        lines.extend(f"  {name}" for name in sorted(
            module_identifiers, key=str.casefold))
    if markers:
        lines.append("interaction markers:")
        lines.extend(f"  {label}" for label in markers)
    if connectivity_images:
        fingerprints = {
            detail.rpartition("sha256=")[2]
            for details in connectivity_images.values()
            for detail in details
        }
        lines.append(
            f"connectivity images: {len(fingerprints)} unique fingerprints"
        )
        for owner in sorted(connectivity_images, key=str.casefold):
            lines.append(f"  {owner}:")
            lines.extend(
                f"    {detail}" for detail in sorted(
                    connectivity_images[owner], key=str.casefold)
            )
    if connectivity_states:
        lines.append("connectivity state setters:")
        for transition, count in sorted(connectivity_states.items()):
            lines.append(f"  {transition} ({count})")
    for route, count in sorted(route_counts.items()):
        lines.append(f"route {route}: {count}")
        for value in sorted(values[route], key=str.casefold)[:20]:
            lines.append(f"  {value}")
        if len(values[route]) > 20:
            lines.append(f"  ... {len(values[route]) - 20} more unique values")
    lines.append(
        "legacy CAR target names observed: "
        + (", ".join(car_hits) if car_hits else "none")
    )
    lines.append(
        "legacy CAML target names observed: "
        + (", ".join(caml_hits) if caml_hits else "none")
    )
    return "\n".join(lines)


def require_live_host(parser: argparse.ArgumentParser, host: str | None) -> str:
    if not host:
        parser.error("--host is required for live actions")
    return host


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=("build", "inject", "read", "capture", "capture-summary",
                 "summary", "mark"),
    )
    parser.add_argument("label", nargs="?", default="")
    parser.add_argument("--host", default=None,
                        help="vPhone guest host (required for live actions)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--duration", type=int, default=180)
    parser.add_argument("--focus", choices=FOCI, default="control-center")
    parser.add_argument("--report", type=Path, default=None,
                        help="local report used by the summary action")
    args = parser.parse_args()

    remote_report, _, local_report, _ = trace_paths(args.focus)

    if args.action == "build":
        print(build(duration=args.duration, focus=args.focus))
        return 0
    if args.action == "summary":
        report_path = args.report or local_report
        if not report_path.is_file():
            raise LabError(f"local report not found: {report_path}")
        print(summarize(report_path.read_text(
            encoding="utf-8", errors="replace")))
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError(
            "refusing: this trace requires vPhone root SSH on port 22222"
        )
    host = require_live_host(parser, args.host)
    if not args.known_hosts.is_file():
        raise LabError(f"known-hosts file does not exist: {args.known_hosts}")
    ssh = SSH(host, args.port, args.user, args.known_hosts, args.password_env)
    require_vphone(ssh)
    if args.action == "read":
        print(read_report(ssh, remote_report), end="")
        return 0
    if args.action in ("capture", "capture-summary"):
        path = capture_report(ssh, remote_report, local_report)
        print(path)
        if args.focus == "connectivity":
            assets = capture_connectivity_assets(ssh)
            print(
                f"captured-connectivity-assets={len(assets)} "
                f"directory={CONNECTIVITY_LOCAL_ASSET_DIR}"
            )
        if args.action == "capture-summary":
            print(summarize(path.read_text(encoding="utf-8", errors="replace")))
        return 0
    if args.action == "mark":
        mark(ssh, args.label, remote_report)
        return 0
    pid, remote, _ = inject(ssh, args.duration, args.focus)
    print(
        f"Pulsar Control Center trace ready pid={pid} payload={remote} "
        f"report={remote_report} duration={args.duration}s "
        f"focus={args.focus} no-system-write=yes"
    )
    print(
        "Exercise Control Center, expanded controls, state changes, and the "
        "gallery; then use capture-summary before the VM is stopped."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
