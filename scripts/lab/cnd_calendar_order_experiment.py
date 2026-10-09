#!/usr/bin/env python3
"""Prepare, execute, and preserve exact VM Calendar ordering evidence."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import cnd_calendar_order_trigger as trigger
import cnd_dynamic_icon_trace as tracer
from cnd_iconservices_inspection import build_trigger, copy_executable
from cnd_remotecall_lab import (
    DEFAULT_KNOWN_HOSTS,
    LabError,
    SSH,
    TARGETS,
    require_vphone,
    resolve_target,
)


DEFAULT_EVIDENCE_PARENT = (
    Path.home() / "Library/CyanideVPhoneLab/evidence/calendar-order"
)
VM_SOCKET = (
    Path.home() /
    "Library/CyanideVPhoneLab/VMs/cyanide-ios26-base/vphone.sock"
)
SESSION_NAME = "session.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_evidence_root(target: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return DEFAULT_EVIDENCE_PARENT / f"{stamp}-{target.lower()}"


def capture_screenshot(path: Path) -> None:
    if not VM_SOCKET.exists():
        raise LabError(f"vPhone control socket is unavailable: {VM_SOCKET}")
    path.parent.mkdir(parents=True, exist_ok=True)
    request = {"t": "screenshot", "path": str(path)}
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
    if not result.get("ok") or not path.is_file():
        raise LabError(f"VM screenshot failed: {result.get('error', result)}")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def read_session(root: Path) -> dict[str, object]:
    path = root / SESSION_NAME
    if not path.is_file():
        raise LabError(f"Calendar order session is not prepared: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise LabError(f"invalid Calendar order session: {path}")
    return value


def persistent_calendar_snapshot(ssh: SSH) -> tuple[list[dict[str, object]], str]:
    executable = copy_executable(
        ssh, build_trigger(), "cnd-calendar-order-persistent"
    )
    records: list[dict[str, object]] = []
    raw_sections: list[str] = []
    for point_size, appearance in (
        (27, 0), (27, 1), (48, 0), (68, 0), (68, 1),
    ):
        descriptor = f"{point_size}x{point_size}@3:a{appearance}:v0:o0"
        output = ssh.command(
            f"{executable} --bundle com.apple.mobilecal "
            f"--point-size {point_size} --appearance {appearance}"
        )
        raw_sections.append(f"--- {descriptor} ---\n{output.rstrip()}\n")
        start = re.search(r" digest=([^ ]+) .*description=", output)
        complete = re.search(
            r"CND_ICON_TRIGGER complete .* uuid=([^ ]+) "
            r"data=([0-9]+)/([0-9a-f]{64}|-) "
            r"token=([0-9]+)/([0-9a-f]{64}|-) "
            r"pixels=([0-9]+)x([0-9]+) rgba=([0-9a-f]{64}|-)",
            output,
        )
        if not start or not complete or complete.group(1) == "-" or \
                complete.group(8) == "-":
            raise LabError(
                f"Calendar persistent record did not verify for {descriptor}"
            )
        records.append({
            "descriptor": descriptor,
            "descriptorDigest": start.group(1),
            "uuid": complete.group(1),
            "dataLength": int(complete.group(2)),
            "dataSHA256": complete.group(3),
            "validationTokenLength": int(complete.group(4)),
            "validationTokenSHA256": complete.group(5),
            "pixelWidth": int(complete.group(6)),
            "pixelHeight": int(complete.group(7)),
            "pixelSHA256": complete.group(8),
        })
    return records, "\n".join(raw_sections)


def prepare(ssh: SSH, root: Path, target: str) -> dict[str, object]:
    if (root / SESSION_NAME).exists():
        raise LabError(
            f"refusing to overwrite an existing evidence session: {root}"
        )
    require_vphone(ssh)
    pid, command = resolve_target(ssh, target)
    if command != TARGETS[target]:
        raise LabError(f"{target} identity mismatch")
    trace_pid, remote = tracer.inject(ssh, False, target)
    if trace_pid != pid:
        raise LabError(f"{target} changed while installing its tracer")
    root.mkdir(parents=True, exist_ok=False)
    persistent_records, persistent_log = persistent_calendar_snapshot(ssh)
    (root / "00-persistent-calendar.log").write_text(
        persistent_log, encoding="utf-8"
    )
    screenshot = root / "00-prepared.png"
    capture_screenshot(screenshot)
    session: dict[str, object] = {
        "schema": 1,
        "createdAt": utc_now(),
        "target": target,
        "pid": pid,
        "command": command,
        "remoteTracePayload": remote,
        "remoteTraceReport": tracer.trace_paths(target)[0],
        "persistentCalendarRecords": persistent_records,
        "persistentCalendarRecordCount": len(persistent_records),
        "persistentCalendarLog": "00-persistent-calendar.log",
        "vmIdentity": {
            "build": "23A341",
            "deviceProfile": "iPhone17,3",
        },
        "noRecursiveViewWalk": True,
        "experiments": [],
    }
    write_json(root / SESSION_NAME, session)
    return session


def bounded_trace_slice(report: str, outer_label: str) -> str:
    begin = f"[CND_DYNAMIC] MARK {outer_label}-begin"
    end = f"[CND_DYNAMIC] MARK {outer_label}-end"
    begin_index = report.rfind(begin)
    end_index = report.find(end, begin_index + len(begin))
    if begin_index < 0 or end_index < 0:
        raise LabError(
            f"trace markers are incomplete for {outer_label}: "
            f"begin={begin_index} end={end_index}"
        )
    line_end = report.find("\n", end_index)
    if line_end < 0:
        line_end = len(report)
    return report[begin_index:line_end + 1]


def summarize_trace(trace: str) -> dict[str, object]:
    lines = trace.splitlines()
    operation_marks: list[dict[str, object]] = []
    resets: list[dict[str, object]] = []
    calendar_events: list[dict[str, object]] = []
    pixel_hashes: list[str] = []
    generations: list[int] = []
    for index, line in enumerate(lines):
        if "[CND_CALENDAR_ORDER] MARK " in line:
            label = re.search(r" label=([^ ]+)", line)
            phase = re.search(r" phase=([^ ]+)", line)
            operation_marks.append({
                "line": index,
                "label": label.group(1) if label else "",
                "phase": phase.group(1) if phase else "",
            })
        if "CACHE_BOUNDARY" in line:
            phase = re.search(r" phase=([^ ]+)", line)
            resets.append({
                "line": index,
                "phase": phase.group(1) if phase else "",
                "text": line,
            })
        calendar_line = (
            "com.apple.mobilecal" in line or
            "SBCalendarIconImageProvider" in line or
            "SBHCalendarApplicationIcon" in line or
            "kind=calendar" in line
        )
        if calendar_line:
            calendar_events.append({"line": index, "text": line})
            for match in re.finditer(r"pixel-sha256=([0-9a-f]{64})", line):
                if match.group(1) not in pixel_hashes:
                    pixel_hashes.append(match.group(1))
            generation = re.search(r"image-generation=1/([0-9]+)", line)
            if generation:
                generations.append(int(generation.group(1)))
    operation_ranges: dict[str, dict[str, int]] = {}
    for mark in operation_marks:
        label = str(mark["label"])
        phase = str(mark["phase"])
        if phase in ("begin", "end"):
            operation_ranges.setdefault(label, {})[phase] = int(mark["line"])
    return {
        "lineCount": len(lines),
        "operationMarks": operation_marks,
        "operationRanges": operation_ranges,
        "cacheBoundaries": resets,
        "calendarEventCount": len(calendar_events),
        "calendarEvents": calendar_events,
        "calendarPixelHashes": pixel_hashes,
        "calendarGenerations": generations,
        "calendarBundleSourceObserved": any(
            "kind=calendar-bundle" in line for line in lines
        ),
        "proceduralCalendarSourceObserved": any(
            "CUIKIcon" in line and "calendar" in line.lower()
            for line in lines
        ),
        "resetObserved": any(
            item["phase"] == "reset-enter" for item in resets
        ),
    }


def parse_trigger_result(report: str) -> dict[str, object]:
    matches = [line for line in report.splitlines()
               if line.startswith("[CND_CALENDAR_ORDER] COMPLETE ")]
    if len(matches) != 1 or " result=" not in matches[0]:
        raise LabError("Calendar trigger report has no unique COMPLETE result")
    value = json.loads(matches[0].split(" result=", 1)[1])
    if not isinstance(value, dict):
        raise LabError("Calendar trigger COMPLETE result is not a dictionary")
    return value


def execute(ssh: SSH, root: Path, sequence: str) -> dict[str, object]:
    session = read_session(root)
    target = str(session.get("target", ""))
    expected_pid = int(session.get("pid", 0))
    if sequence.startswith("spotlight-") != (target == "Spotlight"):
        raise LabError(
            f"sequence {sequence} does not match prepared target {target}"
        )
    live_pid, live_command = resolve_target(ssh, target)
    if live_pid != expected_pid or live_command != session.get("command"):
        raise LabError(
            f"{target} identity changed since prepare: "
            f"{expected_pid} -> {live_pid}"
        )
    experiments = session.get("experiments", [])
    if not isinstance(experiments, list):
        raise LabError("invalid experiments list in Calendar order session")
    number = len(experiments) + 1
    outer_label = re.sub(
        r"[^A-Za-z0-9_.:-]+", "-", f"experiment-{number}-{sequence}"
    )
    tracer.mark(ssh, outer_label + "-begin", target)
    before_path = root / f"{number:02d}-{sequence}-before.png"
    capture_screenshot(before_path)
    action_pid, remote, trigger_report = trigger.inject(
        ssh, sequence, target
    )
    tracer.mark(ssh, outer_label + "-end", target)
    after_path = root / f"{number:02d}-{sequence}-after.png"
    capture_screenshot(after_path)
    final_pid, final_command = resolve_target(ssh, target)
    if final_pid != expected_pid or final_command != session.get("command"):
        raise LabError(f"{target} restarted during {sequence}")
    full_trace = tracer.read_report(ssh, target)
    trace = bounded_trace_slice(full_trace, outer_label)
    trace_path = root / f"{number:02d}-{sequence}.trace.log"
    trigger_path = root / f"{number:02d}-{sequence}.trigger.log"
    trace_path.write_text(trace, encoding="utf-8")
    trigger_path.write_text(trigger_report, encoding="utf-8")
    summary = summarize_trace(trace)
    trigger_result = parse_trigger_result(trigger_report)
    experiment = {
        "number": number,
        "recordedAt": utc_now(),
        "sequence": sequence,
        "target": target,
        "targetPIDBefore": expected_pid,
        "targetPIDAfter": final_pid,
        "targetPIDStable": final_pid == expected_pid,
        "directActionPID": action_pid,
        "directTargetDylib": True,
        "cyanideProcessUsed": False,
        "remoteTriggerPayload": remote,
        "trace": trace_path.name,
        "trigger": trigger_path.name,
        "beforeScreenshot": before_path.name,
        "afterScreenshot": after_path.name,
        "triggerOK": bool(trigger_result.get("ok")),
        "triggerResult": trigger_result,
        "summary": summary,
    }
    experiments.append(experiment)
    session["experiments"] = experiments
    session["updatedAt"] = utc_now()
    write_json(root / SESSION_NAME, session)
    write_json(root / f"{number:02d}-{sequence}.summary.json", experiment)
    return experiment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "execute", "status"))
    parser.add_argument("--target", choices=tracer.TRACE_TARGETS,
                        default="SpringBoard")
    parser.add_argument("--sequence", choices=trigger.ACTIONS,
                        default=trigger.ACTIONS[0])
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--host", default=None,
                        help="vPhone host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    args = parser.parse_args()

    root = args.root or default_evidence_root(args.target)
    if args.action == "status":
        print(json.dumps(read_session(root), indent=2, sort_keys=True))
        return 0
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    if args.action == "prepare":
        session = prepare(ssh, root, args.target)
        print(
            f"Calendar order trace prepared target={args.target} "
            f"pid={session['pid']} root={root}"
        )
        return 0
    require_vphone(ssh)
    result = execute(ssh, root, args.sequence)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
