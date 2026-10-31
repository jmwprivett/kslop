#!/usr/bin/env python3
"""Classify kernel panic reports against the 2026-10-15 VM lab-provider panic.

Read-only observation tool. It never builds, signs, installs, or launches
anything on a device, never opens the VM lab provider socket, and never
performs a kernel read, write, or call. Its only device-side actions are the
CoreDevice `systemCrashLogs` inventory and copy flows already documented in
docs/physical-device-logs.md.

Why this exists instead of a device build of the VM provider flow:

- scripts/lab/cnd_provide_tfp0.c acquires the kernel task through host special
  port 4 / task_for_pid(0), dlopens the vPhone jailbreak's /var/jb libkrw
  plugins, and uses the VRESEARCH-only syscall 439 kernel-call backend. None of
  those exist on the non-jailbroken iPhone17,2.
- docs/research/vm-guide.md: "Never broaden the VM syscall-439 backend into a
  physical-device claim."
- Cyanide/kexploit/CNDLabKernelProvider.h: "Physical-device KRW never routes
  through this API."

The one physical-side question that stays inside those rules is whether the
phone's own kernel has ever recorded the same panic class (a copyio data abort
into a freed "MAC Labels" zone element). This script answers that by reading
the device's existing panic reports, nothing more.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_ROOT = REPO_ROOT / "build"

# docs/physical-device-logs.md "Fixed device information". The other paired
# CoreDevice entry named only "iPhone" is the research VM (iPhone99,11) and is
# refused below.
PHYSICAL_DEVICE_ID = "828515D1-88C1-5CEB-A16F-5AD0AE3E3641"
PHYSICAL_PRODUCT = "iPhone17,2"
PHYSICAL_BUILD = "23A341"
PHYSICAL_KERNEL_FLAVOR = "RELEASE_ARM64_T8140"
VM_PRODUCT = "iPhone99,11"
VM_KERNEL_FLAVOR = "RELEASE_ARM64_VRESEARCH1"

KERNEL_ADDRESS_MASK = 0xFFFF000000000000
REPORT_SCHEMA = "com.zeroxjf.cyanide.physical-panic-signature"
REPORT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class PanicSignature:
    """Pinned from build/VMCrashLogs-20261015/panic-full-2026-10-15-171900.0002.ips."""

    panic_kind: str = "Kernel data abort"
    gzalloc_zone: str = "MAC Labels"
    gzalloc_kind_prefix: str = "use-after-free"
    esr: int = 0x9600004F
    copy_length: int = 0x18
    process_prefix: str = "cnd-provide-tfp0-"
    reference_report: str = (
        "build/VMCrashLogs-20261015/panic-full-2026-10-15-171900.0002.ips"
    )


VM_REFERENCE_SIGNATURE = PanicSignature()


@dataclass
class GZAllocReport:
    zone: str
    address: int
    kind: str


@dataclass
class PanicReport:
    path: str
    timestamp: str
    os_version: str
    product: str
    kernel: str
    panic_kind: str
    pc: int | None
    esr: int | None
    far: int | None
    registers: dict[str, int]
    panicked_pid: int | None
    panicked_process: str | None
    gzalloc: GZAllocReport | None
    kernel_slide: int | None
    kernel_text_base: int | None
    kernel_text_exec_base: int | None
    backtrace: list[int] = field(default_factory=list)

    @property
    def user_frames(self) -> list[int]:
        return [frame for frame in self.backtrace
                if frame & KERNEL_ADDRESS_MASK != KERNEL_ADDRESS_MASK]

    @property
    def kernel_flavor(self) -> str:
        if VM_KERNEL_FLAVOR in self.kernel:
            return VM_KERNEL_FLAVOR
        if PHYSICAL_KERNEL_FLAVOR in self.kernel:
            return PHYSICAL_KERNEL_FLAVOR
        return "unknown"

    @property
    def evidence_level(self) -> str:
        if self.product == PHYSICAL_PRODUCT and \
                self.kernel_flavor == PHYSICAL_KERNEL_FLAVOR:
            return "physical-observed"
        if self.product == VM_PRODUCT or \
                self.kernel_flavor == VM_KERNEL_FLAVOR:
            return "VM-observed"
        return "unknown-environment"


class ProbeError(RuntimeError):
    pass


def run(command: list[str]) -> str:
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        raise ProbeError(
            f"command failed ({result.returncode}): "
            f"{' '.join(command)}\n{result.stdout}"
        )
    return result.stdout


def _hex(match: re.Match[str] | None, group: int = 1) -> int | None:
    return int(match.group(group), 16) if match else None


def split_ips(text: str) -> tuple[dict[str, object], dict[str, object]]:
    """A modern .ips holds two consecutive JSON objects (metadata, payload)."""
    decoder = json.JSONDecoder()
    try:
        metadata, offset = decoder.raw_decode(text)
        while offset < len(text) and text[offset].isspace():
            offset += 1
        payload, _ = decoder.raw_decode(text, offset)
    except json.JSONDecodeError as error:
        raise ProbeError(f"panic report is not two JSON objects: {error}") from error
    if not isinstance(metadata, dict) or not isinstance(payload, dict):
        raise ProbeError("panic report objects have the wrong shape")
    return metadata, payload


def parse_panic_string(panic_string: str) -> dict[str, object]:
    first_line = panic_string.split("\n", 1)[0]
    kind_match = re.search(r"\):\s*(.*?)(?:\.)?\s+at pc\s+0x", first_line)
    panic_kind = kind_match.group(1).strip() if kind_match else \
        first_line.partition("): ")[2].strip()
    registers = {
        name: int(value, 16)
        for name, value in re.findall(
            r"\b(x\d{1,2}):\s+(0x[0-9a-fA-F]+)", panic_string)
    }
    esr_far = re.search(
        r"esr:\s+(0x[0-9a-fA-F]+)\s+far:\s+(0x[0-9a-fA-F]+)", panic_string)
    task = re.search(
        r"Panicked task 0x[0-9a-fA-F]+: \d+ pages, \d+ threads: "
        r"pid (\d+): ([^\n]+)",
        panic_string,
    )
    gzalloc = None
    gz_block = re.search(
        r"Probabilistic GZAlloc Report:\n((?:[ \t]+[^\n]*\n?)+)", panic_string)
    if gz_block:
        block = gz_block.group(1)
        zone = re.search(r"Zone\s*:\s*([^\n]+)", block)
        address = re.search(r"Address\s*:\s*(0x[0-9a-fA-F]+)", block)
        kind = re.search(r"Kind\s*:\s*([^\n]+)", block)
        if zone and address and kind:
            gzalloc = GZAllocReport(
                zone=zone.group(1).strip(),
                address=int(address.group(1), 16),
                kind=kind.group(1).strip(),
            )
    backtrace: list[int] = []
    thread_block = re.search(
        r"Panicked thread: [^\n]*\n((?:[ \t]*lr: 0x[0-9a-fA-F]+\s+fp: "
        r"0x[0-9a-fA-F]+\n?)+)",
        panic_string,
    )
    if thread_block:
        backtrace = [
            int(value, 16) for value in
            re.findall(r"lr: (0x[0-9a-fA-F]+)", thread_block.group(1))
        ]
    return {
        "panic_kind": panic_kind,
        "pc": _hex(re.search(r"\bpc:\s+(0x[0-9a-fA-F]+)", panic_string)),
        "esr": _hex(esr_far, 1),
        "far": _hex(esr_far, 2),
        "registers": registers,
        "panicked_pid": int(task.group(1)) if task else None,
        "panicked_process": task.group(2).strip() if task else None,
        "gzalloc": gzalloc,
        "kernel_slide": _hex(
            re.search(r"Kernel slide:\s+(0x[0-9a-fA-F]+)", panic_string)),
        "kernel_text_base": _hex(
            re.search(r"Kernel text base:\s+(0x[0-9a-fA-F]+)", panic_string)),
        "kernel_text_exec_base": _hex(re.search(
            r"Kernel text exec base:\s+(0x[0-9a-fA-F]+)", panic_string)),
        "backtrace": backtrace,
    }


def parse_panic_report(path: Path) -> PanicReport:
    metadata, payload = split_ips(path.read_text(encoding="utf-8", errors="replace"))
    panic_string = str(payload.get("panicString", ""))
    if not panic_string:
        raise ProbeError(f"panic report has no panicString: {path}")
    parsed = parse_panic_string(panic_string)
    return PanicReport(
        path=str(path),
        timestamp=str(metadata.get("timestamp", "")),
        os_version=str(metadata.get("os_version", "")),
        product=str(payload.get("product", "")),
        kernel=str(payload.get("kernel", "")),
        **parsed,
    )


def parse_route(text: str) -> tuple[str, int]:
    name, separator, value = text.partition("=")
    if not separator or not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", name) or \
            not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", value):
        raise ProbeError(
            "route must look like NAME=0xADDRESS (absolute slid address or "
            "offset from the report's 'Kernel text base')"
        )
    return name, int(value, 16)


def resolve_route(report: PanicReport, address: int) -> int | None:
    if address & KERNEL_ADDRESS_MASK == KERNEL_ADDRESS_MASK:
        return address
    if report.kernel_text_base is None:
        return None
    return report.kernel_text_base + address


def classify(report: PanicReport,
             routes: tuple[tuple[str, int], ...] = (),
             signature: PanicSignature = VM_REFERENCE_SIGNATURE,
             ) -> dict[str, object]:
    gz = report.gzalloc
    zone_matches = gz is not None and gz.zone == signature.gzalloc_zone
    kind_matches = gz is not None and \
        gz.kind.startswith(signature.gzalloc_kind_prefix)
    panic_kind_matches = report.panic_kind == signature.panic_kind
    esr_matches = report.esr == signature.esr
    copy_length_matches = report.registers.get("x2") == signature.copy_length
    far_in_gzalloc_element = gz is not None and report.far == gz.address
    lab_provider_process = bool(
        report.panicked_process and
        report.panicked_process.startswith(signature.process_prefix)
    )
    route_hits = {}
    for name, address in routes:
        resolved = resolve_route(report, address)
        route_hits[name] = {
            "resolved": f"0x{resolved:016x}" if resolved is not None else None,
            "inBacktrace": resolved is not None and resolved in report.backtrace,
        }
    return {
        "report": report.path,
        "timestamp": report.timestamp,
        "product": report.product,
        "osVersion": report.os_version,
        "kernel": report.kernel,
        "kernelFlavor": report.kernel_flavor,
        "evidenceLevel": report.evidence_level,
        "panicKind": report.panic_kind,
        "panickedPID": report.panicked_pid,
        "panickedProcess": report.panicked_process,
        "esr": f"0x{report.esr:x}" if report.esr is not None else None,
        "far": f"0x{report.far:016x}" if report.far is not None else None,
        "copyLength": (
            f"0x{report.registers['x2']:x}" if "x2" in report.registers else None
        ),
        "gzalloc": asdict(gz) | {"address": f"0x{gz.address:016x}"} if gz else None,
        "kernelFrames": len(report.backtrace) - len(report.user_frames),
        "userFrames": [f"0x{frame:x}" for frame in report.user_frames],
        "matchesVMSignature": zone_matches and kind_matches and panic_kind_matches,
        "signatureDetail": {
            "gzallocZone": zone_matches,
            "gzallocKind": kind_matches,
            "panicKind": panic_kind_matches,
            "esr": esr_matches,
            "copyLength": copy_length_matches,
            "farInsideGZAllocElement": far_in_gzalloc_element,
            "labProviderProcess": lab_provider_process,
        },
        "routeHits": route_hits,
        "referenceSignature": asdict(signature),
    }


def verify_device_identity(details: dict[str, object],
                           expected_id: str = PHYSICAL_DEVICE_ID,
                           ) -> dict[str, str]:
    result = details.get("result")
    if not isinstance(result, dict):
        raise ProbeError("devicectl details have no result object")
    hardware = result.get("hardwareProperties", {})
    device = result.get("deviceProperties", {})
    identity = {
        "identifier": str(result.get("identifier", "")),
        "productType": str(hardware.get("productType", "")),
        "osVersionNumber": str(device.get("osVersionNumber", "")),
        "osBuildUpdate": str(device.get("osBuildUpdate", "")),
        "name": str(device.get("name", "")),
    }
    if identity["productType"] == VM_PRODUCT:
        raise ProbeError(
            "refusing: this CoreDevice entry is the research VM, not the phone"
        )
    if identity["identifier"] != expected_id:
        raise ProbeError(
            f"refusing: device identifier {identity['identifier']!r} is not "
            f"the pinned physical device {expected_id}"
        )
    if identity["productType"] != PHYSICAL_PRODUCT or \
            identity["osBuildUpdate"] != PHYSICAL_BUILD:
        raise ProbeError(
            "refusing: device is not the exact "
            f"{PHYSICAL_PRODUCT} / {PHYSICAL_BUILD} target: {identity}"
        )
    return identity


def panic_reports_from_inventory(root: object) -> list[tuple[str, int, str]]:
    rows: list[tuple[str, int, str]] = []

    def walk(value: object) -> None:
        if isinstance(value, dict):
            path = str(value.get("relativePath", ""))
            if path.startswith("panic-full-") and path.endswith(".ips") and \
                    "/" not in path:
                metadata = value.get("metadata", {})
                rows.append((
                    str(metadata.get("lastModDate", "")),
                    int(metadata.get("size", 0)),
                    path,
                ))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(root)
    return sorted(set(rows), reverse=True)


def fresh_capture_dir(parent: Path, stamp: str | None = None) -> Path:
    stamp = stamp or time.strftime("%Y%m%d-%H%M%S")
    capture = parent / f"physical-panic-signature-{stamp}"
    if capture.exists():
        raise ProbeError(f"refusing to reuse an existing capture directory: {capture}")
    capture.mkdir(parents=True)
    return capture


def resumable_capture_dir(capture: Path) -> Path:
    if not capture.is_dir() or not (capture / "crash-files.json").is_file() or \
            not capture.name.startswith("physical-panic-signature-"):
        raise ProbeError(
            f"refusing to resume: not a probe capture directory: {capture}"
        )
    return capture


def device_details(device_id: str) -> dict[str, object]:
    with _temporary_json("details") as output:
        run([
            "xcrun", "devicectl", "device", "info", "details",
            "--device", device_id, "--json-output", str(output),
        ])
        return json.loads(output.read_text())


def device_crash_inventory(device_id: str, destination: Path) -> dict[str, object]:
    run([
        "xcrun", "devicectl", "device", "info", "files",
        "--device", device_id, "--domain-type", "systemCrashLogs",
        "--columns", "*", "--json-output", str(destination),
    ])
    return json.loads(destination.read_text())


def device_copy_report(device_id: str, relative_path: str, destination: Path) -> None:
    if not re.fullmatch(r"panic-full-[0-9-]+\.[0-9]+\.ips", relative_path):
        raise ProbeError(f"refusing to copy a non-panic report: {relative_path}")
    run([
        "xcrun", "devicectl", "device", "copy", "from",
        "--device", device_id, "--domain-type", "systemCrashLogs",
        "--source", relative_path, "--destination", str(destination),
    ])


class _temporary_json:
    def __init__(self, stem: str) -> None:
        self.path = Path(
            os.environ.get("TMPDIR", "/tmp")
        ) / f"cnd-panic-signature-{stem}-{os.getpid()}-{time.time_ns()}.json"

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, *_exc: object) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def classify_files(paths: list[Path],
                   routes: tuple[tuple[str, int], ...]) -> list[dict[str, object]]:
    results = []
    for path in paths:
        if not path.is_file():
            raise ProbeError(f"panic report is missing: {path}")
        results.append(classify(parse_panic_report(path), routes))
    return results


def summarize(results: list[dict[str, object]]) -> dict[str, object]:
    matching = [item["report"] for item in results if item["matchesVMSignature"]]
    levels = sorted({str(item["evidenceLevel"]) for item in results})
    return {
        "reports": len(results),
        "matchingVMSignature": matching,
        "evidenceLevels": levels,
        "panicKinds": sorted({str(item["panicKind"]) for item in results}),
        "panickedProcesses": sorted({
            str(item["panickedProcess"]) for item in results
        }),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    result.add_argument(
        "--route", action="append", default=[],
        help="NAME=0xADDRESS to look for in the panicked thread backtrace; "
             "values below the kernel address range are offsets from the "
             "report's 'Kernel text base'",
    )
    subparsers = result.add_subparsers(dest="command", required=True)

    offline = subparsers.add_parser(
        "classify", help="classify local .ips panic reports (VM or device copies)"
    )
    offline.add_argument("reports", nargs="+", type=Path)

    device = subparsers.add_parser(
        "device-inventory",
        help="list (and optionally copy + classify) the phone's panic-full reports",
    )
    device.add_argument("--device", default=PHYSICAL_DEVICE_ID)
    device.add_argument("--copy", action="store_true",
                        help="copy each panic-full report into a fresh capture dir")
    device.add_argument("--limit", type=int, default=None,
                        help="only consider the newest N panic-full reports")
    device.add_argument("--capture-root", type=Path, default=BUILD_ROOT)
    device.add_argument(
        "--resume", type=Path, default=None,
        help="continue an interrupted capture directory: reports already "
             "present are classified without copying; nothing is overwritten",
    )
    return result


def main() -> int:
    args = parser().parse_args()
    routes = tuple(parse_route(item) for item in args.route)

    if args.command == "classify":
        results = classify_files(list(args.reports), routes)
        print(json.dumps({"summary": summarize(results), "results": results},
                         indent=2, sort_keys=True))
        return 0

    identity = verify_device_identity(device_details(args.device), args.device)
    if args.resume is not None:
        capture = resumable_capture_dir(args.resume)
    else:
        capture = fresh_capture_dir(args.capture_root)
    inventory = device_crash_inventory(args.device, capture / "crash-files.json")
    rows = panic_reports_from_inventory(inventory)
    if args.limit is not None:
        if args.limit < 1:
            raise ProbeError("--limit must be at least 1")
        rows = rows[:args.limit]
    print(f"device={identity['identifier']} product={identity['productType']} "
          f"build={identity['osBuildUpdate']} panicFullReports={len(rows)} "
          f"capture={capture}")
    for modified, size, path in rows:
        print(f"{modified}\t{size:>10}\t{path}")

    results: list[dict[str, object]] = []
    copy_failures: dict[str, str] = {}
    if args.copy:
        for _modified, _size, relative in rows:
            destination = capture / relative
            if not destination.is_file():
                try:
                    device_copy_report(args.device, relative, destination)
                except ProbeError as error:
                    # CoreDevice transfers are occasionally interrupted; keep
                    # the evidence already gathered and record the gap.
                    copy_failures[relative] = str(error).splitlines()[0]
                    print(f"copy failed: {relative}", file=sys.stderr)
                    continue
            results.append(classify(parse_panic_report(destination), routes))
    record = {
        "schema": REPORT_SCHEMA,
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "capturedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "device": identity,
        "evidenceLevel": "physical-observed" if args.copy else "physical-inventory-only",
        "installedAnything": False,
        "launchedAnything": False,
        "kernelReadUsed": False,
        "kernelWriteUsed": False,
        "kernelCallUsed": False,
        "labProviderContacted": False,
        "panicFullReports": [
            {"lastModDate": m, "size": s, "relativePath": p} for m, s, p in rows
        ],
        "copyFailures": copy_failures,
        "complete": args.copy and not copy_failures,
        "summary": summarize(results) if args.copy else None,
        "results": results,
    }
    (capture / "panic-signature-report.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n"
    )
    if args.copy:
        print(json.dumps(record["summary"], indent=2, sort_keys=True))
    print(f"evidence={capture / 'panic-signature-report.json'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
