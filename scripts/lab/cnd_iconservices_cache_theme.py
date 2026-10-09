#!/usr/bin/env python3
"""Publish one themed app response through stock vPhone IconServices."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import time
from pathlib import Path

from cnd_iconservices_inspection import (
    BUILD_DIR,
    build_hold,
    build_trigger,
    copy_executable,
    start_hold,
    stop_hold,
    validate_bundle,
)
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
SOURCE = REPO_ROOT / "scripts/lab/cnd_iconservices_cache_theme.m"
THEME = REPO_ROOT / "Cyanide/IconRedirect/CNDIconRedirectTheme.png"
REPORT_PATH = "/var/tmp/cyanide-iconservices-theme-cache.log"
INJECT_LOG_PATH = "/var/tmp/cyanide-iconservices-theme-inject.log"
EXPECTED_THEME_HASH = (
    "74122c8aa948fc4e2d9d02148f62b88b8e4c77b1727cd34cf5632f9c6bbdca8b"
)
PDF_CANARY_SUBJECT = "CND_SPOTLIGHT_PDF_CANARY_V1"


def c_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_mutator(theme_path: str = "/var/tmp/cnd-iconservices-theme.png",
                  output_token: str = "", root_token: str = "",
                  opaque_black_background: bool = False,
                  flat_payload: bool = False,
                  pdf_canary_path: str = "",
                  expected_pdf_canary_hash: str = "",
                  bundle: str = "com.ebay.iphone",
                  point_size: int = 68, appearance: int = 0,
                  variant_options: int = 0,
                  expected_theme_hash: str = EXPECTED_THEME_HASH) -> Path:
    bundle = validate_bundle(bundle)
    output = BUILD_DIR / "cnd_iconservices_cache_theme.dylib"
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    observed_pixels = {13: 60, 20: 60, 27: 87, 28: 87, 48: 180}
    pixel_size = observed_pixels.get(point_size, point_size * 3)
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-Wall", "-Wextra", "-Werror", "-fobjc-arc",
        "-fblocks", f'-DCND_ICON_THEME_PATH="{c_literal(theme_path)}"',
        f'-DCND_ICON_THEME_OUTPUT_TOKEN="{c_literal(output_token)}"',
        f'-DCND_ICON_THEME_ROOT_TOKEN="{c_literal(root_token)}"',
        f'-DCND_ICON_THEME_TARGET_BUNDLE="{c_literal(bundle)}"',
        f"-DCND_ICON_THEME_OPAQUE_BLACK={int(opaque_black_background)}",
        f"-DCND_ICON_THEME_FLAT_PAYLOAD={int(flat_payload)}",
        f"-DCND_ICON_THEME_PDF_CANARY={int(bool(pdf_canary_path))}",
        f'-DCND_ICON_THEME_PDF_CANARY_PATH="{c_literal(pdf_canary_path)}"',
        f'-DCND_ICON_THEME_EXPECTED_PDF_SHA256="'
        f'{c_literal(expected_pdf_canary_hash)}"',
        f"-DCND_ICON_THEME_POINT_SIZE={point_size}",
        f"-DCND_ICON_THEME_APPEARANCE={appearance}",
        f"-DCND_ICON_THEME_VARIANT_OPTIONS={variant_options}",
        f"-DCND_ICON_THEME_PIXEL_SIZE={pixel_size}",
        f'-DCND_ICON_THEME_EXPECTED_SOURCE_SHA256="{expected_theme_hash}"',
        str(SOURCE), "-framework", "Foundation", "-framework",
        "CoreGraphics", "-framework", "ImageIO", "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def pdf_canary_bytes() -> bytes:
    """Return a deterministic, benign one-page PDF with a trace marker."""
    stream = (
        b"q\n1 0 0 rg\n0 0 34 68 re f\n"
        b"0 1 0 rg\n34 0 34 68 re f\nQ\n"
    )
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 68 68] "
         b"/Resources << >> /Contents 4 0 R >>"),
        (b"<< /Length " + str(len(stream)).encode("ascii") +
         b" >>\nstream\n" + stream + b"endstream"),
        (b"<< /Producer (Cyanide benign reachability probe) /Subject (" +
         PDF_CANARY_SUBJECT.encode("ascii") + b") >>"),
    )
    result = bytearray(b"%PDF-1.4\n% CND benign PDF canary; no malformed data\n")
    offsets = [0]
    for number, body in enumerate(objects, 1):
        offsets.append(len(result))
        result.extend(f"{number} 0 obj\n".encode("ascii"))
        result.extend(body)
        result.extend(b"\nendobj\n")
    xref = len(result)
    result.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    result.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        result.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    result.extend(
        (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R "
         f"/Info 5 0 R >>\nstartxref\n{xref}\n%%EOF\n").encode("ascii")
    )
    return bytes(result)


def build_pdf_canary() -> tuple[Path, str]:
    output = BUILD_DIR / "cnd-spotlight-pdf-canary.pdf"
    output.parent.mkdir(parents=True, exist_ok=True)
    data = pdf_canary_bytes()
    output.write_bytes(data)
    return output, hashlib.sha256(data).hexdigest()


def copy_pdf_canary(ssh: SSH) -> tuple[str, str]:
    local, digest = build_pdf_canary()
    remote = f"/var/tmp/cnd-spotlight-pdf-canary-{digest[:16]}.pdf"
    ssh.copy(local, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0644 {shlex.quote(remote)}"
    )
    return remote, digest


def copy_theme(ssh: SSH, theme: Path = THEME,
               expected_hash: str | None = EXPECTED_THEME_HASH) -> tuple[str, str]:
    if not theme.is_file():
        raise LabError(f"theme file missing: {theme}")
    digest = hashlib.sha256(theme.read_bytes()).hexdigest()
    if expected_hash is not None and digest != expected_hash:
        raise LabError(f"theme hash mismatch: {digest}")
    remote = f"/var/tmp/cnd-iconservices-theme-{digest[:16]}.png"
    ssh.copy(theme, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0644 {shlex.quote(remote)}"
    )
    return remote, digest


def terminate_exact_agent(ssh: SSH, expected_pid: int | None = None) -> None:
    try:
        pid, command = resolve_target(ssh, "iconservicesagent")
    except LabError:
        return
    if expected_pid is not None and pid != expected_pid:
        raise LabError(
            f"refusing to terminate changed iconservicesagent "
            f"({expected_pid} -> {pid})"
        )
    if command != TARGETS["iconservicesagent"] or pid <= 1:
        raise LabError(f"refusing to terminate pid={pid} command={command}")
    ssh.command(f"kill -9 {pid}")


def inject(ssh: SSH, payload: Path, pid: int) -> str:
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-iconservices-cache-theme-{digest}.dylib"
    ssh.copy(payload, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    current_pid, command = resolve_target(ssh, "iconservicesagent")
    if current_pid != pid or command != TARGETS["iconservicesagent"]:
        raise LabError("iconservicesagent identity changed before injection")
    ssh.command(
        f"/iosbinpack64/bin/rm -f {shlex.quote(REPORT_PATH)} "
        f"{shlex.quote(INJECT_LOG_PATH)}; "
        f"/var/jb/usr/bin/timeout -k 2 20 "
        f"/iosbinpack64/bin/opainject {pid} {shlex.quote(remote)} "
        f">{shlex.quote(INJECT_LOG_PATH)} 2>&1; status=$?; "
        f"if test \"$status\" = 124 -o \"$status\" = 137; then "
        f"exit 0; fi; exit \"$status\""
    )
    return remote


def read_report(ssh: SSH) -> str:
    return ssh.command(
        f"if test -f {shlex.quote(REPORT_PATH)}; then "
        f"/iosbinpack64/bin/cat {shlex.quote(REPORT_PATH)}; fi"
    )


def wait_ready(ssh: SSH) -> str:
    # A cold post-boot iconservicesagent can spend more than eight seconds in
    # its first CoreSVG dlopen on the vPhone.  Keep this bounded, but do not
    # misclassify that one-time framework initialization as an injection
    # failure.
    deadline = time.monotonic() + 30.0
    report = ""
    while time.monotonic() < deadline:
        report = read_report(ssh)
        if "TRACE_READY" in report:
            return report
        time.sleep(0.25)
    raise LabError("theme mutator did not become ready:\n" + report)


def parse_response(output: str) -> tuple[str, str, int]:
    matches = re.findall(
        r"CND_ICON_TRIGGER complete .* uuid=([0-9A-F-]+) "
        r"data=([0-9]+)/([0-9a-f]{64})", output,
    )
    if not matches:
        raise LabError("could not parse IconServices trigger response")
    uuid, length, digest = matches[-1]
    return uuid, digest, int(length)


def make_ssh(args: argparse.Namespace) -> SSH:
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: vPhone lab requires root on SSH port 22222")
    if not args.known_hosts.is_file():
        raise LabError(f"known-hosts file missing: {args.known_hosts}")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    return ssh


def restore_stock(ssh: SSH, remote_trigger: str) -> None:
    terminate_exact_agent(ssh)
    remote_hold = copy_executable(ssh, build_hold(),
                                  "cnd-iconservices-hold")
    hold_pid = start_hold(ssh, remote_hold)
    try:
        output = ssh.command(remote_trigger + " --ignore-cache")
        forced = parse_response(output)
        print("--- stock forced response ---")
        print(output.rstrip())
        terminate_exact_agent(ssh)
    finally:
        stop_hold(ssh, hold_pid, remote_hold)
    readback = ssh.command(remote_trigger)
    normal = parse_response(readback)
    print("--- stock persistent readback ---")
    print(readback.rstrip())
    if forced != normal:
        raise LabError(f"stock persistent readback mismatch: {forced} != {normal}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "run", "restore"),
                        nargs="?", default="run")
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    parser.add_argument("--bundle", default="com.ebay.iphone")
    parser.add_argument(
        "--variant", type=int, default=0,
        help=("exact nonnegative ISImageDescriptor variantOptions value "
              "(the printed v: field)"),
    )
    parser.add_argument(
        "--point-size", type=int, default=68,
        help="exact integer descriptor point size",
    )
    parser.add_argument(
        "--appearance", type=int, choices=(0, 1), default=0,
        help="exact descriptor appearance",
    )
    parser.add_argument(
        "--opaque-black-background", action="store_true",
        help="flatten transparent source pixels onto opaque pure black",
    )
    parser.add_argument(
        "--flat-payload", action="store_true",
        help=("construct IFImage.data with initWithCGImage:scale: and no "
              "synthetic structured layer payload"),
    )
    parser.add_argument(
        "--pdf-canary", action="store_true",
        help=("replace the structured icon's vector rendition with a benign "
              "PDF canary for the Spotlight CoreUI reachability test"),
    )
    parser.add_argument(
        "--reuse-clean-agent", action="store_true",
        help=("reuse the currently resident, already-unhooked agent; this is "
              "for bounded matrix runs that verified the preceding unhooked "
              "persistent readback"),
    )
    parser.add_argument(
        "--theme", type=Path, default=THEME,
        help="exact local PNG to publish (defaults to the lab fixture)",
    )
    args = parser.parse_args()
    bundle = validate_bundle(args.bundle)
    if args.variant < 0 or args.variant > 0x7fffffff:
        raise LabError("variant must be a nonnegative int32")
    if args.point_size <= 0 or args.point_size > 1024:
        raise LabError("point size must be in 1-1024")
    if args.pdf_canary and args.flat_payload:
        raise LabError("--pdf-canary requires the structured payload")

    if args.action == "build":
        pdf_path = ""
        pdf_hash = ""
        if args.pdf_canary:
            local_pdf, pdf_hash = build_pdf_canary()
            pdf_path = str(local_pdf)
        print(build_hold())
        print(build_trigger())
        print(build_mutator(
            opaque_black_background=args.opaque_black_background,
            flat_payload=args.flat_payload,
            pdf_canary_path=pdf_path,
            expected_pdf_canary_hash=pdf_hash,
            bundle=bundle, point_size=args.point_size,
            appearance=args.appearance, variant_options=args.variant))
        return 0
    ssh = make_ssh(args)
    trigger = build_trigger()
    remote_trigger = copy_executable(
        ssh, trigger, "cnd-iconservices-trigger")
    remote_trigger = (
        f"{shlex.quote(remote_trigger)} --bundle {shlex.quote(bundle)} "
        f"--variant 0 --variant-options {args.variant} "
        f"--point-size {args.point_size} --appearance {args.appearance}"
    )
    if args.action == "restore":
        restore_stock(ssh, remote_trigger)
        return 0

    if not args.reuse_clean_agent:
        terminate_exact_agent(ssh)
    remote_theme, theme_hash = copy_theme(
        ssh, args.theme,
        EXPECTED_THEME_HASH if args.theme == THEME else None,
    )
    remote_pdf = ""
    pdf_hash = ""
    if args.pdf_canary:
        remote_pdf, pdf_hash = copy_pdf_canary(ssh)
    output_token = issue_file_extension(ssh, "/var/tmp")
    root_token = issue_file_extension(ssh, "/private/var")
    mutator = build_mutator(
        remote_theme, output_token, root_token,
        opaque_black_background=args.opaque_black_background,
        flat_payload=args.flat_payload,
        pdf_canary_path=remote_pdf,
        expected_pdf_canary_hash=pdf_hash,
        bundle=bundle,
        point_size=args.point_size,
        appearance=args.appearance,
        variant_options=args.variant,
        expected_theme_hash=theme_hash,
    )
    remote_hold = copy_executable(ssh, build_hold(),
                                  "cnd-iconservices-hold")
    hold_pid = start_hold(ssh, remote_hold)
    injected_pid = 0
    try:
        # The hold connection makes iconservicesagent resident before we
        # inject.  Let the freshly launched service finish its own framework
        # and cache initialization so ImageIO work in the injected constructor
        # cannot race that startup on the service's worker queues.
        time.sleep(1.0)
        injected_pid, command = resolve_target(ssh, "iconservicesagent")
        remote_mutator = inject(ssh, mutator, injected_pid)
        wait_ready(ssh)
        forced_output = ssh.command(remote_trigger + " --ignore-cache")
        forced = parse_response(forced_output)
        report = read_report(ssh)
        if "THEME_APPLIED" not in report:
            raise LabError("mutator did not report an applied replacement:\n" +
                           report)
        print(
            f"themed generation pid={injected_pid} command={command} "
            f"payload={remote_mutator} theme={remote_theme} "
            f"pdfCanary={remote_pdf or '-'}"
        )
        print("--- themed forced response ---")
        print(forced_output.rstrip())
        print("--- mutator report ---")
        print(report, end="")
    finally:
        if injected_pid:
            terminate_exact_agent(ssh, injected_pid)
        stop_hold(ssh, hold_pid, remote_hold)

    persistent_output = ssh.command(remote_trigger)
    persistent = parse_response(persistent_output)
    print("--- unhooked persistent readback ---")
    print(persistent_output.rstrip())
    if forced != persistent:
        raise LabError(
            f"themed cache did not persist: {forced} != {persistent}"
        )
    print(
        "THEMED_CACHE_PERSISTED "
        f"uuid={persistent[0]} bytes={persistent[2]} sha256={persistent[1]}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
