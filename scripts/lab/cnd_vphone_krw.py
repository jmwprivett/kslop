#!/usr/bin/env python3
"""Arm and verify Cyanide's bounded vPhone lab support provider."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import time
from pathlib import Path

from cnd_remotecall_lab import (
    DEFAULT_KNOWN_HOSTS,
    LabError,
    SSH,
    require_vphone,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
PROVIDER_SOURCE = REPO_ROOT / "scripts/lab/cnd_provide_tfp0.c"
PROBE_SOURCE = REPO_ROOT / "scripts/lab/cnd_lab_krw_probe.c"
CS_ALLOW_INVALID_PROBE_SOURCE = \
    REPO_ROOT / "scripts/lab/cnd_lab_cs_allow_invalid_probe.c"
PROTOCOL_DIR = REPO_ROOT / "Cyanide/kexploit"
TFP0_ENTITLEMENTS = REPO_ROOT / "scripts/lab/cnd_tfp0_entitlements.plist"
BUILD_DIR = REPO_ROOT / "build/lab-vphone-krw"
MARKER_PATH = "/var/tmp/cyanide-enable-libkrw-lab"
LOG_PATH = "/var/tmp/cnd-provide-tfp0.log"
SOCKET_BASENAME = "cyanide-lab-krw.sock"
STANDALONE_SIGNER_SOCKET_PATH = \
    "/var/tmp/cyanide-thread-state-signer-canary.sock"
STANDALONE_KRW_SOCKET_PATH = \
    "/var/tmp/cyanide-kcall-research.sock"
CS_ALLOW_INVALID_OBSERVATION = REPO_ROOT / (
    "build/rea-secure-execution-23A341-iphone17,3/"
    "vm-cs-allow-invalid-observation.json"
)
DEFAULT_APP_BUNDLE_ID = "com.zeroxjf.ios-cyanide1"
APP_BUNDLE_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.-]{0,126}[A-Za-z0-9]$"
)
APP_HOME_PATTERN = re.compile(
    r"^/private/var/mobile/Containers/Data/Application/"
    r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$"
)


def canonical_kernel_address(value: str) -> str:
    if not re.fullmatch(r"0x[0-9A-Fa-f]{16}", value):
        raise LabError("kernel address must be a canonical 16-digit hex address")
    address = int(value, 16)
    if address & 0x3fff or \
            address & 0xffff000000000000 != 0xffff000000000000:
        raise LabError(
            "kernel address must be a canonical 16K-aligned kernel address"
        )
    return f"0x{address:016x}"


def debugger_kernel_address(port: int) -> tuple[str, str]:
    if port < 6000 or port > 65535:
        raise LabError("kernel debug port must be between 6000 and 65535")
    latest = ""
    for attempt in range(3):
        result = run([
            "xcrun", "lldb", "--batch",
            "-o", "platform select remote-ios",
            "-o", f"gdb-remote 127.0.0.1:{port}",
            "-o", "register read pc",
            "-o", "process detach",
        ])
        latest = (result.stdout + result.stderr).decode(
            "utf-8", "replace")
        addresses = re.findall(
            r"^Load Address:\s*(0x[0-9A-Fa-f]{16})\s*$",
            latest, re.MULTILINE,
        )
        uuids = re.findall(
            r"^Kernel UUID:\s*([0-9A-Fa-f-]{36})\s*$",
            latest, re.MULTILINE,
        )
        if "Process 1 detached" not in latest:
            raise LabError(
                "kernel debugger did not detach; refusing another attach"
            )
        if len(addresses) == 1 and len(uuids) == 1:
            return canonical_kernel_address(addresses[0]), uuids[0].upper()
        if len(addresses) > 1 or len(uuids) > 1:
            raise LabError("kernel debugger returned ambiguous boot identity")
        if attempt != 2:
            # The vPhone debug stub can omit its custom identity records on
            # the first connection after boot.  A detached, identity-free
            # handshake is safe to retry; a non-detached one is not.
            time.sleep(0.2)
    raise LabError(
        "kernel debugger did not return one load address/UUID after "
        "three detached handshakes:\n" + latest.rstrip()
    )


def build_binary(source: Path, output_name: str,
                 entitlements: Path | None = None,
                 architecture: str = "arm64",
                 extra_sources: tuple[Path, ...] = (),
                 frameworks: tuple[str, ...] = ()) -> Path:
    if architecture not in {"arm64", "arm64e"}:
        raise LabError(f"unsupported lab architecture: {architecture}")
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / output_name
    # The VM's jailbreak libkrw dylibs are arm64, not arm64e. Inspection
    # probes that exercise a user PAC consumer opt into arm64e explicitly.
    sources = (source, *extra_sources)
    if any(not item.is_file() for item in sources):
        raise LabError("lab build source is missing")
    if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", item)
           for item in frameworks):
        raise LabError("lab framework name is malformed")
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", architecture,
        "-Wall", "-Wextra", "-Werror", "-I", str(PROTOCOL_DIR),
        *(str(item) for item in sources),
        *(argument for item in frameworks
          for argument in ("-framework", item)),
        "-o", str(output),
    ])
    sign = ["codesign", "-s", "-", "--force"]
    if entitlements is not None:
        sign.extend(["--entitlements", str(entitlements)])
    sign.append(str(output))
    run(sign)
    return output


def build() -> tuple[Path, Path]:
    return (
        build_binary(PROVIDER_SOURCE, "cnd_provide_tfp0", TFP0_ENTITLEMENTS),
        build_binary(PROBE_SOURCE, "cnd_lab_krw_probe"),
    )


def build_cs_allow_invalid_probe() -> Path:
    return build_binary(
        CS_ALLOW_INVALID_PROBE_SOURCE,
        "cnd_lab_cs_allow_invalid_probe",
    )


def build_cs_allow_invalid_provider() -> Path:
    # This experiment creates a raw thread in an arm64e target. Build the
    # provider as arm64e so CNDLabTaskThreadStartRequest uses the SDK's
    # presigned-PC API instead of the arm64 NO_PTRAUTH fallback.
    return build_binary(
        PROVIDER_SOURCE,
        "cnd_provide_tfp0_cs_allow_invalid",
        TFP0_ENTITLEMENTS,
        architecture="arm64e",
    )


def current_cyanide(
        ssh: SSH,
        bundle_id: str = DEFAULT_APP_BUNDLE_ID) -> tuple[int, str, str]:
    if not APP_BUNDLE_ID_PATTERN.fullmatch(bundle_id):
        raise LabError("Cyanide app bundle identifier is malformed")
    report = ssh.command("/bin/ps eww -axo pid=,command=")
    service_name = f"XPC_SERVICE_NAME=UIKitApplication:{bundle_id}["
    matches = [line.strip() for line in report.splitlines()
               if "/Cyanide.app/Cyanide " in f"{line} " and
               service_name in line]
    if len(matches) != 1:
        raise LabError(
            f"expected one live Cyanide process, observed {len(matches)}"
        )
    pid_text, _, command = matches[0].partition(" ")
    try:
        pid = int(pid_text)
    except ValueError as error:
        raise LabError("Cyanide process line has an invalid PID") from error
    home_match = re.search(r" CFFIXED_USER_HOME=([^ ]+)", f" {command}")
    if pid <= 1 or not home_match or not APP_HOME_PATTERN.fullmatch(
        home_match.group(1)
    ):
        raise LabError("Cyanide process has no exact current data container")
    private_home = home_match.group(1)
    short_home = private_home.removeprefix("/private")
    socket_path = f"{short_home}/tmp/{SOCKET_BASENAME}"
    # Darwin sockaddr_un.sun_path is 104 bytes including the terminator.
    if len(socket_path.encode()) >= 104:
        raise LabError("current Cyanide container socket path is too long")
    return pid, private_home, socket_path


def parse_marker(data: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in data.decode("utf-8", "strict").splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in values:
            raise LabError("lab provider marker is malformed")
        values[key] = value
    return values


def provider_processes(ssh: SSH) -> list[tuple[int, str]]:
    report = ssh.command("/bin/ps -axo pid=,command=")
    result: list[tuple[int, str]] = []
    for line in report.splitlines():
        if "/var/tmp/cnd-provide-tfp0-" not in line:
            continue
        pid_text, _, command = line.strip().partition(" ")
        try:
            result.append((int(pid_text), command))
        except ValueError as error:
            raise LabError("lab provider process has an invalid PID") from error
    return result


def copy_binary(ssh: SSH, local: Path, stem: str) -> str:
    digest = hashlib.sha256(local.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/{stem}-{digest}"
    ssh.copy(local, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)}"
    )
    ssh.command(f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}")
    return remote


def run_probe(ssh: SSH, probe: str, socket_path: str,
              process: str = "SpringBoard", kcall_smoke: bool = False) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,30}", process):
        raise LabError("probe process must be one exact short process name")
    return ssh.command(
        f"{shlex.quote(probe)} {shlex.quote(socket_path)} "
        f"{shlex.quote(process)}" +
        (" --kcall-smoke" if kcall_smoke else "")
    ).strip()


def run_kcall_smoke(ssh: SSH, probe: str, socket_path: str) -> str:
    return ssh.command(
        f"{shlex.quote(probe)} {shlex.quote(socket_path)} "
        "SpringBoard --kcall-smoke-only"
    ).strip()


def run_thread_state_signer_canary(
        ssh: SSH, probe: str, socket_path: str) -> str:
    return ssh.command(
        f"{shlex.quote(probe)} {shlex.quote(socket_path)} "
        "SpringBoard --thread-state-signer-only"
    ).strip()


def run_cs_allow_invalid_probe(
        ssh: SSH, probe: str, socket_path: str) -> dict[str, object]:
    raw = ssh.command(
        f"{shlex.quote(probe)} {shlex.quote(socket_path)}"
    ).strip()
    try:
        report = json.loads(raw)
    except json.JSONDecodeError as error:
        raise LabError(
            "cs_allow_invalid probe did not return one JSON object: " + raw
        ) from error
    if report.get("schema") != \
            "com.zeroxjf.cyanide.vm-cs-allow-invalid" or \
            report.get("schemaVersion") != 1:
        raise LabError("cs_allow_invalid probe returned the wrong schema")
    return report


def stop_exact_provider(ssh: SSH, socket_path: str) -> None:
    processes = provider_processes(ssh)
    marker = parse_marker(ssh.read_file(MARKER_PATH)) \
        if ssh.file_kind(MARKER_PATH) == "file" else {}
    if processes:
        if len(processes) != 1 or marker.get("socket") != socket_path:
            raise LabError("refusing to stop an unverified lab provider")
        pid, command = processes[0]
        provider_argument = marker.get("argument", "auto")
        if provider_argument != "auto" and not re.fullmatch(
            r"0x[0-9a-f]{16}", provider_argument
        ):
            raise LabError("lab provider marker argument is malformed")
        expected_suffix = f" {provider_argument} {socket_path}"
        if not command.endswith(expected_suffix):
            raise LabError("lab provider marker/process identity mismatch")
        if marker.get("version") == "1":
            try:
                marker_pid = int(marker.get("pid", ""))
            except ValueError as error:
                raise LabError("lab provider marker PID is malformed") from error
            if marker_pid != pid:
                raise LabError("lab provider marker/process identity mismatch")
        elif set(marker) != {"socket"}:
            # Migrate the original one-line marker only when the independently
            # resolved process and endpoint are both exact.  Any other partial
            # marker remains a hard refusal.
            raise LabError("refusing unsupported lab provider marker version")
        ssh.command(f"kill {pid}")
        deadline = time.monotonic() + 5.0
        while any(item[0] == pid for item in provider_processes(ssh)):
            if time.monotonic() >= deadline:
                raise LabError("lab provider did not exit")
            time.sleep(0.1)
    kind = ssh.file_kind(socket_path)
    if kind not in {"missing", "socket"}:
        raise LabError(f"refusing unexpected endpoint object: {kind}")
    if kind == "socket":
        ssh.command(f"/iosbinpack64/bin/rm -f {shlex.quote(socket_path)}")
    if ssh.file_kind(MARKER_PATH) == "file":
        current = parse_marker(ssh.read_file(MARKER_PATH))
        if current.get("socket") != socket_path:
            raise LabError("refusing to remove a marker for another endpoint")
        ssh.command(f"/iosbinpack64/bin/rm -f {shlex.quote(MARKER_PATH)}")


def start_provider(ssh: SSH, provider: str, socket_path: str,
                   provider_argument: str) -> int:
    ssh.command(f"/iosbinpack64/bin/rm -f {shlex.quote(LOG_PATH)}")
    output = ssh.command(
        f"/var/jb/usr/bin/nohup {shlex.quote(provider)} "
        f"{shlex.quote(provider_argument)} "
        f"{shlex.quote(socket_path)} >{shlex.quote(LOG_PATH)} "
        "2>&1 </dev/null & echo $!"
    ).strip()
    if not output.isdigit() or int(output) <= 1:
        raise LabError(f"lab provider returned an invalid PID: {output!r}")
    pid = int(output)
    deadline = time.monotonic() + 8.0
    latest = ""
    while time.monotonic() < deadline:
        if ssh.file_kind(LOG_PATH) == "file":
            latest = ssh.read_file(LOG_PATH).decode("utf-8", "replace")
        if "ready socket=" in latest:
            return pid
        if not any(item[0] == pid for item in provider_processes(ssh)):
            break
        time.sleep(0.2)
    raise LabError("lab provider did not become ready:\n" + latest.rstrip())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "build", "enable", "restart", "status", "signer-canary",
            "standalone-signer-canary", "standalone-enable",
            "standalone-cs-allow-invalid",
        ),
    )
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument(
        "--app-bundle-id", default=DEFAULT_APP_BUNDLE_ID,
        help="exact running Cyanide bundle identifier for the per-container endpoint",
    )
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    kernel_source = parser.add_mutually_exclusive_group()
    kernel_source.add_argument(
        "--kernel-address", default=None,
        help="live 16K-aligned kernel address obtained from the VM debug stub",
    )
    kernel_source.add_argument(
        "--kernel-debug-port", type=int, default=None,
        help="attach to this local VM debug port, capture its live load address, and detach",
    )
    args = parser.parse_args()

    if args.action == "build":
        print("\n".join(str(path) for path in build()))
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this harness requires root on SSH port 22222")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)

    provider_argument = "auto"
    if args.kernel_address is not None:
        provider_argument = canonical_kernel_address(args.kernel_address)
    elif args.kernel_debug_port is not None:
        provider_argument, kernel_uuid = debugger_kernel_address(
            args.kernel_debug_port)
        print(
            f"debugger kernelUUID={kernel_uuid} "
            f"loadAddress={provider_argument}",
            flush=True,
        )

    if args.action == "standalone-signer-canary":
        provider_local, probe_local = build()
        provider_remote = copy_binary(
            ssh, provider_local, "cnd-provide-tfp0")
        probe_remote = copy_binary(ssh, probe_local, "cnd-lab-krw-probe")
        stop_exact_provider(ssh, STANDALONE_SIGNER_SOCKET_PATH)
        start_provider(
            ssh, provider_remote, STANDALONE_SIGNER_SOCKET_PATH,
            provider_argument,
        )
        try:
            result = run_thread_state_signer_canary(
                ssh, probe_remote, STANDALONE_SIGNER_SOCKET_PATH)
        finally:
            stop_exact_provider(ssh, STANDALONE_SIGNER_SOCKET_PATH)
        print(result)
        return 0

    if args.action == "standalone-cs-allow-invalid":
        provider_local = build_cs_allow_invalid_provider()
        probe_local = build_cs_allow_invalid_probe()
        provider_remote = copy_binary(
            ssh, provider_local, "cnd-provide-tfp0")
        probe_remote = copy_binary(
            ssh, probe_local, "cnd-lab-cs-allow-invalid-probe")
        stop_exact_provider(ssh, STANDALONE_KRW_SOCKET_PATH)
        start_provider(
            ssh, provider_remote, STANDALONE_KRW_SOCKET_PATH,
            provider_argument,
        )
        try:
            report = run_cs_allow_invalid_probe(
                ssh, probe_remote, STANDALONE_KRW_SOCKET_PATH)
        finally:
            stop_exact_provider(ssh, STANDALONE_KRW_SOCKET_PATH)
        CS_ALLOW_INVALID_OBSERVATION.parent.mkdir(
            parents=True, exist_ok=True)
        CS_ALLOW_INVALID_OBSERVATION.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, sort_keys=True))
        print(f"evidence={CS_ALLOW_INVALID_OBSERVATION}")
        return 0

    if args.action == "standalone-enable":
        provider_local, _ = build()
        provider_remote = copy_binary(
            ssh, provider_local, "cnd-provide-tfp0")
        stop_exact_provider(ssh, STANDALONE_KRW_SOCKET_PATH)
        provider_pid = start_provider(
            ssh, provider_remote, STANDALONE_KRW_SOCKET_PATH,
            provider_argument,
        )
        print(
            f"standalone provider ready pid={provider_pid} "
            f"socket={STANDALONE_KRW_SOCKET_PATH}"
        )
        return 0

    app_pid, app_home, socket_path = current_cyanide(
        ssh, args.app_bundle_id)

    if args.action == "status":
        processes = provider_processes(ssh)
        marker = parse_marker(ssh.read_file(MARKER_PATH)) \
            if ssh.file_kind(MARKER_PATH) == "file" else {}
        print(
            f"appPID={app_pid} home={app_home} socket={socket_path} "
            f"socketKind={ssh.file_kind(socket_path)} providers={processes} "
            f"marker={marker}"
        )
        return 0

    provider_local, probe_local = build()
    provider_remote = copy_binary(
        ssh, provider_local, "cnd-provide-tfp0")
    probe_remote = copy_binary(ssh, probe_local, "cnd-lab-krw-probe")
    processes = provider_processes(ssh)
    if args.action == "signer-canary":
        if len(processes) != 1 or ssh.file_kind(socket_path) != "socket":
            raise LabError("the exact VM lab provider is not running")
        print(run_thread_state_signer_canary(
            ssh, probe_remote, socket_path))
        return 0
    if args.action == "enable" and processes:
        print(run_kcall_smoke(ssh, probe_remote, socket_path))
        print(run_thread_state_signer_canary(
            ssh, probe_remote, socket_path))
        print(run_probe(ssh, probe_remote, socket_path))
        print(run_probe(
            ssh, probe_remote, socket_path, "iconservicesagent"
        ))
        print(f"provider already ready appPID={app_pid} socket={socket_path}")
        return 0
    if processes or ssh.file_kind(socket_path) == "socket" or \
            ssh.file_kind(MARKER_PATH) == "file":
        stop_exact_provider(ssh, socket_path)
    provider_pid = start_provider(
        ssh, provider_remote, socket_path, provider_argument)
    print(run_kcall_smoke(ssh, probe_remote, socket_path))
    print(run_thread_state_signer_canary(
        ssh, probe_remote, socket_path))
    print(run_probe(ssh, probe_remote, socket_path))
    print(run_probe(ssh, probe_remote, socket_path, "iconservicesagent"))
    print(
        f"provider ready pid={provider_pid} appPID={app_pid} "
        f"socket={socket_path}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
