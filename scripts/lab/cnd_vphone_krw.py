#!/usr/bin/env python3
"""Arm and verify Cyanide's bounded vPhone lab support provider."""

from __future__ import annotations

import argparse
import hashlib
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
PROTOCOL_DIR = REPO_ROOT / "Cyanide/kexploit"
BUILD_DIR = REPO_ROOT / "build/lab-vphone-krw"
MARKER_PATH = "/var/tmp/cyanide-enable-libkrw-lab"
LOG_PATH = "/var/tmp/cnd-provide-tfp0.log"
SOCKET_BASENAME = "cyanide-lab-krw.sock"
APP_HOME_PATTERN = re.compile(
    r"^/private/var/mobile/Containers/Data/Application/"
    r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$"
)


def build_binary(source: Path, output_name: str) -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / output_name
    # The VM's jailbreak libkrw dylibs are arm64, not arm64e. Inspection
    # dylibs injected into Apple processes are still built separately as
    # arm64e by their own harnesses.
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64",
        "-Wall", "-Wextra", "-Werror", "-I", str(PROTOCOL_DIR),
        str(source), "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def build() -> tuple[Path, Path]:
    return (
        build_binary(PROVIDER_SOURCE, "cnd_provide_tfp0"),
        build_binary(PROBE_SOURCE, "cnd_lab_krw_probe"),
    )


def current_cyanide(ssh: SSH) -> tuple[int, str, str]:
    report = ssh.command("/bin/ps eww -axo pid=,command=")
    matches = [line.strip() for line in report.splitlines()
               if "/Cyanide.app/Cyanide " in f"{line} " and
               "XPC_SERVICE_NAME=UIKitApplication:com.zeroxjf.ios-cyanide1["
               in line]
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
              process: str = "SpringBoard") -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,30}", process):
        raise LabError("probe process must be one exact short process name")
    return ssh.command(
        f"{shlex.quote(probe)} {shlex.quote(socket_path)} "
        f"{shlex.quote(process)}"
    ).strip()


def stop_exact_provider(ssh: SSH, socket_path: str) -> None:
    processes = provider_processes(ssh)
    marker = parse_marker(ssh.read_file(MARKER_PATH)) \
        if ssh.file_kind(MARKER_PATH) == "file" else {}
    if processes:
        if len(processes) != 1 or marker.get("socket") != socket_path:
            raise LabError("refusing to stop an unverified lab provider")
        pid, command = processes[0]
        expected_suffix = f" auto {socket_path}"
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


def start_provider(ssh: SSH, provider: str, socket_path: str) -> int:
    ssh.command(f"/iosbinpack64/bin/rm -f {shlex.quote(LOG_PATH)}")
    output = ssh.command(
        f"/var/jb/usr/bin/nohup {shlex.quote(provider)} auto "
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
    parser.add_argument("action", choices=("build", "enable", "restart", "status"))
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    args = parser.parse_args()

    if args.action == "build":
        print("\n".join(str(path) for path in build()))
        return 0
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this harness requires root on SSH port 22222")
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    app_pid, app_home, socket_path = current_cyanide(ssh)

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
    if args.action == "enable" and processes:
        print(run_probe(ssh, probe_remote, socket_path))
        print(run_probe(
            ssh, probe_remote, socket_path, "iconservicesagent"
        ))
        print(f"provider already ready appPID={app_pid} socket={socket_path}")
        return 0
    if processes or ssh.file_kind(socket_path) == "socket" or \
            ssh.file_kind(MARKER_PATH) == "file":
        stop_exact_provider(ssh, socket_path)
    provider_pid = start_provider(ssh, provider_remote, socket_path)
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
