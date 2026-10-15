#!/usr/bin/env python3
"""Install and operate a version-locked Frida environment for the vPhone VM."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from cnd_remotecall_lab import (
    DEFAULT_KNOWN_HOSTS,
    LabError,
    SSH,
    require_vphone,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_DIR = REPO_ROOT / "build/frida-vm"
DOWNLOAD_DIR = BUILD_DIR / "downloads"
VENV_DIR = BUILD_DIR / "venv"
CONTROL_SOCKET = BUILD_DIR / "tunnel.sock"
STATE_PATH = BUILD_DIR / "state.json"
SMOKE_SCRIPT = REPO_ROOT / "scripts/lab/cnd_frida_springboard_smoke.py"

FRIDA_VERSION = "17.23.3"
FRIDA_TOOLS_VERSION = "14.11.0"
PACKAGE_NAME = f"frida_{FRIDA_VERSION}_iphoneos-arm64.deb"
PACKAGE_URL = (
    f"https://github.com/frida/frida/releases/download/{FRIDA_VERSION}/"
    f"{PACKAGE_NAME}"
)
PACKAGE_SHA256 = (
    "6bf24760fe29fdeb786af71ec689dac333f7dda8aa1fe93ed3dff594bf23531b"
)
REMOTE_PACKAGE = f"/var/tmp/{PACKAGE_NAME}"
REMOTE_SERVER = "/var/jb/usr/sbin/frida-server"
REMOTE_LISTEN = "127.0.0.1:27042"
LOCAL_ENDPOINT = "127.0.0.1:27042"
REMOTE_PATH = (
    "/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:"
    "/iosbinpack64/bin:/iosbinpack64/usr/bin:"
    "/iosbinpack64/usr/sbin:/usr/bin:/bin"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verified_package(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0 and \
        sha256(path) == PACKAGE_SHA256


def download_package() -> Path:
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    destination = DOWNLOAD_DIR / PACKAGE_NAME
    if verified_package(destination):
        return destination
    temporary = destination.with_suffix(destination.suffix + ".part")
    if temporary.exists():
        temporary.unlink()
    request = urllib.request.Request(
        PACKAGE_URL,
        headers={"User-Agent": "Cyanide-vPhone-Frida-setup/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response, \
                temporary.open("wb") as output:
            shutil.copyfileobj(response, output)
    except Exception:
        if temporary.exists():
            temporary.unlink()
        raise
    if not verified_package(temporary):
        observed = sha256(temporary) if temporary.is_file() else "missing"
        temporary.unlink(missing_ok=True)
        raise LabError(
            f"Frida package SHA-256 mismatch: expected {PACKAGE_SHA256}, "
            f"observed {observed}"
        )
    temporary.replace(destination)
    return destination


def remote(command: str) -> str:
    return f"export PATH={REMOTE_PATH}; {command}"


def installed_server_version(ssh: SSH) -> str | None:
    output = ssh.command(remote(
        "if test -x /var/jb/usr/bin/dpkg-query; then "
        "/var/jb/usr/bin/dpkg-query -W -f='${Version}' "
        "re.frida.server 2>/dev/null || true; fi"
    )).strip()
    return output or None


def server_processes(ssh: SSH) -> list[tuple[int, str]]:
    output = ssh.command(remote("ps -ax -o pid=,command="))
    processes: list[tuple[int, str]] = []
    for line in output.splitlines():
        if "frida-server" not in line:
            continue
        match = re.fullmatch(r"\s*([0-9]+)\s+(.+?)\s*", line)
        if not match:
            raise LabError("Frida process list contained a malformed entry")
        processes.append((int(match.group(1)), match.group(2)))
    return processes


def expected_server_process(command: str) -> bool:
    return command in {
        f"frida-server -D -l {REMOTE_LISTEN}",
        f"{REMOTE_SERVER} -D -l {REMOTE_LISTEN}",
    }


def install_server(ssh: SSH) -> bool:
    current = installed_server_version(ssh)
    if current == FRIDA_VERSION:
        observed = ssh.command(f"{REMOTE_SERVER} --version").strip()
        if observed != FRIDA_VERSION:
            raise LabError(
                f"Frida package says {current}, server reports {observed}"
            )
        return False
    processes = server_processes(ssh)
    if processes:
        if len(processes) != 1 or not expected_server_process(processes[0][1]):
            detail = ", ".join(
                f"{pid}:{command}" for pid, command in processes)
            raise LabError(
                f"refusing to replace an unexpected Frida process: {detail}"
            )
        ssh.command(remote(f"kill {processes[0][0]}"))
        for _ in range(15):
            if not server_processes(ssh):
                break
            time.sleep(0.2)
        else:
            raise LabError("existing Frida server did not terminate normally")
    package = download_package()
    ssh.copy(package, REMOTE_PACKAGE)
    observed = ssh.command(remote(
        f"sha256sum {REMOTE_PACKAGE} | cut -d' ' -f1"
    )).strip()
    if observed != PACKAGE_SHA256:
        raise LabError(
            f"remote Frida package SHA-256 mismatch: {observed or 'missing'}"
        )
    ssh.command(remote(
        f"DEBIAN_FRONTEND=noninteractive dpkg -i {REMOTE_PACKAGE}"
    ))
    installed = installed_server_version(ssh)
    binary = ssh.command(f"{REMOTE_SERVER} --version").strip()
    if installed != FRIDA_VERSION or binary != FRIDA_VERSION:
        raise LabError(
            "Frida server installation did not produce the locked version"
        )
    return True


def ensure_server(ssh: SSH) -> int:
    current = server_processes(ssh)
    if current:
        if len(current) != 1 or not expected_server_process(current[0][1]):
            detail = ", ".join(f"{pid}:{command}" for pid, command in current)
            raise LabError(
                f"refusing to replace an unexpected Frida process: {detail}"
            )
        return current[0][0]
    ssh.command(f"{REMOTE_SERVER} -D -l {REMOTE_LISTEN}")
    for _ in range(15):
        current = server_processes(ssh)
        if len(current) == 1 and expected_server_process(current[0][1]):
            return current[0][0]
        if current:
            break
        time.sleep(0.2)
    raise LabError("Frida server did not stay running with the expected command")


def venv_versions() -> tuple[str, str] | None:
    python = VENV_DIR / "bin/python"
    if not python.is_file():
        return None
    completed = subprocess.run(
        [str(python), "-c",
         "import frida, importlib.metadata; "
         "print(frida.__version__); "
         "print(importlib.metadata.version('frida-tools'))"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if completed.returncode != 0:
        return None
    lines = completed.stdout.decode("utf-8", "replace").splitlines()
    return (lines[0], lines[1]) if len(lines) == 2 else None


def ensure_host_tools() -> bool:
    if venv_versions() == (FRIDA_VERSION, FRIDA_TOOLS_VERSION):
        return False
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    if not (VENV_DIR / "bin/python").is_file():
        run([sys.executable, "-m", "venv", str(VENV_DIR)])
    run([
        str(VENV_DIR / "bin/python"), "-m", "pip", "install",
        "--disable-pip-version-check", "--no-input",
        f"frida=={FRIDA_VERSION}",
        f"frida-tools=={FRIDA_TOOLS_VERSION}",
    ])
    if venv_versions() != (FRIDA_VERSION, FRIDA_TOOLS_VERSION):
        raise LabError("host Frida virtual environment version check failed")
    return True


def tunnel_base(host: str, port: int, user: str,
                known_hosts: Path, password_env: str) -> tuple[list[str], dict[str, str]]:
    sshpass = shutil.which("sshpass")
    if sshpass is None:
        raise LabError("sshpass is required for the Frida VM tunnel")
    password = os.environ.get(password_env)
    if not password:
        raise LabError(f"set {password_env} to the VM root SSH password")
    environment = dict(os.environ)
    environment["SSHPASS"] = password
    command = [
        sshpass, "-e", "ssh", "-p", str(port),
        "-o", "BatchMode=no", "-o", "ConnectTimeout=5",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        f"{user}@{host}",
    ]
    return command, environment


def tunnel_check(host: str, port: int, user: str) -> bool:
    if not CONTROL_SOCKET.exists():
        return False
    result = subprocess.run(
        ["ssh", "-S", str(CONTROL_SOCKET), "-O", "check",
         "-p", str(port), f"{user}@{host}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode == 0:
        return True
    CONTROL_SOCKET.unlink(missing_ok=True)
    return False


def local_port_available() -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", 27042))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def ensure_tunnel(host: str, port: int, user: str,
                  known_hosts: Path, password_env: str) -> bool:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    if tunnel_check(host, port, user):
        return False
    if not local_port_available():
        raise LabError(
            "local port 27042 is occupied by a process other than the "
            "managed Frida VM tunnel"
        )
    base, environment = tunnel_base(
        host, port, user, known_hosts, password_env)
    command = [
        *base[:-1],
        "-M", "-S", str(CONTROL_SOCKET), "-fNT",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=3",
        "-L", f"{LOCAL_ENDPOINT}:{REMOTE_LISTEN}",
        base[-1],
    ]
    run(command, env=environment)
    if not tunnel_check(host, port, user):
        raise LabError("Frida VM SSH tunnel did not remain active")
    return True


def stop_tunnel(host: str, port: int, user: str) -> bool:
    if not tunnel_check(host, port, user):
        return False
    result = subprocess.run(
        ["ssh", "-S", str(CONTROL_SOCKET), "-O", "exit",
         "-p", str(port), f"{user}@{host}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise LabError(f"could not stop Frida VM tunnel: {detail}")
    CONTROL_SOCKET.unlink(missing_ok=True)
    return True


def smoke() -> dict[str, Any]:
    python = VENV_DIR / "bin/python"
    if venv_versions() != (FRIDA_VERSION, FRIDA_TOOLS_VERSION):
        raise LabError("run setup before the Frida SpringBoard smoke test")
    result = run([
        str(python), str(SMOKE_SCRIPT),
        "--endpoint", LOCAL_ENDPOINT,
        "--target", "SpringBoard",
    ])
    try:
        report = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LabError("Frida smoke test did not return valid JSON") from error
    if report.get("result") != "attached-read-only" or \
            report.get("target") != "SpringBoard":
        raise LabError("Frida smoke test did not prove a SpringBoard attach")
    return report


def remote_status(ssh: SSH) -> dict[str, Any]:
    processes = server_processes(ssh)
    expected = len(processes) == 1 and expected_server_process(processes[0][1])
    return {
        "installedVersion": installed_server_version(ssh),
        "serverVersion": ssh.command(f"{REMOTE_SERVER} --version").strip()
            if installed_server_version(ssh) is not None else None,
        "serverPid": processes[0][0] if expected else None,
        "serverCommand": processes[0][1] if expected else None,
        "serverExpected": expected,
    }


def persist_state(report: dict[str, Any]) -> None:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".json.new")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(STATE_PATH)


def connect(args: argparse.Namespace) -> SSH:
    ssh = SSH(
        args.host, args.port, args.user,
        args.known_hosts.expanduser().resolve(), args.password_env,
    )
    require_vphone(ssh)
    return ssh


def command_setup(args: argparse.Namespace) -> dict[str, Any]:
    ssh = connect(args)
    installed = install_server(ssh)
    server_pid = ensure_server(ssh)
    host_tools_installed = ensure_host_tools()
    tunnel_started = ensure_tunnel(
        args.host, args.port, args.user,
        args.known_hosts.expanduser().resolve(), args.password_env,
    )
    smoke_report = smoke()
    report = {
        "schema": "com.zeroxjf.cyanide.frida-vm-setup",
        "schemaVersion": 1,
        "result": "vm-springboard-attach-proved",
        "host": args.host,
        "sshPort": args.port,
        "sshUser": args.user,
        "fridaVersion": FRIDA_VERSION,
        "fridaToolsVersion": FRIDA_TOOLS_VERSION,
        "packageSHA256": PACKAGE_SHA256,
        "serverInstalledNow": installed,
        "hostToolsInstalledNow": host_tools_installed,
        "tunnelStartedNow": tunnel_started,
        "serverPid": server_pid,
        "localEndpoint": LOCAL_ENDPOINT,
        "smoke": smoke_report,
    }
    persist_state(report)
    return report


def command_status(args: argparse.Namespace) -> dict[str, Any]:
    ssh = connect(args)
    report = {
        "schema": "com.zeroxjf.cyanide.frida-vm-status",
        "schemaVersion": 1,
        "host": args.host,
        "sshPort": args.port,
        "fridaVersion": FRIDA_VERSION,
        "fridaToolsVersion": FRIDA_TOOLS_VERSION,
        "hostVersions": venv_versions(),
        "tunnelActive": tunnel_check(args.host, args.port, args.user),
        "remote": remote_status(ssh),
    }
    report["ready"] = bool(
        report["hostVersions"] == (FRIDA_VERSION, FRIDA_TOOLS_VERSION) and
        report["tunnelActive"] and report["remote"]["serverExpected"]
    )
    return report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Version-locked Frida setup for the authorized vPhone VM",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", required=True)
    common.add_argument("--port", type=int, default=22222)
    common.add_argument("--user", default="root")
    common.add_argument(
        "--known-hosts", type=Path, default=DEFAULT_KNOWN_HOSTS)
    common.add_argument(
        "--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("setup", parents=[common])
    commands.add_parser("status", parents=[common])
    commands.add_parser("smoke", parents=[common])
    commands.add_parser("stop-tunnel", parents=[common])
    return result


def main() -> int:
    args = parser().parse_args()
    if args.port < 1 or args.port > 65535:
        raise SystemExit("SSH port must be between 1 and 65535")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.password_env):
        raise SystemExit("password environment variable name is invalid")
    try:
        if args.command == "setup":
            report = command_setup(args)
        elif args.command == "status":
            report = command_status(args)
        elif args.command == "smoke":
            if not tunnel_check(args.host, args.port, args.user):
                raise LabError("managed Frida VM tunnel is not active")
            report = smoke()
        else:
            report = {
                "schema": "com.zeroxjf.cyanide.frida-vm-tunnel-stop",
                "schemaVersion": 1,
                "stopped": stop_tunnel(args.host, args.port, args.user),
            }
    except (LabError, OSError, urllib.error.URLError) as error:
        raise SystemExit(f"error: {error}") from error
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
