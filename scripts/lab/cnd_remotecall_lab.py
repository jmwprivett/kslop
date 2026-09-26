#!/usr/bin/env python3
"""Explicit vPhone-only launcher for Cyanide's injected RemoteCall backend."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import secrets
import shlex
import shutil
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "scripts/lab/cnd_remotecall_payload.c"
SANDBOX_ISSUE_SOURCE = REPO_ROOT / "scripts/lab/cnd_sandbox_issue.c"
SMOKE_SOURCE = REPO_ROOT / "scripts/lab/cnd_remotecall_smoke.c"
CLIENT_SOURCE = REPO_ROOT / "Cyanide/TaskRop/CNDLabRemoteCallClient.m"
PROTOCOL_DIR = REPO_ROOT / "Cyanide/TaskRop"
BUILD_DIR = REPO_ROOT / "build/lab-remotecall"
MARKER_PATH = "/var/tmp/cyanide-enable-remotecall-lab"
TOKEN_PATH = "/var/tmp/cyanide-remotecall-lab.token"
SOCKET_PREFIX = "/var/tmp/cyanide-remotecall-"
SOCKET_SUFFIX = ".sock"
TARGET_CREDENTIAL_PREFIX = "/var/tmp/cyanide-remotecall-lab."
MAILBOX_SIZE = 17088
DEFAULT_KNOWN_HOSTS = Path.home() / "Library/CyanideVPhoneLab/evidence/phase6/ssh_known_hosts"

TARGETS = {
    "SpringBoard": "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
    "installd": "/usr/libexec/installd",
    "iconservicesagent": "/System/Library/CoreServices/iconservicesagent",
    "Spotlight": "/Applications/Spotlight.app/Spotlight",
    "searchd": "/System/Library/PrivateFrameworks/Search.framework/searchd",
}


class LabError(RuntimeError):
    pass


def parse_marker(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw_line in enumerate(text.splitlines(), 1):
        if not raw_line:
            continue
        key, separator, value = raw_line.partition("=")
        if not separator or not key or key in values:
            raise LabError(f"invalid marker line {number}: {raw_line!r}")
        values[key] = value
    return values


def mailbox_sequences(data: bytes) -> tuple[int, int]:
    if len(data) != MAILBOX_SIZE:
        raise LabError(
            f"mailbox size mismatch: expected={MAILBOX_SIZE} observed={len(data)}"
        )
    return struct.unpack_from("<QQ", data)


def target_token_path(target: str) -> str:
    return f"{TARGET_CREDENTIAL_PREFIX}{target}.token"


def target_marker_path(target: str) -> str:
    return f"{TARGET_CREDENTIAL_PREFIX}{target}.marker"


def expected_socket_path(target: str) -> str:
    if target == "installd":
        return "/var/installd/Library/Caches/.cnd-rc"
    return f"{SOCKET_PREFIX}{target}{SOCKET_SUFFIX}"


def run(command: list[str], *, env: dict[str, str] | None = None,
        input_data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command, input=input_data, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, check=False,
    )
    if result.returncode != 0:
        stdout = result.stdout.decode("utf-8", "replace").strip()
        stderr = result.stderr.decode("utf-8", "replace").strip()
        detail = "\n".join(part for part in (stdout, stderr) if part)
        raise LabError(
            f"command failed ({result.returncode}): "
            f"{shlex.join(command)}{chr(10) + detail if detail else ''}"
        )
    return result


class SSH:
    def __init__(self, host: str, port: int, user: str,
                 known_hosts: Path, password_env: str) -> None:
        sshpass = shutil.which("sshpass")
        if not sshpass:
            raise LabError("sshpass is required for this lab harness")
        password = os.environ.get(password_env)
        if not password:
            raise LabError(f"set {password_env} to the root SSH password")
        self.environment = dict(os.environ)
        self.environment["SSHPASS"] = password
        self.base = [
            sshpass, "-e", "ssh", "-p", str(port),
            "-o", "BatchMode=no", "-o", "ConnectTimeout=5",
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "ControlMaster=auto", "-o", "ControlPersist=30",
            "-o", "ControlPath=/tmp/cnd-remotecall-ssh-%C",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            f"{user}@{host}",
        ]

    def command(self, command: str) -> str:
        return self.command_bytes(command).decode("utf-8", "replace")

    def command_bytes(self, command: str) -> bytes:
        result = run([*self.base, command], env=self.environment)
        return result.stdout

    def read_file(self, path: str) -> bytes:
        return self.command_bytes(
            f"/iosbinpack64/bin/cat {shlex.quote(path)}"
        )

    def file_kind(self, path: str) -> str:
        return self.command(
            f"if test -L {shlex.quote(path)}; then echo symlink; "
            f"elif test -S {shlex.quote(path)}; then echo socket; "
            f"elif test -f {shlex.quote(path)}; then echo file; "
            "else echo missing; fi"
        ).strip()

    def copy(self, source: Path, remote_path: str) -> None:
        run(
            [*self.base,
             f"/iosbinpack64/usr/bin/tee {shlex.quote(remote_path)} "
             ">/dev/null"],
            env=self.environment, input_data=source.read_bytes(),
        )


def build_payload(token: bytes, installd_socket_path: str = "",
                  sandbox_token: str = "",
                  bundle_sandbox_token: str = "",
                  force_mailbox: bool = False) -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_remotecall_payload.dylib"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-dynamiclib", "-Wall", "-Wextra", "-Werror",
        f'-DCND_LAB_EMBEDDED_TOKEN_HEX="{token.hex()}"',
        f'-DCND_LAB_INSTALLD_SOCKET_PATH="{installd_socket_path}"',
        f'-DCND_LAB_INSTALLD_SANDBOX_TOKEN="{sandbox_token}"',
        f'-DCND_LAB_INSTALLD_BUNDLE_SANDBOX_TOKEN="{bundle_sandbox_token}"',
        f"-DCND_LAB_FORCE_MAILBOX={1 if force_mailbox else 0}",
        "-I", str(PROTOCOL_DIR),
        str(SOURCE), "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def build_sandbox_issuer() -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_sandbox_issue"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-Wall", "-Wextra", "-Werror", str(SANDBOX_ISSUE_SOURCE),
        "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def issue_file_extension(ssh: SSH, path: str) -> str:
    executable = build_sandbox_issuer()
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()[:16]
    remote = f"/var/tmp/cnd-sandbox-issue-{digest}"
    ssh.copy(executable, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {remote} && "
        f"/iosbinpack64/bin/chmod 0755 {remote}"
    )
    token = ssh.command(f"{remote} {shlex.quote(path)}").strip()
    if len(token) < 16 or "\n" in token:
        raise LabError("root sandbox-extension issuer returned an invalid token")
    return token


def build_smoke() -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "cnd_remotecall_smoke"
    run([
        "xcrun", "--sdk", "iphoneos", "clang", "-arch", "arm64e",
        "-Wall", "-Wextra", "-Werror", "-I", str(PROTOCOL_DIR),
        str(CLIENT_SOURCE), str(SMOKE_SOURCE), "-o", str(output),
    ])
    run(["codesign", "-s", "-", "--force", str(output)])
    return output


def require_vphone(ssh: SSH) -> None:
    command = (
        "PATH=/iosbinpack64/bin:/iosbinpack64/usr/bin:"
        "/iosbinpack64/usr/sbin:/bin:/usr/bin:/usr/sbin:/sbin; "
        "sysctl -n hw.model; uname -a"
    )
    lines = [line.strip() for line in ssh.command(command).splitlines()
             if line.strip()]
    if len(lines) < 2 or not lines[0].startswith("VPHONE") or \
            "VRESEARCH" not in lines[1]:
        raise LabError(
            "refusing: the SSH target did not identify as a vPhone "
            "VRESEARCH guest"
        )


def process_snapshot(ssh: SSH) -> list[tuple[int, str]]:
    output = ssh.command("/bin/ps -ax -o pid= -o command=")
    result: list[tuple[int, str]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*([0-9]+)\s+(.+?)\s*$", line)
        if not match:
            continue
        result.append((int(match.group(1)), match.group(2)))
    return result


def cyanide_bundle_path(ssh: SSH) -> str:
    output = ssh.command(
        "/iosbinpack64/usr/bin/find /var/containers/Bundle/Application "
        "-mindepth 2 -maxdepth 2 -type d -name Cyanide.app"
    )
    paths = [line.strip() for line in output.splitlines() if line.strip()]
    if len(paths) != 1 or not re.fullmatch(
            r"/var/containers/Bundle/Application/[0-9A-F-]+/Cyanide[.]app",
            paths[0]):
        raise LabError(
            f"refusing: expected one installed Cyanide.app; found {len(paths)}"
        )
    return paths[0]


def resolve_target(ssh: SSH, name: str) -> tuple[int, str]:
    expected = TARGETS[name]
    matches = []
    for pid, command in process_snapshot(ssh):
        executable = command.split(" ", 1)[0]
        if executable == expected:
            matches.append((pid, command))
    if len(matches) != 1:
        raise LabError(
            f"refusing: expected exactly one {name} process at {expected}; "
            f"found {len(matches)}"
        )
    pid, command = matches[0]
    if pid <= 1:
        raise LabError(f"refusing unsafe target PID {pid}")
    return pid, command


def install_credentials(ssh: SSH, target: str, pid: int, token: bytes,
                        socket_path: str, file_token: str = "",
                        bundle_token: str = "",
                        target_bundle_path: str = "",
                        root_token: str = "") -> None:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    token_local = BUILD_DIR / "token"
    marker_local = BUILD_DIR / "marker"
    token_local.write_bytes(token)
    marker_local.write_text(
        f"version=1\nmodel=VPHONE\ntarget={target}\npid={pid}\n"
        f"socket={socket_path}\nfile_token={file_token}\n"
        f"bundle_token={bundle_token}\n"
        f"root_token={root_token}\n"
        f"target_bundle_path={target_bundle_path}\n",
        encoding="utf-8",
    )
    remote_token_tmp = f"{TOKEN_PATH}.new"
    remote_marker_tmp = f"{MARKER_PATH}.new"
    process_token = target_token_path(target)
    process_marker = target_marker_path(target)
    process_token_tmp = f"{process_token}.new"
    process_marker_tmp = f"{process_marker}.new"
    ssh.copy(token_local, remote_token_tmp)
    ssh.copy(marker_local, remote_marker_tmp)
    ssh.copy(token_local, process_token_tmp)
    ssh.copy(marker_local, process_marker_tmp)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote_token_tmp)} "
        f"{shlex.quote(remote_marker_tmp)} {shlex.quote(process_token_tmp)} "
        f"{shlex.quote(process_marker_tmp)} && "
        f"/iosbinpack64/bin/chmod 0644 {shlex.quote(remote_token_tmp)} "
        f"{shlex.quote(remote_marker_tmp)} {shlex.quote(process_token_tmp)} "
        f"{shlex.quote(process_marker_tmp)} && "
        f"/iosbinpack64/bin/mv -f {shlex.quote(remote_token_tmp)} {TOKEN_PATH} && "
        f"/iosbinpack64/bin/mv -f {shlex.quote(remote_marker_tmp)} {MARKER_PATH} && "
        f"/iosbinpack64/bin/mv -f {shlex.quote(process_token_tmp)} "
        f"{shlex.quote(process_token)} && "
        f"/iosbinpack64/bin/mv -f {shlex.quote(process_marker_tmp)} "
        f"{shlex.quote(process_marker)}"
    )
    cyanide_bundle = cyanide_bundle_path(ssh)
    bundle_token_tmp = f"{cyanide_bundle}/CNDLabRemoteCall.token.new"
    bundle_marker_tmp = f"{cyanide_bundle}/CNDLabRemoteCall.marker.new"
    bundle_token_path = f"{cyanide_bundle}/CNDLabRemoteCall.token"
    bundle_marker_path = f"{cyanide_bundle}/CNDLabRemoteCall.marker"
    process_bundle_token = (
        f"{cyanide_bundle}/CNDLabRemoteCall.{target}.token"
    )
    process_bundle_marker = (
        f"{cyanide_bundle}/CNDLabRemoteCall.{target}.marker"
    )
    process_bundle_token_tmp = f"{process_bundle_token}.new"
    process_bundle_marker_tmp = f"{process_bundle_marker}.new"
    ssh.copy(token_local, bundle_token_tmp)
    ssh.copy(marker_local, bundle_marker_tmp)
    ssh.copy(token_local, process_bundle_token_tmp)
    ssh.copy(marker_local, process_bundle_marker_tmp)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown _installd:_installd "
        f"{shlex.quote(bundle_token_tmp)} {shlex.quote(bundle_marker_tmp)} "
        f"{shlex.quote(process_bundle_token_tmp)} "
        f"{shlex.quote(process_bundle_marker_tmp)} && "
        f"/iosbinpack64/bin/chmod 0644 {shlex.quote(bundle_token_tmp)} "
        f"{shlex.quote(bundle_marker_tmp)} "
        f"{shlex.quote(process_bundle_token_tmp)} "
        f"{shlex.quote(process_bundle_marker_tmp)} && "
        f"/iosbinpack64/bin/mv -f {shlex.quote(bundle_token_tmp)} "
        f"{shlex.quote(bundle_token_path)} && "
        f"/iosbinpack64/bin/mv -f {shlex.quote(bundle_marker_tmp)} "
        f"{shlex.quote(bundle_marker_path)} && "
        f"/iosbinpack64/bin/mv -f {shlex.quote(process_bundle_token_tmp)} "
        f"{shlex.quote(process_bundle_token)} && "
        f"/iosbinpack64/bin/mv -f {shlex.quote(process_bundle_marker_tmp)} "
        f"{shlex.quote(process_bundle_marker)}"
    )


def resolve_ebay_bundle_path(ssh: SSH) -> str:
    output = ssh.command(
        "/iosbinpack64/usr/bin/find /var/containers/Bundle/Application "
        "-mindepth 2 -maxdepth 2 -type d -name eBay.app -print"
    )
    matches = [line.strip() for line in output.splitlines() if line.strip()]
    if len(matches) != 1:
        raise LabError(
            f"expected exactly one installed eBay.app, found {len(matches)}"
        )
    path = matches[0]
    parts = Path(path).parts
    if (len(parts) != 7 or parts[:5] !=
            ("/", "var", "containers", "Bundle", "Application") or
            parts[-1] != "eBay.app"):
        raise LabError(f"refusing unexpected eBay bundle path: {path}")
    try:
        uuid.UUID(parts[-2])
    except ValueError as error:
        raise LabError(f"refusing non-UUID eBay bundle path: {path}") from error
    return path


def inject(ssh: SSH, payload: Path, target: str, pid: int) -> str:
    expected = TARGETS[target]
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()[:16]
    remote_payload = f"/var/tmp/cnd-remotecall-{digest}.dylib"
    ssh.copy(payload, remote_payload)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote_payload)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote_payload)}"
    )

    # Re-resolve immediately before injection. Never let an empty lookup,
    # PID 0, PID 1, or a recycled PID reach opainject.
    current_pid, _ = resolve_target(ssh, target)
    if current_pid != pid or pid <= 1:
        raise LabError(
            f"refusing: {target} identity changed before injection "
            f"({pid} -> {current_pid})"
        )
    remote_command = (
        f"current=$(/bin/ps -p {pid} -o command=); "
        f"case \"$current\" in "
        f"{shlex.quote(expected)}|{shlex.quote(expected + ' ')}*) ;; "
        f"*) echo 'target identity changed' >&2; exit 90;; esac; "
        f"exec /iosbinpack64/bin/opainject {pid} "
        f"{shlex.quote(remote_payload)}"
    )
    return ssh.command(remote_command)


def validate_target_marker(values: dict[str, str], target: str, pid: int) -> str:
    required = {"version", "model", "target", "pid", "socket"}
    missing = sorted(required - values.keys())
    if missing:
        raise LabError(f"{target} marker is missing: {', '.join(missing)}")
    if values["version"] != "1" or values["model"] != "VPHONE":
        raise LabError(f"{target} marker version/model is invalid")
    if values["target"] != target:
        raise LabError(
            f"{target} marker names the wrong target: {values['target']}"
        )
    try:
        marker_pid = int(values["pid"], 10)
    except ValueError as error:
        raise LabError(f"{target} marker PID is malformed") from error
    if marker_pid != pid:
        raise LabError(
            f"{target} marker PID is stale: marker={marker_pid} live={pid}"
        )
    expected_socket = expected_socket_path(target)
    if values["socket"] != expected_socket:
        raise LabError(
            f"{target} marker socket mismatch: expected={expected_socket} "
            f"observed={values['socket']}"
        )
    return expected_socket


def read_bundle_credentials(
    ssh: SSH, target: str, pid: int
) -> tuple[bytes, dict[str, str], str]:
    bundle = cyanide_bundle_path(ssh)
    token_path = f"{bundle}/CNDLabRemoteCall.{target}.token"
    marker_path = f"{bundle}/CNDLabRemoteCall.{target}.marker"
    try:
        token = ssh.read_file(token_path)
        marker_text = ssh.read_file(marker_path).decode("utf-8", "strict")
    except (LabError, UnicodeDecodeError) as error:
        raise LabError(
            f"{target} target-specific Cyanide credentials are missing or unreadable"
        ) from error
    if len(token) != 32:
        raise LabError(
            f"{target} token length mismatch: expected=32 observed={len(token)}"
        )
    values = parse_marker(marker_text)
    socket_path = validate_target_marker(values, target, pid)
    return token, values, socket_path


def read_persisted_credentials(
    ssh: SSH, target: str, pid: int
) -> tuple[bytes, dict[str, str]]:
    try:
        token = ssh.read_file(target_token_path(target))
        text = ssh.read_file(target_marker_path(target)).decode(
            "utf-8", "strict"
        )
        values = parse_marker(text)
        validate_target_marker(values, target, pid)
        if len(token) != 32:
            raise LabError(
                f"{target} persisted token length mismatch: {len(token)}"
            )
        return token, values
    except (LabError, UnicodeDecodeError):
        token, values, _ = read_bundle_credentials(ssh, target, pid)
        return token, values


def inspect_endpoint(ssh: SSH, socket_path: str) -> tuple[str, int, int]:
    mailbox_path = f"{socket_path}.mailbox"
    mailbox_kind = ssh.file_kind(mailbox_path)
    if mailbox_kind == "file":
        request, response = mailbox_sequences(ssh.read_file(mailbox_path))
        return mailbox_path, request, response
    if mailbox_kind != "missing":
        raise LabError(f"unsafe mailbox object at {mailbox_path}: {mailbox_kind}")
    if ssh.file_kind(socket_path) == "socket":
        return socket_path, 0, 0
    raise LabError(f"endpoint missing: {socket_path}")


def endpoint_objects(ssh: SSH, target: str) -> list[tuple[str, str]]:
    socket_path = expected_socket_path(target)
    objects = []
    for path in (socket_path, f"{socket_path}.mailbox"):
        kind = ssh.file_kind(path)
        if kind != "missing":
            objects.append((path, kind))
    return objects


def persisted_marker_unchecked(ssh: SSH, target: str) -> dict[str, str]:
    candidates = [target_marker_path(target)]
    try:
        bundle = cyanide_bundle_path(ssh)
        candidates.append(f"{bundle}/CNDLabRemoteCall.{target}.marker")
    except LabError:
        pass
    for path in candidates:
        try:
            return parse_marker(ssh.read_file(path).decode("utf-8", "strict"))
        except (LabError, UnicodeDecodeError):
            continue
    raise LabError(f"{target} has an endpoint but no readable target marker")


def remove_proven_stale_endpoint(
    ssh: SSH, target: str, live_pid: int, objects: list[tuple[str, str]]
) -> None:
    values = persisted_marker_unchecked(ssh, target)
    required = {"version", "model", "target", "pid", "socket"}
    if required - values.keys() or values.get("version") != "1" or \
            values.get("model") != "VPHONE" or values.get("target") != target or \
            values.get("socket") != expected_socket_path(target):
        raise LabError(
            f"refusing to remove {target} endpoint: its marker is not exact"
        )
    try:
        marker_pid = int(values["pid"], 10)
    except ValueError as error:
        raise LabError(
            f"refusing to remove {target} endpoint: malformed marker PID"
        ) from error
    if marker_pid == live_pid:
        raise LabError(
            f"refusing to replace the live {target} backend in PID {live_pid}"
        )
    expected = {
        expected_socket_path(target): "socket",
        f"{expected_socket_path(target)}.mailbox": "file",
    }
    for path, kind in objects:
        if expected.get(path) != kind:
            raise LabError(
                f"refusing to remove unsafe {target} endpoint {path}: {kind}"
            )
    quoted = " ".join(shlex.quote(path) for path, _ in objects)
    ssh.command(f"/iosbinpack64/bin/rm -f {quoted}")


def target_status(ssh: SSH, target: str) -> str:
    pid, command = resolve_target(ssh, target)
    _, _, socket_path = read_bundle_credentials(ssh, target, pid)
    endpoint, request, response = inspect_endpoint(ssh, socket_path)
    state = "idle" if request == response else "busy"
    return (
        f"target={target} pid={pid} command={command} endpoint={endpoint} "
        f"request={request} response={response} state={state}"
    )


def disable(ssh: SSH, target: str | None) -> None:
    paths = [MARKER_PATH, TOKEN_PATH]
    if target:
        paths.extend((target_marker_path(target), target_token_path(target)))
        try:
            bundle = cyanide_bundle_path(ssh)
            paths.extend((
                f"{bundle}/CNDLabRemoteCall.{target}.marker",
                f"{bundle}/CNDLabRemoteCall.{target}.token",
            ))
        except LabError:
            pass
    quoted = " ".join(shlex.quote(path) for path in paths)
    ssh.command(f"/iosbinpack64/bin/rm -f {quoted}")


def run_smoke(ssh: SSH, target: str) -> str:
    executable = build_smoke()
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()[:16]
    # Running from inside Cyanide.app makes CNDLabRemoteCallClient resolve the
    # exact CNDLabRemoteCall.<target>.{token,marker} files used by Cyanide.
    remote = f"{cyanide_bundle_path(ssh)}/CNDLabRemoteCallSmoke-{digest}"
    ssh.copy(executable, remote)
    ssh.command(
        f"/iosbinpack64/usr/sbin/chown root:wheel {shlex.quote(remote)} && "
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)}"
    )
    return ssh.command(f"{remote} {shlex.quote(target)}").strip()


def refresh_credentials(ssh: SSH, target: str) -> str:
    pid, _ = resolve_target(ssh, target)
    token, values = read_persisted_credentials(ssh, target, pid)
    socket_path = validate_target_marker(values, target, pid)
    inspect_endpoint(ssh, socket_path)
    sandbox_path = ("/var/installd/Library/Caches"
                    if target == "installd" else "/var/tmp")
    bundle_access_target = target in {
        "installd", "iconservicesagent", "Spotlight"
    }
    client_file_token = issue_file_extension(ssh, sandbox_path)
    bundle_token = issue_file_extension(
        ssh, "/var/containers/Bundle/Application") \
        if bundle_access_target else ""
    root_token = issue_file_extension(ssh, "/private/var") \
        if bundle_access_target else ""
    target_bundle_path = (resolve_ebay_bundle_path(ssh)
                          if target in {"iconservicesagent", "Spotlight"}
                          else "")
    install_credentials(
        ssh, target, pid, token, socket_path, client_file_token,
        bundle_token, target_bundle_path, root_token)
    return f"refreshed target={target} pid={pid} endpoint={socket_path}"


def gate_target(ssh: SSH, target: str) -> str:
    pid, command = resolve_target(ssh, target)
    _, _, socket_path = read_bundle_credentials(ssh, target, pid)
    endpoint, request, response = inspect_endpoint(ssh, socket_path)
    if request != response:
        raise LabError(
            f"{target} backend is wedged: request={request} response={response}; "
            f"restart {target} before any further test"
        )
    try:
        smoke = run_smoke(ssh, target)
    except LabError as error:
        _, request_after, response_after = inspect_endpoint(ssh, socket_path)
        if request_after != response_after:
            raise LabError(
                f"{target} repair gate wedged the mailbox: "
                f"request={request_after} response={response_after}; "
                f"restart {target}"
            ) from error
        raise LabError(
            f"{target} repair gate failed cleanly at sequence "
            f"{request_after}; backend is not READY and {target} must be "
            f"restarted: {error}"
        ) from error
    _, request_after, response_after = inspect_endpoint(ssh, socket_path)
    if request_after != response_after:
        raise LabError(
            f"{target} smoke left an in-flight request: "
            f"request={request_after} response={response_after}"
        )
    expected = f"ok target={target} pid={pid} "
    if (not smoke.startswith(expected) or " rx=yes " not in f" {smoke} " or
            not smoke.endswith("objc=yes")):
        raise LabError(f"{target} smoke identity mismatch: {smoke}")
    return (
        f"READY target={target} pid={pid} command={command} "
        f"endpoint={endpoint} sequence={request_after} {smoke}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=("enable", "disable", "status", "smoke", "refresh", "gate"),
    )
    parser.add_argument("target", nargs="?", choices=sorted(TARGETS))
    parser.add_argument("--host", default=None, help="device host (required for live operations)")
    parser.add_argument("--port", type=int, default=22222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    parser.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    args = parser.parse_args()

    if args.action in {"enable", "status", "smoke", "refresh", "gate"} and \
            not args.target:
        parser.error(f"{args.action} requires a target")
    if args.port != 22222 or args.user != "root":
        raise LabError("refusing: this harness requires root on SSH port 22222")
    if not args.known_hosts.is_file():
        raise LabError(f"known-hosts file does not exist: {args.known_hosts}")

    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)

    if args.action == "disable":
        disable(ssh, args.target)
        scope = args.target or "legacy-global"
        print(
            f"RemoteCall lab credentials disabled scope={scope}; injected "
            "code remains resident until the target process exits."
        )
        return 0
    if args.action == "status":
        print(target_status(ssh, args.target))
        return 0
    if args.action in {"smoke", "gate"}:
        print(gate_target(ssh, args.target))
        return 0
    if args.action == "refresh":
        print(refresh_credentials(ssh, args.target))
        print(gate_target(ssh, args.target))
        return 0

    pid, command = resolve_target(ssh, args.target)
    objects = endpoint_objects(ssh, args.target)
    if objects:
        values = persisted_marker_unchecked(ssh, args.target)
        try:
            marker_pid = int(values.get("pid", ""), 10)
        except ValueError as error:
            raise LabError(
                f"{args.target} endpoint has a malformed persisted PID; "
                f"restart {args.target} and remove only its proven-stale endpoint"
            ) from error
        if marker_pid == pid:
            try:
                print(refresh_credentials(ssh, args.target))
                print(gate_target(ssh, args.target))
            except LabError as error:
                raise LabError(
                    f"{args.target} already has a backend in PID {pid}, but its "
                    f"repair gate failed: {error}; restart {args.target}; "
                    "refusing blind reinjection"
                ) from error
            print("backend already healthy; injection skipped")
            return 0
        remove_proven_stale_endpoint(ssh, args.target, pid, objects)

    token = secrets.token_bytes(32)
    installd_socket_path = ""
    if args.target == "installd":
        installd_socket_path = "/var/installd/Library/Caches/.cnd-rc"
    elif args.target in {"SpringBoard", "iconservicesagent", "Spotlight"}:
        # Cyanide's production sandbox cannot reliably connect to another
        # process's /var/tmp AF_UNIX endpoint. Give these icon hosts a bounded
        # path and force the mmap mailbox transport that both sides can open
        # through their separately issued file extensions.
        installd_socket_path = (
            f"{SOCKET_PREFIX}{args.target}{SOCKET_SUFFIX}"
        )
    sandbox_path = ("/var/installd/Library/Caches"
                    if args.target == "installd" else "/var/tmp")
    # Sandboxed agents need an explicit grant for the directory containing
    # their Unix endpoint. SpringBoard happens to permit /var/tmp already, but
    # issuing the same bounded grant keeps every non-installd target
    # deterministic and lets iconservicesagent bind its socket.
    sandbox_token = issue_file_extension(ssh, sandbox_path)
    client_file_token = issue_file_extension(ssh, sandbox_path)
    bundle_access_target = args.target in {
        "installd", "iconservicesagent", "Spotlight"
    }
    server_bundle_token = issue_file_extension(
        ssh, "/var/containers/Bundle/Application") \
        if bundle_access_target else ""
    bundle_token = issue_file_extension(
        ssh, "/var/containers/Bundle/Application") \
        if bundle_access_target else ""
    root_token = issue_file_extension(ssh, "/private/var") \
        if bundle_access_target else ""
    target_bundle_path = (resolve_ebay_bundle_path(ssh)
                          if args.target in {"iconservicesagent", "Spotlight"}
                          else "")
    payload = build_payload(
        token, installd_socket_path, sandbox_token, server_bundle_token,
        force_mailbox=args.target in {
            "SpringBoard", "iconservicesagent", "Spotlight"
        })
    current_pid, current_command = resolve_target(ssh, args.target)
    if current_pid != pid or current_command != command:
        raise LabError(
            f"{args.target} identity changed during preparation: "
            f"{pid} -> {current_pid}"
        )
    socket_path = installd_socket_path or (
        f"{SOCKET_PREFIX}{args.target}{SOCKET_SUFFIX}"
    )
    install_credentials(
        ssh, args.target, pid, token, socket_path, client_file_token,
        bundle_token, target_bundle_path, root_token)
    output = inject(ssh, payload, args.target, pid)
    print(output.strip())
    print(
        f"RemoteCall lab enabled target={args.target} pid={pid} "
        f"command={command}"
    )
    deadline = time.monotonic() + 5.0
    while True:
        try:
            print(target_status(ssh, args.target))
            break
        except LabError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
    print(gate_target(ssh, args.target))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
