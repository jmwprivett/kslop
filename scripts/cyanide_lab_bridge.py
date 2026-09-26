#!/usr/bin/env python3
"""Small client for Cyanide's foreground-only authenticated Lab Bridge."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any


DEFAULT_HOST = "iPinky-Max.coredevice.local"
DEFAULT_PORT = 49494
MAX_RESPONSE = 2 * 1024 * 1024


class _DarwinSockAddrIn6(ctypes.Structure):
    _fields_ = [
        ("sin6_len", ctypes.c_uint8),
        ("sin6_family", ctypes.c_uint8),
        ("sin6_port", ctypes.c_uint16),
        ("sin6_flowinfo", ctypes.c_uint32),
        ("sin6_addr", ctypes.c_uint8 * 16),
        ("sin6_scope_id", ctypes.c_uint32),
    ]


class _DarwinSAEndpoints(ctypes.Structure):
    _fields_ = [
        ("sae_srcif", ctypes.c_uint),
        ("sae_srcaddr", ctypes.c_void_p),
        ("sae_srcaddrlen", ctypes.c_uint32),
        ("sae_dstaddr", ctypes.c_void_p),
        ("sae_dstaddrlen", ctypes.c_uint32),
    ]


class _IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


def connect_with_initial_data(host: str, port: int, wire: bytes, timeout: float) -> socket.socket:
    """Connect while enqueueing the first write, avoiding an accepted-socket race."""
    if sys.platform != "darwin":
        connection = socket.create_connection((host, port), timeout=timeout)
        connection.sendall(wire)
        return connection

    resolved = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)[0][4]
    packed = socket.inet_pton(socket.AF_INET6, resolved[0])
    destination = _DarwinSockAddrIn6()
    destination.sin6_len = ctypes.sizeof(destination)
    destination.sin6_family = socket.AF_INET6
    destination.sin6_port = socket.htons(port)
    destination.sin6_flowinfo = 0
    destination.sin6_addr[:] = packed
    destination.sin6_scope_id = resolved[3]
    endpoints = _DarwinSAEndpoints(
        0, None, 0, ctypes.addressof(destination), ctypes.sizeof(destination)
    )
    payload = ctypes.create_string_buffer(wire)
    vector = _IOVec(ctypes.addressof(payload), len(wire))
    enqueued = ctypes.c_size_t(0)
    libc = ctypes.CDLL(None, use_errno=True)
    connectx = libc.connectx
    connectx.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(_DarwinSAEndpoints),
        ctypes.c_uint32,
        ctypes.c_uint,
        ctypes.POINTER(_IOVec),
        ctypes.c_uint,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    connectx.restype = ctypes.c_int
    connection = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    result = connectx(
        connection.fileno(), ctypes.byref(endpoints), 0, 0,
        ctypes.byref(vector), 1, ctypes.byref(enqueued), None,
    )
    if result != 0:
        error = ctypes.get_errno()
        connection.close()
        raise OSError(error, os.strerror(error))
    connection.settimeout(timeout)
    if enqueued.value < len(wire):
        connection.sendall(wire[enqueued.value:])
    return connection


def resolve_bridge_host(host: str, timeout: float) -> str:
    """Acquire CoreDevice's short-lived tunnel and return its numeric peer."""
    if not host.endswith(".coredevice.local"):
        return host
    completed = subprocess.run(
        [
            "xcrun", "devicectl", "device", "info", "details",
            "--device", host, "--timeout", str(max(1, int(timeout))),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    match = re.search(r"tunnelIPAddress:\s*([0-9a-fA-F:]+)", completed.stdout)
    if not match:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"CoreDevice tunnel address unavailable: {detail}")
    return match.group(1)


def load_config(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    return json.loads(Path(path).read_text(encoding="utf-8"))


def request(host: str, port: int, token: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
    payload = dict(body)
    payload["token"] = token
    wire = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    with connect_with_initial_data(host, port, wire, timeout) as connection:
        chunks: list[bytes] = []
        size = 0
        while size < MAX_RESPONSE:
            chunk = connection.recv(65536)
            if not chunk:
                break
            newline = chunk.find(b"\n")
            if newline >= 0:
                chunks.append(chunk[:newline])
                break
            chunks.append(chunk)
            size += len(chunk)
        else:
            raise RuntimeError("bridge response exceeded 2 MiB")
    raw = b"".join(chunks)
    if not raw:
        raise RuntimeError("bridge returned an empty response")
    return json.loads(raw)


def command_body(args: argparse.Namespace) -> dict[str, Any]:
    command = args.command
    if command == "ping":
        return {"command": "ping"}
    if command == "open":
        return {"command": "session.open", "target": args.target}
    if command == "close":
        return {"command": "session.close"}
    if command == "info":
        return {"command": "session.info"}
    if command == "inspect-agent":
        return {"command": "inspect.agent-writer"}
    if command == "inspect-store":
        return {"command": "inspect.live-store"}
    if command == "tail":
        return {"command": "log.tail", "maxBytes": args.max_bytes}
    if command == "raw":
        decoded = json.loads(args.json)
        if not isinstance(decoded, dict):
            raise ValueError("raw request must be a JSON object")
        return decoded
    raise ValueError(f"unsupported command: {command}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--config", help="JSON configuration copied from Cyanide")
    result.add_argument("--host", help="device hostname")
    result.add_argument("--port", type=int, help="bridge TCP port")
    result.add_argument("--token", help="per-launch bridge token")
    result.add_argument("--timeout", type=float, default=120.0)
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("ping")
    opened = sub.add_parser("open")
    opened.add_argument("target", choices=("iconservicesagent", "spotlight"))
    sub.add_parser("close")
    sub.add_parser("info")
    sub.add_parser("inspect-agent")
    sub.add_parser("inspect-store")
    tail = sub.add_parser("tail")
    tail.add_argument("--max-bytes", type=int, default=32768)
    raw = sub.add_parser("raw")
    raw.add_argument("json", help="complete JSON request object")
    return result


def main() -> int:
    args = parser().parse_args()
    config = load_config(args.config)
    host = args.host or config.get("host") or os.environ.get("CYANIDE_LAB_HOST") or DEFAULT_HOST
    port = args.port or config.get("port") or int(os.environ.get("CYANIDE_LAB_PORT", DEFAULT_PORT))
    token = args.token or config.get("token") or os.environ.get("CYANIDE_LAB_TOKEN")
    if not token:
        print("error: provide --token, --config, or CYANIDE_LAB_TOKEN", file=sys.stderr)
        return 2
    try:
        resolved_host = resolve_bridge_host(host, args.timeout)
        response = request(resolved_host, int(port), token, command_body(args), args.timeout)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(response, indent=2, sort_keys=True))
    return 0 if response.get("ok") else 3


if __name__ == "__main__":
    raise SystemExit(main())
