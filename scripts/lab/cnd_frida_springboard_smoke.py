#!/usr/bin/env python3
"""Perform a bounded, read-only Frida attach smoke test in the vPhone VM."""

from __future__ import annotations

import argparse
import json
import threading
from typing import Any

import frida


AGENT_SOURCE = r"""
send({
  schema: 'com.zeroxjf.cyanide.frida-vm-smoke',
  schemaVersion: 1,
  pid: Process.id,
  arch: Process.arch,
  platform: Process.platform,
  pointerSize: Process.pointerSize,
  moduleCount: Process.enumerateModules().length
});
"""


def run(endpoint: str, target: str, timeout: float) -> dict[str, Any]:
    manager = frida.get_device_manager()
    device = manager.add_remote_device(endpoint)
    matches = [process for process in device.enumerate_processes()
               if process.name == target]
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one {target} process, observed {len(matches)}"
        )
    process = matches[0]
    session = device.attach(process.pid)
    event = threading.Event()
    messages: list[dict[str, Any]] = []

    def on_message(message: dict[str, Any], data: bytes | None) -> None:
        if data is not None:
            message = dict(message)
            message["binaryDataLength"] = len(data)
        messages.append(message)
        event.set()

    script = session.create_script(AGENT_SOURCE)
    script.on("message", on_message)
    try:
        script.load()
        if not event.wait(timeout):
            raise RuntimeError("timed out waiting for the Frida VM agent")
        if len(messages) != 1 or messages[0].get("type") != "send":
            raise RuntimeError("Frida VM agent returned an unexpected message")
        payload = messages[0].get("payload")
        if not isinstance(payload, dict) or \
                payload.get("schema") != \
                "com.zeroxjf.cyanide.frida-vm-smoke" or \
                payload.get("pid") != process.pid:
            raise RuntimeError("Frida VM agent identity check failed")
        return {
            "schema": "com.zeroxjf.cyanide.frida-vm-smoke-report",
            "schemaVersion": 1,
            "result": "attached-read-only",
            "endpoint": endpoint,
            "target": target,
            "targetPid": process.pid,
            "agent": payload,
            "writesPerformed": False,
            "hooksInstalled": False,
        }
    finally:
        try:
            script.unload()
        finally:
            session.detach()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default="127.0.0.1:27042")
    parser.add_argument("--target", default="SpringBoard")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()
    if args.target != "SpringBoard":
        raise SystemExit("this bounded smoke test only targets SpringBoard")
    if args.timeout <= 0 or args.timeout > 30:
        raise SystemExit("timeout must be greater than zero and at most 30")
    try:
        report = run(args.endpoint, args.target, args.timeout)
    except (frida.Error, RuntimeError) as error:
        raise SystemExit(f"error: {error}") from error
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
