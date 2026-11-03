#!/usr/bin/env python3
"""Deliver a bounded UAT probe and read its result from the live process.

CoreDevice's appDataContainer file service terminates a running application,
so it cannot be used as a mailbox for a process-local socket KRW primitive.
This helper opens Cyanide's registered URL scheme instead. UIKit delivers the
URL to the existing scene, or launches Cyanide and lets its launch-time parked
KRW recovery finish before the scene receives the command. A random token in
that URL authenticates a single-use TCP result bridge; no app-container file
service is opened.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.parse
import uuid


SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from cyanide_lab_bridge import (  # noqa: E402
    DEFAULT_HOST,
    DEFAULT_PORT,
    request as bridge_request,
    resolve_bridge_host,
)


BUNDLE_ID = "com.zeroxjf.ios-cyanide1"
DEFAULT_DEVICE = "828515D1-88C1-5CEB-A16F-5AD0AE3E3641"
COMMANDS = (
    "control",
    "image",
    "queue",
    "uat-binding-read",
    "uat-binding-write",
    "uat-record-state",
    "uat-signer-inventory",
    "uat-get-pte",
)


def probe_url(command: str, token: str, request_id: str) -> str:
    query = urllib.parse.urlencode(
        {"replyToken": token, "requestID": request_id}
    )
    return f"{BUNDLE_ID}://probe/{command}?{query}"


def read_live_result(
    host: str,
    port: int,
    token: str,
    request_id: str,
    timeout: float,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    resolved_host = resolve_bridge_host(host, min(timeout, 15.0))
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        remaining = max(0.1, deadline - time.monotonic())
        try:
            response = bridge_request(
                resolved_host,
                port,
                token,
                {"command": "probe.result", "requestID": request_id},
                min(2.0, remaining),
            )
        except (OSError, RuntimeError, json.JSONDecodeError) as error:
            last_error = error
            time.sleep(min(0.15, remaining))
            continue
        if not response.get("ok"):
            raise RuntimeError(
                f"live result bridge refused the request: {response}"
            )
        if response.get("status") == "pending":
            time.sleep(min(0.15, remaining))
            continue
        if response.get("status") != "complete":
            raise RuntimeError(f"unexpected live result response: {response}")
        result = response.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("live result response did not contain an object")
        try:
            acknowledgement = bridge_request(
                resolved_host,
                port,
                token,
                {"command": "probe.ack", "requestID": request_id},
                min(2.0, max(0.1, deadline - time.monotonic())),
            )
            if acknowledgement.get("status") == "acknowledged":
                # The app closes the listener 250 ms after encoding the ACK.
                time.sleep(0.35)
        except (OSError, RuntimeError, json.JSONDecodeError):
            # The app also expires the single-use listener after 120 seconds.
            pass
        return result
    detail = f": {last_error}" if last_error else ""
    raise TimeoutError(f"timed out waiting for live probe result{detail}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument(
        "--device",
        default=os.environ.get("CND_DEVICE", DEFAULT_DEVICE),
        help="CoreDevice identifier (default: iPinky Max; or CND_DEVICE)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("CYANIDE_LAB_HOST", DEFAULT_HOST),
        help="CoreDevice hostname used for the live result bridge",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("CYANIDE_LAB_PORT", DEFAULT_PORT)),
        help="live result bridge TCP port",
    )
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--json-output", help="also write the result JSON here")
    args = parser.parse_args()

    token = secrets.token_hex(32)
    request_id = uuid.uuid4().hex
    url = probe_url(args.command, token, request_id)
    completed = subprocess.run(
        [
            "xcrun",
            "devicectl",
            "device",
            "process",
            "launch",
            "--device",
            args.device,
            "--payload-url",
            url,
            BUNDLE_ID,
        ],
        check=False,
    )
    if completed.returncode != 0:
        return completed.returncode
    try:
        result = read_live_result(
            args.host, args.port, token, request_id, args.timeout
        )
    except (OSError, RuntimeError, TimeoutError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json_output:
        Path(args.json_output).write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
