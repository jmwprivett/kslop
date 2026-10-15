#!/usr/bin/env python3
"""Run the normal IOUserEthernet interface-creation signer trigger in vPhone."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
from pathlib import Path
from typing import Any

from cnd_rea_secure_execution import write_json
from cnd_remotecall_lab import DEFAULT_KNOWN_HOSTS, LabError, SSH, require_vphone
from cnd_vphone_krw import build_binary


REPO_ROOT = Path(__file__).resolve().parents[2]
TRIGGER_SOURCE = REPO_ROOT / "scripts/lab/cnd_iouserethernet_signer_trigger.m"
TRIGGER_ENTITLEMENTS = REPO_ROOT / \
    "scripts/lab/cnd_iouserethernet_signer_trigger.entitlements"


def validate_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != \
            "com.zeroxjf.cyanide.iouserethernet-signer-trigger" or \
            value.get("schemaVersion") != 1:
        raise LabError("IOUserEthernet trigger returned an unsupported result")
    if value.get("openKR") != "0x0000000000000000" or \
            value.get("callKR") != "0x0000000000000000":
        raise LabError(
            "IOUserEthernet entitlement/open or controller creation failed"
        )
    if value.get("kernelReadUsed") is not False or \
            value.get("kernelWriteUsed") is not False or \
            value.get("kernelCallUsed") is not False:
        raise LabError("IOUserEthernet trigger violated its no-kernel-primitive invariant")
    created = value.get("createdInterfaces")
    if not isinstance(created, list) or not created or not any(
            isinstance(item, dict) and item.get("bsdName")
            for item in created):
        raise LabError("IOUserEthernet did not publish a new BSD interface")
    return value


def run_live(args: argparse.Namespace) -> dict[str, Any]:
    trigger = build_binary(
        TRIGGER_SOURCE, "cnd_iouserethernet_signer_trigger",
        entitlements=TRIGGER_ENTITLEMENTS, architecture="arm64e",
        frameworks=("Foundation", "IOKit"),
    )
    digest = hashlib.sha256(trigger.read_bytes()).hexdigest()
    remote = f"/var/tmp/cnd-iouserethernet-trigger-{digest[:16]}"
    ssh = SSH(args.host, args.port, args.user, args.known_hosts,
              args.password_env)
    require_vphone(ssh)
    ssh.copy(trigger, remote)
    command = (
        f"/iosbinpack64/bin/chmod 0755 {shlex.quote(remote)} && "
        f"{shlex.quote(remote)}"
    )
    if args.hold:
        command += f" --hold {args.hold}"
    output = ssh.command(command)
    try:
        result = validate_result(json.loads(output))
    except json.JSONDecodeError as error:
        raise LabError("IOUserEthernet trigger did not return JSON") from error
    return {
        "schema": "com.zeroxjf.cyanide.iouserethernet-signer-observation",
        "schemaVersion": 1,
        "classification": "vm-runtime-observed",
        "triggerSHA256": digest,
        "result": result,
        "conclusion": (
            "An entitlement-authorized userland external method created a "
            "fresh BSD-backed IOUserEthernetInterface without KRW or kcall."
        ),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--host", required=True)
    result.add_argument("--port", type=int, default=22222)
    result.add_argument("--user", default="root")
    result.add_argument("--known-hosts", type=Path,
                        default=DEFAULT_KNOWN_HOSTS)
    result.add_argument("--password-env", default="CND_VPHONE_ROOT_PASSWORD")
    result.add_argument("--hold", type=int, default=0, choices=range(0, 301),
                        metavar="SECONDS")
    result.add_argument("--output", type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    write_json(args.output, run_live(args))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LabError as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        raise SystemExit(1)
