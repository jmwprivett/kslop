#!/usr/bin/env python3
"""Deliver a bounded UAT probe command without replacing Cyanide's KRW host.

CoreDevice's appDataContainer file service terminates a running application,
so it cannot be used as a mailbox for a process-local socket KRW primitive.
This helper opens Cyanide's registered URL scheme instead. UIKit delivers the
URL to the existing scene, or launches Cyanide and lets its launch-time parked
KRW recovery finish before the scene receives the command.
"""

from __future__ import annotations

import argparse
import os
import subprocess


BUNDLE_ID = "com.zeroxjf.ios-cyanide1"
DEFAULT_DEVICE = "828515D1-88C1-5CEB-A16F-5AD0AE3E3641"
COMMANDS = ("control", "image", "queue")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument(
        "--device",
        default=os.environ.get("CND_DEVICE", DEFAULT_DEVICE),
        help="CoreDevice identifier (default: iPinky Max; or CND_DEVICE)",
    )
    args = parser.parse_args()

    url = f"{BUNDLE_ID}://probe/{args.command}"
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
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
