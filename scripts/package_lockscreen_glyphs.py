#!/usr/bin/env python3
"""Package the experimental 23A341 glyph CAR as a host-side app resource.

This copies a known research artifact; it never accesses an iOS device. The
trailing padding preserves the catalog bytes while matching the stock length.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "build/lab-systemui-theme-probe/pulsar-coreglyphs-priority-23A341/compiled/Assets.car"
RESOURCE_DIRECTORY = ROOT / "Cyanide/Resources/LockscreenGlyphs"
RESOURCE_NAME = "LockscreenGlyphs-23A341-CoreGlyphsPriority"
TARGET_LENGTH = 309384
SOURCE_SHA256 = "9a56032d2e7fb8dbd8456b75f534c7c7a1466d8e0b067d4a362159e2bb1b0cb2"
STOCK_SHA256 = "bbc4ee4592e94cf6a4929ee0d04263b6aafd3b8fb5fd656c82ab50b8d4e64220"
STOCK_VARIANTS = [
    {
        "identifier": "coreglyphs-priority-23A341-experimental",
        "hardwareModel": "iPhone17,3",
        "thinningSubtype": 2340,
        "stockSHA256": STOCK_SHA256,
        "evidence": "VM/IPSW research catalog",
    },
    {
        "identifier": "coreglyphs-priority-23A341-iphone17-2-experimental",
        "hardwareModel": "iPhone17,2",
        "thinningSubtype": 2688,
        "stockSHA256": "05c2f3af7b331eec47349f3cec71e466f508cf84e81e7f4aeeb6bc667c74341e",
        "evidence": "read-only physical export",
    },
]
TARGET_PATH = "/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPriority.bundle/Assets.car"


def main() -> None:
    source_bytes = SOURCE.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    if source_hash != SOURCE_SHA256 or len(source_bytes) != 153432:
        raise SystemExit("Research CAR does not match the reviewed 23A341 source.")
    payload = source_bytes + bytes(TARGET_LENGTH - len(source_bytes))
    payload_hash = hashlib.sha256(payload).hexdigest()
    RESOURCE_DIRECTORY.mkdir(parents=True, exist_ok=True)
    destination = RESOURCE_DIRECTORY / f"{RESOURCE_NAME}.car"
    with tempfile.TemporaryDirectory(prefix="cnd-glyph-package-") as directory:
        staged = Path(directory) / destination.name
        staged.write_bytes(payload)
        validation = subprocess.run(
            ["xcrun", "assetutil", "-Z", str(staged)],
            capture_output=True, text=True, check=False,
        )
        if validation.returncode != 0:
            raise SystemExit("Padded CAR validation failed: " + validation.stderr)
        destination.write_bytes(payload)
    metadata = {
        "identifier": STOCK_VARIANTS[0]["identifier"],
        "productBuildVersion": "23A341",
        "targetPath": TARGET_PATH,
        "resourceName": RESOURCE_NAME,
        "resourceExtension": "car",
        "stockSHA256": STOCK_SHA256,
        "stockVariants": STOCK_VARIANTS,
        "physicalTargetDigestVerified": True,
        "payloadSHA256": payload_hash,
        "payloadLength": len(payload),
        "sourceSHA256": source_hash,
        "sourceLength": len(source_bytes),
        "paddingLength": len(payload) - len(source_bytes),
        "paddingByte": 0,
        "assetutilValidationPassed": True,
        "status": "experimental-physical-device",
        "deviceVerified": False,
        "sourceCoreUIVersion": 975,
        "stockCoreUIVersion": 970,
        "preservesOriginalPriorityNames": True,
        "preservesOriginalPriorityVisuals": False,
        "preservesPulsarPixelFidelity": False,
        "limitations": [
            "Physical-device symbol lookup and lockscreen appearance are unverified.",
            "Pulsar geometry is monochrome and does not preserve color or antialiasing.",
            "Existing priority glyph names remain, but their vector artwork was flattened.",
            "The generated CoreUI version and key format differ from the stock catalog.",
            "The shared SFSymbols catalog may affect glyph consumers beyond the lockscreen.",
        ],
    }
    (RESOURCE_DIRECTORY / f"{RESOURCE_NAME}.json").write_text(
        json.dumps(metadata, indent=2) + "\n"
    )
    print(json.dumps({"resource": str(destination.relative_to(ROOT)),
                      "length": len(payload), "sha256": payload_hash,
                      "assetutilValidationPassed": True}, indent=2))


if __name__ == "__main__":
    main()
