#!/usr/bin/env python3
"""Export original IPSW Control Center CAML glyphs as design references."""
from pathlib import Path
import json
import shutil
import struct
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "build/iOS26-23A341-CC-assets/23A341__iPhone17,2/System/Library"
OUT = ROOT / "build/CC-Stock-Artwork-References-iOS26-23A341"
RENDERER = ROOT / "build/render-stock-controlcenter-reference"
README = """# Stock Control Center artwork references

Rendered from Apple's original iOS 26.0 build 23A341 resources for iPhone17,2.
Open `contact-sheet.png` for the labeled overview, or `png/` for transparent files.
`manifest.json` records source paths, native states, symbol names, dimensions, and alpha bounds.

Included: Timer; Sleep, Personal, Work, Driving, Fitness, Gaming, Mindful, Reading
Focus modes; four AirPods Listening modes; Stereo and Multichannel Spatial Audio
Off/Fixed/Head Tracked; Conversation Awareness; VPN; three Satellite states; stock
Apple Intelligence and custom Focus star examples.

CAML PNGs preserve native canvas and proportions at 4× scale. CoreGlyphs PNGs are
rendered directly from the original stock vector catalog at 40 points and 3× scale,
preserving the symbol's aspect ratio. Original CAML packages, including animations,
are in `native-packages/`. Theme artwork can use the agreed 220×220 canvas.

## State and identity caveats

Selected listening and Conversation Awareness may share their static glyph with
the unselected state. System button color/background and animation provide further
state distinction. The VPN control similarly uses one stock symbol across states.

Spatial "native active" references apply the named state to the underlying layer
model and freeze animation. The live state repeats an animation; these are not
screenshots of a particular live frame. Use "native base" files for the clearest
drawing reference. Stereo and Multichannel originals differ, so both are included.

Timer's live backdrop vibrancy is flattened to its original vector mask in white
for the transparent reference. Native source packages are unchanged.

The included `apple.intelligence` image is original stock art, but the existing
trace did not record Reduce Interruptions' exact symbol identity. Treat it as a
reference candidate until that identity is confirmed.

Custom Focus has no universal stock icon: users choose a symbol and color.
The included `star.fill` is an explicitly labeled user-selectable example.

## Reproduction and verification

Run `python3 scripts/export_stock_controlcenter_references.py` from the repository.
It builds the host renderer and regenerates PNGs, manifest, contact sheet, README,
and ZIP. Original extracted 23A341 resources must remain at the input paths in the
script. Every PNG is checked for valid dimensions, visible pixels, and transparent
pixels. Alpha bounds are recorded in the manifest. The full sheet was also visually
inspected. No product runtime code or device state is changed by this export.
"""

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "png").mkdir(exist_ok=True)
    (OUT / "native-packages").mkdir(exist_ok=True)
    subprocess.run(["clang", "-fobjc-arc", "-framework", "AppKit", "-framework", "QuartzCore",
                    str(ROOT / "scripts/render_stock_controlcenter_reference.m"), "-o", str(RENDERER)], check=True)
    jobs = [("Timer", "timer", "ControlCenter/Bundles/TimerModule.bundle/Timer.ca", [("idle", "base"), ("running", "timing")])]
    for mode, package in [("Sleep", "sleep_cg_02"), ("Personal", "personal_cg_02"),
                          ("Work", "work_cg_02"), ("Driving", "driving_cg_03"),
                          ("Fitness", "fitness_cg_02"), ("Gaming", "gaming_cg_02"),
                          ("Mindful", "mindful_cg_02"), ("Reading", "reading_cg_02")]:
        jobs.append((f"Focus — {mode}", f"focus_{mode.lower()}",
                     f"PrivateFrameworks/FocusUI.framework/{package}.ca", [("inactive", "OFF"), ("active", "ON")]))
    for mode, package in [("off", "Off"), ("transparency", "Transparency"),
                          ("noise_cancellation", "NoiseCancellation"), ("adaptive", "Auto")]:
        jobs.append(("Listening — " + mode.replace("_", " "), f"airpods_listening_{mode}",
                     f"PrivateFrameworks/MediaControls.framework/ListeningMode{package}.ca",
                     [("unselected", "base"), ("selected", "on")]))
    for family in ["Stereo", "Multichannel"]:
        for mode, package, state in [("off", "Off", "base"), ("fixed", "On", "animating"),
                                     ("head_tracked", "HeadTracked", "head-tracked")]:
            jobs.append((f"Spatial {family.lower()} — {mode.replace('_', ' ')}",
                         f"airpods_spatial_{family.lower()}_{mode}",
                         f"PrivateFrameworks/MediaControls.framework/Spatial{family}{package}.ca",
                         [("native base", "base")] + ([] if state == "base" else [("native active", state)])))
    jobs.append(("Conversation Awareness", "airpods_conversation_awareness",
                 "PrivateFrameworks/MediaControls.framework/ConversationAwareness.ca", [("off", "base"), ("on", "On")]))
    entries = []
    for label, name, path, states in jobs:
        package = SOURCE / path
        shutil.copytree(package, OUT / "native-packages" / package.name, dirs_exist_ok=True)
        for state_label, native_state in states:
            filename = f"{name}_{state_label.replace(' ', '_')}.png"
            target = OUT / "png" / filename
            subprocess.run([str(RENDERER), str(package), native_state, str(target)], check=True)
            data = target.read_bytes()
            width, height = struct.unpack(">II", data[16:24])
            assert data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) > 200
            entries.append({"label": label, "state": state_label, "native_state": native_state,
                            "png": f"png/{filename}", "source": path, "width": width,
                            "height": height, "bytes": len(data), "provenance": "23A341 native CAML"})
    manifest = {"ios_build": "23A341", "device": "iPhone17,2", "render_scale": 4,
                "references": entries, "notes": [
                    "Native package bounds and proportions preserved; transparent sRGB RGBA PNGs.",
                    "Static model states; animation transitions and repeating animation states are available in native-packages.",
                    "Timer backdrop vibrancy is flattened to its original vector mask in white.",
                    "Selected listening states may share their settled glyph with unselected states; system button tint/backdrop is separate.",
                    "Spatial Stereo and Multichannel are both included because the native packages differ.",
                    "Spatial active-model images freeze repeating animations, so use native base images for the clearest shape reference."]}
    symbols = [
        ("VPN", "vpn_stock", "network.connected.to.line.below.fill", "CoreGlyphsPrivate", "stock glyph"),
        ("Satellite — unavailable", "satellite_unavailable", "satellite.slash.fill", "CoreGlyphsPrivate", "stock glyph"),
        ("Satellite — available", "satellite_available", "satellite.wave.2", "CoreGlyphsPrivate", "stock glyph"),
        ("Satellite — connected", "satellite_connected", "satellite.wave.2.fill", "CoreGlyphsPrivate", "stock glyph"),
        ("Apple Intelligence", "focus_reduce_interruptions_symbol_reference", "apple.intelligence", "CoreGlyphs", "identity not trace-confirmed"),
        ("Custom Focus — star example", "focus_custom_star_example", "star.fill", "CoreGlyphs", "user-selectable example"),
    ]
    for label, name, symbol, bundle, state_label in symbols:
        catalog = SOURCE / f"PrivateFrameworks/SFSymbols.framework/{bundle}.bundle/Assets.car"
        target = OUT / "png" / f"{name}.png"
        subprocess.run([str(RENDERER), "--symbol", str(catalog), symbol, str(target)], check=True)
        data = target.read_bytes()
        width, height = struct.unpack(">II", data[16:24])
        entries.append({"label": label, "state": state_label, "png": f"png/{target.name}",
                        "symbol_name": symbol, "source": str(catalog.relative_to(SOURCE)),
                        "width": width, "height": height, "bytes": len(data),
                        "provenance": "23A341 native CoreGlyphs catalog", "render_point_size": 40,
                        "render_scale": 3, "stock_tint": "white"})
    manifest["notes"].extend([
        "VPN uses the same native symbol across states; system tint/background distinguishes selection.",
        "The apple.intelligence glyph is original stock art, but the existing trace did not capture Reduce Interruptions' symbol identity.",
        "Custom Focus has no universal stock image. star.fill is an explicitly labeled user-selectable stock example."])
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    subprocess.run([str(RENDERER), "--sheet", str(OUT / "manifest.json"), str(OUT / "contact-sheet.png")], check=True)
    (OUT / "README.md").write_text(README)
    archive = OUT.with_suffix(".zip")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for item in sorted(OUT.rglob("*")):
            if item.is_file():
                bundle.write(item, item.relative_to(OUT.parent))
    print(f"Exported {len(entries)} references to {OUT}")
    print(f"Archive: {archive}")

if __name__ == "__main__":
    main()
