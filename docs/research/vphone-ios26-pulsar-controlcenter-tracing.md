# iOS 26 Pulsar Control Center tracing

Status: active on iOS 26.0 (`23A341`, `iPhone17,3`). This work targets Phuc
Do's Pulsar Control Center UI v2.0 (`com.dobabaophuc.pulsarCC`) from the
[archived Misaka repository](https://github.com/dobabaophuc1706/misakarepo).
This document is limited to Control Center delivery routes.

## Source-package model

Pulsar v2 has two Control Center asset routes:

- per-module `Assets.car` replacements for static glyphs;
- `.ca/main.caml` replacements for animated and stateful glyphs.

The old payload is a source-art and behavior reference. Its iOS 15/16 CAR and
CAML files must not be copied onto iOS 26 without proving the current bundle,
catalog, package, state, and owning-controller routes.

The official v2.0 payload was recovered from upstream commit `bd13799`. At
that revision, `com.dobabaophuc.pulsarcc2.0.misaka` is a legacy encrypted ZIP
with SHA-256
`2acdf365649ff1fb94bbc73201be4ce1df4ae902c5adfa1a90dfd016369d66aa`.
A later repository commit re-encoded the same release into Misaka's serialized
form, which is why the current raw download does not identify as ZIP. The
original encrypted archive was opened with a known-plaintext recovery against
an unchanged upstream CAML member; no artwork was inferred from screenshots or
substituted from the separate DuoTone package.

`scripts/extract_pulsar_controlcenter_assets.py` stages the extracted payload
as generated build data and writes a hash-checked manifest. The current output
is `build/pulsar-controlcenter-v2-assets/manifest.json`. It inventories eight
raw Wi-Fi/Bluetooth PNGs, four Wi-Fi/Bluetooth CAML variants, and these nine
`ConnectivityModule.bundle/Assets.car` renditions:

```text
AirDropGlyph
AirplaneGlyph
CellularDataGlyph
HotspotGlyph
WiFiHotspotGlyph
WiFiSecureGlyph
WiFiSignalHighGlyph
WiFiSignalLowGlyph
WiFiSignalMediumGlyph
```

The staged connectivity catalog SHA-256 is
`c1d55de21aface3bb631f5819b4838e211ec0b883fffffba802e3af314e3f4d2`.
The first canary selects `wifi_white.png`, `bluetooth_white.png`,
`AirplaneGlyph`, and `CellularDataGlyph` from this manifest. The extended
canary additionally selects `AirDropGlyph`, `HotspotGlyph`, and the two
motion-enabled Wi-Fi/Bluetooth CAML documents. The manifest explicitly records
VPN and Satellite as source gaps because Pulsar v2.0 contains no dedicated
rendition or CAML package for either control.

The canonical static catalog families are:

```text
AccessibilityGuidedAccessControlCenterModule
AccessibilityShorcutsModule
AccessibilitySoundDetectionControlCenterModule
AccessibilityTextSizeModule
AlarmModule
CalculatorModule
CameraModule
ConnectivityModule
DisplayModule
FlashlightModule
MagnifierModule
NFCControlCenterModule
PerformanceTraceModule
QRCodeModule
StopwatchModule
TVRemoteModule
VoiceMemosModule
WalletModule
```

The canonical Control Center CAML targets are:

```text
AppearanceModule/StyleMode.ca
ConnectivityModule/Bluetooth.ca
ConnectivityModule/WiFi.ca
DisplayModule/Brightness.ca
HearingAidsModule/HAE_1_x_1.ca
LowPowerModule/LowPower.ca
MuteModule/Mute.ca
OrientationLockModule/OrientationLock.ca
ReplayKitModule/replaykit.ca
ShazamModule/Shazam.ca
AirPlayMirroringModule/MPAVScreenMirroring.ca
```

## Trace design

`scripts/lab/cnd_pulsar_controlcenter_trace.m` is a bounded, VM-only,
process-local tracer. It preserves normal execution while recording:

- `UIImage` named catalog and system-symbol lookups;
- `NSBundle` `.ca`/`.caml` resource resolution;
- `CAPackage packageWithContentsOfURL:type:options:error:` loads;
- `CCUICAPackageDescription` construction;
- CCUI glyph, package-description, icon, and state setters;
- focused `CCUI`, `CHUI`, and `CHS` class inventories;
- visible Control Center controller and image-view ownership.

It never replaces a catalog, writes a system path, changes a control state, or
invokes a private presentation API. Wrappers and logging vanish with the
SpringBoard process. Recording stops automatically after the configured
30–600 second window.

## VM procedure

Build and run the offline contracts first:

```sh
python3 -m unittest scripts.tests.test_pulsar_controlcenter_trace
python3 scripts/lab/cnd_pulsar_controlcenter_trace.py build
```

After the iOS 26 vPhone has booted and root SSH is forwarded on port 22222:

```sh
export CND_VPHONE_ROOT_PASSWORD='...'
python3 scripts/lab/cnd_pulsar_controlcenter_trace.py inject \
  --host VM_ADDRESS --duration 180
```

Add markers immediately before each interaction phase. Exercise the compact
page, expanded Connectivity, brightness, volume, media, Focus, mirroring,
stateful toggles, edit/gallery mode, and a close/reopen cycle. Then capture
before stopping the VM:

```sh
python3 scripts/lab/cnd_pulsar_controlcenter_trace.py capture-summary \
  --host VM_ADDRESS
```

## Acceptance gate

A useful first capture must contain `TRACE_READY`, at least one live
Control Center controller, at least one catalog/symbol lookup or CAML package
load, state transitions for a stateful module, and `TRACE_COMPLETE` unless the
capture is explicitly labeled partial. The resulting evidence becomes a
module-by-module matrix:

```text
Pulsar v2 target
  -> iOS 26 bundle/path
  -> asset or package name
  -> runtime owner
  -> state variants
  -> porting decision
```

No CAR/CAML overwrite starts until one static canary and one stateful canary
have exact stock hashes, durable backups, candidate validation, readback
verification, and a tested restore path.

## First live capture (2026-10-04)

The first bounded run completed on the iOS 26.0 (`23A341`, `iPhone17,3`)
vPhone after exercising the compact Control Center and stateful controls. The
local evidence is
`build/lab-pulsar-controlcenter-trace/cyanide-pulsar-controlcenter-trace.log`
(164,490 bytes; SHA-256
`f2dc61fbca281aade2ab21a27735cd7756de399e98c02ff9a644606528119a01`).
It reached `TRACE_COMPLETE` after 300 ticks with 30 installed hooks and 121
events. The final snapshots consistently contained 12 windows and 738 views.

Observed module identities include:

```text
com.apple.control-center.ConnectivityModule
com.apple.control-center.DisplayModule
com.apple.control-center.MuteModule
com.apple.control-center.OrientationLockModule
com.apple.FocusUIModule
com.apple.mediaremote.controlcenter.airplaymirroring
com.apple.mediaremote.controlcenter.audio
com.apple.mediaremote.controlcenter.nowplaying
com.apple.mobiletimer.controlcenter.timer
```

Three additional controls used UUID module identifiers and were hosted by
`CCUIControlHostViewController`. This is a distinct iOS 26 delivery route that
does not map directly to Pulsar's old per-module bundle names.

The strongest first-pass route findings are:

- volume loads
  `/System/Library/PrivateFrameworks/MediaControls.framework/VolumeSemibold.ca`
  as `com.apple.coreanimation-bundle`, resolved by the
  `com.apple.MediaControls` bundle;
- Orientation Lock retains the module identity above, exposes `unlocked` and
  `locked` glyph states, and looks up the `lock.rotation` system symbol;
- Mute retains its module identity, exposes `ringer` and `silent` glyph
  states, and looks up `bell.slash.fill`;
- `CCUICAPackageView` exposed `mid` and `light` state names, while a modern
  `CCUIControlTemplateView` exposed an `off` glyph state;
- the expanded connectivity graph delivered AirDrop, Wi-Fi, Bluetooth, VPN,
  and Satellite images through `setGlyphImage:` receivers;
- the old names `ConnectivityModule` and `DisplayModule` correlate with live
  iOS 26 module identities, but this capture did not prove an iOS 26 lookup of
  their old `Assets.car` entries;
- none of Pulsar's old logical CAML target paths appeared exactly. In
  particular, the live volume package is a MediaControls framework asset, not
  Pulsar's old `DisplayModule/Brightness.ca` route.

This cleared the broad discovery gate, not the replacement gate. The focused
capture below proceeds with the connectivity family because it provides both
static and stateful canary routes.

## Focused connectivity capture (2026-10-04)

The follow-up trace ran for 360 seconds with 62 hooks and 48 runtime events.
Its report is
`build/lab-pulsar-controlcenter-trace/cyanide-pulsar-connectivity-trace.log`
(469,190 bytes; SHA-256
`6ff429e535988a426b2ef03aa21dcc976da7a7a351d6bb7122dc7d4f9732c1dd`).
Eight PNG files representing six unique stock glyph fingerprints were copied
to `build/lab-pulsar-controlcenter-trace/connectivity-assets/`. All exports
are from the VM's temporary directory and are private mode `0600` locally.

The expanded connectivity panel exposed Airplane Mode, Wi-Fi, AirDrop,
Bluetooth, and VPN. Cellular did not instantiate as a tile, although its iOS
26 controller classes are loaded. Satellite was observed by the broad trace
but did not materialize in the expanded panel.

| Control | Runtime route | Observed stock evidence | Port consequence |
| --- | --- | --- | --- |
| Airplane Mode | `CCUIConnectivityAirplaneViewController` and system symbol `airplane` | One 28×40-point template image, SHA-256 `f1c4ed9a…`, for both `isEnabled=0` and `isEnabled=1` | The selected color is external state/tint; do not build separate on/off artwork. |
| Wi-Fi off | `CCUIWiFiModuleViewController` | 27.67×25.67-point image, SHA-256 `ddb6c2dc…` | This is a distinct state image, not merely a tint variation. |
| Wi-Fi on | `CCUIWiFiModuleViewController` plus `WFWiFiStateMonitor` | 27.67×21-point image, SHA-256 `8cd9a3bd…`; `setSelected:` receives `1` | Preserve the integer state mapping and substitute the returned image. |
| AirDrop | `CCUIAirDropModuleViewController` | 26.33×25-point image, SHA-256 `0fb16773…` | The VM proved its static off/receiving-disabled glyph only. |
| Bluetooth | `CCUIBluetoothModuleViewController` | 21.67×26-point image, SHA-256 `b0d912be…` | Bluetooth is unavailable in this VM, so the off glyph is proven but active state requires a device. |
| VPN | `CCUIVPNModuleViewController` | 26×29.67-point image, SHA-256 `d9acb6e0…` | No VPN configuration exists in the VM; only the off route is proven. |
| Satellite | `CCUISatelliteModuleViewController` | 25.33×23.33-point setter image in the broad trace | Needs a separate state/export pass if Pulsar will theme it. |
| Cellular | `CCUIConnectivityCellularDataViewController` is loaded but not instantiated | `_glyphImageForDisplayBars:`, `_updateGlyphImageWithDisplayBars:`, `_toggleState`, and `_debugDescriptionForState:` are present | A VM-only synthetic presentation can prove artwork/layout; real service transitions still require a cellular-capable device. |

The class inventory identifies the more durable interception points:

- Wi-Fi: `_glyphImageForState:currentSignalBars:forceSignalBars:network:`
  `applyConfiguration:` and `_updateGlyphImagesWithState:`;
- Bluetooth: `_glyphImageForState:` and `_updateGlyphImagesWithState:`;
- AirDrop and VPN: `_glyphImage` plus `_updateGlyphImages`;
- Satellite: `_glyphImageForState:` and `_updateGlyphImageWithState:`;
- Airplane Mode: `_updateStateWithEnabled:` with a single template image.

The loaded parent `CCUIConnectivityModuleViewController` also has
`setCellularDataButtonViewController:` and
`setExpandedCellularDataButtonViewController:`. A bounded VM probe can
therefore create a synthetic cellular controller, feed it display-bar values,
and attach it only to the process-local connectivity view hierarchy. Bluetooth
can be handled similarly by overriding its controller state. This is suitable
for previewing and validating Pulsar artwork, but it is not evidence that the
VM has working Bluetooth or cellular service.

These routes make a process-local Pulsar connectivity canary preferable to an
unproven `Assets.car` overwrite. The canary should return Pulsar-derived
template images from the controller-specific glyph methods while leaving
selection tint and state transitions under ControlCenterUIKit's ownership.
Wi-Fi off/on and Airplane Mode off/on are the first acceptance pair; Bluetooth
active, VPN active, and Cellular remain physical-device gates.

## VM-only synthetic Bluetooth and Cellular pass

The bounded presentation probe in
`scripts/lab/cnd_pulsar_synthetic_connectivity_probe.py` and
`scripts/lab/cnd_pulsar_synthetic_connectivity_probe.m` completed against the
same running SpringBoard process (PID 39). It does not load or call telephony or
Bluetooth service frameworks. It asks the already-loaded Control Center
controllers for presentation state, disables interaction on the synthetic
Cellular view, and restores every changed controller pointer, view, Bluetooth
state, and observation flag after 45 seconds.

The native Cellular class has no `initWithContentModuleContext:` initializer on
this build. Its superclass contract is instead
`initWithGlyphImage:highlightColor:` followed by
`setContentModuleContext:`. Initializing through that route bypasses the
hardware-availability gate at the view-controller layer without claiming a
radio or service exists. The resulting controller accepted `NSNumber` values
for `_glyphImageForDisplayBars:` and produced the following stock images:

| Synthetic bars | Stock points | SHA-256 result |
| --- | --- | --- |
| 0 | 25.33×16.67 | `778998ebb4a189b827189991f015bb6513c105975c85d637e405cf795f442153` |
| 1 | 25.33×16.67 | `66f3059825d8a3f485f7f1138da660d834435d85103b6a992bca88cc75d71725` |
| 2 | 25.33×16.67 | `0dc3a5584e9c8bde8e24c7e9beacecf2c85b1149de6c2f9dddec4e69ea415f24` |
| 3 | 25.33×16.67 | `37cab1c746875ae1b1dcc45dcc6fa285c7739deb0fe59e4743f24d8c1ff65526` |
| 4 | 25.33×16.67 | `111335ad0d42823c474aa34dee757c0a9ed8cc081e6c7b8eb6af850737e5f310` |
| 5 | 25.33×16.67 | same as 4 bars |

Bluetooth's private integer state map is now proven rather than inferred:

| State | Runtime description | Subtitle | Glyph result |
| --- | --- | --- | --- |
| 0 | unavailable | Off | slashed Bluetooth, `b0d912be…` |
| 1 | power-off | Off | slashed Bluetooth, `b0d912be…` |
| 2 | disconnected | Not Connected | plain Bluetooth, `c18daf2c…` |
| 3 | connected | On | plain Bluetooth, `c18daf2c…`; enabled tint is external |
| 4 | busy | Searching | plain Bluetooth, `c18daf2c…`; busy state is external |
| 5–7 | unavailable | none | no image |

During the visible phase, state 3 changed the existing Bluetooth tile to its
blue `On` presentation. A real
`CCUIConnectivityCellularDataViewController` rendered the four-bar stock glyph
over the VPN position. The captured visible proof is
`build/lab-pulsar-synthetic-connectivity/synthetic-connectivity-visible.png`.
The paired
`build/lab-pulsar-synthetic-connectivity/synthetic-connectivity-restored.png`
shows Bluetooth back at `Off` and the VPN tile restored. The report records
`RESTORED cellular=1 bluetoothState=1 bluetoothObservation=1` followed by
`COMPLETE status=success`; SpringBoard remained PID 39.

Eleven state-specific PNGs were copied to
`build/lab-pulsar-synthetic-connectivity/assets/`. There are seven unique
fingerprints: two Bluetooth shapes and five Cellular bar levels. The full run
report is
`build/lab-pulsar-synthetic-connectivity/cyanide-pulsar-synthetic-connectivity.log`
(SHA-256 `85c9be50c98a1acf8867efe5c8f4ccc146d93b1e7121990c77dd9aa5da06bd92`).
These results remove Bluetooth and Cellular artwork/state mapping as VM gates;
only real radio behavior remains a physical-device validation item.

## Official Pulsar connectivity canary

`scripts/lab/cnd_pulsar_connectivity_canary.py` stages only the four selected
official assets under a nonce-scoped `/var/tmp` directory and injects the same
bounded process-local probe into the identity-checked SpringBoard PID. The old
iOS 15 catalog is loaded as a temporary standalone bundle; it is never copied
over an iOS 26 system catalog. Wi-Fi and Bluetooth use the traced
`CCUIButtonModuleViewController` glyph properties. Airplane uses the visible
`CCUIConnectivityAirplaneViewController` single-glyph setter. Cellular uses
the traced inner image view of a noninteractive synthetic controller mounted
over the otherwise unavailable VPN position.

The successful 30-second run remained in SpringBoard PID 39 and recorded all
four source assets as present. It spoofed Bluetooth presentation state 3
(`connected` / `On`) and a synthetic four-bar Cellular presentation without
calling a Bluetooth, CoreTelephony, or CommCenter service. The local evidence
is:

```text
build/lab-pulsar-connectivity-canary/cyanide-pulsar-connectivity-canary.log
  SHA-256 18875a41432c14b2077abfbec789c177a985efb5e5cc78de4b182a8fd2b0b13c

build/lab-pulsar-connectivity-canary/pulsar-connectivity-visible.png
  SHA-256 55d9cf274138c1d1e454eb207bbbb12216d754f2a9d0bae9a2120276cfadaccd

build/lab-pulsar-connectivity-canary/pulsar-connectivity-restored.png
  SHA-256 e90234f0452ff6891e059a2ea9e6932fc29f6c9f7e55e9fdd5d3d5489148184e
```

The report reached `VISIBLE_READY` with `themeApplied=1`, followed by
`RESTORED` and `COMPLETE status=success`. The restored screenshot proves the
stock Airplane, Wi-Fi, Bluetooth-off, and VPN presentation returned after the
hold. An early refused iteration exposed and corrected a canary-only Airplane
restore bug: restoration now seeds the stock `airplane` system image when the
controller's property is empty and invokes the controller's own `_updateState`
after replacing the original image.

This clears the first static process-local canary gate for Wi-Fi, Bluetooth,
Airplane, and synthetic Cellular. It does not clear persistent installation.

## Extended AirDrop, Hotspot, and motion pass

`scripts/lab/cnd_pulsar_extended_connectivity_canary.py` extends the same
identity-checked, automatically restored VM probe without installing anything.
The final 30-second run resolved this live iOS 26 graph:

```text
AirDrop controller     CCUIAirDropModuleViewController
Wi-Fi expanded view    CCUIControlTemplateView
Bluetooth expanded view CCUIControlTemplateView
AirDrop expanded view  CCUIControlTemplateView
Hotspot controller     absent
VPN controller         CCUIVPNModuleViewController
Satellite controller   CCUISatelliteModuleViewController
```

AirDrop received official `AirDropGlyph` artwork at both its controller and
expanded-template layers. Because the VM has no Hotspot controller, the probe
used the same noninteractive synthetic
`CCUIConnectivityCellularDataViewController` presentation host as the Cellular
pass and substituted official `HotspotGlyph` artwork. This is a visual canary,
not a claim that Personal Hotspot or a cellular radio exists. VPN and Satellite
were left stock: the report records
`SOURCE_GAP vpn=1 satellite=1 reason=no-official-pulsar-v2-art` rather than
inventing replacements.

The old motion documents required two compatibility adaptations in the
nonce-scoped staging directory only:

- their absolute `/var/mobile/Documents/PhucDo/PhucDoUI` image references were
  rewritten to the temporary asset directory, and their absent `wifi.png` and
  `bluetooth.png` references were mapped to Pulsar's official
  `wifi_white.png` and `bluetooth_white.png` files;
- iOS 26 `CAPackage` requires a `.ca/index.xml` package plist whose
  `rootDocument` is `main.caml`. Pulsar v2 supplies the legacy `main.caml`
  replacement but no standalone package wrapper, so the probe generated the
  wrapper while preserving the upstream CAML bytes and hashes.

Both packages then loaded successfully as
`com.apple.coreanimation-bundle`. Both `CCUICAPackageDescription` objects
resolved the expected temporary `.ca` URLs. Assigning those descriptions and
the upstream `poweroff` state to the controller objects succeeded but did not
change the already-materialized expanded tiles. Assigning the same values to
the traced live `CCUIControlTemplateView` consumers produced visible animated
Pulsar Wi-Fi and Bluetooth glyphs. The two captures one second apart have
different hashes:

```text
build/lab-pulsar-extended-connectivity-canary/
  cyanide-pulsar-extended-connectivity-canary.log
    SHA-256 341344d3537a27ce34c7d02bd9df824191c782c26f267b63e26161aa36b59cd8

  pulsar-extended-frame-a.png
    SHA-256 2dae88447462d1d1f529ce622a72c28d60c0537d33c144cbc8edcde01e3af8d1

  pulsar-extended-frame-b.png
    SHA-256 9102a6a8983a0a3123f1004ce9a4afd9ec198d6c6e79a35e90a81770a8e83da1

  pulsar-extended-restored.png
    SHA-256 e90234f0452ff6891e059a2ea9e6932fc29f6c9f7e55e9fdd5d3d5489148184e
```

The report records `motionLoaded=1 motionPresented=1`, restores both template
views' original nil package descriptions and glyph states, restarts every
observation route that the probe stopped, removes the synthetic Hotspot host,
and finishes with `COMPLETE status=success`. The restored screenshot's hash is
identical to the earlier known-stock canary, providing an independent visual
restoration check. SpringBoard remained PID 39 throughout.

This clears the process-local static and animated presentation gates for the
Pulsar connectivity family that actually has upstream artwork. The next design
step is a durable, version-gated delivery mechanism for Airplane, AirDrop,
Hotspot, Wi-Fi, and Bluetooth. VPN and Satellite should remain untouched until
the source theme provides intentional assets or the product defines an
explicit fallback policy.

## Low Power, Screen Recording, and Flashlight admission pass

The iOS 26 control gallery would enter edit mode but dismiss Control Center
instead of presenting the picker. The VM-only helper
`scripts/lab/cnd_vm_controlcenter_config.py` therefore updates the same
mobile-owned layout files that SpringBoard uses:

```text
/var/mobile/Library/ControlCenter/ControlsIconState.plist
/var/mobile/Library/ControlCenter/ModuleConfiguration.plist
```

It first checks that the SSH guest identifies as a VPHONE/VRESEARCH target,
parses both plists, admits only the three allowlisted module identifiers, makes
timestamped adjacent backups, verifies staged SHA-256 digests, atomically
installs both files, and restarts an identity-checked SpringBoard process. The
mutation is idempotent and uses stable UUIDs. The applied backup set is:

```text
/var/mobile/Library/ControlCenter/ControlsIconState.plist.cyanide-backup-20261005T022056Z
/var/mobile/Library/ControlCenter/ModuleConfiguration.plist.cyanide-backup-20261005T022056Z
```

Low Power Mode and Screen Recording then instantiated as genuine native
controls. The focused trace proved these routes:

| Control | Saved module identifier | Live controller and surface | Pulsar v2 source |
| --- | --- | --- | --- |
| Low Power Mode | `com.apple.control-center.LowPowerModule` | `CCUILowPowerModuleViewController` → 73×73 `CCUIControlTemplateView` → `CCUICAPackageView`; observed `disabled` state | `LowPowerModule/LowPower.ca` |
| Screen Recording | `com.apple.replaykit.controlcenter.screencapture` | `RPControlCenterMenuModuleViewController` → 73×73 `CCUIControlTemplateView`; observed `Base State` | `ReplayKitModule/replaykit.ca` and optional `replaykit-v2.ca` |
| Flashlight | `com.apple.control-center.FlashlightModule` | filtered by virtual hardware before a native controller is created | `FlashlightModule.bundle/Assets.car`, renditions `FlashlightOff` and `FlashlightOn` |

Apple's Flashlight bundle declares `camera-flash` in
`UIRequiredDeviceCapabilities`. The layout request was initially accepted and
its legacy module registration remains present, but the vPhone does not
advertise that capability. When Control Center materialized the page,
SpringBoard omitted the fourth-row item and pruned its icon-state entry. The
system volume is read-only; an attempted staged write failed before changing
or backing up the system bundle. The lab deliberately does not patch the
bundle, forge a MobileGestalt answer, or invoke torch APIs.

For visual tracing only,
`scripts/lab/cnd_vm_flashlight_control_probe.py` mounts a noninteractive
`CCUIButtonModuleViewController` in the real empty fourth grid slot at
`{{311, 578.667}, {73, 73}}`. The control contains a live
`CCUIControlTemplateView`, is labeled as a VM synthetic target, makes no system
write or hardware claim, and removes itself automatically after the bounded
hold. This supplies the iOS 26 presentation consumer needed to validate the
official `FlashlightOff` and `FlashlightOn` renditions without pretending the
VM has a torch.

The combined visual proof is
`build/vm-cc-lowpower-screenrecord-flashlight-final.png` (SHA-256
`7c2101b27fe796dcbee5346aa7aec9de724c118051f7588a9bdf7faee9b2ff2d`).
The focused trace is
`build/lab-pulsar-controlcenter-trace/cyanide-pulsar-controlcenter-trace.log`
(SHA-256
`ade1fa13241768c74a3d51a600a69b97e2764c158f960096d48fc92698f0c560`).
It records both native module identifiers plus the synthetic
`CCUIButtonModuleViewController` and its 73×73 template view.

The synthetic probe's own report is
`build/lab-vm-flashlight-control/cyanide-vm-flashlight-control.log`
(SHA-256
`ea4f680d480a7dd36efd42637d686dc06d2d440e7a6f676291b4fcec8f8a3923`).
It ends with `RESTORED mounted=1` and `COMPLETE status=success`. The post-hold
capture `build/vm-cc-flashlight-restored.png` (SHA-256
`06931e59dda4f1a044aa43277a97c7f7d669664d30d68efb02bf19fdbfdf4ce9`)
shows that native Low Power Mode and Screen Recording remain while the
synthetic fourth-slot control is gone.

### Official Pulsar additional-controls canary

`scripts/extract_pulsar_controlcenter_assets.py` now preserves the additional
upstream material needed for this pass alongside the existing connectivity
artifacts:

- both Low Power CAML variants and their `pin_*` PNG dependencies;
- both byte-identical ReplayKit CAML variants and their five PNG dependencies;
- the untouched Pulsar v2 Flashlight `Assets.car` plus an `assetutil`
  inventory proving the presence of the legacy `FlashlightOff` and
  `FlashlightOn` theme renditions. They are not renditions in the iOS 26
  Flashlight bundle.

The generated manifest is
`build/pulsar-controlcenter-v2-assets/manifest.json` (SHA-256
`183a2a4dbd04869a3a760b02a6b6968ec7d5a3fc7eee5f5adcb043ae744d4998`).
The Flashlight catalog retains its upstream SHA-256
`8fbef7ecdcb53f54eca3e6269136f1082dfe8f432a6bc95fa8a7dbc3685d5f2a`.

`scripts/lab/cnd_pulsar_additional_controls_canary.py` stages those assets in
a nonce-scoped `/var/tmp` directory and generates only the `.ca/index.xml`
wrappers needed by iOS 26. Absolute image paths in the staged CAML copies are
rewritten to that temporary directory. It validates both packages through
`CAPackage`, constructs `CCUICAPackageDescription` objects whose URLs must
match the staged `LowPower.ca` and `ReplayKit.ca` directories, and applies
them only to the traced live `CCUIControlTemplateView` consumers. Both are
held in the upstream inactive `disabled` state. The synthetic Flashlight
control receives `FlashlightOff` and `FlashlightOn` from the Pulsar v2 catalog,
remains noninteractive, and is removed at restoration.

An initial compatibility attempt assigned the package descriptions to the
module controller objects. Both packages and descriptions validated, but the
first setter crossed an unsafe iOS 26 boundary and SpringBoard restarted from
PID 3269 to PID 3481. The attempt invoked no control action and made no system
write. The canary was corrected to require and target the descendant
`CCUIControlTemplateView` objects, matching the already proven connectivity
route. The successful retry remained in PID 3481 for its complete lifecycle.

The final report records:

```text
TARGET lowPower=.../CCUIControlTemplateView replayKit=.../CCUIControlTemplateView
PACKAGE name=LowPower loaded=1
PACKAGE name=ReplayKit loaded=1
APPLY ... safeState=disabled originalState=disabled
APPLY ... safeState=disabled originalState=Base State
FLASHLIGHT mounted=1 ... offPoints=15.00x48.00 onPoints=15.00x48.00
VISIBLE_READY ... themeApplied=1 ... controlActions=0 hardwareSpoof=0
RESTORED lowPower=1 replayKit=1 flashlight=1 noSystemWrite=1
COMPLETE status=success ... controlActions=0 hardwareSpoof=0
```

The preserved evidence is:

```text
build/lab-pulsar-additional-controls-canary/
  cyanide-pulsar-additional-controls.log
    SHA-256 913d9530ffd4c8f060d1cc3a066c271eea66838a77810a48e756660701d430aa

  pulsar-additional-controls-visible.png
    SHA-256 5715db95dd3111043fad7c07414d7e6a0ad1349ff63423c1477b3f2a56d3bf3a

  pulsar-additional-controls-restored.png
    SHA-256 1708cb71520f58c0815f501d7a929c62c49f56f7e349e961811a04cdadb2c56c
```

The visible capture shows the official Pulsar Low Power artwork, inactive
ReplayKit `REC` artwork, and official Flashlight artwork in the fourth row.
The restored capture shows the stock Low Power and Screen Recording glyphs
and an empty fourth slot. This clears the process-local presentation gate for
all three controls. It does not install a persistent theme, start recording,
toggle Low Power Mode, emulate torch hardware, or claim Flashlight function.

## Close/reopen persistence mapping

The connectivity-focused trace was repeated across an actual Control Center
teardown rather than only an expanded/compact transition. A hardware Home
event first collapsed expanded Connectivity. A second Home event removed the
Control Center window (`windows=12` to `11`, `views=762` to `508`). Reopening
Control Center returned to `windows=12` and `views=760`.

The compact connectivity module controller and its Wi-Fi/Bluetooth image
views retained their object identities across that teardown. The Airplane
presentation instead received another native `setEnabled:` delivery, and its
expanded child uses a distinct controller. Wi-Fi, Bluetooth, and AirDrop use
the common exact-ABI `CCUIButtonModuleViewController setGlyphImage:` route.
This proves that captured addresses are useful for seeding currently
materialized controls but are not the durable ownership boundary: native
glyph/package delivery must be intercepted and classified when it occurs.

The captured evidence is:

```text
build/lab-pulsar-controlcenter-trace/
  cyanide-pulsar-connectivity-trace.log
    SHA-256 7a25e2c4f6aa2574885696e9f4e31b4c6fe59b1e7e0be982afd0c764708a289c
```

`scripts/lab/cnd_pulsar_connectivity_persistence_canary.py` exercises that
route without a timer-based mutation loop. Its bounded dylib replaces four
exact Objective-C delivery methods, seeds the already-materialized
connectivity receivers once, then lets native state/lifecycle delivery drive
all subsequent substitutions. The driver performs two real closes, two
reopens, one Connectivity expansion, and one collapse. It never invokes a
control action or radio setter.

The final run remained in SpringBoard PID 39. Every verification reported
`found=5 themed=5`: Wi-Fi, Bluetooth, AirDrop, compact Airplane, and expanded
Airplane. The Airplane `setEnabled:` replacement fired after each reopen,
demonstrating event-driven reapplication rather than survival by observation
timing. Restoration verified all four original method implementations and
all five captured stock objects by exact getter readback:

```text
build/lab-pulsar-connectivity-persistence/
  cyanide-pulsar-connectivity-persistence.log
    SHA-256 5c1df8dd9a1da159b8475f02c488764737330de07156592563edf9db72f6df67

RESTORED methods=1 objects=5 objectReadback=1 hookHits=10 newReceivers=0
COMPLETE status=success ... controlActions=0 radioWrites=0 targetFileWrites=0
```

The VM has no real cellular or Personal Hotspot controller, so this proves the
shared delivery mechanism and exact class mappings but not hardware-backed
cellular/hotspot instantiation. Their classes and getter edges remain covered
by the physical inventory and must receive the same device-side canary before
the durable installer is declared production-complete.

## Definitive iOS 26 disk-to-display map

The following map supersedes assumptions made from the legacy Pulsar file
layout. It combines the exact iOS 26.0 (`23A341`, `iPhone17,3`) dyld images,
the mounted VM filesystem, static call-site disassembly, and the live
SpringBoard view/controller trace. A path marked *secondary* is real, but is
not the source of the visible compact or expanded button.

### Connectivity

| Control | File on disk | Construction and state | Visible consumer |
| --- | --- | --- | --- |
| Airplane | `ConnectivityModule.bundle/Assets.car`, rendition `AirplaneGlyph` (`airplane-40.pdf`) | `CCUIConnectivityAirplaneViewController -init` calls `imageNamed:inBundle:` and passes the image to `initWithGlyphImage:highlightColor:`; `RadiosPreferences` drives `setEnabled:` | Compact and expanded connectivity round buttons |
| Wi-Fi | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car`; names `wifi.slash`, `wifi`, and `wifi.badge.lock` | `CCUIWiFiModuleViewController _glyphImageForState:currentSignalBars:forceSignalBars:network:applyConfiguration:` calls `_systemImageNamed:variableValue:withConfiguration:`; `WFControlCenterStateMonitor` supplies state and signal bars | `CCUIRoundButton` when collapsed; `CCUIControlTemplateView`/round-button glyph when expanded |
| Bluetooth | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car`; names `bluetooth.slash` and `bluetooth` | `CCUIBluetoothModuleViewController _glyphImageForState:` selects the name for states 0–4 and calls `_systemImageNamed:withConfiguration:`; `BluetoothManager` drives updates | Same compact/expanded CCUI consumers as Wi-Fi |
| Cellular data button | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car`; variable symbol `cellularbars` | `CCUIConnectivityCellularDataViewController _glyphImageForDisplayBars:` converts the display-bars number to a 0–1 variable value, calls `systemImageNamed:variableValue:withConfiguration:`, then `_updateGlyphImageWithDisplayBars:` delivers it through inherited `setGlyphImage:` | Compact and expanded cellular-data round buttons |
| Cellular menu/gallery icon (*secondary*) | `ConnectivityModule.bundle/Assets.car`, rendition `CellularDataGlyph` (`cellular-40.pdf`) | `CCUIConnectivityCellularModuleViewController` obtains `CellularDataGlyph` with `imageNamed:inBundle:` and calls `setGlyphImage:` | Cellular plan/menu-module or gallery presentation; not the live cellular-data toggle glyph |
| Personal Hotspot button | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car`; names `personalhotspot` and `personalhotspot.slash` | `CCUIConnectivityHotspotViewController _glyphImageForCurrentState` selects between those names, calls the system-image constructor, and is driven by `WFPersonalHotspotStateMonitor`, discoverability, and connection count | Compact/expanded Hotspot button |
| Personal Hotspot preview (*secondary*) | `ConnectivityModule.bundle/Assets.car`, rendition `HotspotGlyph` (`hotspot-40.pdf`) | Catalog-backed preview/gallery artwork | Preview/gallery surface; this explains why the preview could be themed while the menu button remained stock |
| AirDrop | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car`; name `airdrop` | `CCUIAirDropModuleViewController _glyphImage` calls `_systemImageNamed:withConfiguration:`; `SFAirDropDiscoveryController` drives `_updateGlyphImages` | Collapsed round button and expanded control template |
| VPN | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car`; name `network.connected.to.line.below.fill` | `CCUIVPNModuleViewController _glyphImage` calls `_systemImageNamed:withConfiguration:` | Connectivity round/template view |
| Satellite | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car`; names `satellite.slash.fill`, `satellite.wave.2`, and `satellite.wave.2.fill` | `CCUISatelliteModuleViewController _glyphImageForState:` feeds `_updateGlyphImageWithState:` | Connectivity round/template view |

`/System/Library/CoreServices/CoreGlyphs.bundle` is a symlink to
`/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphs.bundle` on
this build. The active Wi-Fi and Bluetooth controllers live in
`/System/Library/PrivateFrameworks/ControlCenterUI.framework/ControlCenterUI`.
Airplane, Cellular, and Hotspot live in the dyld-cached
`ConnectivityModule.bundle/ConnectivityModule` image.

This corrects the earlier Cellular assumption: `CellularDataGlyph` is not the
normal cellular toggle. The normal toggle is the variable `cellularbars`
system symbol. It also proves why the old Pulsar `WiFi.ca` and `Bluetooth.ca`
paths cannot be durable iOS 26 sources: neither package exists in the current
Connectivity bundle.

### Flashlight and bottom-row controls

| Control | File on disk | Construction and state | Visible consumer |
| --- | --- | --- | --- |
| Flashlight | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car`; `flashlight.off.fill` and `flashlight.on.fill` | `FlashlightModule -contentViewControllerForContext:` constructs `CCUIFlashlightModuleViewController`, calls `systemImageNamed:` twice, then `setGlyphImage:` and `setSelectedGlyphImage:`; `SBUIFlashlightController`/`SBUIFlashlightObserver` supplies availability and level | `CCUIControlTemplateView` with normal and selected `UIImage` glyphs |
| Timer | `TimerModule.bundle/Timer.ca` or `Timer_IC.ca` | `MTCCTimerViewController` supplies a `CCUICAPackageDescription` and timer state | `CCUIControlTemplateView` → `CCUICAPackageView` |
| Calculator | `SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car`; `calculator.fill` / `calculator.fill.svg` | WidgetKit identity `com.apple.calculator.CalculatorWidget.control` → `CHUISControlInstanceButton.viewModel.icon` → CoreUI vector glyph | `CCUIControlHostView` → `CHUISControlInstanceButton` → `CHUISControlIconView` |
| Camera | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car`; `camera.fill` / `camera.fill.svg` | WidgetKit identity `com.apple.camera.deeplink.button` follows the same hosted-control/view-model route | `CCUIControlHostView` → `CHUISControlInstanceButton` → `CHUISControlIconView` |
| Code Scanner | `Applications/BarcodeScanner.app/PlugIns/BarcodeScannerWidgetExtension.appex/BarcodeScannerWidgetExtension`; the extension declares `qrcode.viewfinder`, which resolves through CoreGlyphs | WidgetKit identity `com.apple.BarcodeScanner.button` → ChronoUIServices control instance | `CHUISControlInstanceButton` → `CHUISControlIconView` inside the CCUI host/template chain |

The iOS 26 `FlashlightModule.bundle` contains only metadata and localization;
there is no `Assets.car`. The old Pulsar Flashlight catalog can be used as
source art, but overwriting that old path cannot affect the iOS 26 button.
`SpringBoard.framework/Flashlight-Dynamic.ca` is a different flashlight UI and
is not the Control Center button.

The legacy `CalculatorModule.bundle/Assets.car`,
`CameraModule.bundle/Assets.car`, and `QRCodeModule.bundle/Assets.car` still
exist. They are not ancestors of the visible controls above. The active
Calculator, Camera, and Code Scanner controls are hosted WidgetKit controls,
which is why replacing or suppressing the old module glyphs did nothing. QR's
extension-to-symbol chain is complete. The Calculator and Camera extension
executables remain absent from the mounted system and App Cryptex, but that no
longer blocks source attribution: the already-materialized hosted view models
expose their exact `UIImage` objects. The focused
`CCCameraCalculatorVM-20261007-06` capture follows those objects through
`_UIImageCUIVectorGlyphContent` and `CUINamedVectorGlyph` to the names and
catalog bundles above. QR is the positive control and reaches the same public
CoreGlyphs catalog as Camera.

### Mirroring, media, brightness, and volume

| Surface | File on disk | Loader/controller | Visible consumer |
| --- | --- | --- | --- |
| Screen Mirroring | `MediaControls.framework/Mirroring.ca` or `Mirroring_IC.ca` (`MirroringLeading.ca` is an additional layout asset) | `MRUMirroringViewController updateGlyphPackageDescription` chooses `Mirroring` or `Mirroring_IC`; `MRUAssetsProvider packageDescriptionWithName:` resolves the MediaControls bundle and creates a `CCUICAPackageDescription` | `CCUIControlTemplateView` → `CCUICAPackageView` |
| Previous / Next | `MediaControls.framework/ForwardBackward.ca` | `MRUAssetsProvider forwardBackwardPackageName` → package description | `MediaControls.NowPlayingTransportControlsView` → `MediaControls.TransportButton` → `MediaControls.PackageView` |
| Play / Pause / Stop | `MediaControls.framework/PlayPauseStop.ca` | `MRUAssetsProvider playPauseStopPackageName` → package description | Center transport button's `MediaControls.PackageView` |
| Volume slider glyph | `MediaControls.framework/VolumeSemibold.ca` on the captured iOS 26 layout; `Volume.ca`, `VolumeRTL.ca`, `VolumeSemiboldRTL.ca`, and `VolumeBold.ca` are other present variants | `MRUVolumeViewController`/MediaControls assets provider | MediaControls volume surface/package view |
| Brightness slider glyph | `DisplayModule.bundle/Brightness.ca` | Display module creates the package description and drives brightness state | `CCUIControlTemplateView` → `CCUICAPackageView` |

The old `AirPlayMirroringModule.bundle/MPAVScreenMirroring.ca` path is gone.
Misaka already carried replacements for
`MediaControls.framework/Mirroring.ca`, `ForwardBackward.ca`,
`PlayPauseStop.ca`, and `Volume.ca`; those are the right framework family on
iOS 26, but a complete current theme must also cover the variants actually
selected by this build, especially `Mirroring_IC.ca`, `VolumeSemibold.ca`, and
their RTL/weight counterparts.

The live trace proves the media hierarchy independently of static analysis:
`MRUMediaControlsModuleViewController` owns
`MediaControls.NowPlayingTransportControlsView`; the Previous, Play, and Next
buttons each own a `MediaControls.PackageView`. Screen Mirroring is owned by
`MRUMirroringViewController` in
`AirPlayMirroringModule.bundle/AirPlayMirroringModule`, while its packages are
loaded from the separate MediaControls framework.

### Other stateful CAML controls

The following current paths still feed a `CCUIControlTemplateView` and
`CCUICAPackageView` and should be replaced as complete state packages, not as
one flattened image:

```text
/System/Library/ControlCenter/Bundles/LowPowerModule.bundle/LowPower.ca
/System/Library/ControlCenter/Bundles/LowPowerModule.bundle/LowPower_IC.ca
/System/Library/ControlCenter/Bundles/MuteModule.bundle/Mute.ca
/System/Library/ControlCenter/Bundles/MuteModule.bundle/Mute_IC.ca
/System/Library/ControlCenter/Bundles/OrientationLockModule.bundle/OrientationLock.ca
/System/Library/ControlCenter/Bundles/OrientationLockModule.bundle/OrientationLock_IC.ca
/System/Library/ControlCenter/Bundles/ReplayKitModule.bundle/replaykit.ca
/System/Library/ControlCenter/Bundles/ReplayKitModule.bundle/replaykit-v2.ca
/System/Library/ControlCenter/Bundles/ReplayKitModule.bundle/replaykit-v2_IC.ca
```

Covering the `_IC` variants is important: replacing only the older package can
appear to work in one layout/state and then revert to stock when Control Center
chooses its alternate package.

### Implementation boundary

The persistent delivery design therefore has four adapters:

1. Catalog substitution only for the active catalog route (`AirplaneGlyph`)
   and explicitly secondary preview/gallery artwork.
2. Controller-scoped image substitution for Wi-Fi, Bluetooth, Cellular,
   Hotspot, AirDrop, VPN, Satellite, and Flashlight. It must intercept native
   glyph delivery and preserve selected/state behavior; captured object
   addresses are only seeds for already-materialized views.
3. Current-path CAML replacement or package-description substitution for
   Mirroring, media transport, brightness, volume, Timer, Low Power, Mute,
   Orientation Lock, and ReplayKit, including the iOS 26 `_IC`, weight, and RTL
   variants.
4. Native CoreGlyphs/CoreGlyphsPrivate catalog replacement for Camera,
   Calculator, and Code Scanner. Their hosted control identities prove the
   consumer linkage; no `CHUISControlIconView` runtime substitution is needed.

The production implementation uses these native disk providers and does not
install a process-local adapter. CoreGlyphs/CoreGlyphsPrivate replacement now
covers the generated-symbol and hosted WidgetKit controls; current-path CAML
and module catalog replacement cover the remaining proven resource families.
One respring is required to reload cached native resources.

The current physical RemoteCall adapter subclasses and pins captured receivers.
An ordinary redraw of those receivers is distinct from page/view reconstruction
that creates new receivers within the same SpringBoard PID. **Trace CC Lifecycle
Owners** captures nonrecursive controller/registry/model/descriptor/provider
routes to investigate stable anchors for that latter goal. It records all
reached controller classes, machine identity, ABI contracts, anchor-to-target
paths, and unresolved reconstruction requirements, while always reporting
`implementationReady: false` and `samePIDPersistenceVerified: false`. Existing
one-time physical apply discovery still walks loaded view descendants. See the
[ownership-route audit](cc-theming-semantic-route-audit.md) for the distinction
and current diagnostic limits.

The [VM lifecycle-owner map](vphone-ios26-controlcenter-lifecycle-owners.md)
records the 2026-10-05 process/module/model routes, dynamically verified Swift
media object slots, direct hosted-control icon routes, and same-PID Focus and
brightness receiver reconstruction. It also distinguishes cached media redraw
from unverified new Swift session/view generations and narrows the remaining
physical-device work.
