# Pulsar Control Center theming research (iOS 26)

Research history behind Pulsar Control Center theming on iOS 26.0 (`23A341`).
VM work used the `iPhone17,3` vPhone (`cyanide-ios26-base`); physical work is
the `kslop` device. Target theme: Phuc Do's Pulsar Control Center UI v2.0
(`com.dobabaophuc.pulsarCC`) from the
[archived Misaka repository](https://github.com/dobabaophuc1706/misakarepo).

The production installer is documented in
[cc-theming-file-backing.md](cc-theming-file-backing.md). This file does not
repeat its resource coverage, catalog proofs, transaction or verification
details.

## Status

**What ships:** production Apply/Restore call only `CNDCCThemingFileBackingApply`
/ `CNDCCThemingFileBackingRestore` — native CAML package and CoreUI catalog
file replacement with a durable journal, one respring to reload. No
SpringBoard RemoteCall session, live-view seed, per-instance persistence
installer, or Runtime/Persistent/Delivery/executable painter remains in the
project. Exact-route and offscreen materialization code remains only for
read-only probes.

**Superseded positions** (stated once here; older notes said otherwise):

- The 2026-10-06 wiring of named lifecycle-owner routes into a production
  RemoteCall Apply resolver, its offscreen preparation phase, and the
  per-instance subclass/pin persistence adapter are no longer the production
  path. They were removed with the painters. Their route evidence below is
  retained as research.
- The ownership-route audit's description of the physical resolver (recursive
  view discovery, label-based classification, per-instance class changes)
  describes that removed Apply path. The diagnostic classifiers
  (`CNDCCSurface` etc.) survive only in `Cyanide/tweaks/CNDCCThemingProbe.m`.
- The four-adapter "implementation boundary" (catalog / controller-scoped image
  / CAML / CoreGlyphs) is realized only by native disk providers; no
  process-local adapter is installed.
- Now Playing AirPlay was first a CoreGlyphsPriority research candidate.
  CoreGlyphsPriority is no longer an installation route; `airplay.audio`
  (media AirPlay) is covered by the base CoreGlyphs file replacement.

| Research route | Finding | Classification |
| --- | --- | --- |
| Legacy Pulsar CAR/CAML paths copied as-is | Most old paths are not iOS 26 consumers (see disk-to-display map) | Rejected |
| VM process-local canaries (connectivity, extended/motion, Low Power / ReplayKit / Flashlight, persistence) | All cleared process-local presentation gates with verified restore | VM-proved, diagnostic-only; never a persistent install |
| Disk-to-display map | Exact iOS 26 file → constructor → consumer routes | Basis for production file-backed coverage |
| VM lifecycle-owner map (2026-10-05) | Named, nonrecursive owner routes; same-PID Focus and Brightness reconstruction re-resolves | VM-proved; production wiring since removed |
| Physical lifecycle-owner / refined CC (rev 3) / refined Focus (rev 4) traces | Read-only physical route captures | Implemented, diagnostic-only; `implementationReady:false`, `samePIDPersistenceVerified:false` |
| Resource-provenance extension | Factory/package-load observer | Implemented and locally verified; no live VM run captured |
| CoreMaterial `modulesBackground.materialrecipe` canary | Redirect/rollback worked; no visible tint | VM-proved plumbing; **rejected** as an iOS 26 feature |
| Now Playing `airplay.audio` | Exact symbol identity captured in VM | Production via base CoreGlyphs; device consumption not verified |

## Pulsar v2 target inventory and acceptance gates

This section is the canonical Misaka v2 target inventory.

### Source package

Pulsar v2 has two CC asset routes: per-module `Assets.car` replacements for
static glyphs, and `.ca/main.caml` replacements for animated/stateful glyphs.
The old iOS 15/16 CAR and CAML files are a source-art and behavior reference
only; they must not be copied onto iOS 26 without proving the current bundle,
catalog, package, state and owning-controller routes.

The official v2.0 payload was recovered from upstream commit `bd13799`, where
`com.dobabaophuc.pulsarcc2.0.misaka` is a legacy encrypted ZIP, SHA-256
`2acdf365649ff1fb94bbc73201be4ce1df4ae902c5adfa1a90dfd016369d66aa`. A later
commit re-encoded the same release into Misaka's serialized form (why the
current raw download is not a ZIP). The archive was opened by known-plaintext
recovery against an unchanged upstream CAML member; no artwork was inferred
from screenshots or substituted from the separate DuoTone package.

`scripts/extract_pulsar_controlcenter_assets.py` stages the payload and writes
a hash-checked manifest at `build/pulsar-controlcenter-v2-assets/manifest.json`
(SHA-256 `183a2a4dbd04869a3a760b02a6b6968ec7d5a3fc7eee5f5adcb043ae744d4998`
after the additional-controls extension). It inventories:

- eight raw Wi-Fi/Bluetooth PNGs and four Wi-Fi/Bluetooth CAML variants;
- nine `ConnectivityModule.bundle/Assets.car` renditions (staged catalog
  SHA-256 `c1d55de21aface3bb631f5819b4838e211ec0b883fffffba802e3af314e3f4d2`):
  `AirDropGlyph`, `AirplaneGlyph`, `CellularDataGlyph`, `HotspotGlyph`,
  `WiFiHotspotGlyph`, `WiFiSecureGlyph`, `WiFiSignalHighGlyph`,
  `WiFiSignalLowGlyph`, `WiFiSignalMediumGlyph`;
- both Low Power CAML variants and their `pin_*` PNG dependencies;
- both byte-identical ReplayKit CAML variants and five PNG dependencies;
- the untouched Pulsar v2 Flashlight `Assets.car` (SHA-256
  `8fbef7ecdcb53f54eca3e6269136f1082dfe8f432a6bc95fa8a7dbc3685d5f2a`) plus
  an `assetutil` inventory proving legacy `FlashlightOff`/`FlashlightOn`
  renditions (not renditions in the iOS 26 Flashlight bundle).

VPN and Satellite are recorded as **source gaps**: Pulsar v2.0 has no
dedicated rendition or CAML package for either.

Canonical legacy static catalog families:

```text
AccessibilityGuidedAccessControlCenterModule  AccessibilityShorcutsModule
AccessibilitySoundDetectionControlCenterModule AccessibilityTextSizeModule
AlarmModule  CalculatorModule  CameraModule  ConnectivityModule  DisplayModule
FlashlightModule  MagnifierModule  NFCControlCenterModule
PerformanceTraceModule  QRCodeModule  StopwatchModule  TVRemoteModule
VoiceMemosModule  WalletModule
```

Canonical legacy CAML targets:

```text
AppearanceModule/StyleMode.ca          ConnectivityModule/Bluetooth.ca
ConnectivityModule/WiFi.ca             DisplayModule/Brightness.ca
HearingAidsModule/HAE_1_x_1.ca         LowPowerModule/LowPower.ca
MuteModule/Mute.ca                     OrientationLockModule/OrientationLock.ca
ReplayKitModule/replaykit.ca           ShazamModule/Shazam.ca
AirPlayMirroringModule/MPAVScreenMirroring.ca
```

### Tracer and acceptance gate

`scripts/lab/cnd_pulsar_controlcenter_trace.m` is a bounded, VM-only,
process-local tracer recording `UIImage` named-catalog and system-symbol
lookups, `NSBundle` `.ca`/`.caml` resolution, `CAPackage
packageWithContentsOfURL:type:options:error:` loads, `CCUICAPackageDescription`
construction, CCUI glyph/package-description/icon/state setters, focused
`CCUI`/`CHUI`/`CHS` class inventories, and visible controller/image-view
ownership. It never replaces a catalog, writes a system path, changes control
state, or invokes a private presentation API; hooks vanish with SpringBoard and
recording stops after a 30–600 s window.

```sh
python3 -m unittest scripts.tests.test_pulsar_controlcenter_trace
python3 scripts/lab/cnd_pulsar_controlcenter_trace.py build
export CND_VPHONE_ROOT_PASSWORD='...'   # root SSH forwarded on port 22222
python3 scripts/lab/cnd_pulsar_controlcenter_trace.py inject --host VM_ADDRESS --duration 180
# add markers before each phase: compact, expanded Connectivity, brightness,
# volume, media, Focus, mirroring, stateful toggles, edit/gallery, close/reopen
python3 scripts/lab/cnd_pulsar_controlcenter_trace.py capture-summary --host VM_ADDRESS
```

**Capture gate:** `TRACE_READY`, at least one live CC controller, at least one
catalog/symbol lookup or CAML load, state transitions for a stateful module,
and `TRACE_COMPLETE` unless explicitly labeled partial. Output is a per-module
matrix: Pulsar v2 target → iOS 26 bundle/path → asset/package name → runtime
owner → state variants → porting decision.

**Replacement gate:** no CAR/CAML overwrite until one static and one stateful
canary have exact stock hashes, durable backups, candidate validation, readback
verification, and a tested restore path.

### First broad capture (VM, 2026-10-04)

`build/lab-pulsar-controlcenter-trace/cyanide-pulsar-controlcenter-trace.log`
(164,490 bytes; SHA-256
`f2dc61fbca281aade2ab21a27735cd7756de399e98c02ff9a644606528119a01`):
`TRACE_COMPLETE` after 300 ticks, 30 hooks, 121 events, 12 windows / 738 views.
Observed module identities: `com.apple.control-center.ConnectivityModule`,
`.DisplayModule`, `.MuteModule`, `.OrientationLockModule`,
`com.apple.FocusUIModule`, `com.apple.mediaremote.controlcenter.airplaymirroring`,
`.audio`, `.nowplaying`, `com.apple.mobiletimer.controlcenter.timer`. Three more
controls used UUID module identifiers hosted by `CCUIControlHostViewController`
— a distinct iOS 26 route with no Pulsar per-module bundle equivalent.

Findings: volume loads `MediaControls.framework/VolumeSemibold.ca` as
`com.apple.coreanimation-bundle` via the `com.apple.MediaControls` bundle;
Orientation Lock exposes `unlocked`/`locked` and looks up `lock.rotation`;
Mute exposes `ringer`/`silent` and looks up `bell.slash.fill`;
`CCUICAPackageView` exposed `mid`/`light`, a `CCUIControlTemplateView` exposed
`off`; expanded connectivity delivered AirDrop/Wi-Fi/Bluetooth/VPN/Satellite
images via `setGlyphImage:`. No old Pulsar CAML path appeared exactly, and old
`ConnectivityModule`/`DisplayModule` `Assets.car` lookups were not proven. This
cleared discovery, not replacement.

### Focused connectivity capture (VM, 2026-10-04)

360 s, 62 hooks, 48 events;
`build/lab-pulsar-controlcenter-trace/cyanide-pulsar-connectivity-trace.log`
(469,190 bytes; SHA-256
`6ff429e535988a426b2ef03aa21dcc976da7a7a351d6bb7122dc7d4f9732c1dd`). Eight
PNGs (six unique stock fingerprints) in
`build/lab-pulsar-controlcenter-trace/connectivity-assets/` (mode `0600`).
Cellular did not instantiate; Satellite did not materialize in the expanded
panel.

| Control | Runtime route | Stock evidence | Consequence |
| --- | --- | --- | --- |
| Airplane | `CCUIConnectivityAirplaneViewController`, symbol `airplane` | one 28×40-pt template, `f1c4ed9a…`, for `isEnabled=0/1` | Selected color is external tint; no separate on/off art |
| Wi-Fi off | `CCUIWiFiModuleViewController` | 27.67×25.67 pt, `ddb6c2dc…` | Distinct state image |
| Wi-Fi on | same + `WFWiFiStateMonitor` | 27.67×21 pt, `8cd9a3bd…`; `setSelected:` gets `1` | Preserve integer state mapping |
| AirDrop | `CCUIAirDropModuleViewController` | 26.33×25 pt, `0fb16773…` | Off/receiving-disabled only |
| Bluetooth | `CCUIBluetoothModuleViewController` | 21.67×26 pt, `b0d912be…` | Off proven; active needs device |
| VPN | `CCUIVPNModuleViewController` | 26×29.67 pt, `d9acb6e0…` | Off only (no VPN config) |
| Satellite | `CCUISatelliteModuleViewController` | 25.33×23.33-pt setter image | Needs separate pass |
| Cellular | `CCUIConnectivityCellularDataViewController` loaded, not instantiated | `_glyphImageForDisplayBars:`, `_updateGlyphImageWithDisplayBars:`, `_toggleState`, `_debugDescriptionForState:` | VM synthetic presentation possible |

Interception points: Wi-Fi
`_glyphImageForState:currentSignalBars:forceSignalBars:network:applyConfiguration:`
and `_updateGlyphImagesWithState:`; Bluetooth `_glyphImageForState:` /
`_updateGlyphImagesWithState:`; AirDrop and VPN `_glyphImage` /
`_updateGlyphImages`; Satellite `_glyphImageForState:` /
`_updateGlyphImageWithState:`; Airplane `_updateStateWithEnabled:`. Parent
`CCUIConnectivityModuleViewController` has `setCellularDataButtonViewController:`
and `setExpandedCellularDataButtonViewController:`.

### Synthetic Bluetooth and Cellular (VM)

`scripts/lab/cnd_pulsar_synthetic_connectivity_probe.{py,m}` ran in SpringBoard
PID 39 without loading telephony/Bluetooth frameworks, restoring every changed
pointer/view/state/observation flag after 45 s. Cellular has no
`initWithContentModuleContext:` on this build; the route is
`initWithGlyphImage:highlightColor:` then `setContentModuleContext:`, which
bypasses the hardware-availability gate at the view-controller layer without
claiming a radio exists. `_glyphImageForDisplayBars:` (NSNumber) stock images,
all 25.33×16.67 pt:

| Bars | SHA-256 |
| --- | --- |
| 0 | `778998ebb4a189b827189991f015bb6513c105975c85d637e405cf795f442153` |
| 1 | `66f3059825d8a3f485f7f1138da660d834435d85103b6a992bca88cc75d71725` |
| 2 | `0dc3a5584e9c8bde8e24c7e9beacecf2c85b1149de6c2f9dddec4e69ea415f24` |
| 3 | `37cab1c746875ae1b1dcc45dcc6fa285c7739deb0fe59e4743f24d8c1ff65526` |
| 4, 5 | `111335ad0d42823c474aa34dee757c0a9ed8cc081e6c7b8eb6af850737e5f310` |

Bluetooth private state map (proven): 0 unavailable / Off and 1 power-off / Off
→ slashed (`b0d912be…`); 2 disconnected / Not Connected, 3 connected / On, 4
busy / Searching → plain (`c18daf2c…`; enabled/busy appearance external); 5–7
unavailable, no image. Evidence:
`build/lab-pulsar-synthetic-connectivity/synthetic-connectivity-visible.png`,
`…/synthetic-connectivity-restored.png`, eleven PNGs (seven unique) in
`…/assets/`, log `…/cyanide-pulsar-synthetic-connectivity.log` (SHA-256
`85c9be50c98a1acf8867efe5c8f4ccc146d93b1e7121990c77dd9aa5da06bd92`), ending
`RESTORED cellular=1 bluetoothState=1 bluetoothObservation=1` /
`COMPLETE status=success`. Artwork/state mapping is no longer a VM gate; real
radio behavior remains physical-only.

### Process-local Pulsar canaries (VM, diagnostic-only)

None of these installs anything; all are identity-checked, nonce-staged in
`/var/tmp`, and auto-restored in SpringBoard.

**Connectivity** (`scripts/lab/cnd_pulsar_connectivity_canary.py`, 30 s, PID
39): `wifi_white.png`, `bluetooth_white.png`, `AirplaneGlyph`,
`CellularDataGlyph`; the iOS 15 catalog is loaded as a standalone temporary
bundle, never copied over a system catalog. Wi-Fi/Bluetooth via
`CCUIButtonModuleViewController` glyph properties, Airplane via
`CCUIConnectivityAirplaneViewController`'s single-glyph setter, Cellular via a
noninteractive synthetic controller over the VPN slot; Bluetooth spoofed to
state 3, no Bluetooth/CoreTelephony/CommCenter call. `VISIBLE_READY
themeApplied=1` → `RESTORED` → `COMPLETE status=success`. Fixed bug: restore
now seeds the stock `airplane` image when the property is empty and calls the
controller's `_updateState`. Evidence in
`build/lab-pulsar-connectivity-canary/`: log SHA-256
`18875a41432c14b2077abfbec789c177a985efb5e5cc78de4b182a8fd2b0b13c`,
`pulsar-connectivity-visible.png`
`55d9cf274138c1d1e454eb207bbbb12216d754f2a9d0bae9a2120276cfadaccd`,
`pulsar-connectivity-restored.png`
`e90234f0452ff6891e059a2ea9e6932fc29f6c9f7e55e9fdd5d3d5489148184e`.

**Extended AirDrop/Hotspot/motion**
(`scripts/lab/cnd_pulsar_extended_connectivity_canary.py`, 30 s). Live graph:
AirDrop `CCUIAirDropModuleViewController`; Wi-Fi/Bluetooth/AirDrop expanded
views `CCUIControlTemplateView`; Hotspot controller absent; VPN
`CCUIVPNModuleViewController`; Satellite `CCUISatelliteModuleViewController`.
`AirDropGlyph` applied at controller and expanded-template layers; `HotspotGlyph`
shown on the synthetic Cellular host (visual only). VPN/Satellite left stock:
`SOURCE_GAP vpn=1 satellite=1 reason=no-official-pulsar-v2-art`. Motion CAML
adaptations (staging only): absolute `/var/mobile/Documents/PhucDo/PhucDoUI`
references rewritten, absent `wifi.png`/`bluetooth.png` mapped to
`wifi_white.png`/`bluetooth_white.png`; and iOS 26 `CAPackage` needs a
`.ca/index.xml` whose `rootDocument` is `main.caml`, so a wrapper was generated
preserving upstream CAML bytes. Both loaded as `com.apple.coreanimation-bundle`.
Assigning descriptions and the `poweroff` state to **controllers** did not
change materialized tiles; assigning them to the live
`CCUIControlTemplateView` consumers produced animated Pulsar glyphs. Evidence in
`build/lab-pulsar-extended-connectivity-canary/`: log
`341344d3537a27ce34c7d02bd9df824191c782c26f267b63e26161aa36b59cd8`,
`pulsar-extended-frame-a.png`
`2dae88447462d1d1f529ce622a72c28d60c0537d33c144cbc8edcde01e3af8d1`,
`pulsar-extended-frame-b.png`
`9102a6a8983a0a3123f1004ce9a4afd9ec198d6c6e79a35e90a81770a8e83da1`,
`pulsar-extended-restored.png`
`e90234f0452ff6891e059a2ea9e6932fc29f6c9f7e55e9fdd5d3d5489148184e` (identical
to the earlier stock capture). `motionLoaded=1 motionPresented=1`, PID 39
throughout.

**Low Power / Screen Recording / Flashlight admission.** The iOS 26 gallery
dismissed CC instead of showing the picker, so VM-only
`scripts/lab/cnd_vm_controlcenter_config.py` edits
`/var/mobile/Library/ControlCenter/ControlsIconState.plist` and
`ModuleConfiguration.plist` (VPHONE/VRESEARCH check, three allowlisted module
IDs, timestamped backups, SHA-256-verified atomic install, identity-checked
SpringBoard restart, idempotent, stable UUIDs). Applied backups:
`….plist.cyanide-backup-20261005T022056Z` for both files.

| Control | Saved module ID | Live route | Pulsar v2 source |
| --- | --- | --- | --- |
| Low Power | `com.apple.control-center.LowPowerModule` | `CCUILowPowerModuleViewController` → 73×73 `CCUIControlTemplateView` → `CCUICAPackageView`; `disabled` | `LowPowerModule/LowPower.ca` |
| Screen Recording | `com.apple.replaykit.controlcenter.screencapture` | `RPControlCenterMenuModuleViewController` → 73×73 `CCUIControlTemplateView`; `Base State` | `ReplayKitModule/replaykit.ca`, optional `replaykit-v2.ca` |
| Flashlight | `com.apple.control-center.FlashlightModule` | filtered by virtual hardware before a controller exists | `FlashlightModule.bundle/Assets.car` `FlashlightOff`/`FlashlightOn` |

Flashlight declares `camera-flash` in `UIRequiredDeviceCapabilities`; the vPhone
lacks it, so SpringBoard omitted the item and pruned its icon state. The system
volume is read-only (staged write failed before any change). The lab does not
patch the bundle, forge MobileGestalt, or call torch APIs. For visuals only,
`scripts/lab/cnd_vm_flashlight_control_probe.py` mounts a noninteractive,
labeled synthetic `CCUIButtonModuleViewController` in the empty fourth slot
`{{311, 578.667}, {73, 73}}`. Evidence: `build/vm-cc-lowpower-screenrecord-flashlight-final.png`
(`7c2101b27fe796dcbee5346aa7aec9de724c118051f7588a9bdf7faee9b2ff2d`), trace
`build/lab-pulsar-controlcenter-trace/cyanide-pulsar-controlcenter-trace.log`
(`ade1fa13241768c74a3d51a600a69b97e2764c158f960096d48fc92698f0c560`), probe log
`build/lab-vm-flashlight-control/cyanide-vm-flashlight-control.log`
(`ea4f680d480a7dd36efd42637d686dc06d2d440e7a6f676291b4fcec8f8a3923`,
`RESTORED mounted=1`, `COMPLETE status=success`), restored
`build/vm-cc-flashlight-restored.png`
(`06931e59dda4f1a044aa43277a97c7f7d669664d30d68efb02bf19fdbfdf4ce9`).

`scripts/lab/cnd_pulsar_additional_controls_canary.py` then applied Low Power
and ReplayKit packages (generated `.ca/index.xml` wrappers, rewritten image
paths, `CCUICAPackageDescription` URLs required to match staged `LowPower.ca`
/ `ReplayKit.ca`), held in upstream inactive `disabled`, plus
`FlashlightOff`/`FlashlightOn` on the synthetic control. An initial attempt
setting descriptions on **module controllers** crossed an unsafe iOS 26
boundary: SpringBoard restarted PID 3269 → 3481 (no control action, no system
write). The corrected canary targets descendant `CCUIControlTemplateView`s and
stayed in PID 3481:

```text
PACKAGE name=LowPower loaded=1
PACKAGE name=ReplayKit loaded=1
APPLY ... safeState=disabled originalState=disabled
APPLY ... safeState=disabled originalState=Base State
FLASHLIGHT mounted=1 ... offPoints=15.00x48.00 onPoints=15.00x48.00
VISIBLE_READY ... themeApplied=1 ... controlActions=0 hardwareSpoof=0
RESTORED lowPower=1 replayKit=1 flashlight=1 noSystemWrite=1
COMPLETE status=success ... controlActions=0 hardwareSpoof=0
```

Evidence in `build/lab-pulsar-additional-controls-canary/`:
`cyanide-pulsar-additional-controls.log`
`913d9530ffd4c8f060d1cc3a066c271eea66838a77810a48e756660701d430aa`,
`pulsar-additional-controls-visible.png`
`5715db95dd3111043fad7c07414d7e6a0ad1349ff63423c1477b3f2a56d3bf3a`,
`pulsar-additional-controls-restored.png`
`1708cb71520f58c0815f501d7a929c62c49f56f7e349e961811a04cdadb2c56c`. Clears the
process-local presentation gate for all three; does not record, toggle Low
Power, emulate a torch, or claim Flashlight function.

**Close/reopen persistence.** Home collapsed expanded Connectivity; a second
Home removed the CC window (windows 12→11, views 762→508); reopen gave 12/760.
Compact connectivity controller and Wi-Fi/Bluetooth image views kept identity;
Airplane got another native `setEnabled:` and its expanded child is a distinct
controller. Wi-Fi/Bluetooth/AirDrop share exact-ABI
`CCUIButtonModuleViewController setGlyphImage:`. So captured addresses only
seed already-materialized controls; native delivery must be intercepted when it
occurs. Trace: `build/lab-pulsar-controlcenter-trace/cyanide-pulsar-connectivity-trace.log`
(`7a25e2c4f6aa2574885696e9f4e31b4c6fe59b1e7e0be982afd0c764708a289c`).
`scripts/lab/cnd_pulsar_connectivity_persistence_canary.py` replaced four exact
ObjC delivery methods, seeded once, then let native delivery drive substitution
through two closes, two reopens, one expand and one collapse (no control action
or radio setter). PID 39; every check `found=5 themed=5` (Wi-Fi, Bluetooth,
AirDrop, compact and expanded Airplane); Airplane `setEnabled:` replacement
fired after each reopen. Log
`build/lab-pulsar-connectivity-persistence/cyanide-pulsar-connectivity-persistence.log`
(`5c1df8dd9a1da159b8475f02c488764737330de07156592563edf9db72f6df67`):
`RESTORED methods=1 objects=5 objectReadback=1 hookHits=10 newReceivers=0`,
`COMPLETE status=success ... controlActions=0 radioWrites=0 targetFileWrites=0`.
No real Cellular/Hotspot controller exists in the VM, so hardware-backed
instantiation is not proven.

### Definitive iOS 26 disk-to-display map

Supersedes the legacy Pulsar file layout. Combines `23A341` / `iPhone17,3` dyld
images, the mounted VM filesystem, static call-site disassembly and live
traces. *Secondary* = real path, but not the visible compact/expanded button.

**Connectivity**

| Control | File on disk | Construction / state | Consumer |
| --- | --- | --- | --- |
| Airplane | `ConnectivityModule.bundle/Assets.car` `AirplaneGlyph` (`airplane-40.pdf`) | `CCUIConnectivityAirplaneViewController -init` → `imageNamed:inBundle:` → `initWithGlyphImage:highlightColor:`; `RadiosPreferences` drives `setEnabled:` | Compact and expanded round buttons |
| Wi-Fi | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car` `wifi.slash`, `wifi`, `wifi.badge.lock` | `CCUIWiFiModuleViewController _glyphImageForState:…` → `_systemImageNamed:variableValue:withConfiguration:`; `WFControlCenterStateMonitor` | `CCUIRoundButton` collapsed; `CCUIControlTemplateView`/round-button glyph expanded |
| Bluetooth | CoreGlyphs `bluetooth.slash`, `bluetooth` | `CCUIBluetoothModuleViewController _glyphImageForState:` (states 0–4) → `_systemImageNamed:withConfiguration:`; `BluetoothManager` | Same as Wi-Fi |
| Cellular data button | CoreGlyphs variable `cellularbars` | `CCUIConnectivityCellularDataViewController _glyphImageForDisplayBars:` → 0–1 variable value → `systemImageNamed:variableValue:withConfiguration:` → `_updateGlyphImageWithDisplayBars:` → `setGlyphImage:` | Compact/expanded cellular buttons |
| Cellular menu/gallery (*secondary*) | ConnectivityModule `CellularDataGlyph` (`cellular-40.pdf`) | `CCUIConnectivityCellularModuleViewController` `imageNamed:inBundle:` → `setGlyphImage:` | Plan/menu module or gallery; not the toggle |
| Personal Hotspot | CoreGlyphs `personalhotspot`, `personalhotspot.slash` | `CCUIConnectivityHotspotViewController _glyphImageForCurrentState`; `WFPersonalHotspotStateMonitor`, discoverability, connection count | Compact/expanded Hotspot button |
| Hotspot preview (*secondary*) | ConnectivityModule `HotspotGlyph` (`hotspot-40.pdf`) | Catalog-backed preview/gallery art | Explains why the preview themed while the button stayed stock |
| AirDrop | CoreGlyphs `airdrop` | `CCUIAirDropModuleViewController _glyphImage` → `_systemImageNamed:withConfiguration:`; `SFAirDropDiscoveryController` → `_updateGlyphImages` | Round button and expanded template |
| VPN | CoreGlyphs `network.connected.to.line.below.fill` | `CCUIVPNModuleViewController _glyphImage` | Round/template view |
| Satellite | CoreGlyphs `satellite.slash.fill`, `satellite.wave.2`, `satellite.wave.2.fill` | `CCUISatelliteModuleViewController _glyphImageForState:` → `_updateGlyphImageWithState:` | Round/template view |

`/System/Library/CoreServices/CoreGlyphs.bundle` symlinks to
`/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphs.bundle`.
Wi-Fi/Bluetooth controllers live in `ControlCenterUI.framework/ControlCenterUI`;
Airplane, Cellular and Hotspot in dyld-cached
`ConnectivityModule.bundle/ConnectivityModule`. Corrections: `CellularDataGlyph`
is not the normal cellular toggle (it is `cellularbars`); old Pulsar `WiFi.ca`
and `Bluetooth.ca` do not exist in the iOS 26 Connectivity bundle.

**Flashlight and bottom-row controls**

| Control | File on disk | Construction / state | Consumer |
| --- | --- | --- | --- |
| Flashlight | CoreGlyphs `flashlight.off.fill`, `flashlight.on.fill` | `FlashlightModule -contentViewControllerForContext:` → `CCUIFlashlightModuleViewController`, `systemImageNamed:` ×2, `setGlyphImage:` / `setSelectedGlyphImage:`; `SBUIFlashlightController`/`SBUIFlashlightObserver` | `CCUIControlTemplateView` normal/selected glyphs |
| Timer | `TimerModule.bundle/Timer.ca` or `Timer_IC.ca` | `MTCCTimerViewController` package description + state | `CCUIControlTemplateView` → `CCUICAPackageView` |
| Calculator | `SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car` `calculator.fill` / `.svg` | `com.apple.calculator.CalculatorWidget.control` → `CHUISControlInstanceButton.viewModel.icon` → CoreUI vector glyph | `CCUIControlHostView` → `CHUISControlInstanceButton` → `CHUISControlIconView` |
| Camera | CoreGlyphs `camera.fill` / `.svg` | `com.apple.camera.deeplink.button`, same hosted route | same |
| Code Scanner | `Applications/BarcodeScanner.app/PlugIns/BarcodeScannerWidgetExtension.appex/BarcodeScannerWidgetExtension` declares `qrcode.viewfinder` → CoreGlyphs | `com.apple.BarcodeScanner.button` → ChronoUIServices control instance | `CHUISControlInstanceButton` → `CHUISControlIconView` |

iOS 26 `FlashlightModule.bundle` has only metadata/localization, no
`Assets.car`; overwriting the old path cannot affect the button.
`SpringBoard.framework/Flashlight-Dynamic.ca` is a different UI. Legacy
`CalculatorModule`/`CameraModule`/`QRCodeModule.bundle/Assets.car` still exist
but are not ancestors of the visible hosted WidgetKit controls (why replacing
them did nothing). Calculator/Camera extension executables are absent from the
mounted system and App Cryptex, but `CCCameraCalculatorVM-20261007-06` followed
the materialized view models' `UIImage` through `_UIImageCUIVectorGlyphContent`
and `CUINamedVectorGlyph` to the names/catalogs above; QR is the positive
control.

**Mirroring, media, brightness, volume**

| Surface | File on disk | Loader | Consumer |
| --- | --- | --- | --- |
| Screen Mirroring | `MediaControls.framework/Mirroring.ca` / `Mirroring_IC.ca` (`MirroringLeading.ca` extra layout) | `MRUMirroringViewController updateGlyphPackageDescription`; `MRUAssetsProvider packageDescriptionWithName:` | `CCUIControlTemplateView` → `CCUICAPackageView` |
| Previous / Next | `MediaControls.framework/ForwardBackward.ca` | `MRUAssetsProvider forwardBackwardPackageName` | `NowPlayingTransportControlsView` → `TransportButton` → `MediaControls.PackageView` |
| Play / Pause / Stop | `MediaControls.framework/PlayPauseStop.ca` | `playPauseStopPackageName` | center `TransportButton`'s `PackageView` |
| Volume | `MediaControls.framework/VolumeSemibold.ca` (captured); also `Volume.ca`, `VolumeRTL.ca`, `VolumeSemiboldRTL.ca`, `VolumeBold.ca` | `MRUVolumeViewController` / assets provider | MediaControls volume package view |
| Brightness | `DisplayModule.bundle/Brightness.ca` | Display module | `CCUIControlTemplateView` → `CCUICAPackageView` |

The old `AirPlayMirroringModule.bundle/MPAVScreenMirroring.ca` is gone. Misaka's
`Mirroring.ca`, `ForwardBackward.ca`, `PlayPauseStop.ca`, `Volume.ca` are the
right family, but `Mirroring_IC.ca`, `VolumeSemibold.ca` and RTL/weight
variants must also be covered. Live trace: `MRUMediaControlsModuleViewController`
owns `NowPlayingTransportControlsView`; each button owns a
`MediaControls.PackageView`; Mirroring is owned by `MRUMirroringViewController`
in `AirPlayMirroringModule.bundle/AirPlayMirroringModule` with packages from
MediaControls.

**Other stateful CAML** (replace as complete state packages, including `_IC`
variants, or CC may revert to stock when it picks the alternate):

```text
/System/Library/ControlCenter/Bundles/LowPowerModule.bundle/LowPower.ca, LowPower_IC.ca
/System/Library/ControlCenter/Bundles/MuteModule.bundle/Mute.ca, Mute_IC.ca
/System/Library/ControlCenter/Bundles/OrientationLockModule.bundle/OrientationLock.ca, OrientationLock_IC.ca
/System/Library/ControlCenter/Bundles/ReplayKitModule.bundle/replaykit.ca, replaykit-v2.ca, replaykit-v2_IC.ca
```

## Lifecycle owners (VM, 2026-10-05)

VM ownership mapping on `23A341`; the capture installed no adapter. (Its later
production wiring is superseded; see Status.)

### Evidence and method

`build/CCLifecycleOwnerVM-20261005-01/`:

- `final-restored-owners.json` — 4,636 objects, 11,927 edges, named ownership;
- `final-discovery.json` — 6,231 objects, 14,968 edges, selected VM UIKit
  descendant discovery (excluded from named-route calculation);
- `final-budget-audit.json` — member allowance raised to 1,024; largest
  collection 192, depth 14, no limit reached;
- Focus: `focus-expanded-before.json`, `focus-expanded-after.json`,
  `views-rebuild-before.json`, `focus-rebuilt-expanded.json`;
- Brightness: `final-configured-before.json`, `brightness-configured-rebuilt.json`;
- Media: `media-complete-before.json`, `media-complete-after.json`;
- `ownership-summary.json`, `lifecycle-comparisons.json`, `driver-*.json`,
  `stopped.txt`, `cleanup-verification.json` (PID 625, exact-ABI read-only
  `SBControlCenterController.isVisible=false`), `artifact-manifest.json`.

VM: headless from `~/Library/CyanideVPhoneLab/VMs/cyanide-ios26-base`, root SSH
`192.168.64.72:22222` (formerly `.70`); `require_vphone` checked before every
live action. The host control socket refused gestures, so the driver used
checked presentation APIs; no screenshot, tap, radio write, brightness/volume
change, playback or torch action. The probe follows containment, named typed
ivars, checked zero-argument getters, module dictionaries, descriptor/provider
owners and bounded Swift stored-field reflection; labels, accessibility text,
order and geometry are never identity. Early ObjC captures were PID 39; a
nested Swift-helper load accompanied that PID's termination (cause unknown,
no crash report). The final single-image probe ran in PID 625. 39/625
comparisons are not same-PID evidence; earlier 4,096-object captures are
truncated historical discovery.

### Process and module anchors

```text
SpringBoard._mainDisplayControlCenterController -> SBControlCenterController
  ._viewController -> CCUIMainViewController
  ._pagingViewController -> CCUIPagingViewController
```

`CCUIMainViewController.moduleInstanceManager` / `.moduleSettingsManager` are
checked getters `@16@0:8`. The paging controller has Swift fields
`moduleInstanceManager`, `moduleSettingsManager`, `controlDescriptorProvider`,
`controlExtensionProvider`, `controlHost`, `__rootFolderController`,
`iconViewMap`. The physical report
`build/CCLifecycleOwnerTraces-20261005-01/physical-media-focus-semantic-trace.json`
established the alternate `SBCoverSheetPrimarySlidingViewController._controlCenterController`
→ `SBControlCenterController.viewController/_viewController` route.

```text
CCUIModuleInstanceManager
  ._enabledModuleInstanceByUniqueIdentifer[uniqueIdentifier] -> CCUIModuleInstance
      ._metadata -> CCSModuleMetadata.moduleIdentifier
      ._module -> concrete module owner
```

`Identifer` is the real ivar spelling. Keys are machine UUIDs selected by
metadata module identifier — never hardcode UUIDs/addresses. `._repository` →
`CCSModuleRepository` (loadable metadata, bundle URLs). Settings carry
parity-control kind, extension and container identifiers for hosted controls.

### Re-resolvable rendering routes

| Surface | Route from module owner | Evidence |
| --- | --- | --- |
| Brightness | `CCUIDisplayModule._moduleViewController` → `CCUIDisplayModuleViewController._sliderView` → `CCUIContinuousSliderView._glyphPackageView` | `DisplayModule.bundle/Brightness.ca/`, state `mid` |
| Volume | `MediaControlsAudioModule._volumeViewController` → `viewIfLoaded` (`MRUVolumeView`) → `._primarySlider` → `MRUContinuousSliderView._glyphPackageView` | `MediaControls.framework/VolumeSemibold.ca/`; slider has machine `_name` |
| Focus rows | `FCCCControlCenterModule._activityPickerViewController` → `viewIfLoaded` (`FCUIActivityListView`) → `activityViews` → `FCUIActivityControl` by `activityIdentifier` | `activityDescription`, `activityUniqueIdentifier`, `activitySymbolImageName`, `._activityIconPackageView` / `._activityIconImageView` |
| Focus models | `FCCCControlCenterModule._activityManager` → `FCActivityManager._allActivitiesByIdentifier[activityIdentifier]` | `_FCActivity`; manager also owns `_availableActivities`, `_activeActivity`, `_defaultActivity` |
| Timer | `MTCCTimerModule._timerViewController` → `MTCCTimerViewController._buttonModuleView` → `CCUIControlTemplateView._glyphPackageView` | `TimerModule.bundle/Timer.ca/` |
| Screen Recording | `RPControlCenterModule._currentContentViewController` → `RPControlCenterMenuModuleViewController._buttonModuleView` → `._glyphPackageView` | `ReplayKitModule.bundle/replaykit-v2.ca/`, `Base State` |
| Low Power / Mute / Orientation Lock | controller → named button/template view → `._glyphPackageView` | `LowPower.ca`, `Mute.ca`, `OrientationLock.ca`; `disabled`, `ringer`, `locked` |

Materialized Focus rows: DND (`com.apple.donotdisturb.mode.default`,
`moon.fill`), Personal (`com.apple.focus.personal-time`, `person.fill`), Work
(`com.apple.focus.work`, `person.lanyardcard.fill`), Sleep
(`com.apple.sleep.sleep-mode`, `bed.double.fill`). The model dictionary also
holds Reading, Driving, Workout, Mindfulness, Reduce Interruptions and Gaming.
Model availability ≠ materialized row.

### Media Swift ownership

Two Now Playing instances materialized two transport graphs:

```text
MediaControlsModule._contentViewController -> MRUMediaControlsModuleViewController
  .$__lazy_storage_$_contentView -> MediaControls.MediaControlsModuleView
  .sessionsView -> RoutePickerSessionsView<MediaControlsModuleSessionView>
  .sessionViews[key=LOCAL] -> MediaControls.MediaControlsModuleSessionView
  .nowPlayingView -> MediaControls.MediaControlsModuleNowPlayingView
  .transportControlsView -> MediaControls.NowPlayingTransportControlsView
  .leftButton / .centerButton / .rightButton -> MediaControls.TransportButton
  .packageView -> MediaControls.PackageView
```

Parallel model route: `presenter.sessionPresenters[key=LOCAL].value.presentable`.
`LOCAL` is captured identity, not a fixed choice. These Swift classes often have
empty ObjC encodings and no getters; the probe uses bounded `Mirror` then
checks `class_getInstanceVariable` / `object_getIvar`. `verifiedSwiftSlots`
records owner, member, target class, dynamic offset, match; offsets are evidence
not constants. Struct/enum fields such as `viewModel` are values, never pointer
slots. The pure Swift presenter/model chain still needs typed Swift support.

| Role | `viewModel.some.asset` | Package state |
| --- | --- | --- |
| Previous | `symbolName=backward.fill`, `package.file=nextPrevious`, `isHorizontallyFlipped=true` | `State 1` (`State 1`–`State 4`) |
| Play/Pause | `symbolName=play.fill`, `package.file=playPauseStop` | `play` |
| Next | `symbolName=forward.fill`, `package.file=nextPrevious`, `isHorizontallyFlipped=false` | `State 1` |

Optional `leadingButton` had no transport model and is not Previous. No role
reads accessibility text. `MRUAssetsProvider` class getters
`forwardBackwardPackageName`, `playPauseStopPackageName`, `volumePackageName`
(`@16@0:8`) return `ForwardBackward`, `PlayPauseStop`, `Volume`; but the volume
consumer selects `VolumeSemibold.ca`, so `volumePackageName` alone does not
identify the variant.

### Hosted controls and VM omissions

Select `CCUIControlHostViewController` under the paging/root-folder
`CCUIContentModuleContainerViewController` members by checked `identity`
(`@16@0:8`) → `CHSControlIdentity._kind` / `._extensionIdentity`. Chain:
`viewIfLoaded` → `CCUIControlHostView.controlInstance` →
`CHUISControlInstanceButton.iconView` → `CHUISControlIconView` (instance also
exposes `descriptor`, `control`, `configuration`, `instanceIdentity`). The
2026-10-07 follow-up (`build/CCCameraCalculatorVM-20261007-06/initial.json`)
continued via `viewModel` → `_icon`/`icon` → `_UIImageCUIVectorGlyphContent` →
`CUINamedVectorGlyph` → `CUICatalog` → `NSBundle`, without executing the
placeholder extensions:

| Kind | Rendition | Provider |
| --- | --- | --- |
| `com.apple.calculator.CalculatorWidget.control` | `calculator.fill.svg` | `SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car` |
| `com.apple.camera.deeplink.button` | `camera.fill.svg` | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car` |
| `com.apple.BarcodeScanner.button` | `qrcode.viewfinder.svg` | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car` |

Flashlight: `CCSModuleMetadata` has its bundle URL/identifier, but no instance;
`FlashlightModule` and `CCUIFlashlightModuleViewController` are not loaded,
`SBUIFlashlightController` is — absent hardware, not a live route.

### Same-PID lifecycle evidence (PID 625)

SpringBoard, SBControlCenterController, main/paging controllers, module
manager/settings/repository, Focus manager, CHSControlHost and descriptor
provider persisted throughout; module instances stayed registered.

| Exercise | Receiver generation |
| --- | --- |
| Focus expand/collapse/close/reopen/expand | Picker, four rows, package targets cached and re-resolved |
| Media expand/collapse/close/reopen/platter invalidation/expand | Both transport graphs cached and re-resolved; no new transport receivers |
| Focus `setView:nil` → `loadViewIfNeeded` | Picker/manager persisted; all four rows changed address and re-resolved by identifier (Work `0x80e7f4a00`→`0x80e492d00`, DND `0x80e7f4000`→`0x80e492a80`; one Sleep package address reused by the allocator) |
| Brightness reconstruction, stock package/state copied | Controller persisted; slider `0x80be49b00`→`0x80d3c8300`; package `0x80c00ea00`→`0x811821800`, still `Brightness.ca`; root/slider slot restored on stop; no level changed |

Addresses are snapshots; pointer equality does not prove allocation lifetime,
and the tests do not claim visible OS remount. A MediaControlsModule cache
reset did not construct a new controller via `contentViewControllerForContext:`
(restored; driver removed). **Media reconstruction across genuinely new Swift
session/view objects remains unverified.**

### Physical follow-up list (open)

1. Confirm `SpringBoard._mainDisplayControlCenterController` and the media Swift
   member names/types on device; capture real audio sessions and a new media
   session/controller generation.
2. Verify Flashlight availability, module/template ownership, stock off/on
   delivery and hardware model, without activating the torch.
3. Verify Camera/Calculator's real extension descriptor/image provider;
   reconfirm QR's chain.
4. Exercise hardware-only Cellular/Bluetooth/Satellite/Hotspot materialization
   and state delivery.
5. Per adapter family: one ordinary redraw and one new receiver generation in
   the same physical PID (implementation gate, not broad UIKit discovery).

### Reproduce

```sh
python3 scripts/lab/cnd_cc_lifecycle_owners.py build
python3 -m unittest scripts.tests.test_cc_owner_analysis scripts.tests.test_pulsar_controlcenter_trace
python3 scripts/lab/cnd_cc_lifecycle_owners.py inject --host 192.168.64.72
python3 scripts/lab/cnd_cc_lifecycle_owners.py snapshot --phase ownership
python3 scripts/lab/cnd_cc_lifecycle_owners.py snapshot --phase discovery --recursive-discovery
python3 scripts/lab/cnd_cc_lifecycle_owners.py stop
python3 scripts/lab/cnd_cc_owner_analysis.py build/CCLifecycleOwnerVM-20261005-01 \
  --compare final-configured-before brightness-configured-rebuilt \
  --compare views-rebuild-before focus-rebuilt-expanded \
  --compare media-complete-before media-complete-after
```

The ObjC/Swift probe builds with warnings as errors; sixteen focused/related
tests passed. Evidence tests reject accessibility-only transport identity,
exclude recursive-discovery edges from named routes, and reject cross-PID
comparisons. Stop releases the timer, metadata, reconstruction journal and weak
owner maps (no method hooks were installed); the driver restores its journal
and shuts down after a 30-minute deadline. Fourteen staged dylibs were removed
from the VM's `/var/tmp`.

## Physical route traces (diagnostic-only)

All in-app actions under Cyanide → CC Theming; phases are user-declared and
never inferred from geometry, labels, accessibility or position. Every report
keeps `samePIDPersistenceVerified:false` and `implementationReady:false`.
Control, radio, presentation, target-file and runtime-metadata writes are zero;
only bounded runtime scratch/list allocations and app-local report writes occur.
No hooks, subclassing, artwork, torch action or image setter. Cleanup only in
the original healthy SpringBoard PID.

### Lifecycle-owner trace (schema 2)

**Trace CC Lifecycle Owners** / **Share CC Lifecycle Owner Trace**; latest file
`Documents/CCTheming/physical-media-focus-semantic-trace.json` plus timestamped
archives; mode `physical-read-only-lifecycle-owner-trace`. Start audio before
capturing Now Playing; capture Now Playing, expanded Focus and ordinary pages
separately.

The former semantic capture visited 35 controllers but emitted no media/Focus
roots (it filtered controller domains before inspecting ownership and only
considered eight windows). The replacement starts at UIApplication/SpringBoard
plus optional CC process services and follows checked window, root-controller,
presentation, containment, module, registry and provider links; mandatory
`windows`/`rootViewController` contracts are checked even when UIKit superclass
metadata is skipped; failures appear in `rootAcquisitions`. It is strictly
nonrecursive: no `subviews`, geometry, or label text; only allowlisted
zero-argument getters, safely typed ivars and bounded collection membership
(`viewIfLoaded` / `_view` without constructing views). Unknown methods are
`invoked: false`.

`routeCandidates` carry `ownershipRoute` and `lifecycleAnchoring`. Lifetime
scores: process owners 100, providers/registries 90, descriptors 85,
models/configurations 80, module instances 75, controllers 70, transient
view/package/image leaves 20/15/10. `highestStableAnchor` picks the strongest
downstream stable owner; ties prefer fewer transient hops, then fewer steps.
`rootToAnchorPath`, `anchorToTargetPath`, `unresolved`, `unresolvedPaths`
record observed chains and gaps. Scores are not survival proof. No recursive
fallback.

Limits: 512 objects, 128 controllers, 64 runtime classes, 64 members per
runtime list, 2,048 runtime members, 32 per collection, 4,096 edges, 16 hops,
12,000 calls, 30 s deadline (in-flight RemoteCall keeps its own timeout),
4,096 route-relaxation steps. `limitsReached`, `captureTruncated`, `budgets`,
`scratchFreed`, `pidStable`, `transportHealthy`, `transportSuccess` (≥1
controller), `captureComplete` (no limit hit) are reported.

### Refined CC routes — revision 3 (Compact / Expanded Media / Reopened Media)

2026-10-06. **Trace Refined Physical CC Routes** (5 s countdown) →
**Compact** (Flashlight and Camera/Calculator/QR materialized, not pressed) →
**Expanded Media** (user may pre-start audio; capture never starts playback or
transport) → dismiss, **Reopened Media** (no respring/reboot) → **Share Refined
Physical CC Routes**. Latest:
`Documents/CCTheming/physical-refined-controlcenter-routes.json` plus
UUID-suffixed archives. The embedded comparison needs the immediately preceding
successful capture in the same PID.

Schema 3, `refinedRevision:3`, mode `physical-read-only-refined-route-trace`.
Limits: 30 s, 12,000 calls, 512 ownership + 128 reserved diagnostic objects
(640), 128 generic classes, 32 per collection, 16 hops. A finite priority pass
checks 33 exact process/Media/Flashlight/hosted classes first (separate 32-class
allowance for extra CHS/CHUIS), reported in `priorityInspection`. Process route
`SpringBoard._mainDisplayControlCenterController → SBControlCenterController._viewController → CCUIMainViewController._pagingViewController`,
with the `SBCoverSheetPrimarySlidingViewController._controlCenterController`
fallback; registry via `_enabledModuleInstanceByUniqueIdentifer`. Regression
fix: `CCUIModuleSettingsManager` is no longer misclassified as a Foundation set.

Media inventories the VM-confirmed slots (`$__lazy_storage_$_contentView`,
`sessionsView`, `nowPlayingView`, `transportControlsView`, `leadingButton` /
`leftButton` / `centerButton` / `rightButton`, `packageView`, `stateController`,
`packageLayer`) only after exact runtime-class match; offsets come from current
metadata, aligned and in-bounds. `viewModel`, `asset`, package enum/state
structs are never treated as pointers; no Swift ABI is invoked. Roles need
machine semantic data.

Device captures `build/CCRefinedPhysicalCaptures-20261006-01/` established
wrapper class
`_TtGC13MediaControls23RoutePickerSessionsViewCS_30MediaControlsModuleSessionView_`
with empty-encoded `contentView` at 2256 and `sessionViews` at 2264 — type and
target class **not** established. Revision 2 reads one bounded raw word per
field, never dereferences it; `wrapperSlotClassifications` correlate with
independently acquired addresses (`valueDereferenced:false`,
`slotTypeVerified:false`, `productionRoute:false`). The revision-2 capture
`build/CCRefinedPhysicalCaptures-20261006-02/CCTheming/` reached 509 objects but
only 20 diagnostic descendants because discovery shared the ownership visited
set. Revision 3 gives discovery its own visited set/frontier seeded with the
wrapper; matches set `independentAddressValidated:true` and emit a
`diagnosticWrapperReference` edge excluded from ownership paths; `sessionViews`
is never traversed as an array. `mediaSessionChains` report each
`nowPlayingView → transportControlsView → buttons → packageView` chain with
`missingMember`. The diagnostic descendant phase walks ≤128 loaded descendants
from Media, Flashlight and hosted roots via ABI-checked `subviews`/collection
accessors (never `view`), edges `diagnosticDiscovery`, `productionRoute:false`.

**Result:** the supplied refined captures observed the wrapper and an All
Speakers button but **no session or transport receiver**
(`mediaMaterializationEvidence`). Hosted comparison keys use
`CHSControlIdentity.machineIdentities.kind`; replaying compact vs reopened
captures, all nine Camera/QR/Calculator controller/view/instance receivers
persisted by machine kind with no false hosted pairings. A
`CHUISControlIconView`/descriptor is not evidence of the extension image
provider. Other report fields: `processOwnerEvidence`,
`mediaNamedSlotEvidence`, `mediaSlotSnapshots`, `flashlightEvidence`,
`hostedControlEvidence`, `imageProviderEvidence`,
`staticMediaProviderEvidence`, `routeObservations`, `classContracts`,
`priorSamePIDComparison`, `unpairedRouteObservations`.

Build: unsigned `arm64`+`arm64e`
`build/CCRefinedPhysicalRoutes-20261006-02/DerivedData/Build/Products/Debug-iphoneos/Cyanide.app`,
log `build/CCRefinedPhysicalRoutes-20261006-02/xcodebuild.log`; nothing was
installed on device by that task.

### Refined Focus routes — revision 4 (Expanded Focus / Reopened Focus)

2026-10-06, `refinedRevision:4`, same action. **Expanded Focus · Start 5s**
(expand Focus, don't select a row) → dismiss → **Reopened Focus · Start 5s**
(same PID) → Share. Re-capture Expanded Focus if a run fails.

Starts with 20 exact Focus/process/icon classes (separate from the 128-class
budget). Routes to be confirmed on the physical device (not yet captured):

```text
FCCCControlCenterModule
  _activityPickerViewController → FCUIActivityPickerViewController
    viewIfLoaded → FCUIActivityListView
      activityViews → FCUIActivityControl selected by activityIdentifier
        activityDescription → model description and machine identifiers
        _activityIconPackageView → FCUICAPackageView
        _activityIconImageView → image view → image
        _contentView → named content receiver only
  _activityManager → FCActivityManager
    _allActivitiesByIdentifier[activityIdentifier] → _FCActivity
    _availableActivities → available model membership
    _activeActivity / _defaultActivity → observed model or explicit null
```

Identifiers come only from checked getters/typed ivars; no localized text.
Models may be copies (address need not match). Report fields:
`focusOwnerEvidence`, `focusOwnerChains`, `focusManagerStateSnapshots`,
`focusModelEvidence`, `focusModelMembership` (dictionary key must equal the
model's `activityIdentifier`), `focusRowChains`, `focusMaterializationEvidence`
(no four-row assumption). `FCUIActivityControl` is a transient view leaf.
`priorSamePIDComparison.focusReconstructionComparison` groups by module route
and `activityIdentifier`; `changedLeavesUnderUnchangedOwners` requires complete
chains, unchanged module/picker/manager and identities, and a changed
list/row/icon address; null→object is materialization; duplicates never paired.
Also `productionRoute:false`, `allocationLifetimeInferred:false`.
**No descendant discovery**; never `view`, `loadViewIfNeeded`, setters,
actions, Swift layout or ABI. Limits as revision 3 plus 4,096 edges and 128
controllers; no diagnostic object allowance.

Build: unsigned `build/CCFocusPhysicalRoutes-20261006-01/DerivedData/Build/Products/Debug-iphoneos/Cyanide.app`
(`arm64`/`arm64e`, `CODE_SIGNING_ALLOWED=NO`), log
`build/CCFocusPhysicalRoutes-20261006-01/xcodebuild.log`. The two Focus
captures were the remaining physical validation at writing.

### Tests

```sh
python3 -m unittest scripts.tests.test_cc_theming_focus_refined_trace scripts.tests.test_cc_theming_lifecycle_trace scripts.tests.test_cc_theming_semantic_trace scripts.tests.test_cc_theming_refined_trace
./scripts/build.sh
```

16 focused/baseline tests; with physical-probe, runtime, persistence and
delivery suites, 43 passed (at the time). Executable ObjC fixtures cover
empty-typed Swift slots, wrapper offsets, invalid untyped words, class
exhaustion, hosted machine-kind reordering, the SettingsManager regression,
cycle termination, reserved diagnostic allowance, Focus model/row joins,
active-null/default state, reordering, reconstruction under unchanged owners,
duplicate/mismatched identifiers, and different-PID rejection.

## Ownership-route audit of the former physical resolver (2026-10-05)

Historical; describes the removed RemoteCall Apply path. It was **not free of
recursive view traversal or label-based classification**: `CNDCCSurface`
passed accessibility label/identifier, controller class, source and module IDs
to `CNDCCControlKind`.

| Area | Behavior |
| --- | --- |
| Standard/bottom templates | `CNDCCThemingCopyPhysicalInventory` → `CNDCCCopyTemplateViews` descendant walk; label + identifier classification |
| Compact connectivity | `CNDCCCopyViewsMatchingClassNames` for round buttons; kind from accessibility identifier |
| Connectivity controller glyphs | Direct allowlisted getters (`wifiModuleViewController`, `bluetoothModuleViewController`, `cellularDataButtonViewController`, `vpnModuleViewController`) |
| Expanded connectivity fallback | Direct `button` getter, plus descendant fallback; calling `view` can materialize children |
| Brightness/volume | Controller class, then descendant discovery of `CCUICAPackageView` |
| Camera/QR/Calculator | Descendant walk for `CHUISControlIconView` |
| Compact Focus suppression | `customGlyphView` plus descendant discovery for `CHUISControlIconView` / `ButtonGlyphWrapperView` |
| Media transport | Absent from the physical resolver |
| Expanded Focus | Package paths known; physical ownership routes unvalidated |

It also made presentation changes, associated-object updates and per-instance
class changes — runtime operations, not resource-only substitution. A pinned
leaf or per-instance override serves an existing receiver but does not
transfer to a newly constructed view; this is why same-PID reconstruction
persistence was never established for that path and why production moved to
native file backing.

## Resource provenance extension (VM; implemented, not yet run live)

Diagnostic only; no live VM capture yet. Lifecycle snapshots prove routes to
current receivers but not which factory runs on reconstruction.
`scripts/lab/cnd_cc_resource_provenance.inc` (included only by the VM ownership
tracer, enabled by `resource-start`) observes, after method-ownership and
exact-encoding checks, forwarding all arguments/results unchanged (`NSError **`
not dereferenced):

| Source | ABI | Records |
| --- | --- | --- |
| `MRUAssetsProvider` package-name getters | `@16@0:8` | Natural returned names |
| `MRUAssetsProvider packageWithName:` / `packageDescriptionWithName:` | `@24@0:8@16` | Input, result, nested resource/cache calls |
| `FCUICAPackageView packageViewForActivity:` | `@24@0:8@16` | Activity id/symbol, returned view |
| `CCUICAPackageDescription packageDescriptionForActivity:` | `@24@0:8@16` | Activity → description |
| `CCUICAPackageDescription descriptionForPackageNamed:inBundle:` | `@32@0:8@16@24` | Name, bundle URL, result URL |
| `CAPackage packageWithContentsOfURL:type:options:error:` | `@48@0:8@16@24@32^@40` | URL, package, root layer |
| `FCUIActivityControl _updateActivityIcon` + icon setters | exact encodings | Activity identity, receiver before/after |

Also Media `loadView`/`viewDidLoad` and context factory, Focus picker
`loadView`/list configuration, system-image factories, bundle resolution and
nested `NSCache` calls (not enumerated or mutated). Events carry sequence /
parent, phase, addresses, activity ids, URLs, symbols; ≤4,096 events with drop
count; snapshot getter calls suppressed. `resource-stop`/`stop` restore only
methods still owned by the observer, reporting conflicts.

Exercise (fresh `--output-dir`, `CND_VPHONE_ROOT_PASSWORD`, port 22222):
inject, `resource-start --phase …`; snapshot base CC, expanded media,
collapse/dismiss/reopen; expand `com.apple.FocusUIModule`, snapshot,
`reconstruct-views`, snapshot; `resource-stop`, snapshot, `stop`; run
`cnd_cc_owner_analysis.py`. `resourceProvenance` joins Focus package-view
addresses to row slots and package root layers to Media `packageLayer` / Focus
`_rootLayer`; unmatched stays unmatched. Multiple consultations do not prove a
new generation; a fresh Swift Media receiver generation is still needed.
Local verification: `-Wall -Wextra -Werror`; Python tests (static metadata ≠
execution evidence; only verified named edges join); host ObjC fixture with
synthetic classes (no SpringBoard, VM or device).

## CC background material-recipe canary (VM, 2026-10-11) — rejected

Tested the first-stage Lemin/PureKFD color route on `cyanide-ios26-base`
(`23A341`) against only
`/System/Library/PrivateFrameworks/CoreMaterial.framework/modulesBackground.materialrecipe`.
Build-locked, vPhone-model and Cyanide-identity checked, nonce-bound; no sealed
file write — a device-native payload vnode is pinned and the name-cache entry
redirected in memory, with journaled restore of the entry and release of both
pins.

- Stock 343 bytes, `0df75fb8a3483414ba3423cff08a949039b2558bf07501f20ceba36aed659d56`;
  purple payload 343 bytes, `00144e2ca64311c63c666b1f6dbe1f2f8064ab7d380516baa144f86519d5b0df`.
- Apply: exact payload readback; SpringBoard PID 1038 → 1080. Restore: exact
  stock vnode and hash; PID 1080 → 1120. `targetFileWrites` zero throughout.
- Tinted vs restored Favorites screenshots are visually identical: mean
  absolute channel difference `0.346635, 0.150243, 0.006478` (0–255), `0.421532%`
  pixels differing (transient animation/status pixels).
- Lara (local commit `fb2d8640cf78`) caps `CC Module Background` and
  `CC Background Blur` at max version 18.9; its `moduleBG` still names this
  file, so file presence was a false compatibility signal.

Artifacts: `build/lab-cc-material-recipe-canary/full-visual-run.json`,
`tinted.png`, `stock-restored.png`; `scripts/lab/cnd_cc_material_recipe_canary.{py,m}`.
The initial `stock-before.png` showed the remembered Connectivity page; the
harness now selects Favorites (does not affect the negative result).

**Consequence:** do not expose this route on iOS 26 or infer compatibility from
the legacy resource's presence. A port needs the current Liquid Glass material
provider or a bounded live adapter on the actual background/module views. The
name-cache redirect is reusable only after a resource's iOS 26 consumer is
demonstrated.

## Now Playing AirPlay output glyph

Base and expanded Now Playing use system symbol `airplay.audio`, independent of
`Mirroring.ca`, `PlayPauseStop.ca` and `ForwardBackward.ca`. VM captures
`build/CCLifecycleOwnerVM-20261005-01/compact-625-complete.json` and
`media-complete-before.json`:

```text
MediaControlsModuleSessionView.nowPlayingView
  -> MediaControlsModuleNowPlayingView.upperRouteButton / lowerRouteButton
     -> MediaControlsModuleRouteButton
        .viewModel.some.symbol = "airplay.audio"
        .imageView -> UIImageView
```

Slots verified by typed Swift reflection; four instances share the symbol.
Production does not retain or resolve this hierarchy.

Source art: Pulsar's `AirPlayControlAudioLight.ca/main.caml` and
`AirPlayControlAudioDark.ca/main.caml` are identical (SHA-256
`25f3acba533310abb168ab10396a8fee5cbadf05dfbe742480d151a92db551a8`, star/comet
vector); no extra user art needed. The legacy package names are not used. The
generator renders the full drawing in a padded host canvas, crops the alpha
footprint, and stores `MediaAirPlay.png` in the app's Pulsar bundle with source
and output digests recorded. Priority masks use exact pixel-edge contours
(unchanged downsample resolution and alpha threshold; only shared internal
edges and collinear points removed), with pixel-union tests over every mask.

History: it was first added to a CoreGlyphsPriority research catalog (297,288
bytes padded to 309,384; 600 lookups = 15 identities × 4 glyph sizes × 10
weights passed on host CoreUI 975; Flashlight kept its Medium-only contract;
Connectivity and Display payload bytes unchanged), explicitly noting that a priority-catalog
entry does not establish base-CoreGlyphs coverage. Current production delivers
media AirPlay through the base CoreGlyphs replacement (see
cc-theming-file-backing.md); CoreGlyphsPriority is retired. Device consumption
is not verified; other output-device symbols are covered there via the
MediaRemote provider set, not inferred from this capture.
