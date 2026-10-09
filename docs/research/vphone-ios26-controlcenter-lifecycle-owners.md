# iOS 26 Control Center lifecycle owners

Status: VM ownership mapping completed 2026-10-05 on iOS 26.0 `23A341`.
The original capture did not install or change a production adapter. On
2026-10-06 its named ownership routes were wired into Cyanide's production
Apply resolver. Apply now starts at the SpringBoard/module registry anchors
below and resolves current receivers through named getters, ivars, keyed
membership, and one bounded direct-child bridge for Media's native Swift
`sessionViews` storage. It does not call the diagnostic recursive inventory.

The current persistence adapter still pins the receivers resolved by that
Apply. It does not yet install a provider/factory callback that automatically
reacquires a newly reconstructed receiver, so reconstruction persistence must
not be inferred from this integration alone.

Apply now has a separate offscreen preparation phase. It ABI-checks and calls
`loadViewIfNeeded` on the traced controller owners, uses the exact
`contentViewControllerForContext:` / `backgroundViewControllerForContext:`
module factories when an owned controller is still nil, and calls
Connectivity's idempotence-checked `_initializeExpandedView`. It never presents
or expands Control Center, synthesizes appearance callbacks, invokes a control,
or walks descendants. Optional/asynchronous Media and hosted-control gaps are
reported rather than treated as successfully materialized.

## Evidence and method

Artifacts are in `build/CCLifecycleOwnerVM-20261005-01/`:

- `final-restored-owners.json`: 4,636 objects, 11,927 edges, named ownership.
- `final-discovery.json`: 6,231 objects, 14,968 edges, explicitly selected VM
  UIKit descendant discovery. These discovery edges are excluded from the
  analyzer's named-route calculation.
- `final-budget-audit.json`: final capture with explicit collection/depth
  accounting, after the member allowance was increased to 1,024. The largest
  encountered collection had 192 members, ownership depth reached 14, and no
  reported limit was reached.
- `focus-expanded-before.json`, `focus-expanded-after.json`,
  `views-rebuild-before.json`, `focus-rebuilt-expanded.json`: Focus redraw and
  reconstruction evidence.
- `final-configured-before.json`, `brightness-configured-rebuilt.json`:
  brightness reconstruction with the stock package description/state preserved.
- `media-complete-before.json`, `media-complete-after.json`: complete media
  expansion, close/reopen, and platter-container invalidation comparison.
- `ownership-summary.json`, `lifecycle-comparisons.json`: machine-readable
  named routes, model roles, verified Swift slots, providers, and comparisons.
- `driver-*.json`: exact presentation/reconstruction selectors and ABIs.
- `stopped.txt`: acknowledged cleanup, restoration, and timer shutdown.
- `cleanup-verification.json`: PID 625 and exact-ABI read-only
  `SBControlCenterController.isVisible=false` after restoring the UI.
- `artifact-manifest.json`: snapshot hashes and explicitly labeled current
  source hashes, without pretending earlier captures used the final build.

The saved VM was stopped at entry. It was launched headless from
`~/Library/CyanideVPhoneLab/VMs/cyanide-ios26-base`; its current root SSH endpoint
is `192.168.64.72:22222`, rather than the former `.70` address. The existing
`require_vphone` check confirmed the VPHONE/VRESEARCH guest before every live
action. The headless host control socket refused gestures, so the separate VM
driver used checked presentation APIs. No screenshot, control tap, radio
write, brightness/volume adjustment, playback action, or torch action occurred.

The probe follows controller containment, named typed object ivars, checked
zero-argument object getters, module dictionaries, descriptor/provider owners,
and bounded Swift stored-field reflection. It inventories both class and
instance methods without invoking arbitrary discovered selectors. Labels,
accessibility text, button order, and geometry are not semantic identity.
Swift reflection filters accessibility/title/label and geometry fields.

The first ObjC captures used SpringBoard PID 39. A subsequent experimental
nested Swift-helper load accompanied termination of that PID; no new crash
report was available to establish its cause. The final helper is linked into
the single probe image, which loaded and ran in PID 625. No comparison across
39/625 is same-PID evidence. Earlier 4,096-object captures are explicitly
truncated and retained as historical discovery, not the final capture.

## Process and module anchors

The VM exposes a shorter process route than the physical capture's bootstrap:

```text
SpringBoard
  ._mainDisplayControlCenterController -> SBControlCenterController
  ._viewController -> CCUIMainViewController
  ._pagingViewController -> CCUIPagingViewController
```

`CCUIMainViewController.moduleInstanceManager` and `.moduleSettingsManager`
are checked object getters with ABI `@16@0:8`. The paging controller also has
the named Swift fields `moduleInstanceManager`, `moduleSettingsManager`,
`controlDescriptorProvider`, `controlExtensionProvider`, `controlHost`,
`__rootFolderController`, and `iconViewMap`.

The physical report at
`build/CCLifecycleOwnerTraces-20261005-01/physical-media-focus-semantic-trace.json`
already established the alternate
`SBCoverSheetPrimarySlidingViewController._controlCenterController` →
`SBControlCenterController.viewController/_viewController` route. Physical
confirmation of the shorter SpringBoard ivar remains a focused follow-up.

The stable membership route is:

```text
CCUIModuleInstanceManager
  ._enabledModuleInstanceByUniqueIdentifer[uniqueIdentifier]
  -> CCUIModuleInstance
      ._metadata -> CCSModuleMetadata.moduleIdentifier
      ._module -> concrete module owner
```

The misspelling `Identifer` is the actual runtime ivar name. Registry keys are
machine UUIDs obtained from the dictionary, then selected by metadata's module
identifier; none of the captured UUIDs or addresses should be hardcoded.
`._repository` reaches `CCSModuleRepository`, including loadable module
metadata and bundle URLs. Settings carry parity-control kind, extension, and
container identifiers for hosted controls.

## Re-resolvable rendering routes

All arrows below are named ownership, checked getters, or keyed membership.
Generic controller containment selects classes/identities, not array positions.

| Surface | Route from the module owner | Machine evidence |
| --- | --- | --- |
| Brightness | `CCUIDisplayModule._moduleViewController` → `CCUIDisplayModuleViewController._sliderView` → `CCUIContinuousSliderView._glyphPackageView` | `glyphPackageDescription.packageURL` is `DisplayModule.bundle/Brightness.ca/`; captured `glyphState` is `mid`. |
| Volume | `MediaControlsAudioModule._volumeViewController` → `viewIfLoaded` (`MRUVolumeView`) → `._primarySlider` → `MRUContinuousSliderView._glyphPackageView` | Live package is `MediaControls.framework/VolumeSemibold.ca/`; primary slider has a machine `_name`. |
| Focus rows | `FCCCControlCenterModule._activityPickerViewController` → `viewIfLoaded` (`FCUIActivityListView`) → `activityViews` → `FCUIActivityControl` selected by `activityIdentifier` | Each row exposes `activityDescription`, `activityUniqueIdentifier`, `activitySymbolImageName`, and `._activityIconPackageView` / `._activityIconImageView`. |
| Focus models | `FCCCControlCenterModule._activityManager` → `FCActivityManager._allActivitiesByIdentifier[activityIdentifier]` | `_FCActivity` exposes exact identifiers, unique identifiers, and symbol names. The manager also owns `_availableActivities`, `_activeActivity`, and `_defaultActivity`. |
| Timer | `MTCCTimerModule._timerViewController` → `MTCCTimerViewController._buttonModuleView` → `CCUIControlTemplateView._glyphPackageView` | `TimerModule.bundle/Timer.ca/`. |
| Screen Recording | `RPControlCenterModule._currentContentViewController` → `RPControlCenterMenuModuleViewController._buttonModuleView` → `._glyphPackageView` | `ReplayKitModule.bundle/replaykit-v2.ca/`; captured inactive `Base State`. |
| Low Power / Mute / Orientation Lock | Concrete module's controller → named button/template view → `._glyphPackageView` | `LowPower.ca`, `Mute.ca`, `OrientationLock.ca`; captured states include `disabled`, `ringer`, and `locked`. |

For Focus, materialized rows were DND (`com.apple.donotdisturb.mode.default`,
`moon.fill`), Personal (`com.apple.focus.personal-time`, `person.fill`), Work
(`com.apple.focus.work`, `person.lanyardcard.fill`), and Sleep
(`com.apple.sleep.sleep-mode`, `bed.double.fill`). The model dictionary also
contains Reading, Driving, Workout, Mindfulness, Reduce Interruptions, and
Gaming, with their exact symbols. Model availability is distinct from a
materialized expanded row. These models and receivers allow an adapter to
recover row identity after reconstruction without text or ordering.

## Media's Swift ownership

Two registered Now Playing module instances materialized two transport graphs.
The named view route is:

```text
MediaControlsModule._contentViewController
  -> MRUMediaControlsModuleViewController
     .$__lazy_storage_$_contentView -> MediaControls.MediaControlsModuleView
     .sessionsView -> RoutePickerSessionsView<MediaControlsModuleSessionView>
     .sessionViews[key=LOCAL] -> MediaControls.MediaControlsModuleSessionView
     .nowPlayingView -> MediaControls.MediaControlsModuleNowPlayingView
     .transportControlsView -> MediaControls.NowPlayingTransportControlsView
     .leftButton / .centerButton / .rightButton -> MediaControls.TransportButton
     .packageView -> MediaControls.PackageView
```

The presenter supplies a parallel model route:
`presenter.sessionPresenters[key=LOCAL].value.presentable` reaches the same
session view. `LOCAL` is captured session identity, not a fixed future session
choice. Native Swift dictionary keys are recorded explicitly. Early reflection
captures used `<unnamed>` dictionary tuple paths; final captures carry keys.

These Swift classes expose field names and offsets but often **empty Objective-C
type encodings and no getters**. The probe obtains the stored property's type
and reference through bounded Swift `Mirror`, then checks
`class_getInstanceVariable` / `object_getIvar` against that typed reference.
`verifiedSwiftSlots` records the owner, member name, target class, dynamic
offset, and exact match. Captured offsets are evidence, not adapter constants.
Struct/enum fields such as `viewModel` are reflected as values and are never
misread as object-pointer slots. The pure Swift presenter/model chain still
requires typed Swift support or an independently validated runtime accessor.

The button names alone do not establish a media role. Model evidence does:

| Role | `viewModel.some.asset` evidence | Package state |
| --- | --- | --- |
| Previous | `symbolName=backward.fill`, `package.file=nextPrevious`, `isHorizontallyFlipped=true` | `State 1`; multiple `State 1`–`State 4` animation states. |
| Play/Pause | `symbolName=play.fill`, `package.file=playPauseStop` | `play`; package also supports pause/stop semantics. |
| Next | `symbolName=forward.fill`, `package.file=nextPrevious`, `isHorizontallyFlipped=false` | `State 1`; same package family as Previous. |

The optional `leadingButton` has no transport model in this capture and is not
assigned Previous. No role classifier reads accessibility text.

`MRUAssetsProvider` class getters `forwardBackwardPackageName`,
`playPauseStopPackageName`, and `volumePackageName` all have exact ABI
`@16@0:8` and return `ForwardBackward`, `PlayPauseStop`, and `Volume`.
This independently connects Swift `nextPrevious` to the existing
`MediaControls.framework/ForwardBackward.ca` route. The captured volume
consumer still selects `VolumeSemibold.ca`, so `volumePackageName` alone does
not identify every actual weight/layout variant. Package-provider boundaries
are stronger process-lifetime interception candidates than retained buttons.

## Hosted controls and VM omissions

The paging/root-folder controller owns `CCUIContentModuleContainerViewController`
members. Select their `CCUIControlHostViewController` by the checked `identity`
getter (`@16@0:8`), then `CHSControlIdentity._kind` and `._extensionIdentity`.
The exact current kinds are:

```text
com.apple.calculator.CalculatorWidget.control
com.apple.camera.deeplink.button
com.apple.BarcodeScanner.button
```

The direct consumer chain is
`hostController.viewIfLoaded` → `CCUIControlHostView.controlInstance` →
`CHUISControlInstanceButton.iconView` → `CHUISControlIconView`.
The instance also exposes `descriptor`, `control`, `configuration`, and typed
`instanceIdentity`. This reaches all three icon consumers without descendant
view discovery. Their extension/model identities are suitable adapter keys.

Calculator and Camera are materialized hosts even though the base vPhone
image's extensions are placeholders. A focused 2026-10-07 follow-up continued
from each `CHUISControlInstanceButton.viewModel` to its checked `_icon`/`icon`
`UIImage`, `_UIImageCUIVectorGlyphContent`, `CUINamedVectorGlyph`, `CUICatalog`,
and catalog `NSBundle`. This proved the cached live routes without executing a
placeholder extension:

| Kind | Symbol rendition | Native provider |
| --- | --- | --- |
| `com.apple.calculator.CalculatorWidget.control` | `calculator.fill.svg` | `SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car` |
| `com.apple.camera.deeplink.button` | `camera.fill.svg` | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car` |
| `com.apple.BarcodeScanner.button` | `qrcode.viewfinder.svg` | `SFSymbols.framework/CoreGlyphs.bundle/Assets.car` |

The focused evidence is in `build/CCCameraCalculatorVM-20261007-06/initial.json`.
It also records exact extension and container identifiers through the checked
`CHSExtensionIdentity` getters. The legacy Calculator/Camera module catalogs
are not in these consumer chains.

`CCSModuleMetadata` contains Flashlight's bundle URL and identifier, but no
Flashlight module instance or button exists. `FlashlightModule` and
`CCUIFlashlightModuleViewController` are not loaded; `SBUIFlashlightController`
is loaded. This is an absent hardware control, not a live theming route. The
earlier noninteractive synthetic flashlight experiment is a separate artifact
and was not installed or exercised here.

## Same-PID lifecycle evidence

Every comparison below is in PID 625. SpringBoard, SBControlCenterController,
main/paging controllers, module manager/settings/repository, Focus manager,
CHSControlHost, and the descriptor provider persisted throughout these phases.
Module instances and their concrete module owners also remained registered.

| Exercise | Observed receiver generation |
| --- | --- |
| Focus expand, collapse, CC close/reopen, expand | Picker, four rows, and their named package targets were cached and re-resolved. |
| Media expand, collapse, CC close/reopen, platter invalidation, expand | Both transport graphs and checked named object slots were cached and re-resolved. This did not create new transport receivers. |
| Controlled Focus `setView:nil` → `loadViewIfNeeded` | Picker and activity manager persisted; all four activity rows changed addresses and re-resolved through the same activity identifiers and icon slots. |
| Controlled brightness reconstruction with stock package/state copied | Controller persisted; slider changed `0x80be49b00` → `0x80d3c8300`; package receiver changed `0x80c00ea00` → `0x811821800`, retaining the `Brightness.ca` route. The original root/slider slot was restored on stop. |

The reconstructed Work row changed `0x80e7f4a00` → `0x80e492d00`; DND changed
`0x80e7f4000` → `0x80e492a80`. These addresses identify snapshots only. One
Sleep package address was reused by the allocator, so pointer equality alone
does not prove allocation lifetime. The tests do not claim that every view was
visibly remounted by the OS: the controlled reconstruction exercises the
controller's owned view graph and tests target re-resolution. Brightness's
stock presentation is journaled/restored; no brightness level was changed.

An attempted MediaControlsModule cache reset did not construct a new controller
through `contentViewControllerForContext:`; the original was restored and the
unsuccessful driver was removed. Media reconstruction across genuinely new
Swift session/view objects is therefore still an explicit limitation. No
theming adapter has been tested across that generation change in this task.

## Adapter consequence and focused device follow-up

The production resolver now reacquires the current receivers through these
named ownership paths each time Apply runs and records route IDs plus scope in
the install journal. It keeps machine identifiers as keys and does not use a
recursive view walk. Its per-instance subclasses pin the resolved receiver's
generator/value setters for ordinary redraws. A future provider/factory layer
is still required to trigger the same re-resolution automatically whenever a
controller constructs a genuinely new receiver. Finite recursive discovery
remains a VM diagnostic option only.

The minimized physical `kslop` follow-up is:

1. Confirm `SpringBoard._mainDisplayControlCenterController` and the verified
   media Swift member names/types on the physical build; capture actual audio
   sessions, and a genuinely new media session/controller generation.
2. Verify Flashlight availability, module/template ownership, stock off/on
   image delivery, and current hardware model without activating the torch.
3. Verify Camera/Calculator's real extension descriptor/image provider and
   symbol delivery; reconfirm QR's direct control-instance/icon chain.
4. Exercise hardware-only connectivity materialization and selected/state
   delivery for Cellular/Bluetooth/Satellite/Hotspot where VM evidence stops.
5. After implementation, verify one ordinary redraw and one new receiver
   generation for each adapter family in the same physical SpringBoard PID.
   This remains an implementation acceptance gate, not a requirement to repeat
   broad UIKit discovery on the phone.

## Reproduce and validate

```sh
python3 scripts/lab/cnd_cc_lifecycle_owners.py build
python3 -m unittest scripts.tests.test_cc_owner_analysis scripts.tests.test_pulsar_controlcenter_trace
# Supply the established VM password through the existing password environment.
python3 scripts/lab/cnd_cc_lifecycle_owners.py inject --host 192.168.64.72
python3 scripts/lab/cnd_cc_lifecycle_owners.py snapshot --phase ownership
python3 scripts/lab/cnd_cc_lifecycle_owners.py snapshot --phase discovery --recursive-discovery
python3 scripts/lab/cnd_cc_lifecycle_owners.py stop
python3 scripts/lab/cnd_cc_owner_analysis.py build/CCLifecycleOwnerVM-20261005-01 \
  --compare final-configured-before brightness-configured-rebuilt \
  --compare views-rebuild-before focus-rebuilt-expanded \
  --compare media-complete-before media-complete-after
```

The combined Objective-C/Swift probe builds with warnings treated as errors.
Sixteen focused/related tests pass. The three new evidence tests reject
accessibility-only transport identity, exclude recursive-discovery edges from
named routes, and reject lifecycle comparisons across different PIDs while
checking changed generations under a stable owner. The final VM is left
running with CC dismissed. Stopping releases the timer, cached metadata,
temporary reconstruction journal, and weak owner maps; the loaded image is
inert and no method hooks were installed.
The driver also restores its reconstruction journal and shuts down after a
30-minute deadline if an explicit stop request is missed.
Fourteen task-specific staged probe/helper dylibs were removed from the VM's
`/var/tmp` after stop; local build artifacts and remote trace reports remain.
