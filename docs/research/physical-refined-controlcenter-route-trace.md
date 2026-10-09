# Refined physical Control Center route capture

2026-10-06. Refined revision 3; diagnostic implementation only.

Dedicated **Expanded Focus** and **Reopened Focus** phases now use revision 4,
with exact Focus owner/model/row/icon contracts, identifier-keyed comparisons,
and no descendant discovery. See
[the Focus capture guide](physical-refined-focus-route-trace.md). The Media
phases described below retain their revision-3 behavior.

In Cyanide → CC Theming, choose **Trace Refined Physical CC Routes**. Each
run starts after five seconds. The phase is user-declared, never inferred from
screen geometry, labels, accessibility, or collection position.

1. Choose **Compact** and open CC with Flashlight and Camera/Calculator/QR
   controls materialized. Do not press those controls.
2. Choose **Expanded Media** and open/expand Now Playing during the countdown.
   Audio may be started beforehand by the user, but the capture does not start
   playback or invoke transport actions.
3. Dismiss CC yourself, choose **Reopened Media**, and reopen/expand it. Do not
   respring or reboot between runs. Repeat this phase after an ordinary redraw
   if useful; unchanged addresses do not establish actual reconstruction.
4. Use **Share Refined Physical CC Routes**. The latest report embeds the
   comparison with the immediately preceding capture when both captures
   succeeded in the same SpringBoard PID. Retry a failed phase before moving on.

Latest report:
`Documents/CCTheming/physical-refined-controlcenter-routes.json`.
Each run also writes a unique UUID-suffixed archive in the same directory.
No previous lifecycle/expanded inventory/report action is removed or renamed.

## What is measured

The schema-3, `refinedRevision:3` `physical-read-only-refined-route-trace` reuses the existing
PID/time/call/object/class/edge/depth-bounded lifecycle walker. In refined mode
it inventories finite named members instead of scanning arbitrary runtime
method lists. The capture deadline is 30 seconds, 12,000 counted calls, 512
ownership objects plus a reserved 128 diagnostic objects (640 total), 128 generic
runtime classes, 32 members per collection and 16 ownership hops;
partial captures expose all limit flags. An in-flight RemoteCall uses its own
existing timeout. Class/absent-contract caches and healthy-original-PID-only
scratch cleanup are shared with the old trace.

Before broad lifecycle inventory, a separate finite pass checks the 33 exact
process/Media/Flashlight/hosted target classes. Their contracts remain available
when the generic 128-class allowance is exhausted. Exact target objects are
selected ahead of generic queued objects. Additional safely acquired CHS/CHUIS
classes have a separate 32-class allowance. `priorityInspection` reports exact
class availability/completeness, both class counts, and independent truncation
flags. The time/call/object/controller/depth limits still apply; a protected
class contract does not guarantee that its object is materialized or reachable.

Named process evidence checks
`SpringBoard._mainDisplayControlCenterController → SBControlCenterController._viewController → CCUIMainViewController._pagingViewController`.
The existing window/containment route to
`SBCoverSheetPrimarySlidingViewController._controlCenterController` remains a
fallback. Module registry membership uses the actual
`_enabledModuleInstanceByUniqueIdentifer` dictionary and metadata
`moduleIdentifier`, not baked-in UUIDs or array indexes. A regression fix keeps
`CCUIModuleSettingsManager` from being misclassified as a Foundation set.

Media evidence inventories the VM-confirmed named object-reference slots:

- module controller `$__lazy_storage_$_contentView`, then `sessionsView`;
- session `nowPlayingView`, then `transportControlsView`;
- transport `leadingButton`, `leftButton`, `centerButton`, `rightButton`;
- each `TransportButton.packageView`;
- package `stateController` and `packageLayer`, when exact classes match.

Offsets come from current runtime metadata and must be aligned and inside the
current instance size. Empty-encoded Swift reference slots are followed only
for this finite VM-confirmed class/name map and after the physical receiver's
runtime class exactly matches the expected class. Other native Swift slots,
including `viewModel`, `asset`, package enum and state structs, are not guessed
as pointers and no Swift ABI is invoked. Safe object getters and a checked
zero-argument BOOL/char flip getter may provide symbol/package/flip evidence.
Previous/Next/Play-Pause roles require machine semantic data; left/center/right
slot names alone never assign those roles. `MRUAssetsProvider` class getters
record checked ForwardBackward/PlayPauseStop package names separately.

The device captures in `build/CCRefinedPhysicalCaptures-20261006-01/` establish
the wrapper class
`_TtGC13MediaControls23RoutePickerSessionsViewCS_30MediaControlsModuleSessionView_`
with empty-encoded `contentView` at 2256 and `sessionViews` at 2264. They do not
establish either field's type or target class. Revision 2 locates those fields
using current runtime metadata and reads only one bounded raw word per field.
It never calls `object_getClass` or methods on an unknown word, follows a native
Swift array, or assumes a struct layout. `wrapperSlotClassifications` correlates
words only with addresses/classes independently acquired in the same capture
through checked ownership routes or loaded UIKit descendants. Even a match is
unresolved type evidence with `valueDereferenced:false`, `slotTypeVerified:false`
and `productionRoute:false`; it does not create an ownership edge.

The revision-2 expanded-media capture in
`build/CCRefinedPhysicalCaptures-20261006-02/CCTheming/` reached 509 objects but
only 20 diagnostic descendants. Its discovery shared the ownership visited set,
so an already inspected wrapper could stop further descendant inspection.
Revision 3 gives loaded discovery its own visited set and frontier, includes
the exact wrapper as a seed, and crosses previously inspected views. A cycle
cannot repeat a descendant. The 512 ownership objects cannot consume the extra
128 diagnostic object allowance; all existing time/call/collection/depth limits
still apply.

After this independent loaded-descendant acquisition and before resuming named
member inspection, revision 3 correlates wrapper words against the capture's
cached, safely acquired object classes. A match sets
`independentAddressValidated:true` and emits a `diagnosticWrapperReference`
edge. This correlation performs no target read or method call, does not enqueue
an unclassified word, and does not verify a field's Swift type. The edge remains
excluded from ownership paths. In particular, a `sessionViews` word is never
assumed to be an NSArray or traversed as native Swift array storage.

Safely acquired session objects then receive the existing exact-class named
member checks. `mediaSessionChains` reports each
`MediaControlsModuleSessionView.nowPlayingView → MediaControlsModuleNowPlayingView.transportControlsView → leading/left/center/rightButton → packageView`
chain, retaining null addresses and `missingMember` for absent links. A complete
chain requires every named link to match its exact target class. Chain completion
does not assign Previous/Next/Play-Pause roles or establish a production owner
route through the wrapper.

`mediaMaterializationEvidence` reports observed wrapper/session/transport counts
and whether the search was truncated. The supplied refined captures observed
the wrapper and an All Speakers button but no session or transport receiver.
An expanded phase is user-declared and does not prove a now-playing session was
materialized. Older expanded captures show a materialized Media hierarchy but
still do not type these wrapper fields.

When native Swift collections hide the next named path, a second diagnostic
phase walks at most 128 distinct loaded descendants from Media, Flashlight and hosted
roots. It calls only ABI-checked `subviews`/Foundation collection accessors,
never materializes `view`. Edges are `diagnosticDiscovery` with
`productionRoute:false` and are excluded from ownership-path construction.
Named-slot checks on a discovered transport remain useful runtime evidence,
but do not turn the descendant path into a production owner route.

Flashlight evidence follows live module/controller/button/image/package fields
when present. Hosted evidence follows host `identity` → CHS machine `kind` and
extension identity, loaded host `controlInstance`, instance
`descriptor/control/configuration/iconView`, and safe image/provider fields.
Actual extension providers may remain inside native Swift or remote SwiftUI
hosting objects; a `CHUISControlIconView` consumer or descriptor is explicitly
not evidence that the extension image provider itself was reached. Camera,
Calculator and QR outcomes must be reviewed against their host machine kinds.

## Repeated capture evidence and limitations

`processOwnerEvidence`, `mediaNamedSlotEvidence`, `mediaSlotSnapshots`,
`flashlightEvidence`, `hostedControlEvidence`, `imageProviderEvidence`,
`staticMediaProviderEvidence`, `routeObservations` and `classContracts` retain
exact observed data and missing-accessor evidence. `priorSamePIDComparison`
requires two consecutive successful refined reports from the same SpringBoard PID. It
compares named/machine-key routes and separately compares address sets per
verified Media slot. Media sets deliberately do not pair compact/expanded
receivers or infer transport roles from slot position.

Hosted comparison keys include the safely captured
`CHSControlIdentity.machineIdentities.kind`. A host controller's checked
`identity` reference supplies that kind to the controller, loaded host view,
and CHUIS descendants on its ownership route. This separates Camera, QR, and
Calculator even when their named containment routes coincide. The comparator
recomputes keys from historical captures when their object evidence is present;
it does not trust old colliding serialized keys. Missing/ambiguous kinds become
`unpairedRouteObservations`. Duplicate key groups retain unchanged raw address
intersections, report additions/removals, and never infer changed receiver pairs.

Addresses are snapshot observations and can be reused by the allocator.
Missing receivers may simply be nonmaterialized in the selected phase. A
single capture, unchanged receivers, or a changed address cannot by itself
prove allocation lifetime or automatic repaint coverage. Every report keeps
`samePIDPersistenceVerified:false` and `implementationReady:false`. Complete
native Swift semantic-model access, actual physical extension providers, and
real physical Media leaf reconstruction remain follow-up evidence, not claims
made by this diagnostic.

Control, radio, presentation, target-file and runtime-metadata writes are zero.
Only bounded runtime scratch/list allocations and app-local report writes
occur. No hooks, subclassing, artwork substitution, torch action, image setter
or presentation mutation is installed by this capture. Existing production
apply/restore and artwork paths are unchanged.

## Verification/build

Focused tests include executable Objective-C runtime fixtures for empty-typed
Swift-style named reference slots, exact class validation, the device-discovered
wrapper offsets and an invalid untyped word, target contracts after generic
class exhaustion, safe role evidence, reordered machine-kind hosted comparisons,
the SettingsManager regression, and the old bootstrap/failure paths. Revision-3
fixtures also cross an already inspected wrapper, terminate a loaded-view cycle,
validate its content word independently, capture the exact session/package
chains, and check the reserved diagnostic allowance after 512 ownership objects.
Static
tests cover refined schema/settings, discovery separation, and existing action
preservation.

When the supplied local physical captures are available, the executable fixture
also replays compact versus reopened reports: all nine Camera/QR/Calculator
controller/view/instance receivers persist by machine kind, with no false hosted
changed pairings.

Run:

```sh
python3 -m unittest scripts.tests.test_cc_theming_lifecycle_trace scripts.tests.test_cc_theming_semantic_trace scripts.tests.test_cc_theming_refined_trace
./scripts/build.sh
```

The unsigned iPhoneOS build is retained separately under
`build/CCRefinedPhysicalRoutes-20261006-02/`. Nothing was installed on a physical
device. The user must install/sign the app through their established workflow,
perform the three phases above, and export the new physical report.

Unsigned app:
`build/CCRefinedPhysicalRoutes-20261006-02/DerivedData/Build/Products/Debug-iphoneos/Cyanide.app`.
Build log: `build/CCRefinedPhysicalRoutes-20261006-02/xcodebuild.log`.
The app executable contains both `arm64` and `arm64e`; its bundle is unsigned.
