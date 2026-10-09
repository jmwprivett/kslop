# Refined physical Focus route capture

2026-10-06. Dedicated Focus refinement, `refinedRevision:4`; diagnostic only.
The existing Compact/Expanded Media/Reopened Media revision-3 phases remain
available in the same Settings action.

In Cyanide → CC Theming, choose **Trace Refined Physical CC Routes**, then:

1. Choose **Expanded Focus · Start 5s** and open/expand Focus during the
   countdown. Leave the expanded picker visible without selecting a Focus row.
2. Dismiss Control Center yourself, choose **Reopened Focus · Start 5s**, and
   reopen/expand Focus. Keep the same SpringBoard process; do not respring or
   reboot between runs. A prior ordinary redraw may also be captured this way.
3. Use **Share Refined Physical CC Routes** to export the latest report and its
   embedded comparison. The comparison needs consecutive successful Focus
   captures; if one fails, capture Expanded Focus again before Reopened Focus.

Latest report: `Documents/CCTheming/physical-refined-controlcenter-routes.json`.
Every run also saves a unique UUID-suffixed archive. The phase is user-declared:
neither a declared expanded phase nor a reopen phase proves materialization or
view reconstruction.

## Exact routes and evidence

The dedicated Focus pass starts with the 20 exact Focus/process/icon classes.
Their finite named contracts have a separate allocation from the general
128-class budget. Exact queued targets and Foundation memberships are processed
first. Existing process and module-manager bootstrap routes remain available,
including the checked SpringBoard owner route and the runtime
`_enabledModuleInstanceByUniqueIdentifer` dictionary. No UUID, address, offset,
collection index, displayed name, or symbol-to-mode guess is baked into the probe.

The routes being confirmed on the physical device are:

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

The process/module/list/row/icon addresses are observations. The row's
`activityIdentifier`, `activityUniqueIdentifier`, and `activitySymbolImageName`
are captured only through checked object getters or typed named ivars.
`activityDescription` is a model object reference; no localized description or
display-name getter is read. Models may be copies: matching identifiers and
symbols do not require the row's description address to equal the manager's
model address.

`focusOwnerEvidence` and `focusOwnerChains` preserve exact owner/list contracts
and missing members. `focusManagerStateSnapshots` distinguishes a read null
active/default slot from an absent, unsafe, or unread member.
`focusModelEvidence` and `focusModelMembership` distinguish all keyed models,
available memberships, and actual materialized rows. Dictionary keys must
match the model's captured `activityIdentifier` before the row/model join is
accepted. Model availability is never treated as a loaded row.

`focusRowChains` retains the machine-identified row, model, description, package,
image, and content snapshots, with dynamically resolved ivar types/offsets. A
complete observed chain needs the process/module route, loaded picker/list,
unambiguous row identifier, keyed model identifier, matching symbol and unique
identifier, and at least one safely typed named package/image target. Missing
identifiers, duplicate identifiers, mismatched model keys, absent icons, and
unavailable safe accessors remain explicit `missingEvidence`.
`focusMaterializationEvidence` reports counts and whether all *observed* rows
are complete; it does not impose a four-row count or infer missing modes.

`FCUIActivityControl` is classified as a transient view leaf, rather than a
stable activity model. The module, picker, manager, list, row, and icon routes
are re-resolved on each capture. Nothing in this diagnostic installs an adapter
or promises physical repaint coverage.

## Comparison and safety

`priorSamePIDComparison.focusReconstructionComparison` requires successful
Focus captures in the same SpringBoard PID. It groups rows by the captured
module ownership route and `activityIdentifier`, independent of row order.
The shared route comparator also carries the row identifier onto icon routes,
so rows and their consumers cannot collide just because they use the same
named member paths.

The Focus comparison records unchanged owner addresses, changed list/row/icon
members, newly materialized or missing members, unmatched rows, and duplicate
groups. `changedLeavesUnderUnchangedOwners` contains only pairs with complete
chains, unchanged module/picker/manager addresses, unchanged machine identities,
and an actually changed observed list/row/icon address. Null-to-object changes
are separate materialization observations. Duplicate identifiers/groups are
never paired by address or position.

Unchanged addresses do not establish reconstruction; changed addresses can be
allocator-reused. The phase does not infer that any UI action happened. All
reports keep `samePIDPersistenceVerified:false`, `implementationReady:false`,
`productionRoute:false`, and `allocationLifetimeInferred:false`. The comparison
is evidence for designing a lifecycle adapter, not proof that one is installed.

The dedicated Focus pass performs **no descendant discovery** and never requests
`view`, `loadViewIfNeeded`, a setter, an action, a hook, or an artwork change.
It does not interpret empty-typed Swift fields, assume a Swift layout, or invoke
a Swift ABI. Only typed, aligned, instance-bounded object ivars and exact
ABI-checked zero-argument object getters are followed. Foundation collection
count/index/key ABIs retain the existing checks. Unknown return types are skipped.

The existing limits apply: 30 seconds, 12,000 counted calls, 512 ownership
objects, 128 generic runtime classes plus 20 exact priority classes, 32 members
per collection, 16 ownership hops, 4,096 edges, and 128 controllers. Every limit
and partial-capture flag remains visible. No diagnostic object allowance is
used for Focus. Cleanup occurs only in the original healthy SpringBoard PID.
Control/presentation/radio/target-file/runtime-metadata writes remain zero;
bounded runtime scratch allocations and two app-local report writes remain.

## Verification and artifact

Run:

```sh
python3 -m unittest scripts.tests.test_cc_theming_focus_refined_trace scripts.tests.test_cc_theming_lifecycle_trace scripts.tests.test_cc_theming_semantic_trace scripts.tests.test_cc_theming_refined_trace
```

The 16 focused and baseline tests pass; including the physical-probe,
runtime, persistence, and delivery regression suites gives 43 passing tests.
An executable Objective-C fixture runs
the actual production tracer with checked host transport/runtime fixtures. It
confirms model-key/row/symbol joins, active-null/default state, row reordering,
list/row/icon reconstruction under unchanged owners, duplicate/mismatched
identifiers, a null loaded picker, incompatible getter metadata, JSON output,
failed/different-PID rejection, and exact Focus contracts after exhaustion of the
128 generic-class allowance. The existing Media wrapper/session, hosted machine
kind, PID/cleanup, and static safety tests still pass.

Unsigned iPhoneOS app:
`build/CCFocusPhysicalRoutes-20261006-01/DerivedData/Build/Products/Debug-iphoneos/Cyanide.app`.
Build log: `build/CCFocusPhysicalRoutes-20261006-01/xcodebuild.log`.
Build succeeded for `arm64` and `arm64e`; bundle verification reports the app
is unsigned. The build command uses `CODE_SIGNING_ALLOWED=NO`.
Nothing was installed or captured
on a physical device during this implementation; the two new Focus captures
are the remaining physical validation.
