# CC Theming ownership-route audit

Status: 2026-10-05. This describes the physical RemoteCall implementation;
process-local delivery hooks are a separate execution path.

The current physical resolver is **not free of recursive view traversal or
label-based classification**. Its bounded traversals read UIKit object data;
they do not recognize screenshot pixels, but they still depend on view
hierarchy discovery. `CNDCCSurface` currently passes the accessibility label,
accessibility identifier, controller class, source, and module identifiers to
`CNDCCControlKind`. Thus a claim that existing production routes never use
labels would be incorrect.

| Physical resolver area | Existing route/discovery behavior |
| --- | --- |
| Standard and bottom control templates | `CNDCCThemingCopyPhysicalInventory` uses `CNDCCCopyTemplateViews` to walk loaded descendant views. `CNDCCSurface` classifies using class/module/source plus accessibility identifier and label. |
| Compact connectivity | `CNDCCCopyViewsMatchingClassNames` walks the compact controller's loaded view for round buttons. The compact button kind uses its accessibility identifier. |
| Connectivity controller glyphs | Exact allowlisted getters such as `wifiModuleViewController`, `bluetoothModuleViewController`, `cellularDataButtonViewController`, and `vpnModuleViewController` provide direct controller targets. This direct portion does not depend on button order. |
| Expanded connectivity button fallback | The exact controller's `button` getter is direct. The additional materialized-child fallback still calls `CNDCCCopyViewsMatchingClassNames`. Calling the existing `view` getter can materialize child views. |
| Brightness and volume package targets | Controller classes identify the module, then `CNDCCCopyViewsMatchingClassNames` discovers `CCUICAPackageView` descendants. |
| Camera, QR Code, Calculator | The hosted icon consumer is discovered by walking descendants for `CHUISControlIconView`. |
| Compact Focus stock suppression | Uses a direct `customGlyphView` getter and descendant discovery for `CHUISControlIconView` / `ButtonGlyphWrapperView`. |
| Media transport | Deliberately absent from the address-seeded physical resolver. A persistent process-local package-loader adapter does not establish a physical RemoteCall implementation. |
| Expanded Focus | Standard package paths and supplemental artwork are known; robust physical ownership/model routes remain to be validated. |

Physical theming also performs presentation changes, associated-object
updates, and per-instance Objective-C class changes to maintain replacements.
These are runtime operations, even when they reuse existing executable
functions rather than map a new executable payload. They should not be
described as resource-only substitution.

## Nonrecursive lifecycle-owner trace

Use **Trace CC Lifecycle Owners** in CC Theming. Start audio before capturing
Now Playing. Start the five-second countdown, open the page to inspect, and
leave it visible. Capture Now Playing, expanded Focus, and ordinary module
pages separately. **Share CC Lifecycle Owner Trace** exports the latest report.
The existing latest file name remains
`Documents/CCTheming/physical-media-focus-semantic-trace.json`; timestamped
archives and the existing share action remain compatible. New captures use
schema version 2 and mode `physical-read-only-lifecycle-owner-trace`.

The eventual adapter goal is persistence across ordinary redraws and page/view
reconstruction within the **same SpringBoard PID**. A retained leaf address or
a per-instance class override can serve an existing receiver but does not
automatically transfer to a newly constructed view. Module controllers,
registries, models, configurations, descriptors, and package providers are
candidate owners from which an adapter must reconstruct its downstream target.

The former semantic capture visited 35 controllers but emitted no media/Focus
roots. Its bootstrap filtered controller domains before inspecting ownership
links and only considered eight application windows. The replacement begins
with UIApplication/SpringBoard and explicit optional Control Center process
services, then follows checked application-window, root-controller,
presentation, containment, module, registry, and provider links. Mandatory
`windows` and `rootViewController` contracts are checked even when UIKit
superclass metadata is skipped. All reached controller classes are recorded
before domain annotation; generic container classes are not rejected for
lacking a media or Focus name. Optional service acquisition failures remain
visible in `rootAcquisitions`.

This primary trace is strictly nonrecursive with respect to UIKit view
hierarchy. It never calls `subviews`, descends descendant view collections,
reads visual geometry, or classifies labels/accessibility text. It follows
only explicit allowlisted zero-argument object getters, allowlisted safely
typed object ivars, and bounded array/set/dictionary membership. A controller's
`viewIfLoaded` or typed `_view` slot can establish a direct ownership edge
without constructing its view. Unknown runtime methods are metadata with
`invoked: false`; arbitrary discovered getters are not dispatched. Runtime
encodings and argument counts are checked before dispatch, including explicit
collection index/key arguments.

Media Previous, Play/Pause, and Next roles come from exact machine-named
ownership members, including their downstream package/image paths. Ambiguous
center/leading/trailing positions do not establish a transport role. Focus
evidence records activity/mode identifiers, configurations, and symbol names.
Module/control identifiers, package names/URLs/states, and controller/model
classes provide generic evidence for Flashlight, ordinary modules, brightness,
volume, hosted Camera/QR/Calculator, and bottom controls when their explicit
paths are available. Dictionary machine keys and member model identities can
reconstruct membership; collection positions and addresses are snapshots.

`routeCandidates` includes `ownershipRoute` and `lifecycleAnchoring`.
Candidate lifetime scores distinguish process owners (100), providers and
registries (90), descriptors (85), models/configurations (80), module instances
(75), controllers (70), and transient view/package/image leaves (20/15/10).
The process root identifies the namespace; `highestStableAnchor` selects the
strongest downstream stable-owner candidate. When multiple routes exist, the
route policy favors a stronger stable owner, then fewer transient rendering
hops, then fewer steps. Cycles and unknown edge kinds cannot create a route.

`rootToAnchorPath` and `anchorToTargetPath` show the actual observed ownership
chain. `unresolved` explicitly records unverified lifetime, transient target
re-resolution, missing machine membership identity, or a missing stable owner.
`unresolvedPaths` lists requested semantic roles with no captured path. Scores
are class/ownership evidence, not proof that an owner survives reconstruction.
Every report retains `implementationReady: false` and
`samePIDPersistenceVerified: false`. There is no recursive fallback; an
unresolved route remains unresolved. Any future recursive diagnostic must be
a separate, explicitly selected trace.

Global limits are 512 objects, 128 controllers, 64 runtime classes, 64 members
per runtime list, 2,048 runtime members overall, 32 members per collection,
4,096 recorded edges, 16 ownership hops, 12,000 budgeted calls, and a
30-second target-capture deadline. Class names and present/absent ABI contracts
are cached. Pure local route relaxation is also bounded at 4,096 steps.
An already-running call still uses RemoteCall's timeout; the deadline is
checked between operations rather than interrupting an in-flight call.
`limitsReached`, `captureTruncated`, and `budgets` expose partial captures.

Runtime lists are freed immediately, and the count scratch slot is freed in
`@finally` only while the original PID and transport remain healthy. A changed
PID or failed transport prevents cleanup dispatch. `scratchFreed`, `pidStable`,
and `transportHealthy` record the result. `transportSuccess` distinguishes
transport health from capture success, which requires at least one reached
controller. `captureComplete` additionally requires no reported limit. Root
acquisitions and partial object evidence are retained on failure.

Control actions, radio writes, presentation writes, target-file writes, and
runtime metadata writes remain zero. Local JSON report writes and bounded
runtime-list/count scratch allocations are diagnostic operations.

## Apply discovery and persistence limits

The existing physical inventory, expanded trace, and apply resolver above
still use bounded recursive view discovery and some label-based identity.
That current one-time apply discovery is separate from this lifecycle trace;
the trace does not alter apply/restore behavior, artwork, Timer-to-Stopwatch
mapping, VPN, or any existing device report.

The physical persistent adapter currently journals and subclasses/pins
captured receivers. Repainting or refreshing those same receivers differs
from constructing new receivers when a page or view is rebuilt. This trace
provides evidence for future adapters rooted at lifecycle owners; it does not
install those adapters or prove same-PID reconstruction persistence. Review
the machine identities and contracts, then validate owner survival and
downstream re-resolution across redraws and page recreation on a device before
promoting a route into a production adapter.
