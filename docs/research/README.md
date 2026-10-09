# SnowBoard Remix and iOS 26 research

Current status, 2026-09-25: SnowBoard Remix publishes structured `IFImage`
records through a pinned `iconservicesagent` session. The iOS 26.0 (`23A341`,
`iPhone17,3`) descriptor profile comes from VM traces and physical-device
checks. Apply and Restore use recovery journals that retain exact original
stock records; Restore and application-update rebasing have been verified.
**Update Repair** is a manual operation for newly installed or updated apps.
SpringBoard cache invalidation is temporarily disabled while the consumer
refresh path remains under investigation. The persistent index-token repair
has host-build and static-test coverage; its full physical
Apply/audit/reinstall/audit acceptance sequence remains outstanding.

## Descriptor profile

The per-app core profile uses 3× scale throughout:

| Points | Appearances | Notes |
| --- | --- | --- |
| 13×13 | 0 | Core |
| 27×27 | 0, 1 | Core; its appearance-0 store unit can alias 28-point |
| 28×28 | 0 | Core launch/return consumer (`variantOptions=0`) and Share-sheet Apps-list consumer (`variantOptions=0x4`, `drawBorder=YES`) |
| 38×38 | 0, 1 | Core |
| 48×48 | 0 | Core |
| 64×64 | 0 | Core for every app's Spotlight Apps-list result |
| 68×68 | 0, 1 | Core |
| 68×68 | 0 | Core launch/return record with `variantOptions=0x20000` |
| 20×20 | 0 | Safari-only SnippetUI badge, outside the per-app core |

Exact descriptors, including variant options, factory options, and observed
pixel dimensions, are constructed in `CNDIconServicesDescriptorSpec`.
Existing active journals expand safely by publishing only missing records.
AirDrop is the one bounded non-application identity: when a theme supplies
`com.apple.Sharing.AirDrop.png`, Cyanide publishes its 64-point activity-strip
record and its bordered 28-point Apps-list record under
`com.apple.Sharing.AirDrop`.

## Persistence and audit

Publication renders a structured `IFImage` and writes records through one
pinned daemon session. The recovery journal keeps original stock UUIDs, store
hashes, validation tokens, and LaunchServices source identities so Restore can
prove the original state. Update Repair and rebase checks handle replacement
application records without silently overwriting unknown drift.

An unrelated app installation can trigger IconServices garbage collection.
The identified durability defect was a stock LaunchServices validation token
remaining in the on-disk index for a themed record. The current publisher
corrects that persistent token and verifies a fresh lookup; the physical
reinstall sequence still needs to confirm the fix end to end. Alias-aware
audits accept the observed shared 27/28-point store unit only when its indexed
UUID, source identity, and journaled hash prove the peer relationship.

Bounded VM and physical-device audits compare indexed UUIDs, store and pixel
hashes, validation tokens, and LaunchServices source identities. They also
inventory materialized SpringBoard consumers for Home icons, folders, App
Library, notifications, switcher titles, and launch/return transitions. The
tools cover lab KRW, injected inspection dylibs, RemoteCall tracing, local
notification probes, app-install invalidation tracing, and resident consumer
inventories. Spotlight transparency and Clock/Calendar icon sources remain
active research topics. The screen-recording invalidation observation was
isolated and unproven; failed Clock experiments are negative evidence, not
production behavior. The one-second RemoteCall bootstrap wait remains.

The detailed notes below preserve chronology and occasionally say “still needs
validation” about work completed later. Use this status page and the top of
`snowboard-remix-current-handoff.md` for the current position, then the dated
sections for evidence. Static dyld-cache and disassembly work uses the exact
iOS 26.0 `23A341` / `iPhone17,3` VM profile.

Pulsar Control Center port research is documented separately. See
`vphone-ios26-pulsar-controlcenter-tracing.md` for the canonical Misaka v2
target inventory, the bounded iOS 26 runtime trace, and the capture acceptance
gates.

The durable pre/post-respring installer architecture, recovery invariants,
durable SnowBoard and epoch-bound presentation ACTIVE-state semantics, and the
final device-validation checklist are recorded in
`queued-system-change-coordinator.md`.

The authoritative Calendar implementation contract—including the distinct
SpringBoard and Spotlight model graphs, provider/source-cache ordering,
bounded consumer update, Restore sequence, and the physical false-success
proof—is recorded in `vphone-ios26-calendar-provider-repair.md`.

The repeatable VM-only kernel-call setup, live debugger-address capture,
verification gates, signature recovery, and physical-aperture safety boundary
are recorded in
[`vm-guide.md`](vm-guide.md).

The October 7 2026 panic evidence that closed the text-page mutation route
(esr `0x9600004f`, write permission fault in the physical aperture, seven
identical panics) and the follow-up identical-bytes data-page aperture
experiment are recorded in
[`hail-mary-data-page-experiment.md`](hail-mary-data-page-experiment.md).
