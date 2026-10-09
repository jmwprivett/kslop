# SnowBoard Remix current handoff

**Updated:** 2026-09-25
**Repository:** `kslop`
**Branch:** `kslop-main`
**Base HEAD:** `918395db4b8a20ffeb15ba0dfdd3b34e0d89ca89`

## Current status for this handoff

Read [the research status](README.md) first. The 11-record per-app core now
includes the 64-point Spotlight Apps-list icon, and older 10-record journals
expand by publishing only that missing record. Physical Restore and update
rebasing are verified, as is alias-aware classification of the observed
27/28-point store unit. The persistent index-token correction has static tests
and a host build, but its physical Apply/audit/reinstall/audit sequence is still
required. SpringBoard cache invalidation remains disabled. The one-second
RemoteCall bootstrap wait remains. Clock experiments below include failed
routes and must not be read as production behavior; the screen-recording
observation is unproven. Earlier chronological sections retain their original
checkpoint language, including stale validation TODOs.

## Latest checkpoint: publication now commits the durable index token

The physical reinstall audit disproved the process-cache-only token fix. The
themed `IFCacheImage` used `NSData._is_validToken`, but the corresponding
on-disk `ISStoreIndex` value still contained the ordinary 40-byte
LaunchServices validation token. An unrelated application install advances
LaunchServices state; subsequent consumers can then reject that persistent
entry and regenerate stock pixels. This explains why Home, App Library,
notifications, and switcher surfaces could fail together and why a respring
did not necessarily recover them.

Physical publication now waits for Apple's asynchronous index commit before
changing store bytes. It maps and validates the existing 23A341 index, locates
the exact `0x74`-byte descriptor value, changes only the token at `+0x4c` to
`NSData._is_validToken`, performs `msync(MS_SYNC)`, invalidates the daemon's
read mapping, and requires a fresh normal IconServices lookup to return the
same UUID and sentinel token. Retries invalidate the read mapping so polling
cannot remain pinned to a pre-commit view. Any failed write or lookup restores
the original token and stock store unit and fails the publication closed.

Apply acceptance now requires the persistent token write and fresh lookup
proofs. Restore uses Apple's stock token, but must still prove the fresh stock
UUID/token is present in the persistent index. Compact logs expose index
identity settlement, write verification, lookup verification, and attempt
counts. Static tests and the host build pass; a physical Apply/audit/reinstall/
audit run is still required before declaring the durability defect fixed.

## Previous checkpoint: physical audit proved a 27/28 store-unit alias

The corrected audit completed twice on the physical device for Bitwarden,
Messages, Snapchat, and TikTok. All 40 descriptor reads and the bounded
SpringBoard audit succeeded. Thirty-six store hashes exactly matched their own
journaled themed hash. The remaining four were consistently the 27x27@3,
appearance-0 records. Each shared the exact current-index/store UUID and store
hash of the same application's themed 28x28@3, appearance-0 record. Every
source registry contained the current application's LaunchServices identity.

This was an audit classification failure, not missing persistent data.
Snapshot schema 4 resolves aliases only within the same bundle and indexed
UUID, and only when both records have valid index/store/source evidence and
the shared store hash equals the peer descriptor's journaled themed hash. The
record is retained as `store=themed-alias` with its peer descriptor and hash.
The summary reports `aliased-store` separately. The failed schema-3 audit did
not write a baseline, so the alias-aware build must run once before reinstall
to capture the baseline and once afterward for the comparison.

The second-pass `unchanged` classification now depends only on persistent
store hash, index/store UUID, validation token, and LaunchServices source
identity. Process-cache hashes and identifiers remain diagnostic fields but
cannot turn an otherwise unchanged persistent record into a false difference
when the iconservicesagent cache is empty or has been repopulated.

No Apply, Restore, publication, or SpringBoard refresh behavior changed.

## Previous checkpoint: applied-state audit verified against 23A341

The complete applied-state audit was rechecked against the local iOS 26.0
23A341 dyld cache and restore binaries. The original physical audit was not
valid evidence: it treated an empty process-local `ISImageCache` as the
persistent state, used an unsafe `cacheURL` property thunk across the physical
RemoteCall boundary, treated the source-registry result as one `NSData` rather
than an array, and used a store accessor that memoizes units into the process.

The corrected audit now performs an independent current-digest
`findStoreUnitForIcon:descriptor:UUID:validationToken:` lookup using a fresh
`ISBundleIdentifierIcon`, maps the indexed `ISStoreUnit` directly, verifies
its UUID/data/token, and checks every persistent source-registry entry against
the current `LSApplicationRecord.persistentIdentifier`. The canonical
process-local `ISImageCache` is read separately and never refilled; its
population is diagnostic, not a requirement for persistent proof. Unsafe
property getters were replaced with name-and-offset-validated ivar reads, and
file-backed bytes are copied in bounded chunks through the pinned scratch
page.

The SpringBoard half is also bounded and non-refreshing. It inventories
canonical icons, live leaf icons, image generations/layer/observer counts, and
materialized switcher title icons. It does not claim to inspect visible pixels
or all surface caches. The full ABI/layout/control-flow evidence and physical
results are recorded in
`vphone-ios26-applied-state-audit.md`.

No Apply, Restore, publication, or SpringBoard refresh behavior changed as
part of this correction.

## Previous checkpoint: physical reinstall audit receiver corrected

The physical publisher bootstrap no longer calls
`_ISInvalidateCacheEntriesForBundleIdentifier`. Runtime tracing proved that
even the unowned `com.zeroxjf.cyanide.iconservices-wake` identifier schedules
the daemon's global `ClearCacheOperation`/`collectGarbage` path, so invoking it
at the start of Apply could perturb the exact records under test. Both the
nonresident wake and armed-thread RemoteCall provoker now use the read-only
`IconCacheService fetchCacheConfigurationWithReply:` request. The publisher
contains no reference to the invalidation symbol, and a static regression test
enforces that boundary. Apply, Restore, and audit also persist their activity
logs in Documents so an update or normal app exit cannot discard the evidence.

The first physical-device rolling audit produced a false all-unchanged result.
Every descriptor in both samples actually had an empty UUID, empty data/token
hashes, `cacheResponsePresent=false`, and `storeUnitPresent=false`. The audit
had sent `imageForDescriptor:` to `ISImageCache`, whose implementation checks
only that process-local image bag. It therefore compared missing with missing
and never exercised the persistent-store lookup.

iOS 26.0 build 23A341 disassembly established why that sample was invalid:
`-[ISConcreteIcon imageForDescriptor:]` at `0x1a7229fa4` first calls
`_cachedImageForDescriptor:` and then, on a miss,
`_imageFromStoreForDescriptor:` at `0x1a7228530`. The latter calls
`ISIconCache findStoreUnitForIcon:descriptor:UUID:validationToken:` followed
by `storeUnitForUUID:` and materializes the response. Sending that getter to
the canonical icon was considered as an intermediate correction, but it would
refill the cache and cease to be an observation-only audit. The final audit
instead calls `findStoreUnitForIcon:descriptor:UUID:validationToken:` directly,
maps the returned unit without `ISStore` memoization, and observes the
canonical `ISImageCache` separately without refill.

Audit snapshot schema 3 rejects the invalid older samples. A new baseline
is written only when every journaled descriptor resolves to themed bytes in a
valid store unit whose UUID matches the current index, with a real persistent
validation-token hash and a source identifier matching the current
LaunchServices record. The optional process response is not required. A
comparison that finds any difference preserves the pre-reinstall baseline.
Physical publication journals now record the actual indexed UUID and
validation-token hash rather than the former opaque UUID placeholder. Reapply
with the new build before capturing the next baseline.

## Previous checkpoint: controlled Cyanide reinstall captured

The 2026-09-24 controlled Cyanide update captured the real installation
boundary end-to-end. `lsd` PID 131 called
`clearCachedItemsForBundeID:reply:` for `com.zeroxjf.ios-cyanide1`, which
scheduled the global `ISMutableIconCache.collectGarbage` operation. The pass
reconstructs every `unitSourceRegistry` value as an `LSRecord` and removes the
corresponding store UUID when reconstruction fails.

The source value is a 36-byte LaunchServices application-record identifier,
not a bundle ID. Disassembly proves it embeds the database GUID, table/unit
IDs, and an eight-byte per-record identity. The controlled update did not
replace the database generation: its GUID remained
`1F26ABB1-5FAA-455C-B070-6CC78C13193B` throughout. Instead, Cyanide's
application record changed from unit 2632 / identity `0xa48` to unit 2636 /
identity `0xa4c`.

`scripts/lab/cnd_iconservices_inspector.m` now has a read-only lifecycle trace
for this exact chain. It records:

- bundle-scoped and full invalidation requests plus XPC caller PID;
- scheduled operation type and `ClearCacheOperation.run` execution;
- GC entry/exit and checked/valid/invalid/removed totals;
- source registration paired with its store-unit UUID;
- failed `LSRecord` construction classified as `database-guid` or
  `unit-or-record-identity`;
- the exact UUID and on-disk hash passed to `ISStore.removeUnitForUUID:`;
- the selected bundle's current LaunchServices sequence and persistent-ID
  fields before and after each operation.

All 20 runtime ABI gates passed, and the logger remains resident in VM
`<VM_HOST>`, `iconservicesagent` PID 2166, targeting Messages. SpringBoard
also remained PID 2772. Messages stayed at sequence/unit 1960, table 8,
database GUID `1F26ABB1-5FAA-455C-B070-6CC78C13193B`, application identity
`0x7a8`, before and after collection.

The install path was fast rather than delayed: scheduling occurred 1.462 ms
after invalidation entry, GC entered at 16.261 ms, and the pass returned at
92.307 ms. It checked 189 sources, accepted 186, and deleted exactly three
units whose common source was the now-invalid Cyanide predecessor identity
2632/`0xa48`:

```text
36B9F041-205C-3E4A-9624-03A575BB1DD0
FA059E4E-F139-3209-8B42-E6368574EFA3
3E5D376C-8FBB-3969-A051-DF2D1DEB127C
```

Afterward IconServices registered UUID
`52D34001-1748-3044-9150-0D8469D358B6` against source 2636/`0xa4c`; an
independent `LSApplicationRecord` read proved that source is Cyanide's new
identity.

The required themed-before-install control then resolved ownership. A fresh
Messages `68x68@3`, appearance-0, variant-0 publication produced UUID
`00C2AAE0-DC7F-3080-97AF-AC9EEB4974E8`, data hash
`5204990e93369a3ed05476f9a4773c02478cccc185427e8582924d05eea9cb5e`, and
pixel hash
`c2277e4250cdbc8d9daa0b871f7d5dca5c7990c7f350f3f32a5e2e215cb0a8f9`.
The logger paired that UUID with Messages' own source 1960/`0x7a8`, not
Cyanide's identity. The UUID and hashes survived an unhooked agent restart.

On the following Cyanide reinstall, GC checked 188 sources, accepted 187, and
removed only Cyanide UUID `52D34001-1748-3044-9150-0D8469D358B6` from the
now-invalid 2636/`0xa4c` source. A normal post-install lookup returned the
exact same themed Messages UUID, data hash, validation token, and pixel hash.
The correctly sourced 68-point themed record therefore survives Cyanide
reinstall GC. The 27-point App Library and 28-point switcher descriptors still
need the same themed-before-install fingerprint test before their reported
stock regression can be classified as persistent loss or consumer refresh.

If PID 2166 changes, re-arm the research-only logger without issuing an icon
request:

```sh
CND_VPHONE_ROOT_PASSWORD=alpine \
  python3 scripts/lab/cnd_iconservices_inspection.py watch \
  --host <VM_HOST> --bundle com.apple.MobileSMS
```

After the next controlled application reinstall, read only the causal lines:

```sh
CND_VPHONE_ROOT_PASSWORD=alpine \
  python3 scripts/lab/cnd_iconservices_inspection.py read \
  --host <VM_HOST> --lifecycle-only
```

Do not characterize this event as a database-GUID rollover or a Messages
source failure. The trace rules both out for these reinstalls. Persistent
removal occurred only for Cyanide's old own-source units; the controlled
Messages 68-point themed unit remained durable.

## Previous checkpoint: dedicated Clock-background route not proven safe

The follow-up VM experiment tested the proposed SpringBoard-only
`SBHClockApplicationIconImageView -iconForImage` redirect to a dedicated
`clock.base` leaf/source backed by the transparent
`__cnd_clock_background` asset.

The isolated route was internally correct: probe-created consumers resolved
the dedicated leaf, dedicated `ISLayeredIcon`, exact descriptor, and the
expected 204x204 transparent pixels. It did not prove the real consumer.
Opening another Home surface after post-launch injection terminated
SpringBoard in an ordinary `ISConcreteIcon` indexed-store read before a real
Clock view reached the redirect. The route log contains only the four
probe-created `view-hit` events. Startup loading also failed in the same
ordinary store-read family before the route reached `READY`.

The temporary startup-loader files were removed, the final injected code
disappeared with SpringBoard PID 821, and `iconservicesagent` remained PID 266.
No production implementation was changed. Do not promote this dedicated
route, claim visual success, or repeat startup injection from the current VM
state. See
[`vphone-ios26-clock-background-dedicated-route-result.md`](vphone-ios26-clock-background-dedicated-route-result.md)
for the exact hashes, hit count, crash, and decision.

## Previous checkpoint: persistent `clock.base` decision gate failed

The focused vPhone experiment requested the real live Clock source through
the normal outer IconServices API and through a reconstructed SpringBoard
`SBLeafIcon`. It conclusively found no canonical indexed response at the
registered `ISLayeredIcon` boundary.

The exact request was:

```text
ISLayeredIcon
  typeIdentifier = com.apple.application-icon.clock.base
ISImageDescriptor
  68×68 points @3x, appearance 0, variant 0
  specialIconOptions 2, layoutDirection 5
  digest 9E1D8C88-D314-329D-BE0F-1D262142B74B
```

`-[ISIconManager findOrRegisterIcon:]` returned each fresh input object
unchanged. `_identity` and generated-image `uuid` values changed between
getters, validation tokens were absent, `-[ISStore unitForUUID:]` returned
`nil`, and no candidate `.isdata` path existed. Clearing the icon's
process-local `ISImageCache` regenerated the same deterministic 204×204 pixels
without producing a store unit.

After `iconservicesagent` replacement and SpringBoard replacement, the result
was unchanged. The reconstructed live consumer traced as:

```text
SBLeafIcon clock.base
  -> ISIconManager findOrRegisterIcon:
  -> ISLayeredIcon imageForDescriptor:
  -> ISImageCache imageForDescriptor: (miss)
  -> ISLayeredIcon _generateImageWithDescriptor:
  -> IFConcreteImage 204×204
```

The simultaneously active daemon observer saw ordinary bundle requests reach
`ISGenerationRequest` and `ISStore`, but saw no `clock.base` request at all.
The stable data and pixel hashes therefore prove deterministic local
generation, not persistence.

The Phase 1 gate failed, so no production publisher, transaction, restore,
cache invalidation, or Clock presentation code was changed. In particular:

- ordinary `com.apple.mobiletimer` persistent records remain the complete
  static icon used by Spotlight and other static consumers;
- the five Clock hand images remain unchanged;
- Calendar and the transition descriptor matrix remain unchanged;
- the live-leaf/cache bridge remains only an experimental fallback and has
  not been promoted as the durable design;
- no fake bundle-identifier record and no generated-image UUID were used.

See
[`vphone-ios26-clock-base-persistence-result.md`](vphone-ios26-clock-base-persistence-result.md)
for the concise report and
[`vphone-ios26-clock-base-persistence-experiment.log`](vphone-ios26-clock-base-persistence-experiment.log)
for the complete trace. Any next attempt must locate a different stock
canonicalization boundary outside this locally generated `ISLayeredIcon`
path. It must not return to visible-view painting or hierarchy enumeration.

## Previous checkpoint: exact Clock and Calendar source boundaries

The newest Phase 6 VM proof invalidated the previous Clock bundle-slot and
Calendar generic image/layer redirects. The current source now implements the
corrected source boundary for both dynamic icons. Clock intentionally uses
different SpringBoard and Spotlight presentations; Calendar uses the same
exact provider boundary in both processes.

- Every ordinary `com.apple.mobiletimer` descriptor, including 68pt/v0 and
  the launch/return descriptors, continues to use the complete theme icon.
  `__cnd_clock_background` is no longer routed into that bundle matrix.
- SpringBoard keeps the live Clock. Its transparent face is installed only at
  the source observed by the newest VM trace:

  ```text
  SBHClockApplicationIconImageView -iconForImage
    -> retained SBLeafIcon
       identifier com.apple.application-icon.clock.base
    -> ISLayeredIcon type com.apple.application-icon.clock.base
    -> ISImageCache
    -> (68.00, 68.00)@3x descriptor
       digest 9E1D8C88-D314-329D-BE0F-1D262142B74B
  ```

- The obsolete `SBHClockApplicationIconImageView -iconForImage` to
  `SBIconImageView -iconForImage` redirect is restored before touching the
  exact source.
- The exact leaf's generated `ISLayeredIcon` is seeded with an `IFImage` made
  from `__cnd_clock_background`. A per-object subclass implements only
  `iconServicesIconForImage` using Apple's `objc_getAssociatedObject`, pinning
  that canonical source across subsequent Clock refreshes without replacing
  the view or publishing executable payload code.
- A process-owned registry strongly retains each leaf, source, exact
  descriptor, original image, replacement image, and original class. Restore
  puts the original image back, restores the class, clears the association,
  and deletes the registry only after every readback verifies.
- The operation scans only exact mounted
  `SBHClockApplicationIconImageView` instances, runs two normal
  `updateImageAnimated:NO` passes, and then re-verifies both source and cache.
  If no exact Clock leaf is materialized, it reports
  `clock-base-not-materialized` and does not claim success.
- The five already-working Clock hand images remain installed separately in
  `SBHClockHandsImageSet`.
- Spotlight deliberately uses a static Clock instead of recreating that live
  source. Before future result rows are constructed, its process-local
  `SBHClockApplicationIcon -iconImageViewClassForLocation:` implementation is
  redirected to the Apple-signed generic
  `SBIcon -iconImageViewClassForLocation:` implementation. The VM binary proof
  gives both methods the exact `#24@0:8@16` ABI. Future rows therefore use an
  ordinary `SBIconImageView` and consume the already-published static
  `com.apple.mobiletimer` descriptor matrix. Spotlight installs no Clock hand
  images and requires no visible `clock.base` leaf.
- The Spotlight redirect is installed inside the one existing consumer
  RemoteCall session, is backed up per process, and restores the original IMP.
  An already-constructed Clock result must be reconstructed (for example by
  closing and reopening the search UI); no broad row walk or repaint is used.
- SpringBoard always restores that static factory redirect and continues to
  the exact live `clock.base` bridge. Spotlight also restores any older live
  bridge state before enabling the static factory, solely as migration.
- Calendar never replaces a generated `CUIKIcon` or one generated response
  UUID. Both of those identities change on a normal refresh. Instead, a
  per-object subclass of the concrete `SBCalendarIconImageProvider` replaces
  only its `-preparedISIcon` getter with Apple's
  `objc_getAssociatedObject` implementation and an associated, registered
  `ISBundleIdentifierIcon` for `com.apple.mobilecal`.
- The provider's unchanged `iconImageWithInfo:traitCollection:options:` and
  `iconLayerWithInfo:traitCollection:options:` methods continue to construct
  the exact requested descriptors, call `prepareImageForDescriptor:`, and
  produce Apple's normal `UIImage` or `ICRIconLayer`. This retains the
  persistent multi-size descriptor matrix and avoids a separate Calendar face
  asset or a grey generic layer.
- Calendar install performs two bounded `reloadIconImage` passes and verifies
  that both continue to resolve the associated canonical source. Restore puts
  back the provider's original class, clears the association, verifies that
  `-preparedISIcon` again returns a `CUIKIcon` before and after a normal
  reload, and only then clears its process-owned recovery registry.
- Both obsolete class-wide Calendar redirects are explicitly restored. The
  Calendar path performs no visible-view scan and no one-shot view paint.
- Spotlight must materialize Calendar through its exact
  `SearchUIHomeScreenModel -appIconForApplicationBundleIdentifier:` method
  before obtaining the provider. On iOS 26.0 (`23A341`) this method first
  calls `beginTrackingApplicationsWithBundleIdentifiers:` and then performs
  the private `SBHIconModel applicationIconForBundleIdentifier:` lookup.
  Calling the icon model directly can return nil until a result row happens
  to create Calendar. Production verifies the exact `@24@0:8@16` ABI and
  uses the Apple materializer first, so a visible Calendar result is not a
  prerequisite.

This Clock/Calendar source pass has deliberately **not been compiled**, per the user
instruction to implement each dynamic icon separately without building. Host
source-contract tests and `git diff --check` are the only verification to run
for this checkpoint. No runtime Calendar or Clock success is claimed until a
later build and VM/device test is explicitly requested.

Read this file first in a new thread. It is the compact state of the current
SnowBoard Remix work. The older research documents remain the authority for
the detailed VM proofs, but the immediate task is the Clock/Calendar source
fix described below.

## Recovery regression checkpoint

The device report after the 2.0 build is unthemed icons after respring and a
failed recovery. The new 68pt `0x20000` descriptor remains a runtime suspect;
the current evidence does not establish that it is the cause or that its
publication is supported on the physical device. This recovery change does
not alter that descriptor profile or enable presentation during Initial Apply.

Restore now skips a descriptor only when its saved publication explicitly
proves every required mutation flag false and the hook restored/quiescent.
Contradictory success evidence, missing flags, and missing publication reports
remain recovery work. A prior failed Restore must independently prove no
mutation as well. In particular, an unreported `dispatch-possible` checkpoint
is crash-ambiguous and is never discarded just because its state sounds pending.
Whole-journal preflight discard uses the same proof. Mixed journals clear only
after each changed/ambiguous descriptor verifies stock and each skipped
descriptor has that strict no-mutation proof.

Persistent recovery success is separate from session/presentation cleanup.
`persistent-restored-cleanup-partial` reports successful persistent recovery
with cleanup warnings; those warnings do not recreate cleared journals.
`persistentDataClean` describes store state, while `persistentRecoveryOK`
also requires journal cleanup. Therefore a strictly untouched journal whose
local deletion fails is data-clean but still reports unsuccessful recovery
cleanup through `discardFailures` and `persistentRecoveryOK = false`.

Validation includes a host-compiled Foundation fixture for the actual proof
helpers and source checks for restore ordering/status separation. No device
or VM operation is part of this change; physical recovery still needs testing.

## Implementation checkpoint: manual presentation split

The September 22 workflow split is implemented, but the durable Clock and
Calendar face replacements remain unfinished:

- Initial Apply publishes persistent records and performs the existing
  SpringBoard cache refresh only. It no longer stages dynamic inputs or runs
  either presentation repair. The transparency setting does not change this.
- The action and coordinator API are now **Apply SpringBoard Tweaks** /
  `applySpringBoardTweaks`. Existing transparency and Clock hand-image work
  remain here. Both obsolete one-shot face-paint helpers have been removed.
- Spotlight repair retains its existing transparency operation independently.
  Its coordinator reports requested Clock/Calendar sources as not attempted
  and unsupported, rather than claiming the dynamic faces are fixed.
- A successful transparency install retains its lifecycle PID even when the
  overall tweaks action is partial because dynamic source work is pending.
- The core publication profile now includes 68pt appearance 0, variant
  **0x20000 (131072 decimal)**. Apple's descriptor description uses `v:%lx`;
  the captured `v:20000` must not be interpreted as decimal 20000. This format
  is present in the local 23A341 dyld cache `.13`. Normal 68pt and 28pt variant
  0 records were already in the profile. There are now 10 core descriptors,
  or 12 with snippet extras.

## Implementation checkpoint: bounded SpringBoard retained consumers

The September 24 cache audit found two omissions in the one-shot Apply/Restore
refresh; both are process-local consumer retention, not missing descriptors:

- `resetAllIconImageCaches` replaced `SBHIconManager.iconImageCache`, but the
  live `SBRootFolderController`, root view, Home pages, dock, and mounted icon
  views remained bound to the old cache. On PID 2772 the manager was
  `0xb87bc1720` while all three root/dock lists still used `0xb88380a00`.
  Production now purges first and then calls the exact
  `SBFolderController.setIconImageCache:` implementation on the root. Its
  stock propagation rebound 3/3 lists and Files's observer without restarting
  SpringBoard.
- A switcher title-controller rebuild can compute the new 28-point image yet
  leave the visible icon container unchanged. Disassembly shows
  `SBFluidSwitcherItemContainerHeaderView.setTitleItems:animated:` branching
  past both image setters when its `SBDisplayItem` key is unchanged.
  Production now uses only the three class-dumped visible-consumer maps,
  clears their `titleItems`, and then runs `_performUpdateHandler`. Caps are
  128 title controllers and 384 deduplicated consumers; no window/view walk
  or additional RemoteCall session was added.

The Home rebind has focused runtime pointer proof. A complete 23A341
SpringBoard Objective-C metadata sweep found no additional switcher-title
image cache: `SBAppSwitcherSnapshotImageCache` is card-snapshot-only, while
the icon-bearing remainder is the retained title-item/container state covered
by the new clear/rebuild sequence. The current VM had no materialized
switcher title-controller map, so an already-visible Files card still needs
the before/after hash acceptance probe. Notifications likewise still need a
real materialized row. The complete no-restart Apply/Restore loop must not be
claimed until those two live-consumer proofs pass.

Existing active journals with the previous profile must be restored before
reapplying; the existing transaction guard deliberately does not overwrite
their recovery data or automatically restore them.

The remaining blocker is a verified durable production source operation for
future `clock.base` / `CUIKIcon` generations. The traces establish source
identity, but do not establish a persistent source cache or a suitable stock
signed implementation that serves replacement results after regeneration.
Seeding one observed result or repainting a view does not establish that.
Clock/Calendar requests therefore return
`dynamic-source-replacement-unavailable`, while transparency success remains
separately visible. No dynamic source fix or device runtime success is claimed.

Validation for this checkpoint includes the focused PID-2772 Home cache
pointer/rebind probe plus host tests, build, and analyzer. The switcher and
notification live-consumer acceptance steps remain VM work and must precede
physical-device acceptance.

## Current position

The non-bundle IconServices theme engine works on a physical iOS 26 device:

- themed structured IconServices responses persist across
  `iconservicesagent` replacement and device restart;
- the descriptor matrix covers the tested Home Screen, folder, App Library,
  app-switcher, notification, and Spotlight sizes;
- SpringBoard and Spotlight can display transparent themed pixels using
  process-local Apple-signed IMP redirects;
- Apply and Restore maintain per-application recovery journals;
- the Spotlight watcher is manual and Spotlight-only; Apply does not
  automatically start it.

The current blocker is **not** general icon publication. Clock and Calendar
now have source-level implementations awaiting runtime proof:

- SpringBoard uses the exact `clock.base` leaf/cache bridge plus its five
  themed hand images;
- Spotlight uses the generic static icon-view factory and the persistent
  `com.apple.mobiletimer` response, avoiding the live leaf entirely;
- Calendar uses the exact `SBCalendarIconImageProvider -preparedISIcon`
  boundary and leaves Apple's image/layer presentation pipeline intact.

Do not return to bundle `Info.plist`, `Assets.car`, legacy-PNG replacement, or
LaunchServices registration. Those were earlier experiments. The production
route is the persistent IconServices store plus process-local consumer
presentation mappings.

## Working architecture

```text
SnowBoard theme archive
  -> import bundle-id PNGs and special Clock assets
  -> discover installed apps inside one iconservicesagent session
  -> render structured payloads for the descriptor matrix
  -> replace exact indexed IconServices store/cache responses
     using only stock signed methods on physical hardware
  -> close the one retained iconservicesagent RemoteCall session
  -> SpringBoard cache refresh only; Initial Apply finishes
  -> manual Apply SpringBoard Tweaks
       transparency and app-switcher flat-image redirects
       exact live clock.base face and Clock hand-image work
       exact Calendar preparedISIcon provider source
  -> separate manual Spotlight repair
       existing transparency redirects
       static Clock icon-view factory using the persistent descriptor matrix
       exact Calendar preparedISIcon provider source
  -> optional manual Spotlight-only PID watcher for later Spotlight restarts
```

The physical publisher does **not** execute copied Cyanide code inside
`iconservicesagent`. The VM one-shot generation callback proved the store
semantics, but copied executable code is not safe on a physical Apple daemon.
The device publisher instead uses stock signed methods to preserve the stock
UUID and validation token while replacing the exact store unit and canonical
cache response.

The core descriptor point sizes are:

```text
13, 20, 27, 28, 38, 48, 64, and 68 points at 3x
```

Appearance-specific variants are also required where observed. See
`docs/research/vphone-ios26-icon-descriptor-matrix.md` for the exact consumer
mapping and UUID evidence.

## Proven components

### Persistent publication

Primary implementation:

- `Cyanide/installer/CNDSnowBoardRemix.m`
- `Cyanide/installer/CNDIconServicesPublisher*.{h,m,c,S}`
- `Cyanide/installer/CNDIconServicesDescriptorSpec.{h,m}`
- `Cyanide/installer/CNDIconServicesStructuredPayload.{h,m}`
- `Cyanide/installer/CNDIconThemeImageProcessor.{h,m}`
- `Cyanide/installer/CNDIconThemeTransaction.{h,m}`

The current device route is documented in:

- `docs/research/vphone-ios26-iconservices-persistence-and-consumer-mappings.md`
- `docs/research/vphone-ios26-icon-descriptor-matrix.md`

### Consumer transparency and refresh

Primary implementation:

- `Cyanide/installer/CNDIconServicesConsumerHook.{h,m}`
- `Cyanide/installer/CNDIconServicesConsumerLifecycleCoordinator.{h,m}`
- `Cyanide/installer/CNDIconServicesConsumerKernelInstaller.{h,m}`
- `Cyanide/tweaks/themer.{h,m}`

Important lifecycle rules already encoded in the tree:

- Apply performs only persistent publication and the existing cache refresh.
- Presentation work is explicitly requested through the separate actions.
- The explicit watcher monitors only Spotlight.
- SpringBoard repair is a manual one-shot operation.
- A target process gets one RemoteCall session for its combined work; do not
  open one RemoteCall per icon or per redirect.
- A process-local mapping/redirect lasts until that process exits. Persistent
  IconServices data is independent and survives those exits.

### Restore and journals

Each application has a journal whose state reflects persistent store state,
not the overall UI operation result. A successful exact stock readback means
the persistent data is clean even if later presentation cleanup fails.
`persistent-stock-verified` must not be treated as dirty.

Do not reintroduce an automatic restore at the beginning of Apply. Apply and
Restore are separate operations.

## Historical Clock regression that led to the exact source fix

Theme import in `Cyanide/tweaks/snowboardlite.m` correctly prefers the
device-specific Clock background in this order:

```text
ClockIconBackgroundSquare@3x~iphone.png
ClockIconBackgroundSquare@2x~iphone.png
ClockIconBackgroundSquare~iphone.png
ClockIconBackgroundSquare@3x.png
ClockIconBackgroundSquare@2x.png
ClockIconBackgroundSquare.png
```

For the active theme, `ClockIconBackgroundSquare@2x~iphone.png` is the desired
transparent face. It is staged as `__cnd_clock_background.png` and resized to
the device's 68-point raster. The generic `@2x.png` is an opaque stock-like
face and must not win selection.

The five special Clock component images are staged as:

```text
__cnd_clock_hours
__cnd_clock_minutes
__cnd_clock_seconds
__cnd_clock_hour_minute_dot
__cnd_clock_second_dot
```

`themer_configure_clock_calendar_sources_in_session()` in
`Cyanide/tweaks/themer.m` successfully installs those into
`SBHClockHandsImageSet` for the known appearances. The live hands were
confirmed working on device.

The failed background sequence was:

1. Redirecting `SBHClockApplicationIconImageView -iconForImage` to
   `SBIconImageView -iconForImage` produced a background, but it was the normal
   themed `com.apple.mobiletimer` application icon rather than the transparent
   Clock face.
2. The latest change restores the stock `iconForImage` implementation and
   calls `themer_apply_live_clock_background()`, which sets
   `displayedImage`/layer contents on mounted Clock views once.
3. The live Clock refresh immediately reconstructs its background from its
   own source, overwriting that one-shot paint. The observed result is the
   **stock Clock face**, not a blank image.

That direct repaint and the generic redirect have now been removed as the
primary Clock solution. The exact source/cache bridge described in the latest
checkpoint is the implementation derived from this evidence.

### Binary evidence identifying the real Clock source

The iOS 26 SpringBoardHome class dump and disassembly establish this path:

```text
SBHClockApplicationIconImageView -iconForImage
  -> return existing _clockBackgroundIcon, or
  -> clockIconBackgroundTypeIdentifierForNumberingSystem:
       default: com.apple.application-icon.clock.base
  -> create SBLeafIcon for that graphic type
  -> add SBHClockBackgroundIconDataSource
  -> setClockBackgroundIcon:
  -> return the background SBLeafIcon

SBHClockApplicationIconImageView -updateImageAnimated:
  -> superclass image update
  -> iconForImage
  -> regenerate/display the background source
```

Useful local evidence files created during analysis:

- `/tmp/sbh-objc.txt`
- `/tmp/iconservices_objc.txt`
- `/tmp/iconservices-dsc-objc-verbose.txt`

The key conclusion is that the Clock face is **not** the bundle response for
`com.apple.mobiletimer`. It is the graphic IconServices type
`com.apple.application-icon.clock.base` exposed through a retained
`SBLeafIcon`. That is why both the generic redirect and direct repaint were
wrong in different ways.

### VM trace evidence for the Clock source

The bounded read-only tracer in `scripts/lab/cnd_dynamic_icon_trace.{m,py}`
was injected into a fresh SpringBoard process on the iOS 26 VM. It captured
the first IconServices request made inside the retained Clock leaf:

```text
SBLeafIcon
  identifier/type: com.apple.application-icon.clock.base
  data source: SBHClockBackgroundIconDataSource
  -> ISLayeredIcon
     _typeIdentifier: com.apple.application-icon.clock.base
     _imageCache: ISImageCache
  -> ISImageDescriptor (68.00, 68.00)@3x
     digest: 9E1D8C88-D314-329D-BE0F-1D262142B74B
     specialIconOptions=2 shouldApplyMask=1 drawBadge=1
     languageDirection=1 layoutDirection=5
  -> IFConcreteImage
     204x204, alpha=1, 16 bpc / 64 bpp, rowbytes=1632, bytes=332976
```

Repeated requests returned generated image UUIDs rather than one stable UUID.
The source identity and descriptor digest were stable. This proves that the
failed background attempt was not producing an empty raster: the owned source
continued to resolve and repaint a valid stock `IFConcreteImage`. The working
bundle-icon theming path and this Clock path do not address the same source;
the Clock fix must translate the staged face into the response for this exact
`ISLayeredIcon`/descriptor request (or its narrow cache response), not paint a
background `UIImage` onto the view.

## Immediate next task

The Clock and Calendar source implementations are complete at source level but
intentionally uncompiled. Their next step is an explicitly requested
build/runtime validation:

1. For SpringBoard Clock, require `clock-base-source-ready`, the exact digest
   readback, at least one retained source state, and two refresh passes.
2. For Calendar, require `calendar-provider-source-ready`, one retained state
   for every distinct active canonical/live-leaf provider, and exactly one
   verified provider `reloadIconImage` callback per provider. The Calendar
   repair must not report either obsolete generic redirect as installed.
3. Visually verify the transparent Clock face remains while the themed hands
   move, Calendar displays the persistent themed icon rather than a grey plate,
   and launch/return plus App Library sizes continue to use complete icons.
4. Restore and require both `clock-base-restored` and
   `calendar-provider-restored`. A result that survives only until the second
   normal refresh is not success.

Do not solve this by adding a timer, resident repair loop, child overlay, or a
recursive all-view walk.

## Calendar state

Calendar is a separate source problem. iOS 26 has no specialized
`SBHCalendarApplicationIconImageView`. The binary path is:

```text
SBHCalendarApplicationIcon
  makeIconImageWithInfo:traitCollection:context:options:
    -> SBCalendarIconImageProvider
       iconImageWithInfo:traitCollection:options:

SBHCalendarApplicationIcon
  makeIconLayerWithInfo:traitCollection:context:options:
    -> SBCalendarIconImageProvider
       iconLayerWithInfo:traitCollection:options:

SBCalendarIconImageProvider -preparedISIcon
  -> ISIcon initWithDate:calendar:format:
```

The VM trace filled in the concrete source details that the class dump did not
provide:

```text
ISIconFactory initWithDate:calendar:format: (format=0)
  -> CUIKIcon
     _iconGenerator: CUIKDefaultIconGenerator
  -> ISImageDescriptor (32.00, 32.00)@1x
     digest: 8BBB8318-1944-3994-AAD4-A1715909ED9E
     specialIconOptions=2 shouldApplyMask=1 drawBadge=1
     languageDirection=1 layoutDirection=5
  -> IFConcreteImage
     40x40, alpha=1, 16 bpc / 64 bpp, rowbytes=320, bytes=12848
```

New date-specific `CUIKIcon` instances and new result UUIDs are generated on
refresh. `SBCalendarIconImageProvider` then renders the prepared source for
the requested presentation size (including the observed 68-point, 3x path).
This is a procedural/date-specific result, not a persistent static UUID that
should be replaced once.

The binary and VM traces establish the stable interception point more narrowly
than the earlier report:

```text
SBHCalendarApplicationIcon
  -> SBCalendarIconImageProvider
     -> preparedISIcon
        stock: new CUIKIcon for the current date
        themed: registered ISBundleIdentifierIcon(com.apple.mobilecal)
     -> prepareImageForDescriptor: using the outer requested descriptor
     -> UIImage or ICRIconLayer
```

`SBCalendarIconImageProvider` has the exact `-preparedISIcon` ABI
`@16@0:8`. Its
`-iconImageWithInfo:traitCollection:options:` and
`-iconLayerWithInfo:traitCollection:options:` methods both have the measured
`@64@0:8{SBIconImageInfo={CGSize=dd}dd}16@48Q56` ABI. Their disassembly shows
that both obtain `preparedISIcon`, construct the outer size/scale/trait
descriptor, call `prepareImageForDescriptor:`, and then perform their normal
UIKit/IconRendering conversion. Therefore the source now uses a per-provider
object subclass whose only added method is
`-preparedISIcon`, implemented by Apple's signed `objc_getAssociatedObject`.
The selector itself is the association key. The associated object is the
canonical `ISBundleIdentifierIcon` returned by
`ISIconManager -findOrRegisterIcon:` for `com.apple.mobilecal`.

The 23A341 `ISIcon` metadata gives `-prepareImageForDescriptor:` the exact
object-returning ABI `@24@0:8@16`, not `v24@0:8@16`. Its disassembly first
calls `imageForDescriptor:`, drives `_prepareImagesForImageDescriptors:` when
that result is absent or a placeholder, performs the refill lookup, and
returns the resulting image. The descriptor tracer uses that object-returning
signature so instrumentation cannot discard or corrupt this consumer result.

Production deliberately does not invoke this method as a separate RemoteCall
verification step. Physical arm64e testing on 2026-09-29 produced two
SpringBoard `EXC_ARM_PAC_FAIL` reports: one while `NSInvocation
retainArguments` retained the injected descriptor/source argument, and one in
`-[NSUUID isEqual:]` after UUID/token objects crossed separate RemoteCall
invocations without safe ownership. Persistent response bytes and identity
are already verified by the publisher. The live-process operation is limited
to replacing the distinct source cache, invoking Apple's native provider
reload, verifying the consumer generation advance and observing the cache
dictionary afterward; Apple performs `prepareImageForDescriptor:` inside its
ordinary provider/consumer call chain.

This is deliberately not a mutation of the internal 32x32 `CUIKIcon` response.
That response and its UUID are regenerated. It is also not a generic
`SBLeafIcon`/`SBIcon` redirect: those paths skipped part of the provider and
produced the grey plate. Both obsolete redirects are restored before the
provider bridge is installed. No specialized Calendar view class, recursive
view walk, or painted overlay is used.

The process registry strongly retains each covered Calendar model, provider,
replacement source, and original provider/source class. SpringBoard cannot
treat one retained provider as global: its canonical
`applicationIconForBundleIdentifier:` object and the Calendar entry in
`leafIconsUniquedByApplicationBundleIdentifier` can be distinct objects, and
each `SBHCalendarApplicationIcon` owns its own provider. Every invocation with
an empty process registry reacquires that bounded active set, deduplicates
provider pointers, installs one bridge per provider, and rejects incomplete
coverage. A repeated repair in the same process instead validates every
retained model/provider/source relationship and returns through an idempotent
fast path without rediscovery or regeneration. Spotlight continues to use only
its exact private-model materializer for the initial installation.

The resolver must also remain target-role aware. `SearchUIHomeScreenModel`
exists inside SpringBoard, but its Calendar icon is not the mounted Home
consumer. SpringBoard therefore disables the SearchUI graph entirely and
resolves through `SBIconController -> SBHIconManager -> iconModel`; only the
Spotlight target may use `SearchUIHomeScreenModel`. A physical trace caught the
former bug as themed canonical `0xb2a1b37a0` versus mounted Home
`0xb27d64820`. After the role gate, both identities were `0xb27d64820`, its
source changed from `CUIKIcon` to `ISBundleIdentifierIcon`, generation moved
2 to 3, and the four mounted layers repainted immediately without a view scan.
Spotlight follows the equivalent private-model rule: its SearchUI materializer
may initialize the graph but cannot supply the accepted identity; Calendar is
reacquired from the private `SBHIconModel` before any provider is bridged.

The 23A341 disassembly also establishes that this does not require a manual
view repaint. `SBCalendarIconImageProvider -reloadIconImage` synchronously
calls its delegate's `calendarIconImageProviderHasChanged:`, and
`SBHCalendarApplicationIcon` implements that delegate method as a tail call to
its inherited `reloadIconImage`. `SBIcon -reloadIconImage` increments
`imageGeneration`, updates its registered icon-layer views, and notifies its
ordinary image observers. Production issues that one Apple-owned invalidation
callback per newly bridged active provider and verifies the generation advanced
by exactly one. A same-process fast-path repair issues no callback and reports
zero reloads and generation advances. It never scans windows/views, calls
`setDisplayedImage:`, or paints an overlay.

Restore reinstalls every registered provider's original class, clears its
association, proves that the getter again returns a `CUIKIcon` before and after
the provider callback, and only then removes the registry. The same source
bridge is used in SpringBoard and Spotlight, preserving all observed 68pt,
48pt, and 27pt outer presentations through Apple's existing provider logic.

Host-side copies of the raw VM traces are preserved at:

```text
${HOME}/Library/CyanideVPhoneLab/evidence/phase6/cyanide-dynamic-icon-trace-pre-clock-scope.log
${HOME}/Library/CyanideVPhoneLab/evidence/phase6/cyanide-dynamic-icon-trace-clock-scope.log
```

The corrected trace contains 1,912 records, including 12 Clock source-request
records and 14 Calendar source-request records. Matching copies remain in the
VM under `/var/tmp/`.

## Spotlight dynamic-icon trace

A wildcard `ISBundleIdentifierIcon` trace was first run inside Spotlight while
searching for Clock and Calendar. Neither `com.apple.mobiletimer` nor
`com.apple.mobilecal` crossed that ordinary bundle-icon boundary. A second
trace using the dynamic hooks proved why: Spotlight loads the same specialized
SpringBoardHome models as SpringBoard.

For the visible Spotlight Clock result:

```text
SBHClockApplicationIconImageView / SBHClockApplicationIcon
  -> SBLeafIcon + SBHClockBackgroundIconDataSource
  -> ISLayeredIcon type com.apple.application-icon.clock.base
  -> 68x68@3 descriptor, digest 9E1D8C88-D314-329D-BE0F-1D262142B74B
  -> 204x204 IFConcreteImage
```

The Spotlight Clock view also contained the normal live hand layers. For the
visible Calendar result:

```text
SBHCalendarApplicationIcon
  -> SBCalendarIconImageProvider
  -> CUIKIcon internal 32x32@1 request
  -> 40x40 IFConcreteImage
  -> provider 68x68@3 UIImage result, 204x204 pixels
```

The source identities and descriptors match the SpringBoard Home Screen path,
but production no longer shares the live Clock source bridge. SpringBoard
uses that exact live source. Spotlight instead bypasses the specialized live
view for **future rows** by redirecting the Clock model's view-class factory to
the generic `SBIcon` implementation. That makes Spotlight consume the static
ordinary bundle response already present in the persistent descriptor matrix,
without requiring a visible leaf, live hands, or a `clock.base` cache edit.
This is a process-local selection and must be reinstalled for a new Spotlight
PID; an existing row must be reconstructed after installation.

An explicitly marked App Library pass covered both category subfolders and the
alphabetical list. Calendar provider outputs were observed at 27x27@3 (category
mini-icon), 48x48@3 (list row, from the preceding cached/list pass), and
68x68@3 (large tile). Every size continued to originate from the same internal
32x32@1 `CUIKIcon` generation request. Clock's live category/subfolder view
remained 68 points and its background leaf continued to request the same
68x68@3 `clock.base` graphic source. A 48x48@3 outer Clock application-icon
result was also captured for the list path. No additional dynamic source
identity is required for these App Library surfaces: smaller/static consumers
remain covered by the ordinary descriptor matrix, while live Clock surfaces
derive from the one 68-point graphic source.

Additional raw host-side captures:

```text
${HOME}/Library/CyanideVPhoneLab/evidence/phase6/cyanide-icon-descriptor-Spotlight-clock-calendar.log
${HOME}/Library/CyanideVPhoneLab/evidence/phase6/cyanide-dynamic-icon-trace-spotlight-clock-calendar.log
${HOME}/Library/CyanideVPhoneLab/evidence/phase6/cyanide-dynamic-icon-trace-app-library.log
```

## App launch/return stock flash: isolated Files reproduction

The stock flash on both app launch and return to Home is now reproduced with
`com.apple.DocumentsApp` (Files) under a bounded SpringBoard trace. This was a
valid replacement for eBay: eBay 6.271.0 has a pre-existing recursive
`dispatch_once` launch crash (`EXC_BREAKPOINT`/`SIGTRAP`) also present in
September 19 crash reports, before the icon experiment.

The controlled persistent replacement covered only the ordinary 68x68@3
descriptor (`v:0`, digest `9E1D8C88-...`). Those requests consistently
returned themed UUID `7E058EC4-...`, marker 1, pixel SHA-256
`55aed675550a...`. The transition path asks for separate stock records:

- 28x28@3 `v:0` returned stock UUID `ABF9EE18-...`, 87x87 pixel SHA-256
  `166ffb22bf80...`.
- 68x68@3 `v:20000`, digest `E0F23702-...`, returned stock UUID
  `A6B14006-...`, pixel SHA-256 `41e4fe1eea3a...`.
- `SBHIconImageCache` options 6 passed that `v:20000` raster unchanged into
  `updateImageContents...` and `setDisplayedImage:`. The bounded CALayer
  snapshot contained the same stock pixel hash.
- The subsequent ordinary 68-point `makeIconLayer...` path returned the
  themed `v:0` record and its contents child contained `55aed675550a...`.

This establishes the immediate cause: durable publication of only the normal
Home descriptor leaves the transition-specific `v:20000` response (and the
28-point transition request) stock. SpringBoard displays that stock raster,
then replaces it with the normal themed layer, producing the visible flash.
The capture observed the two `v:20000` stock-population passes and the later
themed layers. The user's return/open observation markers were appended after
both gestures, so they do not independently timestamp which pass is launch
versus return. A switcher/crossfade-container plus view-attachment trace would
be needed only to label the two passes; it is no longer needed to prove the
stock source.

### Transition constructor and publication correction

The original production addition did not actually construct this descriptor.
It passed `0x20000` as the first argument of
`+imageDescriptorWithIconVariant:options:`, but that argument is a descriptor
preset enum. The invalid preset fell back to `v:0`, so the supposed transition
publication overwrote/reused the ordinary Home identity. Runtime inventory
found the real property at `_variantOptions` (offset 32) with public
`setVariantOptions:` / `variantOptions` methods. The exact stock construction
is:

1. call `+imageDescriptorWithIconVariant:options:` with preset `0`, options
   `0`;
2. copy the descriptor;
3. set size 68x68, scale 3, appearance 0;
4. call `setVariantOptions:0x20000` and read back `variantOptions`;
5. require digest `E0F23702-19F0-35BF-B6A3-67328315366B` in the VM proof.

The corrected disposable Files publication persisted themed UUID
`C2796BDB-32FF-3376-9A6A-9F2343A131DB`. A fresh unhooked lookup returned
structured-data SHA-256
`66d4ece524a3390044acef073526f5b7f8682b0d1872284796f7426084864ad1`
and pixel SHA-256
`c2277e4250cdbc8d9daa0b871f7d5dca5c7990c7f350f3f32a5e2e215cb0a8f9`.
On the next controlled Files launch/return, the traced `v:20000` lookup,
`SBHIconImageCache` result (options 6), `updateImageContents...` argument, and
`setDisplayedImage:` argument all carried that same themed pixel hash. The
transition path is therefore now proven, not inferred.

Production now uses preset zero plus `setVariantOptions:` in both its direct
stock descriptor builder and its one-shot payload builder. The payload hook
also reads the incoming descriptor's actual `variantOptions` before matching,
so normal `v:0` requests cannot satisfy the `v:20000` transaction.

Raw captures:

```text
${HOME}/Library/CyanideVPhoneLab/evidence/phase6/cyanide-home-return-trace-files-open-close-flash.log
${HOME}/Library/CyanideVPhoneLab/evidence/phase6/cyanide-home-return-trace-ebay-stock-only.log
```

Files currently retains the isolated themed 68-point record for follow-up.
Restore it with:

```sh
CND_VPHONE_ROOT_PASSWORD=alpine \
  python3 scripts/lab/cnd_iconservices_cache_theme.py restore \
  --bundle com.apple.DocumentsApp --host <VM_HOST>
```

## Current source/artifact status

The repository is intentionally very dirty and contains the user's larger
work. Current tracked diff summary is approximately:

```text
48 files changed, 56,325 insertions, 3,128 deletions
```

There are also many required untracked SnowBoard Remix, IconServices, lab,
font, and research files. Do not clean, reset, checkout, or mass-delete this
tree.

Latest existing artifact at the time of this handoff:

```text
<repository-root>/build/Cyanide-1.6.ipa
SHA-256: 31d0e79c27e2bc53ed2dee4030610a08487b7c59b0cab73d3ff5056f3424fc57
Built: 2026-09-22 17:19:22 EDT
```

That artifact contains the currently broken one-shot Clock background repaint.
It is useful for reproducing the regression, not as a known-good dynamic-icon
build.

Current deterministic checks:

```text
python3 -m unittest discover -s scripts/tests
Ran 91 tests: OK

python3 -m unittest scripts.tests.test_dynamic_icon_trace
Ran 18 tests: OK

git diff --check
PASS
```

The tests passing does not override the device result. The Clock background
regression is a missing runtime ownership assertion.

## Build and verification

From the repository root:

```sh
cd <repository-root>
python3 -m unittest discover -s scripts/tests
git diff --check
./scripts/build.sh
```

Optional analyzer after the functional fix:

```sh
xcodebuild analyze \
  -project Cyanide.xcodeproj \
  -scheme Cyanide \
  -sdk iphoneos \
  -configuration Debug \
  -derivedDataPath build/AnalyzeDerived \
  CODE_SIGNING_ALLOWED=NO
```

For device validation, test in this order:

1. Apply the theme with transparency enabled.
2. Confirm normal application icons remain themed.
3. Observe Clock through at least two live update cycles:
   transparent themed face, themed moving hands, no stock face, no blank face.
4. Confirm Calendar separately; do not infer Calendar success from Clock.
5. Run manual SpringBoard repair and repeat the Clock update-cycle check.
6. Restore and confirm persistent journal state becomes clean based on exact
   stock store readback even if a later presentation operation reports an
   independent failure.

## Non-negotiable constraints

- Work only in `<repository-root>` unless explicitly told otherwise.
- Preserve all unrelated user changes and untracked research files.
- Use `apply_patch` for edits.
- Do not delegate this continuation to Luna; the user explicitly requested
  direct work in the primary thread.
- Do not reopen the abandoned eBay bundle-mutation implementation.
- Do not execute copied Cyanide publisher code inside physical Apple daemons.
- Do not open multiple RemoteCall sessions for the same process operation.
- Do not use a per-icon RemoteCall, live repair timer, or broad recursive view
  walk.
- Do not claim visual success from store hashes, method readback, or passing
  source-shape tests. Device observation is required for Clock/Calendar.

## Older details that do not need to be rediscovered

- `docs/research/vphone-ios26-icon-control-flow.md` — original VM control flow.
- `docs/research/vphone-ios26-iconservices-persistence-and-consumer-mappings.md`
  — durable publication plus SpringBoard/Spotlight presentation contract.
- `docs/research/vphone-ios26-icon-descriptor-matrix.md` — all measured icon
  sizes/surfaces and app-switcher boundary.
- `docs/research/vphone-ios26-spotlight-breakpoint-phase1.md` — earlier
  Spotlight interception research.
- `docs/snowboard-remix.md` — product-facing SnowBoard Remix overview.

The next thread should implement the Clock response replacement at the
measured `ISLayeredIcon`/descriptor boundary, then apply the same narrow
generated-result strategy to Calendar's `CUIKIcon`/provider path. General
IconServices publication, descriptor discovery, and transparent consumer
presentation are already proven and should remain intact.
