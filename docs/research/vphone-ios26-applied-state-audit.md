# iOS 26 applied-state audit verification

**Verified:** 2026-09-25
**Build:** iOS 26.0, 23A341, iPhone17,3
**Dyld cache:** `${HOME}/Library/CyanideVPhoneLab/analysis/dyld-23A341/23A341__iPhone17,3/dyld_shared_cache_arm64e`
**Restore tree:** `${HOME}/Library/CyanideVPhoneLab/VMs/cyanide-ios26-base/iPhone17,3_26.0_23A341_Restore`

## Conclusion

The applied-state audit now matches the 23A341 Objective-C metadata and
control flow for every operation it performs. It separately observes:

1. the exact descriptor's current-digest persistent index entry;
2. the indexed `.isdata` store unit and its structured-data hash;
3. every LaunchServices source identifier registered for that unit;
4. the current `LSApplicationRecord.persistentIdentifier`;
5. an optional process-local `ISImageCache` response; and
6. bounded SpringBoard canonical, live-leaf, and materialized switcher icon
   identities.

The persistent proof does not depend on the process-local cache being
populated. An empty process cache is valid evidence and cannot be mistaken for
a missing persistent record. The audit performs no image generation, cache
purge, consumer reload, persistent removal, or persistent write.

One bounded process-local side effect is disclosed explicitly:
`-[ISIconManager findOrRegisterIcon:]` is the synchronized way to find the
canonical icon whose `ISImageCache` is being observed. When no equal icon is
already registered, it can temporarily put the fresh audit icon in the
manager's weak registry. Releasing the fresh icon removes that weak entry.
This does not create an image, index a descriptor, or write the store.

This is a static binary verification of ABI, layout, ownership, and control
flow. It cannot prove that the physical RemoteCall transport will complete
each call. One physical run is still required to validate transport execution
and capture the pre-reinstall baseline.

## IconServices binary evidence

| Audit operation | 23A341 evidence | Audit behavior | Result |
| --- | --- | --- | --- |
| Exact descriptor construction | `ISImageDescriptor +imageDescriptorWithIconVariant:options:` is `@24@0:8i16i20`; size, scale, appearance, variant-options, and ignore-cache setters/getters have the encodings gated in the transport | Builds a copied transient descriptor and requires exact typed readback | Correct |
| Current application identity | `ISBundleIdentifierIcon -initWithBundleIdentifier:` at `0x1a7216398` constructs an `LSApplicationRecord` with `allowPlaceholder:YES` and incorporates its current persistent identity/version in the icon digest | Creates a fresh icon for the lookup; it does not reuse a possibly stale retained digest | Correct |
| Current descriptor index | `ISIconCache -findStoreUnitForIcon:descriptor:UUID:validationToken:` at `0x1a7256044`, encoding `B48@0:8@16@24^@32^@40` | Looks up the fresh icon and exact descriptor and copies both out parameters through the pinned scratch page | Correct and observation-only |
| Manager/cache ownership | `ISIconManager._iconCache` is `+0x10`; `ISIconCache._store` is `+0x10`, `_cacheURL` is `+0x18` | Validates ivar name and exact offset before `object_getIvar` | Correct |
| Optional process cache | `ISConcreteIcon._imageCache` is `+0x20`; `ISImageCache -imageForDescriptor:` at `0x1a7219a54` reads its dictionary under the cache lock | Uses `findOrRegisterIcon:` only to obtain the canonical icon, then reads its `ISImageCache` directly | Correct; does not refill |
| Forbidden cache-refilling path | `ISConcreteIcon -imageForDescriptor:` at `0x1a7229fa4` falls through to `_imageFromStoreForDescriptor:` on a miss | The audit does not call this method | Correct |
| Cached response layout | `IFImage._data` is `+0x18`; `IFCacheImage._uuid` is `+0x90`; `_validationToken` is `+0x98` | Reads the three validated ivars directly; hashes copied data locally | Correct |
| Backing store URL | `ISStore._storeURL` is `+0x10`; `-storeURL` at `0x1a7206848` is an `objc_getProperty` tail thunk | Uses the validated ivar, avoiding the unsafe synthetic property-return boundary | Correct |
| Backing store unit | `+[ISStoreUnit storeUnitWithStoreURL:UUID:]` at `0x1a72626ac`; `ISStoreUnit._UUID` is `+0x8`, `_data` is `+0x10`; `-isValid` is `B16@0:8` | Maps the indexed unit directly, then verifies validity, UUID equality, and structured-data hash | Correct and observation-only |
| Forbidden store memoization | `ISStore -unitForUUID:` at `0x1a723342c` inserts a newly opened unit into `ISStore._registry` on a miss | The audit does not call it | Correct |
| Source-registry location | `ISMutableIconCache` initializes `store-source-registry.map` below the same cache URL | Opens that exact existing file; no guessed daemon getter is used | Correct |
| Existing map validation | `+[NSData(ISMutableStoreIndex) _ISMutableStoreIndex_mappedDataWithURL:]` at `0x1a721be04`; `-[NSData(ISStoreIndex_BlobTable) _ISStoreIndex_isValid]` at `0x1a7206714` | Requires the file to exist, maps it, and validates the header before query | Correct; no create/repair selector called |
| Transient map object | `ISStoreMapTable._data` is `+0x10`; `-initWithURL:capacity:` at `0x1a721a1b0` only stores URL/capacity; `-data` at `0x1a721aabc` can create/repair when `_data` is absent | Injects the already validated mapping into a transient table before any query, so `-data` cannot enter create/repair | Correct |
| Source-registry value shape | `ISStoreMapTable -dataForUUID:` at `0x1a721a2ec` derives the UUID XOR/modulo bucket, walks a strictly increasing node-reference chain, and returns the matching payloads | Mirrors that verified bucket/chain algorithm directly against the validated mapping, with exact node self-reference, bounds, active-flag, payload-length, and entry-count checks; this avoids the block-based selector as a physical synthetic-call boundary | Correct |
| Current source identity | `LSApplicationRecord -initWithBundleIdentifier:allowPlaceholder:error:` is `@36@0:8@16B24^@28`; `LSRecord -persistentIdentifier` is `@16@0:8` | Copies the current persistent identifier and searches every registered source value for an exact byte match | Correct |
| UUID copying | `NSUUID -getUUIDBytes:` uses the accepted 23A341 encodings, including the Swift-backed concrete override | Copies 16 bytes through pinned scratch and formats locally; does not call `UUIDString` | Correct |
| Data copying | File-backed `NSData.bytes` need not be cross-task mappable | Executes bounded target-side `memcpy` chunks into the resident 4 KiB scratch page, then `remote_read`s the page | Correct |

The direct ivar reads are intentional. The first physical run failed every
variant at `audit-source-registry-url-abi` because `ISIconCache.cacheURL` is an
`objc_getProperty` tail thunk whose return did not survive the physical
synthetic completion boundary. The same risk exists for the store URL,
store-unit fields, and cached-response fields. Each replacement now fails
closed unless both the ivar name and the exact 23A341 offset match.

## Persistent classification

A descriptor proves themed persistence only when all of these facts agree:

- the audit completed;
- the store hash equals the journaled themed structured-data hash;
- the current-digest index lookup completed and returned a UUID/token;
- the directly mapped store unit exists and passes `isValid`;
- index UUID and store-unit UUID are equal;
- the persistent validation-token hash is nonempty;
- the source-registry query completed and contains a source;
- the current LaunchServices persistent identifier is present; and
- one registered source value exactly equals that current identifier.

`cacheResponsePresent`, cache/store equality, and cached validation-token
equality remain useful diagnostics, but they are not persistence
preconditions. This distinction is required because the iconservicesagent
process cache can legitimately be empty while the persistent record is valid.

The rolling reinstall comparison preserves the original baseline when any
record changes. It compares the persistent index UUID, store-unit UUID,
persistent validation-token hash, structured-data hash, registered source
identity, and current LaunchServices identity. It cannot advance a baseline
unless every current descriptor has complete themed persistent evidence and
both the IconServices and SpringBoard audit sessions close cleanly.
Process-cache hashes and identifiers remain in the comparison report, but do
not determine `unchanged`: a cache can be empty in either run or repopulated
between runs without changing the persistent record under investigation.

### Shared persistent units

The first successful physical audit on 2026-09-25 established an additional
IconServices behavior that per-descriptor hash comparison must account for.
For Bitwarden, Messages, Snapchat, and TikTok, the 27-point appearance-0 App
Library descriptor and the 28-point appearance-0 switcher descriptor resolved
to the same current-index UUID and the same valid store unit. In every case the
unit contained the journaled themed hash for the 28-point descriptor. The
result repeated unchanged in two independent audits. Appearance 1 remained a
separate 27-point store unit.

Snapshot schema 4 therefore recognizes a `themed-alias` only after all bounded
records have been read. Acceptance requires all of the following:

- both records belong to the same bundle identifier;
- both have complete, valid index/store/source evidence;
- both resolve to the same nonempty indexed UUID, which equals each record's
  store-unit UUID;
- the observed store hash is identical for both records; and
- that hash exactly equals the peer descriptor's journaled themed hash.

The rule does not accept cross-application matches, an arbitrary `other`
hash, a missing or invalid unit, or incomplete LaunchServices source identity.
The snapshot retains the alias descriptor, surface, and expected themed hash,
and the summary reports the accepted aliases separately. The shared unit is
still compared by UUID, validation token, data hash, and source identity after
reinstall.

## SpringBoard supplemental audit

The SpringBoard portion is an identity/retention inventory, not a pixel audit.
The 23A341 SpringBoard and SpringBoardHome metadata confirm all objects it
reads:

| Object | Verified metadata | What is recorded |
| --- | --- | --- |
| `SBHIconModel` | `applicationIconForBundleIdentifier:` exists; `leafIconsUniquedByApplicationBundleIdentifier` is an `NSSet` | Canonical application icon and bounded live-leaf icons |
| `SBIcon` | `_observers` `+0x10`, `_iconLayerViews` `+0x18`, `_imageGeneration` `+0x40`; `imageGeneration` exists | Pointer, generation, layer-view count, observer count |
| `SBApplicationIcon` / `SBApplication` | `application` and `bundleIdentifier` exist | Exact bundle ownership for every recorded icon |
| `SpringBoard` / `SBSwitcherController` | `_switcherController`, `contentViewController`, and `switcherViewController` exist; controller getters are `@16@0:8` | Bounded switcher-controller root |
| `SBFluidSwitcherViewController` | `_appLayoutToTitleItemController` exists | Materialized title controllers only |
| `SBFluidSwitcherSpaceTitleItemController` | `_displayItems` and `_displayItemToIcon` exist | The icon object currently retained for each materialized display item |
| `SBDisplayItem` | `bundleIdentifier` exists | Exact target filtering |

The walk is bounded to 512 requested applications, 2,048 live leaves, 256
title controllers, and 16 display items per controller. It performs no view
hierarchy walk, cache purge, reload, or update handler. Missing or closed
surfaces simply have no materialized switcher records.

This supplemental result must not be read as proof of visible pixels for Home,
App Library, notifications, folders, or transitions. Persistent UUID/hash
evidence comes from IconServices; visible-surface proof remains the separate
cache-invalidation trace and acceptance matrix.

## Changes made after the failed physical audit

- Replaced cache-only-as-persistence logic with an independent current-index
  lookup and direct backing-unit read.
- Kept the process cache as optional diagnostic evidence and made its read
  non-refilling.
- Replaced unsafe property-thunk calls with exact-offset validated ivar reads.
- Replaced `ISStore -unitForUUID:` with the non-memoizing store-unit factory.
- Corrected the source-registry result from one `NSData` to a bounded array of
  source identifiers.
- Added prevalidation and injection of the already mapped source file so the
  transient table cannot lazily create or repair it.
- Copied UUIDs and file-backed data through the pinned session scratch page.
- Made themed-persistence and reinstall comparisons depend on persistent
  index/store/source evidence, not process-cache population.
- Added an explicit report field for the temporary weak-registry probe.

No Apply, Restore, descriptor-publication, cache-refresh, or journal-cleanup
path was changed by this audit correction.

## Remaining runtime check

Install the alias-aware build and run **Audit Applied State** once before
reinstall. The prior audit did not write a baseline. A valid schema-4 baseline
run must show exact records as `store=themed`, shared 27-point records as
`store=themed-alias`, and finish with:

```text
audit-stage=audited
index-ready=yes
index-present=yes
index-id=<uuid>
store-id=<same uuid>
source-count=>0
source-match=yes
aliased-store=4
non-themed-store=0
evidence=complete
snapshot=written
```

Cache may be `themed`, `stock`, or `missing`; that is diagnostic and must not
invalidate otherwise complete persistent evidence. After updating Cyanide,
run the audit again. The `SBR_AUDIT_REINSTALL` lines will then identify an
index replacement, store loss, source-identity mismatch, data replacement, or
an unchanged persistent record without conflating those outcomes with a
SpringBoard display cache.
