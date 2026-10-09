# iOS 26 Calendar consumer-order experiment

This experiment exists to prevent a successful Calendar source installation
from being mistaken for a successful visible repaint. It is VM-only and does
not change production ordering. The target is the pinned iPhone17,3 iOS 26.0
23A341 vPhone.

## Proven boundary under test

Calendar's stock source is procedural:

```text
SBHCalendarApplicationIcon
  -> SBCalendarIconImageProvider
     -> preparedISIcon
        stock: CUIKIcon
        themed: registered ISBundleIdentifierIcon(com.apple.mobilecal)
```

The experiment compares these SpringBoard sequences independently:

```text
refresh-then-calendar:
  restore provider source
  -> reset/purge/reload ordinary consumers
  -> reacquire Calendar model/provider
  -> install preparedISIcon bridge
  -> one provider reload

calendar-then-refresh:
  restore provider source
  -> install preparedISIcon bridge
  -> one provider reload
  -> reset/purge/reload ordinary consumers
```

It separately records the current single-session combined implementation, a
same-PID fast-path repeat, and Spotlight's exact private-model provider path.

## 2026-09-29 retained-source cache result

The direct-dylib A→B experiment identified a cache below the Calendar provider
that the original fast-path proof did not mutate:

```text
SBCalendarIconImageProvider.preparedISIcon
  -> retained ISBundleIdentifierIcon(com.apple.mobilecal)
     -> process-local ISImageCache.imageBagsByDescriptor
```

The persistent 68-point appearance-0 record was changed without restarting
either consumer process:

| State | UUID | canonical RGBA SHA-256 |
| --- | --- | --- |
| A | `DBFB632C-2438-3512-A066-2BCC8494AB24` | `cbc1a9722479fe150942b7fb16b96a697c508e4c2bc797ae5a5a3840efa96115` |
| B | `208BB18F-6723-3C30-92F9-8E0E2964FD44` | `c2277e4250cdbc8d9daa0b871f7d5dca5c7990c7f350f3f32a5e2e215cb0a8f9` |

In Spotlight PID 711 and SpringBoard PID 39, the same result occurred:

1. The old retained fast path verified the model/provider/source relationship,
   performed zero reloads, and kept displaying A.
2. Reloading the retained provider advanced `imageGeneration` by exactly one,
   but the trace still returned A. A provider reload alone is insufficient.
3. The retained source cache contained one descriptor entry. Replacing its
   `imageBagsByDescriptor` dictionary through the runtime-verified
   `v24@0:8@16` setter emptied it `1 -> 0`.
4. One provider reload then returned B's exact `c227…` pixel hash and visibly
   repainted Calendar in both processes. Neither PID changed.

This proves that persistent publication, the SpringBoard image caches, and the
Calendar provider generation are three independent invalidation boundaries.
For a retained Calendar bridge, production must deduplicate and clear every
distinct replacement source `ISImageCache` before reloading its providers.
Creating or re-reading the same registered `ISBundleIdentifierIcon` is not a
cache invalidation.

The provider reload and generation readback are synchronous, but the source
request and mounted UIKit reconstruction are asynchronous. The first direct
SpringBoard refill-barrier run proved that an on-screen consumer happened to
request the source 20 ms after `reloadIconImage`; the original barrier only
counted cache entries, so that experiment did not prove the entry's byte
identity and must not be generalized to an offscreen icon.

The follow-up direct-dylib discriminator removed that visibility dependency.
In SpringBoard PID 39 it performed this exact sequence:

```text
retained source cache 1 -> 0
prepareImageForDescriptor:(68x68@3, appearance 0)
  -> _cachedImageForDescriptor: miss
  -> _imageFromStoreForDescriptor:
  -> ISImageCache setImage:forDescriptor:
provider reloadIconImage
```

The synchronous source request returned UUID
`050C9FF4-15BF-32AC-B9EC-B3F141CA7526`, encoded-data SHA-256
`79b66f6d87e73aa771422d8e4ca41f2a354e7e7692679e929695b49dc8c7e887`,
and pixel SHA-256
`cbc1a9722479fe150942b7fb16b96a697c508e4c2bc797ae5a5a3840efa96115`.
An independent current persistent-store reader returned the same UUID and both
hashes. The subsequent provider render reused the exact cached image and
returned the same pixel hash. SpringBoard remained PID 39.

iOS 26 disassembly explains the result. `ISIcon prepareImageForDescriptor:`
first calls `imageForDescriptor:`. After the process-local dictionary purge,
`ISConcreteIcon _cachedImageForDescriptor:` misses, directly calls
`_imageFromStoreForDescriptor:`, and reinserts the store result through
`ISImageCache setImage:forDescriptor:`. That setter also updates
`latestValidationToken`; manually modifying the token is neither necessary nor
supported. Production can therefore force and verify the store read before the
provider reload instead of waiting for a visible consumer to request pixels.

## Production acceptance boundary

The retained-provider registry is recovery state, not an inventory of current
consumers. SpringBoard can rebuild its Calendar model/provider while retaining
the old bridged provider. Production therefore performs the following bounded
checks on every SpringBoard or Spotlight repair, including a same-PID repeat:

1. Recover the exact serialized `68×68@3` appearance-0 and appearance-1
   responses from the active Calendar journal's validated payload-cache
   entries. The original VM proof exercised appearance 0; production prepares
   both records so the physical device's active light/dark consumer cannot
   miss the proven refill barrier.
2. Reacquire the current canonical/live-leaf Calendar models and their current
   providers; never return early merely because retained provider state exists.
3. Restore and remove retained provider bridges that are absent from the
   current provider inventory.
4. Replace each distinct registered Calendar source's
   `ISImageCache.imageBagsByDescriptor` dictionary once.
5. Construct the exact `68x68@3` appearance-0 and appearance-1 descriptors and
   invoke the object-returning `prepareImageForDescriptor:` ABI for both on
   each distinct source. Retain each returned object inside the same
   target-main-thread invocation.
6. Before any provider reload, require both returned images to be
   non-placeholder and require the bounded
   `ISImageCache -> ISImageBag -> IFImage.data` graph to contain both
   byte-identical journal-verified responses.
7. Reload each current provider and require its model generation to advance by
   exactly one. A bounded cache verifier remains as a fallback, but the proven
   synchronous prepare path satisfies it on the first pass without a delay.
8. Treat an empty `0 -> 0` purge, a placeholder result, a merely nonempty stock
   bag, or generation advancement without the exact themed response as
   failure.

The compact `SBR_CALENDAR_SOURCE` result now records the current model/provider
counts, retired stale states, cache counts before/purge/refill, poll count, and
actual bounded wait. The publisher separately verifies the exact persistent
response before this consumer repair begins; the resident VM tracer records
the UUID, encoded-data hash, and pixel hash returned by the asynchronous
consumer request.

## Evidence captured

The resident trace records, in one sequence-numbered timeline:

- a pre-mutation persistent-record snapshot for Calendar's proven 27-point
  appearances 0/1, 48-point appearance 0, and 68-point appearances 0/1,
  including descriptor digest, UUID, validation-token hash, data hash, and
  canonical RGBA hash;
- SpringBoard or Spotlight PID;
- Calendar model and provider pointers;
- model `imageGeneration`;
- `preparedISIcon` and persistent `com.apple.mobilecal` source activity;
- requested descriptor, UUID, encoded-data hash, and canonical RGBA hash;
- `SBHIconManager` primary/folder cache pointers immediately before and after
  `resetAllIconImageCaches`;
- all dedicated cache getters used by production;
- provider/model reloads and final relayout;
- screenshots immediately before and after each sequence.

The target PID must remain unchanged. An Objective-C result dictionary with
`ok=1` is not visual proof; the source identity, generation, pixel hash, and
screenshot must agree.

The experiment uses two kinds of dylib and no Cyanide process dependency:

- one resident observation dylib in SpringBoard or Spotlight records the
  timeline and source/image boundaries;
- a self-contained one-shot action dylib is injected directly into that same
  target for each sequence. It implements the proven per-provider
  `preparedISIcon` bridge and the bounded reset/reload boundary locally.

The action dylib does not resolve Cyanide symbols, enumerate installed
applications, recursively scan views, activate Spotlight search, or open a
RemoteCall per icon. This keeps a suspended or partially initialized Cyanide
app completely outside the proof.

## Build-only validation

```sh
python3 -m unittest \
  scripts.tests.test_calendar_order_experiment \
  scripts.tests.test_calendar_order_trigger \
  scripts.tests.test_dynamic_icon_trace

python3 scripts/lab/cnd_dynamic_icon_trace.py build --target SpringBoard
python3 scripts/lab/cnd_dynamic_icon_trace.py build --target Spotlight
python3 scripts/lab/cnd_calendar_order_trigger.py build \
  --sequence springboard-refresh-then-calendar
```

## Live VM procedure

Leave the Calendar theme and its persistent descriptors installed. Cyanide
does not need to be open or resident. Prepare each target only once per PID
because the trace dylib remains resident:

```sh
export CND_VPHONE_ROOT_PASSWORD='…'

python3 scripts/lab/cnd_calendar_order_experiment.py prepare \
  --host VM_IP --target SpringBoard --root EVIDENCE_ROOT
```

Run the two independent SpringBoard orders in the same PID. Each sequence
first restores the process-local Calendar source, so the second experiment is
not allowed to inherit the first bridge:

```sh
python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root EVIDENCE_ROOT \
  --sequence springboard-refresh-then-calendar

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root EVIDENCE_ROOT \
  --sequence springboard-calendar-then-refresh

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root EVIDENCE_ROOT \
  --sequence springboard-combined-current

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root EVIDENCE_ROOT \
  --sequence springboard-fast-path

# Direct lifecycle/cache discriminators used by the A->B proof:
python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root EVIDENCE_ROOT \
  --sequence springboard-fast-path-only

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root EVIDENCE_ROOT \
  --sequence springboard-reload-only

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root EVIDENCE_ROOT \
  --sequence springboard-source-cache-reload

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root EVIDENCE_ROOT \
  --sequence springboard-source-cache-refill-barrier

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root EVIDENCE_ROOT \
  --sequence springboard-source-prepare-reload
```

For Spotlight, open Spotlight once so its process and private home-screen
model exist. The Calendar result row itself does not need to be visible. Use a
new evidence root because Spotlight has an independent PID and trace file:

```sh
python3 scripts/lab/cnd_calendar_order_experiment.py prepare \
  --host VM_IP --target Spotlight --root SPOTLIGHT_EVIDENCE_ROOT

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root SPOTLIGHT_EVIDENCE_ROOT \
  --sequence spotlight-calendar

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root SPOTLIGHT_EVIDENCE_ROOT \
  --sequence spotlight-fast-path-only

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root SPOTLIGHT_EVIDENCE_ROOT \
  --sequence spotlight-reload-only

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root SPOTLIGHT_EVIDENCE_ROOT \
  --sequence spotlight-source-cache-reload

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root SPOTLIGHT_EVIDENCE_ROOT \
  --sequence spotlight-source-cache-refill-barrier

python3 scripts/lab/cnd_calendar_order_experiment.py execute \
  --host VM_IP --root SPOTLIGHT_EVIDENCE_ROOT \
  --sequence spotlight-source-prepare-reload
```

## Mounted SpringBoard consumer proof (2026-09-29)

The provider/source proof was necessary but not sufficient for an
already-mounted Home Calendar icon. In SpringBoard PID 39, the canonical
`SBHCalendarApplicationIcon` was `0xdb05b7f20`, the primary
`SBHIconImageCache` was `0xdaf8c7ca0`, and the icon owned 17 observers plus
four `_iconLayerViews`. `SBRootFolderController.displayedIconViewForIcon:`
returned nil even though those model-owned consumers were mounted, so a root
view lookup is not a reliable refresh boundary.

A controlled cycle established stock before every themed trial:

1. Restore the provider to its procedural `CUIKIcon` source.
2. Call `reloadIconImage` for the one Calendar model, followed by
   `SBHIconImageCache.updateImageForIcon:` for that same model.
3. Capture the Home screen and verify the procedural `Tue 29` icon.
4. Install the exact `ISBundleIdentifierIcon/com.apple.mobilecal` provider
   bridge, purge/prepare its source cache, and verify the themed structured
   response (pixel SHA-256 `cbc1a972…`).
5. Call the same one-model cache update and capture the Home screen again.

The final update immediately produced the themed red/dotted Calendar icon in
three consecutive stock-to-theme cycles without changing PID 39. Provider
installation alone was timing-dependent: it sometimes repainted immediately
and previously left the procedural pixels mounted even after the provider had
returned the verified themed response. The per-icon cache update removed that
nondeterminism in both directions.

The 23A341 Objective-C metadata declares
`-[SBHIconImageCache updateImageForIcon:]`; runtime encoding validation uses
`v24@0:8@16`. Production applies it only to the deduplicated Calendar
canonical/live-leaf set (hard cap eight) after source-cache verification. It
does not restore the rejected batch fallback: no installed-app iteration is
performed, and no recursive view scan or direct layer painting is involved.
Restore uses the identical bounded consumer boundary after reinstating the
procedural provider.

## Physical-device host-identity proof (2026-09-29)

A later physical-device failure was not a cache-refill or queue-order defect.
SpringBoard contains `SearchUIHomeScreenModel` as well as its actual Home icon
model. The shared Calendar resolver was consulting the SearchUI singleton in
both target processes, so a SpringBoard repair could successfully bridge an
unmounted SearchUI `SBHCalendarApplicationIcon` and still report complete
source-cache verification.

The failing trace made the identity split explicit:

- the themed canonical object was `0xb2a1b37a0`;
- the mounted Home object was `0xb27d64820`, with three live icon-layer views;
- the mounted provider still returned `CUIKIcon` after the purported repair.

Production now treats the already verified target-process role as an
authority boundary. SpringBoard resolves Calendar only through
`SBIconController -> SBHIconManager -> iconModel`; only the Spotlight target
may consult `SearchUIHomeScreenModel`. Spotlight applies the same identity
rule: the `SearchUIHomeScreenModel` materializer is only allowed to bootstrap
the private graph, its returned icon is discarded, and the authoritative
Calendar object is reacquired through Spotlight's private `SBHIconModel`
using `applicationIconForBundleIdentifier:`.

The immediate physical-device retest selected `0xb27d64820` for both the
canonical repair and mounted consumer. Its provider changed from `CUIKIcon`
to `ISBundleIdentifierIcon/com.apple.mobilecal`, `imageGeneration` advanced
from 2 to 3, all four mounted layer views remained attached, and Home Calendar
repainted immediately. Both appearance-0 and appearance-1 structured
responses were exact matches, the primary/root cache pointer remained
`0xb295f7160`, SpringBoard PID 1091 did not change, and no recursive view scan
or direct layer paint was used.

## Pass criteria

The selected production sequence passes only if:

1. Persistent Calendar descriptor records are already themed before the
   process-local experiment begins.
2. Every active SpringBoard canonical/live-leaf provider, or Spotlight's exact
   materialized provider, returns the registered bundle source.
3. A fresh installation performs exactly one provider callback per distinct
   provider and advances each model generation exactly once.
4. Every distinct purged source cache refills with the exact journal-verified
   themed structured response within the bounded completion poll; neither an
   immediate empty cache nor a merely nonempty stock bag counts as verification.
5. The returned and displayed Calendar pixels match the themed hash.
6. No broad cache reset, installed-app reload, or relayout follows the
   terminal Calendar callback. SpringBoard performs only the proven bounded
   `updateImageForIcon:` call for Calendar's exact active model set.
7. A same-PID repeat reacquires the current model/provider inventory, performs
   the same bounded cache purge and one reload per current provider, and again
   proves the returned persistent identity and themed bytes.
8. Restore returns to a procedural `CUIKIcon` source and stock pixels.
9. SpringBoard/Spotlight PIDs remain unchanged throughout the corresponding
   evidence session.

Only after those facts agree should production call order and its structural
tests be changed.
