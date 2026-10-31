# Hail Mary special-icon-class redirect (Clock / Calendar)

**Status:** data-only GOT redirect **physically applied and verified in the
current processes**, then **reverted by a controlled respring**. The GOT page
is re-created for the new SpringBoard/Spotlight processes, so this route is
**per-process, not per-boot**. It does not meet the "survives respring"
requirement by itself. The `.19` method-list text write is **abandoned** after
a physical level-3 write fault panic; the replacement targets two
SpringBoardHome `__got` class pointers in the non-executable `.33.dylddata`
subcache.
**Target:** `iPhone17,2`, iOS 26.0 (`23A341`).
**Module:** `Cyanide/CNDHailMarySpecialIconClassRedirect.{h,m}`.
**Offline manifest:**
[`special-icon-class-got-redirect-23A341-iphone17,2.json`](special-icon-class-got-redirect-23A341-iphone17,2.json).

## Purpose

SpringBoardHome hard-selects `SBHClockApplicationIcon` and
`SBHCalendarApplicationIcon` for `com.apple.mobiletimer` and
`com.apple.mobilecal`. Their live generators never consult the persistent
IconServices records that SnowBoard Remix publishes, so a static theme record
alone cannot cover the Home Screen or Spotlight.

The selection helper is:

```text
-[SBHIconModel iconClassForApplicationWithBundleIdentifier:]
  -> com.apple.mobiletimer : SBHClockApplicationIcon
  -> com.apple.mobilecal   : SBHCalendarApplicationIcon
  -> everything else       : -[SBHIconModel applicationIconClass]
```

`applicationIconClass` returns `SBHApplicationIcon`. If Clock and Calendar take
that ordinary tail, they consume the already-published persistent
`com.apple.mobiletimer` / `com.apple.mobilecal` IconServices records, i.e. the
SnowBoard static theme artwork.

## Why the method-list text write is dead

The previous implementation targeted the relative method-list IMP field for
`iconClassForApplicationWithBundleIdentifier:` at `0x1be1ef2f4` in
`dyld_shared_cache_arm64e.19`. That page is executable text:

```text
subcache  E5139123-79ED-3CC2-8E2F-40C980D82033 (.19)
page      0x1be1ec000
initProt  5 (r-x)
maxProt   5 (r-x)
```

The exact guard matched and the identical-bytes write was armed, but the store
faulted:

```text
panic     Kernel data abort
esr       0x9600004f   level-3 write permission fault
far       0xfffffff057cbf2f4
task      Cyanide pid 21872
stack     CNDHailMarySpecialIconClassRedirect.m:1255
          -> kwrite32 -> early_kwrite64 -> early_kwrite64_checked
```

The physical aperture will not write that executable shared-cache page. This
route is not retried. The read-only `.19` method-list page remains untouched,
and the method-list probe/apply controls were replaced by the data-only GOT
controls.

## The data-only route

Disassembly of the helper at `0x1be19da24` shows that the two special branches
do not return a class directly. They load a class pointer from a SpringBoardHome
`__got` slot:

```text
__got._OBJC_CLASS_$_SBHClockApplicationIcon    0x1e8278298
__got._OBJC_CLASS_$_SBHCalendarApplicationIcon 0x1e8278270
```

The ordinary tail (`applicationIconClass`, `0x1be19d9e8`) loads
`__got._OBJC_CLASS_$_SBHApplicationIcon` at `0x1e8278240`.

Both special slots are in `dyld_shared_cache_arm64e.33.dylddata`:

| Field | Clock | Calendar |
| --- | --- | --- |
| `__got` slot (unslid) | `0x1e8278298` | `0x1e8278270` |
| Original class (unslid) | `0x1eda02180` (`SBHClockApplicationIcon`) | `0x1eda02568` (`SBHCalendarApplicationIcon`) |
| Replacement class (unslid) | `0x1eda021a8` (`SBHApplicationIcon`) | `0x1eda021a8` |
| Slot file offset | `0x1720298` | `0x1720270` |
| Segment | base `0x1e6b5c000`, file offset `0x4000`, size `0x1e50000` | same |
| Mapping | `initProt=1` (r--), `maxProt=3` (rw-) | same |
| Subcache UUID | `F193189E-840D-3569-816A-2102BCB0FFE5` | same |

The target is non-executable data. The Hail Mary data-page experiment already
proved that this `.33.dylddata` subcache family accepts an identical-bytes
aperture write on the physical device
([`hail-mary-data-page-experiment.md`](hail-mary-data-page-experiment.md)).
That is the key difference from the `.19` text page: the aperture enforces the
executable-text boundary, not `initProt` alone.

The helper caches the selected class per process in
`data_1ebf517d8` / `data_1ebf51640` (`SpringBoardHome/__DATA.__data`,
`initProt=maxProt=rw-`). Those slots are initially zero and are process-private
after the first cache write, so the module does not write them. A respring
starts them at zero; the fresh helper then reads the patched `__got` slots.

## Physical result (2026-10-21)

The read-only probe confirmed the route on the physical device with slide
`0xa58000`:

| Slot | Runtime address | Physical address | Value before |
| --- | --- | --- | --- |
| Clock | `0x1e8cd0298` | `0x1016bf64298` | `0x1ee45a180` (`SBHClockApplicationIcon`) |
| Calendar | `0x1e8cd0270` | `0x1016bf64270` | `0x1ee45a568` (`SBHCalendarApplicationIcon`) |

Both slots resolved to the same physical frame `0x1016bf64000` through
SpringBoard and Spotlight. The apply then performed exactly two `kwrite64`
stores and read both back as `0x1ee45a1a8` (`SBHApplicationIcon`):

```text
special-class-got-apply-confirmed
confirmed=yes mutation-confirmed=yes
kernelWritePrimitiveInvocationCount=2
dispatchEntrySemanticMutationCount=2
readback-exact=yes post-translation-stable=yes
```

There was no panic. The follow-up read-only verify returned
`special-class-got-verify-redirected-confirmed` with both slots in
`SBHApplicationIcon` state and zero writes.

The pre-respring consumer audit still reports
`SBHClockApplicationIcon` / `SBHCalendarApplicationIcon` for the live
canonical and `modelSelection` classes. That is expected: the helper cached
the special classes in this SpringBoard process before the pointer write.

The controlled respring then **reverted the GOT patch**. The kernel slide and
base were unchanged (`0x42ca0000`), but SpringBoard moved from pid 563 to
1264 and Spotlight from 580 to 1283. The `.33` GOT page's physical frame
changed from `0x1016bf64000` to `0x1018e82c000`, and both slots read back the
original values:

| Slot | After respring |
| --- | --- |
| Clock | `0x1ee45a180` (`SBHClockApplicationIcon`) |
| Calendar | `0x1ee45a568` (`SBHCalendarApplicationIcon`) |

The post-respring consumer audit still reports
`SBHClockApplicationIcon` / `SBHCalendarApplicationIcon`. The helper's
per-process class-cache slots are nonzero (`0xafcb26460` / `0xafcb26480`)
and live in a separate writable frame (`0x100c9e9c000`), so reapplying the GOT
pointer alone would not change the live icons: the helper returns its warm
cache before reading the GOT. The GOT route is a valid data-only write proof,
but it is **not a respring-persistent solution**.

## Exact mutation

Two 8-byte class-pointer stores, one per `__got` slot:

```text
Clock:    0x1eda02180 + slide  ->  0x1eda021a8 + slide
Calendar: 0x1eda02568 + slide  ->  0x1eda021a8 + slide
```

No executable text, method-list entry, selector, or cstring is written. The
static themed IconServices records are not touched. The write is
**per-process**: it is visible to the SpringBoard and Spotlight instances that
were alive when it was applied, but a respring starts fresh processes with a
fresh `.33` GOT page and the original class pointers. The earlier "survives a
respring" hypothesis was disproved on the physical device.

## Module boundary

The legacy Hail Mary writer, the legacy `.34` permission probe, and the legacy
read-only data page resolver are unchanged. The special-class module reuses
only the read-only proof and translation helpers from `CNDHailMaryProbe`:

- `Documents/CNDHailMarySpecialIconClassPermission.json` — read-only GOT probe
  result and the per-boot ticket.
- `Documents/CNDHailMarySpecialIconClassRedirect.json` — apply/restore/verify
  report and the exact inverse recovery record.

No existing writer file is imported for mutation.

## Operations

1. **GOT probe** — full read-only physical proof; resolve both `.33` slots
   through SpringBoard and Spotlight; read both 8-byte class pointers; require
   each to be either the original special class or `SBHApplicationIcon`; write
   the per-boot ticket. It invokes no write primitive.
2. **Apply** — requires the same-boot GOT ticket. It re-proves both slots,
   requires both to be original, journals the inverse durably, writes
   `SBHApplicationIcon` into both slots with one `kwrite64` each, requires exact
   readback, and re-translates both slots. It refuses mixed state.
3. **Restore** — the exact inverse. It requires both slots to be redirected,
   journals the inverse, restores both original class pointers, and verifies
   readback and stable translations.
4. **Verify** — resolves both slots and reports original or redirected without
   writing. No ticket is required.

No process lifecycle action is performed. A controlled respring is required
after apply/restore because existing `SBHClockApplicationIcon` /
`SBHCalendarApplicationIcon` objects are not reclassified by the pointer write.

## Entry points

Launch arguments:

```text
--hail-mary-special-icon-class-probe
--hail-mary-special-icon-class-apply
--hail-mary-special-icon-class-restore
--hail-mary-special-icon-class-verify-redirected
--hail-mary-special-icon-class-verify-original
```

Settings exposes the same controls under **Probes**:

- **Run Special-Class GOT Probe**
- **Apply Static Clock + Calendar Icons**
- **Restore Live Clock + Calendar Icons**
- **Verify Static Clock + Calendar State**
- **Verify Original Clock + Calendar State**
- **Audit Clock/Calendar Icon Classes**

The audit row is a read-only SpringBoard RemoteCall check. It reports the
actual class of the canonical Clock and Calendar icon objects
(`SBHApplicationIcon` versus `SBHClockApplicationIcon` /
`SBHCalendarApplicationIcon`) and their leaf and switcher classes. The GOT
verify rows prove the shared-cache pointers; the audit proves which class the
live icon model actually built.

## Acceptance sequence

1. Fresh boot; unlock the device; acquire validated KRW once.
2. Run **Run Special-Class GOT Probe**. Require
   `special-class-got-probe-confirmed` and both slots in `original` state.
3. Apply. Require `special-class-got-apply-confirmed`, exact readback for both
   slots, and stable post-write translations.
4. Respring.
5. Run **Audit Clock/Calendar Icon Classes**. Require the canonical and
   model-selection classes to be `SBHApplicationIcon` for both bundles.
6. Verify Home, Spotlight, App Library, and the switcher show the SnowBoard
   static Clock and Calendar artwork; launching, badges, and quick actions
   remain stock.
7. Restore and respring again; verify the live Clock face and date return.

A result that appears only before the first respring, or only on one surface,
is not acceptance.

## Per-boot preoptimized-dispatch route (implemented 2026-10-21)

The GOT result above motivated a separate route that targets the shared
read-only preoptimized caches instead of process-private `.33` fixups.
Spotlight's model is `SBHIconModel`; SpringBoard's model is the `SBIconModel`
subclass. dyld has a slot-68 entry for the inherited selector in both classes:

| Consumer | Class | Entry | Original | Redirected |
| --- | --- | --- | --- | --- |
| Spotlight | `SBHIconModel` | `0x1ffc330a8` | `0x22440b400be18d3b` | `0x22440b400be18d90` |
| SpringBoard | `SBIconModel` | `0x1ffd52eb8` | `0x22440b4030ceaacf` | `0x22440b4030ceab24` |

Both entries are in `.34.dyldreadonly` (`initProt=maxProt=r--`) and both
redirect to `+[SBHIconModel applicationIconClass]` at `0x1be19d9e8`. The
selector and upper 32 bits remain unchanged, so Apply and Restore each use
two low-word `kwrite32` stores. The exact derivation is pinned in
[`special-icon-class-dispatch-redirect-23A341-iphone17,2.json`](special-icon-class-dispatch-redirect-23A341-iphone17,2.json)
and reproduced by
`scripts/derive_special_icon_class_dispatch_redirect.py`.

This route has its own permission ticket. The permission operation performs
an identical low-word write on each target and requires exact 32-byte
readback and stable SpringBoard/Spotlight translations. Semantic mutation
then requires that same-boot ticket to match each live entry VA, physical
frame, physical address, and aperture KVA. Mixed state is refused, and the
inverse is durably journaled before the first store.

Launch arguments:

```text
--hail-mary-special-icon-dispatch-probe
--hail-mary-special-icon-dispatch-apply
--hail-mary-special-icon-dispatch-restore
--hail-mary-special-icon-dispatch-verify-redirected
--hail-mary-special-icon-dispatch-verify-original
```

Settings exposes five corresponding **Per-Boot** rows after the existing GOT
controls. Unlike the `.33` route, the `.34` state is intended to survive a
controlled respring and expire on reboot. Physical testing subsequently
showed that a respring preserves the archived canonical Clock and Calendar
objects, so it is not the consumer rebuild boundary. Apply/Restore must be
followed by the bounded two-bundle canonical-object migration described
below.

The two-entry redirect and its post-respring guards are physical-device
proved on the pinned build. The new canonical-object migration is implemented,
contract-tested, and compiled. Its SpringBoard zero-mutation preflight is
physical-device proved (both bundles, selected classes, application objects,
and relative paths); Spotlight preflight and semantic migration remain a
separate physical acceptance result from the redirect proof.

### Archived canonical-object result and bounded migration (2026-10-21)

After the redirected pair survived a controlled respring, the read-only
SpringBoard consumer audit reported:

| Bundle | Model selection | Archived canonical/leaf class |
| --- | --- | --- |
| `com.apple.mobiletimer` | `SBHApplicationIcon` | `SBHClockApplicationIcon` |
| `com.apple.mobilecal` | `SBHApplicationIcon` | `SBHCalendarApplicationIcon` |

This explains the stock icons: the dispatch route controls future
construction, while SpringBoard restores the existing special-class objects
from its icon-state archive.

The app now exposes **Rebuild Static Clock + Calendar Objects** and the
symmetric **Rebuild Live Clock + Calendar Objects**. The operation:

1. opens exact PID/proc/task-bound SpringBoard and Spotlight sessions;
2. validates the pinned Objective-C encodings for model lookup, application
   lookup, removal, insertion, and SpringBoard relative-path preservation;
3. proves both bundle identities and both currently selected destination
   classes before the first mutation;
4. removes and re-adds only Clock and Calendar through each live model;
5. requires the replacement canonical objects to have the selected classes;
6. on SpringBoard, captures each old relative path and leaf identifier,
   supplies that desired path before removal, and requires `isEqual:` after
   insertion; and
7. runs a read-only SpringBoard canonical-class audit afterward.

The dry-run launch argument is
`--special-icon-object-preflight`. The mutating launch arguments are
`--special-icon-object-rebuild-static` and
`--special-icon-object-rebuild-live`. This step performs no shared-cache
write, process restart, respring, broad layout reset, or `object_setClass:`.

## Boundaries

- This intentionally removes live behavior: Clock hands stop moving and
  Calendar stops showing today's date; the static theme PNG is what shows.
- The GOT redirect is per-process, not per-boot. It is reverted by a respring
  because the new SpringBoard/Spotlight processes receive a fresh `.33` GOT
  page. Reapplying it alone does not change the live icons after a respring:
  the helper's class-cache slots are already warm. The IconServices records
  themselves remain persistent.
- There is no automatic rollback, panic recovery mechanism, or post-write
  process mutation. Restore is a separate guarded two-slot operation.
- The consumer-object step is deliberately separate from the shared-cache
  Apply/Restore. It refuses before the first removal unless both consumers
  pass preflight; a transport failure after a removal is reported rather than
  hidden behind a broad layout reset.
- The original `.19` method-list text page is never written. Its level-3 fault
  boundary is documented above and must not be retried.
