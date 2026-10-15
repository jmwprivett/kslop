# Spectrum-style system/app accent colors via file and RAM backing

Date: 2026-10-11

## Executive conclusion

The Spectrum port feasibility note
([`spectrum-accent-dylib-port-feasibility.md`](spectrum-accent-dylib-port-feasibility.md))
recommends per-PID window tinting as the first route and treats a true
Spectrum-style semantic-color replacement as blocked on executable payload
admission. That conclusion is correct for hook-based injection, but it omits
two non-injection backings that Cyanide has already proved on the physical
device:

1. **File backing**: native CoreUI `Assets.car` grafting through the
   `overwrite_system_file` transaction, already in physical production use
   for Pulsar Control Center (see
   [`cc-theming-file-backing.md`](cc-theming-file-backing.md)). Named colors
   are CAR BOM entries, not a new resource class; the existing graft pipeline,
   preservation proof, journal, and restore machinery apply to them.
2. **RAM backing**: guarded aperture `kwrite32` writes into dyld
   shared-cache **data** pages, physically confirmed writable for both the
   `.33` `__DATA_CONST` mapping and the nominally read-only `.34`
   `READ_ONLY_DATA` mapping (see
   [`hail-mary-data-page-experiment.md`](hail-mary-data-page-experiment.md)).

Both backings avoid per-PID RemoteCall mutation entirely: one bounded,
reversible, per-boot-or-per-file change replaces the color at the source
every consumer reads. Neither route needs a custom executable payload.

The decisive unknown is not capability but **provenance**: where each target
color's bytes actually live on build `23A341`. That is a read-only Gate 0
inventory, and no mutation route should be selected before it completes.

No implementation was added as part of this note.

## Evidence labels

This note uses the same meanings as the feasibility note:

- **Source-observed**: directly present in upstream tweak source or in the
  current Cyanide tree and its research record.
- **Existing pattern**: Cyanide already uses the technique for another
  bounded target; not yet proved against a color resource.
- **Candidate**: technically plausible, worth a controlled experiment, not
  yet device-proved.
- **Blocked**: depends on a capability current physical evidence does not
  establish.

## The two non-injection backings

### File backing: named-color CAR grafts

The Pulsar Control Center file transaction replaces whole CoreUI 970
catalogs on the physical device while preserving the native CAR header,
named variables, lookup keys, trees, every unrelated BOM block, and the
exact original file length. That machinery is rendition-type-agnostic.
An `Assets.car` also stores **named colors** as theme-keyed CSI values; a
color graft replaces only the selected color's light/dark/high-contrast
values under the existing name and key, preserving everything else.

Properties:

- arbitrary RGB, subject to the value format the native color entry uses;
- applied once per **file**, not per PID: every process that resolves the
  name after the write reads the new value;
- requires a respring and relaunch of affected apps, because CoreUI and
  UIKit consumers cache resolved colors process-locally;
- reversible from the durable journal across Cyanide restarts;
- physical consumption is proven for images (CC glyphs); **named-color
  consumption is not yet proved** and must be gated.

### RAM backing: aperture data-page recolor

The Hail Mary record proves the aperture accepts a kernel write to
shared-cache data pages for both mappings above, with exact byte guards,
readback, and two-process translation stability. The semantic experiment
used it for a packed dispatch IMP redirect; the same primitive can instead
edit a **pure data word**, such as a compiled constant color value on a
`.33`/`.34` page shared by every process that maps that binary.

Properties relative to the IMP redirect:

- no IMP, no `_cmd`, no ABI or PAC surface: the mutation is data only;
- the risk surface is the data consumer contract (bit width, packing,
  theme count) instead of a method contract;
- per boot: the change is lost on reboot and must be reapplied;
- restore is the inverse guarded write on the exact original guard bytes.

The Hail Mary permission tickets (the identical-bytes `.34` probe report)
are per-boot prerequisites for any `.34`-mapping recolor, exactly as they
are for the dispatch redirect.

## Target provenance matrix

The intended first targets are system blue, system green, and the orange
accents of Calculator, Notes, and Clock. Each has two candidate backings;
Gate 0 decides which applies. No cell below is a claim of provenance.

| Target | Primary candidate | Fallback candidate | Deciding Gate 0 evidence |
| --- | --- | --- | --- |
| `systemBlueColor` / `systemGreenColor` (and the semantic family) | Named color in UIKit's own on-disk `Assets.car`, resolved by `UIDynamicSystemColor initWithName:colorsByThemeKey:` through CoreUI theme keys; file graft of that one entry | Color values embedded in the shared cache (catalog data or compiled constants); aperture recolor of the exact data words | `assetutil` name dump of the UIKit car; disassembly of the `systemBlueColor` init path on `23A341` |
| Notes orange accent | Named color in the Notes app or NotesUI framework `Assets.car`; file graft | Compiled constant in the Notes binary (shared cache); aperture recolor | car name dump; disassembly of the accent-producing path |
| Clock orange accent | Named color in the MobileTimer app `Assets.car`; file graft | Compiled constant in the MobileTimer binary; aperture recolor | same |
| Calculator orange accent | Named color in the Calculator app `Assets.car`; file graft | Compiled constant; aperture recolor | same |

### Why the system colors are plausibly file-backed

The feasibility note records that Spectrum hooks
`-[UIDynamicSystemColor initWithName:colorsByThemeKey:]` rather than
hard-coding results. A theme-keyed construction dictionary means the values
are resolved data, and CoreUI resolution means a catalog. Two storage
locations exist: an on-disk UIKit framework catalog, or catalog data
embedded in the dyld shared cache. Upstream Accent replaces whole class
methods and Spectrum replaces the construction input, which is consistent
with neither tweak finding a durable file to edit (classic jailbreaks
rarely graft cars) but does not prove the values are compiled in.

### Why the app oranges are plausibly file-backed

The Clock/Calendar injection-free note
([`vphone-ios26-clock-calendar-without-process-injection.md`](vphone-ios26-clock-calendar-without-process-injection.md))
records that system app bundles live at writable paths with their own
`Assets.car` files, and that framework catalogs (CalendarUIKit) explicitly
contain UI colors. App accent colors are therefore likely named entries in
those cars. The caveat from the same note: some app UI colors are
procedural constants compiled into the binary, which no car edit can reach;
those fall to the aperture recolor. Live-icon conclusions from that note do
not transfer here: accent color consumers are ordinary in-process theme
lookups, not special SpringBoardHome generator classes.

## Route table

| Route | Arbitrary RGB | Affects | Survives app relaunch | Survives reboot | Status |
| --- | --- | --- | --- | --- | --- |
| Named-color CAR graft (app/framework car) | Subject to native entry format; theme variants authored | Every process resolving that name after write | Yes | Yes, if OS-volume writes survive remount (unproved) | Existing physical pattern for images; color entry candidate |
| Named-color CAR graft (on-disk UIKit car) | Same | Every UIKit process after respring | Yes | Same unproved reboot question | Candidate pending Gate 0 provenance |
| Aperture data-page recolor (shared-cache data) | Yes, within native bit packing | Every process mapping that page, for future reads of that word | Yes, per boot | No (per-boot reapply) | Primitive physically confirmed; color-value mutation candidate |
| Per-PID window tint (feasibility Route A) | Yes | That PID only | No | No | Feasibility-recommended fallback, not preferred for these targets |
| Per-PID preset method redirect (Route C) | Presets | That PID only | No | No | Existing pattern; ABI/`_cmd` proof per selector |
| Shared-cache FILE edit (dyld cache on the sealed volume) | Yes | Everything | Yes | Only with a rebuilt, accepted cache | Rejected: build-pinned, seal-breaking; equivalent to the custom-OS route already rejected for icons |
| Per-process injected payload (full Spectrum port) | Yes | That PID | No | No | Blocked on physical executable admission (unchanged) |

The aperture recolor is the missing row of the feasibility note's route
table: it edits the **data a method consumes** rather than redirecting the
method, removing the ABI/`_cmd` risk Route C carries, and its effect is
cross-process rather than per-PID.

## Rejected and bounded routes

- **Editing the dyld shared cache file** to obtain file persistence for
  cache-embedded system colors is the custom-system-image tier already
  rejected for the Clock/Calendar live icons: build-pinned binary edits,
  a broken seal, and a boot chain that must accept the result. The per-boot
  aperture recolor is the strictly safer substitute for the same bytes.
- **Blanket recoloring** remains rejected: semantic reds (destructive,
  alarm-state), greens used as success/status, category and tag colors must
  stay stock unless a full-spectrum mode explicitly opts in. A color graft
  or aperture recolor must target exact names/words, never "everything
  matching this RGB".
- **SpringBoard-wide surfaces** (auth sheets, alerts, StoreKit, and system
  green's success semantics) are inherently included in a system blue/green
  replacement. That is Spectrum's intended semantics, and the UI should say
  so rather than implying per-app scoping.

## State, caching, and honest limitations

- **Resolved-color caching**: `UIDynamicSystemColor` objects and CoreUI
  named colors cache resolved values per process. A file graft or aperture
  recolor covers future resolutions; already-running processes keep their
  resolved objects until relaunch. A respring (system colors) and app
  relaunch (app colors) are part of Apply, exactly as the CC route requires.
- **Reboot persistence is unclaimed** for OS-volume file writes until a
  physical reboot proves the sealed-volume write survives remount and
  consumption. Until then the honest state labels are Applied (this boot)
  versus Restored.
- **Aperture changes are per boot by definition**; Apply must re-derive
  every runtime address from live bytes (never hard-code), re-run the
  permission tickets, and fail closed on any drift.
- **A file graft is not retroactive** and neither route is per-app scoped
  for the system-color family; per-app profiles remain the scoping tool.

## Development gates

### Gate 0: provenance inventory (read-only)

For each target color, on physical `23A341` (VM only where noted):

- dump the candidate cars (`assetutil --info`) for the exact names: UIKit
  car for `systemBlueColor`/`systemGreenColor` (and the family actually
  consumed), Notes/NotesUI, MobileTimer, Calculator for the accent names;
- disassemble the accent-producing paths in each app to separate
  car-resolved lookups from compiled constants;
- record stock catalog SHA-256 digests and native color entry formats
  (value width, packing, theme-key variants);
- for the aperture fallback, locate and record the exact data words, the
  owning mapping (`.33`/`.34`), and the consuming instruction;
- make no mutation.

### Gate 1: named-color canary graft (Calculator)

- one exact-name color graft in the Calculator car through the existing
  transaction stack: preservation proof of every unrelated block, exact
  length, journal, readback;
- relaunch Calculator and verify the accent visually and by resolved-value
  readback;
- restore from the journal and verify byte-identical target.

### Gate 2: Notes and Clock color grafts

- one exact-name graft per app, with semantic guardrails: destructive and
  alarm-state reds, category/tag colors remain stock;
- before/apply/restore screenshots; fail closed on missing names or
  unexpected entry formats.

### Gate 3: system blue/green via the proven provenance

- if on-disk UIKit car: graft only the two named entries (light/dark/all
  theme variants), respring, verify resolved RGBA in a fresh process;
- if cache-embedded: aperture recolor of the exact color words under the
  Hail Mary ticket discipline (per-boot permission report, exact original
  guards, single guarded write per word, readback, stable translations);
- verify link/insertion/selection surfaces that should follow, and that
  destructive/success semantics are unchanged (unless opted in).

### Gate 4: persistence proofs

- physical reboot trial for the file route before any persistence claim;
- repeated apply/restore cycles with no stale journal state, leaked guard,
  or mismatched digest.

## Acceptance checklist

- Every color replacement is bound to an exact car name or an exact
  data-word guard, never to a broad recolor pass.
- System blue/green changes are labeled system-wide in the UI, not per-app.
- Semantic reds/greens (destructive, alarm, success), tag and category
  colors remain stock in the default mode.
- File route: preservation proof of all unrelated BOM blocks, exact file
  length, journal before write, verified readback, durable restore.
- Aperture route: per-boot permission ticket, runtime-derived addresses
  only, original-guard acceptance, exact readback, stable translations,
  inverse restore, fail-closed drift handling.
- Respring/relaunch is an explicit, reported part of Apply; resolved-value
  readback is verified in a fresh consumer, not just file bytes.
- No implementation claims are made for named-color consumption until
  Gate 1 physically proves it.

## Relationship to the feasibility note

This note does not contradict
[`spectrum-accent-dylib-port-feasibility.md`](spectrum-accent-dylib-port-feasibility.md);
it adds two rows to its route table that its author had not yet connected
to the CC file transaction and the Hail Mary data-page proofs. The
feasibility note's ordering still holds for hook-based work; the intended
replacement order for these specific targets becomes:

1. Gate 0 provenance inventory (read-only, physical);
2. app-orange named-color grafts (Calculator canary, then Notes, Clock);
3. system blue/green via the proven provenance (graft or aperture recolor);
4. per-PID window tint remains available as a scoped, non-durable
   complement, not as the primary route for these targets;
5. injected payloads and launch supervision remain the later gates they
   already are.
