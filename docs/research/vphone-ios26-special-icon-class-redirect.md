# iOS 26 Clock/Calendar special-class dispatch redirect

**Date:** 2026-10-08
**Target:** iPhone17,2, iOS 26.0 (`23A341`)
**Status:** the two-entry per-boot route is derived offline and implemented;
it is not yet VM-proved or physical-device-proved.

> **Correction (2026-10-21):** The earlier conclusion that SpringBoard must
> fall through to the relative method list was incomplete. dyld also flattens
> this inherited selector into the `SBIconModel` subclass's own preoptimized
> cache. Spotlight uses the `SBHIconModel` entry at `0x1ffc330a8`;
> SpringBoard uses the `SBIconModel` entry at `0x1ffd52eb8`. Both decode to
> the original IMP and both must be redirected. The `.19` method-list page
> remains forbidden after its physical level-3 write-permission fault.

The proposed special-class kill is viable on the exact build. One packed
Objective-C dispatch entry controls
`-[SBHIconModel iconClassForApplicationWithBundleIdentifier:]` for consumers
of the shared `SpringBoardHome` image. Redirecting that entry to Apple's
`+[SBHIconModel applicationIconClass]` implementation makes the method return
the ordinary `SBApplicationIcon` class for Clock and Calendar as it already
does for every other identifier.

This pass was offline-only. It read the local IPSW and dyld cache, verified
their identities and signed code pages, and added no device writer.

## Exact-build control flow

The target method is at unslid `0x1be19db3c`. Its Swift helper at
`0x1be19da24` contains exactly two special comparisons:

```text
com.apple.mobiletimer -> SBClockApplicationIcon
com.apple.mobilecal   -> SBCalendarApplicationIcon
everything else       -> +[dynamic SBHIconModel class] applicationIconClass
```

`+[SBHIconModel applicationIconClass]` is at unslid `0x1be19d9e8` and
returns the ordinary `SBApplicationIcon` class. Its Objective-C type encoding
is `#16@0:8`, while the target is `#24@0:8@16`; this is not an exact metadata
encoding match, but it is machine-call compatible. The replacement ignores
`self`, `_cmd`, and the extra identifier in `x2`, and returns one `Class` in
`x0`. Both implementations are in the same Apple-signed RX subcache.

## Two-entry dispatch shape

`SBHIconModel` and SpringBoard's `SBIconModel` subclass each carry the
selector in slot 68:

| Class / consumer | Entry | Frame | Original | Redirected |
| --- | --- | --- | --- | --- |
| `SBHIconModel` / Spotlight | `0x1ffc330a8` | `0x1ffc30000` | `0x22440b400be18d3b` | `0x22440b400be18d90` |
| `SBIconModel` / SpringBoard | `0x1ffd52eb8` | `0x1ffd50000` | `0x22440b4030ceaacf` | `0x22440b4030ceab24` |

The selector fields and upper words do not change. The packed values contain
no plain pointer or PAC bits. Decoding each entry relative to its own class
produces original IMP `0x1be19db3c` and replacement IMP `0x1be19d9e8`
exactly. The semantic operation is two 32-bit low-word writes.

The complete original/redirected 32-byte guards, hashes, cache identities,
method records, and code-directory verification are in
`special-icon-class-dispatch-redirect-23A341-iphone17,2.json`. They are
reproduced by
`scripts/derive_special_icon_class_dispatch_redirect.py`.

## What this would buy

After the redirect is installed and a consumer builds fresh icon objects,
Clock and Calendar follow the ordinary `SBApplicationIcon` path. That should
allow the already-published persistent ordinary `com.apple.mobiletimer` and
`com.apple.mobilecal` IconServices records to provide static themed icons
while preserving the real application identity. In that static mode there is
no reason to retain the Clock face/hands or Calendar provider bridges in each
new PID.

The write is shared-cache state, so the intended operating model is one
redirect per boot rather than one source bridge per consumer PID. The exact
cross-process effect and persistence through consumer replacement still need
runtime proof.

## Boundaries before a semantic apply

The prior successful `.34.dyldreadonly` permission experiment targeted entry
`0x1ffc27458`, on frame `0x1ffc24000`. These targets are on two different
frames, `0x1ffc30000` and `0x1ffd50000`. The earlier ticket therefore
authorizes neither write. The new permission operation performs one
identical-low-word `kwrite32` against each exact target, requires the pinned
32-byte guard before and after, and binds the ticket to the slide, physical
frames, physical addresses, and aperture KVAs.

There is also an object-lifetime boundary: changing dispatch does not
reclassify existing `SBHClockApplicationIcon` or
`SBHCalendarApplicationIcon` instances. Physical testing showed that a
controlled respring restores those same special-class identities from the
icon-state archive even while the redirected method now selects
`SBHApplicationIcon`. A live validation must therefore install the redirect
and run the bounded Clock/Calendar remove/re-add migration in both consumers
before judging the static result.

The runtime acceptance test is:

1. prove both exact new `.34` pages with identical low-word writes;
2. apply both guarded low-word redirects;
3. preflight and rebuild exactly Clock and Calendar through SpringBoard's and
   Spotlight's live icon models after the redirect is active;
4. verify both canonical objects are `SBApplicationIcon`, not the special
   subclasses;
5. verify Home, Spotlight, App Library, switcher, and launch/return surfaces
   resolve the existing themed ordinary records;
6. verify bundle identity, badges, quick actions, and launching remain stock;
7. restore the exact original words and run the symmetric two-bundle live
   object rebuild.

Until that run passes, the correct claim is **offline-proved one-write
candidate**, not a completed replacement for the current live-icon bridges.

## Runtime implementation (2026-10-20)

`CNDHailMarySpecialIconClassDispatchRedirect.h` exposes the dedicated
permission/apply/restore/verify API. Its implementation is co-located with the
older GOT experiment in `CNDHailMarySpecialIconClassRedirect.m` so both routes
share the same proof parsing, durable-journal, and mutual-exclusion helpers.
It mints
`Documents/CNDHailMarySpecialIconClassDispatchPermission.json` and records
semantic operations in
`Documents/CNDHailMarySpecialIconClassDispatchRedirect.json`.

The module and UI are implemented and compile, but runtime status remains
unverified: implemented is not VM-proved, and VM-proved is not
physical-device-proved.
