# iOS 26 Clock/Calendar special-class dispatch redirect

**Date:** 2026-10-08
**Target:** iPhone17,2, iOS 26.0 (`23A341`)
**Status:** offline derivation complete; runtime unverified

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

## One-word dispatch shape

`SBHIconModel` has a preoptimized cache at unslid `0x1ffc32e78`. The target
selector occupies slot 68:

| Field | Value |
| --- | --- |
| Entry | `0x1ffc330a8` |
| 16 KiB frame | `0x1ffc30000` |
| Original packed value | `0x22440b400be18d3b` |
| Redirected packed value | `0x22440b400be18d90` |
| Original low word | `0x0be18d3b` |
| Redirected low word | `0x0be18d90` |
| Semantic writes | one 32-bit write |

The selector field and upper word do not change. The packed values contain no
plain pointer or PAC bits. Decoding them relative to the class produces the
original IMP `0x1be19db3c` and replacement IMP `0x1be19d9e8` exactly.

The complete original/redirected 32-byte guards, hashes, cache identities,
method records, and code-directory verification are in
`special-icon-class-redirect-23A341-iphone17,2.json`. They are reproduced by
`scripts/derive_special_icon_class_redirect.py`.

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
`0x1ffc27458`, on frame `0x1ffc24000`. This target is on a different frame,
`0x1ffc30000`. The earlier ticket therefore does not authorize this write.
The next safe experiment is an identical-bytes-only write against the exact
new entry page, with fresh SpringBoard and Spotlight translations proving one
shared physical frame and the exact 32-byte original guard.

There is also an object-lifetime boundary: changing dispatch does not
reclassify existing `SBClockApplicationIcon` or `SBCalendarApplicationIcon`
instances. A live validation must install the redirect first and then rebuild
both consumers' icon models—most cleanly with one controlled userspace
restart—before judging the static result. This is still much cheaper than
ongoing per-PID repair, but it means the first apply is not visually complete
at the instant of the write.

The runtime acceptance test is:

1. prove the exact new `.34` page with an identical-byte write;
2. apply the guarded low-word redirect;
3. rebuild SpringBoard and Spotlight after the redirect is active;
4. verify both canonical objects are `SBApplicationIcon`, not the special
   subclasses;
5. verify Home, Spotlight, App Library, switcher, and launch/return surfaces
   resolve the existing themed ordinary records;
6. verify bundle identity, badges, quick actions, and launching remain stock;
7. restore the exact original word and rebuild consumers again.

Until that run passes, the correct claim is **offline-proved one-write
candidate**, not a completed replacement for the current live-icon bridges.
