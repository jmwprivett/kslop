# Hail Mary `.34` page wire probe (`mlock` cement)

Status: **implemented, physical-proved **negative**.** The probe has run once on
23A341 / iPhone17,2 (2026-10-19 18:05). SpringBoard's `mlock` of the exact
`.34` frame is **accepted** — the thesis that a read-only page cannot be wired
is dead — but the wire does **not** keep that page mapped: the same
SpringBoard later resolved the address through a different leaf table, with
`ARM_PTE_WIRED` set, to a **different physical frame**. Cement is closed as a
route; see "First physical run" below.

## Question

Can the exact `.34` read-only-data frame that carries the live
SBIconImageView dispatch redirect be **wired** from inside SpringBoard, so the
silent clean-page purge that reverts the redirect cannot reclaim it until
reboot?

This is route #2 of `glm-cool.md` ("mlock probe on the .34 page via RemoteCall").
It is *not* a repeat of the earlier `mlock` attempt: that one asked
SpringBoard to wire the **legacy landing text frame** and returned `EPERM`
before any write (`hail-mary-patch.md:39-40`,
`kCNDHailMaryPatchAttemptSpringBoardMlock = NO` in `CNDHailMaryPatch.m`).

| | previously tried | this probe |
|---|---|---|
| word | `0x1a9f17f4` (`cset w20, eq`) | `0x0be3f5c7` (packed dispatch entry) |
| unslid VA | `0x1be102ef0` | `0x1ffc27458` |
| subcache | `.19` (code) | `.34` `dyldreadonly` |
| mapping class | text frame, `r-x` | read-only data, `r--` |
| aperture behaviour | write panicked | identical-bytes write **confirmed** |
| recorded outcome | `EPERM`, no write attempted | unknown |

## Design

Identity, not inference. The probe reuses
`CNDHailMaryReadOnlyDataPageResolveDispatchEntryWithMode` in
`springboard-only` mode: it re-runs the physical-page proof against
SpringBoard alone, deduplicates that process's live slide anchors,
translates the offline entry through SpringBoard's pmap, requires exactly one
candidate exposing the exact 32-byte guard, and re-reads it before returning.
No second process is resolved, opened, or contacted. Either page state is
accepted — the wire targets the frame, not the dispatch value — and the
report records which state was found.

Pinned invariants re-checked after resolution, before arming:

- `physicalAddress - physicalFrame == 0x3458` and
  `pageBase + 0x3458 == runtimeEntry`;
- `runtimeEntry - sharedCacheSlide == 0x1ffc27458` (the boot identity check,
  never a hardcoded runtime address);
- `frame != guardedTextPhysicalFrame` (proves the data page, not the text
  frame);
- `frameKVA + offset == windowKVA`, 16 KiB-aligned frame and aperture;
- one last 32-byte aperture read equal to the resolved guard.

Then **one** bounded SpringBoard `RemoteCall` session, bound to the proven
PID/proc/task, re-proving the recorded three-level leaf path on entry and exit:

1. `mlock` a freshly mapped **anonymous read/write** 16 KiB page, then
   `munmap` — control for "can this caller, over this transport, mlock at all";
2. `mlock` a freshly mapped **anonymous read-only** 16 KiB page, then
   `munmap` — control for "is a `maxProt`-read-only mapping wireable";
3. `mlock` the exact `.34` shared-cache frame — the experiment.

Each failing call has its target-side `errno` read immediately from the
synthetic thread's TLS slot, before any other target call can overwrite it.

## Safety and state

- **No kernel write primitive is invoked and no page byte changes.** The probe
  records `kernelWritePrimitiveInvocationCount = 0`, `semanticMutationCount = 0`
  and no inverse page word; there is nothing semantic to restore.
- The two control pages are the probe's own anonymous memory. They are always
  unmapped, and they cannot touch system state.
- The only durable state is a wire count. A successful target wire is
  **retained on purpose** (the point is to see whether it holds), and the
  report records its inverse — `munlock` of the same 16 KiB range in
  SpringBoard — plus the fact that it is released automatically when
  SpringBoard exits.
- The pre-arm journal is `F_FULLFSYNC`-ed with its parent directory synced
  before the session opens, so a device that does not come back still leaves
  the exact armed page identity on disk.

## Pre-registered outcomes

| anon RW | anon RO | `.34` frame | `interpretation` | meaning |
|---|---|---|---|---|
| wired | wired | wired, same frame | `springboard-wire-accepted` | cement is available; the purge question becomes a longitudinal check |
| wired | wired | wired on a **private copy** (frame moved) | `springboard-wire-accepted-private-copy` | the kernel unshared the page to wire it; the wired frame still carries the exact guard, so the redirect is retained on that copy |
| wired | wired | refused | `shared-cache-page-refused-despite-writable-controls` | the refusal is specific to the shared-cache/file-backed mapping |
| wired | refused | refused | `read-only-mapping-cannot-be-mlocked` | `mlock` needs write protection; no user-space wire can hold an `r--` page — **cement is closed** |
| refused | — | refused | `anonymous-writable-page-refused` / `mlock-unavailable-in-springboard` / `mlock-control-mapping-failed` | the caller, the transport, or the probe's own control mapping is the problem; the result says nothing about the page |
| — | — | — | `wire-preflight-refused` | the SpringBoard session or its identity proof did not open; no control ran, no conclusion about the page |

`confirmed` requires the target `mlock` to land, the RemoteCall session to close
cleanly, and the page SpringBoard now resolves to carry the exact 32-byte
guard. Two shapes satisfy that last condition:

- the frame did not move (`translationStable`), or
- the kernel gave SpringBoard a private copy (`privateCopy`) and the guard read
  at the **wired** frame's window — derived from the physmap base plus the new
  physical address — still matches.

The second shape matters because the pre-fix probe re-read the *old* window
after a move, which only proved that the old page still held the guard. A move
is not by itself a failure: what decides the outcome is whether the redirect
survived onto the frame that is actually wired. A move whose wired frame holds
the stock guard is a re-fault, and the wire did not retain the redirect; it
reports `read-only-data-page-wire-landed-unverified`.

The first physical run landed on the `wired / wired / wired` row and **still
failed the identity re-proof**, so that row reads "the wire is accepted", not
"cement works" — the frame moved anyway (below).

`read-only-data-page-wire-confirmed` proves **wireability only**. It does not
prove the purge is prevented: that needs the longitudinal check recorded in
`followUp` — re-read the same window after the next heavy-usage cycle, and the
guard returning to the pinned original means the wire did not hold.

## Evidence status

| claim | status |
|---|---|
| SpringBoard `mlock` of the `.19` text frame returns `EPERM` | recorded, prose only (`hail-mary-patch.md:39-40`); the errno value itself is not retained in any journal |
| the `.34` read-only-data page accepts an identical-bytes aperture write | physical, `aperture-read-only-data-page-write-confirmed` |
| SpringBoard can wire the `.34` frame | **physical yes** — `mlock` returned 0 and the leaf gained `ARM_PTE_WIRED` |
| that wire keeps the proven page mapped | **physical no** — SpringBoard re-resolved to a different frame while wired |
| the `.19` text-frame `EPERM` was a read-only-class refusal | **physical no** — both anonymous controls and the `.34` data frame wired |
| a SpringBoard wire prevents the clean-page purge | **physical no** — see "First physical run" |

## First physical run — 2026-10-19 18:05

`result = read-only-data-page-wire-landed-unverified`,
`interpretation = wire-landed-but-identity-unstable`, `pageState = original`.

- Target `mlock` returned 0 for page base `0x209e00000` (frame
  `0x10137e40000`), `mlockErrno = 0`.
- Both control beats wired: anonymous RW 16 KiB and anonymous RO 16 KiB. The
  `.19` text-frame `EPERM` is therefore a property of that *text* mapping, not
  of read-only pages.
- The recorded SpringBoard leaf (`0xfffffff05c16bc00`, shared with Spotlight
  pre-wire) moved from `0x0060010137e406c3` to `0x0060010137e40ec3`: exactly
  one attribute bit (`0x800`, `ARM_PTE_NG`), identical output address,
  identical guard SHA (`81c8a1…`).
- The post-wire shared-pair translation refused
  (`shared-terminal-frame-translation-failed`).

Follow-up diagnostics on the same boot and the same SpringBoard (pid 471),
18:20–18:32, resolved the address separately in each pmap:

| process | leaf entry | leaf value | physical frame |
|---|---|---|---|
| SpringBoard | `0xfffffff0a3e67c00` | `0x04600101ca260ec3` | `0x101ca260000` |
| Spotlight | `0xfffffff05c16bc00` | `0x0060010137e40ac3` | `0x10137e40000` |

SpringBoard's `.34` mapping now lives in a **different leaf table**, carries
`ARM_PTE_WIRED` (bit 58, `0x0400000000000000`), and resolves a **different
physical frame** than the frame the probe wired. The wire landed; the page did
not stay. Two mechanisms fit and this data does not separate them:

1. `mlock`'s unshare moved the entry to a private leaf table and re-entered
   the mapping on another page at wire time; or
2. the clean-page purge re-faulted the mapping afterwards while the map entry
   stayed wired (the wired-bit is re-applied on re-fault because the range is
   still `mlock`ed).

Either way the operational consequences are the same:

- **The wire does not keep the proven frame mapped.** If the move is a
  re-fault rather than a copy, a redirect written to the old frame is
  invisible once SpringBoard re-resolves to the new one. The 18:05 run proves
  the move; it never read the new frame, so it cannot say whether a redirect
  would have followed it. The probe now reads the wired frame's window and
  reports `postWireIdentity.wiredFrameGuardStable`.
- **A wire blocks the shared-pair proof path.** While the wire is held,
  `CNDHailMaryProbeTranslateSharedRuntimeAddress` refuses
  (`shared-terminal-frame-translation-failed`), so the read-only resolver
  returns `dispatch-entry-guard-not-found` and the permission probe / `Apply`
  cannot run until SpringBoard restarts.
- **The heal loop must resolve per process.** After any purge the two
  mappings legitimately diverge, so healing has to use
  `CNDHailMaryProbeTranslateRuntimeAddressInProcess(…, @"SpringBoard", …)`
  and never require SpringBoard and Spotlight to share a frame.

The probe's own verification was tightened accordingly: the wire routine
accepts only the single private-entry bit on the *recorded* leaf and reports
it as an observation, while the probe re-derives the SpringBoard walk and
judges the page on the frame SpringBoard actually holds.


## Second physical run — 2026-10-20 20:08 (private copy)

`result = read-only-data-page-wire-landed-unverified` under the pre-fix
check, `pageState = redirected`, SpringBoard pid 13128, `mlock` returned 0.

- proven frame `0x101a7020000` → post-wire frame `0x1012ae8c000`;
  leaf `0xfffffff20c093c00` = `0x046001012ae8cec3`;
- `finalLeafEntryValue` was recorded as `0` and `leafEntryStable` as false,
  but those are artifacts of the patch-wire matcher rejecting any
  output-address change — not evidence that the mlock failed;
- the only guard read was at the **old** window
  (`0xfffffff1daf2b458`), so `guardStable = true` proved the old frame still
  held the redirected SHA (`4ed81474…`) and said nothing about the frame
  SpringBoard now resolves.

That run is what motivated the private-copy classification. The probe now:

- derives the wired frame's window as `frameKVA - frame + postPhysical` (the
  aperture is a linear physmap) and reads the 32-byte guard there;
- reports `privateCopy`, `wiredFrameGuardStable`,
  `wiredFrameGuardSHA256` and the wired-frame window;
- sets `confirmed` when the mlock landed, the session closed cleanly and the
  wired frame carries the resolved guard — whether or not the frame moved;
- records `interpretation = springboard-wire-accepted-private-copy` for that
  shape and points `followUp` at the wired frame's window.

Not yet re-run on device, so whether the 20:08 copy carried the redirect is
still unread. That is the first thing the next run answers.

## Running it

Settings → **Probes** → **Run Hail Mary .34 Page Wire** (fourth row of that
section; the Quick Actions row count stays pinned at 6, so no other retained
Hail Mary diagnostic is surfaced by this). The row confirms what will happen,
shows the inline activity log, and resolves to
`read-only-data-page-wire-confirmed` on success. The launch argument still
works for scripted runs:

```
--hail-mary-page-wire
```

Both entry points run the same body, so exactly one completion is posted per
run: the row feeds its own activity sheet, the argument path posts the usual
actions-complete notification. Validated KRW is acquired or reused; the probe
does not require, present, or contact Spotlight. The report is written to
`Documents/CNDHailMaryPageWire.json`, the only durable artifact of the run.

Report fields worth reading first: `result`, `interpretation`, `pageState`,
`runtimeIdentity`, `wire`, `springBoardPageWire.diagnosticControls`,
`postWireIdentity`, `followUp`.
