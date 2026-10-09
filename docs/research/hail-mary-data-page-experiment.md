# Hail Mary data-page aperture-writability experiment

Status: **CONFIRMED on the physical device, 2026-10-08 00:47.**
`aperture-data-page-write-confirmed`: one identical-bytes dispatch,
readback byte-identical, both translations stable, no panic, zero semantic
mutations. The runtime adrp/ldr decode (page delta `0x28a6c000`,
displacement `0xd20`, slot offset `0x2d20`, unslid slot `0x1e6b6ed20`,
runtime `0x1f0f82d20`) resolved to one shared physical frame
`0x10048458000` in both processes through aperture KVA
`0xfffffff079eead20`. The 32-byte window holds four consecutive user-VA
pointers (`0x1f7a5e558`, `0x1f7a5d6a8`, `0x1f7a5d1a8`, `0x1f7a5a838`) —
runtime (post-slide) values, so the aperture maps non-executable
shared-cache **data** pages writable while the guarded **text** frame is
read-only. The method-IMP redirect on the shared cache data page is now
the main line; treat pointer values on those pages as runtime addresses
derived from the live proof, never hard-coded.

The follow-up `.34` boundary is also **CONFIRMED writable on the physical
device, 2026-10-08**. The exact guard matched one of one live slide candidates
at slide `0x0a414000`, runtime entry `0x20a03b458`, physical frame
`0x1014dcbc000`, physical address `0x1014dcbf458`, and aperture KVA
`0xfffffff17f74f458`. The one identical-word `kwrite32` returned, all 32 bytes
read back exactly, and both process translations remained stable. The result
was `aperture-read-only-data-page-write-confirmed`, with one primitive
invocation and zero semantic mutations. Thus the aperture does **not** enforce
the `.34` mapping's `maxProt=r--` on this route; the packed dispatch entry is a
physically proven semantic target on this boot.

## Offline IMP-slot follow-up (2026-10-08)

The first exact-cache decode narrows that conclusion: the confirmed data-page
write does **not** yet authorize the redirect target.

- `SBIconImageView` is at unslid `0x1eda00588`; its base method list is
  `0x1be200cf0`.
- `effectivelyPrefersFlatImageLayers` is compact-method entry 11 at
  `0x1be200d7c`. Its IMP field is the four-byte signed relative value at
  `0x1be200d84` (`0xfff020e8`), which decodes to `0x1be102e6c`.
- That method record is in `.19` `__TEXT` with `initProt=maxProt=r-x`. It is
  neither an eight-byte pointer nor on the writable data mapping proved above.
- The class does have an eight-byte preoptimized dispatch-cache entry for the
  selector: slot 177 at `0x1ffc27458`. The original packed value
  `0x02c408000be3f5c7` contains a 26-bit selector offset and a signed 38-bit
  class-relative IMP offset; it stores no plain pointer and no PAC bits.
- A same-subcache, exact-ABI Apple implementation already returns true:
  `-[SBIconImageView hasOpaqueImage]` at `0x1be1052a0`, bytes
  `20 00 80 52 c0 03 5f d6` (`mov w0,#1; ret`). The corresponding packed
  dispatch value is `0x02c408000be3ecba`.

The important boundary is the dispatch entry's page. It is in
`.34.dyldreadonly`, marked `READ_ONLY_DATA`, with
`initProt=maxProt=r--`. The successful probe targeted `.33.dylddata`
`__DATA_CONST`, whose `maxProt` is `rw-`. Therefore the next safe experiment is
another **identical-bytes-only** aperture permission probe against the exact
`.34` entry page. A semantic redirect must remain refused until that page is
proved writable; assuming all non-executable shared-cache pages share the
`.33` permission profile is not justified.

The reproducible derivation and complete byte guards are in
`scripts/derive_flat_icon_imp_redirect.py` and
`docs/research/flat-icon-imp-redirect-23A341-iphone17,2.json`.

## `.34` identical-bytes probe implementation (2026-10-08)

`CNDHailMaryReadOnlyDataPage` is the deliberately narrow next experiment.
It does **not** contain the semantic dispatch redirect and does not attempt
the class-cache fallback. Its only mutation beat is one identical-bytes
`kwrite32` transport dispatch against the exact `.34` entry window.

The runtime address is not accepted merely by applying the earlier `.19`
slide. After the complete physical proof succeeds, the experiment collects
and deduplicates the four live slide anchors recorded independently for the
SpringBoard/Spotlight map walks and matched backing-object candidates. Each
unique candidate is translated through both live pmaps at unslid
`0x1ffc27458`. Exactly one candidate must resolve to one shared terminal
physical frame at offset `0x3458` and expose all 32 offline bytes:

`c7f5e30b0008c40200000000c0ffffff0323ed0b0000cc1600000000c0ffffff`

The bytes must also hash to
`81c8a106d2a9e37a93d17d78dc7c54ea3b0ec4f036458a15e2ec1e4403d33677`
and begin with packed entry `0x02c408000be3f5c7`. The winning translation
and the exact guard are checked again immediately before arming. A durable
`Documents/CNDHailMaryReadOnlyDataPage.json` checkpoint records
`dispatchReturned: false` before the sole write. If the system remains alive,
the experiment requires an exact 32-byte readback and stable SpringBoard and
Spotlight translations before reporting
`aperture-read-only-data-page-write-confirmed`.

Because the offline mapping is `initProt=maxProt=r--`, a panic at the armed
checkpoint was the conservative predicted result if the physical aperture
honored maxProt. The physical run disproved that prediction for this exact
page: the dispatch returned and the full postflight proof succeeded. No
rollback or panic mechanism was installed because the write was semantically
a no-op. The Settings quick action remains **Hail Mary .34 RO-Data Write
Probe**, and its successful report is now the per-boot permission ticket for
the semantic operation.

## Guarded semantic dispatch redirect (implemented 2026-10-08)

`CNDHailMaryImpRedirect` implements the apply/restore experiment without using
the dead text word, the compact method list, or the class-cache fallback.

Mutation is fail-closed on all of the following:

1. `Documents/CNDHailMaryReadOnlyDataPage.json` must record the successful
   identical-bytes `.34` probe from the current boot: one returned write,
   exact original guard readback, stable translations, and zero semantic
   mutations.
2. A fresh full physical proof must succeed. The shared resolver scans only
   the live slide anchors and requires exactly one exact 32-byte dispatch
   guard. Its slide, physical frame, physical address, and aperture KVA must
   equal the permission report.
3. Apply accepts only the original guard; Restore accepts only the redirected
   guard. The desired guard and packed 64-bit entry are checked against the
   compiled offline values before arming.
4. `Documents/CNDHailMaryImpRedirect.json` is atomically written and fully
   synced with the exact inverse low word and `dispatchReturned: false` before
   the only writer call.
5. Exactly one `kwrite32` changes the packed entry's low word:
   `0x0be3f5c7 -> 0x0be3ecba` for Apply, or the exact inverse for Restore. The
   upper word and all neighboring bytes remain fixed by the exact 32-byte
   guard.
6. The desired 32-byte guard must read back exactly, and the original
   two-process translation proof must still identify the same frame, physical
   address, and aperture KVA. The confirmed mutation checkpoint is then synced
   durably.
7. Automation stops at that postwrite proof. No process is killed, restarted,
   reopened, or otherwise mutated. The live visual result is judged manually
   by the operator.

There is no automatic rollback, panic mechanism, fallback mutation, or class
cache repoint. Restore is a separate guarded one-write operation. The two
Settings actions are **Apply Hail Mary Dispatch Redirect** and **Restore Hail
Mary Dispatch Entry**. Launch-only lab flags are `--hail-mary-imp-apply` and
`--hail-mary-imp-restore`.

### Retired postwrite Spotlight check

The first physical semantic Apply produced transparent icons, which is direct
operator-visible evidence that the redirect landed. The subsequent automated
Spotlight kill/reopen check froze Cyanide and was followed by a userspace
crash. That lifecycle sequence is not needed to establish the already exact
write/readback/translation result and is now removed entirely. No causal claim
about an individual internal beat is made without the recovered journal; the
whole postwrite lifecycle route is retired regardless.

## Motivation

Every Hail Mary Apply attempt panics deterministically at the store. The
October 7 panics (seven sampled, 18:51-23:14, distinct boot sessions) are
byte-identical in signature:

- `Unexpected fault in kernel physical aperture`;
- `esr 0x9600004f`: EL1 data abort, **write** (WnR=1), level-3 leaf PTE
  **permission fault**;
- `far` = the aperture VA of the guarded instruction word (low 14 bits
  `0x2ef0`, the exact word offset in the 16 KiB frame); the 23:14 panic's
  `far` equals that run's journal `targetKernelVirtualAddress` exactly;
- `x3 = 0x9494d59b52800034`: the merged 64-bit word with the replacement
  `0x52800034` loaded but never stored;
- the faulting `pc` is the same kernel text-exec offset across all seven
  boots; the panicked task is always the Cyanide `setsockopt` copy, never
  SpringBoard or Spotlight;
- journals stop at the armed checkpoint with
  `kernelWritePrimitiveInvocationCount = 0`.

Conclusion: the physical aperture maps the dyld shared-cache **text frame
read-only** (a trusted executable page). Reads through the aperture work
(the whole proof depends on them); the write aborts at the first store beat
with a permission fault, so **the code word never changed and no
racing/`no-readback` strategy can ever work for the text frame**. The
intermittent "transparency achieved" observations were the guarded method's
natural early return paths, not evidence of a write.

## Disassembly of the guarded method

The 188-byte guard (SHA-256
`542063d6c8ea82afbe734ace1895ba0f2b7ab15160c6053176604644741f20d5`) contains
the whole method. It returns 1 (flat layers) through **three early paths**
(`mov w20, #1` at guard offsets 0x2c, 0x7c, and the 0x5c `cbz`) before ever
reaching the guarded `cset w20, eq` at offset 0x94. The final fallback loads
a **global object pointer** via:

- guard offset `0x60`: `adrp x8, <page>` (immediate decodes to page delta
  `0x28a6c000`);
- guard offset `0x64`: `ldr x0, [x8, #0xd20]` (displacement `0xd20`);
- guard offset `0x88`: `bl` to a getter whose result `(v & ~1) == 2` feeds
  the guarded `cset`.

The guarded word therefore only controls the **last** branch of a
multi-branch predicate, and that last branch is decided by **data** — the
global object slot's value through the getter chain.

## The experiment

`CNDHailMaryDataPage.m` (Settings: **Hail Mary Data-Page Write Probe**)
answers one question with one boot: **does the physical aperture accept a
kernel write to a non-executable shared-cache data page?**

1. Run the full read-only Hail Mary proof (unchanged, write-free) and
   require a confirmed shared physical frame with the exact original
   guard.
2. Decode the adrp/ldr pair **at runtime from the validated guard bytes**
   (never hard-coded): register masks, 64-bit LDR opcode bits `0x3e5`, the
   21-bit signed adrp immediate, and the scaled 12-bit LDR immediate give
   the global-object slot's unslid address. The decoded slot must be
   inside the shared region, pointer-aligned, within the adrp reach,
   **never on the guarded text frame** (virtual or physical), and must
   keep its 32-byte transport window inside one 16 KiB frame.
3. Translate the derived runtime slot address through **both** proven live
   pmaps via the new read-only
   `CNDHailMaryProbeTranslateSharedRuntimeAddress` helper (which
   revalidates the exact kernel identity, layout offsets, physical-map
   anchors, and both live process identities, and requires one terminal
   shared physical frame). The slot must resolve to the **same** shared
   frame in SpringBoard and Spotlight — the data page has exactly the
   property the text-page proof established.
4. Read the 32-byte transport window over the slot, hash it, and save the
   **durable armed journal** (identical-bytes mode).
5. One single `kwrite32` dispatch writes the **exact identical** 32-byte
   window (the merged word equals the existing word by construction).
   Identical bytes exercise the aperture PTE's write permission with zero
   semantic change. If the aperture also maps this data page read-only,
   the dispatch panics exactly like the text writes and the journal records
   the armed checkpoint; if the aperture maps it writable, the dispatch
   completes without any semantic risk.
6. If the system stays alive: read the window back (byte-identical
   required), and repeat both translations (frame identity must be
   unchanged).

The report is `Documents/CNDHailMaryDataPage.json`:
`aperture-data-page-write-confirmed` is the green light for the follow-up —
redirecting the method IMP on the shared cache data page (a panic-free
replacement for the dead text-word patch). A panic or
`readback-mismatch`/`translation-unstable` verdict means shared-cache data
pages are also protected, and shared-page persistence on 23A341 should be
abandoned in favor of per-process RemoteCall swizzling.

## Next physical sequence

On a fresh boot (see `hail-mary-patch.md` for the living-session rules), open
the installed app normally and run **Hail Mary .34 RO-Data Write Probe** first.
Only after it returns the confirmed result on that same boot, run **Apply Hail
Mary Dispatch Redirect**. The action may present Spotlight before mutation
only to obtain the required two-process physical proof. After the guarded
one-write mutation it performs exact readback and stable translation checks,
then stops without touching either process. Judge the existing live UI by eye.
Keep **Restore Hail Mary Dispatch Entry** available in the same boot; it
requires the same permission ticket and the exact redirected guard.
