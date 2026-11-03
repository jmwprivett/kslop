# AppleAVE2 `NumberOfTemporalLayers` producer chain and panic primitive

**Date:** 2026-10-31\
**Scope:** read-only static analysis of local artifacts; no device execution and no network access.\
**Vulnerable build:** iOS 27.0.1 (24A446), AppleAVE2 913.43.1.\
**Fixed comparison:** iOS 27.2 (24B119).\
**Offset convention:** `v+...` and `f+...` are offsets into the corresponding AppleAVE2 `__TEXT_EXEC` slice, not runtime addresses.

## Evidence labels

- **[STATIC]** — directly established by instructions/dataflow in the local kext slices.
- **[PANIC]** — corroborated by the supplied physical-device panic log; not reproduced in this analysis.
- **[POC-CLAIM]** — behavior stated by the external PoC/evidence package but not independently reproduced here.
- **[VM-PROVED]** — none; no VM execution was performed.
- **[PHYSICAL-PROVED]** — no new physical test was performed. The supplied panic is external physical evidence, not a new local validation.

## Executive verdict

The bug is an **unbounded, sequential 32-bit OOB store loop**, not an N-indexed pointer-table load.

The corrupting loop uses the 32-bit temporal-layer count at `session+0x3760` and writes `w24` at:

```text
session + 0x4678 + 4*i
```

with no local upper bound. For the N=16463 panic path, adjacent stores of `1` at `session+0x147B0` and `session+0x147B4` replace the first teardown pointer with:

```text
Q = 0x0000000100000001
```

Teardown later loads `Q` from that slot. The panic-time list initializer receives:

```text
P = Q + 0x58 = 0x0000000100000059
```

which exactly matches `x0` and `far` in the supplied panic.

This is **not write-what==where**. N controls how far a linear overwrite proceeds; it does not directly supply an arbitrary 64-bit address or arbitrary 64-bit value. The final list-init operation is a downstream consequence of the corrupted pointer, not the original producer primitive.

## Artifacts

Vulnerable:

```text
/tmp/ave-analysis/v-d23-27.0.1/AppleAVE2.__TEXT_EXEC.bin
/tmp/ave-analysis/v-d23-27.0.1/AppleAVE2.kextblob
```

Fixed:

```text
/tmp/ave-analysis/f-d23-27.2/AppleAVE2.__TEXT_EXEC.bin
/tmp/ave-analysis/f-d23-27.2/AppleAVE2.kextblob
```

External PoC and panic evidence:

```text
/Users/josh/dev/incoming-untrusted/AVETemporalPoC-CVE-2026-112705/AVETemporalPoC/Runner.swift
/Users/josh/dev/incoming-untrusted/AVETemporalPoC-CVE-2026-112705/panic-evidence/panic-full-2026-10-28-014135.0002.ips
```

The PoC's stage 9 sets HEVC, `EncoderUsage=1`, `RCMode=20`, `RealTime=false`, and `NumberOfTemporalLayers=N`, then submits frames. The supplied panic is from `videocodecd` on 27.0.1.

## 1. Which config field carries N?

### Corrupting algorithmic field

The field consumed by the OOB loop is the 32-bit word at:

```text
vulnerable input cfg + 0x1880
        -> internal session/config + 0x3760
```

**[STATIC]** The vulnerable HEVC configuration copy at `v+0x73010` copies `0x2AD0` bytes from input `cfg+0x1878` to internal `+0x3758`. Therefore input `+0x1880` lands at internal `+0x3760`:

```asm
v+0x72FFC  mov  w8, #0x3758
v+0x73000  mov  w9, #0x1878
v+0x73004  add  x0, x20, x8       ; destination = internal+0x3758
v+0x73008  add  x1, x21, x9       ; source      = input cfg+0x1878
v+0x7300C  mov  w2, #0x2AD0
v+0x73010  bl   ...               ; copy
```

The fixed layout is eight bytes later:

```text
fixed input cfg + 0x1888
        -> internal session/config + 0x3768
```

**[STATIC]** Fixed `f+0x76840`–`f+0x76854` copies input `+0x1880` to internal `+0x3760`, so `+0x1888` maps to `+0x3768`.

The fixed build rejects values above 6 in this field:

```asm
f+0x714B0  ldr  w8, [x20, #0x1888]
f+0x714B4  cmp  w8, #6
f+0x714B8  b.hi #0x717C8
```

A second fixed validator has the same `+0x1888 <= 6` check at `f+0x7325C`–`f+0x73264`. The vulnerable OOB consumer has no equivalent count bound.

### Separate HEVC property representation

There is also a property-side representation:

```text
vulnerable input cfg + 0x4350 -> internal +0x6230
fixed      input cfg + 0x4358 -> internal +0x6238
```

**[STATIC]** Vulnerable `v+0x73014`–`v+0x73028` copies `0x38E8` bytes from input `+0x4348` to internal `+0x6228`. Fixed `f+0x76858`–`f+0x7686C` copies from input `+0x4350` to internal `+0x6230`.

The fixed property-side check is:

```asm
; x23 = pInfo+0x4350 in this validator
f+0x71A60  ldr  w10, [x23, #8]    ; pInfo+0x4358
f+0x71A64  cmp  w10, #6
f+0x71A68  b.hi #0x71B10
```

The vulnerable counterparts use the eight-byte-earlier structure base and return without this new range ladder.

**[STATIC]** A normalization path at `v+0x19C82C`–`v+0x19C83C` can write `w9-1` to both internal `+0x6230` and internal `+0x3760`. Thus the exact value in the loop is best named `M`, the effective 32-bit count at `session+0x3760`, rather than assuming every codec path uses `M=N` or `M=N-1`. The observed panic establishes the resulting stores and pointer value exactly.

The earlier suspected byte fields `cfg+0x18D9/+0x18DA` and command `+0x3811/+0x3812` are **not** the producer fields and are rejected.

## 2. Exact N-dependent corruption and P=f(N)

### 2.1 The actual OOB producer

The relevant vulnerable encode-preparation block is:

```asm
v+0x11C078  ldr   x8, [x23, #8]        ; x8 = session/config allocation S
v+0x11C07C  mov   w10, #0x4678
v+0x11C080  add   x10, x8, x10         ; store base = S+0x4678
v+0x11C084  ldr   w11, [x8, #0x3760]   ; M = effective temporal count
v+0x11C088  mov   x12, #-1             ; x9 is already 0: i = 0

v+0x11C08C  str   w24, [x10, x9, lsl #2] ; *(u32 *)(S+0x4678+4*i) = w24
v+0x11C090  add   x9, x9, #1
v+0x11C094  add   x12, x12, #1
v+0x11C098  cmp   x12, x11
v+0x11C09C  b.lo  #0x11C08C
```

**[STATIC]** There is no bounds check on `M` or on the store address in this loop.

The loop executes `M+1` iterations for unsigned `M`, with:

```text
A(i) = S + 0x4678 + 4*i,   i = 0 ... M
W(i) = zero-extended 32-bit w24
```

The fixed loop at `f+0x11FA20`–`f+0x11FA40` has the same store and stride, now using internal `+0x3768`; the important mitigation is the new input validation, not a changed loop bound.

`w24` is computed earlier as a minimum of encoding-derived values. It is not loaded from N and is not an arbitrary attacker-supplied 64-bit value. **[PANIC]** The resulting pointer proves that `w24=1` on the observed panic path.

### 2.2 Why the pointer becomes 0x100000001

The teardown pointer array begins at `S+0x147B0`. Entry zero is initially allocated and stored legitimately:

```asm
v+0x736CC  bl   #0x1D0098             ; allocator
v+0x736D0  bl   #0x123868             ; object constructor
v+0x736D4  str  x0, [x22, #0x7B0]     ; legitimate entry zero
```

Thus the panic value is downstream corruption, not an uninitialized pointer.

The OOB loop reaches that slot at these exact indices:

```text
S+0x147B0 = S+0x4678+4*16462
S+0x147B4 = S+0x4678+4*16463
```

For the N=16463 panic path, the two adjacent 32-bit stores of `1` produce:

```text
u32[S+0x147B0] = 1
u32[S+0x147B4] = 1
Q = u64[S+0x147B0] = 0x0000000100000001
```

**[STATIC+PANIC]** This exactly explains `x19=x21=0x0000000100000001` in the supplied log.

A secondary property-count loop at `v+0x11C0C8`–`v+0x11C0E0` has the same unchecked `w24` store shape, with base `S+0x6424` and count from internal `+0x6230`. It is another reason not to model the defect as a single isolated pointer overwrite: oversized counts cause a long sequential overwrite through the containing allocation.

### 2.3 Teardown reloads the corrupted Q

```asm
v+0x73D5C  add  x8, x19, #0x14, lsl #12
v+0x73D60  add  x23, x8, #0x7B0       ; &S->entries[0], S+0x147B0
v+0x73D64  mov  w24, #3
v+0x73D70  ldr  x21, [x23, x22, lsl #3] ; Q for entry zero
v+0x73D74  cbz  x21, #0x73D90
v+0x73D78  mov  x0, x21
v+0x73D7C  bl   #0x123ADC
```

The wrapper preserves `Q`:

```asm
v+0x123AF0  mov  x19, x0
v+0x123AF4  bl   #0x1238DC
```

and `v+0x1238F8` again moves it to `x19`.

### 2.4 Exact P for the N=16463 panic

```asm
v+0x1239AC  add  x0, x19, #0x58       ; x0 = P = Q+0x58
v+0x1239B0  bl   #0xDA70              ; enter list body, not function entry
v+0x1239B4  add  x0, x19, #0x78       ; actual saved-LR return site
```

Therefore:

```text
P = 0x0000000100000001 + 0x58
  = 0x0000000100000059
```

This is the exact supplied `far`/`x0` value. The actual saved LR maps to `v+0x1239B4`; the previously suggested `+0xE39B4` anchor is incorrect.

So the precise answer to “OOB table load or base+N*stride?” is:

- **Producer:** base-plus-index OOB **stores**, `S+0x4678+4*i`.
- **Panic pointer:** not directly `base+N*stride`; it is a later **array load of the overwritten pointer**, followed by `+0x58`.

A universal closed-form `P(N)` is not appropriate because it depends on the effective count `M`, the pre-existing slot contents, and whether both halves are overwritten. The exact observed case is fully determined as above.

## 3. The +0xDA60 thunk/callee and panic writes

The outlined routine is:

```asm
v+0xDA60  pacibsp
v+0xDA64  stp  x29, x30, [sp, #-0x10]!
v+0xDA68  mov  x29, sp
v+0xDA6C  bl   #0x1CF880
v+0xDA70  bti  c
v+0xDA74  cbz  x0, #0xDA88
v+0xDA78  stp  x0, x0, [x0]
v+0xDA7C  str  x0, [x0, #0x10]
v+0xDA80  str  wzr, [x0, #0x18]
v+0xDA84  ret
```

**[STATIC]** The panic caller branches to the BTI body at `+0xDA70`, not to the PAC prologue at `+0xDA60`. Consequently `+0x1CF880` is **not called on this path**. It is a real outlined callee with its own BTI/PAC prologue, but it is irrelevant to the observed fault.

If P were writable, the body would initialize a list head as follows:

```text
[P+0x00] = P       (8 bytes)
[P+0x08] = P       (8 bytes)
[P+0x10] = P       (8 bytes)
[P+0x18] = 0       (4 bytes)
```

Total touched extent: **28 bytes, P through P+0x1B**. The supplied panic has ESR `0x96000046` (write abort) and stops on the first `stp` at `v+0xDA78`.

## 4. N=16462: does it silently write mapped kernel memory?

**Yes, statically it still performs a long OOB overwrite inside the mapped session/config allocation. “Survives” must not be interpreted as “no write.”**

For the direct algorithmic-loop model `M=N`:

```text
N=16462:
  iterations = 16463
  final store address = S+0x4678+4*16462 = S+0x147B0

N=16463:
  iterations = 16464
  final two stores = S+0x147B0 and S+0x147B4
```

Thus N=16462 reaches the low 32-bit word of entry zero but does not execute the next store into its high word on that loop invocation. The slot afterward is:

```text
Q_after = (Q_before & 0xFFFFFFFF00000000) | zero_extend(w24)
```

not necessarily `0x100000001`.

If a path normalizes the effective count to `M=N-1`, the last algorithmic-loop store is instead four bytes earlier (`S+0x147AC`), still deep inside the mapped allocation. The static verdict that N=16462 is not a non-writing/safe case does not depend on choosing between those normalizations.

**[POC-CLAIM]** N=16462 reportedly survives. No supplied register dump establishes the resulting slot or later lifecycle for that run, so the survival label is not evidence against the instruction-level overwrite.

## 5. Controllability assessment

### What N controls

- The effective loop bound and therefore the end offset of a forward sequential overwrite.
- Whether execution reaches specific later fields, including `S+0x147B0`.
- Indirectly, the value of a pointer later consumed during teardown when the overwrite changes that pointer.

### What N does not provide

- No arbitrary 64-bit write value: each producer store is the current 32-bit `w24`; the panic run has `w24=1`.
- No arbitrary destination independent of history: the store base is fixed at `S+0x4678`, and every earlier 32-bit slot is written before the selected final index.
- No direct way to make the list initializer write attacker-chosen data to an attacker-chosen address: its value and address are both derived from the already-corrupted Q (`P=Q+0x58`, and the list value is P itself).
- No demonstrated single-write `write-what==where` primitive.

The accurate primitive description is:

> **Count-controlled, forward, contiguous 32-bit OOB overwrite with a non-arbitrary encoding-derived value, followed by type confusion/wild-pointer teardown.**

Exploitability beyond denial of service is not established by this analysis. In particular, the exact `0x100000001 -> P=0x100000059` panic is a collision with fixed data written by the loop, not evidence that N directly encodes P.

## 6. Fixed-build comparison

The fixed build preserves the loop but adds validation before oversized values can reach it:

| Meaning | Vulnerable input | Vulnerable internal | Fixed input | Fixed internal | Fixed check |
|---|---:|---:|---:|---:|---|
| Algorithmic temporal count used by OOB loop | `+0x1880` | `+0x3760` | `+0x1888` | `+0x3768` | `f+0x714B0`: `<=6` |
| HEVC property representation | `+0x4350` | `+0x6230` | `+0x4358` | `+0x6238` | `f+0x71A60`: `<=6` |

The fixed algorithmic loop is at `f+0x11FA30`; it still uses stride 4 and the same `i=0...M` shape. The security boundary is therefore the configuration validation, not a safer store instruction.

## 7. Rejected alternate theories

- **`cfg+0x18D9/+0x18DA` as N:** rejected. Those were inferred from structure shifting, not from a producer. The actual corrupting count is the 32-bit field at vulnerable input `+0x1880`, internal `+0x3760`.
- **The supplied fixed `f+0x70EA4` anchor as NTL:** rejected. Its checks match AVC syntax fields (`iNumSliceGroups`, default reference counts, `iLog2MaxFrameNum`, and `iLog2MaxPOCLsb`).
- **The compares against 0x4E/0x4F at `v+0x15781C/+0x157824`:** rejected. They are character checks in formatting code, not temporal-layer bounds.
- **An OOB pointer-table load as the primary bug:** rejected. The primary producer is an OOB `str w24` loop; the pointer load occurs later during teardown.
- **A call to `+0x1CF880` before the panic:** rejected for this path. The caller enters at `+0xDA70`, skipping `+0xDA6C`.
- **Saved LR `+0xE39B4`:** rejected by arithmetic and instruction matching. The real return site is `+0x1239B4`.

## 8. Remaining boundary of this analysis

The kext-side producer and panic chain are closed. This report does not independently reverse the userland VideoToolbox/videocodecd serializer, so the app-property-to-wire-format byte offset is not claimed as independently proved. The analysis starts at the AppleAVE2 input configuration structure and establishes the vulnerable kernel field, copy, OOB store, teardown pointer corruption, and exact panic address.

No VM or physical experiment was run. The N=16463 register-level match is external physical corroboration of the static chain; the N=16462 conclusion is a static write-extent conclusion, not a new dynamic reliability claim.
