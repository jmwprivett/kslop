# AppleAVE2 26.0: dimension arithmetic and `dart-ave` mapping for CVE-2026-112705 shape (B)

**Date:** 2026-11-01\
**Scope:** read-only static reverse engineering of local artifacts. Nothing was run on a device or VM; no network access was used.\
**Primary target:** iOS 26.0 (23A341), iPhone17,2-class AppleAVE2 904.76.7.

## Evidence labels and bottom line

- **[STATIC]** Instruction/dataflow evidence in the local kext slices.
- **[POC-CLAIM]** The external Lak453 report of a `dart-ave` PTE-invalid WRITE fault at 32768x16384. No panic log was supplied and it was not reproduced here.
- **Not VM-proved. Not physical-proved.**

### Executive verdict

1. **`[x22,#0x3a90]` is the encoder-usage selector, not `NumberOfTemporalLayers`.** Its six `cmp #6` sites select usage-name strings for logging. The separate 26.0 temporal-layer check already rejects counts above 8. **[STATIC]**
2. There is a real 32-bit plane-size computation `width * height * bytesPerElement` at `v-ip17+0xF3304/0xF3308`, called for plane 0 at `v-ip17+0x137DD4`. At the PoC dimensions it produces `0x80000000`. **This word is post-map hardware plane metadata, not the DART map length or page count.** **[STATIC]**
3. The DART path pins/maps an IOSurface-derived `IOMemoryDescriptor`. The mapper returns the IOVA; the kext does not compute IOVA from width, height, bpp, or the wrapped plane-size word. **[STATIC]**
4. No direct raw-malloc/non-IOSurface CVPixelBuffer pinning path was found in AppleAVE2. The external-surface interface resolves IOSurfaces, so any malloc-to-IOSurface/memory-descriptor conversion is upstream of this kext boundary. **[STATIC, with that boundary explicit]**
5. The H.264 capability validator rejects both 32768x16384 and the PoC's 16384x16384 guard. Relevant maxima are 4096x4096 or 8192x8192 for the `(1,1)` validator mode; the other H.264 mode's tall/wide entries also do not accept 32768x16384. **[STATIC]**
6. **Controllability verdict:** no attacker-chosen IOVA, no chosen physical-page write, and no arbitrary read-back channel are established. Shape (B) is **not evidenced as an arbitrary-physical-write/KRW primitive**. The reported fault remains **[POC-CLAIM]**; the inspected 26.0 path instead presents validation/fail-closed obstacles before a DMA overrun could be reached. This is not a claim that every upstream VideoToolbox/IOSurface implementation is bug-free.

## Artifacts and notation

Primary files:

```text
/tmp/ave-analysis/v-ip17-26.0/AppleAVE2.__TEXT_EXEC.bin
/tmp/ave-analysis/v-ip17-26.0/AppleAVE2.kextblob
/tmp/ave-analysis/v-ip17-26.0/meta.json
```

Comparison files used for the NTL and arithmetic checks:

```text
/tmp/ave-analysis/v-d23-27.0.1/AppleAVE2.__TEXT_EXEC.bin
/tmp/ave-analysis/f-ip17-27.2/AppleAVE2.__TEXT_EXEC.bin
/tmp/ave-analysis/f-d23-27.2/AppleAVE2.__TEXT_EXEC.bin
```

`v-ip17+...` is an offset in the 26.0 `__TEXT_EXEC` slice. Blob string offsets below are offsets in `AppleAVE2.kextblob`; for `__TEXT`, blob offset equals the kext-relative `__TEXT` offset. The 26.0 `__TEXT` VM base is `0xfffffff00721df50`; `__TEXT_EXEC` VM base is `0xfffffff008cd5b00`.

PoC source reviewed, but not built or run:

```text
/Users/josh/dev/incoming-untrusted/Lak453-CVE-2026-112705-poc/Sources/AVEVideoEncoderProbe.swift
```

It creates an H.264 session at 32768x16384, a 32BGRA CVPixelBuffer without IOSurface attributes, and submits one encode. The guard is 16384x16384. **[POC-CLAIM]** is the separate author report that this causes a `dart-ave` PTE-invalid WRITE fault on 26.0.

---

## 1. Field `0x3a90`: encoder usage, not temporal layers

### 1.1 Representative site

The first of the six sites is in the logging/message-formatting routine beginning at `v-ip17+0x45B1C`:

```asm
v-ip17+0x45BC8  ldr  w8, [x22, #0x3a90]
v-ip17+0x45BCC  cmp  w8, #6
...
v-ip17+0x45BD8  b.hs v-ip17+0x45D68
v-ip17+0x45BDC  adrp x9, ...            ; usage-name table
v-ip17+0x45BE4  lsl  x8, x8, #3         ; 8-byte string pointer per usage
...
v-ip17+0x45BFC  ldr  x8, [x10]          ; select usage name
```

Values below 6 index a six-entry string table. Values 6 and 7 take the explicit fallback selector:

```asm
v-ip17+0x45D68  adrp x9, ...
v-ip17+0x45D6C  add  x9, x9, #0x32d   ; blob 0x503D0: "SideCar (FT)"
v-ip17+0x45D70  adrp x10, ...
v-ip17+0x45D74  add  x10, x10, #0x320 ; blob 0x503DD: "iChat"
v-ip17+0x45D78  cmp  w8, #7
v-ip17+0x45D7C  csel x8, x10, x9, eq
```

The selected name is passed to the format string at blob `0x9116A`:

```text
%lld %d AVE %s: USAGE %s - slices %d
```

The six table entries resolve to:

| Value | Blob offset | String |
|---:|---:|---|
| 0 | `0x50379` | `FaceTime` |
| 1 | `0x50382` | `CarPlay (FT)` |
| 2 | `0x5038F` | `AirPlay (FT)` |
| 3 | `0x5039C` | `SafeView (FT)` |
| 4 | `0x503AA` | `MediaAnalysis (FT)` |
| 5 | `0x503BD` | `ScreenSharing (FT)` |
| 6 | `0x503D0` | `SideCar (FT)` |
| 7 | `0x503DD` | `iChat` |

The other sites (`0x45C68`, `0x45D14`, `0x47158`, `0x471F4`, `0x472A0`) repeat the same usage-name selection in parallel logging paths. They are not NTL bounds checks. **[STATIC]**

### 1.2 The actual 26.0 temporal-layer bound

A separate validator loads `iNumOfTemporalLayer` from `cfg+0x268` and rejects values `>=9`:

```asm
v-ip17+0x57768  ldr  w8, [x21, #0x268]
v-ip17+0x5776C  cmp  w8, #9
v-ip17+0x57770  b.hs v-ip17+0x5781C    ; rejection/logging
v-ip17+0x57774  mov  w20, #0           ; success
```

Its assertion at blob `0x53C62` explicitly names:

```text
0 <= pInfo->sSessionCfg.sEnc.sAlgCfg.sGOP.iNumOfTemporalLayer &&
((...iNumOfTemporalLayer - 1) <= 7) && ...
```

Thus 26.0 accepts 1–8 on this validator path. This is independent of the 27.2 `<=6` hardening and of the 27.0.1-only unbounded store-loop shape (A). The 26.0 loop scanner also finds zero backward `str w,[x,x,lsl #2]` loops, consistent with shape (A) being absent. **[STATIC]**

---

## 2. Dimension to 32-bit plane size: exact overflow site

### 2.1 Plane-info construction happens after mapping

`v-ip17+0x1379D4` builds an 0x80-byte per-plane metadata record. It first requires the surface's mapped flag and obtains the mapper-produced base IOVA:

```asm
v-ip17+0x137A08  ldr  x8, [x19, #0xf0]
v-ip17+0x137A0C  lsr  x8, x8, x22
v-ip17+0x137A10  tbz  w8, #0x10, failure ; require DART-mapped plane
...
v-ip17+0x137A48  ldr  x8, [mapped-entry-slot]
v-ip17+0x137A50  ldr  x24, [x8, #0x20]   ; mapped IOVA
```

For a format without a specialized descriptor—the path applicable to an unrecognized packed format such as BGRA—the generic plane-0 path calls three IOSurface accessors and then the 32-bit multiply helper:

```asm
v-ip17+0x137D9C  ldr  x0, [x19, #0x68]   ; IOSurface
v-ip17+0x137DA0  mov  w1, #0             ; plane 0
v-ip17+0x137DA4  bl   ...                 ; width
v-ip17+0x137DA8  mov  x21, x0
v-ip17+0x137DAC  ldr  x0, [x19, #0x68]
v-ip17+0x137DB0  mov  w1, #0
v-ip17+0x137DB4  bl   ...                 ; height
v-ip17+0x137DB8  mov  x22, x0
v-ip17+0x137DBC  ldr  x0, [x19, #0x68]
v-ip17+0x137DC0  mov  w1, #0
v-ip17+0x137DC4  bl   ...                 ; bytes per element
v-ip17+0x137DC8  mov  x2, x0
v-ip17+0x137DCC  mov  x0, x21
v-ip17+0x137DD0  mov  x1, x22
v-ip17+0x137DD4  bl   v-ip17+0xF3300
v-ip17+0x137DD8  str  w0, [x20, #8]       ; 32-bit plane-info size
```

The helper is exactly:

```asm
v-ip17+0xF3300  bti  c
v-ip17+0xF3304  mul  w8, w1, w0          ; height * width, low 32 bits
v-ip17+0xF3308  mul  w0, w8, w2          ; * bytesPerElement, low 32 bits
v-ip17+0xF330C  ret
```

Equivalent calls occur at `v-ip17+0x137F64` (alternate plane-0 format path) and `v-ip17+0x1381FC` (plane 1). **[STATIC]**

For the PoC's BGRA values:

```text
width * height       = 32768 * 16384 = 0x20000000
* bytesPerElement(4) = 0x80000000
plane_info->size     = 0x80000000
```

**Important precision:** `0x80000000` fits in `uint32_t`; the PoC's exact size does not lose magnitude modulo 2^32. It becomes negative only when consumed as signed `int32_t`. Products above `0xFFFFFFFF` would wrap modulo 2^32. **[STATIC arithmetic]**

### 2.2 What this size does—and does not—control

The result is stored at `plane_info+8`, after a DART mapping already exists. It is not passed as the map length to the DART mapper. No instruction on the mapping path computes page count or IOVA from this product. **[STATIC]**

The 27.2 iPhone17-class slice retains the same two-`mul w` helper at `f-ip17+0x111204/0x111208`; therefore this arithmetic alone is not evidence of the 27.2 CVE fix. **[STATIC comparison]**

---

## 3. DART pin/map and IOVA path

### 3.1 External input is IOSurface-based at this kext boundary

The external-surface wrapper at `v-ip17+0x1327B0` requires a non-null surface object, saves it at `surface+0x68`, and obtains a 32-bit total-length accessor result:

```asm
v-ip17+0x1328D4  mov  x0, x22             ; IOSurface
v-ip17+0x1328D8  bl   ...                  ; total length accessor, w0 result
v-ip17+0x1328DC  str  w0, [x19, #0xe0]    ; surface->size32
v-ip17+0x1328E0  str  x22, [x19, #0x68]   ; surface->IOSurface
```

Its callers resolve the external surface before this constructor; for example `v-ip17+0x132B78–0x132BA4` performs the surface lookup and then calls the wrapper. No inspected constructor takes a raw user virtual address and byte length for an encode input. **[STATIC]**

Consequently, the precise Lak453 malloc-backed CVPixelBuffer cannot be followed directly into AppleAVE2 from the supplied artifacts. The kext sees an IOSurface-style object/descriptor, not the original malloc pointer. Any upstream emulation, copy, or descriptor wrapping remains unanalyzed. **[STATIC boundary]**

### 3.2 Pinning and mapping

The surface preparation routine obtains and prepares the memory descriptor:

```asm
v-ip17+0x1352E8  ldr  x0, [x19, #0x68]
v-ip17+0x1352EC  bl   ...                 ; get IOMemoryDescriptor
v-ip17+0x1352F0  str  x0, [x19, #0x78]
...
v-ip17+0x13534C  mov  w1, #3
v-ip17+0x135358  blraa ...                ; descriptor prepare/pin
```

The DART-map routine then supplies the descriptor to the mapper and obtains a mapped entry:

```asm
v-ip17+0x135D80  ldr  x25, [x19, #0x78]  ; memory descriptor
v-ip17+0x135D84  ldr  x0, [x19, #0x68]
v-ip17+0x135D88  bl   ...                 ; descriptor/DMA-related object
v-ip17+0x135D8C  mov  x2, x0
v-ip17+0x135D90  mov  x0, x20             ; DART manager
v-ip17+0x135D94  mov  x1, x25
v-ip17+0x135D98  bl   v-ip17+0x70804      ; allocate/prepare map entry
...
v-ip17+0x135DA4  ldr  x1, [x19, #0x78]
v-ip17+0x135DBC  mov  x0, x20
v-ip17+0x135DC0  mov  x2, x25             ; output entry slot
v-ip17+0x135DC4  bl   v-ip17+0x6E8D8      ; DART map
```

Inside `0x6E8D8`, virtual mapper operations map the memory and retrieve the mapped segment. On success:

```asm
v-ip17+0x6EE2C  ldp  x9, x8, [x29, #-0x60] ; entry and mapper output
v-ip17+0x6EE30  str  x8, [x9, #0x20]        ; entry->iova = mapper result
v-ip17+0x6EE34  str  x9, [x21]              ; return entry
```

The address later exposed by `v-ip17+0x136734` is `entry+0x20` plus a plane-specific signed offset. There is no `iova = f(width*height*bpp)` operation. The physical pages are those pinned from the supplied memory descriptor. **[STATIC]**

### 3.3 Separate signed-length range check

The wrapper's 32-bit total length at `surface+0xe0` is used after mapping for statistics and, for DART type 3, an IOVA-range check:

```asm
v-ip17+0x135FC0  ldr   x0, [x19, #0x18]
v-ip17+0x135FC4  bl    v-ip17+0x735A8      ; DART type
v-ip17+0x135FCC  cmp   w0, #3
v-ip17+0x135FD0  b.ne  accept_without_this_check
...
v-ip17+0x135FD8  ldr   x9, [x8, #0x20]      ; mapped IOVA
v-ip17+0x136048  ldrsw x10, [x19, #0xe0]    ; signed size32
v-ip17+0x13604C  add   x9, x9, x10           ; IOVA + sign_extend(size32)
v-ip17+0x136050  mov   w10, #1
v-ip17+0x136054  movk  w10, #0x7080, lsl #16 ; 0x70800001
v-ip17+0x136058  cmp   x9, x10
v-ip17+0x13605C  b.lo  accept
```

On this type-3 path, `size32=0x80000000` is sign-extended to `-0x80000000`; the unsigned sum does not satisfy the ordinary low-IOVA upper-bound check, so mapping fails rather than yielding an encode with a shortened mapping. The associated log is `DART mapped address is out of range` (blob `0x7407C`). **[STATIC]**

This check must not be confused with DART page-count computation: it happens after the mapper call, and it is conditional on DART type 3. No dynamic claim is made about which upstream object type the external PoC reached.

---

## 4. Controllability and exploitability

### IOVA control

- The base IOVA is mapper output stored at `entry+0x20` (`0x6EE2C–0x6EE34`). Width, height, bpp, and the wrapped plane-size word do not select it. **[STATIC]**
- Per-plane metadata adds an IOSurface plane offset to that base. This offers only surface-layout influence, not an arbitrary 64-bit IOVA. **[STATIC]**
- No instruction was found that treats the overflowed size as an IOVA or adds it to an attacker-selected physical address. **[STATIC]**

### Physical pages and a hypothetical overrun

The mapped physical pages come from the supplied descriptor. Dimensions do not choose arbitrary physical pages. If a separate upstream bug produced a short mapping while hardware continued with larger dimensions, the plausible result would be a forward DMA access beyond the mapped IOVA extent. A PTE-invalid fault on an unmapped next page is DoS behavior, not by itself a write primitive.

Turning such a hypothetical overrun into a chosen physical write would additionally require control over adjacent IOVA mappings and their physical backing, plus control over the DMA-written contents. IOSurface spraying could influence allocator layout, but the inspected code does not establish IOVA adjacency, a chosen target page, or attacker-selected out-of-range write data. None of those prerequisites is demonstrated by the PoC source. **[STATIC assessment; trigger itself POC-CLAIM]**

### Read-back

Normal encoded H.264 output is not an arbitrary physical-memory read-back channel. No path from the claimed out-of-range DMA write to encoded-output disclosure was found. **[STATIC]**

### Verdict

**No arbitrary-physical-write or KRW primitive is established for shape (B).** The evidence supports, at most, a hypothetical uncontrolled DMA-overrun/DoS model if independent upstream defects were to bypass the checks documented here. The self-reported panic remains unverified, and the exact 26.0 H.264 configuration is rejected by the capability validator described next.

---

## 5. Width/height validation and maximum accepted dimensions

### 5.1 Validator instruction path

The prepare validator loads session width/height and calls `v-ip17+0x69D0C`:

```asm
v-ip17+0x56FEC  ldr  w22, [x21, #0xa58]  ; width
v-ip17+0x56FF0  ldr  w23, [x21, #0xa5c]  ; height
...
v-ip17+0x5719C  mov  x0, x19              ; client/capability class
v-ip17+0x571A0  mov  w1, #1               ; H.264 selector
v-ip17+0x571A4  mov  w2, #1               ; mode 1
v-ip17+0x571A8  mov  x3, x22              ; width
v-ip17+0x571AC  mov  x4, x23              ; height
v-ip17+0x571B0  mov  w5, #1               ; usage class
v-ip17+0x571B4  bl   v-ip17+0x69D0C
```

The helper first requires a minimum-dimension table match, then a per-usage maximum-dimension match:

```asm
; Minimum candidate: skip when minWidth > width or minHeight > height.
v-ip17+0x69D50  ldur w13, [x9, #-4]
v-ip17+0x69D54  cmp  w13, w21
v-ip17+0x69D58  b.gt next
v-ip17+0x69D5C  ldr  w13, [x9]
v-ip17+0x69D60  cmp  w13, w20
v-ip17+0x69D64  b.le minimum_match

; Maximum/usage candidate: require maxWidth >= width and maxHeight >= height.
v-ip17+0x69DA8  ldur w11, [x10, #-4]
v-ip17+0x69DAC  cmp  w11, w21
v-ip17+0x69DB0  b.lt next
v-ip17+0x69DB4  ldr  w11, [x10]
v-ip17+0x69DB8  cmp  w11, w20
v-ip17+0x69DBC  b.lt next
v-ip17+0x69DC0  ldur w11, [x10, #-8]      ; usage, negative = wildcard
v-ip17+0x69DC4  cmp  w11, w19
v-ip17+0x69DC8  b.eq success
v-ip17+0x69DCC  tbnz w11, #0x1f, success
```

Failure returns `-0x3EA`. These are table-driven signed comparisons, not a single universal `cmp width,#0x8000`. **[STATIC]**

### 5.2 Relevant maxima

For the `(H.264 selector=1, mode=1)` lookup:

| Client classes | Capability blob | Minimum entry | Maximum/usage entry |
|---|---:|---|---|
| `0x01–0x1F` (representative tables) | e.g. `0x132A0` | `(1, 192, 96)` | `(-1, 4096, 4096)` |
| `0x20–0x22` | `0x133D8` | `(1, 128, 64)` | `(-1, 8192, 8192)` |

The exact runtime client class was not dynamically measured, but **no H.264 mode-1 class in the table permits either 32768x16384 or 16384x16384**. **[STATIC]**

For the separate `(1,2)` H.264 mode, table entries include wide/tall forms such as 65536x8192 (65520 on classes `0x20–0x22`), 8192x16384, 16384x8192, and 4096x4096, selected by usage. Even those do not include 32768x16384 or 16384x16384 as an accepted pair. **[STATIC]**

Thus, on the inspected 26.0 validator path, the Lak453 session should fail preparation before input DART mapping. This is a static reachability conclusion, not a dynamic reproduction. The absence of logs or returned `OSStatus` values in the external claim leaves the contradiction unresolved.

---

## Final assessment

The 26.0 kext does contain the suspected 32-bit width×height×bytes-per-element arithmetic, but its security role is different from the PoC hypothesis:

```text
IOSurface dimensions
  -> 32-bit plane metadata size at plane_info+8   [post-map]
  -> no dimension-derived DART page count or IOVA found

IOMemoryDescriptor
  -> pin/prepare
  -> DART mapper
  -> mapper-selected IOVA at entry+0x20
```

Field `0x3a90` is usage, NTL is separately bounded to 8, H.264 dimensions are capability-checked below the PoC sizes, and no direct raw-malloc input path or chosen-IOVA mechanism was found. **Shape (B) is not a demonstrated KRW route on the supplied 26.0 evidence; the reported `dart-ave` WRITE panic remains [POC-CLAIM], not VM- or physical-proved.**
