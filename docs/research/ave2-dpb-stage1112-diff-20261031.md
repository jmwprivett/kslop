# AppleAVE2 stage11/stage12 DPB diff: no kernel-side 17-slot OOB write found

Date: 2026-10-31\
Scope: static, read-only analysis of local AppleAVE2 slices and the external PoC source. Nothing was executed on a device or VM; no network access was used.

## Executive result

The external PoC's stage11/stage12 comments do **not** describe the AppleAVE2 kernel consumer found in these binaries.

- The kernel has a DPB initialization loop that copies IOSurface pointers and their 32-bit IDs into fixed per-plane arrays. In **27.0.1**, the loop is already guarded by `num_ref_frame < 17` at `v+0x15F9C`; counts `>= 17` take the rejection path before any array writes.
- The 27.2 loop at `f+0x15FC0` is the same check and the same copy logic, apart from relocated call/branch targets. **27.2 did not add the gate claimed by the PoC comments.**
- The 27.0.1 stores are `str x0, [... + i*8]` for an IOSurface pointer and `str w0, [... + i*4]` for its ID. They are attacker-influenced in the ordinary sense that the app supplied the surfaces, but they are **in-bounds** and therefore are not a kernel-write primitive.
- The separate configuration validator also already requires `userDPBnumFrames` to be in **[2,17]** in 27.0.1 (`v+0x715D8`), with the equivalent check in 27.2 (`f+0x72984`).
- The often-cited fixed ladder at `f+0x70EA4` is **AVC syntax validation, not DPB or NumberOfTemporalLayers validation**. Its fields are slice-group/reference-index and H.264 log2 limits.
- Consequently, stage11/12 cannot presently be assigned to CVE-2026-112468, -112469, -112470, or -112689. Those advisories require an OOB write capable of corrupting **kernel** memory; this path does not provide one. A userland `videocodecd` bug at `session+0xb68` remains a separate, unverified possibility and would not itself be a kernel write.

**Bottom line:** stage11/12 are not a stronger kernel-write primitive than the NumberOfTemporalLayers path on the inspected kext evidence. The NTL panic's wild list initialization remains the only demonstrated kernel-memory write in this PoC audit; the DPB route has no demonstrated OOB kernel write at all.

## Evidence standard

- **Implemented/statically established:** instruction offsets, comparisons, source/destination addressing, loop bounds, and the vulnerable/fixed instruction match below.
- **Externally reported only:** the PoC author's claim of a fixed 17-slot table at userland `session+0xb68` and a 27.2 `count < 17` gate. The corresponding userland plugin was not among the supplied artifacts and was not analyzed here.
- **Not VM-proved:** no trigger was run in the research VM.
- **Not physical-proved:** no trigger was run on the iPhone17,2 or any other device.

## Artifacts and notation

| Label | Build / device class | Slice |
|---|---|---|
| `v` | iOS 27.0.1 24A446, d23, AppleAVE2 913.43.1 | `/tmp/ave-analysis/v-d23-27.0.1/AppleAVE2.__TEXT_EXEC.bin` |
| `f` | iOS 27.2 24B119, d23, AppleAVE2 913.64.1 | `/tmp/ave-analysis/f-d23-27.2/AppleAVE2.__TEXT_EXEC.bin` |
| `v-ip17` | iOS 26.0 23A341, iPhone17,2 class, AppleAVE2 904.76.7 | `/tmp/ave-analysis/v-ip17-26.0/AppleAVE2.__TEXT_EXEC.bin` |
| `f-ip17` | iOS 27.2, iPhone17,2 class | `/tmp/ave-analysis/f-ip17-27.2/AppleAVE2.__TEXT_EXEC.bin` |

All `v+...`/`f+...` addresses are offsets from the start of the corresponding self-contained `__TEXT_EXEC` slice. Disassembly used local Capstone 5.0.7. String references below are to `AppleAVE2.kextblob` offsets in the same directories.

PoC source reviewed:

- `/Users/josh/dev/incoming-untrusted/AVETemporalPoC-CVE-2026-112705/AVETemporalPoC/Runner.swift`
- stage11, lines 736–767: passes an N-element array as `DPBRequirements`.
- stage12, lines 460–526: sets `EnableUserRefForFacetime`, a `DPBRequirements` dictionary, and an N-element `UserDPBFramesForFaceTime` array of `IOSurfaceGetID` values.

## 1. The `f+0x70EA4` ladder is AVC, not DPB

The fixed instructions are:

```asm
f+0x70EA4  ldrb w8, [x24, #0x8e1]
f+0x70EA8  cmp  w8, #1
f+0x70EAC  b.ne rejection

f+0x70EB0  ldrb w8, [x24, #0x8e2]
f+0x70EB4  sub  w8, w8, #1
f+0x70EB8  cmp  w8, #0xf
f+0x70EBC  b.hi rejection

f+0x70EC0  ldrb w8, [x24, #0x8e3]
f+0x70EC4  sub  w8, w8, #1
f+0x70EC8  cmp  w8, #0x10
f+0x70ECC  b.hs rejection

f+0x70ED0  ldrb w8, [x24, #0x89c]
f+0x70ED4  sub  w8, w8, #4
f+0x70ED8  cmp  w8, #0xc
f+0x70EDC  b.hi rejection

f+0x70EE0  ldrb w8, [x24, #0x89e]
f+0x70EE4  sub  w8, w8, #4
f+0x70EE8  cmp  w8, #0xe
f+0x70EEC  b.hs rejection
```

The assertion strings referenced by the surrounding logging blocks identify the fields:

| Field | Accepted values | Identification evidence |
|---|---:|---|
| `cfg+0x8e1` | exactly 1 | `pInfo->sSyntaxCfgAVC.iNumSliceGroups == 1` (blob near `0x62D53`) |
| `cfg+0x8e2` | 1–16 | `iNumRefIdxL0DefaultActive <= (15 + 1)` (near `0x62D99`) |
| `cfg+0x8e3` | 1–16 | `iNumRefIdxL1DefaultActive <= (15 + 1)` (same assertion) |
| `cfg+0x89c` | 4–15 | `4 <= ...iLog2MaxFrameNum <= (12 + 4)` (near `0x62EAD`) |
| `cfg+0x89e` | 4–17 | `4 <= ...iLog2MaxPOCLsb <= (12 + 5)` (near `0x62EF8`) |

Other nearby fixed log strings explicitly say `AVC PPS count`, `AVC log2_max`, and `separate_colour_plane_flag`. None of these five fields is a DPB array count or an IOSurface-ID count. This also corrects the earlier tentative NTL interpretation in `ave2-cve-2026-112705-external-poc-audit-20261031.md`.

There are genuinely new 17-related HEVC syntax checks elsewhere in 27.2—for example, `f+0x71A70` concerns `num_long_term_ref_pics_sps <= 16`, and `f+0x71AF4` concerns the sum of long-term SPS/picture counts. Those are SPS/RPS checks, not `UserDPBFramesForFaceTime` table gates, and should not be conflated with stage12.

## 2. `userDPBnumFrames` was already range-checked in 27.0.1

The kext contains this assertion in both versions:

```text
2 <= pInfo->VideoParamsDriver.userDPBnumFrames &&
pInfo->VideoParamsDriver.userDPBnumFrames <= (max(...) + 1)
```

In 27.0.1 it is at blob `0x6316A`; in 27.2 at `0x63CE3`. The associated failure string is `user DPB number is out of range`.

### Vulnerable 27.0.1 check

```asm
v+0x715BC  ldr   w8, [x21, #0x161c]
v+0x715C0  cmp   w8, #1
v+0x715C4  b.ne  continue
v+0x715C8  mov   w9, #0x1790
v+0x715CC  add   x9, x21, x9
v+0x715D0  ldrb  w9, [x9]
v+0x715D4  tbz   w9, #0, continue
v+0x715D8  ldr   w9, [x21, #0x1794]   ; userDPBnumFrames
v+0x715DC  sub   w9, w9, #2
v+0x715E0  cmp   w9, #0x10
v+0x715E4  b.hs  rejection              ; rejects outside unsigned [2,17]
```

### Fixed 27.2 check

```asm
f+0x72968  ldr   w8, [x21, #0x1624]
f+0x7296C  cmp   w8, #1
f+0x72970  b.ne  continue
f+0x72974  mov   w9, #0x1798
f+0x72978  add   x9, x21, x9
f+0x7297C  ldrb  w9, [x9]
f+0x72980  tbz   w9, #0, continue
f+0x72984  ldr   w9, [x21, #0x179c]
f+0x72988  sub   w9, w9, #2
f+0x7298C  cmp   w9, #0x10
f+0x72990  b.hs  rejection
```

The structure shifted by eight bytes in this area, but the predicate is unchanged. Thus the broad statement “pre-fix has no DPB count gate” is false for this kext configuration path.

## 3. Actual kernel IOSurface-ID consumer and its pre-existing bound

The relevant DPB routine begins at `v+0x15E7C` (`bti c`, then `pacibsp`). Its caller at `v+0x178444` supplies, among other arguments:

- `x0`: DPB object being initialized;
- `x1`: count, moved to `w25` in the callee;
- `x4`: source array of IOSurface pointers, moved to `x24`;
- `x5`/`x6`: additional surface-pointer arrays;
- stack byte: controls the optional RVRA copies, moved to `w19`.

The fixed counterpart begins at `f+0x15EA0`, called at `f+0x17C18C`.

### 3.1 Both count checks precede all indexed stores

In 27.0.1:

```asm
v+0x15F18  ldr  w8, [x20]          ; profile/level maximum
v+0x15F1C  cmp  w25, w8
v+0x15F20  b.ls v+0x15F9C          ; otherwise rejection/logging

v+0x15F9C  cmp  w25, #0x11         ; num_ref_frame < 17 required
v+0x15FA0  b.hs v+0x160C8          ; rejection; no copy loop
v+0x15FA4  str  w25, [x20, #0xb60] ; save bounded count
```

The associated strings are:

- `DPB (%d): num_ref_frame (%d) > m_ctx.m_MaxDpbSizeForThisProfileAndLevel (%d) fail.`
- `DPB num_ref_frame (%d) > AVE_DPB_MAX_SIZE (%d)`
- assertion `num_ref_frame <= ((16) > (16) ? (16) : (16))`

Therefore the loop argument is limited to at most 16 iterations' worth of elements. This is independent of the separate `[2,17]` configuration-field check above; the PoC's raw CFArray element count must not be assumed to be identical to this callee's `num_ref_frame` argument.

The fixed code is byte-identical for this three-instruction sequence:

```asm
f+0x15FC0  cmp  w25, #0x11
f+0x15FC4  b.hs f+0x160EC
f+0x15FC8  str  w25, [x20, #0xb60]
```

The twelve bytes at `v+0x15F9C` and `f+0x15FC0` are exactly:

```text
3f470071 42090054 99620bb9
```

### 3.2 Instruction-level copy loop

Setup in 27.0.1:

```asm
v+0x16178  mov  x26, #0                 ; i = 0
v+0x1617C  add  x8, x20, #0x20
v+0x16180  stur x8, [x29, #-0x60]       ; dst pointer array = DPB+0x20
v+0x16184  add  x27, x20, #0x130        ; dst ID array = DPB+0x130
v+0x16188  add  x9, x20, #0x1b8        ; another pointer array
v+0x1618C  add  x10, x24, #0x110        ; optional RVRA source pointers
v+0x16190  add  x8, x20, #0xa8          ; optional RVRA dst pointers
v+0x16198  add  x8, x20, #0x174         ; optional RVRA dst IDs
```

Per iteration:

```asm
v+0x161A0  ldr  x0, [x24, x26, lsl #3]  ; source IOSurface pointer[i]
v+0x161A4  ldur x8, [x29, #-0x60]
v+0x161A8  str  x0, [x8, x26, lsl #3]   ; DPB+0x20+i*8 = pointer
v+0x161AC  cbz  x0, rejection
v+0x161B0  bl   v+0x159244              ; obtain 32-bit surface ID
v+0x161B4  str  w0, [x27, x26, lsl #2]  ; DPB+0x130+i*4 = ID
```

The accessor thunk is:

```asm
v+0x159244  bti  c
v+0x159248  ldr  x0, [x0, #0x68]
v+0x15924C  cbz  x0, return
v+0x159250  b    v+0x1D0498
```

So the stored 32-bit value comes from the kernel IOSurface object associated with the supplied buffer; it is not a raw 64-bit pointer truncated into the table.

The loop bound is reloaded from the already-checked saved count:

```asm
v+0x16388  ldr  w8, [x20, #0xb60]
v+0x1638C  cmp  x26, x8
v+0x16390  add  x26, x26, #1
v+0x16394  b.lo v+0x161A0
```

Optional RVRA operations in the same bounded loop are:

```asm
v+0x162AC  ldr  x0, [x9, x26, lsl #3]   ; source = user array +0x110
v+0x162B0  str  x0, [x8, x26, lsl #3]   ; DPB+0xa8+i*8
v+0x162B8  bl   v+0x159244
v+0x162C0  str  w0, [x8, x26, lsl #2]   ; DPB+0x174+i*4
```

Another source pointer array is copied to `DPB+0x1b8+i*8` at `v+0x16240..0x16248`, still under the same `num_ref_frame` bound.

The 27.2 instructions match at relocated addresses:

| Operation | 27.0.1 | 27.2 |
|---|---:|---:|
| Load source IOSurface pointer | `v+0x161A0` | `f+0x161C4` |
| Store pointer to `DPB+0x20+i*8` | `v+0x161A8` | `f+0x161CC` |
| Store ID to `DPB+0x130+i*4` | `v+0x161B4` | `f+0x161D8` |
| Reload bounded count | `v+0x16388` | `f+0x163AC` |
| Compare/increment/loop | `v+0x1638C..94` | `f+0x163B0..B8` |

The pointer/ID store sequences and loop-control bytes are unchanged except for PC-relative call/branch encodings. There is no removed check and no changed stride.

### 3.3 iPhone17,2 / iOS 26.0 coverage

The physical device's 26.0 slice has the same upper bound before DPB initialization:

```asm
v-ip17+0xDF5C  cmp  w25, #0x11
v-ip17+0xDF60  b.hs v-ip17+0xE08C
v-ip17+0xDF64  str  w25, [x20, #0xb60]
```

Its copy loop uses different register allocation but the same destinations:

```asm
v-ip17+0xE144  mov  w27, #0x130
v-ip17+0xE148  ldr  x0, [x24]
v-ip17+0xE14C  add  x21, x20, x26, lsl #3
v-ip17+0xE150  str  x0, [x21, #0x20]
v-ip17+0xE158  bl   surface-ID accessor
v-ip17+0xE15C  add  x22, x20, x27
v-ip17+0xE160  str  w0, [x22]
```

The fixed iPhone-class 27.2 slice has the `cmp w25,#0x11; b.hs; str w25,[...,#0xb60]` sequence at `f-ip17+0x15FC0`. Thus this is not a d23-only hardening difference.

## 4. What stage11/stage12 do—and do not—establish

### Stage11

`DPBRequirements` is not present as a string in either inspected AppleAVE2 kext. The kext receives decoded driver/session configuration rather than the raw CFArray used by stage11. No kernel external-method handler was found that walks stage11's N NSNumber elements into a 17-entry table. The claimed raw-array walk is therefore a userland-plugin question, not an evidenced kext write.

### Stage12

The kext does contain diagnostic strings for `UserDPBFramesForFaceTime`, `DPBAllocateRVRABuffers`, `DPBNumberOfFrames`, and `EnableUserRefForFacetime` (for example, vulnerable blob `0x6C81A` onward). Their nearby code is parameter logging, not an unchecked OSArray copy. The actual DPB surface consumer is the bounded routine documented above.

No instruction sequence was found in 27.0.1 that takes an unchecked stage12 N and performs N stores beyond a fixed 17-entry kernel table. Conversely, the concrete kernel ID-copy loop has two pre-existing limits: the profile/level maximum and `num_ref_frame < 17`.

The PoC's `session+0xb68` address is explicitly a userland plugin session offset in the source comments. The kernel DPB object happens to contain `0xb68`-byte per-plane regions, but that size coincidence is not evidence that the userland session and kernel object are the same object or share a base. The kernel ID arrays are at per-plane `+0x130` and `+0x174`, not a demonstrated `session+0xb68` raw-ID destination.

## 5. Value control and comparison with the NTL path

The application does influence which IOSurfaces reach stage12, and `IOSurfaceGetID` values are 32-bit IDs. This provides limited value influence through allocation order and surface grooming. It does **not** provide an arbitrary immediate 32-bit value: the ID is assigned to the surface by IOSurface, and the kernel loop re-obtains it from the IOSurface object.

Most importantly, there is no OOB address component. The effective addresses are:

```text
DPB + 0x20  + 8*i   (64-bit IOSurface pointer)
DPB + 0x130 + 4*i   (32-bit IOSurface ID)
```

with `0 <= i < num_ref_frame <= 16` on the inspected path. These stores are in-bounds. Calling this an attacker-steered OOB write would omit the decisive pre-existing check.

By contrast, the NTL panic at 27.0.1 `v+0xDA78` is a real wild write: `stp x0,x0,[x0]`, followed by more stores through the same pointer, with the supplied panic log showing a write data abort. Its value/address coupling (`P` at `P`) limits exploitation, but it is still a demonstrated kernel corruption path. Stage11/12 currently offer no kernel corruption primitive to compare against it.

## 6. Layout and hypothetical grooming—only if the old bound were bypassed

The following layout is directly implied by the loop's base/stride instructions and the post-initialization routine at `v+0x16880`. `D` is one per-plane DPB region, not the userland session:

| Offset from `D` | Inferred content | Size / next boundary |
|---|---|---|
| `+0x20` | primary IOSurface-pointer array | 17 slots × 8 = `0x88`; next at `+0xA8` |
| `+0xA8` | optional RVRA pointer array | 17 slots × 8; next at `+0x130` |
| `+0x130` | primary 32-bit IOSurface-ID array | 17 slots × 4 = `0x44`; next at `+0x174` |
| `+0x174` | optional RVRA 32-bit ID array | 17 slots × 4; next at `+0x1B8` |
| `+0x1B8` | additional IOSurface-pointer array | 17 slots × 8; next at `+0x240` |
| `+0x240`, `+0x290` | additional pointer arrays | accessed by the bounded setup at `v+0x163A0..C4` |
| `+0x2E0` | DPB elements | stride `0x80`, initialized at `v+0x168B8` onward |
| `+0xB60` | saved `num_ref_frame` | 32-bit |
| `+0xB64` onward | list/state fields | initialized at `v+0x1688C` onward |

The 17-element DPB-element region at `+0x2E0` occupies `17*0x80 = 0x880` bytes, ending exactly at `+0xB60`, which supports this layout interpretation.

If the `<17` check were hypothetically removed, the 18th iteration (`i=17`, zero-based) would make the primary ID store hit `D+0x174` and the primary pointer store hit `D+0xA8`: adjacent RVRA arrays. Further iterations would approach additional pointers and eventually the DPB-element region. That would be a useful corruption shape, especially because IDs are 32-bit and surface-influenced. **It is not a reachable primitive on the inspected 27.0.1 or 26.0 code because the old binary rejects the oversized loop count first.** This layout must not be presented as an implemented grooming result.

Also note the distinction between the configuration value's allowed maximum of 17 and this routine's `num_ref_frame <= 16`; no exact raw-stage12-array-length to `num_ref_frame` transformation is asserted here.

## 7. Apple advisory/CVE mapping

Apple publishes the relevant AVEVideoEncoder entries in both:

- iOS/iPadOS 27.2: <https://support.apple.com/en-us/149230>
- iOS/iPadOS 26.7.2: <https://support.apple.com/en-us/149227>

| CVE | Apple's class / impact | Stage11/12 mapping from this kext evidence |
|---|---|---|
| CVE-2026-112466 | OOB read; app may read kernel memory; improved bounds checking | No match: the analyzed loop is a bounded write, not an OOB read. |
| CVE-2026-112468 | OOB write; app may corrupt kernel memory; improved bounds checking | **Not established.** The required pre-fix OOB kernel write is absent; the same bound exists in 27.0.1 and 27.2. |
| CVE-2026-112469 | OOB write; corrupt kernel memory; improved bounds checking | **Not established**, for the same reason. |
| CVE-2026-112470 | OOB write; corrupt kernel memory; improved bounds checking | **Not established**, for the same reason. |
| CVE-2026-112689 | OOB write; corrupt kernel memory; improved input validation | **Not established.** No stage11/12 kernel input-validation delta leading to an OOB write was found. |
| CVE-2026-112705 | OOB write; unexpected system termination; improved bounds checking | The supplied panic belongs to the NTL `+0xDA78` path, not this bounded DPB loop. |

Assigning one of the four kernel-corruption CVEs to stage11/12 based only on the PoC comments would be speculative. If the userland table bug is real, it may explain process memory corruption in `videocodecd`; without a second kernel-side trust failure it does not satisfy Apple's “corrupt kernel memory” impact.

## Final assessment

1. **Claimed 27.2 gate:** not new in the kernel DPB consumer. The old gate is `v+0x15F9C`; the fixed equivalent is `f+0x15FC0`. The configuration range check likewise predates 27.2.
2. **Claimed OOB instructions:** none on this path. The actual stores are bounded `str x0`/`str w0` operations at `v+0x161A8` and `v+0x161B4` (RVRA variants at `v+0x162B0`/`v+0x162C0`).
3. **Table addressing:** primary pointer table `DPB+0x20`, stride 8; primary ID table `DPB+0x130`, stride 4; optional RVRA tables at `+0xA8`/`+0x174`.
4. **Written values:** valid IOSurface pointers and their kernel-assigned 32-bit IDs, influenced but not arbitrarily chosen by the app, and stored in-bounds.
5. **CVE:** no defensible stage11/12 assignment to CVE-2026-112468/469/470/689 from the kext diff.
6. **Exploitability:** not a stronger primitive than NTL. A separate userland `videocodecd` diff would be needed to test the PoC author's `session+0xb68` claim; no VM or physical validation has been performed.
