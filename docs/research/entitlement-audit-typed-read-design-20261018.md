# Entitlement audit: typed windowless read (design, 2026-10-18)

Replacement for the DFS graph walk in `Cyanide/probes/CNDPhysicalEntitlementAuditProbe.m`.
The walk is retired: both of its captured device panics are now symbolized from
the device's own kernelcache (`docs/research/entitlement-audit-panic-20261018-iphone17,2.md`)
as the walk's own reads — a zone-metadata VA seen by copyio's bounds validation,
and a >=32-byte in-kernel copy from an aperture VA. The aimed-socket
inbound-ICMPv6 dereference (`Cyanide/kexploit/kexploit_opa334.m:1660-1667`)
remains a code-level hazard, but it is **not** what either panic shows.
This read touches only typed pointers, adds no kernel primitive changes, and
still answers one question: does a candidate process carry
`com.apple.networking.ethernet.user-access`.

## Chain (all hops are 8-byte reads)

| # | hop | offset | access | citation |
|---|---|---|---|---|
| 1 | `proc` from `proc_find_by_name` | — | existing | `kutils.m:231` |
| 2 | `proc_ro` | `proc + off_proc_p_proc_ro` (`0x18`) | plain | `offsets.m` pin |
| 3 | `ucred` | `proc_ro + off_proc_ro_p_ucred` (`0x28`) | **SMR** (`kread_smrptr` shape) | `bsd/sys/proc_ro.h` (field is `SMR_POINTER`) |
| 4 | `label` | `ucred + 0x78` | **strip PAC** (`xpacd`/`xpaci`) | device AMFI `getOSEntitlements` = `ldr x16,[x0,#0x78]` then `autda x16,x17`, `x17=(ucred+0x78)\|0x8b90<<48`; also `bsd/sys/ucred.h` |
| 5 | AMFI slot value | `label + amfiSlotOffset` (`0x8`) | plain | `security/_label.h` (`l_perpolicy[MAC_MAX_SLOTS]` at `+8`); runtime slot index from `off_label_l_perpolicy_amfi` (device AMFI reads its index from a global, `0xfffffff007eb6460`, zero at rest) |
| 6 | RO object | `amfiSlotValue + 0x10` | plain | device AMFI `getReadOnlyData` = `ldr x17,[x0,#0x10]` and `initReadOnlyData` = `ldr/str [x19,#0x10]` |
| 7 | DER range | `ro + 0x38` (begin), `ro + 0x40` (end) | plain | AMFI `0xfffffff00977e43c` writes the decoded-item struct at `ctx+0x8` (= `ro+0x10`) and its `+0x28`/`+0x30` are that struct's begin/end -> `ro+0x38`/`ro+0x40`. Same pair `createXMLBlob` reads: `*(ro+0x50)` -> `+0x8` -> `+0x28`/`+0x30` |
| 8 | DER bytes | `[derStart, derEnd)` | 8-byte reads | this design |

`amfiSlotValue` **is** the `OSEntitlements` object; there is no persistent
entitlement dictionary to walk (`copyDictionary` builds it on demand from the
DER). `ucred.cr_label` is PAC-signed and `p_ucred` is an SMR pointer — both must
be decoded, not read raw.

## Admission rules (per hop, before the next hop is dereferenced)

1. Every *object* hop address must pass the object-window check already in the
   probe (`CNDPhysicalEntitlementAuditKernelObject`, `:175-180`) — band + 8-byte
   alignment. This is a *range* test; it is necessary, not sufficient.
   The DER pair is the one exception: it is a byte range, not an object, so it
   gets the band test only (`CNDPhysicalEntitlementAuditObjectBand`) and never
   the alignment test (see the `+0x38`/`+0x40` derivation below).
2. Additional structural gates, in order, aborting the candidate on any failure
   (`aborted` + reason, never `found=false`):
   - hop 5: slot value not in `{0, UINT64_MAX}` (the NULL encodings);
   - hop 6: `*(ro + 0x0) == amfiSlotValue` (owner back-pointer) and
     `*(ro + 0x50) == ro + 0x8` (CE query-context self-pointer);
   - hop 7: `ro + 0x38`/`ro + 0x40` readable, `derStart < derEnd`,
     `derEnd - derStart <= cap`, **both ends in band** — no alignment.
3. DER content tag (`0x30` SEQUENCE / `0x70` context-specific) is **recorded,
   not gated**: the exact leading tag is version-dependent
   (`unverified` from the 12377.1.9 tree), and gating on it would turn a
   version drift into a false "aborted".

## Read shape and the aimed-socket hazard

- **8-byte reads only.** A 32-byte transfer can cross a zone element boundary
  and trip `zone_element_bounds_check` — the captured `MAC Labels` panic is
  exactly that shape. The DER blob is read as `len/8` qwords.
- Reads are ordered: one retarget, one `getsockopt`, then park — the existing
  shape in `early_kread_checked` (`kexploit_opa334.m:1726-1735`). The probe does
  **not** modify the primitive (out of scope: no `kexploit` changes).
- Total read count collapses from 200 000 wild qwords to ~20 validated hops plus
  `len/8` contiguous DER qwords (a few hundred). The aimed window (retarget →
  park) is unchanged in duration but now points only at validated objects.
- Residual risk is not zero: a mismatched offset on the device branch
  (`12377.2.8` vs the `12377.1.9` tree) could still aim at a non-object. That is
  what the self-checks and the trail below are for.

## Persist-before-read (the trail)

The current report is persisted once at start (`:484`) and then only at the end,
which is why the faulting runs left nothing usable. v2 persists:

- the hop **plan** and each hop's raw value as it is read;
- `nextReadAddress` — the address about to be read — before each read batch;
- a rolling `derBytesRead` counter every 512 bytes (and on each 8-byte read in
  the first 64 bytes).

A panic then leaves the exact address that killed it, in the same file.

## Report (schema v2)

Keep `schema`; bump `schemaVersion` to `2`. Per candidate:
`chainOk`, `chainChecksFailed` (`[]`), `procRO`, `ucred`, `ucredRaw`,
`labelRaw`, `label` (stripped), `amfiSlotIndex`, `amfiSlotValue`, `roObject`,
`roSelfChecks` (`{owner, context}`), `derStart`, `derEnd`, `derLength`,
`derFirstByte`, `derKeyOffset` (`-1` when absent), `entitlementValueHex`,
`entitlementFound`, `entitlementStemFound`, `sampleStrings`, `reads`,
`abortReason`. Run-level: `state` (`complete` / `aborted`), `nextReadAddress`,
`readsTotal`, plus the existing hygiene flags (`kernelWriteUsed: false`,
`kernelCallUsed: false`, `providerUsed: false`, `labelBorrowed: false`).

## Test plan (`scripts/tests/test_physical_entitlement_audit_probe.py`)

- remove DFS/window assertions; add: no `0x400`/`0x80` window constants, no
  `Walk`/`ScanGraph` symbols, no `visited` array;
- typed chain present in order, with the PAC strip on `cr_label` and an SMR/`xpacd`
  decode path for `p_ucred`;
- every read is 8 bytes (no 32-byte transfer);
- self-checks abort rather than report a negative;
- persist-before-read: `nextReadAddress` written before reads;
- schema v2 field set; hygiene tests (no writes / no kcall / no provider) stay;
- read cap enforced (hops + DER + budget).

## As built (2026-10-18, `Cyanide/probes/CNDPhysicalEntitlementAuditProbe.m`)

Two things the design above got *better* once the app's own code was read, and one
that got stricter:

1. **The four chain offsets are not constants here.** `kutils.m:453-466` already
   walks `proc + off_proc_p_proc_ro` → `proc_ro + off_proc_ro_p_ucred` →
   `ucred + off_ucred_cr_label` → `label + off_label_l_perpolicy_amfi`, and
   `offsets.m` pins those per OS version (`0x18 / 0x28 / 0x78 / 0x8` on the
   `26.0`-era branch, `offsets.m:875-924`). The probe resolves the same four
   globals with `dlsym`, so its hops cannot drift from the app's own — and the
   report records the values it used. The only constants that stay local are the
   two AMFI read-only-data hops (`+0x10`, `+0x38/+0x40`, `+0x00`, `+0x50`).
2. **Hop 3 is an anchor, not just a hop.** `proc_get_cred_label()` is the
   device-proven path (it produced valid labels on every earlier run). The probe
   derives the label through its own reads and **aborts unless the derived value
   equals that one**. So the chain is validated against a known-good in-process
   answer before the AMFI object is used at all.
3. **The PUCL question is settled at runtime, not guessed.** `p_ucred` is read
   plain (what `kutils.m` does, device-proven) *and* through `kread_smrptr`
   (which applies `smr_base`); whichever lands in the object window is used, and
   `ucredDecode` / `ucredSmr` are reported either way.
4. **The label anchor accepts the decode `kutils` actually uses.** `kread_ptr`
   is `xpaci(kread64(va))` (`krw.m:145`), so `proc_get_cred_label()` returns the
   *instruction* strip. The hop therefore accepts `raw`, `xpaci` or `xpacd`,
   preferring whichever **equals** the device-proven value, and records all three
   plus which one matched (`labelDecode`). Preferring `xpacd` blindly would have
   aborted every chain on a pointer that `kutils` itself resolves fine - a
   self-check that fails for the wrong reason is worse than no self-check.
5. **The read path is already VA-range-gated.** `kread64`/`kreadbuf` funnel into
   `early_kread64_checked`, which rejects addresses outside
   `[VM_MIN_KERNEL_ADDRESS, VM_MAX_KERNEL_ADDRESS]` via `is_kaddr_valid`
   (`kexploit_opa334.m:1713`, `:1928`) before any transfer. That is the floor,
   not the safety argument: the two captured faults were **in-range but
   unmapped**, so the structural checks above remain the actual protection.
6. **"No verdict" is a distinct outcome.** If every candidate aborts, the report
   ends `physical-krw-entitlement-audit-aborted` with `verdictCount 0` and
   `donorAuditVerdictReached NO` - otherwise `donorHasEntitlement: false` would
   read as an answer to the donor question when the chain merely failed to
   verify.
7. **Two of the chain's offsets are now proven from the device's own AMFI image,
   not inferred.** The in-repo kernelcache has the matching UUID and an
   address-to-name map, so the AMFI kext
   (`build/rea-secure-execution-23A341-iphone17,2/kernel-filesets-stock/com.apple.driver.AppleMobileFileIntegrity`)
   disassembles directly:
   - `OSEntitlements::getReadOnlyData` (`0xfffffff00976dfac`) is
     `ldr x17, [x0, #0x10]` and `OSEntitlements::initReadOnlyData`
     (`0xfffffff00976e0d4`) is `ldr x8, [x19, #0x10]` / `str x0, [x19, #0x10]` -
     so the read-only-data hop is **+0x10**, derived, not guessed.
   - `getOSEntitlements(ucred)` (`0xfffffff009763c74`) is `ldr x16, [x0, #0x78]`
     on the ucred - so `cr_label` is **ucred+0x78**, likewise derived.
   Both agree with `offsets.m`, which is now corroboration rather than the only
   source. The read-only object's own fields were derived from the same image in
   the 2026-10-18 offline round, so no chain offset is left as an unbacked
   guess:
   - **`+0x00` owner.** `initReadOnlyData` (`0xfffffff00976e0d4`) writes it with
     `zalloc_ro_mut(zone, ro, 0x0, &this, 8)` (`0xfffffff00976e138`), and
     `getReadOnlyData` (`0xfffffff00976dfac`) re-checks it before handing the
     object out: `ldr x9, [x16]; cmp x9, x19` (`x19` = `this`), `b.ne` into a
     panic (`0xfffffff00976e048`). That is exactly the probe's `roOwnerCheck`.
   - **`+0x08` CoreEntitlements context.** `initEntitlements`
     (`0xfffffff00976e16c`) writes `ro+0x08 .. ro+0x50` in one 0x48-byte
     `zalloc_ro_mut` (`0xfffffff00976e1cc`); `adjustWithoutMonitor` /
     `adjustWithMonitor` write the same span from the decoded query context.
   - **`+0x10` decoded DER item, 0x38 bytes.** `0xfffffff00977674c` is just
     `*out = ctx + 0x8`; `createXMLBlob`'s block (`0xfffffff0097700e0`) calls it
     on `*(ro+0x50)` and then copies (`0xfffffff0097811e8`) 0x38 bytes out of
     it. Its `+0x00` is the `CEContext`, `+0x18` a 16-byte constant, `+0x20` a
     `0x100`/`0x101` type/flag word, `+0x28`/`+0x30` the DER begin/end.
   - **`+0x38` begin / `+0x40` end.** `0xfffffff00977e43c` — called by
     `0xfffffff009776630` as `(ctx, item, dest + 0x8)` — loads the ends with
     `ldp x9, x8, [x1, #0x8]` and stores them as
     `stp x10, x9, [x19, #0x20]` (-> `dest+0x28`) and `str x8, [x19, #0x30]`
     (-> `dest+0x30`). With `dest = ro+0x08` those are `ro+0x38`/`ro+0x40`.
   - **`+0x50` context self-pointer.** `initEntitlements` computes
     `x8 = ro + 0x08`, parks it in a local, and writes the local at `+0x50`
     (`zalloc_ro_mut(..., 0x50, &local, 8)`, `0xfffffff00976e1e4`) — so
     `*(ro+0x50) == ro+0x8` is structural, not coincidental. `createXMLBlob`'s
     block reads it first (`ldr x0, [x1, #0x50]`, `0xfffffff009770100`): the same
     hop this probe takes.
8. **The label field is a PAC-signed pointer, and the kernel authenticates it.**
   The same `getOSEntitlements` body is `autda x16, x17` with
   `x17 = (ucred + 0x78) | 0x8b90 << 48`, then the standard verify idiom
   (`xpacd`, `cmp`, `brk #0xc472` on mismatch); the AMFI *slot index* it passes
   on is read from a runtime global (`0xfffffff007eb6460`, zero at rest in the
   image), so it is not statically derivable. This is why the probe's label hop
   accepts the raw value and both strips and anchors on equality with
   `proc_get_cred_label()` rather than trusting a single decode: the strip
   instructions do not authenticate, so a wrong decode is caught by the anchor
   instead of silently used. A future strengthening could authenticate with the
   computed modifier as an extra evidence field; it is not required, because a
   wrong value already fails the anchor.

Strictness added: the two self-referential AMFI read-only checks gate the DER
read, so **no DER byte is aimed at** unless `*(RO) == OSEntitlements` and
`*(RO+0x50) == RO+0x8` both hold. Every failure is an `aborted` chain with a
reason (`proc-ro-not-object`, `ucred-not-object`, `label-chain-mismatch`,
`amfi-slot-not-object`, `ro-owner-mismatch`, `ro-context-mismatch`,
`der-range-invalid`, `der-read`, `der-buffer-alloc`, `label-window-read`), never
`found = false`. `derKeyOffset` is `-1` when absent; `derFirstByte`,
`derBytesRead`, `derLength` and `entitlementValueHex` (the bytes after the key,
DER `01 01 ff` = TRUE) carry the verdict's evidence.

The one window read left is the 32-byte label read: a MAC label holds
`l_perpolicy[MAC_MAX_SLOTS]`, so 32 bytes cannot cross its element boundary, and
the same read has succeeded on-device every time it has been tried. Everything
else is 8 bytes per read.

Schema is now `schemaVersion 2`; `scripts/tests/test_physical_entitlement_audit_probe.py`
(21 tests) pins the absence of the walk, the hop order, the abort list, the
persist-before-read trail and the DER-only-8-byte rule.

## Further self-checks the offline round proposed (not yet implemented)

These are cheap and independent; none of them is needed for the chain to be
safe (the hops already validate), so they are recorded rather than added:

- **`proc_ro` back-pointers.** `*(proc_ro + 0x0) == proc` and
  `*(proc_ro + 0x8) == task` (`bsd/sys/proc_ro.h:75-76`) would catch a wrong
  `off_proc_p_proc_ro` on the first hop. Downstream hops already catch it (a bad
  `proc_ro` yields a non-object at `+0x28`), so this is diagnostic value.
- **`ucred` sanity.** `cr_ref` at `+0x10` small and non-zero, `cr_ngroups` at
  `+0x24` `<= 16`, `cr_uid` plausible for the donor.
- **`label + 0x0`.** On RELEASE builds `l_owner` is NULL for cred labels
  (`osfmk/kern/mac_process.c:94-110`); it is `-1` only on DEVELOPMENT builds.
  Weak but free.
- **AMFI object identity.** The stripped vtable pointer of the slot object
  should equal the in-repo map's `vtable for OSEntitlements` plus the boot
  slide, adjusted for the C++ vtable-pointer convention. This is the strongest
  available check on the AMFI hops, and it is exactly the kind of check the
  three underived read-only fields need.
- **DER self-length.** The length encoded in the first DER bytes should equal
  `derEnd - derStart`; format-defined, so version-insensitive.


Implement and run the host suite. The device run is a separate, owner-visible step
and should follow the symbolization round
(`cyanide-panic-symbolize-20261018`), which names what the two previous fault PCs
were — so a repeat fault is attributable on sight.

## First physical run of this shape (2026-10-18, installed + launched headless)

Installed `build/DirectDeviceUpdate-20261018-150148/Cyanide.app` and launched

```
xcrun devicectl device process launch --device 828515D1-88C1-5CEB-A16F-5AD0AE3E3641 \
  --terminate-existing com.zeroxjf.ios-cyanide1 -- --entitlement-audit-probe
```

The device stayed up (no panic), and the report was written within ~20 s:

| field | value |
|---|---|
| `result` | `refused-label-slot-mismatch` |
| `schemaVersion` | `2` (so the rewritten probe, not the retired walk) |
| `amfiSlotOffset` / `sandboxSlotOffset` | `0` / `0` |
| `targets`, `auditedProcesses` | empty (refused at the preflight) |

**Cause, and it was a real defect in this probe.** `offsets_init()` is called
from inside the exploit (`kexploit_opa334.m:3121`) and from the persistence path
(`persistence.m:640`) — not at process start. The preflight read the slot
offsets before either had run, so it saw zeroes and refused. Worse, the same
zeroes were the source of `off_proc_p_proc_ro`, `off_proc_ro_p_ucred` and
`off_ucred_cr_label`, i.e. the chain's own hop offsets: the slot check was
accidentally the only thing standing between a fresh process and a chain built
on zeros. Two independent failures were being hidden by one guard.

**Fix.** Both probes now resolve `offsets_init` through their own `dlsym` table
and call it when the offsets are still zero, then persist what they resolved
(`offsetsInitCalled`, and for the audit probe all five offsets). The call stays
before the exploit is asked for anything, which is what the preflight is for —
`offsets_init()` touches no kernel state (it switches on the userland OS version
and `hw.cpufamily`) and is idempotent with the exploit's own call. Pinned by
`test_probe_initializes_offsets_before_the_slot_preflight` in both probe suites.

**What this run does and does not show.** It is physical evidence that the
rewritten probe runs on the device without panicking, and that its preflight
refuses rather than proceeding on unknown offsets. It is **not** a verdict on
the donor gate: no candidate was followed, so `donorHasEntitlement` remains
unanswered and the run is not a substitute for one that gets past the
preflight. Note also that the *previous* device report
(schema 1, `2026-10-17 19:51:26`) came from the retired walk and predates both
panics, so it neither corroborates nor contradicts the panic analysis in
`entitlement-audit-panic-20261018-iphone17,2.md`.

## Second run (fixed build): the donor verdict, 2026-10-18 19:43:38 → 19:56:11

Launched the same way on the same device. The phone stayed up; no panic; the
report is `physical-krw-entitlement-audit-complete`, `schemaVersion 2`,
`chainType typed-windowless-read`, `windowWalkUsed NO` (so the retired walk is
provably not what ran).

| field | value |
|---|---|
| `donorProcess` | `bluetoothd` |
| `donorHasEntitlement` / `donorAuditVerdictReached` | `YES` / `1` |
| `processesWithEntitlement` | `["bluetoothd"]` |
| `verdictCount` / `chainsAborted` | `1` / `4` |
| `requiredEntitlement` | `com.apple.networking.ethernet.user-access` |
| `kernelReadUsed` / `kernelWriteUsed` / `kernelCallUsed` | `YES` / `NO` / `NO` |
| `providerUsed` / `labelBorrowed` | `NO` / `NO` |
| `readGranularityBytes` | `8` |

**The bluetoothd entry, hop by hop:** `proc 0xffffffde1c824880` →
`procRO 0xffffffdd35fd0d88` → `ucred 0xffffffdce800d150` (`ucredDecode: plain`)
→ `label 0xffffffdd35fecbe0` with `labelMatchesKutils YES` → AMFI slot
`0xffffffde1b21d828` → RO object `0xffffffdce80f7ac0` with `roOwnerCheck YES`
(owner == that OSEntitlements) and `roContextCheck YES` → DER range
`0xffffffe8f3fcf168`–`0xffffffe8f3fd19c7`, `derLength 10335` →
the needle found at `derKeyOffset 3040`, `derBytesRead 3200`,
`entitlementMatched "com.apple.networking.ethernet.user-access"`.

Why this is treated as a real match and not a lucky read: the search runs only
over `[derStart, derStart + derLength)` (right-sized `calloc`, 8-byte reads,
budget-capped), and the only bytes searched are the ones the validated RO object
points at. That buffer's own samples are bluetoothd's
(`com.apple.bluetoothd`, `com.apple.BTServer.avrcp`, `com.apple.BTServer.le`,
`com.apple.BTServer.map`, …) — the same set the **retired walk found on
2026-10-17 by an entirely different method**, so two independent reads agree on
what bluetoothd carries.

**What the run also settles:**

- The label anchor is sound on-device: `labelMatchesKutils YES` for all five
  candidates (not just the winner), i.e. the typed hop reproduced
  `proc_get_cred_label()`'s value every time.
- The raw label really is PAC-signed — `labelRaw 0x82cfa9dd35fecbe0` for
  bluetoothd — and `xpaci` strips it to exactly the value the anchor produced.
  That confirms on hardware the reasoning that strip instructions do not
  authenticate (so a wrong decode is caught by the anchor, not silently used).
- `offsets.m` resolved to the pinned contract: `amfi 8`, `sandbox 16`,
  `proc_p_proc_ro 24`, `proc_ro_p_ucred 40`, `ucred_cr_label 120`.
- The `offsets_init` fix was not needed *this* time (`offsetsInitCalled NO`,
  `krwInitiallyReady YES`): the app's own exploit had already run in that process.
  The 19:34 refusal was this same code losing that race. The fix replaces the
  race with a deterministic precondition.

**The four aborts: explained — an invalid criterion, not a finding.** `configd`,
`nehelper`, `symptomsd` and `wifid` all stopped at `der-range-invalid`, the gate
at `CNDPhysicalEntitlementAuditProbe.m:728-730`. It required `derEnd > derStart`,
`derEnd - derStart <= 16384`, and `derStart` "a kernel object" — where that meant
`CNDPhysicalEntitlementAuditKernelObject`, i.e. band **and 8-byte alignment**
(`:234-239`). Their `roOwnerCheck`/`roContextCheck` were **YES** too, so the RO
objects looked like genuine read-only data. Every one of the four pairs was in
band, in order, and a plausible range length (1922..7920 bytes):

| process | `derStart` | `derEnd` | length | `derStart & 7` | why the gate stopped it |
|---|---|---|---|---|---|
| `nehelper` | `0xfffffff11746eb86` | `0xfffffff11746f308` | 1922 | 6 | in band, not 8-aligned |
| `configd` | `0xffffffe8f3df1405` | `0xffffffe8f3df1c15` | 2064 | 5 | in band, not 8-aligned |
| `symptomsd` | `0xffffffe8f412c2a7` | `0xffffffe8f412d05e` | 3511 | 7 | in band, not 8-aligned |
| `wifid` | `0xffffffe8f3f318ca` | `0xffffffe8f3f337ba` | 7920 | 2 | in band, not 8-aligned |

The earlier note that `nehelper` was "out of band / aperture-class, correctly
rejected" was **wrong**: `0xfffffff11746eb86` is below `OBJECT_MAX`
(`0xfffffffbffffffff`), so it too was stopped by nothing but the alignment
clause.

The offline round settles it. `0xfffffff00977e43c` takes both ends straight from
the DER decoder's byte pointers and enforces **only** their order — `cmp x9, x8;
b.hi` into `brk` (`0xfffffff00977e48c`; the mirror branch is at `:510`) — so a
DER range is byte-granular by construction. 8-alignment was never a property of
it: the alignment demand is right for a real kernel object and wrong for a byte
range. All four aborts were the same false negative. They are still *only* a
statement about the gate, not about the ranges: whether each range is actually
readable is what the re-run tests, and `entitlementFound` stays `false` /
`derBytesRead` stays `0` for them until it does.

**Fix applied** (`Cyanide/probes/CNDPhysicalEntitlementAuditProbe.m`): the object-window
test is split into `CNDPhysicalEntitlementAuditObjectBand` (band only) and
`CNDPhysicalEntitlementAuditKernelObject` (band + alignment, still used for the
object hops). Hop 6's gate now band-tests **both** ends, requires
`derStart < derEnd` and length `<= cap`, and drops the alignment demand — the
streamed read that follows, not an alignment test, is what proves the range
readable, so "in band and mapped" reduces offline to "in band, ordered,
bounded". Hop 6 also gained one derivation-backed corroboration, reported and
not gated: `derItemTypeWord` (+ `derItemTypeWordExpected`), the decoded item's
`0x100`/`0x101` type/flag word at `ro+0x30`. It is read *before* the range gate,
so an aborted candidate still carries structural evidence. It stays ungated
because an object whose entitlements came from the non-DER path may not share
that layout.

Expected on the re-run: all four candidates reach the DER stream. If the donor
gate is the question, that is now a wider answer — each candidate either yields a
verdict or fails at a later hop that names why.

## Open items

- All offsets still come from the `12377.1.9` tree; the device runs `12377.2.8`
  (self-checks plus a VM confirmation are the mitigation).
- Whether the sandbox profile's mention of `IOUserEthernetResourceUserClient`
  for `/usr/sbin/bluetoothd` has any bearing on the AMFI gate: it does not
  (independent gates) — recorded here so it is not re-litigated.
