# Entitlement-audit device panics, iPhone17,2 / 23A341 (2026-10-18)

Read-only record of two kernel panics pulled from the device after the
2026-10-18 launches. Nothing here is implemented-level; these are
**physical-observed** artifacts. Both panics are in task `Cyanide` and both
fault classes match the audit walk's two hazard paths, but see
"Attribution is not closed" below before treating them as proof that the
audit walk itself was running.

## Pull

```sh
DID=828515D1-88C1-5CEB-A16F-5AD0AE3E3641
xcrun devicectl device info files --device "$DID" --domain-type systemCrashLogs
xcrun devicectl device copy from --device "$DID" --domain-type systemCrashLogs \
  --source panic-full-2026-10-18-033842.0002.ips --destination build/entitlement-audit-20261017/crashlogs/
xcrun devicectl device copy from --device "$DID" --domain-type systemCrashLogs \
  --source panic-full-2026-10-18-033954.0002.ips --destination build/entitlement-audit-20261017/crashlogs/
xcrun devicectl device copy from --device "$DID" --domain-type appDataContainer \
  --domain-identifier com.zeroxjf.ios-cyanide1 \
  --source Documents/CNDPhysicalEntitlementAuditProbe.json \
  --destination build/entitlement-audit-20261017/live2.json
```

Files: `build/entitlement-audit-20261017/crashlogs/panic-full-2026-10-18-0338{42,54}.0002.ips`.

## The two panics are different classes (both now symbolized)

| | 03:38:42 | 03:39:54 |
|---|---|---|
| panic string | `Kernel data abort` | `Unexpected fault in kernel physical aperture` |
| `pc` offset in kernel text exec | `0xec6b8` | `0x87fa7c` |
| symbolized site (static) | `_zone_element_bounds_check` **+52** (`ldrh`, in-repo map) | map-absent in-kernel `memcpy`/`memmove` **+44** (`ldp x12,x13,[x1]`) |
| reachable from | exactly one tail `B`, inside `_copy_validate_kernel_addr` (copyio validation) | 1754 callers; caller unresolved |
| `far` | `0xffffffdc037034b0` | `0xfffffff1ed88c000` |
| `far` region (that boot) | zone **Metadata** `0xffffffdc026f4000–0xffffffdc03ef4000` | physical aperture |
| `esr` | `0x96000007` (EL1 data abort, read, translation fault) | `0x96000007` |
| panicking task | **Cyanide** (pid 1875, sole `TH_RUN` thread 966083) | **Cyanide** (pid 329, sole `TH_RUN` thread 5135) |
| kernel | `xnu-12377.2.8~1`, T8140, `23A341`, kernelcache UUID `76BB58BF-911D-07E4-D681-DCE7F2DDA3CE` | same kernelcache UUID |

Both boots have the same kernelcache UUID but different slides (text exec base
`0xfffffff038684000` vs `0xfffffff03ec7c000`), i.e. two boots of the same build.

### 03:39:54 — `0x87fa7c`: a large in-kernel copy from an aperture VA

`pc` offset `0x87fa7c` = `0xfffffff008a5fa7c` unslid, and the device's own
kernelcache is in-repo (`build/HailMaryKernel23A341/23A341__iPhone17,2/kernelcache.release.iPhone17,2`,
`LC_UUID 76BB58BF-911D-07E4-D681-DCE7F2DDA3CE` — the UUID both panics carry;
`__TEXT_EXEC` loads at `0xfffffff0081e0000`, which is what `debug.c` prints as
"Kernel text exec base"). That offset is inside a function the in-repo map
(`build/lab-cs-allow-invalid/kernel-23A341/symbols/kernelcache.release.iphone17.decompressed.symbols.json`)
does **not** name; disassembly shows an exact 4-instruction argument-swap thunk
at `0xfffffff008a5fa40` (`bti c; mov x3,x0; mov x0,x1; mov x1,x3` — `_bcopy`)
immediately followed by the function at `0xfffffff008a5fa50` (`bti c`, frame,
`sub x3,x0,x1`), whose faulting instruction is `ldp x12,x13,[x1]` followed by
`ldp x14,x15,[x1,#16]`, `sub x5,x3,x0`, `add x1,x1,x5` — the forward large-copy
path of `bcopy.s`, 32 bytes per iteration, source in `x1`. The function has 1754
direct callers in `__TEXT_EXEC`, i.e. it is the generic in-kernel memcpy/memmove.

**It is not the probe's socket read.** `_bcopyout` (`0xfffffff0081e5468`, in the
unnamed `machine_routines_asm.s` region) is an inline unrolled `0x100`-byte
`ldp`/`stp` loop and has **no** branch to the memcpy function at all, and the
ICMP6 read is capped at 32 bytes (`Cyanide/kexploit/kexploit_opa334.m:84`), while
the faulting instruction implies a length ≥ 32 and a ≥32-byte source. The best
current candidate is the exploit bootstrap's physical out-of-bounds read
(`OOB_SIZE 0xf00`, `kexploit_opa334.m:34,1391-1460`), because the earlier curated
run of 56 aperture panics carries `x2 = 0xf00` in 37 of them
(`build/physical-panic-signature-20261015-223315/panic-signature-report.json`).
**The calling frame is unresolved**; establishing it needs the backtrace frames
from the raw log, symbolized by the same base + offset method.

### 03:38:42 — `0xec6b8`: copyio's zone-bounds check, not the inbound path

`pc` offset `0xec6b8` = `0xfffffff0082cc6b8`, and the in-repo map names
`_zone_element_bounds_check` at `0xfffffff0082cc684` — exactly this offset minus
**52**. The function starts with `bti c` and the faulting instruction is an
`ldrh` (bytes `2a014079`), i.e. the load of a 16-bit zone-metadata index, and the
`far` is indeed inside that boot's zone **Metadata** region. Scanning all of
`__TEXT_EXEC` for branches to that function finds **exactly one**, a tail `B` at
`0xfffffff0083a6240` inside `_copy_validate_kernel_addr` (map address
`0xfffffff0083a61b4`), which itself has exactly five `BL` callers — the copyio
entry points. So this fault is **copyio validating a kernel VA before copying
it**, whose zone-metadata page was unmapped.

That is the probe's own read, not a packet. The earlier attribution to an
inbound ICMPv6 dereference of a left-aimed `rwSocket` filter is **withdrawn**:
`icmp6_input` (`0xfffffff00865af74`) is a different function and nothing in it
branches to the bounds check. Which direction the copy was (`copyin` of the
`setsockopt` buffer, or `copyout` of the `getsockopt` buffer via
`sooptcopyout`) is **unresolved** without the backtrace; the bounded ICMP6 get
path itself is `/dev`-proven on 23A341 by the earlier non-panicking runs.

Consequence: with both PCs symbolized, neither captured panic is evidence for the
aimed-socket inbound-dereference mechanism. That hazard remains a *code-level*
hazard (the comment at `kexploit_opa334.m:1660-1667` stands), but it is not what
these two panics show. What they show is that the retired walk's window reads
faulted in two ways: a zone-metadata VA (via copyio validation) and a ≥32-byte
kernel copy from an aperture VA.

Status: physical-observed panics with **static** symbolization from the device's
own kernelcache and the in-repo map; site B's caller and site A's copy direction
stay unresolved and are labelled as such.


## What the panic run persisted: nothing

`build/entitlement-audit-20261017/live2.json` (pulled as `Documents/CNDPhysicalEntitlementAuditProbe.json`)
is a leftover from an earlier, non-panicking run:

- `state: starting`, `result: physical-krw-entitlement-audit-complete`,
  `kernelBase 0xfffffff03d1f8000`, `kernelSlide 0x361f4000`;
- all five candidates `scanNodes 234`, `scanReads 29952`, `scanTruncated true`,
  `entitlementFound false` — i.e. even the surviving run truncated before
  finding `com.apple.networking.ethernet.user-access`;
- the file mtime predates both panics, so the faulting runs persisted **no**
  replay trail. The "no report retrievable" observation from the crash window
  therefore says nothing about how far the walk got.

## Attribution is not closed

What is proven: both panics are in task `Cyanide` (single `TH_RUN` thread), and
the two fault classes are exactly the ones the walk can produce.

What is not: that the *audit* was the running probe. `CNDPhysicalEntitlementAuditRunOnce`
persists `CNDPhysicalEntitlementAuditProbe.json` as its **first** action
(`Cyanide/CNDPhysicalEntitlementAuditProbe.m:484`), so a faulting audit run
should have re-stamped that file at its own start time. The pulled file is an
earlier run (`state: starting`, candidates at `nodes 234 / reads 29952`), and its
mtime predates both panics. Either the faulting runs were a different Cyanide
probe (e.g. the KCall1 or signer row), or the audit's first persist did not land
before the fault.

Resolution: list the app container (`xcrun devicectl device info files --device
<id> --domain-type appDataContainer --domain-identifier com.zeroxjf.ios-cyanide1`)
and compare each probe report's mtime against `03:38:42` / `03:39:54`. This was
attempted on 2026-10-18 and the device had already left the bus again
(`CoreDeviceError 1011`), so it is still open. Until it is closed, the safe
reading is: the *walk design* has two demonstrated panic paths, and the two
panics are consistent with it.

## Consequences

1. The window walk is retired. Both captured faults are now explained by its own
   reads: a zone-metadata VA validated by copyio, and a ≥32-byte kernel copy from
   an aperture VA. The aimed-socket inbound dereference remains a code-level
   hazard, but these two panics do not evidence it.
2. Any replacement read must be typed and windowless, and must persist
   step/address state **before** each read, or a panic leaves nothing to replay.
3. The donor question was answered at runtime on 2026-10-18 by the replacement
   read (typed, windowless): **bluetoothd carries
   `com.apple.networking.ethernet.user-access`**. See the design doc's
   "Second run" section for the report fields; the run panicked nothing and made
   no kernel writes.

## Open items

- ~~Symbolize `0xec6b8` / `0x87fa7c`~~ — **done** (above), statically, from the
  in-repo UUID-matched kernelcache and symbol map. Remaining: the backtrace
  frames for site B's caller, and site A's copy direction.
- Re-check every offset derived from the in-repo `xnu-12377.1.9` tree against
  the device's `12377.2.8~1`. Partly discharged: `ucred+0x78` (`cr_label`) and
  `OSEntitlements+0x10` (read-only data) are now read straight out of the
  device's own AMFI image (see the design doc), not from the 1.9 source.

## Status update (2026-10-18, later the same day)

- **The walk is gone in code.** `Cyanide/CNDPhysicalEntitlementAuditProbe.m` now
  does the typed, windowless read described in
  `docs/research/entitlement-audit-typed-read-design-20261018.md`; the 0x400/0x80
  window reads, the depth cap, the visited set and the recursion no longer exist
  (the probe suite asserts their absence). This is **implemented**, not
  physical-proved: nothing here has run on the phone again yet.
- **The read path was already VA-range-gated, and that is not enough.** Every
  read funnels into `early_kread64_checked`, which rejects addresses outside
  `[VM_MIN_KERNEL_ADDRESS, VM_MAX_KERNEL_ADDRESS]` via `is_kaddr_valid`
  (`kexploit_opa334.m:1713`, `:1928`). Both captured faults were **in-range but
  unmapped**, so the range gate would not have prevented either one; the chain's
  structural self-checks (and abort-on-failure) are the actual mitigation.
- **Attribution is still open** and unchanged by the rewrite: the faulting runs
  persisted no report, so which code path owned each fault has not been proven
  from the container listing. That listing needs the phone back on the bus.
- **Open item 2 is handled by construction, not by offline verification.** The
  in-repo tree is 12377.1.9 while the device runs 12377.2.8~1; the AMFI read-only
  hops are gated by two self-referential checks
  (`*(RO) == OSEntitlements`, `*(RO+0x50) == RO+0x8`) *before* the DER range is
  read, so a layout drift on 12377.2.8 aborts the chain instead of aiming at a
  wrong address. Open item 1 (symbolization) is with the offline route.
