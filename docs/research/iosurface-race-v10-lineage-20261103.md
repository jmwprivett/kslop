# IOSurface notification race V10 node-lineage witness

Date: 2026-11-03 (America/Toronto)
Target: vPhone research VM, iOS 26.0 `23A341` (kernel UUID
`03A93373-6498-3F25-8975-04DED251AF1F`, IOSurface 393.2.9 UUID
`8132EC95-DE46-3731-9931-024187C84DD2`)
Evidence archive: `~/Library/CyanideVPhoneLab/evidence/iosurface-race-v10-20261103/`

## Objective

Track one selector-17 notification node end-to-end — insertion, close-time
bulk removal, and delivery — to prove or refute node-level staleness without
depending on allocator timing (the gap left by V9).

## Method

Four hardware breakpoints, verified live against this boot's slide
(`0x322e0000`, load address `0xfffffe00392e8000`) before arming:

| Site | IOSurface offset | Instruction | Captures |
| --- | --- | --- | --- |
| insert-link | `+0x1ee4c` | `str x24, [x23, #0x8]` | node=x23, owner=x19, client=x21, `node+0x58`, `owner+0x198` |
| bulk-unlink | `+0x1f078` | `mov x0, x22` (pre-free) | node=x21, owner=x19, `node+0x58` |
| deliver-walk | `+0x1efa4` | `ldr x0, [x22, #0x58]` | node=x22, owner=x20, `node+0x58` |
| deliver-lockload | `+0x2828c` | `ldr x0, [x0, #0xd8]` | client=x0, `client+0xd8` |

Observer: `scripts/lab/cnd_lldb_iosurface_lineage.py` (read-only; registers and
bounded fields only). Race driver: the V9 probe binary run through the
`IOSurfaceNotifyRace.app` container (`com.research.iosurfacenotifyrace`),
close-first, 3000 iterations, run_id `1793739000`. A bare root CLI fails
`IOServiceOpen(IOSurfaceRoot)` on this build; the app's signed context opens
it (noted for future runs). 300 s capture window, clean detach after the probe
exited.

## Probe result

```text
done run_id=1793739000 mode=close-first iterations=3000 success=2638
success_after_close=770 not_open=220 other=142 close_success=3000
```

The vulnerable order (selector 17 completing after close) fired **770 of
3000** iterations (~26%), far higher than V9's 4 — the race is highly
reliable on this boot. No panic occurred during the run; the VM stayed alive.

## Observer counts

```text
insertLink=3084 bulkUnlink=2923 deliverWalk=21390 deliverLockload=20253 readErrors=0
```

(Distinct node addresses are fewer than events because the node zone recycles
addresses quickly: 247 distinct inserted addresses.)

## Findings

1. **The notification list itself stays consistent in this run.** 28
   deliver-walks initially looked like walks of unlinked nodes, but every one
   had the same node address re-inserted (a fresh node at a recycled address)
   between the unlink and the walk. After excluding address reuse: **0
   genuine stale-node walks**. The bulk-removal unlink is therefore not the
   stale object; the list linkage is repaired correctly for nodes present at
   removal time.
2. **The stale pointer is the client reference inside a live node**
   (`node+0x58`), consistent with V7: the same `IOSurfaceRootUserClient *`
   seen at teardown (`str xzr, [x19, #0xd8]`) reappears at delivery's
   `ldr x0, [x0, #0xd8]`, and the NULL lock panics in `IOLockLock`.
3. **No NULL-lock delivery occurred in this window** (0
   `deliver-lockload` events with `lockAtD8 == 0`), so this run did not
   reproduce the panic; it recorded race frequency and list behavior instead.
4. **Selector-17 insertions continued throughout the run** (insert stopIDs
   span 1690..64186, interleaved with unlink stopIDs 10812..64188), so
   late-insertion opportunities are abundant; the limiting factor is whether a
   use-count delivery walks the node after the client's teardown.

## Conclusion

V10 refines the root cause: the UAF is **not** a dangling notification node in
the owner's list (that would be node-level UAF); it is a **live node holding a
stale `IOSurfaceRootUserClient *`** (`node+0x58`) past the client's
termination. The exploit-relevant object to reclaim is therefore the
**client allocation** (`0x148`-byte typed object), not the node.

## Next step

V11: after close, spray the client's kalloc type from the racing process with a
recognizable fill, then trigger delivery and check whether
`deliver-lockload` sees a client whose `+0xd8` (and other fields) match the
spray. A match proves controlled reclaim of the stale client — the missing
prerequisite for turning this race into a controlled dereference (and, from
there, toward KRW per `iosurface-race-krw-derivation-plan-20261103.md`).

## Evidence labels

- **VM**: counts and event sequences above, captured live on the named boot.
- **STATIC**: instruction sites and offsets from the exact-build disassembly.
- Not proved: allocator-release-before-delivery, controlled reclaim, any
  kernel read/write.
