# IOSurface race V11 client-reclaim witness

Date: 2026-11-03 (America/Toronto)
Target: vPhone research VM, iOS 26.0 `23A341` (kernel UUID
`03A93373-6498-3F25-8975-04DED251AF1F`, IOSurface 393.2.9). Same boot as V10:
load `0xfffffe00392e8000`, slide `0x322e0000`, guest `192.168.64.168`.
Evidence archive: `~/Library/CyanideVPhoneLab/evidence/iosurface-race-v11-20261103/`

## Objective

After V10 showed the stale object is the client pointer at `node+0x58`,
determine what the freed `IOSurfaceRootUserClient` (`0x148`-byte typed
allocation) becomes by delivery time: still untouched, reclaimed within its
own class, or reclaimed by an attacker-controlled cross-type allocation.

## Method

Four verified hardware breakpoints (`scripts/lab/cnd_lldb_iosurface_reclaim.py`):

| Site | Offset | Instruction | Captures |
| --- | --- | --- | --- |
| insert-link | `+0x1ee4c` | `str x24, [x23, #0x8]` | node, owner, client, `node+0x58` |
| teardown-clear | `+0x23a54` | `str xzr, [x19, #0xd8]` | client, pre-clear isa `+0x0` and lock `+0xd8` |
| deliver-walk | `+0x1efa4` | `ldr x0, [x22, #0x58]` | node, owner, `node+0x58` |
| deliver-lockload | `+0x2828c` | `ldr x0, [x0, #0xd8]` | client, isa `+0x0` and lock `+0xd8` |

Race driver: `IOSurfaceNotifyRace.app`, close-first, 3000 iterations, run_id
`1793740000` (571 registrations completed after close). Concurrent sprayer:
`cnd_mach_spray` flooding mach messages with body fill `0x4141414141414141`
across body sizes 240..360 to cover the kalloc zones around 0x148. 300 s
capture, clean detach, read-only observer.

## Results

```text
insertLink=3278 teardownClear=3348 deliverWalk=22040 deliverLockload=21043 readErrors=0
probe: iterations=3000 success=2875 success_after_close=571 close_success=3000 (no panic)
```

1. **Stale-client delivery is repeated, not anecdotal: 22 deliver-lockloads
   occurred after the same client's teardown-clear** (vs. V7's single panic
   witness). The stale `node+0x58` deref at delivery is reliable.
2. **The client address is reclaimed within its own class.** For all 22
   stale deliveries, the isa at `client+0x0` at delivery time equals the isa
   recorded at teardown (same PAC-signed `IOSurfaceRootUserClient` class
   pointer), while `client+0xd8` changed from the cleared `0x0` to a fresh
   valid `IOLock *` (`0xfffffe2f...`). Signature: freed client address reused
   by a **new** `IOSurfaceRootUserClient` (the next iteration's connection) —
   same class, new lock.
3. **Cross-type spray does not land in the client zone: 0 lockloads with the
   `0x4141414141414141` magic** despite a continuous mach-message flood.
   The `kalloc_type` allocation for the client class is not shared with IPC
   message buffers at these sizes on this build.
4. **No NULL-lock delivery and no panic in this window** (0 lockloads with
   `+0xd8 == 0`), i.e. by delivery time the address had usually already been
   reused by a same-class client; the V7 panic corresponds to the narrower
   window where delivery wins the race against reuse.

## Conclusion

The exploit-relevant reclaim is **same-class**: the stale node points at an
address that becomes a fresh, attacker-opened `IOSurfaceRootUserClient`. The
delivery path then operates on that new client (lock, then
`lookup_client_subscription` reading `+0x108`/`+0x110`, then the use-count
walk frames). Controlled reclaim therefore means controlling the *state* of
the reclaiming client (its subscriptions, values) rather than its raw bytes —
cross-type heap spray is ruled out for this zone by result 3.

## Next step (V12)

Map exactly which fields of the reclaimed client the delivery path reads or
writes, and which of those the racing process controls on the reclaiming
connection (selector 9 `SetValue`, selector 17 request contents stored in the
node, use-count trigger). The goal is a delivery-path operation on a
client-state field that yields a controlled read/write; per the derivation
plan, `client+0xd8` controlled would give the `casa x8, x9, [lock+8]`
conditional atomic write. Static enumeration of the delivery frames
(`+0x1efb8`, `+0x0d394`, `+0x25e84`, caller `+0x28244`) against the reclaimed
client is the next concrete task.

## Evidence labels

- **VM**: all counts and correlations above, live on the named boot.
- **STATIC**: breakpoint sites from exact-build disassembly.
- Not proved: controlled content in the client zone, allocator
  release-before-delivery, any kernel read/write.
