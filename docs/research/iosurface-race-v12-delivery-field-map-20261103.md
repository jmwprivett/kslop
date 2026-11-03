# IOSurface race V12: delivery-path field map on the reclaimed client

Date: 2026-11-03 (America/Toronto)
Target: iOS 26.0 `23A341`, IOSurface 393.2.9 (UUID
`8132EC95-DE46-3731-9931-024187C84DD2`), kernel UUID
`03A93373-6498-3F25-8975-04DED251AF1F`. Static analysis of the exact-build
kext text (dumped live from the VM over KDP; instruction sites verified live
on two boots) plus the V10/V11 VM evidence.

## Call chain reconstructed (STATIC)

```text
IOSurface use-count transition            FRAME fn, kext +0x327c
  └─ cas refcount at surface+0x178 (PAC ptr, key 0xa39b)
  └─ on transition: lock surface+0x50, then
     └─ WALKER(owner=[global+0xc88], 0, surface)   kext +0x14f74 (live-verified)
        └─ lock owner+0x148; walk owner+0x198 node list
           └─ per node: DELIVER(client=node+0x58, node, arg1, key)  kext +0x1e250
              ├─ IOLockLock(client+0xd8)            ← stale deref #1 (V7 panic site)
              ├─ LOOKUP_SUB(client, key, &sub)      kext +0x1dc5c
              │    ├─ client+0x110 count, client+0x108 PAC array (key 0xf69b)
              │    └─ match sub+0x10 == client+0x118
              ├─ IOLockUnlock(client+0xd8)
              └─ if sub found: notify(node+0x10, 0, {arg1,key}, 2)
                   └─ builds a mach message from node+0x10..0x48 (request
                      payload copied at insertion) and sends it to the
                      port named in the request  (kernel +0x1a50b4 region)
```

Selector-17 wrapper (kext `+0x22330`, live-verified): reads the 0x18-byte
request from `args+0x30`, calls
`insertion(owner=client+0xe8, req, ?, client=this)` — so the node list is a
**global** list owned by `client+0xe8` (== `[global+0xc88]`), and
`node+0x58 = client`, `node+0x50 = request+0x10`, `node+0x10..0x28 = request
body` (attacker-controlled).

## Field map: who controls what at delivery time

| Field | Set by | Attacker-controlled? |
| --- | --- | --- |
| `node+0x58` (client) | insertion arg = closing client | stale pointer (the bug); target of reclaim |
| `node+0x50`, `node+0x10..0x28` | selector-17 request struct | **yes, raw bytes** — but only used as notify payload/port |
| `client+0xd8` (lock) | reclaiming client's init (`IOLockAlloc`) | **no** — re-initialized before any delivery can observe reuse (V11: 22/22 fresh valid locks, isa unchanged) |
| `client+0x108/+0x110/+0x118` | reclaiming client's own subscriptions | only via legitimate selector 17/18 on our own new connection; PAC-signed array |
| `owner+0x148/+0x198` | global list owner | no |

## What the stale deref can and cannot do

1. **Free → delivery before reuse** (V7): `client+0xd8 == 0` →
   `IOLockLock(NULL)` → `casa x8, x9, [x0+8]` at address `0x8` → panic.
   DoS-grade, VM-proved.
2. **Free → delivery after same-class reclaim** (V11, 22 cases): `+0xd8` is a
   fresh valid `IOLock *` → delivery proceeds against the wrong (but live)
   client: locks it, looks up its subscriptions, unlocks, and sends the
   stale node's notify payload to the port in `node+0x10`. No wild pointer.
3. **Free → delivery mid-init** (not observed): `client+0xd8` would be
   transient garbage → `casa` writes the per-CPU thread token at
   `[garbage+8]` where `*==0`. Target address is not attacker-chosen and the
   written value is a semi-fixed token, so even if hit this is a crash-grade
   wild write, not a controlled primitive.

The `casa` write primitive sketched in the derivation plan requires
`client+0xd8` to be attacker-chosen. V11 rules that out for this zone:
`kalloc_type` allocations of the client's size are class-isolated on this
build (mach-message cross-type spray never landed; all observed reclaims are
same-class with the lock field re-initialized).

## Verdict

From this race, the delivery path does **not** provide a controlled kernel
read/write. The VM-proved ceiling is a repeatable stale-pointer deref that
panics when it wins the free→reuse window (null lock) and is otherwise
benign (wrong-client notification). The honest product of this bug class is a
disclosure-grade kernel race / DoS report, matching the 27.2 fix (late
insertion rejected via the `+0xf1` guard).

For a KRW claim one would still need: delivery landing inside the
alloc→lock-init window **and** control of `+0xd8` at that instant, or a
second bug in the notify path. Neither is supported by current evidence, and
V9 already excluded allocator-release-before-delivery as a general property.

## Evidence labels

- **STATIC**: call chain, field map, wrapper contract (exact-build
  disassembly, live-verified sites).
- **VM**: V7 null-lock panic; V10 list consistency; V11 reclaim behavior
  (22 stale deliveries, same-class reclaim, no cross-type spray hits).
- Not proved: controlled reclaim, mid-init delivery, any kernel read/write.
