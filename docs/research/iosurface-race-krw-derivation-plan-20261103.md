# IOSurface notification race: KRW derivation plan

Date: 2026-11-03
Target: vPhone research VM, iOS 26.0 `23A341` (kernel UUID
`03A93373-6498-3F25-8975-04DED251AF1F`, IOSurface 393.2.9 UUID
`8132EC95-DE46-3731-9931-024187C84DD2`), owned iPhone 16 Pro Max only at the
final stage.
Scope: maintainer's own devices only, no third-party targets, no distribution
of tooling, disclosure-grade documentation. Every claim keeps the evidence
standard: implemented ≠ VM-proved ≠ physical-proved.

## Goal

Derive a kernel read/write primitive from the selector-17 vs. final-close
notification race in `IOSurfaceRootUserClient`, or determine precisely which
prerequisite blocks it.

## What is already proved

- **[VM+STATIC]** Selector 17 asynchronously inserts an
  `IOSurfaceNotifyRequest` node for the calling client; the final
  `IOServiceClose` bulk-removes that client's nodes. Delayed insertion after
  close links a node that stores the closing client as a raw pointer at
  node `+0x58` (see `iosurface-race-probe-plan-20261101.md`,
  `iosurface-race-root-cause-23A341-20261102.md`).
- **[VM]** The same `IOSurfaceRootUserClient *` is seen at teardown
  (`str xzr, [x19, #0xd8]`) and later at delivery (`ldr x0, [x0, #0xd8]`),
  with `client+0xd8` transitioning from a valid `IOLock *` to `0x0`
  (`iosurface-race-v7-lifetime-witness-20261102.md`). Detach then produced
  the repeatable panic: `IOLockLock(NULL)` -> `casa x8, x9, [x0+8]` with
  `FAR=0x8`, normalized to IOSurface `+0x28294`.
- **[VM]** V9 clean-exit run (3000 close-first iterations, RC 0, 257 s
  cooldown): 4 registrations completed after close, **zero**
  allocator-release-before-delivery matches. 2,903 allocator releases were
  invalidated by same-class reuse, i.e. the zone recycles quickly even
  without a spray (`iosurface-race-v9-clean-exit-20261103.md`).

## What is not yet proved (the KRW blockers)

1. The notification node itself surviving close and being delivered (lineage),
   independent of allocator timing.
2. The client allocation (`0x148` bytes, typed descriptor live-bound at
   `0xfffffe00364738c8` in the V9 boot) actually being freed before delivery.
3. Attacker-controlled reclaim of that allocation before delivery.
4. Any controlled dereference: today's crash is a null-lock deref, i.e. DoS.

## Phases

### V10 — notification-node lineage witness (VM, read-only)

- Break on the selector-17 insertion return to capture the new node pointer
  and its stored client (`node+0x58`).
- Break on the close bulk-removal loop; record which nodes it unlinks.
- Prove the same node pointer is still linked after removal completes.
- Break on the delivery walk; prove the same node is consumed and its
  `+0x58` client is dereferenced.
- Finite iterations + clean cooldown, same contract as V9.

### V11 — reclaim experiment (VM)

- From the race process, after close, spray the client's kalloc type with a
  recognizable fill pattern using app-reachable allocations (IOSurface
  objects/buffers first, since they share the IOSurface allocator paths).
- Watch delivery for a client pointer whose bytes match the fill pattern.
- Measure determinism across runs; record zone, size class, and reuse lag.

### V12 — fake-client layout (STATIC, exact build)

- Enumerate every field of `IOSurfaceRootUserClient` that the delivery path
  touches (normalized frames IOSurface `+0x1efb8`, `+0x0d394`, `+0x25e84`,
  caller at `+0x28244`/LR `+0x28294`): which offsets are loaded as pointers
  and dereferenced, which are list heads, which are method/vtable pointers.
- Build the fake-client template and classify each reachable operation as
  read, write, or call.

### Primitive assessment (VM + STATIC)

If reclaim succeeds, the delivery path gives, in order:

1. `ldr x0, [client+0xd8]` with controlled `client` -> controlled lock
   pointer -> `casa x8(=0), x9(thread token), [lock+8]`: a conditional
   atomic write of a per-CPU 32-bit token at `lock+8` wherever that qword is
   currently zero. That is a constrained arbitrary write.
2. The subsequent subscription lookup and node walk read/write further
   client and node fields — candidates for read primitives and for
   list-corruption writes.
3. Any indirect call through a client field needs a PAC-signed pointer;
   prefer data-only corruption (corrupt an adjacent object's fields, e.g. a
   neighboring user client or service object) over control-flow hijack.

### V13+ — escalate to arbitrary KRW (VM, stepwise)

- Use the write primitive / fake object to corrupt a chosen kernel object
  and demonstrate read and write of arbitrary kernel addresses, each step
  VM-proved and labeled.
- Physical-device validation only at the end, on the owned iPhone 16 Pro
  Max, per the project evidence standard.

## Disclosure note

The 27.2 comparison already documents the fix (user-client byte `+0xf1` bit
0 guard rejecting late insertion and set before bulk removal). The V10/V11
results should be packaged with the existing root-cause report for
responsible disclosure regardless of whether KRW is achieved.
