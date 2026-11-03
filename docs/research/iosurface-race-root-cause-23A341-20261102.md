# IOSurface notification race: 23A341 panic root cause

Date: 2026-11-02\
Target: vPhone research VM, iOS 26.0 `23A341`\
Evidence: repeated VM kernel panics plus exact-build static analysis

## Result

The two panics are the same fault after removing their different boot slides.
The crashing IOSurface delivery path receives a stale
`IOSurfaceRootUserClient *`, loads its `IOLock *` from client offset `+0xd8`,
and calls the kernel lock helper with a null pointer. The lock helper then
performs an atomic compare-and-swap at `lock + 8`, producing the observed
`FAR = 0x8`.

The user-client free path independently shows the matching teardown:

```text
IOLockFree(client->lock_at_0xd8);
client->lock_at_0xd8 = NULL;
```

The notification node survives because delayed selector 17 insertion can run
after close has already bulk-removed that client's old nodes. The newly linked
node stores the closing client as a raw pointer at node offset `+0x58`.
The later IOSurface use-count transition walks the node and dereferences that
stale client.

This establishes a temporal stale-pointer/use-after-free bug. The concrete
crash observed twice is a null-lock dereference, not controlled kernel
read/write.

## Evidence labels

- **VM**: observed in one of the preserved VM panic reports or V6 host
  telemetry.
- **STATIC**: established from the exact Mach-O instructions or Ghidra
  pseudocode for the UUID-matched images.
- **SEMANTIC**: a descriptive function name inferred from strings, field use,
  and call behavior because Apple stripped the function symbols.

## Exact image identity

The analyzed compressed cache is:

```text
~/Library/CyanideVPhoneLab/VMs/cyanide-ios26-base/
  iPhone17,3_26.0_23A341_Restore/kernelcache.research.vresearch101
SHA-256 5f934a6f2131c8c6590543b133cee9d80f439137ec682dc3557c558d78bfd462
```

Identity checks:

| Image | Panic UUID | Local Mach-O UUID | Result |
|---|---|---|---|
| Inner kernel | `03A93373-6498-3F25-8975-04DED251AF1F` | `03A93373-6498-3F25-8975-04DED251AF1F` | exact |
| `com.apple.iokit.IOSurface` 393.2.9 | `8132EC95-DE46-3731-9931-024187C84DD2` | `8132EC95-DE46-3731-9931-024187C84DD2` | exact |

The local IOSurface `__TEXT_EXEC` begins at
`0xfffffe000907e2b0`, exactly equal to each panic's runtime kext base minus
that boot's `KernelCache slide`.

## Panic normalization

| Observation | First VM panic | V6 VM panic | Normalized result |
|---|---:|---:|---:|
| KernelCache slide | `0x29cd8000` | `0x41490000` | n/a |
| PC | `0xfffffe00317e8284` | `0xfffffe0048fa0284` | `0xfffffe0007b10284` |
| LR | `0xfffffe0032d7e544` | `0xfffffe004a536544` | `0xfffffe00090a6544` |
| IOSurface base | `0xfffffe0032d562b0` | `0xfffffe004a50e2b0` | `0xfffffe000907e2b0` |
| FAR | `0x8` | `0x8` | `0x8` |

Both normalize to IOSurface LR offset `+0x28294`. Their three IOSurface
backtrace frames also normalize identically:

- `IOSurface + 0x1efb8` -> `0xfffffe000909d268`
- `IOSurface + 0x0d394` -> `0xfffffe000908b644`
- `IOSurface + 0x25e84` -> `0xfffffe00090a4134`

Use `scripts/lab/cnd_iosurface_panic_symbolicate.py` to reproduce these
calculations and verify the two local Mach-O UUIDs.

## Faulting instruction

**STATIC:** the normalized PC lies in the kernel function beginning at
`0xfffffe0007b10274`:

```asm
0xfffffe0007b10274  mov   x8, #0
0xfffffe0007b10278  mrs   x1, tpidr_el1
0xfffffe0007b1027c  ldr   w9, [x1, #0x490]
0xfffffe0007b10280  add   x10, x0, #8
0xfffffe0007b10284  casa  x8, x9, [x10]   ; panic PC
```

**VM:** at the panic, `x0 = 0` and `FAR = 8`. The effective address of the
atomic operation is therefore exactly `x0 + 8 = 8`.

**SEMANTIC:** this is the fast path of `IOLockLock`. IOSurface's initialization
path calls the allocation helper immediately before the literal
`"Cannot allocate IOLock"`; its free path calls the paired deallocation
helper. Calls to `0xfffffe0007b10274` and `0xfffffe0007b110b8` bracket critical
sections over that pointer and are identified here as `IOLockLock` and
`IOLockUnlock`.

## IOSurface caller and stale field

The immediate IOSurface caller begins at `0xfffffe00090a6500`:

```asm
0xfffffe00090a653c  ldr  x0, [x0, #0xd8]
0xfffffe00090a6540  bl   0xfffffe0007b10274
0xfffffe00090a6544  mov  x2, sp             ; panic LR
```

Ghidra's exact-build decompilation is equivalent to:

```c
lock(client->field_d8);
found = lookup_client_subscription(client, notification_key, &subscription);
unlock(client->field_d8);
if (found)
    send_async_result(node->async_state, notification_kind, notification_key);
```

The panic proves that `client->field_d8` was null at delivery.

## Teardown clears the same field

**STATIC:** the IOSurfaceRootUserClient initialization function at
`0xfffffe00090a1794` contains the `IOSurfaceRootUserClient` entitlement and
allocation strings, allocates the subscription arrays, and does:

```c
client->field_d8 = IOLockAlloc();
if (client->field_d8 == NULL)
    log("Cannot allocate IOLock");
```

**STATIC:** its free function at `0xfffffe00090a1b40` releases the same
subscription array used by the delivery lookup and then executes:

```asm
0xfffffe00090a1cf8  ldr  x0, [x19, #0xd8]
0xfffffe00090a1cfc  cbz  x0, 0xfffffe00090a1d08
0xfffffe00090a1d00  bl   0xfffffe00081a184c  ; IOLockFree, semantic name
0xfffffe00090a1d04  str  xzr, [x19, #0xd8]
```

This is an exact producer-consumer match: teardown zeros the field that the
notification-delivery path later passes to the faulting lock helper.

## Normalized delivery call chain

The backtrace resolves as follows:

| Address | Role |
|---|---|
| `0xfffffe00090a407c` | use-count transition handler; updates a surface count and requests notification delivery when the transition qualifies |
| `0xfffffe000908b52c` | walks interested surface/client records and detects the transition to notify |
| `0xfffffe000909d224` | locks root `+0x148`, walks the notification list at root `+0x198`, and loads node `+0x58` as the client pointer |
| `0xfffffe00090a6500` | locks client `+0xd8`, looks up the client's subscription, and emits the async notification |
| `0xfffffe0007b10274` | kernel lock fast path; faults at `+0x10` because the supplied lock is null |

The high-level sequence is therefore:

```text
selector 17 delayed insertion
  -> root notification node linked with node->client = closing client
IOServiceClose
  -> IOSurfaceRootUserClient teardown frees/zeros client+0xd8
IOSurface use-count trigger
  -> notification walker loads node->client
  -> delivery loads client+0xd8 == NULL
  -> IOLockLock(NULL)
  -> atomic access at NULL+8
  -> Kernel data abort, FAR 0x8
```

The actual raced order is slightly interleaved: close bulk-removes the old
nodes, and the already-issued selector 17 finishes inserting a new node after
that removal. This is why the node remains reachable after user-client
teardown.

## What is proved

- **VM-proved repeatedly:** the same IOSurface delivery path reaches the same
  null lock fault across different boot slides. V8 added three preserved
  post-detach panics with the same normalized PC, LR, FAR, and image UUIDs.
- **VM-proved in V6:** immediately before the second panic, selector 17 had
  returned success and `IOServiceClose` had completed first; the host captured
  the before-trigger marker and no after-trigger marker.
- **STATIC:** the stale node supplies an `IOSurfaceRootUserClient *` from node
  `+0x58`.
- **STATIC:** user-client free clears its IOLock pointer at `+0xd8`.
- **STATIC + VM:** delivery consumes that cleared field and faults at
  `IOLockLock(NULL) + 0x10`.
- **VM-proved in V7:** the client pointer at teardown and delivery is identical,
  while `client+0xd8` changes from a valid IOLock pointer to zero.

## What is not proved

- No same-zone reclaim or controlled replacement of the user client has been
  observed.
- V8 did not observe allocator completion, no intervening same-class address
  reuse, and strictly later delivery within one continuous debugger interval.
  Therefore allocator-release-before-delivery remains unproved.
- No attacker-chosen non-null lock pointer has been delivered.
- No kernel read, kernel write, or controlled call follows from the current
  evidence.
- Nothing here is physical-device proof.
- The exact C++ names of stripped private helper functions remain semantic
  labels, even though their instructions and object fields are exact.

## V7 result: pointer-lifetime witness

V7 completed this bounded experiment before any reclaim work. It used a fresh
slide and two read-only hardware-breakpoint callbacks at the planned static
instructions:

1. Boot the visible research VM and obtain a fresh slide from the debugger;
   never reuse either panic's slide.
2. Keep the V6 race and host UDP markers unchanged.
3. With read-only debugger observation, capture the client pointer when the
   close/free path executes the store at static `0xfffffe00090a1d04`.
4. Capture the client pointer at delivery immediately before static
   `0xfffffe00090a653c` loads `client+0xd8`.
5. Record whether the pointers are identical and whether `client+0xd8` is zero.
6. Run a no-trigger control to verify the observer itself does not fabricate
   delivery.

The observed tuple was client `0xfffffe250deddb60`, lock
`0xfffffe30a2a9ca10` before the clearing store, and zero at delivery. The
resulting third panic has the same normalized signature and contains the same
client pointer in `x22`. See
`docs/research/iosurface-race-v7-lifetime-witness-20261102.md` for the control,
telemetry, live binding, and evidence inventory. V7 did not spray, replace the
object, write kernel memory, or claim KRW.

## V8 result: allocator-release boundary

Exact-build static analysis after V7 resolved the class's generated deletion
path. `IOSurfaceRootUserClient` is a `0x148`-byte typed allocation using the
descriptor at static `0xfffffe00079cf8c8`. Its deleting destructor at static
`0xfffffe000909fc24` tail-calls the typed release routine from static
`0xfffffe000909fc64`; the routine's underlying allocator call has returned at
static `0xfffffe000812e490`.

V8 observed the exact destructor handoff, the same-thread allocator completion
point, the class's typed-allocation return, and the established delivery load
at static `0xfffffe00090a653c`. The observer rejected same-stop multicore hits
and invalidated release records when the same address was allocated again.

A 100-iteration add-first control produced no qualifying delivery. Three
bounded close-first attempts (300 seconds, continuous 600 seconds, and twelve
continuous 60-second windows) also produced no qualifying delivery. Each
long-running probe reproduced the established panic after the final debugger
detach, but delivery then occurred outside the observation interval. V8 is
therefore a bounded negative, not allocator-release-proven UAF evidence.

Full counters, rejected false positives, post-detach limitations, and the
evidence inventory are in
`docs/research/iosurface-race-v8-allocator-release-20261102.md`. V8 remained
VM-only and did not include a spray, replacement attempt, kernel write, or KRW
claim.

## V9 result: clean probe exit

V9 eliminated V8's detach gap with a finite 3,000-iteration close-first run.
The probe exited normally after 43 seconds, including four registrations that
completed after close. The allocator observer stayed attached for roughly 257
more seconds, then detached with no qualifying delivery and no panic. There was
no V9 process and no new panic report after detach.

This result confirms that the immediate post-detach V8 panics occurred while
the long-running race process was still active. They remain reproductions of
the established null-lock fault, not allocator-release-before-delivery proof.
See `docs/research/iosurface-race-v9-clean-exit-20261103.md`.

## Preserved evidence

- First panic: `~/Library/CyanideVPhoneLab/evidence/iosurface-race-20261101/`
- V6 telemetry and second panic:
  `~/Library/CyanideVPhoneLab/evidence/iosurface-race-v6-20261101/`
- V7 lifetime witness and third panic:
  `~/Library/CyanideVPhoneLab/evidence/iosurface-race-v7-20261102/`
- V8 allocator-boundary controls, event logs, and three post-detach panics:
  `~/Library/CyanideVPhoneLab/evidence/iosurface-race-v8-20261102/`
- V9 finite-run telemetry, continuous observer log, and clean detach evidence:
  `~/Library/CyanideVPhoneLab/evidence/iosurface-race-v9-20261103/`
- Pre-experiment static plan:
  `docs/research/iosurface-race-probe-plan-20261101.md`

The V7 follow-up used only the disposable research VM. No physical device was
touched.
