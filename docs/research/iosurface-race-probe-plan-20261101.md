# IOSurface removed-client notification race: probe plan (2026-11-01)

## Scope and evidence labels

Read-only static reverse engineering of the maintainer's own-device iOS 26.0
(23A341, xnu-12377.2.8) kernelcache and comparison with the previously located
27.2 fix. No app, VM, or physical-device experiment was run for this document.

- **[STATIC]**: directly established from instructions, dispatch records, or
  chained fixups in the local binaries.
- **[INFERRED]**: a semantic name or trigger suggested by those instructions,
  but not proved by a runtime experiment or a recovered C++ symbol.
- **[EXTERNAL-PHYSICAL]**: supplied result from an earlier physical sweep, not
  reproduced here.
- **[PLANNED-VM]**: a proposed experiment, not a result.

The main conclusion is that the raced removal helper is **not directly exposed
as an external-method selector**. The app-reachable pair is:

1. **selector 17**: asynchronously register an `IOSurfaceNotifyRequest` for the
   calling `IOSurfaceRootUserClient`;
2. **final `IOServiceClose` on that same connection**: terminate the user client
   and bulk-remove its notification requests.

The vulnerable order is close/bulk-removal first, followed by a delayed
selector-17 insertion for the already-terminating client.

## Image and offset provenance

**[STATIC]** Both raced helpers are in `com.apple.iokit.IOSurface`, not the main
kernel image.

- IOSurface fileset entry: VM address `0xfffffff0078916a0`, fileset file offset
  `0x88d6a0`.
- Its `__TEXT_EXEC` occupies kernelcache file offsets
  `0x3800920..0x3b3213c` (size `0x3181c`).
- Relative to the extracted global `26.0-23A341.textexec` slice, that kext
  occupies `0x2624920..0x265613c`.
- Consequently:
  - insertion `global +0x2643688` = kext `__TEXT_EXEC +0x1ed68`, VA
    `0xfffffff00a823688`;
  - bulk removal `global +0x26438f4` = kext `__TEXT_EXEC +0x1efd4`, VA
    `0xfffffff00a8238f4`.

The 27.2 comparison remains as previously documented: insertion rejects when
byte `+0xf1` bit 0 is set, and bulk removal sets that byte before unlinking.
The instructions below identify that object as the **user client**, not an
`IOSurface` object.

## Selector to helper mapping

**[STATIC]** `IOSurfaceRootUserClient::externalMethod` at global
`__TEXT_EXEC+0x264c340` selects between two 60-row
`IOExternalMethodDispatch2022` tables and passes `0x3c` as the row count. Each
row is 40 bytes on this build: handler, four 32-bit argument checks,
`allowAsync`, padding, and an entitlement-string pointer.

- Full table: `0xfffffff0080eba28`.
- Reduced table: `0xfffffff0080ec388`.
- Reduced-table selection is client byte `+0x127` bit 0.

The supplied physical note saying “79 selectors” does not match this static
26.0 dispatcher. **Sixty rows is the static count for this user client**; the
old sweep count should be rechecked rather than used to size this table.

| Reachable operation | Full-table selector / path | 26.0 code chain | Argument contract | Relation to raced helpers |
|---|---|---|---|---|
| Add notification request | **17** | row handler `+0x2646c50` -> tail branch to **`+0x2643688`** | 0 scalar inputs, **`0x18`-byte struct**, no outputs, `allowAsync=1`, entitlement pointer NULL | **Direct insertion path** |
| Remove one notification request | **18** | row handler `+0x2646c78` -> **`+0x264378c`** | 0 scalar inputs, **`0x18`-byte struct**, no outputs, `allowAsync=0`, entitlement pointer NULL | Separate single-node removal; **not** the patched bulk-removal helper |
| User-client teardown | No selector; final connection close | termination method `+0x2648590` -> call at `+0x26485d8` to **`+0x26438f4`** | Requires client active byte `+0xf0` bit 0; termination clears it first | **Only direct caller of the raced bulk-removal helper found** |
| Reduced-table selectors 17 and 18 | 17/18 on reduced clients | both -> denial stub `+0x2647d2c` | Same row shapes, but method is replaced | Returns `0xe00002e2` (`kIOReturnNotPermitted`) |

A whole-kernel direct-branch scan found only the teardown call to
`+0x26438f4`. Selector 18 must therefore not be substituted for close in the
primary race: it exercises `+0x264378c`, not the fixed site under study.

There is also an internal insertion tail wrapper at `+0x264acb0`, but it has no
recovered dispatch-table reference. Selector 17's `+0x2646c50` wrapper is the
concrete app path.

### High-level IOSurface framework mapping

These rows are useful for setup and for distinguishing the race from ordinary
attachment operations.

| Framework/API operation | Selector | Evidence |
|---|---:|---|
| `IOSurfaceCreate` | **0** | **[STATIC]** one scalar plus variable serialized input, `0xc68`-byte result; enters surface creation |
| `IOSurfaceLookup` | **4** | **[STATIC]** one surface-ID scalar, `0xc68`-byte result; handler performs client lookup/attach |
| `IOSurfaceSetValue` / `IOSurfaceSetValues` | **9** | **[STATIC/INFERRED]** variable serialized input and 4-byte result, entering attachment mutation |
| `IOSurfaceCopyValue` | **10** | **[STATIC/INFERRED]** variable serialized input and variable output |
| `IOSurfaceRemoveValue` / `IOSurfaceRemoveAllValues` | **11** | **[STATIC/INFERRED]** variable serialized input and 4-byte result |
| `IOSurfaceSetPurgeable` | **20** | **[STATIC/INFERRED]** two scalar inputs and one scalar output, matching surface ID/new state/old state |
| Notification registration for this race | **17/18 directly through IOKit** | **[STATIC]** current locally installed public SDK headers do not declare a high-level wrapper for this pair; use `IOConnectCallAsyncStructMethod` for 17 and `IOConnectCallStructMethod` for 18 |

In particular, `IOSurfaceSetValue` is not the raced insertion path, and ordinary
`CFRelease(surface)` is not the raced removal path.

## Object, list, and lock analysis

### List owner and node

**[STATIC]** Selector 17 receives the `IOSurfaceRootUserClient *` as its target,
loads the root object from client `+0xe8`, and calls the insertion helper as:

```text
insert(root, arguments->asyncReference, structureInput, userClient)
```

The root's relevant fields are:

- root `+0x148`: mutex pointer;
- root `+0x198`: notification-list head;
- root `+0x1a0`: notification-list tail.

Each allocated node is approximately `0x60` bytes and contains:

| Node offset | Meaning established from use |
|---:|---|
| `+0x00`, `+0x08` | forward/back list links |
| `+0x10` | embedded notification/async-request state |
| `+0x20` | 64-bit registration key copied from struct `+0x08` |
| `+0x50` | third input qword copied from struct `+0x10` |
| `+0x58` | owning `IOSurfaceRootUserClient *` |

The kext contains `site.IOSurfaceNotifyRequest` and
`site.IOSurfaceRootUserClient` allocation/type strings. Exact C++ helper names
were not recovered; `insert_notification_request` and
`remove_client_notification_requests` are descriptive names only.

Insertion deduplicates on `(struct qword[1], userClient)`. Repeating the same
key on one live client can therefore return `0xe00002c9` instead of creating
another node.

### Lock and fixed-state object

**[STATIC]** All three list helpers lock root `+0x148` before examining or
changing the list and unlock on exit. The lock fast path uses an owner-thread
CAS and a slow path, consistent with a sleepable IOKit mutex/`IOLock`, not an
unlocked list or a simple test-and-set spinlock.

**[STATIC]** The fixed build's byte `+0xf1` is on the **user client**:

- insertion receives the client as argument 4 and reads `client+0xf1` after
  taking the root lock;
- user-client termination passes that same client as argument 2 to bulk
  removal, which writes `client+0xf1 = 1` after taking the root lock.

**[STATIC]** The mutex prevents concurrent unlink/insert list corruption. The
bug is an ordering/lifetime gap:

```text
T-close: lock(root)
T-close: remove and free every node whose node->client == C
T-close: unlock(root)                 ; 27.2 also marks C removed under lock

T-add:   lock(root)                   ; delayed call was already associated with C
T-add:   26.0 does not reject removed C
T-add:   allocate and link a new node with node->client = C
T-add:   unlock(root)
```

If insertion wins the lock before close, close removes the new node and the
ordering is safe. The target ordering is insertion **after** bulk removal.

### Stale-pointer consumer and potential primitive

**[STATIC]** The root notification walker at `+0x2643884` iterates this list and
calls the delivery helper at `+0x264cb60` with `node->client` as argument 1.
Delivery immediately loads the client mutex from `client+0xd8`, then examines
client subscription fields including `+0x108`, `+0x110`, and `+0x118`.

Thus the static primitive candidate is a **stale
`IOSurfaceRootUserClient *` retained by a live notification-list node**, not a
freed notification node. A post-close notification can cause a UAF read/lock
operation on the reclaimed client. Controlled replacement could influence
later subscription-state accesses, but no controlled write, arbitrary call, or
kernel read/write primitive is established by this analysis.

## Sandbox and entitlement gates

- **[EXTERNAL-PHYSICAL]** The supplied sweep says an ordinary app can open
  `IOSurfaceRoot` with connection type 0.
- **[STATIC]** Full-table rows 17 and 18 have NULL entitlement checks.
- **[STATIC]** Client startup tests
  `com.apple.private.gpu-restricted` and
  `com.apple.developer.gpu-restricted`; either sets client byte `+0x127` and
  selects the reduced table. On that table, selectors 17/18 return
  `0xe00002e2`.
- **[STATIC]** An unentitled ordinary client takes the full table. Do not add
  either GPU-restricted entitlement to the probe app. The separate
  `com.apple.private.iosurfaceinfo` and
  `com.apple.private.IOSurface.protected-access` checks do not select this
  reduced table.
- **[INFERRED]** No root-only operation is needed for the proposed selector-17
  versus close probe. Sandbox acceptance still needs VM confirmation on the
  exact app container/profile.

## Concrete probe plan

### Phase A: functional preflight on a stable connection

**[PLANNED-VM]** Validate the calling convention before racing:

1. Match `IOSurfaceRoot`, open type 0, and retain that connection.
2. Allocate a Mach receive right for async completion.
3. Create a small ordinary surface through `IOSurfaceCreate` and retain it for
   the entire test. Record `IOSurfaceGetID(surface)`.
4. Build a 24-byte input as three qwords:

   ```c
   struct NotifyInput {
       uint64_t request;    // start at 0
       uint64_t key;        // surface ID in the low 32 bits
       uint64_t extra;      // start at 0
   };
   ```

   **[STATIC]** qword 1 is the list key. **[INFERRED]** using a real surface ID
   is the appropriate way to make later notification delivery interesting; the
   insertion helper itself does not look up or validate that ID.
5. Call selector 17 asynchronously with eight zeroed async-reference qwords and
   the 24-byte input. Expect `KERN_SUCCESS` on the full table.
6. Call selector 18 synchronously with the same input. Expect `KERN_SUCCESS`.
7. Repeat 17/18 once without close. This distinguishes argument/transport
   failures from lifecycle-race behavior.

Use `kIOAsyncReferenceCount` (8 on the installed IOKit headers), rather than a
null reference array: selector 17 explicitly rejects a null `asyncReference`
with `0xe00002c2`.

### Phase B: minimal two-thread race

The following is deliberately pseudo-code, not a claim that the sequence has
been run. `surface` and `wake_port` belong to setup and remain alive. Each
iteration uses a fresh raw `io_connect_t` so `IOServiceClose` is the final user
close on that connection.

```c
// Setup once:
surface = IOSurfaceCreate(minimal_valid_properties);
target_id = IOSurfaceGetID(surface);
mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wake_port);

for (iteration = 0; iteration < ITERATIONS; iteration++) {
    io_connect_t C = open_iosurface_root_type_0();
    struct NotifyInput in = { .request = 0, .key = target_id, .extra = 0 };
    uint64_t refs[kIOAsyncReferenceCount] = {0};
    atomic_bool go = false;
    kern_return_t add_kr;

    // Thread A, released by the same barrier as thread B:
    add_kr = IOConnectCallAsyncStructMethod(
        C, 17, wake_port, refs, kIOAsyncReferenceCount,
        &in, sizeof(in), NULL, NULL);

    // Thread B, concurrently:
    IOServiceClose(C);

    join_A_and_B();
    record(add_kr, iteration);

    // Post-close consumer/oracle; keep these balanced and on a live surface.
    IOSurfaceIncrementUseCount(surface);
    IOSurfaceDecrementUseCount(surface);

    // Optionally drain wake_port without blocking, then begin the next cycle.
}
```

The close thread should start immediately after the registration thread has
been released, with a small randomized close delay across iterations (zero to
a few tens of microseconds). Pinning the two threads to different cores and
varying that delay is more useful than simply maximizing thread count.

**[INFERRED]** The use-count transition is a consumer candidate because the
static notification walker is called from surface use-count transition code.
If it does not produce delivery in the VM, retain the same stale-node race and
enumerate other ordinary surface notification sources; do not conclude that
insertion failed merely because no panic occurred.

### Phase C: scale only after Phase B is validated

- Open a fresh connection per attempt and queue several selector-17 calls on
  that connection before closing it. Use distinct real surface IDs/keys to
  avoid the duplicate-key result.
- Keep all corresponding surfaces alive on independent framework connections.
- Vary 1, 2, 4, and 8 concurrent registration callers and the close delay.
- Run the same binary on 26.0 and 27.2. On 27.2, a delayed insertion that hits
  the new guard should return **`0xe00002d8`** (`0xe00002bd + 0x1b` in the
  fixed instructions) and must not leave the stale node.
- Include controls: 17/18 without close, close without 17, and notification
  generation without any raced registration.

## Expected results and failure modes

| Observation | Interpretation |
|---|---|
| Selector 17 returns `0xe00002e2` | Reduced dispatch table; remove GPU-restricted entitlements / wrong client class |
| `0xe00002c2` | Bad argument: wrong struct size, null async references, or invalid call shape; fix preflight before racing |
| IPC/transport error before the helper | Bad wake port, closed connection too early, or sandbox/transport issue; not the target race |
| `0xe00002c9` on a stable client | Duplicate `(key, client)` registration; use a new key or remove with selector 18 |
| Repeated success and no panic | Expected for lost races and for won races without a delivery event; not proof of absence |
| Fixed build returns `0xe00002d8` after close | Direct evidence that the delayed insertion reached the new removed-client guard |
| Panic after a post-close surface event on 26.0 | Potential race win; capture PC and panic string and compare with delivery at `+0x264cb60`, lock acquisition, and nearby client-field accesses |
| Same signature on 27.2 | Not validation of this fix; re-triage as a different path or an experimental artifact |

A useful 26.0 crash signature is a data abort or mutex-related fault while
walking the root notification list after close, especially near the client
`+0xd8` load/lock in `+0x264cb60`. PAC traps or allocator panics may instead be
the first observed symptom depending on reclamation. None should be relabeled
as a controlled primitive without additional evidence.

## Win condition and current boundary

The first **VM-provable win** is:

1. selector 17 was issued on client `C`;
2. final close completed bulk removal for `C`;
3. selector 17 nevertheless completed insertion afterward;
4. a later notification walked the surviving node and dereferenced freed `C`.

That is a concrete stale-client UAF condition. A panic at the subsequent client
lock/subscription access would strongly support it. A reusable corruption
primitive would additionally require demonstrating control over the reclaimed
client allocation and a security-relevant effect beyond the initial UAF read.

Current status: **[STATIC] selector and lifetime chain established;
[PLANNED-VM] trigger designed; not VM-proved, not physical-proved, and no
controlled kernel read/write primitive claimed.**
