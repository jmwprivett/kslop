# RemoteCall dummy-thread mutex panic on 23A341 — root cause and fix (2026-11-02)

## Evidence standard

- **Implemented:** yes — `Cyanide/TaskRop/RemoteCall.m`; focused suites pass (kexploit_reliability 27, krw_socket_parking 20, iconservices_publisher_transport 45, physical_springboard_pac_probe 7, remotecall_mutex_safety 3). A fresh signed arm64/arm64e device build also completed successfully.
- **VM-proved:** no.
- **Physical-proved:** no. The panic was observed on the physical iPhone 16 Pro Max (23A341); the fix has not yet been exercised on device.

## Observed panic

`/tmp/cyanide-ipinky-latest/panic-full-2026-11-02-004838.0002.ips`:

```
panic(cpu 2 caller 0xfffffff04982a97c): Mutex 0xffffffe0aa89de48 is unexpectedly
not owned by thread 0xffffffe0aab1e1c0 @lock_mtx.c:172
Darwin Kernel Version 25.0.0 ... root:xnu-12377.2.8~1/RELEASE_ARM64_T8140
Panicked task ... pid 576: Cyanide
```

Panicked thread backtrace runs through `thread_set_exception_ports` kernel frames and ends at a userspace `pthread_exit` frame — i.e. the RemoteCall **helper thread**, not the main thread. Intermittent: the unchanged binary had run the same bootstrap many times before panicking once, so this is a race, not a deterministic path.

## Root cause (verified against xnu-12377 source)

`osfmk/kern/lock_mtx.h` (xnu-12377.1.9, same family as 12377.2.8): the 32-bit `lck_mtx.data` word stores the **owner ctid in the low 28 bits** (`LCK_MTX_CTID_MASK = 0x0fffffff`); bit 30 is `LCK_MTX_NEEDS_WAKEUP = 0x40000000`. There is no separate LOCKED bit — **owner == 0 means free, and every acquire path requires owner == 0**.

`lock_mtx.c`: `lck_mtx_unlock` slow path panics at line ~172 (`__lck_mtx_not_owned_panic`, "Mutex %p is unexpectedly not owned by thread %p") when `current_thread()->ctid != (data & LCK_MTX_CTID_MASK)`. The fast path CASes `data` from `thread->ctid` to `0` and falls through to that check on any mismatch.

`thread_set_exception_ports` (MIG, `osfmk/kern/ipc_tt.c`) → `thread_set_exception_ports_internal` does `thread_mtx_lock(thread)` / `thread_mtx_unlock(thread)` on the **target thread's own mutex** — here the dummy thread's mutex (`off_thread_mutex_lck_mtx_data`).

`set_exception_port_on_thread` (RemoteCall.m) bootstrap sequence:

1. Forge: `thread_set_mutex(g_RC_dummyThreadAddr, g_RC_selfThreadCtid)` — makes the dummy's mutex read "owned by the bootstrapping thread". This is deliberate: the helper, once resumed, parks inside `lck_mtx_lock` on that word, which keeps its kernel stack (and the `dummyThreadTro` MIG-frame needle) stable long enough for the bootstrap loop to find the needle and swap in the target thread's `tro`.
2. Resume helper → helper runs `thread_set_exception_ports(dummyThreadMach, ...)` → `thread_mtx_lock(dummy)` → parks on the forged owner.
3. Bootstrap loop swaps the tro on the helper's kernel stack.
4. Old code then **unconditionally** rewrote the word: `thread_set_mutex(g_RC_dummyThreadAddr, 0x40000000)`.

The race: if the helper had already acquired the lock (word = helper ctid) by the time step 4 executed, step 4's write replaced the owner with 0. The helper's subsequent `lck_mtx_unlock` then sees `owner 0 != helper ctid` → fast-path CAS fails → slow-path ownership check fails → **panic at lock_mtx.c:172**. When the write lands while the helper is still parked (the common case), the helper acquires afterwards and unlocks cleanly — which is why it only panics occasionally.

## Fix (RemoteCall.m)

Both writes to the dummy's mutex word are now gated on its current owner, using the xnu-12377 encoding:

- **Forge** (`set_exception_port_on_thread`): only write `g_RC_selfThreadCtid` when `(word & 0x0fffffff) == 0` (lock actually free). A non-free word aborts this helper setup before resume. If it is a stale forge owned by the current thread, the guarded release clears it; any other owner is left untouched. The caller can retry with the next candidate thread without running a helper against mutex state this invocation did not create.
- **Release** (new `release_forged_dummy_mutex(why)`, used after the helper loop and on the resume-failure path): only rewrite the word to `LCK_MTX_NEEDS_WAKEUP` when `(word & 0x0fffffff) == g_RC_selfThreadCtid`. This is race-free: while the owner is still our ctid, no acquire path can succeed, so the helper cannot hold the lock, so the write cannot land inside its critical section. If the helper already owns the mutex, we skip the write and its own `lck_mtx_unlock` restores owner 0 with proper turnstile wakeup — no panic.
- The resume-failure early return previously leaked the forged owner entirely (a later `thread_mtx_lock(dummy)` from this thread would have hit `__lck_mtx_owned_panic`, "unexpectedly **owned**"); it now calls `release_forged_dummy_mutex` too.

Constants `CND_LCK_MTX_CTID_MASK` / `CND_LCK_MTX_NEEDS_WAKEUP` are defined next to the `g_RC_*` macros with the xnu source citation.

## What this does not change

The parking mechanism itself (forge owner → helper parks in `lck_mtx_lock` → tro swap → release) is unchanged; only the forge/release writes are gated. The MIG-filter-bypass `usleep`s and the retry loop are untouched. Teardown paths (`destroy_remote_call_internal`, `abandon_remote_call_internal`) never wrote the mutex word and are unaffected.

## Open

- Re-run the SnowBoard apply path on the physical device (and the 23A341 VM) to confirm the panic no longer reproduces across repeated bootstraps; until then this is implemented + build/test-proved only.
- The separate 00:40 APFS/physical-aperture panic remains unattributed and is out of scope here.
