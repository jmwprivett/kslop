## Quest 2 audit: porting the KRW into a kcall

### Where the port actually stands

- **VM: done, and honestly fenced.** `cnd_vphone_krw.py restart` → capability `0xf`, isolated kcall smoke test (inert `__TEXT_EXEC` return stub via syscall 439), per-boot revalidation, debugger-port slide recovery. `CNDLabKernelProvider.h` documents in the header itself that `cnd_lab_kernel_call` is VM-only, never routed from physical KRW, max 8 args, target must lie in the validated kernel image. `vm-guide.md` hard rules ("never infer kcall from tfp0/KRW alone", "never broaden syscall-439 into a physical claim") are exactly right.
- **Physical: absent, by design.** `xpf_arm64_kcall_supported()` = `!gXPF.kernelIsArm64e && xpf_supported_16down()` — arm64e excluded. The old arm64 `kcall_return` gadget set survives only as an excluded XPF set. `springboard-resident` doc constraint 8 states it plainly: physical KRW can *verify* an entry but cannot *call* it, because writing an unsigned address satisfies nothing on a PAC-correct branch.
- **The concrete port candidate exists and is waiting:** `cs_allow_invalid` at unslid `0xfffffff0086e6b68` (base `+0x16e2b68`), 23A341/D47AP, prologue + both `PT_ATTACHEXC` branch instructions decode-verified. The probe refuses to run unless everything matches. It has never been invoked, because invoking it *is* the missing primitive.

### KRW itself (the thing being ported)

`kexploit_opa334.m` — opa334-style socket-KRW with `EARLY_KRW_LENGTH 0x20` window, checked 32-byte writes (`kexploit_early_kwrite32bytes_checked`), restore-snapshot export/import, and a five-way `CNDKExploitOutcome` enum (including `SafelyParked` / `VerifiedRollback`) — an unusually clean exploit lifecycle state machine. Launchd-held fileport park/recover (`persistence.m`) is implemented for Cyanide recovery but SpringBoard recovery is unproved. KRW locking is a process-local `pthread_mutex_t` (`kexploit_opa334.m:876`) — known, documented, unsolved.

### What has been tried for the port (kcall routes)

| Route | Status |
| --- | --- |
| XPF arm64 `kcall_return` gadget | Excluded on arm64e by capability check — correct, no bypass attempted |
| VM syscall-439 provider (`cnd_lab_kernel_call`) | Working, VM-only, smoke-tested per boot — the "port target" semantics, not a port |
| EL1 signer / `thread_set_state` as kcall carrier | **Closed** (EL0 sanitization + `kGUARD_EXC_THREAD_SET_STATE` on unentitled direct calls) |
| `thread->recover` PC as kcall carrier | **Closed** (immutable recover table) |
| `remote_pac` JOP-ID transplant | Physical, KRW-only, signs **user** context pointers; deliberately never claimed as kcall |
| pmap/SPTM adapter in `CNDLabKernelPAC` | Live on VM *only when lab kcall is already active* — i.e. it consumes kcall, it doesn't create it |
| `cs_allow_invalid(exactSpringBoardProc)` narrow call | Specified, entry-verified, **never invoked**; explicitly gated on a PAC-correct kernel control-flow primitive (Quest 1) |
| `CNDLabThreadCallPACBoundary` | Read-only VM probe of a timer port's embedded `thread_call` labels — reconnaissance toward a thread-call PAC target, not an attempt yet |
