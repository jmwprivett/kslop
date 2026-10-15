## Quest 1 audit: the PAC bypass

### Tried and physically closed (stop spending time here)

| Route | Evidence | Verdict |
| --- | --- | --- |
| Aperture write to dyld shared-cache **text** frame (Hail Mary `kwrite32` word patch) | `hail-mary-patch.md`, 7 byte-identical panics, `esr 0x9600004f`, `x3` holds merged word never stored | **Dead.** Aperture maps text frame RO. No racing/no-readback strategy can ever work; the intermittent "transparency" observations were early-return paths, not writes. Correctly diagnosed and correctly retired. |
| Forged task port via stripped `task *` into `ipc_port::ip_kobject` | `CNDKernelTaskBridge`, springboard doc §physical constraints 2; earlier kernel PAC panic recorded in iconservices doc | **Dead on arm64e** (missing destination-diversified kernel data PAC). The bridge correctly fails closed instead of panicking. |
| `thread->recover` boolean → arbitrary signed PC | REA: abort handler uses immutable `copyio_recover_table`, bounds+alignment checked | **Closed by design.** KRW cannot turn the boolean into a PC. |
| `thread_set_state` with kernel PC / EL1 mode via normal caller (`thread_state64_to_saved_state`) | `thread-state-signer-caller-observation.json` (VM, exact kernel): request preserved, saved state read back `0x00000000` | **Closed as kcall/EL1 route** — mode bits sanitized to EL0. Also corrects: kernel addr in an EL0 PC slot is signed data, not execution. |
| Syscall-return preparer as arbitrary signing oracle | REA `0xfffffe0008127df4`: only `ERESTART` branch signs, PC delta fixed `-4` | **Closed.** Legit trigger, uncontrollable. |
| Cross-task executable remap of a callback | iconservices doc: kernel PAC panic on forged remap attempt | **Closed for production** (the data-only IMP redirect replaced it — rightly). |

### Tried and won (keep, this is the current crown)

1. **Aperture data-page writability** (`hail-mary-data-page-experiment.md`):
   - `.33 __DATA_CONST` (maxProt `rw-`): `aperture-data-page-write-confirmed`, 2026-10-08.
   - `.34 dyldreadonly` (maxProt `r--`): **also confirmed writable** — the physical aperture does not honor `.34` maxProt. The identical-bytes probe before the semantic mutation is exactly the right way to earn each permission ticket per boot.
   - Semantic dispatch redirect (`CNDHailMaryImpRedirect`, `0x0be3f5c7 → 0x0be3ecba`, packed offsets, no PAC bits): applied, read back exact, translations stable, **visible transparent icons**. Packed dispatch entries dodge PAC entirely (26-bit selector + 38-bit class-relative IMP offset, no raw pointers). This is a genuine, physically proven, PAC-free code-execution-substitute for Apple-signed behavior redirects.
   - Note honestly: `XPF.output/macos/xpf_test` style claims aside, this is *semantic* redirect of Apple code, not attacker code execution. It cannot call `cs_allow_invalid`.
2. **PAC signing surface, fully mapped (REA)** — `rea-secure-execution-interface.md`:
   - SPTM endpoint 0 / table 0 selectors: `0x10` sign, `0x11` auth+strip, `0x28` batch. XNU stubs `pmap_sign_user_ptr` / `pmap_auth_user_ptr` / batch wrapper found, IA/DA keys 0/2, `ml_enable_user_jop_key` around the call. **Live-confirmed on VM** with synthetic pointers and explicit JOP keys.
   - EL1 saved-state signer chain: `ml_sign_thread_state` (`0xfffffe0007ab9344`), `ml_check_signed_state`, `exception_return` continuations, PACGA chain at saved-state `+0x128`, binds state address, PC, CPSR, LR, x16/x17. **Standalone signer canary passed live** (disambiguating tuple→signature changes). This is a callable VM oracle, explicitly *not* transferred to stock hardware.
   - Public converter path: `thread_convert_thread_state(...FROM_SELF...)` → `machine_thread_state_convert_from_user` (`0xfffffe0007c5e1a0`), pc/lr discriminators (`0x7481`), `thread + 0x1b0` JOP context (VM 23A341; your A17+ table says `0x1c0` — caught and gated via `CNDLabKernelPAC`, good catch, do not generalize).
   - **Cross-task + `EXCEPTION_STATE_IDENTITY` handoff closed on the VM**: child installs identity exception port, parent receives thread+task ports, converts, replies, child resumes at raw PC. `receive/convert/reply_kr=0`. Message 2407, flavor 6, 68 words validated.
3. **Physical `remote_pac`** (`TaskRop/PAC.m:96`): KRW-only — reads remote thread's ROP/JOP IDs, transplants them into a local PAC worker, runs an existing PACIA gadget. Correctly kept as fallback, correctly *not* conflated with the converter route (which avoids transplanting PAC context).
4. **Hail Mary read-only physical proof chain** (`CNDHailMaryProbe`): two-pmap page-table walks to one shared L3 frame, physical bytes + SHA guard, post-read revalidation. `confirmed-shared-physical-frame-and-bytes` on iPinky Max. This is a *prerequisite engine*, and it is excellent.
5. **CNDLabKernelPAC adapter**: `TaskRop/PAC.m` now prefers the pmap/SPTM adapter when lab KRW **and kcall** are active, fail-closed on profile rejection, physical path untouched.

### Tried, unresolved (the actual frontier)

- **Physical `EXCEPTION_STATE_IDENTITY` canary** (`CNDPhysicalPACIdentityCanary`, pinned to iPhone17,2/23A341, message 2407): implemented, Settings-wired, **no recorded physical result in docs/ or logs/**. Same for the **cross-task canary** (sacrificial fork child receiving the exception port via inherited bootstrap special port). These are the cheapest decisive physical experiments you own, and they answer the exact question the VM left open: does a stock (non-dev-enabled) boot deliver a usable identity thread right?
- **`PT_ATTACHEXC` / `cs_allow_invalid` physical RX probe** (`CNDPhysicalCSAllowInvalidProbe` + `scripts/lab/cnd_physical_cs_allow_invalid_probe.py`, "Run SpringBoard RX Probe" row): built, fail-closed, build-locked, prologue/branch-decode verified offline — **"built, not physically run"** per the springboard doc. Rank-0 escalation, deliberately first before any kernel call. Not run.
- **KRW handoff/portability** (launchd-held fileports, `persistence.m` recover-in-SpringBoard): VM negative (1100) was correctly judged *not* a production-path negative (root-SSH namespace, not launchd-issued tokens). Still unproved with exact tokens.
