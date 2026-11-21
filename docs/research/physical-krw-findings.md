# Physical-device KRW findings (23A341 / iPhone17,2) and VM transfer limits

Targets: physical **iPhone17,2** (iPhone 16 Pro Max), iOS 26.0 `23A341`, arm64e,
T8140, `xnu-12377.2.8~1/RELEASE_ARM64_T8140`. Research VM: **iPhone17,3 vPhone**,
iOS 26.0 `23A341`, `xnu-12377.42.6~55/RELEASE_ARM64_VRESEARCH1`. Primitive:
persistent darksword socket KRW. Goal ordering: **KRW → PAC-correct kernel
control flow → reliable kcall → SPTM-adjacent work.**

Evidence labels are not interchangeable: **implemented** ≠ **VM-proved** ≠
**physical-proved** (plus **physical-observed** for read-only device evidence and
**physical-negative** for a device failure). Nothing here upgrades a label.

**No kcall capability exists.** `kcall`/`kcall1` are probe tests, not a
primitive: the physical `kcall1` probe is unfinished and unsuccessful, and the
VM lab kernel call is VM-only behind its own capability bit. The "→ reliable
kcall" in the goal ordering above is a research target, not the current state.

## Summary: phone vs VM-only vs refused

| Capability / route | Physical phone | VM | Section |
|---|---|---|---|
| Socket KRW reads: kernel base/slide, MH_FILESET header, proc/ucred/label resolution, AMFI (`+0x8`) / sandbox (`+0x10`) slots | **Works** (physical-observed, 2026-10-17) | — | §1, §2 |
| Read-only walk of a process's AMFI object reaching real entitlement strings | **Works**, but walks truncated → donor verdict **open** | — | §2 |
| Socket KRW **write** of a MAC-label object (label-borrow transport) | **Refused**: EFAULT (errno 14), contents unchanged, twice | VM-proved (never transferable) | §1 |
| IOUserEthernet kcall route via label borrow | **Never starts** on this build/device | — | §1 |
| Lab provider `cnd_provide_tfp0` / syscall-439 kcall | **Forbidden and structurally impossible** | VM-only (panicked VM 2026-10-15) | §3 |
| VM label-lifetime UAF race | **Not proved anywhere**; 0 of 56 device panics match | VM-proved signature | §3 |
| RemoteCall dummy-thread mutex race fix | Panic **observed** on phone; fix implemented + build/test-proved, **not** exercised on device | not VM-proved | §4 |
| `EXCEPTION_STATE_IDENTITY` handoff | Canary wired, **unexecuted** (as of 2026-10-14) | VM-proved (convert/reply/resume; EL1 transfer closed) | §5.3 |
| IA/0x73d8 thread-call transplant to IA-zero target | — | VM-proved, `usedKernelCall=false` | §5.5 |
| `UPAsynchronousScheduler_` 4-arg `IA/0x61de` dispatch | — | static (VM fileset) only; priority experiment | §5.5 |
| SPTM selectors `0x10`/`0x11`/`0x28`, `pmap_sign/auth_user_ptr` | — | VM-proved only with provider kcall + JOP-key context change | §5.4 |
| AppleAVE2 / AppleJPEGDriver / AppleH16 camera / AGX | present in phone cache; AVE2 open NotPermitted | **absent** (paravirtual) | §5.1 |
| Forging `ip_kobject` from a stripped task pointer | **Closed** (destination-diversified data PAC) | — | §5.2 |

## 1. MAC-label borrow: VM-only, refused on the phone

Status: **observed on device, twice, on two independent probes.** A proof about
the write transport, not about the entitlement gate.

The IOUserEthernet kernel-call route needs `IOServiceOpen` of
`IOUserEthernetResource`, gated in `com.apple.iokit.IOUserEthernet` against the
**opening task** at user-client creation:

```
IOUserEthernetResourceUserClient::initWithTask(task, securityID, type, properties)
    [kext __TEXT_EXEC, static 0xfffffff00ac787b4]
      blraa  super::initWithTask
      add    x23, "com.apple.networking.ethernet.user-access"
                     [kext __TEXT, static 0xfffffff007966f36]
      bl     IOTaskHasEntitlement(task, entitlement)
      cbz    w0 -> "IOUE_UC:: %s entitlement missing"
                     [static 0xfffffff007966f60] and fail
```

The route borrows a donor's MAC label into the app's own `ucred` for the open,
then restores it. Both in-app probes (`CNDPhysicalIOUserEthernetSignerProbe`,
`CNDPhysicalKCall1Probe`) fail at the write of the donor label image into the
app's label object. `CNDPhysicalKCall1Probe.json` (2026-10-17, build 1.6 /
1005002, `com.zeroxjf.ios-cyanide1`):

| field | value |
|---|---|
| `result` | `refused-label-borrow` |
| `labelWriteAccepted` | `false` |
| `labelWriteErrno` | `14` (EFAULT) |
| `borrowInstalled` / `borrowRestored` | `false` / `true` |
| `labelBytesBeforeWrite` vs `labelBytesAfterWrite` | byte-identical |
| `labelChangedAfterWrite` | `false` |

Upstream of the write all verified on the same run: KRW ready and validated,
container base matched (`0xfffffff03d1f8000 - 0x00000000361f4000 =
0xfffffff007004000`), header `0xfeedfacf` / filetype `12` (MH_FILESET), self task
and both labels resolved, `0x8`/`0x10` policy-slot offsets confirmed by the app's
`amfi_cslot_get` / `label_get_sandbox` agreement. The CS allow-invalid probe
recorded the same refusal earlier
(`scripts/lab/cnd_physical_cs_allow_invalid_probe.m:1976-1978`: "the physical
socket writer returned EFAULT for the protected MAC-label object").

Interpretation:

- The label object is **readable** through socket KRW and **not writable**
  through it.
- The `VM_MIN/MAX_KERNEL_ADDRESS` override in `kexploit_opa334.m:3137-3138` is
  VM-only; the writer's own range gate admits the object and is not the cause.
- The borrow transport is **VM-only**; its VM-proved status never transferred,
  and the dependent chain never starts on this build/device.
- Not a statement that the entitlement gate can be bypassed some other way.

Phone path options: a different write transport for the label object; a
different object (e.g. swap the label **pointer** in `ucred`); run the open
inside an already-entitled process; or no borrow. Route table:
`docs/research/kcall1-phone-derivation-20261016/README.md`.

## 2. IOUserEthernet entitlement audit (read-only donor check)

Question: does `bluetoothd` carry `com.apple.networking.ethernet.user-access`?
Probe: `Cyanide/probes/CNDPhysicalEntitlementAuditProbe.{h,m}` (launch
`--entitlement-audit-probe` or Settings → Probes → "Audit IOUserEthernet
Entitlement"; output `CNDPhysicalEntitlementAuditProbe.json`). See also
`docs/research/entitlement-audit-*.md`.

Offline basis: the gate (§1) is in
`build/rea-secure-execution-23A341-iphone17,2/kernel-filesets-stock/com.apple.iokit.IOUserEthernet`;
`com.apple.security.sandbox` has a profile table naming `/usr/sbin/bluetoothd`
with `IOUserEthernetResourceUserClient` / `IOUserEthernetResource` (file offset
`0x192179`). The entitlement string is not in the kernelcache — it is per-process
code-signature data, so only a device read settles it.

Method: per candidate, `proc_find_by_name` → `proc_get_cred_label` → AMFI object
at `label + 0x8` → depth-first walk of reachable pointers for the string. Reads
only on the app's KRW (no writes, borrow, kcall, provider or root). Bounded reads;
followed pointers validated against `0xffffffdc00000000`–`0xfffffffbffffffff`;
both PAC strips tried; report carries `scanNodes`, `scanReads`, `scanTruncated`
and up to eight sample `com.apple.*` strings. A truncated walk is never reported
as "no entitlement".

Device results (three runs, `com.zeroxjf.ios-cyanide1` 1.6 (1005002)) —
**physical-observed**:

1. KRW/resolution: `krwInitiallyReady`/`krwValidated` true, `kernelBase
   0xfffffff03d1f8000`, `kernelSlide 0x361f4000`, `kernelBaseMatchesContainer`
   true, `0xfeedfacf`/`MH_FILESET`, `amfiSlotOffset 8`, `sandboxSlotOffset 16`.
   All five candidates resolved to distinct proc/label/amfiObject/sandboxObject,
   e.g. bluetoothd `proc 0xffffffdf02671660`, `label 0xffffffdce800c800`,
   `amfi 0xffffffde1b669350`.
2. Breadth-first scan truncated at 21 nodes/process with zero strings (worklist
   floods on metadata). Depth-first, never following a node's isa/class word,
   reaches genuine entitlements: bluetoothd `com.apple.bluetoothd0`,
   `com.apple.BTServer.avrcp`, `com.apple.BTServer.le`,
   `com.apple.BluetoothServices`; configd `com.apple.configd`,
   `com.apple.bluetooth.discovery`, `com.apple.server.bluetooth`; nehelper a full
   XML entitlements blob (e.g. `com.apple.networkextension.keychain`); symptomsd /
   wifid their own `com.apple.*` sets.
3. The last two runs still had `scanTruncated: true`. That build used 0x40-byte
   deep windows; current source uses **0x80** (a 37-char key at offset 0x38 must
   not straddle a window) with a **40000-read budget** per process.

**Verdict to date:** `com.apple.networking.ethernet.user-access` **not observed**
in bluetoothd's AMFI object, but **not decisive** — no untruncated walk yet.
Decisive once every candidate reports `scanTruncated: false`:
`donorHasEntitlement: true` → borrow premise right, only the write transport is
missing; `false` untruncated → bluetoothd is not a usable donor on this build;
pick from `processesWithEntitlement`, or treat the sandbox profile table as an
allow-list rather than an entitlement grant.

## 3. 2026-10-15 VM lab-provider panic: what may move to the phone

**Decision:** the flow that panicked the VM (`scripts/lab/cnd_provide_tfp0.c`
driven by `scripts/lab/cnd_vphone_krw.py`) must **not** be built or run on the
iPhone. Only read-only observation of the phone's existing panic reports is
permitted, and that is what was implemented.

Blocking rules: `docs/research/vm-guide.md:155-157` ("Never broaden the VM
syscall-439 backend into a physical-device claim…"), `vm-guide.md:153-154`
("Never infer kcall from tfp0/KRW alone"), `Cyanide/kexploit/CNDLabKernelProvider.h:9`
("VM-only provider"), `:37-39` (target must lie in the validated kernel image,
≤8 integer args, physical KRW never routes through this API).

Structural reasons (implemented, source reading):
`scripts/lab/cnd_remotecall_lab.py:212-225` `require_vphone` refuses any SSH
target that is not a `VPHONE`/`VRESEARCH` guest and `cnd_vphone_krw.py` calls it
before every live action; `cnd_provide_tfp0.c:834-847` gets the kernel task from
host special port 4 or `task_for_pid(0)`, `:326-335` loads `/var/jb` libkrw
plugins, `:76-77` uses VRESEARCH-only syscall 439 — none exist on the
non-jailbroken iPhone17,2. Kernels differ (VRESEARCH1 vs T8140, see
`scripts/lab/cnd_physical_cs_allow_invalid_probe.py:183`), so "same behaviour"
could not transfer anyway.

Implemented read-only subset: `scripts/lab/cnd_physical_panic_signature_probe.py`,
tests `scripts/tests/test_physical_panic_signature_probe.py` (17 tests, passing).
`classify FILE...` checks `.ips` reports against the pinned VM signature
(`Kernel data abort`, GZAlloc zone `MAC Labels`, `use-after-free`, esr
`0x9600004f`, copy length `0x18`, process prefix `cnd-provide-tfp0-`).
`device-inventory [--copy]` verifies the exact pinned iPhone17,2 / 23A341
CoreDevice ID (refusing the VM), then only uses the `systemCrashLogs` inventory
and copy flows from `docs/physical-device-logs.md:181-238`; never installs,
launches, signs, reads, writes or calls (recorded `false` in the JSON). Test
guard pins: the probe never imports/invokes the VM harness, and the harness still
gates on `require_vphone`.

Results:

- **VM-proved:** reference report matches the signature; pid 591 is the lab
  provider; the four triage validation-route offsets resolve (relative to kernel
  text base) to addresses absent from the backtrace.
- **Physical-observed (complete, 56 of 56 `panic-full`, 2026-09-18 → 2026-10-12):**
  none matches. All 56 on T8140; 48 `Unexpected fault in kernel physical
  aperture` in `Cyanide` (the device's own KRW path); 2 PAC failures in
  `Cyanide`; 1 `MAC Labels` zone **bounds-check** panic in `Cyanide` (different
  class from the VM UAF); the only two GZAlloc records are in `kernel_task`
  against `proc_task` and `kalloc.type8.224`. Evidence:
  `build/physical-panic-signature-20261015-223315/panic-signature-report.json`
  (`complete: true`, `copyFailures: {}`, every `*Used`/`*Anything` flag false).
- **Not proved anywhere:** whether the VM label-lifetime race exists on the
  phone. Absence of a matching panic is not proof of absence.

Requests for the provider owner: a read-only in-app canary modelled on
`Cyanide/probes/CNDPhysicalPACIdentityCanary.m` (`kernelReadUsed: YES`,
`kernelWriteUsed: NO`, `kernelCallUsed: NO`) is the only rule-compatible way to
observe label lifetime on the phone (needs a new `.m` producer and
`SettingsViewController.m` wiring). No change requested to
`CNDLabKernelProvider.m/.h`.

## 4. RemoteCall dummy-thread mutex panic (2026-11-02)

Evidence: **implemented** in `Cyanide/TaskRop/RemoteCall.m`; focused suites pass
(kexploit_reliability 27, krw_socket_parking 20, iconservices_publisher_transport
45, physical_springboard_pac_probe 7, remotecall_mutex_safety 3); fresh signed
arm64/arm64e device build succeeded. **Not VM-proved. Not physical-proved** — the
panic was observed on the phone; the fix has not been exercised on device.

Panic `/tmp/cyanide-ipinky-latest/panic-full-2026-11-02-004838.0002.ips`:

```
panic(cpu 2 caller 0xfffffff04982a97c): Mutex 0xffffffe0aa89de48 is unexpectedly
not owned by thread 0xffffffe0aab1e1c0 @lock_mtx.c:172
Darwin Kernel Version 25.0.0 ... root:xnu-12377.2.8~1/RELEASE_ARM64_T8140
Panicked task ... pid 576: Cyanide
```

Backtrace runs through `thread_set_exception_ports` and ends at a userspace
`pthread_exit` — the RemoteCall **helper thread**. Intermittent (same binary ran
the bootstrap many times first): a race.

Root cause (checked against xnu-12377.1.9 `osfmk/kern/lock_mtx.h` / `lock_mtx.c`,
same family as 12377.2.8): `lck_mtx.data` holds the owner ctid in the low 28 bits
(`LCK_MTX_CTID_MASK = 0x0fffffff`), bit 30 is `LCK_MTX_NEEDS_WAKEUP = 0x40000000`;
no separate LOCKED bit — owner 0 = free, every acquire needs owner 0.
`lck_mtx_unlock` fast path CASes `thread->ctid → 0`; on mismatch the slow path
panics (`__lck_mtx_not_owned_panic`, line ~172). `thread_set_exception_ports`
(MIG, `osfmk/kern/ipc_tt.c`) → `thread_set_exception_ports_internal` does
`thread_mtx_lock/unlock` on the **target** thread's mutex — the dummy's
(`off_thread_mutex_lck_mtx_data`).

`set_exception_port_on_thread` bootstrap: (1) forge
`thread_set_mutex(g_RC_dummyThreadAddr, g_RC_selfThreadCtid)` so the resumed
helper parks in `lck_mtx_lock`, keeping its kernel stack and the `dummyThreadTro`
MIG-frame needle stable; (2) resume helper → `thread_mtx_lock(dummy)` parks;
(3) bootstrap loop swaps the tro on the helper's stack; (4) old code
**unconditionally** wrote `0x40000000`. If the helper had already acquired
(word = helper ctid), step 4 zeroed the owner and the helper's unlock panicked.
Usually the write lands while the helper is still parked, hence intermittency.

Fix (both writes gated on current owner):

- **Forge** only when `(word & 0x0fffffff) == 0`; otherwise abort this helper
  setup before resume (a stale forge owned by us is cleared by the guarded
  release; any other owner left alone); caller retries the next candidate thread.
- **Release** via new `release_forged_dummy_mutex(why)` (after the helper loop
  and on the resume-failure path): write `LCK_MTX_NEEDS_WAKEUP` only when
  `(word & 0x0fffffff) == g_RC_selfThreadCtid`. Race-free: while we own it, no
  acquire can succeed. If the helper owns it, skip; its own unlock restores 0
  with proper turnstile wakeup.
- The resume-failure early return previously leaked the forged owner (a later
  `thread_mtx_lock(dummy)` would hit `__lck_mtx_owned_panic`, "unexpectedly
  **owned**"); it now releases too.
- Constants `CND_LCK_MTX_CTID_MASK` / `CND_LCK_MTX_NEEDS_WAKEUP` sit next to the
  `g_RC_*` macros with the xnu citation.

Unchanged: the parking mechanism itself, MIG-filter-bypass `usleep`s, the retry
loop, and teardown (`destroy_remote_call_internal`,
`abandon_remote_call_internal` never wrote the word).

Open: re-run the SnowBoard apply path on the phone (and the 23A341 VM) across
repeated bootstraps; until then implemented + build/test-proved only. The
separate 00:40 APFS/physical-aperture panic remains unattributed.

## 5. Bug-class transfer map: KRW → PAC-correct control flow (2026-10-14)

A transfer study, not a claim that any historical CVE is unpatched; a surviving
component means its design is worth comparing, not that its bug survives.
Grades: **A** = class alive on 23A341, reachable with current primitive, concrete
next experiment; **B** = alive but needs a new entry vector or prerequisite
primitive; **C** = historical only.

| Class | Precedents | 23A341 status | Grade | Next experiment |
|---|---|---|---|---|
| IOKit user-client memory corruption | AppleAVE2 `CVE-2019-8795`, IOAcceleratorFamily2 `CVE-2016-1819`, AppleJPEGDriver `CVE-2020-9768`; AppleH10/H13 camera OOB write (no CVE located) | Phone cache has AppleAVE2, AppleJPEGDriver, IOGPUFamily, IOSurface, AppleH16CameraInterface; VM has paravirtual graphics, no AVE/camera/JPEG | **B** | Don't hunt a replacement KRW; if revisited, inventory physical open/entitlement gates before selector work |
| Mach port / IPC / socket lifetime | `CVE-2016-7644` mach_portal, `CVE-2019-6225` voucher_swap, `CVE-2019-8605` SockPuppet | Subsystems survive; typed allocation, data PAC, object validation kill old fake-port recipes; socket surface already gives KRW | **B** | Only IPC fields that can carry already-authenticated values; don't re-prove KRW |
| Kernel stack / thread state | Fugu14 (`CVE-2021-30740`, `-30768`, `-30769`, `-30770`, `-30773`), badRecovery `CVE-2022-26765`, exception-delivery exploitation | Signer, converter, identity-exception, exception-return semantics survive; Fugu14 EL1 transfer closed by CPSR/EL0 sanitization; physical identity handoff unexecuted | **A** | Run the wired physical `EXCEPTION_STATE_IDENTITY` canary, keep raw result |
| PPL/SPTM boundary data | tlbFail `CVE-2022-26764`, Operation Triangulation `CVE-2023-38606`, Sparrow/Rocket/Titan | SPTM active; cache has XNU→SPTM signing and pmap gates; public paths patched or SoC/version-bound; all need kcall or coprocessor primitive | **B** | After kcall, one benign SPTM gate read-only/round-trip test |
| Signing / authenticated dispatch | voucher_swap PAC signer, Fugu14 state signer, badRecovery, Sparrow signer | **Alive.** REA/Ghidra: 4-arg `IA/0x61de` scheduler and `IA/0x61de → IA-zero` bridge in IOMobileGraphicsFamily; separate two-stage signed-pointer transplant reached chosen IA-zero target in VM without provider kcall | **A** | Resolve one live `UPAsynchronousScheduler_` and run a reversible breakpoint-observed 4-arg dispatch canary |

### Artifact inventory (do not conflate)

- Physical kernel: `build/HailMaryKernel23A341/23A341__iPhone17,2/kernelcache.release.iPhone17,2`,
  SHA-256 `7e66ddbb70b626c4502c3036620b59829b744c54712a74ca50f4a0c004c89f8c`,
  `Darwin 25.0.0`, `xnu-12377.2.8~1/RELEASE_ARM64_T8140`. `ipsw kernel kexts`:
  `com.apple.AGXG17P` 340.24.3, `com.apple.driver.AppleAVE2` 904.76.7,
  `com.apple.driver.AppleH16CameraInterface` 4.31,
  `com.apple.driver.AppleJPEGDriver` 7.7.2, `com.apple.iokit.IOGPUFamily` 128.3,
  `com.apple.iokit.IOMobileGraphicsFamily` 343.0.0, `com.apple.iokit.IOSurface` 392.5.
- VM XNU fileset: `build/rea-secure-execution-23A341-iphone17,3/kernel-filesets/com.apple.kernel`,
  SHA-256 `c32c7005fd8f702bf7f34730a512af5cb896a8c61b4a80b8400401f3897060ea`;
  contains `AppleParavirtGPUIOGPUFamily`, `AppleParavirtIOSurface`, IOGPUFamily,
  IOMobileGraphicsFamily, IOSurface — not AppleAVE2, AppleH16 camera, or
  AppleJPEGDriver.
- Consequence: the VM is right for XNU, SPTM-call-gate, PAC and IOMobileGraphics
  semantics; not representative for camera, AVE, JPEG or AGX user-client triggers.

### 5.1 IOKit user-client UAF / type confusion — Grade B

Precedent shapes:
- AppleAVE2 `CVE-2019-8795` (08Tc3wBB): unchecked selector-controlled indices/lengths
  in session data → controlled virtual call or arbitrary `kfree`
  ([Jamf](https://www.jamf.com/blog/running-code-in-the-context-of-ios-kernel-part-i-lpe-poc-on-ios-137/),
  [P0 survey](https://projectzero.google/2020/06/a-survey-of-recent-ios-kernel-exploits.html)).
- AppleAVE2 `CVE-2020-9907` (Proteas/Qihoo 360): raced userspace-visible pointer
  slot during IOSurface-backed state setup → temporary KRW
  ([HITB Mag 011](https://magazine.hitb.org/wp-content/uploads/2021/05/HITBMag-Issue-011.pdf)).
- `CVE-2020-3865` is **not** AppleAVE — WebKit page loading per
  [iOS 13.3.1 notes](https://support.apple.com/en-sa/103218); never use as an AVE precedent.
- IOAcceleratorFamily2 `CVE-2016-1819` (Ian Beer): `IOAccelContext2::clientMemoryForType`
  busy lock didn't cover shared-memory setup → race UAF
  ([P0 issue](https://project-zero.issues.chromium.org/issues/42452300/dupes)).
- AGX in-the-wild iOS 10 (no CVE in analysis): `AGXAllocationList2::initWithSharedResourceList`
  sized for 6 subentries, structure allowed 7 → OOB write of `IOAccelResource`
  pointers, reachable from WebContent, reclaimed `uio`/IOSurface
  ([P0 chain 1](https://projectzero.google/2019/08/in-wild-ios-exploit-chain-1.html)).
- AppleJPEGDriver `CVE-2020-9768` (@_simo36): raw notification-port address kept
  in async decode request after port release → port UAF from app container
  ([trigger](https://gist.github.com/0x36/3c9e77058eac7069616b72f0088d8b6d),
  [Proteas](https://proteas.github.io/ios/vulnerability/2020/03/27/analysis-of-CVE-2020-9768.html)).
- AppleH10/H13 camera (binaryboy, no CVE located): selector 86 unchecked
  index/address/length → OOB write/swap in Jasper clocking
  ([writeup](https://github.com/b1n4r1b01/n-days/blob/main/AppleH10CamIn-OOBw/AppleH10CamIn-OOBw-Writeup.md));
  required `com.apple.camera.iokit-user-access`
  ([Saar Amar](https://saaramar.github.io/iOS_memory_exhaustion_writeup/)).

Transfer: IOAcceleratorFamily2 → IOGPUFamily in iOS 14
([Tachy0n](https://blog.siguza.net/tachy0n/)); iPhone17,2 has AppleH16, not H13
(successor, not evidence the bug transferred); AVE2/JPEG absent from vPhone;
typed allocation makes UAF replacement far less portable and arbitrary `kfree`
zone-checked ([Apple SockPuppet-on-iOS-16](https://security.apple.com/blog/what-if-we-had-sockpuppet-in-ios16/)).
These need a fresh defect and mostly reproduce KRW we already have; they don't
shorten KRW → kcall. If revisited: physical read-only service/open matrix for the
four confirmed services recording `kern_return_t`, user-client class and
entitlement denial, stopping before selectors; record as `implemented` or
`physical-proved` in a new exact-build JSON, never as VM evidence. (Later
observation: AppleAVE2 direct open is NotPermitted on every type — see
`ave2-cve-2026-112705.md`.)

### 5.2 Mach port / IPC / socket lifetime — Grade B

Precedents: mach_portal `CVE-2016-7644` (racing `set_dp_control_port()`
over-release → OOL-port overlap, host port via `mach_port_get_context`, kernel
task port); voucher_swap `CVE-2019-6225` (Qixun Zhao, Brandon Azad, Ben Sparkes:
`task_swap_mach_voucher()` MIG refcount bug → dangling `thread->ith_voucher` →
fake port/task port) — both in the
[P0 survey](https://projectzero.google/2020/06/a-survey-of-recent-ios-kernel-exploits.html);
SockPuppet `CVE-2019-8605` (Ned Williamson: `in6_pcbdetach()` freed
`in6p_outputopts` without clearing → stale `ip6_pktopts` via
`getsockopt`/`setsockopt`) ([walkthrough](https://projectzero.google/2019/12/sockpuppet-walkthrough-of-kernel.html)).

Transfer: Cyanide's KRW already lives on an ICMPv6/socket-parking surface — not
evidence SockPuppet or a sibling is open. `kalloc_type`, data submap,
zone-checked frees, immovable ports and data PAC invalidated the "free port,
reclaim with OSData/OOL ports, forge `ipc_port`" recipe. Titan's README says its
Coruna-derived `ipc_port->ip_nsrequest` stealing primitive was patched in iOS 26
by data PAC ([Titan](https://github.com/alfiecg24/Titan)) — a warning, not proof
about every IPC field in 23A341. Only justified task: classify writable IPC
fields by authentication schema and look for legitimate consumers of
already-signed values. Forging `ip_kobject` from a stripped task pointer is
**already physically closed** by destination-diversified data PAC.

### 5.3 Kernel stack / exception delivery / thread state — Grade A

Precedents: Beer's exception-oriented exploitation (`EXCEPTION_STATE` port,
corrupted preallocated message size → repeated R/W;
[P0](https://projectzero.google/2017/04/exception-oriented-exploitation-on-ios.html));
Fugu14 bundle (Linus Henze; no per-stage CVE): `thread_state64_to_saved_state()`
left privileged CPSR mode bits, kernel signed a state later resumed in kernel
mode ([writeup](https://raw.githubusercontent.com/LinusHenze/Fugu14/master/Writeup.pdf),
[README](https://github.com/LinusHenze/Fugu14/blob/master/README.md)); badRecovery
`CVE-2022-26765`: recovery handler in `hw_lck_ticket_reserve_orig_allow_invalid`
ended in plain `ret`; Fugu15 then used a sign-and-branch on `x22`
([slides](https://objectivebythesea.org/v5/talks/OBTS_v5_lHenze.pdf)); Sparrow/Rocket
(2026, no CVE mapping): reclaimed thread object + retained send right → raced
`thread_set_state` → exception return as authenticated kcall and
PACIA/PACDA/PACGA service ([reconstruction](https://nvme0n1p.dev/en/posts/sparrow-wp)).

Exact 23A341 VM: `ml_sign_thread_state`, `ml_check_signed_state`, the
thread-state converters, identity exception delivery and exception-return
continuations exist. REA + VM canary established the signing tuple (state
address, PC, CPSR, LR, x16, x17 → PACGA chain). VM cross-task
`EXCEPTION_STATE_IDENTITY` handoff received thread and task rights, converted
state, replied, and resumed (**VM-proved**). Privileged-mode transfer does **not**
survive: exact-build VM test showed `thread_state64_to_saved_state` sanitizes to
EL0; `thread->recover` is table/bounds constrained — don't copy Fugu14 or
badRecovery literally. Open: does stock physical 23A341 deliver a usable identity
thread right and accept the same convert/reply without VM/provider behaviour?
Live class: "kernel legitimately signs and moves thread state across an
exception boundary", not "set EL1 CPSR again".

A-grade experiment:
1. On the unlocked phone, run Settings' existing `CNDPhysicalPACIdentityCanary`
   row; no VM/provider kcall path.
2. Capture the raw report before relaunch. Require exact product, build,
   exception message ID 2407, flavor 6, state count 68, receive/convert/reply
   results, child resume marker.
3. A pass proves only that stock physical exception delivery supplies a usable
   identity right and the converter/reply transport works — not EL1, PAC bypass,
   or kcall.
4. Preserve the untouched report at
   `docs/research/physical-pac-identity-23A341-iphone17,2.json` labelled
   **physical-proved**; a failure keeps its exact `kern_return_t` and stage and is
   **physical-negative**, not generalized from VM.

### 5.4 PPL/SPTM boundary data — Grade B

Precedents: P0 PPL TLB bug (two mappings removed, one TLB entry invalidated;
[P0](https://projectzero.google/2020/07/the-core-of-apple-is-ppl-breaking-xnu.html));
tlbFail `CVE-2022-26764` (nested shared-cache page deleted via non-nested pmap
without flushing every ASID → stale TLB alias onto recycled page table; Fugu15
slides pp. 45-59); Operation Triangulation `CVE-2023-38606` (after
`CVE-2023-32434` physical access, undocumented GPU-adjacent MMIO with
destination/data/hash wrote PPL-protected memory;
[Kaspersky](https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/));
Sparrow (`pmap_iommu_ioctl_internal()` validated UAT state and marked a page
`PP_ATTR_NO_MONITOR` while concurrent `UAT_PPL_IOCTL_TASK_DIED` recycled it —
gate-crossing state-object UAF); Titan (AGX power-thread state overwrite →
coprocessor ROP, hibernation-restored `TTBR1_EL1` + stack → AGX writes AP page
table; thread-state primitive patched by AGX instruction PAC in iOS 18.1 b4,
hibernation bug in 17.4 b4).

Transferable data shapes: page-table mutation request + pmap ownership/type
metadata; validated state object whose identity/lifetime changes after
validation; physical page temporarily classified as ordinary output; IOMMU/UAT
root or descriptor accepted by the protected side; coprocessor register state
(`PC`, `LR`, `CPSR`, stack, TTBRs) restored from writable memory; signing request
carrying pointer, key class, discriminator/context and result destination. Apple:
SPTM/TXM protect page tables even after kernel write/CFI bypass
([platform security guide](https://support.apple.com/en-ca/guide/security/sec8b776536b/web)).

Local 23A341: REA mapped XNU stubs for `pmap_sign_user_ptr`, `pmap_auth_user_ptr`,
batch signing, and SPTM dispatcher selectors `0x10`, `0x11`, `0x28` —
**VM-proved only when the lab provider already supplied kcall and changed
JOP-key context; they do not create kcall.** VM paravirtual GPU is not a testbed
for Titan's AGX path. No public iOS-26/T8140 transfer; every promising endpoint
consumes authenticated control flow — kcall is the prerequisite. First post-kcall
experiment: one exact-build sign/auth selector on a synthetic noncanonical
pointer, auth/strip through the paired selector, verify no page ownership or
mapping change; record request/return tuples, key-context setup, cleanup as
**VM-proved** first. Proves gate reachability and ABI, not an SPTM bypass.

### 5.5 Signing gadgets / authenticated dispatch — Grade A

Scanner signatures (semantics, not addresses):

| Precedent | Signature | Transfer note |
|---|---|---|
| voucher_swap PAC bypass / `sysctl_unregister_oid` (Azad) | `AUTIA` with address-blended context → `PACIZA` even on auth failure → store IA-zero | Apple now compares auth vs stripped and selects the invalid result; still the canonical auth-and-resign shape ([P0](https://projectzero.google/2019/02/examining-pointer-authentication-on.html)) |
| state-signing gadget (Azad) | thread init reads PC/LR/CPSR (later x16/x17) from writable saved state in a race window, calls `sign_thread_state`, stores GA signature bound to state address | look for memory-fed tuple + race window + observable signature ([BH USA 2020](https://bazad.github.io/presentations/BlackHat-USA-2020-iOS_Kernel_PAC_One_Year_Later.pdf)) |
| Fugu14 state conversion | user saved state copied into exception frame, mode bits incompletely normalized, signed, resumed | 23A341 normalizes EL0 — scans must include sanitization |
| badRecovery `CVE-2022-26765` | signed `thread->recover`, controlled fault, recovery hits plain `ret`, then sign-and-branch to chosen register | scan recovery handlers for unauthenticated exits; iOS 15 path historical |
| Sparrow/Rocket thread signer | reclaimed RPC-addressable thread object; exception return executes PACIA/PACDA/PACGA into shared memory; repeatable call carrier | closest public match; published support ends before 23A341 |
| Local IOMobileGraphics scheduler | auth input with kernel IA, discriminator `0x61de`; re-sign IA-zero; queue fixed `0x61de` adapter; worker loads 4 args, `BLRAA target,0x61de`; adapter does IA-zero call | exact-build static match; translates a **valid** `0x61de` pointer, not yet an arbitrary raw-pointer signer |

Definitions: signing gadget = legitimately invokable code with attacker-influenced
signing inputs and an observable result
([P0 remote iPhone pt 3](https://projectzero.google/2020/01/remote-iphone-exploitation-part-3.html?m=1);
[USENIX Sec 2023](https://www.usenix.org/system/files/usenixsecurity23-cai-zechao.pdf)
separates function-level shared interfaces from instruction-level gadgets).
`rootlessJB3` is **not** a kernel PAC-signing precedent (A7–A11, A12 future work;
[repo](https://github.com/jakeajames/rootlessJB3)); state the idea generically as
"reuse a legitimate kernel signer".

**VM-proved constrained authenticated dispatch:**
`thread-call-pac-reuse-dispatch-observation.json` — existing signed `IA/0x73d8`
adapter + existing IA-zero target transplanted into a live thread-call object; KDP
hardware breakpoint observed the target with `x0 = 0x434e445041435830`; all fields
restored, timer destroyed, `usedKernelCall=false`. Target was a fixed safe
early-return function, not arbitrary kcall.

Ghidra, exact VM IOMobileGraphicsFamily (**unslid iPhone17,3 VM addresses — never
copy into the physical profile**):
- `UPAsynchronousScheduler_::startThreadWithAction` `0xfffffe0008f70254` queues a
  native 4-arg `IA/0x61de` action.
- Synchronous wrapper `0xfffffe0008f702bc` auths incoming `IA/0x61de`, applies
  `PACIZA`, queues fixed signed adapter `0xfffffe0008f70d48`.
- Common queue routine `0xfffffe0008f7002c`; entry: action `+0x8`, flags `+0x11`,
  marker `+0x12`, args `+0x18/+0x20/+0x28/+0x30`.
- Worker `0xfffffe0008f7073c` loads 4 args, `x17=0x61de`, `blraa x8,x17`.
- `setDefaultAction` `0xfffffe0008f6ff24` (locked plain store); `prepareThread`
  `0xfffffe0008f6ffbc` (dormant entry); `notifyThread` `0xfffffe0008f7046c`
  (args + wake).

Missing: the live owning object and a harmless valid `IA/0x61de` target
harvestable without provider kcall.

A-grade experiment:
1. Ghidra: finish only constructor/owner xrefs for `UPAsynchronousScheduler_`;
   find the containing service and outer-object→scheduler offset. No kernel-wide scan.
2. Boot the exact 23A341 VM with KDP, syscall-439/provider kcall disabled. Locate
   one live scheduler from its owner; read workloop, interrupt source, queue head,
   default action, lock-adjacent state. Reject unless every pointer is in the
   expected fileset or zone range.
3. `prepareThread` a dormant entry; snapshot entry + owner; transplant only a
   previously observed valid `IA/0x61de` action with read-only/early-return
   callee plus four recognizable canary args.
4. One-shot hardware breakpoint at the stripped callee, `notifyThread`, require
   x0–x3 exactly. Queue changes or no panic are not success.
5. Restore action/default/entry, drain queue, prove byte-for-byte owner
   restoration; abort cleanup on any mismatch rather than freeing guessed objects.
6. Record original/modified/triggered/observed/restored state in
   `build/rea-secure-execution-23A341-iphone17,3/upa-scheduler-61de-canary.json`
   as **VM-proved**, with `usedKernelCall=false`, `usedKernelWrite=true`.

Success = no-provider, PAC-correct, 4-arg **constrained call carrier**, not
arbitrary kcall; arbitrary targets still need a `0x61de` signer, a rich corpus of
already-signed `0x61de` actions, or a second authenticated translation with a
satisfiable input schema.

### Priority (as of 2026-10-14)

Highest leverage: the **`UPAsynchronousScheduler_` live 4-arg `0x61de` canary** —
beats another UAF hunt (KRW exists), the physical identity canary (it tests the
exact missing KRW→control-flow boundary), and SPTM (endpoints consume kcall).
Static work already established dispatcher, arg layout, discriminator,
translator, prepare/notify paths and cleanup-relevant fields. The physical
identity canary is cheap and implemented and should still run in parallel, but
must not delay the VM scheduler canary; only the scheduler result directly
advances no-provider kcall.
