# Bug-class transfer map: KRW to PAC-correct control flow on 23A341

Date: 2026-10-14<br>
Physical target: iPhone17,2 (iPhone 16 Pro Max), iOS 26.0 `23A341`, arm64e, T8140<br>
Research VM: iPhone17,3 vPhone, iOS 26.0 `23A341`<br>
Current primitive: persistent darksword kernel read/write (KRW)<br>
Goal ordering: **KRW -> PAC-correct kernel control flow -> reliable kcall -> SPTM-adjacent work**

This document is a transfer study, not a claim that any historical CVE remains
unpatched. A component surviving in a cache means that its design is worth
comparing; it does not mean that its old bug survives. Grades mean:

- **A**: the semantic bug/exploitation class is alive on 23A341, is reachable
  with the current primitive, and has a concrete next experiment.
- **B**: the class or component is alive, but using it needs a new entry vector
  or a prerequisite primitive.
- **C**: historically useful for understanding the design, but not a sensible
  current route.

Evidence status is always stated as **implemented**, **VM-proved**, or
**physical-proved**. Those labels are not interchangeable; see
[`glm-review/00-header.md`](../glm-review/00-header.md).

## Summary

| Class | Named precedents | 23A341 status | Grade | Next experiment |
| --- | --- | --- | --- | --- |
| IOKit user-client memory corruption | AppleAVE2 `CVE-2019-8795`, IOAcceleratorFamily2 `CVE-2016-1819`, AppleJPEGDriver `CVE-2020-9768`; AppleH10/H13 camera OOB write (no assigned CVE located) | Physical cache contains AppleAVE2, AppleJPEGDriver, IOGPUFamily, IOSurface, and AppleH16CameraInterface. The VM substitutes paravirtual graphics and omits the physical AVE/camera/JPEG drivers. | **B** | Do not hunt a replacement KRW. If revisited, inventory physical-device open/entitlement gates before any selector work. |
| Mach port / IPC / socket lifetime | `CVE-2016-7644` mach_portal, `CVE-2019-6225` voucher_swap, `CVE-2019-8605` SockPuppet | The subsystems survive, but typed allocation, data PAC, and object-validation changes invalidate the old fake-port recipes. Our socket surface already supplies KRW, so another entry bug adds little. | **B** | Restrict follow-up to IPC fields that can carry already-authenticated values; do not re-prove KRW. |
| Kernel stack / thread state | Fugu14 CVE bundle (`CVE-2021-30740`, `-30768`, `-30769`, `-30770`, `-30773`), badRecovery `CVE-2022-26765`, exception-delivery exploitation | The signer, converter, identity-exception, and exception-return semantics survive. The old Fugu14 EL1-mode transfer is closed on 23A341 by CPSR/EL0 sanitization, but the physical identity handoff remains unexecuted. | **A** | Run the already-wired physical `EXCEPTION_STATE_IDENTITY` canary and preserve the raw result. |
| PPL/SPTM boundary data | tlbFail `CVE-2022-26764`, Operation Triangulation `CVE-2023-38606`, Sparrow/Rocket/Titan | SPTM is active and the local cache contains XNU-to-SPTM signing and pmap gates. Public older paths are patched or SoC/version-bound, and every practical path needs authenticated kcall or an equivalent coprocessor primitive first. | **B** | After kcall, test one benign SPTM gate with a read-only/round-trip invariant; do not lead with an SPTM bypass hunt. |
| Signing and authenticated-dispatch gadgets | voucher_swap PAC signer, Fugu14 state signer, badRecovery `CVE-2022-26765`, Sparrow signer service | **Alive and directly relevant.** REA/Ghidra found a four-argument `IA/0x61de` scheduler and an `IA/0x61de -> IA-zero` authenticated bridge in IOMobileGraphicsFamily. A separate two-stage signed-pointer transplant has already reached a chosen IA-zero target in the VM without provider kcall. | **A** | Resolve one live `UPAsynchronousScheduler_` object and execute a reversible, breakpoint-observed four-argument dispatch canary. |

## Artifact and target inventory

The physical and virtual targets must not be conflated:

- The physical kernel is
  `build/HailMaryKernel23A341/23A341__iPhone17,2/kernelcache.release.iPhone17,2`,
  SHA-256
  `7e66ddbb70b626c4502c3036620b59829b744c54712a74ca50f4a0c004c89f8c`,
  `Darwin 25.0.0`, `xnu-12377.2.8~1/RELEASE_ARM64_T8140`.
- `ipsw kernel kexts` on that image confirms:
  `com.apple.AGXG17P` 340.24.3, `com.apple.driver.AppleAVE2` 904.76.7,
  `com.apple.driver.AppleH16CameraInterface` 4.31,
  `com.apple.driver.AppleJPEGDriver` 7.7.2,
  `com.apple.iokit.IOGPUFamily` 128.3,
  `com.apple.iokit.IOMobileGraphicsFamily` 343.0.0, and
  `com.apple.iokit.IOSurface` 392.5.
- The exact VM XNU fileset is
  `build/rea-secure-execution-23A341-iphone17,3/kernel-filesets/com.apple.kernel`,
  SHA-256
  `c32c7005fd8f702bf7f34730a512af5cb896a8c61b4a80b8400401f3897060ea`.
  Its extracted filesets contain `AppleParavirtGPUIOGPUFamily`,
  `AppleParavirtIOSurface`, IOGPUFamily, IOMobileGraphicsFamily, and IOSurface,
  but not the physical AppleAVE2, AppleH16 camera, or AppleJPEGDriver entries.

Consequence: the VM is the right place for XNU, SPTM-call-gate, PAC, and
IOMobileGraphics semantic experiments. It is not representative for a physical
camera, AVE, JPEG, or AGX user-client trigger.

## 1. IOKit user-client UAF and type-confusion class

### Named precedents and exact shapes

**AppleAVE2 — `CVE-2019-8795`, 08Tc3wBB.** The AppleAVE2 user client processed
out-of-bounds session data because selector-controlled indices and lengths were
not adequately checked. The resulting object access could be steered into a
controlled virtual call or arbitrary `kfree`, while companion disclosures and
the AppleAVE sandbox escape completed the published chain. The clearest public
accounts are [Jamf's AppleAVE2 analysis and PoC](https://www.jamf.com/blog/running-code-in-the-context-of-ios-kernel-part-i-lpe-poc-on-ios-137/)
and Project Zero's [public exploit survey](https://projectzero.google/2020/06/a-survey-of-recent-ios-kernel-exploits.html).

**AppleAVE2 — `CVE-2020-9907`, Proteas/Qihoo 360 work.** The encoder path used
a userspace-visible pointer slot while constructing and mapping IOSurface-backed
state; racing the slot let a later load observe an attacker-changed pointer and
turn field copies into temporary kernel read/write. The published treatment is
the [HITB Magazine AppleAVE2 writeup](https://magazine.hitb.org/wp-content/uploads/2021/05/HITBMag-Issue-011.pdf).

The prompt's example `CVE-2020-3865` is not an AppleAVE vulnerability. Apple's
[iOS 13.3.1 security notes](https://support.apple.com/en-sa/103218) identify it
as a WebKit page-loading issue; it must not be used as an AppleAVE precedent.

**IOAcceleratorFamily2 — `CVE-2016-1819`, Ian Beer.** In
`IOAccelContext2::clientMemoryForType`, the busy lock did not cover the full
shared-memory setup. One thread could release raw pages after leaving the lock
while a second thread still used the raw page pointer, producing a race-driven
UAF. See the original [Project Zero issue](https://project-zero.issues.chromium.org/issues/42452300/dupes).

**AGX/IOAccelerator — in-the-wild iOS 10 chain, no CVE assigned in the public
analysis.** `AGXAllocationList2::initWithSharedResourceList` allocated for six
subentries per descriptor while the shared structure allowed seven, so the
driver wrote controlled `IOAccelResource` pointers beyond its allocation. The
attack was directly reachable from WebContent and turned the overflow into a
reclaimed `uio`/IOSurface object. See Ian Beer's primary
[chain analysis](https://projectzero.google/2019/08/in-wild-ios-exploit-chain-1.html).

**AppleJPEGDriver — `CVE-2020-9768`, @_simo36.** A user client retained a raw
notification-port address in an internal asynchronous decode request after
userspace released its port right. Later async processing used the stale port,
giving a port-object UAF reachable from the app container. The discoverer's
[trigger](https://gist.github.com/0x36/3c9e77058eac7069616b72f0088d8b6d)
and [Proteas's analysis](https://proteas.github.io/ios/vulnerability/2020/03/27/analysis-of-CVE-2020-9768.html)
document the shape.

**AppleH10/H13 camera stack — binaryboy, no assigned CVE located.** Selector 86
accepted a userspace-controlled index, address, and length and indexed a large
driver array without validating the index before passing mapped memory into the
Jasper clocking code. The result was an OOB write/swap in the H10 implementation
and the author identified both AppleH10CameraInterface and
AppleH13CameraInterface as locations. See the author's
[writeup](https://github.com/b1n4r1b01/n-days/blob/main/AppleH10CamIn-OOBw/AppleH10CamIn-OOBw-Writeup.md).
The same research notes that the camera user client required
`com.apple.camera.iokit-user-access`, as documented in Saar Amar's
[reachability analysis](https://saaramar.github.io/iOS_memory_exhaustion_writeup/).

### Transfer assessment

The component family survives, but its layout and reachability have changed:

- IOAcceleratorFamily2 was refactored into IOGPUFamily in iOS 14; Siguza calls
  this out explicitly in [Tachy0n](https://blog.siguza.net/tachy0n/).
- The exact iPhone17,2 cache contains AppleH16CameraInterface, not H13. This is
  a successor family, not evidence that the H10/H13 selector bug transferred.
- AVE2 and JPEG survive on the physical image but are absent from the vPhone's
  paravirtual driver set.
- Modern typed allocation makes generic UAF replacement substantially less
  portable. Apple's [SockPuppet-on-iOS-16 retrospective](https://security.apple.com/blog/what-if-we-had-sockpuppet-in-ios16/)
  explains why OOL-port arrays, OSData, and typed objects no longer naturally
  co-locate and why an arbitrary `kfree` becomes zone-checked.

**Grade: B.** These remain worthwhile vulnerability-research surfaces, but they
need a fresh reachable defect and mostly reproduce the KRW we already possess.
They do not presently shorten KRW -> kcall.

If this class is revisited, the bounded experiment is: on the physical target,
run a read-only service/open matrix for the four confirmed services, record the
returned `kern_return_t`, user-client class, and entitlement denial, and stop
before calling selectors. That proves reachability only; it does not claim a
bug. Record it as `implemented` or `physical-proved` in a new exact-build JSON,
never as VM evidence.

## 2. Mach port, IPC, and socket-lifetime class

### Named precedents and exact shapes

**mach_portal — `CVE-2016-7644`, Ian Beer.** Racing
`set_dp_control_port()` over-released a Mach port while the task retained its
receive right. After page reuse, the dangling port could overlap an OOL port
array, disclose the host port through `mach_port_get_context`, and eventually
yield the kernel task port. Project Zero summarizes the original flow in its
[exploit survey](https://projectzero.google/2020/06/a-survey-of-recent-ios-kernel-exploits.html).

**voucher_swap / Chaos / machswap2 — `CVE-2019-6225`, Qixun Zhao, Brandon
Azad, Ben Sparkes.** `task_swap_mach_voucher()` violated MIG reference-lifetime
semantics and could add or drop one reference too many, leaving
`thread->ith_voucher` dangling. Reallocation with OOL ports or controlled
OSObjects turned the stale voucher into a fake port and then a fake task port.
See Brandon Azad's treatment in the same
[Project Zero survey](https://projectzero.google/2020/06/a-survey-of-recent-ios-kernel-exploits.html).

**SockPuppet — `CVE-2019-8605`, Ned Williamson.** `in6_pcbdetach()` freed
`in6p_outputopts` without clearing the pointer; sandbox-reachable
`getsockopt()` and `setsockopt()` then read through or freed members of the
stale `ip6_pktopts`. Attacker-controlled free/use timing plus a built-in
disclosure made the original arbitrary-read/free chain unusually reliable. See
Williamson's primary [walkthrough](https://projectzero.google/2019/12/sockpuppet-walkthrough-of-kernel.html).

### Transfer assessment

The socket/Mach lifetime *class* remains relevant because Cyanide's KRW already
lives on a modern ICMPv6/socket-parking surface. That is not evidence that
SockPuppet or a sibling UAF is open. Since iOS 16, `kalloc_type`, the data
submap, zone-checked frees, immovable ports, and increasing data-PAC coverage
have invalidated the historical "free port, reclaim with OSData/OOL ports,
forge `ipc_port`" recipe. Apple's retrospective specifically concludes that
even the unusually favorable SockPuppet shape becomes unreliable under typed
allocation.

A current public example makes the 26 boundary concrete: Titan's README says
its Coruna-derived `ipc_port->ip_nsrequest` stealing primitive was patched in
iOS 26 by adding data PAC. See the primary
[Titan repository](https://github.com/alfiecg24/Titan). That is a warning
against assuming an unsigned IPC pointer remains transplantable on 23A341; it
is not proof about every IPC field in this exact build.

**Grade: B.** IPC is alive but a new lifetime bug would be a new entry vector,
not the missing post-KRW primitive. The only justified transfer task is to
classify writable IPC fields by authentication schema and look for legitimate
consumers of already-signed values. Forging `ip_kobject` from a stripped task
pointer is already physically closed in this project by destination-diversified
data PAC.

## 3. Kernel stack, exception delivery, and thread-state class

### Named precedents and exact shapes

**Exception-oriented exploitation — pre-CVE precedent, Ian Beer.** With an
exception port installed using `EXCEPTION_STATE`, a faulting thread sends its
register state through a kernel-generated Mach exception message. Beer's
technique corrupted the preallocated message's size so controlled register
state was serialized out of bounds, turning exception delivery into a repeated
read/write mechanism. See the primary
[Project Zero writeup](https://projectzero.google/2017/04/exception-oriented-exploitation-on-ios.html).

**Fugu14 thread-state conversion — Fugu14 CVE bundle: `CVE-2021-30740`,
`CVE-2021-30768`, `CVE-2021-30769`, `CVE-2021-30770`, and `CVE-2021-30773`,
Linus Henze.** The public release lists the bundle but does not assign one ID to
each internal stage. In the PAC stage, `thread_state64_to_saved_state()` left
the privileged CPSR mode bits untouched; by redirecting one thread's kernel
stack to another thread's user saved state, the kernel signed a state that
could later be modified through `thread_set_state()` and resumed in kernel
mode. See the primary [Fugu14 PAC writeup](https://raw.githubusercontent.com/LinusHenze/Fugu14/master/Writeup.pdf)
and [release README](https://github.com/LinusHenze/Fugu14/blob/master/README.md).

**badRecovery — `CVE-2022-26765`, Linus Henze.** A legitimate thread recovery
handler in `hw_lck_ticket_reserve_orig_allow_invalid` ended with ordinary
`ret`, so a signed `thread->recover` pointer could reach an unauthenticated
kernel return with most registers still controlled. Fugu15 then used a
sign-and-branch sequence on `x22` to bootstrap a reusable kernel call. See the
primary [Fugu15 slides](https://objectivebythesea.org/v5/talks/OBTS_v5_lHenze.pdf).

**Sparrow/Rocket thread-object path — public 2026 reconstruction, no public CVE
mapping.** A freed/reclaimed thread object plus a retained thread send right let
the exploit race `thread_set_state`, install controlled continuation/saved-state
fields, and enter exception return. The exception path became both authenticated
kcall and a PACIA/PACDA/PACGA service. See the public
[Sparrow reconstruction](https://nvme0n1p.dev/en/posts/sparrow-wp).

### Transfer assessment

The exact 23A341 VM still contains `ml_sign_thread_state`,
`ml_check_signed_state`, the public thread-state converters, identity exception
delivery, and exception-return continuations. REA and the VM canary established
the signing tuple: state address, PC, CPSR, LR, x16, and x17 feed a PACGA chain.
The VM cross-task `EXCEPTION_STATE_IDENTITY` handoff also received thread and
task rights, converted state, replied, and resumed successfully.

The historical privileged-mode transfer does **not** survive: this project's
exact-build VM test showed `thread_state64_to_saved_state` sanitized the
requested state back to EL0. `thread->recover` is also table/bounds constrained,
so neither Fugu14 nor badRecovery should be copied literally.

What remains open is narrower and valuable: does a stock physical 23A341 boot
deliver a usable identity thread right and accept the same convert/reply
sequence without VM development/provider behavior?

**Grade: A.** The live semantic class is "kernel legitimately signs and moves
thread state across an exception boundary," not "set EL1 CPSR again."

### Exact A-grade experiment

1. On the unlocked iPhone17,2/23A341 device, open Cyanide Settings and run the
   existing `CNDPhysicalPACIdentityCanary` row. Do not enable any VM/provider
   kcall path.
2. Capture the raw report before relaunching the app. Require exact product,
   build, exception message ID 2407, flavor 6, state count 68, receive result,
   convert result, reply result, and child resume marker.
3. A passing result proves only that stock physical exception delivery supplies
   a usable identity right and that the converter/reply transport works. It
   does not prove EL1 execution, PAC bypass, or kcall.
4. Preserve the untouched report under
   `docs/research/physical-pac-identity-23A341-iphone17,2.json` and label it
   **physical-proved**. A failure must retain its exact `kern_return_t` and stage
   and be labeled **physical-negative**, not generalized from VM behavior.

## 4. PPL/SPTM-boundary data class

### Named precedents and exact shapes

**Project Zero PPL TLB bug — public precursor.** PPL removed translations from
two page tables but invalidated the TLB entry for only one mapping. The stale
translation in the second mapping remained usable after the physical page was
reclassified as protected page-table memory, allowing writes through the stale
mapping. See Project Zero's primary
[PPL analysis](https://projectzero.google/2020/07/the-core-of-apple-is-ppl-breaking-xnu.html).

**tlbFail — `CVE-2022-26764`, Linus Henze.** A nested shared-cache page could
be deleted through a non-nested pmap without flushing every relevant ASID. The
exploit kept a stale TLB translation, let PPL recycle the physical page as a
translation table, and wrote a self-referential entry through the stale alias.
See pages 45-59 of the primary
[Fugu15 slides](https://objectivebythesea.org/v5/talks/OBTS_v5_lHenze.pdf).

**Operation Triangulation — `CVE-2023-38606`, Kaspersky GReAT.** After gaining
physical memory access with `CVE-2023-32434`, the chain programmed undocumented
GPU-adjacent MMIO registers with a destination, data, and hash. The hardware
performed writes to otherwise PPL-protected physical memory, bypassing the
normal gate. See Kaspersky's primary
[analysis](https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669/).

**Sparrow — Rocket/Coruna reconstruction, public 2026, no public CVE mapping in
the writeup.** One legitimate `pmap_iommu_ioctl_internal()` call validated a UAT
state and marked an output page `PP_ATTR_NO_MONITOR`; a concurrent
`UAT_PPL_IOCTL_TASK_DIED` freed and recycled that state. The first call resumed
after validation and operated on a different, freshly initialized object at the
same address: a gate-crossing state-object UAF. See the public
[Sparrow writeup](https://nvme0n1p.dev/en/posts/sparrow-wp).

**Titan — Rocket/Coruna-derived SPTM bypass, Alfie CG.** Titan first overwrites
the AGX power thread's state to run a coprocessor ROP chain, then changes the
hibernation-restored `TTBR1_EL1` and stack so AGX maps and writes an AP page
table. The resulting self-referencing AP page table defeats PPL/SPTM. The
author states the thread-state primitive was patched by AGX instruction PAC in
iOS 18.1 beta 4 and the hibernation context bug was patched in iOS 17.4 beta 4.
See the primary [Titan README](https://github.com/alfiecg24/Titan).

### What crosses the gate

The transferable data shapes are more useful than their old addresses:

- a page-table mutation request plus pmap ownership/type metadata;
- a validated state object whose identity or lifetime changes after validation;
- a physical page temporarily classified as an ordinary output page;
- an IOMMU/UAT page-table root or descriptor accepted by the protected side;
- coprocessor register state (`PC`, `LR`, `CPSR`, stack, TTBRs) restored from
  writable memory;
- a signing request carrying pointer, key class, discriminator/context, and a
  destination for the result.

Apple describes modern SPTM/TXM as protecting user and kernel page tables even
after kernel write and control-flow protections are bypassed, with privilege
separation intended to prevent a TXM compromise from automatically becoming an
SPTM compromise. See Apple's current
[operating-system integrity guide](https://support.apple.com/en-ca/guide/security/sec8b776536b/web).

On local 23A341 artifacts, REA has mapped XNU stubs for
`pmap_sign_user_ptr`, `pmap_auth_user_ptr`, and batch signing, plus the SPTM
dispatcher selectors `0x10`, `0x11`, and `0x28`. Those were VM-proved only when
the lab provider already supplied kcall and changed JOP-key context; they do not
create kcall. The physical cache contains AGXG17P/IOGPUFamily, but the VM's
paravirtual GPU is not a valid testbed for Titan's physical AGX path.

**Grade: B.** The gate and its data contracts are alive, but no public
iOS-26/T8140 transfer is established and every promising local endpoint is a
consumer of authenticated control flow. Kcall remains the prerequisite.

The first post-kcall experiment should be a benign round trip: invoke one
exact-build signing/authentication selector on a synthetic noncanonical pointer,
read the returned value, authenticate/strip it through the paired selector, and
verify that no page ownership or mapping state changed. Record request tuple,
return tuple, key-context setup, and cleanup as **VM-proved** first. This proves
gate reachability and ABI, not an SPTM bypass.

## 5. Signing-gadget and authenticated-dispatch class

### Public semantic signatures

This is a bounded census of the major public kernel-PAC writeups with enough
detail to define a scanner. It deliberately records semantics, not addresses.

| Precedent | Semantic signature to scan for | Transfer note |
| --- | --- | --- |
| voucher_swap PAC bypass / `sysctl_unregister_oid`, Brandon Azad | Load an authenticated IA pointer from attacker-writable state; `AUTIA` it with an address-blended constant context; apply `PACIZA` even when authentication failed; store the zero-context IA result. The vulnerable form is `AUTIA -> PACIZA -> store` without preserving authentication failure. | Apple changed the sequence to compare authenticated vs stripped values and select the invalid result on failure. Still the canonical auth-and-resign scanner shape. See [Project Zero](https://projectzero.google/2019/02/examining-pointer-authentication-on.html). |
| state-signing gadget, Brandon Azad | A legitimate thread creation/initialization path reads PC/LR/CPSR (later x16/x17) from a writable saved-state object while interrupts permit attacker-controlled replacement, then calls `sign_thread_state` and stores a GA signature bound to the state address. | Search for signer callers with memory-fed state tuple, preemption/race window, and observable signature. See [iOS Kernel PAC, One Year Later](https://bazad.github.io/presentations/BlackHat-USA-2020-iOS_Kernel_PAC_One_Year_Later.pdf). |
| Fugu14 state conversion, Linus Henze | A user-controlled saved-state tuple is copied into a kernel exception frame, important mode bits are incompletely normalized, and the normal exception signer signs the result. Resuming the state consumes the signature and transfers control. | The 23A341 converter normalizes EL0 mode, so scan results must include sanitization, not merely a signer call. See the [Fugu14 writeup](https://raw.githubusercontent.com/LinusHenze/Fugu14/master/Writeup.pdf). |
| badRecovery `CVE-2022-26765`, Linus Henze | Install or harvest a legitimately signed `thread->recover`; trigger a controlled fault while registers remain useful; recovery reaches ordinary `ret` instead of authenticated return; follow with a gadget that signs and branches to an attacker-chosen register. | Scan recovery handlers for unauthenticated exits and for sign-then-branch sequences, but the specific iOS 15 path is historical. See [Fugu15](https://objectivebythesea.org/v5/talks/OBTS_v5_lHenze.pdf). |
| Sparrow/Rocket thread signer | A reclaimed but still RPC-addressable thread object supplies controlled exception/saved-state fields; exception return legitimately executes PACIA/PACDA/PACGA and writes results to shared memory; the same object becomes a repeatable authenticated call carrier. | Closest public semantic match to the project's thread-state work, but published support ends before 23A341. See [Sparrow](https://nvme0n1p.dev/en/posts/sparrow-wp). |
| Local IOMobileGraphics scheduler | Authenticate an input action with kernel IA and constant discriminator `0x61de`; re-sign it with IA/zero; queue a fixed adapter signed for `0x61de`; worker loads four arguments and invokes `BLRAA target,0x61de`; adapter later performs an IA-zero call. | Exact-build static match; it translates a **valid** `0x61de` pointer and is not yet an arbitrary raw-pointer signer. This is the immediate live canary target. |

The Project Zero definition is useful: a signing gadget is legitimately
invokable code that accepts attacker-influenced signing inputs and makes the
signed result observable. See [Remote iPhone Exploitation, Part 3](https://projectzero.google/2020/01/remote-iphone-exploitation-part-3.html?m=1).
The broader academic classification separates function-level shared signing
interfaces from instruction-level gadgets and requires input control plus an
observable result; see the [USENIX Security 2023 paper](https://www.usenix.org/system/files/usenixsecurity23-cai-zechao.pdf).

`rootlessJB3` is not a kernel PAC-signing precedent. Its public README supports
A7-A11, lists A12 as future work, and therefore predates the arm64e problem in
question; see [rootlessJB3](https://github.com/jakeajames/rootlessJB3). The
useful "jb3-style" idea should be stated generically as *reuse a legitimate
kernel signer*, not attributed to that repository.

### Exact 23A341 local result

The project already has one **VM-proved constrained authenticated dispatch**:
`thread-call-pac-reuse-dispatch-observation.json` records an existing signed
`IA/0x73d8` adapter and an existing IA-zero target transplanted into a live
thread-call object. A KDP hardware breakpoint observed the chosen target with
controlled `x0 = 0x434e445041435830`; all fields were restored and the timer was
destroyed, with `usedKernelCall=false`. This is meaningful progress, but the
target was a fixed safe early-return function, not arbitrary kcall.

Ghidra then found a stronger carrier in the exact VM
IOMobileGraphicsFamily fileset:

- `UPAsynchronousScheduler_::startThreadWithAction` at unslid
  `0xfffffe0008f70254` queues a native four-argument `IA/0x61de` action.
- The synchronous wrapper at `0xfffffe0008f702bc` authenticates an incoming
  `IA/0x61de` action, applies `PACIZA`, and queues a fixed signed adapter at
  `0xfffffe0008f70d48`.
- The common queue routine is `0xfffffe0008f7002c`; entry fields are action at
  `+0x8`, flags at `+0x11`, marker at `+0x12`, and four arguments at
  `+0x18`, `+0x20`, `+0x28`, and `+0x30`.
- The worker at `0xfffffe0008f7073c` loads all four arguments, sets
  `x17=0x61de`, and executes `blraa x8,x17`.
- `setDefaultAction` at `0xfffffe0008f6ff24` is a locked plain store;
  `prepareThread` at `0xfffffe0008f6ffbc` creates a dormant entry; and
  `notifyThread` at `0xfffffe0008f7046c` supplies arguments and wakes the work
  source.

These are unslid iPhone17,3 VM addresses. They are not physical iPhone17,2
offsets and must never be copied into the physical profile.

**Grade: A.** A legitimate authenticated four-argument branch and an
auth-and-resign bridge exist in the exact VM build. The missing facts are the
live owning object and a harmless, valid `IA/0x61de` target that can be harvested
without provider kcall.

### Exact A-grade experiment

1. In Ghidra, finish only the constructor/owner xrefs for
   `UPAsynchronousScheduler_`; identify the containing service and the exact
   outer-object-to-scheduler offset. Do not broaden into a kernel-wide scan.
2. Boot the exact 23A341 VM with KDP but disable syscall-439/provider kcall.
   Locate one live scheduler object from the owning service and read its
   workloop, interrupt source, queue head, default action, and lock-adjacent
   state. Reject the run unless every pointer lands in the expected fileset or
   zone range.
3. Use `prepareThread` to allocate a dormant entry. Snapshot the entry and owner
   state. Transplant only a previously observed valid `IA/0x61de` action whose
   callee has a read-only/early-return contract, plus four recognizable canary
   arguments.
4. Arm a one-shot hardware breakpoint at the stripped callee, invoke
   `notifyThread`, and require the breakpoint to observe x0-x3 exactly. Do not
   count queue-state changes or lack of panic as success.
5. Restore the original action/default/entry fields, drain the queue, and prove
   byte-for-byte owner-state restoration. Abort cleanup on any pointer or state
   mismatch rather than freeing guessed objects.
6. Record original, modified, triggered, observed, and restored state in
   `build/rea-secure-execution-23A341-iphone17,3/upa-scheduler-61de-canary.json`
   as **VM-proved**. The report must include `usedKernelCall=false` and
   `usedKernelWrite=true`.

Success proves a no-provider, PAC-correct, four-argument **constrained call
carrier**. It does not yet prove arbitrary kcall: arbitrary target selection
still needs either a signer for the `0x61de` schema, a sufficiently rich corpus
of already-signed `0x61de` actions, or a second authenticated translation whose
input schema we can satisfy.

## Priority decision

The single highest-leverage experiment is the
**`UPAsynchronousScheduler_` live four-argument `0x61de` canary**.

It wins over another UAF hunt because KRW already exists; over the physical
identity canary because it tests the exact missing KRW-to-control-flow boundary;
and over an SPTM experiment because SPTM endpoints currently consume kcall.
Static work has already established the dispatcher, argument layout,
authentication discriminator, translator, preparation path, notification path,
and cleanup-relevant owner fields. The experiment converts those facts into the
one kind of evidence the project currently lacks: a reversible live observation
of useful PAC-correct control flow without the VM provider.

The physical identity canary should still be run in parallel in the human sense
of priority—it is cheap and already implemented—but it must not delay the VM
scheduler canary. A pass on either route narrows the remaining problem; only the
scheduler result directly advances the present no-provider kcall construction.
