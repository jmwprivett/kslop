# Probe capability and evidence contract

This is the canonical claim boundary for Cyanide's kernel, physical-device,
and VM research. Use it when designing a probe, reviewing probe code, choosing
a follow-up experiment, or reporting what the repository can do.

The governing rule is:

> A validated capability proves only itself, in the environment and identity
> scope that was actually tested.

In particular, physical kernel read/write (KRW) does **not** provide arbitrary
kernel call, a task port, an operation that creates or admits an RX mapping of
any kind, a code-signing bypass, or a general PAC bypass. Those are separate
capabilities with separate proof gates.

Cyanide has **no true kernel-call capability**. `kcall` and `kcall1` are
probe/test artifacts, not product primitives: the physical `kcall1` probe is
unfinished and unsuccessful, and the VM lab kernel call is a VM-only,
capability-gated test facility that proves nothing about the physical device.
Never report either as "kcall works", and never plan a feature on one.

`CNDPhysicalKCall1Probe` has a stricter current status: it is unfinished and
has not succeeded. It is diagnostic experiment code, not a usable capability,
primitive candidate, fallback, dependency, or potential production tool. Do
not plan a consumer around it. A partial signer, inventory, scratch-write, or
trigger observation does not promote the probe or establish physical kcall.

## Current capability boundaries

| Surface | What it can establish | What it does not establish |
| --- | --- | --- |
| Physical opa334 KRW | Kernel reads and writes through the current, validated physical KRW generation, using the primitive's checked transfer shapes and lifecycle | Arbitrary kcall; a kernel ABI; a task right; remote task VM/thread control; allocation or admission of new executable pages; W-to-RX or RWX mappings; code-signing, PAC, PPL/SPTM, AMFI, or sandbox bypass |
| Physical RemoteCall | A separate, PID-bound path that composes existing signed userspace code and the target's validated PAC context | Kernel call; a general task port; injected executable code; a newly admitted RX page; a general PAC-signing oracle |
| Physical `kcall1` probe | Nothing positive at present: it is unfinished, unsuccessful diagnostic experiment code. Partial subprobes may localize a failure but do not establish a callable primitive. | Any usable or potential tool; arbitrary or bounded physical kcall; a normal ABI; register-control guarantees; a production fallback or dependency; portability; executable-memory capability |
| Physical task bridge on arm64e | An explicit unsupported result for the forged-port route when destination-specific kernel data PAC cannot be satisfied | A usable task right or any VM/thread operation merely because KRW can read or write the relevant structures |
| Physical RX / code-sign probes | Nothing about executable-page admission at present; source for an experiment is only implemented code | Physical KRW has no operation that creates or admits a new RX mapping of any kind, including no W-to-RX and no RWX; there is no general process-injection capability |
| VM lab KRW | Kernel read/write only when the independently advertised lab KRW capability is active for the current boot | Lab kcall or direct-task control without their own capability bits and gates; any physical-device capability |
| VM lab kernel call | A VM-only call through `cnd_lab_kernel_call` when the current boot has the kernel-call capability, the isolated smoke test passed, the target is inside the validated kernel image, and the argument count is within `CND_LAB_KCALL_MAX_ARGUMENTS` | Physical kcall; calls outside the validated image; an unbounded ABI; proof that tfp0 or KRW alone implies kcall |
| VM lab direct task | Bounded, root-helper-owned process resolve and task memory/thread operations when the independent direct-task capability is active; this includes the lab's bounded W-to-RX transition | A physical task port or physical RX path; a forged arm64e task right; permission to broaden the operation to another process or beyond the protocol's size and identity bounds |

The VM-only provider contract is declared in
[`CNDLabKernelProvider.h`](../../Cyanide/kexploit/CNDLabKernelProvider.h) and
[`CNDLabKernelProtocol.h`](../../Cyanide/kexploit/CNDLabKernelProtocol.h). The
per-boot proof and safety rules are in [`vm-guide.md`](vm-guide.md). Physical
constraints and the unwired signed-vnode mapping experiment are described in
[`springboard-resident-repair-supervisor-feasibility.md`](springboard-resident-repair-supervisor-feasibility.md).

## Non-implications

Keep these edges broken unless a new, independently accepted artifact proves
one of them:

- KRW does not imply kcall, even when an exact kernel function entry can be
  read, decoded, or overwritten into a field.
- The unfinished, unsuccessful `CNDPhysicalKCall1Probe` is not a capability or
  a potential tool. Its partial subprobes do not imply even a bounded physical
  kcall, much less arbitrary kcall, a standard calling convention, or control
  of additional arguments.
- Kcall does not imply a task right, user-process VM control, executable-page
  admission, or code-signing allowance.
- A task right does not by itself make modified or anonymous pages executable;
  code signing and map/pmap policy remain separate gates.
- A PAC canary, PAC-context transplant, or one producer-signed callback does
  not imply a kernel PAC bypass or a general signing oracle.
- Executing an existing Apple-signed IMP, ROP/JOP path, return stub, or mapped
  signed image is not proof that Cyanide created a new executable mapping.
- Mapping an existing RX page is not W-to-RX. A W-to-RX result is not RWX. A
  result in one exact process is not arbitrary process injection.
- Static address derivation, instruction matching, or an exact preflight proves
  identity of a candidate, not reachability or successful invocation.
- Implemented does not mean runtime-proved. VM-proved does not mean
  physical-proved. A historical boot does not prove the current boot.
- One successful address or transfer shape does not prove every address, size,
  backing type, or concurrency pattern is safe.

The current physical executable-memory boundary is therefore firm: physical
KRW has no primitive for creating or admitting a new RX mapping of any kind,
including no W-to-RX and no RWX capability. Cyanide also has no physical
arbitrary-kcall API. Unfinished probe code does not change either status by
existing.

## Evidence classes

Every positive capability claim must use one of these classes and cite its
artifact:

| Class | Required meaning |
| --- | --- |
| Implemented | Source, tests, or documentation exists. No runtime success is implied. |
| VM-proved | The complete acceptance criteria passed on the named VM, build, boot/kernel identity, and provider generation. |
| Physical-proved | The complete acceptance criteria passed on the named physical product/build and the retained device report proves the decisive effect and cleanup. |

Static-derived, host-tested, observed, refused, failed, and not-run are useful
qualifiers, not promotions to a stronger class. If no decisive artifact is
retained, the claim is not runtime-proved.

Each report or status summary must identify:

- the exact claim, with words such as `bounded`, `kcall1`, `VM-only`, or
  `physical` where they materially limit it;
- product, OS build, environment, and relevant kernel UUID/base provenance;
- boot/provider/KRW generation and target PID/process identity when applicable;
- prerequisites independently checked, not inferred;
- the decisive observation and the retained artifact path;
- cleanup and restoration verdicts; and
- adjacent capabilities that remain unproved or unavailable.

## Probe acceptance criteria

Before a probe can support a positive claim, require all applicable gates:

1. **Exact scope:** product, build, kernel image/UUID, environment, target
   process, and operation are named. Unknown or mismatched identity fails
   closed.
2. **Independent prerequisites:** KRW, lab kcall, direct-task, PAC context,
   code-sign allowance, and executable-map admission are checked separately.
   The probe never substitutes one for another.
3. **Fresh lifecycle:** boot-specific bases, slides, ports, process identities,
   and provider generations are obtained from the current run. A panic, reboot,
   provider restart, process replacement, or KRW cleanup invalidates stale
   state.
4. **Bounded target:** addresses and lengths come from pinned provenance and
   exact expected-before validation. Do not scan, guess, or dereference a
   speculative physical/kernel address to make a gate pass.
5. **Concurrency ownership:** no second process or host uses the physical KRW
   pair concurrently. The existing mutex is process-local; until a broker or
   lease is implemented and proved, it is not cross-process coordination.
6. **Reversible mutation:** snapshot the complete affected state, perform the
   smallest write, verify readback, and restore on success, refusal, timeout,
   and every error path. Verify restored bytes/fields and record any cleanup
   failure as a failed verdict.
7. **Decisive trigger:** distinguish preparation from consumption. A signed
   pointer, mapped address, or accepted syscall is not enough; the expected
   target-side effect or nonce must be observed.
8. **Durable evidence:** persist identity, prerequisites, before/after values,
   trigger result, errors, cleanup, and the final bounded verdict. Preserve a
   negative result at the layer it actually tested; do not turn an outer policy
   denial into proof about an inner gate.

For executable-memory experiments, additionally require a writable-to-RX
transition and execution of a BTI-correct nonce in the exact target. Never use
RWX. Prove that the mapping is private and that original bytes, permissions,
threads, and process state are restored or that the disposable target was
terminated as specified by the probe.

For any future call-carrier experiment, record exactly which PC and registers
are controlled, how the target pointer was authenticated, the calling context,
return behavior, repeatability, and all clobbers. This generic acceptance rule
does not upgrade `CNDPhysicalKCall1Probe`: that probe remains unfinished,
unsuccessful, and unusable. Even a new diagnostic observation would not make it
a tool; a separately scoped and proved primitive would be required before any
consumer could depend on such a capability.

## Review checklist

Reject or narrow a change or claim when any answer is unclear:

- Does the name and report distinguish physical, VM, and host-only behavior?
- Are capabilities checked independently instead of inferred from KRW-ready?
- Could a VM-only API or result leak into a physical claim?
- Is the unfinished `CNDPhysicalKCall1Probe` being treated as a capability,
  candidate tool, fallback, dependency, or successful bounded carrier? If so,
  reject the claim or design.
- Does “RX” mean a newly admitted executable page, rather than execution of
  existing signed code?
- Are exact identity, expected-before, timeout, cleanup, and restore-readback
  gates present?
- Is a current-boot/device artifact cited for every runtime claim?
- Does the final result state both the smallest proved capability and the
  neighboring capabilities that remain absent?
