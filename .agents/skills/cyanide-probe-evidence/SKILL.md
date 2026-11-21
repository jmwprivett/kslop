---
name: cyanide-probe-evidence
description: Keep a new or behavior-changing Cyanide kernel, physical-device, or VM probe within its actual capabilities and evidence. Use only when creating a probe or modifying how an existing probe works, including probes involving KRW, kcall or kcall1, PAC, task ports, RemoteCall, executable memory, or lab providers. Do not use for ordinary implementation, installs, review, testing, documentation, or status reporting merely because those topics are mentioned.
---

# Cyanide probe evidence

Apply this skill only when the task creates a probe or changes an existing
probe's behavior. Do not apply it to ordinary KRW or kernel implementation,
installation, review, test execution, documentation, or reporting that does
not make or modify a probe.

Before designing or implementing an in-scope probe, read
[`docs/research/probe-capability-contract.md`](../../../docs/research/probe-capability-contract.md).
Treat it as the repository's claim and acceptance contract. Inspect the current
source and retained result artifacts as well; a status sentence in an older
research note may be stale.

## Use the shared KRW lifecycle; do not fork it inside a probe

When a probe is meant to use KRW the same way Cyanide's working tweak actions
do, route preparation through the existing shared lifecycle owner before
entering the probe. Do not recreate reuse, parked recovery, validation, or
acquisition policy inside the probe itself.

- By default, the command/action layer calls `settings_ensure_krw_for_probe()`
  and records `shared-tweak-lifecycle` as its policy. That shared owner may
  reuse an active generation, recover the launchd-held generation, or run the
  normal acquisition fallback exactly as it does for other KRW-backed actions.
- If the user explicitly requires an existing or parked generation only, the
  command/action layer instead calls
  `settings_ensure_existing_krw_for_probe()` and records
  `shared-tweak-lifecycle-existing-only`. This is the same shared reuse and
  recovery owner with fresh acquisition disabled. A missing, stale, or failed
  recovery must refuse the probe; never fall through to `kexploit_opa334()`.
- Probe source must not call or resolve `kexploit_krw_ready()`,
  `krw_persistence_recover*`, `krw_persistence_has_saved_recovery()`, or
  `kexploit_opa334()` directly. It must not introduce a probe-specific parked
  recovery adapter or a second lifecycle state machine.
- After the shared owner returns success, the probe still proves only the
  exact operation it needs with the primitive's boolean checked API at a
  bounded, symbol-anchored, exact-image witness. Abort on transfer or witness
  mismatch; never turn a zero-filled compatibility read into success.
- Report the shared lifecycle owner and policy. Do not claim that recovery or
  acquisition was skipped unless the shared owner supplies that exact outcome
  for the current run.
- Initialize non-mutating offset metadata before consuming it. Record the
  current PID and the exact process-local base, slide, and `t1sz` used by the
  checked witness.
- Preserve process identity during command delivery. Do not install,
  terminate, or intentionally relaunch the app while a live generation is in
  scope unless the user separately asks for it. Record the result PID and
  reject a process-identity mismatch.

This shared-lifecycle rule does not weaken the provenance, exact-image,
bounded-read, or fail-closed requirements below.

## Apply the contract

1. Name the environment and identity boundary: physical device or VM, product,
   OS build, kernel identity/boot when relevant, process identity, and active
   primitive generation.
2. List each required capability independently. Never infer kernel call, task
   control, executable mapping, code-signing allowance, or PAC correctness from
   KRW or from one another.
3. State the smallest claim the proposed operation or retained artifact can
   prove. A bounded callback carrier or chosen-PC/chosen-X0 canary is not an
   arbitrary kcall. Existing signed code execution is not a new RX mapping.
   `CNDPhysicalKCall1Probe` is unfinished and unsuccessful; treat it only as
   diagnostic experiment code, never as a capability, primitive candidate,
   fallback, dependency, or potential production tool. Partial subprobe
   observations do not change that status.
4. Keep physical and VM routing visibly separate and fail closed when a named
   capability, exact identity gate, expected-before value, cleanup step, or
   restoration readback is absent.
5. Preserve the evidence classes exactly: implemented, VM-proved, and
   physical-proved are different. Static derivation, host tests, or an old boot
   may support a claim but do not promote its class.
6. For a mutation probe, require bounded targets, before-state capture,
   write/readback, deterministic trigger and verdict, cleanup on every path,
   and verified restoration. Record partial cleanup or ambiguous identity as a
   failure, not a partial proof.

When reporting results, include what was established, what remains unavailable,
the evidence class and artifact, and the exact scope. Do not generalize a VM
result to a physical device, a single build to another build, a one-argument
carrier to a general ABI, or one process's W-to-RX result to arbitrary process
injection.

A request to implement or review a probe does not by itself authorize running
it on a physical device or live VM. Run only the environment the user actually
asked to exercise.
