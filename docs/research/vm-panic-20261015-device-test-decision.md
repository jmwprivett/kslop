# 2026-10-15 VM lab-provider panic: what may move to the physical device

Date: 2026-10-15. Evidence standard: **implemented** ≠ **VM-proved** ≠
**physical-proved**.

## Decision

The provider/harness flow that panicked the VM (`scripts/lab/cnd_provide_tfp0.c`
driven by `scripts/lab/cnd_vphone_krw.py`) must **not** be built or run on the
iPhone 16 Pro Max. Only a read-only observation of the phone's existing panic
reports is permitted, and that is what was implemented.

Rules that block the literal ask (quoted):

- `docs/research/vm-guide.md:155-157` — "Never broaden the VM syscall-439
  backend into a physical-device claim. The current backend accepts a target
  plus at most seven arguments and exists only in the vPhone jailbreak kernel."
- `docs/research/vm-guide.md:153-154` — "Never infer kcall from tfp0/KRW alone."
- `Cyanide/kexploit/CNDLabKernelProvider.h:9` — "VM-only provider."
- `Cyanide/kexploit/CNDLabKernelProvider.h:37-39` — "The target must lie in the
  validated kernel image and at most eight integer arguments are accepted.
  Physical-device KRW never routes through this API."

Structural reasons the flow cannot target the phone even apart from the rules
(**implemented**, source reading):

- `scripts/lab/cnd_remotecall_lab.py:212-225` `require_vphone` refuses any SSH
  target that is not a `VPHONE` / `VRESEARCH` guest, and
  `scripts/lab/cnd_vphone_krw.py` calls it before every live action.
- `scripts/lab/cnd_provide_tfp0.c:834-847` acquires the kernel task from host
  special port 4 or `task_for_pid(0)`; `:326-335` loads `/var/jb` libkrw
  plugins; `:76-77` uses the VRESEARCH-only syscall 439. None exist on the
  non-jailbroken `iPhone17,2`.
- The VM kernel is `xnu-12377.42.6~55/RELEASE_ARM64_VRESEARCH1` (panic header);
  the phone runs `xnu-12377.2.8~1/RELEASE_ARM64_T8140`
  (`scripts/lab/cnd_physical_cs_allow_invalid_probe.py:183`). A "same
  behaviour" claim could not transfer between them anyway.

## Implemented subset (read-only)

`scripts/lab/cnd_physical_panic_signature_probe.py` with tests in
`scripts/tests/test_physical_panic_signature_probe.py` (17 tests, passing).

- `classify FILE...` parses `.ips` panic reports (VM or device) and checks them
  against the pinned VM signature: `Kernel data abort`, GZAlloc zone
  `MAC Labels`, kind `use-after-free`, esr `0x9600004f`, copy length `0x18`,
  panicked process prefix `cnd-provide-tfp0-`.
- `device-inventory [--copy]` verifies the device is the exact pinned
  `iPhone17,2` / `23A341` CoreDevice ID (refusing the VM entry), then only uses
  the `systemCrashLogs` inventory and copy flows from
  `docs/physical-device-logs.md:181-238`. It never installs, launches, signs,
  reads, writes, or calls anything; the report JSON records those as `false`.
- Guard pins in the tests: the probe's code never imports or invokes the VM
  harness, and the VM harness still gates live actions behind `require_vphone`.

## Results

- **VM-proved**: the reference report matches the signature; pid 591 is the lab
  provider; the four validation-route offsets supplied by the triage resolve
  (relative to the kernel text base) to addresses absent from the backtrace.
- **physical-observed (complete, 56 of 56 `panic-full` reports, 2026-09-18 to
  2026-10-12)**: no report matches the VM signature. All 56 are on the T8140
  kernel; 48 are `Unexpected fault in kernel physical aperture` in `Cyanide`
  (the device's own KRW path), 2 are PAC failures in `Cyanide`, 1 is a
  `MAC Labels` zone *bounds-check* panic in `Cyanide` (a different class from
  the VM use-after-free), and the only two GZAlloc records are in
  `kernel_task` against `proc_task` and `kalloc.type8.224`, not `MAC Labels`.
  Evidence: `build/physical-panic-signature-20261015-223315/panic-signature-report.json`
  (`complete: true`, `copyFailures: {}`, every `*Used`/`*Anything` flag false).
- **Not proved anywhere**: whether the VM label-lifetime race exists on the
  phone. Absence of a matching panic is not a proof of absence.

## Requests for the provider owner (out of scope here)

- A read-only in-app canary following `Cyanide/CNDPhysicalPACIdentityCanary.m`
  (`kernelReadUsed: YES`, `kernelWriteUsed: NO`, `kernelCallUsed: NO`) would
  be the only rule-compatible way to observe label lifetime on the phone; it
  needs a new `.m` producer and `SettingsViewController.m` wiring.
- No change requested to `CNDLabKernelProvider.m/.h`.
