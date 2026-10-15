# REA secure-execution bundle

`scripts/lab/cnd_rea_secure_execution.py` gives REA a stable, fail-closed
interface to the three images involved in iOS 26 secure execution: the kernel,
TXM, and SPTM. It solves two recurring mistakes in this lab:

- analyzing the stock iPhone image while the vPhone is running a patched
  `vphone600`/`vresearch1` image set; and
- carrying an address or REA result between images without first checking the
  UUID and SHA-256 identity.

The manifest records each immutable artifact, its Mach-O identity, its REA
snapshot, the exact inner `com.apple.kernel` UUID, and—when a debug port is
provided—the live kernel load address and slide. A UUID mismatch is a hard
failure. `rea-plan` emits argument arrays and environment values rather than
shell fragments, so a caller can execute or review a bounded analysis plan.
Each planned query receives its own snapshot file; later function or xref work
cannot silently replace the baseline or another query's evidence.

## Current vPhone bundle

The iOS 26.0 / 23A341 JB VM is a hybrid research environment. Its relevant
images are:

- patched `kernelcache.research.vphone600`;
- patched `txm.iphoneos.research`; and
- cloudOS `sptm.vresearch1.release`.

Do not substitute the stock `kernelcache.release.iphone17` or
`sptm.t8140.release` for VM conclusions. They remain useful comparison targets
for the physical iPhone, but their addresses and behavior are separate
evidence.

Create and bind the bundle to a running VM:

```sh
python3 scripts/lab/cnd_rea_secure_execution.py create \
  --kernel build/rea-secure-execution-23A341-iphone17,3/kernelcache.research.vphone600.decompressed/kernelcache.research.vphone600.decompressed \
  --txm build/rea-secure-execution-23A341-iphone17,3/txm.iphoneos.research.vm-patched \
  --sptm build/rea-secure-execution-23A341-iphone17,3/sptm.vresearch1.release \
  --snapshot-dir build/rea-secure-execution-23A341-iphone17,3 \
  --build 23A341 --product iPhone17,3 --kernel-debug-port 62139 \
  --kernel-assert 0x1633880=200080d2420000b4400000f9c0035fd6 \
  --kernel-live-assert 0xfffffe0008637880=200080d2420000b4400000f9c0035fd6 \
  --txm-assert 0x2c1f8=000080d2 \
  --txm-assert 0x1f3b8=20008052 \
  --txm-assert 0x1fa58=1f2003d5 \
  --output build/rea-secure-execution-23A341-iphone17,3/bundle.json
```

The kernel assertion binds the AMFI trust-cache function to its four-instruction
always-allow stub. The TXM assertions bind three observed JB patch states: the
legacy trust-cache lookup call is replaced by `mov x0, #0`, the debugger
entitlement result is forced true, and the developer-mode guard is a NOP. The
assertions are offsets and bytes, not inferred symbol names, and are rechecked
by `verify`.
The live assertion translates the unslid AMFI address by the debugger-observed
kernel slide and performs one bounded read. On the current boot it resolves to
`0xfffffe0039247880`; the debugger returned the same 16-byte stub and detached.

Revalidate every artifact and the current live kernel before using saved
addresses:

```sh
python3 scripts/lab/cnd_rea_secure_execution.py verify \
  build/rea-secure-execution-23A341-iphone17,3/bundle.json \
  --kernel-debug-port 62139
```

Produce the bounded REA work list:

```sh
python3 scripts/lab/cnd_rea_secure_execution.py rea-plan \
  build/rea-secure-execution-23A341-iphone17,3/bundle.json \
  --rea-root /Users/josh/dev/rea \
  --ghidra-install /Users/josh/Applications/ghidra_12.1.4_PUBLIC \
  --output build/rea-secure-execution-23A341-iphone17,3/rea-plan.json
```

Produce the exact function/trace plan for the reconciled XNU/SPTM control
plane and PAC services:

```sh
python3 scripts/lab/cnd_rea_secure_execution.py research-plan \
  build/rea-secure-execution-23A341-iphone17,3/bundle.json \
  scripts/lab/profiles/rea-secure-execution-23A341-iphone17,3-trustcache.json \
  --rea-root /Users/josh/dev/rea \
  --ghidra-install /Users/josh/Applications/ghidra_12.1.4_PUBLIC \
  --output build/rea-secure-execution-23A341-iphone17,3/sptm-pac-research-plan.json
```

`research-plan` binds the profile to all three artifact hashes, including the
SPTM SHA-256, and emits only typed `function` and literal `trace` argument
vectors. It carries the recovered dispatch token layout, selectors, service
arguments, constraints, and REA evidence IDs with the operations.
The two thread-consumer targets additionally select the extracted
`kernel-filesets/com.apple.kernel` variant by its own SHA-256. The planner
rejects traversal, missing digests, and hash drift; this avoids repeatedly
timing out on analysis of the complete fileset container.

Bind the exact static findings to a current boot and emit the four bounded
hardware-breakpoint records:

```sh
python3 scripts/lab/cnd_rea_secure_execution.py observe-plan \
  build/rea-secure-execution-23A341-iphone17,3/bundle.json \
  scripts/lab/profiles/rea-secure-execution-23A341-iphone17,3-trustcache.json \
  --kernel-debug-port 62139 \
  --output build/rea-secure-execution-23A341-iphone17,3/trustcache-observation-plan.json
```

`observe-plan` rehashes the kernel, TXM, SPTM, and baseline REA snapshots;
checks the live kernel UUID and assertion bytes; then translates only the
profile's one-to-four validated static addresses by the observed slide. Each
capture is bounded to 16 registers, four memory ranges, and 64 elements per
range. The plan carries the AMFI/TXM ABI and REA evidence IDs alongside the
live addresses, and never writes target memory.

## Targeted findings

The exact VM kernel import completed with REA evidence
`ev_ca15b4bf333f22fe50d2622f15a7bbee5df061b0a607f67dc4e08e4c27ae7a22`:
106,874 procedures, 84,547 strings, and 2,135 mapped segments. Its snapshot is
`build/rea-secure-execution-23A341-iphone17,3/kernel-vm-rea-snapshot.json`.

Extracting only the AMFI fileset entry allowed a focused decompilation of the
patched function at `0xfffffe0008637880` (REA evidence
`ev_897c89bf283d368a8e19f4a2f900c02c8e878ff488697fa46ac13ef85d38c4d7`).
It is exactly 16 bytes, leaves `x0 = 1`, stores `1` through the third argument
when non-null, and returns. REA found six static callers. The live debugger read
the same instructions at slid address `0xfffffe0039247880`.

The exact patched TXM image retains distinct load and unload entitlement gates:

- `com.apple.private.pmap.load-trust-cache` is referenced by the handler at
  `0xfffffff01702627c`; and
- `com.apple.private.unload-trust-cache` is enforced by the separate handler at
  `0xfffffff017026638`.

The load handler validates a bounded request, checks the entitlement when its
dispatch record requires it, and then calls the trust-cache operation selected
through TXM state. Its validation backend is at `0xfffffff017030b34`. The
unload backend at `0xfffffff017030ce0` marks the selected record and returns
its state to the handler, which updates accounting. These are useful
observation points; they do not establish that changing kernel memory alone
bypasses TXM policy.

The shared entitlement helper at `0xfffffff017022a30` resolves either the
current or supplied TXM context, looks up the entitlement, and reports success
only when the returned status has no error byte. Separate REA snapshots preserve
the load handler, unload handler, entitlement helper, external loader, and both
backends under the bundle build directory.

REA now closes the load dispatch mapping as well. The kernel builds operation
`0x0c` with seven arguments and enters its secure dispatcher. In TXM,
dispatcher `0xfffffff01702ae80` selects case `0x0c`, calls the range-validation
adapter at `0xfffffff01702b6f4`, and that adapter calls the load handler at
`0xfffffff01702627c`. The dispatcher observation is preserved as evidence
`ev_5b79f98679e6413c7d4547701442651179e85162e12ed5f728e8055d339b7e1d`;
the adapter observation is
`ev_266d06e60b70ec2d63c26560a9790339f8a320011385d3f002d31a2e61d158b4`.

The exact VM SPTM table reconstruction is now closed far enough to identify
three PAC services in endpoint 0, table 0. Selector `0x10` signs one user
pointer, selector `0x11` authenticates and strips it, and selector `0x28`
performs a bounded batch operation. Their SPTM handlers are respectively
`0xfffffff0270c23c8`, `0xfffffff0270c2740`, and `0xfffffff0270c24e0`.
The single-pointer services accept only key IDs 0 and 2, corresponding in the
observed code to IA and DA operations, and take the discriminator in `x2`.

These are not isolated SPTM helpers. XNU contains deliberate stubs at
`0xfffffe00082f3788`, `0xfffffe00082f37a0`, and `0xfffffe00082f3800` that
construct selectors `0x10`, `0x11`, and `0x28` in `x16`, then enter the shared
GENTER trampoline. SPTM decodes the endpoint/table/selector token, validates
the caller permission, resolves a 16-byte service-table entry, and invokes the
registered handler through a PAC-authenticated call gate. This establishes a
static XNU-to-SPTM control path; it does not by itself establish that these
user-pointer services can sign arbitrary kernel control-flow pointers.

REA then found the selector-`0x10` stub's concrete code caller at
`0xfffffe0007c418fc` (evidence
`ev_99f8f9a0fa0e7e6c37495ea6378faa0557383a457cfb234d40df2d7254f61805`).
The shipped assembly disables interrupts, installs the fourth argument into
`kernkeylo_el1`/`kernkeyhi_el1`, invokes selector `0x10`, restores the prior
key state, and re-enables interrupts. The adjacent batch and authentication
wrappers are at `0xfffffe0007c419c4` and `0xfffffe0007c41c08`.

The older local XNU 12377.1.9 source names these exact-shaped routines
`pmap_sign_user_ptr`, `pmap_batch_sign_user_ptr`, and `pmap_auth_user_ptr`,
with `ml_enable_user_jop_key`/`ml_disable_user_jop_key` around the SPTM call.
That naming is source-assisted inference because the running kernel reports
source version 12377.42.6; the control flow and register operations themselves
are observations from the exact shipped artifact.

## Relationship to current KRW

The physical-device KRW can safely support read-only validation and bounded
data-page experiments after the live image is independently identified. It
does not provide a physical-device kernel call, and executable text remains
physically read-only. The new thread-state route deliberately removes kcall
from the PAC operation: once Cyanide owns a genuine target thread control
right, the public converter can produce reply-compatible PC/LR PAC for that
thread. KRW's remaining role is to locate the exact target thread, validate
its task relationship, and—if normal exception delivery does not provide a
control right—support a separately verified way to obtain one. The VM-only
provider remains useful for diagnostics but is not part of this converter
path and must not be reported as a physical exploit primitive.

The existing physical `remote_pac` route is already KRW-only rather than
kcall-dependent: it reads the remote thread's ROP/JOP IDs, creates a local PAC
worker, writes those IDs into that worker, and executes an existing PACIA
gadget. The converter work is therefore not a replacement for physical KRW.
It is a narrower, kernel-mediated alternative for exception PC/LR that avoids
temporarily transplanting PAC context into a helper thread. The old KRW route
remains the fallback until the identity-delivered right is confirmed on the
physical device.

REA now also identifies the EL1 saved-state integrity pair directly in the
exact `com.apple.kernel` image. `ml_sign_thread_state` is at
`0xfffffe0007ab9344`, `ml_check_signed_state` is at
`0xfffffe0007ab9394`, and `exception_return` begins at
`0xfffffe0007ab8178`; the post-validation restore points are
`0xfffffe0007ab81e4` and `0xfffffe0007ab81f8`. The signer stores its PACGA
chain at saved-state offset `0x128` and binds the saved-state address, PC,
CPSR, LR, x16, and x17. The corresponding REA evidence IDs are
`ev_8094f868c3d2c457309d5f86ac1c94ae49674620d14faf2912dc03b3e9eb484f`,
`ev_1d11828440a507a25c083d8ea115bccc68aac9c18a03cb30ec54e8f94efb5bee`,
and `ev_8e7f011df1b0897239e9211f906b80f755cc2c5129d2bac3618816fa6bccc7fa`.
XPF exposes these as the separate `threadStatePAC` set, so finding this
interface is no longer incorrectly gated on the obsolete bad-recovery exploit.

The old bad-recovery route is closed on this kernel. The reconciled XNU source
and exact assembly show that `thread->recover` is only a boolean condition;
the abort handler derives the recovery destination from the immutable
`copyio_recover_table`, checks both table bounds and exact entry alignment, and
only then modifies and re-signs the saved state. KRW cannot turn that boolean
into an arbitrary signed PC. A physical route therefore needs another
legitimate caller that can be driven with attacker-controlled tuple values, or
a separate way to enter the signer with the required EL1 interrupt/SPSel
context.

A focused REA pass also resolves the only signer caller outside the main
thread-state cluster, `0xfffffe0008127df4`, as the arm64 syscall-return
preparer (evidence
`ev_5e64eb14ee78f905525ee974202acf19a0aca8d245122bb2db4bc8a17055d157`).
Its signing branch first authenticates the existing saved state and, only for
`ERESTART`, changes PC by the fixed value `-4` before re-signing. All other
branches update return registers or flags without entering the signer. This is
a legitimate trigger but not a controllable arbitrary-PC signing oracle, so it
does not replace the closed recovery route.

The strongest caller inside the main cluster is now resolved as well. The
function at `0xfffffe0007c5db28` is the exact shipped counterpart of
`thread_state64_to_saved_state` (REA evidence
`ev_439f6dd64f5c7acef7dcb41535685912723cc5fe07fcc45eafd95074db904a6d`).
Its five protected mutations validate the existing saved state before calling
`ml_sign_thread_state` again. The XNU source and shipped assembly agree on the
critical restriction: incoming CPSR condition flags may be copied, but the
mode bits are cleared to EL0. The REA snapshot is
`build/rea-secure-execution-23A341-iphone17,3/kernel-thread-state-signer-primary-caller-rea-snapshot.json`
with SHA-256
`7c3c8bad63826be895c7a598cc17d4243dd014c81cfaee9b52545f2f53af4957`.

For Cyanide's current `TaskRop`, the public thread-state converter is the more
appropriate first physical path than the direct pmap/SPTM wrapper because the
former does not require kcall. `Thread.m` now exposes a fail-closed helper that
accepts an exact target control port and converts raw PC/LR into that thread's
reply representation. Production `sign_state` is not switched yet: the current
exception plumbing uses `EXCEPTION_STATE`, which carries no thread port. The
next integration boundary is `EXCEPTION_STATE_IDENTITY` (or another
identity-bound right source), followed by an explicit check that the received
right is sufficient for conversion. The direct pmap service remains an exact
semantic match for `remote_pac` and a useful VM reference oracle. Neither path
repairs the physical `CNDKernelTaskBridge` by itself:
`ipc_port::ip_kobject` needs destination-diversified kernel data-pointer PAC,
whereas the confirmed SPTM services operate on IA/DA user-pointer keys under a
selected user JOP context.

That VM integration is now implemented. `CNDLabKernelPAC` parses the live
fileset, requires inner `com.apple.kernel` UUID
`03A93373-6498-3F25-8975-04DED251AF1F`, verifies the exact sign, auth, and
`current_thread` instructions, and only then enables the VM-local `0x1b0`
offset. `TaskRop/PAC.m` prefers this pmap/SPTM adapter whenever the lab KRW and
kcall capabilities are active; profile rejection fails closed, while the
physical path and global A17+ offset table are unchanged. The next high-value
PAC work is an actual TaskRop operation-level smoke test followed by tracing
the next distinct PAC-protected consumer that blocks the post-KRW chain.
Separately, the remaining trust-cache work is observation of a natural
entitled load crossing the seven-argument TXM gateway.

For the VM-only PAC path, the bounded live check is:

```sh
python3 scripts/lab/cnd_sptm_pac_probe.py \
  --host VM_IP --kernel-debug-port 62139 \
  --output build/rea-secure-execution-23A341-iphone17,3/sptm-pac-runtime-observation.json
```

The harness rehashes the kernel, TXM, SPTM, and baseline snapshots; verifies
the live kernel UUID and assertion bytes; distinguishes the outer fileset base
from the inner kernel text; requires one exact armed VM provider; reruns the
kernel-call smoke test; verifies all six instructions in the live sign and
auth stubs; and only then performs the synthetic sign/auth calls. It does not
write kernel or target memory.

The provider-independent thread-state path is checked separately:

```sh
python3 scripts/lab/cnd_thread_state_pac_oracle.py \
  --host VM_IP --user mobile \
  --output build/rea-secure-execution-23A341-iphone17,3/thread-state-pac-oracle-observation.json
```

That runner builds both arm64e probes, requires a vPhone guest, validates the
same-task and transferred cross-task results, and rejects any result that does
not explicitly report `kernel_call_used=false`, `krw_used=false`, and no
persistent mutation.

The direct EL1 signer canary has a standalone VM mode, so it does not depend on
Cyanide staying alive in the foreground:

```sh
python3 scripts/lab/cnd_vphone_krw.py standalone-signer-canary \
  --host VM_IP --kernel-debug-port 62139
```

This action creates a temporary root-only provider endpoint, verifies the live
instructions for the signer, validator, exception-return continuation,
allocator, and deallocator, allocates two disposable saved-state buffers,
calls only the signer, checks the expected bindings, frees both buffers, and
removes the endpoint. It never directly invokes the validator: that routine
requires IRQ-masked EL1 with `SPSel == 1`, and violating those preconditions is
a deliberate panic path in this development kernel.

The normal signer-caller boundary can be checked independently:

```sh
CND_VPHONE_ROOT_PASSWORD=... \
python3 scripts/lab/cnd_thread_state_signer_caller_probe.py \
  --host VM_IP --kernel-debug-port 62139 \
  --output build/rea-secure-execution-23A341-iphone17,3/thread-state-signer-caller-observation.json
```

This VM-only harness is deliberately signed with
`com.apple.private.thread-set-state`; an unentitled direct call is terminated
by `kGUARD_EXC_THREAD_SET_STATE` before the mutation. It suspends a disposable
worker, applies each state while the worker cannot execute, restores the
original state, and resumes only after restoration. It uses neither KRW nor
kcall.

## Runtime result on the current VM

The query half is now closed. A minimal probe injected into the existing
`installd` process called external selector 6 with one scalar and a 20-byte
cdhash. The live breakpoint hit `0xfffffe0039242afc`, the captured
`IOExternalMethodArguments` block contained scalar count 1 and structure size
`0x14`, and the call returned success. This exactly matches the REA handler and
dispatch-table reconstruction.

A bounded negative load probe then called selector 2 with no scalar and a
24-byte deliberately invalid trust-cache header. The live breakpoint hit
`0xfffffe003924271c`, proving the load ABI and handler, but returned
`0xe00002c1` at `com.apple.private.amfi.can-load-trust-cache`. Neither the
kernel load helper nor the TXM gateway fired. A scan of running processes and
top-level `/usr/libexec` binaries found no holder of that entitlement, so the
experiment stopped at the genuine policy boundary instead of bypassing it or
installing a cache. The exact raw argument blocks, probe hashes, and negative
hit results are recorded in
`docs/research/rea-secure-execution-runtime-23A341.json`.

Accordingly, the current status is precise: AMFI query and load-entry behavior
are runtime-confirmed; kernel operation `0x0c` and its TXM handler mapping are
static-confirmed; the seven-argument TXM gateway capture remains pending a
natural entitled load event. The VM remains running and the debugger was
detached cleanly.

The subsequent natural-boot observation saw no AMFI load, kernel load-core,
load-helper, or TXM operation-`0x0c` hit through root-shell readiness, although
a normal AMFI query from PID 129 was observed. That is negative runtime
evidence for this boot window: the VM's trust state was already established,
not evidence that the static load route is unreachable.

The PAC runtime gap is now closed for the bounded service class. On the current
boot (the same kernel UUID, slide `0x328d0000`), selector `0x10` signed
synthetic pointer `0x0000000100000000` with both supported key IDs and selector
`0x11` authenticated both results back to the original pointer. Reusing the
key-0 signature with the discriminator incremented by one returned
`0xffffffffffffffff`, matching the static failure path. The complete
machine-readable result is in
`build/rea-secure-execution-23A341-iphone17,3/sptm-pac-runtime-observation.json`.

The reconciled `pmap_sign_user_ptr`/`pmap_auth_user_ptr` wrappers were also
confirmed live with two explicit synthetic JOP keys. The same pointer and
discriminator signed as `0x3b30000100000000` under
`0x434e440100000001` and `0x9e5f000100000000` under
`0x434e440200000001`. Authentication with the matching first key returned the
raw pointer; authentication under the second key did not. This closes the
selected-context behavior without modifying memory or retaining the temporary
CPU key state.

The exact shipped thread-state conversion path begins at
`0xfffffe0007c5de48`. For a normally kernel-signed PC it selects the 16-bit
`ptrauth_string_discriminator("pc")` value `0x7481`, loads the target thread's
`machine.jop_pid` from `thread + 0x1b0`, and calls the pmap wrapper. A focused
REA dossier over the extracted `com.apple.kernel` fileset preserves this as
evidence `ev_e404f8db27f605fb9923acac232ec3ba1d24a362d9edb997c43e820bcfa02a8b`.
A live arm64e worker resolved its own kernel `thread_t`, asked the normal
`thread_get_state` consumer for its PC, and held that exact thread alive while
the provider read its context. Both the process-local selector and the pmap
wrapper produced the same value as the kernel's signed PC, byte-for-byte, and
both authentication paths returned the raw PC. The explicit target-context key was
`0xfeedfacefeedfad3`; no target or kernel memory was written.

REA also closes the inverse half used by the public
`thread_convert_thread_state(..., THREAD_CONVERT_THREAD_STATE_FROM_SELF, ...)`
API. The exact shipped `machine_thread_state_convert_from_user` is at
`0xfffffe0007c5e1a0` (evidence
`ev_bdb4840de9cc5ed6db5a8a8fd83946a742bdc8c65f9886b847a42970e3392c6c`).
It authenticates incoming PC/LR values through the pmap authentication wrapper
at `0xfffffe0007c41c08`, using `thread + 0x1b0` and the `pc`/`lr`
discriminators. The API enters this half with `TSSF_FLAGS_NONE`, so the input
must be signed in the caller context with the plain PC/LR discriminator even
when the state flags carry a user diversifier. Its subsequent to-user half
preserves those flags and signs the result under the supplied target thread's
JOP context with the user diversifier applied. That output is the shape
expected by a Mach exception state reply: the user-diversified value is
present while the kernel-signed PC/LR flag bits remain clear.

Two arm64e probes then exercised that public path without the lab provider,
KRW, or a kernel call. The same-task probe passed, and a second probe transferred
a child process's real thread control right in a Mach port descriptor, asked
the parent to convert PC/LR for it, and had the child authenticate the returned
values in its own process. Both conversions passed on the current iOS 26 VM.
The combined observation is
`build/rea-secure-execution-23A341-iphone17,3/thread-state-pac-oracle-observation.json`;
the same-task and cross-task probe hashes are respectively
`2c0f6cd69cb90f2e20847611f87cc1c7de26187c22dff5a92209c2b927536e01`
and
`906a27897af5277c320e0c9f46a5e80b59eb845ef741f28e898e5da67bc68af5`.
This confirms cross-task conversion when a genuine control right is already
available. It does not establish how a stock process obtains that right.

A third probe closes the VM exception-delivery handoff. A child installs
`EXCEPTION_STATE_IDENTITY`, triggers a breakpoint, and blocks. The parent
receives the identity message's thread and task ports, passes that exact thread
port to the FROM_SELF converter, and replies with the converted state. The
child resumes at the requested raw PC. The iOS result has `receive_kr=0`,
`convert_kr=0`, `reply_kr=0`, and `child_resumed=true`; its binary SHA-256 is
`e7338d72d6791393bdf2daa8d23272e8c5b7cce6c179be6aab4ea1b485ff990f`.
It uses the same `EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES` behavior as
current TaskRop, and validates message ID 2407, two port descriptors, flavor 6,
and 68 state words before conversion. It establishes the delivered right only
on this developer-enabled vPhone, not on a physical stock boot.

The app-side adapter was then compiled into a dedicated integration probe and
run through the same existing KRW socket while the exact worker remained
alive. It resolved the live fileset base `0xfffffe00398d4000`, slide
`0x328d0000`, and UUID above; selected `thread + 0x1b0`; and reproduced normal
consumer value `0xca1b800102f71008` from raw PC `0x0000000102f71008`.
Authentication returned the raw PC. This establishes the VM lab-KRW PAC
adapter used by TaskRop, not merely a parallel standalone implementation.

The standalone EL1 signer canary subsequently passed on a fresh boot with
fileset base `0xfffffe0046ed4000` and slide `0x3fed0000`. The live signer was
`0xfffffe0047989344`. Repeating an identical tuple in the same scratch state
returned `0xb85b574200000000` both times. Moving that tuple to a different
saved-state address returned `0xb29f62ec00000000`; changing the mode/control
tuple returned `0x94b21da100000000`; changing x17 returned
`0x5a354d7c00000000`. This runtime result confirms the REA binding model and a
callable VM oracle. It does not transfer the VM's patched syscall-439 kcall to
stock hardware, and it does not establish a validator bypass.

The normal caller probe then ran on the same kernel UUID with inner text
`0xfffffe0049c70000` and slide `0x42c68000`. With the VM-only private
entitlement, `thread_set_state` accepted the exact live kernel PC
`0xfffffe004a7201e4` and read it back unchanged while CPSR remained EL0. A
second request supplied CPSR `0x00000005`; conversion preserved that request,
but the saved state read back as `0x00000000`. Thus the normal caller does
reach and re-sign through `thread_state64_to_saved_state`, but it sanitizes the
return mode to EL0. The target never executed a test state, its original state
was restored, and the full observation is in
`build/rea-secure-execution-23A341-iphone17,3/thread-state-signer-caller-observation.json`
(SHA-256
`d54d16d7a8265fcb9663703e012d69605409ee6464b1b999ac226e7cbc38020f`).
This closes the route as an EL1 exception-return or kcall primitive: a kernel
address carried in an EL0 PC slot is signed data, not kernel execution.

This also corrects two earlier inferences. First, the high-half
`0x7481000000000000` value exercised a valid but different discriminator; it
was not the normal kernel-signed-PC branch. Second, the current repeated scope
run produced the same IA/DA signatures in two short-lived processes and a
third process authenticated them, so strict per-process scope is not
established on this VM. The earlier differing-signature run is retained as
historical evidence, but it is not the current conclusion.

There is one direct current-KRW consequence: Cyanide's iOS 26 A17+ table uses
`off_thread_machine_jop_pid = 0x1c0`, while this exact 23A341 vPhone kernel
uses `0x1b0` (and therefore `rop_pid = 0x1a8`). That discrepancy needs an
identity-gated VM override and now receives one through `CNDLabKernelPAC`; it
must not be generalized to physical-device kernels without matching evidence.
The consumer result removes one VM user-pointer PAC uncertainty, but it is
still not arbitrary kernel PAC freedom, an SPTM write primitive, or
executable-memory freedom.
