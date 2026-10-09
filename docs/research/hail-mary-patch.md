# Hail Mary shared-page patch

This is the reversible mutation stage built on top of the read-only
`CNDHailMaryProbe` physical-page proof. It is deliberately pinned to
`iPhone17,2` running build `23A341`; every other device/build is refused.

## Exact mutation

- Unslid user VA: `0x1be102ef0`
- Runtime user VA: derived on every operation from the live proof and its
  shared-cache slide
- Original instruction: `0x1a9f17f4`
- Replacement instruction: `0x52800034` (`mov w20, #1`)
- Guard: 188 bytes beginning at physical-frame offset `0x2e5c`
- Instruction offset in the guard: 148 bytes
- Original guard SHA-256:
  `542063d6c8ea82afbe734ace1895ba0f2b7ab15160c6053176604644741f20d5`
- Patched guard SHA-256:
  `5d11085e066693f14771fea0c97d55ab593bd6468856bfbed2463224dd01569f`

No live physical address or physmap KVA is compiled into the writer. Each
operation derives both from the current read-only proof and refuses a changed
frame, leaf entry, process identity, byte window, or hash. SpringBoard and
Spotlight must report one matching runtime VA and slide, and
`runtime VA - slide` must equal the exact unslid VA above.

## Transaction

Apply requires the exact original guard; Restore requires the exact patched
guard. Both operations:

1. acquire/reuse validated KRW;
2. ensure Spotlight has one validated live identity, opening it through the
   bounded SpringBoard `_toggleSearch` call and acquiring its assertion in that
   same call when it is absent;
3. run the full object, pmap, physical-frame, and byte proof;
4. atomically save and fully sync the prewrite journal file and its parent
   directory;
5. record that SpringBoard `mlock` is deliberately skipped; the earlier exact
   PID/proc/task-bound RemoteCall returned `EPERM` and never reached the write;
6. atomically save and fully sync the `armed-legacy-landing-no-readback`
   journal;
7. reproduce the legacy pre-write conditioning that produced the first known
   successful landing: read and compare the full 188-byte guard immediately
   before mutation, then call the original `kwrite32` route. That route performs
   its 8-byte read/merge followed by the checked writer's 32-byte
   read/retarget/write sequence;
8. perform no physical-aperture read, full postflight proof, rollback write, or
   RemoteCall after the mutation dispatch.

The no-readback boundary is intentional. The mutation may panic while the
physical store is in flight, so a panic does not prove whether the first store
beat landed. If the call returns, the report records only that the dispatch
returned—not that bytes were verified. Behavioral validation and
`verify-patched` are separate
operations, and neither Apply nor Restore automatically resprings. If the
system remains alive, Apply asks the operator to restart Spotlight alone for
behavioral validation. Reports distinguish whether `mlock` was attempted,
whether a page wire exists, write-primitive invocation, transport completion,
omitted physical readback, and direct target-process mutations (always zero).

## 2026-10-07 panic evidence: the text-page store never lands

Seven sampled panics from the October 7 2026 Apply attempts (18:51-23:14,
distinct boot sessions) share one identical signature:
`Unexpected fault in kernel physical aperture`, with `esr 0x9600004f` (EL1
data abort, **write**, level-3 leaf PTE **permission fault**), `far` equal to
the journal's aperture `targetKernelVirtualAddress` (low 14 bits `0x2ef0`),
`x3 = 0x9494d59b52800034` (the merged word with the replacement loaded but
never stored), and the panicked task always the Cyanide `setsockopt` copy.
The physical aperture maps the guarded dyld-cache **text frame read-only**;
the store aborts on the first beat, the code word never changes, and the
write-dispatch/journal window above can never distinguish a landed write.
The "write may panic while in flight" phrasing above is retained
chronologically; the deterministic permission fault and its consequences —
including why intermittent transparency observations were the method's
natural early return paths, not patch evidence — are recorded in
[`hail-mary-data-page-experiment.md`](hail-mary-data-page-experiment.md),
along with the follow-up identical-bytes data-page experiment that tests
whether non-executable shared-cache pages accept aperture writes.

The app wrapper may repeat only the read-only preflight, at most three times
in the same process and KRW session, when process inspection reports the exact
`invalid-or-unstable-entry-list` transient. A report with any write invocation
is never admitted to that retry path.

There is no Hail Mary public address/value writer. `CNDHailMaryPatch.m`
contains one build-locked `kwrite32` call after an exact live guard comparison,
and the existing observation-only probe remains write-free.

## Entry points

Settings exposes **Apply Hail Mary Patch** and **Restore Hail Mary Patch**.
Mutation operations deliberately leave SpringBoard alive. The lab launch
arguments are:

- `--hail-mary-apply`
- `--hail-mary-restore`
- `--hail-mary-verify-patched`
- `--hail-mary-verify-original`

The verification arguments never write or respring. Mutation operations also
avoid automatic respring. This experiment performs the Apply write without a
SpringBoard-owned page wire and may therefore panic or restart userspace.

## Initial physical-device run

The first Apply attempt on iPinky Max refused a transient SpringBoard VM-entry
snapshot as `invalid-or-unstable-entry-list`; its patch report recorded zero
write invocations and zero physical code-word mutations. The first retry was
incorrectly performed by force-terminating the process that still owned live
KRW and launching a replacement. Userspace restarted before the patch module
began. A later clean launch after installing the retry-safe wrapper also
restarted userspace during KRW acquisition, before the patch module produced a
new journal. Live attempts were stopped for the boot.

The journal retrieved after both restarts remained byte-for-byte the original
refusal report (SHA-256
`c6f8253b707a2c0cd6ff476bf53fad370aa301313233c3e01bf29aae990bd7be`):
`confirmed=false`, `kernelWritePrimitiveInvocationCount=0`,
`sharedPhysicalCodeWordMutationCount=0`, and
`targetProcessDirectMutationCount=0`. Therefore no shared-cache patch was
applied and no restore was necessary. A later live attempt must start from a
fresh boot whose KRW acquisition is independently known healthy; retries must
stay inside that one living process/session.

The next safe lab sequence is: fully reboot the device, open the installed app
normally, run **Hail Mary Physical Proof** to establish and validate KRW, and—
without terminating Cyanide—run **Apply Hail Mary Patch** so it reuses that
same session. Do not use `--terminate-existing` between those actions.

On that fresh boot, the read-only proof succeeded at runtime VA
`0x1bebcaef0` with slide `0x00ac8000`. The first writer build correctly made
zero writes but refused it because it had embedded the previous boot's runtime
VA `0x1bfadeef0`. Both runtime addresses subtract to the same exact unslid
target `0x1be102ef0`. The writer now derives the runtime VA from the live proof
and validates that invariant instead.
