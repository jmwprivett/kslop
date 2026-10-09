# Durable queued system-change coordinator

Status: production implementation complete; static tests and unsigned
iPhoneOS build pass. Physical-device end-to-end validation remains required.

## Contract

Cyanide represents each queued mutation as a schema-validated action in
`Application Support/Cyanide/Queue/QueuedChanges.v1.plist`. Writes are atomic.
Unknown schemas and unrecognized actions fail closed and remain on disk for
diagnosis.

The deterministic execution order for a transaction that actually requires a
respring is:

1. SnowBoard Remix Apply or Restore publishes and verifies persistent
   IconServices records.
2. Font Changer and other explicit pre-respring filesystem mutations run.
3. Cyanide records the exact SpringBoard PID, boot epoch, transaction UUID,
   and KRW generation, then announces the 3–2–1 respring countdown.
4. The user reopens Cyanide and selects **Continue After Respring**.
5. Cyanide reacquires or recovers KRW and verifies either a different
   SpringBoard PID or a changed boot epoch.
6. Ordinary adaptive package actions run and report their real asynchronous
   completion.
7. Successful SnowBoard, Font, and SBCustomizer state is bound to the verified
   new SpringBoard PID before any optional presentation repair begins.
8. SpringBoard Fixes and Spotlight Fixes run as independent target actions.
   SpringBoard repair precedes Spotlight repair. The transparency toggle
   controls the presentation redirects and Clock/Calendar work, while the
   Spotlight action always installs its SpringBoard-owned lifetime assertion.
   Immediately before the bounded Spotlight repair, Cyanide opens one
   identity-bound SpringBoard RemoteCall, validates and invokes the global
   `-[SpringBoard _toggleSearch]` path on SpringBoard's main thread, waits for
   two samples of the same Spotlight identity, and acquires the RunningBoard
   assertion before closing that same session. It then confirms the returned
   PID is still stable before opening only the separate Spotlight repair
   session; Cyanide's foreground/background state is diagnostic, not a gate.
9. The transaction is marked
   complete and its durable file is removed.

Both target-fix actions are adaptive. When queued alone they run immediately
in the current process epoch and do not create a respring. When another action
establishes a real restart boundary, they resolve after it, with Spotlight
last. Likewise, an Apply/Restore or Font transaction with no remaining
after-respring actions is durably completed before the countdown; it never
leaves a synthetic empty “1 pending change” continuation behind.

No action opens a per-icon session. Spotlight launch and assertion acquisition
share one bounded SpringBoard session, and the assertion remains owned by
SpringBoard after that session closes. No production watcher, recursive view
scan, arbitrary settle delay, or open RemoteCall channel is part of the
coordinator.

## Recovery rules

Every action is checkpointed as Running before mutation and Succeeded or
Failed afterward. Relaunch turns an interrupted Running action back into a
retryable state without replaying actions already checkpointed Succeeded.

An ordinary transaction whose actions were all durably successful may be
closed during hydration. A boundary-only transaction commits its desired
SnowBoard/Font state before respring and authorizes exactly the next
SpringBoard PID to adopt it, so it can also close without a fake continuation.
A coordinated transaction with real after-respring work remains retryable
until that work and its applied-state boundary have finalized.

Optional SpringBoard/Spotlight presentation repair failure does not roll back
or hide independent actions that already completed. Their transient state is
checkpointed first, leaving only the failed presentation action retryable. A
stopped or failed saved plan can be cleared explicitly. One Clear Queue
operation transactionally removes every package and standalone intent; if a
queued preference cannot be reverted or the durable file cannot be removed,
the preference rollback restores the prior queue rather than partially
clearing it. Already-executed actions are never reversed.

The transient applied-state file is
`Application Support/Cyanide/State/TransientAppliedState.v1.plist`. It accepts
only the SnowBoard Remix, Font Changer, SBCustomizer, SpringBoard Fixes, and
Spotlight Fixes keys. A
coordinator-owned respring carries persistent SnowBoard/Font values to the
verified new SpringBoard PID. Apply and Restore update the corresponding value
after that action succeeds. SBCustomizer is deliberately cleared as soon as a
SpringBoard boundary is prepared because its mutation is process-local; it is
recorded active for the replacement PID only when an adaptive post-respring
SBCustomizer reapply actually succeeds. A standalone SBCustomizer run records
the same state directly against the current verified SpringBoard epoch.

On a new Cyanide process launch, recovery of the previously parked KRW
generation is attempted without starting a fresh exploit. Failed continuity
clears process-local markers but retains SnowBoard: its verified persistent
IconServices records survive app, SpringBoard, userspace, and full-device
restarts, and only a successful explicit Restore clears that marker. Any later
fresh KRW acquisition also clears stale process state before acquisition and
never treats the new primitive as continuity proof. With continuity proven, a
SpringBoard PID change preserves SnowBoard/Font and clears SBCustomizer plus
both process-local fix actions. A Spotlight-only PID change clears only
Spotlight Fixes. A full reboot retains SnowBoard while clearing every
process-local marker, including the edge case where SpringBoard receives the
same numeric PID. Installer badge rendering remains a deterministic disk read;
reconciliation runs once per Cyanide process launch rather than on every
foreground event.

## Validation

The structural suites cover durable encoding, catalog shape validation,
action admission, adaptive fixes routing, boundary-only retirement, real
completion callbacks, the exact 3-second countdown, restart-boundary
verification, Spotlight assertion ABI/retention, applied-state rollover, retry
idempotence, and absence of production watcher starts.

The final physical-device pass should exercise:

1. Queue SnowBoard Apply, Font Apply, at least one ordinary tweak, and
   SpringBoard Fixes and Spotlight Fixes together.
2. Confirm SnowBoard then Font execute before one 3–2–1 respring.
3. Reopen Cyanide, recover KRW, and continue the saved queue.
4. Confirm ordinary work completes before SpringBoard repair, then Spotlight.
5. Confirm SnowBoard, Font, SBCustomizer, SpringBoard Fixes, and Spotlight Fixes
   show the expected ACTIVE state and Spotlight remains resident after Cyanide
   exits normally.
6. Repeat with SnowBoard Restore and Font Restore.
7. Interrupt once before respring and once after respring to verify retry skips
   successful actions.
8. Perform a userspace restart and a full reboot; confirm SnowBoard remains
   ACTIVE while SBCustomizer and both presentation-fix markers clear. Then run
   Restore and confirm that it alone clears SnowBoard's ACTIVE state.
