# Implicit state machines

Date: 2026-11-09
Scope: static architecture review plus the additive queue- and KRW-lifecycle slices in this change. No VM or physical-device validation is claimed.

## Design decision

Do not replace the app's safety-critical state with one global enum. The queue, KRW recovery, RemoteCall, and icon journals already encode distinctions that must remain independent. The highest-leverage shared UX/DX/AX improvement is instead:

1. Keep each authoritative state owner and its recovery evidence intact.
2. Project each family's durable/process-local state into an immutable snapshot: `CNDQueueExecutionSnapshot` for execution and `CNDKRWLifecycleSnapshot` for KRW evidence.
3. Give those projections stable symbolic fields, human guidance, control availability, and a plist-safe `agentRepresentation`.
4. Let Queue Review, the queue popup, Activity, the existing Settings Quick Actions footer, and host command JSON consume the projections without changing durable schemas, action executors, callback tokens, acquisition, recovery, parking, or the exact 3–2–1 respring countdown.

`PackageQueue.executionSnapshot` is read-only and derived on demand. It is not a second store and must not be persisted. `legacyPendingCount` preserves the existing UI continuation sentinel; `pendingActionCount` reports actual unfinished records.

## Inventory and ownership

| Family | Authoritative state and hidden orchestration | Boundary / disposition |
|---|---|---|
| Durable queue actions | `CNDQueuedTransaction` enums, immutable action checkpoints, atomic plist writes | Keep as the sole durable execution authority. Successful checkpoints are never replayed. |
| Queue asynchronous execution | `commitInFlight`, ordinary/coordinated settings waits, resume-before flag, token and toggle IDs, unreadable-store flag in `PackageQueue.m` | Now named by the read-only snapshot. Tokens and callback flags remain execution guards, not persisted presentation state. |
| Queue presentation | Review button derivation, popup categories, Activity terminal/countdown/retry flags and countdown generation | Review/popup and nonterminal Activity text now share the snapshot. Countdown generation and terminal notification ownership remain local to Activity. |
| Package desired/applied state | Installed, queued intent, defaults enablement, `settings_tweak_is_applied`, one-shot versus persistent package kinds | Never collapse enabled, queued, applied this epoch, and persistent into one Boolean. |
| Transient applied state | `CNDTransientAppliedState` PID/boot/KRW-generation markers and prepared transaction transition | Persistent SnowBoard records and process-local fixes deliberately have different survival rules. |
| Icon publication | `CNDIconThemeTransaction` prepared/active/restored/partial/drift/superseded/invalid journals and batch promotion | Preserve journal dispositions and evidence. Queue completion does not itself prove every journal is clean. |
| IconServices consumer lifecycle | Running bit, PID observation/install/block/defer fields, stable samples, attempts, stage strings, repair reservations | Keep PID incarnation and transport evidence distinct from persistent icon journals. |
| Settings action ownership | Atomic run/cleanup locks, pending-only mode, coalesced rerun, queue token completion | One owner at a time. Generic settings completion is not a queue acknowledgement. |
| SnowBoard Automatic Repair | Preference and durable-active reconciliation, mutation semaphore, pending reason/deadline/attempt/immediate/running flags, cooldown, power and wake timers, substantial-repair handoff | Scheduler state is separate from requested theme state. It never autonomously acquires fresh KRW. |
| Respring foreground return | **Removed 2026-11-10.** No pre- or post-respring Cyanide activation, no bounded foreground retry ladder, no process-lifetime bridge for a pending respring | Cyanide never injects into SpringBoard to launch itself, never recovers parked KRW unattended, and never extends its own background lifetime to bridge a respring. A controlled respring starts only from Cyanide's own live window; post-respring work runs only when the user reopens the app and continues the saved queue. |
| Live tweak loops | Per-family `running` and `stop_requested`, generations, tick/failure limits, background/deferred cleanup, app-churn pauses | Each loop retains its own cleanup contract; no shared running flag is safe. |
| Keepalive audio | Requested/running, observers installed, interrupted, media-reset rebuild, recovery generation | `ds_keepalive_is_running()` also requires actual playback. A scheduled recovery is not playback proof. |
| KRW acquisition, parking, recovery | Explicit exploit outcomes, termination dispositions, full-park booleans, durable recovery/transfer/rearm results and stage strings | Now named by the read-only KRW snapshot. Partial park or saved metadata is not proof of a live anchored generation. |
| KRW lifecycle observation | Latest immutable observation cache in Settings, publication at existing ownership/result boundaries, generation-scoped preparation evidence | Cold reads never call checked readiness or execute lifecycle work. Unknown is not `not-ready`; observation never acquires, recovers, parks, or cleans up. |
| SpringBoard RemoteCall | Initialization failure stage, session readiness/sandbox flags, health timestamps/failure counters, PAC/identity diagnostics, dispatch disposition | Dispatched does not prove process exit. Transport and evidence states stay separate from queue status. |
| Document/theme/font import | Pending picker mode/role and reload flags | Input selection is pending UI intent, not an applied package state. |
| Probe rows and host commands | Independent `IsRunning()` implementations, completion callbacks, external KRW action ownership, once-only result delivery | Probe behavior and its evidence contract are unchanged by this work. |
| Update checker | Process-local auto-check flags plus persisted last-check, skipped version, snooze deadline | Network failure intentionally does not consume the throttle window. Manual checking is a separate UI flow. |
| Weather/location | Coalesced completion arrays and independent location/weather in-flight flags | Keep acquisition and fetch phases separate; coalescing is not a global request lock. |
| Application/termination lifecycle | Scene/background flags, external command task ownership, termination cleanup state/disposition | Process exit and queue completion are different events. Termination must retain the explicit KRW disposition. |

## Queue snapshot contract

Stable `phase` values:

- `empty`
- `collecting`
- `running`
- `waiting-for-settings`
- `awaiting-respring`
- `ready-after-respring`
- `retryable`
- `completed`
- `unreadable`

Stable `primaryAction` values: `none`, `confirm`, `continue-after-respring`, `retry`, `wait`, `respring`.

The `reason` field separates synchronous work, ordinary settings completion, coordinated pre/post-respring settings completion, a saved restart boundary, interrupted execution, failure, and an unreadable durable store. Controls are derived from the same captured state: `canCommit`, `canEdit`, and `canClear`.

An `AwaitingRespring` checkpoint enters the existing Activity countdown instead of issuing a premature continuation commit. Only a verified restart plus explicit continuation may run post-respring work. A stopped `Running...` state is projected conservatively as retryable; hydration still performs the authoritative interrupted-action recovery.

Accessibility identifiers `queue.popup`, `queue.confirm`, `queue.clear`, and `queue.activity.status` provide stable UI-automation anchors. Structured consumers should use `agentRepresentation`, not parse display text.

## KRW snapshot contract

`CNDKRWLifecycleSnapshot` is a pure-Foundation immutable projection. It does not own execution and must never be persisted. Its stable `phase` values are:

- `unavailable`
- `no-primitive`
- `recovery-available`
- `busy`
- `live`
- `needs-attention`
- `terminating`
- `terminated`

Stable `nextAction` values are `none`, `wait`, `acquire`, `recover`, `retry-recovery`, `rearm`, `review`, and `reboot`.

The `reason` field preserves distinctions that a Boolean `krwReady` cannot: unchecked readiness, a live but unarmed generation, retryable recovery, reusable-bearer consumption failures, partial park evidence, an unsafe-unverified acquisition barrier, and terminal cleanup disposition. Primitive readiness, next-process recovery, acquisition outcome, parking, exact-generation anchoring, and RemoteCall remain separate evidence groups in `agentRepresentation` (schema version 1).

Park and anchor evidence is tri-state: `unknown`, `not-exact`, or `exact`. A full recoverable-boundary proof now reads the forged control link and restored original control checksum independently, re-parks the complete RW filter region, and only then records the control-socket readback result, returned length, and comparison. Ordinary per-operation readback remains operational evidence with `ReadbackSemantics=unproven-target`; it is not promoted to a full termination proof by itself. A saved record is not proof of the current launchd holder, live-plus-armed is not proof of respring continuity, and RemoteCall readiness never implies KRW readiness. Unknown primitive readiness does not satisfy the no-primitive branch of `canRespring`. If a park transaction supplies only some observations, the snapshot reports `live-park-evidence-incomplete`; a false full-park result reports `live-partial-park-evidence`. Neither partial form is presented as ordinary live state.

Settings publishes a new cached snapshot only at existing lifecycle ownership/result boundaries. Checked readiness is captured only where an actual lifecycle owner already performs validation; a cold getter or UI render does not call `kexploit_krw_ready()`. Scene resign/background callbacks never create a process boundary or close live KRW; cleanup remains explicit, respring-gated, update-gated, or actual termination work. Preparation evidence is retained only for its exact generation ID and handoff serial. Initial acquisition stores one unbound reusable Control/RW lookup bearer pair during its single launchd handoff. Every recovered process consumes the same strings into new process-local handles, validates the exact fileports and socket identities, read-verifies the defaults record and independent backup, and proves the exact launchd holder; recovery never initializes launchd RemoteCall or rotates tokens. If bearer consumption, backup readback, or holder proof fails, the primitive is admitted locally only when its live validation already succeeded, while controlled respring/update handoff stays refused. Merely finding token strings in the record never promotes the armed flag without the independent backup and exact holder proof. `CNDKRWRecoveryObservationForStage` centralizes bounded stage classification without performing recovery or storage access: only a definitive boot identity change is stale; token-consumption failures, missing same-boot holders, readiness failures, and every rejected or unverifiable park preserve their evidence and remain retryable. Historical `unusable-pair-released` evidence is also classified as retryable because socket rejection did not prove launchd released its fileports. The observation path never calls acquisition, recovery, rearm, parking, termination, or cleanup.

The authenticated `krw-diagnostic` live command is deliberately outside that execution path. It returns the cached lifecycle projection, redacted persistence/anchor/termination evidence, and cross-thread cached socket-stage observations without beginning a lifecycle action or performing readiness, recovery, acquisition, parking, or cleanup. Socket target writes, actual RW reads, returned lengths, direct park writes, control readback, and comparisons are recorded separately. Legacy generation IDs containing addresses/service identifiers are suppressed. Raw log buffers, sandbox tokens, fileport names, and kernel pointers are never returned. The host helper is `scripts/lab/cnd_live_probe.py krw-diagnostic`; it does not open the app container.

The existing six-row Quick Actions section now uses the snapshot's footer text and refreshes on `kSettingsKRWLifecycleDidChangeNotification`; no action rows were added. `cnd-state.json`, busy command results, and completed command results add `krwLifecycle` from the latest cached observation. Legacy `krwReady: -1` remains unchanged, and the command timer still performs no KRW readiness poll. These controls are presentation hints only: the existing executors repeat their authoritative checks.

## Verification boundary

The native queue snapshot fixture covers collecting, synchronous execution, all three settings waits, restart boundary, continuation, zero-action sentinel wording, retryable failure, interrupted execution, completed cleanup, unreadable storage, control availability, and plist-safe agent output. Existing queue tests continue to guard checkpoint ordering, token scoping, recovery, and the exact countdown.

The native KRW fixture covers unknown and absent readiness, busy ownership, live/armed and live/unarmed generations, saved and recovered generations, retryable recovery, burned grants, partial and exact park/anchor evidence, unsafe-unverified quarantine, termination dispositions, independent RemoteCall state, control availability, immutable copying, and plist-safe agent output. Structural tests pin the nonblocking getter/timer, legacy host JSON key, additive lifecycle payloads, six-row Settings contract, and preservation of actual acquisition/recovery call paths.

These are implementation, host-test, and unsigned-build results only. They do not establish VM-proved or physical-proved behavior.
