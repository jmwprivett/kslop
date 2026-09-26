# SpringBoard-resident repair supervisor feasibility

Date: 2026-09-24
Branch: `research/vphone-ios26-spotlight`
Baseline: `918395db4b8a20ffeb15ba0dfdd3b34e0d89ca89`

## Executive conclusion

The minimum goal is feasible, but it is **not implementable with the set of
physical-device capabilities that is presently proved in this tree**.

The hard boundary is narrow: SpringBoard needs one private, valid executable
mapping containing a position-independent supervisor entry point. Once that
entry point exists, the current RemoteCall machinery can call `pthread_create`
in SpringBoard, the thread can detach itself, and the current KRW and
RemoteCall code can be compiled into that resident payload. A VM proof in this
investigation demonstrated the downstream lifetime and event design: the
SpringBoard thread survived the installing client and Cyanide itself exiting,
observed four replacement Spotlight PIDs, debounced application identity, and
stopped cleanly.

Physical iOS 26 does not yet have a proved way to admit that executable page.
The production physical path deliberately returns to Apple-signed, data-only
IMP redirects before reaching the historical signed-vnode mapper. The mapper
has careful offset, `F_CHECK_LV`, RX `mmap`, readback, BTI, and PAC handling,
but there is no retained physical result proving that SpringBoard accepted and
executed its page. SpringBoard also has no JIT or unsigned-executable-memory
entitlement.

The first physical test does not need a new kernel-call primitive: Cyanide can
request `PT_ATTACHEXC` against the exact SpringBoard PID, detach immediately,
and then test a fresh SpringBoard-private anonymous W-to-RX page. If attach
authorization succeeds, XNU itself invokes `cs_allow_invalid` for SpringBoard.
The result is persisted before that SpringBoard PID is terminated so the
irreversible allowance does not outlive the experiment. The same attach branch
also invokes it for the tracing Cyanide process, so the probe parks KRW and
terminates Cyanide after saving the result. The fail-closed probe is exposed
by a button in the base Cyanide UI; it does not open or inject Spotlight and
has not been installed or run on the physical device.

If `PT_ATTACHEXC` is denied, or if it does not admit the RX page, the first
narrow exploit escalation to test is **one build-specific, PAC-correct kernel
invocation of `cs_allow_invalid(exactSpringBoardProc)`**, not root, a forged
task port, a general kernel-call API, or a daemon. The exact 23A341/D47AP
unslid entry is now identified as `0xfffffff0086e6b68` (kernel-base offset
`0x16e2b68`). This is a candidate permission transition, not a device-proved
success method. In the published XNU implementation, that operation does more
than set
`CS_DEBUGGED`: it clears `CS_HARD|CS_KILL`, calls `vm_map_cs_wx_enable`, disables
map switch protection, and marks the VM map code-sign-debugged. Those
map/pmap/code-sign-monitor transitions are why a raw write to `p_csflags` is
not equivalent. The call must be followed by an actual SpringBoard-local RX
mapping and execution probe; its return value or `CS_DEBUGGED` alone is not a
pass.

There are two explicit reasons the call itself can still fail on the target
device. `cs_allow_invalid` first runs `mac_proc_check_run_cs_invalid`; a denial
returns false without performing the transition. Separately,
`vm_map_cs_wx_enable` can fail at the pmap/code-sign monitor boundary, and the
published function merely logs that failure before continuing. Consequently,
even a changed proc flag or superficially successful final return does not
prove executable-page admission. If either condition occurs on 23A341, the
smallest escalation must move down to the exact target-local VM/pmap operation
which failed; it must not be broadened automatically into a general kcall.

There remains a second engineering gate, not currently evidence of a needed
exploit escalation: portable ownership of the launchd-held KRW fileports.
Cyanide can recover them in Cyanide, but SpringBoard recovery and
cross-process serialization are unproved. A VM dummy-fileport test consumed a
Mach lookup token inside SpringBoard but `bootstrap_look_up` returned 1100
(`BOOTSTRAP_NOT_PRIVILEGED`); the root-issued token/namespace used by that
disposable test is not the launchd-issued token path used by production, so the
result does not disprove the production design. It does prove that merely
knowing a randomized service name, or consuming an arbitrary issuer's token,
is insufficient.

Do not put the full theme engine in SpringBoard. Use one resident process but
two logical components: a tiny observer/scheduler and a serial one-bundle
repair executor. The executor should reuse the existing update-rebase and
publisher code against staged, pre-rendered structured payloads. A separate
persistent OS process is unnecessary unless bounded file grants to the cache
and journals fail; adding such a process is the daemon-level escalation this
design is intended to avoid.

## Scope and evidence standard

Three statuses are distinguished throughout this document:

- **Implemented** means code for the capability exists in the tree.
- **VM-proved** means this investigation observed it in the vPhone VM. The VM
  uses a root task/RPC provider and does not reproduce physical code-sign or
  corrupted-socket behavior.
- **Physical-proved** means a retained result demonstrates the exact operation
  on physical arm64e. Source comments and a result message that could be
  produced on success are not treated as a retained result.

No production publisher, presentation mapping, or journal was changed. The
experimental implementation remains under `scripts/lab/`; the base app has a
thin compile wrapper and one explicit Settings button:

- `scripts/lab/cnd_resident_supervisor_probe.m`
- `scripts/lab/cnd_resident_supervisor_probe.py`
- `scripts/lab/cnd_fileport_anchor_probe.c`
- `scripts/lab/cnd_physical_cs_allow_invalid_probe.m`
- `scripts/lab/cnd_physical_cs_allow_invalid_probe.py`
- `Cyanide/CNDPhysicalCSAllowInvalidProbe.{h,m}`
- the `Run SpringBoard RX Probe` row in `Cyanide/SettingsViewController.m`

The resident VM probe does not perform KRW, RemoteCall repair, IconServices
publication, method replacement, or a real application update. The physical
permission probe performs only read-only KRW identity checks, one bounded
SpringBoard RemoteCall, and a private anonymous-page nonce. It never opens or
contacts Spotlight, installs a consumer hook, or touches IconServices data.

## Current capability inventory

| Capability | Available now? | Needed by route | Evidence | Missing piece |
| --- | ---: | ---: | --- | --- |
| KRW after Cyanide exits | Partial | All physical routes | `persistence.m:340-426` registers randomized launchd-held fileports; `:538-633` recovers and validates them in a later Cyanide process | No SpringBoard recovery result; VM provider is a root RPC socket, not the corrupted sockets |
| Recover launchd-held fileports in SpringBoard | No proof | Resident physical host | Recovery requires lookup tokens, `bootstrap_look_up`, and `fileport_makefd` at `persistence.m:555-604`; disposable VM lookup returned 1100 after token consumption | Test with the exact launchd-issued tokens and production registration namespace, then validate the corrupted descriptors after Cyanide exits |
| Allocate persistent SpringBoard data | Yes | A, B, D | Current RemoteCall calls target `mmap`/`malloc`; the VM probe retained context and a heartbeat counter in SpringBoard | Production layout and cleanup protocol only |
| Map valid executable code in SpringBoard | VM only | A, B, D | VM root injection and direct-task code can execute; physical production explicitly uses data-only Apple IMPs at `CNDIconServicesConsumerHook.m:2406-2415` | One physically accepted SpringBoard-private RX payload page |
| Start detached SpringBoard pthread | VM-proved, conditional physically | A, D | VM probe created/detached a pthread and survived installer exit; RemoteCall can invoke target pthread APIs | On physical, a valid executable start routine; thread should self-detach on arm64e |
| Observe Spotlight PID changes | VM-proved | All resident routes | `FBProcessManagerObserver` add/remove callbacks fired; add arrived before `finishedLaunching` and settled later | Production callback in the accepted payload and final kernel proc/task identity check |
| Initiate EXC_GUARD RemoteCall from SpringBoard | Implementable, unproved | Spotlight and update repair | RemoteCall is ordinary host code over KRW; its state and universal mutex are process-local | Portable KRW in SpringBoard, minimized link set, and an interprocess ownership protocol |
| Observe application-update completion | Static API found; simulated debounce proved | Update repair | `LSApplicationWorkspaceObserverProtocol -applicationsDidInstall:` and `FBSApplicationLibrary` update/replace observers exist in 23A341; VM simulated two stable samples | One disposable real install/replace event to confirm callback queue and post-install timing |
| Access staged theme data/journals | Not proved in SpringBoard | Update repair | Launchd can issue file extensions; VM SpringBoard consumed a `/var/tmp` grant | Two bounded grants or inherited directory FDs: read-only immutable cache, read-write transaction journals |
| Serialize KRW use between hosts | No | Any multi-client route | `kexploit_opa334.m:876` has only a process-local `pthread_mutex_t`; `RemoteCall.m:64` is also process-local | Single-owner lease/broker, or a crash-releasing interprocess file lock held across whole sessions and read-modify-write operations |
| Repair one updated bundle safely | Core logic yes; entry point no | Update repair | Fingerprinting and guarded rebase exist in `CNDSnowBoardRemix.m:96-156` and `:1195-1328` | Extract a one-bundle API from the full Apply coordinator; stage only that bundle's payload matrix |

### What launchd persistence actually provides

`krw_persistence_transfer_to_launchd()` does the following:

1. creates randomized control and RW service names;
2. asks launchd for Mach-register extensions and consumes them in Cyanide;
3. converts the two socket descriptors to fileports;
4. registers the fileports with launchd;
5. asks launchd for Mach-lookup extensions;
6. stores service names, lookup tokens, PCB addresses, kernel base/slide, the
   launchd proc anchor, and restore filters/checksums in Cyanide's defaults.

That preserves kernel objects. It does not publish the metadata to
SpringBoard, consume the lookup extensions there, establish that
`fileport_makefd` is allowed there, or coordinate two descriptor users.
SpringBoard must be explicitly provisioned during supervisor installation.
It must not try to read Cyanide's `NSUserDefaults` container.

The socket primitive is stateful. A read is a control-socket `setsockopt`
followed by an RW-socket `getsockopt`. Two processes can redirect the shared
PCB between those operations and read or write the wrong address. Moreover,
`early_kwrite64()` performs a 32-byte read and a later 32-byte write while the
current mutex is released between the two calls. A process-shared lock must
cover the entire read/modify/write transaction, not merely the individual
socket syscalls.

The preferred policy is one active KRW owner: SpringBoard after handoff.
Cyanide after relaunch talks to the supervisor, or obtains a bounded lease
while the supervisor is quiescent. If both processes keep descriptors, use an
inherited/staged lock-file descriptor with `flock(LOCK_EX)` and an owner
generation record. Hold it across each complete RemoteCall session and each
complete KRW read/modify/write transaction. File locking is useful here
because the kernel releases it when a process dies. A named semaphore without
robust-owner recovery is not sufficient.

## Minimum supervisor

The minimum payload is not a theme engine. It contains:

1. a position-independent executable text mapping with BTI entry points;
2. one separately mapped RW context;
3. the bounded KRW recovery client and minimum process/task helpers;
4. the minimum RemoteCall host implementation;
5. FrontBoard and LaunchServices observers;
6. a serial event queue and a separate serial repair executor;
7. a compact immutable manifest/cache reader and the existing journal schema's
   one-bundle transaction functions;
8. a stop flag, heartbeat/counters, version, and last terminal result.

Initialization should be:

```text
Cyanide owns KRW exclusively
  -> stage immutable manifest/payload cache and journal grants
  -> map RX supervisor text + RW context in SpringBoard
  -> create pthread whose first action is pthread_detach(pthread_self())
  -> wait for {version, thread-ready, observer-ready}
  -> pass randomized service metadata/tokens and the KRW lease FD
  -> SpringBoard consumes tokens, makes both FDs, validates kernel magic
  -> transfer exclusive lease ownership to SpringBoard
  -> close bootstrap RemoteCall
  -> Cyanide closes or idles its local KRW descriptors
```

The context should be versioned and bounded. It needs the control/RW service
names and tokens, PCB addresses, kernel base/slide, restore snapshot, payload
version, a lock/lease FD, two data-root grants, and hashes of the staged
manifest. It does not need UI settings, an archive reader, image rendering, or
theme discovery.

### Spotlight state machine

Use `FBProcessManager +sharedInstance` and an object implementing
`FBProcessManagerObserver`. The VM established that `didAddProcess:` arrives
on `com.apple.frontboard.process-manager.call-out` while Spotlight can still
report `finishedLaunching=NO`. The callback must only capture immutable
identity fields and enqueue work. It must not perform KRW or RemoteCall on the
FrontBoard callout queue.

```text
didAddProcess(Spotlight)
  -> enqueue candidate {pid, event generation}
  -> sample after ~200 ms
  -> sample again after ~100 ms
  -> require same FBProcess PID and finishedLaunching
  -> under KRW lease, require exact kernel proc/name/task identity
  -> dedupe by {pid, supervisor payload version}
  -> open one bounded Spotlight RemoteCall
  -> install the existing transparency/static dynamic-icon mappings
  -> verify IMP/data readback and exact target identity
  -> restore every guarded thread and close the session
  -> record success or one terminal result for this PID
```

The initial `allProcesses` scan handles Spotlight already resident when the
supervisor starts. An add event is an accelerator, not sufficient identity
proof. One bounded retry is permitted only for explicit transient states such
as “process not yet finished launching” or “EXC_GUARD provoker not resident.”
ABI mismatch, identity drift, rollback failure, or transport contamination is
terminal for that PID. No RemoteCall remains open between events.

### Application-update state machine

The completion signal should be
`LSApplicationWorkspaceObserverProtocol -applicationsDidInstall:`. Treat
`applicationInstallsDidChange:` as progress only. `applicationsDidUninstall:`
removes pending work; it must not attempt to republish an absent application.
`FBSApplicationLibrary -observeDidReplaceApplicationsWithBlock:` and
`-observeDidUpdateApplicationsWithBlock:` are viable alternatives, but they
still require a custom block invoke function and their block ABI/queue must be
runtime-probed before use.

```text
applicationsDidInstall(proxies)
  -> extract and sanitize bundle identifiers
  -> discard identifiers absent from active manifest
  -> coalesce by bundle identifier on a single-flight queue
  -> obtain two equal, non-empty installation fingerprints
  -> open one iconservicesagent batch
  -> recheck authoritative catalog fingerprint in that batch
  -> inspect the existing journal
  -> if journal fingerprint is old:
       checkpoint update-rebase-restoring
       generate and verify stock for the current installation
       mark every current variant persistent-stock-verified
       remove the stale journal only after exact checkpoint readback
  -> publish only this bundle's cached descriptor matrix
  -> verify current UUID/token/data for every descriptor
  -> write a fresh journal with the new fingerprint
  -> close the iconservicesagent session
  -> set SpringBoard refresh identifiers to [bundleID]
  -> open one SpringBoard refresh session
  -> purge/reload canonical, live-leaf, and retained/materialized surfaces
  -> close the session and restore the complete active identifier manifest
```

The authoritative fingerprint must retain the current implementation's
fields: bundle identifier, standardized bundle path, short version, bundle
version, external version, and iconservicesagent `applicationVersion`. Two LS
proxy samples can gate the expensive work, but the worker must verify the
privileged catalog identity before changing a journal.

The existing update rebase has the right invariant. It calls current stock
generation for every saved descriptor, records
`persistent-stock-verified`, and only then removes the stale journal. It does
not write the old journal's stock bytes into the new installation. This logic
should be refactored into a public one-bundle coordinator, not copied into a
new journal format.

### Staged data package

Stage, atomically, only:

- schema, theme revision, supervisor payload version, and manifest hash;
- folded active bundle identifiers;
- descriptor specifications and profile identity for each bundle;
- `StructuredPayloadCache-v3` path/key, expected length, and SHA-256 for each
  pre-rendered structured payload;
- current application fingerprint and source hash;
- recovery-journal directory and schema version;
- the already-rendered static Clock/Calendar payloads needed by Spotlight.

Give SpringBoard read-only access to the immutable manifest/cache and
read-write access only to the transaction directory. Prefer launchd-issued,
process-lifetime sandbox extensions consumed once during installation. If
path grants fail, pass open directory/file descriptors and use `openat`-style
I/O. Do not add PNG rendering, archive extraction, theme import, or a full
theme rescan to SpringBoard.

## Candidate resident-execution routes

### Route A: Cyanide signed-vnode mapping

The historical mapper correctly resolves the thin slice and exact
page-aligned `__TEXT,__cndhook` file offset, allocates a separate RW context,
opens Cyanide's executable in the target, records `F_CHECK_LV`, maps the code
range `MAP_PRIVATE|MAP_FIXED` as RX, and performs an execution probe. It also
avoids reading nonresident file-backed pages through the physical aperture,
which earlier caused a device panic.

`F_CHECK_LV` is not the final executable-page gate. A platform SpringBoard
combining with Cyanide's developer-team image can reject library validation
even if a particular signed page would otherwise be mapped, while sandbox,
vnode code-sign, wrong slice/offset, or target map policy can independently
reject the RX `mmap`. The only authoritative success is:

1. target `open` succeeds after a bounded file/executable grant;
2. exact RX `mmap` returns the requested address;
3. target-side instruction-cache synchronization completes;
4. a BTI entry point executes and writes the expected value to RW context;
5. a detached thread continues after bootstrap RemoteCall closes.

This route is not presently wired into physical production. At
`CNDIconServicesConsumerHook.m:2406-2415`, every physical call returns through
the Apple-signed IMP implementation. The later executable-extension block is
therefore unreachable for physical calls in this revision. No retained log
under the repository or vPhone evidence root contains a successful physical
`consumer-vnode-map`, execution probe, or a diagnostic that cleanly separates
the final rejection. Route A remains the first lab experiment after a safe RX
permission exists; it is not current-capability evidence.

### Route B: platform carrier or private code cave

The extracted 23A341 `SpringBoardHome` and `IconRendering` images contain RX
`__TEXT`, RW `__DATA*`, and read-only `__LINKEDIT`; neither contains an RWX
segment. Live SpringBoard entitlements contain no JIT, dynamic-code, or
unsigned-executable-memory entitlement. Static searching found normal worker
and callback machinery, but no existing data-driven interpreter capable of
performing conditional PID deduplication, KRW socket transactions, guarded
RemoteCall setup, publication, and journal state transitions.

Executable padding is not enough. It is signed RX data. Making a private COW
copy and changing it still requires the target's code-sign map/pmap to accept
an invalid private page. The Spotlight-only self-trace experiment contains
the right mechanical safeguards for one instruction—private `VM_PROT_COPY`,
readback, cache invalidation, RX restoration, and bounded detach—but there is
no retained success log, and it deliberately excludes SpringBoard.

More importantly, XNU's `PT_TRACE_ME` path invokes `cs_allow_invalid` for both
the tracing child and its parent. SpringBoard's parent is launchd. Even a
perfect detach does not reverse those code-sign state changes, so using
self-trace as the SpringBoard bootstrap would broaden the change to launchd.
That is not the desired target-local escalation and should not be promoted to
production.

Do not patch a shared physical cache page. If a private COW carrier is ever
used after target-local permission is established, save original bytes,
require UUID/instruction identity, use an entire private page, synchronize the
instruction cache, restore RX, verify execution, and restore bytes before
stopping the supervisor. A full supervisor is too large for an incidental
padding cave unless the cave only branches to another already accepted RX
payload.

### Route C: data-only Apple-signed Objective-C composition

SpringBoard already has all of the observation and scheduling components:
`FBProcessManager`, `RBSProcessMonitor`, `LSApplicationWorkspace`, dispatch
queues/timers, `NSInvocation`, and operation queues. They can retain objects,
deliver notifications, and call one selected method.

They cannot express the required conditional program solely as data. A block
passed to `RBSProcessMonitor`, an observer method passed to FrontBoard or
LaunchServices, or a timer callback needs an invoke function. The invoke
function must compare generations and PIDs, debounce, acquire the KRW lease,
run a variable RemoteCall sequence, branch on failures, and update journal
state. `NSInvocation` can invoke a method; it is not a conditional state
machine. Chaining unrelated Apple methods would be ABI-fragile and still
would not supply the KRW/RemoteCall orchestration. Route C is insufficient.

### Route D: target-local pthread through RemoteCall

The existing RemoteCall can invoke SpringBoard's pthread APIs. No general task
port or kernel thread operation is needed once a valid user executable entry
point exists. The clean construction is:

1. map RX position-independent payload text and separate RW context;
2. ensure each indirect entry begins with `bti c`;
3. sign stored code/function pointers in the target with the arm64e function
   pointer key/discriminator used by the call site;
4. call `pthread_create` once;
5. have the new thread call `pthread_detach(pthread_self())`, publish READY,
   and enter an event-driven sleep;
6. close the bootstrap RemoteCall only after READY readback.

This identifies the missing capability precisely: **one valid executable
payload mapping in SpringBoard**.

## Static IPSW and runtime event evidence

### Artifact identity

The specified shared cache reports iOS 26, 4,180 images, 77 subcaches, and
UUID `6E2EA2AD-8DC0-31B9-85F6-40C4C47212A0`. It is the 23A341 static source
used below.

The specified expanded restore directory is not a matching second source. Its
`BuildManifest.plist` reports iOS 26.1 build **23B85**, despite the directory
name containing `23A341`. The exact restore IPSW was subsequently found at
Apple restore image `iPhone17,2_26.0_23A341_Restore.ipsw`; its exact
BuildManifest and kernel were remote-extracted under
`build/lab-cs-allow-invalid/` without downloading the entire IPSW.
(SHA-256
`aab1f64097312983b4a731f5fabd03a4528557e3cda418a10b10d7646b8268a7`).
Its decompressed release kernel reports
`xnu-12377.2.8~1/RELEASE_ARM64_T8140` and has SHA-256
`7e66ddbb70b626c4502c3036620b59829b744c54712a74ca50f4a0c004c89f8c`.

In that exact kernel, `ptrace` is at `0xfffffff00876154c`. The two calls in the
`PT_ATTACHEXC` branch at `0xfffffff008761928` establish the target
`0xfffffff0086e6b68` for both the target and tracer; disassembly of that target
matches the published
`cs_allow_invalid` control flow: MAC policy call, proc csflag update, task/map
lookup, pmap W/X enable, ownership transfer, and map debug-state changes. The
runtime probe independently validates the function prologue and decodes both
branch targets before performing any trace or VM operation.

### Pre-device confidence

These are engineering confidence bands, not observed physical results:

| Claim | Confidence | Reason |
| --- | ---: | --- |
| Exact 23A341 function identity/address is correct | 95% | Exact IPSW identity/hash, exact ptrace callsites, and matching function body are all verified |
| The packaged probe can distinguish attach denial, csflag change, RX admission, and execution | 80% | It compiles with warnings-as-errors and validates the host exports/archive, but has not yet loaded under the physical signer/runtime |
| Current-primitive `PT_ATTACHEXC` route passes end to end | 10–20% | Cyanide lacks a proved trace entitlement/control right for a platform process; the outer debug authorization is likely to deny it |
| Direct `cs_allow_invalid(SpringBoardProc)` is sufficient if a PAC-correct call exists | 25–40% | The internal AMFI/MAC hook may deny SpringBoard, and pmap/code-sign monitor W/X enable can still fail |
| One exact lower pmap/code-sign permission transition plus the existing mapper is sufficient | 65–75% | It removes the two known policy gates; remaining risk is arm64e entry/PAC and physical mapping mechanics |

Accordingly, `cs_allow_invalid` should not yet be called the success method.
It is the exact first semantic candidate. The success method is the complete,
observed chain: permission transition, anonymous private RX mapping, BTI nonce
execution, cleanup, and process reset.

### Spotlight lifecycle

23A341 class metadata places these APIs in
`/System/Library/PrivateFrameworks/FrontBoard.framework/FrontBoard`:

- `FBProcessManager +sharedInstance`
- `-addObserver:` / `-removeObserver:`
- `-allProcesses`
- `-processForPID:`
- required `FBProcessManagerObserver` methods
  `-processManager:didAddProcess:` and
  `-processManager:didRemoveProcess:`
- `FBProcess -pid`, `-name`, `-executablePath`, and
  `-finishedLaunching`

The VM runtime encodings were:

| Selector | Encoding |
| --- | --- |
| `+[FBProcessManager sharedInstance]` | `@16@0:8` |
| `-[FBProcessManager addObserver:]` | `v24@0:8@16` |
| `-[FBProcessManager processForPID:]` | `@20@0:8i16` |
| `-[FBProcess pid]` | `i16@0:8` |
| `-[FBProcess finishedLaunching]` | `B16@0:8` |
| `-processManager:didAddProcess:` | `v32@0:8@16@24` |
| `-processManager:didRemoveProcess:` | `v32@0:8@16@24` |

The add callback ran on
`com.apple.frontboard.process-manager.call-out`, included the PID, and fired
with `finishedLaunching=0`. Samples 200 ms and 100 ms later on the main queue
reported the same PID and `finishedLaunching=1`. An initial scan found an
already resident Spotlight. Thus the event is reliable enough to replace
continuous polling, but it is intentionally early and must be followed by the
settle and kernel identity gates.

`RunningBoardServices` also exposes
`RBSProcessMonitor +monitorWithPredicate:updateHandler:`,
`+monitorWithConfiguration:`, `-setUpdateHandler:`, `-states`,
`-stateForIdentity:`, `-invalidate`, and a callout queue. Predicates can match
a bundle identifier or service name; `RBSProcessHandle` exposes PID/name/path
and `RBSProcessState` exposes `running`. This is a viable fallback, but its
update block ABI is not present in a class dump and it still needs a custom
executable block invoke function. FrontBoard was preferred because its exact
observer ABI and early/settled behavior were runtime-proved.

### Application replacement/update

23A341 CoreServices declares
`LSApplicationWorkspaceObserverProtocol` callbacks including:

- `applicationsWillInstall:`
- `applicationInstallsDidStart:`
- `applicationInstallsDidChange:`
- `applicationInstallsDidUpdateIcon:`
- `applicationsDidInstall:`
- install failure/cancel callbacks
- `applicationsDidUninstall:` and uninstall failure callbacks

`LSApplicationWorkspace` exposes `+defaultWorkspace`, `+callbackQueue`,
`-addObserver:`, and `-removeObserver:`. `LSApplicationProxy` exposes
`applicationIdentifier`, `bundleURL`, version fields, `registeredDate`,
`bundleModTime`, and `isAppUpdate`. The observer callback ABI is one object
argument (`v24@0:8@16`). A real disposable update was not performed, so the
actual 23A341 callback queue and whether every replacement arrives as one or
several arrays remain a production probe requirement.

The framework chain is corroborated by
`FBSApplicationLibrary` in FrontBoardServices. It conforms to the LS observer
protocol, owns observer/work/callout/completion queues, and provides:

- `observeDidAddApplicationsWithBlock:`
- `observeDidUpdateApplicationsWithBlock:`
- `observeDidReplaceApplicationsWithBlock:`
- `observeDidRemoveApplicationsWithBlock:`

SpringBoard's `SBApplicationController` implements
`applicationsAdded:`, `applicationsUpdated:`, `applicationsReplaced:`, and
`applicationsRemoved:`. These selectors prove that SpringBoard already
distinguishes update/replacement completion. They should not be swizzled for
production; direct LS observation followed by two authoritative fingerprint
samples is narrower.

## VM results

The VM probe was an arm64e dylib injected into SpringBoard PID 2772 by the
vPhone root lab harness. That is a valid test of process lifetime, APIs, ABIs,
queueing, and cleanup. It is not a test of physical code-sign admission.

### Heartbeat and Cyanide termination

- Injection published READY and created/detached the thread with result 0.
- After the injector exited, heartbeat advanced from 1 to 3 and later from 10
  to 14.
- Cyanide PID 2482 was identity-checked and terminated.
- With no Cyanide process present, heartbeat advanced from 317 to 320.
- The stop flag removed both observers, set the running flag false, and logged
  STOPPED at count 344. Two seconds later the count remained 344.

This passes the resident-lifetime logic milestone in the VM.

### Spotlight observation

The initial scan observed PID 3497. The probe then observed genuine
replacements:

```text
3497 -> 3558 -> 3632 -> 3668 -> 3826
```

Each new process generated one `FB_ADD` candidate and one settled record for
that PID. The final replacement to 3826 happened after Cyanide was terminated.
No Spotlight RemoteCall or mapping was installed; this is deliberately the
observation/deduplication milestone only.

### Application debounce

A disposable command simulated an update event for `com.ebay.iphone`.
SpringBoard resolved a concrete current path and version identity and produced
two equal samples 250 ms apart. The command file was then truncated inside
SpringBoard, and counting after a further delay showed exactly one sample-2
result per command. No journal or IconServices record was mutated.

### Cross-process fileport probe

A disposable root client created a fileport, registered a randomized name,
issued a Mach lookup token, exited, and asked SpringBoard to recover the
descriptor. SpringBoard consumed the token (`handle=6`) but logged:

```text
lookup=1100 fd=-1 bytes=-1 match=0
```

The registration and token were issued from the root SSH job's namespace,
not through the exact launchd RemoteCall path in `persistence.m`; therefore
this is not a negative result for production launchd-issued tokens. It is a
negative result for the assumption that a consumed token and randomized name
alone are enough. Phase 2 is **not passed** until the exact production names
and launchd-issued lookup tokens work in SpringBoard and the two recovered
corrupted socket descriptors still validate after Cyanide exits.

The VM's normal `CNDLabKernelProvider` is a root RPC/task service. Demonstrating
that provider in two clients would not answer the corrupted-socket question
and is not counted as KRW portability evidence.

## Physical constraints

1. **No accepted payload page.** Physical production installs only
   Apple-signed IMP redirects. The historical payload mapper is not on that
   path and has no retained successful SpringBoard execution result.
2. **No valid forged task right on arm64e.** `CNDKernelTaskBridge` refuses the
   physical forged-port route because copying a stripped `task *` into
   `ipc_port::ip_kobject` lacks the destination-specific data PAC. The first
   Mach trap can panic.
3. **A valid task right would not solve code signing.** It supplies VM and
   thread operations, but `mach_vm_protect`/fault handling can still reject
   invalid executable pages.
4. **No dynamic-code entitlement.** Live SpringBoard and Spotlight entitlement
   dumps contain no JIT/dynamic-code/unsigned-executable-memory entitlement.
5. **No safe data-only state machine.** Existing callbacks still require a
   custom invoke function.
6. **Self-trace has the wrong blast radius.** It changes both SpringBoard and
   parent launchd code-sign state and cannot be fully rolled back without
   process restart.
7. **KRW locking is local.** Concurrent socket use across Cyanide and
   SpringBoard can corrupt target selection or a 32-byte read/modify/write.
8. **Physical kcall is absent.** `xpf_arm64_kcall_supported()` excludes arm64e
   and iOS 16+, and the VM provider's call handler is not a physical exported
   primitive. Current physical KRW can verify the exact entry but cannot call
   it with kernel PAC merely by writing the address.

## Exact missing primitive and escalation

Apple's published XNU `cs_allow_invalid(struct proc *)` implementation is the
relevant semantic unit. It:

- runs `mac_proc_check_run_cs_invalid` and returns false on denial;
- clears `CS_KILL | CS_HARD` under the proc lock;
- sets `CS_DEBUGGED` when the process is valid;
- calls `vm_map_cs_wx_enable()` for the task map, but only logs if that call
  fails;
- disables map switch protection;
- calls `vm_map_cs_debugged_set(map, TRUE)`.

References:

- [Apple XNU `kern_cs.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_cs.c)
- [Apple XNU `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [Apple XNU VM-map declarations](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/vm/vm_map_xnu.h)

The exact narrow call candidate is:

```c
int result = cs_allow_invalid(exactSpringBoardProc);
```

Preconditions and verification:

1. resolve PID from the live SpringBoard process;
2. validate `proc_find(pid) == proc`, process name is `SpringBoard`, and
   `proc_task(proc)` remains stable;
3. invoke the build-specific `cs_allow_invalid` entry through a PAC-correct
   kernel control-flow primitive;
4. record the return and `csops(CS_OPS_STATUS)`, but do not accept either as
   proof of pmap/code-sign-monitor success;
5. map the exact private payload RX in SpringBoard;
6. execute a BTI probe which writes a nonce to a separate RW page;
7. create the detached heartbeat thread;
8. verify no shared physical page changed.

For iPhone17,2 (iPhone 16 Pro Max) build 23A341, the verified unslid address is
`0xfffffff0086e6b68`, or `g_kernel_base + 0x16e2b68`. The lab probe refuses to
continue unless the device build is exactly 23A341, the runtime kernel base
equals unslid base plus the recorded slide, the function prologue matches,
and both exact `PT_ATTACHEXC` branch instructions decode back to that entry.

The kernel-call mechanism must be restricted to this one function and one
validated `proc *`. On arm64e the branch/call sequence must satisfy kernel
instruction PAC; a raw unsigned function pointer is not assumed callable.
Record the pre/post proc flags and target execution result. There is no safe
inverse which reconstructs all prior map/pmap/code-sign-monitor state. On
failure, stop and unmap the payload if possible; resetting the allowance
requires restarting SpringBoard. That non-reversibility is a deployment risk,
not a reason to broaden the primitive.

### Why weaker changes are insufficient

- Root credentials do not change SpringBoard's pmap/code-sign policy.
- A file sandbox or `com.apple.sandbox.executable` extension grants path/map
  authorization; it does not prove library combination or invalid-page
  acceptance.
- Ignoring or bypassing `F_CHECK_LV` does not make the subsequent RX mapping
  executable.
- Writing `CS_DEBUGGED`, clearing `CS_HARD|CS_KILL`, or changing one visible VM
  map bit does not execute `vm_map_cs_wx_enable` or the protected pmap/code-sign
  monitor transition.
- A valid task port permits VM/thread APIs but does not itself permit invalid
  executable code.
- A code cave is still a signed RX page; private modification needs the same
  invalid-code permission.
- SpringBoard self-trace reaches the needed XNU function without a new kernel
  primitive, but it also changes launchd, temporarily traces/stops
  SpringBoard, and leaves irreversible allowance state after detach.

### Escalation ranking

| Rank | Route | New exploit capability | Spotlight repair | App-update repair | Survives Cyanide exit | Survives respring | Risk |
| ---: | --- | --- | ---: | ---: | ---: | ---: | --- |
| 0 | Current primitives only | None; try `PT_ATTACHEXC` from Cyanide to SpringBoard | SpringBoard RX probe built, not physically run | Not physically demonstrated | VM only | No | High: outer trace authorization likely denies; an accepted attach deliberately forces one respring after persisting evidence |
| 1 | SpringBoard RX payload permission | Target-local executable mapping accepted by SpringBoard | Yes | Yes | Yes | No | Medium; effect lasts for SpringBoard lifetime |
| 2 | Narrow kernel call | PAC-correct `cs_allow_invalid(exactSpringBoardProc)` once | Conditional on RX execution proof | Conditional on RX execution proof | Conditional | No | Medium/high; MAC/pmap may deny it and the effect is irreversible until respring |
| 3 | Valid task/thread bridge | Kernel-minted task right or destination-correct `ip_kobject` PAC | Not by itself | Not by itself | Conditional | No | High; broad process control and RX policy still missing |
| 4 | Persistent daemon | Trusted executable placement and launchd registration | Yes | Yes | Yes | Yes | Very high; expands trust, filesystem, launch, sandbox, and reboot scope |

Rank 1 describes the capability boundary. The current-primitive Rank 0 attach
probe is attempted first. If outer trace authorization blocks it, the smallest
candidate way to supply the boundary is Rank 2. It is sufficient only if an
actual target-local RX execution probe passes; MAC denial or a failed
`vm_map_cs_wx_enable` requires identifying the narrower failing VM/pmap
transition. Rank 3 is not a substitute for Rank 1, and Rank 4 is unnecessary
for the stated SpringBoard-lifetime requirement.

## Recommended architecture and implementation sequence

### Gate 0: preserve current production behavior

- Keep all work under `scripts/lab/`.
- Do not alter the Apple-signed IMP presentation route, publisher mappings, or
  journal semantics.
- Preserve the exact 23A341 kernel evidence and runtime prologue/callsite
  checks already emitted by the lab build.

### Gate 1: exact KRW handoff

1. Add a lab-only, versioned supervisor bootstrap context.
2. Use the exact launchd-issued lookup tokens produced by `persistence.m`, not
   a token from a root shell namespace.
3. Consume both tokens in SpringBoard and call `bootstrap_look_up` then
   `fileport_makefd`.
4. Import PCB/base/slide/restore metadata without reading Cyanide defaults.
5. Perform read-only kernel magic and exact self-proc/task validation.
6. Terminate Cyanide and repeat validation.
7. Relaunch Cyanide and prove that the ownership lease refuses or serializes
   concurrent use.
8. Stress alternating reads; then exercise one write only against a disposable
   lab-owned value with a complete read/modify/write lock.

Do not proceed if lookup, descriptor recovery, post-exit validation, or lease
recovery fails.

### Gate 2: target-local RX permission

1. In the VM, retain the current root-injected heartbeat as the downstream
   control.
2. On the exact physical build, use the base Cyanide UI to try `PT_ATTACHEXC`
   against SpringBoard. Require a stopped wait status,
   `CS_DEBUGGED`, successful detach, stable proc/task identity, a new anonymous
   W-to-RX page, and a BTI nonce returning `0xc0de`. The probe has no
   `PT_TRACE_ME` fallback, persists the decisive result before cleanup, and
   terminates that SpringBoard PID afterward, parks KRW, and terminates
   Cyanide to clear both allowance states. A rejected attach does not trigger
   either termination. Spotlight is never contacted.
3. If outer ptrace authorization denies the attach, that result does not prove
   the internal `mac_proc_check_run_cs_invalid` result. Only then add a
   one-function PAC-correct call adapter and invoke
   `cs_allow_invalid(SpringBoardProc)` directly. If the internal MAC hook or
   pmap still denies executable admission, identify and test that exact lower
   transition.
4. First retry the exact signed-vnode mapper with a
   `com.apple.sandbox.executable` extension consumed in SpringBoard.
5. If LV rejects the image before mapping, use a private anonymous W-to-RX
   page only after allowance; never RWX.
6. Require target `mmap`/`mprotect`, execution nonce, BTI/PAC correctness,
   thread heartbeat, and clean stop.
7. Inspect that launchd flags did not change. This distinguishes the narrow
   call from the unsafe self-trace route.

### Gate 3: resident observer only

Port the proved lab heartbeat, FB observer, initial scan, settle samples,
version/PID dedupe, stop flag, and metrics. Run repeated Spotlight restarts
with Cyanide terminated. Do not yet include repair.

### Gate 4: Spotlight repair

Port the minimum KRW/RemoteCall functions. For each genuinely new PID, take
the exclusive KRW lease, perform exactly one existing bounded installation,
verify, and tear it down. Keep mappings in Spotlight, not an open RemoteCall.
Record counts and memory use. Repeat until teardown is deterministic and no
guarded thread state remains.

### Gate 5: one-bundle update worker

Refactor, without changing its journal schema:

- fingerprint construction/comparison;
- `CNDRemixRebaseActiveJournalToCurrentStock`;
- one-bundle cache preparation/validation;
- one-bundle publication and fresh journal finalization;
- one-bundle SpringBoard refresh.

Run this as a separate serial executor inside the SpringBoard payload, not on
the lifecycle callback queue. Simulate path/version drift with a disposable
app. Confirm one journal rebase, current stock generation, current UUID/token
publication, and an affected-bundle-only refresh.

### When to introduce a separate worker process

Do not introduce one merely to separate code organization. The same
SpringBoard process can safely own both jobs if the update path is a separate
serial executor with bounded file grants and no UI/rendering code. This avoids
another persistence mechanism and makes one process the KRW owner.

Use a separate minimal process only if all three data routes fail:

1. a read-only cache grant plus read-write journal grant;
2. inherited/open directory or payload FDs;
3. an on-demand iconservicesagent batch orchestrated by SpringBoard.

Such a process must itself remain alive after Cyanide exits. At that point it
is effectively a trusted launchd job with filesystem placement, signing/trust,
entitlements, and lifecycle policy: Rank 4. It should not be called a “small
worker” to hide that escalation.

## Failure and rollback requirements

### Bootstrap and payload

- Never mark installed before the resident thread publishes READY with the
  expected nonce/version.
- If mapping or execution probe fails before thread start, unmap RX/RW pages.
- If thread state is uncertain, do not unmap underneath it; set terminal state
  and require a SpringBoard restart.
- Stop sets a context flag, invalidates observers, drains both queues, closes
  KRW descriptors, publishes STOPPED, and only then permits unmapping.
- The `cs_allow_invalid` effect cannot be fully rolled back; respring is the
  reset boundary.

### KRW and RemoteCall

- One active owner or one crash-releasing lease; no advisory-only convention.
- Lease the complete RemoteCall and complete read/modify/write, not individual
  reads.
- Bind every target operation to PID, proc, task, and process name before and
  after.
- Restore every EXC_GUARD candidate and close every exception port/session.
- If a synthetic call remains in flight, quarantine that PID and never retry
  automatically.
- Never keep Spotlight or iconservicesagent RemoteCall state between events.

### Application updates

- Coalesce by bundle identifier and fingerprint generation.
- Refuse an empty or changing authoritative fingerprint.
- A stale active journal first transitions to
  `update-rebase-restoring`; it is never treated as stock for the new app.
- Remove the stale journal only after current stock is generated, read back,
  and durably checkpointed.
- If any variant fails, keep `recovery-required`; do not publish later variants
  as a successful app transaction.
- Write the new journal before reporting success, then close the agent batch
  before refreshing SpringBoard.
- Refresh only the affected identifier. Never trigger full-theme Apply for one
  app update.
- Terminal ABI, identity, or verification failures are recorded once for that
  fingerprint; no indefinite retry loop.

## Survival matrix

This table describes the recommended SpringBoard-resident design after the RX
and KRW handoff gates pass, not today's production build.

| Event | Supervisor | Spotlight mappings | Update repair | Explanation |
| --- | --- | --- | --- | --- |
| Cyanide suspension | Survives | Current PID survives; new PIDs repaired | Survives | SpringBoard thread, observers, KRW descriptors, grants, and queues are independent of Cyanide scheduling |
| Cyanide termination | Survives | Current PID survives; new PIDs repaired | Survives | VM lifetime demonstrated; physical requires completed KRW handoff |
| Spotlight restart | Survives | Old mapping dies; new PID gets one repair | Survives | Supervisor is hosted by SpringBoard and dedupes by PID/version |
| SpringBoard restart/respring | Does not survive | Spotlight mapping may survive only until its own exit, but no watcher remains | Does not run | SpringBoard address space, thread, descriptors, grants, and context are destroyed |
| Userspace reboot | Does not survive | Does not survive | Does not run | launchd and all userspace anchors restart; no job reinstalls the payload |
| Full reboot | Does not survive | Does not survive | Does not run | exploit state, launchd fileports, and resident mappings are gone |

Persistent IconServices records and recovery journals may remain on disk
across the latter events, but that is data persistence, not supervisor
persistence. The minimum goal does not require automatic respring/reboot
reinstallation.

## Acceptance status

| Criterion | Result |
| --- | --- |
| SpringBoard recovers launchd-parked physical KRW | **Fail/unproved**; disposable VM token lookup returned 1100 |
| Detached supervisor remains after Cyanide termination | **Pass in VM** |
| New Spotlight PID detected with Cyanide absent | **Pass in VM** |
| Exactly one bounded Spotlight repair and clean close | **Not run**; observer only |
| Repeated Spotlight restarts | **Pass for observation in VM** |
| One debounced app update event | **Pass for simulated event in VM** |
| Journal rebase/publication/scoped refresh | **Not run**; production data intentionally untouched |
| No respring/userspace crash/stale recovery state | **Pass for the observer probe**; no journals were touched |
| Physical `cs_allow_invalid` / private RX | **SpringBoard-targeted base-app probe built, not run**; exact 23A341 kernel identity and address verified offline |

Therefore the “current-capability success” acceptance criteria are not met.
The escalation conclusion is nevertheless concrete:

1. downstream resident execution and event handling are VM-proved;
2. the physical failing boundary is one accepted SpringBoard RX payload;
3. the first no-new-exploit test is `PT_ATTACHEXC` against SpringBoard itself;
   if outer authorization blocks it, the first narrow enabling
   candidate is `cs_allow_invalid(exactSpringBoardProc)` through a restricted
   PAC-correct call primitive; neither is accepted until a new RX page executes,
   and a MAC or pmap denial moves the missing primitive to that exact lower
   transition;
4. raw flags, sandbox grants, LV bypass, task rights, code caves, and
   self-trace are insufficient or have the wrong blast radius;
5. portable KRW remains a mandatory pre-production engineering proof, with no
   current evidence that it needs a broader exploit.

## Final answers

1. **Can it be implemented with primitives already proved in the tree?** No.
   The VM path can, and a no-new-kernel-exploit signed-vnode/self-trace path is
   plausible, but physical SpringBoard executable admission and SpringBoard
   KRW recovery have not passed their required proofs. Self-trace is not an
   acceptable production shortcut because it also alters launchd.
2. **Architecture if enabled:** one SpringBoard-resident RX payload, one RW
   context, exclusive launchd-fileport KRW ownership, event-driven FB/LS
   observers, one bounded RemoteCall per new Spotlight PID, and a separate
   in-process serial one-bundle repair executor using staged structured
   payloads and the existing journal format.
3. **Precise missing capability:** acceptance and execution of one private
   SpringBoard payload page. Separately, the exact launchd-token/fileport KRW
   handoff and global serialization are unproved engineering gates.
4. **Smallest exploit escalation to test:** first try the current-primitive
   `PT_ATTACHEXC` path on SpringBoard. If that is denied, add one PAC-correct
   call to exact 23A341 `cs_allow_invalid(exactSpringBoardProc)` after identity
   validation, followed by an actual RX mapping and execution nonce. It is a
   candidate, not yet a physical-device success method; MAC or pmap rejection
   would identify the next, lower exact primitive.
5. **Why weaker escalations fail:** none performs the complete proc + VM map +
   protected pmap/code-sign transition; self-trace performs it too broadly by
   applying it to launchd as well.
6. **Same supervisor or separate worker?** Same SpringBoard process, separate
   serial executor/module. Add a separate persistent OS process only if
   bounded grants and FDs cannot provide the staged cache/journal data.
7. **Survival:** suspension, Cyanide termination, and Spotlight restart: yes
   after the two gates pass. SpringBoard restart, userspace reboot, and full
   reboot: no.
