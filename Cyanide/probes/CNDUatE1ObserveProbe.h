#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Read-only 23A341 observer for the E1 Route-B experiment.  It attempts the
// fully predicate-gated AGX provider -> GART -> AGXUAT -> GPTBAT chain, takes
// before/after snapshots around one type-1 open+close action, and falls back to
// the symbol-anchored gIOUAT object when the known port/kobject wall remains.
void CNDUatE1ObserveRun(
    void (^completion)(NSDictionary<NSString *, id> *report));

// E2 retirement gate.  Cyanide keeps the validated, existing-only KRW
// generation and the read-only TTBAT observer.  A separately signed helper app
// performs one Metal blit and authenticates to the observer over a bounded
// loopback rendezvous.  Success requires one exact TTBAT entry to appear while
// that helper is alive and the same entry to clear after its exit protocol and
// peer EOF.  The host console supplies the independent exit-status witness.
// No allocator reuse is attempted.
void CNDUatE2RetireRun(
    void (^completion)(NSDictionary<NSString *, id> *report));

// E4 in-flight completion versus context teardown.  Cyanide owns a global
// IOSurface canary, requires a completed cross-process GPU control write,
// resets it, then brackets a finite terminal-only GPU marker against the exact
// validated TTBAT entry while a disposable helper exits.  Kernel memory is
// read-only and KRW admission remains existing-only through the shared owner.
void CNDUatE4InflightRun(
    void (^completion)(NSDictionary<NSString *, id> *report));

// E5 object-owner lifetime differential. The helper proves one context open
// with a completed GPU control marker, then drains every helper-owned Metal
// strong reference while its process/socket/App Group mapping remain alive.
// Cyanide polls only the exact validated TTBAT entry, records whether it clears
// or remains valid, and authorizes helper exit only after that verdict.
void CNDUatE5OwnerReleaseRun(
    void (^completion)(NSDictionary<NSString *, id> *report));

// E5 stronger device-lifetime boundary. A separately allocated, exact
// AGXG17PDevice completes the control command, then the helper proves that the
// private device and its complete Metal graph deallocated while the helper and
// process-global system device remain alive. Kernel memory remains read-only.
void CNDUatE5DeviceReleaseRun(
    void (^completion)(NSDictionary<NSString *, id> *report));

// E5 exact low-level connection-owner boundary. The helper constructs the
// artifact-pinned IOGPUMetalDevice through its normal initializer, validates
// its deviceRef, then releases that Objective-C owner normally while the
// helper and process-global system device remain alive.
void CNDUatE5ConnectionReleaseRun(
    void (^completion)(NSDictionary<NSString *, id> *report));

// E5 exact raw IO-command-queue lifetime boundary. The helper opens its own
// type-1 accelerator connection, creates one queue through pinned selector 42,
// destroys it through selector 43 while the connection/process remain alive,
// and closes the connection only after the observer records its verdict.
void CNDUatE5RawQueueReleaseRun(
    void (^completion)(NSDictionary<NSString *, id> *report));

// E5 exact raw queue-binding boundary. The helper creates one selector-42
// queue and one selector-14 notification queue, binds them through selector
// 44, proves the binding through selector 45's count-zero oracle, then
// destroys only the queue while the notification queue, connection, and
// process remain alive. Kernel memory remains read-only.
void CNDUatE5RawQueueBindReleaseRun(
    void (^completion)(NSDictionary<NSString *, id> *report));

// Read-only AGX bootstrap-root observer. It validates the exact G17P
// accelerator+0xd0 AGXSecureGart, requires the statically registered domain-3
// context ID 0, and associates it with the two symbol-retained SPTM TTBAT
// roots. It deliberately does not read either root page: a paddr and physmap
// range do not independently prove EL1 mappedness. Shared KRW is existing-only
// and no kernel or firmware write is performed.
void CNDUatAGXBootstrapRootRun(
    void (^completion)(NSDictionary<NSString *, id> *report));

// Explicit panic-risk C49 RTBuddy alias experiment. It validates the exact
// accelerator -> firmware channel -> RTBuddy -> coredump-map object chain and
// both paired OSArrays. After stable bounded metadata gates, it deliberately
// strips the kernel-PACDA-signed segment backing pointer and performs one
// bounded array read. A covering exact RTBuddySegment authorizes one same-index
// IOMemoryMap element read and one 32-bit firmware output read. No writes,
// scans, GET_PT_ENTRY calls, or KRW acquisition are permitted.
void CNDUatAGXRTBuddyAliasRun(
    void (^completion)(NSDictionary<NSString *, id> *report));

NS_ASSUME_NONNULL_END
