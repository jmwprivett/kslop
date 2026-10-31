#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDHailMaryProbeCompletion)(
    NSDictionary<NSString *, id> *report);

/// Selects which live page tables a proof may use. The shared pair is the
/// Hail Mary default: SpringBoard and Spotlight must agree on one terminal
/// frame. SpringBoard-only proves the same text and data pages through
/// SpringBoard's own pmap and records no Spotlight identity; it exists for
/// consumers whose target is SpringBoard's mapping alone, so their
/// correctness never depends on a second process being alive or sharing the
/// page.
typedef NS_ENUM(NSUInteger, CNDHailMaryProofMode) {
    CNDHailMaryProofModeSharedPair = 0,
    CNDHailMaryProofModeSpringBoardOnly = 1,
};

BOOL CNDHailMaryProbeIsSupported(NSString * _Nullable * _Nullable reasonOut);
BOOL CNDHailMaryProbeIsRunning(void);
void CNDHailMaryProbeRun(CNDHailMaryProbeCompletion completion);
void CNDHailMaryProbeRunWithMode(
    CNDHailMaryProofMode mode,
    CNDHailMaryProbeCompletion completion);

/// Read-only shared-physical translation of one runtime shared-cache virtual
/// address through the two live processes proven by a completed, confirmed
/// probe report. Revalidates the exact kernel identity, kernel layout
/// offsets, and physical-map anchors against the live kernel, re-verifies
/// both live process identities recorded by that proof, and requires both
/// page-table walks to resolve the address to one terminal shared physical
/// frame. Performs kernel reads only; never modifies memory.
BOOL CNDHailMaryProbeTranslateSharedRuntimeAddress(
    NSDictionary<NSString *, id> * _Nullable report,
    uint64_t runtimeVirtualAddress,
    NSDictionary<NSString *, id> * _Nullable * _Nullable
        springBoardTranslationOut,
    NSDictionary<NSString *, id> * _Nullable * _Nullable
        spotlightTranslationOut,
    uint64_t * _Nullable physicalFrameOut,
    uint64_t * _Nullable physicalAddressOut,
    uint64_t * _Nullable frameKernelVirtualAddressOut,
    NSString * _Nullable * _Nullable errorOut);

/// Read-only translation of one runtime shared-cache virtual address inside a
/// single process proven by a completed, confirmed probe report
/// (`@"SpringBoard"` or `@"Spotlight"`). Used when the two proven page tables
/// legitimately stop agreeing: wiring a shared page can force the kernel to
/// give one process a private leaf entry, which makes the shared-pair check
/// above refuse even though both translations still resolve the same frame.
/// Revalidates the same kernel identity, layout, physical-map anchors, and
/// live process identity. Performs kernel reads only; never modifies memory.
BOOL CNDHailMaryProbeTranslateRuntimeAddressInProcess(
    NSDictionary<NSString *, id> * _Nullable report,
    NSString *processName,
    uint64_t runtimeVirtualAddress,
    NSDictionary<NSString *, id> * _Nullable * _Nullable translationOut,
    NSString * _Nullable * _Nullable errorOut);

/// Same single-process translation as above, additionally returning the
/// terminal physical frame, physical address, and the validated physmap KVA
/// for that frame. Used by consumers that must prove a frame without a second
/// process.
BOOL CNDHailMaryProbeTranslateRuntimeAddressInProcessWithPhysical(
    NSDictionary<NSString *, id> * _Nullable report,
    NSString *processName,
    uint64_t runtimeVirtualAddress,
    NSDictionary<NSString *, id> * _Nullable * _Nullable translationOut,
    uint64_t * _Nullable physicalFrameOut,
    uint64_t * _Nullable physicalAddressOut,
    uint64_t * _Nullable frameKernelVirtualAddressOut,
    NSString * _Nullable * _Nullable errorOut);

NS_ASSUME_NONNULL_END
