#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDHailMaryProbeCompletion)(
    NSDictionary<NSString *, id> *report);

BOOL CNDHailMaryProbeIsSupported(NSString * _Nullable * _Nullable reasonOut);
BOOL CNDHailMaryProbeIsRunning(void);
void CNDHailMaryProbeRun(CNDHailMaryProbeCompletion completion);

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

NS_ASSUME_NONNULL_END
