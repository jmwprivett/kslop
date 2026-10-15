#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDPhysicalSpringBoardPACProbeCompletion)(
    NSDictionary<NSString *, id> *report);

BOOL CNDPhysicalSpringBoardPACProbeIsSupported(
    NSString * _Nullable * _Nullable reasonOut);
BOOL CNDPhysicalSpringBoardPACProbeIsRunning(void);

/// Uses the physical KRW-backed identity RemoteCall path against exactly one
/// SpringBoard thread. It executes only getpid, proves the returned process
/// identity, then asks that exact bound SpringBoard incarnation to terminate
/// itself. The replacement process is the cleanup boundary for the retained
/// exception policy; this probe never loads a dylib or requests kcall.
void CNDPhysicalSpringBoardPACProbeRun(
    CNDPhysicalSpringBoardPACProbeCompletion completion);

NS_ASSUME_NONNULL_END
