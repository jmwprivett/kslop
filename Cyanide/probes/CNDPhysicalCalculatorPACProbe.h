#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDPhysicalCalculatorPACProbeCompletion)(
    NSDictionary<NSString *, id> *report);

BOOL CNDPhysicalCalculatorPACProbeIsSupported(
    NSString * _Nullable * _Nullable reasonOut);
BOOL CNDPhysicalCalculatorPACProbeIsRunning(void);

/// Uses the existing KRW-backed RemoteCall exception transport against the
/// stock Calculator process. The first trap requests identity delivery, uses
/// the kernel-minted thread right for public state conversion, executes only
/// getpid as a marker, and restores the original thread state before return.
void CNDPhysicalCalculatorPACProbeRun(
    CNDPhysicalCalculatorPACProbeCompletion completion);

NS_ASSUME_NONNULL_END
