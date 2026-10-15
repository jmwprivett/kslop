#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDPhysicalPACIdentityCanaryCompletion)(
    NSDictionary<NSString *, id> *report);

/// This diagnostic is intentionally pinned to the researched physical target.
/// It is unavailable in vPhone guests even when they emulate the same model.
BOOL CNDPhysicalPACIdentityCanaryIsSupported(
    NSString * _Nullable * _Nullable reasonOut);
BOOL CNDPhysicalPACIdentityCanaryIsRunning(void);

/// Run a read-only KRW-backed exception-identity/PAC conversion canary.  The
/// caller must establish and validate Cyanide's ordinary physical KRW first.
void CNDPhysicalPACIdentityCanaryRun(
    CNDPhysicalPACIdentityCanaryCompletion completion);

/// The next boundary: a sacrificial fork child in a distinct task receives
/// the exception port through its inherited bootstrap special port.  The
/// parent holds no child task/thread right before identity delivery.
BOOL CNDPhysicalPACCrossTaskCanaryIsSupported(
    NSString * _Nullable * _Nullable reasonOut);
BOOL CNDPhysicalPACCrossTaskCanaryIsRunning(void);
void CNDPhysicalPACCrossTaskCanaryRun(
    CNDPhysicalPACIdentityCanaryCompletion completion);

NS_ASSUME_NONNULL_END
