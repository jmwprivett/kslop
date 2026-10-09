#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, CNDHailMaryImpRedirectOperation) {
    CNDHailMaryImpRedirectOperationApply = 0,
    CNDHailMaryImpRedirectOperationRestore = 1,
    CNDHailMaryImpRedirectOperationVerifyRedirected = 2,
    CNDHailMaryImpRedirectOperationVerifyOriginal = 3,
};

typedef void (^CNDHailMaryImpRedirectCompletion)(
    NSDictionary<NSString *, id> *report);

BOOL CNDHailMaryImpRedirectIsSupported(
    NSString * _Nullable * _Nullable reasonOut);
BOOL CNDHailMaryImpRedirectIsRunning(void);

/// Guarded, reversible redirect of SBIconImageView's preoptimized
/// effectivelyPrefersFlatImageLayers dispatch entry.
///
/// Mutation operations require a successful .34 identical-bytes permission
/// report from the current boot, then run a fresh full physical proof and
/// resolve the exact original/redirected 32-byte entry guard through both
/// live pmaps. One kwrite32 changes only the packed entry's low word. The
/// exact inverse is journaled durably first; no automatic rollback or panic
/// mechanism is installed.
///
/// Exact readback and stable translation verification are the terminal
/// automated checks. No process is killed, restarted, reopened, or otherwise
/// mutated after the write. Visual behavior is left to operator observation.
void CNDHailMaryImpRedirectRun(
    CNDHailMaryImpRedirectOperation operation,
    CNDHailMaryImpRedirectCompletion completion);

NS_ASSUME_NONNULL_END
