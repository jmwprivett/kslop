#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDPhysicalCSAllowInvalidProbeCompletion)(
    NSDictionary<NSString *, id> *report);

BOOL CNDPhysicalCSAllowInvalidProbeIsSupported(NSString **reasonOut);
BOOL CNDPhysicalCSAllowInvalidProbeIsRunning(void);
void CNDPhysicalCSAllowInvalidProbeRun(
    CNDPhysicalCSAllowInvalidProbeCompletion completion);

NS_ASSUME_NONNULL_END
