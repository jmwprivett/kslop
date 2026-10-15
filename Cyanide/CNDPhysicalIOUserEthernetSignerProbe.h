#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDPhysicalIOUserEthernetSignerProbeCompletion)(
    NSDictionary<NSString *, id> *report);

BOOL CNDPhysicalIOUserEthernetSignerProbeIsSupported(NSString **reasonOut);
BOOL CNDPhysicalIOUserEthernetSignerProbeIsRunning(void);
void CNDPhysicalIOUserEthernetSignerProbeRun(
    CNDPhysicalIOUserEthernetSignerProbeCompletion completion);

NS_ASSUME_NONNULL_END
