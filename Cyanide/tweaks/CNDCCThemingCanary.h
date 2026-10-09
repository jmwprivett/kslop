#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Requires an active PID-bound SpringBoard RemoteCall session. Resolves the
// current live Flashlight template by stable identity, installs the supplied
// Pulsar images, verifies readback, holds briefly for visual inspection, and
// restores the exact original image objects before returning. It never sends
// a control action or touches torch/radio APIs or target-process files.
NSDictionary<NSString *, id> *CNDCCThemingRunFlashlightApplyRestoreCanary(
    NSData *offPNG,
    NSData *onPNG,
    NSTimeInterval holdSeconds);

NS_ASSUME_NONNULL_END
