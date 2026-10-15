#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Consumes one host-staged request only on the 23A341 vPhone lab guest.
/// Physical devices and ordinary launches with no request are no-ops.
void CNDCCMaterialRecipeVMCanaryProcessPendingRequest(void);

NS_ASSUME_NONNULL_END
