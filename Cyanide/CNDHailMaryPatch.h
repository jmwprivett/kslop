#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, CNDHailMaryPatchOperation) {
    CNDHailMaryPatchOperationApply = 0,
    CNDHailMaryPatchOperationRestore = 1,
    CNDHailMaryPatchOperationVerifyPatched = 2,
    CNDHailMaryPatchOperationVerifyOriginal = 3,
};

typedef void (^CNDHailMaryPatchCompletion)(
    NSDictionary<NSString *, id> *report);

BOOL CNDHailMaryPatchIsSupported(NSString * _Nullable * _Nullable reasonOut);
BOOL CNDHailMaryPatchIsRunning(void);
void CNDHailMaryPatchRun(CNDHailMaryPatchOperation operation,
                         CNDHailMaryPatchCompletion completion);

NS_ASSUME_NONNULL_END
