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

/// The retained SpringBoard `mlock` experiment, exported so the .34 page wire
/// probe can reuse one implementation. Wires, from inside the proven
/// SpringBoard process, the exact 16 KiB shared-cache frame that contains
/// `targetVirtualAddress`, after re-proving the live process identity and the
/// recorded translation path. It never writes kernel memory and never mutates
/// the page.
///
/// Required context keys: `targetVirtualAddress`, `springBoardPID`,
/// `springBoardProc`, `springBoardTask`, `springBoardLeafEntryAddress`,
/// `provenLeafEntryValue`, `springBoardTranslationPath`.
///
/// `options[@"diagnosticControls"]` additionally runs two bounded control
/// beats in the same session (anonymous writable and anonymous read-only
/// 16 KiB pages) so a refusal can be attributed to the page class rather than
/// to the caller.
NSDictionary<NSString *, id> *CNDHailMaryPatchWireSpringBoardPage(
    NSDictionary<NSString *, id> *context,
    NSDictionary<NSString *, id> * _Nullable options);

NS_ASSUME_NONNULL_END
