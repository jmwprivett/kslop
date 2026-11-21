#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// C50 read-only inventory for the iPhone17,2 / 23A341 AGX firmware GFX-RW
/// port.  It proves an owned Metal CPU/GPU baseline and snapshots only exact,
/// predicate-gated object fields.  It never inserts a firmware command, kicks
/// a channel, reads the fixed firmware output, writes kernel memory, or owns
/// KRW acquisition/recovery/cleanup.
void CNDAGXFirmwarePreflightRun(
    NSString * _Nullable requestID,
    void (^completion)(NSDictionary<NSString *, id> *report));

NS_ASSUME_NONNULL_END
