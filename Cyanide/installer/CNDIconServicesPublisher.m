#import "CNDIconServicesPublisher.h"
#import "CNDIconServicesPublisherTransport.h"

NS_ASSUME_NONNULL_BEGIN

/*
 * This file is intentionally transport-neutral.  It owns only the selected
 * transport object and the thread-owned batch lifetime; all daemon/session,
 * staging, hook, and diagnostic work belongs to that object's implementation.
 */
static NSString * const CNDIconServicesPublisherBatchThreadKey =
    @"CNDIconServicesPublisherBatchThreadV1";

@interface CNDIconServicesPublisherBatch : NSObject
@property (nonatomic, strong) id<CNDIconServicesPublisherTransport> transport;
@end

@implementation CNDIconServicesPublisherBatch
@end

static CNDIconServicesPublisherBatch * _Nullable cnd_publisher_batch(void)
{
    id value = NSThread.currentThread.threadDictionary[
        CNDIconServicesPublisherBatchThreadKey];
    return [value isKindOfClass:CNDIconServicesPublisherBatch.class]
        ? value : nil;
}

static NSDictionary<NSString *, id> *cnd_publisher_batch_error(void)
{
    return @{
        @"ok": @NO,
        @"stage": @"batch-session",
        @"message": @"No healthy iconservicesagent batch is open.",
    };
}

static NSDictionary<NSString *, id> *cnd_publisher_facade_error(
    NSString *message)
{
    return @{
        @"ok": @NO,
        @"stage": @"publisher-transport",
        @"message": message ?: @"The publisher transport is unavailable.",
    };
}

NSDictionary<NSString *, id> *CNDIconServicesPublisherPublish(
    NSString *bundleIdentifier, NSData *structuredImageData)
{
    /* Preserve the historical thread-owned reuse rule: a direct operation
     * issued while a batch is open is still borrowed by that batch. */
    CNDIconServicesPublisherBatch *batch = cnd_publisher_batch();
    if (batch) {
        return [batch.transport publishBundleIdentifier:bundleIdentifier
                                   structuredImageData:structuredImageData];
    }
    id<CNDIconServicesPublisherTransport> transport =
        CNDIconServicesPublisherMakeDefaultTransport();
    return transport
        ? [transport publishBundleIdentifier:bundleIdentifier
                        structuredImageData:structuredImageData]
        : cnd_publisher_facade_error(
            @"The publisher transport could not be created.");
}

NSDictionary<NSString *, id> *CNDIconServicesPublisherRestoreStock(
    NSString *bundleIdentifier)
{
    CNDIconServicesPublisherBatch *batch = cnd_publisher_batch();
    if (batch) {
        return [batch.transport restoreStockForBundleIdentifier:bundleIdentifier];
    }
    id<CNDIconServicesPublisherTransport> transport =
        CNDIconServicesPublisherMakeDefaultTransport();
    return transport
        ? [transport restoreStockForBundleIdentifier:bundleIdentifier]
        : cnd_publisher_facade_error(
            @"The publisher transport could not be created.");
}

NSDictionary<NSString *, id> *CNDIconServicesPublisherBeginBatch(
    NSString *wakeBundleIdentifier)
{
    if (cnd_publisher_batch()) {
        return @{
            @"ok": @NO,
            @"stage": @"batch-already-open",
            @"message": @"An iconservicesagent batch is already open on this thread.",
        };
    }

    id<CNDIconServicesPublisherTransport> transport =
        CNDIconServicesPublisherMakeDefaultTransport();
    if (!transport) {
        return cnd_publisher_facade_error(
            @"The publisher transport could not be created.");
    }

    NSDictionary<NSString *, id> *result =
        [transport beginBatch:wakeBundleIdentifier];
    if ([result[@"ok"] boolValue] && [transport isHealthy]) {
        CNDIconServicesPublisherBatch *batch =
            [[CNDIconServicesPublisherBatch alloc] init];
        batch.transport = transport;
        NSThread.currentThread.threadDictionary[
            CNDIconServicesPublisherBatchThreadKey] = batch;
    }
    return result ?: cnd_publisher_facade_error(
        @"The publisher transport returned no begin-batch result.");
}

NSDictionary<NSString *, id> *
CNDIconServicesPublisherCopyInstalledBundleIdentifiersInBatch(void)
{
    CNDIconServicesPublisherBatch *batch = cnd_publisher_batch();
    if (!batch || ![batch.transport isHealthy]) {
        return cnd_publisher_batch_error();
    }
    return [batch.transport copyInstalledBundleIdentifiersInBatch];
}

NSDictionary<NSString *, id> *CNDIconServicesPublisherPublishInBatch(
    NSString *bundleIdentifier, NSData *structuredImageData)
{
    CNDIconServicesPublisherBatch *batch = cnd_publisher_batch();
    if (!batch || ![batch.transport isHealthy]) {
        return cnd_publisher_batch_error();
    }
    return [batch.transport publishBundleIdentifier:bundleIdentifier
                               structuredImageData:structuredImageData];
}


NSDictionary<NSString *, id> *CNDIconServicesPublisherPublishVariantInBatch(
    NSString *bundleIdentifier, NSData *structuredImageData,
    NSDictionary<NSString *, NSNumber *> *descriptorSpecification)
{
    CNDIconServicesPublisherBatch *batch = cnd_publisher_batch();
    if (!batch || ![batch.transport isHealthy]) {
        return cnd_publisher_batch_error();
    }
    return [batch.transport publishBundleIdentifier:bundleIdentifier
                                structuredImageData:structuredImageData
                            descriptorSpecification:descriptorSpecification];
}

NSDictionary<NSString *, id> *CNDIconServicesPublisherRestoreStockInBatch(
    NSString *bundleIdentifier)
{
    CNDIconServicesPublisherBatch *batch = cnd_publisher_batch();
    if (!batch || ![batch.transport isHealthy]) {
        return cnd_publisher_batch_error();
    }
    return [batch.transport restoreStockForBundleIdentifier:bundleIdentifier];
}


NSDictionary<NSString *, id> *
CNDIconServicesPublisherRestoreStockVariantInBatch(
    NSString *bundleIdentifier,
    NSDictionary<NSString *, NSNumber *> *descriptorSpecification)
{
    CNDIconServicesPublisherBatch *batch = cnd_publisher_batch();
    if (!batch || ![batch.transport isHealthy]) {
        return cnd_publisher_batch_error();
    }
    return [batch.transport restoreStockForBundleIdentifier:bundleIdentifier
                                    descriptorSpecification:descriptorSpecification];
}

NSDictionary<NSString *, id> *
CNDIconServicesPublisherAuditVariantInBatch(
    NSString *bundleIdentifier,
    NSDictionary<NSString *, NSNumber *> *descriptorSpecification)
{
    CNDIconServicesPublisherBatch *batch = cnd_publisher_batch();
    if (!batch || ![batch.transport isHealthy]) {
        return cnd_publisher_batch_error();
    }
    return [batch.transport auditBundleIdentifier:bundleIdentifier
                           descriptorSpecification:descriptorSpecification];
}

BOOL CNDIconServicesPublisherBatchIsHealthy(void)
{
    CNDIconServicesPublisherBatch *batch = cnd_publisher_batch();
    return batch && [batch.transport isHealthy];
}

NSDictionary<NSString *, id> *CNDIconServicesPublisherFinishBatch(void)
{
    CNDIconServicesPublisherBatch *batch = cnd_publisher_batch();
    if (!batch) {
        return @{
            @"ok": @YES,
            @"stage": @"no-batch",
            @"message": @"No iconservicesagent batch required finalization.",
            @"closed": @YES,
            @"localStateRemaining": @NO,
        };
    }

    NSDictionary<NSString *, id> *result = [batch.transport finishBatch];
    /* A finish attempt consumes this thread-owned facade batch even when the
     * implementation reports an unhealthy/abandoned session, matching the
     * historical one-shot cleanup boundary. */
    [NSThread.currentThread.threadDictionary
        removeObjectForKey:CNDIconServicesPublisherBatchThreadKey];
    return result ?: cnd_publisher_facade_error(
        @"The publisher transport returned no finish-batch result.");
}

NS_ASSUME_NONNULL_END
