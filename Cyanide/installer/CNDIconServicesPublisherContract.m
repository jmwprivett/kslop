#import "CNDIconServicesPublisher.h"

/*
 * Foundation-only publisher contract implementation.
 *
 * CNDIconServicesPublisher.m adapts the current RemoteCall implementation to
 * these normalized fields.  Keeping the acceptance boundary here makes it
 * usable by another transport and testable without a target device.
 */

static BOOL cnd_publisher_result_has_cache_store_proof(
    NSDictionary<NSString *, id> *result)
{
    return [result[@"agentCacheReadbackVerified"] boolValue] &&
        [result[@"persistentStoreReadbackVerified"] boolValue];
}

static BOOL cnd_publisher_result_is_stock_api_direct(
    NSDictionary<NSString *, id> *result)
{
    return [result isKindOfClass:NSDictionary.class] &&
        [result[@"acceptancePolicy"]
                isEqual:@"stock-iconservices-direct"] &&
        ![result[@"customExecutablePayloadUsed"] boolValue] &&
        ![result[@"methodInterpositionUsed"] boolValue] &&
        ![result[@"payloadLifecycleRequired"] boolValue];
}

BOOL CNDIconServicesPublisherResultIsSafeToFinalize(
    NSDictionary<NSString *, id> *result)
{
    if (![result isKindOfClass:NSDictionary.class] ||
        ![result[@"operationCompleted"] boolValue] ||
        !cnd_publisher_result_has_cache_store_proof(result) ||
        ![result[@"transportHealthy"] boolValue] ||
        ![result[@"transportLifecycleVerified"] boolValue] ||
        ![result[@"transactionCleaned"] boolValue] ||
        [result[@"transportAbandoned"] boolValue]) {
        return NO;
    }

    BOOL direct = cnd_publisher_result_is_stock_api_direct(result);
    if (!direct &&
        (![result[@"hookRestored"] boolValue] ||
         ![result[@"hookQuiescent"] boolValue] ||
         [result[@"hookStillInstalledAtCleanup"] boolValue] ||
         ![result[@"payloadLifecycleVerified"] boolValue])) {
        return NO;
    }

    /*
     * A batch intentionally retains its transport and reusable payload
     * mapping between targets. A standalone operation must close all local
     * transport state before its result can be finalized.
     */
    if ([result[@"batchTransportBorrowed"] boolValue]) {
        return [result[@"transportRetained"] boolValue] &&
            ![result[@"transportClosed"] boolValue] &&
            [result[@"transportLocalStateRemaining"] boolValue];
    }
    return [result[@"transportClosed"] boolValue] &&
        ![result[@"transportRetained"] boolValue] &&
        ![result[@"transportLocalStateRemaining"] boolValue];
}

BOOL CNDIconServicesPublisherPublicationResultIsVerified(
    NSDictionary<NSString *, id> *result)
{
    if (cnd_publisher_result_is_stock_api_direct(result)) {
        return [result[@"mode"] isEqual:@"replace"] &&
            [result[@"stockCaptured"] boolValue] &&
            [result[@"stockGenerationPersisted"] boolValue] &&
            [result[@"persistentIndexIdentitySettled"] boolValue] &&
            [result[@"persistentIndexTokenWriteVerified"] boolValue] &&
            [result[@"persistentIndexTokenLookupVerified"] boolValue] &&
            [result[@"replacementCreated"] boolValue] &&
            [result[@"replacementPublished"] boolValue] &&
            [result[@"directStoreRemoveVerified"] boolValue] &&
            [result[@"directStoreWriteIssued"] boolValue] &&
            [result[@"directStoreWriteVerified"] boolValue] &&
            [result[@"triggerVerified"] boolValue] &&
            CNDIconServicesPublisherResultIsSafeToFinalize(result);
    }
    if (![result isKindOfClass:NSDictionary.class] ||
        ![result[@"mode"] isEqual:@"replace"] ||
        ![result[@"stockCaptured"] boolValue] ||
        ![result[@"replacementCreated"] boolValue] ||
        ![result[@"replacementReturned"] boolValue] ||
        ![result[@"triggerVerified"] boolValue]) {
        return NO;
    }
    return CNDIconServicesPublisherResultIsSafeToFinalize(result);
}

BOOL CNDIconServicesPublisherRestorationResultIsVerified(
    NSDictionary<NSString *, id> *result)
{
    if (cnd_publisher_result_is_stock_api_direct(result)) {
        return [result[@"mode"] isEqual:@"stock"] &&
            [result[@"stockCaptured"] boolValue] &&
            [result[@"stockGenerationPersisted"] boolValue] &&
            [result[@"persistentIndexIdentitySettled"] boolValue] &&
            ![result[@"replacementCreated"] boolValue] &&
            ![result[@"replacementPublished"] boolValue] &&
            [result[@"directStoreRemoveVerified"] boolValue] &&
            [result[@"directStoreWriteIssued"] boolValue] &&
            [result[@"directStoreWriteVerified"] boolValue] &&
            [result[@"triggerVerified"] boolValue] &&
            CNDIconServicesPublisherResultIsSafeToFinalize(result);
    }
    if (![result isKindOfClass:NSDictionary.class] ||
        ![result[@"mode"] isEqual:@"stock"] ||
        ![result[@"stockCaptured"] boolValue] ||
        [result[@"replacementCreated"] boolValue] ||
        [result[@"replacementReturned"] boolValue] ||
        ![result[@"triggerVerified"] boolValue]) {
        return NO;
    }
    return CNDIconServicesPublisherResultIsSafeToFinalize(result);
}
