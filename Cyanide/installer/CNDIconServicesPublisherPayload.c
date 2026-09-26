#include "CNDIconServicesPublisherPayload.h"

#include <stdbool.h>
#include <stdint.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#define CND_PUBLISHER_TEXT                                                \
    __attribute__((section("__TEXT,__cndpub,regular,pure_instructions"),   \
                   noinline, no_stack_protector, used, visibility("hidden")))

typedef uint64_t CNDObject;
typedef uint64_t CNDSelector;

typedef struct {
    double width;
    double height;
} CNDPublisherSize;

typedef CNDObject (*CNDGenerateIMP)(CNDObject, CNDSelector, CNDObject);
typedef CNDObject (*CNDMessageObject0)(CNDObject, CNDSelector);
typedef CNDObject (*CNDMessageObject1)(CNDObject, CNDSelector, CNDObject);
typedef CNDObject (*CNDMessageObject2)(CNDObject, CNDSelector, CNDObject,
                                       CNDObject);
typedef CNDObject (*CNDMessageObjectInt2)(CNDObject, CNDSelector, int32_t,
                                          int32_t);
typedef CNDObject (*CNDMessageObject3)(CNDObject, CNDSelector, CNDObject,
                                       CNDObject, CNDObject);
typedef uint64_t (*CNDMessageUInt0)(CNDObject, CNDSelector);
typedef CNDPublisherSize (*CNDMessageSize0)(CNDObject, CNDSelector);
typedef double (*CNDMessageDouble0)(CNDObject, CNDSelector);
typedef int64_t (*CNDMessageInt640)(CNDObject, CNDSelector);
typedef void (*CNDMessageVoid0)(CNDObject, CNDSelector);
typedef void (*CNDMessageVoidInt641)(CNDObject, CNDSelector, int64_t);
typedef void (*CNDMessageVoidBool1)(CNDObject, CNDSelector, bool);
typedef void (*CNDMessageVoidSize1)(CNDObject, CNDSelector,
                                    CNDPublisherSize);
typedef void (*CNDMessageVoidDouble1)(CNDObject, CNDSelector, double);
typedef void (*CNDReplacementIMP)(void);
typedef CNDReplacementIMP (*CNDMethodSetImplementation)(
    uint64_t, CNDReplacementIMP);
typedef CNDObject (*CNDAutoreleasePoolPush)(void);
typedef void (*CNDAutoreleasePoolPop)(CNDObject);
typedef int (*CNDZlibUncompress)(uint8_t *, unsigned long *,
                                 const uint8_t *, unsigned long);

_Static_assert(sizeof(CNDIconServicesPublisherPayloadContext) <=
                   CND_ICON_PUBLISHER_PAYLOAD_CONTEXT_CAPACITY,
               "publisher context exceeds its isolated RW page capacity");

static CND_PUBLISHER_TEXT bool cnd_publisher_context_valid(
    const CNDIconServicesPublisherPayloadContext *context)
{
    if (!context ||
        context->magic != CND_ICON_PUBLISHER_PAYLOAD_MAGIC ||
        context->version != CND_ICON_PUBLISHER_PAYLOAD_VERSION ||
        !context->objcMsgSend || !context->methodSetImplementation ||
        !context->generationMethod || !context->originalGenerate) {
        return false;
    }
    bool objectsReady = context->targetBundle &&
        (!context->replaceResponse ||
         (context->themedData && context->cacheImageClass));
    bool stagingReady = context->stagingAddress &&
        context->stagingBundleLength > 0 &&
        context->stagingBundleLength < context->stagingCapacity &&
        context->stagingDataOffset <= context->stagingCapacity &&
        context->stagingDataLength <=
            context->stagingCapacity - context->stagingDataOffset &&
        (!context->replaceResponse || context->stagingDataLength > 0) &&
        (!context->stagingCompressed ||
         (context->zlibUncompress && context->stagingDecodedLength > 0 &&
          context->stagingDecodedOffset >=
              context->stagingDataOffset + context->stagingDataLength &&
          context->stagingDecodedOffset <= context->stagingCapacity &&
          context->stagingDecodedLength <=
              context->stagingCapacity - context->stagingDecodedOffset));
    return objectsReady || stagingReady;
}

CND_PUBLISHER_TEXT uint64_t cnd_icon_publisher_payload_probe_body(
    const CNDIconServicesPublisherPayloadContext *context)
{
    return cnd_publisher_context_valid(context)
        ? (context->magic ^ context->version) : 0;
}

/*
 * Create one reusable exact descriptor on the synthetic publisher worker
 * with typed calls. The previous host-side NSInvocation path synchronously
 * waited for iconservicesagent's main thread and could strand the RemoteCall
 * worker when that run loop was not servicing performSelectorOnMainThread:.
 * The returned descriptor is produced by -copy and therefore remains +1 for
 * the batch owner until FinishBatch (or standalone cleanup) releases it.
 */
CND_PUBLISHER_TEXT uint64_t
cnd_icon_publisher_payload_prepare_descriptor_body(
    CNDIconServicesPublisherPayloadContext *context)
{
    if (!cnd_publisher_context_valid(context) ||
        !context->objcAutoreleasePoolPush ||
        !context->objcAutoreleasePoolPop || !context->descriptorClass ||
        !context->selImageDescriptorWithIconVariantOptions ||
        !context->selCopy ||
        !context->selSetSize || !context->selSetScale ||
        !context->selSetAppearance || !context->selAppearance ||
        !context->selSetIgnoreCache || !context->selSize ||
        !context->selScale || !context->selRespondsToSelector ||
        !context->selRelease) {
        return 0;
    }
    if (context->descriptorTemplate && context->descriptorPrepared) {
        return context->descriptorTemplate;
    }

    CNDMessageObject0 object0 =
        (CNDMessageObject0)(uintptr_t)context->objcMsgSend;
    CNDMessageObject1 object1 =
        (CNDMessageObject1)(uintptr_t)context->objcMsgSend;
    CNDMessageObjectInt2 objectInt2 =
        (CNDMessageObjectInt2)(uintptr_t)context->objcMsgSend;
    CNDMessageVoid0 void0 =
        (CNDMessageVoid0)(uintptr_t)context->objcMsgSend;
    CNDMessageVoidInt641 voidInt641 =
        (CNDMessageVoidInt641)(uintptr_t)context->objcMsgSend;
    CNDMessageVoidBool1 voidBool1 =
        (CNDMessageVoidBool1)(uintptr_t)context->objcMsgSend;
    CNDMessageVoidSize1 voidSize1 =
        (CNDMessageVoidSize1)(uintptr_t)context->objcMsgSend;
    CNDMessageVoidDouble1 voidDouble1 =
        (CNDMessageVoidDouble1)(uintptr_t)context->objcMsgSend;
    CNDMessageSize0 size0 =
        (CNDMessageSize0)(uintptr_t)context->objcMsgSend;
    CNDMessageDouble0 double0 =
        (CNDMessageDouble0)(uintptr_t)context->objcMsgSend;
    CNDMessageInt640 int640 =
        (CNDMessageInt640)(uintptr_t)context->objcMsgSend;
    CNDAutoreleasePoolPush poolPush =
        (CNDAutoreleasePoolPush)(uintptr_t)
            context->objcAutoreleasePoolPush;
    CNDAutoreleasePoolPop poolPop =
        (CNDAutoreleasePoolPop)(uintptr_t)
            context->objcAutoreleasePoolPop;

    uint64_t bits = 0;
    CNDObject pool = poolPush();
    if (pool) bits |= CND_ICON_PUBLISHER_DESCRIPTOR_POOL_READY;
    bool factoryReady = object1(
        context->descriptorClass, context->selRespondsToSelector,
        context->selImageDescriptorWithIconVariantOptions) != 0;
    if (factoryReady) bits |= CND_ICON_PUBLISHER_DESCRIPTOR_FACTORY_READY;
    bool factoryInputsValid = context->expectedOptions <= INT32_MAX;
    CNDObject factoryDescriptor = factoryReady && factoryInputsValid
        ? objectInt2(context->descriptorClass,
                     context->selImageDescriptorWithIconVariantOptions,
                     0,
                     (int32_t)context->expectedOptions)
        : 0;
    if (factoryDescriptor)
        bits |= CND_ICON_PUBLISHER_DESCRIPTOR_FACTORY_RETURNED;
    bool descriptorReady = factoryDescriptor &&
        object1(factoryDescriptor, context->selRespondsToSelector,
                context->selCopy) &&
        object1(factoryDescriptor, context->selRespondsToSelector,
                context->selSetSize) &&
        object1(factoryDescriptor, context->selRespondsToSelector,
                context->selSetScale) &&
        object1(factoryDescriptor, context->selRespondsToSelector,
                context->selSetAppearance) &&
        object1(factoryDescriptor, context->selRespondsToSelector,
                context->selSetVariantOptions) &&
        object1(factoryDescriptor, context->selRespondsToSelector,
                context->selSetIgnoreCache) &&
        object1(factoryDescriptor, context->selRespondsToSelector,
                context->selSize) &&
        object1(factoryDescriptor, context->selRespondsToSelector,
                context->selScale) &&
        object1(factoryDescriptor, context->selRespondsToSelector,
                context->selAppearance) &&
        object1(factoryDescriptor, context->selRespondsToSelector,
                context->selVariantOptions);
    CNDObject descriptor = descriptorReady
        ? object0(factoryDescriptor, context->selCopy) : 0;
    if (descriptor) bits |= CND_ICON_PUBLISHER_DESCRIPTOR_COPIED;

    CNDPublisherSize requested = {
        context->expectedWidth, context->expectedHeight
    };
    if (descriptor) {
        voidSize1(descriptor, context->selSetSize, requested);
        voidDouble1(descriptor, context->selSetScale,
                    context->expectedScale);
        voidInt641(descriptor, context->selSetAppearance,
                   (int64_t)context->expectedAppearance);
        voidInt641(descriptor, context->selSetVariantOptions,
                   (int64_t)context->expectedIconVariant);
        voidBool1(descriptor, context->selSetIgnoreCache, true);
        bits |= CND_ICON_PUBLISHER_DESCRIPTOR_CONFIGURED;
    }
    CNDPublisherSize observed = descriptor
        ? size0(descriptor, context->selSize)
        : (CNDPublisherSize){0.0, 0.0};
    double scale = descriptor
        ? double0(descriptor, context->selScale) : 0.0;
    uint64_t appearance = descriptor
        ? (uint64_t)int640(descriptor, context->selAppearance) : UINT64_MAX;
    uint64_t iconVariant = descriptor
        ? (uint64_t)int640(descriptor, context->selVariantOptions)
        : UINT64_MAX;
    uint64_t options = context->expectedOptions;
    context->observedWidth = observed.width;
    context->observedHeight = observed.height;
    context->observedScale = scale;
    context->observedAppearance = appearance;
    context->observedIconVariant = iconVariant;
    context->observedOptions = options;
    bool exact = pool && descriptor &&
        observed.width == context->expectedWidth &&
        observed.height == context->expectedHeight &&
        scale == context->expectedScale &&
        appearance == context->expectedAppearance &&
        iconVariant == context->expectedIconVariant &&
        options == context->expectedOptions;
    if (exact) bits |= CND_ICON_PUBLISHER_DESCRIPTOR_VERIFIED;

    if (!exact && descriptor) {
        void0(descriptor, context->selRelease);
        descriptor = 0;
    }
    if (pool) poolPop(pool);
    __atomic_store_n(&context->descriptorPreparationBits, bits,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&context->descriptorPrepared, exact ? 1 : 0,
                     __ATOMIC_RELEASE);
    if (exact) context->descriptorTemplate = descriptor;
    return descriptor;
}

CND_PUBLISHER_TEXT uint64_t cnd_icon_publisher_payload_install_body(
    uint64_t method, uint64_t replacementAddress,
    const CNDIconServicesPublisherPayloadContext *context)
{
    if (!cnd_publisher_context_valid(context) || !method ||
        !replacementAddress) return 0;
    CNDReplacementIMP replacement =
        (CNDReplacementIMP)(uintptr_t)replacementAddress;
#if __has_feature(ptrauth_calls)
    replacement = (CNDReplacementIMP)ptrauth_sign_unauthenticated(
        ptrauth_strip(replacement, ptrauth_key_function_pointer),
        ptrauth_key_function_pointer, 0);
#endif
    CNDMethodSetImplementation setter =
        (CNDMethodSetImplementation)(uintptr_t)
            context->methodSetImplementation;
    return (uint64_t)(uintptr_t)setter(method, replacement);
}

CND_PUBLISHER_TEXT uint64_t cnd_icon_publisher_payload_generate_body(
    CNDObject self, CNDSelector selector, CNDObject recordIdentifiersOut,
    CNDIconServicesPublisherPayloadContext *context)
{
    if (!cnd_publisher_context_valid(context)) return 0;
    __atomic_add_fetch(&context->inFlight, 1, __ATOMIC_ACQ_REL);

    CNDGenerateIMP original =
        (CNDGenerateIMP)(uintptr_t)context->originalGenerate;
    CNDObject stock = original(self, selector, recordIdentifiersOut);
    if (stock) __atomic_store_n(
        &context->originalReturned, 1, __ATOMIC_RELEASE);

    CNDMessageObject0 object0 =
        (CNDMessageObject0)(uintptr_t)context->objcMsgSend;
    CNDMessageObject1 object1 =
        (CNDMessageObject1)(uintptr_t)context->objcMsgSend;
    CNDMessageObject3 object3 =
        (CNDMessageObject3)(uintptr_t)context->objcMsgSend;
    CNDMessageUInt0 uint0 =
        (CNDMessageUInt0)(uintptr_t)context->objcMsgSend;
    CNDMessageInt640 int640 =
        (CNDMessageInt640)(uintptr_t)context->objcMsgSend;
    CNDMessageSize0 size0 =
        (CNDMessageSize0)(uintptr_t)context->objcMsgSend;
    CNDMessageDouble0 double0 =
        (CNDMessageDouble0)(uintptr_t)context->objcMsgSend;

    CNDObject icon = object0(self, context->selIcon);
    CNDObject descriptor = object0(self, context->selImageDescriptor);
    bool iconContract = icon &&
        object1(icon, context->selRespondsToSelector,
                context->selBundleIdentifier) != 0;
    bool descriptorContract = descriptor &&
        object1(descriptor, context->selRespondsToSelector,
                context->selSize) != 0 &&
        object1(descriptor, context->selRespondsToSelector,
                context->selScale) != 0 &&
        object1(descriptor, context->selRespondsToSelector,
                context->selAppearance) != 0 &&
        object1(descriptor, context->selRespondsToSelector,
                context->selVariantOptions) != 0;
    bool stockContract = stock &&
        object1(stock, context->selRespondsToSelector,
                context->selData) != 0 &&
        object1(stock, context->selRespondsToSelector,
                context->selUUID) != 0 &&
        object1(stock, context->selRespondsToSelector,
                context->selValidationToken) != 0;
    CNDObject bundle = iconContract
        ? object0(icon, context->selBundleIdentifier) : 0;
    bool bundleContract = bundle &&
        object1(bundle, context->selRespondsToSelector,
                context->selIsEqualToString) != 0;
    CNDPublisherSize size = descriptorContract
        ? size0(descriptor, context->selSize)
        : (CNDPublisherSize){0.0, 0.0};
    double scale = descriptorContract
        ? double0(descriptor, context->selScale) : 0.0;
    uint64_t appearance = descriptorContract
        ? (uint64_t)int640(descriptor, context->selAppearance) : UINT64_MAX;
    uint64_t iconVariant = descriptorContract
        ? (uint64_t)int640(descriptor, context->selVariantOptions)
        : UINT64_MAX;
    uint64_t options = context->expectedOptions;
    bool bundleMatches = bundleContract &&
        object1(bundle, context->selIsEqualToString,
                context->targetBundle) != 0;
    uint64_t diagnostics =
        (stock ? (1ULL << 0) : 0) |
        (icon ? (1ULL << 1) : 0) |
        (descriptor ? (1ULL << 2) : 0) |
        (stockContract ? (1ULL << 3) : 0) |
        (iconContract ? (1ULL << 4) : 0) |
        (descriptorContract ? (1ULL << 5) : 0) |
        (bundle ? (1ULL << 6) : 0) |
        (bundleContract ? (1ULL << 7) : 0) |
        (bundleMatches ? (1ULL << 8) : 0) |
        (size.width == context->expectedWidth ? (1ULL << 9) : 0) |
        (size.height == context->expectedHeight ? (1ULL << 10) : 0) |
        (scale == context->expectedScale ? (1ULL << 11) : 0) |
        (appearance == context->expectedAppearance ? (1ULL << 12) : 0) |
        (iconVariant == context->expectedIconVariant ? (1ULL << 13) : 0) |
        (options == context->expectedOptions ? (1ULL << 14) : 0);
    __atomic_store_n(&context->matchDiagnostics, diagnostics,
                     __ATOMIC_RELEASE);
    context->observedWidth = size.width;
    context->observedHeight = size.height;
    context->observedScale = scale;
    context->observedAppearance = appearance;
    context->observedIconVariant = iconVariant;
    context->observedOptions = options;
    bool target = stockContract && bundleContract && descriptorContract &&
        bundleMatches &&
        size.width == context->expectedWidth &&
        size.height == context->expectedHeight &&
        scale == context->expectedScale &&
        appearance == context->expectedAppearance &&
        iconVariant == context->expectedIconVariant &&
        options == context->expectedOptions;

    uint64_t expected = 0;
    if (!target || !__atomic_compare_exchange_n(
            &context->matched, &expected, 1, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        __atomic_sub_fetch(&context->inFlight, 1, __ATOMIC_ACQ_REL);
        return stock;
    }

    // This is a one-shot publisher. Restore the stock IMP before allocating
    // the replacement so later requests cannot enter copied code.
    CNDMethodSetImplementation setter =
        (CNDMethodSetImplementation)(uintptr_t)
            context->methodSetImplementation;
    CNDReplacementIMP prior = setter(
        context->generationMethod,
        (CNDReplacementIMP)(uintptr_t)context->originalGenerate);
    if (prior) __atomic_store_n(
        &context->hookRestored, 1, __ATOMIC_RELEASE);

    CNDObject stockData = object0(stock, context->selData);
    CNDObject stockUUID = object0(stock, context->selUUID);
    CNDObject stockToken = object0(stock, context->selValidationToken);
    bool stockDataContract = stockData &&
        object1(stockData, context->selRespondsToSelector,
                context->selLength) != 0;
    /*
     * The successful VM publisher established that this inner generation
     * result may not have a UUID yet.  Passing nil to IFCacheImage is part of
     * the stock outer transaction: IconServices assigns the canonical UUID
     * when it installs the returned response in its cache/store.  Requiring a
     * pre-persistence UUID here prevented the replacement from ever being
     * constructed in the in-agent trigger path.
     */
    bool stockTokenContract = stockToken &&
        object1(stockToken, context->selRespondsToSelector,
                context->selLength) != 0;
    uint64_t stockLength = stockDataContract
        ? uint0(stockData, context->selLength) : 0;
    uint64_t tokenLength = stockTokenContract
        ? uint0(stockToken, context->selLength) : 0;
    uint64_t themedLength = uint0(
        context->themedData, context->selLength);
    __atomic_store_n(&context->stockDataLength, stockLength,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&context->themedDataLength,
                     context->replaceResponse ? themedLength : 0,
                     __ATOMIC_RELEASE);

    CNDObject retainedIcon = object0(icon, context->selRetain);
    CNDObject retainedDescriptor = object0(
        descriptor, context->selRetain);
    CNDObject retainedData = stockData
        ? object0(stockData, context->selRetain) : 0;
    CNDObject retainedUUID = stockUUID
        ? object0(stockUUID, context->selRetain) : 0;
    CNDObject retainedToken = stockToken
        ? object0(stockToken, context->selRetain) : 0;
    __atomic_store_n(&context->capturedIcon, retainedIcon,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&context->capturedDescriptor, retainedDescriptor,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&context->capturedStockData, retainedData,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&context->capturedStockUUID, retainedUUID,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&context->capturedStockToken, retainedToken,
                     __ATOMIC_RELEASE);

    if (!context->replaceResponse) {
        __atomic_sub_fetch(&context->inFlight, 1, __ATOMIC_ACQ_REL);
        return stock;
    }

    CNDObject allocation = object0(
        context->cacheImageClass, context->selAlloc);
    CNDObject replacement = allocation && stockDataContract &&
        stockTokenContract && stockLength && tokenLength && themedLength
        ? object3(allocation,
                  context->selInitWithDataUUIDValidationToken,
                  context->themedData, stockUUID, stockToken)
        : 0;
    if (replacement) {
        __atomic_store_n(&context->replacementCreated, 1,
                         __ATOMIC_RELEASE);
        CNDObject retainedReplacement = object0(
            replacement, context->selRetain);
        __atomic_store_n(&context->capturedReplacement,
                         retainedReplacement, __ATOMIC_RELEASE);
        replacement = object0(replacement, context->selAutorelease);
        if (replacement) __atomic_store_n(
            &context->replacementReturned, 1, __ATOMIC_RELEASE);
    }

    __atomic_sub_fetch(&context->inFlight, 1, __ATOMIC_ACQ_REL);
    return replacement ? replacement : stock;
}

/*
 * Build and submit the configured exact IconServices request in one execution
 * inside iconservicesagent.  The former host-side implementation split this
 * synchronous operation across many RemoteCall round trips.  The returned
 * response is retained across the remote autorelease-pool boundary and is
 * released by the publisher cleanup after it reads the one-shot context.
 */
CND_PUBLISHER_TEXT uint64_t cnd_icon_publisher_payload_trigger_body(
    CNDIconServicesPublisherPayloadContext *context)
{
    if (!cnd_publisher_context_valid(context) ||
        !context->objcAutoreleasePoolPush ||
        !context->objcAutoreleasePoolPop || !context->iconClass ||
        !context->descriptorClass || !context->descriptorTemplate ||
        !context->selInitWithBundleIdentifier || !context->selCopy ||
        !context->selSetIgnoreCache ||
        !context->selGenerateImageWithDescriptor ||
        !context->selRelease || !context->selRetain) return 0;

    CNDMessageObject0 object0 =
        (CNDMessageObject0)(uintptr_t)context->objcMsgSend;
    CNDMessageObject1 object1 =
        (CNDMessageObject1)(uintptr_t)context->objcMsgSend;
    CNDMessageVoid0 void0 =
        (CNDMessageVoid0)(uintptr_t)context->objcMsgSend;
    CNDMessageVoidBool1 voidBool1 =
        (CNDMessageVoidBool1)(uintptr_t)context->objcMsgSend;
    CNDAutoreleasePoolPush poolPush =
        (CNDAutoreleasePoolPush)(uintptr_t)
            context->objcAutoreleasePoolPush;
    CNDAutoreleasePoolPop poolPop =
        (CNDAutoreleasePoolPop)(uintptr_t)
            context->objcAutoreleasePoolPop;

    CNDObject pool = poolPush();
    CNDObject allocation = object0(context->iconClass, context->selAlloc);
    CNDObject icon = allocation
        ? object1(allocation, context->selInitWithBundleIdentifier,
                  context->targetBundle) : 0;
    CNDObject descriptor = object0(
        context->descriptorTemplate, context->selCopy);
    CNDObject retainedResponse = 0;

    if (icon && descriptor) {
        voidBool1(descriptor, context->selSetIgnoreCache, true);
        CNDObject generated = object1(
            icon, context->selGenerateImageWithDescriptor, descriptor);
        retainedResponse = generated
            ? object0(generated, context->selRetain) : 0;
    }

    if (descriptor) void0(descriptor, context->selRelease);
    if (icon) void0(icon, context->selRelease);
    if (pool) poolPop(pool);
    return retainedResponse;
}

/*
 * Consume the per-icon bytes from the reusable RW staging mapping, construct
 * the two Objective-C input objects in iconservicesagent, arm the one-shot
 * hook, and synchronously submit the exact request.  Keeping this transaction
 * target-side removes the host-driven malloc/NSString/NSData/hook round trips
 * while preserving the proven one-hook-per-icon lifecycle.
 */
CND_PUBLISHER_TEXT uint64_t cnd_icon_publisher_payload_execute_body(
    uint64_t replacementAddress,
    CNDIconServicesPublisherPayloadContext *context)
{
    if (!cnd_publisher_context_valid(context) || !replacementAddress ||
        !context->objcAutoreleasePoolPush ||
        !context->objcAutoreleasePoolPop || !context->stringClass ||
        !context->dataClass || !context->selAlloc ||
        !context->selInitWithUTF8String ||
        !context->selInitWithBytesLength || !context->selRelease) return 0;

    __atomic_store_n(&context->transactionStarted, 1, __ATOMIC_RELEASE);
    CNDMessageObject0 object0 =
        (CNDMessageObject0)(uintptr_t)context->objcMsgSend;
    CNDMessageObject1 object1 =
        (CNDMessageObject1)(uintptr_t)context->objcMsgSend;
    CNDMessageObject2 object2 =
        (CNDMessageObject2)(uintptr_t)context->objcMsgSend;
    CNDMessageVoid0 void0 =
        (CNDMessageVoid0)(uintptr_t)context->objcMsgSend;
    CNDAutoreleasePoolPush poolPush =
        (CNDAutoreleasePoolPush)(uintptr_t)
            context->objcAutoreleasePoolPush;
    CNDAutoreleasePoolPop poolPop =
        (CNDAutoreleasePoolPop)(uintptr_t)
            context->objcAutoreleasePoolPop;

    CNDObject pool = poolPush();
    CNDObject bundleAllocation = object0(
        context->stringClass, context->selAlloc);
    CNDObject bundle = bundleAllocation
        ? object1(bundleAllocation, context->selInitWithUTF8String,
                  context->stagingAddress) : 0;
    uint64_t dataAddress =
        context->stagingAddress + context->stagingDataOffset;
    uint64_t dataLength = context->stagingDataLength;
    if (bundle && context->replaceResponse && context->stagingCompressed) {
        __atomic_store_n(&context->decompressionAttempted, 1,
                         __ATOMIC_RELEASE);
        unsigned long decodedLength =
            (unsigned long)context->stagingDecodedLength;
        CNDZlibUncompress uncompress =
            (CNDZlibUncompress)(uintptr_t)context->zlibUncompress;
        int result = uncompress(
            (uint8_t *)(uintptr_t)(context->stagingAddress +
                                    context->stagingDecodedOffset),
            &decodedLength,
            (const uint8_t *)(uintptr_t)dataAddress,
            (unsigned long)dataLength);
        __atomic_store_n(&context->decompressionResult, result,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&context->decompressedDataLength, decodedLength,
                         __ATOMIC_RELEASE);
        if (result != 0 ||
            decodedLength != context->stagingDecodedLength) {
            void0(bundle, context->selRelease);
            if (pool) poolPop(pool);
            return 0;
        }
        dataAddress = context->stagingAddress +
            context->stagingDecodedOffset;
        dataLength = decodedLength;
        __atomic_store_n(&context->decompressionSucceeded, 1,
                         __ATOMIC_RELEASE);
    }
    CNDObject data = 0;
    if (bundle && context->replaceResponse) {
        CNDObject dataAllocation = object0(
            context->dataClass, context->selAlloc);
        data = dataAllocation
            ? object2(dataAllocation, context->selInitWithBytesLength,
                      dataAddress, dataLength) : 0;
    }
    if (!bundle || (context->replaceResponse && !data)) {
        if (data) void0(data, context->selRelease);
        if (bundle) void0(bundle, context->selRelease);
        if (pool) poolPop(pool);
        return 0;
    }

    context->targetBundle = bundle;
    context->themedData = data;
    __atomic_store_n(&context->transactionObjectsReady, 1,
                     __ATOMIC_RELEASE);

    CNDReplacementIMP replacement =
        (CNDReplacementIMP)(uintptr_t)replacementAddress;
#if __has_feature(ptrauth_calls)
    replacement = (CNDReplacementIMP)ptrauth_sign_unauthenticated(
        ptrauth_strip(replacement, ptrauth_key_function_pointer),
        ptrauth_key_function_pointer, 0);
#endif
    CNDMethodSetImplementation setter =
        (CNDMethodSetImplementation)(uintptr_t)
            context->methodSetImplementation;
    CNDReplacementIMP prior = setter(context->generationMethod, replacement);
#if __has_feature(ptrauth_calls)
    uintptr_t priorComparable = (uintptr_t)ptrauth_strip(
        prior, ptrauth_key_function_pointer);
    uintptr_t originalComparable = (uintptr_t)ptrauth_strip(
        (CNDReplacementIMP)(uintptr_t)context->originalGenerate,
        ptrauth_key_function_pointer);
#else
    uintptr_t priorComparable = (uintptr_t)prior;
    uintptr_t originalComparable = (uintptr_t)context->originalGenerate;
#endif
    if (!prior || priorComparable != originalComparable) {
        if (prior) (void)setter(context->generationMethod, prior);
        if (pool) poolPop(pool);
        return 0;
    }
    __atomic_store_n(&context->transactionInstalled, 1, __ATOMIC_RELEASE);

    CNDObject response = cnd_icon_publisher_payload_trigger_body(context);
    if (!__atomic_load_n(&context->hookRestored, __ATOMIC_ACQUIRE)) {
        CNDReplacementIMP current = setter(
            context->generationMethod,
            (CNDReplacementIMP)(uintptr_t)context->originalGenerate);
#if __has_feature(ptrauth_calls)
        uintptr_t currentComparable = (uintptr_t)ptrauth_strip(
            current, ptrauth_key_function_pointer);
        uintptr_t replacementComparable = (uintptr_t)ptrauth_strip(
            replacement, ptrauth_key_function_pointer);
#else
        uintptr_t currentComparable = (uintptr_t)current;
        uintptr_t replacementComparable = (uintptr_t)replacement;
#endif
        if (currentComparable == replacementComparable) {
            __atomic_store_n(&context->hookRestored, 1,
                             __ATOMIC_RELEASE);
        }
    }
    __atomic_store_n(&context->capturedTriggerResponse, response,
                     __ATOMIC_RELEASE);
    if (pool) poolPop(pool);
    return response;
}
/* Release every per-icon owning reference in one target-side call. */
CND_PUBLISHER_TEXT uint64_t cnd_icon_publisher_payload_cleanup_body(
    CNDIconServicesPublisherPayloadContext *context)
{
    if (!context || context->magic != CND_ICON_PUBLISHER_PAYLOAD_MAGIC ||
        context->version != CND_ICON_PUBLISHER_PAYLOAD_VERSION ||
        !context->objcMsgSend || !context->selRelease ||
        __atomic_load_n(&context->inFlight, __ATOMIC_ACQUIRE) != 0) return 0;
    CNDMessageVoid0 release =
        (CNDMessageVoid0)(uintptr_t)context->objcMsgSend;
    uint64_t *objects[] = {
        (uint64_t *)&context->capturedTriggerResponse,
        (uint64_t *)&context->capturedReplacement,
        (uint64_t *)&context->capturedStockToken,
        (uint64_t *)&context->capturedStockUUID,
        (uint64_t *)&context->capturedStockData,
        (uint64_t *)&context->capturedDescriptor,
        (uint64_t *)&context->capturedIcon,
        &context->themedData,
        &context->targetBundle,
    };
    uint64_t count = 0;
    for (uint64_t index = 0;
         index < sizeof(objects) / sizeof(objects[0]); index++) {
        uint64_t object = __atomic_exchange_n(
            objects[index], 0, __ATOMIC_ACQ_REL);
        if (object) {
            release(object, context->selRelease);
            count++;
        }
    }
    __atomic_store_n(&context->cleanupReleaseCount, count,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&context->transactionCleaned, 1, __ATOMIC_RELEASE);
    return count + 1;
}
