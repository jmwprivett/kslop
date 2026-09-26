#ifndef CNDIconServicesPublisherPayload_h
#define CNDIconServicesPublisherPayload_h

#define CND_ICON_PUBLISHER_PAYLOAD_MAGIC 0x434e445055423031ULL
#define CND_ICON_PUBLISHER_PAYLOAD_VERSION 15ULL
#define CND_ICON_PUBLISHER_PAYLOAD_CONTEXT_CAPACITY 1024

#define CND_ICON_PUBLISHER_DESCRIPTOR_POOL_READY       (1ULL << 0)
#define CND_ICON_PUBLISHER_DESCRIPTOR_FACTORY_READY    (1ULL << 1)
#define CND_ICON_PUBLISHER_DESCRIPTOR_FACTORY_RETURNED (1ULL << 2)
#define CND_ICON_PUBLISHER_DESCRIPTOR_COPIED           (1ULL << 3)
#define CND_ICON_PUBLISHER_DESCRIPTOR_CONFIGURED       (1ULL << 4)
#define CND_ICON_PUBLISHER_DESCRIPTOR_VERIFIED         (1ULL << 5)

#ifndef __ASSEMBLER__

#include <stdint.h>

typedef struct {
    uint64_t magic;
    uint64_t version;

    uint64_t objcMsgSend;
    uint64_t methodSetImplementation;
    uint64_t objcAutoreleasePoolPush;
    uint64_t objcAutoreleasePoolPop;
    uint64_t generationMethod;
    uint64_t originalGenerate;
    uint64_t targetBundle;
    uint64_t themedData;
    uint64_t cacheImageClass;
    uint64_t iconClass;
    uint64_t descriptorClass;
    uint64_t descriptorTemplate;
    uint64_t stringClass;
    uint64_t dataClass;

    uint64_t stagingAddress;
    uint64_t stagingCapacity;
    uint64_t stagingBundleLength;
    uint64_t stagingDataOffset;
    uint64_t stagingDataLength;
    uint64_t stagingDecodedOffset;
    uint64_t stagingDecodedLength;
    uint64_t stagingCompressed;
    uint64_t zlibUncompress;
    uint64_t replacementGenerate;

    uint64_t selIcon;
    uint64_t selImageDescriptor;
    uint64_t selRespondsToSelector;
    uint64_t selBundleIdentifier;
    uint64_t selSize;
    uint64_t selScale;
    uint64_t selIsEqualToString;
    uint64_t selData;
    uint64_t selUUID;
    uint64_t selValidationToken;
    uint64_t selAlloc;
    uint64_t selInitWithDataUUIDValidationToken;
    uint64_t selAutorelease;
    uint64_t selRetain;
    uint64_t selRelease;
    uint64_t selLength;
    uint64_t selUUIDString;
    uint64_t selInitWithBundleIdentifier;
    uint64_t selImageDescriptorWithIconVariantOptions;
    uint64_t selCopy;
    uint64_t selSetSize;
    uint64_t selSetScale;
    uint64_t selSetAppearance;
    uint64_t selSetVariantOptions;
    uint64_t selSetIgnoreCache;
    uint64_t selAppearance;
    uint64_t selVariantOptions;
    uint64_t selGenerateImageWithDescriptor;
    uint64_t selInitWithUTF8String;
    uint64_t selInitWithBytesLength;

    double expectedWidth;
    double expectedHeight;
    double expectedScale;
    uint64_t expectedAppearance;
    uint64_t expectedIconVariant;
    uint64_t expectedOptions;
    uint64_t replaceResponse;

    volatile uint64_t inFlight;
    volatile uint64_t matched;
    volatile uint64_t originalReturned;
    volatile uint64_t hookRestored;
    volatile uint64_t replacementCreated;
    volatile uint64_t replacementReturned;
    volatile uint64_t stockDataLength;
    volatile uint64_t themedDataLength;
    volatile uint64_t capturedIcon;
    volatile uint64_t capturedDescriptor;
    volatile uint64_t capturedStockData;
    volatile uint64_t capturedStockUUID;
    volatile uint64_t capturedStockToken;
    volatile uint64_t capturedReplacement;
    volatile uint64_t capturedTriggerResponse;
    volatile uint64_t transactionStarted;
    volatile uint64_t transactionObjectsReady;
    volatile uint64_t transactionInstalled;
    volatile uint64_t transactionCleaned;
    volatile uint64_t cleanupReleaseCount;
    volatile uint64_t decompressionAttempted;
    volatile uint64_t decompressionSucceeded;
    volatile int64_t decompressionResult;
    volatile uint64_t decompressedDataLength;
    volatile uint64_t matchDiagnostics;
    volatile double observedWidth;
    volatile double observedHeight;
    volatile double observedScale;
    volatile uint64_t observedAppearance;
    volatile uint64_t observedIconVariant;
    volatile uint64_t observedOptions;
    volatile uint64_t descriptorPrepared;
    volatile uint64_t descriptorPreparationBits;
} CNDIconServicesPublisherPayloadContext;

extern const unsigned char cnd_icon_publisher_payload_probe[];
extern const unsigned char cnd_icon_publisher_payload_prepare_descriptor[];
extern const unsigned char cnd_icon_publisher_payload_install[];
extern const unsigned char cnd_icon_publisher_payload_generate[];
extern const unsigned char cnd_icon_publisher_payload_trigger[];
extern const unsigned char cnd_icon_publisher_payload_execute[];
extern const unsigned char cnd_icon_publisher_payload_cleanup[];
extern const unsigned char cnd_icon_publisher_payload_context[];

uint64_t cnd_icon_publisher_payload_probe_body(
    const CNDIconServicesPublisherPayloadContext *context);
uint64_t cnd_icon_publisher_payload_prepare_descriptor_body(
    CNDIconServicesPublisherPayloadContext *context);
uint64_t cnd_icon_publisher_payload_install_body(
    uint64_t method, uint64_t replacementAddress,
    const CNDIconServicesPublisherPayloadContext *context);
uint64_t cnd_icon_publisher_payload_generate_body(
    uint64_t self, uint64_t selector, uint64_t recordIdentifiersOut,
    CNDIconServicesPublisherPayloadContext *context);
uint64_t cnd_icon_publisher_payload_trigger_body(
    CNDIconServicesPublisherPayloadContext *context);
uint64_t cnd_icon_publisher_payload_execute_body(
    uint64_t replacementAddress,
    CNDIconServicesPublisherPayloadContext *context);
uint64_t cnd_icon_publisher_payload_cleanup_body(
    CNDIconServicesPublisherPayloadContext *context);

#endif /* !__ASSEMBLER__ */

#endif /* CNDIconServicesPublisherPayload_h */
