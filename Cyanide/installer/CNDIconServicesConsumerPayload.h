#ifndef CNDIconServicesConsumerPayload_h
#define CNDIconServicesConsumerPayload_h

#define CND_ICON_CONSUMER_PAYLOAD_MAGIC 0x434e4449434f4e31ULL
#define CND_ICON_CONSUMER_PAYLOAD_VERSION 4ULL
#define CND_ICON_CONSUMER_PAYLOAD_CONTEXT_CAPACITY 4096
#define CND_ICON_CONSUMER_PAYLOAD_MARKER_CAPACITY 32
#define CND_ICON_CONSUMER_SELECTOR_COUNT 24
#define CND_ICON_CONSUMER_SELECTOR_BLOB_CAPACITY 768

#ifndef __ASSEMBLER__

#include <stdint.h>

enum {
    CNDIconConsumerInstallStatePrepared = 1,
    CNDIconConsumerInstallStateBootstrapStarted = 2,
    CNDIconConsumerInstallStateInstallerRunning = 3,
    CNDIconConsumerInstallStateComplete = 4,
};

enum {
    CNDIconConsumerInstallResultPending = 0,
    CNDIconConsumerInstallResultSuccess = 1,
    CNDIconConsumerInstallResultContext = 2,
    CNDIconConsumerInstallResultFramework = 3,
    CNDIconConsumerInstallResultABI = 4,
    CNDIconConsumerInstallResultString = 5,
    CNDIconConsumerInstallResultMethod = 6,
    CNDIconConsumerInstallResultReadback = 7,
    CNDIconConsumerInstallResultRollback = 8,
    CNDIconConsumerInstallResultBootstrap = 9,
};

typedef struct {
    uint64_t magic;
    uint64_t version;

    uint64_t objcMsgSend;
    uint64_t objcGetAssociatedObject;
    uint64_t objcSetAssociatedObject;
    uint64_t methodSetImplementation;
    uint64_t cgImageGetWidth;
    uint64_t cgImageGetHeight;

    uint64_t dlopenFunction;
    uint64_t objcGetClass;
    uint64_t selRegisterName;
    uint64_t classGetInstanceMethod;
    uint64_t methodGetTypeEncoding;
    uint64_t methodGetImplementation;
    uint64_t classGetInstanceSize;
    uint64_t classGetInstanceVariable;
    uint64_t ivarGetOffset;
    uint64_t pthreadCreateFromMachThread;
    uint64_t pthreadDetach;

    uint64_t originalInitFromSerializedData;
    uint64_t originalIconLayerInitWithData;
    uint64_t originalIconLayerInitWithFinalizedIcon;
    uint64_t originalIconLayerLayout;

    uint64_t configurationClass;
    uint64_t transactionClass;

    uint64_t selAlloc;
    uint64_t selInit;
    uint64_t selRelease;
    uint64_t selBytes;
    uint64_t selLength;
    uint64_t selRenderedFullBleed;
    uint64_t selCopy;
    uint64_t selCount;
    uint64_t selObjectAtIndex;
    uint64_t selRemoveFromSuperlayer;
    uint64_t selSublayers;
    uint64_t selSetContents;
    uint64_t selSetContentsGravity;
    uint64_t selSetContentsScale;
    uint64_t selSetOpaque;
    uint64_t selSetMasksToBounds;
    uint64_t selSetCornerRadius;
    uint64_t selSetBorderWidth;
    uint64_t selSetBackgroundColor;
    uint64_t selSetShadowOpacity;
    uint64_t selBegin;
    uint64_t selSetDisableActions;
    uint64_t selCommit;
    uint64_t selBounds;

    uint64_t contentsGravityResize;
    uint64_t finalizedChicletOffset;
    uint64_t markerLength;
    double contentsScale;
    double zeroDouble;
    float zeroFloat;
    uint32_t reserved;

    /* The addresses of these fields are stable, process-local association
     * keys. Their values are deliberately unused. */
    uint64_t themedAssociationKey;
    uint64_t imageAssociationKey;

    char marker[CND_ICON_CONSUMER_PAYLOAD_MARKER_CAPACITY];

    uint64_t remoteBase;
    uint64_t replacementOffsets[4];
    uint64_t methodObjects[4];
    uint64_t observedImplementations[4];
    volatile uint32_t installState;
    volatile uint32_t installResult;
    volatile uint32_t bootstrapResult;
    volatile uint32_t installedCount;
    volatile uint32_t rollbackVerified;
    uint32_t selectorCount;
    uint16_t selectorNameOffsets[CND_ICON_CONSUMER_SELECTOR_COUNT];
    uint16_t reserved2;

    char selectorNameBlob[CND_ICON_CONSUMER_SELECTOR_BLOB_CAPACITY];
    char frameworkPath[128];
    char finalizedClassName[32];
    char iconLayerClassName[32];
    char configurationClassName[32];
    char transactionClassName[32];
    char stringClassName[32];
    char stringInitSelectorName[32];
    char gravityString[16];
    char methodSelectorNames[4][64];
    char methodTypeEncodings[4][48];
    char rendererSelectorName[96];
    char rendererTypeEncoding[48];
    char finalizedIvarName[32];
} CNDIconServicesConsumerPayloadContext;

_Static_assert(sizeof(CNDIconServicesConsumerPayloadContext) <=
                   CND_ICON_CONSUMER_PAYLOAD_CONTEXT_CAPACITY,
               "consumer payload context exceeds its reserved page");

extern const unsigned char cnd_icon_consumer_payload_bootstrap[];
extern const unsigned char cnd_icon_consumer_payload_installer[];
extern const unsigned char cnd_icon_consumer_payload_probe[];
extern const unsigned char cnd_icon_consumer_payload_install_method[];
extern const unsigned char cnd_icon_consumer_payload_init_serialized[];
extern const unsigned char cnd_icon_consumer_payload_init_data[];
extern const unsigned char cnd_icon_consumer_payload_init_finalized[];
extern const unsigned char cnd_icon_consumer_payload_layout[];
extern const unsigned char cnd_icon_consumer_payload_context[];

/* The assembly entry stubs branch to these position-independent hook bodies.
 * The complete section is copied unchanged into either RemoteCall transport. */
uint64_t cnd_icon_consumer_payload_install_method_body(
    uint64_t method, uint64_t replacementAddress,
    const CNDIconServicesConsumerPayloadContext *context);
void cnd_icon_consumer_payload_bootstrap_body(
    CNDIconServicesConsumerPayloadContext *context);
uint64_t cnd_icon_consumer_payload_init_serialized_body(
    uint64_t self, uint64_t selector, uint64_t data, uint64_t device,
    uint64_t error,
    const CNDIconServicesConsumerPayloadContext *context);
uint64_t cnd_icon_consumer_payload_init_data_body(
    uint64_t self, uint64_t selector, uint64_t data, uint64_t error,
    const CNDIconServicesConsumerPayloadContext *context);
uint64_t cnd_icon_consumer_payload_init_finalized_body(
    uint64_t self, uint64_t selector, uint64_t finalizedIcon,
    const CNDIconServicesConsumerPayloadContext *context);
void cnd_icon_consumer_payload_layout_body(
    uint64_t self, uint64_t selector,
    const CNDIconServicesConsumerPayloadContext *context);

#endif /* !__ASSEMBLER__ */

#endif /* CNDIconServicesConsumerPayload_h */
