#include "CNDIconServicesConsumerPayload.h"

#include <stdbool.h>
#include <stddef.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#define CND_PAYLOAD_TEXT                                                     \
    __attribute__((section("__TEXT,__cndhook,regular,pure_instructions"),    \
                   noinline, no_stack_protector, used, visibility("hidden")))

typedef uint64_t CNDObject;
typedef uint64_t CNDSelector;

typedef CNDObject (*CNDMessageObject0)(CNDObject, CNDSelector);
typedef CNDObject (*CNDMessageObject1)(CNDObject, CNDSelector, CNDObject);
typedef CNDObject (*CNDMessageObject1Bool)(CNDObject, CNDSelector,
                                           CNDObject, bool);
typedef uint64_t (*CNDMessageUInt0)(CNDObject, CNDSelector);
typedef void (*CNDMessageVoid0)(CNDObject, CNDSelector);
typedef void (*CNDMessageVoidObject)(CNDObject, CNDSelector, CNDObject);
typedef void (*CNDMessageVoidUInt)(CNDObject, CNDSelector, uint64_t);
typedef void (*CNDMessageVoidBool)(CNDObject, CNDSelector, bool);
typedef void (*CNDMessageVoidDouble)(CNDObject, CNDSelector, double);
typedef void (*CNDMessageVoidFloat)(CNDObject, CNDSelector, float);
typedef struct {
    double x;
    double y;
    double width;
    double height;
} CNDRect;
typedef CNDRect (*CNDMessageRect0)(CNDObject, CNDSelector);
typedef size_t (*CNDImageDimension)(const void *);

typedef CNDObject (*CNDInitSerializedIMP)(CNDObject, CNDSelector, CNDObject,
                                          CNDObject, CNDObject);
typedef CNDObject (*CNDInitDataIMP)(CNDObject, CNDSelector, CNDObject,
                                    CNDObject);
typedef CNDObject (*CNDInitFinalizedIMP)(CNDObject, CNDSelector, CNDObject);
typedef void (*CNDLayoutIMP)(CNDObject, CNDSelector);
typedef void (*CNDReplacementIMP)(void);
typedef CNDReplacementIMP (*CNDMethodSetImplementation)(
    uint64_t, CNDReplacementIMP);
typedef CNDObject (*CNDGetAssociatedObject)(CNDObject, const void *);
typedef void (*CNDSetAssociatedObject)(CNDObject, const void *, CNDObject,
                                       uintptr_t);

typedef void *(*CNDDlopenFunction)(const char *, int);
typedef CNDObject (*CNDObjCGetClassFunction)(const char *);
typedef CNDSelector (*CNDSelectorRegisterFunction)(const char *);
typedef uint64_t (*CNDClassGetInstanceMethodFunction)(CNDObject, CNDSelector);
typedef const char *(*CNDMethodGetTypeEncodingFunction)(uint64_t);
typedef uint64_t (*CNDMethodGetImplementationFunction)(uint64_t);
typedef size_t (*CNDClassGetInstanceSizeFunction)(CNDObject);
typedef uint64_t (*CNDClassGetInstanceVariableFunction)(CNDObject,
                                                        const char *);
typedef ptrdiff_t (*CNDIvarGetOffsetFunction)(uint64_t);
typedef int (*CNDPthreadCreateFromMachThreadFunction)(
    uint64_t *, const void *, void *(*)(void *), void *);
typedef int (*CNDPthreadDetachFunction)(uint64_t);

static CND_PAYLOAD_TEXT uint64_t cnd_payload_function(uint64_t raw)
{
#if __has_feature(ptrauth_calls)
    return (uint64_t)(uintptr_t)ptrauth_sign_unauthenticated(
        ptrauth_strip((void *)(uintptr_t)raw,
                      ptrauth_key_function_pointer),
        ptrauth_key_function_pointer, 0);
#else
    return raw;
#endif
}

#define CND_FUNCTION(type, value) \
    ((type)(uintptr_t)cnd_payload_function((uint64_t)(value)))

static CND_PAYLOAD_TEXT bool cnd_payload_cstring_equal(const char *left,
                                                       const char *right)
{
    if (!left || !right) return false;
    while (*left && *right && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

static CND_PAYLOAD_TEXT bool cnd_payload_context_valid(
    const CNDIconServicesConsumerPayloadContext *context)
{
    return context &&
        context->magic == CND_ICON_CONSUMER_PAYLOAD_MAGIC &&
        context->version == CND_ICON_CONSUMER_PAYLOAD_VERSION &&
        context->objcMsgSend && context->objcGetAssociatedObject &&
        context->objcSetAssociatedObject &&
        context->methodSetImplementation && context->cgImageGetWidth &&
        context->cgImageGetHeight;
}

static CND_PAYLOAD_TEXT bool cnd_payload_contains_marker(
    const CNDIconServicesConsumerPayloadContext *context, CNDObject data)
{
    if (!cnd_payload_context_valid(context) || !data ||
        !context->markerLength ||
        context->markerLength > CND_ICON_CONSUMER_PAYLOAD_MARKER_CAPACITY) {
        return false;
    }
    CNDMessageObject0 messageObject =
        CND_FUNCTION(CNDMessageObject0, context->objcMsgSend);
    CNDMessageUInt0 messageUInt =
        CND_FUNCTION(CNDMessageUInt0, context->objcMsgSend);
    const unsigned char *bytes = (const unsigned char *)(uintptr_t)
        messageObject(data, context->selBytes);
    uint64_t length = messageUInt(data, context->selLength);
    uint64_t markerLength = context->markerLength;
    if (!bytes || length < markerLength) return false;
    for (uint64_t offset = 0; offset <= length - markerLength; offset++) {
        bool equal = true;
        for (uint64_t index = 0; index < markerLength; index++) {
            if (bytes[offset + index] !=
                (unsigned char)context->marker[index]) {
                equal = false;
                break;
            }
        }
        if (equal) return true;
    }
    return false;
}

static CND_PAYLOAD_TEXT void cnd_payload_mark_themed(
    const CNDIconServicesConsumerPayloadContext *context, CNDObject object)
{
    if (!object) return;
    CNDSetAssociatedObject setAssociated =
        CND_FUNCTION(CNDSetAssociatedObject,
                     context->objcSetAssociatedObject);
    setAssociated(object, &context->themedAssociationKey, object, 0);
}

static CND_PAYLOAD_TEXT bool cnd_payload_is_themed(
    const CNDIconServicesConsumerPayloadContext *context, CNDObject object)
{
    if (!object) return false;
    CNDGetAssociatedObject getAssociated =
        CND_FUNCTION(CNDGetAssociatedObject,
                     context->objcGetAssociatedObject);
    return getAssociated(object, &context->themedAssociationKey) != 0;
}

static CND_PAYLOAD_TEXT CNDObject cnd_payload_image(
    const CNDIconServicesConsumerPayloadContext *context, CNDObject object)
{
    if (!object) return 0;
    CNDGetAssociatedObject getAssociated =
        CND_FUNCTION(CNDGetAssociatedObject,
                     context->objcGetAssociatedObject);
    return getAssociated(object, &context->imageAssociationKey);
}

static CND_PAYLOAD_TEXT void cnd_payload_set_image(
    const CNDIconServicesConsumerPayloadContext *context, CNDObject object,
    CNDObject image)
{
    if (!object || !image) return;
    CNDSetAssociatedObject setAssociated =
        CND_FUNCTION(CNDSetAssociatedObject,
                     context->objcSetAssociatedObject);
    /* OBJC_ASSOCIATION_RETAIN_NONATOMIC */
    setAssociated(object, &context->imageAssociationKey, image, 1);
}

static CND_PAYLOAD_TEXT void cnd_payload_prepare_image(
    const CNDIconServicesConsumerPayloadContext *context,
    CNDObject finalizedIcon)
{
    CNDMessageObject0 messageObject =
        CND_FUNCTION(CNDMessageObject0, context->objcMsgSend);
    CNDMessageObject1Bool render =
        CND_FUNCTION(CNDMessageObject1Bool, context->objcMsgSend);
    CNDMessageVoid0 messageVoid =
        CND_FUNCTION(CNDMessageVoid0, context->objcMsgSend);
    CNDObject configuration = messageObject(
        messageObject(context->configurationClass, context->selAlloc),
        context->selInit);
    if (!configuration) return;
    CNDObject image = render(finalizedIcon, context->selRenderedFullBleed,
                             configuration, true);
    CNDImageDimension imageWidth =
        CND_FUNCTION(CNDImageDimension, context->cgImageGetWidth);
    CNDImageDimension imageHeight =
        CND_FUNCTION(CNDImageDimension, context->cgImageGetHeight);
    if (image && imageWidth((const void *)(uintptr_t)image) > 0 &&
        imageHeight((const void *)(uintptr_t)image) > 0) {
        cnd_payload_set_image(context, finalizedIcon, image);
    }
    messageVoid(configuration, context->selRelease);
}

CND_PAYLOAD_TEXT uint64_t cnd_icon_consumer_payload_probe_body(
    const CNDIconServicesConsumerPayloadContext *context)
{
    return cnd_payload_context_valid(context)
        ? (context->magic ^ context->version) : 0;
}

CND_PAYLOAD_TEXT uint64_t cnd_icon_consumer_payload_install_method_body(
    uint64_t method, uint64_t replacementAddress,
    const CNDIconServicesConsumerPayloadContext *context)
{
    if (!cnd_payload_context_valid(context) || !method ||
        !replacementAddress) {
        return 0;
    }

    /*
     * method_setImplementation receives an authenticated IMP on arm64e.
     * A copied payload's mapped address is only a raw code address; passing
     * it directly makes libobjc's method_t::setImp authenticate invalid bits
     * while holding the runtime lock.  Sign it in the target process before
     * entering libobjc.  This body is part of the same copied section, so the
     * VM and physical-device RemoteCall transports use the identical path.
     */
    CNDReplacementIMP replacement =
        (CNDReplacementIMP)(uintptr_t)replacementAddress;
#if __has_feature(ptrauth_calls)
    replacement = (CNDReplacementIMP)ptrauth_sign_unauthenticated(
        ptrauth_strip(replacement, ptrauth_key_function_pointer),
        ptrauth_key_function_pointer, 0);
#endif
    CNDMethodSetImplementation setter =
        CND_FUNCTION(CNDMethodSetImplementation,
                     context->methodSetImplementation);
    return (uint64_t)(uintptr_t)setter(method, replacement);
}

static CND_PAYLOAD_TEXT void cnd_payload_publish_install_result(
    CNDIconServicesConsumerPayloadContext *context, uint32_t result)
{
    context->installResult = result;
    __asm__ volatile("dmb ish" ::: "memory");
    context->installState = CNDIconConsumerInstallStateComplete;
    __asm__ volatile("dmb ish" ::: "memory");
}

static CND_PAYLOAD_TEXT bool cnd_payload_blob_string_valid(
    const char *base, size_t capacity, size_t offset)
{
    if (!base || offset >= capacity) return false;
    for (size_t index = offset; index < capacity; index++) {
        if (base[index] == '\0') return index > offset;
    }
    return false;
}

static CND_PAYLOAD_TEXT uint64_t cnd_payload_strip_imp(uint64_t value)
{
    return value & 0x00007fffffffffffULL;
}

CND_PAYLOAD_TEXT void *cnd_icon_consumer_payload_installer_body(
    void *argument)
{
    CNDIconServicesConsumerPayloadContext *context =
        (CNDIconServicesConsumerPayloadContext *)argument;
    if (!context) return NULL;
    context->installState = CNDIconConsumerInstallStateInstallerRunning;
    __asm__ volatile("dmb ish" ::: "memory");
    if (!cnd_payload_context_valid(context) || !context->remoteBase ||
        !context->dlopenFunction || !context->objcGetClass ||
        !context->selRegisterName || !context->classGetInstanceMethod ||
        !context->methodGetTypeEncoding ||
        !context->methodGetImplementation ||
        !context->classGetInstanceSize ||
        !context->classGetInstanceVariable || !context->ivarGetOffset ||
        context->selectorCount != CND_ICON_CONSUMER_SELECTOR_COUNT) {
        cnd_payload_publish_install_result(
            context, CNDIconConsumerInstallResultContext);
        return NULL;
    }

    CNDDlopenFunction openFramework = CND_FUNCTION(
        CNDDlopenFunction, context->dlopenFunction);
    if (!openFramework(context->frameworkPath, 0x2 | 0x4)) {
        cnd_payload_publish_install_result(
            context, CNDIconConsumerInstallResultFramework);
        return NULL;
    }

    CNDObjCGetClassFunction getClass = CND_FUNCTION(
        CNDObjCGetClassFunction, context->objcGetClass);
    CNDSelectorRegisterFunction registerSelector = CND_FUNCTION(
        CNDSelectorRegisterFunction, context->selRegisterName);
    CNDClassGetInstanceMethodFunction getMethod = CND_FUNCTION(
        CNDClassGetInstanceMethodFunction, context->classGetInstanceMethod);
    CNDMethodGetTypeEncodingFunction getTypes = CND_FUNCTION(
        CNDMethodGetTypeEncodingFunction, context->methodGetTypeEncoding);
    CNDMethodGetImplementationFunction getImplementation = CND_FUNCTION(
        CNDMethodGetImplementationFunction,
        context->methodGetImplementation);
    CNDClassGetInstanceSizeFunction getInstanceSize = CND_FUNCTION(
        CNDClassGetInstanceSizeFunction, context->classGetInstanceSize);
    CNDClassGetInstanceVariableFunction getIvar = CND_FUNCTION(
        CNDClassGetInstanceVariableFunction,
        context->classGetInstanceVariable);
    CNDIvarGetOffsetFunction getIvarOffset = CND_FUNCTION(
        CNDIvarGetOffsetFunction, context->ivarGetOffset);

    CNDObject finalizedClass = getClass(context->finalizedClassName);
    CNDObject layerClass = getClass(context->iconLayerClassName);
    context->configurationClass = getClass(
        context->configurationClassName);
    context->transactionClass = getClass(context->transactionClassName);
    CNDObject stringClass = getClass(context->stringClassName);
    if (!finalizedClass || !layerClass || !context->configurationClass ||
        !context->transactionClass || !stringClass) {
        cnd_payload_publish_install_result(
            context, CNDIconConsumerInstallResultABI);
        return NULL;
    }

    uint64_t *selectorSlots = &context->selAlloc;
    for (uint32_t index = 0; index < context->selectorCount; index++) {
        size_t offset = context->selectorNameOffsets[index];
        if (!cnd_payload_blob_string_valid(
                context->selectorNameBlob,
                sizeof(context->selectorNameBlob), offset)) {
            cnd_payload_publish_install_result(
                context, CNDIconConsumerInstallResultContext);
            return NULL;
        }
        selectorSlots[index] = registerSelector(
            context->selectorNameBlob + offset);
        if (!selectorSlots[index]) {
            cnd_payload_publish_install_result(
                context, CNDIconConsumerInstallResultABI);
            return NULL;
        }
    }

    CNDSelector stringInit = registerSelector(
        context->stringInitSelectorName);
    CNDMessageObject0 message0 = CND_FUNCTION(
        CNDMessageObject0, context->objcMsgSend);
    CNDMessageObject1 message1 = CND_FUNCTION(
        CNDMessageObject1, context->objcMsgSend);
    CNDObject stringObject = message0(stringClass, context->selAlloc);
    context->contentsGravityResize = stringObject && stringInit
        ? message1(stringObject, stringInit,
                   (CNDObject)(uintptr_t)context->gravityString)
        : 0;
    if (!context->contentsGravityResize) {
        cnd_payload_publish_install_result(
            context, CNDIconConsumerInstallResultString);
        return NULL;
    }

    CNDObject classes[4] = {
        finalizedClass, layerClass, layerClass, layerClass,
    };
    for (uint32_t index = 0; index < 4; index++) {
        CNDSelector selector = registerSelector(
            context->methodSelectorNames[index]);
        uint64_t method = selector
            ? getMethod(classes[index], selector) : 0;
        const char *types = method ? getTypes(method) : NULL;
        uint64_t implementation = method
            ? getImplementation(method) : 0;
        if (!method || !implementation ||
            !cnd_payload_cstring_equal(
                types, context->methodTypeEncodings[index])) {
            cnd_payload_publish_install_result(
                context, CNDIconConsumerInstallResultABI);
            return NULL;
        }
        context->methodObjects[index] = method;
        context->observedImplementations[index] = implementation;
    }
    context->originalInitFromSerializedData =
        context->observedImplementations[0];
    context->originalIconLayerInitWithData =
        context->observedImplementations[1];
    context->originalIconLayerInitWithFinalizedIcon =
        context->observedImplementations[2];
    context->originalIconLayerLayout =
        context->observedImplementations[3];

    uint64_t ivar = getIvar(finalizedClass, context->finalizedIvarName);
    CNDSelector rendererSelector = registerSelector(
        context->rendererSelectorName);
    uint64_t rendererMethod = rendererSelector
        ? getMethod(finalizedClass, rendererSelector) : 0;
    const char *rendererTypes = rendererMethod
        ? getTypes(rendererMethod) : NULL;
    if (getInstanceSize(finalizedClass) <= context->finalizedChicletOffset ||
        !ivar || getIvarOffset(ivar) != 8 || !rendererMethod ||
        !cnd_payload_cstring_equal(
            rendererTypes, context->rendererTypeEncoding)) {
        cnd_payload_publish_install_result(
            context, CNDIconConsumerInstallResultABI);
        return NULL;
    }

    uint32_t installed = 0;
    for (uint32_t index = 0; index < 4; index++) {
        uint64_t replacement =
            context->remoteBase + context->replacementOffsets[index];
        uint64_t previous = cnd_icon_consumer_payload_install_method_body(
            context->methodObjects[index], replacement, context);
        if (cnd_payload_strip_imp(previous) != cnd_payload_strip_imp(
                context->observedImplementations[index])) {
            break;
        }
        installed++;
        context->installedCount = installed;
    }
    if (installed != 4) {
        bool rollbackOK = true;
        while (installed > 0) {
            installed--;
            uint64_t replacement = context->observedImplementations[installed];
            uint64_t previous = cnd_icon_consumer_payload_install_method_body(
                context->methodObjects[installed], replacement, context);
            rollbackOK = rollbackOK && previous != 0;
        }
        context->installedCount = 0;
        context->rollbackVerified = rollbackOK ? 1U : 0U;
        cnd_payload_publish_install_result(context,
            rollbackOK ? CNDIconConsumerInstallResultMethod :
                         CNDIconConsumerInstallResultRollback);
        return NULL;
    }

    bool readbackOK = true;
    for (uint32_t index = 0; index < 4; index++) {
        uint64_t observed = getImplementation(context->methodObjects[index]);
        context->observedImplementations[index] = observed;
        readbackOK = readbackOK && cnd_payload_strip_imp(observed) ==
            cnd_payload_strip_imp(
                context->remoteBase + context->replacementOffsets[index]);
    }
    if (!readbackOK) {
        bool rollbackOK = true;
        for (uint32_t index = 4; index > 0; index--) {
            uint32_t slot = index - 1;
            uint64_t previous = cnd_icon_consumer_payload_install_method_body(
                context->methodObjects[slot],
                slot == 0 ? context->originalInitFromSerializedData :
                slot == 1 ? context->originalIconLayerInitWithData :
                slot == 2 ? context->originalIconLayerInitWithFinalizedIcon :
                            context->originalIconLayerLayout,
                context);
            rollbackOK = rollbackOK && previous != 0;
        }
        context->installedCount = 0;
        context->rollbackVerified = rollbackOK ? 1U : 0U;
        cnd_payload_publish_install_result(context,
            rollbackOK ? CNDIconConsumerInstallResultReadback :
                         CNDIconConsumerInstallResultRollback);
        return NULL;
    }

    cnd_payload_publish_install_result(
        context, CNDIconConsumerInstallResultSuccess);
    return NULL;
}

CND_PAYLOAD_TEXT void cnd_icon_consumer_payload_bootstrap_body(
    CNDIconServicesConsumerPayloadContext *context)
{
    if (!context) {
        for (;;) __asm__ volatile("wfe");
    }
    context->installState = CNDIconConsumerInstallStateBootstrapStarted;
    __asm__ volatile("dmb ish" ::: "memory");
    if (!context->pthreadCreateFromMachThread) {
        context->bootstrapResult = CNDIconConsumerInstallResultBootstrap;
        cnd_payload_publish_install_result(
            context, CNDIconConsumerInstallResultBootstrap);
        for (;;) __asm__ volatile("wfe");
    }
    CNDPthreadCreateFromMachThreadFunction createThread = CND_FUNCTION(
        CNDPthreadCreateFromMachThreadFunction,
        context->pthreadCreateFromMachThread);
    void *(*installer)(void *) = CND_FUNCTION(
        void *(*)(void *),
        (uint64_t)(uintptr_t)cnd_icon_consumer_payload_installer);
    uint64_t pthread = 0;
    int result = createThread(&pthread, NULL, installer, context);
    context->bootstrapResult = (uint32_t)result;
    __asm__ volatile("dmb ish" ::: "memory");
    /* pthread_create_from_mach_thread() has returned before the new pthread
     * is safe to pass through pthread_detach() from this raw bootstrap on
     * arm64e. The installer is intentionally one-shot; leaving its tiny
     * join record for the lifetime of the hooked process is safer, and the
     * same process restart that removes the hooks reclaims it. */
    if (result != 0 || !pthread) {
        cnd_payload_publish_install_result(
            context, CNDIconConsumerInstallResultBootstrap);
    }
    for (;;) __asm__ volatile("wfe");
}

CND_PAYLOAD_TEXT CNDObject cnd_icon_consumer_payload_init_serialized_body(
    CNDObject self, CNDSelector selector, CNDObject data, CNDObject device,
    CNDObject error, const CNDIconServicesConsumerPayloadContext *context)
{
    if (!context || !context->originalInitFromSerializedData) return 0;
    bool themed = cnd_payload_contains_marker(context, data);
    CNDInitSerializedIMP original = CND_FUNCTION(
        CNDInitSerializedIMP, context->originalInitFromSerializedData);
    CNDObject result = original(self, selector, data, device, error);
    if (!result || !themed || !cnd_payload_context_valid(context)) {
        return result;
    }
    if (context->finalizedChicletOffset) {
        unsigned char *visible = (unsigned char *)(uintptr_t)
            (result + context->finalizedChicletOffset);
        if (*visible == 1) *visible = 0;
    }
    cnd_payload_mark_themed(context, result);
    cnd_payload_prepare_image(context, result);
    return result;
}

CND_PAYLOAD_TEXT CNDObject cnd_icon_consumer_payload_init_data_body(
    CNDObject self, CNDSelector selector, CNDObject data, CNDObject error,
    const CNDIconServicesConsumerPayloadContext *context)
{
    if (!context || !context->originalIconLayerInitWithData) return 0;
    bool themed = cnd_payload_contains_marker(context, data);
    CNDInitDataIMP original = CND_FUNCTION(
        CNDInitDataIMP, context->originalIconLayerInitWithData);
    CNDObject result = original(self, selector, data, error);
    if (result && themed && cnd_payload_context_valid(context)) {
        cnd_payload_mark_themed(context, result);
    }
    return result;
}

CND_PAYLOAD_TEXT CNDObject cnd_icon_consumer_payload_init_finalized_body(
    CNDObject self, CNDSelector selector, CNDObject finalizedIcon,
    const CNDIconServicesConsumerPayloadContext *context)
{
    if (!context || !context->originalIconLayerInitWithFinalizedIcon) return 0;
    bool themed = cnd_payload_context_valid(context) &&
        cnd_payload_is_themed(context, finalizedIcon);
    CNDObject image = themed
        ? cnd_payload_image(context, finalizedIcon) : 0;
    CNDInitFinalizedIMP original = CND_FUNCTION(
        CNDInitFinalizedIMP, context->originalIconLayerInitWithFinalizedIcon);
    CNDObject result = original(self, selector, finalizedIcon);
    if (result && themed) {
        cnd_payload_mark_themed(context, result);
        cnd_payload_set_image(context, result, image);
    }
    return result;
}

CND_PAYLOAD_TEXT void cnd_icon_consumer_payload_layout_body(
    CNDObject self, CNDSelector selector,
    const CNDIconServicesConsumerPayloadContext *context)
{
    if (!context || !context->originalIconLayerLayout) return;
    CNDLayoutIMP original = CND_FUNCTION(
        CNDLayoutIMP, context->originalIconLayerLayout);
    original(self, selector);
    if (!cnd_payload_context_valid(context)) return;
    CNDObject image = cnd_payload_image(context, self);
    if (!image) return;

    CNDMessageObject0 messageObject =
        CND_FUNCTION(CNDMessageObject0, context->objcMsgSend);
    CNDMessageObject1 messageObject1 =
        CND_FUNCTION(CNDMessageObject1, context->objcMsgSend);
    CNDMessageUInt0 messageUInt =
        CND_FUNCTION(CNDMessageUInt0, context->objcMsgSend);
    CNDMessageVoid0 messageVoid =
        CND_FUNCTION(CNDMessageVoid0, context->objcMsgSend);
    CNDMessageVoidObject messageVoidObject =
        CND_FUNCTION(CNDMessageVoidObject, context->objcMsgSend);
    CNDMessageVoidBool messageVoidBool =
        CND_FUNCTION(CNDMessageVoidBool, context->objcMsgSend);
    CNDMessageVoidDouble messageVoidDouble =
        CND_FUNCTION(CNDMessageVoidDouble, context->objcMsgSend);
    CNDMessageVoidFloat messageVoidFloat =
        CND_FUNCTION(CNDMessageVoidFloat, context->objcMsgSend);
    CNDMessageRect0 messageRect =
        CND_FUNCTION(CNDMessageRect0, context->objcMsgSend);
    CNDImageDimension imageWidth =
        CND_FUNCTION(CNDImageDimension, context->cgImageGetWidth);

    messageVoid(context->transactionClass, context->selBegin);
    messageVoidBool(context->transactionClass,
                    context->selSetDisableActions, true);

    CNDObject children = messageObject(self, context->selSublayers);
    CNDObject snapshot = children
        ? messageObject(children, context->selCopy) : 0;
    uint64_t count = snapshot
        ? messageUInt(snapshot, context->selCount) : 0;
    for (uint64_t index = 0; index < count; index++) {
        CNDObject child = messageObject1(
            snapshot, context->selObjectAtIndex, index);
        if (child) messageVoid(child, context->selRemoveFromSuperlayer);
    }
    if (snapshot) messageVoid(snapshot, context->selRelease);

    messageVoidObject(self, context->selSetContents, image);
    messageVoidObject(self, context->selSetContentsGravity,
                      context->contentsGravityResize);
    CNDRect bounds = messageRect(self, context->selBounds);
    double pixelWidth = (double)imageWidth(
        (const void *)(uintptr_t)image);
    double contentsScale = bounds.width > 0.0
        ? pixelWidth / bounds.width : 1.0;
    messageVoidDouble(self, context->selSetContentsScale,
                      contentsScale > 0.0 ? contentsScale : 1.0);
    messageVoidBool(self, context->selSetOpaque, false);
    messageVoidBool(self, context->selSetMasksToBounds, false);
    messageVoidDouble(self, context->selSetCornerRadius,
                      context->zeroDouble);
    messageVoidDouble(self, context->selSetBorderWidth,
                      context->zeroDouble);
    messageVoidObject(self, context->selSetBackgroundColor, 0);
    messageVoidFloat(self, context->selSetShadowOpacity,
                     context->zeroFloat);
    messageVoid(context->transactionClass, context->selCommit);
}
