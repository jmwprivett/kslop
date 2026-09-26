#import "CNDIconServicesConsumerKernelInstaller.h"

#import "CNDIconServicesConsumerPayload.h"
#import "../LogTextView.h"
#import "../TaskRop/CNDKernelTaskBridge.h"

#import <dlfcn.h>
#import <mach/mach_time.h>
#import <ptrauth.h>
#import <string.h>
#import <unistd.h>

static NSString * const CNDConsumerKernelJournalKey =
    @"CNDIconServicesConsumerHookMappingsV1";

extern const uint8_t cnd_consumer_payload_section_start[]
    __asm("section$start$__TEXT$__cndhook");
extern const uint8_t cnd_consumer_payload_section_end[]
    __asm("section$end$__TEXT$__cndhook");

typedef struct {
    const uint8_t *bytes;
    size_t length;
    size_t mappingLength;
    size_t codeLength;
    size_t contextOffset;
    size_t bootstrapOffset;
    size_t replacementOffsets[4];
} CNDConsumerKernelPayloadLayout;

static NSObject *CNDConsumerKernelInstallLock(void)
{
    static NSObject *lock;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ lock = [[NSObject alloc] init]; });
    return lock;
}

static double CNDConsumerKernelElapsedMS(uint64_t start, uint64_t end)
{
    mach_timebase_info_data_t timebase = {0};
    if (end < start || mach_timebase_info(&timebase) != KERN_SUCCESS ||
        timebase.denom == 0) return 0.0;
    long double ns = (long double)(end - start) * timebase.numer /
        timebase.denom;
    return (double)(ns / 1000000.0L);
}

static uint64_t CNDConsumerKernelStripCodePointer(uint64_t value)
{
    return value & 0x00007fffffffffffULL;
}

static uint64_t CNDConsumerKernelRawSymbol(const char *name)
{
    void *symbol = name ? dlsym(RTLD_DEFAULT, name) : NULL;
#if __has_feature(ptrauth_calls)
    if (symbol) {
        symbol = ptrauth_strip(symbol, ptrauth_key_function_pointer);
    }
#endif
    return (uint64_t)(uintptr_t)symbol;
}

static BOOL CNDConsumerKernelCopyCString(char *destination,
                                         size_t capacity,
                                         const char *source)
{
    if (!destination || capacity == 0 || !source) return NO;
    size_t length = strlen(source);
    if (length == 0 || length >= capacity) return NO;
    memcpy(destination, source, length + 1);
    return YES;
}

static BOOL CNDConsumerKernelPayloadLayoutResolve(
    CNDConsumerKernelPayloadLayout *layout, NSString **failure)
{
    if (layout) memset(layout, 0, sizeof(*layout));
    const uint8_t *start = cnd_consumer_payload_section_start;
    const uint8_t *end = cnd_consumer_payload_section_end;
    size_t length = start && end > start ? (size_t)(end - start) : 0;
    size_t pageSize = (size_t)getpagesize();
    if (!layout || pageSize == 0 || length == 0 || length > (1U << 20)) {
        if (failure) *failure = @"The local consumer payload section is invalid.";
        return NO;
    }
#define CND_KERNEL_OFFSET(symbol) ((size_t)((const uint8_t *)(symbol) - start))
    size_t contextOffset = CND_KERNEL_OFFSET(
        cnd_icon_consumer_payload_context);
    size_t bootstrapOffset = CND_KERNEL_OFFSET(
        cnd_icon_consumer_payload_bootstrap);
    size_t replacements[4] = {
        CND_KERNEL_OFFSET(cnd_icon_consumer_payload_init_serialized),
        CND_KERNEL_OFFSET(cnd_icon_consumer_payload_init_data),
        CND_KERNEL_OFFSET(cnd_icon_consumer_payload_init_finalized),
        CND_KERNEL_OFFSET(cnd_icon_consumer_payload_layout),
    };
#undef CND_KERNEL_OFFSET
    size_t mappingLength = (length + pageSize - 1) & ~(pageSize - 1);
    if ((pageSize & (pageSize - 1)) != 0 ||
        contextOffset == 0 || contextOffset % pageSize != 0 ||
        contextOffset + sizeof(CNDIconServicesConsumerPayloadContext) >
            length ||
        contextOffset + CND_ICON_CONSUMER_PAYLOAD_CONTEXT_CAPACITY > length ||
        bootstrapOffset + 8 > contextOffset ||
        mappingLength < length) {
        if (failure) {
            *failure = [NSString stringWithFormat:
                @"The consumer payload code/context split is invalid "
                 "(length=%zu context=%zu page=%zu).",
                length, contextOffset, pageSize];
        }
        return NO;
    }
    for (NSUInteger index = 0; index < 4; index++) {
        if (replacements[index] + 8 > contextOffset) {
            if (failure) *failure = @"A consumer replacement lies outside the executable page range.";
            return NO;
        }
    }
    layout->bytes = start;
    layout->length = length;
    layout->mappingLength = mappingLength;
    layout->codeLength = contextOffset;
    layout->contextOffset = contextOffset;
    layout->bootstrapOffset = bootstrapOffset;
    memcpy(layout->replacementOffsets, replacements, sizeof(replacements));
    return YES;
}

static BOOL CNDConsumerKernelAppendSelector(
    CNDIconServicesConsumerPayloadContext *context,
    uint32_t index, size_t *cursor, const char *name)
{
    if (!context || !cursor || !name ||
        index >= CND_ICON_CONSUMER_SELECTOR_COUNT) return NO;
    size_t length = strlen(name) + 1;
    if (*cursor > UINT16_MAX ||
        length > sizeof(context->selectorNameBlob) - *cursor) return NO;
    context->selectorNameOffsets[index] = (uint16_t)*cursor;
    memcpy(context->selectorNameBlob + *cursor, name, length);
    *cursor += length;
    return YES;
}

static BOOL CNDConsumerKernelPrepareContext(
    CNDIconServicesConsumerPayloadContext *context,
    const CNDConsumerKernelPayloadLayout *layout,
    uint64_t remoteBase, double displayScale,
    NSString **failure)
{
    if (!context || !layout || !remoteBase) return NO;
    memset(context, 0, sizeof(*context));
    context->magic = CND_ICON_CONSUMER_PAYLOAD_MAGIC;
    context->version = CND_ICON_CONSUMER_PAYLOAD_VERSION;
    context->objcMsgSend = CNDConsumerKernelRawSymbol("objc_msgSend");
    context->objcGetAssociatedObject = CNDConsumerKernelRawSymbol(
        "objc_getAssociatedObject");
    context->objcSetAssociatedObject = CNDConsumerKernelRawSymbol(
        "objc_setAssociatedObject");
    context->methodSetImplementation = CNDConsumerKernelRawSymbol(
        "method_setImplementation");
    context->cgImageGetWidth = CNDConsumerKernelRawSymbol("CGImageGetWidth");
    context->cgImageGetHeight = CNDConsumerKernelRawSymbol("CGImageGetHeight");
    context->dlopenFunction = CNDConsumerKernelRawSymbol("dlopen");
    context->objcGetClass = CNDConsumerKernelRawSymbol("objc_getClass");
    context->selRegisterName = CNDConsumerKernelRawSymbol("sel_registerName");
    context->classGetInstanceMethod = CNDConsumerKernelRawSymbol(
        "class_getInstanceMethod");
    context->methodGetTypeEncoding = CNDConsumerKernelRawSymbol(
        "method_getTypeEncoding");
    context->methodGetImplementation = CNDConsumerKernelRawSymbol(
        "method_getImplementation");
    context->classGetInstanceSize = CNDConsumerKernelRawSymbol(
        "class_getInstanceSize");
    context->classGetInstanceVariable = CNDConsumerKernelRawSymbol(
        "class_getInstanceVariable");
    context->ivarGetOffset = CNDConsumerKernelRawSymbol("ivar_getOffset");
    context->pthreadCreateFromMachThread = CNDConsumerKernelRawSymbol(
        "pthread_create_from_mach_thread");
    context->pthreadDetach = CNDConsumerKernelRawSymbol("pthread_detach");
    const uint64_t requiredSymbols[] = {
        context->objcMsgSend, context->objcGetAssociatedObject,
        context->objcSetAssociatedObject, context->methodSetImplementation,
        context->cgImageGetWidth, context->cgImageGetHeight,
        context->dlopenFunction, context->objcGetClass,
        context->selRegisterName, context->classGetInstanceMethod,
        context->methodGetTypeEncoding, context->methodGetImplementation,
        context->classGetInstanceSize, context->classGetInstanceVariable,
        context->ivarGetOffset, context->pthreadCreateFromMachThread,
        context->pthreadDetach,
    };
    for (size_t index = 0;
         index < sizeof(requiredSymbols) / sizeof(requiredSymbols[0]);
         index++) {
        if (!requiredSymbols[index]) {
            if (failure) *failure = @"A required shared-cache runtime symbol is unavailable.";
            return NO;
        }
    }

    context->remoteBase = remoteBase;
    memcpy(context->replacementOffsets, layout->replacementOffsets,
           sizeof(context->replacementOffsets));
    context->finalizedChicletOffset = 0xb8;
    context->contentsScale = displayScale > 0.0 ? displayScale : 3.0;
    context->installState = CNDIconConsumerInstallStatePrepared;
    context->installResult = CNDIconConsumerInstallResultPending;
    context->selectorCount = CND_ICON_CONSUMER_SELECTOR_COUNT;

    const char *marker = "CNDThemeIcon.v1";
    context->markerLength = strlen(marker);
    if (!CNDConsumerKernelCopyCString(context->marker,
            sizeof(context->marker), marker) ||
        !CNDConsumerKernelCopyCString(context->frameworkPath,
            sizeof(context->frameworkPath),
            "/System/Library/PrivateFrameworks/IconRendering.framework/IconRendering") ||
        !CNDConsumerKernelCopyCString(context->finalizedClassName,
            sizeof(context->finalizedClassName), "ICRFinalizedIcon") ||
        !CNDConsumerKernelCopyCString(context->iconLayerClassName,
            sizeof(context->iconLayerClassName), "ICRIconLayer") ||
        !CNDConsumerKernelCopyCString(context->configurationClassName,
            sizeof(context->configurationClassName), "ICRGlobalConfiguration") ||
        !CNDConsumerKernelCopyCString(context->transactionClassName,
            sizeof(context->transactionClassName), "CATransaction") ||
        !CNDConsumerKernelCopyCString(context->stringClassName,
            sizeof(context->stringClassName), "NSString") ||
        !CNDConsumerKernelCopyCString(context->stringInitSelectorName,
            sizeof(context->stringInitSelectorName), "initWithUTF8String:") ||
        !CNDConsumerKernelCopyCString(context->gravityString,
            sizeof(context->gravityString), "resize") ||
        !CNDConsumerKernelCopyCString(context->finalizedIvarName,
            sizeof(context->finalizedIvarName), "finalizedIcon")) {
        if (failure) *failure = @"A payload metadata string exceeded its fixed capacity.";
        return NO;
    }

    const char *selectors[CND_ICON_CONSUMER_SELECTOR_COUNT] = {
        "alloc", "init", "release", "bytes", "length",
        "renderedFullBleedIconWithConfiguration:excludeChicletSpecularHighlights:",
        "copy", "count", "objectAtIndex:", "removeFromSuperlayer",
        "sublayers", "setContents:", "setContentsGravity:",
        "setContentsScale:", "setOpaque:", "setMasksToBounds:",
        "setCornerRadius:", "setBorderWidth:", "setBackgroundColor:",
        "setShadowOpacity:", "begin", "setDisableActions:", "commit",
        "bounds",
    };
    size_t selectorCursor = 0;
    for (uint32_t index = 0; index < CND_ICON_CONSUMER_SELECTOR_COUNT;
         index++) {
        if (!CNDConsumerKernelAppendSelector(
                context, index, &selectorCursor, selectors[index])) {
            if (failure) *failure = @"The selector metadata blob is invalid.";
            return NO;
        }
    }

    const char *methodNames[4] = {
        "initFromSerializedData:device:error:",
        "initWithData:error:",
        "initWithFinalizedIcon:",
        "layoutSublayers",
    };
    const char *methodTypes[4] = {
        "@40@0:8@16@24^@32", "@32@0:8@16^@24",
        "@24@0:8@16", "v16@0:8",
    };
    for (NSUInteger index = 0; index < 4; index++) {
        if (!CNDConsumerKernelCopyCString(context->methodSelectorNames[index],
                sizeof(context->methodSelectorNames[index]), methodNames[index]) ||
            !CNDConsumerKernelCopyCString(context->methodTypeEncodings[index],
                sizeof(context->methodTypeEncodings[index]), methodTypes[index])) {
            if (failure) *failure = @"The method ABI metadata is invalid.";
            return NO;
        }
    }
    if (!CNDConsumerKernelCopyCString(context->rendererSelectorName,
            sizeof(context->rendererSelectorName),
            "renderedFullBleedIconWithConfiguration:excludeChicletSpecularHighlights:") ||
        !CNDConsumerKernelCopyCString(context->rendererTypeEncoding,
            sizeof(context->rendererTypeEncoding),
            "^{CGImage=}28@0:8@16B24")) {
        if (failure) *failure = @"The full-bleed renderer ABI metadata is invalid.";
        return NO;
    }
    return YES;
}

static NSDictionary *CNDConsumerKernelSavedMapping(NSString *host)
{
    NSDictionary *all = [NSUserDefaults.standardUserDefaults
        dictionaryForKey:CNDConsumerKernelJournalKey];
    id value = all[host];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

static void CNDConsumerKernelForgetMapping(NSString *host)
{
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSMutableDictionary *all = [[defaults
        dictionaryForKey:CNDConsumerKernelJournalKey] mutableCopy];
    if (![all[host] isKindOfClass:NSDictionary.class]) return;
    [all removeObjectForKey:host];
    if (all.count) [defaults setObject:all forKey:CNDConsumerKernelJournalKey];
    else [defaults removeObjectForKey:CNDConsumerKernelJournalKey];
    (void)[defaults synchronize];
}

static void CNDConsumerKernelSaveMapping(
    NSString *host, pid_t pid, uint64_t base, uint64_t length,
    uint64_t contextAddress, BOOL complete)
{
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSMutableDictionary *all = [[defaults
        dictionaryForKey:CNDConsumerKernelJournalKey] mutableCopy] ?:
        [NSMutableDictionary dictionary];
    all[host] = @{
        @"pid": @(pid), @"base": @(base), @"length": @(length),
        @"context": @(contextAddress),
        @"version": @(CND_ICON_CONSUMER_PAYLOAD_VERSION),
        @"transport": @"kernel-self-install",
        @"complete": @(complete),
    };
    [defaults setObject:all forKey:CNDConsumerKernelJournalKey];
    (void)[defaults synchronize];
}

static NSString *CNDConsumerKernelResultDescription(uint32_t result)
{
    switch (result) {
        case CNDIconConsumerInstallResultSuccess: return @"success";
        case CNDIconConsumerInstallResultContext: return @"context";
        case CNDIconConsumerInstallResultFramework: return @"framework";
        case CNDIconConsumerInstallResultABI: return @"runtime-abi";
        case CNDIconConsumerInstallResultString: return @"string";
        case CNDIconConsumerInstallResultMethod: return @"method-install";
        case CNDIconConsumerInstallResultReadback: return @"method-readback";
        case CNDIconConsumerInstallResultRollback: return @"rollback";
        case CNDIconConsumerInstallResultBootstrap: return @"bootstrap";
        default: return @"pending";
    }
}

static NSDictionary<NSString *, id> *CNDConsumerKernelInstall(
    pid_t requestedPID, NSString *processName, double displayScale)
{
    uint64_t started = mach_continuous_time();
    NSString *stage = @"preflight";
    NSString *message = @"The direct consumer installer failed.";
    NSString *mode = @"none";
    NSString *failure = nil;
    NSError *openError = nil;
    NSDictionary *saved = nil;
    NSMutableData *payload = nil;
    NSMutableData *payloadReadbackData = nil;
    CNDConsumerKernelPayloadLayout layout = {0};
    CNDIconServicesConsumerPayloadContext prepared = {0};
    CNDIconServicesConsumerPayloadContext observed = {0};
    CNDKernelTaskBridgeSession *session = nil;
    uint64_t mapping = 0;
    uint64_t stack = 0;
    size_t stackLength = (size_t)getpagesize();
    kern_return_t allocateResult = KERN_NOT_SUPPORTED;
    kern_return_t stackAllocateResult = KERN_NOT_SUPPORTED;
    kern_return_t writeResult = KERN_NOT_SUPPORTED;
    kern_return_t readbackResult = KERN_NOT_SUPPORTED;
    kern_return_t protectResult = KERN_NOT_SUPPORTED;
    kern_return_t flushResult = KERN_NOT_SUPPORTED;
    kern_return_t threadResult = KERN_NOT_SUPPORTED;
    kern_return_t threadTerminateResult = KERN_NOT_SUPPORTED;
    kern_return_t stackDeallocateResult = KERN_NOT_SUPPORTED;
    BOOL payloadReadback = NO;
    BOOL identityStable = NO;
    BOOL sessionClosed = NO;
    BOOL existing = NO;
    BOOL installed = NO;

    if (processName.length == 0 || processName.length >= 32 ||
        (requestedPID != 0 && requestedPID <= 1)) {
        stage = @"process-name";
        message = @"A valid target process identity is required.";
        goto finish;
    }
    if (!CNDConsumerKernelPayloadLayoutResolve(&layout, &failure)) {
        stage = @"payload-layout";
        message = failure ?: @"The local consumer payload is invalid.";
        goto finish;
    }
    session = requestedPID > 1
        ? [CNDKernelTaskBridgeSession openPID:requestedPID
                         expectedProcessName:processName error:&openError]
        : [CNDKernelTaskBridgeSession openProcess:processName error:&openError];
    if (!session) {
        stage = @"task-open";
        message = openError.localizedDescription ?:
            @"The direct kernel task bridge could not open the target.";
        goto finish;
    }
    mode = session.mode ?: @"unknown";

    saved = CNDConsumerKernelSavedMapping(processName);
    if (saved) {
        pid_t savedPID = [saved[@"pid"] intValue];
        uint64_t savedVersion = [saved[@"version"] unsignedLongLongValue];
        if (savedPID > 1 && savedPID != session.pid) {
            CNDConsumerKernelForgetMapping(processName);
            saved = nil;
        } else if (savedPID == session.pid &&
                   savedVersion != CND_ICON_CONSUMER_PAYLOAD_VERSION) {
            stage = @"live-version-conflict";
            message = @"This process still has an older consumer payload; restart the process once before installing Phase 2.";
            goto finish;
        }
    }
    if (saved) {
        uint64_t savedBase = [saved[@"base"] unsignedLongLongValue];
        uint64_t savedLength = [saved[@"length"] unsignedLongLongValue];
        uint64_t savedContext = [saved[@"context"] unsignedLongLongValue];
        readbackResult = [session readAddress:savedContext
                                       buffer:&observed
                                       length:sizeof(observed)];
        BOOL offsetsMatch = YES;
        for (NSUInteger index = 0; index < 4; index++) {
            offsetsMatch = offsetsMatch &&
                CNDConsumerKernelStripCodePointer(
                    observed.observedImplementations[index]) ==
                CNDConsumerKernelStripCodePointer(
                    savedBase + layout.replacementOffsets[index]);
        }
        if (savedBase && savedLength == layout.mappingLength &&
            savedContext == savedBase + layout.contextOffset &&
            readbackResult == KERN_SUCCESS &&
            observed.magic == CND_ICON_CONSUMER_PAYLOAD_MAGIC &&
            observed.version == CND_ICON_CONSUMER_PAYLOAD_VERSION &&
            observed.remoteBase == savedBase &&
            observed.installState == CNDIconConsumerInstallStateComplete &&
            observed.installResult == CNDIconConsumerInstallResultSuccess &&
            observed.installedCount == 4 && offsetsMatch) {
            mapping = savedBase;
            existing = YES;
            installed = YES;
            identityStable = [session identityIsStable];
            stage = identityStable ? @"already-installed" : @"identity-drift";
            message = identityStable
                ? @"The marker-aware consumer payload is already installed in this exact process."
                : @"The target identity changed while verifying its existing payload.";
            goto finish;
        }
        stage = @"saved-mapping-mismatch";
        message = @"The saved live-process mapping did not verify; restart this process before retrying.";
        goto finish;
    }

    allocateResult = [session allocateLength:layout.mappingLength
                                   addressOut:&mapping];
    if (allocateResult != KERN_SUCCESS || !mapping) {
        stage = @"payload-allocate";
        message = @"The target payload mapping could not be allocated.";
        goto finish;
    }
    if (!CNDConsumerKernelPrepareContext(
            &prepared, &layout, mapping, displayScale, &failure)) {
        stage = @"context";
        message = failure ?: @"The target installer context is invalid.";
        goto finish;
    }
    payload = [NSMutableData dataWithLength:layout.length];
    memcpy(payload.mutableBytes, layout.bytes, layout.length);
    memcpy((uint8_t *)payload.mutableBytes + layout.contextOffset,
           &prepared, sizeof(prepared));
    writeResult = [session writeAddress:mapping
                                  buffer:payload.bytes
                                  length:payload.length];
    if (writeResult != KERN_SUCCESS) {
        stage = @"payload-write";
        message = @"The complete payload could not be written to the target.";
        goto finish;
    }
    payloadReadbackData = [NSMutableData dataWithLength:layout.length];
    readbackResult = [session readAddress:mapping
                                    buffer:payloadReadbackData.mutableBytes
                                    length:payloadReadbackData.length];
    payloadReadback = readbackResult == KERN_SUCCESS &&
        [payloadReadbackData isEqualToData:payload];
    if (!payloadReadback) {
        stage = @"payload-readback";
        message = @"The target payload failed exact byte readback.";
        goto finish;
    }
    protectResult = [session protectRXAddress:mapping
                                        length:layout.codeLength];
    if (protectResult != KERN_SUCCESS) {
        stage = @"payload-protect";
        message = @"The target payload code pages could not be made read/execute.";
        goto finish;
    }
    flushResult = [session flushInstructionCacheAtAddress:mapping
                                                    length:layout.codeLength];
    if (flushResult != KERN_SUCCESS) {
        stage = @"payload-cache-flush";
        message = @"The target instruction cache could not be synchronized.";
        goto finish;
    }
    stackAllocateResult = [session allocateLength:stackLength
                                        addressOut:&stack];
    if (stackAllocateResult != KERN_SUCCESS || !stack) {
        stage = @"bootstrap-stack";
        message = @"The one-shot bootstrap stack could not be allocated.";
        goto finish;
    }
    threadResult = [session
        startBootstrapThreadAtAddress:mapping + layout.bootstrapOffset
                         stackPointer:(stack + stackLength - 16) & ~0xFULL];
    if (threadResult != KERN_SUCCESS) {
        stage = @"bootstrap-start";
        message = @"The one-shot target bootstrap thread could not be started.";
        goto finish;
    }

    stage = @"installer-wait";
    for (NSUInteger attempt = 0; attempt < 2500; attempt++) {
        readbackResult = [session readAddress:mapping + layout.contextOffset
                                        buffer:&observed
                                        length:sizeof(observed)];
        if (readbackResult != KERN_SUCCESS) break;
        if (observed.installState == CNDIconConsumerInstallStateComplete) break;
        usleep(2000);
    }
    threadTerminateResult = [session terminateBootstrapThread];
    if (readbackResult != KERN_SUCCESS) {
        stage = @"installer-readback";
        message = @"The installer context could not be read back.";
        goto finish;
    }
    if (observed.installState != CNDIconConsumerInstallStateComplete) {
        stage = @"installer-timeout";
        message = @"The target installer did not complete within five seconds.";
        goto finish;
    }
    if (threadTerminateResult != KERN_SUCCESS) {
        stage = @"bootstrap-teardown";
        message = @"The bootstrap thread could not be terminated cleanly.";
        goto finish;
    }
    if (observed.installResult != CNDIconConsumerInstallResultSuccess ||
        observed.installedCount != 4) {
        stage = [NSString stringWithFormat:@"installer-%@",
            CNDConsumerKernelResultDescription(observed.installResult)];
        message = [NSString stringWithFormat:
            @"The target installer rejected its %@ gate; rollback=%@.",
            CNDConsumerKernelResultDescription(observed.installResult),
            observed.rollbackVerified ? @"verified" : @"not-proven"];
        goto finish;
    }
    for (NSUInteger index = 0; index < 4; index++) {
        if (CNDConsumerKernelStripCodePointer(
                observed.observedImplementations[index]) !=
            CNDConsumerKernelStripCodePointer(
                mapping + layout.replacementOffsets[index])) {
            stage = @"method-readback";
            message = @"The target method implementation readback is inconsistent.";
            goto finish;
        }
    }
    identityStable = [session identityIsStable];
    if (!identityStable) {
        stage = @"identity-drift";
        message = @"The target process changed during payload installation.";
        goto finish;
    }
    CNDConsumerKernelSaveMapping(processName, session.pid, mapping,
        layout.mappingLength, mapping + layout.contextOffset, YES);
    installed = YES;
    stage = @"presentation-ready";
    message = @"The marker-aware presentation payload self-installed through one direct task bridge; no RemoteCall remains.";

finish:;
    pid_t targetPID = session.pid;
    if (session && threadResult == KERN_SUCCESS &&
        threadTerminateResult == KERN_NOT_SUPPORTED) {
        threadTerminateResult = [session terminateBootstrapThread];
    }
    if (session && stack) {
        stackDeallocateResult = [session deallocateAddress:stack
                                                    length:stackLength];
        stack = 0;
    }
    /* A suspended target can accept thread_create_running() without executing
     * the copied bootstrap. If exact context readback is still Prepared and
     * the raw thread terminated, no instruction in the payload ran and both
     * mappings are safe to reclaim. Once BootstrapStarted is observed (or
     * readback cannot prove otherwise), retain an incomplete mapping on
     * failure: the bootstrap may have created a pthread whose final return
     * would race an eager unmap. A process restart clears that bounded state. */
    BOOL targetExecutionObserved =
        observed.installState >= CNDIconConsumerInstallStateBootstrapStarted;
    BOOL targetExecutionProvenAbsent = !existing &&
        (threadResult != KERN_SUCCESS ||
         (readbackResult == KERN_SUCCESS &&
          observed.installState == CNDIconConsumerInstallStatePrepared &&
          threadTerminateResult == KERN_SUCCESS));
    BOOL targetExecutionStarted =
        threadResult == KERN_SUCCESS && !targetExecutionProvenAbsent;
    if (session && mapping && !installed && targetExecutionProvenAbsent) {
        (void)[session deallocateAddress:mapping length:layout.mappingLength];
        mapping = 0;
    } else if (session && mapping && !installed && targetExecutionStarted) {
        CNDConsumerKernelSaveMapping(processName, session.pid, mapping,
            layout.mappingLength, mapping + layout.contextOffset, NO);
    }
    if (session && !identityStable) identityStable = [session identityIsStable];
    if (session) sessionClosed = [session close];
    BOOL ok = installed && identityStable && sessionClosed &&
        (existing || threadTerminateResult == KERN_SUCCESS) &&
        (existing || stackDeallocateResult == KERN_SUCCESS);
    if (installed && !ok && [stage isEqualToString:@"presentation-ready"]) {
        stage = @"channel-finalization";
        message = @"The payload installed, but the temporary task channel did not close cleanly.";
    }
    double elapsed = CNDConsumerKernelElapsedMS(started,
                                                 mach_continuous_time());
    log_user("[SBR_KERNEL] Phase 2 target=%s pid=%d ok=%s stage=%s "
             "mode=%s state=%u result=%u hooks=%u time=%.3fms\n",
             processName.UTF8String ?: "", targetPID,
             ok ? "yes" : "no", stage.UTF8String ?: "",
             mode.UTF8String ?: "", observed.installState,
             observed.installResult, observed.installedCount, elapsed);
    return @{
        @"ok": @(ok), @"stage": stage ?: @"phase2",
        @"message": message ?: @"", @"process": processName ?: @"",
        @"pid": @(targetPID), @"bridgeMode": mode ?: @"none",
        @"mappingAddress": @(mapping),
        @"mappingLength": @(layout.mappingLength),
        @"codeLength": @(layout.codeLength),
        @"contextOffset": @(layout.contextOffset),
        @"payloadReadbackVerified": @(payloadReadback),
        @"allocateResult": @(allocateResult),
        @"stackAllocateResult": @(stackAllocateResult),
        @"writeResult": @(writeResult), @"readbackResult": @(readbackResult),
        @"protectResult": @(protectResult), @"flushResult": @(flushResult),
        @"threadStartResult": @(threadResult),
        @"threadTerminateResult": @(threadTerminateResult),
        @"stackDeallocateResult": @(stackDeallocateResult),
        @"installState": @(observed.installState),
        @"installResult": @(observed.installResult),
        @"installedCount": @(observed.installedCount),
        @"rollbackVerified": @(observed.rollbackVerified != 0),
        @"identityStable": @(identityStable),
        @"taskChannelClosed": @(sessionClosed),
        @"alreadyInstalled": @(existing),
        @"remoteCallUsed": @NO,
        @"targetExecutionObserved": @(targetExecutionObserved),
        @"targetExecutionProvenAbsent": @(targetExecutionProvenAbsent),
        @"bootstrapThreadTerminated": @(existing ||
            threadTerminateResult == KERN_SUCCESS),
        @"elapsedMilliseconds": @(elapsed),
    };
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerKernelInstallForProcess(NSString *processName,
                                                double displayScale)
{
    @synchronized (CNDConsumerKernelInstallLock()) {
        return CNDConsumerKernelInstall(0, processName, displayScale);
    }
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerKernelInstallForPID(pid_t pid,
                                            NSString *expectedProcessName,
                                            double displayScale)
{
    @synchronized (CNDConsumerKernelInstallLock()) {
        return CNDConsumerKernelInstall(pid, expectedProcessName,
                                        displayScale);
    }
}
