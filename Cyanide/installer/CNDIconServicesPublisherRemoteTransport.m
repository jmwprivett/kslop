#import "CNDIconServicesPublisherRemoteTransport.h"
#import "CNDIconServicesPublisherPayload.h"
#import "CNDIconServicesStructuredPayload.h"
#import "../TaskRop/RemoteCall.h"
#import "../kexploit/CNDLabKernelProvider.h"
#import "../kexploit/kutils.h"
#import "../tweaks/remote_objc.h"

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <limits.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <stddef.h>
#import <stdio.h>
#import <string.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <unistd.h>
#import <zlib.h>

extern const struct mach_header_64 _mh_execute_header;

extern const uint8_t cnd_publisher_payload_section_start[]
    __asm("section$start$__TEXT$__cndpub");
extern const uint8_t cnd_publisher_payload_section_end[]
    __asm("section$end$__TEXT$__cndpub");

static NSString * const CNDIconServicesPublisherErrorDomain =
    @"CNDIconServicesPublisherErrorDomain";
/* The selected adapter is thread-owned by CNDIconServicesPublisher.m. */
static const NSUInteger CNDIconServicesPublisherMaximumApplications = 2048;
static const NSUInteger CNDIconServicesPublisherDefaultStagingCapacity =
    1U << 20;
static const NSUInteger CNDIconServicesPublisherMaximumStructuredDataLength =
    16U << 20;
static const NSUInteger CNDIconServicesPublisherMaximumStagingCapacity =
    40U << 20;
static const NSUInteger
    CNDIconServicesPublisherMaximumPersistentIdentifierLength = 128U;
static const NSUInteger CNDIconServicesPublisherAuditCopyChunkLength = 4096U;
static const NSUInteger
    CNDIconServicesPublisherAuditMaximumSourceIdentifiers = 32U;
static const NSUInteger
    CNDIconServicesPublisherMaximumPersistentIndexLength = 64U << 20;
static const NSUInteger
    CNDIconServicesPublisherPersistentIndexSettleAttempts = 24U;
static const useconds_t
    CNDIconServicesPublisherPersistentIndexSettleIntervalUS = 1000U;

/* iOS 26.0 (23A341) ISStoreIndex value payload. The enclosing hash-table
 * node is private; only this fixed-size value is inspected or changed. */
typedef struct __attribute__((packed)) {
    uint8_t iconDigest[16];
    double minimumSize;
    double maximumSize;
    double iconSize;
    uint32_t scale;
    uint8_t descriptorDigest[16];
    uint8_t storeUnitUUID[16];
    uint8_t validationToken[40];
} CNDIconServicesStoreIndexValue23A341;

_Static_assert(sizeof(CNDIconServicesStoreIndexValue23A341) == 0x74,
               "23A341 IconServices index value size changed");
_Static_assert(offsetof(CNDIconServicesStoreIndexValue23A341, storeUnitUUID) ==
                   0x3c,
               "23A341 IconServices store UUID offset changed");
_Static_assert(offsetof(CNDIconServicesStoreIndexValue23A341,
                        validationToken) == 0x4c,
               "23A341 IconServices validation-token offset changed");

@interface CNDIconServicesPublisherBatchState : NSObject
@property (nonatomic, strong) RemoteCallSession *session;
@property (nonatomic, copy) NSDictionary<NSString *, id> *wake;
@property (nonatomic, assign) BOOL healthy;
@property (nonatomic, assign) int pid;
@property (nonatomic, assign) uint32_t previousSettleUS;
@property (nonatomic, assign) BOOL settleAdjusted;
@property (nonatomic, assign) BOOL publisherABIReady;
@property (nonatomic, assign) BOOL requestABIReady;
@property (nonatomic, assign) uint64_t requestClass;
@property (nonatomic, assign) uint64_t generationMethod;
@property (nonatomic, assign) uint64_t originalGenerate;
@property (nonatomic, assign) uint64_t cacheImageClass;
@property (nonatomic, assign) uint64_t iconClass;
@property (nonatomic, assign) uint64_t descriptorClass;
@property (nonatomic, assign) uint64_t imageClass;
@property (nonatomic, assign) uint64_t imageCacheClass;
@property (nonatomic, assign) uint64_t stringClass;
@property (nonatomic, assign) uint64_t dataClass;
@property (nonatomic, assign) uint64_t objcMsgSend;
@property (nonatomic, assign) uint64_t methodSetImplementation;
@property (nonatomic, assign) uint64_t objcAutoreleasePoolPush;
@property (nonatomic, assign) uint64_t objcAutoreleasePoolPop;
@property (nonatomic, assign) uint64_t zlibUncompress;
@property (nonatomic, assign) uint64_t pageSize;
@property (nonatomic, assign) BOOL stockStoreABIReady;
@property (nonatomic, assign) uint64_t stockManager;
@property (nonatomic, assign) uint64_t stockManagerCache;
@property (nonatomic, assign) uint64_t stockStore;
@property (nonatomic, assign) uint64_t stockStoreUnitClass;
@property (nonatomic, assign) BOOL auditABIReady;
@property (nonatomic, assign) uint64_t auditSourceRegistry;
@property (nonatomic, assign) uint64_t descriptorTemplate;
@property (nonatomic, copy) NSString *descriptorTemplateKey;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSNumber *> *descriptorTemplates;
@property (nonatomic, assign) uint64_t payloadRemoteBase;
@property (nonatomic, assign) uint64_t payloadMappingLength;
@property (nonatomic, assign) uint64_t payloadContextAddress;
@property (nonatomic, assign) uint64_t payloadContextOffset;
@property (nonatomic, assign) uint64_t payloadProbeOffset;
@property (nonatomic, assign) uint64_t payloadPrepareDescriptorOffset;
@property (nonatomic, assign) uint64_t payloadInstallOffset;
@property (nonatomic, assign) uint64_t payloadGenerateOffset;
@property (nonatomic, assign) uint64_t payloadTriggerOffset;
@property (nonatomic, assign) uint64_t payloadExecuteOffset;
@property (nonatomic, assign) uint64_t payloadCleanupOffset;
@property (nonatomic, assign) uint64_t stagingRemoteBase;
@property (nonatomic, assign) uint64_t stagingCapacity;
@property (nonatomic, assign) uint64_t persistentIndexScratchRemoteBase;
@property (nonatomic, assign) uint64_t persistentIndexScratchLength;
@property (nonatomic, strong) NSData *payloadContextTemplate;
@property (nonatomic, assign) BOOL payloadReady;
@end

@implementation CNDIconServicesPublisherBatchState
@end

@interface CNDIconServicesPublisherRemoteTransport : NSObject
    <CNDIconServicesPublisherTransport>
@property (nonatomic, strong, nullable) CNDIconServicesPublisherBatchState *batchState;
@end

/*
 * cnd_publisher_run predates the transport boundary and is deliberately kept
 * as one unit for behavior parity.  The adapter installs itself only for the
 * duration of a call so that all of its existing batch reuse/cleanup logic
 * reads this instance rather than a facade-owned concrete session.
 */
static __thread __unsafe_unretained CNDIconServicesPublisherRemoteTransport *
    g_cnd_publisher_current_transport;

static NSError *cnd_publisher_error(NSInteger code, NSString *message)
{
    return [NSError errorWithDomain:CNDIconServicesPublisherErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey:
                               message ?: @"IconServices publication failed."}];
}

static CNDIconServicesPublisherBatchState *cnd_publisher_batch_state(void)
{
    return g_cnd_publisher_current_transport.batchState;
}

static NSDictionary<NSString *, id> *cnd_remote_transport_call(
    CNDIconServicesPublisherRemoteTransport *transport,
    NSDictionary<NSString *, id> *(^operation)(void))
{
    CNDIconServicesPublisherRemoteTransport *previous =
        g_cnd_publisher_current_transport;
    g_cnd_publisher_current_transport = transport;
    NSDictionary<NSString *, id> *result = nil;
    @try {
        result = operation();
    } @finally {
        g_cnd_publisher_current_transport = previous;
    }
    return result;
}

static BOOL cnd_remote_transport_health(
    CNDIconServicesPublisherRemoteTransport *transport)
{
    CNDIconServicesPublisherRemoteTransport *previous =
        g_cnd_publisher_current_transport;
    g_cnd_publisher_current_transport = transport;
    __block BOOL healthy = NO;
    @try {
        CNDIconServicesPublisherBatchState *state = cnd_publisher_batch_state();
        healthy = state && state.healthy && state.session &&
            [state.session hasLocalState] && state.session.pid == state.pid;
    } @finally {
        g_cnd_publisher_current_transport = previous;
    }
    return healthy;
}

static BOOL cnd_publisher_valid_bundle_identifier(id value)
{
    if (![value isKindOfClass:NSString.class]) return NO;
    NSString *identifier = [(NSString *)value
        stringByTrimmingCharactersInSet:
            NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (identifier.length == 0 || identifier.length > 255 ||
        [identifier hasPrefix:@"."] || [identifier hasSuffix:@"."] ||
        [identifier containsString:@".."]) {
        return NO;
    }
    static NSCharacterSet *invalid;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSCharacterSet *allowed = [NSCharacterSet
            characterSetWithCharactersInString:
                @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"];
        invalid = allowed.invertedSet;
    });
    return [identifier rangeOfCharacterFromSet:invalid].location == NSNotFound;
}

static NSDictionary<NSString *, NSNumber *> *
cnd_publisher_default_descriptor_specification(void)
{
    return @{
        @"pointWidth": @68,
        @"pointHeight": @68,
        @"scale": @3,
        @"appearance": @0,
        @"iconVariant": @0,
        @"options": @0,
    };
}

static NSDictionary<NSString *, NSNumber *> *
cnd_publisher_normalized_descriptor_specification(NSDictionary *candidate)
{
    NSDictionary *source = [candidate isKindOfClass:NSDictionary.class]
        ? candidate : cnd_publisher_default_descriptor_specification();
    NSNumber *widthNumber = source[@"pointWidth"];
    NSNumber *heightNumber = source[@"pointHeight"];
    NSNumber *scaleNumber = source[@"scale"];
    NSNumber *appearanceNumber = source[@"appearance"];
    NSNumber *variantNumber = source[@"iconVariant"];
    NSNumber *optionsNumber = source[@"options"];
    if (![widthNumber isKindOfClass:NSNumber.class] ||
        ![heightNumber isKindOfClass:NSNumber.class] ||
        ![scaleNumber isKindOfClass:NSNumber.class] ||
        ![appearanceNumber isKindOfClass:NSNumber.class] ||
        ![variantNumber isKindOfClass:NSNumber.class] ||
        ![optionsNumber isKindOfClass:NSNumber.class]) return nil;

    double width = widthNumber.doubleValue;
    double height = heightNumber.doubleValue;
    double scale = scaleNumber.doubleValue;
    unsigned long long appearance = appearanceNumber.unsignedLongLongValue;
    unsigned long long variant = variantNumber.unsignedLongLongValue;
    unsigned long long options = optionsNumber.unsignedLongLongValue;
    if (!isfinite(width) || !isfinite(height) || !isfinite(scale) ||
        width < 1.0 || width > 1024.0 || height < 1.0 || height > 1024.0 ||
        scale < 1.0 || scale > 4.0 || appearance > UINT32_MAX ||
        variant > INT_MAX || options > INT_MAX) return nil;
    return @{
        @"pointWidth": @(width),
        @"pointHeight": @(height),
        @"scale": @(scale),
        @"appearance": @(appearance),
        @"iconVariant": @(variant),
        @"options": @(options),
    };
}

static NSString *cnd_publisher_descriptor_specification_key(
    NSDictionary<NSString *, NSNumber *> *specification)
{
    NSDictionary *spec =
        cnd_publisher_normalized_descriptor_specification(specification);
    if (!spec) return @"";
    return [NSString stringWithFormat:
        @"w=%.6f;h=%.6f;s=%.6f;a=%llu;v=%llu;o=%llu",
        [spec[@"pointWidth"] doubleValue],
        [spec[@"pointHeight"] doubleValue],
        [spec[@"scale"] doubleValue],
        [spec[@"appearance"] unsignedLongLongValue],
        [spec[@"iconVariant"] unsignedLongLongValue],
        [spec[@"options"] unsignedLongLongValue]];
}

static uint64_t cnd_publisher_cached_descriptor(
    CNDIconServicesPublisherBatchState *batch, NSString *key)
{
    return key.length > 0
        ? [batch.descriptorTemplates[key] unsignedLongLongValue] : 0;
}

static void cnd_publisher_cache_descriptor(
    CNDIconServicesPublisherBatchState *batch, NSString *key,
    uint64_t descriptor)
{
    if (!batch || key.length == 0 || descriptor == 0) return;
    if (!batch.descriptorTemplates) {
        batch.descriptorTemplates = [NSMutableDictionary dictionary];
    }
    batch.descriptorTemplates[key] = @(descriptor);
    batch.descriptorTemplateKey = key;
    batch.descriptorTemplate = descriptor;
}

static BOOL cnd_publisher_batch_owns_descriptor(
    CNDIconServicesPublisherBatchState *batch, uint64_t descriptor)
{
    if (!batch || descriptor == 0) return NO;
    return [batch.descriptorTemplates.allValues containsObject:@(descriptor)];
}

static NSString *cnd_publisher_sha256(NSData *data)
{
    if (![data isKindOfClass:NSData.class]) return @"";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *text = [NSMutableString stringWithCapacity:64];
    for (NSUInteger index = 0; index < sizeof(digest); index++) {
        [text appendFormat:@"%02x", digest[index]];
    }
    return text;
}

/*
 * The RemoteCall lab transport moves at most 16 KiB per mailbox exchange, so
 * compression materially reduces VM mailbox traffic.  A physical-device
 * session writes the staging mapping directly through KRW; keep that path raw
 * so iconservicesagent never has to dlopen libz from a hijacked pthread.
 * Keep raw VM bytes too unless compression saves at least 1 KiB.
 */
static NSData *cnd_publisher_transport_data(
    NSData *source, BOOL *compressedOut, int *compressionResultOut)
{
    if (compressedOut) *compressedOut = NO;
    if (compressionResultOut) *compressionResultOut = Z_OK;
    if (source.length < 2048 || source.length > ULONG_MAX) return source;
    uLong sourceLength = (uLong)source.length;
    uLong bound = compressBound(sourceLength);
    if (bound == 0 || bound > NSUIntegerMax) return source;
    NSMutableData *candidate = [NSMutableData dataWithLength:(NSUInteger)bound];
    uLongf encodedLength = bound;
    int result = compress2(candidate.mutableBytes, &encodedLength,
                           source.bytes, sourceLength,
                           Z_DEFAULT_COMPRESSION);
    if (compressionResultOut) *compressionResultOut = result;
    if (result != Z_OK || encodedLength == 0 ||
        encodedLength + 1024 >= sourceLength) {
        return source;
    }
    candidate.length = (NSUInteger)encodedLength;
    if (compressedOut) *compressedOut = YES;
    return candidate;
}

static void *cnd_publisher_local_iconservices_handle(void)
{
    static void *handle = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        handle = dlopen(
            "/System/Library/PrivateFrameworks/IconServices.framework/"
            "IconServices", RTLD_NOW | RTLD_LOCAL);
    });
    return handle;
}

static BOOL cnd_publisher_load_local_iconservices(void)
{
    return cnd_publisher_local_iconservices_handle() != NULL;
}

/*
 * Submit IconServices' read-only cache-configuration request. On iOS 26 the
 * bundle invalidation API schedules a global ISMutableIconCache garbage
 * collection pass even when its bundle identifier has no installed owner, so
 * it must never be used as publication bootstrap traffic. This request wakes
 * the same XPC service without generating, invalidating, or collecting icons.
 */
static BOOL cnd_publisher_submit_read_only_agent_request(
    BOOL waitForReply, NSString **failureOut)
{
    if (failureOut) *failureOut = nil;
    if (!cnd_publisher_load_local_iconservices()) {
        if (failureOut) *failureOut = @"IconServices is unavailable.";
        return NO;
    }
    Class managerClass = NSClassFromString(@"ISIconManager");
    SEL sharedSelector = NSSelectorFromString(@"sharedInstance");
    SEL connectionSelector = NSSelectorFromString(@"connection");
    if (!managerClass || ![managerClass respondsToSelector:sharedSelector]) {
        if (failureOut) *failureOut =
            @"The IconServices manager is unavailable.";
        return NO;
    }
    id manager = ((id (*)(id, SEL))objc_msgSend)(
        managerClass, sharedSelector);
    if (!manager || ![manager respondsToSelector:connectionSelector]) {
        if (failureOut) *failureOut =
            @"The IconServices manager connection is unavailable.";
        return NO;
    }
    NSXPCConnection *connection = ((id (*)(id, SEL))objc_msgSend)(
        manager, connectionSelector);
    if (!connection) {
        if (failureOut) *failureOut =
            @"The IconServices XPC connection is unavailable.";
        return NO;
    }

    dispatch_semaphore_t completion = dispatch_semaphore_create(0);
    __block BOOL replyReceived = NO;
    __block NSString *requestFailure = nil;
    id proxy = [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        @synchronized (connection) {
            requestFailure = error.localizedDescription ?:
                @"The cache-configuration request failed.";
        }
        dispatch_semaphore_signal(completion);
    }];
    if (!proxy) {
        if (failureOut) *failureOut =
            @"The IconServices cache-configuration proxy is unavailable.";
        return NO;
    }
    @try {
        ((void (*)(id, SEL, id))objc_msgSend)(
            proxy,
            NSSelectorFromString(@"fetchCacheConfigurationWithReply:"),
            ^(id configuration) {
                replyReceived = configuration != nil;
                if (!replyReceived) {
                    @synchronized (connection) {
                        requestFailure =
                            @"IconServices returned no cache configuration.";
                    }
                }
                dispatch_semaphore_signal(completion);
            });
    } @catch (NSException *exception) {
        if (failureOut) {
            *failureOut = [NSString stringWithFormat:
                @"The cache-configuration request raised %@: %@",
                exception.name ?: @"an exception",
                exception.reason ?: @"unknown reason"];
        }
        return NO;
    }
    if (!waitForReply) return YES;
    long waitResult = dispatch_semaphore_wait(
        completion, dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC));
    NSString *observedFailure = nil;
    @synchronized (connection) {
        observedFailure = [requestFailure copy];
    }
    if (waitResult != 0 || !replyReceived) {
        if (failureOut) *failureOut = observedFailure ?:
            @"The cache-configuration request timed out.";
        return NO;
    }
    return YES;
}

/*
 * The resolve-only vPhone helper intentionally exposes no kernel proc
 * addresses.  Asking kutils to walk the kernel list in that mode therefore
 * reports a false absence and sends the sandboxed application down the local
 * IconServices XPC wake path.  The daemon is already resident and the
 * authenticated helper can prove its exact PID without broadening production
 * behavior.  Outside the lab, retain the existing kernel-proc identity.
 */
static uint64_t cnd_publisher_resident_agent_identity(pid_t *pidOut)
{
    if (pidOut) *pidOut = 0;
    if (cnd_lab_process_resolve_active()) {
        pid_t pid = 0;
        int result = cnd_lab_resolve_process_pid(
            "iconservicesagent", &pid);
        printf("[ICONSTORE] LAB residency resolve target=iconservicesagent "
               "result=%d pid=%d\n", result, pid);
        if (result != 0 || pid <= 1) return 0;
        if (pidOut) *pidOut = pid;
        return (uint64_t)pid;
    }
    return proc_find_by_name("iconservicesagent");
}

static NSDictionary<NSString *, id> *
cnd_publisher_wake_agent_without_generation(
    NSString *bundleIdentifier, NSError **errorOut)
{
    if (errorOut) *errorOut = nil;
    pid_t residentPID = 0;
    uint64_t resident = cnd_publisher_resident_agent_identity(
        &residentPID);
    if (resident && resident != UINT64_MAX) {
        return @{
            @"submitted": @NO,
            @"requestBoundary": @"already-resident",
            @"applicationClientConnectionAvoided": @YES,
            @"generationRequestAvoided": @YES,
            @"cacheMutationAvoided": @YES,
            @"garbageCollectionTriggerAvoided": @YES,
            @"agentPID": @(residentPID > 1
                ? (uint64_t)residentPID : resident),
        };
    }
    if (bundleIdentifier.length == 0) {
        if (errorOut) *errorOut = cnd_publisher_error(
            1, @"The IconServices wake identifier is unavailable.");
        return nil;
    }
    NSString *requestFailure = nil;
    if (!cnd_publisher_submit_read_only_agent_request(
            YES, &requestFailure)) {
        if (errorOut) *errorOut = cnd_publisher_error(2,
            requestFailure ?:
                @"The read-only IconServices wake request failed.");
        return nil;
    }
    for (NSUInteger attempt = 0; attempt < 40; attempt++) {
        residentPID = 0;
        resident = cnd_publisher_resident_agent_identity(&residentPID);
        if (resident && resident != UINT64_MAX) {
            return @{
                @"submitted": @YES,
                @"requestBoundary":
                    @"fetchCacheConfigurationWithReply:",
                @"applicationClientConnectionAvoided": @NO,
                @"generationRequestAvoided": @YES,
                @"cacheMutationAvoided": @YES,
                @"garbageCollectionTriggerAvoided": @YES,
                @"agentPID": @(residentPID > 1
                    ? (uint64_t)residentPID : resident),
            };
        }
        usleep(25000);
    }
    /*
     * The authenticated vPhone root harness intentionally works without a
     * local kernel process walk, so proc_find_by_name() is not authoritative
     * in that mode. A completed configuration request is sufficient as a wake
     * request; the RemoteCallSession created immediately afterward is the
     * authoritative daemon-residency check on both VM and device.
     */
    return @{
        @"submitted": @YES,
        @"requestBoundary":
            @"fetchCacheConfigurationWithReply:",
        @"applicationClientConnectionAvoided": @NO,
        @"generationRequestAvoided": @YES,
        @"cacheMutationAvoided": @YES,
        @"garbageCollectionTriggerAvoided": @YES,
        @"localResidencyObserved": @NO,
        @"agentPID": @0,
    };
}

/*
 * A resident iconservicesagent is commonly idle.  Merely discovering its proc
 * does not make an armed thread return through the AST_GUARD boundary, and the
 * pre-session wake above necessarily completes before RemoteCall can install
 * its exception ports. Issue another read-only cache-configuration request
 * only after every bootstrap candidate is armed.
 *
 * This is a bootstrap provoker, not a second IconServices publication call:
 * it performs no generation, invalidation, garbage collection, or persistent
 * write, and the resulting RemoteCall session remains pinned for the batch.
 */
static RemoteCallSession *cnd_publisher_open_agent_session(
    NSString *bundleIdentifier, NSError **errorOut)
{
    if (errorOut) *errorOut = nil;
    if (bundleIdentifier.length == 0 ||
        !cnd_publisher_load_local_iconservices()) {
        if (errorOut) *errorOut = cnd_publisher_error(
            4, @"IconServices or the bootstrap bundle identifier is unavailable.");
        return nil;
    }
    NSString *provokerIdentifier = [bundleIdentifier copy];
    dispatch_queue_t provokerQueue = dispatch_queue_create(
        "com.zeroxjf.cyanide.iconservices-bootstrap", DISPATCH_QUEUE_SERIAL);
    dispatch_group_t provokerGroup = dispatch_group_create();
    __block BOOL provokerQueued = NO;
    __block NSString *provokerFailure = nil;
    RemoteCallSession *session = [[RemoteCallSession alloc]
        initWithProcess:@"iconservicesagent"
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000
        originalThreadOnly:NO
        /* iconservicesagent can retain more than eight dispatch workers after
         * repeated invalidations.  Request full coverage up to RemoteCall's
         * bounded sixteen-thread ceiling; smaller daemons still arm only the
         * threads that actually exist. */
        bootstrapThreadCount:16
        bootstrapProvoker:^{
            /*
             * The physical-device client may synchronously wait for an XPC
             * acknowledgement here.  Never perform that wait on RemoteCall's
             * setup thread: the setup thread must enter wait_exception() to
             * receive the EXC_GUARD that the request itself provokes.
             */
            provokerQueued = YES;
            printf("[ICONSTORE] IconServices bootstrap provoker queued "
                   "asynchronously after thread arming.\n");
            dispatch_group_async(provokerGroup, provokerQueue, ^{
                @autoreleasepool {
                    printf("[ICONSTORE] IconServices bootstrap provoker "
                           "worker started.\n");
                    NSString *failure = nil;
                    if (!cnd_publisher_submit_read_only_agent_request(
                            NO, &failure)) {
                        @synchronized (provokerIdentifier) {
                            provokerFailure = failure ?:
                                @"The read-only IconServices bootstrap request failed.";
                        }
                    }
                    printf("[ICONSTORE] IconServices bootstrap provoker "
                           "worker returned.\n");
                }
            });
        }];
    if (provokerQueued) {
        /*
         * A successful bootstrap has already restored the original target
         * thread before returning here, so the request normally completes at
         * once.  Failure cleanup clears every AST_GUARD first.  In either case
         * this bounded observation must never turn a daemon/client failure
         * into another indefinite wait in Cyanide.
         */
        int64_t waitNanoseconds = session
            ? 250LL * NSEC_PER_MSEC : 1500LL * NSEC_PER_MSEC;
        long workerWait = dispatch_group_wait(
            provokerGroup,
            dispatch_time(DISPATCH_TIME_NOW, waitNanoseconds));
        if (workerWait != 0) {
            printf("[ICONSTORE] IconServices bootstrap provoker worker is "
                   "still pending after bounded %s cleanup; continuing "
                   "without waiting.\n", session ? "success" : "failure");
        } else {
            NSString *failure = nil;
            @synchronized (provokerIdentifier) {
                failure = [provokerFailure copy];
            }
            if (failure.length) {
                printf("[ICONSTORE] IconServices bootstrap provoker failed: %s\n",
                       failure.UTF8String);
                if (!session && errorOut) {
                    *errorOut = cnd_publisher_error(
                        6, [@"The asynchronous IconServices bootstrap "
                            @"provoker failed: " stringByAppendingString:failure]);
                }
            } else {
                printf("[ICONSTORE] IconServices bootstrap provoker worker "
                       "completed within the bounded cleanup window.\n");
            }
        }
    }
    return session;
}

static uint64_t cnd_publisher_strip_code_pointer(uint64_t value)
{
    return value & 0x00007fffffffffffULL;
}

static uint64_t cnd_publisher_remote_symbol(const char *name)
{
    uint64_t remoteName = r_alloc_str(name);
    if (!remoteName) return 0;
    uint64_t address = r_dlsym_call(
        R_TIMEOUT, "dlsym", (uint64_t)(intptr_t)-2, remoteName,
        0, 0, 0, 0, 0, 0);
    r_free(remoteName);
    return address;
}

static BOOL cnd_publisher_copy_remote_method_types(
    uint64_t cls, const char *selectorName, BOOL classMethod,
    char *types, size_t typesCapacity)
{
    if (types && typesCapacity > 0) types[0] = '\0';
    if (!cls || !selectorName || !types || typesCapacity < 2) return NO;
    uint64_t selector = r_sel(selectorName);
    uint64_t method = selector ? r_dlsym_call(
        R_TIMEOUT,
        classMethod ? "class_getClassMethod" : "class_getInstanceMethod",
        cls, selector, 0, 0, 0, 0, 0, 0) : 0;
    uint64_t typesAddress = method ? r_dlsym_call(
        R_TIMEOUT, "method_getTypeEncoding", method,
        0, 0, 0, 0, 0, 0, 0) : 0;
    return typesAddress &&
        r_read_cstring(typesAddress, types, typesCapacity) &&
        remote_call_current_success();
}

static BOOL cnd_publisher_remote_method_has_types(
    uint64_t cls, const char *selectorName,
    const char *expected, const char *alternate)
{
    if (!expected) return NO;
    char types[96] = {0};
    return cnd_publisher_copy_remote_method_types(
            cls, selectorName, NO, types, sizeof(types)) &&
        (!strcmp(types, expected) ||
         (alternate && !strcmp(types, alternate)));
}

static BOOL cnd_publisher_remote_class_method_has_types(
    uint64_t cls, const char *selectorName,
    const char *expected, const char *alternate)
{
    if (!expected) return NO;
    char types[96] = {0};
    return cnd_publisher_copy_remote_method_types(
            cls, selectorName, YES, types, sizeof(types)) &&
        (!strcmp(types, expected) ||
         (alternate && !strcmp(types, alternate)));
}

static NSString *cnd_publisher_remote_method_types_description(
    uint64_t cls, const char *selectorName, BOOL classMethod)
{
    char types[96] = {0};
    return cnd_publisher_copy_remote_method_types(
        cls, selectorName, classMethod, types, sizeof(types))
        ? [NSString stringWithUTF8String:types] ?: @"<invalid-utf8>"
        : @"<missing>";
}

static BOOL cnd_publisher_load_remote_framework(const char *path)
{
    uint64_t remotePath = r_alloc_str(path);
    if (!remotePath) return NO;
    uint64_t handle = r_dlsym_call(
        R_TIMEOUT, "dlopen", remotePath, RTLD_NOW | RTLD_LOCAL,
        0, 0, 0, 0, 0, 0);
    r_free(remotePath);
    return handle && remote_call_current_success();
}

static uint64_t cnd_publisher_remote_library_symbol(
    const char *path, const char *symbol)
{
    if (!path || !symbol) return 0;
    uint64_t remotePath = r_alloc_str(path);
    uint64_t handle = remotePath ? r_dlsym_call(
        R_TIMEOUT, "dlopen", remotePath, RTLD_NOW | RTLD_LOCAL,
        0, 0, 0, 0, 0, 0) : 0;
    if (remotePath) r_free(remotePath);
    uint64_t remoteSymbol = handle ? r_alloc_str(symbol) : 0;
    uint64_t address = remoteSymbol ? r_dlsym_call(
        R_TIMEOUT, "dlsym", handle, remoteSymbol,
        0, 0, 0, 0, 0, 0) : 0;
    if (remoteSymbol) r_free(remoteSymbol);
    return address && remote_call_current_success() ? address : 0;
}

/*
 * A target-side anonymous mmap is initially only a virtual reservation.  The
 * physical RemoteCall transport maps the target's backing VM object into
 * Cyanide, so its first host write cannot resolve a page that
 * iconservicesagent has never faulted.  Touch only the range that will be
 * transferred (rather than the whole reusable capacity) before asking KRW to
 * map it.  The VM lab backend writes through its root harness and does not
 * need this physical-page preparation.
 */
static BOOL cnd_publisher_prefault_remote_write_range(
    uint64_t address, uint64_t length)
{
    if (!address || !length || !remote_call_current_success()) return NO;
    if (remote_call_uses_lab_backend()) return YES;

    uint64_t result = r_dlsym_call(
        R_TIMEOUT, "memset", address, 0, length,
        0, 0, 0, 0, 0);
    BOOL ready = result == address && remote_call_current_success();
    if (!ready) {
        printf("[ICONSTORE] target mapping prefault failed address=%#llx "
               "length=%llu result=%#llx\n",
               address, length, result);
    }
    return ready;
}

static BOOL cnd_publisher_resolve_payload_vnode(
    const uint8_t *payload,
    size_t payloadLength,
    uint64_t pageSize,
    size_t contextOffset,
    NSString **pathOut,
    uint64_t *sliceOffsetOut,
    uint64_t *fileOffsetOut,
    NSString **failureOut)
{
    if (pathOut) *pathOut = nil;
    if (sliceOffsetOut) *sliceOffsetOut = 0;
    if (fileOffsetOut) *fileOffsetOut = 0;
    if (failureOut) *failureOut = nil;
    if (!payload || !payloadLength || !pageSize || !contextOffset ||
        !pathOut || !sliceOffsetOut || !fileOffsetOut ||
        (uintptr_t)payload % pageSize || contextOffset % pageSize ||
        contextOffset >= payloadLength) {
        if (failureOut) *failureOut = @"publisher-vnode-layout";
        return NO;
    }

    const struct mach_header_64 *header = &_mh_execute_header;
    if (header->magic != MH_MAGIC_64 || header->ncmds == 0 ||
        header->sizeofcmds == 0) {
        if (failureOut) *failureOut = @"publisher-vnode-mach-header";
        return NO;
    }

    const struct segment_command_64 *textSegment = NULL;
    const struct section_64 *payloadSection = NULL;
    const uint8_t *commandBytes = (const uint8_t *)(header + 1);
    const uint8_t *commandsEnd = commandBytes + header->sizeofcmds;
    for (uint32_t commandIndex = 0;
         commandIndex < header->ncmds; commandIndex++) {
        if (commandBytes + sizeof(struct load_command) > commandsEnd) break;
        const struct load_command *command =
            (const struct load_command *)commandBytes;
        if (command->cmdsize < sizeof(*command) ||
            commandBytes + command->cmdsize > commandsEnd) break;
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, "__TEXT", 16) == 0) {
                textSegment = segment;
                const struct section_64 *sections =
                    (const struct section_64 *)(segment + 1);
                uint64_t required = sizeof(*segment) +
                    (uint64_t)segment->nsects * sizeof(*sections);
                if (required <= segment->cmdsize) {
                    for (uint32_t sectionIndex = 0;
                         sectionIndex < segment->nsects; sectionIndex++) {
                        if (strncmp(sections[sectionIndex].sectname,
                                    "__cndpub", 16) == 0 &&
                            strncmp(sections[sectionIndex].segname,
                                    "__TEXT", 16) == 0) {
                            payloadSection = &sections[sectionIndex];
                            break;
                        }
                    }
                }
            }
        }
        commandBytes += command->cmdsize;
    }

    NSString *path = NSBundle.mainBundle.executablePath;
    struct stat status = {0};
    uint64_t slide = textSegment && textSegment->fileoff == 0 &&
        (uint64_t)(uintptr_t)header >= textSegment->vmaddr
        ? (uint64_t)(uintptr_t)header - textSegment->vmaddr : UINT64_MAX;
    uint64_t runtimeSection = payloadSection && slide != UINT64_MAX
        ? payloadSection->addr + slide : 0;
    BOOL regular = path.length > 0 &&
        lstat(path.fileSystemRepresentation, &status) == 0 &&
        S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode);

    /* The shipped IPA is universal. Mach-O section offsets are relative to
     * the selected thin slice, while mmap(2) offsets are relative to the fat
     * file. Resolve the exact running CPU slice instead of assuming offset 0.
     */
    uint64_t sliceOffset = 0;
    BOOL sliceFound = NO;
    int localFD = regular
        ? open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC) : -1;
    uint8_t fatHeader[8] = {0};
    ssize_t headerRead = localFD >= 0
        ? pread(localFD, fatHeader, sizeof(fatHeader), 0) : -1;
    uint32_t rawMagic = 0;
    if (headerRead == sizeof(fatHeader)) {
        memcpy(&rawMagic, fatHeader, sizeof(rawMagic));
    }
    uint32_t bigMagic = ((uint32_t)fatHeader[0] << 24) |
        ((uint32_t)fatHeader[1] << 16) |
        ((uint32_t)fatHeader[2] << 8) | (uint32_t)fatHeader[3];
    if (headerRead == sizeof(fatHeader) &&
        (rawMagic == MH_MAGIC_64 || rawMagic == MH_CIGAM_64)) {
        sliceFound = YES;
    } else if (headerRead == sizeof(fatHeader) &&
               (bigMagic == FAT_MAGIC || bigMagic == FAT_MAGIC_64)) {
        uint32_t count = ((uint32_t)fatHeader[4] << 24) |
            ((uint32_t)fatHeader[5] << 16) |
            ((uint32_t)fatHeader[6] << 8) | (uint32_t)fatHeader[7];
        size_t entrySize = bigMagic == FAT_MAGIC_64 ? 32U : 20U;
        if (count > 0 && count <= 32) {
            for (uint32_t index = 0; index < count; index++) {
                uint8_t entry[32] = {0};
                off_t entryOffset = (off_t)sizeof(fatHeader) +
                    (off_t)index * (off_t)entrySize;
                if (pread(localFD, entry, entrySize, entryOffset) !=
                    (ssize_t)entrySize) break;
                uint32_t cpuType = ((uint32_t)entry[0] << 24) |
                    ((uint32_t)entry[1] << 16) |
                    ((uint32_t)entry[2] << 8) | (uint32_t)entry[3];
                uint32_t cpuSubtype = ((uint32_t)entry[4] << 24) |
                    ((uint32_t)entry[5] << 16) |
                    ((uint32_t)entry[6] << 8) | (uint32_t)entry[7];
                uint64_t candidateOffset = 0;
                if (bigMagic == FAT_MAGIC_64) {
                    for (NSUInteger byte = 0; byte < 8; byte++) {
                        candidateOffset = (candidateOffset << 8) |
                            entry[8 + byte];
                    }
                } else {
                    candidateOffset = ((uint32_t)entry[8] << 24) |
                        ((uint32_t)entry[9] << 16) |
                        ((uint32_t)entry[10] << 8) |
                        (uint32_t)entry[11];
                }
                uint32_t subtypeMask = ~((uint32_t)CPU_SUBTYPE_MASK);
                if (cpuType == (uint32_t)header->cputype &&
                    (cpuSubtype & subtypeMask) ==
                        ((uint32_t)header->cpusubtype & subtypeMask)) {
                    sliceOffset = candidateOffset;
                    sliceFound = YES;
                    break;
                }
            }
        }
    }
    if (localFD >= 0) close(localFD);

    uint64_t absoluteFileOffset = payloadSection
        ? sliceOffset + payloadSection->offset : 0;
    BOOL exact = textSegment && payloadSection && regular && sliceFound &&
        runtimeSection == (uint64_t)(uintptr_t)payload &&
        payloadSection->size == payloadLength &&
        sliceOffset % pageSize == 0 &&
        absoluteFileOffset % pageSize == 0 &&
        absoluteFileOffset <= (uint64_t)status.st_size &&
        contextOffset <=
            (uint64_t)status.st_size - absoluteFileOffset;
    if (!exact) {
        if (failureOut) *failureOut = @"publisher-vnode-section-validation";
        return NO;
    }

    *pathOut = path;
    *sliceOffsetOut = sliceOffset;
    *fileOffsetOut = absoluteFileOffset;
    return YES;
}

static int cnd_publisher_remote_errno(void)
{
    uint64_t errnoAddress = r_dlsym_call(
        R_TIMEOUT, "__error", 0, 0, 0, 0, 0, 0, 0, 0);
    int value = 0;
    return errnoAddress && remote_read(errnoAddress, &value, sizeof(value))
        ? value : 0;
}

/*
 * Physical iOS rejects instructions copied into anonymous memory inside an
 * Apple platform process.  Cross-task mach_vm_remap through Cyanide's forged
 * task port is also forbidden here: on iOS 26 it produced a kernel DA-key PAC
 * panic in Cyanide.  Instead iconservicesagent opens Cyanide's installed,
 * signed main executable and maps the page-aligned __TEXT,__cndpub range from
 * that vnode as RX.  Only the adjacent context page is anonymous RW.
 *
 * The VM root harness intentionally retains its copied-payload path because
 * its lab kernel accepts those pages.
 */
static BOOL cnd_publisher_map_physical_payload(
    const uint8_t *payload,
    size_t payloadLength,
    uint64_t pageSize,
    size_t contextOffset,
    size_t generateOffset,
    CNDIconServicesPublisherPayloadContext *context,
    uint64_t *remoteBaseOut,
    uint64_t *mappingLengthOut,
    NSString **failureOut)
{
    if (failureOut) *failureOut = nil;
    if (remoteBaseOut) *remoteBaseOut = 0;
    if (mappingLengthOut) *mappingLengthOut = 0;
    if (!payload || !payloadLength || !pageSize || !context ||
        !remoteBaseOut || !mappingLengthOut ||
        ((uintptr_t)payload % pageSize) != 0 ||
        contextOffset == 0 || contextOffset % pageSize != 0 ||
        contextOffset >= payloadLength || generateOffset >= contextOffset) {
        if (failureOut) *failureOut = @"publisher-vnode-map-layout";
        return NO;
    }

    uint64_t mappingLength =
        (payloadLength + pageSize - 1) & ~(pageSize - 1);
    uint64_t contextLength = mappingLength - contextOffset;
    NSString *executablePath = nil;
    uint64_t executableSliceOffset = 0;
    uint64_t payloadFileOffset = 0;
    if (!cnd_publisher_resolve_payload_vnode(
            payload, payloadLength, pageSize, contextOffset,
            &executablePath, &executableSliceOffset,
            &payloadFileOffset, failureOut)) {
        return NO;
    }

    uint64_t remoteBase = r_dlsym_call(
        R_TIMEOUT, "mmap", 0, mappingLength,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
        (uint64_t)-1, 0, 0, 0);
    BOOL allocationLive = remoteBase && remoteBase != UINT64_MAX &&
        remote_call_current_success();
    uint64_t remotePath = allocationLive
        ? r_alloc_str(executablePath.fileSystemRepresentation) : 0;
    int64_t openResult = remotePath ? (int64_t)r_dlsym_call(
        R_TIMEOUT, "open", remotePath, O_RDONLY | O_CLOEXEC,
        0, 0, 0, 0, 0, 0) : -1;
    int openError = openResult < 0 ? cnd_publisher_remote_errno() : 0;
    uint64_t checkAddress = openResult >= 0 ? r_dlsym_call(
        R_TIMEOUT, "malloc", sizeof(fchecklv_t),
        0, 0, 0, 0, 0, 0, 0) : 0;
    fchecklv_t check = {
        .lv_file_start = (off_t)executableSliceOffset,
        .lv_error_message_size = 0,
        .lv_error_message = NULL,
    };
    BOOL checkWritten = checkAddress &&
        cnd_publisher_prefault_remote_write_range(
            checkAddress, sizeof(check)) &&
        remote_write(checkAddress, &check, sizeof(check));
    int64_t validationResult = checkWritten ? (int64_t)r_dlsym_call(
        R_TIMEOUT, "fcntl", (uint64_t)openResult, F_CHECK_LV,
        checkAddress, 0, 0, 0, 0, 0) : -1;
    int validationError = validationResult < 0
        ? cnd_publisher_remote_errno() : 0;
    if (checkAddress && remote_call_current_success()) {
        (void)r_dlsym_call(
            R_TIMEOUT, "free", checkAddress, 0, 0, 0, 0, 0, 0, 0);
    }
    BOOL libraryValidated = validationResult == 0 &&
        remote_call_current_success();
    uint64_t mappedCode = libraryValidated ? r_dlsym_call(
        R_TIMEOUT, "mmap", remoteBase, contextOffset,
        PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED,
        (uint64_t)openResult, payloadFileOffset, 0, 0) : UINT64_MAX;
    int mapError = libraryValidated && mappedCode == UINT64_MAX
        ? cnd_publisher_remote_errno() : 0;
    if (openResult >= 0 && remote_call_current_success()) {
        (void)r_dlsym_call(
            R_TIMEOUT, "close", (uint64_t)openResult,
            0, 0, 0, 0, 0, 0, 0);
    }
    if (remotePath && remote_call_current_success()) r_free(remotePath);
    BOOL codeMappingLive = allocationLive && mappedCode == remoteBase &&
        remote_call_current_success();

    uint64_t contextAddress = remoteBase + contextOffset;
    context->replacementGenerate = remoteBase + generateOffset;
    BOOL contextPrefaulted = codeMappingLive &&
        cnd_publisher_prefault_remote_write_range(
            contextAddress, sizeof(*context));
    BOOL contextWritten = contextPrefaulted && remote_write(
        contextAddress, context, sizeof(*context));

    NSMutableData *codeReadback = codeMappingLive
        ? [NSMutableData dataWithLength:contextOffset] : nil;
    BOOL codeRead = codeReadback && remote_read(
        remoteBase, codeReadback.mutableBytes, codeReadback.length);
    CNDIconServicesPublisherPayloadContext contextReadback = {0};
    BOOL contextRead = contextWritten && remote_read(
        contextAddress, &contextReadback, sizeof(contextReadback));
    if (codeMappingLive && remote_call_current_success()) {
        (void)r_dlsym_call(
            R_TIMEOUT, "sys_icache_invalidate", remoteBase, contextOffset,
            0, 0, 0, 0, 0, 0);
    }
    BOOL exact = allocationLive && codeMappingLive && contextWritten &&
        codeRead && contextRead && remote_call_current_success() &&
        codeReadback.length == contextOffset &&
        memcmp(codeReadback.bytes, payload, contextOffset) == 0 &&
        memcmp(&contextReadback, context, sizeof(*context)) == 0;

    if (!exact && allocationLive && remote_call_current_success()) {
        (void)r_dlsym_call(
            R_TIMEOUT, "munmap", remoteBase, mappingLength,
            0, 0, 0, 0, 0, 0);
    }

    if (!exact) {
        printf("[ICONSTORE] vnode publisher mapping failed "
               "path=%s slice=%#llx file-offset=%#llx alloc=%s "
               "open=%lld/%d library-validation=%lld/%d "
               "map=%#llx/%d context-prefault=%s context-write=%s "
               "code-read=%s context-read=%s exact=%s\n",
               executablePath.fileSystemRepresentation,
               executableSliceOffset, payloadFileOffset,
               allocationLive ? "yes" : "no",
               (long long)openResult, openError,
               (long long)validationResult, validationError,
               mappedCode, mapError,
               contextPrefaulted ? "yes" : "no",
               contextWritten ? "yes" : "no",
               codeRead ? "yes" : "no", contextRead ? "yes" : "no",
               exact ? "yes" : "no");
        if (failureOut) {
            *failureOut = openResult < 0
                ? [NSString stringWithFormat:
                    @"publisher-vnode-open:%d", openError]
                : !libraryValidated
                    ? [NSString stringWithFormat:
                        @"publisher-vnode-library-validation:%d",
                        validationError]
                : mappedCode == UINT64_MAX
                    ? [NSString stringWithFormat:
                        @"publisher-vnode-mmap:%d", mapError]
                    : @"publisher-vnode-map-validation";
        }
        return NO;
    }

    printf("[ICONSTORE] signed vnode publisher code mapped "
           "path=%s slice=%#llx file-offset=%#llx target=%#llx code=%zu "
           "context=%#llx/%llu\n",
           executablePath.fileSystemRepresentation,
           executableSliceOffset, payloadFileOffset,
           remoteBase, contextOffset,
           contextAddress, contextLength);
    *remoteBaseOut = remoteBase;
    *mappingLengthOut = mappingLength;
    return YES;
}

static NSData *cnd_publisher_copy_remote_data(uint64_t object,
                                               NSUInteger maximumLength)
{
    if (!object || maximumLength == 0) return nil;
    uint64_t responds = r_sel("respondsToSelector:");
    uint64_t lengthSelector = r_sel("length");
    uint64_t bytesSelector = r_sel("bytes");
    if (!responds || !lengthSelector || !bytesSelector ||
        !r_msg2(object, "respondsToSelector:",
                lengthSelector, 0, 0, 0) ||
        !r_msg2(object, "respondsToSelector:",
                bytesSelector, 0, 0, 0)) {
        return nil;
    }
    uint64_t length = r_msg2(object, "length", 0, 0, 0, 0);
    uint64_t bytes = length && length <= maximumLength
        ? r_msg2(object, "bytes", 0, 0, 0, 0) : 0;
    if (!bytes || !length || !remote_call_current_success()) return nil;
    NSMutableData *result = [NSMutableData dataWithLength:(NSUInteger)length];
    return remote_read(bytes, result.mutableBytes, result.length)
        ? result : nil;
}

static NSString *cnd_publisher_copy_remote_indexed_identifier(
    uint64_t identifier);
static NSData *cnd_publisher_audit_copy_small_remote_data(
    uint64_t object, NSUInteger maximumLength, uint64_t scratch);
static uint64_t cnd_publisher_audit_object_ivar(
    uint64_t object, const char *name, uint64_t expectedOffset,
    uint64_t scratch);

static BOOL cnd_publisher_set_selectors(
    CNDIconServicesPublisherPayloadContext *context)
{
#define CND_PUBLISHER_SELECTOR(field, name)      \
    do {                                         \
        context->field = r_sel(name);            \
        if (!context->field) return NO;          \
    } while (0)
    CND_PUBLISHER_SELECTOR(selIcon, "icon");
    CND_PUBLISHER_SELECTOR(selImageDescriptor, "imageDescriptor");
    CND_PUBLISHER_SELECTOR(selRespondsToSelector, "respondsToSelector:");
    CND_PUBLISHER_SELECTOR(selBundleIdentifier, "bundleIdentifier");
    CND_PUBLISHER_SELECTOR(selSize, "size");
    CND_PUBLISHER_SELECTOR(selScale, "scale");
    CND_PUBLISHER_SELECTOR(selIsEqualToString, "isEqualToString:");
    CND_PUBLISHER_SELECTOR(selData, "data");
    CND_PUBLISHER_SELECTOR(selUUID, "uuid");
    CND_PUBLISHER_SELECTOR(selValidationToken, "validationToken");
    CND_PUBLISHER_SELECTOR(selAlloc, "alloc");
    CND_PUBLISHER_SELECTOR(selInitWithDataUUIDValidationToken,
                           "initWithData:uuid:validationToken:");
    CND_PUBLISHER_SELECTOR(selAutorelease, "autorelease");
    CND_PUBLISHER_SELECTOR(selRetain, "retain");
    CND_PUBLISHER_SELECTOR(selRelease, "release");
    CND_PUBLISHER_SELECTOR(selLength, "length");
    CND_PUBLISHER_SELECTOR(selUUIDString, "UUIDString");
    CND_PUBLISHER_SELECTOR(selInitWithBundleIdentifier,
                           "initWithBundleIdentifier:");
    CND_PUBLISHER_SELECTOR(selImageDescriptorWithIconVariantOptions,
                           "imageDescriptorWithIconVariant:options:");
    CND_PUBLISHER_SELECTOR(selCopy, "copy");
    CND_PUBLISHER_SELECTOR(selSetSize, "setSize:");
    CND_PUBLISHER_SELECTOR(selSetScale, "setScale:");
    CND_PUBLISHER_SELECTOR(selSetAppearance, "setAppearance:");
    CND_PUBLISHER_SELECTOR(selSetVariantOptions, "setVariantOptions:");
    CND_PUBLISHER_SELECTOR(selSetIgnoreCache, "setIgnoreCache:");
    CND_PUBLISHER_SELECTOR(selAppearance, "appearance");
    CND_PUBLISHER_SELECTOR(selVariantOptions, "variantOptions");
    CND_PUBLISHER_SELECTOR(selGenerateImageWithDescriptor,
                           "generateImageWithDescriptor:");
    CND_PUBLISHER_SELECTOR(selInitWithUTF8String, "initWithUTF8String:");
    CND_PUBLISHER_SELECTOR(selInitWithBytesLength, "initWithBytes:length:");
#undef CND_PUBLISHER_SELECTOR
    return YES;
}

static BOOL cnd_publisher_local_payload(
    const uint8_t **bytesOut, size_t *lengthOut,
    size_t *contextOffsetOut, size_t *probeOffsetOut,
    size_t *prepareDescriptorOffsetOut,
    size_t *installOffsetOut, size_t *generateOffsetOut,
    size_t *triggerOffsetOut, size_t *executeOffsetOut,
    size_t *cleanupOffsetOut)
{
    const uint8_t *start = cnd_publisher_payload_section_start;
    const uint8_t *end = cnd_publisher_payload_section_end;
    size_t length = end > start ? (size_t)(end - start) : 0;
#define CND_PUBLISHER_OFFSET(symbol) \
    ((size_t)((const uint8_t *)(symbol) - start))
    size_t context = CND_PUBLISHER_OFFSET(
        cnd_icon_publisher_payload_context);
    size_t probe = CND_PUBLISHER_OFFSET(cnd_icon_publisher_payload_probe);
    size_t prepareDescriptor = CND_PUBLISHER_OFFSET(
        cnd_icon_publisher_payload_prepare_descriptor);
    size_t install = CND_PUBLISHER_OFFSET(cnd_icon_publisher_payload_install);
    size_t generate = CND_PUBLISHER_OFFSET(cnd_icon_publisher_payload_generate);
    size_t trigger = CND_PUBLISHER_OFFSET(cnd_icon_publisher_payload_trigger);
    size_t execute = CND_PUBLISHER_OFFSET(cnd_icon_publisher_payload_execute);
    size_t cleanup = CND_PUBLISHER_OFFSET(cnd_icon_publisher_payload_cleanup);
#undef CND_PUBLISHER_OFFSET
    if (!start || length == 0 || length > (64U << 10) ||
        context + sizeof(CNDIconServicesPublisherPayloadContext) > length ||
        context + CND_ICON_PUBLISHER_PAYLOAD_CONTEXT_CAPACITY > length ||
        probe + 8 > length || prepareDescriptor + 8 > length ||
        install + 8 > length ||
        generate + 8 > length || trigger + 8 > length ||
        execute + 8 > length || cleanup + 8 > length) {
        return NO;
    }
    if (bytesOut) *bytesOut = start;
    if (lengthOut) *lengthOut = length;
    if (contextOffsetOut) *contextOffsetOut = context;
    if (probeOffsetOut) *probeOffsetOut = probe;
    if (prepareDescriptorOffsetOut)
        *prepareDescriptorOffsetOut = prepareDescriptor;
    if (installOffsetOut) *installOffsetOut = install;
    if (generateOffsetOut) *generateOffsetOut = generate;
    if (triggerOffsetOut) *triggerOffsetOut = trigger;
    if (executeOffsetOut) *executeOffsetOut = execute;
    if (cleanupOffsetOut) *cleanupOffsetOut = cleanup;
    return YES;
}

static BOOL cnd_publisher_remote_objects_equal(uint64_t left,
                                                uint64_t right)
{
    if (!left || !right || !remote_call_current_success()) return NO;
    if (left == right) return YES;
    return (r_msg2(left, "isEqual:", right, 0, 0, 0) & 1U) != 0 &&
        remote_call_current_success();
}

/*
 * Create one target-owned NSData without executing any Cyanide code in the
 * daemon.  The only cross-task mapping is anonymous RW staging data. NSData's
 * stock initializer copies those bytes before a standalone staging mapping is
 * removed; a batch retains and reuses the RW mapping until finishBatch.
 */
static uint64_t cnd_publisher_stock_make_data(
    NSData *data,
    CNDIconServicesPublisherBatchState *batch,
    BOOL borrowedBatchSession,
    BOOL *stagingRetainedOut,
    BOOL *stagingUnmappedOut,
    NSString **failureOut)
{
    if (stagingRetainedOut) *stagingRetainedOut = NO;
    if (stagingUnmappedOut) *stagingUnmappedOut = NO;
    if (failureOut) *failureOut = nil;
    if (![data isKindOfClass:NSData.class] || data.length == 0 ||
        data.length > CNDIconServicesPublisherMaximumStructuredDataLength ||
        !remote_call_current_success()) {
        if (failureOut) *failureOut = @"stock-api-themed-data";
        return 0;
    }

    uint64_t pageSize = borrowedBatchSession && batch.pageSize
        ? batch.pageSize
        : r_dlsym_call(R_TIMEOUT, "getpagesize", 0, 0, 0, 0, 0, 0, 0, 0);
    if (pageSize < 4096 || (pageSize & (pageSize - 1)) != 0) {
        if (failureOut) *failureOut = @"stock-api-page-size";
        return 0;
    }
    if (borrowedBatchSession && !batch.pageSize) batch.pageSize = pageSize;

    uint64_t required = MAX((uint64_t)1, (uint64_t)data.length);
    uint64_t staging = borrowedBatchSession ? batch.stagingRemoteBase : 0;
    uint64_t capacity = borrowedBatchSession ? batch.stagingCapacity : 0;
    if (staging && capacity < required) {
        int result = (int)r_dlsym_call(
            R_TIMEOUT, "munmap", staging, capacity, 0, 0, 0, 0, 0, 0);
        if (result != 0 || !remote_call_current_success()) {
            if (failureOut) *failureOut = @"stock-api-staging-grow-unmap";
            return 0;
        }
        staging = 0;
        capacity = 0;
        batch.stagingRemoteBase = 0;
        batch.stagingCapacity = 0;
    }
    if (!staging) {
        uint64_t desired = borrowedBatchSession
            ? MAX((uint64_t)CNDIconServicesPublisherDefaultStagingCapacity,
                  required)
            : required;
        capacity = (desired + pageSize - 1) & ~(pageSize - 1);
        if (capacity > CNDIconServicesPublisherMaximumStagingCapacity) {
            if (failureOut) *failureOut = @"stock-api-staging-capacity";
            return 0;
        }
        staging = r_dlsym_call(
            R_TIMEOUT, "mmap", 0, capacity, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON, (uint64_t)-1, 0, 0, 0);
        if (!staging || staging == UINT64_MAX) {
            if (failureOut) *failureOut = @"stock-api-staging-mmap";
            return 0;
        }
        if (borrowedBatchSession) {
            batch.stagingRemoteBase = staging;
            batch.stagingCapacity = capacity;
        }
    }

    BOOL copied = cnd_publisher_prefault_remote_write_range(
        staging, data.length) &&
        remote_write(staging, data.bytes, data.length) &&
        remote_call_current_success();
    uint64_t dataClass = copied ? r_class("NSData") : 0;
    uint64_t allocation = dataClass
        ? r_msg2(dataClass, "alloc", 0, 0, 0, 0) : 0;
    uint64_t remoteData = allocation
        ? r_msg2(allocation, "initWithBytes:length:",
                 staging, data.length, 0, 0)
        : 0;

    if (borrowedBatchSession) {
        if (stagingRetainedOut) *stagingRetainedOut = staging != 0;
    } else {
        int unmap = staging && capacity && remote_call_current_success()
            ? (int)r_dlsym_call(
                R_TIMEOUT, "munmap", staging, capacity, 0, 0, 0, 0, 0, 0)
            : -1;
        if (stagingUnmappedOut) *stagingUnmappedOut = unmap == 0;
        if (unmap != 0) {
            if (remoteData && remote_call_current_success()) {
                (void)r_msg2(remoteData, "release", 0, 0, 0, 0);
                remoteData = 0;
            }
            if (failureOut && !*failureOut)
                *failureOut = @"stock-api-staging-unmap";
        }
    }
    if (!remoteData || !remote_call_current_success()) {
        if (failureOut && !*failureOut)
            *failureOut = @"stock-api-nsdata";
        return 0;
    }
    return remoteData;
}

/*
 * Prepare one reusable descriptor per exact matrix identity entirely through
 * stock Objective-C/Foundation machinery. NSInvocation is used only for the
 * floating-point/struct setters and their typed readback; no injected
 * function or method replacement is involved.
 */
static uint64_t cnd_publisher_stock_descriptor(
    CNDIconServicesPublisherBatchState *batch,
    BOOL borrowedBatchSession,
    uint64_t descriptorClass,
    NSDictionary<NSString *, NSNumber *> *descriptorSpecification,
    BOOL requestedIgnoreCache,
    NSDictionary<NSString *, id> **diagnosticsOut,
    NSString **failureOut)
{
    if (diagnosticsOut) *diagnosticsOut = nil;
    if (failureOut) *failureOut = nil;
    NSDictionary *spec = cnd_publisher_normalized_descriptor_specification(
        descriptorSpecification);
    NSString *baseSpecKey = cnd_publisher_descriptor_specification_key(spec);
    NSString *specKey = baseSpecKey.length > 0
        ? [baseSpecKey stringByAppendingFormat:@":ignore=%d",
                                                requestedIgnoreCache]
        : nil;
    if (!spec || specKey.length == 0) {
        if (failureOut) *failureOut = @"stock-api-descriptor-specification";
        return 0;
    }
    uint64_t cachedDescriptor = borrowedBatchSession
        ? cnd_publisher_cached_descriptor(batch, specKey) : 0;
    if (cachedDescriptor) return cachedDescriptor;

    /* iOS 26.0 (23A341) declares this factory as two 32-bit signed ints:
     *   +imageDescriptorWithIconVariant:(int)preset options:(int)options
     *   @24@0:8i16i20
     * The first argument is a descriptor preset enum.  It is not the `v:`
     * value printed by -[ISImageDescriptor description].  That value is the
     * separately writable variantOptions property.  Start from preset zero,
     * then apply and verify the measured variantOptions below. */
    BOOL factoryABI = cnd_publisher_remote_class_method_has_types(
        descriptorClass, "imageDescriptorWithIconVariant:options:",
        "@24@0:8i16i20", NULL);
    BOOL copyABI = cnd_publisher_remote_method_has_types(
        descriptorClass, "copy", "@16@0:8", NULL);
    BOOL sizeSetterABI = cnd_publisher_remote_method_has_types(
        descriptorClass, "setSize:", "v32@0:8{CGSize=dd}16", NULL);
    BOOL scaleSetterABI = cnd_publisher_remote_method_has_types(
        descriptorClass, "setScale:", "v24@0:8d16", NULL);
    BOOL appearanceSetterABI = cnd_publisher_remote_method_has_types(
        descriptorClass, "setAppearance:", "v24@0:8q16", NULL);
    BOOL variantOptionsSetterABI = cnd_publisher_remote_method_has_types(
        descriptorClass, "setVariantOptions:", "v24@0:8Q16", NULL);
    BOOL ignoreSetterABI = cnd_publisher_remote_method_has_types(
        descriptorClass, "setIgnoreCache:", "v20@0:8B16", NULL);
    BOOL sizeGetterABI = cnd_publisher_remote_method_has_types(
        descriptorClass, "size", "{CGSize=dd}16@0:8", NULL);
    BOOL scaleGetterABI = cnd_publisher_remote_method_has_types(
        descriptorClass, "scale", "d16@0:8", NULL);
    BOOL appearanceGetterABI = cnd_publisher_remote_method_has_types(
        descriptorClass, "appearance", "q16@0:8", NULL);
    BOOL variantOptionsGetterABI = cnd_publisher_remote_method_has_types(
        descriptorClass, "variantOptions", "Q16@0:8", NULL);
    BOOL ignoreGetterABI = cnd_publisher_remote_method_has_types(
        descriptorClass, "ignoreCache", "B16@0:8", NULL);
    BOOL descriptorABI = factoryABI && copyABI && sizeSetterABI &&
        scaleSetterABI && appearanceSetterABI && variantOptionsSetterABI &&
        ignoreSetterABI && sizeGetterABI && scaleGetterABI &&
        appearanceGetterABI && variantOptionsGetterABI && ignoreGetterABI;
    if (!descriptorABI) {
        if (diagnosticsOut) {
            *diagnosticsOut = @{
                @"factory": @"imageDescriptorWithIconVariant:options:",
                @"factoryABI": @(factoryABI),
                @"factoryTypes":
                    cnd_publisher_remote_method_types_description(
                        descriptorClass,
                        "imageDescriptorWithIconVariant:options:", YES),
                @"copyTypes": cnd_publisher_remote_method_types_description(
                    descriptorClass, "copy", NO),
                @"sizeSetterTypes":
                    cnd_publisher_remote_method_types_description(
                        descriptorClass, "setSize:", NO),
                @"scaleSetterTypes":
                    cnd_publisher_remote_method_types_description(
                        descriptorClass, "setScale:", NO),
                @"appearanceSetterTypes":
                    cnd_publisher_remote_method_types_description(
                        descriptorClass, "setAppearance:", NO),
                @"variantOptionsSetterTypes":
                    cnd_publisher_remote_method_types_description(
                        descriptorClass, "setVariantOptions:", NO),
                @"ignoreCacheSetterTypes":
                    cnd_publisher_remote_method_types_description(
                        descriptorClass, "setIgnoreCache:", NO),
                @"sizeGetterTypes":
                    cnd_publisher_remote_method_types_description(
                        descriptorClass, "size", NO),
                @"scaleGetterTypes":
                    cnd_publisher_remote_method_types_description(
                        descriptorClass, "scale", NO),
                @"appearanceGetterTypes":
                    cnd_publisher_remote_method_types_description(
                        descriptorClass, "appearance", NO),
                @"variantOptionsGetterTypes":
                    cnd_publisher_remote_method_types_description(
                        descriptorClass, "variantOptions", NO),
                @"ignoreCacheGetterTypes":
                    cnd_publisher_remote_method_types_description(
                        descriptorClass, "ignoreCache", NO),
            };
        }
        if (failureOut) *failureOut = @"stock-api-descriptor-abi";
        return 0;
    }

    uint64_t requestedIconVariant =
        [spec[@"iconVariant"] unsignedLongLongValue];
    int32_t requestedOptions =
        (int32_t)[spec[@"options"] intValue];
    int32_t descriptorPreset = 0;
    uint64_t factoryDescriptor = r_msg2_raw(
        descriptorClass, "imageDescriptorWithIconVariant:options:",
        &descriptorPreset, sizeof(descriptorPreset),
        &requestedOptions, sizeof(requestedOptions),
        NULL, 0, NULL, 0);
    uint64_t descriptor = factoryDescriptor
        ? r_msg2(factoryDescriptor, "copy", 0, 0, 0, 0) : 0;
    if (!descriptor || !remote_call_current_success()) {
        if (failureOut) *failureOut = @"stock-api-descriptor-create";
        return 0;
    }

    CGSize requestedSize = CGSizeMake(
        [spec[@"pointWidth"] doubleValue],
        [spec[@"pointHeight"] doubleValue]);
    double requestedScale = [spec[@"scale"] doubleValue];
    uint64_t requestedAppearance =
        [spec[@"appearance"] unsignedLongLongValue];
    (void)r_msg2_raw(
        descriptor, "setSize:",
        &requestedSize, sizeof(requestedSize),
        NULL, 0, NULL, 0, NULL, 0);
    (void)r_msg2_raw(
        descriptor, "setScale:",
        &requestedScale, sizeof(requestedScale),
        NULL, 0, NULL, 0, NULL, 0);
    BOOL canSetAppearance = appearanceSetterABI;
    (void)r_msg2(descriptor, "setAppearance:",
                 requestedAppearance, 0, 0, 0);
    (void)r_msg2(descriptor, "setVariantOptions:",
                 requestedIconVariant, 0, 0, 0);
    (void)r_msg2(descriptor, "setIgnoreCache:",
                 requestedIgnoreCache, 0, 0, 0);

    CGSize observedSize = CGSizeZero;
    BOOL sizeKnown = r_msg2_struct_ret(
        descriptor, "size", &observedSize, sizeof(observedSize),
        NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    uint64_t scaleBits = r_msg2_raw(
        descriptor, "scale", NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    double observedScale = 0.0;
    memcpy(&observedScale, &scaleBits, sizeof(observedScale));
    BOOL observedIgnoreCache = (r_msg2(
        descriptor, "ignoreCache", 0, 0, 0, 0) & 1U) != 0;
    uint64_t observedAppearance = r_responds(descriptor, "appearance")
        ? r_msg2(descriptor, "appearance", 0, 0, 0, 0) : UINT64_MAX;
    uint64_t observedIconVariant = r_responds(descriptor, "variantOptions")
        ? r_msg2(descriptor, "variantOptions", 0, 0, 0, 0) : UINT64_MAX;
    /* The factory options argument has no corresponding descriptor getter on
     * iOS 26. variantOptions does, and is therefore read back exactly. */
    BOOL exact = sizeKnown &&
        observedSize.width == requestedSize.width &&
        observedSize.height == requestedSize.height &&
        observedScale == requestedScale &&
        observedAppearance == requestedAppearance && canSetAppearance &&
        observedIconVariant == requestedIconVariant &&
        observedIgnoreCache == requestedIgnoreCache &&
        remote_call_current_success();
    if (diagnosticsOut) {
        *diagnosticsOut = @{
            @"factory": @"imageDescriptorWithIconVariant:options:",
            @"factoryABI": @(factoryABI),
            @"factoryReturned": @(factoryDescriptor != 0),
            @"sizeKnown": @(sizeKnown),
            @"requestedWidth": @(requestedSize.width),
            @"requestedHeight": @(requestedSize.height),
            @"observedWidth": @(observedSize.width),
            @"observedHeight": @(observedSize.height),
            @"requestedScale": @(requestedScale),
            @"observedScale": @(observedScale),
            @"requestedAppearance": @(requestedAppearance),
            @"observedAppearance": @(observedAppearance),
            @"appearanceSetterAvailable": @(canSetAppearance),
            @"iconVariant": @(requestedIconVariant),
            @"observedIconVariant": @(observedIconVariant),
            @"descriptorPreset": @(descriptorPreset),
            @"options": @(requestedOptions),
            @"ignoreCache": @(observedIgnoreCache),
            @"requestedIgnoreCache": @(requestedIgnoreCache),
            @"exact": @(exact),
        };
    }
    if (!exact) {
        if (remote_call_current_success())
            (void)r_msg2(descriptor, "release", 0, 0, 0, 0);
        if (failureOut) *failureOut = @"stock-api-descriptor-readback";
        return 0;
    }
    if (borrowedBatchSession) {
        cnd_publisher_cache_descriptor(batch, specKey, descriptor);
    }
    return descriptor;
}

typedef struct {
    BOOL existingMappingValidated;
    BOOL recordFound;
    BOOL recordValidated;
    BOOL writeIssued;
    BOOL writeFlushed;
    BOOL writeVerified;
    BOOL lookupVerified;
    BOOL rollbackAttempted;
    BOOL rollbackVerified;
    NSUInteger candidatesInspected;
    NSUInteger lookupAttempts;
    uint64_t indexDataLength;
    uint64_t recordAddress;
} CNDIconServicesPersistentIndexTokenResult;

static uint64_t cnd_publisher_persistent_index_scratch(
    CNDIconServicesPublisherBatchState *batch, BOOL borrowedBatchSession,
    BOOL *ownedOut)
{
    if (ownedOut) *ownedOut = NO;
    if (borrowedBatchSession && batch.persistentIndexScratchRemoteBase &&
        batch.persistentIndexScratchLength) {
        return batch.persistentIndexScratchRemoteBase;
    }
    uint64_t pageSize = borrowedBatchSession && batch.pageSize
        ? batch.pageSize
        : r_dlsym_call(R_TIMEOUT, "getpagesize", 0, 0, 0, 0, 0, 0, 0, 0);
    if (pageSize < 4096 || pageSize > (64U << 10) ||
        (pageSize & (pageSize - 1)) != 0) return 0;
    if (borrowedBatchSession && !batch.pageSize) batch.pageSize = pageSize;
    uint64_t scratch = r_dlsym_call(
        R_TIMEOUT, "mmap", 0, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON, (uint64_t)-1, 0, 0, 0);
    BOOL ready = scratch && scratch != UINT64_MAX &&
        r_dlsym_call(R_TIMEOUT, "memset", scratch, 0, pageSize,
                     0, 0, 0, 0, 0) == scratch &&
        remote_call_current_success();
    if (!ready) {
        if (scratch && scratch != UINT64_MAX &&
            remote_call_current_success()) {
            (void)r_dlsym_call(R_TIMEOUT, "munmap", scratch, pageSize,
                               0, 0, 0, 0, 0, 0);
        }
        return 0;
    }
    if (borrowedBatchSession) {
        batch.persistentIndexScratchRemoteBase = scratch;
        batch.persistentIndexScratchLength = pageSize;
    } else if (ownedOut) {
        *ownedOut = YES;
    }
    return scratch;
}

static BOOL cnd_publisher_copy_remote_uuid_bytes(
    uint64_t identifier, uint64_t scratch, uint8_t bytes[16])
{
    if (!r_is_objc_ptr(identifier) || !scratch || !bytes) return NO;
    uint64_t identifierClass = r_dlsym_call(
        R_TIMEOUT, "object_getClass", identifier, 0, 0, 0, 0, 0, 0, 0);
    char methodTypes[96] = {0};
    BOOL abi = identifierClass && cnd_publisher_copy_remote_method_types(
        identifierClass, "getUUIDBytes:", NO,
        methodTypes, sizeof(methodTypes)) &&
        (!strcmp(methodTypes, "v24@0:8[16C]16") ||
         !strcmp(methodTypes, "v24@0:8^C16") ||
         !strcmp(methodTypes, "v24@0:8*16"));
    if (!abi || r_dlsym_call(R_TIMEOUT, "memset", scratch, 0, 16,
                             0, 0, 0, 0, 0) != scratch) return NO;
    (void)r_msg2(identifier, "getUUIDBytes:", scratch, 0, 0, 0);
    return remote_call_current_success() && remote_read(scratch, bytes, 16);
}

static BOOL cnd_publisher_wait_for_persistent_index_identity(
    uint64_t managerCache, uint64_t canonicalIcon, uint64_t descriptor,
    uint64_t expectedUUID, uint64_t expectedToken, uint64_t scratch,
    NSUInteger *attemptsOut)
{
    if (attemptsOut) *attemptsOut = 0;
    if (!managerCache || !canonicalIcon || !descriptor || !expectedUUID ||
        !expectedToken || !scratch) return NO;
    uint64_t cacheClass = r_dlsym_call(
        R_TIMEOUT, "object_getClass", managerCache, 0, 0, 0, 0, 0, 0, 0);
    uint64_t managerIndex = cnd_publisher_audit_object_ivar(
        managerCache, "_storeIndex", 0x8, scratch);
    uint64_t managerIndexClass = managerIndex ? r_dlsym_call(
        R_TIMEOUT, "object_getClass", managerIndex,
        0, 0, 0, 0, 0, 0, 0) : 0;
    if (!cacheClass || !managerIndexClass ||
        !cnd_publisher_remote_method_has_types(
            cacheClass,
            "findStoreUnitForIcon:descriptor:UUID:validationToken:",
            "B48@0:8@16@24^@32^@40", NULL) ||
        !cnd_publisher_remote_method_has_types(
            managerIndexClass, "invalidate", "v16@0:8", NULL)) return NO;

    for (NSUInteger attempt = 1;
         attempt <= CNDIconServicesPublisherPersistentIndexSettleAttempts;
         attempt++) {
        if (attemptsOut) *attemptsOut = attempt;
        /* A prior lookup may have materialized the read-only mmap before the
         * asynchronous mutable-index block committed. Remap on each retry so
         * bounded polling cannot remain pinned to that pre-commit view. */
        if (attempt > 1U) {
            (void)r_msg2(managerIndex, "invalidate", 0, 0, 0, 0);
            if (!remote_call_current_success()) return NO;
        }
        uint64_t cleared = r_dlsym_call(
            R_TIMEOUT, "memset", scratch, 0, sizeof(uint64_t) * 2,
            0, 0, 0, 0, 0);
        if (cleared != scratch || !remote_call_current_success()) return NO;
        uint64_t found = r_msg2(
            managerCache,
            "findStoreUnitForIcon:descriptor:UUID:validationToken:",
            canonicalIcon, descriptor, scratch, scratch + sizeof(uint64_t));
        uint64_t outputs[2] = {0};
        BOOL outputsRead = remote_call_current_success() &&
            remote_read(scratch, outputs, sizeof(outputs));
        if ((found & 1U) != 0 && outputsRead && outputs[0] && outputs[1] &&
            cnd_publisher_remote_objects_equal(outputs[0], expectedUUID) &&
            cnd_publisher_remote_objects_equal(outputs[1], expectedToken)) {
            return YES;
        }
        if (attempt < CNDIconServicesPublisherPersistentIndexSettleAttempts) {
            (void)r_dlsym_call(
                R_TIMEOUT, "usleep",
                CNDIconServicesPublisherPersistentIndexSettleIntervalUS,
                0, 0, 0, 0, 0, 0, 0);
            if (!remote_call_current_success()) return NO;
        }
    }
    return NO;
}

/*
 * Update the validation token in the exact current 23A341 store-index value.
 * The Apple mapper opens the existing file O_RDWR and maps it MAP_SHARED. We
 * prevalidate that existing mapping before constructing a transient mutable
 * index, inject the mapping so no create/repair path can run, and change only
 * the forty-byte non-key token field. A fresh indexed lookup is the commit
 * criterion. Any post-write failure restores and verifies the stock token.
 */
static BOOL cnd_publisher_rewrite_persistent_index_token(
    uint64_t managerCache, uint64_t canonicalIcon, uint64_t descriptor,
    uint64_t stockUUID, uint64_t stockToken, uint64_t replacementToken,
    NSDictionary<NSString *, NSNumber *> *specification, uint64_t scratch,
    uint64_t pageSize, CNDIconServicesPersistentIndexTokenResult *resultOut,
    NSString **failureOut)
{
    CNDIconServicesPersistentIndexTokenResult result = {0};
    if (resultOut) *resultOut = result;
    if (failureOut) *failureOut = nil;
    if (!managerCache || !canonicalIcon || !descriptor || !stockUUID ||
        !stockToken || !replacementToken || !specification || !scratch ||
        pageSize < 4096 || (pageSize & (pageSize - 1)) != 0) {
        if (failureOut) *failureOut = @"stock-api-persistent-index-input";
        return NO;
    }

    uint64_t mutableIndex = 0;
    NSString *failure = nil;
    do {
        uint64_t dataClass = r_class("NSData");
        uint64_t mutableIndexClass = r_class("ISMutableStoreIndex");
        uint64_t managerIndex = cnd_publisher_audit_object_ivar(
            managerCache, "_storeIndex", 0x8, scratch);
        uint64_t indexURL = managerIndex
            ? cnd_publisher_audit_object_ivar(
                managerIndex, "_indexFileURL", 0x8, scratch)
            : 0;
        uint64_t managerIndexClass = managerIndex ? r_dlsym_call(
            R_TIMEOUT, "object_getClass", managerIndex,
            0, 0, 0, 0, 0, 0, 0) : 0;
        uint64_t descriptorClass = r_dlsym_call(
            R_TIMEOUT, "object_getClass", descriptor,
            0, 0, 0, 0, 0, 0, 0);
        uint64_t iconClass = r_dlsym_call(
            R_TIMEOUT, "object_getClass", canonicalIcon,
            0, 0, 0, 0, 0, 0, 0);
        BOOL fixedABI = dataClass && mutableIndexClass && managerIndex &&
            indexURL && managerIndexClass && descriptorClass && iconClass &&
            cnd_publisher_remote_class_method_has_types(
                dataClass, "_ISMutableStoreIndex_mappedDataWithURL:",
                "@24@0:8@16", NULL) &&
            cnd_publisher_remote_method_has_types(
                mutableIndexClass, "initWithStoreFileURL:capacity:",
                "@32@0:8@16Q24", NULL) &&
            cnd_publisher_remote_method_has_types(
                mutableIndexClass, "_internalSetData:",
                "v24@0:8@16", NULL) &&
            cnd_publisher_remote_method_has_types(
                mutableIndexClass, "validate", "B16@0:8", NULL) &&
            cnd_publisher_remote_method_has_types(
                mutableIndexClass, "data", "@16@0:8", NULL) &&
            cnd_publisher_remote_method_has_types(
                managerIndexClass, "invalidate", "v16@0:8", NULL) &&
            cnd_publisher_remote_method_has_types(
                descriptorClass, "digest", "@16@0:8", NULL) &&
            cnd_publisher_remote_method_has_types(
                iconClass, "digest", "@16@0:8", NULL) &&
            cnd_publisher_remote_method_has_types(
                dataClass, "length", "Q16@0:8", NULL) &&
            cnd_publisher_remote_method_has_types(
                dataClass, "bytes", "r^v16@0:8", "^v16@0:8");
        if (!fixedABI || !remote_call_current_success()) {
            failure = @"stock-api-persistent-index-abi";
            break;
        }

        uint8_t unitUUIDBytes[16] = {0};
        uint8_t iconDigestBytes[16] = {0};
        uint8_t descriptorDigestBytes[16] = {0};
        /* Mirror findStoreUnitForIcon:descriptor: exactly. Its 23A341
         * implementation obtains both digests through the -digest UUID
         * getters; digest:size: is a different representation and cannot be
         * used to identify the persistent value. */
        uint64_t iconDigest = r_msg2(
            canonicalIcon, "digest", 0, 0, 0, 0);
        uint64_t descriptorDigest = r_msg2(
            descriptor, "digest", 0, 0, 0, 0);
        BOOL identitiesReady = iconDigest && descriptorDigest &&
            cnd_publisher_copy_remote_uuid_bytes(
                stockUUID, scratch, unitUUIDBytes) &&
            cnd_publisher_copy_remote_uuid_bytes(
                iconDigest, scratch, iconDigestBytes) &&
            cnd_publisher_copy_remote_uuid_bytes(
                descriptorDigest, scratch, descriptorDigestBytes);
        NSData *stockTokenBytes = identitiesReady
            ? cnd_publisher_audit_copy_small_remote_data(
                stockToken, 40U, scratch) : nil;
        NSData *replacementTokenBytes = identitiesReady
            ? cnd_publisher_audit_copy_small_remote_data(
                replacementToken, 40U, scratch) : nil;
        if (!identitiesReady || stockTokenBytes.length != 40U ||
            replacementTokenBytes.length != 40U) {
            failure = @"stock-api-persistent-index-identities";
            break;
        }

        uint64_t mappedData = r_msg2(
            dataClass, "_ISMutableStoreIndex_mappedDataWithURL:",
            indexURL, 0, 0, 0);
        uint64_t mappedDataClass = mappedData ? r_dlsym_call(
            R_TIMEOUT, "object_getClass", mappedData,
            0, 0, 0, 0, 0, 0, 0) : 0;
        BOOL mappedABI = mappedDataClass &&
            cnd_publisher_remote_method_has_types(
                mappedDataClass, "_ISStoreIndex_isValid", "B16@0:8", NULL);
        result.existingMappingValidated = mappedABI &&
            (r_msg2(mappedData, "_ISStoreIndex_isValid", 0, 0, 0, 0) & 1U);
        if (!result.existingMappingValidated ||
            !remote_call_current_success()) {
            failure = @"stock-api-persistent-index-existing-map";
            break;
        }

        uint64_t allocation = r_msg2(
            mutableIndexClass, "alloc", 0, 0, 0, 0);
        mutableIndex = allocation ? r_msg2(
            allocation, "initWithStoreFileURL:capacity:",
            indexURL, 0xFA0, 0, 0) : 0;
        if (!mutableIndex) {
            failure = @"stock-api-persistent-index-open";
            break;
        }
        (void)r_msg2(mutableIndex, "_internalSetData:",
                     mappedData, 0, 0, 0);
        BOOL valid = (r_msg2(
            mutableIndex, "validate", 0, 0, 0, 0) & 1U) != 0;
        uint64_t indexData = valid ? r_msg2(
            mutableIndex, "data", 0, 0, 0, 0) : 0;
        result.indexDataLength = indexData
            ? r_msg2(indexData, "length", 0, 0, 0, 0) : 0;
        uint64_t indexBytes = result.indexDataLength > 0 &&
            result.indexDataLength <=
                CNDIconServicesPublisherMaximumPersistentIndexLength
            ? r_msg2(indexData, "bytes", 0, 0, 0, 0) : 0;
        if (!valid || indexData != mappedData || !indexBytes ||
            !remote_call_current_success()) {
            failure = @"stock-api-persistent-index-data";
            break;
        }

        const uint64_t uuidOffset = offsetof(
            CNDIconServicesStoreIndexValue23A341, storeUnitUUID);
        const uint64_t tokenOffset = offsetof(
            CNDIconServicesStoreIndexValue23A341, validationToken);
        if (!remote_write(scratch, unitUUIDBytes, sizeof(unitUUIDBytes)) ||
            !remote_write(scratch + 0x100,
                          replacementTokenBytes.bytes,
                          replacementTokenBytes.length) ||
            !remote_write(scratch + 0x140,
                          stockTokenBytes.bytes,
                          stockTokenBytes.length)) {
            failure = @"stock-api-persistent-index-scratch";
            break;
        }

        uint64_t search = indexBytes;
        uint64_t remaining = result.indexDataLength;
        uint32_t expectedScale =
            [specification[@"scale"] unsignedIntValue];
        double requestedPointSize =
            [specification[@"pointHeight"] doubleValue];
        CNDIconServicesStoreIndexValue23A341 record = {0};
        for (NSUInteger candidate = 0; candidate < 32 && remaining >= 16;
             candidate++) {
            uint64_t match = r_dlsym_call(
                R_TIMEOUT, "memmem", search, remaining, scratch, 16,
                0, 0, 0, 0);
            if (!match || match < indexBytes ||
                match >= indexBytes + result.indexDataLength) break;
            result.candidatesInspected++;
            if (match >= indexBytes + uuidOffset) {
                uint64_t recordAddress = match - uuidOffset;
                if (recordAddress >= indexBytes &&
                    recordAddress <= indexBytes + result.indexDataLength -
                        sizeof(record)) {
                    uint64_t copied = r_dlsym_call(
                        R_TIMEOUT, "memcpy", scratch + 0x200,
                        recordAddress, sizeof(record), 0, 0, 0, 0, 0);
                    BOOL recordRead = copied == scratch + 0x200 &&
                        remote_call_current_success() &&
                        remote_read(scratch + 0x200,
                                    &record, sizeof(record));
                    BOOL exact = recordRead &&
                        record.scale == expectedScale &&
                        requestedPointSize >= record.minimumSize &&
                        requestedPointSize <= record.maximumSize &&
                        memcmp(record.iconDigest, iconDigestBytes, 16) == 0 &&
                        memcmp(record.descriptorDigest,
                               descriptorDigestBytes, 16) == 0 &&
                        memcmp(record.storeUnitUUID,
                               unitUUIDBytes, 16) == 0 &&
                        memcmp(record.validationToken,
                               stockTokenBytes.bytes, 40) == 0;
                    if (exact) {
                        result.recordFound = YES;
                        result.recordValidated = YES;
                        result.recordAddress = recordAddress;
                        break;
                    }
                }
            }
            uint64_t next = match + 1;
            if (next <= search || next >= indexBytes + result.indexDataLength)
                break;
            search = next;
            remaining = indexBytes + result.indexDataLength - search;
        }
        if (!result.recordValidated || !result.recordAddress) {
            failure = @"stock-api-persistent-index-record";
            break;
        }

        uint64_t tokenAddress = result.recordAddress + tokenOffset;
        result.writeIssued = YES;
        uint64_t copied = r_dlsym_call(
            R_TIMEOUT, "memcpy", tokenAddress, scratch + 0x100, 40,
            0, 0, 0, 0, 0);
        uint64_t pageStart = tokenAddress & ~(pageSize - 1);
        uint64_t tokenEnd = tokenAddress + 40;
        uint64_t syncLength = (tokenEnd - pageStart + pageSize - 1) &
            ~(pageSize - 1);
        int64_t syncResult = copied == tokenAddress
            ? (int64_t)r_dlsym_call(
                R_TIMEOUT, "msync", pageStart, syncLength, MS_SYNC,
                0, 0, 0, 0, 0)
            : -1;
        result.writeFlushed = copied == tokenAddress && syncResult == 0 &&
            remote_call_current_success();
        if (result.writeFlushed) {
            uint64_t readback = r_dlsym_call(
                R_TIMEOUT, "memcpy", scratch + 0x200,
                result.recordAddress, sizeof(record), 0, 0, 0, 0, 0);
            result.writeVerified = readback == scratch + 0x200 &&
                remote_call_current_success() &&
                remote_read(scratch + 0x200, &record, sizeof(record)) &&
                memcmp(record.validationToken,
                       replacementTokenBytes.bytes, 40) == 0;
        }
        if (result.writeVerified) {
            (void)r_msg2(managerIndex, "invalidate", 0, 0, 0, 0);
            result.lookupVerified = remote_call_current_success() &&
                cnd_publisher_wait_for_persistent_index_identity(
                    managerCache, canonicalIcon, descriptor,
                    stockUUID, replacementToken, scratch,
                    &result.lookupAttempts);
        }
        if (!result.writeFlushed || !result.writeVerified ||
            !result.lookupVerified) {
            result.rollbackAttempted = result.writeIssued &&
                remote_call_current_success();
            if (result.rollbackAttempted) {
                uint64_t restored = r_dlsym_call(
                    R_TIMEOUT, "memcpy", tokenAddress,
                    scratch + 0x140, 40, 0, 0, 0, 0, 0);
                int64_t rollbackSync = restored == tokenAddress
                    ? (int64_t)r_dlsym_call(
                        R_TIMEOUT, "msync", pageStart, syncLength, MS_SYNC,
                        0, 0, 0, 0, 0)
                    : -1;
                if (rollbackSync == 0 && remote_call_current_success()) {
                    (void)r_msg2(managerIndex, "invalidate", 0, 0, 0, 0);
                    NSUInteger rollbackAttempts = 0;
                    result.rollbackVerified = remote_call_current_success() &&
                        cnd_publisher_wait_for_persistent_index_identity(
                            managerCache, canonicalIcon, descriptor,
                            stockUUID, stockToken, scratch,
                            &rollbackAttempts);
                }
            }
            failure = @"stock-api-persistent-index-token-readback";
            break;
        }
    } while (0);

    if (mutableIndex && remote_call_current_success()) {
        (void)r_msg2(mutableIndex, "release", 0, 0, 0, 0);
    }
    if (resultOut) *resultOut = result;
    if (failureOut) *failureOut = failure;
    return result.lookupVerified && remote_call_current_success();
}

/*
 * Physical-device publication path.
 *
 * The vPhone proof used a one-shot replacement IMP so IconServices' outer
 * transaction would assign/index the response UUID. A physical platform
 * daemon cannot safely execute that copied callback. Instead, first perform a
 * completely stock ignore-cache generation, which gives us an already
 * indexed UUID and validation token. Reuse that identity for one ISStoreUnit
 * write, replace the token in that exact persistent ISStoreIndex value, and
 * update the icon's ordinary ISImageCache. Every instruction run in
 * iconservicesagent therefore belongs to Apple-signed system code.
 */
static NSDictionary<NSString *, id> *
cnd_publisher_run_stock_store(NSString *bundleIdentifier,
                              NSData *structuredImageData,
                              NSDictionary<NSString *, NSNumber *> *
                                  descriptorSpecification)
{
    CFAbsoluteTime startedAt = CFAbsoluteTimeGetCurrent();
    BOOL replacing = structuredImageData.length > 0;
    NSMutableDictionary *report = [@{
        @"ok": @NO,
        @"stage": @"stock-api-preflight",
        @"message": @"The stock IconServices store transaction did not start.",
        @"mode": replacing ? @"replace" : @"stock",
        @"springBoardRemoteCallAttempted": @NO,
        @"spotlightRemoteCallAttempted": @NO,
        @"applicationBundleMutationAttempted": @NO,
        @"customExecutablePayloadUsed": @NO,
        @"methodInterpositionUsed": @NO,
    } mutableCopy];
    NSDictionary *specification =
        cnd_publisher_normalized_descriptor_specification(
            descriptorSpecification);
    if (!cnd_publisher_valid_bundle_identifier(bundleIdentifier) ||
        !specification ||
        (replacing &&
         (structuredImageData.length == 0 ||
          structuredImageData.length >
              CNDIconServicesPublisherMaximumStructuredDataLength))) {
        report[@"stage"] = @"stock-api-input";
        report[@"message"] = @"The stock IconServices transaction input is invalid.";
        return report;
    }

    CNDIconServicesPublisherBatchState *batch = cnd_publisher_batch_state();
    BOOL borrowedBatchSession = batch.session != nil;
    NSDictionary *wake = borrowedBatchSession ? batch.wake : nil;
    RemoteCallSession *session = borrowedBatchSession ? batch.session : nil;
    if (borrowedBatchSession &&
        (!batch.healthy || ![session hasLocalState] ||
         session.pid != batch.pid)) {
        report[@"stage"] = @"batch-session";
        report[@"message"] = @"The pinned iconservicesagent batch session is not healthy.";
        return report;
    }
    if (!session) {
        NSError *wakeError = nil;
        wake = cnd_publisher_wake_agent_without_generation(
            bundleIdentifier, &wakeError);
        if (!wake) {
            report[@"stage"] = @"agent-wake";
            report[@"message"] = wakeError.localizedDescription ?:
                @"IconServices could not be made resident.";
            return report;
        }
        NSError *sessionError = nil;
        session = cnd_publisher_open_agent_session(
            bundleIdentifier, &sessionError);
        if (!session) {
            report[@"stage"] = @"remote-session";
            report[@"message"] = sessionError.localizedDescription ?:
                @"The iconservicesagent session could not be opened.";
            return report;
        }
    }
    report[@"agentPID"] = @(session.pid);
    report[@"batchSessionBorrowed"] = @(borrowedBatchSession);

    __block BOOL remoteOK = NO;
    __block BOOL transactionStarted = NO;
    __block BOOL transactionCleaned = NO;
    __block BOOL stockCaptured = NO;
    __block BOOL stockGenerationInitiallyPersisted = NO;
    __block BOOL stockGenerationPersisted = NO;
    __block BOOL persistentIndexIdentitySettled = NO;
    __block BOOL persistentIndexTokenRewriteVerified = !replacing;
    __block BOOL persistentIndexScratchLifecycleVerified =
        borrowedBatchSession;
    __block BOOL directStoreRemoveIssued = NO;
    __block BOOL directStoreRemoveVerified = NO;
    __block BOOL directStoreWriteIssued = NO;
    __block BOOL directStoreWriteVerified = NO;
    __block BOOL immediateStoreRollbackAttempted = NO;
    __block BOOL immediateStoreRollbackSucceeded = NO;
    __block BOOL replacementCreated = NO;
    __block BOOL replacementPublished = NO;
    __block BOOL cacheVerified = NO;
    __block BOOL storeVerified = NO;
    __block BOOL stagingRetained = NO;
    __block BOOL stagingUnmapped = !replacing;
    __block NSUInteger releaseCount = 0;
    __block NSUInteger persistentIndexIdentityAttempts = 0;
    __block CNDIconServicesPersistentIndexTokenResult
        persistentIndexTokenResult = {0};
    __block uint64_t stockDataLength = 0;
    __block uint64_t themedDataLength = replacing
        ? structuredImageData.length : 0;
    __block uint64_t tokenLength = 0;
    __block uint64_t publishedTokenLength = 0;
    __block NSString *stockUUIDText = @"";
    __block NSString *stockHash = @"";
    __block NSString *stockValidationTokenHash = @"";
    __block NSString *publishedValidationTokenHash = @"";
    __block NSString *failure = nil;
    __block NSDictionary *descriptorDiagnostics = nil;

    @try {
        remote_call_with_session_suppressing_result_logs(session, ^{
            uint64_t pool = r_autorelease_pool_push();
            uint64_t targetBundle = 0, localIcon = 0, stockResponse = 0;
            uint64_t themedData = 0, replacement = 0, storeUnit = 0;
            uint64_t rollbackUnit = 0;
            uint64_t descriptor = 0;
            uint64_t persistentIndexScratch = 0;
            BOOL persistentIndexScratchOwned = NO;
            do {
                if (!pool) { failure = @"stock-api-autorelease-pool"; break; }

                BOOL cached = borrowedBatchSession && batch.stockStoreABIReady;
                uint64_t managerClass = r_class("ISIconManager");
                uint64_t iconClass = r_class("ISBundleIdentifierIcon");
                uint64_t descriptorClass = r_class("ISImageDescriptor");
                uint64_t cacheImageClass = r_class("IFCacheImage");
                uint64_t dataClass = r_class("NSData");
                uint64_t storeUnitClass = cached
                    ? batch.stockStoreUnitClass : r_class("ISStoreUnit");
                uint64_t manager = cached ? batch.stockManager : 0;
                uint64_t managerCache = cached ? batch.stockManagerCache : 0;
                uint64_t store = cached ? batch.stockStore : 0;
                BOOL abi = managerClass && iconClass && descriptorClass &&
                    cacheImageClass && storeUnitClass;
                if (!cached && abi) {
                    abi = cnd_publisher_remote_class_method_has_types(
                            managerClass, "sharedInstance", "@16@0:8", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            managerClass, "findOrRegisterIcon:",
                            "@24@0:8@16", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            managerClass, "iconCache", "@16@0:8", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            iconClass, "initWithBundleIdentifier:",
                            "@24@0:8@16", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            iconClass, "generateImageWithDescriptor:",
                            "@24@0:8@16", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            iconClass, "imageCache", "@16@0:8", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            cacheImageClass,
                            "initWithData:uuid:validationToken:",
                            "@40@0:8@16@24@32", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            cacheImageClass, "data", "@16@0:8", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            cacheImageClass, "uuid", "@16@0:8", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            cacheImageClass, "validationToken",
                            "@16@0:8", NULL) &&
                        (!replacing ||
                         (dataClass &&
                          cnd_publisher_remote_class_method_has_types(
                              dataClass, "_is_validToken",
                              "@16@0:8", NULL))) &&
                        cnd_publisher_remote_method_has_types(
                            storeUnitClass, "initWithData:UUID:",
                            "@32@0:8@16@24", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            storeUnitClass, "data", "@16@0:8", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            storeUnitClass, "UUID", "@16@0:8", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            storeUnitClass, "isValid", "B16@0:8", NULL);
                    manager = abi
                        ? r_msg2(managerClass, "sharedInstance", 0, 0, 0, 0)
                        : 0;
                    managerCache = manager
                        ? r_msg2(manager, "iconCache", 0, 0, 0, 0) : 0;
                    store = managerCache
                        ? r_msg2(managerCache, "store", 0, 0, 0, 0) : 0;
                    uint64_t storeClass = r_class("ISStore");
                    abi = abi && manager && managerCache && store &&
                        storeClass &&
                        cnd_publisher_remote_method_has_types(
                            storeClass, "writeStoreUnit:",
                            "B24@0:8@16", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            storeClass, "unitForUUID:",
                            "@24@0:8@16", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            storeClass, "removeUnitForUUID:",
                            "B24@0:8@16", NULL);
                    if (abi && borrowedBatchSession) {
                        batch.stockStoreABIReady = YES;
                        batch.stockManager = manager;
                        batch.stockManagerCache = managerCache;
                        batch.stockStore = store;
                        batch.stockStoreUnitClass = storeUnitClass;
                    }
                }
                if (!abi || !manager || !managerCache || !store) {
                    failure = @"stock-api-abi-or-store";
                    break;
                }

                descriptor = cnd_publisher_stock_descriptor(
                    batch, borrowedBatchSession, descriptorClass,
                    specification, YES,
                    &descriptorDiagnostics, &failure);
                targetBundle = r_nsstr_retained(bundleIdentifier.UTF8String);
                uint64_t iconAllocation = targetBundle
                    ? r_msg2(iconClass, "alloc", 0, 0, 0, 0) : 0;
                localIcon = iconAllocation
                    ? r_msg2(iconAllocation, "initWithBundleIdentifier:",
                             targetBundle, 0, 0, 0)
                    : 0;
                uint64_t canonicalIcon = localIcon
                    ? r_msg2(manager, "findOrRegisterIcon:",
                             localIcon, 0, 0, 0)
                    : 0;
                uint64_t canonicalCache = canonicalIcon
                    ? r_msg2(canonicalIcon, "imageCache", 0, 0, 0, 0)
                    : 0;
                BOOL cacheABI = canonicalCache &&
                    r_responds(canonicalCache, "setImage:forDescriptor:") &&
                    r_responds(canonicalCache, "imageForDescriptor:");
                if (!descriptor || !targetBundle || !localIcon ||
                    !canonicalIcon || !cacheABI ||
                    !remote_call_current_success()) {
                    if (!failure) failure = @"stock-api-icon-or-cache";
                    break;
                }

                (void)r_msg2(descriptor, "setIgnoreCache:", 1, 0, 0, 0);
                transactionStarted = YES;
                uint64_t generated = r_msg2(
                    canonicalIcon, "generateImageWithDescriptor:",
                    descriptor, 0, 0, 0);
                stockResponse = generated
                    ? r_msg2(generated, "retain", 0, 0, 0, 0) : 0;
                uint64_t stockData = stockResponse
                    ? r_msg2(stockResponse, "data", 0, 0, 0, 0) : 0;
                uint64_t stockUUID = stockResponse
                    ? r_msg2(stockResponse, "uuid", 0, 0, 0, 0) : 0;
                uint64_t stockToken = stockResponse
                    ? r_msg2(stockResponse, "validationToken", 0, 0, 0, 0)
                    : 0;
                stockDataLength = stockData
                    ? r_msg2(stockData, "length", 0, 0, 0, 0) : 0;
                tokenLength = stockToken
                    ? r_msg2(stockToken, "length", 0, 0, 0, 0) : 0;
                BOOL stockUUIDObject = r_is_objc_ptr(stockUUID);
                stockUUIDText = stockUUIDObject
                    ? cnd_publisher_copy_remote_indexed_identifier(stockUUID)
                    : @"";
                stockCaptured = stockData && stockUUIDObject && stockToken &&
                    stockDataLength > 0 && tokenLength > 0 &&
                    remote_call_current_success();
                if (!stockCaptured) {
                    failure = @"stock-api-generation-response";
                    break;
                }

                uint64_t stockUnit = r_msg2(
                    store, "unitForUUID:", stockUUID, 0, 0, 0);
                uint64_t stockUnitData = stockUnit
                    ? r_msg2(stockUnit, "data", 0, 0, 0, 0) : 0;
                stockGenerationInitiallyPersisted = stockUnitData &&
                    cnd_publisher_remote_objects_equal(
                        stockUnitData, stockData);
                stockGenerationPersisted =
                    stockGenerationInitiallyPersisted;
                /*
                 * Apply is destructive, so it may only replace an exact
                 * freshly generated stock unit. Restore is different: the
                 * unit is expected to contain themed bytes, and the fresh
                 * ignore-cache response above is the authoritative stock
                 * source used to rebuild it.
                 */
                if (replacing && !stockGenerationInitiallyPersisted) {
                    failure = @"stock-api-generation-store-readback";
                    break;
                }

                /* generateStoreUnitWithRequest:validationToken: schedules its
                 * ISMutableStoreIndex mutation asynchronously. Do not replace
                 * the store bytes until the public cache lookup proves that
                 * the exact fresh stock UUID and token have reached the
                 * persistent index. Otherwise the delayed Apple block can
                 * race this transaction and overwrite our final token. */
                persistentIndexScratch =
                    cnd_publisher_persistent_index_scratch(
                        batch, borrowedBatchSession,
                        &persistentIndexScratchOwned);
                uint64_t persistentIndexPageSize =
                    borrowedBatchSession && batch.pageSize
                    ? batch.pageSize
                    : r_dlsym_call(R_TIMEOUT, "getpagesize",
                                   0, 0, 0, 0, 0, 0, 0, 0);
                persistentIndexIdentitySettled = persistentIndexScratch &&
                    cnd_publisher_wait_for_persistent_index_identity(
                        managerCache, canonicalIcon, descriptor,
                        stockUUID, stockToken, persistentIndexScratch,
                        &persistentIndexIdentityAttempts);
                if (!persistentIndexIdentitySettled ||
                    persistentIndexPageSize < 4096 ||
                    (persistentIndexPageSize &
                     (persistentIndexPageSize - 1)) != 0) {
                    failure = @"stock-api-persistent-index-settle";
                    break;
                }

                uint64_t expectedResponse = stockResponse;
                uint64_t expectedData = stockData;
                uint64_t publishedToken = stockToken;
                if (replacing) {
                    /*
                     * Ordinary IconServices validation tokens embed the
                     * current LaunchServices knowledge UUID and database
                     * sequence. Any unrelated app install advances that
                     * state and makes a copied stock token stale, allowing a
                     * later consumer lookup to regenerate stock pixels over
                     * the themed record. IconServices' own always-valid
                     * sentinel is explicitly accepted by
                     * -[ISConcreteIcon assessValidationToken:] without that
                     * LaunchServices epoch comparison.
                     */
                    publishedToken = r_msg2(
                        dataClass, "_is_validToken", 0, 0, 0, 0);
                    publishedTokenLength = publishedToken
                        ? r_msg2(publishedToken, "length", 0, 0, 0, 0) : 0;
                    if (!publishedToken || publishedTokenLength != 40U ||
                        !remote_call_current_success()) {
                        failure = @"stock-api-always-valid-token";
                        break;
                    }
                    themedData = cnd_publisher_stock_make_data(
                        structuredImageData, batch, borrowedBatchSession,
                        &stagingRetained, &stagingUnmapped, &failure);
                    uint64_t replacementAllocation = themedData
                        ? r_msg2(cacheImageClass, "alloc", 0, 0, 0, 0) : 0;
                    replacement = replacementAllocation
                        ? r_msg2(replacementAllocation,
                                 "initWithData:uuid:validationToken:",
                                 themedData, stockUUID, publishedToken, 0)
                        : 0;
                    replacementCreated = replacement != 0 &&
                        remote_call_current_success();
                    if (!replacementCreated) {
                        if (!failure) failure = @"stock-api-replacement-create";
                        break;
                    }
                    expectedResponse = replacement;
                    expectedData = themedData;
                } else {
                    publishedTokenLength = tokenLength;
                }

                /* Always rewrite the exact generated unit. Even when a stock
                 * retry initially reads equal bytes, retain the established
                 * remove/write transaction and its explicit readback proof. */
                    uint64_t unitAllocation = r_msg2(
                        storeUnitClass, "alloc", 0, 0, 0, 0);
                    storeUnit = unitAllocation
                        ? r_msg2(unitAllocation, "initWithData:UUID:",
                                 expectedData, stockUUID, 0, 0)
                        : 0;
                    uint64_t unitValid = storeUnit
                        ? r_msg2(storeUnit, "isValid", 0, 0, 0, 0) : 0;
                    if (!storeUnit || (unitValid & 1U) == 0) {
                        failure = replacing
                            ? @"stock-api-replacement-store-unit"
                            : @"stock-api-restoration-store-unit";
                        break;
                    }

                    /* ISStore does not overwrite an already registered UUID.
                     * Remove that exact UUID first and prove it is absent
                     * before issuing the replacement write. */
                    if (stockUnit) {
                        directStoreRemoveIssued = YES;
                        uint64_t removed = r_msg2(
                            store, "removeUnitForUUID:", stockUUID, 0, 0, 0);
                        uint64_t removedReadback = (removed & 1U)
                            ? r_msg2(store, "unitForUUID:",
                                     stockUUID, 0, 0, 0)
                            : stockUnit;
                        directStoreRemoveVerified =
                            (removed & 1U) != 0 && removedReadback == 0;
                    } else {
                        directStoreRemoveVerified = YES;
                    }
                    if (!directStoreRemoveVerified) {
                        failure = @"stock-api-store-remove-readback";
                        break;
                    }

                    directStoreWriteIssued = YES;
                    uint64_t written = r_msg2(
                        store, "writeStoreUnit:", storeUnit, 0, 0, 0);
                    uint64_t unitReadback = r_msg2(
                        store, "unitForUUID:", stockUUID, 0, 0, 0);
                    uint64_t unitReadbackData = unitReadback
                        ? r_msg2(unitReadback, "data", 0, 0, 0, 0) : 0;
                    uint64_t unitReadbackUUID = unitReadback
                        ? r_msg2(unitReadback, "UUID", 0, 0, 0, 0) : 0;
                    directStoreWriteVerified = (written & 1U) != 0 &&
                        unitReadbackData && unitReadbackUUID &&
                        cnd_publisher_remote_objects_equal(
                            unitReadbackData, expectedData) &&
                        cnd_publisher_remote_objects_equal(
                            unitReadbackUUID, stockUUID);
                    if (!directStoreWriteVerified) {
                        /* A failed replacement write follows a verified
                         * removal. Recreate the captured stock unit before
                         * releasing any response identity objects. */
                        immediateStoreRollbackAttempted = YES;
                        {
                            uint64_t partialUnit = r_msg2(
                                store, "unitForUUID:", stockUUID, 0, 0, 0);
                            BOOL partialAbsent = partialUnit == 0;
                            if (partialUnit) {
                                uint64_t partialRemoved = r_msg2(
                                    store, "removeUnitForUUID:",
                                    stockUUID, 0, 0, 0);
                                uint64_t partialReadback =
                                    (partialRemoved & 1U)
                                    ? r_msg2(store, "unitForUUID:",
                                             stockUUID, 0, 0, 0)
                                    : partialUnit;
                                partialAbsent = (partialRemoved & 1U) != 0 &&
                                    partialReadback == 0;
                            }
                            uint64_t rollbackAllocation = partialAbsent
                                ? r_msg2(storeUnitClass, "alloc", 0, 0, 0, 0)
                                : 0;
                            rollbackUnit = rollbackAllocation
                                ? r_msg2(rollbackAllocation,
                                         "initWithData:UUID:",
                                         stockData, stockUUID, 0, 0)
                                : 0;
                            uint64_t rollbackValid = rollbackUnit
                                ? r_msg2(rollbackUnit, "isValid", 0, 0, 0, 0)
                                : 0;
                            uint64_t rollbackWritten =
                                rollbackUnit && (rollbackValid & 1U)
                                ? r_msg2(store, "writeStoreUnit:",
                                         rollbackUnit, 0, 0, 0)
                                : 0;
                            uint64_t rollbackReadback =
                                (rollbackWritten & 1U)
                                ? r_msg2(store, "unitForUUID:",
                                         stockUUID, 0, 0, 0)
                                : 0;
                            uint64_t rollbackData = rollbackReadback
                                ? r_msg2(rollbackReadback, "data",
                                         0, 0, 0, 0)
                                : 0;
                            uint64_t rollbackUUID = rollbackReadback
                                ? r_msg2(rollbackReadback, "UUID",
                                         0, 0, 0, 0)
                                : 0;
                            immediateStoreRollbackSucceeded =
                                (rollbackWritten & 1U) != 0 &&
                                rollbackData && rollbackUUID &&
                                cnd_publisher_remote_objects_equal(
                                    rollbackData, stockData) &&
                                cnd_publisher_remote_objects_equal(
                                    rollbackUUID, stockUUID);
                        }
                        failure = @"stock-api-store-write-readback";
                        break;
                    }
                    if (!replacing) stockGenerationPersisted = YES;

                if (replacing) {
                    NSString *indexFailure = nil;
                    persistentIndexTokenRewriteVerified =
                        cnd_publisher_rewrite_persistent_index_token(
                            managerCache, canonicalIcon, descriptor,
                            stockUUID, stockToken, publishedToken,
                            specification, persistentIndexScratch,
                            persistentIndexPageSize,
                            &persistentIndexTokenResult, &indexFailure);
                    if (!persistentIndexTokenRewriteVerified) {
                        /* Themed bytes are not durable while the index still
                         * carries an ordinary LaunchServices token. Restore
                         * the captured stock unit before returning failure;
                         * the index helper separately restores its token if
                         * its in-place write had already started. */
                        immediateStoreRollbackAttempted = YES;
                        uint64_t currentUnit = r_msg2(
                            store, "unitForUUID:", stockUUID, 0, 0, 0);
                        BOOL currentAbsent = currentUnit == 0;
                        if (currentUnit && remote_call_current_success()) {
                            uint64_t removed = r_msg2(
                                store, "removeUnitForUUID:",
                                stockUUID, 0, 0, 0);
                            uint64_t removedReadback = (removed & 1U)
                                ? r_msg2(store, "unitForUUID:",
                                         stockUUID, 0, 0, 0)
                                : currentUnit;
                            currentAbsent = (removed & 1U) != 0 &&
                                removedReadback == 0;
                        }
                        uint64_t rollbackAllocation = currentAbsent &&
                            remote_call_current_success()
                            ? r_msg2(storeUnitClass, "alloc", 0, 0, 0, 0)
                            : 0;
                        rollbackUnit = rollbackAllocation
                            ? r_msg2(rollbackAllocation,
                                     "initWithData:UUID:",
                                     stockData, stockUUID, 0, 0)
                            : 0;
                        uint64_t rollbackValid = rollbackUnit
                            ? r_msg2(rollbackUnit, "isValid", 0, 0, 0, 0)
                            : 0;
                        uint64_t rollbackWritten =
                            rollbackUnit && (rollbackValid & 1U)
                            ? r_msg2(store, "writeStoreUnit:",
                                     rollbackUnit, 0, 0, 0)
                            : 0;
                        uint64_t rollbackReadback =
                            (rollbackWritten & 1U)
                            ? r_msg2(store, "unitForUUID:",
                                     stockUUID, 0, 0, 0)
                            : 0;
                        uint64_t rollbackData = rollbackReadback
                            ? r_msg2(rollbackReadback, "data", 0, 0, 0, 0)
                            : 0;
                        uint64_t rollbackUUID = rollbackReadback
                            ? r_msg2(rollbackReadback, "UUID", 0, 0, 0, 0)
                            : 0;
                        immediateStoreRollbackSucceeded =
                            (rollbackWritten & 1U) != 0 &&
                            rollbackData && rollbackUUID &&
                            cnd_publisher_remote_objects_equal(
                                rollbackData, stockData) &&
                            cnd_publisher_remote_objects_equal(
                                rollbackUUID, stockUUID) &&
                            (!persistentIndexTokenResult.rollbackAttempted ||
                             persistentIndexTokenResult.rollbackVerified);
                        failure = indexFailure ?:
                            @"stock-api-persistent-index-token";
                        break;
                    }
                }

                (void)r_msg2(canonicalCache, "setImage:forDescriptor:",
                             expectedResponse, descriptor, 0, 0);
                uint64_t cacheReadback = r_msg2(
                    canonicalCache, "imageForDescriptor:",
                    descriptor, 0, 0, 0);
                uint64_t cacheData = cacheReadback
                    ? r_msg2(cacheReadback, "data", 0, 0, 0, 0) : 0;
                uint64_t cacheUUID = cacheReadback
                    ? r_msg2(cacheReadback, "uuid", 0, 0, 0, 0) : 0;
                uint64_t cacheToken = cacheReadback
                    ? r_msg2(cacheReadback, "validationToken", 0, 0, 0, 0)
                    : 0;
                cacheVerified = cacheData && cacheUUID && cacheToken &&
                    cnd_publisher_remote_objects_equal(
                        cacheData, expectedData) &&
                    cnd_publisher_remote_objects_equal(
                        cacheUUID, stockUUID) &&
                    cnd_publisher_remote_objects_equal(
                        cacheToken, publishedToken);
                uint64_t finalUnit = r_msg2(
                    store, "unitForUUID:", stockUUID, 0, 0, 0);
                uint64_t finalUnitData = finalUnit
                    ? r_msg2(finalUnit, "data", 0, 0, 0, 0) : 0;
                storeVerified = finalUnitData &&
                    cnd_publisher_remote_objects_equal(
                        finalUnitData, expectedData);
                replacementPublished = replacing &&
                    directStoreWriteVerified &&
                    persistentIndexTokenRewriteVerified &&
                    cacheVerified && storeVerified;
                if (!cacheVerified || !storeVerified) {
                    failure = @"stock-api-final-readback";
                    break;
                }

                NSData *stockBytes = cnd_publisher_copy_remote_data(
                    stockData,
                    CNDIconServicesPublisherMaximumStructuredDataLength);
                stockHash = cnd_publisher_sha256(stockBytes);
                NSData *stockTokenBytes = cnd_publisher_copy_remote_data(
                    stockToken, 4096U);
                stockValidationTokenHash = stockTokenBytes.length
                    ? cnd_publisher_sha256(stockTokenBytes) : @"";
                NSData *publishedTokenBytes =
                    cnd_publisher_copy_remote_data(publishedToken, 4096U);
                publishedValidationTokenHash = publishedTokenBytes.length
                    ? cnd_publisher_sha256(publishedTokenBytes) : @"";
            } while (0);

            if (persistentIndexScratchOwned && persistentIndexScratch &&
                remote_call_current_success()) {
                uint64_t scratchLength = batch.pageSize
                    ? batch.pageSize
                    : r_dlsym_call(R_TIMEOUT, "getpagesize",
                                   0, 0, 0, 0, 0, 0, 0, 0);
                int unmap = scratchLength
                    ? (int)r_dlsym_call(
                        R_TIMEOUT, "munmap", persistentIndexScratch,
                        scratchLength, 0, 0, 0, 0, 0, 0)
                    : -1;
                persistentIndexScratchLifecycleVerified = unmap == 0;
                if (unmap != 0 && !failure) {
                    failure = @"stock-api-persistent-index-scratch-unmap";
                }
            }

            uint64_t ownedObjects[] = {
                rollbackUnit, storeUnit, replacement, themedData, stockResponse,
                localIcon, targetBundle,
            };
            for (NSUInteger index = 0;
                 index < sizeof(ownedObjects) / sizeof(ownedObjects[0]);
                 index++) {
                if (ownedObjects[index] && remote_call_current_success()) {
                    (void)r_msg2(ownedObjects[index],
                                 "release", 0, 0, 0, 0);
                    releaseCount++;
                }
            }
            if (!borrowedBatchSession && descriptor &&
                remote_call_current_success()) {
                (void)r_msg2(descriptor, "release", 0, 0, 0, 0);
                releaseCount++;
            }
            if (pool && remote_call_current_success())
                (void)r_autorelease_pool_pop(pool);
            remoteOK = remote_call_current_success();
            transactionCleaned = remoteOK;
        });
    } @catch (NSException *exception) {
        failure = [NSString stringWithFormat:@"%@:%@",
            exception.name ?: @"exception",
            exception.reason ?: @"unknown"];
        remoteOK = NO;
        transactionCleaned = NO;
    }

    BOOL operationVerified = transactionStarted && stockCaptured &&
        stockGenerationPersisted && cacheVerified && storeVerified &&
        persistentIndexIdentitySettled &&
        persistentIndexTokenRewriteVerified &&
        persistentIndexScratchLifecycleVerified &&
        directStoreRemoveVerified &&
        directStoreWriteIssued &&
        directStoreWriteVerified &&
        (!replacing || borrowedBatchSession || stagingUnmapped) &&
        (!replacing ||
         (replacementCreated && replacementPublished));
    BOOL sessionRetained = borrowedBatchSession && remoteOK &&
        transactionCleaned && [session hasLocalState] &&
        session.pid == batch.pid;
    BOOL closed = NO;
    BOOL abandoned = NO;
    if (borrowedBatchSession) {
        batch.healthy = batch.healthy && sessionRetained;
        if (!sessionRetained && [session hasLocalState]) {
            [session abandonRemoteCall];
            abandoned = YES;
        }
    } else {
        if ([session hasLocalState] && remoteOK && transactionCleaned) {
            (void)[session destroyRemoteCall];
            closed = ![session hasLocalState];
        }
        if ([session hasLocalState]) {
            [session abandonRemoteCall];
            abandoned = YES;
        } else {
            closed = YES;
        }
    }
    BOOL lifecycleVerified = borrowedBatchSession
        ? sessionRetained : (closed && !abandoned);
    BOOL ok = operationVerified && remoteOK && transactionCleaned &&
        lifecycleVerified;
    NSString *expectedHash = replacing
        ? cnd_publisher_sha256(structuredImageData) : stockHash;
    NSDictionary *stockResponse = @{
        @"dataLength": @(stockDataLength),
        @"dataSHA256": stockHash ?: @"",
        @"uuid": stockUUIDText ?: @"",
        @"validationTokenLength": @(tokenLength),
        @"validationTokenSHA256": stockValidationTokenHash ?: @"",
        @"copiedToHost": @YES,
    };
    NSDictionary *cacheResponse = @{
        @"dataLength": @(replacing ? themedDataLength : stockDataLength),
        @"dataSHA256": expectedHash ?: @"",
        @"uuid": stockUUIDText ?: @"",
        @"validationTokenLength": @(publishedTokenLength),
        @"validationTokenSHA256": publishedValidationTokenHash ?: @"",
    };

    report[@"ok"] = @(ok);
    report[@"stage"] = ok
        ? (replacing ? @"published-stock-store"
                     : @"stock-restored-stock-store")
        : (failure ?: @"stock-api-lifecycle");
    report[@"message"] = ok
        ? (replacing
            ? @"Published and verified."
            : @"Restored stock and verified.")
        : [NSString stringWithFormat:
            @"The signed stock-API IconServices transaction failed at %@.",
            failure ?: @"lifecycle"];
    report[@"installed"] = @(replacing && replacementPublished);
    report[@"transactionPrepared"] = @YES;
    report[@"transactionStarted"] = @(transactionStarted);
    report[@"transactionObjectsReady"] = @(stockCaptured);
    report[@"transactionInstalled"] = @(operationVerified);
    report[@"transactionCleanupUsed"] = @NO;
    report[@"transactionCleaned"] = @(transactionCleaned);
    report[@"targetSideReleaseCount"] = @(releaseCount);
    report[@"payloadMatched"] = @NO;
    report[@"originalReturned"] = @(stockCaptured);
    report[@"hookRestored"] = @YES;
    report[@"hookQuiescent"] = @YES;
    report[@"hookStillInstalledAtCleanup"] = @NO;
    report[@"replacementCreated"] = @(replacementCreated);
    report[@"replacementReturned"] = @NO;
    report[@"replacementPublished"] = @(replacementPublished);
    report[@"stockDataLength"] = @(stockDataLength);
    report[@"themedDataLength"] = @(themedDataLength);
    report[@"observedDescriptorWidth"] = specification[@"pointWidth"];
    report[@"observedDescriptorHeight"] = specification[@"pointHeight"];
    report[@"observedDescriptorScale"] = specification[@"scale"];
    report[@"observedDescriptorAppearance"] = specification[@"appearance"];
    report[@"observedDescriptorIconVariant"] = specification[@"iconVariant"];
    report[@"observedDescriptorOptions"] = specification[@"options"];
    report[@"descriptorSpecification"] = specification;
    report[@"descriptorDiagnostics"] = descriptorDiagnostics ?: @{};
    report[@"stockUUIDPresentAtGeneration"] = @(stockCaptured);
    report[@"canonicalUUIDResolvedFromCache"] = @(cacheVerified);
    report[@"cacheIdentityBoundByDataAndToken"] = @(cacheVerified);
    report[@"mappingCleaned"] = @YES;
    report[@"remoteOK"] = @(remoteOK);
    report[@"closed"] = @(closed);
    report[@"abandoned"] = @(abandoned);
    report[@"sessionRetained"] = @(sessionRetained);
    report[@"sessionLifecycleVerified"] = @(lifecycleVerified);
    report[@"sessionLocalStateRemaining"] = @([session hasLocalState]);
    report[@"triggerVerified"] = @(operationVerified);
    report[@"stockCaptured"] = @(stockCaptured);
    report[@"agentCacheReadbackVerified"] = @(cacheVerified);
    report[@"persistentStoreReadbackVerified"] = @(
        storeVerified && persistentIndexIdentitySettled &&
        persistentIndexTokenRewriteVerified);
    report[@"operationCompleted"] = @(ok);
    report[@"transportHealthy"] = @(remoteOK);
    report[@"transportLifecycleVerified"] = @(lifecycleVerified);
    report[@"batchTransportBorrowed"] = @(borrowedBatchSession);
    report[@"transportRetained"] = @(sessionRetained);
    report[@"transportClosed"] = @(closed);
    report[@"transportAbandoned"] = @(abandoned);
    report[@"transportLocalStateRemaining"] = @([session hasLocalState]);
    report[@"payloadLifecycleVerified"] = @YES;
    report[@"payloadLifecycleRequired"] = @NO;
    report[@"payloadRetainedForBatch"] = @NO;
    report[@"stagingRetainedForBatch"] = @(stagingRetained);
    report[@"payloadPhysicallyUnmapped"] = @YES;
    report[@"stagingPhysicallyUnmapped"] = @(stagingUnmapped);
    report[@"verificationStatus"] = ok ? @"verified-stock-store" : @"failed";
    report[@"deepVerificationSkippedForBenchmark"] = @NO;
    report[@"acceptancePolicy"] = @"stock-iconservices-direct";
    report[@"legacyAcceptanceEligible"] = @NO;
    report[@"directStoreWriteIssued"] = @(directStoreWriteIssued);
    report[@"directStoreWriteVerified"] = @(directStoreWriteVerified);
    report[@"directStoreRemoveIssued"] = @(directStoreRemoveIssued);
    report[@"directStoreRemoveVerified"] = @(directStoreRemoveVerified);
    report[@"immediateStoreRollbackAttempted"] =
        @(immediateStoreRollbackAttempted);
    report[@"immediateStoreRollbackSucceeded"] =
        @(immediateStoreRollbackSucceeded);
    report[@"stockGenerationInitiallyPersisted"] =
        @(stockGenerationInitiallyPersisted);
    report[@"stockGenerationPersisted"] = @(stockGenerationPersisted);
    report[@"persistentIndexIdentitySettled"] =
        @(persistentIndexIdentitySettled);
    report[@"persistentIndexIdentityAttempts"] =
        @(persistentIndexIdentityAttempts);
    report[@"persistentIndexExistingMappingValidated"] =
        @(persistentIndexTokenResult.existingMappingValidated);
    report[@"persistentIndexRecordFound"] =
        @(persistentIndexTokenResult.recordFound);
    report[@"persistentIndexRecordValidated"] =
        @(persistentIndexTokenResult.recordValidated);
    report[@"persistentIndexTokenWriteIssued"] =
        @(persistentIndexTokenResult.writeIssued);
    report[@"persistentIndexTokenWriteFlushed"] =
        @(persistentIndexTokenResult.writeFlushed);
    report[@"persistentIndexTokenWriteVerified"] =
        @(persistentIndexTokenResult.writeVerified);
    report[@"persistentIndexTokenLookupVerified"] =
        @(persistentIndexTokenRewriteVerified);
    report[@"persistentIndexTokenRollbackAttempted"] =
        @(persistentIndexTokenResult.rollbackAttempted);
    report[@"persistentIndexTokenRollbackVerified"] =
        @(persistentIndexTokenResult.rollbackVerified);
    report[@"persistentIndexCandidatesInspected"] =
        @(persistentIndexTokenResult.candidatesInspected);
    report[@"persistentIndexTokenLookupAttempts"] =
        @(persistentIndexTokenResult.lookupAttempts);
    report[@"persistentIndexDataLength"] =
        @(persistentIndexTokenResult.indexDataLength);
    report[@"persistentIndexRecordAddress"] = [NSString stringWithFormat:
        @"0x%llx", persistentIndexTokenResult.recordAddress];
    report[@"persistentIndexScratchLifecycleVerified"] =
        @(persistentIndexScratchLifecycleVerified);
    report[@"persistentStoreDataLength"] = @(
        replacing ? themedDataLength : stockDataLength);
    report[@"persistentStoreDataSHA256"] = expectedHash ?: @"";
    report[@"expectedDataSHA256"] = expectedHash ?: @"";
    report[@"expectedDataSHA256Source"] = replacing
        ? @"local-themed-input" : @"generated-stock-response";
    report[@"validationTokenPolicy"] = replacing
        ? @"iconservices-always-valid" : @"stock-generated";
    report[@"stockResponse"] = stockResponse;
    report[@"agentCacheResponse"] = cacheResponse;
    report[@"wakeRequest"] = wake ?: @{};
    report[@"triggerRequest"] = @{
        @"submitted": @(transactionStarted),
        @"requestBoundary": @"stock-generate-then-indexed-store-write",
        @"ignoreCache": @YES,
        @"pointWidth": specification[@"pointWidth"],
        @"pointHeight": specification[@"pointHeight"],
        @"scale": specification[@"scale"],
        @"appearance": specification[@"appearance"],
        @"iconVariant": specification[@"iconVariant"],
        @"options": specification[@"options"],
    };
    report[@"durationSeconds"] = @(
        CFAbsoluteTimeGetCurrent() - startedAt);
    return report;
}

static NSDictionary<NSString *, id> *
cnd_publisher_run(NSString *bundleIdentifier,
                  NSData *structuredImageData,
                  NSDictionary<NSString *, NSNumber *> *
                      descriptorSpecification)
{
    NSDictionary *specification =
        cnd_publisher_normalized_descriptor_specification(
            descriptorSpecification);
    if (!specification) {
        return @{
            @"ok": @NO,
            @"stage": @"descriptor-specification",
            @"message": @"The IconServices descriptor specification is invalid.",
        };
    }
    /* The copied publisher callback is retained only by the explicit vPhone
     * research harness. Physical devices use the signed stock-store route. */
    if (!remote_call_lab_backend_opted_in()) {
        return cnd_publisher_run_stock_store(
            bundleIdentifier, structuredImageData, specification);
    }
    CFAbsoluteTime operationStartedAt = CFAbsoluteTimeGetCurrent();
    BOOL replacing = structuredImageData.length > 0;
    NSMutableDictionary *report = [@{
        @"ok": @NO,
        @"stage": @"preflight",
        @"message": @"IconServices publication did not start.",
        @"springBoardRemoteCallAttempted": @NO,
        @"spotlightRemoteCallAttempted": @NO,
        @"applicationBundleMutationAttempted": @NO,
    } mutableCopy];
    if (bundleIdentifier.length == 0) {
        report[@"message"] = @"The target bundle identifier is empty.";
        return report;
    }
    NSData *bundleUTF8 = [bundleIdentifier
        dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    if (bundleUTF8.length == 0 || bundleUTF8.length > 255) {
        report[@"stage"] = @"staging-input";
        report[@"message"] = @"The bundle identifier cannot be represented in the bounded publisher staging area.";
        return report;
    }
    NSUInteger stagingDataOffset =
        (bundleUTF8.length + 1U + 7U) & ~(NSUInteger)7U;
    BOOL transportCompressed = NO;
    int compressionResult = Z_OK;
    BOOL labTransport = remote_call_lab_backend_opted_in();
    BOOL compressionAttempted = replacing && labTransport &&
        structuredImageData.length >= 2048;
    CFAbsoluteTime compressionStartedAt = CFAbsoluteTimeGetCurrent();
    NSData *transportData = replacing && labTransport
        ? cnd_publisher_transport_data(
            structuredImageData, &transportCompressed, &compressionResult)
        : (replacing ? structuredImageData : [NSData data]);
    CFAbsoluteTime compressionFinishedAt = CFAbsoluteTimeGetCurrent();
    NSUInteger stagingTransferLength = stagingDataOffset +
        transportData.length;
    NSUInteger stagingDecodedOffset = transportCompressed
        ? (stagingTransferLength + 7U) & ~(NSUInteger)7U : 0;
    NSUInteger requiredStagingLength = transportCompressed
        ? stagingDecodedOffset + structuredImageData.length
        : stagingTransferLength;
    if (structuredImageData.length >
            CNDIconServicesPublisherMaximumStructuredDataLength ||
        requiredStagingLength >
            CNDIconServicesPublisherMaximumStagingCapacity) {
        report[@"stage"] = @"staging-input";
        report[@"message"] = @"The bundle identifier or structured icon exceeds the bounded publisher staging area.";
        return report;
    }
    NSMutableData *stagingTransfer = [NSMutableData
        dataWithLength:MAX((NSUInteger)1, stagingTransferLength)];
    memcpy(stagingTransfer.mutableBytes, bundleUTF8.bytes, bundleUTF8.length);
    if (transportData.length) {
        memcpy((uint8_t *)stagingTransfer.mutableBytes + stagingDataOffset,
               transportData.bytes, transportData.length);
    }

    CNDIconServicesPublisherBatchState *batch = cnd_publisher_batch_state();
    BOOL borrowedBatchSession = batch.session != nil;
    NSDictionary *wake = borrowedBatchSession ? batch.wake : nil;
    RemoteCallSession *session = borrowedBatchSession ? batch.session : nil;
    if (borrowedBatchSession &&
        (!batch.healthy || ![session hasLocalState] || session.pid != batch.pid)) {
        report[@"stage"] = @"batch-session";
        report[@"message"] = @"The pinned iconservicesagent batch session is not healthy.";
        return report;
    }

    if (!session) {
        /* Prefer an already-resident agent. If none exists, use the read-only
         * cache-configuration request so waking the service cannot generate,
         * invalidate, or garbage-collect icon records. */
        NSError *wakeError = nil;
        wake = cnd_publisher_wake_agent_without_generation(
            bundleIdentifier, &wakeError);
        if (!wake) {
            report[@"stage"] = @"agent-wake";
            report[@"message"] = wakeError.localizedDescription ?:
                @"IconServices is not resident and could not be made resident.";
            return report;
        }
        NSError *sessionError = nil;
        session = cnd_publisher_open_agent_session(
            bundleIdentifier, &sessionError);
        if (!session) {
            report[@"stage"] = @"remote-session";
            report[@"message"] = sessionError.localizedDescription ?:
                @"The single iconservicesagent session could not be opened.";
            return report;
        }
    }
    report[@"agentPID"] = @(session.pid);
    report[@"batchSessionBorrowed"] = @(borrowedBatchSession);
    report[@"descriptorSpecification"] = specification;

    __block BOOL installed = NO;
    __block BOOL cleaned = NO;
    __block BOOL remoteOK = NO;
    __block BOOL hookStillInstalled = NO;
    __block uint64_t remoteBase = 0;
    __block uint64_t mappingLength = 0;
    __block uint64_t contextAddress = 0;
    __block uint64_t generationMethod = 0;
    __block uint64_t originalIMP = 0;
    __block uint64_t targetBundle = 0;
    __block uint64_t themedData = 0;
    __block uint64_t descriptorTemplate = 0;
    __block size_t payloadExecuteOffset = 0;
    __block size_t payloadCleanupOffset = 0;
    __block uint64_t stagingRemoteBase = 0;
    __block uint64_t stagingCapacity = 0;
    __block BOOL reusedBatchPayload = NO;
    __block BOOL reusedBatchStaging = NO;
    __block BOOL payloadRetainedForBatch = NO;
    __block BOOL stagingRetainedForBatch = NO;
    __block BOOL payloadPhysicallyUnmapped = NO;
    __block BOOL stagingPhysicallyUnmapped = NO;
    __block BOOL transactionPrepared = NO;
    __block BOOL transactionCleanupUsed = NO;
    __block CNDIconServicesPublisherPayloadContext observed = {0};
    __block NSString *setupFailure = nil;
    __block uint64_t triggerResponse = 0;
    __block NSUInteger completionPollAttempts = 0;
    __block BOOL usedCachedABI = NO;
    __block BOOL usedCachedContext = NO;
    __block BOOL descriptorPreparedInPayload = NO;
    __block uint64_t descriptorPreparationBits = 0;
    __block CFAbsoluteTime setupFinishedAt = operationStartedAt;
    __block CFAbsoluteTime triggerFinishedAt = operationStartedAt;

    @try {
        remote_call_with_session_suppressing_result_logs(session, ^{
            do {
                BOOL cachedABI = borrowedBatchSession &&
                    batch.publisherABIReady;
                uint64_t pool = cachedABI ? 0 : r_autorelease_pool_push();
                if (!cachedABI && !pool) {
                    setupFailure = @"remote-autorelease-pool";
                    break;
                }
                usedCachedABI = cachedABI;
                /*
                 * We are already executing inside iconservicesagent.  Its
                 * IconServices classes are therefore a stronger readiness
                 * proof than calling dlopen() again.  On a physical device a
                 * target-side dlopen can wait on dyld state owned by another
                 * daemon thread and never return to the synthetic exception
                 * boundary.
                 */
                uint64_t requestClass = cachedABI
                    ? batch.requestClass : r_class("ISGenerationRequest");
                BOOL framework = requestClass != 0;
                uint64_t zlibUncompress = cachedABI
                    ? batch.zlibUncompress
                    : (transportCompressed
                        ? cnd_publisher_remote_library_symbol(
                            "/usr/lib/libz.1.dylib", "uncompress")
                        : 0);
                uint64_t selector = cachedABI ? 0 : r_sel(
                    "generateImageReturningRecordIdentifiers:");
                generationMethod = cachedABI
                    ? batch.generationMethod
                    : (requestClass && selector
                    ? r_dlsym_call(R_TIMEOUT, "class_getInstanceMethod",
                        requestClass, selector, 0, 0, 0, 0, 0, 0)
                    : 0);
                uint64_t typesAddress = !cachedABI && generationMethod
                    ? r_dlsym_call(R_TIMEOUT, "method_getTypeEncoding",
                        generationMethod, 0, 0, 0, 0, 0, 0, 0)
                    : 0;
                char types[64] = {0};
                BOOL exactABI = cachedABI ||
                    (typesAddress &&
                     r_read_cstring(typesAddress, types, sizeof(types)) &&
                     strcmp(types, "@24@0:8^@16") == 0);
                uint64_t currentIMP = exactABI
                    ? r_dlsym_call(R_TIMEOUT, "method_getImplementation",
                        generationMethod, 0, 0, 0, 0, 0, 0, 0)
                    : 0;
                originalIMP = cachedABI
                    ? batch.originalGenerate : currentIMP;
                if (cachedABI) {
                    exactABI = currentIMP &&
                        cnd_publisher_strip_code_pointer(currentIMP) ==
                        cnd_publisher_strip_code_pointer(originalIMP);
                }
                uint64_t cacheClass = cachedABI
                    ? batch.cacheImageClass : r_class("IFCacheImage");
                uint64_t iconClass = cachedABI
                    ? batch.iconClass : r_class("ISBundleIdentifierIcon");
                uint64_t descriptorClass = cachedABI
                    ? batch.descriptorClass : r_class("ISImageDescriptor");
                uint64_t imageClass = cachedABI
                    ? batch.imageClass : r_class("IFImage");
                uint64_t imageCacheClass = cachedABI
                    ? batch.imageCacheClass : r_class("ISImageCache");
                uint64_t stringClass = cachedABI
                    ? batch.stringClass : r_class("NSString");
                uint64_t dataClass = cachedABI
                    ? batch.dataClass : r_class("NSData");
                BOOL publicationABI = requestClass && iconClass &&
                    descriptorClass && imageClass && imageCacheClass &&
                    cacheClass && stringClass && dataClass &&
                    (cachedABI ||
                    (cnd_publisher_remote_class_method_has_types(
                        descriptorClass,
                        "imageDescriptorWithIconVariant:options:",
                        "@24@0:8i16i20", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        descriptorClass, "copy", "@16@0:8", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        descriptorClass, "setSize:",
                        "v32@0:8{CGSize=dd}16", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        descriptorClass, "setScale:",
                        "v24@0:8d16", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        descriptorClass, "setAppearance:",
                        "v24@0:8q16", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        descriptorClass, "setVariantOptions:",
                        "v24@0:8Q16", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        descriptorClass, "setIgnoreCache:",
                        "v20@0:8B16", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        requestClass, "icon", "@16@0:8", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        requestClass, "imageDescriptor", "@16@0:8", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        iconClass, "bundleIdentifier", "@16@0:8", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        iconClass, "imageCache", "@16@0:8", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        descriptorClass, "size",
                        "{CGSize=dd}16@0:8", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        descriptorClass, "scale", "d16@0:8", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        descriptorClass, "appearance", "q16@0:8", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        descriptorClass, "variantOptions", "Q16@0:8", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        imageClass, "data", "@16@0:8", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        imageClass, "uuid", "@16@0:8", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        imageClass, "validationToken", "@16@0:8", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        imageCacheClass, "imageForDescriptor:",
                        "@24@0:8@16", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        cacheClass, "initWithData:uuid:validationToken:",
                        "@40@0:8@16@24@32", NULL)));
                NSString *descriptorSpecificationKey =
                    cnd_publisher_descriptor_specification_key(specification);
                descriptorTemplate = borrowedBatchSession
                    ? cnd_publisher_cached_descriptor(
                        batch, descriptorSpecificationKey) : 0;
                if (!framework ||
                    (transportCompressed && !zlibUncompress) ||
                    !exactABI || !publicationABI || !originalIMP) {
                    setupFailure = @"iconservices-agent-abi-or-objects";
                    if (pool && remote_call_current_success())
                        (void)r_autorelease_pool_pop(pool);
                    break;
                }

                const uint8_t *payload = NULL;
                size_t payloadLength = 0, contextOffset = 0;
                size_t probeOffset = 0, prepareDescriptorOffset = 0;
                size_t installOffset = 0;
                size_t generateOffset = 0, triggerOffset = 0;
                size_t executeOffset = 0, cleanupOffset = 0;
                if (!cnd_publisher_local_payload(
                        &payload, &payloadLength, &contextOffset,
                        &probeOffset, &prepareDescriptorOffset,
                        &installOffset, &generateOffset,
                        &triggerOffset, &executeOffset, &cleanupOffset)) {
                    setupFailure = @"publisher-payload-layout";
                    if (pool) (void)r_autorelease_pool_pop(pool);
                    break;
                }

                CNDIconServicesPublisherPayloadContext context = {0};
                BOOL cachedContext = cachedABI &&
                    batch.payloadContextTemplate.length == sizeof(context);
                usedCachedContext = cachedContext;
                if (cachedContext) {
                    memcpy(&context, batch.payloadContextTemplate.bytes,
                           sizeof(context));
                } else {
                    context.magic = CND_ICON_PUBLISHER_PAYLOAD_MAGIC;
                    context.version = CND_ICON_PUBLISHER_PAYLOAD_VERSION;
                    context.objcMsgSend = cnd_publisher_remote_symbol(
                        "objc_msgSend");
                    context.methodSetImplementation =
                        cnd_publisher_remote_symbol(
                            "method_setImplementation");
                    context.objcAutoreleasePoolPush =
                        cnd_publisher_remote_symbol(
                            "objc_autoreleasePoolPush");
                    context.objcAutoreleasePoolPop =
                        cnd_publisher_remote_symbol(
                            "objc_autoreleasePoolPop");
                }
                context.generationMethod = generationMethod;
                context.originalGenerate = originalIMP;
                context.cacheImageClass = cacheClass;
                context.iconClass = iconClass;
                context.descriptorClass = descriptorClass;
                context.descriptorTemplate = descriptorTemplate;
                context.stringClass = stringClass;
                context.dataClass = dataClass;
                context.zlibUncompress = zlibUncompress;
                context.replaceResponse = replacing ? 1 : 0;
                context.expectedWidth =
                    [specification[@"pointWidth"] doubleValue];
                context.expectedHeight =
                    [specification[@"pointHeight"] doubleValue];
                context.expectedScale =
                    [specification[@"scale"] doubleValue];
                context.expectedAppearance =
                    [specification[@"appearance"] unsignedLongLongValue];
                context.expectedIconVariant =
                    [specification[@"iconVariant"] unsignedLongLongValue];
                context.expectedOptions =
                    [specification[@"options"] unsignedLongLongValue];
                context.descriptorPrepared = descriptorTemplate ? 1 : 0;
                context.descriptorPreparationBits = descriptorTemplate
                    ? (CND_ICON_PUBLISHER_DESCRIPTOR_POOL_READY |
                       CND_ICON_PUBLISHER_DESCRIPTOR_FACTORY_READY |
                       CND_ICON_PUBLISHER_DESCRIPTOR_FACTORY_RETURNED |
                       CND_ICON_PUBLISHER_DESCRIPTOR_COPIED |
                       CND_ICON_PUBLISHER_DESCRIPTOR_CONFIGURED |
                       CND_ICON_PUBLISHER_DESCRIPTOR_VERIFIED)
                    : 0;
                if (!context.objcMsgSend ||
                    !context.methodSetImplementation ||
                    !context.objcAutoreleasePoolPush ||
                    !context.objcAutoreleasePoolPop ||
                    (!cachedContext &&
                     !cnd_publisher_set_selectors(&context))) {
                    setupFailure = @"publisher-payload-context";
                    if (pool) (void)r_autorelease_pool_pop(pool);
                    break;
                }

                uint64_t pageSize = cachedABI
                    ? batch.pageSize
                    : r_dlsym_call(
                        R_TIMEOUT, "getpagesize", 0, 0, 0, 0, 0, 0, 0, 0);
                if (pageSize < 4096 ||
                    (pageSize & (pageSize - 1)) != 0) {
                    setupFailure = @"target-page-size";
                    if (pool) (void)r_autorelease_pool_pop(pool);
                    break;
                }
                BOOL splitLayout = contextOffset >= pageSize &&
                    contextOffset % pageSize == 0 &&
                    contextOffset +
                        CND_ICON_PUBLISHER_PAYLOAD_CONTEXT_CAPACITY <=
                        payloadLength &&
                    probeOffset < contextOffset &&
                    prepareDescriptorOffset < contextOffset &&
                    installOffset < contextOffset &&
                    generateOffset < contextOffset &&
                    triggerOffset < contextOffset &&
                    executeOffset < contextOffset &&
                    cleanupOffset < contextOffset;
                if (!splitLayout) {
                    setupFailure = @"publisher-code-context-page-layout";
                    if (pool) (void)r_autorelease_pool_pop(pool);
                    break;
                }

                uint64_t requiredStaging = MAX(
                    (uint64_t)1, (uint64_t)requiredStagingLength);
                BOOL canReuseStaging = borrowedBatchSession &&
                    batch.stagingRemoteBase &&
                    batch.stagingCapacity >= requiredStaging;
                if (canReuseStaging) {
                    stagingRemoteBase = batch.stagingRemoteBase;
                    stagingCapacity = batch.stagingCapacity;
                    reusedBatchStaging = YES;
                } else {
                    if (borrowedBatchSession && batch.stagingRemoteBase &&
                        batch.stagingCapacity) {
                        int oldUnmap = (int)r_dlsym_call(
                            R_TIMEOUT, "munmap", batch.stagingRemoteBase,
                            batch.stagingCapacity, 0, 0, 0, 0, 0, 0);
                        if (oldUnmap != 0) {
                            setupFailure = @"publisher-staging-grow-unmap";
                            if (pool) (void)r_autorelease_pool_pop(pool);
                            break;
                        }
                        batch.stagingRemoteBase = 0;
                        batch.stagingCapacity = 0;
                    }
                    uint64_t desired = MAX(
                        (uint64_t)CNDIconServicesPublisherDefaultStagingCapacity,
                        requiredStaging);
                    stagingCapacity =
                        (desired + pageSize - 1) & ~(pageSize - 1);
                    if (stagingCapacity >
                        CNDIconServicesPublisherMaximumStagingCapacity) {
                        setupFailure = @"publisher-staging-capacity";
                        if (pool) (void)r_autorelease_pool_pop(pool);
                        break;
                    }
                    stagingRemoteBase = r_dlsym_call(
                        R_TIMEOUT, "mmap", 0, stagingCapacity,
                        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
                        (uint64_t)-1, 0, 0, 0);
                    if (!stagingRemoteBase ||
                        stagingRemoteBase == UINT64_MAX) {
                        setupFailure = @"publisher-staging-mmap";
                        if (pool) (void)r_autorelease_pool_pop(pool);
                        break;
                    }
                    if (borrowedBatchSession) {
                        batch.stagingRemoteBase = stagingRemoteBase;
                        batch.stagingCapacity = stagingCapacity;
                    }
                }
                if (!cnd_publisher_prefault_remote_write_range(
                        stagingRemoteBase, stagingTransfer.length)) {
                    setupFailure = @"publisher-staging-prefault";
                    if (pool) (void)r_autorelease_pool_pop(pool);
                    break;
                }
                if (!remote_write(stagingRemoteBase,
                                  stagingTransfer.bytes,
                                  stagingTransfer.length)) {
                    setupFailure = @"publisher-staging-write";
                    if (pool) (void)r_autorelease_pool_pop(pool);
                    break;
                }
                context.stagingAddress = stagingRemoteBase;
                context.stagingCapacity = stagingCapacity;
                context.stagingBundleLength = bundleUTF8.length;
                context.stagingDataOffset = stagingDataOffset;
                context.stagingDataLength = transportData.length;
                context.stagingDecodedOffset = stagingDecodedOffset;
                context.stagingDecodedLength = structuredImageData.length;
                context.stagingCompressed = transportCompressed ? 1 : 0;
                BOOL canReusePayload = borrowedBatchSession &&
                    batch.payloadReady && batch.payloadRemoteBase &&
                    batch.payloadMappingLength &&
                    batch.payloadContextOffset == contextOffset &&
                    batch.payloadProbeOffset == probeOffset &&
                    batch.payloadPrepareDescriptorOffset ==
                        prepareDescriptorOffset &&
                    batch.payloadInstallOffset == installOffset &&
                    batch.payloadGenerateOffset == generateOffset &&
                    batch.payloadTriggerOffset == triggerOffset &&
                    batch.payloadExecuteOffset == executeOffset &&
                    batch.payloadCleanupOffset == cleanupOffset;
                uint64_t probe = 0;
                if (canReusePayload) {
                    reusedBatchPayload = YES;
                    remoteBase = batch.payloadRemoteBase;
                    mappingLength = batch.payloadMappingLength;
                    contextAddress = batch.payloadContextAddress;
                    context.replacementGenerate =
                        remoteBase + generateOffset;
                    probe = remote_write(
                        contextAddress, &context, sizeof(context))
                        ? (CND_ICON_PUBLISHER_PAYLOAD_MAGIC ^
                           CND_ICON_PUBLISHER_PAYLOAD_VERSION)
                        : 0;
                } else {
                    mappingLength =
                        (payloadLength + pageSize - 1) & ~(pageSize - 1);
                    BOOL protected = NO;
                    if (remote_call_uses_lab_backend()) {
                        /* The explicit vPhone harness accepts copied code and
                         * does not expose cross-task remap. */
                        remoteBase = r_dlsym_call(
                            R_TIMEOUT, "mmap", 0, mappingLength,
                            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
                            (uint64_t)-1, 0, 0, 0);
                        if (!remoteBase || remoteBase == UINT64_MAX) {
                            setupFailure = @"publisher-payload-lab-mmap";
                            if (pool) (void)r_autorelease_pool_pop(pool);
                            break;
                        }
                        contextAddress = remoteBase + contextOffset;
                        context.replacementGenerate =
                            remoteBase + generateOffset;
                        NSMutableData *patched = [NSMutableData
                            dataWithBytes:payload length:payloadLength];
                        memcpy((uint8_t *)patched.mutableBytes + contextOffset,
                               &context, sizeof(context));
                        NSMutableData *readback = [NSMutableData
                            dataWithLength:payloadLength];
                        BOOL payloadPrefaulted =
                            cnd_publisher_prefault_remote_write_range(
                                remoteBase, patched.length);
                        BOOL copied = payloadPrefaulted && remote_write(
                            remoteBase, patched.bytes, patched.length) &&
                            remote_read(remoteBase, readback.mutableBytes,
                                        readback.length) &&
                            [readback isEqualToData:patched];
                        (void)r_dlsym_call(
                            R_TIMEOUT, "sys_icache_invalidate",
                            remoteBase, contextOffset,
                            0, 0, 0, 0, 0, 0);
                        protected = copied && (int)r_dlsym_call(
                            R_TIMEOUT, "mprotect", remoteBase, contextOffset,
                            PROT_READ | PROT_EXEC,
                            0, 0, 0, 0, 0) == 0;
                    } else {
                        NSString *mappingFailure = nil;
                        protected = cnd_publisher_map_physical_payload(
                            payload, payloadLength, pageSize,
                            contextOffset, generateOffset, &context,
                            &remoteBase, &mappingLength, &mappingFailure);
                        contextAddress = protected
                            ? remoteBase + contextOffset : 0;
                        if (!protected) {
                            setupFailure = mappingFailure ?:
                                @"publisher-vnode-map";
                            if (pool) (void)r_autorelease_pool_pop(pool);
                            break;
                        }
                    }
                    probe = protected
                        ? do_remote_call_stable_addr(
                            R_TIMEOUT, remoteBase + probeOffset,
                            "cnd_icon_publisher_payload_probe",
                            0, 0, 0, 0, 0, 0, 0, 0)
                        : 0;
                    if (borrowedBatchSession &&
                        probe == (CND_ICON_PUBLISHER_PAYLOAD_MAGIC ^
                                  CND_ICON_PUBLISHER_PAYLOAD_VERSION)) {
                        batch.payloadRemoteBase = remoteBase;
                        batch.payloadMappingLength = mappingLength;
                        batch.payloadContextAddress = contextAddress;
                        batch.payloadContextOffset = contextOffset;
                        batch.payloadProbeOffset = probeOffset;
                        batch.payloadPrepareDescriptorOffset =
                            prepareDescriptorOffset;
                        batch.payloadInstallOffset = installOffset;
                        batch.payloadGenerateOffset = generateOffset;
                        batch.payloadTriggerOffset = triggerOffset;
                        batch.payloadExecuteOffset = executeOffset;
                        batch.payloadCleanupOffset = cleanupOffset;
                        batch.payloadReady = YES;
                    }
                }
                uint64_t expectedProbe = CND_ICON_PUBLISHER_PAYLOAD_MAGIC ^
                    CND_ICON_PUBLISHER_PAYLOAD_VERSION;
                if (probe == expectedProbe && !descriptorTemplate &&
                    remote_call_current_success()) {
                    uint64_t preparedDescriptor =
                        do_remote_call_stable_addr(
                            R_TIMEOUT,
                            remoteBase + prepareDescriptorOffset,
                            "cnd_icon_publisher_payload_prepare_descriptor",
                            0, 0, 0, 0, 0, 0, 0, 0);
                    CNDIconServicesPublisherPayloadContext preparedContext =
                        {0};
                    BOOL descriptorReadback = contextAddress &&
                        remote_read(contextAddress, &preparedContext,
                                    sizeof(preparedContext));
                    if (descriptorReadback) {
                        context = preparedContext;
                        descriptorTemplate =
                            preparedContext.descriptorTemplate;
                        descriptorPreparationBits =
                            preparedContext.descriptorPreparationBits;
                        descriptorPreparedInPayload =
                            preparedContext.descriptorPrepared == 1 &&
                            preparedDescriptor == descriptorTemplate &&
                            descriptorTemplate != 0;
                    }
                    if (!descriptorPreparedInPayload &&
                        remote_call_current_success()) {
                        setupFailure = @"publisher-descriptor-prepare";
                    }
                } else if (descriptorTemplate) {
                    descriptorPreparationBits =
                        context.descriptorPreparationBits;
                    descriptorPreparedInPayload =
                        context.descriptorPrepared == 1;
                }
                payloadExecuteOffset = executeOffset;
                payloadCleanupOffset = cleanupOffset;
                transactionPrepared = probe == expectedProbe &&
                    descriptorPreparedInPayload && descriptorTemplate &&
                    remote_call_current_success();
                if (transactionPrepared && borrowedBatchSession && !cachedABI) {
                    batch.publisherABIReady = YES;
                    batch.requestClass = requestClass;
                    batch.generationMethod = generationMethod;
                    batch.originalGenerate = originalIMP;
                    batch.cacheImageClass = cacheClass;
                    batch.iconClass = iconClass;
                    batch.descriptorClass = descriptorClass;
                    batch.imageClass = imageClass;
                    batch.imageCacheClass = imageCacheClass;
                    batch.stringClass = stringClass;
                    batch.dataClass = dataClass;
                    batch.objcMsgSend = context.objcMsgSend;
                    batch.methodSetImplementation =
                        context.methodSetImplementation;
                    batch.objcAutoreleasePoolPush =
                        context.objcAutoreleasePoolPush;
                    batch.objcAutoreleasePoolPop =
                        context.objcAutoreleasePoolPop;
                    batch.zlibUncompress = zlibUncompress;
                    batch.pageSize = pageSize;
                    cnd_publisher_cache_descriptor(
                        batch, descriptorSpecificationKey,
                        descriptorTemplate);
                    batch.payloadContextTemplate = [NSData
                        dataWithBytes:&context length:sizeof(context)];
                } else if (transactionPrepared && borrowedBatchSession) {
                    cnd_publisher_cache_descriptor(
                        batch, descriptorSpecificationKey,
                        descriptorTemplate);
                }
                if (!transactionPrepared && !setupFailure)
                    setupFailure = @"publisher-transaction-prepare";
                if (pool && remote_call_current_success())
                    (void)r_autorelease_pool_pop(pool);
            } while (0);
            remoteOK = remote_call_current_success();
        });
    } @catch (NSException *exception) {
        setupFailure = [NSString stringWithFormat:@"%@:%@",
            exception.name ?: @"exception",
            exception.reason ?: @"unknown"];
        remoteOK = NO;
    }
    setupFinishedAt = CFAbsoluteTimeGetCurrent();

    __block NSError *triggerError = nil;
    __block NSDictionary *trigger = nil;
    if (transactionPrepared && remoteOK) {
        @try {
            remote_call_with_session_suppressing_result_logs(session, ^{
                triggerResponse = remoteBase && payloadExecuteOffset
                    ? do_remote_call_stable_addr(
                        R_TIMEOUT, remoteBase + payloadExecuteOffset,
                        "cnd_icon_publisher_payload_execute",
                        0, 0, 0, 0, 0, 0, 0, 0)
                    : 0;
                BOOL submitted = triggerResponse != 0 &&
                    remote_call_current_success();
                trigger = @{
                    @"submitted": @(submitted),
                    @"requestBoundary":
                        @"in-agent staged publisher transaction",
                    @"ignoreCache": @YES,
                    @"pointWidth": specification[@"pointWidth"],
                    @"pointHeight": specification[@"pointHeight"],
                    @"scale": specification[@"scale"],
                    @"appearance": specification[@"appearance"],
                    @"iconVariant": specification[@"iconVariant"],
                    @"options": specification[@"options"],
                    @"localResponseReadAttempted": @NO,
                    @"remoteResponse": @(triggerResponse != 0),
                    @"retainedResponse": @(triggerResponse != 0),
                    @"collapsedRemoteRoundTrips": @YES,
                    @"reusableStaging": @YES,
                    @"targetSideObjectConstruction": @YES,
                };
                if (!submitted) {
                    triggerError = cnd_publisher_error(
                        5, @"The in-agent publisher payload did not return a retained IconServices response.");
                }
                remoteOK = remote_call_current_success();
            });
        } @catch (NSException *exception) {
            triggerError = cnd_publisher_error(
                6, [NSString stringWithFormat:
                    @"The in-agent IconServices request raised %@: %@",
                    exception.name ?: @"an exception",
                    exception.reason ?: @"unknown reason"]);
            remoteOK = NO;
        }
    }
    triggerFinishedAt = CFAbsoluteTimeGetCurrent();

    @try {
        remote_call_with_session_suppressing_result_logs(session, ^{
            if (!remote_call_current_success()) {
                remoteOK = NO;
                return;
            }
            if (contextAddress) {
                (void)remote_read(contextAddress, &observed,
                                  sizeof(observed));
                for (NSUInteger attempt = 0;
                     !(observed.matched && observed.hookRestored &&
                       observed.inFlight == 0) && attempt < 60;
                     attempt++) {
                    // generateImageWithDescriptor: is synchronous. Once the
                    // hooked original returned and no invocation remains in
                    // flight, a non-match cannot become a later match; the
                    // old loop merely burned roughly four seconds before
                    // reporting the descriptor mismatch.
                    if (observed.originalReturned &&
                        observed.inFlight == 0) break;
                    completionPollAttempts++;
                    usleep(50000);
                    (void)remote_read(contextAddress, &observed,
                                      sizeof(observed));
                }
            }
            installed = observed.transactionInstalled == 1;
            targetBundle = observed.targetBundle;
            themedData = observed.themedData;
            uint64_t current = generationMethod
                ? r_dlsym_call(R_TIMEOUT, "method_getImplementation",
                    generationMethod, 0, 0, 0, 0, 0, 0, 0)
                : 0;
            uint64_t payloadIMP = remoteBase
                ? remoteBase +
                    ((size_t)((const uint8_t *)
                        cnd_icon_publisher_payload_generate -
                        cnd_publisher_payload_section_start))
                : 0;
            BOOL currentIsOriginal = current &&
                cnd_publisher_strip_code_pointer(current) ==
                    cnd_publisher_strip_code_pointer(originalIMP);
            BOOL currentIsPayload = current && payloadIMP &&
                cnd_publisher_strip_code_pointer(current) ==
                    cnd_publisher_strip_code_pointer(payloadIMP);
            BOOL payloadWasCurrent = currentIsPayload;
            hookStillInstalled = currentIsPayload;
            if (currentIsPayload) {
                (void)r_dlsym_call(R_TIMEOUT, "method_setImplementation",
                    generationMethod, originalIMP, 0, 0, 0, 0, 0, 0);
                current = r_dlsym_call(
                    R_TIMEOUT, "method_getImplementation",
                    generationMethod, 0, 0, 0, 0, 0, 0, 0);
                hookStillInstalled =
                    cnd_publisher_strip_code_pointer(current) !=
                        cnd_publisher_strip_code_pointer(originalIMP);
                currentIsOriginal = !hookStillInstalled;
            }
            for (NSUInteger attempt = 0;
                 contextAddress && observed.inFlight && attempt < 20;
                 attempt++) {
                usleep(25000);
                (void)remote_read(contextAddress, &observed,
                                  sizeof(observed));
            }
            BOOL methodStayedOriginal = !generationMethod || !originalIMP ||
                currentIsOriginal;
            BOOL neverInstalled = !installed && !payloadWasCurrent &&
                methodStayedOriginal && observed.matched == 0 &&
                observed.inFlight == 0;
            // Once the stock IMP is read back and no copied invocation remains
            // in flight, the payload mapping is removable even when the target
            // request never matched. Requiring a successful match here caused
            // an ordinary trigger failure to abandon a now-unreferenced map.
            BOOL quiescentOriginal = currentIsOriginal &&
                observed.inFlight == 0;
            BOOL safeToRemove = !hookStillInstalled &&
                (quiescentOriginal || neverInstalled);
            if (safeToRemove) {
                uint64_t cleanupResult = remoteBase && payloadCleanupOffset
                    ? do_remote_call_stable_addr(
                        R_TIMEOUT, remoteBase + payloadCleanupOffset,
                        "cnd_icon_publisher_payload_cleanup",
                        0, 0, 0, 0, 0, 0, 0, 0)
                    : 0;
                transactionCleanupUsed = cleanupResult > 0 &&
                    remote_call_current_success();
                if (transactionCleanupUsed && contextAddress) {
                    CNDIconServicesPublisherPayloadContext postCleanup = {0};
                    if (remote_read(contextAddress, &postCleanup,
                                    sizeof(postCleanup))) {
                        observed.transactionCleaned =
                            postCleanup.transactionCleaned;
                        observed.cleanupReleaseCount =
                            postCleanup.cleanupReleaseCount;
                    }
                }
            }
            if (safeToRemove && !transactionCleanupUsed) {
                uint64_t retainedObjects[] = {
                    triggerResponse,
                    observed.capturedReplacement,
                    observed.capturedStockToken,
                    observed.capturedStockUUID,
                    observed.capturedStockData,
                    observed.capturedDescriptor,
                    observed.capturedIcon,
                    themedData,
                    targetBundle,
                };
                for (NSUInteger index = 0;
                     index < sizeof(retainedObjects) /
                        sizeof(retainedObjects[0]); index++) {
                    if (retainedObjects[index]) {
                        (void)r_msg2(retainedObjects[index],
                                     "release", 0, 0, 0, 0);
                    }
                }
            }
            if (safeToRemove) {
                targetBundle = 0;
                themedData = 0;
            }
            BOOL keepBatchPayload = borrowedBatchSession &&
                batch.payloadReady &&
                batch.payloadRemoteBase == remoteBase &&
                batch.payloadMappingLength == mappingLength;
            if (safeToRemove && descriptorTemplate &&
                (!borrowedBatchSession ||
                 !cnd_publisher_batch_owns_descriptor(
                     batch, descriptorTemplate))) {
                (void)r_msg2(descriptorTemplate, "release", 0, 0, 0, 0);
                descriptorTemplate = 0;
            }
            int unmap = safeToRemove && remoteBase && mappingLength &&
                !keepBatchPayload
                ? (int)r_dlsym_call(R_TIMEOUT, "munmap", remoteBase,
                    mappingLength, 0, 0, 0, 0, 0, 0)
                : -1;
            BOOL keepBatchStaging = borrowedBatchSession &&
                batch.stagingRemoteBase == stagingRemoteBase &&
                batch.stagingCapacity == stagingCapacity;
            payloadRetainedForBatch = keepBatchPayload;
            stagingRetainedForBatch = keepBatchStaging;
            int stagingUnmap = safeToRemove && stagingRemoteBase &&
                stagingCapacity && !keepBatchStaging
                ? (int)r_dlsym_call(
                    R_TIMEOUT, "munmap", stagingRemoteBase,
                    stagingCapacity, 0, 0, 0, 0, 0, 0)
                : -1;
            cleaned = safeToRemove &&
                (keepBatchPayload || !remoteBase || unmap == 0) &&
                (keepBatchStaging || !stagingRemoteBase ||
                 stagingUnmap == 0) &&
                (transactionCleanupUsed || !transactionPrepared) &&
                remote_call_current_success();
            payloadPhysicallyUnmapped = !remoteBase ||
                (safeToRemove && !keepBatchPayload && unmap == 0);
            stagingPhysicallyUnmapped = !stagingRemoteBase ||
                (safeToRemove && !keepBatchStaging && stagingUnmap == 0);
            remoteOK = remote_call_current_success();
        });
    } @catch (NSException *exception) {
        setupFailure = [NSString stringWithFormat:@"cleanup:%@:%@",
            exception.name ?: @"exception",
            exception.reason ?: @"unknown"];
        remoteOK = NO;
    }

    BOOL closed = NO;
    BOOL abandoned = NO;
    BOOL sessionRetained = borrowedBatchSession && remoteOK && cleaned &&
        [session hasLocalState] && session.pid == batch.pid;
    if (borrowedBatchSession) {
        batch.healthy = batch.healthy && sessionRetained;
        if (!sessionRetained && [session hasLocalState]) {
            [session abandonRemoteCall];
            abandoned = YES;
        }
    } else {
        if ([session hasLocalState] && remoteOK && cleaned) {
            (void)[session destroyRemoteCall];
            closed = ![session hasLocalState];
        }
        if ([session hasLocalState]) {
            [session abandonRemoteCall];
            abandoned = YES;
        } else {
            closed = YES;
        }
    }

    BOOL stockCaptured = observed.stockDataLength > 0;
    BOOL agentCacheReadbackVerified = NO;
    BOOL persistentStoreReadbackVerified = NO;
    NSDictionary *stockResponse = @{
        @"dataLength": @(observed.stockDataLength),
        @"uuidPresentAtGeneration":
            @(observed.capturedStockUUID != 0),
        @"copiedToHost": @NO,
    };
    NSDictionary *cacheResponse = @{};
    NSString *expectedHash = replacing
        ? cnd_publisher_sha256(structuredImageData) : @"";
    BOOL triggerVerified = [trigger[@"submitted"] boolValue] &&
        observed.matched == 1 &&
        observed.originalReturned == 1 && observed.hookRestored == 1 &&
        (replacing
            ? (observed.replacementCreated == 1 &&
               observed.replacementReturned == 1)
            : (observed.replacementCreated == 0 &&
               observed.replacementReturned == 0));
    BOOL compressedTransportVerified = transportCompressed
        ? (observed.decompressionAttempted == 1 &&
           observed.decompressionSucceeded == 1 &&
           observed.decompressionResult == Z_OK &&
           observed.decompressedDataLength == structuredImageData.length)
        : (observed.decompressionAttempted == 0);
    BOOL decompressionFailed = transportCompressed &&
        observed.decompressionAttempted == 1 &&
        observed.decompressionSucceeded == 0;
    BOOL minimalPayloadVerified = observed.magic ==
            CND_ICON_PUBLISHER_PAYLOAD_MAGIC &&
        observed.version == CND_ICON_PUBLISHER_PAYLOAD_VERSION &&
        observed.transactionStarted == 1 &&
        observed.transactionObjectsReady == 1 &&
        observed.transactionInstalled == 1 &&
        observed.transactionCleaned == 1 &&
        compressedTransportVerified &&
        observed.matched == 1 && observed.originalReturned == 1 &&
        observed.hookRestored == 1 && observed.stockDataLength > 0 &&
        (replacing
            ? (observed.replacementCreated == 1 &&
               observed.replacementReturned == 1 &&
               observed.themedDataLength == structuredImageData.length)
            : (observed.replacementCreated == 0 &&
               observed.replacementReturned == 0 &&
               observed.themedDataLength == 0));
    BOOL payloadVerified = minimalPayloadVerified;
    BOOL lifecycleVerified = borrowedBatchSession
        ? sessionRetained : (closed && !abandoned);
    BOOL hookQuiescent = observed.inFlight == 0;
    BOOL payloadLifecycleVerified = cleaned && hookQuiescent &&
        !hookStillInstalled &&
        (!transactionPrepared || observed.transactionCleaned == 1);
    BOOL ok = installed && remoteOK && cleaned && lifecycleVerified &&
        payloadVerified && triggerVerified;

    report[@"ok"] = @(ok);
    report[@"stage"] = ok
        ? (replacing ? @"published-unverified-benchmark"
                     : @"stock-restored-unverified-benchmark")
        : (decompressionFailed ? @"transport-decompression"
           : [setupFailure isEqual:@"publisher-descriptor-prepare"]
                ? @"publisher-descriptor-prepare"
           : !installed ? @"hook-install"
           : ![trigger[@"submitted"] boolValue]
                ? @"automatic-generation-trigger"
           : observed.matched == 0 ? @"request-target-mismatch"
           : @"publisher-lifecycle");
    report[@"message"] = ok
        ? @"The one-shot publisher and cleanup completed. Cache/store readback proof is unavailable, so SnowBoard Remix may accept this result only under its legacy provisional policy."
        : (decompressionFailed
            ? [NSString stringWithFormat:
                @"iconservicesagent rejected the zlib transport payload (status=%lld expected=%lu observed=%llu).",
                (long long)observed.decompressionResult,
                (unsigned long)structuredImageData.length,
                (unsigned long long)observed.decompressedDataLength]
           : triggerError.localizedDescription ?:
           setupFailure ?:
           @"The one-shot publisher or its cleanup did not complete cleanly.");
    report[@"mode"] = replacing ? @"replace" : @"stock";
    report[@"installed"] = @(installed);
    report[@"transactionPrepared"] = @(transactionPrepared);
    report[@"transactionStarted"] = @(observed.transactionStarted == 1);
    report[@"transactionObjectsReady"] =
        @(observed.transactionObjectsReady == 1);
    report[@"transactionInstalled"] =
        @(observed.transactionInstalled == 1);
    report[@"transactionCleanupUsed"] = @(transactionCleanupUsed);
    report[@"transactionCleaned"] = @(observed.transactionCleaned == 1);
    report[@"targetSideReleaseCount"] = @(observed.cleanupReleaseCount);
    report[@"transportCompressionAttempted"] = @(compressionAttempted);
    report[@"transportCompressed"] = @(transportCompressed);
    report[@"transportCompressionAlgorithm"] =
        transportCompressed ? @"zlib" : @"raw";
    report[@"transportCompressionResult"] = @(compressionResult);
    report[@"transportOriginalBytes"] = @(structuredImageData.length);
    report[@"transportEncodedBytes"] = @(transportData.length);
    report[@"transportBytesSaved"] = @(
        structuredImageData.length >= transportData.length
            ? structuredImageData.length - transportData.length : 0);
    report[@"transportCompressionRatio"] = @(
        structuredImageData.length
            ? (double)transportData.length /
                (double)structuredImageData.length : 1.0);
    report[@"transportCompressionSeconds"] = @(
        compressionFinishedAt - compressionStartedAt);
    report[@"targetDecompressionAttempted"] =
        @(observed.decompressionAttempted == 1);
    report[@"targetDecompressionSucceeded"] =
        @(observed.decompressionSucceeded == 1);
    report[@"targetDecompressionResult"] =
        @(observed.decompressionResult);
    report[@"targetDecompressedBytes"] =
        @(observed.decompressedDataLength);
    report[@"compressedTransportVerified"] =
        @(compressedTransportVerified);
    report[@"payloadMatched"] = @(observed.matched == 1);
    report[@"originalReturned"] = @(observed.originalReturned == 1);
    report[@"hookRestored"] = @(observed.hookRestored == 1);
    report[@"hookQuiescent"] = @(observed.inFlight == 0);
    report[@"replacementCreated"] = @(observed.replacementCreated == 1);
    report[@"replacementReturned"] = @(observed.replacementReturned == 1);
    report[@"stockDataLength"] = @(observed.stockDataLength);
    report[@"themedDataLength"] = @(observed.themedDataLength);
    report[@"matchDiagnostics"] = @(observed.matchDiagnostics);
    report[@"observedDescriptorWidth"] = @(observed.observedWidth);
    report[@"observedDescriptorHeight"] = @(observed.observedHeight);
    report[@"observedDescriptorScale"] = @(observed.observedScale);
    report[@"observedDescriptorAppearance"] =
        @(observed.observedAppearance);
    report[@"observedDescriptorIconVariant"] =
        @(observed.observedIconVariant);
    report[@"observedDescriptorOptions"] = @(observed.observedOptions);
    report[@"stockUUIDPresentAtGeneration"] =
        @(observed.capturedStockUUID != 0);
    report[@"canonicalUUIDResolvedFromCache"] = @NO;
    report[@"cacheIdentityBoundByDataAndToken"] = @NO;
    report[@"hookStillInstalledAtCleanup"] = @(hookStillInstalled);
    report[@"mappingCleaned"] = @(cleaned);
    report[@"remoteOK"] = @(remoteOK);
    report[@"closed"] = @(closed);
    report[@"abandoned"] = @(abandoned);
    report[@"sessionRetained"] = @(sessionRetained);
    report[@"sessionLifecycleVerified"] = @(lifecycleVerified);
    report[@"sessionLocalStateRemaining"] = @([session hasLocalState]);
    report[@"triggerVerified"] = @(triggerVerified);
    report[@"stockCaptured"] = @(stockCaptured);
    report[@"agentCacheReadbackVerified"] =
        @(agentCacheReadbackVerified);
    report[@"persistentStoreReadbackVerified"] =
        @(persistentStoreReadbackVerified);
    report[@"operationCompleted"] = @(ok);
    /*
     * Normalized transport/lifecycle adapter. Keep the historical keys above
     * for diagnostics and older consumers, but contract validators consume
     * only these transport-neutral names.
     */
    report[@"transportHealthy"] = @(remoteOK);
    report[@"transportLifecycleVerified"] = @(lifecycleVerified);
    report[@"batchTransportBorrowed"] = @(borrowedBatchSession);
    report[@"transportRetained"] = @(sessionRetained);
    report[@"transportClosed"] = @(closed);
    report[@"transportAbandoned"] = @(abandoned);
    report[@"transportLocalStateRemaining"] =
        @([session hasLocalState]);
    report[@"payloadLifecycleVerified"] = @(payloadLifecycleVerified);
    report[@"payloadRetainedForBatch"] = @(payloadRetainedForBatch);
    report[@"stagingRetainedForBatch"] = @(stagingRetainedForBatch);
    report[@"payloadPhysicallyUnmapped"] = @(payloadPhysicallyUnmapped);
    report[@"stagingPhysicallyUnmapped"] = @(stagingPhysicallyUnmapped);
    report[@"verificationStatus"] = ok ? @"unverified-benchmark" : @"failed";
    report[@"deepVerificationSkippedForBenchmark"] = @YES;
    /*
     * Compatibility policy consumed by the SnowBoard Remix coordinator, not
     * by the strict publisher validators. This preserves the pre-contract
     * apply behavior while keeping the missing cache/store proof explicit.
     */
    report[@"acceptancePolicy"] = @"legacy-remote-call-provisional";
    report[@"legacyAcceptanceEligible"] = @(ok);
    report[@"compactVerificationEnabled"] = @NO;
    report[@"compactInAgentVerification"] = @NO;
    report[@"compactVerificationSucceeded"] = @NO;
    report[@"compactVerificationBits"] = @0;
    report[@"compactVerificationRequiredBits"] = @0;
    report[@"verificationExpectedDataLength"] = @0;
    report[@"verificationResponseDataLength"] = @0;
    report[@"verificationResponseTokenLength"] = @0;
    report[@"persistentStorePath"] = @"";
    report[@"persistentStoreDataLength"] = @0;
    report[@"persistentStoreDataSHA256"] = @"";
    report[@"localResponseReadAttempted"] = @NO;
    report[@"triggerResponsePresent"] = @(triggerResponse != 0);
    report[@"triggerResponseIdentityBound"] = @NO;
    report[@"canonicalResponseSource"] = @"";
    report[@"expectedDataSHA256"] = expectedHash;
    report[@"expectedDataSHA256Source"] = replacing
        ? @"local-themed-input" : @"not-copied";
    report[@"stockResponse"] = stockResponse;
    report[@"agentCacheResponse"] = cacheResponse;
    report[@"wakeRequest"] = wake ?: @{};
    report[@"triggerRequest"] = trigger ?: @{};
    CFAbsoluteTime operationFinishedAt = CFAbsoluteTimeGetCurrent();
    report[@"setupSeconds"] = @(setupFinishedAt - operationStartedAt);
    report[@"triggerSeconds"] = @(triggerFinishedAt - setupFinishedAt);
    report[@"verificationSeconds"] =
        @(operationFinishedAt - triggerFinishedAt);
    report[@"durationSeconds"] =
        @(operationFinishedAt - operationStartedAt);
    report[@"completionPollAttempts"] = @(completionPollAttempts);
    report[@"storePollAttempts"] = @0;
    report[@"requestCacheReadAttempts"] = @0;
    report[@"batchABIReused"] = @(usedCachedABI);
    report[@"batchContextReused"] = @(usedCachedContext);
    report[@"descriptorPreparedInPayload"] =
        @(descriptorPreparedInPayload);
    report[@"descriptorPreparationBits"] =
        @(descriptorPreparationBits);
    report[@"descriptorMainThreadDispatchAvoided"] = @YES;
    report[@"batchPayloadReused"] = @(reusedBatchPayload);
    report[@"batchStagingReused"] = @(reusedBatchStaging);
    report[@"stagingCapacity"] = @(stagingCapacity);
    report[@"stagingTransferBytes"] = @(stagingTransfer.length);
    report[@"stagingRequiredBytes"] = @(requiredStagingLength);
    report[@"targetSidePerIconTransaction"] = @YES;
    report[@"collapsedTriggerRemoteRoundTrips"] = @YES;
    return report;
}

static NSString *cnd_publisher_copy_remote_indexed_identifier(
    uint64_t identifier)
{
    if (!r_is_objc_ptr(identifier)) return @"";
    uint64_t identifierClass = r_dlsym_call(
        R_TIMEOUT, "object_getClass", identifier, 0, 0, 0, 0, 0, 0, 0);
    if (!identifierClass || !cnd_publisher_remote_method_has_types(
            identifierClass, "getUUIDBytes:", "v24@0:8[16C]16",
            "v24@0:8^C16")) return @"";

    /*
     * Do not send UUIDString here. On physical arm64e that object-returning
     * method exits through a PAC-authenticated completion which RemoteCall
     * reports as an unexpected synthetic completion. Publication invokes
     * this helper once per descriptor, so the ostensibly diagnostic getter
     * polluted the pinned transaction with one exception per store write.
     * Copy the documented sixteen UUID bytes instead and format them locally.
     */
    uint8_t bytes[16] = {0};
    uint64_t remoteBytes = r_dlsym_call(
        R_TIMEOUT, "malloc", sizeof(bytes), 0, 0, 0, 0, 0, 0, 0);
    BOOL copied = remoteBytes &&
        remote_write(remoteBytes, bytes, sizeof(bytes));
    if (copied) {
        (void)r_msg2(identifier, "getUUIDBytes:",
                     remoteBytes, 0, 0, 0);
        copied = remote_call_current_success() &&
            remote_read(remoteBytes, bytes, sizeof(bytes));
    }
    if (remoteBytes && remote_call_current_success()) r_free(remoteBytes);
    if (!copied) return @"";

    char text[37] = {0};
    snprintf(text, sizeof(text),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
             "%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5], bytes[6], bytes[7],
             bytes[8], bytes[9], bytes[10], bytes[11],
             bytes[12], bytes[13], bytes[14], bytes[15]);
    return [NSString stringWithUTF8String:text] ?: @"";
}

/* Physical RemoteCall cannot reliably create a shared mapping for the tiny
 * nano-zone allocation used by cnd_publisher_copy_remote_indexed_identifier.
 * The applied-state audit already owns a pinned session with one anonymous,
 * resident RW scratch page. Keep these observation-only copies on that page
 * so a failed 16-byte mapping cannot poison the remaining store/source reads
 * for the descriptor. Publication deliberately continues using its existing
 * helper and staging lifecycle. */
static NSString *cnd_publisher_audit_copy_indexed_identifier(
    uint64_t identifier, uint64_t scratch)
{
    if (!r_is_objc_ptr(identifier) || !scratch) return @"";
    uint64_t identifierClass = r_dlsym_call(
        R_TIMEOUT, "object_getClass", identifier, 0, 0, 0, 0, 0, 0, 0);
    char methodTypes[96] = {0};
    BOOL uuidBytesABI = identifierClass &&
        cnd_publisher_copy_remote_method_types(
            identifierClass, "getUUIDBytes:", NO,
            methodTypes, sizeof(methodTypes)) &&
        (!strcmp(methodTypes, "v24@0:8[16C]16") ||
         !strcmp(methodTypes, "v24@0:8^C16") ||
         /* iOS 26's Swift-backed __NSConcreteUUID override uses char *. */
         !strcmp(methodTypes, "v24@0:8*16"));
    if (!uuidBytesABI) return @"";

    (void)r_msg2(identifier, "getUUIDBytes:", scratch, 0, 0, 0);
    uint8_t bytes[16] = {0};
    if (!remote_call_current_success() ||
        !remote_read(scratch, bytes, sizeof(bytes))) return @"";

    char text[37] = {0};
    snprintf(text, sizeof(text),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
             "%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5], bytes[6], bytes[7],
             bytes[8], bytes[9], bytes[10], bytes[11],
             bytes[12], bytes[13], bytes[14], bytes[15]);
    return [NSString stringWithUTF8String:text] ?: @"";
}

static NSData *cnd_publisher_audit_copy_small_remote_data(
    uint64_t object, NSUInteger maximumLength, uint64_t scratch)
{
    if (!object || !maximumLength ||
        maximumLength > CNDIconServicesPublisherMaximumPersistentIdentifierLength ||
        !scratch) return nil;
    uint64_t responds = r_sel("respondsToSelector:");
    uint64_t lengthSelector = r_sel("length");
    uint64_t bytesSelector = r_sel("bytes");
    if (!responds || !lengthSelector || !bytesSelector ||
        !r_msg2(object, "respondsToSelector:",
                lengthSelector, 0, 0, 0) ||
        !r_msg2(object, "respondsToSelector:",
                bytesSelector, 0, 0, 0)) return nil;
    uint64_t length = r_msg2(object, "length", 0, 0, 0, 0);
    uint64_t bytes = length && length <= maximumLength
        ? r_msg2(object, "bytes", 0, 0, 0, 0) : 0;
    uint64_t copied = bytes && remote_call_current_success()
        ? r_dlsym_call(R_TIMEOUT, "memcpy", scratch, bytes, length,
                       0, 0, 0, 0, 0)
        : 0;
    if (copied != scratch || !remote_call_current_success()) return nil;
    NSMutableData *result = [NSMutableData dataWithLength:(NSUInteger)length];
    return remote_read(scratch, result.mutableBytes, result.length)
        ? result : nil;
}

/* File-backed NSData bytes cannot always be remapped into Cyanide with
 * mach_vm_map. Copy them inside the target into the already-resident audit
 * page, then read that page in bounded chunks. This is observation-only and
 * avoids both a target nano allocation and a direct cross-task mapping of the
 * IconServices store file. */
static NSData *cnd_publisher_audit_copy_remote_data(
    uint64_t object, NSUInteger maximumLength, uint64_t scratch)
{
    if (!object || !maximumLength || !scratch) return nil;
    uint64_t responds = r_sel("respondsToSelector:");
    uint64_t lengthSelector = r_sel("length");
    uint64_t bytesSelector = r_sel("bytes");
    if (!responds || !lengthSelector || !bytesSelector ||
        !r_msg2(object, "respondsToSelector:",
                lengthSelector, 0, 0, 0) ||
        !r_msg2(object, "respondsToSelector:",
                bytesSelector, 0, 0, 0)) return nil;

    uint64_t remoteLength = r_msg2(object, "length", 0, 0, 0, 0);
    if (!remoteLength || remoteLength > maximumLength ||
        remoteLength > NSUIntegerMax) return nil;
    uint64_t bytes = r_msg2(object, "bytes", 0, 0, 0, 0);
    if (!bytes || !remote_call_current_success()) return nil;

    NSUInteger length = (NSUInteger)remoteLength;
    NSMutableData *result = [NSMutableData dataWithLength:length];
    for (NSUInteger offset = 0; offset < length; ) {
        NSUInteger chunk = MIN(
            CNDIconServicesPublisherAuditCopyChunkLength, length - offset);
        if (UINT64_MAX - bytes < offset) return nil;
        uint64_t copied = r_dlsym_call(
            R_TIMEOUT, "memcpy", scratch, bytes + offset, chunk,
            0, 0, 0, 0, 0);
        if (copied != scratch || !remote_call_current_success() ||
            !remote_read(scratch,
                         (uint8_t *)result.mutableBytes + offset, chunk)) {
            return nil;
        }
        offset += chunk;
    }
    return result;
}

/* Resolve only IPSW-verified object ivars. The name lives on the pinned page
 * because r_alloc_str's tiny nano-zone allocation is unreliable under the
 * physical RemoteCall backend. object_getIvar performs a direct non-weak load
 * on this build and therefore avoids property return-value machinery. */
static uint64_t cnd_publisher_audit_instance_ivar(
    uint64_t object, const char *name, uint64_t expectedOffset,
    uint64_t scratch)
{
    size_t nameLength = name ? strlen(name) + 1 : 0;
    if (!r_is_objc_ptr(object) || !nameLength || nameLength > 128 ||
        !expectedOffset || !scratch ||
        !remote_write(scratch, name, nameLength)) return 0;
    uint64_t cls = r_dlsym_call(
        R_TIMEOUT, "object_getClass", object, 0, 0, 0, 0, 0, 0, 0);
    uint64_t ivar = cls ? r_dlsym_call(
        R_TIMEOUT, "class_getInstanceVariable", cls, scratch,
        0, 0, 0, 0, 0, 0) : 0;
    uint64_t offset = ivar ? r_dlsym_call(
        R_TIMEOUT, "ivar_getOffset", ivar, 0, 0, 0, 0, 0, 0, 0) : 0;
    return ivar && offset == expectedOffset && remote_call_current_success()
        ? ivar : 0;
}

static uint64_t cnd_publisher_audit_object_ivar(
    uint64_t object, const char *name, uint64_t expectedOffset,
    uint64_t scratch)
{
    uint64_t ivar = cnd_publisher_audit_instance_ivar(
        object, name, expectedOffset, scratch);
    return ivar ? r_dlsym_call(
        R_TIMEOUT, "object_getIvar", object, ivar,
        0, 0, 0, 0, 0, 0) : 0;
}

/* Open the daemon's persistent UUID -> LaunchServices source table once for
 * this read-only audit batch. ISIconManager.iconCache is an ISIconCache; the
 * unitSourceRegistry getter belongs to the daemon-only ISMutableIconCache
 * retained by IconCacheService, so asking the manager cache for that getter
 * is an ownership error. iOS 26's verified ISMutableIconCache initializer
 * constructs this exact table at <cacheURL>/store-source-registry.map with
 * capacity 4000. The audit first proves that file exists, then retains one
 * ISStoreMapTable until finishBatch; it invokes no mutating map selectors. */
static uint64_t cnd_publisher_source_registry_map(
    CNDIconServicesPublisherBatchState *batch,
    uint64_t managerCache, uint64_t scratch, NSString **failureOut)
{
    if (failureOut) *failureOut = nil;
    if (!batch || !managerCache || !scratch) {
        if (failureOut) *failureOut = @"audit-source-registry-input";
        return 0;
    }
    if (batch.auditSourceRegistry) return batch.auditSourceRegistry;

    uint64_t cacheClass = r_dlsym_call(
        R_TIMEOUT, "object_getClass", managerCache, 0, 0, 0, 0, 0, 0, 0);
    uint64_t mapClass = r_class("ISStoreMapTable");
    uint64_t dataClass = r_class("NSData");
    uint64_t fileManagerClass = r_class("NSFileManager");
    BOOL fixedABI = cacheClass && mapClass && dataClass && fileManagerClass &&
        cnd_publisher_remote_method_has_types(
            mapClass, "initWithURL:capacity:",
            "@32@0:8@16Q24", NULL) &&
        cnd_publisher_remote_method_has_types(
            mapClass, "dataForUUID:", "@24@0:8@16", NULL) &&
        cnd_publisher_remote_class_method_has_types(
            dataClass, "_ISMutableStoreIndex_mappedDataWithURL:",
            "@24@0:8@16", NULL) &&
        cnd_publisher_remote_class_method_has_types(
            fileManagerClass, "defaultManager", "@16@0:8", NULL);
    if (!fixedABI || !remote_call_current_success()) {
        if (failureOut) *failureOut = @"audit-source-registry-fixed-abi";
        return 0;
    }

    /* 23A341 ISIconCache._cacheURL is a strong NSURL * at +0x18. Its public
     * getter is an objc_getProperty thunk and is not a safe synthetic-call
     * completion boundary on the physical backend. */
    uint64_t cacheURL = cnd_publisher_audit_object_ivar(
        managerCache, "_cacheURL", 0x18, scratch);
    uint64_t cacheURLClass = cacheURL ? r_dlsym_call(
        R_TIMEOUT, "object_getClass", cacheURL, 0, 0, 0, 0, 0, 0, 0) : 0;
    BOOL urlABI = cacheURLClass &&
        cnd_publisher_remote_method_has_types(
            cacheURLClass, "URLByAppendingPathComponent:isDirectory:",
            "@28@0:8@16B24", NULL) &&
        cnd_publisher_remote_method_has_types(
            cacheURLClass, "path", "@16@0:8", NULL);
    if (!urlABI || !remote_call_current_success()) {
        if (failureOut) *failureOut = @"audit-source-registry-url-abi";
        return 0;
    }

    uint64_t registryName =
        r_nsstr_retained("store-source-registry.map");
    uint64_t registryURL = registryName
        ? r_msg2(cacheURL, "URLByAppendingPathComponent:isDirectory:",
                 registryName, 0, 0, 0)
        : 0;
    if (registryName && remote_call_current_success()) {
        (void)r_msg2(registryName, "release", 0, 0, 0, 0);
    }
    uint64_t registryPath = registryURL
        ? r_msg2(registryURL, "path", 0, 0, 0, 0) : 0;
    uint64_t fileManager = registryPath
        ? r_msg2(fileManagerClass, "defaultManager", 0, 0, 0, 0) : 0;
    uint64_t fileManagerObjectClass = fileManager ? r_dlsym_call(
        R_TIMEOUT, "object_getClass", fileManager, 0, 0, 0, 0, 0, 0, 0) : 0;
    BOOL fileABI = fileManagerObjectClass &&
        cnd_publisher_remote_method_has_types(
            fileManagerObjectClass, "fileExistsAtPath:",
            "B24@0:8@16", NULL);
    BOOL registryExists = fileABI &&
        (r_msg2(fileManager, "fileExistsAtPath:",
                registryPath, 0, 0, 0) & 1U);
    if (!registryExists || !remote_call_current_success()) {
        if (failureOut) *failureOut = fileABI
            ? @"audit-source-registry-file-missing"
            : @"audit-source-registry-file-abi";
        return 0;
    }

    /* ISStoreMapTable.data lazily creates and backs a new map whenever its
     * mapped data is absent or invalid. Validate the existing file first and
     * inject that exact mapping into the transient table so dataForUUID:
     * cannot enter the create/repair branch during this read-only audit. */
    uint64_t mappedData = r_msg2(
        dataClass, "_ISMutableStoreIndex_mappedDataWithURL:",
        registryURL, 0, 0, 0);
    uint64_t mappedDataClass = mappedData ? r_dlsym_call(
        R_TIMEOUT, "object_getClass", mappedData, 0, 0, 0, 0, 0, 0, 0) : 0;
    BOOL mappedDataABI = mappedDataClass &&
        cnd_publisher_remote_method_has_types(
            mappedDataClass, "_ISStoreIndex_isValid", "B16@0:8", NULL);
    BOOL mappedDataValid = mappedDataABI &&
        (r_msg2(mappedData, "_ISStoreIndex_isValid", 0, 0, 0, 0) & 1U);
    if (!mappedDataValid || !remote_call_current_success()) {
        if (failureOut) *failureOut = mappedDataABI
            ? @"audit-source-registry-invalid"
            : @"audit-source-registry-map-abi";
        return 0;
    }

    uint64_t allocation = r_msg2(mapClass, "alloc", 0, 0, 0, 0);
    uint64_t map = allocation
        ? r_msg2(allocation, "initWithURL:capacity:",
                 registryURL, 4000, 0, 0)
        : 0;
    if (!map || !remote_call_current_success()) {
        if (failureOut) *failureOut = @"audit-source-registry-open";
        return 0;
    }
    uint64_t dataIvar = cnd_publisher_audit_instance_ivar(
        map, "_data", 0x10, scratch);
    if (!dataIvar) {
        (void)r_msg2(map, "release", 0, 0, 0, 0);
        if (failureOut) *failureOut = @"audit-source-registry-data-ivar";
        return 0;
    }
    (void)r_dlsym_call(
        R_TIMEOUT, "object_setIvar", map, dataIvar, mappedData,
        0, 0, 0, 0, 0);
    uint64_t injectedData = remote_call_current_success()
        ? r_dlsym_call(
            R_TIMEOUT, "object_getIvar", map, dataIvar,
            0, 0, 0, 0, 0, 0)
        : 0;
    if (injectedData != mappedData || !remote_call_current_success()) {
        if (remote_call_current_success()) {
            (void)r_msg2(map, "release", 0, 0, 0, 0);
        }
        if (failureOut) *failureOut =
            @"audit-source-registry-data-injection";
        return 0;
    }
    batch.auditSourceRegistry = map;
    return batch.auditSourceRegistry;
}

/* Observation-only state classifier for an already-published descriptor. It
 * creates transient descriptor/icon/LaunchServices objects, reads the
 * persistent source-registry map, and invokes cache/store readers. The
 * manager's synchronized findOrRegisterIcon: lookup can temporarily add a
 * fresh icon to its weak registry when no equal canonical object exists; the
 * audit reports that probe explicitly. It intentionally contains no image
 * generation, cache purge, presentation reload, persistent remove, or write. */
static NSDictionary<NSString *, id> *cnd_publisher_audit_variant(
    NSString *bundleIdentifier,
    NSDictionary<NSString *, NSNumber *> *descriptorSpecification)
{
    CNDIconServicesPublisherBatchState *batch = cnd_publisher_batch_state();
    RemoteCallSession *session = batch.session;
    if (!batch || !batch.healthy || !session ||
        ![session hasLocalState] || session.pid != batch.pid) {
        return @{
            @"ok": @NO,
            @"stage": @"batch-session",
            @"message": @"The applied-state audit requires a healthy pinned iconservicesagent batch.",
        };
    }
    if (!cnd_publisher_valid_bundle_identifier(bundleIdentifier) ||
        !cnd_publisher_normalized_descriptor_specification(
            descriptorSpecification)) {
        return @{
            @"ok": @NO,
            @"stage": @"audit-input",
            @"message": @"The applied-state audit requires a valid bundle and descriptor specification.",
        };
    }

    __block BOOL remoteOK = NO;
    __block BOOL abiReady = NO;
    __block BOOL descriptorReady = NO;
    __block BOOL canonicalCacheReadReady = NO;
    __block BOOL storeIndexLookupReady = NO;
    __block BOOL storeIndexEntryPresent = NO;
    __block BOOL cacheResponsePresent = NO;
    __block BOOL storeUnitPresent = NO;
    __block BOOL storeUnitValid = NO;
    __block BOOL cacheStoreEqual = NO;
    __block BOOL cacheStoreIdentifierEqual = NO;
    __block BOOL cacheStoreValidationTokenEqual = NO;
    __block BOOL storeIndexUnitIdentifierEqual = NO;
    __block BOOL sourceIdentityAuditReady = NO;
    __block BOOL sourceRegistryDataPresent = NO;
    __block BOOL currentSourceIdentifierPresent = NO;
    __block BOOL sourceIdentityMatchesCurrentRecord = NO;
    __block NSUInteger sourceRegistryEntryCount = 0;
    __block uint64_t canonicalIconPointer = 0;
    __block uint64_t canonicalImageCachePointer = 0;
    __block NSData *cacheData = nil;
    __block NSData *storeData = nil;
    __block NSData *validationTokenData = nil;
    __block NSData *storeValidationTokenData = nil;
    __block NSData *sourceRegistryData = nil;
    __block NSData *currentSourceIdentifierData = nil;
    __block NSString *cacheIdentifier = @"";
    __block NSString *indexedIdentifier = @"";
    __block NSString *storeIdentifier = @"";
    __block NSString *failure = nil;
    __block NSDictionary *descriptorDiagnostics = nil;
    uint64_t auditScratch = session.trojanMem;
    if (!auditScratch) {
        return @{
            @"ok": @NO,
            @"stage": @"audit-scratch",
            @"message": @"The pinned IconServices audit session has no bounded scratch page.",
        };
    }

    @try {
        remote_call_with_session_suppressing_result_logs(session, ^{
            uint64_t pool = r_autorelease_pool_push();
            uint64_t targetBundle = 0;
            uint64_t localIcon = 0;
            do {
                if (!pool) { failure = @"audit-autorelease-pool"; break; }

                BOOL cached = batch.auditABIReady;
                uint64_t managerClass = r_class("ISIconManager");
                uint64_t iconClass = r_class("ISBundleIdentifierIcon");
                uint64_t descriptorClass = r_class("ISImageDescriptor");
                uint64_t imageCacheClass = r_class("ISImageCache");
                uint64_t storeUnitClass = cached
                    ? batch.stockStoreUnitClass : r_class("ISStoreUnit");
                uint64_t manager = cached ? batch.stockManager : 0;
                uint64_t managerCache = cached ? batch.stockManagerCache : 0;
                uint64_t store = cached ? batch.stockStore : 0;
                BOOL abi = managerClass && iconClass && descriptorClass &&
                    imageCacheClass && storeUnitClass;
                if (!cached && abi) {
                    abi = cnd_publisher_remote_class_method_has_types(
                            managerClass, "sharedInstance", "@16@0:8", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            managerClass, "findOrRegisterIcon:",
                            "@24@0:8@16", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            iconClass, "initWithBundleIdentifier:",
                            "@24@0:8@16", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            imageCacheClass, "imageForDescriptor:",
                            "@24@0:8@16", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            storeUnitClass, "isValid", "B16@0:8", NULL) &&
                        cnd_publisher_remote_class_method_has_types(
                            storeUnitClass, "storeUnitWithStoreURL:UUID:",
                            "@32@0:8@16@24", NULL);
                    manager = abi
                        ? r_msg2(managerClass, "sharedInstance", 0, 0, 0, 0)
                        : 0;
                    managerCache = manager
                        ? cnd_publisher_audit_object_ivar(
                            manager, "_iconCache", 0x10, auditScratch)
                        : 0;
                    store = managerCache
                        ? cnd_publisher_audit_object_ivar(
                            managerCache, "_store", 0x10, auditScratch)
                        : 0;
                    uint64_t managerCacheClass = managerCache
                        ? r_dlsym_call(
                            R_TIMEOUT, "object_getClass", managerCache,
                            0, 0, 0, 0, 0, 0, 0)
                        : 0;
                    abi = abi && manager && managerCache && store &&
                        managerCacheClass &&
                        cnd_publisher_remote_method_has_types(
                            managerCacheClass,
                            "findStoreUnitForIcon:descriptor:UUID:validationToken:",
                            "B48@0:8@16@24^@32^@40", NULL);
                    if (abi) {
                        batch.auditABIReady = YES;
                        batch.stockStoreABIReady = YES;
                        batch.stockManager = manager;
                        batch.stockManagerCache = managerCache;
                        batch.stockStore = store;
                        batch.stockStoreUnitClass = storeUnitClass;
                    }
                }
                abiReady = abi && manager && managerCache && store;
                if (!abiReady) { failure = @"audit-abi-or-store"; break; }

                uint64_t descriptor = cnd_publisher_stock_descriptor(
                    batch, YES, descriptorClass, descriptorSpecification,
                    NO, &descriptorDiagnostics, &failure);
                descriptorReady = descriptor != 0;
                if (!descriptorReady) break;

                targetBundle = r_nsstr_retained(bundleIdentifier.UTF8String);
                uint64_t iconAllocation = targetBundle
                    ? r_msg2(iconClass, "alloc", 0, 0, 0, 0) : 0;
                localIcon = iconAllocation
                    ? r_msg2(iconAllocation, "initWithBundleIdentifier:",
                             targetBundle, 0, 0, 0)
                    : 0;
                uint64_t canonicalIcon = localIcon
                    ? r_msg2(manager, "findOrRegisterIcon:",
                             localIcon, 0, 0, 0)
                    : 0;
                canonicalIconPointer = canonicalIcon;
                uint64_t canonicalCache = canonicalIcon
                    ? cnd_publisher_audit_object_ivar(
                        canonicalIcon, "_imageCache", 0x20, auditScratch)
                    : 0;
                canonicalImageCachePointer = canonicalCache;
                canonicalCacheReadReady = canonicalCache &&
                    cnd_publisher_remote_method_has_types(
                        r_dlsym_call(R_TIMEOUT, "object_getClass",
                                     canonicalCache, 0, 0, 0, 0, 0, 0, 0),
                        "imageForDescriptor:", "@24@0:8@16", NULL);
                if (!canonicalCacheReadReady) {
                    failure = @"audit-canonical-image-cache";
                    break;
                }

                uint64_t response = r_msg2(
                    canonicalCache, "imageForDescriptor:",
                    descriptor, 0, 0, 0);
                /* 23A341 IFCacheImage inherits IFImage._data at +0x18 and
                 * adds _uuid/+0x90 and _validationToken/+0x98. All three
                 * public getters are property thunks. Keep them off the
                 * physical synthetic-call boundary just like cacheURL. */
                uint64_t responseData = response
                    ? cnd_publisher_audit_object_ivar(
                        response, "_data", 0x18, auditScratch)
                    : 0;
                uint64_t responseUUID = response
                    ? cnd_publisher_audit_object_ivar(
                        response, "_uuid", 0x90, auditScratch)
                    : 0;
                uint64_t responseToken = response
                    ? cnd_publisher_audit_object_ivar(
                        response, "_validationToken", 0x98, auditScratch)
                    : 0;
                if (response && (!responseData || !responseUUID ||
                                 !responseToken)) {
                    failure = @"audit-cache-response-layout";
                    break;
                }
                cacheData = responseData
                    ? cnd_publisher_audit_copy_remote_data(
                        responseData,
                        CNDIconServicesPublisherMaximumStructuredDataLength,
                        auditScratch)
                    : nil;
                validationTokenData = responseToken
                    ? cnd_publisher_audit_copy_small_remote_data(
                        responseToken,
                        CNDIconServicesPublisherMaximumPersistentIdentifierLength,
                        auditScratch)
                    : nil;
                cacheIdentifier = responseUUID
                    ? cnd_publisher_audit_copy_indexed_identifier(
                        responseUUID, auditScratch)
                    : @"";
                cacheResponsePresent = response && responseUUID &&
                    cacheData.length > 0;
                if (responseData && cacheData.length == 0) {
                    failure = @"audit-cache-data-copy";
                    break;
                }
                if (responseUUID && cacheIdentifier.length == 0) {
                    failure = @"audit-cache-identifier-copy";
                    break;
                }
                if (responseToken && validationTokenData.length == 0) {
                    failure = @"audit-validation-token-copy";
                    break;
                }

                uint64_t indexOutputs[2] = {0, 0};
                if (!remote_write(auditScratch, indexOutputs,
                                  sizeof(indexOutputs))) {
                    failure = @"audit-store-index-output";
                    break;
                }
                BOOL indexFound = (r_msg2(
                    managerCache,
                    "findStoreUnitForIcon:descriptor:UUID:validationToken:",
                    localIcon, descriptor, auditScratch,
                    auditScratch + sizeof(uint64_t)) & 1U) != 0;
                storeIndexLookupReady = remote_call_current_success() &&
                    remote_read(auditScratch, indexOutputs,
                                sizeof(indexOutputs));
                if (!storeIndexLookupReady) {
                    failure = @"audit-store-index-lookup";
                    break;
                }
                uint64_t indexedUUID = indexOutputs[0];
                uint64_t indexedToken = indexOutputs[1];
                storeIndexEntryPresent = indexFound;
                if (indexFound && (!r_is_objc_ptr(indexedUUID) ||
                                   !r_is_objc_ptr(indexedToken))) {
                    failure = @"audit-store-index-result";
                    break;
                }
                if (!indexFound && (indexedUUID || indexedToken)) {
                    failure = @"audit-store-index-empty-result";
                    break;
                }
                indexedIdentifier = indexedUUID
                    ? cnd_publisher_audit_copy_indexed_identifier(
                        indexedUUID, auditScratch)
                    : @"";
                storeValidationTokenData = indexedToken
                    ? cnd_publisher_audit_copy_small_remote_data(
                        indexedToken,
                        CNDIconServicesPublisherMaximumPersistentIdentifierLength,
                        auditScratch)
                    : nil;
                if (indexedUUID && indexedIdentifier.length == 0) {
                    failure = @"audit-indexed-identifier-copy";
                    break;
                }
                if (indexedToken && storeValidationTokenData.length == 0) {
                    failure = @"audit-indexed-token-copy";
                    break;
                }

                /* ISStore.storeURL and ISStoreUnit.data/UUID are also
                 * objc_getProperty thunks on 23A341. Validate their exact
                 * layouts before reading them directly. */
                uint64_t storeURL = cnd_publisher_audit_object_ivar(
                    store, "_storeURL", 0x10, auditScratch);
                if (!storeURL) {
                    failure = @"audit-store-url-layout";
                    break;
                }
                uint64_t storeUnit = indexedUUID && storeURL
                    ? r_msg2(storeUnitClass, "storeUnitWithStoreURL:UUID:",
                             storeURL, indexedUUID, 0, 0)
                    : 0;
                uint64_t storeUnitData = storeUnit
                    ? cnd_publisher_audit_object_ivar(
                        storeUnit, "_data", 0x10, auditScratch)
                    : 0;
                uint64_t storeUnitUUID = storeUnit
                    ? cnd_publisher_audit_object_ivar(
                        storeUnit, "_UUID", 0x8, auditScratch)
                    : 0;
                if (storeUnit && (!storeUnitData || !storeUnitUUID)) {
                    failure = @"audit-store-unit-layout";
                    break;
                }
                storeData = storeUnitData
                    ? cnd_publisher_audit_copy_remote_data(
                        storeUnitData,
                        CNDIconServicesPublisherMaximumStructuredDataLength,
                        auditScratch)
                    : nil;
                storeIdentifier = storeUnitUUID
                    ? cnd_publisher_audit_copy_indexed_identifier(
                        storeUnitUUID, auditScratch)
                    : @"";
                if (storeUnitData && storeData.length == 0) {
                    failure = @"audit-store-data-copy";
                    break;
                }
                if (storeUnitUUID && storeIdentifier.length == 0) {
                    failure = @"audit-store-identifier-copy";
                    break;
                }
                storeUnitPresent = storeUnit && storeData.length > 0;
                storeUnitValid = storeUnit &&
                    (r_msg2(storeUnit, "isValid", 0, 0, 0, 0) & 1U);
                cacheStoreEqual = cacheResponsePresent && storeUnitPresent &&
                    [cacheData isEqualToData:storeData];
                cacheStoreIdentifierEqual = responseUUID && storeUnitUUID &&
                    cnd_publisher_remote_objects_equal(
                        responseUUID, storeUnitUUID);
                cacheStoreValidationTokenEqual = responseToken &&
                    indexedToken && validationTokenData.length > 0 &&
                    [validationTokenData
                        isEqualToData:storeValidationTokenData];
                storeIndexUnitIdentifierEqual = indexedUUID && storeUnitUUID &&
                    cnd_publisher_remote_objects_equal(
                        indexedUUID, storeUnitUUID);

                uint64_t recordClass = r_class("LSApplicationRecord");
                BOOL recordABI = recordClass &&
                    cnd_publisher_remote_method_has_types(
                        recordClass,
                        "initWithBundleIdentifier:allowPlaceholder:error:",
                        "@36@0:8@16B24^@28", NULL) &&
                    cnd_publisher_remote_method_has_types(
                        recordClass, "persistentIdentifier",
                        "@16@0:8", NULL);
                if (!recordABI) {
                    failure = @"audit-source-record-abi";
                    break;
                }
                uint64_t recordAllocation = r_msg2(
                    recordClass, "alloc", 0, 0, 0, 0);
                uint64_t currentRecord = recordAllocation
                    ? r_msg2(
                        recordAllocation,
                        "initWithBundleIdentifier:allowPlaceholder:error:",
                        targetBundle, 1, 0, 0)
                    : 0;
                uint64_t currentIdentifierObject = currentRecord
                    ? r_msg2(currentRecord, "persistentIdentifier",
                             0, 0, 0, 0)
                    : 0;
                currentSourceIdentifierData = currentIdentifierObject
                    ? cnd_publisher_audit_copy_small_remote_data(
                        currentIdentifierObject,
                        CNDIconServicesPublisherMaximumPersistentIdentifierLength,
                        auditScratch)
                    : nil;
                currentSourceIdentifierPresent =
                    currentSourceIdentifierData.length > 0;
                if (!currentRecord || !currentSourceIdentifierPresent) {
                    failure = @"audit-current-source-identifier";
                    if (currentRecord && remote_call_current_success()) {
                        (void)r_msg2(currentRecord, "release", 0, 0, 0, 0);
                    }
                    break;
                }

                if (indexedUUID) {
                    NSString *sourceFailure = nil;
                    uint64_t sourceRegistry =
                        cnd_publisher_source_registry_map(
                            batch, managerCache, auditScratch,
                            &sourceFailure);
                    if (!sourceRegistry) {
                        failure = sourceFailure ?:
                            @"audit-source-registry";
                        if (remote_call_current_success()) {
                            (void)r_msg2(
                                currentRecord, "release", 0, 0, 0, 0);
                        }
                        break;
                    }
                    uint64_t sourceDataObject = r_msg2(
                        sourceRegistry, "dataForUUID:",
                        indexedUUID, 0, 0, 0);
                    uint64_t sourceArrayClass = sourceDataObject
                        ? r_dlsym_call(
                            R_TIMEOUT, "object_getClass", sourceDataObject,
                            0, 0, 0, 0, 0, 0, 0)
                        : 0;
                    BOOL sourceArrayABI = sourceArrayClass &&
                        cnd_publisher_remote_method_has_types(
                            sourceArrayClass, "count", "Q16@0:8", NULL) &&
                        cnd_publisher_remote_method_has_types(
                            sourceArrayClass, "objectAtIndex:",
                            "@24@0:8Q16", NULL);
                    if (!sourceArrayABI || !remote_call_current_success()) {
                        failure = @"audit-source-registry-array-abi";
                        if (remote_call_current_success()) {
                            (void)r_msg2(
                                currentRecord, "release", 0, 0, 0, 0);
                        }
                        break;
                    }
                    uint64_t remoteSourceCount = r_msg2(
                        sourceDataObject, "count", 0, 0, 0, 0);
                    if (remoteSourceCount >
                            CNDIconServicesPublisherAuditMaximumSourceIdentifiers) {
                        failure = @"audit-source-registry-entry-cap";
                        if (remote_call_current_success()) {
                            (void)r_msg2(
                                currentRecord, "release", 0, 0, 0, 0);
                        }
                        break;
                    }
                    sourceRegistryEntryCount = (NSUInteger)remoteSourceCount;
                    NSData *firstSourceIdentifier = nil;
                    NSData *matchingSourceIdentifier = nil;
                    for (NSUInteger sourceIndex = 0;
                         sourceIndex < sourceRegistryEntryCount;
                         sourceIndex++) {
                        uint64_t sourceIdentifierObject = r_msg2(
                            sourceDataObject, "objectAtIndex:",
                            sourceIndex, 0, 0, 0);
                        NSData *sourceIdentifier = sourceIdentifierObject
                            ? cnd_publisher_audit_copy_small_remote_data(
                                sourceIdentifierObject,
                                CNDIconServicesPublisherMaximumPersistentIdentifierLength,
                                auditScratch)
                            : nil;
                        if (!sourceIdentifier.length) {
                            failure = @"audit-source-registry-entry-copy";
                            break;
                        }
                        if (!firstSourceIdentifier) {
                            firstSourceIdentifier = sourceIdentifier;
                        }
                        if ([sourceIdentifier
                                isEqualToData:currentSourceIdentifierData]) {
                            matchingSourceIdentifier = sourceIdentifier;
                        }
                    }
                    if (failure) {
                        if (remote_call_current_success()) {
                            (void)r_msg2(
                                currentRecord, "release", 0, 0, 0, 0);
                        }
                        break;
                    }
                    sourceRegistryData = matchingSourceIdentifier ?:
                        firstSourceIdentifier;
                    sourceIdentityMatchesCurrentRecord =
                        matchingSourceIdentifier != nil;
                    sourceIdentityAuditReady =
                        remote_call_current_success();
                } else {
                    /* A completed current-digest index miss is itself valid
                     * evidence. There is no unit UUID against which a source
                     * registry entry could exist. */
                    sourceIdentityAuditReady = storeIndexLookupReady &&
                        !storeIndexEntryPresent;
                }
                sourceRegistryDataPresent = sourceRegistryData.length > 0;
                if (currentRecord && remote_call_current_success()) {
                    (void)r_msg2(currentRecord, "release", 0, 0, 0, 0);
                }
            } while (0);

            if (localIcon && remote_call_current_success()) {
                (void)r_msg2(localIcon, "release", 0, 0, 0, 0);
            }
            if (targetBundle && remote_call_current_success()) {
                (void)r_msg2(targetBundle, "release", 0, 0, 0, 0);
            }
            if (pool && remote_call_current_success()) {
                (void)r_autorelease_pool_pop(pool);
            }
            remoteOK = remote_call_current_success();
        });
    } @catch (NSException *exception) {
        failure = [NSString stringWithFormat:@"%@:%@",
            exception.name ?: @"exception",
            exception.reason ?: @"unknown"];
        remoteOK = NO;
    }

    batch.healthy = batch.healthy && remoteOK &&
        [session hasLocalState] && session.pid == batch.pid;
    BOOL completed = remoteOK && abiReady && descriptorReady &&
        canonicalCacheReadReady && storeIndexLookupReady &&
        sourceIdentityAuditReady;
    NSString *cacheHash = cacheData.length
        ? cnd_publisher_sha256(cacheData) : @"";
    NSString *storeHash = storeData.length
        ? cnd_publisher_sha256(storeData) : @"";
    NSString *sourceRegistryHash = sourceRegistryData.length
        ? cnd_publisher_sha256(sourceRegistryData) : @"";
    NSString *currentSourceIdentifierHash =
        currentSourceIdentifierData.length
            ? cnd_publisher_sha256(currentSourceIdentifierData) : @"";
    NSString *storeValidationTokenHash = storeValidationTokenData.length
        ? cnd_publisher_sha256(storeValidationTokenData) : @"";
    return @{
        @"ok": @(completed),
        @"stage": completed ? @"audited" : (failure ?: @"audit-failed"),
        @"message": completed
            ? @"The current descriptor index, backing store unit, source identity, and optional process-cache response were inspected without generation, purge, or persistent writes."
            : @"The existing IconServices state could not be inspected safely.",
        @"bundleIdentifier": bundleIdentifier,
        @"descriptorSpecification":
            cnd_publisher_normalized_descriptor_specification(
                descriptorSpecification) ?: @{},
        @"descriptorDiagnostics": descriptorDiagnostics ?: @{},
        @"canonicalIconPointer": @(canonicalIconPointer),
        @"canonicalImageCachePointer": @(canonicalImageCachePointer),
        @"canonicalCacheReadReady": @(canonicalCacheReadReady),
        @"cacheResponsePresent": @(cacheResponsePresent),
        @"cacheDataLength": @(cacheData.length),
        @"cacheDataSHA256": cacheHash ?: @"",
        @"cacheIdentifier": cacheIdentifier ?: @"",
        @"validationTokenLength": @(validationTokenData.length),
        @"validationTokenSHA256": validationTokenData.length
            ? cnd_publisher_sha256(validationTokenData) : @"",
        @"storeIndexLookupReady": @(storeIndexLookupReady),
        @"storeIndexEntryPresent": @(storeIndexEntryPresent),
        @"indexedIdentifier": indexedIdentifier ?: @"",
        @"storeValidationTokenLength": @(storeValidationTokenData.length),
        @"storeValidationTokenSHA256": storeValidationTokenHash ?: @"",
        @"storeUnitPresent": @(storeUnitPresent),
        @"storeUnitValid": @(storeUnitValid),
        @"storeDataLength": @(storeData.length),
        @"storeDataSHA256": storeHash ?: @"",
        @"storeIdentifier": storeIdentifier ?: @"",
        @"cacheStoreEqual": @(cacheStoreEqual),
        @"cacheStoreIdentifierEqual": @(cacheStoreIdentifierEqual),
        @"cacheStoreValidationTokenEqual":
            @(cacheStoreValidationTokenEqual),
        @"storeIndexUnitIdentifierEqual":
            @(storeIndexUnitIdentifierEqual),
        @"sourceIdentityAuditReady": @(sourceIdentityAuditReady),
        @"sourceRegistryEntryCount": @(sourceRegistryEntryCount),
        @"sourceRegistryDataPresent": @(sourceRegistryDataPresent),
        @"sourceRegistryDataLength": @(sourceRegistryData.length),
        @"sourceRegistryDataSHA256": sourceRegistryHash ?: @"",
        @"currentSourceIdentifierPresent":
            @(currentSourceIdentifierPresent),
        @"currentSourceIdentifierLength":
            @(currentSourceIdentifierData.length),
        @"currentSourceIdentifierSHA256":
            currentSourceIdentifierHash ?: @"",
        @"sourceIdentityMatchesCurrentRecord":
            @(sourceIdentityMatchesCurrentRecord),
        @"transportHealthy": @(batch.healthy),
        @"transientWeakRegistryProbeIssued": @YES,
        @"persistentMutationsIssued": @NO,
        @"presentationMutationsIssued": @NO,
        @"mutationsIssued": @NO,
        @"generationIssued": @NO,
        @"cachePurgeIssued": @NO,
        @"storeWriteIssued": @NO,
    };
}

@implementation CNDIconServicesPublisherRemoteTransport

- (NSDictionary<NSString *, id> *)beginBatch:(NSString *)wakeBundleIdentifier
{
    return cnd_remote_transport_call(self, ^{
        if (cnd_publisher_batch_state()) {
            return @{
            @"ok": @NO,
            @"stage": @"batch-already-open",
            @"message": @"An iconservicesagent batch is already open on this thread.",
            };
        }
        NSString *wakeIdentifier = cnd_publisher_valid_bundle_identifier(
            wakeBundleIdentifier) ? wakeBundleIdentifier :
            NSBundle.mainBundle.bundleIdentifier;
        if (!cnd_publisher_valid_bundle_identifier(wakeIdentifier)) {
            return @{
            @"ok": @NO,
            @"stage": @"wake-identifier",
            @"message": @"A valid bundle-shaped identifier is required to wake IconServices.",
            };
        }

        NSError *wakeError = nil;
        NSDictionary *wake = cnd_publisher_wake_agent_without_generation(
            wakeIdentifier, &wakeError);
        if (!wake) {
            return @{
            @"ok": @NO,
            @"stage": @"agent-wake",
            @"message": wakeError.localizedDescription ?:
                @"IconServices is not resident and could not be made resident.",
            };
        }
        NSError *sessionError = nil;
        RemoteCallSession *session = cnd_publisher_open_agent_session(
            wakeIdentifier, &sessionError);
        if (!session || ![session hasLocalState] || session.pid <= 1) {
            if ([session hasLocalState]) [session abandonRemoteCall];
            return @{
            @"ok": @NO,
            @"stage": @"remote-session",
            @"message": sessionError.localizedDescription ?:
                @"The iconservicesagent batch session could not be opened.",
            };
        }

        CNDIconServicesPublisherBatchState *state =
            [[CNDIconServicesPublisherBatchState alloc] init];
        state.session = session;
        state.wake = wake;
        state.healthy = YES;
        state.pid = session.pid;
        /*
         * The legacy message helper's conservative default sleeps for 50 ms
         * before every Objective-C message.  A publication performs well over
         * one hundred synchronous messages, while its genuinely asynchronous
         * boundaries already have explicit bounded polling below.  Remove the
         * blanket settle for the pinned batch instead of paying several
         * seconds per icon, and restore the caller's thread-local policy in
         * finishBatch.
         */
        state.previousSettleUS = r_settle_us(0);
        state.settleAdjusted = YES;
        self.batchState = state;
        return @{
        @"ok": @YES,
        @"stage": @"batch-open",
        @"message": @"One pinned iconservicesagent session is ready for catalog and publication.",
        @"agentPID": @(state.pid),
        @"wakeRequest": wake,
        @"sessionRetained": @YES,
        };
    });
}

- (NSDictionary<NSString *, id> *)copyInstalledBundleIdentifiersInBatch
{
    return cnd_remote_transport_call(self, ^{
        CNDIconServicesPublisherBatchState *state = cnd_publisher_batch_state();
        if (!state || !state.healthy || !state.session ||
            ![state.session hasLocalState] || state.session.pid != state.pid) {
            return @{
            @"ok": @NO,
            @"stage": @"batch-session",
            @"message": @"Installed-app discovery requires the pinned iconservicesagent batch session.",
            };
        }

    __block NSData *archiveData = nil;
    __block NSUInteger applicationCount = 0;
    __block NSString *failure = nil;
    __block BOOL remoteOK = NO;
    @try {
        remote_call_with_session_suppressing_result_logs(state.session, ^{
            uint64_t pool = r_autorelease_pool_push();
            NSMutableArray<NSNumber *> *retainedKeys =
                [NSMutableArray array];
            __block uint64_t bundleIdentifierKey = 0;
            do {
                if (!pool) { failure = @"remote-autorelease-pool"; break; }
                NSArray<NSString *> *frameworks = @[
                    @"/System/Library/Frameworks/CoreServices.framework/CoreServices",
                    @"/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices",
                    @"/System/Library/PrivateFrameworks/MobileCoreServices.framework/MobileCoreServices",
                    @"/System/Library/PrivateFrameworks/LaunchServices.framework/LaunchServices",
                ];
                uint64_t workspaceClass = r_class("LSApplicationWorkspace");
                for (NSString *path in frameworks) {
                    if (workspaceClass) break;
                    (void)cnd_publisher_load_remote_framework(
                        path.fileSystemRepresentation);
                    workspaceClass = r_class("LSApplicationWorkspace");
                }
                uint64_t workspace = workspaceClass
                    ? r_msg2(workspaceClass, "defaultWorkspace", 0, 0, 0, 0)
                    : 0;
                if (!workspace) { failure = @"workspace"; break; }

                uint64_t applications = 0;
                for (NSString *selectorName in @[
                    @"allApplications", @"allInstalledApplications"
                ]) {
                    uint64_t selector = r_sel(selectorName.UTF8String);
                    if (!selector || !r_msg2(workspace, "respondsToSelector:",
                                              selector, 0, 0, 0)) continue;
                    uint64_t candidate = r_msg2(
                        workspace, selectorName.UTF8String, 0, 0, 0, 0);
                    if (candidate) { applications = candidate; break; }
                }
                if (!applications) { failure = @"applications"; break; }
                uint64_t count = r_msg2(
                    applications, "count", 0, 0, 0, 0);
                if (count == 0 ||
                    count > CNDIconServicesPublisherMaximumApplications) {
                    failure = @"application-count";
                    break;
                }
                applicationCount = (NSUInteger)count;

                uint64_t firstApplication = r_msg2(
                    applications, "objectAtIndex:", 0, 0, 0, 0);
                uint64_t dictionaryClass = r_class("NSMutableDictionary");
                uint64_t catalogDictionary = dictionaryClass
                    ? r_msg2(dictionaryClass, "dictionaryWithCapacity:",
                             6, 0, 0, 0)
                    : 0;
                if (!firstApplication || !catalogDictionary) {
                    failure = @"catalog-container";
                    break;
                }

                /* Archive compact parallel metadata arrays rather than the
                 * LSApplicationProxy objects themselves.  This keeps the
                 * catalog bounded while giving the caller a durable install
                 * fingerprint (path + marketing/build/store versions) from
                 * the same privileged, pinned iconservicesagent session.
                 * Optional properties are admitted only when the proxy class
                 * actually implements their selector, avoiding KVC faults on
                 * OS builds which omit one of the version fields. */
                for (NSString *keyName in @[
                    @"bundleIdentifier", @"bundleURL",
                    @"shortVersionString", @"bundleVersion",
                    @"externalVersionIdentifier", @"applicationVersion"
                ]) {
                    uint64_t selector = r_sel(keyName.UTF8String);
                    if (!selector ||
                        !r_msg2(firstApplication, "respondsToSelector:",
                                selector, 0, 0, 0)) {
                        continue;
                    }
                    uint64_t key = r_nsstr_retained(keyName.UTF8String);
                    if (!key) continue;
                    [retainedKeys addObject:@(key)];
                    if ([keyName isEqualToString:@"bundleIdentifier"]) {
                        bundleIdentifierKey = key;
                    }
                    uint64_t values = r_msg2(
                        applications, "valueForKey:", key, 0, 0, 0);
                    if (values) {
                        (void)r_msg2(catalogDictionary,
                                     "setObject:forKey:", values, key, 0, 0);
                    }
                }
                uint64_t identifiers = bundleIdentifierKey
                    ? r_msg2(catalogDictionary, "objectForKey:",
                             bundleIdentifierKey, 0, 0, 0)
                    : 0;
                uint64_t archiverClass = r_class("NSKeyedArchiver");
                uint64_t archive = identifiers && archiverClass
                    ? r_msg2(archiverClass, "archivedDataWithRootObject:",
                             catalogDictionary, 0, 0, 0)
                    : 0;
                archiveData = archive
                    ? cnd_publisher_copy_remote_data(archive, 8U << 20)
                    : nil;
                if (archiveData.length == 0) failure = @"catalog-archive";
            } while (0);
            if (remote_call_current_success()) {
                for (NSNumber *keyAddress in retainedKeys.reverseObjectEnumerator) {
                    (void)r_msg2(keyAddress.unsignedLongLongValue,
                                 "release", 0, 0, 0, 0);
                }
            }
            if (pool && remote_call_current_success()) {
                (void)r_autorelease_pool_pop(pool);
            }
            remoteOK = remote_call_current_success();
        });
    } @catch (NSException *exception) {
        failure = [NSString stringWithFormat:@"%@:%@",
            exception.name ?: @"exception",
            exception.reason ?: @"unknown"];
        remoteOK = NO;
    }
    state.healthy = state.healthy && remoteOK &&
        [state.session hasLocalState] && state.session.pid == state.pid;
    if (!state.healthy) {
        return @{
            @"ok": @NO,
            @"stage": @"catalog-transport",
            @"message": @"The pinned iconservicesagent session failed during installed-app discovery.",
            @"reason": failure ?: @"transport-down",
            @"agentPID": @(state.pid),
        };
    }
    if (failure || archiveData.length == 0) {
        return @{
            @"ok": @NO,
            @"stage": failure ?: @"identifier-archive",
            @"message": @"iconservicesagent could not return its compact installed-application list.",
            @"agentPID": @(state.pid),
            @"applicationProxyCount": @(applicationCount),
            @"sessionRetained": @YES,
        };
    }

    id decoded = nil;
    @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        decoded = [NSKeyedUnarchiver unarchiveObjectWithData:archiveData];
#pragma clang diagnostic pop
    } @catch (__unused NSException *exception) {
        decoded = nil;
    }
    if (![decoded isKindOfClass:NSDictionary.class]) {
        return @{
            @"ok": @NO,
            @"stage": @"catalog-decode",
            @"message": @"The iconservicesagent application metadata archive was invalid.",
            @"agentPID": @(state.pid),
            @"sessionRetained": @YES,
        };
    }
    NSDictionary *decodedCatalog = (NSDictionary *)decoded;
    NSArray *decodedIdentifiers = [decodedCatalog[@"bundleIdentifier"]
        isKindOfClass:NSArray.class]
        ? decodedCatalog[@"bundleIdentifier"] : nil;
    if (decodedIdentifiers.count == 0) {
        return @{
            @"ok": @NO,
            @"stage": @"identifier-decode",
            @"message": @"The iconservicesagent application identifier array was invalid.",
            @"agentPID": @(state.pid),
            @"sessionRetained": @YES,
        };
    }
    NSMutableOrderedSet<NSString *> *unique = [NSMutableOrderedSet orderedSet];
    NSMutableDictionary<NSString *, NSDictionary *> *recordByFoldedIdentifier =
        [NSMutableDictionary dictionary];
    NSString *(^textAtIndex)(NSString *, NSUInteger) =
        ^NSString *(NSString *key, NSUInteger index) {
            NSArray *values = [decodedCatalog[key] isKindOfClass:NSArray.class]
                ? decodedCatalog[key] : nil;
            if (index >= values.count) return nil;
            id value = values[index];
            if ([value isKindOfClass:NSString.class]) return value;
            if ([value isKindOfClass:NSNumber.class]) return [value stringValue];
            return nil;
        };
    for (NSUInteger index = 0; index < decodedIdentifiers.count; index++) {
        id value = decodedIdentifiers[index];
        if (!cnd_publisher_valid_bundle_identifier(value)) continue;
        NSString *identifier = [(NSString *)value
            stringByTrimmingCharactersInSet:
                NSCharacterSet.whitespaceAndNewlineCharacterSet];
        [unique addObject:identifier];
        NSMutableDictionary *record = [@{
            @"bundleIdentifier": identifier,
        } mutableCopy];
        NSArray *urlValues = [decodedCatalog[@"bundleURL"]
            isKindOfClass:NSArray.class] ? decodedCatalog[@"bundleURL"] : nil;
        id bundleURLValue = index < urlValues.count ? urlValues[index] : nil;
        NSString *bundlePath = [bundleURLValue isKindOfClass:NSURL.class]
            ? [(NSURL *)bundleURLValue path]
            : ([bundleURLValue isKindOfClass:NSString.class]
                ? (NSString *)bundleURLValue : nil);
        if (bundlePath.length > 0) {
            record[@"bundlePath"] = bundlePath.stringByStandardizingPath;
        }
        for (NSString *key in @[
            @"shortVersionString", @"bundleVersion",
            @"externalVersionIdentifier", @"applicationVersion"
        ]) {
            NSString *text = textAtIndex(key, index);
            if (text.length > 0) record[key] = text;
        }
        NSString *folded = identifier.lowercaseString;
        NSDictionary *prior = recordByFoldedIdentifier[folded];
        if (!prior || record.count > prior.count) {
            recordByFoldedIdentifier[folded] = record;
        }
    }
    NSArray<NSString *> *identifiers = [unique.array
        sortedArrayUsingSelector:@selector(compare:)];
    if (identifiers.count == 0) {
        return @{
            @"ok": @NO,
            @"stage": @"identifier-empty",
            @"message": @"iconservicesagent returned no valid application bundle identifiers.",
            @"agentPID": @(state.pid),
            @"sessionRetained": @YES,
        };
    }
    NSMutableArray<NSDictionary *> *applicationRecords =
        [NSMutableArray arrayWithCapacity:identifiers.count];
    NSUInteger fingerprintableCount = 0;
    for (NSString *identifier in identifiers) {
        NSDictionary *record =
            recordByFoldedIdentifier[identifier.lowercaseString] ?:
            @{ @"bundleIdentifier": identifier };
        if ([record[@"bundlePath"] length] > 0 ||
            [record[@"shortVersionString"] length] > 0 ||
            [record[@"bundleVersion"] length] > 0 ||
            [record[@"externalVersionIdentifier"] length] > 0 ||
            [record[@"applicationVersion"] length] > 0) {
            fingerprintableCount++;
        }
        [applicationRecords addObject:record];
    }
        return @{
        @"ok": @YES,
        @"stage": @"cataloged",
        @"message": @"The pinned iconservicesagent returned installed application identifiers and update identities.",
        @"bundleIdentifiers": identifiers,
        @"applicationRecords": applicationRecords,
        @"fingerprintableApplicationCount": @(fingerprintableCount),
        @"applicationCount": @(identifiers.count),
        @"applicationProxyCount": @(applicationCount),
        @"archiveBytes": @(archiveData.length),
        @"agentPID": @(state.pid),
        @"sessionRetained": @YES,
        };
    });
}

- (NSDictionary<NSString *, id> *)publishBundleIdentifier:(NSString *)bundleIdentifier
                                      structuredImageData:(NSData *)structuredImageData
{
    return cnd_remote_transport_call(self, ^{
        return cnd_publisher_run(
            bundleIdentifier, structuredImageData,
            cnd_publisher_default_descriptor_specification());
    });
}

- (NSDictionary<NSString *, id> *)publishBundleIdentifier:(NSString *)bundleIdentifier
                                      structuredImageData:(NSData *)structuredImageData
                                  descriptorSpecification:(NSDictionary<NSString *,NSNumber *> *)descriptorSpecification
{
    return cnd_remote_transport_call(self, ^{
        return cnd_publisher_run(
            bundleIdentifier, structuredImageData,
            descriptorSpecification);
    });
}

- (NSDictionary<NSString *, id> *)restoreStockForBundleIdentifier:(NSString *)bundleIdentifier
{
    return cnd_remote_transport_call(self, ^{
        return cnd_publisher_run(
            bundleIdentifier, nil,
            cnd_publisher_default_descriptor_specification());
    });
}

- (NSDictionary<NSString *, id> *)restoreStockForBundleIdentifier:(NSString *)bundleIdentifier
                                           descriptorSpecification:(NSDictionary<NSString *,NSNumber *> *)descriptorSpecification
{
    return cnd_remote_transport_call(self, ^{
        return cnd_publisher_run(
            bundleIdentifier, nil, descriptorSpecification);
    });
}

- (NSDictionary<NSString *, id> *)auditBundleIdentifier:(NSString *)bundleIdentifier
                                  descriptorSpecification:(NSDictionary<NSString *,NSNumber *> *)descriptorSpecification
{
    return cnd_remote_transport_call(self, ^{
        return cnd_publisher_audit_variant(
            bundleIdentifier, descriptorSpecification);
    });
}

- (BOOL)isHealthy
{
    return cnd_remote_transport_health(self);
}

- (NSDictionary<NSString *, id> *)finishBatch
{
    return cnd_remote_transport_call(self, ^{
        CNDIconServicesPublisherBatchState *state = cnd_publisher_batch_state();
        if (!state) {
            return @{
            @"ok": @YES,
            @"stage": @"no-batch",
            @"message": @"No iconservicesagent batch required finalization.",
            @"closed": @YES,
            @"localStateRemaining": @NO,
            };
        }
    RemoteCallSession *session = state.session;
    BOOL healthyBeforeClose = state.healthy && session &&
        [session hasLocalState] && session.pid == state.pid;
    BOOL payloadCleanupNeeded = state.payloadReady ||
        state.descriptorTemplates.count > 0 || state.descriptorTemplate ||
        state.stagingRemoteBase || state.persistentIndexScratchRemoteBase;
    BOOL auditSourceRegistryCleanupNeeded =
        state.auditSourceRegistry != 0;
    BOOL remoteCleanupNeeded = payloadCleanupNeeded ||
        auditSourceRegistryCleanupNeeded;
    BOOL payloadCleanupAttempted = NO;
    BOOL payloadCleaned = !payloadCleanupNeeded;
    BOOL auditSourceRegistryCleaned =
        !auditSourceRegistryCleanupNeeded;
    if (healthyBeforeClose && remoteCleanupNeeded) {
        payloadCleanupAttempted = payloadCleanupNeeded;
        __block BOOL cleanupOK = NO;
        @try {
            remote_call_with_session_suppressing_result_logs(session, ^{
                if (state.auditSourceRegistry) {
                    (void)r_msg2(state.auditSourceRegistry,
                                 "release", 0, 0, 0, 0);
                }
                NSMutableSet<NSNumber *> *releasedDescriptors =
                    [NSMutableSet set];
                for (NSNumber *descriptorNumber in
                     state.descriptorTemplates.allValues) {
                    uint64_t descriptor =
                        descriptorNumber.unsignedLongLongValue;
                    if (!descriptor ||
                        [releasedDescriptors containsObject:descriptorNumber])
                        continue;
                    (void)r_msg2(descriptor, "release", 0, 0, 0, 0);
                    [releasedDescriptors addObject:descriptorNumber];
                }
                if (state.descriptorTemplate &&
                    ![releasedDescriptors containsObject:
                        @(state.descriptorTemplate)]) {
                    (void)r_msg2(state.descriptorTemplate,
                                 "release", 0, 0, 0, 0);
                }
                int unmap = state.payloadReady &&
                    state.payloadRemoteBase && state.payloadMappingLength
                    ? (int)r_dlsym_call(
                        R_TIMEOUT, "munmap", state.payloadRemoteBase,
                        state.payloadMappingLength, 0, 0, 0, 0, 0, 0)
                    : 0;
                int stagingUnmap = state.stagingRemoteBase &&
                    state.stagingCapacity
                    ? (int)r_dlsym_call(
                        R_TIMEOUT, "munmap", state.stagingRemoteBase,
                        state.stagingCapacity, 0, 0, 0, 0, 0, 0)
                    : 0;
                int persistentIndexScratchUnmap =
                    state.persistentIndexScratchRemoteBase &&
                    state.persistentIndexScratchLength
                    ? (int)r_dlsym_call(
                        R_TIMEOUT, "munmap",
                        state.persistentIndexScratchRemoteBase,
                        state.persistentIndexScratchLength,
                        0, 0, 0, 0, 0, 0)
                    : 0;
                cleanupOK = unmap == 0 && stagingUnmap == 0 &&
                    persistentIndexScratchUnmap == 0 &&
                    remote_call_current_success();
            });
        } @catch (__unused NSException *exception) {
            cleanupOK = NO;
        }
        payloadCleaned = !payloadCleanupNeeded || cleanupOK;
        auditSourceRegistryCleaned =
            !auditSourceRegistryCleanupNeeded || cleanupOK;
        if (cleanupOK) {
            state.auditSourceRegistry = 0;
            state.descriptorTemplate = 0;
            state.descriptorTemplateKey = nil;
            [state.descriptorTemplates removeAllObjects];
            state.payloadReady = NO;
            state.payloadRemoteBase = 0;
            state.payloadMappingLength = 0;
            state.payloadContextAddress = 0;
            state.stagingRemoteBase = 0;
            state.stagingCapacity = 0;
            state.persistentIndexScratchRemoteBase = 0;
            state.persistentIndexScratchLength = 0;
            state.payloadContextTemplate = nil;
        }
        healthyBeforeClose = healthyBeforeClose && cleanupOK &&
            [session hasLocalState] && session.pid == state.pid;
    }
    BOOL closed = NO;
    BOOL abandoned = NO;
    if (healthyBeforeClose) {
        (void)[session destroyRemoteCall];
        closed = ![session hasLocalState];
    }
    if ([session hasLocalState]) {
        [session abandonRemoteCall];
        abandoned = YES;
    } else {
        closed = YES;
    }
    if (state.settleAdjusted) {
        (void)r_settle_us(state.previousSettleUS);
        state.settleAdjusted = NO;
    }
    BOOL ok = healthyBeforeClose && closed && !abandoned;
        NSDictionary *result = @{
        @"ok": @(ok),
        @"stage": ok ? @"batch-closed" : @"batch-finalization",
        @"message": ok
            ? @"The pinned iconservicesagent batch closed cleanly."
            : @"The pinned iconservicesagent batch did not close cleanly.",
        @"agentPID": @(state.pid),
        @"healthyBeforeClose": @(healthyBeforeClose),
        @"payloadCleanupAttempted": @(payloadCleanupAttempted),
        @"payloadCleaned": @(payloadCleaned),
        @"auditSourceRegistryCleanupNeeded":
            @(auditSourceRegistryCleanupNeeded),
        @"auditSourceRegistryCleaned": @(auditSourceRegistryCleaned),
        @"closed": @(closed),
        @"abandoned": @(abandoned),
        @"localStateRemaining": @([session hasLocalState]),
        };
        if (closed || abandoned || ![session hasLocalState]) {
            self.batchState = nil;
        }
        return result;
    });
}

- (NSDictionary<NSString *, id> *)publishStandaloneBundleIdentifier:(NSString *)bundleIdentifier
                                               structuredImageData:(NSData *)structuredImageData
{
    return cnd_remote_transport_call(self, ^{
        return cnd_publisher_run(
            bundleIdentifier, structuredImageData,
            cnd_publisher_default_descriptor_specification());
    });
}

- (NSDictionary<NSString *, id> *)restoreStandaloneStockForBundleIdentifier:(NSString *)bundleIdentifier
{
    return cnd_remote_transport_call(self, ^{
        return cnd_publisher_run(
            bundleIdentifier, nil,
            cnd_publisher_default_descriptor_specification());
    });
}

@end

id<CNDIconServicesPublisherTransport>
CNDIconServicesPublisherMakeDefaultTransport(void)
{
    return [[CNDIconServicesPublisherRemoteTransport alloc] init];
}
