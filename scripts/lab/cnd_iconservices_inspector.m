#import <Foundation/Foundation.h>

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef CND_ICON_INSPECT_OUTPUT_TOKEN
#define CND_ICON_INSPECT_OUTPUT_TOKEN ""
#endif

#ifndef CND_ICON_INSPECT_ROOT_TOKEN
#define CND_ICON_INSPECT_ROOT_TOKEN ""
#endif

#ifndef CND_ICON_INSPECT_TARGET_BUNDLE
#define CND_ICON_INSPECT_TARGET_BUNDLE "com.apple.MobileSMS"
#endif

static const char *const CNDIconInspectOutputPath =
    "/var/tmp/cyanide-iconservices-inspection.log";
static const unsigned CNDIconInspectExpectedHookCount = 27U;
static const size_t CNDIconInspectMaximumPersistentIdentifierLength = 128U;
static const size_t CNDIconInspectMaximumRegistryObjects = 512U;
static const size_t CNDIconInspectMaximumTargetCaches = 32U;
static int gCNDIconInspectFD = -1;
static unsigned gCNDIconInspectEventCount;
static uint64_t gCNDIconInspectGarbageCollectionCycle;

static IMP gOriginalServiceGenerate;
static IMP gOriginalServiceGenerateUnit;
static IMP gOriginalStoreLookup;
static IMP gOriginalStoreWrite;
static IMP gOriginalStoreAddData;
static IMP gOriginalResponseInit;
static IMP gOriginalCacheImageInit;
static IMP gOriginalProviderMake;
static IMP gOriginalProviderResolve;
static IMP gOriginalGenerationRequestGenerate;
static IMP gOriginalClearCachedItems;
static IMP gOriginalClearAllCachedItems;
static IMP gOriginalFetchCacheConfiguration;
static IMP gOriginalScheduleCacheOperation;
static IMP gOriginalMutableCacheClear;
static IMP gOriginalCollectGarbage;
static IMP gOriginalRegisterRecordIdentifiers;
static IMP gOriginalStoreRemove;
static IMP gOriginalLSRecordInit;
static IMP gOriginalClearOperationRun;
static IMP gOriginalIconManagerFindOrRegister;
static IMP gOriginalImageCacheGet;
static IMP gOriginalImageCacheSet;
static IMP gOriginalImageCacheSetBags;
static IMP gOriginalConcreteImageGet;
static IMP gOriginalConcreteCachedImageGet;
static IMP gOriginalConcreteStoreImageGet;
static pthread_mutex_t gCNDIconInspectTargetCacheLock =
    PTHREAD_MUTEX_INITIALIZER;
static void *gCNDIconInspectTargetCaches[32];
static size_t gCNDIconInspectTargetCacheCount;

typedef struct {
    bool active;
    bool currentDatabaseGUIDKnown;
    uint8_t currentDatabaseGUID[16];
    uint8_t lastInvalidIdentifier[128];
    size_t lastInvalidIdentifierLength;
    uint64_t cycle;
    unsigned checkedRecords;
    unsigned validRecords;
    unsigned invalidRecords;
    unsigned removedUnits;
} CNDIconInspectGarbageCollectionState;

static __thread CNDIconInspectGarbageCollectionState
    gCNDIconInspectGarbageCollectionState;

static void CNDIconInspectLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDIconInspectLog(const char *format, ...)
{
    if (gCNDIconInspectFD < 0) return;
    char line[4096] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDIconInspectFD, line, amount);
    (void)fsync(gCNDIconInspectFD);
}

static uint64_t CNDIconInspectMonotonicNanoseconds(void)
{
    struct timespec time = {0};
    return clock_gettime(CLOCK_MONOTONIC, &time) == 0
        ? (uint64_t)time.tv_sec * 1000000000ULL + (uint64_t)time.tv_nsec
        : 0ULL;
}

static const char *CNDIconInspectClass(id object)
{
    return object ? class_getName(object_getClass(object)) : "-";
}

static void *CNDIconInspectPointer(id object)
{
    return object ? (__bridge void *)object : NULL;
}

static const char *CNDIconInspectSkipQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static id CNDIconInspectObjectGetter(id object, const char *name)
{
    if (!object || !name) return nil;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDIconInspectSkipQualifiers(returnType);
    bool objectReturn = type && (*type == '@' || *type == '#');
    free(returnType);
    if (!objectReturn) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static bool CNDIconInspectBoolGetter(id object, const char *name,
                                     bool *known)
{
    if (known) *known = false;
    if (!object || !name) return false;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return false;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDIconInspectSkipQualifiers(returnType);
    bool scalar = type && strchr("cCBB", *type);
    free(returnType);
    if (!scalar) return false;
    @try {
        bool value = ((BOOL (*)(id, SEL))objc_msgSend)(object, selector);
        if (known) *known = true;
        return value;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static uint64_t CNDIconInspectUnsignedGetter(id object, const char *name,
                                             bool *known)
{
    if (known) *known = false;
    if (!object || !name) return 0ULL;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return 0ULL;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDIconInspectSkipQualifiers(returnType);
    bool scalar = type && strchr("QqILSCB", *type);
    free(returnType);
    if (!scalar) return 0ULL;
    @try {
        uint64_t value = ((uint64_t (*)(id, SEL))objc_msgSend)(
            object, selector);
        if (known) *known = true;
        return value;
    } @catch (__unused NSException *exception) {
        return 0ULL;
    }
}

static NSString *CNDIconInspectTargetBundle(void)
{
    static NSString *bundle;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        bundle = [NSString stringWithUTF8String:CND_ICON_INSPECT_TARGET_BUNDLE];
    });
    return bundle;
}

static bool CNDIconInspectIsTargetIcon(id icon)
{
    id bundle = CNDIconInspectObjectGetter(icon, "bundleIdentifier");
    return [bundle isKindOfClass:NSString.class] &&
        [bundle isEqualToString:CNDIconInspectTargetBundle()];
}

static NSUInteger CNDIconInspectCollectionCount(id collection)
{
    bool known = false;
    uint64_t count = CNDIconInspectUnsignedGetter(collection, "count", &known);
    return known && count <= NSUIntegerMax ? (NSUInteger)count : NSNotFound;
}

static void CNDIconInspectRememberTargetCache(id cache)
{
    if (!cache) return;
    void *pointer = CNDIconInspectPointer(cache);
    pthread_mutex_lock(&gCNDIconInspectTargetCacheLock);
    for (size_t index = 0; index < gCNDIconInspectTargetCacheCount; index++) {
        if (gCNDIconInspectTargetCaches[index] == pointer) {
            pthread_mutex_unlock(&gCNDIconInspectTargetCacheLock);
            return;
        }
    }
    if (gCNDIconInspectTargetCacheCount <
        CNDIconInspectMaximumTargetCaches) {
        gCNDIconInspectTargetCaches[gCNDIconInspectTargetCacheCount++] = pointer;
    }
    pthread_mutex_unlock(&gCNDIconInspectTargetCacheLock);
}

static bool CNDIconInspectIsTargetCache(id cache)
{
    if (!cache) return false;
    bool found = false;
    void *pointer = CNDIconInspectPointer(cache);
    pthread_mutex_lock(&gCNDIconInspectTargetCacheLock);
    for (size_t index = 0; index < gCNDIconInspectTargetCacheCount; index++) {
        if (gCNDIconInspectTargetCaches[index] == pointer) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&gCNDIconInspectTargetCacheLock);
    return found;
}

static int CNDIconInspectCurrentXPCProcessIdentifier(void)
{
    Class connectionClass = NSClassFromString(@"NSXPCConnection");
    SEL currentSelector = sel_registerName("currentConnection");
    Method currentMethod = connectionClass
        ? class_getClassMethod(connectionClass, currentSelector) : NULL;
    if (!currentMethod || method_getNumberOfArguments(currentMethod) != 2U) {
        return -1;
    }
    char *returnType = method_copyReturnType(currentMethod);
    const char *type = CNDIconInspectSkipQualifiers(returnType);
    bool objectReturn = type && *type == '@';
    free(returnType);
    if (!objectReturn) return -1;
    @try {
        id connection = ((id (*)(id, SEL))objc_msgSend)(
            connectionClass, currentSelector);
        SEL pidSelector = sel_registerName("processIdentifier");
        Method pidMethod = connection
            ? class_getInstanceMethod(object_getClass(connection), pidSelector)
            : NULL;
        if (!pidMethod || method_getNumberOfArguments(pidMethod) != 2U) {
            return -1;
        }
        char *pidReturnType = method_copyReturnType(pidMethod);
        const char *pidType = CNDIconInspectSkipQualifiers(pidReturnType);
        bool integerReturn = pidType && (*pidType == 'i' || *pidType == 'I');
        free(pidReturnType);
        return integerReturn
            ? ((int (*)(id, SEL))objc_msgSend)(connection, pidSelector) : -1;
    } @catch (__unused NSException *exception) {
        return -1;
    }
}

static NSString *CNDIconInspectSHA256(NSData *data)
{
    if (!data) return @"-";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:
        CC_SHA256_DIGEST_LENGTH * 2U];
    for (size_t i = 0; i < sizeof(digest); i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    return result;
}

static NSString *CNDIconInspectUUIDText(id uuid)
{
    if ([uuid isKindOfClass:NSUUID.class]) return [uuid UUIDString];
    if ([uuid isKindOfClass:NSString.class]) return uuid;
    return @"-";
}

static NSString *CNDIconInspectPath(id object)
{
    if ([object isKindOfClass:NSURL.class]) return [object path] ?: @"-";
    if ([object isKindOfClass:NSString.class]) return object;
    return @"-";
}

static NSString *CNDIconInspectHexData(NSData *data, NSUInteger maximumLength)
{
    if (![data isKindOfClass:NSData.class]) return @"-";
    const uint8_t *bytes = data.bytes;
    NSUInteger length = MIN(data.length, maximumLength);
    NSMutableString *result = [NSMutableString stringWithCapacity:length * 2U];
    for (NSUInteger index = 0U; index < length; index++) {
        [result appendFormat:@"%02x", bytes[index]];
    }
    if (data.length > length) [result appendString:@"..."];
    return result;
}

static uint32_t CNDIconInspectReadUInt32(NSData *data, NSUInteger offset,
                                        bool *known)
{
    if (known) *known = false;
    if (![data isKindOfClass:NSData.class] ||
        offset > data.length || data.length - offset < sizeof(uint32_t)) {
        return 0U;
    }
    uint32_t value = 0U;
    memcpy(&value, (const uint8_t *)data.bytes + offset, sizeof(value));
    if (known) *known = true;
    return value;
}

static uint64_t CNDIconInspectReadUInt64(NSData *data, NSUInteger offset,
                                        bool *known)
{
    if (known) *known = false;
    if (![data isKindOfClass:NSData.class] ||
        offset > data.length || data.length - offset < sizeof(uint64_t)) {
        return 0ULL;
    }
    uint64_t value = 0ULL;
    memcpy(&value, (const uint8_t *)data.bytes + offset, sizeof(value));
    if (known) *known = true;
    return value;
}

static NSString *CNDIconInspectPersistentIdentifierDatabaseUUID(NSData *data)
{
    if (![data isKindOfClass:NSData.class] || data.length < 28U) return @"-";
    const uint8_t *bytes = data.bytes;
    return [[[NSUUID alloc] initWithUUIDBytes:bytes + 12U] UUIDString] ?: @"-";
}

static void CNDIconInspectCaptureCurrentDatabaseGUID(NSData *identifier)
{
    CNDIconInspectGarbageCollectionState *state =
        &gCNDIconInspectGarbageCollectionState;
    state->currentDatabaseGUIDKnown = false;
    memset(state->currentDatabaseGUID, 0, sizeof(state->currentDatabaseGUID));
    if (![identifier isKindOfClass:NSData.class] || identifier.length < 28U) {
        return;
    }
    memcpy(state->currentDatabaseGUID,
           (const uint8_t *)identifier.bytes + 12U,
           sizeof(state->currentDatabaseGUID));
    state->currentDatabaseGUIDKnown = true;
}

static const char *CNDIconInspectInvalidReason(NSData *identifier)
{
    CNDIconInspectGarbageCollectionState *state =
        &gCNDIconInspectGarbageCollectionState;
    if (!state->currentDatabaseGUIDKnown ||
        ![identifier isKindOfClass:NSData.class] || identifier.length < 28U) {
        return "unknown";
    }
    const uint8_t *identifierGUID =
        (const uint8_t *)identifier.bytes + 12U;
    return memcmp(identifierGUID, state->currentDatabaseGUID,
                  sizeof(state->currentDatabaseGUID)) == 0
        ? "unit-or-record-identity" : "database-guid";
}

static void CNDIconInspectLogPersistentIdentifier(
    const char *label, NSData *identifier, id unitUUID, id record,
    const char *reason)
{
    bool unitKnown = false;
    bool tableKnown = false;
    bool identityKnown = false;
    uint32_t unitID = CNDIconInspectReadUInt32(identifier, 4U, &unitKnown);
    uint32_t tableID = CNDIconInspectReadUInt32(identifier, 8U, &tableKnown);
    uint64_t applicationIdentity =
        CNDIconInspectReadUInt64(identifier, 28U, &identityKnown);
    id recordDatabaseUUID = CNDIconInspectObjectGetter(record, "databaseUUID");
    id recordBundle = CNDIconInspectObjectGetter(record, "bundleIdentifier");
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle source label=%s monoNS=%llu cycle=%llu "
        "unitUUID=%s bytes=%lu sha256=%s raw=%s version=%u "
        "unitID=%u/%d tableID=%u/%d databaseGUID=%s appIdentity=%llx/%d "
        "record=%p/%s recordDatabaseGUID=%s bundle=%s reason=%s\n",
        label, (unsigned long long)CNDIconInspectMonotonicNanoseconds(),
        (unsigned long long)gCNDIconInspectGarbageCollectionState.cycle,
        CNDIconInspectUUIDText(unitUUID).UTF8String,
        (unsigned long)identifier.length,
        CNDIconInspectSHA256(identifier).UTF8String,
        CNDIconInspectHexData(
            identifier, CNDIconInspectMaximumPersistentIdentifierLength)
            .UTF8String,
        identifier.length > 0U ? ((const uint8_t *)identifier.bytes)[0] : 0U,
        unitID, unitKnown, tableID, tableKnown,
        CNDIconInspectPersistentIdentifierDatabaseUUID(identifier).UTF8String,
        (unsigned long long)applicationIdentity, identityKnown,
        CNDIconInspectPointer(record), CNDIconInspectClass(record),
        CNDIconInspectUUIDText(recordDatabaseUUID).UTF8String,
        [recordBundle isKindOfClass:NSString.class]
            ? [recordBundle UTF8String] : "-",
        reason ?: "-");
}

static void CNDIconInspectLogCurrentApplicationRecord(const char *label,
                                                      bool captureDatabaseGUID)
{
    Class recordClass = NSClassFromString(@"LSApplicationRecord");
    SEL selector = sel_registerName(
        "initWithBundleIdentifier:allowPlaceholder:error:");
    Method method = recordClass
        ? class_getInstanceMethod(recordClass, selector) : NULL;
    bool abi = false;
    if (method && method_getNumberOfArguments(method) == 5U) {
        char *returnType = method_copyReturnType(method);
        char *placeholderType = method_copyArgumentType(method, 3U);
        char *errorType = method_copyArgumentType(method, 4U);
        const char *resultType = CNDIconInspectSkipQualifiers(returnType);
        const char *flagType = CNDIconInspectSkipQualifiers(placeholderType);
        const char *outType = CNDIconInspectSkipQualifiers(errorType);
        abi = resultType && *resultType == '@' && flagType &&
            strchr("cCB", *flagType) && outType && *outType == '^';
        free(returnType);
        free(placeholderType);
        free(errorType);
    }

    NSString *bundle = [NSString stringWithUTF8String:
        CND_ICON_INSPECT_TARGET_BUNDLE];
    id record = nil;
    NSError *error = nil;
    if (abi && bundle.length > 0U) {
        @try {
            id allocation = ((id (*)(id, SEL))objc_msgSend)(
                recordClass, sel_registerName("alloc"));
            record = ((id (*)(id, SEL, id, BOOL, NSError **))objc_msgSend)(
                allocation, selector, bundle, YES, &error);
        } @catch (NSException *exception) {
            CNDIconInspectLog(
                "[CND_ICON_AGENT] lifecycle target-exception label=%s "
                "monoNS=%llu bundle=%s name=%s reason=%s\n",
                label, (unsigned long long)CNDIconInspectMonotonicNanoseconds(),
                bundle.UTF8String, exception.name.UTF8String,
                exception.reason.UTF8String);
        }
    }
    NSData *identifier = nil;
    id candidate = CNDIconInspectObjectGetter(record, "persistentIdentifier");
    if ([candidate isKindOfClass:NSData.class]) identifier = candidate;
    if (captureDatabaseGUID) {
        CNDIconInspectCaptureCurrentDatabaseGUID(identifier);
    }
    bool sequenceKnown = false;
    uint64_t sequence = CNDIconInspectUnsignedGetter(
        record, "sequenceNumber", &sequenceKnown);
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle target label=%s monoNS=%llu bundle=%s "
        "abi=%d record=%p/%s sequence=%llu/%d error=%s\n",
        label, (unsigned long long)CNDIconInspectMonotonicNanoseconds(),
        bundle.UTF8String, abi, CNDIconInspectPointer(record),
        CNDIconInspectClass(record), (unsigned long long)sequence,
        sequenceKnown, error.localizedDescription.UTF8String ?: "-");
    CNDIconInspectLogPersistentIdentifier(
        label, identifier, nil, record, record ? "current" : "unavailable");
}

static void CNDIconInspectLogImage(const char *label, id image)
{
    id uuid = CNDIconInspectObjectGetter(image, "uuid");
    id data = CNDIconInspectObjectGetter(image, "data");
    id token = CNDIconInspectObjectGetter(image, "validationToken");
    NSData *dataObject = [data isKindOfClass:NSData.class] ? data : nil;
    NSData *tokenObject = [token isKindOfClass:NSData.class] ? token : nil;
    CGImageRef cgImage = NULL;
    SEL cgSelector = sel_registerName("CGImage");
    Method cgMethod = image
        ? class_getInstanceMethod(object_getClass(image), cgSelector) : NULL;
    if (cgMethod && method_getNumberOfArguments(cgMethod) == 2U) {
        char *returnType = method_copyReturnType(cgMethod);
        const char *type = CNDIconInspectSkipQualifiers(returnType);
        bool pointerReturn = type && *type == '^';
        free(returnType);
        if (pointerReturn) {
            @try {
                cgImage = ((CGImageRef (*)(id, SEL))objc_msgSend)(
                    image, cgSelector);
            } @catch (__unused NSException *exception) {
                cgImage = NULL;
            }
        }
    }
    CNDIconInspectLog(
        "[CND_ICON_AGENT] image label=%s object=%p/%s uuid=%s "
        "data=%lu/%s token=%lu/%s cg=%p pixels=%zux%zu\n",
        label, CNDIconInspectPointer(image), CNDIconInspectClass(image),
        CNDIconInspectUUIDText(uuid).UTF8String,
        (unsigned long)dataObject.length,
        CNDIconInspectSHA256(dataObject).UTF8String,
        (unsigned long)tokenObject.length,
        CNDIconInspectSHA256(tokenObject).UTF8String,
        cgImage, cgImage ? CGImageGetWidth(cgImage) : 0U,
        cgImage ? CGImageGetHeight(cgImage) : 0U);
}

static void CNDIconInspectLogDescriptor(const char *label, id descriptor)
{
    id digest = CNDIconInspectObjectGetter(descriptor, "digest");
    bool sizeKnown = false;
    CGSize size = CGSizeZero;
    SEL sizeSelector = sel_registerName("size");
    Method sizeMethod = descriptor
        ? class_getInstanceMethod(object_getClass(descriptor), sizeSelector)
        : NULL;
    if (sizeMethod && method_getNumberOfArguments(sizeMethod) == 2U) {
        char *returnType = method_copyReturnType(sizeMethod);
        sizeKnown = returnType && !strcmp(
            CNDIconInspectSkipQualifiers(returnType), @encode(CGSize));
        free(returnType);
        if (sizeKnown) {
            size = ((CGSize (*)(id, SEL))objc_msgSend)(
                descriptor, sizeSelector);
        }
    }
    bool scaleKnown = false;
    double scale = 0.0;
    SEL scaleSelector = sel_registerName("scale");
    Method scaleMethod = descriptor
        ? class_getInstanceMethod(object_getClass(descriptor), scaleSelector)
        : NULL;
    if (scaleMethod && method_getNumberOfArguments(scaleMethod) == 2U) {
        char *returnType = method_copyReturnType(scaleMethod);
        const char *type = CNDIconInspectSkipQualifiers(returnType);
        scaleKnown = type && *type == 'd';
        free(returnType);
        if (scaleKnown) {
            scale = ((double (*)(id, SEL))objc_msgSend)(
                descriptor, scaleSelector);
        }
    }
    bool appearanceKnown = false;
    bool optionsKnown = false;
    uint64_t appearance = CNDIconInspectUnsignedGetter(
        descriptor, "appearance", &appearanceKnown);
    uint64_t options = CNDIconInspectUnsignedGetter(
        descriptor, "variantOptions", &optionsKnown);
    NSString *description = nil;
    @try {
        description = [descriptor description];
    } @catch (__unused NSException *exception) {
        description = @"<description-failed>";
    }
    description = [(description ?: @"-")
        stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
    if (description.length > 512U) {
        description = [[description substringToIndex:512U]
            stringByAppendingString:@"..."];
    }
    CNDIconInspectLog(
        "[CND_ICON_AGENT] descriptor label=%s object=%p/%s digest=%s "
        "size=%.3fx%.3f/%d scale=%.3f/%d appearance=%llu/%d "
        "variantOptions=%#llx/%d value=%s\n",
        label, CNDIconInspectPointer(descriptor),
        CNDIconInspectClass(descriptor),
        CNDIconInspectUUIDText(digest).UTF8String,
        size.width, size.height, sizeKnown, scale, scaleKnown,
        (unsigned long long)appearance, appearanceKnown,
        (unsigned long long)options, optionsKnown,
        description.UTF8String);
}

static void CNDIconInspectLogImageCacheState(const char *label, id cache)
{
    id bags = CNDIconInspectObjectGetter(cache, "imageBagsByDescriptor");
    id token = CNDIconInspectObjectGetter(cache, "latestValidationToken");
    NSData *tokenData = [token isKindOfClass:NSData.class] ? token : nil;
    NSUInteger bagCount = CNDIconInspectCollectionCount(bags);
    CNDIconInspectLog(
        "[CND_ICON_AGENT] local-cache label=%s cache=%p/%s bags=%p/%s "
        "bagCount=%lld token=%lu/%s tracked=%d\n",
        label, CNDIconInspectPointer(cache), CNDIconInspectClass(cache),
        CNDIconInspectPointer(bags), CNDIconInspectClass(bags),
        bagCount == NSNotFound ? -1LL : (long long)bagCount,
        (unsigned long)tokenData.length,
        CNDIconInspectSHA256(tokenData).UTF8String,
        CNDIconInspectIsTargetCache(cache));
}

static void CNDIconInspectLogManagerState(const char *label)
{
    Class managerClass = objc_getClass("ISIconManager");
    SEL sharedSelector = sel_registerName("sharedInstance");
    Method sharedMethod = managerClass
        ? class_getClassMethod(managerClass, sharedSelector) : NULL;
    id manager = nil;
    if (sharedMethod && method_getNumberOfArguments(sharedMethod) == 2U) {
        char *returnType = method_copyReturnType(sharedMethod);
        const char *type = CNDIconInspectSkipQualifiers(returnType);
        bool abi = type && *type == '@';
        free(returnType);
        if (abi) {
            @try {
                manager = ((id (*)(id, SEL))objc_msgSend)(
                    managerClass, sharedSelector);
            } @catch (__unused NSException *exception) {
                manager = nil;
            }
        }
    }
    id registry = CNDIconInspectObjectGetter(manager, "iconRegistry");
    id managerCache = CNDIconInspectObjectGetter(manager, "iconCache");
    NSUInteger registryCount = CNDIconInspectCollectionCount(registry);
    NSUInteger scanned = 0U;
    NSUInteger matched = 0U;
    bool capped = false;
    @try {
        if ([registry conformsToProtocol:@protocol(NSFastEnumeration)]) {
            for (id icon in registry) {
                if (scanned >= CNDIconInspectMaximumRegistryObjects) {
                    capped = true;
                    break;
                }
                scanned++;
                if (!CNDIconInspectIsTargetIcon(icon)) continue;
                matched++;
                id cache = CNDIconInspectObjectGetter(icon, "imageCache");
                CNDIconInspectRememberTargetCache(cache);
                id digest = CNDIconInspectObjectGetter(icon, "digest");
                CNDIconInspectLog(
                    "[CND_ICON_AGENT] registry-target label=%s manager=%p/%s "
                    "registry=%p/%s icon=%p/%s digest=%s cache=%p/%s\n",
                    label, CNDIconInspectPointer(manager),
                    CNDIconInspectClass(manager),
                    CNDIconInspectPointer(registry),
                    CNDIconInspectClass(registry),
                    CNDIconInspectPointer(icon), CNDIconInspectClass(icon),
                    CNDIconInspectUUIDText(digest).UTF8String,
                    CNDIconInspectPointer(cache), CNDIconInspectClass(cache));
                CNDIconInspectLogImageCacheState(label, cache);
            }
        }
    } @catch (NSException *exception) {
        CNDIconInspectLog(
            "[CND_ICON_AGENT] registry-exception label=%s name=%s reason=%s\n",
            label, exception.name.UTF8String,
            exception.reason.UTF8String);
    }
    pthread_mutex_lock(&gCNDIconInspectTargetCacheLock);
    size_t trackedCaches = gCNDIconInspectTargetCacheCount;
    pthread_mutex_unlock(&gCNDIconInspectTargetCacheLock);
    CNDIconInspectLog(
        "[CND_ICON_AGENT] registry-summary label=%s manager=%p/%s "
        "managerCache=%p/%s registry=%p/%s count=%lld scanned=%lu "
        "matched=%lu capped=%d trackedCaches=%lu\n",
        label, CNDIconInspectPointer(manager), CNDIconInspectClass(manager),
        CNDIconInspectPointer(managerCache),
        CNDIconInspectClass(managerCache),
        CNDIconInspectPointer(registry), CNDIconInspectClass(registry),
        registryCount == NSNotFound ? -1LL : (long long)registryCount,
        (unsigned long)scanned, (unsigned long)matched, capped,
        (unsigned long)trackedCaches);
}

static void CNDIconInspectLogRequest(const char *label, id request)
{
    id icon = CNDIconInspectObjectGetter(request, "icon");
    if (!icon) icon = CNDIconInspectObjectGetter(request, "requestedIcon");
    id descriptor = CNDIconInspectObjectGetter(request, "descriptor");
    if (!descriptor) {
        descriptor = CNDIconInspectObjectGetter(request, "imageDescriptor");
    }
    id bundle = CNDIconInspectObjectGetter(request, "bundleIdentifier");
    if (!bundle) bundle = CNDIconInspectObjectGetter(icon, "bundleIdentifier");
    id digest = CNDIconInspectObjectGetter(descriptor, "digest");
    bool ignoreKnown = false;
    bool ignoreCache = CNDIconInspectBoolGetter(
        descriptor, "ignoreCache", &ignoreKnown);
    CNDIconInspectLog(
        "[CND_ICON_AGENT] request label=%s object=%p/%s icon=%p/%s "
        "bundle=%s descriptor=%p/%s digest=%s ignoreCache=%d/%d\n",
        label, CNDIconInspectPointer(request), CNDIconInspectClass(request),
        CNDIconInspectPointer(icon), CNDIconInspectClass(icon),
        [bundle isKindOfClass:NSString.class] ? [bundle UTF8String] : "-",
        CNDIconInspectPointer(descriptor), CNDIconInspectClass(descriptor),
        CNDIconInspectUUIDText(digest).UTF8String,
        ignoreKnown, ignoreCache);
    CNDIconInspectLogDescriptor(label, descriptor);
}

static void CNDIconInspectLogStoreUnit(const char *label, id store, id unit)
{
    id uuid = CNDIconInspectObjectGetter(unit, "uuid");
    if (!uuid) uuid = CNDIconInspectObjectGetter(unit, "UUID");
    id data = CNDIconInspectObjectGetter(unit, "data");
    id token = CNDIconInspectObjectGetter(unit, "validationToken");
    id storeURL = CNDIconInspectObjectGetter(store, "storeURL");
    NSString *uuidText = CNDIconInspectUUIDText(uuid);
    NSString *storePath = CNDIconInspectPath(storeURL);
    NSString *unitPath = uuidText.length > 1U && storePath.length > 1U
        ? [storePath stringByAppendingPathComponent:
            [uuidText stringByAppendingPathExtension:@"isdata"]]
        : @"-";
    NSData *dataObject = [data isKindOfClass:NSData.class] ? data : nil;
    NSData *tokenObject = [token isKindOfClass:NSData.class] ? token : nil;
    NSData *fileData = ![unitPath isEqualToString:@"-"]
        ? [NSData dataWithContentsOfFile:unitPath
                                options:NSDataReadingMappedIfSafe error:nil]
        : nil;
    bool validKnown = false;
    bool valid = CNDIconInspectBoolGetter(unit, "isValid", &validKnown);
    CNDIconInspectLog(
        "[CND_ICON_AGENT] store-unit label=%s store=%p/%s url=%s "
        "unit=%p/%s uuid=%s valid=%d/%d data=%lu/%s token=%lu/%s "
        "file=%s bytes=%lu/%s dataEqualsFile=%d\n",
        label, CNDIconInspectPointer(store), CNDIconInspectClass(store),
        storePath.UTF8String, CNDIconInspectPointer(unit),
        CNDIconInspectClass(unit), uuidText.UTF8String,
        validKnown, valid, (unsigned long)dataObject.length,
        CNDIconInspectSHA256(dataObject).UTF8String,
        (unsigned long)tokenObject.length,
        CNDIconInspectSHA256(tokenObject).UTF8String,
        unitPath.UTF8String, (unsigned long)fileData.length,
        CNDIconInspectSHA256(fileData).UTF8String,
        dataObject && fileData && [dataObject isEqualToData:fileData]);
}

static void CNDIconInspectDumpSurface(const char *className)
{
    Class cls = objc_getClass(className);
    if (!cls) {
        CNDIconInspectLog("[CND_ICON_AGENT] surface class=%s available=0\n",
                          className);
        return;
    }
    CNDIconInspectLog("[CND_ICON_AGENT] surface class=%s available=1\n",
                      className);
    for (Class cursor = cls; cursor; cursor = class_getSuperclass(cursor)) {
        if (!strcmp(class_getName(cursor), "NSObject")) break;
        unsigned count = 0U;
        Method *methods = class_copyMethodList(cursor, &count);
        unsigned cap = count < 96U ? count : 96U;
        for (unsigned i = 0; methods && i < cap; i++) {
            CNDIconInspectLog(
                "[CND_ICON_AGENT] method class=%s owner=%s name=%s types=%s\n",
                className, class_getName(cursor),
                sel_getName(method_getName(methods[i])),
                method_getTypeEncoding(methods[i]) ?: "-");
        }
        free(methods);
        break;
    }
}

static void CNDIconInspectLogExactMethod(const char *className,
                                         const char *selectorName,
                                         bool classMethod)
{
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    Method method = !cls ? NULL : (classMethod
        ? class_getClassMethod(cls, selector)
        : class_getInstanceMethod(cls, selector));
    CNDIconInspectLog(
        "[CND_ICON_AGENT] exact-method class=%s kind=%s name=%s "
        "present=%d owner=%s types=%s\n",
        className, classMethod ? "class" : "instance", selectorName,
        method != NULL,
        method ? class_getName(classMethod
            ? object_getClass(cls)
            : cls) : "-",
        method ? method_getTypeEncoding(method) : "-");
}

static id CNDHookIconManagerFindOrRegister(id self, SEL command, id icon)
{
    bool inputTarget = CNDIconInspectIsTargetIcon(icon);
    id result = ((id (*)(id, SEL, id))gOriginalIconManagerFindOrRegister)(
        self, command, icon);
    bool resultTarget = CNDIconInspectIsTargetIcon(result);
    if (inputTarget || resultTarget) {
        gCNDIconInspectEventCount++;
        id inputCache = CNDIconInspectObjectGetter(icon, "imageCache");
        id resultCache = CNDIconInspectObjectGetter(result, "imageCache");
        CNDIconInspectRememberTargetCache(inputCache);
        CNDIconInspectRememberTargetCache(resultCache);
        CNDIconInspectLog(
            "[CND_ICON_AGENT] local-cache find-or-register manager=%p/%s "
            "input=%p/%s inputTarget=%d inputCache=%p/%s "
            "result=%p/%s resultTarget=%d resultCache=%p/%s sameIcon=%d "
            "sameCache=%d count=%u\n",
            CNDIconInspectPointer(self), CNDIconInspectClass(self),
            CNDIconInspectPointer(icon), CNDIconInspectClass(icon), inputTarget,
            CNDIconInspectPointer(inputCache), CNDIconInspectClass(inputCache),
            CNDIconInspectPointer(result), CNDIconInspectClass(result),
            resultTarget, CNDIconInspectPointer(resultCache),
            CNDIconInspectClass(resultCache), icon == result,
            inputCache && inputCache == resultCache,
            gCNDIconInspectEventCount);
        CNDIconInspectLogManagerState("find-or-register-return");
    }
    return result;
}

static id CNDHookImageCacheGet(id self, SEL command, id descriptor)
{
    id result = ((id (*)(id, SEL, id))gOriginalImageCacheGet)(
        self, command, descriptor);
    if (CNDIconInspectIsTargetCache(self)) {
        gCNDIconInspectEventCount++;
        CNDIconInspectLogDescriptor("cache-get", descriptor);
        CNDIconInspectLogImage("cache-get-return", result);
        CNDIconInspectLogImageCacheState("cache-get-return", self);
    }
    return result;
}

static void CNDHookImageCacheSet(id self, SEL command, id image, id descriptor)
{
    bool target = CNDIconInspectIsTargetCache(self);
    if (target) {
        gCNDIconInspectEventCount++;
        CNDIconInspectLogDescriptor("cache-set-before", descriptor);
        CNDIconInspectLogImage("cache-set-before", image);
        CNDIconInspectLogImageCacheState("cache-set-before", self);
    }
    ((void (*)(id, SEL, id, id))gOriginalImageCacheSet)(
        self, command, image, descriptor);
    if (target) {
        CNDIconInspectLogImageCacheState("cache-set-after", self);
    }
}

static void CNDHookImageCacheSetBags(id self, SEL command, id bags)
{
    bool target = CNDIconInspectIsTargetCache(self);
    if (target) {
        gCNDIconInspectEventCount++;
        CNDIconInspectLogImageCacheState("cache-set-bags-before", self);
        NSUInteger count = CNDIconInspectCollectionCount(bags);
        CNDIconInspectLog(
            "[CND_ICON_AGENT] local-cache set-bags-argument cache=%p/%s "
            "bags=%p/%s count=%lld\n",
            CNDIconInspectPointer(self), CNDIconInspectClass(self),
            CNDIconInspectPointer(bags), CNDIconInspectClass(bags),
            count == NSNotFound ? -1LL : (long long)count);
    }
    ((void (*)(id, SEL, id))gOriginalImageCacheSetBags)(
        self, command, bags);
    if (target) {
        CNDIconInspectLogImageCacheState("cache-set-bags-after", self);
    }
}

static void CNDIconInspectLogConcreteLookup(const char *label, id icon,
                                            id descriptor, id result)
{
    if (!CNDIconInspectIsTargetIcon(icon)) return;
    gCNDIconInspectEventCount++;
    id cache = CNDIconInspectObjectGetter(icon, "imageCache");
    CNDIconInspectRememberTargetCache(cache);
    CNDIconInspectLog(
        "[CND_ICON_AGENT] local-cache concrete-lookup label=%s icon=%p/%s "
        "cache=%p/%s result=%p/%s count=%u\n",
        label, CNDIconInspectPointer(icon), CNDIconInspectClass(icon),
        CNDIconInspectPointer(cache), CNDIconInspectClass(cache),
        CNDIconInspectPointer(result), CNDIconInspectClass(result),
        gCNDIconInspectEventCount);
    CNDIconInspectLogDescriptor(label, descriptor);
    CNDIconInspectLogImage(label, result);
    CNDIconInspectLogImageCacheState(label, cache);
}

static id CNDHookConcreteImageGet(id self, SEL command, id descriptor)
{
    id result = ((id (*)(id, SEL, id))gOriginalConcreteImageGet)(
        self, command, descriptor);
    CNDIconInspectLogConcreteLookup(
        "concrete-image-return", self, descriptor, result);
    return result;
}

static id CNDHookConcreteCachedImageGet(id self, SEL command, id descriptor)
{
    id result = ((id (*)(id, SEL, id))gOriginalConcreteCachedImageGet)(
        self, command, descriptor);
    CNDIconInspectLogConcreteLookup(
        "concrete-cache-return", self, descriptor, result);
    return result;
}

static id CNDHookConcreteStoreImageGet(id self, SEL command, id descriptor)
{
    id result = ((id (*)(id, SEL, id))gOriginalConcreteStoreImageGet)(
        self, command, descriptor);
    CNDIconInspectLogConcreteLookup(
        "concrete-store-return", self, descriptor, result);
    return result;
}

static void CNDHookServiceGenerate(id self, SEL command, id request, id reply)
{
    gCNDIconInspectEventCount++;
    CNDIconInspectLogRequest("service-generate-enter", request);
    ((void (*)(id, SEL, id, id))gOriginalServiceGenerate)(
        self, command, request, reply);
    CNDIconInspectLog("[CND_ICON_AGENT] event service-generate-return "
                      "service=%p/%s count=%u\n",
                      CNDIconInspectPointer(self), CNDIconInspectClass(self),
                      gCNDIconInspectEventCount);
}

static id CNDHookServiceGenerateUnit(id self, SEL command, id request,
                                     id *validationTokenOut)
{
    gCNDIconInspectEventCount++;
    CNDIconInspectLogRequest("generate-unit-enter", request);
    id result = ((id (*)(id, SEL, id, id *))gOriginalServiceGenerateUnit)(
        self, command, request, validationTokenOut);
    id validationToken = validationTokenOut ? *validationTokenOut : nil;
    NSData *token = [validationToken isKindOfClass:NSData.class]
        ? validationToken : nil;
    CNDIconInspectLog("[CND_ICON_AGENT] generation-token object=%p/%s "
                      "out=%p bytes=%lu sha256=%s\n",
                      CNDIconInspectPointer(validationToken),
                      CNDIconInspectClass(validationToken),
                      validationTokenOut,
                      (unsigned long)token.length,
                      CNDIconInspectSHA256(token).UTF8String);
    CNDIconInspectLogStoreUnit("generate-unit-return", nil, result);
    CNDIconInspectLogImage("generate-unit-return", result);
    return result;
}

static id CNDHookGenerationRequestGenerate(id self, SEL command,
                                           id *recordIdentifiersOut)
{
    gCNDIconInspectEventCount++;
    CNDIconInspectLogRequest("generation-request-enter", self);
    id result = ((id (*)(id, SEL, id *))gOriginalGenerationRequestGenerate)(
        self, command, recordIdentifiersOut);
    id recordIdentifiers = recordIdentifiersOut ? *recordIdentifiersOut : nil;
    CNDIconInspectLog(
        "[CND_ICON_AGENT] event generation-request-return request=%p/%s "
        "recordsOut=%p records=%p/%s count=%u\n",
        CNDIconInspectPointer(self), CNDIconInspectClass(self),
        recordIdentifiersOut, CNDIconInspectPointer(recordIdentifiers),
        CNDIconInspectClass(recordIdentifiers), gCNDIconInspectEventCount);
    if ([recordIdentifiers isKindOfClass:NSArray.class]) {
        NSArray *records = recordIdentifiers;
        NSUInteger count = MIN(records.count, (NSUInteger)8U);
        for (NSUInteger i = 0; i < count; i++) {
            id record = records[i];
            NSString *description = nil;
            @try {
                description = [record description];
            } @catch (__unused NSException *exception) {
                description = @"<description-failed>";
            }
            NSString *safeDescription = description ?: @"-";
            description = [safeDescription
                stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
            if (description.length > 768U) {
                description = [[description substringToIndex:768U]
                    stringByAppendingString:@"..."];
            }
            CNDIconInspectLog(
                "[CND_ICON_AGENT] record index=%lu object=%p/%s value=%s\n",
                (unsigned long)i, CNDIconInspectPointer(record),
                CNDIconInspectClass(record), description.UTF8String);
        }
    }
    CNDIconInspectLogImage("generation-request-return", result);
    return result;
}

static id CNDHookStoreLookup(id self, SEL command, id uuid)
{
    id result = ((id (*)(id, SEL, id))gOriginalStoreLookup)(
        self, command, uuid);
    gCNDIconInspectEventCount++;
    CNDIconInspectLogStoreUnit("unitForUUID", self, result);
    return result;
}

static BOOL CNDHookStoreWrite(id self, SEL command, id unit)
{
    gCNDIconInspectEventCount++;
    CNDIconInspectLogStoreUnit("write-before", self, unit);
    BOOL result = ((BOOL (*)(id, SEL, id))gOriginalStoreWrite)(
        self, command, unit);
    CNDIconInspectLogStoreUnit("write-after", self, unit);
    CNDIconInspectLog("[CND_ICON_AGENT] event write-result=%d count=%u\n",
                      result, gCNDIconInspectEventCount);
    return result;
}

static id CNDHookStoreAddData(id self, SEL command, id data)
{
    NSData *bytes = [data isKindOfClass:NSData.class] ? data : nil;
    CNDIconInspectLog("[CND_ICON_AGENT] event addUnitWithData-enter "
                      "data=%lu/%s\n", (unsigned long)bytes.length,
                      CNDIconInspectSHA256(bytes).UTF8String);
    id result = ((id (*)(id, SEL, id))gOriginalStoreAddData)(
        self, command, data);
    gCNDIconInspectEventCount++;
    CNDIconInspectLogStoreUnit("addUnitWithData-return", self, result);
    return result;
}

static id CNDHookResponseInit(id self, SEL command, id data, id uuid, id token)
{
    id result = ((id (*)(id, SEL, id, id, id))gOriginalResponseInit)(
        self, command, data, uuid, token);
    gCNDIconInspectEventCount++;
    CNDIconInspectLogImage("ISGenerationResponse-init", result);
    return result;
}

static id CNDHookCacheImageInit(id self, SEL command, id data, id uuid,
                                id token)
{
    id result = ((id (*)(id, SEL, id, id, id))gOriginalCacheImageInit)(
        self, command, data, uuid, token);
    gCNDIconInspectEventCount++;
    CNDIconInspectLogImage("IFCacheImage-init", result);
    return result;
}

static id CNDHookProviderMake(id self, SEL command, BOOL allowFallback)
{
    id bundle = CNDIconInspectObjectGetter(self, "bundleIdentifier");
    id result = ((id (*)(id, SEL, BOOL))gOriginalProviderMake)(
        self, command, allowFallback);
    gCNDIconInspectEventCount++;
    CNDIconInspectLog("[CND_ICON_AGENT] event provider-make icon=%p/%s "
                      "bundle=%s fallback=%d provider=%p/%s count=%u\n",
                      CNDIconInspectPointer(self), CNDIconInspectClass(self),
                      [bundle isKindOfClass:NSString.class]
                        ? [bundle UTF8String] : "-",
                      allowFallback, CNDIconInspectPointer(result),
                      CNDIconInspectClass(result), gCNDIconInspectEventCount);
    return result;
}

static void CNDHookProviderResolve(id self, SEL command)
{
    gCNDIconInspectEventCount++;
    CNDIconInspectLog("[CND_ICON_AGENT] event provider-resolve-enter "
                      "provider=%p/%s\n", CNDIconInspectPointer(self),
                      CNDIconInspectClass(self));
    ((void (*)(id, SEL))gOriginalProviderResolve)(self, command);
    CNDIconInspectLog("[CND_ICON_AGENT] event provider-resolve-return "
                      "provider=%p/%s\n", CNDIconInspectPointer(self),
                      CNDIconInspectClass(self));
}

static void CNDHookClearCachedItems(id self, SEL command, id bundleIdentifier,
                                    id reply)
{
    gCNDIconInspectEventCount++;
    int callerPID = CNDIconInspectCurrentXPCProcessIdentifier();
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle invalidation-enter monoNS=%llu "
        "kind=bundle callerPID=%d service=%p/%s bundle=%s count=%u\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(), callerPID,
        CNDIconInspectPointer(self), CNDIconInspectClass(self),
        [bundleIdentifier isKindOfClass:NSString.class]
            ? [bundleIdentifier UTF8String] : "-",
        gCNDIconInspectEventCount);
    CNDIconInspectLogCurrentApplicationRecord(
        "bundle-invalidation-before", false);
    CNDIconInspectLogManagerState("bundle-invalidation-before");
    ((void (*)(id, SEL, id, id))gOriginalClearCachedItems)(
        self, command, bundleIdentifier, reply);
    CNDIconInspectLogManagerState("bundle-invalidation-return");
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle invalidation-return monoNS=%llu "
        "kind=bundle callerPID=%d bundle=%s\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(), callerPID,
        [bundleIdentifier isKindOfClass:NSString.class]
            ? [bundleIdentifier UTF8String] : "-");
}

static void CNDHookClearAllCachedItems(id self, SEL command, id reply)
{
    gCNDIconInspectEventCount++;
    int callerPID = CNDIconInspectCurrentXPCProcessIdentifier();
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle invalidation-enter monoNS=%llu "
        "kind=all callerPID=%d service=%p/%s count=%u\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(), callerPID,
        CNDIconInspectPointer(self), CNDIconInspectClass(self),
        gCNDIconInspectEventCount);
    CNDIconInspectLogCurrentApplicationRecord("clear-all-before", false);
    CNDIconInspectLogManagerState("clear-all-before");
    ((void (*)(id, SEL, id))gOriginalClearAllCachedItems)(
        self, command, reply);
    CNDIconInspectLogManagerState("clear-all-return");
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle invalidation-return monoNS=%llu "
        "kind=all callerPID=%d\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(), callerPID);
}

static void CNDHookFetchCacheConfiguration(id self, SEL command, id reply)
{
    gCNDIconInspectEventCount++;
    int callerPID = CNDIconInspectCurrentXPCProcessIdentifier();
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle fetch-configuration-enter monoNS=%llu "
        "callerPID=%d service=%p/%s count=%u\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(), callerPID,
        CNDIconInspectPointer(self), CNDIconInspectClass(self),
        gCNDIconInspectEventCount);
    ((void (*)(id, SEL, id))gOriginalFetchCacheConfiguration)(
        self, command, reply);
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle fetch-configuration-return monoNS=%llu "
        "callerPID=%d\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(), callerPID);
}

static void CNDHookScheduleCacheOperation(id self, SEL command,
                                          uint64_t operation)
{
    gCNDIconInspectEventCount++;
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle schedule monoNS=%llu service=%p/%s "
        "operation=%llu meaning=%s callerPID=%d count=%u\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(),
        CNDIconInspectPointer(self), CNDIconInspectClass(self),
        (unsigned long long)operation,
        operation == 1ULL ? "collect-garbage" :
            (operation == 2ULL ? "clear-all" : "unknown"),
        CNDIconInspectCurrentXPCProcessIdentifier(),
        gCNDIconInspectEventCount);
    ((void (*)(id, SEL, uint64_t))gOriginalScheduleCacheOperation)(
        self, command, operation);
}

static void CNDHookMutableCacheClear(id self, SEL command)
{
    gCNDIconInspectEventCount++;
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle clear-enter monoNS=%llu cache=%p/%s "
        "count=%u\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(),
        CNDIconInspectPointer(self), CNDIconInspectClass(self),
        gCNDIconInspectEventCount);
    CNDIconInspectLogCurrentApplicationRecord("clear-before", false);
    CNDIconInspectLogManagerState("mutable-cache-clear-before");
    ((void (*)(id, SEL))gOriginalMutableCacheClear)(self, command);
    CNDIconInspectLogCurrentApplicationRecord("clear-after", false);
    CNDIconInspectLogManagerState("mutable-cache-clear-after");
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle clear-return monoNS=%llu cache=%p/%s\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(),
        CNDIconInspectPointer(self), CNDIconInspectClass(self));
}

static id CNDHookLSRecordInit(id self, SEL command, id identifier)
{
    id result = ((id (*)(id, SEL, id))gOriginalLSRecordInit)(
        self, command, identifier);
    CNDIconInspectGarbageCollectionState *state =
        &gCNDIconInspectGarbageCollectionState;
    if (!state->active) return result;

    state->checkedRecords++;
    state->lastInvalidIdentifierLength = 0U;
    memset(state->lastInvalidIdentifier, 0,
           sizeof(state->lastInvalidIdentifier));
    NSData *data = [identifier isKindOfClass:NSData.class] ? identifier : nil;
    if (result) {
        state->validRecords++;
        return result;
    }

    state->invalidRecords++;
    size_t length = MIN((size_t)data.length,
                        CNDIconInspectMaximumPersistentIdentifierLength);
    if (length > 0U) {
        memcpy(state->lastInvalidIdentifier, data.bytes, length);
        state->lastInvalidIdentifierLength = length;
    }
    CNDIconInspectLogPersistentIdentifier(
        "gc-invalid-source", data, nil, nil,
        CNDIconInspectInvalidReason(data));
    return result;
}

static BOOL CNDHookStoreRemove(id self, SEL command, id uuid)
{
    CNDIconInspectGarbageCollectionState *state =
        &gCNDIconInspectGarbageCollectionState;
    NSData *source = state->active && state->lastInvalidIdentifierLength > 0U
        ? [NSData dataWithBytes:state->lastInvalidIdentifier
                         length:state->lastInvalidIdentifierLength]
        : nil;
    id unit = gOriginalStoreLookup
        ? ((id (*)(id, SEL, id))gOriginalStoreLookup)(
            self, sel_registerName("unitForUUID:"), uuid)
        : nil;
    gCNDIconInspectEventCount++;
    CNDIconInspectLogStoreUnit("remove-before", self, unit);
    if (source) {
        CNDIconInspectLogPersistentIdentifier(
            "gc-remove-source", source, uuid, nil,
            CNDIconInspectInvalidReason(source));
    }
    BOOL result = ((BOOL (*)(id, SEL, id))gOriginalStoreRemove)(
        self, command, uuid);
    if (state->active) state->removedUnits++;
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle remove-unit monoNS=%llu cycle=%llu "
        "mode=%s store=%p/%s uuid=%s result=%d sourcePresent=%d count=%u\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(),
        (unsigned long long)state->cycle,
        state->active ? "collect-garbage" : "other",
        CNDIconInspectPointer(self), CNDIconInspectClass(self),
        CNDIconInspectUUIDText(uuid).UTF8String, result, source != nil,
        gCNDIconInspectEventCount);
    state->lastInvalidIdentifierLength = 0U;
    memset(state->lastInvalidIdentifier, 0,
           sizeof(state->lastInvalidIdentifier));
    return result;
}

static void CNDHookCollectGarbage(id self, SEL command)
{
    CNDIconInspectGarbageCollectionState *state =
        &gCNDIconInspectGarbageCollectionState;
    memset(state, 0, sizeof(*state));
    state->active = true;
    state->cycle = __sync_add_and_fetch(
        &gCNDIconInspectGarbageCollectionCycle, 1ULL);
    gCNDIconInspectEventCount++;
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle gc-enter monoNS=%llu cycle=%llu "
        "cache=%p/%s count=%u\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(),
        (unsigned long long)state->cycle, CNDIconInspectPointer(self),
        CNDIconInspectClass(self), gCNDIconInspectEventCount);
    CNDIconInspectLogCurrentApplicationRecord("gc-before", true);
    CNDIconInspectLogManagerState("gc-before");
    ((void (*)(id, SEL))gOriginalCollectGarbage)(self, command);
    CNDIconInspectLogCurrentApplicationRecord("gc-after", false);
    CNDIconInspectLogManagerState("gc-after");
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle gc-return monoNS=%llu cycle=%llu "
        "checked=%u valid=%u invalid=%u removed=%u currentDatabaseGUID=%s\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(),
        (unsigned long long)state->cycle, state->checkedRecords,
        state->validRecords, state->invalidRecords, state->removedUnits,
        state->currentDatabaseGUIDKnown
            ? [[NSUUID alloc]
                initWithUUIDBytes:state->currentDatabaseGUID].UUIDString.UTF8String
            : "-");
    state->active = false;
}

static void CNDHookRegisterRecordIdentifiers(id self, SEL command,
                                             id identifiers, id unit)
{
    id uuid = CNDIconInspectObjectGetter(unit, "UUID");
    if (!uuid) uuid = CNDIconInspectObjectGetter(unit, "uuid");
    NSUInteger observed = 0U;
    if ([identifiers conformsToProtocol:@protocol(NSFastEnumeration)]) {
        for (id candidate in identifiers) {
            if (observed >= 8U) break;
            NSData *identifier = [candidate isKindOfClass:NSData.class]
                ? candidate : nil;
            CNDIconInspectLogPersistentIdentifier(
                "register-source", identifier, uuid, nil, "registered");
            observed++;
        }
    }
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle register-sources monoNS=%llu "
        "cache=%p/%s unit=%p/%s uuid=%s identifiers=%p/%s "
        "count=%lu observed=%lu capped=%d\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(),
        CNDIconInspectPointer(self), CNDIconInspectClass(self),
        CNDIconInspectPointer(unit), CNDIconInspectClass(unit),
        CNDIconInspectUUIDText(uuid).UTF8String,
        CNDIconInspectPointer(identifiers), CNDIconInspectClass(identifiers),
        (unsigned long)[identifiers respondsToSelector:@selector(count)]
            ? (unsigned long)[identifiers count] : 0UL,
        (unsigned long)observed,
        [identifiers respondsToSelector:@selector(count)] &&
            [identifiers count] > observed);
    ((void (*)(id, SEL, id, id))gOriginalRegisterRecordIdentifiers)(
        self, command, identifiers, unit);
}

static void CNDHookClearOperationRun(id self, SEL command)
{
    bool operationKnown = false;
    uint64_t operation = CNDIconInspectUnsignedGetter(
        self, "operation", &operationKnown);
    id cache = CNDIconInspectObjectGetter(self, "cache");
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle operation-run-enter monoNS=%llu "
        "object=%p/%s operation=%llu/%d meaning=%s cache=%p/%s\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(),
        CNDIconInspectPointer(self), CNDIconInspectClass(self),
        (unsigned long long)operation, operationKnown,
        operation == 1ULL ? "collect-garbage" :
            (operation == 2ULL ? "clear-all" : "unknown"),
        CNDIconInspectPointer(cache), CNDIconInspectClass(cache));
    CNDIconInspectLogManagerState("operation-run-before");
    ((void (*)(id, SEL))gOriginalClearOperationRun)(self, command);
    CNDIconInspectLogManagerState("operation-run-after");
    CNDIconInspectLog(
        "[CND_ICON_AGENT] lifecycle operation-run-return monoNS=%llu "
        "object=%p/%s operation=%llu/%d\n",
        (unsigned long long)CNDIconInspectMonotonicNanoseconds(),
        CNDIconInspectPointer(self), CNDIconInspectClass(self),
        (unsigned long long)operation, operationKnown);
}

static bool CNDIconInstallHook(const char *className, const char *selectorName,
                               IMP replacement, IMP *original,
                               char expectedReturn, unsigned arguments)
{
    if (*original) return true;
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    if (!method) return false;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDIconInspectSkipQualifiers(returnType);
    bool abi = type && *type == expectedReturn &&
        method_getNumberOfArguments(method) == arguments + 2U;
    CNDIconInspectLog(
        "[CND_ICON_AGENT] hook-check class=%s selector=%s types=%s "
        "return=%c args=%u accepted=%d\n", className, selectorName,
        method_getTypeEncoding(method) ?: "-", expectedReturn, arguments, abi);
    free(returnType);
    if (!abi) return false;
    IMP implementation = method_getImplementation(method);
    const char *types = method_getTypeEncoding(method);
    if (!class_addMethod(cls, selector, replacement, types)) {
        method_setImplementation(method, replacement);
    }
    *original = implementation;
    CNDIconInspectLog("[CND_ICON_AGENT] hook-installed class=%s selector=%s "
                      "original=%p replacement=%p\n",
                      className, selectorName, implementation, replacement);
    return true;
}

static unsigned CNDIconInstallHooks(void)
{
    unsigned count = 0U;
    count += CNDIconInstallHook(
        "ISIconManager", "findOrRegisterIcon:",
        (IMP)CNDHookIconManagerFindOrRegister,
        &gOriginalIconManagerFindOrRegister, '@', 1U);
    count += CNDIconInstallHook(
        "ISImageCache", "imageForDescriptor:",
        (IMP)CNDHookImageCacheGet, &gOriginalImageCacheGet, '@', 1U);
    count += CNDIconInstallHook(
        "ISImageCache", "setImage:forDescriptor:",
        (IMP)CNDHookImageCacheSet, &gOriginalImageCacheSet, 'v', 2U);
    count += CNDIconInstallHook(
        "ISImageCache", "setImageBagsByDescriptor:",
        (IMP)CNDHookImageCacheSetBags, &gOriginalImageCacheSetBags, 'v', 1U);
    count += CNDIconInstallHook(
        "ISConcreteIcon", "imageForDescriptor:",
        (IMP)CNDHookConcreteImageGet, &gOriginalConcreteImageGet, '@', 1U);
    count += CNDIconInstallHook(
        "ISConcreteIcon", "_cachedImageForDescriptor:",
        (IMP)CNDHookConcreteCachedImageGet,
        &gOriginalConcreteCachedImageGet, '@', 1U);
    count += CNDIconInstallHook(
        "ISConcreteIcon", "_imageFromStoreForDescriptor:",
        (IMP)CNDHookConcreteStoreImageGet,
        &gOriginalConcreteStoreImageGet, '@', 1U);
    count += CNDIconInstallHook(
        "IconCacheService", "generateImageWithRequest:reply:",
        (IMP)CNDHookServiceGenerate, &gOriginalServiceGenerate, 'v', 2U);
    count += CNDIconInstallHook(
        "IconCacheService", "generateStoreUnitWithRequest:validationToken:",
        (IMP)CNDHookServiceGenerateUnit, &gOriginalServiceGenerateUnit, '@', 2U);
    count += CNDIconInstallHook(
        "ISStore", "unitForUUID:", (IMP)CNDHookStoreLookup,
        &gOriginalStoreLookup, '@', 1U);
    count += CNDIconInstallHook(
        "ISStore", "writeStoreUnit:", (IMP)CNDHookStoreWrite,
        &gOriginalStoreWrite, 'B', 1U);
    count += CNDIconInstallHook(
        "ISStore", "addUnitWithData:", (IMP)CNDHookStoreAddData,
        &gOriginalStoreAddData, '@', 1U);
    count += CNDIconInstallHook(
        "ISGenerationResponse", "initWithData:uuid:validationToken:",
        (IMP)CNDHookResponseInit, &gOriginalResponseInit, '@', 3U);
    count += CNDIconInstallHook(
        "IFCacheImage", "initWithData:uuid:validationToken:",
        (IMP)CNDHookCacheImageInit, &gOriginalCacheImageInit, '@', 3U);
    count += CNDIconInstallHook(
        "ISBundleIdentifierIcon",
        "_makeResourceProviderAllowIconResourceFallback:",
        (IMP)CNDHookProviderMake, &gOriginalProviderMake, '@', 1U);
    count += CNDIconInstallHook(
        "ISRecordResourceProvider", "resolveResources",
        (IMP)CNDHookProviderResolve, &gOriginalProviderResolve, 'v', 0U);
    count += CNDIconInstallHook(
        "ISGenerationRequest", "generateImageReturningRecordIdentifiers:",
        (IMP)CNDHookGenerationRequestGenerate,
        &gOriginalGenerationRequestGenerate, '@', 1U);
    count += CNDIconInstallHook(
        "IconCacheService", "clearCachedItemsForBundeID:reply:",
        (IMP)CNDHookClearCachedItems, &gOriginalClearCachedItems, 'v', 2U);
    count += CNDIconInstallHook(
        "IconCacheService", "clearAllCachedItemsWithReply:",
        (IMP)CNDHookClearAllCachedItems, &gOriginalClearAllCachedItems, 'v', 1U);
    count += CNDIconInstallHook(
        "IconCacheService", "fetchCacheConfigurationWithReply:",
        (IMP)CNDHookFetchCacheConfiguration,
        &gOriginalFetchCacheConfiguration, 'v', 1U);
    count += CNDIconInstallHook(
        "IconCacheService", "scheduleCacheOperation:",
        (IMP)CNDHookScheduleCacheOperation,
        &gOriginalScheduleCacheOperation, 'v', 1U);
    count += CNDIconInstallHook(
        "ISMutableIconCache", "clear", (IMP)CNDHookMutableCacheClear,
        &gOriginalMutableCacheClear, 'v', 0U);
    count += CNDIconInstallHook(
        "ISMutableIconCache", "collectGarbage", (IMP)CNDHookCollectGarbage,
        &gOriginalCollectGarbage, 'v', 0U);
    count += CNDIconInstallHook(
        "ISMutableIconCache", "registerRecordIdentifiers:asSourceForUnit:",
        (IMP)CNDHookRegisterRecordIdentifiers,
        &gOriginalRegisterRecordIdentifiers, 'v', 2U);
    count += CNDIconInstallHook(
        "ISStore", "removeUnitForUUID:", (IMP)CNDHookStoreRemove,
        &gOriginalStoreRemove, 'B', 1U);
    count += CNDIconInstallHook(
        "LSRecord", "initWithPersistentIdentifier:",
        (IMP)CNDHookLSRecordInit, &gOriginalLSRecordInit, '@', 1U);
    count += CNDIconInstallHook(
        "ClearCacheOperation", "run", (IMP)CNDHookClearOperationRun,
        &gOriginalClearOperationRun, 'v', 0U);
    return count;
}

static void CNDIconInspectionPoll(unsigned attempt)
{
    static bool loggedInitialIdentity;
    unsigned hooks = CNDIconInstallHooks();
    if (hooks >= CNDIconInspectExpectedHookCount && !loggedInitialIdentity) {
        loggedInitialIdentity = true;
        CNDIconInspectLogCurrentApplicationRecord("inspector-ready", false);
        CNDIconInspectLogManagerState("inspector-ready");
    }
    if (attempt == 1U || hooks >= CNDIconInspectExpectedHookCount ||
        attempt == 80U) {
        CNDIconInspectLog("[CND_ICON_AGENT] TRACE_READY pid=%d attempt=%u "
                          "hooks=%u expected=%u events=%u target=%s\n",
                          getpid(), attempt, hooks,
                          CNDIconInspectExpectedHookCount,
                          gCNDIconInspectEventCount,
                          CND_ICON_INSPECT_TARGET_BUNDLE);
    }
    if (attempt < 80U && hooks < CNDIconInspectExpectedHookCount) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)(250 * NSEC_PER_MSEC)),
                       dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            CNDIconInspectionPoll(attempt + 1U);
        });
    }
}

__attribute__((constructor))
static void CNDIconInspectionStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t outputHandle = CND_ICON_INSPECT_OUTPUT_TOKEN[0] && consume
            ? consume(CND_ICON_INSPECT_OUTPUT_TOKEN) : -1;
        int64_t rootHandle = CND_ICON_INSPECT_ROOT_TOKEN[0] && consume
            ? consume(CND_ICON_INSPECT_ROOT_TOKEN) : -1;
        gCNDIconInspectFD = open(CNDIconInspectOutputPath,
                                 O_WRONLY | O_CREAT | O_TRUNC, 0644);
        CNDIconInspectLog("[CND_ICON_AGENT] START pid=%d process=%s "
                          "outputToken=%lld rootToken=%lld mode=trace-only\n",
                          getpid(), getprogname(), (long long)outputHandle,
                          (long long)rootHandle);
        static const char *const surfaces[] = {
            "IconCacheService", "ISGenerationRequest",
            "ISGenerationResponse", "ISStore", "ISStoreUnit",
            "IFCacheImage", "ISBundleIdentifierIcon",
            "ISRecordResourceProvider", "ISMutableIconCache",
            "ISStoreMapTable", "LSRecord", "LSApplicationRecord",
            "ClearCacheOperation", "ISIconManager", "ISImageCache",
            "ISConcreteIcon", "ISImageDescriptor"
        };
        for (size_t i = 0; i < sizeof(surfaces) / sizeof(surfaces[0]); i++) {
            CNDIconInspectDumpSurface(surfaces[i]);
        }
        CNDIconInspectLogExactMethod(
            "LSApplicationRecord",
            "initWithBundleIdentifier:allowPlaceholder:error:", false);
        CNDIconInspectLogExactMethod(
            "LSBundleRecord",
            "bundleRecordWithBundleIdentifier:allowPlaceholder:error:",
            true);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            @autoreleasepool {
                CNDIconInspectionPoll(1U);
            }
        });
    }
}
