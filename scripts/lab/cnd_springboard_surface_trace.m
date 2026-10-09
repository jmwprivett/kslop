#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <objc/runtime.h>
#import <objc/message.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef CND_SURFACE_TRACE_OUTPUT_TOKEN
#define CND_SURFACE_TRACE_OUTPUT_TOKEN ""
#endif

#ifndef CND_SURFACE_TRACE_OUTPUT_PATH
#define CND_SURFACE_TRACE_OUTPUT_PATH \
    "/var/tmp/cyanide-springboard-surface-trace.log"
#endif

#ifndef CND_SURFACE_TRACE_OPEN_BUNDLE
#define CND_SURFACE_TRACE_OPEN_BUNDLE ""
#endif

#ifndef CND_SURFACE_TRACE_TARGET_BUNDLE
#define CND_SURFACE_TRACE_TARGET_BUNDLE "com.ebay.iphone"
#endif

static int gCNDSurfaceTraceFD = -1;
static __thread unsigned gCNDSurfaceTraceSwitcherDepth;

typedef enum {
    CNDSurfaceTraceScopeNone = 0,
    CNDSurfaceTraceScopeAppLibraryCategory = 1,
    CNDSurfaceTraceScopeAppLibraryList = 2,
    CNDSurfaceTraceScopeFolderPreview = 3,
} CNDSurfaceTraceScope;

typedef struct {
    CNDSurfaceTraceScope scope;
    uint64_t correlation;
    __unsafe_unretained id owner;
    __unsafe_unretained id icon;
    __unsafe_unretained id consumer;
} CNDSurfaceTraceContext;

typedef struct {
    CGSize size;
    double scale;
    double continuousCornerRadius;
} CNDIconImageInfo;

_Static_assert(sizeof(CNDIconImageInfo) == 32,
               "SBIconImageInfo ABI changed");

static __thread CNDSurfaceTraceContext gCNDSurfaceTraceContext;

typedef id (*CNDObjectOneArgumentIMP)(id, SEL, id);
typedef void (*CNDVoidObjectIMP)(id, SEL, id);
typedef id (*CNDImageForIconIMP)(id, SEL, id, id, NSUInteger);
typedef void (*CNDVoidNoArgumentIMP)(id, SEL);
typedef void (*CNDVoidTwoArgumentIMP)(id, SEL, NSInteger, BOOL);
typedef void (*CNDVoidIconViewIMP)(id, SEL, id, id);
typedef id (*CNDFolderGridImageIMP)(id, SEL, id, id);
typedef id (*CNDFolderGridRendererIMP)(id, SEL, CGSize, id,
                                       CNDIconImageInfo, id,
                                       const uint64_t *);
typedef id (*CNDFolderGridCompositorIMP)(id, SEL, CGSize, id);
typedef void (*CNDVoidBooleanIMP)(id, SEL, BOOL);
typedef void (*CNDVoidObjectBooleanIMP)(id, SEL, id, BOOL);
typedef BOOL (*CNDBooleanBooleanIMP)(id, SEL, BOOL);
typedef void (*CNDVoidObjectObjectBooleanIMP)(id, SEL, id, id, BOOL);
typedef void (*CNDVoidObjectUIntegerIMP)(id, SEL, id, NSUInteger);
typedef void (*CNDVoidObjectPointUIntegerIMP)(id, SEL, id, CGPoint,
                                              NSUInteger);
typedef NSUInteger (*CNDUIntegerNoArgumentIMP)(id, SEL);
typedef void (*CNDVoidThreeObjectsIMP)(id, SEL, id, id, id);

static CNDObjectOneArgumentIMP gCNDOriginalSwitcherImage;
static CNDImageForIconIMP gCNDOriginalImageForIcon;
static CNDVoidNoArgumentIMP gCNDOriginalResetAllCaches;
static CNDVoidNoArgumentIMP gCNDOriginalPurgeAllImages;
static CNDVoidNoArgumentIMP gCNDOriginalNotificationUpdate;
static CNDVoidNoArgumentIMP gCNDOriginalLibraryReload;
static CNDVoidNoArgumentIMP gCNDOriginalLibraryEnqueue;
static CNDVoidTwoArgumentIMP gCNDOriginalLibraryLayout;
static CNDVoidNoArgumentIMP gCNDOriginalFolderRebuild;
static CNDVoidIconViewIMP gCNDOriginalLibraryConfigure;
static CNDVoidIconViewIMP gCNDOriginalLibraryListConfigure;
static CNDVoidObjectIMP gCNDOriginalLibraryListCellConfigure;
static CNDVoidNoArgumentIMP gCNDOriginalLibraryListReloadVisible;
static CNDVoidNoArgumentIMP gCNDOriginalLibraryListReloadApps;
static CNDVoidObjectIMP gCNDOriginalLibraryListRefreshIcon;
static CNDVoidBooleanIMP gCNDOriginalLibrarySearchSetActive;
static CNDFolderGridImageIMP gCNDOriginalFolderGridImage;
static CNDFolderGridRendererIMP gCNDOriginalFolderGridRenderer;
static CNDFolderGridCompositorIMP gCNDOriginalFolderGridCompositor;
static CNDVoidBooleanIMP gCNDOriginalIconViewUpdate;
static CNDVoidObjectIMP gCNDOriginalIconViewCrossfade;
static CNDVoidObjectUIntegerIMP gCNDOriginalIconViewCrossfadeOptions;
static CNDVoidObjectPointUIntegerIMP
    gCNDOriginalIconViewCrossfadeAnchorOptions;
static CNDBooleanBooleanIMP gCNDOriginalImageUpdateFromCache;
static CNDVoidObjectObjectBooleanIMP gCNDOriginalImageUpdateContents;
static CNDVoidObjectIMP gCNDOriginalSetDisplayedImage;
static CNDVoidNoArgumentIMP gCNDOriginalCrossfadePrepareGeometry;
static CNDVoidNoArgumentIMP gCNDOriginalDoubleCrossfadePrepareGeometry;
static CNDVoidNoArgumentIMP gCNDOriginalIconReloadImage;
static CNDVoidNoArgumentIMP gCNDOriginalIconNotifyImageUpdate;
static CNDVoidObjectIMP gCNDOriginalIconUpdateLayerView;
static CNDVoidObjectIMP gCNDOriginalFolderIconUpdateLayerView;
static CNDVoidNoArgumentIMP gCNDOriginalFolderIconReloadImage;
static CNDVoidObjectIMP gCNDOriginalCacheBeginObservingIcon;
static CNDVoidObjectIMP gCNDOriginalCacheIconImageDidUpdate;
static CNDVoidObjectIMP gCNDOriginalCacheUpdateImageForIcon;
static CNDVoidThreeObjectsIMP gCNDOriginalCacheImage;
static CNDVoidObjectIMP gCNDOriginalImageViewIconImageDidUpdate;
static CNDVoidThreeObjectsIMP gCNDOriginalImageViewCacheDidUpdate;
static CNDVoidBooleanIMP gCNDOriginalImageViewUpdateImage;
static CNDVoidObjectBooleanIMP gCNDOriginalImageViewLoadFromCache;
static CNDVoidNoArgumentIMP gCNDOriginalImageViewClearCachedImages;
static IMP gCNDOriginalISImageForDescriptor;
static IMP gCNDOriginalISGenerateForDescriptor;

static _Atomic uint64_t gCNDSurfaceTraceSequence;
static _Atomic uint64_t gCNDSurfaceTraceCorrelation;
static _Atomic uint64_t gCNDSurfaceTraceDescriptorEvents;
static _Atomic uint64_t gCNDSurfaceTraceDescriptorSamples;
static _Atomic uint64_t gCNDSurfaceTraceCompositeSamples;

static void CNDSurfaceTraceLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDSurfaceTraceCaptureDescriptorImage(const char *phase,
                                                   id icon, id descriptor,
                                                   id image);

static void CNDSurfaceTraceLog(const char *format, ...)
{
    if (gCNDSurfaceTraceFD < 0) return;
    char line[4096] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDSurfaceTraceFD, line, amount);
}

static NSString *CNDSurfaceTraceIdentifier(id icon)
{
    if (!icon) return @"-";
    static const char *const selectors[] = {
        "applicationBundleID", "bundleIdentifier", "uniqueIdentifier",
        "displayName",
    };
    for (size_t index = 0;
         index < sizeof(selectors) / sizeof(selectors[0]); index++) {
        SEL selector = sel_registerName(selectors[index]);
        if (![icon respondsToSelector:selector]) continue;
        id value = ((id (*)(id, SEL))objc_msgSend)(icon, selector);
        if ([value isKindOfClass:NSString.class] && [value length]) {
            return value;
        }
    }
    return [NSString stringWithFormat:@"%@:%p",
            NSStringFromClass([icon class]), icon];
}

static uint64_t CNDSurfaceTraceGeneration(id object)
{
    if (!object) return UINT64_MAX;
    SEL selector = sel_registerName("imageGeneration");
    if (![object respondsToSelector:selector]) return UINT64_MAX;
    return ((NSUInteger (*)(id, SEL))objc_msgSend)(object, selector);
}

static uint64_t CNDSurfaceTraceNowUS(void)
{
    struct timespec time = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &time);
    return (uint64_t)time.tv_sec * 1000000ULL +
        (uint64_t)time.tv_nsec / 1000ULL;
}

static const char *CNDSurfaceTraceScopeName(CNDSurfaceTraceScope scope)
{
    switch (scope) {
        case CNDSurfaceTraceScopeAppLibraryCategory:
            return "app-library-category";
        case CNDSurfaceTraceScopeAppLibraryList:
            return "app-library-list";
        case CNDSurfaceTraceScopeFolderPreview:
            return "folder-preview";
        case CNDSurfaceTraceScopeNone:
        default:
            return "none";
    }
}

static CNDSurfaceTraceContext CNDSurfaceTracePushContext(
    CNDSurfaceTraceScope scope, id owner, id icon, id consumer)
{
    CNDSurfaceTraceContext previous = gCNDSurfaceTraceContext;
    uint64_t correlation = atomic_fetch_add_explicit(
        &gCNDSurfaceTraceCorrelation, 1U, memory_order_relaxed) + 1U;
    gCNDSurfaceTraceContext = (CNDSurfaceTraceContext){
        .scope = scope,
        .correlation = correlation,
        .owner = owner,
        .icon = icon,
        .consumer = consumer,
    };
    return previous;
}

static void CNDSurfaceTracePopContext(CNDSurfaceTraceContext previous)
{
    gCNDSurfaceTraceContext = previous;
}

static void CNDSurfaceTraceLogEventPrefix(const char *event)
{
    uint64_t sequence = atomic_fetch_add_explicit(
        &gCNDSurfaceTraceSequence, 1U, memory_order_relaxed) + 1U;
    CNDSurfaceTraceLog(
        "[CND_FETCH] seq=%llu us=%llu main=%d event=%s scope=%s "
        "correlation=%llu scope-owner=%p scope-icon=%p "
        "scope-consumer=%p ",
        (unsigned long long)sequence,
        (unsigned long long)CNDSurfaceTraceNowUS(),
        pthread_main_np() ? 1 : 0, event ?: "-",
        CNDSurfaceTraceScopeName(gCNDSurfaceTraceContext.scope),
        (unsigned long long)gCNDSurfaceTraceContext.correlation,
        gCNDSurfaceTraceContext.owner, gCNDSurfaceTraceContext.icon,
        gCNDSurfaceTraceContext.consumer);
}

static void CNDSurfaceTraceLogIconState(const char *event, id icon)
{
    CNDSurfaceTraceLogEventPrefix(event);
    CNDSurfaceTraceLog(
        "icon=%p/%s id=%s generation=%llu\n", icon,
        icon ? class_getName([icon class]) : "-",
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-",
        (unsigned long long)CNDSurfaceTraceGeneration(icon));
}

static void CNDSurfaceTraceLogCacheState(const char *event, id cache,
                                         id icon, id image)
{
    uint64_t currentGeneration = UINT64_MAX;
    uint64_t cachedGeneration = UINT64_MAX;
    SEL currentSelector = sel_registerName("currentImageGenerationForIcon:");
    SEL cachedSelector = sel_registerName("imageGenerationForCachedImage:");
    if (cache && icon && [cache respondsToSelector:currentSelector]) {
        currentGeneration = ((NSUInteger (*)(id, SEL, id))objc_msgSend)(
            cache, currentSelector, icon);
    }
    if (cache && image && [cache respondsToSelector:cachedSelector]) {
        cachedGeneration = ((NSUInteger (*)(id, SEL, id))objc_msgSend)(
            cache, cachedSelector, image);
    }
    CNDSurfaceTraceLogEventPrefix(event);
    CNDSurfaceTraceLog(
        "cache=%p/%s icon=%p/%s id=%s icon-generation=%llu "
        "cache-current-generation=%llu image=%p/%s "
        "cached-image-generation=%llu\n", cache,
        cache ? class_getName([cache class]) : "-", icon,
        icon ? class_getName([icon class]) : "-",
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-",
        (unsigned long long)CNDSurfaceTraceGeneration(icon),
        (unsigned long long)currentGeneration, image,
        image ? class_getName([image class]) : "-",
        (unsigned long long)cachedGeneration);
}

static id CNDSurfaceTraceObject(id object, const char *selectorName)
{
    if (!object || !selectorName) return nil;
    SEL selector = sel_registerName(selectorName);
    if (![object respondsToSelector:selector]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(object, selector);
}

static const char *CNDSurfaceTraceSkipTypeQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static Method CNDSurfaceTraceMethod(id object, const char *selectorName,
                                    unsigned explicitArguments)
{
    if (!object || !selectorName) return NULL;
    Method method = class_getInstanceMethod(
        object_getClass(object), sel_registerName(selectorName));
    return method && method_getNumberOfArguments(method) ==
        explicitArguments + 2U ? method : NULL;
}

static id CNDSurfaceTraceSafeObject(id object, const char *selectorName)
{
    Method method = CNDSurfaceTraceMethod(object, selectorName, 0U);
    if (!method) return nil;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDSurfaceTraceSkipTypeQualifiers(returnType);
    bool valid = type && (*type == '@' || *type == '#');
    free(returnType);
    if (!valid) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(
            object, sel_registerName(selectorName));
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static bool CNDSurfaceTraceInteger(id object, const char *selectorName,
                                   long long *valueOut)
{
    Method method = CNDSurfaceTraceMethod(object, selectorName, 0U);
    if (!method || !valueOut) return false;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDSurfaceTraceSkipTypeQualifiers(returnType);
    bool valid = type && strchr("cCsSiIlLqQB", *type);
    free(returnType);
    if (!valid) return false;
    @try {
        *valueOut = ((long long (*)(id, SEL))objc_msgSend)(
            object, sel_registerName(selectorName));
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDSurfaceTraceDouble(id object, const char *selectorName,
                                  double *valueOut)
{
    Method method = CNDSurfaceTraceMethod(object, selectorName, 0U);
    if (!method || !valueOut) return false;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDSurfaceTraceSkipTypeQualifiers(returnType);
    bool valid = type && *type == 'd';
    free(returnType);
    if (!valid) return false;
    @try {
        *valueOut = ((double (*)(id, SEL))objc_msgSend)(
            object, sel_registerName(selectorName));
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDSurfaceTraceSize(id object, CGSize *sizeOut)
{
    Method method = CNDSurfaceTraceMethod(object, "size", 0U);
    if (!method || !sizeOut) return false;
    char *returnType = method_copyReturnType(method);
    bool valid = returnType && strstr(returnType, "CGSize") != NULL;
    free(returnType);
    if (!valid) return false;
    @try {
        *sizeOut = ((CGSize (*)(id, SEL))objc_msgSend)(
            object, sel_registerName("size"));
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static NSString *CNDSurfaceTraceUUIDText(id object)
{
    if ([object isKindOfClass:NSUUID.class]) return [object UUIDString];
    if ([object isKindOfClass:NSString.class]) return object;
    return @"-";
}

static bool CNDSurfaceTraceDataHasMarker(NSData *data)
{
    if (![data isKindOfClass:NSData.class] || data.length == 0U) return false;
    static NSData *marker;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        marker = [@"CNDThemeIcon.v1" dataUsingEncoding:NSUTF8StringEncoding];
    });
    return marker.length && [data rangeOfData:marker options:0
                                        range:NSMakeRange(0, data.length)]
        .location != NSNotFound;
}

static NSString *CNDSurfaceTraceShortStack(void)
{
    NSArray<NSString *> *symbols = NSThread.callStackSymbols;
    NSUInteger start = MIN((NSUInteger)2U, symbols.count);
    NSUInteger count = MIN((NSUInteger)12U, symbols.count - start);
    NSString *stack = count
        ? [[symbols subarrayWithRange:NSMakeRange(start, count)]
            componentsJoinedByString:@" | "]
        : @"-";
    stack = [stack stringByReplacingOccurrencesOfString:@"\n"
                                             withString:@" "];
    return stack.length > 3200U
        ? [[stack substringToIndex:3200U] stringByAppendingString:@"..."]
        : stack;
}

static bool CNDSurfaceTraceDescriptorTarget(id icon)
{
    if (gCNDSurfaceTraceContext.scope != CNDSurfaceTraceScopeNone) {
        return true;
    }
    NSString *configured = @CND_SURFACE_TRACE_TARGET_BUNDLE;
    if ([configured isEqualToString:@"*"]) return true;
    NSString *identifier = CNDSurfaceTraceIdentifier(icon);
    return configured.length && [configured isEqualToString:identifier];
}

static void CNDSurfaceTraceLogDescriptor(const char *phase, id icon,
                                         id descriptor, id image)
{
    if (!CNDSurfaceTraceDescriptorTarget(icon)) return;
    uint64_t event = atomic_fetch_add_explicit(
        &gCNDSurfaceTraceDescriptorEvents, 1U, memory_order_relaxed) + 1U;
    if (event > 4096U) return;
    CGSize size = CGSizeZero;
    double scale = 0.0;
    long long appearance = 0;
    long long appearanceVariant = 0;
    long long variant = 0;
    long long options = 0;
    bool hasSize = CNDSurfaceTraceSize(descriptor, &size);
    bool hasScale = CNDSurfaceTraceDouble(descriptor, "scale", &scale);
    bool hasAppearance = CNDSurfaceTraceInteger(
        descriptor, "appearance", &appearance);
    bool hasAppearanceVariant = CNDSurfaceTraceInteger(
        descriptor, "appearanceVariant", &appearanceVariant);
    bool hasVariant = CNDSurfaceTraceInteger(
        descriptor, "iconVariant", &variant);
    bool hasOptions = CNDSurfaceTraceInteger(
        descriptor, "options", &options);
    id digest = CNDSurfaceTraceSafeObject(descriptor, "digest");
    id uuid = CNDSurfaceTraceSafeObject(image, "uuid");
    NSData *data = CNDSurfaceTraceSafeObject(image, "data");
    CGImageRef cgImage = NULL;
    if (image && [image respondsToSelector:sel_registerName("CGImage")]) {
        @try {
            cgImage = ((CGImageRef (*)(id, SEL))objc_msgSend)(
                image, sel_registerName("CGImage"));
        } @catch (__unused NSException *exception) {
            cgImage = NULL;
        }
    }
    CNDSurfaceTraceLogEventPrefix(phase);
    CNDSurfaceTraceLog(
        "descriptor-event=%llu is-icon=%p/%s bundle=%s descriptor=%p/%s "
        "size=%d/%.3fx%.3f scale=%d/%.3f digest=%s "
        "appearance=%d/%lld appearance-variant=%d/%lld "
        "variant=%d/%lld options=%d/%lld image=%p/%s uuid=%s "
        "data=%lu marker=%d pixels=%zux%zu\n",
        (unsigned long long)event, icon,
        icon ? class_getName([icon class]) : "-",
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-", descriptor,
        descriptor ? class_getName([descriptor class]) : "-",
        hasSize ? 1 : 0, size.width, size.height,
        hasScale ? 1 : 0, scale,
        CNDSurfaceTraceUUIDText(digest).UTF8String ?: "-",
        hasAppearance ? 1 : 0, appearance,
        hasAppearanceVariant ? 1 : 0, appearanceVariant,
        hasVariant ? 1 : 0, variant, hasOptions ? 1 : 0, options,
        image, image ? class_getName([image class]) : "-",
        CNDSurfaceTraceUUIDText(uuid).UTF8String ?: "-",
        (unsigned long)([data isKindOfClass:NSData.class] ? data.length : 0U),
        CNDSurfaceTraceDataHasMarker(data) ? 1 : 0,
        cgImage ? CGImageGetWidth(cgImage) : 0U,
        cgImage ? CGImageGetHeight(cgImage) : 0U);
    CNDSurfaceTraceLogEventPrefix("descriptor-stack");
    CNDSurfaceTraceLog("phase=%s stack=%s\n", phase,
                       CNDSurfaceTraceShortStack().UTF8String ?: "-");
    CNDSurfaceTraceCaptureDescriptorImage(
        phase, icon, descriptor, image);
}

static void CNDSurfaceTraceLogViewGeometry(const char *event, id view)
{
    if (![view isKindOfClass:UIView.class]) return;
    UIView *uiView = view;
    CNDSurfaceTraceLogEventPrefix(event);
    CNDSurfaceTraceLog(
        "view=%p/%s bounds=%.3f,%.3f,%.3f,%.3f frame=%.3f,%.3f,%.3f,%.3f "
        "window=%p superview=%p/%s hidden=%d alpha=%.3f\n", view,
        class_getName([view class]), uiView.bounds.origin.x,
        uiView.bounds.origin.y, uiView.bounds.size.width,
        uiView.bounds.size.height, uiView.frame.origin.x,
        uiView.frame.origin.y, uiView.frame.size.width,
        uiView.frame.size.height, uiView.window, uiView.superview,
        uiView.superview ? class_getName([uiView.superview class]) : "-",
        uiView.hidden ? 1 : 0, uiView.alpha);
}

static void CNDSurfaceTraceLogIconConsumer(const char *event, id consumer)
{
    id icon = CNDSurfaceTraceObject(consumer, "icon");
    id displayed = CNDSurfaceTraceObject(consumer, "displayedImage");
    id identity = CNDSurfaceTraceObject(consumer, "displayedImageIdentity");
    id requestedIdentity = CNDSurfaceTraceObject(
        consumer, "requestedImageIdentity");
    id cache = CNDSurfaceTraceObject(consumer, "iconImageCache");
    id appearance = CNDSurfaceTraceObject(consumer, "iconImageAppearance");
    id displayedUUID = CNDSurfaceTraceSafeObject(identity, "uuid");
    if (!displayedUUID) {
        displayedUUID = CNDSurfaceTraceSafeObject(identity, "UUID");
    }
    id requestedUUID = CNDSurfaceTraceSafeObject(requestedIdentity, "uuid");
    if (!requestedUUID) {
        requestedUUID = CNDSurfaceTraceSafeObject(requestedIdentity, "UUID");
    }
    uint64_t displayedGeneration = CNDSurfaceTraceGeneration(identity);
    uint64_t requestedGeneration = CNDSurfaceTraceGeneration(
        requestedIdentity);
    CNDSurfaceTraceLogEventPrefix(event);
    CNDSurfaceTraceLog(
        "consumer=%p/%s icon=%p id=%s icon-generation=%llu "
        "cache=%p/%s displayed=%p/%s identity=%p/%s "
        "displayed-generation=%llu displayed-uuid=%s requested=%p/%s "
        "requested-generation=%llu requested-uuid=%s appearance=%p/%s "
        "can-update=%d delayed=%d\n",
        consumer,
        consumer ? class_getName([consumer class]) : "-", icon,
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-",
        (unsigned long long)CNDSurfaceTraceGeneration(icon), cache,
        cache ? class_getName([cache class]) : "-", displayed,
        displayed ? class_getName([displayed class]) : "-", identity,
        identity ? class_getName([identity class]) : "-",
        (unsigned long long)displayedGeneration,
        CNDSurfaceTraceUUIDText(displayedUUID).UTF8String ?: "-",
        requestedIdentity,
        requestedIdentity ? class_getName([requestedIdentity class]) : "-",
        (unsigned long long)requestedGeneration,
        CNDSurfaceTraceUUIDText(requestedUUID).UTF8String ?: "-",
        appearance, appearance ? class_getName([appearance class]) : "-",
        consumer && [consumer respondsToSelector:sel_registerName(
            "canUpdateImage")]
            ? (((BOOL (*)(id, SEL))objc_msgSend)(
                consumer, sel_registerName("canUpdateImage")) ? 1 : 0)
            : -1,
        consumer && [consumer respondsToSelector:sel_registerName(
            "delayedImageUpdateDueToContentVisibility")]
            ? (((BOOL (*)(id, SEL))objc_msgSend)(
                consumer,
                sel_registerName(
                    "delayedImageUpdateDueToContentVisibility")) ? 1 : 0)
            : -1);
}

typedef struct {
    size_t width;
    size_t height;
    unsigned alphaInfo;
    unsigned cornerAlpha[4];
    size_t transparentPixels;
    size_t translucentPixels;
    bool readable;
} CNDImageAlphaStats;

static CNDImageAlphaStats CNDSurfaceTraceAlphaStats(UIImage *image)
{
    CNDImageAlphaStats stats = {0};
    if (![image isKindOfClass:UIImage.class]) return stats;
    CGSize points = image.size;
    CGFloat scale = image.scale > 0.0 ? image.scale : 3.0;
    size_t width = (size_t)llround(points.width * scale);
    size_t height = (size_t)llround(points.height * scale);
    if (width == 0 || height == 0 || width > 1024 || height > 1024) {
        return stats;
    }
    size_t rowBytes = width * 4U;
    uint8_t *pixels = calloc(height, rowBytes);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(
        pixels, width, height, 8, rowBytes, colorSpace,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(colorSpace);
    if (!pixels || !context) {
        if (context) CGContextRelease(context);
        free(pixels);
        return stats;
    }
    UIGraphicsPushContext(context);
    [image drawInRect:CGRectMake(0.0, 0.0, (CGFloat)width,
                                 (CGFloat)height)];
    UIGraphicsPopContext();
    stats.width = width;
    stats.height = height;
    CGImageRef source = image.CGImage;
    stats.alphaInfo = source ? (unsigned)CGImageGetAlphaInfo(source) : 0U;
    const size_t offsets[4] = {
        3U,
        (width - 1U) * 4U + 3U,
        (height - 1U) * rowBytes + 3U,
        (height - 1U) * rowBytes + (width - 1U) * 4U + 3U,
    };
    for (size_t index = 0; index < 4U; index++) {
        stats.cornerAlpha[index] = pixels[offsets[index]];
    }
    for (size_t y = 0; y < height; y++) {
        for (size_t x = 0; x < width; x++) {
            uint8_t alpha = pixels[y * rowBytes + x * 4U + 3U];
            if (alpha == 0U) stats.transparentPixels++;
            else if (alpha != 255U) stats.translucentPixels++;
        }
    }
    stats.readable = true;
    CGContextRelease(context);
    free(pixels);
    return stats;
}

static void CNDSurfaceTraceLogImage(const char *role, id image)
{
    UIImage *uiImage = [image isKindOfClass:UIImage.class] ? image : nil;
    CNDImageAlphaStats stats = CNDSurfaceTraceAlphaStats(uiImage);
    CNDSurfaceTraceLog(
        "[CND_SURFACE] image role=%s object=%p class=%s points=%.2fx%.2f "
        "scale=%.2f pixels=%zux%zu alpha-info=%u corners=%u,%u,%u,%u "
        "transparent=%zu translucent=%zu readable=%d\n",
        role, image, image ? class_getName([image class]) : "-",
        uiImage.size.width, uiImage.size.height, uiImage.scale,
        stats.width, stats.height, stats.alphaInfo,
        stats.cornerAlpha[0], stats.cornerAlpha[1],
        stats.cornerAlpha[2], stats.cornerAlpha[3],
        stats.transparentPixels, stats.translucentPixels,
        stats.readable ? 1 : 0);
}

static void CNDSurfaceTraceCaptureDescriptorImage(const char *phase,
                                                   id icon, id descriptor,
                                                   id image)
{
    if (!phase || strcmp(phase, "descriptor-image-return") ||
        gCNDSurfaceTraceContext.scope !=
            CNDSurfaceTraceScopeAppLibraryCategory ||
        !image || !descriptor) {
        return;
    }
    CGSize size = CGSizeZero;
    double scale = 0.0;
    if (!CNDSurfaceTraceSize(descriptor, &size) ||
        !CNDSurfaceTraceDouble(descriptor, "scale", &scale) ||
        size.width < 26.0 || size.width > 28.0 ||
        size.height < 26.0 || size.height > 28.0 ||
        scale < 1.0 || scale > 4.0 ||
        ![image respondsToSelector:sel_registerName("CGImage")]) {
        return;
    }
    CGImageRef cgImage = NULL;
    @try {
        cgImage = ((CGImageRef (*)(id, SEL))objc_msgSend)(
            image, sel_registerName("CGImage"));
    } @catch (__unused NSException *exception) {
        cgImage = NULL;
    }
    if (!cgImage) return;
    uint64_t sample = atomic_fetch_add_explicit(
        &gCNDSurfaceTraceDescriptorSamples, 1U,
        memory_order_relaxed) + 1U;
    if (sample > 256U) return;
    UIImage *uiImage = [UIImage imageWithCGImage:cgImage
                                           scale:(CGFloat)scale
                                     orientation:UIImageOrientationUp];
    CNDSurfaceTraceLogImage("app-library-iconservices-return", uiImage);
    NSData *png = UIImagePNGRepresentation(uiImage);
    NSString *path = [NSString stringWithFormat:
        @"/var/tmp/cyanide-app-library-iconservices-%03llu.png",
        (unsigned long long)sample];
    NSError *error = nil;
    BOOL wrote = [png isKindOfClass:NSData.class] && png.length > 0U &&
        png.length <= (8U << 20) &&
        [png writeToFile:path options:NSDataWritingAtomic error:&error];
    CNDSurfaceTraceLogEventPrefix("app-library-iconservices-evidence");
    CNDSurfaceTraceLog(
        "sample=%llu bundle=%s descriptor=%p source=%p/%s "
        "points=%.3fx%.3f scale=%.3f pixels=%zux%zu evidence=%d "
        "bytes=%lu path=%s error=%s\n", (unsigned long long)sample,
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-", descriptor,
        image, class_getName([image class]), size.width, size.height,
        scale, CGImageGetWidth(cgImage), CGImageGetHeight(cgImage),
        wrote ? 1 : 0,
        (unsigned long)([png isKindOfClass:NSData.class] ? png.length : 0U),
        path.UTF8String ?: "-",
        error.localizedDescription.UTF8String ?: "-");
}

static void CNDSurfaceTraceWriteCompositeEvidence(uint64_t sample,
                                                   NSString *phase,
                                                   id image)
{
    if (sample == 0U || sample > 128U ||
        ![phase isKindOfClass:NSString.class] ||
        ![image isKindOfClass:UIImage.class]) {
        return;
    }
    NSData *png = UIImagePNGRepresentation(image);
    if (![png isKindOfClass:NSData.class] || png.length == 0U ||
        png.length > (8U << 20)) {
        CNDSurfaceTraceLog(
            "[CND_COMPOSITOR] sample=%llu phase=%s evidence=0 "
            "reason=png-encoding\n", (unsigned long long)sample,
            phase.UTF8String ?: "-");
        return;
    }
    NSString *path = [NSString stringWithFormat:
        @"/var/tmp/cyanide-app-library-compositor-%03llu-%@.png",
        (unsigned long long)sample, phase];
    NSError *error = nil;
    BOOL wrote = [png writeToFile:path
                          options:NSDataWritingAtomic
                            error:&error];
    CNDSurfaceTraceLog(
        "[CND_COMPOSITOR] sample=%llu phase=%s evidence=%d bytes=%lu "
        "path=%s error=%s\n", (unsigned long long)sample,
        phase.UTF8String ?: "-", wrote ? 1 : 0,
        (unsigned long)png.length, path.UTF8String ?: "-",
        error.localizedDescription.UTF8String ?: "-");
}

static id CNDSurfaceTraceISImageForDescriptor(id self, SEL selector,
                                               id descriptor)
{
    CNDSurfaceTraceLogDescriptor(
        "descriptor-image-enter", self, descriptor, nil);
    id image = ((id (*)(id, SEL, id))gCNDOriginalISImageForDescriptor)(
        self, selector, descriptor);
    CNDSurfaceTraceLogDescriptor(
        "descriptor-image-return", self, descriptor, image);
    return image;
}

static id CNDSurfaceTraceISGenerateForDescriptor(id self, SEL selector,
                                                  id descriptor)
{
    CNDSurfaceTraceLogDescriptor(
        "descriptor-generate-enter", self, descriptor, nil);
    id image = ((id (*)(id, SEL, id))gCNDOriginalISGenerateForDescriptor)(
        self, selector, descriptor);
    CNDSurfaceTraceLogDescriptor(
        "descriptor-generate-return", self, descriptor, image);
    return image;
}

static id CNDSurfaceTraceImageForIcon(id self, SEL selector, id icon,
                                      id appearance, NSUInteger options)
{
    CNDSurfaceTraceLogCacheState("cache-lookup-begin", self, icon, nil);
    id normal = gCNDOriginalImageForIcon(
        self, selector, icon, appearance, options);
    CNDSurfaceTraceLogCacheState("cache-lookup-end", self, icon, normal);
    bool scoped = gCNDSurfaceTraceContext.scope !=
        CNDSurfaceTraceScopeNone;
    if (scoped) {
        CNDSurfaceTraceLogEventPrefix("scoped-cache-result");
        CNDSurfaceTraceLog(
            "cache=%p/%s icon=%p/%s id=%s appearance=%p/%s "
            "options=%lu image=%p/%s\n", self,
            self ? class_getName([self class]) : "-", icon,
            icon ? class_getName([icon class]) : "-",
            CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-",
            appearance,
            appearance ? class_getName([appearance class]) : "-",
            (unsigned long)options, normal,
            normal ? class_getName([normal class]) : "-");
        const char *role = "folder-preview-cache-result";
        if (gCNDSurfaceTraceContext.scope ==
            CNDSurfaceTraceScopeAppLibraryCategory) {
            role = "app-library-category-cache-result";
        } else if (gCNDSurfaceTraceContext.scope ==
                   CNDSurfaceTraceScopeAppLibraryList) {
            role = "app-library-list-cache-result";
        }
        CNDSurfaceTraceLogImage(role, normal);
    }
    if (gCNDSurfaceTraceSwitcherDepth == 0U) return normal;
    id unmasked = nil;
    SEL unmaskedSelector = sel_registerName("unmaskedImageForIcon:options:");
    if ([self respondsToSelector:unmaskedSelector]) {
        unmasked = ((id (*)(id, SEL, id, NSUInteger))objc_msgSend)(
            self, unmaskedSelector, icon, options);
    }
    NSString *identifier = CNDSurfaceTraceIdentifier(icon);
    CNDSurfaceTraceLog(
        "[CND_SURFACE] switcher-cache cache=%p/%s icon=%p id=%s "
        "appearance=%p options=%lu normal=%p unmasked=%p same=%d\n",
        self, class_getName([self class]), icon,
        identifier.UTF8String ?: "-", appearance,
        (unsigned long)options, normal, unmasked, normal == unmasked);
    CNDSurfaceTraceLogImage("switcher-normal", normal);
    CNDSurfaceTraceLogImage("switcher-unmasked", unmasked);
    return normal;
}

static void CNDSurfaceTraceIconReloadImage(id self, SEL selector)
{
    CNDSurfaceTraceLogIconState("icon-reload-begin", self);
    gCNDOriginalIconReloadImage(self, selector);
    CNDSurfaceTraceLogIconState("icon-reload-end", self);
}

static void CNDSurfaceTraceIconNotifyImageUpdate(id self, SEL selector)
{
    CNDSurfaceTraceLogIconState("icon-notify-begin", self);
    gCNDOriginalIconNotifyImageUpdate(self, selector);
    CNDSurfaceTraceLogIconState("icon-notify-end", self);
}

static void CNDSurfaceTraceIconUpdateLayerView(id self, SEL selector,
                                                id layerView)
{
    CNDSurfaceTraceLogEventPrefix("icon-layer-refill-begin");
    CNDSurfaceTraceLog(
        "icon=%p/%s id=%s generation=%llu layer-view=%p/%s "
        "appearance=%p content-layer=%p\n", self,
        self ? class_getName([self class]) : "-",
        CNDSurfaceTraceIdentifier(self).UTF8String ?: "-",
        (unsigned long long)CNDSurfaceTraceGeneration(self), layerView,
        layerView ? class_getName([layerView class]) : "-",
        CNDSurfaceTraceObject(layerView, "iconImageAppearance"),
        CNDSurfaceTraceObject(layerView, "iconContentLayer"));
    gCNDOriginalIconUpdateLayerView(self, selector, layerView);
    CNDSurfaceTraceLogEventPrefix("icon-layer-refill-dispatched");
    CNDSurfaceTraceLog(
        "icon=%p/%s id=%s generation=%llu layer-view=%p/%s "
        "appearance=%p content-layer=%p\n", self,
        self ? class_getName([self class]) : "-",
        CNDSurfaceTraceIdentifier(self).UTF8String ?: "-",
        (unsigned long long)CNDSurfaceTraceGeneration(self), layerView,
        layerView ? class_getName([layerView class]) : "-",
        CNDSurfaceTraceObject(layerView, "iconImageAppearance"),
        CNDSurfaceTraceObject(layerView, "iconContentLayer"));
}

static void CNDSurfaceTraceFolderIconReloadImage(id self, SEL selector)
{
    CNDSurfaceTraceContext previous = CNDSurfaceTracePushContext(
        CNDSurfaceTraceScopeFolderPreview, self, self, nil);
    CNDSurfaceTraceLogIconState("folder-icon-reload-begin", self);
    gCNDOriginalFolderIconReloadImage(self, selector);
    CNDSurfaceTraceLogIconState("folder-icon-reload-end", self);
    CNDSurfaceTracePopContext(previous);
}

static void CNDSurfaceTraceFolderIconUpdateLayerView(id self, SEL selector,
                                                      id layerView)
{
    CNDSurfaceTraceContext previous = CNDSurfaceTracePushContext(
        CNDSurfaceTraceScopeFolderPreview, self, self, layerView);
    CNDSurfaceTraceLogEventPrefix("folder-layer-refill-begin");
    CNDSurfaceTraceLog(
        "folder-icon=%p/%s id=%s generation=%llu layer-view=%p/%s "
        "appearance=%p content-layer=%p\n", self,
        self ? class_getName([self class]) : "-",
        CNDSurfaceTraceIdentifier(self).UTF8String ?: "-",
        (unsigned long long)CNDSurfaceTraceGeneration(self), layerView,
        layerView ? class_getName([layerView class]) : "-",
        CNDSurfaceTraceObject(layerView, "iconImageAppearance"),
        CNDSurfaceTraceObject(layerView, "iconContentLayer"));
    CNDSurfaceTraceLogViewGeometry("folder-layer-view-geometry", layerView);
    gCNDOriginalFolderIconUpdateLayerView(self, selector, layerView);
    CNDSurfaceTraceLogEventPrefix("folder-layer-refill-end");
    CNDSurfaceTraceLog(
        "folder-icon=%p/%s id=%s generation=%llu layer-view=%p/%s "
        "appearance=%p content-layer=%p\n", self,
        self ? class_getName([self class]) : "-",
        CNDSurfaceTraceIdentifier(self).UTF8String ?: "-",
        (unsigned long long)CNDSurfaceTraceGeneration(self), layerView,
        layerView ? class_getName([layerView class]) : "-",
        CNDSurfaceTraceObject(layerView, "iconImageAppearance"),
        CNDSurfaceTraceObject(layerView, "iconContentLayer"));
    CNDSurfaceTracePopContext(previous);
}

static void CNDSurfaceTraceCacheBeginObservingIcon(id self, SEL selector,
                                                    id icon)
{
    CNDSurfaceTraceLogCacheState(
        "cache-observe-begin", self, icon, nil);
    gCNDOriginalCacheBeginObservingIcon(self, selector, icon);
    CNDSurfaceTraceLogCacheState(
        "cache-observe-end", self, icon, nil);
}

static void CNDSurfaceTraceCacheIconImageDidUpdate(id self, SEL selector,
                                                   id icon)
{
    CNDSurfaceTraceLogCacheState(
        "cache-icon-update-begin", self, icon, nil);
    gCNDOriginalCacheIconImageDidUpdate(self, selector, icon);
    CNDSurfaceTraceLogCacheState(
        "cache-icon-update-end", self, icon, nil);
}

static void CNDSurfaceTraceCacheUpdateImageForIcon(id self, SEL selector,
                                                   id icon)
{
    CNDSurfaceTraceLogCacheState(
        "cache-refresh-begin", self, icon, nil);
    gCNDOriginalCacheUpdateImageForIcon(self, selector, icon);
    CNDSurfaceTraceLogCacheState(
        "cache-refresh-end", self, icon, nil);
}

static void CNDSurfaceTraceCacheImage(id self, SEL selector, id image,
                                      id icon, id appearance)
{
    CNDSurfaceTraceLogCacheState(
        "cache-insert-begin", self, icon, image);
    gCNDOriginalCacheImage(self, selector, image, icon, appearance);
    CNDSurfaceTraceLogCacheState(
        "cache-insert-end", self, icon, image);
}

static id CNDSurfaceTraceSwitcherImage(id self, SEL selector, id displayItem)
{
    gCNDSurfaceTraceSwitcherDepth++;
    id image = gCNDOriginalSwitcherImage(self, selector, displayItem);
    gCNDSurfaceTraceSwitcherDepth--;
    CNDSurfaceTraceLog(
        "[CND_SURFACE] switcher-result controller=%p display-item=%p "
        "image=%p\n", self, displayItem, image);
    return image;
}

static void CNDSurfaceTraceResetAllCaches(id self, SEL selector)
{
    CNDSurfaceTraceLog("[CND_SURFACE] refresh reset-all manager=%p begin\n",
                       self);
    gCNDOriginalResetAllCaches(self, selector);
    CNDSurfaceTraceLog("[CND_SURFACE] refresh reset-all manager=%p end\n",
                       self);
}

static void CNDSurfaceTracePurgeAllImages(id self, SEL selector)
{
    CNDSurfaceTraceLog("[CND_SURFACE] refresh purge cache=%p/%s\n", self,
                       class_getName([self class]));
    gCNDOriginalPurgeAllImages(self, selector);
}

static void CNDSurfaceTraceNotificationUpdate(id self, SEL selector)
{
    CNDSurfaceTraceLog("[CND_SURFACE] notification update view=%p\n", self);
    gCNDOriginalNotificationUpdate(self, selector);
}

static void CNDSurfaceTraceLibraryReload(id self, SEL selector)
{
    CNDSurfaceTraceLog("[CND_SURFACE] library reload-app-icons owner=%p\n",
                       self);
    gCNDOriginalLibraryReload(self, selector);
}

static void CNDSurfaceTraceLibraryEnqueue(id self, SEL selector)
{
    CNDSurfaceTraceLog("[CND_SURFACE] library enqueue owner=%p\n", self);
    gCNDOriginalLibraryEnqueue(self, selector);
}

static void CNDSurfaceTraceLibraryLayout(id self, SEL selector,
                                         NSInteger animationType,
                                         BOOL forceRelayout)
{
    CNDSurfaceTraceLog(
        "[CND_SURFACE] library layout owner=%p animation=%ld force=%d\n",
        self, (long)animationType, forceRelayout);
    gCNDOriginalLibraryLayout(self, selector, animationType, forceRelayout);
}

static void CNDSurfaceTraceFolderRebuild(id self, SEL selector)
{
    CNDSurfaceTraceLog("[CND_SURFACE] folder rebuild cache=%p\n", self);
    gCNDOriginalFolderRebuild(self, selector);
}

static void CNDSurfaceTraceLibraryConfigure(id self, SEL selector,
                                            id iconView, id icon)
{
    CNDSurfaceTraceContext previous = CNDSurfaceTracePushContext(
        CNDSurfaceTraceScopeAppLibraryCategory, self, icon, iconView);
    id imageViewBefore = CNDSurfaceTraceObject(iconView, "iconImageView");
    CNDSurfaceTraceLogEventPrefix("library-configure-begin");
    CNDSurfaceTraceLog(
        "list=%p/%s icon-view=%p/%s image-view=%p/%s icon=%p/%s "
        "id=%s generation=%llu\n", self,
        self ? class_getName([self class]) : "-", iconView,
        iconView ? class_getName([iconView class]) : "-", imageViewBefore,
        imageViewBefore ? class_getName([imageViewBefore class]) : "-",
        icon, icon ? class_getName([icon class]) : "-",
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-",
        (unsigned long long)CNDSurfaceTraceGeneration(icon));
    CNDSurfaceTraceLogViewGeometry("library-list-geometry", self);
    CNDSurfaceTraceLogViewGeometry("library-icon-view-before", iconView);
    CNDSurfaceTraceLogViewGeometry(
        "library-image-view-before", imageViewBefore);
    CNDSurfaceTraceLogIconConsumer(
        "library-icon-consumer-before", iconView);
    CNDSurfaceTraceLogIconConsumer(
        "library-image-consumer-before", imageViewBefore);
    gCNDOriginalLibraryConfigure(self, selector, iconView, icon);
    id imageViewAfter = CNDSurfaceTraceObject(iconView, "iconImageView");
    CNDSurfaceTraceLogIconConsumer(
        "library-icon-consumer-after", iconView);
    CNDSurfaceTraceLogIconConsumer(
        "library-image-consumer-after", imageViewAfter);
    CNDSurfaceTraceLogViewGeometry("library-icon-view-after", iconView);
    CNDSurfaceTraceLogViewGeometry(
        "library-image-view-after", imageViewAfter);
    id displayed = CNDSurfaceTraceObject(imageViewAfter, "displayedImage");
    CNDSurfaceTraceLogImage("app-library-displayed", displayed);
    CNDSurfaceTraceLogEventPrefix("library-configure-end");
    CNDSurfaceTraceLog(
        "list=%p icon-view=%p image-view-before=%p image-view-after=%p "
        "displayed=%p id=%s\n", self, iconView, imageViewBefore,
        imageViewAfter, displayed,
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-");
    CNDSurfaceTracePopContext(previous);
}

static void CNDSurfaceTraceLogLibraryListCell(const char *event, id owner,
                                              id cell, id icon)
{
    id iconView = CNDSurfaceTraceSafeObject(cell, "iconView");
    id imageView = CNDSurfaceTraceSafeObject(iconView, "iconImageView");
    id cache = CNDSurfaceTraceSafeObject(owner, "iconImageCache");
    if (!cache) cache = CNDSurfaceTraceSafeObject(iconView, "iconImageCache");
    CNDSurfaceTraceLogEventPrefix(event);
    CNDSurfaceTraceLog(
        "controller=%p/%s cell=%p/%s icon=%p/%s id=%s generation=%llu "
        "icon-view=%p/%s image-view=%p/%s cache=%p/%s\n",
        owner, owner ? class_getName([owner class]) : "-", cell,
        cell ? class_getName([cell class]) : "-", icon,
        icon ? class_getName([icon class]) : "-",
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-",
        (unsigned long long)CNDSurfaceTraceGeneration(icon), iconView,
        iconView ? class_getName([iconView class]) : "-", imageView,
        imageView ? class_getName([imageView class]) : "-", cache,
        cache ? class_getName([cache class]) : "-");
    CNDSurfaceTraceLogViewGeometry(event, cell);
    CNDSurfaceTraceLogViewGeometry("library-list-icon-view-geometry",
                                   iconView);
    CNDSurfaceTraceLogIconConsumer("library-list-icon-consumer", iconView);
    CNDSurfaceTraceLogIconConsumer("library-list-image-consumer", imageView);
}

static void CNDSurfaceTraceLibraryListConfigure(id self, SEL selector,
                                                id cell, id icon)
{
    CNDSurfaceTraceContext previous = CNDSurfaceTracePushContext(
        CNDSurfaceTraceScopeAppLibraryList, self, icon, cell);
    CNDSurfaceTraceLogLibraryListCell(
        "library-list-configure-begin", self, cell, icon);
    gCNDOriginalLibraryListConfigure(self, selector, cell, icon);
    CNDSurfaceTraceLogLibraryListCell(
        "library-list-configure-end", self, cell, icon);
    CNDSurfaceTracePopContext(previous);
}

static void CNDSurfaceTraceLibraryListCellConfigure(id self, SEL selector,
                                                    id icon)
{
    bool ownsContext = gCNDSurfaceTraceContext.scope !=
        CNDSurfaceTraceScopeAppLibraryList;
    CNDSurfaceTraceContext previous = gCNDSurfaceTraceContext;
    if (ownsContext) {
        previous = CNDSurfaceTracePushContext(
            CNDSurfaceTraceScopeAppLibraryList, self, icon, self);
    }
    CNDSurfaceTraceLogLibraryListCell(
        "library-list-cell-configure-begin", nil, self, icon);
    gCNDOriginalLibraryListCellConfigure(self, selector, icon);
    CNDSurfaceTraceLogLibraryListCell(
        "library-list-cell-configure-end", nil, self, icon);
    if (ownsContext) CNDSurfaceTracePopContext(previous);
}

static void CNDSurfaceTraceLogLibraryListControllerState(const char *event,
                                                         id controller)
{
    id tableView = CNDSurfaceTraceSafeObject(controller, "tableView");
    id visibleCells = CNDSurfaceTraceSafeObject(tableView, "visibleCells");
    id cache = CNDSurfaceTraceSafeObject(controller, "iconImageCache");
    id query = CNDSurfaceTraceSafeObject(controller, "currentQuery");
    NSUInteger visibleCount = [visibleCells isKindOfClass:NSArray.class]
        ? [visibleCells count] : 0U;
    CNDSurfaceTraceLogEventPrefix(event);
    CNDSurfaceTraceLog(
        "controller=%p/%s table=%p/%s visible-cells=%lu cache=%p/%s "
        "query=%p/%s window=%p\n", controller,
        controller ? class_getName([controller class]) : "-", tableView,
        tableView ? class_getName([tableView class]) : "-",
        (unsigned long)visibleCount, cache,
        cache ? class_getName([cache class]) : "-", query,
        query ? class_getName([query class]) : "-",
        [tableView isKindOfClass:UIView.class] ? [tableView window] : nil);
}

static void CNDSurfaceTraceLibraryListReloadVisible(id self, SEL selector)
{
    CNDSurfaceTraceContext previous = CNDSurfaceTracePushContext(
        CNDSurfaceTraceScopeAppLibraryList, self, nil, nil);
    CNDSurfaceTraceLogLibraryListControllerState(
        "library-list-reload-visible-begin", self);
    gCNDOriginalLibraryListReloadVisible(self, selector);
    CNDSurfaceTraceLogLibraryListControllerState(
        "library-list-reload-visible-end", self);
    CNDSurfaceTracePopContext(previous);
}

static void CNDSurfaceTraceLibraryListReloadApps(id self, SEL selector)
{
    CNDSurfaceTraceContext previous = CNDSurfaceTracePushContext(
        CNDSurfaceTraceScopeAppLibraryList, self, nil, nil);
    CNDSurfaceTraceLogLibraryListControllerState(
        "library-list-reload-apps-begin", self);
    gCNDOriginalLibraryListReloadApps(self, selector);
    CNDSurfaceTraceLogLibraryListControllerState(
        "library-list-reload-apps-end", self);
    CNDSurfaceTracePopContext(previous);
}

static void CNDSurfaceTraceLibraryListRefreshIcon(id self, SEL selector,
                                                  id icon)
{
    CNDSurfaceTraceContext previous = CNDSurfaceTracePushContext(
        CNDSurfaceTraceScopeAppLibraryList, self, icon, nil);
    CNDSurfaceTraceLogIconState("library-list-refresh-icon-begin", icon);
    gCNDOriginalLibraryListRefreshIcon(self, selector, icon);
    CNDSurfaceTraceLogIconState("library-list-refresh-icon-end", icon);
    CNDSurfaceTracePopContext(previous);
}

static void CNDSurfaceTraceLibrarySearchSetActive(id self, SEL selector,
                                                  BOOL active)
{
    id results = CNDSurfaceTraceSafeObject(self, "searchResultsController");
    CNDSurfaceTraceLog(
        "[CND_SURFACE] library-list search-active-begin controller=%p/%s "
        "active=%d results=%p/%s\n", self,
        self ? class_getName([self class]) : "-", active ? 1 : 0,
        results, results ? class_getName([results class]) : "-");
    gCNDOriginalLibrarySearchSetActive(self, selector, active);
    results = CNDSurfaceTraceSafeObject(self, "searchResultsController");
    CNDSurfaceTraceLog(
        "[CND_SURFACE] library-list search-active-end controller=%p/%s "
        "active=%d results=%p/%s\n", self,
        self ? class_getName([self class]) : "-", active ? 1 : 0,
        results, results ? class_getName([results class]) : "-");
}

static id CNDSurfaceTraceFolderGridImage(id self, SEL selector, id icon,
                                         id appearance)
{
    bool ownsContext = gCNDSurfaceTraceContext.scope ==
        CNDSurfaceTraceScopeNone;
    CNDSurfaceTraceContext previous = gCNDSurfaceTraceContext;
    if (ownsContext) {
        previous = CNDSurfaceTracePushContext(
            CNDSurfaceTraceScopeFolderPreview, self, icon, nil);
    }
    CNDSurfaceTraceLogEventPrefix("folder-grid-begin");
    CNDSurfaceTraceLog(
        "cache=%p/%s icon=%p/%s id=%s generation=%llu "
        "appearance=%p/%s\n", self,
        self ? class_getName([self class]) : "-", icon,
        icon ? class_getName([icon class]) : "-",
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-",
        (unsigned long long)CNDSurfaceTraceGeneration(icon), appearance,
        appearance ? class_getName([appearance class]) : "-");
    CNDSurfaceTraceLogCacheState(
        "folder-grid-cache-before", self, icon, nil);
    id image = gCNDOriginalFolderGridImage(
        self, selector, icon, appearance);
    CNDSurfaceTraceLogCacheState(
        "folder-grid-cache-after", self, icon, image);
    CNDSurfaceTraceLogImage("folder-grid-result", image);
    CNDSurfaceTraceLogEventPrefix("folder-grid-end");
    CNDSurfaceTraceLog(
        "cache=%p/%s icon=%p/%s id=%s appearance=%p/%s "
        "image=%p/%s\n", self,
        self ? class_getName([self class]) : "-", icon,
        icon ? class_getName([icon class]) : "-",
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-", appearance,
        appearance ? class_getName([appearance class]) : "-", image,
        image ? class_getName([image class]) : "-");
    if (ownsContext) CNDSurfaceTracePopContext(previous);
    return image;
}

static id CNDSurfaceTraceFolderGridRenderer(
    id self, SEL selector, CGSize size, id icon,
    CNDIconImageInfo iconImageInfo, id appearance,
    const uint64_t *imageAttributes)
{
    bool ownsContext = gCNDSurfaceTraceContext.scope ==
        CNDSurfaceTraceScopeNone;
    CNDSurfaceTraceContext previous = gCNDSurfaceTraceContext;
    if (ownsContext) {
        previous = CNDSurfaceTracePushContext(
            CNDSurfaceTraceScopeFolderPreview, self, icon, nil);
    }
    CNDSurfaceTraceLogEventPrefix("folder-renderer-begin");
    CNDSurfaceTraceLog(
        "class=%p/%s icon=%p/%s id=%s size=%.3fx%.3f "
        "icon-info=%.3fx%.3f@%.3f/r%.3f appearance=%p/%s "
        "attributes=%p/%s stack=%s\n", self,
        self ? class_getName(self) : "-", icon,
        icon ? class_getName([icon class]) : "-",
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-",
        size.width, size.height, iconImageInfo.size.width,
        iconImageInfo.size.height, iconImageInfo.scale,
        iconImageInfo.continuousCornerRadius, appearance,
        appearance ? class_getName([appearance class]) : "-",
        imageAttributes, imageAttributes ? "uint64-pointer" : "-",
        CNDSurfaceTraceShortStack().UTF8String ?: "-");
    id image = gCNDOriginalFolderGridRenderer(
        self, selector, size, icon, iconImageInfo, appearance,
        imageAttributes);
    CNDSurfaceTraceLogImage("folder-renderer-result", image);
    CNDSurfaceTraceLogEventPrefix("folder-renderer-end");
    CNDSurfaceTraceLog(
        "class=%p icon=%p/%s id=%s size=%.3fx%.3f image=%p/%s\n",
        self, icon, icon ? class_getName([icon class]) : "-",
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-",
        size.width, size.height, image,
        image ? class_getName([image class]) : "-");
    if (ownsContext) CNDSurfaceTracePopContext(previous);
    return image;
}

static id CNDSurfaceTraceFolderGridCompositor(id self, SEL selector,
                                               CGSize size, id iconImage)
{
    uint64_t sample = atomic_fetch_add_explicit(
        &gCNDSurfaceTraceCompositeSamples, 1U,
        memory_order_relaxed) + 1U;
    CNDSurfaceTraceLogEventPrefix("folder-compositor-begin");
    CNDSurfaceTraceLog(
        "sample=%llu class=%p/%s size=%.3fx%.3f source=%p/%s "
        "icon=%p/%s id=%s stack=%s\n", (unsigned long long)sample,
        self, self ? class_getName(self) : "-", size.width, size.height,
        iconImage, iconImage ? class_getName([iconImage class]) : "-",
        gCNDSurfaceTraceContext.icon,
        gCNDSurfaceTraceContext.icon
            ? class_getName([gCNDSurfaceTraceContext.icon class]) : "-",
        CNDSurfaceTraceIdentifier(
            gCNDSurfaceTraceContext.icon).UTF8String ?: "-",
        CNDSurfaceTraceShortStack().UTF8String ?: "-");
    CNDSurfaceTraceLogImage("folder-compositor-source", iconImage);
    CNDSurfaceTraceWriteCompositeEvidence(sample, @"source", iconImage);
    id image = gCNDOriginalFolderGridCompositor(
        self, selector, size, iconImage);
    CNDSurfaceTraceLogImage("folder-compositor-result", image);
    CNDSurfaceTraceWriteCompositeEvidence(sample, @"result", image);
    CNDSurfaceTraceLogEventPrefix("folder-compositor-end");
    CNDSurfaceTraceLog(
        "sample=%llu class=%p size=%.3fx%.3f source=%p result=%p/%s\n",
        (unsigned long long)sample, self, size.width, size.height,
        iconImage, image, image ? class_getName([image class]) : "-");
    return image;
}

static void CNDSurfaceTraceIconViewUpdate(id self, SEL selector, BOOL animated)
{
    CNDSurfaceTraceLogIconConsumer("icon-view-update-begin", self);
    gCNDOriginalIconViewUpdate(self, selector, animated);
    CNDSurfaceTraceLogIconConsumer("icon-view-update-end", self);
}

static void CNDSurfaceTraceIconViewCrossfade(id self, SEL selector, id view)
{
    CNDSurfaceTraceLogIconConsumer("crossfade-one-begin", self);
    gCNDOriginalIconViewCrossfade(self, selector, view);
    CNDSurfaceTraceLogIconConsumer("crossfade-one-end", self);
}

static void CNDSurfaceTraceIconViewCrossfadeOptions(id self, SEL selector,
                                                     id view,
                                                     NSUInteger options)
{
    CNDSurfaceTraceLogIconConsumer("crossfade-options-begin", self);
    gCNDOriginalIconViewCrossfadeOptions(self, selector, view, options);
    CNDSurfaceTraceLogIconConsumer("crossfade-options-end", self);
}

static void CNDSurfaceTraceIconViewCrossfadeAnchorOptions(
    id self, SEL selector, id view, CGPoint anchorPoint, NSUInteger options)
{
    CNDSurfaceTraceLog(
        "[CND_SURFACE] launch event=crossfade-anchor-args owner=%p "
        "other=%p anchor=%.3f,%.3f options=%lu\n", self, view,
        anchorPoint.x, anchorPoint.y, (unsigned long)options);
    CNDSurfaceTraceLogIconConsumer("crossfade-anchor-begin", self);
    gCNDOriginalIconViewCrossfadeAnchorOptions(
        self, selector, view, anchorPoint, options);
    CNDSurfaceTraceLogIconConsumer("crossfade-anchor-end", self);
}

static BOOL CNDSurfaceTraceImageUpdateFromCache(id self, SEL selector,
                                                 BOOL animated)
{
    CNDSurfaceTraceLogIconConsumer("cache-update-begin", self);
    BOOL result = gCNDOriginalImageUpdateFromCache(self, selector, animated);
    CNDSurfaceTraceLogIconConsumer(
        result ? "cache-update-end-hit" : "cache-update-end-miss", self);
    return result;
}

static void CNDSurfaceTraceImageViewIconImageDidUpdate(id self, SEL selector,
                                                       id icon)
{
    CNDSurfaceTraceLogIconConsumer("view-icon-update-begin", self);
    gCNDOriginalImageViewIconImageDidUpdate(self, selector, icon);
    CNDSurfaceTraceLogIconConsumer("view-icon-update-end", self);
}

static void CNDSurfaceTraceImageViewCacheDidUpdate(id self, SEL selector,
                                                   id cache, id icon,
                                                   id appearance)
{
    CNDSurfaceTraceLogIconConsumer("view-cache-update-begin", self);
    CNDSurfaceTraceLogCacheState(
        "view-cache-update-source", cache, icon, nil);
    gCNDOriginalImageViewCacheDidUpdate(
        self, selector, cache, icon, appearance);
    CNDSurfaceTraceLogIconConsumer("view-cache-update-end", self);
}

static void CNDSurfaceTraceImageViewUpdateImage(id self, SEL selector,
                                                BOOL animated)
{
    CNDSurfaceTraceLogIconConsumer("view-update-image-begin", self);
    gCNDOriginalImageViewUpdateImage(self, selector, animated);
    CNDSurfaceTraceLogIconConsumer("view-update-image-end", self);
}

static void CNDSurfaceTraceImageViewLoadFromCache(id self, SEL selector,
                                                  id cache, BOOL animated)
{
    CNDSurfaceTraceLogIconConsumer("view-load-cache-begin", self);
    gCNDOriginalImageViewLoadFromCache(
        self, selector, cache, animated);
    CNDSurfaceTraceLogIconConsumer("view-load-cache-end", self);
}

static void CNDSurfaceTraceImageViewClearCachedImages(id self, SEL selector)
{
    CNDSurfaceTraceLogIconConsumer("view-clear-cached-begin", self);
    gCNDOriginalImageViewClearCachedImages(self, selector);
    CNDSurfaceTraceLogIconConsumer("view-clear-cached-end", self);
}

static void CNDSurfaceTraceImageUpdateContents(id self, SEL selector,
                                                id image, id appearance,
                                                BOOL animated)
{
    id icon = CNDSurfaceTraceObject(self, "icon");
    CNDSurfaceTraceLog(
        "[CND_SURFACE] launch event=contents-update consumer=%p/%s "
        "icon=%p id=%s image=%p/%s appearance=%p animated=%d\n",
        self, class_getName([self class]), icon,
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-", image,
        image ? class_getName([image class]) : "-", appearance,
        animated ? 1 : 0);
    gCNDOriginalImageUpdateContents(
        self, selector, image, appearance, animated);
}

static void CNDSurfaceTraceSetDisplayedImage(id self, SEL selector, id image)
{
    id icon = CNDSurfaceTraceObject(self, "icon");
    CNDSurfaceTraceLog(
        "[CND_SURFACE] launch event=set-displayed consumer=%p/%s icon=%p "
        "id=%s image=%p/%s\n", self, class_getName([self class]), icon,
        CNDSurfaceTraceIdentifier(icon).UTF8String ?: "-", image,
        image ? class_getName([image class]) : "-");
    gCNDOriginalSetDisplayedImage(self, selector, image);
}

static void CNDSurfaceTraceCrossfadePrepareGeometry(id self, SEL selector)
{
    CNDSurfaceTraceLog(
        "[CND_SURFACE] launch event=crossfade-prepare view=%p/%s source=%p "
        "image-view=%p\n", self, class_getName([self class]),
        CNDSurfaceTraceObject(self, "iconImageSource"),
        CNDSurfaceTraceObject(self, "iconImageView"));
    gCNDOriginalCrossfadePrepareGeometry(self, selector);
}

static void CNDSurfaceTraceDoubleCrossfadePrepareGeometry(id self,
                                                           SEL selector)
{
    CNDSurfaceTraceLog(
        "[CND_SURFACE] launch event=double-crossfade-prepare view=%p/%s "
        "source=%p image-view=%p\n", self,
        class_getName([self class]),
        CNDSurfaceTraceObject(self, "iconImageSource"),
        CNDSurfaceTraceObject(self, "iconImageView"));
    gCNDOriginalDoubleCrossfadePrepareGeometry(self, selector);
}

static bool CNDSurfaceTraceRelevantSelector(const char *name)
{
    if (!name) return false;
    static const char *const tokens[] = {
        "cache", "Cache", "image", "Image", "icon", "Icon",
        "grid", "Grid", "folder", "Folder", "reload", "Reload",
        "refresh", "Refresh", "rebuild", "Rebuild", "update", "Update",
        "configure", "Configure", "display", "Display", "layout", "Layout",
    };
    for (size_t index = 0;
         index < sizeof(tokens) / sizeof(tokens[0]); index++) {
        if (strstr(name, tokens[index])) return true;
    }
    return false;
}

static void CNDSurfaceTraceDumpClass(const char *role, Class cls)
{
    CNDSurfaceTraceLog(
        "[CND_INVENTORY] role=%s class=%s loaded=%d address=%p "
        "superclass=%s\n", role ?: "-", cls ? class_getName(cls) : "-",
        cls ? 1 : 0, cls,
        cls && class_getSuperclass(cls)
            ? class_getName(class_getSuperclass(cls)) : "-");
    if (!cls) return;
    unsigned methodCount = 0U;
    Method *methods = class_copyMethodList(cls, &methodCount);
    for (unsigned index = 0; methods && index < methodCount; index++) {
        SEL selector = method_getName(methods[index]);
        const char *name = selector ? sel_getName(selector) : NULL;
        if (!CNDSurfaceTraceRelevantSelector(name)) continue;
        CNDSurfaceTraceLog(
            "[CND_INVENTORY] role=%s class=%s selector=%s types=%s imp=%p\n",
            role ?: "-", class_getName(cls), name ?: "-",
            method_getTypeEncoding(methods[index]) ?: "-",
            method_getImplementation(methods[index]));
    }
    free(methods);
    Class metaclass = object_getClass(cls);
    methodCount = 0U;
    methods = metaclass ? class_copyMethodList(metaclass, &methodCount) : NULL;
    for (unsigned index = 0; methods && index < methodCount; index++) {
        SEL selector = method_getName(methods[index]);
        const char *name = selector ? sel_getName(selector) : NULL;
        if (!CNDSurfaceTraceRelevantSelector(name)) continue;
        CNDSurfaceTraceLog(
            "[CND_INVENTORY] role=%s class=%s class-selector=%s "
            "types=%s imp=%p\n", role ?: "-", class_getName(cls),
            name ?: "-", method_getTypeEncoding(methods[index]) ?: "-",
            method_getImplementation(methods[index]));
    }
    free(methods);
    unsigned inheritedDepth = 0U;
    for (Class cursor = cls; cursor && inheritedDepth < 4U;
         cursor = class_getSuperclass(cursor), inheritedDepth++) {
        unsigned ivarCount = 0U;
        Ivar *ivars = class_copyIvarList(cursor, &ivarCount);
        for (unsigned index = 0; ivars && index < ivarCount; index++) {
            const char *name = ivar_getName(ivars[index]);
            if (!CNDSurfaceTraceRelevantSelector(name)) continue;
            CNDSurfaceTraceLog(
                "[CND_INVENTORY] role=%s class=%s ivar-owner=%s "
                "ivar=%s type=%s offset=%td\n", role ?: "-",
                class_getName(cls), class_getName(cursor), name ?: "-",
                ivar_getTypeEncoding(ivars[index]) ?: "-",
                ivar_getOffset(ivars[index]));
        }
        free(ivars);
        if (!strcmp(class_getName(cursor), "NSObject")) break;
    }
}

static void CNDSurfaceTraceDumpConsumerInventory(void)
{
    static const char *const classNames[] = {
        "SBHLibraryCategoryPodIconListView",
        "SBHLibraryCategoryPodIconView",
        "SBHLibraryPodFolderController",
        "SBHLibraryPodFolderView",
        "SBHLibraryViewController",
        "SBHLibrarySearchController",
        "SBHIconLibraryTableViewController",
        "SBHIconTableViewCell",
        "SBHIconTableViewDiffableDataSource",
        "SBHTableViewIconLibrary",
        "_SBHIconLibraryTableView",
        "SBFolderIcon",
        "SBFolderIconImageCache",
        "SBFolderIconImageView",
        "SBHFolderIconImageView",
        "SBIconImageView",
        "SBHIconImageCache",
    };
    for (size_t index = 0;
         index < sizeof(classNames) / sizeof(classNames[0]); index++) {
        CNDSurfaceTraceDumpClass(
            strstr(classNames[index], "Library")
                ? "app-library" : "folder",
            objc_getClass(classNames[index]));
    }

    CNDSurfaceTraceLog(
        "[CND_INVENTORY] explicit-consumer-inventory-complete count=%zu\n",
        sizeof(classNames) / sizeof(classNames[0]));
}

static bool CNDSurfaceTraceHook(const char *className,
                                const char *selectorName, IMP replacement,
                                IMP *originalOut)
{
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    if (!method) {
        CNDSurfaceTraceLog(
            "[CND_SURFACE] hook class=%s selector=%s ok=0 reason=missing\n",
            className, selectorName);
        return false;
    }
    IMP original = method_getImplementation(method);
    if (!original) return false;
    const char *types = method_getTypeEncoding(method);
    if (!class_addMethod(cls, selector, replacement, types)) {
        method_setImplementation(method, replacement);
    }
    IMP observed = class_getMethodImplementation(cls, selector);
    if (originalOut) *originalOut = original;
    bool ok = observed == replacement;
    CNDSurfaceTraceLog(
        "[CND_SURFACE] hook class=%s selector=%s ok=%d original=%p "
        "replacement=%p observed=%p types=%s\n", className, selectorName,
        ok ? 1 : 0, original, replacement, observed,
        types ?: "-");
    return ok;
}

static bool CNDSurfaceTraceMethodReturnsObject(Method method)
{
    char *returnType = method ? method_copyReturnType(method) : NULL;
    const char *type = CNDSurfaceTraceSkipTypeQualifiers(returnType);
    bool valid = type && *type == '@';
    free(returnType);
    return valid;
}

static bool CNDSurfaceTraceMethodArgumentIsObject(Method method,
                                                   unsigned index)
{
    char *argumentType = method ? method_copyArgumentType(method, index)
                                : NULL;
    const char *type = CNDSurfaceTraceSkipTypeQualifiers(argumentType);
    bool valid = type && *type == '@';
    free(argumentType);
    return valid;
}

static bool CNDSurfaceTraceMethodArgumentContains(Method method,
                                                   unsigned index,
                                                   const char *token)
{
    char *argumentType = method ? method_copyArgumentType(method, index)
                                : NULL;
    bool valid = argumentType && token && strstr(argumentType, token);
    free(argumentType);
    return valid;
}

static bool CNDSurfaceTraceHookFolderClassMethod(
    const char *selectorName, IMP replacement, IMP *originalOut,
    bool renderer)
{
    const char *className = "SBFolderIconImageCache";
    Class cls = objc_getClass(className);
    Class metaclass = cls ? object_getClass(cls) : Nil;
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getClassMethod(cls, selector) : NULL;
    unsigned expectedArguments = renderer ? 7U : 4U;
    bool abiOK = method && metaclass &&
        method_getNumberOfArguments(method) == expectedArguments &&
        CNDSurfaceTraceMethodReturnsObject(method) &&
        CNDSurfaceTraceMethodArgumentContains(method, 2U, "CGSize") &&
        CNDSurfaceTraceMethodArgumentIsObject(method, 3U);
    if (abiOK && renderer) {
        abiOK = CNDSurfaceTraceMethodArgumentContains(
                    method, 4U, "SBIconImageInfo") &&
            CNDSurfaceTraceMethodArgumentIsObject(method, 5U) &&
            CNDSurfaceTraceMethodArgumentContains(method, 6U, "^Q");
    }
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (!abiOK) {
        CNDSurfaceTraceLog(
            "[CND_SURFACE] class-hook class=%s selector=%s ok=0 "
            "reason=abi arguments=%u expected=%u types=%s\n",
            className, selectorName,
            method ? method_getNumberOfArguments(method) : 0U,
            expectedArguments, types ?: "-");
        return false;
    }
    IMP original = method_getImplementation(method);
    if (!original) return false;
    if (!class_addMethod(metaclass, selector, replacement, types)) {
        method_setImplementation(method, replacement);
    }
    IMP observed = class_getMethodImplementation(metaclass, selector);
    if (originalOut) *originalOut = original;
    bool ok = observed == replacement;
    CNDSurfaceTraceLog(
        "[CND_SURFACE] class-hook class=%s selector=%s ok=%d "
        "original=%p replacement=%p observed=%p types=%s\n",
        className, selectorName, ok ? 1 : 0, original, replacement,
        observed, types ?: "-");
    return ok;
}

static bool CNDSurfaceTraceHookDescriptor(const char *selectorName,
                                          IMP replacement,
                                          IMP *originalOut)
{
    Class cls = objc_getClass("ISBundleIdentifierIcon");
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    if (!method || method_getNumberOfArguments(method) != 3U) {
        CNDSurfaceTraceLog(
            "[CND_SURFACE] descriptor-hook selector=%s ok=0 "
            "reason=missing-or-arity\n", selectorName);
        return false;
    }
    char *returnType = method_copyReturnType(method);
    const char *type = CNDSurfaceTraceSkipTypeQualifiers(returnType);
    bool valid = type && *type == '@';
    free(returnType);
    if (!valid) {
        CNDSurfaceTraceLog(
            "[CND_SURFACE] descriptor-hook selector=%s ok=0 "
            "reason=return-type\n", selectorName);
        return false;
    }
    return CNDSurfaceTraceHook(
        "ISBundleIdentifierIcon", selectorName, replacement, originalOut);
}

__attribute__((constructor))
static void CNDSurfaceTraceStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_SURFACE_TRACE_OUTPUT_TOKEN[0] && consume
            ? consume(CND_SURFACE_TRACE_OUTPUT_TOKEN) : -1;
        gCNDSurfaceTraceFD = open(
            CND_SURFACE_TRACE_OUTPUT_PATH,
            O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        CNDSurfaceTraceLog(
            "[CND_SURFACE] START pid=%d process=%s token=%lld "
            "mode=inspection-only descriptor-target=%s\n", getpid(),
            getprogname(), (long long)token,
            CND_SURFACE_TRACE_TARGET_BUNDLE);
        (void)dlopen(
            "/System/Library/PrivateFrameworks/SpringBoardHome.framework/"
            "SpringBoardHome", RTLD_NOW | RTLD_LOCAL);
        (void)dlopen(
            "/System/Library/PrivateFrameworks/UserNotificationsUIKit.framework/"
            "UserNotificationsUIKit", RTLD_NOW | RTLD_LOCAL);
        (void)dlopen(
            "/System/Library/PrivateFrameworks/IconServices.framework/"
            "IconServices", RTLD_NOW | RTLD_LOCAL);

        CNDSurfaceTraceDumpConsumerInventory();

        bool ok = true;
        unsigned optionalHooks = 0U;
        unsigned descriptorHooks = 0U;
        unsigned libraryListHooks = 0U;
        descriptorHooks += CNDSurfaceTraceHookDescriptor(
            "imageForDescriptor:",
            (IMP)CNDSurfaceTraceISImageForDescriptor,
            &gCNDOriginalISImageForDescriptor);
        descriptorHooks += CNDSurfaceTraceHookDescriptor(
            "generateImageWithDescriptor:",
            (IMP)CNDSurfaceTraceISGenerateForDescriptor,
            &gCNDOriginalISGenerateForDescriptor);
        ok &= CNDSurfaceTraceHook(
            "SBFluidSwitcherSpaceTitleItemController",
            "_iconImageForDisplayItem:",
            (IMP)CNDSurfaceTraceSwitcherImage,
            (IMP *)&gCNDOriginalSwitcherImage);
        ok &= CNDSurfaceTraceHook(
            "SBHIconImageCache", "imageForIcon:imageAppearance:options:",
            (IMP)CNDSurfaceTraceImageForIcon,
            (IMP *)&gCNDOriginalImageForIcon);
        ok &= CNDSurfaceTraceHook(
            "SBIcon", "reloadIconImage",
            (IMP)CNDSurfaceTraceIconReloadImage,
            (IMP *)&gCNDOriginalIconReloadImage);
        ok &= CNDSurfaceTraceHook(
            "SBIcon", "_notifyImageDidUpdate",
            (IMP)CNDSurfaceTraceIconNotifyImageUpdate,
            (IMP *)&gCNDOriginalIconNotifyImageUpdate);
        ok &= CNDSurfaceTraceHook(
            "SBIcon", "updateImageInIconLayerView:",
            (IMP)CNDSurfaceTraceIconUpdateLayerView,
            (IMP *)&gCNDOriginalIconUpdateLayerView);
        ok &= CNDSurfaceTraceHook(
            "SBHIconImageCache", "beginObservingIconIfNecessary:",
            (IMP)CNDSurfaceTraceCacheBeginObservingIcon,
            (IMP *)&gCNDOriginalCacheBeginObservingIcon);
        ok &= CNDSurfaceTraceHook(
            "SBHIconImageCache", "iconImageDidUpdate:",
            (IMP)CNDSurfaceTraceCacheIconImageDidUpdate,
            (IMP *)&gCNDOriginalCacheIconImageDidUpdate);
        ok &= CNDSurfaceTraceHook(
            "SBHIconImageCache", "updateImageForIcon:",
            (IMP)CNDSurfaceTraceCacheUpdateImageForIcon,
            (IMP *)&gCNDOriginalCacheUpdateImageForIcon);
        ok &= CNDSurfaceTraceHook(
            "SBHIconImageCache", "cacheImage:forIcon:imageAppearance:",
            (IMP)CNDSurfaceTraceCacheImage,
            (IMP *)&gCNDOriginalCacheImage);
        ok &= CNDSurfaceTraceHook(
            "SBHIconManager", "resetAllIconImageCaches",
            (IMP)CNDSurfaceTraceResetAllCaches,
            (IMP *)&gCNDOriginalResetAllCaches);
        ok &= CNDSurfaceTraceHook(
            "SBHIconImageCache", "purgeAllCachedImages",
            (IMP)CNDSurfaceTracePurgeAllImages,
            (IMP *)&gCNDOriginalPurgeAllImages);
        ok &= CNDSurfaceTraceHook(
            "NCBadgedIconView", "_updateVisibleIcons",
            (IMP)CNDSurfaceTraceNotificationUpdate,
            (IMP *)&gCNDOriginalNotificationUpdate);
        ok &= CNDSurfaceTraceHook(
            "SBHLibraryPodFolderController", "_reloadAppIcons",
            (IMP)CNDSurfaceTraceLibraryReload,
            (IMP *)&gCNDOriginalLibraryReload);
        ok &= CNDSurfaceTraceHook(
            "SBHLibraryViewController", "_enqueueAppLibraryUpdate",
            (IMP)CNDSurfaceTraceLibraryEnqueue,
            (IMP *)&gCNDOriginalLibraryEnqueue);
        ok &= CNDSurfaceTraceHook(
            "SBHLibraryViewController",
            "layoutIconListsWithAnimationType:forceRelayout:",
            (IMP)CNDSurfaceTraceLibraryLayout,
            (IMP *)&gCNDOriginalLibraryLayout);
        ok &= CNDSurfaceTraceHook(
            "SBFolderIconImageCache", "rebuildAllCachedFolderImages",
            (IMP)CNDSurfaceTraceFolderRebuild,
            (IMP *)&gCNDOriginalFolderRebuild);
        ok &= CNDSurfaceTraceHook(
            "SBHLibraryCategoryPodIconListView",
            "configureIconView:forIcon:",
            (IMP)CNDSurfaceTraceLibraryConfigure,
            (IMP *)&gCNDOriginalLibraryConfigure);
        libraryListHooks += CNDSurfaceTraceHook(
            "SBHIconLibraryTableViewController", "_configureCell:forIcon:",
            (IMP)CNDSurfaceTraceLibraryListConfigure,
            (IMP *)&gCNDOriginalLibraryListConfigure);
        libraryListHooks += CNDSurfaceTraceHook(
            "SBHIconTableViewCell", "configureCellForIcon:",
            (IMP)CNDSurfaceTraceLibraryListCellConfigure,
            (IMP *)&gCNDOriginalLibraryListCellConfigure);
        libraryListHooks += CNDSurfaceTraceHook(
            "SBHIconLibraryTableViewController", "_reloadVisibleCells",
            (IMP)CNDSurfaceTraceLibraryListReloadVisible,
            (IMP *)&gCNDOriginalLibraryListReloadVisible);
        libraryListHooks += CNDSurfaceTraceHook(
            "SBHIconLibraryTableViewController", "_reloadAppIcons",
            (IMP)CNDSurfaceTraceLibraryListReloadApps,
            (IMP *)&gCNDOriginalLibraryListReloadApps);
        libraryListHooks += CNDSurfaceTraceHook(
            "SBHIconLibraryTableViewController", "_refreshIconIfVisible:",
            (IMP)CNDSurfaceTraceLibraryListRefreshIcon,
            (IMP *)&gCNDOriginalLibraryListRefreshIcon);
        libraryListHooks += CNDSurfaceTraceHook(
            "SBHLibrarySearchController", "setActive:",
            (IMP)CNDSurfaceTraceLibrarySearchSetActive,
            (IMP *)&gCNDOriginalLibrarySearchSetActive);
        ok &= libraryListHooks == 6U;
        ok &= CNDSurfaceTraceHook(
            "SBFolderIconImageCache", "gridCellImageForIcon:imageAppearance:",
            (IMP)CNDSurfaceTraceFolderGridImage,
            (IMP *)&gCNDOriginalFolderGridImage);
        ok &= CNDSurfaceTraceHookFolderClassMethod(
            "gridCellImageOfSize:forIcon:iconImageInfo:imageAppearance:"
            "imageAttributes:",
            (IMP)CNDSurfaceTraceFolderGridRenderer,
            (IMP *)&gCNDOriginalFolderGridRenderer, true);
        ok &= CNDSurfaceTraceHookFolderClassMethod(
            "gridCellImageOfSize:forIconImage:",
            (IMP)CNDSurfaceTraceFolderGridCompositor,
            (IMP *)&gCNDOriginalFolderGridCompositor, false);
        optionalHooks += CNDSurfaceTraceHook(
            "SBFolderIcon", "reloadIconImage",
            (IMP)CNDSurfaceTraceFolderIconReloadImage,
            (IMP *)&gCNDOriginalFolderIconReloadImage);
        optionalHooks += CNDSurfaceTraceHook(
            "SBFolderIcon", "updateImageInIconLayerView:",
            (IMP)CNDSurfaceTraceFolderIconUpdateLayerView,
            (IMP *)&gCNDOriginalFolderIconUpdateLayerView);
        ok &= CNDSurfaceTraceHook(
            "SBIconView", "_updateIconImageViewAnimated:",
            (IMP)CNDSurfaceTraceIconViewUpdate,
            (IMP *)&gCNDOriginalIconViewUpdate);
        ok &= CNDSurfaceTraceHook(
            "SBIconView", "prepareToCrossfadeImageWithView:",
            (IMP)CNDSurfaceTraceIconViewCrossfade,
            (IMP *)&gCNDOriginalIconViewCrossfade);
        ok &= CNDSurfaceTraceHook(
            "SBIconView", "prepareToCrossfadeImageWithView:options:",
            (IMP)CNDSurfaceTraceIconViewCrossfadeOptions,
            (IMP *)&gCNDOriginalIconViewCrossfadeOptions);
        ok &= CNDSurfaceTraceHook(
            "SBIconView",
            "prepareToCrossfadeImageWithView:anchorPoint:options:",
            (IMP)CNDSurfaceTraceIconViewCrossfadeAnchorOptions,
            (IMP *)&gCNDOriginalIconViewCrossfadeAnchorOptions);
        ok &= CNDSurfaceTraceHook(
            "SBIconImageView", "updateImageContentsFromCacheAnimated:",
            (IMP)CNDSurfaceTraceImageUpdateFromCache,
            (IMP *)&gCNDOriginalImageUpdateFromCache);
        ok &= CNDSurfaceTraceHook(
            "SBIconImageView", "iconImageDidUpdate:",
            (IMP)CNDSurfaceTraceImageViewIconImageDidUpdate,
            (IMP *)&gCNDOriginalImageViewIconImageDidUpdate);
        ok &= CNDSurfaceTraceHook(
            "SBIconImageView",
            "iconImageCache:didUpdateImageForIcon:imageAppearance:",
            (IMP)CNDSurfaceTraceImageViewCacheDidUpdate,
            (IMP *)&gCNDOriginalImageViewCacheDidUpdate);
        ok &= CNDSurfaceTraceHook(
            "SBIconImageView", "updateImageAnimated:",
            (IMP)CNDSurfaceTraceImageViewUpdateImage,
            (IMP *)&gCNDOriginalImageViewUpdateImage);
        ok &= CNDSurfaceTraceHook(
            "SBIconImageView", "loadContentsImageFromCache:animated:",
            (IMP)CNDSurfaceTraceImageViewLoadFromCache,
            (IMP *)&gCNDOriginalImageViewLoadFromCache);
        ok &= CNDSurfaceTraceHook(
            "SBIconImageView", "clearCachedImages",
            (IMP)CNDSurfaceTraceImageViewClearCachedImages,
            (IMP *)&gCNDOriginalImageViewClearCachedImages);
        ok &= CNDSurfaceTraceHook(
            "SBIconImageView",
            "updateImageContentsWithImage:imageAppearance:animated:",
            (IMP)CNDSurfaceTraceImageUpdateContents,
            (IMP *)&gCNDOriginalImageUpdateContents);
        ok &= CNDSurfaceTraceHook(
            "SBIconImageView", "setDisplayedImage:",
            (IMP)CNDSurfaceTraceSetDisplayedImage,
            (IMP *)&gCNDOriginalSetDisplayedImage);
        ok &= CNDSurfaceTraceHook(
            "SBIconImageCrossfadeView", "prepareGeometry",
            (IMP)CNDSurfaceTraceCrossfadePrepareGeometry,
            (IMP *)&gCNDOriginalCrossfadePrepareGeometry);
        ok &= CNDSurfaceTraceHook(
            "SBHDoubleSidedIconImageCrossfadeView", "prepareGeometry",
            (IMP)CNDSurfaceTraceDoubleCrossfadePrepareGeometry,
            (IMP *)&gCNDOriginalDoubleCrossfadePrepareGeometry);
        CNDSurfaceTraceLog(
            "[CND_SURFACE] TRACE_READY pid=%d ok=%d descriptor-hooks=%u "
            "library-list-hooks=%u/6 folder-optional-hooks=%u\n",
            getpid(), ok ? 1 : 0, descriptorHooks, libraryListHooks,
            optionalHooks);
        if (CND_SURFACE_TRACE_OPEN_BUNDLE[0]) {
            NSString *bundle = [NSString stringWithUTF8String:
                CND_SURFACE_TRACE_OPEN_BUNDLE];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                         750 * NSEC_PER_MSEC),
                           dispatch_get_main_queue(), ^{
                (void)dlopen(
                    "/System/Library/Frameworks/CoreServices.framework/"
                    "CoreServices", RTLD_NOW | RTLD_LOCAL);
                Class workspaceClass = NSClassFromString(
                    @"LSApplicationWorkspace");
                SEL defaultSelector = NSSelectorFromString(
                    @"defaultWorkspace");
                id workspace = workspaceClass &&
                    [workspaceClass respondsToSelector:defaultSelector]
                    ? ((id (*)(id, SEL))objc_msgSend)(
                        workspaceClass, defaultSelector) : nil;
                SEL openSelector = NSSelectorFromString(
                    @"openApplicationWithBundleID:");
                BOOL opened = workspace &&
                    [workspace respondsToSelector:openSelector] &&
                    ((BOOL (*)(id, SEL, id))objc_msgSend)(
                        workspace, openSelector, bundle);
                CNDSurfaceTraceLog(
                    "[CND_SURFACE] OPEN bundle=%s accepted=%d\n",
                    bundle.UTF8String ?: "-", opened ? 1 : 0);
            });
        }
    }
}
