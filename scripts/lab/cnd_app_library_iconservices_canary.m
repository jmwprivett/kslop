#import <Foundation/Foundation.h>

#import <CoreGraphics/CoreGraphics.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef CND_APP_LIBRARY_CANARY_OUTPUT_TOKEN
#define CND_APP_LIBRARY_CANARY_OUTPUT_TOKEN ""
#endif

#ifndef CND_APP_LIBRARY_CANARY_REPORT_PATH
#define CND_APP_LIBRARY_CANARY_REPORT_PATH \
    "/var/tmp/cyanide-app-library-iconservices-canary.log"
#endif

#ifndef CND_APP_LIBRARY_CANARY_TARGET_BUNDLE
#define CND_APP_LIBRARY_CANARY_TARGET_BUNDLE "com.apple.Preview"
#endif

#ifndef CND_APP_LIBRARY_CANARY_EXPECTED_PID
#define CND_APP_LIBRARY_CANARY_EXPECTED_PID 0
#endif

#ifndef CND_APP_LIBRARY_CANARY_HOLD_SECONDS
#define CND_APP_LIBRARY_CANARY_HOLD_SECONDS 45
#endif

typedef id (*CNDObjectOneArgumentIMP)(id, SEL, id);
typedef void (*CNDConfigureIconViewIMP)(id, SEL, id, id);

static int gCNDCanaryFD = -1;
static Method gCNDImageMethod;
static Method gCNDConfigureMethod;
static CNDObjectOneArgumentIMP gCNDOriginalImage;
static CNDConfigureIconViewIMP gCNDOriginalConfigure;
static NSData *gCNDTransparentImageData;
static _Atomic bool gCNDArmed;
static _Atomic uint64_t gCNDMatches;
static _Atomic uint64_t gCNDReplacements;
static __thread unsigned gCNDAppLibraryCategoryDepth;

static void CNDCanaryLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDCanaryLog(const char *format, ...)
{
    if (gCNDCanaryFD < 0) return;
    char line[4096] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDCanaryFD, line, amount);
    (void)fsync(gCNDCanaryFD);
}

static const char *CNDCanarySkipTypeQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static bool CNDCanaryMethodHasTypes(id object, const char *selectorName,
                                    const char *expected)
{
    if (!object || !selectorName || !expected) return false;
    Method method = class_getInstanceMethod(
        object_getClass(object), sel_registerName(selectorName));
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    return types && !strcmp(types, expected);
}

static id CNDCanarySafeObject(id object, const char *selectorName)
{
    if (!object || !selectorName) return nil;
    SEL selector = sel_registerName(selectorName);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDCanarySkipTypeQualifiers(returnType);
    bool valid = type && (*type == '@' || *type == '#');
    free(returnType);
    if (!valid) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static bool CNDCanaryReadSize(id descriptor, CGSize *sizeOut)
{
    if (!descriptor || !sizeOut) return false;
    SEL selector = sel_registerName("size");
    Method method = class_getInstanceMethod(object_getClass(descriptor),
                                             selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return false;
    char *returnType = method_copyReturnType(method);
    bool valid = returnType && strstr(returnType, "CGSize");
    free(returnType);
    if (!valid) return false;
    @try {
        *sizeOut = ((CGSize (*)(id, SEL))objc_msgSend)(descriptor, selector);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDCanaryReadDouble(id object, const char *selectorName,
                                double *valueOut)
{
    if (!object || !selectorName || !valueOut) return false;
    SEL selector = sel_registerName(selectorName);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return false;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDCanarySkipTypeQualifiers(returnType);
    bool valid = type && *type == 'd';
    free(returnType);
    if (!valid) return false;
    @try {
        *valueOut = ((double (*)(id, SEL))objc_msgSend)(object, selector);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDCanaryReadInteger(id object, const char *selectorName,
                                 long long *valueOut)
{
    if (!object || !selectorName || !valueOut) return false;
    SEL selector = sel_registerName(selectorName);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return false;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDCanarySkipTypeQualifiers(returnType);
    bool valid = type && strchr("cCsSiIlLqQB", *type);
    free(returnType);
    if (!valid) return false;
    @try {
        *valueOut = ((long long (*)(id, SEL))objc_msgSend)(object, selector);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDCanaryDescriptorMatches(id descriptor)
{
    CGSize size = CGSizeZero;
    double scale = 0.0;
    long long appearance = -1;
    long long appearanceVariant = -1;
    long long iconVariant = -1;
    long long options = -1;
    return CNDCanaryReadSize(descriptor, &size) &&
        CNDCanaryReadDouble(descriptor, "scale", &scale) &&
        CNDCanaryReadInteger(descriptor, "appearance", &appearance) &&
        CNDCanaryReadInteger(
            descriptor, "appearanceVariant", &appearanceVariant) &&
        CNDCanaryReadInteger(descriptor, "iconVariant", &iconVariant) &&
        CNDCanaryReadInteger(descriptor, "options", &options) &&
        size.width == 27.0 && size.height == 27.0 && scale == 3.0 &&
        appearance == 0 && appearanceVariant == 0 && iconVariant == 0 &&
        options == 0;
}

static bool CNDCanaryImageIsTransparent87(id image)
{
    SEL selector = sel_registerName("CGImage");
    if (!image || ![image respondsToSelector:selector]) return false;
    CGImageRef cgImage = NULL;
    @try {
        cgImage = ((CGImageRef (*)(id, SEL))objc_msgSend)(image, selector);
    } @catch (__unused NSException *exception) {
        cgImage = NULL;
    }
    if (!cgImage || CGImageGetWidth(cgImage) != 87U ||
        CGImageGetHeight(cgImage) != 87U) {
        return false;
    }
    size_t rowBytes = 87U * 4U;
    uint8_t *pixels = calloc(87U, rowBytes);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = pixels && colorSpace
        ? CGBitmapContextCreate(
              pixels, 87U, 87U, 8U, rowBytes, colorSpace,
              kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big)
        : NULL;
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    if (!context) {
        free(pixels);
        return false;
    }
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextDrawImage(context, CGRectMake(0.0, 0.0, 87.0, 87.0), cgImage);
    bool transparent = true;
    for (size_t index = 0U; index < 87U * 87U; index++) {
        if (pixels[index * 4U + 3U] != 0U) {
            transparent = false;
            break;
        }
    }
    CGContextRelease(context);
    free(pixels);
    return transparent;
}

static NSData *CNDCanaryMakeTransparentImageData(void)
{
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = colorSpace
        ? CGBitmapContextCreate(
              NULL, 87U, 87U, 8U, 87U * 4U, colorSpace,
              kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big)
        : NULL;
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    if (!context) return nil;
    CGContextClearRect(context, CGRectMake(0.0, 0.0, 87.0, 87.0));
    CGImageRef cgImage = CGBitmapContextCreateImage(context);
    CGContextRelease(context);
    if (!cgImage) return nil;

    Class imageClass = NSClassFromString(@"IFImage");
    id allocation = imageClass ? [imageClass alloc] : nil;
    bool abi = CNDCanaryMethodHasTypes(
        allocation, "initWithCGImage:scale:",
        "@32@0:8^{CGImage=}16d24");
    if (!abi) {
        CGImageRelease(cgImage);
        return nil;
    }
    id image = ((id (*)(id, SEL, CGImageRef, double))objc_msgSend)(
        allocation, sel_registerName("initWithCGImage:scale:"), cgImage, 3.0);
    if (!image) {
        CGImageRelease(cgImage);
        return nil;
    }
    SEL minimumSelector = sel_registerName("setMinimumSize:");
    if (CNDCanaryMethodHasTypes(
            image, "setMinimumSize:", "v32@0:8{CGSize=dd}16")) {
        ((void (*)(id, SEL, CGSize))objc_msgSend)(
            image, minimumSelector, CGSizeMake(27.0, 27.0));
    }
    NSData *data = CNDCanarySafeObject(image, "data");
    bool ready = [data isKindOfClass:NSData.class] && data.length > 0U &&
        CNDCanaryImageIsTransparent87(image);
    CNDCanaryLog(
        "[CND_APP_LIBRARY_CANARY] PAYLOAD ready=%d image=%p/%s "
        "bytes=%lu transparent87=%d\n", ready ? 1 : 0, image,
        image ? class_getName([image class]) : "-",
        (unsigned long)([data isKindOfClass:NSData.class] ? data.length : 0U),
        CNDCanaryImageIsTransparent87(image) ? 1 : 0);
    return ready ? [data copy] : nil;
}

static id CNDCanaryReplacement(id stock)
{
    if (!stock || strcmp(class_getName([stock class]), "IFCacheImage")) {
        return nil;
    }
    if (!gCNDTransparentImageData.length && pthread_main_np()) {
        CNDCanaryLog(
            "[CND_APP_LIBRARY_CANARY] PAYLOAD_LAZY_BEGIN main=1\n");
        gCNDTransparentImageData = CNDCanaryMakeTransparentImageData();
        CNDCanaryLog(
            "[CND_APP_LIBRARY_CANARY] PAYLOAD_LAZY_END bytes=%lu\n",
            (unsigned long)gCNDTransparentImageData.length);
    }
    if (!gCNDTransparentImageData.length) return nil;
    id uuid = CNDCanarySafeObject(stock, "uuid");
    id validationToken = CNDCanarySafeObject(stock, "validationToken");
    Class cacheClass = NSClassFromString(@"IFCacheImage");
    id allocation = cacheClass ? [cacheClass alloc] : nil;
    if (!uuid || !validationToken || !CNDCanaryMethodHasTypes(
            allocation, "initWithData:uuid:validationToken:",
            "@40@0:8@16@24@32")) {
        return nil;
    }
    id replacement =
        ((id (*)(id, SEL, id, id, id))objc_msgSend)(
            allocation,
            sel_registerName("initWithData:uuid:validationToken:"),
            gCNDTransparentImageData, uuid, validationToken);
    if (!replacement ||
        strcmp(class_getName([replacement class]), "IFCacheImage") ||
        !CNDCanaryImageIsTransparent87(replacement)) {
        return nil;
    }
    return replacement;
}

static id CNDCanaryImageForDescriptor(id self, SEL selector, id descriptor)
{
    id stock = gCNDOriginalImage(self, selector, descriptor);
    if (!atomic_load_explicit(&gCNDArmed, memory_order_acquire) ||
        !CNDCanaryDescriptorMatches(descriptor)) {
        return stock;
    }
    NSString *bundle = CNDCanarySafeObject(self, "bundleIdentifier");
    if (![bundle isKindOfClass:NSString.class] ||
        ![bundle isEqualToString:@CND_APP_LIBRARY_CANARY_TARGET_BUNDLE]) {
        return stock;
    }
    uint64_t match = atomic_fetch_add_explicit(
        &gCNDMatches, 1U, memory_order_relaxed) + 1U;
    id replacement = CNDCanaryReplacement(stock);
    if (!replacement) {
        CNDCanaryLog(
            "[CND_APP_LIBRARY_CANARY] REJECT match=%llu bundle=%s "
            "stock=%p/%s main=%d\n", (unsigned long long)match,
            bundle.UTF8String ?: "-", stock,
            stock ? class_getName([stock class]) : "-",
            pthread_main_np() ? 1 : 0);
        return stock;
    }
    uint64_t count = atomic_fetch_add_explicit(
        &gCNDReplacements, 1U, memory_order_relaxed) + 1U;
    CNDCanaryLog(
        "[CND_APP_LIBRARY_CANARY] REPLACED count=%llu match=%llu "
        "bundle=%s descriptor=%p stock=%p/%s replacement=%p/%s "
        "configureDepth=%u main=%d\n",
        (unsigned long long)count, (unsigned long long)match,
        bundle.UTF8String ?: "-", descriptor, stock,
        stock ? class_getName([stock class]) : "-", replacement,
        class_getName([replacement class]), gCNDAppLibraryCategoryDepth,
        pthread_main_np() ? 1 : 0);
    return replacement;
}

static void CNDCanaryConfigureIconView(id self, SEL selector, id iconView,
                                       id icon)
{
    gCNDAppLibraryCategoryDepth++;
    gCNDOriginalConfigure(self, selector, iconView, icon);
    gCNDAppLibraryCategoryDepth--;
}

static void CNDCanaryCollectDescendants(id view, Class targetClass,
                                        NSMutableArray *results,
                                        NSUInteger cap)
{
    if (!view || !targetClass || results.count >= cap) return;
    if ([view isKindOfClass:targetClass]) [results addObject:view];
    NSArray *subviews = CNDCanarySafeObject(view, "subviews");
    if (![subviews isKindOfClass:NSArray.class]) return;
    for (id subview in subviews) {
        if (results.count >= cap) break;
        CNDCanaryCollectDescendants(subview, targetClass, results, cap);
    }
}

static void CNDCanaryRefreshLibrary(void)
{
    Class applicationClass = objc_getClass("UIApplication");
    Class listClass = objc_getClass("SBHLibraryCategoryPodIconListView");
    Class iconViewClass = objc_getClass("SBHLibraryCategoryPodIconView");
    Class indicatorImageViewClass = objc_getClass(
        "SBHLibraryAdditionalItemsIndicatorIconImageView");
    Class imageViewClass = objc_getClass("SBIconImageView");
    id application = CNDCanarySafeObject(
        applicationClass, "sharedApplication");
    NSArray *windows = CNDCanarySafeObject(application, "windows");
    NSMutableArray *lists = [NSMutableArray array];
    for (id window in [windows isKindOfClass:NSArray.class] ? windows : @[]) {
        CNDCanaryCollectDescendants(window, listClass, lists, 64U);
    }
    unsigned iconViews = 0U;
    unsigned indicatorIcons = 0U;
    unsigned indicatorReloads = 0U;
    unsigned configured = 0U;
    NSMutableArray *indicatorIconObjects = [NSMutableArray array];
    for (id list in lists) {
        if (!CNDCanaryMethodHasTypes(
                list, "configureIconView:forIcon:",
                "v32@0:8@16@24")) {
            continue;
        }
        NSMutableArray *views = [NSMutableArray array];
        CNDCanaryCollectDescendants(
            list, iconViewClass, views, 128U);
        iconViews += (unsigned)views.count;
        for (id iconView in views) {
            id icon = CNDCanarySafeObject(iconView, "icon");
            if (!icon) continue;
            const char *iconClassName = class_getName([icon class]);
            if (!iconClassName || strcmp(
                    iconClassName,
                    "SBHLibraryAdditionalItemsIndicatorIcon")) {
                continue;
            }
            indicatorIcons++;
            if (![indicatorIconObjects containsObject:icon]) {
                [indicatorIconObjects addObject:icon];
            }
            if (CNDCanaryMethodHasTypes(
                    icon, "reloadIconImage", "v16@0:8")) {
                ((void (*)(id, SEL))objc_msgSend)(
                    icon, sel_registerName("reloadIconImage"));
                indicatorReloads++;
            }
            ((void (*)(id, SEL, id, id))objc_msgSend)(
                list, sel_registerName("configureIconView:forIcon:"),
                iconView, icon);
            configured++;
        }
    }
    NSMutableArray *indicatorImageViews = [NSMutableArray array];
    for (id window in [windows isKindOfClass:NSArray.class] ? windows : @[]) {
        CNDCanaryCollectDescendants(
            window, indicatorImageViewClass, indicatorImageViews, 64U);
    }
    unsigned imageViewsCleared = 0U;
    unsigned imageViewsRebound = 0U;
    unsigned imageViewsLoaded = 0U;
    unsigned imageViewsUpdated = 0U;
    unsigned targetedCachePurges = 0U;
    NSMutableArray *purgedCaches = [NSMutableArray array];
    for (id imageView in indicatorImageViews) {
        id cache = CNDCanarySafeObject(imageView, "iconImageCache");
        if (indicatorIconObjects.count &&
            ![purgedCaches containsObject:cache] &&
            CNDCanaryMethodHasTypes(
                cache, "purgeCachedImagesForIcons:", "v24@0:8@16")) {
            ((void (*)(id, SEL, id))objc_msgSend)(
                cache, sel_registerName("purgeCachedImagesForIcons:"),
                indicatorIconObjects);
            [purgedCaches addObject:cache];
            targetedCachePurges++;
        }
        id boundIcon = CNDCanarySafeObject(imageView, "icon");
        id boundLocation = CNDCanarySafeObject(imageView, "iconLocation");
        if (boundIcon && CNDCanaryMethodHasTypes(
                imageView, "setIcon:location:animated:",
                "v36@0:8@16@24B32")) {
            ((void (*)(id, SEL, id, id, BOOL))objc_msgSend)(
                imageView, sel_registerName("setIcon:location:animated:"),
                nil, boundLocation, NO);
            ((void (*)(id, SEL, id, id, BOOL))objc_msgSend)(
                imageView, sel_registerName("setIcon:location:animated:"),
                boundIcon, boundLocation, NO);
            imageViewsRebound++;
        }
        if (CNDCanaryMethodHasTypes(
                imageView, "clearCachedImages", "v16@0:8")) {
            ((void (*)(id, SEL))objc_msgSend)(
                imageView, sel_registerName("clearCachedImages"));
            imageViewsCleared++;
        }
        if (CNDCanaryMethodHasTypes(
                imageView, "loadContentsImageFromIconAnimated:",
                "v20@0:8B16")) {
            ((void (*)(id, SEL, BOOL))objc_msgSend)(
                imageView,
                sel_registerName("loadContentsImageFromIconAnimated:"),
                NO);
            imageViewsLoaded++;
        }
        if (CNDCanaryMethodHasTypes(
                imageView, "updateImageAnimated:", "v20@0:8B16")) {
            ((void (*)(id, SEL, BOOL))objc_msgSend)(
                imageView, sel_registerName("updateImageAnimated:"), NO);
            imageViewsUpdated++;
        }
    }
    NSMutableArray *miniImageViews = [NSMutableArray array];
    for (id indicatorImageView in indicatorImageViews) {
        NSMutableArray *descendants = [NSMutableArray array];
        NSArray *subviews = CNDCanarySafeObject(
            indicatorImageView, "subviews");
        for (id subview in
             [subviews isKindOfClass:NSArray.class] ? subviews : @[]) {
            CNDCanaryCollectDescendants(
                subview, imageViewClass, descendants, 128U);
        }
        for (id descendant in descendants) {
            if (![miniImageViews containsObject:descendant]) {
                [miniImageViews addObject:descendant];
            }
        }
    }
    unsigned targetMiniImageViews = 0U;
    unsigned targetMiniPurges = 0U;
    unsigned targetMiniLoads = 0U;
    for (id miniImageView in miniImageViews) {
        id icon = CNDCanarySafeObject(miniImageView, "icon");
        id bundle = CNDCanarySafeObject(icon, "applicationBundleID");
        if (![bundle isKindOfClass:NSString.class]) {
            bundle = CNDCanarySafeObject(icon, "bundleIdentifier");
        }
        if (![bundle isKindOfClass:NSString.class] ||
            ![bundle isEqualToString:
                @CND_APP_LIBRARY_CANARY_TARGET_BUNDLE]) {
            continue;
        }
        targetMiniImageViews++;
        id cache = CNDCanarySafeObject(miniImageView, "iconImageCache");
        if (icon && CNDCanaryMethodHasTypes(
                cache, "purgeCachedImagesForIcons:", "v24@0:8@16")) {
            ((void (*)(id, SEL, id))objc_msgSend)(
                cache, sel_registerName("purgeCachedImagesForIcons:"),
                @[icon]);
            targetMiniPurges++;
        }
        if (CNDCanaryMethodHasTypes(
                miniImageView, "clearCachedImages", "v16@0:8")) {
            ((void (*)(id, SEL))objc_msgSend)(
                miniImageView, sel_registerName("clearCachedImages"));
        }
        if (CNDCanaryMethodHasTypes(
                miniImageView, "loadContentsImageFromIconAnimated:",
                "v20@0:8B16")) {
            ((void (*)(id, SEL, BOOL))objc_msgSend)(
                miniImageView,
                sel_registerName("loadContentsImageFromIconAnimated:"),
                NO);
            targetMiniLoads++;
        }
    }
    CNDCanaryLog(
        "[CND_APP_LIBRARY_CANARY] REFRESH_COMPLETE application=%p/%s "
        "windows=%lu lists=%lu iconViews=%u indicators=%u reloads=%u "
        "configured=%u indicatorImageViews=%lu targetedPurges=%u "
        "rebound=%u cleared=%u loaded=%u updated=%u miniImageViews=%lu "
        "targetMiniViews=%u targetMiniPurges=%u targetMiniLoads=%u\n",
        application,
        application ? class_getName([application class]) : "-",
        (unsigned long)([windows isKindOfClass:NSArray.class]
            ? windows.count : 0U), (unsigned long)lists.count,
        iconViews, indicatorIcons, indicatorReloads, configured,
        (unsigned long)indicatorImageViews.count, targetedCachePurges,
        imageViewsRebound, imageViewsCleared, imageViewsLoaded,
        imageViewsUpdated,
        (unsigned long)miniImageViews.count, targetMiniImageViews,
        targetMiniPurges, targetMiniLoads);
}

static bool CNDCanaryValidateMethod(Method method, unsigned arguments,
                                    char returnType)
{
    if (!method || method_getNumberOfArguments(method) != arguments) {
        return false;
    }
    char *copied = method_copyReturnType(method);
    const char *type = CNDCanarySkipTypeQualifiers(copied);
    bool valid = type && *type == returnType;
    free(copied);
    return valid;
}

static void CNDCanaryRestore(void)
{
    atomic_store_explicit(&gCNDArmed, false, memory_order_release);
    bool imageRestored = false;
    bool configureRestored = false;
    if (gCNDImageMethod && method_getImplementation(gCNDImageMethod) ==
            (IMP)CNDCanaryImageForDescriptor) {
        method_setImplementation(gCNDImageMethod, (IMP)gCNDOriginalImage);
        imageRestored = method_getImplementation(gCNDImageMethod) ==
            (IMP)gCNDOriginalImage;
    }
    if (gCNDConfigureMethod &&
        method_getImplementation(gCNDConfigureMethod) ==
            (IMP)CNDCanaryConfigureIconView) {
        method_setImplementation(
            gCNDConfigureMethod, (IMP)gCNDOriginalConfigure);
        configureRestored = method_getImplementation(gCNDConfigureMethod) ==
            (IMP)gCNDOriginalConfigure;
    }
    CNDCanaryLog(
        "[CND_APP_LIBRARY_CANARY] COMPLETE status=%s imageRestored=%d "
        "configureRestored=%d matches=%llu replacements=%llu\n",
        imageRestored && configureRestored ? "success" : "restore-failed",
        imageRestored ? 1 : 0, configureRestored ? 1 : 0,
        (unsigned long long)atomic_load_explicit(
            &gCNDMatches, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(
            &gCNDReplacements, memory_order_relaxed));
}

__attribute__((constructor))
static void CNDCanaryStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_APP_LIBRARY_CANARY_OUTPUT_TOKEN[0] && consume
            ? consume(CND_APP_LIBRARY_CANARY_OUTPUT_TOKEN) : -1;
        gCNDCanaryFD = open(
            CND_APP_LIBRARY_CANARY_REPORT_PATH,
            O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        CNDCanaryLog(
            "[CND_APP_LIBRARY_CANARY] START pid=%d expectedPid=%d "
            "process=%s token=%lld target=%s hold=%d\n", getpid(),
            CND_APP_LIBRARY_CANARY_EXPECTED_PID, getprogname(),
            (long long)token, CND_APP_LIBRARY_CANARY_TARGET_BUNDLE,
            CND_APP_LIBRARY_CANARY_HOLD_SECONDS);
        if (CND_APP_LIBRARY_CANARY_EXPECTED_PID <= 1 ||
            getpid() != CND_APP_LIBRARY_CANARY_EXPECTED_PID ||
            strcmp(getprogname(), "SpringBoard")) {
            CNDCanaryLog(
                "[CND_APP_LIBRARY_CANARY] REFUSED reason=identity\n");
            return;
        }
        (void)dlopen(
            "/System/Library/PrivateFrameworks/SpringBoardHome.framework/"
            "SpringBoardHome", RTLD_NOW | RTLD_LOCAL);
        (void)dlopen(
            "/System/Library/PrivateFrameworks/IconServices.framework/"
            "IconServices", RTLD_NOW | RTLD_LOCAL);

        Class iconClass = objc_getClass("ISBundleIdentifierIcon");
        Class listClass = objc_getClass("SBHLibraryCategoryPodIconListView");
        gCNDImageMethod = iconClass ? class_getInstanceMethod(
            iconClass, sel_registerName("imageForDescriptor:")) : NULL;
        gCNDConfigureMethod = listClass ? class_getInstanceMethod(
            listClass, sel_registerName("configureIconView:forIcon:")) : NULL;
        bool imageABI = CNDCanaryValidateMethod(gCNDImageMethod, 3U, '@');
        bool configureABI = CNDCanaryValidateMethod(
            gCNDConfigureMethod, 4U, 'v');
        Class imageClass = objc_getClass("IFImage");
        Class cacheClass = objc_getClass("IFCacheImage");
        Method flatInitializer = imageClass ? class_getInstanceMethod(
            imageClass, sel_registerName("initWithCGImage:scale:")) : NULL;
        Method cacheInitializer = cacheClass ? class_getInstanceMethod(
            cacheClass,
            sel_registerName("initWithData:uuid:validationToken:")) : NULL;
        bool constructorsPresent = flatInitializer && cacheInitializer;
        if (!imageABI || !configureABI || !constructorsPresent) {
            CNDCanaryLog(
                "[CND_APP_LIBRARY_CANARY] REFUSED reason=preflight "
                "imageABI=%d configureABI=%d constructors=%d\n",
                imageABI ? 1 : 0, configureABI ? 1 : 0,
                constructorsPresent ? 1 : 0);
            return;
        }

        gCNDOriginalImage = (CNDObjectOneArgumentIMP)
            method_getImplementation(gCNDImageMethod);
        gCNDOriginalConfigure = (CNDConfigureIconViewIMP)
            method_getImplementation(gCNDConfigureMethod);
        method_setImplementation(
            gCNDImageMethod, (IMP)CNDCanaryImageForDescriptor);
        method_setImplementation(
            gCNDConfigureMethod, (IMP)CNDCanaryConfigureIconView);
        bool imageHooked = method_getImplementation(gCNDImageMethod) ==
            (IMP)CNDCanaryImageForDescriptor;
        bool configureHooked = method_getImplementation(gCNDConfigureMethod) ==
            (IMP)CNDCanaryConfigureIconView;
        if (!imageHooked || !configureHooked) {
            if (imageHooked) method_setImplementation(
                gCNDImageMethod, (IMP)gCNDOriginalImage);
            if (configureHooked) method_setImplementation(
                gCNDConfigureMethod, (IMP)gCNDOriginalConfigure);
            CNDCanaryLog(
                "[CND_APP_LIBRARY_CANARY] REFUSED reason=hook "
                "image=%d configure=%d\n", imageHooked ? 1 : 0,
                configureHooked ? 1 : 0);
            return;
        }
        atomic_store_explicit(&gCNDArmed, true, memory_order_release);
        CNDCanaryLog(
            "[CND_APP_LIBRARY_CANARY] ARMED imageOriginal=%p "
            "configureOriginal=%p payload=lazy-main-thread\n",
            gCNDOriginalImage, gCNDOriginalConfigure);
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW,
                          (int64_t)CND_APP_LIBRARY_CANARY_HOLD_SECONDS *
                              NSEC_PER_SEC),
            dispatch_get_main_queue(), ^{
                CNDCanaryRestore();
            });
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, 9LL * NSEC_PER_SEC),
            dispatch_get_main_queue(), ^{
                if (atomic_load_explicit(
                        &gCNDArmed, memory_order_acquire)) {
                    CNDCanaryRefreshLibrary();
                }
            });
    }
}
