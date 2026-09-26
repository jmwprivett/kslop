#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CND_PRESENT_TARGET_BUNDLE
#define CND_PRESENT_TARGET_BUNDLE "com.ebay.iphone"
#endif

static const char *const CNDPresentOutputPath =
    "/var/tmp/cyanide-spotlight-presentation.log";
static int gCNDPresentFD = -1;
static unsigned gCNDPresentTick;
static unsigned gCNDPresentStage;
static unsigned gCNDPresentRepairCount;
static unsigned gCNDPresentStableTicks;
static bool gCNDPresentWasVisible;
static __strong UIView *gCNDPresentRow;
static __strong id gCNDPresentCarrier;

static void CNDPresentLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDPresentLog(const char *format, ...)
{
    if (gCNDPresentFD < 0) return;
    char line[4096] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDPresentFD, line, amount);
    (void)fsync(gCNDPresentFD);
}

static const char *CNDPresentClassName(id object)
{
    return object ? class_getName(object_getClass(object)) : "-";
}

static void *CNDPresentPointer(id object)
{
    return object ? (__bridge void *)object : NULL;
}

static const char *CNDPresentUnqualified(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static Method CNDPresentMethod(id object, const char *name,
                               unsigned argumentCount)
{
    if (!object || !name || !name[0]) return NULL;
    Method method = class_getInstanceMethod(object_getClass(object),
                                             sel_registerName(name));
    return method && method_getNumberOfArguments(method) == argumentCount
        ? method : NULL;
}

static bool CNDPresentMethodReturns(Method method, char expected)
{
    if (!method) return false;
    char *type = method_copyReturnType(method);
    const char *unqualified = CNDPresentUnqualified(type);
    bool matches = unqualified && *unqualified == expected;
    free(type);
    return matches;
}

static bool CNDPresentMethodArgumentIs(Method method, unsigned index,
                                       const char *accepted)
{
    if (!method || !accepted) return false;
    char *type = method_copyArgumentType(method, index);
    const char *unqualified = CNDPresentUnqualified(type);
    bool matches = unqualified && strchr(accepted, *unqualified) != NULL;
    free(type);
    return matches;
}

static void CNDPresentLogMethod(id object, const char *name)
{
    Method method = object && name
        ? class_getInstanceMethod(object_getClass(object),
                                  sel_registerName(name)) : NULL;
    CNDPresentLog("[CND_PRESENT] method object=%p/%s selector=%s present=%d "
                  "arguments=%u types=%s\n", CNDPresentPointer(object),
                  CNDPresentClassName(object), name ?: "-", method != NULL,
                  method ? method_getNumberOfArguments(method) : 0U,
                  method ? method_getTypeEncoding(method) : "-");
}

static id CNDPresentObjectGetter(id object, const char *name)
{
    Method method = CNDPresentMethod(object, name, 2U);
    if (!method || !CNDPresentMethodReturns(method, '@')) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object,
                                               sel_registerName(name));
    } @catch (NSException *exception) {
        CNDPresentLog("[CND_PRESENT] getter-exception object=%p/%s "
                      "selector=%s exception=%s\n",
                      CNDPresentPointer(object), CNDPresentClassName(object),
                      name, exception.name.UTF8String ?: "-");
        return nil;
    }
}

static id CNDPresentObjectArgumentGetter(id object, const char *name,
                                         id argument)
{
    Method method = CNDPresentMethod(object, name, 3U);
    if (!method || !CNDPresentMethodReturns(method, '@') ||
        !CNDPresentMethodArgumentIs(method, 2U, "@")) return nil;
    @try {
        return ((id (*)(id, SEL, id))objc_msgSend)(
            object, sel_registerName(name), argument);
    } @catch (NSException *exception) {
        CNDPresentLog("[CND_PRESENT] getter1-exception object=%p/%s "
                      "selector=%s exception=%s\n",
                      CNDPresentPointer(object), CNDPresentClassName(object),
                      name, exception.name.UTF8String ?: "-");
        return nil;
    }
}

static id CNDPresentObjectIvar(id object, const char *name)
{
    if (!object || !name) return nil;
    Ivar ivar = class_getInstanceVariable(object_getClass(object), name);
    if (!ivar) return nil;
    const char *type = CNDPresentUnqualified(ivar_getTypeEncoding(ivar));
    return type && *type == '@' ? object_getIvar(object, ivar) : nil;
}

static id CNDPresentObjectFromCandidates(id object,
                                         const char *const *getters,
                                         size_t getterCount,
                                         const char *const *ivars,
                                         size_t ivarCount)
{
    for (size_t i = 0; object && i < getterCount; i++) {
        id value = CNDPresentObjectGetter(object, getters[i]);
        if (value) return value;
    }
    for (size_t i = 0; object && i < ivarCount; i++) {
        id value = CNDPresentObjectIvar(object, ivars[i]);
        if (value) return value;
    }
    return nil;
}

static NSArray *CNDPresentCollectionItems(id collection, NSUInteger cap)
{
    if ([collection isKindOfClass:NSArray.class]) {
        NSArray *array = collection;
        return array.count > cap
            ? [array subarrayWithRange:NSMakeRange(0U, cap)] : array;
    }
    id allObjects = CNDPresentObjectGetter(collection, "allObjects");
    if ([allObjects isKindOfClass:NSArray.class]) {
        NSArray *array = allObjects;
        return array.count > cap
            ? [array subarrayWithRange:NSMakeRange(0U, cap)] : array;
    }
    return @[];
}

static NSArray<UIWindow *> *CNDPresentWindows(void)
{
    UIApplication *application = UIApplication.sharedApplication;
    NSMutableArray<UIWindow *> *windows = [NSMutableArray array];
    id scenes = CNDPresentObjectGetter(application, "connectedScenes");
    for (id scene in CNDPresentCollectionItems(scenes, 16U)) {
        id sceneWindows = CNDPresentObjectGetter(scene, "windows");
        for (id window in CNDPresentCollectionItems(sceneWindows, 32U)) {
            if ([window isKindOfClass:UIWindow.class] &&
                ![windows containsObject:window]) [windows addObject:window];
        }
    }
    id legacy = CNDPresentObjectGetter(application, "windows");
    for (id window in CNDPresentCollectionItems(legacy, 32U)) {
        if ([window isKindOfClass:UIWindow.class] &&
            ![windows containsObject:window]) [windows addObject:window];
    }
    return windows;
}

static NSArray<UIView *> *CNDPresentViewsOfClass(Class wantedClass)
{
    if (!wantedClass) return @[];
    NSMutableArray<UIView *> *matches = [NSMutableArray array];
    NSMutableArray<UIView *> *pending = [NSMutableArray array];
    [pending addObjectsFromArray:CNDPresentWindows()];
    NSUInteger cursor = 0U;
    while (cursor < pending.count && cursor < 4096U) {
        UIView *view = pending[cursor++];
        if ([view isKindOfClass:wantedClass]) [matches addObject:view];
        NSUInteger available = pending.count < 4096U
            ? 4096U - pending.count : 0U;
        NSArray<UIView *> *subviews = view.subviews;
        if (subviews.count > available) {
            if (available) [pending addObjectsFromArray:
                [subviews subarrayWithRange:NSMakeRange(0U, available)]];
            break;
        }
        [pending addObjectsFromArray:subviews];
    }
    return matches;
}

static id CNDPresentApplicationIcon(UIView *view)
{
    static const char *const getters[] = {
        "appIcon", "icon", "applicationIcon", "representedIcon"
    };
    static const char *const ivars[] = {
        "_appIcon", "_icon", "_applicationIcon", "_representedIcon"
    };
    return CNDPresentObjectFromCandidates(
        view, getters, sizeof(getters) / sizeof(getters[0]),
        ivars, sizeof(ivars) / sizeof(ivars[0]));
}

static NSString *CNDPresentBundleIdentifier(id view, id icon)
{
    static const char *const links[] = {
        "application", "applicationProxy", "applicationInfo", "proxy"
    };
    for (id root in @[icon ?: NSNull.null, view ?: NSNull.null]) {
        if (root == NSNull.null) continue;
        id identifier = CNDPresentObjectGetter(root, "bundleIdentifier");
        if ([identifier isKindOfClass:NSString.class]) return identifier;
        for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
            id linked = CNDPresentObjectGetter(root, links[i]);
            identifier = CNDPresentObjectGetter(linked, "bundleIdentifier");
            if ([identifier isKindOfClass:NSString.class]) return identifier;
        }
    }
    return nil;
}

static id CNDPresentCarrier(UIView *view)
{
    static const char *const getters[] = {
        "imageView", "_imageView", "iconImageView", "_iconImageView",
        "appIconImageView", "_appIconImageView", "contentImageView",
        "_contentImageView"
    };
    static const char *const ivars[] = {
        "_imageView", "_iconImageView", "_appIconImageView",
        "_contentImageView"
    };
    return CNDPresentObjectFromCandidates(
        view, getters, sizeof(getters) / sizeof(getters[0]),
        ivars, sizeof(ivars) / sizeof(ivars[0]));
}

static id CNDPresentCache(id icon, id carrier)
{
    id iconServicesIcon = CNDPresentObjectGetter(icon,
                                                  "iconServicesIconForImage");
    static const char *const getters[] = {
        "imageCache", "iconImageCache", "cache"
    };
    static const char *const ivars[] = {
        "_imageCache", "_iconImageCache", "_cache"
    };
    for (id root in @[iconServicesIcon ?: NSNull.null,
                      icon ?: NSNull.null, carrier ?: NSNull.null]) {
        if (root == NSNull.null) continue;
        id cache = CNDPresentObjectFromCandidates(
            root, getters, sizeof(getters) / sizeof(getters[0]),
            ivars, sizeof(ivars) / sizeof(ivars[0]));
        if (cache) return cache;
    }
    return nil;
}

static CGImageRef CNDPresentCGImage(id object)
{
    if ([object isKindOfClass:UIImage.class]) return ((UIImage *)object).CGImage;
    Method method = CNDPresentMethod(object, "CGImage", 2U);
    if (!method || !CNDPresentMethodReturns(method, '^')) return NULL;
    return ((CGImageRef (*)(id, SEL))objc_msgSend)(
        object, sel_registerName("CGImage"));
}

static NSData *CNDPresentRGBA(CGImageRef image)
{
    if (!image) return nil;
    size_t width = CGImageGetWidth(image);
    size_t height = CGImageGetHeight(image);
    if (!width || !height || width > 4096U || height > 4096U ||
        width > SIZE_MAX / 4U || height > SIZE_MAX / (width * 4U)) return nil;
    size_t rowBytes = width * 4U;
    NSMutableData *pixels = [NSMutableData dataWithLength:rowBytes * height];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) return nil;
    CGContextRef context = CGBitmapContextCreate(
        pixels.mutableBytes, width, height, 8U, rowBytes, colorSpace,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(colorSpace);
    if (!context) return nil;
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), image);
    CGContextRelease(context);
    return pixels;
}

static NSString *CNDPresentSHA256(NSData *data)
{
    if (!data) return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *text = [NSMutableString stringWithCapacity:64U];
    for (size_t i = 0; i < sizeof(digest); i++) {
        [text appendFormat:@"%02x", digest[i]];
    }
    return text;
}

static NSString *CNDPresentImageHash(id image)
{
    return CNDPresentSHA256(CNDPresentRGBA(CNDPresentCGImage(image)));
}

static CGImageRef CNDPresentLayerImage(id contents)
{
    if (!contents) return NULL;
    CFTypeRef value = (__bridge CFTypeRef)contents;
    return CFGetTypeID(value) == CGImageGetTypeID()
        ? (CGImageRef)value : NULL;
}

static bool CNDPresentLayerContainsHash(CALayer *layer, NSString *hash,
                                        bool ancestorsVisible,
                                        unsigned depth,
                                        CALayer **matchedLayer)
{
    if (!layer || !hash || depth > 6U) return false;
    bool visible = ancestorsVisible && !layer.hidden && layer.opacity > 0.01f;
    CGImageRef image = CNDPresentLayerImage(layer.contents);
    NSString *layerHash = image
        ? CNDPresentSHA256(CNDPresentRGBA(image)) : nil;
    if (visible && [layerHash isEqualToString:hash]) {
        if (matchedLayer) *matchedLayer = layer;
        return true;
    }
    NSUInteger cap = MIN(layer.sublayers.count, 48U);
    for (NSUInteger i = 0; i < cap; i++) {
        if (CNDPresentLayerContainsHash(layer.sublayers[i], hash, visible,
                                        depth + 1U, matchedLayer)) return true;
    }
    return false;
}

static int CNDPresentBoolGetter(id object, const char *name)
{
    Method method = CNDPresentMethod(object, name, 2U);
    if (!method || !CNDPresentMethodReturns(method, 'B')) {
        if (!method || !CNDPresentMethodReturns(method, 'c')) return -1;
    }
    return ((BOOL (*)(id, SEL))objc_msgSend)(object,
                                             sel_registerName(name)) ? 1 : 0;
}

static bool CNDPresentRendererIdle(id carrier)
{
    int canUpdate = CNDPresentBoolGetter(carrier, "canUpdateImage");
    int updating = CNDPresentBoolGetter(carrier, "isUpdatingImage");
    int delayed = CNDPresentBoolGetter(
        carrier, "delayedImageUpdateDueToContentVisibility");
    id cancellation = CNDPresentObjectGetter(carrier,
                                              "cacheRequestCancellation");
    if (!cancellation) {
        cancellation = CNDPresentObjectIvar(carrier,
                                             "_cacheRequestCancellation");
    }
    return canUpdate == 1 && updating == 0 && delayed == 0 && !cancellation;
}

static bool CNDPresentVisibleTheme(id carrier, NSString *themeHash,
                                   CALayer **matchedLayer)
{
    static const char *const imageGetters[] = {
        "displayedImage", "image", "contentsImage", "squareContentsImage"
    };
    for (size_t i = 0; i < sizeof(imageGetters) / sizeof(imageGetters[0]); i++) {
        id image = CNDPresentObjectGetter(carrier, imageGetters[i]);
        if ([[(CNDPresentImageHash(image) ?: @"") lowercaseString]
             isEqualToString:themeHash.lowercaseString]) return true;
    }
    if ([carrier isKindOfClass:UIView.class]) {
        UIView *view = carrier;
        return !view.hidden && view.alpha > 0.01 &&
            CNDPresentLayerContainsHash(view.layer, themeHash, true, 0U,
                                        matchedLayer);
    }
    return false;
}

static void CNDPresentLogState(const char *phase, UIView *row, id icon,
                               id carrier, id cache, id themeImage,
                               NSString *themeHash)
{
    id displayed = CNDPresentObjectGetter(carrier, "displayedImage");
    id desiredIdentity = CNDPresentObjectGetter(carrier,
                                                 "desiredImageIdentity");
    id displayedIdentity = CNDPresentObjectGetter(carrier,
                                                   "displayedImageIdentity");
    id contentsLayerView = CNDPresentObjectGetter(carrier,
                                                   "contentsLayerView");
    id alternateLayer = CNDPresentObjectGetter(carrier,
                                                "alternateContentsLayer");
    CALayer *matchedLayer = nil;
    bool visibleMatch = CNDPresentVisibleTheme(carrier, themeHash,
                                               &matchedLayer);
    UIView *placeholder = CNDPresentObjectGetter(row, "placeholderView");
    CNDPresentLog(
        "[CND_PRESENT] state phase=%s stage=%u row=%p/%s icon=%p/%s "
        "carrier=%p/%s cache=%p/%s theme=%p/%s themeSHA256=%s "
        "displayed=%p/%s displayedSHA256=%s desiredID=%p/%s "
        "displayedID=%p/%s identityEqual=%d displayLayer=%d realContents=%d "
        "shouldLayer=%d canUpdate=%d updating=%d delayed=%d "
        "cancellation=%p/%s idle=%d placeholderLogical=%d carrierHidden=%d "
        "carrierAlpha=%.3f placeholder=%p/%s placeholderHidden=%d "
        "placeholderAlpha=%.3f contentsLayerView=%p/%s alternate=%p/%s "
        "visibleTheme=%d matchedLayer=%p/%s\n",
        phase, gCNDPresentStage, CNDPresentPointer(row),
        CNDPresentClassName(row), CNDPresentPointer(icon),
        CNDPresentClassName(icon), CNDPresentPointer(carrier),
        CNDPresentClassName(carrier), CNDPresentPointer(cache),
        CNDPresentClassName(cache), CNDPresentPointer(themeImage),
        CNDPresentClassName(themeImage), themeHash.UTF8String ?: "-",
        CNDPresentPointer(displayed), CNDPresentClassName(displayed),
        CNDPresentImageHash(displayed).UTF8String ?: "-",
        CNDPresentPointer(desiredIdentity), CNDPresentClassName(desiredIdentity),
        CNDPresentPointer(displayedIdentity),
        CNDPresentClassName(displayedIdentity),
        desiredIdentity && displayedIdentity &&
            [desiredIdentity isEqual:displayedIdentity],
        CNDPresentBoolGetter(carrier, "isDisplayingImageLayer"),
        CNDPresentBoolGetter(carrier, "isShowingRealContentsImage"),
        CNDPresentBoolGetter(carrier, "shouldDisplayImageLayer"),
        CNDPresentBoolGetter(carrier, "canUpdateImage"),
        CNDPresentBoolGetter(carrier, "isUpdatingImage"),
        CNDPresentBoolGetter(
            carrier, "delayedImageUpdateDueToContentVisibility"),
        CNDPresentPointer(CNDPresentObjectGetter(
            carrier, "cacheRequestCancellation")),
        CNDPresentClassName(CNDPresentObjectGetter(
            carrier, "cacheRequestCancellation")),
        CNDPresentRendererIdle(carrier),
        CNDPresentBoolGetter(row, "currentIconIsPlaceholder"),
        [carrier isKindOfClass:UIView.class] ? ((UIView *)carrier).hidden : -1,
        [carrier isKindOfClass:UIView.class] ? ((UIView *)carrier).alpha : -1.0,
        CNDPresentPointer(placeholder), CNDPresentClassName(placeholder),
        placeholder ? placeholder.hidden : -1,
        placeholder ? placeholder.alpha : -1.0,
        CNDPresentPointer(contentsLayerView), CNDPresentClassName(contentsLayerView),
        CNDPresentPointer(alternateLayer), CNDPresentClassName(alternateLayer),
        visibleMatch, CNDPresentPointer(matchedLayer),
        CNDPresentClassName(matchedLayer));
}

static bool CNDPresentInvokeObject(id object, const char *selectorName,
                                   id argument)
{
    Method method = CNDPresentMethod(object, selectorName, 3U);
    if (!method || !CNDPresentMethodReturns(method, 'v') ||
        !CNDPresentMethodArgumentIs(method, 2U, "@")) return false;
    @try {
        ((void (*)(id, SEL, id))objc_msgSend)(
            object, sel_registerName(selectorName), argument);
        return true;
    } @catch (NSException *exception) {
        CNDPresentLog("[CND_PRESENT] invoke-exception selector=%s "
                      "exception=%s\n", selectorName,
                      exception.name.UTF8String ?: "-");
        return false;
    }
}

static bool CNDPresentInvokeBool(id object, const char *selectorName,
                                 BOOL argument)
{
    Method method = CNDPresentMethod(object, selectorName, 3U);
    if (!method || !CNDPresentMethodReturns(method, 'v') ||
        !CNDPresentMethodArgumentIs(method, 2U, "Bc")) return false;
    @try {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(
            object, sel_registerName(selectorName), argument);
        return true;
    } @catch (NSException *exception) {
        CNDPresentLog("[CND_PRESENT] invoke-exception selector=%s "
                      "exception=%s\n", selectorName,
                      exception.name.UTF8String ?: "-");
        return false;
    }
}

static bool CNDPresentInvokeTwoObjects(id object, const char *selectorName,
                                       id first, id second)
{
    Method method = CNDPresentMethod(object, selectorName, 4U);
    if (!method || !CNDPresentMethodReturns(method, 'v') ||
        !CNDPresentMethodArgumentIs(method, 2U, "@") ||
        !CNDPresentMethodArgumentIs(method, 3U, "@")) return false;
    @try {
        ((void (*)(id, SEL, id, id))objc_msgSend)(
            object, sel_registerName(selectorName), first, second);
        return true;
    } @catch (NSException *exception) {
        CNDPresentLog("[CND_PRESENT] invoke-exception selector=%s "
                      "exception=%s\n", selectorName,
                      exception.name.UTF8String ?: "-");
        return false;
    }
}

static bool CNDPresentInvokeFiveArgumentUpdate(id carrier, id image,
                                               id appearance)
{
    const char *selectorName =
        "updateImageContentsWithImage:imageAppearance:animated:"
        "shouldClearDisplayedLayer:";
    Method method = CNDPresentMethod(carrier, selectorName, 6U);
    if (!method || !CNDPresentMethodReturns(method, 'v') ||
        !CNDPresentMethodArgumentIs(method, 2U, "@") ||
        !CNDPresentMethodArgumentIs(method, 3U, "@") ||
        !CNDPresentMethodArgumentIs(method, 4U, "Bc") ||
        !CNDPresentMethodArgumentIs(method, 5U, "Bc")) return false;
    @try {
        ((void (*)(id, SEL, id, id, BOOL, BOOL))objc_msgSend)(
            carrier, sel_registerName(selectorName), image, appearance,
            NO, YES);
        return true;
    } @catch (NSException *exception) {
        CNDPresentLog("[CND_PRESENT] invoke-exception selector=%s "
                      "exception=%s\n", selectorName,
                      exception.name.UTF8String ?: "-");
        return false;
    }
}

static void CNDPresentLogSurface(UIView *row, id carrier)
{
    static const char *const rowMethods[] = {
        "resetImageWithAppIcon:", "_updateIconImageViewAnimated:",
        "iconImageViewDidChangeContents:forIcon:"
    };
    static const char *const carrierMethods[] = {
        "updateExistingIconLayerAnimated:",
        "updateImageContentsWithImage:imageAppearance:animated:"
        "shouldClearDisplayedLayer:"
    };
    for (size_t i = 0; i < sizeof(rowMethods) / sizeof(rowMethods[0]); i++) {
        CNDPresentLogMethod(row, rowMethods[i]);
    }
    for (size_t i = 0;
         i < sizeof(carrierMethods) / sizeof(carrierMethods[0]); i++) {
        CNDPresentLogMethod(carrier, carrierMethods[i]);
    }
}

static void CNDPresentScheduleAfter(double seconds);

static void CNDPresentSchedule(void)
{
    CNDPresentScheduleAfter(1.0);
}

static void CNDPresentRunTick(void)
{
    NSCAssert(NSThread.isMainThread, @"Spotlight presentation must run on main");
    gCNDPresentTick++;
    Class rowClass = NSClassFromString(@"SearchUIHomeScreenAppIconView");
    NSMutableArray<UIView *> *targets = [NSMutableArray array];
    for (UIView *row in CNDPresentViewsOfClass(rowClass)) {
        id icon = CNDPresentApplicationIcon(row);
        NSString *bundle = CNDPresentBundleIdentifier(row, icon);
        if (row.window && !row.hidden && row.alpha > 0.01 &&
            [bundle isEqualToString:@CND_PRESENT_TARGET_BUNDLE]) {
            [targets addObject:row];
        }
    }
    if (targets.count != 1U) {
        CNDPresentLog("[CND_PRESENT] wait tick=%u visibleTargets=%lu\n",
                      gCNDPresentTick, (unsigned long)targets.count);
        if (gCNDPresentWasVisible || gCNDPresentTick < 90U) {
            CNDPresentSchedule();
        } else {
            CNDPresentLog("[CND_PRESENT] FAILED reason=target-row-unresolved\n");
        }
        return;
    }

    UIView *row = targets.firstObject;
    id icon = CNDPresentApplicationIcon(row);
    id carrier = CNDPresentCarrier(row);
    id cache = CNDPresentCache(icon, carrier);
    id themeImage = CNDPresentObjectArgumentGetter(cache,
                                                    "cachedImageForIcon:",
                                                    icon);
    NSString *themeHash = CNDPresentImageHash(themeImage);
    if (!carrier || !cache || !themeImage || !themeHash.length) {
        CNDPresentLog("[CND_PRESENT] wait tick=%u row=%p icon=%p carrier=%p "
                      "cache=%p theme=%p hash=%s reason=graph-incomplete\n",
                      gCNDPresentTick, CNDPresentPointer(row),
                      CNDPresentPointer(icon), CNDPresentPointer(carrier),
                      CNDPresentPointer(cache), CNDPresentPointer(themeImage),
                      themeHash.UTF8String ?: "-");
        if (gCNDPresentTick < 90U) CNDPresentSchedule();
        else CNDPresentLog("[CND_PRESENT] FAILED reason=graph-incomplete\n");
        return;
    }

    if (row != gCNDPresentRow) {
        gCNDPresentRow = row;
        gCNDPresentCarrier = carrier;
        gCNDPresentStage = 4U;
        gCNDPresentRepairCount = 0U;
        gCNDPresentStableTicks = 0U;
        gCNDPresentWasVisible = false;
        CNDPresentLog("[CND_PRESENT] selected tick=%u row=%p/%s icon=%p/%s "
                      "carrier=%p/%s cache=%p/%s theme=%p/%s "
                      "themeSHA256=%s\n", gCNDPresentTick,
                      CNDPresentPointer(row), CNDPresentClassName(row),
                      CNDPresentPointer(icon), CNDPresentClassName(icon),
                      CNDPresentPointer(carrier), CNDPresentClassName(carrier),
                      CNDPresentPointer(cache), CNDPresentClassName(cache),
                      CNDPresentPointer(themeImage),
                      CNDPresentClassName(themeImage), themeHash.UTF8String);
        CNDPresentLogSurface(row, carrier);
        CNDPresentLogState("baseline", row, icon, carrier, cache,
                           themeImage, themeHash);
        CNDPresentScheduleAfter(0.25);
        return;
    }

    if (carrier != gCNDPresentCarrier) {
        CNDPresentLog("[CND_PRESENT] carrier-changed old=%p/%s new=%p/%s "
                      "stage=%u\n", CNDPresentPointer(gCNDPresentCarrier),
                      CNDPresentClassName(gCNDPresentCarrier),
                      CNDPresentPointer(carrier), CNDPresentClassName(carrier),
                      gCNDPresentStage);
        gCNDPresentCarrier = carrier;
        CNDPresentLogSurface(row, carrier);
    }

    bool visibleTheme = CNDPresentVisibleTheme(carrier, themeHash, NULL);
    if (visibleTheme) {
        if (!gCNDPresentWasVisible) {
            CNDPresentLogState("presented", row, icon, carrier, cache,
                               themeImage, themeHash);
            CNDPresentLog("[CND_PRESENT] PRESENTED repairs=%u "
                          "themeSHA256=%s resident=1 monitoring=1\n",
                          gCNDPresentRepairCount, themeHash.UTF8String);
        }
        gCNDPresentWasVisible = true;
        gCNDPresentStableTicks++;
        if (gCNDPresentStableTicks == 20U) {
            CNDPresentLog("[CND_PRESENT] STABLE duration=5s repairs=%u "
                          "resident=1 monitoring=1\n",
                          gCNDPresentRepairCount);
        }
        CNDPresentScheduleAfter(0.25);
        return;
    }

    if (gCNDPresentWasVisible) {
        CNDPresentLogState("regression", row, icon, carrier, cache,
                           themeImage, themeHash);
        CNDPresentLog("[CND_PRESENT] REGRESSION repairs=%u stableTicks=%u "
                      "rendererIdle=%d\n", gCNDPresentRepairCount,
                      gCNDPresentStableTicks, CNDPresentRendererIdle(carrier));
        gCNDPresentStableTicks = 0U;
    }
    gCNDPresentWasVisible = false;

    if (!CNDPresentRendererIdle(carrier)) {
        CNDPresentLog("[CND_PRESENT] wait-renderer tick=%u repairs=%u "
                      "stage=%u\n", gCNDPresentTick,
                      gCNDPresentRepairCount, gCNDPresentStage);
        CNDPresentScheduleAfter(0.25);
        return;
    }

    CNDPresentLogState("pre-rung", row, icon, carrier, cache,
                       themeImage, themeHash);

    bool invoked = false;
    const char *rung = "-";
    switch (gCNDPresentStage) {
        case 1U:
            rung = "reset-row-from-app-icon";
            if (cache) {
                (void)CNDPresentInvokeObject(cache,
                                              "beginObservingIconIfNecessary:",
                                              icon);
            }
            invoked = CNDPresentInvokeObject(row, "resetImageWithAppIcon:",
                                              icon);
            break;
        case 2U:
            rung = "row-update-icon-image-view";
            invoked = CNDPresentInvokeBool(row,
                                            "_updateIconImageViewAnimated:",
                                            NO);
            break;
        case 3U:
            rung = "carrier-update-existing-icon-layer";
            invoked = CNDPresentInvokeBool(carrier,
                                            "updateExistingIconLayerAnimated:",
                                            NO);
            break;
        case 4U: {
            rung = "carrier-clear-displayed-layer";
            id appearance = CNDPresentObjectGetter(
                carrier, "effectiveIconImageAppearance");
            if (!appearance) appearance = CNDPresentObjectGetter(
                carrier, "requestedImageAppearance");
            if (!appearance) appearance = CNDPresentObjectGetter(
                carrier, "displayedImageAppearance");
            invoked = appearance && CNDPresentInvokeFiveArgumentUpdate(
                carrier, themeImage, appearance);
            if (invoked) gCNDPresentRepairCount++;
            CNDPresentLog("[CND_PRESENT] appearance=%p/%s\n",
                          CNDPresentPointer(appearance),
                          CNDPresentClassName(appearance));
            break;
        }
        case 5U:
            rung = "row-content-change-callback";
            invoked = CNDPresentInvokeTwoObjects(
                row, "iconImageViewDidChangeContents:forIcon:", carrier,
                icon);
            break;
        case 6U:
            rung = "layout-pass";
            [row setNeedsLayout];
            [row layoutIfNeeded];
            invoked = true;
            break;
        default:
            CNDPresentLogState("final-failure", row, icon, carrier, cache,
                               themeImage, themeHash);
            CNDPresentLog("[CND_PRESENT] FAILED reason=no-stock-presentation-"
                          "rung-produced-visible-themed-layer\n");
            return;
    }
    CNDPresentLog("[CND_PRESENT] rung stage=%u name=%s invoked=%d\n",
                  gCNDPresentStage, rung, invoked);
    if (gCNDPresentStage != 4U) gCNDPresentStage++;
    CNDPresentScheduleAfter(0.25);
}

static void CNDPresentScheduleAfter(double seconds)
{
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(seconds * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            CNDPresentRunTick();
        }
    });
}

static void *CNDPresentBootstrap(void *context)
{
    (void)context;
    @autoreleasepool {
        usleep(250000);
        dispatch_async(dispatch_get_main_queue(), ^{
            CNDPresentLog("[CND_PRESENT] READY pid=%d process=%s "
                          "mainThread=%d target=%s\n", getpid(),
                          getprogname(), NSThread.isMainThread,
                          CND_PRESENT_TARGET_BUNDLE);
            CNDPresentSchedule();
        });
    }
    return NULL;
}

__attribute__((constructor))
static void CNDPresentStart(void)
{
    gCNDPresentFD = open(CNDPresentOutputPath,
                         O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CNDPresentLog("[CND_PRESENT] START pid=%d target=%s mode=resident-stock-"
                  "presentation-ladder storeWrites=0 bundleWrites=0\n",
                  getpid(), CND_PRESENT_TARGET_BUNDLE);
    pthread_t thread = 0;
    int result = pthread_create(&thread, NULL, CNDPresentBootstrap, NULL);
    if (result == 0) {
        (void)pthread_detach(thread);
    } else {
        CNDPresentLog("[CND_PRESENT] FAILED reason=bootstrap-thread result=%d\n",
                      result);
    }
}
