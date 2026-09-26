#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef CND_HOME_BUNDLE
#define CND_HOME_BUNDLE "com.ebay.iphone"
#endif
#ifndef CND_HOME_TOKEN
#define CND_HOME_TOKEN ""
#endif

static const char *const CNDHomeReport =
    "/var/tmp/cyanide-home-return-trace.log";
static int gCNDHomeFD = -1;
static _Atomic unsigned gCNDHomeSequence;
static __thread unsigned gCNDHomeDepth;

typedef id (*CNDObjectArgIMP)(id, SEL, id);
typedef id (*CNDCacheImageIMP)(id, SEL, id, id, NSUInteger);
typedef void (*CNDVoidObjectIMP)(id, SEL, id);
typedef void (*CNDVoidBoolIMP)(id, SEL, BOOL);
typedef BOOL (*CNDBoolBoolIMP)(id, SEL, BOOL);
typedef void (*CNDVoidObjectObjectBoolIMP)(id, SEL, id, id, BOOL);
typedef void (*CNDVoidObjectObjectBoolBoolIMP)(id, SEL, id, id, BOOL, BOOL);
typedef void (*CNDVoidThreeObjectsIMP)(id, SEL, id, id, id);
typedef struct {
    CGSize size;
    double scale;
    double value;
} CNDIconImageInfo;
typedef struct {
    double width;
    double height;
} CNDHomeSize;
typedef id (*CNDMakeLayerIMP)(id, SEL, CNDIconImageInfo, id, id, NSUInteger);
typedef id (*CNDDescriptorFactoryIMP)(id, SEL, int32_t, int32_t);

static CNDObjectArgIMP gCNDImageForDescriptor;
static CNDObjectArgIMP gCNDGenerateForDescriptor;
static CNDCacheImageIMP gCNDCacheImageForIcon;
static CNDVoidObjectIMP gCNDSetDisplayed;
static CNDVoidBoolIMP gCNDUpdateExisting;
static CNDBoolBoolIMP gCNDUpdateFromCache;
static CNDVoidObjectObjectBoolIMP gCNDUpdateContents;
static CNDVoidObjectObjectBoolBoolIMP gCNDUpdateContentsClear;
static CNDVoidThreeObjectsIMP gCNDCacheDidUpdate;
static CNDMakeLayerIMP gCNDMakeLayer;
static CNDDescriptorFactoryIMP gCNDDescriptorFactory;

static void CNDHomeLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDHomeLog(const char *format, ...)
{
    if (gCNDHomeFD < 0) return;
    char line[2048];
    va_list arguments;
    va_start(arguments, format);
    int size = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (size <= 0) return;
    size_t count = (size_t)size < sizeof(line)
        ? (size_t)size : sizeof(line) - 1U;
    (void)write(gCNDHomeFD, line, count);
}

static unsigned CNDHomeEvent(void)
{
    unsigned value = atomic_fetch_add_explicit(
        &gCNDHomeSequence, 1U, memory_order_relaxed) + 1U;
    return value <= 2500U ? value : 0U;
}

static uint64_t CNDHomeNowUS(void)
{
    struct timespec now = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000ULL +
        (uint64_t)now.tv_nsec / 1000ULL;
}

static const char *CNDHomeClass(id object)
{
    return object ? class_getName(object_getClass(object)) : "-";
}

static id CNDHomeGet(id object, const char *name)
{
    if (!object) return nil;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *type = method_copyReturnType(method);
    bool accepted = type && type[0] == '@';
    free(type);
    if (!accepted) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static const char *CNDHomeSkipTypeQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static bool CNDHomeGetInteger(id object, const char *name,
                              long long *valueOut)
{
    if (!object || !name || !valueOut) return false;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return false;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDHomeSkipTypeQualifiers(returnType);
    bool accepted = type && strchr("cCsSiIlLqQB", *type);
    free(returnType);
    if (!accepted) return false;
    @try {
        *valueOut = ((long long (*)(id, SEL))objc_msgSend)(object, selector);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDHomeGetDouble(id object, const char *name, double *valueOut)
{
    if (!object || !name || !valueOut) return false;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return false;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDHomeSkipTypeQualifiers(returnType);
    bool accepted = type && *type == 'd';
    free(returnType);
    if (!accepted) return false;
    @try {
        *valueOut = ((double (*)(id, SEL))objc_msgSend)(object, selector);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDHomeGetSize(id object, CNDHomeSize *sizeOut)
{
    if (!object || !sizeOut) return false;
    SEL selector = sel_registerName("size");
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (!types || strcmp(types, "{CGSize=dd}16@0:8")) return false;
    @try {
        *sizeOut = ((CNDHomeSize (*)(id, SEL))objc_msgSend)(object, selector);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

/* iconVariant/options are constructor-only fields on iOS 26: the stock
 * ISImageDescriptor has no getters for them.  Its canonical description is
 * the measured readback boundary and prints the variant as hexadecimal
 * ("v:20000" means 0x20000). */
static bool CNDHomeVariantFromDescription(NSString *description,
                                          long long *variantOut)
{
    if (![description isKindOfClass:NSString.class] || !variantOut) {
        return false;
    }
    const char *text = description.UTF8String;
    const char *field = text ? strstr(text, " v:") : NULL;
    unsigned long long value = 0ULL;
    if (!field || sscanf(field + 3, "%llx", &value) != 1 ||
        value > (unsigned long long)LLONG_MAX) {
        return false;
    }
    *variantOut = (long long)value;
    return true;
}

static const char *CNDHomeDescriptorRole(CNDHomeSize size, double scale,
                                         long long appearance,
                                         long long variant)
{
    if (size.width == 28.0 && size.height == 28.0 && scale == 3.0 &&
        appearance == 0 && variant == 0) {
        return "transition-28-v0";
    }
    if (size.width == 68.0 && size.height == 68.0 && scale == 3.0 &&
        appearance == 0 && variant == 0x20000) {
        return "transition-68-v20000";
    }
    if (size.width == 68.0 && size.height == 68.0 && scale == 3.0 &&
        appearance == 0 && variant == 0) {
        return "home-68-v0";
    }
    return "other";
}

static NSString *CNDHomeBundle(id object)
{
    static const char *const names[] = {
        "applicationBundleID", "bundleIdentifier", "uniqueIdentifier",
        "applicationBundleIdentifierForImage",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        id value = CNDHomeGet(object, names[i]);
        if ([value isKindOfClass:NSString.class] && [value length]) {
            return value;
        }
    }
    return nil;
}

static bool CNDHomeTarget(id object)
{
    return [CNDHomeBundle(object) isEqualToString:@CND_HOME_BUNDLE];
}

static bool CNDHomeLeafTarget(id icon)
{
    if (CNDHomeTarget(icon)) return true;
    id active = CNDHomeGet(icon, "activeDataSource");
    if (CNDHomeTarget(active)) return true;
    id value = CNDHomeGet(icon, "applicationBundleIdentifierForImage");
    return [value isKindOfClass:NSString.class] &&
        [value isEqualToString:@CND_HOME_BUNDLE];
}

static id CNDHomeViewIcon(id view)
{
    id icon = CNDHomeGet(view, "iconForImage");
    if (!icon) icon = CNDHomeGet(view, "icon");
    return icon;
}

static NSString *CNDHomeHash(NSData *data)
{
    if (!data) return @"-";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:64U];
    for (size_t i = 0; i < sizeof(digest); i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    return result;
}

static NSString *CNDHomeImageHash(CGImageRef image)
{
    if (!image) return @"-";
    CGDataProviderRef provider = CGImageGetDataProvider(image);
    if (!provider) return @"-";
    CFDataRef data = CGDataProviderCopyData(provider);
    NSString *result = CNDHomeHash((__bridge NSData *)data);
    if (data) CFRelease(data);
    return result;
}

static CGImageRef CNDHomeCGImage(id object)
{
    if ([object isKindOfClass:UIImage.class]) return ((UIImage *)object).CGImage;
    if (!object) return NULL;
    SEL selector = sel_registerName("CGImage");
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return NULL;
    char *type = method_copyReturnType(method);
    bool accepted = type && type[0] == '^';
    free(type);
    return accepted ? ((CGImageRef (*)(id, SEL))objc_msgSend)(
        object, selector) : NULL;
}

static void CNDHomeImage(unsigned event, const char *role, id image)
{
    id uuid = CNDHomeGet(image, "uuid");
    NSData *data = CNDHomeGet(image, "data");
    if (![data isKindOfClass:NSData.class]) data = nil;
    static NSData *marker;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        marker = [@"CNDThemeIcon.v1" dataUsingEncoding:NSUTF8StringEncoding];
    });
    bool themed = data && [data rangeOfData:marker options:0
                                      range:NSMakeRange(0, data.length)]
        .location != NSNotFound;
    CGImageRef cg = CNDHomeCGImage(image);
    CNDHomeLog("[CND_HOME] image seq=%u role=%s object=%p/%s uuid=%s "
               "bytes=%lu marker=%d dataSHA256=%s cg=%p pixels=%zux%zu "
               "pixelSHA256=%s\n", event, role, image,
               CNDHomeClass(image), uuid ? [[uuid description] UTF8String] : "-",
               (unsigned long)data.length, themed,
               CNDHomeHash(data).UTF8String, cg,
               cg ? CGImageGetWidth(cg) : 0U,
               cg ? CGImageGetHeight(cg) : 0U,
               CNDHomeImageHash(cg).UTF8String);
}

static void CNDHomeLayer(unsigned event, const char *role, CALayer *layer,
                         unsigned depth)
{
    if (!layer || depth > 2U) return;
    id contents = layer.contents;
    CGImageRef image = NULL;
    if (contents && CFGetTypeID((__bridge CFTypeRef)contents) ==
        CGImageGetTypeID()) image = (__bridge CGImageRef)contents;
    CNDHomeLog("[CND_HOME] layer seq=%u role=%s depth=%u layer=%p/%s "
               "hidden=%d opacity=%.3f contents=%p pixels=%zux%zu "
               "pixelSHA256=%s children=%lu\n", event, role, depth,
               layer, CNDHomeClass(layer), layer.hidden, layer.opacity,
               contents, image ? CGImageGetWidth(image) : 0U,
               image ? CGImageGetHeight(image) : 0U,
               CNDHomeImageHash(image).UTF8String,
               (unsigned long)layer.sublayers.count);
    NSUInteger count = MIN(layer.sublayers.count, 8U);
    for (NSUInteger i = 0; i < count; i++) {
        CNDHomeLayer(event, role, layer.sublayers[i], depth + 1U);
    }
}

static void CNDHomeState(unsigned event, const char *phase, id view)
{
    id icon = CNDHomeViewIcon(view);
    id displayed = CNDHomeGet(view, "displayedImage");
    id displayedID = CNDHomeGet(view, "displayedImageIdentity");
    id requestedID = CNDHomeGet(view, "requestedImageIdentity");
    id contentsView = CNDHomeGet(view, "contentsLayerView");
    id alternate = CNDHomeGet(view, "alternateContentsLayer");
    CALayer *contentsLayer = [contentsView isKindOfClass:UIView.class]
        ? ((UIView *)contentsView).layer : nil;
    CALayer *alternateLayer = [alternate isKindOfClass:CALayer.class]
        ? alternate : nil;
    UIView *uiView = [view isKindOfClass:UIView.class] ? view : nil;
    CNDHomeLog("[CND_HOME] state seq=%u us=%llu phase=%s main=%d "
               "view=%p/%s icon=%p/%s bundle=%s window=%p hidden=%d "
               "alpha=%.3f displayed=%p/%s displayedID=%p/%s "
               "requestedID=%p/%s identitiesEqual=%d contentsView=%p/%s "
               "alternate=%p/%s\n", event,
               (unsigned long long)CNDHomeNowUS(), phase, pthread_main_np(),
               view, CNDHomeClass(view), icon, CNDHomeClass(icon),
               CNDHomeBundle(icon).UTF8String ?: "-", uiView.window,
               uiView ? uiView.hidden : -1, uiView ? uiView.alpha : -1.0,
               displayed, CNDHomeClass(displayed), displayedID,
               CNDHomeClass(displayedID), requestedID,
               CNDHomeClass(requestedID), displayedID && requestedID &&
                   [displayedID isEqual:requestedID], contentsView,
               CNDHomeClass(contentsView), alternate,
               CNDHomeClass(alternate));
    CNDHomeImage(event, "displayed", displayed);
    CNDHomeLayer(event, "view-root", uiView.layer, 0U);
    if (contentsLayer && contentsLayer != uiView.layer) {
        CNDHomeLayer(event, "contents", contentsLayer, 0U);
    }
    if (alternateLayer) CNDHomeLayer(event, "alternate", alternateLayer, 0U);
}

static void CNDHomeLater(unsigned event, id view, double seconds)
{
    __weak id weakView = view;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(seconds * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        id current = weakView;
        if (current && CNDHomeTarget(CNDHomeViewIcon(current))) {
            CNDHomeState(event, "deferred", current);
        }
    });
}

static void CNDHomeUpdateExisting(id self, SEL selector, BOOL animated)
{
    bool target = !gCNDHomeDepth && CNDHomeTarget(CNDHomeViewIcon(self));
    unsigned event = target ? CNDHomeEvent() : 0U;
    if (event) CNDHomeState(event, "update-layer-enter", self);
    gCNDHomeDepth++;
    gCNDUpdateExisting(self, selector, animated);
    gCNDHomeDepth--;
    if (event) {
        CNDHomeLog("[CND_HOME] call seq=%u selector=%s animated=%d\n",
                   event, sel_getName(selector), animated);
        CNDHomeState(event, "update-layer-return", self);
        CNDHomeLater(event, self, 0.016);
        CNDHomeLater(event, self, 0.080);
        CNDHomeLater(event, self, 0.400);
    }
}

static void CNDHomeSetDisplayed(id self, SEL selector, id image)
{
    bool target = CNDHomeTarget(CNDHomeViewIcon(self));
    unsigned event = target ? CNDHomeEvent() : 0U;
    if (event) {
        CNDHomeState(event, "set-displayed-enter", self);
        CNDHomeImage(event, "set-displayed-arg", image);
    }
    gCNDSetDisplayed(self, selector, image);
    if (event) CNDHomeState(event, "set-displayed-return", self);
}

static void CNDHomeUpdateContents(id self, SEL selector, id image,
                                  id appearance, BOOL animated)
{
    bool target = CNDHomeTarget(CNDHomeViewIcon(self));
    unsigned event = target ? CNDHomeEvent() : 0U;
    if (event) {
        CNDHomeLog("[CND_HOME] call seq=%u selector=%s image=%p "
                   "appearance=%p animated=%d\n", event,
                   sel_getName(selector), image, appearance, animated);
        CNDHomeImage(event, "contents-arg", image);
        CNDHomeState(event, "contents-enter", self);
    }
    gCNDUpdateContents(self, selector, image, appearance, animated);
    if (event) CNDHomeState(event, "contents-return", self);
}

static void CNDHomeUpdateContentsClear(id self, SEL selector, id image,
                                       id appearance, BOOL animated,
                                       BOOL clear)
{
    bool target = CNDHomeTarget(CNDHomeViewIcon(self));
    unsigned event = target ? CNDHomeEvent() : 0U;
    if (event) {
        CNDHomeLog("[CND_HOME] call seq=%u selector=%s image=%p "
                   "appearance=%p animated=%d clear=%d\n", event,
                   sel_getName(selector), image, appearance, animated, clear);
        CNDHomeImage(event, "contents-clear-arg", image);
        CNDHomeState(event, "contents-clear-enter", self);
    }
    gCNDUpdateContentsClear(self, selector, image, appearance,
                            animated, clear);
    if (event) CNDHomeState(event, "contents-clear-return", self);
}

static BOOL CNDHomeUpdateFromCache(id self, SEL selector, BOOL animated)
{
    bool target = CNDHomeTarget(CNDHomeViewIcon(self));
    unsigned event = target ? CNDHomeEvent() : 0U;
    if (event) CNDHomeState(event, "cache-refresh-enter", self);
    BOOL result = gCNDUpdateFromCache(self, selector, animated);
    if (event) CNDHomeState(event, "cache-refresh-return", self);
    return result;
}

static void CNDHomeCacheDidUpdate(id self, SEL selector, id cache,
                                  id icon, id appearance)
{
    bool target = CNDHomeTarget(icon);
    unsigned event = target ? CNDHomeEvent() : 0U;
    if (event) {
        CNDHomeLog("[CND_HOME] call seq=%u selector=%s cache=%p icon=%p "
                   "appearance=%p\n", event, sel_getName(selector),
                   cache, icon, appearance);
        CNDHomeState(event, "cache-notify-enter", self);
    }
    gCNDCacheDidUpdate(self, selector, cache, icon, appearance);
    if (event) CNDHomeState(event, "cache-notify-return", self);
}

static id CNDHomeCacheImageForIcon(id self, SEL selector, id icon,
                                   id appearance, NSUInteger options)
{
    bool target = CNDHomeTarget(icon);
    unsigned event = target ? CNDHomeEvent() : 0U;
    id result = gCNDCacheImageForIcon(
        self, selector, icon, appearance, options);
    if (event) {
        CNDHomeLog("[CND_HOME] cache seq=%u us=%llu icon=%p/%s "
                   "bundle=%s appearance=%p options=%lu cache=%p result=%p\n",
                   event, (unsigned long long)CNDHomeNowUS(), icon,
                   CNDHomeClass(icon), CNDHomeBundle(icon).UTF8String ?: "-",
                   appearance, (unsigned long)options, self, result);
        CNDHomeImage(event, "cache-result", result);
    }
    return result;
}

static void CNDHomeDescriptor(unsigned event, id icon, id descriptor,
                              const char *phase)
{
    NSString *description = descriptor ? [descriptor description] : @"-";
    id digest = CNDHomeGet(descriptor, "digest");
    id imageCache = CNDHomeGet(icon, "imageCache");
    CNDHomeSize size = {0.0, 0.0};
    double scale = 0.0;
    long long appearance = 0;
    long long variant = 0;
    long long options = 0;
    bool hasSize = CNDHomeGetSize(descriptor, &size);
    bool hasScale = CNDHomeGetDouble(descriptor, "scale", &scale);
    bool hasAppearance = CNDHomeGetInteger(
        descriptor, "appearance", &appearance);
    bool hasVariant = CNDHomeGetInteger(
        descriptor, "iconVariant", &variant);
    const char *variantSource = hasVariant ? "getter" : "description";
    if (!hasVariant) {
        hasVariant = CNDHomeVariantFromDescription(description, &variant);
    }
    bool hasOptions = CNDHomeGetInteger(descriptor, "options", &options);
    const char *role = hasSize && hasScale && hasAppearance && hasVariant
            ? CNDHomeDescriptorRole(size, scale, appearance, variant)
            : "unknown";
    CNDHomeLog("[CND_HOME] descriptor seq=%u us=%llu phase=%s "
               "icon=%p/%s bundle=%s descriptor=%p/%s digest=%s "
               "role=%s geometry=%d/%.3fx%.3f scale=%d/%.3f "
               "appearance=%d/%lld variant=%d/%lld/%s options=%d/%lld "
               "imageCache=%p/%s description=%s\n", event,
               (unsigned long long)CNDHomeNowUS(), phase,
               icon, CNDHomeClass(icon), CNDHomeBundle(icon).UTF8String ?: "-",
               descriptor, CNDHomeClass(descriptor),
               digest ? [[digest description] UTF8String] : "-",
               role, hasSize, size.width, size.height, hasScale, scale,
               hasAppearance, appearance, hasVariant, variant,
               variantSource, hasOptions, options, imageCache,
               CNDHomeClass(imageCache), description.UTF8String);
}

static id CNDHomeImageForDescriptor(id self, SEL selector, id descriptor)
{
    bool target = CNDHomeTarget(self);
    unsigned event = target ? CNDHomeEvent() : 0U;
    if (event) CNDHomeDescriptor(event, self, descriptor, "lookup-enter");
    id result = gCNDImageForDescriptor(self, selector, descriptor);
    if (event) {
        CNDHomeDescriptor(event, self, descriptor, "lookup-return");
        CNDHomeImage(event, "iconservices-lookup", result);
    }
    return result;
}

static id CNDHomeGenerateForDescriptor(id self, SEL selector, id descriptor)
{
    bool target = CNDHomeTarget(self);
    unsigned event = target ? CNDHomeEvent() : 0U;
    if (event) CNDHomeDescriptor(event, self, descriptor, "generate-enter");
    id result = gCNDGenerateForDescriptor(self, selector, descriptor);
    if (event) {
        CNDHomeDescriptor(event, self, descriptor, "generate-return");
        CNDHomeImage(event, "iconservices-generate", result);
    }
    return result;
}

static id CNDHomeMakeLayer(id self, SEL selector, CNDIconImageInfo info,
                           id traits, id context, NSUInteger options)
{
    bool target = CNDHomeLeafTarget(self);
    unsigned event = target ? CNDHomeEvent() : 0U;
    if (event) {
        CNDHomeLog("[CND_HOME] make-layer seq=%u phase=enter icon=%p/%s "
                   "size=%.3fx%.3f scale=%.3f options=%lu\n", event,
                   self, CNDHomeClass(self), info.size.width,
                   info.size.height, info.scale, (unsigned long)options);
    }
    id result = gCNDMakeLayer(self, selector, info, traits, context, options);
    if (event) {
        CNDHomeLog("[CND_HOME] make-layer seq=%u phase=return result=%p/%s\n",
                   event, result, CNDHomeClass(result));
        if ([result isKindOfClass:CALayer.class]) {
            CNDHomeLayer(event, "source-layer", result, 0U);
        }
    }
    return result;
}

static id CNDHomeDescriptorFactory(id self, SEL selector,
                                   int32_t iconVariant, int32_t options)
{
    id result = gCNDDescriptorFactory(
        self, selector, iconVariant, options);
    NSString *description = result ? [result description] : @"-";
    bool transition = [description rangeOfString:@" v:20000 "]
        .location != NSNotFound;
    if (transition || iconVariant != 0 || options != 0) {
        unsigned event = CNDHomeEvent();
        if (event) {
            CNDHomeLog("[CND_HOME] descriptor-factory seq=%u us=%llu "
                       "requestedVariant=%d requestedOptions=%d "
                       "result=%p/%s transition=%d description=%s\n",
                       event, (unsigned long long)CNDHomeNowUS(),
                       iconVariant, options, result, CNDHomeClass(result),
                       transition, description.UTF8String);
        }
    }
    return result;
}

static bool CNDHomeHook(const char *className, const char *selectorName,
                        const char *types, IMP wrapper, IMP *original)
{
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    const char *actual = method ? method_getTypeEncoding(method) : NULL;
    if (!actual || strcmp(actual, types)) {
        CNDHomeLog("[CND_HOME] hook class=%s selector=%s ok=0 types=%s "
                   "expected=%s\n", className, selectorName,
                   actual ?: "-", types);
        return false;
    }
    IMP previous = method_getImplementation(method);
    if (!class_addMethod(cls, selector, wrapper, actual)) {
        method_setImplementation(method, wrapper);
    }
    bool installed = class_getMethodImplementation(cls, selector) == wrapper;
    if (installed) *original = previous;
    CNDHomeLog("[CND_HOME] hook class=%s selector=%s ok=%d original=%p\n",
               className, selectorName, installed, previous);
    return installed;
}

static bool CNDHomeHookClass(const char *className,
                             const char *selectorName,
                             const char *types, IMP wrapper, IMP *original)
{
    Class cls = objc_getClass(className);
    Class metaclass = cls ? object_getClass(cls) : Nil;
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getClassMethod(cls, selector) : NULL;
    const char *actual = method ? method_getTypeEncoding(method) : NULL;
    if (!metaclass || !actual || strcmp(actual, types)) {
        CNDHomeLog("[CND_HOME] hook-class class=%s selector=%s ok=0 "
                   "types=%s expected=%s\n", className, selectorName,
                   actual ?: "-", types);
        return false;
    }
    IMP previous = method_getImplementation(method);
    if (!class_addMethod(metaclass, selector, wrapper, actual)) {
        method_setImplementation(method, wrapper);
    }
    bool installed = class_getMethodImplementation(metaclass, selector) ==
        wrapper;
    if (installed) *original = previous;
    CNDHomeLog("[CND_HOME] hook-class class=%s selector=%s ok=%d "
               "original=%p\n", className, selectorName, installed,
               previous);
    return installed;
}

__attribute__((constructor))
static void CNDHomeStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_HOME_TOKEN[0] && consume
            ? consume(CND_HOME_TOKEN) : -1;
        gCNDHomeFD = open(CNDHomeReport,
                          O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        CNDHomeLog("[CND_HOME] START pid=%d bundle=%s token=%lld "
                   "mode=read-only no-view-walk=1\n", getpid(),
                   CND_HOME_BUNDLE, (long long)token);
        (void)dlopen(
            "/System/Library/PrivateFrameworks/SpringBoardHome.framework/"
            "SpringBoardHome", RTLD_NOW | RTLD_LOCAL);
        (void)dlopen(
            "/System/Library/PrivateFrameworks/IconServices.framework/"
            "IconServices", RTLD_NOW | RTLD_LOCAL);
        unsigned installed = 0U;
        installed += CNDHomeHook("ISBundleIdentifierIcon",
            "imageForDescriptor:", "@24@0:8@16",
            (IMP)CNDHomeImageForDescriptor, (IMP *)&gCNDImageForDescriptor);
        installed += CNDHomeHook("ISBundleIdentifierIcon",
            "generateImageWithDescriptor:", "@24@0:8@16",
            (IMP)CNDHomeGenerateForDescriptor,
            (IMP *)&gCNDGenerateForDescriptor);
        installed += CNDHomeHookClass("ISImageDescriptor",
            "imageDescriptorWithIconVariant:options:", "@24@0:8i16i20",
            (IMP)CNDHomeDescriptorFactory,
            (IMP *)&gCNDDescriptorFactory);
        installed += CNDHomeHook("SBHIconImageCache",
            "imageForIcon:imageAppearance:options:", "@40@0:8@16@24Q32",
            (IMP)CNDHomeCacheImageForIcon, (IMP *)&gCNDCacheImageForIcon);
        installed += CNDHomeHook("SBIconImageView", "setDisplayedImage:",
            "v24@0:8@16", (IMP)CNDHomeSetDisplayed,
            (IMP *)&gCNDSetDisplayed);
        installed += CNDHomeHook("SBIconImageView",
            "updateExistingIconLayerAnimated:", "v20@0:8B16",
            (IMP)CNDHomeUpdateExisting, (IMP *)&gCNDUpdateExisting);
        installed += CNDHomeHook("SBIconImageView",
            "updateImageContentsFromCacheAnimated:", "B20@0:8B16",
            (IMP)CNDHomeUpdateFromCache, (IMP *)&gCNDUpdateFromCache);
        installed += CNDHomeHook("SBIconImageView",
            "updateImageContentsWithImage:imageAppearance:animated:",
            "v36@0:8@16@24B32", (IMP)CNDHomeUpdateContents,
            (IMP *)&gCNDUpdateContents);
        installed += CNDHomeHook("SBIconImageView",
            "updateImageContentsWithImage:imageAppearance:animated:"
            "shouldClearDisplayedLayer:", "v40@0:8@16@24B32B36",
            (IMP)CNDHomeUpdateContentsClear,
            (IMP *)&gCNDUpdateContentsClear);
        installed += CNDHomeHook("SBIconImageView",
            "iconImageCache:didUpdateImageForIcon:imageAppearance:",
            "v40@0:8@16@24@32", (IMP)CNDHomeCacheDidUpdate,
            (IMP *)&gCNDCacheDidUpdate);
        installed += CNDHomeHook("SBLeafIcon",
            "makeIconLayerWithInfo:traitCollection:context:options:",
            "@72@0:8{SBIconImageInfo={CGSize=dd}dd}16@48@56Q64",
            (IMP)CNDHomeMakeLayer, (IMP *)&gCNDMakeLayer);
        CNDHomeLog("[CND_HOME] TRACE_READY pid=%d hooks=%u/11 "
                   "bundle=%s no-view-walk=1 event-cap=2500\n",
                   getpid(), installed, CND_HOME_BUNDLE);
    }
}
