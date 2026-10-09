#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef CND_INSPECT_OUTPUT_TOKEN
#define CND_INSPECT_OUTPUT_TOKEN ""
#endif

#ifndef CND_INSPECT_ROOT_TOKEN
#define CND_INSPECT_ROOT_TOKEN ""
#endif

#ifndef CND_INSPECT_TARGET_BUNDLE
#define CND_INSPECT_TARGET_BUNDLE "com.ebay.iphone"
#endif

static const char *const CNDInspectOutputPath =
    "/var/tmp/cyanide-spotlight-inspection.log";
static int gCNDInspectFD = -1;
static unsigned gCNDInspectAttempt;

static void CNDInspectLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDInspectLog(const char *format, ...)
{
    if (gCNDInspectFD < 0) return;
    char line[4096] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDInspectFD, line, amount);
    (void)fsync(gCNDInspectFD);
}

static const char *CNDInspectClassName(id object)
{
    return object ? class_getName(object_getClass(object)) : "-";
}

static void *CNDInspectPointer(id object)
{
    return object ? (__bridge void *)object : NULL;
}

static const char *CNDInspectSkipTypeQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static Method CNDInspectZeroArgumentMethod(id object, SEL selector)
{
    if (!object || !selector) return NULL;
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    return method && method_getNumberOfArguments(method) == 2U ? method : NULL;
}

static id CNDInspectObjectGetter(id object, const char *name)
{
    if (!object || !name || !name[0]) return nil;
    SEL selector = sel_registerName(name);
    Method method = CNDInspectZeroArgumentMethod(object, selector);
    if (!method) return nil;
    char *returnType = method_copyReturnType(method);
    const char *unqualified = CNDInspectSkipTypeQualifiers(returnType);
    bool objectReturn = unqualified &&
        (*unqualified == '@' || *unqualified == '#');
    free(returnType);
    if (!objectReturn) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (NSException *exception) {
        CNDInspectLog("[CND_INSPECT] getter-exception object=%p/%s "
                      "selector=%s exception=%s\n",
                      CNDInspectPointer(object), CNDInspectClassName(object),
                      name, exception.name.UTF8String ?: "-");
        return nil;
    }
}

static bool CNDInspectUnsignedGetter(id object, const char *name,
                                     NSUInteger *value)
{
    if (value) *value = 0U;
    if (!object || !name || !name[0] || !value) return false;
    SEL selector = sel_registerName(name);
    Method method = CNDInspectZeroArgumentMethod(object, selector);
    if (!method) return false;
    char *returnType = method_copyReturnType(method);
    const char *unqualified = CNDInspectSkipTypeQualifiers(returnType);
    bool unsignedReturn = unqualified &&
        (!strcmp(unqualified, @encode(NSUInteger)) ||
         !strcmp(unqualified, @encode(unsigned long long)) ||
         !strcmp(unqualified, @encode(unsigned long)) ||
         !strcmp(unqualified, @encode(unsigned int)));
    free(returnType);
    if (!unsignedReturn) return false;
    @try {
        *value = ((NSUInteger (*)(id, SEL))objc_msgSend)(object, selector);
        return true;
    } @catch (NSException *exception) {
        CNDInspectLog("[CND_INSPECT] unsigned-getter-exception "
                      "object=%p/%s selector=%s exception=%s\n",
                      CNDInspectPointer(object), CNDInspectClassName(object),
                      name, exception.name.UTF8String ?: "-");
        return false;
    }
}

static int CNDInspectBoolGetter(id object, const char *name)
{
    if (!object || !name || !name[0]) return -1;
    SEL selector = sel_registerName(name);
    Method method = CNDInspectZeroArgumentMethod(object, selector);
    if (!method) return -1;
    char *returnType = method_copyReturnType(method);
    const char *unqualified = CNDInspectSkipTypeQualifiers(returnType);
    bool boolReturn = unqualified &&
        (*unqualified == 'B' || *unqualified == 'c');
    free(returnType);
    if (!boolReturn) return -1;
    @try {
        return ((BOOL (*)(id, SEL))objc_msgSend)(object, selector) ? 1 : 0;
    } @catch (NSException *exception) {
        CNDInspectLog("[CND_INSPECT] bool-getter-exception object=%p/%s "
                      "selector=%s exception=%s\n",
                      CNDInspectPointer(object), CNDInspectClassName(object),
                      name, exception.name.UTF8String ?: "-");
        return -1;
    }
}

static id CNDInspectObjectArgumentGetter(id object, const char *name,
                                         id argument)
{
    if (!object || !name || !name[0]) return nil;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 3U) return nil;
    char *returnType = method_copyReturnType(method);
    const char *unqualified = CNDInspectSkipTypeQualifiers(returnType);
    bool objectReturn = unqualified &&
        (*unqualified == '@' || *unqualified == '#');
    free(returnType);
    if (!objectReturn) return nil;
    @try {
        return ((id (*)(id, SEL, id))objc_msgSend)(object, selector, argument);
    } @catch (NSException *exception) {
        CNDInspectLog("[CND_INSPECT] getter1-exception object=%p/%s "
                      "selector=%s exception=%s\n",
                      CNDInspectPointer(object), CNDInspectClassName(object),
                      name, exception.name.UTF8String ?: "-");
        return nil;
    }
}

static id CNDInspectObjectIvar(id object, const char *name)
{
    if (!object || !name || !name[0]) return nil;
    Ivar ivar = class_getInstanceVariable(object_getClass(object), name);
    if (!ivar) return nil;
    const char *type = CNDInspectSkipTypeQualifiers(ivar_getTypeEncoding(ivar));
    if (!type || *type != '@') return nil;
    @try {
        return object_getIvar(object, ivar);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static id CNDInspectObjectFromCandidates(id object,
                                         const char *const *getters,
                                         size_t getterCount,
                                         const char *const *ivars,
                                         size_t ivarCount,
                                         char *source,
                                         size_t sourceLength)
{
    if (source && sourceLength) source[0] = '\0';
    for (size_t i = 0; object && i < getterCount; i++) {
        id value = CNDInspectObjectGetter(object, getters[i]);
        if (!value) continue;
        if (source && sourceLength) {
            snprintf(source, sourceLength, "getter:%s", getters[i]);
        }
        return value;
    }
    for (size_t i = 0; object && i < ivarCount; i++) {
        id value = CNDInspectObjectIvar(object, ivars[i]);
        if (!value) continue;
        if (source && sourceLength) {
            snprintf(source, sourceLength, "ivar:%s", ivars[i]);
        }
        return value;
    }
    return nil;
}

static NSArray *CNDInspectCollectionItems(id collection, NSUInteger cap)
{
    if (!collection || cap == 0U) return @[];
    if ([collection isKindOfClass:NSDictionary.class]) {
        NSArray *keys = [(NSDictionary *)collection allKeys];
        return keys.count > cap
            ? [keys subarrayWithRange:NSMakeRange(0, cap)] : keys;
    }
    if ([collection isKindOfClass:NSArray.class]) {
        NSArray *array = collection;
        return array.count > cap
            ? [array subarrayWithRange:NSMakeRange(0, cap)] : array;
    }
    id objects = CNDInspectObjectGetter(collection, "allObjects");
    if ([objects isKindOfClass:NSArray.class]) {
        NSArray *array = objects;
        return array.count > cap
            ? [array subarrayWithRange:NSMakeRange(0, cap)] : array;
    }
    return @[];
}

static NSArray<UIWindow *> *CNDInspectWindows(void)
{
    UIApplication *application = UIApplication.sharedApplication;
    NSMutableArray<UIWindow *> *windows = [NSMutableArray array];
    id scenes = CNDInspectObjectGetter(application, "connectedScenes");
    for (id scene in CNDInspectCollectionItems(scenes, 16U)) {
        id sceneWindows = CNDInspectObjectGetter(scene, "windows");
        for (id window in CNDInspectCollectionItems(sceneWindows, 32U)) {
            if ([window isKindOfClass:UIWindow.class] &&
                ![windows containsObject:window]) {
                [windows addObject:window];
            }
        }
    }
    id legacyWindows = CNDInspectObjectGetter(application, "windows");
    for (id window in CNDInspectCollectionItems(legacyWindows, 32U)) {
        if ([window isKindOfClass:UIWindow.class] &&
            ![windows containsObject:window]) {
            [windows addObject:window];
        }
    }
    return windows;
}

static NSArray<UIView *> *CNDInspectViewsOfClass(Class wantedClass)
{
    if (!wantedClass) return @[];
    NSMutableArray<UIView *> *matches = [NSMutableArray array];
    NSMutableArray<UIView *> *pending = [NSMutableArray array];
    [pending addObjectsFromArray:CNDInspectWindows()];
    NSUInteger cursor = 0U;
    const NSUInteger viewCap = 4096U;
    while (cursor < pending.count && cursor < viewCap) {
        UIView *view = pending[cursor++];
        if ([view isKindOfClass:wantedClass]) [matches addObject:view];
        NSArray<UIView *> *subviews = view.subviews;
        NSUInteger available = viewCap > pending.count
            ? viewCap - pending.count : 0U;
        if (subviews.count > available) {
            if (available) {
                [pending addObjectsFromArray:
                    [subviews subarrayWithRange:NSMakeRange(0, available)]];
            }
            break;
        }
        [pending addObjectsFromArray:subviews];
    }
    CNDInspectLog("[CND_INSPECT] view-walk windows=%lu visited=%lu "
                  "matches=%lu truncated=%d\n",
                  (unsigned long)CNDInspectWindows().count,
                  (unsigned long)MIN(cursor, viewCap),
                  (unsigned long)matches.count,
                  pending.count > viewCap);
    return matches;
}

static id CNDInspectApplicationIcon(UIView *view, char *source,
                                    size_t sourceLength)
{
    static const char *const getters[] = {
        "appIcon", "icon", "applicationIcon", "representedIcon"
    };
    static const char *const ivars[] = {
        "_appIcon", "_icon", "_applicationIcon", "_representedIcon"
    };
    return CNDInspectObjectFromCandidates(
        view, getters, sizeof(getters) / sizeof(getters[0]),
        ivars, sizeof(ivars) / sizeof(ivars[0]), source, sourceLength);
}

static NSString *CNDInspectBundleIdentifier(id view, id icon,
                                            char *source,
                                            size_t sourceLength)
{
    if (source && sourceLength) source[0] = '\0';
    NSArray *roots = @[icon ?: NSNull.null, view ?: NSNull.null];
    static const char *const links[] = {
        "application", "applicationProxy", "applicationInfo", "proxy"
    };
    for (id root in roots) {
        if (root == NSNull.null) continue;
        id identifier = CNDInspectObjectGetter(root, "bundleIdentifier");
        if ([identifier isKindOfClass:NSString.class]) {
            if (source && sourceLength) {
                snprintf(source, sourceLength, "direct.bundleIdentifier");
            }
            return identifier;
        }
        for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
            id linked = CNDInspectObjectGetter(root, links[i]);
            identifier = CNDInspectObjectGetter(linked, "bundleIdentifier");
            if ([identifier isKindOfClass:NSString.class]) {
                if (source && sourceLength) {
                    snprintf(source, sourceLength, "%s.bundleIdentifier",
                             links[i]);
                }
                return identifier;
            }
        }
    }
    return nil;
}

static id CNDInspectImageCarrier(UIView *view, char *source,
                                 size_t sourceLength)
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
    id carrier = CNDInspectObjectFromCandidates(
        view, getters, sizeof(getters) / sizeof(getters[0]),
        ivars, sizeof(ivars) / sizeof(ivars[0]), source, sourceLength);
    return carrier ?: view;
}

static CGImageRef CNDInspectCGImage(id object)
{
    if (!object) return NULL;
    if ([object isKindOfClass:UIImage.class]) {
        return ((UIImage *)object).CGImage;
    }
    SEL selector = sel_registerName("CGImage");
    Method method = CNDInspectZeroArgumentMethod(object, selector);
    if (!method) return NULL;
    char *returnType = method_copyReturnType(method);
    const char *unqualified = CNDInspectSkipTypeQualifiers(returnType);
    bool pointerReturn = unqualified && *unqualified == '^';
    free(returnType);
    if (!pointerReturn) return NULL;
    @try {
        return ((CGImageRef (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (__unused NSException *exception) {
        return NULL;
    }
}

static NSString *CNDInspectSHA256(NSData *data)
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

static NSData *CNDInspectCanonicalRGBA(CGImageRef image)
{
    if (!image) return nil;
    size_t width = CGImageGetWidth(image);
    size_t height = CGImageGetHeight(image);
    if (!width || !height || width > 4096U || height > 4096U ||
        width > SIZE_MAX / 4U || height > SIZE_MAX / (width * 4U)) {
        return nil;
    }
    size_t bytesPerRow = width * 4U;
    size_t length = bytesPerRow * height;
    if (length > 64U * 1024U * 1024U) return nil;
    NSMutableData *pixels = [NSMutableData dataWithLength:length];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) return nil;
    CGContextRef context = CGBitmapContextCreate(
        pixels.mutableBytes, width, height, 8U, bytesPerRow, colorSpace,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(colorSpace);
    if (!context) return nil;
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), image);
    CGContextRelease(context);
    return pixels;
}

typedef struct {
    size_t pixels;
    size_t alphaNonzero;
    size_t alphaFull;
    size_t colorNonzero;
    unsigned long long alphaSum;
} CNDInspectPixelStats;

static CNDInspectPixelStats CNDInspectRGBAStats(NSData *rgba)
{
    CNDInspectPixelStats stats = {0};
    if (!rgba || rgba.length % 4U != 0U) return stats;
    const unsigned char *bytes = rgba.bytes;
    stats.pixels = rgba.length / 4U;
    for (size_t i = 0; i < stats.pixels; i++) {
        unsigned char red = bytes[i * 4U];
        unsigned char green = bytes[i * 4U + 1U];
        unsigned char blue = bytes[i * 4U + 2U];
        unsigned char alpha = bytes[i * 4U + 3U];
        stats.alphaNonzero += alpha != 0U;
        stats.alphaFull += alpha == 255U;
        stats.colorNonzero += red != 0U || green != 0U || blue != 0U;
        stats.alphaSum += alpha;
    }
    return stats;
}

static void CNDInspectLogImage(const char *label, id image)
{
    CGImageRef cgImage = CNDInspectCGImage(image);
    NSData *rgba = CNDInspectCanonicalRGBA(cgImage);
    CNDInspectPixelStats stats = CNDInspectRGBAStats(rgba);
    CNDInspectLog("[CND_INSPECT] image label=%s object=%p/%s cg=%p "
                  "pixels=%zux%zu rgbaBytes=%lu rgbaSHA256=%s "
                  "alphaNonzero=%zu/%zu alphaFull=%zu colorNonzero=%zu "
                  "alphaSum=%llu\n",
                  label, CNDInspectPointer(image), CNDInspectClassName(image),
                  cgImage, cgImage ? CGImageGetWidth(cgImage) : 0U,
                  cgImage ? CGImageGetHeight(cgImage) : 0U,
                  (unsigned long)rgba.length,
                  rgba ? CNDInspectSHA256(rgba).UTF8String : "-",
                  stats.alphaNonzero, stats.pixels, stats.alphaFull,
                  stats.colorNonzero, stats.alphaSum);
}

static void CNDInspectLogLayerTree(CALayer *layer, unsigned depth)
{
    if (!layer || depth > 5U) return;
    id contents = layer.contents;
    CGImageRef contentsImage = NULL;
    if (contents) {
        CFTypeRef value = (__bridge CFTypeRef)contents;
        if (CFGetTypeID(value) == CGImageGetTypeID()) {
            contentsImage = (CGImageRef)value;
        }
    }
    NSData *rgba = CNDInspectCanonicalRGBA(contentsImage);
    CNDInspectPixelStats stats = CNDInspectRGBAStats(rgba);
    CGColorRef background = layer.backgroundColor;
    CGColorRef border = layer.borderColor;
    CNDInspectLog("[CND_INSPECT] layer depth=%u object=%p/%s delegate=%p/%s "
                  "bounds=%.1f,%.1f,%.1f,%.1f scale=%.2f opacity=%.3f "
                  "hidden=%d opaque=%d masks=%d corner=%.2f "
                  "background=%p/%.3f border=%.2f/%p/%.3f shadow=%.3f "
                  "contents=%p/%s cg=%p pixels=%zux%zu "
                  "rgbaSHA256=%s alphaNonzero=%zu/%zu alphaFull=%zu "
                  "colorNonzero=%zu alphaSum=%llu sublayers=%lu\n",
                  depth, CNDInspectPointer(layer), CNDInspectClassName(layer),
                  CNDInspectPointer(layer.delegate),
                  CNDInspectClassName(layer.delegate), layer.bounds.origin.x,
                  layer.bounds.origin.y, layer.bounds.size.width,
                  layer.bounds.size.height, layer.contentsScale, layer.opacity,
                  layer.hidden, layer.opaque, layer.masksToBounds,
                  layer.cornerRadius, background,
                  background ? CGColorGetAlpha(background) : 0.0,
                  layer.borderWidth, border,
                  border ? CGColorGetAlpha(border) : 0.0,
                  layer.shadowOpacity, CNDInspectPointer(contents),
                  CNDInspectClassName(contents), contentsImage,
                  contentsImage ? CGImageGetWidth(contentsImage) : 0U,
                  contentsImage ? CGImageGetHeight(contentsImage) : 0U,
                  rgba ? CNDInspectSHA256(rgba).UTF8String : "-",
                  stats.alphaNonzero, stats.pixels, stats.alphaFull,
                  stats.colorNonzero, stats.alphaSum,
                  (unsigned long)layer.sublayers.count);
    NSUInteger cap = MIN(layer.sublayers.count, 32U);
    for (NSUInteger i = 0; i < cap; i++) {
        CNDInspectLogLayerTree(layer.sublayers[i], depth + 1U);
    }
}

static bool CNDInspectNameRelevant(const char *name)
{
    if (!name) return false;
    char lowered[256] = {0};
    size_t length = strnlen(name, sizeof(lowered) - 1U);
    for (size_t i = 0; i < length; i++) {
        char c = name[i];
        lowered[i] = c >= 'A' && c <= 'Z' ? (char)(c + ('a' - 'A')) : c;
    }
    static const char *const terms[] = {
        "icon", "image", "cache", "descriptor", "store", "uuid",
        "data", "resource", "content", "digest", "token", "bundle"
    };
    for (size_t i = 0; i < sizeof(terms) / sizeof(terms[0]); i++) {
        if (strstr(lowered, terms[i])) return true;
    }
    return false;
}

static void CNDInspectDumpClassSurface(id object, const char *label)
{
    if (!object) return;
    Class cls = object_getClass(object);
    for (unsigned depth = 0; cls && depth < 8U; depth++,
         cls = class_getSuperclass(cls)) {
        const char *className = class_getName(cls);
        CNDInspectLog("[CND_INSPECT] class label=%s depth=%u object=%p "
                      "name=%s\n", label, depth,
                      CNDInspectPointer(object), className ?: "-");
        if (className &&
            (!strcmp(className, "NSObject") ||
             !strcmp(className, "UIResponder") ||
             !strcmp(className, "UIView") ||
             !strcmp(className, "CALayer"))) {
            continue;
        }
        unsigned methodCount = 0U;
        Method *methods = class_copyMethodList(cls, &methodCount);
        unsigned loggedMethods = 0U;
        for (unsigned i = 0; methods && i < methodCount &&
             loggedMethods < 64U; i++) {
            SEL selector = method_getName(methods[i]);
            const char *name = sel_getName(selector);
            if (!CNDInspectNameRelevant(name)) continue;
            CNDInspectLog("[CND_INSPECT] method label=%s owner=%s name=%s "
                          "types=%s\n", label, className ?: "-",
                          name ?: "-",
                          method_getTypeEncoding(methods[i]) ?: "-");
            loggedMethods++;
        }
        free(methods);

        unsigned ivarCount = 0U;
        Ivar *ivars = class_copyIvarList(cls, &ivarCount);
        unsigned loggedIvars = 0U;
        for (unsigned i = 0; ivars && i < ivarCount && loggedIvars < 64U;
             i++) {
            const char *name = ivar_getName(ivars[i]);
            if (!CNDInspectNameRelevant(name)) continue;
            const char *type = CNDInspectSkipTypeQualifiers(
                ivar_getTypeEncoding(ivars[i]));
            id value = type && *type == '@'
                ? object_getIvar(object, ivars[i]) : nil;
            CNDInspectLog("[CND_INSPECT] ivar label=%s owner=%s name=%s "
                          "types=%s offset=%td value=%p/%s\n",
                          label, className ?: "-", name ?: "-",
                          ivar_getTypeEncoding(ivars[i]) ?: "-",
                          ivar_getOffset(ivars[i]), CNDInspectPointer(value),
                          CNDInspectClassName(value));
            loggedIvars++;
        }
        free(ivars);
    }
}

static id CNDInspectImageCache(id iconServicesIcon, id consumer,
                               id carrier, char *source,
                               size_t sourceLength)
{
    NSArray *objects = @[
        iconServicesIcon ?: NSNull.null,
        consumer ?: NSNull.null,
        carrier ?: NSNull.null,
    ];
    static const char *const getters[] = {
        "imageCache", "iconImageCache", "cache"
    };
    static const char *const ivars[] = {
        "_imageCache", "_iconImageCache", "_cache"
    };
    for (NSUInteger slot = 0; slot < objects.count; slot++) {
        id object = objects[slot];
        if (object == NSNull.null) continue;
        char local[96] = {0};
        id cache = CNDInspectObjectFromCandidates(
            object, getters, sizeof(getters) / sizeof(getters[0]),
            ivars, sizeof(ivars) / sizeof(ivars[0]), local, sizeof(local));
        if (!cache) continue;
        if (source && sourceLength) {
            snprintf(source, sourceLength, "slot%lu.%s",
                     (unsigned long)slot, local);
        }
        return cache;
    }
    return nil;
}

static id CNDInspectManager(void)
{
    Class managerClass = NSClassFromString(@"ISIconManager");
    if (!managerClass) return nil;
    static const char *const getters[] = {
        "sharedInstance", "sharedManager", "defaultManager"
    };
    for (size_t i = 0; i < sizeof(getters) / sizeof(getters[0]); i++) {
        id manager = CNDInspectObjectGetter(managerClass, getters[i]);
        if (manager) return manager;
    }
    return nil;
}

static id CNDInspectManagerStore(id manager, id managerCache)
{
    static const char *const getters[] = {"store", "imageStore"};
    static const char *const ivars[] = {"_store", "_imageStore"};
    for (id object in @[managerCache ?: NSNull.null,
                        manager ?: NSNull.null]) {
        if (object == NSNull.null) continue;
        id store = CNDInspectObjectFromCandidates(
            object, getters, sizeof(getters) / sizeof(getters[0]),
            ivars, sizeof(ivars) / sizeof(ivars[0]), NULL, 0U);
        if (store) return store;
    }
    return nil;
}

static void CNDInspectLogResponse(id response, NSUInteger keyIndex,
                                  NSUInteger imageIndex, id store,
                                  NSString *cachePath,
                                  NSString *visiblePixelHash,
                                  NSUInteger *exactMatches)
{
    id uuid = CNDInspectObjectGetter(response, "uuid");
    id token = CNDInspectObjectGetter(response, "validationToken");
    id data = CNDInspectObjectGetter(response, "data");
    CGImageRef cgImage = CNDInspectCGImage(response);
    NSData *rgba = CNDInspectCanonicalRGBA(cgImage);
    NSString *pixelHash = rgba ? CNDInspectSHA256(rgba) : @"-";
    if (visiblePixelHash && [pixelHash isEqualToString:visiblePixelHash]) {
        (*exactMatches)++;
    }
    NSData *dataObject = [data isKindOfClass:NSData.class] ? data : nil;
    id unit = uuid
        ? CNDInspectObjectArgumentGetter(store, "unitForUUID:", uuid) : nil;
    NSString *uuidText = [uuid isKindOfClass:NSUUID.class]
        ? [uuid UUIDString] :
        ([uuid isKindOfClass:NSString.class] ? uuid : nil);
    NSString *filePath = cachePath.length && uuidText.length
        ? [cachePath stringByAppendingPathComponent:
            [uuidText stringByAppendingPathExtension:@"isdata"]] : nil;
    NSDictionary *attributes = filePath
        ? [NSFileManager.defaultManager attributesOfItemAtPath:filePath
                                                          error:nil] : nil;
    NSData *fileData = filePath
        ? [NSData dataWithContentsOfFile:filePath
                                options:NSDataReadingMappedIfSafe error:nil]
        : nil;
    CNDInspectLog("[CND_INSPECT] response key=%lu image=%lu object=%p/%s "
                  "cg=%p pixels=%zux%zu rgbaBytes=%lu rgbaSHA256=%s "
                  "visibleMatch=%d uuid=%s token=%p/%s dataBytes=%lu "
                  "dataSHA256=%s unit=%p/%s file=%s "
                  "fileBytes=%llu fileSHA256=%s\n",
                  (unsigned long)keyIndex, (unsigned long)imageIndex,
                  CNDInspectPointer(response), CNDInspectClassName(response),
                  cgImage, cgImage ? CGImageGetWidth(cgImage) : 0U,
                  cgImage ? CGImageGetHeight(cgImage) : 0U,
                  (unsigned long)rgba.length, pixelHash.UTF8String,
                  visiblePixelHash && [pixelHash isEqualToString:visiblePixelHash],
                  uuidText.UTF8String ?: "-", CNDInspectPointer(token),
                  CNDInspectClassName(token), (unsigned long)dataObject.length,
                  dataObject ? CNDInspectSHA256(dataObject).UTF8String : "-",
                  CNDInspectPointer(unit), CNDInspectClassName(unit),
                  filePath.UTF8String ?: "-",
                  (unsigned long long)[attributes fileSize],
                  fileData ? CNDInspectSHA256(fileData).UTF8String : "-");
}

static void CNDInspectCache(id cache, id store, NSString *cachePath,
                            NSString *visiblePixelHash)
{
    id bags = CNDInspectObjectGetter(cache, "imageBagsByDescriptor");
    if (![bags isKindOfClass:NSDictionary.class]) {
        CNDInspectLog("[CND_INSPECT] cache-bags cache=%p/%s bags=%p/%s "
                      "dictionary=0\n", CNDInspectPointer(cache),
                      CNDInspectClassName(cache), CNDInspectPointer(bags),
                      CNDInspectClassName(bags));
        return;
    }
    NSDictionary *dictionary = bags;
    NSArray *keys = dictionary.allKeys;
    NSUInteger keyCap = MIN(keys.count, 64U);
    NSUInteger responseCount = 0U;
    NSUInteger exactMatches = 0U;
    CNDInspectLog("[CND_INSPECT] cache-bags cache=%p/%s dictionary=%p/%s "
                  "keys=%lu capped=%lu\n", CNDInspectPointer(cache),
                  CNDInspectClassName(cache), CNDInspectPointer(dictionary),
                  CNDInspectClassName(dictionary), (unsigned long)keys.count,
                  (unsigned long)keyCap);
    for (NSUInteger keyIndex = 0; keyIndex < keyCap; keyIndex++) {
        id key = keys[keyIndex];
        id bag = dictionary[key];
        id images = CNDInspectObjectGetter(bag, "images");
        NSArray *items = CNDInspectCollectionItems(images, 64U);
        id digest = CNDInspectObjectGetter(key, "digest");
        CNDInspectLog("[CND_INSPECT] descriptor key=%lu object=%p/%s "
                      "digest=%p/%s bag=%p/%s images=%lu\n",
                      (unsigned long)keyIndex, CNDInspectPointer(key),
                      CNDInspectClassName(key), CNDInspectPointer(digest),
                      CNDInspectClassName(digest), CNDInspectPointer(bag),
                      CNDInspectClassName(bag), (unsigned long)items.count);
        for (NSUInteger imageIndex = 0; imageIndex < items.count;
             imageIndex++) {
            CNDInspectLogResponse(items[imageIndex], keyIndex, imageIndex,
                                  store, cachePath, visiblePixelHash,
                                  &exactMatches);
            responseCount++;
        }
    }
    CNDInspectLog("[CND_INSPECT] cache-summary keys=%lu responses=%lu "
                  "visiblePixelExactMatches=%lu truncated=%d\n",
                  (unsigned long)keyCap, (unsigned long)responseCount,
                  (unsigned long)exactMatches, keys.count > keyCap);
}

static bool CNDInspectRunOnce(void)
{
    NSCAssert(NSThread.isMainThread, @"Spotlight inspection must run on main");
    Class rowClass = NSClassFromString(@"SearchUIHomeScreenAppIconView");
    NSArray<UIView *> *rows = CNDInspectViewsOfClass(rowClass);
    NSMutableArray<NSDictionary *> *targetRows = [NSMutableArray array];
    for (UIView *row in rows) {
        char iconSource[96] = {0};
        id icon = CNDInspectApplicationIcon(row, iconSource,
                                            sizeof(iconSource));
        char bundleSource[96] = {0};
        NSString *bundle = CNDInspectBundleIdentifier(
            row, icon, bundleSource, sizeof(bundleSource));
        bool visible = row.window != nil && !row.hidden && row.alpha >= 0.01;
        NSUInteger variant = 0U;
        bool hasVariant = CNDInspectUnsignedGetter(row, "variant", &variant);
        id rowCache = CNDInspectObjectGetter(row, "iconImageCache");
        CGSize variantSize = CGSizeZero;
        Class appIconImageClass = NSClassFromString(@"SearchUIAppIconImage");
        SEL sizeSelector = sel_registerName("sizeForVariant:");
        if (hasVariant && [appIconImageClass respondsToSelector:sizeSelector]) {
            variantSize = ((CGSize (*)(id, SEL, NSUInteger))objc_msgSend)(
                appIconImageClass, sizeSelector, variant);
        }
        CNDInspectLog("[CND_INSPECT] row object=%p/%s visible=%d hidden=%d "
                      "alpha=%.3f frame=%.1f,%.1f,%.1f,%.1f "
                      "variant=%s%lu variantSize=%.1fx%.1f cache=%p/%s "
                      "icon=%p/%s iconSource=%s bundle=%s bundleSource=%s\n",
                      CNDInspectPointer(row),
                      CNDInspectClassName(row), visible, row.hidden,
                      row.alpha, row.frame.origin.x, row.frame.origin.y,
                      row.frame.size.width, row.frame.size.height,
                      hasVariant ? "" : "-", (unsigned long)variant,
                      variantSize.width, variantSize.height,
                      CNDInspectPointer(rowCache), CNDInspectClassName(rowCache),
                      CNDInspectPointer(icon),
                      CNDInspectClassName(icon), iconSource[0] ? iconSource : "-",
                      bundle.UTF8String ?: "-",
                      bundleSource[0] ? bundleSource : "-");
        if (visible && [bundle isEqualToString:@CND_INSPECT_TARGET_BUNDLE]) {
            [targetRows addObject:@{@"view": row,
                                    @"icon": icon ?: NSNull.null}];
        }
    }
    CNDInspectLog("[CND_INSPECT] target bundle=%s visibleRows=%lu "
                  "allRows=%lu attempt=%u\n", CND_INSPECT_TARGET_BUNDLE,
                  (unsigned long)targetRows.count, (unsigned long)rows.count,
                  gCNDInspectAttempt);
    if (targetRows.count != 1U) return false;

    UIView *row = targetRows.firstObject[@"view"];
    id consumer = targetRows.firstObject[@"icon"];
    if (consumer == NSNull.null) consumer = nil;
    char carrierSource[96] = {0};
    id carrier = CNDInspectImageCarrier(row, carrierSource,
                                        sizeof(carrierSource));
    CNDInspectLog("[CND_INSPECT] selected row=%p/%s consumer=%p/%s "
                  "carrier=%p/%s carrierSource=%s mainThread=%d\n",
                  CNDInspectPointer(row), CNDInspectClassName(row),
                  CNDInspectPointer(consumer), CNDInspectClassName(consumer),
                  CNDInspectPointer(carrier), CNDInspectClassName(carrier),
                  carrierSource[0] ? carrierSource : "view-fallback",
                  NSThread.isMainThread);

    id effectiveAppearance = CNDInspectObjectGetter(
        carrier, "effectiveIconImageAppearance");
    NSProcessInfo *processInfo = NSProcessInfo.processInfo;
    CNDInspectLog("[CND_INSPECT] presentation-state "
                  "prefersFlat=%d effectivelyFlat=%d square=%d "
                  "appearance=%p/%s hasGlass=%d shouldLayer=%d "
                  "displayingLayer=%d lowPower=%d thermal=%ld\n",
                  CNDInspectBoolGetter(carrier, "prefersFlatImageLayers"),
                  CNDInspectBoolGetter(
                      carrier, "effectivelyPrefersFlatImageLayers"),
                  CNDInspectBoolGetter(carrier, "showsSquareCorners"),
                  CNDInspectPointer(effectiveAppearance),
                  CNDInspectClassName(effectiveAppearance),
                  CNDInspectBoolGetter(effectiveAppearance, "hasGlass"),
                  CNDInspectBoolGetter(carrier, "shouldDisplayImageLayer"),
                  CNDInspectBoolGetter(carrier, "isDisplayingImageLayer"),
                  processInfo.isLowPowerModeEnabled,
                  (long)processInfo.thermalState);

    id displayedImage = nil;
    NSString *visiblePixelHash = nil;
    static const char *const imageGetters[] = {
        "image", "displayedImage", "contentsImage"
    };
    for (size_t getterIndex = 0;
         getterIndex < sizeof(imageGetters) / sizeof(imageGetters[0]);
         getterIndex++) {
        const char *getter = imageGetters[getterIndex];
        id image = CNDInspectObjectGetter(carrier, getter);
        CNDInspectLog("[CND_INSPECT] carrier-getter name=%s result=%p/%s "
                      "mainThread=%d\n", getter, CNDInspectPointer(image),
                      CNDInspectClassName(image), NSThread.isMainThread);
        CNDInspectLogImage(getter, image);
        if (!displayedImage && CNDInspectCGImage(image)) displayedImage = image;
    }
    if (displayedImage) {
        NSData *rgba = CNDInspectCanonicalRGBA(
            CNDInspectCGImage(displayedImage));
        visiblePixelHash = rgba ? CNDInspectSHA256(rgba) : nil;
    }

    static const char *const carrierObjectGetters[] = {
        "squareContentsImage", "iconForImage", "contentsLayerView",
        "iconLayerView", "ICRIconLayer", "alternateContentsLayer",
        "desiredImageIdentity", "displayedImageIdentity"
    };
    NSMutableDictionary<NSString *, id> *carrierObjects =
        [NSMutableDictionary dictionary];
    for (size_t i = 0;
         i < sizeof(carrierObjectGetters) /
             sizeof(carrierObjectGetters[0]); i++) {
        const char *getter = carrierObjectGetters[i];
        id value = CNDInspectObjectGetter(carrier, getter);
        CNDInspectLog("[CND_INSPECT] carrier-object name=%s result=%p/%s\n",
                      getter, CNDInspectPointer(value),
                      CNDInspectClassName(value));
        if (value) {
            carrierObjects[@(getter)] = value;
            CNDInspectLogImage(getter, value);
        }
    }
    id contentsLayerView = carrierObjects[@"contentsLayerView"];
    id carrierICRLayer = carrierObjects[@"ICRIconLayer"];
    if (!carrierICRLayer) {
        carrierICRLayer = CNDInspectObjectGetter(
            contentsLayerView, "ICRIconLayer");
    }
    static const char *const layerViewGetters[] = {
        "iconLayer", "contentLayer", "contentsLayer", "ICRIconLayer",
        "image", "contentsImage", "resource", "resourceProvider"
    };
    for (size_t i = 0; contentsLayerView &&
         i < sizeof(layerViewGetters) / sizeof(layerViewGetters[0]); i++) {
        id value = CNDInspectObjectGetter(contentsLayerView,
                                          layerViewGetters[i]);
        CNDInspectLog("[CND_INSPECT] layer-view-object name=%s "
                      "result=%p/%s\n", layerViewGetters[i],
                      CNDInspectPointer(value), CNDInspectClassName(value));
        if (value) CNDInspectLogImage(layerViewGetters[i], value);
    }
    CNDInspectLog("[CND_INSPECT] layer-root label=row\n");
    CNDInspectLogLayerTree(row.layer, 0U);
    if ([carrier isKindOfClass:UIView.class]) {
        CNDInspectLog("[CND_INSPECT] layer-root label=carrier\n");
        CNDInspectLogLayerTree(((UIView *)carrier).layer, 0U);
    }
    if ([contentsLayerView isKindOfClass:UIView.class]) {
        CNDInspectLog("[CND_INSPECT] layer-root label=contentsLayerView\n");
        CNDInspectLogLayerTree(((UIView *)contentsLayerView).layer, 0U);
    }

    id iconServicesIcon = CNDInspectObjectGetter(
        consumer, "iconServicesIconForImage");
    char cacheSource[128] = {0};
    id cache = CNDInspectImageCache(iconServicesIcon, consumer, carrier,
                                    cacheSource, sizeof(cacheSource));
    id manager = CNDInspectManager();
    id managerCache = CNDInspectObjectGetter(manager, "iconCache");
    if (!managerCache) managerCache = CNDInspectObjectGetter(manager, "cache");
    id store = CNDInspectManagerStore(manager, managerCache);
    id cachePathObject = CNDInspectObjectGetter(managerCache, "cachePath");
    NSString *cachePath = [cachePathObject isKindOfClass:NSString.class]
        ? cachePathObject : nil;
    CNDInspectLog("[CND_INSPECT] graph iconServicesIcon=%p/%s cache=%p/%s "
                  "cacheSource=%s manager=%p/%s managerCache=%p/%s "
                  "store=%p/%s cachePath=%s visiblePixelSHA256=%s\n",
                  CNDInspectPointer(iconServicesIcon),
                  CNDInspectClassName(iconServicesIcon),
                  CNDInspectPointer(cache), CNDInspectClassName(cache),
                  cacheSource[0] ? cacheSource : "-",
                  CNDInspectPointer(manager), CNDInspectClassName(manager),
                  CNDInspectPointer(managerCache),
                  CNDInspectClassName(managerCache), CNDInspectPointer(store),
                  CNDInspectClassName(store), cachePath.UTF8String ?: "-",
                  visiblePixelHash.UTF8String ?: "-");

    static const char *const cachedImageGetters[] = {
        "cachedImageForIcon:", "cachedUnmaskedImageForIcon:"
    };
    for (size_t i = 0;
         i < sizeof(cachedImageGetters) / sizeof(cachedImageGetters[0]); i++) {
        id cachedImage = CNDInspectObjectArgumentGetter(
            cache, cachedImageGetters[i], consumer);
        CNDInspectLog("[CND_INSPECT] row-cache-getter name=%s result=%p/%s\n",
                      cachedImageGetters[i], CNDInspectPointer(cachedImage),
                      CNDInspectClassName(cachedImage));
        CNDInspectLogImage(cachedImageGetters[i], cachedImage);
    }

    id maskedVariantCache = CNDInspectObjectIvar(cache, "_maskedCache");
    id unmaskedVariantCache = CNDInspectObjectIvar(cache, "_unmaskedCache");

    CNDInspectDumpClassSurface(row, "row");
    CNDInspectDumpClassSurface(carrier, "carrier");
    CNDInspectDumpClassSurface(contentsLayerView, "contentsLayerView");
    CNDInspectDumpClassSurface(carrierICRLayer, "carrierICRLayer");
    CNDInspectDumpClassSurface(consumer, "consumer");
    CNDInspectDumpClassSurface(iconServicesIcon, "iconServicesIcon");
    CNDInspectDumpClassSurface(cache, "consumerCache");
    CNDInspectDumpClassSurface(maskedVariantCache, "maskedVariantCache");
    CNDInspectDumpClassSurface(unmaskedVariantCache, "unmaskedVariantCache");
    CNDInspectDumpClassSurface(managerCache, "managerCache");
    CNDInspectDumpClassSurface(store, "managerStore");
    if (cache) CNDInspectCache(cache, store, cachePath, visiblePixelHash);
    if (managerCache && managerCache != cache) {
        CNDInspectCache(managerCache, store, cachePath, visiblePixelHash);
    }
    CNDInspectLog("[CND_INSPECT] COMPLETE pid=%d bundle=%s visibleRows=1 "
                  "row=%p consumer=%p carrier=%p displayed=%p cache=%p "
                  "managerCache=%p noMutation=1 setters=0 storeWrites=0 "
                  "fileWrites=report-only\n", getpid(),
                  CND_INSPECT_TARGET_BUNDLE, CNDInspectPointer(row),
                  CNDInspectPointer(consumer), CNDInspectPointer(carrier),
                  CNDInspectPointer(displayedImage), CNDInspectPointer(cache),
                  CNDInspectPointer(managerCache));
    return true;
}

static void CNDInspectScheduleAttempt(void)
{
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            gCNDInspectAttempt++;
            CNDInspectLog("[CND_INSPECT] attempt=%u mainThread=%d state=%ld\n",
                          gCNDInspectAttempt, NSThread.isMainThread,
                          (long)UIApplication.sharedApplication.applicationState);
            if (CNDInspectRunOnce()) return;
            if (gCNDInspectAttempt < 20U) {
                CNDInspectScheduleAttempt();
            } else {
                CNDInspectLog("[CND_INSPECT] COMPLETE pid=%d bundle=%s "
                              "visibleRows=unresolved attempts=%u "
                              "noMutation=1 setters=0 storeWrites=0 "
                              "fileWrites=report-only\n", getpid(),
                              CND_INSPECT_TARGET_BUNDLE, gCNDInspectAttempt);
            }
        }
    });
}

__attribute__((constructor))
static void CNDInspectStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t outputHandle = CND_INSPECT_OUTPUT_TOKEN[0] && consume
            ? consume(CND_INSPECT_OUTPUT_TOKEN) : -1;
        int64_t rootHandle = CND_INSPECT_ROOT_TOKEN[0] && consume
            ? consume(CND_INSPECT_ROOT_TOKEN) : -1;
        gCNDInspectFD = open(CNDInspectOutputPath,
                             O_WRONLY | O_CREAT | O_TRUNC, 0644);
        CNDInspectLog("[CND_INSPECT] START pid=%d process=%s mainThread=%d "
                      "outputToken=%lld rootToken=%lld target=%s "
                      "mode=read-only\n", getpid(), getprogname(),
                      NSThread.isMainThread, (long long)outputHandle,
                      (long long)rootHandle, CND_INSPECT_TARGET_BUNDLE);
        if (gCNDInspectFD >= 0) CNDInspectScheduleAttempt();
    }
}
