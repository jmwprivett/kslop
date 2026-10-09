#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CND_TRACE_TARGET_BUNDLE
#define CND_TRACE_TARGET_BUNDLE "com.ebay.iphone"
#endif

static const char *const CNDTraceOutputPath =
    "/var/tmp/cyanide-spotlight-transition-trace.log";
static int gCNDTraceFD = -1;
static __thread unsigned gCNDTraceDepth;
static unsigned gCNDTraceEvent;
static unsigned gCNDTraceProvokeAttempt;
static bool gCNDTraceProvoked;
static unsigned gCNDTracePolicySetterCount;
static unsigned gCNDTraceEffectivePolicyCount;
static __thread unsigned gCNDTracePolicyDepth;

typedef void (*CNDTraceBoolIMP)(id, SEL, BOOL);
typedef BOOL (*CNDTraceBoolGetterIMP)(id, SEL);
typedef void (*CNDTraceObjectsIMP)(id, SEL, id, id);
typedef void (*CNDTraceImageUpdateIMP)(id, SEL, id, id, BOOL, BOOL);
typedef id (*CNDTraceObjectArgIMP)(id, SEL, id);
typedef void (*CNDTraceVoidArgIMP)(id, SEL, id);
typedef struct {
    CGSize size;
    double scale;
    double value;
} CNDTraceIconImageInfo;
typedef id (*CNDTraceMakeLayerIMP)(id, SEL, CNDTraceIconImageInfo,
                                   id, id, NSUInteger);

static CNDTraceBoolIMP gCNDOriginalUpdateExisting;
static CNDTraceBoolIMP gCNDOriginalRowUpdate;
static CNDTraceObjectsIMP gCNDOriginalRowCallback;
static CNDTraceImageUpdateIMP gCNDOriginalImageUpdate;
static CNDTraceObjectArgIMP gCNDOriginalImageForDescriptor;
static CNDTraceObjectArgIMP gCNDOriginalPrepareObject;
static CNDTraceVoidArgIMP gCNDOriginalPrepareVoid;
static CNDTraceMakeLayerIMP gCNDOriginalMakeLayer;
static CNDTraceBoolIMP gCNDOriginalIconViewSetPrefersFlat;
static CNDTraceBoolIMP gCNDOriginalImageViewSetPrefersFlat;
static CNDTraceBoolIMP gCNDOriginalIconViewSetShowsSquare;
static CNDTraceBoolIMP gCNDOriginalImageViewSetShowsSquare;
static CNDTraceBoolGetterIMP gCNDOriginalEffectivelyPrefersFlat;

static void CNDTraceLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDTraceLog(const char *format, ...)
{
    if (gCNDTraceFD < 0) return;
    char line[4096] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDTraceFD, line, amount);
    (void)fsync(gCNDTraceFD);
}

static const char *CNDTraceClassName(id object)
{
    return object ? class_getName(object_getClass(object)) : "-";
}

static void *CNDTracePointer(id object)
{
    return object ? (__bridge void *)object : NULL;
}

static const char *CNDTraceUnqualified(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static Method CNDTraceMethod(id object, const char *name,
                             unsigned argumentCount)
{
    if (!object || !name) return NULL;
    Method method = class_getInstanceMethod(object_getClass(object),
                                             sel_registerName(name));
    return method && method_getNumberOfArguments(method) == argumentCount
        ? method : NULL;
}

static bool CNDTraceMethodReturns(Method method, char expected)
{
    if (!method) return false;
    char *type = method_copyReturnType(method);
    const char *unqualified = CNDTraceUnqualified(type);
    bool matches = unqualified && *unqualified == expected;
    free(type);
    return matches;
}

static id CNDTraceObjectGetter(id object, const char *name)
{
    Method method = CNDTraceMethod(object, name, 2U);
    if (!method || !CNDTraceMethodReturns(method, '@')) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object,
                                               sel_registerName(name));
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static id CNDTraceObjectIvar(id object, const char *name)
{
    if (!object || !name) return nil;
    Ivar ivar = class_getInstanceVariable(object_getClass(object), name);
    if (!ivar) return nil;
    const char *type = CNDTraceUnqualified(ivar_getTypeEncoding(ivar));
    return type && *type == '@' ? object_getIvar(object, ivar) : nil;
}

static id CNDTraceObjectFromCandidates(id object,
                                       const char *const *getters,
                                       size_t getterCount,
                                       const char *const *ivars,
                                       size_t ivarCount)
{
    for (size_t i = 0; object && i < getterCount; i++) {
        id value = CNDTraceObjectGetter(object, getters[i]);
        if (value) return value;
    }
    for (size_t i = 0; object && i < ivarCount; i++) {
        id value = CNDTraceObjectIvar(object, ivars[i]);
        if (value) return value;
    }
    return nil;
}

static NSString *CNDTraceBundleIdentifier(id root)
{
    static const char *const links[] = {
        "application", "applicationProxy", "applicationInfo", "proxy"
    };
    id identifier = CNDTraceObjectGetter(root, "bundleIdentifier");
    if ([identifier isKindOfClass:NSString.class]) return identifier;
    for (size_t i = 0; root && i < sizeof(links) / sizeof(links[0]); i++) {
        id linked = CNDTraceObjectGetter(root, links[i]);
        identifier = CNDTraceObjectGetter(linked, "bundleIdentifier");
        if ([identifier isKindOfClass:NSString.class]) return identifier;
    }
    return nil;
}

static id CNDTraceCarrierIcon(id carrier)
{
    static const char *const getters[] = {
        "iconForImage", "icon", "applicationIcon", "representedIcon"
    };
    static const char *const ivars[] = {
        "_iconForImage", "_icon", "_applicationIcon", "_representedIcon"
    };
    return CNDTraceObjectFromCandidates(
        carrier, getters, sizeof(getters) / sizeof(getters[0]),
        ivars, sizeof(ivars) / sizeof(ivars[0]));
}

static id CNDTraceCarrierRow(id carrier)
{
    static const char *const getters[] = {
        "iconView", "delegate", "owningIconView"
    };
    static const char *const ivars[] = {
        "_iconView", "_delegate", "_owningIconView"
    };
    return CNDTraceObjectFromCandidates(
        carrier, getters, sizeof(getters) / sizeof(getters[0]),
        ivars, sizeof(ivars) / sizeof(ivars[0]));
}

static id CNDTraceApplicationIcon(id row)
{
    static const char *const getters[] = {
        "appIcon", "icon", "applicationIcon", "representedIcon"
    };
    static const char *const ivars[] = {
        "_appIcon", "_icon", "_applicationIcon", "_representedIcon"
    };
    return CNDTraceObjectFromCandidates(
        row, getters, sizeof(getters) / sizeof(getters[0]),
        ivars, sizeof(ivars) / sizeof(ivars[0]));
}

static id CNDTraceRowCarrier(id row)
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
    return CNDTraceObjectFromCandidates(
        row, getters, sizeof(getters) / sizeof(getters[0]),
        ivars, sizeof(ivars) / sizeof(ivars[0]));
}

static NSString *CNDTraceCarrierBundle(id carrier, id *iconOut, id *rowOut)
{
    id icon = CNDTraceCarrierIcon(carrier);
    id row = CNDTraceCarrierRow(carrier);
    NSString *bundle = CNDTraceBundleIdentifier(icon);
    if (!bundle) bundle = CNDTraceBundleIdentifier(row);
    if (iconOut) *iconOut = icon;
    if (rowOut) *rowOut = row;
    return bundle;
}

static bool CNDTraceTargetCarrier(id carrier, id *iconOut, id *rowOut)
{
    NSString *bundle = CNDTraceCarrierBundle(carrier, iconOut, rowOut);
    return [bundle isEqualToString:@CND_TRACE_TARGET_BUNDLE];
}

static CGImageRef CNDTraceCGImage(id object)
{
    if ([object isKindOfClass:UIImage.class]) return ((UIImage *)object).CGImage;
    Method method = CNDTraceMethod(object, "CGImage", 2U);
    if (!method || !CNDTraceMethodReturns(method, '^')) return NULL;
    return ((CGImageRef (*)(id, SEL))objc_msgSend)(
        object, sel_registerName("CGImage"));
}

static NSData *CNDTraceRGBA(CGImageRef image)
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

static NSString *CNDTraceSHA256(NSData *data)
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

static NSString *CNDTraceImageHash(id image)
{
    return CNDTraceSHA256(CNDTraceRGBA(CNDTraceCGImage(image)));
}

static NSString *CNDTraceLayerHash(CALayer *layer)
{
    id contents = layer.contents;
    if (!contents) return nil;
    CFTypeRef value = (__bridge CFTypeRef)contents;
    if (CFGetTypeID(value) != CGImageGetTypeID()) return nil;
    return CNDTraceSHA256(CNDTraceRGBA((CGImageRef)value));
}

static int CNDTraceBoolGetter(id object, const char *name);

static NSString *CNDTraceDescription(id object)
{
    if (!object) return @"-";
    @try {
        NSString *description = [object description];
        return description.length ? description : @"-";
    } @catch (__unused NSException *exception) {
        return @"-";
    }
}

static void CNDTraceLogLayerTree(unsigned event, CALayer *layer,
                                 unsigned depth)
{
    if (!layer || depth > 3U) return;
    CNDTraceLog("[CND_TRANSITION] result-layer event=%u depth=%u "
                "layer=%p/%s hidden=%d opacity=%.3f contents=%p/%s "
                "contentsSHA256=%s sublayers=%lu\n", event, depth,
                CNDTracePointer(layer), CNDTraceClassName(layer), layer.hidden,
                layer.opacity, CNDTracePointer(layer.contents),
                CNDTraceClassName(layer.contents),
                CNDTraceLayerHash(layer).UTF8String ?: "-",
                (unsigned long)layer.sublayers.count);
    NSUInteger cap = MIN(layer.sublayers.count, 16U);
    for (NSUInteger i = 0; i < cap; i++) {
        CNDTraceLogLayerTree(event, layer.sublayers[i], depth + 1U);
    }
}

static bool CNDTraceIconTargetsBundle(id icon)
{
    NSString *bundle = CNDTraceBundleIdentifier(icon);
    return [bundle isEqualToString:@CND_TRACE_TARGET_BUNDLE];
}

static void CNDTraceLogDescriptor(unsigned event, id icon, id descriptor,
                                  const char *phase)
{
    id digest = CNDTraceObjectGetter(descriptor, "digest");
    id appearance = CNDTraceObjectGetter(descriptor, "appearance");
    id imageAppearance = CNDTraceObjectGetter(descriptor,
                                               "imageAppearance");
    CNDTraceLog("[CND_TRANSITION] descriptor event=%u phase=%s icon=%p/%s "
                "bundle=%s descriptor=%p/%s digest=%p/%s digestText=%s "
                "appearance=%p/%s imageAppearance=%p/%s description=%s\n",
                event, phase, CNDTracePointer(icon), CNDTraceClassName(icon),
                CNDTraceBundleIdentifier(icon).UTF8String ?: "-",
                CNDTracePointer(descriptor), CNDTraceClassName(descriptor),
                CNDTracePointer(digest), CNDTraceClassName(digest),
                CNDTraceDescription(digest).UTF8String ?: "-",
                CNDTracePointer(appearance), CNDTraceClassName(appearance),
                CNDTracePointer(imageAppearance),
                CNDTraceClassName(imageAppearance),
                CNDTraceDescription(descriptor).UTF8String ?: "-");
}

static void CNDTraceLogIconServicesResult(unsigned event, id result)
{
    id uuid = CNDTraceObjectGetter(result, "uuid");
    id validationToken = CNDTraceObjectGetter(result, "validationToken");
    id data = CNDTraceObjectGetter(result, "data");
    id iconLayer = CNDTraceObjectGetter(result, "ICRIconLayer");
    if (!iconLayer) iconLayer = CNDTraceObjectGetter(result, "iconLayer");
    CALayer *layer = [iconLayer isKindOfClass:CALayer.class] ? iconLayer : nil;
    NSData *dataObject = [data isKindOfClass:NSData.class] ? data : nil;
    CGImageRef image = CNDTraceCGImage(result);
    CNDTraceLog("[CND_TRANSITION] iconservices-result event=%u result=%p/%s "
                "placeholder=%d cg=%p pixels=%zux%zu rgbaSHA256=%s "
                "uuid=%p/%s uuidText=%s validation=%p/%s data=%p/%s "
                "dataBytes=%lu dataSHA256=%s iconLayer=%p/%s\n", event,
                CNDTracePointer(result), CNDTraceClassName(result),
                CNDTraceBoolGetter(result, "isPlaceholder"), image,
                image ? CGImageGetWidth(image) : 0U,
                image ? CGImageGetHeight(image) : 0U,
                CNDTraceSHA256(CNDTraceRGBA(image)).UTF8String ?: "-",
                CNDTracePointer(uuid), CNDTraceClassName(uuid),
                CNDTraceDescription(uuid).UTF8String ?: "-",
                CNDTracePointer(validationToken),
                CNDTraceClassName(validationToken), CNDTracePointer(data),
                CNDTraceClassName(data), (unsigned long)dataObject.length,
                CNDTraceSHA256(dataObject).UTF8String ?: "-",
                CNDTracePointer(iconLayer), CNDTraceClassName(iconLayer));
    if (layer) CNDTraceLogLayerTree(event, layer, 0U);
}

static NSString *CNDTraceLeafBundleIdentifier(id icon)
{
    NSString *bundle = CNDTraceBundleIdentifier(icon);
    if (bundle) return bundle;
    id value = CNDTraceObjectGetter(icon,
                                    "applicationBundleIdentifierForImage");
    if ([value isKindOfClass:NSString.class]) return value;
    id dataSource = CNDTraceObjectGetter(icon, "activeDataSource");
    value = CNDTraceObjectGetter(dataSource, "bundleIdentifier");
    if ([value isKindOfClass:NSString.class]) return value;
    Method method = CNDTraceMethod(
        dataSource, "applicationBundleIdentifierForImageForIcon:", 3U);
    if (method && CNDTraceMethodReturns(method, '@')) {
        @try {
            value = ((id (*)(id, SEL, id))objc_msgSend)(
                dataSource,
                sel_registerName(
                    "applicationBundleIdentifierForImageForIcon:"),
                icon);
        } @catch (__unused NSException *exception) {
            value = nil;
        }
    }
    return [value isKindOfClass:NSString.class] ? value : nil;
}

static id CNDTraceMakeIconLayer(id self, SEL command,
                                CNDTraceIconImageInfo info,
                                id traitCollection, id context,
                                NSUInteger options)
{
    NSString *bundle = CNDTraceLeafBundleIdentifier(self);
    bool target = [bundle isEqualToString:@CND_TRACE_TARGET_BUNDLE];
    unsigned event = target ? ++gCNDTraceEvent : 0U;
    if (target) {
        CNDTraceLog(
            "[CND_TRANSITION] BOUNDARY_CALL event=%u "
            "selector=%s icon=%p/%s bundle=%s "
            "info={%.3f,%.3f,%.3f,%.3f} "
            "trait=%p/%s context=%p/%s options=0x%lx\n",
            event, sel_getName(command), CNDTracePointer(self),
            CNDTraceClassName(self), bundle.UTF8String ?: "-",
            info.size.width, info.size.height, info.scale, info.value,
            CNDTracePointer(traitCollection),
            CNDTraceClassName(traitCollection), CNDTracePointer(context),
            CNDTraceClassName(context), (unsigned long)options);
    }
    id layer = gCNDOriginalMakeLayer(
        self, command, info, traitCollection, context, options);
    if (target) {
        CNDTraceLog(
            "[CND_TRANSITION] BOUNDARY_RETURN event=%u selector=%s "
            "layer=%p/%s\n", event, sel_getName(command),
            CNDTracePointer(layer), CNDTraceClassName(layer));
        if ([layer isKindOfClass:CALayer.class]) {
            CNDTraceLogLayerTree(event, layer, 0U);
        }
    }
    return layer;
}

static int CNDTraceBoolGetter(id object, const char *name)
{
    Method method = CNDTraceMethod(object, name, 2U);
    if (!method) return -1;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDTraceUnqualified(returnType);
    bool valid = type && (*type == 'B' || *type == 'c');
    free(returnType);
    if (!valid) return -1;
    return ((BOOL (*)(id, SEL))objc_msgSend)(
        object, sel_registerName(name)) ? 1 : 0;
}

static void CNDTraceLogStack(unsigned event)
{
    void *frames[20] = {0};
    int count = backtrace(frames, (int)(sizeof(frames) / sizeof(frames[0])));
    int cap = count < 16 ? count : 16;
    for (int i = 1; i < cap; i++) {
        Dl_info info = {0};
        bool resolved = dladdr(frames[i], &info) != 0;
        uintptr_t imageOffset = resolved && info.dli_fbase
            ? (uintptr_t)frames[i] - (uintptr_t)info.dli_fbase : 0U;
        uintptr_t symbolOffset = resolved && info.dli_saddr
            ? (uintptr_t)frames[i] - (uintptr_t)info.dli_saddr : 0U;
        const char *image = resolved && info.dli_fname
            ? strrchr(info.dli_fname, '/') : NULL;
        CNDTraceLog("[CND_TRANSITION] stack event=%u frame=%d pc=%p "
                    "image=%s imageOffset=0x%lx symbol=%s symbolOffset=0x%lx\n",
                    event, i, frames[i], image ? image + 1 : "-",
                    (unsigned long)imageOffset,
                    resolved && info.dli_sname ? info.dli_sname : "-",
                    (unsigned long)symbolOffset);
    }
}

static void CNDTracePolicySetter(id self, SEL command, BOOL value,
                                 CNDTraceBoolIMP original,
                                 const char *hookName)
{
    original(self, command, value);
    id icon = nil;
    id row = nil;
    bool target = CNDTraceTargetCarrier(self, &icon, &row);
    bool withinCap = gCNDTracePolicySetterCount < 128U;
    gCNDTracePolicySetterCount++;
    if (!target && !withinCap) return;
    unsigned event = ++gCNDTraceEvent;
    NSProcessInfo *processInfo = NSProcessInfo.processInfo;
    CNDTraceLog(
        "[CND_TRANSITION] POLICY_SET event=%u hook=%s selector=%s "
        "receiver=%p/%s value=%d target=%d bundle=%s icon=%p/%s "
        "row=%p/%s prefersFlat=%d square=%d lowPower=%d thermal=%ld\n",
        event, hookName, sel_getName(command), CNDTracePointer(self),
        CNDTraceClassName(self), value, target,
        CNDTraceCarrierBundle(self, NULL, NULL).UTF8String ?: "-",
        CNDTracePointer(icon), CNDTraceClassName(icon),
        CNDTracePointer(row), CNDTraceClassName(row),
        CNDTraceBoolGetter(self, "prefersFlatImageLayers"),
        CNDTraceBoolGetter(self, "showsSquareCorners"),
        processInfo.isLowPowerModeEnabled, (long)processInfo.thermalState);
    CNDTraceLogStack(event);
}

static void CNDTraceIconViewSetPrefersFlat(id self, SEL command, BOOL value)
{
    CNDTracePolicySetter(self, command, value,
                         gCNDOriginalIconViewSetPrefersFlat,
                         "SBIconView");
}

static void CNDTraceImageViewSetPrefersFlat(id self, SEL command, BOOL value)
{
    CNDTracePolicySetter(self, command, value,
                         gCNDOriginalImageViewSetPrefersFlat,
                         "SBIconImageView");
}

static void CNDTraceIconViewSetShowsSquare(id self, SEL command, BOOL value)
{
    CNDTracePolicySetter(self, command, value,
                         gCNDOriginalIconViewSetShowsSquare,
                         "SBIconView");
}

static void CNDTraceImageViewSetShowsSquare(id self, SEL command, BOOL value)
{
    CNDTracePolicySetter(self, command, value,
                         gCNDOriginalImageViewSetShowsSquare,
                         "SBIconImageView");
}

static BOOL CNDTraceEffectivelyPrefersFlat(id self, SEL command)
{
    if (gCNDTracePolicyDepth++) {
        BOOL result = gCNDOriginalEffectivelyPrefersFlat(self, command);
        gCNDTracePolicyDepth--;
        return result;
    }
    BOOL result = gCNDOriginalEffectivelyPrefersFlat(self, command);
    id icon = nil;
    id row = nil;
    bool target = CNDTraceTargetCarrier(self, &icon, &row);
    bool withinCap = gCNDTraceEffectivePolicyCount < 128U;
    gCNDTraceEffectivePolicyCount++;
    if (target || withinCap) {
        unsigned event = ++gCNDTraceEvent;
        id appearance = CNDTraceObjectGetter(
            self, "effectiveIconImageAppearance");
        NSProcessInfo *processInfo = NSProcessInfo.processInfo;
        CNDTraceLog(
            "[CND_TRANSITION] POLICY_EFFECTIVE event=%u selector=%s "
            "receiver=%p/%s target=%d bundle=%s icon=%p/%s row=%p/%s "
            "prefersFlat=%d square=%d appearance=%p/%s hasGlass=%d "
            "lowPower=%d thermal=%ld result=%d\n",
            event, sel_getName(command), CNDTracePointer(self),
            CNDTraceClassName(self), target,
            CNDTraceCarrierBundle(self, NULL, NULL).UTF8String ?: "-",
            CNDTracePointer(icon), CNDTraceClassName(icon),
            CNDTracePointer(row), CNDTraceClassName(row),
            CNDTraceBoolGetter(self, "prefersFlatImageLayers"),
            CNDTraceBoolGetter(self, "showsSquareCorners"),
            CNDTracePointer(appearance), CNDTraceClassName(appearance),
            CNDTraceBoolGetter(appearance, "hasGlass"),
            processInfo.isLowPowerModeEnabled,
            (long)processInfo.thermalState, result);
        CNDTraceLogStack(event);
    }
    gCNDTracePolicyDepth--;
    return result;
}

static void CNDTraceLogState(unsigned event, const char *phase, id carrier)
{
    id icon = nil;
    id row = nil;
    NSString *bundle = CNDTraceCarrierBundle(carrier, &icon, &row);
    id displayed = CNDTraceObjectGetter(carrier, "displayedImage");
    id desiredIdentity = CNDTraceObjectGetter(carrier,
                                               "desiredImageIdentity");
    id displayedIdentity = CNDTraceObjectGetter(carrier,
                                                 "displayedImageIdentity");
    id contentsLayerView = CNDTraceObjectGetter(carrier,
                                                 "contentsLayerView");
    CALayer *contentsLayer = [contentsLayerView isKindOfClass:UIView.class]
        ? ((UIView *)contentsLayerView).layer : nil;
    CALayer *alternate = CNDTraceObjectGetter(carrier,
                                               "alternateContentsLayer");
    UIView *placeholder = CNDTraceObjectGetter(row, "placeholderView");
    CNDTraceLog(
        "[CND_TRANSITION] state event=%u phase=%s bundle=%s carrier=%p/%s "
        "icon=%p/%s row=%p/%s displayed=%p/%s displayedSHA256=%s "
        "desiredID=%p/%s displayedID=%p/%s identityEqual=%d "
        "displayLayer=%d shouldLayer=%d canUpdate=%d updating=%d delayed=%d "
        "carrierHidden=%d carrierAlpha=%.3f placeholder=%p/%s "
        "placeholderLogical=%d placeholderHidden=%d placeholderAlpha=%.3f "
        "contentsLayerView=%p/%s contentsLayer=%p/%s contentsSHA256=%s "
        "alternate=%p/%s alternateSHA256=%s\n",
        event, phase, bundle.UTF8String ?: "-", CNDTracePointer(carrier),
        CNDTraceClassName(carrier), CNDTracePointer(icon),
        CNDTraceClassName(icon), CNDTracePointer(row), CNDTraceClassName(row),
        CNDTracePointer(displayed), CNDTraceClassName(displayed),
        CNDTraceImageHash(displayed).UTF8String ?: "-",
        CNDTracePointer(desiredIdentity), CNDTraceClassName(desiredIdentity),
        CNDTracePointer(displayedIdentity),
        CNDTraceClassName(displayedIdentity),
        desiredIdentity && displayedIdentity &&
            [desiredIdentity isEqual:displayedIdentity],
        CNDTraceBoolGetter(carrier, "isDisplayingImageLayer"),
        CNDTraceBoolGetter(carrier, "shouldDisplayImageLayer"),
        CNDTraceBoolGetter(carrier, "canUpdateImage"),
        CNDTraceBoolGetter(carrier, "isUpdatingImage"),
        CNDTraceBoolGetter(carrier,
                           "delayedImageUpdateDueToContentVisibility"),
        [carrier isKindOfClass:UIView.class] ? ((UIView *)carrier).hidden : -1,
        [carrier isKindOfClass:UIView.class] ? ((UIView *)carrier).alpha : -1.0,
        CNDTracePointer(placeholder), CNDTraceClassName(placeholder),
        CNDTraceBoolGetter(row, "currentIconIsPlaceholder"),
        placeholder ? placeholder.hidden : -1,
        placeholder ? placeholder.alpha : -1.0,
        CNDTracePointer(contentsLayerView), CNDTraceClassName(contentsLayerView),
        CNDTracePointer(contentsLayer), CNDTraceClassName(contentsLayer),
        CNDTraceLayerHash(contentsLayer).UTF8String ?: "-",
        CNDTracePointer(alternate), CNDTraceClassName(alternate),
        CNDTraceLayerHash(alternate).UTF8String ?: "-");
}

static void CNDTraceScheduleState(unsigned event, const char *phase,
                                  id carrier, double seconds)
{
    __weak id weakCarrier = carrier;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(seconds * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        id strongCarrier = weakCarrier;
        if (strongCarrier) CNDTraceLogState(event, phase, strongCarrier);
    });
}

static void CNDTraceUpdateExisting(id self, SEL command, BOOL animated)
{
    if (gCNDTraceDepth++) {
        gCNDOriginalUpdateExisting(self, command, animated);
        gCNDTraceDepth--;
        return;
    }
    id icon = nil;
    id row = nil;
    bool target = CNDTraceTargetCarrier(self, &icon, &row);
    unsigned event = target ? ++gCNDTraceEvent : 0U;
    if (target) {
        CNDTraceLog("[CND_TRANSITION] CALL event=%u selector=%s animated=%d "
                    "carrier=%p/%s icon=%p/%s row=%p/%s\n", event,
                    sel_getName(command), animated, CNDTracePointer(self),
                    CNDTraceClassName(self), CNDTracePointer(icon),
                    CNDTraceClassName(icon), CNDTracePointer(row),
                    CNDTraceClassName(row));
        CNDTraceLogState(event, "updateExisting-before", self);
        CNDTraceLogStack(event);
    }
    gCNDOriginalUpdateExisting(self, command, animated);
    if (target) {
        CNDTraceLogState(event, "updateExisting-return", self);
        CNDTraceScheduleState(event, "updateExisting-after-10ms", self, 0.01);
        CNDTraceScheduleState(event, "updateExisting-after-50ms", self, 0.05);
        CNDTraceScheduleState(event, "updateExisting-after-250ms", self, 0.25);
        CNDTraceScheduleState(event, "updateExisting-after-1s", self, 1.0);
    }
    gCNDTraceDepth--;
}

static void CNDTraceRowUpdate(id self, SEL command, BOOL animated)
{
    unsigned event = ++gCNDTraceEvent;
    id icon = CNDTraceApplicationIcon(self);
    NSString *bundle = CNDTraceBundleIdentifier(icon);
    id carrier = CNDTraceRowCarrier(self);
    CNDTraceLog("[CND_TRANSITION] ROW_CALL event=%u selector=%s animated=%d "
                "row=%p/%s icon=%p/%s carrier=%p/%s bundle=%s\n", event,
                sel_getName(command),
                animated, CNDTracePointer(self), CNDTraceClassName(self),
                CNDTracePointer(icon), CNDTraceClassName(icon),
                CNDTracePointer(carrier), CNDTraceClassName(carrier),
                bundle.UTF8String ?: "-");
    if ([bundle isEqualToString:@CND_TRACE_TARGET_BUNDLE] && carrier) {
        CNDTraceLogState(event, "rowUpdate-before", carrier);
        CNDTraceLogStack(event);
    }
    gCNDOriginalRowUpdate(self, command, animated);
    CNDTraceLog("[CND_TRANSITION] ROW_RETURN event=%u selector=%s\n",
                event, sel_getName(command));
    if ([bundle isEqualToString:@CND_TRACE_TARGET_BUNDLE] && carrier) {
        CNDTraceLogState(event, "rowUpdate-return", carrier);
    }
}

static void CNDTraceRowCallback(id self, SEL command, id imageView, id icon)
{
    NSString *bundle = CNDTraceBundleIdentifier(icon);
    bool target = [bundle isEqualToString:@CND_TRACE_TARGET_BUNDLE];
    unsigned event = target ? ++gCNDTraceEvent : 0U;
    if (target) {
        CNDTraceLog("[CND_TRANSITION] CALLBACK event=%u selector=%s row=%p/%s "
                    "imageView=%p/%s icon=%p/%s\n", event,
                    sel_getName(command), CNDTracePointer(self),
                    CNDTraceClassName(self), CNDTracePointer(imageView),
                    CNDTraceClassName(imageView), CNDTracePointer(icon),
                    CNDTraceClassName(icon));
        CNDTraceLogState(event, "callback-before", imageView);
    }
    gCNDOriginalRowCallback(self, command, imageView, icon);
    if (target) CNDTraceLogState(event, "callback-return", imageView);
}

static void CNDTraceImageUpdate(id self, SEL command, id image,
                                id appearance, BOOL animated,
                                BOOL clearDisplayedLayer)
{
    bool target = CNDTraceTargetCarrier(self, NULL, NULL);
    unsigned event = target ? ++gCNDTraceEvent : 0U;
    if (target) {
        CNDTraceLog("[CND_TRANSITION] IMAGE_CALL event=%u selector=%s "
                    "image=%p/%s imageSHA256=%s appearance=%p/%s "
                    "animated=%d clearDisplayedLayer=%d\n", event,
                    sel_getName(command), CNDTracePointer(image),
                    CNDTraceClassName(image),
                    CNDTraceImageHash(image).UTF8String ?: "-",
                    CNDTracePointer(appearance), CNDTraceClassName(appearance),
                    animated, clearDisplayedLayer);
        CNDTraceLogState(event, "imageUpdate-before", self);
    }
    gCNDOriginalImageUpdate(self, command, image, appearance, animated,
                            clearDisplayedLayer);
    if (target) CNDTraceLogState(event, "imageUpdate-return", self);
}

static id CNDTraceImageForDescriptor(id self, SEL command, id descriptor)
{
    bool target = CNDTraceIconTargetsBundle(self);
    unsigned event = target ? ++gCNDTraceEvent : 0U;
    if (target) {
        CNDTraceLog("[CND_TRANSITION] ICONSERVICES_CALL event=%u selector=%s\n",
                    event, sel_getName(command));
        CNDTraceLogDescriptor(event, self, descriptor,
                              "imageForDescriptor-before");
        CNDTraceLogStack(event);
    }
    id result = gCNDOriginalImageForDescriptor(self, command, descriptor);
    if (target) {
        CNDTraceLog("[CND_TRANSITION] ICONSERVICES_RETURN event=%u "
                    "selector=%s result=%p/%s\n", event,
                    sel_getName(command), CNDTracePointer(result),
                    CNDTraceClassName(result));
        __strong id retainedResult = result;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)(0.01 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            CNDTraceLogIconServicesResult(event, retainedResult);
        });
    }
    return result;
}

static id CNDTracePrepareObject(id self, SEL command, id descriptor)
{
    bool target = CNDTraceIconTargetsBundle(self);
    unsigned event = target ? ++gCNDTraceEvent : 0U;
    if (target) CNDTraceLogDescriptor(event, self, descriptor,
                                      "prepare-object-before");
    id result = gCNDOriginalPrepareObject(self, command, descriptor);
    if (target) {
        CNDTraceLog("[CND_TRANSITION] PREPARE_RETURN event=%u selector=%s "
                    "result=%p/%s\n", event, sel_getName(command),
                    CNDTracePointer(result), CNDTraceClassName(result));
    }
    return result;
}

static void CNDTracePrepareVoid(id self, SEL command, id descriptor)
{
    bool target = CNDTraceIconTargetsBundle(self);
    unsigned event = target ? ++gCNDTraceEvent : 0U;
    if (target) CNDTraceLogDescriptor(event, self, descriptor,
                                      "prepare-void-before");
    gCNDOriginalPrepareVoid(self, command, descriptor);
    if (target) {
        CNDTraceLog("[CND_TRANSITION] PREPARE_RETURN event=%u selector=%s "
                    "return=void\n", event, sel_getName(command));
    }
}

static bool CNDTraceInstallHook(const char *className,
                                const char *selectorName,
                                IMP replacement, IMP *original,
                                const char *exactTypes)
{
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    bool accepted = method && types && !strcmp(types, exactTypes);
    CNDTraceLog("[CND_TRANSITION] hook-check class=%s selector=%s types=%s "
                "expected=%s accepted=%d\n", className, selectorName,
                types ?: "-", exactTypes, accepted);
    if (!accepted) return false;
    IMP previous = method_getImplementation(method);
    if (!class_addMethod(cls, selector, replacement, types)) {
        method_setImplementation(method, replacement);
    }
    *original = previous;
    CNDTraceLog("[CND_TRANSITION] hook-installed class=%s selector=%s "
                "original=%p replacement=%p\n", className, selectorName,
                previous, replacement);
    return true;
}

static bool CNDTraceInstallMakeLayerHook(void)
{
    const char *className = "SBLeafIcon";
    const char *selectorName =
        "makeIconLayerWithInfo:traitCollection:context:options:";
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    const char *expected =
        "@72@0:8{SBIconImageInfo={CGSize=dd}dd}16@48@56Q64";
    bool accepted = method && types && !strcmp(types, expected);
    CNDTraceLog("[CND_TRANSITION] boundary-hook-check class=%s "
                "selector=%s types=%s expected=%s accepted=%d\n", className,
                selectorName, types ?: "-", expected, accepted);
    if (!accepted) return false;
    IMP previous = method_getImplementation(method);
    if (!class_addMethod(cls, selector, (IMP)CNDTraceMakeIconLayer, types)) {
        method_setImplementation(method, (IMP)CNDTraceMakeIconLayer);
    }
    gCNDOriginalMakeLayer = (CNDTraceMakeLayerIMP)previous;
    CNDTraceLog("[CND_TRANSITION] boundary-hook-installed class=%s "
                "selector=%s original=%p replacement=%p\n", className,
                selectorName, previous, (IMP)CNDTraceMakeIconLayer);
    return true;
}

static bool CNDTraceInstallPrepareHook(void)
{
    const char *className = "ISConcreteIcon";
    const char *selectorName = "prepareImageForDescriptor:";
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    IMP replacement = NULL;
    IMP *original = NULL;
    if (types && !strcmp(types, "@24@0:8@16")) {
        replacement = (IMP)CNDTracePrepareObject;
        original = (IMP *)&gCNDOriginalPrepareObject;
    } else if (types && !strcmp(types, "v24@0:8@16")) {
        replacement = (IMP)CNDTracePrepareVoid;
        original = (IMP *)&gCNDOriginalPrepareVoid;
    }
    CNDTraceLog("[CND_TRANSITION] hook-check class=%s selector=%s types=%s "
                "expected=@24-or-v24 accepted=%d\n", className,
                selectorName, types ?: "-", replacement != NULL);
    if (!method || !replacement || !original) return false;
    IMP previous = method_getImplementation(method);
    if (!class_addMethod(cls, selector, replacement, types)) {
        method_setImplementation(method, replacement);
    }
    *original = previous;
    CNDTraceLog("[CND_TRANSITION] hook-installed class=%s selector=%s "
                "original=%p replacement=%p\n", className, selectorName,
                previous, replacement);
    return true;
}

static NSArray *CNDTraceCollectionItems(id collection, NSUInteger cap)
{
    if ([collection isKindOfClass:NSArray.class]) {
        NSArray *array = collection;
        return array.count > cap
            ? [array subarrayWithRange:NSMakeRange(0U, cap)] : array;
    }
    id allObjects = CNDTraceObjectGetter(collection, "allObjects");
    if ([allObjects isKindOfClass:NSArray.class]) {
        NSArray *array = allObjects;
        return array.count > cap
            ? [array subarrayWithRange:NSMakeRange(0U, cap)] : array;
    }
    return @[];
}

static NSArray<UIWindow *> *CNDTraceWindows(void)
{
    UIApplication *application = UIApplication.sharedApplication;
    NSMutableArray<UIWindow *> *windows = [NSMutableArray array];
    id scenes = CNDTraceObjectGetter(application, "connectedScenes");
    for (id scene in CNDTraceCollectionItems(scenes, 16U)) {
        id sceneWindows = CNDTraceObjectGetter(scene, "windows");
        for (id window in CNDTraceCollectionItems(sceneWindows, 32U)) {
            if ([window isKindOfClass:UIWindow.class] &&
                ![windows containsObject:window]) [windows addObject:window];
        }
    }
    id legacy = CNDTraceObjectGetter(application, "windows");
    for (id window in CNDTraceCollectionItems(legacy, 32U)) {
        if ([window isKindOfClass:UIWindow.class] &&
            ![windows containsObject:window]) [windows addObject:window];
    }
    return windows;
}

static NSArray<UIView *> *CNDTraceViewsOfClass(Class wantedClass)
{
    if (!wantedClass) return @[];
    NSMutableArray<UIView *> *matches = [NSMutableArray array];
    NSMutableArray<UIView *> *pending = [NSMutableArray array];
    [pending addObjectsFromArray:CNDTraceWindows()];
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

static void CNDTraceScheduleProvoke(void);

static void CNDTraceProvoke(void)
{
    if (gCNDTraceProvoked) return;
    gCNDTraceProvokeAttempt++;
    Class rowClass = NSClassFromString(@"SearchUIHomeScreenAppIconView");
    NSMutableArray<UIView *> *targets = [NSMutableArray array];
    for (UIView *row in CNDTraceViewsOfClass(rowClass)) {
        id icon = CNDTraceApplicationIcon(row);
        NSString *bundle = CNDTraceBundleIdentifier(icon);
        if (row.window && !row.hidden && row.alpha > 0.01 &&
            [bundle isEqualToString:@CND_TRACE_TARGET_BUNDLE]) {
            [targets addObject:row];
        }
    }
    CNDTraceLog("[CND_TRANSITION] provoke-scan attempt=%u visibleTargets=%lu\n",
                gCNDTraceProvokeAttempt, (unsigned long)targets.count);
    if (targets.count != 1U) {
        if (gCNDTraceProvokeAttempt < 30U) CNDTraceScheduleProvoke();
        else CNDTraceLog("[CND_TRANSITION] PROVOKE_FAILED reason=target-row\n");
        return;
    }
    id row = targets.firstObject;
    id carrier = CNDTraceRowCarrier(row);
    Method method = CNDTraceMethod(row, "_updateIconImageViewAnimated:", 3U);
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (!method || !types || strcmp(types, "v20@0:8B16") != 0) {
        CNDTraceLog("[CND_TRANSITION] PROVOKE_FAILED reason=abi types=%s\n",
                    types ?: "-");
        return;
    }
    gCNDTraceProvoked = true;
    CNDTraceLog("[CND_TRANSITION] PROVOKE row=%p/%s carrier=%p/%s "
                "selector=_updateIconImageViewAnimated: animated=0\n",
                CNDTracePointer(row), CNDTraceClassName(row),
                CNDTracePointer(carrier), CNDTraceClassName(carrier));
    if (carrier) CNDTraceLogState(++gCNDTraceEvent, "provoke-before", carrier);
    ((void (*)(id, SEL, BOOL))objc_msgSend)(
        row, sel_registerName("_updateIconImageViewAnimated:"), NO);
    if (carrier) {
        CNDTraceLogState(gCNDTraceEvent, "provoke-return", carrier);
        CNDTraceScheduleState(gCNDTraceEvent, "provoke-after-1s", carrier, 1.0);
    }
    CNDTraceLog("[CND_TRANSITION] PROVOKE_COMPLETE calls=1\n");
}

static void CNDTraceScheduleProvoke(void)
{
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        CNDTraceProvoke();
    });
}

static void CNDTraceInstallHooks(void)
{
    unsigned installed = 0U;
    installed += CNDTraceInstallHook(
        "SBIconView", "setPrefersFlatImageLayers:",
        (IMP)CNDTraceIconViewSetPrefersFlat,
        (IMP *)&gCNDOriginalIconViewSetPrefersFlat, "v20@0:8B16");
    installed += CNDTraceInstallHook(
        "SBIconImageView", "setPrefersFlatImageLayers:",
        (IMP)CNDTraceImageViewSetPrefersFlat,
        (IMP *)&gCNDOriginalImageViewSetPrefersFlat, "v20@0:8B16");
    installed += CNDTraceInstallHook(
        "SBIconView", "setShowsSquareCorners:",
        (IMP)CNDTraceIconViewSetShowsSquare,
        (IMP *)&gCNDOriginalIconViewSetShowsSquare, "v20@0:8B16");
    installed += CNDTraceInstallHook(
        "SBIconImageView", "setShowsSquareCorners:",
        (IMP)CNDTraceImageViewSetShowsSquare,
        (IMP *)&gCNDOriginalImageViewSetShowsSquare, "v20@0:8B16");
    installed += CNDTraceInstallHook(
        "SBIconImageView", "effectivelyPrefersFlatImageLayers",
        (IMP)CNDTraceEffectivelyPrefersFlat,
        (IMP *)&gCNDOriginalEffectivelyPrefersFlat, "B16@0:8");
    installed += CNDTraceInstallHook(
        "SBIconImageView", "updateExistingIconLayerAnimated:",
        (IMP)CNDTraceUpdateExisting, (IMP *)&gCNDOriginalUpdateExisting,
        "v20@0:8B16");
    installed += CNDTraceInstallHook(
        "SBIconImageView",
        "updateImageContentsWithImage:imageAppearance:animated:"
        "shouldClearDisplayedLayer:",
        (IMP)CNDTraceImageUpdate, (IMP *)&gCNDOriginalImageUpdate,
        "v40@0:8@16@24B32B36");
    installed += CNDTraceInstallHook(
        "SearchUIHomeScreenAppIconView", "_updateIconImageViewAnimated:",
        (IMP)CNDTraceRowUpdate, (IMP *)&gCNDOriginalRowUpdate,
        "v20@0:8B16");
    installed += CNDTraceInstallHook(
        "SearchUIHomeScreenAppIconView",
        "iconImageViewDidChangeContents:forIcon:",
        (IMP)CNDTraceRowCallback, (IMP *)&gCNDOriginalRowCallback,
        "v32@0:8@16@24");
    installed += CNDTraceInstallHook(
        "ISConcreteIcon", "imageForDescriptor:",
        (IMP)CNDTraceImageForDescriptor,
        (IMP *)&gCNDOriginalImageForDescriptor, "@24@0:8@16");
    installed += CNDTraceInstallPrepareHook();
    bool boundaryInstalled = CNDTraceInstallMakeLayerHook();
    installed += boundaryInstalled;
    CNDTraceLog("[CND_TRANSITION] TRACE_READY pid=%d installed=%u target=%s "
                "mode=trace-plus-one-stock-refresh hooks=12 boundary=%d "
                "themedPresentationCalls=0 storeWrites=0 "
                "bundleWrites=0\n", getpid(), installed,
                CND_TRACE_TARGET_BUNDLE, boundaryInstalled);
    CNDTraceScheduleProvoke();
}

static void *CNDTraceBootstrap(void *context)
{
    (void)context;
    @autoreleasepool {
        usleep(250000);
        dispatch_async(dispatch_get_main_queue(), ^{
            CNDTraceInstallHooks();
        });
    }
    return NULL;
}

__attribute__((constructor))
static void CNDTraceStart(void)
{
    gCNDTraceFD = open(CNDTraceOutputPath,
                       O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CNDTraceLog("[CND_TRANSITION] START pid=%d target=%s\n", getpid(),
                CND_TRACE_TARGET_BUNDLE);
    pthread_t thread = 0;
    int result = pthread_create(&thread, NULL, CNDTraceBootstrap, NULL);
    if (result == 0) {
        (void)pthread_detach(thread);
    } else {
        CNDTraceLog("[CND_TRANSITION] FAILED bootstrap-thread=%d\n", result);
    }
}
