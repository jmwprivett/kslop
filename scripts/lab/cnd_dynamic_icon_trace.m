#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>

#import <dlfcn.h>
#import <fcntl.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdatomic.h>
#import <stdbool.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <time.h>
#import <unistd.h>

#ifndef CND_DYNAMIC_TRACE_OUTPUT_TOKEN
#define CND_DYNAMIC_TRACE_OUTPUT_TOKEN ""
#endif

#ifndef CND_DYNAMIC_TRACE_OUTPUT_PATH
#define CND_DYNAMIC_TRACE_OUTPUT_PATH \
    "/var/tmp/cyanide-dynamic-icon-trace.log"
#endif

#ifndef CND_DYNAMIC_TRACE_INVENTORY_ONLY
#define CND_DYNAMIC_TRACE_INVENTORY_ONLY 0
#endif

#ifndef CND_DYNAMIC_TRACE_CLOCK_LEAF_PROBE
#define CND_DYNAMIC_TRACE_CLOCK_LEAF_PROBE 0
#endif

/*
 * VM-only Clock/Calendar lifecycle tracer.
 *
 * Deliberately no UIApplication window lookup, recursive subview walk, or
 * installed-icon enumeration exists in this probe. It instruments only the
 * known Clock/Calendar owners and the IconServices objects they return.
 * Callbacks are passive unless the focused, one-shot Clock leaf probe is
 * explicitly enabled at build time.
 */

typedef enum {
    CNDHookABINone = 0,
    CNDHookABIVoid0,
    CNDHookABIVoidObject,
    CNDHookABIVoidObjectObject,
    CNDHookABIVoidBool,
    CNDHookABIVoidBoolBool,
    CNDHookABIObject0,
    CNDHookABIObjectObject,
    CNDHookABIObjectObjectObjectObject,
    CNDHookABIObjectObjectObjectInteger,
    CNDHookABIObjectImageInfo,
    CNDHookABIObjectImageInfoObjectOptions,
    CNDHookABIObjectImageInfoObjectObjectOptions,
} CNDHookABI;

typedef struct {
    CGSize size;
    CGFloat scale;
    CGFloat continuousCornerRadius;
} CNDIconImageInfo;

typedef struct {
    Class targetClass;
    SEL selector;
    IMP original;
    CNDHookABI abi;
    const char *className;
    const char *selectorName;
} CNDHook;

enum { CND_HOOK_CAP = 160 };
enum { CND_SOURCE_CAP = 24, CND_SOURCE_EVENT_CAP = 2048 };
static CNDHook gCNDHooks[CND_HOOK_CAP];
static unsigned gCNDHookCount;
static int gCNDTraceFD = -1;
static _Atomic uint64_t gCNDSequence;
static __thread unsigned gCNDHookDepth;
static _Atomic uintptr_t gCNDClockLeaves[CND_SOURCE_CAP];
static _Atomic uintptr_t gCNDClockISIcons[CND_SOURCE_CAP];
static _Atomic uintptr_t gCNDCalendarISIcons[CND_SOURCE_CAP];
static _Atomic uintptr_t gCNDClockImageCaches[CND_SOURCE_CAP];
static _Atomic uintptr_t gCNDCalendarImageCaches[CND_SOURCE_CAP];
static _Atomic unsigned gCNDClockLeafCount;
static _Atomic unsigned gCNDClockISIconCount;
static _Atomic unsigned gCNDCalendarISIconCount;
static _Atomic unsigned gCNDClockImageCacheCount;
static _Atomic unsigned gCNDCalendarImageCacheCount;
static _Atomic unsigned gCNDSourceEvents;
#if CND_DYNAMIC_TRACE_CLOCK_LEAF_PROBE
static _Atomic bool gCNDClockLeafProbeScheduled;
#endif
static __thread uint64_t gCNDRootSequence;
static __thread bool gCNDSourceLogging;
static __thread bool gCNDClockSourceScope;

static void CNDLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDLog(const char *format, ...)
{
    if (gCNDTraceFD < 0) return;
    char line[8192] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDTraceFD, line, amount);
}

static uint64_t CNDNowUS(void)
{
    struct timespec value = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000000ULL +
        (uint64_t)value.tv_nsec / 1000ULL;
}

static uint64_t CNDActiveRoot(void)
{
    return gCNDHookDepth ? gCNDRootSequence : 0U;
}

static const char *CNDSkipQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type ?: "";
}

static bool CNDClassIsOrInherits(Class actual, Class target)
{
    for (Class cursor = actual; cursor; cursor = class_getSuperclass(cursor)) {
        if (cursor == target) return true;
    }
    return false;
}

static CNDHook *CNDLookupHook(id object, SEL selector)
{
    Class actual = object ? object_getClass(object) : Nil;
    for (Class cursor = actual; cursor; cursor = class_getSuperclass(cursor)) {
        for (unsigned index = 0; index < gCNDHookCount; index++) {
            CNDHook *hook = &gCNDHooks[index];
            if (hook->selector == selector && hook->targetClass == cursor) {
                return hook;
            }
        }
    }
    for (unsigned index = 0; index < gCNDHookCount; index++) {
        CNDHook *hook = &gCNDHooks[index];
        if (hook->selector == selector &&
            CNDClassIsOrInherits(actual, hook->targetClass)) {
            return hook;
        }
    }
    return NULL;
}

static id CNDSafeObjectGetter(id object, const char *selectorName)
{
    if (!object || !selectorName) return nil;
    SEL selector = sel_registerName(selectorName);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *copy = method_copyReturnType(method);
    const char *type = CNDSkipQualifiers(copy);
    bool valid = type && (*type == '@' || *type == '#');
    free(copy);
    if (!valid) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static id CNDObjectIvar(id object, const char *name)
{
    if (!object || !name) return nil;
    for (Class cursor = object_getClass(object); cursor;
         cursor = class_getSuperclass(cursor)) {
        Ivar ivar = class_getInstanceVariable(cursor, name);
        if (!ivar) continue;
        const char *type = CNDSkipQualifiers(ivar_getTypeEncoding(ivar));
        if (!type || *type != '@') return nil;
        @try {
            return object_getIvar(object, ivar);
        } @catch (__unused NSException *exception) {
            return nil;
        }
    }
    return nil;
}

static const char *CNDClassName(id object)
{
    return object ? class_getName(object_getClass(object)) : "-";
}

static NSString *CNDShortValue(id object)
{
    if (!object) return @"-";
    if (![object isKindOfClass:NSString.class] &&
        ![object isKindOfClass:NSNumber.class] &&
        ![object isKindOfClass:NSUUID.class] &&
        ![object isKindOfClass:NSDate.class] &&
        ![object isKindOfClass:NSCalendar.class]) {
        return [NSString stringWithFormat:@"<%s:%p>",
                CNDClassName(object), object];
    }
    NSString *value = nil;
    @try { value = [object description]; }
    @catch (__unused NSException *exception) { value = @"<exception>"; }
    value = [[value ?: @"-" stringByReplacingOccurrencesOfString:@"\n"
                                                      withString:@" "]
        stringByReplacingOccurrencesOfString:@"\r" withString:@" "];
    return value.length <= 320U ? value
        : [[value substringToIndex:320U] stringByAppendingString:@"..."];
}

static NSString *CNDShortDescription(id object)
{
    if (!object) return @"-";
    NSString *value = nil;
    @try { value = [object description]; }
    @catch (__unused NSException *exception) { value = @"<exception>"; }
    value = [[value ?: @"-" stringByReplacingOccurrencesOfString:@"\n"
                                                      withString:@" "]
        stringByReplacingOccurrencesOfString:@"\r" withString:@" "];
    return value.length <= 800U ? value
        : [[value substringToIndex:800U] stringByAppendingString:@"..."];
}

static bool CNDRememberPointer(_Atomic uintptr_t *slots,
                               _Atomic unsigned *count, id object)
{
    if (!object) return false;
    uintptr_t address = (uintptr_t)(__bridge void *)object;
    unsigned used = atomic_load_explicit(count, memory_order_acquire);
    for (unsigned index = 0; index < MIN(used, CND_SOURCE_CAP); index++) {
        if (atomic_load_explicit(&slots[index], memory_order_acquire) ==
            address) return false;
    }
    while (used < CND_SOURCE_CAP) {
        if (atomic_compare_exchange_weak_explicit(
                count, &used, used + 1U, memory_order_acq_rel,
                memory_order_acquire)) {
            atomic_store_explicit(&slots[used], address,
                                  memory_order_release);
            return true;
        }
    }
    return false;
}

static bool CNDContainsPointer(_Atomic uintptr_t *slots,
                               _Atomic unsigned *count, id object)
{
    if (!object) return false;
    uintptr_t address = (uintptr_t)(__bridge void *)object;
    unsigned used = atomic_load_explicit(count, memory_order_acquire);
    for (unsigned index = 0; index < MIN(used, CND_SOURCE_CAP); index++) {
        if (atomic_load_explicit(&slots[index], memory_order_acquire) ==
            address) return true;
    }
    return false;
}

static const char *CNDISIconKind(id object)
{
    if (CNDContainsPointer(gCNDClockISIcons, &gCNDClockISIconCount,
                           object)) return "clock";
    if (CNDContainsPointer(gCNDCalendarISIcons, &gCNDCalendarISIconCount,
                           object)) return "calendar";
    if (CNDContainsPointer(gCNDClockImageCaches,
                           &gCNDClockImageCacheCount,
                           object)) return "clock-cache";
    if (CNDContainsPointer(gCNDCalendarImageCaches,
                           &gCNDCalendarImageCacheCount,
                           object)) return "calendar-cache";
    return NULL;
}

static bool CNDIsClockBaseIcon(id icon)
{
    if (!icon) return false;
    id value = CNDSafeObjectGetter(icon, "typeIdentifier");
    if (!value) value = CNDSafeObjectGetter(icon, "type");
    return [value isKindOfClass:NSString.class] &&
        [value isEqualToString:@"com.apple.application-icon.clock.base"];
}

static void CNDDumpSourceIvars(const char *kind, id object)
{
    unsigned shown = 0U;
    for (Class cursor = object_getClass(object); cursor && shown < 32U;
         cursor = class_getSuperclass(cursor)) {
        unsigned count = 0U;
        Ivar *ivars = class_copyIvarList(cursor, &count);
        for (unsigned index = 0; ivars && index < count && shown < 32U;
             index++, shown++) {
            Ivar ivar = ivars[index];
            const char *type = CNDSkipQualifiers(ivar_getTypeEncoding(ivar));
            id value = type && *type == '@' ? object_getIvar(object, ivar) : nil;
            CNDLog("[CND_DYNAMIC] SOURCE_IVAR kind=%s object=%p owner=%s "
                   "name=%s type=%s value=%p/%s detail=%s\n",
                   kind, object, class_getName(cursor) ?: "-",
                   ivar_getName(ivar) ?: "-", type ?: "-", value,
                   CNDClassName(value), CNDShortValue(value).UTF8String);
        }
        free(ivars);
        if (cursor == NSObject.class) break;
    }
}

static void CNDLogSourceIdentity(const char *kind, id object)
{
    if (!object) return;
    id type = CNDSafeObjectGetter(object, "type");
    id digest = CNDSafeObjectGetter(object, "digest");
    id identity = CNDSafeObjectGetter(object, "_identity");
    id date = CNDSafeObjectGetter(object, "date");
    id calendar = CNDSafeObjectGetter(object, "calendar");
    id format = CNDSafeObjectGetter(object, "format");
    id cache = CNDObjectIvar(object, "_imageCache");
    CNDLog("[CND_DYNAMIC] SOURCE root=%llu kind=%s object=%p/%s type=%s "
           "digest=%s identity=%p/%s date=%s calendar=%s format=%s "
           "image-cache=%p/%s description=%s\n",
           (unsigned long long)CNDActiveRoot(),
           kind, object, CNDClassName(object),
           CNDShortValue(type).UTF8String,
           CNDShortValue(digest).UTF8String,
           identity, CNDClassName(identity), CNDShortValue(date).UTF8String,
           CNDShortValue(calendar).UTF8String,
           CNDShortValue(format).UTF8String, cache, CNDClassName(cache),
           CNDShortDescription(object).UTF8String);
    CNDDumpSourceIvars(kind, object);
}

static void CNDTrackClockLeaf(id leaf)
{
    if (!leaf || !CNDRememberPointer(gCNDClockLeaves,
                                     &gCNDClockLeafCount, leaf)) return;
    id source = CNDSafeObjectGetter(leaf, "activeDataSource");
    if (!source) source = CNDObjectIvar(leaf, "_activeDataSource");
    id type = CNDSafeObjectGetter(leaf, "iconTypeIdentifierForImage");
    CNDLog("[CND_DYNAMIC] CLOCK_LEAF root=%llu leaf=%p/%s identifier=%s "
           "type=%s source=%p/%s source-unique=%s\n",
           (unsigned long long)CNDActiveRoot(),
           leaf, CNDClassName(leaf),
           CNDShortValue(CNDSafeObjectGetter(leaf, "leafIdentifier"))
               .UTF8String,
           CNDShortValue(type).UTF8String, source, CNDClassName(source),
           CNDShortValue(CNDSafeObjectGetter(source, "uniqueIdentifier"))
               .UTF8String);
#if CND_DYNAMIC_TRACE_CLOCK_LEAF_PROBE
    bool expected = false;
    if (atomic_compare_exchange_strong_explicit(
            &gCNDClockLeafProbeScheduled, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        dispatch_async(dispatch_get_main_queue(), ^{
        SEL selector = sel_registerName("iconImageWithInfo:");
        Method method = class_getInstanceMethod(
            object_getClass(leaf), selector);
        CNDIconImageInfo info = {
            .size = CGSizeMake(68.0, 68.0),
            .scale = 3.0,
            .continuousCornerRadius = 0.0,
        };
        CNDLog("[CND_DYNAMIC] CLOCK_LEAF_PROBE phase=enter leaf=%p/%s "
               "selector=iconImageWithInfo: geometry=68x68@3 "
               "bounded=1 no-view-enumeration=1 types=%s\n",
               leaf, CNDClassName(leaf),
               method ? method_getTypeEncoding(method) : "-");
        id image = method
            ? ((id (*)(id, SEL, CNDIconImageInfo))objc_msgSend)(
                leaf, selector, info)
            : nil;
        CNDLog("[CND_DYNAMIC] CLOCK_LEAF_PROBE phase=return leaf=%p/%s "
               "image=%p/%s\n", leaf, CNDClassName(leaf), image,
               CNDClassName(image));
        });
    }
#endif
}

static void CNDTrackISIcon(const char *kind, id icon)
{
    if (!icon) return;
    bool added = !strcmp(kind, "clock")
        ? CNDRememberPointer(gCNDClockISIcons, &gCNDClockISIconCount, icon)
        : CNDRememberPointer(gCNDCalendarISIcons,
                             &gCNDCalendarISIconCount, icon);
    if (added) {
        CNDLogSourceIdentity(kind, icon);
    }
    id cache = CNDObjectIvar(icon, "_imageCache");
    if (!cache) cache = CNDSafeObjectGetter(icon, "imageCache");
    if (!cache) return;
    if (!strcmp(kind, "clock")) {
        (void)CNDRememberPointer(gCNDClockImageCaches,
                                 &gCNDClockImageCacheCount, cache);
    } else {
        (void)CNDRememberPointer(gCNDCalendarImageCaches,
                                 &gCNDCalendarImageCacheCount, cache);
    }
}

static CGImageRef CNDExistingCGImage(id object)
{
    if (!object) return NULL;
    if ([object isKindOfClass:UIImage.class]) return [(UIImage *)object CGImage];
    Method method = class_getInstanceMethod(object_getClass(object),
                                            sel_registerName("CGImage"));
    if (!method || method_getNumberOfArguments(method) != 2U) return NULL;
    char *copy = method_copyReturnType(method);
    bool valid = copy && strstr(copy, "CGImage") != NULL &&
        *CNDSkipQualifiers(copy) == '^';
    free(copy);
    if (!valid) return NULL;
    @try {
        return ((CGImageRef (*)(id, SEL))objc_msgSend)(
            object, sel_registerName("CGImage"));
    } @catch (__unused NSException *exception) {
        return NULL;
    }
}

static void CNDLogPixelMetadata(id image, CGImageRef pixels)
{
    id data = CNDSafeObjectGetter(image, "data");
    CNDLog(" bytes=%lu cgimage=%p pixel-size=%zux%zu "
           "alpha=%u bitmap=0x%x bpc=%zu bpp=%zu rowbytes=%zu",
           (unsigned long)([data isKindOfClass:NSData.class]
               ? [data length] : 0U), pixels,
           pixels ? CGImageGetWidth(pixels) : 0U,
           pixels ? CGImageGetHeight(pixels) : 0U,
           pixels ? (unsigned)CGImageGetAlphaInfo(pixels) : 0U,
           pixels ? (unsigned)CGImageGetBitmapInfo(pixels) : 0U,
           pixels ? CGImageGetBitsPerComponent(pixels) : 0U,
           pixels ? CGImageGetBitsPerPixel(pixels) : 0U,
           pixels ? CGImageGetBytesPerRow(pixels) : 0U);
}

static CGImageRef CNDLayerContentsCGImage(CALayer *layer)
{
    id contents = layer.contents;
    if (!contents) return NULL;
    CFTypeRef value = (__bridge CFTypeRef)contents;
    return CFGetTypeID(value) == CGImageGetTypeID()
        ? (CGImageRef)value : NULL;
}

static void CNDLogCalendarProvider(id provider)
{
    id controller = CNDObjectIvar(provider, "_dateTimeController");
    if (!controller) controller = CNDSafeObjectGetter(
        provider, "dateTimeController");
    id date = CNDSafeObjectGetter(controller, "date");
    if (!date) date = CNDSafeObjectGetter(controller, "currentDate");
    if (!date) date = CNDSafeObjectGetter(controller, "effectiveDate");
    id calendar = CNDSafeObjectGetter(controller, "calendar");
    id format = CNDSafeObjectGetter(provider, "format");
    CNDLog("[CND_DYNAMIC] CALENDAR_PROVIDER root=%llu provider=%p/%s "
           "controller=%p/%s date=%s calendar=%s format=%s "
           "prepared=%p/%s\n",
           (unsigned long long)CNDActiveRoot(),
           provider, CNDClassName(provider), controller,
           CNDClassName(controller), CNDShortValue(date).UTF8String,
           CNDShortValue(calendar).UTF8String,
           CNDShortValue(format).UTF8String,
           CNDObjectIvar(provider, "_preparedISIcon"),
           CNDClassName(CNDObjectIvar(provider, "_preparedISIcon")));
}

static bool CNDGetScalar(id object, const char *name, long long *out)
{
    if (!object || !out) return false;
    Method method = class_getInstanceMethod(object_getClass(object),
                                            sel_registerName(name));
    if (!method || method_getNumberOfArguments(method) != 2U) return false;
    char *copy = method_copyReturnType(method);
    const char *type = CNDSkipQualifiers(copy);
    char scalarType = type ? *type : '\0';
    free(copy);
    SEL selector = sel_registerName(name);
    @try {
        switch (scalarType) {
            case 'q': *out = ((long long (*)(id, SEL))objc_msgSend)(
                          object, selector); return true;
            case 'Q': *out = (long long)((unsigned long long (*)(id, SEL))
                          objc_msgSend)(object, selector); return true;
            case 'l': *out = ((long (*)(id, SEL))objc_msgSend)(
                          object, selector); return true;
            case 'L': *out = (long long)((unsigned long (*)(id, SEL))
                          objc_msgSend)(object, selector); return true;
            case 'i': *out = ((int (*)(id, SEL))objc_msgSend)(
                          object, selector); return true;
            case 'I': *out = ((unsigned int (*)(id, SEL))objc_msgSend)(
                          object, selector); return true;
            case 's': *out = ((short (*)(id, SEL))objc_msgSend)(
                          object, selector); return true;
            case 'S': *out = ((unsigned short (*)(id, SEL))objc_msgSend)(
                          object, selector); return true;
            case 'c': *out = ((signed char (*)(id, SEL))objc_msgSend)(
                          object, selector); return true;
            case 'C':
            case 'B': *out = ((unsigned char (*)(id, SEL))objc_msgSend)(
                          object, selector); return true;
            default: return false;
        }
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDGetSize(id object, CGSize *out)
{
    if (!object || !out) return false;
    Method method = class_getInstanceMethod(object_getClass(object),
                                            sel_registerName("size"));
    if (!method || method_getNumberOfArguments(method) != 2U) return false;
    char *copy = method_copyReturnType(method);
    bool valid = copy && strstr(copy, "CGSize") != NULL;
    free(copy);
    if (!valid) return false;
    @try {
        *out = ((CGSize (*)(id, SEL))objc_msgSend)(
            object, sel_registerName("size"));
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDGetScale(id object, double *out)
{
    if (!object || !out) return false;
    Method method = class_getInstanceMethod(object_getClass(object),
                                            sel_registerName("scale"));
    if (!method || method_getNumberOfArguments(method) != 2U) return false;
    char *copy = method_copyReturnType(method);
    bool valid = *CNDSkipQualifiers(copy) == 'd';
    free(copy);
    if (!valid) return false;
    @try {
        *out = ((double (*)(id, SEL))objc_msgSend)(
            object, sel_registerName("scale"));
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static void CNDLogSourceRequest(const char *phase, const char *kind,
                                id icon, id descriptor, id image)
{
    if (!kind) return;
    unsigned event = atomic_fetch_add_explicit(
        &gCNDSourceEvents, 1U, memory_order_relaxed) + 1U;
    if (event > CND_SOURCE_EVENT_CAP) return;
    CGSize size = CGSizeZero;
    double scale = 0.0;
    bool hasSize = CNDGetSize(descriptor, &size);
    bool hasScale = CNDGetScale(descriptor, &scale);
    static const char *const names[] = {
        "appearance", "appearanceVariant", "variantOptions", "badgeOptions",
        "backgroundStyle", "graphicVariant", "specialIconOptions",
        "platformStyle", "ignoreCache", "shouldApplyMask", "drawBorder",
        "drawBadge", "contrast", "vibrancy", "languageDirection",
        "layoutDirection", "assetPlatformHint",
    };
    CNDLog("[CND_DYNAMIC] SOURCE_REQUEST event=%u root=%llu kind=%s phase=%s "
           "icon=%p/%s descriptor=%p/%s geometry=%d/%.3fx%.3f "
           "scale=%d/%.3f digest=%s image=%p/%s image-uuid=%s "
           "icon-digest=%s image-cache=%p/%s descriptor-description=%s",
           event,
           (unsigned long long)CNDActiveRoot(),
           kind, phase, icon, CNDClassName(icon), descriptor,
           CNDClassName(descriptor), hasSize, size.width, size.height,
           hasScale, scale,
           CNDShortValue(CNDSafeObjectGetter(descriptor, "digest"))
               .UTF8String,
           image, CNDClassName(image),
           CNDShortValue(CNDSafeObjectGetter(image, "uuid")).UTF8String,
           CNDShortValue(CNDSafeObjectGetter(icon, "digest")).UTF8String,
           CNDObjectIvar(icon, "_imageCache"),
           CNDClassName(CNDObjectIvar(icon, "_imageCache")),
           CNDShortDescription(descriptor).UTF8String);
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        long long value = 0;
        if (CNDGetScalar(descriptor, names[index], &value)) {
            CNDLog(" %s=%lld", names[index], value);
        }
    }
    if (image) CNDLogPixelMetadata(image, CNDExistingCGImage(image));
    CNDLog("\n");
}

static NSString *CNDIconIdentifier(id icon)
{
    if (!icon) return @"-";
    static const char *const selectors[] = {
        "applicationBundleID", "bundleIdentifier", "uniqueIdentifier",
        "displayName",
    };
    for (size_t index = 0;
         index < sizeof(selectors) / sizeof(selectors[0]); index++) {
        id value = CNDSafeObjectGetter(icon, selectors[index]);
        if ([value isKindOfClass:NSString.class] && [value length]) {
            return value;
        }
    }
    return [NSString stringWithFormat:@"%@:%p",
            NSStringFromClass([icon class]), icon];
}

static id CNDReceiverIcon(id receiver)
{
    id icon = CNDSafeObjectGetter(receiver, "icon");
    if (!icon) icon = CNDObjectIvar(receiver, "_icon");
    if (!icon) icon = CNDSafeObjectGetter(receiver, "clockBackgroundIcon");
    if (!icon) icon = CNDObjectIvar(receiver, "_clockBackgroundIcon");
    if (!icon && [NSStringFromClass([receiver class])
            hasSuffix:@"ApplicationIcon"]) {
        icon = receiver;
    }
    return icon;
}

static void CNDLogImage(const char *label, id value)
{
    UIImage *image = [value isKindOfClass:UIImage.class] ? value : nil;
    CGImageRef pixels = image.CGImage;
    CNDLog(" image-%s=%p/%s points=%.2fx%.2f scale=%.2f pixels=%zux%zu",
           label ?: "?", value,
           value ? class_getName([value class]) : "-",
           image.size.width, image.size.height, image.scale,
           pixels ? CGImageGetWidth(pixels) : 0U,
           pixels ? CGImageGetHeight(pixels) : 0U);
    if (image) CNDLogPixelMetadata(image, pixels);
}

static void CNDLogDirectLayers(id receiver)
{
    if (![receiver isKindOfClass:UIView.class]) return;
    CALayer *root = [(UIView *)receiver layer];
    NSArray<CALayer *> *layers = root.sublayers ?: @[];
    CNDLog(" direct-layers=%lu", (unsigned long)layers.count);
    NSUInteger cap = MIN((NSUInteger)16U, layers.count);
    for (NSUInteger index = 0; index < cap; index++) {
        CALayer *layer = layers[index];
        CGRect frame = layer.frame;
        CNDLog(" layer[%lu]=%p/%s name=%s hidden=%d opacity=%.3f "
               "frame=%.1f,%.1f,%.1f,%.1f contents=%p",
               (unsigned long)index, layer,
               class_getName([layer class]) ?: "-",
               layer.name.UTF8String ?: "-", layer.hidden ? 1 : 0,
               layer.opacity, frame.origin.x, frame.origin.y,
               frame.size.width, frame.size.height,
               (__bridge void *)layer.contents);
        CNDLogPixelMetadata(nil, CNDLayerContentsCGImage(layer));
    }
}

static void CNDLogDirectSubviews(id receiver)
{
    if (![receiver isKindOfClass:UIView.class]) return;
    NSArray<UIView *> *subviews = [(UIView *)receiver subviews] ?: @[];
    CNDLog(" direct-subviews=%lu", (unsigned long)subviews.count);
    NSUInteger cap = MIN((NSUInteger)16U, subviews.count);
    for (NSUInteger index = 0; index < cap; index++) {
        UIView *view = subviews[index];
        CGRect frame = view.frame;
        CNDLog(" subview[%lu]=%p/%s hidden=%d alpha=%.3f "
               "frame=%.1f,%.1f,%.1f,%.1f",
               (unsigned long)index, view,
               class_getName([view class]) ?: "-",
               view.hidden ? 1 : 0, view.alpha,
               frame.origin.x, frame.origin.y,
               frame.size.width, frame.size.height);
        CNDLogPixelMetadata(nil, CNDLayerContentsCGImage(view.layer));
    }
}

static void CNDSnapshot(const char *phase, CNDHook *hook, id receiver)
{
    if (!hook || !receiver) return;
    uint64_t sequence = atomic_fetch_add_explicit(
        &gCNDSequence, 1U, memory_order_relaxed) + 1U;
    if (!strcmp(phase, "enter") && gCNDHookDepth == 1U) {
        gCNDRootSequence = sequence;
    }
    if (CNDClassIsOrInherits(object_getClass(receiver),
                            objc_getClass("SBHClockApplicationIconImageView"))) {
        CNDTrackClockLeaf(CNDSafeObjectGetter(receiver,
                                              "clockBackgroundIcon"));
    }
    if (CNDClassIsOrInherits(object_getClass(receiver),
                            objc_getClass("SBCalendarIconImageProvider"))) {
        CNDTrackISIcon("calendar", CNDObjectIvar(receiver,
                                                  "_preparedISIcon"));
        CNDLogCalendarProvider(receiver);
    }
    id icon = CNDReceiverIcon(receiver);
    id displayed = CNDSafeObjectGetter(receiver, "displayedImage");
    id background = CNDSafeObjectGetter(receiver, "clockBackgroundImage");
    if (!background) background = CNDObjectIvar(receiver, "_clockBackgroundImage");
    UIView *view = [receiver isKindOfClass:UIView.class] ? receiver : nil;
    CGRect bounds = view ? view.bounds : CGRectZero;
    CNDLog("[CND_DYNAMIC] EVENT seq=%llu us=%llu main=%d phase=%s "
           "class=%s receiver=%p selector=%s icon=%p/%s id=%s "
           "window=%p superview=%p bounds=%.1f,%.1f,%.1f,%.1f",
           (unsigned long long)sequence,
           (unsigned long long)CNDNowUS(), pthread_main_np() ? 1 : 0,
           phase ?: "-", class_getName([receiver class]) ?: "-",
           receiver, hook->selectorName ?: "-", icon,
           icon ? class_getName([icon class]) : "-",
           CNDIconIdentifier(icon).UTF8String ?: "-",
           view.window, view.superview,
           bounds.origin.x, bounds.origin.y,
           bounds.size.width, bounds.size.height);
    CNDLogImage("displayed", displayed);
    CNDLogImage("clock-background", background);
    CNDLogDirectLayers(receiver);
    CNDLogDirectSubviews(receiver);
    CNDLog("\n");
}

static void CNDTraceVoid0(id self, SEL selector)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook || !hook->original) return;
    bool outer = gCNDHookDepth++ == 0U;
    if (outer) CNDSnapshot("enter", hook, self);
    ((void (*)(id, SEL))hook->original)(self, selector);
    if (outer) CNDSnapshot("return", hook, self);
    gCNDHookDepth--;
}

static void CNDTraceVoidObject(id self, SEL selector, id object)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook || !hook->original) return;
    bool outer = gCNDHookDepth++ == 0U;
    if (outer) {
        CNDLog("[CND_DYNAMIC] ARG class=%s receiver=%p selector=%s "
               "object=%p/%s\n", class_getName([self class]) ?: "-",
               self, hook->selectorName ?: "-", object,
               object ? class_getName([object class]) : "-");
        CNDSnapshot("enter", hook, self);
    }
    ((void (*)(id, SEL, id))hook->original)(self, selector, object);
    if (outer) CNDSnapshot("return", hook, self);
    gCNDHookDepth--;
}

static void CNDTraceVoidObjectObject(id self, SEL selector,
                                     id first, id second)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook || !hook->original) return;
    bool outer = gCNDHookDepth++ == 0U;
    if (outer) {
        CNDLog("[CND_DYNAMIC] ARG class=%s receiver=%p selector=%s "
               "objects=%p/%s,%p/%s\n",
               class_getName([self class]) ?: "-", self,
               hook->selectorName ?: "-", first,
               first ? class_getName([first class]) : "-", second,
               second ? class_getName([second class]) : "-");
        CNDSnapshot("enter", hook, self);
    }
    ((void (*)(id, SEL, id, id))hook->original)(
        self, selector, first, second);
    if (outer) CNDSnapshot("return", hook, self);
    gCNDHookDepth--;
}

static void CNDTraceVoidBool(id self, SEL selector, BOOL value)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook || !hook->original) return;
    bool outer = gCNDHookDepth++ == 0U;
    if (outer) {
        CNDLog("[CND_DYNAMIC] ARG class=%s receiver=%p selector=%s bool=%d\n",
               class_getName([self class]) ?: "-", self,
               hook->selectorName ?: "-", value ? 1 : 0);
        CNDSnapshot("enter", hook, self);
    }
    ((void (*)(id, SEL, BOOL))hook->original)(self, selector, value);
    if (outer) CNDSnapshot("return", hook, self);
    gCNDHookDepth--;
}

static void CNDTraceVoidBoolBool(id self, SEL selector, BOOL first,
                                 BOOL second)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook || !hook->original) return;
    bool outer = gCNDHookDepth++ == 0U;
    if (outer) {
        CNDLog("[CND_DYNAMIC] ARG class=%s receiver=%p selector=%s "
               "bools=%d,%d\n", class_getName([self class]) ?: "-",
               self, hook->selectorName ?: "-",
               first ? 1 : 0, second ? 1 : 0);
        CNDSnapshot("enter", hook, self);
    }
    ((void (*)(id, SEL, BOOL, BOOL))hook->original)(
        self, selector, first, second);
    if (outer) CNDSnapshot("return", hook, self);
    gCNDHookDepth--;
}

static void CNDLogReturnedObject(CNDHook *hook, id receiver, id result,
                                 CNDIconImageInfo *info)
{
    CNDLog("[CND_DYNAMIC] RESULT root=%llu class=%s receiver=%p selector=%s "
           "object=%p/%s source=%s",
           (unsigned long long)CNDActiveRoot(),
           receiver ? class_getName([receiver class]) : "-", receiver,
           hook && hook->selectorName ? hook->selectorName : "-", result,
           result ? class_getName([result class]) : "-",
           CNDContainsPointer(gCNDClockLeaves, &gCNDClockLeafCount,
                              receiver) ? "clock-background-leaf" : "-");
    if (info) {
        CNDLog(" info=%.2fx%.2f@%.2f radius=%.3f",
               info->size.width, info->size.height, info->scale,
               info->continuousCornerRadius);
    }
    if ([result isKindOfClass:UIImage.class]) {
        CNDLogImage("result", result);
    } else if ([result isKindOfClass:CALayer.class]) {
        CALayer *layer = result;
        CGRect frame = layer.frame;
        CNDLog(" layer-frame=%.1f,%.1f,%.1f,%.1f contents=%p "
               "sublayers=%lu",
               frame.origin.x, frame.origin.y,
               frame.size.width, frame.size.height,
               (__bridge void *)layer.contents,
               (unsigned long)layer.sublayers.count);
        CNDLogPixelMetadata(nil, CNDLayerContentsCGImage(layer));
    } else if (result) {
        CNDLogPixelMetadata(result, CNDExistingCGImage(result));
    }
    CNDLog("\n");
}

static id CNDTraceObject0(id self, SEL selector)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook || !hook->original) return nil;
    bool leafBoundary = !strcmp(hook->selectorName,
                                "iconServicesIconForImage") &&
        !CNDContainsPointer(gCNDClockLeaves, &gCNDClockLeafCount, self);
    bool outer = gCNDHookDepth++ == 0U;
    if (outer && !leafBoundary) CNDSnapshot("enter", hook, self);
    id result = ((id (*)(id, SEL))hook->original)(self, selector);
    if (!strcmp(hook->selectorName, "iconForImage") &&
        CNDClassIsOrInherits(object_getClass(self),
                            objc_getClass("SBHClockApplicationIconImageView"))) {
        CNDTrackClockLeaf(result);
    } else if (!strcmp(hook->selectorName, "iconServicesIconForImage") &&
               CNDContainsPointer(gCNDClockLeaves, &gCNDClockLeafCount,
                                  self)) {
        CNDTrackISIcon("clock", result);
    } else if (!strcmp(hook->selectorName, "preparedISIcon") &&
               CNDClassIsOrInherits(object_getClass(self),
                                   objc_getClass("SBCalendarIconImageProvider"))) {
        CNDTrackISIcon("calendar", result);
    }
    if (outer && !leafBoundary) {
        CNDLogReturnedObject(hook, self, result, NULL);
        CNDSnapshot("return", hook, self);
    }
    gCNDHookDepth--;
    return result;
}

static id CNDTraceObjectObject(id self, SEL selector, id descriptor)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook || !hook->original) return nil;
    bool clockRegistration = !strcmp(hook->selectorName,
                                     "findOrRegisterIcon:") &&
        CNDIsClockBaseIcon(descriptor);
    if (clockRegistration) {
        CNDTrackISIcon("clock", descriptor);
        CNDLog("[CND_DYNAMIC] CLOCK_REGISTER phase=enter manager=%p/%s "
               "input=%p/%s identity=%s\n", self, CNDClassName(self),
               descriptor, CNDClassName(descriptor),
               CNDShortValue(CNDSafeObjectGetter(descriptor, "_identity"))
                   .UTF8String);
    }
    if (gCNDSourceLogging) {
        return ((id (*)(id, SEL, id))hook->original)(
            self, selector, descriptor);
    }
    const char *kind = CNDISIconKind(self);
    if (!kind && gCNDClockSourceScope) {
        gCNDSourceLogging = true;
        CNDTrackISIcon("clock", self);
        gCNDSourceLogging = false;
        kind = CNDISIconKind(self);
    }
    if (kind) {
        gCNDSourceLogging = true;
        CNDLogSourceRequest(hook->selectorName, kind,
                            self, descriptor, nil);
        gCNDSourceLogging = false;
    }
    id result = ((id (*)(id, SEL, id))hook->original)(
        self, selector, descriptor);
    if (clockRegistration) {
        CNDTrackISIcon("clock", result);
        CNDLog("[CND_DYNAMIC] CLOCK_REGISTER phase=return manager=%p/%s "
               "input=%p/%s result=%p/%s same=%d identity=%s\n",
               self, CNDClassName(self), descriptor,
               CNDClassName(descriptor), result, CNDClassName(result),
               result == descriptor ? 1 : 0,
               CNDShortValue(CNDSafeObjectGetter(result, "_identity"))
                   .UTF8String);
    }
    if (kind) {
        char phase[128];
        (void)snprintf(phase, sizeof(phase), "%s-return",
                       hook->selectorName);
        gCNDSourceLogging = true;
        CNDLogSourceRequest(phase, kind, self, descriptor, result);
        gCNDSourceLogging = false;
    }
    return result;
}

static id CNDTraceCalendarInitObjects(id self, SEL selector, id date,
                                      id calendar, id format)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook || !hook->original) return nil;
    id result = ((id (*)(id, SEL, id, id, id))hook->original)(
        self, selector, date, calendar, format);
    CNDLog("[CND_DYNAMIC] CALENDAR_INIT object=%p/%s date=%s "
           "calendar=%s format=%s result=%p/%s\n",
           self, CNDClassName(self), CNDShortValue(date).UTF8String,
           CNDShortValue(calendar).UTF8String,
           CNDShortValue(format).UTF8String, result,
           CNDClassName(result));
    CNDTrackISIcon("calendar", result);
    return result;
}

static id CNDTraceCalendarInitInteger(id self, SEL selector, id date,
                                      id calendar, NSInteger format)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook || !hook->original) return nil;
    id result = ((id (*)(id, SEL, id, id, NSInteger))hook->original)(
        self, selector, date, calendar, format);
    CNDLog("[CND_DYNAMIC] CALENDAR_INIT object=%p/%s date=%s "
           "calendar=%s format=%ld result=%p/%s\n",
           self, CNDClassName(self), CNDShortValue(date).UTF8String,
           CNDShortValue(calendar).UTF8String, (long)format, result,
           CNDClassName(result));
    CNDTrackISIcon("calendar", result);
    return result;
}

static id CNDTraceObjectImageInfo(id self, SEL selector,
                                  CNDIconImageInfo info)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook || !hook->original) return nil;
    bool outer = gCNDHookDepth++ == 0U;
    bool provider = CNDClassIsOrInherits(object_getClass(self),
        objc_getClass("SBCalendarIconImageProvider"));
    if (outer) CNDSnapshot("enter", hook, self);
    id result = ((id (*)(id, SEL, CNDIconImageInfo))hook->original)(
        self, selector, info);
    if (outer || provider) {
        CNDLogReturnedObject(hook, self, result, &info);
        if (outer) CNDSnapshot("return", hook, self);
    }
    gCNDHookDepth--;
    return result;
}

static id CNDTraceObjectImageInfoObjectOptions(
    id self, SEL selector, CNDIconImageInfo info,
    id object, NSUInteger options)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook || !hook->original) return nil;
    bool outer = gCNDHookDepth++ == 0U;
    bool provider = CNDClassIsOrInherits(object_getClass(self),
        objc_getClass("SBCalendarIconImageProvider"));
    if (outer) CNDSnapshot("enter", hook, self);
    id result = ((id (*)(id, SEL, CNDIconImageInfo, id, NSUInteger))
        hook->original)(self, selector, info, object, options);
    if (outer || provider) {
        CNDLog("[CND_DYNAMIC] IMAGE_OPTIONS class=%s receiver=%p "
               "selector=%s trait=%p/%s options=%lu\n",
               CNDClassName(self), self, hook->selectorName, object,
               CNDClassName(object), (unsigned long)options);
        CNDLogReturnedObject(hook, self, result, &info);
        if (outer) CNDSnapshot("return", hook, self);
    }
    gCNDHookDepth--;
    return result;
}

static id CNDTraceObjectImageInfoObjectObjectOptions(
    id self, SEL selector, CNDIconImageInfo info,
    id first, id second, NSUInteger options)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook || !hook->original) return nil;
    bool outer = gCNDHookDepth++ == 0U;
    bool clockLeaf = CNDContainsPointer(gCNDClockLeaves,
                                        &gCNDClockLeafCount, self);
    bool trace = clockLeaf ||
        (outer && hook->targetClass != objc_getClass("SBLeafIcon"));
    if (trace && outer) CNDSnapshot("enter", hook, self);
    bool previousClockScope = gCNDClockSourceScope;
    if (clockLeaf) gCNDClockSourceScope = true;
    id result = nil;
    @try {
        result = ((id (*)(id, SEL, CNDIconImageInfo, id, id, NSUInteger))
            hook->original)(self, selector, info, first, second, options);
    } @finally {
        gCNDClockSourceScope = previousClockScope;
    }
    if (trace) {
        CNDLogReturnedObject(hook, self, result, &info);
        if (outer) CNDSnapshot("return", hook, self);
    }
    gCNDHookDepth--;
    return result;
}

static bool CNDTypeIsObject(const char *type)
{
    type = CNDSkipQualifiers(type);
    return type && (*type == '@' || *type == '#');
}

static bool CNDTypeIsImageInfo(const char *type)
{
    type = CNDSkipQualifiers(type);
    return type && !strncmp(type, "{SBIconImageInfo=", 17U);
}

static bool CNDTypeIsInteger(const char *type)
{
    type = CNDSkipQualifiers(type);
    return type && strchr("qQiIlLsS", *type);
}

static CNDHookABI CNDMethodABI(Method method)
{
    if (!method) return CNDHookABINone;
    char *returnCopy = method_copyReturnType(method);
    const char *returnType = CNDSkipQualifiers(returnCopy);
    bool returnsVoid = returnType && *returnType == 'v';
    bool returnsObject = CNDTypeIsObject(returnType);
    free(returnCopy);

    unsigned arguments = method_getNumberOfArguments(method);
    if (returnsObject && arguments == 2U) return CNDHookABIObject0;
    if (returnsObject && arguments == 3U) {
        char *argumentCopy = method_copyArgumentType(method, 2U);
        bool valid = CNDTypeIsObject(argumentCopy);
        free(argumentCopy);
        if (valid) return CNDHookABIObjectObject;
    }
    if (returnsObject && arguments == 5U) {
        char *firstCopy = method_copyArgumentType(method, 2U);
        char *secondCopy = method_copyArgumentType(method, 3U);
        char *thirdCopy = method_copyArgumentType(method, 4U);
        bool firstTwo = CNDTypeIsObject(firstCopy) &&
            CNDTypeIsObject(secondCopy);
        CNDHookABI abi = firstTwo && CNDTypeIsObject(thirdCopy)
            ? CNDHookABIObjectObjectObjectObject
            : (firstTwo && CNDTypeIsInteger(thirdCopy)
                ? CNDHookABIObjectObjectObjectInteger : CNDHookABINone);
        free(firstCopy);
        free(secondCopy);
        free(thirdCopy);
        if (abi != CNDHookABINone) return abi;
    }
    if (returnsObject && arguments >= 3U && arguments <= 6U) {
        char *infoCopy = method_copyArgumentType(method, 2U);
        bool imageInfo = CNDTypeIsImageInfo(infoCopy);
        free(infoCopy);
        if (!imageInfo) return CNDHookABINone;
        if (arguments == 3U) return CNDHookABIObjectImageInfo;
        if (arguments == 5U) {
            char *objectCopy = method_copyArgumentType(method, 3U);
            char *optionsCopy = method_copyArgumentType(method, 4U);
            bool valid = CNDTypeIsObject(objectCopy) &&
                CNDTypeIsInteger(optionsCopy);
            free(objectCopy);
            free(optionsCopy);
            return valid ? CNDHookABIObjectImageInfoObjectOptions
                         : CNDHookABINone;
        }
        if (arguments == 6U) {
            char *firstCopy = method_copyArgumentType(method, 3U);
            char *secondCopy = method_copyArgumentType(method, 4U);
            char *optionsCopy = method_copyArgumentType(method, 5U);
            bool valid = CNDTypeIsObject(firstCopy) &&
                CNDTypeIsObject(secondCopy) &&
                CNDTypeIsInteger(optionsCopy);
            free(firstCopy);
            free(secondCopy);
            free(optionsCopy);
            return valid
                ? CNDHookABIObjectImageInfoObjectObjectOptions
                : CNDHookABINone;
        }
        return CNDHookABINone;
    }
    if (!returnsVoid) return CNDHookABINone;
    if (arguments == 2U) return CNDHookABIVoid0;
    if (arguments == 3U) {
        char *argumentCopy = method_copyArgumentType(method, 2U);
        const char *argument = CNDSkipQualifiers(argumentCopy);
        CNDHookABI abi = argument && (*argument == '@' || *argument == '#')
            ? CNDHookABIVoidObject
            : (argument && strchr("BcC", *argument)
                ? CNDHookABIVoidBool : CNDHookABINone);
        free(argumentCopy);
        return abi;
    }
    if (arguments == 4U) {
        char *firstCopy = method_copyArgumentType(method, 2U);
        char *secondCopy = method_copyArgumentType(method, 3U);
        const char *first = CNDSkipQualifiers(firstCopy);
        const char *second = CNDSkipQualifiers(secondCopy);
        bool objects = CNDTypeIsObject(first) && CNDTypeIsObject(second);
        bool booleans = first && second &&
            strchr("BcC", *first) && strchr("BcC", *second);
        free(firstCopy);
        free(secondCopy);
        return objects ? CNDHookABIVoidObjectObject
            : (booleans ? CNDHookABIVoidBoolBool : CNDHookABINone);
    }
    return CNDHookABINone;
}

static IMP CNDReplacementForABI(CNDHookABI abi)
{
    switch (abi) {
        case CNDHookABIVoid0: return (IMP)CNDTraceVoid0;
        case CNDHookABIVoidObject: return (IMP)CNDTraceVoidObject;
        case CNDHookABIVoidObjectObject:
            return (IMP)CNDTraceVoidObjectObject;
        case CNDHookABIVoidBool: return (IMP)CNDTraceVoidBool;
        case CNDHookABIVoidBoolBool: return (IMP)CNDTraceVoidBoolBool;
        case CNDHookABIObject0: return (IMP)CNDTraceObject0;
        case CNDHookABIObjectObject: return (IMP)CNDTraceObjectObject;
        case CNDHookABIObjectObjectObjectObject:
            return (IMP)CNDTraceCalendarInitObjects;
        case CNDHookABIObjectObjectObjectInteger:
            return (IMP)CNDTraceCalendarInitInteger;
        case CNDHookABIObjectImageInfo:
            return (IMP)CNDTraceObjectImageInfo;
        case CNDHookABIObjectImageInfoObjectOptions:
            return (IMP)CNDTraceObjectImageInfoObjectOptions;
        case CNDHookABIObjectImageInfoObjectObjectOptions:
            return (IMP)CNDTraceObjectImageInfoObjectObjectOptions;
        case CNDHookABINone:
        default: return NULL;
    }
}

static IMP CNDOriginalBelowInstalledWrapper(Class cls, SEL selector,
                                             IMP replacement)
{
    for (unsigned index = 0; index < gCNDHookCount; index++) {
        CNDHook *hook = &gCNDHooks[index];
        if (hook->selector != selector || !hook->original ||
            hook->original == replacement) {
            continue;
        }
        if (CNDClassIsOrInherits(cls, hook->targetClass)) {
            return hook->original;
        }
    }
    return NULL;
}

static bool CNDInstallHook(const char *className, const char *selectorName)
{
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    for (unsigned index = 0; index < gCNDHookCount; index++) {
        if (gCNDHooks[index].targetClass == cls &&
            gCNDHooks[index].selector == selector) return true;
    }
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    CNDHookABI abi = CNDMethodABI(method);
    IMP replacement = CNDReplacementForABI(abi);
    if (!cls || !method || !replacement || gCNDHookCount >= CND_HOOK_CAP) {
        CNDLog("[CND_DYNAMIC] HOOK class=%s selector=%s ok=0 "
               "reason=%s types=%s\n", className, selectorName,
               !cls ? "class-missing" : (!method ? "method-missing" :
               (!replacement ? "unsupported-abi" : "capacity")),
               method ? method_getTypeEncoding(method) : "-");
        return false;
    }

    IMP original = method_getImplementation(method);
    if (original == replacement) {
        IMP inheritedOriginal = CNDOriginalBelowInstalledWrapper(
            cls, selector, replacement);
        if (!inheritedOriginal) {
            CNDLog("[CND_DYNAMIC] HOOK class=%s selector=%s ok=0 "
                   "reason=already-wrapped-without-original types=%s\n",
                   className, selectorName,
                   method_getTypeEncoding(method) ?: "-");
            return false;
        }
        original = inheritedOriginal;
    }
    const char *types = method_getTypeEncoding(method);
    CNDHook *hook = &gCNDHooks[gCNDHookCount++];
    *hook = (CNDHook){
        .targetClass = cls,
        .selector = selector,
        .original = original,
        .abi = abi,
        .className = className,
        .selectorName = selectorName,
    };

    bool added = class_addMethod(cls, selector, replacement, types);
    if (!added) {
        Method owned = class_getInstanceMethod(cls, selector);
        (void)method_setImplementation(owned, replacement);
    }
    IMP observed = class_getMethodImplementation(cls, selector);
    bool ok = original && observed == replacement;
    CNDLog("[CND_DYNAMIC] HOOK class=%s selector=%s ok=%d added=%d "
           "abi=%u types=%s original=%p replacement=%p observed=%p\n",
           className, selectorName, ok ? 1 : 0, added ? 1 : 0,
           (unsigned)abi, types ?: "-", original, replacement, observed);
    return ok;
}

static unsigned CNDInstallISIconRequestHooks(void)
{
    Class base = objc_getClass("ISIcon");
    if (!base) return 0U;
    static const char *const selectors[] = {
        "imageForDescriptor:", "imageForImageDescriptor:",
        "_cachedImageForDescriptor:", "_imageFromStoreForDescriptor:",
        "generateImageWithDescriptor:", "_generateImageWithDescriptor:",
    };
    unsigned installed = 0U;
    unsigned classCount = 0U;
    Class *classes = objc_copyClassList(&classCount);
    for (unsigned classIndex = 0; classes && classIndex < classCount;
         classIndex++) {
        Class cls = classes[classIndex];
        if (!CNDClassIsOrInherits(cls, base)) continue;
        unsigned methodCount = 0U;
        Method *methods = class_copyMethodList(cls, &methodCount);
        for (unsigned methodIndex = 0; methods &&
             methodIndex < methodCount; methodIndex++) {
            SEL methodSelector = method_getName(methods[methodIndex]);
            for (size_t selectorIndex = 0;
                 selectorIndex < sizeof(selectors) / sizeof(selectors[0]);
                 selectorIndex++) {
                if (methodSelector != sel_registerName(
                        selectors[selectorIndex])) continue;
                installed += CNDInstallHook(
                    class_getName(cls), selectors[selectorIndex]) ? 1U : 0U;
            }
        }
        free(methods);
    }
    free(classes);
    CNDLog("[CND_DYNAMIC] SOURCE_HOOKS count=%u\n", installed);
    return installed;
}

static unsigned CNDInstallCalendarInitializers(void)
{
    Class base = objc_getClass("ISIcon");
    if (!base) return 0U;
    SEL selector = sel_registerName("initWithDate:calendar:format:");
    unsigned count = 0U;
    unsigned classCount = 0U;
    Class *classes = objc_copyClassList(&classCount);
    for (unsigned index = 0; classes && index < classCount; index++) {
        Class cls = classes[index];
        if (!CNDClassIsOrInherits(cls, base)) continue;
        unsigned methodCount = 0U;
        Method *methods = class_copyMethodList(cls, &methodCount);
        for (unsigned methodIndex = 0; methods &&
             methodIndex < methodCount; methodIndex++) {
            if (method_getName(methods[methodIndex]) != selector) continue;
            if (CNDInstallHook(class_getName(cls),
                               "initWithDate:calendar:format:")) count++;
            break;
        }
        free(methods);
    }
    free(classes);
    CNDLog("[CND_DYNAMIC] CALENDAR_INIT_HOOKS count=%u\n", count);
    return count;
}

static bool CNDRelevantInventoryName(const char *name)
{
    if (!name) return false;
    static const char *const tokens[] = {
        "clock", "Clock", "calendar", "Calendar", "date", "Date",
        "time", "Time", "hand", "Hand", "image", "Image",
        "icon", "Icon", "display", "Display", "update", "Update",
        "layout", "Layout", "window", "Window", "superview", "Superview",
        "background", "Background", "contents", "Contents",
    };
    for (size_t index = 0;
         index < sizeof(tokens) / sizeof(tokens[0]); index++) {
        if (strstr(name, tokens[index])) return true;
    }
    return false;
}

static void CNDDumpClass(const char *name)
{
    Class cls = objc_getClass(name);
    CNDLog("[CND_DYNAMIC] CLASS name=%s loaded=%d address=%p super=%s\n",
           name, cls ? 1 : 0, cls,
           cls && class_getSuperclass(cls)
                ? class_getName(class_getSuperclass(cls)) : "-");
    if (!cls) return;

    for (Class cursor = cls; cursor; cursor = class_getSuperclass(cursor)) {
        unsigned methodCount = 0U;
        Method *methods = class_copyMethodList(cursor, &methodCount);
        for (unsigned index = 0; methods && index < methodCount; index++) {
            SEL selector = method_getName(methods[index]);
            const char *selectorName = selector ? sel_getName(selector) : NULL;
            if (cursor != cls && !CNDRelevantInventoryName(selectorName)) {
                continue;
            }
            CNDLog("[CND_DYNAMIC] METHOD target=%s owner=%s selector=%s "
                   "types=%s imp=%p\n", name, class_getName(cursor) ?: "-",
                   selectorName ?: "-",
                   method_getTypeEncoding(methods[index]) ?: "-",
                   method_getImplementation(methods[index]));
        }
        free(methods);

        unsigned ivarCount = 0U;
        Ivar *ivars = class_copyIvarList(cursor, &ivarCount);
        for (unsigned index = 0; ivars && index < ivarCount; index++) {
            const char *ivarName = ivar_getName(ivars[index]);
            if (cursor != cls && !CNDRelevantInventoryName(ivarName)) continue;
            CNDLog("[CND_DYNAMIC] IVAR target=%s owner=%s name=%s type=%s "
                   "offset=%td\n", name, class_getName(cursor) ?: "-",
                   ivarName ?: "-", ivar_getTypeEncoding(ivars[index]) ?: "-",
                   ivar_getOffset(ivars[index]));
        }
        free(ivars);
        if (!strcmp(class_getName(cursor), "SBIconImageView")) break;
    }
}

static unsigned CNDInstallClassHooks(const char *className)
{
    static const char *const selectors[] = {
        "didMoveToWindow",
        "didMoveToSuperview",
        "layoutSubviews",
        "updateUnanimated",
        "updateAnimated:",
        "updateImageAnimated:",
        "updateImageContentsFromCacheAnimated:",
        "clearCachedImages",
        "iconImageDidUpdate:",
        "setDisplayedImage:",
        "setIcon:",
        "setClockBackgroundIcon:",
        "setHandsHidden:",
        "setHandsHidden:animated:",
        "setDate:",
        "setCalendarIcon:",
        "updateForDate:",
        "_updateForDate:",
        "updateClock",
        "_updateClock",
        "reloadIconImage",
        "calendarIconImageProviderHasChanged:",
        "imageProvider",
        "iconForImage",
        "iconServicesIconForImage",
        "preparedISIcon",
        "iconImageWithInfo:",
        "unmaskedIconImageWithInfo:",
        "iconImageWithInfo:traitCollection:options:",
        "iconLayerWithInfo:traitCollection:options:",
        "makeIconImageWithInfo:traitCollection:context:options:",
        "makeIconLayerWithInfo:traitCollection:context:options:",
        "localeChanged",
        "_startListeningForSignificantTimeChanges",
        "_stopListeningForSignificantTimeChanges",
        "controller:didChangeOverrideDateFromDate:",
    };
    unsigned installed = 0U;
    for (size_t index = 0;
         index < sizeof(selectors) / sizeof(selectors[0]); index++) {
        installed += CNDInstallHook(className, selectors[index]) ? 1U : 0U;
    }
    return installed;
}

static void CNDLogClockBackgroundIdentity(void)
{
    Class clockViewClass = objc_getClass("SBHClockApplicationIconImageView");
    if (!clockViewClass) {
        CNDLog("[CND_DYNAMIC] CLOCK_BACKGROUND class-missing\n");
        return;
    }
    SEL numberingSelector = sel_registerName("systemNumberingSystem");
    SEL typeSelector = sel_registerName(
        "clockIconBackgroundTypeIdentifierForNumberingSystem:");
    NSString *numberingSystem =
        [clockViewClass respondsToSelector:numberingSelector]
            ? ((id (*)(id, SEL))objc_msgSend)(
                clockViewClass, numberingSelector)
            : nil;
    NSString *typeIdentifier =
        numberingSystem && [clockViewClass respondsToSelector:typeSelector]
            ? ((id (*)(id, SEL, id))objc_msgSend)(
                clockViewClass, typeSelector, numberingSystem)
            : nil;
    CNDLog("[CND_DYNAMIC] CLOCK_BACKGROUND numbering=%s type=%s\n",
           numberingSystem.UTF8String ?: "-",
           typeIdentifier.UTF8String ?: "-");
}

__attribute__((constructor))
static void CNDStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_DYNAMIC_TRACE_OUTPUT_TOKEN[0] && consume
            ? consume(CND_DYNAMIC_TRACE_OUTPUT_TOKEN) : -1;
        gCNDTraceFD = open(CND_DYNAMIC_TRACE_OUTPUT_PATH,
                           O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        CNDLog("[CND_DYNAMIC] START pid=%d process=%s token=%lld "
               "inventory-only=%d no-window-walk=1\n",
               getpid(), getprogname(), (long long)token,
               CND_DYNAMIC_TRACE_INVENTORY_ONLY);

        (void)dlopen(
            "/System/Library/PrivateFrameworks/SpringBoardHome.framework/"
            "SpringBoardHome", RTLD_NOW | RTLD_LOCAL);

        dispatch_async(dispatch_get_main_queue(), ^{
            static const char *const classes[] = {
                "SBHClockApplicationIconImageView",
                "SBHClockApplicationIcon",
                "SBHClockHandsImageSet",
                "SBHClockBackgroundIconDataSource",
                "SBHCalendarApplicationIcon",
                "SBCalendarIconImageProvider",
            };
            for (size_t index = 0;
                 index < sizeof(classes) / sizeof(classes[0]); index++) {
                CNDDumpClass(classes[index]);
            }
            CNDDumpClass("ISIcon");
            CNDDumpClass("ISConcreteIcon");
            CNDDumpClass("ISLayeredIcon");
            CNDDumpClass("ISIconManager");
            CNDDumpClass("ISImageCache");
            CNDLogClockBackgroundIdentity();

            unsigned installed = 0U;
            if (!CND_DYNAMIC_TRACE_INVENTORY_ONLY) {
                for (size_t index = 0;
                     index < sizeof(classes) / sizeof(classes[0]); index++) {
                    installed += CNDInstallClassHooks(classes[index]);
                }
                installed += CNDInstallHook(
                    "SBLeafIcon", "iconServicesIconForImage") ? 1U : 0U;
                installed += CNDInstallHook(
                    "SBLeafIcon",
                    "makeIconImageWithInfo:traitCollection:context:options:")
                    ? 1U : 0U;
                installed += CNDInstallHook(
                    "SBLeafIcon",
                    "makeIconLayerWithInfo:traitCollection:context:options:")
                    ? 1U : 0U;
                installed += CNDInstallISIconRequestHooks();
                installed += CNDInstallHook(
                    "ISIconManager", "findOrRegisterIcon:") ? 1U : 0U;
                installed += CNDInstallHook(
                    "ISImageCache", "imageForDescriptor:") ? 1U : 0U;
                installed += CNDInstallHook(
                    "ISImageCache", "setImage:forDescriptor:") ? 1U : 0U;
                installed += CNDInstallCalendarInitializers();
            }
            CNDLog("[CND_DYNAMIC] TRACE_READY pid=%d classes=%zu hooks=%u "
                   "inventory-only=%d no-window-walk=1\n",
                   getpid(), sizeof(classes) / sizeof(classes[0]), installed,
                   CND_DYNAMIC_TRACE_INVENTORY_ONLY);
        });
    }
}
