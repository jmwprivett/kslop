#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef CND_SHARE_TRACE_OUTPUT_TOKEN
#define CND_SHARE_TRACE_OUTPUT_TOKEN ""
#endif

#ifndef CND_SHARE_TRACE_OUTPUT_PATH
#define CND_SHARE_TRACE_OUTPUT_PATH "/var/tmp/cyanide-sharesheet-airdrop-trace.log"
#endif

static int gCNDShareTraceFD = -1;
static unsigned gCNDShareTraceEvents;

static IMP gCNDOriginalAirDropIdentity;
static IMP gCNDOriginalAirDropImage;
static IMP gCNDOriginalConfigureHorizontalCell;
static IMP gCNDOriginalConfigureAirDropCell;
static IMP gCNDOriginalFetchActivityImage;
static IMP gCNDOriginalFetchBundleImage;
static IMP gCNDOriginalHandleIconImage;
static IMP gCNDOriginalDeliverImage;

static void CNDShareTraceLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDShareTraceLog(const char *format, ...)
{
    if (gCNDShareTraceFD < 0) return;
    char line[8192] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDShareTraceFD, line, amount);
}

static const char *CNDShareTraceClass(id object)
{
    return object ? class_getName(object_getClass(object)) : "-";
}

static NSString *CNDShareTraceDescription(id object, NSUInteger limit)
{
    NSString *description = nil;
    @try {
        description = [object description];
    } @catch (__unused NSException *exception) {
        description = @"<description-exception>";
    }
    description = [description ?: @"-"
        stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
    return description.length > limit
        ? [[description substringToIndex:limit] stringByAppendingString:@"..."]
        : description;
}

static id CNDShareTraceObjectGetter(id object, const char *name)
{
    if (!object || !name) return nil;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *returnType = method_copyReturnType(method);
    const char *type = returnType;
    while (type && *type && strchr("rnNoORV", *type)) type++;
    bool valid = type && (*type == '@' || *type == '#');
    free(returnType);
    if (!valid) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static NSString *CNDShareTraceActivityIdentity(id activity)
{
    for (NSString *name in @[
            @"_bundleIdentifierForActivityImageCreation",
            @"activityType", @"activityTitle", @"bundleIdentifier",
            @"identifier"]) {
        id value = CNDShareTraceObjectGetter(activity, name.UTF8String);
        if ([value isKindOfClass:NSString.class] && [value length] > 0) {
            return [NSString stringWithFormat:@"%@=%@", name, value];
        }
    }
    return @"-";
}

static NSData *CNDShareTraceRGBA(CGImageRef image)
{
    if (!image) return nil;
    size_t width = CGImageGetWidth(image);
    size_t height = CGImageGetHeight(image);
    if (!width || !height || width > 2048U || height > 2048U) return nil;
    size_t bytesPerRow = width * 4U;
    NSMutableData *data = [NSMutableData dataWithLength:bytesPerRow * height];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!data || !colorSpace) {
        if (colorSpace) CGColorSpaceRelease(colorSpace);
        return nil;
    }
    CGContextRef context = CGBitmapContextCreate(
        data.mutableBytes, width, height, 8U, bytesPerRow, colorSpace,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(colorSpace);
    if (!context) return nil;
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), image);
    CGContextRelease(context);
    return data;
}

static NSString *CNDShareTraceSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class]) return @"-";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:64U];
    for (NSUInteger index = 0; index < sizeof(digest); index++) {
        [result appendFormat:@"%02x", digest[index]];
    }
    return result;
}

static void CNDShareTraceImage(const char *phase, id image, id identifier)
{
    if (__atomic_add_fetch(&gCNDShareTraceEvents, 1U,
                           __ATOMIC_RELAXED) > 2048U) return;
    CGImageRef cgImage = NULL;
    if ([image respondsToSelector:sel_registerName("CGImage")]) {
        @try {
            cgImage = ((CGImageRef (*)(id, SEL))objc_msgSend)(
                image, sel_registerName("CGImage"));
        } @catch (__unused NSException *exception) {
            cgImage = NULL;
        }
    }
    NSData *rgba = CNDShareTraceRGBA(cgImage);
    CNDShareTraceLog(
        "[CND_SHARE_TRACE] image phase=%s image=%p/%s identifier=%s/%s "
        "pixels=%zux%zu rgba=%s description=%s\n",
        phase, (__bridge void *)image, CNDShareTraceClass(image),
        CNDShareTraceClass(identifier),
        CNDShareTraceDescription(identifier, 300U).UTF8String ?: "-",
        cgImage ? CGImageGetWidth(cgImage) : 0U,
        cgImage ? CGImageGetHeight(cgImage) : 0U,
        CNDShareTraceSHA256(rgba).UTF8String ?: "-",
        CNDShareTraceDescription(image, 300U).UTF8String ?: "-");
}

static id CNDShareTraceAirDropIdentity(id self, SEL selector)
{
    id result = ((id (*)(id, SEL))gCNDOriginalAirDropIdentity)(self, selector);
    CNDShareTraceLog(
        "[CND_SHARE_TRACE] airdrop-identity activity=%p/%s result=%s/%s\n",
        (__bridge void *)self, CNDShareTraceClass(self),
        CNDShareTraceClass(result),
        CNDShareTraceDescription(result, 300U).UTF8String ?: "-");
    return result;
}

static id CNDShareTraceAirDropImage(id self, SEL selector)
{
    id result = ((id (*)(id, SEL))gCNDOriginalAirDropImage)(self, selector);
    CNDShareTraceImage("UIAirDropActivity._activityImage", result, self);
    return result;
}

static void CNDShareTraceConfigureHorizontalCell(id self, SEL selector,
                                                  id cell, id identifier)
{
    CNDShareTraceLog(
        "[CND_SHARE_TRACE] configure-horizontal controller=%p cell=%p/%s "
        "identifier=%p/%s description=%s\n",
        (__bridge void *)self, (__bridge void *)cell,
        CNDShareTraceClass(cell), (__bridge void *)identifier,
        CNDShareTraceClass(identifier),
        CNDShareTraceDescription(identifier, 1000U).UTF8String ?: "-");
    ((void (*)(id, SEL, id, id))gCNDOriginalConfigureHorizontalCell)(
        self, selector, cell, identifier);
}

static void CNDShareTraceConfigureAirDropCell(id self, SEL selector,
                                               id cell, id change)
{
    CNDShareTraceLog(
        "[CND_SHARE_TRACE] configure-airdrop controller=%p cell=%p/%s "
        "change=%p/%s description=%s\n",
        (__bridge void *)self, (__bridge void *)cell,
        CNDShareTraceClass(cell), (__bridge void *)change,
        CNDShareTraceClass(change),
        CNDShareTraceDescription(change, 1000U).UTF8String ?: "-");
    ((void (*)(id, SEL, id, id))gCNDOriginalConfigureAirDropCell)(
        self, selector, cell, change);
}

static void CNDShareTraceFetchActivityImage(id self, SEL selector,
                                             id activity, id category,
                                             long long style,
                                             id configuration)
{
    CNDShareTraceLog(
        "[CND_SHARE_TRACE] fetch-activity provider=%p activity=%p/%s "
        "identity=%s category=%s style=%lld configuration=%s/%s\n",
        (__bridge void *)self, (__bridge void *)activity,
        CNDShareTraceClass(activity),
        CNDShareTraceActivityIdentity(activity).UTF8String ?: "-",
        CNDShareTraceDescription(category, 200U).UTF8String ?: "-", style,
        CNDShareTraceClass(configuration),
        CNDShareTraceDescription(configuration, 300U).UTF8String ?: "-");
    ((void (*)(id, SEL, id, id, long long, id))
        gCNDOriginalFetchActivityImage)(self, selector, activity, category,
                                        style, configuration);
}

static void CNDShareTraceFetchBundleImage(id self, SEL selector,
                                           id identifier, long long activity,
                                           id category, long long style,
                                           int format, id uti)
{
    CNDShareTraceLog(
        "[CND_SHARE_TRACE] fetch-bundle provider=%p identifier=%s/%s "
        "activityCategory=%lld contentCategory=%s style=%lld format=%d "
        "uti=%s\n",
        (__bridge void *)self, CNDShareTraceClass(identifier),
        CNDShareTraceDescription(identifier, 300U).UTF8String ?: "-",
        activity, CNDShareTraceDescription(category, 200U).UTF8String ?: "-",
        style, format, CNDShareTraceDescription(uti, 200U).UTF8String ?: "-");
    ((void (*)(id, SEL, id, long long, id, long long, int, id))
        gCNDOriginalFetchBundleImage)(self, selector, identifier, activity,
                                      category, style, format, uti);
}

static void CNDShareTraceHandleIconImage(id self, SEL selector, id image,
                                          id identifier, long long activity,
                                          id category, int format,
                                          BOOL placeholder, id uti)
{
    CNDShareTraceImage("SFUIActivityImageProvider._handleIconImage",
                       image, identifier);
    CNDShareTraceLog(
        "[CND_SHARE_TRACE] handle-icon provider=%p activityCategory=%lld "
        "contentCategory=%s format=%d placeholder=%d uti=%s\n",
        (__bridge void *)self, activity,
        CNDShareTraceDescription(category, 200U).UTF8String ?: "-",
        format, placeholder ? 1 : 0,
        CNDShareTraceDescription(uti, 200U).UTF8String ?: "-");
    ((void (*)(id, SEL, id, id, long long, id, int, BOOL, id))
        gCNDOriginalHandleIconImage)(self, selector, image, identifier,
                                     activity, category, format,
                                     placeholder, uti);
}

static void CNDShareTraceDeliverImage(id self, SEL selector, id image,
                                       id identifier, BOOL placeholder,
                                       id error)
{
    CNDShareTraceImage("SFUIImageProvider.deliverImage", image, identifier);
    CNDShareTraceLog(
        "[CND_SHARE_TRACE] deliver provider=%p placeholder=%d error=%s/%s\n",
        (__bridge void *)self, placeholder ? 1 : 0, CNDShareTraceClass(error),
        CNDShareTraceDescription(error, 300U).UTF8String ?: "-");
    ((void (*)(id, SEL, id, id, BOOL, id))gCNDOriginalDeliverImage)(
        self, selector, image, identifier, placeholder, error);
}

static bool CNDShareTraceHook(const char *className, const char *selectorName,
                              unsigned argumentCount, char returnType,
                              IMP replacement, IMP *originalOut)
{
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    char *copiedReturn = method ? method_copyReturnType(method) : NULL;
    const char *normalizedReturn = copiedReturn;
    while (normalizedReturn && *normalizedReturn &&
           strchr("rnNoORV", *normalizedReturn)) normalizedReturn++;
    bool abiOK = method && method_getNumberOfArguments(method) ==
        argumentCount + 2U && normalizedReturn &&
        *normalizedReturn == returnType;
    free(copiedReturn);
    if (!abiOK) {
        CNDShareTraceLog(
            "[CND_SHARE_TRACE] hook class=%s selector=%s ok=0 types=%s "
            "arguments=%u\n", className, selectorName, types ?: "-",
            method ? method_getNumberOfArguments(method) : 0U);
        return false;
    }
    IMP original = method_getImplementation(method);
    if (!original) return false;
    if (!class_addMethod(cls, selector, replacement, types)) {
        method_setImplementation(method, replacement);
    }
    IMP observed = class_getMethodImplementation(cls, selector);
    if (originalOut) *originalOut = original;
    bool ok = observed == replacement;
    CNDShareTraceLog(
        "[CND_SHARE_TRACE] hook class=%s selector=%s ok=%d types=%s "
        "original=%p replacement=%p observed=%p\n",
        className, selectorName, ok ? 1 : 0, types ?: "-", original,
        replacement, observed);
    return ok;
}

__attribute__((constructor))
static void CNDShareTraceStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_SHARE_TRACE_OUTPUT_TOKEN[0] && consume
            ? consume(CND_SHARE_TRACE_OUTPUT_TOKEN) : -1;
        gCNDShareTraceFD = open(CND_SHARE_TRACE_OUTPUT_PATH,
            O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        CNDShareTraceLog(
            "[CND_SHARE_TRACE] START pid=%d process=%s token=%lld mode=read-only\n",
            getpid(), getprogname(), (long long)token);
        (void)dlopen(
            "/System/Library/PrivateFrameworks/ShareSheet.framework/ShareSheet",
            RTLD_NOW | RTLD_LOCAL);
        (void)dlopen(
            "/System/Library/PrivateFrameworks/SharingUI.framework/SharingUI",
            RTLD_NOW | RTLD_LOCAL);

        unsigned hooks = 0U;
        hooks += CNDShareTraceHook("UIAirDropActivity",
            "_bundleIdentifierForActivityImageCreation", 0U, '@',
            (IMP)CNDShareTraceAirDropIdentity,
            &gCNDOriginalAirDropIdentity);
        hooks += CNDShareTraceHook("UIAirDropActivity", "_activityImage",
            0U, '@', (IMP)CNDShareTraceAirDropImage,
            &gCNDOriginalAirDropImage);
        hooks += CNDShareTraceHook("UIActivityContentViewController",
            "_configureHorizontalActionCell:itemIdentifier:", 2U, 'v',
            (IMP)CNDShareTraceConfigureHorizontalCell,
            &gCNDOriginalConfigureHorizontalCell);
        hooks += CNDShareTraceHook("UIActivityContentViewController",
            "_configureAirDropCell:withChange:", 2U, 'v',
            (IMP)CNDShareTraceConfigureAirDropCell,
            &gCNDOriginalConfigureAirDropCell);
        hooks += CNDShareTraceHook("SFUIActivityImageProvider",
            "_fetchImageForActivity:contentSizeCategory:userInterfaceStyle:"
            "imageSymbolConfiguration:", 4U, 'v',
            (IMP)CNDShareTraceFetchActivityImage,
            &gCNDOriginalFetchActivityImage);
        hooks += CNDShareTraceHook("SFUIActivityImageProvider",
            "_fetchBundleImageForIdentifier:activityCategory:"
            "contentSizeCategory:userInterfaceStyle:iconFormat:uti:",
            6U, 'v', (IMP)CNDShareTraceFetchBundleImage,
            &gCNDOriginalFetchBundleImage);
        hooks += CNDShareTraceHook("SFUIActivityImageProvider",
            "_handleIconImage:identifier:activityCategory:contentSizeCategory:"
            "iconFormat:placeholder:uti:", 7U, 'v',
            (IMP)CNDShareTraceHandleIconImage,
            &gCNDOriginalHandleIconImage);
        hooks += CNDShareTraceHook("SFUIImageProvider",
            "deliverImage:identifier:placeholder:error:", 4U, 'v',
            (IMP)CNDShareTraceDeliverImage,
            &gCNDOriginalDeliverImage);
        CNDShareTraceLog(
            "[CND_SHARE_TRACE] TRACE_READY pid=%d hooks=%u/8\n",
            getpid(), hooks);
    }
}
