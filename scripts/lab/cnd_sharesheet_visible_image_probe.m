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

#ifndef CND_SHARE_VIEW_OUTPUT_TOKEN
#define CND_SHARE_VIEW_OUTPUT_TOKEN ""
#endif

#define CND_SHARE_VIEW_OUTPUT_PATH \
    "/var/tmp/cyanide-sharesheet-visible-image-probe.log"

static int gCNDShareViewFD = -1;
static unsigned gCNDShareViewEvents;
static IMP gCNDOriginalImageViewSetImage;
static IMP gCNDOriginalButtonSetImage;

static void CNDShareViewLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDShareViewLog(const char *format, ...)
{
    if (gCNDShareViewFD < 0) return;
    char line[8192] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDShareViewFD, line, amount);
}

static NSString *CNDShareViewText(id value, NSUInteger limit)
{
    NSString *text = nil;
    @try {
        text = [value description];
    } @catch (__unused NSException *exception) {
        text = @"<description-exception>";
    }
    text = [text ?: @"-" stringByReplacingOccurrencesOfString:@"\n"
                                                     withString:@" "];
    return text.length > limit
        ? [[text substringToIndex:limit] stringByAppendingString:@"..."]
        : text;
}

static NSData *CNDShareViewRGBA(CGImageRef image)
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

static NSString *CNDShareViewSHA256(NSData *data)
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

static NSString *CNDShareViewParentChain(UIView *view)
{
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    UIView *cursor = view;
    for (NSUInteger depth = 0; cursor && depth < 8U; depth++) {
        [parts addObject:[NSString stringWithUTF8String:
            class_getName(cursor.class)] ?: @"-"];
        cursor = cursor.superview;
    }
    return [parts componentsJoinedByString:@"<-"];
}

static void CNDShareViewLogImage(const char *phase, UIView *view,
                                 UIImage *image)
{
    if (__atomic_add_fetch(&gCNDShareViewEvents, 1U,
                           __ATOMIC_RELAXED) > 2048U) return;
    CGImageRef cgImage = image.CGImage;
    NSData *rgba = CNDShareViewRGBA(cgImage);
    CGRect frame = view.frame;
    CNDShareViewLog(
        "[CND_SHARE_VIEW] image phase=%s view=%p/%s frame=%.2f,%.2f,%.2f,%.2f "
        "hidden=%d alpha=%.3f window=%p pixels=%zux%zu rgba=%s parents=%s "
        "accessibility=%s image=%s\n",
        phase, (__bridge void *)view, class_getName(view.class),
        frame.origin.x, frame.origin.y, frame.size.width, frame.size.height,
        view.hidden ? 1 : 0, view.alpha, (__bridge void *)view.window,
        cgImage ? CGImageGetWidth(cgImage) : 0U,
        cgImage ? CGImageGetHeight(cgImage) : 0U,
        CNDShareViewSHA256(rgba).UTF8String ?: "-",
        CNDShareViewParentChain(view).UTF8String ?: "-",
        CNDShareViewText(view.accessibilityLabel, 300U).UTF8String ?: "-",
        CNDShareViewText(image, 300U).UTF8String ?: "-");
}

static void CNDShareViewImageViewSetImage(UIImageView *self, SEL selector,
                                           UIImage *image)
{
    ((void (*)(id, SEL, id))gCNDOriginalImageViewSetImage)(
        self, selector, image);
    CNDShareViewLogImage("UIImageView.setImage", self, image);
}

static void CNDShareViewButtonSetImage(UIButton *self, SEL selector,
                                        UIImage *image, NSUInteger state)
{
    ((void (*)(id, SEL, id, NSUInteger))gCNDOriginalButtonSetImage)(
        self, selector, image, state);
    CNDShareViewLogImage("UIButton.setImage", self, image);
}

static bool CNDShareViewHook(const char *className, const char *selectorName,
                             unsigned argumentCount, IMP replacement,
                             IMP *originalOut)
{
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    bool valid = method && method_getNumberOfArguments(method) ==
        argumentCount + 2U;
    if (!valid) {
        CNDShareViewLog(
            "[CND_SHARE_VIEW] hook class=%s selector=%s ok=0 types=%s\n",
            className, selectorName, types ?: "-");
        return false;
    }
    IMP original = method_getImplementation(method);
    method_setImplementation(method, replacement);
    if (originalOut) *originalOut = original;
    bool ok = class_getMethodImplementation(cls, selector) == replacement;
    CNDShareViewLog(
        "[CND_SHARE_VIEW] hook class=%s selector=%s ok=%d types=%s "
        "original=%p replacement=%p\n", className, selectorName,
        ok ? 1 : 0, types ?: "-", original, replacement);
    return ok;
}

static void CNDShareViewWalk(UIView *view, unsigned depth,
                             unsigned *visited)
{
    if (!view || depth > 24U || *visited >= 2048U) return;
    (*visited)++;
    if ([view isKindOfClass:UIImageView.class]) {
        CNDShareViewLogImage("snapshot.imageView", view,
                             ((UIImageView *)view).image);
    } else if ([view isKindOfClass:UIButton.class]) {
        CNDShareViewLogImage("snapshot.button", view,
                             ((UIButton *)view).currentImage);
    }

    const char *className = class_getName(view.class);
    NSString *label = CNDShareViewText(view.accessibilityLabel, 300U);
    NSString *identifier = CNDShareViewText(view.accessibilityIdentifier,
                                             300U);
    NSString *text = [view isKindOfClass:UILabel.class]
        ? CNDShareViewText(((UILabel *)view).text, 300U) : @"-";
    bool relevant = strstr(className, "Activity") ||
        strstr(className, "AirDrop") || strstr(className, "Cell") ||
        [label localizedCaseInsensitiveContainsString:@"AirDrop"] ||
        [identifier localizedCaseInsensitiveContainsString:@"AirDrop"] ||
        [text localizedCaseInsensitiveContainsString:@"AirDrop"];
    if (relevant) {
        CGRect frame = view.frame;
        CNDShareViewLog(
            "[CND_SHARE_VIEW] view depth=%u object=%p/%s "
            "frame=%.2f,%.2f,%.2f,%.2f hidden=%d alpha=%.3f window=%p "
            "label=%s identifier=%s text=%s parents=%s\n",
            depth, (__bridge void *)view, className, frame.origin.x,
            frame.origin.y, frame.size.width, frame.size.height,
            view.hidden ? 1 : 0, view.alpha, (__bridge void *)view.window,
            label.UTF8String ?: "-", identifier.UTF8String ?: "-",
            text.UTF8String ?: "-",
            CNDShareViewParentChain(view).UTF8String ?: "-");
    }
    for (UIView *child in view.subviews) {
        CNDShareViewWalk(child, depth + 1U, visited);
    }
}

static void CNDShareViewSnapshot(unsigned tick)
{
    unsigned windows = 0U;
    unsigned views = 0U;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (!window || window.hidden || window.alpha <= 0.01) continue;
            if (++windows > 16U) break;
            CNDShareViewLog(
                "[CND_SHARE_VIEW] window tick=%u object=%p/%s root=%p/%s\n",
                tick, (__bridge void *)window, class_getName(window.class),
                (__bridge void *)window.rootViewController,
                window.rootViewController
                    ? class_getName(window.rootViewController.class) : "-");
            CNDShareViewWalk(window, 0U, &views);
        }
    }
    CNDShareViewLog(
        "[CND_SHARE_VIEW] SNAPSHOT tick=%u windows=%u views=%u cap=2048\n",
        tick, windows, views);
}

__attribute__((constructor))
static void CNDShareViewStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_SHARE_VIEW_OUTPUT_TOKEN[0] && consume
            ? consume(CND_SHARE_VIEW_OUTPUT_TOKEN) : -1;
        gCNDShareViewFD = open(CND_SHARE_VIEW_OUTPUT_PATH,
            O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        CNDShareViewLog(
            "[CND_SHARE_VIEW] START pid=%d process=%s token=%lld mode=read-only\n",
            getpid(), getprogname(), (long long)token);
        unsigned hooks = 0U;
        hooks += CNDShareViewHook("UIImageView", "setImage:", 1U,
            (IMP)CNDShareViewImageViewSetImage,
            &gCNDOriginalImageViewSetImage);
        hooks += CNDShareViewHook("UIButton", "setImage:forState:", 2U,
            (IMP)CNDShareViewButtonSetImage, &gCNDOriginalButtonSetImage);
        dispatch_async(dispatch_get_main_queue(), ^{
            CNDShareViewSnapshot(0U);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                    (int64_t)(0.75 * NSEC_PER_SEC)),
                dispatch_get_main_queue(), ^{
                    CNDShareViewSnapshot(1U);
                    CNDShareViewLog(
                        "[CND_SHARE_VIEW] TRACE_READY pid=%d hooks=%u/2\n",
                        getpid(), hooks);
                });
        });
    }
}
