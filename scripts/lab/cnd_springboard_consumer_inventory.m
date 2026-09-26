#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef CND_CONSUMER_INVENTORY_OUTPUT_TOKEN
#define CND_CONSUMER_INVENTORY_OUTPUT_TOKEN ""
#endif

#ifndef CND_CONSUMER_INVENTORY_OUTPUT_PATH
#define CND_CONSUMER_INVENTORY_OUTPUT_PATH \
    "/var/tmp/cyanide-springboard-consumer-inventory.log"
#endif

#ifndef CND_CONSUMER_INVENTORY_FOCUSED
#define CND_CONSUMER_INVENTORY_FOCUSED 0
#endif

static int gCNDConsumerInventoryFD = -1;
static NSHashTable<UIView *> *gCNDConsumerInventorySeenViews;

static void CNDConsumerInventoryLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDConsumerInventoryLog(const char *format, ...)
{
    if (gCNDConsumerInventoryFD < 0) return;
    char line[8192] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDConsumerInventoryFD, line, amount);
}

static bool CNDConsumerInventoryContainsToken(const char *text,
                                               const char *const *tokens,
                                               size_t tokenCount)
{
    if (!text) return false;
    for (size_t index = 0; index < tokenCount; index++) {
        if (tokens[index] && strstr(text, tokens[index])) return true;
    }
    return false;
}

static bool __attribute__((unused))
CNDConsumerInventoryRelevantClass(const char *name)
{
    static const char *const tokens[] = {
        "IconImage", "FolderIcon", "Library", "SwitcherSpaceTitle",
        "BadgedIcon", "NotificationIcon", "IconView", "IconController",
        "IconManager", "IconModel",
    };
    return CNDConsumerInventoryContainsToken(
        name, tokens, sizeof(tokens) / sizeof(tokens[0]));
}

static bool CNDConsumerInventoryRelevantMethod(const char *name)
{
    static const char *const tokens[] = {
        "icon", "Icon", "image", "Image", "cache", "Cache",
        "reload", "Reload", "refresh", "Refresh", "update", "Update",
        "invalidate", "Invalidate", "purge", "Purge", "rebuild",
        "Rebuild", "layout", "Layout", "configure", "Configure",
        "prepare", "Prepare", "display", "Display",
    };
    return CNDConsumerInventoryContainsToken(
        name, tokens, sizeof(tokens) / sizeof(tokens[0]));
}

static void CNDConsumerInventoryDumpMethods(Class cls, bool classMethods)
{
    if (!cls) return;
    Class owner = classMethods ? object_getClass(cls) : cls;
    unsigned count = 0U;
    Method *methods = class_copyMethodList(owner, &count);
    for (unsigned index = 0; methods && index < count; index++) {
        SEL selector = method_getName(methods[index]);
        const char *name = selector ? sel_getName(selector) : NULL;
        if (!CNDConsumerInventoryRelevantMethod(name)) continue;
        IMP implementation = method_getImplementation(methods[index]);
        Dl_info image = {0};
        (void)dladdr((const void *)implementation, &image);
        CNDConsumerInventoryLog(
            "[CND_CONSUMER] method class=%s kind=%c selector=%s types=%s "
            "imp=%p image=%s base=%p\n", class_getName(cls),
            classMethods ? '+' : '-',
            name ?: "-", method_getTypeEncoding(methods[index]) ?: "-",
            implementation, image.dli_fname ?: "-", image.dli_fbase);
    }
    free(methods);
}

static void CNDConsumerInventoryDumpSelectedIvars(Class cls)
{
    if (!cls) return;
    const char *className = class_getName(cls);
    if (strcmp(className, "SBFluidSwitcherIconImageContainerView") != 0 &&
        strcmp(className, "SBFluidSwitcherSpaceTitleItemController") != 0 &&
        strcmp(className, "SBHLibraryViewController") != 0 &&
        strcmp(className, "SBHLibraryPodFolderController") != 0 &&
        strcmp(className, "NCBadgedIconView") != 0) return;
    unsigned count = 0U;
    Ivar *ivars = class_copyIvarList(cls, &count);
    for (unsigned index = 0; ivars && index < count; index++) {
        CNDConsumerInventoryLog(
            "[CND_CONSUMER] ivar class=%s name=%s type=%s offset=%td\n",
            className, ivar_getName(ivars[index]) ?: "-",
            ivar_getTypeEncoding(ivars[index]) ?: "-",
            ivar_getOffset(ivars[index]));
    }
    free(ivars);
}

static void CNDConsumerInventoryDumpClasses(void)
{
#if CND_CONSUMER_INVENTORY_FOCUSED
    static const char *const focusedClasses[] = {
        "SBFluidSwitcherIconImageContainerView",
        "SBFluidSwitcherSpaceTitleItemController",
    };
    unsigned relevant = 0U;
    for (size_t index = 0;
         index < sizeof(focusedClasses) / sizeof(focusedClasses[0]);
         index++) {
        Class cls = objc_getClass(focusedClasses[index]);
        if (!cls) {
            CNDConsumerInventoryLog(
                "[CND_CONSUMER] focused-class name=%s loaded=0\n",
                focusedClasses[index]);
            continue;
        }
        relevant++;
        CNDConsumerInventoryLog(
            "[CND_CONSUMER] class name=%s superclass=%s focused=1\n",
            class_getName(cls), class_getSuperclass(cls)
                ? class_getName(class_getSuperclass(cls)) : "-");
        CNDConsumerInventoryDumpSelectedIvars(cls);
        CNDConsumerInventoryDumpMethods(cls, false);
        CNDConsumerInventoryDumpMethods(cls, true);
    }
    CNDConsumerInventoryLog(
        "[CND_CONSUMER] CLASS_INVENTORY_COMPLETE focused=1 relevant=%u\n",
        relevant);
#else
    int count = objc_getClassList(NULL, 0);
    if (count <= 0) return;
    Class *classes = (Class *)calloc((size_t)count, sizeof(*classes));
    if (!classes) return;
    int fetched = objc_getClassList(classes, count);
    unsigned relevant = 0U;
    for (int index = 0; index < fetched; index++) {
        Class cls = classes[index];
        const char *name = cls ? class_getName(cls) : NULL;
        if (!CNDConsumerInventoryRelevantClass(name)) continue;
        relevant++;
        CNDConsumerInventoryLog(
            "[CND_CONSUMER] class name=%s superclass=%s\n", name,
            class_getSuperclass(cls)
                ? class_getName(class_getSuperclass(cls)) : "-");
        CNDConsumerInventoryDumpSelectedIvars(cls);
        CNDConsumerInventoryDumpMethods(cls, false);
        CNDConsumerInventoryDumpMethods(cls, true);
    }
    CNDConsumerInventoryLog(
        "[CND_CONSUMER] CLASS_INVENTORY_COMPLETE loaded=%d relevant=%u\n",
        fetched, relevant);
    free(classes);
#endif
}

static NSString *CNDConsumerInventoryResponderChain(UIResponder *responder)
{
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    UIResponder *cursor = responder;
    for (NSUInteger depth = 0; cursor && depth < 24U; depth++) {
        [parts addObject:NSStringFromClass(cursor.class) ?: @"-"];
        UIResponder *next = cursor.nextResponder;
        if (next == cursor) break;
        cursor = next;
    }
    return [parts componentsJoinedByString:@"<-"];
}

static id CNDConsumerInventoryObjectIvar(id object, const char *name)
{
    if (!object || !name) return nil;
    Ivar ivar = class_getInstanceVariable(object_getClass(object), name);
    if (!ivar) return nil;
    const char *type = ivar_getTypeEncoding(ivar);
    if (!type || type[0] != '@') return nil;
    return object_getIvar(object, ivar);
}

static void CNDConsumerInventoryDumpImage(UIImage *image, NSString *label)
{
    if (![image isKindOfClass:UIImage.class]) {
        CNDConsumerInventoryLog(
            "[CND_CONSUMER] image label=%s object=%p class=%s invalid=1\n",
            label.UTF8String ?: "-", (__bridge void *)image,
            image ? class_getName(image.class) : "-");
        return;
    }
    CGImageRef cgImage = image.CGImage;
    CNDConsumerInventoryLog(
        "[CND_CONSUMER] image label=%s object=%p class=%s points=%.2fx%.2f "
        "scale=%.3f pixels=%zux%zu alpha=%u rendering=%ld\n",
        label.UTF8String ?: "-", (__bridge void *)image,
        class_getName(image.class), image.size.width, image.size.height,
        image.scale, cgImage ? CGImageGetWidth(cgImage) : 0U,
        cgImage ? CGImageGetHeight(cgImage) : 0U,
        cgImage ? (unsigned)CGImageGetAlphaInfo(cgImage) : 0U,
        (long)image.renderingMode);
}

static void CNDConsumerInventoryDumpImageView(UIImageView *imageView,
                                              NSString *label)
{
    if (![imageView isKindOfClass:UIImageView.class]) {
        CNDConsumerInventoryLog(
            "[CND_CONSUMER] image-view label=%s object=%p class=%s invalid=1\n",
            label.UTF8String ?: "-", (__bridge void *)imageView,
            imageView ? class_getName(imageView.class) : "-");
        return;
    }
    CALayer *layer = imageView.layer;
    CNDConsumerInventoryLog(
        "[CND_CONSUMER] image-view label=%s object=%p class=%s "
        "frame=%.2f,%.2f,%.2f,%.2f contentMode=%ld opaque=%d "
        "layer=%s corner=%.3f masks=%d border=%.3f background=%p\n",
        label.UTF8String ?: "-", (__bridge void *)imageView,
        class_getName(imageView.class), imageView.frame.origin.x,
        imageView.frame.origin.y, imageView.frame.size.width,
        imageView.frame.size.height, (long)imageView.contentMode,
        imageView.opaque, class_getName(layer.class), layer.cornerRadius,
        layer.masksToBounds, layer.borderWidth, layer.backgroundColor);
    CNDConsumerInventoryDumpImage(imageView.image,
        [label stringByAppendingString:@".image"]);
}

static void CNDConsumerInventoryDumpLayerTree(CALayer *layer,
                                               const char *label,
                                               NSUInteger depth)
{
    if (!layer || depth > 4U) return;
    CGRect frame = layer.frame;
    CGRect bounds = layer.bounds;
    CNDConsumerInventoryLog(
        "[CND_CONSUMER] layer label=%s depth=%lu object=%p class=%s "
        "delegate=%p/%s frame=%.2f,%.2f,%.2f,%.2f "
        "bounds=%.2f,%.2f,%.2f,%.2f hidden=%d opacity=%.3f "
        "contents=%p sublayers=%lu corner=%.3f masks=%d border=%.3f "
        "background=%p\n",
        label ?: "-", (unsigned long)depth, (__bridge void *)layer,
        class_getName(layer.class), (__bridge void *)layer.delegate,
        layer.delegate ? class_getName([layer.delegate class]) : "-",
        frame.origin.x, frame.origin.y, frame.size.width, frame.size.height,
        bounds.origin.x, bounds.origin.y, bounds.size.width,
        bounds.size.height, layer.hidden, layer.opacity,
        (__bridge void *)layer.contents,
        (unsigned long)layer.sublayers.count, layer.cornerRadius,
        layer.masksToBounds, layer.borderWidth, layer.backgroundColor);
    for (CALayer *child in layer.sublayers) {
        CNDConsumerInventoryDumpLayerTree(child, label, depth + 1U);
    }
}

static void CNDConsumerInventoryDumpViewDetails(UIView *view, unsigned tick)
{
    if (!view) return;
    NSString *className = NSStringFromClass(view.class);
    if ([className isEqualToString:@"SBFluidSwitcherIconImageContainerView"]) {
        UIImageView *imageView = CNDConsumerInventoryObjectIvar(
            view, "_imageView");
        UIView *customImageView = CNDConsumerInventoryObjectIvar(
            view, "_customImageView");
        UIImage *image = CNDConsumerInventoryObjectIvar(view, "_image");
        CNDConsumerInventoryLog(
            "[CND_CONSUMER] switcher-detail tick=%u container=%p "
            "responder=%s subviews=%lu imageView=%p/%s custom=%p/%s\n",
            tick, (__bridge void *)view,
            CNDConsumerInventoryResponderChain(view).UTF8String,
            (unsigned long)view.subviews.count,
            (__bridge void *)imageView,
            imageView ? class_getName(imageView.class) : "-",
            (__bridge void *)customImageView,
            customImageView ? class_getName(customImageView.class) : "-");
        CNDConsumerInventoryDumpImageView(imageView, @"switcher._imageView");
        CNDConsumerInventoryDumpImage(image, @"switcher._image");
        if ([customImageView isKindOfClass:UIView.class]) {
            CGRect frame = customImageView.frame;
            CNDConsumerInventoryLog(
                "[CND_CONSUMER] custom-view label=switcher._customImageView "
                "object=%p class=%s frame=%.2f,%.2f,%.2f,%.2f "
                "hidden=%d alpha=%.3f opaque=%d layer=%p/%s\n",
                (__bridge void *)customImageView,
                class_getName(customImageView.class), frame.origin.x,
                frame.origin.y, frame.size.width, frame.size.height,
                customImageView.hidden, customImageView.alpha,
                customImageView.opaque,
                (__bridge void *)customImageView.layer,
                class_getName(customImageView.layer.class));
            CNDConsumerInventoryDumpLayerTree(
                customImageView.layer, "switcher._customImageView", 0U);
        }
        for (NSUInteger index = 0; index < view.subviews.count; index++) {
            UIView *child = view.subviews[index];
            CNDConsumerInventoryLog(
                "[CND_CONSUMER] switcher-child index=%lu object=%p class=%s\n",
                (unsigned long)index, (__bridge void *)child,
                class_getName(child.class));
        }
    } else if ([className isEqualToString:@"SBHLibraryPodFolderView"] ||
               [className isEqualToString:@"NCBadgedIconView"]) {
        CNDConsumerInventoryLog(
            "[CND_CONSUMER] owner-detail tick=%u object=%p class=%s "
            "responder=%s\n", tick, (__bridge void *)view,
            class_getName(view.class),
            CNDConsumerInventoryResponderChain(view).UTF8String);
    }
}

static NSString *CNDConsumerInventoryViewRole(UIView *view)
{
    NSString *name = NSStringFromClass(view.class);
    if ([name containsString:@"SwitcherSpaceTitle"]) return @"switcher";
    if ([name containsString:@"BadgedIcon"] ||
        [name containsString:@"NotificationIcon"]) return @"notification";
    if ([name containsString:@"Library"]) return @"library";
    if ([name containsString:@"FolderIcon"]) return @"folder";
    if ([name containsString:@"IconImage"] ||
        [name containsString:@"IconView"]) return @"icon";
    return nil;
}

static NSString *CNDConsumerInventorySuperviewChain(UIView *view)
{
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    UIView *cursor = view;
    for (NSUInteger depth = 0; cursor && depth < 10U; depth++) {
        [parts addObject:NSStringFromClass(cursor.class) ?: @"-"];
        cursor = cursor.superview;
    }
    return [parts componentsJoinedByString:@"<-"];
}

static void CNDConsumerInventoryWalkView(UIView *view, unsigned tick,
                                         NSUInteger depth,
                                         unsigned *matches)
{
    if (!view || depth > 64U) return;
    NSString *role = CNDConsumerInventoryViewRole(view);
    if (role) {
        (*matches)++;
        if (![gCNDConsumerInventorySeenViews containsObject:view]) {
            [gCNDConsumerInventorySeenViews addObject:view];
            CGRect frame = view.frame;
            CNDConsumerInventoryLog(
                "[CND_CONSUMER] view tick=%u role=%s object=%p class=%s "
                "frame=%.2f,%.2f,%.2f,%.2f hidden=%d alpha=%.3f "
                "window=%p chain=%s\n", tick, role.UTF8String,
                (__bridge void *)view, class_getName(view.class),
                frame.origin.x, frame.origin.y,
                frame.size.width, frame.size.height,
                view.hidden, view.alpha, (__bridge void *)view.window,
                CNDConsumerInventorySuperviewChain(view).UTF8String);
            CNDConsumerInventoryDumpViewDetails(view, tick);
        }
    }
    for (UIView *child in view.subviews) {
        CNDConsumerInventoryWalkView(child, tick, depth + 1U, matches);
    }
}

static void CNDConsumerInventorySnapshot(unsigned tick)
{
    unsigned matches = 0U;
    unsigned windows = 0U;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            windows++;
            CNDConsumerInventoryWalkView(window, tick, 0U, &matches);
        }
    }
    CNDConsumerInventoryLog(
        "[CND_CONSUMER] SNAPSHOT tick=%u windows=%u matches=%u seen=%lu\n",
        tick, windows, matches,
        (unsigned long)gCNDConsumerInventorySeenViews.count);
}

__attribute__((constructor))
static void CNDConsumerInventoryStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_CONSUMER_INVENTORY_OUTPUT_TOKEN[0] && consume
            ? consume(CND_CONSUMER_INVENTORY_OUTPUT_TOKEN) : -1;
        gCNDConsumerInventoryFD = open(
            CND_CONSUMER_INVENTORY_OUTPUT_PATH,
            O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        CNDConsumerInventoryLog(
            "[CND_CONSUMER] START pid=%d process=%s token=%lld "
            "mode=read-only\n", getpid(), getprogname(), (long long)token);

        (void)dlopen(
            "/System/Library/PrivateFrameworks/SpringBoardHome.framework/"
            "SpringBoardHome", RTLD_NOW | RTLD_LOCAL);
        (void)dlopen(
            "/System/Library/PrivateFrameworks/UserNotificationsUIKit.framework/"
            "UserNotificationsUIKit", RTLD_NOW | RTLD_LOCAL);
        CNDConsumerInventoryDumpClasses();
        gCNDConsumerInventorySeenViews = [NSHashTable weakObjectsHashTable];

        dispatch_async(dispatch_get_main_queue(), ^{
            __block unsigned tick = 0U;
            dispatch_source_t timer = dispatch_source_create(
                DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                dispatch_get_main_queue());
            dispatch_source_set_timer(
                timer, dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC),
                NSEC_PER_SEC, 50 * NSEC_PER_MSEC);
            dispatch_source_set_event_handler(timer, ^{
                tick++;
                CNDConsumerInventorySnapshot(tick);
                if (tick >= 180U) {
                    CNDConsumerInventoryLog(
                        "[CND_CONSUMER] TRACE_COMPLETE ticks=%u\n", tick);
                    dispatch_source_cancel(timer);
                }
            });
            dispatch_resume(timer);
        });
        CNDConsumerInventoryLog(
            "[CND_CONSUMER] TRACE_READY pid=%d\n", getpid());
    }
}
