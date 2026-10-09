#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

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

#ifndef CND_DESCRIPTOR_TRACE_OUTPUT_TOKEN
#define CND_DESCRIPTOR_TRACE_OUTPUT_TOKEN ""
#endif

#ifndef CND_DESCRIPTOR_TRACE_OUTPUT_PATH
#define CND_DESCRIPTOR_TRACE_OUTPUT_PATH \
    "/var/tmp/cyanide-icon-descriptor-trace.log"
#endif

#ifndef CND_DESCRIPTOR_TRACE_TARGET_BUNDLE
#define CND_DESCRIPTOR_TRACE_TARGET_BUNDLE "com.ebay.iphone"
#endif

#ifndef CND_DESCRIPTOR_TRACE_HOST
#define CND_DESCRIPTOR_TRACE_HOST "unknown"
#endif

typedef struct {
    double width;
    double height;
} CNDDescriptorTraceSize;

static int gCNDDescriptorTraceFD = -1;
static IMP gCNDOriginalImageForDescriptor;
static IMP gCNDOriginalPrepareForDescriptor;
static IMP gCNDOriginalGenerateForDescriptor;
static unsigned gCNDDescriptorTraceEvents;
static __thread bool gCNDDescriptorTraceInsideHook;

static void CNDDescriptorTraceLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDDescriptorTraceLog(const char *format, ...)
{
    if (gCNDDescriptorTraceFD < 0) return;
    char line[8192] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDDescriptorTraceFD, line, amount);
}

static const char *CNDDescriptorTraceClass(id object)
{
    return object ? class_getName(object_getClass(object)) : "-";
}

static const char *CNDDescriptorTraceSkipQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static Method CNDDescriptorTraceMethod(id object, const char *name,
                                       unsigned explicitArguments)
{
    if (!object || !name) return NULL;
    Method method = class_getInstanceMethod(
        object_getClass(object), sel_registerName(name));
    return method && method_getNumberOfArguments(method) ==
        explicitArguments + 2U ? method : NULL;
}

static id CNDDescriptorTraceObjectGetter(id object, const char *name)
{
    Method method = CNDDescriptorTraceMethod(object, name, 0U);
    if (!method) return nil;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDDescriptorTraceSkipQualifiers(returnType);
    bool valid = type && (*type == '@' || *type == '#');
    free(returnType);
    if (!valid) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(
            object, sel_registerName(name));
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static NSString *CNDDescriptorTraceUUID(id value)
{
    if ([value isKindOfClass:NSUUID.class]) return [value UUIDString];
    if ([value isKindOfClass:NSString.class]) return value;
    return @"-";
}

static NSString *CNDDescriptorTraceSafeDescription(id object,
                                                    NSUInteger limit)
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

static bool CNDDescriptorTraceGetSize(id descriptor,
                                      CNDDescriptorTraceSize *sizeOut)
{
    Method method = CNDDescriptorTraceMethod(descriptor, "size", 0U);
    if (!method || !sizeOut) return false;
    char *returnType = method_copyReturnType(method);
    bool valid = returnType && strstr(returnType, "CGSize") != NULL;
    free(returnType);
    if (!valid) return false;
    @try {
        *sizeOut = ((CNDDescriptorTraceSize (*)(id, SEL))objc_msgSend)(
            descriptor, sel_registerName("size"));
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDDescriptorTraceGetDouble(id object, const char *name,
                                        double *valueOut)
{
    Method method = CNDDescriptorTraceMethod(object, name, 0U);
    if (!method || !valueOut) return false;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDDescriptorTraceSkipQualifiers(returnType);
    bool valid = type && *type == 'd';
    free(returnType);
    if (!valid) return false;
    @try {
        *valueOut = ((double (*)(id, SEL))objc_msgSend)(
            object, sel_registerName(name));
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDDescriptorTraceGetInteger(id object, const char *name,
                                         long long *valueOut)
{
    Method method = CNDDescriptorTraceMethod(object, name, 0U);
    if (!method || !valueOut) return false;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDDescriptorTraceSkipQualifiers(returnType);
    bool valid = type && strchr("cCsSiIlLqQB", *type);
    free(returnType);
    if (!valid) return false;
    @try {
        *valueOut = ((long long (*)(id, SEL))objc_msgSend)(
            object, sel_registerName(name));
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static NSString *CNDDescriptorTraceNamedTemplate(
    id descriptor, CNDDescriptorTraceSize size, double scale)
{
    (void)descriptor;
    if (scale != 3.0 || size.width != size.height) return @"non-square";
    if (size.width == 20.0) return @"Notification-geometry";
    if (size.width == 24.0) return @"WidgetAddGallery-geometry";
    if (size.width == 28.0) return @"TableUI-geometry";
    if (size.width == 29.0) return @"CarNotification-geometry";
    if (size.width == 40.0) return @"Spotlight-default-geometry";
    if (size.width == 60.0) return @"Activity-or-CarLauncher-geometry";
    if (size.width == 64.0) return @"HomeScreen-default-geometry";
    if (size.width == 68.0) return @"SpringBoardHome-override-geometry";
    return @"custom-geometry";
}

static NSString *CNDDescriptorTraceStack(void)
{
    NSArray<NSString *> *symbols = NSThread.callStackSymbols;
    NSUInteger start = MIN((NSUInteger)2U, symbols.count);
    NSUInteger length = MIN((NSUInteger)18U, symbols.count - start);
    NSString *stack = length
        ? [[symbols subarrayWithRange:NSMakeRange(start, length)]
            componentsJoinedByString:@" | "]
        : @"-";
    stack = [stack stringByReplacingOccurrencesOfString:@"\n"
                                             withString:@" "];
    return stack.length > 5000U
        ? [[stack substringToIndex:5000U] stringByAppendingString:@"..."]
        : stack;
}

static bool CNDDescriptorTraceIsTarget(id icon)
{
    id bundle = CNDDescriptorTraceObjectGetter(icon, "bundleIdentifier");
    if (![bundle isKindOfClass:NSString.class]) return false;
    NSString *target = @CND_DESCRIPTOR_TRACE_TARGET_BUNDLE;
    return [target isEqualToString:@"*"] || [bundle isEqualToString:target];
}

static void CNDDescriptorTraceEvent(const char *phase, id icon,
                                    id descriptor, id image)
{
    if (!CNDDescriptorTraceIsTarget(icon)) return;
    unsigned event = __atomic_add_fetch(
        &gCNDDescriptorTraceEvents, 1U, __ATOMIC_RELAXED);
    if (event > 2048U) return;

    CNDDescriptorTraceSize size = {0.0, 0.0};
    double scale = 0.0;
    bool hasSize = CNDDescriptorTraceGetSize(descriptor, &size);
    bool hasScale = CNDDescriptorTraceGetDouble(descriptor, "scale", &scale);
    id digest = CNDDescriptorTraceObjectGetter(descriptor, "digest");
    id bundle = CNDDescriptorTraceObjectGetter(icon, "bundleIdentifier");
    NSString *templateName = hasSize && hasScale
        ? CNDDescriptorTraceNamedTemplate(descriptor, size, scale) : @"-";

    long long variant = 0;
    long long options = 0;
    long long appearance = 0;
    long long appearanceVariant = 0;
    long long variantOptions = 0;
    long long platform = 0;
    long long ignoreCache = 0;
    bool hasVariant = CNDDescriptorTraceGetInteger(
        descriptor, "iconVariant", &variant);
    bool hasOptions = CNDDescriptorTraceGetInteger(
        descriptor, "options", &options);
    bool hasAppearance = CNDDescriptorTraceGetInteger(
        descriptor, "appearance", &appearance);
    bool hasAppearanceVariant = CNDDescriptorTraceGetInteger(
        descriptor, "appearanceVariant", &appearanceVariant);
    bool hasVariantOptions = CNDDescriptorTraceGetInteger(
        descriptor, "variantOptions", &variantOptions);
    bool hasPlatform = CNDDescriptorTraceGetInteger(
        descriptor, "platform", &platform);
    bool hasIgnoreCache = CNDDescriptorTraceGetInteger(
        descriptor, "ignoreCache", &ignoreCache);

    id imageUUID = CNDDescriptorTraceObjectGetter(image, "uuid");
    id imageData = CNDDescriptorTraceObjectGetter(image, "data");
    CGImageRef cgImage = NULL;
    if (image && [image respondsToSelector:sel_registerName("CGImage")]) {
        @try {
            cgImage = ((CGImageRef (*)(id, SEL))objc_msgSend)(
                image, sel_registerName("CGImage"));
        } @catch (__unused NSException *exception) {
            cgImage = NULL;
        }
    }
    CNDDescriptorTraceLog(
        "[CND_DESCRIPTOR] event=%u host=%s phase=%s icon=%p/%s bundle=%s "
        "descriptor=%p/%s name=%s geometry=%.3fx%.3f@%.3f "
        "digest=%s variant=%d/%lld options=%d/%lld appearance=%d/%lld "
        "appearanceVariant=%d/%lld variantOptions=%d/%lld "
        "platform=%d/%lld ignoreCache=%d/%lld image=%p/%s uuid=%s "
        "data=%lu pixels=%zux%zu description=%s\n",
        event, CND_DESCRIPTOR_TRACE_HOST, phase,
        (__bridge void *)icon, CNDDescriptorTraceClass(icon),
        [bundle isKindOfClass:NSString.class] ? [bundle UTF8String] : "-",
        (__bridge void *)descriptor, CNDDescriptorTraceClass(descriptor),
        templateName.UTF8String, size.width, size.height, scale,
        CNDDescriptorTraceUUID(digest).UTF8String,
        hasVariant, variant, hasOptions, options,
        hasAppearance, appearance,
        hasAppearanceVariant, appearanceVariant,
        hasVariantOptions, variantOptions,
        hasPlatform, platform,
        hasIgnoreCache, ignoreCache,
        (__bridge void *)image, CNDDescriptorTraceClass(image),
        CNDDescriptorTraceUUID(imageUUID).UTF8String,
        (unsigned long)([imageData isKindOfClass:NSData.class]
            ? [imageData length] : 0U),
        cgImage ? CGImageGetWidth(cgImage) : 0U,
        cgImage ? CGImageGetHeight(cgImage) : 0U,
        CNDDescriptorTraceSafeDescription(descriptor, 1400U).UTF8String);
    CNDDescriptorTraceLog("[CND_DESCRIPTOR] stack event=%u %s\n",
                          event, CNDDescriptorTraceStack().UTF8String);
}

static id CNDDescriptorTraceImageForDescriptor(id self, SEL command,
                                               id descriptor)
{
    if (gCNDDescriptorTraceInsideHook) {
        return ((id (*)(id, SEL, id))gCNDOriginalImageForDescriptor)(
            self, command, descriptor);
    }
    gCNDDescriptorTraceInsideHook = true;
    CNDDescriptorTraceEvent("image-enter", self, descriptor, nil);
    id result = ((id (*)(id, SEL, id))gCNDOriginalImageForDescriptor)(
        self, command, descriptor);
    CNDDescriptorTraceEvent("image-return", self, descriptor, result);
    gCNDDescriptorTraceInsideHook = false;
    return result;
}

static id CNDDescriptorTracePrepareForDescriptor(id self, SEL command,
                                                 id descriptor)
{
    if (gCNDDescriptorTraceInsideHook) {
        return ((id (*)(id, SEL, id))gCNDOriginalPrepareForDescriptor)(
            self, command, descriptor);
    }
    gCNDDescriptorTraceInsideHook = true;
    CNDDescriptorTraceEvent("prepare-enter", self, descriptor, nil);
    id result = ((id (*)(id, SEL, id))gCNDOriginalPrepareForDescriptor)(
        self, command, descriptor);
    CNDDescriptorTraceEvent("prepare-return", self, descriptor, result);
    gCNDDescriptorTraceInsideHook = false;
    return result;
}

static id CNDDescriptorTraceGenerateForDescriptor(id self, SEL command,
                                                  id descriptor)
{
    if (gCNDDescriptorTraceInsideHook) {
        return ((id (*)(id, SEL, id))gCNDOriginalGenerateForDescriptor)(
            self, command, descriptor);
    }
    gCNDDescriptorTraceInsideHook = true;
    CNDDescriptorTraceEvent("generate-enter", self, descriptor, nil);
    id result = ((id (*)(id, SEL, id))gCNDOriginalGenerateForDescriptor)(
        self, command, descriptor);
    CNDDescriptorTraceEvent("generate-return", self, descriptor, result);
    gCNDDescriptorTraceInsideHook = false;
    return result;
}

static bool CNDDescriptorTraceInstallOne(Class cls, const char *name,
                                         IMP replacement, IMP *original,
                                         char expectedReturn)
{
    SEL selector = sel_registerName(name);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    if (!method || method_getNumberOfArguments(method) != 3U) return false;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDDescriptorTraceSkipQualifiers(returnType);
    bool valid = type && *type == expectedReturn;
    free(returnType);
    if (!valid) return false;
    IMP implementation = method_getImplementation(method);
    const char *types = method_getTypeEncoding(method);
    if (!class_addMethod(cls, selector, replacement, types)) {
        method_setImplementation(method, replacement);
    }
    *original = implementation;
    CNDDescriptorTraceLog(
        "[CND_DESCRIPTOR] hook class=%s selector=%s types=%s original=%p "
        "replacement=%p ok=1\n", class_getName(cls), name, types,
        implementation, replacement);
    return true;
}

static void CNDDescriptorTraceDumpNamedDescriptors(void)
{
    Class descriptorClass = NSClassFromString(@"ISImageDescriptor");
    if (!descriptorClass) return;
    NSArray<NSString *> *suffixes = @[
        @"Activity", @"CarLauncher", @"CarNotification", @"HomeScreen",
        @"LargeHomeScreen", @"MessagesExtensionBadge",
        @"MessagesExtensionLauncher", @"MessagesExtensionStatus",
        @"Notification", @"Spotlight", @"TableUIName", @"WidgetAddGallery"
    ];
    for (NSString *suffix in suffixes) {
        NSString *name = [@"com.apple.IconServices.ImageDescriptor."
            stringByAppendingString:suffix];
        id descriptor = nil;
        @try {
            descriptor = ((id (*)(id, SEL, id))objc_msgSend)(
                descriptorClass, sel_registerName("imageDescriptorNamed:"),
                name);
        } @catch (__unused NSException *exception) {
        }
        CNDDescriptorTraceSize size = {0.0, 0.0};
        double scale = 0.0;
        (void)CNDDescriptorTraceGetSize(descriptor, &size);
        (void)CNDDescriptorTraceGetDouble(descriptor, "scale", &scale);
        id digest = CNDDescriptorTraceObjectGetter(descriptor, "digest");
        CNDDescriptorTraceLog(
            "[CND_DESCRIPTOR] named name=%s geometry=%.3fx%.3f@%.3f "
            "digest=%s description=%s\n", suffix.UTF8String,
            size.width, size.height, scale,
            CNDDescriptorTraceUUID(digest).UTF8String,
            CNDDescriptorTraceSafeDescription(descriptor, 1400U).UTF8String);
    }
}

static void CNDDescriptorTraceDumpObject(const char *role, id object)
{
    CNDDescriptorTraceLog(
        "[CND_DESCRIPTOR] object role=%s object=%p/%s description=%s\n",
        role, (__bridge void *)object, CNDDescriptorTraceClass(object),
        CNDDescriptorTraceSafeDescription(object, 1200U).UTF8String);
    for (Class cls = object_getClass(object); object && cls;
         cls = class_getSuperclass(cls)) {
        unsigned count = 0U;
        Ivar *ivars = class_copyIvarList(cls, &count);
        for (unsigned index = 0; ivars && index < count; index++) {
            const char *name = ivar_getName(ivars[index]);
            const char *type = ivar_getTypeEncoding(ivars[index]);
            if (!name || !type) continue;
            if (type[0] == '@') {
                id value = nil;
                @try {
                    value = object_getIvar(object, ivars[index]);
                } @catch (__unused NSException *exception) {
                }
                CNDDescriptorTraceLog(
                    "[CND_DESCRIPTOR] ivar role=%s owner=%s name=%s "
                    "type=%s value=%p/%s description=%s\n", role,
                    class_getName(cls), name, type, (__bridge void *)value,
                    CNDDescriptorTraceClass(value),
                    CNDDescriptorTraceSafeDescription(value, 800U).UTF8String);
                if ([value isKindOfClass:NSClassFromString(
                        @"ISImageDescriptor")]) {
                    CNDDescriptorTraceEvent("cache-descriptor", nil,
                                            value, nil);
                }
            } else {
                CNDDescriptorTraceLog(
                    "[CND_DESCRIPTOR] ivar role=%s owner=%s name=%s "
                    "type=%s offset=%td\n", role, class_getName(cls),
                    name, type, ivar_getOffset(ivars[index]));
            }
        }
        free(ivars);
        if (!strcmp(class_getName(cls), "NSObject")) break;
    }
}

static id CNDDescriptorTraceCallObject(id object, const char *name)
{
    return CNDDescriptorTraceObjectGetter(object, name);
}

static void CNDDescriptorTraceDumpSpringBoardCaches(void)
{
    Class controllerClass = NSClassFromString(@"SBIconController");
    id controller = nil;
    if ([controllerClass respondsToSelector:sel_registerName(
            "sharedInstance")]) {
        controller = ((id (*)(id, SEL))objc_msgSend)(
            controllerClass, sel_registerName("sharedInstance"));
    }
    if (!controller) return;
    CNDDescriptorTraceDumpObject("icon-controller", controller);
    id notification = CNDDescriptorTraceCallObject(
        controller, "notificationIconImageCache");
    if (notification) {
        CNDDescriptorTraceDumpObject("notification-cache", notification);
    }
    id manager = CNDDescriptorTraceCallObject(controller, "iconManager");
    if (!manager) manager = CNDDescriptorTraceCallObject(
        controller, "homescreenIconManager");
    if (manager) {
        CNDDescriptorTraceDumpObject("icon-manager", manager);
        id cache = CNDDescriptorTraceCallObject(manager, "iconImageCache");
        if (cache) CNDDescriptorTraceDumpObject("home-cache", cache);
        id folder = CNDDescriptorTraceCallObject(
            manager, "folderIconImageCache");
        if (folder) CNDDescriptorTraceDumpObject("folder-cache", folder);
        id trailing = CNDDescriptorTraceCallObject(
            manager, "trailingLibraryViewController");
        if (trailing) CNDDescriptorTraceDumpObject(
            "app-library-trailing", trailing);
        id overlay = CNDDescriptorTraceCallObject(
            manager, "overlayLibraryViewController");
        if (overlay) CNDDescriptorTraceDumpObject(
            "app-library-overlay", overlay);
    }
}

__attribute__((constructor))
static void CNDDescriptorTraceStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_DESCRIPTOR_TRACE_OUTPUT_TOKEN[0] && consume
            ? consume(CND_DESCRIPTOR_TRACE_OUTPUT_TOKEN) : -1;
        gCNDDescriptorTraceFD = open(
            CND_DESCRIPTOR_TRACE_OUTPUT_PATH,
            O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        CNDDescriptorTraceLog(
            "[CND_DESCRIPTOR] START host=%s pid=%d process=%s target=%s "
            "token=%lld mode=read-only\n", CND_DESCRIPTOR_TRACE_HOST,
            getpid(), getprogname(), CND_DESCRIPTOR_TRACE_TARGET_BUNDLE,
            (long long)token);

        (void)dlopen(
            "/System/Library/PrivateFrameworks/IconServices.framework/"
            "IconServices", RTLD_NOW | RTLD_LOCAL);
        (void)dlopen(
            "/System/Library/PrivateFrameworks/SpringBoardHome.framework/"
            "SpringBoardHome", RTLD_NOW | RTLD_LOCAL);
        CNDDescriptorTraceDumpNamedDescriptors();

        Class iconClass = NSClassFromString(@"ISBundleIdentifierIcon");
        unsigned hooks = 0U;
        hooks += CNDDescriptorTraceInstallOne(
            iconClass, "imageForDescriptor:",
            (IMP)CNDDescriptorTraceImageForDescriptor,
            &gCNDOriginalImageForDescriptor, '@');
        hooks += CNDDescriptorTraceInstallOne(
            iconClass, "prepareImageForDescriptor:",
            (IMP)CNDDescriptorTracePrepareForDescriptor,
            &gCNDOriginalPrepareForDescriptor, '@');
        hooks += CNDDescriptorTraceInstallOne(
            iconClass, "generateImageWithDescriptor:",
            (IMP)CNDDescriptorTraceGenerateForDescriptor,
            &gCNDOriginalGenerateForDescriptor, '@');
        CNDDescriptorTraceLog(
            "[CND_DESCRIPTOR] TRACE_READY host=%s pid=%d hooks=%u\n",
            CND_DESCRIPTOR_TRACE_HOST, getpid(), hooks);
        if (!strcmp(CND_DESCRIPTOR_TRACE_HOST, "SpringBoard")) {
            dispatch_async(dispatch_get_main_queue(), ^{
                @autoreleasepool {
                    CNDDescriptorTraceDumpSpringBoardCaches();
                    CNDDescriptorTraceLog(
                        "[CND_DESCRIPTOR] CACHE_SNAPSHOT_COMPLETE\n");
                }
            });
        }
    }
}
