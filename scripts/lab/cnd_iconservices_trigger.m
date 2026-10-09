#import <Foundation/Foundation.h>

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <errno.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    double width;
    double height;
} CNDTriggerSize;

static bool CNDTriggerValidBundle(const char *bundle)
{
    if (!bundle) return false;
    size_t length = strlen(bundle);
    if (length < 3U || length > 200U) return false;
    bool hasDot = false;
    bool segmentStart = true;
    for (size_t index = 0; index < length; index++) {
        unsigned char character = (unsigned char)bundle[index];
        bool alphanumeric = (character >= 'A' && character <= 'Z') ||
            (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9');
        if (character == '.') {
            if (segmentStart) return false;
            hasDot = true;
            segmentStart = true;
        } else if (alphanumeric) {
            segmentStart = false;
        } else if (segmentStart || (character != '-' && character != '_')) {
            return false;
        }
    }
    return hasDot && !segmentStart;
}

static bool CNDTriggerMethodHasTypes(id object, const char *name,
                                     const char *expected)
{
    if (!object || !name || !expected) return false;
    Method method = class_getInstanceMethod(
        object_getClass(object), sel_registerName(name));
    return method && method_getTypeEncoding(method) &&
        strcmp(method_getTypeEncoding(method), expected) == 0;
}

static NSString *CNDTriggerSHA256(NSData *data)
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

static NSData *CNDTriggerRGBAData(CGImageRef image, size_t width,
                                  size_t height)
{
    if (!image || width == 0U || height == 0U ||
        width > SIZE_MAX / 4U || height > SIZE_MAX / (width * 4U)) {
        return nil;
    }
    size_t rowBytes = width * 4U;
    size_t length = rowBytes * height;
    NSMutableData *data = [NSMutableData dataWithLength:length];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = colorSpace
        ? CGBitmapContextCreate(
            data.mutableBytes, width, height, 8U, rowBytes, colorSpace,
            kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big)
        : NULL;
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    if (!context) return nil;
    CGContextClearRect(
        context, CGRectMake(0.0, 0.0, (double)width, (double)height));
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextSetInterpolationQuality(context, kCGInterpolationHigh);
    CGContextDrawImage(
        context, CGRectMake(0.0, 0.0, (double)width, (double)height), image);
    CGContextRelease(context);
    return data;
}

static CGImageRef CNDTriggerLoadCGImage(NSString *path)
{
    NSData *data = path.length
        ? [NSData dataWithContentsOfFile:path] : nil;
    CGImageSourceRef source = data
        ? CGImageSourceCreateWithData((__bridge CFDataRef)data, NULL) : NULL;
    CGImageRef image = source
        ? CGImageSourceCreateImageAtIndex(source, 0U, NULL) : NULL;
    if (source) CFRelease(source);
    return image;
}

static id CNDTriggerObjectGetter(id object, const char *name)
{
    if (!object) return nil;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *type = method_copyReturnType(method);
    const char *cursor = type;
    while (cursor && *cursor && strchr("rnNoORV", *cursor)) cursor++;
    bool objectReturn = cursor && (*cursor == '@' || *cursor == '#');
    free(type);
    if (!objectReturn) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(object, selector);
}

static void CNDTriggerDumpClass(id object, const char *label)
{
    if (!object) {
        printf("CND_ICON_TRIGGER inspect label=%s object=nil\n", label);
        return;
    }
    printf("CND_ICON_TRIGGER inspect label=%s object=%p class=%s\n",
           label, (__bridge void *)object,
           class_getName(object_getClass(object)));
    unsigned depth = 0U;
    for (Class cls = object_getClass(object); cls && depth < 5U;
         cls = class_getSuperclass(cls), depth++) {
        unsigned methodCount = 0U;
        Method *methods = class_copyMethodList(cls, &methodCount);
        printf("CND_ICON_TRIGGER inspect-class label=%s depth=%u class=%s "
               "methods=%u\n", label, depth, class_getName(cls),
               methodCount);
        unsigned methodCap = methodCount < 160U ? methodCount : 160U;
        for (unsigned index = 0U; index < methodCap; index++) {
            printf("CND_ICON_TRIGGER inspect-method label=%s class=%s "
                   "selector=%s types=%s\n", label, class_getName(cls),
                   sel_getName(method_getName(methods[index])),
                   method_getTypeEncoding(methods[index]) ?: "-");
        }
        free(methods);
        unsigned ivarCount = 0U;
        Ivar *ivars = class_copyIvarList(cls, &ivarCount);
        unsigned ivarCap = ivarCount < 80U ? ivarCount : 80U;
        for (unsigned index = 0U; index < ivarCap; index++) {
            printf("CND_ICON_TRIGGER inspect-ivar label=%s class=%s "
                   "name=%s type=%s offset=%td\n", label,
                   class_getName(cls), ivar_getName(ivars[index]) ?: "-",
                   ivar_getTypeEncoding(ivars[index]) ?: "-",
                   ivar_getOffset(ivars[index]));
        }
        free(ivars);
    }
}

static void CNDTriggerDumpClassMethods(Class cls, const char *label)
{
    Class metaclass = cls ? object_getClass(cls) : Nil;
    unsigned methodCount = 0U;
    Method *methods = metaclass
        ? class_copyMethodList(metaclass, &methodCount) : NULL;
    printf("CND_ICON_TRIGGER inspect-metaclass label=%s class=%s "
           "methods=%u\n", label, cls ? class_getName(cls) : "-",
           methodCount);
    for (unsigned index = 0U; index < methodCount; index++) {
        printf("CND_ICON_TRIGGER inspect-class-method label=%s class=%s "
               "selector=%s types=%s\n", label, class_getName(cls),
               sel_getName(method_getName(methods[index])),
               method_getTypeEncoding(methods[index]) ?: "-");
    }
    free(methods);
}

static bool CNDTriggerNameContainsAny(const char *name)
{
    if (!name) return false;
    static const char *const fragments[] = {
        "chiclet", "Chiclet", "finalized", "Finalized",
        "renderingConfiguration", "RenderingConfiguration",
    };
    for (size_t index = 0U;
         index < sizeof(fragments) / sizeof(fragments[0]); index++) {
        if (strstr(name, fragments[index])) return true;
    }
    return false;
}

static void CNDTriggerDumpMatchingRuntime(void)
{
    int classCount = objc_getClassList(NULL, 0);
    if (classCount <= 0) return;
    __unsafe_unretained Class *classes =
        (__unsafe_unretained Class *)calloc(
            (size_t)classCount, sizeof(*classes));
    if (!classes) return;
    classCount = objc_getClassList(classes, classCount);
    for (int classIndex = 0; classIndex < classCount; classIndex++) {
        Class cls = classes[classIndex];
        const char *className = class_getName(cls);
        if (!className || (strncmp(className, "ICR", 3U) != 0 &&
                           strncmp(className, "_TtC13IconRendering", 20U) != 0)) {
            continue;
        }
        Class targets[2] = {cls, object_getClass(cls)};
        for (unsigned targetIndex = 0U; targetIndex < 2U; targetIndex++) {
            Class target = targets[targetIndex];
            unsigned methodCount = 0U;
            Method *methods = class_copyMethodList(target, &methodCount);
            for (unsigned index = 0U; index < methodCount; index++) {
                const char *name = sel_getName(method_getName(methods[index]));
                if (CNDTriggerNameContainsAny(name)) {
                    printf("CND_ICON_TRIGGER runtime-match class=%s scope=%s "
                           "kind=method name=%s types=%s\n",
                           className, targetIndex ? "class" : "instance",
                           name, method_getTypeEncoding(methods[index]) ?: "-");
                }
            }
            free(methods);
        }
        unsigned propertyCount = 0U;
        objc_property_t *properties = class_copyPropertyList(cls,
                                                              &propertyCount);
        for (unsigned index = 0U; index < propertyCount; index++) {
            const char *name = property_getName(properties[index]);
            if (CNDTriggerNameContainsAny(name)) {
                printf("CND_ICON_TRIGGER runtime-match class=%s "
                       "scope=instance kind=property name=%s attributes=%s\n",
                       className, name,
                       property_getAttributes(properties[index]) ?: "-");
            }
        }
        free(properties);
        unsigned ivarCount = 0U;
        Ivar *ivars = class_copyIvarList(cls, &ivarCount);
        for (unsigned index = 0U; index < ivarCount; index++) {
            const char *name = ivar_getName(ivars[index]);
            if (CNDTriggerNameContainsAny(name)) {
                printf("CND_ICON_TRIGGER runtime-match class=%s "
                       "scope=instance kind=ivar name=%s type=%s offset=%td\n",
                       className, name, ivar_getTypeEncoding(ivars[index]) ?: "-",
                       ivar_getOffset(ivars[index]));
            }
        }
        free(ivars);
    }
    free(classes);
}

int main(int argc, char **argv)
{
    @autoreleasepool {
        bool ignoreCache = false;
        bool inspectLayer = false;
        bool inspectDescriptor = false;
        bool probeVariants = false;
        bool factoryRequested = false;
        bool variantOptionsRequested = false;
        bool drawBorderRequested = false;
        bool templateVariantRequested = false;
        bool appearanceVariantRequested = false;
        bool shareStyleRequested = false;
        bool airDropActivityRequested = false;
        int32_t requestedIconVariant = 0;
        int32_t requestedFactoryOptions = 0;
        uint64_t requestedVariantOptions = 0;
        BOOL requestedDrawBorder = NO;
        BOOL requestedTemplateVariant = NO;
        int64_t requestedAppearanceVariant = 0;
        int64_t requestedShareStyle = 1;
        uint32_t requestedPointSize = 68U;
        int64_t requestedAppearance = 0;
        NSString *bundleIdentifier = @"com.ebay.iphone";
        NSString *comparePath = nil;
        NSString *dumpLayerPath = nil;
        for (int i = 1; i < argc; i++) {
            if (!strcmp(argv[i], "--ignore-cache")) {
                ignoreCache = true;
            } else if (!strcmp(argv[i], "--probe-variants")) {
                probeVariants = true;
            } else if (!strcmp(argv[i], "--inspect-layer")) {
                inspectLayer = true;
            } else if (!strcmp(argv[i], "--inspect-descriptor")) {
                inspectDescriptor = true;
            } else if (!strcmp(argv[i], "--airdrop-activity")) {
                airDropActivityRequested = true;
            } else if (!strcmp(argv[i], "--bundle") && i + 1 < argc) {
                bundleIdentifier = [NSString stringWithUTF8String:argv[++i]];
            } else if (!strcmp(argv[i], "--variant") && i + 1 < argc) {
                const char *text = argv[++i];
                char *end = NULL;
                errno = 0;
                long value = strtol(text, &end, 0);
                if (errno || !end || *end || value < 0 || value > INT_MAX) {
                    fprintf(stderr, "variant must be a nonnegative int32\n");
                    return 64;
                }
                requestedIconVariant = (int32_t)value;
                factoryRequested = true;
            } else if (!strcmp(argv[i], "--factory-options") &&
                       i + 1 < argc) {
                const char *text = argv[++i];
                char *end = NULL;
                errno = 0;
                long value = strtol(text, &end, 0);
                if (errno || !end || *end || value < 0 || value > INT_MAX) {
                    fprintf(stderr,
                            "factory options must be a nonnegative int32\n");
                    return 64;
                }
                requestedFactoryOptions = (int32_t)value;
                factoryRequested = true;
            } else if (!strcmp(argv[i], "--variant-options") &&
                       i + 1 < argc) {
                const char *text = argv[++i];
                char *end = NULL;
                errno = 0;
                unsigned long long value = strtoull(text, &end, 0);
                if (errno || !end || *end) {
                    fprintf(stderr,
                            "variant options must be a nonnegative uint64\n");
                    return 64;
                }
                requestedVariantOptions = (uint64_t)value;
                variantOptionsRequested = true;
            } else if (!strcmp(argv[i], "--point-size") &&
                       i + 1 < argc) {
                const char *text = argv[++i];
                char *end = NULL;
                errno = 0;
                unsigned long value = strtoul(text, &end, 0);
                if (errno || !end || *end || value == 0U ||
                    value > 1024U) {
                    fprintf(stderr,
                            "point size must be an integer in 1-1024\n");
                    return 64;
                }
                requestedPointSize = (uint32_t)value;
            } else if (!strcmp(argv[i], "--appearance") &&
                       i + 1 < argc) {
                const char *text = argv[++i];
                char *end = NULL;
                errno = 0;
                long long value = strtoll(text, &end, 0);
                if (errno || !end || *end || value < 0 || value > 1) {
                    fprintf(stderr, "appearance must be 0 or 1\n");
                    return 64;
                }
                requestedAppearance = (int64_t)value;
            } else if (!strcmp(argv[i], "--appearance-variant") &&
                       i + 1 < argc) {
                const char *text = argv[++i];
                char *end = NULL;
                errno = 0;
                long long value = strtoll(text, &end, 0);
                if (errno || !end || *end || value < 0 || value > INT_MAX) {
                    fprintf(stderr,
                            "appearance variant must be a nonnegative int32\n");
                    return 64;
                }
                requestedAppearanceVariant = (int64_t)value;
                appearanceVariantRequested = true;
            } else if (!strcmp(argv[i], "--draw-border") &&
                       i + 1 < argc) {
                const char *text = argv[++i];
                if (strcmp(text, "0") && strcmp(text, "1")) {
                    fprintf(stderr, "draw border must be 0 or 1\n");
                    return 64;
                }
                requestedDrawBorder = !strcmp(text, "1");
                drawBorderRequested = true;
            } else if (!strcmp(argv[i], "--template-variant") &&
                       i + 1 < argc) {
                const char *text = argv[++i];
                if (strcmp(text, "0") && strcmp(text, "1")) {
                    fprintf(stderr, "template variant must be 0 or 1\n");
                    return 64;
                }
                requestedTemplateVariant = !strcmp(text, "1");
                templateVariantRequested = true;
            } else if (!strcmp(argv[i], "--share-style") &&
                       i + 1 < argc) {
                const char *text = argv[++i];
                if (strcmp(text, "1") && strcmp(text, "2")) {
                    fprintf(stderr, "share style must be 1 (light) or 2 (dark)\n");
                    return 64;
                }
                requestedShareStyle = strtoll(text, NULL, 10);
                shareStyleRequested = true;
            } else if (!strcmp(argv[i], "--compare-png") && i + 1 < argc) {
                comparePath = [NSString stringWithUTF8String:argv[++i]];
            } else if (!strcmp(argv[i], "--dump-layer") && i + 1 < argc) {
                dumpLayerPath = [NSString stringWithUTF8String:argv[++i]];
            } else {
                fprintf(stderr,
                        "usage: %s [--bundle IDENTIFIER] [--ignore-cache] "
                        "[--variant INT32] [--factory-options INT32] "
                        "[--variant-options UINT64] "
                        "[--point-size UINT32] [--appearance 0|1] "
                        "[--appearance-variant INT32] "
                        "[--draw-border 0|1] [--template-variant 0|1] "
                        "[--share-style 1|2] "
                        "[--airdrop-activity] "
                        "[--probe-variants] "
                        "[--inspect-descriptor] [--inspect-layer] "
                        "[--compare-png PATH] "
                        "[--dump-layer PATH]\n", argv[0]);
                return 64;
            }
        }
        if (!CNDTriggerValidBundle(bundleIdentifier.UTF8String)) {
            fprintf(stderr, "bundle must be one explicit bundle identifier\n");
            return 64;
        }
        if (airDropActivityRequested) {
            void *shareSheetHandle = dlopen(
                "/System/Library/PrivateFrameworks/ShareSheet.framework/"
                "ShareSheet", RTLD_NOW | RTLD_LOCAL);
            Class activityClass = shareSheetHandle
                ? NSClassFromString(@"UIAirDropActivity") : Nil;
            SEL identitySelector = sel_registerName(
                "_bundleIdentifierForActivityImageCreation");
            SEL imageSelector = sel_registerName("_activityImage");
            Method identityMethod = activityClass
                ? class_getInstanceMethod(activityClass, identitySelector)
                : NULL;
            Method imageMethod = activityClass
                ? class_getInstanceMethod(activityClass, imageSelector)
                : NULL;
            if (!activityClass || !identityMethod || !imageMethod ||
                strcmp(method_getTypeEncoding(identityMethod), "@16@0:8") ||
                strcmp(method_getTypeEncoding(imageMethod), "@16@0:8")) {
                fprintf(stderr, "UIAirDropActivity ABI mismatch\n");
                return 3;
            }
            id activity = [[activityClass alloc] init];
            NSString *identity = ((id (*)(id, SEL))objc_msgSend)(
                activity, identitySelector);
            id image = ((id (*)(id, SEL))objc_msgSend)(
                activity, imageSelector);
            CGImageRef cgImage = NULL;
            SEL cgImageSelector = sel_registerName("CGImage");
            if ([image respondsToSelector:cgImageSelector]) {
                cgImage = ((CGImageRef (*)(id, SEL))objc_msgSend)(
                    image, cgImageSelector);
            }
            size_t pixelWidth = cgImage ? CGImageGetWidth(cgImage) : 0U;
            size_t pixelHeight = cgImage ? CGImageGetHeight(cgImage) : 0U;
            NSData *rgba = CNDTriggerRGBAData(
                cgImage, pixelWidth, pixelHeight);
            printf("CND_AIRDROP_ACTIVITY pid=%d activity=%p/%s "
                   "identity=%s image=%p/%s pixels=%zux%zu rgba=%s\n",
                   getpid(), (__bridge void *)activity,
                   class_getName(object_getClass(activity)),
                   identity.UTF8String ?: "-", (__bridge void *)image,
                   image ? class_getName(object_getClass(image)) : "-",
                   pixelWidth, pixelHeight,
                   CNDTriggerSHA256(rgba).UTF8String ?: "-");
            return image && cgImage ? 0 : 4;
        }
        void *handle = dlopen(
            "/System/Library/PrivateFrameworks/IconServices.framework/"
            "IconServices", RTLD_NOW | RTLD_LOCAL);
        Class iconClass = handle
            ? NSClassFromString(@"ISBundleIdentifierIcon") : Nil;
        Class descriptorClass = handle
            ? NSClassFromString(@"ISImageDescriptor") : Nil;
        if (!iconClass || !descriptorClass) {
            fprintf(stderr, "IconServices runtime classes unavailable\n");
            return 2;
        }
        if (probeVariants) {
            SEL factory = sel_registerName(
                "imageDescriptorWithIconVariant:options:");
            Method factoryMethod = class_getClassMethod(
                descriptorClass, factory);
            const char *factoryTypes = factoryMethod
                ? method_getTypeEncoding(factoryMethod) : NULL;
            if (!factoryTypes || strcmp(factoryTypes, "@24@0:8i16i20")) {
                fprintf(stderr, "variant descriptor factory ABI mismatch\n");
                return 3;
            }
            unsigned matches = 0U;
            for (int32_t variant = 0; variant <= 512; variant++) {
                id candidate = ((id (*)(id, SEL, int32_t, int32_t))
                    objc_msgSend)(descriptorClass, factory, variant, 0);
                NSString *description = candidate
                    ? [candidate description] : @"-";
                bool relevant = [description rangeOfString:
                    @"(68.00, 68.00)@3x"].location != NSNotFound ||
                    ([description rangeOfString:@" v:0 "].location ==
                         NSNotFound &&
                     [description rangeOfString:@" v:"].location !=
                         NSNotFound);
                if (relevant) {
                    matches++;
                    printf("CND_ICON_TRIGGER variant-probe input=%d "
                           "description=%s\n", variant,
                           description.UTF8String);
                }
            }
            printf("CND_ICON_TRIGGER variant-probe-complete range=0-512 "
                   "matches=%u\n", matches);
            return 0;
        }
        id icon = ((id (*)(id, SEL, id))objc_msgSend)(
            [iconClass alloc], sel_registerName("initWithBundleIdentifier:"),
            bundleIdentifier);
        id descriptor = nil;
        id factoryDescriptor = nil;
        if (factoryRequested) {
            SEL factory = sel_registerName(
                "imageDescriptorWithIconVariant:options:");
            Method factoryMethod = class_getClassMethod(
                descriptorClass, factory);
            const char *factoryTypes = factoryMethod
                ? method_getTypeEncoding(factoryMethod) : NULL;
            if (!factoryTypes || strcmp(factoryTypes, "@24@0:8i16i20")) {
                fprintf(stderr, "variant descriptor factory ABI mismatch\n");
                return 3;
            }
            factoryDescriptor = ((id (*)(id, SEL, int32_t, int32_t))objc_msgSend)(
                descriptorClass, factory, requestedIconVariant,
                requestedFactoryOptions);
            descriptor = factoryDescriptor;
        } else {
            descriptor = ((id (*)(id, SEL, id))objc_msgSend)(
                descriptorClass, sel_registerName("imageDescriptorNamed:"),
                @"com.apple.IconServices.ImageDescriptor.Spotlight");
        }
        if (!descriptor || ![descriptor conformsToProtocol:@protocol(NSCopying)]) {
            fprintf(stderr, "named Spotlight descriptor is not copyable\n");
            return 3;
        }
        descriptor = [descriptor copy];
        bool descriptorABI =
            CNDTriggerMethodHasTypes(
                descriptor, "setSize:", "v32@0:8{CGSize=dd}16") &&
            CNDTriggerMethodHasTypes(
                descriptor, "size", "{CGSize=dd}16@0:8") &&
            CNDTriggerMethodHasTypes(
                descriptor, "setScale:", "v24@0:8d16") &&
            CNDTriggerMethodHasTypes(descriptor, "scale", "d16@0:8") &&
            CNDTriggerMethodHasTypes(
                descriptor, "setAppearance:", "v24@0:8q16") &&
            CNDTriggerMethodHasTypes(
                descriptor, "appearance", "q16@0:8") &&
            CNDTriggerMethodHasTypes(descriptor, "digest", "@16@0:8");
        if (!descriptorABI) {
            fprintf(stderr, "Spotlight descriptor ABI mismatch\n");
            return 3;
        }
        CNDTriggerSize requestedSize = {
            (double)requestedPointSize, (double)requestedPointSize,
        };
        ((void (*)(id, SEL, CNDTriggerSize))objc_msgSend)(
            descriptor, sel_registerName("setSize:"), requestedSize);
        ((void (*)(id, SEL, double))objc_msgSend)(
            descriptor, sel_registerName("setScale:"), 3.0);
        ((void (*)(id, SEL, int64_t))objc_msgSend)(
            descriptor, sel_registerName("setAppearance:"),
            requestedAppearance);
        if (variantOptionsRequested) {
            if (!CNDTriggerMethodHasTypes(
                    descriptor, "setVariantOptions:", "v24@0:8Q16") ||
                !CNDTriggerMethodHasTypes(
                    descriptor, "variantOptions", "Q16@0:8")) {
                fprintf(stderr, "variantOptions ABI mismatch\n");
                return 3;
            }
            ((void (*)(id, SEL, uint64_t))objc_msgSend)(
                descriptor, sel_registerName("setVariantOptions:"),
                requestedVariantOptions);
        }
        if (appearanceVariantRequested) {
            if (!CNDTriggerMethodHasTypes(
                    descriptor, "setAppearanceVariant:", "v24@0:8q16") ||
                !CNDTriggerMethodHasTypes(
                    descriptor, "appearanceVariant", "q16@0:8")) {
                fprintf(stderr, "appearanceVariant ABI mismatch\n");
                return 3;
            }
            ((void (*)(id, SEL, int64_t))objc_msgSend)(
                descriptor, sel_registerName("setAppearanceVariant:"),
                requestedAppearanceVariant);
        }
        if (drawBorderRequested) {
            if (!CNDTriggerMethodHasTypes(
                    descriptor, "setDrawBorder:", "v20@0:8B16") ||
                !CNDTriggerMethodHasTypes(
                    descriptor, "drawBorder", "B16@0:8")) {
                fprintf(stderr, "drawBorder ABI mismatch\n");
                return 3;
            }
            ((void (*)(id, SEL, BOOL))objc_msgSend)(
                descriptor, sel_registerName("setDrawBorder:"),
                requestedDrawBorder);
        }
        if (templateVariantRequested) {
            if (!CNDTriggerMethodHasTypes(
                    descriptor, "setTemplateVariant:", "v20@0:8B16") ||
                !CNDTriggerMethodHasTypes(
                    descriptor, "templateVariant", "B16@0:8")) {
                fprintf(stderr, "templateVariant ABI mismatch\n");
                return 3;
            }
            ((void (*)(id, SEL, BOOL))objc_msgSend)(
                descriptor, sel_registerName("setTemplateVariant:"),
                requestedTemplateVariant);
        }
        if (shareStyleRequested) {
            void *sharingHandle = dlopen(
                "/System/Library/PrivateFrameworks/SharingUI.framework/"
                "SharingUI", RTLD_NOW | RTLD_LOCAL);
            Class imageProviderClass = sharingHandle
                ? NSClassFromString(@"SFUIActivityImageProvider") : Nil;
            SEL tintSelector = sel_registerName(
                "tintImageDescriptor:withUserInterfaceStyle:forGraphicIcon:");
            Method tintMethod = imageProviderClass
                ? class_getClassMethod(imageProviderClass, tintSelector) : NULL;
            char *tintReturnType = tintMethod
                ? method_copyReturnType(tintMethod) : NULL;
            bool validTintReturn = tintReturnType &&
                tintReturnType[0] == '@';
            free(tintReturnType);
            if (!tintMethod || method_getNumberOfArguments(tintMethod) != 5U ||
                !validTintReturn) {
                fprintf(stderr, "SharingUI descriptor tint ABI mismatch\n");
                return 3;
            }
            descriptor = ((id (*)(id, SEL, id, int64_t, BOOL))objc_msgSend)(
                imageProviderClass, tintSelector, descriptor,
                requestedShareStyle, NO);
            if (!descriptor) {
                fprintf(stderr, "SharingUI descriptor tint returned nil\n");
                return 3;
            }
        }
        if (ignoreCache) {
            if (!CNDTriggerMethodHasTypes(
                    descriptor, "setIgnoreCache:", "v20@0:8B16")) {
                fprintf(stderr, "Spotlight ignoreCache ABI mismatch\n");
                return 3;
            }
            ((void (*)(id, SEL, BOOL))objc_msgSend)(
                descriptor, sel_registerName("setIgnoreCache:"), YES);
        }
        if (!icon || !descriptor) {
            fprintf(stderr, "could not construct Spotlight request for %s\n",
                    bundleIdentifier.UTF8String ?: "-");
            return 3;
        }

        id provider = nil;
        if ([icon respondsToSelector:sel_registerName(
                "_makeResourceProviderAllowIconResourceFallback:")]) {
            provider = ((id (*)(id, SEL, BOOL))objc_msgSend)(
                icon,
                sel_registerName(
                    "_makeResourceProviderAllowIconResourceFallback:"),
                YES);
        }
        CNDTriggerSize observedSize =
            ((CNDTriggerSize (*)(id, SEL))objc_msgSend)(
                descriptor, sel_registerName("size"));
        double observedScale = ((double (*)(id, SEL))objc_msgSend)(
            descriptor, sel_registerName("scale"));
        int64_t observedAppearance =
            ((int64_t (*)(id, SEL))objc_msgSend)(
                descriptor, sel_registerName("appearance"));
        uint64_t observedVariantOptions =
            CNDTriggerMethodHasTypes(
                descriptor, "variantOptions", "Q16@0:8")
                ? ((uint64_t (*)(id, SEL))objc_msgSend)(
                      descriptor, sel_registerName("variantOptions"))
                : UINT64_MAX;
        int64_t observedAppearanceVariant =
            CNDTriggerMethodHasTypes(
                descriptor, "appearanceVariant", "q16@0:8")
                ? ((int64_t (*)(id, SEL))objc_msgSend)(
                      descriptor, sel_registerName("appearanceVariant"))
                : INT64_MIN;
        BOOL observedDrawBorder =
            CNDTriggerMethodHasTypes(descriptor, "drawBorder", "B16@0:8")
                ? ((BOOL (*)(id, SEL))objc_msgSend)(
                      descriptor, sel_registerName("drawBorder"))
                : NO;
        BOOL observedTemplateVariant =
            CNDTriggerMethodHasTypes(
                descriptor, "templateVariant", "B16@0:8")
                ? ((BOOL (*)(id, SEL))objc_msgSend)(
                      descriptor, sel_registerName("templateVariant"))
                : NO;
        id descriptorDigest = CNDTriggerObjectGetter(descriptor, "digest");
        NSString *descriptorDigestText =
            [descriptorDigest respondsToSelector:@selector(UUIDString)]
                ? [descriptorDigest UUIDString]
                : [descriptorDigest isKindOfClass:NSString.class]
                    ? descriptorDigest : @"-";
        if (observedSize.width != (double)requestedPointSize ||
            observedSize.height != (double)requestedPointSize ||
            observedScale != 3.0 ||
            observedAppearance != requestedAppearance) {
            fprintf(stderr,
                    "Spotlight descriptor geometry readback mismatch "
                    "%.1fx%.1f@%.2f appearance=%lld/%lld\n",
                    observedSize.width, observedSize.height, observedScale,
                    (long long)observedAppearance,
                    (long long)requestedAppearance);
            return 3;
        }
        printf("CND_ICON_TRIGGER start pid=%d bundle=%s variant=%d "
               "factoryOptions=%d variantOptions=%llu/%llu "
               "appearanceVariant=%lld/%lld drawBorder=%d/%d "
               "templateVariant=%d/%d "
               "icon=%p/%s descriptor=%p/%s "
               "provider=%p/%s geometry=%.1fx%.1f@%.2f appearance=%lld "
               "digest=%s "
               "ignoreCache=%d factoryDescription=%s description=%s\n",
               getpid(), bundleIdentifier.UTF8String, requestedIconVariant,
               requestedFactoryOptions,
               (unsigned long long)requestedVariantOptions,
               (unsigned long long)observedVariantOptions,
               (long long)requestedAppearanceVariant,
               (long long)observedAppearanceVariant,
               requestedDrawBorder, observedDrawBorder,
               requestedTemplateVariant, observedTemplateVariant,
               (__bridge void *)icon,
               class_getName(object_getClass(icon)),
               (__bridge void *)descriptor,
               class_getName(object_getClass(descriptor)),
               (__bridge void *)provider,
               provider ? class_getName(object_getClass(provider)) : "-",
               observedSize.width, observedSize.height, observedScale,
               (long long)observedAppearance,
               descriptorDigestText.UTF8String,
               ignoreCache,
               factoryDescriptor
                   ? [[factoryDescriptor description] UTF8String] : "-",
               [[descriptor description] UTF8String]);
        fflush(stdout);
        if (inspectDescriptor) {
            CNDTriggerDumpClass(descriptor, "descriptor");
            CNDTriggerDumpClassMethods(descriptorClass, "descriptor");
            return 0;
        }

        id image = nil;
        if (ignoreCache) {
            if (!CNDTriggerMethodHasTypes(
                    icon, "generateImageWithDescriptor:",
                    "@24@0:8@16")) {
                fprintf(stderr,
                        "ISConcreteIcon generation ABI mismatch\n");
                return 3;
            }
            image = ((id (*)(id, SEL, id))objc_msgSend)(
                icon, sel_registerName("generateImageWithDescriptor:"),
                descriptor);
            printf("CND_ICON_TRIGGER direct-generation image=%p/%s\n",
                   (__bridge void *)image,
                   image ? class_getName(object_getClass(image)) : "-");
            fflush(stdout);
        } else if ([icon respondsToSelector:sel_registerName(
                "prepareImageForDescriptor:")]) {
            image = ((id (*)(id, SEL, id))objc_msgSend)(
                icon, sel_registerName("prepareImageForDescriptor:"),
                descriptor);
        }

        for (unsigned attempt = 1; attempt <= 12U; attempt++) {
            if (!image || strstr(class_getName(object_getClass(image)),
                                 "Placeholder")) {
                image = ((id (*)(id, SEL, id))objc_msgSend)(
                    icon, sel_registerName("imageForDescriptor:"),
                    descriptor);
            }
            const char *imageClass = image
                ? class_getName(object_getClass(image)) : "-";
            printf("CND_ICON_TRIGGER attempt=%u image=%p/%s\n",
                   attempt, (__bridge void *)image, imageClass);
            fflush(stdout);
            if (image && !strstr(imageClass, "Placeholder")) break;
            usleep(250000);
        }
        if (!image) return 4;
        id uuid = CNDTriggerObjectGetter(image, "uuid");
        id data = CNDTriggerObjectGetter(image, "data");
        id token = CNDTriggerObjectGetter(image, "validationToken");
        NSString *uuidText = [uuid respondsToSelector:@selector(UUIDString)]
            ? [uuid UUIDString] : @"-";
        NSData *imageData = [data isKindOfClass:NSData.class] ? data : nil;
        NSData *tokenData = [token isKindOfClass:NSData.class] ? token : nil;
        CGImageRef cgImage = NULL;
        SEL cgSelector = sel_registerName("CGImage");
        if ([image respondsToSelector:cgSelector]) {
            cgImage = ((CGImageRef (*)(id, SEL))objc_msgSend)(
                image, cgSelector);
        }
        size_t pixelWidth = cgImage ? CGImageGetWidth(cgImage) : 0U;
        size_t pixelHeight = cgImage ? CGImageGetHeight(cgImage) : 0U;
        NSData *rgba = CNDTriggerRGBAData(
            cgImage, pixelWidth, pixelHeight);
        CGImageRef referenceImage = CNDTriggerLoadCGImage(comparePath);
        NSData *referenceRGBA = referenceImage
            ? CNDTriggerRGBAData(referenceImage, pixelWidth, pixelHeight)
            : nil;
        if (referenceImage) CGImageRelease(referenceImage);
        bool pixelMatch = rgba && referenceRGBA &&
            [rgba isEqualToData:referenceRGBA];
        printf("CND_ICON_TRIGGER complete image=%p/%s uuid=%s "
               "data=%lu/%s token=%lu/%s pixels=%zux%zu rgba=%s "
               "referenceRGBA=%s pixelMatch=%d\n",
               (__bridge void *)image,
               class_getName(object_getClass(image)),
               uuidText.UTF8String ?: "-", (unsigned long)imageData.length,
               CNDTriggerSHA256(imageData).UTF8String,
               (unsigned long)tokenData.length,
               CNDTriggerSHA256(tokenData).UTF8String,
               pixelWidth, pixelHeight,
               CNDTriggerSHA256(rgba).UTF8String,
               CNDTriggerSHA256(referenceRGBA).UTF8String,
               pixelMatch);
        if (inspectLayer) {
            (void)dlopen(
                "/System/Library/PrivateFrameworks/IconRendering.framework/"
                "IconRendering", RTLD_NOW | RTLD_LOCAL);
            (void)dlopen(
                "/System/Library/PrivateFrameworks/CoreUI.framework/CoreUI",
                RTLD_NOW | RTLD_LOCAL);
            id finalizedClassProbe = [NSClassFromString(@"ICRFinalizedIcon")
                alloc];
            id iconLayerClassProbe = [NSClassFromString(@"ICRIconLayer")
                alloc];
            id renderingModeClassProbe =
                [NSClassFromString(@"ICRRenderingMode") alloc];
            id mutableStackClassProbe =
                [NSClassFromString(@"CUIMutableNamedIconLayerStack") alloc];
            id mutableImageClassProbe =
                [NSClassFromString(@"CUIMutableNamedLayerImage") alloc];
            id layerDataBefore = CNDTriggerObjectGetter(image, "layerData");
            id finalizedBefore = CNDTriggerObjectGetter(image,
                                                        "finalizedIcon");
            id iconLayer = CNDTriggerObjectGetter(image, "ICRIconLayer");
            id finalizedAfter = CNDTriggerObjectGetter(image,
                                                       "finalizedIcon");
            id caLayer = CNDTriggerObjectGetter(image, "CALayer");
            NSData *layerData = [layerDataBefore isKindOfClass:NSData.class]
                ? layerDataBefore : nil;
            BOOL layerWritten = dumpLayerPath.length && layerData
                ? [layerData writeToFile:dumpLayerPath atomically:NO] : NO;
            printf("CND_ICON_TRIGGER inspect-summary layerData=%p/%s "
                   "bytes=%lu sha256=%s finalizedBefore=%p/%s "
                   "finalizedAfter=%p/%s iconLayer=%p/%s CALayer=%p/%s\n",
                   (__bridge void *)layerDataBefore,
                   layerDataBefore
                       ? class_getName(object_getClass(layerDataBefore)) : "-",
                   (unsigned long)layerData.length,
                   CNDTriggerSHA256(layerData).UTF8String,
                   (__bridge void *)finalizedBefore,
                   finalizedBefore
                       ? class_getName(object_getClass(finalizedBefore)) : "-",
                   (__bridge void *)finalizedAfter,
                   finalizedAfter
                       ? class_getName(object_getClass(finalizedAfter)) : "-",
                   (__bridge void *)iconLayer,
                   iconLayer ? class_getName(object_getClass(iconLayer)) : "-",
                   (__bridge void *)caLayer,
                   caLayer ? class_getName(object_getClass(caLayer)) : "-");
            if (dumpLayerPath.length) {
                printf("CND_ICON_TRIGGER inspect-dump path=%s written=%d\n",
                       dumpLayerPath.UTF8String, layerWritten);
            }
            CNDTriggerDumpClass(image, "image");
            CNDTriggerDumpClass(finalizedAfter, "finalized");
            CNDTriggerDumpClass(iconLayer, "icon-layer");
            CNDTriggerDumpClass(finalizedClassProbe,
                                "finalized-class-probe");
            CNDTriggerDumpClass(iconLayerClassProbe,
                                "icon-layer-class-probe");
            CNDTriggerDumpClass(renderingModeClassProbe,
                                "rendering-mode-class-probe");
            CNDTriggerDumpClassMethods(NSClassFromString(@"ICRRenderingMode"),
                                       "rendering-mode-class-probe");
            CNDTriggerDumpClass(mutableStackClassProbe,
                                "mutable-stack-class-probe");
            CNDTriggerDumpClass(mutableImageClassProbe,
                                "mutable-image-class-probe");
            CNDTriggerDumpMatchingRuntime();
        }
        return 0;
    }
}
