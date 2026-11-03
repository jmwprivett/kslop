#import "CNDShareSheetTelemetry.h"

#import "../TaskRop/RemoteCall.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/krw.h"
#import "../kexploit/kutils.h"
#import "../kexploit/offsets.h"
#import "../tweaks/remote_objc.h"

#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <dlfcn.h>
#import <float.h>
#import <math.h>
#import <objc/runtime.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

typedef struct {
    NSUInteger pointWidth;
    NSUInteger pointHeight;
    NSUInteger scale;
    NSUInteger appearance;
    NSUInteger variantOptions;
    NSUInteger factoryOptions;
} CNDShareTelemetryDescriptorSpec;

typedef struct {
    uint64_t label;
    uint64_t cell;
    uint64_t imageView;
    uint64_t image;
    CGRect frame;
    char cellClass[96];
    char imageViewClass[96];
} CNDShareVisibleTile;

static NSString *CNDShareTelemetryHex(const uint8_t bytes[CC_SHA256_DIGEST_LENGTH])
{
    NSMutableString *result = [NSMutableString stringWithCapacity:64];
    for (NSUInteger index = 0; index < CC_SHA256_DIGEST_LENGTH; index++) {
        [result appendFormat:@"%02x", bytes[index]];
    }
    return result;
}

static BOOL CNDShareTelemetryLoadFramework(const char *path)
{
    uint64_t remotePath = r_alloc_str(path);
    if (!remotePath) return NO;
    uint64_t handle = r_dlsym_call(
        R_TIMEOUT, "dlopen", remotePath, RTLD_NOW | RTLD_LOCAL,
        0, 0, 0, 0, 0, 0);
    r_free(remotePath);
    return handle != 0 && remote_call_current_success();
}

static BOOL CNDShareTelemetryReadClassName(uint64_t object,
                                           char *output,
                                           size_t outputLength)
{
    if (output && outputLength) output[0] = '\0';
    if (!r_is_objc_ptr(object) || !output || outputLength < 2) return NO;
    uint64_t cls = r_dlsym_call(
        R_TIMEOUT, "object_getClass", object, 0, 0, 0, 0, 0, 0, 0);
    uint64_t name = cls ? r_dlsym_call(
        R_TIMEOUT, "class_getName", cls, 0, 0, 0, 0, 0, 0, 0) : 0;
    return name && r_read_cstring(name, output, outputLength);
}

static BOOL CNDShareTelemetryMethodEncodingIs(uint64_t method,
                                               const char *expected)
{
    uint64_t typeAddress = method ? r_dlsym_call(
        R_TIMEOUT, "method_getTypeEncoding", method,
        0, 0, 0, 0, 0, 0, 0) : 0;
    char observed[96] = {0};
    return typeAddress && expected &&
        r_read_cstring(typeAddress, observed, sizeof(observed)) &&
        strcmp(observed, expected) == 0;
}

static uint64_t CNDShareTelemetryMethod(uint64_t cls, const char *selectorName,
                                        BOOL classMethod)
{
    uint64_t selector = cls ? r_sel(selectorName) : 0;
    return selector ? r_dlsym_call(
        R_TIMEOUT,
        classMethod ? "class_getClassMethod" : "class_getInstanceMethod",
        cls, selector, 0, 0, 0, 0, 0, 0) : 0;
}

static BOOL CNDShareTelemetryMethodEncodingMatches(
    uint64_t cls, const char *selectorName, BOOL classMethod,
    const char *expected)
{
    return CNDShareTelemetryMethodEncodingIs(
        CNDShareTelemetryMethod(cls, selectorName, classMethod), expected);
}

static uint64_t CNDShareTelemetryDirectRetainedObject(
    uint64_t object, const char *selectorName,
    uint64_t argument0, uint64_t argument1,
    uint64_t argument2, uint64_t argument3)
{
    uint64_t value = r_msg2(
        object, selectorName,
        argument0, argument1, argument2, argument3);
    if (!r_is_objc_ptr(value) || !remote_call_current_success()) return 0;
    uint64_t retained = r_msg2(value, "retain", 0, 0, 0, 0);
    return retained == value && remote_call_current_success() ? value : 0;
}

static NSDictionary<NSString *, id> *CNDShareTelemetrySnapshotRemoteImage(
    uint64_t image)
{
    NSMutableDictionary<NSString *, id> *snapshot = [@{
        @"imagePointer": @(image),
        @"pixelWidth": @0,
        @"pixelHeight": @0,
        @"hashValid": @NO,
        @"rgbaSHA256": @"",
        @"pngLength": @0,
    } mutableCopy];
    if (!r_is_objc_ptr(image) || !r_responds(image, "CGImage")) {
        return snapshot;
    }

    uint64_t cgImage = r_msg2(image, "CGImage", 0, 0, 0, 0);
    uint64_t imageClass = cgImage ? r_class("UIImage") : 0;
    BOOL imageFactoryABI = imageClass &&
        CNDShareTelemetryMethodEncodingMatches(
            imageClass, "imageWithCGImage:", YES, "@24@0:8^{CGImage=}16");
    /* Some SDK/runtime builds spell the opaque CGImage argument as ^v. The
     * ABI is still one pointer-sized argument, so admit that exact spelling
     * while rejecting every other signature. */
    if (!imageFactoryABI && imageClass) {
        imageFactoryABI = CNDShareTelemetryMethodEncodingMatches(
            imageClass, "imageWithCGImage:", YES, "@24@0:8^v16");
    }
    uint64_t normalizedImage = imageFactoryABI
        ? CNDShareTelemetryDirectRetainedObject(
            imageClass, "imageWithCGImage:", cgImage, 0, 0, 0) : 0;
    uint64_t pngData = normalizedImage ? r_dlsym_call(
        R_TIMEOUT, "UIImagePNGRepresentation", normalizedImage,
        0, 0, 0, 0, 0, 0, 0) : 0;
    if (r_is_objc_ptr(pngData)) {
        pngData = r_msg2(pngData, "retain", 0, 0, 0, 0);
    }
    uint64_t length = r_is_objc_ptr(pngData) &&
        r_responds(pngData, "length")
        ? r_msg2(pngData, "length", 0, 0, 0, 0) : 0;
    uint64_t bytes = length > 0 && length <= (16U << 20) &&
        r_responds(pngData, "bytes")
        ? r_msg2(pngData, "bytes", 0, 0, 0, 0) : 0;
    NSMutableData *localPNG = bytes
        ? [NSMutableData dataWithLength:(NSUInteger)length] : nil;
    BOOL copied = localPNG && remote_read(
        bytes, localPNG.mutableBytes, localPNG.length);
    if (r_is_objc_ptr(pngData)) {
        r_msg2(pngData, "release", 0, 0, 0, 0);
    }
    if (r_is_objc_ptr(normalizedImage)) {
        r_msg2(normalizedImage, "release", 0, 0, 0, 0);
    }
    if (!copied) return snapshot;

    UIImage *decoded = [UIImage imageWithData:localPNG];
    CGImageRef localCGImage = decoded.CGImage;
    size_t width = localCGImage ? CGImageGetWidth(localCGImage) : 0;
    size_t height = localCGImage ? CGImageGetHeight(localCGImage) : 0;
    snapshot[@"pixelWidth"] = @(width);
    snapshot[@"pixelHeight"] = @(height);
    snapshot[@"pngLength"] = @(localPNG.length);
    if (!width || !height || width > 512U || height > 512U ||
        width > SIZE_MAX / 4U || height > SIZE_MAX / (width * 4U)) {
        return snapshot;
    }

    size_t bytesPerRow = width * 4U;
    NSMutableData *rgba = [NSMutableData dataWithLength:bytesPerRow * height];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef bitmap = rgba && colorSpace ? CGBitmapContextCreate(
        rgba.mutableBytes, width, height, 8U, bytesPerRow, colorSpace,
        (CGBitmapInfo)((uint32_t)kCGImageAlphaPremultipliedLast |
                       (uint32_t)kCGBitmapByteOrder32Big)) : NULL;
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    if (!bitmap) return snapshot;
    CGContextSetBlendMode(bitmap, kCGBlendModeCopy);
    CGContextDrawImage(bitmap, CGRectMake(0, 0, width, height), localCGImage);
    CGContextRelease(bitmap);

    uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(rgba.bytes, (CC_LONG)rgba.length, digest);
    snapshot[@"hashValid"] = @YES;
    snapshot[@"rgbaSHA256"] = CNDShareTelemetryHex(digest);
    return snapshot;
}

static BOOL CNDShareTelemetryDescriptorABI(uint64_t descriptorClass)
{
    return descriptorClass &&
        CNDShareTelemetryMethodEncodingMatches(
            descriptorClass, "imageDescriptorWithIconVariant:options:",
            YES, "@24@0:8i16i20") &&
        CNDShareTelemetryMethodEncodingMatches(
            descriptorClass, "copy", NO, "@16@0:8") &&
        CNDShareTelemetryMethodEncodingMatches(
            descriptorClass, "setSize:", NO,
            "v32@0:8{CGSize=dd}16") &&
        CNDShareTelemetryMethodEncodingMatches(
            descriptorClass, "setScale:", NO, "v24@0:8d16") &&
        CNDShareTelemetryMethodEncodingMatches(
            descriptorClass, "setAppearance:", NO, "v24@0:8q16") &&
        CNDShareTelemetryMethodEncodingMatches(
            descriptorClass, "setVariantOptions:", NO, "v24@0:8Q16") &&
        CNDShareTelemetryMethodEncodingMatches(
            descriptorClass, "setIgnoreCache:", NO, "v20@0:8B16") &&
        CNDShareTelemetryMethodEncodingMatches(
            descriptorClass, "size", NO, "{CGSize=dd}16@0:8") &&
        CNDShareTelemetryMethodEncodingMatches(
            descriptorClass, "scale", NO, "d16@0:8") &&
        CNDShareTelemetryMethodEncodingMatches(
            descriptorClass, "appearance", NO, "q16@0:8") &&
        CNDShareTelemetryMethodEncodingMatches(
            descriptorClass, "variantOptions", NO, "Q16@0:8") &&
        CNDShareTelemetryMethodEncodingMatches(
            descriptorClass, "ignoreCache", NO, "B16@0:8");
}

static uint64_t CNDShareTelemetryCreateDescriptor(
    uint64_t descriptorClass, const CNDShareTelemetryDescriptorSpec *spec,
    BOOL *exactOut)
{
    if (exactOut) *exactOut = NO;
    if (!spec || !CNDShareTelemetryDescriptorABI(descriptorClass) ||
        spec->variantOptions > INT32_MAX ||
        spec->factoryOptions > INT32_MAX) return 0;

    int32_t descriptorPreset = 0;
    int32_t factoryOptions = (int32_t)spec->factoryOptions;
    uint64_t factoryDescriptor = r_msg2_raw(
        descriptorClass, "imageDescriptorWithIconVariant:options:",
        &descriptorPreset, sizeof(descriptorPreset),
        &factoryOptions, sizeof(factoryOptions),
        NULL, 0, NULL, 0);
    uint64_t descriptor = factoryDescriptor
        ? r_msg2(factoryDescriptor, "copy", 0, 0, 0, 0) : 0;
    if (!r_is_objc_ptr(descriptor)) return 0;

    CGSize requestedSize = CGSizeMake(spec->pointWidth, spec->pointHeight);
    double requestedScale = (double)spec->scale;
    (void)r_msg2_raw(
        descriptor, "setSize:", &requestedSize, sizeof(requestedSize),
        NULL, 0, NULL, 0, NULL, 0);
    (void)r_msg2_raw(
        descriptor, "setScale:", &requestedScale, sizeof(requestedScale),
        NULL, 0, NULL, 0, NULL, 0);
    (void)r_msg2(
        descriptor, "setAppearance:", spec->appearance, 0, 0, 0);
    (void)r_msg2(
        descriptor, "setVariantOptions:", spec->variantOptions, 0, 0, 0);
    (void)r_msg2(descriptor, "setIgnoreCache:", 0, 0, 0, 0);

    CGSize observedSize = CGSizeZero;
    BOOL sizeKnown = r_msg2_struct_ret(
        descriptor, "size", &observedSize, sizeof(observedSize),
        NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    uint64_t scaleBits = r_msg2_raw(
        descriptor, "scale", NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    double observedScale = 0;
    memcpy(&observedScale, &scaleBits, sizeof(observedScale));
    uint64_t observedAppearance = r_msg2(
        descriptor, "appearance", 0, 0, 0, 0);
    uint64_t observedVariantOptions = r_msg2(
        descriptor, "variantOptions", 0, 0, 0, 0);
    BOOL observedIgnoreCache = (r_msg2(
        descriptor, "ignoreCache", 0, 0, 0, 0) & 1U) != 0;
    BOOL exact = sizeKnown &&
        observedSize.width == requestedSize.width &&
        observedSize.height == requestedSize.height &&
        observedScale == requestedScale &&
        observedAppearance == spec->appearance &&
        observedVariantOptions == spec->variantOptions &&
        !observedIgnoreCache && remote_call_current_success();
    if (exactOut) *exactOut = exact;
    if (!exact) {
        r_msg2(descriptor, "release", 0, 0, 0, 0);
        return 0;
    }
    return descriptor;
}

static void CNDShareTelemetryAddUnique(uint64_t *items, NSUInteger *count,
                                       NSUInteger capacity, uint64_t item)
{
    if (!items || !count || !r_is_objc_ptr(item) || *count >= capacity) {
        return;
    }
    for (NSUInteger index = 0; index < *count; index++) {
        if (items[index] == item) return;
    }
    items[(*count)++] = item;
}

static uint64_t CNDShareTelemetryRemoteCount(uint64_t collection,
                                             uint64_t maximum)
{
    if (!r_is_objc_ptr(collection) ||
        !r_responds_main(collection, "count")) return 0;
    uint64_t count = r_msg2_main(collection, "count", 0, 0, 0, 0);
    return MIN(count, maximum);
}

static uint64_t CNDShareTelemetryFindActivityProvider(
    const uint64_t *windows, NSUInteger windowCount,
    uint64_t *cacheOut, char *classOut, size_t classOutLength)
{
    if (cacheOut) *cacheOut = 0;
    if (classOut && classOutLength) classOut[0] = '\0';
    enum { CONTROLLER_CAPACITY = 128 };
    uint64_t controllers[CONTROLLER_CAPACITY] = {0};
    NSUInteger count = 0;
    for (NSUInteger index = 0; index < windowCount; index++) {
        uint64_t root = r_responds_main(windows[index], "rootViewController")
            ? r_msg2_main(windows[index], "rootViewController", 0, 0, 0, 0)
            : 0;
        CNDShareTelemetryAddUnique(
            controllers, &count, CONTROLLER_CAPACITY, root);
    }
    for (NSUInteger cursor = 0;
         cursor < count && cursor < CONTROLLER_CAPACITY &&
         remote_call_current_success(); cursor++) {
        uint64_t controller = controllers[cursor];
        char className[96] = {0};
        CNDShareTelemetryReadClassName(
            controller, className, sizeof(className));
        if (strstr(className, "UIActivityContentViewController")) {
            const char *providerSelectors[] = {
                "activityImageProvider", "_activityImageProvider",
            };
            for (NSUInteger selectorIndex = 0;
                 selectorIndex < sizeof(providerSelectors) /
                    sizeof(providerSelectors[0]); selectorIndex++) {
                const char *selector = providerSelectors[selectorIndex];
                if (!r_responds_main(controller, selector)) continue;
                uint64_t provider = r_msg2_main(
                    controller, selector, 0, 0, 0, 0);
                if (!r_is_objc_ptr(provider)) continue;
                if (classOut && classOutLength) {
                    CNDShareTelemetryReadClassName(
                        provider, classOut, classOutLength);
                }
                if (cacheOut && r_responds_main(provider, "imageCache")) {
                    *cacheOut = r_msg2_main(
                        provider, "imageCache", 0, 0, 0, 0);
                }
                return provider;
            }
        }

        const char *singleSelectors[] = {
            "presentedViewController", "contentViewController",
        };
        for (NSUInteger selectorIndex = 0;
             selectorIndex < sizeof(singleSelectors) /
                sizeof(singleSelectors[0]); selectorIndex++) {
            const char *selector = singleSelectors[selectorIndex];
            if (!r_responds_main(controller, selector)) continue;
            CNDShareTelemetryAddUnique(
                controllers, &count, CONTROLLER_CAPACITY,
                r_msg2_main(controller, selector, 0, 0, 0, 0));
        }
        const char *arraySelectors[] = {"children", "childViewControllers"};
        for (NSUInteger selectorIndex = 0;
             selectorIndex < sizeof(arraySelectors) /
                sizeof(arraySelectors[0]); selectorIndex++) {
            const char *selector = arraySelectors[selectorIndex];
            if (!r_responds_main(controller, selector)) continue;
            uint64_t children = r_msg2_main(
                controller, selector, 0, 0, 0, 0);
            uint64_t childCount = CNDShareTelemetryRemoteCount(children, 32);
            for (uint64_t childIndex = 0; childIndex < childCount; childIndex++) {
                CNDShareTelemetryAddUnique(
                    controllers, &count, CONTROLLER_CAPACITY,
                    r_msg2_main(children, "objectAtIndex:",
                                childIndex, 0, 0, 0));
            }
        }
    }
    return 0;
}

static BOOL CNDShareTelemetryFindVisibleTile(
    const uint64_t *windows, NSUInteger windowCount,
    CNDShareVisibleTile *tileOut)
{
    if (!tileOut) return NO;
    memset(tileOut, 0, sizeof(*tileOut));
    enum { VIEW_CAPACITY = 2048 };
    uint64_t views[VIEW_CAPACITY] = {0};
    NSUInteger viewCount = 0;
    for (NSUInteger index = 0; index < windowCount; index++) {
        CNDShareTelemetryAddUnique(
            views, &viewCount, VIEW_CAPACITY, windows[index]);
    }
    uint64_t labelClass = r_class("UILabel");
    for (NSUInteger cursor = 0;
         cursor < viewCount && cursor < VIEW_CAPACITY &&
         remote_call_current_success(); cursor++) {
        uint64_t view = views[cursor];
        BOOL isLabel = labelClass && r_responds_main(view, "isKindOfClass:") &&
            r_msg2_main(view, "isKindOfClass:", labelClass, 0, 0, 0);
        if (isLabel && r_responds_main(view, "text")) {
            uint64_t text = r_msg2_main(view, "text", 0, 0, 0, 0);
            char buffer[256] = {0};
            if (text && r_read_nsstring(text, buffer, sizeof(buffer)) &&
                [[NSString stringWithUTF8String:buffer]
                    localizedCaseInsensitiveContainsString:@"AirDrop"]) {
                tileOut->label = view;
                uint64_t ancestor = view;
                for (NSUInteger depth = 0; ancestor && depth < 10; depth++) {
                    char className[96] = {0};
                    CNDShareTelemetryReadClassName(
                        ancestor, className, sizeof(className));
                    if (strstr(className, "UIShareGroupActivityCell")) {
                        tileOut->cell = ancestor;
                        snprintf(tileOut->cellClass,
                                 sizeof(tileOut->cellClass), "%s", className);
                        break;
                    }
                    ancestor = r_responds_main(ancestor, "superview")
                        ? r_msg2_main(ancestor, "superview", 0, 0, 0, 0)
                        : 0;
                }
            }
        }
        if (tileOut->cell) break;
        if (!r_responds_main(view, "subviews")) continue;
        uint64_t children = r_msg2_main(view, "subviews", 0, 0, 0, 0);
        uint64_t childCount = CNDShareTelemetryRemoteCount(children, 128);
        for (uint64_t childIndex = 0; childIndex < childCount; childIndex++) {
            CNDShareTelemetryAddUnique(
                views, &viewCount, VIEW_CAPACITY,
                r_msg2_main(children, "objectAtIndex:",
                            childIndex, 0, 0, 0));
        }
    }
    if (!tileOut->cell) return NO;

    uint64_t imageViewClass = r_class("UIImageView");
    uint64_t descendants[256] = {0};
    NSUInteger descendantCount = 0;
    CNDShareTelemetryAddUnique(
        descendants, &descendantCount, 256, tileOut->cell);
    double bestScore = DBL_MAX;
    for (NSUInteger cursor = 0;
         cursor < descendantCount && cursor < 256 &&
         remote_call_current_success(); cursor++) {
        uint64_t view = descendants[cursor];
        BOOL isImageView = imageViewClass &&
            r_responds_main(view, "isKindOfClass:") &&
            r_msg2_main(view, "isKindOfClass:", imageViewClass, 0, 0, 0);
        if (isImageView && r_responds_main(view, "image")) {
            CGRect frame = CGRectZero;
            BOOL frameKnown = r_msg2_main_struct_ret(
                view, "frame", &frame, sizeof(frame),
                NULL, 0, NULL, 0, NULL, 0, NULL, 0);
            uint64_t image = r_msg2_main_retained_object(
                view, "image", 0, 0, 0, 0);
            uint64_t window = r_responds_main(view, "window")
                ? r_msg2_main(view, "window", 0, 0, 0, 0) : 0;
            double score = frameKnown
                ? fabs(frame.size.width - 72.0) +
                  fabs(frame.size.height - 72.0)
                : 1000.0;
            if (r_is_objc_ptr(image) && r_is_objc_ptr(window) &&
                score <= 8.0 && score < bestScore) {
                if (r_is_objc_ptr(tileOut->image)) {
                    r_msg2(tileOut->image, "release", 0, 0, 0, 0);
                }
                bestScore = score;
                tileOut->imageView = view;
                tileOut->image = image;
                tileOut->frame = frame;
                CNDShareTelemetryReadClassName(
                    view, tileOut->imageViewClass,
                    sizeof(tileOut->imageViewClass));
            } else if (r_is_objc_ptr(image)) {
                r_msg2(image, "release", 0, 0, 0, 0);
            }
        }
        if (!r_responds_main(view, "subviews")) continue;
        uint64_t children = r_msg2_main(view, "subviews", 0, 0, 0, 0);
        uint64_t childCount = CNDShareTelemetryRemoteCount(children, 64);
        for (uint64_t childIndex = 0; childIndex < childCount; childIndex++) {
            CNDShareTelemetryAddUnique(
                descendants, &descendantCount, 256,
                r_msg2_main(children, "objectAtIndex:",
                            childIndex, 0, 0, 0));
        }
    }
    return r_is_objc_ptr(tileOut->image);
}

static NSArray<NSNumber *> *CNDShareTelemetryWindows(void)
{
    uint64_t applicationClass = r_class("UIApplication");
    uint64_t application = applicationClass &&
        r_responds_main(applicationClass, "sharedApplication")
        ? r_msg2_main(applicationClass, "sharedApplication", 0, 0, 0, 0)
        : 0;
    uint64_t scenes = application &&
        r_responds_main(application, "connectedScenes")
        ? r_msg2_main(application, "connectedScenes", 0, 0, 0, 0)
        : 0;
    uint64_t sceneArray = scenes && r_responds_main(scenes, "allObjects")
        ? r_msg2_main(scenes, "allObjects", 0, 0, 0, 0) : scenes;
    uint64_t sceneCount = CNDShareTelemetryRemoteCount(sceneArray, 8);
    NSMutableArray<NSNumber *> *windows = [NSMutableArray array];
    for (uint64_t sceneIndex = 0;
         sceneIndex < sceneCount && windows.count < 16; sceneIndex++) {
        uint64_t scene = r_msg2_main(
            sceneArray, "objectAtIndex:", sceneIndex, 0, 0, 0);
        if (!r_is_objc_ptr(scene) || !r_responds_main(scene, "windows")) {
            continue;
        }
        uint64_t sceneWindows = r_msg2_main(
            scene, "windows", 0, 0, 0, 0);
        uint64_t count = CNDShareTelemetryRemoteCount(sceneWindows, 16);
        for (uint64_t windowIndex = 0;
             windowIndex < count && windows.count < 16; windowIndex++) {
            uint64_t window = r_msg2_main(
                sceneWindows, "objectAtIndex:", windowIndex, 0, 0, 0);
            if (r_is_objc_ptr(window)) [windows addObject:@(window)];
        }
    }
    return windows;
}

static NSString *CNDShareTelemetryRemoteText(uint64_t object)
{
    if (!r_is_objc_ptr(object)) return @"";
    uint64_t text = 0;
    if (r_responds(object, "UUIDString")) {
        text = CNDShareTelemetryDirectRetainedObject(
            object, "UUIDString", 0, 0, 0, 0);
    } else if (r_responds(object, "description")) {
        text = CNDShareTelemetryDirectRetainedObject(
            object, "description", 0, 0, 0, 0);
    }
    char buffer[256] = {0};
    NSString *result = text && r_read_nsstring(
        text, buffer, sizeof(buffer))
        ? ([NSString stringWithUTF8String:buffer] ?: @"") : @"";
    if (r_is_objc_ptr(text)) r_msg2(text, "release", 0, 0, 0, 0);
    return result;
}

static NSDictionary<NSString *, id> *CNDShareTelemetryProbeDescriptor(
    uint64_t icon, uint64_t descriptorClass,
    const CNDShareTelemetryDescriptorSpec *spec)
{
    if (!spec) return @{};
    NSString *identity = [NSString stringWithFormat:
        @"%lux%lu@%lu:a%lu:v%lu:o%lu",
        (unsigned long)spec->pointWidth,
        (unsigned long)spec->pointHeight,
        (unsigned long)spec->scale,
        (unsigned long)spec->appearance,
        (unsigned long)spec->variantOptions,
        (unsigned long)spec->factoryOptions];
    BOOL descriptorExact = NO;
    uint64_t descriptor = CNDShareTelemetryCreateDescriptor(
        descriptorClass, spec, &descriptorExact);
    uint64_t digest = descriptor && r_responds(descriptor, "digest")
        ? r_msg2(descriptor, "digest", 0, 0, 0, 0) : 0;
    NSString *digestText = CNDShareTelemetryRemoteText(digest);
    BOOL imageMethodABI = icon && CNDShareTelemetryMethodEncodingMatches(
        r_dlsym_call(R_TIMEOUT, "object_getClass", icon,
                     0, 0, 0, 0, 0, 0, 0),
        "imageForDescriptor:", NO, "@24@0:8@16");
    /* class_getInstanceMethod accepts a superclass too, but object_getClass
     * above gives us the concrete class whose dispatch will actually run. */
    uint64_t image = descriptorExact && imageMethodABI
        ? CNDShareTelemetryDirectRetainedObject(
            icon, "imageForDescriptor:", descriptor, 0, 0, 0) : 0;
    NSMutableDictionary<NSString *, id> *event =
        [CNDShareTelemetrySnapshotRemoteImage(image) mutableCopy];
    [event addEntriesFromDictionary:@{
        @"kind": @"image",
        @"observationMode": @"explicit-exact-descriptor-probe",
        @"descriptorIdentity": identity,
        @"pointWidth": @(spec->pointWidth),
        @"pointHeight": @(spec->pointHeight),
        @"scale": @(spec->scale),
        @"appearance": @(spec->appearance),
        @"iconVariant": @(spec->variantOptions),
        @"options": @(spec->factoryOptions),
        @"digest": digestText ?: @"",
        @"descriptorReadbackVerified": @(descriptorExact),
        @"imageMethodABIVerified": @(imageMethodABI),
    }];
    if (r_is_objc_ptr(image)) {
        r_msg2(image, "release", 0, 0, 0, 0);
    }
    if (r_is_objc_ptr(descriptor)) {
        r_msg2(descriptor, "release", 0, 0, 0, 0);
    }
    return event;
}


NSDictionary<NSString *, id> *CNDShareSheetTelemetryCapture(void)
{
    NSTimeInterval started = NSProcessInfo.processInfo.systemUptime;
    if (!kexploit_krw_ready() && !remote_call_lab_backend_opted_in()) {
        return @{
            @"ok": @NO,
            @"stage": @"krw-unavailable",
            @"message": @"Kernel read/write is required for the bounded data-only Share-sheet capture.",
            @"remoteCallUsed": @NO,
            @"temporaryMethodInterpositionUsed": @NO,
        };
    }

    static const char *processName = "SharingUIService";
    uint64_t expectedProc = 0;
    pid_t expectedPID = 0;
    uint64_t expectedTask = 0;
    for (NSUInteger attempt = 0; attempt < 60; attempt++) {
        expectedProc = proc_find_by_name(processName);
        expectedPID = is_kaddr_valid(expectedProc)
            ? (pid_t)kread32(expectedProc + off_proc_p_pid) : 0;
        expectedTask = is_kaddr_valid(expectedProc)
            ? proc_task(expectedProc) : 0;
        if (expectedPID > 1 && is_kaddr_valid(expectedTask)) break;
        usleep(50000);
    }
    if (expectedPID <= 1 || !is_kaddr_valid(expectedTask)) {
        return @{
            @"ok": @NO,
            @"stage": @"sharing-ui-unavailable",
            @"message": @"SharingUIService did not materialize while the diagnostic Share sheet was visible.",
            @"remoteCallUsed": @NO,
            @"temporaryMethodInterpositionUsed": @NO,
        };
    }

    if (!remote_call_lab_backend_opted_in()) {
        g_RC_targetProcOverride = expectedProc;
    }
    RemoteCallSession *session = [[RemoteCallSession alloc]
        initWithIdentityBootstrapProcess:@"SharingUIService"
        firstExceptionTimeoutMS:10000];
    g_RC_targetProcOverride = 0;
    if (!session) {
        return @{
            @"ok": @NO,
            @"stage": @"sharing-ui-session",
            @"message": @"The exact SharingUIService data-only telemetry session could not be opened.",
            @"pid": @(expectedPID),
            @"remoteCallUsed": @YES,
            @"temporaryMethodInterpositionUsed": @NO,
        };
    }

    BOOL identityBound = session.pid == expectedPID &&
        session.taskAddr == expectedTask &&
        proc_find(expectedPID) == expectedProc &&
        proc_task(expectedProc) == expectedTask;
    __block NSMutableDictionary<NSString *, id> *capture =
        [NSMutableDictionary dictionary];
    __block BOOL remoteOK = NO;
    __block BOOL captureComplete = NO;
    NSString *exceptionText = nil;

    if (identityBound) {
        @try {
            remote_call_with_session(session, ^{
                uint64_t pool = r_autorelease_pool_push();
                uint64_t targetIdentifier = 0;
                uint64_t localIcon = 0;
                uint64_t activity = 0;
                uint64_t identity = 0;
                uint64_t activityImage = 0;
                CNDShareVisibleTile tile = {0};
                do {
                    BOOL frameworksReady = pool &&
                        CNDShareTelemetryLoadFramework(
                            "/System/Library/PrivateFrameworks/IconServices.framework/IconServices") &&
                        CNDShareTelemetryLoadFramework(
                            "/System/Library/PrivateFrameworks/ShareSheet.framework/ShareSheet");
                    if (!frameworksReady) {
                        capture[@"stage"] = @"frameworks";
                        break;
                    }

                    uint64_t iconClass = r_class("ISBundleIdentifierIcon");
                    uint64_t descriptorClass = r_class("ISImageDescriptor");
                    uint64_t managerClass = r_class("ISIconManager");
                    BOOL iconABI = iconClass &&
                        CNDShareTelemetryMethodEncodingMatches(
                            iconClass, "initWithBundleIdentifier:", NO,
                            "@24@0:8@16") &&
                        CNDShareTelemetryMethodEncodingMatches(
                            iconClass, "imageForDescriptor:", NO,
                            "@24@0:8@16");
                    BOOL managerABI = managerClass &&
                        CNDShareTelemetryMethodEncodingMatches(
                            managerClass, "sharedInstance", YES,
                            "@16@0:8") &&
                        CNDShareTelemetryMethodEncodingMatches(
                            managerClass, "findOrRegisterIcon:", NO,
                            "@24@0:8@16");
                    BOOL descriptorABI =
                        CNDShareTelemetryDescriptorABI(descriptorClass);
                    if (!iconABI || !managerABI || !descriptorABI) {
                        capture[@"stage"] = @"data-only-method-abi";
                        capture[@"iconABIVerified"] = @(iconABI);
                        capture[@"managerABIVerified"] = @(managerABI);
                        capture[@"descriptorABIVerified"] = @(descriptorABI);
                        break;
                    }

                    /* The physical transport has KRW plus register-level
                     * calls, but target VM-object aliases are not a reliable
                     * byte-transfer primitive. Materialize this one bounded
                     * constant entirely inside SharingUIService. */
                    targetIdentifier = r_cfstr_register_only(
                        "com.apple.Sharing.AirDrop");
                    /* objc_msgSend("alloc") returned nil on the physical
                     * SharingUIService synthetic thread even though the class
                     * and its exact instance ABI were valid. Use libobjc's
                     * signed allocation entry point directly; it takes only
                     * the already-resolved Class register and requires no
                     * selector or cross-process byte transfer. */
                    uint64_t allocation = targetIdentifier
                        ? r_dlsym_call(
                            R_TIMEOUT, "objc_alloc", iconClass,
                            0, 0, 0, 0, 0, 0, 0) : 0;
                    uint64_t initializerSelector = allocation
                        ? r_sel("initWithBundleIdentifier:") : 0;
                    uint64_t initializerMethod = initializerSelector
                        ? CNDShareTelemetryMethod(
                            iconClass, "initWithBundleIdentifier:", NO) : 0;
                    uint64_t initializerIMP = initializerMethod
                        ? r_dlsym_call(
                            R_TIMEOUT, "method_getImplementation",
                            initializerMethod, 0, 0, 0, 0, 0, 0, 0) : 0;
                    localIcon = initializerIMP ? r_call_address(
                        R_TIMEOUT, initializerIMP,
                        "ISBundleIdentifierIcon.initWithBundleIdentifier:",
                        allocation, initializerSelector, targetIdentifier,
                        0, 0, 0, 0, 0) : 0;
                    uint64_t manager = localIcon ? r_msg2(
                        managerClass, "sharedInstance", 0, 0, 0, 0) : 0;
                    uint64_t probeIcon = manager ? r_msg2(
                        manager, "findOrRegisterIcon:",
                        localIcon, 0, 0, 0) : 0;
                    if (!r_is_objc_ptr(probeIcon)) probeIcon = localIcon;
                    capture[@"iconConstruction"] = @{
                        @"identifierPointer": @(targetIdentifier),
                        @"allocationPointer": @(allocation),
                        @"initializerMethodPointer": @(initializerMethod),
                        @"initializerIMPPointer": @(initializerIMP),
                        @"localIconPointer": @(localIcon),
                        @"managerPointer": @(manager),
                        @"probeIconPointer": @(probeIcon),
                        @"allocationTransport": @"objc_alloc",
                        @"initializerTransport": @"direct-verified-imp",
                        @"remoteCallHealthy": @(
                            remote_call_current_success()),
                    };
                    if (!r_is_objc_ptr(probeIcon)) {
                        capture[@"stage"] = !targetIdentifier
                            ? @"data-only-identifier"
                            : (!allocation
                                ? @"data-only-icon-allocation"
                                : @"data-only-icon-initialization");
                        break;
                    }

                    static const CNDShareTelemetryDescriptorSpec specs[] = {
                        {64U, 64U, 3U, 0U, 0U, 0U},
                        {28U, 28U, 3U, 0U, 4U, 0U},
                    };
                    NSMutableArray<NSDictionary *> *events =
                        [NSMutableArray arrayWithCapacity:2];
                    for (NSUInteger index = 0;
                         index < sizeof(specs) / sizeof(specs[0]); index++) {
                        NSDictionary *event = CNDShareTelemetryProbeDescriptor(
                            probeIcon, descriptorClass, &specs[index]);
                        if (event.count) [events addObject:event];
                    }
                    capture[@"events"] = events;
                    capture[@"eventCount"] = @(events.count);
                    capture[@"overflowCount"] = @0;

                    uint64_t activityClass = r_class("UIAirDropActivity");
                    BOOL activityABI = activityClass &&
                        CNDShareTelemetryMethodEncodingMatches(
                            activityClass,
                            "_bundleIdentifierForActivityImageCreation",
                            NO, "@16@0:8") &&
                        CNDShareTelemetryMethodEncodingMatches(
                            activityClass, "_activityImage", NO,
                            "@16@0:8");
                    if (activityABI) {
                        activity = r_msg2(activityClass, "alloc", 0, 0, 0, 0);
                        activity = activity ? r_msg2_main(
                            activity, "init", 0, 0, 0, 0) : 0;
                        identity = activity
                            ? r_msg2_main_retained_object(
                                activity,
                                "_bundleIdentifierForActivityImageCreation",
                                0, 0, 0, 0) : 0;
                    }
                    char identityText[192] = {0};
                    BOOL identityVerified = identity && r_read_nsstring(
                        identity, identityText, sizeof(identityText)) &&
                        strcmp(identityText,
                               "com.apple.Sharing.AirDrop") == 0;
                    activityImage = identityVerified
                        ? r_msg2_main_retained_object(
                            activity, "_activityImage", 0, 0, 0, 0) : 0;
                    NSDictionary *activitySnapshot =
                        CNDShareTelemetrySnapshotRemoteImage(activityImage);
                    capture[@"activityIdentity"] = identityText[0]
                        ? ([NSString stringWithUTF8String:identityText] ?: @"")
                        : @"";
                    capture[@"activityIdentityVerified"] =
                        @(identityVerified);
                    capture[@"activityImage"] = activitySnapshot;

                    NSArray<NSNumber *> *windowNumbers =
                        CNDShareTelemetryWindows();
                    uint64_t windows[16] = {0};
                    NSUInteger windowCount = MIN(
                        windowNumbers.count, (NSUInteger)16);
                    for (NSUInteger index = 0;
                         index < windowCount; index++) {
                        windows[index] =
                            windowNumbers[index].unsignedLongLongValue;
                    }
                    char providerClass[96] = {0};
                    uint64_t providerCache = 0;
                    uint64_t provider = CNDShareTelemetryFindActivityProvider(
                        windows, windowCount, &providerCache,
                        providerClass, sizeof(providerClass));
                    BOOL tileFound = CNDShareTelemetryFindVisibleTile(
                        windows, windowCount, &tile);
                    NSDictionary *displayedSnapshot =
                        CNDShareTelemetrySnapshotRemoteImage(tile.image);
                    capture[@"displayedImage"] = displayedSnapshot;
                    capture[@"windowCount"] = @(windowCount);
                    capture[@"activityProviderPointer"] = @(provider);
                    capture[@"activityProviderClass"] = providerClass[0]
                        ? ([NSString stringWithUTF8String:providerClass] ?: @"")
                        : @"";
                    capture[@"activityProviderCachePointer"] =
                        @(providerCache);
                    capture[@"visibleTileFound"] = @(tileFound);
                    capture[@"visibleTile"] = @{
                        @"labelPointer": @(tile.label),
                        @"cellPointer": @(tile.cell),
                        @"cellClass": tile.cellClass[0]
                            ? ([NSString stringWithUTF8String:tile.cellClass]
                                ?: @"") : @"",
                        @"imageViewPointer": @(tile.imageView),
                        @"imageViewClass": tile.imageViewClass[0]
                            ? ([NSString stringWithUTF8String:
                                tile.imageViewClass] ?: @"") : @"",
                        @"frame": @{
                            @"x": @(tile.frame.origin.x),
                            @"y": @(tile.frame.origin.y),
                            @"width": @(tile.frame.size.width),
                            @"height": @(tile.frame.size.height),
                        },
                    };

                    BOOL descriptorEvidence = events.count == 2;
                    for (NSDictionary *event in events) {
                        descriptorEvidence = descriptorEvidence &&
                            [event[@"descriptorReadbackVerified"] boolValue] &&
                            [event[@"imageMethodABIVerified"] boolValue] &&
                            [event[@"hashValid"] boolValue];
                    }
                    captureComplete = descriptorEvidence &&
                        identityVerified &&
                        [activitySnapshot[@"hashValid"] boolValue] &&
                        tileFound &&
                        [displayedSnapshot[@"hashValid"] boolValue];
                    capture[@"stage"] = captureComplete
                        ? @"captured" : @"data-only-evidence-incomplete";
                } while (0);

                if (r_is_objc_ptr(tile.image)) {
                    r_msg2(tile.image, "release", 0, 0, 0, 0);
                }
                if (r_is_objc_ptr(activityImage)) {
                    r_msg2(activityImage, "release", 0, 0, 0, 0);
                }
                if (r_is_objc_ptr(identity)) {
                    r_msg2(identity, "release", 0, 0, 0, 0);
                }
                if (r_is_objc_ptr(activity)) {
                    r_msg2(activity, "release", 0, 0, 0, 0);
                }
                if (r_is_objc_ptr(localIcon)) {
                    r_msg2(localIcon, "release", 0, 0, 0, 0);
                }
                if (r_is_objc_ptr(targetIdentifier)) {
                    r_msg2(targetIdentifier, "release", 0, 0, 0, 0);
                }
                if (pool && remote_call_current_success()) {
                    (void)r_autorelease_pool_pop(pool);
                }
                remoteOK = remote_call_current_success();
            });
        } @catch (NSException *exception) {
            exceptionText = [NSString stringWithFormat:@"%@:%@",
                exception.name ?: @"exception",
                exception.reason ?: @"unknown"];
            remoteOK = NO;
        }
    }

    if ([session hasLocalState] && ![session hasInFlightSyntheticCall]) {
        (void)[session destroyRemoteCall];
    }
    BOOL teardownDeferred = NO;
    if ([session hasInFlightSyntheticCall]) {
        teardownDeferred = [session deferTeardownForInFlightSyntheticCall];
    }
    BOOL closed = ![session hasLocalState];
    BOOL finalIdentityStable = proc_find(expectedPID) == expectedProc &&
        proc_task(expectedProc) == expectedTask;
    BOOL ok = identityBound && captureComplete && remoteOK && closed &&
        !teardownDeferred && finalIdentityStable;

    capture[@"ok"] = @(ok);
    capture[@"stage"] = ok ? @"airdrop-data-only-captured" :
        (capture[@"stage"] ?: @"airdrop-data-only-capture");
    capture[@"message"] = ok
        ? @"The two exact AirDrop IconServices descriptors, UIAirDropActivity image, and materialized Share-sheet tile were captured through existing signed code only."
        : @"The data-only AirDrop capture did not obtain complete descriptor, provider, and visible-tile pixel evidence.";
    capture[@"pid"] = @(expectedPID);
    capture[@"identityBound"] = @(identityBound);
    capture[@"finalIdentityStable"] = @(finalIdentityStable);
    capture[@"remoteOK"] = @(remoteOK);
    capture[@"closed"] = @(closed);
    capture[@"teardownDeferred"] = @(teardownDeferred);
    capture[@"exception"] = exceptionText ?: @"";
    capture[@"remoteCallUsed"] = @YES;
    capture[@"captureMode"] = @"data-only-existing-signed-code";
    capture[@"naturalDescriptorInterceptionUsed"] = @NO;
    capture[@"temporaryMethodInterpositionUsed"] = @NO;
    capture[@"temporaryHooksRestored"] = @YES;
    capture[@"temporaryHooksQuiesced"] = @YES;
    capture[@"failedRestoreCleanup"] = @{};
    capture[@"payloadMapped"] = @NO;
    capture[@"mappingCleaned"] = @YES;
    capture[@"mappingCleanupRequired"] = @NO;
    capture[@"elapsedMilliseconds"] = @(
        (NSProcessInfo.processInfo.systemUptime - started) * 1000.0);
    return capture;
}
