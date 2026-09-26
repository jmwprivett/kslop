#import <Foundation/Foundation.h>

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef CND_ICON_THEME_PATH
#define CND_ICON_THEME_PATH "/var/tmp/cnd-iconservices-theme.png"
#endif

#ifndef CND_ICON_THEME_OUTPUT_TOKEN
#define CND_ICON_THEME_OUTPUT_TOKEN ""
#endif

#ifndef CND_ICON_THEME_ROOT_TOKEN
#define CND_ICON_THEME_ROOT_TOKEN ""
#endif

#ifndef CND_ICON_THEME_OPAQUE_BLACK
#define CND_ICON_THEME_OPAQUE_BLACK 0
#endif

#ifndef CND_ICON_THEME_TARGET_BUNDLE
#define CND_ICON_THEME_TARGET_BUNDLE "com.ebay.iphone"
#endif

#ifndef CND_ICON_THEME_POINT_SIZE
#define CND_ICON_THEME_POINT_SIZE 68
#endif

#ifndef CND_ICON_THEME_APPEARANCE
#define CND_ICON_THEME_APPEARANCE 0
#endif

#ifndef CND_ICON_THEME_VARIANT_OPTIONS
#define CND_ICON_THEME_VARIANT_OPTIONS 0
#endif

#ifndef CND_ICON_THEME_PIXEL_SIZE
#define CND_ICON_THEME_PIXEL_SIZE 204
#endif

static const char *const CNDThemeOutputPath =
    "/var/tmp/cyanide-iconservices-theme-cache.log";
static const char *const CNDThemeExpectedSourceSHA256 =
    "74122c8aa948fc4e2d9d02148f62b88b8e4c77b1727cd34cf5632f9c6bbdca8b";
static const char *const CNDThemeTargetBundle = CND_ICON_THEME_TARGET_BUNDLE;

typedef struct {
    double width;
    double height;
} CNDThemeSize;

static int gCNDThemeFD = -1;
static CGImageRef gCNDThemeCGImage;
static Method gCNDGenerateMethod;
static IMP gCNDOriginalGenerate;
static unsigned gCNDAppliedCount;

static void CNDThemeLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDThemeLog(const char *format, ...)
{
    if (gCNDThemeFD < 0) return;
    char line[4096] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = MIN((size_t)length, sizeof(line) - 1U);
    (void)write(gCNDThemeFD, line, amount);
    (void)fsync(gCNDThemeFD);
}

static NSString *CNDThemeSHA256(NSData *data)
{
    if (!data) return @"-";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *text = [NSMutableString stringWithCapacity:64U];
    for (size_t i = 0; i < sizeof(digest); i++) {
        [text appendFormat:@"%02x", digest[i]];
    }
    return text;
}

static NSData *CNDThemeRGBAData(CGImageRef image, size_t width,
                                size_t height)
{
    if (!image || !width || !height || width > SIZE_MAX / 4U ||
        height > SIZE_MAX / (width * 4U)) return nil;
    NSMutableData *pixels = [NSMutableData dataWithLength:width * height * 4U];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = colorSpace
        ? CGBitmapContextCreate(
              pixels.mutableBytes, width, height, 8U, width * 4U,
              colorSpace, kCGImageAlphaPremultipliedLast |
                  kCGBitmapByteOrder32Big)
        : NULL;
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    if (!context) return nil;
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextDrawImage(context, CGRectMake(0.0, 0.0, width, height), image);
    CGContextRelease(context);
    return pixels;
}

static CGImageRef CNDThemeCreateInverseAlphaMask(CGImageRef image)
{
    size_t width = image ? CGImageGetWidth(image) : 0U;
    size_t height = image ? CGImageGetHeight(image) : 0U;
    NSData *sourceData = CNDThemeRGBAData(image, width, height);
    if (!width || !height || sourceData.length != width * height * 4U) {
        return NULL;
    }
    NSMutableData *maskData = [NSMutableData dataWithLength:sourceData.length];
    const uint8_t *source = sourceData.bytes;
    uint8_t *mask = maskData.mutableBytes;
    for (size_t index = 0U; index < width * height; index++) {
        size_t offset = index * 4U;
        uint8_t inverseAlpha = UINT8_MAX - source[offset + 3U];
        mask[offset] = 0U;
        mask[offset + 1U] = 0U;
        mask[offset + 2U] = 0U;
        mask[offset + 3U] = inverseAlpha;
    }
    CGDataProviderRef provider = CGDataProviderCreateWithCFData(
        (__bridge CFDataRef)maskData);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGImageRef maskImage = provider && colorSpace
        ? CGImageCreate(width, height, 8U, 32U, width * 4U, colorSpace,
                        kCGImageAlphaPremultipliedLast |
                            kCGBitmapByteOrder32Big,
                        provider, NULL, false,
                        kCGRenderingIntentDefault)
        : NULL;
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    if (provider) CGDataProviderRelease(provider);
    return maskImage;
}

static void CNDThemeLogRenderedProbe(CGImageRef rendered,
                                     const char *label)
{
    const size_t width = gCNDThemeCGImage
        ? CGImageGetWidth(gCNDThemeCGImage) : 0U;
    const size_t height = gCNDThemeCGImage
        ? CGImageGetHeight(gCNDThemeCGImage) : 0U;
    NSData *sourceData = CNDThemeRGBAData(gCNDThemeCGImage, width, height);
    NSData *renderedData = CNDThemeRGBAData(rendered, width, height);
    if (sourceData.length != width * height * 4U ||
        renderedData.length != width * height * 4U) {
        CNDThemeLog("[CND_ICON_THEME] rendered-probe label=%s failed=rgba "
                    "source=%lu rendered=%lu\n", label ?: "-",
                    (unsigned long)sourceData.length,
                    (unsigned long)renderedData.length);
        return;
    }
    const uint8_t *source = sourceData.bytes;
    const uint8_t *pixels = renderedData.bytes;
    uint64_t red = 0U;
    uint64_t green = 0U;
    uint64_t blue = 0U;
    uint64_t alpha = 0U;
    uint8_t minimumAlpha = UINT8_MAX;
    uint8_t maximumAlpha = 0U;
    size_t sourceTransparent = 0U;
    size_t outputTransparent = 0U;
    size_t outputTranslucent = 0U;
    size_t outputOpaque = 0U;
    size_t exposed = 0U;
    size_t purpleDominant = 0U;
    for (size_t y = 20U; y < height - 20U; y++) {
        for (size_t x = 20U; x < width - 20U; x++) {
            size_t offset = (y * width + x) * 4U;
            if (source[offset + 3U] > 4U) {
                continue;
            }
            sourceTransparent++;
            uint8_t renderedAlpha = pixels[offset + 3U];
            minimumAlpha = MIN(minimumAlpha, renderedAlpha);
            maximumAlpha = MAX(maximumAlpha, renderedAlpha);
            if (renderedAlpha <= 4U) {
                outputTransparent++;
                continue;
            }
            if (renderedAlpha >= 250U) {
                outputOpaque++;
            } else {
                outputTranslucent++;
            }
            red += pixels[offset];
            green += pixels[offset + 1U];
            blue += pixels[offset + 2U];
            alpha += renderedAlpha;
            if (pixels[offset + 2U] > pixels[offset] + 20U &&
                pixels[offset + 2U] > pixels[offset + 1U] + 20U) {
                purpleDominant++;
            }
            exposed++;
        }
    }
    CNDThemeLog("[CND_ICON_THEME] rendered-probe label=%s object=%p "
                "pixels=%zux%zu rgba=%s exposed=%zu "
                "sourceTransparent=%zu outputTransparent=%zu "
                "outputTranslucent=%zu outputOpaque=%zu alphaRange=%u-%u "
                "average=%llu,%llu,%llu,%llu purpleDominant=%zu/%zu\n",
                label ?: "-", rendered, width, height,
                CNDThemeSHA256(renderedData).UTF8String, exposed,
                sourceTransparent, outputTransparent, outputTranslucent,
                outputOpaque,
                sourceTransparent ? (unsigned)minimumAlpha : 0U,
                (unsigned)maximumAlpha,
                (unsigned long long)(exposed ? red / exposed : 0U),
                (unsigned long long)(exposed ? green / exposed : 0U),
                (unsigned long long)(exposed ? blue / exposed : 0U),
                (unsigned long long)(exposed ? alpha / exposed : 0U),
                purpleDominant, exposed);
}

static const char *CNDThemeSkipQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static bool CNDThemeMethodHasTypes(id object, const char *name,
                                   const char *expected)
{
    if (!object || !name || !expected) return false;
    Method method = class_getInstanceMethod(
        object_getClass(object), sel_registerName(name));
    return method && method_getTypeEncoding(method) &&
        strcmp(method_getTypeEncoding(method), expected) == 0;
}

static id CNDThemeObjectGetter(id object, const char *name)
{
    if (!object || !name) return nil;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDThemeSkipQualifiers(returnType);
    bool objectReturn = type && (*type == '@' || *type == '#');
    free(returnType);
    if (!objectReturn) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static bool CNDThemeFinalizedChicletFlagAddress(id finalizedIcon,
                                                uint8_t **addressOut,
                                                size_t *instanceSizeOut)
{
    Class cls = finalizedIcon ? object_getClass(finalizedIcon) : Nil;
    if (!cls || strcmp(class_getName(cls), "ICRFinalizedIcon") != 0) {
        return false;
    }
    Ivar storage = class_getInstanceVariable(cls, "finalizedIcon");
    ptrdiff_t storageOffset = storage ? ivar_getOffset(storage) : -1;
    size_t instanceSize = class_getInstanceSize(cls);
    /*
     * iOS 26 IconRendering stores its inline Swift FinalizedIcon value in
     * this ObjC wrapper. FinalizedIcon.Configuration starts at +0x20 in
     * that value, and Icon.chicletIsVisible is the byte at +0x90 in the
     * configuration. Validate every enclosing runtime fact before touching
     * the byte, then validate it again after ICRIconLayer deserialization.
     */
    const size_t configurationOffset = 0x20U;
    const size_t chicletFlagOffset = 0x90U;
    if (storageOffset != 8 || instanceSize <=
            (size_t)storageOffset + configurationOffset +
                chicletFlagOffset) {
        return false;
    }
    uint8_t *address = (uint8_t *)(__bridge void *)finalizedIcon +
        (size_t)storageOffset + configurationOffset + chicletFlagOffset;
    if (addressOut) *addressOut = address;
    if (instanceSizeOut) *instanceSizeOut = instanceSize;
    return true;
}

static bool CNDThemeReadFinalizedChicletVisible(id finalizedIcon,
                                                bool *visibleOut)
{
    uint8_t *address = NULL;
    if (!CNDThemeFinalizedChicletFlagAddress(finalizedIcon, &address, NULL) ||
        *address > 1U) {
        return false;
    }
    if (visibleOut) *visibleOut = *address != 0U;
    return true;
}

static bool CNDThemeInterestingRuntimeName(const char *name)
{
    if (!name) return false;
    static const char *const fragments[] = {
        "chiclet", "Chiclet", "visible", "Visible", "style", "Style",
        "config", "Config", "display", "Display", "icon", "Icon",
        "layer", "Layer", "effect", "Effect", "glass", "Glass",
        "specular", "Specular", "opacity", "Opacity", "blend", "Blend",
    };
    for (size_t index = 0U;
         index < sizeof(fragments) / sizeof(fragments[0]); index++) {
        if (strstr(name, fragments[index])) return true;
    }
    return false;
}

static void CNDThemeInspectRuntimeObject(id object, const char *label)
{
    if (!object) {
        CNDThemeLog("[CND_ICON_THEME] inspect-object label=%s object=nil\n",
                    label ?: "-");
        return;
    }
    Class cls = object_getClass(object);
    CNDThemeLog("[CND_ICON_THEME] inspect-object label=%s object=%p class=%s\n",
                label ?: "-", (__bridge void *)object,
                cls ? class_getName(cls) : "-");
    for (Class current = cls; current; current = class_getSuperclass(current)) {
        unsigned methodCount = 0U;
        Method *methods = class_copyMethodList(current, &methodCount);
        for (unsigned index = 0U; index < methodCount; index++) {
            const char *name = sel_getName(method_getName(methods[index]));
            if (CNDThemeInterestingRuntimeName(name)) {
                CNDThemeLog("[CND_ICON_THEME] inspect-method label=%s "
                            "class=%s selector=%s types=%s\n",
                            label ?: "-", class_getName(current), name,
                            method_getTypeEncoding(methods[index]) ?: "-");
            }
        }
        free(methods);
        unsigned propertyCount = 0U;
        objc_property_t *properties =
            class_copyPropertyList(current, &propertyCount);
        for (unsigned index = 0U; index < propertyCount; index++) {
            const char *name = property_getName(properties[index]);
            if (CNDThemeInterestingRuntimeName(name)) {
                CNDThemeLog("[CND_ICON_THEME] inspect-property label=%s "
                            "class=%s name=%s attributes=%s\n",
                            label ?: "-", class_getName(current), name,
                            property_getAttributes(properties[index]) ?: "-");
            }
        }
        free(properties);
        unsigned ivarCount = 0U;
        Ivar *ivars = class_copyIvarList(current, &ivarCount);
        for (unsigned index = 0U; index < ivarCount; index++) {
            const char *name = ivar_getName(ivars[index]);
            CNDThemeLog("[CND_ICON_THEME] inspect-ivar label=%s class=%s "
                        "name=%s type=%s offset=%td\n",
                        label ?: "-", class_getName(current), name ?: "-",
                        ivar_getTypeEncoding(ivars[index]) ?: "-",
                        ivar_getOffset(ivars[index]));
        }
        free(ivars);
    }
}

static bool CNDThemeReadDescriptorGeometry(id descriptor,
                                           CNDThemeSize *sizeOut,
                                           double *scaleOut)
{
    if (!CNDThemeMethodHasTypes(
            descriptor, "size", "{CGSize=dd}16@0:8") ||
        !CNDThemeMethodHasTypes(descriptor, "scale", "d16@0:8")) {
        return false;
    }
    CNDThemeSize size = ((CNDThemeSize (*)(id, SEL))objc_msgSend)(
        descriptor, sel_registerName("size"));
    double scale = ((double (*)(id, SEL))objc_msgSend)(
        descriptor, sel_registerName("scale"));
    if (sizeOut) *sizeOut = size;
    if (scaleOut) *scaleOut = scale;
    return true;
}

static bool CNDThemeReadDescriptorMetadata(id descriptor,
                                           int64_t *appearanceOut,
                                           uint64_t *variantOptionsOut)
{
    if (!CNDThemeMethodHasTypes(descriptor, "appearance", "q16@0:8") ||
        !CNDThemeMethodHasTypes(
            descriptor, "variantOptions", "Q16@0:8")) {
        return false;
    }
    int64_t appearance = ((int64_t (*)(id, SEL))objc_msgSend)(
        descriptor, sel_registerName("appearance"));
    uint64_t variantOptions = ((uint64_t (*)(id, SEL))objc_msgSend)(
        descriptor, sel_registerName("variantOptions"));
    if (appearanceOut) *appearanceOut = appearance;
    if (variantOptionsOut) *variantOptionsOut = variantOptions;
    return true;
}

static CGImageRef CNDThemeLoadImage(void)
{
    NSData *sourceData = [NSData dataWithContentsOfFile:
        @CND_ICON_THEME_PATH options:NSDataReadingMappedIfSafe error:nil];
    NSString *sourceHash = CNDThemeSHA256(sourceData);
    if (!sourceData || ![sourceHash isEqualToString:
            @(CNDThemeExpectedSourceSHA256)]) {
        CNDThemeLog("[CND_ICON_THEME] source-invalid path=%s bytes=%lu "
                    "sha256=%s expected=%s\n", CND_ICON_THEME_PATH,
                    (unsigned long)sourceData.length,
                    sourceHash.UTF8String,
                    CNDThemeExpectedSourceSHA256);
        return NULL;
    }
    CGImageSourceRef source = CGImageSourceCreateWithData(
        (__bridge CFDataRef)sourceData, NULL);
    CGImageRef decoded = source
        ? CGImageSourceCreateImageAtIndex(source, 0U, NULL) : NULL;
    if (source) CFRelease(source);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    const size_t outputPixels = (size_t)CND_ICON_THEME_PIXEL_SIZE;
    CGContextRef context = decoded && colorSpace && outputPixels > 0U
        ? CGBitmapContextCreate(
            NULL, outputPixels, outputPixels, 8U, outputPixels * 4U,
            colorSpace,
            kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big)
        : NULL;
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    if (context) {
        if (CND_ICON_THEME_OPAQUE_BLACK) {
            CGContextSetRGBFillColor(context, 0.0, 0.0, 0.0, 1.0);
            CGContextFillRect(context,
                              CGRectMake(0.0, 0.0, outputPixels,
                                         outputPixels));
            CGContextSetBlendMode(context, kCGBlendModeNormal);
        } else {
            CGContextClearRect(context,
                               CGRectMake(0.0, 0.0, outputPixels,
                                          outputPixels));
            CGContextSetBlendMode(context, kCGBlendModeCopy);
        }
        CGContextSetInterpolationQuality(context, kCGInterpolationHigh);
        CGContextDrawImage(
            context, CGRectMake(0.0, 0.0, outputPixels, outputPixels),
            decoded);
    }
    CGImageRef image = context ? CGBitmapContextCreateImage(context) : NULL;
    if (context) CGContextRelease(context);
    if (decoded) CGImageRelease(decoded);
    size_t width = image ? CGImageGetWidth(image) : 0U;
    size_t height = image ? CGImageGetHeight(image) : 0U;
    CNDThemeLog("[CND_ICON_THEME] source-ready path=%s bytes=%lu sha256=%s "
                "pixels=%zux%zu alpha=%u flatten=%s\n", CND_ICON_THEME_PATH,
                (unsigned long)sourceData.length, sourceHash.UTF8String,
                width, height,
                image ? (unsigned)CGImageGetAlphaInfo(image) : 0U,
                CND_ICON_THEME_OPAQUE_BLACK ? "opaque-black" : "none");
    if (width != outputPixels || height != outputPixels) {
        if (image) CGImageRelease(image);
        return NULL;
    }
    return image;
}

static NSData *CNDThemeMakeLayerData(double scale)
{
    static NSString *const CNDThemeLayerMarker = @"CNDThemeIcon.v1";
    Class stackClass = NSClassFromString(@"CUIMutableNamedIconLayerStack");
    Class colorClass = NSClassFromString(@"CUIMutableNamedColor");
    Class groupClass = NSClassFromString(@"CUIMutableNamedIconLayerGroup");
    Class layerClass = NSClassFromString(@"CUIMutableNamedLayerImage");
    Class renderingModeClass = NSClassFromString(@"ICRRenderingMode");
    Class effectPresetClass = NSClassFromString(@"CUIShapeEffectPreset");
    CNDThemeInspectRuntimeObject(effectPresetClass,
                                 "shape-effect-preset-class");
    id stackAllocation = stackClass ? [stackClass alloc] : nil;
    id chiclet = colorClass ? [[colorClass alloc] init] : nil;
    id group = groupClass ? [[groupClass alloc] init] : nil;
    id eraserGroup = groupClass ? [[groupClass alloc] init] : nil;
    id layer = layerClass ? [[layerClass alloc] init] : nil;
    id eraserLayer = layerClass ? [[layerClass alloc] init] : nil;
    CGImageRef inverseAlphaMask = CNDThemeCreateInverseAlphaMask(
        gCNDThemeCGImage);
    CNDThemeSize pointSize = {
        CND_ICON_THEME_POINT_SIZE, CND_ICON_THEME_POINT_SIZE,
    };
    bool abi = stackAllocation && chiclet && group && eraserGroup && layer &&
        eraserLayer && inverseAlphaMask && renderingModeClass &&
        effectPresetClass &&
        CNDThemeMethodHasTypes(
            stackAllocation, "initWithName:withSize:atScale:",
            "@48@0:8@16{CGSize=dd}24d40") &&
        CNDThemeMethodHasTypes(
            stackAllocation, "dataRepresentationWithError:",
            "@24@0:8^@16") &&
        CNDThemeMethodHasTypes(
            stackAllocation, "_deviceClassFromPlatform:", "q24@0:8Q16") &&
        CNDThemeMethodHasTypes(
            stackAllocation, "_icrAppearanceFromAppearance:",
            "Q24@0:8q16") &&
        CNDThemeMethodHasTypes(
            stackAllocation,
            "finalizedIconWithSize:scale:deviceClass:appearance:"
            "renderingMode:layoutDirection:isLegacyContent:",
            "@76@0:8{CGSize=dd}16q32q40Q48@56Q64B72") &&
        CNDThemeMethodHasTypes(renderingModeClass, "color", "@16@0:8") &&
        CNDThemeMethodHasTypes(
            chiclet, "setCGColor:", "v24@0:8^{CGColor=}16") &&
        CNDThemeMethodHasTypes(
            chiclet, "setAppearance:", "v24@0:8@16") &&
        CNDThemeMethodHasTypes(group, "addLayer:", "v24@0:8@16") &&
        CNDThemeMethodHasTypes(
            eraserGroup, "setBlendMode:", "v20@0:8i16") &&
        CNDThemeMethodHasTypes(
            effectPresetClass, "cuiEffectBlendModeFromCGBlendMode:",
            "I20@0:8i16") &&
        CNDThemeMethodHasTypes(layer, "setImage:",
                               "v24@0:8^{CGImage=}16") &&
        CNDThemeMethodHasTypes(
            layer, "setFrame:",
            "v48@0:8{CGRect={CGPoint=dd}{CGSize=dd}}16") &&
        CNDThemeMethodHasTypes(layer, "setScale:", "v24@0:8d16") &&
        CNDThemeMethodHasTypes(layer, "setOpacity:", "v24@0:8d16");
    if (!abi || scale <= 0.0 || pointSize.width <= 0.0 ||
        pointSize.height <= 0.0) {
        CNDThemeLog("[CND_ICON_THEME] layer-data-failed reason=abi "
                    "stack=%p/%s chiclet=%p/%s group=%p/%s "
                    "layer=%p/%s eraserGroup=%p/%s eraserLayer=%p/%s "
                    "mask=%p scale=%.2f\n",
                    (__bridge void *)stackAllocation,
                    stackAllocation
                        ? class_getName(object_getClass(stackAllocation)) : "-",
                    (__bridge void *)chiclet,
                    chiclet ? class_getName(object_getClass(chiclet)) : "-",
                    (__bridge void *)group,
                    group ? class_getName(object_getClass(group)) : "-",
                    (__bridge void *)layer,
                    layer ? class_getName(object_getClass(layer)) : "-",
                    (__bridge void *)eraserGroup,
                    eraserGroup
                        ? class_getName(object_getClass(eraserGroup)) : "-",
                    (__bridge void *)eraserLayer,
                    eraserLayer
                        ? class_getName(object_getClass(eraserLayer)) : "-",
                    inverseAlphaMask,
                    scale);
        if (inverseAlphaMask) CGImageRelease(inverseAlphaMask);
        return nil;
    }

    id stack = nil;
    NSError *error = nil;
    @try {
        stack = ((id (*)(id, SEL, id, CNDThemeSize, double))objc_msgSend)(
            stackAllocation,
            sel_registerName("initWithName:withSize:atScale:"),
            CNDThemeLayerMarker, pointSize, scale);
        if (!stack || !CNDThemeMethodHasTypes(
                stack, "addLayer:", "v24@0:8@16")) {
            CNDThemeLog("[CND_ICON_THEME] layer-data-failed "
                        "reason=stack-init\n");
            return nil;
        }
        CGColorSpaceRef chicletColorSpace =
            CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
        /* Test the modern structured-icon path independently of the legacy
         * finalizer.  The color object is present (as stock expects), but its
         * requested fill is genuinely transparent. */
        CGFloat populatedComponents[4] = {0.0, 0.0, 0.0, 0.0};
        CGColorRef populatedChiclet = chicletColorSpace
            ? CGColorCreate(chicletColorSpace, populatedComponents) : NULL;
        if (chicletColorSpace) CGColorSpaceRelease(chicletColorSpace);
        if (!populatedChiclet) {
            CNDThemeLog("[CND_ICON_THEME] layer-data-failed "
                        "reason=populated-chiclet-color\n");
            return nil;
        }
        ((void (*)(id, SEL, CGColorRef))objc_msgSend)(
            chiclet, sel_registerName("setCGColor:"), populatedChiclet);
        CGColorRelease(populatedChiclet);
        NSString *appearanceName = CND_ICON_THEME_APPEARANCE == 1
            ? @"dark" : @"light";
        ((void (*)(id, SEL, id))objc_msgSend)(
            chiclet, sel_registerName("setAppearance:"), appearanceName);
        ((void (*)(id, SEL, CGImageRef))objc_msgSend)(
            layer, sel_registerName("setImage:"), gCNDThemeCGImage);
        ((void (*)(id, SEL, CGRect))objc_msgSend)(
            layer, sel_registerName("setFrame:"),
            CGRectMake(0.0, 0.0, pointSize.width, pointSize.height));
        ((void (*)(id, SEL, double))objc_msgSend)(
            layer, sel_registerName("setScale:"), scale);
        ((void (*)(id, SEL, double))objc_msgSend)(
            layer, sel_registerName("setOpacity:"), 1.0);
        if (CNDThemeMethodHasTypes(
                group, "setAppearance:", "v24@0:8@16")) {
            ((void (*)(id, SEL, id))objc_msgSend)(
                group, sel_registerName("setAppearance:"), appearanceName);
        }
        if (CNDThemeMethodHasTypes(group, "setOpacity:", "v24@0:8d16")) {
            ((void (*)(id, SEL, double))objc_msgSend)(
                group, sel_registerName("setOpacity:"), 1.0);
        }
        ((void (*)(id, SEL, id))objc_msgSend)(
            group, sel_registerName("addLayer:"), layer);
        ((void (*)(id, SEL, CGImageRef))objc_msgSend)(
            eraserLayer, sel_registerName("setImage:"), inverseAlphaMask);
        CGImageRelease(inverseAlphaMask);
        inverseAlphaMask = NULL;
        ((void (*)(id, SEL, CGRect))objc_msgSend)(
            eraserLayer, sel_registerName("setFrame:"),
            CGRectMake(0.0, 0.0, pointSize.width, pointSize.height));
        ((void (*)(id, SEL, double))objc_msgSend)(
            eraserLayer, sel_registerName("setScale:"), scale);
        ((void (*)(id, SEL, double))objc_msgSend)(
            eraserLayer, sel_registerName("setOpacity:"), 1.0);
        ((void (*)(id, SEL, id))objc_msgSend)(
            eraserGroup, sel_registerName("addLayer:"), eraserLayer);
        uint32_t destinationOutBlend =
            ((uint32_t (*)(id, SEL, int))objc_msgSend)(
                effectPresetClass,
                sel_registerName("cuiEffectBlendModeFromCGBlendMode:"),
                (int)kCGBlendModeDestinationOut);
        ((void (*)(id, SEL, int))objc_msgSend)(
            eraserGroup, sel_registerName("setBlendMode:"),
            (int)destinationOutBlend);
        if (CNDThemeMethodHasTypes(
                eraserGroup, "setHasLightingEffects:", "v20@0:8B16")) {
            ((void (*)(id, SEL, BOOL))objc_msgSend)(
                eraserGroup, sel_registerName("setHasLightingEffects:"), NO);
        }
        ((void (*)(id, SEL, id))objc_msgSend)(
            stack, sel_registerName("addLayer:"), chiclet);
        ((void (*)(id, SEL, id))objc_msgSend)(
            stack, sel_registerName("addLayer:"), group);
        ((void (*)(id, SEL, id))objc_msgSend)(
            stack, sel_registerName("addLayer:"), eraserGroup);
        if (CNDThemeMethodHasTypes(
                stack, "setAppearance:", "v24@0:8@16")) {
            ((void (*)(id, SEL, id))objc_msgSend)(
                stack, sel_registerName("setAppearance:"), appearanceName);
        }
        if (!CNDThemeMethodHasTypes(
                stack, "setRenderingProperties:", "v24@0:8@16")) {
            CNDThemeLog("[CND_ICON_THEME] layer-data-failed "
                        "reason=rendering-properties-abi\n");
            return nil;
        }
        NSString *renderingJSON = [NSString stringWithFormat:
            @"{\"layers\":[{"
             "\"contentBounds\":[[0,0],[%d,%d]],"
             "\"knocksOutBorder\":true},{"
             "\"contentBounds\":[[0,0],[%d,%d]],"
             "\"knocksOutBorder\":true}],\"style\":{"
             "\"renderingMode\":{\"contents\":{\"color\":{}}},"
             "\"layoutDirection\":{\"leftToRight\":{}},"
             "\"platform\":0,\"appearance\":\"%@\"}}",
            CND_ICON_THEME_POINT_SIZE, CND_ICON_THEME_POINT_SIZE,
            CND_ICON_THEME_POINT_SIZE, CND_ICON_THEME_POINT_SIZE,
            appearanceName];
        ((void (*)(id, SEL, id))objc_msgSend)(
            stack, sel_registerName("setRenderingProperties:"),
            @{ @"json": renderingJSON });
        int64_t deviceClass =
            ((int64_t (*)(id, SEL, uint64_t))objc_msgSend)(
                stack,
                sel_registerName("_deviceClassFromPlatform:"), 0U);
        uint64_t appearance =
            ((uint64_t (*)(id, SEL, int64_t))objc_msgSend)(
                stack,
                sel_registerName("_icrAppearanceFromAppearance:"),
                CND_ICON_THEME_APPEARANCE);
        id colorMode = ((id (*)(id, SEL))objc_msgSend)(
            renderingModeClass, sel_registerName("color"));
        id finalizedIcon =
            ((id (*)(id, SEL, CNDThemeSize, int64_t, int64_t, uint64_t,
                     id, uint64_t, BOOL))objc_msgSend)(
                stack,
                sel_registerName(
                    "finalizedIconWithSize:scale:deviceClass:appearance:"
                    "renderingMode:layoutDirection:isLegacyContent:"),
                pointSize, (int64_t)scale, deviceClass, appearance,
                colorMode, 0U, NO);
        if (!colorMode || !finalizedIcon) {
            CNDThemeLog("[CND_ICON_THEME] layer-data-failed "
                        "reason=structured-modern-finalization mode=%p/%s "
                        "deviceClass=%lld appearance=%llu\n",
                        (__bridge void *)colorMode,
                        colorMode
                            ? class_getName(object_getClass(colorMode)) : "-",
                        (long long)deviceClass,
                        (unsigned long long)appearance);
            return nil;
        }
        bool finalizedChicletVisible = true;
        bool finalizedChicletKnown = CNDThemeReadFinalizedChicletVisible(
            finalizedIcon, &finalizedChicletVisible);
        CNDThemeInspectRuntimeObject(finalizedIcon, "finalized-wrapper");
        Class configurationClass = NSClassFromString(
            @"ICRGlobalConfiguration");
        id configuration = configurationClass
            ? [[configurationClass alloc] init] : nil;
        CNDThemeInspectRuntimeObject(configuration, "global-configuration");
        bool renderABI = CNDThemeMethodHasTypes(
            finalizedIcon, "renderedIconWithConfiguration:",
            "^{CGImage=}24@0:8@16");
        CGImageRef rendered = configuration && renderABI
            ? ((CGImageRef (*)(id, SEL, id))objc_msgSend)(
                  finalizedIcon,
                  sel_registerName("renderedIconWithConfiguration:"),
                  configuration)
            : NULL;
        CNDThemeLogRenderedProbe(rendered, "pre-serialization-default");

        /* RenderingMode.clear is the system's clear/glass appearance, not a
         * request to omit the icon chiclet.  Measure all public mode factories
         * against the exact same transparent stack so that distinction is
         * established by pixels rather than selector names. */
        id clearMode = CNDThemeMethodHasTypes(
                renderingModeClass, "clear", "@16@0:8")
            ? ((id (*)(id, SEL))objc_msgSend)(
                  renderingModeClass, sel_registerName("clear"))
            : nil;
        id tintedMode = CNDThemeMethodHasTypes(
                renderingModeClass, "tintWithRed:green:blue:alpha:",
                "@48@0:8d16d24d32d40")
            ? ((id (*)(id, SEL, double, double, double, double))objc_msgSend)(
                  renderingModeClass,
                  sel_registerName("tintWithRed:green:blue:alpha:"),
                  1.0, 1.0, 1.0, 1.0)
            : nil;
        id clearFinalized = clearMode
            ? ((id (*)(id, SEL, CNDThemeSize, int64_t, int64_t, uint64_t,
                       id, uint64_t, BOOL))objc_msgSend)(
                  stack,
                  sel_registerName(
                      "finalizedIconWithSize:scale:deviceClass:appearance:"
                      "renderingMode:layoutDirection:isLegacyContent:"),
                  pointSize, (int64_t)scale, deviceClass, appearance,
                  clearMode, 0U, NO)
            : nil;
        id tintedFinalized = tintedMode
            ? ((id (*)(id, SEL, CNDThemeSize, int64_t, int64_t, uint64_t,
                       id, uint64_t, BOOL))objc_msgSend)(
                  stack,
                  sel_registerName(
                      "finalizedIconWithSize:scale:deviceClass:appearance:"
                      "renderingMode:layoutDirection:isLegacyContent:"),
                  pointSize, (int64_t)scale, deviceClass, appearance,
                  tintedMode, 0U, NO)
            : nil;
        CGImageRef renderedClear = clearFinalized && configuration && renderABI
            ? ((CGImageRef (*)(id, SEL, id))objc_msgSend)(
                  clearFinalized,
                  sel_registerName("renderedIconWithConfiguration:"),
                  configuration)
            : NULL;
        CGImageRef renderedTinted =
            tintedFinalized && configuration && renderABI
                ? ((CGImageRef (*)(id, SEL, id))objc_msgSend)(
                      tintedFinalized,
                      sel_registerName("renderedIconWithConfiguration:"),
                      configuration)
                : NULL;
        CNDThemeLogRenderedProbe(
            renderedClear, "pre-serialization-rendering-mode-clear");
        CNDThemeLogRenderedProbe(
            renderedTinted, "pre-serialization-rendering-mode-tinted");

        id noEffectsConfiguration = configurationClass
            ? [[configurationClass alloc] init] : nil;
        bool effectsSetterABI = CNDThemeMethodHasTypes(
            noEffectsConfiguration, "setEffectsAreEnabled:",
            "v20@0:8B16");
        if (effectsSetterABI) {
            ((void (*)(id, SEL, BOOL))objc_msgSend)(
                noEffectsConfiguration,
                sel_registerName("setEffectsAreEnabled:"), NO);
        }
        CGImageRef renderedWithoutEffects =
            noEffectsConfiguration && renderABI && effectsSetterABI
                ? ((CGImageRef (*)(id, SEL, id))objc_msgSend)(
                      finalizedIcon,
                      sel_registerName("renderedIconWithConfiguration:"),
                      noEffectsConfiguration)
                : NULL;
        CNDThemeLogRenderedProbe(
            renderedWithoutEffects, "pre-serialization-effects-disabled");

        bool fullBleedABI = CNDThemeMethodHasTypes(
            finalizedIcon, "renderedFullBleedIconWithConfiguration:",
            "^{CGImage=}24@0:8@16");
        CGImageRef fullBleed = configuration && fullBleedABI
            ? ((CGImageRef (*)(id, SEL, id))objc_msgSend)(
                  finalizedIcon,
                  sel_registerName(
                      "renderedFullBleedIconWithConfiguration:"),
                  configuration)
            : NULL;
        CNDThemeLogRenderedProbe(fullBleed, "pre-serialization-full-bleed");

        bool fullBleedExcludingSpecularABI = CNDThemeMethodHasTypes(
            finalizedIcon,
            "renderedFullBleedIconWithConfiguration:"
            "excludeChicletSpecularHighlights:",
            "^{CGImage=}28@0:8@16B24");
        CGImageRef fullBleedExcludingSpecular =
            configuration && fullBleedExcludingSpecularABI
                ? ((CGImageRef (*)(id, SEL, id, BOOL))objc_msgSend)(
                      finalizedIcon,
                      sel_registerName(
                          "renderedFullBleedIconWithConfiguration:"
                          "excludeChicletSpecularHighlights:"),
                      configuration, YES)
                : NULL;
        CNDThemeLogRenderedProbe(
            fullBleedExcludingSpecular,
            "pre-serialization-full-bleed-excluding-specular");

        bool glassABI = CNDThemeMethodHasTypes(
            finalizedIcon,
            "renderedSystemGlassCompatibleIconWithConfiguration:",
            "^{CGImage=}24@0:8@16");
        CGImageRef glassCompatible = configuration && glassABI
            ? ((CGImageRef (*)(id, SEL, id))objc_msgSend)(
                  finalizedIcon,
                  sel_registerName(
                      "renderedSystemGlassCompatibleIconWithConfiguration:"),
                  configuration)
            : NULL;
        CNDThemeLogRenderedProbe(
            glassCompatible, "pre-serialization-system-glass");

        uint8_t *chicletFlag = NULL;
        bool serializedWithHiddenChiclet =
            CNDThemeFinalizedChicletFlagAddress(
                finalizedIcon, &chicletFlag, NULL) && *chicletFlag == 1U;
        if (serializedWithHiddenChiclet) *chicletFlag = 0U;
        CGImageRef renderedWithHiddenChiclet =
            serializedWithHiddenChiclet && configuration && renderABI
                ? ((CGImageRef (*)(id, SEL, id))objc_msgSend)(
                      finalizedIcon,
                      sel_registerName("renderedIconWithConfiguration:"),
                      configuration)
                : NULL;
        CNDThemeLogRenderedProbe(
            renderedWithHiddenChiclet,
            "pre-serialization-chiclet-flag-disabled");
        CGImageRef hiddenChicletExcludingSpecular =
            serializedWithHiddenChiclet && configuration &&
                    fullBleedExcludingSpecularABI
                ? ((CGImageRef (*)(id, SEL, id, BOOL))objc_msgSend)(
                      finalizedIcon,
                      sel_registerName(
                          "renderedFullBleedIconWithConfiguration:"
                          "excludeChicletSpecularHighlights:"),
                      configuration, YES)
                : NULL;
        CNDThemeLogRenderedProbe(
            hiddenChicletExcludingSpecular,
            "pre-serialization-hidden-chiclet-excluding-specular");
        id stackDataObject = ((id (*)(id, SEL, NSError **))objc_msgSend)(
            stack, sel_registerName("dataRepresentationWithError:"),
            &error);
        NSData *stackData = [stackDataObject isKindOfClass:NSData.class]
            ? stackDataObject : nil;
        NSError *serializationError = nil;
        if (!CNDThemeMethodHasTypes(
                finalizedIcon, "serializedDataWithError:",
                "@24@0:8^@16")) {
            CNDThemeLog("[CND_ICON_THEME] layer-data-failed "
                        "reason=finalized-serialization-abi\n");
            return nil;
        }
        id layerDataObject =
            ((id (*)(id, SEL, NSError **))objc_msgSend)(
                finalizedIcon,
                sel_registerName("serializedDataWithError:"),
                &serializationError);
        if (serializedWithHiddenChiclet) *chicletFlag = 1U;
        NSData *layerData =
            [layerDataObject isKindOfClass:NSData.class]
                ? layerDataObject : nil;
        NSData *markerData = [CNDThemeLayerMarker
            dataUsingEncoding:NSUTF8StringEncoding];
        bool markerSerialized = markerData.length &&
            [layerData rangeOfData:markerData options:0
                             range:NSMakeRange(0, layerData.length)].location !=
                NSNotFound;
        bool stackHasBOMHeader = stackData.length >= 8U &&
            !memcmp(stackData.bytes, "BOMStore", 8U);
        CNDThemeLog("[CND_ICON_THEME] layer-data-built stack=%p/%s "
                    "modernTopLevel=transparent-color,group(image),"
                    "destination-out-group(inverse-alpha) "
                    "chiclet=%p/%s group=%p/%s layer=%p/%s "
                    "eraserGroup=%p/%s eraserLayer=%p/%s "
                    "eraserBlend=0x%08x "
                    "points=%.1fx%.1f@%.2f "
                    "stackBytes=%lu stackSHA256=%s stackBOM=%d "
                    "finalized=%p/%s mode=%p/%s "
                    "finalizer=structured-modern isLegacyContent=0 "
                    "requestedTransparent=1 "
                    "serializedWithHiddenChiclet=%d "
                    "chicletKnown=%d chicletVisible=%d "
                    "deviceClass=%lld appearance=%llu marker=%s/%d "
                    "bytes=%lu sha256=%s "
                    "error=%s serializationError=%s\n",
                    (__bridge void *)stack,
                    stack ? class_getName(object_getClass(stack)) : "-",
                    (__bridge void *)chiclet,
                    class_getName(object_getClass(chiclet)),
                    (__bridge void *)group,
                    class_getName(object_getClass(group)),
                    (__bridge void *)layer,
                    class_getName(object_getClass(layer)),
                    (__bridge void *)eraserGroup,
                    class_getName(object_getClass(eraserGroup)),
                    (__bridge void *)eraserLayer,
                    class_getName(object_getClass(eraserLayer)),
                    destinationOutBlend, pointSize.width,
                    pointSize.height, scale, (unsigned long)stackData.length,
                    CNDThemeSHA256(stackData).UTF8String, stackHasBOMHeader,
                    (__bridge void *)finalizedIcon,
                    class_getName(object_getClass(finalizedIcon)),
                    (__bridge void *)colorMode,
                    class_getName(object_getClass(colorMode)),
                    serializedWithHiddenChiclet,
                    finalizedChicletKnown, finalizedChicletVisible,
                    (long long)deviceClass,
                    (unsigned long long)appearance,
                    CNDThemeLayerMarker.UTF8String, markerSerialized,
                    (unsigned long)layerData.length,
                    CNDThemeSHA256(layerData).UTF8String,
                    error.description.UTF8String ?: "-",
                    serializationError.description.UTF8String ?: "-");
        return stackHasBOMHeader && markerSerialized && layerData.length
            ? layerData : nil;
    } @catch (NSException *exception) {
        CNDThemeLog("[CND_ICON_THEME] layer-data-failed "
                    "reason=exception name=%s detail=%s\n",
                    exception.name.UTF8String ?: "-",
                    exception.reason.UTF8String ?: "-");
        return nil;
    }
}

static id CNDThemeMakeIFImage(double scale)
{
    Class imageClass = NSClassFromString(@"IFImage");
    id allocation = imageClass ? [imageClass alloc] : nil;
    NSData *layerData = CNDThemeMakeLayerData(scale);
    if (!allocation || !CNDThemeMethodHasTypes(
            allocation, "initWithCGImage:scale:layerData:",
            "@40@0:8^{CGImage=}16d24@32") || !layerData.length) {
        CNDThemeLog("[CND_ICON_THEME] themed-image-failed reason=abi-or-layer "
                    "layerBytes=%lu\n", (unsigned long)layerData.length);
        return nil;
    }
    CGImageRef transferredImage = CGImageRetain(gCNDThemeCGImage);
    id image =
        ((id (*)(id, SEL, CGImageRef, double, id))objc_msgSend)(
            allocation,
            sel_registerName("initWithCGImage:scale:layerData:"),
            transferredImage, scale, layerData);
    if (!image) {
        CNDThemeLog("[CND_ICON_THEME] themed-image-failed reason=init\n");
        return nil;
    }
    if (CNDThemeMethodHasTypes(
            image, "setMinimumSize:", "v32@0:8{CGSize=dd}16")) {
        CNDThemeSize minimum = {
            CND_ICON_THEME_POINT_SIZE, CND_ICON_THEME_POINT_SIZE,
        };
        ((void (*)(id, SEL, CNDThemeSize))objc_msgSend)(
            image, sel_registerName("setMinimumSize:"), minimum);
    }
    return image;
}

static id CNDThemeHookGenerate(id self, SEL command,
                               id *recordIdentifiersOut)
{
    id stock = ((id (*)(id, SEL, id *))gCNDOriginalGenerate)(
        self, command, recordIdentifiersOut);
    id icon = CNDThemeObjectGetter(self, "icon");
    id descriptor = CNDThemeObjectGetter(self, "imageDescriptor");
    id bundle = CNDThemeObjectGetter(icon, "bundleIdentifier");
    CNDThemeSize size = {0.0, 0.0};
    double scale = 0.0;
    int64_t appearance = -1;
    uint64_t variantOptions = UINT64_MAX;
    bool geometryKnown = CNDThemeReadDescriptorGeometry(
        descriptor, &size, &scale);
    bool metadataKnown = CNDThemeReadDescriptorMetadata(
        descriptor, &appearance, &variantOptions);
    bool target = [bundle isKindOfClass:NSString.class] &&
        [bundle isEqualToString:@(CNDThemeTargetBundle)] &&
        geometryKnown && metadataKnown &&
        size.width == CND_ICON_THEME_POINT_SIZE &&
        size.height == CND_ICON_THEME_POINT_SIZE && scale == 3.0 &&
        appearance == CND_ICON_THEME_APPEARANCE &&
        variantOptions == CND_ICON_THEME_VARIANT_OPTIONS;
    if (!target || !stock || !gCNDThemeCGImage) return stock;

    id themed = CNDThemeMakeIFImage(scale);
    id themedDataObject = CNDThemeObjectGetter(themed, "data");
    id stockDataObject = CNDThemeObjectGetter(stock, "data");
    NSData *themedData = [themedDataObject isKindOfClass:NSData.class]
        ? themedDataObject : nil;
    NSData *stockData = [stockDataObject isKindOfClass:NSData.class]
        ? stockDataObject : nil;
    id stockUUID = CNDThemeObjectGetter(stock, "uuid");
    id stockToken = CNDThemeObjectGetter(stock, "validationToken");
    Class cacheImageClass = NSClassFromString(@"IFCacheImage");
    id cacheAllocation = cacheImageClass ? [cacheImageClass alloc] : nil;
    bool replacementABI = CNDThemeMethodHasTypes(
        cacheAllocation, "initWithData:uuid:validationToken:",
        "@40@0:8@16@24@32");
    if (!themedData.length || !replacementABI || !stockToken) {
        CNDThemeLog("[CND_ICON_THEME] replacement-rejected themed=%p/%s "
                    "bytes=%lu replacementABI=%d token=%p/%s\n",
                    (__bridge void *)themed,
                    themed ? class_getName(object_getClass(themed)) : "-",
                    (unsigned long)themedData.length, replacementABI,
                    (__bridge void *)stockToken,
                    stockToken ? class_getName(object_getClass(stockToken))
                               : "-");
        return stock;
    }

    id replacement = ((id (*)(id, SEL, id, id, id))objc_msgSend)(
        cacheAllocation,
        sel_registerName("initWithData:uuid:validationToken:"),
        themedData, stockUUID, stockToken);
    id replacementDataObject = CNDThemeObjectGetter(replacement, "data");
    id replacementLayerDataObject = CNDThemeObjectGetter(
        replacement, "layerData");
    id replacementIconLayer = CNDThemeObjectGetter(
        replacement, "ICRIconLayer");
    /* Materializing ICRIconLayer causes IFConcreteImage to deserialize and
     * retain the ICRFinalizedIcon on the image itself.  ICRIconLayer.icon is
     * the source CUINamedIconLayerStack API and is nil for this data-backed
     * reconstruction, so read the canonical finalizedIcon property instead. */
    id replacementFinalizedIcon = CNDThemeObjectGetter(
        replacement, "finalizedIcon");
    bool replacementChicletVisible = true;
    bool replacementChicletKnown = CNDThemeReadFinalizedChicletVisible(
        replacementFinalizedIcon, &replacementChicletVisible);
    Class replacementConfigurationClass = NSClassFromString(
        @"ICRGlobalConfiguration");
    id replacementConfiguration = replacementConfigurationClass
        ? [[replacementConfigurationClass alloc] init] : nil;
    bool replacementRenderABI = CNDThemeMethodHasTypes(
        replacementFinalizedIcon, "renderedIconWithConfiguration:",
        "^{CGImage=}24@0:8@16");
    CGImageRef replacementRendered =
        replacementConfiguration && replacementRenderABI
            ? ((CGImageRef (*)(id, SEL, id))objc_msgSend)(
                  replacementFinalizedIcon,
                  sel_registerName("renderedIconWithConfiguration:"),
                  replacementConfiguration)
            : NULL;
    CNDThemeLogRenderedProbe(
        replacementRendered, "post-deserialization-default");
    NSData *replacementData =
        [replacementDataObject isKindOfClass:NSData.class]
            ? replacementDataObject : nil;
    NSData *replacementLayerData =
        [replacementLayerDataObject isKindOfClass:NSData.class]
            ? replacementLayerDataObject : nil;
    CGImageRef replacementCG = NULL;
    if (replacement && [replacement respondsToSelector:
            sel_registerName("CGImage")]) {
        replacementCG = ((CGImageRef (*)(id, SEL))objc_msgSend)(
            replacement, sel_registerName("CGImage"));
    }
    const size_t expectedPixels = (size_t)CND_ICON_THEME_PIXEL_SIZE;
    bool replacementReady = replacement && replacementData.length > 0U &&
        replacementCG && CGImageGetWidth(replacementCG) == expectedPixels &&
        CGImageGetHeight(replacementCG) == expectedPixels &&
        replacementLayerData.length > 0U && replacementIconLayer;
    if (!replacementReady) {
        CNDThemeLog("[CND_ICON_THEME] replacement-rejected reason=cache-init "
                    "object=%p/%s bytes=%lu pixels=%zux%zu "
                    "layerData=%p/%s layerBytes=%lu layer=%p/%s "
                    "finalized=%p/%s chicletKnown=%d chicletVisible=%d\n",
                    (__bridge void *)replacement,
                    replacement
                        ? class_getName(object_getClass(replacement)) : "-",
                    (unsigned long)replacementData.length,
                    replacementCG ? CGImageGetWidth(replacementCG) : 0U,
                    replacementCG ? CGImageGetHeight(replacementCG) : 0U,
                    (__bridge void *)replacementLayerDataObject,
                    replacementLayerDataObject
                        ? class_getName(object_getClass(
                              replacementLayerDataObject)) : "-",
                    (unsigned long)replacementLayerData.length,
                    (__bridge void *)replacementIconLayer,
                    replacementIconLayer
                        ? class_getName(object_getClass(replacementIconLayer))
                        : "-",
                    (__bridge void *)replacementFinalizedIcon,
                    replacementFinalizedIcon
                        ? class_getName(object_getClass(
                              replacementFinalizedIcon)) : "-",
                    replacementChicletKnown, replacementChicletVisible);
        return stock;
    }

    gCNDAppliedCount++;
    CNDThemeLog("[CND_ICON_THEME] THEME_APPLIED count=%u bundle=%s "
                "geometry=%.1fx%.1f@%.2f appearance=%lld "
                "variantOptions=%llu stock=%lu/%s themed=%lu/%s "
                "replacement=%lu/%s layerData=%lu/%s layer=%p/%s "
                "chicletKnown=%d chicletVisible=%d token=%p/%s "
                "records=%p/%s\n",
                gCNDAppliedCount,
                CNDThemeTargetBundle, size.width, size.height, scale,
                (long long)appearance,
                (unsigned long long)variantOptions,
                (unsigned long)stockData.length,
                CNDThemeSHA256(stockData).UTF8String,
                (unsigned long)themedData.length,
                CNDThemeSHA256(themedData).UTF8String,
                (unsigned long)replacementData.length,
                CNDThemeSHA256(replacementData).UTF8String,
                (unsigned long)replacementLayerData.length,
                CNDThemeSHA256(replacementLayerData).UTF8String,
                (__bridge void *)replacementIconLayer,
                class_getName(object_getClass(replacementIconLayer)),
                replacementChicletKnown, replacementChicletVisible,
                (__bridge void *)stockToken,
                class_getName(object_getClass(stockToken)),
                recordIdentifiersOut ? (__bridge void *)*recordIdentifiersOut
                                     : NULL,
                recordIdentifiersOut && *recordIdentifiersOut
                    ? class_getName(object_getClass(*recordIdentifiersOut))
                    : "-");
    if (gCNDGenerateMethod && gCNDOriginalGenerate) {
        IMP displaced = method_setImplementation(
            gCNDGenerateMethod, gCNDOriginalGenerate);
        CNDThemeLog("[CND_ICON_THEME] HOOK_REMOVED count=%u "
                    "displaced=%p restored=%p\n",
                    gCNDAppliedCount, displaced, gCNDOriginalGenerate);
    }
    return replacement;
}

static bool CNDThemeInstallHook(void)
{
    Class cls = NSClassFromString(@"ISGenerationRequest");
    SEL selector = sel_registerName(
        "generateImageReturningRecordIdentifiers:");
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    if (!method || !method_getTypeEncoding(method) ||
        strcmp(method_getTypeEncoding(method), "@24@0:8^@16") != 0) {
        CNDThemeLog("[CND_ICON_THEME] hook-failed types=%s\n",
                    method ? method_getTypeEncoding(method) : "-");
        return false;
    }
    gCNDGenerateMethod = method;
    gCNDOriginalGenerate = method_getImplementation(method);
    method_setImplementation(method, (IMP)CNDThemeHookGenerate);
    CNDThemeLog("[CND_ICON_THEME] TRACE_READY pid=%d original=%p "
                "replacement=%p source=%p\n", getpid(),
                gCNDOriginalGenerate, CNDThemeHookGenerate,
                gCNDThemeCGImage);
    return true;
}

__attribute__((constructor))
static void CNDThemeStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t outputHandle = CND_ICON_THEME_OUTPUT_TOKEN[0] && consume
            ? consume(CND_ICON_THEME_OUTPUT_TOKEN) : -1;
        int64_t rootHandle = CND_ICON_THEME_ROOT_TOKEN[0] && consume
            ? consume(CND_ICON_THEME_ROOT_TOKEN) : -1;
        gCNDThemeFD = open(CNDThemeOutputPath,
                           O_WRONLY | O_CREAT | O_TRUNC, 0644);
        CNDThemeLog("[CND_ICON_THEME] START pid=%d outputToken=%lld "
                    "rootToken=%lld mode=vm-cache-theme\n", getpid(),
                    (long long)outputHandle, (long long)rootHandle);
        CNDThemeLog("[CND_ICON_THEME] LOAD IconServices begin\n");
        void *iconServicesHandle = dlopen(
            "/System/Library/PrivateFrameworks/IconServices.framework/"
            "IconServices", RTLD_NOW | RTLD_LOCAL);
        CNDThemeLog("[CND_ICON_THEME] LOAD IconServices end handle=%p error=%s\n",
                    iconServicesHandle, dlerror() ?: "-");
        CNDThemeLog("[CND_ICON_THEME] LOAD CoreUI begin\n");
        void *coreUIHandle = dlopen(
            "/System/Library/PrivateFrameworks/CoreUI.framework/CoreUI",
            RTLD_NOW | RTLD_LOCAL);
        CNDThemeLog("[CND_ICON_THEME] LOAD CoreUI end handle=%p error=%s\n",
                    coreUIHandle, dlerror() ?: "-");
        CNDThemeLog("[CND_ICON_THEME] LOAD IconRendering begin\n");
        void *iconRenderingHandle = dlopen(
            "/System/Library/PrivateFrameworks/IconRendering.framework/"
            "IconRendering", RTLD_NOW | RTLD_LOCAL);
        CNDThemeLog("[CND_ICON_THEME] LOAD IconRendering end handle=%p "
                    "error=%s\n", iconRenderingHandle, dlerror() ?: "-");
        CNDThemeLog("[CND_ICON_THEME] LOAD source begin\n");
        gCNDThemeCGImage = CNDThemeLoadImage();
        CNDThemeLog("[CND_ICON_THEME] LOAD source end image=%p\n",
                    gCNDThemeCGImage);
        if (gCNDThemeCGImage) (void)CNDThemeInstallHook();
    }
}
