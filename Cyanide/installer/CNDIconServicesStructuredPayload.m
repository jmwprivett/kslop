#import "CNDIconServicesStructuredPayload.h"

#import <ImageIO/ImageIO.h>
#import <dlfcn.h>
#import <math.h>
#import <objc/message.h>
#import <objc/runtime.h>

NSString * const CNDIconServicesThemeMarker = @"CNDThemeIcon.v1";
NSString * const CNDIconServicesStructuredPayloadErrorDomain =
    @"CNDIconServicesStructuredPayloadErrorDomain";

typedef struct {
    double width;
    double height;
} CNDIconServicesSize;

/* Private declarations are intentionally limited to the two initializer
 * families used here. Calling these through a cast objc_msgSend hides the
 * `init` ownership convention from ARC and is not safe for class clusters. */
@interface NSObject (CNDStructuredPrivateInitializers)
- (instancetype)initWithName:(NSString *)name
                    withSize:(CGSize)size
                     atScale:(double)scale;
- (instancetype)initWithCGImage:(CGImageRef)image
                           scale:(double)scale
                       layerData:(NSData *)layerData;
@end

typedef NS_ENUM(NSInteger, CNDIconServicesStructuredPayloadError) {
    CNDIconServicesStructuredPayloadInvalidInput = 1,
    CNDIconServicesStructuredPayloadFrameworkUnavailable = 2,
    CNDIconServicesStructuredPayloadUnsupportedABI = 3,
    CNDIconServicesStructuredPayloadConstructionFailed = 4,
    CNDIconServicesStructuredPayloadMarkerMissing = 5,
};

static void CNDStructuredSetError(
    NSError **errorOut,
    CNDIconServicesStructuredPayloadError code,
    NSString *description)
{
    if (!errorOut) return;
    *errorOut = [NSError errorWithDomain:CNDIconServicesStructuredPayloadErrorDomain
                                    code:code
                                userInfo:@{
        NSLocalizedDescriptionKey: description ?: @"Structured icon payload failed."
    }];
}

static BOOL CNDStructuredMethodHasTypes(id object,
                                        const char *selectorName,
                                        const char *expectedTypes)
{
    if (!object || !selectorName || !expectedTypes) return NO;
    Method method = class_getInstanceMethod(
        object_getClass(object), sel_registerName(selectorName));
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    return types && strcmp(types, expectedTypes) == 0;
}

static BOOL CNDStructuredClassHasInstanceMethodTypes(
    Class cls, const char *selectorName, const char *expectedTypes)
{
    if (!cls || !selectorName || !expectedTypes) return NO;
    Method method = class_getInstanceMethod(
        cls, sel_registerName(selectorName));
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    return types && strcmp(types, expectedTypes) == 0;
}

static BOOL CNDStructuredLoadFrameworks(void)
{
    static BOOL loaded = NO;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // IFImage is owned by IconFoundation.  The successful resident-dylib
        // proof ran inside hosts which had already loaded it, but Cyanide does
        // not.  Load it explicitly before IconServices so local structured
        // payload construction has the same class/initializer ABI.
        void *iconFoundation = dlopen(
            "/System/Library/PrivateFrameworks/IconFoundation.framework/"
            "IconFoundation",
            RTLD_NOW | RTLD_LOCAL);
        void *iconServices = dlopen(
            "/System/Library/PrivateFrameworks/IconServices.framework/"
            "IconServices",
            RTLD_NOW | RTLD_LOCAL);
        void *coreUI = dlopen(
            "/System/Library/PrivateFrameworks/CoreUI.framework/CoreUI",
            RTLD_NOW | RTLD_LOCAL);
        void *iconRendering = dlopen(
            "/System/Library/PrivateFrameworks/IconRendering.framework/"
            "IconRendering",
            RTLD_NOW | RTLD_LOCAL);
        loaded = iconFoundation && iconServices && coreUI && iconRendering;
    });
    return loaded;
}

static NSString *CNDStructuredClassInstanceMethodTypeDescription(
    Class cls, const char *selectorName)
{
    if (!cls || !selectorName) return @"missing-class";
    Method method = class_getInstanceMethod(
        cls, sel_registerName(selectorName));
    if (!method) return @"missing-method";
    const char *types = method_getTypeEncoding(method);
    return types ? [NSString stringWithUTF8String:types] : @"missing-types";
}

static id CNDStructuredObjectGetter(id object, const char *name)
{
    if (!object || !name) return nil;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2) return nil;
    const char *types = method_getTypeEncoding(method);
    if (!types || types[0] != '@') return nil;
    return ((id (*)(id, SEL))objc_msgSend)(object, selector);
}

static CGImageRef CNDStructuredCreateImage(NSData *pngData,
                                           CGSize pixelSize)
{
    CGImageSourceRef source = CGImageSourceCreateWithData(
        (__bridge CFDataRef)pngData, NULL);
    if (!source || CGImageSourceGetCount(source) != 1) {
        if (source) CFRelease(source);
        return NULL;
    }
    CGImageRef decoded = CGImageSourceCreateImageAtIndex(source, 0, NULL);
    CFRelease(source);
    size_t expectedWidth = (size_t)llround(pixelSize.width);
    size_t expectedHeight = (size_t)llround(pixelSize.height);
    if (!decoded || CGImageGetWidth(decoded) != expectedWidth ||
        CGImageGetHeight(decoded) != expectedHeight) {
        if (decoded) CGImageRelease(decoded);
        return NULL;
    }
    return decoded;
}

static CGImageRef CNDStructuredCreateInverseAlphaMask(CGImageRef image)
{
    size_t width = image ? CGImageGetWidth(image) : 0;
    size_t height = image ? CGImageGetHeight(image) : 0;
    if (!width || !height || width > SIZE_MAX / 4 ||
        height > SIZE_MAX / (width * 4)) return NULL;

    size_t byteCount = width * height * 4;
    NSMutableData *sourceBytes = [NSMutableData dataWithLength:byteCount];
    NSMutableData *maskBytes = [NSMutableData dataWithLength:byteCount];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = colorSpace ? CGBitmapContextCreate(
        sourceBytes.mutableBytes, width, height, 8, width * 4, colorSpace,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big) : NULL;
    if (context) {
        CGContextSetBlendMode(context, kCGBlendModeCopy);
        CGContextDrawImage(context, CGRectMake(0, 0, width, height), image);
        CGContextRelease(context);
    }
    if (!context) {
        if (colorSpace) CGColorSpaceRelease(colorSpace);
        return NULL;
    }

    const uint8_t *source = sourceBytes.bytes;
    uint8_t *mask = maskBytes.mutableBytes;
    for (size_t index = 0; index < width * height; index++) {
        size_t offset = index * 4;
        mask[offset] = 0;
        mask[offset + 1] = 0;
        mask[offset + 2] = 0;
        mask[offset + 3] = UINT8_MAX - source[offset + 3];
    }
    CGDataProviderRef provider = CGDataProviderCreateWithCFData(
        (__bridge CFDataRef)maskBytes);
    CGImageRef result = provider && colorSpace ? CGImageCreate(
        width, height, 8, 32, width * 4, colorSpace,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big,
        provider, NULL, false, kCGRenderingIntentDefault) : NULL;
    if (provider) CGDataProviderRelease(provider);
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    return result;
}

static BOOL CNDStructuredChicletFlagAddress(id finalizedIcon,
                                            uint8_t **addressOut)
{
    Class cls = finalizedIcon ? object_getClass(finalizedIcon) : Nil;
    if (!cls || strcmp(class_getName(cls), "ICRFinalizedIcon") != 0) {
        return NO;
    }
    Ivar storage = class_getInstanceVariable(cls, "finalizedIcon");
    ptrdiff_t storageOffset = storage ? ivar_getOffset(storage) : -1;
    const size_t configurationOffset = 0x20;
    const size_t chicletFlagOffset = 0x90;
    size_t instanceSize = class_getInstanceSize(cls);
    if (storageOffset != 8 || instanceSize <=
        (size_t)storageOffset + configurationOffset + chicletFlagOffset) {
        return NO;
    }
    uint8_t *address = (uint8_t *)(__bridge void *)finalizedIcon +
        (size_t)storageOffset + configurationOffset + chicletFlagOffset;
    if (*address > 1) return NO;
    if (addressOut) *addressOut = address;
    return YES;
}

NSData *CNDIconServicesCreateStructuredLayerDataWithPixelSize(
    NSData *scaledPNGData,
    CGSize pointSize,
    CGFloat scale,
    CGSize pixelSize,
    NSDictionary<NSString *, id> **diagnosticsOut,
    NSError **errorOut)
{
    if (diagnosticsOut) *diagnosticsOut = nil;
    if (errorOut) *errorOut = nil;
    if (![scaledPNGData isKindOfClass:NSData.class] ||
        scaledPNGData.length == 0 || !isfinite(pointSize.width) ||
        !isfinite(pointSize.height) || !isfinite(scale) ||
        pointSize.width < 1.0 || pointSize.width > 1024.0 ||
        pointSize.height < 1.0 || pointSize.height > 1024.0 ||
        scale < 1.0 || scale > 4.0 || !isfinite(pixelSize.width) ||
        !isfinite(pixelSize.height) || pixelSize.width < 1.0 ||
        pixelSize.height < 1.0 || pixelSize.width > 4096.0 ||
        pixelSize.height > 4096.0) {
        CNDStructuredSetError(errorOut,
            CNDIconServicesStructuredPayloadInvalidInput,
            @"The structured payload requires one bounded, exact-geometry scaled PNG.");
        return nil;
    }
    if (!CNDStructuredLoadFrameworks()) {
        CNDStructuredSetError(errorOut,
            CNDIconServicesStructuredPayloadFrameworkUnavailable,
            @"CoreUI or IconRendering could not be loaded.");
        return nil;
    }

    CGImageRef image = CNDStructuredCreateImage(scaledPNGData, pixelSize);
    CGImageRef inverseMask = CNDStructuredCreateInverseAlphaMask(image);
    if (!image || !inverseMask) {
        if (image) CGImageRelease(image);
        if (inverseMask) CGImageRelease(inverseMask);
        CNDStructuredSetError(errorOut,
            CNDIconServicesStructuredPayloadInvalidInput,
            @"The scaled PNG could not be decoded at its exact geometry.");
        return nil;
    }

    Class stackClass = NSClassFromString(@"CUIMutableNamedIconLayerStack");
    Class colorClass = NSClassFromString(@"CUIMutableNamedColor");
    Class groupClass = NSClassFromString(@"CUIMutableNamedIconLayerGroup");
    Class layerClass = NSClassFromString(@"CUIMutableNamedLayerImage");
    Class renderingModeClass = NSClassFromString(@"ICRRenderingMode");
    Class effectPresetClass = NSClassFromString(@"CUIShapeEffectPreset");
    id chiclet = colorClass ? [[colorClass alloc] init] : nil;
    id imageGroup = groupClass ? [[groupClass alloc] init] : nil;
    id eraserGroup = groupClass ? [[groupClass alloc] init] : nil;
    id imageLayer = layerClass ? [[layerClass alloc] init] : nil;
    id eraserLayer = layerClass ? [[layerClass alloc] init] : nil;

    BOOL abi = stackClass && chiclet && imageGroup && eraserGroup &&
        imageLayer && eraserLayer && renderingModeClass && effectPresetClass &&
        CNDStructuredClassHasInstanceMethodTypes(stackClass,
            "initWithName:withSize:atScale:",
            "@48@0:8@16{CGSize=dd}24d40") &&
        CNDStructuredClassHasInstanceMethodTypes(stackClass,
            "dataRepresentationWithError:", "@24@0:8^@16") &&
        CNDStructuredClassHasInstanceMethodTypes(stackClass,
            "_deviceClassFromPlatform:", "q24@0:8Q16") &&
        CNDStructuredClassHasInstanceMethodTypes(stackClass,
            "_icrAppearanceFromAppearance:", "Q24@0:8q16") &&
        CNDStructuredClassHasInstanceMethodTypes(stackClass,
            "finalizedIconWithSize:scale:deviceClass:appearance:renderingMode:"
            "layoutDirection:isLegacyContent:",
            "@76@0:8{CGSize=dd}16q32q40Q48@56Q64B72") &&
        CNDStructuredClassHasInstanceMethodTypes(stackClass,
            "setRenderingProperties:", "v24@0:8@16") &&
        CNDStructuredMethodHasTypes(renderingModeClass, "color", "@16@0:8") &&
        CNDStructuredMethodHasTypes(chiclet, "setCGColor:",
            "v24@0:8^{CGColor=}16") &&
        CNDStructuredMethodHasTypes(chiclet, "setAppearance:",
            "v24@0:8@16") &&
        CNDStructuredMethodHasTypes(imageGroup, "addLayer:", "v24@0:8@16") &&
        CNDStructuredMethodHasTypes(eraserGroup, "setBlendMode:",
            "v20@0:8i16") &&
        CNDStructuredMethodHasTypes(effectPresetClass,
            "cuiEffectBlendModeFromCGBlendMode:", "I20@0:8i16") &&
        CNDStructuredMethodHasTypes(imageLayer, "setImage:",
            "v24@0:8^{CGImage=}16") &&
        CNDStructuredMethodHasTypes(imageLayer, "setFrame:",
            "v48@0:8{CGRect={CGPoint=dd}{CGSize=dd}}16") &&
        CNDStructuredMethodHasTypes(imageLayer, "setScale:", "v24@0:8d16") &&
        CNDStructuredMethodHasTypes(imageLayer, "setOpacity:", "v24@0:8d16");
    if (!abi) {
        CGImageRelease(inverseMask);
        CGImageRelease(image);
        CNDStructuredSetError(errorOut,
            CNDIconServicesStructuredPayloadUnsupportedABI,
            @"The iOS 26 structured IconRendering ABI did not match.");
        return nil;
    }

    NSData *result = nil;
    @try {
        CNDIconServicesSize size = { pointSize.width, pointSize.height };
        id stack = [[stackClass alloc]
            initWithName:CNDIconServicesThemeMarker
                withSize:pointSize
                 atScale:scale];
        if (!stack || !CNDStructuredMethodHasTypes(
                stack, "addLayer:", "v24@0:8@16")) {
            @throw [NSException exceptionWithName:@"CNDStructuredStack"
                                           reason:@"stack initialization failed"
                                         userInfo:nil];
        }

        CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(
            kCGColorSpaceSRGB);
        const CGFloat transparent[4] = { 0, 0, 0, 0 };
        CGColorRef transparentColor = colorSpace
            ? CGColorCreate(colorSpace, transparent) : NULL;
        if (colorSpace) CGColorSpaceRelease(colorSpace);
        if (!transparentColor) {
            @throw [NSException exceptionWithName:@"CNDStructuredColor"
                                           reason:@"transparent chiclet color failed"
                                         userInfo:nil];
        }
        ((void (*)(id, SEL, CGColorRef))objc_msgSend)(
            chiclet, sel_registerName("setCGColor:"), transparentColor);
        CGColorRelease(transparentColor);
        ((void (*)(id, SEL, id))objc_msgSend)(
            chiclet, sel_registerName("setAppearance:"), @"light");

        CGRect frame = CGRectMake(0, 0, pointSize.width, pointSize.height);
        ((void (*)(id, SEL, CGImageRef))objc_msgSend)(
            imageLayer, sel_registerName("setImage:"), image);
        ((void (*)(id, SEL, CGRect))objc_msgSend)(
            imageLayer, sel_registerName("setFrame:"), frame);
        ((void (*)(id, SEL, double))objc_msgSend)(
            imageLayer, sel_registerName("setScale:"), scale);
        ((void (*)(id, SEL, double))objc_msgSend)(
            imageLayer, sel_registerName("setOpacity:"), 1.0);
        if (CNDStructuredMethodHasTypes(
                imageGroup, "setAppearance:", "v24@0:8@16")) {
            ((void (*)(id, SEL, id))objc_msgSend)(
                imageGroup, sel_registerName("setAppearance:"), @"light");
        }
        if (CNDStructuredMethodHasTypes(
                imageGroup, "setOpacity:", "v24@0:8d16")) {
            ((void (*)(id, SEL, double))objc_msgSend)(
                imageGroup, sel_registerName("setOpacity:"), 1.0);
        }
        ((void (*)(id, SEL, id))objc_msgSend)(
            imageGroup, sel_registerName("addLayer:"), imageLayer);

        ((void (*)(id, SEL, CGImageRef))objc_msgSend)(
            eraserLayer, sel_registerName("setImage:"), inverseMask);
        ((void (*)(id, SEL, CGRect))objc_msgSend)(
            eraserLayer, sel_registerName("setFrame:"), frame);
        ((void (*)(id, SEL, double))objc_msgSend)(
            eraserLayer, sel_registerName("setScale:"), scale);
        ((void (*)(id, SEL, double))objc_msgSend)(
            eraserLayer, sel_registerName("setOpacity:"), 1.0);
        ((void (*)(id, SEL, id))objc_msgSend)(
            eraserGroup, sel_registerName("addLayer:"), eraserLayer);
        uint32_t destinationOut =
            ((uint32_t (*)(id, SEL, int))objc_msgSend)(
                effectPresetClass,
                sel_registerName("cuiEffectBlendModeFromCGBlendMode:"),
                (int)kCGBlendModeDestinationOut);
        ((void (*)(id, SEL, int))objc_msgSend)(
            eraserGroup, sel_registerName("setBlendMode:"),
            (int)destinationOut);
        if (CNDStructuredMethodHasTypes(
                eraserGroup, "setHasLightingEffects:", "v20@0:8B16")) {
            ((void (*)(id, SEL, BOOL))objc_msgSend)(
                eraserGroup, sel_registerName("setHasLightingEffects:"), NO);
        }

        ((void (*)(id, SEL, id))objc_msgSend)(
            stack, sel_registerName("addLayer:"), chiclet);
        ((void (*)(id, SEL, id))objc_msgSend)(
            stack, sel_registerName("addLayer:"), imageGroup);
        ((void (*)(id, SEL, id))objc_msgSend)(
            stack, sel_registerName("addLayer:"), eraserGroup);
        if (CNDStructuredMethodHasTypes(
                stack, "setAppearance:", "v24@0:8@16")) {
            ((void (*)(id, SEL, id))objc_msgSend)(
                stack, sel_registerName("setAppearance:"), @"light");
        }
        NSString *renderingJSON = [NSString stringWithFormat:
            @"{\"layers\":[{\"contentBounds\":[[0,0],[%.0f,%.0f]],"
             "\"knocksOutBorder\":true},{\"contentBounds\":[[0,0],"
             "[%.0f,%.0f]],\"knocksOutBorder\":true}],\"style\":{"
             "\"renderingMode\":{\"contents\":{\"color\":{}}},"
             "\"layoutDirection\":{\"leftToRight\":{}},\"platform\":0,"
             "\"appearance\":\"light\"}}",
            pointSize.width, pointSize.height,
            pointSize.width, pointSize.height];
        ((void (*)(id, SEL, id))objc_msgSend)(
            stack, sel_registerName("setRenderingProperties:"),
            @{ @"json": renderingJSON });

        int64_t deviceClass =
            ((int64_t (*)(id, SEL, uint64_t))objc_msgSend)(
                stack, sel_registerName("_deviceClassFromPlatform:"), 0);
        uint64_t appearance =
            ((uint64_t (*)(id, SEL, int64_t))objc_msgSend)(
                stack, sel_registerName("_icrAppearanceFromAppearance:"), 0);
        id colorMode = ((id (*)(id, SEL))objc_msgSend)(
            renderingModeClass, sel_registerName("color"));
        id finalizedIcon =
            ((id (*)(id, SEL, CNDIconServicesSize, int64_t, int64_t,
                     uint64_t, id, uint64_t, BOOL))objc_msgSend)(
                stack,
                sel_registerName(
                    "finalizedIconWithSize:scale:deviceClass:appearance:"
                    "renderingMode:layoutDirection:isLegacyContent:"),
                size, (int64_t)scale, deviceClass, appearance,
                colorMode, 0, NO);
        if (!finalizedIcon || !CNDStructuredMethodHasTypes(
                finalizedIcon, "serializedDataWithError:",
                "@24@0:8^@16")) {
            @throw [NSException exceptionWithName:@"CNDStructuredFinalizer"
                                           reason:@"structured finalization failed"
                                         userInfo:nil];
        }

        NSError *stackError = nil;
        NSData *stackData = ((id (*)(id, SEL, NSError **))objc_msgSend)(
            stack, sel_registerName("dataRepresentationWithError:"),
            &stackError);
        BOOL stackValid = [stackData isKindOfClass:NSData.class] &&
            stackData.length >= 8 && !memcmp(stackData.bytes, "BOMStore", 8);
        uint8_t *chicletFlag = NULL;
        BOOL flagKnown = CNDStructuredChicletFlagAddress(
            finalizedIcon, &chicletFlag);
        uint8_t originalFlag = flagKnown ? *chicletFlag : 0;
        if (!flagKnown || originalFlag != 1) {
            @throw [NSException exceptionWithName:@"CNDStructuredChiclet"
                                           reason:@"chiclet flag ABI failed"
                                         userInfo:nil];
        }
        *chicletFlag = 0;
        NSError *serializationError = nil;
        id serialized = ((id (*)(id, SEL, NSError **))objc_msgSend)(
            finalizedIcon, sel_registerName("serializedDataWithError:"),
            &serializationError);
        *chicletFlag = originalFlag;
        NSData *layerData = [serialized isKindOfClass:NSData.class]
            ? serialized : nil;
        NSData *marker = [CNDIconServicesThemeMarker
            dataUsingEncoding:NSUTF8StringEncoding];
        BOOL markerPresent = layerData.length >= marker.length &&
            [layerData rangeOfData:marker options:0
                             range:NSMakeRange(0, layerData.length)].location !=
                NSNotFound;
        if (!stackValid || !layerData.length || !markerPresent) {
            NSString *reason = serializationError.localizedDescription ?:
                stackError.localizedDescription ?:
                @"The structured payload did not retain its marker.";
            @throw [NSException exceptionWithName:@"CNDStructuredSerialization"
                                           reason:reason
                                         userInfo:nil];
        }
        result = [layerData copy];
        if (diagnosticsOut) {
            *diagnosticsOut = @{
                @"marker": CNDIconServicesThemeMarker,
                @"markerPresent": @YES,
                @"layerDataLength": @(result.length),
                @"stackDataLength": @(stackData.length),
                @"pointWidth": @(pointSize.width),
                @"pointHeight": @(pointSize.height),
                @"scale": @(scale),
                @"pixelWidth": @(CGImageGetWidth(image)),
                @"pixelHeight": @(CGImageGetHeight(image)),
                @"serializedWithHiddenChiclet": @YES,
            };
        }
    } @catch (NSException *exception) {
        CNDStructuredSetError(errorOut,
            CNDIconServicesStructuredPayloadConstructionFailed,
            exception.reason ?: @"Structured IconRendering construction failed.");
    }

    CGImageRelease(inverseMask);
    CGImageRelease(image);
    return result;
}

NSData *CNDIconServicesCreateStructuredImageDataWithPixelSize(
    NSData *scaledPNGData,
    CGSize pointSize,
    CGFloat scale,
    CGSize pixelSize,
    NSDictionary<NSString *, id> **diagnosticsOut,
    NSError **errorOut)
{
    if (diagnosticsOut) *diagnosticsOut = nil;
    if (errorOut) *errorOut = nil;

    NSDictionary *layerDiagnostics = nil;
    NSError *layerError = nil;
    NSData *layerData = CNDIconServicesCreateStructuredLayerDataWithPixelSize(
        scaledPNGData, pointSize, scale, pixelSize, &layerDiagnostics,
        &layerError);
    if (!layerData.length) {
        if (errorOut) *errorOut = layerError;
        return nil;
    }

    CGImageRef source = CNDStructuredCreateImage(scaledPNGData, pixelSize);
    Class imageClass = NSClassFromString(@"IFImage");
    if (!source || !imageClass ||
        !CNDStructuredClassHasInstanceMethodTypes(
            imageClass, "initWithCGImage:scale:layerData:",
            "@40@0:8^{CGImage=}16d24@32")) {
        if (source) CGImageRelease(source);
        NSString *observed =
            CNDStructuredClassInstanceMethodTypeDescription(
                imageClass, "initWithCGImage:scale:layerData:");
        CNDStructuredSetError(errorOut,
            CNDIconServicesStructuredPayloadUnsupportedABI,
            [NSString stringWithFormat:
                @"The local IFImage serialization ABI did not match "
                 "(class=%@ initializer=%@).",
                imageClass ? @"loaded" : @"missing", observed]);
        return nil;
    }

    NSData *result = nil;
    @try {
        /* 23A341's -[IFConcreteImage initWithCGImage:scale:layerData:]
         * CFRetains the supplied image before storing it. Pass our existing
         * +1 reference and release it after serialization; retaining here as
         * well leaks one CGImage for every rendered matrix variant. */
        id image = [[imageClass alloc]
            initWithCGImage:source
                      scale:(double)scale
                  layerData:layerData];
        if (!image) {
            @throw [NSException exceptionWithName:@"CNDStructuredIFImage"
                                           reason:@"IFImage initialization failed"
                                         userInfo:nil];
        }
        if (CNDStructuredMethodHasTypes(
                image, "setMinimumSize:", "v32@0:8{CGSize=dd}16")) {
            CNDIconServicesSize minimum = {
                pointSize.width, pointSize.height
            };
            ((void (*)(id, SEL, CNDIconServicesSize))objc_msgSend)(
                image, sel_registerName("setMinimumSize:"), minimum);
        }

        NSData *imageData = CNDStructuredObjectGetter(image, "data");
        NSData *roundTripLayer = CNDStructuredObjectGetter(
            image, "layerData");
        CGImageRef roundTripImage = NULL;
        if (CNDStructuredMethodHasTypes(
                image, "CGImage", "^{CGImage=}16@0:8")) {
            roundTripImage =
                ((CGImageRef (*)(id, SEL))objc_msgSend)(
                    image, sel_registerName("CGImage"));
        }
        NSData *marker = [CNDIconServicesThemeMarker
            dataUsingEncoding:NSUTF8StringEncoding];
        BOOL markerPresent = roundTripLayer.length >= marker.length &&
            [roundTripLayer rangeOfData:marker options:0
                                  range:NSMakeRange(0, roundTripLayer.length)]
                .location != NSNotFound;
        size_t expectedWidth = (size_t)llround(pixelSize.width);
        size_t expectedHeight = (size_t)llround(pixelSize.height);
        BOOL geometryVerified = roundTripImage &&
            CGImageGetWidth(roundTripImage) == expectedWidth &&
            CGImageGetHeight(roundTripImage) == expectedHeight;
        if (![imageData isKindOfClass:NSData.class] ||
            imageData.length == 0 ||
            ![roundTripLayer isEqualToData:layerData] ||
            !markerPresent || !geometryVerified) {
            @throw [NSException exceptionWithName:@"CNDStructuredIFImage"
                                           reason:@"IFImage serialization readback failed"
                                         userInfo:nil];
        }
        result = [imageData copy];
        if (diagnosticsOut) {
            NSMutableDictionary *diagnostics =
                [layerDiagnostics mutableCopy] ?: [NSMutableDictionary dictionary];
            diagnostics[@"imageDataLength"] = @(result.length);
            diagnostics[@"imageLayerDataRoundTrip"] = @YES;
            diagnostics[@"imageGeometryRoundTrip"] = @YES;
            diagnostics[@"imageMarkerRoundTrip"] = @YES;
            *diagnosticsOut = diagnostics;
        }
    } @catch (NSException *exception) {
        CNDStructuredSetError(errorOut,
            CNDIconServicesStructuredPayloadConstructionFailed,
            exception.reason ?: @"IFImage serialization failed.");
    }
    CGImageRelease(source);
    return result;
}

NSData *CNDIconServicesCreateStructuredLayerData(
    NSData *scaledPNGData,
    CGSize pointSize,
    CGFloat scale,
    NSDictionary<NSString *, id> **diagnosticsOut,
    NSError **errorOut)
{
    return CNDIconServicesCreateStructuredLayerDataWithPixelSize(
        scaledPNGData, pointSize, scale,
        CGSizeMake(pointSize.width * scale, pointSize.height * scale),
        diagnosticsOut, errorOut);
}

NSData *CNDIconServicesCreateStructuredImageData(
    NSData *scaledPNGData,
    CGSize pointSize,
    CGFloat scale,
    NSDictionary<NSString *, id> **diagnosticsOut,
    NSError **errorOut)
{
    return CNDIconServicesCreateStructuredImageDataWithPixelSize(
        scaledPNGData, pointSize, scale,
        CGSizeMake(pointSize.width * scale, pointSize.height * scale),
        diagnosticsOut, errorOut);
}
