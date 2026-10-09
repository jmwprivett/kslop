#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef CND_CLOCK_ROUTE_OUTPUT_TOKEN
#define CND_CLOCK_ROUTE_OUTPUT_TOKEN ""
#endif

#ifndef CND_CLOCK_ROUTE_OUTPUT_PATH
#define CND_CLOCK_ROUTE_OUTPUT_PATH "/var/tmp/cnd-clock-background-route.log"
#endif

#ifndef CND_CLOCK_ROUTE_IMAGE_PATH
#define CND_CLOCK_ROUTE_IMAGE_PATH "/var/tmp/cnd-clock-background-route.png"
#endif

typedef struct {
    double width;
    double height;
} CNDClockRouteSize;

static NSString *const CNDClockRouteType =
    @"com.apple.application-icon.clock.base";
static NSString *const CNDClockRouteDigest =
    @"9E1D8C88-D314-329D-BE0F-1D262142B74B";

static IMP gCNDClockRouteViewOriginal;
static id gCNDClockRouteDescriptor;
static id gCNDClockRouteReplacement;
static NSString *gCNDClockRouteReplacementPixels;
static id gCNDClockRouteDedicatedLeaf;
static id gCNDClockRouteDedicatedSource;
static unsigned gCNDClockRouteViewHits;

static void CNDClockRouteLog(NSString *format, ...) NS_FORMAT_FUNCTION(1, 2);

static void CNDClockRouteLog(NSString *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    NSString *message = [[NSString alloc] initWithFormat:format
                                               arguments:arguments];
    va_end(arguments);
    flockfile(stderr);
    fprintf(stderr, "%s\n", message.UTF8String ?: "-");
    fflush(stderr);
    funlockfile(stderr);
}

static const char *CNDClockRouteSkipQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static id CNDClockRouteObjectGetter(id object, const char *name)
{
    if (!object || !name) return nil;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *copied = method_copyReturnType(method);
    const char *type = CNDClockRouteSkipQualifiers(copied);
    bool objectReturn = type && (*type == '@' || *type == '#');
    free(copied);
    if (!objectReturn) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static NSString *CNDClockRouteIdentifier(id object)
{
    static const char *const selectors[] = {
        "leafIdentifier", "iconTypeIdentifierForImage", "typeIdentifier",
        "bundleIdentifier",
    };
    for (NSUInteger index = 0;
         index < sizeof(selectors) / sizeof(selectors[0]); index++) {
        id value = CNDClockRouteObjectGetter(object, selectors[index]);
        if ([value isKindOfClass:NSString.class] && [value length] > 0U) {
            return value;
        }
    }
    return @"-";
}

static NSString *CNDClockRouteSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class]) return @"-";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *text = [NSMutableString stringWithCapacity:64U];
    for (size_t index = 0; index < sizeof(digest); index++) {
        [text appendFormat:@"%02x", digest[index]];
    }
    return text;
}

static NSData *CNDClockRouteRGBA(CGImageRef image)
{
    size_t width = image ? CGImageGetWidth(image) : 0U;
    size_t height = image ? CGImageGetHeight(image) : 0U;
    if (!width || !height || width > SIZE_MAX / 4U ||
        height > SIZE_MAX / (width * 4U)) return nil;
    NSMutableData *pixels = [NSMutableData dataWithLength:
        width * height * 4U];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = colorSpace
        ? CGBitmapContextCreate(
            pixels.mutableBytes, width, height, 8U, width * 4U,
            colorSpace, kCGImageAlphaPremultipliedLast |
                kCGBitmapByteOrder32Big)
        : NULL;
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    if (!context) return nil;
    CGContextClearRect(context, CGRectMake(0.0, 0.0, width, height));
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextDrawImage(context, CGRectMake(0.0, 0.0, width, height), image);
    CGContextRelease(context);
    return pixels;
}

static NSDictionary *CNDClockRouteImageSummary(id image)
{
    CGImageRef cgImage = NULL;
    if (image && [image respondsToSelector:sel_registerName("CGImage")]) {
        cgImage = ((CGImageRef (*)(id, SEL))objc_msgSend)(
            image, sel_registerName("CGImage"));
    }
    NSData *rgba = CNDClockRouteRGBA(cgImage);
    NSUInteger transparent = 0U;
    NSUInteger translucent = 0U;
    NSUInteger opaque = 0U;
    const uint8_t *bytes = rgba.bytes;
    for (NSUInteger offset = 3U; offset < rgba.length; offset += 4U) {
        uint8_t alpha = bytes[offset];
        if (alpha == 0U) transparent++;
        else if (alpha == UINT8_MAX) opaque++;
        else translucent++;
    }
    return @{
        @"class": image ? @(class_getName(object_getClass(image))) : @"-",
        @"width": @(cgImage ? CGImageGetWidth(cgImage) : 0U),
        @"height": @(cgImage ? CGImageGetHeight(cgImage) : 0U),
        @"pixelSHA256": CNDClockRouteSHA256(rgba),
        @"transparent": @(transparent),
        @"translucent": @(translucent),
        @"opaque": @(opaque),
    };
}

static bool CNDClockRouteSetInteger(id object, const char *name,
                                    uint64_t value)
{
    SEL selector = sel_registerName(name);
    if (![object respondsToSelector:selector]) return true;
    @try {
        ((void (*)(id, SEL, uint64_t))objc_msgSend)(object, selector, value);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static id CNDClockRouteMakeDescriptor(void)
{
    Class descriptorClass = NSClassFromString(@"ISImageDescriptor");
    SEL factory = sel_registerName("imageDescriptorWithIconVariant:options:");
    if (!descriptorClass || ![descriptorClass respondsToSelector:factory]) {
        return nil;
    }
    id descriptor = [((id (*)(id, SEL, int32_t, int32_t))objc_msgSend)(
        descriptorClass, factory, 0, 0) copy];
    if (!descriptor) return nil;
    CNDClockRouteSize size = {68.0, 68.0};
    ((void (*)(id, SEL, CNDClockRouteSize))objc_msgSend)(
        descriptor, sel_registerName("setSize:"), size);
    ((void (*)(id, SEL, double))objc_msgSend)(
        descriptor, sel_registerName("setScale:"), 3.0);
    ((void (*)(id, SEL, int64_t))objc_msgSend)(
        descriptor, sel_registerName("setAppearance:"), 0);
    bool configured =
        CNDClockRouteSetInteger(descriptor, "setIconVariant:", 0U) &&
        CNDClockRouteSetInteger(descriptor, "setVariantOptions:", 0U) &&
        CNDClockRouteSetInteger(descriptor, "setBadgeOptions:", 0U) &&
        CNDClockRouteSetInteger(descriptor, "setBackgroundStyle:", 0U) &&
        CNDClockRouteSetInteger(descriptor, "setGraphicVariant:", 0U) &&
        CNDClockRouteSetInteger(descriptor, "setSpecialIconOptions:", 2U) &&
        CNDClockRouteSetInteger(descriptor, "setPlatformStyle:", 0U) &&
        CNDClockRouteSetInteger(descriptor, "setIgnoreCache:", 0U) &&
        CNDClockRouteSetInteger(descriptor, "setShouldApplyMask:", 1U) &&
        CNDClockRouteSetInteger(descriptor, "setDrawBorder:", 0U) &&
        CNDClockRouteSetInteger(descriptor, "setDrawBadge:", 1U) &&
        CNDClockRouteSetInteger(descriptor, "setContrast:", 0U) &&
        CNDClockRouteSetInteger(descriptor, "setVibrancy:", 0U) &&
        CNDClockRouteSetInteger(descriptor, "setLanguageDirection:", 1U) &&
        CNDClockRouteSetInteger(descriptor, "setLayoutDirection:", 5U) &&
        CNDClockRouteSetInteger(descriptor, "setAssetPlatformHint:", 0U);
    NSString *description = [descriptor description] ?: @"-";
    bool exact = configured &&
        [description containsString:CNDClockRouteDigest];
    CNDClockRouteLog(@"CND_CLOCK_ROUTE descriptor exact=%d value=%@",
                     exact, description);
    return exact ? descriptor : nil;
}

static id CNDClockRouteMakeReplacement(void)
{
    NSData *data = [NSData dataWithContentsOfFile:@(CND_CLOCK_ROUTE_IMAGE_PATH)];
    UIImage *source = data.length ? [UIImage imageWithData:data] : nil;
    if (!source.CGImage) return nil;
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(68.0, 68.0), NO, 3.0);
    [source drawInRect:CGRectMake(0.0, 0.0, 68.0, 68.0)];
    UIImage *scaled = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    if (!scaled.CGImage) return nil;

    Class imageClass = NSClassFromString(@"IFImage");
    id allocation = imageClass ? [imageClass alloc] : nil;
    SEL initializer = sel_registerName("initWithCGImage:scale:");
    if (!allocation || ![allocation respondsToSelector:initializer]) return nil;
    CGImageRef transferred = CGImageRetain(scaled.CGImage);
    id image = ((id (*)(id, SEL, CGImageRef, double))objc_msgSend)(
        allocation, initializer, transferred, 3.0);
    if (!image) CGImageRelease(transferred);
    NSDictionary *summary = CNDClockRouteImageSummary(image);
    CNDClockRouteLog(@"CND_CLOCK_ROUTE replacement inputBytes=%lu "
                     "inputSHA256=%@ summary=%@",
                     (unsigned long)data.length, CNDClockRouteSHA256(data),
                     summary);
    bool exact = [summary[@"width"] unsignedIntegerValue] == 204U &&
        [summary[@"height"] unsignedIntegerValue] == 204U &&
        [summary[@"transparent"] unsignedIntegerValue] > 0U;
    return exact ? image : nil;
}

static id CNDClockRouteOuterRequest(id source, id descriptor)
{
    if (!source || !descriptor) return nil;
    SEL prepare = sel_registerName("prepareImageForDescriptor:");
    if ([source respondsToSelector:prepare]) {
        id prepared = ((id (*)(id, SEL, id))objc_msgSend)(
            source, prepare, descriptor);
        if (prepared) return prepared;
    }
    SEL imageForDescriptor = sel_registerName("imageForDescriptor:");
    SEL imageForImageDescriptor = sel_registerName("imageForImageDescriptor:");
    for (unsigned attempt = 0U; attempt < 20U; attempt++) {
        id image = nil;
        if ([source respondsToSelector:imageForDescriptor]) {
            image = ((id (*)(id, SEL, id))objc_msgSend)(
                source, imageForDescriptor, descriptor);
        } else if ([source respondsToSelector:imageForImageDescriptor]) {
            image = ((id (*)(id, SEL, id))objc_msgSend)(
                source, imageForImageDescriptor, descriptor);
        }
        if (image) return image;
        usleep(25000U);
    }
    return nil;
}

static bool CNDClockRouteSeed(id source)
{
    if (!source || !gCNDClockRouteDescriptor || !gCNDClockRouteReplacement ||
        ![CNDClockRouteIdentifier(source) isEqualToString:CNDClockRouteType]) {
        return false;
    }
    id cache = CNDClockRouteObjectGetter(source, "imageCache");
    SEL setter = sel_registerName("setImage:forDescriptor:");
    SEL getter = sel_registerName("imageForDescriptor:");
    if (!cache || ![cache respondsToSelector:setter] ||
        ![cache respondsToSelector:getter]) return false;
    ((void (*)(id, SEL, id, id))objc_msgSend)(
        cache, setter, gCNDClockRouteReplacement, gCNDClockRouteDescriptor);
    id cached = ((id (*)(id, SEL, id))objc_msgSend)(
        cache, getter, gCNDClockRouteDescriptor);
    NSDictionary *summary = CNDClockRouteImageSummary(cached);
    bool ok = [summary[@"pixelSHA256"]
        isEqualToString:gCNDClockRouteReplacementPixels];
    CNDClockRouteLog(@"CND_CLOCK_ROUTE seed source=%p/%s cache=%p/%s "
                     "ok=%d summary=%@", (__bridge void *)source,
                     class_getName(object_getClass(source)),
                     (__bridge void *)cache,
                     class_getName(object_getClass(cache)), ok, summary);
    return ok;
}

static id CNDClockRouteDedicatedIconServicesIcon(
    __unused id self, __unused SEL command)
{
    return gCNDClockRouteDedicatedSource;
}

static id CNDClockRouteDedicatedImage(
    __unused id self, __unused SEL command, id descriptor)
{
    static unsigned responses;
    responses++;
    if (responses <= 16U) {
        CNDClockRouteLog(@"CND_CLOCK_ROUTE source-response count=%u "
                         "selector=%s descriptor=%@ image=%p/%s",
                         responses, sel_getName(command), descriptor,
                         (__bridge void *)gCNDClockRouteReplacement,
                         gCNDClockRouteReplacement
                            ? class_getName(object_getClass(
                                gCNDClockRouteReplacement)) : "-");
    }
    return gCNDClockRouteReplacement;
}

static id CNDClockRouteViewIconForImage(
    id self, __unused SEL command)
{
    id leaf = gCNDClockRouteDedicatedLeaf;
    gCNDClockRouteViewHits++;
    id source = gCNDClockRouteDedicatedSource;
    if (gCNDClockRouteViewHits <= 16U) {
        CNDClockRouteLog(@"CND_CLOCK_ROUTE view-hit count=%u view=%p "
                         "leaf=%p/%s identifier=%@ source=%p/%s",
                         gCNDClockRouteViewHits, (__bridge void *)self,
                         (__bridge void *)leaf,
                         leaf ? class_getName(object_getClass(leaf)) : "-",
                         CNDClockRouteIdentifier(leaf),
                         (__bridge void *)source,
                         source ? class_getName(object_getClass(source)) : "-");
    }
    return leaf;
}

static bool CNDClockRouteInstallOverride(Class cls, SEL selector, IMP replacement,
                                         IMP *originalOut)
{
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (!method || !types || strcmp(types, "@16@0:8")) return false;
    IMP original = method_getImplementation(method);
    if (!original) return false;

    bool owns = false;
    unsigned count = 0U;
    Method *methods = class_copyMethodList(cls, &count);
    for (unsigned index = 0U; index < count; index++) {
        if (method_getName(methods[index]) == selector) {
            owns = true;
            break;
        }
    }
    free(methods);
    bool installed = owns
        ? method_setImplementation(method, replacement) != NULL
        : class_addMethod(cls, selector, replacement, types);
    Method observed = class_getInstanceMethod(cls, selector);
    installed = installed && observed &&
        method_getImplementation(observed) == replacement;
    if (installed && originalOut) *originalOut = original;
    CNDClockRouteLog(@"CND_CLOCK_ROUTE hook class=%s selector=%s owns=%d "
                     "installed=%d original=%p replacement=%p",
                     cls ? class_getName(cls) : "-", sel_getName(selector),
                     owns, installed, original, replacement);
    return installed;
}

static bool CNDClockRoutePrepareDedicatedBackground(void)
{
    Class leafClass = NSClassFromString(@"SBLeafIcon");
    Class dataSourceClass = NSClassFromString(@"SBHClockBackgroundIconDataSource");
    id leafAllocation = leafClass ? [leafClass alloc] : nil;
    SEL initializer = sel_registerName(
        "initWithLeafIdentifier:applicationBundleID:");
    id leaf = leafAllocation && [leafAllocation respondsToSelector:initializer]
        ? ((id (*)(id, SEL, id, id))objc_msgSend)(
            leafAllocation, initializer, CNDClockRouteType, nil)
        : nil;
    id dataSource = dataSourceClass ? [[dataSourceClass alloc] init] : nil;
    SEL addDataSource = sel_registerName("addIconDataSource:");
    if (leaf && dataSource && [leaf respondsToSelector:addDataSource]) {
        ((void (*)(id, SEL, id))objc_msgSend)(
            leaf, addDataSource, dataSource);
    }
    SEL setActiveDataSource = sel_registerName("setActiveDataSource:");
    if (leaf && dataSource && [leaf respondsToSelector:setActiveDataSource]) {
        ((void (*)(id, SEL, id))objc_msgSend)(
            leaf, setActiveDataSource, dataSource);
    }
    Class sourceClass = NSClassFromString(@"ISLayeredIcon");
    id sourceAllocation = sourceClass ? [sourceClass alloc] : nil;
    SEL sourceInitializer = sel_registerName(
        "initWithTypeIdentifier:layerGroups:");
    id source = sourceAllocation &&
            [sourceAllocation respondsToSelector:sourceInitializer]
        ? ((id (*)(id, SEL, id, id))objc_msgSend)(
            sourceAllocation, sourceInitializer, CNDClockRouteType, @[])
        : nil;
    if (!leaf || !source ||
        ![CNDClockRouteIdentifier(leaf) isEqualToString:CNDClockRouteType] ||
        ![CNDClockRouteIdentifier(source) isEqualToString:CNDClockRouteType] ||
        !CNDClockRouteSeed(source)) {
        CNDClockRouteLog(@"CND_CLOCK_ROUTE dedicated-prepare failed "
                         "leaf=%p/%s leafID=%@ dataSource=%p/%s "
                         "active=%p/%s iconType=%@ source=%p/%s sourceID=%@",
                         (__bridge void *)leaf,
                         leaf ? class_getName(object_getClass(leaf)) : "-",
                         CNDClockRouteIdentifier(leaf),
                         (__bridge void *)dataSource,
                         dataSource
                            ? class_getName(object_getClass(dataSource)) : "-",
                         (__bridge void *)CNDClockRouteObjectGetter(
                            leaf, "activeDataSource"),
                         CNDClockRouteObjectGetter(leaf, "activeDataSource")
                            ? class_getName(object_getClass(
                                CNDClockRouteObjectGetter(
                                    leaf, "activeDataSource"))) : "-",
                         CNDClockRouteObjectGetter(
                            leaf, "iconTypeIdentifierForImage") ?: @"-",
                         (__bridge void *)source,
                         source ? class_getName(object_getClass(source)) : "-",
                         CNDClockRouteIdentifier(source));
        return false;
    }


    Class originalSourceClass = object_getClass(source);
    char sourceSubclassName[160] = {0};
    snprintf(sourceSubclassName, sizeof(sourceSubclassName),
             "CNDClockRouteDedicatedSource_%d", getpid());
    Class sourceSubclass = objc_allocateClassPair(
        originalSourceClass, sourceSubclassName, 0U);
    bool sourceSubclassReady = sourceSubclass;
    static const char *const responseSelectors[] = {
        "imageForDescriptor:", "imageForImageDescriptor:",
        "_generateImageWithDescriptor:",
    };
    for (NSUInteger index = 0U;
         sourceSubclassReady &&
         index < sizeof(responseSelectors) / sizeof(responseSelectors[0]);
         index++) {
        sourceSubclassReady = class_addMethod(
            sourceSubclass, sel_registerName(responseSelectors[index]),
            (IMP)CNDClockRouteDedicatedImage, "@24@0:8@16");
    }
    if (sourceSubclassReady) objc_registerClassPair(sourceSubclass);
    if (!sourceSubclassReady ||
        object_setClass(source, sourceSubclass) != originalSourceClass) {
        CNDClockRouteLog(@"CND_CLOCK_ROUTE dedicated-prepare failed "
                         "reason=source-subclass original=%s subclass=%s",
                         originalSourceClass
                            ? class_getName(originalSourceClass) : "-",
                         sourceSubclass ? class_getName(sourceSubclass) : "-");
        return false;
    }

    Class originalClass = object_getClass(leaf);
    char subclassName[160] = {0};
    snprintf(subclassName, sizeof(subclassName),
             "CNDClockRouteDedicatedLeaf_%d", getpid());
    Class subclass = objc_allocateClassPair(originalClass, subclassName, 0U);
    bool subclassReady = subclass && class_addMethod(
        subclass, sel_registerName("iconServicesIconForImage"),
        (IMP)CNDClockRouteDedicatedIconServicesIcon, "@16@0:8");
    if (subclassReady) objc_registerClassPair(subclass);
    if (!subclassReady || object_setClass(leaf, subclass) != originalClass) {
        CNDClockRouteLog(@"CND_CLOCK_ROUTE dedicated-prepare failed "
                         "reason=subclass original=%s subclass=%s",
                         originalClass ? class_getName(originalClass) : "-",
                         subclass ? class_getName(subclass) : "-");
        return false;
    }

    gCNDClockRouteDedicatedLeaf = leaf;
    gCNDClockRouteDedicatedSource = source;
    id readbackSource = CNDClockRouteObjectGetter(
        gCNDClockRouteDedicatedLeaf, "iconServicesIconForImage");
    id readbackImage = CNDClockRouteOuterRequest(
        readbackSource, gCNDClockRouteDescriptor);
    NSDictionary *summary = CNDClockRouteImageSummary(readbackImage);
    bool ready = readbackSource == gCNDClockRouteDedicatedSource &&
        [summary[@"pixelSHA256"]
            isEqualToString:gCNDClockRouteReplacementPixels];
    CNDClockRouteLog(@"CND_CLOCK_ROUTE dedicated-prepare ready=%d "
                     "leaf=%p/%s source=%p/%s image=%@",
                     ready, (__bridge void *)gCNDClockRouteDedicatedLeaf,
                     class_getName(object_getClass(gCNDClockRouteDedicatedLeaf)),
                     (__bridge void *)gCNDClockRouteDedicatedSource,
                     class_getName(object_getClass(gCNDClockRouteDedicatedSource)),
                     summary);
    return ready;
}

static NSDictionary *CNDClockRouteFreshConsumer(NSString *label)
    __attribute__((unused));

static NSDictionary *CNDClockRouteFreshConsumer(NSString *label)
{
    Class viewClass = NSClassFromString(@"SBHClockApplicationIconImageView");
    id view = viewClass
        ? [[viewClass alloc] initWithFrame:CGRectMake(0.0, 0.0, 68.0, 68.0)]
        : nil;
    id leaf = CNDClockRouteObjectGetter(view, "iconForImage");
    id source = CNDClockRouteObjectGetter(leaf, "iconServicesIconForImage");
    id image = CNDClockRouteOuterRequest(source, gCNDClockRouteDescriptor);
    NSDictionary *summary = CNDClockRouteImageSummary(image);
    id layers = CNDClockRouteObjectGetter(CNDClockRouteObjectGetter(view, "layer"),
                                          "sublayers");
    NSUInteger directLayerCount = [layers isKindOfClass:NSArray.class]
        ? [layers count] : 0U;
    bool ok = view && leaf && source &&
        leaf == gCNDClockRouteDedicatedLeaf &&
        source == gCNDClockRouteDedicatedSource &&
        [CNDClockRouteIdentifier(leaf) isEqualToString:CNDClockRouteType] &&
        [CNDClockRouteIdentifier(source) isEqualToString:CNDClockRouteType] &&
        [summary[@"pixelSHA256"]
            isEqualToString:gCNDClockRouteReplacementPixels];
    NSDictionary *result = @{
        @"label": label ?: @"-",
        @"ok": @(ok),
        @"view": [NSString stringWithFormat:@"%p", view],
        @"leaf": [NSString stringWithFormat:@"%p", leaf],
        @"source": [NSString stringWithFormat:@"%p", source],
        @"leafIdentifier": CNDClockRouteIdentifier(leaf),
        @"sourceIdentifier": CNDClockRouteIdentifier(source),
        @"directLayerCount": @(directLayerCount),
        @"image": summary,
    };
    CNDClockRouteLog(@"CND_CLOCK_ROUTE consumer %@", result);
    return result;
}

/*
 * Exercise the already-mounted Clock through SpringBoard's exact model and
 * displayed-view identity path.  This is deliberately a validation trigger,
 * not a discovery mechanism for the route itself: it performs no window or
 * subview walk and it never calls -iconForImage directly.  The stock reload
 * methods must reach the installed class-wide redirect on their own.
 */
static bool CNDClockRouteTriggerDisplayedClock(void)
{
    Class controllerClass = NSClassFromString(@"SBIconController");
    id controller = CNDClockRouteObjectGetter(controllerClass,
                                               "sharedInstance");
    id manager = CNDClockRouteObjectGetter(controller, "iconManager");
    if (!manager) {
        manager = CNDClockRouteObjectGetter(
            NSClassFromString(@"SBHIconManager"), "sharedInstance");
    }
    id model = CNDClockRouteObjectGetter(manager, "iconModel");
    if (!model) model = CNDClockRouteObjectGetter(manager, "model");

    SEL applicationLookup = sel_registerName(
        "applicationIconForBundleIdentifier:");
    id icon = model && [model respondsToSelector:applicationLookup]
        ? ((id (*)(id, SEL, id))objc_msgSend)(
            model, applicationLookup, @"com.apple.mobiletimer")
        : nil;
    id root = CNDClockRouteObjectGetter(manager, "rootFolderController");
    if (!root) {
        root = CNDClockRouteObjectGetter(controller,
                                         "rootFolderController");
    }
    SEL displayedLookup = sel_registerName("displayedIconViewForIcon:");
    id iconView = root && icon && [root respondsToSelector:displayedLookup]
        ? ((id (*)(id, SEL, id))objc_msgSend)(
            root, displayedLookup, icon)
        : nil;
    SEL firstLookup = sel_registerName("firstIconViewForIcon:options:");
    if (!iconView && root && icon &&
        [root respondsToSelector:firstLookup]) {
        iconView = ((id (*)(id, SEL, id, NSUInteger))objc_msgSend)(
            root, firstLookup, icon, 0U);
    }
    id imageView = CNDClockRouteObjectGetter(iconView, "_iconImageView");
    Class expected = NSClassFromString(@"SBHClockApplicationIconImageView");
    bool exact = imageView && expected &&
        [imageView isKindOfClass:expected];

    unsigned before = gCNDClockRouteViewHits;
    bool iconReload = false;
    bool viewReload = false;
    bool imageReload = false;
    SEL reloadIcon = sel_registerName("reloadIconImage");
    if (exact && [icon respondsToSelector:reloadIcon]) {
        ((void (*)(id, SEL))objc_msgSend)(icon, reloadIcon);
        iconReload = true;
    }
    SEL updateView = sel_registerName("_updateIconImageViewAnimated:");
    if (exact && [iconView respondsToSelector:updateView]) {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(
            iconView, updateView, NO);
        viewReload = true;
    }
    SEL updateImage = sel_registerName("updateImageAnimated:");
    if (exact && [imageView respondsToSelector:updateImage]) {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(
            imageView, updateImage, NO);
        imageReload = true;
    }
    unsigned after = gCNDClockRouteViewHits;
    CNDClockRouteLog(@"CND_CLOCK_ROUTE REAL label=displayed-clock "
                     "exact=%d before=%u after=%u delta=%u "
                     "iconReload=%d viewReload=%d imageReload=%d "
                     "controller=%p/%s manager=%p/%s model=%p/%s "
                     "icon=%p/%s root=%p/%s iconView=%p/%s "
                     "imageView=%p/%s",
                     exact, before, after, after - before,
                     iconReload, viewReload, imageReload,
                     (__bridge void *)controller,
                     controller ? class_getName(object_getClass(controller)) : "-",
                     (__bridge void *)manager,
                     manager ? class_getName(object_getClass(manager)) : "-",
                     (__bridge void *)model,
                     model ? class_getName(object_getClass(model)) : "-",
                     (__bridge void *)icon,
                     icon ? class_getName(object_getClass(icon)) : "-",
                     (__bridge void *)root,
                     root ? class_getName(object_getClass(root)) : "-",
                     (__bridge void *)iconView,
                     iconView ? class_getName(object_getClass(iconView)) : "-",
                     (__bridge void *)imageView,
                     imageView ? class_getName(object_getClass(imageView)) : "-");
    return exact && after > before;
}

static void CNDClockRouteScheduleDisplayedClockAttempt(unsigned attempt)
{
    if (attempt >= 5U) return;
    unsigned delay = attempt == 0U ? 0U : 2U;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(delay * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (CNDClockRouteTriggerDisplayedClock()) return;
        CNDClockRouteScheduleDisplayedClockAttempt(attempt + 1U);
    });
}

static void CNDClockRouteRunPhase(NSString *label)
    __attribute__((unused));

static void CNDClockRouteRunPhase(NSString *label)
{
    @autoreleasepool {
        NSDictionary *first = CNDClockRouteFreshConsumer(
            [label stringByAppendingString:@"-first"]);
        NSDictionary *second = CNDClockRouteFreshConsumer(
            [label stringByAppendingString:@"-second"]);
        bool ok = [first[@"ok"] boolValue] && [second[@"ok"] boolValue];
        CNDClockRouteLog(@"CND_CLOCK_ROUTE PHASE label=%@ ok=%d "
                         "viewHits=%u targetedReloadUsed=0",
                         label, ok, gCNDClockRouteViewHits);
    }
}

__attribute__((constructor))
static void CNDClockRouteStart(void)
{
    void *symbol = dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    int64_t (*consume)(const char *) = symbol;
    int64_t consumed = CND_CLOCK_ROUTE_OUTPUT_TOKEN[0] && consume
        ? consume(CND_CLOCK_ROUTE_OUTPUT_TOKEN) : -1;
    FILE *redirected = freopen(CND_CLOCK_ROUTE_OUTPUT_PATH, "a", stderr);
    setvbuf(stderr, NULL, _IOLBF, 0);
    CNDClockRouteLog(@"CND_CLOCK_ROUTE start pid=%d token=%lld log=%d",
                     getpid(), (long long)consumed, redirected != NULL);

    dispatch_async(dispatch_get_main_queue(), ^{
        gCNDClockRouteDescriptor = CNDClockRouteMakeDescriptor();
        gCNDClockRouteReplacement = CNDClockRouteMakeReplacement();
        NSDictionary *replacement = CNDClockRouteImageSummary(
            gCNDClockRouteReplacement);
        gCNDClockRouteReplacementPixels = replacement[@"pixelSHA256"];
        Class viewClass = NSClassFromString(@"SBHClockApplicationIconImageView");
        bool dedicatedReady = gCNDClockRouteDescriptor &&
            gCNDClockRouteReplacement &&
            CNDClockRoutePrepareDedicatedBackground();
        bool viewHook = dedicatedReady && CNDClockRouteInstallOverride(
            viewClass, sel_registerName("iconForImage"),
            (IMP)CNDClockRouteViewIconForImage,
            &gCNDClockRouteViewOriginal);
        CNDClockRouteLog(@"CND_CLOCK_ROUTE READY pid=%d dedicatedReady=%d "
                         "viewHook=%d replacement=%@",
                         getpid(), dedicatedReady, viewHook, replacement);
        if (!dedicatedReady || !viewHook) return;
        CNDClockRouteScheduleDisplayedClockAttempt(0U);
    });
}
