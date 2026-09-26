#import <Foundation/Foundation.h>

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    double width;
    double height;
} CNDClockBaseSize;

static const char *const CNDClockBaseType =
    "com.apple.application-icon.clock.base";
static const char *const CNDClockBaseExpectedDigest =
    "9E1D8C88-D314-329D-BE0F-1D262142B74B";

static const char *CNDClockBaseSkipQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static Method CNDClockBaseMethod(id object, const char *name)
{
    return object && name
        ? class_getInstanceMethod(object_getClass(object),
                                  sel_registerName(name))
        : NULL;
}

static bool CNDClockBaseMethodHasTypes(id object, const char *name,
                                       const char *types)
{
    Method method = CNDClockBaseMethod(object, name);
    return method && method_getTypeEncoding(method) && types &&
        strcmp(method_getTypeEncoding(method), types) == 0;
}

static id CNDClockBaseObjectGetter(id object, const char *name)
{
    Method method = CNDClockBaseMethod(object, name);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDClockBaseSkipQualifiers(returnType);
    bool returnsObject = type && (*type == '@' || *type == '#');
    free(returnType);
    if (!returnsObject) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(
            object, sel_registerName(name));
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static NSString *CNDClockBaseSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class]) return @"-";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *text = [NSMutableString stringWithCapacity:64U];
    for (size_t index = 0U; index < sizeof(digest); index++) {
        [text appendFormat:@"%02x", digest[index]];
    }
    return text;
}

static NSString *CNDClockBaseUUIDText(id value)
{
    if ([value isKindOfClass:NSUUID.class]) return [value UUIDString];
    if ([value isKindOfClass:NSString.class]) return value;
    return @"-";
}

static NSData *CNDClockBaseRGBAData(CGImageRef image)
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

static NSDictionary<NSString *, NSNumber *> *
CNDClockBaseAlphaSummary(NSData *rgba)
{
    if (![rgba isKindOfClass:NSData.class] || rgba.length % 4U != 0U) {
        return @{};
    }
    const uint8_t *bytes = rgba.bytes;
    NSUInteger transparent = 0U;
    NSUInteger translucent = 0U;
    NSUInteger opaque = 0U;
    uint8_t minimum = UINT8_MAX;
    uint8_t maximum = 0U;
    for (NSUInteger offset = 3U; offset < rgba.length; offset += 4U) {
        uint8_t alpha = bytes[offset];
        minimum = MIN(minimum, alpha);
        maximum = MAX(maximum, alpha);
        if (alpha == 0U) transparent++;
        else if (alpha == UINT8_MAX) opaque++;
        else translucent++;
    }
    return @{
        @"transparent": @(transparent),
        @"translucent": @(translucent),
        @"opaque": @(opaque),
        @"minimum": @(minimum),
        @"maximum": @(maximum),
    };
}

static void CNDClockBaseDumpMethods(id object, const char *label)
{
    if (!object) return;
    for (Class cls = object_getClass(object); cls; cls = class_getSuperclass(cls)) {
        unsigned count = 0U;
        Method *methods = class_copyMethodList(cls, &count);
        unsigned cap = MIN(count, 160U);
        for (unsigned index = 0U; index < cap; index++) {
            printf("CND_CLOCK_BASE method label=%s owner=%s selector=%s "
                   "types=%s\n", label, class_getName(cls),
                   sel_getName(method_getName(methods[index])),
                   method_getTypeEncoding(methods[index]) ?: "-");
        }
        free(methods);
        if (!strcmp(class_getName(cls), "NSObject")) break;
    }
}

static id CNDClockBaseMakeDescriptor(Class descriptorClass,
                                     bool ignoreCache)
{
    SEL factory = sel_registerName("imageDescriptorWithIconVariant:options:");
    Method factoryMethod = descriptorClass
        ? class_getClassMethod(descriptorClass, factory) : NULL;
    if (!factoryMethod || !method_getTypeEncoding(factoryMethod) ||
        strcmp(method_getTypeEncoding(factoryMethod), "@24@0:8i16i20")) {
        return nil;
    }
    id template = ((id (*)(id, SEL, int32_t, int32_t))objc_msgSend)(
        descriptorClass, factory, 0, 0);
    id descriptor = [template conformsToProtocol:@protocol(NSCopying)]
        ? [template copy] : nil;
    bool abi = CNDClockBaseMethodHasTypes(
            descriptor, "setSize:", "v32@0:8{CGSize=dd}16") &&
        CNDClockBaseMethodHasTypes(
            descriptor, "setScale:", "v24@0:8d16") &&
        CNDClockBaseMethodHasTypes(
            descriptor, "setAppearance:", "v24@0:8q16") &&
        CNDClockBaseMethodHasTypes(
            descriptor, "setVariantOptions:", "v24@0:8Q16") &&
        CNDClockBaseMethodHasTypes(
            descriptor, "setIgnoreCache:", "v20@0:8B16");
    if (!abi) return nil;
    CNDClockBaseSize size = {68.0, 68.0};
    ((void (*)(id, SEL, CNDClockBaseSize))objc_msgSend)(
        descriptor, sel_registerName("setSize:"), size);
    ((void (*)(id, SEL, double))objc_msgSend)(
        descriptor, sel_registerName("setScale:"), 3.0);
    ((void (*)(id, SEL, int64_t))objc_msgSend)(
        descriptor, sel_registerName("setAppearance:"), 0);
    ((void (*)(id, SEL, uint64_t))objc_msgSend)(
        descriptor, sel_registerName("setVariantOptions:"), 0U);
    ((void (*)(id, SEL, BOOL))objc_msgSend)(
        descriptor, sel_registerName("setIgnoreCache:"), ignoreCache);
    return descriptor;
}

static id CNDClockBaseMakeIcon(Class iconClass)
{
    id allocation = iconClass ? [iconClass alloc] : nil;
    if (!CNDClockBaseMethodHasTypes(
            allocation, "initWithTypeIdentifier:layerGroups:",
            "@32@0:8@16@24")) return nil;
    return ((id (*)(id, SEL, id, id))objc_msgSend)(
        allocation, sel_registerName("initWithTypeIdentifier:layerGroups:"),
        @(CNDClockBaseType), @[]);
}

static id CNDClockBaseOuterRequest(id icon, id descriptor)
{
    if (!icon || !descriptor) return nil;
    SEL prepare = sel_registerName("prepareImageForDescriptor:");
    if ([icon respondsToSelector:prepare]) {
        ((void (*)(id, SEL, id))objc_msgSend)(icon, prepare, descriptor);
    }
    SEL imageSelector = sel_registerName("imageForDescriptor:");
    if (![icon respondsToSelector:imageSelector]) return nil;
    id image = nil;
    for (unsigned attempt = 1U; attempt <= 20U; attempt++) {
        image = ((id (*)(id, SEL, id))objc_msgSend)(
            icon, imageSelector, descriptor);
        const char *className = image
            ? class_getName(object_getClass(image)) : "-";
        printf("CND_CLOCK_BASE outer-attempt=%u icon=%p/%s image=%p/%s\n",
               attempt, (__bridge void *)icon,
               class_getName(object_getClass(icon)),
               (__bridge void *)image, className);
        fflush(stdout);
        if (image && !strstr(className, "Placeholder")) break;
        usleep(250000);
    }
    return image;
}

static NSDictionary *CNDClockBaseDescribeImage(id image, id store)
{
    id uuid1 = CNDClockBaseObjectGetter(image, "uuid");
    id uuid2 = CNDClockBaseObjectGetter(image, "uuid");
    id token = CNDClockBaseObjectGetter(image, "validationToken");
    id data = CNDClockBaseObjectGetter(image, "data");
    NSData *imageData = [data isKindOfClass:NSData.class] ? data : nil;
    NSData *tokenData = [token isKindOfClass:NSData.class] ? token : nil;
    CGImageRef cgImage = NULL;
    Method cgMethod = CNDClockBaseMethod(image, "CGImage");
    if (cgMethod) {
        char *returnType = method_copyReturnType(cgMethod);
        const char *type = CNDClockBaseSkipQualifiers(returnType);
        bool pointerReturn = type && *type == '^';
        free(returnType);
        if (pointerReturn) {
            cgImage = ((CGImageRef (*)(id, SEL))objc_msgSend)(
                image, sel_registerName("CGImage"));
        }
    }
    NSData *rgba = CNDClockBaseRGBAData(cgImage);
    id unit = uuid1 && store && [store respondsToSelector:
        sel_registerName("unitForUUID:")]
        ? ((id (*)(id, SEL, id))objc_msgSend)(
            store, sel_registerName("unitForUUID:"), uuid1)
        : nil;
    NSData *unitData = [CNDClockBaseObjectGetter(unit, "data")
        isKindOfClass:NSData.class]
        ? CNDClockBaseObjectGetter(unit, "data") : nil;
    id storeURL = CNDClockBaseObjectGetter(store, "storeURL");
    NSString *storePath = [storeURL isKindOfClass:NSURL.class]
        ? [storeURL path] : @"-";
    NSString *unitPath = ![CNDClockBaseUUIDText(uuid1) isEqualToString:@"-"] &&
        ![storePath isEqualToString:@"-"]
        ? [storePath stringByAppendingPathComponent:
            [CNDClockBaseUUIDText(uuid1)
                stringByAppendingPathExtension:@"isdata"]]
        : @"-";
    NSData *fileData = ![unitPath isEqualToString:@"-"]
        ? [NSData dataWithContentsOfFile:unitPath] : nil;
    return @{
        @"class": image ? @(class_getName(object_getClass(image))) : @"-",
        @"uuid1": CNDClockBaseUUIDText(uuid1),
        @"uuid2": CNDClockBaseUUIDText(uuid2),
        @"uuidStableAcrossGetters": @([CNDClockBaseUUIDText(uuid1)
            isEqualToString:CNDClockBaseUUIDText(uuid2)]),
        @"dataLength": @(imageData.length),
        @"dataSHA256": CNDClockBaseSHA256(imageData),
        @"tokenLength": @(tokenData.length),
        @"tokenSHA256": CNDClockBaseSHA256(tokenData),
        @"pixelWidth": @(cgImage ? CGImageGetWidth(cgImage) : 0U),
        @"pixelHeight": @(cgImage ? CGImageGetHeight(cgImage) : 0U),
        @"pixelSHA256": CNDClockBaseSHA256(rgba),
        @"alpha": CNDClockBaseAlphaSummary(rgba),
        @"storeUnitPresent": @(unit != nil),
        @"storeUnitClass": unit
            ? @(class_getName(object_getClass(unit))) : @"-",
        @"storeUnitDataLength": @(unitData.length),
        @"storeUnitDataSHA256": CNDClockBaseSHA256(unitData),
        @"storeURL": storePath ?: @"-",
        @"storeUnitPath": unitPath ?: @"-",
        @"storeFileLength": @(fileData.length),
        @"storeFileSHA256": CNDClockBaseSHA256(fileData),
    };
}

static NSString *CNDClockBaseJSON(id object)
{
    NSData *data = [NSJSONSerialization dataWithJSONObject:object
        options:NSJSONWritingSortedKeys error:nil];
    return data ? [[NSString alloc] initWithData:data
                                         encoding:NSUTF8StringEncoding]
                : @"{}";
}

static NSDictionary *CNDClockBaseClearLocalImageCache(id icon)
{
    id cache = CNDClockBaseObjectGetter(icon, "imageCache");
    id before = CNDClockBaseObjectGetter(cache, "allImages");
    NSUInteger beforeCount = [before respondsToSelector:@selector(count)]
        ? [before count] : NSNotFound;
    SEL setter = sel_registerName("setImageBagsByDescriptor:");
    BOOL supported = cache && [cache respondsToSelector:setter];
    BOOL succeeded = NO;
    NSString *exceptionText = @"-";
    if (supported) {
        @try {
            ((void (*)(id, SEL, id))objc_msgSend)(
                cache, setter, [NSMutableDictionary dictionary]);
            succeeded = YES;
        } @catch (NSException *exception) {
            exceptionText = exception.description ?: @"unknown";
        }
    }
    id after = CNDClockBaseObjectGetter(cache, "allImages");
    NSUInteger afterCount = [after respondsToSelector:@selector(count)]
        ? [after count] : NSNotFound;
    return @{
        @"cacheClass": cache
            ? @(class_getName(object_getClass(cache))) : @"-",
        @"cachePointer": [NSString stringWithFormat:@"%p", cache],
        @"setImageBagsSupported": @(supported),
        @"clearSucceeded": @(succeeded),
        @"beforeCount": beforeCount == NSNotFound
            ? @(-1) : @(beforeCount),
        @"afterCount": afterCount == NSNotFound
            ? @(-1) : @(afterCount),
        @"exception": exceptionText,
    };
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        bool ignoreCache = false;
        bool dumpRuntime = false;
        for (int index = 1; index < argc; index++) {
            if (!strcmp(argv[index], "--ignore-cache")) {
                ignoreCache = true;
            } else if (!strcmp(argv[index], "--dump-runtime")) {
                dumpRuntime = true;
            } else {
                fprintf(stderr, "usage: %s [--ignore-cache] "
                                "[--dump-runtime]\n", argv[0]);
                return 64;
            }
        }
        void *handle = dlopen(
            "/System/Library/PrivateFrameworks/IconServices.framework/"
            "IconServices", RTLD_NOW | RTLD_LOCAL);
        Class iconClass = handle ? NSClassFromString(@"ISLayeredIcon") : Nil;
        Class managerClass = handle ? NSClassFromString(@"ISIconManager") : Nil;
        Class descriptorClass = handle
            ? NSClassFromString(@"ISImageDescriptor") : Nil;
        if (!iconClass || !managerClass || !descriptorClass) {
            fprintf(stderr, "IconServices classes unavailable\n");
            return 2;
        }
        id manager = ((id (*)(id, SEL))objc_msgSend)(
            managerClass, sel_registerName("sharedInstance"));
        id managerCache = CNDClockBaseObjectGetter(manager, "iconCache");
        id store = CNDClockBaseObjectGetter(managerCache, "store");
        id descriptor = CNDClockBaseMakeDescriptor(
            descriptorClass, ignoreCache);
        id firstLocal = CNDClockBaseMakeIcon(iconClass);
        id first = firstLocal && manager
            ? ((id (*)(id, SEL, id))objc_msgSend)(
                manager, sel_registerName("findOrRegisterIcon:"), firstLocal)
            : nil;
        id secondLocal = CNDClockBaseMakeIcon(iconClass);
        id second = secondLocal && manager
            ? ((id (*)(id, SEL, id))objc_msgSend)(
                manager, sel_registerName("findOrRegisterIcon:"), secondLocal)
            : nil;
        if (!descriptor || !first || !second) {
            fprintf(stderr, "clock.base construction or registration failed\n");
            return 3;
        }
        id digest = CNDClockBaseObjectGetter(descriptor, "digest");
        NSString *digestText = CNDClockBaseUUIDText(digest);
        NSInteger appearance = [descriptor respondsToSelector:
            sel_registerName("appearance")]
            ? ((NSInteger (*)(id, SEL))objc_msgSend)(
                descriptor, sel_registerName("appearance")) : -1;
        NSInteger special = [descriptor respondsToSelector:
            sel_registerName("specialIconOptions")]
            ? ((NSInteger (*)(id, SEL))objc_msgSend)(
                descriptor, sel_registerName("specialIconOptions")) : -1;
        NSInteger layout = [descriptor respondsToSelector:
            sel_registerName("layoutDirection")]
            ? ((NSInteger (*)(id, SEL))objc_msgSend)(
                descriptor, sel_registerName("layoutDirection")) : -1;
        id firstIdentity = CNDClockBaseObjectGetter(first, "_identity");
        id secondIdentity = CNDClockBaseObjectGetter(second, "_identity");
        NSDictionary *registration = @{
            @"local1": [NSString stringWithFormat:@"%p", firstLocal],
            @"canonical1": [NSString stringWithFormat:@"%p", first],
            @"local2": [NSString stringWithFormat:@"%p", secondLocal],
            @"canonical2": [NSString stringWithFormat:@"%p", second],
            @"sameCanonicalObject": @(first == second),
            @"identity1": CNDClockBaseUUIDText(firstIdentity),
            @"identity2": CNDClockBaseUUIDText(secondIdentity),
            @"sameIdentity": @([CNDClockBaseUUIDText(firstIdentity)
                isEqualToString:CNDClockBaseUUIDText(secondIdentity)]),
            @"typeIdentifier": CNDClockBaseObjectGetter(
                first, "typeIdentifier") ?: @"-",
        };
        NSDictionary *descriptorReport = @{
            @"description": [descriptor description] ?: @"-",
            @"digest": digestText,
            @"expectedDigest": @(CNDClockBaseExpectedDigest),
            @"digestMatches": @([digestText isEqualToString:
                @(CNDClockBaseExpectedDigest)]),
            @"appearance": @(appearance),
            @"specialIconOptions": @(special),
            @"layoutDirection": @(layout),
            @"ignoreCache": @(ignoreCache),
        };
        id sameObjectImage1 = CNDClockBaseOuterRequest(first, descriptor);
        NSDictionary *same1 = CNDClockBaseDescribeImage(
            sameObjectImage1, store);
        id sameObjectImage2 = CNDClockBaseOuterRequest(first, descriptor);
        NSDictionary *same2 = CNDClockBaseDescribeImage(
            sameObjectImage2, store);
        id freshImage = CNDClockBaseOuterRequest(second, descriptor);
        NSDictionary *fresh = CNDClockBaseDescribeImage(freshImage, store);
        NSDictionary *localCacheClear =
            CNDClockBaseClearLocalImageCache(first);
        id afterClearImage = CNDClockBaseOuterRequest(first, descriptor);
        NSDictionary *afterClear = CNDClockBaseDescribeImage(
            afterClearImage, store);

        id freshManager = ((id (*)(id, SEL))objc_msgSend)(
            managerClass, sel_registerName("sharedInstance"));
        id thirdLocal = CNDClockBaseMakeIcon(iconClass);
        id third = thirdLocal && freshManager
            ? ((id (*)(id, SEL, id))objc_msgSend)(
                freshManager, sel_registerName("findOrRegisterIcon:"),
                thirdLocal)
            : nil;
        id thirdIdentity = CNDClockBaseObjectGetter(third, "_identity");
        id freshManagerImage = CNDClockBaseOuterRequest(third, descriptor);
        NSDictionary *freshManagerLookup = @{
            @"managerPointer": [NSString stringWithFormat:@"%p",
                freshManager],
            @"sameManagerObject": @(freshManager == manager),
            @"localPointer": [NSString stringWithFormat:@"%p", thirdLocal],
            @"canonicalPointer": [NSString stringWithFormat:@"%p", third],
            @"returnedLocalObject": @(third == thirdLocal),
            @"identity": CNDClockBaseUUIDText(thirdIdentity),
            @"image": CNDClockBaseDescribeImage(
                freshManagerImage, store),
        };
        NSDictionary *result = @{
            @"pid": @(getpid()),
            @"registration": registration,
            @"descriptor": descriptorReport,
            @"managerCacheClass": managerCache
                ? @(class_getName(object_getClass(managerCache))) : @"-",
            @"storeClass": store
                ? @(class_getName(object_getClass(store))) : @"-",
            @"sameObjectFirst": same1,
            @"sameObjectSecond": same2,
            @"freshRegisteredIcon": fresh,
            @"localCacheClear": localCacheClear,
            @"afterLocalCacheClear": afterClear,
            @"freshManagerLookup": freshManagerLookup,
        };
        printf("CND_CLOCK_BASE result=%s\n",
               CNDClockBaseJSON(result).UTF8String);
        if (dumpRuntime) {
            CNDClockBaseDumpMethods(manager, "manager");
            CNDClockBaseDumpMethods(first, "registered-icon");
            CNDClockBaseDumpMethods(
                CNDClockBaseObjectGetter(first, "imageCache"),
                "icon-image-cache");
            CNDClockBaseDumpMethods(managerCache, "manager-image-cache");
            CNDClockBaseDumpMethods(store, "store");
        }
        bool exactDescriptor = [digestText isEqualToString:
            @(CNDClockBaseExpectedDigest)] && appearance == 0 &&
            special == 2 && layout == 5;
        return exactDescriptor && sameObjectImage1 && sameObjectImage2 &&
            freshImage && afterClearImage && freshManagerImage ? 0 : 4;
    }
}
