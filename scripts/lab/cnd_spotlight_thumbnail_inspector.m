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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CND_THUMBNAIL_OUTPUT_TOKEN
#define CND_THUMBNAIL_OUTPUT_TOKEN ""
#endif

#ifndef CND_THUMBNAIL_APPLY
#define CND_THUMBNAIL_APPLY 0
#endif

#ifndef CND_THUMBNAIL_PERSIST
#define CND_THUMBNAIL_PERSIST 0
#endif

static const char *const CNDThumbnailOutputPath =
    "/var/tmp/cyanide-spotlight-thumbnail-inspection.log";
static int gCNDThumbnailFD = -1;
static unsigned gCNDThumbnailAttempt;
static bool gCNDThumbnailPersistentFetchStarted;
static bool gCNDThumbnailPersistentFetchFinished;
static bool gCNDThumbnailPersistentSourceLogged;
static id gCNDThumbnailFetchedItem;
static id gCNDThumbnailFetchError;
static id gCNDThumbnailFilesFallbackImage;
#if CND_THUMBNAIL_PERSIST
static bool gCNDThumbnailPersistentMutationAttempted;
static bool gCNDThumbnailPersistentMutationOK;
#endif

static void CNDThumbnailLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDThumbnailLog(const char *format, ...)
{
    if (gCNDThumbnailFD < 0) return;
    char line[8192] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDThumbnailFD, line, amount);
    (void)fsync(gCNDThumbnailFD);
}

static const char *CNDThumbnailClassName(id object)
{
    return object ? class_getName(object_getClass(object)) : "-";
}

static void *CNDThumbnailPointer(id object)
{
    return object ? (__bridge void *)object : NULL;
}

static const char *CNDThumbnailSkipQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static id CNDThumbnailObjectGetter(id object, const char *name)
{
    if (!object || !name || !name[0]) return nil;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *returnType = method_copyReturnType(method);
    const char *unqualified = CNDThumbnailSkipQualifiers(returnType);
    bool objectReturn = unqualified &&
        (*unqualified == '@' || *unqualified == '#');
    free(returnType);
    if (!objectReturn) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (NSException *exception) {
        CNDThumbnailLog("[CND_THUMBNAIL] getter-exception object=%p/%s "
                        "selector=%s exception=%s\n",
                        CNDThumbnailPointer(object),
                        CNDThumbnailClassName(object), name,
                        exception.name.UTF8String ?: "-");
        return nil;
    }
}

static id CNDThumbnailObjectIvar(id object, const char *name)
{
    if (!object || !name || !name[0]) return nil;
    Ivar ivar = class_getInstanceVariable(object_getClass(object), name);
    if (!ivar) return nil;
    const char *type = CNDThumbnailSkipQualifiers(ivar_getTypeEncoding(ivar));
    if (!type || *type != '@') return nil;
    @try {
        return object_getIvar(object, ivar);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static bool CNDThumbnailUnsignedGetter(id object, const char *name,
                                       NSUInteger *value)
{
    if (value) *value = 0U;
    if (!object || !name || !name[0] || !value) return false;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return false;
    char *returnType = method_copyReturnType(method);
    const char *unqualified = CNDThumbnailSkipQualifiers(returnType);
    bool valid = unqualified &&
        (!strcmp(unqualified, @encode(NSUInteger)) ||
         !strcmp(unqualified, @encode(unsigned long long)) ||
         !strcmp(unqualified, @encode(unsigned long)) ||
         !strcmp(unqualified, @encode(unsigned int)));
    free(returnType);
    if (!valid) return false;
    @try {
        *value = ((NSUInteger (*)(id, SEL))objc_msgSend)(object, selector);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static int CNDThumbnailBoolGetter(id object, const char *name)
{
    if (!object || !name || !name[0]) return -1;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return -1;
    char *returnType = method_copyReturnType(method);
    const char *unqualified = CNDThumbnailSkipQualifiers(returnType);
    bool valid = unqualified && (*unqualified == 'B' || *unqualified == 'c');
    free(returnType);
    if (!valid) return -1;
    @try {
        return ((BOOL (*)(id, SEL))objc_msgSend)(object, selector) ? 1 : 0;
    } @catch (__unused NSException *exception) {
        return -1;
    }
}

static NSArray *CNDThumbnailCollectionItems(id collection, NSUInteger cap)
{
    if (!collection || cap == 0U) return @[];
    if ([collection isKindOfClass:NSArray.class]) {
        NSArray *array = collection;
        return array.count > cap
            ? [array subarrayWithRange:NSMakeRange(0, cap)] : array;
    }
    id objects = CNDThumbnailObjectGetter(collection, "allObjects");
    if ([objects isKindOfClass:NSArray.class]) {
        NSArray *array = objects;
        return array.count > cap
            ? [array subarrayWithRange:NSMakeRange(0, cap)] : array;
    }
    return @[];
}

static NSArray<UIWindow *> *CNDThumbnailWindows(void)
{
    UIApplication *application = UIApplication.sharedApplication;
    NSMutableArray<UIWindow *> *windows = [NSMutableArray array];
    id scenes = CNDThumbnailObjectGetter(application, "connectedScenes");
    for (id scene in CNDThumbnailCollectionItems(scenes, 16U)) {
        id sceneWindows = CNDThumbnailObjectGetter(scene, "windows");
        for (id window in CNDThumbnailCollectionItems(sceneWindows, 32U)) {
            if ([window isKindOfClass:UIWindow.class] &&
                ![windows containsObject:window]) {
                [windows addObject:window];
            }
        }
    }
    id legacyWindows = CNDThumbnailObjectGetter(application, "windows");
    for (id window in CNDThumbnailCollectionItems(legacyWindows, 32U)) {
        if ([window isKindOfClass:UIWindow.class] &&
            ![windows containsObject:window]) {
            [windows addObject:window];
        }
    }
    return windows;
}

static NSArray<UIView *> *CNDThumbnailAllViews(void)
{
    NSMutableArray<UIView *> *views = [NSMutableArray array];
    NSMutableArray<UIView *> *pending = [NSMutableArray array];
    [pending addObjectsFromArray:CNDThumbnailWindows()];
    const NSUInteger cap = 4096U;
    NSUInteger cursor = 0U;
    while (cursor < pending.count && cursor < cap) {
        UIView *view = pending[cursor++];
        [views addObject:view];
        NSUInteger available = cap > pending.count ? cap - pending.count : 0U;
        NSArray<UIView *> *subviews = view.subviews;
        if (subviews.count > available) {
            if (available) {
                [pending addObjectsFromArray:
                    [subviews subarrayWithRange:NSMakeRange(0, available)]];
            }
            break;
        }
        [pending addObjectsFromArray:subviews];
    }
    CNDThumbnailLog("[CND_THUMBNAIL] view-walk windows=%lu views=%lu "
                    "truncated=%d\n",
                    (unsigned long)CNDThumbnailWindows().count,
                    (unsigned long)views.count, pending.count > cap);
    return views;
}

static NSString *CNDThumbnailString(id object)
{
    if (!object) return @"-";
    if ([object isKindOfClass:NSString.class]) return object;
    if ([object isKindOfClass:NSURL.class]) {
        return [(NSURL *)object absoluteString] ?: @"-";
    }
    NSString *description = nil;
    @try {
        description = [object description];
    } @catch (__unused NSException *exception) {
        description = nil;
    }
    if (![description isKindOfClass:NSString.class]) return @"-";
    return description.length > 512U
        ? [[description substringToIndex:512U] stringByAppendingString:@"..."]
        : description;
}

static NSData *CNDThumbnailCanonicalRGBA(CGImageRef image)
{
    if (!image) return nil;
    size_t width = CGImageGetWidth(image);
    size_t height = CGImageGetHeight(image);
    if (!width || !height || width > 2048U || height > 2048U ||
        width > SIZE_MAX / 4U || height > SIZE_MAX / (width * 4U)) {
        return nil;
    }
    size_t bytesPerRow = width * 4U;
    NSMutableData *pixels = [NSMutableData dataWithLength:bytesPerRow * height];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    if (!colorSpace) return nil;
    CGContextRef context = CGBitmapContextCreate(
        pixels.mutableBytes, width, height, 8U, bytesPerRow, colorSpace,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(colorSpace);
    if (!context) return nil;
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), image);
    CGContextRelease(context);
    return pixels;
}

static NSString *CNDThumbnailImageHash(UIImage *image)
{
    NSData *pixels = CNDThumbnailCanonicalRGBA(image.CGImage);
    if (!pixels) return @"-";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(pixels.bytes, (CC_LONG)pixels.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:64U];
    for (size_t i = 0; i < sizeof(digest); i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    return result;
}

static void CNDThumbnailLogControllerGraph(void)
{
    NSMutableArray *pending = [NSMutableArray array];
    for (UIWindow *window in CNDThumbnailWindows()) {
        if (window.rootViewController) {
            [pending addObject:window.rootViewController];
        }
    }
    NSMutableSet<NSValue *> *seen = [NSMutableSet set];
    for (NSUInteger cursor = 0U; cursor < pending.count && cursor < 128U;
         cursor++) {
        UIViewController *controller = pending[cursor];
        NSValue *identity = [NSValue valueWithPointer:
            (__bridge const void *)controller];
        if ([seen containsObject:identity]) continue;
        [seen addObject:identity];
        NSString *className = NSStringFromClass(controller.class);
        if ([className containsString:@"Search"] ||
            [className containsString:@"Spotlight"] ||
            [controller respondsToSelector:
                sel_registerName("resultsTableViewController")]) {
            CNDThumbnailLog("[CND_THUMBNAIL] controller object=%p/%s "
                            "children=%lu presented=%p/%s\n",
                            CNDThumbnailPointer(controller),
                            CNDThumbnailClassName(controller),
                            (unsigned long)controller.childViewControllers.count,
                            CNDThumbnailPointer(
                                controller.presentedViewController),
                            CNDThumbnailClassName(
                                controller.presentedViewController));
        }
        UIViewController *presented = controller.presentedViewController;
        if (presented && pending.count < 128U) [pending addObject:presented];
        for (UIViewController *child in controller.childViewControllers) {
            if (pending.count >= 128U) break;
            [pending addObject:child];
        }
        id results = CNDThumbnailObjectGetter(
            controller, "resultsTableViewController");
        id collection = CNDThumbnailObjectGetter(results, "collectionView");
        id visibleCells = CNDThumbnailObjectGetter(collection, "visibleCells");
        if (!results || !collection || !visibleCells) continue;
        NSArray *cells = CNDThumbnailCollectionItems(visibleCells, 128U);
        CNDThumbnailLog("[CND_THUMBNAIL] results-graph owner=%p/%s "
                        "results=%p/%s collection=%p/%s visibleCells=%lu\n",
                        CNDThumbnailPointer(controller),
                        CNDThumbnailClassName(controller),
                        CNDThumbnailPointer(results),
                        CNDThumbnailClassName(results),
                        CNDThumbnailPointer(collection),
                        CNDThumbnailClassName(collection),
                        (unsigned long)cells.count);
        for (id cell in cells) {
            id model = CNDThumbnailObjectGetter(cell, "rowModel");
            id title = CNDThumbnailObjectGetter(model, "displayTitle");
            if ([title isKindOfClass:NSString.class] &&
                [(NSString *)title localizedCaseInsensitiveContainsString:
                    @"File Provider Storage"]) {
                CNDThumbnailLog("[CND_THUMBNAIL] results-cell target=1 "
                                "cell=%p/%s model=%p/%s title=%s\n",
                                CNDThumbnailPointer(cell),
                                CNDThumbnailClassName(cell),
                                CNDThumbnailPointer(model),
                                CNDThumbnailClassName(model),
                                [(NSString *)title UTF8String]);
            }
        }
    }
}

static void CNDThumbnailLogGetter(id object, const char *label,
                                  const char *getter)
{
    id value = CNDThumbnailObjectGetter(object, getter);
    CNDThumbnailLog("[CND_THUMBNAIL] property label=%s owner=%p/%s "
                    "name=%s value=%p/%s text=%s\n",
                    label, CNDThumbnailPointer(object),
                    CNDThumbnailClassName(object), getter,
                    CNDThumbnailPointer(value), CNDThumbnailClassName(value),
                    CNDThumbnailString(value).UTF8String ?: "-");
}

static void CNDThumbnailDumpRelevantSurface(id object, const char *label)
{
    if (!object) return;
    for (Class cls = object_getClass(object); cls; cls = class_getSuperclass(cls)) {
        const char *className = class_getName(cls);
        if (className && (!strcmp(className, "NSObject") ||
                          !strcmp(className, "UIView") ||
                          !strcmp(className, "UIResponder"))) break;
        unsigned ivarCount = 0U;
        Ivar *ivars = class_copyIvarList(cls, &ivarCount);
        for (unsigned i = 0U; ivars && i < ivarCount && i < 96U; i++) {
            const char *name = ivar_getName(ivars[i]);
            const char *type = CNDThumbnailSkipQualifiers(
                ivar_getTypeEncoding(ivars[i]));
            if (!name || !type || *type != '@') continue;
            id value = nil;
            @try { value = object_getIvar(object, ivars[i]); }
            @catch (__unused NSException *exception) { value = nil; }
            CNDThumbnailLog("[CND_THUMBNAIL] ivar label=%s owner=%s "
                            "name=%s value=%p/%s text=%s\n",
                            label, className ?: "-", name,
                            CNDThumbnailPointer(value),
                            CNDThumbnailClassName(value),
                            CNDThumbnailString(value).UTF8String ?: "-");
        }
        free(ivars);
    }
}

static void CNDThumbnailMutatePersistentSourceIfRequested(void)
{
#if CND_THUMBNAIL_PERSIST
    if (gCNDThumbnailPersistentMutationAttempted) return;
    gCNDThumbnailPersistentMutationAttempted = true;
    id item = gCNDThumbnailFetchedItem;
    NSURL *url = CNDThumbnailObjectGetter(item, "fileURL");
    Class additionClass = NSClassFromString(@"QLThumbnailAddition");
    NSError *error = nil;
    BOOL ok = NO;
#if CND_THUMBNAIL_PERSIST == 1
    SEL loadSelector = sel_registerName("loadImageWithScale:isDarkStyle:");
    UIImage *image = gCNDThumbnailFilesFallbackImage &&
        [gCNDThumbnailFilesFallbackImage respondsToSelector:loadSelector]
        ? ((id (*)(id, SEL, double, BOOL))objc_msgSend)(
            gCNDThumbnailFilesFallbackImage, loadSelector, 3.0, NO)
        : nil;
    CGImageRef cgImage = image.CGImage;
    SEL metadataSelector = sel_registerName(
        "metadataForGeneratedThumbnailForURL:maximumDimension:");
    NSDictionary *metadata = additionClass && url &&
        [additionClass respondsToSelector:metadataSelector]
        ? ((id (*)(id, SEL, id, double))objc_msgSend)(
            additionClass, metadataSelector, url,
            (double)MAX(CGImageGetWidth(cgImage), CGImageGetHeight(cgImage)))
        : nil;
    SEL associateSelector = sel_registerName(
        "associateImage:metadata:automaticallyGenerated:withURL:error:");
    if (additionClass && url && cgImage &&
        [additionClass respondsToSelector:associateSelector]) {
        ok = ((BOOL (*)(id, SEL, CGImageRef, id, BOOL, id, NSError **))
            objc_msgSend)(additionClass, associateSelector, cgImage,
                          metadata, NO, url, &error);
    }
    CNDThumbnailLog("[CND_THUMBNAIL] persistent-mutation action=install "
                    "ok=%d url=%s image=%p pixels=%zux%zu metadata=%p/%s "
                    "error=%s\n", ok, url.absoluteString.UTF8String ?: "-",
                    CNDThumbnailPointer(image),
                    cgImage ? CGImageGetWidth(cgImage) : 0U,
                    cgImage ? CGImageGetHeight(cgImage) : 0U,
                    CNDThumbnailPointer(metadata),
                    CNDThumbnailClassName(metadata),
                    CNDThumbnailString(error).UTF8String ?: "-");
#elif CND_THUMBNAIL_PERSIST == 2
    SEL removeSelector = sel_registerName("removeAdditionsOnURL:error:");
    if (additionClass && url &&
        [additionClass respondsToSelector:removeSelector]) {
        ok = ((BOOL (*)(id, SEL, id, NSError **))objc_msgSend)(
            additionClass, removeSelector, url, &error);
    }
    CNDThumbnailLog("[CND_THUMBNAIL] persistent-mutation action=remove "
                    "ok=%d url=%s error=%s\n", ok,
                    url.absoluteString.UTF8String ?: "-",
                    CNDThumbnailString(error).UTF8String ?: "-");
#endif
    id addition = nil;
    NSError *readbackError = nil;
    SEL allocationSelector = sel_registerName("alloc");
    SEL initSelector = sel_registerName(
        "initWithAdditionsPresentOnURL:includingExtendedAttributes:error:");
    if (additionClass && url &&
        [additionClass instancesRespondToSelector:initSelector]) {
        id allocation = ((id (*)(id, SEL))objc_msgSend)(
            additionClass, allocationSelector);
        addition = ((id (*)(id, SEL, id, BOOL, NSError **))objc_msgSend)(
            allocation, initSelector, url, YES, &readbackError);
    }
#if CND_THUMBNAIL_PERSIST == 1
    gCNDThumbnailPersistentMutationOK = ok && addition != nil;
#else
    gCNDThumbnailPersistentMutationOK = ok && addition == nil;
#endif
    CNDThumbnailLog("[CND_THUMBNAIL] persistent-mutation-readback "
                    "ok=%d addition=%p/%s size=%s version=%s error=%s\n",
                    gCNDThumbnailPersistentMutationOK,
                    CNDThumbnailPointer(addition),
                    CNDThumbnailClassName(addition),
                    CNDThumbnailString(CNDThumbnailObjectGetter(
                        addition, "additionSize")).UTF8String ?: "-",
                    CNDThumbnailString(CNDThumbnailObjectGetter(
                        addition, "thumbnailVersion")).UTF8String ?: "-",
                    CNDThumbnailString(readbackError).UTF8String ?: "-");
#endif
}

static void CNDThumbnailInspectPersistentSource(id leadingImage,
                                                 id fallbackImage)
{
    if (!gCNDThumbnailFilesFallbackImage && fallbackImage) {
        gCNDThumbnailFilesFallbackImage = fallbackImage;
    }
    if (!gCNDThumbnailPersistentFetchStarted && leadingImage) {
        Class imageClass = NSClassFromString(@"SearchUIImage");
        SEL wrapSelector = sel_registerName("imageWithSFImage:");
        id wrapper = imageClass &&
            [imageClass respondsToSelector:wrapSelector]
            ? ((id (*)(id, SEL, id))objc_msgSend)(
                imageClass, wrapSelector, leadingImage)
            : nil;
        id itemID = CNDThumbnailObjectGetter(wrapper, "fpItemID");
        Class managerClass = NSClassFromString(@"FPItemManager");
        SEL defaultSelector = sel_registerName("defaultManager");
        id manager = managerClass &&
            [managerClass respondsToSelector:defaultSelector]
            ? ((id (*)(id, SEL))objc_msgSend)(managerClass, defaultSelector)
            : nil;
        SEL fetchSelector = sel_registerName(
            "fetchItemForItemID:completionHandler:");
        if (itemID && manager && [manager respondsToSelector:fetchSelector]) {
            gCNDThumbnailPersistentFetchStarted = true;
            CNDThumbnailLog("[CND_THUMBNAIL] persistent-fetch begin "
                            "wrapper=%p/%s itemID=%p/%s text=%s\n",
                            CNDThumbnailPointer(wrapper),
                            CNDThumbnailClassName(wrapper),
                            CNDThumbnailPointer(itemID),
                            CNDThumbnailClassName(itemID),
                            CNDThumbnailString(itemID).UTF8String ?: "-");
            void (^completion)(id, NSError *) = ^(id item, NSError *error) {
                gCNDThumbnailFetchedItem = item;
                gCNDThumbnailFetchError = error;
                gCNDThumbnailPersistentFetchFinished = true;
            };
            ((void (*)(id, SEL, id, id))objc_msgSend)(
                manager, fetchSelector, itemID, completion);
        } else {
            gCNDThumbnailPersistentFetchStarted = true;
            gCNDThumbnailPersistentFetchFinished = true;
            gCNDThumbnailFetchError = @"FPItemManager route unavailable";
        }
    }

    if (!gCNDThumbnailPersistentFetchFinished ||
        gCNDThumbnailPersistentSourceLogged) return;
    gCNDThumbnailPersistentSourceLogged = true;
    id item = gCNDThumbnailFetchedItem;
    CNDThumbnailLog("[CND_THUMBNAIL] persistent-fetch end item=%p/%s "
                    "error=%s\n", CNDThumbnailPointer(item),
                    CNDThumbnailClassName(item),
                    CNDThumbnailString(gCNDThumbnailFetchError).UTF8String ?:
                        "-");
    static const char *const itemGetters[] = {
        "itemIdentifier", "providerItemIdentifier", "providerIdentifier",
        "providerID", "domainIdentifier", "providerDomainID",
        "fileURL", "filename", "displayName", "contentType",
        "typeIdentifier", "versionIdentifier", "itemVersion",
        "extendedAttributes", "userInfo", "resolvedUserInfo",
        "folderType", "fileID", "documentID", "contentModificationDate",
        "creationDate", "appContainerBundleIdentifier",
        "fp_appContainerBundleIdentifier", "spotlightDomainIdentifier",
        "fp_spotlightDomainIdentifier", "providerItemID", "itemID",
    };
    for (size_t index = 0;
         item && index < sizeof(itemGetters) / sizeof(itemGetters[0]);
         index++) {
        CNDThumbnailLogGetter(item, "persistent-fp-item",
                              itemGetters[index]);
    }
    if (item) CNDThumbnailDumpRelevantSurface(item, "persistent-fp-item");

    Class requestClass = NSClassFromString(@"QLThumbnailGenerationRequest");
    SEL identifierSelector = sel_registerName(
        "_fileProviderFileIdentifierForFPItem:");
    id cacheIdentifier = item && requestClass &&
        [requestClass respondsToSelector:identifierSelector]
        ? ((id (*)(id, SEL, id))objc_msgSend)(
            requestClass, identifierSelector, item)
        : nil;
    CNDThumbnailLog("[CND_THUMBNAIL] persistent-cache-identifier "
                    "object=%p/%s text=%s\n",
                    CNDThumbnailPointer(cacheIdentifier),
                    CNDThumbnailClassName(cacheIdentifier),
                    CNDThumbnailString(cacheIdentifier).UTF8String ?: "-");
    if (cacheIdentifier) {
        CNDThumbnailDumpRelevantSurface(
            cacheIdentifier, "persistent-cache-identifier");
    }
    CNDThumbnailMutatePersistentSourceIfRequested();
}

static bool CNDThumbnailRunOnce(void)
{
    NSCAssert(NSThread.isMainThread, @"thumbnail inspection requires main");
    CNDThumbnailLogControllerGraph();
    NSArray<UIView *> *views = CNDThumbnailAllViews();
    Class rowClass = NSClassFromString(@"SearchUIRowCardSectionView");
    Class cellClass = NSClassFromString(@"SearchUICollectionViewCell");
    Class imageViewClass = NSClassFromString(@"SearchUIImageView");
    Class quickLookClass = NSClassFromString(@"SearchUIQuickLookThumbnailImage");
    NSUInteger visibleRows = 0U;
    NSUInteger matchingRows = 0U;
    NSUInteger visibleImageViews = 0U;
    NSUInteger quickLookImages = 0U;
    NSUInteger exactRootImages = 0U;
    NSUInteger appliedRootImages = 0U;

    for (UIView *view in views) {
        BOOL rowCarrier = (rowClass && [view isKindOfClass:rowClass]) ||
            (cellClass && [view isKindOfClass:cellClass]) ||
            [view respondsToSelector:sel_registerName("rowModel")];
        if (!rowCarrier || !view.window || view.hidden ||
            view.alpha < 0.01) continue;
        visibleRows++;
        id rowModel = CNDThumbnailObjectGetter(view, "rowModel") ?:
            CNDThumbnailObjectIvar(view, "_rowModel");
        id title = CNDThumbnailObjectGetter(rowModel, "displayTitle");
        id leadingImage = CNDThumbnailObjectGetter(rowModel, "leadingImage") ?:
            CNDThumbnailObjectIvar(rowModel, "_leadingImage");
        id fallbackImage = CNDThumbnailObjectGetter(rowModel, "fallbackImage") ?:
            CNDThumbnailObjectIvar(rowModel, "_fallbackImage");
        CGRect frame = [view convertRect:view.bounds toView:nil];
        BOOL target = [title isKindOfClass:NSString.class] &&
            [(NSString *)title localizedCaseInsensitiveContainsString:
                @"File Provider Storage"];
        if (target) matchingRows++;
        CNDThumbnailLog("[CND_THUMBNAIL] row target=%d view=%p/%s "
                        "frame=%.1f,%.1f,%.1f,%.1f model=%p/%s title=%s "
                        "leading=%p/%s fallback=%p/%s\n",
                        target, CNDThumbnailPointer(view),
                        CNDThumbnailClassName(view), frame.origin.x,
                        frame.origin.y, frame.size.width, frame.size.height,
                        CNDThumbnailPointer(rowModel),
                        CNDThumbnailClassName(rowModel),
                        CNDThumbnailString(title).UTF8String ?: "-",
                        CNDThumbnailPointer(leadingImage),
                        CNDThumbnailClassName(leadingImage),
                        CNDThumbnailPointer(fallbackImage),
                        CNDThumbnailClassName(fallbackImage));
        if (!target) continue;

        static const char *const rowGetters[] = {
            "applicationBundleIdentifier", "coreSpotlightIdentifier",
            "fileProviderIdentifier", "itemIdentifier", "dragAppBundleID",
            "dragURL", "fileProviderFetchedURL", "identifyingResult",
            "results", "cardSection", "launchActivityAppBundleId"
        };
        for (size_t i = 0; i < sizeof(rowGetters) / sizeof(rowGetters[0]); i++) {
            CNDThumbnailLogGetter(rowModel, "target-row", rowGetters[i]);
        }
        CNDThumbnailDumpRelevantSurface(rowModel, "target-row-model");
        CNDThumbnailDumpRelevantSurface(leadingImage, "target-leading-image");
        CNDThumbnailInspectPersistentSource(leadingImage, fallbackImage);
    }

    for (UIView *view in views) {
        if (![view isKindOfClass:imageViewClass] || !view.window || view.hidden ||
            view.alpha < 0.01) continue;
        visibleImageViews++;
        CGRect frame = [view convertRect:view.bounds toView:nil];
        id current = CNDThumbnailObjectGetter(view, "currentImage") ?:
            CNDThumbnailObjectIvar(view, "_currentImage");
        id fallback = CNDThumbnailObjectGetter(view, "fallbackImage") ?:
            CNDThumbnailObjectIvar(view, "_fallbackImage");
        id searchImage = CNDThumbnailObjectGetter(current, "searchUIImage");
        id candidate = searchImage ?: current;
        BOOL quick = quickLookClass && [candidate isKindOfClass:quickLookClass];
        if (quick) quickLookImages++;
        CNDThumbnailLog("[CND_THUMBNAIL] image-view quick=%d view=%p/%s "
                        "frame=%.1f,%.1f,%.1f,%.1f current=%p/%s "
                        "searchImage=%p/%s fallback=%p/%s\n",
                        quick, CNDThumbnailPointer(view),
                        CNDThumbnailClassName(view), frame.origin.x,
                        frame.origin.y, frame.size.width, frame.size.height,
                        CNDThumbnailPointer(current),
                        CNDThumbnailClassName(current),
                        CNDThumbnailPointer(searchImage),
                        CNDThumbnailClassName(searchImage),
                        CNDThumbnailPointer(fallback),
                        CNDThumbnailClassName(fallback));
        if (!quick) continue;

        id fpItemID = CNDThumbnailObjectGetter(candidate, "fpItemID");
        NSString *providerIdentifier =
            CNDThumbnailObjectGetter(fpItemID, "providerIdentifier") ?:
            CNDThumbnailObjectGetter(fpItemID, "providerID");
        NSString *itemIdentifier =
            CNDThumbnailObjectGetter(fpItemID, "identifier");
        NSString *fallbackBundle =
            CNDThumbnailObjectGetter(fallback, "bundleIdentifier");
        BOOL exactRoot =
            [providerIdentifier isEqualToString:
                @"com.apple.FileProvider.LocalStorage"] &&
            [itemIdentifier isEqualToString:
                @"NSFileProviderRootContainerItemIdentifier"] &&
            [fallbackBundle isEqualToString:@"com.apple.DocumentsApp"];
        if (exactRoot) exactRootImages++;
        CNDThumbnailLog("[CND_THUMBNAIL] root-candidate exact=%d "
                        "provider=%s item=%s fallbackBundle=%s\n",
                        exactRoot,
                        providerIdentifier.UTF8String ?: "-",
                        itemIdentifier.UTF8String ?: "-",
                        fallbackBundle.UTF8String ?: "-");

        NSUInteger variant = 0U;
        bool hasVariant = CNDThumbnailUnsignedGetter(candidate, "variant",
                                                     &variant);
        CNDThumbnailLog("[CND_THUMBNAIL] quicklook object=%p/%s variant=%s%lu "
                        "compact=%d multiple=%d representation=%ld\n",
                        CNDThumbnailPointer(candidate),
                        CNDThumbnailClassName(candidate),
                        hasVariant ? "" : "-", (unsigned long)variant,
                        CNDThumbnailBoolGetter(candidate, "isCompact"),
                        CNDThumbnailBoolGetter(candidate,
                                               "hasMultipleRepresentations"),
                        (long)[CNDThumbnailObjectGetter(candidate,
                            "bestRepresentationTypeLoaded") integerValue]);
        static const char *const thumbnailGetters[] = {
            "url", "fpItemID", "request", "appIconImage", "uiImage",
            "sfImage", "contentType", "typeIdentifier"
        };
        for (size_t i = 0; i < sizeof(thumbnailGetters) /
             sizeof(thumbnailGetters[0]); i++) {
            CNDThumbnailLogGetter(candidate, "quicklook", thumbnailGetters[i]);
        }
        static const char *const itemGetters[] = {
            "identifier", "itemIdentifier", "providerIdentifier",
            "domainIdentifier", "filename", "displayName"
        };
        for (size_t i = 0; i < sizeof(itemGetters) / sizeof(itemGetters[0]); i++) {
            CNDThumbnailLogGetter(fpItemID, "fp-item-id", itemGetters[i]);
        }
        CNDThumbnailDumpRelevantSurface(candidate, "quicklook-image");
        CNDThumbnailDumpRelevantSurface(fpItemID, "fp-item-id");

#if CND_THUMBNAIL_APPLY
        if (exactRoot && fallback) {
            Class converter = NSClassFromString(@"SearchUITLKImageConverter");
            Class cacheClass = NSClassFromString(@"SearchUIImageCache");
            SEL convertSelector = sel_registerName("imageForSFImage:");
            SEL cacheSelector = sel_registerName("cacheTLKImage:forSFImage:");
            id themedTLKImage = [converter respondsToSelector:convertSelector]
                ? ((id (*)(id, SEL, id))objc_msgSend)(
                    converter, convertSelector, fallback)
                : nil;
            if (themedTLKImage && [cacheClass respondsToSelector:cacheSelector]) {
                ((void (*)(id, SEL, id, id))objc_msgSend)(
                    cacheClass, cacheSelector, themedTLKImage, candidate);
            }
            SEL updateSelector = sel_registerName(
                "updateWithImage:fallbackImage:needsOverlayButton:animateTransition:");
            BOOL applied = themedTLKImage &&
                [view respondsToSelector:updateSelector];
            if (applied) {
                ((void (*)(id, SEL, id, id, BOOL, BOOL))objc_msgSend)(
                    view, updateSelector, fallback, fallback, NO, NO);
                applied = CNDThumbnailObjectGetter(view, "currentImage") ==
                    fallback;
            }
            if (applied) appliedRootImages++;
            id cached = [cacheClass respondsToSelector:
                    sel_registerName("cachedTlkImageForSFImage:")]
                ? ((id (*)(id, SEL, id))objc_msgSend)(
                    cacheClass,
                    sel_registerName("cachedTlkImageForSFImage:"),
                    candidate)
                : nil;
            CNDThumbnailLog("[CND_THUMBNAIL] apply-root applied=%d "
                            "fallback=%p/%s tlk=%p/%s cached=%p/%s "
                            "cacheVerified=%d\n", applied,
                            CNDThumbnailPointer(fallback),
                            CNDThumbnailClassName(fallback),
                            CNDThumbnailPointer(themedTLKImage),
                            CNDThumbnailClassName(themedTLKImage),
                            CNDThumbnailPointer(cached),
                            CNDThumbnailClassName(cached),
                            cached == themedTLKImage);
        }
#endif

        NSMutableArray<UIView *> *descendants = [NSMutableArray arrayWithObject:view];
        for (NSUInteger cursor = 0U; cursor < descendants.count && cursor < 128U;
             cursor++) {
            UIView *child = descendants[cursor];
            [descendants addObjectsFromArray:child.subviews];
            if (![child isKindOfClass:UIImageView.class]) continue;
            UIImage *image = ((UIImageView *)child).image;
            CGRect imageFrame = [child convertRect:child.bounds toView:nil];
            CNDThumbnailLog("[CND_THUMBNAIL] rendered-image view=%p/%s "
                            "frame=%.1f,%.1f,%.1f,%.1f image=%p/%s "
                            "pixels=%zux%zu scale=%.2f hash=%s\n",
                            CNDThumbnailPointer(child),
                            CNDThumbnailClassName(child), imageFrame.origin.x,
                            imageFrame.origin.y, imageFrame.size.width,
                            imageFrame.size.height, CNDThumbnailPointer(image),
                            CNDThumbnailClassName(image),
                            image.CGImage ? CGImageGetWidth(image.CGImage) : 0U,
                            image.CGImage ? CGImageGetHeight(image.CGImage) : 0U,
                            image.scale,
                            CNDThumbnailImageHash(image).UTF8String ?: "-");
        }
    }

    CNDThumbnailLog("[CND_THUMBNAIL] summary attempt=%u state=%ld rows=%lu "
                    "targetRows=%lu imageViews=%lu quickLookImages=%lu "
                    "exactRoots=%lu appliedRoots=%lu mode=%s\n",
                    gCNDThumbnailAttempt,
                    (long)UIApplication.sharedApplication.applicationState,
                    (unsigned long)visibleRows, (unsigned long)matchingRows,
                    (unsigned long)visibleImageViews,
                    (unsigned long)quickLookImages,
                    (unsigned long)exactRootImages,
                    (unsigned long)appliedRootImages,
                    CND_THUMBNAIL_APPLY ? "apply" : "inspect");
    if ((exactRootImages == 0U && matchingRows == 0U) ||
        !gCNDThumbnailPersistentSourceLogged ||
#if CND_THUMBNAIL_PERSIST
        !gCNDThumbnailPersistentMutationOK ||
#endif
        (CND_THUMBNAIL_APPLY && appliedRootImages == 0U)) return false;
    CNDThumbnailLog("[CND_THUMBNAIL] COMPLETE pid=%d targetRows=%lu "
                    "quickLookImages=%lu exactRoots=%lu appliedRoots=%lu "
                    "noMutation=%d\n", getpid(),
                    (unsigned long)matchingRows,
                    (unsigned long)quickLookImages,
                    (unsigned long)exactRootImages,
                    (unsigned long)appliedRootImages,
                    CND_THUMBNAIL_APPLY ? 0 : 1);
    return true;
}

static void CNDThumbnailScheduleAttempt(void)
{
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @autoreleasepool {
            gCNDThumbnailAttempt++;
            if (CNDThumbnailRunOnce()) return;
            if (gCNDThumbnailAttempt < 30U) {
                CNDThumbnailScheduleAttempt();
            } else {
                CNDThumbnailLog("[CND_THUMBNAIL] COMPLETE pid=%d "
                                "targetRows=unresolved attempts=%u "
                                "noMutation=1\n", getpid(),
                                gCNDThumbnailAttempt);
            }
        }
    });
}

__attribute__((constructor))
static void CNDThumbnailStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t outputHandle = CND_THUMBNAIL_OUTPUT_TOKEN[0] && consume
            ? consume(CND_THUMBNAIL_OUTPUT_TOKEN) : -1;
        gCNDThumbnailFD = open(CNDThumbnailOutputPath,
                               O_WRONLY | O_CREAT | O_TRUNC, 0644);
        CNDThumbnailLog("[CND_THUMBNAIL] START pid=%d process=%s main=%d "
                        "outputToken=%lld mode=read-only\n", getpid(),
                        getprogname(), NSThread.isMainThread,
                        (long long)outputHandle);
        if (gCNDThumbnailFD >= 0) CNDThumbnailScheduleAttempt();
    }
}
