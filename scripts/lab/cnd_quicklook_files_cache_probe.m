#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef CND_QL_OUTPUT_TOKEN
#define CND_QL_OUTPUT_TOKEN ""
#endif

#ifndef CND_QL_ACTION
#define CND_QL_ACTION 0
#endif

static const char *const CNDQLOutputPath =
    "/var/tmp/cyanide-quicklook-files-cache.log";
static int gCNDQLFD = -1;
static id gCNDQLTransaction;

@interface NSObject (CNDQuickLookProbe)
+ (id)sharedInstance;
+ (id)appIconForBundleIdentifier:(id)identifier
                         variant:(unsigned long long)variant;
+ (unsigned long long)bestVariantForSize:(CGSize)size;
- (id)initWithProviderID:(id)providerID
        domainIdentifier:(id)domainIdentifier
           itemIdentifier:(id)itemIdentifier;
- (id)initWithItemID:(id)itemID;
- (id)initWithFileIdentifier:(id)identifier version:(id)version;
- (id)initWithVersionedFileIdentifier:(id)identifier
                                  size:(CGSize)size
                                 scale:(double)scale
                              iconMode:(BOOL)iconMode
                                flavor:(int)flavor
                         wantsBaseline:(BOOL)wantsBaseline
                      minimumDimension:(double)minimumDimension
                        requestedTypes:(unsigned long long)requestedTypes;
- (id)loadImageWithScale:(double)scale isDarkStyle:(BOOL)isDarkStyle;
- (id)cacheThread;
- (dispatch_queue_t)queue;
- (id)allThumbnailsForFPItemID:(id)itemID;
- (id)diskCache;
- (id)memoryCache;
- (id)indexDatabase;
- (id)enumeratorForAllThumbnailsWithFileIdentifier:(id)identifier;
- (id)nextThumbnailData;
- (BOOL)removeThumbnailForFileIdentifier:(id)identifier;
- (BOOL)addThumbnailIntoCache:(id)request
                  bitmapFormat:(id)bitmapFormat
                    bitmapData:(id)bitmapData
                      metadata:(id)metadata
                        flavor:(int)flavor
                   contentRect:(CGRect)contentRect
                     badgeType:(unsigned long long)badgeType
     externalGeneratorDataHash:(unsigned long long)externalGeneratorDataHash;
- (void)forceCommit;
- (void)reset;
- (id)fileIdentifier;
- (id)version;
- (float)size;
- (BOOL)iconMode;
- (long long)iconVariant;
- (int)interpolationQuality;
- (unsigned long long)badgeType;
- (id)bitmapFormat;
- (id)bitmapData;
- (id)metadata;
- (int)flavor;
- (CGRect)contentRect;
- (unsigned long long)externalGeneratorDataHash;
- (unsigned long long)width;
- (unsigned long long)height;
- (unsigned long long)bitsPerComponent;
- (unsigned long long)bytesPerRow;
- (unsigned int)bitmapInfo;
- (CGColorSpaceRef)colorSpace;
@end

static void CNDQLLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDQLLog(const char *format, ...)
{
    if (gCNDQLFD < 0) return;
    char line[8192] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDQLFD, line, amount);
    (void)fsync(gCNDQLFD);
}

static const char *CNDQLClassName(id object)
{
    return object ? class_getName(object_getClass(object)) : "-";
}

static void *CNDQLPointer(id object)
{
    return object ? (__bridge void *)object : NULL;
}

static NSString *CNDQLSHA256(NSData *data)
{
    if (!data) return @"-";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:64U];
    for (size_t index = 0; index < sizeof(digest); index++) {
        [result appendFormat:@"%02x", digest[index]];
    }
    return result;
}

static NSArray *CNDQLItems(id collection)
{
    if ([collection isKindOfClass:NSArray.class]) return collection;
    if ([collection isKindOfClass:NSSet.class]) return [collection allObjects];
    return @[];
}

static float CNDQLFloatGetter(id object, SEL selector)
{
    return object && [object respondsToSelector:selector]
        ? ((float (*)(id, SEL))objc_msgSend)(object, selector) : 0.0f;
}

static unsigned long long CNDQLUnsignedGetter(id object, SEL selector)
{
    return object && [object respondsToSelector:selector]
        ? ((unsigned long long (*)(id, SEL))objc_msgSend)(object, selector) : 0U;
}

static unsigned int CNDQLUnsignedIntGetter(id object, SEL selector)
{
    return object && [object respondsToSelector:selector]
        ? ((unsigned int (*)(id, SEL))objc_msgSend)(object, selector) : 0U;
}

static CGColorSpaceRef CNDQLColorSpaceGetter(id object, SEL selector)
{
    return object && [object respondsToSelector:selector]
        ? ((CGColorSpaceRef (*)(id, SEL))objc_msgSend)(object, selector) : NULL;
}

static bool CNDQLLoadFramework(const char *path)
{
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    CNDQLLog("[CND_QL] dlopen path=%s handle=%p error=%s\n",
             path, handle, handle ? "-" : (dlerror() ?: "unknown"));
    return handle != NULL;
}

static id CNDQLExactThumbnail(NSArray *thumbnails)
{
    for (id item in thumbnails) {
        id thumbnail = item;
        if ([item isKindOfClass:NSDictionary.class]) {
            NSDictionary *dictionary = item;
            CNDQLLog("[CND_QL] candidate-dictionary object=%p keys=%s "
                     "description=%s\n", CNDQLPointer(dictionary),
                     [[[dictionary allKeys] description] UTF8String] ?: "-",
                     [[dictionary description] UTF8String] ?: "-");
            for (id value in dictionary.allValues) {
                if ([value respondsToSelector:@selector(bitmapData)] &&
                    [value respondsToSelector:@selector(bitmapFormat)]) {
                    thumbnail = value;
                    break;
                }
            }
        }
        float size = CNDQLFloatGetter(thumbnail, @selector(size));
        BOOL iconMode = [thumbnail respondsToSelector:@selector(iconMode)]
            ? [thumbnail iconMode] : NO;
        id data = [thumbnail respondsToSelector:@selector(bitmapData)]
            ? [thumbnail bitmapData] : nil;
        id format = [thumbnail respondsToSelector:@selector(bitmapFormat)]
            ? [thumbnail bitmapFormat] : nil;
        CNDQLLog("[CND_QL] candidate object=%p/%s size=%.1f iconMode=%d "
                 "format=%p/%s bytes=%lu sha256=%s\n",
                 CNDQLPointer(thumbnail), CNDQLClassName(thumbnail), size,
                 iconMode, CNDQLPointer(format), CNDQLClassName(format),
                 (unsigned long)[data length], CNDQLSHA256(data).UTF8String);
        if (fabsf(size - 192.0f) < 0.5f && iconMode && format && data) {
            return thumbnail;
        }
    }
    return nil;
}

static NSData *CNDQLDrawImage(UIImage *image, id format)
    __attribute__((unused));

static NSData *CNDQLDrawImage(UIImage *image, id format)
{
    if (!image.CGImage || !format) return nil;
    size_t width = (size_t)CNDQLUnsignedGetter(format, @selector(width));
    size_t height = (size_t)CNDQLUnsignedGetter(format, @selector(height));
    size_t bitsPerComponent = (size_t)CNDQLUnsignedGetter(
        format, @selector(bitsPerComponent));
    size_t bytesPerRow = (size_t)CNDQLUnsignedGetter(
        format, @selector(bytesPerRow));
    CGBitmapInfo bitmapInfo = (CGBitmapInfo)CNDQLUnsignedIntGetter(
        format, @selector(bitmapInfo));
    CGColorSpaceRef colorSpace = CNDQLColorSpaceGetter(
        format, @selector(colorSpace));
    if (!width || !height || width > 2048U || height > 2048U ||
        !bytesPerRow || bytesPerRow > SIZE_MAX / height || !colorSpace) {
        return nil;
    }
    NSMutableData *pixels =
        [NSMutableData dataWithLength:bytesPerRow * height];
    CGContextRef context = CGBitmapContextCreate(
        pixels.mutableBytes, width, height, bitsPerComponent, bytesPerRow,
        colorSpace, bitmapInfo);
    if (!context) return nil;
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextClearRect(context, CGRectMake(0, 0, width, height));
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), image.CGImage);
    CGContextRelease(context);
    return pixels;
}

static void CNDQLRunOnServer(id server)
{
    @autoreleasepool {
        Class itemIDClass = NSClassFromString(@"FPItemID");
        id cacheThread = [server respondsToSelector:@selector(cacheThread)]
            ? [server cacheThread] : nil;
        id diskCache = [cacheThread respondsToSelector:@selector(diskCache)]
            ? [cacheThread diskCache] : nil;
        id memoryCache = [cacheThread respondsToSelector:@selector(memoryCache)]
            ? [cacheThread memoryCache] : nil;
        id itemID = [[itemIDClass alloc]
            initWithProviderID:@"com.apple.FileProvider.LocalStorage"
            domainIdentifier:@"NSFileProviderDomainDefaultIdentifier"
            itemIdentifier:@"NSFileProviderRootContainerItemIdentifier"];
        NSArray *thumbnails = CNDQLItems(
            [cacheThread respondsToSelector:@selector(allThumbnailsForFPItemID:)]
                ? [cacheThread allThumbnailsForFPItemID:itemID] : nil);
        Class fileIdentifierClass =
            NSClassFromString(@"QLCacheFileProviderFileIdentifier");
        id providerFileIdentifier = [[fileIdentifierClass alloc]
            initWithItemID:itemID];
        id enumerator =
            [diskCache respondsToSelector:
                @selector(enumeratorForAllThumbnailsWithFileIdentifier:)]
                ? [diskCache
                    enumeratorForAllThumbnailsWithFileIdentifier:
                        providerFileIdentifier] : nil;
        NSMutableArray *thumbnailData = [NSMutableArray array];
        for (NSUInteger index = 0U; index < 16U; index++) {
            id value = [enumerator respondsToSelector:@selector(nextThumbnailData)]
                ? [enumerator nextThumbnailData] : nil;
            if (!value) break;
            [thumbnailData addObject:value];
        }
        CNDQLLog("[CND_QL] roots server=%p/%s cacheThread=%p/%s "
                 "disk=%p/%s memory=%p/%s itemID=%p/%s text=%s "
                 "diagnosticCount=%lu dataCount=%lu fileIdentifier=%p/%s "
                 "enumerator=%p/%s action=%d\n",
                 CNDQLPointer(server), CNDQLClassName(server),
                 CNDQLPointer(cacheThread), CNDQLClassName(cacheThread),
                 CNDQLPointer(diskCache), CNDQLClassName(diskCache),
                 CNDQLPointer(memoryCache), CNDQLClassName(memoryCache),
                 CNDQLPointer(itemID), CNDQLClassName(itemID),
                 [[itemID description] UTF8String] ?: "-",
                 (unsigned long)thumbnails.count,
                 (unsigned long)thumbnailData.count,
                 CNDQLPointer(providerFileIdentifier),
                 CNDQLClassName(providerFileIdentifier),
                 CNDQLPointer(enumerator), CNDQLClassName(enumerator),
                 CND_QL_ACTION);

        (void)CNDQLExactThumbnail(thumbnails);
        id original = CNDQLExactThumbnail(thumbnailData);
        BOOL success = original != nil;

#if CND_QL_ACTION == 1
        Class appImageClass = NSClassFromString(@"SearchUIAppIconImage");
        unsigned long long variant =
            [appImageClass respondsToSelector:@selector(bestVariantForSize:)]
                ? [appImageClass bestVariantForSize:CGSizeMake(64.0, 64.0)] : 0;
        id imageSource =
            [appImageClass respondsToSelector:
                @selector(appIconForBundleIdentifier:variant:)]
                ? [appImageClass
                    appIconForBundleIdentifier:@"com.apple.DocumentsApp"
                    variant:variant] : nil;
        UIImage *image =
            [imageSource respondsToSelector:
                @selector(loadImageWithScale:isDarkStyle:)]
                ? [imageSource loadImageWithScale:3.0 isDarkStyle:NO] : nil;
        id format = [original bitmapFormat];
        NSData *pixels = CNDQLDrawImage(image, format);
        id fileIdentifier = [original fileIdentifier];
        id version = [original version];
        Class versionedClass =
            NSClassFromString(@"QLCacheFileProviderVersionedFileIdentifier");
        id versioned = [[versionedClass alloc]
            initWithFileIdentifier:fileIdentifier version:version];
        Class requestClass = NSClassFromString(@"QLTThumbnailRequest");
        id request = [[requestClass alloc]
            initWithVersionedFileIdentifier:versioned
            size:CGSizeMake(64.0, 64.0)
            scale:3.0
            iconMode:YES
            flavor:[original flavor]
            wantsBaseline:NO
            minimumDimension:0.0
            requestedTypes:1U];
        BOOL added = request && pixels &&
            [cacheThread respondsToSelector:
                @selector(addThumbnailIntoCache:bitmapFormat:bitmapData:
                          metadata:flavor:contentRect:badgeType:
                          externalGeneratorDataHash:)] &&
            [cacheThread addThumbnailIntoCache:request
                                  bitmapFormat:format
                                    bitmapData:pixels
                                      metadata:[original metadata]
                                        flavor:[original flavor]
                                   contentRect:[original contentRect]
                                     badgeType:[original badgeType]
                     externalGeneratorDataHash:
                         [original externalGeneratorDataHash]];
        if (added && [cacheThread respondsToSelector:@selector(forceCommit)]) {
            [cacheThread forceCommit];
        }
        success = success && image && pixels && request && added;
        CNDQLLog("[CND_QL] apply variant=%llu source=%p/%s image=%p/%s "
                 "imagePixels=%zux%zu format=%p/%s replacementBytes=%lu "
                 "replacementSHA256=%s versioned=%p/%s request=%p/%s "
                 "added=%d\n",
                 variant, CNDQLPointer(imageSource), CNDQLClassName(imageSource),
                 CNDQLPointer(image), CNDQLClassName(image),
                 image.CGImage ? CGImageGetWidth(image.CGImage) : 0U,
                 image.CGImage ? CGImageGetHeight(image.CGImage) : 0U,
                 CNDQLPointer(format), CNDQLClassName(format),
                 (unsigned long)pixels.length,
                 CNDQLSHA256(pixels).UTF8String,
                 CNDQLPointer(versioned), CNDQLClassName(versioned),
                 CNDQLPointer(request), CNDQLClassName(request), added);
#elif CND_QL_ACTION == 2
        id fileIdentifier = [original fileIdentifier];
        id index = [diskCache respondsToSelector:@selector(indexDatabase)]
            ? [diskCache indexDatabase] : nil;
        BOOL removed = fileIdentifier &&
            [index respondsToSelector:
                @selector(removeThumbnailForFileIdentifier:)] &&
            [index removeThumbnailForFileIdentifier:fileIdentifier];
        if ([memoryCache respondsToSelector:@selector(reset)]) {
            [memoryCache reset];
        }
        if ([cacheThread respondsToSelector:@selector(forceCommit)]) {
            [cacheThread forceCommit];
        }
        success = success && removed;
        CNDQLLog("[CND_QL] restore index=%p/%s fileIdentifier=%p/%s "
                 "removed=%d memoryReset=%d\n",
                 CNDQLPointer(index), CNDQLClassName(index),
                 CNDQLPointer(fileIdentifier), CNDQLClassName(fileIdentifier),
                 removed, [memoryCache respondsToSelector:@selector(reset)]);
#endif

        CNDQLLog("[CND_QL] COMPLETE pid=%d action=%d ok=%d\n",
                 getpid(), CND_QL_ACTION, success);
        if (gCNDQLFD >= 0) {
            close(gCNDQLFD);
            gCNDQLFD = -1;
        }
        gCNDQLTransaction = nil;
    }
}

static void CNDQLRun(void)
{
    @autoreleasepool {
        CNDQLLoadFramework(
            "/System/Library/Frameworks/QuickLookThumbnailing.framework/"
            "QuickLookThumbnailing");
        CNDQLLoadFramework(
            "/System/Library/PrivateFrameworks/FileProvider.framework/"
            "FileProvider");
        CNDQLLoadFramework(
            "/System/Library/PrivateFrameworks/SearchUI.framework/SearchUI");
        Class serverClass = NSClassFromString(@"QLServerThread");
        id server = [serverClass respondsToSelector:@selector(sharedInstance)]
            ? [serverClass sharedInstance] : nil;
        dispatch_queue_t queue =
            [server respondsToSelector:@selector(queue)] ? [server queue] : nil;
        CNDQLLog("[CND_QL] schedule server=%p/%s queue=%p\n",
                 CNDQLPointer(server), CNDQLClassName(server),
                 queue);
        if (queue) {
            dispatch_sync(queue, ^{
                CNDQLRunOnServer(server);
            });
            return;
        }
        CNDQLLog("[CND_QL] COMPLETE pid=%d action=%d ok=0 reason=no-server\n",
                 getpid(), CND_QL_ACTION);
        if (gCNDQLFD >= 0) {
            close(gCNDQLFD);
            gCNDQLFD = -1;
        }
        gCNDQLTransaction = nil;
    }
}

__attribute__((constructor)) static void CNDQLStart(void)
{
    if (CND_QL_OUTPUT_TOKEN[0]) {
        typedef int (*ConsumeExtensionFn)(const char *);
        ConsumeExtensionFn consume =
            (ConsumeExtensionFn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
        if (consume) (void)consume(CND_QL_OUTPUT_TOKEN);
    }
    gCNDQLFD = open(CNDQLOutputPath,
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (gCNDQLFD < 0) return;
    typedef void *(*CreateTransactionFn)(const char *);
    CreateTransactionFn createTransaction = (CreateTransactionFn)dlsym(
        RTLD_DEFAULT, "os_transaction_create");
    if (createTransaction) {
        gCNDQLTransaction = (__bridge_transfer id)createTransaction(
            "com.cyanide.quicklook-files-cache-probe");
    }
    CNDQLLog("[CND_QL] transaction=%p/%s\n",
             CNDQLPointer(gCNDQLTransaction),
             CNDQLClassName(gCNDQLTransaction));
    dispatch_async(dispatch_get_main_queue(), ^{
        CNDQLRun();
    });
}
