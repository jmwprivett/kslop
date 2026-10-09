#import "CNDIconDeclarationRedirect.h"
#import "CNDLaunchServicesRegistration.h"
#import "CNDLaunchServicesRegistrationDictionary.h"
#import "CNDIconThemeImageProcessor.h"
#import "../TaskRop/RemoteCall.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/persistence.h"
#import "../utils/file.h"
#import "../utils/sandbox.h"

#import <CommonCrypto/CommonDigest.h>
#import <ImageIO/ImageIO.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <objc/runtime.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

static NSString * const CNDIconRedirectDeviceBundleIdentifier = @"com.ebay.iphone";
static NSString * const CNDIconRedirectPayloadName = @"CNDIconRedirectTheme";
static NSString * const CNDIconRedirectPayloadSHA256 =
    @"74122c8aa948fc4e2d9d02148f62b88b8e4c77b1727cd34cf5632f9c6bbdca8b";
static NSString * const CNDIconRedirectCompactPayloadName =
    @"CNDIconRedirectTheme120";
static NSString * const CNDIconRedirectCompactPayloadSHA256 =
    @"717a887c38e13e6ba3a3813f82e6c01cb710348cb660587c6f5c34d9e07221fb";
static NSString * const CNDIconRedirectBackupName =
    @"CyanideEbayLaunchServicesRegistration.plist";
static NSString * const CNDIconRedirectStageName = @"CyanideEbayIconStage.bin";
static NSString * const CNDIconRedirectCreatedBase = @"CNDIconRedirectLegacy60x60";
static const NSUInteger CNDIconRedirectBackupVersion = 2;
static const NSUInteger CNDIconRedirectTargetSelectionRecipeVersion = 1;
static NSString * const CNDIconRedirectTargetSelectionRecipeName =
    @"legacy-phone-fallback";
static volatile int32_t gOperationRunning;
static NSString *gCNDIconRedirectOverrideBundleIdentifier;
static NSData *gCNDIconRedirectOverrideSourcePNGData;
static NSURL *gCNDIconRedirectOverrideJournalURL;
static NSURL *cnd_icon_backup_url(void);

NSString *CNDIconDeclarationRedirectTargetBundleIdentifier(void)
{
    if (gCNDIconRedirectOverrideBundleIdentifier.length > 0) {
        return gCNDIconRedirectOverrideBundleIdentifier;
    }
    if (remote_call_lab_backend_opted_in()) {
        NSDictionary *pending = [NSDictionary
            dictionaryWithContentsOfURL:cnd_icon_backup_url()];
        NSString *pendingIdentifier = [pending[@"bundleIdentifier"]
            isKindOfClass:NSString.class] ? pending[@"bundleIdentifier"] : nil;
        if (pendingIdentifier.length > 0) return pendingIdentifier;
        NSString *identifier = NSBundle.mainBundle.bundleIdentifier;
        if (identifier.length > 0) return identifier;
    }
    return CNDIconRedirectDeviceBundleIdentifier;
}

static NSString *cnd_icon_target_bundle_identifier(void)
{
    if (gCNDIconRedirectOverrideBundleIdentifier.length > 0) {
        return gCNDIconRedirectOverrideBundleIdentifier;
    }
    return CNDIconDeclarationRedirectTargetBundleIdentifier();
}

typedef void (*CNDISInvalidateCacheEntriesForBundleIdentifier)(NSString *);
static NSString *cnd_icon_sha256(NSData *data);
static NSDictionary<NSString *, id> *cnd_icon_result(
    BOOL ok, NSString *stage, NSString *message, NSDictionary *details);

@protocol CNDISBundleIdentifierIconRuntime <NSObject>
- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier;
- (id)_makeResourceProviderAllowIconResourceFallback:(BOOL)allowFallback;
- (id)prepareImageForDescriptor:(id)descriptor;
- (id)imageForDescriptor:(id)descriptor;
@end

@protocol CNDISImageDescriptorRuntime <NSObject>
+ (id)imageDescriptorNamed:(NSString *)name;
@end

@protocol CNDISRecordResourceProviderRuntime <NSObject>
- (void)resolveResources;
@end

@protocol CNDIFImageRuntime <NSObject>
- (CGImageRef)CGImage;
@end

static NSError *cnd_icon_error(NSInteger code, NSString *message)
{
    return [NSError errorWithDomain:@"CNDIconRedirect" code:code
        userInfo:@{NSLocalizedDescriptionKey: message ?: @"icon redirect failed"}];
}

static BOOL cnd_icon_invalidate_iconservices_cache(NSString **failureOut)
{
    void *handle = dlopen(
        "/System/Library/PrivateFrameworks/IconServices.framework/IconServices",
        RTLD_NOW | RTLD_LOCAL);
    CNDISInvalidateCacheEntriesForBundleIdentifier invalidate = handle
        ? (CNDISInvalidateCacheEntriesForBundleIdentifier)dlsym(
            handle, "_ISInvalidateCacheEntriesForBundleIdentifier") : NULL;
    if (!invalidate) {
        if (failureOut) {
            *failureOut = @"iOS did not expose IconServices' per-bundle cache invalidator";
        }
        return NO;
    }
    invalidate(cnd_icon_target_bundle_identifier());
    return YES;
}

static BOOL cnd_icon_method_has_object_return_and_arguments(
    Class cls, SEL selector, BOOL classMethod, const char *argumentType)
{
    Method method = classMethod
        ? class_getClassMethod(cls, selector)
        : class_getInstanceMethod(cls, selector);
    if (!method || method_getNumberOfArguments(method) !=
            (argumentType ? 3u : 2u)) return NO;
    char returnType[16] = {0};
    method_getReturnType(method, returnType, sizeof(returnType));
    if (returnType[0] != '@') return NO;
    if (argumentType) {
        char observed[16] = {0};
        method_getArgumentType(method, 2, observed, sizeof(observed));
        if (observed[0] != argumentType[0]) return NO;
    }
    return YES;
}

static BOOL cnd_icon_method_has_argument(Class cls, SEL selector,
                                         const char *argumentType)
{
    Method method = class_getInstanceMethod(cls, selector);
    if (!method || method_getNumberOfArguments(method) != 3u) return NO;
    char observed[16] = {0};
    method_getArgumentType(method, 2, observed, sizeof(observed));
    return observed[0] == argumentType[0];
}

static BOOL cnd_icon_method_is_no_argument(Class cls, SEL selector)
{
    Method method = class_getInstanceMethod(cls, selector);
    return method && method_getNumberOfArguments(method) == 2u;
}

static BOOL cnd_icon_method_returns_pointer_without_arguments(
    Class cls, SEL selector)
{
    Method method = class_getInstanceMethod(cls, selector);
    if (!method || method_getNumberOfArguments(method) != 2u) return NO;
    char returnType[32] = {0};
    method_getReturnType(method, returnType, sizeof(returnType));
    return returnType[0] == '^';
}

static BOOL cnd_icon_object_is_expected_legacy_resource(id object,
                                                         NSString **classOut)
{
    if (!object) return NO;
    NSString *name = NSStringFromClass(object_getClass(object));
    if ([name isEqual:@"ISIconStackCompositeResource"]) {
        if (classOut) *classOut = name;
        return YES;
    }
    return NO;
}

static BOOL cnd_icon_container_has_expected_legacy_resource(
    id value, NSString **classOut)
{
    if (cnd_icon_object_is_expected_legacy_resource(value, classOut)) {
        return YES;
    }
    NSArray *objects = nil;
    if ([value isKindOfClass:NSDictionary.class]) {
        NSDictionary *dictionary = value;
        if (dictionary.count > 64) return NO;
        objects = dictionary.allValues;
    } else if ([value isKindOfClass:NSArray.class]) {
        NSArray *array = value;
        if (array.count > 64) return NO;
        objects = array;
    } else if ([value isKindOfClass:NSSet.class]) {
        NSSet *set = value;
        if (set.count > 64) return NO;
        objects = set.allObjects;
    }
    for (id object in objects) {
        if (cnd_icon_object_is_expected_legacy_resource(object, classOut)) {
            return YES;
        }
    }
    return NO;
}

static BOOL cnd_icon_provider_has_expected_legacy_resource(
    id provider, NSString **classOut)
{
    NSUInteger inspected = 0;
    for (Class cls = object_getClass(provider); cls && inspected < 64;
         cls = class_getSuperclass(cls)) {
        unsigned int count = 0;
        Ivar *ivars = class_copyIvarList(cls, &count);
        for (unsigned int index = 0; index < count && inspected < 64; index++) {
            const char *type = ivar_getTypeEncoding(ivars[index]);
            if (!type || type[0] != '@') continue;
            inspected++;
            id value = object_getIvar(provider, ivars[index]);
            if (cnd_icon_container_has_expected_legacy_resource(
                    value, classOut)) {
                free(ivars);
                return YES;
            }
        }
        free(ivars);
    }
    return NO;
}

static NSString *cnd_icon_copy_rendered_pixel_hash(CGImageRef image,
                                                    size_t *widthOut,
                                                    size_t *heightOut,
                                                    size_t *lengthOut,
                                                    size_t *transparentPixelsOut,
                                                    size_t *partialAlphaPixelsOut,
                                                    size_t *opaquePixelsOut)
{
    if (!image) return nil;
    size_t width = CGImageGetWidth(image);
    size_t height = CGImageGetHeight(image);
    if (width == 0 || height == 0 || width > 4096 || height > 4096 ||
        width > SIZE_MAX / height || width * height > 16777216 ||
        width * height > SIZE_MAX / 4) return nil;
    size_t length = width * height * 4;
    NSMutableData *pixels = [NSMutableData dataWithLength:length];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = colorSpace ? CGBitmapContextCreate(
        pixels.mutableBytes, width, height, 8, width * 4, colorSpace,
        (CGBitmapInfo)(kCGImageAlphaPremultipliedLast |
                       kCGBitmapByteOrder32Big)) : NULL;
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    if (!context) return nil;
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), image);
    CGContextRelease(context);
    const uint8_t *raw = pixels.bytes;
    size_t transparentPixels = 0;
    size_t partialAlphaPixels = 0;
    size_t opaquePixels = 0;
    for (size_t index = 0; index < width * height; index++) {
        uint8_t alpha = raw[index * 4u + 3u];
        if (alpha == 0u) transparentPixels++;
        else if (alpha == 255u) opaquePixels++;
        else partialAlphaPixels++;
    }
    if (widthOut) *widthOut = width;
    if (heightOut) *heightOut = height;
    if (lengthOut) *lengthOut = length;
    if (transparentPixelsOut) *transparentPixelsOut = transparentPixels;
    if (partialAlphaPixelsOut) *partialAlphaPixelsOut = partialAlphaPixels;
    if (opaquePixelsOut) *opaquePixelsOut = opaquePixels;
    return cnd_icon_sha256(pixels);
}

// This verifier runs only after exact filesystem and LaunchServices readback
// plus per-bundle cache invalidation. A new ISBundleIdentifierIcon forces a
// new record-provider construction in this process. Provider inspection proves
// that the redirected declaration selected the legacy icon-stack resource;
// the returned CGImage hash and alpha counts prove that the same canonical
// client path also produced bounded, non-placeholder pixels and show whether
// IconServices composited away the staged transparency. No cache object or UI
// process is mutated by this readback.
static NSDictionary *cnd_icon_verify_canonical_resolution(NSString *bundleID)
{
    void *handle = dlopen(
        "/System/Library/PrivateFrameworks/IconServices.framework/IconServices",
        RTLD_NOW | RTLD_LOCAL);
    Class iconClass = handle ? NSClassFromString(@"ISBundleIdentifierIcon") : Nil;
    Class descriptorClass = handle ? NSClassFromString(@"ISImageDescriptor") : Nil;
    SEL initSelector = @selector(initWithBundleIdentifier:);
    SEL providerSelector = NSSelectorFromString(
        @"_makeResourceProviderAllowIconResourceFallback:");
    SEL descriptorSelector = NSSelectorFromString(@"imageDescriptorNamed:");
    SEL imageSelector = NSSelectorFromString(@"imageForDescriptor:");
    if (!iconClass || !descriptorClass ||
        !cnd_icon_method_has_object_return_and_arguments(
            iconClass, initSelector, NO, "@") ||
        !cnd_icon_method_has_object_return_and_arguments(
            iconClass, providerSelector, NO, "B") ||
        !cnd_icon_method_has_object_return_and_arguments(
            descriptorClass, descriptorSelector, YES, "@") ||
        !cnd_icon_method_has_object_return_and_arguments(
            iconClass, imageSelector, NO, "@")) {
        return cnd_icon_result(NO, @"iconservices-abi",
            @"IconServices does not expose the verified iOS 26 canonical resolver ABI",
            nil);
    }

    @try {
        id<CNDISBundleIdentifierIconRuntime> icon =
            [(id<CNDISBundleIdentifierIconRuntime>)[iconClass alloc]
                initWithBundleIdentifier:bundleID];
        id provider = [icon _makeResourceProviderAllowIconResourceFallback:YES];
        NSString *providerClass = provider
            ? NSStringFromClass(object_getClass(provider)) : @"";
        /* iOS 26 returns the concrete ISResourceProvider facade here. Some
         * builds expose the record-backed subclass name instead, so validate
         * the known ABI and resolved resource instead of one class spelling. */
        BOOL knownProviderClass =
            [providerClass isEqual:@"ISResourceProvider"] ||
            [providerClass isEqual:@"ISRecordResourceProvider"];
        if (!icon || !knownProviderClass) {
            return cnd_icon_result(NO, @"iconservices-provider",
                @"a fresh canonical icon did not produce the expected record provider",
                @{ @"providerClass": providerClass });
        }
        NSString *resourceClass = nil;
        BOOL providerCanResolve = [provider respondsToSelector:
            @selector(resolveResources)];
        if (providerCanResolve && cnd_icon_method_is_no_argument(
                object_getClass(provider), @selector(resolveResources))) {
            [(id<CNDISRecordResourceProviderRuntime>)provider resolveResources];
            (void)cnd_icon_provider_has_expected_legacy_resource(
                provider, &resourceClass);
        }

        NSString *descriptorName =
            @"com.apple.IconServices.ImageDescriptor.Spotlight";
        id descriptor = [(id<CNDISImageDescriptorRuntime>)descriptorClass
            imageDescriptorNamed:descriptorName];
        if (!descriptor) {
            return cnd_icon_result(NO, @"iconservices-descriptor",
                @"IconServices did not create its canonical Spotlight descriptor", nil);
        }
        if ([icon respondsToSelector:@selector(prepareImageForDescriptor:)]) {
            if (!cnd_icon_method_has_argument(iconClass,
                    @selector(prepareImageForDescriptor:), "@")) {
                return cnd_icon_result(NO, @"iconservices-abi",
                    @"IconServices exposes an unexpected prepare-image ABI", nil);
            }
            [icon prepareImageForDescriptor:descriptor];
        }
        id image = [icon imageForDescriptor:descriptor];
        NSString *imageClass = image
            ? NSStringFromClass(object_getClass(image)) : @"";
        if (!image || [imageClass containsString:@"Placeholder"] ||
            !cnd_icon_method_returns_pointer_without_arguments(
                object_getClass(image), @selector(CGImage))) {
            return cnd_icon_result(NO, @"iconservices-image",
                @"canonical IconServices rendering returned no concrete image",
                @{ @"imageClass": imageClass });
        }
        CGImageRef cgImage = [(id<CNDIFImageRuntime>)image CGImage];
        size_t width = 0, height = 0, length = 0;
        size_t transparentPixels = 0;
        size_t partialAlphaPixels = 0;
        size_t opaquePixels = 0;
        NSString *pixelHash = cnd_icon_copy_rendered_pixel_hash(
            cgImage, &width, &height, &length,
            &transparentPixels, &partialAlphaPixels, &opaquePixels);
        if (pixelHash.length != 64) {
            return cnd_icon_result(NO, @"iconservices-pixels",
                @"canonical IconServices output could not be read back as bounded pixels",
                @{ @"imageClass": imageClass });
        }
        return cnd_icon_result(YES, @"iconservices-verified",
            @"fresh canonical IconServices resolution selected the redirected legacy resource and rendered concrete pixels",
            @{
                @"bundleIdentifier": bundleID,
                @"providerClass": providerClass,
                @"resourceClass": resourceClass ?: @"not-exposed-by-provider",
                @"providerResolveAvailable": @(providerCanResolve),
                @"imageClass": imageClass,
                @"descriptorName": descriptorName,
                @"pixelWidth": @(width),
                @"pixelHeight": @(height),
                @"pixelByteLength": @(length),
                @"transparentPixelCount": @(transparentPixels),
                @"partialAlphaPixelCount": @(partialAlphaPixels),
                @"opaquePixelCount": @(opaquePixels),
                @"hasTransparentPixels": @(transparentPixels > 0),
                @"hasPartialAlpha": @(partialAlphaPixels > 0),
                @"renderedPixelSHA256": pixelHash,
            });
    } @catch (NSException *exception) {
        return cnd_icon_result(NO, @"iconservices-exception",
            @"canonical IconServices verification raised an exception",
            @{ @"exception": exception.description ?: @"unknown" });
    }
}

static NSURL *cnd_icon_support_url(NSString *name)
{
    NSURL *support = [[NSFileManager defaultManager]
        URLsForDirectory:NSApplicationSupportDirectory
               inDomains:NSUserDomainMask].firstObject;
    return [support URLByAppendingPathComponent:name isDirectory:NO];
}

static NSURL *cnd_icon_backup_url(void)
{
    if (gCNDIconRedirectOverrideJournalURL) {
        return gCNDIconRedirectOverrideJournalURL;
    }
    return cnd_icon_support_url(CNDIconRedirectBackupName);
}

static NSURL *cnd_icon_stage_url(void)
{
    return cnd_icon_support_url(CNDIconRedirectStageName);
}

BOOL CNDIconDeclarationRedirectIsActive(void)
{
    return [[NSFileManager defaultManager]
        fileExistsAtPath:cnd_icon_backup_url().path];
}

static NSDictionary<NSString *, id> *cnd_icon_result(
    BOOL ok, NSString *stage, NSString *message, NSDictionary *details)
{
    NSMutableDictionary *result = details
        ? [details mutableCopy] : [NSMutableDictionary dictionary];
    result[@"ok"] = @(ok);
    result[@"stage"] = stage ?: @"unknown";
    result[@"message"] = message ?: @"";
    BOOL journalPresent = CNDIconDeclarationRedirectIsActive();
    NSDictionary *journal = journalPresent
        ? [NSDictionary dictionaryWithContentsOfURL:cnd_icon_backup_url()] : nil;
    NSString *transactionState = journal[@"transactionState"];
    BOOL batchPending = [transactionState isEqual:@"pending"] ||
        [transactionState isEqual:@"restore-pending"] ||
        [journal[@"batchCommitState"] isEqual:@"pending"];
    result[@"active"] = @(journalPresent && !batchPending);
    result[@"recoveryRequired"] = @(journalPresent);
    if (transactionState.length > 0) result[@"transactionState"] = transactionState;
    return result;
}

static BOOL cnd_icon_registration_succeeded(NSDictionary *result)
{
    BOOL retained = [result[@"teardownMode"] isEqual:@"retained"] &&
        [result[@"teardown"] intValue] == 0 &&
        [result[@"localStateRemaining"] boolValue];
    BOOL finalized = [result[@"teardown"] intValue] == 0 &&
        ![result[@"localStateRemaining"] boolValue];
    return [result[@"ok"] boolValue] &&
        [result[@"registrationAccepted"] boolValue] &&
        [result[@"transport"] isEqual:@"healthy"] &&
        (retained || finalized);
}

static BOOL cnd_icon_is_plist(id value)
{
    NSError *error = nil;
    NSData *serialized = value ? [NSPropertyListSerialization
        dataWithPropertyList:value format:NSPropertyListBinaryFormat_v1_0
        options:0 error:&error] : nil;
    return serialized.length > 0 && error == nil;
}

static NSString *cnd_icon_sha256(NSData *data)
{
    if (![data isKindOfClass:NSData.class]) return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString
        stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    return hex;
}

static NSString *cnd_icon_canonical_path(NSString *path)
{
    if (![path isKindOfClass:NSString.class] || path.length == 0) return nil;
    return path.stringByStandardizingPath.stringByResolvingSymlinksInPath;
}

static BOOL cnd_icon_is_safe_leaf(NSString *name)
{
    if (![name isKindOfClass:NSString.class] || name.length == 0 ||
        [name isEqual:@"."] || [name isEqual:@".."] || name.isAbsolutePath) {
        return NO;
    }
    return [name rangeOfString:@"/"].location == NSNotFound &&
        [name rangeOfString:@"\\"].location == NSNotFound;
}

static BOOL cnd_icon_path_is_strictly_beneath(NSString *path,
                                               NSString *bundlePath)
{
    NSString *canonicalPath = cnd_icon_canonical_path(path);
    NSString *canonicalBundle = cnd_icon_canonical_path(bundlePath);
    return canonicalPath.length > canonicalBundle.length &&
        [canonicalPath hasPrefix:[canonicalBundle stringByAppendingString:@"/"]];
}

static BOOL cnd_icon_read_regular_file(NSString *path, NSData **dataOut,
                                       struct stat *statOut, NSError **errorOut)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errorOut) *errorOut = cnd_icon_error(10,
            [NSString stringWithFormat:@"open(%@) failed: %s", path,
                                       strerror(errno)]);
        return NO;
    }
    struct stat st = {0};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        if (errorOut) *errorOut = cnd_icon_error(11,
            [NSString stringWithFormat:@"%@ is not a readable regular file", path]);
        close(fd);
        return NO;
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)st.st_size];
    uint8_t *cursor = data.mutableBytes;
    NSUInteger remaining = data.length;
    while (remaining > 0) {
        ssize_t amount = read(fd, cursor, remaining);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) {
            if (errorOut) *errorOut = cnd_icon_error(12,
                [NSString stringWithFormat:@"reading %@ failed: %s", path,
                                           amount < 0 ? strerror(errno) : "short read"]);
            close(fd);
            return NO;
        }
        cursor += amount;
        remaining -= (NSUInteger)amount;
    }
    close(fd);
    if (dataOut) *dataOut = data;
    if (statOut) *statOut = st;
    return YES;
}

static NSDictionary *cnd_icon_stat_dictionary(const struct stat *st)
{
    return @{
        @"device": @((uint64_t)st->st_dev),
        @"inode": @((uint64_t)st->st_ino),
        @"uid": @(st->st_uid),
        @"gid": @(st->st_gid),
        @"permissions": @(st->st_mode & 07777),
        @"length": @((uint64_t)st->st_size),
    };
}

static BOOL cnd_icon_stat_matches(NSDictionary *saved, const struct stat *st,
                                  BOOL requireVnode)
{
    if (![saved isKindOfClass:NSDictionary.class]) return NO;
    BOOL metadataMatches = [saved[@"uid"] unsignedIntValue] == st->st_uid &&
        [saved[@"gid"] unsignedIntValue] == st->st_gid &&
        [saved[@"permissions"] unsignedIntValue] == (st->st_mode & 07777) &&
        [saved[@"length"] unsignedLongLongValue] == (uint64_t)st->st_size;
    if (!metadataMatches || !requireVnode) return metadataMatches;
    return [saved[@"device"] unsignedLongLongValue] == (uint64_t)st->st_dev &&
        [saved[@"inode"] unsignedLongLongValue] == (uint64_t)st->st_ino;
}

// APFS assigns a fresh st_dev value when the vPhone guest volumes are mounted
// again after a reboot. The file's inode and all ordinary metadata remain
// stable, so treating st_dev as durable in the VM makes a known journaled
// replacement impossible to restore after reboot. Keep device restores
// strict; only the explicitly opted-in root-harness backend may accept that
// one remount artifact, and it must still match inode, metadata, exact bytes,
// and (for Info.plist) the decoded dictionary at each caller.
static BOOL cnd_icon_recovery_stat_matches(NSDictionary *saved,
                                           const struct stat *st,
                                           BOOL requireVnode)
{
    if (cnd_icon_stat_matches(saved, st, requireVnode)) return YES;
    if (!requireVnode || !remote_call_lab_backend_opted_in()) return NO;
    return cnd_icon_stat_matches(saved, st, NO) &&
        [saved[@"inode"] unsignedLongLongValue] != 0 &&
        [saved[@"inode"] unsignedLongLongValue] == (uint64_t)st->st_ino;
}

// A create-mode transaction starts from proven absence and records the exact
// device/inode plus ordinary metadata immediately after O_EXCL creation. Some
// installed-app bundle leaves remain non-reopenable even after both Cyanide
// and installd consume fresh file extensions. For recovery only, that durable
// creation identity is sufficient to remove the leaf we created, provided no
// field has changed and the journal still proves the original was empty.
static BOOL cnd_icon_created_leaf_matches_journal_identity(
    NSDictionary *file, const struct stat *st)
{
    if (![file[@"mode"] isEqual:@"create"] || !st ||
        S_ISLNK(st->st_mode) || !S_ISREG(st->st_mode)) return NO;
    NSData *original = file[@"originalData"];
    NSDictionary *created = file[@"createdMetadata"];
    uint64_t replacementLength =
        [file[@"replacementLength"] unsignedLongLongValue];
    return [original isKindOfClass:NSData.class] && original.length == 0 &&
        [file[@"originalHash"] isEqual:cnd_icon_sha256([NSData data])] &&
        [created isKindOfClass:NSDictionary.class] &&
        [created[@"device"] unsignedLongLongValue] != 0 &&
        [created[@"inode"] unsignedLongLongValue] != 0 &&
        replacementLength > 0 && replacementLength == (uint64_t)st->st_size &&
        [created[@"length"] unsignedLongLongValue] == replacementLength &&
        cnd_icon_recovery_stat_matches(created, st, YES);
}

static BOOL cnd_icon_regular_leaf(NSString *path, struct stat *statOut,
                                  NSString **failureOut)
{
    if (![path isKindOfClass:NSString.class] || path.length == 0) {
        if (failureOut) *failureOut = @"the bundle file path is empty";
        return NO;
    }
    struct stat st = {0};
    if (lstat(path.fileSystemRepresentation, &st) != 0) {
        if (failureOut) *failureOut = [NSString stringWithFormat:
            @"%@ is unavailable: %s", path, strerror(errno)];
        return NO;
    }
    if (S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode)) {
        if (failureOut) *failureOut = [NSString stringWithFormat:
            @"%@ is not a regular non-symlink file", path];
        return NO;
    }
    if (statOut) *statOut = st;
    return YES;
}

typedef struct {
    const uint8_t *bytes;
    NSUInteger length;
    NSUInteger trailerOffset;
    NSUInteger offsetTableOffset;
    uint8_t offsetIntSize;
    uint8_t objectRefSize;
    uint64_t objectCount;
    uint64_t rootObject;
} CNDBinaryPlistView;

static BOOL cnd_bplist_read_uint(const uint8_t *bytes, NSUInteger length,
                                 NSUInteger offset, uint8_t width,
                                 uint64_t *valueOut)
{
    if (!bytes || width == 0 || width > 8 || offset > length ||
        width > length - offset) return NO;
    uint64_t value = 0;
    for (uint8_t i = 0; i < width; i++) {
        value = (value << 8) | bytes[offset + i];
    }
    if (valueOut) *valueOut = value;
    return YES;
}

static void cnd_bplist_write_uint(uint8_t *bytes, NSUInteger offset,
                                  uint8_t width, uint64_t value)
{
    for (NSUInteger index = 0; index < width; index++) {
        bytes[offset + width - index - 1] =
            (uint8_t)(value >> (index * 8u));
    }
}

static BOOL cnd_bplist_open(NSData *data, CNDBinaryPlistView *viewOut,
                            NSError **errorOut)
{
    if (![data isKindOfClass:NSData.class] || data.length < 40 ||
        memcmp(data.bytes, "bplist00", 8) != 0) {
        if (errorOut) *errorOut = cnd_icon_error(70,
            @"the installed Info.plist is not a supported binary property list");
        return NO;
    }
    const uint8_t *bytes = data.bytes;
    NSUInteger trailerOffset = data.length - 32;
    uint8_t offsetIntSize = bytes[trailerOffset + 6];
    uint8_t objectRefSize = bytes[trailerOffset + 7];
    if ((offsetIntSize != 1 && offsetIntSize != 2 &&
         offsetIntSize != 4 && offsetIntSize != 8) ||
        (objectRefSize != 1 && objectRefSize != 2 &&
         objectRefSize != 4 && objectRefSize != 8)) {
        if (errorOut) *errorOut = cnd_icon_error(71,
            @"the installed binary plist uses unsupported integer widths");
        return NO;
    }
    uint64_t objectCount = 0;
    uint64_t rootObject = 0;
    uint64_t offsetTableOffset = 0;
    if (!cnd_bplist_read_uint(bytes, data.length, trailerOffset + 8, 8,
                              &objectCount) ||
        !cnd_bplist_read_uint(bytes, data.length, trailerOffset + 16, 8,
                              &rootObject) ||
        !cnd_bplist_read_uint(bytes, data.length, trailerOffset + 24, 8,
                              &offsetTableOffset) ||
        objectCount == 0 || rootObject >= objectCount ||
        objectCount > NSUIntegerMax / offsetIntSize ||
        offsetTableOffset > trailerOffset ||
        (NSUInteger)offsetTableOffset +
            (NSUInteger)objectCount * offsetIntSize != trailerOffset) {
        if (errorOut) *errorOut = cnd_icon_error(72,
            @"the installed binary plist has an inconsistent object table");
        return NO;
    }
    if (viewOut) *viewOut = (CNDBinaryPlistView){
        .bytes = bytes,
        .length = data.length,
        .trailerOffset = trailerOffset,
        .offsetTableOffset = (NSUInteger)offsetTableOffset,
        .offsetIntSize = offsetIntSize,
        .objectRefSize = objectRefSize,
        .objectCount = objectCount,
        .rootObject = rootObject,
    };
    return YES;
}

static BOOL cnd_bplist_object_offset(const CNDBinaryPlistView *view,
                                     uint64_t objectRef,
                                     NSUInteger *offsetOut)
{
    if (!view || objectRef >= view->objectCount ||
        objectRef > NSUIntegerMax / view->offsetIntSize) return NO;
    NSUInteger entry = view->offsetTableOffset +
        (NSUInteger)objectRef * view->offsetIntSize;
    uint64_t offset = 0;
    if (!cnd_bplist_read_uint(view->bytes, view->length, entry,
                              view->offsetIntSize, &offset) ||
        offset >= view->offsetTableOffset) return NO;
    if (offsetOut) *offsetOut = (NSUInteger)offset;
    return YES;
}

static BOOL cnd_bplist_object_count(const CNDBinaryPlistView *view,
                                    NSUInteger objectOffset,
                                    uint8_t expectedType,
                                    uint64_t *countOut,
                                    NSUInteger *headerLengthOut,
                                    NSUInteger *longIntegerOffsetOut,
                                    uint8_t *longIntegerWidthOut)
{
    if (!view || objectOffset >= view->offsetTableOffset) return NO;
    uint8_t marker = view->bytes[objectOffset];
    if ((marker >> 4) != expectedType) return NO;
    uint8_t shortCount = marker & 0x0f;
    if (shortCount < 0x0f) {
        if (countOut) *countOut = shortCount;
        if (headerLengthOut) *headerLengthOut = 1;
        if (longIntegerOffsetOut) *longIntegerOffsetOut = NSNotFound;
        if (longIntegerWidthOut) *longIntegerWidthOut = 0;
        return YES;
    }
    if (objectOffset + 2 > view->offsetTableOffset) return NO;
    uint8_t integerMarker = view->bytes[objectOffset + 1];
    if ((integerMarker >> 4) != 0x1 || (integerMarker & 0x0f) > 3) {
        return NO;
    }
    uint8_t width = (uint8_t)(1U << (integerMarker & 0x0f));
    uint64_t count = 0;
    if (!cnd_bplist_read_uint(view->bytes, view->length,
                              objectOffset + 2, width, &count) ||
        objectOffset + 2 + width > view->offsetTableOffset) return NO;
    if (countOut) *countOut = count;
    if (headerLengthOut) *headerLengthOut = 2 + width;
    if (longIntegerOffsetOut) *longIntegerOffsetOut = objectOffset + 2;
    if (longIntegerWidthOut) *longIntegerWidthOut = width;
    return YES;
}

static NSString *cnd_bplist_string(const CNDBinaryPlistView *view,
                                    uint64_t objectRef)
{
    NSUInteger offset = 0;
    if (!cnd_bplist_object_offset(view, objectRef, &offset)) return nil;
    uint8_t type = view->bytes[offset] >> 4;
    if (type != 0x5 && type != 0x6) return nil;
    uint64_t characterCount = 0;
    NSUInteger headerLength = 0;
    if (!cnd_bplist_object_count(view, offset, type, &characterCount,
                                 &headerLength, NULL, NULL)) return nil;
    NSUInteger unit = type == 0x5 ? 1 : 2;
    if (characterCount > NSUIntegerMax / unit) return nil;
    NSUInteger byteCount = (NSUInteger)characterCount * unit;
    NSUInteger payloadOffset = offset + headerLength;
    if (payloadOffset > view->offsetTableOffset ||
        byteCount > view->offsetTableOffset - payloadOffset) return nil;
    NSStringEncoding encoding = type == 0x5
        ? NSASCIIStringEncoding : NSUTF16BigEndianStringEncoding;
    return [[NSString alloc] initWithBytes:view->bytes + payloadOffset
                                    length:byteCount
                                  encoding:encoding];
}

/*
 * Return the byte span reserved for an object by the binary-plist offset
 * table.  The object itself may occupy fewer bytes than this span (for
 * example after a same-size edit), but bytes in the remainder are unreachable
 * and must never be interpreted as a second object.
 */
static BOOL cnd_bplist_object_span(const CNDBinaryPlistView *view,
                                   uint64_t objectRef,
                                   NSUInteger *offsetOut,
                                   NSUInteger *lengthOut)
{
    NSUInteger offset = 0;
    if (!cnd_bplist_object_offset(view, objectRef, &offset)) return NO;
    NSUInteger end = view->offsetTableOffset;
    for (uint64_t candidate = 0; candidate < view->objectCount; candidate++) {
        NSUInteger candidateOffset = 0;
        if (!cnd_bplist_object_offset(view, candidate, &candidateOffset)) return NO;
        if (candidateOffset > offset && candidateOffset < end) {
            end = candidateOffset;
        }
    }
    if (end <= offset) return NO;
    if (offsetOut) *offsetOut = offset;
    if (lengthOut) *lengthOut = end - offset;
    return YES;
}

/* Count references from every collection object.  This is deliberately a
 * structural scan rather than a byte-pattern search: object references can
 * be one, two, four, or eight bytes wide and arbitrary payload bytes must not
 * be mistaken for references. */
static BOOL cnd_bplist_reference_count(const CNDBinaryPlistView *view,
                                       uint64_t targetRef,
                                       NSUInteger *countOut)
{
    if (!view || targetRef >= view->objectCount) return NO;
    NSUInteger total = 0;
    for (uint64_t objectRef = 0; objectRef < view->objectCount; objectRef++) {
        NSUInteger objectOffset = 0;
        if (!cnd_bplist_object_offset(view, objectRef, &objectOffset)) return NO;
        uint8_t type = view->bytes[objectOffset] >> 4;
        BOOL isDictionary = type == 0xD;
        BOOL isCollection = isDictionary || type == 0xA || type == 0xB ||
            type == 0xC;
        if (!isCollection) continue;

        uint64_t count = 0;
        NSUInteger headerLength = 0;
        if (!cnd_bplist_object_count(view, objectOffset, type, &count,
                                     &headerLength, NULL, NULL) ||
            count > NSUIntegerMax / view->objectRefSize ||
            (isDictionary && count > NSUIntegerMax /
                (2u * view->objectRefSize))) {
            return NO;
        }
        NSUInteger referenceCount = (NSUInteger)count *
            (isDictionary ? 2u : 1u);
        NSUInteger refsOffset = objectOffset + headerLength;
        if (refsOffset > view->offsetTableOffset ||
            referenceCount > (view->offsetTableOffset - refsOffset) /
                view->objectRefSize) return NO;
        for (NSUInteger index = 0; index < referenceCount; index++) {
            uint64_t reference = 0;
            if (!cnd_bplist_read_uint(view->bytes, view->length,
                                      refsOffset + index * view->objectRefSize,
                                      view->objectRefSize, &reference) ||
                reference >= view->objectCount) return NO;
            if (reference == targetRef) {
                if (total == NSUIntegerMax) return NO;
                total++;
            }
        }
    }
    if (countOut) *countOut = total;
    return YES;
}

static BOOL cnd_bplist_find_string_ref(const CNDBinaryPlistView *view,
                                       NSString *string,
                                       uint64_t *referenceOut)
{
    if (!view || ![string isKindOfClass:NSString.class]) return NO;
    for (uint64_t objectRef = 0; objectRef < view->objectCount; objectRef++) {
        if ([cnd_bplist_string(view, objectRef) isEqual:string]) {
            if (referenceOut) *referenceOut = objectRef;
            return YES;
        }
    }
    return NO;
}

static BOOL cnd_bplist_dictionary_lookup(const CNDBinaryPlistView *view,
                                         uint64_t dictionaryRef,
                                         NSString *key,
                                         uint64_t *valueRefOut,
                                         uint64_t *entryIndexOut)
{
    NSUInteger offset = 0;
    uint64_t count = 0;
    NSUInteger headerLength = 0;
    if (!cnd_bplist_object_offset(view, dictionaryRef, &offset) ||
        !cnd_bplist_object_count(view, offset, 0xD, &count, &headerLength,
                                 NULL, NULL) ||
        count > NSUIntegerMax / (2 * view->objectRefSize)) return NO;
    NSUInteger refsOffset = offset + headerLength;
    NSUInteger refsLength = (NSUInteger)count * 2 * view->objectRefSize;
    if (refsOffset > view->offsetTableOffset ||
        refsLength > view->offsetTableOffset - refsOffset) return NO;
    BOOL found = NO;
    uint64_t foundValue = 0;
    uint64_t foundIndex = 0;
    for (uint64_t index = 0; index < count; index++) {
        uint64_t keyRef = 0;
        uint64_t valueRef = 0;
        NSUInteger keyOffset = refsOffset +
            (NSUInteger)index * view->objectRefSize;
        NSUInteger valueOffset = refsOffset +
            (NSUInteger)(count + index) * view->objectRefSize;
        if (!cnd_bplist_read_uint(view->bytes, view->length, keyOffset,
                                  view->objectRefSize, &keyRef) ||
            !cnd_bplist_read_uint(view->bytes, view->length, valueOffset,
                                  view->objectRefSize, &valueRef) ||
            keyRef >= view->objectCount || valueRef >= view->objectCount) {
            return NO;
        }
        if ([cnd_bplist_string(view, keyRef) isEqual:key]) {
            if (found) return NO;
            found = YES;
            foundValue = valueRef;
            foundIndex = index;
        }
    }
    if (!found) return NO;
    if (valueRefOut) *valueRefOut = foundValue;
    if (entryIndexOut) *entryIndexOut = foundIndex;
    return YES;
}

static NSData *cnd_icon_binary_plist_remove_phone_icon_name(
    NSData *originalData, NSDictionary *expected, NSError **errorOut)
{
    CNDBinaryPlistView view = {0};
    if (!cnd_bplist_open(originalData, &view, errorOut)) return nil;
    uint64_t iconsRef = 0;
    uint64_t primaryRef = 0;
    uint64_t removedIndex = 0;
    if (!cnd_bplist_dictionary_lookup(&view, view.rootObject,
                                      @"CFBundleIcons", &iconsRef, NULL) ||
        !cnd_bplist_dictionary_lookup(&view, iconsRef,
                                      @"CFBundlePrimaryIcon", &primaryRef,
                                      NULL) ||
        !cnd_bplist_dictionary_lookup(&view, primaryRef,
                                      @"CFBundleIconName", NULL,
                                      &removedIndex)) {
        if (errorOut) *errorOut = cnd_icon_error(73,
            @"the installed binary plist does not expose one unambiguous phone primary CFBundleIconName reference");
        return nil;
    }
    NSUInteger dictionaryOffset = 0;
    uint64_t count = 0;
    NSUInteger headerLength = 0;
    NSUInteger longIntegerOffset = NSNotFound;
    uint8_t longIntegerWidth = 0;
    if (!cnd_bplist_object_offset(&view, primaryRef, &dictionaryOffset) ||
        !cnd_bplist_object_count(&view, dictionaryOffset, 0xD, &count,
                                 &headerLength, &longIntegerOffset,
                                 &longIntegerWidth) ||
        count == 0 || removedIndex >= count ||
        count > NSUIntegerMax / (2 * view.objectRefSize)) {
        if (errorOut) *errorOut = cnd_icon_error(74,
            @"the phone primary binary-plist dictionary layout is invalid");
        return nil;
    }
    NSUInteger refsOffset = dictionaryOffset + headerLength;
    NSUInteger oldRefsLength = (NSUInteger)count * 2 * view.objectRefSize;
    if (refsOffset > view.offsetTableOffset ||
        oldRefsLength > view.offsetTableOffset - refsOffset) {
        if (errorOut) *errorOut = cnd_icon_error(75,
            @"the phone primary binary-plist references are out of bounds");
        return nil;
    }
    NSMutableData *compacted = [NSMutableData dataWithCapacity:
        oldRefsLength - 2 * view.objectRefSize];
    for (uint64_t index = 0; index < count; index++) {
        if (index == removedIndex) continue;
        [compacted appendBytes:view.bytes + refsOffset +
            (NSUInteger)index * view.objectRefSize
                         length:view.objectRefSize];
    }
    NSUInteger valuesOffset = refsOffset +
        (NSUInteger)count * view.objectRefSize;
    for (uint64_t index = 0; index < count; index++) {
        if (index == removedIndex) continue;
        [compacted appendBytes:view.bytes + valuesOffset +
            (NSUInteger)index * view.objectRefSize
                         length:view.objectRefSize];
    }
    if (compacted.length != oldRefsLength - 2 * view.objectRefSize) {
        if (errorOut) *errorOut = cnd_icon_error(76,
            @"the phone primary binary-plist references did not compact exactly");
        return nil;
    }
    NSMutableData *result = [originalData mutableCopy];
    uint8_t *mutableBytes = result.mutableBytes;
    uint64_t newCount = count - 1;
    if (longIntegerOffset == NSNotFound) {
        if (newCount > 0x0e) {
            if (errorOut) *errorOut = cnd_icon_error(77,
                @"the short binary-plist dictionary count cannot be decremented in place");
            return nil;
        }
        mutableBytes[dictionaryOffset] =
            (uint8_t)(0xD0 | (uint8_t)newCount);
    } else {
        uint64_t maximum = longIntegerWidth == 8
            ? UINT64_MAX : ((1ULL << (longIntegerWidth * 8)) - 1);
        if (newCount > maximum) return nil;
        for (uint8_t i = 0; i < longIntegerWidth; i++) {
            mutableBytes[longIntegerOffset + i] = (uint8_t)(newCount >>
                ((longIntegerWidth - i - 1) * 8));
        }
    }
    memcpy(mutableBytes + refsOffset, compacted.bytes, compacted.length);
    memset(mutableBytes + refsOffset + compacted.length, 0,
           oldRefsLength - compacted.length);

    NSError *parseError = nil;
    id decoded = [NSPropertyListSerialization propertyListWithData:result
        options:NSPropertyListImmutable format:nil error:&parseError];
    if (![decoded isKindOfClass:NSDictionary.class] ||
        ![decoded isEqual:expected]) {
        if (errorOut) *errorOut = cnd_icon_error(78,
            parseError.localizedDescription ?:
                @"the in-place binary plist edit did not produce the exact expected dictionary");
        return nil;
    }
    return result;
}

/*
 * Asset-catalog-only applications commonly have a phone primary dictionary
 * containing only CFBundleIconName, while the iPad declaration already keeps
 * a CFBundleIconFiles key object in the same binary plist.  Foundation's
 * serializer may make the new declaration larger than the original vnode,
 * even though the existing object graph has enough slots to express it.
 *
 * Reuse only objects that are already present in the plist:
 *   - the existing CFBundleIconFiles string object becomes the new key;
 *   - the now-unreferenced CFBundleIconName key object's slot becomes a
 *     one-element array containing the original icon-name string object.
 *
 * The primary dictionary entry count and every offset-table entry remain
 * unchanged.  The old key must have exactly one structural reference, and
 * the resulting bytes are reparsed and compared with the expected Foundation
 * dictionary before this result can be used.
 */
static NSData *cnd_icon_binary_plist_add_phone_icon_files(
    NSData *originalData, NSDictionary *expected, NSError **errorOut)
{
    CNDBinaryPlistView view = {0};
    if (!cnd_bplist_open(originalData, &view, errorOut)) return nil;

    NSDictionary *expectedIcons = [expected[@"CFBundleIcons"]
        isKindOfClass:NSDictionary.class] ? expected[@"CFBundleIcons"] : nil;
    NSDictionary *expectedPrimary = [expectedIcons[@"CFBundlePrimaryIcon"]
        isKindOfClass:NSDictionary.class] ? expectedIcons[@"CFBundlePrimaryIcon"] : nil;
    NSArray *expectedFiles = [expectedPrimary[@"CFBundleIconFiles"]
        isKindOfClass:NSArray.class] ? expectedPrimary[@"CFBundleIconFiles"] : nil;
    if (expectedFiles.count != 1 ||
        ![expectedFiles.firstObject isKindOfClass:NSString.class]) {
        if (errorOut) *errorOut = cnd_icon_error(79,
            @"the catalog-only phone fallback must contain one safe icon file");
        return nil;
    }

    uint64_t iconsRef = 0;
    uint64_t primaryRef = 0;
    uint64_t removedIndex = 0;
    if (!cnd_bplist_dictionary_lookup(&view, view.rootObject,
                                      @"CFBundleIcons", &iconsRef, NULL) ||
        !cnd_bplist_dictionary_lookup(&view, iconsRef,
                                      @"CFBundlePrimaryIcon", &primaryRef,
                                      NULL) ||
        !cnd_bplist_dictionary_lookup(&view, primaryRef,
                                      @"CFBundleIconName", NULL,
                                      &removedIndex)) {
        if (errorOut) *errorOut = cnd_icon_error(80,
            @"the phone primary CFBundleIconName entry is not uniquely addressable");
        return nil;
    }

    NSUInteger dictionaryOffset = 0;
    uint64_t count = 0;
    NSUInteger headerLength = 0;
    if (!cnd_bplist_object_offset(&view, primaryRef, &dictionaryOffset) ||
        !cnd_bplist_object_count(&view, dictionaryOffset, 0xD, &count,
                                 &headerLength, NULL, NULL) ||
        removedIndex >= count || count > NSUIntegerMax /
            (2u * view.objectRefSize)) {
        if (errorOut) *errorOut = cnd_icon_error(81,
            @"the phone primary dictionary layout cannot be edited safely");
        return nil;
    }

    NSUInteger refsOffset = dictionaryOffset + headerLength;
    NSUInteger valuesOffset = refsOffset +
        (NSUInteger)count * view.objectRefSize;
    uint64_t oldKeyRef = 0;
    uint64_t oldValueRef = 0;
    if (!cnd_bplist_read_uint(view.bytes, view.length,
                              refsOffset + (NSUInteger)removedIndex *
                                  view.objectRefSize,
                              view.objectRefSize, &oldKeyRef) ||
        !cnd_bplist_read_uint(view.bytes, view.length,
                              valuesOffset + (NSUInteger)removedIndex *
                                  view.objectRefSize,
                              view.objectRefSize, &oldValueRef) ||
        ![cnd_bplist_string(&view, oldKeyRef) isEqual:@"CFBundleIconName"] ||
        ![cnd_bplist_string(&view, oldValueRef)
            isEqual:expectedFiles.firstObject]) {
        if (errorOut) *errorOut = cnd_icon_error(82,
            @"the existing phone icon-name objects cannot safely provide the fallback value");
        return nil;
    }

    NSUInteger oldKeyReferences = 0;
    if (!cnd_bplist_reference_count(&view, oldKeyRef, &oldKeyReferences) ||
        oldKeyReferences != 1) {
        if (errorOut) *errorOut = cnd_icon_error(83,
            @"the CFBundleIconName key object is shared by another declaration");
        return nil;
    }

    uint64_t filesKeyRef = 0;
    if (!cnd_bplist_find_string_ref(&view, @"CFBundleIconFiles",
                                    &filesKeyRef) || filesKeyRef == oldKeyRef) {
        if (errorOut) *errorOut = cnd_icon_error(84,
            @"the binary plist has no reusable CFBundleIconFiles key object");
        return nil;
    }

    NSUInteger oldKeyOffset = 0;
    NSUInteger oldKeySpan = 0;
    if (!cnd_bplist_object_span(&view, oldKeyRef, &oldKeyOffset,
                                &oldKeySpan) ||
        oldKeySpan < 1u + view.objectRefSize) {
        if (errorOut) *errorOut = cnd_icon_error(85,
            @"the removed icon-name key object has no safe array slot");
        return nil;
    }

    NSMutableData *result = [originalData mutableCopy];
    uint8_t *bytes = result.mutableBytes;
    /* Keep the primary dictionary's one entry, replacing its key and value
     * references with CFBundleIconFiles and the new array object. */
    cnd_bplist_write_uint(bytes, refsOffset + (NSUInteger)removedIndex *
        view.objectRefSize, view.objectRefSize, filesKeyRef);
    cnd_bplist_write_uint(bytes, valuesOffset + (NSUInteger)removedIndex *
        view.objectRefSize, view.objectRefSize, oldKeyRef);

    memset(bytes + oldKeyOffset, 0, oldKeySpan);
    bytes[oldKeyOffset] = 0xA1; // one-element array
    cnd_bplist_write_uint(bytes, oldKeyOffset + 1u, view.objectRefSize,
                          oldValueRef);

    NSError *parseError = nil;
    id decoded = [NSPropertyListSerialization propertyListWithData:result
        options:NSPropertyListImmutable format:nil error:&parseError];
    if (![decoded isKindOfClass:NSDictionary.class] ||
        ![decoded isEqual:expected]) {
        if (errorOut) *errorOut = cnd_icon_error(86,
            parseError.localizedDescription ?:
                @"the same-size catalog-only binary plist edit did not reparse to the expected dictionary");
        return nil;
    }
    return result;
}

/*
 * overwrite_system_file() deliberately never truncates its destination.  A
 * binary plist therefore has to occupy the destination's complete original
 * length.  Appending bytes after the binary-plist trailer is not a valid
 * representation (and is rejected by NSPropertyListSerialization), so this
 * adds one unreachable, but valid, ASCII-string object immediately before the
 * offset table.  The root object and all existing offsets remain unchanged;
 * the resulting data is reparsed before it is allowed near the bundle.
 */
static NSData *cnd_icon_binary_plist_exact_length(NSData *serialized,
                                                   NSUInteger capacity,
                                                   NSError **errorOut)
{
    if (![serialized isKindOfClass:NSData.class] || serialized.length < 40 ||
        capacity < serialized.length ||
        memcmp(serialized.bytes, "bplist00", 8) != 0) {
        if (errorOut) *errorOut = cnd_icon_error(35,
            @"the staged Info.plist is not a usable binary property list");
        return nil;
    }
    if (capacity == serialized.length) return serialized;

    const uint8_t *bytes = serialized.bytes;
    NSUInteger trailerOffset = serialized.length - 32;
    uint8_t offsetIntSize = bytes[trailerOffset + 6];
    uint8_t objectRefSize = bytes[trailerOffset + 7];
    if ((offsetIntSize != 1 && offsetIntSize != 2 &&
         offsetIntSize != 4 && offsetIntSize != 8) ||
        (objectRefSize != 1 && objectRefSize != 2 &&
         objectRefSize != 4 && objectRefSize != 8)) {
        if (errorOut) *errorOut = cnd_icon_error(36,
            @"the staged binary plist uses unsupported integer widths");
        return nil;
    }
    uint64_t objectCount = 0;
    uint64_t rootObject = 0;
    uint64_t offsetTableOffset = 0;
    for (NSUInteger i = 0; i < 8; i++) {
        objectCount = (objectCount << 8) | bytes[trailerOffset + 8 + i];
        rootObject = (rootObject << 8) | bytes[trailerOffset + 16 + i];
        offsetTableOffset = (offsetTableOffset << 8) |
            bytes[trailerOffset + 24 + i];
    }
    if (offsetTableOffset > trailerOffset ||
        objectCount == 0 || rootObject >= objectCount ||
        offsetTableOffset + objectCount * offsetIntSize != trailerOffset) {
        if (errorOut) *errorOut = cnd_icon_error(37,
            @"the staged binary plist has an inconsistent offset table");
        return nil;
    }

    NSUInteger delta = capacity - serialized.length;
    NSUInteger objectOffsetWidth = offsetIntSize;
    if (delta <= objectOffsetWidth || objectCount == UINT64_MAX) {
        if (errorOut) *errorOut = cnd_icon_error(38,
            @"the Info.plist has no exact-length binary representation available");
        return nil;
    }

    /* A valid unreachable ASCII object consumes exactly delta bytes when its
     * object bytes are delta - offsetIntSize bytes long.  Its length marker is
     * chosen so that no padding bytes are left outside the plist trailer. */
    NSUInteger objectLength = delta - objectOffsetWidth;
    NSUInteger payloadLength = 0;
    NSUInteger lengthIntegerWidth = 0;
    if (objectLength == 1) {
        /* A one-byte boolean object handles the smallest representable gap. */
        payloadLength = 0;
    } else if (objectLength <= 15) {
        payloadLength = objectLength - 1;
    } else {
        for (NSUInteger width = 1; width <= 8; width *= 2) {
            if (objectLength <= 1 + 1 + width) continue;
            NSUInteger candidate = objectLength - 1 - (1 + width);
            if (candidate <= (NSUInteger)UINT64_MAX &&
                (width == 1 ? candidate <= UINT8_MAX :
                 width == 2 ? candidate <= UINT16_MAX :
                 width == 4 ? candidate <= UINT32_MAX : YES)) {
                payloadLength = candidate;
                lengthIntegerWidth = width;
                break;
            }
        }
    }
    if (objectLength == 0 || (objectLength > 1 && objectLength <= 15 && payloadLength == 0) ||
        (objectLength > 15 && (payloadLength == 0 || lengthIntegerWidth == 0))) {
        if (errorOut) *errorOut = cnd_icon_error(39,
            @"the Info.plist exact-length filler object could not be encoded");
        return nil;
    }

    NSMutableData *result = [NSMutableData dataWithCapacity:capacity];
    [result appendBytes:bytes length:(NSUInteger)offsetTableOffset];
    NSUInteger fillerOffset = result.length;
    if (objectLength == 1) {
        uint8_t marker = 0x08; // valid, unreachable boolean false object
        [result appendBytes:&marker length:1];
    } else if (objectLength <= 15) {
        uint8_t marker = (uint8_t)(0x50 | payloadLength);
        [result appendBytes:&marker length:1];
    } else {
        uint8_t marker = (uint8_t)(0x50 | 0x0f);
        [result appendBytes:&marker length:1];
        uint8_t lengthMarker = (uint8_t)(0x10 | (uint8_t)
            __builtin_ctzll((unsigned long long)lengthIntegerWidth));
        [result appendBytes:&lengthMarker length:1];
        for (NSUInteger i = 0; i < lengthIntegerWidth; i++) {
            uint8_t value = (uint8_t)(payloadLength >>
                ((lengthIntegerWidth - i - 1) * 8));
            [result appendBytes:&value length:1];
        }
    }
    NSMutableData *payload = [NSMutableData dataWithLength:payloadLength];
    memset(payload.mutableBytes, 'x', payload.length);
    [result appendData:payload];
    if (result.length - fillerOffset != objectLength) {
        if (errorOut) *errorOut = cnd_icon_error(40,
            @"the Info.plist exact-length filler object size was inconsistent");
        return nil;
    }

    for (uint64_t index = 0; index < objectCount; index++) {
        NSUInteger entryOffset = (NSUInteger)offsetTableOffset +
            (NSUInteger)index * offsetIntSize;
        uint64_t objectOffset = 0;
        for (NSUInteger i = 0; i < offsetIntSize; i++) {
            objectOffset = (objectOffset << 8) | bytes[entryOffset + i];
        }
        for (NSInteger i = (NSInteger)offsetIntSize - 1; i >= 0; i--) {
            uint8_t value = (uint8_t)(objectOffset >> ((NSUInteger)i * 8));
            [result appendBytes:&value length:1];
        }
    }
    uint64_t fillerOffsetValue = fillerOffset;
    for (NSInteger i = (NSInteger)offsetIntSize - 1; i >= 0; i--) {
        uint8_t value = (uint8_t)(fillerOffsetValue >> ((NSUInteger)i * 8));
        [result appendBytes:&value length:1];
    }

    NSMutableData *trailer = [NSMutableData dataWithBytes:
        bytes + trailerOffset length:32];
    uint64_t newObjectCount = objectCount + 1;
    uint64_t newOffsetTableOffset = offsetTableOffset + objectLength;
    uint8_t *trailerBytes = trailer.mutableBytes;
    for (NSUInteger i = 0; i < 8; i++) {
        trailerBytes[8 + i] = (uint8_t)(newObjectCount >>
            ((7 - i) * 8));
        trailerBytes[24 + i] = (uint8_t)(newOffsetTableOffset >>
            ((7 - i) * 8));
    }
    [result appendData:trailer];
    if (result.length != capacity) {
        if (errorOut) *errorOut = cnd_icon_error(41,
            @"the Info.plist exact-length binary representation has an unexpected size");
        return nil;
    }
    return result;
}

static void cnd_icon_prepare_bundle_access(void)
{
    // A successful root extension/patch changes Cyanide's process-wide
    // sandbox state for the rest of this launch. Per-target path, symlink,
    // vnode, metadata, and hash checks still run below for every app.
    static BOOL processAccessVerified = NO;
    if (processAccessVerified) return;
    if (remote_call_lab_backend_opted_in()) {
        if (remote_call_lab_prepare_bundle_access()) {
            processAccessVerified = YES;
        } else {
            // A bundle marker can survive a guest reboot, but its sandbox
            // extension and injected installd endpoint cannot. Never fall
            // through to device-only KRW helpers merely because that one-use
            // lab credential is stale; subsequent path/RemoteCall checks fail
            // closed without touching the target.
            printf("[ICONREDIRECT] vPhone lab bundle token is unavailable; skipping device-only sandbox/KRW paths\n");
        }
        return;
    }
    if (check_sandbox_var_rw() == 0) {
        processAccessVerified = YES;
        return;
    }
    if (krw_persistence_consume_launchd_root_file_token() &&
        check_sandbox_var_rw() == 0) {
        processAccessVerified = YES;
        return;
    }
    if (patch_sandbox_ext() == 0 && check_sandbox_var_rw() == 0) {
        processAccessVerified = YES;
        return;
    }

    static const char *donors[] = {
        "installd",
        "mobile_installation_proxy",
        "sysdiagnosed",
        "cfprefsd",
        NULL,
    };
    for (int i = 0; donors[i]; i++) {
        if (borrow_sandbox_ext(donors[i]) == 0 &&
            check_sandbox_var_rw() == 0) {
            processAccessVerified = YES;
            return;
        }
    }

    // Global /private/var write access is not required for the absent-file
    // path (stock installd owns create/read/remove) or for an existing-vnode
    // overwrite (the shared primitive needs only a readable target fd before
    // it adjusts that fileglob). Let the path-specific discovery/preflight
    // checks decide whether the required access is actually available.
    printf("[ICONREDIRECT] global /private/var rw probe still denied; continuing with path-specific checks\n");
}

static BOOL cnd_icon_validate_bundle(NSDictionary *registration,
                                     NSString **bundlePathOut,
                                     NSString **failureOut)
{
    NSString *rawPath = registration[@"Path"];
    NSString *bundlePath = cnd_icon_canonical_path(rawPath);
    NSString *hostPath = cnd_icon_canonical_path(NSBundle.mainBundle.bundlePath);
    struct stat st = {0};
    BOOL labSelfTarget = remote_call_lab_backend_opted_in() &&
        [registration[@"CFBundleIdentifier"]
            isEqual:NSBundle.mainBundle.bundleIdentifier] &&
        [bundlePath isEqual:hostPath];
    BOOL remixSelfTarget = gCNDIconRedirectOverrideBundleIdentifier.length > 0 &&
        [registration[@"CFBundleIdentifier"]
            isEqual:NSBundle.mainBundle.bundleIdentifier] &&
        [bundlePath isEqual:hostPath];
    if (![registration[@"CFBundleIdentifier"]
            isEqual:cnd_icon_target_bundle_identifier()] ||
        bundlePath.length == 0 ||
        ([bundlePath isEqual:hostPath] && !labSelfTarget && !remixSelfTarget) ||
        [bundlePath hasPrefix:[hostPath stringByAppendingString:@"/"]] ||
        lstat(bundlePath.fileSystemRepresentation, &st) != 0 ||
        !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
        if (failureOut) {
            *failureOut = @"the captured eBay bundle identity/path boundary is invalid";
        }
        return NO;
    }
    if (bundlePathOut) *bundlePathOut = bundlePath;
    return YES;
}

static NSDictionary *cnd_icon_primary_dictionary(NSDictionary *registration)
{
    NSDictionary *icons = registration[@"CFBundleIcons"];
    NSDictionary *primary = [icons isKindOfClass:NSDictionary.class]
        ? icons[@"CFBundlePrimaryIcon"] : nil;
    return [primary isKindOfClass:NSDictionary.class] ? primary : nil;
}

static NSArray<NSString *> *cnd_icon_declared_files(NSDictionary *registration)
{
    NSDictionary *primary = cnd_icon_primary_dictionary(registration);
    id value = primary[@"CFBundleIconFiles"];
    // Older applications may keep the fallback declaration at the root of
    // the plist instead of under CFBundlePrimaryIcon. Treat both forms as
    // declarations, while leaving the original location untouched during
    // the eventual semantic plist edit.
    if (![value isKindOfClass:NSArray.class]) value = registration[@"CFBundleIconFiles"];
    if (![value isKindOfClass:NSArray.class]) {
        // A safe CFBundleIconName is a useful base-name hint when the legacy
        // array is absent. It is not itself a file declaration; discovery
        // still requires an existing matching PNG or a validated dimension
        // inference before a file can be created.
        NSString *name = primary[@"CFBundleIconName"];
        if (cnd_icon_is_safe_leaf(name)) value = @[name];
    }
    if (![value isKindOfClass:NSArray.class]) return @[];
    NSMutableArray<NSString *> *files = [NSMutableArray array];
    for (id item in (NSArray *)value) {
        if (![item isKindOfClass:NSString.class] ||
            !cnd_icon_is_safe_leaf(item)) return nil;
        [files addObject:item];
    }
    return files;
}

static NSArray<NSString *> *cnd_icon_filenames_for_declaration(
    NSString *declaration, NSInteger scale)
{
    if (!cnd_icon_is_safe_leaf(declaration)) return @[];
    NSString *base = [[declaration pathExtension].lowercaseString isEqual:@"png"]
        ? [declaration stringByDeletingPathExtension] : declaration;
    NSString *scaleSuffix = [NSString stringWithFormat:@"@%ldx", (long)scale];
    BOOL hasExplicitScale = NO;
    for (NSInteger candidateScale = 1; candidateScale <= 4; candidateScale++) {
        if ([base hasSuffix:[NSString stringWithFormat:@"@%ldx",
                                                       (long)candidateScale]]) {
            hasExplicitScale = YES;
            break;
        }
    }
    if (hasExplicitScale && ![base hasSuffix:scaleSuffix]) return @[];
    NSString *scaledBase = hasExplicitScale
        ? base : [base stringByAppendingString:scaleSuffix];
    NSMutableArray<NSString *> *filenames = [NSMutableArray arrayWithArray:@[
        [scaledBase stringByAppendingString:@".png"],
        [scaledBase stringByAppendingString:@"~iphone.png"],
    ]];
    if (!hasExplicitScale && scale == 1) {
        // Legacy declarations sometimes point at an unscaled PNG (for
        // example Icon.png) rather than an @1x sibling.
        [filenames addObject:[base stringByAppendingString:@".png"]];
        [filenames addObject:[base stringByAppendingString:@"~iphone.png"]];
    }
    return filenames;
}

static BOOL cnd_icon_declaration_has_explicit_scale(NSString *declaration)
{
    if (!cnd_icon_is_safe_leaf(declaration)) return NO;
    NSString *base = [[declaration.pathExtension.lowercaseString isEqual:@"png"]
        ? [declaration stringByDeletingPathExtension] : declaration copy];
    for (NSInteger scale = 1; scale <= 4; scale++) {
        if ([base hasSuffix:[NSString stringWithFormat:@"@%ldx", (long)scale]]) {
            return YES;
        }
    }
    return NO;
}

static BOOL cnd_icon_infer_missing_dimensions(
    NSString *bundlePath,
    NSString *declaration,
    NSInteger targetScale,
    NSDictionary<NSString *, NSDictionary *> *candidatesByFilename,
    NSUInteger *widthOut,
    NSUInteger *heightOut)
{
    if (!bundlePath.length || !declaration.length || targetScale <= 0) return NO;
    NSUInteger pointWidth = 0;
    NSUInteger pointHeight = 0;
    BOOL found = NO;
    for (NSString *filename in candidatesByFilename) {
        NSDictionary *candidate = candidatesByFilename[filename];
        if (![candidate[@"declaration"] isEqual:declaration]) continue;
        NSInteger scale = [candidate[@"scale"] integerValue];
        if (scale <= 0) continue;
        NSString *path = [bundlePath stringByAppendingPathComponent:filename];
        NSData *data = nil;
        if (!cnd_icon_read_regular_file(path, &data, NULL, NULL)) return NO;
        UIImage *image = [UIImage imageWithData:data];
        if (image.CGImage == nil) return NO;
        NSUInteger width = CGImageGetWidth(image.CGImage);
        NSUInteger height = CGImageGetHeight(image.CGImage);
        if (width == 0 || height == 0 || width % (NSUInteger)scale != 0 ||
            height % (NSUInteger)scale != 0) return NO;
        NSUInteger candidatePointWidth = width / (NSUInteger)scale;
        NSUInteger candidatePointHeight = height / (NSUInteger)scale;
        if (!found) {
            pointWidth = candidatePointWidth;
            pointHeight = candidatePointHeight;
            found = YES;
        } else if (pointWidth != candidatePointWidth ||
                   pointHeight != candidatePointHeight) {
            return NO;
        }
    }

    if (!found) {
        NSRegularExpression *sizeExpression = [NSRegularExpression
            regularExpressionWithPattern:@"([0-9]{1,4})x([0-9]{1,4})"
            options:NSRegularExpressionCaseInsensitive error:nil];
        NSTextCheckingResult *match = [sizeExpression firstMatchInString:declaration
            options:0 range:NSMakeRange(0, declaration.length)];
        if (!match || match.numberOfRanges != 3) return NO;
        pointWidth = [[declaration substringWithRange:[match rangeAtIndex:1]] integerValue];
        pointHeight = [[declaration substringWithRange:[match rangeAtIndex:2]] integerValue];
    }
    if (pointWidth == 0 || pointHeight == 0 || pointWidth > 1024 ||
        pointHeight > 1024 || pointWidth > NSUIntegerMax / (NSUInteger)targetScale ||
        pointHeight > NSUIntegerMax / (NSUInteger)targetScale) return NO;
    NSUInteger width = pointWidth * (NSUInteger)targetScale;
    NSUInteger height = pointHeight * (NSUInteger)targetScale;
    if (width > CNDIconThemeImageProcessorMaximumDimension ||
        height > CNDIconThemeImageProcessorMaximumDimension) return NO;
    if (widthOut) *widthOut = width;
    if (heightOut) *heightOut = height;
    return YES;
}

static BOOL cnd_icon_write_stage(NSData *data, NSError **errorOut);
static NSDictionary *cnd_icon_plist_object_from_data(NSData *data,
                                                     NSError **errorOut);

static NSDictionary *cnd_icon_discover_target(NSDictionary *plistDictionary,
                                               NSString *bundlePath,
                                               NSUInteger sourceWidth,
                                               NSUInteger sourceHeight,
                                               NSError **errorOut)
{
    NSDictionary *primary = cnd_icon_primary_dictionary(plistDictionary);
    id rawIcons = plistDictionary[@"CFBundleIcons"];
    if (rawIcons != nil && ![rawIcons isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = cnd_icon_error(20,
            @"the captured phone icon declaration is malformed");
        return nil;
    }
    if (!primary) primary = @{};
    NSArray<NSString *> *declared = cnd_icon_declared_files(plistDictionary);
    if (!declared) {
        if (errorOut) *errorOut = cnd_icon_error(21,
            @"eBay's primary CFBundleIconFiles contains an unsafe entry");
        return nil;
    }

    // SnowBoard Remix deliberately targets the proven phone fallback slot.
    // The iOS 26 vPhone resolver proof used AppIcon60x60@2x.png even for a
    // 3x IconServices descriptor request; do not derive this from UIScreen.
    static const NSInteger deviceScale = 2;
    NSError *listingError = nil;
    NSArray<NSString *> *bundleEntries = [NSFileManager.defaultManager
        contentsOfDirectoryAtPath:bundlePath error:&listingError];
    if (!bundleEntries) {
        if (errorOut) *errorOut = cnd_icon_error(22,
            listingError.localizedDescription ?:
                @"the eBay bundle contents could not be enumerated");
        return nil;
    }
    NSSet<NSString *> *entrySet = [NSSet setWithArray:bundleEntries];
    NSMutableArray<NSString *> *effectiveDeclared = [declared mutableCopy];
    BOOL primaryFilesPresent = [primary[@"CFBundleIconFiles"] isKindOfClass:NSArray.class] &&
                               [primary[@"CFBundleIconFiles"] count] > 0;
    BOOL rootFilesPresent = [plistDictionary[@"CFBundleIconFiles"] isKindOfClass:NSArray.class] &&
                            [plistDictionary[@"CFBundleIconFiles"] count] > 0;
    BOOL addsDeclaration = !primaryFilesPresent && !rootFilesPresent;
    if (effectiveDeclared.count == 0) {
        // Apps that only declare an asset-catalog name can still be handled
        // when that name has an unambiguous legacy PNG sibling. This keeps
        // the fallback name bundle-relative and fails closed for arbitrary
        // resource PNGs rather than guessing among them.
        NSString *iconName = primary[@"CFBundleIconName"];
        if (cnd_icon_is_safe_leaf(iconName)) {
            [effectiveDeclared addObject:iconName];
        } else {
            NSMutableSet<NSString *> *candidateBases = [NSMutableSet set];
            NSRegularExpression *scaleExpression = [NSRegularExpression
                regularExpressionWithPattern:@"^(.*)@([1-4])x(?:~iphone)?\\.png$"
                options:NSRegularExpressionCaseInsensitive error:nil];
            for (NSString *entry in bundleEntries) {
                if (!cnd_icon_is_safe_leaf(entry) ||
                    ![entry.pathExtension.lowercaseString isEqual:@"png"]) continue;
                NSTextCheckingResult *match = [scaleExpression firstMatchInString:entry
                    options:0 range:NSMakeRange(0, entry.length)];
                if (!match || match.numberOfRanges != 3) continue;
                NSString *base = [entry substringWithRange:[match rangeAtIndex:1]];
                if (cnd_icon_is_safe_leaf(base) && base.length > 0) {
                    [candidateBases addObject:base];
                }
            }
            if (candidateBases.count == 1) {
                [effectiveDeclared addObject:candidateBases.anyObject];
            }
        }
    }
    if (effectiveDeclared.count == 0) {
        if (errorOut) *errorOut = cnd_icon_error(21,
            @"the application has no unambiguous legacy phone fallback declaration");
        return nil;
    }
    NSMutableDictionary<NSString *, NSDictionary *> *candidatesByFilename =
        [NSMutableDictionary dictionary];
    for (NSString *declaration in effectiveDeclared) {
        for (NSInteger candidateScale = 1; candidateScale <= 4;
             candidateScale++) {
            for (NSString *filename in cnd_icon_filenames_for_declaration(
                     declaration, candidateScale)) {
                if (![entrySet containsObject:filename]) continue;
                NSString *path = [bundlePath stringByAppendingPathComponent:filename];
                struct stat st = {0};
                if (lstat(path.fileSystemRepresentation, &st) != 0) {
                    if (errorOut) *errorOut = cnd_icon_error(23,
                        [NSString stringWithFormat:
                            @"the enumerated icon %@ disappeared: %s",
                            filename, strerror(errno)]);
                    return nil;
                }
                if (S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode) ||
                    !cnd_icon_path_is_strictly_beneath(path, bundlePath)) {
                    if (errorOut) *errorOut = cnd_icon_error(24,
                        [NSString stringWithFormat:@"declared icon %@ is not a safe regular bundle file", filename]);
                    return nil;
                }
                NSDictionary *existing = candidatesByFilename[filename];
                if (existing &&
                    ![existing[@"declaration"] isEqual:declaration]) {
                    if (errorOut) *errorOut = cnd_icon_error(25,
                        [NSString stringWithFormat:
                            @"declared icon %@ maps to more than one base name",
                            filename]);
                    return nil;
                }
                candidatesByFilename[filename] = @{
                    @"declaration": declaration,
                    @"scale": @(candidateScale),
                };
            }
        }
    }

    NSMutableArray<NSString *> *bestFilenames = [NSMutableArray array];
    for (NSString *candidateFilename in candidatesByFilename) {
        NSInteger candidateScale =
            [candidatesByFilename[candidateFilename][@"scale"] integerValue];
        if (candidateScale == deviceScale) {
            [bestFilenames addObject:candidateFilename];
        }
    }
    if (bestFilenames.count > 1) {
        if (errorOut) *errorOut = cnd_icon_error(25,
            [NSString stringWithFormat:
                @"more than one declared eBay icon is equally suitable for the %ldx device scale",
                (long)deviceScale]);
        return nil;
    }

    if (bestFilenames.count == 0 && effectiveDeclared.count != 1) {
        if (errorOut) *errorOut = cnd_icon_error(25,
            @"the application has no unambiguous declared @2x phone fallback");
        return nil;
    }

    NSString *filename = bestFilenames.firstObject;
    NSDictionary *selectedCandidate = filename
        ? candidatesByFilename[filename] : nil;
    NSString *declaration = selectedCandidate[@"declaration"];
    NSInteger selectedScale = selectedCandidate
        ? [selectedCandidate[@"scale"] integerValue] : deviceScale;
    BOOL createsFile = filename.length == 0;
    if (createsFile) {
        // Prefer creating the device-scale fallback when a declared base has
        // only a different sibling scale. The sibling dimensions are used to
        // derive the new target size below; an existing fallback is never
        // replaced solely because it is a different scale.
        if (effectiveDeclared.count == 1 &&
            !cnd_icon_declaration_has_explicit_scale(effectiveDeclared.firstObject)) {
            declaration = effectiveDeclared.firstObject;
            filename = cnd_icon_filenames_for_declaration(
                declaration, deviceScale).firstObject;
        }
        if (declaration.length == 0 || filename.length == 0) {
            if (effectiveDeclared.count > 0) declaration = effectiveDeclared.firstObject;
            filename = cnd_icon_filenames_for_declaration(
                declaration, deviceScale).firstObject;
        }
    }
    if (!cnd_icon_is_safe_leaf(filename) || !cnd_icon_is_safe_leaf(declaration)) {
        if (errorOut) *errorOut = cnd_icon_error(26,
            @"the selected legacy icon declaration is not a safe bundle-relative name");
        return nil;
    }

    NSString *targetPath = [bundlePath stringByAppendingPathComponent:filename];
    if (!cnd_icon_path_is_strictly_beneath(targetPath, bundlePath)) {
        if (errorOut) *errorOut = cnd_icon_error(27,
            @"the selected icon path escaped the captured eBay bundle");
        return nil;
    }

    NSData *originalData = [NSData data];
    struct stat originalStat = {0};
    NSUInteger width = 0;
    NSUInteger height = 0;
    NSDictionary *metadata = @{};
    NSString *dimensionsSource = @"unknown";
    if (!createsFile) {
        if (!cnd_icon_read_regular_file(targetPath, &originalData,
                                        &originalStat, errorOut)) return nil;
        UIImage *originalImage = [UIImage imageWithData:originalData];
        if (originalImage.CGImage == nil) {
            if (errorOut) *errorOut = cnd_icon_error(28,
                @"the selected existing eBay icon is not a decodable image");
            return nil;
        }
        width = CGImageGetWidth(originalImage.CGImage);
        height = CGImageGetHeight(originalImage.CGImage);
        if (width == 0 || height == 0) {
            if (errorOut) *errorOut = cnd_icon_error(29,
                @"the selected existing eBay icon has invalid dimensions");
            return nil;
        }
        metadata = cnd_icon_stat_dictionary(&originalStat);
        dimensionsSource = @"existing-icon";
    } else {
        struct stat absent = {0};
        if (lstat(targetPath.fileSystemRepresentation, &absent) == 0 ||
            errno != ENOENT) {
            if (errorOut) *errorOut = cnd_icon_error(30,
                @"the new-file icon fallback target is not provably absent");
            return nil;
        }
        /*
         * An asset-catalog-only application can expose a perfectly valid
         * phone-primary CFBundleIconName without declaring any legacy PNG.
         * There is no on-disk sibling from which to infer a point-size
         * relationship in that case.  The Remix experiment deliberately
         * creates the conventional @2x leaf while retaining the validated
         * source PNG's pixel dimensions.  This is bounded by the source
         * preflight and the final PNG decoder; it does not weaken any path,
         * vnode, hash, or registration checks.
         */
        BOOL hasSiblingForSelectedDeclaration = NO;
        for (NSDictionary *candidate in candidatesByFilename.allValues) {
            if ([candidate[@"declaration"] isEqual:declaration]) {
                hasSiblingForSelectedDeclaration = YES;
                break;
            }
        }
        if (!hasSiblingForSelectedDeclaration && sourceWidth > 0 &&
            sourceHeight > 0) {
            width = sourceWidth;
            height = sourceHeight;
            dimensionsSource = @"source-png";
        } else if (!cnd_icon_infer_missing_dimensions(
                       bundlePath, declaration, deviceScale,
                       candidatesByFilename, &width, &height)) {
            if (errorOut) *errorOut = cnd_icon_error(30,
                @"the missing @2x fallback dimensions could not be inferred from its declaration or sibling icon");
            return nil;
        } else {
            dimensionsSource = @"declaration-or-sibling";
        }
    }

    return @{
        @"mode": createsFile ? @"create" : @"overwrite",
        @"bundlePath": bundlePath,
        @"relativePath": filename,
        @"targetPath": targetPath,
        @"declaredBaseName": declaration,
        @"declaredFilesBefore": declared,
        @"effectiveDeclaredFiles": effectiveDeclared,
        @"declaredFilesBeforePresent": @(primaryFilesPresent || rootFilesPresent),
        @"addsDeclaration": @(addsDeclaration),
        @"scale": @(selectedScale),
        @"deviceScale": @(deviceScale),
        @"width": @(width),
        @"height": @(height),
        @"dimensionsSource": dimensionsSource,
        @"originalData": originalData,
        @"originalHash": cnd_icon_sha256(originalData) ?: @"",
        @"originalMetadata": metadata,
    };
}

static NSDictionary *cnd_icon_discover_plist(NSString *bundlePath,
                                              NSError **errorOut)
{
    NSArray<NSString *> *entries = [NSFileManager.defaultManager
        contentsOfDirectoryAtPath:bundlePath error:errorOut];
    if (!entries) return nil;
    NSMutableArray<NSString *> *matchingPaths = [NSMutableArray array];
    for (NSString *entry in entries) {
        if (!cnd_icon_is_safe_leaf(entry) ||
            ![entry.pathExtension.lowercaseString isEqual:@"plist"]) continue;
        NSString *candidatePath = [bundlePath stringByAppendingPathComponent:entry];
        if (!cnd_icon_path_is_strictly_beneath(candidatePath, bundlePath)) continue;
        struct stat candidateStat = {0};
        if (lstat(candidatePath.fileSystemRepresentation, &candidateStat) != 0 ||
            S_ISLNK(candidateStat.st_mode) || !S_ISREG(candidateStat.st_mode) ||
            candidateStat.st_size <= 0 || candidateStat.st_size > 4 * 1024 * 1024) continue;
        NSData *candidateData = [NSData dataWithContentsOfFile:candidatePath
            options:NSDataReadingMappedIfSafe error:nil];
        NSDictionary *candidate = candidateData.length > 0
            ? [NSPropertyListSerialization propertyListWithData:candidateData
                options:NSPropertyListImmutable format:nil error:nil] : nil;
        if ([candidate isKindOfClass:NSDictionary.class] &&
            [candidate[@"CFBundleIdentifier"]
                isEqual:cnd_icon_target_bundle_identifier()] &&
            [candidate[@"CFBundlePackageType"] isEqual:@"APPL"]) {
            [matchingPaths addObject:candidatePath];
        }
    }
    if (matchingPaths.count != 1) {
        if (errorOut) *errorOut = cnd_icon_error(42,
            @"the application's real root Info.plist could not be identified unambiguously");
        return nil;
    }
    NSString *targetPath = matchingPaths.firstObject;
    if (!cnd_icon_path_is_strictly_beneath(targetPath, bundlePath)) {
        if (errorOut) *errorOut = cnd_icon_error(42,
            @"the captured Info.plist path escaped the eBay bundle");
        return nil;
    }
    struct stat originalStat = {0};
    NSString *leafFailure = nil;
    if (!cnd_icon_regular_leaf(targetPath, &originalStat, &leafFailure)) {
        if (errorOut) *errorOut = cnd_icon_error(43, leafFailure);
        return nil;
    }
    NSData *originalData = nil;
    NSError *readError = nil;
    if (!cnd_icon_read_regular_file(targetPath, &originalData, &originalStat,
                                    &readError)) {
        if (errorOut) *errorOut = readError ?: cnd_icon_error(44,
            @"the captured Info.plist could not be read");
        return nil;
    }
    NSError *parseError = nil;
    id parsed = [NSPropertyListSerialization propertyListWithData:originalData
        options:NSPropertyListImmutable format:nil error:&parseError];
    if (![parsed isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = cnd_icon_error(45,
            parseError.localizedDescription ?:
                @"the captured eBay Info.plist is not a property-list dictionary");
        return nil;
    }
    NSDictionary *original = parsed;
    if (![original[@"CFBundleIdentifier"]
            isEqual:cnd_icon_target_bundle_identifier()]) {
        if (errorOut) *errorOut = cnd_icon_error(46,
            @"the captured eBay Info.plist bundle identifier is unexpected");
        return nil;
    }
    NSDictionary *icons = original[@"CFBundleIcons"];
    if (icons != nil && ![icons isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = cnd_icon_error(47,
            @"the actual phone icon declaration is not a dictionary");
        return nil;
    }
    return @{
        @"targetPath": targetPath,
        @"originalData": originalData,
        @"originalHash": cnd_icon_sha256(originalData) ?: @"",
        @"originalMetadata": cnd_icon_stat_dictionary(&originalStat),
        @"originalDictionary": original,
        @"replacementDictionary": original,
    };
}

static NSDictionary *cnd_icon_plist_replacement_for_target(
    NSDictionary *original, NSDictionary *target, NSError **errorOut)
{
    if (![original isKindOfClass:NSDictionary.class] ||
        ![target isKindOfClass:NSDictionary.class]) return nil;
    NSDictionary *icons = [original[@"CFBundleIcons"] isKindOfClass:NSDictionary.class]
        ? original[@"CFBundleIcons"] : @{};
    NSDictionary *primary = [icons[@"CFBundlePrimaryIcon"] isKindOfClass:NSDictionary.class]
        ? icons[@"CFBundlePrimaryIcon"] : @{};
    NSMutableDictionary *modified = [original mutableCopy];
    NSMutableDictionary *modifiedIcons = [icons mutableCopy];
    NSMutableDictionary *modifiedPrimary = [primary mutableCopy];
    [modifiedPrimary removeObjectForKey:@"CFBundleIconName"];
    id declaredFiles = primary[@"CFBundleIconFiles"];
    if (![declaredFiles isKindOfClass:NSArray.class] ||
        [(NSArray *)declaredFiles count] == 0) {
        NSString *base = target[@"declaredBaseName"];
        if (!cnd_icon_is_safe_leaf(base)) {
            if (errorOut) *errorOut = cnd_icon_error(48,
                @"a safe phone fallback declaration could not be constructed");
            return nil;
        }
        modifiedPrimary[@"CFBundleIconFiles"] = @[base];
    }
    modifiedIcons[@"CFBundlePrimaryIcon"] = modifiedPrimary;
    modified[@"CFBundleIcons"] = modifiedIcons;
    return modified;
}

static BOOL cnd_icon_exact_plist_mutation(NSDictionary *original,
                                          NSDictionary *modified)
{
    if (![original isKindOfClass:NSDictionary.class] ||
        ![modified isKindOfClass:NSDictionary.class]) return NO;
    NSDictionary *icons = original[@"CFBundleIcons"];
    NSDictionary *primary = [icons isKindOfClass:NSDictionary.class]
        ? icons[@"CFBundlePrimaryIcon"] : nil;
    NSDictionary *modifiedIcons = modified[@"CFBundleIcons"];
    NSDictionary *modifiedPrimary = [modifiedIcons isKindOfClass:NSDictionary.class]
        ? modifiedIcons[@"CFBundlePrimaryIcon"] : nil;
    if (icons != nil && ![icons isKindOfClass:NSDictionary.class]) return NO;
    if (primary != nil && ![primary isKindOfClass:NSDictionary.class]) return NO;
    if (![modifiedIcons isKindOfClass:NSDictionary.class] ||
        ![modifiedPrimary isKindOfClass:NSDictionary.class] ||
        modifiedPrimary[@"CFBundleIconName"] != nil) return NO;
    id files = modifiedPrimary[@"CFBundleIconFiles"];
    if (![files isKindOfClass:NSArray.class] || [(NSArray *)files count] == 0) return NO;
    for (id file in (NSArray *)files) if (!cnd_icon_is_safe_leaf(file)) return NO;

    NSMutableDictionary *expectedPrimary = primary
        ? [primary mutableCopy] : [NSMutableDictionary dictionary];
    [expectedPrimary removeObjectForKey:@"CFBundleIconName"];
    id originalFiles = primary[@"CFBundleIconFiles"];
    if (originalFiles != nil) {
        if (![files isEqual:originalFiles]) return NO;
    } else {
        expectedPrimary[@"CFBundleIconFiles"] = files;
    }
    if (![expectedPrimary isEqual:modifiedPrimary]) return NO;

    NSMutableDictionary *expected = [original mutableCopy];
    NSMutableDictionary *expectedIcons = [icons mutableCopy];
    if (!expectedIcons) expectedIcons = [NSMutableDictionary dictionary];
    expectedIcons[@"CFBundlePrimaryIcon"] = expectedPrimary;
    expected[@"CFBundleIcons"] = expectedIcons;
    return [expected isEqual:modified];
}

static NSData *cnd_icon_render_payload(NSData *payloadData, NSUInteger width,
                                       NSUInteger height, NSUInteger capacity,
                                       NSDictionary **processingOut,
                                       NSError **errorOut)
{
    NSDictionary *processing = CNDProcessIconThemePNG(
        payloadData, width, height, capacity, errorOut);
    NSData *staged = processing[@"paddedBytes"];
    if (![staged isKindOfClass:NSData.class] || staged.length == 0) return nil;
    if (!cnd_icon_write_stage(staged, errorOut)) return nil;
    NSData *diskReadback = nil;
    if (!cnd_icon_read_regular_file(cnd_icon_stage_url().path, &diskReadback,
                                    NULL, errorOut) ||
        ![cnd_icon_sha256(diskReadback) isEqual:cnd_icon_sha256(staged)]) {
        if (errorOut && !*errorOut) *errorOut = cnd_icon_error(33,
            @"the staged PNG failed exact disk readback verification");
        return nil;
    }
    if (processingOut) *processingOut = processing;
    return staged;
}

static NSData *cnd_icon_render_plist(NSData *originalData,
                                     NSDictionary *original,
                                     NSDictionary *modified,
                                     NSUInteger capacity,
                                     NSError **errorOut)
{
    if (!cnd_icon_exact_plist_mutation(original, modified)) {
        if (errorOut) *errorOut = cnd_icon_error(49,
            @"the requested Info.plist mutation is not the supported phone-primary fallback edit");
        return nil;
    }
    NSError *inPlaceError = nil;
    if ([originalData isKindOfClass:NSData.class] &&
        originalData.length == capacity && originalData.length >= 8 &&
        memcmp(originalData.bytes, "bplist00", 8) == 0) {
        NSDictionary *originalIcons = [original[@"CFBundleIcons"]
            isKindOfClass:NSDictionary.class] ? original[@"CFBundleIcons"] : nil;
        NSDictionary *originalPrimary = [originalIcons[@"CFBundlePrimaryIcon"]
            isKindOfClass:NSDictionary.class]
            ? originalIcons[@"CFBundlePrimaryIcon"] : nil;
        NSDictionary *modifiedIcons = [modified[@"CFBundleIcons"]
            isKindOfClass:NSDictionary.class] ? modified[@"CFBundleIcons"] : nil;
        NSDictionary *modifiedPrimary = [modifiedIcons[@"CFBundlePrimaryIcon"]
            isKindOfClass:NSDictionary.class]
            ? modifiedIcons[@"CFBundlePrimaryIcon"] : nil;
        BOOL addsPhoneFiles = ![originalPrimary[@"CFBundleIconFiles"]
            isKindOfClass:NSArray.class] &&
            [modifiedPrimary[@"CFBundleIconFiles"] isKindOfClass:NSArray.class];
        NSData *inPlace = addsPhoneFiles
            ? cnd_icon_binary_plist_add_phone_icon_files(
                originalData, modified, &inPlaceError)
            : cnd_icon_binary_plist_remove_phone_icon_name(
                originalData, modified, &inPlaceError);
        if (inPlace) return inPlace;
    }
    NSError *serializationError = nil;
    NSData *serialized = [NSPropertyListSerialization
        dataWithPropertyList:modified
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:&serializationError];
    if (serialized.length == 0 || serializationError) {
        if (errorOut) *errorOut = cnd_icon_error(50,
            serializationError.localizedDescription ?:
                @"the modified Info.plist could not be serialized");
        return nil;
    }
    if (serialized.length > capacity && inPlaceError) {
        if (errorOut) *errorOut = inPlaceError;
        return nil;
    }
    NSData *staged = cnd_icon_binary_plist_exact_length(
        serialized, capacity, errorOut);
    if (!staged) return nil;
    NSError *parseError = nil;
    id decoded = [NSPropertyListSerialization propertyListWithData:staged
        options:NSPropertyListImmutable format:nil error:&parseError];
    if (![decoded isKindOfClass:NSDictionary.class] ||
        ![decoded isEqual:modified]) {
        if (errorOut) *errorOut = cnd_icon_error(51,
            parseError.localizedDescription ?:
                @"the exact-length staged Info.plist did not reparse to the requested dictionary");
        return nil;
    }
    return staged;
}

static BOOL cnd_icon_stage_plist_verified(NSData *data,
                                          NSDictionary *expected,
                                          NSError **errorOut)
{
    if (!cnd_icon_write_stage(data, errorOut)) return NO;
    NSData *readback = nil;
    NSError *readError = nil;
    NSDictionary *decoded = nil;
    if (!cnd_icon_read_regular_file(cnd_icon_stage_url().path, &readback,
                                    NULL, &readError)) {
        if (errorOut) *errorOut = readError;
        return NO;
    }
    decoded = cnd_icon_plist_object_from_data(readback, &readError);
    if (readback.length != data.length ||
        ![cnd_icon_sha256(readback) isEqual:cnd_icon_sha256(data)] ||
        ![decoded isEqual:expected]) {
        if (errorOut) *errorOut = cnd_icon_error(64,
            readError.localizedDescription ?:
                @"the staged Info.plist failed preflight byte/hash/object verification");
        return NO;
    }
    return YES;
}

static BOOL cnd_icon_write_dictionary(NSDictionary *dictionary,
                                      NSError **errorOut)
{
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:dictionary
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:errorOut];
    if (data.length == 0) return NO;
    NSURL *url = cnd_icon_backup_url();
    NSFileManager *manager = NSFileManager.defaultManager;
    if (![manager createDirectoryAtURL:url.URLByDeletingLastPathComponent
           withIntermediateDirectories:YES
                            attributes:@{NSFileProtectionKey: NSFileProtectionNone}
                                 error:errorOut] ||
        ![data writeToURL:url options:NSDataWritingAtomic error:errorOut] ||
        ![manager setAttributes:@{
                NSFileProtectionKey: NSFileProtectionNone,
                NSFilePosixPermissions: @0600,
            } ofItemAtPath:url.path error:errorOut]) return NO;

    NSData *readback = [NSData dataWithContentsOfURL:url options:0 error:errorOut];
    NSDictionary *decoded = readback.length > 0
        ? [NSPropertyListSerialization propertyListWithData:readback
            options:NSPropertyListImmutable format:nil error:errorOut] : nil;
    if (![decoded isEqual:dictionary]) {
        if (errorOut && !*errorOut) {
            *errorOut = cnd_icon_error(40,
                @"the icon recovery journal did not survive readback intact");
        }
        return NO;
    }
    return YES;
}

static NSDictionary *cnd_icon_read_backup(NSError **errorOut)
{
    NSData *data = [NSData dataWithContentsOfURL:cnd_icon_backup_url()
        options:0 error:errorOut];
    if (data.length == 0) return nil;
    id value = [NSPropertyListSerialization propertyListWithData:data
        options:NSPropertyListImmutable format:nil error:errorOut];
    if (![value isKindOfClass:NSDictionary.class]) return nil;
    NSDictionary *envelope = value;
    NSDictionary *registration = envelope[@"registrationDictionary"];
    NSUInteger version = [envelope[@"version"] unsignedIntegerValue];
    BOOL baseValid = [envelope[@"bundleIdentifier"]
            isEqual:cnd_icon_target_bundle_identifier()] &&
        [registration isKindOfClass:NSDictionary.class] &&
        [registration[@"CFBundleIdentifier"]
            isEqual:cnd_icon_target_bundle_identifier()] &&
        [registration[@"Path"] isKindOfClass:NSString.class] &&
        cnd_icon_is_plist(registration);
    if (version == 1 && baseValid) return envelope;

    NSDictionary *file = envelope[@"fileMutation"];
    NSSet *states = [NSSet setWithArray:@[
        @"prepared", @"icon-written", @"plist-written", @"registered",
        @"file-overwritten", @"plist-overwritten", @"registration-applied",
        @"active", @"pending", @"restore-pending", @"restoring", @"restored",
    ]];
    BOOL fileValid = [file isKindOfClass:NSDictionary.class] &&
        ([(NSString *)file[@"mode"] isEqual:@"overwrite"] ||
         [(NSString *)file[@"mode"] isEqual:@"create"]) &&
        cnd_icon_is_safe_leaf(file[@"relativePath"]) &&
        [file[@"bundlePath"] isEqual:envelope[@"bundlePath"]] &&
        [file[@"targetPath"] isEqual:[envelope[@"bundlePath"]
            stringByAppendingPathComponent:file[@"relativePath"]]] &&
        [file[@"replacementHash"] isKindOfClass:NSString.class] &&
        [file[@"originalHash"] isKindOfClass:NSString.class] &&
        [file[@"originalData"] isKindOfClass:NSData.class];
    NSString *mode = file[@"mode"];
    NSData *originalData = file[@"originalData"];
    NSDictionary *originalMetadata = file[@"originalMetadata"];
    BOOL bytesValid = fileValid &&
        [file[@"replacementHash"] length] == CC_SHA256_DIGEST_LENGTH * 2 &&
        [file[@"originalHash"] length] == CC_SHA256_DIGEST_LENGTH * 2 &&
        [file[@"replacementLength"] unsignedLongLongValue] > 0 &&
        [file[@"replacementLength"] unsignedLongLongValue] <= 4 * 1024 * 1024 &&
        [cnd_icon_sha256(originalData) isEqual:file[@"originalHash"]] &&
        ([mode isEqual:@"create"]
            ? originalData.length == 0
            : ([originalMetadata isKindOfClass:NSDictionary.class] &&
               originalData.length ==
                   [originalMetadata[@"length"] unsignedLongLongValue] &&
               [file[@"replacementLength"] unsignedLongLongValue] ==
                   [originalMetadata[@"length"] unsignedLongLongValue]));
    NSDictionary *plist = envelope[@"plistMutation"];
    BOOL plistAbsent = plist == nil;
    BOOL plistDictionary = [plist isKindOfClass:NSDictionary.class];
    NSDictionary *plistOriginal = plistDictionary ? plist[@"originalDictionary"] : nil;
    NSDictionary *plistReplacement = plistDictionary ? plist[@"replacementDictionary"] : nil;
    NSData *plistOriginalData = plistDictionary ? plist[@"originalData"] : nil;
    NSDictionary *plistMetadata = plistDictionary ? plist[@"originalMetadata"] : nil;
    BOOL plistValid = plistAbsent || (
        [plist isKindOfClass:NSDictionary.class] &&
        [plist[@"mode"] isEqual:@"overwrite"] &&
        [((NSString *)plist[@"targetPath"]).pathExtension.lowercaseString isEqual:@"plist"] &&
        cnd_icon_path_is_strictly_beneath(plist[@"targetPath"],
                                          envelope[@"bundlePath"]) &&
        [plist[@"originalHash"] isKindOfClass:NSString.class] &&
        [plist[@"replacementHash"] isKindOfClass:NSString.class] &&
        [plist[@"replacementLength"] unsignedLongLongValue] > 0 &&
        [plist[@"replacementLength"] unsignedLongLongValue] <= 4 * 1024 * 1024 &&
        [plistOriginalData isKindOfClass:NSData.class] &&
        [plistMetadata isKindOfClass:NSDictionary.class] &&
        plistOriginalData.length == [plistMetadata[@"length"] unsignedLongLongValue] &&
        [plist[@"replacementLength"] unsignedLongLongValue] ==
            [plistMetadata[@"length"] unsignedLongLongValue] &&
        [cnd_icon_sha256(plistOriginalData) isEqual:plist[@"originalHash"]] &&
        [plistOriginal isKindOfClass:NSDictionary.class] &&
        [plistReplacement isKindOfClass:NSDictionary.class] &&
        cnd_icon_exact_plist_mutation(plistOriginal, plistReplacement) &&
        [plist[@"originalHash"] length] == CC_SHA256_DIGEST_LENGTH * 2 &&
        [plist[@"replacementHash"] length] == CC_SHA256_DIGEST_LENGTH * 2);
    if (version != CNDIconRedirectBackupVersion || !baseValid || !fileValid ||
        !bytesValid || !plistValid ||
        ![envelope[@"bundlePath"] isEqual:
            cnd_icon_canonical_path(registration[@"Path"])] ||
        ![states containsObject:envelope[@"transactionState"]] ||
        !cnd_icon_path_is_strictly_beneath(file[@"targetPath"],
                                           envelope[@"bundlePath"])) {
        if (errorOut) *errorOut = cnd_icon_error(41,
            @"the saved eBay icon recovery journal is invalid");
        return nil;
    }
    return envelope;
}

static NSDictionary *cnd_icon_target_selection_recipe(
    NSDictionary *target)
{
    if (![target isKindOfClass:NSDictionary.class]) return nil;
    NSArray *declaredFiles = [target[@"declaredFilesBefore"]
        isKindOfClass:NSArray.class] ? target[@"declaredFilesBefore"] : @[];
    NSArray *effectiveFiles = [target[@"effectiveDeclaredFiles"]
        isKindOfClass:NSArray.class] ? target[@"effectiveDeclaredFiles"] : @[];
    NSString *relativePath = [target[@"relativePath"] isKindOfClass:NSString.class]
        ? target[@"relativePath"] : nil;
    NSString *declaration = [target[@"declaredBaseName"] isKindOfClass:NSString.class]
        ? target[@"declaredBaseName"] : nil;
    if (relativePath.length == 0 || declaration.length == 0) return nil;
    return @{
        @"version": @(CNDIconRedirectTargetSelectionRecipeVersion),
        @"name": CNDIconRedirectTargetSelectionRecipeName,
        @"deviceScale": target[@"deviceScale"] ?: @0,
        @"selectedScale": target[@"scale"] ?: @0,
        @"selectedRelativePath": relativePath,
        @"selectedDeclaration": declaration,
        @"declaredFilesBefore": declaredFiles,
        @"effectiveDeclaredFiles": effectiveFiles,
        @"declaredFilesBeforePresent": target[@"declaredFilesBeforePresent"] ?: @NO,
        @"addsDeclaration": target[@"addsDeclaration"] ?: @NO,
    };
}

static BOOL cnd_icon_update_journal(NSDictionary **journalInOut,
                                    NSString *state,
                                    NSDictionary *fileUpdates,
                                    NSError **errorOut)
{
    NSMutableDictionary *journal = [*journalInOut mutableCopy];
    journal[@"transactionState"] = state;
    journal[@"updatedAt"] = [NSDate date];
    if (fileUpdates.count > 0) {
        NSMutableDictionary *file = [journal[@"fileMutation"] mutableCopy];
        [file addEntriesFromDictionary:fileUpdates];
        journal[@"fileMutation"] = file;
    }
    if (!cnd_icon_write_dictionary(journal, errorOut)) return NO;
    *journalInOut = journal;
    return YES;
}

static BOOL cnd_icon_write_stage(NSData *data, NSError **errorOut)
{
    NSURL *url = cnd_icon_stage_url();
    if (![[NSFileManager defaultManager]
            createDirectoryAtURL:url.URLByDeletingLastPathComponent
      withIntermediateDirectories:YES
                       attributes:@{NSFileProtectionKey: NSFileProtectionNone}
                            error:errorOut] ||
        ![data writeToURL:url options:NSDataWritingAtomic error:errorOut]) return NO;
    return [[NSFileManager defaultManager] setAttributes:@{
        NSFileProtectionKey: NSFileProtectionNone,
        NSFilePosixPermissions: @0600,
    } ofItemAtPath:url.path error:errorOut];
}

static BOOL cnd_icon_create_file(NSString *path, NSData *data,
                                 NSData **readbackOut,
                                 struct stat *statOut, NSError **errorOut)
{
    NSDictionary *creation =
        CNDLaunchServicesCreateAbsentBundleIconViaInstalld(path, data);
    if (![creation[@"ok"] boolValue]) {
        if (errorOut) *errorOut = cnd_icon_error(50,
            [NSString stringWithFormat:
                @"creating %@ through stock installd failed at %@: %@",
                path, creation[@"stage"] ?: @"unknown",
                creation[@"message"] ?: @"unknown failure"]);
        return NO;
    }
    NSData *readback = creation[@"data"];
    if (![readback isKindOfClass:NSData.class] ||
        ![readback isEqualToData:data]) {
        if (errorOut) *errorOut = cnd_icon_error(58,
            @"stock installd did not return the exact same-descriptor readback bytes");
        return NO;
    }
    struct stat st = {0};
    if (lstat(path.fileSystemRepresentation, &st) != 0 ||
        S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode)) {
        if (errorOut) *errorOut = cnd_icon_error(51,
            @"the installd-created icon is not a visible regular non-symlink file");
        return NO;
    }
    if (readbackOut) *readbackOut = readback;
    if (statOut) *statOut = st;
    return YES;
}

// Recovery has no retained creation descriptor. Prefer Cyanide's freshly
// consumed root file extension so recovery survives an installd restart, then
// fall back to stock installd for older environments where local access is
// still unavailable. Fresh apply verification reads back on the O_EXCL
// creation descriptor before close.
static BOOL cnd_icon_read_created_file(NSDictionary *file, NSData **dataOut,
                                       struct stat *statOut,
                                       NSError **errorOut)
{
    NSString *path = file[@"targetPath"];
    NSUInteger expectedLength =
        [file[@"replacementLength"] unsignedIntegerValue];
    NSDictionary *readback =
        CNDLaunchServicesReadBundleIconViaInstalld(path, expectedLength);
    NSData *data = readback[@"data"];
    if (![readback[@"ok"] boolValue] ||
        ![data isKindOfClass:NSData.class] ||
        data.length != expectedLength) {
        if (errorOut) *errorOut = cnd_icon_error(56,
            [NSString stringWithFormat:
                @"installd recovery readback failed at %@: %@ (expected=%llu observed=%lld read=%llu)",
                readback[@"stage"] ?: @"unknown",
                readback[@"message"] ?: @"unknown failure",
                (unsigned long long)expectedLength,
                [readback[@"observedLength"] longLongValue],
                [readback[@"bytesRead"] unsignedLongLongValue]]);
        return NO;
    }
    struct stat st = {0};
    if (lstat(path.fileSystemRepresentation, &st) != 0 ||
        S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode) ||
        st.st_size != (off_t)expectedLength) {
        if (errorOut) *errorOut = cnd_icon_error(57,
            @"the remotely verified recovery icon is not the expected visible regular file");
        return NO;
    }
    if (dataOut) *dataOut = data;
    if (statOut) *statOut = st;
    return YES;
}

static BOOL cnd_icon_read_recovery_file(NSDictionary *file, NSData **dataOut,
                                        struct stat *statOut,
                                        NSError **errorOut)
{
    NSString *path = file[@"targetPath"];
    NSError *localError = nil;
    if (cnd_icon_read_regular_file(path, dataOut, statOut, &localError)) {
        return YES;
    }
    if (![file[@"mode"] isEqual:@"create"]) {
        if (errorOut) *errorOut = localError;
        return NO;
    }

    if (dataOut) *dataOut = nil;
    if (statOut) memset(statOut, 0, sizeof(*statOut));
    NSError *remoteError = nil;
    if (cnd_icon_read_created_file(
            file, dataOut, statOut, &remoteError)) {
        return YES;
    }
    if (errorOut) *errorOut = cnd_icon_error(58,
        [NSString stringWithFormat:
            @"local recovery read failed: %@; installd recovery read failed: %@",
            localError.localizedDescription ?: @"unknown local failure",
            remoteError.localizedDescription ?: @"unknown remote failure"]);
    return NO;
}

static BOOL cnd_icon_remove_created_file(NSString *path, NSString **failureOut)
{
    if (unlink(path.fileSystemRepresentation) == 0) {
        struct stat remaining = {0};
        if (lstat(path.fileSystemRepresentation, &remaining) != 0 &&
            errno == ENOENT) {
            return YES;
        }
        if (failureOut) *failureOut =
            @"the locally removed transaction icon did not remain absent";
        return NO;
    }
    int localError = errno;

    NSDictionary *removal =
        CNDLaunchServicesRemoveCreatedBundleIconViaInstalld(path);
    BOOL ok = [removal[@"ok"] boolValue];
    if (!ok && failureOut) {
        *failureOut = [NSString stringWithFormat:
            @"local removal failed (%s); stock installd removal failed at %@: %@",
            strerror(localError),
            removal[@"stage"] ?: @"unknown",
            removal[@"message"] ?: @"unknown failure"];
    }
    if (!ok) return NO;

    struct stat remaining = {0};
    if (lstat(path.fileSystemRepresentation, &remaining) != 0 &&
        errno == ENOENT) {
        return YES;
    }
    if (failureOut) *failureOut =
        @"stock installd reported removal, but the transaction-created icon is still visible";
    return NO;
}

static BOOL cnd_icon_overwrite_existing_file(NSString *targetPath,
                                             NSData *contents)
{
    if (remote_call_lab_backend_opted_in()) {
        NSDictionary<NSString *, id> *result =
            CNDLaunchServicesOverwriteExistingBundleFileViaInstalld(
                targetPath, contents);
        return [result[@"ok"] boolValue];
    }
    return overwrite_system_file(
        (char *)targetPath.fileSystemRepresentation,
        (char *)cnd_icon_stage_url().path.fileSystemRepresentation) == 0;
}

static BOOL cnd_icon_apply_file(NSDictionary *file, NSData *replacement,
                                NSDictionary **metadataOut,
                                NSError **errorOut)
{
    NSString *targetPath = file[@"targetPath"];
    struct stat before = {0};
    NSData *readback = nil;
    if ([file[@"mode"] isEqual:@"overwrite"]) {
        NSData *current = nil;
        if (!cnd_icon_read_regular_file(targetPath, &current, &before, errorOut) ||
            ![cnd_icon_sha256(current) isEqual:file[@"originalHash"]] ||
            !cnd_icon_stat_matches(file[@"originalMetadata"], &before, YES)) {
            if (errorOut && !*errorOut) *errorOut = cnd_icon_error(52,
                @"the existing eBay icon changed after capture; refusing to overwrite it");
            return NO;
        }
        if (!cnd_icon_overwrite_existing_file(targetPath, replacement)) {
            if (errorOut) *errorOut = cnd_icon_error(53,
                @"overwrite_system_file() rejected the staged icon");
            return NO;
        }
    } else {
        if (!cnd_icon_create_file(targetPath, replacement, &readback,
                                  &before, errorOut)) {
            return NO;
        }
    }

    struct stat after = {0};
    NSError *readbackError = nil;
    BOOL overwriteMode = [file[@"mode"] isEqual:@"overwrite"];
    BOOL readbackOK = NO;
    if (overwriteMode) {
        readbackOK = cnd_icon_read_regular_file(
            targetPath, &readback, &after, &readbackError);
    } else {
        NSUInteger expectedLength =
            [file[@"replacementLength"] unsignedIntegerValue];
        if ([readback isKindOfClass:NSData.class] &&
            readback.length == expectedLength &&
            lstat(targetPath.fileSystemRepresentation, &after) == 0 &&
            !S_ISLNK(after.st_mode) && S_ISREG(after.st_mode) &&
            after.st_size == (off_t)expectedLength) {
            readbackOK = YES;
        } else {
            readbackError = cnd_icon_error(57,
                @"the same-descriptor installd readback did not match the visible created file");
        }
    }
    BOOL hashOK = readbackOK &&
        [cnd_icon_sha256(readback) isEqual:file[@"replacementHash"]];
    BOOL metadataOK = overwriteMode
        ? (readbackOK && cnd_icon_stat_matches(
            file[@"originalMetadata"], &after, YES))
        : (readbackOK && before.st_dev == after.st_dev &&
           before.st_ino == after.st_ino && before.st_uid == after.st_uid &&
           before.st_gid == after.st_gid &&
           (before.st_mode & 07777) == (after.st_mode & 07777) &&
           after.st_size == (off_t)replacement.length);
    if (!hashOK || !metadataOK) {
        // This is the immediate post-mutation failure path, where ownership of
        // the just-mutated vnode/file is still known. Restore now; the more
        // conservative crash-recovery path intentionally refuses unknown hashes.
        BOOL rollbackOK = NO;
        struct stat rollbackTarget = {0};
        if (lstat(targetPath.fileSystemRepresentation, &rollbackTarget) == 0 &&
            S_ISREG(rollbackTarget.st_mode) && !S_ISLNK(rollbackTarget.st_mode) &&
            rollbackTarget.st_dev == before.st_dev &&
            rollbackTarget.st_ino == before.st_ino) {
            if (overwriteMode) {
                NSError *rollbackStageError = nil;
                if (cnd_icon_write_stage(file[@"originalData"],
                                         &rollbackStageError)) {
                    rollbackOK = cnd_icon_overwrite_existing_file(
                        targetPath, file[@"originalData"]);
                }
            } else {
                rollbackOK = cnd_icon_remove_created_file(targetPath, NULL);
            }
        }
        NSString *verificationFailure = nil;
        if (!readbackOK) {
            verificationFailure = readbackError.localizedDescription ?:
                @"the target could not be read back";
        } else if (!hashOK) {
            verificationFailure = [NSString stringWithFormat:
                @"target hash mismatch (expected %@, observed %@, bytes=%llu)",
                file[@"replacementHash"] ?: @"",
                cnd_icon_sha256(readback) ?: @"",
                (unsigned long long)readback.length];
        } else {
            verificationFailure = @"target vnode metadata changed during verification";
        }
        if (errorOut) *errorOut = cnd_icon_error(
            metadataOK ? 54 : 55,
            [NSString stringWithFormat:@"%@; the immediate file rollback %@",
                verificationFailure,
                rollbackOK ? @"succeeded" : @"could not be verified"]);
        return NO;
    }
    if (metadataOut) *metadataOut = cnd_icon_stat_dictionary(&after);
    return YES;
}

static NSDictionary *cnd_icon_plist_object_from_data(NSData *data,
                                                     NSError **errorOut)
{
    NSError *error = nil;
    id value = [NSPropertyListSerialization propertyListWithData:data
        options:NSPropertyListImmutable format:nil error:&error];
    if (![value isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = cnd_icon_error(59,
            error.localizedDescription ?:
                @"the Info.plist readback is not a dictionary");
        return nil;
    }
    return value;
}

static BOOL cnd_icon_apply_plist(NSDictionary *plist, NSData *replacement,
                                 NSDictionary **metadataOut,
                                 NSError **errorOut)
{
    NSString *targetPath = plist[@"targetPath"];
    NSData *current = nil;
    struct stat before = {0};
    if (!cnd_icon_regular_leaf(targetPath, &before, NULL) ||
        !cnd_icon_read_regular_file(targetPath, &current, &before, errorOut) ||
        ![cnd_icon_sha256(current) isEqual:plist[@"originalHash"]] ||
        !cnd_icon_stat_matches(plist[@"originalMetadata"], &before, YES)) {
        if (errorOut && !*errorOut) *errorOut = cnd_icon_error(60,
            @"the actual eBay Info.plist changed after capture; refusing to overwrite it");
        return NO;
    }
    if (replacement.length != before.st_size ||
        replacement.length != [plist[@"replacementLength"] unsignedIntegerValue]) {
        if (errorOut) *errorOut = cnd_icon_error(61,
            @"the staged Info.plist does not occupy the exact original capacity");
        return NO;
    }
    if (!cnd_icon_overwrite_existing_file(targetPath, replacement)) {
        if (errorOut) *errorOut = cnd_icon_error(62,
            @"overwrite_system_file() rejected the staged Info.plist");
        return NO;
    }
    NSData *readback = nil;
    struct stat after = {0};
    NSError *readError = nil;
    BOOL readOK = cnd_icon_read_regular_file(targetPath, &readback, &after,
                                             &readError);
    NSDictionary *decoded = readOK
        ? cnd_icon_plist_object_from_data(readback, &readError) : nil;
    BOOL exact = readOK && readback.length == replacement.length &&
        [cnd_icon_sha256(readback) isEqual:plist[@"replacementHash"]] &&
        cnd_icon_stat_matches(plist[@"originalMetadata"], &after, YES) &&
        [decoded isEqual:plist[@"replacementDictionary"]];
    if (!exact) {
        if (errorOut) *errorOut = cnd_icon_error(63,
            readError.localizedDescription ?:
                @"the staged Info.plist failed exact byte/hash/vnode/object readback");
        return NO;
    }
    if (metadataOut) *metadataOut = cnd_icon_stat_dictionary(&after);
    return YES;
}

static BOOL cnd_icon_restore_plist(NSDictionary *plist, NSString **failureOut)
{
    if (![plist isKindOfClass:NSDictionary.class]) return YES;
    NSString *targetPath = plist[@"targetPath"];
    NSData *current = nil;
    struct stat currentStat = {0};
    NSError *readError = nil;
    if (!cnd_icon_read_regular_file(targetPath, &current, &currentStat,
                                    &readError)) {
        if (failureOut) *failureOut = readError.localizedDescription;
        return NO;
    }
    NSString *currentHash = cnd_icon_sha256(current);
    if ([currentHash isEqual:plist[@"originalHash"]]) {
        NSDictionary *decoded = cnd_icon_plist_object_from_data(current, NULL);
        BOOL ok = cnd_icon_recovery_stat_matches(plist[@"originalMetadata"],
                                                 &currentStat, YES) &&
            [decoded isEqual:plist[@"originalDictionary"]];
        if (!ok && failureOut) *failureOut =
            @"the original Info.plist bytes have changed metadata or object contents";
        return ok;
    }
    if (![currentHash isEqual:plist[@"replacementHash"]]) {
        if (failureOut) *failureOut =
            @"the Info.plist hash is neither the saved original nor this transaction's mutation";
        return NO;
    }
    if (!cnd_icon_recovery_stat_matches(plist[@"originalMetadata"],
                                        &currentStat, YES)) {
        if (failureOut) *failureOut =
            @"the mutated Info.plist is no longer on the captured vnode; refusing to overwrite replacement bytes";
        return NO;
    }
    NSData *original = plist[@"originalData"];
    if (![original isKindOfClass:NSData.class] ||
        original.length != [plist[@"originalMetadata"][@"length"] unsignedIntegerValue]) {
        if (failureOut) *failureOut = @"the saved original Info.plist bytes are invalid";
        return NO;
    }
    NSError *stageError = nil;
    if (!cnd_icon_write_stage(original, &stageError)) {
        if (failureOut) *failureOut = stageError.localizedDescription;
        return NO;
    }
    if (!cnd_icon_overwrite_existing_file(targetPath, original)) {
        if (failureOut) *failureOut =
            @"overwrite_system_file() could not restore the original Info.plist bytes";
        return NO;
    }
    NSData *readback = nil;
    struct stat restoredStat = {0};
    NSDictionary *decoded = nil;
    NSError *verifyError = nil;
    readback = nil;
    BOOL readOK = cnd_icon_read_regular_file(targetPath, &readback,
                                             &restoredStat, &verifyError);
    decoded = readOK ? cnd_icon_plist_object_from_data(readback, &verifyError)
                     : nil;
    if (!readOK || ![cnd_icon_sha256(readback) isEqual:plist[@"originalHash"]] ||
        !cnd_icon_recovery_stat_matches(plist[@"originalMetadata"],
                                        &restoredStat, YES) ||
        ![decoded isEqual:plist[@"originalDictionary"]]) {
        if (failureOut) *failureOut = verifyError.localizedDescription ?:
            @"the restored Info.plist failed exact hash/vnode/object verification";
        return NO;
    }
    return YES;
}

static BOOL cnd_icon_restore_file(NSDictionary *file, NSString **failureOut)
{
    NSString *targetPath = file[@"targetPath"];
    NSString *mode = file[@"mode"];
    struct stat pathStat = {0};
    if (lstat(targetPath.fileSystemRepresentation, &pathStat) != 0) {
        if (errno == ENOENT && [mode isEqual:@"create"]) return YES;
        if (failureOut) *failureOut = [NSString stringWithFormat:
            @"the saved eBay icon target is unavailable: %s", strerror(errno)];
        return NO;
    }
    if (S_ISLNK(pathStat.st_mode) || !S_ISREG(pathStat.st_mode)) {
        if (failureOut) *failureOut =
            @"the saved eBay icon target is no longer a regular non-symlink file";
        return NO;
    }
    NSData *current = nil;
    struct stat currentStat = {0};
    NSError *readError = nil;
    BOOL readOK = cnd_icon_read_recovery_file(
        file, &current, &currentStat, &readError);
    if (!readOK) {
        if ([mode isEqual:@"create"] &&
            cnd_icon_created_leaf_matches_journal_identity(file, &pathStat)) {
            if (!cnd_icon_remove_created_file(targetPath, failureOut)) {
                return NO;
            }
            return YES;
        }
        if (failureOut) *failureOut = readError.localizedDescription;
        return NO;
    }
    NSString *currentHash = cnd_icon_sha256(current);
    if ([mode isEqual:@"create"]) {
        if (![currentHash isEqual:file[@"replacementHash"]]) {
            if (failureOut) *failureOut =
                @"the created icon has an unknown hash; refusing to remove it";
            return NO;
        }
        NSDictionary *createdMetadata = file[@"createdMetadata"];
        if ([createdMetadata[@"inode"] unsignedLongLongValue] != 0 &&
            !cnd_icon_recovery_stat_matches(createdMetadata, &currentStat,
                                            YES)) {
            if (failureOut) *failureOut =
                @"the created icon vnode identity changed; refusing to remove it";
            return NO;
        }
        if (!cnd_icon_remove_created_file(targetPath, failureOut)) {
            return NO;
        }
        return YES;
    }

    if ([currentHash isEqual:file[@"originalHash"]]) {
        return cnd_icon_recovery_stat_matches(file[@"originalMetadata"],
                                              &currentStat, YES);
    }
    if (![currentHash isEqual:file[@"replacementHash"]]) {
        if (failureOut) *failureOut =
            @"the eBay icon hash is neither the saved original nor this transaction's theme; refusing to overwrite it";
        return NO;
    }
    if (!cnd_icon_recovery_stat_matches(file[@"originalMetadata"],
                                        &currentStat, YES)) {
        if (failureOut) *failureOut =
            @"the mutated eBay icon is no longer on the captured vnode; refusing to overwrite replacement bytes";
        return NO;
    }
    NSData *original = file[@"originalData"];
    NSError *stageError = nil;
    if (!cnd_icon_write_stage(original, &stageError)) {
        if (failureOut) *failureOut = stageError.localizedDescription;
        return NO;
    }
    if (!cnd_icon_overwrite_existing_file(targetPath, original)) {
        if (failureOut) *failureOut =
            @"overwrite_system_file() could not restore the original icon bytes";
        return NO;
    }
    NSData *readback = nil;
    struct stat restoredStat = {0};
    NSError *verifyError = nil;
    if (!cnd_icon_read_regular_file(targetPath, &readback, &restoredStat,
                                    &verifyError) ||
        ![cnd_icon_sha256(readback) isEqual:file[@"originalHash"]] ||
        !cnd_icon_recovery_stat_matches(file[@"originalMetadata"],
                                        &restoredStat, YES)) {
        if (failureOut) *failureOut = verifyError.localizedDescription ?:
            @"the restored eBay icon failed exact hash/vnode verification";
        return NO;
    }
    return YES;
}

static BOOL cnd_icon_recovery_target_is_known(NSDictionary *file,
                                               NSString **stateOut,
                                               NSString **failureOut)
{
    NSString *targetPath = file[@"targetPath"];
    NSString *mode = file[@"mode"];
    struct stat pathStat = {0};
    if (lstat(targetPath.fileSystemRepresentation, &pathStat) != 0) {
        if (errno == ENOENT && [mode isEqual:@"create"]) {
            if (stateOut) *stateOut = @"missing-created-file";
            return YES;
        }
        if (failureOut) *failureOut = [NSString stringWithFormat:
            @"the saved icon target is unavailable: %s", strerror(errno)];
        return NO;
    }
    if (S_ISLNK(pathStat.st_mode) || !S_ISREG(pathStat.st_mode)) {
        if (failureOut) *failureOut =
            @"the saved icon target is no longer a regular non-symlink file";
        return NO;
    }
    NSData *current = nil;
    struct stat currentStat = {0};
    NSError *readError = nil;
    BOOL readOK = cnd_icon_read_recovery_file(
        file, &current, &currentStat, &readError);
    if (!readOK) {
        if ([mode isEqual:@"create"] &&
            cnd_icon_created_leaf_matches_journal_identity(file, &pathStat)) {
            if (stateOut) *stateOut =
                @"replacement-created-identity-unreadable";
            return YES;
        }
        if (failureOut) *failureOut = readError.localizedDescription;
        return NO;
    }
    NSString *hash = cnd_icon_sha256(current);
    if ([mode isEqual:@"overwrite"] &&
        [hash isEqual:file[@"originalHash"]] &&
        cnd_icon_recovery_stat_matches(file[@"originalMetadata"],
                                       &currentStat, YES)) {
        if (stateOut) *stateOut = @"original";
        return YES;
    }
    if ([hash isEqual:file[@"replacementHash"]]) {
        NSDictionary *metadata = [mode isEqual:@"create"]
            ? file[@"createdMetadata"] : file[@"originalMetadata"];
        BOOL requireMetadata = [mode isEqual:@"overwrite"] ||
            [metadata[@"inode"] unsignedLongLongValue] != 0;
        if (!requireMetadata ||
            cnd_icon_recovery_stat_matches(metadata, &currentStat, YES)) {
            if (stateOut) *stateOut = @"replacement";
            return YES;
        }
    }
    if (failureOut) *failureOut =
        @"the saved icon path has an unknown hash or vnode identity; refusing to submit stale registration or mutate it";
    return NO;
}

static BOOL cnd_icon_recovery_plist_is_known(NSDictionary *plist,
                                             NSString **stateOut,
                                             NSString **failureOut)
{
    if (![plist isKindOfClass:NSDictionary.class]) return YES;
    NSString *path = plist[@"targetPath"];
    NSData *current = nil;
    struct stat currentStat = {0};
    NSError *readError = nil;
    if (!cnd_icon_read_regular_file(path, &current, &currentStat,
                                    &readError)) {
        if (failureOut) *failureOut = readError.localizedDescription;
        return NO;
    }
    NSString *hash = cnd_icon_sha256(current);
    if ([hash isEqual:plist[@"originalHash"]] &&
        cnd_icon_recovery_stat_matches(plist[@"originalMetadata"],
                                       &currentStat, YES) &&
        [cnd_icon_plist_object_from_data(current, NULL)
            isEqual:plist[@"originalDictionary"]]) {
        if (stateOut) *stateOut = @"original";
        return YES;
    }
    if ([hash isEqual:plist[@"replacementHash"]] &&
        cnd_icon_recovery_stat_matches(plist[@"originalMetadata"],
                                       &currentStat, YES) &&
        [cnd_icon_plist_object_from_data(current, NULL)
            isEqual:plist[@"replacementDictionary"]]) {
        if (stateOut) *stateOut = @"replacement";
        return YES;
    }
    if (failureOut) *failureOut =
        @"the saved Info.plist has an unknown hash, vnode identity, or dictionary; refusing stale recovery";
    return NO;
}

static BOOL cnd_icon_same_saved_install(NSDictionary *original,
                                        NSDictionary *current)
{
    for (NSString *key in @[
        @"CFBundleVersion", @"CFBundleShortVersionString", @"CFBundleExecutable"
    ]) {
        id savedValue = original[key];
        id currentValue = current[key];
        if (!((savedValue == nil && currentValue == nil) ||
              [savedValue isEqual:currentValue])) return NO;
    }
    return YES;
}

// Procursus uicache -p does not pass the bundle's Info.plist keys back to
// LaunchServices. It supplies only registration identity/container metadata
// (and equivalent metadata for each plug-in), which makes LaunchServices read
// the current on-disk Info.plist. Keep this deliberately separate from the
// complete proxy dictionary used for capture and effective-record readback.
static NSDictionary *cnd_icon_uicache_registration_component(
    NSDictionary *source, BOOL isPlugin, NSString **failureOut)
{
    if (![source isKindOfClass:NSDictionary.class]) {
        if (failureOut) *failureOut =
            @"the captured registration component is not a dictionary";
        return nil;
    }

    NSArray<NSString *> *keys = isPlugin ? @[
        @"Entitlements", @"ApplicationType", @"CFBundleIdentifier",
        @"CodeInfoIdentifier", @"CompatibilityState", @"IsContainerized",
        @"Container", @"EnvironmentVariables", @"Path",
        @"PluginOwnerBundleID", @"SignerOrganization", @"SignatureVersion",
        @"SignerIdentity", @"TeamIdentifier", @"HasAppGroupContainers",
        @"HasSystemGroupContainers", @"GroupContainers",
    ] : @[
        @"Entitlements", @"ApplicationType", @"BundleNameIsLocalized",
        @"CFBundleIdentifier", @"CodeInfoIdentifier", @"CompatibilityState",
        @"IsContainerized", @"Container", @"EnvironmentVariables",
        @"IsDeletable", @"Path", @"SignerOrganization",
        @"SignatureVersion", @"SignerIdentity", @"IsAdHocSigned",
        @"LSInstallType", @"HasMIDBasedSINF", @"MissingSINF", @"FamilyID",
        @"IsOnDemandInstallCapable", @"TeamIdentifier",
        @"HasAppGroupContainers", @"HasSystemGroupContainers",
        @"GroupContainers",
    ];
    NSMutableDictionary *registration = [NSMutableDictionary dictionary];
    for (NSString *key in keys) {
        id value = source[key];
        if (value != nil) registration[key] = value;
    }

    NSString *identifier = registration[@"CFBundleIdentifier"];
    NSString *path = registration[@"Path"];
    NSString *applicationType = registration[@"ApplicationType"];
    NSDictionary *entitlements = registration[@"Entitlements"];
    if (![identifier isKindOfClass:NSString.class] || identifier.length == 0 ||
        ![path isKindOfClass:NSString.class] || path.length == 0 ||
        ![applicationType isKindOfClass:NSString.class] ||
        applicationType.length == 0 ||
        ![entitlements isKindOfClass:NSDictionary.class]) {
        if (failureOut) *failureOut = [NSString stringWithFormat:
            @"the captured %@ registration lacks uicache-required identity metadata",
            isPlugin ? @"plug-in" : @"application"];
        return nil;
    }

    if (!isPlugin) {
        NSDictionary *sourcePlugins = source[@"_LSBundlePlugins"];
        if (sourcePlugins != nil &&
            ![sourcePlugins isKindOfClass:NSDictionary.class]) {
            if (failureOut) *failureOut =
                @"the captured LaunchServices plug-in map is malformed";
            return nil;
        }
        NSMutableDictionary *plugins = [NSMutableDictionary dictionary];
        __block NSString *pluginEnumerationFailure = nil;
        [(sourcePlugins ?: @{}) enumerateKeysAndObjectsUsingBlock:
            ^(id key, id value, BOOL *stop) {
                if (*stop) return;
                if (![key isKindOfClass:NSString.class] ||
                    [(NSString *)key length] == 0) {
                    pluginEnumerationFailure =
                        @"the captured LaunchServices plug-in identifier is invalid";
                    *stop = YES;
                    return;
                }
                NSString *pluginFailure = nil;
                NSDictionary *plugin =
                    cnd_icon_uicache_registration_component(
                        value, YES, &pluginFailure);
                if (!plugin ||
                    ![plugin[@"CFBundleIdentifier"] isEqual:key]) {
                    pluginEnumerationFailure = pluginFailure ?:
                        @"a captured plug-in registration changed identity";
                    *stop = YES;
                    return;
                }
                plugins[key] = plugin;
            }];
        if (pluginEnumerationFailure) {
            if (failureOut) *failureOut = pluginEnumerationFailure;
            return nil;
        }
        registration[@"_LSBundlePlugins"] = plugins;
    }

    if (registration[@"CFBundleIcons"] != nil ||
        registration[@"CFBundleIcons~ipad"] != nil ||
        !cnd_icon_is_plist(registration)) {
        if (failureOut) *failureOut =
            @"the targeted registration dictionary retained bundle declaration keys or is not a property list";
        return nil;
    }
    return registration;
}

static NSDictionary *cnd_icon_uicache_registration_dictionary(
    NSDictionary *source, NSString **failureOut)
{
    NSDictionary *registration =
        cnd_icon_uicache_registration_component(source, NO, failureOut);
    if (registration &&
        (![registration[@"CFBundleIdentifier"]
            isEqual:cnd_icon_target_bundle_identifier()] ||
         ![cnd_icon_canonical_path(registration[@"Path"])
            isEqual:cnd_icon_canonical_path(source[@"Path"])])) {
        if (failureOut) *failureOut =
            @"the targeted registration dictionary changed eBay's identity or path";
        return nil;
    }
    return registration;
}

static BOOL cnd_icon_effective_registration_matches(
    NSDictionary *capture, NSDictionary *file, NSString **failureOut)
{
    if (![capture isKindOfClass:NSDictionary.class] ||
        ![file isKindOfClass:NSDictionary.class]) {
        if (failureOut) *failureOut = @"post-registration LaunchServices recapture failed";
        return NO;
    }
    NSDictionary *effective = capture[@"registrationDictionary"];
    if (![capture[@"ok"] boolValue] ||
        ![effective isKindOfClass:NSDictionary.class] ||
        ![effective[@"CFBundleIdentifier"]
            isEqual:cnd_icon_target_bundle_identifier()] ||
        ![cnd_icon_canonical_path(effective[@"Path"])
            isEqual:cnd_icon_canonical_path(file[@"bundlePath"])]) {
        if (failureOut) *failureOut = @"post-registration LaunchServices recapture failed";
        return NO;
    }
    NSDictionary *primary = cnd_icon_primary_dictionary(effective);
    if (![primary isKindOfClass:NSDictionary.class]) {
        if (failureOut) *failureOut = @"post-registration LaunchServices primary icon record is malformed";
        return NO;
    }
    if (primary[@"CFBundleIconName"] != nil) {
        if (failureOut) *failureOut =
            @"post-registration LaunchServices still exposes phone CFBundleIconName";
        return NO;
    }
    NSArray *expectedFiles = file[@"declaredFilesAfter"] ?:
        file[@"declaredFilesBefore"];
    id observedFiles = primary[@"CFBundleIconFiles"];
    BOOL expectedFilesPresent = expectedFiles.count > 0;
    BOOL filesMatch = expectedFilesPresent
        ? ([expectedFiles isKindOfClass:NSArray.class] &&
           [observedFiles isEqual:expectedFiles])
        : (observedFiles == nil);
    if (!filesMatch) {
        if (failureOut) *failureOut = [NSString stringWithFormat:
            @"post-registration CFBundleIconFiles differs from the expected phone declaration (expected=%@ observed=%@)",
            expectedFilesPresent ? (expectedFiles ?: @[]) : @"<absent>",
            observedFiles ?: @"<absent>"];
        return NO;
    }
    return YES;
}

static BOOL cnd_icon_effective_registration_matches_original(
    NSDictionary *capture, NSString *bundlePath, NSDictionary *plist,
    NSString **failureOut)
{
    if (![capture isKindOfClass:NSDictionary.class] ||
        ![plist isKindOfClass:NSDictionary.class]) {
        if (failureOut) *failureOut =
            @"post-restore LaunchServices recapture was unavailable";
        return NO;
    }
    NSDictionary *effective = capture[@"registrationDictionary"];
    if (![capture[@"ok"] boolValue] ||
        ![effective isKindOfClass:NSDictionary.class] ||
        ![effective[@"CFBundleIdentifier"]
            isEqual:cnd_icon_target_bundle_identifier()] ||
        ![cnd_icon_canonical_path(effective[@"Path"])
            isEqual:cnd_icon_canonical_path(bundlePath)]) {
        if (failureOut) *failureOut =
            @"post-restore LaunchServices recapture failed or identified the wrong bundle";
        return NO;
    }

    NSDictionary *original = plist[@"originalDictionary"];
    NSDictionary *expectedPrimary = cnd_icon_primary_dictionary(original);
    NSDictionary *observedPrimary = cnd_icon_primary_dictionary(effective);
    if (![expectedPrimary isKindOfClass:NSDictionary.class] ||
        ![observedPrimary isKindOfClass:NSDictionary.class]) {
        if (failureOut) *failureOut =
            @"post-restore LaunchServices primary icon record is malformed";
        return NO;
    }

    id expectedIconName = expectedPrimary[@"CFBundleIconName"];
    id observedIconName = observedPrimary[@"CFBundleIconName"];
    BOOL iconNameMatches = expectedIconName == nil
        ? observedIconName == nil
        : ([expectedIconName isKindOfClass:NSString.class] &&
           [(NSString *)expectedIconName length] > 0 &&
           [observedIconName isEqual:expectedIconName]);
    if (!iconNameMatches) {
        if (failureOut) *failureOut =
            @"post-restore LaunchServices did not recover the original phone CFBundleIconName";
        return NO;
    }

    id expectedFiles = expectedPrimary[@"CFBundleIconFiles"];
    id observedFiles = observedPrimary[@"CFBundleIconFiles"];
    BOOL filesMatch = expectedFiles != nil
        ? [observedFiles isEqual:expectedFiles] : observedFiles == nil;
    if (!filesMatch) {
        if (failureOut) *failureOut = [NSString stringWithFormat:
            @"post-restore LaunchServices CFBundleIconFiles differs from the saved phone declaration (expected=%@ observed=%@)",
            expectedFiles ?: @"<absent>", observedFiles ?: @"<absent>"];
        return NO;
    }
    return YES;
}

static NSDictionary *cnd_icon_try_local_journal_cleanup(NSDictionary *saved)
{
    NSString *state = saved[@"transactionState"];
    NSString *restoreOrigin = saved[@"restoreOriginState"];
    NSDictionary *file = saved[@"fileMutation"];
    NSDictionary *createdMetadata = file[@"createdMetadata"];
    BOOL alreadyRestored = [state isEqual:@"restored"];
    // Version-2 journals written before restoreOriginState existed can only be
    // classified as prepared-origin when create mode never acquired recorded
    // vnode metadata. A successful file apply persists createdMetadata before
    // registration is attempted.
    BOOL legacyPreparedRestore = [state isEqual:@"restoring"] &&
        ![restoreOrigin isKindOfClass:NSString.class] &&
        [file[@"mode"] isEqual:@"create"] &&
        [createdMetadata[@"inode"] unsignedLongLongValue] == 0;
    BOOL preparedOrigin = [state isEqual:@"prepared"] ||
        ([state isEqual:@"restoring"] && [restoreOrigin isEqual:@"prepared"]) ||
        legacyPreparedRestore;
    if (!alreadyRestored && !preparedOrigin) return nil;

    NSString *recoveryFileState = @"journal-restored";
    if (preparedOrigin) {
        NSString *mode = file[@"mode"];
        NSString *targetPath = file[@"targetPath"];
        if ([mode isEqual:@"create"]) {
            struct stat st = {0};
            if (lstat(targetPath.fileSystemRepresentation, &st) == 0 ||
                errno != ENOENT) return nil;
            recoveryFileState = @"missing-created-file";
        } else if ([mode isEqual:@"overwrite"]) {
            NSData *current = nil;
            struct stat currentStat = {0};
            if (!cnd_icon_read_regular_file(targetPath, &current,
                                             &currentStat, NULL) ||
                ![cnd_icon_sha256(current) isEqual:file[@"originalHash"]] ||
                !cnd_icon_recovery_stat_matches(file[@"originalMetadata"],
                                                &currentStat, YES)) return nil;
            recoveryFileState = @"original";
        } else {
            return nil;
        }
        NSDictionary *plist = saved[@"plistMutation"];
        if (plist) {
            NSString *plistState = nil;
            if (!cnd_icon_recovery_plist_is_known(plist, &plistState, NULL) ||
                ![plistState isEqual:@"original"]) return nil;
        }
    }

    NSDictionary *journal = saved;
    NSError *cleanupError = nil;
    if (!alreadyRestored &&
        !cnd_icon_update_journal(&journal, @"restored", nil,
                                 &cleanupError)) {
        return cnd_icon_result(NO, @"local-recovery-journal",
            cleanupError.localizedDescription ?:
                @"the locally verified recovery journal could not be finalized",
            @{
                @"registrationSkipped": @YES,
                @"fileRestored": @YES,
                @"recoveryFileState": recoveryFileState,
            });
    }

    BOOL removed = [NSFileManager.defaultManager
        removeItemAtURL:cnd_icon_backup_url() error:&cleanupError];
    BOOL journalAbsent = !CNDIconDeclarationRedirectIsActive();
    [NSFileManager.defaultManager removeItemAtURL:cnd_icon_stage_url()
                                             error:nil];
    BOOL ok = removed || journalAbsent;
    return cnd_icon_result(ok,
        ok ? @"restored-local-noop" : @"local-recovery-cleanup",
        ok
            ? @"the prepared transaction had no surviving external mutation; its journal was cleared locally"
            : (cleanupError.localizedDescription ?:
               @"the locally restored journal could not be removed"),
        @{
            @"registrationSkipped": @YES,
            @"fileRestored": @YES,
            @"iconCacheInvalidationIssued": @NO,
            @"recoveryFileState": recoveryFileState,
            @"cleanupError": ok ? @"" :
                (cleanupError.localizedDescription ?: @"unknown cleanup failure"),
        });
}

static NSDictionary *cnd_icon_restore_v2(NSDictionary *saved,
                                          NSDictionary *currentIdentity)
{
    NSDictionary *original = saved[@"registrationDictionary"];
    NSDictionary *file = saved[@"fileMutation"];
    NSString *savedBundle = saved[@"bundlePath"];
    NSString *targetedRegistrationFailure = nil;
    NSDictionary *targetedRegistration =
        cnd_icon_uicache_registration_dictionary(
            original, &targetedRegistrationFailure);
    if (!targetedRegistration) {
        return cnd_icon_result(NO, @"restore-targeted-registration",
            targetedRegistrationFailure ?:
                @"the saved identity cannot produce a targeted uicache-style registration",
            nil);
    }
    NSDictionary *currentRegistration = currentIdentity[@"registrationDictionary"];
    NSString *currentBundle = cnd_icon_canonical_path(currentRegistration[@"Path"]);
    if (![currentIdentity[@"ok"] boolValue] || currentBundle.length == 0 ||
        ![currentBundle isEqual:savedBundle] ||
        !cnd_icon_same_saved_install(original, currentRegistration)) {
        return cnd_icon_result(NO, @"restore-bundle-changed",
            @"eBay's installed bundle path or version changed; refusing to submit stale registration or touch the saved path",
            @{@"identity": currentIdentity ?: @{}});
    }

    NSString *recoveryFileState = nil;
    NSString *preflightFailure = nil;
    if (!cnd_icon_recovery_target_is_known(
            file, &recoveryFileState, &preflightFailure)) {
        return cnd_icon_result(NO, @"restore-file-drift",
            preflightFailure, @{
                @"identity": currentIdentity,
                @"targetPath": file[@"targetPath"] ?: @"",
            });
    }
    NSDictionary *plist = saved[@"plistMutation"];
    NSString *recoveryPlistState = nil;
    if (!cnd_icon_recovery_plist_is_known(
            plist, &recoveryPlistState, &preflightFailure)) {
        return cnd_icon_result(NO, @"restore-plist-drift",
            preflightFailure, @{
                @"identity": currentIdentity,
                @"targetPath": plist[@"targetPath"] ?: @"",
            });
    }

    NSMutableDictionary *journalWithOrigin = [saved mutableCopy];
    if (![journalWithOrigin[@"restoreOriginState"] isKindOfClass:NSString.class]) {
        journalWithOrigin[@"restoreOriginState"] =
            saved[@"transactionState"] ?: @"unknown";
    }
    NSDictionary *journal = journalWithOrigin;
    NSError *journalError = nil;
    if (!cnd_icon_update_journal(&journal, @"restoring", nil,
                                 &journalError)) {
        return cnd_icon_result(NO, @"restore-journal",
            journalError.localizedDescription, nil);
    }

    NSString *plistFailure = nil;
    BOOL plistOK = cnd_icon_restore_plist(plist, &plistFailure);
    NSString *fileFailure = nil;
    BOOL fileOK = cnd_icon_restore_file(file, &fileFailure);
    NSDictionary *registration =
        CNDLaunchServicesRegisterViaInstalld(targetedRegistration);
    NSDictionary *captureSessionFinalization =
        CNDLaunchServicesFinishRetainedInstalldSession();
    BOOL registrationOK = cnd_icon_registration_succeeded(registration);
    BOOL remixSkipsEffectiveRegistrationReadback =
        gCNDIconRedirectOverrideJournalURL != nil;
    BOOL effectiveRegistrationRequired =
        [plist isKindOfClass:NSDictionary.class] &&
        !remixSkipsEffectiveRegistrationReadback;
    NSDictionary *effectiveRegistration = @{};
    NSString *effectiveRegistrationFailure = nil;
    NSDictionary *effectiveRegistrationSessionFinalization = nil;
    BOOL effectiveRegistrationVerified = NO;
    BOOL effectiveRegistrationOK = !effectiveRegistrationRequired && registrationOK;
    if (registrationOK && effectiveRegistrationRequired) {
        effectiveRegistration =
            CNDLaunchServicesCopyRegistrationDictionaryForBundleIdentifierRetainingSession(
                cnd_icon_target_bundle_identifier());
        effectiveRegistrationSessionFinalization =
            CNDLaunchServicesFinishRetainedInstalldSession();
        BOOL recaptureSessionOK =
            [effectiveRegistrationSessionFinalization[@"ok"] boolValue];
        effectiveRegistrationVerified =
            cnd_icon_effective_registration_matches_original(
                effectiveRegistration, savedBundle, plist,
                &effectiveRegistrationFailure) && recaptureSessionOK;
        effectiveRegistrationOK = effectiveRegistrationVerified;
        if (!recaptureSessionOK && effectiveRegistrationVerified == NO &&
            effectiveRegistrationFailure.length == 0) {
            effectiveRegistrationFailure =
                @"post-restore LaunchServices recapture session did not close cleanly";
        }
    } else {
        effectiveRegistrationSessionFinalization =
            CNDLaunchServicesFinishRetainedInstalldSession();
        if (effectiveRegistrationRequired) {
            effectiveRegistrationFailure = registrationOK
                ? @"post-restore LaunchServices recapture was skipped because stock registration was not accepted"
                : @"post-restore LaunchServices record was not checked because stock registration failed";
        } else {
            effectiveRegistrationFailure = remixSkipsEffectiveRegistrationReadback
                ? @"SnowBoard Remix post-registration LaunchServices recapture was disabled"
                : @"legacy v2 journal had no on-disk Info.plist snapshot; persisted icon declaration verification was skipped";
        }
    }
    NSString *cacheFailure = nil;
    BOOL cacheOK = cnd_icon_invalidate_iconservices_cache(&cacheFailure);
    NSDictionary *sessionFinalization =
        CNDLaunchServicesFinishRetainedInstalldSession();
    BOOL sessionOK = [sessionFinalization[@"ok"] boolValue];
    BOOL restored = registrationOK && fileOK && plistOK && cacheOK &&
        sessionOK && effectiveRegistrationOK;

    NSError *cleanupError = nil;
    BOOL removed = NO;
    BOOL batchSessionPending = restored &&
        CNDLaunchServicesBatchInstalldSessionIsHealthy();
    if (restored && cnd_icon_update_journal(
            &journal, batchSessionPending ? @"restore-pending" : @"restored",
            batchSessionPending ? @{ @"batchCommitState": @"pending" } : nil,
            &cleanupError)) {
        removed = batchSessionPending || [NSFileManager.defaultManager
            removeItemAtURL:cnd_icon_backup_url() error:&cleanupError];
    }
    [[NSFileManager defaultManager] removeItemAtURL:cnd_icon_stage_url()
                                              error:nil];
    restored = restored && removed;
    NSString *stage = restored ?
        (batchSessionPending ? @"restore-pending" : @"restored") :
        (!fileOK ? @"restore-file" :
         (!plistOK ? @"restore-plist" :
          (!registrationOK ? @"restore-registration" :
           (!effectiveRegistrationOK ? @"restore-effective-registration" :
            (!cacheOK ? @"restore-cache-invalidation" :
             (!sessionOK ? @"restore-session-finalization" :
              @"restore-backup-cleanup"))))));
    NSString *message = restored
        ? (batchSessionPending
            ? @"the original eBay files and registration were verified; journal cleanup is pending shared installd batch finalization"
            : @"eBay's stock bundle registration and exact original Info.plist/icon bytes and vnode identities were restored; IconServices invalidation was issued")
        : (!fileOK ? (fileFailure ?: @"the original eBay icon could not be restored")
            : (!plistOK ? (plistFailure ?: @"the original Info.plist could not be restored")
                : (!registrationOK
                    ? @"the original files were restored, but stock installd did not accept the saved eBay registration"
                    : (!effectiveRegistrationOK
                        ? (effectiveRegistrationFailure ?: @"the restored LaunchServices record could not be verified")
                        : (!cacheOK ? (cacheFailure ?: @"IconServices invalidation failed")
                         : (!sessionOK
                            ? (sessionFinalization[@"message"] ?:
                               @"the retained installd session did not close cleanly")
                            : (cleanupError.localizedDescription ?:
                               @"the completed recovery journal could not be removed")))))));
    return cnd_icon_result(restored, stage, message, @{
        @"registration": registration ?: @{},
        @"captureSessionFinalization": captureSessionFinalization ?: @{},
        @"fileRestored": @(fileOK),
        @"fileFailure": fileFailure ?: @"",
        @"infoRestored": @(plistOK),
        @"infoFailure": plistFailure ?: @"",
        @"iconCacheInvalidationIssued": @(cacheOK),
        @"installdSessionFinalization": sessionFinalization ?: @{},
        @"effectiveRegistration": effectiveRegistration ?: @{},
        @"effectiveRegistrationVerified": @(effectiveRegistrationVerified),
        @"effectiveRegistrationFailure": effectiveRegistrationFailure ?: @"",
        @"effectiveRegistrationSessionFinalization":
            effectiveRegistrationSessionFinalization ?: @{},
        @"effectiveRegistrationVerificationSkipped":
            @(!effectiveRegistrationRequired),
        @"cleanupError": cleanupError.localizedDescription ?: @"",
        @"batchSessionPending": @(batchSessionPending),
        @"batchCommitState": batchSessionPending ? @"pending" : @"committed",
        @"targetPath": file[@"targetPath"] ?: @"",
        @"originalHash": file[@"originalHash"] ?: @"",
        @"infoTargetPath": plist[@"targetPath"] ?: @"",
        @"infoOriginalHash": plist[@"originalHash"] ?: @"",
        @"infoOriginalLength": plist[@"originalMetadata"][@"length"] ?: @0,
        @"infoReplacementLength": plist[@"replacementLength"] ?: @0,
        @"infoReplacementHash": plist[@"replacementHash"] ?: @"",
        @"recoveryFileState": recoveryFileState ?: @"unknown",
        @"recoveryInfoState": recoveryPlistState ?: @"not-journaled",
    });
}

NSDictionary<NSString *, id> *CNDIconDeclarationRedirectApply(void)
{
    if (!__sync_bool_compare_and_swap(&gOperationRunning, 0, 1)) {
        return cnd_icon_result(NO, @"operation-active",
            @"another eBay icon operation is running", nil);
    }
    NSDictionary *answer = nil;
    @try {
        if (!remote_call_lab_backend_opted_in() && !kexploit_krw_ready()) {
            answer = cnd_icon_result(NO, @"krw-prerequisite",
                @"live kernel read/write is required before the icon proof", nil);
        } else if (CNDIconDeclarationRedirectIsActive()) {
            answer = cnd_icon_result(NO, @"restore-required",
                @"a saved eBay transaction exists; restore it before another proof", nil);
        } else {
            NSDictionary *identity =
                CNDLaunchServicesCopyRegistrationDictionaryForBundleIdentifierRetainingSession(
                    cnd_icon_target_bundle_identifier());
            NSDictionary *original = identity[@"registrationDictionary"];
            NSString *targetedRegistrationFailure = nil;
            NSDictionary *targetedRegistration =
                cnd_icon_uicache_registration_dictionary(
                    original, &targetedRegistrationFailure);
            NSString *bundlePath = nil;
            NSString *boundaryFailure = nil;
            if (![identity[@"ok"] boolValue] ||
                ![original isKindOfClass:NSDictionary.class]) {
                answer = cnd_icon_result(NO, @"identity",
                    @"kslop could not capture a complete stock eBay identity",
                    @{@"identity": identity ?: @{}});
            } else if (!targetedRegistration) {
                answer = cnd_icon_result(NO, @"targeted-registration",
                    targetedRegistrationFailure ?:
                        @"kslop could not construct the targeted uicache-style registration",
                    @{@"identity": identity});
            } else {
                cnd_icon_prepare_bundle_access();
                if (!cnd_icon_validate_bundle(
                        original, &bundlePath, &boundaryFailure)) {
                    answer = cnd_icon_result(NO, @"identity-boundary",
                        boundaryFailure, @{@"identity": identity});
                } else {
                    NSString *payloadPath = [NSBundle.mainBundle
                        pathForResource:CNDIconRedirectPayloadName ofType:@"png"];
                    NSData *payloadData = gCNDIconRedirectOverrideSourcePNGData ?:
                        (payloadPath.length > 0
                            ? [NSData dataWithContentsOfFile:payloadPath] : nil);
                    UIImage *payload = payloadData.length > 0
                        ? [UIImage imageWithData:payloadData] : nil;
                    if (payload.CGImage == nil ||
                        (!gCNDIconRedirectOverrideSourcePNGData &&
                         ![cnd_icon_sha256(payloadData)
                            isEqual:CNDIconRedirectPayloadSHA256])) {
                        answer = cnd_icon_result(NO, @"theme",
                            @"the bundled payload is not the exact requested kslop theme PNG",
                            @{@"payloadHash": cnd_icon_sha256(payloadData) ?: @""});
                    } else {
                        NSError *discoveryError = nil;
                        NSMutableDictionary *discoveredPlist =
                            [cnd_icon_discover_plist(bundlePath, &discoveryError)
                                mutableCopy];
                        NSMutableDictionary *discovered = discoveredPlist
                            ? [cnd_icon_discover_target(
                                discoveredPlist[@"originalDictionary"],
                                bundlePath,
                                payload.CGImage ? CGImageGetWidth(payload.CGImage) : 0,
                                payload.CGImage ? CGImageGetHeight(payload.CGImage) : 0,
                                &discoveryError) mutableCopy]
                            : nil;
                        if (discoveredPlist && discovered) {
                            NSArray *beforeFiles = discovered[@"declaredFilesBefore"];
                            discovered[@"declaredFilesAfter"] = beforeFiles.count > 0
                                ? beforeFiles : @[discovered[@"declaredBaseName"]];
                            NSDictionary *replacementDictionary =
                                cnd_icon_plist_replacement_for_target(
                                    discoveredPlist[@"originalDictionary"],
                                    discovered, &discoveryError);
                            if (replacementDictionary) {
                                discoveredPlist[@"replacementDictionary"] =
                                    replacementDictionary;
                            } else {
                                discoveredPlist = nil;
                            }
                        }
                        NSUInteger capacity = [discovered[@"mode"] isEqual:@"overwrite"]
                            ? [discovered[@"originalMetadata"][@"length"]
                                unsignedIntegerValue] : 0;
                        NSError *renderError = nil;
                        NSDictionary *processing = nil;
                        NSData *replacement = discovered ? cnd_icon_render_payload(
                            payloadData, [discovered[@"width"] unsignedIntegerValue],
                            [discovered[@"height"] unsignedIntegerValue],
                            capacity, &processing, &renderError) : nil;
                        if (discovered && processing) {
                            discovered[@"processing"] = processing;
                        }
                        NSUInteger plistCapacity = [discoveredPlist[@"originalMetadata"]
                            [@"length"] unsignedIntegerValue];
                        NSError *plistRenderError = nil;
                        NSData *plistReplacement = discoveredPlist
                            ? cnd_icon_render_plist(
                                discoveredPlist[@"originalData"],
                                discoveredPlist[@"originalDictionary"],
                                discoveredPlist[@"replacementDictionary"],
                                plistCapacity, &plistRenderError) : nil;
                        if (!discovered || !replacement || !discoveredPlist ||
                            !plistReplacement) {
                            NSError *failure = discoveryError ?:
                                (renderError ?: plistRenderError);
                            NSString *failureStage = !discovered || !discoveredPlist
                                ? @"target-discovery"
                                : (!replacement ? @"icon-fit"
                                   : (!plistReplacement ? @"plist-fit"
                                      : @"theme-fit"));
                            NSMutableDictionary *diagnostic = [NSMutableDictionary
                                dictionaryWithDictionary:@{
                                    @"discoveryMode": discovered
                                        ? (discovered[@"mode"] ?: @"unknown")
                                        : @"unresolved",
                                    @"chosenBase": discovered[@"declaredBaseName"] ?: @"",
                                    @"chosenLeaf": discovered[@"relativePath"] ?: @"",
                                    @"targetWidth": discovered[@"width"] ?: @0,
                                    @"targetHeight": discovered[@"height"] ?: @0,
                                    @"dimensionsSource": discovered[@"dimensionsSource"] ?: @"",
                                    @"plistFit": plistReplacement
                                        ? @"fit" : (discoveredPlist ? @"no-fit" : @"not-run"),
                                    @"plistOriginalBytes": discoveredPlist[
                                        @"originalMetadata"][@"length"] ?: @0,
                                    @"plistReplacementBytes": plistReplacement
                                        ? @(plistReplacement.length) : @0,
                                    @"creationResult": (discovered &&
                                        [discovered[@"mode"] isEqual:@"create"])
                                        ? @"not-run" : @"not-applicable",
                                    @"registrationResult": @"not-run",
                                    @"rollbackReason": @"not-started",
                                }];
                            diagnostic[@"reason"] = failure.localizedDescription ?: @"preflight failed";
                            answer = cnd_icon_result(NO,
                                failureStage,
                                failure.localizedDescription ?:
                                    @"the theme source or target preflight failed",
                                @{@"identity": identity,
                                  @"remixDiagnostic": diagnostic});
                        } else {
                            NSMutableDictionary *file = [discovered mutableCopy];
                            file[@"replacementHash"] = cnd_icon_sha256(replacement);
                            file[@"replacementLength"] = @(replacement.length);
                            NSMutableDictionary *plist = [discoveredPlist mutableCopy];
                            plist[@"mode"] = @"overwrite";
                            plist[@"replacementHash"] = cnd_icon_sha256(plistReplacement);
                            plist[@"replacementLength"] = @(plistReplacement.length);
                            if (!cnd_icon_exact_plist_mutation(
                                    plist[@"originalDictionary"],
                                    plist[@"replacementDictionary"]) ||
                                !cnd_icon_is_plist(
                                    plist[@"replacementDictionary"])) {
                                answer = cnd_icon_result(NO, @"registration-guard",
                                    @"the exact on-disk phone-primary Info.plist mutation guard failed",
                                    @{@"identity": identity});
                            } else {
                                NSDictionary *journal = @{
                                    @"version": @(CNDIconRedirectBackupVersion),
                                    @"bundleIdentifier": cnd_icon_target_bundle_identifier(),
                                    @"bundlePath": bundlePath,
                                    @"capturedAt": [NSDate date],
                                    @"updatedAt": [NSDate date],
                                    @"transactionState": @"prepared",
                                    @"registrationDictionary": original,
                                    @"fileMutation": file,
                                    @"plistMutation": plist,
                                    @"targetSelectionRecipe":
                                        cnd_icon_target_selection_recipe(discovered) ?: @{},
                                    @"targetSelectionRecipeVersion":
                                        @(CNDIconRedirectTargetSelectionRecipeVersion),
                                };
                                NSError *journalError = nil;
                                if (!cnd_icon_write_dictionary(journal,
                                                               &journalError)) {
                                    answer = cnd_icon_result(NO, @"backup",
                                        journalError.localizedDescription,
                                        @{@"identity": identity});
                                } else {
                                    NSError *stageError = nil;
                                    BOOL plistStageOK =
                                        cnd_icon_stage_plist_verified(
                                            plistReplacement,
                                            plist[@"replacementDictionary"],
                                            &stageError);
                                    BOOL iconStageOK = plistStageOK &&
                                        cnd_icon_write_stage(replacement,
                                                             &stageError);
                                    if (!plistStageOK || !iconStageOK) {
                                        [NSFileManager.defaultManager
                                            removeItemAtURL:cnd_icon_backup_url()
                                            error:nil];
                                        answer = cnd_icon_result(NO,
                                            plistStageOK ? @"icon-stage" : @"plist-stage",
                                            stageError.localizedDescription ?:
                                                @"the staged mutation failed preflight verification",
                                            @{ @"identity": identity,
                                               @"infoTargetPath": plist[@"targetPath"] ?: @"",
                                               @"infoOriginalLength": plist[@"originalMetadata"][@"length"] ?: @0,
                                               @"infoReplacementLength": plist[@"replacementLength"] ?: @0,
                                               @"infoOriginalHash": plist[@"originalHash"] ?: @"",
                                               @"infoReplacementHash": plist[@"replacementHash"] ?: @"",
                                               @"transactionState": journal[@"transactionState"] ?: @"prepared"});
                                    } else {
                                    NSDictionary *createdMetadata = nil;
                                    NSError *fileError = nil;
                                    BOOL fileOK = cnd_icon_apply_file(
                                        file, replacement, &createdMetadata,
                                        &fileError);
                                    if (!fileOK) {
                                        NSString *rollbackFailure = nil;
                                        BOOL rollbackOK = cnd_icon_restore_file(
                                            file, &rollbackFailure);
                                        NSString *infoRollbackFailure = nil;
                                        BOOL infoRollbackOK =
                                            cnd_icon_restore_plist(
                                                plist, &infoRollbackFailure);
                                        rollbackOK = rollbackOK && infoRollbackOK;
                                        answer = cnd_icon_result(NO, @"file-apply",
                                            fileError.localizedDescription,
                                            @{
                                                @"identity": identity,
                                                @"targetPath": file[@"targetPath"],
                                                @"fileMode": file[@"mode"],
                                                @"declaredBaseName": file[@"declaredBaseName"],
                                                @"relativePath": file[@"relativePath"] ?: @"",
                                                @"dimensionsSource": file[@"dimensionsSource"] ?: @"",
                                                @"width": file[@"width"],
                                                @"height": file[@"height"],
                                                @"originalLength": file[@"originalMetadata"][@"length"] ?: @0,
                                                @"replacementLength": file[@"replacementLength"],
                                                @"originalHash": file[@"originalHash"],
                                                @"replacementHash": file[@"replacementHash"],
                                                @"infoTargetPath": plist[@"targetPath"],
                                                @"infoOriginalLength": plist[@"originalMetadata"][@"length"] ?: @0,
                                                @"infoReplacementLength": plist[@"replacementLength"] ?: @0,
                                                @"infoOriginalHash": plist[@"originalHash"],
                                                @"infoReplacementHash": plist[@"replacementHash"],
                                                @"transactionState": journal[@"transactionState"],
                                                @"fileRollbackSucceeded": @(rollbackOK),
                                                @"fileRollbackFailure": rollbackFailure ?: @"",
                                                @"infoRollbackSucceeded": @(infoRollbackOK),
                                                @"infoRollbackFailure": infoRollbackFailure ?: @"",
                                                @"cleanupPreparedJournalAfterFinalization": @(rollbackOK),
                                            });
                                    } else if (!cnd_icon_update_journal(
                                            &journal, @"icon-written",
                                            @{@"createdMetadata":
                                                createdMetadata ?: @{}},
                                            &journalError)) {
                                        NSString *iconRollbackFailure = nil;
                                        BOOL iconRollbackOK =
                                            cnd_icon_restore_file(
                                                file, &iconRollbackFailure);
                                        NSString *infoRollbackFailure = nil;
                                        BOOL infoRollbackOK =
                                            cnd_icon_restore_plist(
                                                plist, &infoRollbackFailure);
                                        NSString *cacheFailure = nil;
                                        BOOL cacheOK =
                                            cnd_icon_invalidate_iconservices_cache(
                                                &cacheFailure);
                                        BOOL rollbackOK = iconRollbackOK &&
                                            infoRollbackOK && cacheOK;
                                        answer = cnd_icon_result(NO,
                                            @"journal-after-file",
                                            journalError.localizedDescription,
                                            @{@"targetPath": file[@"targetPath"],
                                              @"fileMode": file[@"mode"],
                                              @"originalLength": file[@"originalMetadata"][@"length"] ?: @0,
                                              @"replacementLength": file[@"replacementLength"] ?: @0,
                                              @"originalHash": file[@"originalHash"] ?: @"",
                                              @"replacementHash": file[@"replacementHash"] ?: @"",
                                              @"infoTargetPath": plist[@"targetPath"] ?: @"",
                                              @"infoOriginalLength": plist[@"originalMetadata"][@"length"] ?: @0,
                                              @"infoReplacementLength": plist[@"replacementLength"] ?: @0,
                                              @"infoOriginalHash": plist[@"originalHash"] ?: @"",
                                              @"infoReplacementHash": plist[@"replacementHash"] ?: @"",
                                              @"transactionState": journal[@"transactionState"] ?: @"prepared",
                                              @"fileRollbackSucceeded": @(iconRollbackOK),
                                              @"fileRollbackFailure": iconRollbackFailure ?: @"",
                                              @"infoRollbackSucceeded": @(infoRollbackOK),
                                              @"infoRollbackFailure": infoRollbackFailure ?: @"",
                                              @"iconCacheInvalidationIssued": @(cacheOK),
                                              @"cleanupPreparedJournalAfterFinalization": @(rollbackOK)});
                                    } else {
                                        file = [journal[@"fileMutation"] mutableCopy];
                                        NSError *plistError = nil;
                                        BOOL plistStageOK =
                                            cnd_icon_stage_plist_verified(
                                                plistReplacement,
                                                plist[@"replacementDictionary"],
                                                &plistError);
                                        NSDictionary *plistMetadata = nil;
                                        BOOL plistOK = plistStageOK &&
                                            cnd_icon_apply_plist(
                                                plist, plistReplacement,
                                                &plistMetadata, &plistError);
                                        if (!plistOK) {
                                            NSString *iconRollbackFailure = nil;
                                            BOOL iconRollbackOK =
                                                cnd_icon_restore_file(
                                                    file, &iconRollbackFailure);
                                            NSString *infoRollbackFailure = nil;
                                            BOOL infoRollbackOK =
                                                cnd_icon_restore_plist(
                                                    plist, &infoRollbackFailure);
                                            NSString *cacheFailure = nil;
                                            BOOL cacheOK =
                                                cnd_icon_invalidate_iconservices_cache(
                                                    &cacheFailure);
                                            BOOL rollbackOK = iconRollbackOK &&
                                                infoRollbackOK && cacheOK;
                                            if (rollbackOK &&
                                                cnd_icon_update_journal(
                                                    &journal, @"restored", nil,
                                                    &journalError)) {
                                                [NSFileManager.defaultManager
                                                    removeItemAtURL:cnd_icon_backup_url()
                                                    error:&journalError];
                                            }
                                            answer = cnd_icon_result(NO,
                                                @"plist-apply",
                                                plistError.localizedDescription ?:
                                                    @"the Info.plist mutation failed",
                                                @{
                                                    @"identity": identity,
                                                    @"targetPath": file[@"targetPath"],
                                                    @"fileMode": file[@"mode"],
                                                    @"relativePath": file[@"relativePath"] ?: @"",
                                                    @"declaredBaseName": file[@"declaredBaseName"] ?: @"",
                                                    @"dimensionsSource": file[@"dimensionsSource"] ?: @"",
                                                    @"originalLength": file[@"originalMetadata"][@"length"] ?: @0,
                                                    @"replacementLength": file[@"replacementLength"] ?: @0,
                                                    @"originalHash": file[@"originalHash"] ?: @"",
                                                    @"replacementHash": file[@"replacementHash"] ?: @"",
                                                    @"infoTargetPath": plist[@"targetPath"],
                                                    @"infoOriginalLength": plist[@"originalMetadata"][@"length"] ?: @0,
                                                    @"infoReplacementLength": plist[@"replacementLength"] ?: @0,
                                                    @"infoOriginalHash": plist[@"originalHash"],
                                                    @"infoReplacementHash": plist[@"replacementHash"],
                                                    @"transactionState": journal[@"transactionState"],
                                                    @"infoRollbackSucceeded": @(infoRollbackOK),
                                                    @"infoRollbackFailure": infoRollbackFailure ?: @"",
                                                    @"fileRollbackSucceeded": @(iconRollbackOK),
                                                    @"fileRollbackFailure": iconRollbackFailure ?: @"",
                                                    @"iconCacheInvalidationIssued": @(cacheOK),
                                                    @"cleanupPreparedJournalAfterFinalization": @(rollbackOK),
                                                });
                                        } else if (!cnd_icon_update_journal(
                                                &journal, @"plist-written",
                                                nil, &journalError)) {
                                            NSString *iconRollbackFailure = nil;
                                            BOOL iconRollbackOK =
                                                cnd_icon_restore_file(
                                                    file, &iconRollbackFailure);
                                            NSString *infoRollbackFailure = nil;
                                            BOOL infoRollbackOK =
                                                cnd_icon_restore_plist(
                                                    plist, &infoRollbackFailure);
                                            BOOL rollbackOK = iconRollbackOK &&
                                                infoRollbackOK;
                                            answer = cnd_icon_result(NO,
                                                @"journal-after-plist",
                                                journalError.localizedDescription,
                                                @{
                                                    @"targetPath": file[@"targetPath"],
                                                    @"fileMode": file[@"mode"],
                                                    @"originalLength": file[@"originalMetadata"][@"length"] ?: @0,
                                                    @"replacementLength": file[@"replacementLength"] ?: @0,
                                                    @"originalHash": file[@"originalHash"] ?: @"",
                                                    @"replacementHash": file[@"replacementHash"] ?: @"",
                                                    @"infoTargetPath": plist[@"targetPath"],
                                                    @"infoOriginalLength": plist[@"originalMetadata"][@"length"] ?: @0,
                                                    @"infoReplacementLength": plist[@"replacementLength"] ?: @0,
                                                    @"infoOriginalHash": plist[@"originalHash"],
                                                    @"infoReplacementHash": plist[@"replacementHash"],
                                                    @"transactionState": journal[@"transactionState"],
                                                    @"infoRollbackSucceeded": @(infoRollbackOK),
                                                    @"infoRollbackFailure": infoRollbackFailure ?: @"",
                                                    @"fileRollbackSucceeded": @(iconRollbackOK),
                                                    @"fileRollbackFailure": iconRollbackFailure ?: @"",
                                                    @"cleanupPreparedJournalAfterFinalization": @(rollbackOK),
                                                });
                                        } else {
                                        NSDictionary *registration =
                                            CNDLaunchServicesRegisterViaInstalld(
                                                targetedRegistration);
                                        NSDictionary *registrationSessionFinalization =
                                            CNDLaunchServicesFinishRetainedInstalldSession();
                                        NSDictionary *effectiveIdentity = nil;
                                        NSString *effectiveFailure = nil;
                                        NSDictionary *effectiveSessionFinalization = nil;
                                        BOOL registrationAccepted =
                                            cnd_icon_registration_succeeded(registration);
                                        BOOL remixSkipsEffectiveRegistrationReadback =
                                            gCNDIconRedirectOverrideJournalURL != nil;
                                        BOOL effectiveOK =
                                            remixSkipsEffectiveRegistrationReadback &&
                                            registrationAccepted &&
                                            [registrationSessionFinalization[@"ok"] boolValue];
                                        BOOL effectiveSessionOK = YES;
                                        if (registrationAccepted &&
                                            [registrationSessionFinalization[@"ok"] boolValue] &&
                                            !remixSkipsEffectiveRegistrationReadback) {
                                            effectiveIdentity =
                                                CNDLaunchServicesCopyRegistrationDictionaryForBundleIdentifierRetainingSession(
                                                    cnd_icon_target_bundle_identifier());
                                            effectiveOK =
                                                cnd_icon_effective_registration_matches(
                                                    effectiveIdentity, file,
                                                    &effectiveFailure);
                                            effectiveSessionFinalization =
                                                CNDLaunchServicesFinishRetainedInstalldSession();
                                            effectiveSessionOK =
                                                [effectiveSessionFinalization[@"ok"] boolValue];
                                            if (!effectiveSessionOK) {
                                                effectiveOK = NO;
                                                if (effectiveFailure.length == 0) {
                                                    effectiveFailure =
                                                        @"the effective LaunchServices recapture session did not close cleanly";
                                                }
                                            }
                                        } else if (remixSkipsEffectiveRegistrationReadback &&
                                                   registrationAccepted &&
                                                   [registrationSessionFinalization[@"ok"] boolValue]) {
                                            effectiveFailure =
                                                @"SnowBoard Remix post-registration LaunchServices recapture was disabled";
                                            effectiveSessionFinalization =
                                                registrationSessionFinalization;
                                        } else {
                                            effectiveFailure =
                                                @"the registration session did not finalize cleanly; effective LaunchServices readback was skipped";
                                            effectiveSessionFinalization =
                                                CNDLaunchServicesFinishRetainedInstalldSession();
                                            effectiveSessionOK =
                                                [effectiveSessionFinalization[@"ok"] boolValue];
                                        }
                                        if (!registrationAccepted || !effectiveOK) {
                                            NSString *fileRollbackFailure = nil;
                                            BOOL fileRollbackOK =
                                                cnd_icon_restore_file(file,
                                                    &fileRollbackFailure);
                                            NSString *infoRollbackFailure = nil;
                                            BOOL infoRollbackOK =
                                                cnd_icon_restore_plist(
                                                    plist, &infoRollbackFailure);
                                            NSDictionary *rollback =
                                                (fileRollbackOK && infoRollbackOK && effectiveSessionOK)
                                                    ? CNDLaunchServicesRegisterViaInstalld(
                                                        targetedRegistration)
                                                    : @{};
                                            BOOL registrationRollbackOK =
                                                cnd_icon_registration_succeeded(rollback);
                                            NSString *cacheFailure = nil;
                                            BOOL cacheOK =
                                                cnd_icon_invalidate_iconservices_cache(
                                                    &cacheFailure);
                                            BOOL rollbackOK = registrationRollbackOK &&
                                                fileRollbackOK && infoRollbackOK &&
                                                effectiveSessionOK && cacheOK;
                                            if (rollbackOK && cnd_icon_update_journal(
                                                    &journal, @"restored", nil,
                                                    &journalError)) {
                                                [NSFileManager.defaultManager
                                                    removeItemAtURL:cnd_icon_backup_url()
                                                    error:&journalError];
                                            }
                                            answer = cnd_icon_result(NO,
                                                @"registration",
                                                rollbackOK
                                                    ? (registrationAccepted
                                                        ? @"the effective LaunchServices readback failed; both stock registration and original files were restored"
                                                        : @"the targeted registration failed; both stock registration and original files were restored")
                                                    : @"the targeted registration or effective readback failed and recovery remains pending",
                                                @{
                                                    @"registration": registration ?: @{},
                                                    @"rollback": rollback ?: @{},
                                                    @"effectiveRegistration": effectiveIdentity ?: @{},
                                                    @"effectiveRegistrationVerified": @(effectiveOK),
                                                    @"effectiveRegistrationVerificationSkipped":
                                                        @(remixSkipsEffectiveRegistrationReadback),
                                                    @"effectiveRegistrationFailure": effectiveFailure ?: @"",
                                                    @"effectiveRegistrationSessionFinalization": effectiveSessionFinalization ?: @{},
                                                    @"registrationSessionFinalization": registrationSessionFinalization ?: @{},
                                                    @"fileRollbackSucceeded": @(fileRollbackOK),
                                                    @"fileRollbackFailure": fileRollbackFailure ?: @"",
                                                    @"infoRollbackSucceeded": @(infoRollbackOK),
                                                    @"infoRollbackFailure": infoRollbackFailure ?: @"",
                                                    @"iconCacheInvalidationIssued": @(cacheOK),
                                                    @"targetPath": file[@"targetPath"],
                                                    @"fileMode": file[@"mode"],
                                                    @"declaredBaseName": file[@"declaredBaseName"],
                                                    @"relativePath": file[@"relativePath"] ?: @"",
                                                    @"dimensionsSource": file[@"dimensionsSource"] ?: @"",
                                                    @"width": file[@"width"],
                                                    @"height": file[@"height"],
                                                    @"originalLength": file[@"originalMetadata"][@"length"] ?: @0,
                                                    @"replacementLength": file[@"replacementLength"],
                                                    @"originalHash": file[@"originalHash"],
                                                    @"replacementHash": file[@"replacementHash"],
                                                    @"infoTargetPath": plist[@"targetPath"],
                                                    @"infoOriginalLength": plist[@"originalMetadata"][@"length"] ?: @0,
                                                    @"infoReplacementLength": plist[@"replacementLength"],
                                                    @"infoOriginalHash": plist[@"originalHash"],
                                                    @"infoReplacementHash": plist[@"replacementHash"],
                                                    @"transactionState": journal[@"transactionState"],
                                                });
                                        } else {
                                            BOOL journalOK = cnd_icon_update_journal(
                                                &journal, @"registered",
                                                nil, &journalError);
                                            NSString *cacheFailure = nil;
                                            BOOL cacheOK =
                                                cnd_icon_invalidate_iconservices_cache(
                                                    &cacheFailure);
                                            NSDictionary *canonicalVerification =
                                                (journalOK && cacheOK)
                                                    ? cnd_icon_verify_canonical_resolution(
                                                        cnd_icon_target_bundle_identifier())
                                                    : @{};
                                            BOOL batchSessionPending =
                                                journalOK && cacheOK &&
                                                CNDLaunchServicesBatchInstalldSessionIsHealthy();
                                            if (journalOK && cacheOK) {
                                                NSMutableDictionary *commitDetails =
                                                    [NSMutableDictionary dictionaryWithObject:
                                                        canonicalVerification ?: @{}
                                                        forKey:@"canonicalIconServicesVerification"];
                                                if (batchSessionPending) {
                                                    commitDetails[@"batchCommitState"] = @"pending";
                                                }
                                                journalOK = cnd_icon_update_journal(
                                                    &journal,
                                                    batchSessionPending
                                                        ? @"pending" : @"active",
                                                    commitDetails,
                                                    &journalError);
                                            }
                                            BOOL ok = journalOK && cacheOK;
                                            NSDictionary *rollback = nil;
                                            BOOL rollbackFileOK = NO;
                                            BOOL rollbackInfoOK = NO;
                                            BOOL rollbackRegistrationOK = NO;
                                            BOOL rollbackCacheOK = NO;
                                            if (!ok) {
                                                (void)CNDLaunchServicesFinishRetainedInstalldSession();
                                                NSString *rollbackFileFailure = nil;
                                                rollbackFileOK = cnd_icon_restore_file(
                                                    file, &rollbackFileFailure);
                                                NSString *rollbackInfoFailure = nil;
                                                rollbackInfoOK = cnd_icon_restore_plist(
                                                    plist, &rollbackInfoFailure);
                                                rollback = (rollbackFileOK && rollbackInfoOK)
                                                    ? CNDLaunchServicesRegisterViaInstalld(
                                                        targetedRegistration) : @{};
                                                rollbackRegistrationOK =
                                                    cnd_icon_registration_succeeded(rollback);
                                                NSString *rollbackCacheFailure = nil;
                                                rollbackCacheOK =
                                                    cnd_icon_invalidate_iconservices_cache(
                                                        &rollbackCacheFailure);
                                                BOOL rollbackOK = rollbackFileOK &&
                                                    rollbackInfoOK &&
                                                    rollbackRegistrationOK &&
                                                    rollbackCacheOK;
                                                if (rollbackOK &&
                                                    cnd_icon_update_journal(
                                                        &journal, @"restored", nil,
                                                        &journalError)) {
                                                    [NSFileManager.defaultManager
                                                        removeItemAtURL:cnd_icon_backup_url()
                                                        error:&journalError];
                                                    if (CNDIconDeclarationRedirectIsActive()) {
                                                        rollbackOK = NO;
                                                    }
                                                }
                                                if (rollbackOK) {
                                                    ok = NO;
                                                }
                                            }
                                            answer = cnd_icon_result(ok,
                                                ok ? (batchSessionPending
                                                    ? @"pending" : @"active") :
                                                    (!journalOK ? @"journal-after-registration" :
                                                     @"icon-cache-invalidation"),
                                                ok
                                                    ? (batchSessionPending
                                                        ? @"the icon and Info.plist vnodes, registration, and cache invalidation succeeded; activation is pending shared installd batch finalization"
                                                        : @"the icon and Info.plist vnodes, exact readback dictionaries, targeted uicache-style registration, and cache invalidation all succeeded")
                                                    : (journalError.localizedDescription ?:
                                                       cacheFailure ?:
                                                       canonicalVerification[@"message"] ?:
                                                       @"activation verification failed"),
                                                @{
                                                    @"identity": identity,
                                                    @"registration": registration,
                                                    @"effectiveRegistration": effectiveIdentity ?: @{},
                                                    @"effectiveRegistrationVerified": @(effectiveOK),
                                                    @"effectiveRegistrationVerificationSkipped":
                                                        @(remixSkipsEffectiveRegistrationReadback),
                                                    @"effectiveRegistrationFailure": effectiveFailure ?: @"",
                                                    @"effectiveRegistrationSessionFinalization": effectiveSessionFinalization ?: @{},
                                                    @"registrationSessionFinalization": registrationSessionFinalization ?: @{},
                                                    @"rollback": rollback ?: @{},
                                                    @"fileRollbackSucceeded": @(rollbackFileOK),
                                                    @"infoRollbackSucceeded": @(rollbackInfoOK),
                                                    @"rollbackRegistrationSucceeded": @(rollbackRegistrationOK),
                                                    @"rollbackCacheInvalidationIssued": @(rollbackCacheOK),
                                                    @"targetPath": file[@"targetPath"],
                                                    @"fileMode": file[@"mode"],
                                                    @"declaredBaseName": file[@"declaredBaseName"],
                                                    @"width": file[@"width"],
                                                    @"height": file[@"height"],
                                                    @"originalLength": file[@"originalMetadata"][@"length"] ?: @0,
                                                    @"replacementLength": file[@"replacementLength"],
                                                    @"originalHash": file[@"originalHash"],
                                                    @"replacementHash": file[@"replacementHash"],
                                                    @"infoTargetPath": plist[@"targetPath"],
                                                    @"infoOriginalLength": plist[@"originalMetadata"][@"length"],
                                                    @"infoReplacementLength": plist[@"replacementLength"],
                                                    @"infoOriginalHash": plist[@"originalHash"],
                                                    @"infoReplacementHash": plist[@"replacementHash"],
                                                    @"iconCacheInvalidationIssued": @(cacheOK),
                                                    @"canonicalIconServicesVerification": canonicalVerification,
                                                    @"batchSessionPending": @(batchSessionPending),
                                                    @"batchCommitState": batchSessionPending
                                                        ? @"pending" : @"committed",
                                                    @"transactionState": journal[@"transactionState"],
                                                });
                                        }
                                        }
                                    }
                                    [NSFileManager.defaultManager
                                        removeItemAtURL:cnd_icon_stage_url()
                                        error:nil];
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } @catch (NSException *exception) {
        answer = cnd_icon_result(NO, @"exception",
            @"the eBay icon proof raised an Objective-C exception",
            @{@"exception": exception.description ?: @"unknown"});
    } @finally {
        NSDictionary *sessionFinalization =
            CNDLaunchServicesFinishRetainedInstalldSession();
        if (answer) {
            NSMutableDictionary *withFinalization = [answer mutableCopy];
            withFinalization[@"installdSessionFinalization"] =
                sessionFinalization ?: @{};
            BOOL cleanupPreparedJournal =
                [withFinalization[@"cleanupPreparedJournalAfterFinalization"]
                    boolValue];
            [withFinalization
                removeObjectForKey:@"cleanupPreparedJournalAfterFinalization"];
            if (cleanupPreparedJournal &&
                [sessionFinalization[@"ok"] boolValue]) {
                NSError *cleanupError = nil;
                BOOL removed = [NSFileManager.defaultManager
                    removeItemAtURL:cnd_icon_backup_url()
                             error:&cleanupError];
                if (!removed && CNDIconDeclarationRedirectIsActive()) {
                    withFinalization[@"journalCleanupFailure"] =
                        cleanupError.localizedDescription ?:
                            @"the restored prepared journal could not be removed";
                }
            }
            if ([answer[@"ok"] boolValue] &&
                ![sessionFinalization[@"ok"] boolValue]) {
                withFinalization[@"ok"] = @NO;
                withFinalization[@"stage"] = @"installd-session-finalization";
                withFinalization[@"message"] =
                    @"the icon transaction completed, but its retained installd RemoteCall session did not close cleanly; recovery remains active";
                withFinalization[@"active"] =
                    @(CNDIconDeclarationRedirectIsActive());
            }
            withFinalization[@"active"] =
                @(CNDIconDeclarationRedirectIsActive());
            answer = withFinalization;
        }
        __sync_lock_release(&gOperationRunning);
    }
    return answer ?: cnd_icon_result(NO, @"unknown",
        @"the eBay icon proof ended without a result", nil);
}

NSDictionary<NSString *, id> *CNDIconDeclarationRedirectRestore(void)
{
    if (!__sync_bool_compare_and_swap(&gOperationRunning, 0, 1)) {
        return cnd_icon_result(NO, @"operation-active",
            @"another eBay icon operation is running", nil);
    }
    NSDictionary *answer = nil;
    @try {
        NSError *backupError = nil;
        NSDictionary *backup = cnd_icon_read_backup(&backupError);
        NSDictionary *original = backup[@"registrationDictionary"];
        if (!original) {
            answer = cnd_icon_result(NO, @"backup-missing",
                backupError.localizedDescription ?:
                    @"no valid saved eBay recovery transaction exists", nil);
        } else {
            NSDictionary *localCleanup =
                [backup[@"version"] unsignedIntegerValue] ==
                    CNDIconRedirectBackupVersion
                ? cnd_icon_try_local_journal_cleanup(backup) : nil;
            if (localCleanup) {
                answer = localCleanup;
            } else if (!remote_call_lab_backend_opted_in() &&
                       !kexploit_krw_ready()) {
                answer = cnd_icon_result(NO, @"krw-prerequisite",
                    @"live kernel read/write is required before recovery", nil);
            } else if ([backup[@"version"] unsignedIntegerValue] == 1) {
                NSDictionary *currentIdentity =
                    CNDLaunchServicesCopyRegistrationDictionaryForBundleIdentifierRetainingSession(
                        cnd_icon_target_bundle_identifier());
                NSDictionary *currentRegistration =
                    currentIdentity[@"registrationDictionary"];
                NSString *savedPath = cnd_icon_canonical_path(original[@"Path"]);
                NSString *currentPath = cnd_icon_canonical_path(
                    currentRegistration[@"Path"]);
                if (![currentIdentity[@"ok"] boolValue] ||
                    ![savedPath isEqual:currentPath] ||
                    !cnd_icon_same_saved_install(original, currentRegistration)) {
                    answer = cnd_icon_result(NO, @"restore-bundle-changed",
                        @"eBay's bundle path or version changed; the version-1 registration backup was retained",
                        @{@"identity": currentIdentity ?: @{}});
                } else {
                    NSDictionary *registration =
                        CNDLaunchServicesRegisterViaInstalld(original);
                    BOOL registrationOK =
                        cnd_icon_registration_succeeded(registration);
                    NSString *cacheFailure = nil;
                    BOOL cacheOK =
                        cnd_icon_invalidate_iconservices_cache(&cacheFailure);
                    NSDictionary *sessionFinalization =
                        CNDLaunchServicesFinishRetainedInstalldSession();
                    BOOL sessionOK = [sessionFinalization[@"ok"] boolValue];
                    NSError *removeError = nil;
                    BOOL removed = registrationOK && cacheOK && sessionOK &&
                        [NSFileManager.defaultManager
                            removeItemAtURL:cnd_icon_backup_url()
                            error:&removeError];
                    answer = cnd_icon_result(removed,
                        removed ? @"restored-legacy" :
                            (!registrationOK ? @"restore-registration" :
                             (!cacheOK ? @"restore-cache-invalidation" :
                              (!sessionOK ? @"restore-session-finalization" :
                               @"restore-backup-cleanup"))),
                        removed
                            ? @"the pending version-1 registration-only experiment was restored"
                            : (!registrationOK
                                ? @"stock installd did not accept the saved version-1 registration"
                                : (!cacheOK ? (cacheFailure ?:
                                   @"IconServices invalidation failed")
                                   : (!sessionOK
                                      ? (sessionFinalization[@"message"] ?:
                                         @"the retained installd session did not close cleanly")
                                      : (removeError.localizedDescription ?:
                                         @"the version-1 backup remains pending")))),
                        @{
                            @"registration": registration ?: @{},
                            @"iconCacheInvalidationIssued": @(cacheOK),
                            @"installdSessionFinalization":
                                sessionFinalization ?: @{},
                            @"cleanupError": removeError.localizedDescription ?: @"",
                        });
                }
            } else {
                NSDictionary *currentIdentity =
                    CNDLaunchServicesCopyRegistrationDictionaryForBundleIdentifierRetainingSession(
                        cnd_icon_target_bundle_identifier());
                cnd_icon_prepare_bundle_access();
                answer = cnd_icon_restore_v2(backup, currentIdentity);
            }
        }
    } @catch (NSException *exception) {
        answer = cnd_icon_result(NO, @"restore-exception",
            @"restoring eBay raised an Objective-C exception",
            @{@"exception": exception.description ?: @"unknown"});
    } @finally {
        NSDictionary *sessionFinalization =
            CNDLaunchServicesFinishRetainedInstalldSession();
        if (answer && !answer[@"installdSessionFinalization"]) {
            NSMutableDictionary *withFinalization = [answer mutableCopy];
            withFinalization[@"installdSessionFinalization"] =
                sessionFinalization ?: @{};
            if ([answer[@"ok"] boolValue] &&
                ![sessionFinalization[@"ok"] boolValue]) {
                withFinalization[@"ok"] = @NO;
                withFinalization[@"stage"] = @"restore-session-finalization";
                withFinalization[@"message"] =
                    @"recovery completed, but the retained installd RemoteCall session did not close cleanly; the journal was retained";
                withFinalization[@"active"] =
                    @(CNDIconDeclarationRedirectIsActive());
            }
            answer = withFinalization;
        }
        __sync_lock_release(&gOperationRunning);
    }
    return answer ?: cnd_icon_result(NO, @"unknown",
        @"the eBay icon recovery ended without a result", nil);
}

NSDictionary<NSString *, id> *CNDIconDeclarationRedirectEmergencyClear(void)
{
    if (!__sync_bool_compare_and_swap(&gOperationRunning, 0, 1)) {
        return cnd_icon_result(NO, @"operation-active",
            @"another eBay icon operation is running", nil);
    }

    NSDictionary *answer = nil;
    @try {
        NSError *backupError = nil;
        NSDictionary *backup = cnd_icon_read_backup(&backupError);
        NSDictionary *file = backup[@"fileMutation"];
        NSDictionary *original = backup[@"registrationDictionary"];
        NSString *savedBundle = cnd_icon_canonical_path(backup[@"bundlePath"]);
        NSString *targetPath = file[@"targetPath"];
        BOOL legacyCreateOnly =
            [backup[@"version"] unsignedIntegerValue] ==
                CNDIconRedirectBackupVersion &&
            [file[@"mode"] isEqual:@"create"] &&
            backup[@"plistMutation"] == nil &&
            [original isKindOfClass:NSDictionary.class] &&
            savedBundle.length > 0 &&
            [file[@"bundlePath"] isEqual:savedBundle] &&
            [targetPath isEqual:[savedBundle stringByAppendingPathComponent:
                file[@"relativePath"]]] &&
            cnd_icon_path_is_strictly_beneath(targetPath, savedBundle);
        if (!legacyCreateOnly) {
            answer = cnd_icon_result(NO, @"emergency-scope",
                backupError.localizedDescription ?:
                    @"Emergency Clear is limited to the legacy create-file transaction with no on-disk Info.plist mutation",
                nil);
        } else if (!remote_call_lab_backend_opted_in() &&
                   !kexploit_krw_ready()) {
            answer = cnd_icon_result(NO, @"krw-prerequisite",
                @"live kernel read/write is required before Emergency Clear",
                nil);
        } else {
            NSDictionary *identity =
                CNDLaunchServicesCopyRegistrationDictionaryForBundleIdentifierRetainingSession(
                    cnd_icon_target_bundle_identifier());
            NSDictionary *current = identity[@"registrationDictionary"];
            NSString *currentBundle = cnd_icon_canonical_path(current[@"Path"]);
            if (![identity[@"ok"] boolValue] ||
                ![currentBundle isEqual:savedBundle] ||
                !cnd_icon_same_saved_install(original, current)) {
                answer = cnd_icon_result(NO, @"emergency-bundle-changed",
                    @"eBay's bundle path or installed version changed; Emergency Clear refused the stale target",
                    @{ @"identity": identity ?: @{} });
            } else {
                cnd_icon_prepare_bundle_access();
                struct stat targetStat = {0};
                BOOL targetAbsent =
                    lstat(targetPath.fileSystemRepresentation, &targetStat) != 0 &&
                    errno == ENOENT;
                NSString *fileFailure = nil;
                BOOL fileOK = targetAbsent;
                if (!targetAbsent) {
                    if (S_ISLNK(targetStat.st_mode) ||
                        !S_ISREG(targetStat.st_mode)) {
                        fileFailure =
                            @"the journaled emergency target is not a regular non-symlink file";
                    } else {
                        fileOK = cnd_icon_remove_created_file(
                            targetPath, &fileFailure);
                    }
                }

                NSString *targetedRegistrationFailure = nil;
                NSDictionary *targetedRegistration =
                    cnd_icon_uicache_registration_dictionary(
                        original, &targetedRegistrationFailure);
                NSDictionary *registration =
                    fileOK && targetedRegistration
                    ? CNDLaunchServicesRegisterViaInstalld(targetedRegistration)
                    : @{
                        @"ok": @NO,
                        @"stage": !fileOK ? @"file-remove" :
                            @"targeted-registration",
                        @"message": !fileOK
                            ? (fileFailure ?: @"the emergency icon removal failed")
                            : (targetedRegistrationFailure ?:
                               @"the saved identity cannot produce a targeted uicache-style registration"),
                        @"registrationAccepted": @NO,
                        @"transport": @"not-run",
                        @"teardown": @0,
                        @"localStateRemaining": @NO,
                    };
                NSDictionary *captureFinalization =
                    CNDLaunchServicesFinishRetainedInstalldSession();
                BOOL captureOK = [captureFinalization[@"ok"] boolValue];
                BOOL registrationOK =
                    cnd_icon_registration_succeeded(registration);
                NSString *cacheFailure = nil;
                BOOL cacheOK = registrationOK &&
                    cnd_icon_invalidate_iconservices_cache(&cacheFailure);
                NSError *cleanupError = nil;
                BOOL cleanupOK = NO;
                if (fileOK && captureOK && registrationOK && cacheOK) {
                    cleanupOK = [NSFileManager.defaultManager
                        removeItemAtURL:cnd_icon_backup_url()
                                 error:&cleanupError] ||
                        !CNDIconDeclarationRedirectIsActive();
                    [NSFileManager.defaultManager
                        removeItemAtURL:cnd_icon_stage_url() error:nil];
                }
                BOOL ok = fileOK && captureOK && registrationOK &&
                    cacheOK && cleanupOK;
                NSString *stage = ok ? @"emergency-cleared" :
                    (!fileOK ? @"emergency-file-remove" :
                     (!captureOK ? @"emergency-capture-finalization" :
                      (!registrationOK ? @"emergency-registration" :
                       (!cacheOK ? @"emergency-cache-invalidation" :
                        @"emergency-journal-cleanup"))));
                NSString *message = ok
                    ? @"the legacy transaction-created icon was removed, stock on-disk registration was rebuilt, and the emergency journal was cleared"
                    : (!fileOK ? (fileFailure ?:
                        @"the legacy transaction-created icon could not be removed")
                       : (!captureOK ? (captureFinalization[@"message"] ?:
                            @"the capture session did not close cleanly")
                          : (!registrationOK ? (registration[@"message"] ?:
                                @"stock bundle registration failed")
                             : (!cacheOK ? (cacheFailure ?:
                                    @"IconServices invalidation failed")
                                : (cleanupError.localizedDescription ?:
                                    @"the emergency journal could not be removed")))));
                answer = cnd_icon_result(ok, stage, message, @{
                    @"identity": identity,
                    @"targetPath": targetPath,
                    @"fileRestored": @(fileOK),
                    @"fileFailure": fileFailure ?: @"",
                    @"captureSessionFinalization": captureFinalization,
                    @"registration": registration,
                    @"iconCacheInvalidationIssued": @(cacheOK),
                    @"cleanupError": cleanupError.localizedDescription ?: @"",
                    @"emergencyHashVerificationSkipped": @YES,
                });
            }
        }
    } @catch (NSException *exception) {
        answer = cnd_icon_result(NO, @"emergency-exception",
            @"Emergency Clear raised an Objective-C exception",
            @{ @"exception": exception.description ?: @"unknown" });
    } @finally {
        NSDictionary *finalization =
            CNDLaunchServicesFinishRetainedInstalldSession();
        if (answer && !answer[@"installdSessionFinalization"]) {
            NSMutableDictionary *withFinalization = [answer mutableCopy];
            withFinalization[@"installdSessionFinalization"] =
                finalization ?: @{};
            if ([answer[@"ok"] boolValue] &&
                ![finalization[@"ok"] boolValue]) {
                withFinalization[@"ok"] = @NO;
                withFinalization[@"stage"] =
                    @"emergency-session-finalization";
                withFinalization[@"message"] =
                    @"Emergency Clear completed, but a retained installd session did not close cleanly; recovery state was retained";
            }
            withFinalization[@"active"] =
                @(CNDIconDeclarationRedirectIsActive());
            answer = withFinalization;
        }
        __sync_lock_release(&gOperationRunning);
    }
    return answer ?: cnd_icon_result(NO, @"emergency-unknown",
        @"Emergency Clear ended without a result", nil);
}

NSDictionary<NSString *, id> *
CNDIconDeclarationRedirectResetRecoveryState(void)
{
    if (!__sync_bool_compare_and_swap(&gOperationRunning, 0, 1)) {
        return cnd_icon_result(NO, @"operation-active",
            @"another icon operation is running", nil);
    }

    NSDictionary *answer = nil;
    @try {
        NSFileManager *manager = NSFileManager.defaultManager;
        NSURL *journalURL = cnd_icon_backup_url();
        NSURL *stageURL = cnd_icon_stage_url();
        BOOL journalWasPresent = [manager
            fileExistsAtPath:journalURL.path];
        BOOL stageWasPresent = [manager
            fileExistsAtPath:stageURL.path];
        NSError *journalError = nil;
        NSError *stageError = nil;
        if (journalWasPresent) {
            (void)[manager removeItemAtURL:journalURL error:&journalError];
        }
        if (stageWasPresent) {
            (void)[manager removeItemAtURL:stageURL error:&stageError];
        }
        BOOL journalAbsent = ![manager
            fileExistsAtPath:journalURL.path];
        BOOL stageAbsent = ![manager
            fileExistsAtPath:stageURL.path];
        BOOL ok = journalAbsent && stageAbsent;
        answer = cnd_icon_result(
            ok,
            ok ? @"recovery-state-reset" : @"recovery-state-reset-failed",
            ok
                ? @"kslop forgot its local icon redirect recovery state without opening or modifying the target application, its registration, or IconServices."
                : @"kslop could not verify removal of its local icon redirect recovery files; no target application state was contacted.",
            @{
                @"journalWasPresent": @(journalWasPresent),
                @"stageWasPresent": @(stageWasPresent),
                @"journalCleared": @(journalAbsent),
                @"stageCleared": @(stageAbsent),
                @"journalCleanupError":
                    journalError.localizedDescription ?: @"",
                @"stageCleanupError":
                    stageError.localizedDescription ?: @"",
                @"targetFileContacted": @NO,
                @"plistContacted": @NO,
                @"registrationAttempted": @NO,
                @"cacheInvalidationIssued": @NO,
                @"restorationClaimed": @NO,
            });
    } @catch (NSException *exception) {
        answer = cnd_icon_result(NO, @"recovery-state-reset-exception",
            @"Resetting kslop's local icon redirect state raised an exception; no target application state was contacted.",
            @{ @"exception": exception.description ?: @"unknown" });
    } @finally {
        __sync_lock_release(&gOperationRunning);
    }
    return answer ?: cnd_icon_result(NO, @"recovery-state-reset-unknown",
        @"Resetting kslop's local icon redirect state ended without a result",
        nil);
}

NSDictionary<NSString *, id> *CNDIconDeclarationRedirectApplyThemeData(
    NSString *bundleIdentifier, NSData *sourcePNGData, NSURL *journalURL)
{
    if (![bundleIdentifier isKindOfClass:NSString.class] ||
        bundleIdentifier.length == 0 ||
        ![sourcePNGData isKindOfClass:NSData.class] || sourcePNGData.length == 0 ||
        ![journalURL isKindOfClass:NSURL.class] || !journalURL.isFileURL) {
        return cnd_icon_result(NO, @"parameter-validation",
            @"SnowBoard Remix requires a bundle identifier, source PNG, and journal URL", nil);
    }
    @synchronized ([NSObject class]) {
        gCNDIconRedirectOverrideBundleIdentifier = [bundleIdentifier copy];
        gCNDIconRedirectOverrideSourcePNGData = [sourcePNGData copy];
        gCNDIconRedirectOverrideJournalURL = [journalURL copy];
        NSDictionary *result = CNDIconDeclarationRedirectApply();
        gCNDIconRedirectOverrideBundleIdentifier = nil;
        gCNDIconRedirectOverrideSourcePNGData = nil;
        gCNDIconRedirectOverrideJournalURL = nil;
        return result;
    }
}

NSDictionary<NSString *, id> *CNDIconDeclarationRedirectRestoreJournal(
    NSString *bundleIdentifier, NSURL *journalURL)
{
    if (![bundleIdentifier isKindOfClass:NSString.class] ||
        bundleIdentifier.length == 0 ||
        ![journalURL isKindOfClass:NSURL.class] || !journalURL.isFileURL) {
        return cnd_icon_result(NO, @"parameter-validation",
            @"SnowBoard Remix requires a bundle identifier and journal URL", nil);
    }
    @synchronized ([NSObject class]) {
        gCNDIconRedirectOverrideBundleIdentifier = [bundleIdentifier copy];
        gCNDIconRedirectOverrideJournalURL = [journalURL copy];
        NSDictionary *result = CNDIconDeclarationRedirectRestore();
        gCNDIconRedirectOverrideBundleIdentifier = nil;
        gCNDIconRedirectOverrideJournalURL = nil;
        return result;
    }
}
