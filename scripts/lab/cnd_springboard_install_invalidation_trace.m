#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CommonCrypto/CommonDigest.h>

#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef CND_INSTALL_TRACE_OUTPUT_TOKEN
#define CND_INSTALL_TRACE_OUTPUT_TOKEN ""
#endif

#ifndef CND_INSTALL_TRACE_OUTPUT_PATH
#define CND_INSTALL_TRACE_OUTPUT_PATH \
    "/var/tmp/cyanide-springboard-install-invalidation.log"
#endif

#ifndef CND_INSTALL_TRACE_TARGET_BUNDLE
#define CND_INSTALL_TRACE_TARGET_BUNDLE "com.apple.MobileSMS"
#endif

enum {
    CNDInstallTraceExpectedHooks = 23,
    CNDInstallTraceCollectionCap = 64,
    CNDInstallTraceSampleCap = 12,
    CNDInstallTraceLeafCap = 512,
    CNDInstallTraceImageEventCap = 4096,
};

static int gCNDInstallTraceFD = -1;
static _Atomic uint64_t gCNDInstallTraceSequence;
static _Atomic uint64_t gCNDInstallTraceImageEvents;

static IMP gOriginalApplicationsAdded;
static IMP gOriginalApplicationsReplaced;
static IMP gOriginalApplicationsUpdated;
static IMP gOriginalLoadApplications;
static IMP gOriginalInstalledAppsDidChange;
static IMP gOriginalMutateInstalledApps;
static IMP gOriginalIconModelInstalledAppsDidChange;
static IMP gOriginalApplicationIconDataSourceDidChange;
static IMP gOriginalReloadIcons;
static IMP gOriginalNoteApplicationIconImageChanged;
static IMP gOriginalPurgeAllCachedImages;
static IMP gOriginalPurgeCachedImagesForIcons;
static IMP gOriginalUpdateImageForIcon;
static IMP gOriginalSetIconCache;
static IMP gOriginalIconManagerDidInvalidateIcons;
static IMP gOriginalReplaceIconDataSource;
static IMP gOriginalDidReplaceIconDataSource;
static IMP gOriginalNoteActiveDataSourceDidChange;
static IMP gOriginalNoteDataSourceDidInvalidate;
static IMP gOriginalBundleImageForDescriptor;
static IMP gOriginalConcreteCachedImageForDescriptor;
static IMP gOriginalConcreteStoreImageForDescriptor;
static IMP gOriginalSetImageBagsByDescriptor;

static void CNDInstallTraceLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static uint64_t CNDInstallTraceNowNS(void)
{
    struct timespec value = {0};
    return clock_gettime(CLOCK_MONOTONIC, &value) == 0
        ? (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec
        : 0ULL;
}

static void CNDInstallTraceLog(const char *format, ...)
{
    if (gCNDInstallTraceFD < 0) return;
    char line[8192] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDInstallTraceFD, line, amount);
    (void)fsync(gCNDInstallTraceFD);
}

static void CNDInstallTracePrefix(const char *kind, const char *phase,
                                  id self, SEL command)
{
    uint64_t sequence = atomic_fetch_add_explicit(
        &gCNDInstallTraceSequence, 1U, memory_order_relaxed) + 1U;
    CNDInstallTraceLog(
        "[CND_INSTALL] seq=%llu monoNS=%llu main=%d kind=%s phase=%s "
        "self=%p/%s selector=%s ",
        (unsigned long long)sequence,
        (unsigned long long)CNDInstallTraceNowNS(),
        pthread_main_np() ? 1 : 0, kind ?: "-", phase ?: "-", self,
        self ? class_getName(object_getClass(self)) : "-",
        command ? sel_getName(command) : "-");
}

static const char *CNDInstallTraceSkipQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static Method CNDInstallTraceMethod(id object, const char *name)
{
    if (!object || !name) return NULL;
    return class_getInstanceMethod(object_getClass(object),
                                   sel_registerName(name));
}

static id CNDInstallTraceObject(id object, const char *name)
{
    Method method = CNDInstallTraceMethod(object, name);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *returnType = method_copyReturnType(method);
    const char *type = CNDInstallTraceSkipQualifiers(returnType);
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

static bool CNDInstallTraceInteger(id object, const char *name,
                                   uint64_t *valueOut)
{
    Method method = CNDInstallTraceMethod(object, name);
    if (!method || method_getNumberOfArguments(method) != 2U || !valueOut) {
        return false;
    }
    char *returnType = method_copyReturnType(method);
    const char *type = CNDInstallTraceSkipQualifiers(returnType);
    bool valid = type && strchr("cCsSiIlLqQB", *type);
    free(returnType);
    if (!valid) return false;
    @try {
        *valueOut = ((uint64_t (*)(id, SEL))objc_msgSend)(
            object, sel_registerName(name));
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDInstallTraceDouble(id object, const char *name,
                                  double *valueOut)
{
    Method method = CNDInstallTraceMethod(object, name);
    if (!method || method_getNumberOfArguments(method) != 2U || !valueOut) {
        return false;
    }
    char *returnType = method_copyReturnType(method);
    const char *type = CNDInstallTraceSkipQualifiers(returnType);
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

static bool CNDInstallTraceSize(id object, CGSize *sizeOut)
{
    Method method = CNDInstallTraceMethod(object, "size");
    if (!method || method_getNumberOfArguments(method) != 2U || !sizeOut) {
        return false;
    }
    char *returnType = method_copyReturnType(method);
    bool valid = returnType && strstr(returnType, "CGSize");
    free(returnType);
    if (!valid) return false;
    @try {
        *sizeOut = ((CGSize (*)(id, SEL))objc_msgSend)(
            object, sel_registerName("size"));
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static NSString *CNDInstallTraceTargetBundle(void)
{
    static NSString *value;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        value = [NSString stringWithUTF8String:
            CND_INSTALL_TRACE_TARGET_BUNDLE];
    });
    return value;
}

static NSString *CNDInstallTraceIdentifier(id object)
{
    static const char *const selectors[] = {
        "applicationBundleID", "applicationBundleIdentifierForImage",
        "bundleIdentifier", "uniqueIdentifier", "displayIdentifier",
    };
    for (size_t index = 0;
         index < sizeof(selectors) / sizeof(selectors[0]); index++) {
        id value = CNDInstallTraceObject(object, selectors[index]);
        if ([value isKindOfClass:NSString.class] && [value length]) {
            return value;
        }
    }
    return @"-";
}

static bool CNDInstallTraceIsTarget(id object)
{
    return [CNDInstallTraceIdentifier(object)
        isEqualToString:CNDInstallTraceTargetBundle()];
}

static NSString *CNDInstallTraceSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class]) return @"-";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *text = [NSMutableString stringWithCapacity:
        CC_SHA256_DIGEST_LENGTH * 2U];
    for (size_t index = 0; index < sizeof(digest); index++) {
        [text appendFormat:@"%02x", digest[index]];
    }
    return text;
}

static NSString *CNDInstallTraceUUID(id object)
{
    if ([object isKindOfClass:NSUUID.class]) return [object UUIDString];
    if ([object isKindOfClass:NSString.class]) return object;
    return @"-";
}

static NSData *CNDInstallTracePixelData(id image, size_t *widthOut,
                                        size_t *heightOut)
{
    if (widthOut) *widthOut = 0U;
    if (heightOut) *heightOut = 0U;
    if (!image || ![image respondsToSelector:sel_registerName("CGImage")]) {
        return nil;
    }
    CGImageRef cgImage = NULL;
    @try {
        cgImage = ((CGImageRef (*)(id, SEL))objc_msgSend)(
            image, sel_registerName("CGImage"));
    } @catch (__unused NSException *exception) {
        return nil;
    }
    if (!cgImage) return nil;
    size_t width = CGImageGetWidth(cgImage);
    size_t height = CGImageGetHeight(cgImage);
    if (!width || !height || width > 1024U || height > 1024U ||
        width > SIZE_MAX / 4U || height > SIZE_MAX / (width * 4U)) {
        return nil;
    }
    size_t rowBytes = width * 4U;
    NSMutableData *data = [NSMutableData dataWithLength:rowBytes * height];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(
        data.mutableBytes, width, height, 8U, rowBytes, colorSpace,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(colorSpace);
    if (!context) return nil;
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), cgImage);
    CGContextRelease(context);
    if (widthOut) *widthOut = width;
    if (heightOut) *heightOut = height;
    return data;
}

static NSUInteger CNDInstallTraceCount(id collection)
{
    uint64_t count = 0U;
    return CNDInstallTraceInteger(collection, "count", &count) &&
        count <= NSUIntegerMax ? (NSUInteger)count : NSNotFound;
}

static id CNDInstallTraceObjectAtIndex(id collection, NSUInteger index)
{
    SEL selector = sel_registerName("objectAtIndex:");
    if (!collection || ![collection respondsToSelector:selector]) return nil;
    @try {
        return ((id (*)(id, SEL, NSUInteger))objc_msgSend)(
            collection, selector, index);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static NSArray *CNDInstallTraceObjects(id collection)
{
    if ([collection isKindOfClass:NSArray.class]) return collection;
    id values = CNDInstallTraceObject(collection, "allValues");
    if ([values isKindOfClass:NSArray.class]) return values;
    id objects = CNDInstallTraceObject(collection, "allObjects");
    if ([objects isKindOfClass:NSArray.class]) return objects;
    return nil;
}

static void CNDInstallTraceLogCollection(const char *label, id collection)
{
    NSArray *objects = CNDInstallTraceObjects(collection);
    NSUInteger declared = CNDInstallTraceCount(collection);
    if (declared == NSNotFound) declared = CNDInstallTraceCount(objects);
    NSUInteger bounded = objects
        ? MIN(objects.count, (NSUInteger)CNDInstallTraceCollectionCap) : 0U;
    bool target = false;
    NSMutableArray<NSString *> *samples = [NSMutableArray array];
    for (NSUInteger index = 0; index < bounded; index++) {
        id object = CNDInstallTraceObjectAtIndex(objects, index);
        NSString *identifier = CNDInstallTraceIdentifier(object);
        if ([identifier isEqualToString:CNDInstallTraceTargetBundle()]) {
            target = true;
        }
        if (samples.count < CNDInstallTraceSampleCap &&
            ![identifier isEqualToString:@"-"]) {
            [samples addObject:identifier];
        }
    }
    NSString *sample = [samples componentsJoinedByString:@","];
    CNDInstallTraceLog(
        "[CND_INSTALL] collection label=%s object=%p/%s count=%s%lu "
        "scanned=%lu capped=%d target=%d sample=%s\n",
        label ?: "-", collection,
        collection ? class_getName(object_getClass(collection)) : "-",
        declared == NSNotFound ? "?" : "",
        (unsigned long)(declared == NSNotFound ? 0U : declared),
        (unsigned long)bounded,
        objects && objects.count > CNDInstallTraceCollectionCap ? 1 : 0,
        target ? 1 : 0, sample.UTF8String ?: "-");
}

static id CNDInstallTraceSingleton(const char *className)
{
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName("sharedInstance");
    Method method = cls ? class_getClassMethod(cls, selector) : NULL;
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(cls, selector);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static id CNDInstallTraceModel(id controller, id manager)
{
    static const char *const selectors[] = {"model", "iconModel"};
    id roots[] = {controller, manager};
    for (size_t root = 0; root < 2U; root++) {
        for (size_t index = 0;
             index < sizeof(selectors) / sizeof(selectors[0]); index++) {
            id model = CNDInstallTraceObject(roots[root], selectors[index]);
            if (model && [model respondsToSelector:sel_registerName(
                    "applicationIconForBundleIdentifier:")]) {
                return model;
            }
        }
    }
    return nil;
}

static id CNDInstallTraceIconManager(id controller)
{
    id manager = CNDInstallTraceSingleton("SBHIconManager");
    if (!manager) manager = CNDInstallTraceObject(controller, "iconManager");
    if (!manager) manager = CNDInstallTraceObject(controller, "_iconManager");
    return manager;
}

static void CNDInstallTraceLogCache(const char *label, id owner,
                                    const char *getter)
{
    id cache = CNDInstallTraceObject(owner, getter);
    uint64_t count = 0U;
    bool countKnown = CNDInstallTraceInteger(
        cache, "numberOfCachedImages", &count);
    CNDInstallTraceLog(
        "[CND_INSTALL] cache label=%s owner=%p/%s getter=%s "
        "cache=%p/%s images=%s%llu\n",
        label ?: "-", owner,
        owner ? class_getName(object_getClass(owner)) : "-", getter,
        cache, cache ? class_getName(object_getClass(cache)) : "-",
        countKnown ? "" : "?", (unsigned long long)count);
}

static void CNDInstallTraceLogIcon(const char *role, id icon)
{
    uint64_t generation = 0U;
    bool generationKnown = CNDInstallTraceInteger(
        icon, "imageGeneration", &generation);
    id activeDataSource = CNDInstallTraceObject(icon, "activeDataSource");
    id servicesIcon = CNDInstallTraceObject(icon, "iconServicesIconForImage");
    CNDInstallTraceLog(
        "[CND_INSTALL] icon role=%s icon=%p/%s bundle=%s "
        "generation=%s%llu activeDataSource=%p/%s servicesIcon=%p/%s\n",
        role ?: "-", icon,
        icon ? class_getName(object_getClass(icon)) : "-",
        CNDInstallTraceIdentifier(icon).UTF8String ?: "-",
        generationKnown ? "" : "?", (unsigned long long)generation,
        activeDataSource,
        activeDataSource ? class_getName(object_getClass(activeDataSource)) : "-",
        servicesIcon,
        servicesIcon ? class_getName(object_getClass(servicesIcon)) : "-");
}

static void CNDInstallTraceSnapshot(const char *label)
{
    @autoreleasepool {
        id controller = CNDInstallTraceSingleton("SBIconController");
        id manager = CNDInstallTraceIconManager(controller);
        id model = CNDInstallTraceModel(controller, manager);
        id servicesManager = CNDInstallTraceSingleton("ISIconManager");
        uint64_t sequence = atomic_fetch_add_explicit(
            &gCNDInstallTraceSequence, 1U, memory_order_relaxed) + 1U;
        CNDInstallTraceLog(
            "[CND_INSTALL] seq=%llu monoNS=%llu main=%d kind=snapshot "
            "phase=%s controller=%p/%s manager=%p/%s model=%p/%s "
            "servicesManager=%p/%s servicesCache=%p/%s\n",
            (unsigned long long)sequence,
            (unsigned long long)CNDInstallTraceNowNS(),
            pthread_main_np() ? 1 : 0, label ?: "-", controller,
            controller ? class_getName(object_getClass(controller)) : "-",
            manager, manager ? class_getName(object_getClass(manager)) : "-",
            model, model ? class_getName(object_getClass(model)) : "-",
            servicesManager,
            servicesManager
                ? class_getName(object_getClass(servicesManager)) : "-",
            CNDInstallTraceObject(servicesManager, "iconCache"),
            CNDInstallTraceObject(servicesManager, "iconCache")
                ? class_getName(object_getClass(
                    CNDInstallTraceObject(servicesManager, "iconCache"))) : "-");

        CNDInstallTraceLogCache("home", manager, "iconImageCache");
        CNDInstallTraceLogCache("folder-composite", manager,
                                "folderIconImageCache");
        CNDInstallTraceLogCache("notifications", controller,
                                "notificationIconImageCache");
        CNDInstallTraceLogCache("table-ui", controller,
                                "tableUIIconImageCache");
        CNDInstallTraceLogCache("switcher", controller,
                                "appSwitcherHeaderIconImageCache");

        id rootFolderController = CNDInstallTraceObject(
            manager, "rootFolderController");
        CNDInstallTraceLogCache("root-folder", rootFolderController,
                                "iconImageCache");

        static const char *const libraryGetters[] = {
            "trailingLibraryViewController", "overlayLibraryViewController",
        };
        id seenLibraries[2] = {nil, nil};
        NSUInteger seenLibraryCount = 0U;
        for (size_t index = 0;
             index < sizeof(libraryGetters) / sizeof(libraryGetters[0]);
             index++) {
            id library = CNDInstallTraceObject(manager, libraryGetters[index]);
            if (!library) continue;
            bool duplicate = false;
            for (NSUInteger seen = 0; seen < seenLibraryCount; seen++) {
                duplicate |= seenLibraries[seen] == library;
            }
            if (duplicate) continue;
            seenLibraries[seenLibraryCount++] = library;
            CNDInstallTraceLogCache("app-library", library,
                                    "iconImageCache");
            id directTable = CNDInstallTraceObject(
                library, "iconTableViewController");
            CNDInstallTraceLogCache("app-library-table", directTable,
                                    "iconImageCache");
            id search = CNDInstallTraceObject(
                library, "containerViewController");
            id searchTable = CNDInstallTraceObject(
                search, "searchResultsController");
            if (searchTable != directTable) {
                CNDInstallTraceLogCache("app-library-search", searchTable,
                                        "iconImageCache");
            }
        }

        id canonical = nil;
        SEL lookup = sel_registerName("applicationIconForBundleIdentifier:");
        if (model && [model respondsToSelector:lookup]) {
            @try {
                canonical = ((id (*)(id, SEL, id))objc_msgSend)(
                    model, lookup, CNDInstallTraceTargetBundle());
            } @catch (__unused NSException *exception) {
                canonical = nil;
            }
        }
        CNDInstallTraceLogIcon("canonical", canonical);

        id leaves = CNDInstallTraceObject(
            model, "leafIconsUniquedByApplicationBundleIdentifier");
        NSArray *leafObjects = CNDInstallTraceObjects(leaves);
        NSUInteger leafCount = leafObjects.count;
        NSUInteger bounded = MIN(leafCount, (NSUInteger)CNDInstallTraceLeafCap);
        NSUInteger targetCount = 0U;
        for (NSUInteger index = 0; index < bounded; index++) {
            id icon = CNDInstallTraceObjectAtIndex(leafObjects, index);
            if (!CNDInstallTraceIsTarget(icon)) continue;
            targetCount++;
            CNDInstallTraceLogIcon("live-leaf", icon);
        }
        CNDInstallTraceLog(
            "[CND_INSTALL] leaves collection=%p/%s declared=%lu "
            "scanned=%lu capped=%d targetCount=%lu\n",
            leaves, leaves ? class_getName(object_getClass(leaves)) : "-",
            (unsigned long)leafCount, (unsigned long)bounded,
            leafCount > CNDInstallTraceLeafCap ? 1 : 0,
            (unsigned long)targetCount);
    }
}

static void CNDInstallTraceScheduleSnapshots(const char *event)
{
    NSString *name = [NSString stringWithUTF8String:event ?: "event"];
    NSArray<NSNumber *> *delays = @[@0, @100, @500, @2000];
    for (NSNumber *delayValue in delays) {
        NSUInteger delayMS = delayValue.unsignedIntegerValue;
        NSString *label = [NSString stringWithFormat:@"%@+%lums", name,
                           (unsigned long)delayMS];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)delayMS * NSEC_PER_MSEC),
                       dispatch_get_main_queue(), ^{
            CNDInstallTraceSnapshot(label.UTF8String);
        });
    }
}

static void CNDInstallTraceApplicationEvent(id self, SEL command,
                                            id applications, IMP original)
{
    CNDInstallTracePrefix("application-controller", "enter", self, command);
    CNDInstallTraceLog("applications=%p/%s\n", applications,
                       applications
                           ? class_getName(object_getClass(applications)) : "-");
    CNDInstallTraceLogCollection(sel_getName(command), applications);
    CNDInstallTraceSnapshot("application-event-before");
    ((void (*)(id, SEL, id))original)(self, command, applications);
    CNDInstallTracePrefix("application-controller", "return", self, command);
    CNDInstallTraceLog("applications=%p\n", applications);
    CNDInstallTraceScheduleSnapshots(sel_getName(command));
}

static void CNDHookApplicationsAdded(id self, SEL command, id applications)
{
    CNDInstallTraceApplicationEvent(
        self, command, applications, gOriginalApplicationsAdded);
}

static void CNDHookApplicationsReplaced(id self, SEL command, id applications)
{
    CNDInstallTraceApplicationEvent(
        self, command, applications, gOriginalApplicationsReplaced);
}

static void CNDHookApplicationsUpdated(id self, SEL command, id applications)
{
    CNDInstallTraceApplicationEvent(
        self, command, applications, gOriginalApplicationsUpdated);
}

static void CNDHookLoadApplications(id self, SEL command, id applications,
                                    id removed)
{
    CNDInstallTracePrefix("application-controller", "enter", self, command);
    CNDInstallTraceLog("applications=%p removed=%p\n", applications, removed);
    CNDInstallTraceLogCollection("_loadApplications-applications", applications);
    CNDInstallTraceLogCollection("_loadApplications-removed", removed);
    ((void (*)(id, SEL, id, id))gOriginalLoadApplications)(
        self, command, applications, removed);
    CNDInstallTracePrefix("application-controller", "return", self, command);
    CNDInstallTraceLog("applications=%p removed=%p\n", applications, removed);
}

static void CNDHookInstalledAppsDidChange(id self, SEL command,
                                         NSNotification *notification)
{
    CNDInstallTracePrefix("icon-controller", "enter", self, command);
    CNDInstallTraceLog("notification=%p/%s name=%s userInfo=%p\n",
                       notification,
                       notification
                           ? class_getName(object_getClass(notification)) : "-",
                       notification.name.UTF8String ?: "-",
                       notification.userInfo);
    NSDictionary *userInfo = notification.userInfo;
    NSArray *keys = [[userInfo allKeys] sortedArrayUsingComparator:
        ^NSComparisonResult(id left, id right) {
            return [[left description] compare:[right description]];
        }];
    for (id key in keys) {
        CNDInstallTraceLogCollection(
            [[NSString stringWithFormat:@"notification-%@", key]
                UTF8String], userInfo[key]);
    }
    CNDInstallTraceSnapshot("installed-apps-before");
    ((void (*)(id, SEL, id))gOriginalInstalledAppsDidChange)(
        self, command, notification);
    CNDInstallTracePrefix("icon-controller", "return", self, command);
    CNDInstallTraceLog("notification=%p\n", notification);
    CNDInstallTraceScheduleSnapshots("installed-apps");
}

static void CNDHookMutateInstalledApps(id self, SEL command, id controller,
                                       id added, id modified, id removed)
{
    CNDInstallTracePrefix("icon-controller", "enter", self, command);
    CNDInstallTraceLog("controller=%p added=%p modified=%p removed=%p\n",
                       controller, added, modified, removed);
    CNDInstallTraceLogCollection("mutate-added", added);
    CNDInstallTraceLogCollection("mutate-modified", modified);
    CNDInstallTraceLogCollection("mutate-removed", removed);
    ((void (*)(id, SEL, id, id, id, id))gOriginalMutateInstalledApps)(
        self, command, controller, added, modified, removed);
    CNDInstallTracePrefix("icon-controller", "return", self, command);
    CNDInstallTraceLog("controller=%p\n", controller);
}

static void CNDInstallTraceOneObjectEvent(const char *kind, id self,
                                          SEL command, id object,
                                          IMP original)
{
    CNDInstallTracePrefix(kind, "enter", self, command);
    CNDInstallTraceLog("argument=%p/%s id=%s target=%d\n", object,
                       object ? class_getName(object_getClass(object)) : "-",
                       CNDInstallTraceIdentifier(object).UTF8String ?: "-",
                       CNDInstallTraceIsTarget(object) ? 1 : 0);
    ((void (*)(id, SEL, id))original)(self, command, object);
    CNDInstallTracePrefix(kind, "return", self, command);
    CNDInstallTraceLog("argument=%p\n", object);
}

#define CND_ONE_OBJECT_HOOK(NAME, KIND, ORIGINAL) \
    static void NAME(id self, SEL command, id object) \
    { \
        CNDInstallTraceOneObjectEvent(KIND, self, command, object, ORIGINAL); \
    }

CND_ONE_OBJECT_HOOK(CNDHookIconModelInstalledAppsDidChange,
                    "icon-controller", gOriginalIconModelInstalledAppsDidChange)
CND_ONE_OBJECT_HOOK(CNDHookApplicationIconDataSourceDidChange,
                    "icon-controller", gOriginalApplicationIconDataSourceDidChange)
CND_ONE_OBJECT_HOOK(CNDHookNoteApplicationIconImageChanged,
                    "icon-model", gOriginalNoteApplicationIconImageChanged)
CND_ONE_OBJECT_HOOK(CNDHookPurgeCachedImagesForIcons,
                    "image-cache", gOriginalPurgeCachedImagesForIcons)
CND_ONE_OBJECT_HOOK(CNDHookUpdateImageForIcon,
                    "image-cache", gOriginalUpdateImageForIcon)
CND_ONE_OBJECT_HOOK(CNDHookSetIconCache,
                    "iconservices-manager", gOriginalSetIconCache)
CND_ONE_OBJECT_HOOK(CNDHookNoteDataSourceDidInvalidate,
                    "leaf-icon", gOriginalNoteDataSourceDidInvalidate)
CND_ONE_OBJECT_HOOK(CNDHookSetImageBagsByDescriptor,
                    "iconservices-image-cache", gOriginalSetImageBagsByDescriptor)

#undef CND_ONE_OBJECT_HOOK

static void CNDInstallTraceNoObjectEvent(const char *kind, id self,
                                         SEL command, IMP original)
{
    CNDInstallTracePrefix(kind, "enter", self, command);
    CNDInstallTraceLog("target=%d\n", CNDInstallTraceIsTarget(self) ? 1 : 0);
    ((void (*)(id, SEL))original)(self, command);
    CNDInstallTracePrefix(kind, "return", self, command);
    CNDInstallTraceLog("target=%d\n", CNDInstallTraceIsTarget(self) ? 1 : 0);
}

static void CNDHookReloadIcons(id self, SEL command)
{
    CNDInstallTraceNoObjectEvent(
        "icon-model", self, command, gOriginalReloadIcons);
    CNDInstallTraceScheduleSnapshots("reload-icons");
}

static void CNDHookPurgeAllCachedImages(id self, SEL command)
{
    CNDInstallTraceNoObjectEvent(
        "image-cache", self, command, gOriginalPurgeAllCachedImages);
}

static void CNDHookIconManagerDidInvalidateIcons(id self, SEL command,
                                                 id manager, id icons)
{
    CNDInstallTracePrefix("iconservices-observer", "enter", self, command);
    CNDInstallTraceLog("manager=%p/%s icons=%p/%s\n", manager,
                       manager ? class_getName(object_getClass(manager)) : "-",
                       icons, icons ? class_getName(object_getClass(icons)) : "-");
    CNDInstallTraceLogCollection("invalidated-icons", icons);
    ((void (*)(id, SEL, id, id))gOriginalIconManagerDidInvalidateIcons)(
        self, command, manager, icons);
    CNDInstallTracePrefix("iconservices-observer", "return", self, command);
    CNDInstallTraceLog("manager=%p icons=%p\n", manager, icons);
    CNDInstallTraceScheduleSnapshots("iconservices-invalidation");
}

static void CNDInstallTraceTwoObjectLeafEvent(id self, SEL command,
                                              id oldValue, id newValue,
                                              IMP original)
{
    bool target = CNDInstallTraceIsTarget(self);
    CNDInstallTracePrefix("leaf-icon", "enter", self, command);
    CNDInstallTraceLog(
        "target=%d bundle=%s old=%p/%s new=%p/%s\n", target ? 1 : 0,
        CNDInstallTraceIdentifier(self).UTF8String ?: "-", oldValue,
        oldValue ? class_getName(object_getClass(oldValue)) : "-", newValue,
        newValue ? class_getName(object_getClass(newValue)) : "-");
    ((void (*)(id, SEL, id, id))original)(
        self, command, oldValue, newValue);
    CNDInstallTracePrefix("leaf-icon", "return", self, command);
    CNDInstallTraceLog("target=%d bundle=%s\n", target ? 1 : 0,
                       CNDInstallTraceIdentifier(self).UTF8String ?: "-");
}

static void CNDHookReplaceIconDataSource(id self, SEL command,
                                         id oldValue, id newValue)
{
    CNDInstallTraceTwoObjectLeafEvent(
        self, command, oldValue, newValue, gOriginalReplaceIconDataSource);
}

static void CNDHookDidReplaceIconDataSource(id self, SEL command,
                                            id oldValue, id newValue)
{
    CNDInstallTraceTwoObjectLeafEvent(
        self, command, oldValue, newValue, gOriginalDidReplaceIconDataSource);
}

static void CNDHookNoteActiveDataSourceDidChange(id self, SEL command,
                                                 BOOL reload)
{
    bool target = CNDInstallTraceIsTarget(self);
    CNDInstallTracePrefix("leaf-icon", "enter", self, command);
    CNDInstallTraceLog("target=%d bundle=%s reload=%d\n", target ? 1 : 0,
                       CNDInstallTraceIdentifier(self).UTF8String ?: "-",
                       reload ? 1 : 0);
    ((void (*)(id, SEL, BOOL))gOriginalNoteActiveDataSourceDidChange)(
        self, command, reload);
    CNDInstallTracePrefix("leaf-icon", "return", self, command);
    CNDInstallTraceLog("target=%d reload=%d\n", target ? 1 : 0,
                       reload ? 1 : 0);
}

static void CNDInstallTraceLogImage(const char *phase, id icon,
                                    id descriptor, id image)
{
    if (!CNDInstallTraceIsTarget(icon)) return;
    uint64_t event = atomic_fetch_add_explicit(
        &gCNDInstallTraceImageEvents, 1U, memory_order_relaxed) + 1U;
    if (event > CNDInstallTraceImageEventCap) return;
    CGSize size = CGSizeZero;
    double scale = 0.0;
    uint64_t appearance = 0U;
    uint64_t variant = 0U;
    bool hasSize = CNDInstallTraceSize(descriptor, &size);
    bool hasScale = CNDInstallTraceDouble(descriptor, "scale", &scale);
    bool hasAppearance = CNDInstallTraceInteger(
        descriptor, "appearance", &appearance);
    bool hasVariant = CNDInstallTraceInteger(
        descriptor, "variantOptions", &variant);
    if (!hasVariant) {
        hasVariant = CNDInstallTraceInteger(descriptor, "options", &variant);
    }
    NSData *data = CNDInstallTraceObject(image, "data");
    NSData *token = CNDInstallTraceObject(image, "validationToken");
    id uuid = CNDInstallTraceObject(image, "uuid");
    if (!uuid) uuid = CNDInstallTraceObject(image, "UUID");
    id digest = CNDInstallTraceObject(descriptor, "digest");
    id localCache = CNDInstallTraceObject(icon, "imageCache");
    id bags = CNDInstallTraceObject(localCache, "imageBagsByDescriptor");
    NSUInteger bagCount = CNDInstallTraceCount(bags);
    size_t width = 0U;
    size_t height = 0U;
    NSData *pixels = CNDInstallTracePixelData(image, &width, &height);
    CNDInstallTraceLog(
        "[CND_INSTALL] image event=%llu phase=%s icon=%p/%s bundle=%s "
        "descriptor=%p/%s size=%s%.3fx%.3f scale=%s%.3f "
        "appearance=%s%llu variantOptions=%s0x%llx digest=%s "
        "image=%p/%s uuid=%s dataBytes=%lu dataSHA256=%s "
        "tokenBytes=%lu tokenSHA256=%s pixels=%zux%zu pixelSHA256=%s "
        "localCache=%p/%s bags=%s%lu\n",
        (unsigned long long)event, phase ?: "-", icon,
        icon ? class_getName(object_getClass(icon)) : "-",
        CNDInstallTraceIdentifier(icon).UTF8String ?: "-", descriptor,
        descriptor ? class_getName(object_getClass(descriptor)) : "-",
        hasSize ? "" : "?", size.width, size.height,
        hasScale ? "" : "?", scale,
        hasAppearance ? "" : "?", (unsigned long long)appearance,
        hasVariant ? "" : "?", (unsigned long long)variant,
        CNDInstallTraceUUID(digest).UTF8String ?: "-", image,
        image ? class_getName(object_getClass(image)) : "-",
        CNDInstallTraceUUID(uuid).UTF8String ?: "-",
        (unsigned long)([data isKindOfClass:NSData.class] ? data.length : 0U),
        CNDInstallTraceSHA256(data).UTF8String ?: "-",
        (unsigned long)([token isKindOfClass:NSData.class] ? token.length : 0U),
        CNDInstallTraceSHA256(token).UTF8String ?: "-", width, height,
        CNDInstallTraceSHA256(pixels).UTF8String ?: "-", localCache,
        localCache ? class_getName(object_getClass(localCache)) : "-",
        bagCount == NSNotFound ? "?" : "",
        (unsigned long)(bagCount == NSNotFound ? 0U : bagCount));
}

static id CNDInstallTraceImageEvent(id self, SEL command, id descriptor,
                                    IMP original, const char *phase)
{
    id result = ((id (*)(id, SEL, id))original)(self, command, descriptor);
    CNDInstallTraceLogImage(phase, self, descriptor, result);
    return result;
}

static id CNDHookBundleImageForDescriptor(id self, SEL command, id descriptor)
{
    return CNDInstallTraceImageEvent(
        self, command, descriptor, gOriginalBundleImageForDescriptor,
        "imageForDescriptor-return");
}

static id CNDHookConcreteCachedImageForDescriptor(id self, SEL command,
                                                  id descriptor)
{
    return CNDInstallTraceImageEvent(
        self, command, descriptor, gOriginalConcreteCachedImageForDescriptor,
        "cachedImage-return");
}

static id CNDHookConcreteStoreImageForDescriptor(id self, SEL command,
                                                 id descriptor)
{
    return CNDInstallTraceImageEvent(
        self, command, descriptor, gOriginalConcreteStoreImageForDescriptor,
        "storeImage-return");
}

typedef enum {
    CNDInstallTraceReturnVoid,
    CNDInstallTraceReturnObject,
} CNDInstallTraceReturn;

static bool CNDInstallTraceHook(const char *className,
                                const char *selectorName,
                                CNDInstallTraceReturn expectedReturn,
                                const char *argumentTypes,
                                IMP replacement, IMP *originalOut)
{
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    const char *encoding = method ? method_getTypeEncoding(method) : NULL;
    bool accepted = method != NULL;
    unsigned expectedArguments = 2U + (unsigned)strlen(argumentTypes ?: "");
    accepted &= method && method_getNumberOfArguments(method) == expectedArguments;
    char *returnType = method ? method_copyReturnType(method) : NULL;
    const char *normalizedReturn = CNDInstallTraceSkipQualifiers(returnType);
    accepted &= normalizedReturn &&
        ((expectedReturn == CNDInstallTraceReturnVoid &&
          *normalizedReturn == 'v') ||
         (expectedReturn == CNDInstallTraceReturnObject &&
          *normalizedReturn == '@'));
    for (unsigned index = 0U; accepted && index < strlen(argumentTypes ?: "");
         index++) {
        char *argumentType = method_copyArgumentType(method, index + 2U);
        const char *normalized = CNDInstallTraceSkipQualifiers(argumentType);
        char expected = argumentTypes[index];
        accepted &= normalized &&
            ((expected == '@' && *normalized == '@') ||
             (expected == 'B' && strchr("BcC", *normalized)));
        free(argumentType);
    }
    free(returnType);
    IMP original = accepted ? method_getImplementation(method) : NULL;
    bool installed = false;
    if (accepted && original) {
        if (!class_addMethod(cls, selector, replacement, encoding)) {
            (void)method_setImplementation(method, replacement);
        }
        installed = class_getMethodImplementation(cls, selector) == replacement;
    }
    if (installed && originalOut) *originalOut = original;
    CNDInstallTraceLog(
        "[CND_INSTALL] hook class=%s selector=%s types=%s expectedReturn=%s "
        "expectedArgs=%s accepted=%d installed=%d original=%p "
        "replacement=%p observed=%p\n",
        className, selectorName, encoding ?: "-",
        expectedReturn == CNDInstallTraceReturnVoid ? "v" : "@",
        argumentTypes ?: "", accepted ? 1 : 0, installed ? 1 : 0,
        original, replacement,
        cls ? class_getMethodImplementation(cls, selector) : NULL);
    return installed;
}

#define CND_HOOK(CLASS, SELECTOR, RETURN, ARGS, REPLACEMENT, ORIGINAL) \
    (installed += CNDInstallTraceHook( \
        CLASS, SELECTOR, RETURN, ARGS, (IMP)REPLACEMENT, &ORIGINAL) ? 1U : 0U)

__attribute__((constructor))
static void CNDInstallTraceStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_INSTALL_TRACE_OUTPUT_TOKEN[0] && consume
            ? consume(CND_INSTALL_TRACE_OUTPUT_TOKEN) : -1;
        gCNDInstallTraceFD = open(
            CND_INSTALL_TRACE_OUTPUT_PATH,
            O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        CNDInstallTraceLog(
            "[CND_INSTALL] START pid=%d process=%s monoNS=%llu token=%lld "
            "target=%s mode=inspection-only expectedHooks=%u\n",
            getpid(), getprogname(),
            (unsigned long long)CNDInstallTraceNowNS(), (long long)token,
            CND_INSTALL_TRACE_TARGET_BUNDLE,
            CNDInstallTraceExpectedHooks);

        (void)dlopen(
            "/System/Library/PrivateFrameworks/SpringBoardHome.framework/"
            "SpringBoardHome", RTLD_NOW | RTLD_LOCAL);
        (void)dlopen(
            "/System/Library/PrivateFrameworks/IconServices.framework/"
            "IconServices", RTLD_NOW | RTLD_LOCAL);

        unsigned installed = 0U;
        CND_HOOK("SBApplicationController", "applicationsAdded:",
                 CNDInstallTraceReturnVoid, "@", CNDHookApplicationsAdded,
                 gOriginalApplicationsAdded);
        CND_HOOK("SBApplicationController", "applicationsReplaced:",
                 CNDInstallTraceReturnVoid, "@", CNDHookApplicationsReplaced,
                 gOriginalApplicationsReplaced);
        CND_HOOK("SBApplicationController", "applicationsUpdated:",
                 CNDInstallTraceReturnVoid, "@", CNDHookApplicationsUpdated,
                 gOriginalApplicationsUpdated);
        CND_HOOK("SBApplicationController", "_loadApplications:remove:",
                 CNDInstallTraceReturnVoid, "@@", CNDHookLoadApplications,
                 gOriginalLoadApplications);
        CND_HOOK("SBIconController", "_installedAppsDidChange:",
                 CNDInstallTraceReturnVoid, "@", CNDHookInstalledAppsDidChange,
                 gOriginalInstalledAppsDidChange);
        CND_HOOK("SBIconController",
                 "_mutateIconListsForInstalledAppsDidChangeWithController:"
                 "added:modified:removed:",
                 CNDInstallTraceReturnVoid, "@@@@", CNDHookMutateInstalledApps,
                 gOriginalMutateInstalledApps);
        CND_HOOK("SBIconController", "_iconModelInstalledAppsDidChange:",
                 CNDInstallTraceReturnVoid, "@",
                 CNDHookIconModelInstalledAppsDidChange,
                 gOriginalIconModelInstalledAppsDidChange);
        CND_HOOK("SBIconController", "_applicationIconDataSourceDidChange:",
                 CNDInstallTraceReturnVoid, "@",
                 CNDHookApplicationIconDataSourceDidChange,
                 gOriginalApplicationIconDataSourceDidChange);
        CND_HOOK("SBHIconModel", "reloadIcons", CNDInstallTraceReturnVoid, "",
                 CNDHookReloadIcons, gOriginalReloadIcons);
        CND_HOOK("SBHIconModel", "noteApplicationIconImageChanged:",
                 CNDInstallTraceReturnVoid, "@",
                 CNDHookNoteApplicationIconImageChanged,
                 gOriginalNoteApplicationIconImageChanged);
        CND_HOOK("SBHIconImageCache", "purgeAllCachedImages",
                 CNDInstallTraceReturnVoid, "", CNDHookPurgeAllCachedImages,
                 gOriginalPurgeAllCachedImages);
        CND_HOOK("SBHIconImageCache", "purgeCachedImagesForIcons:",
                 CNDInstallTraceReturnVoid, "@",
                 CNDHookPurgeCachedImagesForIcons,
                 gOriginalPurgeCachedImagesForIcons);
        CND_HOOK("SBHIconImageCache", "updateImageForIcon:",
                 CNDInstallTraceReturnVoid, "@", CNDHookUpdateImageForIcon,
                 gOriginalUpdateImageForIcon);
        CND_HOOK("ISIconManager", "setIconCache:",
                 CNDInstallTraceReturnVoid, "@", CNDHookSetIconCache,
                 gOriginalSetIconCache);
        CND_HOOK("ISIconObserver", "iconManager:didInvalidateIcons:",
                 CNDInstallTraceReturnVoid, "@@",
                 CNDHookIconManagerDidInvalidateIcons,
                 gOriginalIconManagerDidInvalidateIcons);
        CND_HOOK("SBLeafIcon", "replaceIconDataSource:withIconDataSource:",
                 CNDInstallTraceReturnVoid, "@@", CNDHookReplaceIconDataSource,
                 gOriginalReplaceIconDataSource);
        CND_HOOK("SBLeafIcon", "didReplaceIconDataSource:withIconDataSource:",
                 CNDInstallTraceReturnVoid, "@@",
                 CNDHookDidReplaceIconDataSource,
                 gOriginalDidReplaceIconDataSource);
        CND_HOOK("SBLeafIcon", "_noteActiveDataSourceDidChangeAndReloadIcon:",
                 CNDInstallTraceReturnVoid, "B",
                 CNDHookNoteActiveDataSourceDidChange,
                 gOriginalNoteActiveDataSourceDidChange);
        CND_HOOK("SBLeafIcon", "_noteDataSourceDidInvalidateNotification:",
                 CNDInstallTraceReturnVoid, "@",
                 CNDHookNoteDataSourceDidInvalidate,
                 gOriginalNoteDataSourceDidInvalidate);
        CND_HOOK("ISBundleIdentifierIcon", "imageForDescriptor:",
                 CNDInstallTraceReturnObject, "@",
                 CNDHookBundleImageForDescriptor,
                 gOriginalBundleImageForDescriptor);
        CND_HOOK("ISConcreteIcon", "_cachedImageForDescriptor:",
                 CNDInstallTraceReturnObject, "@",
                 CNDHookConcreteCachedImageForDescriptor,
                 gOriginalConcreteCachedImageForDescriptor);
        CND_HOOK("ISConcreteIcon", "_imageFromStoreForDescriptor:",
                 CNDInstallTraceReturnObject, "@",
                 CNDHookConcreteStoreImageForDescriptor,
                 gOriginalConcreteStoreImageForDescriptor);
        CND_HOOK("ISImageCache", "setImageBagsByDescriptor:",
                 CNDInstallTraceReturnVoid, "@",
                 CNDHookSetImageBagsByDescriptor,
                 gOriginalSetImageBagsByDescriptor);

        CNDInstallTraceLog(
            "[CND_INSTALL] TRACE_READY pid=%d monoNS=%llu hooks=%u "
            "expected=%u complete=%d\n",
            getpid(), (unsigned long long)CNDInstallTraceNowNS(), installed,
            CNDInstallTraceExpectedHooks,
            installed == CNDInstallTraceExpectedHooks ? 1 : 0);
        dispatch_async(dispatch_get_main_queue(), ^{
            CNDInstallTraceSnapshot("initial");
        });
    }
}

#undef CND_HOOK
