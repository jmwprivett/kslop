#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <CommonCrypto/CommonDigest.h>

#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef CND_CALENDAR_ORDER_OUTPUT_TOKEN
#define CND_CALENDAR_ORDER_OUTPUT_TOKEN ""
#endif

#ifndef CND_CALENDAR_ORDER_OUTPUT_PATH
#define CND_CALENDAR_ORDER_OUTPUT_PATH \
    "/var/tmp/cyanide-calendar-order-trigger.log"
#endif

#ifndef CND_CALENDAR_ORDER_NONCE
#define CND_CALENDAR_ORDER_NONCE "0"
#endif

#ifndef CND_CALENDAR_ORDER_ACTION
#define CND_CALENDAR_ORDER_ACTION "springboard-refresh-then-calendar"
#endif

enum {
    CNDCalendarOrderModelCap = 8,
    CNDCalendarOrderLeafScanCap = 2048,
    CNDCalendarOrderCacheCap = 16,
};

static int gCNDCalendarOrderFD = -1;
static NSString *const CNDCalendarBundleIdentifier =
    @"com.apple.mobilecal";
static const char *const CNDCalendarSubclassPrefix =
    "CNDLabCalendarPreparedSourceV1_";

static void CNDCalendarOrderLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDCalendarOrderLog(const char *format, ...)
{
    if (gCNDCalendarOrderFD < 0) return;
    char line[8192] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = MIN((size_t)length, sizeof(line) - 1U);
    (void)write(gCNDCalendarOrderFD, line, amount);
    (void)fsync(gCNDCalendarOrderFD);
}

static NSString *CNDCalendarOrderTarget(void)
{
    return [@(CND_CALENDAR_ORDER_ACTION) hasPrefix:@"spotlight-"]
        ? @"Spotlight" : @"SpringBoard";
}

static void CNDCalendarOrderMark(NSString *label, const char *phase)
{
    NSString *target = CNDCalendarOrderTarget();
    const char *path = [target isEqualToString:@"Spotlight"]
        ? "/var/tmp/cyanide-dynamic-icon-trace-spotlight.log"
        : "/var/tmp/cyanide-dynamic-icon-trace.log";
    int descriptor = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (descriptor < 0) return;
    struct timespec value = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &value);
    char line[1024] = {0};
    int length = snprintf(
        line, sizeof(line),
        "[CND_CALENDAR_ORDER] MARK us=%llu process=%s label=%s phase=%s\n",
        (unsigned long long)value.tv_sec * 1000000ULL +
            (unsigned long long)value.tv_nsec / 1000ULL,
        target.UTF8String ?: "-", label.UTF8String ?: "-", phase ?: "-");
    if (length > 0) {
        (void)write(descriptor, line,
                    MIN((size_t)length, sizeof(line) - 1U));
        (void)fsync(descriptor);
    }
    (void)close(descriptor);
}

static const char *CNDCalendarOrderSkipQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type;
}

static bool CNDCalendarOrderMethodTypes(id object, SEL selector,
                                        const char *expected)
{
    if (!object || !selector || !expected) return false;
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    return types && strcmp(types, expected) == 0;
}

static id CNDCalendarOrderObjectGetter(id object, const char *name)
{
    if (!object || !name) return nil;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *copied = method_copyReturnType(method);
    const char *type = CNDCalendarOrderSkipQualifiers(copied);
    bool objectReturn = type && (*type == '@' || *type == '#');
    free(copied);
    if (!objectReturn) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static bool CNDCalendarOrderVoidNoArgument(id object, const char *name)
{
    if (!object || !name) return false;
    SEL selector = sel_registerName(name);
    if (!CNDCalendarOrderMethodTypes(object, selector, "v16@0:8")) {
        return false;
    }
    @try {
        ((void (*)(id, SEL))objc_msgSend)(object, selector);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDCalendarOrderBoolNoArgument(id object, const char *name)
{
    if (!object || !name) return false;
    SEL selector = sel_registerName(name);
    if (!CNDCalendarOrderMethodTypes(object, selector, "B16@0:8")) {
        return false;
    }
    @try {
        return ((BOOL (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static NSUInteger CNDCalendarOrderGeneration(id model)
{
    SEL selector = sel_registerName("imageGeneration");
    if (!CNDCalendarOrderMethodTypes(model, selector, "Q16@0:8")) {
        return NSNotFound;
    }
    return ((NSUInteger (*)(id, SEL))objc_msgSend)(model, selector);
}

static NSString *CNDCalendarOrderBundleIdentifier(id icon)
{
    static const char *const selectors[] = {
        "applicationBundleID", "applicationBundleIdentifier",
        "bundleIdentifier",
    };
    for (NSUInteger index = 0U;
         icon && index < sizeof(selectors) / sizeof(selectors[0]); index++) {
        id value = CNDCalendarOrderObjectGetter(icon, selectors[index]);
        if ([value isKindOfClass:NSString.class] && [value length] > 0U) {
            return value;
        }
    }
    return nil;
}

static NSArray *CNDCalendarOrderObjects(id collection)
{
    if (!collection) return @[];
    if ([collection isKindOfClass:NSArray.class]) return collection;
    id values = CNDCalendarOrderObjectGetter(collection, "allValues");
    if ([values isKindOfClass:NSArray.class]) return values;
    id objects = CNDCalendarOrderObjectGetter(collection, "allObjects");
    return [objects isKindOfClass:NSArray.class] ? objects : @[];
}

static NSMutableArray<NSDictionary *> *CNDCalendarOrderRegistry(bool create)
{
    id owner = NSProcessInfo.processInfo;
    const void *key = sel_registerName(
        "cnd_lab_calendar_order_provider_states_v1");
    id registry = objc_getAssociatedObject(owner, key);
    if (![registry isKindOfClass:NSMutableArray.class] && create) {
        registry = [NSMutableArray arrayWithCapacity:CNDCalendarOrderModelCap];
        objc_setAssociatedObject(owner, key, registry,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        registry = objc_getAssociatedObject(owner, key);
    }
    return [registry isKindOfClass:NSMutableArray.class] ? registry : nil;
}

static void CNDCalendarOrderClearRegistry(void)
{
    objc_setAssociatedObject(
        NSProcessInfo.processInfo,
        sel_registerName("cnd_lab_calendar_order_provider_states_v1"),
        nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static bool CNDCalendarOrderStockSourceValid(id source)
{
    Class stockClass = NSClassFromString(@"CUIKIcon");
    return source && stockClass && [source isKindOfClass:stockClass] &&
        [source respondsToSelector:sel_registerName(
            "prepareImageForDescriptor:")];
}

static bool CNDCalendarOrderBundleSourceValid(id source)
{
    Class sourceClass = NSClassFromString(@"ISBundleIdentifierIcon");
    NSString *bundle = CNDCalendarOrderObjectGetter(
        source, "bundleIdentifier");
    return source && sourceClass && [source isKindOfClass:sourceClass] &&
        [bundle isEqualToString:CNDCalendarBundleIdentifier] &&
        [source respondsToSelector:sel_registerName(
            "prepareImageForDescriptor:")];
}

static id CNDCalendarOrderRegisteredBundleSource(void)
{
    (void)dlopen(
        "/System/Library/PrivateFrameworks/IconServices.framework/"
        "IconServices", RTLD_NOW | RTLD_LOCAL);
    Class sourceClass = NSClassFromString(@"ISBundleIdentifierIcon");
    Class managerClass = NSClassFromString(@"ISIconManager");
    SEL initializer = sel_registerName("initWithBundleIdentifier:");
    SEL shared = sel_registerName("sharedInstance");
    SEL registerIcon = sel_registerName("findOrRegisterIcon:");
    id candidate = sourceClass &&
            [sourceClass instancesRespondToSelector:initializer]
        ? ((id (*)(id, SEL, id))objc_msgSend)(
            [sourceClass alloc], initializer, CNDCalendarBundleIdentifier)
        : nil;
    id manager = managerClass && [managerClass respondsToSelector:shared]
        ? ((id (*)(id, SEL))objc_msgSend)(managerClass, shared) : nil;
    id source = manager && candidate &&
            [manager respondsToSelector:registerIcon]
        ? ((id (*)(id, SEL, id))objc_msgSend)(
            manager, registerIcon, candidate)
        : nil;
    return CNDCalendarOrderBundleSourceValid(source) ? source : nil;
}

typedef struct {
    double width;
    double height;
} CNDCalendarOrderSize;

static id CNDCalendarOrderMakeDescriptor(int64_t appearance)
{
    Class descriptorClass = NSClassFromString(@"ISImageDescriptor");
    SEL factory = sel_registerName(
        "imageDescriptorWithIconVariant:options:");
    Method factoryMethod = descriptorClass
        ? class_getClassMethod(descriptorClass, factory) : NULL;
    const char *factoryTypes = factoryMethod
        ? method_getTypeEncoding(factoryMethod) : NULL;
    if (!factoryTypes || strcmp(factoryTypes, "@24@0:8i16i20")) {
        return nil;
    }
    id template = ((id (*)(id, SEL, int32_t, int32_t))objc_msgSend)(
        descriptorClass, factory, 0, 0);
    id descriptor = [template conformsToProtocol:@protocol(NSCopying)]
        ? [template copy] : nil;
    bool abi = descriptor &&
        CNDCalendarOrderMethodTypes(
            descriptor, sel_registerName("setSize:"),
            "v32@0:8{CGSize=dd}16") &&
        CNDCalendarOrderMethodTypes(
            descriptor, sel_registerName("setScale:"), "v24@0:8d16") &&
        CNDCalendarOrderMethodTypes(
            descriptor, sel_registerName("setAppearance:"),
            "v24@0:8q16") &&
        CNDCalendarOrderMethodTypes(
            descriptor, sel_registerName("setAppearanceVariant:"),
            "v24@0:8q16") &&
        CNDCalendarOrderMethodTypes(
            descriptor, sel_registerName("setVariantOptions:"),
            "v24@0:8Q16") &&
        CNDCalendarOrderMethodTypes(
            descriptor, sel_registerName("setIgnoreCache:"),
            "v20@0:8B16");
    if (!abi) return nil;

    CNDCalendarOrderSize size = {68.0, 68.0};
    ((void (*)(id, SEL, CNDCalendarOrderSize))objc_msgSend)(
        descriptor, sel_registerName("setSize:"), size);
    ((void (*)(id, SEL, double))objc_msgSend)(
        descriptor, sel_registerName("setScale:"), 3.0);
    ((void (*)(id, SEL, int64_t))objc_msgSend)(
        descriptor, sel_registerName("setAppearance:"), appearance);
    ((void (*)(id, SEL, int64_t))objc_msgSend)(
        descriptor, sel_registerName("setAppearanceVariant:"), 0);
    ((void (*)(id, SEL, uint64_t))objc_msgSend)(
        descriptor, sel_registerName("setVariantOptions:"), 0U);
    ((void (*)(id, SEL, BOOL))objc_msgSend)(
        descriptor, sel_registerName("setIgnoreCache:"), NO);
    return descriptor;
}

static NSString *CNDCalendarOrderSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class] || data.length == 0U ||
        data.length > UINT32_MAX) return @"-";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    char hex[CC_SHA256_DIGEST_LENGTH * 2U + 1U] = {0};
    for (NSUInteger index = 0U;
         index < CC_SHA256_DIGEST_LENGTH; index++) {
        snprintf(hex + index * 2U, 3U, "%02x", digest[index]);
    }
    return [NSString stringWithUTF8String:hex] ?: @"-";
}

static Class CNDCalendarOrderOriginalProviderClass(Class current)
{
    while (current &&
           !strncmp(class_getName(current), CNDCalendarSubclassPrefix,
                    strlen(CNDCalendarSubclassPrefix))) {
        current = class_getSuperclass(current);
    }
    return current;
}

static Class CNDCalendarOrderProviderSubclass(Class current)
{
    Class original = CNDCalendarOrderOriginalProviderClass(current);
    Method method = original ? class_getInstanceMethod(
        original, sel_registerName("preparedISIcon")) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (!original || !types || strcmp(types, "@16@0:8")) return Nil;

    char name[192] = {0};
    int length = snprintf(name, sizeof(name), "%s%s",
                          CNDCalendarSubclassPrefix,
                          class_getName(original));
    if (length <= 0 || (size_t)length >= sizeof(name)) return Nil;
    Class subclass = objc_getClass(name);
    if (!subclass) {
        subclass = objc_allocateClassPair(original, name, 0U);
        if (!subclass || !class_addMethod(
                subclass, sel_registerName("preparedISIcon"),
                (IMP)objc_getAssociatedObject, "@16@0:8")) {
            return Nil;
        }
        objc_registerClassPair(subclass);
    }
    Method installed = class_getInstanceMethod(
        subclass, sel_registerName("preparedISIcon"));
    return class_getSuperclass(subclass) == original && installed &&
        !strcmp(method_getTypeEncoding(installed), "@16@0:8") &&
        method_getImplementation(installed) == (IMP)objc_getAssociatedObject
        ? subclass : Nil;
}

static bool CNDCalendarOrderAddModel(
    id __unsafe_unretained *models, NSUInteger *count, id model,
    bool *truncated)
{
    if (!model || !models || !count) return false;
    for (NSUInteger index = 0U; index < *count; index++) {
        if (models[index] == model) return true;
    }
    if (*count >= CNDCalendarOrderModelCap) {
        if (truncated) *truncated = true;
        return false;
    }
    models[(*count)++] = model;
    return true;
}

static id CNDCalendarOrderSpringBoardManager(id *controllerOut,
                                              id *modelOut)
{
    id controller = CNDCalendarOrderObjectGetter(
        NSClassFromString(@"SBIconController"), "sharedInstance");
    id manager = CNDCalendarOrderObjectGetter(controller, "iconManager");
    if (!manager) {
        manager = CNDCalendarOrderObjectGetter(
            NSClassFromString(@"SBHIconManager"), "sharedInstance");
    }
    id model = CNDCalendarOrderObjectGetter(manager, "iconModel");
    if (!model) model = CNDCalendarOrderObjectGetter(manager, "model");
    if (controllerOut) *controllerOut = controller;
    if (modelOut) *modelOut = model;
    return manager;
}

static NSUInteger CNDCalendarOrderCollectModels(
    id __unsafe_unretained *models, bool *truncatedOut,
    NSUInteger *leafMatchesOut)
{
    if (truncatedOut) *truncatedOut = false;
    if (leafMatchesOut) *leafMatchesOut = 0U;
    NSUInteger count = 0U;
    bool truncated = false;
    NSString *target = CNDCalendarOrderTarget();

    if ([target isEqualToString:@"Spotlight"]) {
        Class ownerClass = NSClassFromString(@"SearchUIHomeScreenModel");
        id owner = CNDCalendarOrderObjectGetter(ownerClass, "sharedInstance");
        SEL materialize = sel_registerName(
            "appIconForApplicationBundleIdentifier:");
        id model = CNDCalendarOrderMethodTypes(
                owner, materialize, "@24@0:8@16")
            ? ((id (*)(id, SEL, id))objc_msgSend)(
                owner, materialize, CNDCalendarBundleIdentifier)
            : nil;
        if ([CNDCalendarOrderBundleIdentifier(model)
                isEqualToString:CNDCalendarBundleIdentifier]) {
            (void)CNDCalendarOrderAddModel(
                models, &count, model, &truncated);
        }
    } else {
        id model = nil;
        (void)CNDCalendarOrderSpringBoardManager(NULL, &model);
        SEL lookup = sel_registerName(
            "applicationIconForBundleIdentifier:");
        id canonical = CNDCalendarOrderMethodTypes(
                model, lookup, "@24@0:8@16")
            ? ((id (*)(id, SEL, id))objc_msgSend)(
                model, lookup, CNDCalendarBundleIdentifier)
            : nil;
        if ([CNDCalendarOrderBundleIdentifier(canonical)
                isEqualToString:CNDCalendarBundleIdentifier]) {
            (void)CNDCalendarOrderAddModel(
                models, &count, canonical, &truncated);
        }

        id leafMap = CNDCalendarOrderObjectGetter(
            model, "leafIconsUniquedByApplicationBundleIdentifier");
        NSArray *leaves = CNDCalendarOrderObjects(leafMap);
        NSUInteger bounded = MIN(
            leaves.count, (NSUInteger)CNDCalendarOrderLeafScanCap);
        if (leaves.count > bounded) truncated = true;
        NSUInteger leafMatches = 0U;
        for (NSUInteger index = 0U; index < bounded; index++) {
            id candidate = leaves[index];
            if (![CNDCalendarOrderBundleIdentifier(candidate)
                    isEqualToString:CNDCalendarBundleIdentifier]) continue;
            NSUInteger before = count;
            if (CNDCalendarOrderAddModel(
                    models, &count, candidate, &truncated) &&
                count > before) {
                leafMatches++;
            }
        }
        if (leafMatchesOut) *leafMatchesOut = leafMatches;
    }

    if (truncatedOut) *truncatedOut = truncated;
    return count;
}

static NSDictionary *CNDCalendarOrderRestore(void)
{
    NSMutableArray<NSDictionary *> *registry =
        CNDCalendarOrderRegistry(false);
    NSUInteger states = registry.count;
    bool ok = states <= CNDCalendarOrderModelCap;
    NSUInteger restored = 0U;
    NSUInteger reloads = 0U;
    for (NSDictionary *state in [registry copy]) {
        id model = state[@"model"];
        id provider = state[@"provider"];
        id replacement = state[@"source"];
        Class original = [state[@"originalClass"] pointerValue];
        bool one = model && provider && replacement && original;
        Class current = one ? object_getClass(provider) : Nil;
        if (one && current != original) {
            one = object_setClass(provider, original) == current;
        }
        if (one) {
            objc_setAssociatedObject(
                provider, sel_registerName("preparedISIcon"), nil,
                OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        id stockBefore = one
            ? CNDCalendarOrderObjectGetter(provider, "preparedISIcon") : nil;
        one = one && stockBefore != replacement &&
            CNDCalendarOrderStockSourceValid(stockBefore);
        if (one && CNDCalendarOrderVoidNoArgument(
                provider, "reloadIconImage")) {
            reloads++;
        } else {
            one = false;
        }
        id stockAfter = one
            ? CNDCalendarOrderObjectGetter(provider, "preparedISIcon") : nil;
        one = one && stockAfter != replacement &&
            CNDCalendarOrderStockSourceValid(stockAfter);
        if (one) restored++;
        ok = ok && one;
    }
    if (ok) CNDCalendarOrderClearRegistry();
    return @{
        @"ok": @(ok),
        @"stage": ok ? @"calendar-provider-restored" :
            @"calendar-provider-restore",
        @"stateCount": @(states),
        @"restoredStateCount": @(restored),
        @"reloadPasses": @(reloads),
    };
}

static NSDictionary *CNDCalendarOrderInstall(void)
{
    NSMutableArray<NSDictionary *> *registry =
        CNDCalendarOrderRegistry(true);
    if (!registry || registry.count > CNDCalendarOrderModelCap) {
        return @{
            @"ok": @NO,
            @"stage": @"calendar-provider-registry-invalid",
        };
    }

    if (registry.count > 0U) {
        bool ready = true;
        NSUInteger verified = 0U;
        for (NSDictionary *state in registry) {
            id model = state[@"model"];
            id provider = state[@"provider"];
            id source = state[@"source"];
            bool one = model && provider &&
                CNDCalendarOrderBundleSourceValid(source) &&
                CNDCalendarOrderObjectGetter(model, "imageProvider") ==
                    provider &&
                CNDCalendarOrderObjectGetter(provider, "delegate") == model &&
                CNDCalendarOrderObjectGetter(provider, "preparedISIcon") ==
                    source;
            if (one) verified++;
            ready = ready && one;
        }
        return @{
            @"ok": @(ready),
            @"stage": ready ? @"calendar-provider-source-ready" :
                @"calendar-provider-source-verify",
            @"stateCount": @(registry.count),
            @"configuredProviderCount": @(verified),
            @"newStateCount": @0,
            @"reloadPasses": @0,
            @"generationAdvanceCount": @0,
            @"fastPath": @YES,
        };
    }

    id __unsafe_unretained models[CNDCalendarOrderModelCap] = {nil};
    bool truncated = false;
    NSUInteger leafMatches = 0U;
    NSUInteger modelCount = CNDCalendarOrderCollectModels(
        models, &truncated, &leafMatches);
    bool ok = modelCount > 0U && !truncated;
    NSUInteger configured = 0U;
    NSUInteger reloads = 0U;
    NSUInteger generations = 0U;
    id __unsafe_unretained providers[CNDCalendarOrderModelCap] = {nil};
    NSUInteger providerCount = 0U;

    for (NSUInteger index = 0U; ok && index < modelCount; index++) {
        id model = models[index];
        id provider = CNDCalendarOrderObjectGetter(model, "imageProvider");
        bool duplicate = false;
        for (NSUInteger other = 0U; other < providerCount; other++) {
            duplicate |= providers[other] == provider;
        }
        bool one = provider && !duplicate &&
            CNDCalendarOrderMethodTypes(
                provider, sel_registerName("preparedISIcon"), "@16@0:8") &&
            CNDCalendarOrderMethodTypes(
                provider, sel_registerName("reloadIconImage"), "v16@0:8") &&
            CNDCalendarOrderMethodTypes(
                provider, sel_registerName("delegate"), "@16@0:8") &&
            CNDCalendarOrderObjectGetter(provider, "delegate") == model &&
            CNDCalendarOrderStockSourceValid(
                CNDCalendarOrderObjectGetter(provider, "preparedISIcon"));
        id source = one ? CNDCalendarOrderRegisteredBundleSource() : nil;
        Class original = one
            ? CNDCalendarOrderOriginalProviderClass(object_getClass(provider))
            : Nil;
        Class subclass = one
            ? CNDCalendarOrderProviderSubclass(original) : Nil;
        one = one && CNDCalendarOrderBundleSourceValid(source) &&
            original && subclass;
        NSUInteger before = one
            ? CNDCalendarOrderGeneration(model) : NSNotFound;

        if (one) {
            objc_setAssociatedObject(
                provider, sel_registerName("preparedISIcon"), source,
                OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            Class previous = object_setClass(provider, subclass);
            one = previous == original &&
                CNDCalendarOrderObjectGetter(provider, "preparedISIcon") ==
                    source;
        }
        NSDictionary *state = one ? @{
            @"model": model,
            @"provider": provider,
            @"source": source,
            @"originalClass": [NSValue valueWithPointer:(__bridge void *)original],
        } : nil;
        if (one) [registry addObject:state];
        one = one && CNDCalendarOrderVoidNoArgument(
            provider, "reloadIconImage");
        NSUInteger after = one
            ? CNDCalendarOrderGeneration(model) : NSNotFound;
        bool advanced = one && before != NSNotFound && after == before + 1U;
        one = one && advanced &&
            CNDCalendarOrderObjectGetter(provider, "preparedISIcon") == source;
        if (one) {
            providers[providerCount++] = provider;
            configured++;
            reloads++;
            generations++;
        }
        ok = ok && one;
    }

    ok = ok && registry.count == modelCount &&
        configured == modelCount && providerCount == modelCount &&
        reloads == modelCount && generations == modelCount;
    if (!ok) {
        (void)CNDCalendarOrderRestore();
    }
    return @{
        @"ok": @(ok),
        @"stage": ok ? @"calendar-provider-source-ready" :
            @"calendar-provider-source-verify",
        @"activeModelCount": @(modelCount),
        @"liveLeafModelCount": @(leafMatches),
        @"activeModelsTruncated": @(truncated),
        @"activeProviderCount": @(providerCount),
        @"configuredProviderCount": @(configured),
        @"newStateCount": @(configured),
        @"stateCount": @(registry.count),
        @"reloadPasses": @(reloads),
        @"generationAdvanceCount": @(generations),
        @"fastPath": @NO,
    };
}

static NSDictionary *CNDCalendarOrderReloadRetained(void)
{
    NSMutableArray<NSDictionary *> *registry =
        CNDCalendarOrderRegistry(false);
    NSUInteger states = registry.count;
    bool ok = states > 0U && states <= CNDCalendarOrderModelCap;
    NSUInteger verified = 0U;
    NSUInteger reloads = 0U;
    NSUInteger generations = 0U;
    for (NSDictionary *state in [registry copy]) {
        id model = state[@"model"];
        id provider = state[@"provider"];
        id source = state[@"source"];
        bool one = model && provider &&
            CNDCalendarOrderBundleSourceValid(source) &&
            CNDCalendarOrderObjectGetter(model, "imageProvider") ==
                provider &&
            CNDCalendarOrderObjectGetter(provider, "delegate") == model &&
            CNDCalendarOrderObjectGetter(provider, "preparedISIcon") ==
                source;
        NSUInteger before = one
            ? CNDCalendarOrderGeneration(model) : NSNotFound;
        if (one && CNDCalendarOrderVoidNoArgument(
                provider, "reloadIconImage")) {
            reloads++;
        } else {
            one = false;
        }
        NSUInteger after = one
            ? CNDCalendarOrderGeneration(model) : NSNotFound;
        bool advanced = one && before != NSNotFound &&
            after == before + 1U;
        if (advanced) generations++;
        one = one && advanced &&
            CNDCalendarOrderObjectGetter(provider, "preparedISIcon") ==
                source;
        if (one) verified++;
        ok = ok && one;
    }
    ok = ok && verified == states && reloads == states &&
        generations == states;
    return @{
        @"ok": @(ok),
        @"stage": ok ? @"calendar-retained-provider-reloaded" :
            @"calendar-retained-provider-reload",
        @"stateCount": @(states),
        @"configuredProviderCount": @(verified),
        @"reloadPasses": @(reloads),
        @"generationAdvanceCount": @(generations),
        @"fastPath": @NO,
        @"retainedSource": @YES,
    };
}

static NSDictionary *CNDCalendarOrderPurgeSourceCaches(bool reloadAfterPurge)
{
    NSMutableArray<NSDictionary *> *registry =
        CNDCalendarOrderRegistry(false);
    NSUInteger states = registry.count;
    bool ok = states > 0U && states <= CNDCalendarOrderModelCap;
    id __unsafe_unretained caches[CNDCalendarOrderModelCap] = {nil};
    NSUInteger cacheCount = 0U;
    NSUInteger purged = 0U;
    NSUInteger entriesBefore = 0U;
    NSUInteger entriesAfter = 0U;

    for (NSDictionary *state in [registry copy]) {
        id source = state[@"source"];
        bool one = CNDCalendarOrderBundleSourceValid(source) &&
            CNDCalendarOrderMethodTypes(
                source, sel_registerName("imageCache"), "@16@0:8");
        id cache = one
            ? CNDCalendarOrderObjectGetter(source, "imageCache") : nil;
        one = one && cache &&
            [cache isKindOfClass:NSClassFromString(@"ISImageCache")] &&
            CNDCalendarOrderMethodTypes(
                cache, sel_registerName("imageBagsByDescriptor"),
                "@16@0:8") &&
            CNDCalendarOrderMethodTypes(
                cache, sel_registerName("setImageBagsByDescriptor:"),
                "v24@0:8@16");
        bool duplicate = false;
        for (NSUInteger index = 0U; index < cacheCount; index++) {
            duplicate |= caches[index] == cache;
        }
        if (one && !duplicate) {
            id before = CNDCalendarOrderObjectGetter(
                cache, "imageBagsByDescriptor");
            entriesBefore += [before respondsToSelector:@selector(count)]
                ? [before count] : 0U;
            NSMutableDictionary *empty = [NSMutableDictionary dictionary];
            @try {
                ((void (*)(id, SEL, id))objc_msgSend)(
                    cache, sel_registerName("setImageBagsByDescriptor:"),
                    empty);
            } @catch (__unused NSException *exception) {
                one = false;
            }
            id after = one ? CNDCalendarOrderObjectGetter(
                cache, "imageBagsByDescriptor") : nil;
            NSUInteger afterCount =
                [after respondsToSelector:@selector(count)]
                ? [after count] : NSNotFound;
            one = one && after && afterCount == 0U;
            if (one) {
                caches[cacheCount++] = cache;
                purged++;
                entriesAfter += afterCount;
            }
        }
        ok = ok && one;
    }

    NSDictionary *reload = ok && reloadAfterPurge
        ? CNDCalendarOrderReloadRetained() : @{};
    ok = ok && purged == cacheCount && cacheCount > 0U &&
        (!reloadAfterPurge || [reload[@"ok"] boolValue]);
    return @{
        @"ok": @(ok),
        @"stage": ok ? @"calendar-source-cache-purged-and-reloaded" :
            @"calendar-source-cache-purge-reload",
        @"stateCount": @(states),
        @"sourceCacheCount": @(cacheCount),
        @"purgedSourceCacheCount": @(purged),
        @"sourceCacheEntriesBefore": @(entriesBefore),
        @"sourceCacheEntriesAfter": @(entriesAfter),
        @"reload": reload,
    };
}

static NSDictionary *CNDCalendarOrderPurgeSourceCachesAndReload(void)
{
    return CNDCalendarOrderPurgeSourceCaches(true);
}

/* A provider generation advance is not a demand for pixels when Calendar is
 * offscreen. Exercise the real ISIcon contract synchronously so this proof
 * does not depend on a mounted SBIconImageView. ISIcon's implementation first
 * calls imageForDescriptor:, falls through to the persistent store on the
 * purged cache, and returns the resulting IFImage. */
static NSDictionary *CNDCalendarOrderPrepareRetainedSources(void)
{
    NSMutableArray<NSDictionary *> *registry =
        CNDCalendarOrderRegistry(false);
    NSUInteger states = registry.count;
    bool ok = states > 0U && states <= CNDCalendarOrderModelCap;
    id __unsafe_unretained sources[CNDCalendarOrderModelCap] = {nil};
    NSUInteger sourceCount = 0U;
    NSUInteger preparedCount = 0U;
    NSUInteger exactDataCount = 0U;
    NSMutableArray<NSDictionary *> *responses = [NSMutableArray array];

    for (NSDictionary *state in [registry copy]) {
        id source = state[@"source"];
        bool one = CNDCalendarOrderBundleSourceValid(source) &&
            CNDCalendarOrderMethodTypes(
                source, sel_registerName("prepareImageForDescriptor:"),
                "@24@0:8@16");
        bool duplicate = false;
        for (NSUInteger index = 0U; index < sourceCount; index++) {
            duplicate |= sources[index] == source;
        }
        if (!one || duplicate) {
            ok = ok && one;
            continue;
        }
        if (sourceCount >= CNDCalendarOrderModelCap) {
            ok = false;
            break;
        }
        sources[sourceCount++] = source;

        id descriptor = CNDCalendarOrderMakeDescriptor(0);
        id image = descriptor
            ? ((id (*)(id, SEL, id))objc_msgSend)(
                source, sel_registerName("prepareImageForDescriptor:"),
                descriptor)
            : nil;
        bool placeholder = image &&
            CNDCalendarOrderMethodTypes(
                image, sel_registerName("placeholder"), "B16@0:8")
            ? ((BOOL (*)(id, SEL))objc_msgSend)(
                image, sel_registerName("placeholder"))
            : true;
        NSData *data = CNDCalendarOrderObjectGetter(image, "data");
        NSUUID *uuid = CNDCalendarOrderObjectGetter(image, "UUID");
        one = descriptor && image && !placeholder &&
            [data isKindOfClass:NSData.class] && data.length > 0U;
        if (image) preparedCount++;
        if (one) exactDataCount++;
        [responses addObject:@{
            @"source": [NSString stringWithFormat:@"%p", source],
            @"image": [NSString stringWithFormat:@"%p", image],
            @"uuid": [uuid isKindOfClass:NSUUID.class]
                ? uuid.UUIDString : @"-",
            @"dataLength": @([data isKindOfClass:NSData.class]
                ? data.length : 0U),
            @"dataSHA256": CNDCalendarOrderSHA256(data),
            @"placeholder": @(placeholder),
        }];
        ok = ok && one;
    }
    ok = ok && sourceCount > 0U && preparedCount == sourceCount &&
        exactDataCount == sourceCount;
    return @{
        @"ok": @(ok),
        @"stage": ok ? @"calendar-source-prepared-from-store" :
            @"calendar-source-prepare-failed",
        @"stateCount": @(states),
        @"sourceCount": @(sourceCount),
        @"preparedSourceCount": @(preparedCount),
        @"exactDataCount": @(exactDataCount),
        @"responses": responses,
    };
}

static NSDictionary *CNDCalendarOrderSourceCacheSnapshot(void)
{
    NSMutableArray<NSDictionary *> *registry =
        CNDCalendarOrderRegistry(false);
    NSUInteger states = registry.count;
    bool ok = states > 0U && states <= CNDCalendarOrderModelCap;
    id __unsafe_unretained caches[CNDCalendarOrderModelCap] = {nil};
    NSUInteger cacheCount = 0U;
    NSUInteger populated = 0U;
    NSUInteger entries = 0U;

    for (NSDictionary *state in [registry copy]) {
        id source = state[@"source"];
        bool one = CNDCalendarOrderBundleSourceValid(source) &&
            CNDCalendarOrderMethodTypes(
                source, sel_registerName("imageCache"), "@16@0:8");
        id cache = one
            ? CNDCalendarOrderObjectGetter(source, "imageCache") : nil;
        one = one && cache &&
            [cache isKindOfClass:NSClassFromString(@"ISImageCache")] &&
            CNDCalendarOrderMethodTypes(
                cache, sel_registerName("imageBagsByDescriptor"),
                "@16@0:8");
        bool duplicate = false;
        for (NSUInteger index = 0U; index < cacheCount; index++) {
            duplicate |= caches[index] == cache;
        }
        if (one && !duplicate) {
            id bags = CNDCalendarOrderObjectGetter(
                cache, "imageBagsByDescriptor");
            NSUInteger count =
                [bags respondsToSelector:@selector(count)]
                ? [bags count] : NSNotFound;
            one = bags && count != NSNotFound;
            if (one) {
                caches[cacheCount++] = cache;
                entries += count;
                if (count > 0U) populated++;
            }
        }
        ok = ok && one;
    }
    bool refilled = ok && cacheCount > 0U && populated == cacheCount;
    return @{
        @"ok": @(ok),
        @"stage": @"calendar-source-cache-snapshot",
        @"stateCount": @(states),
        @"sourceCacheCount": @(cacheCount),
        @"populatedSourceCacheCount": @(populated),
        @"sourceCacheEntryCount": @(entries),
        @"allSourceCachesPopulated": @(refilled),
    };
}

static void CNDCalendarOrderAddCache(
    id __unsafe_unretained *caches, NSUInteger *count, id cache)
{
    if (!cache || !caches || !count) return;
    for (NSUInteger index = 0U; index < *count; index++) {
        if (caches[index] == cache) return;
    }
    if (*count < CNDCalendarOrderCacheCap) caches[(*count)++] = cache;
}

static NSDictionary *CNDCalendarOrderBroadRefresh(void)
{
    id controller = nil;
    id model = nil;
    id manager = CNDCalendarOrderSpringBoardManager(&controller, &model);
    id iconBefore = CNDCalendarOrderObjectGetter(manager, "iconImageCache");
    id folderBefore = CNDCalendarOrderObjectGetter(
        manager, "folderIconImageCache");
    CNDCalendarOrderLog(
        "[CND_CALENDAR_ORDER] CACHE phase=before-reset manager=%p "
        "icon=%p folder=%p\n", manager, iconBefore, folderBefore);
    bool reset = CNDCalendarOrderVoidNoArgument(
        manager, "resetAllIconImageCaches");
    id iconAfter = CNDCalendarOrderObjectGetter(manager, "iconImageCache");
    id folderAfter = CNDCalendarOrderObjectGetter(
        manager, "folderIconImageCache");
    CNDCalendarOrderLog(
        "[CND_CALENDAR_ORDER] CACHE phase=after-reset manager=%p "
        "icon=%p folder=%p icon-replaced=%d folder-replaced=%d\n",
        manager, iconAfter, folderAfter, iconBefore != iconAfter,
        folderBefore != folderAfter);

    id __unsafe_unretained caches[CNDCalendarOrderCacheCap] = {nil};
    NSUInteger cacheCount = 0U;
    CNDCalendarOrderAddCache(caches, &cacheCount, iconAfter);
    static const char *const controllerCaches[] = {
        "notificationIconImageCache", "tableUIIconImageCache",
        "appSwitcherHeaderIconImageCache",
    };
    for (NSUInteger index = 0U;
         index < sizeof(controllerCaches) / sizeof(controllerCaches[0]);
         index++) {
        CNDCalendarOrderAddCache(
            caches, &cacheCount,
            CNDCalendarOrderObjectGetter(controller, controllerCaches[index]));
    }

    id library = CNDCalendarOrderObjectGetter(
        manager, "trailingLibraryViewController");
    if (!library) {
        library = CNDCalendarOrderObjectGetter(
            manager, "overlayLibraryViewController");
    }
    CNDCalendarOrderAddCache(
        caches, &cacheCount,
        CNDCalendarOrderObjectGetter(library, "iconImageCache"));
    id directTable = CNDCalendarOrderObjectGetter(
        library, "iconTableViewController");
    id container = CNDCalendarOrderObjectGetter(
        library, "containerViewController");
    id searchTable = CNDCalendarOrderObjectGetter(
        container, "searchResultsController");
    CNDCalendarOrderAddCache(
        caches, &cacheCount,
        CNDCalendarOrderObjectGetter(directTable, "iconImageCache"));
    CNDCalendarOrderAddCache(
        caches, &cacheCount,
        CNDCalendarOrderObjectGetter(searchTable, "iconImageCache"));
    NSUInteger purged = 0U;
    for (NSUInteger index = 0U; index < cacheCount; index++) {
        if (CNDCalendarOrderVoidNoArgument(
                caches[index], "purgeAllCachedImages")) purged++;
    }

    id __unsafe_unretained models[CNDCalendarOrderModelCap] = {nil};
    bool truncated = false;
    NSUInteger leafMatches = 0U;
    NSUInteger modelCount = CNDCalendarOrderCollectModels(
        models, &truncated, &leafMatches);
    NSUInteger iconReloads = 0U;
    for (NSUInteger index = 0U; index < modelCount; index++) {
        if (CNDCalendarOrderVoidNoArgument(
                models[index], "reloadIconImage")) iconReloads++;
    }

    bool folderRebuilt = CNDCalendarOrderVoidNoArgument(
        folderAfter, "rebuildAllCachedFolderImages");
    id folderController = CNDCalendarOrderObjectGetter(
        library, "folderController");
    bool podReloaded = CNDCalendarOrderVoidNoArgument(
        folderController, "_reloadAppIcons");
    bool libraryEnqueued = CNDCalendarOrderVoidNoArgument(
        library, "_enqueueAppLibraryUpdate");
    bool directApps = CNDCalendarOrderVoidNoArgument(
        directTable, "_reloadAppIcons");
    bool directCells = CNDCalendarOrderVoidNoArgument(
        directTable, "_reloadVisibleCells");
    bool searchApps = directTable == searchTable ||
        CNDCalendarOrderVoidNoArgument(searchTable, "_reloadAppIcons");
    bool searchCells = directTable == searchTable ||
        CNDCalendarOrderVoidNoArgument(searchTable, "_reloadVisibleCells");
    bool relayout = CNDCalendarOrderBoolNoArgument(manager, "relayout");
    bool ok = manager && model && reset && iconReloads == modelCount &&
        modelCount > 0U && !truncated && relayout;
    return @{
        @"ok": @(ok),
        @"stage": ok ? @"springboard-calendar-refresh-complete" :
            @"springboard-calendar-refresh-incomplete",
        @"cacheCount": @(cacheCount),
        @"purgedCacheCount": @(purged),
        @"iconCacheReplaced": @(iconBefore != iconAfter),
        @"folderCacheReplaced": @(folderBefore != folderAfter),
        @"activeModelCount": @(modelCount),
        @"liveLeafModelCount": @(leafMatches),
        @"iconReloadCount": @(iconReloads),
        @"folderRebuilt": @(folderRebuilt),
        @"podReloaded": @(podReloaded),
        @"libraryEnqueued": @(libraryEnqueued),
        @"directTableReload": @(directApps && directCells),
        @"searchTableReload": @(searchApps && searchCells),
        @"relayout": @(relayout),
    };
}

static NSDictionary *CNDCalendarOrderStep(
    NSMutableArray<NSDictionary *> *steps, NSString *label,
    NSDictionary *(^operation)(void))
{
    CNDCalendarOrderMark(label, "begin");
    NSDictionary *result = operation ? operation() : nil;
    CNDCalendarOrderMark(label, "end");
    NSDictionary *step = @{
        @"label": label,
        @"result": result ?: @{
            @"ok": @NO,
            @"stage": @"missing-operation",
        },
    };
    [steps addObject:step];
    return result ?: @{};
}

static bool CNDCalendarOrderStepsSucceeded(NSArray<NSDictionary *> *steps)
{
    if (steps.count == 0U) return false;
    for (NSDictionary *step in steps) {
        if (![step[@"result"][@"ok"] boolValue]) return false;
    }
    return true;
}

static void CNDCalendarOrderFinish(
    NSString *action, NSArray<NSDictionary *> *steps)
{
    bool ok = CNDCalendarOrderStepsSucceeded(steps);
    NSDictionary *result = @{
        @"ok": @(ok),
        @"nonce": @(CND_CALENDAR_ORDER_NONCE),
        @"action": action,
        @"target": CNDCalendarOrderTarget(),
        @"directTargetDylib": @YES,
        @"cyanideSymbolsUsed": @NO,
        @"steps": steps,
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:result
                                                   options:0
                                                     error:nil];
    NSString *serialized = json
        ? [[NSString alloc] initWithData:json
                                encoding:NSUTF8StringEncoding]
        : @"{}";
    CNDCalendarOrderLog(
        "[CND_CALENDAR_ORDER] COMPLETE nonce=%s ok=%d result=%s\n",
        CND_CALENDAR_ORDER_NONCE, ok ? 1 : 0,
        serialized.UTF8String ?: "{}");
}

static void CNDCalendarOrderRun(void)
{
    NSString *action = @(CND_CALENDAR_ORDER_ACTION);
    NSMutableArray<NSDictionary *> *steps = [NSMutableArray array];

    if ([action isEqualToString:@"springboard-refresh-then-calendar"]) {
        (void)CNDCalendarOrderStep(
            steps, @"restore-dynamic-source", ^{
                return CNDCalendarOrderRestore();
            });
        (void)CNDCalendarOrderStep(
            steps, @"refresh-before-calendar", ^{
                return CNDCalendarOrderBroadRefresh();
            });
        (void)CNDCalendarOrderStep(
            steps, @"calendar-terminal", ^{
                return CNDCalendarOrderInstall();
            });
    } else if ([action isEqualToString:
                   @"springboard-calendar-then-refresh"] ||
               [action isEqualToString:@"springboard-combined-current"]) {
        (void)CNDCalendarOrderStep(
            steps, @"restore-dynamic-source", ^{
                return CNDCalendarOrderRestore();
            });
        (void)CNDCalendarOrderStep(
            steps, @"calendar-before-refresh", ^{
                return CNDCalendarOrderInstall();
            });
        (void)CNDCalendarOrderStep(
            steps, @"refresh-after-calendar", ^{
                return CNDCalendarOrderBroadRefresh();
            });
    } else if ([action isEqualToString:@"springboard-fast-path"] ||
               [action isEqualToString:@"spotlight-calendar"]) {
        (void)CNDCalendarOrderStep(
            steps, @"restore-dynamic-source", ^{
                return CNDCalendarOrderRestore();
            });
        (void)CNDCalendarOrderStep(
            steps, @"calendar-fresh", ^{
                return CNDCalendarOrderInstall();
            });
        (void)CNDCalendarOrderStep(
            steps, @"calendar-fast-path", ^{
                return CNDCalendarOrderInstall();
            });
    } else if ([action isEqualToString:@"springboard-restore-only"] ||
               [action isEqualToString:@"spotlight-restore-only"]) {
        (void)CNDCalendarOrderStep(
            steps, @"restore-dynamic-source", ^{
                return CNDCalendarOrderRestore();
            });
    } else if ([action isEqualToString:@"springboard-fast-path-only"] ||
               [action isEqualToString:@"spotlight-fast-path-only"]) {
        (void)CNDCalendarOrderStep(
            steps, @"calendar-fast-path-only", ^{
                return CNDCalendarOrderInstall();
            });
    } else if ([action isEqualToString:@"springboard-reload-only"] ||
               [action isEqualToString:@"spotlight-reload-only"]) {
        (void)CNDCalendarOrderStep(
            steps, @"calendar-retained-reload-only", ^{
                return CNDCalendarOrderReloadRetained();
            });
    } else if ([action isEqualToString:
                   @"springboard-source-cache-reload"] ||
               [action isEqualToString:
                   @"spotlight-source-cache-reload"]) {
        (void)CNDCalendarOrderStep(
            steps, @"calendar-source-cache-reload", ^{
                return CNDCalendarOrderPurgeSourceCachesAndReload();
            });
    } else if ([action isEqualToString:
                   @"springboard-source-cache-refill-barrier"] ||
               [action isEqualToString:
                   @"spotlight-source-cache-refill-barrier"]) {
        (void)CNDCalendarOrderStep(
            steps, @"calendar-source-cache-reload", ^{
                return CNDCalendarOrderPurgeSourceCachesAndReload();
            });
        (void)CNDCalendarOrderStep(
            steps, @"calendar-source-cache-immediate", ^{
                return CNDCalendarOrderSourceCacheSnapshot();
            });
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_MSEC),
            dispatch_get_main_queue(), ^{
                CNDCalendarOrderMark(
                    @"calendar-source-cache-after-20ms", "begin");
                NSDictionary *snapshot =
                    CNDCalendarOrderSourceCacheSnapshot();
                NSMutableDictionary *required =
                    [snapshot mutableCopy];
                bool refilled =
                    [snapshot[@"allSourceCachesPopulated"] boolValue];
                required[@"ok"] = @(refilled);
                required[@"stage"] = refilled
                    ? @"calendar-source-cache-refilled"
                    : @"calendar-source-cache-refill-timeout";
                CNDCalendarOrderMark(
                    @"calendar-source-cache-after-20ms", "end");
                [steps addObject:@{
                    @"label": @"calendar-source-cache-after-20ms",
                    @"result": required,
                }];
                CNDCalendarOrderFinish(action, steps);
        });
        return;
    } else if ([action isEqualToString:
                   @"springboard-source-prepare-reload"] ||
               [action isEqualToString:
                   @"spotlight-source-prepare-reload"]) {
        (void)CNDCalendarOrderStep(
            steps, @"calendar-source-cache-purge", ^{
                return CNDCalendarOrderPurgeSourceCaches(false);
            });
        (void)CNDCalendarOrderStep(
            steps, @"calendar-source-prepare", ^{
                return CNDCalendarOrderPrepareRetainedSources();
            });
        (void)CNDCalendarOrderStep(
            steps, @"calendar-provider-reload", ^{
                return CNDCalendarOrderReloadRetained();
            });
    } else {
        [steps addObject:@{
            @"label": @"invalid-action",
            @"result": @{
                @"ok": @NO,
                @"stage": @"invalid-action",
            },
        }];
    }

    CNDCalendarOrderFinish(action, steps);
}

__attribute__((constructor))
static void CNDCalendarOrderStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_CALENDAR_ORDER_OUTPUT_TOKEN[0] && consume
            ? consume(CND_CALENDAR_ORDER_OUTPUT_TOKEN) : -1;
        gCNDCalendarOrderFD = open(
            CND_CALENDAR_ORDER_OUTPUT_PATH,
            O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
        if (gCNDCalendarOrderFD < 0) return;
        CNDCalendarOrderLog(
            "[CND_CALENDAR_ORDER] START nonce=%s action=%s target=%s "
            "pid=%d token=%lld direct=1 cyanide-symbols=0\n",
            CND_CALENDAR_ORDER_NONCE, CND_CALENDAR_ORDER_ACTION,
            CNDCalendarOrderTarget().UTF8String ?: "-", getpid(),
            (long long)token);
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, 500 * NSEC_PER_MSEC),
            dispatch_get_main_queue(), ^{
                CNDCalendarOrderRun();
            });
    }
}
