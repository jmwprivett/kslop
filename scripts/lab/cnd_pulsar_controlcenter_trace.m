#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <CommonCrypto/CommonDigest.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef CND_PULSAR_TRACE_OUTPUT_TOKEN
#define CND_PULSAR_TRACE_OUTPUT_TOKEN ""
#endif

#ifndef CND_PULSAR_TRACE_DURATION
#define CND_PULSAR_TRACE_DURATION 180
#endif

#ifndef CND_PULSAR_TRACE_REPORT_PATH
#define CND_PULSAR_TRACE_REPORT_PATH \
    "/var/tmp/cyanide-pulsar-controlcenter-trace.log"
#endif

#ifndef CND_PULSAR_TRACE_CONNECTIVITY
#define CND_PULSAR_TRACE_CONNECTIVITY 0
#endif

/*
 * VM-only Pulsar Control Center route tracer.
 *
 * Pulsar v2 used two delivery mechanisms: named renditions from per-module
 * Assets.car files and CAPackage-backed .ca/main.caml animations. This probe
 * preserves normal execution while observing those routes, the CCUI glyph
 * setters that consume them, and the modern CCUI/CHUI control hosts.
 *
 * It never writes a system path, replaces an asset, changes a control state,
 * or calls a private presentation API. The method wrappers are process-local
 * and disappear when SpringBoard exits.
 */

static const char *const CNDReportPath =
    CND_PULSAR_TRACE_REPORT_PATH;

#if CND_PULSAR_TRACE_CONNECTIVITY
static const char *const CNDConnectivityExportDirectory =
    "/var/tmp/cyanide-pulsar-connectivity-assets";
#endif

enum {
    CNDHookCap = 256,
    CNDEventCap = 12000,
    CNDInventoryMemberCap = 96,
    CNDViewCap = 3072,
    CNDViewDepthCap = 64,
};

typedef enum {
    CNDABINone = 0,
    CNDABIObject0,
    CNDABIObject1,
    CNDABIObject2,
    CNDABIObject3,
    CNDABIObject3Pointer,
    CNDABIVoidObject,
    CNDABIVoidInteger,
} CNDHookABI;

typedef struct {
    Class targetClass;
    SEL selector;
    IMP original;
    CNDHookABI abi;
    const char *logicalClassName;
    const char *selectorName;
    bool classMethod;
} CNDHook;

static CNDHook gHooks[CNDHookCap];
static _Atomic unsigned gHookCount;
static _Atomic unsigned gEventCount;
static _Atomic bool gTraceActive;
static int gReportFD = -1;
static dispatch_source_t gTimer;
static NSHashTable<UIViewController *> *gSeenControllers;
static NSMapTable<UIView *, NSString *> *gViewSignatures;
static __thread unsigned gWrapperDepth;
#if CND_PULSAR_TRACE_CONNECTIVITY
static NSMutableSet<NSString *> *gConnectivityFingerprints;
#endif

static void CNDLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDLog(const char *format, ...)
{
    if (gReportFD < 0) return;
    char line[8192] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t count = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gReportFD, line, count);
}

static NSString *CNDToken(NSString *value)
{
    if (![value isKindOfClass:NSString.class] || value.length == 0U) {
        return @"-";
    }
    NSMutableString *result = [NSMutableString string];
    NSUInteger limit = MIN(value.length, 512U);
    for (NSUInteger index = 0; index < limit; index++) {
        unichar character = [value characterAtIndex:index];
        if (character == '\t' || character == '\n' || character == '\r') {
            [result appendString:@" "];
        } else if (character >= 32U && character < 127U) {
            [result appendFormat:@"%C", character];
        } else {
            [result appendString:@"?"];
        }
    }
    return result.length ? result : @"-";
}

static const char *CNDClassName(id object)
{
    return object ? class_getName(object_getClass(object)) : "-";
}

static const char *CNDSkipQualifiers(const char *type)
{
    while (type && *type && strchr("rnNoORV", *type)) type++;
    return type ?: "";
}

static id CNDSafeObjectGetter(id object, const char *name)
{
    if (!object || !name) return nil;
    SEL selector = sel_registerName(name);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return nil;
    char *returnCopy = method_copyReturnType(method);
    const char *returnType = CNDSkipQualifiers(returnCopy);
    bool valid = returnType && (*returnType == '@' || *returnType == '#');
    free(returnCopy);
    if (!valid) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static NSString *CNDIdentity(id object)
{
    if (!object) return @"-";
    static const char *const getters[] = {
        "moduleIdentifier", "bundleIdentifier", "containerBundleIdentifier",
        "applicationBundleIdentifier", "uniqueIdentifier", "identifier",
        "packageName", "packageURL", "glyphState", "stateName", "kind",
    };
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    for (size_t index = 0;
         index < sizeof(getters) / sizeof(getters[0]); index++) {
        id value = CNDSafeObjectGetter(object, getters[index]);
        NSString *text = nil;
        if ([value isKindOfClass:NSString.class]) {
            text = value;
        } else if ([value isKindOfClass:NSURL.class]) {
            text = [(NSURL *)value path] ?: [(NSURL *)value absoluteString];
        } else if ([value isKindOfClass:NSNumber.class]) {
            text = [(NSNumber *)value stringValue];
        }
        if (text.length) {
            [parts addObject:[NSString stringWithFormat:@"%s=%@",
                              getters[index], CNDToken(text)]];
        }
    }
    return parts.count ? [parts componentsJoinedByString:@";"] : @"-";
}

static NSString *CNDDescribe(id object)
{
    if (!object) return @"-";
    if ([object isKindOfClass:NSString.class]) return CNDToken(object);
    if ([object isKindOfClass:NSURL.class]) {
        NSURL *url = object;
        return CNDToken(url.path ?: url.absoluteString);
    }
    if ([object isKindOfClass:NSBundle.class]) {
        NSBundle *bundle = object;
        return CNDToken([NSString stringWithFormat:@"%@|%@",
                         bundle.bundleIdentifier ?: @"-",
                         bundle.bundlePath ?: @"-"]);
    }
    if ([object isKindOfClass:UIImage.class]) {
        UIImage *image = object;
        return [NSString stringWithFormat:@"%.2fx%.2f@%.3f;rendering=%ld",
                image.size.width, image.size.height, image.scale,
                (long)image.renderingMode];
    }
    if ([object isKindOfClass:NSDictionary.class]) {
        return [NSString stringWithFormat:@"count=%lu",
                (unsigned long)[(NSDictionary *)object count]];
    }
    if ([object isKindOfClass:NSArray.class]) {
        return [NSString stringWithFormat:@"count=%lu",
                (unsigned long)[(NSArray *)object count]];
    }
    NSString *identity = CNDIdentity(object);
    return ![identity isEqualToString:@"-"] ? identity
        : [NSString stringWithFormat:@"<%s:%p>", CNDClassName(object), object];
}

#if CND_PULSAR_TRACE_CONNECTIVITY
static bool CNDConnectivityClassName(const char *name)
{
    if (!name || strncmp(name, "CCUI", 4)) return false;
    static const char *const tokens[] = {
        "WiFi", "Bluetooth", "AirDrop", "VPN", "Satellite",
        "Airplane", "Cellular", "MobileData", "ConnectivityModule",
        "ConnectivityButton", "LabeledRoundButton",
    };
    for (size_t index = 0;
         index < sizeof(tokens) / sizeof(tokens[0]); index++) {
        if (strstr(name, tokens[index])) return true;
    }
    return false;
}

static bool CNDConnectivityInventoryClassName(const char *name)
{
    if (CNDConnectivityClassName(name)) return true;
    return name && (!strcmp(name, "WFWiFiStateMonitor") ||
                    !strcmp(name, "WFControlCenterStateMonitor"));
}

static NSString *CNDScalarState(id object)
{
    if (!object) return @"-";
    static const char *const getters[] = {
        "isSelected", "selected", "isEnabled", "enabled", "isOn", "on",
        "isActive", "active", "isExpanded", "expanded", "state",
    };
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    for (size_t index = 0;
         index < sizeof(getters) / sizeof(getters[0]); index++) {
        SEL selector = sel_registerName(getters[index]);
        Method method = class_getInstanceMethod(object_getClass(object),
                                                 selector);
        if (!method || method_getNumberOfArguments(method) != 2U) continue;
        char *returnCopy = method_copyReturnType(method);
        const char *returnType = CNDSkipQualifiers(returnCopy);
        bool scalar = returnType && *returnType &&
            strchr("BcCsSiIlLqQ", *returnType);
        free(returnCopy);
        if (!scalar) continue;
        @try {
            uintptr_t value = ((uintptr_t (*)(id, SEL))objc_msgSend)(
                object, selector);
            [parts addObject:[NSString stringWithFormat:@"%s=%llu",
                              getters[index], (unsigned long long)value]];
        } @catch (__unused NSException *exception) {
        }
    }
    return parts.count ? [parts componentsJoinedByString:@";"] : @"-";
}

static NSString *CNDSHA256(NSData *data)
{
    if (!data.length) return @"-";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    (void)CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    char output[CC_SHA256_DIGEST_LENGTH * 2U + 1U] = {0};
    for (unsigned index = 0; index < CC_SHA256_DIGEST_LENGTH; index++) {
        (void)snprintf(output + index * 2U, 3U, "%02x", digest[index]);
    }
    return [NSString stringWithUTF8String:output];
}

static bool CNDWriteTemporaryData(NSData *data, NSString *path)
{
    if (!data.length || !path.length) return false;
    int descriptor = open(path.fileSystemRepresentation,
                          O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0) return access(path.fileSystemRepresentation, F_OK) == 0;
    const uint8_t *bytes = data.bytes;
    NSUInteger remaining = data.length;
    bool ok = true;
    while (remaining > 0U) {
        ssize_t count = write(descriptor, bytes, remaining);
        if (count <= 0) {
            ok = false;
            break;
        }
        bytes += (NSUInteger)count;
        remaining -= (NSUInteger)count;
    }
    (void)close(descriptor);
    return ok && remaining == 0U;
}

static void CNDRecordConnectivityImage(unsigned event, id owner,
                                       UIImage *image, const char *source)
{
    if (!image || !CNDConnectivityClassName(CNDClassName(owner))) return;
    NSData *png = UIImagePNGRepresentation(image);
    NSString *digest = CNDSHA256(png);
    NSString *key = [NSString stringWithFormat:@"%s/%@/%@",
                     CNDClassName(owner), digest,
                     CNDScalarState(owner)];
    @synchronized (gConnectivityFingerprints) {
        if ([gConnectivityFingerprints containsObject:key]) return;
        [gConnectivityFingerprints addObject:key];
    }
    CGImageRef cgImage = image.CGImage;
    size_t width = cgImage ? CGImageGetWidth(cgImage) : 0U;
    size_t height = cgImage ? CGImageGetHeight(cgImage) : 0U;
    size_t bits = cgImage ? CGImageGetBitsPerPixel(cgImage) : 0U;
    NSString *fileName = [NSString stringWithFormat:@"%s-%@.png",
                          CNDClassName(owner), digest];
    NSString *path = [[NSString stringWithUTF8String:
        CNDConnectivityExportDirectory] stringByAppendingPathComponent:fileName];
    bool exported = CNDWriteTemporaryData(png, path);
    CNDLog("[CND_PULSAR]\tCONNECTIVITY_IMAGE\tevent=%u\tsource=%s\t"
           "owner=%p/%s\tidentity=%s\tscalars=%s\tpoints=%.2fx%.2f\t"
           "scale=%.3f\tpixels=%zux%zu\tbitsPerPixel=%zu\t"
           "rendering=%ld\tpngBytes=%lu\tsha256=%s\texport=%s\n",
           event, source, (__bridge void *)owner, CNDClassName(owner),
           CNDIdentity(owner).UTF8String ?: "-",
           CNDScalarState(owner).UTF8String ?: "-",
           image.size.width, image.size.height, image.scale, width, height,
           bits, (long)image.renderingMode, (unsigned long)png.length,
           digest.UTF8String ?: "-", exported ? path.UTF8String : "-");
    NSArray<NSString *> *stack = NSThread.callStackSymbols;
    NSUInteger limit = MIN(stack.count, 14U);
    for (NSUInteger index = 1U; index < limit; index++) {
        CNDLog("[CND_PULSAR]\tCONNECTIVITY_STACK\tevent=%u\tindex=%lu\t"
               "frame=%s\n", event, (unsigned long)index,
               CNDToken(stack[index]).UTF8String ?: "-");
    }
}
#endif

static bool CNDStringContains(NSString *value, NSString *needle)
{
    return [value rangeOfString:needle options:NSCaseInsensitiveSearch].location
        != NSNotFound;
}

static bool CNDMediaControlsRuntimeClass(const char *name)
{
    if (!name) return false;
    if (strstr(name, "MediaControls")) return true;
    if (strncmp(name, "MRU", 3)) return false;
    static const char *const tokens[] = {
        "Media", "NowPlaying", "Transport", "Volume", "Package",
        "Mirroring",
    };
    for (size_t index = 0;
         index < sizeof(tokens) / sizeof(tokens[0]); index++) {
        if (strstr(name, tokens[index])) return true;
    }
    return false;
}

static bool CNDRelevantBundle(id object)
{
    if (![object isKindOfClass:NSBundle.class]) return false;
    NSBundle *bundle = object;
    NSString *value = [NSString stringWithFormat:@"%@ %@",
                       bundle.bundleIdentifier ?: @"",
                       bundle.bundlePath ?: @""];
    static NSArray<NSString *> *tokens;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        tokens = @[@"ControlCenter", @"MediaControls", @"FocusUI",
                   @"SpringBoard", @"CoverSheet", @"ReplayKit",
                   @"Shazam", @"Hearing", @"AirPlay"];
    });
    for (NSString *token in tokens) {
        if (CNDStringContains(value, token)) return true;
    }
    return false;
}

static const char *CNDRoute(const CNDHook *hook)
{
    if (!hook) return "unknown";
    if (!strcmp(hook->logicalClassName, "CAPackage")) return "package-load";
    if (!strcmp(hook->logicalClassName, "NSBundle")) return "package-resource";
    if (!strcmp(hook->logicalClassName, "UIImage")) {
        return strstr(hook->selectorName, "systemImageNamed")
            ? "symbol-lookup" : "asset-lookup";
    }
    if (strstr(hook->logicalClassName, "CAPackageDescription")) {
        return "package-description";
    }
    if (CNDMediaControlsRuntimeClass(hook->logicalClassName)) return "media";
    if (strstr(hook->selectorName, "State") ||
        strstr(hook->selectorName, "state")) return "state";
    if (strstr(hook->logicalClassName, "ControlIcon") ||
        strstr(hook->logicalClassName, "ModuleIcon")) return "control-icon";
    return "glyph";
}

static bool CNDShouldLog(const CNDHook *hook, id argument0, id argument1)
{
    if (!hook || !atomic_load_explicit(&gTraceActive, memory_order_acquire)) {
        return false;
    }
    if (!strcmp(hook->logicalClassName, "UIImage") &&
        strstr(hook->selectorName, "imageNamed:inBundle:")) {
        return CNDRelevantBundle(argument1);
    }
    if (!strcmp(hook->logicalClassName, "NSBundle")) {
        NSString *name = [argument0 isKindOfClass:NSString.class]
            ? argument0 : @"";
        NSString *extension = [argument1 isKindOfClass:NSString.class]
            ? [(NSString *)argument1 lowercaseString] : @"";
        return [extension isEqualToString:@"ca"] ||
            [extension isEqualToString:@"caml"] ||
            [name isEqualToString:@"main"];
    }
    return true;
}

static void CNDTraceEvent(const CNDHook *hook, id receiver,
                          id argument0, id argument1, id argument2,
                          id result, const char *phase)
{
    if (!CNDShouldLog(hook, argument0, argument1)) return;
    unsigned event = atomic_fetch_add_explicit(
        &gEventCount, 1U, memory_order_relaxed) + 1U;
    if (event > CNDEventCap) {
        if (event == CNDEventCap + 1U) {
            CNDLog("[CND_PULSAR]\tEVENT_CAP\tcap=%u\n", CNDEventCap);
        }
        return;
    }
    NSString *receiverIdentity = CNDIdentity(receiver);
    NSString *a0 = CNDDescribe(argument0);
    NSString *a1 = CNDDescribe(argument1);
    NSString *a2 = CNDDescribe(argument2);
    NSString *output = CNDDescribe(result);
    CNDLog("[CND_PULSAR]\tEVENT\tseq=%u\tphase=%s\troute=%s\t"
           "class=%s\tselector=%s\treceiver=%p/%s\tidentity=%s\t"
           "a0Class=%s\ta0=%s\ta1Class=%s\ta1=%s\t"
           "a2Class=%s\ta2=%s\tresult=%p/%s\tresultValue=%s\n",
           event, phase, CNDRoute(hook), hook->logicalClassName,
           hook->selectorName, (__bridge void *)receiver,
           CNDClassName(receiver), receiverIdentity.UTF8String ?: "-",
           CNDClassName(argument0), a0.UTF8String ?: "-",
           CNDClassName(argument1), a1.UTF8String ?: "-",
           CNDClassName(argument2), a2.UTF8String ?: "-",
           (__bridge void *)result, CNDClassName(result),
           output.UTF8String ?: "-");
#if CND_PULSAR_TRACE_CONNECTIVITY
    if (CNDConnectivityClassName(CNDClassName(receiver))) {
        bool isImage = [argument0 isKindOfClass:UIImage.class];
        CNDLog("[CND_PULSAR]\tCONNECTIVITY_RECEIVER\tevent=%u\t"
               "owner=%p/%s\tselector=%s\targument=%p/%s\t"
               "isImage=%d\tidentity=%s\tscalars=%s\n", event,
               (__bridge void *)receiver, CNDClassName(receiver),
               hook->selectorName, (__bridge void *)argument0,
               CNDClassName(argument0), isImage,
               CNDIdentity(receiver).UTF8String ?: "-",
               CNDScalarState(receiver).UTF8String ?: "-");
        if (isImage) {
            CNDRecordConnectivityImage(event, receiver, argument0, "setter");
        }
    }
#endif
}

static bool CNDClassIsOrInherits(Class actual, Class target)
{
    for (Class cursor = actual; cursor; cursor = class_getSuperclass(cursor)) {
        if (cursor == target) return true;
    }
    return false;
}

static CNDHook *CNDLookupHook(id receiver, SEL selector)
{
    Class actual = receiver ? object_getClass(receiver) : Nil;
    unsigned count = atomic_load_explicit(&gHookCount, memory_order_acquire);
    for (Class cursor = actual; cursor; cursor = class_getSuperclass(cursor)) {
        for (unsigned index = 0; index < count; index++) {
            CNDHook *hook = &gHooks[index];
            if (hook->targetClass == cursor && hook->selector == selector) {
                return hook;
            }
        }
    }
    for (unsigned index = 0; index < count; index++) {
        CNDHook *hook = &gHooks[index];
        if (hook->selector == selector &&
            CNDClassIsOrInherits(actual, hook->targetClass)) return hook;
    }
    return NULL;
}

static id CNDTraceObject0(id self, SEL selector)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook) return nil;
    bool outer = gWrapperDepth++ == 0U;
    id result = ((id (*)(id, SEL))hook->original)(self, selector);
    if (outer) CNDTraceEvent(hook, self, nil, nil, nil, result, "return");
    gWrapperDepth--;
    return result;
}

static id CNDTraceObject1(id self, SEL selector, id argument0)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook) return nil;
    bool outer = gWrapperDepth++ == 0U;
    id result = ((id (*)(id, SEL, id))hook->original)(
        self, selector, argument0);
    if (outer) {
        CNDTraceEvent(hook, self, argument0, nil, nil, result, "return");
    }
    gWrapperDepth--;
    return result;
}

static id CNDTraceObject2(id self, SEL selector, id argument0, id argument1)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook) return nil;
    bool outer = gWrapperDepth++ == 0U;
    id result = ((id (*)(id, SEL, id, id))hook->original)(
        self, selector, argument0, argument1);
    if (outer) {
        CNDTraceEvent(hook, self, argument0, argument1, nil, result, "return");
    }
    gWrapperDepth--;
    return result;
}

static id CNDTraceObject3(id self, SEL selector, id argument0, id argument1,
                          id argument2)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook) return nil;
    bool outer = gWrapperDepth++ == 0U;
    id result = ((id (*)(id, SEL, id, id, id))hook->original)(
        self, selector, argument0, argument1, argument2);
    if (outer) {
        CNDTraceEvent(hook, self, argument0, argument1, argument2,
                      result, "return");
    }
    gWrapperDepth--;
    return result;
}

static id CNDTraceObject3Pointer(id self, SEL selector, id argument0,
                                 id argument1, id argument2,
                                 id __autoreleasing *error)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook) return nil;
    bool outer = gWrapperDepth++ == 0U;
    id result = ((id (*)(id, SEL, id, id, id, id __autoreleasing *))
                 hook->original)(self, selector, argument0, argument1,
                                 argument2, error);
    if (outer) {
        CNDTraceEvent(hook, self, argument0, argument1, argument2,
                      result, "return");
    }
    gWrapperDepth--;
    return result;
}

static void CNDTraceVoidObject(id self, SEL selector, id argument0)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook) return;
    bool outer = gWrapperDepth++ == 0U;
    if (outer) {
        CNDTraceEvent(hook, self, argument0, nil, nil, nil, "enter");
    }
    ((void (*)(id, SEL, id))hook->original)(self, selector, argument0);
    gWrapperDepth--;
}

static void CNDTraceVoidInteger(id self, SEL selector, uintptr_t argument0)
{
    CNDHook *hook = CNDLookupHook(self, selector);
    if (!hook) return;
    bool outer = gWrapperDepth++ == 0U;
    if (outer && atomic_load_explicit(&gTraceActive, memory_order_acquire)) {
        unsigned event = atomic_fetch_add_explicit(
            &gEventCount, 1U, memory_order_relaxed) + 1U;
        if (event <= CNDEventCap) {
            NSString *identity = CNDIdentity(self);
            CNDLog("[CND_PULSAR]\tEVENT\tseq=%u\tphase=enter\troute=%s\t"
                   "class=%s\tselector=%s\treceiver=%p/%s\tidentity=%s\t"
                   "integer=%llu\n", event, CNDRoute(hook),
                   hook->logicalClassName, hook->selectorName,
                   (__bridge void *)self, CNDClassName(self),
                   identity.UTF8String ?: "-",
                   (unsigned long long)argument0);
#if CND_PULSAR_TRACE_CONNECTIVITY
            if (CNDConnectivityClassName(CNDClassName(self))) {
                CNDLog("[CND_PULSAR]\tCONNECTIVITY_STATE\tevent=%u\t"
                       "owner=%p/%s\tselector=%s\tvalue=%llu\t"
                       "identity=%s\tscalars=%s\n", event,
                       (__bridge void *)self, CNDClassName(self),
                       hook->selectorName, (unsigned long long)argument0,
                       CNDIdentity(self).UTF8String ?: "-",
                       CNDScalarState(self).UTF8String ?: "-");
            }
#endif
        }
    }
    ((void (*)(id, SEL, uintptr_t))hook->original)(self, selector, argument0);
    gWrapperDepth--;
}

static IMP CNDReplacement(CNDHookABI abi)
{
    switch (abi) {
        case CNDABIObject0: return (IMP)CNDTraceObject0;
        case CNDABIObject1: return (IMP)CNDTraceObject1;
        case CNDABIObject2: return (IMP)CNDTraceObject2;
        case CNDABIObject3: return (IMP)CNDTraceObject3;
        case CNDABIObject3Pointer: return (IMP)CNDTraceObject3Pointer;
        case CNDABIVoidObject: return (IMP)CNDTraceVoidObject;
        case CNDABIVoidInteger: return (IMP)CNDTraceVoidInteger;
        case CNDABINone: default: return NULL;
    }
}

static bool CNDTypeIsObject(const char *type)
{
    const char *value = CNDSkipQualifiers(type);
    return value && (*value == '@' || *value == '#');
}

static bool CNDTypeIsInteger(const char *type)
{
    const char *value = CNDSkipQualifiers(type);
    return value && *value && strchr("BcCsSiIlLqQ", *value);
}

static CNDHookABI CNDMethodABI(Method method)
{
    if (!method) return CNDABINone;
    char *returnCopy = method_copyReturnType(method);
    const char *returnType = CNDSkipQualifiers(returnCopy);
    bool returnsObject = CNDTypeIsObject(returnType);
    bool returnsVoid = returnType && *returnType == 'v';
    free(returnCopy);
    unsigned arguments = method_getNumberOfArguments(method);
    if (returnsObject && arguments >= 2U && arguments <= 6U) {
        if (arguments == 2U) return CNDABIObject0;
        bool objectArguments = true;
        for (unsigned index = 2U; index < arguments; index++) {
            char *argumentCopy = method_copyArgumentType(method, index);
            bool object = CNDTypeIsObject(argumentCopy);
            free(argumentCopy);
            if (!object) {
                objectArguments = false;
                break;
            }
        }
        if (objectArguments) {
            if (arguments == 3U) return CNDABIObject1;
            if (arguments == 4U) return CNDABIObject2;
            if (arguments == 5U) return CNDABIObject3;
        }
        if (arguments == 6U) {
            bool firstThreeObjects = true;
            for (unsigned index = 2U; index < 5U; index++) {
                char *argumentCopy = method_copyArgumentType(method, index);
                firstThreeObjects &= CNDTypeIsObject(argumentCopy);
                free(argumentCopy);
            }
            char *lastCopy = method_copyArgumentType(method, 5U);
            const char *last = CNDSkipQualifiers(lastCopy);
            bool pointer = last && *last == '^';
            free(lastCopy);
            if (firstThreeObjects && pointer) return CNDABIObject3Pointer;
        }
    }
    if (returnsVoid && arguments == 3U) {
        char *argumentCopy = method_copyArgumentType(method, 2U);
        CNDHookABI abi = CNDTypeIsObject(argumentCopy) ? CNDABIVoidObject
            : (CNDTypeIsInteger(argumentCopy) ? CNDABIVoidInteger
                                              : CNDABINone);
        free(argumentCopy);
        return abi;
    }
    return CNDABINone;
}

static Method CNDOwnedMethod(Class target, SEL selector)
{
    unsigned count = 0U;
    Method *methods = class_copyMethodList(target, &count);
    Method result = NULL;
    for (unsigned index = 0; methods && index < count; index++) {
        if (method_getName(methods[index]) == selector) {
            result = methods[index];
            break;
        }
    }
    free(methods);
    return result;
}

static bool CNDInstallHook(Class logicalClass, bool classMethod,
                           const char *selectorName)
{
    if (!logicalClass || !selectorName) return false;
    Class target = classMethod ? object_getClass(logicalClass) : logicalClass;
    SEL selector = sel_registerName(selectorName);
    unsigned existing = atomic_load_explicit(&gHookCount, memory_order_acquire);
    for (unsigned index = 0; index < existing; index++) {
        if (gHooks[index].targetClass == target &&
            gHooks[index].selector == selector) return true;
    }
    Method method = CNDOwnedMethod(target, selector);
    CNDHookABI abi = CNDMethodABI(method);
    IMP replacement = CNDReplacement(abi);
    if (!method || !replacement || existing >= CNDHookCap) return false;
    IMP original = method_getImplementation(method);
    if (!original || original == replacement) return false;
    const char *types = method_getTypeEncoding(method);
    CNDHook *slot = &gHooks[existing];
    *slot = (CNDHook){
        .targetClass = target,
        .selector = selector,
        .original = original,
        .abi = abi,
        .logicalClassName = class_getName(logicalClass),
        .selectorName = selectorName,
        .classMethod = classMethod,
    };
    (void)method_setImplementation(method, replacement);
    bool ok = method_getImplementation(method) == replacement;
    if (!ok) return false;
    atomic_store_explicit(&gHookCount, existing + 1U, memory_order_release);
    Dl_info info = {0};
    (void)dladdr((const void *)original, &info);
    NSString *image = info.dli_fname
        ? [NSString stringWithUTF8String:info.dli_fname] : @"-";
    CNDLog("[CND_PULSAR]\tHOOK\tclass=%s\tkind=%c\tselector=%s\t"
           "abi=%u\ttypes=%s\toriginal=%p\timage=%s\n",
           class_getName(logicalClass), classMethod ? '+' : '-',
           selectorName, (unsigned)abi, types ?: "-", original,
           CNDToken(image).UTF8String ?: "-");
    return true;
}

static bool CNDHookSelectorName(const char *name)
{
    if (!name) return false;
    static const char *const selectors[] = {
        "setGlyphImage:", "setSelectedGlyphImage:",
        "setGlyphPackageDescription:", "_setGlyphPackageDescription:",
        "setHeaderGlyphImage:", "setHeaderGlyphPackageDescription:",
        "setGlyphState:", "_setGlyphState:", "setHeaderGlyphState:",
        "setPackageDescription:", "setPackage:", "setStateName:",
        "setState:", "setIcon:", "setIconView:", "setGlyphView:",
        "setCustomGlyphView:", "glyphImageForState:",
        "_glyphImageForState:", "iconGlyph", "selectedIconGlyph",
        "initWithPackageName:inBundle:",
        "descriptionForPackageNamed:inBundle:",
        "ccuiPackageFromDescription:",
#if CND_PULSAR_TRACE_CONNECTIVITY
        "setSelected:", "setEnabled:", "setOn:", "setActive:",
        "setExpanded:",
#endif
    };
    for (size_t index = 0;
         index < sizeof(selectors) / sizeof(selectors[0]); index++) {
        if (!strcmp(name, selectors[index])) return true;
    }
    return false;
}

static bool CNDMediaHookSelectorName(const char *name)
{
    if (!name || (strncmp(name, "set", 3) && strncmp(name, "_set", 4))) {
        return false;
    }
    static const char *const tokens[] = {
        "Image", "Glyph", "Icon", "Package", "State",
    };
    for (size_t index = 0;
         index < sizeof(tokens) / sizeof(tokens[0]); index++) {
        if (strstr(name, tokens[index])) return true;
    }
    return false;
}

static bool CNDFocusedClassName(const char *name)
{
    if (!name) return false;
#if CND_PULSAR_TRACE_CONNECTIVITY
    if (CNDConnectivityInventoryClassName(name)) return true;
#endif
    if (!strcmp(name, "CCUICAPackageDescription") ||
        !strcmp(name, "CCUICAPackageView") ||
        !strcmp(name, "CCUIButtonModuleViewController") ||
        !strcmp(name, "CCUIMenuModuleViewController") ||
        !strcmp(name, "CCUIControlHostViewController") ||
        !strcmp(name, "CCUIControlIconElement") ||
        !strcmp(name, "CCUIModuleIconElement")) return true;
    if (!strncmp(name, "CCUI", 4) &&
        (strstr(name, "Package") || strstr(name, "ButtonModule") ||
         strstr(name, "ControlIcon") || strstr(name, "ModuleIcon"))) {
        return true;
    }
    if ((!strncmp(name, "CHUI", 4) || !strncmp(name, "CHS", 3)) &&
        (strstr(name, "ControlInstance") || strstr(name, "ControlIcon") ||
         strstr(name, "ControlPicker") || strstr(name, "ControlDescriptor") ||
         strstr(name, "ControlIdentity"))) return true;
    if (CNDMediaControlsRuntimeClass(name) &&
        (strstr(name, "Package") || strstr(name, "Transport") ||
         strstr(name, "NowPlaying") || strstr(name, "Volume") ||
         strstr(name, "Mirroring") ||
         strstr(name, "MediaControlsModule"))) return true;
    return false;
}

static unsigned CNDInstallFocusedHooks(void)
{
    unsigned before = atomic_load_explicit(&gHookCount, memory_order_acquire);
    Class image = objc_getClass("UIImage");
    (void)CNDInstallHook(image, true, "imageNamed:inBundle:");
    (void)CNDInstallHook(image, true,
                         "imageNamed:inBundle:compatibleWithTraitCollection:");
    (void)CNDInstallHook(image, true, "systemImageNamed:");
    (void)CNDInstallHook(image, true, "_systemImageNamed:");
    (void)CNDInstallHook(image, true,
                         "systemImageNamed:withConfiguration:");
    Class bundle = objc_getClass("NSBundle");
    (void)CNDInstallHook(bundle, false, "URLForResource:withExtension:");
    (void)CNDInstallHook(bundle, false, "pathForResource:ofType:");
    Class package = objc_getClass("CAPackage");
    (void)CNDInstallHook(package, true,
                         "packageWithContentsOfURL:type:options:error:");

    unsigned classCount = 0U;
    Class *classes = objc_copyClassList(&classCount);
    for (unsigned classIndex = 0; classes && classIndex < classCount;
         classIndex++) {
        Class cls = classes[classIndex];
        const char *className = cls ? class_getName(cls) : NULL;
        if (!CNDFocusedClassName(className)) continue;
        for (unsigned kind = 0; kind < 2U; kind++) {
            Class target = kind ? object_getClass(cls) : cls;
            unsigned methodCount = 0U;
            Method *methods = class_copyMethodList(target, &methodCount);
            for (unsigned methodIndex = 0;
                 methods && methodIndex < methodCount; methodIndex++) {
                SEL selector = method_getName(methods[methodIndex]);
                const char *selectorName = selector
                    ? sel_getName(selector) : NULL;
                if (CNDHookSelectorName(selectorName) ||
                    (CNDMediaControlsRuntimeClass(className) &&
                     CNDMediaHookSelectorName(selectorName))) {
                    (void)CNDInstallHook(cls, kind != 0U, selectorName);
                }
            }
            free(methods);
        }
    }
    free(classes);
    unsigned after = atomic_load_explicit(&gHookCount, memory_order_acquire);
    return after - before;
}

static bool CNDInventoryMemberName(const char *name)
{
    if (!name) return false;
    static const char *const tokens[] = {
        "image", "Image", "icon", "Icon", "glyph", "Glyph",
        "package", "Package", "state", "State", "bundle", "Bundle",
        "module", "Module", "control", "Control", "identifier",
        "Identifier", "symbol", "Symbol",
    };
    for (size_t index = 0;
         index < sizeof(tokens) / sizeof(tokens[0]); index++) {
        if (strstr(name, tokens[index])) return true;
    }
    return false;
}

static void CNDDumpClass(Class cls)
{
    const char *name = class_getName(cls);
    const char *image = class_getImageName(cls);
    CNDLog("[CND_PULSAR]\tCLASS\tname=%s\tsuper=%s\taddress=%p\timage=%s\n",
           name, class_getSuperclass(cls)
                ? class_getName(class_getSuperclass(cls)) : "-", cls,
           image ?: "-");
    unsigned emitted = 0U;
    for (unsigned kind = 0; kind < 2U; kind++) {
        Class target = kind ? object_getClass(cls) : cls;
        unsigned count = 0U;
        Method *methods = class_copyMethodList(target, &count);
        for (unsigned index = 0; methods && index < count; index++) {
            const char *selector = sel_getName(method_getName(methods[index]));
            if (!CNDInventoryMemberName(selector)) continue;
            if (emitted++ >= CNDInventoryMemberCap) break;
            CNDLog("[CND_PULSAR]\tMETHOD\tclass=%s\tkind=%c\tname=%s\t"
                   "types=%s\timp=%p\n", name, kind ? '+' : '-',
                   selector ?: "-",
                   method_getTypeEncoding(methods[index]) ?: "-",
                   method_getImplementation(methods[index]));
        }
        free(methods);
    }
    unsigned count = 0U;
    objc_property_t *properties = class_copyPropertyList(cls, &count);
    for (unsigned index = 0; properties && index < count; index++) {
        const char *propertyName = property_getName(properties[index]);
        if (!CNDInventoryMemberName(propertyName)) continue;
        if (emitted++ >= CNDInventoryMemberCap) break;
        CNDLog("[CND_PULSAR]\tPROPERTY\tclass=%s\tname=%s\tattrs=%s\n",
               name, propertyName ?: "-",
               property_getAttributes(properties[index]) ?: "-");
    }
    free(properties);
    count = 0U;
    Ivar *ivars = class_copyIvarList(cls, &count);
    for (unsigned index = 0; ivars && index < count; index++) {
        const char *ivarName = ivar_getName(ivars[index]);
        if (!CNDInventoryMemberName(ivarName)) continue;
        if (emitted++ >= CNDInventoryMemberCap) break;
        CNDLog("[CND_PULSAR]\tIVAR\tclass=%s\tname=%s\ttype=%s\t"
               "offset=%td\n", name, ivarName ?: "-",
               ivar_getTypeEncoding(ivars[index]) ?: "-",
               ivar_getOffset(ivars[index]));
    }
    free(ivars);
}

static void CNDDumpFocusedInventory(void)
{
    unsigned classCount = 0U;
    Class *classes = objc_copyClassList(&classCount);
    unsigned focused = 0U;
    for (unsigned index = 0; classes && index < classCount; index++) {
        Class cls = classes[index];
        if (!cls || !CNDFocusedClassName(class_getName(cls))) continue;
        CNDDumpClass(cls);
        focused++;
    }
    free(classes);
    CNDLog("[CND_PULSAR]\tINVENTORY_COMPLETE\tloaded=%u\tfocused=%u\n",
           classCount, focused);
}

static bool CNDControlCenterRuntimeClass(const char *name)
{
    if (!name) return false;
    return !strncmp(name, "CCUI", 4) || !strncmp(name, "CHUI", 4) ||
        strstr(name, "ControlCenterUI") ||
        strstr(name, "ControlCenterUIServices") ||
        CNDMediaControlsRuntimeClass(name);
}

static UIViewController *CNDOwningController(UIView *view)
{
    UIResponder *cursor = view;
    for (unsigned depth = 0; cursor && depth < 24U; depth++) {
        if ([cursor isKindOfClass:UIViewController.class]) {
            return (UIViewController *)cursor;
        }
        UIResponder *next = cursor.nextResponder;
        if (next == cursor) break;
        cursor = next;
    }
    return nil;
}

static void CNDWalkView(UIView *view, unsigned tick, unsigned depth,
                        bool inheritedContext, unsigned *budget)
{
    if (!view || view.hidden || view.alpha <= 0.01 ||
        depth > CNDViewDepthCap || *budget >= CNDViewCap) return;
    (*budget)++;
    const char *className = class_getName(view.class);
    UIViewController *owner = CNDOwningController(view);
    bool context = inheritedContext || CNDControlCenterRuntimeClass(className) ||
        (owner && CNDControlCenterRuntimeClass(class_getName(owner.class)));
    void *imagePointer = NULL;
    UIImage *image = nil;
    if ([view isKindOfClass:UIImageView.class]) {
        image = ((UIImageView *)view).image;
        imagePointer = (__bridge void *)image;
    } else if ([view isKindOfClass:UIButton.class]) {
        image = ((UIButton *)view).currentImage;
        imagePointer = (__bridge void *)image;
    }
    NSString *signature = [NSString stringWithFormat:@"%d/%d/%.3f/%@/%p/%p",
                           view.hidden, context, view.alpha,
                           NSStringFromCGRect(view.frame), imagePointer,
                           (__bridge void *)view.layer.contents];
    NSString *previous = [gViewSignatures objectForKey:view];
    if (context && ![signature isEqualToString:previous] &&
        (CNDControlCenterRuntimeClass(className) || image ||
         view.layer.contents)) {
        NSString *identifier = nil;
        NSString *label = nil;
        @try {
            identifier = view.accessibilityIdentifier;
            label = view.accessibilityLabel;
        } @catch (__unused NSException *exception) {
            identifier = @"<unavailable>";
            label = @"<unavailable>";
        }
        CNDLog("[CND_PULSAR]\tVIEW\ttick=%u\tdepth=%u\tclass=%s\t"
               "object=%p\tframe=%s\towner=%p/%s\tidentity=%s\t"
               "accessibilityID=%s\taccessibilityLabel=%s\timage=%p/%s\t"
               "imageValue=%s\tlayerContents=%p\n", tick, depth,
               className, (__bridge void *)view,
               CNDToken(NSStringFromCGRect(view.frame)).UTF8String ?: "-",
               (__bridge void *)owner,
               owner ? class_getName(owner.class) : "-",
               owner ? CNDIdentity(owner).UTF8String : "-",
               CNDToken(identifier).UTF8String ?: "-",
               CNDToken(label).UTF8String ?: "-",
               imagePointer, CNDClassName(image),
               CNDDescribe(image).UTF8String ?: "-",
               (__bridge void *)view.layer.contents);
        [gViewSignatures setObject:signature forKey:view];
    }
#if CND_PULSAR_TRACE_CONNECTIVITY
    if (image && owner && CNDConnectivityClassName(class_getName(owner.class))) {
        CNDRecordConnectivityImage(0U, owner, image, "visible-view");
    }
#endif
    for (UIView *child in view.subviews) {
        CNDWalkView(child, tick, depth + 1U, context, budget);
    }
}

static void CNDWalkController(UIViewController *controller, unsigned tick)
{
    if (!controller || !controller.isViewLoaded || controller.view.hidden ||
        controller.view.alpha <= 0.01) return;
    const char *className = class_getName(controller.class);
    if (CNDControlCenterRuntimeClass(className) &&
        ![gSeenControllers containsObject:controller]) {
        CNDLog("[CND_PULSAR]\tCONTROLLER\ttick=%u\tclass=%s\tobject=%p\t"
               "view=%p\tparent=%p/%s\tpresented=%p/%s\tidentity=%s\n",
               tick, className, (__bridge void *)controller,
               (__bridge void *)controller.view,
               (__bridge void *)controller.parentViewController,
               CNDClassName(controller.parentViewController),
               (__bridge void *)controller.presentedViewController,
               CNDClassName(controller.presentedViewController),
               CNDIdentity(controller).UTF8String ?: "-");
        [gSeenControllers addObject:controller];
    }
    for (UIViewController *child in controller.childViewControllers) {
        CNDWalkController(child, tick);
    }
    CNDWalkController(controller.presentedViewController, tick);
}

static void CNDSnapshot(unsigned tick)
{
    unsigned windows = 0U;
    unsigned views = 0U;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] ||
            scene.activationState != UISceneActivationStateForegroundActive) {
            continue;
        }
        UIWindowScene *windowScene = (UIWindowScene *)scene;
        for (UIWindow *window in windowScene.windows) {
            if (!window || window.hidden || window.alpha <= 0.01) continue;
            windows++;
            CNDWalkController(window.rootViewController, tick);
            CNDWalkView(window, tick, 0U, false, &views);
        }
    }
    CNDLog("[CND_PULSAR]\tSNAPSHOT\ttick=%u\twindows=%u\tviews=%u\t"
           "hooks=%u\tevents=%u\n", tick, windows, views,
           atomic_load_explicit(&gHookCount, memory_order_acquire),
           atomic_load_explicit(&gEventCount, memory_order_relaxed));
}

__attribute__((constructor))
static void CNDPulsarControlCenterTraceStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_PULSAR_TRACE_OUTPUT_TOKEN[0] && consume
            ? consume(CND_PULSAR_TRACE_OUTPUT_TOKEN) : -1;
        gReportFD = open(CNDReportPath,
            O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        if (gReportFD < 0) return;
        CNDLog("[CND_PULSAR]\tSTART\tpid=%d\tprocess=%s\ttoken=%lld\t"
               "mode=ephemeral-observation\tnoSystemWrite=1\tduration=%d\t"
               "focus=%s\n",
               getpid(), getprogname(), (long long)token,
               CND_PULSAR_TRACE_DURATION,
               CND_PULSAR_TRACE_CONNECTIVITY ? "connectivity" : "general");
        dispatch_async(dispatch_get_main_queue(), ^{
            gSeenControllers = [NSHashTable weakObjectsHashTable];
            gViewSignatures = [NSMapTable weakToStrongObjectsMapTable];
#if CND_PULSAR_TRACE_CONNECTIVITY
            gConnectivityFingerprints = [NSMutableSet set];
            (void)mkdir(CNDConnectivityExportDirectory, 0700);
#endif
            atomic_store_explicit(&gTraceActive, true, memory_order_release);
            CNDDumpFocusedInventory();
            (void)CNDInstallFocusedHooks();
            CNDSnapshot(0U);
            CNDLog("[CND_PULSAR]\tTRACE_READY\tpid=%d\thooks=%u\t"
                   "duration=%d\tmode=ephemeral-observation\n",
                   getpid(),
                   atomic_load_explicit(&gHookCount, memory_order_acquire),
                   CND_PULSAR_TRACE_DURATION);
            __block unsigned tick = 0U;
            gTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,
                0U, 0U, dispatch_get_main_queue());
            dispatch_source_set_timer(gTimer,
                dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC),
                2ULL * NSEC_PER_SEC, 100ULL * NSEC_PER_MSEC);
            dispatch_source_set_event_handler(gTimer, ^{
                tick += 2U;
                unsigned added = CNDInstallFocusedHooks();
                if (added) {
                    CNDLog("[CND_PULSAR]\tHOOK_REFRESH\ttick=%u\tadded=%u\t"
                           "total=%u\n", tick, added,
                           atomic_load_explicit(&gHookCount,
                                                memory_order_acquire));
                }
                CNDSnapshot(tick);
                if (tick >= CND_PULSAR_TRACE_DURATION) {
                    atomic_store_explicit(&gTraceActive, false,
                                          memory_order_release);
                    CNDLog("[CND_PULSAR]\tTRACE_COMPLETE\tpid=%d\t"
                           "ticks=%u\thooks=%u\tevents=%u\t"
                           "mode=ephemeral-observation\n", getpid(), tick,
                           atomic_load_explicit(&gHookCount,
                                                memory_order_acquire),
                           atomic_load_explicit(&gEventCount,
                                                memory_order_relaxed));
                    dispatch_source_cancel(gTimer);
                    gTimer = nil;
                }
            });
            dispatch_resume(gTimer);
        });
    }
}
