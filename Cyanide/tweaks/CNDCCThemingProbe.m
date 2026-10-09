#import "CNDCCThemingProbe.h"

#import "remote_objc.h"
#import "../TaskRop/RemoteCall.h"

#include <string.h>

enum {
    CNDCCWindowCap = 32,
    CNDCCControllerCap = 256,
    CNDCCViewCapPerController = 128,
    CNDCCTraceObjectCapPerController = 512,
    CNDCCCollectionSanityMax = 4096,
};

static NSString *CNDCCAddress(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%llx", (unsigned long long)value];
}

static NSString *CNDCCClassNameForClass(uint64_t cls)
{
    if (!r_is_objc_ptr(cls)) return nil;
    uint64_t name = r_dlsym_call(R_TIMEOUT, "class_getName", cls,
        0, 0, 0, 0, 0, 0, 0);
    char buffer[192] = {0};
    if (!name || !r_read_cstring(name, buffer, sizeof(buffer))) return nil;
    return [NSString stringWithUTF8String:buffer];
}

static NSString *CNDCCClassName(uint64_t object)
{
    if (!r_is_objc_ptr(object)) return nil;
    uint64_t cls = r_dlsym_call(R_TIMEOUT, "object_getClass", object,
        0, 0, 0, 0, 0, 0, 0);
    return CNDCCClassNameForClass(cls);
}

static NSDictionary *CNDCCObject(uint64_t object)
{
    return @{
        @"address": CNDCCAddress(object),
        @"className": CNDCCClassName(object) ?: @"unavailable",
    };
}

static NSDictionary *CNDCCGeometry(uint64_t object)
{
    NSMutableDictionary *geometry = [NSMutableDictionary dictionary];
    struct { double x, y, width, height; } rect = {0};
    if (r_responds_main(object, "frame") &&
        r_msg2_main_struct_ret(object, "frame", &rect, sizeof(rect),
            NULL, 0, NULL, 0, NULL, 0, NULL, 0)) {
        geometry[@"frame"] = @{
            @"x": @(rect.x), @"y": @(rect.y),
            @"width": @(rect.width), @"height": @(rect.height),
        };
    }
    memset(&rect, 0, sizeof(rect));
    if (r_responds_main(object, "bounds") &&
        r_msg2_main_struct_ret(object, "bounds", &rect, sizeof(rect),
            NULL, 0, NULL, 0, NULL, 0, NULL, 0)) {
        geometry[@"bounds"] = @{
            @"x": @(rect.x), @"y": @(rect.y),
            @"width": @(rect.width), @"height": @(rect.height),
        };
    }
    struct { double x, y; } point = {0};
    if (r_responds_main(object, "center") &&
        r_msg2_main_struct_ret(object, "center", &point, sizeof(point),
            NULL, 0, NULL, 0, NULL, 0, NULL, 0)) {
        geometry[@"center"] = @{@"x": @(point.x), @"y": @(point.y)};
    }
    return geometry;
}

static uint64_t CNDCCGetter(uint64_t object, const char *selector)
{
    if (!remote_call_current_success() || !r_is_objc_ptr(object) ||
        !selector || !r_responds_main(object, selector)) return 0;
    return r_msg2_main(object, selector, 0, 0, 0, 0);
}

static uint64_t CNDCCArrayObject(uint64_t array, NSUInteger index)
{
    if (!remote_call_current_success() || !r_is_objc_ptr(array) ||
        !r_responds_main(array, "objectAtIndex:")) return 0;
    return r_msg2_main(array, "objectAtIndex:", index, 0, 0, 0);
}

static NSUInteger CNDCCBoundedCount(uint64_t raw, NSUInteger cap,
                                    NSUInteger *invalidCollections)
{
    if (raw > CNDCCCollectionSanityMax) {
        if (invalidCollections) (*invalidCollections)++;
        return 0;
    }
    return (NSUInteger)MIN(raw, (uint64_t)cap);
}

static NSString *CNDCCStringGetter(uint64_t object, const char *selector)
{
    uint64_t value = CNDCCGetter(object, selector);
    if (!r_is_objc_ptr(value)) return nil;
    char buffer[512] = {0};
    if (!r_read_nsstring(value, buffer, sizeof(buffer))) return nil;
    return [NSString stringWithUTF8String:buffer];
}

static NSDictionary *CNDCCControllerObject(uint64_t controller)
{
    NSMutableDictionary *result = [CNDCCObject(controller) mutableCopy];
    static const char *const identitySelectors[] = {
        "moduleIdentifier",
        "bundleIdentifier",
        "containerBundleIdentifier",
        "applicationBundleIdentifier",
        "uniqueIdentifier",
        "identifier",
    };
    for (NSUInteger i = 0;
         i < sizeof(identitySelectors) / sizeof(identitySelectors[0]); i++) {
        const char *selector = identitySelectors[i];
        NSString *value = CNDCCStringGetter(controller, selector);
        if (!value.length) continue;
        result[[NSString stringWithUTF8String:selector]] = value;
    }
    return result;
}

static NSString *CNDCCControllerIdentityText(NSDictionary *controller)
{
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    for (NSString *key in @[
        @"moduleIdentifier", @"bundleIdentifier",
        @"containerBundleIdentifier", @"applicationBundleIdentifier",
        @"uniqueIdentifier", @"identifier",
    ]) {
        NSString *value = [controller[key] isKindOfClass:NSString.class]
            ? controller[key] : nil;
        if (value.length) [parts addObject:value];
    }
    return [parts componentsJoinedByString:@" "];
}

static NSDictionary *CNDCCMethodContract(uint64_t object,
                                         const char *selectorName)
{
    NSMutableDictionary *result = [@{
        @"selector": selectorName
            ? [NSString stringWithUTF8String:selectorName] : @"",
        @"present": @NO,
    } mutableCopy];
    if (!r_is_objc_ptr(object) || !selectorName ||
        !remote_call_current_success()) return result;

    uint64_t cls = r_dlsym_call(R_TIMEOUT, "object_getClass", object,
        0, 0, 0, 0, 0, 0, 0);
    uint64_t selector = r_sel(selectorName);
    uint64_t method = r_is_objc_ptr(cls) && selector
        ? r_dlsym_call(R_TIMEOUT, "class_getInstanceMethod", cls, selector,
            0, 0, 0, 0, 0, 0)
        : 0;
    uint64_t types = method
        ? r_dlsym_call(R_TIMEOUT, "method_getTypeEncoding", method,
            0, 0, 0, 0, 0, 0, 0)
        : 0;
    char typeBuffer[192] = {0};
    if (types) (void)r_read_cstring(types, typeBuffer, sizeof(typeBuffer));
    result[@"present"] = @(method != 0);
    if (typeBuffer[0]) {
        result[@"types"] = [NSString stringWithUTF8String:typeBuffer];
    }
    return result;
}

static BOOL CNDCCIsTemplateView(uint64_t view, uint64_t templateClass)
{
    if (!r_is_objc_ptr(view) || !r_is_objc_ptr(templateClass) ||
        !remote_call_current_success()) return NO;
    return r_msg2_main(view, "isKindOfClass:", templateClass, 0, 0, 0) != 0;
}

static NSArray<NSNumber *> *CNDCCCopyTemplateViews(
    uint64_t root,
    uint64_t templateClass,
    NSUInteger *visitedViews,
    NSUInteger *invalidCollections,
    NSUInteger *truncatedTraversals)
{
    if (!r_is_objc_ptr(root)) return @[];
    NSMutableArray<NSNumber *> *queue = [NSMutableArray arrayWithObject:@(root)];
    NSMutableSet<NSNumber *> *seen = [NSMutableSet setWithObject:@(root)];
    NSMutableArray<NSNumber *> *templates = [NSMutableArray array];
    for (NSUInteger cursor = 0;
         cursor < queue.count && cursor < CNDCCViewCapPerController &&
         remote_call_current_success(); cursor++) {
        uint64_t view = queue[cursor].unsignedLongLongValue;
        if (visitedViews) (*visitedViews)++;
        if (CNDCCIsTemplateView(view, templateClass)) {
            [templates addObject:@(view)];
        }
        uint64_t subviews = CNDCCGetter(view, "subviews");
        uint64_t rawCount = CNDCCGetter(subviews, "count");
        NSUInteger remaining = CNDCCViewCapPerController - queue.count;
        if (rawCount <= CNDCCCollectionSanityMax && rawCount > remaining &&
            truncatedTraversals) {
            (*truncatedTraversals)++;
        }
        NSUInteger count = CNDCCBoundedCount(rawCount, remaining,
                                              invalidCollections);
        for (NSUInteger i = 0; i < count; i++) {
            uint64_t child = CNDCCArrayObject(subviews, i);
            NSNumber *key = @(child);
            if (!r_is_objc_ptr(child) || [seen containsObject:key]) continue;
            [seen addObject:key];
            [queue addObject:key];
        }
    }
    return templates;
}

static NSArray<NSNumber *> *CNDCCCopyViewsMatchingClassNames(
    uint64_t root,
    NSArray<NSString *> *classNames)
{
    if (!r_is_objc_ptr(root) || classNames.count == 0) return @[];
    NSMutableArray<NSNumber *> *queue = [NSMutableArray arrayWithObject:@(root)];
    NSMutableSet<NSNumber *> *seen = [NSMutableSet setWithObject:@(root)];
    NSMutableArray<NSNumber *> *matches = [NSMutableArray array];
    for (NSUInteger cursor = 0;
         cursor < queue.count && cursor < CNDCCViewCapPerController &&
         remote_call_current_success(); cursor++) {
        uint64_t view = queue[cursor].unsignedLongLongValue;
        NSString *className = CNDCCClassName(view) ?: @"";
        BOOL classMatches = NO;
        for (NSString *candidate in classNames) {
            if ([className isEqualToString:candidate] ||
                [className hasSuffix:candidate]) {
                classMatches = YES;
                break;
            }
        }
        if (classMatches) [matches addObject:@(view)];
        uint64_t subviews = CNDCCGetter(view, "subviews");
        NSUInteger count = CNDCCBoundedCount(
            CNDCCGetter(subviews, "count"),
            CNDCCViewCapPerController - queue.count, NULL);
        for (NSUInteger i = 0; i < count; i++) {
            uint64_t child = CNDCCArrayObject(subviews, i);
            NSNumber *key = @(child);
            if (!r_is_objc_ptr(child) || [seen containsObject:key]) continue;
            [seen addObject:key];
            [queue addObject:key];
        }
    }
    return matches;
}

static NSString *CNDCCControlKind(NSString *className,
                                  NSString *identifier,
                                  NSString *label,
                                  NSString *source,
                                  NSString *controllerIdentity)
{
    NSString *name = [[NSString stringWithFormat:@"%@ %@ %@ %@ %@",
        className ?: @"", identifier ?: @"", label ?: @"", source ?: @"",
        controllerIdentity ?: @""] lowercaseString];
    NSArray<NSArray<NSString *> *> *rules = @[
        @[@"bluetooth", @"bluetooth"],
        @[@"cellular", @"cellular"],
        @[@"airplane", @"airplaneMode"],
        @[@"wifi", @"wifi"],
        @[@"wi-fi", @"wifi"],
        @[@"airdrop", @"airDrop"],
        @[@"hotspot", @"hotspot"],
        @[@"flashlight", @"flashlight"],
        @[@"torch", @"flashlight"],
        @[@"lowpower", @"lowPower"],
        @[@"low power", @"lowPower"],
        @[@"rpcontrolcenter", @"screenRecording"],
        @[@"replaykit", @"screenRecording"],
        @[@"screencapture", @"screenRecording"],
        @[@"screenrecord", @"screenRecording"],
        @[@"screen record", @"screenRecording"],
        @[@"calculator", @"calculator"],
        @[@"barcode", @"qrCode"],
        @[@"camera", @"camera"],
        @[@"qrcode", @"qrCode"],
        @[@"qr code", @"qrCode"],
        @[@"orientation", @"orientationLock"],
        @[@"mute", @"mute"],
        @[@"focus", @"focus"],
        @[@"appearance", @"appearance"],
        @[@"display", @"display"],
        @[@"brightness", @"display"],
        @[@"sounddetection", @"soundDetection"],
        @[@"sound detection", @"soundDetection"],
        @[@"sound", @"sound"],
        @[@"volume", @"sound"],
        @[@"alarm", @"alarm"],
        @[@"timer", @"timer"],
        @[@"stopwatch", @"stopwatch"],
        @[@"wallet", @"wallet"],
        @[@"voice", @"voiceMemos"],
        @[@"magnifier", @"magnifier"],
        @[@"hearing", @"hearing"],
        @[@"shazam", @"musicRecognition"],
        @[@"musicrecognition", @"musicRecognition"],
        @[@"music recognition", @"musicRecognition"],
        @[@"airplay", @"screenMirroring"],
        @[@"mirroring", @"screenMirroring"],
        @[@"guidedaccess", @"guidedAccess"],
        @[@"shortcut", @"accessibilityShortcuts"],
        @[@"textsize", @"textSize"],
        @[@"text size", @"textSize"],
        @[@"tvremote", @"tvRemote"],
        @[@"vpn", @"vpn"],
        @[@"satellite", @"satellite"],
        @[@"nfc", @"nfc"],
        @[@"performance", @"performanceTrace"],
    ];
    for (NSArray<NSString *> *rule in rules) {
        if ([name containsString:rule[0]]) return rule[1];
    }
    return @"unclassified";
}

static NSDictionary *CNDCCImage(uint64_t image)
{
    if (!r_is_objc_ptr(image)) return CNDCCObject(0);
    NSMutableDictionary *result = [CNDCCObject(image) mutableCopy];
    if (r_responds_main(image, "renderingMode")) {
        result[@"renderingMode"] = @((int64_t)r_msg2_main(
            image, "renderingMode", 0, 0, 0, 0));
    }
    struct { double width, height; } size = {0};
    if (r_responds_main(image, "size") &&
        r_msg2_main_struct_ret(image, "size", &size, sizeof(size),
            NULL, 0, NULL, 0, NULL, 0, NULL, 0)) {
        result[@"size"] = @{
            @"width": @(size.width), @"height": @(size.height)
        };
    }
    return result;
}

static NSDictionary *CNDCCSurface(uint64_t controller,
                                  uint64_t templateView,
                                  NSString *source)
{
    NSString *controllerClass = CNDCCClassName(controller) ?: @"unavailable";
    NSDictionary *controllerObject = CNDCCControllerObject(controller);
    NSString *controllerIdentity =
        CNDCCControllerIdentityText(controllerObject);
    NSString *identifier = CNDCCStringGetter(templateView,
                                              "accessibilityIdentifier");
    NSString *label = CNDCCStringGetter(templateView, "accessibilityLabel");
    NSMutableDictionary *result = [@{
        @"source": source ?: @"controllerGraph",
        @"kind": CNDCCControlKind(controllerClass, identifier, label, source,
                                   controllerIdentity),
        @"controller": controllerObject,
        @"templateView": CNDCCObject(templateView),
        @"contracts": @{
            @"glyphImage": CNDCCMethodContract(templateView, "glyphImage"),
            @"setGlyphImage": CNDCCMethodContract(templateView, "setGlyphImage:"),
            @"selectedGlyphImage": CNDCCMethodContract(templateView, "selectedGlyphImage"),
            @"setSelectedGlyphImage": CNDCCMethodContract(templateView, "setSelectedGlyphImage:"),
            @"glyphPackageDescription": CNDCCMethodContract(templateView, "glyphPackageDescription"),
            @"setGlyphPackageDescription": CNDCCMethodContract(templateView, "setGlyphPackageDescription:"),
            @"glyphState": CNDCCMethodContract(templateView, "glyphState"),
            @"setGlyphState": CNDCCMethodContract(templateView, "setGlyphState:"),
        },
    } mutableCopy];

    if (identifier.length) result[@"accessibilityIdentifier"] = identifier;
    if (label.length) result[@"accessibilityLabel"] = label;
    result[@"window"] = CNDCCObject(CNDCCGetter(templateView, "window"));

    uint64_t glyphImage = CNDCCGetter(templateView, "glyphImage");
    uint64_t selectedGlyphImage = CNDCCGetter(templateView,
                                               "selectedGlyphImage");
    uint64_t packageDescription = CNDCCGetter(templateView,
                                               "glyphPackageDescription");
    if (glyphImage) result[@"glyphImage"] = CNDCCImage(glyphImage);
    if (selectedGlyphImage)
        result[@"selectedGlyphImage"] = CNDCCImage(selectedGlyphImage);
    if (packageDescription)
        result[@"glyphPackageDescription"] = CNDCCObject(packageDescription);
    if (r_responds_main(templateView, "glyphState")) {
        uint64_t state = r_msg2_main(templateView, "glyphState", 0, 0, 0, 0);
        result[@"glyphStateRaw"] = CNDCCAddress(state);
        result[@"glyphStateSigned"] = @((int64_t)state);
        char stateBuffer[512] = {0};
        if (r_is_objc_ptr(state) &&
            r_read_nsstring(state, stateBuffer, sizeof(stateBuffer)) &&
            stateBuffer[0]) {
            result[@"glyphStateString"] =
                [NSString stringWithUTF8String:stateBuffer];
        }
    }
    return result;
}

static BOOL CNDCCSurfaceHasLiveWindow(NSDictionary *surface)
{
    NSString *address = [surface[@"window"] isKindOfClass:NSDictionary.class]
        ? surface[@"window"][@"address"] : nil;
    return address.length > 0 && ![address isEqualToString:@"0x0"];
}

static void CNDCCRecordSurface(
    NSMutableArray<NSDictionary *> *surfaces,
    NSMutableDictionary<NSString *, NSDictionary *> *named,
    NSMutableDictionary<NSString *, NSMutableArray<NSDictionary *> *> *byKind,
    NSDictionary *surface)
{
    if (![surface isKindOfClass:NSDictionary.class]) return;
    [surfaces addObject:surface];
    NSString *kind = [surface[@"kind"] isKindOfClass:NSString.class]
        ? surface[@"kind"] : @"unclassified";
    if ([kind isEqualToString:@"unclassified"]) return;

    NSDictionary *current = named[kind];
    if (!current || (!CNDCCSurfaceHasLiveWindow(current) &&
                     CNDCCSurfaceHasLiveWindow(surface))) {
        named[kind] = surface;
    }

    NSMutableArray<NSDictionary *> *matches = byKind[kind];
    if (!matches) {
        matches = [NSMutableArray array];
        byKind[kind] = matches;
    }
    NSString *templateAddress = surface[@"templateView"][@"address"];
    for (NSUInteger i = 0; i < matches.count; i++) {
        NSDictionary *existing = matches[i];
        if ([existing[@"templateView"][@"address"]
                isEqualToString:templateAddress]) {
            if (!CNDCCSurfaceHasLiveWindow(existing) &&
                CNDCCSurfaceHasLiveWindow(surface)) {
                matches[i] = surface;
            }
            return;
        }
    }
    [matches addObject:surface];
}

static void CNDCCEnqueueController(NSMutableArray<NSNumber *> *queue,
                                   NSMutableSet<NSNumber *> *seen,
                                   uint64_t controller)
{
    if (queue.count >= CNDCCControllerCap || !r_is_objc_ptr(controller)) return;
    NSNumber *key = @(controller);
    if ([seen containsObject:key]) return;
    [seen addObject:key];
    [queue addObject:key];
}

static BOOL CNDCCLooksRelevantController(NSString *className)
{
    return [className containsString:@"CCUI"] ||
        [className containsString:@"ControlCenter"] ||
        [className containsString:@"RPControlCenter"] ||
        [className hasPrefix:@"MRU"] ||
        [className hasPrefix:@"MediaControls"];
}

static BOOL CNDCCLooksMediaTraceController(NSString *className)
{
    NSString *lower = className.lowercaseString;
    return [lower containsString:@"mru"] ||
        [lower containsString:@"media"] ||
        [lower containsString:@"nowplaying"];
}

static BOOL CNDCCLooksConnectivityTraceController(NSString *className)
{
    return [className.lowercaseString containsString:@"connectivity"];
}

static NSString *CNDCCExpandedTraceDomain(NSString *className)
{
    NSString *lower = className.lowercaseString;
    if (CNDCCLooksMediaTraceController(className)) return @"media";
    if (CNDCCLooksConnectivityTraceController(className)) return @"connectivity";
    for (NSArray<NSString *> *rule in @[
        @[@"focus", @"focus"], @[@"dnd", @"focus"],
        @[@"brightness", @"brightness"], @[@"display", @"brightness"],
        @[@"volume", @"volume"],
        @[@"chuis", @"hostedControl"], @[@"chrono", @"hostedControl"],
        @[@"camera", @"hostedControl"], @[@"calculator", @"hostedControl"],
        @[@"barcode", @"hostedControl"], @[@"qrcode", @"hostedControl"],
        @[@"widget", @"hostedControl"],
    ]) {
        if ([lower containsString:rule[0]]) return rule[1];
    }
    return nil;
}

static BOOL CNDCCLooksTraceableObject(NSString *className)
{
    NSString *lower = className.lowercaseString;
    for (NSString *token in @[
        @"button", @"transport", @"glyph", @"package", @"media",
        @"mru", @"nowplaying", @"control", @"connectivity", @"image",
        @"slider", @"icon", @"focus", @"dnd", @"display",
        @"brightness", @"volume", @"hosted", @"chuis", @"chrono",
        @"camera", @"calculator", @"barcode", @"qrcode", @"widget",
    ]) {
        if ([lower containsString:token]) return YES;
    }
    return NO;
}

static void CNDCCEnqueueTraceObject(
    NSMutableArray<NSDictionary<NSString *, id> *> *queue,
    NSMutableSet<NSNumber *> *seen,
    uint64_t object,
    uint64_t parent,
    NSUInteger depth,
    NSString *relation)
{
    if (queue.count >= CNDCCTraceObjectCapPerController ||
        !r_is_objc_ptr(object)) return;
    NSNumber *key = @(object);
    if ([seen containsObject:key]) return;
    [seen addObject:key];
    [queue addObject:@{
        @"object": key,
        @"parent": @(parent),
        @"depth": @(depth),
        @"relation": relation ?: @"unknown",
    }];
}

// This diagnostic deliberately follows lifecycle ownership, never UIKit
// hierarchy discovery. All target operations share one PID/time/call budget;
// runtime contracts, including absent contracts, are cached for this capture.
// An in-flight call still uses the existing RemoteCall timeout.
enum {
    CNDCCSemanticControllerCap = 128,
    CNDCCSemanticObjectCap = 512,
    CNDCCRefinedDiscoveryObjectCap = 128,
    CNDCCSemanticClassCap = 64,
    CNDCCSemanticMemberCap = 64,
    CNDCCSemanticGlobalMemberCap = 2048,
    CNDCCSemanticCollectionCap = 32,
    CNDCCSemanticEdgeCap = 4096,
    CNDCCSemanticDepthCap = 16,
    CNDCCSemanticCallCap = 12000,
};

typedef struct {
    NSTimeInterval started;
    NSUInteger calls;
    NSUInteger members;
    int pid;
    uint64_t ioFailures;
    BOOL budgetReached;
    BOOL memberLimitReached;
    BOOL objectLimitReached;
    BOOL classLimitReached;
    BOOL priorityClassLimitReached;
    BOOL depthLimitReached;
    BOOL collectionLimitReached;
    BOOL edgeLimitReached;
    BOOL controllerLimitReached;
    BOOL scratchFreed;
    BOOL refined;
    BOOL focusScope;
    NSUInteger discoveryObjects;
    uint64_t countSlot;
    __unsafe_unretained NSMutableDictionary *contracts;
    __unsafe_unretained NSMutableDictionary *objectClasses;
    __unsafe_unretained NSMutableDictionary *classNames;
} CNDCCSemanticContext;

// Exact route owners and physical target classes get their own finite metadata
// pass. Broad containment inventory cannot spend their class allocation.
static NSArray *CNDCCRefinedPriorityClassNames(void)
{
    return @[@"SpringBoard", @"SBControlCenterController", @"CCUIMainViewController",
        @"CCUIPagingViewController", @"ControlCenterUI.IconListRootFolderController",
        @"SBCoverSheetPrimarySlidingViewController", @"CCUIContentModuleContainerViewController",
        @"CCUIModuleInstanceManager", @"CCUIModuleInstance", @"CCUIModuleMetadata",
        @"MediaControlsModule", @"MRUMediaControlsModuleViewController",
        @"MediaControls.MediaControlsModuleView",
        @"_TtGC13MediaControls23RoutePickerSessionsViewCS_30MediaControlsModuleSessionView_",
        @"MediaControls.MediaControlsModuleSessionView", @"MediaControls.MediaControlsModuleNowPlayingView",
        @"MediaControls.NowPlayingTransportControlsView", @"MediaControls.TransportButton",
        @"MediaControls.PackageView", @"CAStateController", @"CALayer",
        @"CCUIFlashlightModule", @"CCUIFlashlightModuleViewController", @"CCUIControlTemplateView",
        @"CCUIControlHostViewController", @"CCUIControlHostView", @"CHSControlIdentity",
        @"CHSExtensionIdentity", @"CHUISControlInstance", @"CHUISControlInstanceButton",
        @"CHUISControlIconView", @"CHUISControlView", @"CHUISControlDescriptor"];
}

static BOOL CNDCCRefinedPriorityClass(NSString *name)
{
    return [CNDCCRefinedPriorityClassNames() containsObject:name] ||
        [name hasPrefix:@"CHS"] || [name hasPrefix:@"CHUIS"];
}

static NSArray *CNDCCFocusPriorityClassNames(void)
{
    return @[@"FCCCControlCenterModule", @"FCActivityManager", @"_FCActivity",
        @"FCUIActivityPickerViewController", @"FCUIActivityListView", @"FCUIActivityControl",
        @"_FCUIActivityControlContentView", @"FCUICAPackageView", @"UIImageView", @"UIImage",
        @"CAStateController", @"CALayer", @"SpringBoard", @"SBControlCenterController",
        @"CCUIMainViewController", @"CCUIModuleInstanceManager", @"CCUIModuleInstance",
        @"CCUIModuleMetadata", @"CCUIContentModuleContainerViewController",
        @"SBCoverSheetPrimarySlidingViewController"];
}

static BOOL CNDCCFocusPriorityClass(NSString *name)
{
    return [CNDCCFocusPriorityClassNames() containsObject:name];
}

static BOOL CNDCCRefinedUntypedWrapperSlot(NSString *className, NSString *slot)
{
    return [className isEqualToString:
        @"_TtGC13MediaControls23RoutePickerSessionsViewCS_30MediaControlsModuleSessionView_"] &&
        [@[@"contentView", @"sessionViews"] containsObject:slot];
}

// VM-validated class-bound reference slots only. Native Swift structs/enums
// deliberately have no guessed pointer or calling convention here.
static NSDictionary *CNDCCRefinedSwiftReferenceSlots(NSString *name)
{
    if ([name isEqualToString:@"CCUIMainViewController"])
        return @{@"_pagingViewController": @"CCUIPagingViewController"};
    if ([name isEqualToString:@"CCUIPagingViewController"])
        return @{@"__rootFolderController": @"ControlCenterUI.IconListRootFolderController",
            @"controlDescriptorProvider": @"CCUIControlDescriptorProvider"};
    if ([name isEqualToString:@"MediaControls.NowPlayingTransportControlsView"])
        return @{@"leadingButton": @"MediaControls.TransportButton",
            @"leftButton": @"MediaControls.TransportButton",
            @"centerButton": @"MediaControls.TransportButton",
            @"rightButton": @"MediaControls.TransportButton"};
    if ([name isEqualToString:@"MediaControls.TransportButton"])
        return @{@"packageView": @"MediaControls.PackageView"};
    if ([name isEqualToString:@"MediaControls.PackageView"])
        return @{@"stateController": @"CAStateController", @"packageLayer": @"CALayer"};
    if ([name isEqualToString:@"MRUMediaControlsModuleViewController"])
        return @{@"$__lazy_storage_$_contentView": @"MediaControls.MediaControlsModuleView"};
    if ([name isEqualToString:@"MediaControls.MediaControlsModuleView"])
        return @{@"sessionsView": @"_TtGC13MediaControls23RoutePickerSessionsViewCS_30MediaControlsModuleSessionView_"};
    if ([name isEqualToString:@"MediaControls.MediaControlsModuleSessionView"])
        return @{@"nowPlayingView": @"MediaControls.MediaControlsModuleNowPlayingView"};
    if ([name isEqualToString:@"MediaControls.MediaControlsModuleNowPlayingView"])
        return @{@"transportControlsView": @"MediaControls.NowPlayingTransportControlsView"};
    return @{};
}

static NSArray *CNDCCRefinedGetterNames(NSString *name)
{
    if ([name isEqualToString:@"SpringBoard"])
        return @[@"windows", @"coverSheetViewController", @"coverSheetSlidingViewController"];
    if ([name containsString:@"Window"]) return @[@"rootViewController"];
    if ([name isEqualToString:@"CCUIMainViewController"])
        return @[@"moduleInstanceManager", @"moduleSettingsManager", @"childViewControllers"];
    if ([name isEqualToString:@"CCUIModuleInstanceManager"])
        return @[@"moduleInstances", @"moduleInstancesByIdentifier", @"moduleRepository"];
    if ([name isEqualToString:@"CCUIModuleInstance"])
        return @[@"module", @"metadata", @"identifier", @"uniqueIdentifier"];
    if ([name containsString:@"ModuleMetadata"])
        return @[@"moduleIdentifier", @"moduleBundleURL", @"bundleIdentifier"];
    if ([name isEqualToString:@"CCUIControlHostViewController"])
        return @[@"identity", @"viewIfLoaded", @"descriptor", @"controlDescriptor"];
    if ([name hasPrefix:@"CHS"] || [name hasPrefix:@"CHUIS"] ||
        [name containsString:@"Provider"] || [name containsString:@"ImageAsset"])
        return @[@"identity", @"identifier", @"kind", @"extensionIdentity", @"instanceIdentity", @"viewController",
            @"descriptor", @"control", @"configuration", @"iconView", @"imageProvider",
            @"glyphProvider", @"iconViewProvider", @"provider", @"image", @"symbolName",
            @"systemImageName", @"imageName", @"bundleIdentifier", @"extensionIdentifier",
            @"packageDescription", @"packageURL", @"URL"];
    if ([name isEqualToString:@"UIImage"] || [name containsString:@"ImageView"])
        return @[@"image", @"imageAsset", @"symbolName", @"systemImageName", @"imageName"];
    if ([name containsString:@"Package"] || [name containsString:@"StateController"])
        return @[@"package", @"packageDescription", @"packageURL", @"packageName",
            @"stateController", @"stateName", @"stateNames", @"currentState", @"rootLayer"];
    if ([name containsString:@"Transport"])
        return @[@"leftButton", @"centerButton", @"rightButton", @"leadingButton", @"packageView",
            @"viewModel", @"asset", @"symbolName", @"packageName", @"isHorizontallyFlipped"];
    if ([name containsString:@"MediaControls"] || [name hasPrefix:@"MRU"])
        return @[@"childViewControllers", @"viewIfLoaded", @"contentView", @"sessionsView",
            @"sessionViews", @"nowPlayingView", @"transportControlsView", @"packageView"];
    if ([name containsString:@"Flashlight"] || [name isEqualToString:@"CCUIControlTemplateView"])
        return @[@"viewIfLoaded", @"button", @"contentViewController", @"glyphImage",
            @"selectedGlyphImage", @"image", @"imageProvider", @"glyphProvider",
            @"glyphPackageDescription", @"glyphState", @"moduleIdentifier"];
    if ([name containsString:@"ViewController"] || [name hasSuffix:@"Controller"] ||
        [name containsString:@"RootFolder"])
        return @[@"childViewControllers", @"presentedViewController", @"viewController",
            @"controlCenterController", @"contentViewController", @"viewIfLoaded"];
    return @[];
}

static NSArray *CNDCCRefinedIvarNames(NSString *name)
{
    NSMutableSet *names = [NSMutableSet set];
    for (NSString *getter in CNDCCRefinedGetterNames(name)) {
        [names addObject:getter]; [names addObject:[@"_" stringByAppendingString:getter]];
    }
    for (NSString *slot in CNDCCRefinedSwiftReferenceSlots(name)) [names addObject:slot];
    NSDictionary *special = @{
        @"SpringBoard": @[@"_mainDisplayControlCenterController", @"_coverSheetSlidingViewController", @"_coverSheetViewController"],
        @"SBCoverSheetPrimarySlidingViewController": @[@"_controlCenterController"],
        @"CCUIMainViewController": @[@"_pagingViewController"],
        @"CCUIPagingViewController": @[@"__rootFolderController", @"_rootFolderController", @"controlDescriptorProvider"],
        @"CCUIModuleInstanceManager": @[@"_enabledModuleInstanceByUniqueIdentifer", @"_repository"],
        @"CCUIModuleInstance": @[@"_module", @"_metadata"],
        @"CCUIControlHostView": @[@"controlInstance", @"templateView", @"applicationContext"],
        @"CHSControlIdentity": @[@"_kind", @"_extensionIdentity"],
        @"MediaControlsModule": @[@"_contentViewController"],
        @"FlashlightModule": @[@"_moduleViewController", @"_contentViewController", @"_flashlightController"],
        @"CCUIFlashlightModuleViewController": @[@"_buttonModuleView", @"_flashlightController", @"_button"],
        @"CCUIControlTemplateView": @[@"_glyphImageView", @"_glyphPackageView", @"_glyphImage", @"_selectedGlyphImage"],
        @"UIImage": @[@"_imageAsset", @"_image", @"_symbolImageName"],
    };
    [names addObjectsFromArray:special[name] ?: @[]];
    return [names.allObjects sortedArrayUsingSelector:@selector(compare:)];
}

// Exact Focus contracts are independent of the broad Media/hosted pass.
// The model dictionary describes availability; only the loaded picker list
// describes materialized rows. Neither collection position is row identity.
static NSArray *CNDCCFocusGetterNames(NSString *name)
{
    if ([name isEqualToString:@"FCCCControlCenterModule"])
        return @[@"activityPickerViewController", @"activityManager"];
    if ([name isEqualToString:@"FCActivityManager"])
        return @[@"allActivitiesByIdentifier", @"availableActivities", @"activeActivity", @"defaultActivity"];
    if ([name isEqualToString:@"FCUIActivityPickerViewController"]) return @[@"viewIfLoaded"];
    if ([name isEqualToString:@"FCUIActivityListView"]) return @[@"activityViews"];
    if ([name isEqualToString:@"FCUIActivityControl"])
        return @[@"activityIdentifier", @"activityUniqueIdentifier", @"activitySymbolImageName", @"activityDescription"];
    if ([name isEqualToString:@"_FCActivity"])
        return @[@"activityIdentifier", @"activityUniqueIdentifier", @"activitySymbolImageName"];
    if ([name isEqualToString:@"FCUICAPackageView"] || [name isEqualToString:@"CAStateController"])
        return @[@"packageName", @"packageURL", @"stateController", @"rootLayer", @"stateName", @"currentState"];
    if ([name isEqualToString:@"UIImage"] || [name containsString:@"ImageView"])
        return @[@"image", @"imageAsset", @"symbolName", @"systemImageName", @"imageName"];
    if ([name isEqualToString:@"CCUIMainViewController"]) return @[@"moduleInstanceManager", @"childViewControllers"];
    if ([name isEqualToString:@"CCUIModuleInstanceManager"]) return @[@"moduleInstances", @"moduleInstancesByIdentifier"];
    if ([name isEqualToString:@"SpringBoard"] || [name isEqualToString:@"CCUIModuleInstance"] ||
        [name containsString:@"ModuleMetadata"] || [name containsString:@"Window"])
        return CNDCCRefinedGetterNames(name);
    if ([name containsString:@"ViewController"] || [name hasSuffix:@"Controller"])
        return @[@"childViewControllers", @"presentedViewController", @"controlCenterController", @"contentViewController"];
    return @[];
}

static NSArray *CNDCCFocusIvarNames(NSString *name)
{
    NSMutableSet *names = [NSMutableSet set];
    for (NSString *getter in CNDCCFocusGetterNames(name)) {
        [names addObject:getter]; [names addObject:[@"_" stringByAppendingString:getter]];
    }
    NSDictionary *special = @{
        @"SpringBoard": @[@"_mainDisplayControlCenterController", @"_coverSheetSlidingViewController", @"_coverSheetViewController"],
        @"SBControlCenterController": @[@"_viewController"],
        @"SBCoverSheetPrimarySlidingViewController": @[@"_controlCenterController"],
        @"CCUIModuleInstanceManager": @[@"_enabledModuleInstanceByUniqueIdentifer"],
        @"CCUIModuleInstance": @[@"_module", @"_metadata"],
        @"FCCCControlCenterModule": @[@"_activityPickerViewController", @"_activityManager"],
        @"FCActivityManager": @[@"_allActivitiesByIdentifier", @"_availableActivities", @"_activeActivity", @"_defaultActivity"],
        @"FCUIActivityControl": @[@"_activityDescription", @"_activityIconPackageView", @"_activityIconImageView", @"_contentView"],
        @"FCUICAPackageView": @[@"_stateController", @"_rootLayer"],
    };
    [names addObjectsFromArray:special[name] ?: @[]];
    return [names.allObjects sortedArrayUsingSelector:@selector(compare:)];
}

static BOOL CNDCCSemanticContinue(CNDCCSemanticContext *context)
{
    if (!remote_call_current_success() || context->pid <= 1 ||
        remote_call_current_pid() != context->pid ||
        remote_call_current_io_failure_count() != context->ioFailures) return NO;
    if (context->calls >= CNDCCSemanticCallCap ||
        [NSProcessInfo processInfo].systemUptime - context->started >= 30.0) {
        context->budgetReached = YES;
        return NO;
    }
    return YES;
}

static uint64_t CNDCCSemanticCall(CNDCCSemanticContext *context,
                                  const char *name,
                                  uint64_t a0, uint64_t a1)
{
    if (!CNDCCSemanticContinue(context)) return 0;
    context->calls++;
    return r_dlsym_call(R_TIMEOUT, name, a0, a1, 0, 0, 0, 0, 0, 0);
}

static NSString *CNDCCSemanticCString(uint64_t address)
{
    char buffer[192] = {0};
    return address && r_read_cstring(address, buffer, sizeof(buffer))
        ? [NSString stringWithUTF8String:buffer] : nil;
}

static NSString *CNDCCSemanticUnqualifiedType(NSString *encoding)
{
    NSUInteger index = 0;
    while (index < encoding.length &&
        [@"rnNoORV" rangeOfString:[encoding substringWithRange:
            NSMakeRange(index, 1)]].location != NSNotFound) index++;
    return [encoding substringFromIndex:index];
}

static NSDictionary *CNDCCSemanticContract(CNDCCSemanticContext *context,
                                          uint64_t cls, NSString *selector)
{
    if (!r_is_objc_ptr(cls) || !CNDCCSemanticContinue(context)) return nil;
    NSString *key = [NSString stringWithFormat:@"%llx:%@",
        (unsigned long long)cls, selector];
    id cached = context->contracts[key];
    if (cached) return cached == NSNull.null ? nil : cached;
    context->calls++; // selector registration is bounded as well
    uint64_t method = CNDCCSemanticCall(context, "class_getInstanceMethod",
                                       cls, r_sel(selector.UTF8String));
    if (!method || !CNDCCSemanticContinue(context)) {
        context->contracts[key] = NSNull.null;
        return nil;
    }
    NSString *types = CNDCCSemanticCString(CNDCCSemanticCall(
        context, "method_getTypeEncoding", method, 0)) ?: @"";
    uint64_t arguments = CNDCCSemanticCall(
        context, "method_getNumberOfArguments", method, 0);
    // Type encoding begins with the return type. Blocks are not object
    // getters; structs, pointers, floating-point, and void are never invoked.
    NSString *returnType = CNDCCSemanticUnqualifiedType(types);
    BOOL objectGetter = arguments == 2 &&
        [returnType hasPrefix:@"@"] && ![returnType hasPrefix:@"@?"] &&
        [selector rangeOfString:@":"].location == NSNotFound;
    NSDictionary *contract = @{@"selector": selector, @"types": types,
        @"argumentCount": @(arguments), @"objectGetterABI": @(objectGetter)};
    context->contracts[key] = contract;
    return contract;
}

static NSString *CNDCCSemanticClassName(CNDCCSemanticContext *context,
                                       uint64_t object, uint64_t *classOut)
{
    if (!r_is_objc_ptr(object) || !CNDCCSemanticContinue(context)) return @"";
    NSNumber *cachedClass = context->objectClasses[@(object)];
    uint64_t cls = cachedClass ? cachedClass.unsignedLongLongValue
        : CNDCCSemanticCall(context, "object_getClass", object, 0);
    if (classOut) *classOut = cls;
    context->objectClasses[@(object)] = @(cls);
    NSString *name = context->classNames[@(cls)];
    if (!name) {
        name = CNDCCSemanticCString(CNDCCSemanticCall(context,
            "class_getName", cls, 0)) ?: @"";
        context->classNames[@(cls)] = name;
    }
    return name;
}

static NSArray<NSString *> *CNDCCSemanticObjectGetters(void)
{
    return @[
        @"windows", @"rootViewController", @"presentedViewController",
        @"childViewControllers", @"controlCenterController",
        @"controlCenterCoordinator", @"controlCenter", @"controlCenterService",
        @"viewController", @"containerViewController", @"contentContainerViewController",
        @"moduleContainerViewController", @"moduleViewController", @"moduleViewControllers",
        @"moduleControllers", @"moduleInstances", @"moduleInstancesByIdentifier",
        @"moduleControllersByIdentifier", @"moduleInstanceManager", @"moduleRegistry",
        @"moduleRepository", @"moduleSettingsManager", @"moduleSettings",
        @"modules", @"module", @"moduleInstance", @"moduleIdentifier",
        @"bundleIdentifier", @"containerBundleIdentifier", @"applicationBundleIdentifier",
        @"moduleDescription", @"moduleDescriptor", @"descriptor", @"controlDescriptor",
        @"control", @"controlIdentifier", @"controlIdentity", @"controlModel",
        @"provider", @"packageProvider", @"glyphProvider", @"imageProvider",
        @"contentProvider", @"configurationProvider", @"registeredModules",
        @"button", @"contentView", @"customGlyphView", @"controlIconView",
        @"brightnessSlider", @"volumeSlider", @"slider", @"sliderView",
        @"wifiModuleViewController", @"bluetoothModuleViewController",
        @"cellularDataButtonViewController", @"airplaneButtonViewController",
        @"hotspotButtonViewController", @"airDropModuleViewController",
        @"vpnModuleViewController", @"satelliteButtonViewController",
        @"viewIfLoaded", @"contentViewController", @"moduleContentViewController",
        @"expandedViewController", @"expandedContentViewController",
        @"nowPlayingViewController", @"mediaControlsViewController",
        @"transportControlsViewController", @"transportControlsView",
        @"transportControlView", @"transportControls", @"playbackControlsView",
        @"nowPlayingView", @"sessionView", @"controlsView",
        @"previousButton", @"skipBackwardButton", @"backwardButton",
        @"playPauseButton", @"playPauseStopButton", @"centerButton",
        @"nextButton", @"skipForwardButton", @"forwardButton",
        @"leadingButton", @"trailingButton", @"leftButton", @"rightButton",
        @"packageView", @"package", @"packageDescription",
        @"glyphPackageDescription", @"glyphView", @"imageView",
        @"rootLayer", @"stateController", @"stateName", @"glyphState",
        @"packageName", @"packageURL", @"URL", @"url",
        @"packageState", @"packageStateName", @"image", @"glyphImage",
        @"focusViewController", @"focusModeViewController",
        @"activityViewController", @"activityControlsViewController",
        @"activityControlsView", @"activityControls", @"activityViews",
        @"activities", @"focusModes", @"modes", @"rows", @"items",
        @"activity", @"representedActivity", @"focusActivity", @"focusMode",
        @"mode", @"model", @"configuration", @"activityConfiguration",
        @"modeConfiguration", @"settings", @"icon", @"iconView",
        @"activityIdentifier", @"modeIdentifier", @"identifier",
        @"uniqueIdentifier", @"systemIdentifier", @"semanticIdentifier",
        @"UUID", @"uuid", @"symbolName", @"iconSymbolName",
        @"glyphName", @"activityType", @"modeType",
    ];
}

static BOOL CNDCCSemanticIdentityName(NSString *name)
{
    NSString *normalized = [name stringByTrimmingCharactersInSet:
        [NSCharacterSet characterSetWithCharactersInString:@"_"]];
    return [@[@"activityIdentifier", @"modeIdentifier", @"identifier",
        @"moduleIdentifier", @"bundleIdentifier", @"containerBundleIdentifier",
        @"applicationBundleIdentifier", @"controlIdentifier", @"controlIdentity",
        @"uniqueIdentifier", @"systemIdentifier", @"semanticIdentifier",
        @"UUID", @"uuid", @"symbolName", @"iconSymbolName", @"glyphName",
        @"packageName", @"packageURL", @"URL", @"url", @"stateName",
        @"glyphState", @"packageState", @"packageStateName", @"activityType",
        @"modeType", @"kind", @"extensionIdentifier", @"systemImageName",
        @"imageName", @"activityUniqueIdentifier", @"activitySymbolImageName"] containsObject:normalized];
}

// Pure lifecycle policy helpers are exercised without RemoteCall by host tests.
static NSDictionary *CNDCCLifecycleClassEvidence(NSString *className)
{
    NSString *lower = className.lowercaseString;
    NSString *kind = @"unknown";
    NSUInteger rank = 0;
    BOOL stable = NO;
    if ([className isEqualToString:@"FCUIActivityControl"] ||
        [className isEqualToString:@"_FCUIActivityControlContentView"]) {
        kind = @"view-leaf"; rank = 20;
    } else if ([className isEqualToString:@"FCCCControlCenterModule"]) {
        kind = @"module-instance"; rank = 75; stable = YES;
    } else if ([lower containsString:@"viewcontroller"] || ([lower hasSuffix:@"controller"] &&
        ![lower containsString:@"statecontroller"])) {
        kind = @"controller"; rank = 70; stable = YES;
    } else if ([lower containsString:@"provider"] || [lower containsString:@"repository"] ||
        [lower containsString:@"registry"] || [lower containsString:@"manager"]) {
        kind = @"provider-or-registry"; rank = 90; stable = YES;
    } else if ([lower containsString:@"descriptor"] || [lower containsString:@"description"]) {
        kind = @"descriptor"; rank = 85; stable = YES;
    } else if ([lower containsString:@"imageview"] || [lower containsString:@"iconview"]) {
        kind = @"image-leaf"; rank = 10;
    } else if ([lower containsString:@"package"] && [lower containsString:@"view"]) {
        kind = @"package-leaf"; rank = 15;
    } else if ([lower containsString:@"view"] || [lower containsString:@"layer"]) {
        kind = @"view-leaf"; rank = 20;
    } else if ([lower containsString:@"model"] || [lower containsString:@"configuration"] ||
        [lower containsString:@"activity"] || [lower containsString:@"mode"] ||
        [lower containsString:@"statecontroller"]) {
        kind = @"model-or-configuration"; rank = 80; stable = YES;
    } else if ([lower containsString:@"module"]) {
        kind = @"module-instance"; rank = 75; stable = YES;
    } else if ([lower containsString:@"package"]) {
        kind = @"package-leaf"; rank = 15;
    } else if ([lower containsString:@"image"]) {
        kind = @"image-leaf"; rank = 10;
    } else if ([className isEqualToString:@"SpringBoard"] ||
        [className isEqualToString:@"UIApplication"]) {
        kind = @"process-owner"; rank = 100; stable = YES;
    }
    return @{@"kind": kind, @"rank": @(rank), @"stableOwnerCandidate": @(stable),
        @"lifetimeVerified": @NO};
}

static NSArray *CNDCCSemanticRoles(NSString *className, NSDictionary *identities,
                                 NSString *incomingName)
{
    NSMutableArray *roles = [NSMutableArray array];
    NSString *name = [[incomingName stringByTrimmingCharactersInSet:
        [NSCharacterSet characterSetWithCharactersInString:@"_"]] lowercaseString];
    if ([@[@"previousbutton", @"skipbackwardbutton", @"backwardbutton"] containsObject:name])
        [roles addObject:@"media.previous"];
    if ([@[@"playpausebutton", @"playpausestopbutton"] containsObject:name])
        [roles addObject:@"media.playPause"];
    if ([@[@"nextbutton", @"skipforwardbutton", @"forwardbutton"] containsObject:name])
        [roles addObject:@"media.next"];
    if (identities[@"activityIdentifier"] || identities[@"modeIdentifier"] ||
        ([className hasPrefix:@"FCUI"] && [className.lowercaseString containsString:@"activity"]))
        [roles addObject:@"focus.activityOrMode"];
    NSString *machine = [[@[className ?: @"", [identities.allValues componentsJoinedByString:@" "]]
        componentsJoinedByString:@" "] lowercaseString];
    for (NSArray *mapping in @[@[@"flashlight", @"flashlight"], @[@"brightness", @"brightness"],
        @[@"displaymodule", @"brightness"], @[@"volume", @"volume"],
        @[@"camera", @"camera"], @[@"barcode", @"qrCode"], @[@"scanner", @"qrCode"],
        @[@"calculator", @"calculator"]]) {
        if ([machine containsString:mapping[0]] && ![roles containsObject:mapping[1]])
            [roles addObject:mapping[1]];
    }
    if ([className containsString:@"Module"] || identities[@"moduleIdentifier"] ||
        identities[@"controlIdentifier"]) [roles addObject:@"moduleOrBottomControl"];
    return roles;
}

static BOOL CNDCCSemanticOwnershipIvar(NSString *name)
{
    NSString *normalized = [name stringByTrimmingCharactersInSet:
        [NSCharacterSet characterSetWithCharactersInString:@"_"]];
    // Only explicit ownership members are followed. UIKit hierarchy fields
    // and unknown object slots cannot introduce a discovery walk.
    return [CNDCCSemanticObjectGetters() containsObject:normalized] ||
        [@[@"view", @"controlIconView", @"moduleInstanceByIdentifier",
            @"moduleViewControllersByIdentifier", @"activityModel",
            @"activityViewModels", @"activityRows", @"buttonGlyphView",
            @"controlTemplateView", @"controlHostView", @"packageDescriptionProvider"]
            containsObject:normalized];
}

static NSString *CNDCCSemanticDomain(NSString *className)
{
    if ([className isEqualToString:@"MRUMediaControlsModuleViewController"] ||
        [className containsString:@"MediaControlsModule"] ||
        [className containsString:@"NowPlaying"] ||
        [className containsString:@"Transport"] ||
        [className isEqualToString:@"MediaControls.PackageView"]) return @"media";
    NSString *lower = className.lowercaseString;
    if ([className hasPrefix:@"FCUI"] || [className isEqualToString:@"FCCCControlCenterModule"] ||
        [className isEqualToString:@"FCActivityManager"] || [className isEqualToString:@"_FCActivity"] ||
        [className hasPrefix:@"DND"] || [className hasPrefix:@"FUI"] ||
        [lower containsString:@"focus"]) return @"focus";
    return nil;
}

static BOOL CNDCCSemanticDataObject(NSString *className)
{
    // Domains annotate evidence after inspection; they never gate bootstrap.
    if (!className.length) return NO;
    return !([className containsString:@"String"] || [className containsString:@"Number"] ||
        [className containsString:@"UUID"] || [className containsString:@"URL"] ||
        [className containsString:@"Data"] || [className containsString:@"Date"]);
}

static uint64_t CNDCCSemanticGetter(CNDCCSemanticContext *context,
                                   uint64_t object, NSDictionary *contract)
{
    if (![contract[@"objectGetterABI"] boolValue] ||
        !CNDCCSemanticContinue(context)) return 0;
    context->calls++;
    return r_msg2_main(object, [contract[@"selector"] UTF8String], 0, 0, 0, 0);
}

static NSString *CNDCCSemanticIdentityValue(CNDCCSemanticContext *context,
                                          uint64_t object, NSString *className)
{
    if ([className containsString:@"String"]) {
        char buffer[256] = {0};
        context->calls++;
        return CNDCCSemanticContinue(context) &&
            r_read_nsstring(object, buffer, sizeof(buffer))
            ? [NSString stringWithUTF8String:buffer] : nil;
    }
    NSString *selector = [className containsString:@"UUID"] ? @"UUIDString"
        : ([className containsString:@"URL"] ? @"path" : nil);
    if (!selector) return nil;
    uint64_t cls = 0;
    (void)CNDCCSemanticClassName(context, object, &cls);
    NSDictionary *contract = CNDCCSemanticContract(context, cls, selector);
    uint64_t string = CNDCCSemanticGetter(context, object, contract);
    char buffer[256] = {0};
    context->calls++;
    return r_is_objc_ptr(string) && CNDCCSemanticContinue(context) &&
        r_read_nsstring(string, buffer, sizeof(buffer))
        ? [NSString stringWithUTF8String:buffer] : nil;
}

static NSDictionary *CNDCCSemanticClassMetadata(CNDCCSemanticContext *context,
                                               uint64_t cls, NSString *className)
{
    if (context->refined) {
        NSMutableArray *ivars = [NSMutableArray array];
        NSMutableDictionary *contracts = [NSMutableDictionary dictionary];
        uint64_t size = CNDCCSemanticCall(context, "class_getInstanceSize", cls, 0);
        NSArray *ivarNames = context->focusScope ? CNDCCFocusIvarNames(className) : CNDCCRefinedIvarNames(className);
        for (NSString *name in ivarNames) {
            if (!CNDCCSemanticContinue(context)) break;
            // SEL names are converted back to const char* with the runtime's
            // documented accessor; no host pointer is passed to the target.
            context->calls++;
            uint64_t string = CNDCCSemanticCall(context, "sel_getName", r_sel(name.UTF8String), 0);
            uint64_t ivar = CNDCCSemanticCall(context, "class_getInstanceVariable", cls, string);
            if (!ivar) continue;
            NSString *types = CNDCCSemanticCString(CNDCCSemanticCall(context,
                "ivar_getTypeEncoding", ivar, 0)) ?: @"";
            int64_t offset = (int64_t)CNDCCSemanticCall(context, "ivar_getOffset", ivar, 0);
            BOOL bounded = offset >= 8 && (uint64_t)offset % 8 == 0 &&
                size >= 8 && (uint64_t)offset <= size - 8;
            NSString *type = CNDCCSemanticUnqualifiedType(types);
            BOOL typed = [type hasPrefix:@"@"] && ![type hasPrefix:@"@?"];
            NSString *expected = context->focusScope ? nil : CNDCCRefinedSwiftReferenceSlots(className)[name];
            [ivars addObject:@{@"name": name, @"ownerClass": className,
                @"types": types, @"offset": @(offset), @"safeObjectSlot": @(bounded && typed),
                @"boundedSlot": @(bounded), @"expectedReferenceClass": expected ?: @"",
                @"diagnosticUntypedWord": @(bounded && !types.length &&
                    CNDCCRefinedUntypedWrapperSlot(className, name)),
                @"allowlistedOwnershipMember": @YES}];
        }
        NSArray *getterNames = context->focusScope ? CNDCCFocusGetterNames(className) : CNDCCRefinedGetterNames(className);
        for (NSString *name in getterNames) {
            NSDictionary *contract = CNDCCSemanticContract(context, cls, name);
            if (contract) contracts[name] = contract;
        }
        return @{@"className": className, @"ivars": ivars, @"contracts": contracts,
            @"discoveredMethods": @[], @"ownerClasses": @[className],
            @"metadataPolicy": @"finite-named-members-only"};
    }
    NSMutableDictionary *contracts = [NSMutableDictionary dictionary];
    NSMutableArray *ivars = [NSMutableArray array];
    NSMutableArray *methods = [NSMutableArray array];
    NSMutableArray *ownerClasses = [NSMutableArray array];
    uint64_t receiverClass = cls;
    NSMutableSet *getterNames = [NSMutableSet setWithArray:@[@"windows", @"rootViewController",
        @"viewIfLoaded", @"childViewControllers", @"presentedViewController",
        @"controlCenterController", @"controlCenterCoordinator", @"controlCenterService",
        @"moduleInstanceManager", @"moduleRegistry", @"moduleRepository", @"moduleSettingsManager",
        @"moduleInstancesByIdentifier", @"moduleControllersByIdentifier", @"moduleViewControllers",
        @"contentViewController", @"moduleContentViewController", @"expandedViewController",
        @"viewController", @"containerViewController"]];
    uint64_t instanceSize = CNDCCSemanticCall(
        context, "class_getInstanceSize", cls, 0);
    for (NSUInteger level = 0; level < 3 && r_is_objc_ptr(cls) &&
         CNDCCSemanticContinue(context); level++) {
        NSString *owner = CNDCCSemanticCString(CNDCCSemanticCall(
            context, "class_getName", cls, 0)) ?: @"unavailable";
        [ownerClasses addObject:owner];
        // NSObject/UIKit inheritance metadata overwhelms the useful custom
        // contracts and can be examined separately if a trace requires it.
        if ([owner hasPrefix:@"UI"] || [owner hasPrefix:@"NS"]) break;
        uint64_t list = CNDCCSemanticCall(context, "class_copyIvarList",
                                         cls, context->countSlot);
        uint32_t count = 0;
        if (list && remote_read(context->countSlot, &count, sizeof(count))) {
            if (count > CNDCCSemanticMemberCap) context->memberLimitReached = YES;
            for (NSUInteger i = 0; i < MIN(count, CNDCCSemanticMemberCap) &&
                 CNDCCSemanticContinue(context); i++) {
                if (context->members >= CNDCCSemanticGlobalMemberCap) {
                    context->memberLimitReached = YES; break;
                }
                context->members++;
                uint64_t ivar = remote_read64(list + i * sizeof(uint64_t));
                NSString *name = CNDCCSemanticCString(CNDCCSemanticCall(
                    context, "ivar_getName", ivar, 0)) ?: @"";
                NSString *types = CNDCCSemanticCString(CNDCCSemanticCall(
                    context, "ivar_getTypeEncoding", ivar, 0)) ?: @"";
                int64_t offset = (int64_t)CNDCCSemanticCall(
                    context, "ivar_getOffset", ivar, 0);
                NSString *type = CNDCCSemanticUnqualifiedType(types);
                BOOL objectTyped = [type hasPrefix:@"@"] &&
                    ![type hasPrefix:@"@?"] && offset >= (int64_t)sizeof(uint64_t) &&
                    (uint64_t)offset % sizeof(uint64_t) == 0 &&
                    instanceSize >= sizeof(uint64_t) &&
                    (uint64_t)offset <= instanceSize - sizeof(uint64_t);
                [ivars addObject:@{@"ownerClass": owner, @"name": name,
                    @"types": types, @"offset": @(offset),
                    @"safeObjectSlot": @(objectTyped),
                    @"allowlistedOwnershipMember": @(CNDCCSemanticOwnershipIvar(name))}];
            }
        }
        // Cleanup bypasses the diagnostic budget, but never a broken session.
        if (list && remote_call_current_success() && remote_call_current_pid() == context->pid &&
            remote_call_current_io_failure_count() == context->ioFailures) r_free(list);
        if (!CNDCCSemanticContinue(context)) break;
        list = CNDCCSemanticCall(context, "class_copyMethodList",
                                 cls, context->countSlot);
        count = 0;
        if (list && remote_read(context->countSlot, &count, sizeof(count))) {
            if (count > CNDCCSemanticMemberCap) context->memberLimitReached = YES;
            for (NSUInteger i = 0; i < MIN(count, CNDCCSemanticMemberCap) &&
                 CNDCCSemanticContinue(context); i++) {
                if (context->members >= CNDCCSemanticGlobalMemberCap) {
                    context->memberLimitReached = YES; break;
                }
                context->members++;
                uint64_t method = remote_read64(list + i * sizeof(uint64_t));
                uint64_t selector = CNDCCSemanticCall(
                    context, "method_getName", method, 0);
                NSString *name = CNDCCSemanticCString(CNDCCSemanticCall(
                    context, "sel_getName", selector, 0)) ?: @"";
                if ([CNDCCSemanticObjectGetters() containsObject:name])
                    [getterNames addObject:name];
                NSString *lower = name.lowercaseString;
                BOOL relevant = NO;
                for (NSString *token in @[@"transport", @"previous", @"next",
                    @"play", @"pause", @"forward", @"backward", @"package",
                    @"activity", @"focus", @"mode", @"identifier", @"symbol",
                    @"glyph", @"state", @"model", @"module", @"registry",
                    @"provider", @"descriptor", @"control", @"slider"]) {
                    if ([lower containsString:token]) { relevant = YES; break; }
                }
                if (!relevant) continue;
                NSString *types = CNDCCSemanticCString(CNDCCSemanticCall(
                    context, "method_getTypeEncoding", method, 0)) ?: @"";
                [methods addObject:@{@"ownerClass": owner, @"selector": name,
                    @"types": types, @"invoked": @NO}];
            }
        }
        if (list && remote_call_current_success() && remote_call_current_pid() == context->pid &&
            remote_call_current_io_failure_count() == context->ioFailures) r_free(list);
        cls = CNDCCSemanticCall(context, "class_getSuperclass", cls, 0);
    }
    for (NSString *selector in [getterNames.allObjects sortedArrayUsingSelector:@selector(compare:)]) {
        if (!CNDCCSemanticContinue(context)) break;
        NSDictionary *contract = CNDCCSemanticContract(context, receiverClass, selector);
        if (contract) contracts[selector] = contract;
    }
    return @{@"className": className, @"contracts": contracts,
        @"ivars": ivars, @"discoveredMethods": methods, @"ownerClasses": ownerClasses};
}

static void CNDCCSemanticEnqueue(CNDCCSemanticContext *context,
                                NSMutableArray *queue, NSMutableSet *seen,
                                uint64_t object, NSUInteger depth, NSString *domain)
{
    if (!r_is_objc_ptr(object) || [seen containsObject:@(object)]) return;
    if (depth > CNDCCSemanticDepthCap) { context->depthLimitReached = YES; return; }
    // Reserve a separate finite allowance for the diagnostic phase. Broad
    // ownership inventory cannot consume the loaded-descendant allowance.
    NSUInteger objectCap = CNDCCSemanticObjectCap +
        (context->refined && [domain isEqualToString:@"diagnosticDiscovery"]
            ? CNDCCRefinedDiscoveryObjectCap : 0);
    if (queue.count >= objectCap) { context->objectLimitReached = YES; return; }
    [seen addObject:@(object)];
    [queue addObject:@{@"object": @(object), @"depth": @(depth),
        @"diagnosticDiscovery": @(context->refined && [domain isEqualToString:@"diagnosticDiscovery"]),
        @"domain": domain ?: @"unknown"}];
}

static void CNDCCSemanticAddEdge(CNDCCSemanticContext *context,
                                 NSMutableArray *edges, NSDictionary *edge)
{
    if (edges.count >= CNDCCSemanticEdgeCap) { context->edgeLimitReached = YES; return; }
    [edges addObject:edge];
}

static uint64_t CNDCCSemanticObjectGetter(CNDCCSemanticContext *context,
                                        uint64_t object, NSString *selector)
{
    uint64_t cls = 0;
    (void)CNDCCSemanticClassName(context, object, &cls);
    return CNDCCSemanticGetter(context, object,
        CNDCCSemanticContract(context, cls, selector));
}

static NSUInteger CNDCCSemanticCollectionCount(CNDCCSemanticContext *context,
                                               uint64_t object, uint64_t cls)
{
    NSDictionary *countContract = CNDCCSemanticContract(context, cls, @"count");
    NSString *countType = CNDCCSemanticUnqualifiedType(countContract[@"types"] ?: @"");
    if ([countContract[@"argumentCount"] unsignedIntegerValue] != 2 ||
        !([countType hasPrefix:@"Q"] || [countType hasPrefix:@"q"]) ||
        !CNDCCSemanticContinue(context)) return 0;
    context->calls++;
    uint64_t count = r_msg2_main(object, "count", 0, 0, 0, 0);
    if (count > CNDCCSemanticCollectionCap) context->collectionLimitReached = YES;
    return CNDCCBoundedCount(count, CNDCCSemanticCollectionCap, NULL);
}

static uint64_t CNDCCSemanticArrayElement(CNDCCSemanticContext *context,
                                         uint64_t array, NSUInteger index)
{
    uint64_t cls = 0;
    (void)CNDCCSemanticClassName(context, array, &cls);
    NSDictionary *contract = CNDCCSemanticContract(context, cls, @"objectAtIndex:");
    NSString *types = CNDCCSemanticUnqualifiedType(contract[@"types"] ?: @"");
    // Validate the explicit argument too: an object-returning three-argument
    // method alone does not prove NSUInteger indexing is ABI safe.
    NSString *pattern = @"^@(?:\"[^\"]*\")?[0-9]*@[0-9]*:[0-9]*[Qq][0-9]*$";
    if ([contract[@"argumentCount"] unsignedIntegerValue] != 3 ||
        [types rangeOfString:pattern options:NSRegularExpressionSearch].location == NSNotFound ||
        !CNDCCSemanticContinue(context)) return 0;
    context->calls++;
    return r_msg2_main(array, "objectAtIndex:", index, 0, 0, 0);
}

static BOOL CNDCCSemanticCollectionClass(NSString *className)
{
    BOOL foundation = [className hasPrefix:@"NS"] || [className hasPrefix:@"__NS"] ||
        [className hasPrefix:@"_NS"] || [className hasPrefix:@"__CF"];
    return foundation && ([className containsString:@"Array"] ||
        [className containsString:@"Dictionary"] || [className containsString:@"Set"]);
}

static void CNDCCSemanticInspectCollection(CNDCCSemanticContext *context,
                                           NSMutableArray *queue, NSMutableSet *seen,
                                           NSMutableArray *edges, uint64_t object,
                                           NSString *className, uint64_t cls,
                                           NSUInteger depth, NSString *domain)
{
    NSUInteger count = CNDCCSemanticCollectionCount(context, object, cls);
    BOOL dictionary = [className containsString:@"Dictionary"];
    uint64_t array = object;
    NSDictionary *lookup = nil;
    if (dictionary) {
        array = CNDCCSemanticObjectGetter(context, object, @"allKeys");
        lookup = CNDCCSemanticContract(context, cls, @"objectForKey:");
        NSString *types = CNDCCSemanticUnqualifiedType(lookup[@"types"] ?: @"");
        if ([lookup[@"argumentCount"] unsignedIntegerValue] != 3 ||
            [types rangeOfString:@"^@(?:\"[^\"]*\")?[0-9]*@[0-9]*:[0-9]*@[0-9]*$"
                options:NSRegularExpressionSearch].location == NSNotFound) return;
    } else if ([className containsString:@"Set"] && ![className containsString:@"OrderedSet"]) {
        array = CNDCCSemanticObjectGetter(context, object, @"allObjects");
    }
    for (NSUInteger i = 0; i < count && CNDCCSemanticContinue(context); i++) {
        uint64_t element = CNDCCSemanticArrayElement(context, array, i);
        uint64_t key = dictionary ? element : 0;
        if (dictionary && r_is_objc_ptr(key)) {
            context->calls++;
            element = r_msg2_main(object, "objectForKey:", key, 0, 0, 0);
        }
        if (!r_is_objc_ptr(element)) continue;
        NSString *elementClass = CNDCCSemanticClassName(context, element, NULL);
        NSMutableDictionary *edge = [@{@"kind": dictionary ? @"dictionaryMember" : @"collectionElement",
            @"indexSnapshot": @(i), @"indexIsIdentity": @NO,
            @"fromAddress": CNDCCAddress(object), @"toAddress": CNDCCAddress(element),
            @"toClass": elementClass, @"membershipMustBeReResolved": @YES} mutableCopy];
        if (dictionary) {
            NSString *keyClass = CNDCCSemanticClassName(context, key, NULL);
            NSString *machineKey = CNDCCSemanticIdentityValue(context, key, keyClass);
            if (machineKey) edge[@"machineKey"] = machineKey;
            edge[@"keyClass"] = keyClass;
        }
        NSString *machineValue = CNDCCSemanticIdentityValue(context, element, elementClass);
        if (machineValue) edge[@"machineValue"] = machineValue;
        CNDCCSemanticAddEdge(context, edges, edge);
        CNDCCSemanticEnqueue(context, queue, seen, element, depth + 1, domain);
    }
}

static NSArray<NSNumber *> *CNDCCSemanticPathPreference(NSArray *path)
{
    NSUInteger stableRank = 0, transientCount = 0;
    for (NSDictionary *step in path) {
        NSDictionary *evidence = CNDCCLifecycleClassEvidence(step[@"toClass"] ?: step[@"className"] ?: @"");
        if ([evidence[@"stableOwnerCandidate"] boolValue] &&
            ![evidence[@"kind"] isEqualToString:@"process-owner"])
            stableRank = MAX(stableRank, [evidence[@"rank"] unsignedIntegerValue]);
        else if ([evidence[@"rank"] unsignedIntegerValue] &&
            ![evidence[@"stableOwnerCandidate"] boolValue]) transientCount++;
    }
    return @[@(stableRank), @(transientCount), @(path.count)];
}

static BOOL CNDCCSemanticPreferPath(NSArray *candidate, NSArray *current)
{
    if (!current) return YES;
    NSArray *next = CNDCCSemanticPathPreference(candidate);
    NSArray *prior = CNDCCSemanticPathPreference(current);
    if (![next[0] isEqual:prior[0]]) return [next[0] unsignedIntegerValue] > [prior[0] unsignedIntegerValue];
    if (![next[1] isEqual:prior[1]]) return [next[1] unsignedIntegerValue] < [prior[1] unsignedIntegerValue];
    return [next[2] unsignedIntegerValue] < [prior[2] unsignedIntegerValue];
}

static NSDictionary *CNDCCSemanticDirectPaths(NSArray *roots, NSArray *edges)
{
    NSMutableDictionary *paths = [NSMutableDictionary dictionary];
    NSMutableArray *queue = [NSMutableArray array];
    NSMutableDictionary *outgoing = [NSMutableDictionary dictionary];
    for (NSDictionary *edge in edges) {
        if (![@[@"getter", @"ivar", @"collectionElement", @"dictionaryMember"]
            containsObject:edge[@"kind"]]) continue;
        NSString *from = edge[@"fromAddress"];
        NSString *to = edge[@"toAddress"];
        if (!from.length || !to.length) continue;
        if (!outgoing[from]) outgoing[from] = [NSMutableArray array];
        [outgoing[from] addObject:edge];
    }
    for (NSDictionary *root in roots) {
        NSString *address = root[@"address"];
        if (!address.length || paths[address]) continue;
        paths[address] = @[@{@"kind": @"root", @"address": address,
            @"className": root[@"className"] ?: @"", @"acquisition": root[@"acquisition"] ?: @{}}];
        [queue addObject:address];
    }
    for (NSUInteger i = 0; i < queue.count && i < CNDCCSemanticEdgeCap; i++) {
        NSString *from = queue[i];
        if ([paths[from] count] > CNDCCSemanticDepthCap) continue;
        for (NSDictionary *edge in outgoing[from]) {
            NSString *to = edge[@"toAddress"];
            BOOL cycle = NO;
            for (NSDictionary *step in paths[from]) {
                if ([to isEqualToString:step[@"toAddress"] ?: step[@"address"]]) { cycle = YES; break; }
            }
            if (cycle || (!paths[to] && paths.count >= CNDCCSemanticObjectCap)) continue;
            NSArray *candidate = [paths[from] arrayByAddingObject:edge];
            // A later registry/model route may provide a stronger lifecycle
            // owner than the first, shorter controller-to-view route.
            if (!CNDCCSemanticPreferPath(candidate, paths[to])) continue;
            paths[to] = candidate;
            [queue addObject:to];
        }
    }
    return paths;
}

static NSDictionary *CNDCCLifecycleAnchorEvidence(NSArray *path, NSDictionary *objects)
{
    NSUInteger bestRank = 0, bestIndex = 0;
    NSDictionary *anchor = nil;
    NSUInteger transientHops = 0;
    BOOL membershipReconstructionUnresolved = NO;
    for (NSUInteger i = 0; i < path.count; i++) {
        NSDictionary *edge = path[i];
        NSString *address = i == 0 ? edge[@"address"] : edge[@"toAddress"];
        NSDictionary *object = objects[address] ?: @{};
        NSString *className = object[@"className"] ?: (i == 0 ? edge[@"className"] : edge[@"toClass"]);
        NSDictionary *lifecycle = object[@"lifecycle"] ?: CNDCCLifecycleClassEvidence(className ?: @"");
        if ([lifecycle[@"rank"] unsignedIntegerValue] > 0 &&
            ![lifecycle[@"stableOwnerCandidate"] boolValue]) transientHops++;
        // A process root reconstructs the namespace. Select the strongest
        // downstream controller/model/provider anchor for an eventual adapter.
        if ([lifecycle[@"stableOwnerCandidate"] boolValue] &&
            ![lifecycle[@"kind"] isEqualToString:@"process-owner"] &&
            [lifecycle[@"rank"] unsignedIntegerValue] > bestRank) {
            bestRank = [lifecycle[@"rank"] unsignedIntegerValue];
            bestIndex = i;
            anchor = @{@"address": address ?: @"", @"className": className ?: @"",
                @"lifecycle": lifecycle, @"machineIdentities": object[@"machineIdentities"] ?: @{}};
        }
        if ([@[@"collectionElement", @"dictionaryMember"] containsObject:edge[@"kind"]] &&
            ![edge[@"machineKey"] length] && ![object[@"machineIdentities"] count])
            membershipReconstructionUnresolved = YES;
    }
    NSMutableArray *unresolved = [NSMutableArray arrayWithObject:
        @"Owner lifetime and target re-resolution after redraw/page reconstruction have not been observed."];
    if (!path.count) [unresolved addObject:@"No allowlisted route from an acquired process/container root."];
    if (!anchor) [unresolved addObject:@"No stable controller/model/provider/descriptor anchor was reached."];
    if (transientHops) [unresolved addObject:@"The downstream route crosses transient rendering objects; their addresses must be re-resolved."];
    if (membershipReconstructionUnresolved)
        [unresolved addObject:@"Collection membership has no captured machine key or member identity; position cannot reconstruct it."];
    return @{@"highestStableAnchor": anchor ?: NSNull.null,
        @"stableAnchorRank": @(bestRank), @"processRoot": path.firstObject ?: @{},
        @"rootToAnchorPath": anchor ? [path subarrayWithRange:NSMakeRange(0, bestIndex + 1)] : @[],
        @"anchorToTargetPath": anchor ? [path subarrayWithRange:NSMakeRange(bestIndex + 1,
            path.count - bestIndex - 1)] : @[],
        @"transientRenderingHopCount": @(transientHops),
        @"membershipReconstructionUnresolved": @(membershipReconstructionUnresolved),
        @"samePIDPersistenceVerified": @NO, @"implementationReady": @NO,
        @"unresolved": unresolved};
}

// BEGIN EXPLICIT REFINED DISCOVERY: diagnostic only, never a production route.
static void CNDCCRefinedDiscoverChildren(CNDCCSemanticContext *context,
    NSMutableArray *queue, NSMutableSet *seen, NSMutableArray *edges,
    NSMutableArray *frontier, NSMutableSet *discoverySeen,
    uint64_t object, NSUInteger depth)
{
    if (!context->refined || context->discoveryObjects >= 128 ||
        !CNDCCSemanticContinue(context)) return;
    uint64_t children = CNDCCSemanticObjectGetter(context, object, @"subviews");
    uint64_t cls = 0;
    NSString *name = CNDCCSemanticClassName(context, children, &cls);
    if (!CNDCCSemanticCollectionClass(name)) return;
    NSUInteger count = CNDCCSemanticCollectionCount(context, children, cls);
    for (NSUInteger i = 0; i < count && context->discoveryObjects < 128 &&
        CNDCCSemanticContinue(context); i++) {
        uint64_t child = CNDCCSemanticArrayElement(context, children, i);
        if (!r_is_objc_ptr(child) || [discoverySeen containsObject:@(child)]) continue;
        if (depth >= CNDCCSemanticDepthCap) { context->depthLimitReached = YES; continue; }
        [discoverySeen addObject:@(child)];
        context->discoveryObjects++;
        // This frontier is independent of ownership 'seen'. Already inspected
        // module/wrapper views still need their loaded children visited.
        [frontier addObject:@{@"object": @(child), @"depth": @(depth + 1)}];
        CNDCCSemanticAddEdge(context, edges, @{@"kind": @"diagnosticDiscovery",
            @"name": @"loaded-view-descendant", @"productionRoute": @NO,
            @"indexIsIdentity": @NO, @"fromAddress": CNDCCAddress(object),
            @"toAddress": CNDCCAddress(child),
            @"toClass": CNDCCSemanticClassName(context, child, NULL)});
        CNDCCSemanticEnqueue(context, queue, seen, child, depth + 1, @"diagnosticDiscovery");
    }
    if (context->discoveryObjects >= 128) context->objectLimitReached = YES;
}
// END EXPLICIT REFINED DISCOVERY

// Correlate only with cached classes of independently acquired objects. This
// performs no target read/call and never interprets a Swift collection layout.
// The resumed named-member pass uses those acquired objects, not raw words.
static void CNDCCRefinedValidateWrapperWords(CNDCCSemanticContext *context,
    NSArray *rows, NSMutableArray *edges)
{
    if (!context->refined || !CNDCCSemanticContinue(context)) return;
    for (NSDictionary *row in rows) for (NSMutableDictionary *slot in row[@"objectIvars"]) {
        if (![slot[@"diagnosticUntypedWord"] boolValue] ||
            ![slot[@"slotReadSucceeded"] boolValue]) continue;
        uint64_t word = strtoull([slot[@"rawWordHex"] UTF8String], NULL, 16);
        NSNumber *knownClass = context->objectClasses[@(word)];
        NSString *knownName = knownClass ? context->classNames[knownClass] : nil;
        if (!knownName.length) continue;
        slot[@"independentAddressValidated"] = @YES;
        slot[@"independentlyObservedClass"] = knownName;
        slot[@"validationPhase"] = @"after independent acquisition, before resumed named-member inspection";
        CNDCCSemanticAddEdge(context, edges, @{@"kind": @"diagnosticWrapperReference",
            @"name": slot[@"name"], @"fromAddress": row[@"address"],
            @"toAddress": slot[@"rawWordHex"], @"toClass": knownName,
            @"independentAddressValidated": @YES, @"slotTypeVerified": @NO,
            @"productionRoute": @NO, @"valueDereferenced": @NO});
    }
}

static NSDictionary *CNDCCThemingCopyLifecycleOwnerTraceImpl(BOOL refined, BOOL focusScope)
{
    int pid = remote_call_current_pid();
    NSMutableDictionary *report = [@{
        @"schemaVersion": @2, @"mode": @"physical-read-only-lifecycle-owner-trace",
        @"target": @"SpringBoard", @"targetPID": @(pid), @"success": @NO,
        @"readOnly": @YES, @"controlActions": @0, @"presentationWrites": @0,
        @"radioWrites": @0, @"fileWrites": @0, @"runtimeMetadataWrites": @0,
        @"usesLabelsAsIdentity": @NO, @"usesGeometryAsIdentity": @NO,
        @"viewHierarchyTraversal": @NO, @"recursiveFallbackUsed": @NO,
        @"implementationReady": @NO, @"samePIDPersistenceVerified": @NO,
        @"controllers": @[], @"roots": @[], @"objects": @[],
        @"classContracts": @[], @"edges": @[], @"routeCandidates": @[],
        @"goal": @"Anchor future adapters at lifecycle owners so they can re-resolve targets after ordinary redraws and page/view reconstruction within the same SpringBoard PID.",
    } mutableCopy];
    if (pid <= 1 || !remote_call_current_success()) {
        report[@"failureReason"] = @"The SpringBoard session was not healthy and PID-bound at entry.";
        return report;
    }
    uint32_t settle = r_settle_us(0);
    NSMutableDictionary *contracts = [NSMutableDictionary dictionary];
    NSMutableDictionary *objectClasses = [NSMutableDictionary dictionary];
    NSMutableDictionary *classNames = [NSMutableDictionary dictionary];
    CNDCCSemanticContext context = {
        .started = [NSProcessInfo processInfo].systemUptime,
        .pid = pid, .ioFailures = remote_call_current_io_failure_count(),
        .refined = refined, .focusScope = focusScope,
        .contracts = contracts, .objectClasses = objectClasses, .classNames = classNames,
    };
    NSMutableArray *controllers = [NSMutableArray array];
    NSMutableArray *roots = [NSMutableArray array];
    NSMutableArray *rootAcquisitions = [NSMutableArray array];
    NSMutableArray *queue = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];
    NSMutableArray *rows = [NSMutableArray array];
    NSMutableArray *edges = [NSMutableArray array];
    NSMutableDictionary *metadataCache = [NSMutableDictionary dictionary];
    NSMutableSet *priorityClasses = [NSMutableSet set];
    NSMutableArray *priorityClassEvidence = [NSMutableArray array];
    NSUInteger classCap = refined ? 128 : CNDCCSemanticClassCap;
    NSUInteger genericClassCount = 0;
    NSUInteger dynamicPriorityClassCount = 0;
    const NSUInteger dynamicPriorityClassCap = 32;
    NSArray *exactPriorityNames = focusScope ? CNDCCFocusPriorityClassNames() : CNDCCRefinedPriorityClassNames();
    @try {
        context.countSlot = CNDCCSemanticCall(&context, "calloc", 1, sizeof(uint32_t));
        if (refined) {
            for (NSString *name in exactPriorityNames) {
                BOOL continued = CNDCCSemanticContinue(&context);
                uint64_t cls = 0;
                if (continued && context.countSlot) { context.calls++; cls = r_class(name.UTF8String); }
                BOOL inspected = cls && CNDCCSemanticContinue(&context) && context.countSlot;
                if (inspected) {
                    metadataCache[@(cls)] = CNDCCSemanticClassMetadata(&context, cls, name);
                    [priorityClasses addObject:@(cls)];
                }
                [priorityClassEvidence addObject:@{@"className": name, @"available": @(cls != 0),
                    @"inspected": @(inspected), @"classBudgetExempt": @YES,
                    @"metadataComplete": @(inspected && CNDCCSemanticContinue(&context)),
                    @"reason": inspected ? @"dedicated exact-class pass before lifecycle inventory"
                        : (!continued ? @"time/call/session limit" : (!context.countSlot ? @"scratch unavailable" : @"class not loaded"))}];
            }
            if (!focusScope) {
                NSMutableArray *providerEvidence = [NSMutableArray array];
                context.calls++;
                uint64_t provider = r_class("MRUAssetsProvider");
                uint64_t meta = provider ? CNDCCSemanticCall(&context, "object_getClass", provider, 0) : 0;
                for (NSString *selector in @[@"forwardBackwardPackageName", @"playPauseStopPackageName"]) {
                    NSDictionary *contract = CNDCCSemanticContract(&context, meta, selector);
                    uint64_t value = CNDCCSemanticGetter(&context, provider, contract);
                    NSString *name = CNDCCSemanticClassName(&context, value, NULL);
                    [providerEvidence addObject:@{@"className": @"MRUAssetsProvider", @"selector": selector,
                        @"contract": contract ?: @{}, @"classMethod": @YES,
                        @"machineValue": CNDCCSemanticIdentityValue(&context, value, name) ?: NSNull.null}];
                }
                report[@"staticMediaProviderEvidence"] = providerEvidence;
            }
        }
        // Begin at process/container and registry owners, without a media or
        // Focus class-name gate. The generic application/window/controller
        // routes remain available even if optional private services are absent.
        for (NSArray *entry in @[
            @[@"UIApplication", @"sharedApplication"],
            @[@"SBControlCenterController", @"sharedInstance"],
            @[@"CCUIControlCenter", @"sharedInstance"],
            @[@"CCUIModuleInstanceManager", @"sharedInstance"],
            @[@"CCUIModuleSettingsManager", @"sharedInstance"],
            @[@"CCUIModuleRepository", @"sharedInstance"],
            @[@"CCUIModuleRegistry", @"sharedInstance"],
        ]) {
            if (focusScope && ![@[@"UIApplication", @"SBControlCenterController", @"CCUIModuleInstanceManager"]
                containsObject:entry[0]]) continue;
            if (!CNDCCSemanticContinue(&context)) break;
            context.calls++;
            uint64_t cls = r_class([entry[0] UTF8String]);
            uint64_t meta = cls ? CNDCCSemanticCall(&context, "object_getClass", cls, 0) : 0;
            NSDictionary *contract = CNDCCSemanticContract(&context, meta, entry[1]);
            uint64_t object = CNDCCSemanticGetter(&context, cls, contract);
            NSString *className = CNDCCSemanticClassName(&context, object, NULL);
            NSDictionary *acquisition = @{@"className": entry[0], @"selector": entry[1],
                @"contract": contract ?: @{}, @"available": @(r_is_objc_ptr(object))};
            [rootAcquisitions addObject:acquisition];
            if (!r_is_objc_ptr(object) || [seen containsObject:@(object)]) continue;
            [roots addObject:@{@"address": CNDCCAddress(object), @"className": className,
                @"acquisition": acquisition}];
            CNDCCSemanticEnqueue(&context, queue, seen, object, 0, CNDCCSemanticDomain(className));
        }
        BOOL discoverySeeded = focusScope;
        for (NSUInteger i = 0; (i < queue.count || (refined && !discoverySeeded)) &&
            CNDCCSemanticContinue(&context); i++) {
            if (i == queue.count) {
                discoverySeeded = YES;
                NSMutableArray *frontier = [NSMutableArray array];
                NSMutableSet *discoverySeen = [NSMutableSet set];
                // Run after primary ownership inspection, from loaded scoped
                // objects only. This never obtains/materializes controller.view.
                for (NSDictionary *seed in [rows copy]) {
                    NSString *name = seed[@"className"];
                    if ([name isEqualToString:@"MediaControls.MediaControlsModuleView"] ||
                        CNDCCRefinedUntypedWrapperSlot(name, @"contentView") ||
                        [name isEqualToString:@"CCUIControlHostView"] ||
                        [name isEqualToString:@"CCUIFlashlightModuleViewController"]) {
                        uint64_t root = strtoull([seed[@"address"] UTF8String], NULL, 16);
                        if ([name isEqualToString:@"CCUIFlashlightModuleViewController"])
                            root = CNDCCSemanticObjectGetter(&context, root, @"viewIfLoaded");
                        if (r_is_objc_ptr(root) && ![discoverySeen containsObject:@(root)]) {
                            [discoverySeen addObject:@(root)];
                            [frontier addObject:@{@"object": @(root),
                                @"depth": seed[@"ownershipDepth"] ?: @0}];
                        }
                    }
                }
                for (NSUInteger next = 0; next < frontier.count &&
                    CNDCCSemanticContinue(&context); next++) {
                    CNDCCRefinedDiscoverChildren(&context, queue, seen, edges, frontier, discoverySeen,
                        [frontier[next][@"object"] unsignedLongLongValue],
                        [frontier[next][@"depth"] unsignedIntegerValue]);
                }
                CNDCCRefinedValidateWrapperWords(&context, rows, edges);
                if (i >= queue.count) break;
            }
            // Select known exact targets and their collections before generic
            // entries already waiting in the queue. No runtime class is
            // obtained from an untyped word to make this selection.
            if (refined) for (NSUInteger next = i; next < queue.count; next++) {
                NSNumber *queuedObject = queue[next][@"object"];
                NSNumber *queuedClassNumber = objectClasses[queuedObject];
                NSString *queuedClass = queuedClassNumber ? classNames[queuedClassNumber] : nil;
                if ((focusScope ? CNDCCFocusPriorityClass(queuedClass) : CNDCCRefinedPriorityClass(queuedClass)) ||
                    ((focusScope || [queue[next][@"domain"] isEqualToString:@"media"]) &&
                        CNDCCSemanticCollectionClass(queuedClass))) {
                    if (next != i) [queue exchangeObjectAtIndex:i withObjectAtIndex:next];
                    break;
                }
            }
            NSDictionary *entry = queue[i];
            uint64_t object = [entry[@"object"] unsignedLongLongValue];
            NSUInteger depth = [entry[@"depth"] unsignedIntegerValue];
            uint64_t cls = 0;
            NSString *className = CNDCCSemanticClassName(&context, object, &cls);
            NSString *domain = [entry[@"diagnosticDiscovery"] boolValue] ? @"diagnosticDiscovery"
                : (CNDCCSemanticDomain(className) ?: entry[@"domain"]);
            NSMutableDictionary *row = [@{@"address": CNDCCAddress(object),
                @"className": className, @"domain": domain ?: @"unknown",
                @"ownershipDepth": @(depth), @"lifecycle": CNDCCLifecycleClassEvidence(className)} mutableCopy];
            [rows addObject:row];
            row[@"priorityTarget"] = @(refined && (focusScope ? CNDCCFocusPriorityClass(className) : CNDCCRefinedPriorityClass(className)));
            row[@"diagnosticDiscovery"] = entry[@"diagnosticDiscovery"] ?: @NO;
            if ([className containsString:@"ViewController"] ||
                [className hasSuffix:@"Controller"]) {
                if (controllers.count < CNDCCSemanticControllerCap) [controllers addObject:row];
                else { context.controllerLimitReached = YES; row[@"inspectionSkipped"] = @"controller limit"; continue; }
            }
            if (CNDCCSemanticCollectionClass(className)) {
                row[@"collectionMembershipIsIdentity"] = @NO;
                CNDCCSemanticInspectCollection(&context, queue, seen, edges, object,
                    className, cls, depth, domain);
                continue;
            }
            if (!CNDCCSemanticDataObject(className)) continue;
            NSDictionary *metadata = metadataCache[@(cls)];
            BOOL priorityTarget = [row[@"priorityTarget"] boolValue];
            BOOL dynamicPriority = priorityTarget && ![exactPriorityNames containsObject:className];
            BOOL classAllowed = priorityTarget ? (!dynamicPriority || dynamicPriorityClassCount < dynamicPriorityClassCap)
                : genericClassCount < classCap;
            if (!metadata && context.countSlot && classAllowed) {
                metadata = CNDCCSemanticClassMetadata(&context, cls, className);
                metadataCache[@(cls)] = metadata;
                if (priorityTarget) [priorityClasses addObject:@(cls)];
                else genericClassCount++;
                if (dynamicPriority) dynamicPriorityClassCount++;
            }
            if (!metadata) {
                if (priorityTarget) context.priorityClassLimitReached |= !classAllowed;
                else context.classLimitReached |= !classAllowed;
                row[@"inspectionSkipped"] = context.countSlot
                    ? (priorityTarget ? @"priority runtime class budget" : @"runtime class budget") : @"scratch unavailable";
                continue;
            }
            row[@"ownerClasses"] = metadata[@"ownerClasses"];
            if ([row[@"lifecycle"][@"rank"] unsignedIntegerValue] == 0) {
                for (NSString *ownerClass in metadata[@"ownerClasses"]) {
                    NSDictionary *evidence = CNDCCLifecycleClassEvidence(ownerClass);
                    if ([evidence[@"rank"] unsignedIntegerValue]) {
                        row[@"lifecycle"] = evidence;
                        row[@"lifecycleEvidenceClass"] = ownerClass;
                        break;
                    }
                }
            }
            // Per-instance delivery subclasses can hide the familiar class
            // suffix. ABI-checked controller contracts still record them.
            if (![controllers containsObject:row] &&
                [metadata[@"contracts"][@"childViewControllers"][@"objectGetterABI"] boolValue] &&
                [metadata[@"contracts"][@"viewIfLoaded"][@"objectGetterABI"] boolValue]) {
                if (controllers.count < CNDCCSemanticControllerCap) [controllers addObject:row];
                else { context.controllerLimitReached = YES; row[@"inspectionSkipped"] = @"controller limit"; continue; }
            }
            NSMutableDictionary *identities = [NSMutableDictionary dictionary];
            NSMutableArray *values = [NSMutableArray array];
            for (NSDictionary *ivar in metadata[@"ivars"]) {
                if (!CNDCCSemanticContinue(&context)) break;
                BOOL verifiedReference = NO;
                NSString *expected = ivar[@"expectedReferenceClass"];
                if (refined && [ivar[@"diagnosticUntypedWord"] boolValue]) {
                    uint64_t word = 0;
                    context.calls++;
                    BOOL read = remote_read(object + [ivar[@"offset"] unsignedLongLongValue],
                        &word, sizeof(word));
                    NSMutableDictionary *snapshot = [ivar mutableCopy];
                    snapshot[@"rawWordHex"] = read ? CNDCCAddress(word) : @"unavailable";
                    snapshot[@"slotReadSucceeded"] = @(read);
                    snapshot[@"valueDereferenced"] = @NO;
                    snapshot[@"expectedReferenceClassKnown"] = @NO;
                    snapshot[@"productionRoute"] = @NO;
                    snapshot[@"resolved"] = @NO;
                    snapshot[@"interpretation"] = @"untyped word only; no Swift struct/array layout assumed";
                    [values addObject:snapshot];
                    continue;
                }
                if (![ivar[@"safeObjectSlot"] boolValue] &&
                    !(refined && [ivar[@"boundedSlot"] boolValue] && expected.length)) continue;
                if (![ivar[@"allowlistedOwnershipMember"] boolValue]) continue;
                context.calls++;
                uint64_t value = 0;
                if (!remote_read(object + [ivar[@"offset"] unsignedLongLongValue], &value, sizeof(value))) continue;
                NSMutableDictionary *snapshot = [ivar mutableCopy];
                snapshot[@"valueAddress"] = CNDCCAddress(value);
                snapshot[@"slotReadSucceeded"] = @YES;
                if (![ivar[@"safeObjectSlot"] boolValue]) {
                    uint64_t readableHeader = 0;
                    if (r_is_objc_ptr(value) && remote_read(value, &readableHeader, sizeof(readableHeader)) &&
                        CNDCCSemanticContinue(&context)) {
                        uint64_t actualClass = CNDCCSemanticCall(&context, "object_getClass", value, 0);
                        context.calls++;
                        uint64_t expectedClass = r_class(expected.UTF8String);
                        verifiedReference = expectedClass && actualClass == expectedClass;
                    }
                    snapshot[@"runtimeReferenceClassMatched"] = @(verifiedReference);
                    if (!verifiedReference) { [values addObject:snapshot]; continue; }
                    snapshot[@"validation"] = @"VM-confirmed named class reference; dynamic bounded offset and exact physical runtime class match";
                }
                if (r_is_objc_ptr(value)) {
                    NSString *valueClass = CNDCCSemanticClassName(&context, value, NULL);
                    snapshot[@"valueClass"] = valueClass;
                    if (CNDCCSemanticIdentityName(ivar[@"name"])) {
                        NSString *identity = CNDCCSemanticIdentityValue(&context, value, valueClass);
                        if (identity) {
                            snapshot[@"machineValue"] = identity;
                            NSString *name = [ivar[@"name"] stringByTrimmingCharactersInSet:
                                [NSCharacterSet characterSetWithCharactersInString:@"_"]];
                            identities[name] = identity;
                        }
                    }
                    CNDCCSemanticAddEdge(&context, edges, @{@"kind": @"ivar", @"name": ivar[@"name"],
                        @"verifiedSwiftReference": @(verifiedReference),
                        @"ownerClass": ivar[@"ownerClass"], @"types": ivar[@"types"],
                        @"offset": ivar[@"offset"], @"fromAddress": CNDCCAddress(object),
                        @"toAddress": CNDCCAddress(value), @"toClass": valueClass});
                    CNDCCSemanticEnqueue(&context, queue, seen, value, depth + 1, domain);
                }
                [values addObject:snapshot];
            }
            row[@"objectIvars"] = values;
            NSMutableDictionary *getters = [NSMutableDictionary dictionary];
            for (NSString *selector in [[metadata[@"contracts"] allKeys]
                sortedArrayUsingSelector:@selector(compare:)]) {
                if (!CNDCCSemanticContinue(&context)) break;
                NSDictionary *contract = metadata[@"contracts"][selector];
                if (![contract[@"objectGetterABI"] boolValue]) continue;
                NSUInteger callsBeforeGetter = context.calls;
                uint64_t value = CNDCCSemanticGetter(&context, object, contract);
                NSMutableDictionary *snapshot = [@{@"contract": contract,
                    @"valueAddress": CNDCCAddress(value),
                    @"getterInvoked": @(context.calls > callsBeforeGetter),
                    @"getterSucceeded": @(context.calls > callsBeforeGetter && remote_call_current_success() &&
                        remote_call_current_pid() == context.pid && remote_call_current_io_failure_count() == context.ioFailures)} mutableCopy];
                if (r_is_objc_ptr(value)) {
                    NSString *valueClass = CNDCCSemanticClassName(&context, value, NULL);
                    snapshot[@"valueClass"] = valueClass;
                    if (CNDCCSemanticIdentityName(selector)) {
                        NSString *identity = CNDCCSemanticIdentityValue(&context, value, valueClass);
                        if (identity) { snapshot[@"machineValue"] = identity; identities[selector] = identity; }
                    }
                    CNDCCSemanticAddEdge(&context, edges, @{@"kind": @"getter", @"name": selector,
                        @"types": contract[@"types"], @"fromAddress": CNDCCAddress(object),
                        @"toAddress": CNDCCAddress(value), @"toClass": valueClass});
                    CNDCCSemanticEnqueue(&context, queue, seen, value, depth + 1, domain);
                }
                getters[selector] = snapshot;
            }
            row[@"getters"] = getters;
            row[@"machineIdentities"] = identities;
            if (refined && !focusScope) {
                NSDictionary *flip = CNDCCSemanticContract(&context, cls, @"isHorizontallyFlipped");
                NSString *type = CNDCCSemanticUnqualifiedType(flip[@"types"] ?: @"");
                if ([flip[@"argumentCount"] unsignedIntegerValue] == 2 &&
                    [type rangeOfString:@"^[Bc][0-9]*@[0-9]*:[0-9]*$"
                        options:NSRegularExpressionSearch].location != NSNotFound &&
                    CNDCCSemanticContinue(&context)) {
                    context.calls++;
                    row[@"checkedScalars"] = @{@"isHorizontallyFlipped": @{
                        @"contract": flip, @"value": @(r_msg2_main(object,
                            "isHorizontallyFlipped", 0, 0, 0, 0) != 0)}};
                }
            }
        }
    } @finally {
        // Never send cleanup into a different PID or a failed transport.
        if (context.countSlot && remote_call_current_success() &&
            remote_call_current_pid() == pid &&
            remote_call_current_io_failure_count() == context.ioFailures) {
            r_free(context.countSlot);
            context.scratchFreed = remote_call_current_success();
        }
        (void)r_settle_us(settle);
    }
    NSDictionary *directPaths = CNDCCSemanticDirectPaths(roots, edges);
    NSMutableDictionary *byAddress = [NSMutableDictionary dictionary];
    for (NSDictionary *row in rows) byAddress[row[@"address"]] = row;
    NSMutableArray *candidates = [NSMutableArray array];
    NSMutableDictionary *roleEvidence = [NSMutableDictionary dictionary];
    for (NSDictionary *row in rows) {
        NSArray *path = directPaths[row[@"address"]] ?: @[];
        NSMutableSet *roles = [NSMutableSet setWithArray:CNDCCSemanticRoles(row[@"className"],
            row[@"machineIdentities"] ?: @{}, @"")];
        // Exact machine-named ownership members establish transport roles,
        // including their downstream package/image consumers.
        for (NSDictionary *edge in path) {
            for (NSString *role in CNDCCSemanticRoles(@"", @{}, edge[@"name"] ?: @""))
                [roles addObject:role];
        }
        if (!roles.count && [row[@"lifecycle"][@"rank"] unsignedIntegerValue] == 0) continue;
        NSMutableDictionary *candidate = [row mutableCopy];
        candidate[@"semanticRoles"] = [roles.allObjects sortedArrayUsingSelector:@selector(compare:)];
        candidate[@"hasDirectControllerRoute"] = @(path.count > 0); // legacy report consumer
        candidate[@"directControllerRoute"] = path;
        candidate[@"ownershipRoute"] = path;
        candidate[@"lifecycleAnchoring"] = CNDCCLifecycleAnchorEvidence(path, byAddress);
        candidate[@"implementationReady"] = @NO;
        [candidates addObject:candidate];
        for (NSString *role in roles) {
            if (!roleEvidence[role]) roleEvidence[role] = [NSMutableArray array];
            [roleEvidence[role] addObject:@{@"address": row[@"address"], @"className": row[@"className"],
                @"hasOwnershipRoute": @(path.count > 0),
                @"stableAnchorRank": candidate[@"lifecycleAnchoring"][@"stableAnchorRank"]}];
        }
    }
    NSMutableArray *unresolved = [NSMutableArray array];
    for (NSString *role in @[@"media.previous", @"media.playPause", @"media.next",
        @"focus.activityOrMode", @"flashlight", @"brightness", @"volume",
        @"camera", @"qrCode", @"calculator", @"moduleOrBottomControl"]) {
        if (![roleEvidence[role] count]) [unresolved addObject:@{@"semanticRole": role,
            @"reason": @"No machine-identified allowlisted ownership path was captured; no hierarchy fallback was attempted."}];
    }
    BOOL healthy = remote_call_current_success() &&
        remote_call_current_io_failure_count() == context.ioFailures;
    BOOL pidStable = pid > 1 && remote_call_current_pid() == pid;
    report[@"controllers"] = controllers; report[@"roots"] = roots;
    report[@"rootAcquisitions"] = rootAcquisitions; report[@"objects"] = rows;
    report[@"classContracts"] = metadataCache.allValues;
    if (refined) report[@"priorityInspection"] = @{
        @"policy": focusScope ? @"exact Focus and process contracts before scoped ownership inventory; separate from generic class budget"
            : @"finite exact target classes before broad inventory; separate from generic class budget",
        @"classEvidence": priorityClassEvidence, @"inspectedPriorityClassCount": @(priorityClasses.count),
        @"additionalHostedClassCount": @(dynamicPriorityClassCount), @"additionalHostedClassBudget": @(focusScope ? 0 : dynamicPriorityClassCap),
        @"priorityClassBudgetReached": @(context.priorityClassLimitReached),
        @"genericClassCount": @(genericClassCount), @"genericClassBudgetReached": @(context.classLimitReached)};
    report[@"edges"] = edges; report[@"routeCandidates"] = candidates;
    report[@"semanticRoleEvidence"] = roleEvidence; report[@"unresolvedPaths"] = unresolved;
    report[@"visitedControllerCount"] = @(controllers.count);
    report[@"tracedObjectCount"] = @(rows.count);
    report[@"discoveryObjectCount"] = @(context.discoveryObjects);
    if (refined && context.discoveryObjects) {
        report[@"viewHierarchyTraversal"] = @YES;
        report[@"recursiveFallbackUsed"] = @YES;
    }
    report[@"metadataCallCount"] = @(context.calls);
    report[@"runtimeMemberCount"] = @(context.members);
    report[@"budgetReached"] = @(context.budgetReached);
    NSDictionary *limits = @{@"timeOrCalls": @(context.budgetReached),
        @"objects": @(context.objectLimitReached), @"classes": @(context.classLimitReached),
        @"priorityClasses": @(context.priorityClassLimitReached),
        @"members": @(context.memberLimitReached), @"depth": @(context.depthLimitReached),
        @"collections": @(context.collectionLimitReached), @"edges": @(context.edgeLimitReached),
        @"controllers": @(context.controllerLimitReached)};
    report[@"limitsReached"] = limits;
    report[@"captureTruncated"] = @([limits.allValues containsObject:@YES]);
    report[@"budgets"] = @{@"seconds": @30, @"calls": @(CNDCCSemanticCallCap),
        @"objects": @(CNDCCSemanticObjectCap + (refined && !focusScope ? CNDCCRefinedDiscoveryObjectCap : 0)),
        @"ownershipObjects": @(CNDCCSemanticObjectCap),
        @"diagnosticDiscoveryObjects": @(refined && !focusScope ? CNDCCRefinedDiscoveryObjectCap : 0), @"classes": @(classCap),
        @"dedicatedPriorityClasses": @(refined ? exactPriorityNames.count + (focusScope ? 0 : dynamicPriorityClassCap) : 0),
        @"controllers": @(CNDCCSemanticControllerCap), @"membersPerClassList": @(CNDCCSemanticMemberCap),
        @"globalMembers": @(CNDCCSemanticGlobalMemberCap), @"collectionMembers": @(CNDCCSemanticCollectionCap),
        @"edges": @(CNDCCSemanticEdgeCap), @"ownershipDepth": @(CNDCCSemanticDepthCap)};
    report[@"elapsedSeconds"] = @([NSProcessInfo processInfo].systemUptime - context.started);
    report[@"pidStable"] = @(pidStable); report[@"transportHealthy"] = @(healthy);
    report[@"scratchFreed"] = @(context.scratchFreed);
    report[@"transportSuccess"] = @(healthy && pidStable);
    report[@"success"] = @(healthy && pidStable && controllers.count > 0 && roots.count > 0 && rows.count > 0 &&
        context.countSlot != 0 && context.scratchFreed);
    report[@"captureComplete"] = @([report[@"success"] boolValue] && ![report[@"captureTruncated"] boolValue]);
    report[@"routeEvidencePolicy"] = @"Only acquired process/container roots, ABI-checked allowlisted object getters, named safely typed object ivars, and bounded collection membership establish routes. Machine identities must reconstruct membership; indexes and object addresses are snapshots. Stable-owner scores are review evidence, not persistence proof or implementation approval.";
    if (![report[@"success"] boolValue]) report[@"failureReason"] = roots.count == 0
        ? @"No process/container owner could be acquired with a checked object-getter contract."
        : (controllers.count == 0 ? @"Process roots were acquired, but no controller ownership route completed; root and partial object evidence is preserved."
            : @"The bounded PID-bound trace did not finish cleanly; partial ownership evidence is preserved.");
    return report;
}

NSDictionary<NSString *, id> *CNDCCThemingCopyLifecycleOwnerTrace(void)
{
    return CNDCCThemingCopyLifecycleOwnerTraceImpl(NO, NO);
}

static NSString *CNDCCRefinedMachineRole(NSDictionary *object)
{
    NSDictionary *identity = object[@"machineIdentities"] ?: @{};
    NSString *symbol = identity[@"symbolName"] ?: identity[@"systemImageName"];
    NSString *package = identity[@"packageName"];
    NSNumber *flip = object[@"checkedScalars"][@"isHorizontallyFlipped"][@"value"];
    if ([package isEqualToString:@"nextPrevious"] && flip) {
        if ([symbol isEqualToString:@"backward.fill"] && flip.boolValue) return @"media.previous";
        if ([symbol isEqualToString:@"forward.fill"] && !flip.boolValue) return @"media.next";
    }
    if ([package isEqualToString:@"playPauseStop"] &&
        [@[@"play.fill", @"pause.fill", @"stop.fill"] containsObject:symbol ?: @""])
        return @"media.playPause";
    return nil;
}

static NSDictionary *CNDCCRefinedObjectsByAddress(NSArray *objects)
{
    NSMutableDictionary *byAddress = [NSMutableDictionary dictionary];
    for (NSDictionary *object in objects)
        if ([object[@"address"] isKindOfClass:NSString.class]) byAddress[object[@"address"]] = object;
    return byAddress;
}

static NSDictionary *CNDCCRefinedComparisonObservation(NSDictionary *row, NSDictionary *byAddress)
{
    NSArray *route = row[@"ownershipRoute"] ?: @[];
    NSMutableArray *tokens = [NSMutableArray array];
    NSMutableArray *routeObjects = [NSMutableArray arrayWithObject:row];
    for (NSDictionary *step in route) {
        [tokens addObject:step[@"name"] ?: step[@"kind"] ?: @""];
        if (step[@"machineKey"]) [tokens addObject:step[@"machineKey"]];
        NSDictionary *object = byAddress[step[@"toAddress"] ?: step[@"address"] ?: @""];
        if (object) [routeObjects addObject:object];
    }
    NSString *name = row[@"className"] ?: @"";
    BOOL hosted = [name hasPrefix:@"CHS"] || [name hasPrefix:@"CHUIS"] || [name containsString:@"ControlHost"];
    NSMutableSet *kinds = [NSMutableSet set];
    BOOL focusIdentityRequired = [name isEqualToString:@"FCUIActivityControl"] || [name isEqualToString:@"_FCActivity"];
    NSMutableSet *activityIdentifiers = [NSMutableSet set];
    for (NSDictionary *object in routeObjects) {
        NSString *objectClass = object[@"className"] ?: @"";
        if ([objectClass isEqualToString:@"FCUIActivityControl"] ||
            ([name isEqualToString:@"_FCActivity"] && object == row)) {
            focusIdentityRequired = YES;
            NSString *identifier = object[@"machineIdentities"][@"activityIdentifier"];
            if ([identifier isKindOfClass:NSString.class] && identifier.length) [activityIdentifiers addObject:identifier];
        }
        if ([objectClass containsString:@"ControlHost"]) hosted = YES;
        NSString *kind = [objectClass isEqualToString:@"CHSControlIdentity"]
            ? object[@"machineIdentities"][@"kind"] : nil;
        if ([objectClass isEqualToString:@"CCUIControlHostViewController"]) {
            NSString *identityAddress = object[@"getters"][@"identity"][@"valueAddress"];
            NSDictionary *identity = byAddress[identityAddress ?: @""];
            if ([identity[@"className"] isEqualToString:@"CHSControlIdentity"])
                kind = identity[@"machineIdentities"][@"kind"];
        }
        if ([kind isKindOfClass:NSString.class] && kind.length) [kinds addObject:kind];
    }
    NSMutableDictionary *observation = [row mutableCopy];
    NSString *base = route.count ? [NSString stringWithFormat:@"%@|%@", name,
        [tokens componentsJoinedByString:@"/"]] : (row[@"key"] ?: name);
    observation[@"comparisonEligible"] = @(!hosted || kinds.count == 1);
    observation[@"hostedMachineKindRequired"] = @(hosted);
    if (hosted && kinds.count == 1) {
        NSString *kind = kinds.anyObject;
        observation[@"hostedMachineKind"] = kind;
        // This comes from checked CHS identity evidence, never a displayed
        // label, a collection position, or a receiver address.
        observation[@"key"] = [base stringByAppendingFormat:@"|hostKind=%@", kind];
    } else {
        observation[@"key"] = base;
        if (hosted) observation[@"comparisonUnresolvedReason"] = @"No unique captured CHS machine kind for this hosted route.";
    }
    observation[@"focusActivityIdentifierRequired"] = @(focusIdentityRequired);
    if (focusIdentityRequired) {
        observation[@"comparisonEligible"] = @([observation[@"comparisonEligible"] boolValue] && activityIdentifiers.count == 1);
        if (activityIdentifiers.count == 1) {
            observation[@"activityIdentifier"] = activityIdentifiers.anyObject;
            observation[@"key"] = [observation[@"key"] stringByAppendingFormat:@"|activityIdentifier=%@", activityIdentifiers.anyObject];
        } else observation[@"comparisonUnresolvedReason"] = @"No unique captured Focus activityIdentifier for this row/model/icon route.";
    }
    return observation;
}

static NSArray *CNDCCRefinedWrapperWordClassifications(NSArray *objects)
{
    NSDictionary *byAddress = CNDCCRefinedObjectsByAddress(objects);
    NSMutableArray *classifications = [NSMutableArray array];
    for (NSDictionary *object in objects) for (NSDictionary *slot in object[@"objectIvars"]) {
        if (![slot[@"diagnosticUntypedWord"] boolValue]) continue;
        NSMutableDictionary *classification = [slot mutableCopy];
        classification[@"ownerAddress"] = object[@"address"];
        classification[@"unknownMethodsInvoked"] = @NO;
        classification[@"swiftABICalled"] = @NO;
        classification[@"slotTypeVerified"] = @NO;
        classification[@"independentAddressValidated"] = @([slot[@"independentAddressValidated"] boolValue]);
        NSDictionary *known = [slot[@"slotReadSucceeded"] boolValue]
            ? byAddress[slot[@"rawWordHex"] ?: @""] : nil;
        if (known) {
            classification[@"classification"] = @"matches-independently-observed-object-address";
            classification[@"independentlyObservedClass"] = known[@"className"] ?: @"";
            classification[@"independentAcquisition"] = [known[@"diagnosticDiscovery"] boolValue]
                ? @"checked loaded UIKit descendant" : @"checked ownership getter/typed or validated reference slot";
            classification[@"reason"] = @"Address correlation only; the word was not dereferenced and does not establish a Swift slot type or ownership route.";
        } else {
            classification[@"classification"] = [slot[@"slotReadSucceeded"] boolValue]
                ? @"unclassified-raw-word" : @"slot-read-unavailable";
            classification[@"reason"] = @"No independently acquired object address matches; do not invoke object_getClass, collection methods, or a Swift ABI on this word.";
        }
        [classifications addObject:classification];
    }
    return classifications;
}

static NSDictionary *CNDCCRefinedMatchedMediaSlot(NSDictionary *owner, NSString *name,
    NSString *expectedClass, NSDictionary *byAddress)
{
    for (NSDictionary *slot in owner[@"objectIvars"]) {
        if (![slot[@"name"] isEqualToString:name] ||
            (![slot[@"runtimeReferenceClassMatched"] boolValue] &&
                ![slot[@"safeObjectSlot"] boolValue]) ||
            ![slot[@"valueClass"] isEqualToString:expectedClass]) continue;
        NSDictionary *target = byAddress[slot[@"valueAddress"] ?: @""];
        if ([target[@"className"] isEqualToString:expectedClass]) return target;
    }
    return nil;
}

// Report exact session/member chains separately from hierarchy discovery and
// transport semantic roles. Missing named links stay visible in each chain.
static NSArray *CNDCCRefinedMediaSessionChains(NSArray *objects)
{
    NSDictionary *byAddress = CNDCCRefinedObjectsByAddress(objects);
    NSMutableArray *chains = [NSMutableArray array];
    for (NSDictionary *session in objects) {
        if (![session[@"className"] isEqualToString:@"MediaControls.MediaControlsModuleSessionView"]) continue;
        NSDictionary *nowPlaying = CNDCCRefinedMatchedMediaSlot(session, @"nowPlayingView",
            @"MediaControls.MediaControlsModuleNowPlayingView", byAddress);
        NSDictionary *transport = CNDCCRefinedMatchedMediaSlot(nowPlaying, @"transportControlsView",
            @"MediaControls.NowPlayingTransportControlsView", byAddress);
        for (NSString *name in @[@"leadingButton", @"leftButton", @"centerButton", @"rightButton"]) {
            NSDictionary *button = CNDCCRefinedMatchedMediaSlot(transport, name,
                @"MediaControls.TransportButton", byAddress);
            NSDictionary *package = CNDCCRefinedMatchedMediaSlot(button, @"packageView",
                @"MediaControls.PackageView", byAddress);
            [chains addObject:@{@"sessionAddress": session[@"address"],
                @"nowPlayingAddress": nowPlaying[@"address"] ?: NSNull.null,
                @"transportAddress": transport[@"address"] ?: NSNull.null,
                @"buttonSlot": name, @"buttonAddress": button[@"address"] ?: NSNull.null,
                @"packageAddress": package[@"address"] ?: NSNull.null,
                @"complete": @(package != nil), @"productionRoute": @NO,
                @"semanticRoleVerified": @NO,
                @"missingMember": package ? NSNull.null : (!nowPlaying ? @"nowPlayingView"
                    : (!transport ? @"transportControlsView" : (!button ? name : @"packageView")))}];
        }
    }
    return chains;
}

NSDictionary<NSString *, id> *CNDCCThemingCopyRefinedPhysicalRouteTrace(void)
{
    NSMutableDictionary *report = [CNDCCThemingCopyLifecycleOwnerTraceImpl(YES, NO) mutableCopy];
    report[@"schemaVersion"] = @3;
    report[@"refinedRevision"] = @3;
    report[@"mode"] = @"physical-read-only-refined-route-trace";
    report[@"scope"] = @[@"processOwner", @"mediaNamedSlots", @"flashlight", @"camera", @"calculator", @"qrCode"];
    report[@"goal"] = @"Confirm the VM-derived named process and module routes on a physical device; compare repeated same-PID snapshots without controlling presentation or control state.";
    report[@"discoveryPolicy"] = @"After primary named routes, a maximum of 128 loaded descendants are inspected from Media/Flashlight/host roots. diagnosticDiscovery edges are non-production and excluded from ownership routes; slot and class evidence does not turn a descendant path into a production route.";
    NSMutableArray *process = [NSMutableArray array], *media = [NSMutableArray array];
    NSMutableArray *flashlight = [NSMutableArray array], *hosted = [NSMutableArray array];
    NSMutableArray *providers = [NSMutableArray array], *observations = [NSMutableArray array];
    NSDictionary *paths = CNDCCSemanticDirectPaths(report[@"roots"] ?: @[], report[@"edges"] ?: @[]);
    NSDictionary *byAddress = CNDCCRefinedObjectsByAddress(report[@"objects"] ?: @[]);
    for (NSDictionary *row in report[@"objects"]) {
        NSString *name = row[@"className"] ?: @"";
        NSArray *route = paths[row[@"address"]] ?: @[];
        NSMutableDictionary *evidence = [row mutableCopy];
        evidence[@"ownershipRoute"] = route;
        evidence[@"productionRoute"] = @NO; // evidence, not an approved adapter
        NSString *lower = name.lowercaseString;
        if ([@[@"SpringBoard", @"SBControlCenterController", @"CCUIMainViewController",
            @"CCUIPagingViewController", @"SBCoverSheetPrimarySlidingViewController",
            @"CCUIModuleInstanceManager"] containsObject:name]) [process addObject:evidence];
        if ([lower containsString:@"transport"] || [name isEqualToString:@"MediaControls.PackageView"] ||
            [name isEqualToString:@"MediaControlsModule"] || [name hasPrefix:@"MRUMediaControls"] ||
            [name containsString:@"MediaControlsModule"] || CNDCCRefinedUntypedWrapperSlot(name, @"contentView")) {
            evidence[@"confirmedTransportRole"] = CNDCCRefinedMachineRole(row) ?: NSNull.null;
            evidence[@"nativeSwiftModelEvidence"] = @{
                @"structLayoutRead": @NO, @"swiftABICalled": @NO,
                @"resolved": @(CNDCCRefinedMachineRole(row) != nil),
                @"reason": @"Only ABI-checked object/scalar accessors are read. Native viewModel.asset/package enum/state structs have no safe physical accessor here; named slot position alone is not Previous/Play-Pause/Next identity."};
            [media addObject:evidence];
        }
        NSString *machine = [[row[@"machineIdentities"] allValues] componentsJoinedByString:@" "] ?: @"";
        if ([lower containsString:@"flashlight"] || [machine.lowercaseString containsString:@"flashlight"])
            [flashlight addObject:evidence];
        if ([name hasPrefix:@"CHS"] || [name hasPrefix:@"CHUIS"] || [name containsString:@"ControlHost"])
            [hosted addObject:evidence];
        if ([lower containsString:@"provider"] || [lower containsString:@"imageasset"])
            [providers addObject:evidence];
        // Named route + machine key is the comparison key, never collection
        // index, geometry, label, or an address baked into an adapter.
        if (route.count && ([lower containsString:@"transport"] ||
            [name isEqualToString:@"MediaControls.PackageView"] || [lower containsString:@"flashlight"] ||
            [name hasPrefix:@"CHUIS"] || [name containsString:@"ControlHost"] ||
            [lower containsString:@"provider"] || [name isEqualToString:@"CCUIModuleInstanceManager"] ||
            [name isEqualToString:@"CCUIMainViewController"] || [name isEqualToString:@"CCUIPagingViewController"])) {
            [observations addObject:CNDCCRefinedComparisonObservation(@{@"address": row[@"address"],
                @"className": name, @"machineIdentities": row[@"machineIdentities"] ?: @{},
                @"ownershipRoute": route, @"getters": row[@"getters"] ?: @{},
                @"lifecycle": row[@"lifecycle"] ?: @{}}, byAddress)];
        }
    }
    report[@"processOwnerEvidence"] = process; report[@"mediaNamedSlotEvidence"] = media;
    report[@"flashlightEvidence"] = flashlight; report[@"hostedControlEvidence"] = hosted;
    report[@"imageProviderEvidence"] = providers; report[@"routeObservations"] = observations;
    report[@"wrapperSlotClassifications"] = CNDCCRefinedWrapperWordClassifications(report[@"objects"] ?: @[]);
    report[@"mediaSessionChains"] = CNDCCRefinedMediaSessionChains(report[@"objects"] ?: @[]);
    NSUInteger wrappers = 0, sessions = 0, transports = 0;
    for (NSDictionary *object in report[@"objects"]) {
        NSString *name = object[@"className"];
        wrappers += CNDCCRefinedUntypedWrapperSlot(name, @"contentView");
        sessions += [name isEqualToString:@"MediaControls.MediaControlsModuleSessionView"];
        transports += [name isEqualToString:@"MediaControls.NowPlayingTransportControlsView"];
    }
    report[@"mediaMaterializationEvidence"] = @{@"wrapperCount": @(wrappers),
        @"sessionViewCount": @(sessions), @"transportViewCount": @(transports),
        @"searchTruncated": report[@"captureTruncated"] ?: @YES,
        @"presentationStateInferred": @NO,
        @"reason": transports ? @"Transport receiver independently observed; named-role and owner evidence still require review."
            : @"No transport receiver observed. The session may be unmaterialized or outside captured safe routes; a user-declared expanded phase does not establish its presence."};
    NSMutableArray *slots = [NSMutableArray array];
    for (NSDictionary *edge in report[@"edges"]) {
        if (![edge[@"verifiedSwiftReference"] boolValue] ||
            ![@[@"leftButton", @"centerButton", @"rightButton", @"leadingButton", @"packageView"]
                containsObject:edge[@"name"]]) continue;
        [slots addObject:@{@"slotName": edge[@"name"], @"ownerClass": edge[@"ownerClass"],
            @"ownerAddress": edge[@"fromAddress"], @"valueAddress": edge[@"toAddress"],
            @"valueClass": edge[@"toClass"], @"dynamicOffset": edge[@"offset"],
            @"semanticRoleVerified": @NO, @"productionRoute": @NO,
            @"ownershipRoute": paths[edge[@"fromAddress"]] ?: @[]}];
    }
    report[@"mediaSlotSnapshots"] = slots;
    report[@"providerResolutionPolicy"] = @"Host identity kind/extension identity and descriptor -> instance -> icon/provider edges must be inspected together. An icon consumer or descriptor is not proof that the extension's actual image provider was reached.";
    report[@"remainingPhysicalChecks"] = @[
        @"Capture compact page with Flashlight and Camera/Calculator/QR materialized, then expanded Media, then dismiss/reopen and capture again without respringing.",
        @"Confirm actual Flashlight button/provider and extension image-provider routes, not merely module metadata or hosted icon consumers.",
        @"Native Swift model package enum/symbol/flip semantics are unresolved when their safe Objective-C accessors are absent.",
        @"Same receiver addresses across captures do not prove reconstruction. Changed named leaves under unchanged owners are evidence of re-resolution, not complete lifetime-hook coverage."];
    return report;
}

// Local report assembly only. A missing/unread member and a safely read null
// member remain distinct, especially for the manager's active/default state.
static NSDictionary *CNDCCFocusMemberSnapshot(NSDictionary *owner, NSString *member)
{
    for (NSDictionary *slot in owner[@"objectIvars"]) {
        if (![slot[@"name"] isEqualToString:member] || ![slot[@"safeObjectSlot"] boolValue]) continue;
        NSMutableDictionary *snapshot = [slot mutableCopy];
        snapshot[@"acquisition"] = @"typed named ivar at current bounded runtime offset";
        snapshot[@"status"] = [slot[@"valueAddress"] isEqualToString:@"0x0"] ? @"null" : @"object";
        return snapshot;
    }
    NSString *getter = [member stringByTrimmingCharactersInSet:
        [NSCharacterSet characterSetWithCharactersInString:@"_"]];
    NSDictionary *value = owner[@"getters"][getter];
    if ([value[@"contract"][@"objectGetterABI"] boolValue] && [value[@"getterSucceeded"] boolValue]) {
        NSMutableDictionary *snapshot = [value mutableCopy];
        snapshot[@"acquisition"] = @"ABI-checked zero-argument object getter";
        snapshot[@"status"] = [value[@"valueAddress"] isEqualToString:@"0x0"] ? @"null" : @"object";
        return snapshot;
    }
    return @{@"name": member, @"status": @"member absent, unsafe, or unread in this capture",
        @"valueAddress": NSNull.null};
}

static NSDictionary *CNDCCFocusMemberObject(NSDictionary *owner, NSString *member,
    NSString *expectedClass, NSDictionary *byAddress)
{
    NSDictionary *snapshot = CNDCCFocusMemberSnapshot(owner, member);
    id address = snapshot[@"valueAddress"];
    NSDictionary *target = [address isKindOfClass:NSString.class] ? byAddress[address] : nil;
    return target && (!expectedClass || [target[@"className"] isEqualToString:expectedClass]) ? target : nil;
}

static NSString *CNDCCFocusModuleRouteKey(NSArray *route)
{
    NSMutableArray *tokens = [NSMutableArray array];
    for (NSDictionary *edge in route) {
        [tokens addObject:edge[@"name"] ?: edge[@"kind"] ?: @""];
        if ([edge[@"machineKey"] isKindOfClass:NSString.class]) [tokens addObject:edge[@"machineKey"]];
    }
    return [tokens componentsJoinedByString:@"/"];
}

NSDictionary<NSString *, id> *CNDCCThemingCopyRefinedFocusRouteTrace(void)
{
    NSMutableDictionary *report = [CNDCCThemingCopyLifecycleOwnerTraceImpl(YES, YES) mutableCopy];
    report[@"schemaVersion"] = @3;
    report[@"refinedRevision"] = @4;
    report[@"mode"] = @"physical-read-only-refined-route-trace";
    report[@"captureScope"] = @"focus";
    report[@"scope"] = @[@"processOwner", @"focusOwner", @"focusModels", @"focusRows", @"focusIcons"];
    report[@"goal"] = @"Physically confirm machine-keyed Focus owner/model/row/icon routes and compare re-resolution after user-performed close/reopen or ordinary redraw within one SpringBoard PID.";
    report[@"discoveryPolicy"] = @"No loaded-descendant discovery in the dedicated Focus capture. Only exact named members, checked object getters, typed ivars, and bounded Foundation memberships are followed; the picker is read through viewIfLoaded.";
    NSDictionary *byAddress = CNDCCRefinedObjectsByAddress(report[@"objects"] ?: @[]);
    NSDictionary *paths = CNDCCSemanticDirectPaths(report[@"roots"] ?: @[], report[@"edges"] ?: @[]);
    NSMutableArray *owners = [NSMutableArray array], *models = [NSMutableArray array];
    NSMutableArray *ownerChains = [NSMutableArray array], *rowChains = [NSMutableArray array];
    NSMutableArray *managerStates = [NSMutableArray array], *observations = [NSMutableArray array];
    NSMutableArray *memberships = [NSMutableArray array];
    for (NSDictionary *row in report[@"objects"]) {
        NSString *name = row[@"className"];
        NSArray *route = paths[row[@"address"]] ?: @[];
        NSMutableDictionary *evidence = [row mutableCopy];
        evidence[@"ownershipRoute"] = route;
        evidence[@"productionRoute"] = @NO;
        if ([@[@"FCCCControlCenterModule", @"FCActivityManager", @"FCUIActivityPickerViewController",
            @"FCUIActivityListView"] containsObject:name]) [owners addObject:evidence];
        if ([name isEqualToString:@"_FCActivity"]) [models addObject:evidence];
        if (route.count && (CNDCCFocusPriorityClass(name) || [name containsString:@"ImageView"]))
            [observations addObject:CNDCCRefinedComparisonObservation(evidence, byAddress)];
    }
    for (NSDictionary *module in report[@"objects"]) {
        if (![module[@"className"] isEqualToString:@"FCCCControlCenterModule"]) continue;
        NSDictionary *picker = CNDCCFocusMemberObject(module, @"_activityPickerViewController",
            @"FCUIActivityPickerViewController", byAddress);
        NSDictionary *manager = CNDCCFocusMemberObject(module, @"_activityManager", @"FCActivityManager", byAddress);
        NSDictionary *list = CNDCCFocusMemberObject(picker, @"viewIfLoaded", @"FCUIActivityListView", byAddress);
        NSDictionary *rowCollection = CNDCCFocusMemberObject(list, @"activityViews", nil, byAddress);
        NSDictionary *modelDictionary = CNDCCFocusMemberObject(manager, @"_allActivitiesByIdentifier", nil, byAddress);
        BOOL validRows = CNDCCSemanticCollectionClass(rowCollection[@"className"] ?: @"");
        BOOL validModels = CNDCCSemanticCollectionClass(modelDictionary[@"className"] ?: @"") &&
            [modelDictionary[@"className"] containsString:@"Dictionary"];
        NSArray *moduleRoute = paths[module[@"address"]] ?: @[];
        NSDictionary *ownerAddresses = @{@"module": module[@"address"], @"picker": picker[@"address"] ?: NSNull.null,
            @"manager": manager[@"address"] ?: NSNull.null};
        [ownerChains addObject:@{@"ownerAddresses": ownerAddresses, @"listAddress": list[@"address"] ?: NSNull.null,
            @"rowCollectionAddress": validRows ? rowCollection[@"address"] : NSNull.null,
            @"modelDictionaryAddress": validModels ? modelDictionary[@"address"] : NSNull.null,
            @"ownershipRoute": moduleRoute, @"complete": @(moduleRoute.count && picker && manager && list && validRows && validModels),
            @"productionRoute": @NO, @"membershipUsesPosition": @NO,
            @"missingMember": !moduleRoute.count ? @"process-to-module route" : (!picker ? @"_activityPickerViewController"
                : (!manager ? @"_activityManager" : (!list ? @"viewIfLoaded"
                    : (!validRows ? @"activityViews" : (!validModels ? @"_allActivitiesByIdentifier" : (id)NSNull.null)))))}];
        if (manager) {
            NSMutableDictionary *state = [@{@"managerAddress": manager[@"address"],
                @"ownershipRoute": paths[manager[@"address"]] ?: @[]} mutableCopy];
            for (NSString *member in @[@"_availableActivities", @"_activeActivity", @"_defaultActivity", @"_allActivitiesByIdentifier"]) {
                NSMutableDictionary *snapshot = [CNDCCFocusMemberSnapshot(manager, member) mutableCopy];
                NSDictionary *value = CNDCCFocusMemberObject(manager, member, nil, byAddress);
                snapshot[@"machineIdentities"] = value[@"machineIdentities"] ?: @{};
                state[member] = snapshot;
            }
            [managerStates addObject:state];
        }
        NSMutableDictionary *modelGroups = [NSMutableDictionary dictionary];
        NSDictionary *available = CNDCCFocusMemberObject(manager, @"_availableActivities", nil, byAddress);
        for (NSDictionary *edge in report[@"edges"]) {
            BOOL keyed = validModels && [edge[@"fromAddress"] isEqual:modelDictionary[@"address"]] &&
                [edge[@"kind"] isEqualToString:@"dictionaryMember"];
            BOOL availableMember = [edge[@"fromAddress"] isEqual:available[@"address"]] &&
                [@[@"collectionElement", @"dictionaryMember"] containsObject:edge[@"kind"]];
            if (!keyed && !availableMember) continue;
            NSDictionary *model = byAddress[edge[@"toAddress"] ?: @""];
            NSString *key = edge[@"machineKey"];
            NSDictionary *membership = @{@"managerAddress": manager[@"address"],
                @"collectionMember": keyed ? @"_allActivitiesByIdentifier" : @"_availableActivities",
                @"machineKey": key ?: (id)NSNull.null, @"modelAddress": edge[@"toAddress"],
                @"modelClass": model[@"className"] ?: edge[@"toClass"] ?: @"",
                @"machineIdentities": model[@"machineIdentities"] ?: @{},
                @"keyMatchesModelIdentifier": @(key && [key isEqual:model[@"machineIdentities"][@"activityIdentifier"]]),
                @"indexIsIdentity": @NO};
            [memberships addObject:membership];
            if (keyed && [key isKindOfClass:NSString.class] && model) {
                if (!modelGroups[key]) modelGroups[key] = [NSMutableArray array];
                [modelGroups[key] addObject:model];
            }
        }
        NSMutableArray *rows = [NSMutableArray array];
        NSMutableDictionary *identifierCounts = [NSMutableDictionary dictionary];
        for (NSDictionary *edge in report[@"edges"]) {
            if (!validRows || ![edge[@"fromAddress"] isEqual:rowCollection[@"address"]] ||
                ![@[@"collectionElement", @"dictionaryMember"] containsObject:edge[@"kind"]]) continue;
            NSDictionary *row = byAddress[edge[@"toAddress"] ?: @""];
            if (![row[@"className"] isEqualToString:@"FCUIActivityControl"]) continue;
            [rows addObject:row];
            NSString *identifier = row[@"machineIdentities"][@"activityIdentifier"];
            if ([identifier isKindOfClass:NSString.class] && identifier.length)
                identifierCounts[identifier] = @([identifierCounts[identifier] unsignedIntegerValue] + 1);
        }
        for (NSDictionary *row in rows) {
            NSDictionary *identity = row[@"machineIdentities"] ?: @{};
            NSString *identifier = identity[@"activityIdentifier"];
            BOOL identified = [identifier isKindOfClass:NSString.class] && identifier.length;
            NSArray *matchingModels = identified ? modelGroups[identifier] : nil;
            NSDictionary *model = matchingModels.count == 1 ? matchingModels.firstObject : nil;
            NSDictionary *modelIdentity = model[@"machineIdentities"] ?: @{};
            BOOL identifierMatch = identified && [identifier isEqual:modelIdentity[@"activityIdentifier"]];
            NSDictionary *description = CNDCCFocusMemberObject(row, @"activityDescription", nil, byAddress);
            NSDictionary *package = CNDCCFocusMemberObject(row, @"_activityIconPackageView", @"FCUICAPackageView", byAddress);
            NSDictionary *image = CNDCCFocusMemberObject(row, @"_activityIconImageView", nil, byAddress);
            NSString *imageClass = image[@"className"] ?: @"";
            if (![imageClass containsString:@"ImageView"]) image = nil;
            BOOL symbolMatch = [identity[@"activitySymbolImageName"] isKindOfClass:NSString.class] &&
                [identity[@"activitySymbolImageName"] isEqual:modelIdentity[@"activitySymbolImageName"]];
            BOOL uniqueMatch = [identity[@"activityUniqueIdentifier"] isKindOfClass:NSString.class] &&
                [identity[@"activityUniqueIdentifier"] isEqual:modelIdentity[@"activityUniqueIdentifier"]];
            BOOL uniqueRow = identified && [identifierCounts[identifier] unsignedIntegerValue] == 1;
            NSArray *route = paths[row[@"address"]] ?: @[];
            NSMutableArray *missingEvidence = [NSMutableArray array];
            if (!moduleRoute.count) [missingEvidence addObject:@"process-to-module ownership route"];
            if (!manager) [missingEvidence addObject:@"_activityManager"];
            if (!identified) [missingEvidence addObject:@"safe nonempty activityIdentifier"];
            else if (!uniqueRow) [missingEvidence addObject:@"unique activityIdentifier within this loaded list"];
            if (!identifierMatch) [missingEvidence addObject:@"_allActivitiesByIdentifier key and matching model identifier"];
            if (!symbolMatch) [missingEvidence addObject:@"matching row/model activitySymbolImageName"];
            if (!uniqueMatch) [missingEvidence addObject:@"matching row/model activityUniqueIdentifier"];
            if (!package && !image) [missingEvidence addObject:@"typed named package or image view"];
            [rowChains addObject:@{@"chainKey": [NSString stringWithFormat:@"Focus|%@|activityIdentifier=%@",
                CNDCCFocusModuleRouteKey(moduleRoute), identified ? identifier : @"unresolved"],
                @"activityIdentifier": identifier ?: (id)NSNull.null, @"machineIdentities": identity,
                @"ownerAddresses": ownerAddresses, @"listAddress": list[@"address"] ?: NSNull.null,
                @"rowAddress": row[@"address"], @"modelAddress": model[@"address"] ?: NSNull.null,
                @"modelMachineIdentities": modelIdentity, @"descriptionAddress": description[@"address"] ?: NSNull.null,
                @"descriptionMachineIdentities": description[@"machineIdentities"] ?: @{},
                @"packageAddress": package[@"address"] ?: NSNull.null, @"imageViewAddress": image[@"address"] ?: NSNull.null,
                @"packageSlot": CNDCCFocusMemberSnapshot(row, @"_activityIconPackageView"),
                @"imageSlot": CNDCCFocusMemberSnapshot(row, @"_activityIconImageView"),
                @"contentSlot": CNDCCFocusMemberSnapshot(row, @"_contentView"),
                @"ownershipRoute": route, @"modelKeyMatchesRowIdentifier": @(identifierMatch),
                @"symbolIdentityMatched": @(symbolMatch), @"uniqueIdentifierMatched": @(uniqueMatch),
                @"identifierAmbiguous": @(identified && !uniqueRow),
                @"missingEvidence": missingEvidence,
                @"comparisonEligible": @(moduleRoute.count && uniqueRow),
                @"complete": @(moduleRoute.count && manager && picker && list && uniqueRow && identifierMatch && symbolMatch && uniqueMatch && (package || image)),
                @"productionRoute": @NO, @"membershipUsesPosition": @NO}];
        }
    }
    NSUInteger complete = 0;
    for (NSDictionary *chain in rowChains) complete += [chain[@"complete"] boolValue];
    report[@"focusOwnerEvidence"] = owners;
    report[@"focusModelEvidence"] = models;
    report[@"focusOwnerChains"] = ownerChains;
    report[@"focusManagerStateSnapshots"] = managerStates;
    report[@"focusModelMembership"] = memberships;
    report[@"focusRowChains"] = rowChains;
    report[@"routeObservations"] = observations;
    NSMutableArray *unresolved = [NSMutableArray array];
    if (!ownerChains.count) [unresolved addObject:@{@"semanticRole": @"focus.owner",
        @"reason": @"No FCCCControlCenterModule was reached through the checked process/module registry routes."}];
    for (NSDictionary *chain in ownerChains) if (![chain[@"complete"] boolValue])
        [unresolved addObject:@{@"semanticRole": @"focus.owner", @"missingMember": chain[@"missingMember"],
            @"ownerAddresses": chain[@"ownerAddresses"]}];
    for (NSDictionary *chain in rowChains) if (![chain[@"complete"] boolValue])
        [unresolved addObject:@{@"semanticRole": @"focus.activityOrMode", @"activityIdentifier": chain[@"activityIdentifier"],
            @"rowAddress": chain[@"rowAddress"], @"missingEvidence": chain[@"missingEvidence"]}];
    if (ownerChains.count && !rowChains.count) [unresolved addObject:@{@"semanticRole": @"focus.activityOrMode",
        @"reason": @"No materialized machine-identified activity row was captured. The declared phase does not establish a loaded picker or row."}];
    report[@"unresolvedPaths"] = unresolved;
    report[@"focusMaterializationEvidence"] = @{@"moduleCount": @(ownerChains.count), @"rowCount": @(rowChains.count),
        @"completeRowChainCount": @(complete), @"allObservedRowsComplete": @(rowChains.count && complete == rowChains.count),
        @"searchTruncated": report[@"captureTruncated"] ?: @YES, @"presentationStateInferred": @NO};
    report[@"remainingPhysicalChecks"] = @[@"Capture Expanded Focus, then Reopened Focus after user-performed close/reopen in the same SpringBoard PID.",
        @"Unchanged receivers establish persistence observations only. Changed identified leaves under unchanged module/picker/manager owners provide re-resolution evidence; no allocation lifetime or complete repaint-hook coverage is inferred."];
    return report;
}

static NSDictionary *CNDCCFocusCompareChains(NSDictionary *current, NSDictionary *previous, BOOL valid)
{
    BOOL focusPair = valid && [current[@"captureScope"] isEqualToString:@"focus"] &&
        [previous[@"captureScope"] isEqualToString:@"focus"];
    NSMutableDictionary *prior = [NSMutableDictionary dictionary], *next = [NSMutableDictionary dictionary];
    NSMutableArray *unpaired = [NSMutableArray array], *ambiguous = [NSMutableArray array];
    if (focusPair) for (NSUInteger phase = 0; phase < 2; phase++) {
        NSMutableDictionary *groups = phase ? next : prior;
        for (NSDictionary *chain in (phase ? current : previous)[@"focusRowChains"]) {
            if (![chain[@"comparisonEligible"] boolValue] || ![chain[@"chainKey"] isKindOfClass:NSString.class]) {
                [unpaired addObject:@{@"capture": phase ? @"current" : @"previous", @"chain": chain}]; continue;
            }
            NSString *key = chain[@"chainKey"];
            if (!groups[key]) groups[key] = [NSMutableArray array];
            [groups[key] addObject:chain];
        }
    }
    NSMutableSet *keys = [NSMutableSet setWithArray:prior.allKeys]; [keys addObjectsFromArray:next.allKeys];
    NSMutableArray *comparisons = [NSMutableArray array], *reResolved = [NSMutableArray array];
    NSMutableArray *added = [NSMutableArray array], *missing = [NSMutableArray array];
    for (NSString *key in [keys.allObjects sortedArrayUsingSelector:@selector(compare:)]) {
        NSArray *before = prior[key] ?: @[], *after = next[key] ?: @[];
        if (before.count > 1 || after.count > 1) {
            [ambiguous addObject:@{@"chainKey": key, @"previousChains": before, @"currentChains": after,
                @"receiverPairingInferred": @NO}]; continue;
        }
        if (!before.count) { [added addObjectsFromArray:after]; continue; }
        if (!after.count) { [missing addObjectsFromArray:before]; continue; }
        NSDictionary *old = before.firstObject, *row = after.firstObject;
        BOOL ownersPersisted = YES;
        for (NSString *owner in @[@"module", @"picker", @"manager"]) {
            id address = row[@"ownerAddresses"][owner];
            ownersPersisted &= [address isKindOfClass:NSString.class] && [address isEqual:old[@"ownerAddresses"][owner]];
        }
        NSMutableArray *changedMembers = [NSMutableArray array];
        NSMutableArray *newMembers = [NSMutableArray array], *missingMembers = [NSMutableArray array];
        for (NSString *member in @[@"listAddress", @"rowAddress", @"packageAddress", @"imageViewAddress"]) {
            id beforeAddress = old[member], afterAddress = row[member];
            BOOL beforePresent = [beforeAddress isKindOfClass:NSString.class];
            BOOL afterPresent = [afterAddress isKindOfClass:NSString.class];
            if (beforePresent && afterPresent && ![beforeAddress isEqual:afterAddress]) [changedMembers addObject:member];
            if (!beforePresent && afterPresent) [newMembers addObject:member];
            if (beforePresent && !afterPresent) [missingMembers addObject:member];
        }
        BOOL identitiesUnchanged = [old[@"machineIdentities"] isEqual:row[@"machineIdentities"]];
        BOOL evidence = ownersPersisted && identitiesUnchanged && changedMembers.count &&
            [old[@"complete"] boolValue] && [row[@"complete"] boolValue];
        NSDictionary *comparison = @{@"chainKey": key, @"activityIdentifier": row[@"activityIdentifier"],
            @"previousChain": old, @"currentChain": row, @"ownersPersisted": @(ownersPersisted),
            @"machineIdentitiesUnchanged": @(identitiesUnchanged), @"changedMembers": changedMembers,
            @"newlyObservedMembers": newMembers, @"noLongerObservedMembers": missingMembers,
            @"changedLeavesUnderUnchangedOwners": @(evidence), @"allocationLifetimeInferred": @NO,
            @"implementationReady": @NO};
        [comparisons addObject:comparison];
        if (evidence) [reResolved addObject:comparison];
    }
    BOOL phaseSequence = focusPair && [current[@"capturePhase"] isEqualToString:@"reopened-focus"] &&
        [@[@"expanded-focus", @"reopened-focus"] containsObject:previous[@"capturePhase"] ?: @""];
    return @{@"comparisonAvailable": @(focusPair), @"userDeclaredReopenSequence": @(phaseSequence),
        @"rowComparisons": comparisons, @"changedLeavesUnderUnchangedOwners": reResolved,
        @"newlyObservedRows": added, @"noLongerObservedRows": missing,
        @"unpairedFocusChains": unpaired, @"ambiguousFocusChainGroups": ambiguous,
        @"samePIDPersistenceVerified": @NO, @"implementationReady": @NO,
        @"reason": focusPair ? @"Machine-identified rows and named icon members were re-resolved from captured owners. Unchanged addresses do not prove reconstruction, changed addresses may be allocator-reused, and the declared phase does not infer a presentation action."
            : @"Requires two successful Focus captures in the same SpringBoard PID."};
}

NSDictionary<NSString *, id> *CNDCCThemingCompareRefinedPhysicalRoutes(NSDictionary *current, NSDictionary *previous)
{
    BOOL samePID = [current[@"targetPID"] intValue] > 1 &&
        [current[@"targetPID"] isEqual:previous[@"targetPID"]];
    BOOL valid = samePID && [current[@"success"] boolValue] && [previous[@"success"] boolValue] &&
        [current[@"mode"] isEqualToString:@"physical-read-only-refined-route-trace"] &&
        [previous[@"mode"] isEqualToString:@"physical-read-only-refined-route-trace"];
    NSMutableArray *persisted = [NSMutableArray array], *changed = [NSMutableArray array];
    NSMutableArray *created = [NSMutableArray array], *missing = [NSMutableArray array];
    NSMutableArray *unpaired = [NSMutableArray array], *ambiguous = [NSMutableArray array];
    NSMutableDictionary *prior = [NSMutableDictionary dictionary], *next = [NSMutableDictionary dictionary];
    if (valid) for (NSUInteger phase = 0; phase < 2; phase++) {
        NSDictionary *capture = phase ? current : previous;
        NSDictionary *byAddress = CNDCCRefinedObjectsByAddress(capture[@"objects"] ?: @[]);
        NSMutableDictionary *groups = phase ? next : prior;
        for (NSDictionary *row in capture[@"routeObservations"]) {
            // Recompute even historical schema-3 keys from captured CHS kind
            // evidence. The old serialized named-only keys can collide.
            NSDictionary *observation = CNDCCRefinedComparisonObservation(row, byAddress);
            if (![observation[@"comparisonEligible"] boolValue]) {
                [unpaired addObject:@{@"capture": phase ? @"current" : @"previous", @"observation": observation}];
                continue;
            }
            NSString *key = observation[@"key"];
            if (!groups[key]) groups[key] = [NSMutableArray array];
            [groups[key] addObject:observation];
        }
    }
    NSMutableSet *keys = [NSMutableSet setWithArray:prior.allKeys];
    [keys addObjectsFromArray:next.allKeys];
    for (NSString *key in [keys.allObjects sortedArrayUsingSelector:@selector(compare:)]) {
        NSArray *before = prior[key] ?: @[], *after = next[key] ?: @[];
        NSMutableArray *beforeOnly = [before mutableCopy], *afterOnly = [NSMutableArray array];
        for (NSDictionary *row in after) {
            NSDictionary *same = nil;
            for (NSDictionary *old in beforeOnly)
                if ([old[@"address"] isEqual:row[@"address"]]) { same = old; break; }
            if (same) { [persisted addObject:row]; [beforeOnly removeObject:same]; }
            else [afterOnly addObject:row];
        }
        if (before.count == 1 && after.count == 1 && beforeOnly.count && afterOnly.count) {
            NSDictionary *row = afterOnly.firstObject, *old = beforeOnly.firstObject;
            [changed addObject:@{@"key": key, @"className": row[@"className"],
                @"beforeAddress": old[@"address"], @"afterAddress": row[@"address"],
                @"ownershipRoute": row[@"ownershipRoute"] ?: @[],
                @"hostedMachineKind": row[@"hostedMachineKind"] ?: NSNull.null}];
        } else {
            [created addObjectsFromArray:afterOnly]; [missing addObjectsFromArray:beforeOnly];
            if (before.count > 1 || after.count > 1)
                [ambiguous addObject:@{@"key": key, @"beforeCount": @(before.count),
                    @"afterCount": @(after.count), @"receiverPairingInferred": @NO}];
        }
    }
    NSMutableArray *slotComparisons = [NSMutableArray array];
    if (valid) for (NSString *name in @[@"leftButton", @"centerButton", @"rightButton", @"leadingButton", @"packageView"]) {
        NSMutableSet *before = [NSMutableSet set], *after = [NSMutableSet set];
        for (NSDictionary *slot in previous[@"mediaSlotSnapshots"])
            if ([slot[@"slotName"] isEqualToString:name]) [before addObject:slot[@"valueAddress"]];
        for (NSDictionary *slot in current[@"mediaSlotSnapshots"])
            if ([slot[@"slotName"] isEqualToString:name]) [after addObject:slot[@"valueAddress"]];
        NSMutableSet *unchanged = [before mutableCopy]; [unchanged intersectSet:after];
        NSMutableSet *new = [after mutableCopy]; [new minusSet:before];
        NSMutableSet *gone = [before mutableCopy]; [gone minusSet:after];
        [slotComparisons addObject:@{@"slotName": name, @"unchangedAddresses": unchanged.allObjects,
            @"newlyObservedAddresses": new.allObjects, @"noLongerObservedAddresses": gone.allObjects,
            @"receiverPairingInferred": @NO, @"semanticRoleVerified": @NO}];
    }
    return @{@"comparisonAvailable": @(valid), @"samePID": @(samePID),
        @"focusReconstructionComparison": CNDCCFocusCompareChains(current, previous, valid),
        @"mediaNamedSlotSetComparisons": slotComparisons,
        @"previousCapturedAt": previous[@"capturedAt"] ?: NSNull.null,
        @"persistedRouteReceivers": persisted, @"changedRouteReceivers": changed,
        @"newlyObservedRoutes": created, @"noLongerObservedRoutes": missing,
        @"unpairedRouteObservations": unpaired, @"ambiguousRouteReceiverGroups": ambiguous,
        @"hostedComparisonPolicy": @"Rebuild keys with captured CHS machine kind for host/descendant routes; unresolved kinds and duplicate groups never infer receiver pairings.",
        @"samePIDPersistenceVerified": @NO, @"implementationReady": @NO,
        @"reason": valid ? @"Re-resolved named-route snapshots only. Missing routes can mean a nonmaterialized page; addresses may be allocator-reused. No UI lifecycle action was performed or inferred."
            : @"Requires two successful refined reports from the same SpringBoard PID."};
}

NSDictionary<NSString *, id> *CNDCCThemingCopyMediaFocusSemanticTrace(void)
{
    return CNDCCThemingCopyLifecycleOwnerTrace();
}

NSDictionary<NSString *, id> *
CNDCCThemingCopyMediaConnectivityTrace(void)
{
    int targetPIDAtEntry = remote_call_current_pid();
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schemaVersion": @2,
        @"mode": @"physical-read-only-expanded-control-center-trace",
        @"target": @"SpringBoard",
        @"targetPID": @(targetPIDAtEntry),
        @"success": @NO,
        @"readOnly": @YES,
        @"controlActions": @0,
        @"presentationWrites": @0,
        @"radioWrites": @0,
        @"fileWrites": @0,
        @"targetScratchAllocations": @YES,
        @"controllers": @[],
        @"objects": @[],
        @"getterEdges": @[],
    } mutableCopy];
    if (!remote_call_current_success()) {
        report[@"failureReason"] = @"The SpringBoard RemoteCall transport was not healthy at trace entry.";
        return report;
    }

    uint32_t previousSettle = r_settle_us(0);
    NSUInteger invalidCollections = 0;
    NSUInteger truncatedControllerTraces = 0;
    NSMutableArray<NSNumber *> *controllers = [NSMutableArray array];
    NSMutableSet<NSNumber *> *seenControllers = [NSMutableSet set];
    NSMutableArray<NSDictionary *> *controllerRows = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *objectRows = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *getterEdges = [NSMutableArray array];

    uint64_t application = CNDCCGetter(r_class("UIApplication"),
                                       "sharedApplication");
    uint64_t windows = CNDCCGetter(application, "windows");
    NSUInteger windowCount = CNDCCBoundedCount(CNDCCGetter(windows, "count"),
        CNDCCWindowCap, &invalidCollections);
    for (NSUInteger i = 0; i < windowCount && remote_call_current_success(); i++) {
        uint64_t window = CNDCCArrayObject(windows, i);
        CNDCCEnqueueController(controllers, seenControllers,
            CNDCCGetter(window, "rootViewController"));
    }

    for (NSUInteger cursor = 0;
         cursor < controllers.count && cursor < CNDCCControllerCap &&
         remote_call_current_success(); cursor++) {
        uint64_t controller = controllers[cursor].unsignedLongLongValue;
        CNDCCEnqueueController(controllers, seenControllers,
            CNDCCGetter(controller, "presentedViewController"));
        uint64_t children = CNDCCGetter(controller, "childViewControllers");
        NSUInteger remaining = CNDCCControllerCap - controllers.count;
        NSUInteger count = CNDCCBoundedCount(CNDCCGetter(children, "count"),
                                              remaining, &invalidCollections);
        for (NSUInteger i = 0; i < count; i++) {
            CNDCCEnqueueController(controllers, seenControllers,
                                   CNDCCArrayObject(children, i));
        }
    }

    NSArray<NSString *> *getterSelectors = @[
        @"viewIfLoaded",
        @"contentViewController", @"moduleContentViewController",
        @"expandedViewController", @"expandedContentViewController",
        @"transportControlsView", @"transportControlView",
        @"transportControls", @"transportControlsViewController",
        @"playbackControlsView", @"controlsView",
        @"nowPlayingViewController", @"mediaControlsViewController",
        @"centerButton", @"leftButton", @"leadingButton",
        @"previousButton", @"skipBackwardButton",
        @"rightButton", @"trailingButton", @"nextButton",
        @"skipForwardButton", @"playPauseButton", @"button",
        @"packageView", @"package", @"packageDescription",
        @"glyphPackageDescription", @"glyphView", @"customGlyphView",
        @"imageView", @"image", @"icon", @"iconView", @"_iconView",
        @"controlIconView", @"_controlIconView", @"contentView",
        @"foregroundView", @"backgroundView", @"symbolImage",
        @"slider", @"sliderView", @"continuousSlider",
        @"brightnessSlider", @"volumeSlider",
        @"focusViewController", @"focusModeViewController",
        @"displayModuleViewController", @"brightnessViewController",
        @"volumeViewController",
        @"wifiModuleViewController", @"wifiButtonViewController",
        @"expandedWiFiButtonViewController",
        @"bluetoothModuleViewController", @"bluetoothButtonViewController",
        @"expandedBluetoothButtonViewController",
        @"airplaneButtonViewController", @"expandedAirplaneButtonViewController",
        @"cellularDataButtonViewController", @"expandedCellularDataButtonViewController",
        @"airDropModuleViewController", @"hotspotButtonViewController",
        @"expandedHotspotButtonViewController",
    ];
    NSArray<NSString *> *contractSelectors = [getterSelectors arrayByAddingObjectsFromArray:@[
        @"setPackage:", @"setPackageDescription:",
        @"glyphImage", @"setGlyphImage:",
        @"selectedGlyphImage", @"setSelectedGlyphImage:",
        @"setGlyphPackageDescription:",
        @"glyphState", @"setGlyphState:",
        @"setImage:", @"setIcon:", @"setSymbolImage:",
        @"setCustomGlyphView:", @"setHidden:",
    ]];

    NSUInteger mediaControllerCount = 0;
    NSUInteger connectivityControllerCount = 0;
    NSUInteger mediaButtonCandidateCount = 0;
    NSUInteger connectivityButtonCandidateCount = 0;
    NSUInteger hostedIconCandidateCount = 0;
    NSUInteger sliderCandidateCount = 0;
    NSUInteger focusCandidateCount = 0;
    NSMutableDictionary<NSString *, NSNumber *> *traceDomainCounts =
        [NSMutableDictionary dictionary];
    // Many Control Center controllers share or nest the same visible view
    // subtree. A per-controller seen set multiplied that subtree by every
    // generic CCUI container and made the physical trace effectively
    // unbounded. The targeted domains share one set so each remote object is
    // inspected at most once per capture.
    NSMutableSet<NSNumber *> *seenTraceObjects = [NSMutableSet set];
    for (NSNumber *controllerNumber in controllers) {
        if (!remote_call_current_success()) break;
        uint64_t controller = controllerNumber.unsignedLongLongValue;
        NSString *controllerClass = CNDCCClassName(controller) ?: @"";
        BOOL mediaController = CNDCCLooksMediaTraceController(controllerClass);
        BOOL connectivityController =
            CNDCCLooksConnectivityTraceController(controllerClass);
        NSString *traceDomain = CNDCCExpandedTraceDomain(controllerClass);
        if (!traceDomain.length) continue;
        mediaControllerCount += mediaController ? 1 : 0;
        connectivityControllerCount += connectivityController ? 1 : 0;
        traceDomainCounts[traceDomain] = @(
            [traceDomainCounts[traceDomain] unsignedIntegerValue] + 1);

        NSMutableDictionary *controllerRow =
            [CNDCCControllerObject(controller) mutableCopy];
        controllerRow[@"traceDomain"] = traceDomain;
        [controllerRows addObject:controllerRow];

        NSMutableArray<NSDictionary<NSString *, id> *> *queue =
            [NSMutableArray array];
        CNDCCEnqueueTraceObject(queue, seenTraceObjects, controller, 0, 0,
                                @"controller");
        for (NSUInteger cursor = 0;
             cursor < queue.count &&
             cursor < CNDCCTraceObjectCapPerController &&
             remote_call_current_success(); cursor++) {
            NSDictionary<NSString *, id> *entry = queue[cursor];
            uint64_t object = [entry[@"object"] unsignedLongLongValue];
            uint64_t parent = [entry[@"parent"] unsignedLongLongValue];
            NSUInteger depth = [entry[@"depth"] unsignedIntegerValue];
            NSString *className = CNDCCClassName(object) ?: @"unavailable";
            NSString *lowerClass = className.lowercaseString;
            if (mediaController &&
                ([lowerClass containsString:@"button"] ||
                 [lowerClass containsString:@"transport"])) {
                mediaButtonCandidateCount++;
            }
            if (connectivityController &&
                [lowerClass containsString:@"button"]) {
                connectivityButtonCandidateCount++;
            }
            if ([lowerClass containsString:@"chuis"] ||
                [lowerClass containsString:@"icon"] ||
                [lowerClass containsString:@"widget"]) {
                hostedIconCandidateCount++;
            }
            if ([lowerClass containsString:@"slider"] ||
                [lowerClass containsString:@"brightness"] ||
                [lowerClass containsString:@"volume"]) {
                sliderCandidateCount++;
            }
            if ([lowerClass containsString:@"focus"] ||
                [lowerClass containsString:@"dnd"]) {
                focusCandidateCount++;
            }

            NSMutableDictionary *row = [CNDCCObject(object) mutableCopy];
            row[@"ownerControllerAddress"] = CNDCCAddress(controller);
            row[@"ownerControllerClass"] = controllerClass;
            row[@"traceDomain"] = traceDomain;
            row[@"parentAddress"] = CNDCCAddress(parent);
            row[@"depth"] = @(depth);
            row[@"relation"] = entry[@"relation"] ?: @"unknown";
            NSString *identifier = CNDCCStringGetter(
                object, "accessibilityIdentifier");
            NSString *label = CNDCCStringGetter(object, "accessibilityLabel");
            if (identifier.length) row[@"accessibilityIdentifier"] = identifier;
            if (label.length) row[@"accessibilityLabel"] = label;
            row[@"window"] = CNDCCObject(CNDCCGetter(object, "window"));
            row[@"superview"] = CNDCCObject(CNDCCGetter(object, "superview"));
            row[@"layer"] = CNDCCObject(CNDCCGetter(object, "layer"));
            NSDictionary *geometry = CNDCCGeometry(object);
            if (geometry.count) row[@"geometry"] = geometry;
            if (r_responds_main(object, "isHidden")) {
                row[@"hidden"] = @(CNDCCGetter(object, "isHidden") != 0);
            }

            BOOL inspect = [entry[@"relation"] isEqualToString:@"controller"] ||
                CNDCCLooksTraceableObject(className);
            if (inspect) {
                NSMutableDictionary<NSString *, NSDictionary *> *contracts =
                    [NSMutableDictionary dictionary];
                for (NSString *selector in contractSelectors) {
                    NSDictionary *contract = CNDCCMethodContract(
                        object, selector.UTF8String);
                    if ([contract[@"present"] boolValue]) {
                        contracts[selector] = contract;
                    }
                }
                if (contracts.count) row[@"contracts"] = contracts;

                NSMutableDictionary<NSString *, NSDictionary *> *getters =
                    [NSMutableDictionary dictionary];
                for (NSString *selector in getterSelectors) {
                    if (!r_responds_main(object, selector.UTF8String)) continue;
                    uint64_t value = CNDCCGetter(object, selector.UTF8String);
                    NSMutableDictionary *getter = [@{
                        @"contract": CNDCCMethodContract(
                            object, selector.UTF8String),
                        @"value": CNDCCObject(value),
                    } mutableCopy];
                    getters[selector] = getter;
                    if (!r_is_objc_ptr(value)) continue;
                    [getterEdges addObject:@{
                        @"from": CNDCCObject(object),
                        @"selector": selector,
                        @"to": CNDCCObject(value),
                    }];
                    CNDCCEnqueueTraceObject(queue, seenTraceObjects, value, object,
                        depth + 1,
                        [@"getter." stringByAppendingString:selector]);
                }
                if (getters.count) row[@"getters"] = getters;
            }

            uint64_t subviews = CNDCCGetter(object, "subviews");
            uint64_t rawCount = CNDCCGetter(subviews, "count");
            NSUInteger remaining = CNDCCTraceObjectCapPerController - queue.count;
            if (rawCount <= CNDCCCollectionSanityMax && rawCount > remaining) {
                truncatedControllerTraces++;
            }
            NSUInteger count = CNDCCBoundedCount(rawCount, remaining,
                                                  &invalidCollections);
            for (NSUInteger i = 0; i < count; i++) {
                CNDCCEnqueueTraceObject(queue, seenTraceObjects,
                    CNDCCArrayObject(subviews, i), object, depth + 1,
                    @"subview");
            }
            [objectRows addObject:row];
        }
    }

    report[@"windowCount"] = @(windowCount);
    report[@"visitedControllerCount"] = @(controllers.count);
    report[@"traceControllerCount"] = @(controllerRows.count);
    report[@"mediaControllerCount"] = @(mediaControllerCount);
    report[@"connectivityControllerCount"] = @(connectivityControllerCount);
    report[@"mediaButtonCandidateCount"] = @(mediaButtonCandidateCount);
    report[@"connectivityButtonCandidateCount"] =
        @(connectivityButtonCandidateCount);
    report[@"hostedIconCandidateCount"] = @(hostedIconCandidateCount);
    report[@"sliderCandidateCount"] = @(sliderCandidateCount);
    report[@"focusCandidateCount"] = @(focusCandidateCount);
    report[@"traceDomainCounts"] = traceDomainCounts;
    report[@"tracedObjectCount"] = @(objectRows.count);
    report[@"getterEdgeCount"] = @(getterEdges.count);
    report[@"invalidCollectionCount"] = @(invalidCollections);
    report[@"truncatedControllerTraceCount"] =
        @(truncatedControllerTraces);
    report[@"controllers"] = controllerRows;
    report[@"objects"] = objectRows;
    report[@"getterEdges"] = getterEdges;
    (void)r_settle_us(previousSettle);

    int targetPIDAtExit = remote_call_current_pid();
    BOOL pidStable = targetPIDAtEntry > 0 &&
        targetPIDAtExit == targetPIDAtEntry;
    report[@"targetPIDAtExit"] = @(targetPIDAtExit);
    report[@"pidStable"] = @(pidStable);
    report[@"transportHealthy"] = @(remote_call_current_success());
    BOOL success = remote_call_current_success() && pidStable &&
        invalidCollections == 0 && controllerRows.count > 0 &&
        objectRows.count > 0;
    report[@"success"] = @(success);
    if (!success) {
        report[@"failureReason"] = controllerRows.count == 0
            ? @"No loaded Control Center controller was visible. Open the target Control Center page and retry."
            : @"The expanded Control Center graph did not remain stable for the bounded read-only trace.";
    }
    return report;
}

NSDictionary<NSString *, id> *CNDCCThemingCopyPhysicalInventory(void)
{
    int targetPIDAtEntry = remote_call_current_pid();
    NSMutableDictionary *report = [@{
        @"schemaVersion": @3,
        @"mode": @"physical-read-only-control-center-inventory",
        @"target": @"SpringBoard",
        @"targetPID": @(targetPIDAtEntry),
        @"success": @NO,
        @"readOnly": @YES,
        @"controlActions": @0,
        @"presentationWrites": @0,
        @"radioWrites": @0,
        @"fileWrites": @0,
        @"targetScratchAllocations": @YES,
        @"surfaces": @[],
        @"namedControls": @{},
    } mutableCopy];
    if (!remote_call_current_success()) {
        report[@"failureReason"] = @"The SpringBoard RemoteCall transport was not healthy at probe entry.";
        return report;
    }

    uint32_t previousSettle = r_settle_us(0);
    NSUInteger invalidCollections = 0;
    NSUInteger visitedViews = 0;
    NSUInteger truncatedTemplateTraversals = 0;
    NSMutableArray<NSNumber *> *controllers = [NSMutableArray array];
    NSMutableSet<NSNumber *> *seenControllers = [NSMutableSet set];
    NSMutableArray<NSDictionary *> *controllerRows = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *surfaces = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSDictionary *> *named =
        [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSMutableArray<NSDictionary *> *> *surfacesByKind =
        [NSMutableDictionary dictionary];
    NSMutableSet<NSString *> *recordedPairs = [NSMutableSet set];

    uint64_t application = CNDCCGetter(r_class("UIApplication"),
                                       "sharedApplication");
    uint64_t windows = CNDCCGetter(application, "windows");
    NSUInteger windowCount = CNDCCBoundedCount(CNDCCGetter(windows, "count"),
        CNDCCWindowCap, &invalidCollections);
    for (NSUInteger i = 0; i < windowCount && remote_call_current_success(); i++) {
        uint64_t window = CNDCCArrayObject(windows, i);
        CNDCCEnqueueController(controllers, seenControllers,
            CNDCCGetter(window, "rootViewController"));
    }

    for (NSUInteger cursor = 0;
         cursor < controllers.count && cursor < CNDCCControllerCap &&
         remote_call_current_success(); cursor++) {
        uint64_t controller = controllers[cursor].unsignedLongLongValue;
        NSString *className = CNDCCClassName(controller) ?: @"unavailable";
        if (CNDCCLooksRelevantController(className)) {
            [controllerRows addObject:CNDCCControllerObject(controller)];
        }
        CNDCCEnqueueController(controllers, seenControllers,
            CNDCCGetter(controller, "presentedViewController"));
        uint64_t children = CNDCCGetter(controller, "childViewControllers");
        NSUInteger remaining = CNDCCControllerCap - controllers.count;
        NSUInteger count = CNDCCBoundedCount(CNDCCGetter(children, "count"),
                                              remaining, &invalidCollections);
        for (NSUInteger i = 0; i < count; i++) {
            CNDCCEnqueueController(controllers, seenControllers,
                                   CNDCCArrayObject(children, i));
        }
    }

    uint64_t templateClass = r_class("CCUIControlTemplateView");
    uint64_t connectivity = 0;
    for (NSNumber *number in controllers) {
        uint64_t controller = number.unsignedLongLongValue;
        NSString *className = CNDCCClassName(controller) ?: @"";
        if ([className isEqualToString:@"CCUIConnectivityModuleViewController"])
            connectivity = controller;
    }

    NSDictionary<NSString *, NSArray<NSString *> *> *connectivityRoutes = @{
        @"wifi": @[@"wifiModuleViewController", @"wifiButtonViewController",
                    @"expandedWiFiButtonViewController"],
        @"bluetooth": @[@"bluetoothModuleViewController", @"bluetoothButtonViewController",
                         @"expandedBluetoothButtonViewController"],
        @"airplaneMode": @[@"airplaneButtonViewController", @"expandedAirplaneButtonViewController"],
        @"cellular": @[@"cellularDataButtonViewController", @"expandedCellularDataButtonViewController"],
        @"airDrop": @[@"airDropModuleViewController"],
        @"hotspot": @[@"hotspotButtonViewController", @"expandedHotspotButtonViewController"],
        @"vpn": @[@"vpnModuleViewController"],
        @"satellite": @[@"satelliteModuleViewController"],
    };
    NSMutableDictionary<NSString *, NSDictionary *> *connectivityContracts =
        [NSMutableDictionary dictionary];
    for (NSString *kind in connectivityRoutes) {
        NSMutableDictionary<NSString *, NSDictionary *> *kindContracts =
            [NSMutableDictionary dictionary];
        for (NSString *selector in connectivityRoutes[kind]) {
            kindContracts[selector] = CNDCCMethodContract(
                connectivity, selector.UTF8String);
        }
        connectivityContracts[kind] = kindContracts;
    }
    if (connectivity) {
        for (NSString *kind in connectivityRoutes) {
            for (NSString *selector in connectivityRoutes[kind]) {
                const char *selectorName = selector.UTF8String;
                if (!r_responds_main(connectivity, selectorName)) continue;
                uint64_t controller = CNDCCGetter(connectivity, selectorName);
                if (!r_is_objc_ptr(controller)) continue;
                uint64_t view = CNDCCGetter(controller, "viewIfLoaded");
                NSArray<NSNumber *> *templateViews = CNDCCCopyTemplateViews(
                    view, templateClass, &visitedViews, &invalidCollections,
                    &truncatedTemplateTraversals);
                for (NSNumber *templateNumber in templateViews) {
                    uint64_t templateView = templateNumber.unsignedLongLongValue;
                    NSString *pair = [NSString stringWithFormat:@"%llx:%llx",
                        (unsigned long long)controller,
                        (unsigned long long)templateView];
                    if ([recordedPairs containsObject:pair]) continue;
                    [recordedPairs addObject:pair];
                    NSDictionary *surface = CNDCCSurface(controller, templateView,
                        [@"connectivity." stringByAppendingString:selector]);
                    NSMutableDictionary *namedSurface = [surface mutableCopy];
                    namedSurface[@"kind"] = kind;
                    CNDCCRecordSurface(surfaces, named, surfacesByKind,
                                       namedSurface);
                }
            }
        }
    }

    for (NSNumber *number in controllers) {
        if (!remote_call_current_success()) break;
        uint64_t controller = number.unsignedLongLongValue;
        NSString *className = CNDCCClassName(controller) ?: @"";
        if (!CNDCCLooksRelevantController(className)) continue;
        uint64_t view = CNDCCGetter(controller, "viewIfLoaded");
        NSArray<NSNumber *> *templateViews = CNDCCCopyTemplateViews(
            view, templateClass, &visitedViews, &invalidCollections,
            &truncatedTemplateTraversals);
        for (NSNumber *templateNumber in templateViews) {
            uint64_t templateView = templateNumber.unsignedLongLongValue;
            NSString *pair = [NSString stringWithFormat:@"%llx:%llx",
                (unsigned long long)controller,
                (unsigned long long)templateView];
            if ([recordedPairs containsObject:pair]) continue;
            [recordedPairs addObject:pair];
            NSDictionary *surface = CNDCCSurface(controller, templateView,
                                                  @"controllerGraph");
            CNDCCRecordSurface(surfaces, named, surfacesByKind, surface);
        }
    }

    NSArray<NSString *> *priorityKinds = @[
        @"wifi", @"airplaneMode", @"cellular", @"bluetooth", @"airDrop",
        @"hotspot", @"vpn", @"flashlight", @"lowPower", @"screenRecording",
        @"calculator", @"camera", @"timer", @"qrCode",
        @"orientationLock",
    ];
    NSMutableArray<NSString *> *missing = [NSMutableArray array];
    for (NSString *kind in priorityKinds) {
        if (!named[kind]) [missing addObject:kind];
    }
    NSArray<NSString *> *pulsarKinds = @[
        @"wifi", @"airplaneMode", @"cellular", @"bluetooth", @"airDrop",
        @"hotspot", @"vpn", @"flashlight", @"lowPower", @"screenRecording",
        @"guidedAccess", @"accessibilityShortcuts", @"soundDetection",
        @"textSize", @"screenMirroring", @"alarm", @"timer", @"appearance",
        @"calculator", @"camera", @"display", @"hearing", @"magnifier",
        @"mute", @"orientationLock", @"qrCode", @"musicRecognition",
        @"stopwatch", @"tvRemote", @"voiceMemos", @"wallet", @"sound",
        @"nfc", @"performanceTrace",
    ];
    NSMutableArray<NSString *> *missingPulsarKinds = [NSMutableArray array];
    for (NSString *kind in pulsarKinds) {
        if (!named[kind]) [missingPulsarKinds addObject:kind];
    }

    report[@"windowCount"] = @(windowCount);
    report[@"visitedControllerCount"] = @(controllers.count);
    report[@"controlCenterControllerCount"] = @(controllerRows.count);
    report[@"visitedViewCount"] = @(visitedViews);
    report[@"invalidCollectionCount"] = @(invalidCollections);
    report[@"templateEnumerationMode"] = @"all-descendants";
    report[@"truncatedTemplateTraversalCount"] =
        @(truncatedTemplateTraversals);
    report[@"connectivityController"] = CNDCCObject(connectivity);
    report[@"connectivityContracts"] = connectivityContracts;
    report[@"controllers"] = controllerRows;
    report[@"surfaces"] = surfaces;
    report[@"namedControls"] = named;
    report[@"controlSurfacesByKind"] = surfacesByKind;
    report[@"missingPriorityControls"] = missing;
    report[@"missingPulsarModuleKinds"] = missingPulsarKinds;
    (void)r_settle_us(previousSettle);
    int targetPIDAtExit = remote_call_current_pid();
    BOOL pidStable = targetPIDAtEntry > 0 &&
        targetPIDAtExit == targetPIDAtEntry;
    report[@"targetPIDAtExit"] = @(targetPIDAtExit);
    report[@"pidStable"] = @(pidStable);
    report[@"transportHealthy"] = @(remote_call_current_success());

    BOOL success = remote_call_current_success() &&
        pidStable &&
        invalidCollections == 0 && controllerRows.count > 0 &&
        surfaces.count > 0;
    report[@"success"] = @(success);
    if (!success) {
        report[@"failureReason"] = controllerRows.count == 0
            ? @"Control Center was not visible during the capture window. Open it before the countdown ends and retry."
            : @"Control Center was found, but no live CCUIControlTemplateView surface could be inventoried safely.";
    }
    return report;
}

static BOOL CNDCCExactMethodHasTypes(uint64_t object,
                                     const char *selector,
                                     NSArray<NSString *> *acceptedTypes)
{
    if (!r_is_objc_ptr(object) || !selector || !acceptedTypes.count)
        return NO;
    NSDictionary *contract = CNDCCMethodContract(object, selector);
    NSString *types = [contract[@"types"] isKindOfClass:NSString.class]
        ? contract[@"types"] : nil;
    return [contract[@"present"] boolValue] &&
        [acceptedTypes containsObject:types ?: @""];
}

static BOOL CNDCCExactClassMatches(uint64_t object, NSString *expected)
{
    if (!r_is_objc_ptr(object)) return NO;
    if (!expected.length) return YES;
    NSString *actual = CNDCCClassName(object) ?: @"";
    if ([actual isEqualToString:expected] ||
        [actual isEqualToString:
            [@"NSKVONotifying_" stringByAppendingString:expected]]) {
        return YES;
    }
    uint64_t expectedClass = r_class(expected.UTF8String);
    return r_is_objc_ptr(expectedClass) &&
        r_msg2_main(object, "isKindOfClass:", expectedClass, 0, 0, 0) != 0;
}

// Resolve only a named getter or a named runtime ivar. This is the production
// counterpart of the VM lifecycle-owner trace: it never descends through an
// arbitrary UIKit subview graph and never uses labels, geometry, or ordering
// as semantic identity.
static uint64_t CNDCCExactNamedObject(uint64_t owner,
                                      NSString *getter,
                                      NSString *ivar,
                                      NSString *expectedClass)
{
    if (!r_is_objc_ptr(owner) || !remote_call_current_success()) return 0;
    uint64_t value = getter.length && CNDCCExactMethodHasTypes(
        owner, getter.UTF8String, @[@"@16@0:8"])
        ? r_msg2_main(owner, getter.UTF8String, 0, 0, 0, 0) : 0;
    if (!r_is_objc_ptr(value) && ivar.length) {
        value = r_ivar_value(owner, ivar.UTF8String);
    }
    return CNDCCExactClassMatches(value, expectedClass) ? value : 0;
}

static NSString *CNDCCExactStringObject(uint64_t object)
{
    if (!r_is_objc_ptr(object)) return nil;
    char buffer[768] = {0};
    if (!r_read_nsstring(object, buffer, sizeof(buffer)) || !buffer[0]) {
        return nil;
    }
    return [NSString stringWithUTF8String:buffer];
}

static NSString *CNDCCExactStringMember(uint64_t owner,
                                        NSString *getter,
                                        NSString *ivar)
{
    return CNDCCExactStringObject(
        CNDCCExactNamedObject(owner, getter, ivar, nil));
}

static NSArray<NSNumber *> *CNDCCExactCollectionObjects(uint64_t collection,
                                                        NSUInteger cap)
{
    if (!r_is_objc_ptr(collection)) return @[];
    NSUInteger count = CNDCCBoundedCount(
        CNDCCGetter(collection, "count"), cap, NULL);
    NSMutableArray<NSNumber *> *objects = [NSMutableArray array];
    for (NSUInteger index = 0;
         index < count && remote_call_current_success(); index++) {
        uint64_t object = CNDCCArrayObject(collection, index);
        if (r_is_objc_ptr(object)) [objects addObject:@(object)];
    }
    return objects;
}

static NSArray<NSNumber *> *CNDCCExactDictionaryValues(uint64_t dictionary,
                                                       NSUInteger cap)
{
    if (!r_is_objc_ptr(dictionary) ||
        !r_responds_main(dictionary, "allKeys") ||
        !r_responds_main(dictionary, "objectForKey:")) return @[];
    uint64_t keys = CNDCCGetter(dictionary, "allKeys");
    NSMutableArray<NSNumber *> *values = [NSMutableArray array];
    for (NSNumber *number in CNDCCExactCollectionObjects(keys, cap)) {
        uint64_t value = r_msg2_main(dictionary, "objectForKey:",
            number.unsignedLongLongValue, 0, 0, 0);
        if (r_is_objc_ptr(value)) [values addObject:@(value)];
    }
    return values;
}

// A single named owner's direct children may be selected by dynamic class.
// This is deliberately non-recursive and is used only where Swift Dictionary
// storage has no safe Objective-C object ABI (Media sessionViews on iOS 26).
static NSArray<NSNumber *> *CNDCCExactDirectSubviews(uint64_t owner,
                                                     NSString *expectedClass)
{
    uint64_t subviews = CNDCCExactNamedObject(
        owner, @"subviews", nil, nil);
    NSMutableArray<NSNumber *> *matches = [NSMutableArray array];
    for (NSNumber *number in CNDCCExactCollectionObjects(
            subviews, CNDCCViewCapPerController)) {
        if (CNDCCExactClassMatches(
                number.unsignedLongLongValue, expectedClass)) {
            [matches addObject:number];
        }
    }
    return matches;
}

static NSString *CNDCCSatelliteArtworkKind(uint64_t controller,
                                           uint64_t *stateOut)
{
    if (stateOut) *stateOut = 0;
    if (!r_is_objc_ptr(controller) ||
        ![(CNDCCClassName(controller) ?: @"")
            isEqualToString:@"CCUISatelliteModuleViewController"]) {
        return @"satelliteUnavailable";
    }

    uint64_t monitor = CNDCCGetter(controller, "satelliteMonitor");
    NSDictionary *contract = CNDCCMethodContract(monitor, "state");
    NSString *types = [contract[@"types"] isKindOfClass:NSString.class]
        ? contract[@"types"] : nil;
    uint64_t state = 0;
    if ([contract[@"present"] boolValue] &&
        ([types isEqualToString:@"Q16@0:8"] ||
         [types isEqualToString:@"q16@0:8"])) {
        state = r_msg2_main(monitor, "state", 0, 0, 0, 0);
    }
    if (stateOut) *stateOut = state;

    // iOS 26's CCUISatelliteModuleViewController maps states 0-1 to
    // satellite.slash.fill, 2-3 to satellite.fill, 4 to satellite.wave.2,
    // and 5-6 to satellite.wave.2.fill.  The supplemental set intentionally
    // has three semantic variants, so the transient satellite.fill states use
    // the available artwork while preserving connected separately.
    if (state >= 5) return @"satelliteConnected";
    if (state >= 2) return @"satelliteAvailable";
    return @"satelliteUnavailable";
}

static NSString *CNDCCExactModuleKind(NSString *identifier,
                                      NSString *moduleClass)
{
    NSDictionary<NSString *, NSString *> *exact = @{
        @"com.apple.control-center.ConnectivityModule": @"connectivity",
        @"com.apple.control-center.DisplayModule": @"display",
        @"com.apple.mediaremote.controlcenter.audio": @"sound",
        @"com.apple.mediaremote.controlcenter.nowplaying": @"nowPlaying",
        @"com.apple.FocusUIModule": @"focus",
        @"com.apple.mobiletimer.controlcenter.timer": @"timer",
        @"com.apple.replaykit.controlcenter.screencapture": @"screenRecording",
        @"com.apple.control-center.LowPowerModule": @"lowPower",
        @"com.apple.control-center.MuteModule": @"mute",
        @"com.apple.control-center.OrientationLockModule": @"orientationLock",
    };
    NSString *kind = exact[identifier];
    // Production offscreen materialization must never promote a merely
    // similar module through the diagnostic substring classifier. In
    // particular, iOS 26's Audio/Video Conference modules also contain the
    // "replaykit" token, but their content factory expects a different
    // context contract than the Screen Recording module. Calling that factory
    // with CCUIContentModuleContext raises an exception in SpringBoard.
    (void)moduleClass;
    return kind.length ? kind : @"unclassified";
}

static NSString *CNDCCExactHostedKind(NSString *identity)
{
    NSString *value = identity.lowercaseString;
    if ([value isEqualToString:
            @"com.apple.calculator.calculatorwidget.control"]) {
        return @"calculator";
    }
    if ([value isEqualToString:@"com.apple.camera.deeplink.button"]) {
        return @"camera";
    }
    if ([value isEqualToString:@"com.apple.barcodescanner.button"]) {
        return @"qrCode";
    }
    return nil;
}

static NSString *CNDCCExactFocusKind(NSString *identifier)
{
    if ([identifier isEqualToString:@"com.apple.donotdisturb.mode.default"])
        return @"focus";
    if ([identifier isEqualToString:@"com.apple.sleep.sleep-mode"])
        return @"focusSleep";
    if ([identifier isEqualToString:@"com.apple.focus.personal-time"])
        return @"focusPersonal";
    if ([identifier isEqualToString:@"com.apple.focus.work"])
        return @"focusWork";
    if ([identifier isEqualToString:
            @"com.apple.focus.reduce-interruptions"])
        return @"focusReduceInterruptions";
    return identifier.length ? @"focusCustom" : nil;
}

static void CNDCCAppendExactTarget(
    NSMutableArray<NSDictionary<NSString *, id> *> *resolved,
    NSMutableSet<NSString *> *seen,
    uint64_t controller,
    uint64_t target,
    NSString *kind,
    NSString *targetType,
    NSString *routeID,
    NSArray<NSString *> *ownershipPath,
    NSString *moduleIdentifier,
    NSArray<NSString *> *scopes,
    BOOL directChildSelection)
{
    if (!r_is_objc_ptr(controller) || !r_is_objc_ptr(target) ||
        !kind.length || !targetType.length || !routeID.length) return;
    NSString *dedup = [NSString stringWithFormat:@"%llx:%@:%@",
        (unsigned long long)target, kind, targetType];
    if ([seen containsObject:dedup]) return;

    uint64_t window = CNDCCGetter(target, "window");
    NSString *windowClass = CNDCCClassName(window) ?: @"";
    NSMutableDictionary *row = [@{
        @"kind": kind,
        @"source": @"exactLifecycleRoute",
        @"resolutionMode": @"named-ownership-no-recursive-view-walk",
        @"routeID": routeID,
        @"ownershipPath": ownershipPath ?: @[],
        @"targetType": targetType,
        @"target": CNDCCObject(target),
        @"targetAddressValue": @(target),
        @"controller": CNDCCControllerObject(controller),
        @"controllerAddressValue": @(controller),
        @"window": CNDCCObject(window),
        @"attachedToControlCenterWindow": @(
            r_is_objc_ptr(window) &&
            [windowClass isEqualToString:@"SBControlCenterWindow"]),
        @"recursiveViewWalkUsed": @NO,
        @"directChildSelectionUsed": @(directChildSelection),
        @"scopes": scopes ?: @[],
    } mutableCopy];
    if (moduleIdentifier.length) row[@"moduleIdentifier"] = moduleIdentifier;
    [resolved addObject:row];
    [seen addObject:dedup];
}

static NSDictionary<NSString *, id> *CNDCCExactContainerForModule(
    NSArray<NSDictionary<NSString *, id> *> *containers,
    uint64_t module,
    NSString *moduleIdentifier)
{
    NSDictionary *identifierMatch = nil;
    for (NSDictionary *container in containers) {
        if ([container[@"contentModule"] unsignedLongLongValue] == module) {
            return container;
        }
        if (!identifierMatch && moduleIdentifier.length &&
            [container[@"moduleIdentifier"] isEqualToString:moduleIdentifier]) {
            identifierMatch = container;
        }
    }
    return identifierMatch;
}

static uint64_t CNDCCExactTemplateForController(uint64_t controller)
{
    if (CNDCCExactClassMatches(controller, @"CCUIControlTemplateView")) {
        return controller;
    }
    for (NSString *ivar in @[@"_buttonModuleView", @"_templateView"]) {
        uint64_t view = CNDCCExactNamedObject(
            controller, nil, ivar, @"CCUIControlTemplateView");
        if (view) return view;
    }
    return CNDCCExactNamedObject(
        controller, @"viewIfLoaded", nil, @"CCUIControlTemplateView");
}

static uint64_t CNDCCExactGlyphTargetForController(uint64_t controller)
{
    uint64_t button = CNDCCExactNamedObject(
        controller, @"button", @"_button", nil);
    if (button) return button;
    uint64_t view = CNDCCExactNamedObject(
        controller, @"viewIfLoaded", nil, nil);
    return view ?: controller;
}

static void CNDCCExactRecordMaterialization(
    NSMutableArray<NSDictionary<NSString *, id> *> *events,
    NSString *routeID,
    uint64_t owner,
    uint64_t beforeView,
    uint64_t afterView,
    NSString *status,
    NSString *selector)
{
    [events addObject:@{
        @"routeID": routeID ?: @"unknown",
        @"owner": CNDCCObject(owner),
        @"beforeView": CNDCCObject(beforeView),
        @"afterView": CNDCCObject(afterView),
        @"status": status ?: @"unknown",
        @"selector": selector ?: @"",
    }];
}

// UIViewController view construction is deliberately separate from every
// read-only trace entry point. Only the inherited, exact no-argument lifecycle
// ABI is accepted, and completion is established by rereading viewIfLoaded.
static uint64_t CNDCCExactLoadController(
    uint64_t controller,
    NSString *routeID,
    NSMutableArray<NSDictionary<NSString *, id> *> *events)
{
    if (!r_is_objc_ptr(controller)) {
        CNDCCExactRecordMaterialization(events, routeID, 0, 0, 0,
            @"ownerMissing", @"loadViewIfNeeded");
        return 0;
    }
    uint64_t before = CNDCCExactNamedObject(
        controller, @"viewIfLoaded", nil, nil);
    if (before) {
        CNDCCExactRecordMaterialization(events, routeID, controller,
            before, before, @"alreadyLoaded", @"viewIfLoaded");
        return before;
    }
    if (!CNDCCExactMethodHasTypes(
            controller, "loadViewIfNeeded", @[@"v16@0:8"])) {
        CNDCCExactRecordMaterialization(events, routeID, controller,
            0, 0, @"ABIRejected", @"loadViewIfNeeded");
        return 0;
    }
    (void)r_msg2_main(controller, "loadViewIfNeeded", 0, 0, 0, 0);
    uint64_t after = CNDCCExactNamedObject(
        controller, @"viewIfLoaded", nil, nil);
    CNDCCExactRecordMaterialization(events, routeID, controller,
        before, after, after ? @"loadedOffscreen" : @"viewStillMissing",
        @"loadViewIfNeeded");
    return after;
}

static uint64_t CNDCCExactFactoryController(
    uint64_t module,
    uint64_t context,
    NSString *selector,
    NSString *expectedClass,
    NSString *routeID,
    NSMutableArray<NSDictionary<NSString *, id> *> *events)
{
    if (!r_is_objc_ptr(module) || !r_is_objc_ptr(context)) {
        CNDCCExactRecordMaterialization(events, routeID, module,
            0, 0, @"ownerMissing", selector);
        return 0;
    }
    if (!CNDCCExactMethodHasTypes(
            module, selector.UTF8String, @[@"@24@0:8@16"])) {
        CNDCCExactRecordMaterialization(events, routeID, module,
            0, 0, @"ABIRejected", selector);
        return 0;
    }
    uint64_t controller = r_msg2_main(
        module, selector.UTF8String, context, 0, 0, 0);
    if (!CNDCCExactClassMatches(controller, expectedClass)) controller = 0;
    CNDCCExactRecordMaterialization(events, routeID, module,
        0, controller, controller ? @"factoryProduced" : @"viewStillMissing",
        selector);
    return controller;
}

NSDictionary<NSString *, id> *
CNDCCThemingMaterializeExactRouteOwners(void)
{
    int targetPID = remote_call_current_pid();
    NSMutableArray<NSDictionary<NSString *, id> *> *events =
        [NSMutableArray array];
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schemaVersion": @1,
        @"mode": @"named-lifecycle-offscreen-materialization",
        @"success": @NO,
        @"targetPID": @(targetPID),
        @"recursiveViewWalkUsed": @NO,
        @"presentationActions": @0,
        @"controlActions": @0,
        @"radioWrites": @0,
        @"targetFileWrites": @0,
    } mutableCopy];
    if (targetPID <= 1 || !remote_call_current_success()) {
        report[@"failureReason"] = @"SpringBoard RemoteCall was unavailable.";
        report[@"events"] = events;
        return report;
    }

    uint64_t springBoard = CNDCCGetter(
        r_class("UIApplication"), "sharedApplication");
    uint64_t controlCenter = CNDCCExactNamedObject(
        springBoard, nil, @"_mainDisplayControlCenterController",
        @"SBControlCenterController");
    uint64_t mainController = CNDCCExactNamedObject(
        controlCenter, @"viewController", @"_viewController",
        @"CCUIMainViewController");
    uint64_t mainView = CNDCCExactLoadController(
        mainController, @"root.mainViewController", events);

    // Reread these owners after main-view construction. On a cold SpringBoard
    // session the paging/root members can be nil before loadViewIfNeeded.
    uint64_t manager = CNDCCExactNamedObject(
        mainController, @"moduleInstanceManager", @"_moduleInstanceManager",
        @"CCUIModuleInstanceManager");
    uint64_t pagingController = CNDCCExactNamedObject(
        mainController, @"pagingViewController", @"_pagingViewController",
        @"CCUIPagingViewController");
    uint64_t pagingView = CNDCCExactLoadController(
        pagingController, @"root.pagingViewController", events);
    uint64_t rootFolderController = CNDCCExactNamedObject(
        pagingController, nil, @"__rootFolderController",
        @"ControlCenterUI.IconListRootFolderController");
    uint64_t rootView = CNDCCExactLoadController(
        rootFolderController, @"root.folderController", events);
    uint64_t registry = CNDCCExactNamedObject(
        manager, nil, @"_enabledModuleInstanceByUniqueIdentifer", nil);

    NSMutableArray<NSDictionary<NSString *, id> *> *containers =
        [NSMutableArray array];
    uint64_t rootChildren = CNDCCExactNamedObject(
        rootFolderController, @"childViewControllers", nil, nil);
    for (NSNumber *number in CNDCCExactCollectionObjects(
            rootChildren, CNDCCControllerCap)) {
        uint64_t container = number.unsignedLongLongValue;
        if (!CNDCCExactClassMatches(
                container, @"CCUIContentModuleContainerViewController")) {
            continue;
        }
        CNDCCExactLoadController(container,
            @"root.containerViewController", events);
        uint64_t contentModule = CNDCCExactNamedObject(
            container, @"contentModule", @"_contentModule", nil);
        uint64_t contentController = CNDCCExactNamedObject(
            container, @"contentViewController", @"_contentViewController",
            nil);
        uint64_t backgroundController = CNDCCExactNamedObject(
            container, @"backgroundViewController",
            @"_backgroundViewController", nil);
        NSString *identifier = CNDCCExactStringMember(
            container, @"moduleIdentifier", @"_moduleIdentifier") ?: @"";
        [containers addObject:@{
            @"container": @(container),
            @"contentModule": @(contentModule),
            @"contentController": @(contentController),
            @"backgroundController": @(backgroundController),
            @"moduleIdentifier": identifier,
        }];
        if (contentController) {
            CNDCCExactLoadController(contentController,
                @"root.container.contentViewController", events);
        }
        if (backgroundController) {
            CNDCCExactLoadController(backgroundController,
                @"root.container.backgroundViewController", events);
        }
    }

    NSMutableArray<NSDictionary<NSString *, id> *> *modules =
        [NSMutableArray array];
    for (NSNumber *number in CNDCCExactDictionaryValues(
            registry, CNDCCControllerCap)) {
        uint64_t instance = number.unsignedLongLongValue;
        if (!CNDCCExactClassMatches(instance, @"CCUIModuleInstance")) continue;
        uint64_t metadata = CNDCCExactNamedObject(
            instance, @"metadata", @"_metadata", @"CCSModuleMetadata");
        uint64_t module = CNDCCExactNamedObject(
            instance, @"module", @"_module", nil);
        NSString *identifier = CNDCCExactStringMember(
            metadata, @"moduleIdentifier", @"_moduleIdentifier");
        if (!module || !identifier.length) continue;
        [modules addObject:@{
            @"module": @(module),
            @"moduleIdentifier": identifier,
        }];
    }

    for (NSDictionary *moduleRecord in modules) {
        uint64_t module = [moduleRecord[@"module"] unsignedLongLongValue];
        NSString *identifier = moduleRecord[@"moduleIdentifier"];
        NSString *kind = CNDCCExactModuleKind(
            identifier, CNDCCClassName(module) ?: @"");
        if (!kind.length || [kind isEqualToString:@"unclassified"]) continue;
        NSDictionary *container = CNDCCExactContainerForModule(
            containers, module, identifier);
        uint64_t contentController =
            [container[@"contentController"] unsignedLongLongValue];
        uint64_t context = CNDCCExactNamedObject(
            module, @"contentModuleContext", @"_contentModuleContext",
            @"CCUIContentModuleContext");
        if (!contentController) {
            contentController = CNDCCExactFactoryController(
                module, context, @"contentViewControllerForContext:", nil,
                [@"module.factory.content." stringByAppendingString:identifier],
                events);
        }
        CNDCCExactLoadController(contentController,
            [@"module.content." stringByAppendingString:identifier], events);

        if ([kind isEqualToString:@"connectivity"] && contentController) {
            BOOL stateABI = CNDCCExactMethodHasTypes(contentController,
                "isExpandedViewInitialized", @[@"B16@0:8", @"c16@0:8"]);
            BOOL initialized = stateABI && r_msg2_main(contentController,
                "isExpandedViewInitialized", 0, 0, 0, 0) != 0;
            if (initialized) {
                CNDCCExactRecordMaterialization(events,
                    @"connectivity.expandedOwners", contentController,
                    0, 0, @"alreadyLoaded", @"isExpandedViewInitialized");
            } else if (stateABI && CNDCCExactMethodHasTypes(contentController,
                    "_initializeExpandedView", @[@"v16@0:8"])) {
                (void)r_msg2_main(contentController,
                    "_initializeExpandedView", 0, 0, 0, 0);
                BOOL verified = r_msg2_main(contentController,
                    "isExpandedViewInitialized", 0, 0, 0, 0) != 0;
                CNDCCExactRecordMaterialization(events,
                    @"connectivity.expandedOwners", contentController,
                    0, 0, verified ? @"loadedOffscreen" : @"viewStillMissing",
                    @"_initializeExpandedView");
            } else {
                CNDCCExactRecordMaterialization(events,
                    @"connectivity.expandedOwners", contentController,
                    0, 0, @"ABIRejected", @"_initializeExpandedView");
            }
            for (NSString *member in @[
                @"airplaneButtonViewController",
                @"expandedAirplaneButtonViewController",
                @"cellularDataButtonViewController",
                @"expandedCellularDataButtonViewController",
                @"hotspotButtonViewController",
                @"expandedHotspotButtonViewController",
                @"wifiModuleViewController",
                @"bluetoothModuleViewController",
                @"airDropModuleViewController",
                @"vpnModuleViewController",
                @"satelliteModuleViewController",
            ]) {
                uint64_t child = CNDCCExactNamedObject(contentController,
                    member, [@"_" stringByAppendingString:member], nil);
                CNDCCExactLoadController(child,
                    [@"connectivity." stringByAppendingString:member], events);
            }
            continue;
        }

        if ([kind isEqualToString:@"display"]) {
            uint64_t compact = CNDCCExactNamedObject(module, nil,
                @"_moduleViewController", @"CCUIDisplayModuleViewController")
                ?: contentController;
            CNDCCExactLoadController(compact,
                @"display.compactController", events);
            uint64_t background = CNDCCExactNamedObject(module, nil,
                @"_backgroundViewController",
                @"CCUIDisplayBackgroundViewController")
                ?: [container[@"backgroundController"] unsignedLongLongValue];
            if (!background) {
                background = CNDCCExactFactoryController(module, context,
                    @"backgroundViewControllerForContext:",
                    @"CCUIDisplayBackgroundViewController",
                    @"display.backgroundFactory", events);
            }
            CNDCCExactLoadController(background,
                @"display.backgroundController", events);
            for (NSString *ivar in @[
                    @"_styleModeButton", @"_nightShiftButton",
                    @"_trueToneButton"]) {
                uint64_t buttonController = CNDCCExactNamedObject(
                    background, nil, ivar, @"CCUILabeledRoundButtonViewController");
                CNDCCExactLoadController(buttonController,
                    [@"display" stringByAppendingString:ivar], events);
            }
            continue;
        }

        if ([kind isEqualToString:@"sound"]) {
            uint64_t volume = CNDCCExactNamedObject(module,
                @"volumeViewController", @"_volumeViewController",
                @"MRUVolumeViewController") ?: contentController;
            CNDCCExactLoadController(volume, @"volume.primaryController", events);
            uint64_t background = CNDCCExactNamedObject(module,
                @"volumeBackgroundViewController",
                @"_volumeBackgroundViewController",
                @"MRUVolumeBackgroundViewController");
            if (!background) {
                background = CNDCCExactFactoryController(module, context,
                    @"backgroundViewControllerForContext:",
                    @"MRUVolumeBackgroundViewController",
                    @"volume.backgroundFactory", events);
            }
            CNDCCExactLoadController(background,
                @"volume.backgroundController", events);
            continue;
        }

        if ([kind isEqualToString:@"focus"]) {
            uint64_t compact = CNDCCExactNamedObject(module, nil,
                @"_moduleViewController", @"FCCCModuleViewController")
                ?: contentController;
            CNDCCExactLoadController(compact, @"focus.compactController", events);
            uint64_t picker = CNDCCExactNamedObject(module, nil,
                @"_activityPickerViewController",
                @"FCUIActivityPickerViewController");
            CNDCCExactLoadController(picker, @"focus.activityPicker", events);
            continue;
        }

        if ([kind isEqualToString:@"nowPlaying"]) {
            uint64_t media = CNDCCExactNamedObject(module,
                @"contentViewController", @"_contentViewController",
                @"MRUMediaControlsModuleViewController") ?: contentController;
            CNDCCExactLoadController(media, @"media.contentController", events);
        }
    }

    NSUInteger loaded = 0;
    NSUInteger alreadyLoaded = 0;
    NSUInteger unresolved = 0;
    for (NSDictionary *event in events) {
        NSString *status = event[@"status"];
        if ([status isEqualToString:@"loadedOffscreen"] ||
            [status isEqualToString:@"factoryProduced"]) loaded++;
        else if ([status isEqualToString:@"alreadyLoaded"]) alreadyLoaded++;
        else unresolved++;
    }
    BOOL pidStable = remote_call_current_pid() == targetPID;
    BOOL rootReady = springBoard && controlCenter && mainController && mainView &&
        manager && pagingController && pagingView && rootFolderController &&
        rootView && registry;
    BOOL success = rootReady && pidStable && remote_call_current_success();
    report[@"events"] = events;
    report[@"eventCount"] = @(events.count);
    report[@"loadedOffscreenCount"] = @(loaded);
    report[@"alreadyLoadedCount"] = @(alreadyLoaded);
    report[@"unresolvedOwnerCount"] = @(unresolved);
    report[@"moduleCount"] = @(modules.count);
    report[@"containerCount"] = @(containers.count);
    report[@"rootReady"] = @(rootReady);
    report[@"pidStable"] = @(pidStable);
    report[@"success"] = @(success);
    if (!success) {
        report[@"failureReason"] = !rootReady
            ? @"The named Control Center root graph could not be materialized offscreen."
            : @"SpringBoard identity or RemoteCall transport changed during materialization.";
    } else if (unresolved) {
        report[@"partialNotice"] =
            @"The root graph loaded offscreen; optional or asynchronously supplied owners remain listed in events.";
    }
    return report;
}

NSArray<NSDictionary<NSString *, id> *> *
CNDCCThemingCopyResolvedLiveTemplates(void)
{
    if (!remote_call_current_success()) return @[];
    int targetPID = remote_call_current_pid();

    uint64_t springBoard = CNDCCGetter(
        r_class("UIApplication"), "sharedApplication");
    if (!CNDCCExactClassMatches(springBoard, @"SpringBoard")) return @[];
    uint64_t controlCenter = CNDCCExactNamedObject(
        springBoard, nil, @"_mainDisplayControlCenterController",
        @"SBControlCenterController");
    uint64_t mainController = CNDCCExactNamedObject(
        controlCenter, @"viewController", @"_viewController",
        @"CCUIMainViewController");
    uint64_t manager = CNDCCExactNamedObject(
        mainController, @"moduleInstanceManager", @"_moduleInstanceManager",
        @"CCUIModuleInstanceManager");
    uint64_t pagingController = CNDCCExactNamedObject(
        mainController, nil, @"_pagingViewController",
        @"CCUIPagingViewController");
    uint64_t rootFolderController = CNDCCExactNamedObject(
        pagingController, nil, @"__rootFolderController",
        @"ControlCenterUI.IconListRootFolderController");
    uint64_t registry = CNDCCExactNamedObject(
        manager, nil, @"_enabledModuleInstanceByUniqueIdentifer", nil);
    if (!springBoard || !controlCenter || !mainController || !manager ||
        !pagingController || !rootFolderController || !registry ||
        remote_call_current_pid() != targetPID) return @[];

    NSMutableArray<NSDictionary<NSString *, id> *> *modules =
        [NSMutableArray array];
    for (NSNumber *number in CNDCCExactDictionaryValues(
            registry, CNDCCControllerCap)) {
        uint64_t instance = number.unsignedLongLongValue;
        if (!CNDCCExactClassMatches(instance, @"CCUIModuleInstance")) continue;
        uint64_t metadata = CNDCCExactNamedObject(
            instance, @"metadata", @"_metadata", @"CCSModuleMetadata");
        uint64_t module = CNDCCExactNamedObject(
            instance, @"module", @"_module", nil);
        NSString *identifier = CNDCCExactStringMember(
            metadata, @"moduleIdentifier", @"_moduleIdentifier");
        if (!module || !identifier.length) continue;
        [modules addObject:@{
            @"instance": @(instance),
            @"module": @(module),
            @"moduleIdentifier": identifier,
        }];
    }

    NSMutableArray<NSDictionary<NSString *, id> *> *containers =
        [NSMutableArray array];
    uint64_t rootChildren = CNDCCExactNamedObject(
        rootFolderController, @"childViewControllers", nil, nil);
    for (NSNumber *number in CNDCCExactCollectionObjects(
            rootChildren, CNDCCControllerCap)) {
        uint64_t container = number.unsignedLongLongValue;
        if (!CNDCCExactClassMatches(
                container, @"CCUIContentModuleContainerViewController")) {
            continue;
        }
        uint64_t contentModule = CNDCCExactNamedObject(
            container, @"contentModule", @"_contentModule", nil);
        uint64_t contentController = CNDCCExactNamedObject(
            container, @"contentViewController", @"_contentViewController",
            nil);
        uint64_t backgroundController = CNDCCExactNamedObject(
            container, nil, @"_backgroundViewController", nil);
        NSString *identifier = CNDCCExactStringMember(
            container, @"moduleIdentifier", @"_moduleIdentifier") ?: @"";
        [containers addObject:@{
            @"container": @(container),
            @"contentModule": @(contentModule),
            @"contentController": @(contentController),
            @"backgroundController": @(backgroundController),
            @"moduleIdentifier": identifier,
        }];
    }

    NSMutableArray<NSDictionary<NSString *, id> *> *resolved =
        [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];

    // Hosted Controls are not legacy module instances. Resolve their exact
    // host/identity/instance/icon chain from the root folder's direct module
    // containers instead of searching descendants of the template view.
    for (NSDictionary *container in containers) {
        uint64_t hostController =
            [container[@"contentController"] unsignedLongLongValue];
        if (!CNDCCExactClassMatches(
                hostController, @"CCUIControlHostViewController")) continue;
        uint64_t identity = CNDCCExactNamedObject(
            hostController, @"identity", nil, @"CHSControlIdentity");
        NSString *identityKind = CNDCCExactStringMember(
            identity, @"kind", @"_kind");
        NSString *kind = CNDCCExactHostedKind(identityKind);
        if (!kind.length) continue;
        uint64_t hostView = CNDCCExactNamedObject(
            hostController, @"viewIfLoaded", nil, @"CCUIControlHostView");
        uint64_t controlInstance = CNDCCExactNamedObject(
            hostView, @"controlInstance", @"controlInstance",
            @"CHUISControlInstanceButton");
        uint64_t iconView = CNDCCExactNamedObject(
            controlInstance, @"iconView", nil, @"CHUISControlIconView");
        CNDCCAppendExactTarget(resolved, seen, hostController, iconView,
            kind, @"hostedControlIcon",
            [@"hosted." stringByAppendingString:kind],
            @[@"rootFolderController.childViewControllers",
              @"container.contentViewController", @"host.identity.kind",
              @"host.viewIfLoaded", @"controlInstance", @"iconView"],
            container[@"moduleIdentifier"], @[@"compactHostedControl"], NO);
    }

    for (NSDictionary *moduleRecord in modules) {
        uint64_t module = [moduleRecord[@"module"] unsignedLongLongValue];
        NSString *identifier = moduleRecord[@"moduleIdentifier"];
        NSString *moduleClass = CNDCCClassName(module) ?: @"";
        NSString *kind = CNDCCExactModuleKind(identifier, moduleClass);
        NSDictionary *container = CNDCCExactContainerForModule(
            containers, module, identifier);
        uint64_t contentController =
            [container[@"contentController"] unsignedLongLongValue];

        // Every ordinary control uses its module container's named content
        // controller and a named template ivar. This preserves the existing
        // bottom-row mappings without an all-descendant view walk.
        if (kind.length && ![kind isEqualToString:@"unclassified"] &&
            ![@[@"connectivity", @"display", @"sound", @"nowPlaying"]
                containsObject:kind]) {
            uint64_t templateView = CNDCCExactTemplateForController(
                contentController ?: module);
            CNDCCAppendExactTarget(resolved, seen,
                contentController ?: module, templateView, kind, @"template",
                [@"module." stringByAppendingString:kind],
                @[@"moduleRegistry[metadata.moduleIdentifier]",
                  @"rootFolderController.childViewControllers[contentModule]",
                  @"contentViewController", @"_buttonModuleView/_templateView"],
                identifier, @[@"compactModule"], NO);
            if ([kind isEqualToString:@"focus"] && templateView) {
                uint64_t custom = CNDCCExactNamedObject(
                    templateView, @"customGlyphView", nil, nil);
                CNDCCAppendExactTarget(resolved, seen, contentController,
                    custom, kind, @"suppressedView", @"focus.compact.custom",
                    @[@"focus._moduleViewController", @"_templateView",
                      @"customGlyphView"], identifier,
                    @[@"compactFocus"], NO);
            }
        }

        if ([kind isEqualToString:@"connectivity"]) {
            uint64_t connectivity = contentController;
            NSDictionary<NSString *, NSArray<NSString *> *> *routes = @{
                @"airplaneMode": @[@"airplaneButtonViewController",
                    @"expandedAirplaneButtonViewController"],
                @"cellular": @[@"cellularDataButtonViewController",
                    @"expandedCellularDataButtonViewController"],
                @"hotspot": @[@"hotspotButtonViewController",
                    @"expandedHotspotButtonViewController"],
                @"wifi": @[@"wifiButtonViewController",
                    @"wifiModuleViewController",
                    @"expandedWiFiButtonViewController"],
                @"bluetooth": @[@"bluetoothButtonViewController",
                    @"bluetoothModuleViewController",
                    @"expandedBluetoothButtonViewController"],
                @"airDrop": @[@"airDropModuleViewController"],
                @"vpn": @[@"vpnModuleViewController"],
                @"satellite": @[@"satelliteModuleViewController"],
            };
            for (NSString *baseKind in routes) {
                for (NSString *member in routes[baseKind]) {
                    uint64_t child = CNDCCExactNamedObject(connectivity,
                        member, [@"_" stringByAppendingString:member], nil);
                    if (!child) continue;
                    NSString *resolvedKind = [baseKind isEqualToString:@"satellite"]
                        ? CNDCCSatelliteArtworkKind(child, NULL) : baseKind;
                    uint64_t glyphTarget =
                        CNDCCExactGlyphTargetForController(child);
                    BOOL expanded = [member hasPrefix:@"expanded"];
                    NSArray *scopes = expanded
                        ? @[@"expandedConnectivity"]
                        : ([member containsString:@"ModuleViewController"]
                            ? @[@"compactConnectivity", @"expandedConnectivity"]
                            : @[@"compactConnectivity"]);
                    CNDCCAppendExactTarget(resolved, seen, child, glyphTarget,
                        resolvedKind, @"singleGlyph",
                        [@"connectivity." stringByAppendingString:member],
                        @[@"connectivity container.contentViewController",
                          member, @"button/viewIfLoaded"], identifier,
                        scopes, NO);
                }
            }
            continue;
        }

        if ([kind isEqualToString:@"display"]) {
            uint64_t controller = CNDCCExactNamedObject(module, nil,
                @"_moduleViewController", @"CCUIDisplayModuleViewController")
                ?: contentController;
            uint64_t slider = CNDCCExactNamedObject(controller,
                @"sliderView", @"_sliderView", @"CCUIContinuousSliderView");
            uint64_t glyph = CNDCCExactNamedObject(slider, nil,
                @"_glyphPackageView", @"CCUICAPackageView");
            CNDCCAppendExactTarget(resolved, seen, controller, glyph,
                @"display", @"ccuiPackageView", @"display.compact.glyph",
                @[@"CCUIDisplayModule._moduleViewController", @"_sliderView",
                  @"_glyphPackageView"], identifier,
                @[@"compactBrightness"], NO);

            uint64_t background = CNDCCExactNamedObject(module, nil,
                @"_backgroundViewController",
                @"CCUIDisplayBackgroundViewController")
                ?: [container[@"backgroundController"] unsignedLongLongValue];
            uint64_t package = CNDCCExactNamedObject(background, nil,
                @"_packageView", @"CCUICAPackageView");
            CNDCCAppendExactTarget(resolved, seen, background, package,
                @"display", @"ccuiPackageView", @"display.expanded.package",
                @[@"CCUIDisplayModule._backgroundViewController",
                  @"_packageView"], identifier,
                @[@"expandedBrightness"], NO);
            NSDictionary *buttons = @{
                @"appearance": @"_styleModeButton",
                @"nightShift": @"_nightShiftButton",
                @"trueTone": @"_trueToneButton",
            };
            for (NSString *buttonKind in buttons) {
                NSString *ivar = buttons[buttonKind];
                uint64_t buttonController = CNDCCExactNamedObject(
                    background, nil, ivar, nil);
                uint64_t button = CNDCCExactGlyphTargetForController(
                    buttonController);
                CNDCCAppendExactTarget(resolved, seen, buttonController,
                    button, buttonKind, @"singleGlyph",
                    [@"display.expanded."
                        stringByAppendingString:buttonKind],
                    @[@"CCUIDisplayModule._backgroundViewController", ivar,
                      @"button/viewIfLoaded"], identifier,
                    @[@"expandedBrightness"], NO);
            }
            continue;
        }

        if ([kind isEqualToString:@"sound"]) {
            uint64_t controller = CNDCCExactNamedObject(module, nil,
                @"_volumeViewController", @"MRUVolumeViewController")
                ?: contentController;
            uint64_t volumeView = CNDCCExactNamedObject(
                controller, @"viewIfLoaded", nil, @"MRUVolumeView");
            uint64_t primarySlider = CNDCCExactNamedObject(
                volumeView, nil, @"_primarySlider", @"MRUContinuousSliderView");
            uint64_t glyph = CNDCCExactNamedObject(primarySlider, nil,
                @"_glyphPackageView", @"CCUICAPackageView");
            CNDCCAppendExactTarget(resolved, seen, controller, glyph,
                @"sound", @"ccuiPackageView", @"volume.primary.glyph",
                @[@"MediaControlsAudioModule._volumeViewController",
                  @"viewIfLoaded", @"_primarySlider", @"_glyphPackageView"],
                identifier, @[@"compactVolume", @"expandedVolume"], NO);
            continue;
        }

        if ([kind isEqualToString:@"focus"]) {
            uint64_t focusController = CNDCCExactNamedObject(module, nil,
                @"_moduleViewController", @"FCCCModuleViewController");
            uint64_t compactTemplate = CNDCCExactTemplateForController(
                focusController);
            CNDCCAppendExactTarget(resolved, seen, focusController,
                compactTemplate, @"focus", @"template", @"focus.compact",
                @[@"FCCCControlCenterModule._moduleViewController",
                  @"_templateView"], identifier, @[@"compactFocus"], NO);

            uint64_t picker = CNDCCExactNamedObject(module, nil,
                @"_activityPickerViewController",
                @"FCUIActivityPickerViewController");
            uint64_t managerObject = CNDCCExactNamedObject(module, nil,
                @"_activityManager", @"FCActivityManager");
            uint64_t modelDictionary = CNDCCExactNamedObject(
                managerObject, nil, @"_allActivitiesByIdentifier", nil);
            uint64_t list = CNDCCExactNamedObject(
                picker, @"viewIfLoaded", nil, @"FCUIActivityListView");
            uint64_t rows = CNDCCExactNamedObject(
                list, @"activityViews", nil, nil);
            for (NSNumber *number in CNDCCExactCollectionObjects(
                    rows, CNDCCViewCapPerController)) {
                uint64_t row = number.unsignedLongLongValue;
                if (!CNDCCExactClassMatches(row, @"FCUIActivityControl"))
                    continue;
                uint64_t identifierObject = CNDCCExactNamedObject(
                    row, @"activityIdentifier", nil, nil);
                NSString *activityIdentifier =
                    CNDCCExactStringObject(identifierObject);
                NSString *focusKind =
                    CNDCCExactFocusKind(activityIdentifier);
                uint64_t model = identifierObject && modelDictionary
                    ? r_msg2_main(modelDictionary, "objectForKey:",
                        identifierObject, 0, 0, 0) : 0;
                if (!focusKind.length || !r_is_objc_ptr(model)) continue;
                uint64_t imageView = CNDCCExactNamedObject(
                    row, nil, @"_activityIconImageView", @"UIImageView");
                uint64_t packageView = CNDCCExactNamedObject(
                    row, nil, @"_activityIconPackageView",
                    @"FCUICAPackageView");
                NSString *route = [@"focus.expanded."
                    stringByAppendingString:activityIdentifier];
                CNDCCAppendExactTarget(resolved, seen, picker, imageView,
                    focusKind, @"imageView", route,
                    @[@"FCCCControlCenterModule._activityPickerViewController",
                      @"viewIfLoaded.activityViews[activityIdentifier]",
                      @"_activityIconImageView"], identifier,
                    @[@"expandedFocus"], NO);
                CNDCCAppendExactTarget(resolved, seen, picker, packageView,
                    focusKind, @"suppressedView",
                    [route stringByAppendingString:@".stockPackage"],
                    @[@"FCCCControlCenterModule._activityPickerViewController",
                      @"viewIfLoaded.activityViews[activityIdentifier]",
                      @"_activityIconPackageView"], identifier,
                    @[@"expandedFocus"], NO);
            }
            continue;
        }

        if ([kind isEqualToString:@"nowPlaying"]) {
            uint64_t controller = CNDCCExactNamedObject(module,
                @"contentViewController", @"_contentViewController",
                @"MRUMediaControlsModuleViewController");
            uint64_t moduleView = CNDCCExactNamedObject(controller,
                @"viewIfLoaded", @"$__lazy_storage_$_contentView",
                @"MediaControls.MediaControlsModuleView");
            uint64_t sessions = CNDCCExactNamedObject(moduleView, nil,
                @"sessionsView",
                @"_TtGC13MediaControls23RoutePickerSessionsViewCS_30MediaControlsModuleSessionView_");
            uint64_t sessionsContent = CNDCCExactNamedObject(
                sessions, nil, @"contentView", @"UIView");
            NSArray<NSNumber *> *sessionViews = CNDCCExactDirectSubviews(
                sessionsContent, @"MediaControls.MediaControlsModuleSessionView");
            NSString *scope = container ? @"baseNowPlaying"
                : @"expandedNowPlaying";
            for (NSNumber *sessionNumber in sessionViews) {
                uint64_t session = sessionNumber.unsignedLongLongValue;
                uint64_t nowPlaying = CNDCCExactNamedObject(session, nil,
                    @"nowPlayingView",
                    @"MediaControls.MediaControlsModuleNowPlayingView");
                uint64_t transport = CNDCCExactNamedObject(nowPlaying, nil,
                    @"transportControlsView",
                    @"MediaControls.NowPlayingTransportControlsView");
                NSDictionary *buttons = @{
                    @"mediaPrevious": @"leftButton",
                    @"mediaPlayPause": @"centerButton",
                    @"mediaNext": @"rightButton",
                };
                for (NSString *transportKind in buttons) {
                    NSString *member = buttons[transportKind];
                    uint64_t button = CNDCCExactNamedObject(transport, nil,
                        member, @"MediaControls.TransportButton");
                    uint64_t packageView = CNDCCExactNamedObject(button, nil,
                        @"packageView", @"MediaControls.PackageView");
                    CNDCCAppendExactTarget(resolved, seen, controller,
                        packageView, transportKind, @"mruPackageView",
                        [@"media.transport."
                            stringByAppendingString:member],
                        @[@"MediaControlsModule._contentViewController",
                          @"$__lazy_storage_$_contentView", @"sessionsView",
                          @"contentView.directSessionSubview", @"nowPlayingView",
                          @"transportControlsView", member, @"packageView"],
                        identifier, @[scope], YES);
                }

                // The iOS 26 Swift route buttons expose their rendered symbol
                // through named upper/lower slots and a typed imageView field.
                // The VM trace proved both slots carry the exact
                // `airplay.audio` identity. Resolve those slots directly;
                // never infer them from position or recursively walk views.
                for (NSString *routeMember in @[
                        @"upperRouteButton", @"lowerRouteButton"]) {
                    uint64_t routeButton = CNDCCExactNamedObject(
                        nowPlaying, nil, routeMember,
                        @"MediaControls.MediaControlsModuleRouteButton");
                    uint64_t imageView = CNDCCExactNamedObject(
                        routeButton, nil, @"imageView", @"UIImageView");
                    CNDCCAppendExactTarget(resolved, seen, controller,
                        imageView, @"mediaAirPlay", @"imageView",
                        [@"media.route." stringByAppendingString:routeMember],
                        @[@"MediaControlsModule._contentViewController",
                          @"$__lazy_storage_$_contentView", @"sessionsView",
                          @"contentView.directSessionSubview", @"nowPlayingView",
                          routeMember, @"imageView"],
                        identifier, @[scope], NO);
                }
            }
        }
    }

    if (!remote_call_current_success() ||
        remote_call_current_pid() != targetPID) return @[];
    return resolved;
}

uint64_t CNDCCThemingResolveLiveTemplate(
    NSString *kind,
    NSDictionary<NSString *, id> **metadata)
{
    if (metadata) *metadata = nil;
    if (![kind isKindOfClass:NSString.class] || kind.length == 0 ||
        !remote_call_current_success()) return 0;

    NSDictionary *best = nil;
    for (NSDictionary *candidate in CNDCCThemingCopyResolvedLiveTemplates()) {
        if (![candidate[@"kind"] isEqualToString:kind]) continue;
        if (!best || [candidate[@"attachedToControlCenterWindow"] boolValue]) {
            best = candidate;
        }
    }
    if (metadata) *metadata = best;
    return [best[@"targetAddressValue"] unsignedLongLongValue];
}
