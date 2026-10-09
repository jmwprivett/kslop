#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <unistd.h>

#ifndef CND_CC_OWNER_OUTPUT_TOKEN
#define CND_CC_OWNER_OUTPUT_TOKEN ""
#endif
#ifndef CND_CC_OWNER_EXPECTED_PID
#define CND_CC_OWNER_EXPECTED_PID 0
#endif

/* VM-only ownership discovery. No control actions or artwork changes. The
 * default follows named ownership and controller containment. UIKit descendant
 * discovery requires an explicit request and marks every resulting edge. */
static NSString *const RequestPath = @"/var/tmp/cnd-cc-owner-request.json";
static NSString *const OutputDirectory = @"/var/tmp/cnd-cc-owner-traces";
static dispatch_source_t Timer;
static NSMutableDictionary *Metadata;
static BOOL Stopped;
static __weak id MainController;
static __weak id PagingController;
static __weak id PresentationController;
static void *(*SwiftReflect)(const void *);
extern void *CNDCCOwnerSwiftReflect(const void *object);
static NSMapTable *ViewOwners;
static __weak id BrightnessContainer;
static NSMutableDictionary *ReconstructionJournal;
static NSTimeInterval Deadline;

static NSString *Address(id object) {
    return [NSString stringWithFormat:@"%p", (__bridge void *)object];
}
static NSString *ClassName(id object) {
    return object ? NSStringFromClass(object_getClass(object)) : @"";
}
static BOOL Domain(NSString *name) {
    if ([name isEqual:@"UIImage"] || [name hasPrefix:@"_UIImage"] || [name hasPrefix:@"CUI"] ||
        [name isEqual:@"NSBundle"]) return YES;
    for (NSString *prefix in @[@"CC", @"CH", @"MR", @"MediaControls", @"DND",
         @"FC", @"_FC", @"CAPackage", @"CAStateController", @"ControlCenterUI.", @"FocusUI.",
         @"_TtGC13MediaControls", @"RPControlCenter", @"RPCC", @"RPVideoEffects", @"MTCCTimer", @"MPAVAirPlayMirroring",
         @"SBHReusableViewMap", @"SBControlCenter", @"SBCoverSheet", @"SpringBoard", @"CSCoverSheet"])
        if ([name hasPrefix:prefix]) return YES;
    return NO;
}
static BOOL Scalar(id object) {
    return [object isKindOfClass:NSString.class] ||
        [object isKindOfClass:NSNumber.class] ||
        [object isKindOfClass:NSURL.class] || [object isKindOfClass:NSUUID.class];
}
static id ScalarValue(id object) {
    if ([object isKindOfClass:NSURL.class]) return [(NSURL *)object absoluteString];
    if ([object isKindOfClass:NSUUID.class]) return [(NSUUID *)object UUIDString];
    return object;
}
static BOOL IdentityName(NSString *name) {
    NSString *lower = name.lowercaseString;
    return [lower containsString:@"identifier"] || [lower containsString:@"identity"] ||
        [lower containsString:@"uuid"] || [lower containsString:@"symbol"] ||
        [lower containsString:@"package"] || [lower containsString:@"glyphstate"] ||
        [lower containsString:@"statename"] || [lower containsString:@"url"] ||
        [lower containsString:@"kind"] || [lower containsString:@"bundlename"];
}
static NSDictionary *Contract(Class cls, NSString *name, BOOL classMethod) {
    Method method = classMethod ? class_getClassMethod(cls, NSSelectorFromString(name))
        : class_getInstanceMethod(cls, NSSelectorFromString(name));
    if (!method) return @{@"available": @NO, @"selector": name};
    char *result = method_copyReturnType(method);
    BOOL getter = method_getNumberOfArguments(method) == 2 && result && result[0] == '@';
    free(result);
    return @{@"available": @YES, @"selector": name,
        @"types": @(method_getTypeEncoding(method)),
        @"argumentCount": @(method_getNumberOfArguments(method)),
        @"objectGetterABI": @(getter), @"classMethod": @(classMethod)};
}
static id Getter(id object, NSString *name) {
    if (!object || ![Contract(object_getClass(object), name, NO)[@"objectGetterABI"] boolValue]) return nil;
    @try { return ((id (*)(id, SEL))objc_msgSend)(object, NSSelectorFromString(name)); }
    @catch (__unused NSException *exception) { return nil; }
}
#include "cnd_cc_resource_provenance.inc"
static NSArray *Getters(void) {
    return @[@"windows", @"rootViewController", @"childViewControllers", @"presentedViewController",
        @"coverSheetViewController", @"coverSheetSlidingViewController", @"controlCenterController",
        @"viewController", @"moduleInstanceManager", @"moduleSettingsManager", @"moduleRepository",
        @"moduleRegistry", @"moduleInstances", @"moduleInstancesByIdentifier", @"moduleControllers",
        @"moduleViewControllers", @"moduleContainers", @"modules", @"registeredModules",
        @"module", @"moduleInstance", @"moduleIdentifier", @"identifier", @"uniqueIdentifier",
        @"bundleIdentifier", @"applicationBundleIdentifier", @"extensionBundleIdentifier",
        @"containerBundleIdentifier", @"deviceIdentifier", @"controlIdentifier", @"controlIdentity",
        @"moduleDescription", @"moduleDescriptor", @"descriptor", @"controlDescriptor", @"control",
        @"provider", @"packageProvider", @"glyphProvider", @"imageProvider", @"contentProvider",
        @"configurationProvider", @"contentViewController", @"moduleContentViewController",
        @"contentContainerViewController", @"moduleContainerViewController", @"expandedViewController",
        @"expandedContentViewController", @"viewIfLoaded", @"button", @"contentView", @"customGlyphView",
        @"controlIconView", @"brightnessSlider", @"volumeSlider", @"slider", @"sliderView",
        @"nowPlayingViewController", @"mediaControlsViewController", @"transportControlsViewController",
        @"transportControlsView", @"transportControlView", @"transportControls", @"playbackControlsView",
        @"nowPlayingView", @"sessionView", @"controlsView", @"previousButton", @"skipBackwardButton",
        @"backwardButton", @"playPauseButton", @"playPauseStopButton", @"nextButton", @"skipForwardButton",
        @"forwardButton", @"leadingButton", @"trailingButton", @"leftButton", @"rightButton", @"centerButton",
        @"packageView", @"package", @"packageDescription", @"glyphPackageDescription", @"glyphView",
        @"imageView", @"rootLayer", @"stateController", @"stateName", @"glyphState", @"packageName",
        @"packageURL", @"URL", @"url", @"packageState", @"packageStateName", @"image", @"glyphImage",
        @"imageAsset", @"symbolConfiguration", @"systemSymbolName", @"_systemSymbolName",
        @"ccui_systemImageName", @"artworkCatalogBackingFileURL", @"renditionName", @"assetName", @"name",
        @"bundleURL", @"resourceURL", @"bundlePath", @"resourcePath",
        @"focusViewController", @"focusModeViewController", @"activityViewController",
        @"activityControlsViewController", @"activityControlsView", @"activityControls", @"activityViews",
        @"activities", @"focusModes", @"modes", @"rows", @"items", @"activity", @"representedActivity",
        @"focusActivity", @"focusMode", @"mode", @"model", @"configuration", @"activityConfiguration",
        @"modeConfiguration", @"settings", @"icon", @"iconView", @"activityIdentifier", @"modeIdentifier",
        @"systemIdentifier", @"semanticIdentifier", @"UUID", @"uuid", @"symbolName", @"iconSymbolName",
        @"glyphName", @"activityType", @"modeType", @"controlDescriptorProvider", @"controlExtensionProvider",
        @"controlHost", @"controlInstance", @"rootFolderController", @"iconViewMap", @"iconViewProvider",
        @"iconImageViewControllerCache", @"expandedViewControllers", @"controlIntentStore",
        @"activityManager", @"moduleView", @"transportView", @"iconViewController", @"metadata",
        @"viewModel", @"sb_viewModel",
        @"moduleBundleURL", @"associatedBundleIdentifier", @"moduleContainerBundleIdentifier",
        @"parityControlKind", @"parityControlExtensionIdentifier", @"parityControlContainerBundleIdentifier",
        @"identity", @"contentModule", @"activityDescription", @"activitySymbolImageName", @"activityUniqueIdentifier",
        @"activityIcon", @"activityStore", @"stateNames"];
}
static NSDictionary *ClassMetadata(Class cls) {
    NSString *key = NSStringFromClass(cls);
    if (Metadata[key]) return Metadata[key];
    NSMutableArray *methods = [NSMutableArray array], *ivars = [NSMutableArray array];
    NSMutableDictionary *contracts = [NSMutableDictionary dictionary];
    for (NSString *name in Getters()) {
        NSDictionary *contract = Contract(cls, name, NO);
        if ([contract[@"available"] boolValue]) contracts[name] = contract;
    }
    for (Class owner = cls; owner && owner != NSObject.class && owner != UIView.class &&
         owner != UIViewController.class && owner != CALayer.class && owner != UIControl.class &&
         owner != UIApplication.class; owner = class_getSuperclass(owner)) {
        unsigned count = 0;
        Ivar *list = class_copyIvarList(owner, &count);
        for (unsigned i = 0; i < count; i++) {
            const char *type = ivar_getTypeEncoding(list[i]);
            [ivars addObject:@{@"name": @(ivar_getName(list[i])), @"types": type ? @(type) : @"",
                @"offset": @(ivar_getOffset(list[i])), @"ownerClass": NSStringFromClass(owner),
                @"objectSlot": @(type && type[0] == '@' && type[1] != '?')}];
        }
        free(list);
        for (unsigned kind = 0; kind < 2; kind++) {
            Method *members = class_copyMethodList(kind ? object_getClass(owner) : owner, &count);
            for (unsigned i = 0; i < count; i++)
                [methods addObject:@{@"selector": NSStringFromSelector(method_getName(members[i])),
                    @"types": @(method_getTypeEncoding(members[i])),
                    @"argumentCount": @(method_getNumberOfArguments(members[i])),
                    @"ownerClass": NSStringFromClass(owner), @"classMethod": @(kind == 1),
                    @"invoked": @NO}];
            free(members);
        }
    }
    NSDictionary *row = @{@"className": key, @"methods": methods, @"ivars": ivars, @"contracts": contracts};
    Metadata[key] = row;
    return row;
}
static void Capture(NSString *phase, BOOL discovery) {
    ResourceSuppress(YES);
    NSMutableArray *queue = [NSMutableArray array], *edges = [NSMutableArray array],
        *objects = [NSMutableArray array], *roots = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set], *usedClasses = [NSMutableSet set];
    NSMutableDictionary *depths = [NSMutableDictionary dictionary];
    __block BOOL collectionLimit = NO, depthLimit = NO;
    void (^enqueue)(id, NSUInteger) = ^(id object, NSUInteger depth) {
        if (!object || Scalar(object)) return;
        if (depth > 24) { depthLimit = YES; return; }
        if (queue.count >= 8192) return;
        NSString *address = Address(object);
        if ([seen containsObject:address]) return;
        [seen addObject:address]; depths[address] = @(depth); [queue addObject:object];
    };
    void (^edge)(id, id, NSString *, NSString *, NSDictionary *, NSUInteger) =
    ^(id from, id to, NSString *kind, NSString *name, NSDictionary *extra, NSUInteger depth) {
        if (!to || edges.count >= 40000) return;
        NSMutableDictionary *row = [@{@"from": Address(from), @"to": Address(to),
            @"toClass": ClassName(to), @"kind": kind, @"name": name} mutableCopy];
        if (Scalar(to)) row[@"value"] = ScalarValue(to);
        [row addEntriesFromDictionary:extra ?: @{}];
        row[@"name"] = name; row[@"kind"] = kind;
        [edges addObject:row];
        enqueue(to, depth);
    };
    id application = UIApplication.sharedApplication;
    [roots addObject:@{@"address": Address(application), @"className": ClassName(application),
        @"acquisition": @"UIApplication.sharedApplication"}]; enqueue(application, 0);
    for (NSArray *root in @[@[@"SBControlCenterController", @"sharedInstance"],
         @[@"CCUIModuleInstanceManager", @"sharedInstance"],
         @[@"CCUIModuleSettingsManager", @"sharedInstance"], @[@"CCUIModuleRepository", @"sharedInstance"]]) {
        Class cls = NSClassFromString(root[0]);
        NSDictionary *contract = cls ? Contract(cls, root[1], YES) : @{};
        if (![contract[@"objectGetterABI"] boolValue]) continue;
        id object = ((id (*)(id, SEL))objc_msgSend)(cls, NSSelectorFromString(root[1]));
        if (object) { [roots addObject:@{@"address": Address(object), @"className": ClassName(object),
            @"acquisition": [root componentsJoinedByString:@"."], @"contract": contract}]; enqueue(object, 0); }
    }
    NSTimeInterval start = NSProcessInfo.processInfo.systemUptime;
    for (NSUInteger i = 0; i < queue.count && NSProcessInfo.processInfo.systemUptime - start < 20; i++) {
        id object = queue[i]; NSString *className = ClassName(object), *address = Address(object);
        if ([className isEqual:@"CCUIMainViewController"]) MainController = object;
        if ([className isEqual:@"CCUIPagingViewController"]) PagingController = object;
        if ([className isEqual:@"SBControlCenterController"]) PresentationController = object;
        if ([className isEqual:@"CCUIDisplayModuleViewController"] || [className isEqual:@"FCUIActivityPickerViewController"])
            [ViewOwners setObject:object forKey:className];
        if ([className isEqual:@"CCUIContentModuleContainerViewController"] &&
            [Getter(object, @"moduleIdentifier") isEqual:@"com.apple.control-center.DisplayModule"]) BrightnessContainer = object;
        NSUInteger depth = [depths[address] unsignedIntegerValue];
        NSMutableDictionary *row = [@{@"address": address, @"className": className, @"depth": @(depth),
            @"identities": [NSMutableDictionary dictionary]} mutableCopy];
        if ([className isEqual:@"SBControlCenterController"] &&
            [Contract(object_getClass(object), @"isVisible", NO)[@"types"] isEqual:@"B16@0:8"]) {
            BOOL visible = ((BOOL (*)(id, SEL))objc_msgSend)(object, NSSelectorFromString(@"isVisible"));
            row[@"readOnlyScalars"] = @{@"isVisible": @(visible), @"identityEvidence": @NO};
        }
        [objects addObject:row];
        @try {
            if ([object isKindOfClass:NSDictionary.class]) {
                row[@"collectionCount"] = @([object count]);
                row[@"collectionTruncated"] = @([object count] > 1024);
                if ([object count] > 1024) collectionLimit = YES;
                NSUInteger n = 0;
                for (id key in object) { if (++n > 1024) break;
                    id value = [object objectForKey:key];
                    edge(object, value, @"dictionary-member", @"objectForKey:",
                        @{@"machineKey": Scalar(key) ? ScalarValue(key) : ClassName(key)}, depth + 1); }
                continue;
            }
            if ([object isKindOfClass:NSArray.class] || [object isKindOfClass:NSSet.class] ||
                [object isKindOfClass:NSOrderedSet.class] || [object isKindOfClass:NSHashTable.class]) {
                row[@"collectionCount"] = @([object count]);
                row[@"collectionTruncated"] = @([object count] > 1024);
                if ([object count] > 1024) collectionLimit = YES;
                NSUInteger n = 0;
                for (id value in object) { if (++n > 1024) break;
                    edge(object, value, @"collection-member", @"member", @{@"identityUsesPosition": @NO}, depth + 1); }
                continue;
            }
            BOOL domain = Domain(className);
            if (domain && SwiftReflect && ([className containsString:@"."] || [className hasPrefix:@"_TtGC13MediaControls"] ||
                [className hasPrefix:@"CHUIS"] ||
                [className isEqual:@"MRUMediaControlsModuleViewController"] ||
                [className isEqual:@"CCUIPagingViewController"] ||
                [className isEqual:@"CCUIControlHostViewController"])) {
                void *pointer = SwiftReflect((__bridge const void *)object);
                NSDictionary *reflection = pointer ? CFBridgingRelease(pointer) : nil;
                NSMutableArray *pending = [NSMutableArray arrayWithArray:reflection[@"fields"] ?: @[]];
                NSMutableArray *fields = [NSMutableArray array];
                for (NSUInteger j = 0; j < pending.count && j < 512; j++) {
                    NSDictionary *field = pending[j];
                    id value = field[@"object"];
                    NSMutableDictionary *copy = [field mutableCopy];
                    [copy removeObjectForKey:@"object"]; [copy removeObjectForKey:@"children"];
                    if (value) {
                        edge(object, value, @"swift-field", field[@"path"], copy, depth + 1);
                        copy[@"objectAddress"] = Address(value); copy[@"objectClass"] = ClassName(value);
                        // Swift ivars often expose their names and offsets with
                        // empty ObjC encodings. Validate only immediate object
                        // fields already proven by typed Swift reflection.
                        if ([field[@"path"] isEqual:field[@"name"]]) {
                            Ivar ivar = class_getInstanceVariable(object_getClass(object), [field[@"name"] UTF8String]);
                            if (ivar) {
                                id slot = object_getIvar(object, ivar);
                                copy[@"namedSlotVerified"] = @(slot == value);
                                copy[@"runtimeOffset"] = @(ivar_getOffset(ivar));
                                if (slot == value) edge(object, value, @"verified-swift-object-ivar", field[@"name"],
                                    @{@"offset": @(ivar_getOffset(ivar)), @"expectedClass": ClassName(value),
                                      @"verification": @"dynamic named slot equals typed Swift reflection"}, depth + 1);
                            }
                        }
                    }
                    [fields addObject:copy];
                    [pending addObjectsFromArray:field[@"children"] ?: @[]];
                }
                row[@"swiftFields"] = fields;
            }
            if (domain) {
                NSDictionary *metadata = ClassMetadata(object_getClass(object)); [usedClasses addObject:className];
                for (NSDictionary *slot in metadata[@"ivars"]) {
                    if (![slot[@"objectSlot"] boolValue]) continue;
                    NSString *name = slot[@"name"];
                    if ([name isEqual:@"_subviews"] || [name isEqual:@"_accessibilityElements"] ||
                        [name containsString:@"delegate"] || [name containsString:@"Delegate"]) continue;
                    if ([className isEqual:@"SpringBoard"] && ![name.lowercaseString containsString:@"coversheet"] &&
                        ![name.lowercaseString containsString:@"controlcenter"]) continue;
                    Ivar ivar = class_getInstanceVariable(object_getClass(object), name.UTF8String);
                    id value = ivar ? object_getIvar(object, ivar) : nil;
                    edge(object, value, @"ivar", name, slot, depth + 1);
                    if (Scalar(value) && IdentityName(name)) row[@"identities"][name] = ScalarValue(value);
                }
            }
            if (domain || [object isKindOfClass:UIWindow.class] || [object isKindOfClass:UIViewController.class]) {
                for (NSString *name in Getters()) {
                    if (!domain && ![@[@"rootViewController", @"childViewControllers", @"presentedViewController"] containsObject:name]) continue;
                    id value = Getter(object, name);
                    if (!value) continue;
                    edge(object, value, @"getter", name, Contract(object_getClass(object), name, NO), depth + 1);
                    if (Scalar(value) && IdentityName(name)) row[@"identities"][name] = ScalarValue(value);
                }
            }
            if (discovery && [object isKindOfClass:UIView.class]) {
                UIView *view = object;
                edge(object, view.subviews, @"recursive-discovery", @"subviews",
                    @{@"productionRoute": @NO, @"explicitDiscoveryMode": @YES}, depth + 1);
            }
        } @catch (NSException *exception) { row[@"exception"] = exception.name; }
    }
    NSMutableArray *metadataRows = [NSMutableArray array];
    for (NSString *name in [[usedClasses allObjects] sortedArrayUsingSelector:@selector(compare:)])
        [metadataRows addObject:Metadata[name]];
    NSMutableArray *optionalClasses = [NSMutableArray array], *providers = [NSMutableArray array];
    for (NSString *name in @[@"MRUAssetsProvider", @"FlashlightModule", @"CCUIFlashlightModuleViewController",
         @"SBUIFlashlightController", @"CHUISControlInstance", @"MTCCTimerViewController",
         @"RPControlCenterMenuModuleViewController", @"FCUIActivityIcon"]) {
        Class cls = NSClassFromString(name);
        [optionalClasses addObject:@{@"className": name, @"loaded": @(cls != Nil),
            @"metadata": cls ? ClassMetadata(cls) : @{}}];
    }
    Class assets = NSClassFromString(@"MRUAssetsProvider");
    for (NSString *selector in @[@"forwardBackwardPackageName", @"playPauseStopPackageName", @"volumePackageName"]) {
        NSDictionary *contract = assets ? Contract(assets, selector, YES) : @{};
        id value = [contract[@"objectGetterABI"] boolValue] ?
            ((id (*)(id, SEL))objc_msgSend)(assets, NSSelectorFromString(selector)) : nil;
        [providers addObject:@{@"className": @"MRUAssetsProvider", @"contract": contract,
            @"value": Scalar(value) ? ScalarValue(value) : @"", @"invoked": @(value != nil)}];
    }
    NSDictionary *result = @{@"schemaVersion": @1, @"pid": @(getpid()), @"phase": phase,
        @"capturedAt": NSISO8601DateFormatter.new ? [NSISO8601DateFormatter.new stringFromDate:NSDate.date] : @"",
        @"mode": discovery ? @"explicit-vm-recursive-discovery" : @"vm-named-ownership",
        @"usesLabelsAsIdentity": @NO, @"usesGeometryAsIdentity": @NO, @"controlActions": @0,
        @"artworkWrites": @0, @"runtimeMetadataWrites": @(ResourceMetadataWrites), @"roots": roots, @"objects": objects,
        @"edges": edges, @"classContracts": metadataRows, @"objectBudget": @8192, @"edgeBudget": @40000,
        @"depthBudget": @24, @"seconds": @(NSProcessInfo.processInfo.systemUptime - start),
        @"optionalClassInventory": optionalClasses, @"staticProviderGetters": providers,
        @"resourceProvenanceTrace": ResourceTraceReport(),
        @"collectionMemberBudget": @1024, @"collectionLimitReached": @(collectionLimit), @"depthLimitReached": @(depthLimit),
        @"truncated": @(objects.count < queue.count || queue.count >= 8192 || edges.count >= 40000 || collectionLimit || depthLimit)};
    NSData *data = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:nil];
    [data writeToFile:[OutputDirectory stringByAppendingPathComponent:[phase stringByAppendingString:@".json"]] atomically:YES];
    ResourceSuppress(NO);
}
static void Drive(NSDictionary *request) {
    /* Explicit VM driver, separate from read-only captures. Only presentation
     * and container invalidation are permitted; no module action selectors. */
    NSString *action = request[@"action"], *selector = @"";
    id target = nil;
    if ([action isEqual:@"present"]) { target = PresentationController; selector = @"presentAnimated:completion:"; }
    if ([action isEqual:@"dismiss"]) { target = PresentationController; selector = @"dismissAnimated:"; }
    if ([action isEqual:@"expand"]) { target = MainController; selector = @"expandModuleWithIdentifier:"; }
    if ([action isEqual:@"collapse"]) { target = MainController; selector = @"dismissExpandedModuleAnimated:completion:"; }
    if ([action isEqual:@"invalidate-container"]) {
        target = PagingController; selector = @"invalidateContainerViewsForPlatterTreatmentWithIdentifier:";
    }
    Method method = target ? class_getInstanceMethod(object_getClass(target), NSSelectorFromString(selector)) : NULL;
    NSString *types = method ? @(method_getTypeEncoding(method)) : @"";
    BOOL invoked = NO;
    NSMutableArray *reconstructions = [NSMutableArray array];
    NSArray *resourceRestoration = @[];
    ResourceTracePhase(request[@"phase"]);
    @try {
        if ([action isEqual:@"resource-start"]) {
            ResourceTraceStart(request[@"phase"] ?: @"resource-start"); invoked = ResourceActive;
            selector = @"VM resource observation enabled with checked stock method ABIs";
        } else if ([action isEqual:@"resource-stop"]) {
            resourceRestoration = ResourceTraceStop(); invoked = !ResourceActive;
            selector = @"VM resource observation restored";
        } else if ([action isEqual:@"restore-brightness-view"]) {
            UIViewController *owner = [ViewOwners objectForKey:@"CCUIDisplayModuleViewController"];
            id original = Getter(BrightnessContainer, @"contentView");
            Ivar slider = owner ? class_getInstanceVariable(object_getClass(owner), "_sliderView") : NULL;
            if (owner && [ClassName(original) isEqual:@"CCUIContinuousSliderView"] && slider &&
                strcmp(ivar_getTypeEncoding(slider), "@\"CCUIContinuousSliderView\"") == 0) {
                owner.view = original; object_setIvar(owner, slider, original); invoked = YES;
            }
            selector = @"container.contentView -> controller.view/_sliderView";
        } else if ([action isEqual:@"reconstruct-views"]) {
            NSString *identifier = request[@"moduleIdentifier"];
            NSString *ownerName = [identifier isEqual:@"com.apple.control-center.DisplayModule"] ? @"CCUIDisplayModuleViewController" :
                ([identifier isEqual:@"com.apple.FocusUIModule"] ? @"FCUIActivityPickerViewController" : nil);
            UIViewController *owner = ownerName ? [ViewOwners objectForKey:ownerName] : nil;
            if (owner && [Contract(object_getClass(owner), @"setView:", NO)[@"types"] isEqual:@"v24@0:8@16"] &&
                [Contract(object_getClass(owner), @"loadViewIfNeeded", NO)[@"types"] isEqual:@"v16@0:8"]) {
                UIView *oldView = owner.viewIfLoaded;
                if (oldView && !ReconstructionJournal[ownerName]) ReconstructionJournal[ownerName] = @{@"owner": owner, @"view": oldView};
                id package = Getter(oldView, @"glyphPackageDescription"), state = Getter(oldView, @"glyphState");
                owner.view = nil; [owner loadViewIfNeeded];
                UIView *newView = owner.viewIfLoaded;
                if (package && [Contract(object_getClass(newView), @"setGlyphPackageDescription:", NO)[@"types"] isEqual:@"v24@0:8@16"])
                    ((void (*)(id, SEL, id))objc_msgSend)(newView, NSSelectorFromString(@"setGlyphPackageDescription:"), package);
                if (state && [Contract(object_getClass(newView), @"setGlyphState:", NO)[@"types"] isEqual:@"v24@0:8@16"])
                    ((void (*)(id, SEL, id))objc_msgSend)(newView, NSSelectorFromString(@"setGlyphState:"), state);
                invoked = newView && newView != oldView;
                [reconstructions addObject:@{@"controller": Address(owner), @"controllerClass": ownerName,
                    @"oldView": Address(oldView), @"newView": Address(newView), @"stateAction": @NO,
                    @"resetTypes": @"v24@0:8@16", @"loadTypes": @"v16@0:8"}];
                if (!invoked) owner.view = oldView;
            }
            selector = @"setView:nil -> loadViewIfNeeded";
        } else if ([types isEqual:@"v28@0:8B16@?20"] &&
            ([action isEqual:@"present"] || [action isEqual:@"collapse"])) {
            ((void (*)(id, SEL, BOOL, id))objc_msgSend)(target, NSSelectorFromString(selector), YES, nil); invoked = YES;
        } else if ([types isEqual:@"v20@0:8B16"] && [action isEqual:@"dismiss"]) {
            ((void (*)(id, SEL, BOOL))objc_msgSend)(target, NSSelectorFromString(selector), YES); invoked = YES;
        } else if ([types isEqual:@"v24@0:8@16"] &&
                   ([action isEqual:@"expand"] || [action isEqual:@"invalidate-container"]) &&
                   [request[@"moduleIdentifier"] isKindOfClass:NSString.class] &&
                   [request[@"moduleIdentifier"] hasPrefix:@"com.apple."]) {
            ((void (*)(id, SEL, id))objc_msgSend)(target, NSSelectorFromString(selector), request[@"moduleIdentifier"]); invoked = YES;
        }
    } @catch (__unused NSException *exception) { invoked = NO; }
    NSDictionary *event = @{@"action": action ?: @"", @"selector": selector, @"types": types,
        @"targetClass": ClassName(target), @"target": Address(target), @"pid": @(getpid()),
        @"moduleIdentifier": request[@"moduleIdentifier"] ?: @"", @"invoked": @(invoked),
        @"controlActions": @0, @"presentationOnly": @YES, @"reconstructions": reconstructions,
        @"resourceObservationActive": @(ResourceActive), @"resourceRestoration": resourceRestoration};
    NSData *data = [NSJSONSerialization dataWithJSONObject:event options:NSJSONWritingPrettyPrinted error:nil];
    [data writeToFile:[OutputDirectory stringByAppendingPathComponent:@"driver-latest.json"] atomically:YES];
}
__attribute__((constructor)) static void Start(void) {
    if (CND_CC_OWNER_EXPECTED_PID && getpid() != CND_CC_OWNER_EXPECTED_PID) return;
    if (![NSProcessInfo.processInfo.processName isEqualToString:@"SpringBoard"]) return;
    int64_t (*consume)(const char *) = dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    if (consume && CND_CC_OWNER_OUTPUT_TOKEN[0]) (void)consume(CND_CC_OWNER_OUTPUT_TOKEN);
    SwiftReflect = CNDCCOwnerSwiftReflect;
    dispatch_async(dispatch_get_main_queue(), ^{
        Metadata = [NSMutableDictionary dictionary];
        ViewOwners = [NSMapTable strongToWeakObjectsMapTable];
        ReconstructionJournal = [NSMutableDictionary dictionary];
        Deadline = NSProcessInfo.processInfo.systemUptime + 1800;
        [NSFileManager.defaultManager createDirectoryAtPath:OutputDirectory withIntermediateDirectories:YES attributes:nil error:nil];
        Capture(@"initial", NO);
        Timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
        dispatch_source_set_timer(Timer, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), NSEC_PER_SEC, NSEC_PER_SEC / 10);
        dispatch_source_set_event_handler(Timer, ^{
            if (Stopped) return;
            NSData *data = [NSData dataWithContentsOfFile:RequestPath];
            if (!data && NSProcessInfo.processInfo.systemUptime < Deadline) return;
            if (data) [NSFileManager.defaultManager removeItemAtPath:RequestPath error:nil];
            NSDictionary *request = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : @{@"action": @"stop"};
            if ([request[@"action"] isEqual:@"stop"]) {
                NSArray *resourceRestoration = ResourceTraceStop();
                NSData *restorationData = [NSJSONSerialization dataWithJSONObject:resourceRestoration options:NSJSONWritingPrettyPrinted error:nil];
                [restorationData writeToFile:[OutputDirectory stringByAppendingPathComponent:@"resource-restoration.json"] atomically:YES];
                for (NSString *name in ReconstructionJournal) {
                    UIViewController *owner = ReconstructionJournal[name][@"owner"];
                    UIView *view = ReconstructionJournal[name][@"view"]; owner.view = view;
                    if ([name isEqual:@"CCUIDisplayModuleViewController"]) {
                        Ivar slider = class_getInstanceVariable(object_getClass(owner), "_sliderView");
                        if (slider && strcmp(ivar_getTypeEncoding(slider), "@\"CCUIContinuousSliderView\"") == 0) object_setIvar(owner, slider, view);
                    }
                }
                ReconstructionJournal = nil;
                Stopped = YES; dispatch_source_cancel(Timer); Timer = nil; Metadata = nil; ViewOwners = nil;
                [@"stopped; reconstruction journal restored; no method hooks or retained targets\n" writeToFile:[OutputDirectory stringByAppendingPathComponent:@"stopped.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
                return;
            }
            NSString *phase = request[@"phase"];
            NSCharacterSet *unsafe = [[NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"] invertedSet];
            if ([request[@"action"] isEqual:@"snapshot"] && [phase isKindOfClass:NSString.class] &&
                phase.length && phase.length < 96 && [phase rangeOfCharacterFromSet:unsafe].location == NSNotFound)
                Capture(phase, [request[@"recursiveDiscovery"] boolValue]);
            else Drive(request);
        });
        dispatch_resume(Timer);
    });
}
