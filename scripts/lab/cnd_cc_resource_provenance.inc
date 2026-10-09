/* Bounded VM-only observation of stock Control Center resource factories.
 * Inputs and return values are forwarded unchanged. No artwork is installed.
 * This is activated by an explicit resource-start request and restored on stop.
 * No private Swift calling convention or guessed object layout is used. */
#ifndef CND_CC_RESOURCE_PACKAGE_CLASS
#define CND_CC_RESOURCE_PACKAGE_CLASS @"CAPackage"
#endif
typedef struct {
    Class owner;
    SEL selector;
    Method method;
    IMP original;
    IMP observer;
    BOOL classMethod;
} CNDResourceMethod;
static CNDResourceMethod ResourceMethods[64];
static NSUInteger ResourceMethodCount;
static NSRecursiveLock *ResourceLock;
static NSMutableArray *ResourceEvents, *ResourceContracts;
static NSString *ResourcePhase;
static BOOL ResourceActive;
static NSUInteger ResourceSequence, ResourceDropped, ResourceMetadataWrites;
static NSString *const ResourceStackKey = @"CNDCCVMResourceStack";
static NSString *const ResourceSuppressionKey = @"CNDCCVMResourceSuppression";

static void ResourceSuppress(BOOL suppress) {
    NSMutableDictionary *local = NSThread.currentThread.threadDictionary;
    NSUInteger count = [local[ResourceSuppressionKey] unsignedIntegerValue];
    local[ResourceSuppressionKey] = @(suppress ? count + 1 : (count ? count - 1 : 0));
}
static NSDictionary *ResourceObject(id object) {
    if (!object) return @{@"nil": @YES};
    if (Scalar(object)) return @{@"className": ClassName(object), @"value": ScalarValue(object)};
    NSMutableDictionary *row = [@{@"address": Address(object), @"className": ClassName(object)} mutableCopy];
    for (NSString *name in @[@"activityIdentifier", @"activityUniqueIdentifier", @"activitySymbolImageName",
                             @"packageURL", @"packageName", @"symbolName", @"identifier", @"kind",
                             @"bundleIdentifier", @"extensionBundleIdentifier", @"containerBundleIdentifier",
                             @"deviceIdentifier"]) {
        id value = Getter(object, name);
        if (value && Scalar(value)) row[name] = ScalarValue(value);
    }
    if ([object isKindOfClass:NSBundle.class]) row[@"bundleURL"] = [(NSBundle *)object bundleURL].absoluteString ?: @"";
    if ([ClassName(object) isEqual:CND_CC_RESOURCE_PACKAGE_CLASS]) {
        id layer = Getter(object, @"rootLayer");
        if (layer) row[@"rootLayer"] = @{@"address": Address(layer), @"className": ClassName(layer)};
    }
    if ([ClassName(object) isEqual:@"FCUICAPackageView"]) {
        Ivar ivar = class_getInstanceVariable(object_getClass(object), "_rootLayer");
        const char *type = ivar ? ivar_getTypeEncoding(ivar) : NULL;
        id layer = type && strcmp(type, "@\"CALayer\"") == 0 ? object_getIvar(object, ivar) : nil;
        if (layer) row[@"_rootLayer"] = @{@"address": Address(layer), @"className": ClassName(layer)};
    }
    /* Named Focus slots correlate factory results with the actual icon receiver. */
    if ([ClassName(object) isEqual:@"FCUIActivityControl"]) {
        for (NSString *name in @[@"_activityIconPackageView", @"_activityIconImageView", @"_activityDescription"]) {
            Ivar ivar = class_getInstanceVariable(object_getClass(object), name.UTF8String);
            const char *type = ivar ? ivar_getTypeEncoding(ivar) : NULL;
            if (!type || type[0] != '@' || type[1] == '?') continue;
            id value = object_getIvar(object, ivar);
            if (value) row[name] = @{@"address": Address(value), @"className": ClassName(value)};
        }
    }
    return row;
}
static IMP ResourceOriginal(id object, SEL selector) {
    BOOL classMethod = object_isClass(object);
    Class cls = classMethod ? object : object_getClass(object);
    for (NSUInteger i = 0; i < ResourceMethodCount; i++) {
        CNDResourceMethod entry = ResourceMethods[i];
        if (entry.selector == selector && entry.classMethod == classMethod &&
            (cls == entry.owner || (!classMethod && [object isKindOfClass:entry.owner]))) return entry.original;
    }
    return NULL;
}
static BOOL ResourceDomain(id object) {
    NSString *name = object_isClass(object) ? NSStringFromClass(object) : ClassName(object);
    return [name hasPrefix:@"FCUI"] || [name hasPrefix:@"MRU"] ||
        [name hasPrefix:@"MediaControls"] || [name hasPrefix:@"CHS"] ||
        [name hasPrefix:@"CHUIS"] || [name hasPrefix:@"CCUIControl"] ||
        [name isEqual:@"CCUICAPackageDescription"];
}
static BOOL ResourceShouldObserve(id object) {
    NSMutableDictionary *local = NSThread.currentThread.threadDictionary;
    return ResourceActive && ![local[ResourceSuppressionKey] unsignedIntegerValue] &&
        (ResourceDomain(object) || [local[ResourceStackKey] count]);
}
static NSMutableDictionary *ResourceBeginScoped(id object, SEL selector, NSArray *arguments, BOOL relevantURL) {
    NSMutableDictionary *local = NSThread.currentThread.threadDictionary;
    NSMutableArray *stack = local[ResourceStackKey];
    BOOL domain = ResourceDomain(object);
    if (!ResourceActive || [local[ResourceSuppressionKey] unsignedIntegerValue] || (!domain && !stack.count && !relevantURL)) return nil;
    ResourceSuppress(YES);
    NSMutableDictionary *event = [NSMutableDictionary dictionary];
    [ResourceLock lock];
    event[@"sequence"] = @(++ResourceSequence);
    event[@"phase"] = ResourcePhase ?: @"unlabelled";
    [ResourceLock unlock];
    event[@"selector"] = NSStringFromSelector(selector);
    event[@"receiver"] = ResourceObject(object);
    event[@"classMethod"] = @(object_isClass(object));
    event[@"mainThread"] = @(NSThread.isMainThread);
    event[@"parentSequence"] = stack.count ? stack.lastObject[@"sequence"] : @0;
    event[@"depth"] = @(stack.count);
    event[@"startedAtUptime"] = @(NSProcessInfo.processInfo.systemUptime);
    event[@"arguments"] = arguments ?: @[];
    event[@"matchedCanonicalResourceURL"] = @(relevantURL);
    if (!stack) { stack = [NSMutableArray array]; local[ResourceStackKey] = stack; }
    [stack addObject:event];
    ResourceSuppress(NO);
    return event;
}
static NSMutableDictionary *ResourceBegin(id object, SEL selector, NSArray *arguments) {
    return ResourceBeginScoped(object, selector, arguments, NO);
}
static NSArray *ResourceArgumentValues(NSArray *arguments) {
    ResourceSuppress(YES);
    NSMutableArray *values = [NSMutableArray array];
    for (id object in arguments) [values addObject:object == NSNull.null ? @{@"nil": @YES} : ResourceObject(object)];
    ResourceSuppress(NO);
    return values;
}
static NSArray *ResourceArguments(id receiver, NSArray *arguments) {
    return ResourceShouldObserve(receiver) ? ResourceArgumentValues(arguments) : @[];
}
static void ResourceEnd(NSMutableDictionary *event, id receiver, id result, BOOL hasResult) {
    if (!event) return;
    ResourceSuppress(YES);
    event[@"receiverAfter"] = ResourceObject(receiver);
    if (hasResult) event[@"result"] = ResourceObject(result);
    event[@"stockArgumentsUnchanged"] = @YES;
    event[@"stockReturnUnchanged"] = @YES;
    event[@"elapsedSeconds"] = @(NSProcessInfo.processInfo.systemUptime - [event[@"startedAtUptime"] doubleValue]);
    NSMutableArray *stack = NSThread.currentThread.threadDictionary[ResourceStackKey];
    if (stack.lastObject == event) [stack removeLastObject];
    [ResourceLock lock];
    if (ResourceEvents.count < 4096) [ResourceEvents addObject:event]; else ResourceDropped++;
    [ResourceLock unlock];
    ResourceSuppress(NO);
}
static id ResourceObject0(id object, SEL selector) {
    NSMutableDictionary *event = ResourceBegin(object, selector, @[]);
    id result = nil;
    @try { result = ((id (*)(id, SEL))ResourceOriginal(object, selector))(object, selector); }
    @finally { ResourceEnd(event, object, result, YES); }
    return result;
}
static id ResourceObject1(id object, SEL selector, id argument) {
    NSMutableDictionary *event = ResourceBegin(object, selector, ResourceArguments(object, @[argument ?: NSNull.null]));
    id result = nil;
    @try { result = ((id (*)(id, SEL, id))ResourceOriginal(object, selector))(object, selector, argument); }
    @finally { ResourceEnd(event, object, result, YES); }
    return result;
}
static id ResourceObject2(id object, SEL selector, id first, id second) {
    NSMutableDictionary *event = ResourceBegin(object, selector, ResourceArguments(object, @[first ?: NSNull.null, second ?: NSNull.null]));
    id result = nil;
    @try { result = ((id (*)(id, SEL, id, id))ResourceOriginal(object, selector))(object, selector, first, second); }
    @finally { ResourceEnd(event, object, result, YES); }
    return result;
}
static id ResourceObject3(id object, SEL selector, id first, id second, id third) {
    NSMutableDictionary *event = ResourceBegin(object, selector,
        ResourceArguments(object, @[first ?: NSNull.null, second ?: NSNull.null, third ?: NSNull.null]));
    id result = nil;
    @try { result = ((id (*)(id, SEL, id, id, id))ResourceOriginal(object, selector))(
        object, selector, first, second, third); }
    @finally { ResourceEnd(event, object, result, YES); }
    return result;
}
static id ResourcePackageURL(id object, SEL selector, id url, id type, id options, NSError **error) {
    NSString *path = [url isKindOfClass:NSURL.class] ? [url path] : @"";
    BOOL relevant = [path hasPrefix:@"/System/Library/PrivateFrameworks/FocusUI.framework/"] ||
        ([path hasPrefix:@"/System/Library/PrivateFrameworks/MediaControls.framework/"] &&
         [@[@"PlayPauseStop.ca", @"ForwardBackward.ca", @"SkipForwardBackward.ca"] containsObject:path.lastPathComponent]);
    NSArray *arguments = (relevant && ResourceActive) ? ResourceArgumentValues(@[url ?: NSNull.null, type ?: NSNull.null]) :
        ResourceArguments(object, @[url ?: NSNull.null, type ?: NSNull.null]);
    NSMutableDictionary *event = ResourceBeginScoped(object, selector, arguments, relevant);
    id result = nil;
    @try { result = ((id (*)(id, SEL, id, id, id, NSError **))ResourceOriginal(object, selector))(object, selector, url, type, options, error); }
    @finally { ResourceEnd(event, object, result, YES); }
    return result;
}
static void ResourceVoid0(id object, SEL selector) {
    NSMutableDictionary *event = ResourceBegin(object, selector, @[]);
    @try { ((void (*)(id, SEL))ResourceOriginal(object, selector))(object, selector); }
    @finally { ResourceEnd(event, object, nil, NO); }
}
static void ResourceVoid1(id object, SEL selector, id argument) {
    NSMutableDictionary *event = ResourceBegin(object, selector, ResourceArguments(object, @[argument ?: NSNull.null]));
    @try { ((void (*)(id, SEL, id))ResourceOriginal(object, selector))(object, selector, argument); }
    @finally { ResourceEnd(event, object, nil, NO); }
}
static void ResourceVoid2(id object, SEL selector, id first, id second) {
    NSMutableDictionary *event = ResourceBegin(object, selector, ResourceArguments(object, @[first ?: NSNull.null, second ?: NSNull.null]));
    @try { ((void (*)(id, SEL, id, id))ResourceOriginal(object, selector))(object, selector, first, second); }
    @finally { ResourceEnd(event, object, nil, NO); }
}
static void ResourceVoidBool(id object, SEL selector, BOOL argument) {
    NSMutableDictionary *event = ResourceBegin(object, selector, @[@{@"value": @(argument)}]);
    @try { ((void (*)(id, SEL, BOOL))ResourceOriginal(object, selector))(object, selector, argument); }
    @finally { ResourceEnd(event, object, nil, NO); }
}
static void ResourceVoidObjectBool(id object, SEL selector, id first, BOOL second) {
    NSMutableArray *arguments = [ResourceArguments(object, @[first ?: NSNull.null]) mutableCopy];
    [arguments addObject:@{@"value": @(second)}];
    NSMutableDictionary *event = ResourceBegin(object, selector, arguments);
    @try { ((void (*)(id, SEL, id, BOOL))ResourceOriginal(object, selector))(object, selector, first, second); }
    @finally { ResourceEnd(event, object, nil, NO); }
}
static void ResourceObserve(NSString *name, NSString *selectorName, BOOL classMethod, NSString *types, IMP observer) {
    Class cls = NSClassFromString(name);
    SEL selector = NSSelectorFromString(selectorName);
    Class owner = classMethod ? object_getClass(cls) : cls;
    Method method = owner ? class_getInstanceMethod(owner, selector) : NULL;
    BOOL owned = NO;
    unsigned count = 0;
    Method *methods = owner ? class_copyMethodList(owner, &count) : NULL;
    for (unsigned i = 0; i < count; i++) if (methods[i] == method) owned = YES;
    free(methods);
    NSString *actual = method ? @(method_getTypeEncoding(method)) : @"";
    BOOL checked = owned && [actual isEqual:types] && ResourceMethodCount < 64;
    [ResourceContracts addObject:@{@"className": name, @"selector": selectorName, @"classMethod": @(classMethod),
        @"expectedTypes": types, @"actualTypes": actual, @"ownedMethod": @(owned), @"installed": @(checked)}];
    if (!checked) return;
    CNDResourceMethod entry = {cls, selector, method, method_getImplementation(method), observer, classMethod};
    ResourceMethods[ResourceMethodCount++] = entry;
    method_setImplementation(method, observer);
    ResourceMetadataWrites++;
}
static void ResourceTraceStart(NSString *phase) {
    if (ResourceActive || ResourceMethodCount) return;
    ResourceLock = NSRecursiveLock.new;
    ResourceEvents = [NSMutableArray array]; ResourceContracts = [NSMutableArray array];
    ResourcePhase = [phase copy]; ResourceSequence = ResourceDropped = 0;
    for (NSString *getter in @[@"forwardBackwardPackageName", @"playPauseStopPackageName", @"skipForwardBackwardPackageName"])
        ResourceObserve(@"MRUAssetsProvider", getter, YES, @"@16@0:8", (IMP)ResourceObject0);
    for (NSString *factory in @[@"packageWithName:", @"packageDescriptionWithName:"])
        ResourceObserve(@"MRUAssetsProvider", factory, YES, @"@24@0:8@16", (IMP)ResourceObject1);
    ResourceObserve(@"MediaControlsModule", @"contentViewControllerForContext:", NO, @"@24@0:8@16", (IMP)ResourceObject1);
    for (NSString *lifecycle in @[@"loadView", @"viewDidLoad"])
        ResourceObserve(@"MRUMediaControlsModuleViewController", lifecycle, NO, @"v16@0:8", (IMP)ResourceVoid0);
    ResourceObserve(@"FCUICAPackageView", @"packageViewForActivity:", YES, @"@24@0:8@16", (IMP)ResourceObject1);
    ResourceObserve(@"CCUICAPackageDescription", @"packageDescriptionForActivity:", YES, @"@24@0:8@16", (IMP)ResourceObject1);
    ResourceObserve(@"CCUICAPackageDescription", @"descriptionForPackageNamed:inBundle:", YES, @"@32@0:8@16@24", (IMP)ResourceObject2);
    ResourceObserve(CND_CC_RESOURCE_PACKAGE_CLASS, @"packageWithContentsOfURL:type:options:error:", YES, @"@48@0:8@16@24@32^@40", (IMP)ResourcePackageURL);
    ResourceObserve(@"FCUIActivityPickerViewController", @"loadView", NO, @"v16@0:8", (IMP)ResourceVoid0);
    ResourceObserve(@"FCUIActivityPickerViewController", @"_configureActivityListViewWithAvailableActivities:", NO, @"v24@0:8@16", (IMP)ResourceVoid1);
    ResourceObserve(@"FCUIActivityControl", @"_updateActivityIcon", NO, @"v16@0:8", (IMP)ResourceVoid0);
    for (NSString *setter in @[@"setActivityDescription:", @"setActivityIcon:", @"_setActivityIconPackageView:"])
        ResourceObserve(@"FCUIActivityControl", setter, NO, @"v24@0:8@16", (IMP)ResourceVoid1);
    ResourceObserve(@"FCUIActivityControl", @"_configureActivityIconImageViewIfNecessaryForReference:", NO, @"v20@0:8B16", (IMP)ResourceVoidBool);
    ResourceObserve(@"FCUIActivityControl", @"_setActivityIcon:forReference:", NO, @"v28@0:8@16B24", (IMP)ResourceVoidObjectBool);
    ResourceObserve(@"CCUIControlDescriptorProvider", @"descriptorFor:", NO, @"@24@0:8@16", (IMP)ResourceObject1);
    ResourceObserve(@"CHSWidgetExtensionProvider", @"controlDescriptorForControl:", NO, @"@24@0:8@16", (IMP)ResourceObject1);
    ResourceObserve(@"CHSWidgetExtensionProvider", @"controlDescriptorForIdentifiable:", NO, @"@24@0:8@16", (IMP)ResourceObject1);
    ResourceObserve(@"UIImage", @"systemImageNamed:", YES, @"@24@0:8@16", (IMP)ResourceObject1);
    for (NSString *factory in @[@"systemImageNamed:withConfiguration:", @"systemImageNamed:compatibleWithTraitCollection:"])
        ResourceObserve(@"UIImage", factory, YES, @"@32@0:8@16@24", (IMP)ResourceObject2);
    ResourceObserve(@"UIImage", @"imageNamed:", YES, @"@24@0:8@16", (IMP)ResourceObject1);
    ResourceObserve(@"UIImage", @"imageNamed:inBundle:compatibleWithTraitCollection:", YES,
                    @"@40@0:8@16@24@32", (IMP)ResourceObject3);
    ResourceObserve(@"NSBundle", @"URLForResource:withExtension:", NO, @"@32@0:8@16@24", (IMP)ResourceObject2);
    ResourceObserve(@"NSCache", @"objectForKey:", NO, @"@24@0:8@16", (IMP)ResourceObject1);
    ResourceObserve(@"NSCache", @"setObject:forKey:", NO, @"v32@0:8@16@24", (IMP)ResourceVoid2);
    ResourceActive = YES;
}
static NSArray *ResourceTraceStop(void) {
    if (!ResourceActive) return @[];
    ResourceActive = NO;
    NSMutableArray *restored = [NSMutableArray array];
    for (NSUInteger i = 0; i < ResourceMethodCount; i++) {
        CNDResourceMethod entry = ResourceMethods[i];
        BOOL ours = method_getImplementation(entry.method) == entry.observer;
        if (ours) { method_setImplementation(entry.method, entry.original); ResourceMetadataWrites++; }
        [restored addObject:@{@"className": NSStringFromClass(entry.owner),
            @"selector": NSStringFromSelector(entry.selector), @"restored": @(ours), @"replacementConflict": @(!ours)}];
    }
    /* Keep the original function table available to any in-flight observer. */
    return restored;
}
static void ResourceTracePhase(NSString *phase) {
    if (!ResourceLock || !phase.length) return;
    [ResourceLock lock]; ResourcePhase = [phase copy]; [ResourceLock unlock];
}
static NSDictionary *ResourceTraceReport(void) {
    if (!ResourceLock) return @{@"active": @NO, @"events": @[], @"methodContracts": @[]};
    [ResourceLock lock];
    NSDictionary *result = @{@"active": @(ResourceActive), @"events": [ResourceEvents copy],
        @"methodContracts": [ResourceContracts copy], @"eventBudget": @4096, @"droppedEvents": @(ResourceDropped),
        @"diagnosticMethodInterception": @YES, @"productionAdapterInstalled": @NO,
        @"installedObserverCount": @(ResourceActive ? ResourceMethodCount : 0),
        @"runtimeMetadataWrites": @(ResourceMetadataWrites),
        @"observationsForwardStockInputsAndReturns": @YES, @"snapshotGetterCallsSuppressed": @YES,
        @"usesLabelsAsIdentity": @NO, @"usesGeometryAsIdentity": @NO,
        @"artworkWrites": @0, @"controlActions": @0};
    [ResourceLock unlock]; return result;
}
