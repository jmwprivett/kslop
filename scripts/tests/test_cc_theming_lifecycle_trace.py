"""Executable and static safety tests for the physical lifecycle-owner trace."""

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class CCLifecycleTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.m").read_text()
        cls.trace = cls.probe.split("// This diagnostic deliberately", 1)[1].split(
            "CNDCCThemingCopyMediaConnectivityTrace(void)", 1
        )[0]

    def test_primary_trace_never_uses_hierarchy_or_visual_discovery(self):
        primary = re.sub(r"// BEGIN EXPLICIT REFINED DISCOVERY.*?// END EXPLICIT REFINED DISCOVERY",
                         "", self.trace, flags=re.S)
        for forbidden in (
            "subviews", "superview", "accessibilityLabel", "accessibilityIdentifier",
            "CNDCCGeometry", "CNDCCControlKind", "CNDCCCopyTemplateViews",
            "CNDCCCopyViewsMatchingClassNames", '@"geometry"', '"title"', '"displayName"',
        ):
            self.assertNotIn(forbidden, primary)
        self.assertIn('@"viewHierarchyTraversal": @NO', self.trace)
        self.assertIn('@"recursiveFallbackUsed": @NO', self.trace)
        self.assertNotIn("if (!domain) continue;", self.trace)

    def test_getters_ivars_and_members_require_checked_abi(self):
        for expected in (
            '"method_getNumberOfArguments"', "arguments == 2",
            '[returnType hasPrefix:@"@"]', '![returnType hasPrefix:@"@?"]',
            'if (![contract[@"objectGetterABI"] boolValue]',
            '"ivar_getTypeEncoding"', '"ivar_getOffset"',
            "instanceSize - sizeof(uint64_t)",
            'if (![ivar[@"safeObjectSlot"] boolValue] &&',
            'if (![ivar[@"allowlistedOwnershipMember"] boolValue]) continue;',
            '"class_copyMethodList"', '@"invoked": @NO',
            '"objectAtIndex:"', '"objectForKey:"', "NSRegularExpressionSearch",
            '@"machineKey"', '@"indexIsIdentity": @NO',
        ):
            self.assertIn(expected, self.trace)
        self.assertNotRegex(self.trace, r"CNDCC(?:Getter|ClassName|ArrayObject)\(")

    def test_target_mutation_and_implementation_approval_are_absent(self):
        for forbidden in (
            "object_setClass", "class_addMethod", "object_setIvar",
            "objc_setAssociatedObject", "remote_write", "writeToFile", "setImage:",
        ):
            self.assertNotIn(forbidden, self.trace)
        self.assertNotRegex(self.trace, re.compile(
            r'r_msg2(?:_main|_raw)?\([^;]*"(?:set|toggle|activate|sendAction)', re.S
        ))
        for field in ("controlActions", "presentationWrites", "radioWrites",
                      "fileWrites", "runtimeMetadataWrites"):
            self.assertIn(f'@"{field}": @0', self.trace)
        self.assertIn('@"implementationReady": @NO', self.trace)
        self.assertIn('@"samePIDPersistenceVerified": @NO', self.trace)

    def test_capture_has_global_limits_caches_and_pid_bound_cleanup(self):
        for budget in ("ControllerCap", "ObjectCap", "ClassCap", "MemberCap",
                       "GlobalMemberCap", "CollectionCap", "EdgeCap", "DepthCap", "CallCap"):
            self.assertIn(f"CNDCCSemantic{budget}", self.trace)
        self.assertIn("context->started >= 30.0", self.trace)
        self.assertIn("context->contracts[key] = NSNull.null", self.trace)
        self.assertIn("metadataCache[@(cls)]", self.trace)
        self.assertIn("remote_call_current_pid() != context->pid", self.trace)
        self.assertIn("remote_call_current_io_failure_count()", self.trace)
        self.assertEqual(self.trace.count("r_free(list)"), 2)
        self.assertIn("@finally", self.trace)
        self.assertIn("r_free(context.countSlot)", self.trace)
        self.assertIn("r_settle_us(settle)", self.trace)
        self.assertIn('@"highestStableAnchor"', self.trace)
        self.assertIn('@"anchorToTargetPath"', self.trace)
        self.assertIn('@"unresolvedPaths"', self.trace)
        self.assertIn("controllers.count > 0", self.trace)

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("xcrun"),
                         "requires macOS Objective-C Foundation")
    def test_actual_trace_bootstrap_routes_lifecycle_and_failure_cases(self):
        # Compile the entire production lifecycle tracer against local,
        # observation-only runtime/transport fixtures. This executes its actual
        # UIApplication bootstrap, contracts, ivars, collections and reporting.
        start = self.probe.index("// This diagnostic deliberately")
        end = self.probe.index(
            "NSDictionary<NSString *, id> *\nCNDCCThemingCopyMediaConnectivityTrace(void)", start
        )
        address = self.probe[self.probe.index("static NSString *CNDCCAddress("):
                             self.probe.index("static NSString *CNDCCClassNameForClass(")]
        count = self.probe[self.probe.index("static NSUInteger CNDCCBoundedCount("):
                           self.probe.index("static NSString *CNDCCStringGetter(")]
        harness = HARNESS.replace("PRODUCTION_HELPERS", address + count).replace(
            "PRODUCTION_TRACE", self.probe[start:end]
        )
        with tempfile.TemporaryDirectory(prefix="cyanide-lifecycle-trace-") as directory:
            source = Path(directory) / "lifecycle.m"
            source.write_text(harness)
            binary = Path(directory) / "lifecycle"
            compiled = subprocess.run([
                "xcrun", "clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
                "-framework", "Foundation", str(source), "-o", str(binary)
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            tested = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)
            self.assertIn("actual lifecycle trace assertions passed", tested.stdout)
            physical = ROOT / "build/CCRefinedPhysicalCaptures-20261006-01"
            if (physical / "physical-refined-controlcenter-routes.json").exists():
                self.assertIn("physical capture replay: nine hosted receivers persisted by machine kind", tested.stdout)


HARNESS = r'''
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <string.h>
enum { R_TIMEOUT = 1, CNDCCCollectionSanityMax = 4096 };
static int fixturePID = 42, forbiddenCalls = 0;
static BOOL flipPID = NO, fixtureHealthy = YES;
static NSMutableSet *scratch;
static NSArray *fixtureWindows;
static id fixtureApplication;
static BOOL fixtureDiscoveryEnabled = NO;
static NSMutableDictionary *fixtureLoadedChildren;
static id fixtureSubviews(id object, SEL selector) {
    (void)selector;
    return fixtureLoadedChildren[@((uint64_t)(__bridge void *)object)] ?: @[];
}

static BOOL remote_call_current_success(void) { return fixtureHealthy; }
static int remote_call_current_pid(void) { return fixturePID; }
static uint64_t remote_call_current_io_failure_count(void) { return 0; }
static BOOL r_is_objc_ptr(uint64_t address) { return address > 4096; }
static uint32_t r_settle_us(uint32_t value) { static uint32_t old = 1; uint32_t prior = old; old = value; return prior; }
static uint64_t r_class(const char *name) { return (uint64_t)(__bridge void *)NSClassFromString(@(name)); }
static uint64_t r_sel(const char *name) { return (uint64_t)(void *)sel_registerName(name); }
static BOOL remote_read(uint64_t address, void *buffer, size_t length) { memcpy(buffer, (void *)address, length); return YES; }
static uint64_t remote_read64(uint64_t address) { return *(uint64_t *)address; }
static BOOL r_read_cstring(uint64_t address, char *buffer, size_t length) {
    if (!address) return NO; strlcpy(buffer, (const char *)address, length); return YES;
}
static BOOL r_read_nsstring(uint64_t address, char *buffer, size_t length) {
    id value = (__bridge id)(void *)address;
    if (![value isKindOfClass:NSString.class]) return NO;
    strlcpy(buffer, [value UTF8String], length); return YES;
}
static void r_free(uint64_t address) { [scratch removeObject:@(address)]; free((void *)address); }
static uint64_t r_dlsym_call(int timeout, const char *name, uint64_t a, uint64_t b,
    uint64_t c, uint64_t d, uint64_t e, uint64_t f, uint64_t g, uint64_t h) {
    (void)timeout; (void)c; (void)d; (void)e; (void)f; (void)g; (void)h;
    Class cls = (__bridge Class)(void *)a;
    if (!strcmp(name, "object_getClass")) return (uint64_t)(__bridge void *)object_getClass((__bridge id)(void *)a);
    if (!strcmp(name, "class_getName")) return (uint64_t)class_getName(cls);
    if (!strcmp(name, "class_getInstanceMethod")) return (uint64_t)class_getInstanceMethod(cls, (SEL)b);
    if (!strcmp(name, "class_getInstanceVariable")) return (uint64_t)class_getInstanceVariable(cls, (const char *)b);
    if (!strcmp(name, "method_getTypeEncoding")) return (uint64_t)method_getTypeEncoding((Method)a);
    if (!strcmp(name, "method_getNumberOfArguments")) return method_getNumberOfArguments((Method)a);
    if (!strcmp(name, "class_getInstanceSize")) return class_getInstanceSize(cls);
    if (!strcmp(name, "class_getSuperclass")) return (uint64_t)(__bridge void *)class_getSuperclass(cls);
    if (!strcmp(name, "ivar_getName")) return (uint64_t)ivar_getName((Ivar)a);
    if (!strcmp(name, "ivar_getTypeEncoding")) return (uint64_t)ivar_getTypeEncoding((Ivar)a);
    if (!strcmp(name, "ivar_getOffset")) return (uint64_t)ivar_getOffset((Ivar)a);
    if (!strcmp(name, "method_getName")) return (uint64_t)(void *)method_getName((Method)a);
    if (!strcmp(name, "sel_getName")) return (uint64_t)sel_getName((SEL)a);
    void *allocation = NULL;
    if (!strcmp(name, "calloc")) allocation = calloc(a, b);
    else if (!strcmp(name, "class_copyIvarList")) allocation = class_copyIvarList(cls, (unsigned int *)b);
    else if (!strcmp(name, "class_copyMethodList")) allocation = class_copyMethodList(cls, (unsigned int *)b);
    else { fprintf(stderr, "Unexpected runtime call %s\n", name); abort(); }
    if (allocation) [scratch addObject:@((uint64_t)allocation)];
    return (uint64_t)allocation;
}
static uint64_t r_msg2_main(uint64_t object, const char *name, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    NSString *selector = @(name);
    for (NSString *forbidden in @[@"subviews", @"superview", @"view", @"accessibilityLabel",
        @"accessibilityIdentifier", @"toggle", @"setImage:"])
        if ([selector isEqualToString:forbidden] &&
            !(fixtureDiscoveryEnabled && [selector isEqualToString:@"subviews"])) { forbiddenCalls++; abort(); }
    uint64_t result = ((uint64_t (*)(id, SEL, uint64_t, uint64_t, uint64_t, uint64_t))objc_msgSend)(
        (__bridge id)(void *)object, sel_registerName(name), a, b, c, d);
    if (flipPID && !strcmp(name, "windows")) fixturePID = 99;
    return result;
}

@interface UIViewController : NSObject
@property NSArray *childViewControllers;
@end
@implementation UIViewController
- (instancetype)init { if ((self = [super init])) _childViewControllers = @[]; return self; }
- (id)presentedViewController { return nil; }
- (id)viewIfLoaded { return nil; }
@end
@interface UIWindow : NSObject
@property UIViewController *rootViewController;
@end
@implementation UIWindow @end
@interface UIApplication : NSObject
@end
@implementation UIApplication
+ (id)sharedApplication { return fixtureApplication; }
- (NSArray *)windows { return fixtureWindows; }
@end
@interface SpringBoard : UIApplication @end
@implementation SpringBoard @end
@interface FixturePackageView : NSObject @end
@implementation FixturePackageView
- (NSString *)packageName { return @"Previous"; }
@end
@interface FixtureTransportButton : NSObject
@property id packageView;
@end
@implementation FixtureTransportButton @end
@interface MRUMediaControlsModuleViewController : UIViewController
@property id previousButton;
@property id playPauseButton;
@property id nextButton;
@end
@implementation MRUMediaControlsModuleViewController @end
@interface FCUIActivityConfiguration : NSObject @end
@implementation FCUIActivityConfiguration
- (NSString *)activityIdentifier { return @"com.apple.focus.sleep"; }
- (NSString *)symbolName { return @"bed.double.fill"; }
@end
@interface FCUIActivityViewController : UIViewController
@property NSArray *activities;
@end
@implementation FCUIActivityViewController @end
@interface FixtureModuleRegistry : NSObject
@property NSDictionary *moduleInstancesByIdentifier;
@end
@implementation FixtureModuleRegistry @end
@interface FixtureOrdinaryViewController : UIViewController
@property FixtureModuleRegistry *moduleRegistry;
@end
@implementation FixtureOrdinaryViewController @end
@interface WrongABIViewController : UIViewController @end
@implementation WrongABIViewController
- (NSInteger)nextButton { forbiddenCalls++; return 7; }
@end
@interface FixtureBudgetGroupController : UIViewController @end
@implementation FixtureBudgetGroupController @end

PRODUCTION_HELPERS
PRODUCTION_TRACE

static NSDictionary *objectWithClass(NSDictionary *report, NSString *name) {
    for (NSDictionary *object in report[@"objects"])
        if ([object[@"className"] isEqualToString:name]) return object;
    return nil;
}
int main(void) {
    @autoreleasepool {
        scratch = [NSMutableSet set];
        fixtureApplication = [SpringBoard new];
        MRUMediaControlsModuleViewController *media = [MRUMediaControlsModuleViewController new];
        for (NSString *name in @[@"previousButton", @"playPauseButton", @"nextButton"]) {
            FixtureTransportButton *button = [FixtureTransportButton new];
            button.packageView = [FixturePackageView new];
            [media setValue:button forKey:name];
        }
        FCUIActivityViewController *focus = [FCUIActivityViewController new];
        focus.activities = @[[FCUIActivityConfiguration new]];
        FixtureModuleRegistry *registry = [FixtureModuleRegistry new];
        registry.moduleInstancesByIdentifier = @{@"com.apple.media": media, @"com.apple.focus": focus};
        NSMutableArray *windows = [NSMutableArray array];
        for (NSUInteger i = 0; i < 10; i++) {
            UIWindow *window = [UIWindow new];
            FixtureOrdinaryViewController *controller = [FixtureOrdinaryViewController new];
            window.rootViewController = controller;
            if (i == 9) {
                controller.moduleRegistry = registry;
                NSMutableArray *children = [NSMutableArray arrayWithObjects:media, focus, [WrongABIViewController new], nil];
                for (NSUInteger j = 0; j < 22; j++) [children addObject:[FixtureOrdinaryViewController new]];
                controller.childViewControllers = children;
            }
            [windows addObject:window];
        }
        fixtureWindows = windows;
        NSDictionary *report = CNDCCThemingCopyLifecycleOwnerTrace();
        if (![report[@"success"] boolValue] || [report[@"visitedControllerCount"] unsignedIntegerValue] != 35) return 1;
        if ([report[@"controllers"] count] != 35 || !objectWithClass(report, @"MRUMediaControlsModuleViewController")) return 2;
        if (scratch.count || forbiddenCalls || ![report[@"scratchFreed"] boolValue]) return 3;
        for (NSString *role in @[@"media.previous", @"media.playPause", @"media.next", @"focus.activityOrMode"])
            if (![report[@"semanticRoleEvidence"][role] count]) return 4;
        NSDictionary *previous = nil;
        for (NSDictionary *candidate in report[@"routeCandidates"])
            if ([candidate[@"semanticRoles"] containsObject:@"media.previous"] &&
                [candidate[@"className"] isEqualToString:@"FixtureTransportButton"]) { previous = candidate; break; }
        if (!previous || ![previous[@"ownershipRoute"] count]) return 5;
        if ([previous[@"lifecycleAnchoring"][@"stableAnchorRank"] unsignedIntegerValue] != 90) return 6;
        if (![previous[@"lifecycleAnchoring"][@"highestStableAnchor"][@"className"] isEqualToString:@"FixtureModuleRegistry"]) return 7;
        if (![previous[@"lifecycleAnchoring"][@"anchorToTargetPath"] count] ||
            [previous[@"lifecycleAnchoring"][@"samePIDPersistenceVerified"] boolValue]) return 8;
        if ([CNDCCLifecycleClassEvidence(@"MRUMediaControlsModuleViewController")[@"rank"] unsignedIntegerValue] != 70 ||
            [CNDCCLifecycleClassEvidence(@"MediaControls.PackageView")[@"stableOwnerCandidate"] boolValue] ||
            [CNDCCLifecycleClassEvidence(@"ImagePackageProvider")[@"rank"] unsignedIntegerValue] != 90 ||
            [CNDCCLifecycleClassEvidence(@"ControlViewPackageProvider")[@"rank"] unsignedIntegerValue] != 90 ||
            [CNDCCLifecycleClassEvidence(@"MediaControls.PackageView")[@"rank"] unsignedIntegerValue] != 15) return 9;
        NSArray *roots = @[@{@"address": @"owner", @"className": @"FixtureModuleRegistry"}];
        NSArray *edges = @[
            @{@"kind": @"getter", @"name": @"packageView", @"fromAddress": @"owner", @"toAddress": @"package", @"toClass": @"FixturePackageView"},
            @{@"kind": @"ivar", @"name": @"_module", @"fromAddress": @"package", @"toAddress": @"owner"},
            @{@"kind": @"discoverySubview", @"fromAddress": @"owner", @"toAddress": @"visual"},
            @{@"kind": @"unknown", @"fromAddress": @"owner", @"toAddress": @"unknown"}
        ];
        NSDictionary *paths = CNDCCSemanticDirectPaths(roots, edges);
        if (paths.count != 2 || paths[@"visual"] || paths[@"unknown"]) return 10;
        NSArray *membership = @[
            @{@"kind": @"root", @"address": @"owner", @"className": @"FixtureModuleRegistry"},
            @{@"kind": @"collectionElement", @"fromAddress": @"owner", @"toAddress": @"row", @"toClass": @"FCUIActivityConfiguration"}
        ];
        NSDictionary *anchor = CNDCCLifecycleAnchorEvidence(membership, @{});
        if (![anchor[@"membershipReconstructionUnresolved"] boolValue]) return 11;
        anchor = CNDCCLifecycleAnchorEvidence(membership, @{@"row": @{@"machineIdentities": @{@"activityIdentifier": @"sleep"}}});
        if ([anchor[@"membershipReconstructionUnresolved"] boolValue]) return 12;
        if ([CNDCCSemanticRoles(@"", @{}, @"centerButton") count] ||
            ![CNDCCSemanticRoles(@"", @{}, @"_skipBackwardButton") containsObject:@"media.previous"]) return 13;
        if (CNDCCSemanticCollectionClass(@"CCUIModuleSettingsManager") ||
            CNDCCSemanticCollectionClass(@"SomeSettingsModel") ||
            !CNDCCSemanticCollectionClass(@"__NSArrayM") ||
            !CNDCCSemanticCollectionClass(@"__NSSetM") ||
            !CNDCCSemanticCollectionClass(@"__NSDictionaryM")) return 16;
        if (![CNDCCRefinedSwiftReferenceSlots(@"MediaControls.TransportButton")[@"packageView"]
            isEqualToString:@"MediaControls.PackageView"]) return 17;
        NSDictionary *previousRole = @{@"machineIdentities": @{@"symbolName": @"backward.fill", @"packageName": @"nextPrevious"},
            @"checkedScalars": @{@"isHorizontallyFlipped": @{@"value": @YES}}};
        if (![CNDCCRefinedMachineRole(previousRole) isEqualToString:@"media.previous"] ||
            CNDCCRefinedMachineRole(@{@"machineIdentities": @{@"symbolName": @"backward.fill"}}) ||
            CNDCCRefinedMachineRole(@{@"machineIdentities": @{@"packageName": @"nextPrevious"},
                @"checkedScalars": @{@"isHorizontallyFlipped": @{@"value": @YES}}})) return 18;
        NSDictionary *before = @{@"targetPID": @42, @"success": @YES,
            @"mode": @"physical-read-only-refined-route-trace", @"routeObservations": @[
                @{@"key": @"module/slot", @"address": @"old", @"className": @"MediaControls.TransportButton", @"ownershipRoute": @[]} ]};
        NSDictionary *after = @{@"targetPID": @42, @"success": @YES,
            @"mode": @"physical-read-only-refined-route-trace", @"routeObservations": @[
                @{@"key": @"module/slot", @"address": @"new", @"className": @"MediaControls.TransportButton", @"ownershipRoute": @[]} ]};
        NSDictionary *comparison = CNDCCThemingCompareRefinedPhysicalRoutes(after, before);
        if (![comparison[@"comparisonAvailable"] boolValue] || [comparison[@"changedRouteReceivers"] count] != 1 ||
            [comparison[@"samePIDPersistenceVerified"] boolValue]) return 19;
        NSMutableDictionary *otherPID = [after mutableCopy]; otherPID[@"targetPID"] = @43;
        if ([CNDCCThemingCompareRefinedPhysicalRoutes(otherPID, before)[@"comparisonAvailable"] boolValue] ||
            [CNDCCThemingCompareRefinedPhysicalRoutes(after, nil)[@"comparisonAvailable"] boolValue]) return 20;
        // Real runtime metadata with empty Swift-style ivar encodings. Keep
        // all fixture references alive independently of the untyped slots.
        Class packageClass = objc_allocateClassPair(NSObject.class, "MediaControls.PackageView", 0);
        objc_registerClassPair(packageClass);
        Class buttonClass = objc_allocateClassPair(NSObject.class, "MediaControls.TransportButton", 0);
        if (!class_addIvar(buttonClass, "packageView", 8, 3, "")) return 21;
        objc_registerClassPair(buttonClass);
        Class transportClass = objc_allocateClassPair(NSObject.class, "MediaControls.NowPlayingTransportControlsView", 0);
        for (NSString *slot in @[@"leftButton", @"centerButton", @"rightButton"])
            if (!class_addIvar(transportClass, slot.UTF8String, 8, 3, "")) return 22;
        objc_registerClassPair(transportClass);
        id transport = [transportClass new];
        NSMutableArray *keepAlive = [NSMutableArray arrayWithObject:transport];
        for (NSString *slot in @[@"leftButton", @"centerButton", @"rightButton"]) {
            id button = [buttonClass new], package = [packageClass new];
            [keepAlive addObjectsFromArray:@[button, package]];
            object_setIvar(button, class_getInstanceVariable(buttonClass, "packageView"), package);
            object_setIvar(transport, class_getInstanceVariable(transportClass, slot.UTF8String), button);
        }
        media.childViewControllers = @[transport];
        NSDictionary *refined = CNDCCThemingCopyRefinedPhysicalRouteTrace();
        if (![refined[@"success"] boolValue] || [refined[@"schemaVersion"] intValue] != 3 ||
            [refined[@"mediaSlotSnapshots"] count] != 6 || scratch.count || forbiddenCalls) return 23;
        for (NSDictionary *slot in refined[@"mediaSlotSnapshots"])
            if ([slot[@"semanticRoleVerified"] boolValue] || [slot[@"dynamicOffset"] intValue] < 8) return 24;
        if (![refined[@"staticMediaProviderEvidence"] count] || ![refined[@"processOwnerEvidence"] count]) return 25;
        // Reproduce the discovered wrapper offsets, but deliberately provide
        // no claimed Swift field types. One raw word matches an independently
        // acquired object; the other is an invalid object address. Neither may
        // cause a runtime call or a dereference of the raw word.
        const char *wrapperName = "_TtGC13MediaControls23RoutePickerSessionsViewCS_30MediaControlsModuleSessionView_";
        Class wrapperClass = objc_allocateClassPair(NSObject.class, wrapperName, 0);
        if (!class_addIvar(wrapperClass, "fixturePadding", 2248, 3, "[2248c]") ||
            !class_addIvar(wrapperClass, "contentView", 8, 3, "") ||
            !class_addIvar(wrapperClass, "sessionViews", 8, 3, "")) return 26;
        objc_registerClassPair(wrapperClass);
        if (ivar_getOffset(class_getInstanceVariable(wrapperClass, "contentView")) != 2256 ||
            ivar_getOffset(class_getInstanceVariable(wrapperClass, "sessionViews")) != 2264) return 27;
        id wrapper = [wrapperClass new];
        uintptr_t wrapperAddress = (uintptr_t)(__bridge void *)wrapper;
        uint64_t knownWord = (uint64_t)(__bridge void *)transport, unknownWord = 0x12345678;
        memcpy((void *)(wrapperAddress + 2256), &knownWord, 8);
        memcpy((void *)(wrapperAddress + 2264), &unknownWord, 8);
        [keepAlive addObject:wrapper];
        media.childViewControllers = @[wrapper, transport];
        refined = CNDCCThemingCopyRefinedPhysicalRouteTrace();
        NSArray *classifications = refined[@"wrapperSlotClassifications"];
        if (classifications.count != 2) return 28;
        for (NSDictionary *classification in classifications) {
            if ([classification[@"valueDereferenced"] boolValue] || [classification[@"resolved"] boolValue] ||
                [classification[@"slotTypeVerified"] boolValue] || [classification[@"productionRoute"] boolValue]) return 29;
            if ([classification[@"name"] isEqualToString:@"contentView"] &&
                ![classification[@"independentlyObservedClass"] isEqualToString:@"MediaControls.NowPlayingTransportControlsView"]) return 30;
            if ([classification[@"name"] isEqualToString:@"sessionViews"] &&
                ![classification[@"classification"] isEqualToString:@"unclassified-raw-word"]) return 31;
        }
        if ([CNDCCRefinedSwiftReferenceSlots(@(wrapperName)) count] ||
            [refined[@"mediaMaterializationEvidence"][@"wrapperCount"] intValue] != 1) return 32;
        media.childViewControllers = @[wrapper];
        refined = CNDCCThemingCopyRefinedPhysicalRouteTrace();
        if ([refined[@"mediaMaterializationEvidence"][@"transportViewCount"] intValue] ||
            [refined[@"mediaMaterializationEvidence"][@"presentationStateInferred"] boolValue]) return 33;
        // The wrapper is already in ownership 'seen'. Loaded discovery must
        // cross it independently, acquire content/session receivers, correlate
        // the content word, then resume exact session -> transport -> packages.
        Class moduleViewClass = objc_allocateClassPair(NSObject.class, "MediaControls.MediaControlsModuleView", 0);
        Class sessionClass = objc_allocateClassPair(NSObject.class, "MediaControls.MediaControlsModuleSessionView", 0);
        Class nowPlayingClass = objc_allocateClassPair(NSObject.class, "MediaControls.MediaControlsModuleNowPlayingView", 0);
        if (!class_addIvar(moduleViewClass, "sessionsView", 8, 3, "") ||
            !class_addIvar(sessionClass, "nowPlayingView", 8, 3, "") ||
            !class_addIvar(nowPlayingClass, "transportControlsView", 8, 3, "")) return 54;
        objc_registerClassPair(moduleViewClass); objc_registerClassPair(sessionClass); objc_registerClassPair(nowPlayingClass);
        for (Class cls in @[moduleViewClass, wrapperClass, sessionClass])
            if (!class_addMethod(cls, @selector(subviews), (IMP)fixtureSubviews, "@16@0:8")) return 55;
        id moduleView = [moduleViewClass new], content = [sessionClass new], nowPlaying = [nowPlayingClass new];
        [keepAlive addObjectsFromArray:@[moduleView, content, nowPlaying]];
        object_setIvar(moduleView, class_getInstanceVariable(moduleViewClass, "sessionsView"), wrapper);
        object_setIvar(content, class_getInstanceVariable(sessionClass, "nowPlayingView"), nowPlaying);
        object_setIvar(nowPlaying, class_getInstanceVariable(nowPlayingClass, "transportControlsView"), transport);
        knownWord = (uint64_t)(__bridge void *)content;
        memcpy((void *)(wrapperAddress + 2256), &knownWord, 8);
        fixtureLoadedChildren = [@{
            @((uint64_t)(__bridge void *)moduleView): @[wrapper],
            @((uint64_t)(__bridge void *)wrapper): @[content],
            @((uint64_t)(__bridge void *)content): @[wrapper], // cycle must terminate
        } mutableCopy];
        fixtureDiscoveryEnabled = YES;
        media.childViewControllers = @[moduleView];
        refined = CNDCCThemingCopyRefinedPhysicalRouteTrace();
        if (![refined[@"success"] boolValue] || [refined[@"refinedRevision"] intValue] != 3 ||
            [refined[@"mediaMaterializationEvidence"][@"sessionViewCount"] intValue] != 1 ||
            [refined[@"mediaMaterializationEvidence"][@"transportViewCount"] intValue] != 1 ||
            [refined[@"mediaSessionChains"] count] != 4 ||
            [refined[@"mediaSlotSnapshots"] count] != 6) return 56;
        NSUInteger completeChains = 0, wrapperMatches = 0;
        for (NSDictionary *chain in refined[@"mediaSessionChains"])
            completeChains += [chain[@"complete"] boolValue];
        for (NSDictionary *slot in refined[@"wrapperSlotClassifications"])
            wrapperMatches += [slot[@"independentAddressValidated"] boolValue];
        if (completeChains != 3 || wrapperMatches != 1 || scratch.count || forbiddenCalls) return 57;
        // A full ownership queue must still accept the reserved diagnostic
        // objects, while a further ownership enqueue remains bounded at 512.
        CNDCCSemanticContext capContext = {.refined = YES};
        NSMutableArray *capQueue = [NSMutableArray array];
        NSMutableSet *capSeen = [NSMutableSet set];
        for (NSUInteger i = 0; i < CNDCCSemanticObjectCap; i++)
            CNDCCSemanticEnqueue(&capContext, capQueue, capSeen, 0x10000 + i * 8, 0, @"media");
        CNDCCSemanticEnqueue(&capContext, capQueue, capSeen, 0x20000, 0, @"media");
        if (capQueue.count != CNDCCSemanticObjectCap) return 58;
        for (NSUInteger i = 0; i <= CNDCCRefinedDiscoveryObjectCap; i++)
            CNDCCSemanticEnqueue(&capContext, capQueue, capSeen, 0x30000 + i * 8, 0, @"diagnosticDiscovery");
        if (capQueue.count != CNDCCSemanticObjectCap + CNDCCRefinedDiscoveryObjectCap) return 59;
        fixtureLoadedChildren = nil;
        // Exceed the generic 128-class allowance with ordinary lifecycle
        // objects; physical target classes keep their dedicated contracts.
        Class iconClass = objc_allocateClassPair(NSObject.class, "CHUISControlIconView", 0);
        objc_registerClassPair(iconClass);
        Class instanceClass = objc_allocateClassPair(NSObject.class, "CHUISControlInstanceButton", 0);
        if (!class_addIvar(instanceClass, "_iconView", 8, 3, "@")) return 40;
        objc_registerClassPair(instanceClass);
        Class extraHostedClass = objc_allocateClassPair(NSObject.class, "CHUISFixturePhysicalProvider", 0);
        objc_registerClassPair(extraHostedClass);
        id instance = [instanceClass new], icon = [iconClass new], extraHosted = [extraHostedClass new];
        object_setIvar(instance, class_getInstanceVariable(instanceClass, "_iconView"), icon);
        [keepAlive addObjectsFromArray:@[instance, icon, extraHosted]];
        NSMutableArray *budgetGroups = [NSMutableArray array];
        for (NSUInteger group = 0; group < 5; group++) {
            FixtureBudgetGroupController *owner = [FixtureBudgetGroupController new];
            NSMutableArray *children = [NSMutableArray array];
            for (NSUInteger index = 0; index < 30; index++) {
                NSString *name = [NSString stringWithFormat:@"FixtureBudgetObject%lu", (unsigned long)(group * 30 + index)];
                Class cls = objc_allocateClassPair(NSObject.class, name.UTF8String, 0);
                objc_registerClassPair(cls);
                [children addObject:[cls new]];
            }
            if (group == 4) [children addObjectsFromArray:@[instance, extraHosted]];
            owner.childViewControllers = children;
            [budgetGroups addObject:owner];
        }
        ((UIViewController *)((UIWindow *)windows.lastObject).rootViewController).childViewControllers =
            [budgetGroups arrayByAddingObject:media];
        media.childViewControllers = @[wrapper, transport];
        refined = CNDCCThemingCopyRefinedPhysicalRouteTrace();
        if (![refined[@"limitsReached"][@"classes"] boolValue] ||
            [refined[@"priorityInspection"][@"genericClassCount"] intValue] != 128 ||
            [refined[@"mediaSlotSnapshots"] count] != 6 ||
            objectWithClass(refined, @(wrapperName))[@"inspectionSkipped"]) return 34;
        BOOL priorityTransportInspected = NO;
        for (NSDictionary *evidence in refined[@"priorityInspection"][@"classEvidence"])
            if ([evidence[@"className"] isEqualToString:@"MediaControls.NowPlayingTransportControlsView"])
                priorityTransportInspected = [evidence[@"inspected"] boolValue] && [evidence[@"classBudgetExempt"] boolValue];
        if (!priorityTransportInspected || [refined[@"classContracts"] count] <= 128 || scratch.count ||
            !objectWithClass(refined, @"CHUISControlIconView") ||
            objectWithClass(refined, @"CHUISControlInstanceButton")[@"inspectionSkipped"] ||
            objectWithClass(refined, @"CHUISFixturePhysicalProvider")[@"inspectionSkipped"] ||
            [refined[@"priorityInspection"][@"additionalHostedClassCount"] intValue] != 1) return 35;
        // Historical named-only hosted keys collide. Recompute with CHS kind
        // for the controller, its host view, and its CHUIS instance even when
        // the enumeration order changes. Stable addresses must all persist.
        NSMutableArray *hostObjects = [NSMutableArray array], *hostObservations = [NSMutableArray array];
        NSArray *hostKinds = @[@"com.apple.camera.deeplink.button", @"com.apple.BarcodeScanner.button",
            @"com.apple.calculator.CalculatorWidget.control"];
        for (NSUInteger index = 0; index < hostKinds.count; index++) {
            NSString *hostAddress = [NSString stringWithFormat:@"host%lu", (unsigned long)index];
            NSString *identityAddress = [NSString stringWithFormat:@"identity%lu", (unsigned long)index];
            [hostObjects addObject:@{@"address": identityAddress, @"className": @"CHSControlIdentity",
                @"machineIdentities": @{@"kind": hostKinds[index]}}];
            NSDictionary *host = @{@"address": hostAddress, @"className": @"CCUIControlHostViewController",
                @"getters": @{@"identity": @{@"valueAddress": identityAddress}}};
            [hostObjects addObject:host];
            NSArray *hostRoute = @[@{@"kind": @"collectionElement", @"toAddress": hostAddress,
                @"toClass": @"CCUIControlHostViewController"}];
            for (NSString *name in @[@"CCUIControlHostViewController", @"CCUIControlHostView", @"CHUISControlInstanceButton"]) {
                NSString *address = [name isEqualToString:@"CCUIControlHostViewController"] ? hostAddress
                    : [NSString stringWithFormat:@"%@%lu", name, (unsigned long)index];
                [hostObservations addObject:@{@"key": name, @"address": address,
                    @"className": name, @"ownershipRoute": hostRoute}];
            }
        }
        before = @{@"targetPID": @42, @"success": @YES, @"mode": @"physical-read-only-refined-route-trace",
            @"objects": hostObjects, @"routeObservations": hostObservations};
        after = @{@"targetPID": @42, @"success": @YES, @"mode": @"physical-read-only-refined-route-trace",
            @"objects": hostObjects, @"routeObservations": [[hostObservations reverseObjectEnumerator] allObjects]};
        comparison = CNDCCThemingCompareRefinedPhysicalRoutes(after, before);
        if ([comparison[@"persistedRouteReceivers"] count] != 9 || [comparison[@"changedRouteReceivers"] count] ||
            [comparison[@"unpairedRouteObservations"] count] || [comparison[@"ambiguousRouteReceiverGroups"] count]) return 36;
        for (NSDictionary *observation in comparison[@"persistedRouteReceivers"])
            if (![hostKinds containsObject:observation[@"hostedMachineKind"]] ||
                ![observation[@"key"] containsString:@"|hostKind="]) return 37;
        NSMutableArray *changedHostObservations = [hostObservations mutableCopy];
        NSMutableDictionary *changedHost = [changedHostObservations[0] mutableCopy];
        changedHost[@"address"] = @"new-camera-host";
        changedHostObservations[0] = changedHost;
        NSMutableDictionary *changedCapture = [after mutableCopy];
        changedCapture[@"routeObservations"] = changedHostObservations;
        comparison = CNDCCThemingCompareRefinedPhysicalRoutes(changedCapture, before);
        if ([comparison[@"changedRouteReceivers"] count] != 1 || [comparison[@"persistedRouteReceivers"] count] != 8 ||
            ![comparison[@"changedRouteReceivers"][0][@"hostedMachineKind"] isEqualToString:hostKinds[0]]) return 38;
        changedCapture[@"objects"] = @[];
        comparison = CNDCCThemingCompareRefinedPhysicalRoutes(changedCapture, before);
        if ([comparison[@"changedRouteReceivers"] count] || [comparison[@"unpairedRouteObservations"] count] != 9) return 39;
        // Two receivers with the same kind and route still cannot be paired
        // merely because their group has one unmatched address on each side.
        NSMutableDictionary *secondCamera = [hostObservations[0] mutableCopy];
        secondCamera[@"address"] = @"second-camera-host";
        NSMutableDictionary *duplicateBefore = [before mutableCopy];
        duplicateBefore[@"routeObservations"] = [hostObservations arrayByAddingObject:secondCamera];
        changedCapture[@"objects"] = hostObjects;
        changedCapture[@"routeObservations"] = [changedHostObservations arrayByAddingObject:secondCamera];
        comparison = CNDCCThemingCompareRefinedPhysicalRoutes(changedCapture, duplicateBefore);
        if ([comparison[@"changedRouteReceivers"] count] || [comparison[@"persistedRouteReceivers"] count] != 9 ||
            [comparison[@"ambiguousRouteReceiverGroups"] count] != 1 ||
            [comparison[@"newlyObservedRoutes"] count] != 1 || [comparison[@"noLongerObservedRoutes"] count] != 1) return 41;
        // If the local physical captures are present, replay the actual old
        // named-only observations. These nine raw hosted receivers remained
        // stable despite the prior comparator's false changed pairings.
        NSString *physicalDirectory = @"build/CCRefinedPhysicalCaptures-20261006-01/";
        NSData *physicalBeforeData = [NSData dataWithContentsOfFile:[physicalDirectory stringByAppendingString:
            @"physical-refined-controlcenter-routes-223D4CA5-C939-4A87-86E3-6DFFCF79DB26.json"]];
        NSData *physicalAfterData = [NSData dataWithContentsOfFile:[physicalDirectory stringByAppendingString:
            @"physical-refined-controlcenter-routes.json"]];
        if (physicalBeforeData && physicalAfterData) {
            NSDictionary *physicalBefore = [NSJSONSerialization JSONObjectWithData:physicalBeforeData options:0 error:NULL];
            NSDictionary *physicalAfter = [NSJSONSerialization JSONObjectWithData:physicalAfterData options:0 error:NULL];
            NSDictionary *physicalComparison = CNDCCThemingCompareRefinedPhysicalRoutes(physicalAfter, physicalBefore);
            NSUInteger stableHosted = 0;
            for (NSDictionary *observation in physicalComparison[@"persistedRouteReceivers"])
                stableHosted += observation[@"hostedMachineKind"] != nil;
            for (NSDictionary *observation in physicalComparison[@"changedRouteReceivers"])
                if ([observation[@"hostedMachineKind"] isKindOfClass:NSString.class]) return 42;
            if (stableHosted != 9 || [physicalComparison[@"unpairedRouteObservations"] count]) return 43;
            puts("physical capture replay: nine hosted receivers persisted by machine kind");
        }
        fixtureWindows = @[];
        report = CNDCCThemingCopyLifecycleOwnerTrace();
        if ([report[@"success"] boolValue] || ![report[@"transportSuccess"] boolValue] ||
            [report[@"visitedControllerCount"] unsignedIntegerValue] || !report[@"failureReason"] || scratch.count) return 14;
        fixtureWindows = windows;
        flipPID = YES;
        report = CNDCCThemingCopyLifecycleOwnerTrace();
        if ([report[@"success"] boolValue] || [report[@"pidStable"] boolValue] ||
            [report[@"scratchFreed"] boolValue] || scratch.count != 1) return 15;
        for (NSNumber *address in scratch.allObjects) r_free(address.unsignedLongLongValue);
        puts("actual lifecycle trace assertions passed");
    }
    return 0;
}
'''


if __name__ == "__main__":
    unittest.main()
