/* Host fixture for the VM-only observer. It exercises stock forwarding,
 * nested provenance, snapshot suppression, bounded capture, and restoration
 * without loading or contacting SpringBoard. */
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <stdio.h>

static NSString *Address(id object) { return [NSString stringWithFormat:@"%p", (__bridge void *)object]; }
static NSString *ClassName(id object) { return object ? NSStringFromClass(object_getClass(object)) : @""; }
static BOOL Scalar(id object) {
    return [object isKindOfClass:NSString.class] || [object isKindOfClass:NSNumber.class] ||
        [object isKindOfClass:NSURL.class] || [object isKindOfClass:NSUUID.class];
}
static id ScalarValue(id object) {
    if ([object isKindOfClass:NSURL.class]) return [object absoluteString];
    if ([object isKindOfClass:NSUUID.class]) return [object UUIDString];
    return object;
}
static id Getter(id object, NSString *name) {
    Method method = class_getInstanceMethod(object_getClass(object), NSSelectorFromString(name));
    char *type = method ? method_copyReturnType(method) : NULL;
    BOOL checked = method && method_getNumberOfArguments(method) == 2 && type && type[0] == '@';
    free(type);
    return checked ? ((id (*)(id, SEL))objc_msgSend)(object, NSSelectorFromString(name)) : nil;
}
#define CND_CC_RESOURCE_PACKAGE_CLASS @"CNDCCFixturePackage"
#include "../lab/cnd_cc_resource_provenance.inc"

@interface CNDCCFixturePackage : NSObject
@property(nonatomic, strong) NSObject *rootLayer;
+ (id)packageWithContentsOfURL:(id)url type:(id)type options:(id)options error:(NSError **)error;
@end
@implementation CNDCCFixturePackage
+ (id)packageWithContentsOfURL:(__unused id)url type:(__unused id)type options:(__unused id)options error:(NSError **)error {
    if (error) *error = nil;
    CNDCCFixturePackage *package = [CNDCCFixturePackage new]; package.rootLayer = [NSObject new]; return package;
}
@end

@interface MRUAssetsProvider : NSObject
+ (NSString *)playPauseStopPackageName;
+ (id)packageWithName:(id)name;
@end
@implementation MRUAssetsProvider
+ (NSString *)playPauseStopPackageName { return @"PlayPauseStop"; }
+ (id)packageWithName:(id)name {
    static NSCache *cache;
    if (!cache) cache = [NSCache new];
    id value = [cache objectForKey:name];
    if (!value) {
        value = [CNDCCFixturePackage packageWithContentsOfURL:[NSURL fileURLWithPath:@"/System/Library/PrivateFrameworks/MediaControls.framework/PlayPauseStop.ca"]
                                               type:@"archive" options:nil error:nil];
        [cache setObject:value forKey:name];
    }
    return value;
}
@end

@interface UIImage : NSObject
+ (id)systemImageNamed:(id)name;
@end
@implementation UIImage
+ (id)systemImageNamed:(__unused id)name { return [UIImage new]; }
@end

@interface FixtureActivity : NSObject
@property(nonatomic, copy) NSString *activityIdentifier;
@property(nonatomic, copy) NSString *activitySymbolImageName;
@end
@implementation FixtureActivity
@end

@interface FCUICAPackageView : NSObject
+ (id)packageViewForActivity:(id)activity;
@end
@implementation FCUICAPackageView
+ (id)packageViewForActivity:(id)activity {
    (void)[UIImage systemImageNamed:[activity activitySymbolImageName]];
    return [FCUICAPackageView new];
}
@end

@interface FCUIActivityControl : NSObject
@property(nonatomic, strong) FixtureActivity *activityDescription;
@property(nonatomic, strong) FCUICAPackageView *activityIconPackageView;
- (NSString *)activityIdentifier;
- (NSString *)activitySymbolImageName;
- (void)_updateActivityIcon;
- (void)_setActivityIconPackageView:(FCUICAPackageView *)view;
@end
@implementation FCUIActivityControl
- (NSString *)activityIdentifier { return self.activityDescription.activityIdentifier; }
- (NSString *)activitySymbolImageName { return self.activityDescription.activitySymbolImageName; }
- (void)_updateActivityIcon { [self _setActivityIconPackageView:[FCUICAPackageView packageViewForActivity:self.activityDescription]]; }
- (void)_setActivityIconPackageView:(FCUICAPackageView *)view { self.activityIconPackageView = view; }
@end

static NSArray *Calls(NSDictionary *report, NSString *selector) {
    return [report[@"events"] filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDictionary *event, __unused NSDictionary *bindings) {
        return [event[@"selector"] isEqual:selector];
    }]];
}
#define REQUIRE(condition, message) do { if (!(condition)) { fprintf(stderr, "%s\n", message); return 1; } } while (0)
int main(void) {
    @autoreleasepool {
        IMP original = class_getMethodImplementation(object_getClass(MRUAssetsProvider.class), @selector(packageWithName:));
        ResourceTraceStart(@"compact");
        REQUIRE(ResourceActive, "observer did not activate");
        id package = [MRUAssetsProvider packageWithName:[MRUAssetsProvider playPauseStopPackageName]];
        REQUIRE([package isKindOfClass:CNDCCFixturePackage.class], "stock factory return changed");
        REQUIRE(package == [MRUAssetsProvider packageWithName:@"PlayPauseStop"], "stock cache identity changed");
        NSDictionary *report = ResourceTraceReport();
        REQUIRE(Calls(report, @"packageWithName:").count == 2, "natural factory calls not recorded");
        REQUIRE(Calls(report, @"packageWithContentsOfURL:type:options:error:").count == 1, "package URL provenance missing");
        REQUIRE(Calls(report, @"objectForKey:").count == 2, "scoped cache lookup missing");
        REQUIRE(Calls(report, @"setObject:forKey:").count == 1, "scoped cache insertion missing");
        NSDictionary *load = Calls(report, @"packageWithContentsOfURL:type:options:error:").firstObject;
        REQUIRE([load[@"parentSequence"] unsignedIntegerValue] > 0, "package load not correlated to provider");
        REQUIRE([load[@"result"][@"rootLayer"][@"address"] isEqual:Address([package rootLayer])], "loaded package root identity changed");
        NSUInteger eventCount = [report[@"events"] count];
        (void)[[NSCache new] objectForKey:@"outside-ui-context"];
        ResourceSuppress(YES);
        (void)[MRUAssetsProvider playPauseStopPackageName];
        ResourceSuppress(NO);
        REQUIRE([ResourceTraceReport()[@"events"] count] == eventCount, "snapshot or unrelated cache call polluted natural evidence");
        FixtureActivity *activity = [FixtureActivity new];
        activity.activityIdentifier = @"com.apple.focus.personal";
        activity.activitySymbolImageName = @"person.fill";
        FCUIActivityControl *row = [FCUIActivityControl new]; row.activityDescription = activity;
        ResourceTracePhase(@"focus-reconstructed"); [row _updateActivityIcon];
        report = ResourceTraceReport();
        REQUIRE(Calls(report, @"packageViewForActivity:").count == 1, "Focus factory missing");
        NSDictionary *symbol = Calls(report, @"systemImageNamed:").firstObject;
        REQUIRE([symbol[@"parentSequence"] unsignedIntegerValue] > 0, "Focus symbol has no factory context");
        REQUIRE([symbol[@"arguments"][0][@"value"] isEqual:@"person.fill"], "stock symbol input changed");
        NSDictionary *update = Calls(report, @"_updateActivityIcon").firstObject;
        REQUIRE([update[@"receiverAfter"][@"activityIdentifier"] isEqual:activity.activityIdentifier], "Focus machine identity missing");
        REQUIRE([update[@"receiverAfter"][@"_activityIconPackageView"][@"address"] isEqual:Address(row.activityIconPackageView)], "Focus named consumer correlation missing");
        for (NSUInteger i = 0; i < 4097; i++)
            REQUIRE([[MRUAssetsProvider playPauseStopPackageName] isEqual:@"PlayPauseStop"], "stock return changed when event budget filled");
        report = ResourceTraceReport();
        REQUIRE([report[@"events"] count] == 4096 && [report[@"droppedEvents"] unsignedIntegerValue] > 0,
                "event budget was not bounded or dropped observations were hidden");
        NSArray *restored = ResourceTraceStop();
        for (NSDictionary *entry in restored) REQUIRE([entry[@"restored"] boolValue], "observer failed to restore its stock method");
        REQUIRE(!ResourceActive, "observer remained active");
        REQUIRE(class_getMethodImplementation(object_getClass(MRUAssetsProvider.class), @selector(packageWithName:)) == original, "stock IMP was not restored");
        eventCount = [ResourceTraceReport()[@"events"] count];
        REQUIRE(package == [MRUAssetsProvider packageWithName:@"PlayPauseStop"], "stock result changed after restore");
        REQUIRE([ResourceTraceReport()[@"events"] count] == eventCount, "observer recorded after restore");
        printf("resource observer forwarding, provenance, suppression, and restoration passed\n");
    }
    return 0;
}
