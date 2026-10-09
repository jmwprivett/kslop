"""Execute the physical Focus tracer against checked Objective-C fixtures."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.tests.test_cc_theming_lifecycle_trace import HARNESS

ROOT = Path(__file__).resolve().parents[2]


class FocusRefinedTraceTests(unittest.TestCase):
    def test_focus_phases_and_scoped_named_contracts(self):
        source = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.m").read_text()
        settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()
        for expected in (
            'CNDCCThemingCopyRefinedFocusRouteTrace()', 'Expanded Focus · Start 5s',
            'Reopened Focus · Start 5s', '@"expanded-focus"', '@"reopened-focus"',
            '@"focusReconstructionComparison"', '[CC_THEMING_FOCUS]',
        ):
            self.assertIn(expected, settings)
        focus = source.split("static NSArray *CNDCCFocusGetterNames", 1)[1].split(
            "static BOOL CNDCCSemanticContinue", 1)[0]
        for member in (
            "activityIdentifier", "activityUniqueIdentifier", "activitySymbolImageName",
            "activityDescription", "viewIfLoaded", "activityViews", "_activityPickerViewController",
            "_activityManager", "_allActivitiesByIdentifier", "_availableActivities",
            "_activeActivity", "_defaultActivity", "_activityIconPackageView", "_activityIconImageView",
        ):
            self.assertIn(f'@"{member}"', focus)
        for forbidden in ('@"view"', 'subviews', 'displayName', 'title', 'accessibility', 'geometry'):
            self.assertNotIn(forbidden, focus)
        self.assertIn("BOOL discoverySeeded = focusScope;", source)
        self.assertIn("context->focusScope ? nil : CNDCCRefinedSwiftReferenceSlots", source)
        self.assertIn('@"identifierAmbiguous"', source)
        self.assertIn('@"modelKeyMatchesRowIdentifier"', source)
        self.assertIn('@"allocationLifetimeInferred": @NO', source)

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("xcrun"),
                         "requires macOS Objective-C Foundation")
    def test_actual_focus_routes_reordered_rows_reconstruction_and_missing_members(self):
        probe = (ROOT / "Cyanide/tweaks/CNDCCThemingProbe.m").read_text()
        trace = probe[probe.index("// This diagnostic deliberately"):probe.index(
            "NSDictionary<NSString *, id> *\nCNDCCThemingCopyMediaConnectivityTrace(void)")]
        helpers = probe[probe.index("static NSString *CNDCCAddress("):probe.index(
            "static NSString *CNDCCClassNameForClass(")]
        helpers += probe[probe.index("static NSUInteger CNDCCBoundedCount("):probe.index(
            "static NSString *CNDCCStringGetter(")]
        # Reuse only the checked transport/runtime fixtures, not the old main.
        harness = HARNESS.split("int main(void) {", 1)[0]
        # Existing methods keep their original encoding when their IMP changes.
        # Supply the incompatible remote metadata explicitly in this fixture.
        harness = harness.replace("static BOOL fixtureDiscoveryEnabled", "static uint64_t fixtureFocusWrongABIMethod;\nstatic BOOL fixtureDiscoveryEnabled")
        harness = harness.replace("return (uint64_t)method_getTypeEncoding((Method)a);",
            'return a == fixtureFocusWrongABIMethod ? (uint64_t)"q16@0:8" : (uint64_t)method_getTypeEncoding((Method)a);')
        harness = harness.replace("PRODUCTION_HELPERS", FOCUS_FIXTURES + helpers).replace(
            "PRODUCTION_TRACE", trace) + FOCUS_MAIN
        with tempfile.TemporaryDirectory(prefix="cyanide-focus-trace-") as directory:
            source = Path(directory) / "focus.m"
            source.write_text(harness)
            binary = Path(directory) / "focus"
            compiled = subprocess.run([
                "xcrun", "clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
                "-framework", "Foundation", str(source), "-o", str(binary),
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            tested = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)
            self.assertIn("physical Focus fixture assertions passed", tested.stdout)


FOCUS_FIXTURES = r'''
static id fixtureFocusRegistry;
@interface CCUIModuleInstanceManager : NSObject
@property NSDictionary *enabledModuleInstanceByUniqueIdentifer;
@end
@implementation CCUIModuleInstanceManager
+ (id)sharedInstance { return fixtureFocusRegistry; }
@end
@interface CCUIModuleInstance : NSObject
@property id module;
@end
@implementation CCUIModuleInstance @end
@interface _FCActivity : NSObject
@property NSString *activityIdentifier;
@property NSString *activityUniqueIdentifier;
@property NSString *activitySymbolImageName;
@end
@implementation _FCActivity @end
@interface UIImage : NSObject @end
@implementation UIImage @end
@interface UIImageView : NSObject
@property UIImage *image;
@end
@implementation UIImageView @end
@interface FCUICAPackageView : NSObject @end
@implementation FCUICAPackageView @end
@interface FCUIActivityControl : NSObject
@property _FCActivity *activityDescription;
@property FCUICAPackageView *activityIconPackageView;
@property UIImageView *activityIconImageView;
@end
@implementation FCUIActivityControl
- (id)activityIdentifier { return _activityDescription.activityIdentifier; }
- (id)activityUniqueIdentifier { return _activityDescription.activityUniqueIdentifier; }
- (id)activitySymbolImageName { return _activityDescription.activitySymbolImageName; }
@end
@interface FCUIActivityListView : NSObject
@property NSArray *activityViews;
@end
@implementation FCUIActivityListView @end
@interface FCUIActivityPickerViewController : UIViewController
@property id loadedList;
@end
@implementation FCUIActivityPickerViewController
- (id)viewIfLoaded { return _loadedList; }
- (id)view { forbiddenCalls++; abort(); }
@end
@interface FCActivityManager : NSObject
@property NSDictionary *allActivitiesByIdentifier;
@property NSArray *availableActivities;
@property _FCActivity *activeActivity;
@property _FCActivity *defaultActivity;
@end
@implementation FCActivityManager @end
@interface FCCCControlCenterModule : NSObject
@property FCActivityManager *activityManager;
@property FCUIActivityPickerViewController *activityPickerViewController;
@end
@implementation FCCCControlCenterModule @end
static NSInteger wrongActivityIdentifier(id object, SEL selector) {
    (void)object; (void)selector; fputs("wrong ABI identifier invoked\n", stderr); forbiddenCalls++; abort();
}
static FCUIActivityControl *makeFocusRow(_FCActivity *model) {
    FCUIActivityControl *row = [FCUIActivityControl new];
    row.activityDescription = model;
    row.activityIconPackageView = [FCUICAPackageView new];
    row.activityIconImageView = [UIImageView new];
    row.activityIconImageView.image = [UIImage new];
    return row;
}
'''


FOCUS_MAIN = r'''
int main(void) {
    @autoreleasepool {
        (void)fixtureSubviews;
        scratch = [NSMutableSet set]; fixtureApplication = [SpringBoard new];
        fixtureWindows = @[];
        NSArray *identifiers = @[@"com.apple.donotdisturb.mode.default", @"com.apple.focus.work", @"com.apple.sleep.sleep-mode"];
        NSArray *symbols = @[@"moon.fill", @"person.lanyardcard.fill", @"bed.double.fill"];
        NSMutableDictionary *models = [NSMutableDictionary dictionary];
        NSMutableArray *rows = [NSMutableArray array];
        for (NSUInteger index = 0; index < identifiers.count; index++) {
            _FCActivity *model = [_FCActivity new];
            model.activityIdentifier = identifiers[index]; model.activitySymbolImageName = symbols[index];
            model.activityUniqueIdentifier = [NSString stringWithFormat:@"machine-uuid-%lu", (unsigned long)index];
            models[identifiers[index]] = model; [rows addObject:makeFocusRow(model)];
        }
        FCActivityManager *manager = [FCActivityManager new];
        manager.allActivitiesByIdentifier = models; manager.availableActivities = models.allValues;
        manager.defaultActivity = models[identifiers[0]];
        FCUIActivityListView *list = [FCUIActivityListView new]; list.activityViews = rows;
        FCUIActivityPickerViewController *picker = [FCUIActivityPickerViewController new]; picker.loadedList = list;
        FCCCControlCenterModule *module = [FCCCControlCenterModule new];
        module.activityManager = manager; module.activityPickerViewController = picker;
        CCUIModuleInstance *instance = [CCUIModuleInstance new]; instance.module = module;
        CCUIModuleInstanceManager *registry = [CCUIModuleInstanceManager new];
        registry.enabledModuleInstanceByUniqueIdentifer = @{@"runtime-module-uuid": instance}; fixtureFocusRegistry = registry;
        NSMutableDictionary *before = [CNDCCThemingCopyRefinedFocusRouteTrace() mutableCopy];
        before[@"capturePhase"] = @"expanded-focus";
        if (![before[@"success"] boolValue] || [before[@"refinedRevision"] intValue] != 4 ||
            [before[@"focusRowChains"] count] != 3 || ![before[@"focusMaterializationEvidence"][@"allObservedRowsComplete"] boolValue]) return 61;
        if ([before[@"viewHierarchyTraversal"] boolValue] || [before[@"recursiveFallbackUsed"] boolValue] ||
            [before[@"discoveryObjectCount"] intValue] || forbiddenCalls || scratch.count) return 62;
        NSDictionary *state = [before[@"focusManagerStateSnapshots"] firstObject];
        if (![state[@"_activeActivity"][@"status"] isEqualToString:@"null"] ||
            ![state[@"_defaultActivity"][@"machineIdentities"][@"activityIdentifier"] isEqual:identifiers[0]]) return 63;
        for (NSDictionary *chain in before[@"focusRowChains"])
            if (![chain[@"modelKeyMatchesRowIdentifier"] boolValue] || ![chain[@"symbolIdentityMatched"] boolValue] ||
                ![chain[@"uniqueIdentifierMatched"] boolValue] || [chain[@"membershipUsesPosition"] boolValue] ||
                [chain[@"productionRoute"] boolValue]) return 64;
        if ([CNDCCLifecycleClassEvidence(@"FCUIActivityControl")[@"stableOwnerCandidate"] boolValue] ||
            [CNDCCLifecycleClassEvidence(@"FCCCControlCenterModule")[@"rank"] intValue] != 75) return 65;
        // Reordering the same identified rows must preserve their pairing.
        list.activityViews = [[rows reverseObjectEnumerator] allObjects];
        NSMutableDictionary *after = [CNDCCThemingCopyRefinedFocusRouteTrace() mutableCopy];
        after[@"capturePhase"] = @"reopened-focus";
        NSDictionary *comparison = CNDCCThemingCompareRefinedPhysicalRoutes(after, before);
        NSDictionary *focusComparison = comparison[@"focusReconstructionComparison"];
        if (![focusComparison[@"comparisonAvailable"] boolValue] || [focusComparison[@"rowComparisons"] count] != 3 ||
            [focusComparison[@"changedLeavesUnderUnchangedOwners"] count] || ![focusComparison[@"userDeclaredReopenSequence"] boolValue] ||
            [comparison[@"ambiguousRouteReceiverGroups"] count]) return 66;
        // Reconstruct list, rows, and icons under the same module/picker/manager.
        FCUIActivityListView *rebuiltList = [FCUIActivityListView new];
        NSMutableArray *rebuiltRows = [NSMutableArray array];
        for (NSString *identifier in [[identifiers reverseObjectEnumerator] allObjects])
            [rebuiltRows addObject:makeFocusRow(models[identifier])];
        rebuiltList.activityViews = rebuiltRows; picker.loadedList = rebuiltList;
        after = [CNDCCThemingCopyRefinedFocusRouteTrace() mutableCopy]; after[@"capturePhase"] = @"reopened-focus";
        comparison = CNDCCThemingCompareRefinedPhysicalRoutes(after, before);
        focusComparison = comparison[@"focusReconstructionComparison"];
        if ([focusComparison[@"changedLeavesUnderUnchangedOwners"] count] != 3 ||
            [comparison[@"samePIDPersistenceVerified"] boolValue] || [focusComparison[@"implementationReady"] boolValue]) return 67;
        for (NSDictionary *row in focusComparison[@"rowComparisons"])
            if (![row[@"ownersPersisted"] boolValue] || ![row[@"machineIdentitiesUnchanged"] boolValue] ||
                ![row[@"changedMembers"] containsObject:@"rowAddress"] || [row[@"allocationLifetimeInferred"] boolValue]) return 68;
        // Ambiguous identifiers must remain unpaired, even with changed leaves.
        rebuiltList.activityViews = [rebuiltRows arrayByAddingObject:makeFocusRow(models[identifiers[0]])];
        NSMutableDictionary *duplicate = [CNDCCThemingCopyRefinedFocusRouteTrace() mutableCopy];
        duplicate[@"capturePhase"] = @"reopened-focus";
        focusComparison = CNDCCThemingCompareRefinedPhysicalRoutes(duplicate, before)[@"focusReconstructionComparison"];
        if ([focusComparison[@"unpairedFocusChains"] count] != 2 || [focusComparison[@"rowComparisons"] count] != 2) return 69;
        // A null loaded view reports missing materialization without requesting view.
        picker.loadedList = nil;
        NSDictionary *unloaded = CNDCCThemingCopyRefinedFocusRouteTrace();
        if (![unloaded[@"success"] boolValue] || [unloaded[@"focusRowChains"] count] ||
            ![unloaded[@"focusOwnerChains"][0][@"missingMember"] isEqualToString:@"viewIfLoaded"] || forbiddenCalls) return 70;
        picker.loadedList = rebuiltList; rebuiltList.activityViews = rebuiltRows;
        // A mismatched keyed model stays visible and makes only that row incomplete.
        _FCActivity *wrong = [_FCActivity new]; wrong.activityIdentifier = @"different-machine-identifier";
        NSMutableDictionary *badModels = [models mutableCopy]; badModels[identifiers[0]] = wrong;
        manager.allActivitiesByIdentifier = badModels;
        NSDictionary *mismatch = CNDCCThemingCopyRefinedFocusRouteTrace();
        if ([mismatch[@"focusMaterializationEvidence"][@"completeRowChainCount"] intValue] != 2) return 71;
        manager.allActivitiesByIdentifier = models;
        // Exhaust general class metadata while the exact Focus contracts survive.
        NSMutableArray *groups = [NSMutableArray array];
        for (NSUInteger group = 0; group < 5; group++) {
            FixtureBudgetGroupController *owner = [FixtureBudgetGroupController new];
            NSMutableArray *children = [NSMutableArray array];
            for (NSUInteger index = 0; index < 30; index++) {
                NSString *name = [NSString stringWithFormat:@"FocusBudgetObject%lu", (unsigned long)(group * 30 + index)];
                Class cls = objc_allocateClassPair(NSObject.class, name.UTF8String, 0); objc_registerClassPair(cls);
                [children addObject:[cls new]];
            }
            owner.childViewControllers = children; [groups addObject:owner];
        }
        UIWindow *window = [UIWindow new]; UIViewController *root = [UIViewController new];
        root.childViewControllers = groups; window.rootViewController = root; fixtureWindows = @[window];
        NSDictionary *limited = CNDCCThemingCopyRefinedFocusRouteTrace();
        if (![limited[@"limitsReached"][@"classes"] boolValue] ||
            [limited[@"priorityInspection"][@"genericClassCount"] intValue] != 128 ||
            [limited[@"focusMaterializationEvidence"][@"completeRowChainCount"] intValue] != 3 ||
            objectWithClass(limited, @"FCUIActivityControl")[@"inspectionSkipped"] || forbiddenCalls || scratch.count) return 72;
        NSMutableDictionary *failed = [after mutableCopy]; failed[@"success"] = @NO;
        NSMutableDictionary *otherPID = [after mutableCopy]; otherPID[@"targetPID"] = @43;
        if ([CNDCCThemingCompareRefinedPhysicalRoutes(failed, before)[@"focusReconstructionComparison"][@"comparisonAvailable"] boolValue] ||
            [CNDCCThemingCompareRefinedPhysicalRoutes(otherPID, before)[@"focusReconstructionComparison"][@"comparisonAvailable"] boolValue]) return 73;
        // ABI-incompatible row identifier getters are never invoked or inferred from the model.
        Method identifierMethod = class_getInstanceMethod(FCUIActivityControl.class, @selector(activityIdentifier));
        IMP original = method_getImplementation(identifierMethod);
        fixtureFocusWrongABIMethod = (uint64_t)identifierMethod;
        method_setImplementation(identifierMethod, (IMP)wrongActivityIdentifier);
        NSDictionary *wrongABI = CNDCCThemingCopyRefinedFocusRouteTrace();
        method_setImplementation(identifierMethod, original); fixtureFocusWrongABIMethod = 0;
        if ([wrongABI[@"focusMaterializationEvidence"][@"completeRowChainCount"] intValue] || forbiddenCalls || scratch.count) return 74;
        // Reports are real JSON, including explicit null and unresolved member state.
        if (![NSJSONSerialization dataWithJSONObject:wrongABI options:0 error:NULL] ||
            ![NSJSONSerialization dataWithJSONObject:comparison options:0 error:NULL]) return 75;
        puts("physical Focus fixture assertions passed");
    }
    return 0;
}
'''

if __name__ == "__main__":
    unittest.main()
