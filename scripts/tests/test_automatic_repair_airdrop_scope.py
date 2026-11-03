"""Automatic Repair must leave isolated AirDrop diagnostic journals alone."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def definition(source: str, signature: str) -> str:
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]


class AutomaticRepairAirDropScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.remix = (ROOT / "Cyanide/installer/CNDSnowBoardRemix.m").read_text()
        cls.header = (ROOT / "Cyanide/installer/CNDSnowBoardRemix.h").read_text()
        cls.settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()

    def test_watch_and_both_automatic_repairs_require_app_recovery_data(self) -> None:
        active = definition(self.settings,
                            "static BOOL settings_snowboard_automatic_repair_is_active(")
        self.assertIn("[CNDSnowBoardRemix hasAutomaticRepairData]", active)
        self.assertNotIn("[CNDSnowBoardRemix hasRecoveryData]", active)
        self.assertIn("+ (BOOL)hasAutomaticRepairData;", self.header)
        for signature in (
            "static void settings_arm_snowboard_automatic_repair(void)\n{",
            "static void settings_enqueue_snowboard_automatic_repair(\n"
            "    NSString *reason,\n    NSTimeInterval delay,\n"
            "    NSUInteger attempt,\n    BOOL immediate)\n{",
        ):
            self.assertIn("settings_snowboard_automatic_repair_is_active()",
                          definition(self.settings, signature))
        automatic = definition(self.settings,
                               "static BOOL settings_run_snowboard_automatic_repair(")
        gated = automatic[automatic.index("@try {"):]
        for operation in ("setTransparencyFixEnabled:YES",
                          "settings_update_repair_snowboard_remix()"):
            self.assertLess(gated.index(
                "if (!settings_snowboard_automatic_repair_is_active()) return NO;"),
                gated.index(operation))

    def test_manual_recovery_and_isolated_actions_remain_available(self) -> None:
        recovery = definition(self.remix, "+ (BOOL)hasRecoveryData")
        self.assertNotIn("CNDRemixIsSupportedPseudoBundleIdentifier", recovery)
        self.assertIn("CNDRemixJournalRepresentsDirtyPersistentData(journal)", recovery)
        for action in ("applyIsolatedAirDropTest", "auditIsolatedAirDropTest",
                       "restoreIsolatedAirDropTest"):
            self.assertIn("CNDRemixAirDropPseudoBundleIdentifier", definition(
                self.remix, f"+ (NSDictionary<NSString *, id> *){action}"))

    def test_share_diagnostics_require_explicit_or_actual_airdrop_work(self) -> None:
        apply = definition(self.remix,
                           "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme(")
        self.assertIn(
            "BOOL airDropTargetRequested = [foldedBundleFilter containsObject:\n"
            "        CNDRemixAirDropPseudoBundleIdentifier.lowercaseString];", apply)
        self.assertRegex(
            apply,
            r"if \(airDropTargetRequested \|\|\s*"
            r"\[matched containsObject:\s*"
            r"CNDRemixAirDropPseudoBundleIdentifier\]\) \{\s*"
            r"log_user\(\"\[SBR_SHARE\] airdrop asset=",
        )
        self.assertRegex(
            apply,
            r"if \(airDropTargetRequested \|\| airDropResult \|\| "
            r"airDropUnthemed \|\|\s*airDropActive\) \{\s*"
            r"log_user\(\"\[SBR_SHARE\] airdrop active=",
        )

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"),
                         "requires macOS Foundation and clang")
    def test_production_selection_and_journal_predicates_exclude_airdrop(self) -> None:
        # Compile the production predicates and both admission loops. Remote
        # publication is irrelevant: AirDrop must never reach its target list.
        installed_start = self.remix.index("            for (NSString *bundleIdentifier in installed)")
        installed_end = self.remix.index("            BOOL debugApplicationLimit", installed_start)
        pseudo_start = self.remix.index("            for (NSString *pseudoBundleIdentifier in", installed_end)
        pseudo_end = self.remix.index('            if (airDropTargetRequested ||', pseudo_start)
        parts = {
            "// PSEUDO_PREDICATE": definition(self.remix,
                "static BOOL CNDRemixIsSupportedPseudoBundleIdentifier("),
            "// ACTIVE_IDENTIFIERS": definition(self.remix,
                "static NSArray<NSString *> *CNDRemixActiveIconServicesBundleIdentifiers("),
            "// RECOVERY_PREDICATES": "\n".join(definition(self.remix, signature) for signature in (
                "+ (BOOL)hasRecoveryData", "+ (BOOL)hasAutomaticRepairData")),
            "// ADMISSION_LOOPS": self.remix[installed_start:installed_end] +
                                  self.remix[pseudo_start:pseudo_end],
        }
        source = HARNESS
        for placeholder, production in parts.items():
            source = source.replace(placeholder, production)
        with tempfile.TemporaryDirectory(prefix="cyanide-airdrop-repair-") as directory:
            fixture = Path(directory) / "scope.m"
            executable = Path(directory) / "scope"
            fixture.write_text(source)
            compiled = subprocess.run(
                ["clang", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra", "-Werror",
                 "-framework", "Foundation", str(fixture), "-o", str(executable)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(executable)], capture_output=True,
                                      text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stderr)


HARNESS = r'''
#import <Foundation/Foundation.h>
#include <assert.h>

static NSString * const CNDRemixAirDropPseudoBundleIdentifier = @"com.apple.Sharing.AirDrop";
static NSArray<NSDictionary *> *fakeJournals;
static NSArray *fakeLegacyTransactions;
static BOOL fakeProofActive;
static NSArray *CNDRemixIconServicesJournals(void) { return fakeJournals; }
static BOOL CNDRemixJournalRepresentsDirtyPersistentData(NSDictionary *journal) {
    return [journal[@"dirty"] boolValue];
}
static BOOL CNDIconServicesInterceptProofIsActive(void) { return fakeProofActive; }
// PSEUDO_PREDICATE
static NSArray<NSString *> *CNDRemixSupportedPseudoBundleIdentifiers(void) {
    return @[CNDRemixAirDropPseudoBundleIdentifier];
}
// ACTIVE_IDENTIFIERS

@interface CNDIconThemeTransaction : NSObject
+ (NSArray *)journaledTransactions;
@end
@implementation CNDIconThemeTransaction
+ (NSArray *)journaledTransactions { return fakeLegacyTransactions; }
@end
@interface CNDSnowBoardRemix : NSObject
+ (BOOL)hasRecoveryData;
+ (BOOL)hasAutomaticRepairData;
@end
@implementation CNDSnowBoardRemix
// RECOVERY_PREDICATES
@end

static NSArray *Select(NSArray *installed, NSSet *bundleFilter, BOOL repairLivePersistentRecords) {
    NSMutableSet *foldedBundleFilter = bundleFilter ? [NSMutableSet set] : nil;
    for (NSString *identifier in bundleFilter) [foldedBundleFilter addObject:identifier.lowercaseString];
    NSDictionary *themeLookup = @{@"com.apple.sharing.airdrop": @"asset", @"com.apple.mobilesms": @"asset"};
    NSMutableArray *matched = [NSMutableArray array];
    NSMutableSet *seenFolded = [NSMutableSet set];
// ADMISSION_LOOPS
    return matched;
}

int main(void) {
    @autoreleasepool {
        NSString *airdrop = CNDRemixAirDropPseudoBundleIdentifier;
        NSString *app = @"com.apple.MobileSMS";
        for (NSString *identifier in @[airdrop, @"COM.APPLE.SHARING.AIRDROP"]) {
            fakeJournals = @[@{@"bundleIdentifier": identifier, @"dirty": @YES}];
            assert([CNDSnowBoardRemix hasRecoveryData]);
            assert(![CNDSnowBoardRemix hasAutomaticRepairData]);
            assert(CNDRemixActiveIconServicesBundleIdentifiers().count == 0);
        }
        fakeJournals = @[@{@"bundleIdentifier": airdrop, @"dirty": @YES},
                         @{@"bundleIdentifier": app, @"dirty": @NO}];
        assert(![CNDSnowBoardRemix hasAutomaticRepairData]);
        fakeJournals = @[@{@"bundleIdentifier": airdrop, @"dirty": @YES},
                         @{@"bundleIdentifier": app, @"dirty": @YES}];
        assert([CNDSnowBoardRemix hasAutomaticRepairData]);
        assert(([CNDRemixActiveIconServicesBundleIdentifiers() isEqualToArray:@[app]]));
        fakeJournals = @[];
        assert(![CNDSnowBoardRemix hasAutomaticRepairData]);
        fakeLegacyTransactions = @[@"legacy app"];
        assert([CNDSnowBoardRemix hasAutomaticRepairData]);
        fakeLegacyTransactions = @[];
        fakeProofActive = YES;
        assert([CNDSnowBoardRemix hasAutomaticRepairData]);

        for (NSArray *installed in @[@[], @[airdrop], @[@"COM.APPLE.SHARING.AIRDROP"]]) {
            for (NSSet *filter in @[[NSSet setWithObject:airdrop],
                                    [NSSet setWithObject:@"COM.APPLE.SHARING.AIRDROP"]]) {
                assert(Select(installed, filter, YES).count == 0);
                // Explicit diagnostics retain their own AirDrop admission.
                assert(Select(installed, filter, NO).count == 1);
            }
            assert(Select(installed, nil, YES).count == 0);
            assert(Select(installed, nil, NO).count == 0);
        }
        NSArray *mixed = @[app, airdrop];
        assert(([Select(mixed, nil, YES) isEqualToArray:@[app]]));
        assert(([Select(mixed, [NSSet setWithArray:mixed], YES) isEqualToArray:@[app]]));
    }
    return 0;
}
'''


if __name__ == "__main__":
    unittest.main()
