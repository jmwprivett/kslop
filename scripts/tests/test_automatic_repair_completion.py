"""Automatic Repair results must not complete a foreground progress sheet."""

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
AUTOMATIC_NOTIFICATION = "kSettingsSnowBoardAutomaticRepairDidCompleteNotification"


class AutomaticRepairCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.settings = (ROOT / "Cyanide/SettingsViewController.m").read_text()
        cls.header = (ROOT / "Cyanide/SettingsViewController.h").read_text()
        cls.progress = (ROOT / "Cyanide/installer/InstallProgressViewController.m").read_text()
        start = cls.settings.index("static BOOL settings_run_snowboard_automatic_repair(")
        end = cls.settings.index("static void settings_cancel_pending_snowboard_automatic_repair(", start)
        cls.automatic = cls.settings[start:end]

    def test_background_completion_has_a_separate_channel_and_preserves_refreshes(self) -> None:
        self.assertIn(f"extern NSString * const {AUTOMATIC_NOTIFICATION};", self.header)
        self.assertIn(f"postNotificationName:{AUTOMATIC_NOTIFICATION}", self.automatic)
        self.assertNotIn("postNotificationName:kSettingsActionsDidCompleteNotification", self.automatic)
        self.assertNotIn("settings_post_actions_complete_async(", self.automatic)
        completion = self.automatic[self.automatic.index("    NSString *message = completionMessage"):]
        for preserved in (
            "dispatch_async(dispatch_get_main_queue(), ^{",
            "settings_invalidate_snowboard_remix_status_cache();",
            "postNotificationName:PackageQueueDidChangeNotification",
            "object:[PackageQueue sharedQueue]",
            "kSettingsActionsDidCompleteSuccessKey: @(success)",
            "kSettingsActionsDidCompleteMessageKey: message",
            "cyanide_upload_log_if_enabled();",
        ):
            with self.subTest(preserved=preserved):
                self.assertIn(preserved, completion)
        self.assertNotIn(AUTOMATIC_NOTIFICATION, self.progress)

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"),
                         "requires macOS Foundation and clang")
    def test_production_notification_post_and_progress_registration_do_not_cross_deliver(self) -> None:
        # Compile the actual completion tail and progress observer registration
        # against Foundation; the controller's UIKit rendering is irrelevant to
        # whether its completion selector can receive a background result.
        constants = []
        for name in (
            "kSettingsActionsDidCompleteNotification",
            "kSettingsActionsDidCompleteSuccessKey",
            "kSettingsActionsDidCompleteMessageKey",
            AUTOMATIC_NOTIFICATION,
        ):
            match = re.search(r"^NSString \* const " + name + r'\s*=\s*@"[^"]+";',
                              self.settings, re.MULTILINE)
            self.assertIsNotNone(match, name)
            constants.append(match.group())
        start = self.progress.index("    NSString *completionNotification =")
        end = self.progress.index("object:completionObject];", start) + len("object:completionObject];")
        registration = self.progress[start:end]
        start = self.automatic.index("    NSString *message = completionMessage")
        completion = self.automatic[start:self.automatic.rindex("\n}")]
        fixture_source = (HARNESS.replace("// PRODUCTION_CONSTANTS", "\n".join(constants))
                          .replace("// PRODUCTION_REGISTRATION", registration)
                          .replace("// PRODUCTION_COMPLETION", completion))
        with tempfile.TemporaryDirectory(prefix="cyanide-repair-completion-") as directory:
            fixture = Path(directory) / "completion.m"
            executable = Path(directory) / "completion"
            fixture.write_text(fixture_source)
            compiled = subprocess.run(
                ["clang", "-fobjc-arc", "-fblocks", "-Wall", "-Wextra", "-Werror",
                 "-framework", "Foundation", str(fixture), "-o", str(executable)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(executable)], capture_output=True,
                                      text=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stderr)


HARNESS = r'''
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>

// PRODUCTION_CONSTANTS
NSString * const PackageQueueDidChangeNotification = @"PackageQueueDidChange";
NSString * const PackageQueueExecutionDidCompleteNotification = @"PackageQueueExecutionDidComplete";
static NSUInteger cacheInvalidations;
static NSUInteger logUploads;
static void settings_invalidate_snowboard_remix_status_cache(void) { cacheInvalidations++; }
static void cyanide_upload_log_if_enabled(void) { logUploads++; }

@interface PackageQueue : NSObject
+ (instancetype)sharedQueue;
@end
@implementation PackageQueue
+ (instancetype)sharedQueue {
    static PackageQueue *queue;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ queue = [PackageQueue new]; });
    return queue;
}
@end

@interface ProgressObserver : NSObject
@property BOOL expectsPackageQueueCompletion;
@property NSUInteger completionCount;
- (void)registerCompletionObserver;
- (void)didReceiveCompleteNotification:(NSNotification *)note;
@end
@implementation ProgressObserver
- (void)registerCompletionObserver {
// PRODUCTION_REGISTRATION
}
- (void)didReceiveCompleteNotification:(NSNotification *)note {
    (void)note;
    self.completionCount++;
}
@end

static BOOL RunAutomatic(BOOL result) {
    NSString *completionMessage = result ? @"automatic success" : @"automatic failure";
    BOOL updateRepairOK = result;
    BOOL hailMaryApplicable = NO;
    BOOL hailMaryOK = NO;
    BOOL attempted = YES;
// PRODUCTION_COMPLETION
}

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "check failed: %s\n", #condition); exit(1); \
} } while (0)

int main(void) {
    @autoreleasepool {
        NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
        ProgressObserver *foreground = [ProgressObserver new];
        [foreground registerCompletionObserver];
        ProgressObserver *queue = [ProgressObserver new];
        queue.expectsPackageQueueCompletion = YES;
        [queue registerCompletionObserver];
        NSMutableArray<NSNumber *> *results = [NSMutableArray new];
        NSMutableArray<NSString *> *messages = [NSMutableArray new];
        __block NSUInteger queueRefreshes = 0;
        id automaticToken = [center addObserverForName:kSettingsSnowBoardAutomaticRepairDidCompleteNotification
            object:nil queue:nil usingBlock:^(NSNotification *note) {
                [results addObject:note.userInfo[kSettingsActionsDidCompleteSuccessKey]];
                [messages addObject:note.userInfo[kSettingsActionsDidCompleteMessageKey]];
            }];
        id refreshToken = [center addObserverForName:PackageQueueDidChangeNotification
            object:PackageQueue.sharedQueue queue:nil usingBlock:^(NSNotification *note) {
                (void)note;
                queueRefreshes++;
            }];
        CHECK(RunAutomatic(NO));
        CHECK(RunAutomatic(YES));
        dispatch_async(dispatch_get_main_queue(), ^{
            CHECK(([results isEqualToArray:@[@NO, @YES]]));
            CHECK(([messages isEqualToArray:@[@"automatic failure", @"automatic success"]]));
            CHECK(foreground.completionCount == 0);
            CHECK(queue.completionCount == 0);
            CHECK(cacheInvalidations == 2 && logUploads == 2 && queueRefreshes == 2);
            [center postNotificationName:kSettingsActionsDidCompleteNotification object:nil];
            CHECK(foreground.completionCount == 1 && queue.completionCount == 0);
            [center postNotificationName:PackageQueueExecutionDidCompleteNotification
                                 object:PackageQueue.sharedQueue];
            CHECK(foreground.completionCount == 1 && queue.completionCount == 1);
            [center removeObserver:automaticToken];
            [center removeObserver:refreshToken];
            exit(0);
        });
        dispatch_main();
    }
}
'''


if __name__ == "__main__":
    unittest.main()
