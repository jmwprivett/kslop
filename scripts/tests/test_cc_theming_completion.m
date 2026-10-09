#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <stdarg.h>

NSString * const kSettingsActionsDidCompleteNotification = @"SettingsActionsDidCompleteNotification";
NSString * const kSettingsActionsDidCompleteSuccessKey = @"success";
NSString * const kSettingsActionsDidCompleteMessageKey = @"message";

@interface PackageQueue : NSObject
@property BOOL commitInFlight;
@property BOOL hasDurableTransaction;
@property NSUInteger pendingCount;
+ (instancetype)sharedQueue;
@end
@implementation PackageQueue
+ (instancetype)sharedQueue { static PackageQueue *queue; if (!queue) queue = [self new]; return queue; }
@end

static BOOL locked, lab, guest, krw, throwReport;
static NSUInteger releases, applyCalls, restoreCalls, completions;
static NSDictionary *fixtureReport, *lastCompletion;
static NSURL *reportURL;
static BOOL expectedLockedAtCompletion;

static void Check(BOOL condition, NSString *message)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message.UTF8String); exit(1); }
}
static BOOL settings_try_claim_actions_lock(const char *label, const char *message)
{
    (void)label; (void)message;
    if (locked) return NO;
    locked = YES;
    return YES;
}
static void settings_release_actions_lock(void) { Check(locked, @"release owned lock"); locked = NO; releases++; }
static BOOL remote_call_lab_backend_opted_in(void) { return lab; }
static BOOL cnd_lab_vphone_guest(void) { return guest; }
static BOOL settings_ensure_kexploit(void) { return krw; }
static NSDictionary *Report(void)
{
    if (throwReport) [NSException raise:@"FixtureFailure" format:@"fixture failure"];
    return fixtureReport;
}
static NSDictionary *CNDCCThemingFileBackingApply(void) { applyCalls++; return Report(); }
static NSDictionary *CNDCCThemingFileBackingRestore(void) { restoreCalls++; return Report(); }
static NSURL *settings_cc_theming_production_report_url(void) { return reportURL; }
static void log_user(const char *format, ...) { (void)format; }

// Compiles the actual production runner and main-queue notification helper.
#include "cc_completion_runner.inc"

static void Reset(NSURL *url)
{
    locked = lab = guest = throwReport = NO;
    krw = YES;
    expectedLockedAtCompletion = NO;
    releases = applyCalls = restoreCalls = completions = 0;
    lastCompletion = nil;
    reportURL = url;
    fixtureReport = @{@"success": @YES, @"requiresSpringBoardRefresh": @YES};
    PackageQueue *queue = [PackageQueue sharedQueue];
    queue.commitInFlight = queue.hasDurableTransaction = NO;
    queue.pendingCount = 0;
}

static void Run(BOOL apply, BOOL success, NSUInteger expectedCalls, NSUInteger expectedReleases, NSString *message)
{
    settings_run_cc_theming_file_resources(apply);
    Check(completions == 0, @"completion delivery stays asynchronous");
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:1];
    while (!completions && deadline.timeIntervalSinceNow > 0)
        [[NSRunLoop mainRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    Check(completions == 1, @"exactly one terminal notification");
    Check([lastCompletion[@"success"] boolValue] == success, @"accurate terminal success");
    Check([lastCompletion[@"message"] containsString:message], @"useful terminal message");
    Check(applyCalls + restoreCalls == expectedCalls, @"preflight blocks operation");
    Check(releases == expectedReleases, @"only owned lock released");
    Check(apply ? restoreCalls == 0 : applyCalls == 0, @"correct apply/restore dispatch");
    [[NSRunLoop mainRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    Check(completions == 1, @"no duplicate completion after run loop drains");
}

int main(int argc, const char **argv)
{
    @autoreleasepool {
        Check(argc == 2, @"fixture directory supplied");
        NSURL *root = [NSURL fileURLWithPath:@(argv[1]) isDirectory:YES];
        NSURL *url = [root URLByAppendingPathComponent:@"report.json"];
        id observer = [[NSNotificationCenter defaultCenter] addObserverForName:kSettingsActionsDidCompleteNotification
            object:nil queue:nil usingBlock:^(NSNotification *note) {
                Check(NSThread.isMainThread, @"UI completion delivered on main thread");
                Check(locked == expectedLockedAtCompletion, @"completion occurs after own lock release");
                completions++;
                lastCompletion = note.userInfo;
            }];

        Reset(url); Run(YES, YES, 1, 1, @"Pulsar Control Center resources installed");
        Reset(url); Run(NO, YES, 1, 1, @"Stock Control Center resources restored");
        Reset(url); fixtureReport = @{@"success": @YES}; Run(YES, YES, 1, 1, @"resources installed");
        Reset(url); fixtureReport = @{@"success": @YES}; Run(NO, YES, 1, 1, @"resources restored");
        Reset(url); locked = expectedLockedAtCompletion = YES; Run(YES, NO, 0, 0, @"blocked");
        Reset(url); lab = YES; Run(YES, NO, 0, 1, @"physical device");
        Reset(url); guest = YES; Run(YES, NO, 0, 1, @"physical device");
        Reset(url); [PackageQueue sharedQueue].commitInFlight = YES; Run(YES, NO, 0, 1, @"package queue");
        Reset(url); [PackageQueue sharedQueue].hasDurableTransaction = YES; Run(YES, NO, 0, 1, @"package queue");
        Reset(url); [PackageQueue sharedQueue].pendingCount = 1; Run(YES, NO, 0, 1, @"package queue");
        Reset(url); krw = NO; Run(YES, NO, 0, 1, @"primitives are unavailable");
        Reset(url); fixtureReport = @{@"success": @NO, @"rollbackComplete": @YES,
            @"failureReason": @"Catalog mismatch", @"failed": @[@{@"path": @"fixture.car", @"reason": @"Mismatch"}]};
        Run(YES, NO, 1, 1, @"incomplete");
        Reset(nil); Run(YES, NO, 1, 1, @"report could not be saved");
        Reset([url URLByAppendingPathComponent:@"invalid.json"]); Run(YES, NO, 1, 1, @"report could not be saved");
        Reset(url); throwReport = YES; Run(YES, NO, 1, 1, @"unexpectedly");
        Reset(url); throwReport = YES; Run(NO, NO, 1, 1, @"unexpectedly");
        Reset(url); fixtureReport = nil; Run(YES, NO, 1, 1, @"incomplete");

        [[NSNotificationCenter defaultCenter] removeObserver:observer];
        puts("17 completion scenarios passed");
    }
    return 0;
}
