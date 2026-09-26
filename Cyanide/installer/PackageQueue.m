//
//  PackageQueue.m
//  Cyanide
//

#import "PackageQueue.h"
#import "PackageCatalog.h"
#import "../SettingsViewController.h"

NSString * const PackageQueueDidChangeNotification = @"PackageQueueDidChangeNotification";

@interface PackageQueue ()
@property (nonatomic, strong) NSMutableArray<Package *> *installs;
@property (nonatomic, strong) NSMutableArray<Package *> *uninstalls;
@end

static BOOL PackageRequiresThemerTheme(Package *package)
{
    return [package.identifier isEqualToString:@"com.darksword.themer"];
}

static BOOL PackageRequiresFontFamily(Package *package)
{
    return package.kind == PackageInstallKindFontChanger;
}

static BOOL PackageCanQueueInstall(Package *package)
{
    if (package.kind == PackageInstallKindDirectTool) return NO;
    if (PackageRequiresThemerTheme(package)) return settings_themer_has_selected_theme();
    if (PackageRequiresFontFamily(package)) return settings_font_changer_has_regular_font();
    return YES;
}

static BOOL PackageRequiresExclusiveRespringEdit(Package *package)
{
    return package.kind == PackageInstallKindHideHomeBar ||
           package.kind == PackageInstallKindFontChanger;
}

@implementation PackageQueue

+ (instancetype)sharedQueue
{
    static PackageQueue *q;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ q = [[PackageQueue alloc] init]; });
    return q;
}

- (instancetype)init
{
    if ((self = [super init])) {
        _installs   = [NSMutableArray array];
        _uninstalls = [NSMutableArray array];
    }
    return self;
}

- (NSArray<Package *> *)queuedInstalls
{
    NSMutableArray<Package *> *out = [self.installs mutableCopy];
    if ([self hasExplicitExclusiveRespringEditQueued]) {
        NSMutableArray<Package *> *onlyExclusive = [NSMutableArray array];
        for (Package *p in out) {
            if (PackageRequiresExclusiveRespringEdit(p)) [onlyExclusive addObject:p];
        }
        return onlyExclusive;
    }

    for (Package *p in [PackageCatalog allPackages]) {
        if (p.isInstallDisabled) continue;
        if (!PackageCanQueueInstall(p)) continue;
        if (!p.isQueuedForApply) continue;
        if ([self packageInArray:out matching:p]) continue;
        if ([self packageInArray:self.uninstalls matching:p]) continue;
        [out addObject:p];
    }
    return out;
}

- (NSArray<Package *> *)queuedUninstalls
{
    if (![self hasExplicitExclusiveRespringEditQueued]) return [self.uninstalls copy];

    NSMutableArray<Package *> *onlyExclusive = [NSMutableArray array];
    for (Package *p in self.uninstalls) {
        if (PackageRequiresExclusiveRespringEdit(p)) [onlyExclusive addObject:p];
    }
    return onlyExclusive;
}
- (NSInteger)pendingCount                { return (NSInteger)(self.queuedInstalls.count + self.queuedUninstalls.count); }

- (PackageQueueIntent)intentForPackage:(Package *)package
{
    if (package.kind == PackageInstallKindDirectTool) return PackageQueueIntentNone;
    BOOL exclusiveQueued = [self hasExplicitExclusiveRespringEditQueued];
    BOOL isExclusive = PackageRequiresExclusiveRespringEdit(package);
    if (exclusiveQueued && !isExclusive) return PackageQueueIntentNone;
    if (!package.isInstalled && !PackageCanQueueInstall(package)) return PackageQueueIntentNone;
    if ([self packageInArray:self.installs matching:package])   return PackageQueueIntentInstall;
    if ([self packageInArray:self.uninstalls matching:package]) return PackageQueueIntentUninstall;
    if (package.isInstallDisabled) return PackageQueueIntentNone;
    if (package.isQueuedForApply) return PackageQueueIntentInstall;
    return PackageQueueIntentNone;
}

- (Package *)packageInArray:(NSArray<Package *> *)array matching:(Package *)package
{
    for (Package *p in array) {
        if ([p.identifier isEqualToString:package.identifier]) return p;
    }
    return nil;
}

- (BOOL)hasExplicitExclusiveRespringEditQueued
{
    for (Package *p in self.installs) {
        if (PackageRequiresExclusiveRespringEdit(p)) return YES;
    }
    for (Package *p in self.uninstalls) {
        if (PackageRequiresExclusiveRespringEdit(p)) return YES;
    }
    return NO;
}

- (NSInteger)pendingCountExcludingPackage:(Package *)package
{
    NSInteger count = 0;
    for (Package *p in self.queuedInstalls) {
        if (package && [p.identifier isEqualToString:package.identifier]) continue;
        count++;
    }
    for (Package *p in self.queuedUninstalls) {
        if (package && [p.identifier isEqualToString:package.identifier]) continue;
        count++;
    }
    return count;
}

- (Package *)queuedExclusiveRespringEditExcludingPackage:(Package *)package
{
    for (Package *p in self.installs) {
        if (package && [p.identifier isEqualToString:package.identifier]) continue;
        if (PackageRequiresExclusiveRespringEdit(p)) return p;
    }
    for (Package *p in self.uninstalls) {
        if (package && [p.identifier isEqualToString:package.identifier]) continue;
        if (PackageRequiresExclusiveRespringEdit(p)) return p;
    }
    return nil;
}

- (BOOL)canQueueIntent:(PackageQueueIntent)intent
            forPackage:(Package *)package
                reason:(NSString * _Nullable * _Nullable)reason
{
    if (reason) *reason = nil;
    if (!package) return NO;
    if (intent == PackageQueueIntentNone) return YES;

    BOOL isExclusive = PackageRequiresExclusiveRespringEdit(package);
    if (isExclusive && [self pendingCountExcludingPackage:package] > 0) {
        if (reason) {
            *reason = [NSString stringWithFormat:@"%@ changes system files and needs a respring right after. Clear the current queue, run %@ by itself, respring, then queue your other tweaks.",
                       package.name, package.name];
        }
        return NO;
    }

    Package *queuedExclusive = [self queuedExclusiveRespringEditExcludingPackage:package];
    if (!isExclusive && queuedExclusive) {
        if (reason) {
            *reason = [NSString stringWithFormat:@"%@ is already waiting in the queue and must run by itself. Apply or remove %@ first, then queue other tweaks after the respring.",
                       queuedExclusive.name, queuedExclusive.name];
        }
        return NO;
    }

    return YES;
}

- (void)toggleForPackage:(Package *)package
{
    PackageQueueIntent current = [self intentForPackage:package];
    if (current != PackageQueueIntentNone) {
        [self removePackage:package];
        return;
    }
    if (package.isInstallDisabled && !package.isInstalled) return;
    if (!package.isInstalled && !PackageCanQueueInstall(package)) return;
    PackageQueueIntent nextIntent = package.isInstalled ? PackageQueueIntentUninstall : PackageQueueIntentInstall;
    if (![self canQueueIntent:nextIntent forPackage:package reason:nil]) return;

    if (package.isInstalled) {
        [self.uninstalls addObject:package];
    } else {
        [self.installs addObject:package];
    }
    [self notifyChange];
}

- (void)queueIntent:(PackageQueueIntent)intent forPackage:(Package *)package
{
    if (![self canQueueIntent:intent forPackage:package reason:nil]) return;
    [self removePackage:package];
    if (intent == PackageQueueIntentInstall) {
        if (!PackageCanQueueInstall(package)) return;
        [self.installs addObject:package];
    } else if (intent == PackageQueueIntentUninstall) {
        [self.uninstalls addObject:package];
    }
    [self notifyChange];
}

- (void)removePackage:(Package *)package
{
    Package *match = [self packageInArray:self.installs matching:package];
    if (match) [self.installs removeObject:match];
    match = [self packageInArray:self.uninstalls matching:package];
    if (match) [self.uninstalls removeObject:match];
    if (package.isQueuedForApply) {
        [package applyCommittedState:NO];
    }
    [self notifyChange];
}

- (void)clear
{
    // Always fire notifyChange — observers like QueuePopupBar drive their
    // visibility off pendingCount and need a kick to re-evaluate when the
    // queue empties (e.g. after Reset All Packages drained the isQueuedForApply
    // packages via applyCommittedState:NO before clear() got a chance to act).
    NSArray<Package *> *queuedForApply = self.queuedInstalls;
    for (Package *pkg in queuedForApply) {
        if (![self packageInArray:self.installs matching:pkg] && pkg.isQueuedForApply) {
            [pkg applyCommittedState:NO];
        }
    }
    [self.installs removeAllObjects];
    [self.uninstalls removeAllObjects];
    [self notifyChange];
}

- (void)commit
{
    NSArray<Package *> *toInstall   = self.queuedInstalls;
    NSArray<Package *> *toUninstall = self.queuedUninstalls;

    // Split packages into "stateful" (toggle: just flips an NSUserDefaults
    // BOOL — fast, safe to call on main) and "heavy" (OTA / NanoRegistry —
    // run kexploit + plist write, blocking). Apply stateful inline so
    // settings_run_actions sees the right flags; dispatch heavy to a
    // background queue so the InstallProgressViewController's log can
    // actually scroll while it runs.
    NSMutableArray<Package *> *heavyInstalls   = [NSMutableArray array];
    NSMutableArray<Package *> *heavyUninstalls = [NSMutableArray array];
    BOOL needsRunActions = NO;

    for (Package *pkg in toInstall) {
        if (pkg.kind == PackageInstallKindToggle) {
            needsRunActions = YES;
            [pkg applyCommittedState:YES];
        } else {
            [heavyInstalls addObject:pkg];
        }
    }
    for (Package *pkg in toUninstall) {
        if (pkg.kind == PackageInstallKindToggle) {
            needsRunActions = YES;
            [pkg applyCommittedState:NO];
        } else {
            [heavyUninstalls addObject:pkg];
        }
    }

    [self.installs removeAllObjects];
    [self.uninstalls removeAllObjects];
    [self notifyChange];

    BOOL hasHeavy = (heavyInstalls.count + heavyUninstalls.count) > 0;

    if (!hasHeavy) {
        if (needsRunActions) {
            settings_run_pending_actions();
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                [[NSNotificationCenter defaultCenter]
                    postNotificationName:kSettingsActionsDidCompleteNotification
                                  object:nil];
            });
        }
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        for (Package *pkg in heavyInstalls)   [pkg applyCommittedState:YES];
        for (Package *pkg in heavyUninstalls) [pkg applyCommittedState:NO];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (needsRunActions) {
                settings_run_pending_actions();
            } else {
                [[NSNotificationCenter defaultCenter]
                    postNotificationName:kSettingsActionsDidCompleteNotification
                                  object:nil];
            }
        });
    });
}

- (void)notifyChange
{
    [[NSNotificationCenter defaultCenter] postNotificationName:PackageQueueDidChangeNotification
                                                        object:self];
}

@end
