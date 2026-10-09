//
//  PackageQueue.m
//  Cyanide
//

#import "PackageQueue.h"
#import "PackageCatalog.h"
#import "CNDQueuedActionCatalog.h"
#import "CNDSnowBoardRemix.h"
#import "CNDTransientAppliedState.h"
#import "../TaskRop/CNDKernelTaskBridge.h"
#import "../SettingsViewController.h"
#import "../LogTextView.h"
#import "../tweaks/snowboardlite.h"

#import <UIKit/UIKit.h>
#import <math.h>
#import <unistd.h>

NSString * const PackageQueueDidChangeNotification = @"PackageQueueDidChangeNotification";
NSString * const PackageQueueExecutionDidCompleteNotification =
    @"PackageQueueExecutionDidCompleteNotification";
NSString * const PackageQueueReadyForRespringNotification =
    @"PackageQueueReadyForRespringNotification";

static NSString * const kQueuedTransactionDirectory = @"Cyanide/Queue";
static NSString * const kQueuedTransactionFilename = @"QueuedChanges.v1.plist";
static NSString * const kSBCustomizerPackageIdentifier =
    @"com.darksword.sbcustomizer";

@interface PackageQueue ()
@property (nonatomic, strong) NSMutableArray<Package *> *installs;
@property (nonatomic, strong) NSMutableArray<Package *> *uninstalls;
@property (nonatomic, strong, nullable) CNDQueuedTransaction *transaction;
@property (nonatomic, readwrite) BOOL commitInFlight;
@property (nonatomic) BOOL waitingForSettingsCompletion;
@property (nonatomic) BOOL waitingForCoordinatedSettingsCompletion;
@property (nonatomic) BOOL resumeCoordinatorBeforeRespringAfterSettings;
@property (nonatomic, copy, nullable) NSString *settingsCompletionToken;
@property (nonatomic, copy) NSArray<NSString *> *coordinatedToggleActionIdentifiers;
@property (nonatomic) BOOL durableStoreUnavailable;
- (void)beginPendingSettingsRunForCoordinator:(BOOL)coordinated;
- (BOOL)finalizeTransientAppliedStateForTransaction:
    (CNDQueuedTransaction *)transaction;
- (BOOL)recordOrdinaryCurrentEpochStateForTransaction:
    (CNDQueuedTransaction *)transaction;
- (BOOL)prepareBoundaryOnlyTransientAppliedStateForTransaction:
    (CNDQueuedTransaction *)transaction
    springBoardPID:(pid_t)springBoardPID
    bootEpoch:(NSTimeInterval)bootEpoch
    generation:(NSString *)generation;
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
    if (package.kind == PackageInstallKindDirectTool ||
        package.kind == PackageInstallKindLockscreenGlyphs) return NO;
    if (PackageRequiresThemerTheme(package)) return settings_themer_has_selected_theme();
    if (PackageRequiresFontFamily(package)) return settings_font_changer_has_regular_font();
    return YES;
}

static NSString *CNDQueuedRecordIdentifier(Package *package, BOOL installed)
{
    return [NSString stringWithFormat:@"package:%@:%@",
        package.identifier ?: @"",
        installed ? CNDQueuedActionOperationInstall
                  : CNDQueuedActionOperationUninstall];
}

static BOOL CNDQueuedBootEpochMatches(NSTimeInterval stored,
                                      NSTimeInterval current)
{
    return stored > 0.0 && current > 0.0 &&
        fabs(stored - current) <= 5.0;
}

static CNDQueuedAction *CNDQueuedActionByCopyingExecutionState(
    CNDQueuedAction *catalogAction,
    CNDQueuedAction *sourceAction)
{
    return [[CNDQueuedAction alloc]
        initWithRecordIdentifier:catalogAction.recordIdentifier
                            kind:catalogAction.kind
               subjectIdentifier:catalogAction.subjectIdentifier
                       operation:catalogAction.operation
                           phase:catalogAction.phase
                           state:sourceAction.state
                      parameters:catalogAction.parameters
                       createdAt:sourceAction.createdAt
                       updatedAt:sourceAction.updatedAt
                       lastError:sourceAction.lastError];
}

static BOOL CNDQueuedActionIsPresentationFix(CNDQueuedAction *action)
{
    return [action.kind isEqualToString:CNDQueuedActionKindSpringBoardFixes] ||
        [action.kind isEqualToString:CNDQueuedActionKindSpotlightFixes] ||
        [action.kind isEqualToString:
            CNDQueuedActionKindSpringBoardSpotlightFixes];
}

static void CNDPackageQueueRunOnMainThreadSynchronously(
    dispatch_block_t block)
{
    if (!block) return;
    if (NSThread.isMainThread) {
        block();
    } else {
        dispatch_sync(dispatch_get_main_queue(), block);
    }
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
        _installs = [NSMutableArray array];
        _uninstalls = [NSMutableArray array];
        [self hydrateDurableTransaction];
        [[NSNotificationCenter defaultCenter]
            addObserver:self
               selector:@selector(settingsActionsDidComplete:)
                   name:kSettingsQueuedRunDidCompleteNotification
                 object:nil];
    }
    return self;
}

- (void)dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

#pragma mark - Durable transaction storage

- (NSURL *)durableTransactionURL
{
    NSURL *support = [[NSFileManager defaultManager]
        URLsForDirectory:NSApplicationSupportDirectory
               inDomains:NSUserDomainMask].firstObject;
    NSURL *directory = [support URLByAppendingPathComponent:kQueuedTransactionDirectory
                                               isDirectory:YES];
    return [directory URLByAppendingPathComponent:kQueuedTransactionFilename
                                       isDirectory:NO];
}

- (BOOL)persistDurableTransaction
{
    @synchronized (self) {
        if (self.durableStoreUnavailable) return NO;

        NSURL *url = [self durableTransactionURL];
        NSFileManager *manager = [NSFileManager defaultManager];
        if (!self.transaction) {
            if (![manager fileExistsAtPath:url.path]) return YES;
            NSError *removeError = nil;
            if (![manager removeItemAtURL:url error:&removeError]) {
                NSLog(@"[QUEUE] Could not remove completed queue transaction: %@",
                      removeError.localizedDescription);
                return NO;
            }
            return YES;
        }

        NSError *directoryError = nil;
        if (![manager createDirectoryAtURL:url.URLByDeletingLastPathComponent
               withIntermediateDirectories:YES
                                attributes:nil
                                     error:&directoryError]) {
            NSLog(@"[QUEUE] Could not create durable queue directory: %@",
                  directoryError.localizedDescription);
            return NO;
        }

        NSError *serializationError = nil;
        NSData *data = [NSPropertyListSerialization
            dataWithPropertyList:self.transaction.propertyListRepresentation
                          format:NSPropertyListBinaryFormat_v1_0
                         options:0
                           error:&serializationError];
        if (!data) {
            NSLog(@"[QUEUE] Could not encode durable queue transaction: %@",
                  serializationError.localizedDescription);
            return NO;
        }

        NSError *writeError = nil;
        if (![data writeToURL:url options:NSDataWritingAtomic error:&writeError]) {
            NSLog(@"[QUEUE] Could not atomically save queue transaction: %@",
                  writeError.localizedDescription);
            return NO;
        }
        return YES;
    }
}

- (void)hydrateDurableTransaction
{
    NSURL *url = [self durableTransactionURL];
    NSFileManager *manager = [NSFileManager defaultManager];
    if (![manager fileExistsAtPath:url.path]) return;

    NSError *readError = nil;
    NSData *data = [NSData dataWithContentsOfURL:url options:0 error:&readError];
    if (!data) {
        self.durableStoreUnavailable = YES;
        NSLog(@"[QUEUE] Durable queue exists but could not be read; leaving it untouched: %@",
              readError.localizedDescription);
        return;
    }

    NSPropertyListFormat format = NSPropertyListBinaryFormat_v1_0;
    NSError *decodeError = nil;
    id propertyList = [NSPropertyListSerialization propertyListWithData:data
                                                                options:NSPropertyListImmutable
                                                                 format:&format
                                                                  error:&decodeError];
    CNDQueuedTransaction *loaded = propertyList
        ? [CNDQueuedTransaction transactionFromPropertyList:propertyList
                                                       error:&decodeError]
        : nil;
    if (!loaded) {
        self.durableStoreUnavailable = YES;
        NSLog(@"[QUEUE] Durable queue is invalid or uses an unsupported schema; leaving it untouched: %@",
              decodeError.localizedDescription);
        return;
    }

    if (loaded.state == CNDQueuedTransactionStateCompleted) {
        NSError *removeError = nil;
        if (![manager removeItemAtURL:url error:&removeError]) {
            self.transaction = loaded;
            NSLog(@"[QUEUE] Completed durable queue could not be removed: %@",
                  removeError.localizedDescription);
        }
        return;
    }

    NSMutableDictionary<NSString *, Package *> *packagesByIdentifier =
        [NSMutableDictionary dictionary];
    for (Package *package in [PackageCatalog allPackagesIncludingExperimental]) {
        if (package.identifier.length > 0) {
            packagesByIdentifier[package.identifier] = package;
        }
    }

    BOOL recoveredInterruptedAction = NO;
    BOOL migratedAdaptiveAction = NO;
    BOOL unresolvedAction = NO;
    NSMutableArray<CNDQueuedAction *> *normalizedActions =
        [NSMutableArray arrayWithCapacity:loaded.actions.count];
    for (CNDQueuedAction *action in loaded.actions) {
        NSArray<CNDQueuedAction *> *expandedActions = @[ action ];
        if ([action.kind isEqualToString:
                CNDQueuedActionKindSpringBoardSpotlightFixes]) {
            BOOL transparency = [action.parameters[
                CNDQueuedActionParameterTransparencyEnabled] boolValue];
            NSMutableArray<CNDQueuedAction *> *expanded =
                [NSMutableArray arrayWithCapacity:2];
            if (transparency) {
                [expanded addObject:CNDQueuedActionByCopyingExecutionState(
                    CNDQueuedSpringBoardFixesAction(YES), action)];
            }
            [expanded addObject:CNDQueuedActionByCopyingExecutionState(
                CNDQueuedSpotlightFixesAction(transparency), action)];
            expandedActions = expanded;
            migratedAdaptiveAction = YES;
        }

        for (CNDQueuedAction *expandedAction in expandedActions) {
            CNDQueuedAction *normalized = expandedAction;
            if (normalized.state == CNDQueuedActionStateRunning) {
                normalized = [normalized
                    actionByUpdatingState:CNDQueuedActionStatePending
                               lastError:@"Recovered after an interrupted queue run."];
                recoveredInterruptedAction = YES;
            }
            if (normalized.phase == CNDQueuedActionPhaseAfterRespring &&
                CNDQueuedActionIsPresentationFix(normalized)) {
                // Early schema-v1 builds encoded presentation repair as
                // strictly post-respring. Preserve its intent while restoring
                // the adaptive phase used by both independent target actions.
                normalized = [[CNDQueuedAction alloc]
                    initWithRecordIdentifier:normalized.recordIdentifier
                                        kind:normalized.kind
                           subjectIdentifier:normalized.subjectIdentifier
                                   operation:normalized.operation
                                       phase:CNDQueuedActionPhaseAutomatic
                                       state:normalized.state
                                  parameters:normalized.parameters
                                   createdAt:normalized.createdAt
                                   updatedAt:normalized.updatedAt
                                   lastError:normalized.lastError];
                migratedAdaptiveAction = YES;
            }
            [normalizedActions addObject:normalized];

            NSString *shapeError = nil;
            if (!CNDQueuedActionHasSupportedShape(normalized, &shapeError)) {
                unresolvedAction = YES;
                NSLog(@"[QUEUE] Keeping unsupported durable action %@ for diagnosis: %@",
                      normalized.recordIdentifier, shapeError);
                continue;
            }
            if (![normalized.kind isEqualToString:CNDQueuedActionKindPackage]) {
                continue;
            }
            if (normalized.state == CNDQueuedActionStateSucceeded) {
                continue;
            }
            Package *package = packagesByIdentifier[normalized.subjectIdentifier];
            if (!package) {
                unresolvedAction = YES;
                NSLog(@"[QUEUE] Keeping unresolved durable package action %@ for diagnosis.",
                      normalized.recordIdentifier);
                continue;
            }
            if ([normalized.operation isEqualToString:
                    CNDQueuedActionOperationInstall]) {
                if (![self packageInArray:self.installs matching:package]) {
                    [self.installs addObject:package];
                }
            } else if ([normalized.operation isEqualToString:
                           CNDQueuedActionOperationUninstall]) {
                if (![self packageInArray:self.uninstalls matching:package]) {
                    [self.uninstalls addObject:package];
                }
            } else {
                unresolvedAction = YES;
                NSLog(@"[QUEUE] Keeping durable action with unsupported operation %@ for diagnosis.",
                      normalized.operation);
            }
        }
    }

    CNDQueuedTransactionState normalizedState = loaded.state;
    NSString *recoveryError = loaded.lastError;
    if (loaded.state == CNDQueuedTransactionStateRunningBeforeRespring ||
        loaded.state == CNDQueuedTransactionStateRunningAfterRespring ||
        recoveredInterruptedAction) {
        normalizedState = CNDQueuedTransactionStateFailed;
        recoveryError = @"Cyanide exited while this queue was running. The unfinished actions are ready to retry.";
    }
    self.transaction = [loaded transactionByUpdatingState:normalizedState
                                                   actions:normalizedActions
                                                 lastError:recoveryError];

    if (unresolvedAction) {
        // Do not let a newer binary overwrite an action it cannot interpret.
        self.durableStoreUnavailable = YES;
        return;
    }

    BOOL everyActionSucceeded = normalizedActions.count > 0;
    for (CNDQueuedAction *action in normalizedActions) {
        if (action.state != CNDQueuedActionStateSucceeded) {
            everyActionSucceeded = NO;
            break;
        }
    }
    NSArray<CNDQueuedAction *> *remainingAfterRespring =
        CNDQueuedActionsForExecutionPhase(
            normalizedActions, CNDQueuedActionPhaseAfterRespring, YES);
    BOOL staleBoundaryOnlyContinuation =
        loaded.preRespringSpringBoardPID > 1 && everyActionSucceeded &&
        remainingAfterRespring.count == 0;
    if (staleBoundaryOnlyContinuation &&
        [self prepareBoundaryOnlyTransientAppliedStateForTransaction:
            self.transaction
            springBoardPID:loaded.preRespringSpringBoardPID
            bootEpoch:loaded.bootEpoch
            generation:loaded.krwGenerationIdentifier]) {
        // Migrate a queue written by the old coordinator: all requested work
        // already succeeded, so retain only the authorized PID-adoption marker
        // and remove the synthetic empty post-respring continuation.
        self.transaction = [self.transaction
            transactionByUpdatingState:CNDQueuedTransactionStateCompleted
                                 actions:normalizedActions
                               lastError:nil];
        if ([self persistDurableTransaction]) {
            CNDQueuedTransaction *completed = self.transaction;
            self.transaction = nil;
            if (![self persistDurableTransaction]) self.transaction = completed;
        }
        return;
    }

    BOOL interruptedTransaction =
        loaded.state == CNDQueuedTransactionStateRunningBeforeRespring ||
        loaded.state == CNDQueuedTransactionStateRunningAfterRespring;
    BOOL allActionsSucceeded = interruptedTransaction && normalizedActions.count > 0;
    BOOL coordinatorCompletionPending =
        loaded.preRespringSpringBoardPID > 1;
    for (CNDQueuedAction *action in normalizedActions) {
        if (action.phase != CNDQueuedActionPhaseAutomatic) {
            coordinatorCompletionPending = YES;
        }
        if (action.state != CNDQueuedActionStateSucceeded) {
            allActionsSucceeded = NO;
        }
    }
    if (allActionsSucceeded && !coordinatorCompletionPending) {
        // An ordinary queue with no process boundary can be closed from its
        // durable checkpoints. A coordinated queue must instead retry
        // completeCoordinator so its carried ACTIVE state is finalized before
        // the transaction file is removed.
        self.transaction = [self.transaction
            transactionByUpdatingState:CNDQueuedTransactionStateCompleted
                                 actions:normalizedActions
                               lastError:nil];
        if ([self persistDurableTransaction]) {
            CNDQueuedTransaction *completed = self.transaction;
            self.transaction = nil;
            if (![self persistDurableTransaction]) self.transaction = completed;
        }
        return;
    }
    if (recoveredInterruptedAction || migratedAdaptiveAction ||
        normalizedState != loaded.state) {
        [self persistDurableTransaction];
    }
}

- (CNDQueuedTransaction *)durableTransaction
{
    @synchronized (self) {
        return self.transaction;
    }
}

- (BOOL)hasDurableTransaction
{
    @synchronized (self) {
        return self.transaction != nil || self.durableStoreUnavailable;
    }
}

- (BOOL)transactionExecutionHasStarted
{
    @synchronized (self) {
        return self.transaction &&
            self.transaction.state != CNDQueuedTransactionStateCollecting;
    }
}

- (BOOL)transactionNeedsCoordinator
{
    @synchronized (self) {
        if (!self.transaction) return NO;
        if (self.transaction.state == CNDQueuedTransactionStateCompleted) {
            return NO;
        }
        if (self.transaction.preRespringSpringBoardPID > 1 ||
            self.transaction.state == CNDQueuedTransactionStateAwaitingRespring ||
            self.transaction.state == CNDQueuedTransactionStateReadyAfterRespring ||
            self.transaction.state == CNDQueuedTransactionStateRunningAfterRespring ||
            CNDQueuedActionsRequireRespring(self.transaction.actions)) {
            return YES;
        }
        // A completed pre-respring mutation still needs its boundary even if
        // the PID checkpoint itself failed on the prior attempt.
        for (CNDQueuedAction *action in self.transaction.actions) {
            if (![action.kind isEqualToString:CNDQueuedActionKindPackage] &&
                action.state != CNDQueuedActionStateSucceeded) return YES;
            if (action.phase != CNDQueuedActionPhaseAutomatic) return YES;
        }
        return NO;
    }
}

- (CNDQueuedAction *)existingActionWithRecordIdentifier:(NSString *)identifier
{
    for (CNDQueuedAction *action in self.transaction.actions) {
        if ([action.recordIdentifier isEqualToString:identifier]) return action;
    }
    return nil;
}

- (CNDQueuedAction *)actionForPackage:(Package *)package installed:(BOOL)installed
{
    CNDQueuedAction *existing = [self existingActionWithRecordIdentifier:
        CNDQueuedRecordIdentifier(package, installed)];
    if (existing.state == CNDQueuedActionStateSucceeded) return existing;
    return CNDQueuedActionForPackage(package, installed);
}

- (NSArray<CNDQueuedAction *> *)actionsForInstalls:(NSArray<Package *> *)installs
                                        uninstalls:(NSArray<Package *> *)uninstalls
{
    NSMutableArray<CNDQueuedAction *> *actions = [NSMutableArray array];
    NSMutableSet<NSString *> *included = [NSMutableSet set];
    for (CNDQueuedAction *action in self.transaction.actions) {
        BOOL standalone = ![action.kind isEqualToString:
            CNDQueuedActionKindPackage];
        if (!standalone && action.state != CNDQueuedActionStateSucceeded) {
            continue;
        }
        [actions addObject:action];
        [included addObject:action.recordIdentifier];
    }
    for (Package *package in installs) {
        CNDQueuedAction *action = [self actionForPackage:package installed:YES];
        if (![included containsObject:action.recordIdentifier]) {
            [actions addObject:action];
            [included addObject:action.recordIdentifier];
        }
    }
    for (Package *package in uninstalls) {
        CNDQueuedAction *action = [self actionForPackage:package installed:NO];
        if (![included containsObject:action.recordIdentifier]) {
            [actions addObject:action];
            [included addObject:action.recordIdentifier];
        }
    }
    return actions;
}

- (BOOL)saveCollectingTransaction
{
    @synchronized (self) {
        BOOL hasStandaloneAction = NO;
        for (CNDQueuedAction *action in self.transaction.actions) {
            if (![action.kind isEqualToString:CNDQueuedActionKindPackage] &&
                action.state != CNDQueuedActionStateSucceeded) {
                hasStandaloneAction = YES;
                break;
            }
        }
        if (self.installs.count == 0 && self.uninstalls.count == 0 &&
            !hasStandaloneAction) {
            self.transaction = nil;
            return [self persistDurableTransaction];
        }
        NSArray<CNDQueuedAction *> *actions =
            [self actionsForInstalls:self.installs uninstalls:self.uninstalls];
        if (self.transaction) {
            self.transaction = [self.transaction
                transactionByUpdatingState:CNDQueuedTransactionStateCollecting
                                     actions:actions
                                   lastError:nil];
        } else {
            self.transaction =
                [CNDQueuedTransaction collectingTransactionWithActions:actions];
        }
        return [self persistDurableTransaction];
    }
}

- (BOOL)prepareTransactionForInstalls:(NSArray<Package *> *)installs
                           uninstalls:(NSArray<Package *> *)uninstalls
{
    @synchronized (self) {
        NSArray<CNDQueuedAction *> *actions =
            [self actionsForInstalls:installs uninstalls:uninstalls];
        if (self.transaction) {
            self.transaction = [self.transaction
                transactionByUpdatingState:CNDQueuedTransactionStateRunningBeforeRespring
                                     actions:actions
                                   lastError:nil];
        } else {
            CNDQueuedTransaction *collecting =
                [CNDQueuedTransaction collectingTransactionWithActions:actions];
            self.transaction = [collecting
                transactionByUpdatingState:CNDQueuedTransactionStateRunningBeforeRespring
                                     actions:actions
                                   lastError:nil];
        }
        return [self persistDurableTransaction];
    }
}

- (BOOL)updateActionForPackage:(Package *)package
                     installed:(BOOL)installed
                         state:(CNDQueuedActionState)state
                     lastError:(NSString *)lastError
{
    @synchronized (self) {
        NSString *recordIdentifier = CNDQueuedRecordIdentifier(package, installed);
        NSMutableArray<CNDQueuedAction *> *actions =
            [self.transaction.actions mutableCopy];
        NSUInteger index = [actions indexOfObjectPassingTest:
            ^BOOL(CNDQueuedAction *action, NSUInteger idx, BOOL *stop) {
                (void)idx; (void)stop;
                return [action.recordIdentifier isEqualToString:recordIdentifier];
            }];
        if (index == NSNotFound) return NO;
        CNDQueuedAction *current = actions[index];
        if (current.state == CNDQueuedActionStateSucceeded) return YES;
        actions[index] = [current actionByUpdatingState:state lastError:lastError];
        self.transaction = [self.transaction
            transactionByUpdatingState:self.transaction.state
                                 actions:actions
                               lastError:self.transaction.lastError];
        return [self persistDurableTransaction];
    }
}

- (BOOL)actionAlreadySucceededForPackage:(Package *)package installed:(BOOL)installed
{
    @synchronized (self) {
        CNDQueuedAction *action = [self existingActionWithRecordIdentifier:
            CNDQueuedRecordIdentifier(package, installed)];
        return action.state == CNDQueuedActionStateSucceeded;
    }
}

#pragma mark - Queue contents

- (NSArray<Package *> *)queuedInstalls
{
    NSMutableArray<Package *> *out = nil;
    NSArray<Package *> *uninstalls = nil;
    @synchronized (self) {
        out = [self.installs mutableCopy];
        uninstalls = [self.uninstalls copy];
    }
    for (Package *package in [PackageCatalog allPackages]) {
        if (package.isInstallDisabled) continue;
        if (!PackageCanQueueInstall(package)) continue;
        if (!package.isQueuedForApply) continue;
        if ([self packageInArray:out matching:package]) continue;
        if ([self packageInArray:uninstalls matching:package]) continue;
        [out addObject:package];
    }
    return out;
}

- (NSArray<Package *> *)queuedUninstalls
{
    @synchronized (self) {
        return [self.uninstalls copy];
    }
}

- (NSArray<CNDQueuedAction *> *)queuedStandaloneActions
{
    @synchronized (self) {
        NSMutableArray<CNDQueuedAction *> *actions = [NSMutableArray array];
        for (CNDQueuedAction *action in self.transaction.actions) {
            if ([action.kind isEqualToString:CNDQueuedActionKindPackage] ||
                action.state == CNDQueuedActionStateSucceeded) {
                continue;
            }
            [actions addObject:action];
        }
        return [actions copy];
    }
}

- (NSInteger)pendingCount
{
    NSInteger count = (NSInteger)(self.queuedInstalls.count +
                                  self.queuedUninstalls.count +
                                  self.queuedStandaloneActions.count);
    // A transaction with all pre-respring actions complete still needs one
    // user-visible Continue step after the process boundary.
    if (count == 0 && [self transactionNeedsCoordinator]) return 1;
    return count;
}

- (BOOL)canClear
{
    @synchronized (self) {
        if (self.commitInFlight || self.durableStoreUnavailable) return NO;
    }
    return self.pendingCount > 0;
}

- (PackageQueueIntent)intentForPackage:(Package *)package
{
    if (package.kind == PackageInstallKindDirectTool ||
        package.kind == PackageInstallKindLockscreenGlyphs)
        return PackageQueueIntentNone;
    if (!package.isInstalled && !PackageCanQueueInstall(package) &&
        package.kind != PackageInstallKindLockscreenGlyphs) return PackageQueueIntentNone;
    @synchronized (self) {
        if ([self packageInArray:self.installs matching:package]) {
            return PackageQueueIntentInstall;
        }
        if ([self packageInArray:self.uninstalls matching:package]) {
            return PackageQueueIntentUninstall;
        }
    }
    if (package.isInstallDisabled) return PackageQueueIntentNone;
    if (package.isQueuedForApply) return PackageQueueIntentInstall;
    return PackageQueueIntentNone;
}

- (Package *)packageInArray:(NSArray<Package *> *)array matching:(Package *)package
{
    for (Package *candidate in array) {
        if ([candidate.identifier isEqualToString:package.identifier]) return candidate;
    }
    return nil;
}

- (BOOL)canQueueIntent:(PackageQueueIntent)intent
            forPackage:(Package *)package
                reason:(NSString * _Nullable * _Nullable)reason
{
    if (reason) *reason = nil;
    if (!package) return NO;
    if (self.commitInFlight) {
        if (reason) *reason = @"The current queue is still applying.";
        return NO;
    }
    if ([self transactionExecutionHasStarted]) {
        if (reason) {
            *reason = @"Finish or retry the saved respring plan before editing the queue.";
        }
        return NO;
    }
    if (self.durableStoreUnavailable) {
        if (reason) {
            *reason = @"The saved queue could not be read safely. Preserve the queue file for diagnosis before trying another change.";
        }
        return NO;
    }
    if (intent == PackageQueueIntentNone) return YES;
    if (package.kind == PackageInstallKindLockscreenGlyphs) {
        if (reason) *reason = @"Use the Lockscreen Glyphs Apply or Restore control.";
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
    PackageQueueIntent next = package.isInstalled
        ? PackageQueueIntentUninstall : PackageQueueIntentInstall;
    [self queueIntent:next forPackage:package];
}

- (void)queueIntent:(PackageQueueIntent)intent forPackage:(Package *)package
{
    if (![self canQueueIntent:intent forPackage:package reason:nil]) return;

    NSArray<Package *> *oldInstalls = nil;
    NSArray<Package *> *oldUninstalls = nil;
    CNDQueuedTransaction *oldTransaction = nil;
    @synchronized (self) {
        oldInstalls = [self.installs copy];
        oldUninstalls = [self.uninstalls copy];
        oldTransaction = self.transaction;
        Package *match = [self packageInArray:self.installs matching:package];
        if (match) [self.installs removeObject:match];
        match = [self packageInArray:self.uninstalls matching:package];
        if (match) [self.uninstalls removeObject:match];

        if (intent == PackageQueueIntentInstall) {
            if (!PackageCanQueueInstall(package)) return;
            [self.installs addObject:package];
        } else if (intent == PackageQueueIntentUninstall) {
            [self.uninstalls addObject:package];
        }
        if (![self saveCollectingTransaction]) {
            self.installs = [oldInstalls mutableCopy];
            self.uninstalls = [oldUninstalls mutableCopy];
            self.transaction = oldTransaction;
            return;
        }
    }
    [self notifyChange];
}

- (void)removePackage:(Package *)package
{
    if (self.commitInFlight || self.durableStoreUnavailable ||
        [self transactionExecutionHasStarted]) return;
    BOOL removed = NO;
    NSArray<Package *> *oldInstalls = nil;
    NSArray<Package *> *oldUninstalls = nil;
    CNDQueuedTransaction *oldTransaction = nil;
    @synchronized (self) {
        oldInstalls = [self.installs copy];
        oldUninstalls = [self.uninstalls copy];
        oldTransaction = self.transaction;
        Package *match = [self packageInArray:self.installs matching:package];
        if (match) {
            [self.installs removeObject:match];
            removed = YES;
        }
        match = [self packageInArray:self.uninstalls matching:package];
        if (match) {
            [self.uninstalls removeObject:match];
            removed = YES;
        }
        if (![self saveCollectingTransaction]) {
            self.installs = [oldInstalls mutableCopy];
            self.uninstalls = [oldUninstalls mutableCopy];
            self.transaction = oldTransaction;
            return;
        }
    }
    if (package.isQueuedForApply) {
        [package applyCommittedState:NO];
        removed = YES;
    }
    if (removed) [self notifyChange];
}

- (CNDQueuedAction *)standaloneActionForConflictKey:(NSString *)conflictKey
{
    if (conflictKey.length == 0) return nil;
    @synchronized (self) {
        for (CNDQueuedAction *action in self.transaction.actions) {
            if ([action.kind isEqualToString:CNDQueuedActionKindPackage] ||
                action.state == CNDQueuedActionStateSucceeded) {
                continue;
            }
            if ([CNDQueuedActionConflictKey(action) isEqualToString:conflictKey]) {
                return action;
            }
        }
        return nil;
    }
}

- (BOOL)queueStandaloneAction:(CNDQueuedAction *)action
                       reason:(NSString **)reason
{
    if (reason) *reason = nil;
    if (self.commitInFlight) {
        if (reason) *reason = @"The current queue is still applying.";
        return NO;
    }
    if ([self transactionExecutionHasStarted]) {
        if (reason) {
            *reason = @"Finish or retry the saved respring plan before editing the queue.";
        }
        return NO;
    }
    if (self.durableStoreUnavailable) {
        if (reason) {
            *reason = @"The saved queue could not be read safely. Preserve the queue file for diagnosis before trying another change.";
        }
        return NO;
    }
    NSString *shapeError = nil;
    if (!CNDQueuedActionHasSupportedShape(action, &shapeError) ||
        [action.kind isEqualToString:CNDQueuedActionKindPackage]) {
        if (reason) {
            *reason = shapeError.length > 0
                ? shapeError : @"Only catalog-backed standalone actions can use this queue entry point.";
        }
        return NO;
    }
    if (action.state != CNDQueuedActionStatePending) {
        if (reason) *reason = @"A newly queued action must be pending.";
        return NO;
    }

    CNDQueuedTransaction *oldTransaction = nil;
    @synchronized (self) {
        oldTransaction = self.transaction;
        NSString *conflictKey = CNDQueuedActionConflictKey(action);
        BOOL restoringSnowBoard =
            [action.kind isEqualToString:CNDQueuedActionKindSnowBoardRemix] &&
            [action.operation isEqualToString:
                CNDQueuedActionOperationRestoreTheme];
        NSMutableArray<CNDQueuedAction *> *actions = [NSMutableArray array];
        for (CNDQueuedAction *existing in self.transaction.actions) {
            BOOL sameConflict =
                ![existing.kind isEqualToString:CNDQueuedActionKindPackage] &&
                [CNDQueuedActionConflictKey(existing) isEqualToString:conflictKey];
            /* A pending presentation repair belongs to the themed state.
             * Replacing Apply with Restore must not preserve that independent
             * post-respring row and reinstall theme presentation hooks after
             * the persistent records have returned to stock. Keep this in
             * the same atomic queue rewrite as the Restore replacement. */
            BOOL staleThemePresentation = restoringSnowBoard &&
                CNDQueuedActionIsPresentationFix(existing);
            if (!sameConflict && !staleThemePresentation) {
                [actions addObject:existing];
            }
        }
        [actions addObject:action];
        if (self.transaction) {
            self.transaction = [self.transaction
                transactionByUpdatingState:CNDQueuedTransactionStateCollecting
                                     actions:actions
                                   lastError:nil];
        } else {
            self.transaction =
                [CNDQueuedTransaction collectingTransactionWithActions:actions];
        }
        if (![self persistDurableTransaction]) {
            self.transaction = oldTransaction;
            if (reason) *reason = @"The queued action could not be saved.";
            return NO;
        }
    }
    [self notifyChange];
    return YES;
}

- (BOOL)removeStandaloneActionForConflictKey:(NSString *)conflictKey
{
    if (conflictKey.length == 0 || self.commitInFlight ||
        self.durableStoreUnavailable || [self transactionExecutionHasStarted]) {
        return NO;
    }

    BOOL removed = NO;
    CNDQueuedTransaction *oldTransaction = nil;
    @synchronized (self) {
        oldTransaction = self.transaction;
        NSMutableArray<CNDQueuedAction *> *actions =
            [self.transaction.actions mutableCopy] ?: [NSMutableArray array];
        NSIndexSet *indexes = [actions indexesOfObjectsPassingTest:
            ^BOOL(CNDQueuedAction *action, NSUInteger index, BOOL *stop) {
                (void)index; (void)stop;
                return ![action.kind isEqualToString:CNDQueuedActionKindPackage] &&
                    [CNDQueuedActionConflictKey(action) isEqualToString:conflictKey];
            }];
        if (indexes.count == 0) return NO;
        [actions removeObjectsAtIndexes:indexes];
        self.transaction = [self.transaction
            transactionByUpdatingState:CNDQueuedTransactionStateCollecting
                                 actions:actions
                               lastError:nil];
        if (![self saveCollectingTransaction]) {
            self.transaction = oldTransaction;
            return NO;
        }
        removed = YES;
    }
    if (removed) [self notifyChange];
    return removed;
}

- (void)clear
{
    if (!self.canClear) return;

    CNDQueuedTransaction *snapshot = nil;
    @synchronized (self) { snapshot = self.transaction; }
    BOOL executionStarted = snapshot &&
        snapshot.state != CNDQueuedTransactionStateCollecting;
    // A failed post-respring presentation repair must not erase the ACTIVE
    // state of independent actions that already succeeded. Best-effort the
    // same verified transition checkpoint before discarding the remainder.
    if (executionStarted && snapshot.preRespringSpringBoardPID > 1 &&
        ![self finalizeTransientAppliedStateForTransaction:snapshot]) {
        log_user("[ACTIVE_STATE] Clear could not checkpoint completed state actions; discarding only the saved queue.\n");
    }

    // The legacy cancellation behavior is appropriate only before execution:
    // once work has started, clearing means discard the remaining plan, not
    // toggle a successfully applied package back off.
    NSArray<Package *> *queuedForApply = executionStarted
        ? @[] : self.queuedInstalls;
    NSString *transactionIdentifier =
        snapshot.transactionIdentifier ?: @"";
    NSMutableArray<Package *> *revertedPreferencePackages =
        [NSMutableArray array];
    for (Package *package in queuedForApply) {
        if (!package.isQueuedForApply) continue;
        if (![package applyCommittedState:NO]) {
            for (Package *reverted in revertedPreferencePackages) {
                (void)[reverted applyCommittedState:YES];
            }
            log_user("[QUEUE] Clear aborted because a queued package preference could not be reverted; the complete queue was retained.\n");
            return;
        }
        [revertedPreferencePackages addObject:package];
    }

    BOOL cleared = NO;
    @synchronized (self) {
        if (self.commitInFlight || self.durableStoreUnavailable ||
            self.transaction != snapshot) {
            for (Package *reverted in revertedPreferencePackages) {
                (void)[reverted applyCommittedState:YES];
            }
            log_user("[QUEUE] Clear aborted because the queue changed while preferences were being reverted; the complete queue was retained.\n");
            return;
        }
        CNDQueuedTransaction *oldTransaction = self.transaction;
        self.transaction = nil;
        if (![self persistDurableTransaction]) {
            self.transaction = oldTransaction;
            for (Package *reverted in revertedPreferencePackages) {
                (void)[reverted applyCommittedState:YES];
            }
            return;
        }
        [self.installs removeAllObjects];
        [self.uninstalls removeAllObjects];
        self.waitingForSettingsCompletion = NO;
        self.waitingForCoordinatedSettingsCompletion = NO;
        self.resumeCoordinatorBeforeRespringAfterSettings = NO;
        self.settingsCompletionToken = nil;
        self.coordinatedToggleActionIdentifiers = @[];
        cleared = YES;
    }
    if (!cleared) return;
    CNDTransientAppliedStateCancelPreparedTransition(transactionIdentifier);
    [self notifyChange];
}

#pragma mark - Commit and checkpoints

- (BOOL)checkpointTransactionState:(CNDQueuedTransactionState)state
                          lastError:(NSString *)lastError
{
    @synchronized (self) {
        if (!self.transaction) return NO;
        CNDQueuedTransaction *previous = self.transaction;
        self.transaction = [previous transactionByUpdatingState:state
                                                         actions:previous.actions
                                                       lastError:lastError];
        if (![self persistDurableTransaction]) {
            self.transaction = previous;
            return NO;
        }
        return YES;
    }
}

- (BOOL)checkpointActionIdentifier:(NSString *)recordIdentifier
                             state:(CNDQueuedActionState)state
                         lastError:(NSString *)lastError
{
    @synchronized (self) {
        if (!self.transaction || recordIdentifier.length == 0) return NO;
        NSMutableArray<CNDQueuedAction *> *actions =
            [self.transaction.actions mutableCopy];
        NSUInteger index = [actions indexOfObjectPassingTest:
            ^BOOL(CNDQueuedAction *action, NSUInteger idx, BOOL *stop) {
                (void)idx; (void)stop;
                return [action.recordIdentifier isEqualToString:recordIdentifier];
            }];
        if (index == NSNotFound) return NO;
        CNDQueuedAction *current = actions[index];
        if (current.state == CNDQueuedActionStateSucceeded &&
            state != CNDQueuedActionStateSucceeded) return YES;
        actions[index] = [current actionByUpdatingState:state
                                               lastError:lastError];
        CNDQueuedTransaction *previous = self.transaction;
        self.transaction = [previous
            transactionByUpdatingState:previous.state
                                 actions:actions
                               lastError:previous.lastError];
        if (![self persistDurableTransaction]) {
            self.transaction = previous;
            return NO;
        }
        return YES;
    }
}

- (Package *)packageForQueuedAction:(CNDQueuedAction *)action
{
    if (![action.kind isEqualToString:CNDQueuedActionKindPackage]) return nil;
    for (Package *package in [PackageCatalog allPackagesIncludingExperimental]) {
        if ([package.identifier isEqualToString:action.subjectIdentifier]) {
            NSNumber *snapshottedKind =
                action.parameters[CNDQueuedActionParameterPackageInstallKind];
            if (snapshottedKind &&
                snapshottedKind.integerValue != package.kind) return nil;
            return package;
        }
    }
    return nil;
}

- (BOOL)queuedActionRequestsInstalledState:(CNDQueuedAction *)action
{
    return [action.operation isEqualToString:CNDQueuedActionOperationInstall];
}

- (void)removePackageFromMemoryForAction:(CNDQueuedAction *)action
{
    Package *package = [self packageForQueuedAction:action];
    if (!package) return;
    BOOL installed = [self queuedActionRequestsInstalledState:action];
    @synchronized (self) {
        NSMutableArray<Package *> *array = installed
            ? self.installs : self.uninstalls;
        Package *match = [self packageInArray:array matching:package];
        if (match) [array removeObject:match];
    }
}

- (void)finishCoordinatorWithFailure:(NSString *)message
{
    NSString *failure = message.length > 0
        ? message : @"The saved respring plan failed.";
    @synchronized (self) {
        if (self.transaction) {
            NSMutableArray<CNDQueuedAction *> *actions =
                [self.transaction.actions mutableCopy];
            for (NSUInteger index = 0; index < actions.count; index++) {
                CNDQueuedAction *action = actions[index];
                if (action.state == CNDQueuedActionStateRunning) {
                    actions[index] = [action
                        actionByUpdatingState:CNDQueuedActionStateFailed
                                   lastError:failure];
                }
            }
            CNDQueuedTransaction *previous = self.transaction;
            self.transaction = [previous
                transactionByUpdatingState:CNDQueuedTransactionStateFailed
                                     actions:actions
                                   lastError:failure];
            if (![self persistDurableTransaction]) {
                self.transaction = previous;
            }
        }
        self.waitingForCoordinatedSettingsCompletion = NO;
        self.waitingForSettingsCompletion = NO;
        self.resumeCoordinatorBeforeRespringAfterSettings = NO;
        self.settingsCompletionToken = nil;
        self.coordinatedToggleActionIdentifiers = @[];
        self.commitInFlight = NO;
    }
    [self notifyChange];
    [self postCompletionWithSuccess:NO message:failure];
}

- (BOOL)prepareCoordinatorTransaction
{
    @synchronized (self) {
        NSArray<CNDQueuedAction *> *actions = [self
            actionsForInstalls:self.queuedInstalls
                    uninstalls:self.queuedUninstalls];
        CNDQueuedTransaction *previous = self.transaction;
        CNDQueuedTransaction *base = previous ?:
            [CNDQueuedTransaction collectingTransactionWithActions:actions];
        self.transaction = [base
            transactionByUpdatingState:CNDQueuedTransactionStateRunningBeforeRespring
                                 actions:actions
                               lastError:nil];
        if (![self persistDurableTransaction]) {
            self.transaction = previous;
            return NO;
        }
        return YES;
    }
}

- (BOOL)executeSnowBoardAction:(CNDQueuedAction *)action
                        reason:(NSString **)reason
{
    if (reason) *reason = nil;
    NSDictionary<NSString *, id> *result = nil;
    if ([action.operation isEqualToString:CNDQueuedActionOperationApplyTheme]) {
        NSString *queuedTheme =
            action.parameters[CNDQueuedActionParameterThemeIdentifier];
        NSString *selectedTheme = [[NSUserDefaults standardUserDefaults]
            stringForKey:kSettingsSnowBoardRemixSelectedThemeID] ?: @"";
        if (![queuedTheme isEqualToString:selectedTheme]) {
            if (reason) {
                *reason = @"The selected SnowBoard theme changed after this plan was queued. Remove and queue Apply again.";
            }
            return NO;
        }
        result = settings_apply_snowboard_remix();
    } else if ([action.operation isEqualToString:
                   CNDQueuedActionOperationRestoreTheme]) {
        result = settings_restore_all_snowboard_remix();
    }
    BOOL ok = [result[@"ok"] boolValue];
    if (!ok && reason) {
        *reason = [result[@"message"] isKindOfClass:NSString.class]
            ? result[@"message"] : @"SnowBoard Remix did not complete.";
    }
    if (result) settings_invalidate_snowboard_remix_status_cache();
    return ok;
}

- (BOOL)executeTransparencyFixAction:(CNDQueuedAction *)action
                              reason:(NSString **)reason
{
    if (reason) *reason = nil;
    BOOL apply = [action.operation isEqualToString:
        CNDQueuedActionOperationApplyTransparencyFix];
    NSDictionary<NSString *, id> *result =
        [CNDSnowBoardRemix setTransparencyFixEnabled:apply];
    BOOL ok = [result[@"ok"] boolValue];
    if (!ok && reason) {
        *reason = [result[@"message"] isKindOfClass:NSString.class]
            ? result[@"message"] : @"Transparency Fix did not complete.";
    }
    return ok;
}

- (BOOL)executeSynchronousQueuedAction:(CNDQueuedAction *)action
                                reason:(NSString **)reason
{
    if (reason) *reason = nil;
    if ([action.kind isEqualToString:CNDQueuedActionKindSnowBoardRemix]) {
        return [self executeSnowBoardAction:action reason:reason];
    }
    if ([action.kind isEqualToString:CNDQueuedActionKindTransparencyFix]) {
        return [self executeTransparencyFixAction:action reason:reason];
    }
    if ([action.kind isEqualToString:CNDQueuedActionKindPackage]) {
        Package *package = [self packageForQueuedAction:action];
        if (!package) {
            if (reason) *reason = @"A queued package no longer matches the installed catalog.";
            return NO;
        }
        BOOL installed = [self queuedActionRequestsInstalledState:action];
        BOOL ok = [package applyCommittedState:installed];
        if (!ok && reason) {
            *reason = [NSString stringWithFormat:@"%@ failed.",
                package.name ?: package.identifier];
        }
        return ok;
    }
    if (reason) *reason = @"The queued action has no bounded executor.";
    return NO;
}

- (void)runCoordinatorBeforeRespring
{
    NSString *krwFailure = nil;
    if (!settings_prepare_queued_system_actions(&krwFailure)) {
        [self finishCoordinatorWithFailure:krwFailure];
        return;
    }

    NSArray<CNDQueuedAction *> *actions = nil;
    BOOL transactionRequiresRespring = NO;
    @synchronized (self) {
        transactionRequiresRespring =
            CNDQueuedActionsRequireRespring(self.transaction.actions);
        actions = CNDQueuedActionsForExecutionPhase(
            self.transaction.actions, CNDQueuedActionPhaseBeforeRespring,
            transactionRequiresRespring);
    }
    for (CNDQueuedAction *action in actions) {
        if ([action.kind isEqualToString:CNDQueuedActionKindPackage]) {
            Package *package = [self packageForQueuedAction:action];
            if (!package) {
                [self finishCoordinatorWithFailure:
                    @"A queued package no longer matches the installed catalog."];
                return;
            }
            if (package.kind == PackageInstallKindToggle) {
                NSMutableArray<NSString *> *toggleIdentifiers =
                    [NSMutableArray array];
                for (CNDQueuedAction *candidate in actions) {
                    if (![candidate.kind isEqualToString:
                            CNDQueuedActionKindPackage] ||
                        candidate.state == CNDQueuedActionStateSucceeded) {
                        continue;
                    }
                    Package *candidatePackage =
                        [self packageForQueuedAction:candidate];
                    if (candidatePackage.kind != PackageInstallKindToggle) {
                        continue;
                    }
                    if (![self checkpointActionIdentifier:
                            candidate.recordIdentifier
                                                    state:CNDQueuedActionStateRunning
                                                lastError:nil] ||
                        ![candidatePackage applyCommittedState:
                            [self queuedActionRequestsInstalledState:candidate]]) {
                        [self finishCoordinatorWithFailure:
                            [NSString stringWithFormat:@"Could not stage %@.",
                                candidatePackage.name ?:
                                    candidatePackage.identifier]];
                        return;
                    }
                    [toggleIdentifiers addObject:candidate.recordIdentifier];
                }
                @synchronized (self) {
                    self.coordinatedToggleActionIdentifiers =
                        [toggleIdentifiers copy];
                    self.resumeCoordinatorBeforeRespringAfterSettings = YES;
                }
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self beginPendingSettingsRunForCoordinator:YES];
                });
                return;
            }
        }
        if (![self checkpointActionIdentifier:action.recordIdentifier
                                        state:CNDQueuedActionStateRunning
                                    lastError:nil]) {
            [self finishCoordinatorWithFailure:
                @"A queue checkpoint could not be saved before a system edit."];
            return;
        }
        NSString *failure = nil;
        BOOL success = CNDQueuedActionIsPresentationFix(action)
            ? [self executePresentationFixesAction:action reason:&failure]
            : [self executeSynchronousQueuedAction:action reason:&failure];
        if (![self checkpointActionIdentifier:action.recordIdentifier
                                        state:success
                                            ? CNDQueuedActionStateSucceeded
                                            : CNDQueuedActionStateFailed
                                    lastError:failure]) {
            [self finishCoordinatorWithFailure:
                @"A completed pre-respring action could not be checkpointed."];
            return;
        }
        if (!success) {
            [self finishCoordinatorWithFailure:failure];
            return;
        }
        if ([action.kind isEqualToString:CNDQueuedActionKindPackage]) {
            [self removePackageFromMemoryForAction:action];
        }
    }

    if (!transactionRequiresRespring) {
        // Adaptive standalone work uses the durable coordinator but must not
        // manufacture a process boundary when no queued change needs one.
        [self completeCoordinator];
        return;
    }

    pid_t springBoardPID = settings_current_springboard_pid();
    if (springBoardPID <= 1) {
        [self finishCoordinatorWithFailure:
            @"The pre-respring actions completed, but SpringBoard's process identity could not be recorded safely."];
        return;
    }
    NSTimeInterval bootEpoch = settings_current_boot_epoch();
    NSString *generation = [NSUUID UUID].UUIDString;
    NSString *transactionIdentifier = nil;
    @synchronized (self) {
        transactionIdentifier = self.transaction.transactionIdentifier;
    }
    CNDQueuedTransaction *boundarySnapshot = nil;
    NSArray<CNDQueuedAction *> *postRespringActions = nil;
    @synchronized (self) {
        boundarySnapshot = self.transaction;
        postRespringActions = CNDQueuedActionsForExecutionPhase(
            boundarySnapshot.actions, CNDQueuedActionPhaseAfterRespring, YES);
    }
    BOOL boundaryOnly = postRespringActions.count == 0;
    BOOL preparedTransition = boundaryOnly
        ? [self prepareBoundaryOnlyTransientAppliedStateForTransaction:
              boundarySnapshot
              springBoardPID:springBoardPID
              bootEpoch:bootEpoch
              generation:generation]
        : CNDTransientAppliedStatePrepareTransition(
              transactionIdentifier, springBoardPID, bootEpoch);
    if (!preparedTransition) {
        [self finishCoordinatorWithFailure:
            @"The transient applied-state boundary could not be saved, so Cyanide will not respring."];
        return;
    }
    BOOL savedBoundary = NO;
    @synchronized (self) {
        CNDQueuedTransaction *previous = self.transaction;
        self.transaction = [previous
            transactionByUpdatingState:boundaryOnly
                ? CNDQueuedTransactionStateCompleted
                : CNDQueuedTransactionStateAwaitingRespring
                                 actions:previous.actions
              preRespringSpringBoardPID:springBoardPID
                               bootEpoch:bootEpoch
                 krwGenerationIdentifier:generation
                               lastError:nil];
        savedBoundary = [self persistDurableTransaction];
        if (!savedBoundary) self.transaction = previous;
        if (savedBoundary) self.commitInFlight = NO;
    }
    if (!savedBoundary) {
        CNDTransientAppliedStateCancelPreparedTransition(
            transactionIdentifier);
        [self finishCoordinatorWithFailure:
            @"The restart boundary could not be saved, so Cyanide will not respring."];
        return;
    }
    log_user("[QUEUE] Pre-respring phase complete; boundary sb-pid=%d boot=%.0f generation=%s.\n",
             springBoardPID, bootEpoch, generation.UTF8String ?: "");
    if (boundaryOnly) {
        log_user("[QUEUE] No post-respring actions remain; the completed transaction will not create an empty continuation.\n");
    }
    [self notifyChange];
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter]
            postNotificationName:PackageQueueReadyForRespringNotification
                          object:self
                        userInfo:@{
                            @"springBoardPID": @(springBoardPID),
                            @"transactionIdentifier":
                                transactionIdentifier ?: @"",
                        }];
    });
}

- (BOOL)executeSpringBoardFixesAction:(CNDQueuedAction *)action
                               reason:(NSString **)reason
{
    if (reason) *reason = nil;
    BOOL transparency = [action.parameters[
        CNDQueuedActionParameterTransparencyEnabled] boolValue];
    if (!transparency) {
        if (reason) {
            *reason = @"Enable Transparent Icon Presentation before queuing SpringBoard Fixes.";
        }
        return NO;
    }

    NSDictionary *springBoard = [CNDSnowBoardRemix applySpringBoardTweaks];
    if (![springBoard[@"ok"] boolValue]) {
        if (reason) {
            *reason = [springBoard[@"message"] isKindOfClass:NSString.class]
                ? springBoard[@"message"]
                : @"SpringBoard presentation repair failed.";
        }
        return NO;
    }
    if (!CNDTransientAppliedStateSetActiveForCurrentEpoch(
            CNDTransientAppliedStateSpringBoardFixes, YES)) {
        if (reason) {
            *reason = @"SpringBoard Fixes completed, but their current-process ACTIVE state could not be saved.";
        }
        return NO;
    }
    return YES;
}

- (BOOL)executeSpotlightFixesAction:(CNDQueuedAction *)action
                             reason:(NSString **)reason
{
    if (reason) *reason = nil;
    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    BOOL transparency = [action.parameters[
        CNDQueuedActionParameterTransparencyEnabled] boolValue];
    __block UIBackgroundTaskIdentifier backgroundTask =
        UIBackgroundTaskInvalid;
    __block int backgroundTaskExpired = 0;
    __block BOOL backgroundTaskStarted = NO;
    BOOL remoteCallsSafe = YES;

    CNDPackageQueueRunOnMainThreadSynchronously(^{
        UIApplication *application = UIApplication.sharedApplication;
        backgroundTask = [application
            beginBackgroundTaskWithName:@"Cyanide Spotlight RemoteCall"
                      expirationHandler:^{
            __atomic_store_n(&backgroundTaskExpired, 1,
                             __ATOMIC_SEQ_CST);
            log_user("[SPOTLIGHT] Background execution expired before the Spotlight work completed; no further RemoteCall work will start.\n");
            UIBackgroundTaskIdentifier expiredTask = backgroundTask;
            backgroundTask = UIBackgroundTaskInvalid;
            if (expiredTask != UIBackgroundTaskInvalid) {
                [application endBackgroundTask:expiredTask];
            }
        }];
        backgroundTaskStarted = backgroundTask != UIBackgroundTaskInvalid;
    });
    if (!backgroundTaskStarted) {
        remoteCallsSafe = NO;
        [failures addObject:
            @"Cyanide could not reserve background execution for the Spotlight work."];
    }

    @try {
        NSDictionary *presentation = nil;
        if (remoteCallsSafe) {
            log_user("[SPOTLIGHT] Requesting global Spotlight presentation "
                     "and its lifetime assertion through one bounded "
                     "SpringBoard session.\n");
            presentation =
                [CNDSnowBoardRemix presentSpotlight];
            remoteCallsSafe = [presentation[@"ok"] boolValue];
            if (!remoteCallsSafe) {
                NSString *message =
                    [presentation[@"message"] isKindOfClass:NSString.class]
                        ? presentation[@"message"]
                        : @"SpringBoard could not present Spotlight and bind its lifetime assertion safely.";
                [failures addObject:message];
            }
        }

        if (transparency && remoteCallsSafe) {
            __block UIApplicationState applicationState =
                UIApplicationStateInactive;
            __block NSTimeInterval backgroundTimeRemaining = 0.0;
            __block BOOL backgroundTaskRegistered = NO;
            BOOL backgroundTaskIsLive = NO;
            BOOL applicationIsBackgrounded = NO;
            BOOL enoughBackgroundTime = NO;
            pid_t candidateSpotlightPID =
                [presentation[@"spotlightPID"] intValue];
            pid_t settledSpotlightPID = 0;
            NSUInteger stableSpotlightSamples =
                candidateSpotlightPID > 1 ? 1 : 0;
            NSError *lastIdentityError = nil;
            NSTimeInterval deadline =
                NSProcessInfo.processInfo.systemUptime + 5.0;
            while (remoteCallsSafe &&
                   NSProcessInfo.processInfo.systemUptime < deadline) {
                CNDPackageQueueRunOnMainThreadSynchronously(^{
                    UIApplication *application =
                        UIApplication.sharedApplication;
                    applicationState = application.applicationState;
                    backgroundTimeRemaining =
                        application.backgroundTimeRemaining;
                    backgroundTaskRegistered =
                        backgroundTask != UIBackgroundTaskInvalid;
                });
                backgroundTaskIsLive = backgroundTaskRegistered &&
                    __atomic_load_n(&backgroundTaskExpired,
                                    __ATOMIC_SEQ_CST) == 0;
                applicationIsBackgrounded =
                    applicationState == UIApplicationStateBackground;
                enoughBackgroundTime = backgroundTimeRemaining >= 15.0;
                if (!backgroundTaskIsLive || !enoughBackgroundTime) break;

                NSError *identityError = nil;
                pid_t observedPID =
                    CNDKernelTaskBridgeResolveProcessPID(
                        @"Spotlight", &identityError);
                lastIdentityError = identityError;
                if (observedPID > 1 &&
                    observedPID == candidateSpotlightPID) {
                    stableSpotlightSamples++;
                } else {
                    candidateSpotlightPID = observedPID;
                    stableSpotlightSamples = observedPID > 1 ? 1 : 0;
                }
                if (stableSpotlightSamples >= 2) {
                    settledSpotlightPID = candidateSpotlightPID;
                    break;
                }
                usleep(100000);
            }
            remoteCallsSafe = remoteCallsSafe && backgroundTaskIsLive &&
                enoughBackgroundTime && settledSpotlightPID > 1 &&
                stableSpotlightSamples >= 2;
            log_user("[SPOTLIGHT] lifecycle background=%d task=%s "
                     "expired=%d remaining=%.1fs pid=%d samples=%lu "
                     "safe=%d\n",
                     applicationIsBackgrounded,
                     backgroundTaskIsLive ? "live" : "unavailable",
                     __atomic_load_n(&backgroundTaskExpired,
                                     __ATOMIC_SEQ_CST),
                     backgroundTimeRemaining, settledSpotlightPID,
                     (unsigned long)stableSpotlightSamples,
                     remoteCallsSafe);
            if (!remoteCallsSafe && [presentation[@"ok"] boolValue]) {
                NSString *message = nil;
                if (!backgroundTaskIsLive) {
                    message = @"Cyanide's protected background execution expired before Spotlight became ready.";
                } else if (!enoughBackgroundTime) {
                    message = @"Cyanide did not have enough protected background execution remaining to repair Spotlight safely. Retry the action.";
                } else {
                    message = lastIdentityError.localizedDescription ?:
                        @"Spotlight opened, but its process identity did not stabilize before the bounded wait expired.";
                }
                [failures addObject:message];
            }
            if (remoteCallsSafe) {
                NSDictionary *spotlight =
                    [CNDSnowBoardRemix repairSpotlightPresentation];
                if (![spotlight[@"ok"] boolValue]) {
                    [failures addObject:
                        [spotlight[@"message"]
                            isKindOfClass:NSString.class]
                            ? spotlight[@"message"]
                            : @"Spotlight presentation repair failed."];
                }
            }
        }

        if (failures.count == 0 &&
            !CNDTransientAppliedStateSetActiveForCurrentEpoch(
                CNDTransientAppliedStateSpotlightFixes, YES)) {
            [failures addObject:
                @"Spotlight Fixes completed, but their exact Spotlight-process ACTIVE state could not be saved."];
        }
    } @finally {
        CNDPackageQueueRunOnMainThreadSynchronously(^{
            UIBackgroundTaskIdentifier task = backgroundTask;
            backgroundTask = UIBackgroundTaskInvalid;
            if (task != UIBackgroundTaskInvalid) {
                [UIApplication.sharedApplication endBackgroundTask:task];
            }
        });
    }
    if (failures.count > 0 && reason) {
        *reason = [failures componentsJoinedByString:@" "];
    }
    return failures.count == 0;
}

- (BOOL)executePresentationFixesAction:(CNDQueuedAction *)action
                                reason:(NSString **)reason
{
    if ([action.kind isEqualToString:CNDQueuedActionKindSpringBoardFixes]) {
        return [self executeSpringBoardFixesAction:action reason:reason];
    }
    if ([action.kind isEqualToString:CNDQueuedActionKindSpotlightFixes]) {
        return [self executeSpotlightFixesAction:action reason:reason];
    }
    if ([action.kind isEqualToString:
            CNDQueuedActionKindSpringBoardSpotlightFixes]) {
        BOOL transparency = [action.parameters[
            CNDQueuedActionParameterTransparencyEnabled] boolValue];
        if (transparency &&
            ![self executeSpringBoardFixesAction:action reason:reason]) {
            return NO;
        }
        return [self executeSpotlightFixesAction:action reason:reason];
    }
    if (reason) *reason = @"The presentation action has no bounded executor.";
    return NO;
}

- (BOOL)finalizeTransientAppliedStateForTransaction:
    (CNDQueuedTransaction *)snapshot
{
    if (!snapshot || snapshot.preRespringSpringBoardPID <= 1) return YES;
    NSNumber *snowBoardActive = nil;
    NSNumber *fontChangerActive = nil;
    // SBCustomizer is process-local. A replacement SpringBoard starts without
    // it unless this transaction successfully reapplied SBC after the boundary.
    NSNumber *sbCustomizerActive = @NO;
    for (CNDQueuedAction *action in snapshot.actions) {
        if (action.state != CNDQueuedActionStateSucceeded) continue;
        if ([action.kind isEqualToString:CNDQueuedActionKindSnowBoardRemix]) {
            snowBoardActive = @([action.operation isEqualToString:
                CNDQueuedActionOperationApplyTheme]);
        } else if ([action.kind isEqualToString:CNDQueuedActionKindPackage] &&
                   [action.subjectIdentifier isEqualToString:
                       @"com.darksword.font-changer"]) {
            fontChangerActive = @([action.operation isEqualToString:
                CNDQueuedActionOperationInstall]);
        } else if ([action.kind isEqualToString:CNDQueuedActionKindPackage] &&
                   [action.subjectIdentifier isEqualToString:
                       kSBCustomizerPackageIdentifier]) {
            sbCustomizerActive = @([action.operation isEqualToString:
                CNDQueuedActionOperationInstall]);
        }
    }
    return CNDTransientAppliedStateFinalizeTransition(
        snapshot.transactionIdentifier,
        snapshot.preRespringSpringBoardPID,
        settings_current_springboard_pid(),
        snapshot.bootEpoch,
        snapshot.krwGenerationIdentifier,
        snowBoardActive,
        fontChangerActive,
        sbCustomizerActive);
}

- (BOOL)prepareBoundaryOnlyTransientAppliedStateForTransaction:
    (CNDQueuedTransaction *)snapshot
    springBoardPID:(pid_t)springBoardPID
    bootEpoch:(NSTimeInterval)bootEpoch
    generation:(NSString *)generation
{
    NSNumber *snowBoardActive = nil;
    NSNumber *fontChangerActive = nil;
    for (CNDQueuedAction *action in snapshot.actions) {
        if (action.state != CNDQueuedActionStateSucceeded) continue;
        if ([action.kind isEqualToString:CNDQueuedActionKindSnowBoardRemix]) {
            snowBoardActive = @([action.operation isEqualToString:
                CNDQueuedActionOperationApplyTheme]);
        } else if ([action.kind isEqualToString:CNDQueuedActionKindPackage] &&
                   [action.subjectIdentifier isEqualToString:
                       @"com.darksword.font-changer"]) {
            fontChangerActive = @([action.operation isEqualToString:
                CNDQueuedActionOperationInstall]);
        }
    }
    return CNDTransientAppliedStatePrepareBoundaryOnlyTransition(
        snapshot.transactionIdentifier,
        springBoardPID,
        bootEpoch,
        generation,
        snowBoardActive,
        fontChangerActive);
}

- (BOOL)recordOrdinaryCurrentEpochStateForTransaction:
    (CNDQueuedTransaction *)snapshot
{
    NSNumber *sbCustomizerActive = nil;
    for (CNDQueuedAction *action in snapshot.actions) {
        if (![action.kind isEqualToString:CNDQueuedActionKindPackage] ||
            ![action.subjectIdentifier isEqualToString:
                kSBCustomizerPackageIdentifier] ||
            action.state == CNDQueuedActionStateFailed) {
            continue;
        }
        sbCustomizerActive = @([action.operation isEqualToString:
            CNDQueuedActionOperationInstall]);
    }
    if (sbCustomizerActive == nil) return YES;
    return CNDTransientAppliedStateSetActiveForCurrentEpoch(
        CNDTransientAppliedStateSBCustomizer,
        sbCustomizerActive.boolValue);
}

- (void)completeCoordinator
{
    CNDQueuedTransaction *snapshot = nil;
    @synchronized (self) { snapshot = self.transaction; }
    for (CNDQueuedAction *action in snapshot.actions) {
        if (action.state != CNDQueuedActionStateSucceeded) {
            [self finishCoordinatorWithFailure:
                @"The queue still contains an unfinished action and was not cleared."];
            return;
        }
    }
    BOOL recordedState = snapshot.preRespringSpringBoardPID > 1
        ? [self finalizeTransientAppliedStateForTransaction:snapshot]
        : [self recordOrdinaryCurrentEpochStateForTransaction:snapshot];
    if (!recordedState) {
        [self finishCoordinatorWithFailure:
            @"The SnowBoard/Font/SBCustomizer applied-state marker could not be finalized; the queue remains retryable."];
        return;
    }

    BOOL finalized = NO;
    @synchronized (self) {
        for (CNDQueuedAction *action in self.transaction.actions) {
            if (action.state != CNDQueuedActionStateSucceeded) {
                self.commitInFlight = NO;
                [self postCompletionWithSuccess:NO
                    message:@"The queue still contains an unfinished action and was not cleared."];
                return;
            }
        }
        CNDQueuedTransaction *previous = self.transaction;
        self.transaction = [previous
            transactionByUpdatingState:CNDQueuedTransactionStateCompleted
                                 actions:previous.actions
                               lastError:nil];
        finalized = [self persistDurableTransaction];
        if (finalized) {
            [self.installs removeAllObjects];
            [self.uninstalls removeAllObjects];
            CNDQueuedTransaction *completed = self.transaction;
            self.transaction = nil;
            if (![self persistDurableTransaction]) {
                self.transaction = completed;
                finalized = NO;
            }
        } else {
            self.transaction = previous;
        }
        self.commitInFlight = NO;
    }
    [self notifyChange];
    [self postCompletionWithSuccess:finalized
        message:finalized
            ? (snapshot.preRespringSpringBoardPID > 1
                ? @"Saved changes completed across the shared respring."
                : @"Saved changes completed.")
            : @"All changes ran, but the completed queue checkpoint could not be cleared."];
}

- (void)continueCoordinatorAfterRespring
{
    NSArray<CNDQueuedAction *> *actions = nil;
    @synchronized (self) {
        actions = CNDQueuedActionsForExecutionPhase(
            self.transaction.actions, CNDQueuedActionPhaseAfterRespring,
            YES);
    }
    for (CNDQueuedAction *action in actions) {
        if (CNDQueuedActionIsPresentationFix(action)) {
            CNDQueuedTransaction *snapshot = nil;
            @synchronized (self) { snapshot = self.transaction; }
            // Presentation repair is optional and independently retryable.
            // Commit successful theme/font/layout state before running it so
            // a later Spotlight failure cannot suppress ACTIVE.
            if (![self finalizeTransientAppliedStateForTransaction:snapshot]) {
                [self finishCoordinatorWithFailure:
                    @"Completed tweak state could not be checkpointed before the optional presentation repair."];
                return;
            }
        }
        if ([action.kind isEqualToString:CNDQueuedActionKindPackage]) {
            Package *package = [self packageForQueuedAction:action];
            if (!package) {
                [self finishCoordinatorWithFailure:
                    @"A queued package no longer matches the installed catalog."];
                return;
            }
            if (package.kind == PackageInstallKindToggle) {
                NSMutableArray<NSString *> *toggleIdentifiers =
                    [NSMutableArray array];
                for (CNDQueuedAction *candidate in actions) {
                    if (![candidate.kind isEqualToString:
                            CNDQueuedActionKindPackage] ||
                        candidate.state == CNDQueuedActionStateSucceeded) {
                        continue;
                    }
                    Package *candidatePackage =
                        [self packageForQueuedAction:candidate];
                    if (candidatePackage.kind != PackageInstallKindToggle) {
                        continue;
                    }
                    if (![self checkpointActionIdentifier:
                            candidate.recordIdentifier
                                                    state:CNDQueuedActionStateRunning
                                                lastError:nil] ||
                        ![candidatePackage applyCommittedState:
                            [self queuedActionRequestsInstalledState:candidate]]) {
                        [self finishCoordinatorWithFailure:
                            [NSString stringWithFormat:@"Could not stage %@.",
                                candidatePackage.name ?:
                                    candidatePackage.identifier]];
                        return;
                    }
                    [toggleIdentifiers addObject:candidate.recordIdentifier];
                }
                @synchronized (self) {
                    self.coordinatedToggleActionIdentifiers =
                        [toggleIdentifiers copy];
                    self.resumeCoordinatorBeforeRespringAfterSettings = NO;
                }
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self beginPendingSettingsRunForCoordinator:YES];
                });
                return;
            }
        }

        if (![self checkpointActionIdentifier:action.recordIdentifier
                                        state:CNDQueuedActionStateRunning
                                    lastError:nil]) {
            [self finishCoordinatorWithFailure:
                @"A post-respring checkpoint could not be saved before execution."];
            return;
        }
        NSString *failure = nil;
        BOOL success = CNDQueuedActionIsPresentationFix(action)
            ? [self executePresentationFixesAction:action reason:&failure]
            : [self executeSynchronousQueuedAction:action reason:&failure];
        if (![self checkpointActionIdentifier:action.recordIdentifier
                                        state:success
                                            ? CNDQueuedActionStateSucceeded
                                            : CNDQueuedActionStateFailed
                                    lastError:failure]) {
            [self finishCoordinatorWithFailure:
                @"A completed post-respring action could not be checkpointed."];
            return;
        }
        if (!success) {
            [self finishCoordinatorWithFailure:failure];
            return;
        }
        if ([action.kind isEqualToString:CNDQueuedActionKindPackage]) {
            [self removePackageFromMemoryForAction:action];
        }
    }
    [self completeCoordinator];
}

- (void)resumeCoordinatorAfterVerifiedRespring
{
    NSString *krwFailure = nil;
    if (!settings_prepare_queued_system_actions(&krwFailure)) {
        [self finishCoordinatorWithFailure:krwFailure];
        return;
    }
    pid_t currentPID = settings_current_springboard_pid();
    pid_t previousPID = 0;
    NSTimeInterval previousBoot = 0;
    @synchronized (self) {
        previousPID = self.transaction.preRespringSpringBoardPID;
        previousBoot = self.transaction.bootEpoch;
    }
    NSTimeInterval currentBoot = settings_current_boot_epoch();
    BOOL fullBootChanged = previousBoot > 0.0 && currentBoot > 0.0 &&
        !CNDQueuedBootEpochMatches(previousBoot, currentBoot);
    BOOL processBoundaryObserved = currentPID != previousPID || fullBootChanged;
    if (currentPID <= 1 || previousPID <= 1 ||
        !processBoundaryObserved) {
        @synchronized (self) { self.commitInFlight = NO; }
        [self notifyChange];
        [self postCompletionWithSuccess:NO
            message:currentPID == previousPID && !fullBootChanged
                ? @"SpringBoard has not restarted yet. Respring, reopen Cyanide, and continue the saved queue."
                : @"The SpringBoard restart boundary could not be verified safely."];
        return;
    }
    log_user("[QUEUE] Restart boundary verified old-sb=%d new-sb=%d old-boot=%.0f new-boot=%.0f full-boot=%d.\n",
             previousPID, currentPID, previousBoot, currentBoot,
             fullBootChanged);
    if (![self checkpointTransactionState:
            CNDQueuedTransactionStateReadyAfterRespring lastError:nil] ||
        ![self checkpointTransactionState:
            CNDQueuedTransactionStateRunningAfterRespring lastError:nil]) {
        [self finishCoordinatorWithFailure:
            @"The post-respring queue state could not be checkpointed."];
        return;
    }
    [self continueCoordinatorAfterRespring];
}

- (void)beginOrResumeCoordinator
{
    BOOL hasBoundary = NO;
    @synchronized (self) {
        hasBoundary = self.transaction.preRespringSpringBoardPID > 1;
    }
    self.commitInFlight = YES;
    [self notifyChange];
    if (hasBoundary) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            [self resumeCoordinatorAfterVerifiedRespring];
        });
        return;
    }
    if (![self prepareCoordinatorTransaction]) {
        self.commitInFlight = NO;
        [self postCompletionWithSuccess:NO
            message:@"The queue could not be saved, so no changes were started."];
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self runCoordinatorBeforeRespring];
    });
}

- (void)commit
{
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self commit]; });
        return;
    }
    if (self.commitInFlight || self.durableStoreUnavailable) return;

    if ([self transactionNeedsCoordinator]) {
        [self beginOrResumeCoordinator];
        return;
    }

    NSArray<Package *> *toInstall = self.queuedInstalls;
    NSArray<Package *> *toUninstall = self.queuedUninstalls;
    if (toInstall.count + toUninstall.count == 0) {
        [self postCompletionWithSuccess:YES message:@"No queued changes."];
        return;
    }

    self.commitInFlight = YES;
    if (![self prepareTransactionForInstalls:toInstall uninstalls:toUninstall]) {
        self.commitInFlight = NO;
        [self postCompletionWithSuccess:NO
                               message:@"The queue could not be saved, so no changes were started."];
        return;
    }
    [self notifyChange];

    NSMutableArray<NSDictionary<NSString *, id> *> *heavyActions =
        [NSMutableArray array];
    BOOL needsRunActions = NO;
    NSString *preflightFailure = nil;

    for (Package *package in toInstall) {
        if ([self actionAlreadySucceededForPackage:package installed:YES]) continue;
        if (package.kind != PackageInstallKindToggle) {
            [heavyActions addObject:@{ @"package": package, @"installed": @YES }];
            continue;
        }
        needsRunActions = YES;
        if (![self updateActionForPackage:package installed:YES
                                    state:CNDQueuedActionStateRunning
                                lastError:nil] ||
            ![package applyCommittedState:YES]) {
            preflightFailure = [NSString stringWithFormat:
                @"Could not stage %@.", package.name ?: package.identifier];
            [self updateActionForPackage:package installed:YES
                                   state:CNDQueuedActionStateFailed
                               lastError:preflightFailure];
            break;
        }
    }
    if (!preflightFailure) {
        for (Package *package in toUninstall) {
            if ([self actionAlreadySucceededForPackage:package installed:NO]) continue;
            if (package.kind != PackageInstallKindToggle) {
                [heavyActions addObject:@{ @"package": package, @"installed": @NO }];
                continue;
            }
            needsRunActions = YES;
            if (![self updateActionForPackage:package installed:NO
                                        state:CNDQueuedActionStateRunning
                                    lastError:nil] ||
                ![package applyCommittedState:NO]) {
                preflightFailure = [NSString stringWithFormat:
                    @"Could not stage %@.", package.name ?: package.identifier];
                [self updateActionForPackage:package installed:NO
                                       state:CNDQueuedActionStateFailed
                                   lastError:preflightFailure];
                break;
            }
        }
    }
    if (preflightFailure) {
        [self finishWithFailure:preflightFailure postCompletion:YES];
        return;
    }

    if (heavyActions.count == 0) {
        if (needsRunActions) {
            [self beginPendingSettingsRunForCoordinator:NO];
        } else {
            [self finishSuccessfullyPostingCompletion:YES];
        }
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *failure = nil;
        for (NSDictionary<NSString *, id> *entry in heavyActions) {
            Package *package = entry[@"package"];
            BOOL installed = [entry[@"installed"] boolValue];
            if ([self actionAlreadySucceededForPackage:package installed:installed]) continue;

            if (![self updateActionForPackage:package installed:installed
                                        state:CNDQueuedActionStateRunning
                                    lastError:nil]) {
                failure = @"A queue checkpoint could not be saved before a system edit.";
                break;
            }
            BOOL success = [package applyCommittedState:installed];
            NSString *itemError = success ? nil : [NSString stringWithFormat:
                @"%@ failed.", package.name ?: package.identifier];
            if (![self updateActionForPackage:package installed:installed
                                        state:success ? CNDQueuedActionStateSucceeded
                                                      : CNDQueuedActionStateFailed
                                    lastError:itemError]) {
                failure = @"A completed system edit could not be checkpointed.";
                break;
            }
            if (!success) {
                failure = itemError;
                break;
            }
            @synchronized (self) {
                NSMutableArray<Package *> *array = installed
                    ? self.installs : self.uninstalls;
                Package *match = [self packageInArray:array matching:package];
                if (match) [array removeObject:match];
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            if (failure) {
                [self finishWithFailure:failure postCompletion:YES];
            } else if (needsRunActions) {
                [self beginPendingSettingsRunForCoordinator:NO];
            } else {
                [self finishSuccessfullyPostingCompletion:YES];
            }
        });
    });
}

- (void)beginPendingSettingsRunForCoordinator:(BOOL)coordinated
{
    NSString *token = NSUUID.UUID.UUIDString;
    @synchronized (self) {
        self.settingsCompletionToken = token;
        self.waitingForCoordinatedSettingsCompletion = coordinated;
        self.waitingForSettingsCompletion = !coordinated;
    }
    settings_run_pending_actions_for_queue_token(token);
}

- (void)settingsActionsDidComplete:(NSNotification *)notification
{
    NSString *observedToken =
        notification.userInfo[kSettingsQueuedRunCompletionTokenKey];
    NSString *expectedToken = nil;
    @synchronized (self) {
        expectedToken = self.settingsCompletionToken;
    }
    if (expectedToken.length == 0 ||
        ![observedToken isKindOfClass:NSString.class] ||
        ![observedToken isEqualToString:expectedToken]) {
        return;
    }

    if (self.waitingForCoordinatedSettingsCompletion) {
        BOOL resumeBeforeRespring = NO;
        @synchronized (self) {
            self.waitingForCoordinatedSettingsCompletion = NO;
            self.settingsCompletionToken = nil;
            resumeBeforeRespring =
                self.resumeCoordinatorBeforeRespringAfterSettings;
            self.resumeCoordinatorBeforeRespringAfterSettings = NO;
        }
        NSNumber *successValue =
            notification.userInfo[kSettingsActionsDidCompleteSuccessKey];
        BOOL success = [successValue isKindOfClass:NSNumber.class] &&
            [successValue boolValue];
        NSString *message =
            notification.userInfo[kSettingsActionsDidCompleteMessageKey];
        NSArray<NSString *> *identifiers =
            self.coordinatedToggleActionIdentifiers ?: @[];
        self.coordinatedToggleActionIdentifiers = @[];
        if (!success) {
            [self finishCoordinatorWithFailure:message.length
                ? message : @"The queued runtime changes failed."];
            return;
        }
        for (NSString *identifier in identifiers) {
            CNDQueuedAction *action = nil;
            @synchronized (self) {
                action = [self existingActionWithRecordIdentifier:identifier];
            }
            if (![self checkpointActionIdentifier:identifier
                                            state:CNDQueuedActionStateSucceeded
                                        lastError:nil]) {
                [self finishCoordinatorWithFailure:
                    @"A completed runtime action could not be checkpointed."];
                return;
            }
            if (action) [self removePackageFromMemoryForAction:action];
        }
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            if (resumeBeforeRespring) {
                [self runCoordinatorBeforeRespring];
            } else {
                [self continueCoordinatorAfterRespring];
            }
        });
        return;
    }
    if (!self.waitingForSettingsCompletion) return;
    @synchronized (self) {
        self.waitingForSettingsCompletion = NO;
        self.settingsCompletionToken = nil;
    }
    NSNumber *successValue = notification.userInfo[kSettingsActionsDidCompleteSuccessKey];
    BOOL success = [successValue isKindOfClass:NSNumber.class] &&
        [successValue boolValue];
    NSString *message = notification.userInfo[kSettingsActionsDidCompleteMessageKey];
    if (success) {
        CNDQueuedTransaction *snapshot = nil;
        @synchronized (self) { snapshot = self.transaction; }
        if (![self recordOrdinaryCurrentEpochStateForTransaction:snapshot]) {
            [self finishWithFailure:
                @"SBCustomizer completed, but its current SpringBoard state could not be recorded."
                 postCompletion:YES];
        } else {
            [self finishSuccessfullyPostingCompletion:YES];
        }
    } else {
        [self finishWithFailure:message.length ? message : @"The queued runtime changes failed."
                 postCompletion:YES];
    }
}

- (void)finishWithFailure:(NSString *)message postCompletion:(BOOL)postCompletion
{
    @synchronized (self) {
        NSMutableArray<CNDQueuedAction *> *actions =
            [self.transaction.actions mutableCopy];
        for (NSUInteger index = 0; index < actions.count; index++) {
            CNDQueuedAction *action = actions[index];
            if (action.state == CNDQueuedActionStateRunning) {
                actions[index] = [action actionByUpdatingState:CNDQueuedActionStateFailed
                                                     lastError:message];
            }
        }
        self.transaction = [self.transaction
            transactionByUpdatingState:CNDQueuedTransactionStateFailed
                                 actions:actions
                               lastError:message];
        [self persistDurableTransaction];
        self.waitingForSettingsCompletion = NO;
        self.waitingForCoordinatedSettingsCompletion = NO;
        self.resumeCoordinatorBeforeRespringAfterSettings = NO;
        self.settingsCompletionToken = nil;
        self.commitInFlight = NO;
    }
    [self notifyChange];
    if (postCompletion) [self postCompletionWithSuccess:NO message:message];
}

- (void)finishSuccessfullyPostingCompletion:(BOOL)postCompletion
{
    BOOL finalized = NO;
    @synchronized (self) {
        NSMutableArray<CNDQueuedAction *> *actions =
            [NSMutableArray arrayWithCapacity:self.transaction.actions.count];
        for (CNDQueuedAction *action in self.transaction.actions) {
            [actions addObject:action.state == CNDQueuedActionStateSucceeded
                ? action
                : [action actionByUpdatingState:CNDQueuedActionStateSucceeded
                                      lastError:nil]];
        }
        self.transaction = [self.transaction
            transactionByUpdatingState:CNDQueuedTransactionStateCompleted
                                 actions:actions
                               lastError:nil];
        finalized = [self persistDurableTransaction];
        if (finalized) {
            [self.installs removeAllObjects];
            [self.uninstalls removeAllObjects];
            CNDQueuedTransaction *completed = self.transaction;
            self.transaction = nil;
            if (![self persistDurableTransaction]) {
                self.transaction = completed;
            }
        }
        self.waitingForSettingsCompletion = NO;
        self.waitingForCoordinatedSettingsCompletion = NO;
        self.resumeCoordinatorBeforeRespringAfterSettings = NO;
        self.settingsCompletionToken = nil;
        self.commitInFlight = NO;
    }
    [self notifyChange];
    if (postCompletion) {
        [self postCompletionWithSuccess:finalized
            message:finalized ? @"Queued changes completed."
                              : @"Changes ran, but the completed queue checkpoint could not be saved."];
    }
}

- (void)postCompletionWithSuccess:(BOOL)success message:(NSString *)message
{
    void (^post)(void) = ^{
        [[NSNotificationCenter defaultCenter]
            postNotificationName:PackageQueueExecutionDidCompleteNotification
                          object:self
                        userInfo:@{
                            kSettingsActionsDidCompleteSuccessKey: @(success),
                            kSettingsActionsDidCompleteMessageKey: message ?: @""
                        }];
    };
    if ([NSThread isMainThread]) post();
    else dispatch_async(dispatch_get_main_queue(), post);
}

- (void)notifyChange
{
    void (^post)(void) = ^{
        [[NSNotificationCenter defaultCenter]
            postNotificationName:PackageQueueDidChangeNotification
                          object:self];
    };
    if ([NSThread isMainThread]) post();
    else dispatch_async(dispatch_get_main_queue(), post);
}

@end
