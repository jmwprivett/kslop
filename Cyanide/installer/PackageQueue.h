//
//  PackageQueue.h
//  Cyanide
//
//  Sileo-style install/uninstall queue. User taps Install/Uninstall in a
//  package detail page; nothing applies until commit() is called from the
//  Queue review screen.
//

#import <Foundation/Foundation.h>
#import "Package.h"
#import "CNDQueuedTransaction.h"

NS_ASSUME_NONNULL_BEGIN

extern NSString * const PackageQueueDidChangeNotification;
/// Terminal result for one PackageQueue commit. Unlike the generic settings
/// notification, this is emitted only by PackageQueue after durable state and
/// commitInFlight have reached their final state.
extern NSString * const PackageQueueExecutionDidCompleteNotification;
/// Posted only after every pre-respring action and the exact old SpringBoard
/// PID have been durably checkpointed. The activity UI owns the 3-2-1
/// countdown and calls the shared cleanup/respring flow.
extern NSString * const PackageQueueReadyForRespringNotification;

// Intent stored per package once enqueued.
typedef NS_ENUM(NSInteger, PackageQueueIntent) {
    PackageQueueIntentNone = 0,
    PackageQueueIntentInstall,
    PackageQueueIntentUninstall,
};

@interface PackageQueue : NSObject

+ (instancetype)sharedQueue;

@property (nonatomic, readonly) NSArray<Package *> *queuedInstalls;
@property (nonatomic, readonly) NSArray<Package *> *queuedUninstalls;
@property (nonatomic, readonly) NSArray<CNDQueuedAction *> *queuedStandaloneActions;
@property (nonatomic, readonly) NSInteger pendingCount;
@property (nonatomic, readonly, nullable) CNDQueuedTransaction *durableTransaction;
@property (nonatomic, readonly) BOOL hasDurableTransaction;
@property (nonatomic, readonly) BOOL commitInFlight;
/// YES when the saved plan is stopped and can be discarded safely. One clear
/// atomically removes all package and standalone intents; a started plan never
/// attempts to undo actions already checkpointed.
@property (nonatomic, readonly) BOOL canClear;

- (PackageQueueIntent)intentForPackage:(Package *)package;
- (BOOL)canQueueIntent:(PackageQueueIntent)intent
            forPackage:(Package *)package
                reason:(NSString * _Nullable * _Nullable)reason;

// Sileo-style "tap toggles queue":
//   not installed + not queued  → queue install
//   not installed + queued      → cancel queue
//   installed     + not queued  → queue uninstall
//   installed     + queued      → cancel queue
- (void)toggleForPackage:(Package *)package;

- (void)queueIntent:(PackageQueueIntent)intent forPackage:(Package *)package;
- (void)removePackage:(Package *)package;

/// Adds or replaces one non-package action using its catalog conflict key.
/// The replacement and durable transaction write are atomic from the queue's
/// perspective: persistence failure restores the previous transaction.
- (BOOL)queueStandaloneAction:(CNDQueuedAction *)action
                       reason:(NSString * _Nullable * _Nullable)reason;
- (nullable CNDQueuedAction *)standaloneActionForConflictKey:
    (NSString *)conflictKey;
- (BOOL)removeStandaloneActionForConflictKey:(NSString *)conflictKey;
- (void)clear;

// Writes the persisted state for every queued package, then triggers
// settings_run_actions() once. Each item is durably checkpointed and is only
// removed after the corresponding operation reports success.
- (void)commit;

@end

NS_ASSUME_NONNULL_END
