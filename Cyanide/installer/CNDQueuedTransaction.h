#import <Foundation/Foundation.h>
#import <sys/types.h>

NS_ASSUME_NONNULL_BEGIN

/// On-disk schema for the installer queue. Increment only when the property-
/// list representation changes incompatibly; older/unknown schemas fail
/// closed and are left on disk for diagnosis instead of being overwritten.
FOUNDATION_EXPORT const NSInteger CNDQueuedTransactionSchemaVersion;

typedef NS_ENUM(NSInteger, CNDQueuedActionPhase) {
    CNDQueuedActionPhaseAutomatic = 0,
    CNDQueuedActionPhaseBeforeRespring,
    CNDQueuedActionPhaseAfterRespring,
};

typedef NS_ENUM(NSInteger, CNDQueuedActionState) {
    CNDQueuedActionStatePending = 0,
    CNDQueuedActionStateRunning,
    CNDQueuedActionStateSucceeded,
    CNDQueuedActionStateFailed,
};

typedef NS_ENUM(NSInteger, CNDQueuedTransactionState) {
    CNDQueuedTransactionStateCollecting = 0,
    CNDQueuedTransactionStateRunningBeforeRespring,
    CNDQueuedTransactionStateAwaitingRespring,
    CNDQueuedTransactionStateReadyAfterRespring,
    CNDQueuedTransactionStateRunningAfterRespring,
    CNDQueuedTransactionStateCompleted,
    CNDQueuedTransactionStateFailed,
};

/// A stable, property-list-backed action. Phase 1 records package intents;
/// later phases add SnowBoard and presentation action kinds without changing
/// the transaction or recovery format.
@interface CNDQueuedAction : NSObject <NSCopying>

@property (nonatomic, readonly, copy) NSString *recordIdentifier;
@property (nonatomic, readonly, copy) NSString *kind;
@property (nonatomic, readonly, copy) NSString *subjectIdentifier;
@property (nonatomic, readonly, copy) NSString *operation;
@property (nonatomic, readonly, assign) CNDQueuedActionPhase phase;
@property (nonatomic, readonly, assign) CNDQueuedActionState state;
/// A recursively immutable snapshot. Only property-list values with string
/// dictionary keys are accepted; unsupported values and cycles fail to init.
@property (nonatomic, readonly, copy) NSDictionary<NSString *, id> *parameters;
@property (nonatomic, readonly, copy) NSDate *createdAt;
@property (nonatomic, readonly, copy) NSDate *updatedAt;
@property (nonatomic, readonly, copy, nullable) NSString *lastError;

- (nullable instancetype)initWithRecordIdentifier:(NSString *)recordIdentifier
                                     kind:(NSString *)kind
                        subjectIdentifier:(NSString *)subjectIdentifier
                                operation:(NSString *)operation
                                    phase:(CNDQueuedActionPhase)phase
                                    state:(CNDQueuedActionState)state
                               parameters:(NSDictionary<NSString *, id> *)parameters
                                createdAt:(NSDate *)createdAt
                                updatedAt:(NSDate *)updatedAt
                                lastError:(nullable NSString *)lastError
    NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

- (CNDQueuedAction *)actionByUpdatingState:(CNDQueuedActionState)state
                                 lastError:(nullable NSString *)lastError;
- (NSDictionary<NSString *, id> *)propertyListRepresentation;
+ (nullable instancetype)actionFromPropertyList:(id)propertyList
                                           error:(NSError **)error;

@end

@interface CNDQueuedTransaction : NSObject <NSCopying>

@property (nonatomic, readonly, assign) NSInteger schemaVersion;
@property (nonatomic, readonly, copy) NSString *transactionIdentifier;
@property (nonatomic, readonly, assign) CNDQueuedTransactionState state;
@property (nonatomic, readonly, copy) NSArray<CNDQueuedAction *> *actions;
@property (nonatomic, readonly, copy) NSDate *createdAt;
@property (nonatomic, readonly, copy) NSDate *updatedAt;
@property (nonatomic, readonly, assign) pid_t preRespringSpringBoardPID;
@property (nonatomic, readonly, assign) NSTimeInterval bootEpoch;
@property (nonatomic, readonly, copy) NSString *krwGenerationIdentifier;
@property (nonatomic, readonly, copy, nullable) NSString *lastError;

+ (instancetype)collectingTransactionWithActions:
    (NSArray<CNDQueuedAction *> *)actions;

- (instancetype)initWithSchemaVersion:(NSInteger)schemaVersion
                 transactionIdentifier:(NSString *)transactionIdentifier
                                 state:(CNDQueuedTransactionState)state
                               actions:(NSArray<CNDQueuedAction *> *)actions
                             createdAt:(NSDate *)createdAt
                             updatedAt:(NSDate *)updatedAt
            preRespringSpringBoardPID:(pid_t)preRespringSpringBoardPID
                             bootEpoch:(NSTimeInterval)bootEpoch
               krwGenerationIdentifier:(NSString *)krwGenerationIdentifier
                             lastError:(nullable NSString *)lastError
    NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

- (CNDQueuedTransaction *)transactionByUpdatingState:
    (CNDQueuedTransactionState)state
                                               actions:(NSArray<CNDQueuedAction *> *)actions
                                             lastError:(nullable NSString *)lastError;
/// Records the exact process epoch that must end before after-respring work
/// can run. This is written atomically with AwaitingRespring, before the UI is
/// told that it may initiate the restart.
- (CNDQueuedTransaction *)transactionByUpdatingState:
    (CNDQueuedTransactionState)state
                                               actions:(NSArray<CNDQueuedAction *> *)actions
                            preRespringSpringBoardPID:(pid_t)preRespringSpringBoardPID
                                             bootEpoch:(NSTimeInterval)bootEpoch
                               krwGenerationIdentifier:(NSString *)krwGenerationIdentifier
                                             lastError:(nullable NSString *)lastError;
- (NSDictionary<NSString *, id> *)propertyListRepresentation;
+ (nullable instancetype)transactionFromPropertyList:(id)propertyList
                                                error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
