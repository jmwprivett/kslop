#import "CNDQueuedTransaction.h"
#include <limits.h>
#include <math.h>

const NSInteger CNDQueuedTransactionSchemaVersion = 1;

static NSString * const CNDQueuedTransactionErrorDomain =
    @"com.zeroxjf.cyanide.queued-transaction";

static NSError *CNDQueuedTransactionError(NSString *description)
{
    return [NSError errorWithDomain:CNDQueuedTransactionErrorDomain
                               code:1
                           userInfo:@{
        NSLocalizedDescriptionKey: description ?: @"Invalid queued transaction."
    }];
}

static BOOL CNDQueuedPropertyListDictionary(id value)
{
    return [value isKindOfClass:NSDictionary.class];
}

static NSString *CNDQueuedString(id value)
{
    return [value isKindOfClass:NSString.class] ? value : nil;
}

static NSDate *CNDQueuedDate(id value)
{
    return [value isKindOfClass:NSDate.class] ? value : nil;
}

static NSNumber *CNDQueuedNumber(id value)
{
    if (![value isKindOfClass:NSNumber.class] ||
        CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID() ||
        !isfinite([value doubleValue])) return nil;
    return value;
}

static NSNumber *CNDQueuedInteger(id value, NSInteger minimum, NSInteger maximum)
{
    NSNumber *number = CNDQueuedNumber(value);
    if (!number || [number compare:@(minimum)] == NSOrderedAscending ||
        [number compare:@(maximum)] == NSOrderedDescending ||
        [number compare:@(number.integerValue)] != NSOrderedSame) return nil;
    return number;
}

static id CNDQueuedPropertyListSnapshot(id value, NSHashTable *ancestors)
{
    BOOL dictionary = [value isKindOfClass:NSDictionary.class];
    BOOL array = [value isKindOfClass:NSArray.class];
    if (dictionary || array) {
        if ([ancestors containsObject:value]) return nil;
        [ancestors addObject:value];
        id snapshot = nil;
        if (dictionary) {
            NSMutableDictionary *result = [NSMutableDictionary dictionary];
            for (id key in value) {
                if (![key isKindOfClass:NSString.class]) {
                    [ancestors removeObject:value];
                    return nil;
                }
                id child = CNDQueuedPropertyListSnapshot(value[key], ancestors);
                if (!child) {
                    [ancestors removeObject:value];
                    return nil;
                }
                result[[key copy]] = child;
            }
            snapshot = [result copy];
        } else {
            NSMutableArray *result = [NSMutableArray array];
            for (id element in value) {
                id child = CNDQueuedPropertyListSnapshot(element, ancestors);
                if (!child) {
                    [ancestors removeObject:value];
                    return nil;
                }
                [result addObject:child];
            }
            snapshot = [result copy];
        }
        [ancestors removeObject:value];
        return snapshot;
    }
    if ([value isKindOfClass:NSString.class] ||
        [value isKindOfClass:NSNumber.class] ||
        [value isKindOfClass:NSDate.class] ||
        [value isKindOfClass:NSData.class]) return [value copy];
    return nil;
}

static NSDictionary<NSString *, id> *CNDQueuedParameters(id value)
{
    if (!CNDQueuedPropertyListDictionary(value)) return nil;
    NSHashTable *ancestors = [NSHashTable hashTableWithOptions:
        NSPointerFunctionsStrongMemory | NSPointerFunctionsObjectPointerPersonality];
    NSDictionary *snapshot = CNDQueuedPropertyListSnapshot(value, ancestors);
    if (!snapshot || ![NSPropertyListSerialization propertyList:snapshot
                               isValidForFormat:NSPropertyListBinaryFormat_v1_0]) return nil;
    return snapshot;
}

@implementation CNDQueuedAction

- (instancetype)initWithRecordIdentifier:(NSString *)recordIdentifier
                                     kind:(NSString *)kind
                        subjectIdentifier:(NSString *)subjectIdentifier
                                operation:(NSString *)operation
                                    phase:(CNDQueuedActionPhase)phase
                                    state:(CNDQueuedActionState)state
                               parameters:(NSDictionary<NSString *,id> *)parameters
                                createdAt:(NSDate *)createdAt
                                updatedAt:(NSDate *)updatedAt
                                lastError:(NSString *)lastError
{
    NSDictionary *snapshot = CNDQueuedParameters(parameters);
    if (!snapshot) return nil;
    if ((self = [super init])) {
        _recordIdentifier = [recordIdentifier copy];
        _kind = [kind copy];
        _subjectIdentifier = [subjectIdentifier copy];
        _operation = [operation copy];
        _phase = phase;
        _state = state;
        _parameters = snapshot;
        _createdAt = [createdAt copy];
        _updatedAt = [updatedAt copy];
        _lastError = [lastError copy];
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone
{
    return self;
}

- (CNDQueuedAction *)actionByUpdatingState:(CNDQueuedActionState)state
                                 lastError:(NSString *)lastError
{
    return [[CNDQueuedAction alloc]
        initWithRecordIdentifier:self.recordIdentifier
                            kind:self.kind
               subjectIdentifier:self.subjectIdentifier
                       operation:self.operation
                           phase:self.phase
                           state:state
                      parameters:self.parameters
                       createdAt:self.createdAt
                       updatedAt:[NSDate date]
                       lastError:lastError];
}

- (NSDictionary<NSString *,id> *)propertyListRepresentation
{
    NSMutableDictionary<NSString *, id> *result = [@{
        @"recordIdentifier": self.recordIdentifier,
        @"kind": self.kind,
        @"subjectIdentifier": self.subjectIdentifier,
        @"operation": self.operation,
        @"phase": @(self.phase),
        @"state": @(self.state),
        @"parameters": self.parameters,
        @"createdAt": self.createdAt,
        @"updatedAt": self.updatedAt,
    } mutableCopy];
    if (self.lastError.length > 0) result[@"lastError"] = self.lastError;
    return result;
}

+ (instancetype)actionFromPropertyList:(id)propertyList
                                  error:(NSError **)error
{
    if (error) *error = nil;
    if (!CNDQueuedPropertyListDictionary(propertyList)) {
        if (error) *error = CNDQueuedTransactionError(
            @"A queued action is not a dictionary.");
        return nil;
    }
    NSDictionary *dictionary = propertyList;
    NSString *recordIdentifier = CNDQueuedString(dictionary[@"recordIdentifier"]);
    NSString *kind = CNDQueuedString(dictionary[@"kind"]);
    NSString *subjectIdentifier = CNDQueuedString(dictionary[@"subjectIdentifier"]);
    NSString *operation = CNDQueuedString(dictionary[@"operation"]);
    NSDate *createdAt = CNDQueuedDate(dictionary[@"createdAt"]);
    NSDate *updatedAt = CNDQueuedDate(dictionary[@"updatedAt"]);
    NSDictionary *parameters = CNDQueuedParameters(dictionary[@"parameters"]);
    NSNumber *phaseNumber = CNDQueuedInteger(dictionary[@"phase"],
        CNDQueuedActionPhaseAutomatic, CNDQueuedActionPhaseAfterRespring);
    NSNumber *stateNumber = CNDQueuedInteger(dictionary[@"state"],
        CNDQueuedActionStatePending, CNDQueuedActionStateFailed);
    NSInteger phase = phaseNumber.integerValue;
    NSInteger state = stateNumber.integerValue;
    NSString *lastError = CNDQueuedString(dictionary[@"lastError"]);
    BOOL lastErrorValid = dictionary[@"lastError"] == nil || lastError != nil;
    BOOL valid = recordIdentifier.length > 0 && kind.length > 0 &&
        subjectIdentifier.length > 0 && operation.length > 0 &&
        createdAt != nil && updatedAt != nil && parameters != nil &&
        phaseNumber != nil && stateNumber != nil &&
        lastErrorValid &&
        phase >= CNDQueuedActionPhaseAutomatic &&
        phase <= CNDQueuedActionPhaseAfterRespring &&
        state >= CNDQueuedActionStatePending &&
        state <= CNDQueuedActionStateFailed;
    if (!valid) {
        if (error) *error = CNDQueuedTransactionError(
            @"A queued action contains invalid or missing fields.");
        return nil;
    }
    return [[self alloc] initWithRecordIdentifier:recordIdentifier
                                             kind:kind
                                subjectIdentifier:subjectIdentifier
                                        operation:operation
                                            phase:(CNDQueuedActionPhase)phase
                                            state:(CNDQueuedActionState)state
                                       parameters:parameters
                                        createdAt:createdAt
                                        updatedAt:updatedAt
                                        lastError:lastError];
}

@end

@implementation CNDQueuedTransaction

+ (instancetype)collectingTransactionWithActions:
    (NSArray<CNDQueuedAction *> *)actions
{
    NSDate *now = [NSDate date];
    return [[self alloc]
        initWithSchemaVersion:CNDQueuedTransactionSchemaVersion
        transactionIdentifier:[NSUUID UUID].UUIDString
        state:CNDQueuedTransactionStateCollecting
        actions:actions ?: @[]
        createdAt:now
        updatedAt:now
        preRespringSpringBoardPID:0
        bootEpoch:0
        krwGenerationIdentifier:@""
        lastError:nil];
}

- (instancetype)initWithSchemaVersion:(NSInteger)schemaVersion
                 transactionIdentifier:(NSString *)transactionIdentifier
                                 state:(CNDQueuedTransactionState)state
                               actions:(NSArray<CNDQueuedAction *> *)actions
                             createdAt:(NSDate *)createdAt
                             updatedAt:(NSDate *)updatedAt
            preRespringSpringBoardPID:(pid_t)preRespringSpringBoardPID
                             bootEpoch:(NSTimeInterval)bootEpoch
               krwGenerationIdentifier:(NSString *)krwGenerationIdentifier
                             lastError:(NSString *)lastError
{
    if ((self = [super init])) {
        _schemaVersion = schemaVersion;
        _transactionIdentifier = [transactionIdentifier copy];
        _state = state;
        _actions = [actions copy] ?: @[];
        _createdAt = [createdAt copy];
        _updatedAt = [updatedAt copy];
        _preRespringSpringBoardPID = preRespringSpringBoardPID;
        _bootEpoch = bootEpoch;
        _krwGenerationIdentifier = [krwGenerationIdentifier copy] ?: @"";
        _lastError = [lastError copy];
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone
{
    return self;
}

- (CNDQueuedTransaction *)transactionByUpdatingState:
    (CNDQueuedTransactionState)state
                                               actions:(NSArray<CNDQueuedAction *> *)actions
                                             lastError:(NSString *)lastError
{
    return [[CNDQueuedTransaction alloc]
        initWithSchemaVersion:self.schemaVersion
        transactionIdentifier:self.transactionIdentifier
        state:state
        actions:actions ?: @[]
        createdAt:self.createdAt
        updatedAt:[NSDate date]
        preRespringSpringBoardPID:self.preRespringSpringBoardPID
        bootEpoch:self.bootEpoch
        krwGenerationIdentifier:self.krwGenerationIdentifier
        lastError:lastError];
}

- (CNDQueuedTransaction *)transactionByUpdatingState:
    (CNDQueuedTransactionState)state
                                               actions:(NSArray<CNDQueuedAction *> *)actions
                            preRespringSpringBoardPID:(pid_t)preRespringSpringBoardPID
                                             bootEpoch:(NSTimeInterval)bootEpoch
                               krwGenerationIdentifier:(NSString *)krwGenerationIdentifier
                                             lastError:(NSString *)lastError
{
    return [[CNDQueuedTransaction alloc]
        initWithSchemaVersion:self.schemaVersion
        transactionIdentifier:self.transactionIdentifier
        state:state
        actions:actions ?: @[]
        createdAt:self.createdAt
        updatedAt:[NSDate date]
        preRespringSpringBoardPID:preRespringSpringBoardPID
        bootEpoch:bootEpoch
        krwGenerationIdentifier:krwGenerationIdentifier ?: @""
        lastError:lastError];
}

- (NSDictionary<NSString *,id> *)propertyListRepresentation
{
    NSMutableArray<NSDictionary<NSString *, id> *> *actions =
        [NSMutableArray arrayWithCapacity:self.actions.count];
    for (CNDQueuedAction *action in self.actions) {
        [actions addObject:action.propertyListRepresentation];
    }
    NSMutableDictionary<NSString *, id> *result = [@{
        @"schemaVersion": @(self.schemaVersion),
        @"transactionIdentifier": self.transactionIdentifier,
        @"state": @(self.state),
        @"actions": actions,
        @"createdAt": self.createdAt,
        @"updatedAt": self.updatedAt,
        @"preRespringSpringBoardPID": @(self.preRespringSpringBoardPID),
        @"bootEpoch": @(self.bootEpoch),
        @"krwGenerationIdentifier": self.krwGenerationIdentifier,
    } mutableCopy];
    if (self.lastError.length > 0) result[@"lastError"] = self.lastError;
    return result;
}

+ (instancetype)transactionFromPropertyList:(id)propertyList
                                       error:(NSError **)error
{
    if (error) *error = nil;
    if (!CNDQueuedPropertyListDictionary(propertyList)) {
        if (error) *error = CNDQueuedTransactionError(
            @"The queued transaction is not a dictionary.");
        return nil;
    }
    NSDictionary *dictionary = propertyList;
    NSNumber *schemaNumber = CNDQueuedInteger(dictionary[@"schemaVersion"],
        CNDQueuedTransactionSchemaVersion, CNDQueuedTransactionSchemaVersion);
    NSInteger schemaVersion = schemaNumber.integerValue;
    if (schemaVersion != CNDQueuedTransactionSchemaVersion) {
        if (error) *error = CNDQueuedTransactionError(
            [NSString stringWithFormat:
                @"Unsupported queued transaction schema %ld.",
                (long)schemaVersion]);
        return nil;
    }
    NSString *transactionIdentifier =
        CNDQueuedString(dictionary[@"transactionIdentifier"]);
    NSDate *createdAt = CNDQueuedDate(dictionary[@"createdAt"]);
    NSDate *updatedAt = CNDQueuedDate(dictionary[@"updatedAt"]);
    NSArray *encodedActions = [dictionary[@"actions"] isKindOfClass:NSArray.class]
        ? dictionary[@"actions"] : nil;
    NSNumber *stateNumber = CNDQueuedInteger(dictionary[@"state"],
        CNDQueuedTransactionStateCollecting, CNDQueuedTransactionStateFailed);
    NSNumber *springBoardPID =
        CNDQueuedInteger(dictionary[@"preRespringSpringBoardPID"], 0, INT_MAX);
    NSNumber *bootEpoch = CNDQueuedNumber(dictionary[@"bootEpoch"]);
    NSString *generation =
        CNDQueuedString(dictionary[@"krwGenerationIdentifier"]);
    NSString *lastError = CNDQueuedString(dictionary[@"lastError"]);
    BOOL lastErrorValid = dictionary[@"lastError"] == nil || lastError != nil;
    NSInteger state = stateNumber.integerValue;
    if (schemaNumber == nil || transactionIdentifier.length == 0 ||
        createdAt == nil || updatedAt == nil || encodedActions == nil ||
        stateNumber == nil || springBoardPID == nil || bootEpoch == nil ||
        bootEpoch.doubleValue < 0 ||
        generation == nil || !lastErrorValid ||
        state < CNDQueuedTransactionStateCollecting ||
        state > CNDQueuedTransactionStateFailed) {
        if (error) *error = CNDQueuedTransactionError(
            @"The queued transaction contains invalid or missing fields.");
        return nil;
    }

    NSMutableArray<CNDQueuedAction *> *actions =
        [NSMutableArray arrayWithCapacity:encodedActions.count];
    NSMutableSet<NSString *> *recordIdentifiers = [NSMutableSet set];
    for (id encodedAction in encodedActions) {
        NSError *actionError = nil;
        CNDQueuedAction *action =
            [CNDQueuedAction actionFromPropertyList:encodedAction
                                               error:&actionError];
        if (!action) {
            if (error) *error = actionError;
            return nil;
        }
        if ([recordIdentifiers containsObject:action.recordIdentifier]) {
            if (error) *error = CNDQueuedTransactionError(
                @"The queued transaction contains duplicate action identifiers.");
            return nil;
        }
        [recordIdentifiers addObject:action.recordIdentifier];
        [actions addObject:action];
    }

    return [[self alloc]
        initWithSchemaVersion:schemaVersion
        transactionIdentifier:transactionIdentifier
        state:(CNDQueuedTransactionState)state
        actions:actions
        createdAt:createdAt
        updatedAt:updatedAt
        preRespringSpringBoardPID:
            (pid_t)springBoardPID.intValue
        bootEpoch:bootEpoch.doubleValue
        krwGenerationIdentifier:generation
        lastError:lastError];
}

@end
