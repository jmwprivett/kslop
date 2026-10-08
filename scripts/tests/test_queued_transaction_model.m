#import <Foundation/Foundation.h>
#import "../../Cyanide/installer/CNDQueuedTransaction.h"
#include <limits.h>
#include <math.h>

static void Check(BOOL condition, NSString *message)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message.UTF8String); exit(1); }
}

static CNDQueuedAction *Action(NSDictionary *parameters)
{
    NSDate *now = [NSDate dateWithTimeIntervalSince1970:1234];
    return [[CNDQueuedAction alloc] initWithRecordIdentifier:@"record"
        kind:@"synthetic" subjectIdentifier:@"subject" operation:@"operation"
        phase:CNDQueuedActionPhaseAutomatic state:CNDQueuedActionStatePending
        parameters:parameters createdAt:now updatedAt:now lastError:nil];
}

static void RejectAction(NSDictionary *base, NSString *key, id value)
{
    NSMutableDictionary *encoded = [base mutableCopy];
    encoded[key] = value;
    NSError *error = nil;
    Check([CNDQueuedAction actionFromPropertyList:encoded error:&error] == nil && error != nil,
        [NSString stringWithFormat:@"invalid action %@ is rejected", key]);
}

static void RejectTransaction(NSDictionary *base, NSString *key, id value)
{
    NSMutableDictionary *encoded = [base mutableCopy];
    encoded[key] = value;
    NSError *error = nil;
    Check([CNDQueuedTransaction transactionFromPropertyList:encoded error:&error] == nil && error != nil,
        [NSString stringWithFormat:@"invalid transaction %@ is rejected", key]);
}

int main(void)
{
    @autoreleasepool {
        NSMutableString *text = [NSMutableString stringWithString:@"before"];
        NSMutableData *bytes = [NSMutableData dataWithBytes:"abc" length:3];
        NSMutableDictionary *nested = [@{@"text": text, @"data": bytes} mutableCopy];
        NSMutableArray *array = [NSMutableArray arrayWithObject:nested];
        NSMutableDictionary *parameters = [@{@"array": array, @"boolean": @YES,
            @"date": [NSDate dateWithTimeIntervalSince1970:42], @"number": @3.5} mutableCopy];
        CNDQueuedAction *action = Action(parameters);
        NSDictionary *before = action.propertyListRepresentation;
        [text appendString:@"changed"];
        [bytes appendBytes:"d" length:1];
        nested[@"new"] = @YES;
        [array addObject:@"added"];
        parameters[@"new"] = @YES;
        Check(action.parameters[@"new"] == nil && [action.parameters[@"array"] count] == 1,
            @"parameter dictionary and array are independent snapshots");
        NSDictionary *saved = action.parameters[@"array"][0];
        Check([saved[@"text"] isEqual:@"before"] && [saved[@"data"] length] == 3 && saved[@"new"] == nil,
            @"nested dictionaries, mutable strings, and mutable data are snapshots");
        Check(![action.parameters isKindOfClass:NSMutableDictionary.class] &&
            ![action.parameters[@"array"] isKindOfClass:NSMutableArray.class] &&
            ![saved isKindOfClass:NSMutableDictionary.class] &&
            ![saved[@"text"] isKindOfClass:NSMutableString.class] &&
            ![saved[@"data"] isKindOfClass:NSMutableData.class], @"snapshots are recursively immutable");
        CNDQueuedAction *updated = [action actionByUpdatingState:CNDQueuedActionStateSucceeded lastError:nil];
        Check(updated.state == CNDQueuedActionStateSucceeded && action.state == CNDQueuedActionStatePending &&
            [updated.parameters isEqual:action.parameters], @"state updates preserve immutable parameters");

        CNDQueuedTransaction *transaction = [CNDQueuedTransaction collectingTransactionWithActions:@[action]];
        NSDictionary *encoded = transaction.propertyListRepresentation;
        NSError *error = nil;
        NSData *data = [NSPropertyListSerialization dataWithPropertyList:encoded
            format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
        Check(data != nil && error == nil, @"model serializes as a binary plist");
        NSDictionary *parsed = [NSPropertyListSerialization propertyListWithData:data
            options:NSPropertyListMutableContainersAndLeaves format:NULL error:&error];
        error = [NSError errorWithDomain:@"stale" code:1 userInfo:nil];
        CNDQueuedTransaction *roundTrip = [CNDQueuedTransaction transactionFromPropertyList:parsed error:&error];
        Check(roundTrip != nil && error == nil && [roundTrip.propertyListRepresentation isEqual:encoded],
            @"schema-1 binary round trip preserves all valid fields and clears stale errors");
        [parsed[@"actions"][0][@"parameters"] setObject:@YES forKey:@"changedAfterDecode"];
        Check(roundTrip.actions[0].parameters[@"changedAfterDecode"] == nil,
            @"deserialization also snapshots mutable parameters");

        for (NSNumber *number in @[@(-1), @0.5, @YES, @(NAN), @(INFINITY), @(LLONG_MAX)]) {
            RejectAction(before, @"phase", number);
            RejectAction(before, @"state", number);
            RejectTransaction(encoded, @"state", number);
            RejectTransaction(encoded, @"preRespringSpringBoardPID", number);
        }
        RejectAction(before, @"phase", @3);
        RejectAction(before, @"state", @4);
        RejectTransaction(encoded, @"state", @7);
        for (id invalid in @[@0, @2, @1.5, @YES, @(NAN), @(INFINITY),
            [NSDecimalNumber decimalNumberWithString:@"1.0000000000000000001"]])
            RejectTransaction(encoded, @"schemaVersion", invalid);
        for (id invalid in @[@(-0.1), @YES, @(NAN), @(INFINITY), @"42"])
            RejectTransaction(encoded, @"bootEpoch", invalid);
        for (NSInteger phase = CNDQueuedActionPhaseAutomatic; phase <= CNDQueuedActionPhaseAfterRespring; phase++) {
            NSMutableDictionary *valid = [before mutableCopy]; valid[@"phase"] = @(phase);
            Check([CNDQueuedAction actionFromPropertyList:valid error:NULL] != nil, @"all valid phases accepted");
        }
        for (NSInteger state = CNDQueuedActionStatePending; state <= CNDQueuedActionStateFailed; state++) {
            NSMutableDictionary *valid = [before mutableCopy]; valid[@"state"] = @(state);
            Check([CNDQueuedAction actionFromPropertyList:valid error:NULL] != nil, @"all valid action states accepted");
        }
        for (NSInteger state = CNDQueuedTransactionStateCollecting; state <= CNDQueuedTransactionStateFailed; state++) {
            NSMutableDictionary *valid = [encoded mutableCopy]; valid[@"state"] = @(state);
            valid[@"preRespringSpringBoardPID"] = @(INT_MAX); valid[@"bootEpoch"] = @123.5;
            Check([CNDQueuedTransaction transactionFromPropertyList:valid error:NULL] != nil,
                @"all valid transaction states and numeric bounds accepted");
        }
        RejectTransaction(encoded, @"actions", @[before, before]);
        for (NSDictionary *invalid in @[@{@"unsupported": [NSObject new]}, @{@"null": NSNull.null},
            @{@"nested": @[@{@1: @"non-string key"}]}]) {
            Check(Action(invalid) == nil, @"initializer rejects non-property-list parameter values");
            RejectAction(before, @"parameters", invalid);
        }
        NSMutableArray *cycle = [NSMutableArray array];
        [cycle addObject:@{@"back": cycle}];
        NSDictionary *cyclic = @{@"cycle": cycle};
        Check(Action(cyclic) == nil, @"initializer rejects cyclic parameters");
        RejectAction(before, @"parameters", cyclic);
        [cycle removeAllObjects];
        NSMutableArray *shared = [NSMutableArray arrayWithObject:@1];
        Check(Action(@{@"first": shared, @"second": shared}) != nil,
            @"shared containers without cycles remain valid");
        printf("PASS: schema-1 round trips, numeric validation, immutable snapshots, property-list validation, cycles\n");
    }
    return 0;
}
