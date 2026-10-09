#import "CNDTransientAppliedState.h"

#import "../TaskRop/CNDKernelTaskBridge.h"
#import "../kexploit/kexploit_opa334.h"
#import "../LogTextView.h"

#import <math.h>
#import <sys/sysctl.h>

NSString * const CNDTransientAppliedStateSnowBoardRemix =
    @"snowboard-remix";
NSString * const CNDTransientAppliedStateFontChanger = @"font-changer";
NSString * const CNDTransientAppliedStateSBCustomizer = @"sbcustomizer";
NSString * const CNDTransientAppliedStateSpringBoardFixes =
    @"springboard-fixes";
NSString * const CNDTransientAppliedStateSpotlightFixes =
    @"spotlight-fixes";

static const NSInteger CNDTransientAppliedStateSchemaVersion = 1;
static NSString * const CNDTransientAppliedStateDirectory = @"Cyanide/State";
static NSString * const CNDTransientAppliedStateFilename =
    @"TransientAppliedState.v1.plist";

static NSObject *CNDTransientAppliedStateLock(void)
{
    static NSObject *lock = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ lock = [NSObject new]; });
    return lock;
}

static NSURL *CNDTransientAppliedStateURL(void)
{
    NSURL *support = [[NSFileManager defaultManager]
        URLsForDirectory:NSApplicationSupportDirectory
               inDomains:NSUserDomainMask].firstObject;
    NSURL *directory = [support
        URLByAppendingPathComponent:CNDTransientAppliedStateDirectory
                        isDirectory:YES];
    return [directory
        URLByAppendingPathComponent:CNDTransientAppliedStateFilename
                        isDirectory:NO];
}

static NSTimeInterval CNDTransientAppliedStateCurrentBootEpoch(void)
{
    struct timeval bootTime = {0};
    size_t length = sizeof(bootTime);
    if (sysctlbyname("kern.boottime", &bootTime, &length, NULL, 0) == 0 &&
        bootTime.tv_sec > 0) {
        return (NSTimeInterval)bootTime.tv_sec;
    }
    return NSDate.date.timeIntervalSince1970 -
        NSProcessInfo.processInfo.systemUptime;
}

static BOOL CNDTransientAppliedStateBootMatches(NSTimeInterval stored,
                                                NSTimeInterval current)
{
    // kern.boottime is second-granular and stable for the lifetime of a boot.
    // Keep only a small allowance for the date-minus-uptime fallback; a broad
    // window can mistake a quick reboot for the coordinator-owned respring.
    return stored > 0.0 && current > 0.0 && fabs(stored - current) <= 5.0;
}

static NSSet<NSString *> *CNDTransientAppliedStateAllowedKeys(void)
{
    static NSSet<NSString *> *keys = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        keys = [NSSet setWithObjects:
            CNDTransientAppliedStateSnowBoardRemix,
            CNDTransientAppliedStateFontChanger,
            CNDTransientAppliedStateSBCustomizer,
            CNDTransientAppliedStateSpringBoardFixes,
            CNDTransientAppliedStateSpotlightFixes, nil];
    });
    return keys;
}

static NSMutableDictionary<NSString *, id> *
CNDTransientAppliedStateReadLocked(void)
{
    NSData *data = [NSData dataWithContentsOfURL:CNDTransientAppliedStateURL()];
    if (!data) return nil;
    NSPropertyListFormat format = NSPropertyListBinaryFormat_v1_0;
    id object = [NSPropertyListSerialization propertyListWithData:data
                                                          options:NSPropertyListMutableContainers
                                                           format:&format
                                                            error:nil];
    if (![object isKindOfClass:NSMutableDictionary.class]) return nil;
    NSMutableDictionary *state = object;
    NSNumber *schema = [state[@"schemaVersion"] isKindOfClass:NSNumber.class]
        ? state[@"schemaVersion"] : nil;
    NSNumber *pid = [state[@"springBoardPID"] isKindOfClass:NSNumber.class]
        ? state[@"springBoardPID"] : nil;
    NSNumber *boot = [state[@"bootEpoch"] isKindOfClass:NSNumber.class]
        ? state[@"bootEpoch"] : nil;
    NSNumber *spotlightPID =
        [state[@"spotlightPID"] isKindOfClass:NSNumber.class]
            ? state[@"spotlightPID"] : nil;
    NSDictionary *states = [state[@"states"] isKindOfClass:NSDictionary.class]
        ? state[@"states"] : nil;
    if (schema.integerValue != CNDTransientAppliedStateSchemaVersion ||
        pid.intValue <= 1 || boot.doubleValue <= 0.0 || !states ||
        states.count > 5 ||
        (state[@"spotlightPID"] != nil && spotlightPID == nil) ||
        spotlightPID.intValue < 0) return nil;
    NSSet<NSString *> *allowedStateKeys =
        CNDTransientAppliedStateAllowedKeys();
    for (NSString *key in states) {
        if (![key isKindOfClass:NSString.class] ||
            ![allowedStateKeys containsObject:key] ||
            ![states[key] isKindOfClass:NSNumber.class]) return nil;
    }
    return state;
}

static BOOL CNDTransientAppliedStateWriteLocked(
    NSDictionary<NSString *, id> *state)
{
    NSURL *url = CNDTransientAppliedStateURL();
    NSFileManager *manager = NSFileManager.defaultManager;
    if (!state) {
        if (![manager fileExistsAtPath:url.path]) return YES;
        return [manager removeItemAtURL:url error:nil];
    }
    if (![manager createDirectoryAtURL:url.URLByDeletingLastPathComponent
           withIntermediateDirectories:YES attributes:nil error:nil]) {
        return NO;
    }
    NSData *data = [NSPropertyListSerialization
        dataWithPropertyList:state
                      format:NSPropertyListBinaryFormat_v1_0
                     options:0
                       error:nil];
    return data && [data writeToURL:url options:NSDataWritingAtomic error:nil];
}

static BOOL CNDTransientAppliedStatePreserveSnowBoardOnlyLocked(
    NSDictionary<NSString *, id> *state,
    NSNumber *snowBoardActiveOverride,
    pid_t preferredSpringBoardPID,
    NSTimeInterval preferredBootEpoch)
{
    NSDictionary *storedStates =
        [state[@"states"] isKindOfClass:NSDictionary.class]
            ? state[@"states"] : @{};
    BOOL snowBoardActive = snowBoardActiveOverride != nil
        ? snowBoardActiveOverride.boolValue
        : [storedStates[CNDTransientAppliedStateSnowBoardRemix] boolValue];
    if (!snowBoardActive) {
        return CNDTransientAppliedStateWriteLocked(nil);
    }

    pid_t springBoardPID = preferredSpringBoardPID > 1
        ? preferredSpringBoardPID
        : [state[@"springBoardPID"] intValue];
    NSTimeInterval bootEpoch = preferredBootEpoch > 0.0
        ? preferredBootEpoch
        : [state[@"bootEpoch"] doubleValue];
    if (springBoardPID <= 1 || bootEpoch <= 0.0) return NO;

    // SnowBoard publishes persistent IconServices records. They survive app,
    // SpringBoard, userspace, and full-device restarts, so losing the KRW or
    // process epoch is not evidence that the theme was restored. Strip every
    // process-bound marker and pending transition, but retain SnowBoard until
    // a successful explicit Restore records @NO.
    NSDictionary *durable = @{
        @"schemaVersion": @(CNDTransientAppliedStateSchemaVersion),
        @"springBoardPID": @(springBoardPID),
        @"spotlightPID": @0,
        @"bootEpoch": @(bootEpoch),
        @"krwGenerationIdentifier": @"",
        @"states": @{
            CNDTransientAppliedStateSnowBoardRemix: @YES,
        },
        @"updatedAt": NSDate.date,
    };
    return CNDTransientAppliedStateWriteLocked(durable);
}

static pid_t CNDTransientAppliedStateCurrentSpringBoardPID(void)
{
    if (!kexploit_krw_ready()) return 0;
    return CNDKernelTaskBridgeResolveProcessPID(@"SpringBoard", nil);
}

static pid_t CNDTransientAppliedStateCurrentSpotlightPID(void)
{
    if (!kexploit_krw_ready()) return 0;
    return CNDKernelTaskBridgeResolveProcessPID(@"Spotlight", nil);
}

static void CNDTransientAppliedStateRemoveProcessLocalStates(
    NSMutableDictionary<NSString *, NSNumber *> *states)
{
    [states removeObjectForKey:CNDTransientAppliedStateSBCustomizer];
    [states removeObjectForKey:CNDTransientAppliedStateSpringBoardFixes];
    [states removeObjectForKey:CNDTransientAppliedStateSpotlightFixes];
}

BOOL CNDTransientAppliedStateReconcileCurrentEpoch(void)
{
    @synchronized (CNDTransientAppliedStateLock()) {
        NSMutableDictionary *state = CNDTransientAppliedStateReadLocked();
        if (!state) return NO;
        NSTimeInterval currentBoot =
            CNDTransientAppliedStateCurrentBootEpoch();
        if (!CNDTransientAppliedStateBootMatches(
                [state[@"bootEpoch"] doubleValue], currentBoot)) {
            pid_t currentPID =
                CNDTransientAppliedStateCurrentSpringBoardPID();
            BOOL snowBoardActive =
                [state[@"states"]
                    [CNDTransientAppliedStateSnowBoardRemix] boolValue];
            BOOL saved =
                CNDTransientAppliedStatePreserveSnowBoardOnlyLocked(
                    state, nil, currentPID, currentBoot);
            if (saved) {
                log_user(snowBoardActive
                    ? "[ACTIVE_STATE] Boot epoch changed; preserved durable SnowBoard state and cleared process-local ACTIVE markers.\n"
                    : "[ACTIVE_STATE] Boot epoch changed; cleared process-local ACTIVE markers.\n");
            }
            return saved;
        }

        pid_t currentPID = CNDTransientAppliedStateCurrentSpringBoardPID();
        if (currentPID <= 1) return NO;
        pid_t storedPID = [state[@"springBoardPID"] intValue];

        NSString *pending = [state[@"pendingTransactionIdentifier"]
            isKindOfClass:NSString.class]
            ? state[@"pendingTransactionIdentifier"] : @"";
        pid_t pendingFrom = [state[@"pendingFromSpringBoardPID"]
            isKindOfClass:NSNumber.class]
            ? [state[@"pendingFromSpringBoardPID"] intValue] : 0;
        BOOL adoptNextPID = [state[@"pendingAdoptNextSpringBoardPID"]
            isKindOfClass:NSNumber.class] &&
            [state[@"pendingAdoptNextSpringBoardPID"] boolValue];
        if (pending.length > 0 &&
            pendingFrom == storedPID && currentPID != storedPID) {
            if (adoptNextPID) {
                NSMutableDictionary *adopted = [state mutableCopy];
                adopted[@"springBoardPID"] = @(currentPID);
                adopted[@"spotlightPID"] = @0;
                [adopted removeObjectForKey:@"pendingTransactionIdentifier"];
                [adopted removeObjectForKey:@"pendingFromSpringBoardPID"];
                [adopted removeObjectForKey:
                    @"pendingAdoptNextSpringBoardPID"];
                adopted[@"updatedAt"] = NSDate.date;
                NSDictionary *states = adopted[@"states"];
                BOOL saved = CNDTransientAppliedStateWriteLocked(
                    states.count > 0 ? adopted : nil);
                if (saved) {
                    log_user("[ACTIVE_STATE] Adopted completed respring boundary transaction=%s %d->%d active=%lu.\n",
                             pending.UTF8String ?: "", pendingFrom,
                             currentPID, (unsigned long)states.count);
                }
                return saved;
            }
            // The durable queue owns this one transition and will either
            // finalize it or remain retryable. Do not erase the carried state
            // while its post-respring work is still pending.
            return NO;
        }

        NSMutableDictionary<NSString *, NSNumber *> *states =
            [state[@"states"] mutableCopy] ?: [NSMutableDictionary dictionary];
        if (currentPID != storedPID) {
            CNDTransientAppliedStateRemoveProcessLocalStates(states);
            NSMutableDictionary *updated = [state mutableCopy];
            updated[@"springBoardPID"] = @(currentPID);
            updated[@"spotlightPID"] = @0;
            updated[@"states"] = states;
            updated[@"updatedAt"] = NSDate.date;
            BOOL saved = CNDTransientAppliedStateWriteLocked(
                states.count > 0 ? updated : nil);
            if (saved) {
                log_user("[ACTIVE_STATE] SpringBoard changed %d->%d; preserved persistent SnowBoard/Font state and cleared process-local SpringBoard/Spotlight/SBC state.\n",
                         storedPID, currentPID);
            }
            return saved;
        }

        if (![states[CNDTransientAppliedStateSpotlightFixes] boolValue]) {
            return NO;
        }
        pid_t storedSpotlightPID = [state[@"spotlightPID"] intValue];
        pid_t currentSpotlightPID =
            CNDTransientAppliedStateCurrentSpotlightPID();
        if (currentSpotlightPID > 1 &&
            currentSpotlightPID == storedSpotlightPID) return NO;

        [states removeObjectForKey:CNDTransientAppliedStateSpotlightFixes];
        NSMutableDictionary *updated = [state mutableCopy];
        updated[@"spotlightPID"] = @0;
        updated[@"states"] = states;
        updated[@"updatedAt"] = NSDate.date;
        BOOL saved = CNDTransientAppliedStateWriteLocked(
            states.count > 0 ? updated : nil);
        if (saved) {
            log_user("[ACTIVE_STATE] Spotlight changed %d->%d while SpringBoard remained %d; cleared only Spotlight Fixes.\n",
                     storedSpotlightPID, currentSpotlightPID, currentPID);
        }
        return saved;
    }
}

BOOL CNDTransientAppliedStateResetAfterKRWLoss(void)
{
    @synchronized (CNDTransientAppliedStateLock()) {
        // A malformed or schema-incompatible file must not survive continuity
        // loss and become trusted by a later build or recovery path. A valid
        // SnowBoard marker is different: its persistent IconServices records
        // do not depend on the KRW generation, so preserve it while dropping
        // every process-bound state and pending transition.
        if (![NSFileManager.defaultManager
                fileExistsAtPath:CNDTransientAppliedStateURL().path]) {
            return NO;
        }
        NSMutableDictionary *state = CNDTransientAppliedStateReadLocked();
        BOOL snowBoardActive =
            [state[@"states"]
                [CNDTransientAppliedStateSnowBoardRemix] boolValue];
        BOOL saved = state
            ? CNDTransientAppliedStatePreserveSnowBoardOnlyLocked(
                state, nil, 0, CNDTransientAppliedStateCurrentBootEpoch())
            : CNDTransientAppliedStateWriteLocked(nil);
        if (saved) {
            log_user(snowBoardActive
                ? "[ACTIVE_STATE] KRW continuity was lost; preserved durable SnowBoard state and cleared process-local ACTIVE markers.\n"
                : "[ACTIVE_STATE] KRW continuity was lost; cleared process-local ACTIVE markers.\n");
        }
        return saved;
    }
}

BOOL CNDTransientAppliedStateIsActive(NSString *stateKey)
{
    if (![CNDTransientAppliedStateAllowedKeys() containsObject:stateKey]) {
        return NO;
    }
    @synchronized (CNDTransientAppliedStateLock()) {
        NSDictionary *state = CNDTransientAppliedStateReadLocked();
        if (!state) return NO;

        // Rendering a package badge must be a deterministic disk read. Never
        // run KRW validation or a kernel process-list walk from this UI path:
        // table configuration can query the same package several times and a
        // transient readiness/read failure made identical rows disagree after
        // an ordinary app relaunch. The boot epoch is available without KRW,
        // so a real reboot can discard process-local markers immediately while
        // retaining SnowBoard's durable state. Exact SpringBoard PID
        // validation remains in ReconcileCurrentEpoch(), which the settings
        // path invokes after KRW is successfully reused or recovered.
        NSTimeInterval currentBoot =
            CNDTransientAppliedStateCurrentBootEpoch();
        if (!CNDTransientAppliedStateBootMatches(
                [state[@"bootEpoch"] doubleValue], currentBoot)) {
            BOOL snowBoardActive =
                [state[@"states"]
                    [CNDTransientAppliedStateSnowBoardRemix] boolValue];
            BOOL saved =
                CNDTransientAppliedStatePreserveSnowBoardOnlyLocked(
                    state, nil, 0, currentBoot);
            if (saved) {
                log_user(snowBoardActive
                    ? "[ACTIVE_STATE] Boot epoch changed; preserved durable SnowBoard state and cleared process-local ACTIVE markers.\n"
                    : "[ACTIVE_STATE] Boot epoch changed; cleared process-local ACTIVE markers.\n");
            }
            return [stateKey isEqualToString:
                CNDTransientAppliedStateSnowBoardRemix] && snowBoardActive;
        }
        NSDictionary *states = state[@"states"];
        return [states[stateKey] boolValue];
    }
}

BOOL CNDTransientAppliedStateSetActiveForCurrentEpoch(NSString *stateKey,
                                                      BOOL active)
{
    if (![CNDTransientAppliedStateAllowedKeys() containsObject:stateKey]) {
        return NO;
    }
    (void)CNDTransientAppliedStateReconcileCurrentEpoch();
    NSTimeInterval currentBoot = CNDTransientAppliedStateCurrentBootEpoch();
    pid_t currentPID = CNDTransientAppliedStateCurrentSpringBoardPID();
    pid_t currentSpotlightPID =
        [stateKey isEqualToString:CNDTransientAppliedStateSpotlightFixes] &&
        active ? CNDTransientAppliedStateCurrentSpotlightPID() : 0;
    if (currentBoot <= 0.0 || currentPID <= 1) return NO;
    if ([stateKey isEqualToString:CNDTransientAppliedStateSpotlightFixes] &&
        active && currentSpotlightPID <= 1) return NO;

    @synchronized (CNDTransientAppliedStateLock()) {
        NSMutableDictionary *existing = CNDTransientAppliedStateReadLocked();
        if (existing) {
            NSString *pending = [existing[@"pendingTransactionIdentifier"]
                isKindOfClass:NSString.class]
                ? existing[@"pendingTransactionIdentifier"] : @"";
            if (pending.length > 0 ||
                !CNDTransientAppliedStateBootMatches(
                    [existing[@"bootEpoch"] doubleValue], currentBoot) ||
                [existing[@"springBoardPID"] intValue] != currentPID) {
                return NO;
            }
        } else if (!active) {
            return YES;
        }

        NSMutableDictionary<NSString *, NSNumber *> *states =
            [existing[@"states"] mutableCopy] ?:
                [NSMutableDictionary dictionary];
        if (active) states[stateKey] = @YES;
        else [states removeObjectForKey:stateKey];

        if (states.count == 0) {
            return CNDTransientAppliedStateWriteLocked(nil);
        }
        NSString *generation =
            [existing[@"krwGenerationIdentifier"] isKindOfClass:NSString.class]
                ? existing[@"krwGenerationIdentifier"] : @"";
        if (generation.length == 0) generation = NSUUID.UUID.UUIDString;
        pid_t spotlightPID = [existing[@"spotlightPID"] intValue];
        if ([stateKey isEqualToString:CNDTransientAppliedStateSpotlightFixes]) {
            spotlightPID = active ? currentSpotlightPID : 0;
        }
        NSDictionary *updated = @{
            @"schemaVersion": @(CNDTransientAppliedStateSchemaVersion),
            @"springBoardPID": @(currentPID),
            @"spotlightPID": @(spotlightPID),
            @"bootEpoch": @(currentBoot),
            @"krwGenerationIdentifier": generation,
            @"states": states,
            @"updatedAt": NSDate.date,
        };
        BOOL saved = CNDTransientAppliedStateWriteLocked(updated);
        if (saved) {
            log_user("[ACTIVE_STATE] Recorded current-epoch state key=%s active=%d sb=%d.\n",
                     stateKey.UTF8String ?: "", active ? 1 : 0,
                     currentPID);
        }
        return saved;
    }
}

BOOL CNDTransientAppliedStatePrepareTransition(
    NSString *transactionIdentifier,
    pid_t fromPID,
    NSTimeInterval bootEpoch)
{
    if (transactionIdentifier.length == 0 || fromPID <= 1 ||
        bootEpoch <= 0.0) return NO;
    @synchronized (CNDTransientAppliedStateLock()) {
        NSMutableDictionary *existing = CNDTransientAppliedStateReadLocked();
        NSMutableDictionary<NSString *, NSNumber *> *states =
            [NSMutableDictionary dictionary];
        if (existing &&
            CNDTransientAppliedStateBootMatches(
                [existing[@"bootEpoch"] doubleValue], bootEpoch) &&
            [existing[@"springBoardPID"] intValue] == fromPID) {
            [states addEntriesFromDictionary:existing[@"states"] ?: @{}];
        } else if ([existing[@"states"]
                        [CNDTransientAppliedStateSnowBoardRemix] boolValue]) {
            states[CNDTransientAppliedStateSnowBoardRemix] = @YES;
        }
        // The authorized boundary itself ends SBCustomizer's process-local
        // mutation. If SBC is queued adaptively, the post-respring executor
        // will record it again only after that reapply actually succeeds.
        CNDTransientAppliedStateRemoveProcessLocalStates(states);
        NSDictionary *prepared = @{
            @"schemaVersion": @(CNDTransientAppliedStateSchemaVersion),
            @"springBoardPID": @(fromPID),
            @"spotlightPID": @0,
            @"bootEpoch": @(bootEpoch),
            @"krwGenerationIdentifier": @"",
            @"pendingTransactionIdentifier": transactionIdentifier,
            @"pendingFromSpringBoardPID": @(fromPID),
            @"states": states,
            @"updatedAt": NSDate.date,
        };
        BOOL saved = CNDTransientAppliedStateWriteLocked(prepared);
        if (saved) {
            log_user("[ACTIVE_STATE] Prepared authorized SpringBoard transition transaction=%s from=%d carried=%lu.\n",
                     transactionIdentifier.UTF8String ?: "", fromPID,
                     (unsigned long)states.count);
        }
        return saved;
    }
}

BOOL CNDTransientAppliedStatePrepareBoundaryOnlyTransition(
    NSString *transactionIdentifier,
    pid_t fromPID,
    NSTimeInterval bootEpoch,
    NSString *krwGenerationIdentifier,
    NSNumber *snowBoardActive,
    NSNumber *fontChangerActive)
{
    if (transactionIdentifier.length == 0 || fromPID <= 1 ||
        bootEpoch <= 0.0 || krwGenerationIdentifier.length == 0) {
        return NO;
    }
    @synchronized (CNDTransientAppliedStateLock()) {
        NSMutableDictionary *existing = CNDTransientAppliedStateReadLocked();
        NSMutableDictionary<NSString *, NSNumber *> *states =
            [NSMutableDictionary dictionary];
        if (existing &&
            CNDTransientAppliedStateBootMatches(
                [existing[@"bootEpoch"] doubleValue], bootEpoch) &&
            [existing[@"springBoardPID"] intValue] == fromPID) {
            [states addEntriesFromDictionary:existing[@"states"] ?: @{}];
        } else if ([existing[@"states"]
                        [CNDTransientAppliedStateSnowBoardRemix] boolValue]) {
            states[CNDTransientAppliedStateSnowBoardRemix] = @YES;
        }
        if (snowBoardActive != nil) {
            if (snowBoardActive.boolValue) {
                states[CNDTransientAppliedStateSnowBoardRemix] = @YES;
            } else {
                [states removeObjectForKey:
                    CNDTransientAppliedStateSnowBoardRemix];
            }
        }
        if (fontChangerActive != nil) {
            if (fontChangerActive.boolValue) {
                states[CNDTransientAppliedStateFontChanger] = @YES;
            } else {
                [states removeObjectForKey:
                    CNDTransientAppliedStateFontChanger];
            }
        }
        // Every respring destroys SBCustomizer's one-shot process mutation.
        // Boundary-only transactions have no eligible post-respring action
        // that could reinstall it in the replacement SpringBoard.
        CNDTransientAppliedStateRemoveProcessLocalStates(states);

        NSDictionary *prepared = @{
            @"schemaVersion": @(CNDTransientAppliedStateSchemaVersion),
            @"springBoardPID": @(fromPID),
            @"spotlightPID": @0,
            @"bootEpoch": @(bootEpoch),
            @"krwGenerationIdentifier": krwGenerationIdentifier,
            @"pendingTransactionIdentifier": transactionIdentifier,
            @"pendingFromSpringBoardPID": @(fromPID),
            @"pendingAdoptNextSpringBoardPID": @YES,
            @"states": states,
            @"updatedAt": NSDate.date,
        };
        BOOL saved = CNDTransientAppliedStateWriteLocked(prepared);
        if (saved) {
            log_user("[ACTIVE_STATE] Completed boundary-only state transaction=%s from=%d snowboard=%d font=%d sbc=0; next SpringBoard PID will adopt it.\n",
                     transactionIdentifier.UTF8String ?: "", fromPID,
                     [states[CNDTransientAppliedStateSnowBoardRemix]
                         boolValue],
                     [states[CNDTransientAppliedStateFontChanger]
                         boolValue]);
        }
        return saved;
    }
}

void CNDTransientAppliedStateCancelPreparedTransition(
    NSString *transactionIdentifier)
{
    if (transactionIdentifier.length == 0) return;
    @synchronized (CNDTransientAppliedStateLock()) {
        NSMutableDictionary *state = CNDTransientAppliedStateReadLocked();
        if (![state[@"pendingTransactionIdentifier"]
                isEqualToString:transactionIdentifier]) return;
        [state removeObjectForKey:@"pendingTransactionIdentifier"];
        [state removeObjectForKey:@"pendingFromSpringBoardPID"];
        [state removeObjectForKey:@"pendingAdoptNextSpringBoardPID"];
        state[@"updatedAt"] = NSDate.date;
        NSDictionary *states = state[@"states"];
        (void)CNDTransientAppliedStateWriteLocked(
            states.count > 0 ? state : nil);
    }
}

BOOL CNDTransientAppliedStateFinalizeTransition(
    NSString *transactionIdentifier,
    pid_t fromPID,
    pid_t toPID,
    NSTimeInterval bootEpoch,
    NSString *krwGenerationIdentifier,
    NSNumber * _Nullable snowBoardActive,
    NSNumber * _Nullable fontChangerActive,
    NSNumber * _Nullable sbCustomizerActive)
{
    if (transactionIdentifier.length == 0 || fromPID <= 1 ||
        bootEpoch <= 0.0 ||
        krwGenerationIdentifier.length == 0) return NO;
    @synchronized (CNDTransientAppliedStateLock()) {
        NSMutableDictionary *state = CNDTransientAppliedStateReadLocked();
        NSTimeInterval currentBoot =
            CNDTransientAppliedStateCurrentBootEpoch();
        if (!CNDTransientAppliedStateBootMatches(bootEpoch, currentBoot)) {
            BOOL saved =
                CNDTransientAppliedStatePreserveSnowBoardOnlyLocked(
                    state, snowBoardActive, toPID, currentBoot);
            if (saved) {
                log_user("[ACTIVE_STATE] The queue crossed a full reboot; retained the durable SnowBoard result and cleared process-local ACTIVE markers.\n");
            }
            return saved;
        }
        // Check the boot boundary before applying the respring-only PID
        // rules. A full reboot may coincidentally assign SpringBoard the same
        // PID, but process-local markers must still be discarded.
        if (toPID <= 1 || fromPID == toPID) return NO;
        BOOL prepared = state &&
            [state[@"pendingTransactionIdentifier"]
                isEqualToString:transactionIdentifier] &&
            [state[@"pendingFromSpringBoardPID"] intValue] == fromPID &&
            [state[@"springBoardPID"] intValue] == fromPID &&
            CNDTransientAppliedStateBootMatches(
                [state[@"bootEpoch"] doubleValue], bootEpoch);
        if (!prepared) {
            BOOL alreadyFinalized = state &&
                [state[@"springBoardPID"] intValue] == toPID &&
                [state[@"krwGenerationIdentifier"]
                    isEqualToString:krwGenerationIdentifier] &&
                CNDTransientAppliedStateBootMatches(
                    [state[@"bootEpoch"] doubleValue], bootEpoch);
            return alreadyFinalized;
        }

        NSMutableDictionary<NSString *, NSNumber *> *states =
            [state[@"states"] mutableCopy] ?: [NSMutableDictionary dictionary];
        // A replacement SpringBoard never inherits SBCustomizer's one-shot
        // process-local mutation. A successfully completed post-respring SBC
        // action below may explicitly set it again for the new PID.
        CNDTransientAppliedStateRemoveProcessLocalStates(states);
        if (snowBoardActive != nil) {
            if (snowBoardActive.boolValue) {
                states[CNDTransientAppliedStateSnowBoardRemix] = @YES;
            } else {
                [states removeObjectForKey:
                    CNDTransientAppliedStateSnowBoardRemix];
            }
        }
        if (fontChangerActive != nil) {
            if (fontChangerActive.boolValue) {
                states[CNDTransientAppliedStateFontChanger] = @YES;
            } else {
                [states removeObjectForKey:
                    CNDTransientAppliedStateFontChanger];
            }
        }
        if (sbCustomizerActive != nil) {
            if (sbCustomizerActive.boolValue) {
                states[CNDTransientAppliedStateSBCustomizer] = @YES;
            }
        }
        NSDictionary *finalized = @{
            @"schemaVersion": @(CNDTransientAppliedStateSchemaVersion),
            @"springBoardPID": @(toPID),
            @"spotlightPID": @0,
            @"bootEpoch": @(bootEpoch),
            @"krwGenerationIdentifier": krwGenerationIdentifier,
            @"states": states,
            @"updatedAt": NSDate.date,
        };
        BOOL saved = CNDTransientAppliedStateWriteLocked(finalized);
        if (saved) {
            log_user("[ACTIVE_STATE] Finalized authorized SpringBoard transition transaction=%s %d->%d snowboard=%d font=%d sbc=%d.\n",
                     transactionIdentifier.UTF8String ?: "", fromPID, toPID,
                     [states[CNDTransientAppliedStateSnowBoardRemix] boolValue],
                     [states[CNDTransientAppliedStateFontChanger] boolValue],
                     [states[CNDTransientAppliedStateSBCustomizer] boolValue]);
        }
        return saved;
    }
}
