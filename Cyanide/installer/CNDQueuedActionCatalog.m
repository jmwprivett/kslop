#import "CNDQueuedActionCatalog.h"

NSString * const CNDQueuedActionKindPackage = @"package";
NSString * const CNDQueuedActionKindSnowBoardRemix = @"snowboard-remix";
NSString * const CNDQueuedActionKindTransparencyFix = @"transparency-fix";
NSString * const CNDQueuedActionKindSpringBoardFixes = @"springboard-fixes";
NSString * const CNDQueuedActionKindSpotlightFixes = @"spotlight-fixes";
NSString * const CNDQueuedActionKindSpringBoardSpotlightFixes =
    @"springboard-spotlight-fixes";

NSString * const CNDQueuedActionOperationInstall = @"install";
NSString * const CNDQueuedActionOperationUninstall = @"uninstall";
NSString * const CNDQueuedActionOperationApplyTheme = @"apply-theme";
NSString * const CNDQueuedActionOperationRestoreTheme = @"restore-theme";
NSString * const CNDQueuedActionOperationApplyTransparencyFix =
    @"apply-transparency-fix";
NSString * const CNDQueuedActionOperationRestoreTransparencyFix =
    @"restore-transparency-fix";
NSString * const CNDQueuedActionOperationApplyFixes = @"apply-fixes";

NSString * const CNDQueuedActionParameterPackageInstallKind =
    @"packageInstallKind";
NSString * const CNDQueuedActionParameterThemeIdentifier = @"themeIdentifier";
NSString * const CNDQueuedActionParameterTransparencyEnabled =
    @"transparencyEnabled";
NSString * const CNDQueuedActionParameterSpotlightAssertionRequired =
    @"spotlightAssertionRequired";

NSString * const CNDQueuedActionConflictKeySnowBoardRemix =
    @"snowboard-remix:icons";
NSString * const CNDQueuedActionConflictKeyTransparencyFix =
    @"snowboard-remix:transparency-fix";
NSString * const CNDQueuedActionConflictKeySpringBoardFixes =
    @"springboard-fixes:springboard";
NSString * const CNDQueuedActionConflictKeySpotlightFixes =
    @"spotlight-fixes:spotlight";
NSString * const CNDQueuedActionConflictKeySpringBoardSpotlightFixes =
    @"springboard-spotlight-fixes:system-ui";

static CNDQueuedAction *CNDQueuedCatalogAction(
    NSString *recordIdentifier,
    NSString *kind,
    NSString *subjectIdentifier,
    NSString *operation,
    CNDQueuedActionPhase phase,
    NSDictionary<NSString *, id> *parameters)
{
    NSDate *now = [NSDate date];
    return [[CNDQueuedAction alloc]
        initWithRecordIdentifier:recordIdentifier
                            kind:kind
               subjectIdentifier:subjectIdentifier
                       operation:operation
                           phase:phase
                           state:CNDQueuedActionStatePending
                      parameters:parameters ?: @{}
                       createdAt:now
                       updatedAt:now
                       lastError:nil];
}

static CNDQueuedActionPhase CNDQueuedPackagePhaseForKind(
    PackageInstallKind kind)
{
    switch (kind) {
        case PackageInstallKindHideHomeBar:
        case PackageInstallKindFontChanger:
        case PackageInstallKindControlCenterTheming:
            return CNDQueuedActionPhaseBeforeRespring;
        case PackageInstallKindToggle:
        case PackageInstallKindOTA:
        case PackageInstallKindNanoRegistry:
        case PackageInstallKindCallRecordingSound:
        case PackageInstallKindLockscreenGlyphs:
        case PackageInstallKindDirectTool:
            return CNDQueuedActionPhaseAutomatic;
    }
    return CNDQueuedActionPhaseAutomatic;
}

static BOOL CNDQueuedPackageKindIsSupported(NSInteger rawKind)
{
    switch ((PackageInstallKind)rawKind) {
        case PackageInstallKindToggle:
        case PackageInstallKindOTA:
        case PackageInstallKindNanoRegistry:
        case PackageInstallKindCallRecordingSound:
        case PackageInstallKindHideHomeBar:
        case PackageInstallKindFontChanger:
        case PackageInstallKindControlCenterTheming:
            return YES;
        case PackageInstallKindLockscreenGlyphs:
        case PackageInstallKindDirectTool:
            return NO;
    }
    return NO;
}

CNDQueuedAction *CNDQueuedActionForPackage(Package *package, BOOL installed)
{
    NSString *operation = installed
        ? CNDQueuedActionOperationInstall : CNDQueuedActionOperationUninstall;
    NSString *recordIdentifier = [NSString stringWithFormat:
        @"package:%@:%@", package.identifier ?: @"", operation];
    return CNDQueuedCatalogAction(
        recordIdentifier,
        CNDQueuedActionKindPackage,
        package.identifier ?: @"",
        operation,
        CNDQueuedPackagePhaseForKind(package.kind),
        @{ CNDQueuedActionParameterPackageInstallKind: @(package.kind) });
}

CNDQueuedAction *CNDQueuedSnowBoardRemixAction(
    BOOL apply,
    NSString *themeIdentifier)
{
    NSString *operation = apply
        ? CNDQueuedActionOperationApplyTheme
        : CNDQueuedActionOperationRestoreTheme;
    NSDictionary<NSString *, id> *parameters = apply
        ? @{ CNDQueuedActionParameterThemeIdentifier: themeIdentifier ?: @"" }
        : @{};
    return CNDQueuedCatalogAction(
        [NSString stringWithFormat:@"snowboard-remix:icons:%@", operation],
        CNDQueuedActionKindSnowBoardRemix,
        @"icons",
        operation,
        CNDQueuedActionPhaseBeforeRespring,
        parameters);
}

CNDQueuedAction *CNDQueuedTransparencyFixAction(BOOL apply)
{
    NSString *operation = apply
        ? CNDQueuedActionOperationApplyTransparencyFix
        : CNDQueuedActionOperationRestoreTransparencyFix;
    return CNDQueuedCatalogAction(
        [NSString stringWithFormat:@"transparency-fix:shared-cache:%@",
            operation],
        CNDQueuedActionKindTransparencyFix,
        @"shared-cache",
        operation,
        CNDQueuedActionPhaseAutomatic,
        @{});
}

CNDQueuedAction *CNDQueuedSpringBoardFixesAction(
    BOOL transparencyEnabled)
{
    return CNDQueuedCatalogAction(
        @"springboard-fixes:springboard:apply-fixes",
        CNDQueuedActionKindSpringBoardFixes,
        @"springboard",
        CNDQueuedActionOperationApplyFixes,
        CNDQueuedActionPhaseAutomatic,
        @{
            CNDQueuedActionParameterTransparencyEnabled:
                @(transparencyEnabled),
        });
}

CNDQueuedAction *CNDQueuedSpotlightFixesAction(
    BOOL transparencyEnabled)
{
    return CNDQueuedCatalogAction(
        @"spotlight-fixes:spotlight:apply-fixes",
        CNDQueuedActionKindSpotlightFixes,
        @"spotlight",
        CNDQueuedActionOperationApplyFixes,
        CNDQueuedActionPhaseAutomatic,
        @{
            CNDQueuedActionParameterTransparencyEnabled:
                @(transparencyEnabled),
            CNDQueuedActionParameterSpotlightAssertionRequired: @YES,
        });
}

CNDQueuedAction *CNDQueuedSpringBoardSpotlightFixesAction(
    BOOL transparencyEnabled)
{
    return CNDQueuedCatalogAction(
        @"springboard-spotlight-fixes:system-ui:apply-fixes",
        CNDQueuedActionKindSpringBoardSpotlightFixes,
        @"system-ui",
        CNDQueuedActionOperationApplyFixes,
        CNDQueuedActionPhaseAutomatic,
        @{
            CNDQueuedActionParameterTransparencyEnabled:
                @(transparencyEnabled),
            CNDQueuedActionParameterSpotlightAssertionRequired: @YES,
        });
}

static BOOL CNDQueuedCatalogReject(
    NSString *message,
    NSString **reason)
{
    if (reason) *reason = message;
    return NO;
}

BOOL CNDQueuedActionHasSupportedShape(
    CNDQueuedAction *action,
    NSString **reason)
{
    if (reason) *reason = nil;
    if (!action) {
        return CNDQueuedCatalogReject(@"The queued action is missing.", reason);
    }

    NSString *expectedRecordIdentifier = [NSString stringWithFormat:
        @"%@:%@:%@", action.kind, action.subjectIdentifier,
        action.operation];
    if (![action.recordIdentifier isEqualToString:expectedRecordIdentifier]) {
        return CNDQueuedCatalogReject(
            @"The queued action identifier does not match its fields.", reason);
    }

    if ([action.kind isEqualToString:CNDQueuedActionKindPackage]) {
        BOOL operationSupported =
            [action.operation isEqualToString:CNDQueuedActionOperationInstall] ||
            [action.operation isEqualToString:CNDQueuedActionOperationUninstall];
        if (!operationSupported) {
            return CNDQueuedCatalogReject(
                @"The package operation is unsupported.", reason);
        }
        id packageKind =
            action.parameters[CNDQueuedActionParameterPackageInstallKind];
        if (packageKind != nil &&
            ![packageKind isKindOfClass:NSNumber.class]) {
            return CNDQueuedCatalogReject(
                @"The package action contains an invalid package kind.", reason);
        }
        if (packageKind != nil) {
            NSInteger rawKind = [packageKind integerValue];
            if (!CNDQueuedPackageKindIsSupported(rawKind)) {
                return CNDQueuedCatalogReject(
                    @"The package action contains an unsupported package kind.",
                    reason);
            }
            CNDQueuedActionPhase expectedPhase =
                CNDQueuedPackagePhaseForKind((PackageInstallKind)rawKind);
            if (action.phase != expectedPhase) {
                return CNDQueuedCatalogReject(
                    @"The package action phase does not match its package kind.",
                    reason);
            }
        } else if (action.phase != CNDQueuedActionPhaseAutomatic) {
            // Schema-v1 records written before package-kind snapshots existed
            // are accepted only in their original adaptive phase.
            return CNDQueuedCatalogReject(
                @"The legacy package action has an invalid phase.", reason);
        }
        return YES;
    }

    if ([action.kind isEqualToString:CNDQueuedActionKindSnowBoardRemix]) {
        if (![action.subjectIdentifier isEqualToString:@"icons"] ||
            action.phase != CNDQueuedActionPhaseBeforeRespring) {
            return CNDQueuedCatalogReject(
                @"The SnowBoard Remix action has an invalid subject or phase.",
                reason);
        }
        if ([action.operation isEqualToString:CNDQueuedActionOperationApplyTheme]) {
            NSString *theme =
                action.parameters[CNDQueuedActionParameterThemeIdentifier];
            if (![theme isKindOfClass:NSString.class] || theme.length == 0) {
                return CNDQueuedCatalogReject(
                    @"The SnowBoard Remix Apply action has no selected theme.",
                    reason);
            }
            return YES;
        }
        if ([action.operation isEqualToString:CNDQueuedActionOperationRestoreTheme] &&
            action.parameters.count == 0) {
            return YES;
        }
        return CNDQueuedCatalogReject(
            @"The SnowBoard Remix operation is unsupported.", reason);
    }

    if ([action.kind isEqualToString:CNDQueuedActionKindTransparencyFix]) {
        BOOL validOperation =
            [action.operation isEqualToString:
                CNDQueuedActionOperationApplyTransparencyFix] ||
            [action.operation isEqualToString:
                CNDQueuedActionOperationRestoreTransparencyFix];
        BOOL valid =
            [action.subjectIdentifier isEqualToString:@"shared-cache"] &&
            action.phase == CNDQueuedActionPhaseAutomatic &&
            validOperation && action.parameters.count == 0;
        return valid ? YES : CNDQueuedCatalogReject(
            @"The Transparency Fix action has an invalid shape.", reason);
    }

    if ([action.kind isEqualToString:CNDQueuedActionKindSpringBoardFixes]) {
        id transparency =
            action.parameters[CNDQueuedActionParameterTransparencyEnabled];
        BOOL valid =
            [action.subjectIdentifier isEqualToString:@"springboard"] &&
            [action.operation isEqualToString:CNDQueuedActionOperationApplyFixes] &&
            action.phase == CNDQueuedActionPhaseAutomatic &&
            [transparency isKindOfClass:NSNumber.class] &&
            action.parameters.count == 1;
        return valid ? YES : CNDQueuedCatalogReject(
            @"The SpringBoard fixes action has an invalid shape.", reason);
    }

    if ([action.kind isEqualToString:CNDQueuedActionKindSpotlightFixes] ||
        [action.kind isEqualToString:
            CNDQueuedActionKindSpringBoardSpotlightFixes]) {
        id transparency =
            action.parameters[CNDQueuedActionParameterTransparencyEnabled];
        id assertion =
            action.parameters[CNDQueuedActionParameterSpotlightAssertionRequired];
        BOOL legacy = [action.kind isEqualToString:
            CNDQueuedActionKindSpringBoardSpotlightFixes];
        BOOL valid =
            [action.subjectIdentifier isEqualToString:
                legacy ? @"system-ui" : @"spotlight"] &&
            [action.operation isEqualToString:CNDQueuedActionOperationApplyFixes] &&
            action.phase == CNDQueuedActionPhaseAutomatic &&
            [transparency isKindOfClass:NSNumber.class] &&
            [assertion isKindOfClass:NSNumber.class] &&
            [assertion boolValue] && action.parameters.count == 2;
        return valid ? YES : CNDQueuedCatalogReject(
            legacy
                ? @"The legacy SpringBoard & Spotlight action has an invalid shape."
                : @"The Spotlight fixes action has an invalid shape.",
            reason);
    }

    return CNDQueuedCatalogReject(@"The queued action kind is unsupported.",
                                  reason);
}

NSString *CNDQueuedActionConflictKey(CNDQueuedAction *action)
{
    if ([action.kind isEqualToString:CNDQueuedActionKindPackage]) {
        return [NSString stringWithFormat:@"package:%@",
            action.subjectIdentifier];
    }
    if ([action.kind isEqualToString:CNDQueuedActionKindSnowBoardRemix]) {
        return CNDQueuedActionConflictKeySnowBoardRemix;
    }
    if ([action.kind isEqualToString:CNDQueuedActionKindTransparencyFix]) {
        return CNDQueuedActionConflictKeyTransparencyFix;
    }
    if ([action.kind isEqualToString:CNDQueuedActionKindSpringBoardFixes]) {
        return CNDQueuedActionConflictKeySpringBoardFixes;
    }
    if ([action.kind isEqualToString:CNDQueuedActionKindSpotlightFixes]) {
        return CNDQueuedActionConflictKeySpotlightFixes;
    }
    if ([action.kind isEqualToString:
            CNDQueuedActionKindSpringBoardSpotlightFixes]) {
        return CNDQueuedActionConflictKeySpringBoardSpotlightFixes;
    }
    return action.recordIdentifier;
}

CNDQueuedActionPhase CNDQueuedActionResolvedPhase(
    CNDQueuedAction *action,
    BOOL transactionRequiresRespring)
{
    if (action.phase != CNDQueuedActionPhaseAutomatic) return action.phase;
    return transactionRequiresRespring
        ? CNDQueuedActionPhaseAfterRespring
        : CNDQueuedActionPhaseBeforeRespring;
}

BOOL CNDQueuedActionsRequireRespring(NSArray<CNDQueuedAction *> *actions)
{
    for (CNDQueuedAction *action in actions) {
        if (action.state == CNDQueuedActionStateSucceeded) continue;
        // An explicit post-respring action also establishes the boundary when
        // it is queued by itself; otherwise it would have no process epoch in
        // which it could become eligible.
        if (action.phase != CNDQueuedActionPhaseAutomatic) return YES;
    }
    return NO;
}

static NSInteger CNDQueuedActionExecutionPriority(CNDQueuedAction *action)
{
    if ([action.kind isEqualToString:CNDQueuedActionKindSnowBoardRemix]) {
        return 100;
    }
    if ([action.kind isEqualToString:CNDQueuedActionKindPackage]) {
        return 200;
    }
    if ([action.kind isEqualToString:CNDQueuedActionKindTransparencyFix]) {
        return 250;
    }
    if ([action.kind isEqualToString:
            CNDQueuedActionKindSpringBoardSpotlightFixes]) {
        return 300;
    }
    if ([action.kind isEqualToString:CNDQueuedActionKindSpringBoardFixes]) {
        return 300;
    }
    if ([action.kind isEqualToString:CNDQueuedActionKindSpotlightFixes]) {
        return 400;
    }
    return NSIntegerMax;
}

NSArray<CNDQueuedAction *> *CNDQueuedActionsForExecutionPhase(
    NSArray<CNDQueuedAction *> *actions,
    CNDQueuedActionPhase phase,
    BOOL transactionRequiresRespring)
{
    if (phase == CNDQueuedActionPhaseAutomatic) return @[];
    NSMutableArray<CNDQueuedAction *> *eligible = [NSMutableArray array];
    for (CNDQueuedAction *action in actions) {
        if (action.state == CNDQueuedActionStateSucceeded) continue;
        if (CNDQueuedActionResolvedPhase(action, transactionRequiresRespring) !=
            phase) {
            continue;
        }
        [eligible addObject:action];
    }
    [eligible sortUsingComparator:^NSComparisonResult(
        CNDQueuedAction *left,
        CNDQueuedAction *right) {
        NSInteger leftPriority = CNDQueuedActionExecutionPriority(left);
        NSInteger rightPriority = CNDQueuedActionExecutionPriority(right);
        if (leftPriority < rightPriority) return NSOrderedAscending;
        if (leftPriority > rightPriority) return NSOrderedDescending;
        NSComparisonResult dateOrder = [left.createdAt compare:right.createdAt];
        if (dateOrder != NSOrderedSame) return dateOrder;
        return [left.recordIdentifier compare:right.recordIdentifier];
    }];
    return eligible;
}
