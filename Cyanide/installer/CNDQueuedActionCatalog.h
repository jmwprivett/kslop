#import <Foundation/Foundation.h>

#import "CNDQueuedTransaction.h"
#import "Package.h"

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString * const CNDQueuedActionKindPackage;
FOUNDATION_EXPORT NSString * const CNDQueuedActionKindSnowBoardRemix;
FOUNDATION_EXPORT NSString * const CNDQueuedActionKindTransparencyFix;
FOUNDATION_EXPORT NSString * const CNDQueuedActionKindSpringBoardFixes;
FOUNDATION_EXPORT NSString * const CNDQueuedActionKindSpotlightFixes;
/// Legacy schema-v1 kind. Hydration expands it into the two bounded actions.
FOUNDATION_EXPORT NSString * const CNDQueuedActionKindSpringBoardSpotlightFixes;

FOUNDATION_EXPORT NSString * const CNDQueuedActionOperationInstall;
FOUNDATION_EXPORT NSString * const CNDQueuedActionOperationUninstall;
FOUNDATION_EXPORT NSString * const CNDQueuedActionOperationApplyTheme;
FOUNDATION_EXPORT NSString * const CNDQueuedActionOperationRestoreTheme;
FOUNDATION_EXPORT NSString * const CNDQueuedActionOperationApplyTransparencyFix;
FOUNDATION_EXPORT NSString * const CNDQueuedActionOperationRestoreTransparencyFix;
FOUNDATION_EXPORT NSString * const CNDQueuedActionOperationApplyFixes;

FOUNDATION_EXPORT NSString * const CNDQueuedActionParameterPackageInstallKind;
FOUNDATION_EXPORT NSString * const CNDQueuedActionParameterThemeIdentifier;
FOUNDATION_EXPORT NSString * const CNDQueuedActionParameterTransparencyEnabled;
FOUNDATION_EXPORT NSString * const CNDQueuedActionParameterSpotlightAssertionRequired;

FOUNDATION_EXPORT NSString * const CNDQueuedActionConflictKeySnowBoardRemix;
FOUNDATION_EXPORT NSString * const CNDQueuedActionConflictKeyTransparencyFix;
FOUNDATION_EXPORT NSString * const CNDQueuedActionConflictKeySpringBoardFixes;
FOUNDATION_EXPORT NSString * const CNDQueuedActionConflictKeySpotlightFixes;
FOUNDATION_EXPORT NSString * const CNDQueuedActionConflictKeySpringBoardSpotlightFixes;

/// Creates the durable action for the package's current install or uninstall
/// intent. System-file changes that need a process restart are explicitly
/// pre-respring. Normal packages remain adaptive so the coordinator can run
/// them immediately when there is no restart boundary, or afterward when one
/// exists.
FOUNDATION_EXPORT CNDQueuedAction *CNDQueuedActionForPackage(
    Package *package,
    BOOL installed);

/// Persistent IconServices mutations happen before the shared respring.
/// Apply snapshots the selected theme identifier so relaunch cannot silently
/// change the requested input. Restore uses an empty theme identifier.
FOUNDATION_EXPORT CNDQueuedAction *CNDQueuedSnowBoardRemixAction(
    BOOL apply,
    NSString * _Nullable themeIdentifier);

/// Per-boot shared-cache transparency redirect. It is adaptive: when queued
/// alone it runs in the current process epoch; when combined with a respring
/// plan it runs afterward. Apply and Restore replace each other atomically.
FOUNDATION_EXPORT CNDQueuedAction *CNDQueuedTransparencyFixAction(BOOL apply);

/// Independent adaptive presentation actions. Each runs in the current
/// process epoch when queued alone, or after the shared respring when another
/// action establishes a restart boundary. Spotlight always acquires its
/// SpringBoard-owned lifetime assertion; transparency controls the optional
/// icon/Clock/Calendar presentation work.
FOUNDATION_EXPORT CNDQueuedAction *CNDQueuedSpringBoardFixesAction(
    BOOL transparencyEnabled);
FOUNDATION_EXPORT CNDQueuedAction *CNDQueuedSpotlightFixesAction(
    BOOL transparencyEnabled);

/// Legacy factory retained only for schema-v1 source compatibility. New UI
/// and queue code must enqueue the two independent factories above.
FOUNDATION_EXPORT CNDQueuedAction *CNDQueuedSpringBoardSpotlightFixesAction(
    BOOL transparencyEnabled);

/// Rejects malformed or unknown action shapes without executing them. Package
/// availability is resolved separately against PackageCatalog at hydration.
FOUNDATION_EXPORT BOOL CNDQueuedActionHasSupportedShape(
    CNDQueuedAction *action,
    NSString *_Nullable *_Nullable reason);

/// Actions sharing a conflict key replace one another when they represent
/// mutually-exclusive desired states (for example theme Apply vs Restore).
FOUNDATION_EXPORT NSString *CNDQueuedActionConflictKey(CNDQueuedAction *action);

/// Resolves adaptive actions for a particular transaction. If any explicit
/// pre-respring action exists, adaptive actions run after it; otherwise they
/// run in the current process epoch.
FOUNDATION_EXPORT CNDQueuedActionPhase CNDQueuedActionResolvedPhase(
    CNDQueuedAction *action,
    BOOL transactionRequiresRespring);

FOUNDATION_EXPORT BOOL CNDQueuedActionsRequireRespring(
    NSArray<CNDQueuedAction *> *actions);

/// Returns unfinished actions for one resolved phase in deterministic order.
/// SnowBoard's persistent publication/restoration precedes system-file edits;
/// after the boundary, ordinary package work precedes SpringBoard repair and
/// Spotlight repair remains last so its user-visible open prompt is timely.
FOUNDATION_EXPORT NSArray<CNDQueuedAction *> *CNDQueuedActionsForExecutionPhase(
    NSArray<CNDQueuedAction *> *actions,
    CNDQueuedActionPhase phase,
    BOOL transactionRequiresRespring);

NS_ASSUME_NONNULL_END
