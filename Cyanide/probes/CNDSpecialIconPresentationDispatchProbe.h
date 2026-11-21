#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDSpecialIconPresentationDispatchCompletion)(
    NSDictionary<NSString *, id> *report);

typedef NS_ENUM(NSUInteger, CNDSpecialIconPresentationRoute) {
    CNDSpecialIconPresentationRouteClock = 0,
    CNDSpecialIconPresentationRouteCalendar = 1,
    CNDSpecialIconPresentationRouteSwitcher = 2,
    CNDSpecialIconPresentationRouteAppLibraryMiniatures = 3,
};

typedef NS_ENUM(NSUInteger, CNDSpecialIconPresentationOperation) {
    CNDSpecialIconPresentationOperationApply = 0,
    CNDSpecialIconPresentationOperationRestore = 1,
    CNDSpecialIconPresentationOperationVerifyRedirected = 2,
    CNDSpecialIconPresentationOperationVerifyOriginal = 3,
};

/// Exact physical-device gate: iPhone17,2 on 23A341.
BOOL CNDSpecialIconPresentationDispatchProbeIsSupported(
    NSString * _Nullable * _Nullable reasonOut);
BOOL CNDSpecialIconPresentationDispatchPermissionIsRunning(void);
BOOL CNDSpecialIconPresentationDispatchRedirectIsRunning(void);

/// Runs one SpringBoard-only read-only Hail Mary proof, resolves all four
/// exact `.34.dyldreadonly` dispatch entries, and performs an identical
/// low-word write/readback at each exact address. No semantic state changes.
/// A confirmed report is the same-boot ticket for both routes.
void CNDSpecialIconPresentationDispatchPermissionRun(
    CNDSpecialIconPresentationDispatchCompletion completion);

/// Switcher-only counterpart. Proves the two distinct `.34.dyldreadonly`
/// pages that hold the matched title-item storage and provider entries. Its
/// ticket is intentionally separate from the Clock/Calendar ticket.
void CNDSwitcherPresentationDispatchPermissionRun(
    CNDSpecialIconPresentationDispatchCompletion completion);

/// App-Library-miniature counterpart. Proves the one `.34.dyldreadonly` page
/// containing `-[SBHIconManager prefersFlatImageLayers]`. Its ticket is
/// separate from both the Clock/Calendar and Switcher tickets.
void CNDAppLibraryMiniaturePresentationDispatchPermissionRun(
    CNDSpecialIconPresentationDispatchCompletion completion);

/// Applies, restores, or verifies one route. Clock owns one entry; Calendar
/// owns three entries; Switcher owns its matched two-entry storage/provider
/// route; App Library Miniatures owns one exact Boolean dispatch entry. Mutation
/// requires the exact route-compatible same-boot permission ticket. The
/// implementation never opens, injects, or calls
/// SpringBoard/Spotlight and never removes an icon object.
void CNDSpecialIconPresentationDispatchRedirectRun(
    CNDSpecialIconPresentationRoute route,
    CNDSpecialIconPresentationOperation operation,
    CNDSpecialIconPresentationDispatchCompletion completion);

NS_ASSUME_NONNULL_END
