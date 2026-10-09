#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Requires an active SpringBoard RemoteCall context. This probe only reads the
// live Control Center controller/view graph and Objective-C runtime metadata.
// It never invokes a control action, setter, radio API, or file API in the
// target process.
NSDictionary<NSString *, id> *CNDCCThemingCopyPhysicalInventory(void);

// Captures the loaded compact/expanded Control Center controller and view
// graph, including media, connectivity, slider, Focus, and hosted-control icon
// owners. Only viewIfLoaded and other object getters are invoked; no view is
// materialized and no setter or control action is called.
NSDictionary<NSString *, id> *
CNDCCThemingCopyMediaConnectivityTrace(void);

// Captures lifecycle owners and direct, ABI-checked getter/typed-ivar routes
// from SpringBoard/Control Center containers and module registries. Never
// walks the UIKit view hierarchy or uses labels, geometry, or member order as
// control identity. Reports stable anchors and unresolved reconstruction
// paths; a capture does not prove an adapter survives view reconstruction.
NSDictionary<NSString *, id> *CNDCCThemingCopyLifecycleOwnerTrace(void);

// Narrow physical follow-up: process anchor, Media named slots, Flashlight,
// and Camera/Calculator/QR providers. Shares the bounded lifecycle walker;
// any loaded-view recursion is explicitly diagnostic/non-production.
NSDictionary<NSString *, id> *CNDCCThemingCopyRefinedPhysicalRouteTrace(void);

// Dedicated physical Focus capture: exact module/model/list/row/icon members,
// checked machine identifiers, and loaded picker view only; no discovery walk.
NSDictionary<NSString *, id> *CNDCCThemingCopyRefinedFocusRouteTrace(void);

// Local report-only comparison. Address changes are observations, not proof
// of allocation lifetime. Different/failed PID captures are never compared.
NSDictionary<NSString *, id> *CNDCCThemingCompareRefinedPhysicalRoutes(
    NSDictionary *current, NSDictionary * _Nullable previous);

// Compatibility entry point for the former media/Focus semantic diagnostic.
// Uses the same nonrecursive lifecycle trace; no discovery fallback exists.
NSDictionary<NSString *, id> *
CNDCCThemingCopyMediaFocusSemanticTrace(void);

// Re-enumerates the current Control Center graph and returns live template,
// compact connectivity, slider package, and media package targets that still
// classify to a stable kind. Address NSNumbers are ephemeral and valid only
// for the current PID-bound RemoteCall session.
NSArray<NSDictionary<NSString *, id> *> *
CNDCCThemingCopyResolvedLiveTemplates(void);

// Apply-only preparation. Materializes the already-owned Control Center
// controllers through ABI-checked loadViewIfNeeded and the traced module
// factories, without presenting Control Center, invoking a control action, or
// walking the view hierarchy. The read-only trace entry points above never
// call this function.
NSDictionary<NSString *, id> *
CNDCCThemingMaterializeExactRouteOwners(void);

// Resolves a stable inventory kind to its current live target inside the same
// PID-bound RemoteCall session. The returned address is ephemeral and is valid
// only while that session/PID remains current. No mutation is performed.
uint64_t CNDCCThemingResolveLiveTemplate(
    NSString *kind,
    NSDictionary<NSString *, id> * _Nullable * _Nullable metadata);

NS_ASSUME_NONNULL_END
