#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Persistent IconServices proof state. Apply uses one scoped
/// iconservicesagent session and the normal generation/store pipeline, then
/// one scoped installer session per UI consumer to leave the verified
/// marker-aware payload mapping resident. Rendering itself does not retain a
/// RemoteCall channel. Neither eBay's bundle nor its LaunchServices
/// registration is changed. See
/// docs/research/vphone-ios26-iconservices-persistence-and-consumer-mappings.md.
BOOL CNDIconServicesInterceptProofIsActive(void);
/// Retired entry point retained for source compatibility. It fails closed and
/// never opens Spotlight.
NSDictionary<NSString *, id> *CNDIconServicesInterceptProofInspectVisibleResponse(void);
NSDictionary<NSString *, id> *CNDIconServicesInterceptProofApply(void);
NSDictionary<NSString *, id> *CNDIconServicesInterceptProofRestore(void);

/// Forgets only Cyanide's active publisher/recovery bookkeeping. Live
/// consumer-mapping identities are retained so later applies can safely reuse
/// rather than stack them. This does not contact iconservicesagent,
/// SpringBoard, Spotlight, LaunchServices, or the target application, and it
/// does not claim that any external mutation was restored.
NSDictionary<NSString *, id> *CNDIconServicesInterceptProofResetRecoveryState(void);

NS_ASSUME_NONNULL_END
