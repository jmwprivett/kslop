#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Installs one one-shot ISGenerationRequest hook in iconservicesagent,
/// submits one direct `generateImageWithDescriptor:` client request, captures
/// and verifies both the
/// stock and replacement responses inside the service, restores the IMP,
/// removes the copied payload, requires the exact UUID-named `.isdata` bytes,
/// and closes that one session. SpringBoard and Spotlight are never opened.
/// `structuredImageData` is the outer IFImage.data envelope.
NSDictionary<NSString *, id> *
CNDIconServicesPublisherPublish(NSString *bundleIdentifier,
                                NSData *structuredImageData);

/// Uses the same service-side one-shot path without replacing the generated
/// response. The forced stock response and the service cache must match before
/// this reports success. No response getter is invoked in Cyanide.
NSDictionary<NSString *, id> *
CNDIconServicesPublisherRestoreStock(NSString *bundleIdentifier);

/// Opens one thread-owned iconservicesagent session for a complete batch. The
/// same pinned agent PID is used for installed-application discovery and every
/// publish/restore operation until FinishBatch is called on this thread.
NSDictionary<NSString *, id> *
CNDIconServicesPublisherBeginBatch(NSString *wakeBundleIdentifier);

/// Returns the compact, authoritative LaunchServices bundle-identifier list
/// plus path/version records used to fingerprint app updates, all from the
/// already-open iconservicesagent session. No second daemon or RemoteCall
/// channel is opened.
NSDictionary<NSString *, id> *
CNDIconServicesPublisherCopyInstalledBundleIdentifiersInBatch(void);

/// Per-target operations which reuse the current batch session. Their one-shot
/// publisher IMP and per-command objects are restored/quiesced before the
/// function returns. Reusable code/staging mappings may intentionally remain
/// owned by the batch until FinishBatch; only the batch transport remains
/// open between targets.
NSDictionary<NSString *, id> *
CNDIconServicesPublisherPublishInBatch(NSString *bundleIdentifier,
                                       NSData *structuredImageData);
NSDictionary<NSString *, id> *
CNDIconServicesPublisherRestoreStockInBatch(NSString *bundleIdentifier);

/// Variant-aware forms used by SnowBoard Remix's descriptor matrix. The
/// specification must contain pointWidth, pointHeight, scale, appearance,
/// iconVariant, and options. `iconVariant` is the persisted compatibility
/// name for ISImageDescriptor.variantOptions (the printed `v:` value), not
/// Apple's descriptor-factory preset enum. These calls borrow the thread-owned
/// batch and never open another iconservicesagent session.
NSDictionary<NSString *, id> *
CNDIconServicesPublisherPublishVariantInBatch(
    NSString *bundleIdentifier,
    NSData *structuredImageData,
    NSDictionary<NSString *, NSNumber *> *descriptorSpecification);
NSDictionary<NSString *, id> *
CNDIconServicesPublisherRestoreStockVariantInBatch(
    NSString *bundleIdentifier,
    NSDictionary<NSString *, NSNumber *> *descriptorSpecification);

/// Reads the existing canonical cache response, its exact ISStore unit, and
/// the UUID's persistent LaunchServices source identifier for one
/// already-journaled descriptor. It never generates, publishes, removes,
/// writes, restores, or invalidates an icon. The result includes independent
/// cache/store/source hashes and a byte-exact comparison with the current
/// LSApplicationRecord persistent identifier.
NSDictionary<NSString *, id> *
CNDIconServicesPublisherAuditVariantInBatch(
    NSString *bundleIdentifier,
    NSDictionary<NSString *, NSNumber *> *descriptorSpecification);

/*
 * Transport-neutral publisher result contract.
 *
 * The normalized operationCompleted field means that the one-shot command
 * itself completed. It is deliberately not a publication or restoration
 * proof. Callers which persist, activate, invalidate, or delete recovery
 * state must use the validators below. They consume:
 *
 *   agentCacheReadbackVerified       generated response matches agent cache
 *   persistentStoreReadbackVerified  exact indexed .isdata readback matches
 *   hookRestored / hookQuiescent     original IMP restored, no call in flight
 *   transactionCleaned               per-command target objects released
 *   payloadLifecycleVerified         no in-flight payload use; a reusable
 *                                    batch mapping may remain intentionally
 *   transportHealthy                 transport operation succeeded
 *   transportLifecycleVerified       transport is retained or closed cleanly
 *   batchTransportBorrowed           this result uses a retained batch
 *                                    transport rather than a standalone one
 *   transportRetained / transportClosed / transportAbandoned
 *   transportLocalStateRemaining     normalized session-state observation
 *
 * payloadPhysicallyUnmapped is diagnostic only: it is false when a reusable
 * batch payload/staging mapping is safely retained for FinishBatch. The
 * validators require payloadLifecycleVerified, not physical unmapping.
 *
 * deepVerificationSkippedForBenchmark, when present, is diagnostic only and
 * can never make one of these validators return YES.  The contract is
 * independent of the concrete transport implementation. SnowBoard Remix may
 * separately recognize an explicitly labeled legacy provisional acceptance
 * policy so the established RemoteCall apply behavior remains available;
 * that policy does not turn an unverified result into verified proof.
 */
BOOL CNDIconServicesPublisherPublicationResultIsVerified(
    NSDictionary<NSString *, id> *result);
BOOL CNDIconServicesPublisherRestorationResultIsVerified(
    NSDictionary<NSString *, id> *result);
BOOL CNDIconServicesPublisherResultIsSafeToFinalize(
    NSDictionary<NSString *, id> *result);

BOOL CNDIconServicesPublisherBatchIsHealthy(void);

/// Closes and clears the thread-owned batch transport. A successful result
/// proves clean teardown and no remaining local transport state or reusable
/// payload/staging mapping.
NSDictionary<NSString *, id> *
CNDIconServicesPublisherFinishBatch(void);

NS_ASSUME_NONNULL_END
