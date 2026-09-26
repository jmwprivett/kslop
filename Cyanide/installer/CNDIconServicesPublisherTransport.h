#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/*
 * Internal publisher boundary.  The facade owns the selected instance and
 * its thread affinity; implementations own only the transport-specific
 * session and per-operation work.  Keep this contract free of any concrete
 * session, task, or Objective-C message types so another implementation can
 * be added without changing the public publisher API.
 */
@protocol CNDIconServicesPublisherTransport <NSObject>

- (NSDictionary<NSString *, id> *)beginBatch:(NSString *)wakeBundleIdentifier;
- (NSDictionary<NSString *, id> *)copyInstalledBundleIdentifiersInBatch;
- (NSDictionary<NSString *, id> *)publishBundleIdentifier:(NSString *)bundleIdentifier
                                      structuredImageData:(nullable NSData *)structuredImageData;
- (NSDictionary<NSString *, id> *)publishBundleIdentifier:(NSString *)bundleIdentifier
                                      structuredImageData:(nullable NSData *)structuredImageData
                                  descriptorSpecification:(NSDictionary<NSString *, NSNumber *> *)descriptorSpecification;
- (NSDictionary<NSString *, id> *)restoreStockForBundleIdentifier:(NSString *)bundleIdentifier;
- (NSDictionary<NSString *, id> *)restoreStockForBundleIdentifier:(NSString *)bundleIdentifier
                                           descriptorSpecification:(NSDictionary<NSString *, NSNumber *> *)descriptorSpecification;
- (NSDictionary<NSString *, id> *)auditBundleIdentifier:(NSString *)bundleIdentifier
                                  descriptorSpecification:(NSDictionary<NSString *, NSNumber *> *)descriptorSpecification;
- (BOOL)isHealthy;
- (NSDictionary<NSString *, id> *)finishBatch;

@end

/// Returns the currently selected implementation for the public facade.
/// The concrete adapter and its session state are private to that
/// implementation.
id<CNDIconServicesPublisherTransport>
CNDIconServicesPublisherMakeDefaultTransport(void);

NS_ASSUME_NONNULL_END
