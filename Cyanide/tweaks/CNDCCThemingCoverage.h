#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Summarizes local installation records. Kind counts describe captured
/// receivers; they cannot establish which page renders those receivers or
/// whether future receivers inherit their artwork.
static inline NSDictionary<NSString *, id> *CNDCCThemingCapturedCoverage(
    NSArray<NSDictionary<NSString *, id> *> *records)
{
    NSDictionary<NSString *, NSArray<NSString *> *> *scopeKinds = @{
        @"compactConnectivity": @[@"wifi", @"bluetooth", @"airDrop",
            @"airplaneMode", @"cellular", @"hotspot", @"vpn",
            @"satelliteUnavailable", @"satelliteAvailable", @"satelliteConnected"],
        @"expandedConnectivity": @[@"wifi", @"bluetooth", @"airDrop",
            @"airplaneMode", @"cellular", @"hotspot", @"vpn",
            @"satelliteUnavailable", @"satelliteAvailable", @"satelliteConnected"],
        @"compactBrightness": @[@"display"],
        @"expandedBrightness": @[@"display", @"appearance", @"nightShift", @"trueTone"],
        @"compactVolume": @[@"sound"],
        @"expandedVolume": @[@"sound"],
        @"baseNowPlaying": @[@"mediaPrevious", @"mediaPlayPause", @"mediaNext",
            @"mediaAirPlay"],
        @"expandedNowPlaying": @[@"mediaPrevious", @"mediaPlayPause", @"mediaNext",
            @"mediaAirPlay"],
        @"expandedFocus": @[@"focus", @"focusSleep", @"focusPersonal",
            @"focusWork", @"focusReduceInterruptions", @"focusCustom"],
    };
    NSMutableDictionary *scopes = [NSMutableDictionary dictionary];
    for (NSString *scope in scopeKinds) {
        NSMutableDictionary<NSString *, NSNumber *> *counts =
            [NSMutableDictionary dictionary];
        NSMutableArray<NSString *> *routeIDs = [NSMutableArray array];
        for (id candidate in records) {
            if (![candidate isKindOfClass:NSDictionary.class]) continue;
            NSArray *recordScopes = [candidate[@"scopes"]
                isKindOfClass:NSArray.class] ? candidate[@"scopes"] : @[];
            NSString *kind = [candidate[@"kind"] isKindOfClass:NSString.class]
                ? candidate[@"kind"] : nil;
            BOOL legacyKindOnlyRecord = recordScopes.count == 0 &&
                [scopeKinds[scope] containsObject:kind ?: @""];
            if (![recordScopes containsObject:scope] &&
                !legacyKindOnlyRecord) continue;
            if (kind.length) {
                counts[kind] = @([counts[kind] unsignedIntegerValue] + 1);
            }
            NSString *routeID = [candidate[@"routeID"]
                isKindOfClass:NSString.class] ? candidate[@"routeID"] : nil;
            if (routeID.length && ![routeIDs containsObject:routeID]) {
                [routeIDs addObject:routeID];
            }
        }
        NSMutableDictionary *kindCounts = [NSMutableDictionary dictionary];
        NSUInteger count = 0;
        for (NSString *kind in scopeKinds[scope]) {
            NSNumber *observed = counts[kind] ?: @0;
            kindCounts[kind] = observed;
            count += observed.unsignedIntegerValue;
        }
        scopes[scope] = @{
            @"status": count ? @"surface-coverage-unverified" : @"no-kind-receivers-captured",
            @"capturedReceiverCountsByKind": kindCounts,
            @"exactRouteIDs": routeIDs,
            @"exactNamedRouteCount": @(routeIDs.count),
            @"countsAreSurfaceCoverage": @NO,
            @"surfaceCoverageVerified": @NO,
            @"interactionPersistenceVerified": @NO,
            @"reconstructionPersistenceVerified": @NO,
            @"complete": @NO,
        };
    }
    return @{
        @"installationScope": @"captured-receivers",
        @"providerFactoryActive": @NO,
        @"samePIDPersistenceVerified": @NO,
        @"complete": @NO,
        @"surfaceCoverage": scopes,
        @"pendingCoverageScopes": [scopeKinds.allKeys sortedArrayUsingSelector:@selector(compare:)],
    };
}

NS_ASSUME_NONNULL_END
