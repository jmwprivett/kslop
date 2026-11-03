#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Captures the two measured AirDrop descriptors, UIAirDropActivity image,
/// and currently materialized Share-sheet tile in the exact running
/// SharingUIService process. The diagnostic invokes only resident Apple-signed
/// Objective-C/UIKit code and copies PNG data back for local canonical hashing;
/// it performs no method interposition and creates no executable mapping.
FOUNDATION_EXPORT NSDictionary<NSString *, id> *
CNDShareSheetTelemetryCapture(void);

NS_ASSUME_NONNULL_END
