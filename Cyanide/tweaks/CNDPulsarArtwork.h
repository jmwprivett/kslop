#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

NSData *CNDPulsarCameraPNGData(void);
NSData *CNDPulsarFlashlightOffPNGData(void);
NSData *CNDPulsarFlashlightOnPNGData(void);

// Every official Pulsar v2 Control Center asset with a stable live mapping.
// Static entries contain embedded PNG data; stateful entries name a packaged
// CAML resource. All entries retain source and compatibility metadata.
NSDictionary<NSString *, NSDictionary<NSString *, id> *> *
CNDPulsarControlCenterArtwork(void);

NS_ASSUME_NONNULL_END
