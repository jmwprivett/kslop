#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Requires an active SpringBoard RemoteCall state. Decodes the three supplied
// PNG renditions inside SpringBoard, then updates only the live flashlight
// image glyph and camera button glyph. The mutation lives in SpringBoard
// memory and therefore naturally ends at respring/reboot.
NSDictionary<NSString *, id> *CNDLockscreenQuickActionApplyArtwork(
    NSData *cameraPNG,
    NSData *flashlightOffPNG,
    NSData *flashlightOnPNG);

// Rebuilds both stock glyphs through CSQuickActionsButton's native glyph
// factory and installs them on the live buttons. This is the inverse of the
// in-memory artwork apply and does not require a saved system-file backup.
NSDictionary<NSString *, id> *CNDLockscreenQuickActionRestoreStock(void);

NS_ASSUME_NONNULL_END
