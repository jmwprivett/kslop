#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NSDictionary<NSString *, id> * _Nonnull
    (^CyanideLabBridgeRequestHandler)(NSDictionary<NSString *, id> *request);

BOOL cyanide_lab_bridge_start(
    CyanideLabBridgeRequestHandler handler,
    dispatch_block_t stopHandler,
    NSError **errorOut);
void cyanide_lab_bridge_stop(void);
BOOL cyanide_lab_bridge_is_running(void);
NSString * _Nullable cyanide_lab_bridge_token(void);
uint16_t cyanide_lab_bridge_port(void);

NS_ASSUME_NONNULL_END
