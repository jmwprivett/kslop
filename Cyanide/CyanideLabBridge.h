#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NSDictionary<NSString *, id> * _Nonnull
    (^CyanideLabBridgeRequestHandler)(NSDictionary<NSString *, id> *request);

BOOL cyanide_lab_bridge_start(
    CyanideLabBridgeRequestHandler handler,
    dispatch_block_t stopHandler,
    NSError **errorOut);
/// Starts an exclusive bridge instance with a caller-provided, single-use
/// authentication token.  Unlike cyanide_lab_bridge_start(), this fails when
/// another bridge already owns the listener instead of silently reusing it.
BOOL cyanide_lab_bridge_start_with_token(
    CyanideLabBridgeRequestHandler handler,
    dispatch_block_t _Nullable stopHandler,
    NSString *token,
    NSError **errorOut);
void cyanide_lab_bridge_stop(void);
BOOL cyanide_lab_bridge_is_running(void);
NSString * _Nullable cyanide_lab_bridge_token(void);
uint16_t cyanide_lab_bridge_port(void);

NS_ASSUME_NONNULL_END
