#import <Foundation/Foundation.h>

@class RemoteCallSession;

NS_ASSUME_NONNULL_BEGIN

NSDictionary<NSString *, id> *cyanide_lab_probe_handle_request(
    RemoteCallSession *session,
    NSDictionary<NSString *, id> *request);

NS_ASSUME_NONNULL_END
