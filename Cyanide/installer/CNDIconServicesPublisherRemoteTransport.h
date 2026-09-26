#import "CNDIconServicesPublisherTransport.h"

NS_ASSUME_NONNULL_BEGIN

/// Creates the legacy IconServices transport adapter used by the facade.
/// The concrete session type remains private to the adapter implementation.
id<CNDIconServicesPublisherTransport>
CNDIconServicesPublisherMakeDefaultTransport(void);

NS_ASSUME_NONNULL_END
