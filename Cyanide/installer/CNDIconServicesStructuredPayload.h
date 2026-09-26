#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString * const CNDIconServicesThemeMarker;
FOUNDATION_EXPORT NSString * const CNDIconServicesStructuredPayloadErrorDomain;

/// Builds the exact iOS 26 structured IconRendering payload used by the
/// transparent-chiclet VM proof. `scaledPNGData` must already match
/// `pointSize * scale`; no filesystem or remote-process state is changed.
NSData *_Nullable CNDIconServicesCreateStructuredLayerData(
    NSData *scaledPNGData,
    CGSize pointSize,
    CGFloat scale,
    NSDictionary<NSString *, id> *_Nullable *_Nullable diagnosticsOut,
    NSError *_Nullable *_Nullable errorOut);

/// Matrix form for consumers whose stock response canvas is padded beyond
/// `pointSize * scale` (notably 13pt -> 60px and 27/28pt -> 87px on the
/// observed iPhone iOS 26 pipeline). Descriptor geometry remains `pointSize`;
/// `pixelSize` validates the outer IFImage canvas only.
NSData *_Nullable CNDIconServicesCreateStructuredLayerDataWithPixelSize(
    NSData *scaledPNGData,
    CGSize pointSize,
    CGFloat scale,
    CGSize pixelSize,
    NSDictionary<NSString *, id> *_Nullable *_Nullable diagnosticsOut,
    NSError *_Nullable *_Nullable errorOut);

/// Wraps the structured layer data in the same serialized `IFImage.data`
/// envelope returned by the successful iconservicesagent generation proof.
/// The returned bytes are suitable for `IFCacheImage`
/// `initWithData:uuid:validationToken:`; no cache or process is changed.
NSData *_Nullable CNDIconServicesCreateStructuredImageData(
    NSData *scaledPNGData,
    CGSize pointSize,
    CGFloat scale,
    NSDictionary<NSString *, id> *_Nullable *_Nullable diagnosticsOut,
    NSError *_Nullable *_Nullable errorOut);

NSData *_Nullable CNDIconServicesCreateStructuredImageDataWithPixelSize(
    NSData *scaledPNGData,
    CGSize pointSize,
    CGFloat scale,
    CGSize pixelSize,
    NSDictionary<NSString *, id> *_Nullable *_Nullable diagnosticsOut,
    NSError *_Nullable *_Nullable errorOut);

NS_ASSUME_NONNULL_END
