//
//  CNDIconThemeImageProcessor.h
//  Cyanide
//
//  Bounded, deterministic PNG processing for SnowBoard Remix icon assets.
//
//  This file deliberately does not depend on UIKit.  The implementation
//  decodes PNGs into straight RGBA8 pixels, applies PNG EXIF orientation, fits
//  the image on a transparent canvas using premultiplied-alpha Catmull-Rom
//  resampling, and writes a canonical PNG.  It is
//  therefore also suitable for a small host-side verifier.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSString * const CNDIconThemeImageProcessorErrorDomain;

typedef NS_ERROR_ENUM(CNDIconThemeImageProcessorErrorDomain,
                      CNDIconThemeImageProcessorError) {
    CNDIconThemeImageProcessorErrorInvalidArgument = 1,
    CNDIconThemeImageProcessorErrorInvalidPNG = 2,
    CNDIconThemeImageProcessorErrorUnsupportedPNG = 3,
    CNDIconThemeImageProcessorErrorResourceLimit = 4,
    CNDIconThemeImageProcessorErrorDecode = 5,
    CNDIconThemeImageProcessorErrorEncode = 6,
    CNDIconThemeImageProcessorErrorIconDoesNotFit = 7,
    // Kept as a readable alias for callers that use the shorter failure
    // classification in logs and telemetry.
    CNDIconThemeImageProcessorErrorIconFit =
        CNDIconThemeImageProcessorErrorIconDoesNotFit,
};

/// The maximum source/target dimension accepted by the bounded decoder.
FOUNDATION_EXPORT const NSUInteger CNDIconThemeImageProcessorMaximumDimension;

/// The maximum number of source or target pixels accepted by the processor.
FOUNDATION_EXPORT const NSUInteger CNDIconThemeImageProcessorMaximumPixels;

/// Processes one PNG and returns a property-list-safe structured result.
///
/// `capacity` is the exact byte capacity of the existing icon slot.  A
/// non-zero capacity causes the selected PNG to be zero-padded to exactly that
/// length.  Passing zero disables the size limit and returns the unpadded PNG
/// as both `unpaddedBytes` and `paddedBytes`.
FOUNDATION_EXPORT NSDictionary<NSString *, id> * _Nullable
CNDProcessIconThemePNG(NSData *pngData,
                       NSUInteger targetWidth,
                       NSUInteger targetHeight,
                       NSUInteger capacity,
                       NSError * _Nullable * _Nullable error);

/// Convenience spelling for clients that keep target dimensions together.
FOUNDATION_EXPORT NSDictionary<NSString *, id> * _Nullable
CNDProcessIconThemePNGWithTargetSize(NSData *pngData,
                                     CGSize targetSize,
                                     NSUInteger capacity,
                                     NSError * _Nullable * _Nullable error);

/// Processes several target slots from one source PNG.  The source is decoded
/// exactly once; each generated PNG is still decoded again by the existing
/// verifier before it is returned.  `targets` is an array of dictionaries,
/// each containing `width` and `height` (required) and `capacity` (optional,
/// defaulting to zero).  The returned array preserves input order and has one
/// property-list-safe result dictionary per target.
FOUNDATION_EXPORT NSArray<NSDictionary<NSString *, id> *> * _Nullable
CNDProcessIconThemePNGForTargets(NSData *pngData,
                                 NSArray<NSDictionary<NSString *, NSNumber *> *> *targets,
                                 NSError * _Nullable * _Nullable error);

/// Convenience form for callers with parallel target sizes and capacities.
/// `capacities` may be nil (all targets are unbounded) or must have the same
/// count as `targetSizes`.
FOUNDATION_EXPORT NSArray<NSDictionary<NSString *, id> *> * _Nullable
CNDProcessIconThemePNGWithTargetSizes(NSData *pngData,
                                      NSArray<NSValue *> *targetSizes,
                                      NSArray<NSNumber *> * _Nullable capacities,
                                      NSError * _Nullable * _Nullable error);

/// Objective-C façade for code that prefers a namespaced class method.
@interface CNDIconThemeImageProcessor : NSObject

+ (nullable NSDictionary<NSString *, id> *)processPNGData:(NSData *)pngData
                                             targetWidth:(NSUInteger)targetWidth
                                            targetHeight:(NSUInteger)targetHeight
                                               capacity:(NSUInteger)capacity
                                                   error:(NSError * _Nullable * _Nullable)error;

+ (nullable NSDictionary<NSString *, id> *)processPNGData:(NSData *)pngData
                                               targetSize:(CGSize)targetSize
                                                capacity:(NSUInteger)capacity
                                                   error:(NSError * _Nullable * _Nullable)error;

// Alias used by importer code that calls the input an image rather than a
// PNG.  It has exactly the same validation and result semantics.
+ (nullable NSDictionary<NSString *, id> *)processImageData:(NSData *)imageData
                                                targetWidth:(NSUInteger)targetWidth
                                               targetHeight:(NSUInteger)targetHeight
                                                  capacity:(NSUInteger)capacity
                                                      error:(NSError * _Nullable * _Nullable)error;

+ (nullable NSArray<NSDictionary<NSString *, id> *> *)processPNGData:(NSData *)pngData
                                                            targets:(NSArray<NSDictionary<NSString *, NSNumber *> *> *)targets
                                                               error:(NSError * _Nullable * _Nullable)error;

+ (nullable NSArray<NSDictionary<NSString *, id> *> *)processPNGData:(NSData *)pngData
                                                        targetSizes:(NSArray<NSValue *> *)targetSizes
                                                          capacities:(NSArray<NSNumber *> * _Nullable)capacities
                                                               error:(NSError * _Nullable * _Nullable)error;

@end

NS_ASSUME_NONNULL_END
