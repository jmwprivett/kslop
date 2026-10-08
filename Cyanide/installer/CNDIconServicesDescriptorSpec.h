//
//  CNDIconServicesDescriptorSpec.h
//  Cyanide
//
//  Immutable, Foundation-only values describing an IconServices request.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Explicit opt-in additions to the observed iPhone iOS 26 descriptor set.
/// The snippet sizes are useful for SearchUI/SnippetUI, but are not part of
/// the core set and are never returned unless this option is requested.
typedef NS_OPTIONS(NSUInteger, CNDIconServicesDescriptorProfileExtras) {
    CNDIconServicesDescriptorProfileExtrasNone = 0,
    CNDIconServicesDescriptorProfileExtrasSnippet = 1u << 0,
};

/// The six fields that form an IconServices descriptor identity.  All values
/// are integer-valued because the observed descriptors use whole point sizes
/// and scale factors; this also makes the canonical key independent of locale
/// and floating-point formatting.
@interface CNDIconServicesDescriptorSpec : NSObject <NSCopying, NSSecureCoding>

@property (nonatomic, readonly) NSUInteger pointWidth;
@property (nonatomic, readonly) NSUInteger pointHeight;
@property (nonatomic, readonly) NSUInteger scale;
@property (nonatomic, readonly) NSUInteger appearance;
/// Persisted compatibility name for `ISImageDescriptor.variantOptions`, the
/// value rendered as `v:%lx` in Apple's descriptor description. It is not the
/// first (preset-enum) argument of imageDescriptorWithIconVariant:options:.
@property (nonatomic, readonly) NSUInteger iconVariant;
/// The second signed-int argument to Apple's descriptor factory.
@property (nonatomic, readonly) NSUInteger options;

/// Pixel canvas observed for the corresponding stock iPhone/iOS 26 response.
/// This is deliberately not part of the descriptor/store identity: some
/// consumers request a 13-point descriptor but receive a padded 60-pixel
/// image, the 27/28-point requests receive an 87-pixel image, and the
/// App Library's 48-point list request receives a 180-pixel image.
@property (nonatomic, readonly) NSUInteger targetPixelWidth;
@property (nonatomic, readonly) NSUInteger targetPixelHeight;

/// A stable, locale-independent identity suitable for dictionary and journal
/// keys.  It includes every descriptor field, including zero values.
@property (nonatomic, readonly, copy) NSString *canonicalIdentity;

/// The six descriptor fields plus `canonicalIdentity`, represented using
/// immutable property-list values.
@property (nonatomic, readonly, copy) NSDictionary<NSString *, id> *dictionaryRepresentation;

- (nullable instancetype)initWithPointWidth:(NSUInteger)pointWidth
                                pointHeight:(NSUInteger)pointHeight
                                      scale:(NSUInteger)scale
                                  appearance:(NSUInteger)appearance
                                  iconVariant:(NSUInteger)iconVariant
                                     options:(NSUInteger)options NS_DESIGNATED_INITIALIZER;

+ (nullable instancetype)specWithPointWidth:(NSUInteger)pointWidth
                                  pointHeight:(NSUInteger)pointHeight
                                        scale:(NSUInteger)scale
                                    appearance:(NSUInteger)appearance
                                    iconVariant:(NSUInteger)iconVariant
                                       options:(NSUInteger)options;

/// Reconstructs a spec from `dictionaryRepresentation` or an equivalent
/// dictionary.  Unknown keys are ignored so callers can persist metadata
/// alongside a descriptor without making the value non-round-trippable.
- (nullable instancetype)initWithDictionary:(NSDictionary<NSString *, id> *)dictionary
                                       error:(NSError * _Nullable * _Nullable)error;
+ (nullable instancetype)specWithDictionary:(NSDictionary<NSString *, id> *)dictionary
                                       error:(NSError * _Nullable * _Nullable)error;

@end

/// A validated, sorted, deduplicated descriptor collection.  Profiles are
/// immutable after initialization and can safely be retained by a batch
/// publisher for the duration of an apply or restore operation.
@interface CNDIconServicesDescriptorProfile : NSObject <NSCopying, NSSecureCoding>

@property (nonatomic, readonly, copy) NSArray<CNDIconServicesDescriptorSpec *> *specifications;
/// Alias retained for callers that use the shorter term in their model.
@property (nonatomic, readonly, copy) NSArray<CNDIconServicesDescriptorSpec *> *specs;
@property (nonatomic, readonly, copy) NSString *canonicalIdentity;
@property (nonatomic, readonly, copy) NSDictionary<NSString *, id> *dictionaryRepresentation;

- (instancetype)initWithSpecifications:(NSArray<CNDIconServicesDescriptorSpec *> *)specifications NS_DESIGNATED_INITIALIZER;
+ (instancetype)profileWithSpecifications:(NSArray<CNDIconServicesDescriptorSpec *> *)specifications;

/// The exact twelve-record core set observed on an iPhone-class iOS 26 3x
/// display: 13a0, 27a0, 27a1, ordinary 28a0, Share-list 28a0/v0x4, 38a0,
/// 38a1, 48a0, 64a0, normal 68a0, transition 68a0/v0x20000 and 68a1. All
/// other values (including 20 and 40 points) are intentionally absent.
+ (NSArray<CNDIconServicesDescriptorSpec *> *)coreIPhoneIOS26SpecsAt3x;

/// Returns the core set with explicitly requested conditional records.  The
/// only currently supported extra is `CNDIconServicesDescriptorProfileExtrasSnippet`,
/// which adds 20a0.  Passing `None` is equivalent to the core set.
+ (NSArray<CNDIconServicesDescriptorSpec *> *)specsForIPhoneIOS26At3xWithConditionalExtras:(CNDIconServicesDescriptorProfileExtras)extras;
+ (NSArray<CNDIconServicesDescriptorSpec *> *)specsForIPhoneIOS26At3xIncludingSnippetExtras:(BOOL)includeSnippetExtras;
+ (instancetype)iPhoneIOS26ProfileAt3xWithConditionalExtras:(CNDIconServicesDescriptorProfileExtras)extras;
+ (instancetype)iPhoneIOS26ProfileAt3xIncludingSnippetExtras:(BOOL)includeSnippetExtras;

@end

NS_ASSUME_NONNULL_END
