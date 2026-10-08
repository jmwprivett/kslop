//
//  CNDIconServicesDescriptorSpec.m
//  Cyanide
//

#import "CNDIconServicesDescriptorSpec.h"
#import <limits.h>
#import <math.h>

static NSString * const kCNDDescriptorErrorDomain = @"CNDIconServicesDescriptorSpecErrorDomain";

/* ISImageDescriptor prints variantOptions with v:%lx. The measured
 * launch/return description v:20000 therefore identifies 0x20000, not
 * decimal 20000.  `iconVariant` remains the persisted compatibility name for
 * this observed property; it is not the factory preset enum. */
static const NSUInteger CNDIconServicesTransitionVariantOptions = 0x20000u;
/* SharingUI sets -drawBorder:YES on the TableUIName descriptor used by the
 * Share sheet's Apps list. The iOS 26 readback is variantOptions=0x4 and its
 * descriptor digest is 32AFEB06-1183-3764-B197-7B175B199D11. */
static const NSUInteger CNDIconServicesShareSheetBorderVariantOptions = 0x4u;

typedef NS_ENUM(NSInteger, CNDDescriptorErrorCode) {
    CNDDescriptorErrorInvalidArgument = 1,
    CNDDescriptorErrorInvalidDictionary = 2,
};

static NSError *CNDDescriptorError(CNDDescriptorErrorCode code, NSString *message)
{
    return [NSError errorWithDomain:kCNDDescriptorErrorDomain
                               code:code
                           userInfo:@{ NSLocalizedDescriptionKey : message ?: @"Invalid IconServices descriptor." }];
}

static NSNumber *CNDUnsignedField(NSDictionary *dictionary, NSString *key)
{
    id value = dictionary[key];
    if (![value isKindOfClass:NSNumber.class]) return nil;
    NSNumber *number = value;
    if (number.doubleValue < 0.0 || number.doubleValue > (double)NSUIntegerMax) return nil;
    // Reject fractional values even though unsignedIntegerValue truncates.
    if (floor(number.doubleValue) != number.doubleValue) return nil;
    return @(number.unsignedIntegerValue);
}

static NSUInteger CNDObservedPixelDimension(NSUInteger points,
                                             NSUInteger scale)
{
    if (scale == 3u) {
        if (points == 13u || points == 20u) return 60u;
        if (points == 27u || points == 28u) return 87u;
        if (points == 48u) return 180u;
    }
    if (points > NSUIntegerMax / scale) return 0;
    return points * scale;
}

@implementation CNDIconServicesDescriptorSpec

+ (BOOL)supportsSecureCoding { return YES; }

- (instancetype)init {
    return [self initWithPointWidth:0 pointHeight:0 scale:0
                          appearance:0 iconVariant:0 options:0];
}

- (nullable instancetype)initWithPointWidth:(NSUInteger)pointWidth
                                pointHeight:(NSUInteger)pointHeight
                                      scale:(NSUInteger)scale
                                  appearance:(NSUInteger)appearance
                                  iconVariant:(NSUInteger)iconVariant
                                     options:(NSUInteger)options
{
    /* Bound persisted identity values to the transport's admitted range.
     * `iconVariant` represents ISImageDescriptor.variantOptions; `options`
     * remains the signed 32-bit factory options argument. */
    if (pointWidth == 0u || pointHeight == 0u || scale == 0u ||
        iconVariant > INT_MAX || options > INT_MAX) return nil;
    self = [super init];
    if (!self) return nil;
    _pointWidth = pointWidth;
    _pointHeight = pointHeight;
    _scale = scale;
    _appearance = appearance;
    _iconVariant = iconVariant;
    _options = options;
    _targetPixelWidth = CNDObservedPixelDimension(pointWidth, scale);
    _targetPixelHeight = CNDObservedPixelDimension(pointHeight, scale);
    if (_targetPixelWidth == 0u || _targetPixelHeight == 0u) return nil;
    _canonicalIdentity = [[NSString alloc] initWithFormat:@"%lux%lu@%lu:a%lu:v%lu:o%lu",
        (unsigned long)pointWidth, (unsigned long)pointHeight, (unsigned long)scale,
        (unsigned long)appearance, (unsigned long)iconVariant, (unsigned long)options];
    _dictionaryRepresentation = @{
        @"pointWidth": @(pointWidth),
        @"pointHeight": @(pointHeight),
        @"scale": @(scale),
        @"appearance": @(appearance),
        @"iconVariant": @(iconVariant),
        @"options": @(options),
        @"canonicalIdentity": _canonicalIdentity,
    };
    return self;
}

+ (nullable instancetype)specWithPointWidth:(NSUInteger)pointWidth
                                  pointHeight:(NSUInteger)pointHeight
                                        scale:(NSUInteger)scale
                                    appearance:(NSUInteger)appearance
                                    iconVariant:(NSUInteger)iconVariant
                                       options:(NSUInteger)options
{
    return [[self alloc] initWithPointWidth:pointWidth pointHeight:pointHeight
                                      scale:scale appearance:appearance
                                  iconVariant:iconVariant options:options];
}

- (nullable instancetype)initWithDictionary:(NSDictionary<NSString *,id> *)dictionary
                                       error:(NSError **)error
{
    if (error) *error = nil;
    if (![dictionary isKindOfClass:NSDictionary.class]) {
        if (error) *error = CNDDescriptorError(CNDDescriptorErrorInvalidDictionary,
                                               @"Descriptor dictionary is not an NSDictionary.");
        return nil;
    }
    NSArray<NSString *> *keys = @[ @"pointWidth", @"pointHeight", @"scale",
                                   @"appearance", @"iconVariant", @"options" ];
    NSMutableArray<NSNumber *> *values = [NSMutableArray arrayWithCapacity:keys.count];
    for (NSString *key in keys) {
        NSNumber *number = CNDUnsignedField(dictionary, key);
        if (number == nil) {
            if (error) *error = CNDDescriptorError(CNDDescriptorErrorInvalidDictionary,
                                                   [NSString stringWithFormat:@"Descriptor field %@ is missing or invalid.", key]);
            return nil;
        }
        [values addObject:number];
    }
    self = [self initWithPointWidth:values[0].unsignedIntegerValue
                         pointHeight:values[1].unsignedIntegerValue
                               scale:values[2].unsignedIntegerValue
                           appearance:values[3].unsignedIntegerValue
                           iconVariant:values[4].unsignedIntegerValue
                              options:values[5].unsignedIntegerValue];
    if (!self && error) *error = CNDDescriptorError(CNDDescriptorErrorInvalidDictionary,
                                                     @"Descriptor dimensions and scale must be nonzero.");
    return self;
}

+ (nullable instancetype)specWithDictionary:(NSDictionary<NSString *,id> *)dictionary
                                       error:(NSError **)error
{
    return [[self alloc] initWithDictionary:dictionary error:error];
}

- (id)copyWithZone:(NSZone *)zone { return self; }

- (void)encodeWithCoder:(NSCoder *)coder
{
    [coder encodeInteger:(NSInteger)self.pointWidth forKey:@"pointWidth"];
    [coder encodeInteger:(NSInteger)self.pointHeight forKey:@"pointHeight"];
    [coder encodeInteger:(NSInteger)self.scale forKey:@"scale"];
    [coder encodeInteger:(NSInteger)self.appearance forKey:@"appearance"];
    [coder encodeInteger:(NSInteger)self.iconVariant forKey:@"iconVariant"];
    [coder encodeInteger:(NSInteger)self.options forKey:@"options"];
}

- (nullable instancetype)initWithCoder:(NSCoder *)coder
{
    NSInteger pointWidth = [coder decodeIntegerForKey:@"pointWidth"];
    NSInteger pointHeight = [coder decodeIntegerForKey:@"pointHeight"];
    NSInteger scale = [coder decodeIntegerForKey:@"scale"];
    NSInteger appearance = [coder decodeIntegerForKey:@"appearance"];
    NSInteger iconVariant = [coder decodeIntegerForKey:@"iconVariant"];
    NSInteger options = [coder decodeIntegerForKey:@"options"];
    if (pointWidth <= 0 || pointHeight <= 0 || scale <= 0 ||
        appearance < 0 || iconVariant < 0 || options < 0) return nil;
    return [self initWithPointWidth:(NSUInteger)pointWidth
                        pointHeight:(NSUInteger)pointHeight
                              scale:(NSUInteger)scale
                          appearance:(NSUInteger)appearance
                          iconVariant:(NSUInteger)iconVariant
                             options:(NSUInteger)options];
}

- (NSUInteger)hash { return self.canonicalIdentity.hash; }

- (BOOL)isEqual:(id)object
{
    if (self == object) return YES;
    if (![object isKindOfClass:CNDIconServicesDescriptorSpec.class]) return NO;
    CNDIconServicesDescriptorSpec *other = object;
    return [self.canonicalIdentity isEqualToString:other.canonicalIdentity];
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"<%@: %@>", NSStringFromClass(self.class), self.canonicalIdentity];
}

@end

@implementation CNDIconServicesDescriptorProfile

+ (BOOL)supportsSecureCoding { return YES; }

- (instancetype)init { return [self initWithSpecifications:@[]]; }

- (instancetype)initWithSpecifications:(NSArray<CNDIconServicesDescriptorSpec *> *)specifications
{
    NSMutableDictionary<NSString *, CNDIconServicesDescriptorSpec *> *deduplicated = [NSMutableDictionary dictionary];
    for (id candidate in specifications ?: @[]) {
        if (![candidate isKindOfClass:CNDIconServicesDescriptorSpec.class]) continue;
        CNDIconServicesDescriptorSpec *spec = candidate;
        deduplicated[spec.canonicalIdentity] = spec;
    }
    NSArray *sorted = [[deduplicated allValues] sortedArrayUsingComparator:^NSComparisonResult(CNDIconServicesDescriptorSpec *a, CNDIconServicesDescriptorSpec *b) {
        return [a.canonicalIdentity compare:b.canonicalIdentity options:NSLiteralSearch];
    }];
    self = [super init];
    if (!self) return nil;
    _specifications = [sorted copy];
    _specs = _specifications;
    NSMutableArray *identities = [NSMutableArray arrayWithCapacity:sorted.count];
    for (CNDIconServicesDescriptorSpec *spec in sorted) [identities addObject:spec.canonicalIdentity];
    _canonicalIdentity = [identities componentsJoinedByString:@"|"];
    NSMutableArray *dictionarySpecs = [NSMutableArray arrayWithCapacity:sorted.count];
    for (CNDIconServicesDescriptorSpec *spec in sorted) {
        [dictionarySpecs addObject:spec.dictionaryRepresentation];
    }
    _dictionaryRepresentation = @{
        @"specifications": [dictionarySpecs copy],
        @"specs": [dictionarySpecs copy],
        @"canonicalIdentity": _canonicalIdentity,
    };
    return self;
}

+ (instancetype)profileWithSpecifications:(NSArray<CNDIconServicesDescriptorSpec *> *)specifications
{
    return [[self alloc] initWithSpecifications:specifications];
}

+ (NSArray<CNDIconServicesDescriptorSpec *> *)coreIPhoneIOS26SpecsAt3x
{
    static NSArray *core;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        /* This is the per-application core matrix. Spotlight's vertical Apps
         * results use 64pt/v0 for every application (SearchUI variant 4),
         * while its Top Hit results use the ordinary 68pt records (variant
         * 5). SharingUI's Apps list uses a separate 28pt descriptor with the
         * measured draw-border/variantOptions 0x4 bit. The ordinary 28pt/v0
         * and 68pt/v0x20000 records are launch/return consumers for every
         * app. None are special cases for dynamic Clock/Calendar icons. */
        NSArray *fields = @[
            @[@13, @13, @3, @0, @0, @0],
            @[@27, @27, @3, @0, @0, @0],
            @[@27, @27, @3, @1, @0, @0],
            @[@28, @28, @3, @0, @0, @0],
            @[@28, @28, @3, @0,
              @(CNDIconServicesShareSheetBorderVariantOptions), @0],
            @[@38, @38, @3, @0, @0, @0],
            @[@38, @38, @3, @1, @0, @0],
            @[@48, @48, @3, @0, @0, @0],
            @[@64, @64, @3, @0, @0, @0],
            @[@68, @68, @3, @0, @0, @0],
            @[@68, @68, @3, @0,
              @(CNDIconServicesTransitionVariantOptions), @0],
            @[@68, @68, @3, @1, @0, @0],
        ];
        NSMutableArray *result = [NSMutableArray arrayWithCapacity:fields.count];
        for (NSArray *entry in fields) {
            [result addObject:[[CNDIconServicesDescriptorSpec alloc]
                initWithPointWidth:[entry[0] unsignedIntegerValue]
                pointHeight:[entry[1] unsignedIntegerValue]
                scale:[entry[2] unsignedIntegerValue]
                appearance:[entry[3] unsignedIntegerValue]
                iconVariant:[entry[4] unsignedIntegerValue]
                options:[entry[5] unsignedIntegerValue]]];
        }
        core = [result copy];
    });
    return core;
}

+ (NSArray<CNDIconServicesDescriptorSpec *> *)specsForIPhoneIOS26At3xWithConditionalExtras:(CNDIconServicesDescriptorProfileExtras)extras
{
    NSMutableArray *result = [[self coreIPhoneIOS26SpecsAt3x] mutableCopy];
    if ((extras & CNDIconServicesDescriptorProfileExtrasSnippet) != 0u) {
        [result addObject:[[CNDIconServicesDescriptorSpec alloc] initWithPointWidth:20 pointHeight:20 scale:3 appearance:0 iconVariant:0 options:0]];
    }
    return [[[CNDIconServicesDescriptorProfile alloc] initWithSpecifications:result] specifications];
}

+ (NSArray<CNDIconServicesDescriptorSpec *> *)specsForIPhoneIOS26At3xIncludingSnippetExtras:(BOOL)includeSnippetExtras
{
    return [self specsForIPhoneIOS26At3xWithConditionalExtras:includeSnippetExtras ? CNDIconServicesDescriptorProfileExtrasSnippet : CNDIconServicesDescriptorProfileExtrasNone];
}

+ (instancetype)iPhoneIOS26ProfileAt3xWithConditionalExtras:(CNDIconServicesDescriptorProfileExtras)extras
{
    return [[self alloc] initWithSpecifications:[self specsForIPhoneIOS26At3xWithConditionalExtras:extras]];
}

+ (instancetype)iPhoneIOS26ProfileAt3xIncludingSnippetExtras:(BOOL)includeSnippetExtras
{
    return [self iPhoneIOS26ProfileAt3xWithConditionalExtras:includeSnippetExtras ? CNDIconServicesDescriptorProfileExtrasSnippet : CNDIconServicesDescriptorProfileExtrasNone];
}

- (id)copyWithZone:(NSZone *)zone { return self; }

- (void)encodeWithCoder:(NSCoder *)coder { [coder encodeObject:self.specifications forKey:@"specifications"]; }

- (instancetype)initWithCoder:(NSCoder *)coder
{
    NSSet *classes = [NSSet setWithObjects:NSArray.class, CNDIconServicesDescriptorSpec.class, nil];
    NSArray *specs = [coder decodeObjectOfClasses:classes forKey:@"specifications"];
    return [self initWithSpecifications:specs ?: @[]];
}

- (NSUInteger)hash { return self.canonicalIdentity.hash; }
- (BOOL)isEqual:(id)object
{
    return [object isKindOfClass:CNDIconServicesDescriptorProfile.class] &&
        [self.canonicalIdentity isEqualToString:[object canonicalIdentity]];
}

@end
