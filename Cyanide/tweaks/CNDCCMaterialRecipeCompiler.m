#import "CNDCCMaterialRecipeCompiler.h"
#include <math.h>
#include <stdint.h>
#include <string.h>

NSErrorDomain const CNDCCMaterialRecipeCompilerErrorDomain = @"CNDCCMaterialRecipeCompiler";

@interface CNDCCMaterialRecipeCompilation ()
@property (nonatomic, readwrite, copy) NSData *data;
@property (nonatomic, readwrite) BOOL compacted;
@property (nonatomic, readwrite, copy) NSArray<NSString *> *removedKeyPaths;
@property (nonatomic, readwrite) NSUInteger unpaddedLength;
@end

@implementation CNDCCMaterialRecipeCompilation
@end

static void CNDRecipeError(NSError **error, CNDCCMaterialRecipeCompilerError code,
                           NSString *message, NSDictionary *details)
{
    if (!error) return;
    NSMutableDictionary *info = [details mutableCopy] ?: [NSMutableDictionary dictionary];
    info[NSLocalizedDescriptionKey] = message;
    *error = [NSError errorWithDomain:CNDCCMaterialRecipeCompilerErrorDomain code:code userInfo:info];
}

static BOOL CNDRecipeNumber(id value)
{
    return [value isKindOfClass:NSNumber.class] &&
        CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID() && isfinite([value doubleValue]);
}

static uint64_t CNDRecipeReadBE64(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (NSUInteger i = 0; i < 8; i++) value = (value << 8) | bytes[i];
    return value;
}

static void CNDRecipeWriteBE64(uint8_t *bytes, uint64_t value)
{
    for (NSUInteger i = 8; i > 0; i--) { bytes[i - 1] = (uint8_t)value; value >>= 8; }
}

/// Binary plist offsets point at objects preceding the offset table. Insert
/// inert zero bytes before that table, then relocate the trailer's table
/// pointer. Foundation also requires its offset width to accommodate the new
/// table position, so widen the offset entries when necessary. The trailer
/// remains the final 32 bytes; appending bytes is invalid.
static NSData *CNDRecipePad(NSData *binary, NSUInteger targetLength, NSError **error)
{
    if (binary.length > targetLength) return nil;
    const uint8_t *bytes = binary.bytes;
    if (binary.length < 40 || memcmp(bytes, "bplist00", 8) != 0) {
        CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorSerialization,
            @"The serializer did not produce a complete binary plist.", nil);
        return nil;
    }
    const uint8_t *trailer = bytes + binary.length - 32;
    uint8_t offsetSize = trailer[6];
    uint8_t referenceSize = trailer[7];
    uint64_t objectCount = CNDRecipeReadBE64(trailer + 8);
    uint64_t rootObject = CNDRecipeReadBE64(trailer + 16);
    uint64_t tableOffset = CNDRecipeReadBE64(trailer + 24);
    if (!(offsetSize == 1 || offsetSize == 2 || offsetSize == 4 || offsetSize == 8) ||
        !(referenceSize == 1 || referenceSize == 2 || referenceSize == 4 || referenceSize == 8) ||
        objectCount == 0 || rootObject >= objectCount || tableOffset < 8 ||
        tableOffset > binary.length - 32 ||
        objectCount > (binary.length - 32 - tableOffset) / offsetSize ||
        objectCount * offsetSize != binary.length - 32 - tableOffset) {
        CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorSerialization,
            @"The serializer produced an invalid binary-plist offset table.", nil);
        return nil;
    }
    uint8_t paddedOffsetSize = offsetSize;
    uint64_t paddedTableOffset = 0;
    for (;;) {
        if (objectCount > (targetLength - 32 - tableOffset) / paddedOffsetSize) {
            CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorCannotFit,
                @"The exact target size cannot accommodate the padded binary-plist offset table.",
                @{@"sourceLength": @(targetLength),
                  @"requiredLength": @(tableOffset + objectCount * paddedOffsetSize + 32)});
            return nil;
        }
        paddedTableOffset = targetLength - 32 - objectCount * paddedOffsetSize;
        if (paddedOffsetSize == 8 || paddedTableOffset < (1ULL << (paddedOffsetSize * 8))) break;
        paddedOffsetSize *= 2;
    }
    NSMutableData *padded = [NSMutableData dataWithLength:targetLength];
    uint8_t *destination = padded.mutableBytes;
    memcpy(destination, bytes, (NSUInteger)tableOffset);
    for (uint64_t i = 0; i < objectCount; i++) {
        uint64_t objectOffset = 0;
        for (NSUInteger j = 0; j < offsetSize; j++)
            objectOffset = (objectOffset << 8) | bytes[tableOffset + i * offsetSize + j];
        if (objectOffset < 8 || objectOffset >= tableOffset) {
            CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorSerialization,
                @"The serializer produced an out-of-range binary-plist object offset.", nil);
            return nil;
        }
        for (NSUInteger j = paddedOffsetSize; j > 0; j--) {
            destination[paddedTableOffset + i * paddedOffsetSize + j - 1] = (uint8_t)objectOffset;
            objectOffset >>= 8;
        }
    }
    memcpy(destination + targetLength - 32, trailer, 32);
    destination[targetLength - 26] = paddedOffsetSize;
    CNDRecipeWriteBE64(destination + targetLength - 8, paddedTableOffset);
    return [padded copy];
}

static NSData *CNDRecipeSerialize(NSDictionary *recipe, NSError **error)
{
    NSError *underlying = nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:recipe
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:&underlying];
    if (!data) CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorSerialization,
        @"The transformed material recipe could not be serialized.",
        underlying ? @{NSUnderlyingErrorKey: underlying} : nil);
    return data;
}

CNDCCMaterialRecipeCompilation *CNDCCCompileBackgroundMaterialRecipe(
    NSData *stockData, CNDCCMaterialRecipeParameters p,
    CNDCCMaterialRecipeSizingPolicy policy, NSError **error)
{
    if (error) *error = nil;
    if (![stockData isKindOfClass:NSData.class] || stockData.length == 0 ||
        !(policy == CNDCCMaterialRecipeSizingPolicyPreserveStock ||
          policy == CNDCCMaterialRecipeSizingPolicyAllowCompactBackground)) {
        CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorInvalidInput,
            @"Provide a nonempty stock recipe and a supported sizing policy.", nil);
        return nil;
    }
    const double components[] = {p.red, p.green, p.blue, p.opacity};
    for (NSUInteger i = 0; i < 4; i++) {
        if (!isfinite(components[i]) || components[i] < 0 || components[i] > 1) {
            CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorInvalidInput,
                @"Red, green, blue, and opacity must be finite values in 0...1.", nil);
            return nil;
        }
    }
    if (!isfinite(p.blurRadius) || p.blurRadius < 0 || p.blurRadius > 200) {
        CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorInvalidInput,
            @"Blur radius must be a finite value in 0...200 points.", nil);
        return nil;
    }
    NSError *underlying = nil;
    id parsed = [NSPropertyListSerialization propertyListWithData:stockData
        options:NSPropertyListImmutable format:NULL error:&underlying];
    if (![parsed isKindOfClass:NSDictionary.class]) {
        CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorInvalidSchema,
            @"The stock material recipe must be a property-list dictionary.",
            underlying ? @{NSUnderlyingErrorKey: underlying} : nil);
        return nil;
    }
    NSDictionary *stock = parsed;
    id version = stock[@"materialSettingsVersion"];
    id nativeBase = stock[@"baseMaterial"];
    id nativeFiltering = [nativeBase isKindOfClass:NSDictionary.class] ? nativeBase[@"materialFiltering"] : nil;
    if (!CNDRecipeNumber(version) || [version doubleValue] != 2 ||
        ![nativeFiltering isKindOfClass:NSDictionary.class] ||
        !CNDRecipeNumber(nativeFiltering[@"blurRadius"]) || [nativeFiltering[@"blurRadius"] doubleValue] < 0) {
        CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorInvalidSchema,
            @"Expected materialSettingsVersion 2 and baseMaterial.materialFiltering.blurRadius.", nil);
        return nil;
    }
    id nativeTinting = nativeBase[@"tinting"];
    id nativeColor = [nativeTinting isKindOfClass:NSDictionary.class] ? nativeTinting[@"tintColor"] : nil;
    if ((nativeTinting && ![nativeTinting isKindOfClass:NSDictionary.class]) ||
        (nativeColor && ![nativeColor isKindOfClass:NSDictionary.class]) || nativeFiltering[@"tinting"] ||
        ([nativeColor isKindOfClass:NSDictionary.class] && nativeColor[@"white"])) {
        CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorInvalidSchema,
            @"The stock recipe has an unsupported or conflicting tinting structure.", nil);
        return nil;
    }

    // Behavioral reference: Lemin/PureKFD SpringboardColorManager's background
    // recipe shape. Compile from current stock metadata; no upstream or Apple
    // recipe asset is bundled, and compacting is an explicit caller choice.
    NSMutableDictionary *recipe = [stock mutableCopy];
    NSMutableDictionary *base = [nativeBase mutableCopy];
    NSMutableDictionary *filtering = [nativeFiltering mutableCopy];
    NSMutableDictionary *tinting = nativeTinting ? [nativeTinting mutableCopy] : [NSMutableDictionary dictionary];
    NSMutableDictionary *color = nativeColor ? [nativeColor mutableCopy] : [NSMutableDictionary dictionary];
    color[@"red"] = @(p.red); color[@"green"] = @(p.green);
    color[@"blue"] = @(p.blue); color[@"alpha"] = @1.0;
    tinting[@"tintColor"] = color; tinting[@"tintAlpha"] = @(p.opacity);
    filtering[@"blurRadius"] = @(p.blurRadius);
    base[@"materialFiltering"] = filtering; base[@"tinting"] = tinting;
    recipe[@"baseMaterial"] = base;

    NSData *binary = CNDRecipeSerialize(recipe, error);
    if (!binary) return nil;
    NSMutableArray<NSString *> *removed = [NSMutableArray array];
    NSError *fitError = nil;
    NSData *padded = binary.length <= stockData.length ? CNDRecipePad(binary, stockData.length, &fitError) : nil;
    if (fitError && fitError.code != CNDCCMaterialRecipeCompilerErrorCannotFit) {
        if (error) *error = fitError;
        return nil;
    }
    if (!padded && policy == CNDCCMaterialRecipeSizingPolicyAllowCompactBackground) {
        NSDictionary *styles = stock[@"styles"];
        NSArray *allowedFilters = @[@"blurRadius", @"luminanceAmount", @"luminanceValues", @"saturation", @"zoom"];
        BOOL compatible = [styles isKindOfClass:NSDictionary.class] && styles.count == 2 &&
            [styles[@"fill"] isEqual:@"moduleFill"] && [styles[@"stroke"] isEqual:@"moduleStroke"];
        for (NSString *key in nativeFiltering) if (![allowedFilters containsObject:key]) compatible = NO;
        if (!compatible) {
            CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorCannotFit,
                @"The recipe is too large, and its native filters/style references do not permit compact background mode.",
                @{@"sourceLength": @(stockData.length), @"requiredLength": @(binary.length)});
            return nil;
        }
        for (NSString *key in @[@"luminanceAmount", @"luminanceValues", @"saturation", @"zoom"]) {
            if (filtering[key]) {
                [filtering removeObjectForKey:key];
                [removed addObject:[@"baseMaterial.materialFiltering." stringByAppendingString:key]];
            }
        }
        [recipe removeObjectForKey:@"styles"];
        [removed addObjectsFromArray:@[@"styles.fill", @"styles.stroke"]];
        binary = CNDRecipeSerialize(recipe, error);
        if (!binary) return nil;
        fitError = nil;
        padded = binary.length <= stockData.length ? CNDRecipePad(binary, stockData.length, &fitError) : nil;
    }
    if (!padded) {
        if (fitError) {
            if (error) *error = fitError;
        } else {
            CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorCannotFit,
                @"The transformed material recipe cannot fit the original byte length.",
                @{@"sourceLength": @(stockData.length), @"requiredLength": @(binary.length),
                  @"removedKeyPaths": removed});
        }
        return nil;
    }
    NSPropertyListFormat format = 0;
    NSDictionary *verified = [NSPropertyListSerialization propertyListWithData:padded
        options:NSPropertyListImmutable format:&format error:&underlying];
    NSDictionary *verifiedBase = verified[@"baseMaterial"];
    NSDictionary *verifiedTint = verifiedBase[@"tinting"];
    NSDictionary *verifiedColor = verifiedTint[@"tintColor"];
    if (format != NSPropertyListBinaryFormat_v1_0 || padded.length != stockData.length ||
        ![verified isEqual:recipe] || [verifiedColor[@"red"] doubleValue] != p.red ||
        [verifiedColor[@"green"] doubleValue] != p.green || [verifiedColor[@"blue"] doubleValue] != p.blue ||
        [verifiedColor[@"alpha"] doubleValue] != 1.0 || [verifiedTint[@"tintAlpha"] doubleValue] != p.opacity ||
        [verifiedBase[@"materialFiltering"][@"blurRadius"] doubleValue] != p.blurRadius) {
        CNDRecipeError(error, CNDCCMaterialRecipeCompilerErrorVerification,
            @"The serialized material recipe did not pass size, metadata, and parameter readback checks.",
            underlying ? @{NSUnderlyingErrorKey: underlying} : nil);
        return nil;
    }
    CNDCCMaterialRecipeCompilation *result = [CNDCCMaterialRecipeCompilation new];
    result.data = padded; result.compacted = removed.count > 0;
    result.removedKeyPaths = removed; result.unpaddedLength = binary.length;
    return result;
}
