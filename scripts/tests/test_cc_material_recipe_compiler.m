#import <Foundation/Foundation.h>
#import "../../Cyanide/tweaks/CNDCCMaterialRecipeCompiler.h"
#include <math.h>
#include <string.h>

static void Check(BOOL condition, NSString *message)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message.UTF8String); exit(1); }
}

static NSData *Binary(id object)
{
    NSError *error = nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:object
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
    Check(data != nil, [NSString stringWithFormat:@"fixture serializes: %@", error]);
    return data;
}

// Synthetic iOS 26-shaped fixture, constructed from public plist primitives.
// No Apple resource file is copied into the repository.
static NSDictionary *Stock(void)
{
    return @{@"baseMaterial": @{@"materialFiltering": @{
        @"blurRadius": @25, @"luminanceAmount": @0.4,
        @"luminanceValues": @[@0.38, @0, @1, @0.76], @"saturation": @1.6, @"zoom": @0.04}},
        @"materialSettingsVersion": @2,
        @"styles": @{@"fill": @"moduleFill", @"stroke": @"moduleStroke"}};
}

static uint64_t Read64(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (NSUInteger i = 0; i < 8; i++) value = (value << 8) | bytes[i];
    return value;
}

static NSData *FixtureLength(NSData *binary, NSUInteger length)
{
    Check(binary.length <= length, @"fixture fits requested byte length");
    const uint8_t *bytes = binary.bytes;
    uint64_t offset = Read64(bytes + binary.length - 8);
    NSMutableData *fixture = [NSMutableData dataWithLength:length];
    uint8_t *destination = fixture.mutableBytes;
    NSUInteger padding = length - binary.length;
    memcpy(destination, bytes, (NSUInteger)offset);
    memcpy(destination + offset + padding, bytes + offset, binary.length - (NSUInteger)offset);
    uint64_t relocated = offset + padding;
    for (NSUInteger i = 0; i < 8; i++) { destination[length - 1 - i] = (uint8_t)relocated; relocated >>= 8; }
    Check([NSPropertyListSerialization propertyListWithData:fixture options:0 format:NULL error:NULL] != nil,
        @"padded stock fixture reparses independently");
    return fixture;
}

static NSDictionary *Parsed(NSData *data)
{
    NSPropertyListFormat format = 0;
    id value = [NSPropertyListSerialization propertyListWithData:data options:0 format:&format error:NULL];
    Check([value isKindOfClass:NSDictionary.class] && format == NSPropertyListBinaryFormat_v1_0,
        @"output is a valid binary plist dictionary");
    return value;
}

static void Readback(CNDCCMaterialRecipeCompilation *result, CNDCCMaterialRecipeParameters p)
{
    NSDictionary *recipe = Parsed(result.data);
    NSDictionary *base = recipe[@"baseMaterial"];
    NSDictionary *tint = base[@"tinting"];
    NSDictionary *color = tint[@"tintColor"];
    Check([color[@"red"] doubleValue] == p.red && [color[@"green"] doubleValue] == p.green &&
        [color[@"blue"] doubleValue] == p.blue, @"RGB readback");
    Check([color[@"alpha"] doubleValue] == 1.0 && [tint[@"tintAlpha"] doubleValue] == p.opacity,
        @"opaque RGB color and independent requested opacity read back");
    Check([base[@"materialFiltering"][@"blurRadius"] doubleValue] == p.blurRadius, @"blur readback");
    Check([recipe[@"materialSettingsVersion"] isEqual:@2], @"native version retained");
    Check(base[@"materialFiltering"][@"tinting"] == nil, @"tinting uses native sibling path");
}

static void Failure(NSData *source, CNDCCMaterialRecipeParameters p,
                    CNDCCMaterialRecipeSizingPolicy policy, CNDCCMaterialRecipeCompilerError code)
{
    NSError *error = nil;
    Check(CNDCCCompileBackgroundMaterialRecipe(source, p, policy, &error) == nil, @"invalid input fails closed");
    Check([error.domain isEqual:CNDCCMaterialRecipeCompilerErrorDomain] && error.code == code &&
        error.localizedDescription.length > 0, [NSString stringWithFormat:@"useful expected error: %@", error]);
    Check(CNDCCCompileBackgroundMaterialRecipe(source, p, policy, NULL) == nil, @"nullable error sink");
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        CNDCCMaterialRecipeParameters p = {0.125, 0.5, 0.875, 0.625, 47.5};
        NSData *source = FixtureLength(Binary(Stock()), 343);
        NSData *original = [source copy];
        NSError *error = nil;
        CNDCCMaterialRecipeCompilation *compact = CNDCCCompileBackgroundMaterialRecipe(source, p,
            CNDCCMaterialRecipeSizingPolicyAllowCompactBackground, &error);
        Check(compact != nil && error == nil, [NSString stringWithFormat:@"343-byte native-shaped compile: %@", error]);
        Check(compact.compacted && compact.data.length == 343 && compact.unpaddedLength < 343,
            @"compact output exactly matches 343-byte stock");
        Check([compact.removedKeyPaths isEqual:@[@"baseMaterial.materialFiltering.luminanceAmount",
            @"baseMaterial.materialFiltering.luminanceValues", @"baseMaterial.materialFiltering.saturation",
            @"baseMaterial.materialFiltering.zoom", @"styles.fill", @"styles.stroke"]], @"explicit compact omission report");
        Readback(compact, p);
        Check([source isEqual:original] && [Parsed(source) isEqual:Stock()], @"stock NSData and metadata are unmodified");
        Check(Parsed(compact.data)[@"styles"] == nil, @"compact mode omits only approved styles");
        NSData *exactSource = Binary(Parsed(compact.data));
        CNDCCMaterialRecipeCompilation *exact = CNDCCCompileBackgroundMaterialRecipe(exactSource, p,
            CNDCCMaterialRecipeSizingPolicyPreserveStock, &error);
        Check(exact != nil && !exact.compacted && exact.unpaddedLength == exact.data.length &&
            [exact.data isEqual:exactSource], @"already exact binary output requires no padding or widening");
        for (NSUInteger i = 0; i < 20; i++) {
            NSData *fresh = FixtureLength(Binary(Stock()), 343);
            CNDCCMaterialRecipeCompilation *repeat = CNDCCCompileBackgroundMaterialRecipe(fresh, p,
                CNDCCMaterialRecipeSizingPolicyAllowCompactBackground, NULL);
            Check([repeat.data isEqual:compact.data], @"byte deterministic repeated fresh dictionaries");
        }
        Failure(source, p, CNDCCMaterialRecipeSizingPolicyPreserveStock, CNDCCMaterialRecipeCompilerErrorCannotFit);

        NSMutableDictionary *withMetadata = [Stock() mutableCopy];
        withMetadata[@"nativeMetadata"] = @{@"name": @"synthetic-background", @"enabled": @YES};
        NSMutableDictionary *base = [withMetadata[@"baseMaterial"] mutableCopy];
        base[@"tinting"] = @{@"tintAlpha": @0.2, @"tintColor": @{@"red": @0.1, @"colorSpace": @"native-space"},
            @"nativeTintMetadata": @"retain"};
        withMetadata[@"baseMaterial"] = base;
        NSData *roomyXML = [NSPropertyListSerialization dataWithPropertyList:withMetadata
            format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
        NSMutableData *roomy = [roomyXML mutableCopy];
        NSData *roomyBefore = [roomy copy];
        error = [NSError errorWithDomain:@"stale" code:1 userInfo:nil];
        CNDCCMaterialRecipeCompilation *preserved = CNDCCCompileBackgroundMaterialRecipe(roomy, p,
            CNDCCMaterialRecipeSizingPolicyPreserveStock, &error);
        Check(preserved != nil && error == nil && !preserved.compacted && preserved.removedKeyPaths.count == 0,
            @"strict mode retains metadata and clears stale errors");
        NSDictionary *preservedRecipe = Parsed(preserved.data);
        Check([preservedRecipe[@"styles"] isEqual:Stock()[@"styles"]] &&
            [preservedRecipe[@"nativeMetadata"] isEqual:withMetadata[@"nativeMetadata"]] &&
            [preservedRecipe[@"baseMaterial"][@"tinting"][@"tintColor"][@"colorSpace"] isEqual:@"native-space"] &&
            [preservedRecipe[@"baseMaterial"][@"tinting"][@"nativeTintMetadata"] isEqual:@"retain"] &&
            [preservedRecipe[@"baseMaterial"][@"materialFiltering"][@"luminanceValues"] isEqual:
                Stock()[@"baseMaterial"][@"materialFiltering"][@"luminanceValues"]], @"native references and unknown metadata preserved");
        Check([roomy isEqual:roomyBefore] && preserved.data.length == roomy.length, @"mutable source unmodified");
        Readback(preserved, p);
        CNDCCMaterialRecipeCompilation *allowButRoomy = CNDCCCompileBackgroundMaterialRecipe(roomy, p,
            CNDCCMaterialRecipeSizingPolicyAllowCompactBackground, NULL);
        Check(!allowButRoomy.compacted && [allowButRoomy.data isEqual:preserved.data], @"no unnecessary compaction");

        for (NSUInteger i = 0; i < 5; i++) {
            CNDCCMaterialRecipeParameters bad = p;
            double *fields[] = {&bad.red, &bad.green, &bad.blue, &bad.opacity, &bad.blurRadius};
            *fields[i] = NAN;
            Failure(source, bad, 0, CNDCCMaterialRecipeCompilerErrorInvalidInput);
            *fields[i] = INFINITY;
            Failure(source, bad, 0, CNDCCMaterialRecipeCompilerErrorInvalidInput);
            *fields[i] = -0.01;
            Failure(source, bad, 0, CNDCCMaterialRecipeCompilerErrorInvalidInput);
            *fields[i] = i == 4 ? 200.01 : 1.01;
            Failure(source, bad, 0, CNDCCMaterialRecipeCompilerErrorInvalidInput);
        }
        for (NSUInteger i = 0; i < 2; i++) {
            CNDCCMaterialRecipeParameters edge = {i, i, i, i, i * 200};
            CNDCCMaterialRecipeCompilation *result = CNDCCCompileBackgroundMaterialRecipe(source, edge, 1, &error);
            Check(result != nil, @"inclusive zero and maximum parameter bounds");
            Readback(result, edge);
        }
        Failure([NSData data], p, 0, CNDCCMaterialRecipeCompilerErrorInvalidInput);
        Failure(source, p, 99, CNDCCMaterialRecipeCompilerErrorInvalidInput);
        Failure([@"invalid" dataUsingEncoding:NSUTF8StringEncoding], p, 0, CNDCCMaterialRecipeCompilerErrorInvalidSchema);
        Failure([source subdataWithRange:NSMakeRange(0, source.length - 10)], p, 0,
            CNDCCMaterialRecipeCompilerErrorInvalidSchema);
        NSMutableData *badTrailer = [source mutableCopy];
        memset((uint8_t *)badTrailer.mutableBytes + badTrailer.length - 8, 0xff, 8);
        Failure(badTrailer, p, 0, CNDCCMaterialRecipeCompilerErrorInvalidSchema);
        for (id invalid in @[@[], @{}, @{@"materialSettingsVersion": @3, @"baseMaterial": Stock()[@"baseMaterial"]},
            @{@"materialSettingsVersion": @YES, @"baseMaterial": Stock()[@"baseMaterial"]},
            @{@"materialSettingsVersion": @2, @"baseMaterial": @"wrong"},
            @{@"materialSettingsVersion": @2, @"baseMaterial": @{@"materialFiltering": @{}}},
            @{@"materialSettingsVersion": @2, @"baseMaterial": @{@"materialFiltering": @{@"blurRadius": @"25"}}},
            @{@"materialSettingsVersion": @2, @"baseMaterial": @{@"materialFiltering": @{@"blurRadius": @YES}}},
            @{@"materialSettingsVersion": @2, @"baseMaterial": @{@"materialFiltering": @{@"blurRadius": @25}, @"tinting": @"bad"}},
            @{@"materialSettingsVersion": @2, @"baseMaterial": @{@"materialFiltering": @{@"blurRadius": @25},
                @"tinting": @{@"tintColor": @{@"white": @0.5}}}}]) {
            Failure(Binary(invalid), p, 1, CNDCCMaterialRecipeCompilerErrorInvalidSchema);
        }
        NSMutableDictionary *unknown = [Stock() mutableCopy];
        unknown[@"styles"] = @{@"fill": @"anotherFill", @"stroke": @"moduleStroke"};
        Failure(Binary(unknown), p, 1, CNDCCMaterialRecipeCompilerErrorCannotFit);
        unknown[@"styles"] = Stock()[@"styles"];
        NSMutableDictionary *unknownBase = [Stock()[@"baseMaterial"] mutableCopy];
        NSMutableDictionary *unknownFilter = [unknownBase[@"materialFiltering"] mutableCopy];
        unknownFilter[@"futureFilter"] = @YES;
        unknownBase[@"materialFiltering"] = unknownFilter;
        unknown[@"baseMaterial"] = unknownBase;
        Failure(Binary(unknown), p, 1, CNDCCMaterialRecipeCompilerErrorCannotFit);
        NSData *tiny = Binary(@{@"materialSettingsVersion": @2,
            @"baseMaterial": @{@"materialFiltering": @{@"blurRadius": @25}}});
        Failure(tiny, p, 0, CNDCCMaterialRecipeCompilerErrorCannotFit);
        Failure(tiny, p, 1, CNDCCMaterialRecipeCompilerErrorCannotFit);
        if (argc == 2) {
            NSData *actualStock = [NSData dataWithContentsOfFile:@(argv[1])];
            CNDCCMaterialRecipeCompilation *actual = CNDCCCompileBackgroundMaterialRecipe(actualStock, p, 1, &error);
            Check(actual != nil && actual.data.length == actualStock.length, @"optional local native fixture audit");
            Readback(actual, p);
        }
        printf("PASS: native-shaped fixture, preservation, compact report, bounds, malformed input, sizing, source immutability\n");
        printf("DETERMINISM:%s\n", [compact.data base64EncodedStringWithOptions:0].UTF8String);
    }
    return 0;
}
