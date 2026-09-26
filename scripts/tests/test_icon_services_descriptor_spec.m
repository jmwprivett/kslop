// Host-side checks for the immutable iOS 26 descriptor profile.
// Build with:
//   xcrun --sdk macosx clang -fobjc-arc -I Cyanide/installer \
//     scripts/tests/test_icon_services_descriptor_spec.m \
//     Cyanide/installer/CNDIconServicesDescriptorSpec.m \
//     -framework Foundation -o build/icon-services-descriptor-spec-test

#import <Foundation/Foundation.h>
#import <limits.h>
#import "CNDIconServicesDescriptorSpec.h"

static void Require(BOOL condition, NSString *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message.UTF8String);
        exit(1);
    }
}

int main(void)
{
    @autoreleasepool {
        NSArray *core = [CNDIconServicesDescriptorProfile coreIPhoneIOS26SpecsAt3x];
        Require(core.count == 11u, @"core descriptor count mismatch");
        NSArray *expected = @[ @"13x13@3:a0:v0:o0", @"27x27@3:a0:v0:o0",
                              @"27x27@3:a1:v0:o0", @"28x28@3:a0:v0:o0",
                              @"38x38@3:a0:v0:o0", @"38x38@3:a1:v0:o0",
                              @"48x48@3:a0:v0:o0", @"64x64@3:a0:v0:o0",
                              @"68x68@3:a0:v0:o0",
                              @"68x68@3:a0:v131072:o0",
                              @"68x68@3:a1:v0:o0" ];
        NSArray *expectedPixels = @[ @60, @87, @87, @87, @114, @114,
                                     @180, @192, @204, @204, @204 ];
        for (NSUInteger index = 0u; index < expected.count; index++) {
            CNDIconServicesDescriptorSpec *spec = core[index];
            Require([spec.canonicalIdentity isEqual:expected[index]],
                    @"core descriptor identity mismatch");
            Require(spec.targetPixelWidth ==
                        [expectedPixels[index] unsignedIntegerValue] &&
                    spec.targetPixelHeight ==
                        [expectedPixels[index] unsignedIntegerValue],
                    @"core descriptor response canvas mismatch");
        }
        NSArray *extras = [CNDIconServicesDescriptorProfile
            specsForIPhoneIOS26At3xWithConditionalExtras:CNDIconServicesDescriptorProfileExtrasSnippet];
        Require(extras.count == 12u, @"conditional descriptor count mismatch");
        NSMutableSet *identities = [NSMutableSet set];
        for (CNDIconServicesDescriptorSpec *spec in extras) [identities addObject:spec.canonicalIdentity];
        Require([identities containsObject:@"20x20@3:a0:v0:o0"], @"20-point snippet extra missing");
        Require([identities containsObject:@"64x64@3:a0:v0:o0"], @"64-point core Apps-list descriptor missing");
        Require([identities containsObject:@"68x68@3:a0:v131072:o0"],
                @"launch/return transition descriptor missing");
        Require(![identities containsObject:@"68x68@3:a0:v20000:o0"],
                @"hexadecimal transition variant was interpreted as decimal");
        for (CNDIconServicesDescriptorSpec *spec in extras) {
            if ([spec.canonicalIdentity isEqual:@"20x20@3:a0:v0:o0"]) {
                Require(spec.targetPixelWidth == 60u &&
                        spec.targetPixelHeight == 60u,
                        @"20-point response canvas mismatch");
            }
            if ([spec.canonicalIdentity isEqual:@"64x64@3:a0:v0:o0"]) {
                Require(spec.targetPixelWidth == 192u &&
                        spec.targetPixelHeight == 192u,
                        @"64-point response canvas mismatch");
            }
        }
        Require(![identities containsObject:@"40x40@3:a0:v0:o0"], @"40-point descriptor was added");
        Require([CNDIconServicesDescriptorProfile coreIPhoneIOS26SpecsAt3x].count == 11u,
                @"core descriptor set was mutated by conditional extras");
        Require([CNDIconServicesDescriptorSpec specWithPointWidth:68
            pointHeight:68 scale:3 appearance:0
            iconVariant:(NSUInteger)INT_MAX + 1u options:0] == nil,
            @"variantOptions value wider than admitted range was accepted");
        Require([CNDIconServicesDescriptorSpec specWithPointWidth:68
            pointHeight:68 scale:3 appearance:0
            iconVariant:0 options:(NSUInteger)INT_MAX + 1u] == nil,
            @"factory options wider than signed int were accepted");
        NSLog(@"ok descriptors=%lu extras=%lu", (unsigned long)core.count, (unsigned long)extras.count);
    }
    return 0;
}
