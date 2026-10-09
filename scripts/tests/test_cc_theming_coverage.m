#import <Foundation/Foundation.h>
#import "../../Cyanide/tweaks/CNDCCThemingCoverage.h"

#define REQUIRE(test) do { if (!(test)) { \
    fprintf(stderr, "coverage assertion failed: %s (line %d)\n", #test, __LINE__); \
    return 1; \
} } while (0)

int main(void)
{
    @autoreleasepool {
        NSDictionary *empty = CNDCCThemingCapturedCoverage(@[]);
        REQUIRE(![empty[@"complete"] boolValue]);
        REQUIRE(![empty[@"providerFactoryActive"] boolValue]);
        REQUIRE(![empty[@"samePIDPersistenceVerified"] boolValue]);
        REQUIRE([empty[@"pendingCoverageScopes"] count] == 9);
        REQUIRE([empty[@"surfaceCoverage"][@"expandedConnectivity"][@"status"]
            isEqualToString:@"no-kind-receivers-captured"]);

        NSDictionary *snapshot = CNDCCThemingCapturedCoverage(@[
            @{@"kind": @"wifi"}, @{@"kind": @"wifi"},
            @{@"kind": @"airDrop"}, @{@"kind": @"display"},
            @{@"kind": @"sound"}, @{@"kind": @"mediaPrevious"},
            @{@"kind": @"mediaPlayPause"}, @{@"kind": @"mediaNext"},
            @{@"kind": @"focus"}, @{@"kind": @"focusPersonal"},
        ]);
        REQUIRE(![snapshot[@"complete"] boolValue]);
        REQUIRE(![snapshot[@"providerFactoryActive"] boolValue]);
        for (NSDictionary *scope in [snapshot[@"surfaceCoverage"] allValues]) {
            REQUIRE(![scope[@"complete"] boolValue]);
            REQUIRE(![scope[@"countsAreSurfaceCoverage"] boolValue]);
            REQUIRE(![scope[@"surfaceCoverageVerified"] boolValue]);
            REQUIRE(![scope[@"interactionPersistenceVerified"] boolValue]);
            REQUIRE(![scope[@"reconstructionPersistenceVerified"] boolValue]);
        }
        NSDictionary *connectivity = snapshot[@"surfaceCoverage"][@"expandedConnectivity"];
        REQUIRE([connectivity[@"capturedReceiverCountsByKind"][@"wifi"] integerValue] == 2);
        REQUIRE([connectivity[@"capturedReceiverCountsByKind"][@"cellular"] integerValue] == 0);
        NSDictionary *brightness = snapshot[@"surfaceCoverage"][@"expandedBrightness"];
        REQUIRE([brightness[@"capturedReceiverCountsByKind"][@"display"] integerValue] == 1);
        REQUIRE([brightness[@"capturedReceiverCountsByKind"][@"nightShift"] integerValue] == 0);
        REQUIRE([brightness[@"capturedReceiverCountsByKind"][@"trueTone"] integerValue] == 0);
        puts("captured coverage assertions passed");
    }
    return 0;
}
