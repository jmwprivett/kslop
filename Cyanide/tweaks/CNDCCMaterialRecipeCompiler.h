#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const CNDCCMaterialRecipeCompilerErrorDomain;

typedef NS_ERROR_ENUM(CNDCCMaterialRecipeCompilerErrorDomain, CNDCCMaterialRecipeCompilerError) {
    CNDCCMaterialRecipeCompilerErrorInvalidInput = 1,
    CNDCCMaterialRecipeCompilerErrorInvalidSchema,
    CNDCCMaterialRecipeCompilerErrorSerialization,
    CNDCCMaterialRecipeCompilerErrorCannotFit,
    CNDCCMaterialRecipeCompilerErrorVerification,
};

typedef NS_ENUM(NSInteger, CNDCCMaterialRecipeSizingPolicy) {
    CNDCCMaterialRecipeSizingPolicyPreserveStock = 0,
    /// If necessary, omit the stock moduleFill/moduleStroke references and
    /// luminance/saturation/zoom filters. The result reports every omitted path.
    CNDCCMaterialRecipeSizingPolicyAllowCompactBackground = 1,
};

typedef struct {
    double red;
    double green;
    double blue;
    /// Normalized opacity, written to tintAlpha. The RGB color stays opaque.
    double opacity;
    /// Finite radius in points, in the inclusive range 0...200.
    double blurRadius;
} CNDCCMaterialRecipeParameters;

@interface CNDCCMaterialRecipeCompilation : NSObject
@property (nonatomic, readonly, copy) NSData *data;
@property (nonatomic, readonly) BOOL compacted;
@property (nonatomic, readonly, copy) NSArray<NSString *> *removedKeyPaths;
@property (nonatomic, readonly) NSUInteger unpaddedLength;
@end

/// Pure offline transformation of a stock modulesBackground.materialrecipe.
/// Supports materialSettingsVersion 2 and preserves native metadata except
/// for explicitly reported omissions under AllowCompactBackground. Output is
/// a verified binary plist with exactly stockData.length bytes. No file I/O.
CNDCCMaterialRecipeCompilation * _Nullable CNDCCCompileBackgroundMaterialRecipe(
    NSData *stockData, CNDCCMaterialRecipeParameters parameters,
    CNDCCMaterialRecipeSizingPolicy sizingPolicy, NSError * _Nullable * _Nullable error);

NS_ASSUME_NONNULL_END
