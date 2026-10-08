#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>

// Private CoreAnimation declarations used only by this host-side build tool.
// The generated PNGs are embedded in Cyanide; this code never runs on-device.
@interface CAPackage : NSObject
+ (instancetype)packageWithContentsOfURL:(NSURL *)url
                                     type:(NSString *)type
                                  options:(NSDictionary *)options
                                    error:(NSError **)error;
- (CALayer *)rootLayer;
@end

static void CNDSetPlayPauseState(CALayer *layer, NSString *state)
{
    NSString *name = layer.name.lowercaseString;
    if ([name isEqualToString:@"play shape"]) {
        layer.opacity = [state isEqualToString:@"play"] ? 1.0 : 0.0;
    } else if ([name isEqualToString:@"pause shape"]) {
        layer.opacity = [state isEqualToString:@"pause"] ? 1.0 : 0.0;
    } else if ([name isEqualToString:@"stop shape"]) {
        layer.opacity = [state isEqualToString:@"stop"] ? 1.0 : 0.0;
    }
    for (CALayer *sublayer in layer.sublayers ?: @[]) {
        CNDSetPlayPauseState(sublayer, state);
    }
}

static BOOL CNDRenderLayer(CALayer *layer,
                           NSString *state,
                           BOOL flipHorizontally,
                           NSURL *outputURL,
                           NSError **error)
{
    if (!layer || !outputURL) return NO;
    if (state.length) {
        CNDSetPlayPauseState(layer, state);
    }

    CGRect bounds = layer.bounds;
    if (CGRectIsEmpty(bounds)) bounds = CGRectMake(0, 0, 84, 84);
    const CGFloat scale = 3.0;
    const CGFloat padding = 168.0;
    size_t workingWidth = (size_t)ceil(
        (CGRectGetWidth(bounds) + padding * 2.0) * scale);
    size_t workingHeight = (size_t)ceil(
        (CGRectGetHeight(bounds) + padding * 2.0) * scale);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(NULL, workingWidth,
        workingHeight, 8, workingWidth * 4, colorSpace,
        kCGBitmapByteOrder32Big | kCGImageAlphaPremultipliedLast);
    if (!context) return NO;

    CGContextScaleCTM(context, scale, scale);
    CGContextTranslateCTM(context, 0,
        CGRectGetHeight(bounds) + padding * 2.0);
    CGContextScaleCTM(context, 1, -1);
    CGContextTranslateCTM(context, padding, padding);
    if (flipHorizontally) {
        CGContextTranslateCTM(context, CGRectGetWidth(bounds), 0);
        CGContextScaleCTM(context, -1, 1);
    }
    [CATransaction begin];
    [CATransaction setDisableActions:YES];
    [layer renderInContext:context];
    [CATransaction commit];

    unsigned char *pixels = CGBitmapContextGetData(context);
    size_t minX = workingWidth, minY = workingHeight, maxX = 0, maxY = 0;
    BOOL found = NO;
    for (size_t y = 0; y < workingHeight; y++) {
        for (size_t x = 0; x < workingWidth; x++) {
            if (pixels[(y * workingWidth + x) * 4 + 3] == 0) continue;
            found = YES;
            minX = MIN(minX, x);
            minY = MIN(minY, y);
            maxX = MAX(maxX, x);
            maxY = MAX(maxY, y);
        }
    }
    CGImageRef workingImage = CGBitmapContextCreateImage(context);
    CGContextRelease(context);
    if (!workingImage || !found) {
        CGImageRelease(workingImage);
        CGColorSpaceRelease(colorSpace);
        return NO;
    }

    CGRect cropRect = CGRectMake(minX, minY, maxX - minX + 1,
                                 maxY - minY + 1);
    CGImageRef cropped = CGImageCreateWithImageInRect(workingImage, cropRect);
    CGImageRelease(workingImage);
    if (!cropped) {
        CGColorSpaceRelease(colorSpace);
        return NO;
    }

    const size_t outputPixels = 252;
    const CGFloat glyphPixels = 112.0;
    CGFloat cropWidth = CGImageGetWidth(cropped);
    CGFloat cropHeight = CGImageGetHeight(cropped);
    CGFloat fit = glyphPixels / MAX(cropWidth, cropHeight);
    CGFloat drawWidth = cropWidth * fit;
    CGFloat drawHeight = cropHeight * fit;
    CGRect drawRect = CGRectMake((outputPixels - drawWidth) / 2.0,
        (outputPixels - drawHeight) / 2.0, drawWidth, drawHeight);
    CGContextRef outputContext = CGBitmapContextCreate(NULL, outputPixels,
        outputPixels, 8, outputPixels * 4, colorSpace,
        kCGBitmapByteOrder32Big | kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(colorSpace);
    if (!outputContext) {
        CGImageRelease(cropped);
        return NO;
    }
    CGContextSetInterpolationQuality(outputContext, kCGInterpolationHigh);
    CGContextDrawImage(outputContext, drawRect, cropped);
    CGImageRelease(cropped);
    CGImageRef image = CGBitmapContextCreateImage(outputContext);
    CGContextRelease(outputContext);
    if (!image) return NO;
    NSBitmapImageRep *bitmap = [[NSBitmapImageRep alloc] initWithCGImage:image];
    CGImageRelease(image);
    NSData *png = [bitmap representationUsingType:NSBitmapImageFileTypePNG
                                       properties:@{}];
    return [png writeToURL:outputURL options:NSDataWritingAtomic error:error];
}

static CAPackage *CNDLoadPackage(NSString *path, NSError **error)
{
    return [NSClassFromString(@"CAPackage")
        packageWithContentsOfURL:[NSURL fileURLWithPath:path]
        type:@"com.apple.coreanimation-bundle"
        options:@{}
        error:error];
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 4) {
            fprintf(stderr,
                "usage: %s PLAY_PAUSE.ca FORWARD_BACKWARD.ca OUTPUT_DIR\n",
                argv[0]);
            return 64;
        }
        NSString *playPath = [NSString stringWithUTF8String:argv[1]];
        NSString *forwardPath = [NSString stringWithUTF8String:argv[2]];
        NSURL *output = [NSURL fileURLWithPath:
            [NSString stringWithUTF8String:argv[3]] isDirectory:YES];
        NSError *error = nil;
        if (![[NSFileManager defaultManager] createDirectoryAtURL:output
            withIntermediateDirectories:YES attributes:nil error:&error]) {
            fprintf(stderr, "%s\n", error.localizedDescription.UTF8String);
            return 1;
        }

        CAPackage *play = CNDLoadPackage(playPath, &error);
        CAPackage *forward = CNDLoadPackage(forwardPath, &error);
        if (!play || !forward) {
            fprintf(stderr, "%s\n",
                (error.localizedDescription ?: @"CAPackage load failed").UTF8String);
            return 1;
        }
        NSArray<NSDictionary *> *jobs = @[
            @{ @"layer": play.rootLayer, @"state": @"play",
               @"name": @"Media-Play.png", @"flip": @NO },
            @{ @"layer": play.rootLayer, @"state": @"pause",
               @"name": @"Media-Pause.png", @"flip": @NO },
            @{ @"layer": forward.rootLayer, @"state": @"",
               @"name": @"Media-Next.png", @"flip": @NO },
            @{ @"layer": forward.rootLayer, @"state": @"",
               @"name": @"Media-Previous.png", @"flip": @YES },
        ];
        for (NSDictionary *job in jobs) {
            NSURL *destination = [output URLByAppendingPathComponent:job[@"name"]];
            if (!CNDRenderLayer(job[@"layer"], job[@"state"],
                                [job[@"flip"] boolValue], destination,
                                &error)) {
                fprintf(stderr, "%s: %s\n",
                    [(NSString *)job[@"name"] UTF8String],
                    (error.localizedDescription ?: @"render failed").UTF8String);
                return 1;
            }
            printf("%s\n", destination.path.UTF8String);
        }
    }
    return 0;
}
