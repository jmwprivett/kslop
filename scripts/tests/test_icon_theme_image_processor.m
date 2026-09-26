// Host-side regression harness for the bounded SnowBoard Remix PNG processor.
// Build locally with:
//   xcrun --sdk macosx clang -fobjc-arc -I Cyanide/installer \
//     scripts/tests/test_icon_theme_image_processor.m \
//     Cyanide/installer/CNDIconThemeImageProcessor.m \
//     -framework Foundation -framework CoreGraphics -framework ImageIO -lz \
//     -o build/icon-theme-image-processor-test

#import <CoreGraphics/CoreGraphics.h>
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import "CNDIconThemeImageProcessor.h"

#include <math.h>
#include <stdio.h>

static void Fail(NSString *message)
{
    fprintf(stderr, "icon processor test failed: %s\n", message.UTF8String);
    exit(1);
}

static NSData *MakeGradientPNG(NSUInteger width, NSUInteger height)
{
    NSMutableData *rgba = [NSMutableData dataWithLength:width * height * 4u];
    uint8_t *bytes = rgba.mutableBytes;
    for (NSUInteger y = 0; y < height; y++) {
        for (NSUInteger x = 0; x < width; x++) {
            NSUInteger offset = (y * width + x) * 4u;
            BOOL transparent = x < 7u || y < 7u || x + 7u >= width || y + 7u >= height;
            uint8_t noise = (uint8_t)((x * 37u + y * 73u + x * y * 11u) & 0xffu);
            bytes[offset] = (uint8_t)(((x * 255u) /
                                       MAX((NSUInteger)1u, width - 1u)) ^ noise);
            bytes[offset + 1u] = (uint8_t)(((y * 255u) /
                                           MAX((NSUInteger)1u, height - 1u)) ^ (noise >> 1u));
            bytes[offset + 2u] = (uint8_t)((((x + y) * 255u) /
                                           MAX((NSUInteger)1u, width + height - 2u)) ^
                                           (noise >> 2u));
            bytes[offset + 3u] = transparent ? 0u :
                (uint8_t)(48u + ((x * 207u) / MAX((NSUInteger)1u, width - 1u)));
            if (transparent) bytes[offset] = bytes[offset + 1u] = bytes[offset + 2u] = 0u;
        }
    }
    CGDataProviderRef provider = CGDataProviderCreateWithCFData((__bridge CFDataRef)rgba);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGImageRef image = CGImageCreate(width, height, 8u, 32u, width * 4u,
                                     colorSpace, kCGImageAlphaLast | kCGBitmapByteOrderDefault,
                                     provider, NULL, false, kCGRenderingIntentDefault);
    NSMutableData *png = [NSMutableData data];
    CGImageDestinationRef destination = CGImageDestinationCreateWithData(
        (__bridge CFMutableDataRef)png, CFSTR("public.png"), 1u, NULL);
    if (!provider || !colorSpace || !image || !destination) Fail(@"could not create gradient PNG");
    CGImageDestinationAddImage(destination, image, NULL);
    if (!CGImageDestinationFinalize(destination)) Fail(@"could not finalize gradient PNG");
    CFRelease(destination);
    CGImageRelease(image);
    CGColorSpaceRelease(colorSpace);
    CGDataProviderRelease(provider);
    return png;
}

static void Require(BOOL condition, NSString *message)
{
    if (!condition) Fail(message);
}

static NSData *DecodeRGBA(NSData *png)
{
    CGImageSourceRef source = CGImageSourceCreateWithData((__bridge CFDataRef)png, NULL);
    CGImageRef image = source ? CGImageSourceCreateImageAtIndex(source, 0u, NULL) : NULL;
    if (!source || !image) Fail(@"could not decode staged PNG in harness");
    size_t width = CGImageGetWidth(image);
    size_t height = CGImageGetHeight(image);
    NSMutableData *rgba = [NSMutableData dataWithLength:width * height * 4u];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(rgba.mutableBytes, width, height, 8u,
                                                   width * 4u, colorSpace,
                                                   kCGImageAlphaPremultipliedLast |
                                                       kCGBitmapByteOrder32Big);
    if (!context) Fail(@"could not create RGBA decode context");
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), image);
    CGContextRelease(context);
    CGColorSpaceRelease(colorSpace);
    CGImageRelease(image);
    CFRelease(source);
    return rgba;
}

int main(void)
{
    @autoreleasepool {
        NSData *source = MakeGradientPNG(256u, 256u);
        NSError *error = nil;
        NSDictionary *unbounded = CNDProcessIconThemePNG(source, 120u, 120u, 0u, &error);
        if (!unbounded) Fail(error.localizedDescription ?: @"unbounded processing failed");
        Require([unbounded[@"targetWidth"] unsignedIntegerValue] == 120u,
                @"target width mismatch");
        Require([unbounded[@"targetHeight"] unsignedIntegerValue] == 120u,
                @"target height mismatch");
        Require([unbounded[@"completeDecodeVerified"] boolValue],
                @"staged decode was not verified");
        Require([unbounded[@"alphaPreserved"] boolValue], @"alpha was not preserved");
        Require([unbounded[@"alphaClassesPreserved"] boolValue],
                @"source transparency classes were lost in RGBA output");
        Require([unbounded[@"alphaSourceMetrics"][@"hasTransparentPixels"] boolValue],
                @"synthetic source did not contain transparent pixels");
        Require([unbounded[@"alphaDecodedMetrics"][@"hasTransparentPixels"] boolValue],
                @"decoded RGBA output did not contain transparent pixels");
        NSDictionary *repeat = CNDProcessIconThemePNG(source, 120u, 120u, 0u, &error);
        Require(repeat != nil &&
                    [repeat[@"unpaddedHash"] isEqual:unbounded[@"unpaddedHash"]],
                @"identical input did not produce a deterministic hash");

        NSData *rgbaPNG = unbounded[@"unpaddedBytes"];
        NSUInteger capacity = rgbaPNG.length > 1u ? rgbaPNG.length - 1u : rgbaPNG.length;
        NSDictionary *fitted = CNDProcessIconThemePNG(source, 120u, 120u, capacity, &error);
        if (!fitted) Fail(error.localizedDescription ?: @"capacity processing failed");
        Require([fitted[@"paddedLength"] unsignedIntegerValue] == capacity,
                @"padded output did not exactly fill the capacity");
        Require([fitted[@"modeFamily"] isEqual:@"indexed"],
                @"capacity fallback did not select an indexed representation");
        Require([fitted[@"completeDecodeVerified"] boolValue],
                @"padded indexed output was not decoded after padding");
        Require([fitted[@"alphaClassesPreserved"] boolValue],
                @"indexed quantization erased source transparency classes");
        Require([fitted[@"alphaDecodedMetrics"][@"hasTransparentPixels"] boolValue],
                @"indexed output did not retain transparent pixels");
        NSData *decodedRGBA = DecodeRGBA(fitted[@"unpaddedBytes"]);
        const uint8_t *decodedBytes = decodedRGBA.bytes;
        Require(decodedBytes[3] == 0u, @"transparent padding became visible");
        Require(decodedBytes[(60u * 120u + 60u) * 4u + 3u] > 0u,
                @"visible artwork lost alpha");
        NSUInteger alphaZeroEntries = 0u;
        for (NSDictionary *entry in fitted[@"palette"]) {
            if ([entry[@"a"] unsignedIntegerValue] == 0u) alphaZeroEntries++;
        }
        Require(alphaZeroEntries > 0u, @"transparent palette entry was lost");
        printf("ok mode=%s bytes=%lu capacity=%lu hash=%s\n",
               [fitted[@"mode"] UTF8String],
               (unsigned long)[fitted[@"unpaddedLength"] unsignedIntegerValue],
               (unsigned long)capacity,
               [fitted[@"paddedHash"] UTF8String]);
    }
    return 0;
}
