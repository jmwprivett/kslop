#import <AppKit/AppKit.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// Host-only reference renderer. It never runs in Cyanide or on an iOS device.
@interface CAPackage : NSObject
+ (instancetype)packageWithContentsOfURL:(NSURL *)url type:(NSString *)type
                                options:(NSDictionary *)options error:(NSError **)error;
- (CALayer *)rootLayer;
@end

@interface CUINamedImage : NSObject
- (CGImageRef)image;
@end
@interface CUICatalog : NSObject
- (instancetype)initWithURL:(NSURL *)url error:(NSError **)error;
- (CUINamedImage *)imageWithName:(NSString *)name scaleFactor:(double)scale
                     deviceIdiom:(NSInteger)idiom deviceSubtype:(NSUInteger)subtype;
- (id)namedVectorGlyphWithName:(NSString *)name scaleFactor:(double)scale
                  deviceIdiom:(NSInteger)idiom glyphSize:(NSInteger)size
                  glyphWeight:(NSInteger)weight glyphPointSize:(double)pointSize
               appearanceName:(NSString *)appearance;
@end
@interface NSObject (StockVectorGlyph)
- (CGImageRef)imageWithTintColor:(CGColorRef)color;
@end

static int ExportCatalogImage(NSString *catalogPath, NSString *name, NSString *destination,
                              double scale) {
    dlopen("/System/Library/PrivateFrameworks/CoreUI.framework/CoreUI", RTLD_LAZY);
    NSError *error = nil;
    CUICatalog *catalog = [[NSClassFromString(@"CUICatalog") alloc]
        initWithURL:[NSURL fileURLWithPath:catalogPath] error:&error];
    CUINamedImage *rendition = [catalog imageWithName:name scaleFactor:scale
        deviceIdiom:1 deviceSubtype:2688];
    CGImageRef image = rendition ? [rendition image] : NULL;
    if (!image) {
        fprintf(stderr, "catalog image '%s' unavailable at scale %g in %s\n",
            name.UTF8String, scale, catalogPath.UTF8String);
        return 1;
    }
    size_t width = CGImageGetWidth(image), height = CGImageGetHeight(image);
    CGColorSpaceRef space = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGContextRef context = CGBitmapContextCreate(NULL, width, height, 8, width * 4,
        space, kCGBitmapByteOrder32Big | kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(space);
    if (!context) return 2;
    CGRect canvas = CGRectMake(0, 0, width, height);
    CGContextDrawImage(context, canvas, image);
    CGContextSetBlendMode(context, kCGBlendModeSourceIn);
    CGContextSetRGBFillColor(context, 1, 1, 1, 1);
    CGContextFillRect(context, canvas);
    CGImageRef tinted = CGBitmapContextCreateImage(context);
    NSBitmapImageRep *bitmap = [[NSBitmapImageRep alloc] initWithCGImage:tinted];
    CGImageRelease(tinted);
    CGContextRelease(context);
    NSData *png = [bitmap representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    return [png writeToFile:destination atomically:YES] ? 0 : 2;
}

static int ExportSymbol(NSString *catalogPath, NSString *name, NSString *destination,
                        NSInteger size, NSInteger weight, double pointSize, double scale) {
    dlopen("/System/Library/PrivateFrameworks/CoreUI.framework/CoreUI", RTLD_LAZY);
    NSError *error = nil;
    CUICatalog *catalog = [[NSClassFromString(@"CUICatalog") alloc]
        initWithURL:[NSURL fileURLWithPath:catalogPath] error:&error];
    id glyph = [catalog namedVectorGlyphWithName:name scaleFactor:scale deviceIdiom:1
        glyphSize:size glyphWeight:weight glyphPointSize:pointSize appearanceName:nil];
    if (!glyph) { fprintf(stderr, "stock symbol '%s' unavailable in %s\n", name.UTF8String, catalogPath.UTF8String); return 1; }
    CGColorRef tint = CGColorCreateGenericRGB(1, 1, 1, 1);
    CGImageRef image = [glyph imageWithTintColor:tint];
    CGColorRelease(tint);
    if (!image) return 2;
    NSBitmapImageRep *bitmap = [[NSBitmapImageRep alloc] initWithCGImage:image];
    NSData *png = [bitmap representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    if (![png writeToFile:destination atomically:YES]) return 3;
    printf("%s %zux%zu\n", destination.UTF8String, CGImageGetWidth(image), CGImageGetHeight(image));
    return 0;
}

static void RemoveAnimations(CALayer *layer) {
    [layer removeAllAnimations];
    for (CALayer *child in layer.sublayers) RemoveAnimations(child);
}

static void ApplyState(CALayer *layer, NSString *name) {
    NSArray *states = [layer valueForKey:@"states"];
    id selected = nil;
    for (id state in states) if ([[state valueForKey:@"name"] isEqual:name]) selected = state;
    if (!selected) {
        fprintf(stderr, "state '%s' unavailable\n", name.UTF8String);
        return;
    }
    id base = [selected valueForKey:@"basedOn"];
    if ([base isKindOfClass:NSString.class] && [base length]) ApplyState(layer, base);
    for (id element in [selected valueForKey:@"elements"]) {
        if (![NSStringFromClass([element class]) containsString:@"SetValue"]) continue;
        @try {
            id target = [element valueForKey:@"target"];
            NSString *key = [element valueForKey:@"keyPath"];
            id value = [element valueForKey:@"value"];
            [target setValue:value forKeyPath:key];
        } @catch (NSException *exception) {
            fprintf(stderr, "state property skipped: %s\n", exception.reason.UTF8String);
        }
    }
}

// Backdrop vibrancy requires the live system background. A transparent reference
// instead shows its native vector mask in white; geometry stays unmodified.
static void FlattenBackdrop(CALayer *layer) {
    for (CALayer *child in [layer.sublayers copy]) {
        if ([NSStringFromClass(child.class) containsString:@"Backdrop"] && child.mask) {
            CALayer *mask = child.mask;
            child.mask = nil;
            CALayer *replacement = [CALayer layer];
            replacement.bounds = child.bounds;
            replacement.position = child.position;
            replacement.anchorPoint = child.anchorPoint;
            replacement.transform = child.transform;
            replacement.opacity = child.opacity;
            [replacement addSublayer:mask];
            [layer replaceSublayer:child with:replacement];
        } else FlattenBackdrop(child);
    }
}

static CGRect ContentsBounds(CALayer *layer) {
    CGImageRef image = (__bridge CGImageRef)layer.contents;
    if (!image || CFGetTypeID(image) != CGImageGetTypeID()) return CGRectNull;
    NSBitmapImageRep *bitmap = [[NSBitmapImageRep alloc] initWithCGImage:image];
    NSInteger minX = bitmap.pixelsWide, minY = bitmap.pixelsHigh, maxX = -1, maxY = -1;
    for (NSInteger y = 0; y < bitmap.pixelsHigh; y++) for (NSInteger x = 0; x < bitmap.pixelsWide; x++) {
        if ([[bitmap colorAtX:x y:y] alphaComponent] < 24.0 / 255.0) continue;
        minX = MIN(minX, x); minY = MIN(minY, y); maxX = MAX(maxX, x); maxY = MAX(maxY, y);
    }
    if (maxX < minX || maxY < minY) return CGRectNull;
    return CGRectMake(layer.bounds.origin.x + minX * layer.bounds.size.width / bitmap.pixelsWide,
        layer.bounds.origin.y + minY * layer.bounds.size.height / bitmap.pixelsHigh,
        (maxX + 1 - minX) * layer.bounds.size.width / bitmap.pixelsWide,
        (maxY + 1 - minY) * layer.bounds.size.height / bitmap.pixelsHigh);
}

static CGRect DrawingBounds(CALayer *layer, CALayer *canvas) {
    if (layer.hidden || layer.opacity == 0) return CGRectNull;
    id compositing = layer.compositingFilter;
    NSString *filterName = [compositing isKindOfClass:NSString.class] ? compositing :
        ([compositing respondsToSelector:@selector(name)] ? [compositing valueForKey:@"name"] : nil);
    if ([filterName isEqualToString:@"destOut"]) return CGRectNull;
    CGRect local = CGRectNull;
    if ([layer isKindOfClass:CAShapeLayer.class]) {
        CAShapeLayer *shape = (CAShapeLayer *)layer;
        if (shape.path && shape.fillColor && CGColorGetAlpha(shape.fillColor) > 0)
            local = CGPathGetPathBoundingBox(shape.path);
    } else if (layer.contents) local = ContentsBounds(layer);
    else if (layer.backgroundColor && CGColorGetAlpha(layer.backgroundColor) > 0) local = layer.bounds;
    CGRect result = CGRectIsNull(local) ? CGRectNull : [layer convertRect:local toLayer:canvas];
    if ([layer isKindOfClass:CAReplicatorLayer.class]) {
        CAReplicatorLayer *replicator = (CAReplicatorLayer *)layer;
        if (!CATransform3DIsAffine(replicator.instanceTransform) || replicator.instanceCount > 64) return CGRectNull;
        CGFloat anchorX = layer.bounds.origin.x + layer.bounds.size.width * layer.anchorPoint.x;
        CGFloat anchorY = layer.bounds.origin.y + layer.bounds.size.height * layer.anchorPoint.y;
        CGAffineTransform step = CATransform3DGetAffineTransform(replicator.instanceTransform);
        for (CALayer *child in layer.sublayers) {
            CGRect bounds = DrawingBounds(child, layer);
            if (CGRectIsNull(bounds)) continue;
            CGAffineTransform instance = CGAffineTransformIdentity;
            for (NSInteger i = 0; i < replicator.instanceCount; i++) {
                CGRect offset = CGRectOffset(bounds, -anchorX, -anchorY);
                CGRect replicated = CGRectOffset(CGRectApplyAffineTransform(offset, instance), anchorX, anchorY);
                result = CGRectUnion(result, [layer convertRect:replicated toLayer:canvas]);
                instance = CGAffineTransformConcat(instance, step);
            }
        }
        return result;
    }
    for (CALayer *child in layer.sublayers) result = CGRectUnion(result, DrawingBounds(child, canvas));
    return result;
}

// Offline geometry evidence for resource adaptation. This follows the local
// resource's vector paths and PNG alpha bounds through CoreAnimation transforms.
// No UIKit view, presentation frame, label, or device is inspected.
static int ExportLayout(NSString *path, NSString *state, NSString *destination) {
    NSError *error = nil;
    CAPackage *package = [NSClassFromString(@"CAPackage")
        packageWithContentsOfURL:[NSURL fileURLWithPath:path]
        type:@"com.apple.coreanimation-bundle" options:@{} error:&error];
    if (!package) { fprintf(stderr, "%s\n", error.description.UTF8String); return 1; }
    CALayer *root = package.rootLayer;
    CGRect documentBounds = root.bounds;
    [CATransaction begin];
    [CATransaction setDisableActions:YES];
    if (![state isEqual:@"base"]) ApplyState(root, state);
    RemoveAnimations(root);
    FlattenBackdrop(root);
    CALayer *canvas = [CALayer layer];
    canvas.bounds = CGRectMake(-256, -256, 512, 512);
    root.position = CGPointZero;
    [canvas addSublayer:root];
    [CATransaction commit];
    CGRect drawing = DrawingBounds(root, canvas);
    if (CGRectIsNull(drawing) || CGRectIsInfinite(drawing)) return 5;
    NSDictionary *layout = @{
        @"documentBounds": @[@(documentBounds.origin.x), @(documentBounds.origin.y),
            @(documentBounds.size.width), @(documentBounds.size.height)],
        @"state": state, @"alphaThreshold": @24,
        @"contentBoundsRelativeToRootPosition": @[@(drawing.origin.x), @(drawing.origin.y),
            @(drawing.size.width), @(drawing.size.height)],
    };
    NSData *data = [NSJSONSerialization dataWithJSONObject:layout
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:&error];
    return [data writeToFile:destination options:NSDataWritingAtomic error:&error] ? 0 : 4;
}

// Export the complete vector drawing rather than the historical CAML canvas.
// Upstream theme packages may place paths outside that canvas. Measuring and
// cropping their resource layers preserves the authored art without clipping.
static int ExportContent(NSString *path, NSString *state, NSString *destination) {
    NSError *error = nil;
    CAPackage *package = [NSClassFromString(@"CAPackage")
        packageWithContentsOfURL:[NSURL fileURLWithPath:path]
        type:@"com.apple.coreanimation-bundle" options:@{} error:&error];
    if (!package) { fprintf(stderr, "%s\n", error.description.UTF8String); return 1; }
    CALayer *root = package.rootLayer;
    [CATransaction begin];
    [CATransaction setDisableActions:YES];
    if (![state isEqual:@"base"]) ApplyState(root, state);
    RemoveAnimations(root);
    FlattenBackdrop(root);
    [CATransaction commit];
    const CGFloat scale = 8;
    // The legacy artwork's transforms can extend beyond its document. Capture
    // its real alpha footprint in a padded host canvas before cropping it.
    const CGFloat padding = 128;
    size_t width = ceil((root.bounds.size.width + 2 * padding) * scale);
    size_t height = ceil((root.bounds.size.height + 2 * padding) * scale);
    CGColorSpaceRef space = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGContextRef context = CGBitmapContextCreate(NULL, width, height, 8, width * 4,
        space, kCGBitmapByteOrder32Big | kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(space);
    if (!context) return 2;
    CGContextScaleCTM(context, scale, scale);
    CGContextTranslateCTM(context, padding - root.bounds.origin.x, padding - root.bounds.origin.y);
    [root renderInContext:context];
    CGImageRef image = CGBitmapContextCreateImage(context);
    NSBitmapImageRep *bitmap = [[NSBitmapImageRep alloc] initWithCGImage:image];
    NSInteger minX = width, minY = height, maxX = -1, maxY = -1;
    for (NSInteger y = 0; y < (NSInteger)height; y++) for (NSInteger x = 0; x < (NSInteger)width; x++) {
        if ([[bitmap colorAtX:x y:y] alphaComponent] == 0) continue;
        minX = MIN(minX, x); minY = MIN(minY, y); maxX = MAX(maxX, x); maxY = MAX(maxY, y);
    }
    if (maxX < minX || minX == 0 || minY == 0 || maxX + 1 == (NSInteger)width || maxY + 1 == (NSInteger)height) {
        CGImageRelease(image); CGContextRelease(context); return 5;
    }
    CGImageRef cropped = CGImageCreateWithImageInRect(image,
        CGRectMake(minX - 1, minY - 1, maxX - minX + 3, maxY - minY + 3));
    NSBitmapImageRep *croppedBitmap = [[NSBitmapImageRep alloc] initWithCGImage:cropped];
    NSData *png = [croppedBitmap representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    BOOL ok = [png writeToFile:destination options:NSDataWritingAtomic error:&error];
    CGImageRelease(image);
    CGImageRelease(cropped);
    CGContextRelease(context);
    if (!ok) { fprintf(stderr, "%s\n", error.description.UTF8String); return 3; }
    return 0;
}

static int ContactSheet(NSString *manifestPath, NSString *destination) {
    NSMutableDictionary *manifest = [NSJSONSerialization JSONObjectWithData:
        [NSData dataWithContentsOfFile:manifestPath] options:NSJSONReadingMutableContainers error:nil];
    NSArray<NSMutableDictionary *> *entries = manifest[@"references"];
    NSUInteger columns = 5, rows = (entries.count + columns - 1) / columns;
    CGFloat cellWidth = 238, cellHeight = 190;
    NSImage *sheet = [[NSImage alloc] initWithSize:NSMakeSize(columns * cellWidth, rows * cellHeight)];
    [sheet lockFocus];
    [[NSColor colorWithWhite:0.11 alpha:1] setFill];
    NSRectFill(NSMakeRect(0, 0, sheet.size.width, sheet.size.height));
    NSDictionary *attributes = @{NSFontAttributeName: [NSFont systemFontOfSize:12],
        NSForegroundColorAttributeName: NSColor.whiteColor};
    for (NSUInteger i = 0; i < entries.count; i++) {
        NSMutableDictionary *entry = entries[i];
        CGFloat x = (i % columns) * cellWidth;
        CGFloat y = sheet.size.height - (i / columns + 1) * cellHeight;
        NSImage *icon = [[NSImage alloc] initWithContentsOfFile:
            [manifestPath.stringByDeletingLastPathComponent stringByAppendingPathComponent:entry[@"png"]]];
        NSBitmapImageRep *sourceBitmap = [[NSBitmapImageRep alloc] initWithData:icon.TIFFRepresentation];
        NSUInteger nonzero = 0, transparent = 0;
        NSInteger minX = sourceBitmap.pixelsWide, minY = sourceBitmap.pixelsHigh, maxX = -1, maxY = -1;
        for (NSInteger py = 0; py < sourceBitmap.pixelsHigh; py++) {
            for (NSInteger px = 0; px < sourceBitmap.pixelsWide; px++) {
                CGFloat alpha = [[sourceBitmap colorAtX:px y:py] alphaComponent];
                if (alpha == 0) transparent++;
                else { nonzero++; minX = MIN(minX, px); minY = MIN(minY, py); maxX = MAX(maxX, px); maxY = MAX(maxY, py); }
            }
        }
        if (!nonzero || !transparent) { fprintf(stderr, "invalid transparent glyph: %s\n", [entry[@"png"] UTF8String]); return 2; }
        entry[@"nonzero_alpha_pixels"] = @(nonzero);
        entry[@"alpha_bbox"] = @[@(minX), @(minY), @(maxX + 1), @(maxY + 1)];
        CGFloat fit = 108 / MAX(icon.size.width, icon.size.height);
        NSSize size = NSMakeSize(icon.size.width * fit, icon.size.height * fit);
        [icon drawInRect:NSMakeRect(x + (cellWidth - size.width) / 2,
            y + 60 + (108 - size.height) / 2, size.width, size.height)];
        [entry[@"label"] drawInRect:NSMakeRect(x + 12, y + 32, cellWidth - 24, 22) withAttributes:attributes];
        [entry[@"state"] drawInRect:NSMakeRect(x + 12, y + 10, cellWidth - 24, 22) withAttributes:attributes];
    }
    [sheet unlockFocus];
    NSBitmapImageRep *bitmap = [[NSBitmapImageRep alloc] initWithData:sheet.TIFFRepresentation];
    NSData *png = [bitmap representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    NSData *updatedManifest = [NSJSONSerialization dataWithJSONObject:manifest options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:nil];
    [updatedManifest writeToFile:manifestPath atomically:YES];
    return [png writeToFile:destination atomically:YES] ? 0 : 1;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc == 5 && [@(argv[1]) isEqual:@"--symbol"]) return ExportSymbol(@(argv[2]), @(argv[3]), @(argv[4]), 0, 0, 40, 3);
        if (argc == 7 && [@(argv[1]) isEqual:@"--symbol"]) return ExportSymbol(@(argv[2]), @(argv[3]), @(argv[4]), [@(argv[5]) integerValue], [@(argv[6]) integerValue], 40, 3);
        if (argc == 8 && [@(argv[1]) isEqual:@"--symbol"]) return ExportSymbol(@(argv[2]), @(argv[3]), @(argv[4]), [@(argv[5]) integerValue], [@(argv[6]) integerValue], [@(argv[7]) doubleValue], 3);
        if (argc == 9 && [@(argv[1]) isEqual:@"--symbol"]) return ExportSymbol(@(argv[2]), @(argv[3]), @(argv[4]), [@(argv[5]) integerValue], [@(argv[6]) integerValue], [@(argv[7]) doubleValue], [@(argv[8]) doubleValue]);
        if (argc == 6 && [@(argv[1]) isEqual:@"--image"]) return ExportCatalogImage(@(argv[2]), @(argv[3]), @(argv[4]), [@(argv[5]) doubleValue]);
        if (argc == 5 && [@(argv[1]) isEqual:@"--layout"]) return ExportLayout(@(argv[2]), @(argv[3]), @(argv[4]));
        if (argc == 5 && [@(argv[1]) isEqual:@"--content"]) return ExportContent(@(argv[2]), @(argv[3]), @(argv[4]));
        if (argc == 4 && [@(argv[1]) isEqual:@"--sheet"]) return ContactSheet(@(argv[2]), @(argv[3]));
        if (argc != 4) {
            fprintf(stderr, "usage: %s PACKAGE.ca STATE_OR_BASE OUTPUT.png\n", argv[0]);
            return 64;
        }
        NSError *error = nil;
        CAPackage *package = [NSClassFromString(@"CAPackage")
            packageWithContentsOfURL:[NSURL fileURLWithPath:@(argv[1])]
            type:@"com.apple.coreanimation-bundle" options:@{} error:&error];
        if (!package) { fprintf(stderr, "%s\n", error.description.UTF8String); return 1; }
        CALayer *layer = package.rootLayer;
        NSString *state = @(argv[2]);
        [CATransaction begin];
        [CATransaction setDisableActions:YES];
        if (![state isEqual:@"base"]) ApplyState(layer, state);
        RemoveAnimations(layer);
        FlattenBackdrop(layer);
        [CATransaction commit];
        CGRect bounds = layer.bounds;
        const CGFloat scale = 4;
        size_t width = ceil(bounds.size.width * scale), height = ceil(bounds.size.height * scale);
        CGColorSpaceRef space = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
        CGContextRef context = CGBitmapContextCreate(NULL, width, height, 8, width * 4,
            space, kCGBitmapByteOrder32Big | kCGImageAlphaPremultipliedLast);
        CGColorSpaceRelease(space);
        if (!context) return 2;
        CGContextScaleCTM(context, scale, scale);
        CGContextTranslateCTM(context, -bounds.origin.x, -bounds.origin.y);
        [layer renderInContext:context];
        CGImageRef image = CGBitmapContextCreateImage(context);
        NSBitmapImageRep *bitmap = [[NSBitmapImageRep alloc] initWithCGImage:image];
        NSData *png = [bitmap representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
        BOOL ok = [png writeToFile:@(argv[3]) options:NSDataWritingAtomic error:&error];
        CGImageRelease(image);
        CGContextRelease(context);
        if (!ok) { fprintf(stderr, "%s\n", error.description.UTF8String); return 3; }
        printf("%s %zux%zu\n", argv[3], width, height);
    }
    return 0;
}
