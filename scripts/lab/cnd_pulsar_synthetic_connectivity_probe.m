#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <CommonCrypto/CommonDigest.h>

#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef CND_SYNTHETIC_CONNECTIVITY_OUTPUT_TOKEN
#define CND_SYNTHETIC_CONNECTIVITY_OUTPUT_TOKEN ""
#endif

#ifndef CND_SYNTHETIC_CONNECTIVITY_REPORT_PATH
#define CND_SYNTHETIC_CONNECTIVITY_REPORT_PATH \
    "/var/tmp/cyanide-pulsar-synthetic-connectivity.log"
#endif

#ifndef CND_SYNTHETIC_CONNECTIVITY_ASSET_DIRECTORY
#define CND_SYNTHETIC_CONNECTIVITY_ASSET_DIRECTORY \
    "/var/tmp/cyanide-pulsar-synthetic-connectivity-assets"
#endif

#ifndef CND_SYNTHETIC_CONNECTIVITY_EXPECTED_PID
#define CND_SYNTHETIC_CONNECTIVITY_EXPECTED_PID 0
#endif

#ifndef CND_SYNTHETIC_CONNECTIVITY_HOLD_SECONDS
#define CND_SYNTHETIC_CONNECTIVITY_HOLD_SECONDS 45
#endif

#ifndef CND_PULSAR_CONNECTIVITY_CANARY
#define CND_PULSAR_CONNECTIVITY_CANARY 0
#endif

#ifndef CND_PULSAR_THEME_DIRECTORY
#define CND_PULSAR_THEME_DIRECTORY \
    "/var/tmp/cyanide-pulsar-connectivity-canary-assets"
#endif

#ifndef CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
#define CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY 0
#endif

/*
 * VM-only, process-local connectivity presentation probe.
 *
 * This intentionally does not load or call CoreTelephony, CommCenter, or a
 * Bluetooth daemon. It asks the already-loaded ControlCenterUIKit classes for
 * their own glyphs, temporarily drives the existing Bluetooth controller, and
 * mounts a noninteractive Cellular controller in the visible connectivity
 * panel. Every touched state is restored before the probe completes.
 */

static int gReportFD = -1;
static __strong UIViewController *gParentController;
static __strong UIViewController *gSyntheticCellularController;
static __strong UIViewController *gCoveredController;
static __strong UIView *gSyntheticMountedView;
static __strong UIView *gCoveredMountedView;
static __strong id gOriginalCellularController;
static __strong id gOriginalExpandedCellularController;
static __strong id gBluetoothController;
static __strong id gWiFiController;
static __strong id gAirplaneController;
static __strong id gExpandedAirplaneController;
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
static __strong id gAirDropController;
static __strong id gWiFiTemplateView;
static __strong id gBluetoothTemplateView;
static __strong id gAirDropTemplateView;
#endif
static __strong UIImage *gOriginalWiFiGlyph;
static __strong UIImage *gOriginalWiFiSelectedGlyph;
static __strong UIImage *gOriginalBluetoothGlyph;
static __strong UIImage *gOriginalBluetoothSelectedGlyph;
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
static __strong UIImage *gOriginalAirDropGlyph;
static __strong UIImage *gOriginalAirDropSelectedGlyph;
static __strong UIImage *gOriginalWiFiTemplateGlyph;
static __strong UIImage *gOriginalWiFiTemplateSelectedGlyph;
static __strong UIImage *gOriginalBluetoothTemplateGlyph;
static __strong UIImage *gOriginalBluetoothTemplateSelectedGlyph;
static __strong UIImage *gOriginalAirDropTemplateGlyph;
static __strong UIImage *gOriginalAirDropTemplateSelectedGlyph;
#endif
static __strong UIImage *gOriginalAirplaneGlyph;
static __strong NSArray<UIImageView *> *gAirplaneImageViews;
static __strong NSArray<UIImage *> *gOriginalAirplaneImages;
static __strong UIImageView *gCellularImageView;
static __strong UIImageView *gVisibleAirplaneImageView;
static __strong UIImage *gOriginalCellularImage;
static __strong UIImage *gOriginalVisibleAirplaneImage;
static BOOL gCoveredViewWasHidden;
static BOOL gBluetoothWasObserving;
static BOOL gBluetoothObservationChanged;
static BOOL gWiFiWasObserving;
static BOOL gWiFiObservationChanged;
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
static BOOL gAirDropWasObserving;
static BOOL gAirDropObservationChanged;
#endif
static int32_t gOriginalBluetoothState;
static bool gBluetoothStateCaptured;
static bool gPresentationActive;
static bool gThemeApplied;
static bool gWiFiThemeApplied;
static bool gBluetoothThemeApplied;
static bool gAirplaneThemeApplied;
static bool gCellularThemeApplied;
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
static bool gAirDropThemeApplied;
static bool gWiFiTemplateThemeApplied;
static bool gBluetoothTemplateThemeApplied;
static bool gAirDropTemplateThemeApplied;
static __strong id gOriginalWiFiPackageDescription;
static __strong id gOriginalBluetoothPackageDescription;
static __strong NSString *gOriginalWiFiGlyphState;
static __strong NSString *gOriginalBluetoothGlyphState;
static __strong id gWiFiMotionDescription;
static __strong id gBluetoothMotionDescription;
static __strong id gWiFiMotionPackage;
static __strong id gBluetoothMotionPackage;
static bool gWiFiMotionApplied;
static bool gBluetoothMotionApplied;
#endif
static bool gRestored;

static void CNDLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDLog(const char *format, ...)
{
    if (gReportFD < 0) return;
    char line[8192] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t count = MIN((size_t)length, sizeof(line) - 1U);
    (void)write(gReportFD, line, count);
    (void)fsync(gReportFD);
}

static const char *CNDClassName(id object)
{
    return object ? class_getName(object_getClass(object)) : "-";
}

static bool CNDMethodTypes(id object, const char *name, const char *expected)
{
    if (!object || !name || !expected) return false;
    Method method = class_getInstanceMethod(
        object_getClass(object), sel_registerName(name));
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    return types && strcmp(types, expected) == 0;
}

static id CNDObjectGetter(id object, const char *name)
{
    if (!CNDMethodTypes(object, name, "@16@0:8")) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(
            object, sel_registerName(name));
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static bool CNDObjectSetter(id object, const char *name, id value)
{
    if (!CNDMethodTypes(object, name, "v24@0:8@16")) return false;
    @try {
        ((void (*)(id, SEL, id))objc_msgSend)(
            object, sel_registerName(name), value);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDVoidNoArgument(id object, const char *name)
{
    if (!CNDMethodTypes(object, name, "v16@0:8")) return false;
    @try {
        ((void (*)(id, SEL))objc_msgSend)(object, sel_registerName(name));
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static BOOL CNDBoolNoArgument(id object, const char *name, bool *valid)
{
    if (!CNDMethodTypes(object, name, "B16@0:8")) {
        if (valid) *valid = false;
        return NO;
    }
    @try {
        BOOL value = ((BOOL (*)(id, SEL))objc_msgSend)(
            object, sel_registerName(name));
        if (valid) *valid = true;
        return value;
    } @catch (__unused NSException *exception) {
        if (valid) *valid = false;
        return NO;
    }
}

static bool CNDBoolSetter(id object, const char *name, BOOL value)
{
    if (!CNDMethodTypes(object, name, "v20@0:8B16")) return false;
    @try {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(
            object, sel_registerName(name), value);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDIntGetter(id object, const char *name, int32_t *value)
{
    if (!value || !CNDMethodTypes(object, name, "i16@0:8")) return false;
    @try {
        *value = ((int32_t (*)(id, SEL))objc_msgSend)(
            object, sel_registerName(name));
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static bool CNDVoidInt(id object, const char *name, int32_t value)
{
    if (!CNDMethodTypes(object, name, "v20@0:8i16")) return false;
    @try {
        ((void (*)(id, SEL, int32_t))objc_msgSend)(
            object, sel_registerName(name), value);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

static id CNDObjectForInt(id object, const char *name, int32_t value)
{
    if (!CNDMethodTypes(object, name, "@20@0:8i16")) return nil;
    @try {
        return ((id (*)(id, SEL, int32_t))objc_msgSend)(
            object, sel_registerName(name), value);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static BOOL CNDBoolForInt(id object, const char *name, int32_t value,
                          bool *valid)
{
    if (!CNDMethodTypes(object, name, "B20@0:8i16")) {
        if (valid) *valid = false;
        return NO;
    }
    @try {
        BOOL result = ((BOOL (*)(id, SEL, int32_t))objc_msgSend)(
            object, sel_registerName(name), value);
        if (valid) *valid = true;
        return result;
    } @catch (__unused NSException *exception) {
        if (valid) *valid = false;
        return NO;
    }
}

static id CNDObjectForObject(id object, const char *name, id value)
{
    if (!CNDMethodTypes(object, name, "@24@0:8@16")) return nil;
    @try {
        return ((id (*)(id, SEL, id))objc_msgSend)(
            object, sel_registerName(name), value);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static bool CNDVoidObject(id object, const char *name, id value)
{
    if (!CNDMethodTypes(object, name, "v24@0:8@16")) return false;
    @try {
        ((void (*)(id, SEL, id))objc_msgSend)(
            object, sel_registerName(name), value);
        return true;
    } @catch (__unused NSException *exception) {
        return false;
    }
}

#if CND_PULSAR_CONNECTIVITY_CANARY
static UIImage *CNDThemePNG(NSString *name)
{
    if (!name.length) return nil;
    NSString *path = [@CND_PULSAR_THEME_DIRECTORY
        stringByAppendingPathComponent:name];
    NSData *data = [NSData dataWithContentsOfFile:path options:0 error:nil];
    UIImage *image = data.length ? [UIImage imageWithData:data scale:3.0] : nil;
    return [image imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
}

static UIImage *CNDThemeCatalogImage(NSString *name)
{
    if (!name.length) return nil;
    NSString *path = [@CND_PULSAR_THEME_DIRECTORY
        stringByAppendingPathComponent:@"PulsarConnectivity.bundle"];
    NSBundle *bundle = [NSBundle bundleWithPath:path];
    UIImage *image = bundle ? [UIImage imageNamed:name inBundle:bundle
        compatibleWithTraitCollection:nil] : nil;
    return [image imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
}

static bool CNDApplyThemeGlyph(id controller, UIImage *image,
                               UIImage *__strong *original,
                               UIImage *__strong *originalSelected)
{
    if (!controller || !image || !original || !originalSelected) return false;
    if (!CNDMethodTypes(controller, "glyphImage", "@16@0:8") ||
        !CNDMethodTypes(controller, "selectedGlyphImage", "@16@0:8") ||
        !CNDMethodTypes(controller, "setGlyphImage:", "v24@0:8@16") ||
        !CNDMethodTypes(controller, "setSelectedGlyphImage:",
                        "v24@0:8@16")) return false;
    *original = CNDObjectGetter(controller, "glyphImage");
    *originalSelected = CNDObjectGetter(controller, "selectedGlyphImage");
    bool standard = CNDObjectSetter(controller, "setGlyphImage:", image);
    bool selected = CNDObjectSetter(
        controller, "setSelectedGlyphImage:", image);
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] THEME_GLYPH controller=%p/%s "
           "points=%.2fx%.2f scale=%.3f standard=%d selected=%d\n",
           (__bridge void *)controller, CNDClassName(controller),
           image.size.width, image.size.height, image.scale,
           standard, selected);
    return standard && selected;
}

static void CNDRestoreThemeGlyph(id controller, UIImage *original,
                                 UIImage *originalSelected)
{
    if (!controller) return;
    (void)CNDObjectSetter(controller, "setGlyphImage:", original);
    (void)CNDObjectSetter(
        controller, "setSelectedGlyphImage:", originalSelected);
}

static bool CNDApplyThemeSingleGlyph(id controller, UIImage *image,
                                     UIImage *__strong *original)
{
    if (!controller || !image || !original ||
        !CNDMethodTypes(controller, "setGlyphImage:", "v24@0:8@16")) {
        return false;
    }
    *original = CNDObjectGetter(controller, "glyphImage");
    bool applied = CNDObjectSetter(controller, "setGlyphImage:", image);
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] THEME_SINGLE_GLYPH "
           "controller=%p/%s original=%d points=%.2fx%.2f scale=%.3f "
           "applied=%d\n", (__bridge void *)controller,
           CNDClassName(controller), *original != nil, image.size.width,
           image.size.height, image.scale, applied);
    return applied;
}

static UIImageView *CNDFirstImageView(UIView *view)
{
    if (![view isKindOfClass:UIView.class]) return nil;
    if ([view isKindOfClass:UIImageView.class] &&
        ((UIImageView *)view).image) return (UIImageView *)view;
    for (UIView *subview in view.subviews) {
        UIImageView *match = CNDFirstImageView(subview);
        if (match) return match;
    }
    return nil;
}

static bool CNDApplyThemeViewImage(UIViewController *controller,
                                   UIImage *image,
                                   UIImageView *__strong *imageView,
                                   UIImage *__strong *original)
{
    if (![controller isKindOfClass:UIViewController.class] || !image ||
        !imageView || !original) return false;
    UIImageView *view = CNDFirstImageView(controller.view);
    if (!view) return false;
    *imageView = view;
    *original = view.image;
    view.image = image;
    [view setNeedsLayout];
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] THEME_VIEW controller=%p/%s "
           "imageView=%p points=%.2fx%.2f scale=%.3f\n",
           (__bridge void *)controller, CNDClassName(controller),
           (__bridge void *)view, image.size.width, image.size.height,
           image.scale);
    return true;
}

static void CNDRestoreThemeViewImage(UIImageView *view, UIImage *original)
{
    if (view) view.image = original;
}

static void CNDCollectImageViews(UIView *view, NSString *identifier,
                                 bool belowMatch,
                                 NSMutableArray<UIImageView *> *matches)
{
    if (![view isKindOfClass:UIView.class] || !identifier.length || !matches) {
        return;
    }
    bool matchesIdentifier = belowMatch ||
        [view.accessibilityIdentifier isEqualToString:identifier];
    if (matchesIdentifier && [view isKindOfClass:UIImageView.class] &&
        ((UIImageView *)view).image) {
        [matches addObject:(UIImageView *)view];
    }
    for (UIView *subview in view.subviews) {
        CNDCollectImageViews(
            subview, identifier, matchesIdentifier, matches);
    }
}

static bool CNDApplyThemeImagesForIdentifier(UIViewController *controller,
                                             NSString *identifier,
                                             UIImage *image)
{
    if (![controller isKindOfClass:UIViewController.class] ||
        !identifier.length || !image) return false;
    NSMutableArray<UIImageView *> *views = [NSMutableArray array];
    CNDCollectImageViews(controller.view, identifier, false, views);
    if (!views.count) return false;
    NSMutableArray<UIImage *> *originals = [NSMutableArray array];
    for (UIImageView *view in views) {
        [originals addObject:view.image];
        view.image = image;
        [view setNeedsLayout];
    }
    gAirplaneImageViews = views.copy;
    gOriginalAirplaneImages = originals.copy;
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] THEME_IDENTIFIER id=%s "
           "views=%lu points=%.2fx%.2f scale=%.3f\n",
           identifier.UTF8String ?: "-", (unsigned long)views.count,
           image.size.width, image.size.height, image.scale);
    return true;
}

static void CNDRestoreThemeIdentifierImages(void)
{
    NSUInteger count = MIN(
        gAirplaneImageViews.count, gOriginalAirplaneImages.count);
    for (NSUInteger index = 0; index < count; index++) {
        gAirplaneImageViews[index].image = gOriginalAirplaneImages[index];
    }
}

#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
static bool CNDClassMethodTypes(Class cls, const char *name,
                                const char *expected)
{
    if (!cls || !name || !expected) return false;
    Method method = class_getClassMethod(cls, sel_registerName(name));
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    return types && strcmp(types, expected) == 0;
}

static id CNDLoadMotionPackage(NSString *name)
{
    if (!name.length) return nil;
    NSString *relative = [NSString stringWithFormat:
        @"PulsarMotion.bundle/%@.ca", name];
    NSString *path = [@CND_PULSAR_THEME_DIRECTORY
        stringByAppendingPathComponent:relative];
    NSURL *url = [NSURL fileURLWithPath:path isDirectory:YES];
    Class cls = NSClassFromString(@"CAPackage");
    const char *selectorName =
        "packageWithContentsOfURL:type:options:error:";
    if (!CNDClassMethodTypes(cls, selectorName, "@48@0:8@16@24@32^@40")) {
        CNDLog("[CND_SYNTHETIC_CONNECTIVITY] MOTION_PACKAGE name=%s "
               "contract=0 loaded=0 path=%s\n", name.UTF8String ?: "-",
               path.UTF8String ?: "-");
        return nil;
    }
    NSError *__autoreleasing error = nil;
    id package = nil;
    @try {
        package = ((id (*)(id, SEL, id, id, id, NSError **))objc_msgSend)(
            cls, sel_registerName(selectorName), url,
            @"com.apple.coreanimation-bundle", nil, &error);
    } @catch (NSException *exception) {
        CNDLog("[CND_SYNTHETIC_CONNECTIVITY] MOTION_PACKAGE_EXCEPTION "
               "name=%s exception=%s reason=%s\n",
               name.UTF8String ?: "-", exception.name.UTF8String ?: "-",
               exception.reason.UTF8String ?: "-");
    }
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] MOTION_PACKAGE name=%s "
           "contract=1 loaded=%d path=%s error=%s\n",
           name.UTF8String ?: "-", package != nil, path.UTF8String ?: "-",
           error.description.UTF8String ?: "-");
    return package;
}

static id CNDCreateMotionDescription(NSString *name)
{
    if (!name.length) return nil;
    NSString *bundlePath = [@CND_PULSAR_THEME_DIRECTORY
        stringByAppendingPathComponent:@"PulsarMotion.bundle"];
    NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
    Class cls = NSClassFromString(@"CCUICAPackageDescription");
    SEL initializer = sel_registerName("initWithPackageName:inBundle:");
    Method method = cls ? class_getInstanceMethod(cls, initializer) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (!bundle || !types || strcmp(types, "@32@0:8@16@24") != 0) {
        CNDLog("[CND_SYNTHETIC_CONNECTIVITY] MOTION_DESCRIPTION name=%s "
               "contract=0 created=0 bundle=%d\n",
               name.UTF8String ?: "-", bundle != nil);
        return nil;
    }
    id description = nil;
    @try {
        description = ((id (*)(id, SEL, id, id))objc_msgSend)(
            [cls alloc], initializer, name, bundle);
    } @catch (NSException *exception) {
        CNDLog("[CND_SYNTHETIC_CONNECTIVITY] MOTION_DESCRIPTION_EXCEPTION "
               "name=%s exception=%s reason=%s\n",
               name.UTF8String ?: "-", exception.name.UTF8String ?: "-",
               exception.reason.UTF8String ?: "-");
    }
    NSURL *url = CNDObjectGetter(description, "packageURL");
    NSString *expected = [bundlePath stringByAppendingPathComponent:
        [name stringByAppendingPathExtension:@"ca"]];
    bool urlValid = [url isKindOfClass:NSURL.class] &&
        [url.path isEqualToString:expected];
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] MOTION_DESCRIPTION name=%s "
           "contract=1 created=%d urlValid=%d url=%s\n",
           name.UTF8String ?: "-", description != nil, urlValid,
           url.path.UTF8String ?: "-");
    return urlValid ? description : nil;
}

static bool CNDApplyMotionDescription(id controller, id description,
                                      id __strong *originalDescription,
                                      NSString *__strong *originalState)
{
    if (!controller || !description || !originalDescription ||
        !originalState ||
        !CNDMethodTypes(controller, "glyphPackageDescription", "@16@0:8") ||
        !CNDMethodTypes(controller, "glyphState", "@16@0:8") ||
        !CNDMethodTypes(controller, "setGlyphPackageDescription:",
                        "v24@0:8@16") ||
        !CNDMethodTypes(controller, "setGlyphState:", "v24@0:8@16")) {
        return false;
    }
    *originalDescription = CNDObjectGetter(
        controller, "glyphPackageDescription");
    *originalState = CNDObjectGetter(controller, "glyphState");
    bool descriptionSet = CNDObjectSetter(
        controller, "setGlyphPackageDescription:", description);
    bool stateSet = descriptionSet && CNDObjectSetter(
        controller, "setGlyphState:", @"poweroff");
    if (!descriptionSet || !stateSet) {
        (void)CNDObjectSetter(
            controller, "setGlyphPackageDescription:",
            *originalDescription);
        (void)CNDObjectSetter(
            controller, "setGlyphState:", *originalState);
    }
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] MOTION_APPLY controller=%p/%s "
           "description=%d state=%d originalDescription=%d "
           "originalState=%s\n", (__bridge void *)controller,
           CNDClassName(controller), descriptionSet, stateSet,
           *originalDescription != nil,
           (*originalState).UTF8String ?: "-");
    return descriptionSet && stateSet;
}

static void CNDRestoreMotionDescription(id controller,
                                        id originalDescription,
                                        NSString *originalState)
{
    if (!controller) return;
    (void)CNDObjectSetter(
        controller, "setGlyphPackageDescription:", originalDescription);
    (void)CNDObjectSetter(controller, "setGlyphState:", originalState);
}
#endif
#endif

static NSString *CNDSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class] || data.length == 0U ||
        data.length > UINT32_MAX) return @"-";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    (void)CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    char output[CC_SHA256_DIGEST_LENGTH * 2U + 1U] = {0};
    for (unsigned index = 0; index < CC_SHA256_DIGEST_LENGTH; index++) {
        (void)snprintf(output + index * 2U, 3U, "%02x", digest[index]);
    }
    return [NSString stringWithUTF8String:output];
}

static bool CNDWriteData(NSData *data, NSString *path)
{
    if (!data.length || !path.length) return false;
    int descriptor = open(path.fileSystemRepresentation,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0) return false;
    const uint8_t *bytes = data.bytes;
    NSUInteger remaining = data.length;
    bool ok = true;
    while (remaining > 0U) {
        ssize_t count = write(descriptor, bytes, remaining);
        if (count <= 0) {
            ok = false;
            break;
        }
        bytes += (NSUInteger)count;
        remaining -= (NSUInteger)count;
    }
    (void)fsync(descriptor);
    (void)close(descriptor);
    return ok && remaining == 0U;
}

static void CNDExportImage(NSString *kind, NSInteger state, UIImage *image)
{
    if (![image isKindOfClass:UIImage.class]) {
        CNDLog("[CND_SYNTHETIC_CONNECTIVITY] IMAGE kind=%s state=%ld "
               "result=nil\n", kind.UTF8String ?: "-", (long)state);
        return;
    }
    NSData *png = UIImagePNGRepresentation(image);
    NSString *digest = CNDSHA256(png);
    NSString *name = [NSString stringWithFormat:@"%@-%ld-%@.png",
                      kind, (long)state, digest];
    NSString *directory = @CND_SYNTHETIC_CONNECTIVITY_ASSET_DIRECTORY;
    NSString *path = [directory stringByAppendingPathComponent:name];
    CGImageRef cgImage = image.CGImage;
    bool wrote = CNDWriteData(png, path);
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] IMAGE kind=%s state=%ld "
           "points=%.2fx%.2f scale=%.3f pixels=%zux%zu pngBytes=%lu "
           "sha256=%s export=%s\n", kind.UTF8String ?: "-", (long)state,
           image.size.width, image.size.height, image.scale,
           cgImage ? CGImageGetWidth(cgImage) : 0U,
           cgImage ? CGImageGetHeight(cgImage) : 0U,
           (unsigned long)png.length, digest.UTF8String ?: "-",
           wrote ? path.UTF8String : "-");
}

static UIViewController *CNDFindVisibleController(
    UIViewController *controller, Class target)
{
    if (!controller || !target) return nil;
    if ([controller isKindOfClass:target] && controller.isViewLoaded &&
        controller.view.window && !controller.view.hidden &&
        controller.view.alpha > 0.01) return controller;
    UIViewController *presented = CNDFindVisibleController(
        controller.presentedViewController, target);
    if (presented) return presented;
    for (UIViewController *child in controller.childViewControllers) {
        UIViewController *match = CNDFindVisibleController(child, target);
        if (match) return match;
    }
    return nil;
}

static UIViewController *CNDVisibleConnectivityController(void)
{
    Class target = NSClassFromString(@"CCUIConnectivityModuleViewController");
    if (!target) return nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] ||
            scene.activationState != UISceneActivationStateForegroundActive) {
            continue;
        }
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (!window || window.hidden || window.alpha <= 0.01) continue;
            UIViewController *match = CNDFindVisibleController(
                window.rootViewController, target);
            if (match) return match;
        }
    }
    return nil;
}

static bool CNDRequiredRuntimeContract(id parent)
{
    Class cellularClass = NSClassFromString(
        @"CCUIConnectivityCellularDataViewController");
    bool valid = parent && cellularClass &&
        CNDMethodTypes(parent, "contentModuleContext", "@16@0:8") &&
        CNDMethodTypes(parent, "bluetoothModuleViewController", "@16@0:8") &&
        CNDMethodTypes(parent, "vpnModuleViewController", "@16@0:8") &&
        CNDMethodTypes(parent, "cellularDataButtonViewController", "@16@0:8") &&
        CNDMethodTypes(parent, "expandedCellularDataButtonViewController",
                       "@16@0:8") &&
        CNDMethodTypes(parent, "setCellularDataButtonViewController:",
                       "v24@0:8@16") &&
        CNDMethodTypes(parent, "setExpandedCellularDataButtonViewController:",
                       "v24@0:8@16");
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] CONTRACT parent=%p/%s "
           "cellularClass=%p valid=%d\n", (__bridge void *)parent,
           CNDClassName(parent), cellularClass, valid);
    return valid;
}

static int32_t CNDEnumerateBluetooth(id bluetooth)
{
    int32_t candidate = INT32_MIN;
    bool hasContract = bluetooth &&
        CNDMethodTypes(bluetooth, "_currentState", "i16@0:8") &&
        CNDMethodTypes(bluetooth, "_glyphImageForState:", "@20@0:8i16") &&
        CNDMethodTypes(bluetooth, "_updateWithState:", "v20@0:8i16");
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] BLUETOOTH_CONTRACT object=%p/%s "
           "valid=%d\n", (__bridge void *)bluetooth,
           CNDClassName(bluetooth), hasContract);
    if (!hasContract) return candidate;
    gBluetoothStateCaptured = CNDIntGetter(
        bluetooth, "_currentState", &gOriginalBluetoothState);
    for (int32_t state = 0; state <= 7; state++) {
        UIImage *image = CNDObjectForInt(
            bluetooth, "_glyphImageForState:", state);
        NSString *description = CNDObjectForInt(
            bluetooth, "_debugDescriptionForState:", state);
        NSString *subtitle = CNDObjectForInt(
            bluetooth, "_subtitleTextWithState:", state);
        bool enabledValid = false;
        bool inoperativeValid = false;
        BOOL enabled = CNDBoolForInt(
            bluetooth, "_enabledForState:", state, &enabledValid);
        BOOL inoperative = CNDBoolForInt(
            bluetooth, "_inoperativeForState:", state, &inoperativeValid);
        CNDLog("[CND_SYNTHETIC_CONNECTIVITY] BLUETOOTH_STATE state=%d "
               "description=%s subtitle=%s image=%d enabled=%d/%d "
               "inoperative=%d/%d original=%d\n", state,
               [description description].UTF8String ?: "-",
               [subtitle description].UTF8String ?: "-", image != nil,
               enabledValid, enabled, inoperativeValid, inoperative,
               gBluetoothStateCaptured && state == gOriginalBluetoothState);
        CNDExportImage(@"bluetooth", state, image);
        NSString *lower = [[description description] lowercaseString];
        if (image && enabledValid && enabled &&
            (!inoperativeValid || !inoperative)) {
            if (candidate == INT32_MIN) candidate = state;
            if ([lower containsString:@"connected"] ||
                [lower containsString:@"on"] ||
                [lower containsString:@"enabled"]) candidate = state;
        }
    }
    return candidate;
}

static void CNDEnumerateCellular(id cellular)
{
    bool valid = CNDMethodTypes(
        cellular, "_glyphImageForDisplayBars:", "@24@0:8@16") &&
        CNDMethodTypes(cellular, "_updateGlyphImageWithDisplayBars:",
                       "v24@0:8@16");
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] CELLULAR_CONTRACT object=%p/%s "
           "valid=%d\n", (__bridge void *)cellular,
           CNDClassName(cellular), valid);
    if (!valid) return;
    for (NSInteger bars = 0; bars <= 5; bars++) {
        NSNumber *value = @(bars);
        UIImage *image = CNDObjectForObject(
            cellular, "_glyphImageForDisplayBars:", value);
        CNDLog("[CND_SYNTHETIC_CONNECTIVITY] CELLULAR_BARS bars=%ld "
               "argumentClass=%s image=%d\n", (long)bars,
               CNDClassName(value), image != nil);
        CNDExportImage(@"cellular", bars, image);
    }
}

static id CNDCreateCellular(id context)
{
    Class cls = NSClassFromString(@"CCUIConnectivityCellularDataViewController");
    if (!cls) return nil;
    SEL initializer = sel_registerName("initWithGlyphImage:highlightColor:");
    Method method = class_getInstanceMethod(cls, initializer);
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (!types || strcmp(types, "@32@0:8@16@24") != 0) return nil;
    UIImage *seed = [UIImage systemImageNamed:@"cellularbars"];
    if (!seed) {
        seed = [UIImage systemImageNamed:
            @"antenna.radiowaves.left.and.right"];
    }
    @try {
        id controller = ((id (*)(id, SEL, id, id))objc_msgSend)(
            [cls alloc], initializer, seed, UIColor.systemGreenColor);
        if (controller &&
            !CNDObjectSetter(controller, "setContentModuleContext:", context)) {
            CNDLog("[CND_SYNTHETIC_CONNECTIVITY] CELLULAR_INIT_EXCEPTION "
                   "name=RuntimeContract reason=context-setter\n");
            return nil;
        }
        return controller;
    } @catch (NSException *exception) {
        CNDLog("[CND_SYNTHETIC_CONNECTIVITY] CELLULAR_INIT_EXCEPTION "
               "name=%s reason=%s\n", exception.name.UTF8String ?: "-",
               exception.reason.UTF8String ?: "-");
        return nil;
    }
}

static void CNDRestore(void)
{
    if (gRestored) return;
    gRestored = true;
    if (gPresentationActive) {
        id current = CNDObjectGetter(
            gParentController, "cellularDataButtonViewController");
        if (current == gSyntheticCellularController) {
            (void)CNDObjectSetter(
                gParentController, "setCellularDataButtonViewController:",
                gOriginalCellularController);
        }
        current = CNDObjectGetter(
            gParentController, "expandedCellularDataButtonViewController");
        if (current == gSyntheticCellularController) {
            (void)CNDObjectSetter(
                gParentController,
                "setExpandedCellularDataButtonViewController:",
                gOriginalExpandedCellularController);
        }
        [gSyntheticCellularController willMoveToParentViewController:nil];
        [gSyntheticMountedView removeFromSuperview];
        [gSyntheticCellularController removeFromParentViewController];
        gCoveredMountedView.hidden = gCoveredViewWasHidden;
    }
    if (gBluetoothStateCaptured && gBluetoothController) {
        (void)CNDVoidInt(
            gBluetoothController, "_updateWithState:",
            gOriginalBluetoothState);
    }
#if CND_PULSAR_CONNECTIVITY_CANARY
    if (gThemeApplied) {
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
        if (gWiFiMotionApplied) {
            CNDRestoreMotionDescription(
                gWiFiTemplateView, gOriginalWiFiPackageDescription,
                gOriginalWiFiGlyphState);
        }
        if (gBluetoothMotionApplied) {
            CNDRestoreMotionDescription(
                gBluetoothTemplateView,
                gOriginalBluetoothPackageDescription,
                gOriginalBluetoothGlyphState);
        }
#endif
        if (gWiFiThemeApplied) {
            CNDRestoreThemeGlyph(
                gWiFiController, gOriginalWiFiGlyph,
                gOriginalWiFiSelectedGlyph);
        }
        if (gBluetoothThemeApplied) {
            CNDRestoreThemeGlyph(
                gBluetoothController, gOriginalBluetoothGlyph,
                gOriginalBluetoothSelectedGlyph);
        }
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
        if (gWiFiTemplateThemeApplied) {
            CNDRestoreThemeGlyph(
                gWiFiTemplateView, gOriginalWiFiTemplateGlyph,
                gOriginalWiFiTemplateSelectedGlyph);
        }
        if (gBluetoothTemplateThemeApplied) {
            CNDRestoreThemeGlyph(
                gBluetoothTemplateView, gOriginalBluetoothTemplateGlyph,
                gOriginalBluetoothTemplateSelectedGlyph);
        }
#endif
        if (gAirplaneThemeApplied) {
            if (gOriginalAirplaneGlyph) {
                (void)CNDObjectSetter(
                    gAirplaneController, "setGlyphImage:",
                    gOriginalAirplaneGlyph);
            }
            CNDRestoreThemeIdentifierImages();
            CNDRestoreThemeViewImage(
                gVisibleAirplaneImageView, gOriginalVisibleAirplaneImage);
        }
        if (gCellularThemeApplied) {
            CNDRestoreThemeViewImage(
                gCellularImageView, gOriginalCellularImage);
        }
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
        if (gAirDropThemeApplied) {
            CNDRestoreThemeGlyph(
                gAirDropController, gOriginalAirDropGlyph,
                gOriginalAirDropSelectedGlyph);
        }
        if (gAirDropTemplateThemeApplied) {
            CNDRestoreThemeGlyph(
                gAirDropTemplateView, gOriginalAirDropTemplateGlyph,
                gOriginalAirDropTemplateSelectedGlyph);
        }
#endif
        (void)CNDVoidNoArgument(gAirplaneController, "_updateState");
    }
#endif
    if (gBluetoothObservationChanged && gBluetoothWasObserving) {
        (void)CNDVoidNoArgument(
            gBluetoothController, "startObservingStateChanges");
    }
    if (gWiFiObservationChanged && gWiFiWasObserving) {
        (void)CNDVoidNoArgument(
            gWiFiController, "startObservingStateChanges");
    }
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
    if (gAirDropObservationChanged && gAirDropWasObserving) {
        (void)CNDVoidNoArgument(
            gAirDropController, "startObservingStateChangesIfNecessary");
    }
#endif
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] RESTORED cellular=%d "
           "bluetoothState=%d bluetoothObservation=%d "
           "wifiObservation=%d theme=%d"
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
           " airDropObservation=%d wifiMotion=%d bluetoothMotion=%d"
#endif
           "\n",
           gPresentationActive, gBluetoothStateCaptured,
           gBluetoothObservationChanged, gWiFiObservationChanged,
           gThemeApplied
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
           , gAirDropObservationChanged, gWiFiMotionApplied,
           gBluetoothMotionApplied
#endif
           );
    gPresentationActive = false;
    gThemeApplied = false;
    gWiFiThemeApplied = false;
    gBluetoothThemeApplied = false;
    gAirplaneThemeApplied = false;
    gCellularThemeApplied = false;
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
    gAirDropThemeApplied = false;
    gWiFiTemplateThemeApplied = false;
    gBluetoothTemplateThemeApplied = false;
    gAirDropTemplateThemeApplied = false;
    gWiFiMotionApplied = false;
    gBluetoothMotionApplied = false;
#endif
    gSyntheticCellularController = nil;
    gCoveredController = nil;
    gSyntheticMountedView = nil;
    gCoveredMountedView = nil;
    gParentController = nil;
    gOriginalCellularController = nil;
    gOriginalExpandedCellularController = nil;
    gBluetoothController = nil;
    gWiFiController = nil;
    gAirplaneController = nil;
    gExpandedAirplaneController = nil;
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
    gAirDropController = nil;
    gWiFiTemplateView = nil;
    gBluetoothTemplateView = nil;
    gAirDropTemplateView = nil;
#endif
    gOriginalWiFiGlyph = nil;
    gOriginalWiFiSelectedGlyph = nil;
    gOriginalBluetoothGlyph = nil;
    gOriginalBluetoothSelectedGlyph = nil;
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
    gOriginalAirDropGlyph = nil;
    gOriginalAirDropSelectedGlyph = nil;
    gOriginalWiFiTemplateGlyph = nil;
    gOriginalWiFiTemplateSelectedGlyph = nil;
    gOriginalBluetoothTemplateGlyph = nil;
    gOriginalBluetoothTemplateSelectedGlyph = nil;
    gOriginalAirDropTemplateGlyph = nil;
    gOriginalAirDropTemplateSelectedGlyph = nil;
    gOriginalWiFiPackageDescription = nil;
    gOriginalBluetoothPackageDescription = nil;
    gOriginalWiFiGlyphState = nil;
    gOriginalBluetoothGlyphState = nil;
    gWiFiMotionDescription = nil;
    gBluetoothMotionDescription = nil;
    gWiFiMotionPackage = nil;
    gBluetoothMotionPackage = nil;
#endif
    gOriginalAirplaneGlyph = nil;
    gAirplaneImageViews = nil;
    gOriginalAirplaneImages = nil;
    gCellularImageView = nil;
    gVisibleAirplaneImageView = nil;
    gOriginalCellularImage = nil;
    gOriginalVisibleAirplaneImage = nil;
}

static void CNDComplete(const char *status)
{
    CNDRestore();
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] COMPLETE status=%s pid=%d "
           "noRadioSpoof=1 noSystemWrite=1\n", status ?: "-", getpid());
}

static bool CNDPresent(void)
{
    UIViewController *parent = CNDVisibleConnectivityController();
    if (!CNDRequiredRuntimeContract(parent)) return false;
    id context = CNDObjectGetter(parent, "contentModuleContext");
    id bluetooth = CNDObjectGetter(parent, "bluetoothModuleViewController");
#if CND_PULSAR_CONNECTIVITY_CANARY
    id wifi = CNDObjectGetter(parent, "wifiModuleViewController");
    id airplane = CNDObjectGetter(parent, "airplaneButtonViewController");
    id expandedAirplane = CNDObjectGetter(
        parent, "expandedAirplaneButtonViewController");
    if (expandedAirplane == airplane) expandedAirplane = nil;
    UIViewController *visibleAirplane = CNDFindVisibleController(
        parent, NSClassFromString(@"CCUIConnectivityAirplaneViewController"));
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
    id airDrop = CNDObjectGetter(parent, "airDropModuleViewController");
    id hotspot = CNDObjectGetter(parent, "hotspotButtonViewController");
    id satellite = CNDObjectGetter(parent, "satelliteModuleViewController");
    id wifiTemplate = CNDObjectGetter(
        wifi, "templateViewForExpandedConnectivityModule");
    id bluetoothTemplate = CNDObjectGetter(
        bluetooth, "templateViewForExpandedConnectivityModule");
    id airDropTemplate = CNDObjectGetter(
        airDrop, "templateViewForExpandedConnectivityModule");
#endif
#endif
    UIViewController *covered = CNDObjectGetter(
        parent, "vpnModuleViewController");
    UIView *coveredView = CNDObjectGetter(
        covered, "templateViewForExpandedConnectivityModule");
    if (!context || !bluetooth ||
#if CND_PULSAR_CONNECTIVITY_CANARY
        !wifi || !airplane || !visibleAirplane ||
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
        !airDrop || !wifiTemplate || !bluetoothTemplate ||
        !airDropTemplate ||
#endif
#endif
        ![covered isKindOfClass:UIViewController.class] ||
        ![coveredView isKindOfClass:UIView.class] || !coveredView.superview) {
        CNDLog("[CND_SYNTHETIC_CONNECTIVITY] WAIT parent=%p context=%p "
               "bluetooth=%p covered=%p mountedView=%p superview=%p\n",
               (__bridge void *)parent, (__bridge void *)context,
               (__bridge void *)bluetooth, (__bridge void *)covered,
               (__bridge void *)coveredView,
               (__bridge void *)coveredView.superview);
        return false;
    }
    id cellular = CNDCreateCellular(context);
    if (![cellular isKindOfClass:UIViewController.class]) {
        CNDLog("[CND_SYNTHETIC_CONNECTIVITY] REFUSED reason=cellular-init\n");
        CNDComplete("refused-cellular-init");
        return true;
    }
    gParentController = parent;
    gBluetoothController = bluetooth;
#if CND_PULSAR_CONNECTIVITY_CANARY
    gWiFiController = wifi;
    gAirplaneController = visibleAirplane;
    gExpandedAirplaneController = expandedAirplane;
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
    gAirDropController = airDrop;
    gWiFiTemplateView = wifiTemplate;
    gBluetoothTemplateView = bluetoothTemplate;
    gAirDropTemplateView = airDropTemplate;
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] EXTENDED_CONTROLLERS "
           "airDrop=%p/%s hotspot=%p/%s vpn=%p/%s satellite=%p/%s "
           "wifiTemplate=%p/%s bluetoothTemplate=%p/%s "
           "airDropTemplate=%p/%s\n",
           (__bridge void *)airDrop, CNDClassName(airDrop),
           (__bridge void *)hotspot, CNDClassName(hotspot),
           (__bridge void *)covered, CNDClassName(covered),
           (__bridge void *)satellite, CNDClassName(satellite),
           (__bridge void *)wifiTemplate, CNDClassName(wifiTemplate),
           (__bridge void *)bluetoothTemplate,
           CNDClassName(bluetoothTemplate),
           (__bridge void *)airDropTemplate,
           CNDClassName(airDropTemplate));
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] SOURCE_GAP vpn=1 satellite=1 "
           "reason=no-official-pulsar-v2-art\n");
#endif
#endif
    gSyntheticCellularController = cellular;
    gCoveredController = covered;
    gCoveredMountedView = coveredView;
    gOriginalCellularController = CNDObjectGetter(
        parent, "cellularDataButtonViewController");
    gOriginalExpandedCellularController = CNDObjectGetter(
        parent, "expandedCellularDataButtonViewController");
    gCoveredViewWasHidden = coveredView.hidden;

    int32_t bluetoothCandidate = CNDEnumerateBluetooth(bluetooth);
    CNDEnumerateCellular(cellular);

    bool observationValid = false;
    gBluetoothWasObserving = CNDBoolNoArgument(
        bluetooth, "isObservingStateChanges", &observationValid);
    if (observationValid && gBluetoothWasObserving) {
        gBluetoothObservationChanged = CNDVoidNoArgument(
            bluetooth, "stopObservingStateChanges");
    }
#if CND_PULSAR_CONNECTIVITY_CANARY
    bool wifiObservationValid = false;
    gWiFiWasObserving = CNDBoolNoArgument(
        wifi, "isObservingStateChanges", &wifiObservationValid);
    if (wifiObservationValid && gWiFiWasObserving) {
        gWiFiObservationChanged = CNDVoidNoArgument(
            wifi, "stopObservingStateChanges");
    }
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
    bool airDropObservationValid = false;
    gAirDropWasObserving = CNDBoolNoArgument(
        airDrop, "isObservingStateChanges", &airDropObservationValid);
    if (airDropObservationValid && gAirDropWasObserving) {
        gAirDropObservationChanged = CNDVoidNoArgument(
            airDrop, "stopObservingStateChangesIfNecessary");
    }
#endif
#endif
    if (bluetoothCandidate != INT32_MIN) {
        (void)CNDVoidInt(
            bluetooth, "_updateWithState:", bluetoothCandidate);
    }

    (void)CNDVoidNoArgument(cellular, "stopObservingStateChanges");
    UIViewController *cellularController = cellular;
    UIView *cellularView = cellularController.view;
    if (![cellularView isKindOfClass:UIView.class]) {
        CNDLog("[CND_SYNTHETIC_CONNECTIVITY] REFUSED "
               "reason=cellular-view\n");
        CNDComplete("refused-cellular-view");
        return true;
    }
    gSyntheticMountedView = cellularView;
    (void)CNDVoidObject(
        cellular, "_updateGlyphImageWithDisplayBars:", @4);
    (void)CNDBoolSetter(cellular, "setSelected:", YES);
    (void)CNDBoolSetter(cellular, "setEnabled:", YES);

    [parent addChildViewController:cellularController];
    cellularView.translatesAutoresizingMaskIntoConstraints = YES;
    cellularView.autoresizingMask =
        UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    cellularView.frame = coveredView.frame;
    cellularView.hidden = NO;
    cellularView.alpha = 1.0;
    cellularView.userInteractionEnabled = NO;
    [coveredView.superview insertSubview:cellularView aboveSubview:coveredView];
    [cellularController didMoveToParentViewController:parent];
    coveredView.hidden = YES;
    bool standardSet = CNDObjectSetter(
        parent, "setCellularDataButtonViewController:", cellular);
    bool expandedSet = CNDObjectSetter(
        parent, "setExpandedCellularDataButtonViewController:", cellular);
    [cellularView setNeedsLayout];
    [cellularView layoutIfNeeded];
    gPresentationActive = true;
#if CND_PULSAR_CONNECTIVITY_CANARY
    UIImage *wifiImage = CNDThemePNG(@"wifi_white.png");
    UIImage *bluetoothImage = CNDThemePNG(@"bluetooth_white.png");
    UIImage *airplaneImage = CNDThemeCatalogImage(@"AirplaneGlyph");
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
    UIImage *cellularImage = CNDThemeCatalogImage(@"HotspotGlyph");
    UIImage *airDropImage = CNDThemeCatalogImage(@"AirDropGlyph");
#else
    UIImage *cellularImage = CNDThemeCatalogImage(@"CellularDataGlyph");
#endif
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] THEME_ASSETS wifi=%d "
           "bluetooth=%d airplane=%d cellular=%d"
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
           " airDrop=%d syntheticKind=hotspot"
#endif
           " directory=%s\n",
           wifiImage != nil, bluetoothImage != nil, airplaneImage != nil,
           cellularImage != nil,
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
           airDropImage != nil,
#endif
           CND_PULSAR_THEME_DIRECTORY);
    if (!wifiImage || !bluetoothImage || !airplaneImage || !cellularImage) {
        CNDComplete("refused-theme-assets");
        return true;
    }
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
    if (!airDropImage) {
        CNDComplete("refused-extended-theme-assets");
        return true;
    }
#endif
    UIImage *stockAirplane = [[UIImage systemImageNamed:@"airplane"]
        imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
    if (!CNDObjectGetter(visibleAirplane, "glyphImage")) {
        bool repaired = stockAirplane && CNDObjectSetter(
            visibleAirplane, "setGlyphImage:", stockAirplane);
        if (!repaired || !CNDObjectGetter(visibleAirplane, "glyphImage")) {
            CNDComplete("refused-airplane-repair");
            return true;
        }
    }
    (void)CNDVoidNoArgument(visibleAirplane, "_updateState");
    gWiFiThemeApplied = CNDApplyThemeGlyph(
        wifi, wifiImage, &gOriginalWiFiGlyph,
        &gOriginalWiFiSelectedGlyph);
    gBluetoothThemeApplied = CNDApplyThemeGlyph(
        bluetooth, bluetoothImage, &gOriginalBluetoothGlyph,
        &gOriginalBluetoothSelectedGlyph);
    bool airplaneValid = CNDApplyThemeSingleGlyph(
        visibleAirplane, airplaneImage, &gOriginalAirplaneGlyph);
    if (!airplaneValid) {
        airplaneValid = CNDApplyThemeViewImage(
            visibleAirplane, airplaneImage, &gVisibleAirplaneImageView,
            &gOriginalVisibleAirplaneImage);
    }
    if (!airplaneValid) {
        airplaneValid = CNDApplyThemeImagesForIdentifier(
            parent, @"com.apple.ControlCenter.Airplane", airplaneImage);
    }
    gAirplaneThemeApplied = airplaneValid;
    gCellularThemeApplied = CNDApplyThemeViewImage(
        cellular, cellularImage, &gCellularImageView,
        &gOriginalCellularImage);
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
    gAirDropThemeApplied = CNDApplyThemeGlyph(
        airDrop, airDropImage, &gOriginalAirDropGlyph,
        &gOriginalAirDropSelectedGlyph);
    gWiFiTemplateThemeApplied = CNDApplyThemeGlyph(
        wifiTemplate, wifiImage, &gOriginalWiFiTemplateGlyph,
        &gOriginalWiFiTemplateSelectedGlyph);
    gBluetoothTemplateThemeApplied = CNDApplyThemeGlyph(
        bluetoothTemplate, bluetoothImage,
        &gOriginalBluetoothTemplateGlyph,
        &gOriginalBluetoothTemplateSelectedGlyph);
    gAirDropTemplateThemeApplied = CNDApplyThemeGlyph(
        airDropTemplate, airDropImage, &gOriginalAirDropTemplateGlyph,
        &gOriginalAirDropTemplateSelectedGlyph);
    gWiFiMotionPackage = CNDLoadMotionPackage(@"WiFi");
    gBluetoothMotionPackage = CNDLoadMotionPackage(@"Bluetooth");
    gWiFiMotionDescription = CNDCreateMotionDescription(@"WiFi");
    gBluetoothMotionDescription = CNDCreateMotionDescription(@"Bluetooth");
    bool motionLoaded = gWiFiMotionPackage && gBluetoothMotionPackage &&
        gWiFiMotionDescription && gBluetoothMotionDescription;
    if (motionLoaded) {
        gWiFiMotionApplied = CNDApplyMotionDescription(
            wifiTemplate, gWiFiMotionDescription,
            &gOriginalWiFiPackageDescription, &gOriginalWiFiGlyphState);
        gBluetoothMotionApplied = CNDApplyMotionDescription(
            bluetoothTemplate, gBluetoothMotionDescription,
            &gOriginalBluetoothPackageDescription,
            &gOriginalBluetoothGlyphState);
    }
    bool motionPresented = gWiFiMotionApplied && gBluetoothMotionApplied;
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] MOTION_RESULT loaded=%d "
           "presented=%d wifi=%d bluetooth=%d state=poweroff\n",
           motionLoaded, motionPresented, gWiFiMotionApplied,
           gBluetoothMotionApplied);
#endif
    gThemeApplied = gWiFiThemeApplied || gBluetoothThemeApplied ||
        gAirplaneThemeApplied || gCellularThemeApplied
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
        || gAirDropThemeApplied || gWiFiMotionApplied ||
        gBluetoothMotionApplied || gWiFiTemplateThemeApplied ||
        gBluetoothTemplateThemeApplied || gAirDropTemplateThemeApplied
#endif
        ;
    bool themeValid = gWiFiThemeApplied && gBluetoothThemeApplied &&
        gAirplaneThemeApplied && gCellularThemeApplied
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
        && gAirDropThemeApplied && gWiFiTemplateThemeApplied &&
        gBluetoothTemplateThemeApplied && gAirDropTemplateThemeApplied
#endif
        ;
    if (!themeValid) {
        CNDComplete("refused-theme-contract");
        return true;
    }
#endif
    CNDLog("[CND_SYNTHETIC_CONNECTIVITY] VISIBLE_READY pid=%d "
           "parent=%p/%s cellular=%p/%s covered=%p/%s frame=%s "
           "bluetooth=%p/%s originalState=%d candidateState=%d "
           "standardSet=%d expandedSet=%d interaction=disabled "
           "themeApplied=%d"
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
           " extended=1 airdrop=%d syntheticKind=hotspot "
           "presentationHost=CCUIConnectivityCellularDataViewController "
           "motionLoaded=%d motionPresented=%d sourceGaps=2"
#endif
           " holdSeconds=%d\n", getpid(),
           (__bridge void *)parent,
           CNDClassName(parent), (__bridge void *)cellular,
           CNDClassName(cellular), (__bridge void *)covered,
           CNDClassName(covered), NSStringFromCGRect(cellularView.frame).UTF8String,
           (__bridge void *)bluetooth, CNDClassName(bluetooth),
           gOriginalBluetoothState, bluetoothCandidate, standardSet,
           expandedSet, gThemeApplied,
#if CND_PULSAR_EXTENDED_CONNECTIVITY_CANARY
           gAirDropThemeApplied, motionLoaded, motionPresented,
#endif
           CND_SYNTHETIC_CONNECTIVITY_HOLD_SECONDS);
    dispatch_after(dispatch_time(
        DISPATCH_TIME_NOW,
        (int64_t)CND_SYNTHETIC_CONNECTIVITY_HOLD_SECONDS * NSEC_PER_SEC),
        dispatch_get_main_queue(), ^{
            CNDComplete("success");
        });
    return true;
}

__attribute__((constructor))
static void CNDSyntheticConnectivityStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_SYNTHETIC_CONNECTIVITY_OUTPUT_TOKEN[0] && consume
            ? consume(CND_SYNTHETIC_CONNECTIVITY_OUTPUT_TOKEN) : -1;
        gReportFD = open(CND_SYNTHETIC_CONNECTIVITY_REPORT_PATH,
                         O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC,
                         0600);
        if (gReportFD < 0) return;
        bool identity = !strcmp(getprogname(), "SpringBoard") &&
            CND_SYNTHETIC_CONNECTIVITY_EXPECTED_PID > 1 &&
            getpid() == CND_SYNTHETIC_CONNECTIVITY_EXPECTED_PID;
        CNDLog("[CND_SYNTHETIC_CONNECTIVITY] START pid=%d expectedPid=%d "
               "process=%s token=%lld identity=%d mode=vm-ui-only "
               "noRadioSpoof=1 noSystemWrite=1\n", getpid(),
               CND_SYNTHETIC_CONNECTIVITY_EXPECTED_PID, getprogname(),
               (long long)token, identity);
        if (!identity) {
            CNDComplete("refused-identity");
            return;
        }
        (void)mkdir(CND_SYNTHETIC_CONNECTIVITY_ASSET_DIRECTORY, 0700);
        dispatch_async(dispatch_get_main_queue(), ^{
            __block unsigned attempt = 0U;
            __block dispatch_source_t timer = dispatch_source_create(
                DISPATCH_SOURCE_TYPE_TIMER, 0U, 0U,
                dispatch_get_main_queue());
            dispatch_source_set_timer(
                timer, DISPATCH_TIME_NOW, 250ULL * NSEC_PER_MSEC,
                25ULL * NSEC_PER_MSEC);
            dispatch_source_set_event_handler(timer, ^{
                attempt++;
                if (CNDPresent()) {
                    dispatch_source_cancel(timer);
                    timer = nil;
                } else if (attempt >= 80U) {
                    dispatch_source_cancel(timer);
                    timer = nil;
                    CNDComplete("refused-no-visible-connectivity-panel");
                }
            });
            dispatch_resume(timer);
        });
    }
}
