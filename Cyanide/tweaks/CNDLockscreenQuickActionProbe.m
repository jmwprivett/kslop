#import "CNDLockscreenQuickActionProbe.h"

#import "remote_objc.h"
#import "../TaskRop/RemoteCall.h"

#include <string.h>

enum {
    CNDQuickActionWindowCap = 32,
    CNDQuickActionControllerCap = 128,
    CNDQuickActionButtonCap = 4,
    CNDQuickActionCollectionCountSanityMax = 4096,
};

static NSString *CNDQuickActionHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%llx", (unsigned long long)value];
}

static NSString *CNDQuickActionClassName(uint64_t object)
{
    if (!r_is_objc_ptr(object)) return nil;
    uint64_t cls = r_dlsym_call(R_TIMEOUT, "object_getClass",
        object, 0, 0, 0, 0, 0, 0, 0);
    uint64_t name = r_is_objc_ptr(cls) ? r_dlsym_call(
        R_TIMEOUT, "class_getName", cls, 0, 0, 0, 0, 0, 0, 0) : 0;
    char buffer[192] = {0};
    if (!name || !r_read_cstring(name, buffer, sizeof(buffer))) return nil;
    return [NSString stringWithUTF8String:buffer];
}

static NSDictionary *CNDQuickActionObject(uint64_t object)
{
    if (!r_is_objc_ptr(object)) return @{ @"address": @"0x0" };
    return @{ @"address": CNDQuickActionHex(object),
              @"className": CNDQuickActionClassName(object) ?: @"unavailable" };
}

static uint64_t CNDQuickActionGetter(uint64_t object, const char *selector)
{
    return remote_call_current_success() && r_is_objc_ptr(object) &&
        r_responds_main(object, selector)
        ? r_msg2_main(object, selector, 0, 0, 0, 0) : 0;
}

static uint64_t CNDQuickActionArrayObject(uint64_t array, NSUInteger index)
{
    return remote_call_current_success() && r_is_objc_ptr(array) &&
        r_responds_main(array, "objectAtIndex:")
        ? r_msg2_main(array, "objectAtIndex:", index, 0, 0, 0) : 0;
}

static NSUInteger CNDQuickActionBoundedCount(uint64_t rawCount, NSUInteger cap,
                                             NSUInteger *invalidCollectionCount)
{
    if (rawCount > CNDQuickActionCollectionCountSanityMax) {
        (*invalidCollectionCount)++;
        return 0;
    }
    return (NSUInteger)MIN(rawCount, (uint64_t)cap);
}

static BOOL CNDQuickActionHasExactClass(uint64_t object, uint64_t cls)
{
    return remote_call_current_success() && r_is_objc_ptr(object) &&
        r_is_objc_ptr(cls) && r_dlsym_call(R_TIMEOUT, "object_getClass",
            object, 0, 0, 0, 0, 0, 0, 0) == cls;
}

static void CNDQuickActionEnqueueController(NSMutableArray<NSNumber *> *queue,
                                           NSMutableSet<NSNumber *> *seen,
                                           uint64_t controller)
{
    if (queue.count >= CNDQuickActionControllerCap ||
        !r_is_objc_ptr(controller) || [seen containsObject:@(controller)]) return;
    [seen addObject:@(controller)];
    [queue addObject:@(controller)];
}

typedef struct {
    uint64_t flashlightButton;
    uint64_t flashlightGlyph;
    uint64_t cameraButton;
    uint64_t cameraGlyph;
    NSUInteger matchedControllerCount;
    NSUInteger visitedControllerCount;
    NSUInteger invalidCollectionCount;
} CNDQuickActionTargets;

static CNDQuickActionTargets CNDQuickActionDiscoverTargets(void)
{
    CNDQuickActionTargets targets = {0};
    NSMutableArray<NSNumber *> *queue = [NSMutableArray array];
    NSMutableSet<NSNumber *> *seen = [NSMutableSet set];
    uint64_t controllerClass = r_class("CSQuickActionsViewController");
    uint64_t buttonClass = r_class("CSQuickActionsButton");
    uint64_t flashlightActionClass = r_class("CSFlashlightQuickAction");
    uint64_t cameraActionClass = r_class("CSCameraSystemQuickAction");
    uint64_t application = CNDQuickActionGetter(r_class("UIApplication"),
                                                "sharedApplication");
    uint64_t windows = CNDQuickActionGetter(application, "windows");
    uint64_t rawWindowCount = CNDQuickActionGetter(windows, "count");
    NSUInteger windowCount = CNDQuickActionBoundedCount(rawWindowCount,
        CNDQuickActionWindowCap, &targets.invalidCollectionCount);

    for (NSUInteger index = 0; index < windowCount &&
         remote_call_current_success(); index++) {
        uint64_t window = CNDQuickActionArrayObject(windows, index);
        CNDQuickActionEnqueueController(queue, seen,
            CNDQuickActionGetter(window, "rootViewController"));
    }

    for (NSUInteger cursor = 0; cursor < queue.count &&
         targets.visitedControllerCount < CNDQuickActionControllerCap &&
         remote_call_current_success(); cursor++) {
        uint64_t controller = queue[cursor].unsignedLongLongValue;
        targets.visitedControllerCount++;
        if (CNDQuickActionHasExactClass(controller, controllerClass)) {
            targets.matchedControllerCount++;
            uint64_t view = CNDQuickActionGetter(controller,
                                                  "quickActionsViewIfLoaded");
            uint64_t buttons = CNDQuickActionGetter(view, "buttons");
            uint64_t rawButtonCount = CNDQuickActionGetter(buttons, "count");
            NSUInteger buttonCount = CNDQuickActionBoundedCount(rawButtonCount,
                CNDQuickActionButtonCap, &targets.invalidCollectionCount);
            for (NSUInteger index = 0; index < buttonCount &&
                 remote_call_current_success(); index++) {
                uint64_t button = CNDQuickActionArrayObject(buttons, index);
                if (!CNDQuickActionHasExactClass(button, buttonClass)) continue;
                uint64_t action = CNDQuickActionGetter(button, "action");
                uint64_t glyph = r_ivar_value(button, "_glyphView");
                if (CNDQuickActionHasExactClass(action, flashlightActionClass)) {
                    targets.flashlightButton = button;
                    targets.flashlightGlyph = glyph;
                } else if (CNDQuickActionHasExactClass(action,
                                                       cameraActionClass)) {
                    targets.cameraButton = button;
                    targets.cameraGlyph = glyph;
                }
            }
        }

        if (targets.flashlightButton && targets.cameraButton) break;
        if (queue.count >= CNDQuickActionControllerCap) continue;
        CNDQuickActionEnqueueController(queue, seen,
            CNDQuickActionGetter(controller, "presentedViewController"));
        if (queue.count >= CNDQuickActionControllerCap) continue;
        uint64_t children = CNDQuickActionGetter(controller,
                                                 "childViewControllers");
        uint64_t rawChildCount = CNDQuickActionGetter(children, "count");
        NSUInteger childCount = CNDQuickActionBoundedCount(rawChildCount,
            CNDQuickActionControllerCap - queue.count,
            &targets.invalidCollectionCount);
        for (NSUInteger index = 0; index < childCount &&
             queue.count < CNDQuickActionControllerCap &&
             remote_call_current_success(); index++) {
            CNDQuickActionEnqueueController(queue, seen,
                CNDQuickActionArrayObject(children, index));
        }
    }
    return targets;
}

static uint64_t CNDQuickActionRetain(uint64_t object)
{
    if (!r_is_objc_ptr(object) || !remote_call_current_success()) return 0;
    uint64_t retained = r_msg2(object, "retain", 0, 0, 0, 0);
    return retained == object && remote_call_current_success() ? object : 0;
}

static void CNDQuickActionRelease(uint64_t object)
{
    if (r_is_objc_ptr(object) && remote_call_current_success())
        (void)r_msg2(object, "release", 0, 0, 0, 0);
}

static uint64_t CNDQuickActionRemoteTemplateImage(NSData *pngData)
{
    if (pngData.length == 0 || !remote_call_current_success()) return 0;
    uint64_t buffer = r_dlsym_call(R_TIMEOUT, "malloc", pngData.length,
        0, 0, 0, 0, 0, 0, 0);
    if (!buffer || !remote_write(buffer, pngData.bytes, pngData.length)) {
        if (buffer && remote_call_current_success())
            r_dlsym_call(R_TIMEOUT, "free", buffer, 0, 0, 0, 0, 0, 0, 0);
        return 0;
    }

    // NSData/UIImage creation does not touch the view hierarchy. Keep it on
    // the already-serialized RemoteCall thread; marshalling each of these
    // calls through a separate main-thread NSInvocation is needlessly slow.
    uint64_t dataClass = r_class("NSData");
    uint64_t dataAlloc = r_msg2(dataClass, "alloc", 0, 0, 0, 0);
    uint64_t remoteData = r_is_objc_ptr(dataAlloc)
        ? r_msg2(dataAlloc, "initWithBytes:length:", buffer,
                 pngData.length, 0, 0)
        : 0;
    if (remote_call_current_success())
        r_dlsym_call(R_TIMEOUT, "free", buffer, 0, 0, 0, 0, 0, 0, 0);
    if (!r_is_objc_ptr(remoteData) || !remote_call_current_success()) return 0;

    uint64_t imageClass = r_class("UIImage");
    uint64_t imageAlloc = r_msg2(imageClass, "alloc", 0, 0, 0, 0);
    // The source renditions are 90 px. A 3.0 image scale preserves Pulsar's
    // 30 pt logical size inside the 58 pt quick-action glyph container.
    double scale = 3.0;
    uint64_t image = r_is_objc_ptr(imageAlloc)
        ? r_msg2_raw(imageAlloc, "initWithData:scale:",
            &remoteData, sizeof(remoteData), &scale, sizeof(scale),
            NULL, 0, NULL, 0)
        : 0;
    CNDQuickActionRelease(remoteData);
    if (!r_is_objc_ptr(image) || !remote_call_current_success()) return 0;

    // Pulsar's source catalog marks these renditions as automatic template
    // images. Force template mode here because the decoded PNG no longer has
    // the CoreUI rendition metadata that originally carried that behavior.
    uint64_t templateImage = r_msg2(image, "imageWithRenderingMode:",
                                    2, 0, 0, 0);
    templateImage = CNDQuickActionRetain(templateImage);
    CNDQuickActionRelease(image);
    return templateImage;
}

static BOOL CNDQuickActionReadDoubleIvar(uint64_t object,
                                         const char *ivarName,
                                         double *value)
{
    if (!r_is_objc_ptr(object) || !ivarName || !value ||
        !remote_call_current_success()) return NO;
    uint64_t cls = r_dlsym_call(R_TIMEOUT, "object_getClass", object,
        0, 0, 0, 0, 0, 0, 0);
    uint64_t remoteName = r_alloc_str(ivarName);
    uint64_t ivar = r_is_objc_ptr(cls) && remoteName
        ? r_dlsym_call(R_TIMEOUT, "class_getInstanceVariable", cls,
            remoteName, 0, 0, 0, 0, 0, 0)
        : 0;
    if (remoteName) r_free(remoteName);
    uint64_t offset = ivar ? r_dlsym_call(R_TIMEOUT, "ivar_getOffset", ivar,
        0, 0, 0, 0, 0, 0, 0) : 0;
    double readValue = 0;
    BOOL read = ivar && remote_read(object + offset, &readValue,
                                    sizeof(readValue));
    if (read) *value = readValue;
    return read && remote_call_current_success();
}

static uint64_t CNDQuickActionInstanceIvar(uint64_t object,
                                           const char *ivarName)
{
    if (!r_is_objc_ptr(object) || !ivarName ||
        !remote_call_current_success()) return 0;
    uint64_t cls = r_dlsym_call(R_TIMEOUT, "object_getClass", object,
        0, 0, 0, 0, 0, 0, 0);
    uint64_t remoteName = r_alloc_str(ivarName);
    uint64_t ivar = r_is_objc_ptr(cls) && remoteName
        ? r_dlsym_call(R_TIMEOUT, "class_getInstanceVariable", cls,
            remoteName, 0, 0, 0, 0, 0, 0)
        : 0;
    if (remoteName) r_free(remoteName);
    return ivar;
}

static BOOL CNDQuickActionSetGlyphImages(uint64_t glyph,
                                         uint64_t image,
                                         uint64_t selectedImage)
{
    if (!r_is_objc_ptr(glyph) || !r_is_objc_ptr(image) ||
        !r_is_objc_ptr(selectedImage) || !remote_call_current_success())
        return NO;
    uint64_t imageIvar = CNDQuickActionInstanceIvar(glyph, "_image");
    uint64_t selectedImageIvar = CNDQuickActionInstanceIvar(
        glyph, "_selectedImage");
    if (!imageIvar || !selectedImageIvar || !remote_call_current_success())
        return NO;

    // CSQuickActionImageGlyphView subclasses UIImageView. KVC for "image"
    // therefore resolves to UIImageView's -setImage: and does not update the
    // subclass's separate _image backing ivar. Assign the two known strong
    // ivars explicitly, then ask the glyph to refresh once on the main thread.
    (void)r_dlsym_call(R_TIMEOUT, "object_setIvarWithStrongDefault",
        glyph, imageIvar, image, 0, 0, 0, 0, 0);
    if (remote_call_current_success()) {
        (void)r_dlsym_call(R_TIMEOUT, "object_setIvarWithStrongDefault",
            glyph, selectedImageIvar, selectedImage, 0, 0, 0, 0, 0);
    }
    BOOL ivarsVerified = remote_call_current_success() &&
        r_ivar_value(glyph, "_image") == image &&
        r_ivar_value(glyph, "_selectedImage") == selectedImage;
    if (ivarsVerified)
        (void)r_msg2_main(glyph, "_updateImageAppearance", 0, 0, 0, 0);
    return ivarsVerified && remote_call_current_success() &&
        r_ivar_value(glyph, "_image") == image &&
        r_ivar_value(glyph, "_selectedImage") == selectedImage;
}

static uint64_t CNDQuickActionCreateImageGlyph(uint64_t imageGlyphClass,
                                               uint64_t referenceGlyph)
{
    if (!r_is_objc_ptr(imageGlyphClass) || !r_is_objc_ptr(referenceGlyph) ||
        !remote_call_current_success()) return 0;
    double symbolScale = 1.0;
    (void)CNDQuickActionReadDoubleIvar(referenceGlyph, "_symbolScaleValue",
                                      &symbolScale);
    if (symbolScale <= 0.0 || symbolScale > 10.0) symbolScale = 1.0;

    struct { double x, y, width, height; } bounds = {0};
    BOOL boundsRead = r_msg2_main_struct_ret(referenceGlyph, "bounds", &bounds,
        sizeof(bounds), NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    double buttonDiameter = boundsRead ? MAX(bounds.width, bounds.height) : 58.0;
    if (buttonDiameter < 20.0 || buttonDiameter > 200.0) buttonDiameter = 58.0;

    uint64_t name = r_nsstr_retained("camera.fill");
    uint64_t allocated = r_msg2_main(imageGlyphClass, "alloc", 0, 0, 0, 0);
    uint64_t glyph = r_is_objc_ptr(name) && r_is_objc_ptr(allocated)
        ? r_msg2_main_raw(allocated,
            "initWithSystemImageName:selectedSystemImageName:symbolScaleValue:buttonDiameter:",
            &name, sizeof(name), &name, sizeof(name),
            &symbolScale, sizeof(symbolScale),
            &buttonDiameter, sizeof(buttonDiameter))
        : 0;
    CNDQuickActionRelease(name);
    return glyph;
}

static NSDictionary<NSString *, id> *CNDQuickActionApplyArtworkFast(
    NSData *cameraPNG, NSData *flashlightOffPNG, NSData *flashlightOnPNG)
{
    NSMutableDictionary *result = [@{
        @"schemaVersion": @1,
        @"mode": @"live-runtime-artwork",
        @"target": @"SpringBoard",
        @"success": @NO,
        @"rolledBack": @NO,
        @"transportHealthy": @(remote_call_current_success()),
    } mutableCopy];
    if (cameraPNG.length == 0 || flashlightOffPNG.length == 0 ||
        flashlightOnPNG.length == 0 || !remote_call_current_success()) {
        result[@"failureReason"] = @"One or more embedded artwork payloads are empty.";
        return result;
    }

    CNDQuickActionTargets targets = CNDQuickActionDiscoverTargets();
    result[@"matchedControllerCount"] = @(targets.matchedControllerCount);
    result[@"visitedControllerCount"] = @(targets.visitedControllerCount);
    result[@"invalidCollectionCount"] = @(targets.invalidCollectionCount);
    result[@"flashlightButton"] = CNDQuickActionHex(targets.flashlightButton);
    result[@"cameraButton"] = CNDQuickActionHex(targets.cameraButton);
    result[@"flashlightGlyphBefore"] = CNDQuickActionObject(targets.flashlightGlyph);
    result[@"cameraGlyphBefore"] = CNDQuickActionObject(targets.cameraGlyph);

    uint64_t imageGlyphClass = r_class("CSQuickActionImageGlyphView");
    uint64_t controlGlyphClass = r_class("CSQuickActionControlGlyphView");
    BOOL flashlightCompatible = targets.flashlightButton &&
        CNDQuickActionHasExactClass(targets.flashlightGlyph, imageGlyphClass);
    BOOL cameraIsImageGlyph = targets.cameraButton &&
        CNDQuickActionHasExactClass(targets.cameraGlyph, imageGlyphClass);
    BOOL cameraIsControlGlyph = targets.cameraButton &&
        CNDQuickActionHasExactClass(targets.cameraGlyph, controlGlyphClass);
    if (!flashlightCompatible || (!cameraIsImageGlyph && !cameraIsControlGlyph) ||
        targets.invalidCollectionCount != 0 || !remote_call_current_success()) {
        result[@"failureReason"] = @"The two known live button/glyph targets were not found in the expected classes.";
        result[@"transportHealthy"] = @(remote_call_current_success());
        return result;
    }

    uint64_t cameraImage = CNDQuickActionRemoteTemplateImage(cameraPNG);
    uint64_t flashlightOffImage = remote_call_current_success()
        ? CNDQuickActionRemoteTemplateImage(flashlightOffPNG) : 0;
    uint64_t flashlightOnImage = remote_call_current_success()
        ? CNDQuickActionRemoteTemplateImage(flashlightOnPNG) : 0;
    if (!r_is_objc_ptr(cameraImage) || !r_is_objc_ptr(flashlightOffImage) ||
        !r_is_objc_ptr(flashlightOnImage) || !remote_call_current_success()) {
        result[@"failureReason"] = @"SpringBoard could not decode all three Pulsar PNG renditions.";
        CNDQuickActionRelease(flashlightOnImage);
        CNDQuickActionRelease(flashlightOffImage);
        CNDQuickActionRelease(cameraImage);
        result[@"transportHealthy"] = @(remote_call_current_success());
        return result;
    }

    uint64_t oldFlashlightImage = CNDQuickActionRetain(
        r_ivar_value(targets.flashlightGlyph, "_image"));
    uint64_t oldFlashlightSelectedImage = CNDQuickActionRetain(
        r_ivar_value(targets.flashlightGlyph, "_selectedImage"));
    uint64_t oldCameraImage = cameraIsImageGlyph ? CNDQuickActionRetain(
        r_ivar_value(targets.cameraGlyph, "_image")) : 0;
    uint64_t oldCameraSelectedImage = cameraIsImageGlyph ? CNDQuickActionRetain(
        r_ivar_value(targets.cameraGlyph, "_selectedImage")) : 0;
    uint64_t oldCameraGlyph = cameraIsControlGlyph
        ? CNDQuickActionRetain(targets.cameraGlyph) : 0;
    BOOL backupsReady = oldFlashlightImage && oldFlashlightSelectedImage &&
        (cameraIsControlGlyph ? oldCameraGlyph != 0
                             : (oldCameraImage && oldCameraSelectedImage));

    uint64_t cameraGlyph = cameraIsImageGlyph ? targets.cameraGlyph
        : CNDQuickActionCreateImageGlyph(imageGlyphClass, targets.cameraGlyph);
    result[@"backupsReady"] = @(backupsReady);
    result[@"cameraGlyphCreated"] = @(r_is_objc_ptr(cameraGlyph));
    BOOL cameraPrepared = backupsReady && r_is_objc_ptr(cameraGlyph) &&
        CNDQuickActionSetGlyphImages(cameraGlyph, cameraImage, cameraImage);
    result[@"cameraPrepared"] = @(cameraPrepared);
    BOOL flashlightApplied = cameraPrepared &&
        CNDQuickActionSetGlyphImages(targets.flashlightGlyph,
                                     flashlightOffImage,
                                     flashlightOnImage);
    result[@"flashlightApplied"] = @(flashlightApplied);
    BOOL cameraAttached = flashlightApplied;
    if (cameraAttached && cameraIsControlGlyph) {
        (void)r_msg2_main(targets.cameraButton, "setGlyphView:", cameraGlyph,
                          0, 0, 0);
        cameraAttached = remote_call_current_success() &&
            r_ivar_value(targets.cameraButton, "_glyphView") == cameraGlyph;
    }
    BOOL success = cameraAttached && remote_call_current_success() &&
        r_ivar_value(targets.flashlightGlyph, "_image") == flashlightOffImage &&
        r_ivar_value(targets.flashlightGlyph, "_selectedImage") == flashlightOnImage &&
        r_ivar_value(cameraGlyph, "_image") == cameraImage &&
        r_ivar_value(cameraGlyph, "_selectedImage") == cameraImage;

    BOOL rolledBack = NO;
    if (!success && backupsReady && remote_call_current_success()) {
        BOOL flashRestored = CNDQuickActionSetGlyphImages(
            targets.flashlightGlyph, oldFlashlightImage,
            oldFlashlightSelectedImage);
        BOOL cameraRestored = NO;
        if (cameraIsControlGlyph) {
            (void)r_msg2_main(targets.cameraButton, "setGlyphView:",
                              oldCameraGlyph, 0, 0, 0);
            cameraRestored = remote_call_current_success() &&
                r_ivar_value(targets.cameraButton, "_glyphView") == oldCameraGlyph;
        } else {
            cameraRestored = CNDQuickActionSetGlyphImages(
                targets.cameraGlyph, oldCameraImage, oldCameraSelectedImage);
        }
        rolledBack = flashRestored && cameraRestored &&
            remote_call_current_success();
    }

    uint64_t cameraGlyphAfter = remote_call_current_success()
        ? r_ivar_value(targets.cameraButton, "_glyphView") : 0;
    result[@"success"] = @(success);
    result[@"rolledBack"] = @(rolledBack);
    result[@"cameraGlyphAfter"] = CNDQuickActionObject(cameraGlyphAfter);
    result[@"cameraGlyphReplaced"] = @(success && cameraIsControlGlyph);
    result[@"flashlightImageVerified"] = @(success);
    result[@"cameraImageVerified"] = @(success);
    if (!success) {
        NSString *failureStage = !backupsReady ? @"retain-originals"
            : !r_is_objc_ptr(cameraGlyph) ? @"create-camera-image-glyph"
            : !cameraPrepared ? @"assign-camera-images"
            : !flashlightApplied ? @"assign-flashlight-images"
            : !cameraAttached ? @"attach-camera-glyph"
            : @"final-readback";
        result[@"failureStage"] = failureStage;
        result[@"failureReason"] = rolledBack
            ? @"The live mutation did not verify; the original glyph objects were restored."
            : @"The live mutation did not verify cleanly.";
    }

    CNDQuickActionRelease(oldCameraGlyph);
    CNDQuickActionRelease(oldCameraSelectedImage);
    CNDQuickActionRelease(oldCameraImage);
    CNDQuickActionRelease(oldFlashlightSelectedImage);
    CNDQuickActionRelease(oldFlashlightImage);
    if (cameraIsControlGlyph) CNDQuickActionRelease(cameraGlyph);
    CNDQuickActionRelease(flashlightOnImage);
    CNDQuickActionRelease(flashlightOffImage);
    CNDQuickActionRelease(cameraImage);
    result[@"transportHealthy"] = @(remote_call_current_success());
    return result;
}

NSDictionary<NSString *, id> *CNDLockscreenQuickActionApplyArtwork(
    NSData *cameraPNG, NSData *flashlightOffPNG, NSData *flashlightOnPNG)
{
    NSTimeInterval startedAt = NSProcessInfo.processInfo.systemUptime;
    uint32_t previousSettleUS = r_settle_us(0);
    NSDictionary *raw = nil;
    @try {
        raw = CNDQuickActionApplyArtworkFast(
            cameraPNG, flashlightOffPNG, flashlightOnPNG);
    } @finally {
        (void)r_settle_us(previousSettleUS);
    }
    NSMutableDictionary *result = [raw mutableCopy] ?: [NSMutableDictionary dictionary];
    result[@"elapsedSeconds"] = @(
        NSProcessInfo.processInfo.systemUptime - startedAt);
    result[@"remoteSettleUS"] = @0;
    result[@"artworkPointSize"] = @30;
    return result;
}

static uint64_t CNDQuickActionCreateNativeGlyph(uint64_t button)
{
    if (!r_is_objc_ptr(button) || !remote_call_current_success() ||
        !r_responds_main(button, "_createButtonGlyphForAction:")) return 0;
    uint64_t action = CNDQuickActionGetter(button, "action");
    return r_is_objc_ptr(action)
        ? r_msg2_main_retained_object(button,
            "_createButtonGlyphForAction:", action, 0, 0, 0)
        : 0;
}

static NSDictionary<NSString *, id> *CNDQuickActionRestoreStockFast(void)
{
    NSMutableDictionary *result = [@{
        @"schemaVersion": @1,
        @"mode": @"live-runtime-restore",
        @"target": @"SpringBoard",
        @"success": @NO,
        @"rolledBack": @NO,
        @"transportHealthy": @(remote_call_current_success()),
    } mutableCopy];
    CNDQuickActionTargets targets = CNDQuickActionDiscoverTargets();
    result[@"matchedControllerCount"] = @(targets.matchedControllerCount);
    result[@"visitedControllerCount"] = @(targets.visitedControllerCount);
    result[@"invalidCollectionCount"] = @(targets.invalidCollectionCount);
    result[@"flashlightGlyphBefore"] = CNDQuickActionObject(targets.flashlightGlyph);
    result[@"cameraGlyphBefore"] = CNDQuickActionObject(targets.cameraGlyph);
    if (!targets.flashlightButton || !targets.cameraButton ||
        targets.invalidCollectionCount != 0 || !remote_call_current_success()) {
        result[@"failureStage"] = @"discover-buttons";
        result[@"failureReason"] =
            @"The two known live quick-action buttons were not found.";
        return result;
    }

    uint64_t oldFlashlightGlyph = CNDQuickActionRetain(targets.flashlightGlyph);
    uint64_t oldCameraGlyph = CNDQuickActionRetain(targets.cameraGlyph);
    uint64_t stockFlashlightGlyph = CNDQuickActionCreateNativeGlyph(
        targets.flashlightButton);
    uint64_t stockCameraGlyph = remote_call_current_success()
        ? CNDQuickActionCreateNativeGlyph(targets.cameraButton) : 0;
    result[@"stockFlashlightGlyphCreated"] = @(r_is_objc_ptr(stockFlashlightGlyph));
    result[@"stockCameraGlyphCreated"] = @(r_is_objc_ptr(stockCameraGlyph));

    uint64_t imageGlyphClass = r_class("CSQuickActionImageGlyphView");
    uint64_t controlGlyphClass = r_class("CSQuickActionControlGlyphView");
    BOOL factoryVerified = r_is_objc_ptr(oldFlashlightGlyph) &&
        r_is_objc_ptr(oldCameraGlyph) &&
        CNDQuickActionHasExactClass(stockFlashlightGlyph, imageGlyphClass) &&
        CNDQuickActionHasExactClass(stockCameraGlyph, controlGlyphClass) &&
        remote_call_current_success();
    BOOL flashlightAttached = NO;
    BOOL cameraAttached = NO;
    if (factoryVerified) {
        (void)r_msg2_main(targets.flashlightButton, "setGlyphView:",
                          stockFlashlightGlyph, 0, 0, 0);
        flashlightAttached = remote_call_current_success() &&
            r_ivar_value(targets.flashlightButton, "_glyphView") ==
                stockFlashlightGlyph;
    }
    if (flashlightAttached) {
        (void)r_msg2_main(targets.cameraButton, "setGlyphView:",
                          stockCameraGlyph, 0, 0, 0);
        cameraAttached = remote_call_current_success() &&
            r_ivar_value(targets.cameraButton, "_glyphView") == stockCameraGlyph;
    }
    BOOL success = factoryVerified && flashlightAttached && cameraAttached &&
        remote_call_current_success();

    BOOL rolledBack = NO;
    if (!success && factoryVerified && remote_call_current_success()) {
        (void)r_msg2_main(targets.flashlightButton, "setGlyphView:",
                          oldFlashlightGlyph, 0, 0, 0);
        BOOL flashlightRestored = remote_call_current_success() &&
            r_ivar_value(targets.flashlightButton, "_glyphView") ==
                oldFlashlightGlyph;
        if (remote_call_current_success()) {
            (void)r_msg2_main(targets.cameraButton, "setGlyphView:",
                              oldCameraGlyph, 0, 0, 0);
        }
        BOOL cameraRestored = remote_call_current_success() &&
            r_ivar_value(targets.cameraButton, "_glyphView") == oldCameraGlyph;
        rolledBack = flashlightRestored && cameraRestored &&
            remote_call_current_success();
    }

    uint64_t flashlightAfter = remote_call_current_success()
        ? r_ivar_value(targets.flashlightButton, "_glyphView") : 0;
    uint64_t cameraAfter = remote_call_current_success()
        ? r_ivar_value(targets.cameraButton, "_glyphView") : 0;
    result[@"success"] = @(success);
    result[@"rolledBack"] = @(rolledBack);
    result[@"flashlightGlyphAfter"] = CNDQuickActionObject(flashlightAfter);
    result[@"cameraGlyphAfter"] = CNDQuickActionObject(cameraAfter);
    if (!success) {
        result[@"failureStage"] = !factoryVerified ? @"native-glyph-factory"
            : !flashlightAttached ? @"attach-flashlight-glyph"
            : @"attach-camera-glyph";
        result[@"failureReason"] = rolledBack
            ? @"The stock glyph restore did not verify; the previous live glyphs were restored."
            : @"The stock glyph restore did not verify cleanly.";
    }

    CNDQuickActionRelease(stockCameraGlyph);
    CNDQuickActionRelease(stockFlashlightGlyph);
    CNDQuickActionRelease(oldCameraGlyph);
    CNDQuickActionRelease(oldFlashlightGlyph);
    result[@"transportHealthy"] = @(remote_call_current_success());
    return result;
}

NSDictionary<NSString *, id> *CNDLockscreenQuickActionRestoreStock(void)
{
    NSTimeInterval startedAt = NSProcessInfo.processInfo.systemUptime;
    uint32_t previousSettleUS = r_settle_us(0);
    NSDictionary *raw = nil;
    @try {
        raw = CNDQuickActionRestoreStockFast();
    } @finally {
        (void)r_settle_us(previousSettleUS);
    }
    NSMutableDictionary *result = [raw mutableCopy] ?: [NSMutableDictionary dictionary];
    result[@"elapsedSeconds"] = @(
        NSProcessInfo.processInfo.systemUptime - startedAt);
    result[@"remoteSettleUS"] = @0;
    return result;
}
