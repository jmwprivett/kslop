#import "CNDCCThemingCanary.h"

#import "CNDCCThemingProbe.h"
#import "remote_objc.h"
#import "../TaskRop/RemoteCall.h"

#include <string.h>

static NSString *CNDCCCanaryAddress(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%llx", (unsigned long long)value];
}

static NSString *CNDCCCanaryClassName(uint64_t object)
{
    if (!r_is_objc_ptr(object)) return nil;
    uint64_t cls = r_dlsym_call(R_TIMEOUT, "object_getClass", object,
        0, 0, 0, 0, 0, 0, 0);
    uint64_t name = r_is_objc_ptr(cls) ? r_dlsym_call(
        R_TIMEOUT, "class_getName", cls, 0, 0, 0, 0, 0, 0, 0) : 0;
    char buffer[192] = {0};
    if (!name || !r_read_cstring(name, buffer, sizeof(buffer))) return nil;
    return [NSString stringWithUTF8String:buffer];
}

static BOOL CNDCCCanaryMethodHasTypes(uint64_t object,
                                      const char *selectorName,
                                      const char *expectedTypes)
{
    if (!r_is_objc_ptr(object) || !selectorName || !expectedTypes ||
        !remote_call_current_success()) return NO;
    uint64_t cls = r_dlsym_call(R_TIMEOUT, "object_getClass", object,
        0, 0, 0, 0, 0, 0, 0);
    uint64_t selector = r_sel(selectorName);
    uint64_t method = r_is_objc_ptr(cls) && selector
        ? r_dlsym_call(R_TIMEOUT, "class_getInstanceMethod", cls, selector,
            0, 0, 0, 0, 0, 0)
        : 0;
    uint64_t types = method ? r_dlsym_call(
        R_TIMEOUT, "method_getTypeEncoding", method,
        0, 0, 0, 0, 0, 0, 0) : 0;
    char buffer[128] = {0};
    return types && r_read_cstring(types, buffer, sizeof(buffer)) &&
        strcmp(buffer, expectedTypes) == 0;
}

static uint64_t CNDCCCanaryRetain(uint64_t object)
{
    if (!r_is_objc_ptr(object) || !remote_call_current_success()) return 0;
    uint64_t retained = r_msg2(object, "retain", 0, 0, 0, 0);
    return retained == object && remote_call_current_success() ? object : 0;
}

static void CNDCCCanaryRelease(uint64_t object)
{
    if (r_is_objc_ptr(object) && remote_call_current_success())
        (void)r_msg2(object, "release", 0, 0, 0, 0);
}

static uint64_t CNDCCCanaryRemoteTemplateImage(NSData *pngData)
{
    if (pngData.length == 0 || !remote_call_current_success()) return 0;
    uint64_t buffer = r_dlsym_call(R_TIMEOUT, "malloc", pngData.length,
        0, 0, 0, 0, 0, 0, 0);
    if (!buffer || !remote_write(buffer, pngData.bytes, pngData.length)) {
        if (buffer && remote_call_current_success())
            (void)r_dlsym_call(R_TIMEOUT, "free", buffer,
                0, 0, 0, 0, 0, 0, 0);
        return 0;
    }

    uint64_t dataClass = r_class("NSData");
    uint64_t dataAlloc = r_msg2(dataClass, "alloc", 0, 0, 0, 0);
    uint64_t remoteData = r_is_objc_ptr(dataAlloc)
        ? r_msg2(dataAlloc, "initWithBytes:length:", buffer,
                 pngData.length, 0, 0)
        : 0;
    if (remote_call_current_success()) {
        (void)r_dlsym_call(R_TIMEOUT, "free", buffer,
            0, 0, 0, 0, 0, 0, 0);
    }
    if (!r_is_objc_ptr(remoteData) || !remote_call_current_success()) return 0;

    uint64_t imageClass = r_class("UIImage");
    uint64_t imageAlloc = r_msg2(imageClass, "alloc", 0, 0, 0, 0);
    double scale = 3.0;
    uint64_t image = r_is_objc_ptr(imageAlloc)
        ? r_msg2_raw(imageAlloc, "initWithData:scale:",
            &remoteData, sizeof(remoteData), &scale, sizeof(scale),
            NULL, 0, NULL, 0)
        : 0;
    CNDCCCanaryRelease(remoteData);
    if (!r_is_objc_ptr(image) || !remote_call_current_success()) return 0;

    uint64_t templateImage = r_msg2(image, "imageWithRenderingMode:",
                                    2, 0, 0, 0);
    templateImage = CNDCCCanaryRetain(templateImage);
    CNDCCCanaryRelease(image);
    return templateImage;
}

static uint64_t CNDCCCanaryGetter(uint64_t object, const char *selector)
{
    return r_is_objc_ptr(object) && remote_call_current_success() &&
        r_responds_main(object, selector)
        ? r_msg2_main(object, selector, 0, 0, 0, 0) : 0;
}

static BOOL CNDCCCanarySetAndVerify(uint64_t target,
                                    const char *setter,
                                    const char *getter,
                                    uint64_t value)
{
    if (!r_is_objc_ptr(target) || !r_is_objc_ptr(value) ||
        !remote_call_current_success()) return NO;
    (void)r_msg2_main(target, setter, value, 0, 0, 0);
    return remote_call_current_success() &&
        CNDCCCanaryGetter(target, getter) == value;
}

NSDictionary<NSString *, id> *CNDCCThemingRunFlashlightApplyRestoreCanary(
    NSData *offPNG,
    NSData *onPNG,
    NSTimeInterval holdSeconds)
{
    int targetPIDAtEntry = remote_call_current_pid();
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schemaVersion": @1,
        @"mode": @"physical-flashlight-apply-readback-restore-canary",
        @"target": @"SpringBoard",
        @"targetKind": @"flashlight",
        @"targetPID": @(targetPIDAtEntry),
        @"success": @NO,
        @"applyVerified": @NO,
        @"restoreVerified": @NO,
        @"rollbackAttempted": @NO,
        @"controlActions": @0,
        @"radioWrites": @0,
        @"targetFileWrites": @0,
        @"glyphPresentationWrites": @0,
    } mutableCopy];
    if (offPNG.length == 0 || onPNG.length == 0 ||
        holdSeconds < 0 || holdSeconds > 10 ||
        !remote_call_current_success()) {
        report[@"failureReason"] =
            @"Embedded artwork, hold duration, or RemoteCall transport was invalid.";
        return report;
    }

    uint32_t previousSettle = r_settle_us(0);
    uint64_t target = 0;
    uint64_t retainedTarget = 0;
    uint64_t originalImage = 0;
    uint64_t originalSelectedImage = 0;
    uint64_t offImage = 0;
    uint64_t onImage = 0;
    BOOL applyVerified = NO;
    BOOL restoreVerified = NO;
    BOOL rollbackAttempted = NO;
    NSUInteger writeCount = 0;
    @try {
        do {
        NSDictionary *metadata = nil;
        target = CNDCCThemingResolveLiveTemplate(@"flashlight", &metadata);
        report[@"resolvedTarget"] = metadata ?: @{};
        report[@"targetAddress"] = CNDCCCanaryAddress(target);
        report[@"targetClass"] = CNDCCCanaryClassName(target) ?: @"unavailable";
        BOOL contractsValid =
            CNDCCCanaryMethodHasTypes(target, "glyphImage", "@16@0:8") &&
            CNDCCCanaryMethodHasTypes(target, "selectedGlyphImage", "@16@0:8") &&
            CNDCCCanaryMethodHasTypes(target, "setGlyphImage:", "v24@0:8@16") &&
            CNDCCCanaryMethodHasTypes(target, "setSelectedGlyphImage:", "v24@0:8@16");
        report[@"contractsValid"] = @(contractsValid);
        if (!target || !contractsValid) {
            report[@"failureStage"] = @"stable-target-resolution";
            report[@"failureReason"] =
                @"A live Flashlight template with the exact glyph ABI was not resolved.";
            break;
        }

        retainedTarget = CNDCCCanaryRetain(target);
        originalImage = CNDCCCanaryRetain(
            CNDCCCanaryGetter(target, "glyphImage"));
        originalSelectedImage = CNDCCCanaryRetain(
            CNDCCCanaryGetter(target, "selectedGlyphImage"));
        report[@"originalImage"] = CNDCCCanaryAddress(originalImage);
        report[@"originalSelectedImage"] =
            CNDCCCanaryAddress(originalSelectedImage);
        if (retainedTarget != target || !originalImage ||
            !originalSelectedImage) {
            report[@"failureStage"] = @"retain-originals";
            report[@"failureReason"] =
                @"The live target or its two original image objects could not be retained.";
            break;
        }

        offImage = CNDCCCanaryRemoteTemplateImage(offPNG);
        onImage = remote_call_current_success()
            ? CNDCCCanaryRemoteTemplateImage(onPNG) : 0;
        report[@"offImage"] = CNDCCCanaryAddress(offImage);
        report[@"onImage"] = CNDCCCanaryAddress(onImage);
        if (!offImage || !onImage || !remote_call_current_success()) {
            report[@"failureStage"] = @"decode-artwork";
            report[@"failureReason"] =
                @"SpringBoard could not decode both embedded Pulsar images.";
            break;
        }

        writeCount++;
        BOOL standardApplied = CNDCCCanarySetAndVerify(
            target, "setGlyphImage:", "glyphImage", offImage);
        BOOL selectedApplied = NO;
        if (standardApplied) {
            writeCount++;
            selectedApplied = CNDCCCanarySetAndVerify(
                target, "setSelectedGlyphImage:", "selectedGlyphImage", onImage);
        }
        applyVerified = standardApplied && selectedApplied &&
            remote_call_current_pid() == targetPIDAtEntry;
        report[@"applyVerified"] = @(applyVerified);
        if (!applyVerified) {
            report[@"failureStage"] = @"apply-readback";
            report[@"failureReason"] =
                @"The Pulsar image setters did not read back exactly.";
        } else if (holdSeconds > 0) {
            [NSThread sleepForTimeInterval:holdSeconds];
            BOOL held = remote_call_current_success() &&
                remote_call_current_pid() == targetPIDAtEntry &&
                CNDCCCanaryGetter(target, "glyphImage") == offImage &&
                CNDCCCanaryGetter(target, "selectedGlyphImage") == onImage;
            report[@"holdReadbackVerified"] = @(held);
            applyVerified = held;
            report[@"applyVerified"] = @(applyVerified);
            if (!held) {
                report[@"failureStage"] = @"hold-readback";
                report[@"failureReason"] =
                    @"The themed glyph did not remain installed for the bounded hold.";
            }
        }
        } while (0);
    } @finally {
        if (r_is_objc_ptr(target) && originalImage &&
            originalSelectedImage && remote_call_current_success() &&
            remote_call_current_pid() == targetPIDAtEntry) {
            rollbackAttempted = YES;
            writeCount++;
            BOOL standardRestored = CNDCCCanarySetAndVerify(
                target, "setGlyphImage:", "glyphImage", originalImage);
            BOOL selectedRestored = NO;
            if (standardRestored) {
                writeCount++;
                selectedRestored = CNDCCCanarySetAndVerify(
                    target, "setSelectedGlyphImage:", "selectedGlyphImage",
                    originalSelectedImage);
            }
            restoreVerified = standardRestored && selectedRestored;
        }
        report[@"rollbackAttempted"] = @(rollbackAttempted);
        report[@"restoreVerified"] = @(restoreVerified);
        report[@"glyphPresentationWrites"] = @(writeCount);
        CNDCCCanaryRelease(onImage);
        CNDCCCanaryRelease(offImage);
        CNDCCCanaryRelease(originalSelectedImage);
        CNDCCCanaryRelease(originalImage);
        CNDCCCanaryRelease(retainedTarget);
        (void)r_settle_us(previousSettle);
    }

    int targetPIDAtExit = remote_call_current_pid();
    BOOL pidStable = targetPIDAtEntry > 0 &&
        targetPIDAtExit == targetPIDAtEntry;
    report[@"targetPIDAtExit"] = @(targetPIDAtExit);
    report[@"pidStable"] = @(pidStable);
    report[@"transportHealthy"] = @(remote_call_current_success());
    report[@"holdSeconds"] = @(holdSeconds);
    BOOL success = applyVerified && restoreVerified && pidStable &&
        remote_call_current_success();
    report[@"success"] = @(success);
    if (!success && !report[@"failureReason"]) {
        report[@"failureStage"] = @"restore-readback";
        report[@"failureReason"] = restoreVerified
            ? @"The canary completed but its PID/transport invariant failed."
            : @"The exact original Flashlight glyph images did not read back after restore.";
    }
    return report;
}
