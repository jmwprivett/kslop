#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef CND_PULSAR_ADDITIONAL_OUTPUT_TOKEN
#define CND_PULSAR_ADDITIONAL_OUTPUT_TOKEN ""
#endif

#ifndef CND_PULSAR_ADDITIONAL_REPORT_PATH
#define CND_PULSAR_ADDITIONAL_REPORT_PATH \
    "/var/tmp/cyanide-pulsar-additional-controls.log"
#endif

#ifndef CND_PULSAR_ADDITIONAL_THEME_DIRECTORY
#define CND_PULSAR_ADDITIONAL_THEME_DIRECTORY \
    "/var/tmp/cyanide-pulsar-additional-controls-a1"
#endif

#ifndef CND_PULSAR_ADDITIONAL_EXPECTED_PID
#define CND_PULSAR_ADDITIONAL_EXPECTED_PID 0
#endif

#ifndef CND_PULSAR_ADDITIONAL_HOLD_SECONDS
#define CND_PULSAR_ADDITIONAL_HOLD_SECONDS 45
#endif

/*
 * Reversible presentation-only canary for the official Pulsar Low Power,
 * ReplayKit, and Flashlight assets.  Low Power and ReplayKit keep their safe
 * inactive state.  Flashlight is a noninteractive VM-only control because the
 * vPhone does not advertise camera-flash hardware.  No module action is sent.
 */

static int gReportFD = -1;
static __strong UIViewController *gLowPowerController;
static __strong UIViewController *gReplayKitController;
static __strong UIView *gLowPowerTarget;
static __strong UIView *gReplayKitTarget;
static __strong UIViewController *gHostController;
static __strong UIViewController *gFlashlightController;
static __strong UIView *gFlashlightMount;
static __strong id gLowPowerOriginalDescription;
static __strong NSString *gLowPowerOriginalState;
static __strong id gReplayKitOriginalDescription;
static __strong NSString *gReplayKitOriginalState;
static __strong id gLowPowerPackage;
static __strong id gReplayKitPackage;
static __strong id gLowPowerDescription;
static __strong id gReplayKitDescription;
static bool gLowPowerApplied;
static bool gReplayKitApplied;
static bool gFlashlightApplied;
static bool gRestored;

static void CNDLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDLog(const char *format, ...)
{
    if (gReportFD < 0) return;
    char line[4096] = {0};
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

static bool CNDClassMethodTypes(Class cls, const char *name,
                                const char *expected)
{
    if (!cls || !name || !expected) return false;
    Method method = class_getClassMethod(cls, sel_registerName(name));
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    return types && strcmp(types, expected) == 0;
}

static id CNDObjectGetter(id object, const char *name)
{
    if (!CNDMethodTypes(object, name, "@16@0:8")) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, sel_registerName(name));
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

static UIViewController *CNDVisibleControllerNamed(NSString *name)
{
    Class target = NSClassFromString(name);
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

static UIView *CNDFindTemplateView(UIView *view)
{
    if (!view) return nil;
    Class target = NSClassFromString(@"CCUIControlTemplateView");
    if (target && [view isKindOfClass:target]) return view;
    for (UIView *subview in view.subviews) {
        UIView *match = CNDFindTemplateView(subview);
        if (match) return match;
    }
    return nil;
}

static bool CNDIsIconListView(UIView *view)
{
    if (![view isKindOfClass:UIView.class]) return false;
    NSString *name = NSStringFromClass(view.class);
    return [name containsString:@"IconListView"] &&
        ![name hasSuffix:@"IconView"] && view.bounds.size.width > 400.0;
}

static bool CNDFindGrid(UIViewController *lowPower,
                        UIView *__strong *listView,
                        UIView *__strong *lowPowerWrapper)
{
    if (!lowPower || !listView || !lowPowerWrapper) return false;
    UIView *cursor = lowPower.view;
    while (cursor.superview) {
        if (CNDIsIconListView(cursor.superview)) {
            *listView = cursor.superview;
            *lowPowerWrapper = cursor;
            return true;
        }
        cursor = cursor.superview;
    }
    return false;
}

static CGRect CNDTargetFrame(UIView *listView, UIView *anchorView)
{
    CGRect anchor = anchorView.frame;
    NSMutableArray<NSNumber *> *origins = [NSMutableArray array];
    for (UIView *sibling in listView.subviews) {
        CGRect frame = sibling.frame;
        if (fabs(frame.origin.y - anchor.origin.y) <= 1.0 &&
            fabs(frame.size.width - anchor.size.width) <= 1.0 &&
            fabs(frame.size.height - anchor.size.height) <= 1.0) {
            [origins addObject:@(frame.origin.x)];
        }
    }
    [origins sortUsingSelector:@selector(compare:)];
    CGFloat pitch = anchor.size.width + 15.333333333333334;
    if (origins.count >= 2U) {
        CGFloat last = origins.lastObject.doubleValue;
        CGFloat previous = origins[origins.count - 2U].doubleValue;
        if (last - previous > anchor.size.width) pitch = last - previous;
    }
    CGFloat nextX = origins.count ? origins.lastObject.doubleValue + pitch :
        anchor.origin.x + 2.0 * pitch;
    return CGRectMake(nextX, anchor.origin.y,
                      anchor.size.width, anchor.size.height);
}

static id CNDLoadPackage(NSString *name)
{
    NSString *relative = [NSString stringWithFormat:
        @"PulsarAdditionalMotion.bundle/%@.ca", name];
    NSString *path = [@CND_PULSAR_ADDITIONAL_THEME_DIRECTORY
        stringByAppendingPathComponent:relative];
    Class cls = NSClassFromString(@"CAPackage");
    const char *selectorName = "packageWithContentsOfURL:type:options:error:";
    if (!name.length || !CNDClassMethodTypes(
            cls, selectorName, "@48@0:8@16@24@32^@40")) return nil;
    NSError *__autoreleasing error = nil;
    id package = nil;
    @try {
        package = ((id (*)(id, SEL, id, id, id, NSError **))objc_msgSend)(
            cls, sel_registerName(selectorName),
            [NSURL fileURLWithPath:path isDirectory:YES],
            @"com.apple.coreanimation-bundle", nil, &error);
    } @catch (NSException *exception) {
        CNDLog("[CND_PULSAR_ADDITIONAL] PACKAGE_EXCEPTION name=%s "
               "exception=%s reason=%s\n", name.UTF8String ?: "-",
               exception.name.UTF8String ?: "-",
               exception.reason.UTF8String ?: "-");
    }
    CNDLog("[CND_PULSAR_ADDITIONAL] PACKAGE name=%s loaded=%d path=%s "
           "error=%s\n", name.UTF8String ?: "-", package != nil,
           path.UTF8String ?: "-", error.description.UTF8String ?: "-");
    return package;
}

static id CNDCreateDescription(NSString *name)
{
    NSString *bundlePath = [@CND_PULSAR_ADDITIONAL_THEME_DIRECTORY
        stringByAppendingPathComponent:@"PulsarAdditionalMotion.bundle"];
    NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
    Class cls = NSClassFromString(@"CCUICAPackageDescription");
    SEL initializer = sel_registerName("initWithPackageName:inBundle:");
    Method method = cls ? class_getInstanceMethod(cls, initializer) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (!bundle || !types || strcmp(types, "@32@0:8@16@24") != 0) {
        return nil;
    }
    id description = nil;
    @try {
        description = ((id (*)(id, SEL, id, id))objc_msgSend)(
            [cls alloc], initializer, name, bundle);
    } @catch (NSException *exception) {
        CNDLog("[CND_PULSAR_ADDITIONAL] DESCRIPTION_EXCEPTION name=%s "
               "exception=%s reason=%s\n", name.UTF8String ?: "-",
               exception.name.UTF8String ?: "-",
               exception.reason.UTF8String ?: "-");
    }
    NSURL *url = CNDObjectGetter(description, "packageURL");
    NSString *expected = [bundlePath stringByAppendingPathComponent:
        [name stringByAppendingPathExtension:@"ca"]];
    bool valid = [url isKindOfClass:NSURL.class] &&
        [url.path isEqualToString:expected];
    CNDLog("[CND_PULSAR_ADDITIONAL] DESCRIPTION name=%s created=%d "
           "urlValid=%d url=%s\n", name.UTF8String ?: "-",
           description != nil, valid, url.path.UTF8String ?: "-");
    return valid ? description : nil;
}

static bool CNDApplyDescription(id controller, id description,
                                NSString *safeState,
                                id __strong *originalDescription,
                                NSString *__strong *originalState)
{
    if (!controller || !description || !safeState.length ||
        !originalDescription || !originalState ||
        !CNDMethodTypes(controller, "glyphPackageDescription", "@16@0:8") ||
        !CNDMethodTypes(controller, "glyphState", "@16@0:8") ||
        !CNDMethodTypes(controller, "setGlyphPackageDescription:",
                        "v24@0:8@16") ||
        !CNDMethodTypes(controller, "setGlyphState:", "v24@0:8@16")) {
        return false;
    }
    *originalDescription = CNDObjectGetter(controller, "glyphPackageDescription");
    *originalState = CNDObjectGetter(controller, "glyphState");
    bool descriptionSet = CNDObjectSetter(
        controller, "setGlyphPackageDescription:", description);
    bool stateSet = descriptionSet && CNDObjectSetter(
        controller, "setGlyphState:", safeState);
    if (!stateSet) {
        (void)CNDObjectSetter(controller, "setGlyphPackageDescription:",
                              *originalDescription);
        (void)CNDObjectSetter(controller, "setGlyphState:", *originalState);
    }
    CNDLog("[CND_PULSAR_ADDITIONAL] APPLY controller=%p/%s "
           "description=%d state=%d safeState=%s originalState=%s\n",
           (__bridge void *)controller, CNDClassName(controller),
           descriptionSet, stateSet, safeState.UTF8String ?: "-",
           (*originalState).UTF8String ?: "-");
    return descriptionSet && stateSet;
}

static UIImage *CNDFlashlightImage(NSString *name)
{
    NSString *path = [@CND_PULSAR_ADDITIONAL_THEME_DIRECTORY
        stringByAppendingPathComponent:@"PulsarFlashlight.bundle"];
    NSBundle *bundle = [NSBundle bundleWithPath:path];
    UIImage *image = bundle ? [UIImage imageNamed:name inBundle:bundle
        compatibleWithTraitCollection:nil] : nil;
    return [image imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
}

static bool CNDMountFlashlight(UIViewController *lowPower)
{
    UIView *listView = nil;
    UIView *anchor = nil;
    if (!CNDFindGrid(lowPower, &listView, &anchor)) return false;
    if ([listView viewWithTag:0x434E4446]) return false;
    Class cls = NSClassFromString(@"CCUIButtonModuleViewController");
    UIViewController *controller = cls ? [[cls alloc]
        initWithNibName:nil bundle:nil] : nil;
    UIImage *off = CNDFlashlightImage(@"FlashlightOff");
    UIImage *on = CNDFlashlightImage(@"FlashlightOn");
    bool standard = CNDObjectSetter(controller, "setGlyphImage:", off);
    bool selected = CNDObjectSetter(controller, "setSelectedGlyphImage:", on);
    bool color = CNDObjectSetter(controller, "setGlyphColor:", UIColor.whiteColor);
    bool selectedColor = CNDObjectSetter(
        controller, "setSelectedGlyphColor:", UIColor.whiteColor);
    UIView *contentView = controller.view;
    if (!off || !on || ![contentView isKindOfClass:UIView.class] ||
        !standard || !selected) {
        CNDLog("[CND_PULSAR_ADDITIONAL] FLASHLIGHT_ASSETS off=%d on=%d "
               "standard=%d selected=%d color=%d/%d\n", off != nil,
               on != nil, standard, selected, color, selectedColor);
        return false;
    }
    CGRect target = CNDTargetFrame(listView, anchor);
    if (CGRectGetMaxX(target) > listView.bounds.size.width + 0.5 ||
        target.origin.x < 0.0 || target.origin.y < 0.0) return false;
    UIViewController *host = lowPower.parentViewController.parentViewController;
    if (![host isKindOfClass:UIViewController.class]) return false;

    UIView *mount = [[UIView alloc] initWithFrame:target];
    mount.layer.cornerRadius = target.size.width / 2.0;
    mount.layer.masksToBounds = YES;
    mount.layer.borderWidth = 0.5;
    mount.layer.borderColor =
        [UIColor colorWithWhite:1.0 alpha:0.32].CGColor;
    UIBlurEffect *blur = [UIBlurEffect effectWithStyle:
        UIBlurEffectStyleSystemUltraThinMaterialDark];
    UIVisualEffectView *material = [[UIVisualEffectView alloc]
        initWithEffect:blur];
    material.frame = mount.bounds;
    material.autoresizingMask = UIViewAutoresizingFlexibleWidth |
        UIViewAutoresizingFlexibleHeight;
    material.userInteractionEnabled = NO;
    material.contentView.backgroundColor =
        [UIColor colorWithWhite:0.72 alpha:0.16];
    [mount addSubview:material];
    contentView.frame = mount.bounds;
    contentView.autoresizingMask = UIViewAutoresizingFlexibleWidth |
        UIViewAutoresizingFlexibleHeight;
    contentView.backgroundColor = UIColor.clearColor;
    contentView.userInteractionEnabled = NO;
    [mount addSubview:contentView];
    [host addChildViewController:controller];
    mount.translatesAutoresizingMaskIntoConstraints = YES;
    mount.autoresizingMask = UIViewAutoresizingNone;
    mount.userInteractionEnabled = NO;
    mount.tag = 0x434E4446;
    mount.accessibilityIdentifier =
        @"com.cyanide.vm.synthetic.flashlight.pulsar";
    mount.accessibilityLabel = @"Flashlight (VM synthetic, Pulsar)";
    [listView addSubview:mount];
    [controller didMoveToParentViewController:host];
    [mount setNeedsLayout];
    [mount layoutIfNeeded];
    gHostController = host;
    gFlashlightController = controller;
    gFlashlightMount = mount;
    CNDLog("[CND_PULSAR_ADDITIONAL] FLASHLIGHT mounted=1 frame=%s "
           "offPoints=%.2fx%.2f onPoints=%.2fx%.2f interaction=disabled\n",
           NSStringFromCGRect(target).UTF8String, off.size.width,
           off.size.height, on.size.width, on.size.height);
    return true;
}

static void CNDRestore(void)
{
    if (gRestored) return;
    gRestored = true;
    if (gLowPowerApplied) {
        (void)CNDObjectSetter(gLowPowerTarget,
            "setGlyphPackageDescription:", gLowPowerOriginalDescription);
        (void)CNDObjectSetter(gLowPowerTarget,
            "setGlyphState:", gLowPowerOriginalState);
    }
    if (gReplayKitApplied) {
        (void)CNDObjectSetter(gReplayKitTarget,
            "setGlyphPackageDescription:", gReplayKitOriginalDescription);
        (void)CNDObjectSetter(gReplayKitTarget,
            "setGlyphState:", gReplayKitOriginalState);
    }
    if (gFlashlightController.parentViewController) {
        [gFlashlightController willMoveToParentViewController:nil];
    }
    [gFlashlightMount removeFromSuperview];
    [gFlashlightController removeFromParentViewController];
    CNDLog("[CND_PULSAR_ADDITIONAL] RESTORED lowPower=%d replayKit=%d "
           "flashlight=%d noSystemWrite=1\n", gLowPowerApplied,
           gReplayKitApplied, gFlashlightApplied);
    gLowPowerController = nil;
    gReplayKitController = nil;
    gLowPowerTarget = nil;
    gReplayKitTarget = nil;
    gHostController = nil;
    gFlashlightController = nil;
    gFlashlightMount = nil;
    gLowPowerOriginalDescription = nil;
    gLowPowerOriginalState = nil;
    gReplayKitOriginalDescription = nil;
    gReplayKitOriginalState = nil;
    gLowPowerPackage = nil;
    gReplayKitPackage = nil;
    gLowPowerDescription = nil;
    gReplayKitDescription = nil;
}

static void CNDComplete(const char *status)
{
    CNDRestore();
    CNDLog("[CND_PULSAR_ADDITIONAL] COMPLETE status=%s pid=%d "
           "controlActions=0 hardwareSpoof=0 interaction=disabled "
           "noSystemWrite=1\n", status ?: "-", getpid());
}

static bool CNDPresent(void)
{
    UIViewController *lowPower = CNDVisibleControllerNamed(
        @"CCUILowPowerModuleViewController");
    UIViewController *replayKit = CNDVisibleControllerNamed(
        @"RPControlCenterMenuModuleViewController");
    if (!lowPower || !replayKit) return false;
    gLowPowerController = lowPower;
    gReplayKitController = replayKit;
    gLowPowerTarget = CNDFindTemplateView(lowPower.view);
    gReplayKitTarget = CNDFindTemplateView(replayKit.view);
    if (!gLowPowerTarget || !gReplayKitTarget) {
        CNDLog("[CND_PULSAR_ADDITIONAL] REFUSED reason=template-target "
               "lowPower=%d replayKit=%d\n", gLowPowerTarget != nil,
               gReplayKitTarget != nil);
        CNDComplete("refused-template-target");
        return true;
    }
    CNDLog("[CND_PULSAR_ADDITIONAL] TARGET lowPower=%p/%s replayKit=%p/%s\n",
           (__bridge void *)gLowPowerTarget, CNDClassName(gLowPowerTarget),
           (__bridge void *)gReplayKitTarget, CNDClassName(gReplayKitTarget));
    gLowPowerPackage = CNDLoadPackage(@"LowPower");
    gReplayKitPackage = CNDLoadPackage(@"ReplayKit");
    gLowPowerDescription = CNDCreateDescription(@"LowPower");
    gReplayKitDescription = CNDCreateDescription(@"ReplayKit");
    bool loaded = gLowPowerPackage && gReplayKitPackage &&
        gLowPowerDescription && gReplayKitDescription;
    if (!loaded) {
        CNDLog("[CND_PULSAR_ADDITIONAL] REFUSED reason=motion-load "
               "lowPackage=%d replayPackage=%d lowDescription=%d "
               "replayDescription=%d\n", gLowPowerPackage != nil,
               gReplayKitPackage != nil, gLowPowerDescription != nil,
               gReplayKitDescription != nil);
        CNDComplete("refused-motion-load");
        return true;
    }
    gLowPowerApplied = CNDApplyDescription(
        gLowPowerTarget, gLowPowerDescription, @"disabled",
        &gLowPowerOriginalDescription, &gLowPowerOriginalState);
    gReplayKitApplied = CNDApplyDescription(
        gReplayKitTarget, gReplayKitDescription, @"disabled",
        &gReplayKitOriginalDescription, &gReplayKitOriginalState);
    gFlashlightApplied = CNDMountFlashlight(lowPower);
    if (!gLowPowerApplied || !gReplayKitApplied || !gFlashlightApplied) {
        CNDLog("[CND_PULSAR_ADDITIONAL] REFUSED reason=presentation "
               "lowPower=%d replayKit=%d flashlight=%d\n",
               gLowPowerApplied, gReplayKitApplied, gFlashlightApplied);
        CNDComplete("refused-presentation");
        return true;
    }
    CNDLog("[CND_PULSAR_ADDITIONAL] VISIBLE_READY pid=%d "
           "themeApplied=1 lowPower=1 lowPowerState=disabled replayKit=1 "
           "replayKitState=disabled flashlight=1 interaction=disabled "
           "controlActions=0 hardwareSpoof=0 holdSeconds=%d\n", getpid(),
           CND_PULSAR_ADDITIONAL_HOLD_SECONDS);
    dispatch_after(dispatch_time(
        DISPATCH_TIME_NOW,
        (int64_t)CND_PULSAR_ADDITIONAL_HOLD_SECONDS * NSEC_PER_SEC),
        dispatch_get_main_queue(), ^{
            CNDComplete("success");
        });
    return true;
}

static void CNDPoll(NSUInteger attempt)
{
    if (gRestored) return;
    if (CNDPresent()) return;
    if (attempt >= 120U) {
        CNDLog("[CND_PULSAR_ADDITIONAL] REFUSED "
               "reason=required-controls-not-visible\n");
        CNDComplete("refused-required-controls-not-visible");
        return;
    }
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
            CNDPoll(attempt + 1U);
        });
}

__attribute__((constructor))
static void CNDPulsarAdditionalStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_PULSAR_ADDITIONAL_OUTPUT_TOKEN[0] && consume ?
            consume(CND_PULSAR_ADDITIONAL_OUTPUT_TOKEN) : -1;
        if (CND_PULSAR_ADDITIONAL_EXPECTED_PID > 0 &&
            getpid() != CND_PULSAR_ADDITIONAL_EXPECTED_PID) return;
        if (![NSProcessInfo.processInfo.processName isEqualToString:
              @"SpringBoard"]) return;
        gReportFD = open(CND_PULSAR_ADDITIONAL_REPORT_PATH,
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (gReportFD < 0) return;
        CNDLog("[CND_PULSAR_ADDITIONAL] START pid=%d token=%d "
               "mode=ephemeral controlActions=0 hardwareSpoof=0 "
               "noSystemWrite=1\n", getpid(), token >= 0);
        dispatch_async(dispatch_get_main_queue(), ^{
            CNDPoll(0U);
        });
    }
}
