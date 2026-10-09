#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef CND_VM_FLASHLIGHT_OUTPUT_TOKEN
#define CND_VM_FLASHLIGHT_OUTPUT_TOKEN ""
#endif

#ifndef CND_VM_FLASHLIGHT_REPORT_PATH
#define CND_VM_FLASHLIGHT_REPORT_PATH \
    "/var/tmp/cyanide-vm-flashlight-control.log"
#endif

#ifndef CND_VM_FLASHLIGHT_EXPECTED_PID
#define CND_VM_FLASHLIGHT_EXPECTED_PID 0
#endif

#ifndef CND_VM_FLASHLIGHT_HOLD_SECONDS
#define CND_VM_FLASHLIGHT_HOLD_SECONDS 120
#endif

/*
 * VM-only presentation shim for a device-gated Flashlight control.
 *
 * The saved iOS 26 layout can contain FlashlightModule, but SpringBoard omits
 * it when the virtual hardware does not advertise `camera-flash`.  This probe
 * places a noninteractive CCUIButtonModuleViewController in the otherwise
 * empty grid slot.  It does not claim torch hardware, invoke the module, or
 * write system files, and it removes the mounted view at the hold deadline.
 */

static int gReportFD = -1;
static __strong UIViewController *gHostController;
static __strong UIViewController *gSyntheticController;
static __strong UIView *gMountedView;
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

static UIViewController *CNDVisibleLowPowerController(void)
{
    Class target = NSClassFromString(@"CCUILowPowerModuleViewController");
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

static CGRect CNDTargetFrame(UIView *listView, UIView *lowPowerWrapper)
{
    CGRect anchor = lowPowerWrapper.frame;
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

static void CNDRestore(void)
{
    if (gRestored) return;
    gRestored = true;
    if (gSyntheticController.parentViewController) {
        [gSyntheticController willMoveToParentViewController:nil];
    }
    [gMountedView removeFromSuperview];
    [gSyntheticController removeFromParentViewController];
    CNDLog("[CND_VM_FLASHLIGHT] RESTORED mounted=%d noSystemWrite=1\n",
           gMountedView != nil);
    gMountedView = nil;
    gSyntheticController = nil;
    gHostController = nil;
}

static void CNDComplete(const char *status)
{
    CNDRestore();
    CNDLog("[CND_VM_FLASHLIGHT] COMPLETE status=%s pid=%d "
           "hardwareSpoof=0 interaction=disabled noSystemWrite=1\n",
           status ?: "-", getpid());
}

static bool CNDPresent(void)
{
    UIViewController *lowPower = CNDVisibleLowPowerController();
    UIView *listView = nil;
    UIView *lowPowerWrapper = nil;
    if (!CNDFindGrid(lowPower, &listView, &lowPowerWrapper)) return false;
    if ([listView viewWithTag:0x434E4446]) {
        CNDLog("[CND_VM_FLASHLIGHT] REFUSED reason=already-mounted\n");
        CNDComplete("refused-already-mounted");
        return true;
    }

    Class controllerClass = NSClassFromString(@"CCUIButtonModuleViewController");
    if (!controllerClass) {
        CNDLog("[CND_VM_FLASHLIGHT] REFUSED reason=controller-class\n");
        CNDComplete("refused-controller-class");
        return true;
    }
    UIViewController *controller = [[controllerClass alloc]
        initWithNibName:nil bundle:nil];
    UIImage *off = [[UIImage systemImageNamed:@"flashlight.off.fill"]
        imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
    UIImage *on = [[UIImage systemImageNamed:@"flashlight.on.fill"]
        imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
    bool standard = CNDObjectSetter(controller, "setGlyphImage:", off);
    bool selected = CNDObjectSetter(controller, "setSelectedGlyphImage:", on);
    bool color = CNDObjectSetter(
        controller, "setGlyphColor:", UIColor.whiteColor);
    bool selectedColor = CNDObjectSetter(
        controller, "setSelectedGlyphColor:", UIColor.whiteColor);
    UIView *contentView = controller.view;
    if (!off || ![contentView isKindOfClass:UIView.class] || !standard || !selected) {
        CNDLog("[CND_VM_FLASHLIGHT] REFUSED reason=controller-contract "
               "off=%d view=%d standard=%d selected=%d color=%d/%d\n",
               off != nil, [contentView isKindOfClass:UIView.class], standard,
               selected, color, selectedColor);
        CNDComplete("refused-controller-contract");
        return true;
    }

    CGRect target = CNDTargetFrame(listView, lowPowerWrapper);
    if (CGRectGetMaxX(target) > listView.bounds.size.width + 0.5 ||
        target.origin.x < 0.0 || target.origin.y < 0.0) {
        CNDLog("[CND_VM_FLASHLIGHT] REFUSED reason=target-frame frame=%s "
               "bounds=%s\n", NSStringFromCGRect(target).UTF8String,
               NSStringFromCGRect(listView.bounds).UTF8String);
        CNDComplete("refused-target-frame");
        return true;
    }

    UIViewController *host = lowPower.parentViewController.parentViewController;
    if (![host isKindOfClass:UIViewController.class]) {
        CNDLog("[CND_VM_FLASHLIGHT] REFUSED reason=host-controller\n");
        CNDComplete("refused-host-controller");
        return true;
    }
    gHostController = host;
    gSyntheticController = controller;
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
    material.autoresizingMask =
        UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    material.userInteractionEnabled = NO;
    material.contentView.backgroundColor =
        [UIColor colorWithWhite:0.72 alpha:0.16];
    [mount addSubview:material];
    contentView.frame = mount.bounds;
    contentView.autoresizingMask =
        UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    contentView.backgroundColor = UIColor.clearColor;
    contentView.userInteractionEnabled = NO;
    [mount addSubview:contentView];
    gMountedView = mount;
    [host addChildViewController:controller];
    mount.translatesAutoresizingMaskIntoConstraints = YES;
    mount.autoresizingMask = UIViewAutoresizingNone;
    mount.hidden = NO;
    mount.alpha = 1.0;
    mount.userInteractionEnabled = NO;
    mount.tag = 0x434E4446;
    mount.accessibilityIdentifier = @"com.cyanide.vm.synthetic.flashlight";
    mount.accessibilityLabel = @"Flashlight (VM synthetic)";
    [listView addSubview:mount];
    [controller didMoveToParentViewController:host];
    [mount setNeedsLayout];
    [mount layoutIfNeeded];

    CNDLog("[CND_VM_FLASHLIGHT] VISIBLE_READY pid=%d controller=%p/%s "
           "view=%p/%s host=%p/%s list=%p/%s frame=%s "
           "interaction=disabled hardwareSpoof=0 holdSeconds=%d\n",
           getpid(), (__bridge void *)controller, CNDClassName(controller),
           (__bridge void *)mount, CNDClassName(mount),
           (__bridge void *)host, CNDClassName(host),
           (__bridge void *)listView, CNDClassName(listView),
           NSStringFromCGRect(mount.frame).UTF8String,
           CND_VM_FLASHLIGHT_HOLD_SECONDS);
    dispatch_after(dispatch_time(
        DISPATCH_TIME_NOW,
        (int64_t)CND_VM_FLASHLIGHT_HOLD_SECONDS * NSEC_PER_SEC),
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
        CNDLog("[CND_VM_FLASHLIGHT] REFUSED reason=control-center-not-visible\n");
        CNDComplete("refused-control-center-not-visible");
        return;
    }
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
            CNDPoll(attempt + 1U);
        });
}

__attribute__((constructor))
static void CNDVMFlashlightStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_VM_FLASHLIGHT_OUTPUT_TOKEN[0] && consume ?
            consume(CND_VM_FLASHLIGHT_OUTPUT_TOKEN) : -1;
        if (CND_VM_FLASHLIGHT_EXPECTED_PID > 0 &&
            getpid() != CND_VM_FLASHLIGHT_EXPECTED_PID) return;
        if (![NSProcessInfo.processInfo.processName isEqualToString:
              @"SpringBoard"]) return;
        gReportFD = open(CND_VM_FLASHLIGHT_REPORT_PATH,
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (gReportFD < 0) return;
        CNDLog("[CND_VM_FLASHLIGHT] START pid=%d token=%d mode=ephemeral "
               "interaction=disabled hardwareSpoof=0 noSystemWrite=1\n",
               getpid(), token >= 0);
        dispatch_async(dispatch_get_main_queue(), ^{
            CNDPoll(0U);
        });
    }
}
