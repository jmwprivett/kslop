#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>
#if CND_SIGNED_IMP_SET_QUERY
#import <UIKit/UIKit.h>
#endif

#import <dlfcn.h>
#import <fcntl.h>
#import <objc/runtime.h>
#import <stdarg.h>
#import <unistd.h>

#ifndef CND_SIGNED_IMP_REPORT_PATH
#define CND_SIGNED_IMP_REPORT_PATH \
    "/var/tmp/cyanide-spotlight-signed-imp-probe.log"
#endif

#ifndef CND_SIGNED_IMP_OUTPUT_TOKEN
#define CND_SIGNED_IMP_OUTPUT_TOKEN ""
#endif

#ifndef CND_SIGNED_IMP_FLAT_PREF
#define CND_SIGNED_IMP_FLAT_PREF 0
#endif

#ifndef CND_SIGNED_IMP_REMOVE_PROMINENCE
#define CND_SIGNED_IMP_REMOVE_PROMINENCE 0
#endif

#ifndef CND_SIGNED_IMP_FORCE_OPAQUE_REPORT
#define CND_SIGNED_IMP_FORCE_OPAQUE_REPORT 0
#endif

#ifndef CND_SIGNED_IMP_QUERY_TEXT
#define CND_SIGNED_IMP_QUERY_TEXT "eBay"
#endif

static int gCNDProbeFD = -1;

static void CNDProbeLog(const char *format, ...)
{
    if (gCNDProbeFD < 0) return;
    char line[2048] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length;
    if (amount >= sizeof(line)) amount = sizeof(line) - 1U;
    (void)write(gCNDProbeFD, line, amount);
    (void)fsync(gCNDProbeFD);
}

static void CNDProbeDumpClass(const char *name)
{
    Class cls = objc_getClass(name);
    CNDProbeLog("[CND_SIGNED_IMP] CLASS name=%s class=%p super=%s\n",
                name, cls,
                cls && class_getSuperclass(cls)
                    ? class_getName(class_getSuperclass(cls)) : "-");
    for (Class owner = cls; owner; owner = class_getSuperclass(owner)) {
        unsigned count = 0;
        Method *methods = class_copyMethodList(owner, &count);
        CNDProbeLog("[CND_SIGNED_IMP] OWNER class=%s methods=%u\n",
                    class_getName(owner) ?: "-", count);
        for (unsigned index = 0; methods && index < count; index++) {
            SEL selector = method_getName(methods[index]);
            CNDProbeLog("[CND_SIGNED_IMP] METHOD owner=%s selector=%s "
                        "types=%s imp=%p\n",
                        class_getName(owner) ?: "-",
                        selector ? sel_getName(selector) : "-",
                        method_getTypeEncoding(methods[index]) ?: "-",
                        method_getImplementation(methods[index]));
        }
        free(methods);
        if (owner == NSObject.class || owner == CALayer.class) break;
    }
}

static void CNDProbeLogCandidate(Class cls, SEL selector,
                                 const char *label)
{
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    CNDProbeLog("[CND_SIGNED_IMP] CANDIDATE label=%s class=%s selector=%s "
                "types=%s imp=%p\n",
                label, cls ? class_getName(cls) : "-",
                selector ? sel_getName(selector) : "-",
                method ? method_getTypeEncoding(method) : "-",
                method ? method_getImplementation(method) : NULL);
}

#if CND_SIGNED_IMP_MUTATE
static bool CNDProbeInstallRemovalOverride(const char *className,
                                           IMP removalIMP)
{
    Class cls = objc_getClass(className);
    SEL layout = @selector(layoutSublayers);
    if (!cls || !removalIMP) return false;
    unsigned count = 0;
    Method *owned = class_copyMethodList(cls, &count);
    Method ownedLayout = NULL;
    for (unsigned index = 0; owned && index < count; index++) {
        if (method_getName(owned[index]) == layout) {
            ownedLayout = owned[index];
            break;
        }
    }
    free(owned);
    bool installed = false;
    if (ownedLayout) {
        IMP previous = method_setImplementation(ownedLayout, removalIMP);
        installed = previous != NULL ||
            method_getImplementation(ownedLayout) == removalIMP;
        CNDProbeLog("[CND_SIGNED_IMP] REPLACE class=%s previous=%p "
                    "replacement=%p ok=%d\n",
                    className, previous, removalIMP, installed);
    } else {
        installed = class_addMethod(cls, layout, removalIMP, "v16@0:8");
        CNDProbeLog("[CND_SIGNED_IMP] ADD class=%s replacement=%p ok=%d\n",
                    className, removalIMP, installed);
    }
    Method observed = class_getInstanceMethod(cls, layout);
    IMP observedIMP = observed ? method_getImplementation(observed) : NULL;
    bool verified = observedIMP == removalIMP;
    CNDProbeLog("[CND_SIGNED_IMP] VERIFY class=%s observed=%p expected=%p "
                "ok=%d\n", className, observedIMP, removalIMP, verified);
    return verified;
}
#endif

#if CND_SIGNED_IMP_FORCE_OPAQUE_REPORT
static bool CNDProbeInstallOpaqueReport(void)
{
    Class targetClass = objc_getClass("SBIconImageView");
    SEL targetSelector = sel_registerName("hasOpaqueImage");
    Method targetMethod = NULL;
    unsigned count = 0;
    Method *owned = targetClass
        ? class_copyMethodList(targetClass, &count) : NULL;
    for (unsigned index = 0; owned && index < count; index++) {
        if (method_getName(owned[index]) == targetSelector) {
            targetMethod = owned[index];
            break;
        }
    }
    free(owned);
    Method sourceMethod = class_getInstanceMethod(
        NSObject.class, sel_registerName("isNSObject__"));
    const char *targetTypes = targetMethod
        ? method_getTypeEncoding(targetMethod) : NULL;
    const char *sourceTypes = sourceMethod
        ? method_getTypeEncoding(sourceMethod) : NULL;
    IMP sourceIMP = sourceMethod
        ? method_getImplementation(sourceMethod) : NULL;
    bool abi = targetTypes && sourceTypes &&
        strcmp(targetTypes, "B16@0:8") == 0 &&
        strcmp(sourceTypes, "B16@0:8") == 0 && sourceIMP;
    IMP previous = abi
        ? method_setImplementation(targetMethod, sourceIMP) : NULL;
    IMP observed = targetMethod
        ? method_getImplementation(targetMethod) : NULL;
    bool verified = abi && observed == sourceIMP;
    CNDProbeLog("[CND_SIGNED_IMP] OPAQUE-REPORT class=%s target=%s "
                "targetTypes=%s source=NSObject/isNSObject__ "
                "sourceTypes=%s previous=%p replacement=%p observed=%p "
                "ok=%d\n",
                targetClass ? class_getName(targetClass) : "-",
                sel_getName(targetSelector), targetTypes ?: "-",
                sourceTypes ?: "-", previous, sourceIMP, observed, verified);
    return verified;
}
#endif

#if CND_SIGNED_IMP_REMOVE_PROMINENCE
static bool CNDProbeInstallProminenceRemoval(void)
{
    Class targetClass = objc_getClass("TLKProminenceView");
    SEL targetSelector = sel_registerName("didMoveToSuperview");
    Method sourceMethod = class_getInstanceMethod(
        UIView.class, @selector(removeFromSuperview));
    const char *sourceTypes = sourceMethod
        ? method_getTypeEncoding(sourceMethod) : NULL;
    IMP sourceIMP = sourceMethod
        ? method_getImplementation(sourceMethod) : NULL;
    bool abi = targetClass && sourceTypes &&
        strcmp(sourceTypes, "v16@0:8") == 0 && sourceIMP;
    bool added = abi && class_addMethod(
        targetClass, targetSelector, sourceIMP, sourceTypes);
    Method observedMethod = targetClass
        ? class_getInstanceMethod(targetClass, targetSelector) : NULL;
    const char *observedTypes = observedMethod
        ? method_getTypeEncoding(observedMethod) : NULL;
    IMP observed = observedMethod
        ? method_getImplementation(observedMethod) : NULL;
    bool verified = observedTypes &&
        strcmp(observedTypes, "v16@0:8") == 0 && observed == sourceIMP;
    CNDProbeLog("[CND_SIGNED_IMP] REMOVE-PROMINENCE class=%s "
                "selector=%s source=UIView/removeFromSuperview "
                "sourceTypes=%s added=%d replacement=%p observed=%p "
                "observedTypes=%s ok=%d\n",
                targetClass ? class_getName(targetClass) : "-",
                sel_getName(targetSelector), sourceTypes ?: "-", added,
                sourceIMP, observed, observedTypes ?: "-", verified);
    return verified;
}
#endif

#if CND_SIGNED_IMP_FLAT_PREF
static bool CNDProbeInstallFlatPreference(void)
{
    Class targetClass = objc_getClass("SBIconImageView");
    SEL targetSelector = sel_registerName("effectivelyPrefersFlatImageLayers");
    Method targetMethod = NULL;
    unsigned count = 0;
    Method *owned = targetClass
        ? class_copyMethodList(targetClass, &count) : NULL;
    for (unsigned index = 0; owned && index < count; index++) {
        if (method_getName(owned[index]) == targetSelector) {
            targetMethod = owned[index];
            break;
        }
    }
    free(owned);
    Method sourceMethod = class_getInstanceMethod(
        NSObject.class, sel_registerName("isNSObject__"));
    const char *targetTypes = targetMethod
        ? method_getTypeEncoding(targetMethod) : NULL;
    const char *sourceTypes = sourceMethod
        ? method_getTypeEncoding(sourceMethod) : NULL;
    IMP sourceIMP = sourceMethod
        ? method_getImplementation(sourceMethod) : NULL;
    bool abi = targetTypes && sourceTypes &&
        strcmp(targetTypes, "B16@0:8") == 0 &&
        strcmp(sourceTypes, "B16@0:8") == 0 && sourceIMP;
    IMP previous = abi
        ? method_setImplementation(targetMethod, sourceIMP) : NULL;
    IMP observed = targetMethod
        ? method_getImplementation(targetMethod) : NULL;
    bool verified = abi && observed == sourceIMP;
    CNDProbeLog("[CND_SIGNED_IMP] FLAT-PREF class=%s target=%s "
                "targetTypes=%s source=NSObject/isNSObject__ "
                "sourceTypes=%s previous=%p replacement=%p observed=%p "
                "ok=%d\n",
                targetClass ? class_getName(targetClass) : "-",
                sel_getName(targetSelector), targetTypes ?: "-",
                sourceTypes ?: "-", previous, sourceIMP, observed, verified);
    return verified;
}
#endif

#if CND_SIGNED_IMP_SET_QUERY
static UITextField *CNDProbeFindTextField(UIView *view)
{
    if ([view isKindOfClass:UITextField.class]) return (UITextField *)view;
    for (UIView *child in view.subviews) {
        UITextField *field = CNDProbeFindTextField(child);
        if (field) return field;
    }
    return nil;
}

#if CND_SIGNED_IMP_REMOVE_PROMINENCE
static void CNDProbeRemoveExistingProminence(UIView *view,
                                             NSUInteger *matched)
{
    if ([view isKindOfClass:NSClassFromString(@"TLKProminenceView")]) {
        CNDProbeLog("[CND_SIGNED_IMP] REMOVE-EXISTING-PROMINENCE "
                    "view=%p super=%p\n", view, view.superview);
        [view removeFromSuperview];
        (*matched)++;
        return;
    }
    for (UIView *child in view.subviews) {
        CNDProbeRemoveExistingProminence(child, matched);
    }
}
#endif

static void CNDProbeSetQuery(void)
{
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UITextField *field = nil;
        for (UIWindow *window in UIApplication.sharedApplication.windows) {
            field = CNDProbeFindTextField(window);
            if (field) break;
        }
        if (!field) {
            CNDProbeLog("[CND_SIGNED_IMP] QUERY field=nil\n");
            return;
        }
        field.text = @"";
        [field sendActionsForControlEvents:UIControlEventEditingChanged];
        [NSNotificationCenter.defaultCenter
            postNotificationName:UITextFieldTextDidChangeNotification
                          object:field];
        CNDProbeLog("[CND_SIGNED_IMP] QUERY-CLEAR field=%p class=%s\n",
                    field, class_getName(object_getClass(field)) ?: "-");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)(0.35 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            field.text = @CND_SIGNED_IMP_QUERY_TEXT;
            [field sendActionsForControlEvents:UIControlEventEditingChanged];
            [NSNotificationCenter.defaultCenter
                postNotificationName:UITextFieldTextDidChangeNotification
                              object:field];
            CNDProbeLog("[CND_SIGNED_IMP] QUERY field=%p class=%s text=%s\n",
                        field, class_getName(object_getClass(field)) ?: "-",
                        field.text.UTF8String ?: "-");
#if CND_SIGNED_IMP_REMOVE_PROMINENCE
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                         (int64_t)(0.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                NSUInteger matched = 0;
                for (UIWindow *window in UIApplication.sharedApplication.windows) {
                    CNDProbeRemoveExistingProminence(window, &matched);
                }
                CNDProbeLog("[CND_SIGNED_IMP] REMOVE-PROMINENCE matched=%lu\n",
                            (unsigned long)matched);
            });
#endif
        });
    });
}
#endif

static void CNDSpotlightSignedIMPProbeStart(void)
{
    if (CND_SIGNED_IMP_OUTPUT_TOKEN[0]) {
        void *sandbox = dlopen("/usr/lib/system/libsystem_sandbox.dylib",
                               RTLD_LAZY | RTLD_LOCAL);
        int (*consume)(const char *) = sandbox
            ? (int (*)(const char *))dlsym(
                  sandbox, "sandbox_extension_consume") : NULL;
        if (consume) (void)consume(CND_SIGNED_IMP_OUTPUT_TOKEN);
    }
    unlink(CND_SIGNED_IMP_REPORT_PATH);
    gCNDProbeFD = open(CND_SIGNED_IMP_REPORT_PATH,
                       O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (gCNDProbeFD < 0) return;
    void *handle = dlopen(
        "/System/Library/PrivateFrameworks/IconRendering.framework/"
        "IconRendering", RTLD_NOW | RTLD_LOCAL);
    CNDProbeLog("[CND_SIGNED_IMP] START pid=%d framework=%p error=%s\n",
                getpid(), handle, handle ? "-" : (dlerror() ?: "-"));
    if (!handle) return;

    static const char *const classes[] = {
        "ICRFinalizedIcon",
        "ICRIconLayer",
        "ICRSimulatedGlassChicletLayer",
        "SimulatedGlassChicletLayer",
        "_TtC13IconRendering29ICRSimulatedGlassChicletLayer",
        "_TtC13IconRendering26SimulatedGlassChicletLayer",
    };
    if (!CND_SIGNED_IMP_MUTATE && !CND_SIGNED_IMP_FLAT_PREF &&
        !CND_SIGNED_IMP_FORCE_OPAQUE_REPORT &&
        !CND_SIGNED_IMP_REMOVE_PROMINENCE) {
        for (size_t index = 0;
             index < sizeof(classes) / sizeof(classes[0]); index++) {
            CNDProbeDumpClass(classes[index]);
        }
    }

    CNDProbeLogCandidate(CALayer.class, @selector(layoutSublayers),
                         "calayer-layout");
    CNDProbeLogCandidate(CALayer.class, @selector(removeFromSuperlayer),
                         "calayer-remove");
    CNDProbeLogCandidate(NSObject.class, @selector(self), "nsobject-self");
    CNDProbeLogCandidate(NSObject.class, @selector(isProxy),
                         "nsobject-false");
#if CND_SIGNED_IMP_MUTATE
    Method removeMethod = class_getInstanceMethod(
        CALayer.class, @selector(removeFromSuperlayer));
    IMP removalIMP = removeMethod
        ? method_getImplementation(removeMethod) : NULL;
    bool wrapper = CNDProbeInstallRemovalOverride(
        "_TtC13IconRendering29ICRSimulatedGlassChicletLayer", removalIMP);
    bool renderer = CNDProbeInstallRemovalOverride(
        "_TtC13IconRendering26SimulatedGlassChicletLayer", removalIMP);
    CNDProbeLog("[CND_SIGNED_IMP] READY mutation=chiclet-removal "
                "wrapper=%d renderer=%d\n", wrapper, renderer);
#else
    CNDProbeLog("[CND_SIGNED_IMP] READY mutation=none\n");
#endif
#if CND_SIGNED_IMP_FLAT_PREF
    bool flatPreference = CNDProbeInstallFlatPreference();
    CNDProbeLog("[CND_SIGNED_IMP] READY flat-preference=%d\n",
                flatPreference);
#endif
#if CND_SIGNED_IMP_FORCE_OPAQUE_REPORT
    bool opaqueReport = CNDProbeInstallOpaqueReport();
    CNDProbeLog("[CND_SIGNED_IMP] READY opaque-report=%d\n",
                opaqueReport);
#endif
#if CND_SIGNED_IMP_REMOVE_PROMINENCE
    bool prominenceRemoval = CNDProbeInstallProminenceRemoval();
    CNDProbeLog("[CND_SIGNED_IMP] READY prominence-removal=%d\n",
                prominenceRemoval);
#endif
#if CND_SIGNED_IMP_SET_QUERY
    CNDProbeSetQuery();
#endif
}

#if CND_SIGNED_IMP_STANDALONE
int main(void)
{
    @autoreleasepool {
        CNDSpotlightSignedIMPProbeStart();
    }
    return 0;
}
#else
__attribute__((constructor))
static void CNDSpotlightSignedIMPProbeConstructor(void)
{
    CNDSpotlightSignedIMPProbeStart();
}
#endif
