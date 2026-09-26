#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <dlfcn.h>
#import <fcntl.h>
#import <objc/runtime.h>
#import <stdarg.h>
#import <unistd.h>

#ifndef CND_PROMINENCE_TRACE_OUTPUT_TOKEN
#define CND_PROMINENCE_TRACE_OUTPUT_TOKEN ""
#endif

static const char *const CNDProminenceTracePath =
    "/var/tmp/cyanide-spotlight-prominence-trace.log";
static int gCNDProminenceTraceFD = -1;
static void (*gCNDOriginalDidMoveToSuperview)(id, SEL);
static void (*gCNDOriginalSetProminence)(id, SEL, uint64_t);
static void (*gCNDOriginalSetCustomColorAlpha)(id, SEL, double);
static unsigned gCNDProminenceTraceCount;

static void CNDProminenceLog(const char *format, ...)
{
    if (gCNDProminenceTraceFD < 0) return;
    char line[4096] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = MIN((size_t)length, sizeof(line) - 1U);
    (void)write(gCNDProminenceTraceFD, line, amount);
    (void)fsync(gCNDProminenceTraceFD);
}

static bool CNDProminenceHasAppRowAncestor(UIView *view)
{
    Class rowClass = NSClassFromString(@"SearchUIHomeScreenAppIconView");
    for (UIView *cursor = view.superview; cursor; cursor = cursor.superview) {
        if (rowClass && [cursor isKindOfClass:rowClass]) return true;
    }
    return false;
}

static void CNDProminenceLogMutation(UIView *view, const char *kind,
                                     double value)
{
    unsigned event = __atomic_add_fetch(
        &gCNDProminenceTraceCount, 1U, __ATOMIC_RELAXED);
    bool appRow = CNDProminenceHasAppRowAncestor(view);
    bool iconSized = fabs(view.bounds.size.width - 74.0) < 1.0 &&
        fabs(view.bounds.size.height - 74.0) < 1.0;
    if (event > 512U || (!appRow && !iconSized)) return;
    CNDProminenceLog("[CND_PROMINENCE] MUTATION event=%u kind=%s "
                     "view=%p super=%p/%s bounds=%.2fx%.2f value=%.3f "
                     "appRow=%d iconSized=%d\n", event, kind, view,
                     view.superview, view.superview
                        ? class_getName(object_getClass(view.superview)) : "-",
                     view.bounds.size.width, view.bounds.size.height, value,
                     appRow, iconSized);
    for (NSString *frame in NSThread.callStackSymbols) {
        CNDProminenceLog("[CND_PROMINENCE] stack event=%u %s\n", event,
                         frame.UTF8String ?: "-");
    }
}

static void CNDProminenceSetProminence(id object, SEL selector,
                                       uint64_t prominence)
{
    if (gCNDOriginalSetProminence) {
        gCNDOriginalSetProminence(object, selector, prominence);
    }
    if ([object isKindOfClass:UIView.class]) {
        CNDProminenceLogMutation(object, "prominence", (double)prominence);
    }
}

static void CNDProminenceSetCustomColorAlpha(id object, SEL selector,
                                             double alpha)
{
    if (gCNDOriginalSetCustomColorAlpha) {
        gCNDOriginalSetCustomColorAlpha(object, selector, alpha);
    }
    if ([object isKindOfClass:UIView.class]) {
        CNDProminenceLogMutation(object, "custom-alpha", alpha);
    }
}

static void CNDProminenceDidMoveToSuperview(id object, SEL selector)
{
    if (gCNDOriginalDidMoveToSuperview) {
        gCNDOriginalDidMoveToSuperview(object, selector);
    }
    if (![object isKindOfClass:UIView.class]) return;
    UIView *view = object;
    unsigned event = __atomic_add_fetch(
        &gCNDProminenceTraceCount, 1U, __ATOMIC_RELAXED);
    bool appRow = CNDProminenceHasAppRowAncestor(view);
    bool iconSized = fabs(view.bounds.size.width - 74.0) < 1.0 &&
        fabs(view.bounds.size.height - 74.0) < 1.0;
    if (event > 256U || (!appRow && !iconSized)) return;
    CNDProminenceLog("[CND_PROMINENCE] event=%u view=%p super=%p/%s "
                     "bounds=%.2fx%.2f appRow=%d iconSized=%d\n",
                     event, view, view.superview,
                     view.superview
                        ? class_getName(object_getClass(view.superview)) : "-",
                     view.bounds.size.width, view.bounds.size.height,
                     appRow, iconSized);
    unsigned depth = 0;
    for (UIView *cursor = view.superview; cursor && depth < 12U;
         cursor = cursor.superview, depth++) {
        CNDProminenceLog("[CND_PROMINENCE] ancestor event=%u depth=%u "
                         "view=%p/%s bounds=%.2fx%.2f\n", event, depth,
                         cursor, class_getName(object_getClass(cursor)),
                         cursor.bounds.size.width, cursor.bounds.size.height);
    }
    for (NSString *frame in NSThread.callStackSymbols) {
        CNDProminenceLog("[CND_PROMINENCE] stack event=%u %s\n", event,
                         frame.UTF8String ?: "-");
    }
}

static void CNDProminenceDumpClass(Class cls)
{
    unsigned count = 0;
    Method *methods = cls ? class_copyMethodList(cls, &count) : NULL;
    CNDProminenceLog("[CND_PROMINENCE] CLASS name=%s methods=%u\n",
                     cls ? class_getName(cls) : "-", count);
    for (unsigned index = 0; methods && index < count; index++) {
        CNDProminenceLog("[CND_PROMINENCE] METHOD name=%s types=%s imp=%p\n",
                         sel_getName(method_getName(methods[index])),
                         method_getTypeEncoding(methods[index]) ?: "-",
                         method_getImplementation(methods[index]));
    }
    free(methods);
}

__attribute__((constructor))
static void CNDProminenceTraceStart(void)
{
    if (CND_PROMINENCE_TRACE_OUTPUT_TOKEN[0]) {
        void *sandbox = dlopen("/usr/lib/system/libsystem_sandbox.dylib",
                               RTLD_LAZY | RTLD_LOCAL);
        int (*consume)(const char *) = sandbox
            ? (int (*)(const char *))dlsym(
                  sandbox, "sandbox_extension_consume") : NULL;
        if (consume) (void)consume(CND_PROMINENCE_TRACE_OUTPUT_TOKEN);
    }
    unlink(CNDProminenceTracePath);
    gCNDProminenceTraceFD = open(
        CNDProminenceTracePath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (gCNDProminenceTraceFD < 0) return;
    Class cls = objc_getClass("TLKProminenceView");
    CNDProminenceDumpClass(cls);
    SEL selector = @selector(didMoveToSuperview);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    gCNDOriginalDidMoveToSuperview = method
        ? (void (*)(id, SEL))method_getImplementation(method) : NULL;
    bool installed = cls && types && !strcmp(types, "v16@0:8") &&
        gCNDOriginalDidMoveToSuperview && class_addMethod(
            cls, selector, (IMP)CNDProminenceDidMoveToSuperview, types);
    Method observed = cls ? class_getInstanceMethod(cls, selector) : NULL;
    bool verified = installed && observed &&
        method_getImplementation(observed) ==
            (IMP)CNDProminenceDidMoveToSuperview;
    Method prominenceMethod = cls ? class_getInstanceMethod(
        cls, sel_registerName("setProminence:")) : NULL;
    Method alphaMethod = cls ? class_getInstanceMethod(
        cls, sel_registerName("setCustomColorAlpha:")) : NULL;
    const char *prominenceTypes = prominenceMethod
        ? method_getTypeEncoding(prominenceMethod) : NULL;
    const char *alphaTypes = alphaMethod
        ? method_getTypeEncoding(alphaMethod) : NULL;
    bool prominenceABI = prominenceTypes &&
        !strcmp(prominenceTypes, "v24@0:8Q16");
    bool alphaABI = alphaTypes && !strcmp(alphaTypes, "v24@0:8d16");
    gCNDOriginalSetProminence = prominenceABI
        ? (void (*)(id, SEL, uint64_t))method_setImplementation(
              prominenceMethod, (IMP)CNDProminenceSetProminence) : NULL;
    gCNDOriginalSetCustomColorAlpha = alphaABI
        ? (void (*)(id, SEL, double))method_setImplementation(
              alphaMethod, (IMP)CNDProminenceSetCustomColorAlpha) : NULL;
    CNDProminenceLog("[CND_PROMINENCE] READY pid=%d class=%p types=%s "
                     "original=%p installed=%d verified=%d "
                     "prominence=%s/%p alpha=%s/%p\n", getpid(), cls,
                     types ?: "-", gCNDOriginalDidMoveToSuperview,
                     installed, verified, prominenceTypes ?: "-",
                     gCNDOriginalSetProminence, alphaTypes ?: "-",
                     gCNDOriginalSetCustomColorAlpha);
}
