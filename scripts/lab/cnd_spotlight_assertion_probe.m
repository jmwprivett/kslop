#import <Foundation/Foundation.h>

#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#ifndef CND_SPOTLIGHT_ASSERTION_TARGET_PID
#define CND_SPOTLIGHT_ASSERTION_TARGET_PID 0
#endif

#ifndef CND_SPOTLIGHT_ASSERTION_PROBE_MODE
#define CND_SPOTLIGHT_ASSERTION_PROBE_MODE 0
#endif

static const char *const CNDAssertionProbeOutputPath =
    "/var/tmp/cyanide-spotlight-assertion-probe.log";
static int gCNDAssertionProbeFD = -1;

static void CNDAssertionProbeLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDAssertionProbeLog(const char *format, ...)
{
    if (gCNDAssertionProbeFD < 0) return;
    char line[4096] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDAssertionProbeFD, line, amount);
    (void)fsync(gCNDAssertionProbeFD);
}

static void CNDAssertionProbeInspectMethod(Class cls, bool classMethod,
                                           const char *selectorName)
{
    SEL selector = sel_registerName(selectorName);
    Method method = classMethod ? class_getClassMethod(cls, selector)
                                : class_getInstanceMethod(cls, selector);
    Class owner = Nil;
    if (method) {
        for (Class candidate = classMethod ? object_getClass(cls) : cls;
             candidate;
             candidate = class_getSuperclass(candidate)) {
            Method direct = classMethod
                ? class_getInstanceMethod(candidate, selector)
                : class_getInstanceMethod(candidate, selector);
            if (direct && method_getImplementation(direct) ==
                              method_getImplementation(method)) {
                owner = classMethod ? (Class)objc_getClass(class_getName(cls))
                                    : candidate;
                if (!classMethod) break;
            }
        }
    }
    CNDAssertionProbeLog(
        "[CND_ASSERTION] method class=%s kind=%c selector=%s exists=%d "
        "owner=%s encoding=%s imp=%p\n",
        cls ? class_getName(cls) : "-", classMethod ? '+' : '-', selectorName,
        method != NULL, owner ? class_getName(owner) : "-",
        method ? method_getTypeEncoding(method) : "-",
        method ? method_getImplementation(method) : NULL);
}

static id CNDAssertionProbeClassObject(Class cls, const char *selectorName)
{
    if (!cls) return nil;
    SEL selector = sel_registerName(selectorName);
    Method method = class_getClassMethod(cls, selector);
    if (!method) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(cls, selector);
}

static id CNDAssertionProbeClassUInt64(Class cls, const char *selectorName,
                                       uint64_t value)
{
    if (!cls) return nil;
    SEL selector = sel_registerName(selectorName);
    Method method = class_getClassMethod(cls, selector);
    if (!method) return nil;
    return ((id (*)(id, SEL, uint64_t))objc_msgSend)(cls, selector, value);
}

static id CNDAssertionProbeClassInt(Class cls, const char *selectorName,
                                    int value)
{
    if (!cls) return nil;
    SEL selector = sel_registerName(selectorName);
    Method method = class_getClassMethod(cls, selector);
    if (!method) return nil;
    return ((id (*)(id, SEL, int))objc_msgSend)(cls, selector, value);
}

static BOOL CNDAssertionProbeBool(id object, const char *selectorName)
{
    if (!object) return NO;
    return ((BOOL (*)(id, SEL))objc_msgSend)(
        object, sel_registerName(selectorName));
}

static uint64_t CNDAssertionProbeUInt64(id object, const char *selectorName)
{
    if (!object) return 0;
    return ((uint64_t (*)(id, SEL))objc_msgSend)(
        object, sel_registerName(selectorName));
}

static void CNDAssertionProbeLogState(const char *stage, id assertion,
                                      NSError *error)
{
    id attributes = assertion
        ? ((id (*)(id, SEL))objc_msgSend)(assertion,
                                         sel_registerName("attributes"))
        : nil;
    CNDAssertionProbeLog(
        "[CND_ASSERTION] %s assertion=%p valid=%d state=%llu "
        "error-domain=%s error-code=%lld error=%s attributes=%s "
        "description=%s\n",
        stage, (__bridge void *)assertion,
        CNDAssertionProbeBool(assertion, "isValid"),
        (unsigned long long)CNDAssertionProbeUInt64(assertion, "state"),
        error.domain.UTF8String ?: "-", (long long)error.code,
        error.localizedDescription.UTF8String ?: "-",
        [[attributes description] UTF8String] ?: "-",
        [[assertion description] UTF8String] ?: "-");
}

static id CNDAssertionProbeObject(id object, const char *selectorName)
{
    if (!object) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(
        object, sel_registerName(selectorName));
}

static unsigned char CNDAssertionProbeByte(id object,
                                           const char *selectorName)
{
    if (!object) return 0;
    return ((unsigned char (*)(id, SEL))objc_msgSend)(
        object, sel_registerName(selectorName));
}

static void CNDAssertionProbeLogProcessState(const char *stage, id target)
{
    Class handleClass = NSClassFromString(@"RBSProcessHandle");
    id identifier = CNDAssertionProbeObject(target, "processIdentifier");
    NSError *error = nil;
    id handle = handleClass && identifier
        ? ((id (*)(id, SEL, id, NSError *__autoreleasing *))objc_msgSend)(
              handleClass, sel_registerName("handleForIdentifier:error:"),
              identifier, &error)
        : nil;
    id state = CNDAssertionProbeObject(handle, "currentState");
    id primitiveAssertions =
        CNDAssertionProbeObject(state, "primitiveAssertions");
    CNDAssertionProbeLog(
        "[CND_ASSERTION] process-state stage=%s handle=%p state=%p "
        "running=%d task=%u resistance=%u cpu-role=%u primitives=%s "
        "error=%s description=%s\n",
        stage, (__bridge void *)handle, (__bridge void *)state,
        CNDAssertionProbeBool(state, "isRunning"),
        CNDAssertionProbeByte(state, "taskState"),
        CNDAssertionProbeByte(state, "terminationResistance"),
        CNDAssertionProbeByte(state, "cpuRole"),
        [[primitiveAssertions description] UTF8String] ?: "-",
        error.localizedDescription.UTF8String ?: "-",
        [[state description] UTF8String] ?: "-");
}

static void CNDAssertionProbeRun(void)
{
    gCNDAssertionProbeFD = open(CNDAssertionProbeOutputPath,
                                O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (gCNDAssertionProbeFD < 0) return;

    void *runningBoard = dlopen(
        "/System/Library/PrivateFrameworks/RunningBoardServices.framework/"
        "RunningBoardServices",
        RTLD_NOW | RTLD_LOCAL);
    CNDAssertionProbeLog(
        "[CND_ASSERTION] begin pid=%d target-pid=%d mode=%d framework=%p "
        "error=%s\n",
        getpid(), CND_SPOTLIGHT_ASSERTION_TARGET_PID,
        CND_SPOTLIGHT_ASSERTION_PROBE_MODE, runningBoard,
        runningBoard ? "-" : (dlerror() ?: "unknown"));

    Class assertionClass = NSClassFromString(@"RBSAssertion");
    Class targetClass = NSClassFromString(@"RBSTarget");
    Class resistanceClass = NSClassFromString(@"RBSResistTerminationGrant");
    Class jetsamClass = NSClassFromString(@"RBSJetsamPriorityGrant");
    Class cpuClass = NSClassFromString(@"RBSCPUAccessGrant");
    Class runningReasonClass = NSClassFromString(@"RBSRunningReasonAttribute");
    Class relativeStartClass =
        NSClassFromString(@"RBSDefineRelativeStartTimeGrant");
    Class durationClass = NSClassFromString(@"RBSDurationAttribute");
    Class handleClass = NSClassFromString(@"RBSProcessHandle");
    Class processStateClass = NSClassFromString(@"RBSProcessState");

    CNDAssertionProbeInspectMethod(
        assertionClass, false, "initWithExplanation:target:attributes:");
    CNDAssertionProbeInspectMethod(assertionClass, false, "acquireWithError:");
    CNDAssertionProbeInspectMethod(
        assertionClass, false, "invalidateSyncWithError:");
    CNDAssertionProbeInspectMethod(assertionClass, false, "invalidate");
    CNDAssertionProbeInspectMethod(assertionClass, false, "isValid");
    CNDAssertionProbeInspectMethod(assertionClass, false, "state");
    CNDAssertionProbeInspectMethod(targetClass, true, "targetWithPid:");
    CNDAssertionProbeInspectMethod(
        resistanceClass, true, "grantWithResistance:");
    CNDAssertionProbeInspectMethod(
        jetsamClass, true, "grantWithBackgroundPriority");
    CNDAssertionProbeInspectMethod(
        jetsamClass, true, "grantWithForegroundPriority");
    CNDAssertionProbeInspectMethod(cpuClass, true, "grant");
    CNDAssertionProbeInspectMethod(cpuClass, true, "grantUserInitiated");
    CNDAssertionProbeInspectMethod(
        runningReasonClass, true, "withReason:");
    CNDAssertionProbeInspectMethod(relativeStartClass, true, "grant");
    CNDAssertionProbeInspectMethod(
        durationClass, true, "invalidateAfterInterval:");
    CNDAssertionProbeInspectMethod(
        handleClass, true, "handleForIdentifier:error:");
    CNDAssertionProbeInspectMethod(handleClass, false, "currentState");
    CNDAssertionProbeInspectMethod(
        processStateClass, false, "terminationResistance");
    CNDAssertionProbeInspectMethod(processStateClass, false, "cpuRole");
    CNDAssertionProbeInspectMethod(processStateClass, false, "taskState");
    CNDAssertionProbeInspectMethod(processStateClass, false, "isRunning");
    CNDAssertionProbeInspectMethod(
        processStateClass, false, "primitiveAssertions");

    @try {
        SEL associationKey =
            sel_registerName("cnd_spotlight_noninteractive_assertion");
        NSProcessInfo *processInfo = NSProcessInfo.processInfo;
        id existing = objc_getAssociatedObject(processInfo, associationKey);
        CNDAssertionProbeLogState("retained-before", existing, nil);

        id target = CNDAssertionProbeClassInt(
            targetClass, "targetWithPid:", CND_SPOTLIGHT_ASSERTION_TARGET_PID);
        CNDAssertionProbeLogProcessState("before", target);
        id resistance = CNDAssertionProbeClassUInt64(
            resistanceClass, "grantWithResistance:", 30U);
        id backgroundPriority = CNDAssertionProbeClassObject(
            jetsamClass, "grantWithBackgroundPriority");
        id cpu = CNDAssertionProbeClassObject(cpuClass, "grant");
        id runningReason = CNDAssertionProbeClassUInt64(
            runningReasonClass, "withReason:", 0x2713U);
        id relativeStart = CNDAssertionProbeClassObject(relativeStartClass,
                                                        "grant");
        NSArray *objects = @[ resistance ?: NSNull.null,
                              backgroundPriority ?: NSNull.null,
                              cpu ?: NSNull.null,
                              runningReason ?: NSNull.null,
                              relativeStart ?: NSNull.null ];
        CNDAssertionProbeLog(
            "[CND_ASSERTION] objects target=%p target-desc=%s "
            "candidate-attributes=%s\n",
            (__bridge void *)target,
            [[target description] UTF8String] ?: "-",
            objects.description.UTF8String ?: "-");

        if (CND_SPOTLIGHT_ASSERTION_PROBE_MODE == 3) {
            NSError *error = nil;
            BOOL invalidated = existing
                ? ((BOOL (*)(id, SEL, NSError *__autoreleasing *))objc_msgSend)(
                      existing, sel_registerName("invalidateSyncWithError:"),
                      &error)
                : YES;
            CNDAssertionProbeLog(
                "[CND_ASSERTION] release-result invalidated=%d\n",
                invalidated);
            CNDAssertionProbeLogState("release-state", existing, error);
            objc_setAssociatedObject(processInfo, associationKey, nil,
                                     OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            CNDAssertionProbeLogState(
                "retained-after-release",
                objc_getAssociatedObject(processInfo, associationKey), nil);
        } else if (CND_SPOTLIGHT_ASSERTION_PROBE_MODE == 2) {
            CNDAssertionProbeLogState("status", existing, nil);
        } else {
            id assertion = nil;
            if (assertionClass && target && resistance) {
                NSArray *attributes =
                    CND_SPOTLIGHT_ASSERTION_PROBE_MODE == 4 &&
                            backgroundPriority
                        ? @[ resistance, backgroundPriority ]
                        : @[ resistance ];
                assertion = ((id (*)(id, SEL, id, id, id))objc_msgSend)(
                    ((id (*)(id, SEL))objc_msgSend)(
                        assertionClass, sel_registerName("alloc")),
                    sel_registerName("initWithExplanation:target:attributes:"),
                    CND_SPOTLIGHT_ASSERTION_PROBE_MODE == 4
                        ? @"Cyanide Spotlight background-priority lifetime probe"
                        : @"Cyanide Spotlight noninteractive lifetime probe",
                    target, attributes);
            }
            CNDAssertionProbeLogState("constructed", assertion, nil);
            if ((CND_SPOTLIGHT_ASSERTION_PROBE_MODE == 1 ||
                 CND_SPOTLIGHT_ASSERTION_PROBE_MODE == 4) && assertion) {
                if (existing) {
                    ((void (*)(id, SEL))objc_msgSend)(
                        existing, sel_registerName("invalidate"));
                    objc_setAssociatedObject(
                        processInfo, associationKey, nil,
                        OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                }
                NSError *error = nil;
                BOOL acquired = ((BOOL (*)(
                    id, SEL, NSError *__autoreleasing *))objc_msgSend)(
                        assertion, sel_registerName("acquireWithError:"),
                        &error);
                CNDAssertionProbeLog(
                    "[CND_ASSERTION] acquire-result acquired=%d\n", acquired);
                CNDAssertionProbeLogState("acquired", assertion, error);
                if (acquired && CNDAssertionProbeBool(assertion, "isValid")) {
                    objc_setAssociatedObject(
                        processInfo, associationKey, assertion,
                        OBJC_ASSOCIATION_RETAIN_NONATOMIC);
                } else {
                    ((void (*)(id, SEL))objc_msgSend)(
                        assertion, sel_registerName("invalidate"));
                }
                CNDAssertionProbeLogState(
                    "retained-after-acquire",
                    objc_getAssociatedObject(processInfo, associationKey), nil);
            } else if (assertion) {
                ((void (*)(id, SEL))objc_msgSend)(
                    assertion, sel_registerName("invalidate"));
            }
        }
        CNDAssertionProbeLogProcessState("after", target);
    } @catch (NSException *exception) {
        CNDAssertionProbeLog(
            "[CND_ASSERTION] exception name=%s reason=%s\n",
            exception.name.UTF8String ?: "-",
            exception.reason.UTF8String ?: "-");
    }

    CNDAssertionProbeLog("[CND_ASSERTION] COMPLETE mode=%d\n",
                         CND_SPOTLIGHT_ASSERTION_PROBE_MODE);
    (void)close(gCNDAssertionProbeFD);
    gCNDAssertionProbeFD = -1;
}

__attribute__((constructor)) static void CNDAssertionProbeStart(void)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        CNDAssertionProbeRun();
    });
}
