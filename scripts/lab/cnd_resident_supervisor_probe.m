#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/fileport.h>
#include <time.h>
#include <unistd.h>

#ifndef CND_RESIDENT_SUPERVISOR_OUTPUT_TOKEN
#define CND_RESIDENT_SUPERVISOR_OUTPUT_TOKEN ""
#endif

#ifndef CND_RESIDENT_SUPERVISOR_NONCE
#define CND_RESIDENT_SUPERVISOR_NONCE "0"
#endif

static const char *const CNDResidentReportPath =
    "/var/tmp/cyanide-resident-supervisor.log";
static const char *const CNDResidentHeartbeatPath =
    "/var/tmp/cyanide-resident-supervisor.heartbeat";
static const char *const CNDResidentStopPath =
    "/var/tmp/cyanide-resident-supervisor.stop";
static const char *const CNDResidentSimulatePath =
    "/var/tmp/cyanide-resident-supervisor.simulate";
static const char *const CNDResidentRelaunchSpotlightPath =
    "/var/tmp/cyanide-resident-supervisor.relaunch-spotlight";
static const char *const CNDResidentFileportPath =
    "/var/tmp/cyanide-resident-supervisor.fileport";

extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_look_up(
    mach_port_t bootstrap, const char *service_name, mach_port_t *service_port);

static int gCNDResidentReportFD = -1;
static int gCNDResidentHeartbeatFD = -1;
static pthread_mutex_t gCNDResidentLogLock = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool gCNDResidentRunning = ATOMIC_VAR_INIT(false);
static atomic_ullong gCNDResidentHeartbeat = ATOMIC_VAR_INIT(0);
static id gCNDResidentObserver;
static id gCNDResidentProcessManager;
static id gCNDResidentWorkspace;
static NSMutableDictionary<NSString *, NSString *> *gCNDFingerprintSamples;
static NSMutableDictionary<NSString *, NSNumber *> *gCNDFingerprintGeneration;

static const char *CNDResidentQueueLabel(void)
{
    const char *label = dispatch_queue_get_label(DISPATCH_CURRENT_QUEUE_LABEL);
    return label && label[0] ? label : "-";
}

static void CNDResidentLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDResidentLog(const char *format, ...)
{
    if (gCNDResidentReportFD < 0) return;
    char line[4096] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = MIN((size_t)length, sizeof(line) - 1U);
    pthread_mutex_lock(&gCNDResidentLogLock);
    (void)write(gCNDResidentReportFD, line, amount);
    (void)fsync(gCNDResidentReportFD);
    pthread_mutex_unlock(&gCNDResidentLogLock);
}

static id CNDResidentSendObject0(id object, const char *selectorName)
{
    if (!object || !selectorName) return nil;
    SEL selector = sel_registerName(selectorName);
    if (![object respondsToSelector:selector]) return nil;
    @try {
        return ((id (*)(id, SEL))objc_msgSend)(object, selector);
    } @catch (__unused NSException *exception) {
        return nil;
    }
}

static void CNDResidentSendVoid1(id object, const char *selectorName,
                                 id argument)
{
    if (!object || !selectorName) return;
    SEL selector = sel_registerName(selectorName);
    if (![object respondsToSelector:selector]) return;
    @try {
        ((void (*)(id, SEL, id))objc_msgSend)(object, selector, argument);
    } @catch (__unused NSException *exception) {
    }
}

static long long CNDResidentSendInteger0(id object, const char *selectorName,
                                         bool *validOut)
{
    if (validOut) *validOut = false;
    if (!object || !selectorName) return 0;
    SEL selector = sel_registerName(selectorName);
    Method method = class_getInstanceMethod(object_getClass(object), selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return 0;
    char *returnType = method_copyReturnType(method);
    const char *type = returnType;
    while (type && *type && strchr("rnNoORV", *type)) type++;
    bool accepted = type && *type && strchr("cCsSiIlLqQB", *type);
    free(returnType);
    if (!accepted) return 0;
    @try {
        long long value =
            ((long long (*)(id, SEL))objc_msgSend)(object, selector);
        if (validOut) *validOut = true;
        return value;
    } @catch (__unused NSException *exception) {
        return 0;
    }
}

static NSString *CNDResidentText(id value)
{
    if ([value isKindOfClass:NSString.class]) return value;
    if ([value isKindOfClass:NSNumber.class] ||
        [value isKindOfClass:NSDate.class] ||
        [value isKindOfClass:NSUUID.class] ||
        [value isKindOfClass:NSURL.class]) {
        return [value description] ?: @"";
    }
    return @"";
}

static NSString *CNDResidentPropertyText(id object, const char *name)
{
    return CNDResidentText(CNDResidentSendObject0(object, name));
}

static void CNDResidentLogMethod(Class owner, const char *selectorName,
                                 bool classMethod)
{
    SEL selector = sel_registerName(selectorName);
    Method method = classMethod
        ? class_getClassMethod(owner, selector)
        : class_getInstanceMethod(owner, selector);
    CNDResidentLog(
        "[CND_RESIDENT] ABI owner=%s selector=%s kind=%s types=%s imp=%p\n",
        owner ? class_getName(owner) : "-", selectorName,
        classMethod ? "class" : "instance",
        method ? method_getTypeEncoding(method) : "-",
        method ? method_getImplementation(method) : NULL);
}

static BOOL CNDResidentIsSpotlightProcess(id process)
{
    NSString *name = CNDResidentPropertyText(process, "name");
    NSString *path = CNDResidentPropertyText(process, "executablePath");
    NSString *bundle = CNDResidentPropertyText(process, "bundleIdentifier");
    return [name isEqualToString:@"Spotlight"] ||
        [path hasSuffix:@"/Applications/Spotlight.app/Spotlight"] ||
        [bundle caseInsensitiveCompare:@"com.apple.Spotlight"] ==
            NSOrderedSame;
}

static void CNDResidentSampleSpotlight(id process, const char *source,
                                       unsigned sample)
{
    bool pidValid = false;
    bool finishedValid = false;
    long long pid = CNDResidentSendInteger0(process, "pid", &pidValid);
    long long finished = CNDResidentSendInteger0(
        process, "finishedLaunching", &finishedValid);
    NSString *name = CNDResidentPropertyText(process, "name");
    NSString *path = CNDResidentPropertyText(process, "executablePath");
    CNDResidentLog(
        "[CND_RESIDENT] SPOTLIGHT_SAMPLE source=%s sample=%u pid=%lld "
        "pidValid=%d finished=%lld finishedValid=%d name=%s path=%s "
        "queue=%s\n",
        source ?: "-", sample, pid, pidValid ? 1 : 0, finished,
        finishedValid ? 1 : 0, name.UTF8String ?: "-",
        path.UTF8String ?: "-", CNDResidentQueueLabel());
}

static void CNDResidentScheduleSpotlightSettle(id process,
                                                const char *source)
{
    if (!CNDResidentIsSpotlightProcess(process)) return;
    CNDResidentSampleSpotlight(process, source, 0);
    __weak id weakProcess = process;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(200 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{
        id first = weakProcess;
        if (!first || !atomic_load_explicit(
                &gCNDResidentRunning, memory_order_acquire)) return;
        CNDResidentSampleSpotlight(first, source, 1);
        bool pidValid = false;
        long long pid = CNDResidentSendInteger0(first, "pid", &pidValid);
        id current = nil;
        /* processForPID: takes an integer; do not route it through a generic
         * object-argument helper because that silently violates the ABI. */
        if (pidValid && gCNDResidentProcessManager &&
            [gCNDResidentProcessManager respondsToSelector:
                sel_registerName("processForPID:")]) {
            current = ((id (*)(id, SEL, int))objc_msgSend)(
                gCNDResidentProcessManager, sel_registerName("processForPID:"),
                (int)pid);
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)(100 * NSEC_PER_MSEC)),
                       dispatch_get_main_queue(), ^{
            if (!current || !atomic_load_explicit(
                    &gCNDResidentRunning, memory_order_acquire)) return;
            bool secondPIDValid = false;
            long long secondPID = CNDResidentSendInteger0(
                current, "pid", &secondPIDValid);
            CNDResidentSampleSpotlight(current, source, 2);
            CNDResidentLog(
                "[CND_RESIDENT] SPOTLIGHT_SETTLED source=%s pid=%lld "
                "stable=%d queue=%s\n",
                source ?: "-", pid,
                pidValid && secondPIDValid && pid == secondPID ? 1 : 0,
                CNDResidentQueueLabel());
        });
    });
}

static NSString *CNDResidentFingerprint(NSString *bundleIdentifier)
{
    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    id proxy = proxyClass ? ((id (*)(id, SEL, id))objc_msgSend)(
        proxyClass, sel_registerName("applicationProxyForIdentifier:"),
        bundleIdentifier) : nil;
    if (!proxy) return @"";
    id bundleURL = CNDResidentSendObject0(proxy, "bundleURL");
    NSString *path = CNDResidentPropertyText(bundleURL, "path");
    NSString *shortVersion = CNDResidentPropertyText(
        proxy, "shortVersionString");
    NSString *externalVersion = CNDResidentPropertyText(
        proxy, "externalVersionIdentifier");
    NSString *registeredDate = CNDResidentPropertyText(
        proxy, "registeredDate");
    bool modTimeValid = false;
    long long modTime = CNDResidentSendInteger0(
        proxy, "bundleModTime", &modTimeValid);
    return [NSString stringWithFormat:
        @"%@|%@|%@|%@|%lld/%d", path ?: @"", shortVersion ?: @"",
        externalVersion ?: @"", registeredDate ?: @"", modTime,
        modTimeValid ? 1 : 0];
}

static void CNDResidentScheduleFingerprint(NSString *bundleIdentifier,
                                           const char *source)
{
    if (bundleIdentifier.length == 0) return;
    NSNumber *oldGeneration = gCNDFingerprintGeneration[bundleIdentifier];
    NSUInteger generation = oldGeneration.unsignedIntegerValue + 1U;
    gCNDFingerprintGeneration[bundleIdentifier] = @(generation);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(250 * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{
        if ([gCNDFingerprintGeneration[bundleIdentifier]
                unsignedIntegerValue] != generation) return;
        NSString *first = CNDResidentFingerprint(bundleIdentifier);
        gCNDFingerprintSamples[bundleIdentifier] = first ?: @"";
        CNDResidentLog(
            "[CND_RESIDENT] APP_FINGERPRINT source=%s bundle=%s sample=1 "
            "available=%d value=%s queue=%s\n",
            source ?: "-", bundleIdentifier.UTF8String ?: "-",
            first.length > 0 ? 1 : 0, first.UTF8String ?: "-",
            CNDResidentQueueLabel());
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)(250 * NSEC_PER_MSEC)),
                       dispatch_get_main_queue(), ^{
            if ([gCNDFingerprintGeneration[bundleIdentifier]
                    unsignedIntegerValue] != generation) return;
            NSString *second = CNDResidentFingerprint(bundleIdentifier);
            NSString *saved = gCNDFingerprintSamples[bundleIdentifier] ?: @"";
            BOOL stable = saved.length > 0 && [saved isEqualToString:second];
            CNDResidentLog(
                "[CND_RESIDENT] APP_FINGERPRINT source=%s bundle=%s "
                "sample=2 available=%d stable=%d value=%s queue=%s\n",
                source ?: "-", bundleIdentifier.UTF8String ?: "-",
                second.length > 0 ? 1 : 0, stable ? 1 : 0,
                second.UTF8String ?: "-", CNDResidentQueueLabel());
        });
    });
}

static NSArray<NSString *> *CNDResidentBundleIdentifiers(id value)
{
    NSArray *values = [value isKindOfClass:NSArray.class] ? value :
        (value ? @[value] : @[]);
    NSMutableOrderedSet<NSString *> *identifiers =
        [NSMutableOrderedSet orderedSet];
    for (id item in values) {
        NSString *identifier = [item isKindOfClass:NSString.class]
            ? item : CNDResidentPropertyText(item, "applicationIdentifier");
        if (identifier.length == 0) {
            identifier = CNDResidentPropertyText(item, "bundleIdentifier");
        }
        if (identifier.length > 0) [identifiers addObject:identifier];
    }
    return identifiers.array;
}

@interface CNDResidentSupervisorObserver : NSObject
@end

@implementation CNDResidentSupervisorObserver

- (void)processManager:(id)manager didAddProcess:(id)process
{
    (void)manager;
    CNDResidentLog(
        "[CND_RESIDENT] FB_ADD class=%s spotlight=%d queue=%s\n",
        process ? class_getName(object_getClass(process)) : "-",
        CNDResidentIsSpotlightProcess(process) ? 1 : 0,
        CNDResidentQueueLabel());
    CNDResidentScheduleSpotlightSettle(process, "frontboard-add");
}

- (void)processManager:(id)manager didRemoveProcess:(id)process
{
    (void)manager;
    if (!CNDResidentIsSpotlightProcess(process)) return;
    bool valid = false;
    long long pid = CNDResidentSendInteger0(process, "pid", &valid);
    CNDResidentLog(
        "[CND_RESIDENT] FB_REMOVE spotlight=1 pid=%lld valid=%d queue=%s\n",
        pid, valid ? 1 : 0, CNDResidentQueueLabel());
}

- (void)applicationInstallsDidChange:(id)applications
{
    NSArray<NSString *> *identifiers =
        CNDResidentBundleIdentifiers(applications);
    CNDResidentLog(
        "[CND_RESIDENT] LS_CHANGE count=%lu argumentClass=%s queue=%s\n",
        (unsigned long)identifiers.count,
        applications ? class_getName(object_getClass(applications)) : "-",
        CNDResidentQueueLabel());
}

- (void)applicationsDidInstall:(id)applications
{
    NSArray<NSString *> *identifiers =
        CNDResidentBundleIdentifiers(applications);
    CNDResidentLog(
        "[CND_RESIDENT] LS_DID_INSTALL count=%lu argumentClass=%s queue=%s\n",
        (unsigned long)identifiers.count,
        applications ? class_getName(object_getClass(applications)) : "-",
        CNDResidentQueueLabel());
    for (NSString *identifier in identifiers) {
        CNDResidentScheduleFingerprint(identifier, "ls-did-install");
    }
}

- (void)applicationsDidUninstall:(id)applications
{
    NSArray<NSString *> *identifiers =
        CNDResidentBundleIdentifiers(applications);
    CNDResidentLog(
        "[CND_RESIDENT] LS_DID_UNINSTALL count=%lu queue=%s\n",
        (unsigned long)identifiers.count, CNDResidentQueueLabel());
}

@end

static void CNDResidentWriteHeartbeat(void)
{
    unsigned long long heartbeat = atomic_fetch_add_explicit(
        &gCNDResidentHeartbeat, 1, memory_order_relaxed) + 1ULL;
    char snapshot[512] = {0};
    int length = snprintf(
        snapshot, sizeof(snapshot),
        "[CND_RESIDENT] HEARTBEAT pid=%d count=%llu nonce=%s\n",
        getpid(), heartbeat, CND_RESIDENT_SUPERVISOR_NONCE);
    if (length <= 0 || gCNDResidentHeartbeatFD < 0) return;
    size_t amount = MIN((size_t)length, sizeof(snapshot) - 1U);
    (void)pwrite(gCNDResidentHeartbeatFD, snapshot, amount, 0);
    (void)ftruncate(gCNDResidentHeartbeatFD, (off_t)amount);
    (void)fsync(gCNDResidentHeartbeatFD);
}

static void CNDResidentTruncateCommand(const char *path)
{
    int descriptor = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (descriptor >= 0) (void)close(descriptor);
}

static void CNDResidentRunFileportProbe(void)
{
    NSData *data = [NSData dataWithContentsOfFile:
        [NSString stringWithUTF8String:CNDResidentFileportPath]];
    NSString *command = data.length > 0
        ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
        : nil;
    CNDResidentTruncateCommand(CNDResidentFileportPath);
    NSArray<NSString *> *lines = [command componentsSeparatedByString:@"\n"];
    if (lines.count < 3 || lines[0].length == 0 ||
        lines[1].length == 0 || lines[2].length == 0) return;
    NSString *service = lines[0];
    NSString *expected = lines[1];
    NSString *token = lines[2];
    typedef int64_t (*ConsumeFunction)(const char *);
    ConsumeFunction consume = (ConsumeFunction)dlsym(
        RTLD_DEFAULT, "sandbox_extension_consume");
    int64_t tokenHandle = consume ? consume(token.UTF8String) : -1;
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t lookup = tokenHandle >= 0
        ? bootstrap_look_up(bootstrap_port, service.UTF8String, &port)
        : KERN_NO_ACCESS;
    int descriptor = lookup == KERN_SUCCESS && port != MACH_PORT_NULL
        ? fileport_makefd(port) : -1;
    if (port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), port);
    }
    char observed[256] = {0};
    ssize_t amount = descriptor >= 0
        ? pread(descriptor, observed, sizeof(observed) - 1U, 0) : -1;
    if (descriptor >= 0) close(descriptor);
    BOOL match = amount == (ssize_t)strlen(expected.UTF8String) &&
        memcmp(observed, expected.UTF8String, (size_t)amount) == 0;
    CNDResidentLog(
        "[CND_RESIDENT] FILEPORT_RECOVERY service=%s token=%lld "
        "lookup=%d fd=%d bytes=%lld match=%d queue=%s\n",
        service.UTF8String ?: "-", (long long)tokenHandle, lookup,
        descriptor, (long long)amount, match ? 1 : 0,
        CNDResidentQueueLabel());
}

static void CNDResidentStopOnMainQueue(void)
{
    CNDResidentSendVoid1(gCNDResidentProcessManager, "removeObserver:",
                         gCNDResidentObserver);
    CNDResidentSendVoid1(gCNDResidentWorkspace, "removeObserver:",
                         gCNDResidentObserver);
    atomic_store_explicit(&gCNDResidentRunning, false,
                          memory_order_release);
    CNDResidentLog(
        "[CND_RESIDENT] STOPPED pid=%d heartbeat=%llu queue=%s\n",
        getpid(), atomic_load_explicit(&gCNDResidentHeartbeat,
                                      memory_order_relaxed),
        CNDResidentQueueLabel());
}

static void *CNDResidentHeartbeatMain(void *argument)
{
    (void)argument;
    while (atomic_load_explicit(&gCNDResidentRunning,
                                memory_order_acquire)) {
        @autoreleasepool {
            CNDResidentWriteHeartbeat();
            if (access(CNDResidentSimulatePath, F_OK) == 0) {
                NSData *data = [NSData dataWithContentsOfFile:
                    [NSString stringWithUTF8String:CNDResidentSimulatePath]];
                NSString *identifier = data.length > 0
                    ? [[NSString alloc] initWithData:data
                                            encoding:NSUTF8StringEncoding]
                    : nil;
                identifier = [identifier stringByTrimmingCharactersInSet:
                    NSCharacterSet.whitespaceAndNewlineCharacterSet];
                CNDResidentTruncateCommand(CNDResidentSimulatePath);
                if (identifier.length > 0 && identifier.length <= 255) {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        CNDResidentLog(
                            "[CND_RESIDENT] SIMULATED_UPDATE bundle=%s "
                            "queue=%s\n", identifier.UTF8String ?: "-",
                            CNDResidentQueueLabel());
                        CNDResidentScheduleFingerprint(
                            identifier, "simulated-update");
                    });
                }
            }
            if (access(CNDResidentRelaunchSpotlightPath, F_OK) == 0) {
                struct stat status = {0};
                if (stat(CNDResidentRelaunchSpotlightPath, &status) == 0 &&
                    status.st_size > 0) {
                    CNDResidentTruncateCommand(
                        CNDResidentRelaunchSpotlightPath);
                    dispatch_async(dispatch_get_main_queue(), ^{
                        SEL selector = sel_registerName(
                            "openApplicationWithBundleID:");
                        BOOL opened = gCNDResidentWorkspace &&
                            [gCNDResidentWorkspace
                                respondsToSelector:selector] &&
                            ((BOOL (*)(id, SEL, id))objc_msgSend)(
                                gCNDResidentWorkspace, selector,
                                @"com.apple.Spotlight");
                        CNDResidentLog(
                            "[CND_RESIDENT] SPOTLIGHT_RELAUNCH "
                            "accepted=%d queue=%s\n", opened ? 1 : 0,
                            CNDResidentQueueLabel());
                    });
                }
            }
            if (access(CNDResidentFileportPath, F_OK) == 0) {
                struct stat status = {0};
                if (stat(CNDResidentFileportPath, &status) == 0 &&
                    status.st_size > 0) {
                    CNDResidentRunFileportProbe();
                }
            }
            if (access(CNDResidentStopPath, F_OK) == 0) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    CNDResidentStopOnMainQueue();
                });
                return NULL;
            }
        }
        sleep(1);
    }
    return NULL;
}

static void CNDResidentInstall(void)
{
    gCNDFingerprintSamples = [NSMutableDictionary dictionary];
    gCNDFingerprintGeneration = [NSMutableDictionary dictionary];
    gCNDResidentObserver = [[CNDResidentSupervisorObserver alloc] init];

    Class managerClass = NSClassFromString(@"FBProcessManager");
    Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
    CNDResidentLogMethod(managerClass, "sharedInstance", true);
    CNDResidentLogMethod(managerClass, "addObserver:", false);
    CNDResidentLogMethod(managerClass, "removeObserver:", false);
    CNDResidentLogMethod(managerClass, "processForPID:", false);
    CNDResidentLogMethod(NSClassFromString(@"FBProcess"), "pid", false);
    CNDResidentLogMethod(NSClassFromString(@"FBProcess"), "name", false);
    CNDResidentLogMethod(NSClassFromString(@"FBProcess"),
                         "finishedLaunching", false);
    CNDResidentLogMethod(workspaceClass, "defaultWorkspace", true);
    CNDResidentLogMethod(workspaceClass, "addObserver:", false);
    CNDResidentLogMethod(workspaceClass, "removeObserver:", false);
    CNDResidentLogMethod(CNDResidentSupervisorObserver.class,
                         "processManager:didAddProcess:", false);
    CNDResidentLogMethod(CNDResidentSupervisorObserver.class,
                         "processManager:didRemoveProcess:", false);
    CNDResidentLogMethod(CNDResidentSupervisorObserver.class,
                         "applicationInstallsDidChange:", false);
    CNDResidentLogMethod(CNDResidentSupervisorObserver.class,
                         "applicationsDidInstall:", false);

    gCNDResidentProcessManager = managerClass
        ? ((id (*)(id, SEL))objc_msgSend)(
            managerClass, sel_registerName("sharedInstance")) : nil;
    gCNDResidentWorkspace = workspaceClass
        ? ((id (*)(id, SEL))objc_msgSend)(
            workspaceClass, sel_registerName("defaultWorkspace")) : nil;
    CNDResidentSendVoid1(gCNDResidentProcessManager, "addObserver:",
                         gCNDResidentObserver);
    CNDResidentSendVoid1(gCNDResidentWorkspace, "addObserver:",
                         gCNDResidentObserver);

    NSArray *processes = CNDResidentSendObject0(
        gCNDResidentProcessManager, "allProcesses");
    NSUInteger spotlightCount = 0;
    for (id process in [processes isKindOfClass:NSArray.class]
             ? processes : @[]) {
        if (!CNDResidentIsSpotlightProcess(process)) continue;
        spotlightCount++;
        CNDResidentScheduleSpotlightSettle(process, "initial-scan");
    }
    CNDResidentLog(
        "[CND_RESIDENT] READY pid=%d nonce=%s main=%d manager=%d "
        "workspace=%d initialSpotlight=%lu queue=%s\n",
        getpid(), CND_RESIDENT_SUPERVISOR_NONCE,
        [NSThread isMainThread] ? 1 : 0,
        gCNDResidentProcessManager ? 1 : 0,
        gCNDResidentWorkspace ? 1 : 0,
        (unsigned long)spotlightCount, CNDResidentQueueLabel());

    pthread_t thread = NULL;
    int createResult = pthread_create(
        &thread, NULL, CNDResidentHeartbeatMain, NULL);
    int detachResult = createResult == 0
        ? pthread_detach(thread) : createResult;
    CNDResidentLog(
        "[CND_RESIDENT] THREAD create=%d detach=%d thread=%p\n",
        createResult, detachResult, (void *)thread);
    if (createResult != 0 || detachResult != 0) {
        CNDResidentStopOnMainQueue();
    }
}

__attribute__((constructor))
static void CNDResidentSupervisorStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_RESIDENT_SUPERVISOR_OUTPUT_TOKEN[0] && consume
            ? consume(CND_RESIDENT_SUPERVISOR_OUTPUT_TOKEN) : -1;
        gCNDResidentReportFD = open(
            CNDResidentReportPath,
            O_CREAT | O_TRUNC | O_WRONLY | O_APPEND | O_CLOEXEC, 0644);
        gCNDResidentHeartbeatFD = open(
            CNDResidentHeartbeatPath,
            O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0644);
        if (gCNDResidentReportFD < 0 || gCNDResidentHeartbeatFD < 0) return;
        (void)unlink(CNDResidentStopPath);
        (void)unlink(CNDResidentSimulatePath);
        (void)unlink(CNDResidentRelaunchSpotlightPath);
        (void)unlink(CNDResidentFileportPath);
        atomic_store_explicit(&gCNDResidentRunning, true,
                              memory_order_release);
        CNDResidentLog(
            "[CND_RESIDENT] START pid=%d token=%lld nonce=%s main=%d "
            "queue=%s\n", getpid(), (long long)token,
            CND_RESIDENT_SUPERVISOR_NONCE,
            [NSThread isMainThread] ? 1 : 0, CNDResidentQueueLabel());
        dispatch_async(dispatch_get_main_queue(), ^{
            CNDResidentInstall();
        });
    }
}
