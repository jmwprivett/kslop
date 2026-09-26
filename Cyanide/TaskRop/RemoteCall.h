//
//  RemoteCall.h
//  Cyanide
//
//  Created by seo on 3/29/26.
//

#ifndef RemoteCall_h
#define RemoteCall_h

#import <mach/mach.h>
#ifdef __OBJC__
#import <Foundation/Foundation.h>
#endif

struct VMShmem {
    uint64_t port;
    uint64_t remoteAddress;
    uint64_t localAddress;
    bool     used;
};

// from Duy Tran's TaskPortHaxxApp
// https://github.com/khanhduytran0/TaskPortHaxxApp/blob/pacbypass/TaskPortHaxxApp/Header.h#L83
typedef struct {
    uint64_t __x[29];       /* General purpose registers x0-x28 */
    uint64_t __fp; /* Frame pointer x29 */
    uint64_t __lr; /* Link register x30 */
    uint64_t __sp; /* Stack pointer x31 */
    uint64_t __pc; /* Program counter */
    uint32_t __cpsr;        /* Current program status register */
    uint32_t __flags; /* Flags describing structure format */
} arm_thread_state64_internal;

typedef enum {
    RemoteCallInitFailureNone = 0,
    RemoteCallInitFailureKRWUnavailable,
    RemoteCallInitFailureProcessMissing,
    RemoteCallInitFailureInvalidTask,
    RemoteCallInitFailureExceptionPort,
    RemoteCallInitFailureTaskGuard,
    RemoteCallInitFailureLocalThread,
    RemoteCallInitFailureNoTargetThreads,
    RemoteCallInitFailureFirstExceptionTimeout,
    RemoteCallInitFailureOther,
} RemoteCallInitFailure;

typedef struct {
    bool hasLocalState;
    bool success;
    bool labBackend;
    int pid;
    uint64_t procAddr;
    uint64_t taskAddr;
    uint64_t vmMap;
    uint64_t trojanThreadAddr;
    uint64_t trojanMem;
    uint64_t stableCalls;
    uint64_t stableFailures;
    uint64_t ioFailures;
    uint64_t shmemUsed;
    uint64_t shmemEvictions;
    uint64_t shmemClock;
    char lastStableCall[64];
    char lastStableFailure[64];
    char lastStableFailureReason[96];
} RemoteCallDebugSnapshot;

// Result of the terminal, one-way owner self-termination request.  Dispatch
// possible means the exact bound session accepted the request for dispatch;
// it never means that the process has exited.  The caller must prove owner
// exit independently before abandoning this RemoteCall session.
typedef enum {
    RemoteCallTerminalDispatchRejected = 0,
    RemoteCallTerminalDispatchPossible = 1,
} RemoteCallTerminalDispatchStatus;

typedef struct {
    RemoteCallTerminalDispatchStatus status;
    bool sessionBound;
    bool expectedPIDBound;
    bool expectedProcBound;
    bool expectedTaskBound;
    bool liveKernelIdentityBound;
    bool transportHealthy;
    bool killSymbolResolved;
    bool oneWayDispatched;
    // Always false: dispatch does not wait for or establish owner exit.
    bool ownerExitProven;
    int expectedPID;
    int currentPID;
    uint64_t expectedProc;
    uint64_t currentProc;
    uint64_t expectedTask;
    uint64_t currentTask;
    char reason[160];
} RemoteCallTerminalDispatchReport;

mach_port_t create_exception_port(void);
int disable_excguard_kill(uint64_t task);
// One-shot override consumed by the next call to init_remote_call. When
// non-zero, init_remote_call skips its proc_find_by_name lookup and uses
// this kernel proc address directly. Useful when there are multiple
// processes with the same name (e.g. system vs per-user cfprefsd) and we
// need to target a specific one. Reset to 0 by init_remote_call.
extern uint64_t g_RC_targetProcOverride;
int init_remote_call(const char* process, bool useMigFilterBypass);
int init_remote_call_with_first_exception_timeout(const char* process, bool useMigFilterBypass, int firstExceptionTimeoutMS);
int init_remote_call_original_thread_only_with_first_exception_timeout(const char* process, bool useMigFilterBypass, int firstExceptionTimeoutMS);
uint64_t do_remote_call_stable(int timeout, const char *name, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7);
uint64_t do_remote_call_stable_addr(int timeout, uint64_t pcAddr, const char *name, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7);
void sign_state(uint64_t signingThread, arm_thread_state64_internal *state, uint64_t pc, uint64_t lr);
uint64_t remote_pac(uint64_t remoteThreadAddr, uint64_t address, uint64_t modifier);
bool remote_read(uint64_t src, void *dst, uint64_t size);
uint64_t remote_read64(uint64_t src);
void remote_hexdump(uint64_t remoteAddr, size_t size);
bool remote_write(uint64_t dst, const void *src, uint64_t size);
bool remote_write64(uint64_t dst, uint64_t val);
bool remote_writeStr(uint64_t dst, const char *str);
uint64_t remote_call_trojan_mem(void);
int destroy_remote_call(void);
// Drop every piece of local RemoteCall state without trying to IPC the remote
// task. Use this when the remote task is known dead (e.g. SpringBoard just
// crashed and respawned) — destroy_remote_call would otherwise hang for
// 100s on its munmap/pthread_exit calls into a vanished trojan thread.
void abandon_remote_call(void);
bool remote_call_has_local_state(void);
bool remote_call_current_success(void);
// True when the VM-only marker is visible on a VPHONE guest, whether or not a
// target session has connected yet. Callers use this only to bypass their own
// pre-RemoteCall KRW gate; RemoteCall still authenticates the target socket.
bool remote_call_lab_backend_opted_in(void);
// Consumes the VM harness's fresh read/write extension for installed app
// bundles. It is unavailable outside the explicit VPHONE marker path.
bool remote_call_lab_prepare_bundle_access(void);
// Copies the root harness's resolved proof-target bundle path. The caller must
// still validate the path and target identity before using it.
bool remote_call_lab_copy_target_bundle_path(char *path, size_t pathSize);
// True only while this session is using the explicit vPhone root-harness
// transport. Kernel proc/task identity is intentionally unavailable there.
bool remote_call_uses_lab_backend(void);
uint64_t remote_call_current_io_failure_count(void);
int remote_call_current_pid(void);
uint64_t remote_call_current_proc(void);
uint64_t remote_call_current_task(void);
int remote_call_set_stable_timeout_floor_ms(int timeoutMS);
bool remote_call_copy_debug_snapshot(RemoteCallDebugSnapshot *outSnapshot);
// Copies the register state captured before RemoteCall temporarily redirected
// the original target thread. The target thread is restored before normal
// stable calls begin; this accessor is observation-only.
bool remote_call_copy_original_thread_state(
    arm_thread_state64_internal *outState);
// Copies every pre-hijack target-thread state that was already delivered
// while RemoteCall established the session. No new exception is injected and
// no target state is changed by this accessor.
size_t remote_call_copy_original_thread_states(
    arm_thread_state64_internal *outStates, size_t capacity);
void remote_call_clear_shmem_cache_public(const char *reason);
// Dispatches a target self-kill only for the currently active session whose
// PID/proc/task exactly match the supplied identity.  This uses the existing
// negative-timeout one-way call and never waits for return or proves exit.
RemoteCallTerminalDispatchStatus remote_call_dispatch_self_sigkill(
    int expectedPID,
    uint64_t expectedProc,
    uint64_t expectedTask,
    RemoteCallTerminalDispatchReport *reportOut);
RemoteCallInitFailure remote_call_last_init_failure(void);
uint32_t remote_call_last_init_failure_pid(void);
const char *remote_call_init_failure_description(RemoteCallInitFailure failure);

#ifdef __OBJC__
@class RemotePointer;

@interface RemoteCallSession : NSObject

@property(nonatomic, readonly) uint64_t taskAddr;
@property(nonatomic, readonly) uint64_t trojanMem;
@property(nonatomic, readonly) int pid;

- (instancetype)initWithProcess:(NSString *)process useMigFilterBypass:(BOOL)useMigFilterBypass;
- (instancetype)initWithProcess:(NSString *)process
              useMigFilterBypass:(BOOL)useMigFilterBypass
         firstExceptionTimeoutMS:(int)firstExceptionTimeoutMS;
- (instancetype)initWithProcess:(NSString *)process
              useMigFilterBypass:(BOOL)useMigFilterBypass
         firstExceptionTimeoutMS:(int)firstExceptionTimeoutMS
              originalThreadOnly:(BOOL)originalThreadOnly;
- (instancetype)initWithProcess:(NSString *)process
              useMigFilterBypass:(BOOL)useMigFilterBypass
         firstExceptionTimeoutMS:(int)firstExceptionTimeoutMS
              originalThreadOnly:(BOOL)originalThreadOnly
            bootstrapThreadCount:(int)bootstrapThreadCount
               bootstrapProvoker:(void (^ _Nullable)(void))bootstrapProvoker;
- (uint64_t)doRemoteCallStableWithTimeout:(int)timeout
                             functionName:(const char *)name
                                       x0:(uint64_t)x0
                                       x1:(uint64_t)x1
                                       x2:(uint64_t)x2
                                       x3:(uint64_t)x3
                                       x4:(uint64_t)x4
                                       x5:(uint64_t)x5
                                       x6:(uint64_t)x6
                                       x7:(uint64_t)x7;
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
                                       x7:(uint64_t)x7;
- (BOOL)remoteRead:(uint64_t)src to:(void *)dst size:(uint64_t)size;
- (uint64_t)remoteRead64:(uint64_t)src;
- (BOOL)remoteWrite:(uint64_t)dst from:(const void *)src size:(uint64_t)size;
- (BOOL)remoteWrite64:(uint64_t)dst value:(uint64_t)val;
- (BOOL)remoteWriteString:(uint64_t)dst value:(const char *)str;
- (int)destroyRemoteCall;
- (void)abandonRemoteCall;
// A synthetic call that timed out after dispatch is still executing in the
// target. Destroying its exception receive right would make the target crash
// when that call eventually returns to RemoteCall's sentinel PC. This method
// retains the session and drains/tears it down asynchronously; it returns NO
// when no such live call needs deferred ownership.
- (BOOL)deferTeardownForInFlightSyntheticCall;
- (BOOL)hasInFlightSyntheticCall;
- (RemoteCallTerminalDispatchStatus)dispatchSelfSIGKILLForExpectedPID:(int)expectedPID
                                                                  proc:(uint64_t)expectedProc
                                                                  task:(uint64_t)expectedTask
                                                                report:(RemoteCallTerminalDispatchReport *)reportOut;
- (BOOL)hasLocalState;
- (RemotePointer *)objectAtIndexedSubscript:(NSUInteger)address;

@end

@interface RemotePointer : NSObject

@property(nonatomic, strong, readonly) RemoteCallSession *session;
@property(nonatomic, readonly) uint64_t address;

@property(nonatomic, copy) NSString *string;
@property(nonatomic) uint8_t value8;
@property(nonatomic) uint16_t value16;
@property(nonatomic) uint32_t value32;
@property(nonatomic) uint64_t value64;

- (instancetype)initWithSession:(RemoteCallSession *)session address:(uint64_t)address;
- (BOOL)writeCString:(const char *)string;
- (BOOL)readTo:(void *)dst size:(uint64_t)size;
- (BOOL)writeFrom:(const void *)src size:(uint64_t)size;
- (NSString *)stringWithMaxLength:(size_t)maxLength;

@end

void remote_call_with_session(RemoteCallSession *session, void (^block)(void));
// Suppress only successful per-call return lines on this thread while the
// block runs. Diagnostic failures and explicit RC_VERBOSE output remain visible.
void remote_call_with_session_suppressing_result_logs(
    RemoteCallSession *session, void (^block)(void));
#endif

#endif /* RemoteCall_h */
