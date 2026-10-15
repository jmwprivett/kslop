#include <errno.h>
#include <mach/arm/thread_status.h>
#include <mach/exc.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>
#include <ptrauth.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#if !__has_feature(ptrauth_calls)
#error "the exception-identity PAC probe must be built for arm64e"
#endif

/* The iPhoneOS SDK does not publish servers/bootstrap.h, but libSystem does. */
extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_register(mach_port_t, const char *, mach_port_t);
extern kern_return_t bootstrap_look_up(mach_port_t, const char *, mach_port_t *);

enum {
    CNDExceptionIdentityMessageID = 2407,
};

static const uint64_t CNDUserPointerMask = 0x0000007fffffffffULL;
static const uint64_t CNDValidatorMarkerX16 = 0x434e4456414c3136ULL;
static const uint64_t CNDValidatorMarkerX17 = 0x434e4456414c3137ULL;

typedef struct {
    uint64_t resume_pc;
    uint64_t fallback_lr;
} CNDChildTargets;

typedef struct {
    uint64_t resumed;
    uint64_t x16;
    uint64_t x17;
} CNDChildResumeResult;

#pragma pack(push, 4)
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
} CNDMachExceptionIdentityRequest;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    int flavor;
    mach_msg_type_number_t new_stateCnt;
    natural_t new_state[1296];
} CNDMachExceptionIdentityReply;
#pragma pack(pop)

static int write_all(int fd, const void *buffer, size_t length)
{
    const uint8_t *cursor = buffer;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return errno ? errno : EIO;
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

static int read_all(int fd, void *buffer, size_t length)
{
    uint8_t *cursor = buffer;
    while (length > 0) {
        ssize_t amount = read(fd, cursor, length);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return amount == 0 ? EPIPE : errno;
        cursor += (size_t)amount;
        length -= (size_t)amount;
    }
    return 0;
}

__attribute__((noinline))
static void cnd_fallback_lr(void)
{
    _exit(18);
}

static uint64_t raw_function_pointer(void (*function)(void))
{
    return (uint64_t)(uintptr_t)ptrauth_strip(
        function, ptrauth_key_function_pointer) & CNDUserPointerMask;
}

static int child_main(const char *service_name, int target_fd, int result_fd)
{
    mach_port_t exception_port = MACH_PORT_NULL;
    if (bootstrap_look_up(bootstrap_port, service_name, &exception_port) !=
        KERN_SUCCESS) return 10;

    mach_port_t self_thread = mach_thread_self();
    kern_return_t kr = thread_set_exception_ports(
        self_thread, EXC_MASK_BREAKPOINT, exception_port,
        EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
        ARM_THREAD_STATE64);
    (void)mach_port_deallocate(mach_task_self(), self_thread);
    (void)mach_port_deallocate(mach_task_self(), exception_port);
    if (kr != KERN_SUCCESS) return 11;

    CNDChildTargets targets = {
        .resume_pc = ((uint64_t)(uintptr_t)&&resumed) & CNDUserPointerMask,
        .fallback_lr = raw_function_pointer(cnd_fallback_lr),
    };
    if (write_all(target_fd, &targets, sizeof(targets)) != 0) return 12;
    __asm__ volatile("brk #0x434" ::: "memory");

resumed:
    {
        uint64_t observed_x16 = 0;
        uint64_t observed_x17 = 0;
        __asm__ volatile(
            "mov %0, x16\n"
            "mov %1, x17\n"
            : "=r"(observed_x16), "=r"(observed_x17));
        CNDChildResumeResult result = {
            .resumed = 1,
            .x16 = observed_x16,
            .x17 = observed_x17,
        };
        return write_all(result_fd, &result, sizeof(result)) == 0
            ? 0 : 13;
    }
}

static kern_return_t receive_identity_exception(
    mach_port_t receive_port,
    CNDMachExceptionIdentityRequest *request)
{
    union {
        CNDMachExceptionIdentityRequest request;
        uint8_t bytes[
            sizeof(CNDMachExceptionIdentityRequest) +
            sizeof(mach_msg_max_trailer_t)
        ];
    } receive = {0};
    kern_return_t kr = mach_msg(
        &receive.request.Head, MACH_RCV_MSG, 0, sizeof(receive),
        receive_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr == KERN_SUCCESS) *request = receive.request;
    return kr;
}

static kern_return_t reply_identity_exception(
    const CNDMachExceptionIdentityRequest *request,
    const arm_thread_state64_t *state)
{
    CNDMachExceptionIdentityReply reply = {0};
    reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    reply.Head.msgh_remote_port = request->Head.msgh_remote_port;
    reply.Head.msgh_id = request->Head.msgh_id + 100;
    reply.NDR = request->NDR;
    reply.RetCode = KERN_SUCCESS;
    reply.flavor = ARM_THREAD_STATE64;
    reply.new_stateCnt = ARM_THREAD_STATE64_COUNT;
    memcpy(reply.new_state, state, sizeof(*state));
    reply.Head.msgh_size = (mach_msg_size_t)(
        offsetof(CNDMachExceptionIdentityReply, new_state) +
        sizeof(*state));
    return mach_msg(&reply.Head, MACH_SEND_MSG, reply.Head.msgh_size, 0,
                    MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

static void prepare_converter_input(arm_thread_state64_t *state,
                                    uint64_t raw_pc, uint64_t raw_lr,
                                    int retain_x17)
{
    uint32_t flags = state->__opaque_flags;
    flags &= ~(0x1U | 0x2U | 0x4U | 0x8U);
    state->__opaque_flags = flags;
    void *signed_pc = ptrauth_sign_unauthenticated(
        (void *)(uintptr_t)(raw_pc & CNDUserPointerMask),
        ptrauth_key_process_independent_code,
        ptrauth_string_discriminator("pc"));
    void *signed_lr = ptrauth_sign_unauthenticated(
        (void *)(uintptr_t)(raw_lr & CNDUserPointerMask),
        ptrauth_key_process_independent_code,
        ptrauth_string_discriminator("lr"));
    arm_thread_state64_set_pc_presigned_fptr(*state, signed_pc);
    arm_thread_state64_set_lr_presigned_fptr(*state, signed_lr);
    state->__x[16] = CNDValidatorMarkerX16;
    if (!retain_x17) state->__x[17] = CNDValidatorMarkerX17;
}

int main(int argc, char **argv)
{
    int debug_gate = argc == 2 && (
        strcmp(argv[1], "--debug-gate") == 0 ||
        strcmp(argv[1], "--validator-gate") == 0);
    int retain_x17 = argc == 2 &&
        strcmp(argv[1], "--validator-gate") == 0;
    if (argc != 1 && !debug_gate) {
        fprintf(stderr,
                "usage: %s [--debug-gate|--validator-gate]\n", argv[0]);
        return 64;
    }
    mach_port_t exception_port = MACH_PORT_NULL;
    mach_port_options_t options = {
        .flags = MPO_INSERT_SEND_RIGHT,
        .mpl = { .mpl_qlimit = 1 },
    };
    kern_return_t kr = mach_port_construct(
        mach_task_self(), &options, 0, &exception_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "exception port failed: %d\n", kr);
        return 2;
    }
    char service_name[96] = {0};
    (void)snprintf(service_name, sizeof(service_name),
                   "com.zeroxjf.cyanide.identity-probe.%d", getpid());
    kr = bootstrap_register(bootstrap_port, service_name, exception_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "bootstrap register failed: %d\n", kr);
        return 2;
    }

    int targets_pipe[2] = {-1, -1};
    int result_pipe[2] = {-1, -1};
    if (pipe(targets_pipe) != 0 || pipe(result_pipe) != 0) {
        fprintf(stderr, "pipe failed: %d\n", errno);
        return 2;
    }
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "fork failed: %d\n", errno);
        return 2;
    }
    if (child == 0) {
        close(targets_pipe[0]);
        close(result_pipe[0]);
        _exit(child_main(service_name, targets_pipe[1], result_pipe[1]));
    }
    close(targets_pipe[1]);
    close(result_pipe[1]);

    CNDChildTargets targets = {0};
    int target_read = read_all(targets_pipe[0], &targets, sizeof(targets));
    close(targets_pipe[0]);

    CNDMachExceptionIdentityRequest request = {0};
    kern_return_t receive_kr = target_read == 0
        ? receive_identity_exception(exception_port, &request)
        : KERN_FAILURE;
    int request_valid = receive_kr == KERN_SUCCESS &&
        request.Head.msgh_id == CNDExceptionIdentityMessageID &&
        (request.Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) &&
        request.msgh_body.msgh_descriptor_count == 2 &&
        request.thread.type == MACH_MSG_PORT_DESCRIPTOR &&
        request.task.type == MACH_MSG_PORT_DESCRIPTOR &&
        MACH_PORT_VALID(request.thread.name) &&
        MACH_PORT_VALID(request.task.name) &&
        request.flavor == ARM_THREAD_STATE64 &&
        request.old_stateCnt == ARM_THREAD_STATE64_COUNT;

    arm_thread_state64_t input = {0};
    arm_thread_state64_t output = {0};
    uint64_t expected_x17 = CNDValidatorMarkerX17;
    if (request_valid) {
        memcpy(&input, request.old_state, sizeof(input));
        if (retain_x17) expected_x17 = input.__x[17];
        prepare_converter_input(
            &input, targets.resume_pc, targets.fallback_lr, retain_x17);
    }
    mach_msg_type_number_t output_count = ARM_THREAD_STATE64_COUNT;
    kern_return_t convert_kr = request_valid
        ? thread_convert_thread_state(
            request.thread.name, THREAD_CONVERT_THREAD_STATE_FROM_SELF,
            ARM_THREAD_STATE64, (thread_state_t)&input,
            ARM_THREAD_STATE64_COUNT, (thread_state_t)&output, &output_count)
        : KERN_FAILURE;
    int gate_result = 0;
    if (debug_gate && convert_kr == KERN_SUCCESS) {
        char ready[128] = {0};
        int ready_length = snprintf(
            ready, sizeof(ready),
            "CND_VALIDATOR_READY pid=%d thread_port=%#x x17=%#018llx\n",
            getpid(), request.thread.name, expected_x17);
        if (ready_length <= 0 || (size_t)ready_length >= sizeof(ready)) {
            gate_result = EOVERFLOW;
        } else {
            gate_result = write_all(
                STDERR_FILENO, ready, (size_t)ready_length);
        }
        struct pollfd gate = {
            .fd = STDIN_FILENO,
            .events = POLLIN,
        };
        if (gate_result == 0 && poll(&gate, 1, 20000) != 1) {
            gate_result = ETIMEDOUT;
        }
        char command = 0;
        if (gate_result == 0) {
            gate_result = read_all(STDIN_FILENO, &command, sizeof(command));
        }
        if (gate_result == 0 && command != 'G') gate_result = EINVAL;
    }
    kern_return_t reply_kr = convert_kr == KERN_SUCCESS && gate_result == 0
        ? reply_identity_exception(&request, &output)
        : KERN_FAILURE;

    CNDChildResumeResult child_result = {0};
    int result_read = reply_kr == KERN_SUCCESS
        ? read_all(result_pipe[0], &child_result, sizeof(child_result))
        : EIO;
    close(result_pipe[0]);
    if (reply_kr != KERN_SUCCESS) (void)kill(child, SIGKILL);
    int child_status = 0;
    pid_t waited = waitpid(child, &child_status, 0);

    uint64_t output_pc = (uint64_t)(uintptr_t)output.__opaque_pc;
    uint64_t output_lr = (uint64_t)(uintptr_t)output.__opaque_lr;
    int exact = request_valid && convert_kr == KERN_SUCCESS &&
        output_count == ARM_THREAD_STATE64_COUNT &&
        output.__opaque_flags == input.__opaque_flags &&
        (output_pc & CNDUserPointerMask) == targets.resume_pc &&
        (output_lr & CNDUserPointerMask) == targets.fallback_lr &&
        reply_kr == KERN_SUCCESS && result_read == 0 &&
        child_result.resumed == 1 &&
        child_result.x16 == CNDValidatorMarkerX16 &&
        child_result.x17 == expected_x17 &&
        waited == child && WIFEXITED(child_status) &&
        WEXITSTATUS(child_status) == 0;

    printf("{\"schema\":"
           "\"com.zeroxjf.cyanide.thread-state-pac-exception-identity-probe\","
           "\"schema_version\":1,\"persistent_mutation\":false,"
           "\"kernel_call_used\":false,\"krw_used\":false,"
           "\"debug_gate_used\":%s,"
           "\"validator_gate_used\":%s,\"retained_x17\":%s,"
           "\"exception_state_identity\":true,"
           "\"mach_exception_codes\":true,"
           "\"identity_message_received\":%s,"
           "\"thread_port_received\":%s,\"task_port_received\":%s,"
           "\"direction_from_self\":%d,\"receive_kr\":%d,"
           "\"message_id\":%d,\"message_size\":%u,"
           "\"descriptor_count\":%u,\"thread_descriptor_type\":%u,"
           "\"task_descriptor_type\":%u,\"flavor\":%d,"
           "\"old_state_count\":%u,"
           "\"convert_kr\":%d,\"reply_kr\":%d,"
           "\"output_count\":%u,\"output_flags\":\"%#010x\","
           "\"raw_resume_pc\":\"%#018llx\","
           "\"raw_fallback_lr\":\"%#018llx\","
           "\"converted_pc\":\"%#018llx\","
           "\"converted_lr\":\"%#018llx\","
           "\"validator_marker_x16\":\"%#018llx\","
           "\"validator_marker_x17\":\"%#018llx\","
           "\"resumed_x16\":\"%#018llx\","
           "\"resumed_x17\":\"%#018llx\","
           "\"validator_markers_restored\":%s,"
           "\"child_resumed\":%s,"
           "\"exact_exception_identity_conversion\":%s}\n",
           debug_gate ? "true" : "false",
           retain_x17 ? "true" : "false",
           retain_x17 ? "true" : "false",
           request_valid ? "true" : "false",
           request_valid && MACH_PORT_VALID(request.thread.name)
               ? "true" : "false",
           request_valid && MACH_PORT_VALID(request.task.name)
               ? "true" : "false",
           THREAD_CONVERT_THREAD_STATE_FROM_SELF, receive_kr,
           request.Head.msgh_id, request.Head.msgh_size,
           request.msgh_body.msgh_descriptor_count, request.thread.type,
           request.task.type, request.flavor, request.old_stateCnt,
           convert_kr, reply_kr, output_count, output.__opaque_flags,
           targets.resume_pc, targets.fallback_lr, output_pc, output_lr,
           CNDValidatorMarkerX16, expected_x17,
           child_result.x16, child_result.x17,
           child_result.x16 == CNDValidatorMarkerX16 &&
               child_result.x17 == expected_x17 ? "true" : "false",
           child_result.resumed ? "true" : "false",
           exact ? "true" : "false");
    return exact ? 0 : 3;
}
