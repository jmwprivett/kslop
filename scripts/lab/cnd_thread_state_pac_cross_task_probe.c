#include <errno.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* The iPhoneOS SDK does not publish servers/bootstrap.h, but libSystem does. */
extern mach_port_t bootstrap_port;
extern kern_return_t bootstrap_register(mach_port_t, const char *, mach_port_t);
extern kern_return_t bootstrap_look_up(mach_port_t, const char *, mach_port_t *);

#if !__has_feature(ptrauth_calls)
#error "the cross-task thread-state PAC probe must be built for arm64e"
#endif

enum {
    CNDUserDiversifier = 0x5a000000U,
    CNDMessageID = 0x434e4450,
};

static const uint64_t CNDUserPointerMask = 0x0000007fffffffffULL;

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread;
} CNDThreadPortMessage;

typedef struct {
    uint64_t pc;
    uint64_t lr;
    int valid;
} CNDChildAuthentication;

__attribute__((noinline))
static void cnd_cross_task_pc_target(void)
{
    __asm__ volatile("" ::: "memory");
}

__attribute__((noinline))
static void cnd_cross_task_lr_target(void)
{
    __asm__ volatile("" ::: "memory");
}

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

static int send_current_thread_port(mach_port_t destination)
{
    mach_port_t thread = mach_thread_self();
    CNDThreadPortMessage message = {0};
    message.header.msgh_bits = MACH_MSGH_BITS_COMPLEX |
        MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    message.header.msgh_size = sizeof(message);
    message.header.msgh_remote_port = destination;
    message.header.msgh_id = CNDMessageID;
    message.body.msgh_descriptor_count = 1;
    message.thread.name = thread;
    message.thread.disposition = MACH_MSG_TYPE_COPY_SEND;
    message.thread.type = MACH_MSG_PORT_DESCRIPTOR;
    kern_return_t kr = mach_msg(&message.header, MACH_SEND_MSG,
                                message.header.msgh_size, 0,
                                MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE,
                                MACH_PORT_NULL);
    (void)mach_port_deallocate(mach_task_self(), thread);
    return kr == KERN_SUCCESS ? 0 : kr;
}

static kern_return_t receive_thread_port(mach_port_t receive_port,
                                         mach_port_t *thread_out)
{
    struct {
        CNDThreadPortMessage message;
        mach_msg_max_trailer_t trailer;
    } receive = {0};
    kern_return_t kr = mach_msg(&receive.message.header, MACH_RCV_MSG, 0,
                                sizeof(receive), receive_port,
                                MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) return kr;
    CNDThreadPortMessage message = receive.message;
    if (!(message.header.msgh_bits & MACH_MSGH_BITS_COMPLEX) ||
        message.header.msgh_id != CNDMessageID ||
        message.body.msgh_descriptor_count != 1 ||
        message.thread.type != MACH_MSG_PORT_DESCRIPTOR ||
        !MACH_PORT_VALID(message.thread.name)) {
        return KERN_INVALID_ARGUMENT;
    }
    *thread_out = message.thread.name;
    return KERN_SUCCESS;
}

static uint64_t raw_function_pointer(void (*function)(void))
{
    return (uint64_t)(uintptr_t)ptrauth_strip(
        function, ptrauth_key_function_pointer) & CNDUserPointerMask;
}

static void prepare_converter_input(arm_thread_state64_t *state,
                                    uint64_t raw_pc, uint64_t raw_lr)
{
    memset(state, 0, sizeof(*state));
    state->__opaque_flags = CNDUserDiversifier;
    void *signed_pc = ptrauth_sign_unauthenticated(
        (void *)(uintptr_t)raw_pc,
        ptrauth_key_process_independent_code,
        ptrauth_string_discriminator("pc"));
    void *signed_lr = ptrauth_sign_unauthenticated(
        (void *)(uintptr_t)raw_lr,
        ptrauth_key_process_independent_code,
        ptrauth_string_discriminator("lr"));
    arm_thread_state64_set_pc_presigned_fptr(*state, signed_pc);
    arm_thread_state64_set_lr_presigned_fptr(*state, signed_lr);
}

static int child_main(const char *service_name, int state_fd, int result_fd)
{
    mach_port_t parent_port = MACH_PORT_NULL;
    if (bootstrap_look_up(bootstrap_port, service_name, &parent_port) !=
        KERN_SUCCESS) return 9;
    if (send_current_thread_port(parent_port) != 0) return 10;
    arm_thread_state64_t target_state = {0};
    if (read_all(state_fd, &target_state, sizeof(target_state)) != 0) return 11;
    CNDChildAuthentication result = {
        .pc = arm_thread_state64_get_pc(target_state),
        .lr = arm_thread_state64_get_lr(target_state),
    };
    result.valid = result.pc != 0 && result.lr != 0;
    return write_all(result_fd, &result, sizeof(result)) == 0 ? 0 : 12;
}

int main(void)
{
    mach_port_t rendezvous = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(
        mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &rendezvous);
    if (kr == KERN_SUCCESS) {
        kr = mach_port_insert_right(mach_task_self(), rendezvous,
                                    rendezvous, MACH_MSG_TYPE_MAKE_SEND);
    }
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "rendezvous port failed: %d\n", kr);
        return 2;
    }
    char service_name[96] = {0};
    (void)snprintf(service_name, sizeof(service_name),
                   "com.zeroxjf.cyanide.pac-probe.%d", getpid());
    kr = bootstrap_register(bootstrap_port, service_name, rendezvous);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "bootstrap register failed: %d\n", kr);
        return 2;
    }

    int to_child[2] = {-1, -1};
    int from_child[2] = {-1, -1};
    if (pipe(to_child) != 0 || pipe(from_child) != 0) {
        fprintf(stderr, "pipe failed: %d\n", errno);
        return 2;
    }
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "fork failed: %d\n", errno);
        return 2;
    }
    if (child == 0) {
        close(to_child[1]);
        close(from_child[0]);
        _exit(child_main(service_name, to_child[0], from_child[1]));
    }
    close(to_child[0]);
    close(from_child[1]);

    mach_port_t target_thread = MACH_PORT_NULL;
    kr = receive_thread_port(rendezvous, &target_thread);
    uint64_t raw_pc = raw_function_pointer(cnd_cross_task_pc_target);
    uint64_t raw_lr = raw_function_pointer(cnd_cross_task_lr_target);
    arm_thread_state64_t input = {0};
    arm_thread_state64_t output = {0};
    prepare_converter_input(&input, raw_pc, raw_lr);
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t convert_kr = kr == KERN_SUCCESS
        ? thread_convert_thread_state(
            target_thread, THREAD_CONVERT_THREAD_STATE_FROM_SELF,
            ARM_THREAD_STATE64, (thread_state_t)&input,
            ARM_THREAD_STATE64_COUNT, (thread_state_t)&output, &count)
        : kr;
    int pipe_result = convert_kr == KERN_SUCCESS
        ? write_all(to_child[1], &output, sizeof(output)) : EIO;
    close(to_child[1]);

    CNDChildAuthentication authenticated = {0};
    int read_result = pipe_result == 0
        ? read_all(from_child[0], &authenticated, sizeof(authenticated))
        : EIO;
    close(from_child[0]);
    int child_status = 0;
    pid_t waited = waitpid(child, &child_status, 0);

    uint64_t input_pc = (uint64_t)(uintptr_t)input.__opaque_pc;
    uint64_t input_lr = (uint64_t)(uintptr_t)input.__opaque_lr;
    uint64_t target_pc = (uint64_t)(uintptr_t)output.__opaque_pc;
    uint64_t target_lr = (uint64_t)(uintptr_t)output.__opaque_lr;
    int exact = kr == KERN_SUCCESS && convert_kr == KERN_SUCCESS &&
        count == ARM_THREAD_STATE64_COUNT &&
        output.__opaque_flags == CNDUserDiversifier && pipe_result == 0 &&
        read_result == 0 && authenticated.valid &&
        authenticated.pc == raw_pc && authenticated.lr == raw_lr &&
        target_pc != raw_pc && target_lr != raw_lr &&
        (target_pc & CNDUserPointerMask) == raw_pc &&
        (target_lr & CNDUserPointerMask) == raw_lr &&
        waited == child && WIFEXITED(child_status) &&
        WEXITSTATUS(child_status) == 0;

    printf("{\"schema\":"
           "\"com.zeroxjf.cyanide.thread-state-pac-cross-task-probe\","
           "\"schema_version\":1,\"persistent_mutation\":false,"
           "\"kernel_call_used\":false,\"krw_used\":false,"
           "\"cross_task_target\":true,"
           "\"thread_port_transferred\":%s,"
           "\"requires_thread_control_port\":true,"
           "\"direction_from_self\":%d,\"convert_kr\":%d,"
           "\"output_count\":%u,\"user_diversifier\":\"%#010x\","
           "\"raw_pc\":\"%#018llx\",\"raw_lr\":\"%#018llx\","
           "\"local_plain_signed_pc\":\"%#018llx\","
           "\"local_plain_signed_lr\":\"%#018llx\","
           "\"target_diversified_signed_pc\":\"%#018llx\","
           "\"target_diversified_signed_lr\":\"%#018llx\","
           "\"target_process_authenticated_pc\":\"%#018llx\","
           "\"target_process_authenticated_lr\":\"%#018llx\","
           "\"output_flags\":\"%#010x\","
           "\"exact_cross_task_conversion\":%s}\n",
           kr == KERN_SUCCESS ? "true" : "false",
           THREAD_CONVERT_THREAD_STATE_FROM_SELF, convert_kr, count,
           CNDUserDiversifier, raw_pc, raw_lr, input_pc, input_lr,
           target_pc, target_lr, authenticated.pc, authenticated.lr,
           output.__opaque_flags, exact ? "true" : "false");
    return exact ? 0 : 3;
}
