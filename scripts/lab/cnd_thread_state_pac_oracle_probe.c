#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !__has_feature(ptrauth_calls)
#error "the thread-state PAC oracle probe must be built for arm64e"
#endif

/*
 * No KRW-provider or vPhone kcall symbols are linked into this probe.
 *
 * thread_convert_thread_state(FROM_SELF) first authenticates the input under
 * the caller's thread context with TSSF_FLAGS_NONE, then signs the output for
 * the supplied target thread with TSSF_PRESERVE_FLAGS.  The asymmetry is
 * useful: an input whose PC/LR carry a user diversifier must be locally signed
 * with the plain pc/lr discriminator; the target output is signed with the
 * user-diversified discriminator required by an exception reply.
 *
 * The target below is a suspended thread in this task.  The probe never
 * installs or executes the converted state.
 */

enum {
    CNDUserDiversifier = 0x5a000000U,
};

static const uint64_t CNDUserPointerMask = 0x0000007fffffffffULL;

static void trace_stage(const char *stage)
{
    if (getenv("CND_PAC_PROBE_TRACE")) {
        fprintf(stderr, "stage=%s\n", stage);
        fflush(stderr);
    }
}

__attribute__((noinline))
static void cnd_probe_pc_target(void)
{
    __asm__ volatile("" ::: "memory");
}

__attribute__((noinline))
static void cnd_probe_lr_target(void)
{
    __asm__ volatile("" ::: "memory");
}

static uint64_t raw_function_pointer(void (*function)(void))
{
    return (uint64_t)(uintptr_t)ptrauth_strip(
        function, ptrauth_key_function_pointer) & CNDUserPointerMask;
}

static uint64_t state_pc_bits(const arm_thread_state64_t *state)
{
    return (uint64_t)(uintptr_t)state->__opaque_pc;
}

static uint64_t state_lr_bits(const arm_thread_state64_t *state)
{
    return (uint64_t)(uintptr_t)state->__opaque_lr;
}

static void prepare_converter_input(arm_thread_state64_t *state,
                                    uint64_t raw_pc, uint64_t raw_lr)
{
    memset(state, 0, sizeof(*state));
    state->__opaque_flags = CNDUserDiversifier;

    /* The converter's FROM_SELF authentication uses TSSF_FLAGS_NONE, so its
     * input discriminator is deliberately plain even though the preserved
     * output flags request a user-diversified target signature. */
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

static kern_return_t convert_from_self(thread_act_t target,
                                       const arm_thread_state64_t *input,
                                       arm_thread_state64_t *output,
                                       mach_msg_type_number_t *count_out)
{
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    memset(output, 0, sizeof(*output));
    kern_return_t kr = thread_convert_thread_state(
        target, THREAD_CONVERT_THREAD_STATE_FROM_SELF,
        ARM_THREAD_STATE64, (thread_state_t)(uintptr_t)input,
        ARM_THREAD_STATE64_COUNT, (thread_state_t)output, &count);
    if (count_out) *count_out = count;
    return kr;
}

int main(void)
{
    trace_stage("thread-create");
    thread_act_t target = MACH_PORT_NULL;
    kern_return_t create_kr = thread_create(mach_task_self(), &target);
    if (create_kr != KERN_SUCCESS || !MACH_PORT_VALID(target)) {
        fprintf(stderr, "thread_create failed: %d\n", create_kr);
        return 2;
    }

    uint64_t raw_pc = raw_function_pointer(cnd_probe_pc_target);
    uint64_t raw_lr = raw_function_pointer(cnd_probe_lr_target);
    arm_thread_state64_t local_input = {0};
    arm_thread_state64_t target_output = {0};

    trace_stage("prepare-local-input");
    prepare_converter_input(&local_input, raw_pc, raw_lr);
    uint64_t input_pc = state_pc_bits(&local_input);
    uint64_t input_lr = state_lr_bits(&local_input);
    uint64_t input_pc_raw = (uint64_t)(uintptr_t)ptrauth_auth_data(
        local_input.__opaque_pc, ptrauth_key_process_independent_code,
        ptrauth_string_discriminator("pc"));
    uint64_t input_lr_raw = (uint64_t)(uintptr_t)ptrauth_auth_data(
        local_input.__opaque_lr, ptrauth_key_process_independent_code,
        ptrauth_string_discriminator("lr"));

    trace_stage("convert-from-self");
    mach_msg_type_number_t output_count = 0;
    kern_return_t convert_kr = convert_from_self(
        target, &local_input, &target_output, &output_count);
    uint64_t target_pc = state_pc_bits(&target_output);
    uint64_t target_lr = state_lr_bits(&target_output);

    /* A normal thread created in this task shares its user PAC context.  This
     * local authentication validates that the converter emitted the blended
     * pc/lr form selected by the preserved user-diversifier flags. */
    uint64_t target_pc_raw = 0;
    uint64_t target_lr_raw = 0;
    if (convert_kr == KERN_SUCCESS &&
        output_count == ARM_THREAD_STATE64_COUNT &&
        target_output.__opaque_flags == CNDUserDiversifier) {
        trace_stage("authenticate-target-output");
        target_pc_raw = arm_thread_state64_get_pc(target_output);
        target_lr_raw = arm_thread_state64_get_lr(target_output);
    }

    int exact_conversion = convert_kr == KERN_SUCCESS &&
        output_count == ARM_THREAD_STATE64_COUNT &&
        input_pc_raw == raw_pc && input_lr_raw == raw_lr &&
        target_output.__opaque_flags == CNDUserDiversifier &&
        target_pc != raw_pc && target_lr != raw_lr &&
        target_pc_raw == raw_pc && target_lr_raw == raw_lr;

    trace_stage("report");
    printf("{\"schema\":\"com.zeroxjf.cyanide.thread-state-pac-oracle-probe\","
           "\"schema_version\":1,\"persistent_mutation\":false,"
           "\"kernel_call_used\":false,\"krw_used\":false,"
           "\"same_task_target\":true,"
           "\"requires_thread_control_port\":true,"
           "\"direction_from_self\":%d,"
           "\"user_diversifier\":\"%#010x\","
           "\"convert_kr\":%d,\"output_count\":%u,"
           "\"raw_pc\":\"%#018llx\",\"raw_lr\":\"%#018llx\","
           "\"local_plain_signed_pc\":\"%#018llx\","
           "\"local_plain_signed_lr\":\"%#018llx\","
           "\"target_diversified_signed_pc\":\"%#018llx\","
           "\"target_diversified_signed_lr\":\"%#018llx\","
           "\"target_authenticated_pc\":\"%#018llx\","
           "\"target_authenticated_lr\":\"%#018llx\","
           "\"output_flags\":\"%#010x\","
           "\"exception_reply_compatible_shape\":%s,"
           "\"exact_target_context_conversion\":%s}\n",
           THREAD_CONVERT_THREAD_STATE_FROM_SELF,
           CNDUserDiversifier, convert_kr, output_count,
           raw_pc, raw_lr, input_pc, input_lr, target_pc, target_lr,
           target_pc_raw, target_lr_raw, target_output.__opaque_flags,
           target_output.__opaque_flags == CNDUserDiversifier
               ? "true" : "false",
           exact_conversion ? "true" : "false");
    /* The probe process owns target and exits immediately.  Let task teardown
     * reap the never-started thread and its port together; explicitly
     * terminating an uninitialized thread is not portable across the stock
     * and vPhone kernels. */
    return exact_conversion ? 0 : 3;
}
