#include <errno.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>
#include <pthread.h>
#include <ptrauth.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !__has_feature(ptrauth_calls)
#error "the signer-caller boundary probe must be built for arm64e"
#endif

enum {
    CNDUserDiversifier = 0x5a000000U,
    CNDPSRModeMask = 0xfU,
    CNDPSRModeEL0 = 0x0U,
    CNDPSRModeEL1 = 0x5U,
};

static const uint64_t CNDUserPointerMask = 0x0000007fffffffffULL;
static _Atomic int CNDWorkerReady;
static _Atomic int CNDWorkerRelease;

typedef struct {
    kern_return_t convert_kr;
    kern_return_t set_kr;
    kern_return_t get_kr;
    mach_msg_type_number_t converted_count;
    mach_msg_type_number_t observed_count;
    uint32_t requested_cpsr;
    uint32_t converted_cpsr;
    uint32_t observed_cpsr;
    uint64_t requested_pc;
    uint64_t converted_pc_bits;
    uint64_t observed_pc;
    arm_thread_state64_t caller_input;
    arm_thread_state64_t converted;
} CNDBoundaryResult;

__attribute__((noinline))
static void cnd_user_pc_target(void)
{
    __asm__ volatile("" ::: "memory");
}

__attribute__((noinline))
static void cnd_user_lr_target(void)
{
    __asm__ volatile("" ::: "memory");
}

static uint64_t raw_function_pointer(void (*function)(void))
{
    return (uint64_t)(uintptr_t)ptrauth_strip(
        function, ptrauth_key_function_pointer) & CNDUserPointerMask;
}

static void *cnd_worker(void *unused)
{
    (void)unused;
    atomic_store_explicit(&CNDWorkerReady, 1, memory_order_release);
    while (!atomic_load_explicit(&CNDWorkerRelease, memory_order_acquire)) {
        (void)sched_yield();
    }
    return NULL;
}

static void prepare_converter_input(arm_thread_state64_t *state,
                                    uint64_t raw_pc, uint64_t raw_lr,
                                    uint32_t cpsr)
{
    memset(state, 0, sizeof(*state));
    state->__opaque_flags = CNDUserDiversifier;
    state->__cpsr = cpsr;
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

static CNDBoundaryResult run_boundary(thread_act_t target, uint64_t raw_pc,
                                      uint64_t raw_lr, uint32_t cpsr)
{
    CNDBoundaryResult result = {
        .convert_kr = KERN_FAILURE,
        .set_kr = KERN_FAILURE,
        .get_kr = KERN_FAILURE,
        .requested_cpsr = cpsr,
        .requested_pc = raw_pc,
    };
    arm_thread_state64_t input = {0};
    prepare_converter_input(&input, raw_pc, raw_lr, cpsr);
    result.caller_input = input;
    result.converted_count = ARM_THREAD_STATE64_COUNT;
    fprintf(stderr, "cnd-signer-caller: convert begin %#llx/%#x\n",
            raw_pc, cpsr);
    result.convert_kr = thread_convert_thread_state(
        target, THREAD_CONVERT_THREAD_STATE_FROM_SELF,
        ARM_THREAD_STATE64, (thread_state_t)&input,
        ARM_THREAD_STATE64_COUNT, (thread_state_t)&result.converted,
        &result.converted_count);
    fprintf(stderr, "cnd-signer-caller: convert end %d/%u\n",
            result.convert_kr, result.converted_count);
    if (result.convert_kr != KERN_SUCCESS ||
        result.converted_count != ARM_THREAD_STATE64_COUNT) {
        return result;
    }
    result.converted_cpsr = result.converted.__cpsr;
    result.converted_pc_bits =
        (uint64_t)(uintptr_t)result.converted.__opaque_pc;
    fprintf(stderr, "cnd-signer-caller: set begin\n");
    result.set_kr = thread_set_state(
        target, ARM_THREAD_STATE64,
        (thread_state_t)&result.caller_input, ARM_THREAD_STATE64_COUNT);
    fprintf(stderr, "cnd-signer-caller: set end %d\n", result.set_kr);
    if (result.set_kr != KERN_SUCCESS) return result;

    arm_thread_state64_t observed = {0};
    result.observed_count = ARM_THREAD_STATE64_COUNT;
    fprintf(stderr, "cnd-signer-caller: get begin\n");
    result.get_kr = thread_get_state(
        target, ARM_THREAD_STATE64, (thread_state_t)&observed,
        &result.observed_count);
    fprintf(stderr, "cnd-signer-caller: get end %d/%u\n",
            result.get_kr, result.observed_count);
    if (result.get_kr == KERN_SUCCESS &&
        result.observed_count == ARM_THREAD_STATE64_COUNT) {
        result.observed_cpsr = observed.__cpsr;
        result.observed_pc = arm_thread_state64_get_pc(observed);
    }
    return result;
}

static int parse_kernel_pc(const char *text, uint64_t *value)
{
    if (!text || !value || strlen(text) != 18 || text[0] != '0' ||
        text[1] != 'x') return EINVAL;
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 16);
    if (errno != 0 || !end || *end != '\0' ||
        (parsed & 3ULL) != 0 ||
        (parsed & 0xffff000000000000ULL) != 0xffff000000000000ULL) {
        return EINVAL;
    }
    *value = (uint64_t)parsed;
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    fprintf(stderr, "cnd-signer-caller: parse\n");
    uint64_t kernel_pc = 0;
    if (argc != 2 || parse_kernel_pc(argv[1], &kernel_pc) != 0) {
        fprintf(stderr, "usage: %s 0xCANONICAL_KERNEL_PC\n", argv[0]);
        return 2;
    }

    pthread_t worker;
    fprintf(stderr, "cnd-signer-caller: pthread_create\n");
    int create_result = pthread_create(&worker, NULL, cnd_worker, NULL);
    if (create_result != 0) {
        fprintf(stderr, "pthread_create failed: %d\n", create_result);
        return 3;
    }
    for (unsigned int attempt = 0;
         !atomic_load_explicit(&CNDWorkerReady, memory_order_acquire) &&
         attempt < 5000; attempt++) {
        usleep(1000);
    }
    thread_act_t target = pthread_mach_thread_np(worker);
    if (!atomic_load_explicit(&CNDWorkerReady, memory_order_acquire) ||
        !MACH_PORT_VALID(target)) {
        atomic_store_explicit(&CNDWorkerRelease, 1, memory_order_release);
        (void)pthread_join(worker, NULL);
        fprintf(stderr, "worker did not become ready\n");
        return 3;
    }
    kern_return_t suspend_kr = thread_suspend(target);
    if (suspend_kr != KERN_SUCCESS) {
        atomic_store_explicit(&CNDWorkerRelease, 1, memory_order_release);
        (void)pthread_join(worker, NULL);
        fprintf(stderr, "thread_suspend failed: %d\n", suspend_kr);
        return 3;
    }
    arm_thread_state64_t original = {0};
    mach_msg_type_number_t original_count = ARM_THREAD_STATE64_COUNT;
    kern_return_t original_get_kr = thread_get_state(
        target, ARM_THREAD_STATE64, (thread_state_t)&original,
        &original_count);
    if (original_get_kr != KERN_SUCCESS ||
        original_count != ARM_THREAD_STATE64_COUNT) {
        atomic_store_explicit(&CNDWorkerRelease, 1, memory_order_release);
        (void)thread_resume(target);
        (void)pthread_join(worker, NULL);
        fprintf(stderr, "initial thread_get_state failed: %d/%u\n",
                original_get_kr, original_count);
        return 3;
    }

    uint64_t user_pc = raw_function_pointer(cnd_user_pc_target);
    uint64_t user_lr = raw_function_pointer(cnd_user_lr_target);
    fprintf(stderr, "cnd-signer-caller: baseline\n");
    CNDBoundaryResult baseline = run_boundary(
        target, user_pc, user_lr, CNDPSRModeEL0);
    fprintf(stderr, "cnd-signer-caller: baseline done %d/%d/%d\n",
            baseline.convert_kr, baseline.set_kr, baseline.get_kr);
    int baseline_ok = baseline.convert_kr == KERN_SUCCESS &&
        baseline.set_kr == KERN_SUCCESS && baseline.get_kr == KERN_SUCCESS &&
        baseline.observed_count == ARM_THREAD_STATE64_COUNT &&
        baseline.observed_pc == user_pc &&
        (baseline.observed_cpsr & CNDPSRModeMask) == CNDPSRModeEL0;

    fprintf(stderr, "cnd-signer-caller: kernel-el0\n");
    CNDBoundaryResult kernel_el0 = run_boundary(
        target, kernel_pc, user_lr, CNDPSRModeEL0);
    fprintf(stderr, "cnd-signer-caller: kernel-el0 done %d/%d/%d\n",
            kernel_el0.convert_kr, kernel_el0.set_kr, kernel_el0.get_kr);
    kern_return_t restore_after_kernel = baseline_ok
        ? thread_set_state(target, ARM_THREAD_STATE64,
                           (thread_state_t)&baseline.caller_input,
                           ARM_THREAD_STATE64_COUNT)
        : KERN_FAILURE;

    fprintf(stderr, "cnd-signer-caller: kernel-el1\n");
    CNDBoundaryResult kernel_el1 = run_boundary(
        target, kernel_pc, user_lr, CNDPSRModeEL1);
    fprintf(stderr, "cnd-signer-caller: kernel-el1 done %d/%d/%d\n",
            kernel_el1.convert_kr, kernel_el1.set_kr, kernel_el1.get_kr);
    kern_return_t final_restore = thread_set_state(
        target, ARM_THREAD_STATE64, (thread_state_t)&original,
        ARM_THREAD_STATE64_COUNT);
    atomic_store_explicit(&CNDWorkerRelease, 1, memory_order_release);
    kern_return_t resume_kr = thread_resume(target);
    int join_result = resume_kr == KERN_SUCCESS
        ? pthread_join(worker, NULL) : EIO;

    int kernel_pc_el0_accepted = kernel_el0.convert_kr == KERN_SUCCESS &&
        kernel_el0.set_kr == KERN_SUCCESS &&
        kernel_el0.get_kr == KERN_SUCCESS &&
        kernel_el0.observed_pc == kernel_pc &&
        (kernel_el0.observed_cpsr & CNDPSRModeMask) == CNDPSRModeEL0;
    int el1_preserved = kernel_el1.convert_kr == KERN_SUCCESS &&
        kernel_el1.set_kr == KERN_SUCCESS &&
        kernel_el1.get_kr == KERN_SUCCESS &&
        (kernel_el1.observed_cpsr & CNDPSRModeMask) == CNDPSRModeEL1;
    int el1_sanitized = kernel_el1.convert_kr == KERN_SUCCESS &&
        kernel_el1.set_kr == KERN_SUCCESS &&
        kernel_el1.get_kr == KERN_SUCCESS &&
        (kernel_el1.observed_cpsr & CNDPSRModeMask) == CNDPSRModeEL0;
    int el1_rejected = kernel_el1.convert_kr != KERN_SUCCESS ||
        kernel_el1.set_kr != KERN_SUCCESS;
    int exact = baseline_ok && restore_after_kernel == KERN_SUCCESS &&
        final_restore == KERN_SUCCESS && resume_kr == KERN_SUCCESS &&
        join_result == 0 && !el1_preserved &&
        (el1_sanitized || el1_rejected);

    printf("{\"schema\":"
           "\"com.zeroxjf.cyanide.thread-state-signer-caller-probe\","
           "\"schema_version\":1,\"normal_trigger\":\"thread_set_state\","
           "\"set_state_input\":\"caller-user-representation\","
           "\"private_thread_set_state_entitlement\":true,"
           "\"target_thread_suspended\":true,"
           "\"target_thread_resumed_only_after_restore\":%s,"
           "\"test_state_executed\":false,"
           "\"kernel_call_used\":false,\"krw_used\":false,"
           "\"persistent_mutation\":false,"
           "\"requested_kernel_pc\":\"%#018llx\","
           "\"baseline\":{\"convert_kr\":%d,\"set_kr\":%d,"
           "\"get_kr\":%d,\"observed_pc\":\"%#018llx\","
           "\"observed_cpsr\":\"0x%08x\",\"passed\":%s},"
           "\"kernel_pc_el0\":{\"convert_kr\":%d,\"set_kr\":%d,"
           "\"get_kr\":%d,\"converted_pc_bits\":\"%#018llx\","
           "\"observed_pc\":\"%#018llx\","
           "\"observed_cpsr\":\"0x%08x\",\"accepted\":%s},"
           "\"kernel_pc_el1\":{\"convert_kr\":%d,\"set_kr\":%d,"
           "\"get_kr\":%d,\"requested_cpsr\":\"0x%08x\","
           "\"converted_cpsr\":\"0x%08x\","
           "\"observed_cpsr\":\"0x%08x\",\"preserved\":%s,"
           "\"sanitized_to_el0\":%s,\"rejected\":%s},"
           "\"restore_after_kernel_kr\":%d,\"final_restore_kr\":%d,"
           "\"resume_kr\":%d,\"join_result\":%d,"
           "\"arbitrary_el1_state_signed\":false,"
           "\"boundary_classified\":%s}\n",
           final_restore == KERN_SUCCESS && resume_kr == KERN_SUCCESS
               ? "true" : "false",
           kernel_pc,
           baseline.convert_kr, baseline.set_kr, baseline.get_kr,
           baseline.observed_pc, baseline.observed_cpsr,
           baseline_ok ? "true" : "false",
           kernel_el0.convert_kr, kernel_el0.set_kr, kernel_el0.get_kr,
           kernel_el0.converted_pc_bits, kernel_el0.observed_pc,
           kernel_el0.observed_cpsr,
           kernel_pc_el0_accepted ? "true" : "false",
           kernel_el1.convert_kr, kernel_el1.set_kr, kernel_el1.get_kr,
           kernel_el1.requested_cpsr, kernel_el1.converted_cpsr,
           kernel_el1.observed_cpsr, el1_preserved ? "true" : "false",
           el1_sanitized ? "true" : "false",
           el1_rejected ? "true" : "false",
           restore_after_kernel, final_restore, resume_kr, join_result,
           exact ? "true" : "false");
    return exact ? 0 : 4;
}
