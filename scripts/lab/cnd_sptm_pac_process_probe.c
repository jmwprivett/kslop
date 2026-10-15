#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    CNDVPhoneKCallSyscall = 439,
    CNDVPhoneKCallMaxArguments = 7,
};

static volatile int CNDWorkerReady = 0;
static volatile int CNDWorkerStop = 0;
static volatile int CNDWorkerKCallResult = 0;
static volatile uint64_t CNDWorkerCurrentThreadStub = 0;
static volatile uint64_t CNDWorkerKernelThread = 0;

static int vphone_kcall(uint64_t function, const uint64_t arguments[3],
                        uint64_t *result);

__attribute__((noinline))
static void *thread_state_worker(void *unused)
{
    (void)unused;
    const uint64_t no_arguments[3] = {0};
    uint64_t kernel_thread = 0;
    CNDWorkerKCallResult = vphone_kcall(
        CNDWorkerCurrentThreadStub, no_arguments, &kernel_thread);
    CNDWorkerKernelThread = kernel_thread;
    CNDWorkerReady = 1;
    while (!CNDWorkerStop) {
        __asm__ volatile("" ::: "memory");
    }
    return NULL;
}

static const uint64_t CNDStaticKernelText = 0xfffffe0007008000ULL;
static const uint64_t CNDStaticSignStub = 0xfffffe00082f3788ULL;
static const uint64_t CNDStaticAuthStub = 0xfffffe00082f37a0ULL;
static const uint64_t CNDStaticCurrentThread = 0xfffffe0007c56714ULL;
static const uint64_t CNDPointer = 0x0000000100000000ULL;
static const uint64_t CNDDiscriminator = 0x0000000000434e44ULL;
static const uint64_t CNDPCDiscriminator = 0x0000000000007481ULL;
static const uint64_t CNDUserPointerMask = 0x0000007fffffffffULL;

enum {
    CNDThreadStateNoPtrauth = 0x1,
    CNDThreadStateKernelSignedPC = 0x4,
};

static int parse_hex64(const char *text, uint64_t *value, int kernel)
{
    if (!text || strlen(text) != 18 || text[0] != '0' || text[1] != 'x') {
        return EINVAL;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 16);
    if (errno != 0 || !end || *end != '\0') return EINVAL;
    if (kernel && ((parsed & 0xffff000000000000ULL) !=
                   0xffff000000000000ULL || (parsed & 0x3fffULL) != 0)) {
        return EINVAL;
    }
    *value = (uint64_t)parsed;
    return 0;
}

static int vphone_kcall(uint64_t function, const uint64_t arguments[3],
                        uint64_t *result)
{
    uint64_t values[CNDVPhoneKCallMaxArguments] = {
        arguments[0], arguments[1], arguments[2], 0, 0, 0, 0,
    };
    register uint64_t x0 __asm("x0") = function;
    register uint64_t x1 __asm("x1") = values[0];
    register uint64_t x2 __asm("x2") = values[1];
    register uint64_t x3 __asm("x3") = values[2];
    register uint64_t x4 __asm("x4") = values[3];
    register uint64_t x5 __asm("x5") = values[4];
    register uint64_t x6 __asm("x6") = values[5];
    register uint64_t x7 __asm("x7") = values[6];
    register uint64_t x16 __asm("x16") = CNDVPhoneKCallSyscall;
    unsigned int failed = 0;
    __asm__ volatile(
        "svc #0x80\n\t"
        "cset %w[failed], cs"
        : "+r"(x0), [failed] "=&r"(failed)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6),
          "r"(x7), "r"(x16)
        : "cc", "memory");
    if (failed) return x0 <= INT_MAX ? (int)x0 : EIO;
    *result = x0;
    return 0;
}

static int pac_call(uint64_t function, uint64_t pointer, uint64_t key,
                    uint64_t *result)
{
    const uint64_t arguments[3] = { pointer, key, CNDDiscriminator };
    return vphone_kcall(function, arguments, result);
}

static int pac_call_with_discriminator(uint64_t function, uint64_t pointer,
                                       uint64_t key, uint64_t discriminator,
                                       uint64_t *result)
{
    const uint64_t arguments[3] = { pointer, key, discriminator };
    return vphone_kcall(function, arguments, result);
}

static int thread_state_consumer_probe(uint64_t sign_stub,
                                       uint64_t auth_stub,
                                       uint64_t current_thread_stub)
{
    CNDWorkerReady = 0;
    CNDWorkerStop = 0;
    CNDWorkerKCallResult = 0;
    CNDWorkerKernelThread = 0;
    CNDWorkerCurrentThreadStub = current_thread_stub;
    pthread_t worker = NULL;
    int pthread_result = pthread_create(
        &worker, NULL, thread_state_worker, NULL);
    if (pthread_result != 0) {
        fprintf(stderr, "pthread_create failed=%d\n", pthread_result);
        return 3;
    }
    for (unsigned int attempt = 0; !CNDWorkerReady && attempt < 1000;
         attempt++) {
        usleep(1000);
    }
    thread_act_t thread = pthread_mach_thread_np(worker);
    uint64_t kernel_thread = CNDWorkerKernelThread;
    if (!CNDWorkerReady || !MACH_PORT_VALID(thread) ||
        CNDWorkerKCallResult != 0 ||
        (kernel_thread & 0xffff000000000000ULL) !=
            0xffff000000000000ULL) {
        CNDWorkerStop = 1;
        (void)pthread_join(worker, NULL);
        fprintf(stderr,
                "worker did not publish a valid thread mach=%u kcall=%d "
                "kernel=%#llx\n",
                thread, CNDWorkerKCallResult, kernel_thread);
        return 3;
    }
    uint64_t worker_start =
        (uint64_t)(uintptr_t)&thread_state_worker & CNDUserPointerMask;
    const char *ready_path = getenv("CND_PAC_PROBE_READY_PATH");
    const char *delay_text = getenv("CND_PAC_PROBE_DELAY_MS");
    static const char ready_prefix[] = "/var/tmp/cnd-sptm-pac-ready-";
    unsigned long delay_ms = 0;
    if (delay_text) {
        char *end = NULL;
        delay_ms = strtoul(delay_text, &end, 10);
        if (!end || *end != '\0' || delay_ms > 30000) {
            CNDWorkerStop = 1;
            (void)pthread_join(worker, NULL);
            fprintf(stderr, "invalid CND_PAC_PROBE_DELAY_MS\n");
            return 3;
        }
    }
    arm_thread_state64_t state = {0};
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(
        thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
    if (kr != KERN_SUCCESS || count != ARM_THREAD_STATE64_COUNT) {
        CNDWorkerStop = 1;
        (void)pthread_join(worker, NULL);
        fprintf(stderr,
                "thread_get_state failed kr=%d count=%u\n", kr, count);
        return 3;
    }
#if __DARWIN_OPAQUE_ARM_THREAD_STATE64
    uint64_t state_pc = (uint64_t)(uintptr_t)state.__opaque_pc;
    uint32_t state_flags = state.__opaque_flags;
#else
    uint64_t state_pc = state.__pc;
    uint32_t state_flags = 0;
#endif
    uint64_t raw_pc = state_pc & CNDUserPointerMask;
#if __has_feature(ptrauth_calls)
    uint64_t api_authenticated_pc = arm_thread_state64_get_pc(state);
#else
    uint64_t api_authenticated_pc = raw_pc;
#endif
    uint64_t sptm_pc = 0;
    uint64_t authenticated_pc = 0;
    int result = pac_call_with_discriminator(
        sign_stub, raw_pc, 0, CNDPCDiscriminator, &sptm_pc);
    if (result == 0) {
        result = pac_call_with_discriminator(
            auth_stub, sptm_pc, 0, CNDPCDiscriminator, &authenticated_pc);
    }
    int state_is_signed = state_pc != raw_pc &&
        (state_flags & CNDThreadStateNoPtrauth) == 0 &&
        (state_flags & CNDThreadStateKernelSignedPC) != 0;
    if (result != 0 || state_pc == 0 || raw_pc == 0 ||
        !state_is_signed || api_authenticated_pc != raw_pc ||
        authenticated_pc != raw_pc ||
        raw_pc < worker_start || raw_pc >= worker_start + 0x1000) {
        fprintf(stderr,
                "thread-state PAC consumer mismatch result=%d flags=%#x "
                "statePC=%#llx rawPC=%#llx apiPC=%#llx sptmPC=%#llx "
                "authPC=%#llx worker=%#llx\n",
                result, state_flags, state_pc, raw_pc, api_authenticated_pc,
                sptm_pc, authenticated_pc, worker_start);
        CNDWorkerStop = 1;
        (void)pthread_join(worker, NULL);
        return 3;
    }
    if (ready_path && strncmp(ready_path, ready_prefix,
                             sizeof(ready_prefix) - 1) == 0) {
        FILE *ready = fopen(ready_path, "w");
        int ready_failed = !ready;
        if (ready && fprintf(
                ready,
                "pid=%d\nworker_start=%#018llx\nkernel_thread=%#018llx\n"
                "signed_pc=%#018llx\nraw_pc=%#018llx\n",
                getpid(), worker_start, kernel_thread, state_pc, raw_pc) < 0) {
            ready_failed = 1;
        }
        if (ready && fclose(ready) != 0) ready_failed = 1;
        if (ready_failed) {
            CNDWorkerStop = 1;
            (void)pthread_join(worker, NULL);
            fprintf(stderr, "failed to publish ready marker\n");
            return 3;
        }
    }
    if (delay_ms > 0) {
        sleep((unsigned int)(delay_ms / 1000));
        usleep((useconds_t)(delay_ms % 1000) * 1000);
    }
    CNDWorkerStop = 1;
    pthread_result = pthread_join(worker, NULL);
    if (ready_path) (void)unlink(ready_path);
    if (pthread_result != 0) {
        fprintf(stderr, "worker join failed=%d\n", pthread_result);
        return 3;
    }
    printf("{\"schema\":\"com.zeroxjf.cyanide.sptm-pac-process-probe\","
           "\"schema_version\":1,\"mode\":\"thread-state\","
           "\"persistent_mutation\":false,"
           "\"thread_state_flags\":\"%#010x\","
           "\"thread_state_signed_pc\":\"%#018llx\","
           "\"thread_state_raw_pc\":\"%#018llx\","
           "\"thread_state_api_authenticated_pc\":\"%#018llx\","
           "\"worker_start\":\"%#018llx\","
           "\"kernel_thread\":\"%#018llx\","
           "\"current_thread_stub\":\"%#018llx\","
           "\"pc_discriminator\":\"%#018llx\","
           "\"sptm_signed_pc\":\"%#018llx\","
           "\"sptm_authenticated_pc\":\"%#018llx\","
           "\"raw_selector_matches_thread_state\":%s}\n",
           state_flags, state_pc, raw_pc, api_authenticated_pc, worker_start,
           kernel_thread, current_thread_stub, CNDPCDiscriminator, sptm_pc,
           authenticated_pc,
           sptm_pc == state_pc ? "true" : "false");
    return 0;
}

int main(int argc, char **argv)
{
    if ((argc != 3 && argc != 5) ||
        (strcmp(argv[2], "sign") != 0 && strcmp(argv[2], "auth") != 0 &&
         strcmp(argv[2], "thread-state") != 0) ||
        (strcmp(argv[2], "sign") == 0 && argc != 3) ||
        (strcmp(argv[2], "auth") == 0 && argc != 5) ||
        (strcmp(argv[2], "thread-state") == 0 && argc != 3)) {
        fprintf(stderr,
                "usage: %s LIVE_INNER_KERNEL_TEXT "
                "sign|thread-state|auth KEY0_SIGNATURE KEY2_SIGNATURE\n",
                argv[0]);
        return 2;
    }
    uint64_t live_text = 0;
    if (parse_hex64(argv[1], &live_text, 1) != 0 ||
        live_text < CNDStaticKernelText) {
        fprintf(stderr, "invalid live inner kernel text\n");
        return 2;
    }
    uint64_t slide = live_text - CNDStaticKernelText;
    uint64_t sign_stub = CNDStaticSignStub + slide;
    uint64_t auth_stub = CNDStaticAuthStub + slide;
    uint64_t current_thread_stub = CNDStaticCurrentThread + slide;
    if (strcmp(argv[2], "thread-state") == 0) {
        return thread_state_consumer_probe(
            sign_stub, auth_stub, current_thread_stub);
    }
    uint64_t key0 = 0;
    uint64_t key2 = 0;
    uint64_t auth0 = 0;
    uint64_t auth2 = 0;
    int result = 0;
    if (strcmp(argv[2], "sign") == 0) {
        result = pac_call(sign_stub, CNDPointer, 0, &key0);
        if (result == 0) result = pac_call(auth_stub, key0, 0, &auth0);
        if (result == 0) result = pac_call(sign_stub, CNDPointer, 2, &key2);
        if (result == 0) result = pac_call(auth_stub, key2, 2, &auth2);
        if (result != 0 || key0 == CNDPointer || key2 == CNDPointer ||
            auth0 != CNDPointer || auth2 != CNDPointer) {
            fprintf(stderr,
                    "process-local PAC round trip failed result=%d "
                    "key0=%#llx auth0=%#llx key2=%#llx auth2=%#llx\n",
                    result, key0, auth0, key2, auth2);
            return 3;
        }
    } else {
        if (parse_hex64(argv[3], &key0, 0) != 0 ||
            parse_hex64(argv[4], &key2, 0) != 0) {
            fprintf(stderr, "invalid signatures\n");
            return 2;
        }
        result = pac_call(auth_stub, key0, 0, &auth0);
        if (result == 0) result = pac_call(auth_stub, key2, 2, &auth2);
        if (result != 0) {
            fprintf(stderr, "cross-process authentication call failed=%d\n",
                    result);
            return 3;
        }
    }
    printf("{\"schema\":\"com.zeroxjf.cyanide.sptm-pac-process-probe\","
           "\"schema_version\":1,\"mode\":\"%s\","
           "\"persistent_mutation\":false,"
           "\"key_0_signature\":\"%#018llx\","
           "\"key_0_auth_result\":\"%#018llx\","
           "\"key_2_signature\":\"%#018llx\","
           "\"key_2_auth_result\":\"%#018llx\"}\n",
           argv[2], key0, auth0, key2, auth2);
    return 0;
}
