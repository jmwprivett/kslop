#include "CNDLabKernelProtocol.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

enum {
    CNDProbeExitUsage = 2,
    CNDProbeExitConnection = 3,
    CNDProbeExitIdentity = 4,
    CNDProbeExitCall = 5,
};

/*
 * The provider returns the outer MH_FILESET base. LLDB reports the inner
 * com.apple.kernel __TEXT address, which is exactly one 16K page later in
 * this image. Both therefore produce the same slide when kept distinct.
 */
static const uint64_t CNDStaticFilesetBase = 0xfffffe0007004000ULL;
static const uint64_t CNDStaticSignStub = 0xfffffe00082f3788ULL;
static const uint64_t CNDStaticAuthStub = 0xfffffe00082f37a0ULL;
static const uint64_t CNDStaticPmapSign = 0xfffffe0007c418fcULL;
static const uint64_t CNDStaticPmapAuth = 0xfffffe0007c41c08ULL;
static const uint64_t CNDStaticCurrentThread = 0xfffffe0007c56714ULL;
/* Exact 23A341 vPhone kernel: machine_thread_state_convert_to_user loads
 * thread->machine.jop_pid from +0x1b0 before pmap_sign_user_ptr. */
static const uint64_t CNDThreadMachineJopPIDOffset = 0x1b0ULL;
static const uint64_t CNDPCDiscriminator = 0x0000000000007481ULL;

static int transfer_all(int fd, void *buffer, size_t size, int writing)
{
    unsigned char *cursor = buffer;
    while (size > 0) {
        ssize_t amount = writing
            ? write(fd, cursor, size) : read(fd, cursor, size);
        if (amount == 0) return ECONNRESET;
        if (amount < 0) {
            if (errno == EINTR) continue;
            return errno ?: EIO;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return 0;
}

static int request(int fd, uint32_t operation, uint64_t address,
                   void *buffer, size_t length, uint64_t *value)
{
    int sends_payload = operation == CNDLabKRWOperationKernelCall;
    int receives_payload = operation == CNDLabKRWOperationRead;
    CNDLabKRWRequest message = {
        .magic = CND_LAB_KRW_MAGIC,
        .version = CND_LAB_KRW_VERSION,
        .operation = operation,
        .length = (uint32_t)length,
        .address = address,
    };
    int result = transfer_all(fd, &message, sizeof(message), 1);
    if (result == 0 && sends_payload && length > 0) {
        result = transfer_all(fd, buffer, length, 1);
    }
    CNDLabKRWResponse response = {0};
    if (result == 0) {
        result = transfer_all(fd, &response, sizeof(response), 0);
    }
    if (result == 0 && (response.magic != CND_LAB_KRW_MAGIC ||
        response.status != 0 ||
        (receives_payload && response.length != length))) {
        result = response.status ?: EPROTO;
    }
    if (result == 0 && receives_payload && length > 0) {
        result = transfer_all(fd, buffer, length, 0);
    }
    if (result == 0 && value) *value = response.value;
    return result;
}

static int parse_kernel_base(const char *text, uint64_t *value)
{
    if (!text || strlen(text) != 18 || text[0] != '0' || text[1] != 'x') {
        return EINVAL;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 16);
    if (errno != 0 || !end || *end != '\0' ||
        (parsed & 0xffff000000000000ULL) != 0xffff000000000000ULL ||
        (parsed & 0x3fffULL) != 0) {
        return EINVAL;
    }
    *value = (uint64_t)parsed;
    return 0;
}

static int parse_hex64(const char *text, uint64_t *value)
{
    if (!text || strlen(text) != 18 || text[0] != '0' || text[1] != 'x') {
        return EINVAL;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 16);
    if (errno != 0 || !end || *end != '\0') return EINVAL;
    *value = (uint64_t)parsed;
    return 0;
}

static int verify_stub(int fd, uint64_t address, const uint32_t *expected,
                       size_t word_count)
{
    if (!expected || word_count == 0 || word_count > 6) return EINVAL;
    uint32_t observed[6] = {0};
    int result = request(fd, CNDLabKRWOperationRead, address,
                         observed, word_count * sizeof(observed[0]), NULL);
    if (result != 0) return result;
    return memcmp(observed, expected,
                  word_count * sizeof(observed[0])) == 0 ? 0 : EILSEQ;
}

static int kernel_call(int fd, uint64_t function, uint64_t pointer,
                       uint64_t key, uint64_t discriminator,
                       uint64_t *result)
{
    CNDLabKernelCallRequest call = {
        .version = CND_LAB_KCALL_ABI_VERSION,
        .argument_count = 3,
        .function = function,
        .arguments = { pointer, key, discriminator },
    };
    return request(fd, CNDLabKRWOperationKernelCall,
                   0, &call, sizeof(call), result);
}

static int kernel_call4(int fd, uint64_t function, uint64_t pointer,
                        uint64_t key, uint64_t discriminator,
                        uint64_t jop_key, uint64_t *result)
{
    CNDLabKernelCallRequest call = {
        .version = CND_LAB_KCALL_ABI_VERSION,
        .argument_count = 4,
        .function = function,
        .arguments = { pointer, key, discriminator, jop_key },
    };
    return request(fd, CNDLabKRWOperationKernelCall,
                   0, &call, sizeof(call), result);
}

int main(int argc, char **argv)
{
    int context_mode = argc == 7 && strcmp(argv[3], "context") == 0;
    if ((argc != 3 && !context_mode) ||
        strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        fprintf(stderr,
                "usage: %s SOCKET EXPECTED_KERNEL_BASE "
                "[context KERNEL_THREAD SIGNED_PC RAW_PC]\n", argv[0]);
        return CNDProbeExitUsage;
    }
    uint64_t expected_base = 0;
    if (parse_kernel_base(argv[2], &expected_base) != 0) {
        fprintf(stderr, "invalid expected kernel base\n");
        return CNDProbeExitUsage;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, argv[1]);
    if (fd < 0 || connect(fd, (struct sockaddr *)&address,
                          sizeof(address)) != 0) {
        perror("connect");
        return CNDProbeExitConnection;
    }

    uint64_t capabilities = 0;
    uint64_t live_base = 0;
    int result = request(fd, CNDLabKRWOperationCapabilities,
                         0, NULL, 0, &capabilities);
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationKBase,
                         0, NULL, 0, &live_base);
    }
    uint64_t required = CNDLabKRWCapabilityKernelReadWrite |
        CNDLabKRWCapabilityKernelCall;
    if (result != 0 || (capabilities & required) != required ||
        live_base != expected_base || live_base < CNDStaticFilesetBase) {
        fprintf(stderr,
                "identity/capability mismatch result=%d capabilities=%#llx "
                "expected=%#llx observed=%#llx\n",
                result, capabilities, expected_base, live_base);
        close(fd);
        return CNDProbeExitIdentity;
    }

    uint64_t slide = live_base - CNDStaticFilesetBase;
    uint64_t sign_stub = CNDStaticSignStub + slide;
    uint64_t auth_stub = CNDStaticAuthStub + slide;
    uint64_t pmap_sign = CNDStaticPmapSign + slide;
    uint64_t pmap_auth = CNDStaticPmapAuth + slide;
    uint64_t current_thread_stub = CNDStaticCurrentThread + slide;
    static const uint32_t sign_words[6] = {
        0xd503245fU, 0xf2e00010U, 0xf2c00010U,
        0xf2a00010U, 0xf2800210U, 0x144b56b1U,
    };
    static const uint32_t auth_words[6] = {
        0xd503245fU, 0xf2e00010U, 0xf2c00010U,
        0xf2a00010U, 0xf2800230U, 0x144b56abU,
    };
    result = verify_stub(fd, sign_stub, sign_words, 6);
    if (result == 0) result = verify_stub(fd, auth_stub, auth_words, 6);
    if (result != 0) {
        fprintf(stderr, "live XNU SPTM stub verification failed result=%d\n",
                result);
        close(fd);
        return CNDProbeExitIdentity;
    }

    if (context_mode) {
        uint64_t kernel_thread = 0;
        uint64_t expected_signed_pc = 0;
        uint64_t raw_pc = 0;
        if (parse_hex64(argv[4], &kernel_thread) != 0 ||
            parse_hex64(argv[5], &expected_signed_pc) != 0 ||
            parse_hex64(argv[6], &raw_pc) != 0 ||
            (kernel_thread & 0xffff000000000000ULL) !=
                0xffff000000000000ULL || raw_pc >= 0x0000008000000000ULL ||
            kernel_thread > UINT64_MAX - CNDThreadMachineJopPIDOffset) {
            fprintf(stderr, "invalid target-context arguments\n");
            close(fd);
            return CNDProbeExitUsage;
        }
        static const uint32_t current_thread_words[2] = {
            0xd538d080U, 0xd65f03c0U,
        };
        result = verify_stub(
            fd, current_thread_stub, current_thread_words, 2);
        uint64_t jop_pid = 0;
        if (result == 0) {
            result = request(
                fd, CNDLabKRWOperationRead,
                kernel_thread + CNDThreadMachineJopPIDOffset,
                &jop_pid, sizeof(jop_pid), NULL);
        }
        uint64_t context_signed_pc = 0;
        uint64_t context_authenticated_pc = 0;
        if (result == 0) {
            result = kernel_call4(
                fd, pmap_sign, raw_pc, 0, CNDPCDiscriminator, jop_pid,
                &context_signed_pc);
        }
        if (result == 0) {
            result = kernel_call4(
                fd, pmap_auth, context_signed_pc, 0, CNDPCDiscriminator,
                jop_pid, &context_authenticated_pc);
        }
        close(fd);
        if (result != 0 || context_signed_pc != expected_signed_pc ||
            context_authenticated_pc != raw_pc) {
            fprintf(stderr,
                    "target-context PAC mismatch result=%d thread=%#llx "
                    "jop=%#llx expected=%#llx signed=%#llx raw=%#llx "
                    "authenticated=%#llx\n",
                    result, kernel_thread, jop_pid, expected_signed_pc,
                    context_signed_pc, raw_pc, context_authenticated_pc);
            return CNDProbeExitCall;
        }
        printf("{\"schema\":"
               "\"com.zeroxjf.cyanide.sptm-pac-target-context-probe\","
               "\"schema_version\":1,\"persistent_mutation\":false,"
               "\"kernel_thread\":\"%#018llx\","
               "\"thread_jop_pid_offset\":\"%#018llx\","
               "\"jop_pid\":\"%#018llx\","
               "\"raw_pc\":\"%#018llx\","
               "\"expected_signed_pc\":\"%#018llx\","
               "\"context_signed_pc\":\"%#018llx\","
               "\"context_authenticated_pc\":\"%#018llx\","
               "\"current_thread_stub\":\"%#018llx\","
               "\"pmap_sign_wrapper\":\"%#018llx\","
               "\"pmap_auth_wrapper\":\"%#018llx\","
               "\"exact_match\":true}\n",
               kernel_thread, CNDThreadMachineJopPIDOffset, jop_pid, raw_pc,
               expected_signed_pc, context_signed_pc,
               context_authenticated_pc, current_thread_stub, pmap_sign,
               pmap_auth);
        return 0;
    }

    static const uint64_t pointer = 0x0000000100000000ULL;
    static const uint64_t discriminator = 0x0000000000434e44ULL;
    uint64_t signed_ia = 0;
    uint64_t authenticated_ia = 0;
    uint64_t rejected_ia = 0;
    uint64_t signed_da = 0;
    uint64_t authenticated_da = 0;
    static const uint64_t jop_key_a = 0x434e440100000001ULL;
    static const uint64_t jop_key_b = 0x434e440200000001ULL;
    uint64_t explicit_signed_a = 0;
    uint64_t explicit_authenticated_a = 0;
    uint64_t explicit_wrong_key = 0;
    uint64_t explicit_signed_b = 0;
    result = kernel_call(fd, sign_stub, pointer, 0, discriminator, &signed_ia);
    if (result == 0) {
        result = kernel_call(fd, auth_stub, signed_ia, 0, discriminator,
                             &authenticated_ia);
    }
    if (result == 0) {
        result = kernel_call(fd, auth_stub, signed_ia, 0, discriminator + 1,
                             &rejected_ia);
    }
    if (result == 0) {
        result = kernel_call(fd, sign_stub, pointer, 2, discriminator,
                             &signed_da);
    }
    if (result == 0) {
        result = kernel_call(fd, auth_stub, signed_da, 2, discriminator,
                             &authenticated_da);
    }
    if (result == 0) {
        result = kernel_call4(fd, pmap_sign, pointer, 0, discriminator,
                              jop_key_a, &explicit_signed_a);
    }
    if (result == 0) {
        result = kernel_call4(fd, pmap_auth, explicit_signed_a, 0,
                              discriminator, jop_key_a,
                              &explicit_authenticated_a);
    }
    if (result == 0) {
        result = kernel_call4(fd, pmap_auth, explicit_signed_a, 0,
                              discriminator, jop_key_b,
                              &explicit_wrong_key);
    }
    if (result == 0) {
        result = kernel_call4(fd, pmap_sign, pointer, 0, discriminator,
                              jop_key_b, &explicit_signed_b);
    }
    close(fd);
    if (result != 0 || signed_ia == pointer || signed_da == pointer ||
        authenticated_ia != pointer || authenticated_da != pointer ||
        rejected_ia != UINT64_MAX || explicit_signed_a == pointer ||
        explicit_signed_b == pointer || explicit_signed_a == explicit_signed_b ||
        explicit_authenticated_a != pointer || explicit_wrong_key == pointer) {
        fprintf(stderr,
                "PAC round trip failed result=%d ia=%#llx iaAuth=%#llx "
                "iaReject=%#llx da=%#llx daAuth=%#llx explicitA=%#llx "
                "explicitAAuth=%#llx explicitWrong=%#llx explicitB=%#llx\n",
                result, signed_ia, authenticated_ia, rejected_ia,
                signed_da, authenticated_da, explicit_signed_a,
                explicit_authenticated_a, explicit_wrong_key,
                explicit_signed_b);
        return CNDProbeExitCall;
    }

    printf("{\"schema\":\"com.zeroxjf.cyanide.sptm-pac-probe\","
           "\"schema_version\":1,\"persistent_mutation\":false,"
           "\"kernel_base\":\"%#018llx\",\"slide\":\"%#llx\","
           "\"sign_stub\":\"%#018llx\",\"auth_stub\":\"%#018llx\","
           "\"pointer\":\"%#018llx\",\"discriminator\":\"%#018llx\","
           "\"key_0_signed\":\"%#018llx\","
           "\"key_0_authenticated\":\"%#018llx\","
           "\"wrong_discriminator_result\":\"%#018llx\","
           "\"key_2_signed\":\"%#018llx\","
           "\"key_2_authenticated\":\"%#018llx\","
           "\"pmap_sign_wrapper\":\"%#018llx\","
           "\"pmap_auth_wrapper\":\"%#018llx\","
           "\"explicit_jop_key_a\":\"%#018llx\","
           "\"explicit_jop_key_a_signed\":\"%#018llx\","
           "\"explicit_jop_key_a_authenticated\":\"%#018llx\","
           "\"explicit_jop_key_b\":\"%#018llx\","
           "\"explicit_jop_key_b_signed\":\"%#018llx\","
           "\"key_a_signature_auth_with_key_b\":\"%#018llx\"}\n",
           live_base, slide, sign_stub, auth_stub, pointer, discriminator,
           signed_ia, authenticated_ia, rejected_ia,
           signed_da, authenticated_da, pmap_sign, pmap_auth,
           jop_key_a, explicit_signed_a, explicit_authenticated_a,
           jop_key_b, explicit_signed_b, explicit_wrong_key);
    return 0;
}
