#include "CNDLabKernelPAC.h"
#include "CNDLabKernelProtocol.h"
#include "CNDLabKernelProvider.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

enum {
    CNDIntegrationExitUsage = 2,
    CNDIntegrationExitConnection = 3,
    CNDIntegrationExitIdentity = 4,
    CNDIntegrationExitConsumer = 5,
};

static int gSocket = -1;
static uint64_t gCapabilities;
static uint64_t gKernelBase;

static int transfer_all(int fd, void *buffer, size_t size, int writing)
{
    uint8_t *cursor = buffer;
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

static int request(uint32_t operation, uint64_t address,
                   void *buffer, size_t size, uint64_t *value)
{
    int sends_payload = operation == CNDLabKRWOperationKernelCall;
    int receives_payload = operation == CNDLabKRWOperationRead;
    if (gSocket < 0 || size > CND_LAB_KRW_MAX_TRANSFER) return EINVAL;
    CNDLabKRWRequest message = {
        .magic = CND_LAB_KRW_MAGIC,
        .version = CND_LAB_KRW_VERSION,
        .operation = operation,
        .length = (uint32_t)size,
        .address = address,
    };
    int result = transfer_all(gSocket, &message, sizeof(message), 1);
    if (result == 0 && sends_payload && size > 0) {
        result = transfer_all(gSocket, buffer, size, 1);
    }
    CNDLabKRWResponse response = {0};
    if (result == 0) {
        result = transfer_all(gSocket, &response, sizeof(response), 0);
    }
    if (result == 0 && (response.magic != CND_LAB_KRW_MAGIC ||
        response.status != 0 ||
        (receives_payload && response.length != size))) {
        result = response.status ?: EPROTO;
    }
    if (result == 0 && receives_payload && size > 0) {
        result = transfer_all(gSocket, buffer, size, 0);
    }
    if (result == 0 && value) *value = response.value;
    return result;
}

bool cnd_lab_krw_ready(void)
{
    return gSocket >= 0;
}

bool cnd_lab_kernel_call_active(void)
{
    return gSocket >= 0 &&
        (gCapabilities & CNDLabKRWCapabilityKernelCall) != 0;
}

bool cnd_lab_kernel_base(uint64_t *address_out)
{
    if (!address_out || gKernelBase == 0 ||
        (gCapabilities & CNDLabKRWCapabilityKernelReadWrite) == 0) {
        return false;
    }
    *address_out = gKernelBase;
    return true;
}

bool cnd_lab_krw_read(uint64_t address, void *buffer, size_t size)
{
    return buffer && size > 0 &&
        request(CNDLabKRWOperationRead, address, buffer, size, NULL) == 0;
}

int cnd_lab_kernel_call(uint64_t function, size_t argument_count,
                        const uint64_t *arguments, uint64_t *result_out)
{
    if (!result_out || argument_count > CND_LAB_KCALL_MAX_ARGUMENTS ||
        (argument_count > 0 && !arguments)) return EINVAL;
    CNDLabKernelCallRequest call = {
        .version = CND_LAB_KCALL_ABI_VERSION,
        .argument_count = (uint32_t)argument_count,
        .function = function,
    };
    if (argument_count > 0) {
        memcpy(call.arguments, arguments,
               argument_count * sizeof(arguments[0]));
    }
    return request(CNDLabKRWOperationKernelCall, 0,
                   &call, sizeof(call), result_out);
}

static int parse_hex64(const char *text, uint64_t *value)
{
    if (!text || !value || strlen(text) != 18 ||
        text[0] != '0' || text[1] != 'x') return EINVAL;
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 16);
    if (errno != 0 || !end || *end != '\0') return EINVAL;
    *value = (uint64_t)parsed;
    return 0;
}

static int connect_provider(const char *path)
{
    if (!path || strlen(path) >=
        sizeof(((struct sockaddr_un *)0)->sun_path)) return EINVAL;
    gSocket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (gSocket < 0) return errno ?: EIO;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, path);
    if (connect(gSocket, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int result = errno ?: EIO;
        close(gSocket);
        gSocket = -1;
        return result;
    }
    int result = request(CNDLabKRWOperationCapabilities,
                         0, NULL, 0, &gCapabilities);
    if (result == 0) {
        result = request(CNDLabKRWOperationKBase,
                         0, NULL, 0, &gKernelBase);
    }
    uint64_t required = CNDLabKRWCapabilityKernelReadWrite |
        CNDLabKRWCapabilityKernelCall;
    if (result != 0 || (gCapabilities & required) != required) {
        close(gSocket);
        gSocket = -1;
        return result ?: ENOTSUP;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr,
                "usage: %s SOCKET EXPECTED_BASE KERNEL_THREAD "
                "EXPECTED_SIGNED_PC RAW_PC\n", argv[0]);
        return CNDIntegrationExitUsage;
    }
    uint64_t expected_base = 0;
    uint64_t kernel_thread = 0;
    uint64_t expected_signed_pc = 0;
    uint64_t raw_pc = 0;
    if (parse_hex64(argv[2], &expected_base) != 0 ||
        parse_hex64(argv[3], &kernel_thread) != 0 ||
        parse_hex64(argv[4], &expected_signed_pc) != 0 ||
        parse_hex64(argv[5], &raw_pc) != 0) {
        fprintf(stderr, "invalid integration probe argument\n");
        return CNDIntegrationExitUsage;
    }
    int result = connect_provider(argv[1]);
    if (result != 0) {
        fprintf(stderr, "provider connection failed: %d\n", result);
        return CNDIntegrationExitConnection;
    }

    CNDLabPACProfile profile = {0};
    if (!cnd_lab_pac_profile(&profile) ||
        profile.version != CND_LAB_PAC_PROFILE_VERSION ||
        profile.kernel_base != expected_base ||
        profile.thread_machine_jop_pid_offset != 0x1b0ULL) {
        fprintf(stderr,
                "identity-bound PAC profile failed base=%#llx expected=%#llx\n",
                profile.kernel_base, expected_base);
        close(gSocket);
        return CNDIntegrationExitIdentity;
    }
    result = cnd_lab_pac_consumer_self_test(
        kernel_thread, raw_pc, expected_signed_pc,
        CNDLabPACKeyInstructionA, 0x7481ULL);
    uint64_t jop_pid = 0;
    if (result == 0) {
        result = cnd_lab_pac_thread_jop_pid(kernel_thread, &jop_pid);
    }
    close(gSocket);
    gSocket = -1;
    if (result != 0) {
        fprintf(stderr, "PAC consumer self-test failed: %d\n", result);
        return CNDIntegrationExitConsumer;
    }

    printf("{\"schema\":"
           "\"com.zeroxjf.cyanide.lab-pac-integration-probe\","
           "\"schema_version\":1,\"persistent_mutation\":false,"
           "\"kernel_uuid\":\"%s\","
           "\"kernel_base\":\"%#018llx\","
           "\"kernel_slide\":\"%#llx\","
           "\"kernel_thread\":\"%#018llx\","
           "\"thread_jop_pid_offset\":\"%#018llx\","
           "\"jop_pid\":\"%#018llx\","
           "\"raw_pc\":\"%#018llx\","
           "\"expected_signed_pc\":\"%#018llx\","
           "\"pmap_sign_wrapper\":\"%#018llx\","
           "\"pmap_auth_wrapper\":\"%#018llx\","
           "\"exact_consumer_match\":true}\n",
           CND_LAB_PAC_KERNEL_UUID, profile.kernel_base,
           profile.kernel_slide, kernel_thread,
           profile.thread_machine_jop_pid_offset, jop_pid, raw_pc,
           expected_signed_pc, profile.pmap_sign_user_ptr,
           profile.pmap_auth_user_ptr);
    return 0;
}
