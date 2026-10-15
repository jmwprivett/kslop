#include "CNDLabKernelProtocol.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * VM-only call probe for experiments that need to instantiate or inspect a
 * kernel object before the real no-provider boundary test begins.  The probe
 * refuses providers without the explicit KernelCall capability and binds each
 * invocation to the caller-supplied live kernel base.
 */

static int transfer_all(int fd, void *buffer, size_t size, int writing)
{
    unsigned char *cursor = buffer;
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

static int request(int fd, uint32_t operation, void *payload, size_t length,
                   uint64_t *value)
{
    int sends_payload = operation == CNDLabKRWOperationKernelCall;
    CNDLabKRWRequest request = {
        .magic = CND_LAB_KRW_MAGIC,
        .version = CND_LAB_KRW_VERSION,
        .operation = operation,
        .length = (uint32_t)length,
        .address = 0,
    };
    int result = transfer_all(fd, &request, sizeof(request), 1);
    if (result == 0 && sends_payload && length != 0) {
        result = transfer_all(fd, payload, length, 1);
    }
    CNDLabKRWResponse response = {0};
    if (result == 0) {
        result = transfer_all(fd, &response, sizeof(response), 0);
    }
    if (result == 0 && (response.magic != CND_LAB_KRW_MAGIC ||
        response.status != 0 || response.length != 0)) {
        result = response.status != 0 ? response.status : EPROTO;
    }
    if (result == 0 && value != NULL) *value = response.value;
    return result;
}

static int parse_u64(const char *text, uint64_t *value)
{
    if (text == NULL || value == NULL || text[0] == '\0' || text[0] == '-') {
        return EINVAL;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') return EINVAL;
    *value = (uint64_t)parsed;
    return 0;
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

int main(int argc, char **argv)
{
    if (argc < 4 || argc > 4 + (int)CND_LAB_KCALL_MAX_ARGUMENTS) {
        fprintf(stderr,
                "usage: %s PROVIDER_SOCKET EXPECTED_KERNEL_BASE FUNCTION "
                "[ARG0 ... ARG7]\n", argv[0]);
        return 64;
    }

    uint64_t expected_base = 0;
    uint64_t function = 0;
    if (parse_u64(argv[2], &expected_base) != 0 ||
        parse_u64(argv[3], &function) != 0 || (function & 3) != 0) {
        fprintf(stderr, "invalid kernel base or function\n");
        return 64;
    }
    CNDLabKernelCallRequest call = {
        .version = CND_LAB_KCALL_ABI_VERSION,
        .argument_count = (uint32_t)(argc - 4),
        .function = function,
    };
    for (int index = 4; index < argc; index++) {
        if (parse_u64(argv[index], &call.arguments[index - 4]) != 0) {
            fprintf(stderr, "invalid argument %d\n", index - 4);
            return 64;
        }
    }

    int fd = connect_provider(argv[1]);
    if (fd < 0) {
        fprintf(stderr, "provider connect failed: %s\n", strerror(errno));
        return 1;
    }
    uint64_t capabilities = 0;
    uint64_t kernel_base = 0;
    int result = request(fd, CNDLabKRWOperationCapabilities, NULL, 0,
                         &capabilities);
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationKBase, NULL, 0, &kernel_base);
    }
    uint64_t required = CNDLabKRWCapabilityKernelReadWrite |
        CNDLabKRWCapabilityKernelCall;
    if (result != 0 || kernel_base != expected_base ||
        (capabilities & required) != required) {
        fprintf(stderr,
                "provider identity failed: result=%d base=%#llx "
                "expected=%#llx capabilities=%#llx\n",
                result, kernel_base, expected_base, capabilities);
        close(fd);
        return 2;
    }

    uint64_t call_result = 0;
    result = request(fd, CNDLabKRWOperationKernelCall, &call, sizeof(call),
                     &call_result);
    close(fd);
    if (result != 0) {
        fprintf(stderr, "kernel call failed: %d\n", result);
        return 3;
    }

    printf("{\"schema\":\"com.zeroxjf.cyanide.lab-provider-call\","
           "\"schemaVersion\":1,\"kernelBase\":\"%#llx\","
           "\"capabilities\":\"%#llx\",\"function\":\"%#llx\","
           "\"argumentCount\":%u,\"result\":\"%#llx\","
           "\"usedKernelWrite\":false,\"usedKernelCall\":true}\n",
           kernel_base, capabilities, function, call.argument_count,
           call_result);
    return 0;
}
