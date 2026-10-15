#include "CNDLabKernelProtocol.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * Exact-base-bound VM provider KRW interface for reversible boundary tests.
 * It deliberately exposes no KernelCall operation.  Writes are limited to a
 * single 1-, 2-, 4-, or 8-byte scalar and require an exact readback match.
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

static int request(int fd, uint32_t operation, uint64_t address,
                   void *buffer, size_t length, uint64_t *value)
{
    int sends_payload = operation == CNDLabKRWOperationWrite;
    int receives_payload = operation == CNDLabKRWOperationRead;
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
    if (result == 0) {
        result = transfer_all(fd, &response, sizeof(response), 0);
    }
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

static int parse_u64(const char *text, uint64_t *value)
{
    if (!text || !value || !text[0] || text[0] == '-') return EINVAL;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') return EINVAL;
    *value = (uint64_t)parsed;
    return 0;
}

static int kernel_address(uint64_t address, size_t length)
{
    return length != 0 && address <= UINT64_MAX - (length - 1) &&
        (address & UINT64_C(0xffff000000000000)) ==
            UINT64_C(0xffff000000000000);
}

static int connect_provider(const char *path)
{
    if (!path || strlen(path) >=
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

static void print_bytes(const unsigned char *bytes, size_t length)
{
    for (size_t index = 0; index < length; index++) {
        printf("%02x", bytes[index]);
    }
}

int main(int argc, char **argv)
{
    if (argc < 5 || argc > 6) {
        fprintf(stderr,
                "usage: %s PROVIDER_SOCKET EXPECTED_KERNEL_BASE "
                "read ADDRESS LENGTH\n"
                "       %s PROVIDER_SOCKET EXPECTED_KERNEL_BASE "
                "write{1,2,4,8} ADDRESS VALUE\n",
                argv[0], argv[0]);
        return 64;
    }

    uint64_t expected_base = 0;
    uint64_t address = 0;
    if (parse_u64(argv[2], &expected_base) != 0 ||
        parse_u64(argv[4], &address) != 0) {
        fprintf(stderr, "invalid kernel base or address\n");
        return 64;
    }

    int reading = strcmp(argv[3], "read") == 0;
    size_t length = 0;
    uint64_t scalar = 0;
    if (reading) {
        uint64_t parsed_length = 0;
        if (argc != 6 || parse_u64(argv[5], &parsed_length) != 0 ||
            parsed_length == 0 || parsed_length > 64) {
            fprintf(stderr, "read length must be between 1 and 64\n");
            return 64;
        }
        length = (size_t)parsed_length;
    } else {
        uint64_t parsed_width = 0;
        if (argc != 6 || strncmp(argv[3], "write", 5) != 0 ||
            parse_u64(argv[3] + 5, &parsed_width) != 0 ||
            (parsed_width != 1 && parsed_width != 2 &&
             parsed_width != 4 && parsed_width != 8) ||
            parse_u64(argv[5], &scalar) != 0 ||
            (parsed_width < 8 &&
             scalar >= (UINT64_C(1) << (parsed_width * 8)))) {
            fprintf(stderr, "write width must be 1, 2, 4, or 8 bytes\n");
            return 64;
        }
        length = (size_t)parsed_width;
    }
    if (!kernel_address(address, length)) {
        fprintf(stderr, "non-canonical kernel range\n");
        return 64;
    }

    int fd = connect_provider(argv[1]);
    if (fd < 0) {
        fprintf(stderr, "provider connect failed: %s\n", strerror(errno));
        return 1;
    }
    uint64_t capabilities = 0;
    uint64_t kernel_base = 0;
    int result = request(fd, CNDLabKRWOperationCapabilities, 0,
                         NULL, 0, &capabilities);
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationKBase, 0,
                         NULL, 0, &kernel_base);
    }
    if (result != 0 || kernel_base != expected_base ||
        (capabilities & CNDLabKRWCapabilityKernelReadWrite) == 0) {
        fprintf(stderr,
                "provider identity failed: result=%d base=%#" PRIx64
                " expected=%#" PRIx64 " capabilities=%#" PRIx64 "\n",
                result, kernel_base, expected_base, capabilities);
        close(fd);
        return 2;
    }

    unsigned char bytes[64] = {0};
    if (reading) {
        result = request(fd, CNDLabKRWOperationRead, address,
                         bytes, length, NULL);
    } else {
        memcpy(bytes, &scalar, length);
        result = request(fd, CNDLabKRWOperationWrite, address,
                         bytes, length, NULL);
        unsigned char readback[8] = {0};
        if (result == 0) {
            result = request(fd, CNDLabKRWOperationRead, address,
                             readback, length, NULL);
        }
        if (result == 0 && memcmp(bytes, readback, length) != 0) {
            result = EIO;
        }
        if (result == 0) memcpy(bytes, readback, length);
    }
    close(fd);
    if (result != 0) {
        fprintf(stderr, "%s failed: %d\n", reading ? "read" : "write",
                result);
        return 3;
    }

    printf("{\"schema\":\"com.zeroxjf.cyanide.lab-provider-krw\","
           "\"schemaVersion\":1,\"kernelBase\":\"%#" PRIx64 "\","
           "\"capabilities\":\"%#" PRIx64 "\",\"operation\":\"%s\","
           "\"address\":\"%#" PRIx64 "\",\"length\":%zu,\"bytes\":\"",
           kernel_base, capabilities, reading ? "read" : "write",
           address, length);
    print_bytes(bytes, length);
    printf("\",\"writeVerified\":%s,\"usedKernelWrite\":%s,"
           "\"usedKernelCall\":false}\n",
           reading ? "false" : "true", reading ? "false" : "true");
    return 0;
}
