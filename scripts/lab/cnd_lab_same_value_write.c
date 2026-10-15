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
 * Bounded VM-lab page-permission probe.  It reads one uint64_t, asks the
 * provider to write the identical bytes back, and verifies that the value did
 * not change.  KernelCall is neither requested nor accepted.
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
    if (operation != CNDLabKRWOperationCapabilities &&
        operation != CNDLabKRWOperationRead &&
        operation != CNDLabKRWOperationWrite) {
        return EPERM;
    }
    if ((operation == CNDLabKRWOperationRead ||
         operation == CNDLabKRWOperationWrite) &&
        length != sizeof(uint64_t)) {
        return EINVAL;
    }
    CNDLabKRWRequest message = {
        .magic = CND_LAB_KRW_MAGIC,
        .version = CND_LAB_KRW_VERSION,
        .operation = operation,
        .length = (uint32_t)length,
        .address = address,
    };
    int result = transfer_all(fd, &message, sizeof(message), 1);
    if (result == 0 && operation == CNDLabKRWOperationWrite) {
        result = transfer_all(fd, buffer, length, 1);
    }
    CNDLabKRWResponse response = {0};
    if (result == 0) {
        result = transfer_all(fd, &response, sizeof(response), 0);
    }
    if (result == 0 && (response.magic != CND_LAB_KRW_MAGIC ||
        response.status != 0 ||
        (operation == CNDLabKRWOperationRead &&
         response.length != length))) {
        result = response.status != 0 ? response.status : EPROTO;
    }
    if (result == 0 && operation == CNDLabKRWOperationRead) {
        result = transfer_all(fd, buffer, length, 0);
    }
    if (result == 0 && value != NULL) *value = response.value;
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 3 || strlen(argv[1]) >=
            sizeof(((struct sockaddr_un *)0)->sun_path)) {
        fprintf(stderr, "usage: %s SOCKET KERNEL_ADDRESS\n", argv[0]);
        return 2;
    }
    char *end = NULL;
    errno = 0;
    uint64_t address = strtoull(argv[2], &end, 0);
    if (errno != 0 || end == argv[2] || *end != '\0' ||
        (address & UINT64_C(0xffff000000000000)) !=
            UINT64_C(0xffff000000000000)) {
        fprintf(stderr, "invalid kernel address\n");
        return 2;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un socket_address = { .sun_family = AF_UNIX };
    strcpy(socket_address.sun_path, argv[1]);
    if (fd < 0 || connect(fd, (struct sockaddr *)&socket_address,
                          sizeof(socket_address)) != 0) {
        perror("connect");
        return 3;
    }

    uint64_t capabilities = 0;
    int read_result = request(fd, CNDLabKRWOperationCapabilities,
                              0, NULL, 0, &capabilities);
    uint64_t before = 0;
    if (read_result == 0) {
        read_result = request(fd, CNDLabKRWOperationRead, address,
                              &before, sizeof(before), NULL);
    }
    int write_result = read_result == 0
        ? request(fd, CNDLabKRWOperationWrite, address,
                  &before, sizeof(before), NULL) : read_result;
    uint64_t after = 0;
    int verify_result = request(fd, CNDLabKRWOperationRead, address,
                                &after, sizeof(after), NULL);
    close(fd);

    printf("{\"address\":\"%#" PRIx64 "\","
           "\"capabilities\":\"%#" PRIx64 "\","
           "\"before\":\"%#" PRIx64 "\","
           "\"after\":\"%#" PRIx64 "\","
           "\"readResult\":%d,\"writeResult\":%d,"
           "\"verifyResult\":%d,\"sameValue\":%s,"
           "\"usedKernelCall\":false}\n",
           address, capabilities, before, after, read_result, write_result,
           verify_result, before == after ? "true" : "false");
    return read_result == 0 && write_result == 0 &&
        verify_result == 0 && before == after ? 0 : 1;
}
