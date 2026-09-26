#include "CNDLabKernelProtocol.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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
    int sends_payload = operation == CNDLabKRWOperationResolvePID ||
        operation == CNDLabKRWOperationTaskWrite;
    int receives_payload = operation == CNDLabKRWOperationTaskRead;
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

int main(int argc, char **argv)
{
    if (argc != 3 || strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path) ||
        strlen(argv[2]) == 0 || strlen(argv[2]) >= 31) {
        fprintf(stderr, "usage: %s SOCKET PROCESS\n", argv[0]);
        return 2;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, argv[1]);
    if (fd < 0 || connect(fd, (struct sockaddr *)&address,
                          sizeof(address)) != 0) {
        perror("connect");
        return 3;
    }

    uint64_t capabilities = 0;
    int result = request(fd, CNDLabKRWOperationCapabilities,
                         0, NULL, 0, &capabilities);
    if (result != 0 ||
        (capabilities & CNDLabKRWCapabilityProcessResolve) == 0) {
        fprintf(stderr, "capability probe failed result=%d capabilities=%#llx\n",
                result, capabilities);
        return 4;
    }

    uint64_t pid = 0;
    result = request(fd, CNDLabKRWOperationResolvePID, 0, argv[2],
                     strlen(argv[2]) + 1, &pid);
    if (result == 0 &&
        (capabilities & CNDLabKRWCapabilityDirectTask) == 0) {
        close(fd);
        printf("ready process=%s pid=%llu capabilities=%#llx "
               "mode=resolve-only\n", argv[2], pid, capabilities);
        return 0;
    }
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationTaskOpen,
                         pid, NULL, 0, NULL);
    }
    uint64_t remote = 0;
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationTaskAllocate,
                         0, NULL, 0x4000, &remote);
    }
    uint64_t expected = 0x434e444c41424b52ULL;
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationTaskWrite,
                         remote, &expected, sizeof(expected), NULL);
    }
    uint64_t observed = 0;
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationTaskRead,
                         remote, &observed, sizeof(observed), NULL);
    }
    if (result == 0 && observed != expected) result = EILSEQ;
    int deallocate_result = remote ? request(
        fd, CNDLabKRWOperationTaskDeallocate,
        remote, NULL, 0x4000, NULL) : 0;
    int close_result = request(fd, CNDLabKRWOperationTaskClose,
                               0, NULL, 0, NULL);
    close(fd);

    if (result != 0 || deallocate_result != 0 || close_result != 0) {
        fprintf(stderr,
                "direct-task probe failed pid=%llu address=%#llx "
                "operation=%d deallocate=%d close=%d\n",
                pid, remote, result, deallocate_result, close_result);
        return 5;
    }
    printf("ready process=%s pid=%llu capabilities=%#llx address=%#llx "
           "readback=yes close=yes\n", argv[2], pid, capabilities, remote);
    return 0;
}
