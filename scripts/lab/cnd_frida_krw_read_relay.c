#include "CNDLabKernelProtocol.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * Read-only stdio relay for the Frida/KRW VM bridge.  The SSH server in the
 * research guest accepts StreamLocal forwarding but closes forwarded streams,
 * so the host starts this helper as an SSH command instead.  Only identity and
 * read operations are admitted; write, kcall, and task operations never reach
 * the provider.
 */

#define CND_BRIDGE_PROVIDER_SOCKET \
    "/var/tmp/cyanide-kcall-research.sock"

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

static int send_error(int status)
{
    CNDLabKRWResponse response = {
        .magic = CND_LAB_KRW_MAGIC,
        .status = status,
    };
    return transfer_all(STDOUT_FILENO, &response, sizeof(response), 1);
}

static int connect_provider(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    _Static_assert(sizeof(CND_BRIDGE_PROVIDER_SOCKET) <=
                   sizeof(address.sun_path), "provider socket path too long");
    strcpy(address.sun_path, CND_BRIDGE_PROVIDER_SOCKET);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int request_is_read_only(const CNDLabKRWRequest *request)
{
    if (request->magic != CND_LAB_KRW_MAGIC ||
        request->version != CND_LAB_KRW_VERSION) return 0;
    if (request->operation == CNDLabKRWOperationCapabilities ||
        request->operation == CNDLabKRWOperationKBase) {
        return request->length == 0 && request->address == 0;
    }
    if (request->operation != CNDLabKRWOperationRead ||
        request->length == 0 ||
        request->length > CND_LAB_KRW_MAX_TRANSFER ||
        request->address > UINT64_MAX - (request->length - 1)) return 0;
    uint64_t last = request->address + request->length - 1;
    return (request->address & UINT64_C(0xffff000000000000)) ==
               UINT64_C(0xffff000000000000) &&
           (last & UINT64_C(0xffff000000000000)) ==
               UINT64_C(0xffff000000000000);
}

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "this relay accepts no arguments\n");
        return 64;
    }
    int provider = connect_provider();
    if (provider < 0) {
        fprintf(stderr, "provider connection failed: %s\n", strerror(errno));
        return 1;
    }

    for (;;) {
        CNDLabKRWRequest request = {0};
        int result = transfer_all(
            STDIN_FILENO, &request, sizeof(request), 0);
        if (result == ECONNRESET) break;
        if (result != 0) {
            close(provider);
            return 2;
        }
        if (!request_is_read_only(&request)) {
            (void)send_error(EPERM);
            close(provider);
            return 3;
        }
        result = transfer_all(provider, &request, sizeof(request), 1);
        CNDLabKRWResponse response = {0};
        if (result == 0) {
            result = transfer_all(provider, &response, sizeof(response), 0);
        }
        if (result != 0 || response.magic != CND_LAB_KRW_MAGIC ||
            response.length > CND_LAB_KRW_MAX_TRANSFER ||
            (request.operation != CNDLabKRWOperationRead &&
             response.length != 0) ||
            (request.operation == CNDLabKRWOperationRead &&
             response.status == 0 && response.length != request.length)) {
            (void)send_error(EPROTO);
            close(provider);
            return 4;
        }
        result = transfer_all(
            STDOUT_FILENO, &response, sizeof(response), 1);
        if (result != 0) {
            close(provider);
            return 5;
        }
        if (response.length != 0) {
            unsigned char payload[CND_LAB_KRW_MAX_TRANSFER];
            result = transfer_all(provider, payload, response.length, 0);
            if (result == 0) {
                result = transfer_all(
                    STDOUT_FILENO, payload, response.length, 1);
            }
            if (result != 0) {
                close(provider);
                return 6;
            }
        }
    }
    close(provider);
    return 0;
}
