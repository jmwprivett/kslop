#include "CNDLabRemoteCallClient.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>

static int call(CNDLabRemoteCallClient *client, const char *symbol,
                const uint64_t arguments[8], uint64_t *value)
{
    return cnd_lab_remotecall_call_symbol(
        client, 10000, symbol, arguments, value);
}

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1][0] != '/') return 64;
    CNDLabRemoteCallClient client = {.socketFD = -1, .responseFD = -1};
    char error[128] = {0};
    int result = cnd_lab_remotecall_connect(
        "installd", &client, error, sizeof(error));
    if (result != 0) return 2;
    size_t pathLength = strlen(argv[1]) + 1;
    uint64_t arguments[8] = {pathLength, 0, 0, 0, 0, 0, 0, 0};
    uint64_t remotePath = 0;
    result = call(&client, "malloc", arguments, &remotePath);
    if (result == 0) result = cnd_lab_remotecall_write(
        &client, remotePath, argv[1], pathLength);
    uint64_t descriptor = UINT64_MAX;
    memset(arguments, 0, sizeof(arguments));
    arguments[0] = remotePath;
    arguments[1] = O_RDONLY | O_NOFOLLOW;
    if (result == 0) result = call(&client, "open", arguments, &descriptor);
    uint64_t remoteBytes = 0;
    memset(arguments, 0, sizeof(arguments));
    arguments[0] = 8;
    if (result == 0 && (int32_t)descriptor >= 0) {
        result = call(&client, "malloc", arguments, &remoteBytes);
    }
    uint64_t bytesRead = 0;
    memset(arguments, 0, sizeof(arguments));
    arguments[0] = descriptor;
    arguments[1] = remoteBytes;
    arguments[2] = 8;
    if (result == 0) result = call(&client, "read", arguments, &bytesRead);
    unsigned char bytes[8] = {0};
    if (result == 0 && bytesRead == 8) result = cnd_lab_remotecall_read(
        &client, remoteBytes, bytes, sizeof(bytes));
    memset(arguments, 0, sizeof(arguments));
    arguments[0] = descriptor;
    if ((int32_t)descriptor >= 0) (void)call(
        &client, "close", arguments, &descriptor);
    memset(arguments, 0, sizeof(arguments));
    arguments[0] = remoteBytes;
    if (remoteBytes) (void)call(&client, "free", arguments, &descriptor);
    arguments[0] = remotePath;
    if (remotePath) (void)call(&client, "free", arguments, &descriptor);
    int closeResult = cnd_lab_remotecall_close(&client);
    printf("result=%d read=%llu magic=%02x%02x%02x%02x close=%d\n",
           result, bytesRead, bytes[0], bytes[1], bytes[2], bytes[3],
           closeResult);
    return result == 0 && bytesRead == 8 && closeResult == 0 ? 0 : 1;
}
