#import "CNDLabRemoteCallClient.h"

#import <errno.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <limits.h>
#import <mach-o/dyld.h>
#import <stdio.h>
#import <string.h>
#import <sys/file.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/mman.h>
#import <sys/time.h>
#import <sys/un.h>
#import <unistd.h>

static int cnd_lab_transfer_all(int fd, void *buffer, size_t size, bool writing)
{
    uint8_t *cursor = buffer;
    while (size > 0) {
        ssize_t amount = writing
            ? write(fd, cursor, size) : read(fd, cursor, size);
        if (amount == 0) return ECONNRESET;
        if (amount < 0) {
            if (errno == EINTR) continue;
            return errno ? errno : EIO;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return 0;
}

static bool cnd_lab_process_name_valid(const char *process)
{
    if (!process || !process[0] ||
        strnlen(process, CND_LAB_REMOTECALL_PROCESS_LENGTH) >=
            CND_LAB_REMOTECALL_PROCESS_LENGTH) {
        return false;
    }
    for (const unsigned char *cursor = (const unsigned char *)process;
         *cursor; cursor++) {
        unsigned char c = *cursor;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

static bool cnd_lab_is_vphone(void)
{
    char model[64] = {0};
    size_t size = sizeof(model);
    return sysctlbyname("hw.model", model, &size, NULL, 0) == 0 &&
           strncmp(model, "VPHONE", 6) == 0;
}

static int cnd_lab_open_shared_file(const char *absolutePath,
                                    const char *bundleLeaf)
{
    int fd = open(absolutePath, O_RDONLY);
    if (fd >= 0) return fd;
    char executable[PATH_MAX] = {0};
    uint32_t executableSize = sizeof(executable);
    if (_NSGetExecutablePath(executable, &executableSize) != 0) return -1;
    char *slash = strrchr(executable, '/');
    if (!slash) return -1;
    *slash = '\0';
    char path[PATH_MAX] = {0};
    if (snprintf(path, sizeof(path), "%s/%s", executable, bundleLeaf) >=
        (int)sizeof(path)) return -1;
    return open(path, O_RDONLY);
}

static int cnd_lab_open_process_file(const char *process,
                                     const char *suffix,
                                     const char *fallbackAbsolutePath,
                                     const char *fallbackBundleLeaf)
{
    if (!cnd_lab_process_name_valid(process) || !suffix || !suffix[0]) {
        errno = EINVAL;
        return -1;
    }
    char bundleLeaf[NAME_MAX] = {0};
    if (snprintf(bundleLeaf, sizeof(bundleLeaf),
                 "CNDLabRemoteCall.%s.%s", process, suffix) >=
        (int)sizeof(bundleLeaf)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = cnd_lab_open_shared_file("/path/only/available/in/bundle",
                                      bundleLeaf);
    if (fd >= 0) return fd;
    return cnd_lab_open_shared_file(fallbackAbsolutePath,
                                    fallbackBundleLeaf);
}

bool cnd_lab_remotecall_opted_in(void)
{
    if (!cnd_lab_is_vphone()) return false;
    int fd = cnd_lab_open_shared_file(
        CND_LAB_REMOTECALL_MARKER_PATH,
        CND_LAB_REMOTECALL_BUNDLE_MARKER_LEAF);
    if (fd < 0) return false;
    close(fd);
    return true;
}

static int cnd_lab_read_token_for_process(
    const char *process,
    uint8_t token[CND_LAB_REMOTECALL_TOKEN_LENGTH])
{
    int fd = cnd_lab_open_process_file(
        process, "token",
        CND_LAB_REMOTECALL_TOKEN_PATH,
        CND_LAB_REMOTECALL_BUNDLE_TOKEN_LEAF);
    if (fd < 0) return errno ? errno : EACCES;
    uint8_t bytes[CND_LAB_REMOTECALL_TOKEN_LENGTH + 1] = {0};
    ssize_t amount = read(fd, bytes, sizeof(bytes));
    int saved = errno;
    close(fd);
    if (amount != CND_LAB_REMOTECALL_TOKEN_LENGTH) {
        return amount < 0 ? (saved ? saved : EIO) : EPROTO;
    }
    memcpy(token, bytes, CND_LAB_REMOTECALL_TOKEN_LENGTH);
    return 0;
}

static int cnd_lab_read_marker_value_for_process(
    const char *process,
    const char *key,
    char *output,
    size_t outputSize)
{
    if (!key || !key[0] || !output || outputSize == 0) return EINVAL;
    int fd = process
        ? cnd_lab_open_process_file(
            process, "marker",
            CND_LAB_REMOTECALL_MARKER_PATH,
            CND_LAB_REMOTECALL_BUNDLE_MARKER_LEAF)
        : cnd_lab_open_shared_file(
        CND_LAB_REMOTECALL_MARKER_PATH,
        CND_LAB_REMOTECALL_BUNDLE_MARKER_LEAF);
    if (fd < 0) return errno ? errno : EACCES;
    char marker[1024] = {0};
    ssize_t amount = read(fd, marker, sizeof(marker) - 1);
    int saved = errno;
    close(fd);
    if (amount <= 0) return amount < 0 ? (saved ? saved : EIO) : EPROTO;
    marker[amount] = '\0';
    char *start = strstr(marker, key);
    if (!start) return EPROTO;
    start += strlen(key);
    char *end = strchr(start, '\n');
    size_t length = end ? (size_t)(end - start) : strlen(start);
    if (length == 0 || length >= outputSize) {
        return ENAMETOOLONG;
    }
    memcpy(output, start, length);
    output[length] = '\0';
    return 0;
}

static int cnd_lab_read_marker_value(const char *key,
                                     char *output, size_t outputSize)
{
    return cnd_lab_read_marker_value_for_process(
        NULL, key, output, outputSize);
}

static int cnd_lab_read_icon_file_marker_value(
    const char *key,
    char *output,
    size_t outputSize)
{
    int result = cnd_lab_read_marker_value_for_process(
        "Spotlight", key, output, outputSize);
    return result == 0 ? 0 : cnd_lab_read_marker_value(
        key, output, outputSize);
}

bool cnd_lab_remotecall_consume_bundle_file_token(void)
{
    if (!cnd_lab_remotecall_opted_in()) return false;
    char token[1024] = {0};
    if (cnd_lab_read_icon_file_marker_value(
            "bundle_token=", token, sizeof(token)) != 0) return false;
    typedef int64_t (*ConsumeFunction)(const char *);
    ConsumeFunction consume = (ConsumeFunction)dlsym(
        RTLD_DEFAULT, "sandbox_extension_consume");
    return consume && consume(token) >= 0;
}

bool cnd_lab_remotecall_consume_root_file_token(void)
{
    if (!cnd_lab_remotecall_opted_in()) return false;
    char token[1024] = {0};
    if (cnd_lab_read_icon_file_marker_value(
            "root_token=", token, sizeof(token)) != 0) return false;
    typedef int64_t (*ConsumeFunction)(const char *);
    ConsumeFunction consume = (ConsumeFunction)dlsym(
        RTLD_DEFAULT, "sandbox_extension_consume");
    return consume && consume(token) >= 0;
}

bool cnd_lab_remotecall_copy_target_bundle_path(char *path, size_t pathSize)
{
    if (!path || pathSize == 0 || !cnd_lab_remotecall_opted_in()) return false;
    path[0] = '\0';
    return cnd_lab_read_icon_file_marker_value(
        "target_bundle_path=", path, pathSize) == 0;
}

static void cnd_lab_set_timeout(int fd, int timeoutMS)
{
    if (timeoutMS <= 0) timeoutMS = 10000;
    struct timeval timeout = {
        .tv_sec = timeoutMS / 1000,
        .tv_usec = (timeoutMS % 1000) * 1000,
    };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static int cnd_lab_exchange(CNDLabRemoteCallClient *client,
                            CNDLabRemoteCallRequest *request,
                            const void *outbound, void *inbound,
                            CNDLabRemoteCallResponse *response)
{
    if (!client || client->socketFD < 0 || !request || !response) {
        return EINVAL;
    }
    request->magic = CND_LAB_REMOTECALL_MAGIC;
    request->version = CND_LAB_REMOTECALL_VERSION;
    request->expectedPID = client->pid;
    memcpy(request->token, client->token, sizeof(request->token));

    if (client->mailbox) {
        CNDLabRemoteCallMailbox *mailbox = client->mailbox;
        uint64_t current = __atomic_load_n(
            &mailbox->requestSequence, __ATOMIC_ACQUIRE);
        uint64_t sequence = current + 1;
        if (outbound && request->length > 0) {
            memcpy(mailbox->payload, outbound, request->length);
        }
        mailbox->request = *request;
        __atomic_store_n(
            &mailbox->requestSequence, sequence, __ATOMIC_RELEASE);
        unsigned int remaining = request->timeoutMS
            ? request->timeoutMS : 10000;
        while (__atomic_load_n(
                   &mailbox->responseSequence, __ATOMIC_ACQUIRE) != sequence) {
            if (remaining == 0) return ETIMEDOUT;
            usleep(1000);
            remaining--;
        }
        *response = mailbox->response;
        if (response->magic != CND_LAB_REMOTECALL_MAGIC ||
            response->version != CND_LAB_REMOTECALL_VERSION ||
            response->operation != request->operation ||
            (client->pid > 1 && response->pid != client->pid) ||
            (client->pid <= 1 && response->pid <= 1)) return EPROTO;
        if (response->status != 0) return response->status;
        if (inbound && request->operation ==
                CNDLabRemoteCallOperationRead) {
            if (response->length != request->length) return EPROTO;
            memcpy(inbound, mailbox->payload, response->length);
        }
        return 0;
    }

    cnd_lab_set_timeout(client->socketFD, (int)request->timeoutMS);
    int responseFD = client->responseFD >= 0
        ? client->responseFD : client->socketFD;
    int result = cnd_lab_transfer_all(
        client->socketFD, request, sizeof(*request), true);
    if (result == 0 && outbound && request->length > 0) {
        result = cnd_lab_transfer_all(
            client->socketFD, (void *)outbound, request->length, true);
    }
    memset(response, 0, sizeof(*response));
    if (result == 0) {
        result = cnd_lab_transfer_all(
            responseFD, response, sizeof(*response), false);
    }
    if (result == 0 && (response->magic != CND_LAB_REMOTECALL_MAGIC ||
        response->version != CND_LAB_REMOTECALL_VERSION ||
        response->operation != request->operation ||
        (client->pid > 1 && response->pid != client->pid) ||
        (client->pid <= 1 && response->pid <= 1))) {
        result = EPROTO;
    }
    if (result == 0 && response->status != 0) result = response->status;
    if (result == 0 && inbound && request->operation ==
            CNDLabRemoteCallOperationRead) {
        if (response->length != request->length) return EPROTO;
        result = cnd_lab_transfer_all(
            responseFD, inbound, response->length, false);
    }
    return result;
}

int cnd_lab_remotecall_connect(const char *process,
                               CNDLabRemoteCallClient *client,
                               char *error, size_t errorSize)
{
    if (!client || !cnd_lab_process_name_valid(process)) return EINVAL;
    memset(client, 0, sizeof(*client));
    client->socketFD = -1;
    client->responseFD = -1;
    if (!cnd_lab_remotecall_opted_in()) return ENOENT;

    int result = cnd_lab_read_token_for_process(process, client->token);
    if (result != 0) goto fail;

    char path[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    int count = snprintf(path, sizeof(path), "%s%s%s",
                         CND_LAB_REMOTECALL_SOCKET_PREFIX, process,
                         CND_LAB_REMOTECALL_SOCKET_SUFFIX);
    if (count <= 0 || (size_t)count >= sizeof(path)) {
        result = ENAMETOOLONG;
        goto fail;
    }

    client->socketFD = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client->socketFD < 0) {
        result = errno ? errno : EIO;
        goto fail;
    }
    int one = 1;
    (void)setsockopt(
        client->socketFD, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    cnd_lab_set_timeout(client->socketFD, 5000);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strlcpy(address.sun_path, path, sizeof(address.sun_path));
    if (connect(client->socketFD, (const struct sockaddr *)&address,
                sizeof(address)) != 0) {
        result = errno ? errno : ECONNREFUSED;
        close(client->socketFD);
        client->socketFD = -1;

        // Some production sandboxes reject AF_UNIX bind even after receiving
        // file access to the endpoint directory. The harness records a
        // bounded mailbox path and a separate client file extension; the
        // per-run credential still authenticates every request.
        char bundleSocket[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
        char fileToken[1024] = {0};
        result = cnd_lab_read_marker_value_for_process(
            process,
            "file_token=", fileToken, sizeof(fileToken));
        if (result != 0) goto fail;
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        // The host-side gate smoke runs as root from inside Cyanide.app so it
        // resolves the exact per-target credentials, but it is not sandboxed
        // and must not consume Cyanide's one-shot client grant. The actual app
        // remains fail-closed and must successfully consume that grant.
        if (geteuid() != 0 && (!consume || consume(fileToken) < 0)) {
            result = EACCES;
            goto fail;
        }
        result = cnd_lab_read_marker_value_for_process(
            process,
            "socket=", bundleSocket, sizeof(bundleSocket));
        if (result != 0 || bundleSocket[0] != '/') {
            if (result == 0) result = EPROTO;
            goto fail;
        }
        char mailboxPath[PATH_MAX] = {0};
        if (snprintf(mailboxPath, sizeof(mailboxPath), "%s.mailbox",
                     bundleSocket) >= (int)sizeof(mailboxPath)) {
            result = ENAMETOOLONG;
            goto fail;
        }
        client->socketFD = open(mailboxPath, O_RDWR);
        if (client->socketFD < 0) {
            result = errno ? errno : ENOENT;
            goto fail;
        }
        // A mailbox has one request/response slot. Refuse overlapping app and
        // host-gate sessions instead of letting either client overwrite the
        // other's sequence or payload while a test is in progress.
        if (flock(client->socketFD, LOCK_EX | LOCK_NB) != 0) {
            result = errno == EWOULDBLOCK ? EBUSY : (errno ? errno : EIO);
            goto fail;
        }
        struct stat mailboxStat = {0};
        if (fstat(client->socketFD, &mailboxStat) != 0 ||
            !S_ISREG(mailboxStat.st_mode) ||
            mailboxStat.st_size != (off_t)sizeof(CNDLabRemoteCallMailbox)) {
            result = EPROTO;
            goto fail;
        }
        client->mailboxSize = sizeof(CNDLabRemoteCallMailbox);
        client->mailbox = mmap(NULL, client->mailboxSize,
            PROT_READ | PROT_WRITE, MAP_SHARED, client->socketFD, 0);
        if (client->mailbox == MAP_FAILED) {
            client->mailbox = NULL;
            result = errno ? errno : EIO;
            goto fail;
        }
    }

    CNDLabRemoteCallRequest request = {
        .magic = CND_LAB_REMOTECALL_MAGIC,
        .version = CND_LAB_REMOTECALL_VERSION,
        .operation = CNDLabRemoteCallOperationHandshake,
        .timeoutMS = 5000,
        .expectedPID = 0,
    };
    strlcpy(request.process, process, sizeof(request.process));
    CNDLabRemoteCallResponse response = {0};
    result = cnd_lab_exchange(
        client, &request, NULL, NULL, &response);
    if (result != 0 || response.magic != CND_LAB_REMOTECALL_MAGIC ||
        response.version != CND_LAB_REMOTECALL_VERSION ||
        response.operation != CNDLabRemoteCallOperationHandshake ||
        response.status != 0 || response.pid <= 1 ||
        strncmp(response.process, process, sizeof(response.process)) != 0 ||
        response.scratchAddress == 0) {
        result = result != 0 ? result :
            (response.status != 0 ? response.status : EPROTO);
        if (error && errorSize > 0) {
            snprintf(error, errorSize,
                "handshake result=%d magic=%#x version=%u operation=%u "
                "status=%d pid=%d process=%.63s scratch=%#llx",
                result, response.magic, response.version,
                response.operation, response.status, response.pid,
                response.process,
                (unsigned long long)response.scratchAddress);
        }
        goto fail;
    }
    client->pid = response.pid;
    client->scratchAddress = response.scratchAddress;
    strlcpy(client->process, process, sizeof(client->process));
    return 0;

fail:
    if (error && errorSize > 0 && error[0] == '\0') {
        snprintf(error, errorSize, "%s", strerror(result));
    }
    cnd_lab_remotecall_abandon(client);
    return result;
}

static int cnd_lab_call(CNDLabRemoteCallClient *client, int timeoutMS,
                        uint32_t operation, uint64_t address,
                        const char *symbol, const uint64_t arguments[8],
                        uint64_t *value)
{
    if (!client || !arguments || !value) return EINVAL;
    CNDLabRemoteCallRequest request = {
        .operation = operation,
        .flags = timeoutMS < 0 ? CNDLabRemoteCallFlagOneWay : 0,
        .timeoutMS = (uint32_t)(timeoutMS < 0 ? 10000 : timeoutMS),
        .address = address,
    };
    memcpy(request.arguments, arguments, sizeof(request.arguments));
    if (symbol) {
        if (strnlen(symbol, sizeof(request.symbol)) >= sizeof(request.symbol)) {
            return ENAMETOOLONG;
        }
        strlcpy(request.symbol, symbol, sizeof(request.symbol));
    }
    CNDLabRemoteCallResponse response = {0};
    int result = cnd_lab_exchange(
        client, &request, NULL, NULL, &response);
    if (result == 0) *value = response.value;
    return result;
}

int cnd_lab_remotecall_call_symbol(CNDLabRemoteCallClient *client,
                                   int timeoutMS, const char *symbol,
                                   const uint64_t arguments[8],
                                   uint64_t *value)
{
    return symbol ? cnd_lab_call(
        client, timeoutMS, CNDLabRemoteCallOperationCallSymbol, 0,
        symbol, arguments, value) : EINVAL;
}

int cnd_lab_remotecall_call_address(CNDLabRemoteCallClient *client,
                                    int timeoutMS, uint64_t address,
                                    const uint64_t arguments[8],
                                    uint64_t *value)
{
    return address ? cnd_lab_call(
        client, timeoutMS, CNDLabRemoteCallOperationCallAddress, address,
        NULL, arguments, value) : EINVAL;
}

int cnd_lab_remotecall_read(CNDLabRemoteCallClient *client, uint64_t address,
                            void *buffer, size_t size)
{
    if (!client || !address || !buffer || size == 0) return EINVAL;
    uint8_t *cursor = buffer;
    while (size > 0) {
        uint32_t amount = (uint32_t)(size > CND_LAB_REMOTECALL_MAX_TRANSFER
            ? CND_LAB_REMOTECALL_MAX_TRANSFER : size);
        CNDLabRemoteCallRequest request = {
            .operation = CNDLabRemoteCallOperationRead,
            .length = amount,
            .timeoutMS = 10000,
            .address = address,
        };
        CNDLabRemoteCallResponse response = {0};
        int result = cnd_lab_exchange(
            client, &request, NULL, cursor, &response);
        if (result != 0) return result;
        cursor += amount;
        address += amount;
        size -= amount;
    }
    return 0;
}

int cnd_lab_remotecall_write(CNDLabRemoteCallClient *client, uint64_t address,
                             const void *buffer, size_t size)
{
    if (!client || !address || !buffer || size == 0) return EINVAL;
    const uint8_t *cursor = buffer;
    while (size > 0) {
        uint32_t amount = (uint32_t)(size > CND_LAB_REMOTECALL_MAX_TRANSFER
            ? CND_LAB_REMOTECALL_MAX_TRANSFER : size);
        CNDLabRemoteCallRequest request = {
            .operation = CNDLabRemoteCallOperationWrite,
            .length = amount,
            .timeoutMS = 10000,
            .address = address,
        };
        CNDLabRemoteCallResponse response = {0};
        int result = cnd_lab_exchange(
            client, &request, cursor, NULL, &response);
        if (result != 0) return result;
        cursor += amount;
        address += amount;
        size -= amount;
    }
    return 0;
}

int cnd_lab_remotecall_close(CNDLabRemoteCallClient *client)
{
    if (!client || client->socketFD < 0) return 0;
    CNDLabRemoteCallRequest request = {
        .operation = CNDLabRemoteCallOperationClose,
        .timeoutMS = 2000,
    };
    CNDLabRemoteCallResponse response = {0};
    int result = cnd_lab_exchange(
        client, &request, NULL, NULL, &response);
    cnd_lab_remotecall_abandon(client);
    return result;
}

void cnd_lab_remotecall_abandon(CNDLabRemoteCallClient *client)
{
    if (!client) return;
    if (client->mailbox && client->mailboxSize > 0) {
        munmap(client->mailbox, client->mailboxSize);
    }
    if (client->socketFD >= 0) close(client->socketFD);
    if (client->responseFD >= 0 &&
        client->responseFD != client->socketFD) close(client->responseFD);
    memset(client, 0, sizeof(*client));
    client->socketFD = -1;
    client->responseFD = -1;
}

bool cnd_lab_remotecall_has_state(const CNDLabRemoteCallClient *client)
{
    return client && client->socketFD >= 0;
}
