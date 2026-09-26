#include "CNDLabRemoteCallClient.h"

#include <errno.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xpc/xpc.h>

typedef struct {
    CNDLabRemoteCallClient client;
    uint64_t scratch;
    size_t scratchOffset;
} Probe;

static int call_symbol(Probe *probe, const char *symbol,
                       uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                       uint64_t *value)
{
    uint64_t arguments[8] = {a0, a1, a2, a3, 0, 0, 0, 0};
    int result = cnd_lab_remotecall_call_symbol(
        &probe->client, 5000, symbol, arguments, value);
    if (result != 0) {
        fprintf(stderr, "call %s failed: %d (%s)\n", symbol, result,
                strerror(result));
    }
    return result;
}

static uint64_t remote_copy(Probe *probe, const void *bytes, size_t size)
{
    size_t aligned = (size + 15U) & ~15U;
    if (aligned == 0 || probe->scratchOffset + aligned > 0x80000U) return 0;
    uint64_t address = probe->scratch + probe->scratchOffset;
    if (cnd_lab_remotecall_write(
            &probe->client, address, bytes, size) != 0) return 0;
    probe->scratchOffset += aligned;
    return address;
}

static uint64_t remote_cstring(Probe *probe, const char *string)
{
    return string ? remote_copy(probe, string, strlen(string) + 1U) : 0;
}

static bool remote_read(Probe *probe, uint64_t address,
                        void *buffer, size_t size)
{
    return address && buffer && size &&
        cnd_lab_remotecall_read(
            &probe->client, address, buffer, size) == 0;
}

static bool remote_read_cstring(Probe *probe, uint64_t address,
                                char *buffer, size_t size)
{
    if (!address || !buffer || size < 2U) return false;
    memset(buffer, 0, size);
    for (size_t i = 0; i + 1U < size; i++) {
        if (!remote_read(probe, address + i, &buffer[i], 1U)) return false;
        if (buffer[i] == '\0') return true;
    }
    buffer[size - 1U] = '\0';
    return false;
}

static uint64_t symbol_call1(Probe *probe, const char *symbol, uint64_t a0)
{
    uint64_t value = 0;
    return call_symbol(probe, symbol, a0, 0, 0, 0, &value) == 0 ? value : 0;
}

static uint64_t symbol_call2(Probe *probe, const char *symbol,
                             uint64_t a0, uint64_t a1)
{
    uint64_t value = 0;
    return call_symbol(probe, symbol, a0, a1, 0, 0, &value) == 0 ? value : 0;
}

static uint64_t objc_class(Probe *probe, const char *name)
{
    return symbol_call1(probe, "objc_getClass", remote_cstring(probe, name));
}

static uint64_t objc_selector(Probe *probe, const char *name)
{
    return symbol_call1(
        probe, "sel_registerName", remote_cstring(probe, name));
}

static uint64_t objc_send0(Probe *probe, uint64_t object, const char *name)
{
    uint64_t selector = objc_selector(probe, name);
    return selector ? symbol_call2(probe, "objc_msgSend", object, selector) : 0;
}

static uint64_t objc_send1(Probe *probe, uint64_t object, const char *name,
                           uint64_t argument)
{
    uint64_t selector = objc_selector(probe, name);
    uint64_t value = 0;
    return selector && call_symbol(
        probe, "objc_msgSend", object, selector, argument, 0, &value) == 0
        ? value : 0;
}

static uint64_t remote_nsstring(Probe *probe, const char *string)
{
    uint64_t cls = objc_class(probe, "NSString");
    uint64_t bytes = remote_cstring(probe, string);
    return cls && bytes
        ? objc_send1(probe, cls, "stringWithUTF8String:", bytes) : 0;
}

static void class_name(Probe *probe, uint64_t cls,
                       char *buffer, size_t size)
{
    uint64_t name = symbol_call1(probe, "class_getName", cls);
    if (!remote_read_cstring(probe, name, buffer, size)) {
        snprintf(buffer, size, "?");
    }
}

static void object_class_name(Probe *probe, uint64_t object,
                              char *buffer, size_t size)
{
    uint64_t cls = symbol_call1(probe, "object_getClass", object);
    class_name(probe, cls, buffer, size);
}

static void dump_methods(Probe *probe, uint64_t cls, const char *owner)
{
    uint32_t zero = 0;
    uint64_t countAddress = remote_copy(probe, &zero, sizeof(zero));
    uint64_t list = symbol_call2(
        probe, "class_copyMethodList", cls, countAddress);
    uint32_t count = 0;
    if (!list || !remote_read(probe, countAddress, &count, sizeof(count)) ||
        count > 1024U) return;
    uint32_t cap = count < 128U ? count : 128U;
    for (uint32_t i = 0; i < cap; i++) {
        uint64_t method = 0;
        if (!remote_read(probe, list + (uint64_t)i * 8U,
                         &method, sizeof(method))) break;
        uint64_t selector = symbol_call1(probe, "method_getName", method);
        uint64_t nameAddress = symbol_call1(probe, "sel_getName", selector);
        uint64_t typesAddress = symbol_call1(
            probe, "method_getTypeEncoding", method);
        char name[192] = {0};
        char types[192] = {0};
        remote_read_cstring(probe, nameAddress, name, sizeof(name));
        remote_read_cstring(probe, typesAddress, types, sizeof(types));
        printf("METHOD owner=%s name=%s types=%s\n", owner, name, types);
    }
    (void)symbol_call1(probe, "free", list);
}

static void dump_ivars(Probe *probe, uint64_t object, uint64_t cls,
                       const char *owner, const char *phase)
{
    uint32_t zero = 0;
    uint64_t countAddress = remote_copy(probe, &zero, sizeof(zero));
    uint64_t list = symbol_call2(
        probe, "class_copyIvarList", cls, countAddress);
    uint32_t count = 0;
    if (!list || !remote_read(probe, countAddress, &count, sizeof(count)) ||
        count > 1024U) return;
    uint32_t cap = count < 128U ? count : 128U;
    for (uint32_t i = 0; i < cap; i++) {
        uint64_t ivar = 0;
        if (!remote_read(probe, list + (uint64_t)i * 8U,
                         &ivar, sizeof(ivar))) break;
        uint64_t nameAddress = symbol_call1(probe, "ivar_getName", ivar);
        uint64_t typesAddress = symbol_call1(
            probe, "ivar_getTypeEncoding", ivar);
        uint64_t offset = symbol_call1(probe, "ivar_getOffset", ivar);
        char name[192] = {0};
        char types[192] = {0};
        remote_read_cstring(probe, nameAddress, name, sizeof(name));
        remote_read_cstring(probe, typesAddress, types, sizeof(types));
        uint64_t raw = 0;
        (void)remote_read(probe, object + offset, &raw, sizeof(raw));
        char valueClass[192] = "-";
        if (types[0] == '@' && raw) {
            object_class_name(probe, raw, valueClass, sizeof(valueClass));
        }
        printf("IVAR phase=%s owner=%s name=%s types=%s offset=%" PRIu64
               " raw=0x%" PRIx64 " class=%s\n",
               phase, owner, name, types, offset, raw, valueClass);
    }
    (void)symbol_call1(probe, "free", list);
}

static void dump_object(Probe *probe, uint64_t object, const char *phase)
{
    uint64_t cls = symbol_call1(probe, "object_getClass", object);
    for (unsigned depth = 0; cls && depth < 8U; depth++) {
        char owner[192] = {0};
        class_name(probe, cls, owner, sizeof(owner));
        printf("CLASS phase=%s depth=%u name=%s object=0x%" PRIx64 "\n",
               phase, depth, owner, object);
        dump_methods(probe, cls, owner);
        dump_ivars(probe, object, cls, owner, phase);
        cls = symbol_call1(probe, "class_getSuperclass", cls);
    }
}

static int wake_iconservices(void)
{
    typedef xpc_connection_t (*CreateMachService)(
        const char *, dispatch_queue_t, uint64_t);
    CreateMachService create = (CreateMachService)dlsym(
        RTLD_DEFAULT, "xpc_connection_create_mach_service");
    if (!create) return 1;
    xpc_connection_t connection = create(
        "com.apple.iconservices", NULL, 0);
    if (!connection) return 1;
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        (void)event;
    });
    xpc_connection_resume(connection);
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_connection_send_message(connection, message);
    xpc_release(message);
    sleep(2);
    xpc_connection_cancel(connection);
    xpc_release(connection);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--wake") == 0) {
        return wake_iconservices();
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--wake]\n", argv[0]);
        return 1;
    }
    Probe probe = {.client = {.socketFD = -1}};
    char error[256] = {0};
    int result = cnd_lab_remotecall_connect(
        "iconservicesagent", &probe.client, error, sizeof(error));
    if (result != 0) {
        fprintf(stderr, "connect failed: %d (%s) detail=%s\n", result,
                strerror(result), error);
        return 2;
    }
    probe.scratch = probe.client.scratchAddress;
    probe.scratchOffset = 0x1000U;

    uint64_t iconClass = objc_class(&probe, "ISBundleIdentifierIcon");
    uint64_t identifier = remote_nsstring(&probe, "com.ebay.iphone");
    uint64_t icon = objc_send0(&probe, iconClass, "alloc");
    icon = objc_send1(&probe, icon, "initWithBundleIdentifier:", identifier);
    uint64_t provider = objc_send1(
        &probe, icon, "_makeResourceProviderAllowIconResourceFallback:", 1);
    if (!provider) {
        fprintf(stderr, "stock provider construction failed\n");
        cnd_lab_remotecall_abandon(&probe.client);
        return 3;
    }
    provider = objc_send0(&probe, provider, "retain");
    char providerClass[192] = {0};
    object_class_name(&probe, provider, providerClass, sizeof(providerClass));
    printf("PROVIDER object=0x%" PRIx64 " class=%s\n",
           provider, providerClass);
    dump_object(&probe, provider, "before-resolve");
    (void)objc_send0(&probe, provider, "resolveResources");
    dump_object(&probe, provider, "after-resolve");

    (void)objc_send0(&probe, provider, "release");
    (void)objc_send0(&probe, icon, "release");
    result = cnd_lab_remotecall_close(&probe.client);
    if (result != 0) {
        fprintf(stderr, "close failed: %d (%s)\n", result, strerror(result));
        return 4;
    }
    return 0;
}
