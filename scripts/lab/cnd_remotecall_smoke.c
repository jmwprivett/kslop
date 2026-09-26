#include "CNDLabRemoteCallClient.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int call_symbol(CNDLabRemoteCallClient *client, const char *symbol,
                       uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                       uint64_t *value)
{
    uint64_t arguments[8] = {a0, a1, a2, a3, 0, 0, 0, 0};
    int result = cnd_lab_remotecall_call_symbol(
        client, 5000, symbol, arguments, value);
    if (result != 0) {
        fprintf(stderr, "capability symbol=%s result=%d\n", symbol, result);
    }
    return result;
}

static int write_string(CNDLabRemoteCallClient *client, uint64_t address,
                        const char *value)
{
    return cnd_lab_remotecall_write(
        client, address, value, strlen(value) + 1);
}

static int verify_executable_and_objc_mutation(
    CNDLabRemoteCallClient *client)
{
    uint64_t page = 0;
    uint64_t mmap_arguments[8] = {
        0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
        UINT64_MAX, 0, 0, 0,
    };
    int result = cnd_lab_remotecall_call_symbol(
        client, 5000, "mmap", mmap_arguments, &page);
    if (result != 0 || page == 0 || page == UINT64_MAX) return 10;

    // mov x0, #41; ret; mov x0, #42; ret
    static const uint32_t code[] = {
        0xd2800520U, 0xd65f03c0U, 0xd2800540U, 0xd65f03c0U,
    };
    result = cnd_lab_remotecall_write(client, page, code, sizeof(code));
    uint64_t ignored = 0;
    if (result == 0) {
        result = call_symbol(
            client, "sys_icache_invalidate", page, sizeof(code), 0, 0,
            &ignored);
    }
    if (result == 0) {
        result = call_symbol(
            client, "mprotect", page, 0x4000,
            PROT_READ | PROT_EXEC, 0, &ignored);
    }
    uint64_t arguments[8] = {0};
    uint64_t value = 0;
    if (result == 0) {
        result = cnd_lab_remotecall_call_address(
            client, 5000, page + 8, arguments, &value);
    }
    if (result != 0 || value != 42) return 11;

    uint64_t scratch = client->scratchAddress;
    if (write_string(client, scratch + 0x100, "NSObject") != 0 ||
        write_string(client, scratch + 0x180, "description") != 0) {
        return 12;
    }

    uint64_t probe_class = 0, selector = 0;
    uint64_t method = 0, original = 0, replaced = 0, observed = 0;
    if (call_symbol(client, "objc_getClass", scratch + 0x100, 0, 0, 0,
                    &probe_class) != 0 || !probe_class ||
        call_symbol(client, "sel_registerName", scratch + 0x180, 0, 0, 0,
                    &selector) != 0 || !selector ||
        call_symbol(client, "class_getInstanceMethod", probe_class, selector,
                    0, 0, &method) != 0 || !method ||
        call_symbol(client, "method_getImplementation", method, 0, 0, 0,
                    &original) != 0 || !original ||
        // Setting the current IMP back to itself exercises the exact runtime
        // mutation primitive used by the consumer hook without changing any
        // target behavior.
        call_symbol(client, "method_setImplementation", method, original,
                    0, 0, &replaced) != 0 || !replaced ||
        call_symbol(client, "method_getImplementation", method, 0, 0, 0,
                    &observed) != 0 || !observed) {
        fprintf(stderr,
                "objc values class=%#llx selector=%#llx "
                "method=%#llx original=%#llx replaced=%#llx "
                "observed=%#llx\n",
                (unsigned long long)probe_class,
                (unsigned long long)selector,
                (unsigned long long)method,
                (unsigned long long)original,
                (unsigned long long)replaced,
                (unsigned long long)observed);
        return 13;
    }
    const uint64_t pointer_mask = 0x0000ffffffffffffULL;
    if ((replaced & pointer_mask) != (original & pointer_mask) ||
        (observed & pointer_mask) != (original & pointer_mask)) {
        return 14;
    }
    if (call_symbol(client, "munmap", page, 0x4000, 0, 0, &ignored) != 0) {
        return 15;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: cnd_remotecall_smoke PROCESS\n");
        return 2;
    }

    CNDLabRemoteCallClient client = { .socketFD = -1 };
    char error[128] = {0};
    int result = cnd_lab_remotecall_connect(
        argv[1], &client, error, sizeof(error));
    if (result != 0) {
        fprintf(stderr, "connect failed: %d (%s)\n", result,
                error[0] ? error : "unknown");
        return 3;
    }

    uint64_t arguments[8] = {0};
    uint64_t remotePID = 0;
    result = cnd_lab_remotecall_call_symbol(
        &client, 5000, "getpid", arguments, &remotePID);
    if (result != 0 || remotePID != (uint64_t)client.pid) {
        fprintf(stderr, "getpid failed: result=%d expected=%d observed=%llu\n",
                result, client.pid, remotePID);
        cnd_lab_remotecall_abandon(&client);
        return 4;
    }

    static const unsigned char expected[] =
        "Cyanide vPhone RemoteCall root-harness round trip";
    unsigned char observed[sizeof(expected)] = {0};
    result = cnd_lab_remotecall_write(
        &client, client.scratchAddress, expected, sizeof(expected));
    if (result != 0) {
        fprintf(stderr, "scratch write failed: %d address=0x%llx\n", result,
                (unsigned long long)client.scratchAddress);
    }
    if (result == 0) {
        result = cnd_lab_remotecall_read(
            &client, client.scratchAddress, observed, sizeof(observed));
        if (result != 0) {
            fprintf(stderr, "scratch read failed: %d address=0x%llx\n", result,
                    (unsigned long long)client.scratchAddress);
        }
    }
    if (result != 0 || memcmp(expected, observed, sizeof(expected)) != 0) {
        fprintf(stderr, "scratch round trip failed: %d\n", result);
        cnd_lab_remotecall_abandon(&client);
        return 5;
    }

    result = verify_executable_and_objc_mutation(&client);
    if (result != 0) {
        fprintf(stderr, "capability probe failed: stage=%d\n", result);
        cnd_lab_remotecall_abandon(&client);
        return 7;
    }

    uint64_t scratchAddress = client.scratchAddress;
    result = cnd_lab_remotecall_close(&client);
    if (result != 0) {
        fprintf(stderr, "close failed: %d\n", result);
        return 8;
    }
    printf("ok target=%s pid=%llu scratch=0x%llx bytes=%zu rx=yes objc=yes\n",
           argv[1], (unsigned long long)remotePID,
           (unsigned long long)scratchAddress, sizeof(expected));
    return 0;
}
