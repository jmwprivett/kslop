#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;

typedef CFMutableDictionaryRef (*IOServiceMatchingFn)(const char *name);
typedef io_service_t (*IOServiceGetMatchingServiceFn)(
    mach_port_t main_port, CFDictionaryRef matching);
typedef kern_return_t (*IOServiceOpenFn)(
    io_service_t service, task_port_t owning_task, uint32_t type,
    io_connect_t *connection);
typedef kern_return_t (*IOServiceCloseFn)(io_connect_t connection);
typedef kern_return_t (*IOObjectReleaseFn)(io_object_t object);
typedef kern_return_t (*IOConnectCallMethodFn)(
    io_connect_t connection, uint32_t selector,
    const uint64_t *scalar_input, uint32_t scalar_input_count,
    const void *struct_input, size_t struct_input_size,
    uint64_t *scalar_output, uint32_t *scalar_output_count,
    void *struct_output, size_t *struct_output_size);
typedef kern_return_t (*IOConnectCallStructMethodFn)(
    io_connect_t connection, uint32_t selector,
    const void *input, size_t input_size,
    void *output, size_t *output_size);

enum {
    CND_AMFI_IS_CDHASH_IN_TRUST_CACHE = 6,
    CND_AMFI_LOAD_TRUST_CACHE = 2,
    CND_CDHASH_SIZE = 20,
    CND_INVALID_TRUST_CACHE_SIZE = 24,
};

#ifndef CND_AMFI_QUERY_RESULT_PATH
#define CND_AMFI_QUERY_RESULT_PATH \
    "/var/tmp/cnd_amfi_trustcache_query.result"
#endif

static const char *g_last_stage = "not-started";
static kern_return_t g_last_ioreturn = KERN_FAILURE;
static size_t g_last_output_size = 0;
static uint32_t g_last_selector = CND_AMFI_IS_CDHASH_IN_TRUST_CACHE;
static uint32_t g_last_scalar_input_count = 1;
static size_t g_last_input_size = CND_CDHASH_SIZE;

static void *require_symbol(void *image, const char *name)
{
    void *symbol = dlsym(image, name);
    if (symbol == NULL) {
        fprintf(stderr, "missing IOKit symbol: %s\n", name);
    }
    return symbol;
}

static int run_query(uint32_t connection_type)
{
    g_last_stage = "dlopen-iokit";
    void *iokit = dlopen(
        "/System/Library/Frameworks/IOKit.framework/IOKit",
        RTLD_NOW | RTLD_LOCAL);
    if (iokit == NULL) {
        fprintf(stderr, "unable to load IOKit: %s\n", dlerror());
        return 2;
    }

    g_last_stage = "resolve-symbols";
    IOServiceMatchingFn service_matching =
        (IOServiceMatchingFn)require_symbol(iokit, "IOServiceMatching");
    IOServiceGetMatchingServiceFn get_matching_service =
        (IOServiceGetMatchingServiceFn)require_symbol(
            iokit, "IOServiceGetMatchingService");
    IOServiceOpenFn service_open =
        (IOServiceOpenFn)require_symbol(iokit, "IOServiceOpen");
    IOServiceCloseFn service_close =
        (IOServiceCloseFn)require_symbol(iokit, "IOServiceClose");
    IOObjectReleaseFn object_release =
        (IOObjectReleaseFn)require_symbol(iokit, "IOObjectRelease");
#if defined(CND_AMFI_NEGATIVE_LOAD_PROBE)
    IOConnectCallStructMethodFn call_struct_method =
        (IOConnectCallStructMethodFn)require_symbol(
            iokit, "IOConnectCallStructMethod");
#else
    IOConnectCallMethodFn call_method =
        (IOConnectCallMethodFn)require_symbol(iokit, "IOConnectCallMethod");
#endif
    if (service_matching == NULL || get_matching_service == NULL ||
        service_open == NULL || service_close == NULL ||
        object_release == NULL ||
#if defined(CND_AMFI_NEGATIVE_LOAD_PROBE)
        call_struct_method == NULL) {
#else
        call_method == NULL) {
#endif
        dlclose(iokit);
        return 2;
    }

    CFMutableDictionaryRef matching =
        service_matching("AppleMobileFileIntegrity");
    g_last_stage = "service-matching";
    if (matching == NULL) {
        fprintf(stderr, "IOServiceMatching returned null\n");
        dlclose(iokit);
        return 3;
    }

    io_service_t service =
        get_matching_service(MACH_PORT_NULL, matching);
    g_last_stage = "matching-service";
    if (service == MACH_PORT_NULL) {
        fprintf(stderr, "AppleMobileFileIntegrity service was not found\n");
        dlclose(iokit);
        return 4;
    }

    io_connect_t connection = MACH_PORT_NULL;
    kern_return_t result =
        service_open(
            service, mach_task_self(), connection_type, &connection);
    g_last_stage = "service-open";
    g_last_ioreturn = result;
    (void)object_release(service);
    if (result != KERN_SUCCESS || connection == MACH_PORT_NULL) {
        fprintf(
            stderr, "connection_type=%u IOServiceOpen failed: 0x%08x\n",
            connection_type, result);
        dlclose(iokit);
        return 5;
    }

    size_t output_size = 0;
    g_last_stage = "external-method";
#if defined(CND_AMFI_NEGATIVE_LOAD_PROBE)
    uint8_t invalid_trust_cache[CND_INVALID_TRUST_CACHE_SIZE];
    memset(invalid_trust_cache, 0, sizeof(invalid_trust_cache));
    memset(invalid_trust_cache, 0xa5, 16);
    memset(invalid_trust_cache + 16, 0xff, sizeof(uint32_t));
    g_last_selector = CND_AMFI_LOAD_TRUST_CACHE;
    g_last_scalar_input_count = 0;
    g_last_input_size = sizeof(invalid_trust_cache);
    result = call_struct_method(
        connection, g_last_selector,
        invalid_trust_cache, sizeof(invalid_trust_cache), NULL, &output_size);
#else
    uint8_t cdhash[CND_CDHASH_SIZE];
    memset(cdhash, 0xa5, sizeof(cdhash));
    uint64_t query_options = 0;
    result = call_method(
        connection, g_last_selector,
        &query_options, 1, cdhash, sizeof(cdhash),
        NULL, NULL, NULL, &output_size);
#endif
    g_last_ioreturn = result;
    g_last_output_size = output_size;

    printf(
        "connection_type=%u selector=%u cdhash_size=%zu "
        "ioreturn=0x%08x output_size=%zu\n",
        connection_type, g_last_selector, g_last_input_size,
        result, output_size);

    (void)service_close(connection);
    dlclose(iokit);
    return result == KERN_SUCCESS ? 0 : 1;
}

#if defined(CND_AMFI_QUERY_DYLIB)
__attribute__((constructor))
static void cnd_amfi_trustcache_query_on_load(void)
{
    int status = run_query(0);
    FILE *result_file =
        fopen(CND_AMFI_QUERY_RESULT_PATH, "w");
    if (result_file != NULL) {
        fprintf(
            result_file,
            "status=%d\nstage=%s\nioreturn=0x%08x\nselector=%u\n"
            "scalar_input_count=%u\ninput_size=%zu\noutput_size=%zu\n",
            status, g_last_stage, g_last_ioreturn,
            g_last_selector, g_last_scalar_input_count, g_last_input_size,
            g_last_output_size);
        fclose(result_file);
    }
    fprintf(stderr, "cnd_amfi_trustcache_query status=%d\n", status);
}
#else
int main(int argc, char **argv)
{
    uint32_t connection_type = 0;
    if (argc == 2) {
        char *end = NULL;
        unsigned long parsed = strtoul(argv[1], &end, 0);
        if (end == argv[1] || *end != '\0' || parsed > UINT32_MAX) {
            fprintf(stderr, "invalid connection type: %s\n", argv[1]);
            return 2;
        }
        connection_type = (uint32_t)parsed;
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [connection-type]\n", argv[0]);
        return 2;
    }
    return run_query(connection_type);
}
#endif
