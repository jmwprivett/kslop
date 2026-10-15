#include "CNDLabKernelProtocol.h"

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * Read-only exact-build helper for the iOS 26.0 / 23A341 vPhone lab.  It
 * resolves ordinary IOService send rights through the calling process' IPC
 * table, strips (but never creates) the kernel-owned PAC values, and reports
 * the live vtable entries used by the PM translator.  It deliberately does
 * not issue the provider's KernelCall or Write operations.
 */

typedef mach_port_t io_object_t;
typedef io_object_t io_iterator_t;
typedef io_object_t io_service_t;
typedef char io_name_t[128];

typedef CFMutableDictionaryRef (*IOServiceMatchingFn)(const char *name);
typedef kern_return_t (*IOServiceGetMatchingServicesFn)(
    mach_port_t main_port, CFDictionaryRef matching, io_iterator_t *iterator);
typedef io_object_t (*IOIteratorNextFn)(io_iterator_t iterator);
typedef kern_return_t (*IOObjectReleaseFn)(io_object_t object);
typedef kern_return_t (*IORegistryEntryGetNameFn)(
    io_object_t entry, io_name_t name);

static const uint64_t kStaticAllProc = UINT64_C(0xfffffe0009813020);
static const uint64_t kStaticRootDomainGlobal =
    UINT64_C(0xfffffe0009816ce0);
static const uint64_t kStaticKernelBase = UINT64_C(0xfffffe0007004000);
static const uint64_t kProcNextOffset = 0x0;
static const uint64_t kProcROOffset = 0x18;
static const uint64_t kProcPIDOffset = 0x60;
static const uint64_t kProcROTaskOffset = 0x8;
static const uint64_t kTaskIPCSpaceOffset = 0x310;
static const uint64_t kIPCSpaceTableOffset = 0x48;
static const uint64_t kIPCEntrySize = 0x18;
static const uint64_t kZoneMin = UINT64_C(0xfffffe1000000000);
static const uint64_t kZoneMax = UINT64_C(0xfffffe3fffffffff);
enum {
    kMaxProcWalk = 1024,
    kMaxServices = 2048,
    kMethodCount = 9,
    kMaxGraphNodes = 8192,
    kGraphMethodCount = 8,
    /*
     * IOService's exact-build base allocation covers the first 0xa0 bytes.
     * Do not blindly scan discovered child allocations: GZAlloc correctly
     * traps an in-kernel provider read that crosses a child's zone boundary.
     * Deeper inspection belongs in debugger-side KDP reads.
     */
    kGraphMaximumDepth = 1,
    kGraphRootScanBytes = 0xa0,
    kGraphChildScanBytes = 0,
};

typedef struct {
    char name[sizeof(io_name_t)];
    uint64_t object;
    uint64_t raw_vtable;
    uint64_t vtable;
    uint64_t methods[kMethodCount];
    uint32_t instances;
} PMProfile;

typedef struct {
    char root_name[sizeof(io_name_t)];
    uint64_t object;
    uint64_t parent;
    uint64_t parent_offset;
    uint64_t raw_vtable;
    uint64_t vtable;
    uint64_t methods[kGraphMethodCount];
    uint32_t depth;
} GraphNode;

static void json_string(const char *text);

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

static int provider_request(int fd, uint32_t operation, uint64_t address,
                            void *buffer, size_t length, uint64_t *value)
{
    if (operation != CNDLabKRWOperationRead &&
        operation != CNDLabKRWOperationKBase &&
        operation != CNDLabKRWOperationCapabilities) {
        return EPERM;
    }
    CNDLabKRWRequest request = {
        .magic = CND_LAB_KRW_MAGIC,
        .version = CND_LAB_KRW_VERSION,
        .operation = operation,
        .length = (uint32_t)length,
        .address = address,
    };
    int result = transfer_all(fd, &request, sizeof(request), 1);
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
        int result = provider_request(fd, CNDLabKRWOperationRead, address,
                                      cursor, amount, NULL);
        if (result != 0) return result;
        address += amount;
        cursor += amount;
        length -= amount;
    }
    return 0;
}

static int read_u32(int fd, uint64_t address, uint32_t *value)
{
    return kernel_read(fd, address, value, sizeof(*value));
}

static int read_u64(int fd, uint64_t address, uint64_t *value)
{
    return kernel_read(fd, address, value, sizeof(*value));
}

#if defined(__arm64__)
__attribute__((naked))
static uint64_t strip_instruction_pac(uint64_t value)
{
    __asm__ volatile(".long 0xdac143e0"); /* xpaci x0 */
    __asm__ volatile("ret");
}

__attribute__((naked))
static uint64_t strip_data_pac(uint64_t value)
{
    __asm__ volatile(".long 0xdac147e0"); /* xpacd x0 */
    __asm__ volatile("ret");
}
#else
static uint64_t canonical_pointer(uint64_t value)
{
    value &= UINT64_C(0x0000ffffffffffff);
    if ((value & UINT64_C(0x0000800000000000)) != 0) {
        value |= UINT64_C(0xffff000000000000);
    }
    return value;
}
static uint64_t strip_instruction_pac(uint64_t value)
{
    return canonical_pointer(value);
}
static uint64_t strip_data_pac(uint64_t value)
{
    return canonical_pointer(value);
}
#endif

static int zone_pointer(uint64_t value)
{
    return value >= kZoneMin && value <= kZoneMax && (value & 7) == 0;
}

static int kernel_pointer(uint64_t value)
{
    return (value & UINT64_C(0xffff000000000000)) ==
        UINT64_C(0xffff000000000000) && (value & 3) == 0;
}

static int kernel_image_pointer(uint64_t value, uint64_t kernel_base)
{
    return kernel_pointer(value) && value >= kernel_base &&
        value - kernel_base < UINT64_C(0x40000000);
}

static uint64_t find_self_proc(int fd, uint64_t slide)
{
    uint64_t raw = 0;
    if (read_u64(fd, kStaticAllProc + slide, &raw) != 0) return 0;
    uint64_t proc = strip_data_pac(raw);
    pid_t pid = getpid();
    for (uint32_t index = 0; index < kMaxProcWalk; index++) {
        if (!zone_pointer(proc)) return 0;
        uint32_t candidate = 0;
        if (read_u32(fd, proc + kProcPIDOffset, &candidate) != 0) return 0;
        if (candidate == (uint32_t)pid) return proc;
        if (read_u64(fd, proc + kProcNextOffset, &raw) != 0) return 0;
        uint64_t next = strip_data_pac(raw);
        if (next == 0 || next == proc) return 0;
        proc = next;
    }
    return 0;
}

static uint64_t read_data_pointer(int fd, uint64_t address)
{
    uint64_t raw = 0;
    if (read_u64(fd, address, &raw) != 0) return 0;
    return strip_data_pac(raw);
}

static int inspect_graph_object(int fd, uint64_t object,
                                uint64_t kernel_base,
                                uint64_t *raw_vtable_out,
                                uint64_t *vtable_out,
                                uint64_t methods[kGraphMethodCount])
{
    static const uint64_t offsets[kGraphMethodCount] = {
        0x0, 0xe8, 0xf0, 0x100, 0x108, 0x110, 0x128, 0x540,
    };
    uint64_t raw_vtable = 0;
    if (!zone_pointer(object) ||
        read_u64(fd, object, &raw_vtable) != 0) {
        return 0;
    }
    uint64_t vtable = strip_data_pac(raw_vtable);
    if (!kernel_image_pointer(vtable, kernel_base)) return 0;
    uint64_t table[(0x540 + sizeof(uint64_t)) / sizeof(uint64_t)] = {0};
    if (kernel_read(fd, vtable, table, sizeof(table)) != 0) return 0;
    for (size_t index = 0; index < kGraphMethodCount; index++) {
        methods[index] = 0;
        uint64_t raw_method = table[offsets[index] / sizeof(uint64_t)];
        uint64_t method = strip_instruction_pac(raw_method);
        if (kernel_image_pointer(method, kernel_base)) {
            methods[index] = method;
        }
    }
    if (methods[0] == 0) return 0;
    if (raw_vtable_out != NULL) *raw_vtable_out = raw_vtable;
    if (vtable_out != NULL) *vtable_out = vtable;
    return 1;
}

static int graph_find_node(const GraphNode *nodes, uint32_t count,
                           uint64_t object)
{
    for (uint32_t index = 0; index < count; index++) {
        if (nodes[index].object == object) return (int)index;
    }
    return -1;
}

static int graph_add_node(int fd, GraphNode *nodes, uint32_t *count,
                          uint64_t kernel_base, const char *root_name,
                          uint64_t object, uint64_t parent,
                          uint64_t parent_offset, uint32_t depth)
{
    if (graph_find_node(nodes, *count, object) >= 0) return 0;
    if (*count >= kMaxGraphNodes) return -1;
    GraphNode candidate = {
        .object = object,
        .parent = parent,
        .parent_offset = parent_offset,
        .depth = depth,
    };
    snprintf(candidate.root_name, sizeof(candidate.root_name), "%s",
             root_name != NULL ? root_name : "unknown");
    if (!inspect_graph_object(fd, object, kernel_base,
            &candidate.raw_vtable, &candidate.vtable,
            candidate.methods)) {
        return 0;
    }
    nodes[*count] = candidate;
    (*count)++;
    return 1;
}

static uint32_t emit_object_graph(int fd, const GraphNode *roots,
                                  uint32_t root_count,
                                  uint64_t kernel_base)
{
    static const uint64_t method_offsets[kGraphMethodCount] = {
        0x0, 0xe8, 0xf0, 0x100, 0x108, 0x110, 0x128, 0x540,
    };
    GraphNode *nodes = calloc(kMaxGraphNodes, sizeof(*nodes));
    if (nodes == NULL) return 0;
    uint32_t node_count = 0;
    for (uint32_t index = 0; index < root_count; index++) {
        (void)graph_add_node(fd, nodes, &node_count, kernel_base,
                            roots[index].root_name, roots[index].object,
                            0, 0, 0);
    }

    for (uint32_t index = 0; index < node_count; index++) {
        GraphNode *node = &nodes[index];
        if (node->depth >= kGraphMaximumDepth) continue;
        uint64_t scan_bytes = node->depth == 0
            ? kGraphRootScanBytes : kGraphChildScanBytes;
        uint64_t words[kGraphRootScanBytes / sizeof(uint64_t)] = {0};
        int block_read = kernel_read(
            fd, node->object, words, (size_t)scan_bytes) == 0;
        for (uint64_t offset = 8; offset < scan_bytes; offset += 8) {
            uint64_t raw_child = words[offset / sizeof(uint64_t)];
            if (!block_read &&
                read_u64(fd, node->object + offset, &raw_child) != 0) {
                    continue;
            }
            uint64_t child = strip_data_pac(raw_child);
            if (!zone_pointer(child) || child == node->object) continue;
            (void)graph_add_node(fd, nodes, &node_count, kernel_base,
                                node->root_name, child, node->object,
                                offset, node->depth + 1);
        }
    }

    for (uint32_t index = 0; index < node_count; index++) {
        const GraphNode *node = &nodes[index];
        printf("{\"kind\":\"graph-node\",\"index\":%u,"
               "\"depth\":%u,\"rootName\":", index, node->depth);
        json_string(node->root_name);
        printf(",\"object\":\"%#llx\",\"parent\":\"%#llx\","
               "\"parentOffset\":\"%#llx\","
               "\"rawVtable\":\"%#llx\",\"vtable\":\"%#llx\"",
               node->object, node->parent, node->parent_offset,
               node->raw_vtable, node->vtable);
        for (size_t method = 0; method < kGraphMethodCount; method++) {
            printf(",\"slot%03llx\":\"%#llx\"",
                   method_offsets[method], node->methods[method]);
        }
        printf("}\n");
    }
    free(nodes);
    return node_count;
}

static uint64_t self_task(int fd, uint64_t proc)
{
    uint64_t proc_ro = read_data_pointer(fd, proc + kProcROOffset);
    if (!zone_pointer(proc_ro)) return 0;
    uint64_t task = read_data_pointer(fd, proc_ro + kProcROTaskOffset);
    return zone_pointer(task) ? task : 0;
}

static uint64_t task_ipc_table(int fd, uint64_t task)
{
    uint64_t space = read_data_pointer(fd, task + kTaskIPCSpaceOffset);
    if (!zone_pointer(space)) return 0;
    uint64_t table = read_data_pointer(fd, space + kIPCSpaceTableOffset);
    table &= ~UINT64_C(0x1f);
    return zone_pointer(table) ? table : 0;
}

static uint64_t port_object(int fd, uint64_t table, mach_port_name_t name)
{
    if (!zone_pointer(table)) return 0;
    uint64_t entry = table + ((uint64_t)name >> 8) * kIPCEntrySize;
    if (!zone_pointer(entry)) return 0;
    uint64_t object = read_data_pointer(fd, entry);
    return zone_pointer(object) ? object : 0;
}

static int read_method_targets(int fd, uint64_t vtable,
                               const uint64_t *offsets, size_t count,
                               uint64_t kernel_base, uint64_t *methods)
{
    if (count == 0) return EINVAL;
    for (size_t index = 0; index < count; index++) {
        uint64_t raw_target = 0;
        if ((offsets[index] & 7) != 0 ||
            read_u64(fd, vtable + offsets[index], &raw_target) != 0) {
            return EIO;
        }
        methods[index] = strip_instruction_pac(raw_target);
        if (!kernel_image_pointer(methods[index], kernel_base)) return ENOEXEC;
    }
    return 0;
}

static int connect_provider(const char *path)
{
    if (strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void json_string(const char *text)
{
    putchar('"');
    for (const unsigned char *cursor = (const unsigned char *)text;
         *cursor != 0; cursor++) {
        unsigned char byte = *cursor;
        if (byte == '"' || byte == '\\') {
            putchar('\\');
            putchar(byte);
        } else if (byte >= 0x20 && byte < 0x7f) {
            putchar(byte);
        } else {
            printf("\\u%04x", byte);
        }
    }
    putchar('"');
}

int main(int argc, char **argv)
{
    int unique_profiles = argc == 3 && strcmp(argv[2], "--unique") == 0;
    int graph_mode = argc == 3 && strcmp(argv[2], "--graph") == 0;
    int slot_mode = argc == 4 && strcmp(argv[2], "--slot") == 0;
    int find_target_mode = argc == 4 &&
        strcmp(argv[2], "--find-target") == 0;
    uint64_t requested_slot = 0;
    uint64_t requested_static_target = 0;
    if (slot_mode) {
        char *end = NULL;
        errno = 0;
        requested_slot = strtoull(argv[3], &end, 0);
        if (errno != 0 || end == argv[3] || *end != '\0' ||
            requested_slot > 0x4000 || (requested_slot & 7) != 0) {
            fprintf(stderr, "slot offset must be an aligned value <= 0x4000\n");
            return 64;
        }
    }
    if (find_target_mode) {
        char *end = NULL;
        errno = 0;
        requested_static_target = strtoull(argv[3], &end, 0);
        if (errno != 0 || end == argv[3] || *end != '\0' ||
            !kernel_pointer(requested_static_target) ||
            requested_static_target < kStaticKernelBase ||
            requested_static_target - kStaticKernelBase >=
                UINT64_C(0x40000000)) {
            fprintf(stderr, "target must be a static kernel image address\n");
            return 64;
        }
    }
    if (argc < 2 || argc > 4 ||
        (argc == 3 && !unique_profiles && !graph_mode) ||
        (argc == 4 && !slot_mode && !find_target_mode)) {
        fprintf(stderr,
                "usage: %s PROVIDER_SOCKET "
                "[--unique | --graph | --slot OFFSET | "
                "--find-target STATIC_ADDRESS]\n",
                argv[0]);
        return 64;
    }
    int fd = connect_provider(argv[1]);
    if (fd < 0) {
        fprintf(stderr, "provider connect failed: %s\n", strerror(errno));
        return 1;
    }
    uint64_t capabilities = 0;
    uint64_t kernel_base = 0;
    int result = provider_request(fd, CNDLabKRWOperationCapabilities, 0,
                                  NULL, 0, &capabilities);
    if (result == 0) {
        result = provider_request(fd, CNDLabKRWOperationKBase, 0,
                                  NULL, 0, &kernel_base);
    }
    if (result != 0 ||
        (capabilities & CNDLabKRWCapabilityKernelReadWrite) == 0 ||
        kernel_base < kStaticKernelBase) {
        fprintf(stderr, "provider identity failed: %d\n", result);
        close(fd);
        return 1;
    }
    uint64_t slide = kernel_base - kStaticKernelBase;
    uint64_t proc = find_self_proc(fd, slide);
    uint64_t task = proc != 0 ? self_task(fd, proc) : 0;
    uint64_t ipc_table = task != 0 ? task_ipc_table(fd, task) : 0;
    if (task == 0 || ipc_table == 0) {
        fprintf(stderr,
                "self IPC recovery failed base=%#llx slide=%#llx "
                "task=%#llx table=%#llx\n",
                kernel_base, slide, task, ipc_table);
        close(fd);
        return 1;
    }

    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                         RTLD_NOW | RTLD_LOCAL);
    IOServiceMatchingFn service_matching = iokit != NULL
        ? (IOServiceMatchingFn)dlsym(iokit, "IOServiceMatching") : NULL;
    IOServiceGetMatchingServicesFn get_matching_services = iokit != NULL
        ? (IOServiceGetMatchingServicesFn)dlsym(
            iokit, "IOServiceGetMatchingServices") : NULL;
    IOIteratorNextFn iterator_next = iokit != NULL
        ? (IOIteratorNextFn)dlsym(iokit, "IOIteratorNext") : NULL;
    IOObjectReleaseFn object_release = iokit != NULL
        ? (IOObjectReleaseFn)dlsym(iokit, "IOObjectRelease") : NULL;
    IORegistryEntryGetNameFn entry_get_name = iokit != NULL
        ? (IORegistryEntryGetNameFn)dlsym(
            iokit, "IORegistryEntryGetName") : NULL;
    if (service_matching == NULL || get_matching_services == NULL ||
        iterator_next == NULL || object_release == NULL ||
        entry_get_name == NULL) {
        fprintf(stderr, "IOKit API resolution failed\n");
        close(fd);
        if (iokit != NULL) dlclose(iokit);
        return 1;
    }

    CFMutableDictionaryRef root_match = service_matching("IOPMrootDomain");
    io_iterator_t root_iterator = MACH_PORT_NULL;
    result = root_match != NULL
        ? get_matching_services(MACH_PORT_NULL, root_match, &root_iterator)
        : KERN_FAILURE;
    io_service_t root_service = result == KERN_SUCCESS
        ? iterator_next(root_iterator) : MACH_PORT_NULL;
    if (MACH_PORT_VALID(root_iterator)) object_release(root_iterator);
    uint64_t root_port = MACH_PORT_VALID(root_service)
        ? port_object(fd, ipc_table, root_service) : 0;
    uint64_t root = read_data_pointer(
        fd, kStaticRootDomainGlobal + slide);
    uint64_t kobject_offset = UINT64_MAX;
    uint64_t kobject_inner_offset = UINT64_MAX;
    if (zone_pointer(root_port) && zone_pointer(root)) {
        for (uint64_t offset = 0; offset < 0x100; offset += 8) {
            uint64_t candidate = read_data_pointer(fd, root_port + offset);
            if (candidate == root) {
                kobject_offset = offset;
                kobject_inner_offset = 0;
                break;
            }
            if (!zone_pointer(candidate)) continue;
            for (uint64_t inner = 0; inner < 0x80; inner += 8) {
                uint64_t nested = read_data_pointer(fd, candidate + inner);
                if (nested == root) {
                    kobject_offset = offset;
                    kobject_inner_offset = inner;
                    break;
                }
            }
            if (kobject_offset != UINT64_MAX) break;
        }
    }
    if (MACH_PORT_VALID(root_service)) object_release(root_service);
    if (kobject_offset == UINT64_MAX) {
        fprintf(stderr,
                "IOService port label offset unresolved root=%#llx port=%#llx\n",
                root, root_port);
        close(fd);
        dlclose(iokit);
        return 1;
    }

    CFMutableDictionaryRef matching = service_matching("IOService");
    io_iterator_t iterator = MACH_PORT_NULL;
    result = matching != NULL
        ? get_matching_services(MACH_PORT_NULL, matching, &iterator)
        : KERN_FAILURE;
    if (result != KERN_SUCCESS || !MACH_PORT_VALID(iterator)) {
        fprintf(stderr, "IOService enumeration failed: %#x\n", result);
        close(fd);
        dlclose(iokit);
        return 1;
    }

    printf("{\"kind\":\"header\",\"kernelBase\":\"%#llx\","
           "\"slide\":\"%#llx\",\"capabilities\":\"%#llx\","
           "\"selfProc\":\"%#llx\",\"selfTask\":\"%#llx\","
           "\"root\":\"%#llx\",\"portKobjectOffset\":\"%#llx\","
           "\"kobjectInnerOffset\":\"%#llx\"}\n",
           kernel_base, slide, capabilities, proc, task, root,
           kobject_offset, kobject_inner_offset);
    if (slot_mode) {
        printf("{\"kind\":\"slot-request\",\"offset\":\"%#llx\"}\n",
               requested_slot);
    }
    uint64_t requested_live_target = requested_static_target + slide;
    if (find_target_mode) {
        printf("{\"kind\":\"target-request\","
               "\"staticTarget\":\"%#llx\",\"liveTarget\":\"%#llx\"}\n",
               requested_static_target, requested_live_target);
    }

    uint64_t observed_objects[kMaxServices];
    PMProfile profiles[kMaxServices] = {0};
    GraphNode *graph_roots = graph_mode
        ? calloc(kMaxServices, sizeof(*graph_roots)) : NULL;
    if (graph_mode && graph_roots == NULL) {
        fprintf(stderr, "graph root allocation failed\n");
        object_release(iterator);
        close(fd);
        dlclose(iokit);
        return 1;
    }
    uint32_t graph_root_count = 0;
    uint32_t observed_count = 0;
    uint32_t profile_count = 0;
    uint32_t emitted = 0;
    for (uint32_t index = 0; index < kMaxServices; index++) {
        io_service_t service = iterator_next(iterator);
        if (!MACH_PORT_VALID(service)) break;
        io_name_t name = {0};
        if (entry_get_name(service, name) != KERN_SUCCESS || name[0] == 0) {
            snprintf(name, sizeof(name), "unknown-%u", index);
        }
        uint64_t port = port_object(fd, ipc_table, service);
        uint64_t wrapper = zone_pointer(port)
            ? read_data_pointer(fd, port + kobject_offset) : 0;
        uint64_t object = kobject_inner_offset == 0
            ? wrapper
            : (zone_pointer(wrapper)
                ? read_data_pointer(fd, wrapper + kobject_inner_offset) : 0);
        object_release(service);
        if (!zone_pointer(object)) continue;
        int duplicate = 0;
        for (uint32_t prior = 0; prior < observed_count; prior++) {
            if (observed_objects[prior] == object) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) continue;
        observed_objects[observed_count++] = object;

        if (graph_mode) {
            GraphNode *root_node = &graph_roots[graph_root_count++];
            snprintf(root_node->root_name, sizeof(root_node->root_name),
                     "%s", name);
            root_node->object = object;
            continue;
        }

        uint64_t raw_vtable = 0;
        if (read_u64(fd, object, &raw_vtable) != 0) continue;
        uint64_t vtable = strip_data_pac(raw_vtable);
        if (!kernel_image_pointer(vtable, kernel_base)) continue;
        if (find_target_mode) {
            enum { kFindTargetVtableBytes = 0x1000 };
            uint64_t table[kFindTargetVtableBytes / sizeof(uint64_t)] = {0};
            if (kernel_read(fd, vtable, table, sizeof(table)) != 0) continue;
            for (uint64_t offset = 0; offset < sizeof(table); offset += 8) {
                uint64_t raw_target = table[offset / sizeof(uint64_t)];
                uint64_t target = strip_instruction_pac(raw_target);
                if (target != requested_live_target) continue;
                printf("{\"kind\":\"target-match\",\"index\":%u,"
                       "\"name\":", index);
                json_string(name);
                printf(",\"object\":\"%#llx\",\"rawVtable\":\"%#llx\","
                       "\"vtable\":\"%#llx\",\"offset\":\"%#llx\","
                       "\"rawTarget\":\"%#llx\",\"target\":\"%#llx\"}\n",
                       object, raw_vtable, vtable, offset, raw_target, target);
                emitted++;
            }
            continue;
        }
        if (slot_mode) {
            uint64_t raw_target = 0;
            if (read_u64(fd, vtable + requested_slot, &raw_target) != 0) {
                continue;
            }
            uint64_t target = strip_instruction_pac(raw_target);
            if (!kernel_image_pointer(target, kernel_base)) continue;
            printf("{\"kind\":\"slot\",\"index\":%u,\"name\":", index);
            json_string(name);
            printf(",\"object\":\"%#llx\",\"rawVtable\":\"%#llx\","
                   "\"vtable\":\"%#llx\",\"offset\":\"%#llx\","
                   "\"rawTarget\":\"%#llx\",\"target\":\"%#llx\"}\n",
                   object, raw_vtable, vtable, requested_slot, raw_target,
                   target);
            emitted++;
            continue;
        }
        if (unique_profiles) {
            uint32_t profile = 0;
            for (; profile < profile_count; profile++) {
                if (profiles[profile].vtable == vtable) {
                    profiles[profile].instances++;
                    break;
                }
            }
            if (profile == profile_count && profile_count < kMaxServices) {
                PMProfile *entry = &profiles[profile_count++];
                snprintf(entry->name, sizeof(entry->name), "%s", name);
                entry->object = object;
                entry->raw_vtable = raw_vtable;
                entry->vtable = vtable;
                entry->instances = 1;
            }
            continue;
        }
        const uint64_t offsets[kMethodCount] = {
            0x0f0, 0x108, 0x428, 0x4d8, 0x4e8, 0x4f8, 0x500, 0x588,
            0x720,
        };
        uint64_t methods[kMethodCount] = {0};
        if (read_method_targets(fd, vtable, offsets, kMethodCount,
                                kernel_base, methods) != 0) continue;

        printf("{\"kind\":\"service\",\"index\":%u,\"name\":",
               index);
        json_string(name);
        printf(",\"object\":\"%#llx\",\"rawVtable\":\"%#llx\","
               "\"vtable\":\"%#llx\",\"slot0f0\":\"%#llx\","
               "\"slot108\":\"%#llx\",\"slot428\":\"%#llx\","
               "\"slot4d8\":\"%#llx\",\"slot4e8\":\"%#llx\","
               "\"slot4f8\":\"%#llx\",\"slot500\":\"%#llx\","
               "\"slot588\":\"%#llx\",\"slot720\":\"%#llx\"}\n",
               object, raw_vtable, vtable, methods[0], methods[1],
               methods[2], methods[3], methods[4], methods[5],
               methods[6], methods[7], methods[8]);
        emitted++;
    }
    object_release(iterator);
    if (graph_mode) {
        emitted = emit_object_graph(fd, graph_roots, graph_root_count,
                                    kernel_base);
    }
    if (unique_profiles) {
        const uint64_t offsets[kMethodCount] = {
            0x0f0, 0x108, 0x428, 0x4d8, 0x4e8, 0x4f8, 0x500, 0x588,
            0x720,
        };
        uint32_t candidates = profile_count;
        uint32_t condensed = 0;
        for (uint32_t profile = 0; profile < candidates; profile++) {
            PMProfile candidate = profiles[profile];
            if (read_method_targets(fd, candidate.vtable, offsets,
                                    kMethodCount, kernel_base,
                                    candidate.methods) != 0) {
                continue;
            }
            uint32_t existing = 0;
            for (; existing < condensed; existing++) {
                if (memcmp(profiles[existing].methods, candidate.methods,
                           sizeof(candidate.methods)) == 0) {
                    profiles[existing].instances += candidate.instances;
                    break;
                }
            }
            if (existing == condensed) profiles[condensed++] = candidate;
        }
        profile_count = condensed;
        for (uint32_t profile = 0; profile < profile_count; profile++) {
            PMProfile *entry = &profiles[profile];
            printf("{\"kind\":\"profile\",\"index\":%u,\"name\":",
                   profile);
            json_string(entry->name);
            printf(",\"instances\":%u,\"object\":\"%#llx\","
                   "\"rawVtable\":\"%#llx\",\"vtable\":\"%#llx\","
                   "\"slot0f0\":\"%#llx\",\"slot108\":\"%#llx\","
                   "\"slot428\":\"%#llx\",\"slot4d8\":\"%#llx\","
                   "\"slot4e8\":\"%#llx\",\"slot4f8\":\"%#llx\","
                   "\"slot500\":\"%#llx\",\"slot588\":\"%#llx\","
                   "\"slot720\":\"%#llx\"}\n",
                   entry->instances, entry->object, entry->raw_vtable,
                   entry->vtable, entry->methods[0], entry->methods[1],
                   entry->methods[2], entry->methods[3], entry->methods[4],
                   entry->methods[5], entry->methods[6], entry->methods[7],
                   entry->methods[8]);
            emitted++;
        }
    }
    printf("{\"kind\":\"summary\",\"objects\":%u,\"profiles\":%u,"
           "\"graphRoots\":%u,"
           "\"emitted\":%u,\"usedKernelWrite\":false,"
           "\"usedKernelCall\":false}\n",
           observed_count, unique_profiles ? profile_count : 0,
           graph_mode ? graph_root_count : 0, emitted);
    free(graph_roots);
    close(fd);
    dlclose(iokit);
    return emitted != 0 ? 0 : 1;
}
