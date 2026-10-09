#include "CNDLabKernelProtocol.h"

#include <errno.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int transfer_all(int fd, void *buffer, size_t size, int writing)
{
    unsigned char *cursor = buffer;
    while (size > 0) {
        ssize_t amount = writing
            ? write(fd, cursor, size) : read(fd, cursor, size);
        if (amount == 0) return ECONNRESET;
        if (amount < 0) {
            if (errno == EINTR) continue;
            return errno ?: EIO;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return 0;
}

static int request(int fd, uint32_t operation, uint64_t address,
                   void *buffer, size_t length, uint64_t *value)
{
    int sends_payload = operation == CNDLabKRWOperationResolvePID ||
        operation == CNDLabKRWOperationTaskWrite ||
        operation == CNDLabKRWOperationKernelCall;
    int receives_payload = operation == CNDLabKRWOperationRead ||
        operation == CNDLabKRWOperationTaskRead;
    CNDLabKRWRequest message = {
        .magic = CND_LAB_KRW_MAGIC,
        .version = CND_LAB_KRW_VERSION,
        .operation = operation,
        .length = (uint32_t)length,
        .address = address,
    };
    int result = transfer_all(fd, &message, sizeof(message), 1);
    if (result == 0 && sends_payload && length > 0) {
        result = transfer_all(fd, buffer, length, 1);
    }
    CNDLabKRWResponse response = {0};
    if (result == 0) {
        result = transfer_all(fd, &response, sizeof(response), 0);
    }
    if (result == 0 && (response.magic != CND_LAB_KRW_MAGIC ||
        response.status != 0 ||
        (receives_payload && response.length != length))) {
        result = response.status ?: EPROTO;
    }
    if (result == 0 && receives_payload && length > 0) {
        result = transfer_all(fd, buffer, length, 0);
    }
    if (result == 0 && value) *value = response.value;
    return result;
}

static int kernel_read(int fd, uint64_t address, void *buffer, size_t length)
{
    unsigned char *cursor = buffer;
    while (length > 0) {
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

static int image_commands(int fd, uint64_t address,
                          struct mach_header_64 *header,
                          unsigned char **commands)
{
    int result = kernel_read(fd, address, header, sizeof(*header));
    if (result != 0) return result;
    if (header->magic != MH_MAGIC_64 || header->ncmds == 0 ||
        header->ncmds > 4096 || header->sizeofcmds == 0 ||
        header->sizeofcmds > 1024 * 1024) {
        return ENOEXEC;
    }
    unsigned char *loaded = malloc(header->sizeofcmds);
    if (!loaded) return ENOMEM;
    result = kernel_read(fd, address + sizeof(*header),
                         loaded, header->sizeofcmds);
    if (result != 0) {
        free(loaded);
        return result;
    }
    *commands = loaded;
    return 0;
}

static int next_command(const struct mach_header_64 *header,
                        const unsigned char *commands, uint32_t index,
                        size_t *offset, const struct load_command **command)
{
    if (index >= header->ncmds ||
        *offset + sizeof(struct load_command) > header->sizeofcmds) {
        return ENOEXEC;
    }
    const struct load_command *current =
        (const struct load_command *)(commands + *offset);
    if (current->cmdsize < sizeof(*current) ||
        *offset + current->cmdsize > header->sizeofcmds) {
        return ENOEXEC;
    }
    *command = current;
    *offset += current->cmdsize;
    return 0;
}

static int find_safe_return_stub(int fd, uint64_t base,
                                 uint64_t *gadget,
                                 uint64_t argument_sentinel,
                                 uint64_t *expected_result)
{
    struct mach_header_64 fileset_header = {0};
    unsigned char *fileset_commands = NULL;
    int result = image_commands(
        fd, base, &fileset_header, &fileset_commands);
    if (result != 0 || fileset_header.filetype != MH_FILESET) {
        free(fileset_commands);
        return result ?: ENOEXEC;
    }

    uint64_t unslid_fileset_base = 0;
    uint64_t kernel_vmaddr = 0;
    uint64_t kernel_fileoff = 0;
    size_t offset = 0;
    for (uint32_t i = 0; i < fileset_header.ncmds; i++) {
        const struct load_command *command = NULL;
        result = next_command(&fileset_header, fileset_commands,
                              i, &offset, &command);
        if (result != 0) break;
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (segment->fileoff == 0 && unslid_fileset_base == 0) {
                unslid_fileset_base = segment->vmaddr;
            }
        } else if (command->cmd == LC_FILESET_ENTRY &&
                   command->cmdsize >= sizeof(struct fileset_entry_command)) {
            const struct fileset_entry_command *entry =
                (const struct fileset_entry_command *)command;
            uint32_t name_offset = entry->entry_id.offset;
            if (name_offset < entry->cmdsize) {
                const char *name = (const char *)entry + name_offset;
                size_t capacity = entry->cmdsize - name_offset;
                if (strnlen(name, capacity) < capacity &&
                    strcmp(name, "com.apple.kernel") == 0) {
                    kernel_vmaddr = entry->vmaddr;
                    kernel_fileoff = entry->fileoff;
                }
            }
        }
    }
    free(fileset_commands);
    if (result != 0 || unslid_fileset_base == 0 ||
        kernel_vmaddr == 0 || kernel_fileoff == 0 ||
        base < unslid_fileset_base) {
        return result ?: ENOEXEC;
    }

    uint64_t slide = base - unslid_fileset_base;
    uint64_t kernel_address = kernel_vmaddr + slide;
    if (kernel_address != base + kernel_fileoff) return ENOEXEC;

    struct mach_header_64 kernel_header = {0};
    unsigned char *kernel_commands = NULL;
    result = image_commands(
        fd, kernel_address, &kernel_header, &kernel_commands);
    if (result != 0 || kernel_header.filetype != MH_EXECUTE) {
        free(kernel_commands);
        return result ?: ENOEXEC;
    }

    uint64_t execute_address = 0;
    uint64_t execute_size = 0;
    offset = 0;
    for (uint32_t i = 0; i < kernel_header.ncmds; i++) {
        const struct load_command *command = NULL;
        result = next_command(&kernel_header, kernel_commands,
                              i, &offset, &command);
        if (result != 0) break;
        if (command->cmd != LC_SEGMENT_64 ||
            command->cmdsize < sizeof(struct segment_command_64)) {
            continue;
        }
        const struct segment_command_64 *segment =
            (const struct segment_command_64 *)command;
        if (strncmp(segment->segname, "__TEXT_EXEC", 16) == 0 &&
            (segment->initprot & 4) != 0) {
            execute_address = segment->vmaddr + slide;
            execute_size = segment->vmsize;
            break;
        }
    }
    free(kernel_commands);
    if (result != 0 || execute_address < base || execute_size < 8 ||
        execute_address - base >= 0x40000000ULL) {
        return result ?: ENOEXEC;
    }

    static const uint32_t return_x30 = 0xd65f03c0U;
    static const struct {
        uint32_t instruction;
        uint64_t result;
        int returns_argument;
    } safe_stubs[] = {
        { 0xaa0003e0U, 0, 1 }, /* mov x0, x0; ret */
        { 0x52800000U, 0, 0 }, /* mov w0, #0; ret */
        { 0xd2800000U, 0, 0 }, /* mov x0, #0; ret */
        { 0xaa1f03e0U, 0, 0 }, /* mov x0, xzr; ret */
        { 0x52800020U, 1, 0 }, /* mov w0, #1; ret */
        { 0xd2800020U, 1, 0 }, /* mov x0, #1; ret */
    };
    unsigned char buffer[CND_LAB_KRW_MAX_TRANSFER];
    uint64_t scanned = 0;
    uint64_t limit = execute_size < 0x1000000ULL
        ? execute_size : 0x1000000ULL;
    while (scanned < limit) {
        size_t amount = (size_t)(limit - scanned);
        if (amount > sizeof(buffer)) amount = sizeof(buffer);
        result = kernel_read(fd, execute_address + scanned, buffer, amount);
        if (result != 0) return result;
        for (size_t i = 0; i + 8 <= amount; i += 4) {
            uint32_t first = 0;
            uint32_t second = 0;
            memcpy(&first, buffer + i, sizeof(first));
            memcpy(&second, buffer + i + 4, sizeof(second));
            if (second == return_x30) {
                for (size_t pattern = 0;
                     pattern < sizeof(safe_stubs) / sizeof(safe_stubs[0]);
                     pattern++) {
                    if (first != safe_stubs[pattern].instruction) continue;
                    *gadget = execute_address + scanned + i;
                    *expected_result = safe_stubs[pattern].returns_argument
                        ? argument_sentinel : safe_stubs[pattern].result;
                    return 0;
                }
            }
        }
        scanned += amount;
    }
    return ENOENT;
}

static int kernel_call_smoke(int fd, uint64_t capabilities,
                             uint64_t *gadget, uint64_t *observed)
{
    if ((capabilities & CNDLabKRWCapabilityKernelReadWrite) == 0 ||
        (capabilities & CNDLabKRWCapabilityKernelCall) == 0) {
        return ENOTSUP;
    }
    uint64_t base = 0;
    int result = request(fd, CNDLabKRWOperationKBase,
                         0, NULL, 0, &base);
    if (result != 0) return result;
    static const uint64_t sentinel = 0x434e444b43414c4cULL;
    uint64_t expected = 0;
    result = find_safe_return_stub(
        fd, base, gadget, sentinel, &expected);
    if (result != 0) return result;

    CNDLabKernelCallRequest call = {
        .version = CND_LAB_KCALL_ABI_VERSION,
        .argument_count = 1,
        .function = *gadget,
        .arguments = { sentinel },
    };
    result = request(fd, CNDLabKRWOperationKernelCall,
                     0, &call, sizeof(call), observed);
    if (result == 0 && *observed != expected) result = EILSEQ;
    return result;
}

int main(int argc, char **argv)
{
    int run_kcall_smoke = argc == 4 &&
        strcmp(argv[3], "--kcall-smoke") == 0;
    int kcall_smoke_only = argc == 4 &&
        strcmp(argv[3], "--kcall-smoke-only") == 0;
    if ((argc != 3 && !run_kcall_smoke && !kcall_smoke_only) ||
        strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path) ||
        strlen(argv[2]) == 0 || strlen(argv[2]) >= 31) {
        fprintf(stderr,
                "usage: %s SOCKET PROCESS "
                "[--kcall-smoke|--kcall-smoke-only]\n", argv[0]);
        return 2;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, argv[1]);
    if (fd < 0 || connect(fd, (struct sockaddr *)&address,
                          sizeof(address)) != 0) {
        perror("connect");
        return 3;
    }

    uint64_t capabilities = 0;
    int result = request(fd, CNDLabKRWOperationCapabilities,
                         0, NULL, 0, &capabilities);
    if (result != 0 ||
        (capabilities & CNDLabKRWCapabilityProcessResolve) == 0) {
        fprintf(stderr, "capability probe failed result=%d capabilities=%#llx\n",
                result, capabilities);
        return 4;
    }

    if (kcall_smoke_only) {
        uint64_t gadget = 0;
        uint64_t call_result = 0;
        int smoke_result = kernel_call_smoke(
            fd, capabilities, &gadget, &call_result);
        close(fd);
        if (smoke_result != 0) {
            fprintf(stderr, "kernel-call smoke failed result=%d\n",
                    smoke_result);
            return 5;
        }
        printf("ready capabilities=%#llx kernelCall=available "
               "smoke=passed gadget=%#llx result=%#llx\n",
               capabilities, gadget, call_result);
        return 0;
    }

    uint64_t pid = 0;
    result = request(fd, CNDLabKRWOperationResolvePID, 0, argv[2],
                     strlen(argv[2]) + 1, &pid);
    if (result == 0 &&
        (capabilities & CNDLabKRWCapabilityDirectTask) == 0) {
        uint64_t gadget = 0;
        uint64_t call_result = 0;
        int smoke_result = run_kcall_smoke
            ? kernel_call_smoke(fd, capabilities, &gadget, &call_result) : 0;
        close(fd);
        if (smoke_result != 0) {
            fprintf(stderr, "kernel-call smoke failed result=%d\n",
                    smoke_result);
            return 5;
        }
        printf("ready process=%s pid=%llu capabilities=%#llx "
               "mode=resolve-only kernelCall=%s smoke=%s gadget=%#llx "
               "result=%#llx\n", argv[2], pid,
               capabilities,
               (capabilities & CNDLabKRWCapabilityKernelCall)
                   ? "available" : "unavailable",
               run_kcall_smoke ? "passed" : "not-run", gadget,
               call_result);
        return 0;
    }
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationTaskOpen,
                         pid, NULL, 0, NULL);
    }
    uint64_t remote = 0;
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationTaskAllocate,
                         0, NULL, 0x4000, &remote);
    }
    uint64_t expected = 0x434e444c41424b52ULL;
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationTaskWrite,
                         remote, &expected, sizeof(expected), NULL);
    }
    uint64_t observed = 0;
    if (result == 0) {
        result = request(fd, CNDLabKRWOperationTaskRead,
                         remote, &observed, sizeof(observed), NULL);
    }
    if (result == 0 && observed != expected) result = EILSEQ;
    int deallocate_result = remote ? request(
        fd, CNDLabKRWOperationTaskDeallocate,
        remote, NULL, 0x4000, NULL) : 0;
    int close_result = request(fd, CNDLabKRWOperationTaskClose,
                               0, NULL, 0, NULL);
    uint64_t gadget = 0;
    uint64_t call_result = 0;
    int smoke_result = run_kcall_smoke
        ? kernel_call_smoke(fd, capabilities, &gadget, &call_result) : 0;
    close(fd);

    if (result != 0 || deallocate_result != 0 || close_result != 0 ||
        smoke_result != 0) {
        fprintf(stderr,
                "direct-task probe failed pid=%llu address=%#llx "
                "operation=%d deallocate=%d close=%d kcallSmoke=%d\n",
                pid, remote, result, deallocate_result, close_result,
                smoke_result);
        return 5;
    }
    printf("ready process=%s pid=%llu capabilities=%#llx address=%#llx "
           "readback=yes close=yes kernelCall=%s smoke=%s gadget=%#llx "
           "result=%#llx\n", argv[2], pid,
           capabilities, remote,
           (capabilities & CNDLabKRWCapabilityKernelCall)
               ? "available" : "unavailable",
           run_kcall_smoke ? "passed" : "not-run", gadget, call_result);
    return 0;
}
