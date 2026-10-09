#include "CNDLabKernelProtocol.h"

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <mach-o/loader.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <unistd.h>

extern kern_return_t mach_vm_read_overwrite(
    task_t task, mach_vm_address_t address, mach_vm_size_t size,
    mach_vm_address_t data, mach_vm_size_t *out_size);
extern kern_return_t mach_vm_allocate(
    task_t task, mach_vm_address_t *address, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(
    task_t task, mach_vm_address_t address, mach_vm_size_t size);
extern kern_return_t mach_vm_write(
    task_t task, mach_vm_address_t address, mach_vm_address_t data,
    mach_msg_type_number_t data_count);
extern kern_return_t mach_vm_protect(
    task_t task, mach_vm_address_t address, mach_vm_size_t size,
    boolean_t set_maximum, vm_prot_t new_protection);
extern kern_return_t mach_vm_machine_attribute(
    task_t task, mach_vm_address_t address, mach_vm_size_t size,
    vm_machine_attribute_t attribute,
    vm_machine_attribute_val_t *value);
extern kern_return_t mach_vm_region_recurse(
    vm_map_t target_task, mach_vm_address_t *address,
    mach_vm_size_t *size, natural_t *depth,
    vm_region_recurse_info_t info, mach_msg_type_number_t *info_count);

typedef int (*CNDKBaseFunction)(uint64_t *address);
typedef int (*CNDKReadFunction)(uint64_t from, void *to, size_t length);
typedef int (*CNDKWriteFunction)(void *from, uint64_t to, size_t length);
typedef int (*CNDKMallocFunction)(uint64_t *address, size_t size);
typedef int (*CNDKDeallocFunction)(uint64_t address, size_t size);
typedef int (*CNDKCallFunction)(uint64_t function, size_t argument_count,
                               const uint64_t *arguments, uint64_t *result);
typedef int (*CNDPhysReadFunction)(uint64_t from, void *to, size_t length,
                                  uint8_t granule);
typedef int (*CNDPhysWriteFunction)(void *from, uint64_t to, size_t length,
                                   uint8_t granule);

typedef struct {
    uint64_t version;
    CNDKBaseFunction kbase;
    CNDKReadFunction kread;
    CNDKWriteFunction kwrite;
    CNDKMallocFunction kmalloc;
    CNDKDeallocFunction kdealloc;
    CNDKCallFunction kcall;
    CNDPhysReadFunction physread;
    CNDPhysWriteFunction physwrite;
} CNDKRWHandlers;

typedef int (*CNDKRWInitializer)(CNDKRWHandlers *handlers);

static void *g_libkrw_handle;
static CNDKReadFunction g_libkrw_read;
static CNDKWriteFunction g_libkrw_write;
static CNDKCallFunction g_libkrw_kcall;
static int g_vphone_kcall_syscall;

enum {
    CND_VPHONE_KCALL_SYSCALL = 439,
    CND_VPHONE_KCALL_MAX_ARGUMENTS = 7,
};

static int kernel_call_target_valid(uint64_t base, uint64_t function)
{
    static const uint64_t maximum_kernel_image_span = 0x40000000ULL;
    return base != 0 && function >= base &&
        function - base < maximum_kernel_image_span &&
        (function & 0x3ULL) == 0;
}

/*
 * The jailbroken vPhone firmware reserves syscall 439 for its ABI-correct
 * target + seven arguments kernel-call cave. Use the raw Darwin arm64 syscall
 * convention so a successful UINT64_MAX result is not mistaken for errno.
 */
static int vphone_kcall_syscall(uint64_t function, size_t argument_count,
                               const uint64_t *arguments, uint64_t *result)
{
    if (!result || argument_count > CND_VPHONE_KCALL_MAX_ARGUMENTS ||
        (argument_count != 0 && !arguments)) {
        return EINVAL;
    }
    uint64_t values[CND_VPHONE_KCALL_MAX_ARGUMENTS] = {0};
    if (argument_count != 0) {
        memcpy(values, arguments, argument_count * sizeof(values[0]));
    }
    register uint64_t x0 __asm("x0") = function;
    register uint64_t x1 __asm("x1") = values[0];
    register uint64_t x2 __asm("x2") = values[1];
    register uint64_t x3 __asm("x3") = values[2];
    register uint64_t x4 __asm("x4") = values[3];
    register uint64_t x5 __asm("x5") = values[4];
    register uint64_t x6 __asm("x6") = values[5];
    register uint64_t x7 __asm("x7") = values[6];
    register uint64_t x16 __asm("x16") = CND_VPHONE_KCALL_SYSCALL;
    unsigned int failed = 0;
    __asm__ volatile(
        "svc #0x80\n\t"
        "cset %w[failed], cs"
        : "+r"(x0), [failed] "=&r"(failed)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6),
          "r"(x7), "r"(x16)
        : "cc", "memory");
    if (failed) return x0 <= INT_MAX ? (int)x0 : EIO;
    *result = x0;
    return 0;
}

static int vphone_kcall_syscall_available(void)
{
    uint64_t ignored = 0;
    int result = vphone_kcall_syscall(0, 0, NULL, &ignored);
    /* The patched cave rejects a null target; stock kas_info is ENOTSUP. */
    return result == EINVAL;
}

static CNDKCallFunction active_kernel_call(void)
{
    if (g_libkrw_kcall) return g_libkrw_kcall;
    return g_vphone_kcall_syscall ? vphone_kcall_syscall : NULL;
}

/*
 * kinfo_proc.p_comm is limited to MAXCOMLEN (16) characters.  Several of the
 * exact targets used by this lab are longer (notably "iconservicesagent"), so
 * strcmp(p_comm, requested_name) can never resolve them.  Root may read the
 * bounded KERN_PROCARGS2 record; its first string is the executable path and
 * gives us an exact, non-prefix basename check without broad process access.
 */
static int process_executable_name_matches(pid_t pid, const char *name)
{
    enum { CND_LAB_PROCARGS_MAX = 64 * 1024 };
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };
    size_t size = 0;
    if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0 ||
        size <= sizeof(int) || size > CND_LAB_PROCARGS_MAX) {
        return 0;
    }
    unsigned char *arguments = calloc(1, size + 1);
    if (!arguments) return 0;
    size_t actual = size;
    int matches = 0;
    if (sysctl(mib, 3, arguments, &actual, NULL, 0) == 0 &&
        actual > sizeof(int) && actual <= size) {
        const char *path = (const char *)arguments + sizeof(int);
        size_t path_capacity = actual - sizeof(int);
        size_t path_length = strnlen(path, path_capacity);
        if (path_length > 0 && path_length < path_capacity) {
            const char *basename = strrchr(path, '/');
            basename = basename ? basename + 1 : path;
            matches = strcmp(basename, name) == 0;
        }
    }
    free(arguments);
    return matches;
}

static int process_name_matches(const struct kinfo_proc *process,
                                const char *name)
{
    if (strcmp(process->kp_proc.p_comm, name) == 0) return 1;
    size_t name_length = strlen(name);
    if (name_length <= MAXCOMLEN ||
        strncmp(process->kp_proc.p_comm, name, MAXCOMLEN) != 0) {
        return 0;
    }
    return process_executable_name_matches(
        process->kp_proc.p_pid, name);
}

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

static int send_response(int fd, int status, uint32_t length, uint64_t value)
{
    CNDLabKRWResponse response = {
        .magic = CND_LAB_KRW_MAGIC,
        .status = status,
        .length = length,
        .value = value,
    };
    return transfer_all(fd, &response, sizeof(response), 1);
}

static int plausible_kernel_slide(uint64_t value)
{
    return value <= 0x400000000ULL && (value & 0x3fffULL) == 0;
}

static int kernel_base(mach_port_t kernel_task, uint64_t *base,
                       const char **source)
{
    static const uint64_t vphone_unslid_text_base = 0xfffffe0007004000ULL;

    task_dyld_info_data_t info = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(kernel_task, TASK_DYLD_INFO,
                                 (task_info_t)&info, &count);
    if (kr == KERN_SUCCESS) {
        // The lab jailbreak stashes either the full kernel base or its slide in
        // TASK_DYLD_INFO. Do not probe speculative kernel addresses here: this
        // vPhone kernel treats some invalid physical-aperture reads as fatal.
        if ((info.all_image_info_addr & 0xffff000000000000ULL) ==
            0xffff000000000000ULL) {
            *base = info.all_image_info_addr;
            if (source) *source = "task-dyld-base";
            return 0;
        }

        uint64_t slide = 0;
        const char *slide_source = NULL;
        if (info.all_image_info_addr != 0 &&
            plausible_kernel_slide(info.all_image_info_addr)) {
            slide = info.all_image_info_addr;
            slide_source = "task-dyld-address-slide";
        } else if (info.all_image_info_size != 0 &&
                   plausible_kernel_slide(info.all_image_info_size)) {
            slide = info.all_image_info_size;
            slide_source = "task-dyld-size-slide";
        }
        if (slide_source) {
            *base = vphone_unslid_text_base + slide;
            if (source) *source = slide_source;
            return 0;
        }
    }

    fprintf(stderr,
            "jailbreak did not supply a plausible TASK_DYLD_INFO base/slide: "
            "kr=%d addr=%#llx size=%#llx\n",
            kr, info.all_image_info_addr, info.all_image_info_size);

    // Some vPhone jailbreak boots hand out a valid kernel task port without
    // populating TASK_DYLD_INFO. Enumerate mapped kernel regions instead of
    // probing speculative addresses; the latter can fault the VM's physical
    // aperture. The fileset header sits at the start of a readable mapping.
    mach_vm_address_t address = vphone_unslid_text_base;
    for (unsigned int i = 0; i < 512; i++) {
        mach_vm_size_t region_size = 0;
        natural_t depth = 0;
        vm_region_submap_info_data_64_t region = {0};
        mach_msg_type_number_t region_count =
            VM_REGION_SUBMAP_INFO_COUNT_64;
        kr = mach_vm_region_recurse(
            kernel_task, &address, &region_size, &depth,
            (vm_region_recurse_info_t)&region, &region_count);
        if (kr != KERN_SUCCESS || region_size == 0) {
            fprintf(stderr,
                    "kernel region enumeration stopped index=%u kr=%d "
                    "address=%#llx size=%#llx\n",
                    i, kr, address, region_size);
            break;
        }

        if (i < 16) {
            fprintf(stderr,
                    "kernel region index=%u address=%#llx size=%#llx "
                    "protection=%#x max=%#x submap=%u\n",
                    i, address, region_size, region.protection,
                    region.max_protection, region.is_submap);
        }

        if ((region.protection & VM_PROT_READ) != 0) {
            struct mach_header_64 header = {0};
            mach_vm_size_t copied = 0;
            kern_return_t read_result = mach_vm_read_overwrite(
                kernel_task, address, sizeof(header),
                (mach_vm_address_t)&header, &copied);
            if (i < 16) {
                fprintf(stderr,
                        "kernel region index=%u address=%#llx size=%#llx "
                        "protection=%#x read=%d copied=%#llx magic=%#x "
                        "filetype=%#x\n",
                        i, address, region_size, region.protection,
                        read_result, copied, header.magic, header.filetype);
            }
            if (read_result == KERN_SUCCESS && copied == sizeof(header) &&
                header.magic == MH_MAGIC_64 &&
                (header.filetype == MH_FILESET ||
                 header.filetype == MH_EXECUTE)) {
                *base = address;
                if (source) *source = "kernel-task-region";
                return 0;
            }
        }

        mach_vm_address_t next = address + region_size;
        if (next <= address || next >
            vphone_unslid_text_base + 0x400000000ULL) break;
        address = next;
    }
    return ENOENT;
}

static int activate_libkrw(uint64_t *base, const char **source)
{
    static const char *plugin_paths[] = {
        "/var/jb/usr/lib/libkrw/libkrw-tfp0.dylib",
        "/usr/lib/libkrw/libkrw-tfp0.dylib",
    };
    static const char *paths[] = {
        "/var/jb/usr/lib/libkrw.0.dylib",
        "/usr/lib/libkrw.0.dylib",
    };

    /*
     * Palera1n's libkrw front-end can be installed without an active default
     * backend.  In that state its exported kbase returns ENOTSUP even though
     * the tfp0 plugin is usable.  Match Cyanide's VM-only provider and ask the
     * plugin for its versioned handler table before trying the front-end.
     * The lab server must be built as arm64 on this image because both dylibs
     * are arm64; injected inspection payloads remain arm64e.
     */
    for (size_t i = 0;
         i < sizeof(plugin_paths) / sizeof(plugin_paths[0]); i++) {
        void *handle = dlopen(plugin_paths[i], RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            fprintf(stderr, "libkrw plugin load failed path=%s error=%s\n",
                    plugin_paths[i], dlerror() ?: "unknown");
            continue;
        }

        CNDKRWInitializer initialize =
            (CNDKRWInitializer)dlsym(handle, "krw_initializer");
        CNDKRWHandlers handlers = { .version = 0 };
        int initialize_result = initialize ? initialize(&handlers) : ENOSYS;
        uint64_t candidate = 0;
        uint32_t magic = 0;
        int base_result = initialize_result == 0 && handlers.kbase
            ? handlers.kbase(&candidate) : initialize_result;
        int read_result = base_result == 0 && handlers.kread
            ? handlers.kread(candidate, &magic, sizeof(magic)) : ENOSYS;
        if (initialize_result == 0 && base_result == 0 && read_result == 0 &&
            handlers.kwrite &&
            (candidate & 0xffff000000000000ULL) ==
                0xffff000000000000ULL &&
            magic == 0xfeedfacf) {
            g_libkrw_handle = handle;
            g_libkrw_read = handlers.kread;
            g_libkrw_write = handlers.kwrite;
            g_libkrw_kcall = handlers.kcall;
            *base = candidate;
            if (source) *source = "libkrw-tfp0";
            return 0;
        }
        fprintf(stderr,
                "libkrw plugin validation failed path=%s init=%d "
                "baseResult=%d readResult=%d base=%#llx magic=%#x\n",
                plugin_paths[i], initialize_result, base_result, read_result,
                candidate, magic);
        dlclose(handle);
        g_libkrw_kcall = NULL;
    }

    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        void *handle = dlopen(paths[i], RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            fprintf(stderr, "libkrw load failed path=%s error=%s\n",
                    paths[i], dlerror() ?: "unknown");
            continue;
        }

        CNDKBaseFunction kbase =
            (CNDKBaseFunction)dlsym(handle, "kbase");
        CNDKReadFunction kread =
            (CNDKReadFunction)dlsym(handle, "kread");
        CNDKWriteFunction kwrite =
            (CNDKWriteFunction)dlsym(handle, "kwrite");
        CNDKCallFunction kcall =
            (CNDKCallFunction)dlsym(handle, "kcall");
        uint64_t candidate = 0;
        uint32_t magic = 0;
        int base_result = kbase ? kbase(&candidate) : ENOSYS;
        int read_result = base_result == 0 && kread
            ? kread(candidate, &magic, sizeof(magic)) : ENOSYS;
        if (base_result == 0 && read_result == 0 &&
            (candidate & 0xffff000000000000ULL) ==
                0xffff000000000000ULL &&
            magic == 0xfeedfacf) {
            g_libkrw_handle = handle;
            g_libkrw_read = kread;
            g_libkrw_write = kwrite;
            g_libkrw_kcall = kcall;
            *base = candidate;
            if (source) *source = "libkrw";
            return 0;
        }
        fprintf(stderr,
                "libkrw validation failed path=%s baseResult=%d "
                "readResult=%d base=%#llx magic=%#x\n",
                paths[i], base_result, read_result, candidate, magic);
        dlclose(handle);
        g_libkrw_kcall = NULL;
    }
    return ENOENT;
}

static int resolve_debugger_base(mach_port_t kernel_task,
                                 uint64_t candidate, uint64_t *base)
{
    uint64_t fallback_execute = 0;
    for (unsigned int i = 0; i < 0x1000; i++) {
        uint64_t address = candidate - ((uint64_t)i * 0x4000ULL);
        struct mach_header_64 header = {0};
        mach_vm_size_t copied = 0;
        kern_return_t kr = mach_vm_read_overwrite(
            kernel_task, address, sizeof(header),
            (mach_vm_address_t)&header, &copied);
        if (kr != KERN_SUCCESS || copied != sizeof(header)) {
            fprintf(stderr,
                    "debugger-base walk stopped index=%u address=%#llx "
                    "kr=%d copied=%#llx\n",
                    i, address, kr, copied);
            break;
        }
        if (header.magic != MH_MAGIC_64) continue;
        fprintf(stderr,
                "debugger-base candidate index=%u address=%#llx "
                "filetype=%#x\n",
                i, address, header.filetype);
        if (header.filetype == MH_FILESET) {
            *base = address;
            return 0;
        }
        if (header.filetype == MH_EXECUTE && fallback_execute == 0) {
            fallback_execute = address;
        }
    }
    if (fallback_execute != 0) {
        *base = fallback_execute;
        return 0;
    }
    return ENOENT;
}

static int handle_client(int client, mach_port_t kernel_task, uint64_t base)
{
    unsigned char payload[CND_LAB_KRW_MAX_TRANSFER];
    mach_port_t remote_task = MACH_PORT_NULL;
    thread_act_t remote_thread = MACH_PORT_NULL;
    int result = 0;
    for (;;) {
        CNDLabKRWRequest request = {0};
        result = transfer_all(client, &request, sizeof(request), 0);
        if (result != 0) return result;
        int has_payload = request.operation == CNDLabKRWOperationWrite ||
            request.operation == CNDLabKRWOperationResolvePID ||
            request.operation == CNDLabKRWOperationTaskWrite ||
            request.operation == CNDLabKRWOperationTaskThreadStart ||
            request.operation == CNDLabKRWOperationKernelCall;
        int returns_payload = request.operation == CNDLabKRWOperationRead ||
            request.operation == CNDLabKRWOperationTaskRead;
        if (request.magic != CND_LAB_KRW_MAGIC ||
            request.version != CND_LAB_KRW_VERSION ||
            request.length > CND_LAB_TASK_REGION_MAX ||
            ((has_payload || returns_payload) &&
             request.length > CND_LAB_KRW_MAX_TRANSFER)) {
            (void)send_response(client, EPROTO, 0, 0);
            return EPROTO;
        }

        if (has_payload && request.length > 0) {
            result = transfer_all(client, payload, request.length, 0);
            if (result != 0) goto finish;
        }

        if (request.operation == CNDLabKRWOperationCapabilities) {
            uint64_t capabilities = geteuid() == 0
                ? CNDLabKRWCapabilityProcessResolve : 0;
            if (MACH_PORT_VALID(kernel_task)) {
                capabilities |= CNDLabKRWCapabilityDirectTask;
            }
            if ((g_libkrw_read && g_libkrw_write && base != 0) ||
                (MACH_PORT_VALID(kernel_task) && base != 0)) {
                capabilities |= CNDLabKRWCapabilityKernelReadWrite;
            }
            if (active_kernel_call() && base != 0) {
                capabilities |= CNDLabKRWCapabilityKernelCall;
            }
            result = send_response(client, capabilities ? 0 : ENOTSUP, 0,
                                   capabilities);
        } else if (request.operation == CNDLabKRWOperationKBase) {
            result = send_response(client, base ? 0 : ENOTSUP, 0, base);
        } else if (request.operation == CNDLabKRWOperationRead) {
            int status = EIO;
            if (g_libkrw_read) {
                status = g_libkrw_read(
                    request.address, payload, request.length) == 0
                    ? 0 : EIO;
            } else if (MACH_PORT_VALID(kernel_task)) {
                mach_vm_size_t copied = 0;
                kern_return_t kr = mach_vm_read_overwrite(
                    kernel_task, request.address, request.length,
                    (mach_vm_address_t)payload, &copied);
                status = kr == KERN_SUCCESS && copied == request.length
                    ? 0 : EIO;
            }
            result = send_response(client, status,
                                   status == 0 ? request.length : 0, 0);
            if (result == 0 && status == 0) {
                result = transfer_all(client, payload, request.length, 1);
            }
        } else if (request.operation == CNDLabKRWOperationWrite) {
            int status = EIO;
            if (g_libkrw_write) {
                status = g_libkrw_write(
                    payload, request.address, request.length) == 0
                    ? 0 : EIO;
            } else if (MACH_PORT_VALID(kernel_task)) {
                kern_return_t kr = mach_vm_write(
                    kernel_task, request.address, (mach_vm_address_t)payload,
                    request.length);
                status = kr == KERN_SUCCESS ? 0 : EIO;
            }
            result = send_response(client, status, 0, 0);
        } else if (request.operation == CNDLabKRWOperationKernelCall) {
            int status = ENOTSUP;
            uint64_t call_result = 0;
            if (request.address != 0 ||
                request.length != sizeof(CNDLabKernelCallRequest)) {
                status = EINVAL;
            } else {
                CNDLabKernelCallRequest call = {0};
                memcpy(&call, payload, sizeof(call));
                if (call.version != CND_LAB_KCALL_ABI_VERSION ||
                    call.argument_count > CND_LAB_KCALL_MAX_ARGUMENTS ||
                    !kernel_call_target_valid(base, call.function)) {
                    status = EINVAL;
                } else if (active_kernel_call()) {
                    if (!g_libkrw_kcall &&
                        call.argument_count >
                            CND_VPHONE_KCALL_MAX_ARGUMENTS) {
                        status = E2BIG;
                    } else {
                        status = active_kernel_call()(
                            call.function, call.argument_count,
                            call.arguments, &call_result);
                    }
                }
            }
            result = send_response(client, status, 0,
                                   status == 0 ? call_result : 0);
        } else if (request.operation == CNDLabKRWOperationResolvePID) {
            int status = ESRCH;
            pid_t found_pid = 0;
            if (request.length > 1 && request.length <= 32 &&
                payload[request.length - 1] == '\0') {
                int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
                size_t process_bytes = 0;
                if (sysctl(mib, 3, NULL, &process_bytes, NULL, 0) == 0 &&
                    process_bytes >= sizeof(struct kinfo_proc)) {
                    struct kinfo_proc *processes = malloc(process_bytes);
                    if (processes &&
                        sysctl(mib, 3, processes, &process_bytes, NULL, 0) == 0) {
                        size_t count = process_bytes / sizeof(*processes);
                        for (size_t i = 0; i < count; i++) {
                            if (process_name_matches(
                                    &processes[i],
                                    (const char *)payload)) {
                                if (found_pid != 0) {
                                    found_pid = 0;
                                    status = EEXIST;
                                    break;
                                }
                                found_pid = processes[i].kp_proc.p_pid;
                                status = 0;
                            }
                        }
                    } else if (!processes) {
                        status = ENOMEM;
                    }
                    free(processes);
                }
            } else {
                status = EINVAL;
            }
            result = send_response(client, status, 0,
                                   status == 0 ? (uint64_t)found_pid : 0);
        } else if (request.operation == CNDLabKRWOperationTaskOpen) {
            int status = EINVAL;
            mach_port_t candidate = MACH_PORT_NULL;
            pid_t pid = (pid_t)request.address;
            if (request.length == 0 && pid > 1) {
                kern_return_t kr = task_for_pid(
                    mach_task_self(), pid, &candidate);
                pid_t observed_pid = 0;
                if (kr == KERN_SUCCESS && MACH_PORT_VALID(candidate)) {
                    kr = pid_for_task(candidate, &observed_pid);
                }
                status = kr == KERN_SUCCESS && observed_pid == pid
                    ? 0 : (int)(kr ?: KERN_FAILURE);
            }
            if (status == 0) {
                if (MACH_PORT_VALID(remote_task)) {
                    mach_port_deallocate(mach_task_self(), remote_task);
                }
                remote_task = candidate;
            } else if (MACH_PORT_VALID(candidate)) {
                mach_port_deallocate(mach_task_self(), candidate);
            }
            result = send_response(client, status, 0, 0);
        } else if (request.operation == CNDLabKRWOperationTaskAllocate) {
            mach_vm_address_t address = 0;
            kern_return_t kr = MACH_PORT_VALID(remote_task) &&
                request.length > 0
                ? mach_vm_allocate(remote_task, &address, request.length,
                                   VM_FLAGS_ANYWHERE)
                : KERN_INVALID_TASK;
            result = send_response(client, kr, 0,
                                   kr == KERN_SUCCESS ? address : 0);
        } else if (request.operation == CNDLabKRWOperationTaskRead) {
            mach_vm_size_t copied = 0;
            kern_return_t kr = MACH_PORT_VALID(remote_task) &&
                request.length > 0
                ? mach_vm_read_overwrite(
                    remote_task, request.address, request.length,
                    (mach_vm_address_t)payload, &copied)
                : KERN_INVALID_TASK;
            int status = kr == KERN_SUCCESS && copied == request.length
                ? 0 : (int)(kr ?: KERN_FAILURE);
            result = send_response(client, status,
                                   status == 0 ? request.length : 0, 0);
            if (result == 0 && status == 0) {
                result = transfer_all(client, payload, request.length, 1);
            }
        } else if (request.operation == CNDLabKRWOperationTaskWrite) {
            kern_return_t kr = MACH_PORT_VALID(remote_task) &&
                request.length > 0
                ? mach_vm_write(remote_task, request.address,
                                (mach_vm_address_t)payload, request.length)
                : KERN_INVALID_TASK;
            result = send_response(client, kr, 0, 0);
        } else if (request.operation == CNDLabKRWOperationTaskDeallocate) {
            kern_return_t kr = MACH_PORT_VALID(remote_task) &&
                request.length > 0
                ? mach_vm_deallocate(remote_task, request.address,
                                     request.length)
                : KERN_INVALID_TASK;
            result = send_response(client, kr, 0, 0);
        } else if (request.operation == CNDLabKRWOperationTaskClose) {
            int status = 0;
            if (MACH_PORT_VALID(remote_thread)) {
                (void)thread_terminate(remote_thread);
                /*
                 * On the vPhone host bridge, terminating a raw task thread can
                 * synchronously invalidate the returned thread name.  A
                 * subsequent mach_port_deallocate() is therefore not merely a
                 * harmless KERN_INVALID_NAME: the guarded port trap terminates
                 * this provider.  Treat thread_terminate() as consuming the
                 * temporary name here.  The provider owns no usable right once
                 * the call returns, and the target thread is already gone.
                 */
                remote_thread = MACH_PORT_NULL;
            }
            if (MACH_PORT_VALID(remote_task)) {
                status = mach_port_deallocate(
                    mach_task_self(), remote_task);
                remote_task = MACH_PORT_NULL;
            }
            result = send_response(client, status, 0, 0);
        } else if (request.operation == CNDLabKRWOperationTaskProtectRX) {
            kern_return_t kr = MACH_PORT_VALID(remote_task) &&
                request.length > 0
                ? mach_vm_protect(remote_task, request.address,
                                  request.length, FALSE,
                                  VM_PROT_READ | VM_PROT_EXECUTE)
                : KERN_INVALID_TASK;
            result = send_response(client, kr, 0, 0);
        } else if (request.operation == CNDLabKRWOperationTaskCacheFlush) {
            vm_machine_attribute_val_t value = MATTR_VAL_CACHE_FLUSH;
            kern_return_t kr = MACH_PORT_VALID(remote_task) &&
                request.length > 0
                ? mach_vm_machine_attribute(
                    remote_task, request.address, request.length,
                    MATTR_CACHE, &value)
                : KERN_INVALID_TASK;
            result = send_response(client, kr, 0, 0);
        } else if (request.operation == CNDLabKRWOperationTaskThreadStart) {
            kern_return_t kr = KERN_INVALID_ARGUMENT;
            if (MACH_PORT_VALID(remote_task) &&
                request.length == sizeof(CNDLabTaskThreadStartRequest)) {
                CNDLabTaskThreadStartRequest start = {0};
                memcpy(&start, payload, sizeof(start));
                arm_thread_state64_t state = {0};
#if __DARWIN_OPAQUE_ARM_THREAD_STATE64
#if __has_feature(ptrauth_calls)
                /* thread_create_running() consumes process-independent
                 * authenticated thread-state pointers on arm64e. Supplying
                 * raw values under NO_PTRAUTH lets the kernel return a
                 * signed-looking PC that faults as soon as a foreground
                 * target actually executes it. */
                void *signed_pc = ptrauth_sign_unauthenticated(
                    (void *)(uintptr_t)start.entry_point,
                    ptrauth_key_process_independent_code,
                    ptrauth_string_discriminator("pc"));
                arm_thread_state64_set_pc_presigned_fptr(state, signed_pc);
                arm_thread_state64_set_sp(state, start.stack_pointer);
#else
                state.__opaque_pc = (void *)(uintptr_t)start.entry_point;
                state.__opaque_sp = (void *)(uintptr_t)start.stack_pointer;
                state.__opaque_flags =
                    __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH;
#endif
#else
                state.__pc = start.entry_point;
                state.__sp = start.stack_pointer;
#endif
                if (MACH_PORT_VALID(remote_thread)) {
                    (void)thread_terminate(remote_thread);
                    remote_thread = MACH_PORT_NULL;
                }
                kr = thread_create_running(
                    remote_task, ARM_THREAD_STATE64,
                    (thread_state_t)&state, ARM_THREAD_STATE64_COUNT,
                    &remote_thread);
                if (kr == KERN_SUCCESS && MACH_PORT_VALID(remote_thread)) {
                    /* Lab-only evidence for failures before the copied
                     * bootstrap can publish its first state transition. */
                    usleep(10000);
                    thread_basic_info_data_t basic = {0};
                    mach_msg_type_number_t basic_count =
                        THREAD_BASIC_INFO_COUNT;
                    kern_return_t basic_kr = thread_info(
                        remote_thread, THREAD_BASIC_INFO,
                        (thread_info_t)&basic, &basic_count);
                    kern_return_t resume_kr = KERN_NOT_SUPPORTED;
                    if (basic_kr == KERN_SUCCESS &&
                        basic.suspend_count > 0) {
                        resume_kr = thread_resume(remote_thread);
                        usleep(10000);
                    }
                    arm_thread_state64_t observed = {0};
                    mach_msg_type_number_t observed_count =
                        ARM_THREAD_STATE64_COUNT;
                    kern_return_t state_kr = thread_get_state(
                        remote_thread, ARM_THREAD_STATE64,
                        (thread_state_t)&observed, &observed_count);
#if __DARWIN_OPAQUE_ARM_THREAD_STATE64
                    uint64_t observed_pc =
                        (uint64_t)(uintptr_t)observed.__opaque_pc;
                    uint64_t observed_sp =
                        (uint64_t)(uintptr_t)observed.__opaque_sp;
#else
                    uint64_t observed_pc = observed.__pc;
                    uint64_t observed_sp = observed.__sp;
#endif
                    fprintf(stderr,
                            "task-thread-start kr=%d basic-kr=%d "
                            "run=%d suspend=%d flags=0x%x resume=%d "
                            "state-kr=%d entry=0x%llx pc=0x%llx "
                            "sp=0x%llx\n",
                            kr, basic_kr, basic.run_state,
                            basic.suspend_count, basic.flags, resume_kr,
                            state_kr,
                            (unsigned long long)start.entry_point,
                            (unsigned long long)observed_pc,
                            (unsigned long long)observed_sp);
                    fflush(stderr);
                }
            }
            result = send_response(client, kr, 0,
                                   kr == KERN_SUCCESS ? 1 : 0);
        } else if (request.operation ==
                   CNDLabKRWOperationTaskThreadTerminate) {
            kern_return_t kr = KERN_SUCCESS;
            if (MACH_PORT_VALID(remote_thread)) {
                kr = thread_terminate(remote_thread);
                remote_thread = MACH_PORT_NULL;
            }
            result = send_response(client, kr, 0, 0);
        } else {
            result = send_response(client, ENOTSUP, 0, 0);
        }
        if (result != 0) goto finish;
    }

finish:
    if (MACH_PORT_VALID(remote_thread)) {
        (void)thread_terminate(remote_thread);
    }
    if (MACH_PORT_VALID(remote_task)) {
        mach_port_deallocate(mach_task_self(), remote_task);
    }
    return result;
}

static mach_port_t acquire_kernel_task(void)
{
    mach_port_t kernel_task = MACH_PORT_NULL;
    kern_return_t kr = host_get_special_port(
        mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task);
    if (kr == KERN_SUCCESS && MACH_PORT_VALID(kernel_task)) {
        return kernel_task;
    }

    kernel_task = MACH_PORT_NULL;
    kr = task_for_pid(mach_task_self(), 0, &kernel_task);
    return kr == KERN_SUCCESS && MACH_PORT_VALID(kernel_task)
        ? kernel_task : MACH_PORT_NULL;
}

int main(int argc, char **argv)
{
    g_vphone_kcall_syscall = vphone_kcall_syscall_available();
    fprintf(stderr, "vphone kcall syscall=%s\n",
            g_vphone_kcall_syscall ? "available" : "unavailable");
    mach_port_t kernel_task = acquire_kernel_task();
    const char *socket_path = argc >= 3
        ? argv[2] : CND_LAB_KRW_SOCKET_PATH;

    uint64_t base = 0;
    const char *base_source = "unknown";
    int base_result = ENOENT;
    if (argc >= 2 && strcmp(argv[1], "auto") == 0 &&
        MACH_PORT_VALID(kernel_task)) {
        base_result = kernel_base(kernel_task, &base, &base_source);
    } else if (argc >= 2 && MACH_PORT_VALID(kernel_task)) {
        char *end = NULL;
        errno = 0;
        uint64_t supplied = strtoull(argv[1], &end, 0);
        if (errno == 0 && end && *end == '\0' &&
            (supplied & 0x3fffULL) == 0 &&
            (supplied & 0xffff000000000000ULL) ==
                0xffff000000000000ULL) {
            base_result = resolve_debugger_base(
                kernel_task, supplied, &base);
            if (base_result == 0) {
                base_source = "host-debug-pc-header-walk";
            } else {
                fprintf(stderr,
                        "supplied debugger base did not resolve a kernel "
                        "Mach-O header base=%#llx\n", supplied);
            }
        } else {
            fprintf(stderr,
                    "supplied kernel base is malformed base=%#llx\n",
                    supplied);
        }
    } else if (MACH_PORT_VALID(kernel_task)) {
        base_result = kernel_base(kernel_task, &base, &base_source);
    }
    if (base_result != 0) {
        base_result = activate_libkrw(&base, &base_source);
    }
    if (base_result != 0) {
        if (geteuid() != 0) {
            fprintf(stderr,
                    "kernel provider lookup failed and the bounded root lab "
                    "provider requires root: task=%#x result=%d\n",
                    kernel_task, base_result);
            return 2;
        }
        base = 0;
        base_source = "root-process-resolver";
        fprintf(stderr,
                "kernel read/write unavailable; continuing with bounded "
                "root process-resolution capability: task=%#x result=%d\n",
                kernel_task, base_result);
    }

    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) {
        perror("socket");
        return 3;
    }
    (void)unlink(socket_path);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (strlen(socket_path) >= sizeof(address.sun_path)) return 4;
    strcpy(address.sun_path, socket_path);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(socket_path, 0666) != 0 || listen(server, 2) != 0) {
        perror("bind/listen");
        return 5;
    }

    uint64_t capabilities = CNDLabKRWCapabilityProcessResolve;
    if (MACH_PORT_VALID(kernel_task)) {
        capabilities |= CNDLabKRWCapabilityDirectTask;
    }
    if ((g_libkrw_read && g_libkrw_write && base != 0) ||
        (MACH_PORT_VALID(kernel_task) && base != 0)) {
        capabilities |= CNDLabKRWCapabilityKernelReadWrite;
    }
    if (active_kernel_call() && base != 0) {
        capabilities |= CNDLabKRWCapabilityKernelCall;
    }
    FILE *marker = fopen(CND_LAB_KRW_MARKER_PATH, "w");
    if (!marker) return 6;
    fprintf(marker,
            "version=1\npid=%d\nsocket=%s\nargument=%s\n"
            "capabilities=%#llx\n",
            getpid(), socket_path, argc >= 2 ? argv[1] : "auto",
            capabilities);
    fclose(marker);

    printf("ready socket=%s kernelTask=%#x base=%#llx source=%s "
           "capabilities=%#llx\n", socket_path, kernel_task, base,
           base_source, capabilities);
    fflush(stdout);
    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            return 7;
        }
        int result = handle_client(client, kernel_task, base);
        close(client);
        if (result != ECONNRESET && result != EPIPE) {
            fprintf(stderr, "client ended: %d\n", result);
            fflush(stderr);
        }
    }
}
