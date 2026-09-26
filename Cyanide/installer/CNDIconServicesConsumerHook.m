#import "CNDIconServicesConsumerHook.h"
#import "CNDIconServicesConsumerPayload.h"
#import "CNDIconServicesStructuredPayload.h"
#import "../LogTextView.h"
#import "../TaskRop/RemoteCall.h"
#import "../kexploit/CNDLabKernelProvider.h"
#import "../kexploit/krw.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/kutils.h"
#import "../kexploit/offsets.h"
#import "../tweaks/remote_objc.h"
#import "../tweaks/themer.h"

#import <dlfcn.h>
#import <fcntl.h>
#import <mach-o/fat.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>
#import <signal.h>
#import <stdio.h>
#import <string.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <unistd.h>

static NSString * const CNDConsumerHookJournalKey =
    @"CNDIconServicesConsumerHookMappingsV1";

/*
 * Physical-device presentation experiment.
 *
 * This is the single process-wide instruction proven by the resident VM
 * dylib.  It is deliberately narrower than the four Objective-C consumer
 * hooks below: every icon rendered by this exact IconRendering build gets a
 * hidden chiclet until the consumer exits.  The UUID, original instruction,
 * executable segment, and exact readback are all gates; an OS update fails
 * closed instead of applying an offset to a different binary.
 */
static const uint64_t CNDConsumerChicletPatchVMAddress = 0x1b0d5065cULL;
static const uint32_t CNDConsumerChicletOriginalInstruction = 0x52800028U;
static const uint32_t CNDConsumerChicletPatchedInstruction = 0x52800008U;
static const uint8_t CNDConsumerIconRenderingUUID[16] = {
    0x81, 0xcb, 0x5b, 0xe9, 0xb5, 0xda, 0x35, 0x51,
    0x90, 0xfd, 0x90, 0xd6, 0xe1, 0x8d, 0x56, 0x9a,
};

enum {
    CNDConsumerPTTraceMe = 0,
    CNDConsumerPTDetach = 11,
    CNDConsumerCSOpsStatus = 0,
};

static const uint32_t CNDConsumerCSDebugged = 0x10000000U;

// These linker-synthesized symbols are live, ASLR-adjusted addresses.  Using
// them keeps the payload symbols and section base in the same address space;
// getsectiondata() can instead return an unslid section vmaddr for the main PIE
// image on the vPhone runtime.
extern const uint8_t cnd_consumer_payload_section_start[]
    __asm("section$start$__TEXT$__cndhook");
extern const uint8_t cnd_consumer_payload_section_end[]
    __asm("section$end$__TEXT$__cndhook");
extern const struct mach_header_64 _mh_execute_header;

typedef struct {
    uint64_t classObject;
    uint64_t selector;
    uint64_t method;
    uint64_t implementation;
    uint64_t payloadOffset;
    const char *className;
    const char *selectorName;
    const char *expectedTypes;
} CNDConsumerHookMethod;

static uint64_t cnd_consumer_strip_code_pointer(uint64_t value)
{
    /* arm64e PAC may occupy bit 47 as well as the upper sixteen bits.  User
     * executable mappings on the supported targets are canonical low-half
     * addresses, so compare the low 47 address bits rather than retaining a
     * signature bit and spuriously rejecting a correctly installed IMP. */
    return value & 0x00007fffffffffffULL;
}

static void cnd_consumer_reason(CNDIconServicesConsumerHookReport *report,
                                const char *reason)
{
    if (!report) return;
    snprintf(report->reason, sizeof(report->reason), "%s", reason ?: "");
}

static uint64_t cnd_consumer_remote_symbol(const char *name)
{
    uint64_t remoteName = r_alloc_str(name);
    if (!remoteName) return 0;
    uint64_t address = r_dlsym_call(
        R_TIMEOUT, "dlsym", (uint64_t)(intptr_t)-2, remoteName,
        0, 0, 0, 0, 0, 0);
    r_free(remoteName);
    return address;
}

static bool cnd_consumer_load_remote_framework(const char *path)
{
    uint64_t remotePath = r_alloc_str(path);
    if (!remotePath) return false;
    uint64_t handle = r_dlsym_call(
        R_TIMEOUT, "dlopen", remotePath, RTLD_NOW | RTLD_LOCAL,
        0, 0, 0, 0, 0, 0);
    r_free(remotePath);
    return handle != 0 && remote_call_current_success();
}

static bool cnd_consumer_local_payload(
    const uint8_t **bytesOut, size_t *lengthOut,
    size_t *contextOffsetOut, CNDConsumerHookMethod methods[4],
    size_t *probeOffsetOut, size_t *installMethodOffsetOut,
    char *diagnostic, size_t diagnosticLength)
{
    if (bytesOut) *bytesOut = NULL;
    if (lengthOut) *lengthOut = 0;
    const uint8_t *section = cnd_consumer_payload_section_start;
    const uint8_t *sectionEnd = cnd_consumer_payload_section_end;
    size_t sectionLength = sectionEnd > section
        ? (size_t)(sectionEnd - section)
        : 0;
    if (!section || sectionLength == 0 || sectionLength > (64U << 10)) {
        if (diagnostic && diagnosticLength) {
            snprintf(diagnostic, diagnosticLength,
                "payload-section-invalid:start=%p:end=%p:length=%zu",
                section, sectionEnd, sectionLength);
        }
        return false;
    }

#define CND_OFFSET(symbol) ((size_t)((const uint8_t *)(symbol) - section))
    size_t contextOffset = CND_OFFSET(cnd_icon_consumer_payload_context);
    size_t probeOffset = CND_OFFSET(cnd_icon_consumer_payload_probe);
    size_t installMethodOffset =
        CND_OFFSET(cnd_icon_consumer_payload_install_method);
    size_t offsets[4] = {
        CND_OFFSET(cnd_icon_consumer_payload_init_serialized),
        CND_OFFSET(cnd_icon_consumer_payload_init_data),
        CND_OFFSET(cnd_icon_consumer_payload_init_finalized),
        CND_OFFSET(cnd_icon_consumer_payload_layout),
    };
#undef CND_OFFSET
    if (contextOffset + sizeof(CNDIconServicesConsumerPayloadContext) >
            sectionLength ||
        contextOffset + CND_ICON_CONSUMER_PAYLOAD_CONTEXT_CAPACITY >
            sectionLength ||
        probeOffset + 8 > sectionLength ||
        installMethodOffset + 8 > sectionLength) {
        if (diagnostic && diagnosticLength) {
            snprintf(diagnostic, diagnosticLength,
                "payload-bounds-invalid:length=%zu:context=%zu/%zu:probe=%zu",
                sectionLength, contextOffset,
                sizeof(CNDIconServicesConsumerPayloadContext), probeOffset);
        }
        return false;
    }
    for (NSUInteger index = 0; index < 4; index++) {
        if (offsets[index] + 8 > sectionLength ||
            offsets[index] >= contextOffset) {
            if (diagnostic && diagnosticLength) {
                snprintf(diagnostic, diagnosticLength,
                    "payload-method-bounds-invalid:index=%lu:offset=%zu:length=%zu",
                    (unsigned long)index, offsets[index], sectionLength);
            }
            return false;
        }
        methods[index].payloadOffset = offsets[index];
    }
    if (probeOffset >= contextOffset ||
        installMethodOffset >= contextOffset) {
        if (diagnostic && diagnosticLength) {
            snprintf(diagnostic, diagnosticLength,
                "payload-code-crosses-context:probe=%zu:install=%zu:context=%zu",
                probeOffset, installMethodOffset, contextOffset);
        }
        return false;
    }
    if (bytesOut) *bytesOut = section;
    if (lengthOut) *lengthOut = (size_t)sectionLength;
    if (contextOffsetOut) *contextOffsetOut = contextOffset;
    if (probeOffsetOut) *probeOffsetOut = probeOffset;
    if (installMethodOffsetOut) {
        *installMethodOffsetOut = installMethodOffset;
    }
    if (diagnostic && diagnosticLength) diagnostic[0] = '\0';
    return true;
}

static bool cnd_consumer_prefault_remote_write_range(
    uint64_t address, uint64_t length)
{
    if (!address || !length || !remote_call_current_success()) return false;
    if (remote_call_uses_lab_backend()) return true;
    return r_dlsym_call(
        R_TIMEOUT, "memset", address, 0, length,
        0, 0, 0, 0, 0) == address && remote_call_current_success();
}

static int cnd_consumer_remote_errno(void)
{
    uint64_t address = r_dlsym_call(
        R_TIMEOUT, "__error", 0, 0, 0, 0, 0, 0, 0, 0);
    int value = 0;
    return address && remote_read(address, &value, sizeof(value))
        ? value : 0;
}

/* Resolve the exact running thin slice and the page-aligned __cndhook file
 * range. The target maps these signed vnode pages RX; only the adjacent
 * context page remains anonymous RW. */
static bool cnd_consumer_resolve_payload_vnode(
    const uint8_t *payload, size_t payloadLength, uint64_t pageSize,
    size_t contextOffset, NSString **pathOut, uint64_t *sliceOffsetOut,
    uint64_t *fileOffsetOut, NSString **failureOut)
{
    if (pathOut) *pathOut = nil;
    if (sliceOffsetOut) *sliceOffsetOut = 0;
    if (fileOffsetOut) *fileOffsetOut = 0;
    if (failureOut) *failureOut = nil;
    if (!payload || !payloadLength || !pageSize || !contextOffset ||
        !pathOut || !sliceOffsetOut || !fileOffsetOut ||
        (uintptr_t)payload % pageSize || contextOffset % pageSize ||
        contextOffset >= payloadLength) {
        if (failureOut) *failureOut = @"consumer-vnode-layout";
        return false;
    }

    const struct mach_header_64 *header = &_mh_execute_header;
    if (header->magic != MH_MAGIC_64 || !header->ncmds ||
        !header->sizeofcmds) {
        if (failureOut) *failureOut = @"consumer-vnode-mach-header";
        return false;
    }
    const struct segment_command_64 *textSegment = NULL;
    const struct section_64 *payloadSection = NULL;
    const uint8_t *commandBytes = (const uint8_t *)(header + 1);
    const uint8_t *commandsEnd = commandBytes + header->sizeofcmds;
    for (uint32_t commandIndex = 0;
         commandIndex < header->ncmds; commandIndex++) {
        if (commandBytes + sizeof(struct load_command) > commandsEnd) break;
        const struct load_command *command =
            (const struct load_command *)commandBytes;
        if (command->cmdsize < sizeof(*command) ||
            commandBytes + command->cmdsize > commandsEnd) break;
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, "__TEXT", 16) == 0) {
                textSegment = segment;
                const struct section_64 *sections =
                    (const struct section_64 *)(segment + 1);
                uint64_t required = sizeof(*segment) +
                    (uint64_t)segment->nsects * sizeof(*sections);
                if (required <= segment->cmdsize) {
                    for (uint32_t sectionIndex = 0;
                         sectionIndex < segment->nsects; sectionIndex++) {
                        if (strncmp(sections[sectionIndex].sectname,
                                    "__cndhook", 16) == 0 &&
                            strncmp(sections[sectionIndex].segname,
                                    "__TEXT", 16) == 0) {
                            payloadSection = &sections[sectionIndex];
                            break;
                        }
                    }
                }
            }
        }
        commandBytes += command->cmdsize;
    }

    NSString *path = NSBundle.mainBundle.executablePath;
    struct stat status = {0};
    uint64_t slide = textSegment && textSegment->fileoff == 0 &&
        (uint64_t)(uintptr_t)header >= textSegment->vmaddr
        ? (uint64_t)(uintptr_t)header - textSegment->vmaddr : UINT64_MAX;
    uint64_t runtimeSection = payloadSection && slide != UINT64_MAX
        ? payloadSection->addr + slide : 0;
    bool regular = path.length > 0 &&
        lstat(path.fileSystemRepresentation, &status) == 0 &&
        S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode);

    uint64_t sliceOffset = 0;
    bool sliceFound = false;
    int localFD = regular
        ? open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC) : -1;
    uint8_t fatHeader[8] = {0};
    ssize_t headerRead = localFD >= 0
        ? pread(localFD, fatHeader, sizeof(fatHeader), 0) : -1;
    uint32_t rawMagic = 0;
    if (headerRead == sizeof(fatHeader)) {
        memcpy(&rawMagic, fatHeader, sizeof(rawMagic));
    }
    uint32_t bigMagic = ((uint32_t)fatHeader[0] << 24) |
        ((uint32_t)fatHeader[1] << 16) |
        ((uint32_t)fatHeader[2] << 8) | (uint32_t)fatHeader[3];
    if (headerRead == sizeof(fatHeader) &&
        (rawMagic == MH_MAGIC_64 || rawMagic == MH_CIGAM_64)) {
        sliceFound = true;
    } else if (headerRead == sizeof(fatHeader) &&
               (bigMagic == FAT_MAGIC || bigMagic == FAT_MAGIC_64)) {
        uint32_t count = ((uint32_t)fatHeader[4] << 24) |
            ((uint32_t)fatHeader[5] << 16) |
            ((uint32_t)fatHeader[6] << 8) | (uint32_t)fatHeader[7];
        size_t entrySize = bigMagic == FAT_MAGIC_64 ? 32U : 20U;
        if (count > 0 && count <= 32) {
            for (uint32_t index = 0; index < count; index++) {
                uint8_t entry[32] = {0};
                off_t entryOffset = (off_t)sizeof(fatHeader) +
                    (off_t)index * (off_t)entrySize;
                if (pread(localFD, entry, entrySize, entryOffset) !=
                    (ssize_t)entrySize) break;
                uint32_t cpuType = ((uint32_t)entry[0] << 24) |
                    ((uint32_t)entry[1] << 16) |
                    ((uint32_t)entry[2] << 8) | (uint32_t)entry[3];
                uint32_t cpuSubtype = ((uint32_t)entry[4] << 24) |
                    ((uint32_t)entry[5] << 16) |
                    ((uint32_t)entry[6] << 8) | (uint32_t)entry[7];
                uint64_t candidateOffset = 0;
                if (bigMagic == FAT_MAGIC_64) {
                    for (NSUInteger byte = 0; byte < 8; byte++) {
                        candidateOffset = (candidateOffset << 8) |
                            entry[8 + byte];
                    }
                } else {
                    candidateOffset = ((uint32_t)entry[8] << 24) |
                        ((uint32_t)entry[9] << 16) |
                        ((uint32_t)entry[10] << 8) |
                        (uint32_t)entry[11];
                }
                uint32_t subtypeMask = ~((uint32_t)CPU_SUBTYPE_MASK);
                if (cpuType == (uint32_t)header->cputype &&
                    (cpuSubtype & subtypeMask) ==
                        ((uint32_t)header->cpusubtype & subtypeMask)) {
                    sliceOffset = candidateOffset;
                    sliceFound = true;
                    break;
                }
            }
        }
    }
    if (localFD >= 0) close(localFD);

    uint64_t absoluteFileOffset = payloadSection
        ? sliceOffset + payloadSection->offset : 0;
    bool exact = textSegment && payloadSection && regular && sliceFound &&
        runtimeSection == (uint64_t)(uintptr_t)payload &&
        payloadSection->size == payloadLength &&
        sliceOffset % pageSize == 0 &&
        absoluteFileOffset % pageSize == 0 &&
        absoluteFileOffset <= (uint64_t)status.st_size &&
        contextOffset <=
            (uint64_t)status.st_size - absoluteFileOffset;
    if (!exact) {
        if (failureOut) {
            *failureOut = @"consumer-vnode-section-validation";
        }
        return false;
    }
    *pathOut = path;
    *sliceOffsetOut = sliceOffset;
    *fileOffsetOut = absoluteFileOffset;
    return true;
}

static bool cnd_consumer_map_physical_payload(
    const uint8_t *payload, size_t payloadLength, uint64_t pageSize,
    size_t contextOffset, CNDIconServicesConsumerPayloadContext *context,
    uint64_t *remoteBaseOut, uint64_t *mappingLengthOut,
    bool *libraryValidationAcceptedOut,
    bool *libraryValidationPolicyFallbackUsedOut,
    int *libraryValidationErrnoOut,
    char *diagnostic, size_t diagnosticLength)
{
    if (remoteBaseOut) *remoteBaseOut = 0;
    if (mappingLengthOut) *mappingLengthOut = 0;
    if (libraryValidationAcceptedOut) {
        *libraryValidationAcceptedOut = false;
    }
    if (libraryValidationPolicyFallbackUsedOut) {
        *libraryValidationPolicyFallbackUsedOut = false;
    }
    if (libraryValidationErrnoOut) *libraryValidationErrnoOut = 0;
    if (!payload || !payloadLength || !pageSize || !context ||
        !remoteBaseOut || !mappingLengthOut ||
        (uintptr_t)payload % pageSize || contextOffset % pageSize ||
        contextOffset >= payloadLength) {
        if (diagnostic && diagnosticLength) {
            snprintf(diagnostic, diagnosticLength,
                     "consumer-vnode-map-layout");
        }
        return false;
    }

    NSString *path = nil;
    NSString *failure = nil;
    uint64_t sliceOffset = 0, fileOffset = 0;
    if (!cnd_consumer_resolve_payload_vnode(
            payload, payloadLength, pageSize, contextOffset,
            &path, &sliceOffset, &fileOffset, &failure)) {
        if (diagnostic && diagnosticLength) {
            snprintf(diagnostic, diagnosticLength, "%s",
                     failure.UTF8String ?: "consumer-vnode-resolution");
        }
        return false;
    }

    uint64_t mappingLength =
        (payloadLength + pageSize - 1) & ~(pageSize - 1);
    uint64_t remoteBase = r_dlsym_call(
        R_TIMEOUT, "mmap", 0, mappingLength,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
        (uint64_t)-1, 0, 0, 0);
    bool allocationLive = remoteBase && remoteBase != UINT64_MAX &&
        remote_call_current_success();
    uint64_t remotePath = allocationLive
        ? r_alloc_str(path.fileSystemRepresentation) : 0;
    int64_t openResult = remotePath ? (int64_t)r_dlsym_call(
        R_TIMEOUT, "open", remotePath, O_RDONLY | O_CLOEXEC,
        0, 0, 0, 0, 0, 0) : -1;
    int openError = openResult < 0 ? cnd_consumer_remote_errno() : 0;
    /* Keep both F_CHECK_LV's input structure and its diagnostic output in the
     * anonymous mapping created in this exact target task. A null/zero-length
     * lv_error_message works when validation succeeds (as it did in
     * IconServicesAgent), but a platform consumer's policy rejection needs to
     * copy out an explanation. Supplying no destination turns that rejection
     * into EFAULT and hides the real policy errno. The context page remains RW
     * when the preceding code pages are replaced and is overwritten with the
     * actual payload context immediately afterward. */
    const size_t validationMessageCapacity = 512;
    const size_t validationMessageOffset =
        (sizeof(fchecklv_t) + 15U) & ~15U;
    const size_t validationStorageLength =
        validationMessageOffset + validationMessageCapacity;
    uint64_t checkAddress = openResult >= 0 &&
        mappingLength - contextOffset >= validationStorageLength
        ? remoteBase + contextOffset : 0;
    uint64_t validationMessageAddress = checkAddress
        ? checkAddress + validationMessageOffset : 0;
    fchecklv_t check = {
        .lv_file_start = (off_t)sliceOffset,
        .lv_error_message_size = validationMessageCapacity,
        .lv_error_message = (void *)(uintptr_t)validationMessageAddress,
    };
    bool validationMessageZeroed = validationMessageAddress &&
        r_dlsym_call(R_TIMEOUT, "memset", validationMessageAddress, 0,
                     validationMessageCapacity, 0, 0, 0, 0, 0) ==
            validationMessageAddress &&
        remote_call_current_success();
    bool checkWritten = validationMessageZeroed &&
        cnd_consumer_prefault_remote_write_range(
            checkAddress, sizeof(check)) &&
        remote_write(checkAddress, &check, sizeof(check));
    int64_t validationResult = checkWritten ? (int64_t)r_dlsym_call(
        R_TIMEOUT, "fcntl", (uint64_t)openResult, F_CHECK_LV,
        checkAddress, 0, 0, 0, 0, 0) : -1;
    int validationError = validationResult < 0
        ? cnd_consumer_remote_errno() : 0;
    char validationMessage[192] = {0};
    if (validationMessageAddress) {
        (void)remote_read(validationMessageAddress, validationMessage,
                          sizeof(validationMessage) - 1);
        validationMessage[sizeof(validationMessage) - 1] = '\0';
        for (size_t index = 0; index < sizeof(validationMessage) - 1 &&
             validationMessage[index]; index++) {
            unsigned char value = (unsigned char)validationMessage[index];
            if (value < 0x20 || value == 0x7f) {
                validationMessage[index] = ' ';
            }
        }
    }
    bool libraryValidated = validationResult == 0 &&
        remote_call_current_success();
    /*
     * F_CHECK_LV is dyld's library-combination policy check, not the vnode
     * executable-page integrity check. SpringBoard and Spotlight are Apple
     * platform processes, while this range belongs to Cyanide's development-
     * team main executable, so the combination is deliberately outside the
     * policy that F_CHECK_LV answers. On iOS 26 those consumers return an
     * opaque EFAULT before producing the documented diagnostic; limiting the
     * fallback to EPERM/EACCES therefore prevents the real integrity gate
     * from ever running.
     *
     * Keep F_CHECK_LV as an advisory diagnostic, but after a target-owned,
     * prefaulted argument was successfully written, let the exact fixed RX
     * mmap be authoritative for every LV rejection. The mapping names the
     * already-running Cyanide executable, exact thin-slice file offset and
     * exact signed __cndhook page range. A bad offset, signature, protection,
     * sandbox decision, or code-sign policy fails mmap before any hook IMP is
     * installed or executed. A RemoteCall/argument construction failure still
     * fails closed and never reaches mmap.
     */
    bool policyFallbackUsed = !libraryValidated && checkWritten &&
        remote_call_current_success();
    bool executableMapPermitted = libraryValidated || policyFallbackUsed;
    uint64_t mappedCode = executableMapPermitted ? r_dlsym_call(
        R_TIMEOUT, "mmap", remoteBase, contextOffset,
        PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED,
        (uint64_t)openResult, fileOffset, 0, 0) : UINT64_MAX;
    int mapError = executableMapPermitted && mappedCode == UINT64_MAX
        ? cnd_consumer_remote_errno() : 0;
    if (openResult >= 0 && remote_call_current_success()) {
        (void)r_dlsym_call(
            R_TIMEOUT, "close", (uint64_t)openResult,
            0, 0, 0, 0, 0, 0, 0);
    }
    if (remotePath && remote_call_current_success()) r_free(remotePath);
    bool codeMappingLive = allocationLive && mappedCode == remoteBase &&
        remote_call_current_success();

    if (libraryValidationAcceptedOut) {
        *libraryValidationAcceptedOut = libraryValidated;
    }
    if (libraryValidationPolicyFallbackUsedOut) {
        *libraryValidationPolicyFallbackUsedOut = policyFallbackUsed;
    }
    if (libraryValidationErrnoOut) {
        *libraryValidationErrnoOut = validationError;
    }

    context->remoteBase = remoteBase;
    uint64_t contextAddress = remoteBase + contextOffset;
    bool contextWritten = codeMappingLive &&
        cnd_consumer_prefault_remote_write_range(
            contextAddress, sizeof(*context)) &&
        remote_write(contextAddress, context, sizeof(*context));
    // Do not pull file-backed executable pages through the physical-device
    // shmem mapper. Merely mapping the signed vnode does not guarantee those
    // pages are resident; walking that VM object from Cyanide was observed to
    // fault through the kernel physical aperture and panic the device. The
    // mapping is instead established by exact local Mach-O offsets, target
    // F_CHECK_LV, an exact target mmap result, and the target-side execution
    // probe immediately following this helper.
    CNDIconServicesConsumerPayloadContext observed = {0};
    bool contextRead = contextWritten && remote_read(
        contextAddress, &observed, sizeof(observed));
    bool exact = codeMappingLive && contextWritten &&
        contextRead && remote_call_current_success() &&
        memcmp(&observed, context, sizeof(observed)) == 0;
    if (!exact && allocationLive && remote_call_current_success()) {
        (void)r_dlsym_call(
            R_TIMEOUT, "munmap", remoteBase, mappingLength,
            0, 0, 0, 0, 0, 0);
    }
    if (!exact) {
        if (diagnostic && diagnosticLength) {
            snprintf(diagnostic, diagnosticLength,
                     "consumer-vnode-map:open=%lld/%d:lv-arg=%#llx:lv-output=%#llx:lv-written=%d:lv=%lld/%d:lv-message=%s:lv-policy-fallback=%d:map=%#llx/%d:context=%d",
                     (long long)openResult, openError,
                     (unsigned long long)checkAddress,
                     (unsigned long long)validationMessageAddress,
                     checkWritten,
                     (long long)validationResult, validationError,
                     validationMessage[0] ? validationMessage : "-",
                     policyFallbackUsed,
                     (unsigned long long)mappedCode, mapError,
                     contextRead);
        }
        return false;
    }
    *remoteBaseOut = remoteBase;
    *mappingLengthOut = mappingLength;
    return true;
}

static bool cnd_consumer_prepare_method(CNDConsumerHookMethod *method)
{
    method->classObject = r_class(method->className);
    method->selector = r_sel(method->selectorName);
    method->method = method->classObject && method->selector
        ? r_dlsym_call(R_TIMEOUT, "class_getInstanceMethod",
                       method->classObject, method->selector,
                       0, 0, 0, 0, 0, 0)
        : 0;
    uint64_t types = method->method
        ? r_dlsym_call(R_TIMEOUT, "method_getTypeEncoding", method->method,
                       0, 0, 0, 0, 0, 0, 0)
        : 0;
    char actualTypes[96] = {0};
    bool typesMatch = types &&
        r_read_cstring(types, actualTypes, sizeof(actualTypes)) &&
        strcmp(actualTypes, method->expectedTypes) == 0;
    method->implementation = typesMatch
        ? r_dlsym_call(R_TIMEOUT, "method_getImplementation", method->method,
                       0, 0, 0, 0, 0, 0, 0)
        : 0;
    return method->classObject && method->selector && method->method &&
        method->implementation && typesMatch &&
        remote_call_current_success();
}

static bool cnd_consumer_validate_finalized_layout(uint64_t finalizedClass)
{
    uint64_t instanceSize = r_dlsym_call(
        R_TIMEOUT, "class_getInstanceSize", finalizedClass,
        0, 0, 0, 0, 0, 0, 0);
    uint64_t ivarName = r_alloc_str("finalizedIcon");
    uint64_t ivar = ivarName
        ? r_dlsym_call(R_TIMEOUT, "class_getInstanceVariable",
                       finalizedClass, ivarName, 0, 0, 0, 0, 0, 0)
        : 0;
    if (ivarName) r_free(ivarName);
    uint64_t offset = ivar
        ? r_dlsym_call(R_TIMEOUT, "ivar_getOffset", ivar,
                       0, 0, 0, 0, 0, 0, 0)
        : UINT64_MAX;
    return instanceSize > 0xb8U && offset == 8U &&
        remote_call_current_success();
}

static bool cnd_consumer_validate_full_bleed_renderer(
    uint64_t finalizedClass)
{
    uint64_t selector = r_sel(
        "renderedFullBleedIconWithConfiguration:"
        "excludeChicletSpecularHighlights:");
    uint64_t method = finalizedClass && selector
        ? r_dlsym_call(R_TIMEOUT, "class_getInstanceMethod",
                       finalizedClass, selector,
                       0, 0, 0, 0, 0, 0)
        : 0;
    uint64_t types = method
        ? r_dlsym_call(R_TIMEOUT, "method_getTypeEncoding", method,
                       0, 0, 0, 0, 0, 0, 0)
        : 0;
    char actualTypes[96] = {0};
    return types &&
        r_read_cstring(types, actualTypes, sizeof(actualTypes)) &&
        strcmp(actualTypes, "^{CGImage=}28@0:8@16B24") == 0 &&
        remote_call_current_success();
}

static bool cnd_consumer_imp_matches(uint64_t observed,
                                     uint64_t expected)
{
    return cnd_consumer_strip_code_pointer(observed) ==
        cnd_consumer_strip_code_pointer(expected);
}

static bool cnd_consumer_methods_match(CNDConsumerHookMethod methods[4],
                                       uint64_t remoteBase,
                                       NSUInteger *mismatchIndexOut,
                                       uint64_t *observedOut,
                                       uint64_t *expectedOut)
{
    if (mismatchIndexOut) *mismatchIndexOut = NSNotFound;
    if (observedOut) *observedOut = 0;
    if (expectedOut) *expectedOut = 0;
    for (NSUInteger index = 0; index < 4; index++) {
        uint64_t observed = r_dlsym_call(
            R_TIMEOUT, "method_getImplementation", methods[index].method,
            0, 0, 0, 0, 0, 0, 0);
        uint64_t expected = remoteBase + methods[index].payloadOffset;
        if (!cnd_consumer_imp_matches(observed, expected)) {
            if (mismatchIndexOut) *mismatchIndexOut = index;
            if (observedOut) *observedOut = observed;
            if (expectedOut) *expectedOut = expected;
            return false;
        }
    }
    return remote_call_current_success();
}

static NSDictionary *cnd_consumer_saved_mapping(NSString *host)
{
    NSDictionary *all = [NSUserDefaults.standardUserDefaults
        dictionaryForKey:CNDConsumerHookJournalKey];
    id value = all[host];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

static void cnd_consumer_save_mapping(NSString *host, int pid,
                                      uint64_t base, uint64_t length,
                                      uint64_t context)
{
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSMutableDictionary *all = [[defaults
        dictionaryForKey:CNDConsumerHookJournalKey] mutableCopy] ?:
        [NSMutableDictionary dictionary];
    all[host] = @{
        @"pid": @(pid),
        @"base": @(base),
        @"length": @(length),
        @"context": @(context),
        @"version": @(CND_ICON_CONSUMER_PAYLOAD_VERSION),
        @"transport": remote_call_uses_lab_backend()
            ? @"vm-anonymous-remotecall"
            : @"physical-signed-vnode-remotecall",
    };
    [defaults setObject:all forKey:CNDConsumerHookJournalKey];
    (void)[defaults synchronize];
}

static void cnd_consumer_forget_saved_mapping(NSString *host)
{
    if (host.length == 0) return;
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSMutableDictionary *all = [[defaults
        dictionaryForKey:CNDConsumerHookJournalKey] mutableCopy];
    if (!all[host]) return;
    [all removeObjectForKey:host];
    if (all.count > 0) {
        [defaults setObject:all forKey:CNDConsumerHookJournalKey];
    } else {
        [defaults removeObjectForKey:CNDConsumerHookJournalKey];
    }
    (void)[defaults synchronize];
}

static bool cnd_consumer_existing_mapping(
    NSString *host, int pid, size_t contextOffset,
    CNDConsumerHookMethod methods[4], uint64_t *baseOut,
    uint64_t *lengthOut)
{
    NSDictionary *saved = cnd_consumer_saved_mapping(host);
    if ([saved[@"pid"] intValue] != pid ||
        [saved[@"version"] unsignedLongLongValue] !=
            CND_ICON_CONSUMER_PAYLOAD_VERSION) {
        return false;
    }
    uint64_t base = [saved[@"base"] unsignedLongLongValue];
    uint64_t length = [saved[@"length"] unsignedLongLongValue];
    uint64_t contextAddress = [saved[@"context"] unsignedLongLongValue];
    CNDIconServicesConsumerPayloadContext context = {0};
    if (!base || !length || contextAddress != base + contextOffset ||
        !remote_read(contextAddress, &context, sizeof(context)) ||
        context.magic != CND_ICON_CONSUMER_PAYLOAD_MAGIC ||
        context.version != CND_ICON_CONSUMER_PAYLOAD_VERSION ||
        !cnd_consumer_methods_match(methods, base, NULL, NULL, NULL)) {
        return false;
    }
    if (baseOut) *baseOut = base;
    if (lengthOut) *lengthOut = length;
    return true;
}

static bool cnd_consumer_set_context_selectors(
    CNDIconServicesConsumerPayloadContext *context)
{
#define CND_SET_SELECTOR(field, name)                   \
    do {                                                \
        context->field = r_sel(name);                   \
        if (!context->field) return false;              \
    } while (0)
    CND_SET_SELECTOR(selAlloc, "alloc");
    CND_SET_SELECTOR(selInit, "init");
    CND_SET_SELECTOR(selRelease, "release");
    CND_SET_SELECTOR(selBytes, "bytes");
    CND_SET_SELECTOR(selLength, "length");
    CND_SET_SELECTOR(selRenderedFullBleed,
        "renderedFullBleedIconWithConfiguration:excludeChicletSpecularHighlights:");
    CND_SET_SELECTOR(selCopy, "copy");
    CND_SET_SELECTOR(selCount, "count");
    CND_SET_SELECTOR(selObjectAtIndex, "objectAtIndex:");
    CND_SET_SELECTOR(selRemoveFromSuperlayer, "removeFromSuperlayer");
    CND_SET_SELECTOR(selSublayers, "sublayers");
    CND_SET_SELECTOR(selSetContents, "setContents:");
    CND_SET_SELECTOR(selSetContentsGravity, "setContentsGravity:");
    CND_SET_SELECTOR(selSetContentsScale, "setContentsScale:");
    CND_SET_SELECTOR(selSetOpaque, "setOpaque:");
    CND_SET_SELECTOR(selSetMasksToBounds, "setMasksToBounds:");
    CND_SET_SELECTOR(selSetCornerRadius, "setCornerRadius:");
    CND_SET_SELECTOR(selSetBorderWidth, "setBorderWidth:");
    CND_SET_SELECTOR(selSetBackgroundColor, "setBackgroundColor:");
    CND_SET_SELECTOR(selSetShadowOpacity, "setShadowOpacity:");
    CND_SET_SELECTOR(selBegin, "begin");
    CND_SET_SELECTOR(selSetDisableActions, "setDisableActions:");
    CND_SET_SELECTOR(selCommit, "commit");
    CND_SET_SELECTOR(selBounds, "bounds");
#undef CND_SET_SELECTOR
    return true;
}

static bool cnd_consumer_rollback_methods(CNDConsumerHookMethod methods[4],
                                          NSUInteger installedCount)
{
    bool ok = true;
    while (installedCount > 0) {
        installedCount--;
        uint64_t replaced = r_dlsym_call(
            R_TIMEOUT, "method_setImplementation",
            methods[installedCount].method,
            methods[installedCount].implementation,
            0, 0, 0, 0, 0, 0);
        ok = ok && replaced != 0 && remote_call_current_success();
    }
    for (NSUInteger index = 0; index < 4 && ok; index++) {
        uint64_t observed = r_dlsym_call(
            R_TIMEOUT, "method_getImplementation", methods[index].method,
            0, 0, 0, 0, 0, 0, 0);
        ok = cnd_consumer_imp_matches(
            observed, methods[index].implementation);
    }
    return ok;
}

CNDIconServicesConsumerHookResult
CNDIconServicesConsumerHookInstallInCurrentSession(
    const char *host, double displayScale,
    CNDIconServicesConsumerHookReport *reportOut)
{
    CNDIconServicesConsumerHookReport report = {0};
    report.result = CNDIconServicesConsumerHookFailed;
    report.pid = remote_call_current_pid();
    snprintf(report.host, sizeof(report.host), "%s", host ?: "");
    CNDConsumerHookMethod methods[4] = {
        { .className = "ICRFinalizedIcon",
          .selectorName = "initFromSerializedData:device:error:",
          .expectedTypes = "@40@0:8@16@24^@32" },
        { .className = "ICRIconLayer",
          .selectorName = "initWithData:error:",
          .expectedTypes = "@32@0:8@16^@24" },
        { .className = "ICRIconLayer",
          .selectorName = "initWithFinalizedIcon:",
          .expectedTypes = "@24@0:8@16" },
        { .className = "ICRIconLayer",
          .selectorName = "layoutSublayers",
          .expectedTypes = "v16@0:8" },
    };

    do {
    if (!remote_call_current_success() || report.pid <= 1) {
        cnd_consumer_reason(&report, "no-active-remote-session");
        break;
    }
    /* Both the vPhone lab backend and the physical-device RemoteCall use this
     * same architecture-neutral payload.  The caller owns one target session;
     * all setup, delivery, verification, and store work reuse that session. */
    if (!cnd_consumer_load_remote_framework(
            "/System/Library/PrivateFrameworks/IconRendering.framework/IconRendering")) {
        cnd_consumer_reason(&report, "iconrendering-load-failed");
        break;
    }

    const uint8_t *localPayload = NULL;
    size_t payloadLength = 0, contextOffset = 0, probeOffset = 0;
    size_t installMethodOffset = 0;
    char payloadDiagnostic[192] = {0};
    if (!cnd_consumer_local_payload(
            &localPayload, &payloadLength, &contextOffset,
            methods, &probeOffset, &installMethodOffset, payloadDiagnostic,
            sizeof(payloadDiagnostic))) {
        cnd_consumer_reason(&report, payloadDiagnostic[0]
            ? payloadDiagnostic : "local-payload-layout-invalid");
        break;
    }
    NSString *hostKey = [NSString stringWithUTF8String:host ?: ""];
    NSDictionary *savedMapping = cnd_consumer_saved_mapping(hostKey);
    int savedPID = [savedMapping[@"pid"] intValue];
    uint64_t savedVersion =
        [savedMapping[@"version"] unsignedLongLongValue];
    if (savedMapping && savedPID == report.pid &&
        savedVersion != CND_ICON_CONSUMER_PAYLOAD_VERSION) {
        cnd_consumer_reason(
            &report, "live-consumer-mapping-version-restart-required");
        break;
    }
    if (savedMapping && savedPID > 1 && savedPID != report.pid) {
        /*
         * The mapping belongs to the old address space and disappears with
         * that consumer.  Retaining its PID as a conflict permanently blocks
         * the required reinstall after SpringBoard/Spotlight restarts.  It is
         * safe to forget only this local identity record; no remote memory is
         * touched.  Same-PID version/readback mismatches remain strict because
         * a live method table could still point into that payload.
         */
        cnd_consumer_forget_saved_mapping(hostKey);
        savedMapping = nil;
        savedPID = 0;
    }
    bool methodsReady = true;
    for (NSUInteger index = 0; index < 4; index++) {
        methodsReady = methodsReady &&
            cnd_consumer_prepare_method(&methods[index]);
    }
    if (!methodsReady ||
        !cnd_consumer_validate_finalized_layout(methods[0].classObject) ||
        !cnd_consumer_validate_full_bleed_renderer(
            methods[0].classObject)) {
        cnd_consumer_reason(&report, "iconrendering-abi-mismatch");
        break;
    }
    report.abiValidated = true;

    uint64_t existingBase = 0, existingLength = 0;
    if (hostKey.length > 0 && cnd_consumer_existing_mapping(
            hostKey, report.pid, contextOffset, methods,
            &existingBase, &existingLength)) {
        report.result = CNDIconServicesConsumerHookAlreadyInstalled;
        report.mappingAddress = existingBase;
        report.mappingLength = existingLength;
        report.payloadCopied = true;
        report.payloadReadbackVerified = true;
        report.executableProtectionApplied = true;
        report.executionProbeVerified = true;
        report.methodsInstalled = true;
        report.methodsReadbackVerified = true;
        cnd_consumer_reason(&report, "marker-aware-consumer-already-installed");
        break;
    }
    if (savedMapping && savedPID == report.pid) {
        cnd_consumer_reason(
            &report, "saved-consumer-mapping-readback-mismatch");
        break;
    }

    CNDIconServicesConsumerPayloadContext context = {0};
    context.magic = CND_ICON_CONSUMER_PAYLOAD_MAGIC;
    context.version = CND_ICON_CONSUMER_PAYLOAD_VERSION;
    context.objcMsgSend = cnd_consumer_remote_symbol("objc_msgSend");
    context.objcGetAssociatedObject =
        cnd_consumer_remote_symbol("objc_getAssociatedObject");
    context.objcSetAssociatedObject =
        cnd_consumer_remote_symbol("objc_setAssociatedObject");
    context.methodSetImplementation =
        cnd_consumer_remote_symbol("method_setImplementation");
    context.cgImageGetWidth = cnd_consumer_remote_symbol("CGImageGetWidth");
    context.cgImageGetHeight =
        cnd_consumer_remote_symbol("CGImageGetHeight");
    context.originalInitFromSerializedData = methods[0].implementation;
    context.originalIconLayerInitWithData = methods[1].implementation;
    context.originalIconLayerInitWithFinalizedIcon = methods[2].implementation;
    context.originalIconLayerLayout = methods[3].implementation;
    context.configurationClass = r_class("ICRGlobalConfiguration");
    context.transactionClass = r_class("CATransaction");
    context.contentsGravityResize = r_nsstr_retained("resize");
    context.finalizedChicletOffset = 0xb8U;
    context.markerLength = [CNDIconServicesThemeMarker
        lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    /* Kept in the context for report/layout compatibility; the payload
     * derives the actual contentsScale from CGImage pixels / layer bounds,
     * exactly like the proven dylib. */
    context.contentsScale = displayScale > 0.0 ? displayScale : 3.0;
    snprintf(context.marker, sizeof(context.marker), "%s",
             CNDIconServicesThemeMarker.UTF8String);
    if (!context.objcMsgSend || !context.objcGetAssociatedObject ||
        !context.objcSetAssociatedObject ||
        !context.methodSetImplementation || !context.configurationClass ||
        !context.transactionClass || !context.contentsGravityResize ||
        context.markerLength == 0 ||
        context.markerLength >= sizeof(context.marker) ||
        !cnd_consumer_set_context_selectors(&context)) {
        cnd_consumer_reason(&report, "payload-context-resolution-failed");
        break;
    }

    uint64_t pageSize = r_dlsym_call(
        R_TIMEOUT, "getpagesize", 0, 0, 0, 0, 0, 0, 0, 0);
    if (pageSize < 4096 || (pageSize & (pageSize - 1)) != 0) {
        cnd_consumer_reason(&report, "target-page-size-invalid");
        break;
    }
    uint64_t mappingLength =
        (payloadLength + pageSize - 1) & ~(pageSize - 1);
    uint64_t remoteBase = 0;
    if (!remote_call_uses_lab_backend()) {
        char mappingDiagnostic[192] = {0};
        if (!cnd_consumer_map_physical_payload(
                localPayload, payloadLength, pageSize, contextOffset,
                &context, &remoteBase, &mappingLength,
                &report.libraryValidationAccepted,
                &report.libraryValidationPolicyFallbackUsed,
                &report.libraryValidationErrno,
                mappingDiagnostic, sizeof(mappingDiagnostic))) {
            cnd_consumer_reason(&report, mappingDiagnostic[0]
                ? mappingDiagnostic : "consumer-vnode-map-failed");
            break;
        }
        report.mappingAddress = remoteBase;
        report.mappingLength = mappingLength;
        report.payloadCopied = true;
        report.payloadReadbackVerified = true;
        report.executableProtectionApplied = true;
    } else {
        remoteBase = r_dlsym_call(
            R_TIMEOUT, "mmap", 0, mappingLength,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
            (uint64_t)-1, 0, 0, 0);
        if (!remoteBase || remoteBase == UINT64_MAX) {
            cnd_consumer_reason(&report, "payload-rw-mapping-failed");
            break;
        }
        report.mappingAddress = remoteBase;
        report.mappingLength = mappingLength;

        context.remoteBase = remoteBase;
        NSMutableData *patchedPayload =
            [NSMutableData dataWithBytes:localPayload length:payloadLength];
        memcpy((uint8_t *)patchedPayload.mutableBytes + contextOffset,
               &context, sizeof(context));
        if (!remote_write(remoteBase, patchedPayload.bytes,
                          patchedPayload.length)) {
            cnd_consumer_reason(&report, "payload-copy-failed");
            break;
        }
        report.payloadCopied = true;
        NSMutableData *readback =
            [NSMutableData dataWithLength:payloadLength];
        report.payloadReadbackVerified = remote_read(
            remoteBase, readback.mutableBytes, readback.length) &&
            [readback isEqualToData:patchedPayload];
        if (!report.payloadReadbackVerified) {
            cnd_consumer_reason(&report, "payload-readback-mismatch");
            break;
        }
        (void)r_dlsym_call(
            R_TIMEOUT, "sys_icache_invalidate", remoteBase, payloadLength,
            0, 0, 0, 0, 0, 0);
        int protectResult = (int)r_dlsym_call(
            R_TIMEOUT, "mprotect", remoteBase, mappingLength,
            PROT_READ | PROT_EXEC, 0, 0, 0, 0, 0);
        report.executableProtectionApplied = protectResult == 0 &&
            remote_call_current_success();
        if (!report.executableProtectionApplied) {
            cnd_consumer_reason(&report, "payload-rx-transition-failed");
            break;
        }
    }

    uint64_t expectedProbe = CND_ICON_CONSUMER_PAYLOAD_MAGIC ^
        CND_ICON_CONSUMER_PAYLOAD_VERSION;
    uint64_t observedProbe = do_remote_call_stable_addr(
        R_TIMEOUT, remoteBase + probeOffset, "cnd_consumer_payload_probe",
        0, 0, 0, 0, 0, 0, 0, 0);
    report.executionProbeVerified = observedProbe == expectedProbe &&
        remote_call_current_success();
    if (!report.executionProbeVerified) {
        cnd_consumer_reason(&report, "payload-execution-probe-failed");
        break;
    }

    NSUInteger installedCount = 0;
    for (NSUInteger index = 0; index < 4; index++) {
        uint64_t replaced = do_remote_call_stable_addr(
            R_TIMEOUT, remoteBase + installMethodOffset,
            "cnd_consumer_payload_install_method",
            methods[index].method,
            remoteBase + methods[index].payloadOffset,
            0, 0, 0, 0, 0, 0);
        if (!replaced || !cnd_consumer_imp_matches(
                replaced, methods[index].implementation) ||
            !remote_call_current_success()) {
            break;
        }
        installedCount++;
    }
    report.methodsInstalled = installedCount == 4;
    NSUInteger mismatchIndex = NSNotFound;
    uint64_t mismatchObserved = 0;
    uint64_t mismatchExpected = 0;
    report.methodsReadbackVerified = report.methodsInstalled &&
        cnd_consumer_methods_match(
            methods, remoteBase, &mismatchIndex,
            &mismatchObserved, &mismatchExpected);
    if (!report.methodsReadbackVerified) {
        report.rollbackAttempted = installedCount > 0;
        report.rollbackVerified = cnd_consumer_rollback_methods(
            methods, installedCount);
        if (report.methodsInstalled && mismatchIndex != NSNotFound) {
            snprintf(report.reason, sizeof(report.reason),
                "method-readback-mismatch:index=%lu:observed=0x%llx:"
                "expected=0x%llx:rollback=%s",
                (unsigned long)mismatchIndex,
                (unsigned long long)mismatchObserved,
                (unsigned long long)mismatchExpected,
                report.rollbackVerified ? "succeeded" : "unverified");
        } else {
            snprintf(report.reason, sizeof(report.reason),
                "method-install-incomplete:installed=%lu/4:rollback=%s",
                (unsigned long)installedCount,
                report.rollbackVerified ? "succeeded" : "unverified");
        }
        break;
    }

    report.result = CNDIconServicesConsumerHookInstalled;
    cnd_consumer_save_mapping(
        hostKey, report.pid, remoteBase, mappingLength,
        remoteBase + contextOffset);
    cnd_consumer_reason(&report, "marker-aware-consumer-installed");
    } while (0);

    // Failed installs must not accumulate executable mappings. Only unmap
    // when no method can still point into the payload; an unverified rollback
    // deliberately leaves the mapping resident to avoid a dangling IMP.
    if (report.result == CNDIconServicesConsumerHookFailed &&
        report.mappingAddress && report.mappingLength &&
        (!report.rollbackAttempted || report.rollbackVerified) &&
        remote_call_current_success()) {
        report.mappingCleanupAttempted = true;
        int cleanupResult = (int)r_dlsym_call(
            R_TIMEOUT, "munmap", report.mappingAddress,
            report.mappingLength, 0, 0, 0, 0, 0, 0);
        report.mappingCleanupVerified = cleanupResult == 0 &&
            remote_call_current_success();
    }

    report.transportClean = remote_call_current_success();
    printf("[ICONCONSUMER] result=%ld host=%s pid=%d abi=%d copy=%d/%d "
           "rx=%d probe=%d methods=%d/%d rollback=%d/%d "
           "mapping-cleanup=%d/%d mapping=%#llx/%llu transport=%d reason=%s\n",
           (long)report.result, report.host, report.pid,
           report.abiValidated, report.payloadCopied,
           report.payloadReadbackVerified,
           report.executableProtectionApplied,
           report.executionProbeVerified, report.methodsInstalled,
           report.methodsReadbackVerified, report.rollbackAttempted,
           report.rollbackVerified, report.mappingCleanupAttempted,
           report.mappingCleanupVerified, report.mappingAddress,
           report.mappingLength, report.transportClean,
           report.reason[0] ? report.reason : "-");
    if (reportOut) *reportOut = report;
    return report.result;
}

NSDictionary<NSString *, id> *CNDIconServicesConsumerHookReportDictionary(
    const CNDIconServicesConsumerHookReport *report)
{
    if (!report) return @{};
    return @{
        @"result": @((NSInteger)report->result),
        @"host": [NSString stringWithUTF8String:report->host] ?: @"",
        @"pid": @(report->pid),
        @"abiValidated": @(report->abiValidated),
        @"payloadCopied": @(report->payloadCopied),
        @"payloadReadbackVerified": @(report->payloadReadbackVerified),
        @"executableProtectionApplied":
            @(report->executableProtectionApplied),
        @"libraryValidationAccepted":
            @(report->libraryValidationAccepted),
        @"libraryValidationPolicyFallbackUsed":
            @(report->libraryValidationPolicyFallbackUsed),
        @"libraryValidationErrno": @(report->libraryValidationErrno),
        @"executionProbeVerified": @(report->executionProbeVerified),
        @"methodsInstalled": @(report->methodsInstalled),
        @"methodsReadbackVerified": @(report->methodsReadbackVerified),
        @"rollbackAttempted": @(report->rollbackAttempted),
        @"rollbackVerified": @(report->rollbackVerified),
        @"mappingCleanupAttempted": @(report->mappingCleanupAttempted),
        @"mappingCleanupVerified": @(report->mappingCleanupVerified),
        @"transportClean": @(report->transportClean),
        @"mappingAddress": @(report->mappingAddress),
        @"mappingLength": @(report->mappingLength),
        @"reason": [NSString stringWithUTF8String:report->reason] ?: @"",
    };
}

/*
 * Physical-device presentation path proven on the iOS 26 vPhone.
 *
 * SBIconImageView already has a stock flat-image branch which presents the
 * canonical IFImage.CGImage directly on a plain CALayer. Selecting that
 * branch before a row/icon is constructed preserves the alpha contained in
 * Cyanide's persistent IconServices response and avoids ICRIconLayer's grey
 * chiclet. SpringBoard's app-switcher title is a separate consumer: it asks
 * SBFluidSwitcherSpaceTitleItemController for an SBHIconLayerView and stores
 * it through setImageView:.  The VM trace proved that the same controller also
 * has a stock flat-UIImage provider and the title item has its matching image
 * setter.  SpringBoard redirects that provider/setter pair together so the
 * existing flat path is selected without introducing executable bytes or a
 * custom IMP.  Every replacement is ABI-identical Apple-signed code installed
 * and verified in the target's one existing RemoteCall session.
 */
static BOOL cnd_consumer_remote_class_owns_method(
    uint64_t classObject, uint64_t method, uint32_t *methodCountOut)
{
    if (methodCountOut) *methodCountOut = 0;
    if (!classObject || !method || !remote_call_current_success()) return NO;

    uint64_t countAddress = r_dlsym_call(
        R_TIMEOUT, "malloc", sizeof(uint32_t), 0, 0, 0, 0, 0, 0, 0);
    if (!countAddress) return NO;
    (void)r_dlsym_call(
        R_TIMEOUT, "memset", countAddress, 0, sizeof(uint32_t),
        0, 0, 0, 0, 0);
    uint64_t methodList = remote_call_current_success()
        ? r_dlsym_call(
            R_TIMEOUT, "class_copyMethodList", classObject, countAddress,
            0, 0, 0, 0, 0, 0)
        : 0;
    uint32_t methodCount = 0;
    BOOL countRead = methodList && remote_call_current_success() &&
        remote_read(countAddress, &methodCount, sizeof(methodCount));
    BOOL ownsMethod = NO;
    if (countRead && methodCount > 0 && methodCount <= 4096) {
        NSMutableData *methods = [NSMutableData
            dataWithLength:(NSUInteger)methodCount * sizeof(uint64_t)];
        if (remote_read(methodList, methods.mutableBytes, methods.length)) {
            const uint64_t *entries = methods.bytes;
            for (uint32_t index = 0; index < methodCount; index++) {
                if (entries[index] == method) {
                    ownsMethod = YES;
                    break;
                }
            }
        }
    }
    if (methodCountOut) *methodCountOut = methodCount;
    if (methodList && remote_call_current_success()) r_free(methodList);
    if (remote_call_current_success()) r_free(countAddress);
    return ownsMethod && remote_call_current_success();
}

static BOOL cnd_consumer_remote_method_has_exact_types(
    uint64_t method, const char *expectedTypes, char actualTypes[96])
{
    if (actualTypes) actualTypes[0] = '\0';
    if (!method || !expectedTypes || !actualTypes ||
        !remote_call_current_success()) return NO;
    uint64_t types = r_dlsym_call(
        R_TIMEOUT, "method_getTypeEncoding", method,
        0, 0, 0, 0, 0, 0, 0);
    return types && r_read_cstring(types, actualTypes, 96) &&
        strcmp(actualTypes, expectedTypes) == 0 &&
        remote_call_current_success();
}

typedef struct {
    const char *label;
    const char *targetClassName;
    const char *targetSelectorName;
    const char *sourceClassName;
    const char *sourceSelectorName;
    const char *expectedTypes;
    uint64_t targetClass;
    uint64_t sourceClass;
    uint64_t targetMethod;
    uint64_t sourceMethod;
    uint64_t originalIMP;
    uint64_t sourceIMP;
    uint64_t observedIMP;
    uint32_t targetMethodCount;
    uint32_t sourceMethodCount;
    BOOL targetMethodOwned;
    BOOL sourceMethodOwned;
    BOOL abiValidated;
    BOOL alreadyInstalled;
    BOOL installedByThisCall;
    BOOL readbackVerified;
    BOOL rollbackVerified;
    char targetTypes[96];
    char sourceTypes[96];
} CNDConsumerSignedIMPRedirect;

static BOOL cnd_consumer_prepare_signed_imp_redirect(
    CNDConsumerSignedIMPRedirect *redirect)
{
    if (!redirect || !redirect->targetClassName ||
        !redirect->targetSelectorName || !redirect->sourceClassName ||
        !redirect->sourceSelectorName || !redirect->expectedTypes ||
        !remote_call_current_success()) return NO;

    redirect->targetClass = r_class(redirect->targetClassName);
    if (!redirect->targetClass &&
        strcmp(redirect->targetClassName, "SBIconImageView") == 0) {
        (void)cnd_consumer_load_remote_framework(
            "/System/Library/PrivateFrameworks/"
            "SpringBoardHome.framework/SpringBoardHome");
        redirect->targetClass = r_class(redirect->targetClassName);
    }
    redirect->sourceClass = r_class(redirect->sourceClassName);
    uint64_t targetSelector = r_sel(redirect->targetSelectorName);
    uint64_t sourceSelector = r_sel(redirect->sourceSelectorName);
    redirect->targetMethod = redirect->targetClass && targetSelector
        ? r_dlsym_call(
            R_TIMEOUT, "class_getInstanceMethod", redirect->targetClass,
            targetSelector, 0, 0, 0, 0, 0, 0)
        : 0;
    redirect->sourceMethod = redirect->sourceClass && sourceSelector
        ? r_dlsym_call(
            R_TIMEOUT, "class_getInstanceMethod", redirect->sourceClass,
            sourceSelector, 0, 0, 0, 0, 0, 0)
        : 0;
    redirect->targetMethodOwned =
        cnd_consumer_remote_class_owns_method(
            redirect->targetClass, redirect->targetMethod,
            &redirect->targetMethodCount);
    redirect->sourceMethodOwned = remote_call_current_success() &&
        cnd_consumer_remote_class_owns_method(
            redirect->sourceClass, redirect->sourceMethod,
            &redirect->sourceMethodCount);
    BOOL targetABI = remote_call_current_success() &&
        cnd_consumer_remote_method_has_exact_types(
            redirect->targetMethod, redirect->expectedTypes,
            redirect->targetTypes);
    BOOL sourceABI = remote_call_current_success() &&
        cnd_consumer_remote_method_has_exact_types(
            redirect->sourceMethod, redirect->expectedTypes,
            redirect->sourceTypes);
    redirect->abiValidated = redirect->targetMethodOwned &&
        redirect->sourceMethodOwned && targetABI && sourceABI;
    redirect->originalIMP = redirect->abiValidated ? r_dlsym_call(
        R_TIMEOUT, "method_getImplementation", redirect->targetMethod,
        0, 0, 0, 0, 0, 0, 0) : 0;
    redirect->sourceIMP = redirect->abiValidated ? r_dlsym_call(
        R_TIMEOUT, "method_getImplementation", redirect->sourceMethod,
        0, 0, 0, 0, 0, 0, 0) : 0;
    redirect->alreadyInstalled = redirect->originalIMP &&
        redirect->sourceIMP && cnd_consumer_imp_matches(
            redirect->originalIMP, redirect->sourceIMP);
    return redirect->abiValidated && redirect->originalIMP &&
        redirect->sourceIMP && remote_call_current_success();
}

static NSDictionary<NSString *, id> *
cnd_consumer_install_physical_flat_image_redirect(
    NSString *processName, pid_t expectedPID,
    uint64_t expectedProc, uint64_t expectedTask,
    NSDictionary<NSString *, NSData *> *staticIconDataByBundle,
    BOOL installPresentationRedirects,
    BOOL refreshSpringBoardCaches,
    BOOL updateStaticDynamicIcons)
{
    NSTimeInterval started = NSProcessInfo.processInfo.systemUptime;
    BOOL usesLabRemoteCall = remote_call_lab_backend_opted_in();
    if (!usesLabRemoteCall) g_RC_targetProcOverride = expectedProc;
    RemoteCallSession *session = [[RemoteCallSession alloc]
        initWithProcess:processName
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    /* init_remote_call_configured consumes the override on every physical
     * path. Clear it defensively if construction failed before that point. */
    g_RC_targetProcOverride = 0;
    if (!session) {
        return @{
            @"ok": @NO,
            @"stage": @"process-unavailable",
            @"message": @"The consumer could not open its one-time signed-IMP session.",
            @"process": processName ?: @"",
            @"expectedPID": @(expectedPID),
            @"remoteCallUsed": @YES,
            @"mappingTransport": @"apple-signed-imp-remotecall",
        };
    }

    int sessionPID = session.pid;
    uint64_t sessionTask = session.taskAddr;
    pid_t labIdentityPID = 0;
    int labIdentityResult = usesLabRemoteCall
        ? cnd_lab_resolve_process_pid(
            processName.UTF8String, &labIdentityPID)
        : ENOTSUP;
    BOOL identityBound = usesLabRemoteCall
        ? (labIdentityResult == 0 && labIdentityPID == expectedPID &&
           sessionPID == expectedPID)
        : (sessionPID == expectedPID && sessionTask == expectedTask &&
           proc_find(expectedPID) == expectedProc &&
           proc_task(expectedProc) == expectedTask);
    BOOL isSpringBoard = [processName isEqualToString:@"SpringBoard"];
    BOOL isSpotlight = [processName isEqualToString:@"Spotlight"];
    const NSUInteger redirectCount = installPresentationRedirects
        ? (isSpringBoard ? 3 : 1) : 0;
    CNDConsumerSignedIMPRedirect redirectStorage[3] = {
        {
            .label = "flat-icon-image-view",
            .targetClassName = "SBIconImageView",
            .targetSelectorName = "effectivelyPrefersFlatImageLayers",
            .sourceClassName = "NSObject",
            .sourceSelectorName = "isNSObject__",
            .expectedTypes = "B16@0:8",
        },
        {
            /* Install the matching storage route before the provider route.
             * Theme application runs while Cyanide owns the foreground, so
             * the switcher is not rebuilding title items in this tiny window. */
            .label = "switcher-flat-image-storage",
            .targetClassName = "SBFluidSwitcherSpaceTitleItem",
            .targetSelectorName = "setImageView:",
            .sourceClassName = "SBFluidSwitcherSpaceTitleItem",
            .sourceSelectorName = "setImage:",
            .expectedTypes = "v24@0:8@16",
        },
        {
            .label = "switcher-flat-image-provider",
            .targetClassName = "SBFluidSwitcherSpaceTitleItemController",
            .targetSelectorName = "_iconViewForDisplayItem:",
            .sourceClassName = "SBFluidSwitcherSpaceTitleItemController",
            .sourceSelectorName = "_iconImageForDisplayItem:",
            .expectedTypes = "@24@0:8@16",
        },
    };
    CNDConsumerSignedIMPRedirect *redirects = redirectStorage;
    __block BOOL abiValidated = NO;
    __block BOOL allAlreadyInstalled = YES;
    __block BOOL installed = NO;
    __block BOOL readbackVerified = NO;
    __block NSUInteger verifiedRedirectCount = 0;
    __block NSUInteger changedRedirectCount = 0;
    __block BOOL springBoardRefreshAttempted = NO;
    __block BOOL springBoardRefreshVerified = NO;
    __block BOOL staticIconsAttempted = NO;
    __block BOOL staticIconsVerified = NO;
    __block NSDictionary<NSString *, id> *staticIconsResult = @{};
    __block BOOL rollbackAttempted = NO;
    __block BOOL rollbackVerified = NO;
    __block BOOL remoteOK = NO;
    __block NSString *failure = nil;

    if (identityBound) {
        @try {
            remote_call_with_session(session, ^{
                BOOL prepared = YES;
                for (NSUInteger index = 0; index < redirectCount; index++) {
                    CNDConsumerSignedIMPRedirect *redirect = &redirects[index];
                    if (!cnd_consumer_prepare_signed_imp_redirect(redirect)) {
                        prepared = NO;
                        failure = [NSString stringWithFormat:
                            @"The %@ redirect ABI did not match "
                             "(target-owned=%@ source-owned=%@ target=%s "
                             "source=%s expected=%s).",
                            [NSString stringWithUTF8String:redirect->label],
                            redirect->targetMethodOwned ? @"yes" : @"no",
                            redirect->sourceMethodOwned ? @"yes" : @"no",
                            redirect->targetTypes[0]
                                ? redirect->targetTypes : "-",
                            redirect->sourceTypes[0]
                                ? redirect->sourceTypes : "-",
                            redirect->expectedTypes];
                        break;
                    }
                    if (!redirect->alreadyInstalled) {
                        allAlreadyInstalled = NO;
                    }
                }
                abiValidated = prepared && remote_call_current_success();

                if (abiValidated) {
                    for (NSUInteger index = 0;
                         index < redirectCount; index++) {
                        CNDConsumerSignedIMPRedirect *redirect =
                            &redirects[index];
                        if (redirect->alreadyInstalled) {
                            redirect->observedIMP = redirect->originalIMP;
                            redirect->readbackVerified = YES;
                            verifiedRedirectCount++;
                            continue;
                        }
                        uint64_t replaced = r_dlsym_call(
                            R_TIMEOUT, "method_setImplementation",
                            redirect->targetMethod, redirect->sourceIMP,
                            0, 0, 0, 0, 0, 0);
                        redirect->installedByThisCall = replaced != 0 &&
                            remote_call_current_success();
                        if (redirect->installedByThisCall) {
                            changedRedirectCount++;
                        }
                        BOOL replacedExpected =
                            redirect->installedByThisCall &&
                            cnd_consumer_imp_matches(
                                replaced, redirect->originalIMP);
                        redirect->observedIMP = replacedExpected
                            ? r_dlsym_call(
                                R_TIMEOUT, "method_getImplementation",
                                redirect->targetMethod,
                                0, 0, 0, 0, 0, 0, 0)
                            : 0;
                        redirect->readbackVerified = replacedExpected &&
                            cnd_consumer_imp_matches(
                                redirect->observedIMP,
                                redirect->sourceIMP) &&
                            remote_call_current_success();
                        if (!redirect->readbackVerified) {
                            failure = [NSString stringWithFormat:
                                @"The %@ signed-IMP readback failed.",
                                [NSString stringWithUTF8String:
                                    redirect->label]];
                            break;
                        }
                        verifiedRedirectCount++;
                    }
                }

                readbackVerified = abiValidated &&
                    verifiedRedirectCount == redirectCount;
                installed = readbackVerified;
                if (!readbackVerified && changedRedirectCount > 0 &&
                    remote_call_current_success()) {
                    rollbackAttempted = YES;
                    rollbackVerified = YES;
                    for (NSUInteger reverse = redirectCount;
                         reverse > 0; reverse--) {
                        CNDConsumerSignedIMPRedirect *redirect =
                            &redirects[reverse - 1];
                        if (!redirect->installedByThisCall) continue;
                        (void)r_dlsym_call(
                            R_TIMEOUT, "method_setImplementation",
                            redirect->targetMethod, redirect->originalIMP,
                            0, 0, 0, 0, 0, 0);
                        uint64_t rollbackIMP = remote_call_current_success()
                            ? r_dlsym_call(
                                R_TIMEOUT, "method_getImplementation",
                                redirect->targetMethod,
                                0, 0, 0, 0, 0, 0, 0)
                            : 0;
                        redirect->rollbackVerified = rollbackIMP &&
                            cnd_consumer_imp_matches(
                                rollbackIMP, redirect->originalIMP) &&
                            remote_call_current_success();
                        rollbackVerified = rollbackVerified &&
                            redirect->rollbackVerified;
                    }
                    failure = [NSString stringWithFormat:
                        @"%@ Reverse rollback %@.",
                        failure ?: @"The signed-IMP transaction failed.",
                        rollbackVerified ? @"verified" : @"did not verify"];
                }
                /* Refresh ordinary consumers before the separately requested
                 * dynamic-icon work. Initial Apply uses the cache-only route. */
                if (isSpringBoard && refreshSpringBoardCaches &&
                    readbackVerified && remote_call_current_success()) {
                    springBoardRefreshAttempted = YES;
                    springBoardRefreshVerified =
                        themer_refresh_springboard_iconservices_cache_in_session();
                }
                /* Keep SpringBoard's measured live Clock source, but make
                 * Spotlight's future Clock rows ordinary static icon views.
                 * Both changes remain process-local and use this one already
                 * open consumer session. Calendar uses the same session to
                 * replace only SBCalendarIconImageProvider's exact
                 * preparedISIcon source on its concrete provider object. */
                if (updateStaticDynamicIcons &&
                    readbackVerified && remote_call_current_success()) {
                    staticIconsAttempted = YES;
                    /* This is one bounded, synchronous target session.  The
                     * default 50 ms inter-call settle is useful to interactive
                     * repair loops, but multiplying it through Calendar's
                     * main-thread NSInvocation plumbing made one provider
                     * install appear hung.  The publisher already uses the
                     * same zero-settle policy for its bounded batch. */
                    uint32_t previousSettleUS = r_settle_us(0);
                    staticIconsResult =
                        themer_set_static_dynamic_icon_overlays_in_session(
                            staticIconDataByBundle ?: @{}, isSpotlight);
                    (void)r_settle_us(previousSettleUS);
                    staticIconsVerified =
                        [staticIconsResult[@"ok"] boolValue];
                }
                remoteOK = remote_call_current_success();
            });
        } @catch (NSException *exception) {
            failure = [NSString stringWithFormat:@"%@:%@",
                exception.name ?: @"exception",
                exception.reason ?: @"unknown"];
            remoteOK = NO;
        }
    } else {
        failure = @"The consumer identity changed while opening its signed-IMP session.";
    }

    if ([session hasLocalState] && ![session hasInFlightSyntheticCall]) {
        (void)[session destroyRemoteCall];
    }
    BOOL teardownDeferred = NO;
    if ([session hasInFlightSyntheticCall]) {
        teardownDeferred =
            [session deferTeardownForInFlightSyntheticCall];
    }
    BOOL closed = ![session hasLocalState];
    pid_t finalLabPID = 0;
    int finalLabIdentityResult = usesLabRemoteCall
        ? cnd_lab_resolve_process_pid(
            processName.UTF8String, &finalLabPID)
        : ENOTSUP;
    BOOL finalIdentityStable = usesLabRemoteCall
        ? (finalLabIdentityResult == 0 && finalLabPID == expectedPID &&
           sessionPID == expectedPID)
        : (proc_find(expectedPID) == expectedProc &&
           proc_task(expectedProc) == expectedTask);
    BOOL presentationVerified = identityBound && abiValidated && installed &&
        readbackVerified && remoteOK && closed && !teardownDeferred &&
        finalIdentityStable;
    BOOL ok = presentationVerified &&
        (!refreshSpringBoardCaches ||
            (springBoardRefreshAttempted && springBoardRefreshVerified)) &&
        (!updateStaticDynamicIcons ||
            (staticIconsAttempted && staticIconsVerified));
    NSTimeInterval elapsed =
        (NSProcessInfo.processInfo.systemUptime - started) * 1000.0;

    CNDConsumerSignedIMPRedirect *primary = &redirects[0];
    NSMutableArray<NSDictionary<NSString *, id> *> *redirectReports =
        [NSMutableArray arrayWithCapacity:redirectCount];
    for (NSUInteger index = 0; index < redirectCount; index++) {
        CNDConsumerSignedIMPRedirect *redirect = &redirects[index];
        [redirectReports addObject:@{
            @"label": [NSString stringWithUTF8String:redirect->label] ?: @"",
            @"targetClass": [NSString stringWithUTF8String:
                redirect->targetClassName] ?: @"",
            @"targetSelector": [NSString stringWithUTF8String:
                redirect->targetSelectorName] ?: @"",
            @"sourceClass": [NSString stringWithUTF8String:
                redirect->sourceClassName] ?: @"",
            @"sourceSelector": [NSString stringWithUTF8String:
                redirect->sourceSelectorName] ?: @"",
            @"expectedTypes": [NSString stringWithUTF8String:
                redirect->expectedTypes] ?: @"",
            @"targetTypes": redirect->targetTypes[0]
                ? [NSString stringWithUTF8String:redirect->targetTypes] : @"",
            @"sourceTypes": redirect->sourceTypes[0]
                ? [NSString stringWithUTF8String:redirect->sourceTypes] : @"",
            @"targetMethodOwned": @(redirect->targetMethodOwned),
            @"sourceMethodOwned": @(redirect->sourceMethodOwned),
            @"abiValidated": @(redirect->abiValidated),
            @"originalIMP": @(redirect->originalIMP),
            @"replacementIMP": @(redirect->sourceIMP),
            @"observedIMP": @(redirect->observedIMP),
            @"alreadyInstalled": @(redirect->alreadyInstalled),
            @"installedByThisCall": @(redirect->installedByThisCall),
            @"readbackVerified": @(redirect->readbackVerified),
            @"rollbackVerified": @(redirect->rollbackVerified),
        }];
    }

    log_user("[SBR_FLAT_IMP] target=%s pid=%d ok=%s redirects=%lu/%lu "
             "switcher=%s existing=%s original=%#llx replacement=%#llx "
             "observed=%#llx "
             "rollback=%s/%s home-refresh=%s/%s static-icons=%s/%s "
             "transport=%s closed=%s "
             "time=%.3fms\n",
             processName.UTF8String ?: "", expectedPID,
             ok ? "yes" : "no",
             (unsigned long)verifiedRedirectCount,
             (unsigned long)redirectCount,
             isSpringBoard
                ? (verifiedRedirectCount == redirectCount
                    ? "verified" : "failed")
                : "not-required",
             allAlreadyInstalled ? "yes" : "no",
             (unsigned long long)primary->originalIMP,
             (unsigned long long)primary->sourceIMP,
             (unsigned long long)primary->observedIMP,
             rollbackAttempted ? "attempted" : "not-needed",
             rollbackVerified ? "verified" : "not-needed",
             springBoardRefreshAttempted ? "attempted" : "not-needed",
             springBoardRefreshVerified ? "verified" :
                (springBoardRefreshAttempted ? "failed" : "not-needed"),
             staticIconsAttempted ? "attempted" : "not-needed",
             staticIconsVerified ? "verified" :
                (staticIconsAttempted ? "failed" : "not-needed"),
             remoteOK ? "healthy" : "failed",
             closed ? "yes" : "no", elapsed);

    return @{
        @"ok": @(ok),
        @"stage": ok
            ? (installPresentationRedirects
                ? @"presentation-ready" : @"cache-refresh-ready")
            : (installPresentationRedirects
                ? @"presentation-install" : @"cache-refresh"),
        @"message": ok
            ? (!installPresentationRedirects
                ? @"SpringBoard's bounded icon cache purge and visible-consumer refresh completed without installing presentation redirects."
                : (allAlreadyInstalled
                    ? @"Every required stock flat-image presentation redirect was already active for this process."
                    : (isSpringBoard
                        ? @"The stock flat-image presentation branch and app-switcher UIImage route are active through ABI-matched Apple-signed IMP redirects."
                        : @"The stock flat-image presentation branch is active through an ABI-matched Apple-signed IMP redirect.")))
            : (failure ?: @"The stock flat-image presentation redirect did not verify."),
        @"process": processName ?: @"",
        @"pid": @(sessionPID),
        @"expectedPID": @(expectedPID),
        @"identityBound": @(identityBound),
        @"finalIdentityStable": @(finalIdentityStable),
        @"targetClass": @"SBIconImageView",
        @"targetSelector": @"effectivelyPrefersFlatImageLayers",
        @"sourceClass": @"NSObject",
        @"sourceSelector": @"isNSObject__",
        @"targetMethodCount": @(primary->targetMethodCount),
        @"sourceMethodCount": @(primary->sourceMethodCount),
        @"targetMethodOwned": @(primary->targetMethodOwned),
        @"sourceMethodOwned": @(primary->sourceMethodOwned),
        @"abiValidated": @(abiValidated),
        @"targetTypes": primary->targetTypes[0]
            ? [NSString stringWithUTF8String:primary->targetTypes] : @"",
        @"sourceTypes": primary->sourceTypes[0]
            ? [NSString stringWithUTF8String:primary->sourceTypes] : @"",
        @"originalIMP": @(primary->originalIMP),
        @"replacementIMP": @(primary->sourceIMP),
        @"observedIMP": @(primary->observedIMP),
        @"alreadyInstalled": @(allAlreadyInstalled),
        @"installedCount": @(verifiedRedirectCount),
        @"requiredRedirectCount": @(redirectCount),
        @"verifiedRedirectCount": @(verifiedRedirectCount),
        @"changedRedirectCount": @(changedRedirectCount),
        @"presentationRedirectsRequested": @(installPresentationRedirects),
        @"switcherRedirectsRequired": @(
            installPresentationRedirects && isSpringBoard),
        @"switcherRedirectsVerified": @(!installPresentationRedirects ||
            !isSpringBoard ||
            verifiedRedirectCount == redirectCount),
        @"redirects": redirectReports,
        @"methodsReadbackVerified": @(readbackVerified),
        @"transparencyVerified": @(
            installPresentationRedirects && presentationVerified),
        @"rollbackAttempted": @(rollbackAttempted),
        @"rollbackVerified": @(rollbackVerified),
        @"springBoardCacheRefreshAttempted":
            @(springBoardRefreshAttempted),
        @"springBoardCacheRefreshVerified":
            @(springBoardRefreshVerified),
        @"staticIconsAttempted": @(staticIconsAttempted),
        @"staticIconsVerified": @(staticIconsVerified),
        @"staticIcons": staticIconsResult ?: @{},
        @"transportClean": @(remoteOK),
        @"remoteOK": @(remoteOK),
        @"closed": @(closed),
        @"teardownDeferred": @(teardownDeferred),
        @"remoteCallUsed": @YES,
        @"mappingTransport": usesLabRemoteCall
            ? @"vphone-injected-remotecall"
            : @"apple-signed-imp-remotecall",
        @"libraryValidationPolicyFallbackUsed": @NO,
        @"libraryValidationErrno": @0,
        @"elapsedMilliseconds": @(elapsed),
    };
}

typedef struct {
    uint32_t flagsBefore;
    uint32_t flagsAfter;
    int parentPID;
    int64_t traceMeResult;
    int traceMeErrno;
    BOOL traceAttempted;
    BOOL alreadyDebugged;
    int64_t stopResult;
    int stopErrno;
    int64_t detachResult;
    int detachErrno;
    int64_t continueResult;
    int continueErrno;
    BOOL statusBeforeRead;
    BOOL statusAfterRead;
    BOOL targetRemoteHealthy;
    BOOL targetSessionClosed;
    BOOL targetTeardownDeferred;
    BOOL parentRemoteHealthy;
    BOOL parentSessionClosed;
    BOOL parentTeardownDeferred;
} CNDConsumerAllowInvalidReport;

/*
 * PT_TRACE_ME is intentionally issued by the target itself.  XNU routes that
 * request through a different MAC authorization path than cross-process
 * PT_ATTACHEXC and, on success, calls cs_allow_invalid(current_proc()).
 *
 * PT_DETACH requires the tracee to be stopped.  Once the target's one and only
 * RemoteCall session has closed, its verified parent (PID 1) briefly sends
 * SIGSTOP and performs a bounded detach.  A failed detach sends SIGCONT before
 * returning failure so this experiment cannot knowingly leave Spotlight
 * stopped.  SpringBoard is deliberately excluded until Spotlight proves the
 * complete self-trace, private-COW, teardown, stop, and detach lifecycle.
 */
static BOOL cnd_consumer_finish_self_trace_via_launchd(
    pid_t pid, CNDConsumerAllowInvalidReport *report,
    NSString **failureOut)
{
    if (failureOut) *failureOut = nil;
    if (!report || pid <= 1 || report->parentPID != 1 ||
        !report->traceAttempted) {
        if (failureOut) {
            *failureOut = @"The target did not issue a PID-1 self-trace attempt.";
        }
        return NO;
    }

    RemoteCallSession *launchd = [[RemoteCallSession alloc]
        initWithProcess:@"launchd"
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    if (!launchd) {
        if (failureOut) {
            *failureOut = @"launchd could not open the bounded self-trace detach session.";
        }
        return NO;
    }

    @try {
        remote_call_with_session(launchd, ^{
            report->stopResult = (int64_t)r_dlsym_call(
                R_TIMEOUT, "kill", (uint64_t)pid, SIGSTOP,
                0, 0, 0, 0, 0, 0);
            if (report->stopResult < 0) {
                report->stopErrno = cnd_consumer_remote_errno();
            } else {
                /* XNU's PT_DETACH gate requires SSTOP.  Retry only EBUSY,
                 * which is the expected bounded stop-delivery race. */
                for (unsigned attempt = 0; attempt < 5; attempt++) {
                    (void)r_dlsym_call(
                        R_TIMEOUT, "usleep", attempt == 0 ? 100000 : 50000,
                        0, 0, 0, 0, 0, 0, 0);
                    report->detachResult = (int64_t)r_dlsym_call(
                        R_TIMEOUT, "ptrace", CNDConsumerPTDetach,
                        (uint64_t)pid, 0, 0, 0, 0, 0, 0);
                    if (report->detachResult == 0) {
                        report->detachErrno = 0;
                        break;
                    }
                    report->detachErrno = cnd_consumer_remote_errno();
                    if (report->detachErrno != EBUSY) break;
                }
            }

            if (report->detachResult != 0) {
                report->continueResult = (int64_t)r_dlsym_call(
                    R_TIMEOUT, "kill", (uint64_t)pid, SIGCONT,
                    0, 0, 0, 0, 0, 0);
                if (report->continueResult < 0) {
                    report->continueErrno = cnd_consumer_remote_errno();
                }
            }
            report->parentRemoteHealthy = remote_call_current_success();
        });
    } @catch (__unused NSException *exception) {
        report->parentRemoteHealthy = NO;
    }

    if ([launchd hasLocalState] &&
        ![launchd hasInFlightSyntheticCall]) {
        (void)[launchd destroyRemoteCall];
    }
    if ([launchd hasInFlightSyntheticCall]) {
        report->parentTeardownDeferred =
            [launchd deferTeardownForInFlightSyntheticCall];
    }
    report->parentSessionClosed = ![launchd hasLocalState];

    BOOL ok = report->parentRemoteHealthy && report->parentSessionClosed &&
        !report->parentTeardownDeferred && report->stopResult == 0 &&
        report->detachResult == 0;
    if (!ok && failureOut) {
        *failureOut = [NSString stringWithFormat:
            @"The PID-1 self-trace cleanup did not verify "
             "(stop=%lld/%d detach=%lld/%d continue=%lld/%d "
             "transport=%@ closed=%@ deferred=%@).",
            (long long)report->stopResult, report->stopErrno,
            (long long)report->detachResult, report->detachErrno,
            (long long)report->continueResult, report->continueErrno,
            report->parentRemoteHealthy ? @"healthy" : @"failed",
            report->parentSessionClosed ? @"yes" : @"no",
            report->parentTeardownDeferred ? @"yes" : @"no"];
    }
    return ok;
}

typedef struct {
    uint64_t header;
    uint64_t slide;
    uint64_t target;
    uint64_t textStart;
    uint64_t textEnd;
    uint8_t uuid[16];
    char path[256];
} CNDConsumerIconRenderingImage;

static BOOL cnd_consumer_resolve_iconrendering_image(
    CNDConsumerIconRenderingImage *image, NSString **failureOut)
{
    if (image) memset(image, 0, sizeof(*image));
    if (failureOut) *failureOut = nil;
    if (!image || !cnd_consumer_load_remote_framework(
            "/System/Library/PrivateFrameworks/IconRendering.framework/IconRendering")) {
        if (failureOut) *failureOut = @"IconRendering could not be loaded.";
        return NO;
    }

    uint64_t classObject = r_class("ICRFinalizedIcon");
    uint64_t selector = r_sel("initFromSerializedData:device:error:");
    uint64_t method = classObject && selector ? r_dlsym_call(
        R_TIMEOUT, "class_getInstanceMethod", classObject, selector,
        0, 0, 0, 0, 0, 0) : 0;
    uint64_t implementation = method ? r_dlsym_call(
        R_TIMEOUT, "method_getImplementation", method,
        0, 0, 0, 0, 0, 0, 0) : 0;
    uint64_t infoAddress = implementation ? r_dlsym_call(
        R_TIMEOUT, "malloc", sizeof(Dl_info),
        0, 0, 0, 0, 0, 0, 0) : 0;
    Dl_info info = {0};
    BOOL haveInfo = NO;
    if (infoAddress) {
        (void)r_dlsym_call(
            R_TIMEOUT, "memset", infoAddress, 0, sizeof(Dl_info),
            0, 0, 0, 0, 0);
        uint64_t result = r_dlsym_call(
            R_TIMEOUT, "dladdr", implementation, infoAddress,
            0, 0, 0, 0, 0, 0);
        haveInfo = result != 0 &&
            remote_read(infoAddress, &info, sizeof(info));
        if (remote_call_current_success()) r_free(infoAddress);
    }
    if (!haveInfo || !info.dli_fbase || !info.dli_fname ||
        !r_read_cstring((uint64_t)(uintptr_t)info.dli_fname,
                        image->path, sizeof(image->path)) ||
        !strstr(image->path,
            "/System/Library/PrivateFrameworks/IconRendering.framework/IconRendering")) {
        if (failureOut) {
            *failureOut = @"The exact loaded IconRendering image could not be resolved.";
        }
        return NO;
    }

    image->header = (uint64_t)(uintptr_t)info.dli_fbase;
    struct mach_header_64 header = {0};
    if (!remote_read(image->header, &header, sizeof(header)) ||
        header.magic != MH_MAGIC_64 || header.ncmds == 0 ||
        header.ncmds > 1024 || header.sizeofcmds == 0 ||
        header.sizeofcmds > (1U << 20)) {
        if (failureOut) *failureOut = @"The IconRendering Mach header is invalid.";
        return NO;
    }
    NSMutableData *commands = [NSMutableData dataWithLength:header.sizeofcmds];
    if (!remote_read(image->header + sizeof(header),
                     commands.mutableBytes, commands.length)) {
        if (failureOut) *failureOut = @"The IconRendering load commands could not be read.";
        return NO;
    }

    const uint8_t *cursor = commands.bytes;
    const uint8_t *end = cursor + commands.length;
    BOOL haveUUID = NO;
    BOOL haveText = NO;
    for (uint32_t index = 0; index < header.ncmds; index++) {
        if (cursor + sizeof(struct load_command) > end) break;
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command) ||
            cursor + command->cmdsize > end) break;
        if (command->cmd == LC_UUID &&
            command->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uuid =
                (const struct uuid_command *)command;
            memcpy(image->uuid, uuid->uuid, sizeof(image->uuid));
            haveUUID = YES;
        } else if (command->cmd == LC_SEGMENT_64 &&
                   command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, "__TEXT", 16) == 0 &&
                segment->fileoff == 0 &&
                (segment->initprot & VM_PROT_EXECUTE) != 0 &&
                image->header >= segment->vmaddr) {
                image->slide = image->header - segment->vmaddr;
                image->textStart = segment->vmaddr;
                image->textEnd = segment->vmaddr + segment->vmsize;
                haveText = image->textEnd > image->textStart;
            }
        }
        cursor += command->cmdsize;
    }

    BOOL exact = haveUUID && haveText &&
        memcmp(image->uuid, CNDConsumerIconRenderingUUID,
               sizeof(image->uuid)) == 0 &&
        CNDConsumerChicletPatchVMAddress >= image->textStart &&
        CNDConsumerChicletPatchVMAddress + sizeof(uint32_t) <=
            image->textEnd;
    if (!exact) {
        if (failureOut) {
            *failureOut = @"The loaded IconRendering UUID or executable layout does not match the proven build.";
        }
        return NO;
    }
    image->target = CNDConsumerChicletPatchVMAddress + image->slide;
    return YES;
}

/* Read code through an ordinary target-owned heap buffer.  The newly COW'd
 * executable page is intentionally private; asking RemoteCall's shared-page
 * mapper to map that page directly is unnecessary and has failed on physical
 * arm64e for other anonymous/private VM objects. */
static BOOL cnd_consumer_copy_remote_bytes_via_target(
    uint64_t source, void *destination, size_t length)
{
    if (!source || !destination || length == 0 || length > 0x1000 ||
        !remote_call_current_success()) return NO;
    uint64_t scratch = r_dlsym_call(
        R_TIMEOUT, "malloc", length, 0, 0, 0, 0, 0, 0, 0);
    uint64_t copied = scratch ? r_dlsym_call(
        R_TIMEOUT, "memcpy", scratch, source, length,
        0, 0, 0, 0, 0) : 0;
    BOOL ok = copied == scratch && remote_call_current_success() &&
        remote_read(scratch, destination, length);
    if (scratch && remote_call_current_success()) r_free(scratch);
    return ok;
}

static BOOL cnd_consumer_apply_private_chiclet_patch(
    CNDConsumerIconRenderingImage *image, BOOL *alreadyInstalledOut,
    kern_return_t *copyProtectOut, kern_return_t *rxProtectOut,
    NSString **failureOut)
{
    if (alreadyInstalledOut) *alreadyInstalledOut = NO;
    if (copyProtectOut) *copyProtectOut = KERN_NOT_SUPPORTED;
    if (rxProtectOut) *rxProtectOut = KERN_NOT_SUPPORTED;
    if (failureOut) *failureOut = nil;
    if (!image || !image->target) return NO;

    uint32_t before = 0;
    if (!cnd_consumer_copy_remote_bytes_via_target(
            image->target, &before, sizeof(before))) {
        if (failureOut) *failureOut = @"The target instruction could not be read.";
        return NO;
    }
    if (before == CNDConsumerChicletPatchedInstruction) {
        if (alreadyInstalledOut) *alreadyInstalledOut = YES;
        return YES;
    }
    if (before != CNDConsumerChicletOriginalInstruction) {
        if (failureOut) {
            *failureOut = [NSString stringWithFormat:
                @"The target instruction is not the proven MOV (observed=%08x).",
                before];
        }
        return NO;
    }

    uint64_t pageSize = r_dlsym_call(
        R_TIMEOUT, "getpagesize", 0, 0, 0, 0, 0, 0, 0, 0);
    uint64_t taskSelfAddress = cnd_consumer_remote_symbol("mach_task_self_");
    mach_port_t taskSelf = MACH_PORT_NULL;
    if (pageSize < 4096 || (pageSize & (pageSize - 1)) != 0 ||
        !taskSelfAddress ||
        !remote_read(taskSelfAddress, &taskSelf, sizeof(taskSelf)) ||
        !MACH_PORT_VALID(taskSelf)) {
        if (failureOut) *failureOut = @"The target task/page identity is invalid.";
        return NO;
    }
    uint64_t page = image->target & ~(pageSize - 1);
    kern_return_t copyProtect = (kern_return_t)r_dlsym_call(
        R_TIMEOUT, "vm_protect", taskSelf, page, pageSize, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, 0, 0, 0);
    if (copyProtectOut) *copyProtectOut = copyProtect;
    if (copyProtect != KERN_SUCCESS || !remote_call_current_success()) {
        if (failureOut) {
            *failureOut = [NSString stringWithFormat:
                @"The private VM_PROT_COPY transition failed (%d).",
                copyProtect];
        }
        return NO;
    }

    uint64_t scratch = r_dlsym_call(
        R_TIMEOUT, "malloc", sizeof(uint32_t), 0, 0, 0, 0, 0, 0, 0);
    uint32_t patched = CNDConsumerChicletPatchedInstruction;
    BOOL scratchWritten = scratch &&
        remote_write(scratch, &patched, sizeof(patched));
    uint64_t copyResult = scratchWritten ? r_dlsym_call(
        R_TIMEOUT, "memcpy", image->target, scratch, sizeof(patched),
        0, 0, 0, 0, 0) : 0;
    if (scratch && remote_call_current_success()) r_free(scratch);
    if (copyResult == image->target && remote_call_current_success()) {
        (void)r_dlsym_call(
            R_TIMEOUT, "sys_icache_invalidate", image->target,
            sizeof(patched), 0, 0, 0, 0, 0, 0);
    }
    kern_return_t rxProtect = remote_call_current_success()
        ? (kern_return_t)r_dlsym_call(
            R_TIMEOUT, "vm_protect", taskSelf, page, pageSize, FALSE,
            VM_PROT_READ | VM_PROT_EXECUTE, 0, 0, 0)
        : KERN_FAILURE;
    if (rxProtectOut) *rxProtectOut = rxProtect;
    uint32_t after = 0;
    BOOL verified = rxProtect == KERN_SUCCESS &&
        remote_call_current_success() &&
        cnd_consumer_copy_remote_bytes_via_target(
            image->target, &after, sizeof(after)) &&
        after == CNDConsumerChicletPatchedInstruction;
    if (verified) return YES;

    /* Best-effort byte rollback.  The process was already granted invalid
     * code execution, so restoring the proven instruction and RX protection
     * is safe even when the first readback failed. */
    kern_return_t rollbackProtect = (kern_return_t)r_dlsym_call(
        R_TIMEOUT, "vm_protect", taskSelf, page, pageSize, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, 0, 0, 0);
    if (rollbackProtect == KERN_SUCCESS && remote_call_current_success()) {
        uint64_t rollbackScratch = r_dlsym_call(
            R_TIMEOUT, "malloc", sizeof(uint32_t), 0, 0, 0, 0, 0, 0, 0);
        uint32_t original = CNDConsumerChicletOriginalInstruction;
        if (rollbackScratch &&
            remote_write(rollbackScratch, &original, sizeof(original))) {
            (void)r_dlsym_call(
                R_TIMEOUT, "memcpy", image->target, rollbackScratch,
                sizeof(original), 0, 0, 0, 0, 0);
            (void)r_dlsym_call(
                R_TIMEOUT, "sys_icache_invalidate", image->target,
                sizeof(original), 0, 0, 0, 0, 0, 0);
        }
        if (rollbackScratch && remote_call_current_success()) {
            r_free(rollbackScratch);
        }
        (void)r_dlsym_call(
            R_TIMEOUT, "vm_protect", taskSelf, page, pageSize, FALSE,
            VM_PROT_READ | VM_PROT_EXECUTE, 0, 0, 0);
    }
    if (failureOut) {
        *failureOut = [NSString stringWithFormat:
            @"The private instruction patch did not verify "
             "(copy=%llu rx=%d observed=%08x rollback-rw=%d).",
            (unsigned long long)copyResult, rxProtect, after,
            rollbackProtect];
    }
    return NO;
}

static NSDictionary<NSString *, id> * __attribute__((unused))
cnd_consumer_install_physical_instruction_patch(
    NSString *processName, pid_t expectedPID,
    uint64_t expectedProc, uint64_t expectedTask)
{
    if (![processName isEqualToString:@"Spotlight"]) {
        log_user("[SBR_SELFTRACE] target=%s pid=%d skipped=yes "
                 "reason=spotlight-first-safety-gate\n",
                 processName.UTF8String ?: "", expectedPID);
        return @{
            @"ok": @NO, @"stage": @"self-trace-spotlight-probe-only",
            @"message": @"The physical self-trace experiment is intentionally limited to Spotlight until its complete lifecycle verifies.",
            @"process": processName ?: @"",
            @"expectedPID": @(expectedPID),
            @"remoteCallUsed": @NO,
            @"mappingTransport": @"spotlight-first-safety-gate",
        };
    }

    __block CNDConsumerAllowInvalidReport allowance = {
        .traceMeResult = -1,
        .stopResult = -1,
        .detachResult = -1,
        .continueResult = 0,
    };
    RemoteCallSession *session = [[RemoteCallSession alloc]
        initWithProcess:processName
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    if (!session) {
        return @{
            @"ok": @NO, @"stage": @"process-unavailable",
            @"message": @"Spotlight could not open its one-time self-trace and patch session.",
            @"process": processName ?: @"",
            @"expectedPID": @(expectedPID),
            @"remoteCallUsed": @YES,
            @"mappingTransport": @"self-trace-private-cow",
        };
    }
    BOOL identityBound = session.pid == expectedPID &&
        session.taskAddr == expectedTask &&
        proc_find(expectedPID) == expectedProc &&
        proc_task(expectedProc) == expectedTask;
    __block CNDConsumerIconRenderingImage image = {0};
    __block BOOL patched = NO;
    __block BOOL alreadyInstalled = NO;
    __block kern_return_t copyProtect = KERN_NOT_SUPPORTED;
    __block kern_return_t rxProtect = KERN_NOT_SUPPORTED;
    __block NSString *patchFailure = nil;
    if (identityBound) {
        @try {
            remote_call_with_session(session, ^{
                uint64_t statusAddress = r_dlsym_call(
                    R_TIMEOUT, "malloc", sizeof(uint32_t),
                    0, 0, 0, 0, 0, 0, 0);
                if (!statusAddress) {
                    patchFailure = @"Spotlight could not allocate its code-sign status buffer.";
                } else {
                    (void)r_dlsym_call(
                        R_TIMEOUT, "memset", statusAddress, 0,
                        sizeof(uint32_t), 0, 0, 0, 0, 0);
                    int64_t beforeResult = (int64_t)r_dlsym_call(
                        R_TIMEOUT, "csops", (uint64_t)expectedPID,
                        CNDConsumerCSOpsStatus, statusAddress,
                        sizeof(uint32_t), 0, 0, 0, 0);
                    allowance.statusBeforeRead = beforeResult == 0 &&
                        remote_read(statusAddress, &allowance.flagsBefore,
                                    sizeof(allowance.flagsBefore));
                    allowance.parentPID = (int)r_dlsym_call(
                        R_TIMEOUT, "getppid", 0, 0, 0, 0, 0, 0, 0, 0);
                    allowance.alreadyDebugged =
                        allowance.statusBeforeRead &&
                        (allowance.flagsBefore & CNDConsumerCSDebugged) != 0;

                    if (allowance.alreadyDebugged) {
                        allowance.traceMeResult = 0;
                        allowance.flagsAfter = allowance.flagsBefore;
                        allowance.statusAfterRead = YES;
                    } else if (!allowance.statusBeforeRead) {
                        patchFailure = @"Spotlight could not read its initial code-sign status.";
                    } else if (allowance.parentPID != 1) {
                        patchFailure = [NSString stringWithFormat:
                            @"Spotlight parent PID %d is not launchd; self-trace was not attempted.",
                            allowance.parentPID];
                    } else {
                        allowance.traceAttempted = YES;
                        allowance.traceMeResult = (int64_t)r_dlsym_call(
                            R_TIMEOUT, "ptrace", CNDConsumerPTTraceMe,
                            0, 0, 0, 0, 0, 0, 0);
                        if (allowance.traceMeResult < 0) {
                            allowance.traceMeErrno =
                                cnd_consumer_remote_errno();
                            patchFailure = [NSString stringWithFormat:
                                @"Spotlight PT_TRACE_ME failed with errno %d.",
                                allowance.traceMeErrno];
                        } else if (remote_call_current_success()) {
                            (void)r_dlsym_call(
                                R_TIMEOUT, "memset", statusAddress, 0,
                                sizeof(uint32_t), 0, 0, 0, 0, 0);
                            int64_t afterResult = (int64_t)r_dlsym_call(
                                R_TIMEOUT, "csops", (uint64_t)expectedPID,
                                CNDConsumerCSOpsStatus, statusAddress,
                                sizeof(uint32_t), 0, 0, 0, 0);
                            allowance.statusAfterRead = afterResult == 0 &&
                                remote_read(statusAddress,
                                    &allowance.flagsAfter,
                                    sizeof(allowance.flagsAfter));
                            if (!allowance.statusAfterRead ||
                                !(allowance.flagsAfter &
                                  CNDConsumerCSDebugged)) {
                                patchFailure = @"PT_TRACE_ME returned success but cs_allow_invalid did not set CS_DEBUGGED.";
                            }
                        }
                    }

                    BOOL allowed = allowance.statusAfterRead &&
                        (allowance.flagsAfter &
                         CNDConsumerCSDebugged) != 0;
                    if (allowed && remote_call_current_success()) {
                        BOOL resolved =
                            cnd_consumer_resolve_iconrendering_image(
                                &image, &patchFailure);
                        patched = resolved &&
                            cnd_consumer_apply_private_chiclet_patch(
                                &image, &alreadyInstalled, &copyProtect,
                                &rxProtect, &patchFailure);
                    }
                    if (remote_call_current_success()) r_free(statusAddress);
                }
                allowance.targetRemoteHealthy =
                    remote_call_current_success();
            });
        } @catch (NSException *exception) {
            patchFailure = [NSString stringWithFormat:@"%@:%@",
                exception.name ?: @"exception",
                exception.reason ?: @"unknown"];
            allowance.targetRemoteHealthy = NO;
        }
    } else {
        patchFailure = @"The consumer identity changed while opening its patch session.";
    }

    if ([session hasLocalState] &&
        ![session hasInFlightSyntheticCall]) {
        (void)[session destroyRemoteCall];
    }
    if ([session hasInFlightSyntheticCall]) {
        allowance.targetTeardownDeferred =
            [session deferTeardownForInFlightSyntheticCall];
    }
    allowance.targetSessionClosed = ![session hasLocalState];

    NSString *cleanupFailure = nil;
    BOOL cleanupOK = YES;
    /* A successful PT_TRACE_ME must always be detached.  Also run the
     * bounded parent cleanup when its return could not be observed because
     * the target transport failed or remained in flight: that is precisely
     * the case where assuming failure could leave Spotlight traced.  A
     * definite, cleanly returned ptrace failure needs no cleanup. */
    BOOL traceMayBeActive = allowance.traceAttempted &&
        (allowance.traceMeResult == 0 ||
         !allowance.targetRemoteHealthy ||
         allowance.targetTeardownDeferred ||
         !allowance.targetSessionClosed);
    if (traceMayBeActive) {
        BOOL cleanupIdentityStable =
            proc_find(expectedPID) == expectedProc &&
            proc_task(expectedProc) == expectedTask;
        cleanupOK = cleanupIdentityStable &&
            cnd_consumer_finish_self_trace_via_launchd(
                expectedPID, &allowance, &cleanupFailure);
        if (!cleanupIdentityStable) {
            cleanupFailure = @"Spotlight changed identity before PID-1 could detach the self-trace.";
        }
    } else {
        allowance.stopResult = 0;
        allowance.detachResult = 0;
        allowance.continueResult = 0;
        allowance.parentRemoteHealthy = YES;
        allowance.parentSessionClosed = YES;
    }

    BOOL finalIdentityStable = proc_find(expectedPID) == expectedProc &&
        proc_task(expectedProc) == expectedTask;
    BOOL allowed = allowance.statusAfterRead &&
        (allowance.flagsAfter & CNDConsumerCSDebugged) != 0;
    BOOL ok = identityBound && allowed && patched &&
        allowance.targetRemoteHealthy && allowance.targetSessionClosed &&
        !allowance.targetTeardownDeferred && cleanupOK &&
        finalIdentityStable;
    log_user("[SBR_SELFTRACE] target=%s pid=%d ok=%s parent=%d "
             "flags=%08x->%08x trace=%lld/%d stop=%lld/%d "
             "detach=%lld/%d continue=%lld/%d target-closed=%s "
             "parent-closed=%s\n",
             processName.UTF8String ?: "", expectedPID,
             (allowed && cleanupOK) ? "yes" : "no",
             allowance.parentPID, allowance.flagsBefore,
             allowance.flagsAfter, (long long)allowance.traceMeResult,
             allowance.traceMeErrno, (long long)allowance.stopResult,
             allowance.stopErrno, (long long)allowance.detachResult,
             allowance.detachErrno, (long long)allowance.continueResult,
             allowance.continueErrno,
             allowance.targetSessionClosed ? "yes" : "no",
             allowance.parentSessionClosed ? "yes" : "no");
    log_user("[SBR_COW] target=%s pid=%d ok=%s image=%s slide=%#llx "
             "address=%#llx copy-protect=%d rx-protect=%d existing=%s "
             "transport=%s closed=%s\n",
             processName.UTF8String ?: "", expectedPID,
             ok ? "yes" : "no", image.path[0] ? image.path : "-",
             (unsigned long long)image.slide,
             (unsigned long long)image.target, copyProtect, rxProtect,
             alreadyInstalled ? "yes" : "no",
             allowance.targetRemoteHealthy ? "healthy" : "failed",
             allowance.targetSessionClosed ? "yes" : "no");
    NSString *resultFailure = cleanupFailure ?: patchFailure;
    NSString *stage = !allowed ? @"cs-allow-invalid" :
        (!cleanupOK ? @"self-trace-cleanup" : @"presentation-install");
    return @{
        @"ok": @(ok),
        @"stage": ok ? @"presentation-ready" : stage,
        @"message": ok
            ? (alreadyInstalled
                ? @"The exact private IconRendering chiclet patch was already active."
                : @"Spotlight self-trace, XNU cs_allow_invalid, the exact private IconRendering patch, and PID-1 detach all verified.")
            : (resultFailure ?: @"The Spotlight self-trace and private IconRendering patch did not verify."),
        @"process": processName ?: @"",
        @"pid": @(session.pid),
        @"expectedPID": @(expectedPID),
        @"identityBound": @(identityBound),
        @"finalIdentityStable": @(finalIdentityStable),
        @"csFlagsBefore": @(allowance.flagsBefore),
        @"csFlagsAfter": @(allowance.flagsAfter),
        @"parentPID": @(allowance.parentPID),
        @"ptraceTraceMeResult": @(allowance.traceMeResult),
        @"ptraceTraceMeErrno": @(allowance.traceMeErrno),
        @"ptraceAttachResult": @(allowance.traceMeResult),
        @"ptraceAttachErrno": @(allowance.traceMeErrno),
        @"stopResult": @(allowance.stopResult),
        @"stopErrno": @(allowance.stopErrno),
        @"ptraceDetachResult": @(allowance.detachResult),
        @"ptraceDetachErrno": @(allowance.detachErrno),
        @"continueResult": @(allowance.continueResult),
        @"continueErrno": @(allowance.continueErrno),
        @"launchdSessionClosed": @(allowance.parentSessionClosed),
        @"imagePath": image.path[0]
            ? ([NSString stringWithUTF8String:image.path] ?: @"") : @"",
        @"imageHeader": @(image.header),
        @"imageSlide": @(image.slide),
        @"patchAddress": @(image.target),
        @"copyProtectResult": @(copyProtect),
        @"rxProtectResult": @(rxProtect),
        @"alreadyInstalled": @(alreadyInstalled),
        @"installedCount": @(ok ? 1 : 0),
        @"methodsReadbackVerified": @(patched),
        @"transportClean": @(allowance.targetRemoteHealthy &&
                              allowance.parentRemoteHealthy),
        @"remoteOK": @(allowance.targetRemoteHealthy),
        @"closed": @(allowance.targetSessionClosed &&
                      allowance.parentSessionClosed),
        @"teardownDeferred": @(allowance.targetTeardownDeferred ||
                                allowance.parentTeardownDeferred),
        @"remoteCallUsed": @YES,
        @"mappingTransport": @"self-trace-private-cow",
        @"libraryValidationPolicyFallbackUsed": @NO,
        @"libraryValidationErrno": @0,
    };
}

static NSDictionary<NSString *, id> *
cnd_consumer_install_for_process(NSString *processName,
                                 pid_t expectedPID,
                                 double displayScale,
                                 NSDictionary<NSString *, NSData *> *
                                     staticIconDataByBundle,
                                 BOOL refreshSpringBoardCaches,
                                 BOOL updateStaticDynamicIcons)
{
    if (processName.length == 0) {
        return @{
            @"ok": @NO, @"stage": @"process-name",
            @"message": @"A consumer process name is required.",
            @"remoteCallUsed": @NO,
        };
    }

    BOOL usesLabRemoteCall = remote_call_lab_backend_opted_in();
    uint64_t expectedProc = 0;
    uint64_t expectedTask = 0;
    if (expectedPID <= 1) {
        if (usesLabRemoteCall) {
            pid_t labPID = 0;
            if (cnd_lab_resolve_process_pid(
                    processName.UTF8String, &labPID) == 0) {
                expectedPID = labPID;
            }
        } else {
            expectedProc = proc_find_by_name(processName.UTF8String);
            expectedPID = is_kaddr_valid(expectedProc)
                ? (pid_t)kread32(expectedProc + off_proc_p_pid) : 0;
            expectedTask = is_kaddr_valid(expectedProc)
                ? proc_task(expectedProc) : 0;
        }
    }
    if (expectedPID > 1 && !usesLabRemoteCall) {
        if (!expectedProc) expectedProc = proc_find(expectedPID);
        if (!expectedTask) {
            expectedTask = expectedProc ? proc_task(expectedProc) : 0;
        }
        const char *kernelName = expectedProc
            ? proc_get_p_name(expectedProc) : NULL;
        if (!expectedProc || !expectedTask || !kernelName ||
            strcmp(kernelName, processName.UTF8String) != 0) {
            return @{
                @"ok": @NO, @"stage": @"process-identity",
                @"message": @"The exact consumer PID is no longer live.",
                @"process": processName,
                @"expectedPID": @(expectedPID),
                @"remoteCallUsed": @NO,
            };
        }
    }

    /* Physical arm64e uses the data-only, Apple-signed IMP redirect proven in
     * the VM. It neither maps executable code nor modifies shared-cache text.
     * The VM retains the four-hook direct-task path for comparison. */
    if (!usesLabRemoteCall) {
        return cnd_consumer_install_physical_flat_image_redirect(
            processName, expectedPID, expectedProc, expectedTask,
            staticIconDataByBundle ?: @{},
            YES,
            refreshSpringBoardCaches,
            updateStaticDynamicIcons);
    }

    /*
     * Opening Cyanide's executable and mapping it executable are distinct
     * sandbox operations. SpringBoard and Spotlight can read the installed
     * app bundle, but physical iOS rejects the RX mmap with EPERM unless the
     * target has consumed a com.apple.sandbox.executable extension. Issue one
     * fresh token from launchd before opening the one and only target session;
     * the token is copied locally, launchd is closed, and the exact target PID
     * consumes it on that existing session immediately before installation.
     */
    NSData *executableToken = nil;
    NSString *executableGrantFailure = nil;
    BOOL executableTokenIssued = NO;
    BOOL launchdGrantSessionClosed = YES;
    BOOL launchdGrantTeardownDeferred = NO;
    if (!remote_call_lab_backend_opted_in()) {
        NSString *executablePath = NSBundle.mainBundle.executablePath;
        RemoteCallSession *launchd = executablePath.length
            ? [[RemoteCallSession alloc]
                initWithProcess:@"launchd"
                useMigFilterBypass:NO
                firstExceptionTimeoutMS:10000]
            : nil;
        if (!launchd) {
            executableGrantFailure = executablePath.length
                ? @"launchd could not be opened to issue the executable mapping extension"
                : @"Cyanide's installed executable path is unavailable";
            launchdGrantSessionClosed = launchd == nil;
        } else {
            __block BOOL issueHealthy = NO;
            __block uint64_t remoteToken = 0;
            __block NSMutableData *copiedToken = nil;
            remote_call_with_session(launchd, ^{
                uint64_t remoteClass = r_alloc_str(
                    "com.apple.sandbox.executable");
                uint64_t remotePath = r_alloc_str(
                    executablePath.fileSystemRepresentation);
                if (remoteClass && remotePath) {
                    remoteToken = r_dlsym_call(
                        R_TIMEOUT, "sandbox_extension_issue_file",
                        remoteClass, remotePath, 0,
                        0, 0, 0, 0, 0);
                }
                uint64_t tokenLength = remoteToken
                    ? r_dlsym_call(R_TIMEOUT, "strlen", remoteToken,
                                   0, 0, 0, 0, 0, 0, 0)
                    : 0;
                if (tokenLength > 0 && tokenLength < 0x4000 &&
                    remote_call_current_success()) {
                    copiedToken = [NSMutableData
                        dataWithLength:(NSUInteger)tokenLength + 1];
                    if (!remote_read(remoteToken, copiedToken.mutableBytes,
                                     copiedToken.length)) {
                        copiedToken = nil;
                    }
                }
                issueHealthy = remote_call_current_success();
                if (remoteToken && issueHealthy) r_free(remoteToken);
                if (remotePath && remote_call_current_success()) {
                    r_free(remotePath);
                }
                if (remoteClass && remote_call_current_success()) {
                    r_free(remoteClass);
                }
                issueHealthy = issueHealthy &&
                    remote_call_current_success();
            });
            if ([launchd hasLocalState] &&
                ![launchd hasInFlightSyntheticCall]) {
                (void)[launchd destroyRemoteCall];
            }
            if ([launchd hasInFlightSyntheticCall]) {
                launchdGrantTeardownDeferred =
                    [launchd deferTeardownForInFlightSyntheticCall];
            }
            launchdGrantSessionClosed = ![launchd hasLocalState];
            if (issueHealthy && copiedToken.length > 1 &&
                launchdGrantSessionClosed &&
                !launchdGrantTeardownDeferred) {
                executableToken = [copiedToken copy];
                executableTokenIssued = YES;
            } else {
                executableGrantFailure = [NSString stringWithFormat:
                    @"launchd executable-token issuance failed "
                     "(issued=%@ closed=%@ deferred=%@)",
                    copiedToken.length > 1 ? @"yes" : @"no",
                    launchdGrantSessionClosed ? @"yes" : @"no",
                    launchdGrantTeardownDeferred ? @"yes" : @"no"];
            }
        }
        if (!executableTokenIssued) {
            return @{
                @"ok": @NO, @"stage": @"executable-sandbox-grant",
                @"message": executableGrantFailure ?:
                    @"The executable mapping extension could not be issued.",
                @"process": processName,
                @"expectedPID": @(expectedPID),
                @"executableTokenIssued": @NO,
                @"launchdGrantSessionClosed":
                    @(launchdGrantSessionClosed),
                @"launchdGrantTeardownDeferred":
                    @(launchdGrantTeardownDeferred),
                @"remoteCallUsed": @YES,
            };
        }
    }

    RemoteCallSession *session = [[RemoteCallSession alloc]
        initWithProcess:processName
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    if (!session) {
        return @{
            @"ok": @NO, @"stage": @"process-unavailable",
            @"message": @"The consumer process is not currently available.",
            @"process": processName,
            @"expectedPID": @(expectedPID),
            @"remoteCallUsed": @YES,
        };
    }
    int sessionPID = session.pid;
    uint64_t sessionTask = session.taskAddr;

    pid_t labIdentityPID = 0;
    int labIdentityResult = usesLabRemoteCall
        ? cnd_lab_resolve_process_pid(
            processName.UTF8String, &labIdentityPID)
        : ENOTSUP;
    BOOL identityBound = usesLabRemoteCall
        ? (expectedPID > 1 && labIdentityResult == 0 &&
           labIdentityPID == expectedPID && sessionPID == expectedPID)
        : (expectedPID <= 1 ||
           (sessionPID == expectedPID && sessionTask == expectedTask &&
            proc_find(expectedPID) == expectedProc &&
            proc_task(expectedProc) == expectedTask));
    if (!identityBound) {
        BOOL closed = YES;
        BOOL deferred = NO;
        if ([session hasLocalState]) {
            (void)[session destroyRemoteCall];
            closed = ![session hasLocalState];
        }
        if ([session hasInFlightSyntheticCall]) {
            deferred = [session deferTeardownForInFlightSyntheticCall];
        } else if ([session hasLocalState]) {
            // Identity drift means the exact bound target is no longer the
            // live process requested by this operation. Abandon is safe only
            // after that fact has been established.
            [session abandonRemoteCall];
            closed = YES;
        }
        return @{
            @"ok": @NO, @"stage": @"process-identity",
            @"message": @"The consumer process changed while its one-time session was opening.",
            @"process": processName,
            @"expectedPID": @(expectedPID),
            @"actualPID": @(sessionPID),
            @"identityBound": @NO,
            @"closed": @(closed),
            @"teardownDeferred": @(deferred),
            @"remoteCallUsed": @YES,
        };
    }

    __block CNDIconServicesConsumerHookReport report = {0};
    __block BOOL remoteOK = NO;
    __block BOOL executableTokenConsumed =
        remote_call_lab_backend_opted_in();
    __block int64_t executableTokenHandle =
        executableTokenConsumed ? 0 : -1;
    NSString *exceptionText = nil;
    @try {
        remote_call_with_session(session, ^{
            // Physical signed-vnode opens and code-signature validation can
            // block well beyond the generic 10-second stable-call floor. A
            // return timeout cannot be treated as cancellation because the
            // target is still running with RemoteCall's sentinel LR.
            int previousFloor = remote_call_set_stable_timeout_floor_ms(120000);
            @try {
                uint64_t remoteExecutableToken = executableToken
                    ? r_alloc_str(executableToken.bytes) : 0;
                if (remoteExecutableToken) {
                    executableTokenHandle = (int64_t)r_dlsym_call(
                        R_TIMEOUT, "sandbox_extension_consume",
                        remoteExecutableToken, 0, 0, 0, 0, 0, 0, 0);
                    executableTokenConsumed =
                        executableTokenHandle >= 0 &&
                        remote_call_current_success();
                    if (remote_call_current_success()) {
                        r_free(remoteExecutableToken);
                    }
                }
                if (executableTokenConsumed) {
                    (void)CNDIconServicesConsumerHookInstallInCurrentSession(
                        processName.UTF8String, displayScale, &report);
                } else {
                    report.pid = sessionPID;
                    snprintf(report.host, sizeof(report.host), "%s",
                             processName.UTF8String ?: "");
                    cnd_consumer_reason(
                        &report,
                        "consumer-executable-sandbox-grant-consume-failed");
                }
                remoteOK = remote_call_current_success();
            } @finally {
                (void)remote_call_set_stable_timeout_floor_ms(previousFloor);
            }
        });
    } @catch (NSException *exception) {
        exceptionText = [NSString stringWithFormat:@"%@:%@",
            exception.name ?: @"exception",
            exception.reason ?: @"unknown"];
        remoteOK = NO;
    }

    BOOL closed = NO;
    BOOL abandoned = NO;
    BOOL teardownDeferred = NO;
    if ([session hasLocalState] &&
        ![session hasInFlightSyntheticCall]) {
        (void)[session destroyRemoteCall];
        closed = ![session hasLocalState];
    }
    if ([session hasInFlightSyntheticCall]) {
        teardownDeferred =
            [session deferTeardownForInFlightSyntheticCall];
    } else if ([session hasLocalState]) {
        // Never use abandon as a generic error cleanup for a live target. It
        // destroys the exception receive right and turns any delayed return
        // into a process crash. A stable live identity is left to normal
        // object teardown; only a proven-dead/drifted target may be abandoned.
        uint64_t liveProc = !usesLabRemoteCall && expectedPID > 1
            ? proc_find(expectedPID) : 0;
        BOOL targetGone = !usesLabRemoteCall && expectedPID > 1 &&
            (liveProc != expectedProc ||
             (liveProc && proc_task(liveProc) != expectedTask));
        if (targetGone) {
            [session abandonRemoteCall];
            abandoned = YES;
            closed = YES;
        }
    } else {
        closed = YES;
    }
    BOOL installed =
        report.result == CNDIconServicesConsumerHookInstalled ||
        report.result == CNDIconServicesConsumerHookAlreadyInstalled;
    pid_t finalLabPID = 0;
    int finalLabIdentityResult = usesLabRemoteCall
        ? cnd_lab_resolve_process_pid(
            processName.UTF8String, &finalLabPID)
        : ENOTSUP;
    BOOL finalIdentityStable = usesLabRemoteCall
        ? (expectedPID > 1 && finalLabIdentityResult == 0 &&
           finalLabPID == expectedPID && sessionPID == expectedPID)
        : (expectedPID <= 1 ||
           (sessionPID == expectedPID &&
            proc_find(expectedPID) == expectedProc &&
            proc_task(expectedProc) == expectedTask));
    BOOL ok = installed && report.methodsReadbackVerified &&
        report.transportClean && remoteOK && closed && !abandoned &&
        finalIdentityStable;
    NSMutableDictionary *result =
        [CNDIconServicesConsumerHookReportDictionary(&report) mutableCopy];
    [result addEntriesFromDictionary:@{
        @"ok": @(ok),
        @"stage": ok ? @"presentation-ready" : @"presentation-install",
        @"message": ok
            ? (report.libraryValidationPolicyFallbackUsed
                ? @"The process-wide marker-aware presentation mapping is ready; the exact signed vnode mapping passed after the target rejected dylib-style library validation."
                : @"The process-wide marker-aware presentation mapping is ready.")
            : [NSString stringWithFormat:
                @"The marker-aware presentation mapping did not verify "
                 "(%@; executable-grant=%@/%@ handle=%lld).",
                [NSString stringWithUTF8String:report.reason] ?: @"unknown",
                executableTokenIssued ? @"issued" : @"not-issued",
                executableTokenConsumed ? @"consumed" : @"not-consumed",
                (long long)executableTokenHandle],
        @"process": processName,
        @"expectedPID": @(expectedPID),
        @"identityBound": @(identityBound),
        @"finalIdentityStable": @(finalIdentityStable),
        @"remoteCallUsed": @YES,
        @"mappingTransport": @"signed-vnode-remotecall",
        @"executableTokenIssued": @(executableTokenIssued),
        @"executableTokenConsumed": @(executableTokenConsumed),
        @"executableTokenHandle": @(executableTokenHandle),
        @"launchdGrantSessionClosed": @(launchdGrantSessionClosed),
        @"launchdGrantTeardownDeferred":
            @(launchdGrantTeardownDeferred),
        @"remoteOK": @(remoteOK),
        @"closed": @(closed),
        @"abandoned": @(abandoned),
        @"teardownDeferred": @(teardownDeferred),
        @"exception": exceptionText ?: @"",
    }];
    return result;
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerHookInstallForProcess(NSString *processName,
                                             double displayScale)
{
    return cnd_consumer_install_for_process(
        processName, 0, displayScale, @{}, NO, NO);
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerHookInstallForPID(pid_t pid,
                                         NSString *expectedProcessName,
                                         double displayScale)
{
    if (pid <= 1) {
        return @{
            @"ok": @NO, @"stage": @"process-identity",
            @"message": @"A valid consumer PID is required.",
            @"process": expectedProcessName ?: @"",
            @"expectedPID": @(pid),
            @"remoteCallUsed": @NO,
        };
    }
    return cnd_consumer_install_for_process(
        expectedProcessName, pid, displayScale, @{}, NO, NO);
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerHookInstallForPIDWithStaticIcons(
    pid_t pid,
    NSString *expectedProcessName,
    double displayScale,
    NSDictionary<NSString *, NSData *> *staticIconDataByBundle)
{
    return CNDIconServicesConsumerHookInstallForPIDWithOptions(
        pid, expectedProcessName, displayScale,
        staticIconDataByBundle, YES, YES);
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerHookInstallForPIDWithOptions(
    pid_t pid,
    NSString *expectedProcessName,
    double displayScale,
    NSDictionary<NSString *, NSData *> *staticIconDataByBundle,
    BOOL refreshSpringBoardCaches,
    BOOL updateStaticDynamicIcons)
{
    if (pid <= 1) {
        return @{
            @"ok": @NO, @"stage": @"process-identity",
            @"message": @"A valid consumer PID is required.",
            @"process": expectedProcessName ?: @"",
            @"expectedPID": @(pid),
            @"remoteCallUsed": @NO,
        };
    }
    return cnd_consumer_install_for_process(
        expectedProcessName, pid, displayScale,
        staticIconDataByBundle ?: @{},
        refreshSpringBoardCaches,
        updateStaticDynamicIcons);
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerHookRefreshSpringBoardForPID(pid_t pid)
{
    if (pid <= 1) {
        return @{
            @"ok": @NO, @"stage": @"process-identity",
            @"message": @"A valid SpringBoard PID is required.",
            @"process": @"SpringBoard",
            @"expectedPID": @(pid),
            @"remoteCallUsed": @NO,
        };
    }
    if (remote_call_lab_backend_opted_in()) {
        pid_t livePID = 0;
        int resolveResult = cnd_lab_resolve_process_pid(
            "SpringBoard", &livePID);
        if (resolveResult != 0 || livePID != pid) {
            return @{
                @"ok": @NO, @"stage": @"process-identity",
                @"message": @"The exact SpringBoard PID is no longer live.",
                @"process": @"SpringBoard",
                @"expectedPID": @(pid),
                @"actualPID": @(livePID),
                @"remoteCallUsed": @NO,
            };
        }
        return cnd_consumer_install_physical_flat_image_redirect(
            @"SpringBoard", pid, 0, 0, @{}, NO, YES, NO);
    }
    uint64_t expectedProc = proc_find(pid);
    uint64_t expectedTask = expectedProc ? proc_task(expectedProc) : 0;
    const char *kernelName = expectedProc
        ? proc_get_p_name(expectedProc) : NULL;
    if (!expectedProc || !expectedTask || !kernelName ||
        strcmp(kernelName, "SpringBoard") != 0) {
        return @{
            @"ok": @NO, @"stage": @"process-identity",
            @"message": @"The exact SpringBoard PID is no longer live.",
            @"process": @"SpringBoard",
            @"expectedPID": @(pid),
            @"remoteCallUsed": @NO,
        };
    }
    return cnd_consumer_install_physical_flat_image_redirect(
        @"SpringBoard", pid, expectedProc, expectedTask, @{},
        NO, YES, NO);
}

NSDictionary<NSString *, id> *
CNDIconServicesConsumerHookAuditSpringBoard(
    NSArray<NSString *> *bundleIdentifiers)
{
    NSMutableOrderedSet<NSString *> *sanitized =
        [NSMutableOrderedSet orderedSet];
    for (id value in bundleIdentifiers ?: @[]) {
        if (![value isKindOfClass:NSString.class]) continue;
        NSString *identifier = [(NSString *)value
            stringByTrimmingCharactersInSet:
                NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (identifier.length > 0) [sanitized addObject:identifier];
    }
    NSArray<NSString *> *targets = sanitized.array;
    if (targets.count == 0 || targets.count > 512) {
        return @{
            @"ok": @NO,
            @"stage": @"audit-input",
            @"message": @"The SpringBoard consumer audit requires 1-512 journaled bundle identifiers.",
            @"targetCount": @(targets.count),
            @"remoteCallUsed": @NO,
        };
    }
    if (!kexploit_krw_ready()) {
        return @{
            @"ok": @NO,
            @"stage": @"krw-unavailable",
            @"message": @"Kernel read/write is required to inspect SpringBoard's current consumer objects.",
            @"remoteCallUsed": @NO,
        };
    }

    uint64_t expectedProc = proc_find_by_name("SpringBoard");
    pid_t expectedPID = is_kaddr_valid(expectedProc)
        ? (pid_t)kread32(expectedProc + off_proc_p_pid) : 0;
    uint64_t expectedTask = is_kaddr_valid(expectedProc)
        ? proc_task(expectedProc) : 0;
    if (expectedPID <= 1 || !is_kaddr_valid(expectedTask)) {
        return @{
            @"ok": @NO,
            @"stage": @"springboard-unavailable",
            @"message": @"The exact SpringBoard process identity is unavailable.",
            @"remoteCallUsed": @NO,
        };
    }

    if (!remote_call_lab_backend_opted_in()) {
        g_RC_targetProcOverride = expectedProc;
    }
    RemoteCallSession *session = [[RemoteCallSession alloc]
        initWithProcess:@"SpringBoard"
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    g_RC_targetProcOverride = 0;
    if (!session) {
        return @{
            @"ok": @NO,
            @"stage": @"springboard-session",
            @"message": @"The read-only SpringBoard audit session could not be opened.",
            @"pid": @(expectedPID),
            @"remoteCallUsed": @YES,
        };
    }

    BOOL identityBound = session.pid == expectedPID &&
        session.taskAddr == expectedTask &&
        proc_find(expectedPID) == expectedProc &&
        proc_task(expectedProc) == expectedTask;
    __block NSDictionary<NSString *, id> *snapshot = nil;
    __block BOOL remoteOK = NO;
    NSString *exceptionText = nil;
    if (identityBound) {
        @try {
            remote_call_with_session(session, ^{
                snapshot =
                    themer_audit_springboard_iconservices_consumers_in_session(
                        targets);
                remoteOK = remote_call_current_success();
            });
        } @catch (NSException *exception) {
            exceptionText = [NSString stringWithFormat:@"%@:%@",
                exception.name ?: @"exception",
                exception.reason ?: @"unknown"];
            remoteOK = NO;
        }
    }

    if ([session hasLocalState] && ![session hasInFlightSyntheticCall]) {
        (void)[session destroyRemoteCall];
    }
    BOOL teardownDeferred = NO;
    if ([session hasInFlightSyntheticCall]) {
        teardownDeferred = [session deferTeardownForInFlightSyntheticCall];
    }
    BOOL closed = ![session hasLocalState];
    BOOL finalIdentityStable = proc_find(expectedPID) == expectedProc &&
        proc_task(expectedProc) == expectedTask;
    BOOL ok = identityBound && remoteOK && [snapshot[@"ok"] boolValue] &&
        closed && !teardownDeferred && finalIdentityStable;
    NSMutableDictionary<NSString *, id> *result =
        [NSMutableDictionary dictionaryWithDictionary:snapshot ?: @{}];
    result[@"ok"] = @(ok);
    result[@"stage"] = ok ? @"springboard-consumers-audited" :
        (snapshot[@"stage"] ?: @"springboard-consumer-audit");
    result[@"message"] = ok
        ? @"SpringBoard's canonical, leaf, and materialized switcher icon identities were inspected without mutation."
        : (snapshot[@"message"] ?:
            @"The SpringBoard consumer audit did not complete safely.");
    result[@"pid"] = @(expectedPID);
    result[@"identityBound"] = @(identityBound);
    result[@"finalIdentityStable"] = @(finalIdentityStable);
    result[@"remoteOK"] = @(remoteOK);
    result[@"closed"] = @(closed);
    result[@"teardownDeferred"] = @(teardownDeferred);
    result[@"exception"] = exceptionText ?: @"";
    result[@"remoteCallUsed"] = @YES;
    result[@"mutationsIssued"] = @NO;
    return result;
}
