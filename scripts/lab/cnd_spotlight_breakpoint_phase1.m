#import <Foundation/Foundation.h>

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <objc/runtime.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern kern_return_t mach_vm_region_recurse(
    vm_map_t targetTask, mach_vm_address_t *address,
    mach_vm_size_t *size, natural_t *depth,
    vm_region_recurse_info_t info, mach_msg_type_number_t *infoCount);
extern kern_return_t mach_vm_read_overwrite(
    vm_map_t targetTask, mach_vm_address_t address,
    mach_vm_size_t size, mach_vm_address_t data,
    mach_vm_size_t *outSize);

#ifndef CND_BP_PHASE1_OUTPUT_TOKEN
#define CND_BP_PHASE1_OUTPUT_TOKEN ""
#endif

#ifndef CND_BP_PHASE1_REPORT_PATH
#define CND_BP_PHASE1_REPORT_PATH \
    "/var/tmp/cyanide-spotlight-breakpoint-phase1.log"
#endif

/* These values are the verified iOS 26 vPhone control from
 * cnd_spotlight_chiclet_patch.m.  This probe never writes the instruction. */
static const uint64_t CNDIconRenderingPatchVMAddress = 0x1b0d5065cULL;
static const uint32_t CNDExpectedInstruction = 0x52800028U; /* mov w8, #1 */
static const uint8_t CNDExpectedIconRenderingUUID[16] = {
    0x81, 0xcb, 0x5b, 0xe9, 0xb5, 0xda, 0x35, 0x51,
    0x90, 0xfd, 0x90, 0xd6, 0xe1, 0x8d, 0x56, 0x9a,
};

static const char *const CNDReportPath = CND_BP_PHASE1_REPORT_PATH;
static const char *const CNDIconRenderingPath =
    "/System/Library/PrivateFrameworks/IconRendering.framework/"
    "IconRendering";

typedef id (*CNDInitFromSerializedDataIMP)(id, SEL, id, id, NSError **);

typedef struct {
    uint64_t threadID;
    mach_port_t machThread;
    uint64_t events;
} CNDThreadRecord;

static CNDInitFromSerializedDataIMP gOriginalInitFromSerializedData;
static pthread_mutex_t gLogLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t gRecordLock = PTHREAD_MUTEX_INITIALIZER;
static CNDThreadRecord gThreadRecords[32];
static uint32_t gThreadRecordCount;
static uint64_t gEventCount;
static bool gContractVerified;

static void CNDLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDLog(const char *format, ...)
{
    pthread_mutex_lock(&gLogLock);
    int descriptor = open(CNDReportPath,
                          O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (descriptor >= 0) {
        char line[4096] = {0};
        va_list arguments;
        va_start(arguments, format);
        int length = vsnprintf(line, sizeof(line), format, arguments);
        va_end(arguments);
        if (length > 0) {
            size_t amount = (size_t)length < sizeof(line)
                ? (size_t)length : sizeof(line) - 1U;
            (void)write(descriptor, line, amount);
        }
        close(descriptor);
    }
    pthread_mutex_unlock(&gLogLock);
}

static bool CNDHasSuffix(const char *value, const char *suffix)
{
    if (!value || !suffix) return false;
    size_t valueLength = strlen(value);
    size_t suffixLength = strlen(suffix);
    return valueLength >= suffixLength &&
        memcmp(value + valueLength - suffixLength,
               suffix, suffixLength) == 0;
}

static void CNDUUIDString(const uint8_t uuid[16], char result[37])
{
    snprintf(result, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
             "%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5], uuid[6], uuid[7],
             uuid[8], uuid[9], uuid[10], uuid[11],
             uuid[12], uuid[13], uuid[14], uuid[15]);
}

static bool CNDImageUUID(const struct mach_header_64 *header,
                         uint8_t result[16])
{
    if (!header || header->magic != MH_MAGIC_64) return false;
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    for (uint32_t index = 0; index < header->ncmds; index++) {
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command)) return false;
        if (command->cmd == LC_UUID &&
            command->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uuid =
                (const struct uuid_command *)command;
            memcpy(result, uuid->uuid, 16U);
            return true;
        }
        cursor += command->cmdsize;
    }
    return false;
}

static bool CNDImageTextRange(const struct mach_header_64 *header,
                              uint64_t *startOut, uint64_t *sizeOut)
{
    if (!header || header->magic != MH_MAGIC_64) return false;
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    for (uint32_t index = 0; index < header->ncmds; index++) {
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command)) return false;
        if (command->cmd == LC_SEGMENT_64 &&
            command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                (const struct segment_command_64 *)command;
            if (strncmp(segment->segname, SEG_TEXT,
                        sizeof(segment->segname)) == 0) {
                if (startOut) *startOut = segment->vmaddr;
                if (sizeOut) *sizeOut = segment->vmsize;
                return segment->vmsize != 0;
            }
        }
        cursor += command->cmdsize;
    }
    return false;
}

static const struct mach_header_64 *CNDIconRenderingHeader(
    intptr_t *slideOut, const char **pathOut)
{
    uint32_t count = _dyld_image_count();
    for (uint32_t index = 0; index < count; index++) {
        const char *path = _dyld_get_image_name(index);
        if (!CNDHasSuffix(path, CNDIconRenderingPath)) continue;
        const struct mach_header *header = _dyld_get_image_header(index);
        if (!header || header->magic != MH_MAGIC_64) return NULL;
        if (slideOut) *slideOut = _dyld_get_image_vmaddr_slide(index);
        if (pathOut) *pathOut = path;
        return (const struct mach_header_64 *)header;
    }
    return NULL;
}

static bool CNDRegionInfo(mach_vm_address_t address,
                          vm_region_submap_info_data_64_t *infoOut,
                          mach_vm_address_t *startOut,
                          mach_vm_size_t *sizeOut)
{
    mach_vm_address_t start = address;
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info = {0};
    for (;;) {
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t result = mach_vm_region_recurse(
            mach_task_self(), &start, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        if (result != KERN_SUCCESS || address < start ||
            address >= start + size) return false;
        if (!info.is_submap) break;
        depth++;
        start = address;
    }
    if (infoOut) *infoOut = info;
    if (startOut) *startOut = start;
    if (sizeOut) *sizeOut = size;
    return true;
}

static bool CNDReadWord(mach_vm_address_t address, uint32_t *wordOut)
{
    if (!address || !wordOut) return false;
    uint32_t word = 0;
    mach_vm_size_t amount = 0;
    kern_return_t result = mach_vm_read_overwrite(
        mach_task_self(), address, sizeof(word),
        (mach_vm_address_t)(uintptr_t)&word, &amount);
    if (result != KERN_SUCCESS || amount != sizeof(word)) return false;
    *wordOut = word;
    return true;
}

static bool CNDInspectIconRendering(void)
{
    intptr_t slide = 0;
    const char *path = NULL;
    const struct mach_header_64 *header =
        CNDIconRenderingHeader(&slide, &path);
    uint8_t uuid[16] = {0};
    uint64_t textStart = 0;
    uint64_t textSize = 0;
    bool haveUUID = CNDImageUUID(header, uuid);
    bool haveText = CNDImageTextRange(header, &textStart, &textSize);
    bool uuidMatches = haveUUID &&
        memcmp(uuid, CNDExpectedIconRenderingUUID, sizeof(uuid)) == 0;
    bool addressInText = haveText &&
        CNDIconRenderingPatchVMAddress >= textStart &&
        CNDIconRenderingPatchVMAddress + sizeof(uint32_t) <=
            textStart + textSize;
    mach_vm_address_t target = addressInText
        ? (mach_vm_address_t)((int64_t)CNDIconRenderingPatchVMAddress + slide)
        : 0;
    vm_region_submap_info_data_64_t info = {0};
    mach_vm_address_t regionStart = 0;
    mach_vm_size_t regionSize = 0;
    bool haveRegion = target && CNDRegionInfo(
        target, &info, &regionStart, &regionSize);
    bool executable = haveRegion && (info.protection & VM_PROT_EXECUTE);
    uint32_t instruction = 0;
    bool readInstruction = executable && CNDReadWord(target, &instruction);
    bool instructionMatches = readInstruction &&
        instruction == CNDExpectedInstruction;
    char uuidText[37] = "-";
    char expectedUUIDText[37] = "-";
    if (haveUUID) CNDUUIDString(uuid, uuidText);
    CNDUUIDString(CNDExpectedIconRenderingUUID, expectedUUIDText);

    CNDLog("[CND_BP_PHASE1] FRAMEWORK path=%s header=%p slide=0x%llx "
           "uuid=%s expectedUUID=%s uuidMatch=%d text=0x%llx+0x%llx "
           "target=0x%llx region=0x%llx+0x%llx protection=0x%x/0x%x "
           "shared=%d instruction=0x%08x expected=0x%08x\n",
           path ?: "-", header, (uint64_t)slide, uuidText,
           expectedUUIDText, uuidMatches, textStart, textSize, target,
           regionStart, regionSize, haveRegion ? info.protection : 0,
           haveRegion ? info.max_protection : 0,
           haveRegion ? info.share_mode : -1, instruction,
           CNDExpectedInstruction);

    if (executable && target >= regionStart + 16U &&
        target + 20U <= regionStart + regionSize) {
        for (int relative = -4; relative <= 4; relative++) {
            mach_vm_address_t address = target +
                (mach_vm_address_t)((int64_t)relative * 4LL);
            uint32_t word = 0;
            bool readWord = CNDReadWord(address, &word);
            CNDLog("[CND_BP_PHASE1] OPCODE relative=%d "
                   "unslid=0x%llx runtime=0x%llx read=%d word=0x%08x%s\n",
                   relative,
                   CNDIconRenderingPatchVMAddress +
                       (uint64_t)((int64_t)relative * 4LL),
                   address, readWord, word,
                   relative == 0 ? " breakpoint-site" : "");
        }
    }

    gContractVerified = header && uuidMatches && addressInText &&
        executable && instructionMatches;
    CNDLog("[CND_BP_PHASE1] CONTRACT status=%s image=%d uuid=%d "
           "text=%d executable=%d instruction=%d\n",
           gContractVerified ? "verified" : "unverified",
           header != NULL, uuidMatches, addressInText, executable,
           instructionMatches);
    return header != NULL;
}

static void CNDSnapshotThread(mach_port_t thread, uint64_t threadID)
{
    exception_mask_t masks[EXC_TYPES_COUNT] = {0};
    mach_port_t ports[EXC_TYPES_COUNT] = {0};
    exception_behavior_t behaviors[EXC_TYPES_COUNT] = {0};
    thread_state_flavor_t flavors[EXC_TYPES_COUNT] = {0};
    mach_msg_type_number_t actionCount = EXC_TYPES_COUNT;
    kern_return_t actionResult = thread_get_exception_ports(
        thread, EXC_MASK_BREAKPOINT, masks, &actionCount, ports,
        behaviors, flavors);
    CNDLog("[CND_BP_PHASE1] EXCEPTION_ACTIONS tid=%llu mach=0x%x "
           "kr=%d count=%u\n", threadID, thread, actionResult,
           actionResult == KERN_SUCCESS ? actionCount : 0U);
    if (actionResult == KERN_SUCCESS) {
        for (mach_msg_type_number_t index = 0; index < actionCount; index++) {
            CNDLog("[CND_BP_PHASE1] EXCEPTION_ACTION tid=%llu index=%u "
                   "mask=0x%x port=0x%x behavior=0x%x flavor=%d\n",
                   threadID, index, masks[index], ports[index],
                   behaviors[index], flavors[index]);
            if (MACH_PORT_VALID(ports[index])) {
                mach_port_deallocate(mach_task_self(), ports[index]);
            }
        }
    }

    arm_debug_state64_t debugState = {0};
    mach_msg_type_number_t debugCount = ARM_DEBUG_STATE64_COUNT;
    kern_return_t debugResult = thread_get_state(
        thread, ARM_DEBUG_STATE64, (thread_state_t)&debugState,
        &debugCount);
    unsigned occupiedBreakpoints = 0;
    unsigned occupiedWatchpoints = 0;
    if (debugResult == KERN_SUCCESS) {
        for (unsigned slot = 0; slot < 16U; slot++) {
            if (debugState.__bvr[slot] || debugState.__bcr[slot]) {
                occupiedBreakpoints++;
                CNDLog("[CND_BP_PHASE1] DEBUG_SLOT tid=%llu kind=breakpoint "
                       "slot=%u value=0x%llx control=0x%llx enabled=%d\n",
                       threadID, slot, debugState.__bvr[slot],
                       debugState.__bcr[slot],
                       (debugState.__bcr[slot] & 1ULL) != 0);
            }
            if (debugState.__wvr[slot] || debugState.__wcr[slot]) {
                occupiedWatchpoints++;
                CNDLog("[CND_BP_PHASE1] DEBUG_SLOT tid=%llu kind=watchpoint "
                       "slot=%u value=0x%llx control=0x%llx enabled=%d\n",
                       threadID, slot, debugState.__wvr[slot],
                       debugState.__wcr[slot],
                       (debugState.__wcr[slot] & 1ULL) != 0);
            }
        }
    }
    CNDLog("[CND_BP_PHASE1] DEBUG_STATE tid=%llu mach=0x%x kr=%d "
           "count=%u mdscr=0x%llx occupiedBreakpoints=%u "
           "occupiedWatchpoints=%u\n", threadID, thread, debugResult,
           debugResult == KERN_SUCCESS ? debugCount : 0U,
           debugResult == KERN_SUCCESS ? debugState.__mdscr_el1 : 0ULL,
           occupiedBreakpoints, occupiedWatchpoints);
}

static uint32_t CNDRecordThread(uint64_t threadID, mach_port_t machThread,
                                uint64_t *threadEventsOut,
                                uint32_t *uniqueCountOut, bool *isNewOut)
{
    pthread_mutex_lock(&gRecordLock);
    uint32_t index = 0;
    for (; index < gThreadRecordCount; index++) {
        if (gThreadRecords[index].threadID == threadID) break;
    }
    bool isNew = index == gThreadRecordCount;
    if (isNew && gThreadRecordCount <
            sizeof(gThreadRecords) / sizeof(gThreadRecords[0])) {
        gThreadRecords[index].threadID = threadID;
        gThreadRecords[index].machThread = machThread;
        gThreadRecordCount++;
    } else if (isNew) {
        index = UINT32_MAX;
    }
    uint64_t threadEvents = 0;
    if (index != UINT32_MAX) {
        gThreadRecords[index].events++;
        threadEvents = gThreadRecords[index].events;
    }
    uint32_t uniqueCount = gThreadRecordCount;
    pthread_mutex_unlock(&gRecordLock);
    if (threadEventsOut) *threadEventsOut = threadEvents;
    if (uniqueCountOut) *uniqueCountOut = uniqueCount;
    if (isNewOut) *isNewOut = isNew && index != UINT32_MAX;
    return index;
}

static id CNDObservedInitFromSerializedData(id self, SEL selector, id data,
                                            id device, NSError **error)
{
    pthread_t pthread = pthread_self();
    mach_port_t machThread = pthread_mach_thread_np(pthread);
    uint64_t threadID = 0;
    (void)pthread_threadid_np(pthread, &threadID);
    char threadName[64] = "-";
    (void)pthread_getname_np(pthread, threadName, sizeof(threadName));
    qos_class_t qosClass = QOS_CLASS_UNSPECIFIED;
    int relativePriority = 0;
    (void)pthread_get_qos_class_np(pthread, &qosClass, &relativePriority);
    const char *queueLabel = dispatch_queue_get_label(
        DISPATCH_CURRENT_QUEUE_LABEL);
    if (!queueLabel || !queueLabel[0]) queueLabel = "-";

    uint64_t threadEvents = 0;
    uint32_t uniqueCount = 0;
    bool isNew = false;
    uint32_t threadIndex = CNDRecordThread(
        threadID, machThread, &threadEvents, &uniqueCount, &isNew);
    uint64_t event = __atomic_add_fetch(
        &gEventCount, 1ULL, __ATOMIC_RELAXED);
    NSUInteger dataLength = [data respondsToSelector:@selector(length)]
        ? (NSUInteger)[data length] : 0U;

    id result = gOriginalInitFromSerializedData
        ? gOriginalInitFromSerializedData(self, selector, data, device, error)
        : nil;
    Class resultClass = result ? object_getClass(result) : Nil;
    size_t resultSize = resultClass ? class_getInstanceSize(resultClass) : 0U;
    int chiclet = -1;
    if (result && resultSize > 0xb8U) {
        const volatile uint8_t *bytes =
            (const volatile uint8_t *)(__bridge const void *)result;
        chiclet = (int)bytes[0xb8U];
    }
    CNDLog("[CND_BP_PHASE1] DESERIALIZE event=%llu threadIndex=%u "
           "threadEvents=%llu uniqueThreads=%u tid=%llu mach=0x%x "
           "pthread=%p main=%d qos=%u relativePriority=%d name=%s "
           "queue=%s dataBytes=%lu result=%p chiclet=%d contract=%s\n",
           event, threadIndex, threadEvents, uniqueCount, threadID,
           machThread, pthread, pthread_main_np() != 0,
           (unsigned)qosClass, relativePriority, threadName[0]
               ? threadName : "-", queueLabel, (unsigned long)dataLength,
           (__bridge void *)result, chiclet,
           gContractVerified ? "verified" : "unverified");
    if (isNew) CNDSnapshotThread(machThread, threadID);
    return result;
}

static bool CNDInstallObserver(void)
{
    Class cls = objc_getClass("ICRFinalizedIcon");
    SEL selector = sel_registerName("initFromSerializedData:device:error:");
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (!method || !types || strcmp(types, "@40@0:8@16@24^@32") != 0) {
        CNDLog("[CND_BP_PHASE1] OBSERVER_REJECTED class=%p method=%p "
               "types=%s\n", cls, method, types ?: "-");
        return false;
    }
    IMP original = method_getImplementation(method);
    Dl_info originalInfo = {0};
    (void)dladdr((const void *)original, &originalInfo);
    gOriginalInitFromSerializedData =
        (CNDInitFromSerializedDataIMP)original;
    method_setImplementation(
        method, (IMP)CNDObservedInitFromSerializedData);
    bool verified = method_getImplementation(method) ==
        (IMP)CNDObservedInitFromSerializedData;
    CNDLog("[CND_BP_PHASE1] OBSERVER status=%s class=ICRFinalizedIcon "
           "selector=initFromSerializedData:device:error: types=%s "
           "original=%p image=%s symbol=%s\n",
           verified ? "installed" : "failed", types, original,
           originalInfo.dli_fname ?: "-", originalInfo.dli_sname ?: "-");
    return verified;
}

__attribute__((constructor))
static void CNDSpotlightBreakpointPhase1Start(void)
{
    if (CND_BP_PHASE1_OUTPUT_TOKEN[0]) {
        void *sandbox = dlopen("/usr/lib/system/libsystem_sandbox.dylib",
                               RTLD_LAZY | RTLD_LOCAL);
        int (*consume)(const char *) = sandbox
            ? (int (*)(const char *))dlsym(
                  sandbox, "sandbox_extension_consume")
            : NULL;
        if (consume) (void)consume(CND_BP_PHASE1_OUTPUT_TOKEN);
    }
    unlink(CNDReportPath);
    void *iconRendering = dlopen(
        CNDIconRenderingPath, RTLD_NOW | RTLD_LOCAL);
    if (!iconRendering) {
        CNDLog("[CND_BP_PHASE1] LOAD_REJECTED framework=IconRendering "
               "error=%s\n", dlerror() ?: "-");
        return;
    }
    if (!CNDInspectIconRendering()) {
        CNDLog("[CND_BP_PHASE1] LOAD_REJECTED reason=image-not-found\n");
        return;
    }
    if (!CNDInstallObserver()) return;
    CNDLog("[CND_BP_PHASE1] READY pid=%d contract=%s writes=0 "
           "breakpoints=0 byteMutation=0\n", getpid(),
           gContractVerified ? "verified" : "unverified");
}
