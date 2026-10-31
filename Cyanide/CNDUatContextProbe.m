//
//  CNDUatContextProbe.m
//
//  E1: the differential read of the UAT/gart context table.
//
//  What it does, in order
//  ----------------------
//  1. Acquires the same KRW lease every other probe uses (offsets_init, then
//     kexploit if not ready), and requires the pin witnesses to pass.
//  2. Reads the XNU IOUAT global `gIOUAT` and the table pointer it publishes.
//  3. Snapshots the 256-entry table (AGX bounds the task id at 0x100).
//  4. Performs one named app action at a time, re-snapshotting after each:
//       open AGX client  ->  create queue  ->  destroy queue  ->  close client
//     plus a read-only selector call as the negative control.
//  5. Reports every entry whose 16 bytes changed, decoded.
//
//  Why the table and not `uat_instance`
//  ------------------------------------
//  `uat_instance` (0xfffffff027085838) lives in SPTM's address space.  EL1 cannot
//  dereference it, so a task-based kread would fault, not read.  The XNU-side
//  `gIOUAT` global is the reachable counterpart: its +0x28 pointer is the array
//  AGX writes (`AGXUnifiedAddressTranslator::mapTaskIdIntoGPTBAT` reads the base
//  from `this+0x20`, which AGX obtains from the IOUAT accessor that returns this
//  same pointer).  Reading the array is therefore the identity join W3 asked for,
//  and the differential is E1's behavioural half.
//
//  Entry encoding, pinned from both writers (tools/uat_root_table_audit.py):
//     word0 = (ttbr0_paddr & 0x3ffffffc000) | (ctx << 48) | 1
//     word1 = (ttbr1_paddr & 0x3ffffffc000) | (ctx << 48) | 1
//
//  KRW source
//  ----------
//  This is a kslop probe: it uses the app's own in-process KRW lease through the
//  same symbols every other probe uses (`kreadbuf`/`kread64`/`kwrite64`, the
//  `g_kernel_base`/`g_kernel_slide` globals, and the kernel's own
//  `is_kaddr_valid` for pointer validation).  There is no external provider
//  socket, no host side, no root, and no lab VM call path involved.
//
//  Safety
//  ------
//  Read-only.  The only writes are to this process's own allocations.  The table
//  pointer is validated with kslop's `is_kaddr_valid` before it is dereferenced;
//  an implausible value is reported, never followed.  No selector is swept.
//

#import "CNDUatContextProbe.h"

#import <dlfcn.h>
#import <mach/mach.h>
#import <stdio.h>
#import <IOKit/IOKitLib.h>

#pragma mark - pinned addresses (iPhone17,2, iOS 26.0 23A341)

// Container __TEXT vmaddr; the runtime base is (this + slide).
static const uint64_t CNDUatCtxUnslidTextBase = 0xfffffff007004000ull;

// Slide witnesses.  `IOUAT::commitUnmaps` and `sptm_uat_set_ctx_id`'s XNU
// counterpart both start with pacibsp in this image.
static const uint64_t CNDUatCtxUnslidCommitUnmaps = 0xfffffff0089f4ba4ull;
static const uint64_t CNDUatCtxUnslidSetCtxId     = 0xfffffff0089f5adcull;
static const uint64_t CNDUatCtxUnslidPrepareFwUnmap = 0xfffffff0089f6558ull;
static const uint32_t CNDUatCtxPacibsp            = 0xd503237full;

// The XNU IOUAT global.  `IOUAT::set_ctx_id` and the table accessor both reach it
// as `adrp x8, 0xfffffff00b393000 ; add x8, x8, #0x4f8`.
static const uint64_t CNDUatCtxUnslidIOUATGlobal = 0xfffffff00b3934f8ull;
enum {
    CNDUatCtxOffStatus   = 0x00,  // u32, 1 == IOUAT enabled
    CNDUatCtxOffMode     = 0x08,  // u64, selects the writer path
    CNDUatCtxOffDebug    = 0x10,  // u8, bit 1 gates the driver's own logging
    CNDUatCtxOffTtbr0    = 0x20,  // u64, TTBR0 base in mode 0
    CNDUatCtxOffTablePtr = 0x28,  // u64, the context table (kernel VA)
};

// AGX windows for the vtable-anchored instance search.  A measured run showed
// that gIOUAT+0x28 is NOT the context array (the bytes there are ASCII), so the
// anchor is the GART/AGXUAT object: find the AGX vtable that carries
// AGXSecureGart::unmapWithAddress in __DATA_CONST, then find the objects holding
// that vtable in __DATA/__bss.  Same technique the UAT observer already uses.
static const uint64_t CNDUatCtxAgxConst      = 0xfffffff007cd24f8ull;
static const uint64_t CNDUatCtxAgxConstSize  = 0xf108ull;
static const uint64_t CNDUatCtxAgxData       = 0xfffffff00b424280ull;
static const uint64_t CNDUatCtxAgxDataSize   = 0x13c4ull;
static const uint64_t CNDUatCtxAgxBss        = 0xfffffff00b425660ull;
static const uint64_t CNDUatCtxAgxBssSize    = 0x4a30ull;
static const uint64_t CNDUatCtxAgxUnmapWithAddress = 0xfffffff008b2c024ull;
// The __DATA_CONST slot that holds it (resolved offline through the container's
// chained fixups; see tools/chained_fixups.py).
static const uint64_t CNDUatCtxVtableSlot = 0xfffffff007cd9250ull;
// GPTBAT base inside the AGXUAT side of that object (mapTaskIdIntoGPTBAT reads it
// as `ldr x9, [x19, #0x20]`).
static const uint64_t CNDUatCtxOffGptbat = 0x20ull;

// AGX asserts task id < 0x100, so the table is 256 entries of 16 bytes.
enum {
    CNDUatCtxEntryCount = 0x100,
    CNDUatCtxEntryBytes = 0x10,
};
// Any kernel VA outside this window is refused rather than dereferenced.
static const uint64_t CNDUatCtxKernelLow  = 0xfffffff000000000ull;
static const uint64_t CNDUatCtxKernelHigh = 0xffffffff00000000ull;

#pragma mark - kexploit API (same contract as CNDUatObserverProbe)

typedef void (*CNDUatKReadBufFn)(uint64_t address, void *buffer, uint64_t length);
typedef uint64_t (*CNDUatKRead64Fn)(uint64_t address);
// kslop's own kernel-pointer validity check (kexploit/krw.h).
typedef bool (*CNDUatKAddrValidFn)(uint64_t address);
typedef bool (*CNDUatReadyFn)(void);
typedef int (*CNDUatKexploitFn)(void);
typedef void (*CNDUatOffsetsInitFn)(void);

typedef struct {
    CNDUatKReadBufFn kreadbuf;
    CNDUatKRead64Fn kread64;
    CNDUatKAddrValidFn isKaddrValid;
    // kslop's kernel pointer mask (krw.h: PTR_MASK = ONES(64 - t1sz_boot)).  A
    // signed kernel pointer keeps only those low bits; the rest is PAC.  Measured
    // 2026-10-27: on this device the mask is 36 bits, not 48.
    uint64_t ptrMask;
    uint64_t *t1sz;
    CNDUatReadyFn krwReady;
    CNDUatKexploitFn kexploit;
    CNDUatOffsetsInitFn offsetsInit;
    uint64_t *kernelBase;
    uint64_t *kernelSlide;
} CNDUatCtxAPI;

static bool CNDUatCtxResolveAPI(CNDUatCtxAPI *api, NSString **reason)
{
    if (api == NULL) {
        return false;
    }
    memset(api, 0, sizeof(*api));
    api->kreadbuf = (CNDUatKReadBufFn)dlsym(RTLD_DEFAULT, "kreadbuf");
    api->kread64 = (CNDUatKRead64Fn)dlsym(RTLD_DEFAULT, "kread64");
    api->isKaddrValid = (CNDUatKAddrValidFn)dlsym(RTLD_DEFAULT, "is_kaddr_valid");
    api->t1sz = (uint64_t *)dlsym(RTLD_DEFAULT, "t1sz_boot");
    uint64_t t1sz = (api->t1sz != NULL) ? *api->t1sz : 0;
    api->ptrMask = (t1sz > 0 && t1sz < 64)
        ? ((1ull << (64 - t1sz)) - 1ull) : 0xFFFFFFFFFull;
    api->krwReady = (CNDUatReadyFn)dlsym(RTLD_DEFAULT, "kexploit_krw_ready");
    api->kexploit = (CNDUatKexploitFn)dlsym(RTLD_DEFAULT, "kexploit_opa334");
    api->offsetsInit = (CNDUatOffsetsInitFn)dlsym(RTLD_DEFAULT, "offsets_init");
    api->kernelBase = (uint64_t *)dlsym(RTLD_DEFAULT, "g_kernel_base");
    api->kernelSlide = (uint64_t *)dlsym(RTLD_DEFAULT, "g_kernel_slide");

    bool ok = api->kreadbuf != NULL && api->krwReady != NULL &&
        api->kexploit != NULL && api->offsetsInit != NULL &&
        api->kernelBase != NULL && api->kernelSlide != NULL;
    if (!ok && reason != NULL) {
        *reason = @"kexploit API incomplete (kreadbuf/krwReady/g_kernel_base/"
                  @"g_kernel_slide)";
    }
    return ok;
}

static bool CNDUatCtxRead(const CNDUatCtxAPI *api, uint64_t address, void *buffer,
                          size_t length)
{
    if (api == NULL || api->kreadbuf == NULL || buffer == NULL || length == 0) {
        return false;
    }
    api->kreadbuf(address, buffer, (uint64_t)length);
    return true;
}

#pragma mark - report plumbing

static NSString *CNDUatCtxReportPath(void)
{
    NSString *dir = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (dir == nil) {
        return nil;
    }
    return [dir stringByAppendingPathComponent:@"CNDUatContextProbe.json"];
}

static void CNDUatCtxPersist(NSMutableDictionary<NSString *, id> *report,
                             NSString *key, id value)
{
    if (key != nil && value != nil) {
        report[key] = value;
    }
    report[@"updatedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:nil];
    NSString *path = CNDUatCtxReportPath();
    if (data != nil && path != nil) {
        (void)[data writeToFile:path options:NSDataWritingAtomic error:nil];
        report[@"reportPath"] = path;
    }
    if (key != nil) {
        NSLog(@"[CND_UATCTX] %@=%@", key, value);
    }
}

#pragma mark - table snapshot

typedef struct {
    uint64_t raw0;
    uint64_t raw1;
} CNDUatCtxEntry;

typedef struct {
    bool valid;
    CNDUatCtxEntry entries[CNDUatCtxEntryCount];
    uint64_t tablePtr;
    uint32_t validCount;
} CNDUatCtxSnapshot;

// Prefers kslop's `is_kaddr_valid` (which uses this device's real T1SZ/PAC mask);
// the pinned window is only a fallback for a build where that symbol is absent.
static bool CNDUatCtxPlausiblePointer(const CNDUatCtxAPI *api, uint64_t address)
{
    if (address == 0 || (address & 0x7) != 0) {
        return false;
    }
    if (api != NULL && api->isKaddrValid != NULL) {
        return api->isKaddrValid(address);
    }
    return address >= CNDUatCtxKernelLow && address < CNDUatCtxKernelHigh;
}

static NSString *CNDUatCtxDecodeEntry(const CNDUatCtxEntry *entry)
{
    uint32_t valid0 = (uint32_t)(entry->raw0 & 1);
    uint32_t valid1 = (uint32_t)(entry->raw1 & 1);
    uint32_t id = (uint32_t)((entry->raw0 >> 48) & 0xffff);
    uint64_t ttbr0 = entry->raw0 & 0x3ffffffc000ull;
    uint64_t ttbr1 = entry->raw1 & 0x3ffffffc000ull;
    return [NSString stringWithFormat:
        @"v=%u%u id=0x%x ttbr0=0x%llx ttbr1=0x%llx raw=%016llx:%016llx",
        valid0, valid1, id,
        (unsigned long long)ttbr0, (unsigned long long)ttbr1,
        (unsigned long long)entry->raw0, (unsigned long long)entry->raw1];
}

// Reads the table through the pointer published by gIOUAT.  Returns false with a
// reason instead of dereferencing anything implausible.
static bool CNDUatCtxSnapshotRead(const CNDUatCtxAPI *api, uint64_t tablePtr,
                                  CNDUatCtxSnapshot *out, NSString **reason)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (!CNDUatCtxPlausiblePointer(api, tablePtr)) {
        if (reason != NULL) {
            *reason = [NSString stringWithFormat:
                @"table pointer 0x%llx is not a plausible kernel VA",
                (unsigned long long)tablePtr];
        }
        return false;
    }
    if (!CNDUatCtxRead(api, tablePtr, out->entries,
                       CNDUatCtxEntryCount * CNDUatCtxEntryBytes)) {
        if (reason != NULL) {
            *reason = @"kreadbuf refused";
        }
        return false;
    }
    out->tablePtr = tablePtr;
    for (uint32_t i = 0; i < CNDUatCtxEntryCount; i++) {
        if (out->entries[i].raw0 & 1) {
            out->validCount++;
        }
    }
    out->valid = true;
    return true;
}

static NSArray<NSString *> *CNDUatCtxValidEntries(const CNDUatCtxSnapshot *snap)
{
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    for (uint32_t i = 0; i < CNDUatCtxEntryCount; i++) {
        if (snap->entries[i].raw0 & 1) {
            [lines addObject:[NSString stringWithFormat:@"[%u] %@", i,
                CNDUatCtxDecodeEntry(&snap->entries[i])]];
        }
    }
    return lines;
}

static NSArray<NSString *> *CNDUatCtxDiff(const CNDUatCtxSnapshot *before,
                                          const CNDUatCtxSnapshot *after)
{
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    if (before == NULL || after == NULL || !before->valid || !after->valid) {
        return lines;
    }
    for (uint32_t i = 0; i < CNDUatCtxEntryCount; i++) {
        if (before->entries[i].raw0 == after->entries[i].raw0 &&
            before->entries[i].raw1 == after->entries[i].raw1) {
            continue;
        }
        [lines addObject:[NSString stringWithFormat:
            @"[%u] %@ -> %@", i,
            CNDUatCtxDecodeEntry(&before->entries[i]),
            CNDUatCtxDecodeEntry(&after->entries[i])]];
    }
    if (before->tablePtr != after->tablePtr) {
        [lines addObject:[NSString stringWithFormat:
            @"table pointer moved 0x%llx -> 0x%llx",
            (unsigned long long)before->tablePtr,
            (unsigned long long)after->tablePtr]];
    }
    return lines;
}

#pragma mark - AGX instance search

// Returns the number of candidate instance slots written to `slots` (bounded).
static NSUInteger CNDUatCtxFindGartInstances(const CNDUatCtxAPI *api,
                                             uint64_t slide,
                                             uint64_t *slots,
                                             NSUInteger maxSlots,
                                             NSMutableArray<NSNumber *> *vtableHits,
                                             NSMutableArray<NSNumber *> *rejected)
{
    // Step 1: qwords in AGX __DATA_CONST that hold the PAC-stripped vtable entry.
    uint8_t *cb = (uint8_t *)malloc((size_t)CNDUatCtxAgxConstSize);
    if (cb == NULL) {
        return 0;
    }
    uint64_t constAddr = CNDUatCtxAgxConst + slide;
    uint64_t want = (CNDUatCtxAgxUnmapWithAddress + slide) & api->ptrMask;
    if (!CNDUatCtxRead(api, constAddr, cb, (size_t)CNDUatCtxAgxConstSize)) {
        free(cb);
        return 0;
    }
    for (size_t off = 0; off + 8 <= (size_t)CNDUatCtxAgxConstSize; off += 8) {
        uint64_t q = 0;
        memcpy(&q, cb + off, 8);
        if ((q & api->ptrMask) == want) {
            [vtableHits addObject:@(constAddr + off)];
        }
    }
    free(cb);
    if (vtableHits.count == 0) {
        return 0;
    }

    // Step 2: objects whose first word is one of those vtable addresses.
    const uint64_t windows[2][2] = {
        { CNDUatCtxAgxData, CNDUatCtxAgxDataSize },
        { CNDUatCtxAgxBss,  CNDUatCtxAgxBssSize },
    };
    NSUInteger found = 0;
    for (int w = 0; w < 2 && found < maxSlots; w++) {
        uint8_t *db = (uint8_t *)malloc((size_t)windows[w][1]);
        if (db == NULL) {
            continue;
        }
        uint64_t base = windows[w][0] + slide;
        if (CNDUatCtxRead(api, base, db, (size_t)windows[w][1])) {
            for (size_t off = 0; off + 8 <= (size_t)windows[w][1] && found < maxSlots;
                 off += 8) {
                uint64_t q = 0;
                memcpy(&q, db + off, 8);
                uint64_t qa = q & api->ptrMask;
                BOOL isVtable = NO;
                for (NSNumber *hit in vtableHits) {
                    if (([hit unsignedLongLongValue] & api->ptrMask) == qa) {
                        isVtable = YES;
                        break;
                    }
                }
                if (!isVtable) {
                    continue;
                }
                // The object lives at the scanned address; its first word is the
                // vtable pointer.  No masking on the address itself.
                slots[found++] = base + off;
            }
        }
        free(db);
    }
    (void)rejected;
    return found;
}

#pragma mark - actions

// One client connection to the AGX accelerator, kept open across a snapshot so
// that a transient context registration is observable rather than being undone
// before we look.
static io_connect_t CNDUatCtxOpenAGX(io_service_t *outService)
{
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                            IOServiceMatching("AGXAcceleratorG17P"));
    if (outService != NULL) {
        *outService = svc;
    }
    if (!svc) {
        return 0;
    }
    io_connect_t conn = 0;
    if (IOServiceOpen(svc, mach_task_self(), 1, &conn) != KERN_SUCCESS) {
        return 0;
    }
    return conn;
}

static void CNDUatCtxCloseAGX(io_service_t svc, io_connect_t conn)
{
    if (conn) {
        IOObjectRelease(conn);
    }
    if (svc) {
        IOObjectRelease(svc);
    }
}

// A read-only getter, used elsewhere as the connection-health witness.  Calling
// it must not move the table; that is the negative control.
static void CNDUatCtxCallGetter(io_connect_t conn)
{
    if (!conn) {
        return;
    }
    uint8_t *out = (uint8_t *)calloc(1, 536);
    size_t sz = 536;
    if (out != NULL) {
        (void)IOConnectCallMethod(conn, 2, NULL, 0, NULL, 0, NULL, NULL,
                                  out, &sz);
        free(out);
    }
}

static uint32_t CNDUatCtxCreateQueue(io_connect_t conn)
{
    if (!conn) {
        return 0;
    }
    uint64_t scalars[2] = { 0, 0 };
    uint64_t out[2] = { 0, 0 };
    uint32_t outCnt = 2;
    if (IOConnectCallMethod(conn, 42, scalars, 2, NULL, 0, out, &outCnt,
                            NULL, NULL) != KERN_SUCCESS) {
        return 0;
    }
    return (uint32_t)out[0];
}

static void CNDUatCtxDestroyQueue(io_connect_t conn, uint32_t qid)
{
    if (!conn || qid == 0) {
        return;
    }
    uint64_t destroyScalar = qid;
    (void)IOConnectCallMethod(conn, 43, &destroyScalar, 1, NULL, 0,
                              NULL, NULL, NULL, NULL);
}

#pragma mark - main body

bool CNDUatContextProbeIsSupported(NSString **reason)
{
    CNDUatCtxAPI api;
    return CNDUatCtxResolveAPI(&api, reason);
}

void CNDUatContextProbeRun(void (^completion)(NSDictionary<NSString *, id> *))
{
    NSMutableDictionary<NSString *, id> *report = [NSMutableDictionary dictionary];
    report[@"schema"] = @"com.zeroxjf.cyanide.uat-context-probe";
    report[@"schemaVersion"] = @1;
    report[@"pinnedImage"] =
        @"iPhone17,2 23A341 kernelcache "
        @"7e66ddbb70b626c4502c3036620b59829b744c54712a74ca50f4a0c004c89f8c";
    report[@"krwSource"] = @"kslop in-process lease (kreadbuf/is_kaddr_valid)";

    CNDUatCtxAPI api;
    NSString *reason = nil;
    if (!CNDUatCtxResolveAPI(&api, &reason)) {
        CNDUatCtxPersist(report, @"result", reason ?: @"api-missing");
        if (completion != nil) {
            completion(report);
        }
        return;
    }

    api.offsetsInit();
    report[@"offsetsInitCalled"] = @YES;
    if (!api.krwReady()) {
        report[@"kexploitResult"] = @(api.kexploit());
    }
    report[@"kernelBase"] = @(*(api.kernelBase));
    report[@"kernelSlide"] = @(*(api.kernelSlide));
    if (!api.krwReady()) {
        CNDUatCtxPersist(report, @"result", @"krw-not-ready");
        if (completion != nil) {
            completion(report);
        }
        return;
    }

    uint64_t slide = *(api.kernelSlide);
    uint64_t derived = *(api.kernelBase) - CNDUatCtxUnslidTextBase;
    report[@"slideFromBase"] = @(derived);
    if (derived != slide) {
        CNDUatCtxPersist(report, @"result", @"slide-disagreement");
        if (completion != nil) {
            completion(report);
        }
        return;
    }

    // Witnesses: the slide must land on the same image the addresses came from.
    struct {
        const char *name;
        uint64_t addr;
    } witnesses[] = {
        { "commitUnmaps", CNDUatCtxUnslidCommitUnmaps },
        { "set_ctx_id", CNDUatCtxUnslidSetCtxId },
        { "prepareFWUnmap", CNDUatCtxUnslidPrepareFwUnmap },
    };
    NSMutableDictionary<NSString *, id> *witnessReport = [NSMutableDictionary dictionary];
    for (size_t i = 0; i < sizeof(witnesses) / sizeof(witnesses[0]); i++) {
        uint32_t insn = 0;
        CNDUatCtxRead(&api, witnesses[i].addr + slide, &insn, sizeof(insn));
        NSString *value = [NSString stringWithFormat:@"0x%08x", insn];
        witnessReport[@(witnesses[i].name)] = value;
        if (insn != CNDUatCtxPacibsp) {
            CNDUatCtxPersist(report, @"witnesses", witnessReport);
            CNDUatCtxPersist(report, @"result", @"pin-witness-mismatch");
            if (completion != nil) {
                completion(report);
            }
            return;
        }
    }
    report[@"witnesses"] = witnessReport;

    // The IOUAT global: status first.  If it is not 1 the driver believes the
    // system is disabled and nothing below would be meaningful.
    uint64_t global = CNDUatCtxUnslidIOUATGlobal + slide;
    uint32_t status = 0;
    uint64_t mode = 0, ttbr0Base = 0, tablePtr = 0;
    uint8_t debug = 0;
    CNDUatCtxRead(&api, global + CNDUatCtxOffStatus, &status, sizeof(status));
    CNDUatCtxRead(&api, global + CNDUatCtxOffMode, &mode, sizeof(mode));
    CNDUatCtxRead(&api, global + CNDUatCtxOffDebug, &debug, sizeof(debug));
    CNDUatCtxRead(&api, global + CNDUatCtxOffTtbr0, &ttbr0Base, sizeof(ttbr0Base));
    // Measured 2026-10-27: the bytes at this pointer are ASCII, so it is NOT the
    // context array.  It is reported for the record; the array comes from AGX.
    CNDUatCtxRead(&api, global + CNDUatCtxOffTablePtr, &tablePtr, sizeof(tablePtr));

    report[@"pointerGuard"] = api.isKaddrValid != NULL
        ? @"is_kaddr_valid" : @"pinned-window-fallback";
    report[@"iouatGlobal"] = @{
        @"address": @(global),
        @"status": @(status),
        @"mode": @(mode),
        @"debugByte": @(debug),
        @"ttbr0Base": @(ttbr0Base),
        @"field0x28": @(tablePtr),
    };
    if (status != 1) {
        CNDUatCtxPersist(report, @"result",
                         [NSString stringWithFormat:@"iouat-not-enabled(status=%u)", status]);
        if (completion != nil) {
            completion(report);
        }
        return;
    }

    // Locate the AGX GART/AGXUAT object and take its GPTBAT base.
    uint64_t slots[8] = { 0 };
    NSMutableArray<NSNumber *> *vtableHits = [NSMutableArray array];
    NSMutableArray<NSNumber *> *rejected = [NSMutableArray array];
    NSUInteger instanceCount = CNDUatCtxFindGartInstances(&api, slide, slots, 8,
                                                          vtableHits, rejected);
    report[@"gartSearch"] = @{
        @"ptrMask": @(api.ptrMask),
        @"wantMasked": @((CNDUatCtxAgxUnmapWithAddress + slide) & api.ptrMask),
        @"vtableSlotAddress": @(CNDUatCtxVtableSlot + slide),
        @"vtableSlotWords": ({
            NSMutableArray *a = [NSMutableArray array];
            for (int i = 0; i < 6; i++) {
                uint64_t w = 0;
                CNDUatCtxRead(&api, CNDUatCtxVtableSlot + slide + (uint64_t)i * 8,
                              &w, sizeof(w));
                [a addObject:@(w)];
            }
            a;
        }),
        @"constWindowHead": ({
            NSMutableArray *a = [NSMutableArray array];
            for (int i = 0; i < 4; i++) {
                uint64_t w = 0;
                CNDUatCtxRead(&api, CNDUatCtxAgxConst + slide + (uint64_t)i * 8,
                              &w, sizeof(w));
                [a addObject:@(w)];
            }
            a;
        }),
        @"vtableHits": vtableHits,
        @"instanceCount": @(instanceCount),
        @"instances": ({
            NSMutableArray *a = [NSMutableArray array];
            for (NSUInteger i = 0; i < instanceCount; i++) [a addObject:@(slots[i])];
            a;
        }),
    };
    if (instanceCount == 0) {
        CNDUatCtxPersist(report, @"result", @"gart-instance-not-found");
        if (completion != nil) {
            completion(report);
        }
        return;
    }

    // The first candidate whose +0x20 is a valid kernel pointer wins.  Report all
    // candidates' +0x20 so a wrong pick is visible rather than silent.
    NSMutableArray *gptbatCandidates = [NSMutableArray array];
    uint64_t gptbat = 0;
    for (NSUInteger i = 0; i < instanceCount; i++) {
        uint64_t value = 0;
        CNDUatCtxRead(&api, slots[i] + CNDUatCtxOffGptbat, &value, sizeof(value));
        [gptbatCandidates addObject:@{
            @"instance": @(slots[i]),
            @"gptbat": @(value),
            @"valid": @(CNDUatCtxPlausiblePointer(&api, value)),
        }];
        if (gptbat == 0 && CNDUatCtxPlausiblePointer(&api, value)) {
            gptbat = value;
        }
    }
    report[@"gptbatCandidates"] = gptbatCandidates;
    if (gptbat == 0) {
        CNDUatCtxPersist(report, @"result", @"gptbat-pointer-not-found");
        if (completion != nil) {
            completion(report);
        }
        return;
    }
    report[@"gptbatPointer"] = @(gptbat);
    tablePtr = gptbat;

    CNDUatCtxSnapshot before;
    NSString *snapReason = nil;
    if (!CNDUatCtxSnapshotRead(&api, tablePtr, &before, &snapReason)) {
        CNDUatCtxPersist(report, @"result", snapReason ?: @"snapshot-refused");
        if (completion != nil) {
            completion(report);
        }
        return;
    }
    report[@"snapshotBefore"] = CNDUatCtxValidEntries(&before);
    report[@"validBefore"] = @(before.validCount);

    // Each step records a snapshot and diffs it against the previous one, so a
    // transient registration during a live action is visible in the step that
    // follows it.  The getter call is the negative control: it must change
    // nothing.
    NSMutableArray<NSDictionary<NSString *, id> *> *results = [NSMutableArray array];
    __block CNDUatCtxSnapshot previous = before;

    typedef void (^CNDUatCtxStep)(NSString *name, NSString *detail);
    CNDUatCtxStep step = ^(NSString *name, NSString *detail) {
        CNDUatCtxSnapshot after;
        NSString *why = nil;
        bool ok = CNDUatCtxSnapshotRead(&api, tablePtr, &after, &why);
        NSDictionary<NSString *, id> *row = @{
            @"action": name,
            @"detail": detail ?: @"",
            @"snapshotOK": @(ok),
            @"reason": why ?: @"",
            @"validCount": @(ok ? after.validCount : 0),
            @"diff": ok ? CNDUatCtxDiff(&previous, &after) : @[],
            @"entries": ok ? CNDUatCtxValidEntries(&after) : @[],
        };
        [results addObject:row];
        if (ok) {
            previous = after;
        }
    };

    // Step 1: open a client and read a getter while it is open.  A context
    // registration here would be visible in this snapshot.
    io_service_t svc = 0;
    io_connect_t conn = CNDUatCtxOpenAGX(&svc);
    CNDUatCtxCallGetter(conn);
    step(@"after-open-and-getter", conn ? @"client open" : @"open failed");

    // Step 2: create one queue and snapshot before destroying it.
    uint32_t qid = CNDUatCtxCreateQueue(conn);
    step(@"after-queue-create",
         [NSString stringWithFormat:@"qid=%u", qid]);

    // Step 3: destroy it and snapshot again.
    CNDUatCtxDestroyQueue(conn, qid);
    step(@"after-queue-destroy",
         [NSString stringWithFormat:@"qid=%u", qid]);

    // Step 4: close the client.
    CNDUatCtxCloseAGX(svc, conn);
    step(@"after-client-close", @"");

    // Step 5: control.  Nothing happens, so nothing may change.
    step(@"control-noop", @"no action between snapshots");

    report[@"actions"] = results;
    report[@"validAfter"] = @(previous.validCount);

    NSUInteger changed = 0;
    for (NSDictionary<NSString *, id> *row in results) {
        if ([row[@"diff"] count] != 0) {
            changed++;
        }
    }
    report[@"actionsWithChanges"] = @(changed);
    report[@"result"] = changed ? @"table-changed" : @"table-stable";
    report[@"note"] =
        @"read-only probe: no kernel write, no selector sweep. A stable table means "
        @"none of these actions is the UAT trigger; a change names the entry that "
        @"moved, which is E1's pass condition.";
    CNDUatCtxPersist(report, @"result", report[@"result"]);
    if (completion != nil) {
        completion(report);
    }
}
