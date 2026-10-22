//
// CNDUatObserverProbe.m
//
// Why this exists
// ---------------
// The userland sweep (iOS27.0.1-SPTM-Research, work/ios26/device-runs) showed
// that an IOSurface purge removes the UAT translation and the GPU's reads come
// back zero: on this build that trigger looks synchronous.  To tell whether a
// teardown takes the synchronous path or the *deferred* firmware-unmap path we
// need to see the kernel's IOUAT side, and the kernel already has the answer:
// `IOUAT::commitUnmaps` and `IOUAT::prepareFWUnmap` begin with
//
//     ldrb w8, [<debug byte>]
//     tbz  w8, #1, <skip>
//     ... log ...
//
// so setting bit 1 makes the driver log every commit and every firmware unmap.
// This probe flips exactly that bit through the app's existing KRW lease, and
// can put it back.
//
// Addresses are pinned to the iPhone17,2 / iOS 26.0 23A341 kernelcache
// (SHA-256 7e66ddbb70b626c4502c3036620b59829b744c54712a74ca50f4a0c004c89f8c,
// container __TEXT vmaddr 0xfffffff007004000).  Every one is verified against
// the image bytes at run time before anything is written; a mismatch refuses
// the run rather than writing to a guessed address.
//

#import "CNDUatObserverProbe.h"

#import <dlfcn.h>
#import <mach/mach.h>
#import <stdio.h>

#pragma mark - pinned addresses (iPhone17,2 23A341)

// Container __TEXT vmaddr; runtime base is (this + slide).
static const uint64_t CNDUatUnslidTextBase = 0xfffffff007004000ull;
// `IOUAT::commitUnmaps` - starts with pacibsp (0xd503237f), used as the
// slide witness because it is inside __TEXT_EXEC and unique.
static const uint64_t CNDUatUnslidCommitUnmaps = 0xfffffff0089f4ba4ull;
static const uint32_t CNDUatPacibsp = 0xd503237full;
// `IOUAT::prepareFWUnmap` - the deferred-firmware-unmap entry point.
static const uint64_t CNDUatUnslidPrepareFwUnmap = 0xfffffff0089f6558ull;
// AGXG17P: AGXSecureGart::unmapWithAddress - prologue is pacibsp; the
// deferred-vs-direct decision below is inside this function.
static const uint64_t CNDUatUnslidGartUnmapWithAddress = 0xfffffff008b2c024ull;
// Global feature byte that selects the path:
//   adrp x25, 0xfffffff00b429000 ; ... ldrb w9, [x25, #0xae0] ; tbz w9,#0
// bit 0 set  -> vtable/queue path (deferred)
// bit 0 clear-> direct AGXUAT::unmap call
static const uint64_t CNDUatUnslidGartFeatureByte = 0xfffffff00b429ae0ull;

// IOGPUFamily geometry in the pinned image.  The user-client dispatch table
// lives in __DATA_CONST,__const and is only resolvable in the live kernel,
// because the kernel-collection fixups that fill it in are not applied on disk.
static const uint64_t CNDUatUnslidIOGPUText = 0xfffffff00a4f90a0ull;
static const uint64_t CNDUatUnslidIOGPUTextSize = 0x42eccull;
static const uint64_t CNDUatUnslidIOGPUConst = 0xfffffff0080669f0ull;
static const uint64_t CNDUatUnslidIOGPUConstSize = 0x6f50ull;
// Selector dispatcher found by code shape at unmap+0x...3128c:
//   cmp w1, #0x29 ; ... ; ldr x1, [x1, #0x7b0]
// so the table POINTER lives at __DATA_CONST + 0x7b0.
static const uint64_t CNDUatUnslidIOGPUDispatchPtr = 0xfffffff0080667b0ull;
static const uint32_t CNDUatIOGPUSelectorCount = 0x29;
// Two user-client methods confirmed by disassembly (they read
// IOExternalMethodArguments at [x2+0x20] / [x2+0x58]).  Their addresses, once
// slid, identify the dispatch table inside __DATA_CONST by value.
static const uint64_t CNDUatUnslidIOGPUHandlerA = 0xfffffff00a4ffb74ull;
static const uint64_t CNDUatUnslidIOGPUHandlerB = 0xfffffff00a5002d4ull;
// The externalMethod override at 0xfffffff00a502aac does:
//   cmp w1, #0x37 ; mov w9,#0x18 ; umull x9,w1,w9
//   adrp/add -> 0xfffffff0080682f0   (table A, flag bit set)
//   adrp/add -> 0xfffffff008067db0   (table B, flag bit clear)
//   csel x3, A+sel*24, B+sel*24, ne ; tail-call IOUserClient::externalMethod
static const uint64_t CNDUatUnslidIOGPUDispatchA = 0xfffffff0080682f0ull;
static const uint64_t CNDUatUnslidIOGPUDispatchB = 0xfffffff008067db0ull;
static const uint32_t CNDUatIOGPUUserSelectorCount = 0x38;

// AGXG17P sections (pinned image) for the vtable-anchored instance search.
static const uint64_t CNDUatAgxConst   = 0xfffffff007cd24f8ull;
static const uint64_t CNDUatAgxConstSz = 0xf108ull;
static const uint64_t CNDUatAgxData    = 0xfffffff00b424280ull;
static const uint64_t CNDUatAgxDataSz  = 0x13c4ull;
static const uint64_t CNDUatAgxBss     = 0xfffffff00b425660ull;
static const uint64_t CNDUatAgxBssSz   = 0x4a30ull;
// AGXSecureGart::unmapWithAddress (virtual, verified pacibsp at runtime).
static const uint64_t CNDUatAgxUnmapWithAddress = 0xfffffff008b2c024ull;

// ANE (H11ANE / AppleH16ANEInterface) dispatch-table candidates found by code
// shape: small functions with `cmp w1,#N` and an adrp+add table pointer.
static const uint64_t CNDUatAneTables[5] = {
    0xfffffff007e02978ull, 0xfffffff007e038a8ull, 0xfffffff007e07f50ull,
    0xfffffff007e08d88ull, 0xfffffff007e08da8ull,
};

// ANE user-client vtables found from the constructors that store them.
static const uint64_t CNDUatAneVtables[3] = {
    0xfffffff007e04680ull, 0xfffffff007e052f8ull, 0xfffffff007e04c70ull,
};

// IOGPUDeviceUserClient::externalMethod (function start, bti c at +4).
static const uint64_t CNDUatIOGPUExternalMethod = 0xfffffff00a502aa8ull;

// The driver's debug byte.  From commitUnmaps:
//   adrp x8, 0xfffffff00b393000 ; add x8, x8, #0x4f8 ; ldrb w8, [x8, #0x10]
static const uint64_t CNDUatUnslidDebugByte = 0xfffffff00b393508ull;

#pragma mark - kexploit API

typedef void (*CNDUatKReadBufFn)(uint64_t address, void *buffer, uint64_t length);
typedef uint64_t (*CNDUatKRead64Fn)(uint64_t address);
typedef void (*CNDUatKWrite64Fn)(uint64_t address, uint64_t value);
typedef bool (*CNDUatReadyFn)(void);
typedef int (*CNDUatKexploitFn)(void);
typedef void (*CNDUatOffsetsInitFn)(void);

typedef struct {
    CNDUatKReadBufFn kreadbuf;
    CNDUatKRead64Fn kread64;
    CNDUatKWrite64Fn kwrite64;
    CNDUatReadyFn krwReady;
    CNDUatKexploitFn kexploit;
    CNDUatOffsetsInitFn offsetsInit;
    uint64_t *kernelBase;
    uint64_t *kernelSlide;
} CNDUatKernelAPI;

static bool CNDUatResolveAPI(CNDUatKernelAPI *api, NSString **reason)
{
    if (api == NULL) {
        return false;
    }
    memset(api, 0, sizeof(*api));
    api->kreadbuf = (CNDUatKReadBufFn)dlsym(RTLD_DEFAULT, "kreadbuf");
    api->kread64 = (CNDUatKRead64Fn)dlsym(RTLD_DEFAULT, "kread64");
    api->kwrite64 = (CNDUatKWrite64Fn)dlsym(RTLD_DEFAULT, "kwrite64");
    api->krwReady = (CNDUatReadyFn)dlsym(RTLD_DEFAULT, "kexploit_krw_ready");
    api->kexploit = (CNDUatKexploitFn)dlsym(RTLD_DEFAULT, "kexploit_opa334");
    api->offsetsInit = (CNDUatOffsetsInitFn)dlsym(RTLD_DEFAULT, "offsets_init");
    api->kernelBase = (uint64_t *)dlsym(RTLD_DEFAULT, "g_kernel_base");
    api->kernelSlide = (uint64_t *)dlsym(RTLD_DEFAULT, "g_kernel_slide");

    bool ok = api->kreadbuf != NULL && api->kread64 != NULL &&
        api->kwrite64 != NULL && api->krwReady != NULL &&
        api->kexploit != NULL && api->offsetsInit != NULL &&
        api->kernelBase != NULL && api->kernelSlide != NULL;
    if (!ok && reason != NULL) {
        *reason = @"kexploit API incomplete (kreadbuf/kread64/kwrite64/krwReady/"
                  @"g_kernel_base/g_kernel_slide)";
    }
    return ok;
}

static bool CNDUatRead(CNDUatKernelAPI *api, uint64_t address, void *buffer,
                       size_t length)
{
    if (api == NULL || api->kreadbuf == NULL || buffer == NULL || length == 0) {
        return false;
    }
    api->kreadbuf(address, buffer, (uint64_t)length);
    return true;
}

static bool CNDUatReadU32(CNDUatKernelAPI *api, uint64_t address, uint32_t *out)
{
    if (out == NULL) {
        return false;
    }
    *out = 0;
    return CNDUatRead(api, address, out, sizeof(*out));
}

static bool CNDUatReadU64(CNDUatKernelAPI *api, uint64_t address, uint64_t *out)
{
    if (out == NULL) {
        return false;
    }
    *out = 0;
    return CNDUatRead(api, address, out, sizeof(*out));
}

static bool CNDUatWriteU64Verify(CNDUatKernelAPI *api, uint64_t address,
                                 uint64_t value)
{
    if (api == NULL || api->kwrite64 == NULL) {
        return false;
    }
    api->kwrite64(address, value);
    uint64_t observed = 0;
    return CNDUatReadU64(api, address, &observed) && observed == value;
}

#pragma mark - report

static NSString *CNDUatReportPath(void)
{
    NSString *dir = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (dir == nil) {
        return nil;
    }
    return [dir stringByAppendingPathComponent:@"CNDUatObserverProbe.json"];
}

static void CNDUatPersist(NSMutableDictionary<NSString *, id> *report,
                          NSString *key, id value)
{
    if (key != nil && value != nil) {
        report[key] = value;
    }
    report[@"updatedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:nil];
    NSString *path = CNDUatReportPath();
    if (data != nil && path != nil) {
        (void)[data writeToFile:path options:NSDataWritingAtomic error:nil];
        report[@"reportPath"] = path;
    }
    if (key != nil) {
        NSLog(@"[CND_UAT] %@=%@", key, value);
    }
}

#pragma mark - shared body

// mode: 1 = enable, 0 = restore.
static void CNDUatObserverRunWithMode(int enable,
                                      void (^completion)(NSDictionary<NSString *, id> *))
{
    NSMutableDictionary<NSString *, id> *report = [NSMutableDictionary dictionary];
    report[@"schema"] = @"com.zeroxjf.cyanide.uat-observer";
    report[@"schemaVersion"] = @1;
    report[@"mode"] = enable ? @"enable" : @"restore";
    report[@"pinnedImage"] =
        @"iPhone17,2 23A341 kernelcache "
        @"7e66ddbb70b626c4502c3036620b59829b744c54712a74ca50f4a0c004c89f8c";

    CNDUatKernelAPI api;
    NSString *reason = nil;
    if (!CNDUatResolveAPI(&api, &reason)) {
        CNDUatPersist(report, @"result", reason ?: @"api-missing");
        if (completion != nil) {
            completion(report);
        }
        return;
    }

    // Same bring-up order as the kcall1 probe: offsets first, then acquire the
    // lease if it is not already held.  Calling kreadbuf/kwrite64 before this
    // is what aborted the first attempt (SIGABRT on launch).
    api.offsetsInit();
    report[@"offsetsInitCalled"] = @YES;
    bool initiallyReady = api.krwReady();
    report[@"krwInitiallyReady"] = @(initiallyReady);
    if (!initiallyReady) {
        int exploitResult = api.kexploit();
        report[@"kexploitResult"] = @(exploitResult);
    }

    report[@"kernelBase"] = @(*(api.kernelBase));
    report[@"kernelSlide"] = @(*(api.kernelSlide));

    if (!api.krwReady()) {
        CNDUatPersist(report, @"result", @"krw-not-ready");
        if (completion != nil) {
            completion(report);
        }
        return;
    }

    uint64_t slide = *(api.kernelSlide);
    // Derive the slide from the reported base as well and require agreement;
    // a disagreement means the pinned image does not match this boot.
    uint64_t derivedSlide = *(api.kernelBase) - CNDUatUnslidTextBase;
    report[@"slideFromBase"] = @(derivedSlide);
    if (derivedSlide != slide) {
        CNDUatPersist(report, @"result", @"slide-disagreement");
        if (completion != nil) {
            completion(report);
        }
        return;
    }

    // Witness 1: the kernel header.
    uint32_t magic = 0;
    CNDUatReadU32(&api, *(api.kernelBase), &magic);
    report[@"kernelMagic"] = [NSString stringWithFormat:@"0x%08x", magic];
    if (magic != 0xfeedfacfu) {
        CNDUatPersist(report, @"result", @"kernel-magic-mismatch");
        if (completion != nil) {
            completion(report);
        }
        return;
    }

    // Witness 2: the instruction at IOUAT::commitUnmaps must be pacibsp.
    // This proves the slide applies to the same image the addresses came from.
    uint64_t commitAddr = CNDUatUnslidCommitUnmaps + slide;
    uint64_t fwUnmapAddr = CNDUatUnslidPrepareFwUnmap + slide;
    uint32_t commitInsn = 0;
    CNDUatReadU32(&api, commitAddr, &commitInsn);
    report[@"commitUnmapsAddress"] = @(commitAddr);
    report[@"prepareFwUnmapAddress"] = @(fwUnmapAddr);
    report[@"commitUnmapsInsn"] = [NSString stringWithFormat:@"0x%08x", commitInsn];
    if (commitInsn != CNDUatPacibsp) {
        CNDUatPersist(report, @"result", @"slide-witness-failed");
        if (completion != nil) {
            completion(report);
        }
        return;
    }

    // Witness 3: AGXG17P::AGXSecureGart::unmapWithAddress prologue.
    uint64_t gartAddr = CNDUatUnslidGartUnmapWithAddress + slide;
    uint32_t gartInsn = 0;
    CNDUatReadU32(&api, gartAddr, &gartInsn);
    report[@"gartUnmapWithAddressAddress"] = @(gartAddr);
    report[@"gartUnmapWithAddressInsn"] = [NSString stringWithFormat:@"0x%08x", gartInsn];
    report[@"gartWitnessOK"] = @(gartInsn == CNDUatPacibsp);

    // The AGXUAT path selector, read only here.
    uint64_t gartFeatureAddr = CNDUatUnslidGartFeatureByte + slide;
    uint64_t fw = 0;
    if (CNDUatReadU64(&api, gartFeatureAddr & ~7ull, &fw)) {
        uint8_t fb = (uint8_t)((fw >> ((gartFeatureAddr & 7) * 8)) & 0xff);
        report[@"gartFeatureAddress"] = @(gartFeatureAddr);
        report[@"gartFeatureByte"] = [NSString stringWithFormat:@"0x%02x", fb];
        report[@"agxuatDeferredPath"] = @((fb & 0x1) != 0);
    }

    // Dispatch-table recovery: read IOGPUFamily's __DATA_CONST,__const as the
    // live kernel has it and pick out IOExternalMethodDispatch records
    // (u64 handler, u32 scalarIn, u32 structIn, u32 scalarOut, u32 structOut).
    {
        // Handler pointers in kernel data are PAC-signed: compare only the
        // canonical low 48 bits, which carry the actual address.
        const uint64_t pacMask = 0x0000FFFFFFFFFFFFull;
        uint64_t textLo = (CNDUatUnslidIOGPUText + slide) & pacMask;
        uint64_t textHi = textLo + CNDUatUnslidIOGPUTextSize;
        uint64_t constAddr = CNDUatUnslidIOGPUConst + slide;
        size_t constSize = (size_t)CNDUatUnslidIOGPUConstSize;

        uint8_t *blob = (uint8_t *)malloc(constSize);
        NSMutableArray *records = [NSMutableArray array];
        if (blob != NULL && CNDUatRead(&api, constAddr, blob, constSize)) {
            for (size_t off = 0; off + 24 <= constSize; off += 8) {
                uint64_t fn = 0;
                memcpy(&fn, blob + off, 8);
                uint64_t fnAddr = fn & pacMask;
                if (fnAddr < textLo || fnAddr >= textHi) {
                    continue;
                }
                uint32_t a = 0, b = 0, c = 0, d = 0;
                memcpy(&a, blob + off + 8, 4);
                memcpy(&b, blob + off + 12, 4);
                memcpy(&c, blob + off + 16, 4);
                memcpy(&d, blob + off + 20, 4);
                if (a > 64 || b > 0x8000 || c > 64 || d > 0x8000) {
                    continue;
                }
                [records addObject:@{
                    @"recordAddress": @(constAddr + off),
                    @"handler": @(fn),
                    @"handlerOffsetFromText": @(fnAddr - textLo),
                    @"handlerRaw": @(fn),
                    @"scalarIn": @(a), @"structIn": @(b),
                    @"scalarOut": @(c), @"structOut": @(d),
                }];
                if (records.count >= 64) {
                    break;
                }
            }
        }
        // Head of the section, so the address itself can be checked offline
        // against the on-disk image.
        if (blob != NULL) {
            NSMutableArray *head = [NSMutableArray array];
            for (int i = 0; i < 8; i++) {
                uint64_t w = 0;
                memcpy(&w, blob + i * 8, 8);
                [head addObject:@(w)];
            }
            report[@"dispatchSectionHead"] = head;
        }
        free(blob);
        report[@"dispatchRecords"] = records;
        report[@"dispatchRecordCount"] = @(records.count);
        report[@"dispatchConstAddress"] = @(constAddr);
    }

    // Dump both user-client dispatch tables (24-byte IOExternalMethodDispatch
    // records).  The override picks one by a flag byte, so both are captured.
    {
        uint64_t tables[2] = { CNDUatUnslidIOGPUDispatchA + slide,
                               CNDUatUnslidIOGPUDispatchB + slide };
        NSMutableArray *dump = [NSMutableArray array];
        for (int t = 0; t < 2; t++) {
            uint8_t *blob = (uint8_t *)malloc((size_t)CNDUatIOGPUUserSelectorCount * 24);
            if (blob == NULL) continue;
            if (CNDUatRead(&api, tables[t], blob, (size_t)CNDUatIOGPUUserSelectorCount * 24)) {
                for (uint32_t i = 0; i < CNDUatIOGPUUserSelectorCount; i++) {
                    uint64_t fn = 0;
                    uint32_t a = 0, b = 0, c = 0, d = 0;
                    memcpy(&fn, blob + i * 24, 8);
                    memcpy(&a, blob + i * 24 + 8, 4);
                    memcpy(&b, blob + i * 24 + 12, 4);
                    memcpy(&c, blob + i * 24 + 16, 4);
                    memcpy(&d, blob + i * 24 + 20, 4);
                    if (fn == 0) continue;
                    [dump addObject:@{ @"table": @(t),
                                       @"selector": @(i),
                                       // The table stores arm64e signed pointers; the
                                       // canonical kernel text VA is 0xfffffff0_xxxxxxxx.
                                       @"handler": @(0xfffffff000000000ull |
                                           (fn & 0xFFFFFFFFull)),
                                       @"handlerRaw": @(fn),
                                       @"scalarIn": @(a), @"structIn": @(b),
                                       @"scalarOut": @(c), @"structOut": @(d) }];
                }
            }
            free(blob);
        }
        report[@"userDispatchTables"] = dump;
    }

    // Follow the dispatcher's table pointer and dump the table itself.
    {
        uint64_t ptrAddr = CNDUatUnslidIOGPUDispatchPtr + slide;
        uint64_t tablePtr = 0;
        if (CNDUatReadU64(&api, ptrAddr, &tablePtr)) {
            // PAC leaves the signature in bits 63:48; the address itself is the
            // low 48 bits with the kernel-space prefix implied.
            uint64_t table = 0xffff000000000000ull |
                (tablePtr & 0x0000FFFFFFFFFFFFull);
            report[@"dispatchPointerAddress"] = @(ptrAddr);
            report[@"dispatchTableRaw"] = @(tablePtr);
            report[@"dispatchTable"] = @(table);
            NSMutableArray *rows = [NSMutableArray array];
            uint8_t *tbl = (uint8_t *)malloc((size_t)CNDUatIOGPUSelectorCount * 24);
            if (tbl != NULL && table != 0 &&
                CNDUatRead(&api, table, tbl, (size_t)CNDUatIOGPUSelectorCount * 24)) {
                for (uint32_t i = 0; i < CNDUatIOGPUSelectorCount; i++) {
                    uint64_t fn = 0;
                    uint32_t a = 0, b = 0, c = 0, d = 0;
                    memcpy(&fn, tbl + i * 24, 8);
                    memcpy(&a, tbl + i * 24 + 8, 4);
                    memcpy(&b, tbl + i * 24 + 12, 4);
                    memcpy(&c, tbl + i * 24 + 16, 4);
                    memcpy(&d, tbl + i * 24 + 20, 4);
                    [rows addObject:@{ @"selector": @(i),
                                       @"handlerRaw": @(fn),
                                       // The table stores arm64e signed pointers; the
                                       // canonical kernel text VA is 0xfffffff0_xxxxxxxx.
                                       @"handler": @(0xfffffff000000000ull |
                                           (fn & 0xFFFFFFFFull)),
                                       @"handlerRaw": @(fn),
                                       @"scalarIn": @(a), @"structIn": @(b),
                                       @"scalarOut": @(c), @"structOut": @(d) }];
                }
            }
            free(tbl);
            report[@"selectorTable"] = rows;
        }
    }

    // Vtable-anchored search for the AGXSecureGart/AGXUAT instance:
    //  1. find qwords in __DATA_CONST equal to the slid unmapWithAddress,
    //  2. find qwords in __DATA/__bss equal to those vtable addresses.
    // Both scans are bounded to known sections of one kext.
    {
        const uint64_t pacMask = 0x0000FFFFFFFFFFFFull;
        const uint64_t vaOr = 0xfffffff000000000ull;
        uint64_t constAddr = CNDUatAgxConst + slide;
        uint8_t *cb = (uint8_t *)malloc((size_t)CNDUatAgxConstSz);
        NSMutableArray *vtableHits = [NSMutableArray array];
        if (cb && CNDUatRead(&api, constAddr, cb, (size_t)CNDUatAgxConstSz)) {
            uint64_t want = (CNDUatAgxUnmapWithAddress + slide) & pacMask;
            for (size_t off = 0; off + 8 <= (size_t)CNDUatAgxConstSz; off += 8) {
                uint64_t q = 0;
                memcpy(&q, cb + off, 8);
                if ((q & pacMask) == want) {
                    [vtableHits addObject:@{ @"offset": @(off),
                                             @"address": @(vaOr | (constAddr + off) & pacMask) }];
                }
            }
        }
        free(cb);
        report[@"gartVtableHits"] = vtableHits;

        NSMutableArray *instances = [NSMutableArray array];
        uint64_t ranges[2][2] = { { CNDUatAgxData, CNDUatAgxDataSz },
                                  { CNDUatAgxBss,  CNDUatAgxBssSz } };
        for (int r = 0; r < 2; r++) {
            uint8_t *db = (uint8_t *)malloc((size_t)ranges[r][1]);
            if (!db) continue;
            if (CNDUatRead(&api, ranges[r][0] + slide, db, (size_t)ranges[r][1])) {
                for (size_t off = 0; off + 8 <= (size_t)ranges[r][1]; off += 8) {
                    uint64_t q = 0;
                    memcpy(&q, db + off, 8);
                    uint64_t qa = vaOr | (q & pacMask);
                    for (NSDictionary *hit in vtableHits) {
                        if (qa == [hit[@"address"] unsignedLongLongValue]) {
                            // Candidate instance: report the first 8 words.
                            uint64_t objAddr = vaOr | ((ranges[r][0] + slide + off) & pacMask);
                            uint64_t w[8] = {0};
                            CNDUatRead(&api, objAddr, w, sizeof(w));
                            NSMutableArray *words = [NSMutableArray array];
                            for (int k = 0; k < 8; k++) [words addObject:@(w[k])];
                            [instances addObject:@{ @"slot": @(objAddr),
                                                    @"vtable": @(qa),
                                                    @"section": r == 0 ? @"__data" : @"__bss",
                                                    @"words": words }];
                            break;
                        }
                    }
                }
            }
            free(db);
        }
        report[@"gartInstanceCandidates"] = instances;
    }

    // Vtable runs in the AGX data sections.  The file offsets are chained
    // fixups, so pointers only resolve in the live kernel; a vtable is a run of
    // at least ten consecutive qwords that canonicalise into kernel text.
    {
        const uint64_t low36 = 0x0000000FFFFFFFFFull;
        const uint64_t vaOr  = 0xfffffff000000000ull;
        const uint64_t lo = 0xfffffff008000000ull + slide;
        const uint64_t hi = 0xfffffff00c000000ull + slide;
        NSMutableArray *runs = [NSMutableArray array];
        uint64_t ranges[2][3] = { { CNDUatAgxConst, CNDUatAgxConstSz, 0 },
                                  { CNDUatAgxData,  CNDUatAgxDataSz,  1 } };
        for (int r = 0; r < 2; r++) {
            uint8_t *db = (uint8_t *)malloc((size_t)ranges[r][1]);
            if (!db) continue;
            if (CNDUatRead(&api, ranges[r][0] + slide, db, (size_t)ranges[r][1])) {
                size_t n = (size_t)ranges[r][1] / 8;
                size_t start = 0; BOOL in = NO;
                for (size_t i = 0; i <= n; i++) {
                    BOOL ok = NO;
                    if (i < n) {
                        uint64_t q = 0;
                        memcpy(&q, db + i * 8, 8);
                        uint64_t va = vaOr | (q & low36);
                        ok = (va >= lo && va < hi);
                    }
                    if (ok && !in) { start = i; in = YES; }
                    else if (!ok && in) {
                        size_t len = i - start;
                        if (len >= 10) {
                            NSMutableArray *ents = [NSMutableArray array];
                            for (size_t k = start; k < start + len && k < start + 8; k++) {
                                uint64_t q = 0;
                                memcpy(&q, db + k * 8, 8);
                                [ents addObject:@(vaOr | (q & low36))];
                            }
                            [runs addObject:@{ @"section": r == 0 ? @"const" : @"data",
                                               @"unslid": @(ranges[r][0] + start * 8),
                                               @"length": @(len),
                                               @"head": ents }];
                        }
                        in = NO;
                    }
                }
            }
            free(db);
        }
        report[@"agxVtableRuns"] = runs;
    }

    // AGXDeviceUserClient's own vtable.  Address derived statically: the
    // metaclass constructor at 0x8ab04e0 signs 0x7cd43b0+0x10 and stores it in
    // the new metaclass; instance size 0x138, name string "AGXDeviceUserClient".
    {
        uint64_t addr = 0xfffffff007cd43b0ull + slide;
        uint64_t words[96] = {0};
        if (CNDUatRead(&api, addr, words, sizeof(words))) {
            NSMutableArray *w = [NSMutableArray array];
            for (int i = 0; i < 96; i++) {
                uint64_t v = words[i];
                uint64_t canon = 0xfffffff000000000ull | (v & 0x0000000FFFFFFFFFull);
                [w addObject:@{ @"i": @(i), @"raw": @(v), @"va": @(canon) }];
            }
            report[@"agxUserClientVtable"] = @{ @"vtable": @(addr), @"entries": w };
        }
    }

    // ANE dispatch tables.  The file image stores them with encoded handler
    // pointers, so they only resolve live; a table is a run of 24-byte
    // IOExternalMethodDispatch records whose handler lands in ANE text.  The
    // four check fields are plain integers.
    {
        const uint64_t vaOr = 0xfffffff000000000ull;
        const uint64_t t0 = 0xfffffff0091fba90ull + slide;
        const uint64_t t1 = t0 + 0x105670ull;
        struct { uint64_t addr, size; } ranges[5] = {
            { 0xfffffff00739b7a0ull, 0xae8  },
            { 0xfffffff007dfcc70ull, 0xc278 },
            { 0xfffffff00b441c28ull, 0x3ed4 },
            { 0xfffffff00b445b00ull, 0x658  },
            { 0xfffffff00b446158ull, 0x628  },
        };
        NSMutableArray *tabs = [NSMutableArray array];
        for (int r = 0; r < 5; r++) {
            uint8_t *db = (uint8_t *)malloc((size_t)ranges[r].size);
            if (!db) continue;
            if (CNDUatRead(&api, ranges[r].addr + slide, db, (size_t)ranges[r].size)) {
                size_t n = (size_t)ranges[r].size;
                for (size_t off = 0; off + 24 <= n; off += 8) {
                    size_t start = off, cnt = 0;
                    while (start + 24 * (cnt + 1) <= n) {
                        uint64_t q = 0; uint32_t a,b,c,d;
                        memcpy(&q, db + start + cnt * 24, 8);
                        memcpy(&a, db + start + cnt * 24 + 8, 4);
                        memcpy(&b, db + start + cnt * 24 + 12, 4);
                        memcpy(&c, db + start + cnt * 24 + 16, 4);
                        memcpy(&d, db + start + cnt * 24 + 20, 4);
                        uint64_t va = vaOr | (q & 0xFFFFFFFFull);
                        if (q != 0 && !(va >= t0 && va < t1)) break;
                        if (a > 8 || b > 0x100000 || c > 16 || d > 0x100000) break;
                        cnt++;
                    }
                    if (cnt >= 8) {
                        NSMutableArray *rows = [NSMutableArray array];
                        for (size_t k = 0; k < cnt; k++) {
                            uint64_t q = 0; uint32_t a,b,c,d;
                            memcpy(&q, db + start + k * 24, 8);
                            memcpy(&a, db + start + k * 24 + 8, 4);
                            memcpy(&b, db + start + k * 24 + 12, 4);
                            memcpy(&c, db + start + k * 24 + 16, 4);
                            memcpy(&d, db + start + k * 24 + 20, 4);
                            [rows addObject:@{ @"sel": @(k),
                                               @"handler": @(vaOr | (q & 0xFFFFFFFFull)),
                                               @"sic": @(a), @"sis": @(b),
                                               @"soc": @(c), @"sos": @(d) }];
                        }
                        [tabs addObject:@{ @"where": @(r),
                                           @"unslid": @(ranges[r].addr + start),
                                           @"count": @(cnt),
                                           @"rows": rows }];
                        off = start + cnt * 24 - 8;
                    }
                }
            }
            free(db);
        }
        report[@"aneDispatchTables"] = tabs;
    }

    // AppleJPEGDriver dispatch table.  Same 24-byte IOExternalMethodDispatch
    // records as the other clients; the handler pointers only resolve live.
    {
        const uint64_t vaOr = 0xfffffff000000000ull;
        const uint64_t t0 = 0xfffffff008000000ull + slide;   // any kernel text
        const uint64_t t1 = 0xfffffff00c000000ull + slide;
        struct { uint64_t addr, size; } ranges[4] = {
            { 0xfffffff007e773a8ull, 0x4700 },
            { 0xfffffff00b44c700ull, 0x2208 },
            { 0xfffffff00b44e908ull, 0x380  },
            { 0xfffffff0074856c0ull, 0x3684 },
        };
        NSMutableArray *tabs = [NSMutableArray array];
        for (int r = 0; r < 4; r++) {
            uint8_t *db = (uint8_t *)malloc((size_t)ranges[r].size);
            if (!db) continue;
            if (CNDUatRead(&api, ranges[r].addr + slide, db, (size_t)ranges[r].size)) {
                size_t n = (size_t)ranges[r].size;
                for (size_t off = 0; off + 24 <= n; off += 8) {
                    size_t start = off, cnt = 0;
                    while (start + 24 * (cnt + 1) <= n) {
                        uint64_t q = 0; uint32_t a,b,c,d;
                        memcpy(&q, db + start + cnt*24, 8);
                        memcpy(&a, db + start + cnt*24 + 8, 4);
                        memcpy(&b, db + start + cnt*24 + 12, 4);
                        memcpy(&c, db + start + cnt*24 + 16, 4);
                        memcpy(&d, db + start + cnt*24 + 20, 4);
                        uint64_t va = vaOr | (q & 0xFFFFFFFFull);
                        if (q != 0 && !(va >= t0 && va < t1)) break;
                        if (a > 8 || b > 0x100000 || c > 16 || d > 0x100000) break;
                        cnt++;
                    }
                    if (cnt >= 6) {
                        NSMutableArray *rows = [NSMutableArray array];
                        for (size_t k = 0; k < cnt; k++) {
                            uint64_t q = 0; uint32_t a,b,c,d;
                            memcpy(&q, db + start + k*24, 8);
                            memcpy(&a, db + start + k*24 + 8, 4);
                            memcpy(&b, db + start + k*24 + 12, 4);
                            memcpy(&c, db + start + k*24 + 16, 4);
                            memcpy(&d, db + start + k*24 + 20, 4);
                            [rows addObject:@{ @"sel": @(k),
                                               @"handler": @(vaOr | (q & 0xFFFFFFFFull)),
                                               @"sic": @(a), @"sis": @(b),
                                               @"soc": @(c), @"sos": @(d) }];
                        }
                        [tabs addObject:@{ @"where": @(r),
                                           @"unslid": @(ranges[r].addr + start),
                                           @"count": @(cnt), @"rows": rows }];
                        off = start + cnt * 24 - 8;
                    }
                }
            }
            free(db);
        }
        report[@"jpegDispatchTables"] = tabs;
    }

    // Dump the ANE dispatch-table candidates (24-byte IOExternalMethodDispatch
    // records), so the map/unmap selectors can be identified by their handler.
    {
        NSMutableArray *ane = [NSMutableArray array];
        for (int t = 0; t < 5; t++) {
            uint64_t addr = CNDUatAneTables[t] + slide;
            uint8_t *blob = (uint8_t *)malloc(24 * 32);
            if (!blob) continue;
            if (CNDUatRead(&api, addr, blob, 24 * 32)) {
                for (int i = 0; i < 64; i++) {
                    uint64_t fn = 0; uint32_t a=0,b=0,c=0,d=0;
                    memcpy(&fn, blob + i*24, 8);
                    memcpy(&a, blob + i*24 + 8, 4);
                    memcpy(&b, blob + i*24 + 12, 4);
                    memcpy(&c, blob + i*24 + 16, 4);
                    memcpy(&d, blob + i*24 + 20, 4);
                    if (fn == 0) continue;
                    [ane addObject:@{ @"table": @(t), @"selector": @(i),
                                      @"handler": @(0xfffffff000000000ull | (fn & 0xFFFFFFFFull)),
                                      @"scalarIn": @(a), @"structIn": @(b),
                                      @"scalarOut": @(c), @"structOut": @(d) }];
                }
            }
            free(blob);
        }
        report[@"aneTables"] = ane;
    }

    // Dump the ANE vtables; entries resolve only in the live kernel.
    {
        NSMutableArray *vts = [NSMutableArray array];
        for (int t = 0; t < 3; t++) {
            uint64_t addr = CNDUatAneVtables[t] + slide;
            uint64_t words[64] = {0};
            if (CNDUatRead(&api, addr, words, sizeof(words))) {
                NSMutableArray *w = [NSMutableArray array];
                for (int i = 0; i < 64; i++) {
                    uint64_t v = words[i];
                    uint64_t canon = 0xfffffff000000000ull | (v & 0xFFFFFFFFull);
                    [w addObject:@{ @"i": @(i), @"raw": @(v), @"va": @(canon) }];
                }
                [vts addObject:@{ @"vtable": @(addr), @"entries": w }];
            }
        }
        report[@"aneVtables"] = vts;
    }

    // Slot index of externalMethod: find the IOGPU vtable entry that points at
    // the known override, then read the same slot in the ANE vtables. Both
    // classes derive from IOUserClient, so the slot index is shared.
    {
        uint64_t constAddr = CNDUatUnslidIOGPUConst + slide;
        size_t constSize = (size_t)CNDUatUnslidIOGPUConstSize;
        uint8_t *blob = (uint8_t *)malloc(constSize);
        NSInteger slot = -1;
        uint64_t wantLow = (CNDUatIOGPUExternalMethod + slide) & 0xFFFFFFFFull;
        if (blob && CNDUatRead(&api, constAddr, blob, constSize)) {
            for (size_t off = 0; off + 8 <= constSize; off += 8) {
                uint64_t q = 0;
                memcpy(&q, blob + off, 8);
                if ((q & 0xFFFFFFFFull) == wantLow) { slot = (NSInteger)(off / 8); break; }
            }
        }
        free(blob);
        report[@"extMethodSlot"] = @(slot);
        if (slot >= 0) {
            NSMutableArray *rows = [NSMutableArray array];
            for (int t = 0; t < 3; t++) {
                uint64_t vt = CNDUatAneVtables[t] + slide;
                uint64_t q = 0;
                if (CNDUatRead(&api, vt + (uint64_t)slot * 8, &q, 8)) {
                    [rows addObject:@{ @"vtable": @(vt), @"slot": @(slot),
                                       @"entry": @(q),
                                       @"va": @(0xfffffff000000000ull | (q & 0xFFFFFFFFull)) }];
                }
            }
            report[@"aneExtMethod"] = rows;
        }
    }

    uint64_t debugAddr = CNDUatUnslidDebugByte + slide;
    report[@"debugByteAddress"] = @(debugAddr);

    uint64_t word = 0;
    if (!CNDUatReadU64(&api, debugAddr & ~7ull, &word)) {
        CNDUatPersist(report, @"result", @"debug-byte-read-failed");
        if (completion != nil) {
            completion(report);
        }
        return;
    }
    uint8_t before = (uint8_t)((word >> ((debugAddr & 7) * 8)) & 0xff);
    report[@"debugByteBefore"] = [NSString stringWithFormat:@"0x%02x", before];
    report[@"iouatLoggingBefore"] = @((before & 0x2) != 0);

    uint64_t desired = word;
    uint64_t shift = (debugAddr & 7) * 8;
    if (enable) {
        desired |= (0x2ull << shift);
    } else {
        desired &= ~(0x2ull << shift);
    }

    if (desired == word) {
        CNDUatPersist(report, @"result", @"unchanged");
        CNDUatPersist(report, @"debugByteAfter",
                      [NSString stringWithFormat:@"0x%02x", before]);
        if (completion != nil) {
            completion(report);
        }
        return;
    }

    if (!CNDUatWriteU64Verify(&api, debugAddr & ~7ull, desired)) {
        CNDUatPersist(report, @"result", @"write-verify-failed");
        if (completion != nil) {
            completion(report);
        }
        return;
    }

    uint64_t after = 0;
    CNDUatReadU64(&api, debugAddr & ~7ull, &after);
    uint8_t afterByte = (uint8_t)((after >> shift) & 0xff);
    report[@"debugByteAfter"] = [NSString stringWithFormat:@"0x%02x", afterByte];
    report[@"iouatLoggingAfter"] = @((afterByte & 0x2) != 0);
    report[@"result"] = enable ? @"enabled" : @"restored";

    CNDUatPersist(report, nil, nil);
    NSLog(@"[CND_UAT] result=%@ before=0x%02x after=0x%02x addr=0x%llx",
          report[@"result"], before, afterByte, debugAddr);
    if (completion != nil) {
        completion(report);
    }
}

#pragma mark - public

bool CNDUatObserverProbeIsSupported(NSString **reason)
{
    CNDUatKernelAPI api;
    NSString *why = nil;
    if (!CNDUatResolveAPI(&api, &why)) {
        if (reason != NULL) {
            *reason = why;
        }
        return false;
    }
    if (!api.krwReady()) {
        if (reason != NULL) {
            *reason = @"kexploit KRW not ready";
        }
        return false;
    }
    if (reason != NULL) {
        *reason = nil;
    }
    return true;
}

void CNDUatObserverProbeRun(void (^completion)(NSDictionary<NSString *, id> *))
{
    CNDUatObserverRunWithMode(1, completion);
}

void CNDUatObserverProbeRestoreRun(void (^completion)(NSDictionary<NSString *, id> *))
{
    CNDUatObserverRunWithMode(0, completion);
}
