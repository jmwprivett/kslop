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
