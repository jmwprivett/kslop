#import <Foundation/Foundation.h>

#import <CommonCrypto/CommonDigest.h>

#import "../../Cyanide/tweaks/CNDCCMaterialRecipeCompiler.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#ifndef CND_CC_RECIPE_CANARY_ACTION
#define CND_CC_RECIPE_CANARY_ACTION 0
#endif

#ifndef CND_CC_RECIPE_CANARY_EXPECTED_PID
#define CND_CC_RECIPE_CANARY_EXPECTED_PID 0
#endif

#ifndef CND_CC_RECIPE_CANARY_OUTPUT_TOKEN
#define CND_CC_RECIPE_CANARY_OUTPUT_TOKEN ""
#endif

#ifndef CND_CC_RECIPE_CANARY_APP_NATIVE
#define CND_CC_RECIPE_CANARY_APP_NATIVE 0
#endif

static NSString *const CNDTarget =
    @"/System/Library/PrivateFrameworks/CoreMaterial.framework/modulesBackground.materialrecipe";
static NSString *const CNDBackupName = @"modulesBackground.stock.materialrecipe";
static NSString *const CNDPayloadName = @"modulesBackground.purple.materialrecipe";
static NSString *const CNDJournalName = @"journal.json";
static NSString *const CNDReportName = @"report.json";
static NSString *const CNDRequestName = @"request.json";
static const NSUInteger CNDExpectedRecipeLength = 343;
#if CND_CC_RECIPE_CANARY_APP_NATIVE
// Located and disassembled from the exact 23A341 VPHONE600 kernel UUID
// 03A93373-6498-3F25-8975-04DED251AF1F. This remains an unslid, build-bound
// offset; the validated provider supplies the current boot's kernel base.
static const uint64_t CNDCurrentProcOffset23A341 = 0x112500c;
static const uint32_t CNDCurrentProcInstructions23A341[] = {
    0xd503237f, 0xa9bf7bfd, 0x910003fd, 0x97e941b1,
    0xf9400c00, 0xb4000060, 0xa8c17bfd, 0xd65f0fff,
    0x90ffb308, 0xf940b500, 0xa8c17bfd, 0xd65f0fff,
};
// Verified from the exact 23A341 vnode/namecache layouts. These complement
// Cyanide's existing offsets with fields that are only used by this VM canary.
static const uint32_t CNDVnodeVIDOffset23A341 = 0x74;
static const uint32_t CNDNamecacheNCVIDOffset23A341 = 0x40;
static const uint32_t CNDNamecacheNCNameOffset23A341 = 0x60;
#endif

typedef int (*CNDKExploitFunction)(void);
typedef uint64_t (*CNDOverwriteFunction)(char *, char *);

static NSString *CNDCanaryDirectory(void)
{
#if CND_CC_RECIPE_CANARY_APP_NATIVE
    const char *fixedHome = getenv("CFFIXED_USER_HOME");
    NSString *home = fixedHome ? @(fixedHome) : nil;
    if (![home hasPrefix:@"/private/var/mobile/Containers/Data/Application/"]) {
        home = NSHomeDirectory();
    }
    return [home stringByAppendingPathComponent:
        @"Library/Application Support/CNDCCMaterialRecipeVMCanary"];
#else
    return @"/var/tmp/cnd-cc-material-recipe-canary";
#endif
}

static NSString *CNDPath(NSString *name)
{
    return [CNDCanaryDirectory() stringByAppendingPathComponent:name];
}

static NSString *CNDSHA256(NSData *data)
{
    if (!data) return @"";
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *value = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger index = 0; index < sizeof(digest); index++) {
        [value appendFormat:@"%02x", digest[index]];
    }
    return value;
}

static BOOL CNDWriteDurable(NSData *data, NSString *path, NSError **error)
{
    if (![data writeToFile:path options:NSDataWritingAtomic error:error]) return NO;
    int descriptor = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    BOOL synchronized = descriptor >= 0 && fsync(descriptor) == 0;
    if (descriptor >= 0) close(descriptor);
    if (!synchronized && error && !*error) {
        *error = [NSError errorWithDomain:@"CNDCCRecipeCanary" code:1
            userInfo:@{NSLocalizedDescriptionKey: @"The staged file could not be synchronized."}];
    }
    return synchronized;
}

static BOOL CNDWriteJSON(NSDictionary *object, NSString *path, NSError **error)
{
    NSData *data = [NSJSONSerialization dataWithJSONObject:object
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:error];
    return data && CNDWriteDurable(data, path, error);
}

static NSDictionary *CNDReadJSON(NSString *path)
{
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:NULL];
    id value = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] : nil;
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

static NSString *CNDCurrentBuild(void)
{
    char value[64] = {0};
    size_t length = sizeof(value);
    return sysctlbyname("kern.osversion", value, &length, NULL, 0) == 0 ? @(value) : @"";
}

static BOOL CNDIsVPhone(void)
{
    char model[64] = {0};
    size_t length = sizeof(model);
    if (sysctlbyname("hw.model", model, &length, NULL, 0) == 0 &&
        length > 0 && length <= sizeof(model) && !strcmp(model, "VPHONE600AP")) return YES;
    char machine[64] = {0};
    length = sizeof(machine);
    return sysctlbyname("hw.machine", machine, &length, NULL, 0) == 0 &&
        length > 0 && length <= sizeof(machine) && !strncmp(machine, "iPhone99,", 9);
}

static NSMutableDictionary *CNDBaseReport(NSString *action)
{
    return [@{
        @"schemaVersion": @1,
        @"mode": @"vphone-cc-background-material-recipe-canary",
        @"action": action,
        @"success": @NO,
        @"targetPath": CNDTarget,
        @"targetFileWrites": @0,
        @"targetRedirects": @0,
        @"productBuildVersion": CNDCurrentBuild(),
        @"process": @(getprogname() ?: ""),
        @"pid": @(getpid()),
        @"expectedPID": @(CND_CC_RECIPE_CANARY_EXPECTED_PID),
        @"vphone": @(CNDIsVPhone()),
        @"parameters": @{
            @"red": @0.60, @"green": @0.05, @"blue": @1.00,
            @"opacity": @0.78, @"blurRadius": @25.0,
        },
    } mutableCopy];
}

static void CNDFinish(NSMutableDictionary *report, NSString *phase, NSString *message)
{
    report[@"phase"] = phase ?: @"unknown";
    report[@"message"] = message ?: @"";
    report[@"finishedAt"] = [NSISO8601DateFormatter.new stringFromDate:NSDate.date];
    NSError *error = nil;
    if (!CNDWriteJSON(report, CNDPath(CNDReportName), &error)) {
        fprintf(stderr, "[CND_CC_RECIPE_CANARY] report write failed: %s\n",
                error.localizedDescription.UTF8String ?: "unknown");
    }
}

static BOOL CNDPreflight(NSMutableDictionary *report)
{
#if CND_CC_RECIPE_CANARY_APP_NATIVE
    BOOL identity = !strcmp(getprogname(), "Cyanide");
#else
    BOOL identity = !strcmp(getprogname(), "Cyanide") &&
        CND_CC_RECIPE_CANARY_EXPECTED_PID > 1 &&
        getpid() == CND_CC_RECIPE_CANARY_EXPECTED_PID;
#endif
    if (!identity) {
        CNDFinish(report, @"refused-identity", @"The injected process identity did not match Cyanide.");
        return NO;
    }
    if (!CNDIsVPhone()) {
        CNDFinish(report, @"refused-environment", @"This canary runs only in the vPhone VM.");
        return NO;
    }
    if (![CNDCurrentBuild() isEqualToString:@"23A341"]) {
        CNDFinish(report, @"refused-build", @"This canary supports only iOS build 23A341.");
        return NO;
    }
    return YES;
}

static BOOL CNDPrepareKernelWriter(NSMutableDictionary *report,
                                   CNDOverwriteFunction *writerOut)
{
#if CND_CC_RECIPE_CANARY_APP_NATIVE
    extern int kexploit_opa334(void);
    extern uint64_t g_kernel_base;
    extern uint32_t kread32(uint64_t);
    extern int cnd_lab_kernel_call(uint64_t, size_t, const uint64_t *,
                                   uint64_t *);
    extern bool kutils_recover_self_proc_from(uint64_t);
    extern uint64_t proc_self(void);
    CNDKExploitFunction acquire = kexploit_opa334;
    CNDOverwriteFunction writer = NULL;
#else
    CNDKExploitFunction acquire = (CNDKExploitFunction)dlsym(RTLD_DEFAULT, "kexploit_opa334");
    CNDOverwriteFunction writer = (CNDOverwriteFunction)dlsym(RTLD_DEFAULT, "overwrite_system_file");
#endif
    report[@"resolvedKExploit"] = @(acquire != NULL);
    report[@"resolvedOverwrite"] = @(writer != NULL);
#if CND_CC_RECIPE_CANARY_APP_NATIVE
    if (!acquire) {
#else
    if (!acquire || !writer) {
#endif
        CNDFinish(report, @"refused-symbols", @"Cyanide's bounded VM writer symbols were unavailable.");
        return NO;
    }
    int result = acquire();
    report[@"kernelProviderResult"] = @(result);
    if (result != 0) {
        CNDFinish(report, @"refused-provider", @"The validated VM kernel provider was unavailable.");
        return NO;
    }
#if CND_CC_RECIPE_CANARY_APP_NATIVE
    uint64_t currentProcFunction =
        g_kernel_base + CNDCurrentProcOffset23A341;
    BOOL signatureValid = YES;
    NSMutableArray *observedCurrentProcInstructions = [NSMutableArray array];
    for (NSUInteger index = 0;
         index < sizeof(CNDCurrentProcInstructions23A341) /
                     sizeof(CNDCurrentProcInstructions23A341[0]); index++) {
        uint32_t observed = kread32(
            currentProcFunction + index * sizeof(uint32_t));
        [observedCurrentProcInstructions addObject:@(observed)];
        if (observed != CNDCurrentProcInstructions23A341[index]) {
            signatureValid = NO;
        }
    }
    uint64_t providerProc = 0;
    int currentProcCallResult = signatureValid
        ? cnd_lab_kernel_call(currentProcFunction, 0, NULL, &providerProc)
        : ENOTSUP;
    BOOL recoveredSelf = currentProcCallResult == 0 && providerProc != 0 &&
        kutils_recover_self_proc_from(providerProc);
    report[@"kernelBase"] = @(g_kernel_base);
    report[@"currentProcFunction"] = @(currentProcFunction);
    report[@"currentProcSignatureValid"] = @(signatureValid);
    report[@"currentProcObservedInstructions"] =
        observedCurrentProcInstructions;
    report[@"currentProcCallResult"] = @(currentProcCallResult);
    report[@"providerProc"] = @(providerProc);
    report[@"selfProcRecovered"] = @(recoveredSelf);
    report[@"selfProc"] = @(proc_self());
    if (!recoveredSelf || proc_self() == 0) {
        CNDFinish(report, @"refused-self-proc",
                  @"The VM provider could not recover Cyanide's live proc object.");
        return NO;
    }
#endif
    *writerOut = writer;
    return YES;
}

#if !CND_CC_RECIPE_CANARY_APP_NATIVE
static BOOL CNDWriteTarget(CNDOverwriteFunction writer, NSString *source,
                           NSString *expectedSHA, NSMutableDictionary *report)
{
    report[@"targetFileWrites"] = @([report[@"targetFileWrites"] unsignedIntegerValue] + 1);
    errno = 0;
    uint64_t result = writer((char *)CNDTarget.fileSystemRepresentation,
                             (char *)source.fileSystemRepresentation);
    int writerErrno = errno;
    NSData *readback = [NSData dataWithContentsOfFile:CNDTarget
        options:NSDataReadingMappedIfSafe error:NULL];
    NSString *readbackSHA = CNDSHA256(readback);
    report[@"overwriteResult"] = @(result);
    report[@"overwriteErrno"] = @(writerErrno);
    report[@"overwriteError"] = @(strerror(writerErrno));
    report[@"readbackLength"] = @(readback.length);
    report[@"readbackSHA256"] = readbackSHA;
    return result == 0 && readback.length == CNDExpectedRecipeLength &&
        [readbackSHA isEqualToString:expectedSHA];
}
#endif

static BOOL CNDBytesAreKnownPartialWrite(NSData *current, NSData *original,
                                         NSData *payload)
{
    if (current.length != original.length || current.length != payload.length) return NO;
    const uint8_t *actual = current.bytes;
    const uint8_t *before = original.bytes;
    const uint8_t *after = payload.bytes;
    for (NSUInteger index = 0; index < current.length; index++) {
        if (actual[index] != before[index] && actual[index] != after[index]) return NO;
    }
    return YES;
}

#if CND_CC_RECIPE_CANARY_APP_NATIVE
static BOOL CNDResolveRedirectState(NSString *payloadPath,
                                    NSMutableDictionary *report,
                                    uint64_t *targetVnodeOut,
                                    uint64_t *payloadVnodeOut,
                                    uint64_t *targetNamecacheOut,
                                    uint32_t *originalNCVIDOut,
                                    uint32_t *targetVIDOut,
                                    uint32_t *payloadVIDOut,
                                    uint32_t *targetUsecountOut,
                                    uint32_t *payloadUsecountOut)
{
    extern uint64_t get_vnode_for_path_by_open(const char *);
    extern uint64_t kread64(uint64_t);
    extern uint32_t kread32(uint64_t);
    extern void kreadbuf(uint64_t, void *, uint64_t);
    extern bool is_kaddr_valid(uint64_t);
    extern uint32_t off_vnode_v_usecount;
    extern uint32_t off_vnode_v_nclinks_lh_first;
    extern uint32_t off_namecache_nc_vp;

    uint64_t targetVnode = get_vnode_for_path_by_open(
        CNDTarget.fileSystemRepresentation);
    uint64_t payloadVnode = get_vnode_for_path_by_open(
        payloadPath.fileSystemRepresentation);
    BOOL offsetsValid = off_vnode_v_nclinks_lh_first == 0x40 &&
        off_namecache_nc_vp == 0x50 && off_vnode_v_usecount == 0x60;
    uint64_t targetNamecache = targetVnode != (uint64_t)-1
        ? kread64(targetVnode + off_vnode_v_nclinks_lh_first) : 0;
    uint64_t originalNCVnode = is_kaddr_valid(targetNamecache)
        ? kread64(targetNamecache + off_namecache_nc_vp) : 0;
    uint32_t originalNCVID = is_kaddr_valid(targetNamecache)
        ? kread32(targetNamecache + CNDNamecacheNCVIDOffset23A341) : 0;
    uint32_t targetVID = targetVnode != (uint64_t)-1
        ? kread32(targetVnode + CNDVnodeVIDOffset23A341) : 0;
    uint32_t payloadVID = payloadVnode != (uint64_t)-1
        ? kread32(payloadVnode + CNDVnodeVIDOffset23A341) : 0;
    uint64_t namePointer = is_kaddr_valid(targetNamecache)
        ? kread64(targetNamecache + CNDNamecacheNCNameOffset23A341) : 0;
    char observedName[64] = {0};
    if (is_kaddr_valid(namePointer)) {
        kreadbuf(namePointer, observedName, sizeof(observedName) - 1);
    }
    BOOL valid = targetVnode != (uint64_t)-1 &&
        payloadVnode != (uint64_t)-1 && targetVnode != payloadVnode &&
        is_kaddr_valid(targetVnode) && is_kaddr_valid(payloadVnode) &&
        offsetsValid && is_kaddr_valid(targetNamecache) &&
        originalNCVnode == targetVnode && originalNCVID == targetVID &&
        targetVID != 0 && payloadVID != 0 &&
        !strcmp(observedName, CNDTarget.lastPathComponent.UTF8String);
    report[@"redirectTargetVnode"] = @(targetVnode);
    report[@"redirectPayloadVnode"] = @(payloadVnode);
    report[@"redirectTargetNamecache"] = @(targetNamecache);
    report[@"redirectOriginalNCVnode"] = @(originalNCVnode);
    report[@"redirectOriginalNCVID"] = @(originalNCVID);
    report[@"redirectTargetVID"] = @(targetVID);
    report[@"redirectPayloadVID"] = @(payloadVID);
    report[@"redirectName"] = @(observedName);
    report[@"redirectOffsetsValid"] = @(offsetsValid);
    if (!valid) return NO;

    uint32_t targetUsecount = kread32(
        targetVnode + off_vnode_v_usecount);
    uint32_t payloadUsecount = kread32(
        payloadVnode + off_vnode_v_usecount);
    report[@"redirectTargetUsecountBefore"] = @(targetUsecount);
    report[@"redirectPayloadUsecountBefore"] = @(payloadUsecount);
    *targetVnodeOut = targetVnode;
    *payloadVnodeOut = payloadVnode;
    *targetNamecacheOut = targetNamecache;
    *originalNCVIDOut = originalNCVID;
    *targetVIDOut = targetVID;
    *payloadVIDOut = payloadVID;
    *targetUsecountOut = targetUsecount;
    *payloadUsecountOut = payloadUsecount;
    return YES;
}

static BOOL CNDApplyNamecacheRedirect(uint64_t targetVnode,
                                      uint64_t payloadVnode,
                                      uint64_t targetNamecache,
                                      uint32_t originalNCVID,
                                      uint32_t payloadVID,
                                      uint32_t targetUsecount,
                                      uint32_t payloadUsecount,
                                      NSMutableDictionary *report)
{
    extern uint64_t kread64(uint64_t);
    extern uint32_t kread32(uint64_t);
    extern void kwrite64(uint64_t, uint64_t);
    extern void kwrite32(uint64_t, uint32_t);
    extern uint32_t off_vnode_v_usecount;
    extern uint32_t off_namecache_nc_vp;

    if (targetUsecount == UINT32_MAX || payloadUsecount == UINT32_MAX) {
        return NO;
    }
    kwrite32(targetVnode + off_vnode_v_usecount, targetUsecount + 1);
    uint32_t pinnedTargetUsecount = kread32(
        targetVnode + off_vnode_v_usecount);
    report[@"redirectTargetUsecountPinned"] = @(pinnedTargetUsecount);
    if (pinnedTargetUsecount != targetUsecount + 1) return NO;

    kwrite32(payloadVnode + off_vnode_v_usecount, payloadUsecount + 1);
    uint32_t pinnedPayloadUsecount = kread32(
        payloadVnode + off_vnode_v_usecount);
    report[@"redirectPayloadUsecountPinned"] = @(pinnedPayloadUsecount);
    if (pinnedPayloadUsecount != payloadUsecount + 1) {
        kwrite32(targetVnode + off_vnode_v_usecount, targetUsecount);
        return NO;
    }

    kwrite64(targetNamecache + off_namecache_nc_vp, payloadVnode);
    kwrite32(targetNamecache + CNDNamecacheNCVIDOffset23A341, payloadVID);
    uint64_t observedNCVnode = kread64(
        targetNamecache + off_namecache_nc_vp);
    uint32_t observedNCVID = kread32(
        targetNamecache + CNDNamecacheNCVIDOffset23A341);
    report[@"redirectObservedNCVnode"] = @(observedNCVnode);
    report[@"redirectObservedNCVID"] = @(observedNCVID);
    report[@"targetRedirects"] = @([report[@"targetRedirects"] unsignedIntegerValue] + 1);
    if (observedNCVnode == payloadVnode && observedNCVID == payloadVID) {
        return YES;
    }

    kwrite64(targetNamecache + off_namecache_nc_vp, targetVnode);
    kwrite32(targetNamecache + CNDNamecacheNCVIDOffset23A341,
             originalNCVID);
    kwrite32(payloadVnode + off_vnode_v_usecount, payloadUsecount);
    kwrite32(targetVnode + off_vnode_v_usecount, targetUsecount);
    return NO;
}

static BOOL CNDRestoreNamecacheRedirect(uint64_t targetNamecache,
                                        uint64_t targetVnode,
                                        uint32_t originalNCVID,
                                        NSMutableDictionary *report,
                                        NSString *phase)
{
    extern uint64_t kread64(uint64_t);
    extern uint32_t kread32(uint64_t);
    extern void kwrite64(uint64_t, uint64_t);
    extern void kwrite32(uint64_t, uint32_t);
    extern bool is_kaddr_valid(uint64_t);
    extern uint32_t off_namecache_nc_vp;

    if (!is_kaddr_valid(targetNamecache) || !is_kaddr_valid(targetVnode)) {
        return NO;
    }
    kwrite64(targetNamecache + off_namecache_nc_vp, targetVnode);
    kwrite32(targetNamecache + CNDNamecacheNCVIDOffset23A341,
             originalNCVID);
    uint64_t observedVnode = kread64(targetNamecache + off_namecache_nc_vp);
    uint32_t observedVID = kread32(
        targetNamecache + CNDNamecacheNCVIDOffset23A341);
    report[[phase stringByAppendingString:@"NCVnode"]] = @(observedVnode);
    report[[phase stringByAppendingString:@"NCVID"]] = @(observedVID);
    return observedVnode == targetVnode && observedVID == originalNCVID;
}

static BOOL CNDReleaseVnodePin(uint64_t vnode, uint32_t expectedVID,
                               NSMutableDictionary *report,
                               NSString *label)
{
    extern uint32_t kread32(uint64_t);
    extern void kwrite32(uint64_t, uint32_t);
    extern bool is_kaddr_valid(uint64_t);
    extern uint32_t off_vnode_v_usecount;

    if (!is_kaddr_valid(vnode) ||
        kread32(vnode + CNDVnodeVIDOffset23A341) != expectedVID) return NO;
    uint32_t current = kread32(vnode + off_vnode_v_usecount);
    if (current == 0) return NO;
    kwrite32(vnode + off_vnode_v_usecount, current - 1);
    uint32_t restored = kread32(vnode + off_vnode_v_usecount);
    report[[label stringByAppendingString:@"UsecountBeforeRelease"]] =
        @(current);
    report[[label stringByAppendingString:@"UsecountAfterRelease"]] =
        @(restored);
    return restored == current - 1;
}
#endif

static void CNDApply(NSMutableDictionary *report)
{
    NSData *stock = [NSData dataWithContentsOfFile:CNDTarget
        options:NSDataReadingMappedIfSafe error:NULL];
    report[@"beforeLength"] = @(stock.length);
    report[@"beforeSHA256"] = CNDSHA256(stock);
    if (stock.length != CNDExpectedRecipeLength) {
        CNDFinish(report, @"refused-stock-size", @"The live recipe did not have the verified 343-byte size.");
        return;
    }
    NSDictionary *parsed = [NSPropertyListSerialization propertyListWithData:stock
        options:NSPropertyListImmutable format:NULL error:NULL];
    NSDictionary *base = [parsed isKindOfClass:NSDictionary.class] ? parsed[@"baseMaterial"] : nil;
    if (![base isKindOfClass:NSDictionary.class] || base[@"tinting"] != nil) {
        CNDFinish(report, @"refused-stock-schema", @"The live recipe was not an untinted stock background recipe.");
        return;
    }
    NSDictionary *existingJournal = CNDReadJSON(CNDPath(CNDJournalName));
    if (existingJournal && ![existingJournal[@"state"] isEqualToString:@"restored"]) {
        CNDFinish(report, @"refused-journal", @"An unrestored material-recipe canary journal already exists.");
        return;
    }

    CNDCCMaterialRecipeParameters parameters = {0.60, 0.05, 1.00, 0.78, 25.0};
    NSError *compileError = nil;
    CNDCCMaterialRecipeCompilation *compiled = CNDCCCompileBackgroundMaterialRecipe(
        stock, parameters, CNDCCMaterialRecipeSizingPolicyAllowCompactBackground, &compileError);
    if (!compiled || compiled.data.length != stock.length) {
        report[@"compilerError"] = compileError.localizedDescription ?: @"unknown";
        CNDFinish(report, @"refused-compile", @"The offline compiler did not produce an exact-size verified recipe.");
        return;
    }
    NSString *originalSHA = CNDSHA256(stock);
    NSString *payloadSHA = CNDSHA256(compiled.data);
    report[@"payloadSHA256"] = payloadSHA;
    report[@"compacted"] = @(compiled.compacted);
    report[@"removedKeyPaths"] = compiled.removedKeyPaths;

    NSError *writeError = nil;
    if (!CNDWriteDurable(stock, CNDPath(CNDBackupName), &writeError) ||
        !CNDWriteDurable(compiled.data, CNDPath(CNDPayloadName), &writeError)) {
        report[@"stagingError"] = writeError.localizedDescription ?: @"unknown";
        CNDFinish(report, @"refused-staging", @"The stock backup or compiled payload could not be staged durably.");
        return;
    }
    NSMutableDictionary *journal = [@{
        @"schemaVersion": @(CND_CC_RECIPE_CANARY_APP_NATIVE ? 3 : 1),
        @"state": @"prepared", @"targetPath": CNDTarget,
        @"length": @(stock.length), @"originalSHA256": originalSHA,
        @"payloadSHA256": payloadSHA, @"backupName": CNDBackupName,
        @"payloadName": CNDPayloadName,
    } mutableCopy];
    if (!CNDWriteJSON(journal, CNDPath(CNDJournalName), &writeError)) {
        report[@"journalError"] = writeError.localizedDescription ?: @"unknown";
        CNDFinish(report, @"refused-journal-write", @"The before-write journal could not be saved.");
        return;
    }

    CNDOverwriteFunction writer = NULL;
    if (!CNDPrepareKernelWriter(report, &writer)) return;
    NSData *unchanged = [NSData dataWithContentsOfFile:CNDTarget];
    if (![CNDSHA256(unchanged) isEqualToString:originalSHA]) {
        CNDFinish(report, @"refused-race", @"The target changed after preflight and before its write.");
        return;
    }
#if CND_CC_RECIPE_CANARY_APP_NATIVE
    (void)writer;
    uint64_t targetVnode = 0;
    uint64_t payloadVnode = 0;
    uint64_t targetNamecache = 0;
    uint32_t originalNCVID = 0;
    uint32_t targetVID = 0;
    uint32_t payloadVID = 0;
    uint32_t targetUsecount = 0;
    uint32_t payloadUsecount = 0;
    if (!CNDResolveRedirectState(CNDPath(CNDPayloadName), report,
            &targetVnode, &payloadVnode, &targetNamecache, &originalNCVID,
            &targetVID, &payloadVID, &targetUsecount, &payloadUsecount)) {
        CNDFinish(report, @"refused-redirect-state",
                  @"The target name-cache entry and payload vnode could not be validated.");
        return;
    }
    journal[@"redirectKind"] = @"namecache-nc-vp";
    journal[@"kernelBase"] = report[@"kernelBase"] ?: @0;
    journal[@"targetVnode"] = @(targetVnode);
    journal[@"payloadVnode"] = @(payloadVnode);
    journal[@"targetNamecache"] = @(targetNamecache);
    journal[@"originalNCVID"] = @(originalNCVID);
    journal[@"targetVID"] = @(targetVID);
    journal[@"payloadVID"] = @(payloadVID);
    journal[@"targetUsecountBefore"] = @(targetUsecount);
    journal[@"payloadUsecountBefore"] = @(payloadUsecount);
    journal[@"targetPinned"] = @NO;
    journal[@"sourcePinned"] = @NO;
    journal[@"state"] = @"redirecting";
    if (!CNDWriteJSON(journal, CNDPath(CNDJournalName), &writeError)) {
        CNDFinish(report, @"refused-journal-write",
                  @"The redirecting state could not be journaled.");
        return;
    }
    if (!CNDApplyNamecacheRedirect(
            targetVnode, payloadVnode, targetNamecache, originalNCVID,
            payloadVID, targetUsecount, payloadUsecount, report)) {
        journal[@"state"] = @"apply-failed";
        (void)CNDWriteJSON(journal, CNDPath(CNDJournalName), NULL);
        CNDFinish(report, @"apply-failed",
                  @"The target name-cache entry did not accept the payload vnode.");
        return;
    }
    journal[@"targetPinned"] = @YES;
    journal[@"sourcePinned"] = @YES;
    extern uint64_t get_vnode_for_path_by_open(const char *);
    uint64_t readbackVnode = get_vnode_for_path_by_open(
        CNDTarget.fileSystemRepresentation);
    report[@"redirectReadbackVnode"] = @(readbackVnode);
    NSData *redirected = [NSData dataWithContentsOfFile:CNDTarget];
    report[@"readbackLength"] = @(redirected.length);
    report[@"readbackSHA256"] = CNDSHA256(redirected);
    if (readbackVnode != payloadVnode ||
        redirected.length != CNDExpectedRecipeLength ||
        ![CNDSHA256(redirected) isEqualToString:payloadSHA]) {
        report[@"readbackBase64"] =
            [redirected base64EncodedStringWithOptions:0] ?: @"";
        BOOL entryRestored = CNDRestoreNamecacheRedirect(
            targetNamecache, targetVnode, originalNCVID, report,
            @"rollback");
        BOOL sourcePinReleased = CNDReleaseVnodePin(
            payloadVnode, payloadVID, report, @"redirectPayload");
        BOOL targetPinReleased = CNDReleaseVnodePin(
            targetVnode, targetVID, report, @"redirectTarget");
        journal[@"sourcePinned"] = @(sourcePinReleased ? NO : YES);
        journal[@"targetPinned"] = @(targetPinReleased ? NO : YES);
        journal[@"state"] = @"apply-failed";
        (void)CNDWriteJSON(journal, CNDPath(CNDJournalName), NULL);
        report[@"rollbackVerified"] = @(
            entryRestored && sourcePinReleased && targetPinReleased);
        CNDFinish(report, @"apply-failed",
                  @"The redirected recipe did not read back exactly; the name-cache rollback was attempted.");
        return;
    }
#else
    journal[@"state"] = @"writing";
    if (!CNDWriteJSON(journal, CNDPath(CNDJournalName), &writeError)) {
        CNDFinish(report, @"refused-journal-write", @"The writing state could not be journaled.");
        return;
    }
    if (!CNDWriteTarget(writer, CNDPath(CNDPayloadName), payloadSHA, report)) {
        NSData *current = [NSData dataWithContentsOfFile:CNDTarget];
        if ([CNDSHA256(current) isEqualToString:payloadSHA] ||
            CNDBytesAreKnownPartialWrite(current, stock, compiled.data)) {
            (void)CNDWriteTarget(writer, CNDPath(CNDBackupName), originalSHA, report);
        }
        journal[@"state"] = @"apply-failed";
        (void)CNDWriteJSON(journal, CNDPath(CNDJournalName), NULL);
        CNDFinish(report, @"apply-failed", @"The exact payload readback failed; stock restoration was attempted.");
        return;
    }
#endif
    journal[@"state"] = @"applied";
    if (!CNDWriteJSON(journal, CNDPath(CNDJournalName), &writeError)) {
#if CND_CC_RECIPE_CANARY_APP_NATIVE
        BOOL entryRestored = CNDRestoreNamecacheRedirect(
            targetNamecache, targetVnode, originalNCVID, report,
            @"journalRollback");
        BOOL sourcePinReleased = CNDReleaseVnodePin(
            payloadVnode, payloadVID, report, @"redirectPayload");
        BOOL targetPinReleased = CNDReleaseVnodePin(
            targetVnode, targetVID, report, @"redirectTarget");
        BOOL restored = entryRestored && sourcePinReleased &&
            targetPinReleased;
#else
        BOOL restored = CNDWriteTarget(writer, CNDPath(CNDBackupName), originalSHA, report);
#endif
        report[@"rollbackVerified"] = @(restored);
        CNDFinish(report, @"apply-journal-failed", @"The payload applied, but its final journal did not; stock restoration was attempted.");
        return;
    }
    report[@"success"] = @YES;
    report[@"requiresSpringBoardRestart"] = @YES;
    CNDFinish(report, @"applied", CND_CC_RECIPE_CANARY_APP_NATIVE
        ? @"The purple background recipe was redirected and read back exactly."
        : @"The purple background recipe was written and read back exactly.");
}

static void CNDRestore(NSMutableDictionary *report)
{
    NSDictionary *journal = CNDReadJSON(CNDPath(CNDJournalName));
    NSData *backup = [NSData dataWithContentsOfFile:CNDPath(CNDBackupName)];
    NSData *payload = [NSData dataWithContentsOfFile:CNDPath(CNDPayloadName)];
    NSString *originalSHA = CNDSHA256(backup);
    NSString *payloadSHA = CNDSHA256(payload);
    BOOL valid = [journal[@"schemaVersion"] integerValue] ==
            (CND_CC_RECIPE_CANARY_APP_NATIVE ? 3 : 1) &&
        [journal[@"targetPath"] isEqualToString:CNDTarget] &&
        [journal[@"length"] unsignedIntegerValue] == CNDExpectedRecipeLength &&
        [journal[@"originalSHA256"] isEqualToString:originalSHA] &&
        [journal[@"payloadSHA256"] isEqualToString:payloadSHA] &&
        backup.length == CNDExpectedRecipeLength && payload.length == CNDExpectedRecipeLength;
#if CND_CC_RECIPE_CANARY_APP_NATIVE
    valid = valid && [journal[@"redirectKind"] isEqualToString:@"namecache-nc-vp"] &&
        [journal[@"kernelBase"] isKindOfClass:NSNumber.class] &&
        [journal[@"targetVnode"] isKindOfClass:NSNumber.class] &&
        [journal[@"payloadVnode"] isKindOfClass:NSNumber.class] &&
        [journal[@"targetNamecache"] isKindOfClass:NSNumber.class] &&
        [journal[@"originalNCVID"] isKindOfClass:NSNumber.class] &&
        [journal[@"targetVID"] isKindOfClass:NSNumber.class] &&
        [journal[@"payloadVID"] isKindOfClass:NSNumber.class];
#endif
    if (!valid) {
        CNDFinish(report, @"refused-restore-journal", @"The exact stock backup and canary journal did not validate.");
        return;
    }
    NSData *current = [NSData dataWithContentsOfFile:CNDTarget];
    NSString *currentSHA = CNDSHA256(current);
    report[@"beforeLength"] = @(current.length);
    report[@"beforeSHA256"] = currentSHA;
    BOOL alreadyStock = [currentSHA isEqualToString:originalSHA];
    BOOL redirectedPayload = [currentSHA isEqualToString:payloadSHA];
    if (!alreadyStock && !redirectedPayload) {
        CNDFinish(report, @"refused-external-change", @"The live recipe matched neither the canary payload nor its stock backup.");
        return;
    }
#if CND_CC_RECIPE_CANARY_APP_NATIVE
    if (alreadyStock && ![journal[@"sourcePinned"] boolValue] &&
        ![journal[@"targetPinned"] boolValue]) {
        NSMutableDictionary *restored = [journal mutableCopy];
        restored[@"state"] = @"restored";
        NSError *journalError = nil;
        if (!CNDWriteJSON(restored, CNDPath(CNDJournalName), &journalError)) {
            report[@"journalError"] = journalError.localizedDescription ?: @"unknown";
            CNDFinish(report, @"restore-journal-failed",
                      @"Stock routing was already active, but the journal update failed.");
            return;
        }
        report[@"success"] = @YES;
        report[@"alreadyRestored"] = @YES;
        CNDFinish(report, @"restored",
                  @"The live recipe was stock and no canary vnode pin remained.");
        return;
    }
    CNDOverwriteFunction unusedWriter = NULL;
    if (!CNDPrepareKernelWriter(report, &unusedWriter)) return;
    (void)unusedWriter;
    extern uint64_t g_kernel_base;
    extern uint64_t get_vnode_for_path_by_open(const char *);
    extern uint64_t kread64(uint64_t);
    extern uint32_t kread32(uint64_t);
    extern bool is_kaddr_valid(uint64_t);
    extern uint32_t off_namecache_nc_vp;

    uint64_t journalKernelBase = [journal[@"kernelBase"] unsignedLongLongValue];
    if (alreadyStock && journalKernelBase != g_kernel_base) {
        NSMutableDictionary *restored = [journal mutableCopy];
        restored[@"state"] = @"restored";
        restored[@"sourcePinned"] = @NO;
        restored[@"targetPinned"] = @NO;
        NSError *journalError = nil;
        if (!CNDWriteJSON(restored, CNDPath(CNDJournalName), &journalError)) {
            report[@"journalError"] = journalError.localizedDescription ?: @"unknown";
            CNDFinish(report, @"restore-journal-failed",
                      @"The reboot cleared the redirect, but the journal update failed.");
            return;
        }
        report[@"success"] = @YES;
        report[@"alreadyRestored"] = @YES;
        report[@"redirectClearedByReboot"] = @YES;
        CNDFinish(report, @"restored",
                  @"The reboot cleared the memory-only name-cache redirect and vnode pins.");
        return;
    }

    uint64_t targetVnode = [journal[@"targetVnode"] unsignedLongLongValue];
    uint64_t payloadVnode = [journal[@"payloadVnode"] unsignedLongLongValue];
    uint64_t targetNamecache = [journal[@"targetNamecache"] unsignedLongLongValue];
    uint32_t originalNCVID = [journal[@"originalNCVID"] unsignedIntValue];
    uint32_t targetVID = [journal[@"targetVID"] unsignedIntValue];
    uint32_t payloadVID = [journal[@"payloadVID"] unsignedIntValue];
    uint64_t livePathVnode = get_vnode_for_path_by_open(
        CNDTarget.fileSystemRepresentation);
    uint64_t observedNCVnode = is_kaddr_valid(targetNamecache)
        ? kread64(targetNamecache + off_namecache_nc_vp) : 0;
    uint32_t observedNCVID = is_kaddr_valid(targetNamecache)
        ? kread32(targetNamecache + CNDNamecacheNCVIDOffset23A341) : 0;
    report[@"restoreLivePathVnode"] = @(livePathVnode);
    report[@"restoreObservedNCVnode"] = @(observedNCVnode);
    report[@"restoreObservedNCVID"] = @(observedNCVID);
    BOOL vnodeIdentityValid = is_kaddr_valid(targetVnode) &&
        is_kaddr_valid(payloadVnode) && is_kaddr_valid(targetNamecache) &&
        kread32(targetVnode + CNDVnodeVIDOffset23A341) == targetVID &&
        kread32(payloadVnode + CNDVnodeVIDOffset23A341) == payloadVID;
    BOOL expectedState = vnodeIdentityValid &&
        ((alreadyStock && livePathVnode == targetVnode &&
          observedNCVnode == targetVnode && observedNCVID == originalNCVID) ||
         (redirectedPayload && livePathVnode == payloadVnode &&
          observedNCVnode == payloadVnode && observedNCVID == payloadVID));
    if (!expectedState) {
        CNDFinish(report, @"refused-redirect-identity",
                  @"The live name-cache entry no longer matched the journaled redirect identity.");
        return;
    }
    if (redirectedPayload) {
        BOOL entryRestored = CNDRestoreNamecacheRedirect(
            targetNamecache, targetVnode, originalNCVID, report,
            @"restoreFinal");
        uint64_t restoredPathVnode = get_vnode_for_path_by_open(
            CNDTarget.fileSystemRepresentation);
        NSData *readback = [NSData dataWithContentsOfFile:CNDTarget];
        report[@"restoreReadbackVnode"] = @(restoredPathVnode);
        report[@"readbackLength"] = @(readback.length);
        report[@"readbackSHA256"] = CNDSHA256(readback);
        if (!entryRestored || restoredPathVnode != targetVnode ||
            ![CNDSHA256(readback) isEqualToString:originalSHA]) {
            CNDFinish(report, @"restore-failed",
                      @"Restoring the stock name-cache vnode did not verify.");
            return;
        }
    }
    NSMutableDictionary *restored = [journal mutableCopy];
    BOOL sourcePinReleased = ![journal[@"sourcePinned"] boolValue] ||
        CNDReleaseVnodePin(payloadVnode, payloadVID, report,
                           @"redirectPayload");
    if (sourcePinReleased) restored[@"sourcePinned"] = @NO;
    BOOL targetPinReleased = ![journal[@"targetPinned"] boolValue] ||
        CNDReleaseVnodePin(targetVnode, targetVID, report,
                           @"redirectTarget");
    if (targetPinReleased) restored[@"targetPinned"] = @NO;
    if (!sourcePinReleased || !targetPinReleased) {
        restored[@"state"] = @"restore-pin-failed";
        (void)CNDWriteJSON(restored, CNDPath(CNDJournalName), NULL);
        CNDFinish(report, @"restore-pin-failed",
                  @"Stock routing was restored, but a canary vnode pin could not be released.");
        return;
    }
    restored[@"state"] = @"restored";
    NSError *journalError = nil;
    if (!CNDWriteJSON(restored, CNDPath(CNDJournalName), &journalError)) {
        report[@"journalError"] = journalError.localizedDescription ?: @"unknown";
        CNDFinish(report, @"restore-journal-failed",
                  @"Stock routing was restored, but the journal update failed.");
        return;
    }
    report[@"success"] = @YES;
    report[@"alreadyRestored"] = @(alreadyStock);
    report[@"requiresSpringBoardRestart"] = @YES;
    CNDFinish(report, @"restored",
              alreadyStock ? @"The live recipe already used its stock name-cache vnode."
                           : @"The exact stock background recipe name-cache vnode was restored.");
#else
    if (alreadyStock) {
        NSMutableDictionary *restored = [journal mutableCopy];
        restored[@"state"] = @"restored";
        (void)CNDWriteJSON(restored, CNDPath(CNDJournalName), NULL);
        report[@"success"] = @YES;
        report[@"alreadyRestored"] = @YES;
        CNDFinish(report, @"restored", @"The live recipe already matched the exact stock backup.");
        return;
    }
    CNDOverwriteFunction writer = NULL;
    if (!CNDPrepareKernelWriter(report, &writer)) return;
    if (!CNDWriteTarget(writer, CNDPath(CNDBackupName), originalSHA, report)) {
        CNDFinish(report, @"restore-failed", @"Restoring the exact stock recipe did not verify.");
        return;
    }
    NSMutableDictionary *restored = [journal mutableCopy];
    restored[@"state"] = @"restored";
    NSError *journalError = nil;
    if (!CNDWriteJSON(restored, CNDPath(CNDJournalName), &journalError)) {
        report[@"journalError"] = journalError.localizedDescription ?: @"unknown";
        CNDFinish(report, @"restore-journal-failed", @"Stock bytes were restored, but the journal update failed.");
        return;
    }
    report[@"success"] = @YES;
    report[@"requiresSpringBoardRestart"] = @YES;
    CNDFinish(report, @"restored", @"The exact stock background recipe was restored and read back.");
#endif
}

#if CND_CC_RECIPE_CANARY_ACTION != 0
__attribute__((constructor))
static void CNDCCMaterialRecipeCanaryStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_CC_RECIPE_CANARY_OUTPUT_TOKEN[0] && consume
            ? consume(CND_CC_RECIPE_CANARY_OUTPUT_TOKEN) : -1;
        (void)token;
        (void)[NSFileManager.defaultManager createDirectoryAtPath:CNDCanaryDirectory()
            withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @0700} error:NULL];

        NSString *action = CND_CC_RECIPE_CANARY_ACTION == 1 ? @"apply" :
            CND_CC_RECIPE_CANARY_ACTION == 2 ? @"restore" : @"invalid";
        NSMutableDictionary *report = CNDBaseReport(action);
        report[@"sandboxTokenConsumed"] = @(token >= 0);
        if (!CNDPreflight(report)) return;
        if (CND_CC_RECIPE_CANARY_ACTION == 1) CNDApply(report);
        else if (CND_CC_RECIPE_CANARY_ACTION == 2) CNDRestore(report);
        else CNDFinish(report, @"refused-action", @"The canary action was invalid.");
    }
}
#endif

#if CND_CC_RECIPE_CANARY_APP_NATIVE
void CNDCCMaterialRecipeVMCanaryProcessPendingRequest(void)
{
    NSString *requestPath = CNDPath(CNDRequestName);
    NSDictionary *request = CNDReadJSON(requestPath);
    NSString *action = [request[@"action"] isKindOfClass:NSString.class]
        ? request[@"action"] : @"";
    NSString *nonce = [request[@"nonce"] isKindOfClass:NSString.class]
        ? request[@"nonce"] : @"";
    NSString *targetToken = [request[@"targetSandboxToken"] isKindOfClass:NSString.class]
        ? request[@"targetSandboxToken"] : @"";
    NSCharacterSet *hex = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
    BOOL validNonce = nonce.length == 32 &&
        [nonce rangeOfCharacterFromSet:hex.invertedSet].location == NSNotFound;
    BOOL validTargetToken = targetToken.length >= 16 && targetToken.length <= 8192 &&
        [targetToken rangeOfCharacterFromSet:NSCharacterSet.newlineCharacterSet].location == NSNotFound;
    if (!request || !validNonce || !validTargetToken ||
        ![@[@"apply", @"restore"] containsObject:action]) return;
    if (![NSFileManager.defaultManager removeItemAtPath:requestPath error:NULL]) return;

    static volatile int running;
    if (!__sync_bool_compare_and_swap(&running, 0, 1)) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            NSMutableDictionary *report = CNDBaseReport(action);
            report[@"requestNonce"] = nonce;
            report[@"appNative"] = @YES;
            typedef int64_t (*ConsumeFunction)(const char *);
            ConsumeFunction consume = (ConsumeFunction)dlsym(
                RTLD_DEFAULT, "sandbox_extension_consume");
            int64_t tokenHandle = consume
                ? consume(targetToken.fileSystemRepresentation) : -1;
            report[@"targetSandboxTokenConsumed"] = @(tokenHandle >= 0);
            if (tokenHandle < 0) {
                CNDFinish(report, @"refused-sandbox-token",
                    @"The exact target sandbox extension could not be consumed.");
            } else if (CNDPreflight(report)) {
                if ([action isEqualToString:@"apply"]) CNDApply(report);
                else CNDRestore(report);
            }
        }
        __sync_lock_release(&running);
    });
}

__attribute__((constructor))
static void CNDCCMaterialRecipeVMCanaryStart(void)
{
    @autoreleasepool {
        CNDCCMaterialRecipeVMCanaryProcessPendingRequest();
    }
}
#endif
