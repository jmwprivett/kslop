#import "CNDHailMaryPatch.h"

#import "CNDHailMaryImpRedirect.h"
#import "CNDHailMaryProbe.h"
#import "TaskRop/RemoteCall.h"
#import "kexploit/kexploit_opa334.h"
#import "kexploit/krw.h"
#import "kexploit/kutils.h"
#import "tweaks/remote_objc.h"

#import <CommonCrypto/CommonDigest.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#define CND_HAIL_MARY_PATCH_BUILD "23A341"
#define CND_HAIL_MARY_PATCH_PRODUCT "iPhone17,2"
#define CND_HAIL_MARY_ORIGINAL_SHA256 "542063d6c8ea82afbe734ace1895ba0f2b7ab15160c6053176604644741f20d5"
#define CND_HAIL_MARY_PATCHED_SHA256 "5d11085e066693f14771fea0c97d55ab593bd6468856bfbed2463224dd01569f"

static const uint64_t kCNDHailMaryPatchPageSize = UINT64_C(0x4000);
static const uint64_t kCNDHailMaryPatchUnslidTargetVirtualAddress =
    UINT64_C(0x1be102ef0);
static const uint64_t kCNDHailMaryPatchGuardOffsetWithinFrame =
    UINT64_C(0x2e5c);
static const uint64_t kCNDHailMaryPatchWordOffsetWithinFrame =
    UINT64_C(0x2ef0);
static const size_t kCNDHailMaryPatchGuardLength = 188;
static const size_t kCNDHailMaryPatchWordOffsetWithinGuard = 148;
static const uint32_t kCNDHailMaryPatchOriginalWord =
    UINT32_C(0x1a9f17f4);
static const uint32_t kCNDHailMaryPatchReplacementWord =
    UINT32_C(0x52800034);

/* The SpringBoard mlock experiment is retained for reference, but the live
 * mutation path deliberately follows the legacy landing sequence that once
 * produced the persistent patch: final guard read, kwrite32, no readback. */
static const BOOL kCNDHailMaryPatchAttemptSpringBoardMlock = NO;

static volatile int gCNDHailMaryPatchRunning;

static NSString *CNDHailMaryPatchHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx",
        (unsigned long long)value];
}

static BOOL CNDHailMaryPatchParseHex(NSString *text, uint64_t *valueOut)
{
    if (![text isKindOfClass:NSString.class] ||
        ![text hasPrefix:@"0x"] || text.length <= 2) {
        return NO;
    }
    NSScanner *scanner = [NSScanner scannerWithString:
        [text substringFromIndex:2]];
    unsigned long long value = 0;
    if (![scanner scanHexLongLong:&value] || !scanner.isAtEnd) return NO;
    if (valueOut) *valueOut = (uint64_t)value;
    return YES;
}

static NSData *CNDHailMaryPatchDataFromHex(NSString *text)
{
    if (![text isKindOfClass:NSString.class] || text.length % 2 != 0) {
        return nil;
    }
    NSMutableData *data = [NSMutableData dataWithLength:text.length / 2];
    uint8_t *bytes = data.mutableBytes;
    for (NSUInteger index = 0; index < text.length; index += 2) {
        NSString *pair = [text substringWithRange:NSMakeRange(index, 2)];
        NSScanner *scanner = [NSScanner scannerWithString:pair];
        unsigned int value = 0;
        if (![scanner scanHexInt:&value] || !scanner.isAtEnd) return nil;
        bytes[index / 2] = (uint8_t)value;
    }
    return data;
}

static NSString *CNDHailMaryPatchSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class] || data.length > UINT32_MAX) {
        return @"";
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString
        stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger index = 0; index < sizeof(digest); index++) {
        [hex appendFormat:@"%02x", digest[index]];
    }
    return hex;
}

static uint32_t CNDHailMaryPatchWord(NSData *data)
{
    if (data.length < kCNDHailMaryPatchWordOffsetWithinGuard +
            sizeof(uint32_t)) {
        return 0;
    }
    uint32_t word = 0;
    [data getBytes:&word
             range:NSMakeRange(kCNDHailMaryPatchWordOffsetWithinGuard,
                               sizeof(word))];
    return word;
}

static NSString *CNDHailMaryPatchReportPath(void)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    return [directory stringByAppendingPathComponent:
        @"CNDHailMaryPatch.json"];
}

static void CNDHailMaryPatchSave(
    NSDictionary<NSString *, id> *report, NSString *path)
{
    if (!report || path.length == 0) return;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
                                                   options:NSJSONWritingPrettyPrinted |
                                                           NSJSONWritingSortedKeys
                                                     error:nil];
    if (data) {
        (void)[data writeToFile:path options:NSDataWritingAtomic error:nil];
    }
}

static BOOL CNDHailMaryPatchSyncFileDescriptor(int descriptor)
{
    if (descriptor < 0) return NO;
#ifdef F_FULLFSYNC
    if (fcntl(descriptor, F_FULLFSYNC) == 0) return YES;
#endif
    return fsync(descriptor) == 0;
}

static BOOL CNDHailMaryPatchSaveDurably(
    NSDictionary<NSString *, id> *report,
    NSString *path,
    NSString **errorOut)
{
    if (!report || path.length == 0) {
        if (errorOut) *errorOut = @"invalid-journal-path";
        return NO;
    }
    NSError *serializationError = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report
                                                   options:NSJSONWritingPrettyPrinted |
                                                           NSJSONWritingSortedKeys
                                                     error:&serializationError];
    if (!data) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-serialization-failed:%@",
            serializationError.localizedDescription ?: @"unknown"];
        return NO;
    }
    NSError *writeError = nil;
    if (![data writeToFile:path
                   options:NSDataWritingAtomic
                     error:&writeError]) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-atomic-write-failed:%@",
            writeError.localizedDescription ?: @"unknown"];
        return NO;
    }

    int fileDescriptor = open(path.fileSystemRepresentation,
                              O_RDONLY | O_CLOEXEC);
    if (fileDescriptor < 0) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-open-failed:%d", errno];
        return NO;
    }
    BOOL fileSynced = CNDHailMaryPatchSyncFileDescriptor(fileDescriptor);
    int fileSyncError = fileSynced ? 0 : errno;
    close(fileDescriptor);
    if (!fileSynced) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-file-sync-failed:%d", fileSyncError];
        return NO;
    }

    NSString *directory = path.stringByDeletingLastPathComponent;
    int directoryDescriptor = open(directory.fileSystemRepresentation,
                                   O_RDONLY | O_CLOEXEC);
    if (directoryDescriptor < 0) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-directory-open-failed:%d", errno];
        return NO;
    }
    BOOL directorySynced = fsync(directoryDescriptor) == 0;
    int directorySyncError = directorySynced ? 0 : errno;
    close(directoryDescriptor);
    if (!directorySynced) {
        if (errorOut) *errorOut = [NSString stringWithFormat:
            @"journal-directory-sync-failed:%d", directorySyncError];
        return NO;
    }
    return YES;
}

static NSString *CNDHailMaryPatchOperationName(
    CNDHailMaryPatchOperation operation)
{
    switch (operation) {
        case CNDHailMaryPatchOperationApply: return @"apply";
        case CNDHailMaryPatchOperationRestore: return @"restore";
        case CNDHailMaryPatchOperationVerifyPatched:
            return @"verify-patched";
        case CNDHailMaryPatchOperationVerifyOriginal:
            return @"verify-original";
    }
    return @"unknown";
}

static BOOL CNDHailMaryPatchExpectedPatched(
    CNDHailMaryPatchOperation operation)
{
    return operation == CNDHailMaryPatchOperationRestore ||
        operation == CNDHailMaryPatchOperationVerifyPatched;
}

static BOOL CNDHailMaryPatchIsMutation(
    CNDHailMaryPatchOperation operation)
{
    return operation == CNDHailMaryPatchOperationApply ||
        operation == CNDHailMaryPatchOperationRestore;
}

static BOOL CNDHailMaryPatchTranslationPathMatches(
    id candidate,
    uint64_t *terminalAddressOut,
    uint64_t *expectedTerminalValueOut,
    uint64_t *observedTerminalValueOut)
{
    if (![candidate isKindOfClass:NSArray.class]) return NO;
    NSArray *path = candidate;
    if (path.count != 3) return NO;

    BOOL matches = YES;
    uint64_t terminalAddress = 0;
    uint64_t expectedTerminalValue = 0;
    uint64_t observedTerminalValue = 0;
    for (NSUInteger index = 0; index < path.count; index++) {
        NSDictionary<NSString *, id> *node = path[index];
        BOOL terminal = index == path.count - 1;
        uint64_t entryAddress = 0;
        uint64_t entryValue = 0;
        if (![node isKindOfClass:NSDictionary.class] ||
            [node[@"level"] unsignedIntegerValue] != index + 1 ||
            [node[@"terminal"] boolValue] != terminal ||
            !CNDHailMaryPatchParseHex(node[@"entryAddress"],
                                      &entryAddress) ||
            !CNDHailMaryPatchParseHex(node[@"entryValue"],
                                      &entryValue) ||
            !is_kaddr_valid(entryAddress) || (entryAddress & 7U) != 0 ||
            entryValue == 0) {
            return NO;
        }
        uint64_t observedValue = kread64(entryAddress);
        if (observedValue != entryValue) matches = NO;
        if (terminal) {
            terminalAddress = entryAddress;
            expectedTerminalValue = entryValue;
            observedTerminalValue = observedValue;
        }
    }

    if (terminalAddressOut) *terminalAddressOut = terminalAddress;
    if (expectedTerminalValueOut) {
        *expectedTerminalValueOut = expectedTerminalValue;
    }
    if (observedTerminalValueOut) {
        *observedTerminalValueOut = observedTerminalValue;
    }
    return matches && terminalAddress != 0 && expectedTerminalValue != 0;
}

static NSDictionary<NSString *, id> *CNDHailMaryPatchValidateProof(
    NSDictionary<NSString *, id> *report,
    BOOL expectPatched,
    NSData **guardDataOut,
    NSString **errorOut)
{
    if (![report isKindOfClass:NSDictionary.class] ||
        [report[@"schemaVersion"] unsignedIntegerValue] != 2 ||
        ![report[@"probe"] isEqual:@"hail-mary-physical-page-proof"] ||
        ![report[@"productType"] isEqual:@CND_HAIL_MARY_PATCH_PRODUCT] ||
        ![report[@"productBuildVersion"]
            isEqual:@CND_HAIL_MARY_PATCH_BUILD]) {
        if (errorOut) *errorOut = @"probe-identity-mismatch";
        return nil;
    }

    NSDictionary<NSString *, id> *objectProof =
        report[@"objectBackingComparison"];
    NSDictionary<NSString *, id> *springObject =
        objectProof[@"springBoard"];
    NSDictionary<NSString *, id> *spotlightObject =
        objectProof[@"spotlight"];
    NSDictionary<NSString *, id> *physicalProof =
        report[@"physicalPageProof"];
    NSDictionary<NSString *, id> *guard = physicalProof[@"guard"];
    NSDictionary<NSString *, id> *springBoard = physicalProof[@"springBoard"];
    NSDictionary<NSString *, id> *spotlight = physicalProof[@"spotlight"];
    NSDictionary<NSString *, id> *springBoardProcess = report[@"springBoard"];
    NSDictionary<NSString *, id> *spotlightProcess = report[@"spotlight"];
    if (![objectProof[@"confirmed"] boolValue] ||
        ![objectProof[@"sameBackingObject"] boolValue] ||
        ![objectProof[@"sameObjectOffset"] boolValue] ||
        ![objectProof[@"sameBackingObjectPageSlot"] boolValue] ||
        ![physicalProof[@"confirmed"] boolValue] ||
        ![physicalProof[@"physicalFrameResolved"] boolValue] ||
        ![physicalProof[@"samePhysicalFrame"] boolValue] ||
        ![physicalProof[@"samePhysicalAddress"] boolValue] ||
        ![physicalProof[@"postReadTranslationStable"] boolValue] ||
        ![physicalProof[@"runtimeInstructionBytesVerified"] boolValue] ||
        ![springBoard[@"translationStable"] boolValue] ||
        ![spotlight[@"translationStable"] boolValue] ||
        [springBoard[@"pid"] intValue] <= 1 ||
        [spotlight[@"pid"] intValue] <= 1 ||
        [springBoardProcess[@"pid"] intValue] !=
            [springBoard[@"pid"] intValue] ||
        [spotlightProcess[@"pid"] intValue] !=
            [spotlight[@"pid"] intValue] ||
        ![springBoard[@"process"] isEqual:@"SpringBoard"] ||
        ![spotlight[@"process"] isEqual:@"Spotlight"] ||
        [springBoard[@"terminalLevel"] unsignedIntegerValue] != 3 ||
        [spotlight[@"terminalLevel"] unsignedIntegerValue] != 3) {
        if (errorOut) *errorOut = @"shared-physical-proof-incomplete";
        return nil;
    }

    uint64_t springEntryAddress = 0;
    uint64_t spotlightEntryAddress = 0;
    uint64_t springEntryValue = 0;
    uint64_t spotlightEntryValue = 0;
    uint64_t springObservedEntryValue = 0;
    uint64_t spotlightObservedEntryValue = 0;
    BOOL springPathMatches = CNDHailMaryPatchTranslationPathMatches(
        springBoard[@"path"], &springEntryAddress, &springEntryValue,
        &springObservedEntryValue);
    BOOL spotlightPathMatches = CNDHailMaryPatchTranslationPathMatches(
        spotlight[@"path"], &spotlightEntryAddress, &spotlightEntryValue,
        &spotlightObservedEntryValue);
    if (!springPathMatches || !spotlightPathMatches) {
        if (errorOut) *errorOut = @"leaf-translation-path-changed";
        return nil;
    }
    if (springEntryValue != spotlightEntryValue ||
        springObservedEntryValue != spotlightObservedEntryValue) {
        if (errorOut) *errorOut = @"leaf-translation-value-mismatch";
        return nil;
    }

    uint64_t physicalFrame = 0;
    uint64_t physicalAddress = 0;
    uint64_t frameKVA = 0;
    uint64_t springPhysical = 0;
    uint64_t spotlightPhysical = 0;
    uint64_t springVirtual = 0;
    uint64_t spotlightVirtual = 0;
    uint64_t springObjectRuntime = 0;
    uint64_t spotlightObjectRuntime = 0;
    uint64_t springSlide = 0;
    uint64_t spotlightSlide = 0;
    uint64_t springProc = 0;
    uint64_t springTask = 0;
    uint64_t spotlightProc = 0;
    uint64_t spotlightTask = 0;
    if (!CNDHailMaryPatchParseHex(physicalProof[@"physicalFrame"],
                                  &physicalFrame) ||
        !CNDHailMaryPatchParseHex(physicalProof[@"physicalAddress"],
                                  &physicalAddress) ||
        !CNDHailMaryPatchParseHex(
            physicalProof[@"frameKernelVirtualAddress"], &frameKVA) ||
        !CNDHailMaryPatchParseHex(springBoard[@"physicalAddress"],
                                  &springPhysical) ||
        !CNDHailMaryPatchParseHex(spotlight[@"physicalAddress"],
                                  &spotlightPhysical) ||
        !CNDHailMaryPatchParseHex(springBoard[@"virtualAddress"],
                                  &springVirtual) ||
        !CNDHailMaryPatchParseHex(spotlight[@"virtualAddress"],
                                  &spotlightVirtual) ||
        !CNDHailMaryPatchParseHex(springObject[@"runtimeAddress"],
                                  &springObjectRuntime) ||
        !CNDHailMaryPatchParseHex(spotlightObject[@"runtimeAddress"],
                                  &spotlightObjectRuntime) ||
        !CNDHailMaryPatchParseHex(springObject[@"slide"],
                                  &springSlide) ||
        !CNDHailMaryPatchParseHex(spotlightObject[@"slide"],
                                  &spotlightSlide) ||
        !CNDHailMaryPatchParseHex(springBoardProcess[@"proc"],
                                  &springProc) ||
        !CNDHailMaryPatchParseHex(springBoardProcess[@"task"],
                                  &springTask) ||
        !CNDHailMaryPatchParseHex(spotlightProcess[@"proc"],
                                  &spotlightProc) ||
        !CNDHailMaryPatchParseHex(spotlightProcess[@"task"],
                                  &spotlightTask) ||
        !is_kaddr_valid(springProc) || !is_kaddr_valid(springTask) ||
        !is_kaddr_valid(spotlightProc) || !is_kaddr_valid(spotlightTask) ||
        physicalFrame == 0 ||
        physicalAddress < physicalFrame ||
        (physicalFrame & (kCNDHailMaryPatchPageSize - 1)) != 0 ||
        (frameKVA & (kCNDHailMaryPatchPageSize - 1)) != 0 ||
        !is_kaddr_valid(frameKVA) ||
        physicalAddress - physicalFrame !=
            kCNDHailMaryPatchWordOffsetWithinFrame ||
        springPhysical != physicalAddress ||
        spotlightPhysical != physicalAddress ||
        springVirtual != spotlightVirtual ||
        springVirtual != springObjectRuntime ||
        spotlightVirtual != spotlightObjectRuntime ||
        springSlide != spotlightSlide ||
        springVirtual < springSlide ||
        springVirtual - springSlide !=
            kCNDHailMaryPatchUnslidTargetVirtualAddress) {
        if (errorOut) *errorOut = @"physical-target-identity-mismatch";
        return nil;
    }

    NSString *bytesHex = guard[@"bytesHex"];
    NSData *guardData = CNDHailMaryPatchDataFromHex(bytesHex);
    NSString *expectedSHA = expectPatched
        ? @CND_HAIL_MARY_PATCHED_SHA256
        : @CND_HAIL_MARY_ORIGINAL_SHA256;
    uint32_t expectedWord = expectPatched
        ? kCNDHailMaryPatchReplacementWord
        : kCNDHailMaryPatchOriginalWord;
    if (guardData.length != kCNDHailMaryPatchGuardLength ||
        [guard[@"byteLength"] unsignedIntegerValue] !=
            kCNDHailMaryPatchGuardLength ||
        [guard[@"offsetWithinFrame"] unsignedLongLongValue] !=
            kCNDHailMaryPatchGuardOffsetWithinFrame ||
        ![[CNDHailMaryPatchSHA256(guardData) lowercaseString]
            isEqual:expectedSHA] ||
        ![[guard[@"sha256"] lowercaseString] isEqual:expectedSHA] ||
        CNDHailMaryPatchWord(guardData) != expectedWord) {
        if (errorOut) *errorOut = expectPatched
            ? @"patched-byte-guard-mismatch"
            : @"original-byte-guard-mismatch";
        return nil;
    }

    if (frameKVA > UINT64_MAX - kCNDHailMaryPatchWordOffsetWithinFrame ||
        frameKVA > UINT64_MAX - kCNDHailMaryPatchGuardOffsetWithinFrame) {
        if (errorOut) *errorOut = @"kernel-virtual-target-overflow";
        return nil;
    }
    uint64_t targetKVA = frameKVA +
        kCNDHailMaryPatchWordOffsetWithinFrame;
    uint64_t guardKVA = frameKVA +
        kCNDHailMaryPatchGuardOffsetWithinFrame;
    if (!is_kaddr_valid(targetKVA) || !is_kaddr_valid(guardKVA) ||
        (targetKVA & 3U) != 0) {
        if (errorOut) *errorOut = @"invalid-kernel-virtual-write-target";
        return nil;
    }

    if (guardDataOut) *guardDataOut = guardData;
    return @{
        @"physicalFrame": CNDHailMaryPatchHex(physicalFrame),
        @"physicalAddress": CNDHailMaryPatchHex(physicalAddress),
        @"frameKernelVirtualAddress": CNDHailMaryPatchHex(frameKVA),
        @"guardKernelVirtualAddress": CNDHailMaryPatchHex(guardKVA),
        @"targetKernelVirtualAddress": CNDHailMaryPatchHex(targetKVA),
        @"targetVirtualAddress": CNDHailMaryPatchHex(springVirtual),
        @"unslidTargetVirtualAddress": CNDHailMaryPatchHex(
            kCNDHailMaryPatchUnslidTargetVirtualAddress),
        @"sharedCacheSlide": CNDHailMaryPatchHex(springSlide),
        @"springBoardPID": springBoard[@"pid"],
        @"spotlightPID": spotlight[@"pid"],
        @"springBoardProc": CNDHailMaryPatchHex(springProc),
        @"springBoardTask": CNDHailMaryPatchHex(springTask),
        @"spotlightProc": CNDHailMaryPatchHex(spotlightProc),
        @"spotlightTask": CNDHailMaryPatchHex(spotlightTask),
        @"springBoardPmap": springBoard[@"pmap"],
        @"spotlightPmap": spotlight[@"pmap"],
        @"leafEntryAddressesShared": @(
            springEntryAddress == spotlightEntryAddress),
        @"springBoardLeafEntryAddress": CNDHailMaryPatchHex(
            springEntryAddress),
        @"spotlightLeafEntryAddress": CNDHailMaryPatchHex(
            spotlightEntryAddress),
        @"provenLeafEntryValue": CNDHailMaryPatchHex(springEntryValue),
        @"springBoardTranslationPath": springBoard[@"path"],
        @"spotlightTranslationPath": spotlight[@"path"],
        @"guardSHA256": expectedSHA,
        @"instructionWord": CNDHailMaryPatchHex(expectedWord),
    };
}

static NSDictionary<NSString *, id> *
CNDHailMaryPatchWireSpringBoardPage(
    NSDictionary<NSString *, id> *context)
{
    uint64_t targetVirtualAddress = 0;
    uint64_t expectedProc = 0;
    uint64_t expectedTask = 0;
    uint64_t springBoardLeafEntryAddress = 0;
    uint64_t provenLeafEntryValue = 0;
    NSArray *springBoardTranslationPath =
        [context[@"springBoardTranslationPath"] isKindOfClass:NSArray.class]
            ? context[@"springBoardTranslationPath"] : nil;
    pid_t expectedPID = (pid_t)[context[@"springBoardPID"] intValue];
    BOOL parsed = expectedPID > 1 &&
        CNDHailMaryPatchParseHex(context[@"targetVirtualAddress"],
                                 &targetVirtualAddress) &&
        CNDHailMaryPatchParseHex(context[@"springBoardProc"],
                                 &expectedProc) &&
        CNDHailMaryPatchParseHex(context[@"springBoardTask"],
                                 &expectedTask) &&
        CNDHailMaryPatchParseHex(context[@"springBoardLeafEntryAddress"],
                                 &springBoardLeafEntryAddress) &&
        CNDHailMaryPatchParseHex(context[@"provenLeafEntryValue"],
                                 &provenLeafEntryValue) &&
        is_kaddr_valid(expectedProc) && is_kaddr_valid(expectedTask) &&
        is_kaddr_valid(springBoardLeafEntryAddress) &&
        springBoardTranslationPath.count == 3;
    uint64_t pageBase = targetVirtualAddress &
        ~(kCNDHailMaryPatchPageSize - 1);
    if (!parsed || pageBase == 0 ||
        targetVirtualAddress - pageBase >= kCNDHailMaryPatchPageSize) {
        return @{
            @"ok": @NO,
            @"stage": @"wire-input-validation",
            @"message": @"The proven SpringBoard page identity could not be parsed for mlock.",
        };
    }

    uint64_t initialProc = proc_find(expectedPID);
    uint64_t initialTask = is_kaddr_valid(initialProc)
        ? proc_task(initialProc) : 0;
    BOOL initialIdentity = initialProc == expectedProc &&
        initialTask == expectedTask &&
        strcmp(proc_get_p_name(initialProc) ?: "", "SpringBoard") == 0;
    if (!initialIdentity) {
        return @{
            @"ok": @NO,
            @"stage": @"wire-process-identity",
            @"message": @"SpringBoard changed after the physical-page proof and before mlock.",
            @"expectedPID": @(expectedPID),
            @"pageBase": CNDHailMaryPatchHex(pageBase),
        };
    }

    uint64_t initialPathTerminalAddress = 0;
    uint64_t initialPathExpectedValue = 0;
    uint64_t initialPathObservedValue = 0;
    BOOL initialPathStable = CNDHailMaryPatchTranslationPathMatches(
        springBoardTranslationPath, &initialPathTerminalAddress,
        &initialPathExpectedValue, &initialPathObservedValue) &&
        initialPathTerminalAddress == springBoardLeafEntryAddress &&
        initialPathExpectedValue == provenLeafEntryValue &&
        initialPathObservedValue == provenLeafEntryValue;
    if (!initialPathStable) {
        return @{
            @"ok": @NO,
            @"stage": @"wire-translation-path-changed",
            @"message": @"SpringBoard's proven translation path changed before mlock.",
            @"expectedPID": @(expectedPID),
            @"pageBase": CNDHailMaryPatchHex(pageBase),
            @"springBoardLeafEntryAddress": CNDHailMaryPatchHex(
                springBoardLeafEntryAddress),
            @"expectedLeafEntryValue": CNDHailMaryPatchHex(
                provenLeafEntryValue),
            @"observedLeafEntryValue": CNDHailMaryPatchHex(
                initialPathObservedValue),
        };
    }

    g_RC_targetProcOverride = expectedProc;
    RemoteCallSession *session = [[RemoteCallSession alloc]
        initWithProcess:@"SpringBoard"
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    g_RC_targetProcOverride = 0;
    if (!session) {
        return @{
            @"ok": @NO,
            @"stage": @"wire-remote-session",
            @"message": @"SpringBoard RemoteCall could not be opened for mlock.",
            @"expectedPID": @(expectedPID),
            @"pageBase": CNDHailMaryPatchHex(pageBase),
        };
    }

    BOOL identityBound = session.pid == expectedPID &&
        session.taskAddr == expectedTask;
    __block uint64_t mlockResult = UINT64_MAX;
    __block BOOL mlockErrnoAddressResolved = NO;
    __block BOOL mlockErrnoCaptured = NO;
    __block int mlockErrno = 0;
    __block BOOL remoteOK = NO;
    NSString *exceptionText = nil;
    if (identityBound) {
        @try {
            remote_call_with_session(session, ^{
                /* Resolve this synthetic pthread's TLS errno slot before
                 * mlock.  On failure, read the slot immediately: making a
                 * second target-side call first could overwrite the value we
                 * are trying to diagnose. */
                uint64_t remoteErrnoAddress = r_dlsym_call(
                    R_TIMEOUT, "__error", 0, 0, 0, 0, 0, 0, 0, 0);
                mlockErrnoAddressResolved =
                    remote_call_current_success() &&
                    remoteErrnoAddress != 0;
                mlockResult = r_dlsym_call(
                    R_TIMEOUT, "mlock", pageBase,
                    kCNDHailMaryPatchPageSize, 0, 0, 0, 0, 0, 0);
                BOOL mlockCallHealthy = remote_call_current_success();
                if (mlockCallHealthy && mlockResult == UINT64_MAX &&
                    mlockErrnoAddressResolved) {
                    int value = 0;
                    mlockErrnoCaptured = remote_read(
                        remoteErrnoAddress, &value, sizeof(value));
                    if (mlockErrnoCaptured) mlockErrno = value;
                }
                remoteOK = mlockCallHealthy;
            });
        } @catch (NSException *exception) {
            exceptionText = [NSString stringWithFormat:@"%@:%@",
                exception.name ?: @"exception",
                exception.reason ?: @"unknown"];
            remoteOK = NO;
        }
    }

    if ([session hasLocalState] && ![session hasInFlightSyntheticCall]) {
        (void)[session destroyRemoteCall];
    }
    BOOL teardownDeferred = NO;
    if ([session hasInFlightSyntheticCall]) {
        teardownDeferred =
            [session deferTeardownForInFlightSyntheticCall];
    }
    BOOL closed = ![session hasLocalState];

    uint64_t finalProc = proc_find(expectedPID);
    uint64_t finalTask = is_kaddr_valid(finalProc) ? proc_task(finalProc) : 0;
    BOOL finalIdentity = finalProc == expectedProc &&
        finalTask == expectedTask &&
        strcmp(proc_get_p_name(finalProc) ?: "", "SpringBoard") == 0;
    uint64_t finalPathTerminalAddress = 0;
    uint64_t finalPathExpectedValue = 0;
    uint64_t finalLeafEntryValue = 0;
    BOOL translationPathStable = finalIdentity &&
        CNDHailMaryPatchTranslationPathMatches(
            springBoardTranslationPath, &finalPathTerminalAddress,
            &finalPathExpectedValue, &finalLeafEntryValue) &&
        finalPathTerminalAddress == springBoardLeafEntryAddress &&
        finalPathExpectedValue == provenLeafEntryValue;
    BOOL leafStable = translationPathStable &&
        finalLeafEntryValue == provenLeafEntryValue;
    BOOL ok = identityBound && remoteOK && mlockResult == 0 && closed &&
        !teardownDeferred && finalIdentity && leafStable;
    NSString *mlockErrnoDescription = mlockErrnoCaptured
        ? ([NSString stringWithUTF8String:strerror(mlockErrno)] ?:
            @"unknown")
        : @"unavailable";

    NSMutableDictionary<NSString *, id> *report = [@{
        @"ok": @(ok),
        @"attempted": @YES,
        @"wired": @(ok),
        @"stage": ok ? @"springboard-page-wired" : @"springboard-page-wire-failed",
        @"message": ok
            ? @"SpringBoard mlock wired the exact proven 16 KiB shared-cache page and its mapping identity remained stable."
            : @"SpringBoard did not retain one clean, identity-stable mlock of the proven shared-cache page.",
        @"expectedPID": @(expectedPID),
        @"sessionPID": @(session.pid),
        @"pageBase": CNDHailMaryPatchHex(pageBase),
        @"byteLength": @(kCNDHailMaryPatchPageSize),
        @"mlockReturn": CNDHailMaryPatchHex(mlockResult),
        @"mlockErrnoAddressResolved": @(mlockErrnoAddressResolved),
        @"mlockErrnoCaptured": @(mlockErrnoCaptured),
        @"mlockErrno": @(mlockErrno),
        @"mlockErrnoDescription": mlockErrnoDescription,
        @"identityBound": @(identityBound),
        @"remoteCallHealthy": @(remoteOK),
        @"sessionClosed": @(closed),
        @"teardownDeferred": @(teardownDeferred),
        @"finalIdentityStable": @(finalIdentity),
        @"translationPathStable": @(translationPathStable),
        @"leafEntryStable": @(leafStable),
        @"leafEntryAddressesSharedBeforeMlock":
            context[@"leafEntryAddressesShared"] ?: @NO,
        @"springBoardLeafEntryAddress": CNDHailMaryPatchHex(
            springBoardLeafEntryAddress),
        @"spotlightLeafEntryAddress":
            context[@"spotlightLeafEntryAddress"] ?: @"",
        @"expectedLeafEntryValue": CNDHailMaryPatchHex(
            provenLeafEntryValue),
        @"finalLeafEntryValue": CNDHailMaryPatchHex(finalLeafEntryValue),
    } mutableCopy];
    if (exceptionText) report[@"exception"] = exceptionText;
    return report;
}

static NSData *CNDHailMaryPatchReadGuard(
    NSDictionary<NSString *, id> *context)
{
    uint64_t guardKVA = 0;
    if (!CNDHailMaryPatchParseHex(context[@"guardKernelVirtualAddress"],
                                  &guardKVA) ||
        !is_kaddr_valid(guardKVA) ||
        guardKVA > UINT64_MAX - kCNDHailMaryPatchGuardLength) {
        return nil;
    }

    NSMutableData *guard = [NSMutableData
        dataWithLength:kCNDHailMaryPatchGuardLength];
    kreadbuf(guardKVA, guard.mutableBytes, guard.length);
    return guard;
}

static BOOL CNDHailMaryPatchWriteWordLegacyLanding(
    NSDictionary<NSString *, id> *context,
    NSData *expectedBefore,
    uint32_t desiredWord,
    BOOL *writeInvokedOut,
    NSString **errorOut)
{
    if (writeInvokedOut) *writeInvokedOut = NO;
    uint64_t targetKVA = 0;
    if (!CNDHailMaryPatchParseHex(context[@"targetKernelVirtualAddress"],
                                  &targetKVA) ||
        !is_kaddr_valid(targetKVA) || (targetKVA & 3U) != 0 ||
        expectedBefore.length != kCNDHailMaryPatchGuardLength ||
        kCNDHailMaryPatchWordOffsetWithinGuard + EARLY_KRW_LENGTH >
            expectedBefore.length) {
        if (errorOut) *errorOut = @"write-target-revalidation-failed";
        return NO;
    }

    /* Reproduce the successful legacy conditioning exactly. This 188-byte
     * physical guard read is immediately followed by kwrite32, whose original
     * implementation performs its 8-byte read/merge and the checked writer's
     * 32-byte read/retarget/write sequence. Nothing touches KRW afterward. */
    NSData *lastMomentGuard = CNDHailMaryPatchReadGuard(context);
    if (lastMomentGuard.length != kCNDHailMaryPatchGuardLength) {
        if (errorOut) *errorOut = @"last-moment-guard-read-failed";
        return NO;
    }
    if (![lastMomentGuard isEqualToData:expectedBefore]) {
        if (errorOut) *errorOut = @"guard-changed-before-write";
        return NO;
    }

    /* This is intentionally the same public compatibility route used by the
     * successful legacy build. Do not add verification or cleanup below it. */
    if (writeInvokedOut) *writeInvokedOut = YES;
    kwrite32(targetKVA, desiredWord);
    return YES;
}

static void CNDHailMaryPatchFinish(
    NSMutableDictionary<NSString *, id> *report,
    CNDHailMaryPatchCompletion completion)
{
    NSString *path = report[@"reportPath"];
    CNDHailMaryPatchSave(report, path);
    NSDictionary<NSString *, id> *finished = [report copy];
    __sync_lock_release(&gCNDHailMaryPatchRunning);
    dispatch_async(dispatch_get_main_queue(), ^{
        completion(finished);
    });
}

BOOL CNDHailMaryPatchIsSupported(NSString **reasonOut)
{
    NSString *probeReason = nil;
    BOOL supported = CNDHailMaryProbeIsSupported(&probeReason);
    if (reasonOut) {
        *reasonOut = supported
            ? @"Exact iPhone17,2 / 23A341 target matched."
            : probeReason;
    }
    return supported;
}

BOOL CNDHailMaryPatchIsRunning(void)
{
    return __sync_fetch_and_add(&gCNDHailMaryPatchRunning, 0) != 0;
}

void CNDHailMaryPatchRun(CNDHailMaryPatchOperation operation,
                         CNDHailMaryPatchCompletion completion)
{
    if (!completion) return;
    if (!__sync_bool_compare_and_swap(&gCNDHailMaryPatchRunning, 0, 1)) {
        completion(@{
            @"confirmed": @NO,
            @"result": @"refused-already-running",
            @"message": @"The Hail Mary Patch operation is already running.",
        });
        return;
    }

    NSString *reportPath = CNDHailMaryPatchReportPath();
    NSMutableDictionary<NSString *, id> *report = [@{
        @"schemaVersion": @2,
        @"experiment": @"hail-mary-reversible-shared-page-word-patch",
        @"operation": CNDHailMaryPatchOperationName(operation),
        @"productType": @CND_HAIL_MARY_PATCH_PRODUCT,
        @"productBuildVersion": @CND_HAIL_MARY_PATCH_BUILD,
        @"reportPath": reportPath,
        @"startedAtUnixTime": @([[NSDate date] timeIntervalSince1970]),
        @"confirmed": @NO,
        @"kernelWritePrimitiveInvocationCount": @0,
        @"sharedPhysicalCodeWordMutationCount": @0,
        @"targetProcessDirectMutationCount": @0,
        @"expected": @{
            @"unslidTargetVirtualAddress": CNDHailMaryPatchHex(
                kCNDHailMaryPatchUnslidTargetVirtualAddress),
            @"guardOffsetWithinFrame": @(
                kCNDHailMaryPatchGuardOffsetWithinFrame),
            @"wordOffsetWithinFrame": @(
                kCNDHailMaryPatchWordOffsetWithinFrame),
            @"guardLength": @(kCNDHailMaryPatchGuardLength),
            @"originalWord": CNDHailMaryPatchHex(
                kCNDHailMaryPatchOriginalWord),
            @"replacementWord": CNDHailMaryPatchHex(
                kCNDHailMaryPatchReplacementWord),
            @"originalGuardSHA256":
                @CND_HAIL_MARY_ORIGINAL_SHA256,
            @"patchedGuardSHA256":
                @CND_HAIL_MARY_PATCHED_SHA256,
        },
    } mutableCopy];

    NSString *supportReason = nil;
    if (!CNDHailMaryPatchIsSupported(&supportReason)) {
        report[@"result"] = @"refused-unsupported-device";
        report[@"message"] = supportReason ?: @"Unsupported device.";
        CNDHailMaryPatchFinish(report, completion);
        return;
    }
    if (CNDHailMaryImpRedirectIsRunning()) {
        report[@"result"] = @"refused-conflicting-hail-mary-experiment";
        report[@"message"] = @"The guarded dispatch redirect is already running.";
        CNDHailMaryPatchFinish(report, completion);
        return;
    }
    if (!kexploit_krw_ready()) {
        report[@"result"] = @"refused-krw-unavailable";
        report[@"message"] = @"Validated KRW is required.";
        CNDHailMaryPatchFinish(report, completion);
        return;
    }

    BOOL expectPatchedBefore = CNDHailMaryPatchExpectedPatched(operation);
    CNDHailMaryProbeRun(^(NSDictionary<NSString *, id> *preflight) {
        dispatch_async(dispatch_get_global_queue(
            QOS_CLASS_USER_INITIATED, 0), ^{
            report[@"preflightProbe"] = preflight ?: @{};
            NSData *beforeGuard = nil;
            NSString *preflightError = nil;
            NSDictionary<NSString *, id> *context =
                CNDHailMaryPatchValidateProof(
                    preflight, expectPatchedBefore, &beforeGuard,
                    &preflightError);
            if (!context) {
                report[@"result"] = @"preflight-refused";
                report[@"message"] = preflightError ?:
                    @"The exact physical-page preflight failed.";
                CNDHailMaryPatchFinish(report, completion);
                return;
            }
            report[@"preflight"] = context;

            if (!CNDHailMaryPatchIsMutation(operation)) {
                report[@"confirmed"] = @YES;
                report[@"result"] = expectPatchedBefore
                    ? @"confirmed-patched-shared-physical-frame"
                    : @"confirmed-original-shared-physical-frame";
                report[@"message"] = expectPatchedBefore
                    ? @"The replacement word and patched guard are present through one stable shared physical frame."
                    : @"The original word and guard are present through one stable shared physical frame.";
                CNDHailMaryPatchFinish(report, completion);
                return;
            }

            BOOL apply = operation == CNDHailMaryPatchOperationApply;
            uint32_t desiredWord = apply
                ? kCNDHailMaryPatchReplacementWord
                : kCNDHailMaryPatchOriginalWord;
            NSString *desiredSHA = apply
                ? @CND_HAIL_MARY_PATCHED_SHA256
                : @CND_HAIL_MARY_ORIGINAL_SHA256;
            report[@"recovery"] = @{
                @"automaticRollbackEnabled": @NO,
                @"reason": @"No physical-aperture read or rollback write is permitted after the single mutation dispatch.",
                @"restoreOriginalWord": CNDHailMaryPatchHex(
                    kCNDHailMaryPatchOriginalWord),
                @"restoreRequiresExactPatchedGuard": @YES,
            };
            report[@"stage"] = apply
                ? @"arming-legacy-landing-no-mlock"
                : @"arming-legacy-landing-restore";
            NSString *journalError = nil;
            if (!CNDHailMaryPatchSaveDurably(
                    report, reportPath, &journalError)) {
                report[@"result"] = @"prewrite-journal-sync-failed";
                report[@"message"] = journalError ?:
                    @"The prewrite journal could not be made durable.";
                CNDHailMaryPatchFinish(report, completion);
                return;
            }

            NSDictionary<NSString *, id> *pageWire = nil;
            if (apply && kCNDHailMaryPatchAttemptSpringBoardMlock) {
                pageWire = CNDHailMaryPatchWireSpringBoardPage(context);
            } else if (apply) {
                pageWire = @{
                    @"ok": @YES,
                    @"attempted": @NO,
                    @"wired": @NO,
                    @"stage": @"skipped-for-legacy-landing",
                    @"message": @"SpringBoard mlock was deliberately skipped so the mutation can reproduce the legacy pre-write conditioning sequence.",
                };
            } else {
                pageWire = @{
                    @"ok": @YES,
                    @"attempted": @NO,
                    @"wired": @NO,
                    @"stage": @"not-requested-for-restore",
                    @"message": @"Restore does not add another process-owned page wire.",
                };
            }
            report[@"springBoardPageWire"] = pageWire;
            if (![pageWire[@"ok"] boolValue]) {
                report[@"result"] = @"springboard-page-wire-failed";
                report[@"message"] = pageWire[@"message"] ?:
                    @"SpringBoard could not wire the exact shared-cache page.";
                CNDHailMaryPatchFinish(report, completion);
                return;
            }

            report[@"stage"] = @"armed-legacy-landing-no-readback";
            journalError = nil;
            if (!CNDHailMaryPatchSaveDurably(
                    report, reportPath, &journalError)) {
                report[@"result"] = @"armed-journal-sync-failed";
                report[@"message"] = journalError ?:
                    @"The armed single-write journal could not be made durable.";
                CNDHailMaryPatchFinish(report, completion);
                return;
            }

            uint8_t plannedWriteWindowBytes[EARLY_KRW_LENGTH] = {0};
            [beforeGuard getBytes:plannedWriteWindowBytes
                            range:NSMakeRange(
                                kCNDHailMaryPatchWordOffsetWithinGuard,
                                sizeof(plannedWriteWindowBytes))];
            memcpy(plannedWriteWindowBytes, &desiredWord,
                   sizeof(desiredWord));
            NSData *plannedWriteWindow = [NSData
                dataWithBytes:plannedWriteWindowBytes
                       length:sizeof(plannedWriteWindowBytes)];
            BOOL writeInvoked = NO;
            NSString *writeError = nil;
            BOOL writeDispatchReturned =
                CNDHailMaryPatchWriteWordLegacyLanding(
                    context, beforeGuard, desiredWord, &writeInvoked,
                    &writeError);
            report[@"kernelWritePrimitiveInvocationCount"] =
                @(writeInvoked ? 1 : 0);
            report[@"sharedPhysicalCodeWordMutationCount"] =
                @(writeInvoked ? 1 : 0);
            NSData *beforeWindow = beforeGuard.length >=
                    kCNDHailMaryPatchWordOffsetWithinGuard + EARLY_KRW_LENGTH
                ? [beforeGuard subdataWithRange:NSMakeRange(
                    kCNDHailMaryPatchWordOffsetWithinGuard,
                    EARLY_KRW_LENGTH)]
                : nil;
            report[@"write"] = @{
                @"logicalByteCount": @4,
                @"transportByteCount": @(EARLY_KRW_LENGTH),
                @"beforeWord": CNDHailMaryPatchHex(
                    CNDHailMaryPatchWord(beforeGuard)),
                @"desiredWord": CNDHailMaryPatchHex(desiredWord),
                @"beforeGuardSHA256": CNDHailMaryPatchSHA256(
                    beforeGuard),
                @"lastMomentGuardMatchedPreflight": @(writeInvoked),
                @"desiredGuardSHA256": desiredSHA,
                @"beforeTransportWindowSHA256":
                    CNDHailMaryPatchSHA256(beforeWindow),
                @"plannedWriteTransportWindowSHA256":
                    CNDHailMaryPatchSHA256(plannedWriteWindow),
                @"neighborBytesPreservedFromLastMomentGuard": @YES,
                @"prewritePhysicalGuardReadPerformed": @YES,
                @"legacyConditioningSequence": @[
                    @"guard-kreadbuf-188",
                    @"kwrite32-kread64",
                    @"early-kwrite64-read32",
                    @"early-kwrite64-write32",
                ],
                @"writeDispatchReturned": @(writeDispatchReturned),
                @"physicalReadbackPerformed": @NO,
                @"postflightProbePerformed": @NO,
            };
            report[@"writeDispatchReturned"] = @(writeDispatchReturned);
            report[@"physicalReadbackPerformed"] = @NO;
            report[@"postflightProbePerformed"] = @NO;
            report[@"stage"] = writeDispatchReturned
                ? @"legacy-write-dispatch-returned-no-readback"
                : @"legacy-write-refused-before-dispatch";
            if (!writeDispatchReturned) {
                report[@"result"] = @"legacy-write-refused-before-dispatch";
                report[@"message"] = writeError ?:
                    @"The legacy landing sequence refused the write before dispatch; no physical readback or automatic rollback was attempted.";
                CNDHailMaryPatchFinish(report, completion);
                return;
            }
            report[@"result"] = apply
                ? @"apply-legacy-write-dispatch-returned-no-readback"
                : @"restore-legacy-write-dispatch-returned-no-readback";
            report[@"message"] = apply
                ? @"The legacy landing sequence returned from its single kwrite32 dispatch. This is not byte verification. No post-write physical read, rollback, or automatic respring was attempted; if the system remains alive, restart Spotlight alone for behavioral validation."
                : @"The legacy landing sequence returned from its single restore kwrite32 dispatch. This is not byte verification. No post-write physical read or automatic respring was attempted; verification must run as a separate operation.";
            CNDHailMaryPatchFinish(report, completion);
        });
    });
}
