#import "CNDIconServicesInterceptProof.h"
#import "CNDIconDeclarationRedirect.h"
#import "CNDIconServicesConsumerHook.h"
#import "CNDIconServicesConsumerPayload.h"
#import "CNDIconServicesPublisher.h"
#import "CNDIconServicesStructuredPayload.h"
#import "CNDIconThemeImageProcessor.h"
#import "../TaskRop/RemoteCall.h"
#import "../kexploit/kutils.h"
#import "../tweaks/themer.h"

#import <CommonCrypto/CommonDigest.h>
#import <dlfcn.h>
#import <errno.h>
#import <limits.h>
#import <objc/message.h>
#import <signal.h>
#import <sys/stat.h>
#import <UIKit/UIKit.h>

static NSString * const CNDInterceptTarget = @"com.ebay.iphone";
static NSString * const CNDInterceptThemeName = @"CNDIconRedirectTheme";
static NSString * const CNDInterceptThemeHash =
    @"74122c8aa948fc4e2d9d02148f62b88b8e4c77b1727cd34cf5632f9c6bbdca8b";
static NSString * const CNDInterceptJournalKey =
    @"CNDIconServicesProviderInterceptProofV1";
static NSString * const CNDInterceptRetiredConsumerJournalKey =
    @"CNDIconServicesConsumerHookMappingsV1";

typedef void (*CNDInvalidateIconCache)(NSString *bundleIdentifier);

static NSString *cnd_intercept_sha256(NSData *data)
{
    if (!data) return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *text = [NSMutableString stringWithCapacity:64];
    for (NSUInteger i = 0; i < sizeof(digest); i++) {
        [text appendFormat:@"%02x", digest[i]];
    }
    return text;
}

static NSDictionary *cnd_intercept_result(BOOL ok, NSString *stage,
                                           NSString *message,
                                           NSDictionary *details)
{
    NSMutableDictionary *result = [@{
        @"ok": @(ok),
        @"active": @(CNDIconServicesInterceptProofIsActive()),
        @"stage": stage ?: @"unknown",
        @"message": message ?: @"",
    } mutableCopy];
    if (details) [result addEntriesFromDictionary:details];
    return result;
}

static NSDictionary *cnd_intercept_journal(void)
{
    id value = [NSUserDefaults.standardUserDefaults
        objectForKey:CNDInterceptJournalKey];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

BOOL CNDIconServicesInterceptProofIsActive(void)
{
    NSString *phase = cnd_intercept_journal()[@"phase"];
    return themer_spotlight_persistent_store_has_recovery() ||
        [phase isEqualToString:@"prepared"] ||
        [phase isEqualToString:@"dispatch-possible"] ||
        [phase isEqualToString:@"store-published"] ||
        [phase isEqualToString:@"active"] ||
        [phase isEqualToString:@"recovery-required"];
}

/// The old consumer journal cannot safely prove process birth identity. Only
/// discard an entry after its recorded PID is conclusively absent. EPERM and
/// every other result remain recovery-required and fail closed.
static BOOL cnd_intercept_prune_exited_retired_consumers(
    NSDictionary **remainingOut)
{
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSDictionary *saved = [defaults
        dictionaryForKey:CNDInterceptRetiredConsumerJournalKey] ?: @{};
    NSMutableDictionary *remaining = [NSMutableDictionary dictionary];
    for (NSString *host in saved) {
        NSDictionary *entry = [saved[host] isKindOfClass:NSDictionary.class]
            ? saved[host] : nil;
        int pid = [entry[@"pid"] intValue];
        errno = 0;
        BOOL conclusivelyExited = pid > 1 &&
            kill(pid, 0) != 0 && errno == ESRCH;
        if (!conclusivelyExited) remaining[host] = entry ?: @{};
    }

    if (remaining.count > 0) {
        [defaults setObject:remaining
                     forKey:CNDInterceptRetiredConsumerJournalKey];
    } else {
        [defaults removeObjectForKey:CNDInterceptRetiredConsumerJournalKey];
    }
    BOOL synchronized = [defaults synchronize];
    NSDictionary *readback = [defaults
        dictionaryForKey:CNDInterceptRetiredConsumerJournalKey] ?: @{};
    BOOL exact = synchronized && [readback isEqualToDictionary:remaining];
    if (remainingOut) *remainingOut = readback;
    return exact;
}

static BOOL cnd_intercept_store_journal(NSDictionary *journal)
{
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    if (journal) [defaults setObject:journal forKey:CNDInterceptJournalKey];
    else [defaults removeObjectForKey:CNDInterceptJournalKey];
    if (![defaults synchronize]) return NO;
    NSDictionary *readback = cnd_intercept_journal();
    return journal ? [readback isEqualToDictionary:journal] : readback == nil;
}

NSDictionary<NSString *, id> *
CNDIconServicesInterceptProofResetRecoveryState(void)
{
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    BOOL publisherJournalWasPresent = cnd_intercept_journal() != nil;
    BOOL consumerJournalWasPresent = [defaults
        objectForKey:CNDInterceptRetiredConsumerJournalKey] != nil;
    BOOL storeRecoveryWasPresent =
        themer_spotlight_persistent_store_has_recovery();

    /*
     * A live marker-aware consumer mapping is harmless once the published
     * response is stock, but its address remains the only safe identity for
     * recognizing an already-installed hook in that process.  Emergency
     * reset must therefore forget publication/recovery state without
     * forgetting live mappings.  Otherwise a subsequent Apply could treat
     * our hook as the stock IMP and install a second layer on top of it.
     */
    NSDictionary *retainedConsumerMappings = nil;
    BOOL consumerJournalVerified =
        cnd_intercept_prune_exited_retired_consumers(
            &retainedConsumerMappings);

    BOOL storeRecoveryCleared =
        themer_spotlight_persistent_store_discard_recovery();
    [defaults removeObjectForKey:CNDInterceptJournalKey];
    BOOL synchronized = [defaults synchronize];
    BOOL publisherJournalCleared = cnd_intercept_journal() == nil;
    NSDictionary *consumerJournalReadback = [defaults
        dictionaryForKey:CNDInterceptRetiredConsumerJournalKey] ?: @{};
    BOOL consumerJournalPreserved = consumerJournalVerified &&
        [consumerJournalReadback isEqualToDictionary:
            retainedConsumerMappings ?: @{}];
    BOOL consumerJournalCleared = consumerJournalReadback.count == 0;
    BOOL inactive = !CNDIconServicesInterceptProofIsActive();
    BOOL ok = synchronized && storeRecoveryCleared &&
        publisherJournalCleared && consumerJournalPreserved && inactive;

    return cnd_intercept_result(
        ok,
        ok ? @"recovery-state-reset" : @"recovery-state-reset-failed",
        ok
            ? @"kslop forgot its IconServices publication/recovery state without contacting a target. Live presentation-mapping identities were retained so a later Apply cannot stack hooks; they are inert whenever no kslop-marked response is published."
            : @"kslop could not verify removal of every local IconServices recovery record; no target process or target file was contacted.",
        @{
            @"publisherJournalWasPresent": @(publisherJournalWasPresent),
            @"retiredConsumerJournalWasPresent": @(consumerJournalWasPresent),
            @"persistentStoreRecoveryWasPresent": @(storeRecoveryWasPresent),
            @"publisherJournalCleared": @(publisherJournalCleared),
            @"retiredConsumerJournalCleared": @(consumerJournalCleared),
            @"consumerJournalPreserved": @(consumerJournalPreserved),
            @"retainedConsumerMappings": retainedConsumerMappings ?: @{},
            @"persistentStoreRecoveryCleared": @(storeRecoveryCleared),
            @"targetProcessContacted": @NO,
            @"targetFileContacted": @NO,
            @"registrationAttempted": @NO,
            @"cacheInvalidationIssued": @NO,
            @"restorationClaimed": @NO,
        });
}

static BOOL cnd_intercept_invalidate(void)
{
    void *handle = dlopen(
        "/System/Library/PrivateFrameworks/IconServices.framework/IconServices",
        RTLD_NOW | RTLD_LOCAL);
    CNDInvalidateIconCache invalidate = handle
        ? (CNDInvalidateIconCache)dlsym(
            handle, "_ISInvalidateCacheEntriesForBundleIdentifier") : NULL;
    if (!invalidate) return NO;
    invalidate(CNDInterceptTarget);
    return YES;
}

static NSDictionary<NSString *, id> *
cnd_intercept_install_consumer_mapping(NSString *processName,
                                       double displayScale)
{
    NSMutableDictionary *result = [@{
        @"ok": @NO,
        @"attempted": @YES,
        @"process": processName ?: @"",
        @"remoteOK": @NO,
        @"closed": @NO,
        @"abandoned": @NO,
    } mutableCopy];
    if (processName.length == 0) {
        result[@"reason"] = @"process-name-missing";
        return result;
    }

    RemoteCallSession *session = [[RemoteCallSession alloc]
        initWithProcess:processName
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    if (!session) {
        result[@"reason"] = @"target-process-or-session-unavailable";
        return result;
    }
    result[@"pid"] = @(session.pid);

    __block CNDIconServicesConsumerHookReport report = {0};
    __block BOOL remoteOK = NO;
    @try {
        remote_call_with_session(session, ^{
            (void)CNDIconServicesConsumerHookInstallInCurrentSession(
                processName.UTF8String, displayScale, &report);
            remoteOK = remote_call_current_success();
        });
    } @catch (NSException *exception) {
        result[@"exception"] = [NSString stringWithFormat:@"%@:%@",
            exception.name ?: @"exception",
            exception.reason ?: @"unknown"];
        remoteOK = NO;
    }

    BOOL closed = NO;
    BOOL abandoned = NO;
    if ([session hasLocalState] && remoteOK) {
        (void)[session destroyRemoteCall];
        closed = ![session hasLocalState];
    }
    if ([session hasLocalState]) {
        [session abandonRemoteCall];
        abandoned = YES;
    } else {
        closed = YES;
    }

    NSDictionary *hook = CNDIconServicesConsumerHookReportDictionary(&report);
    BOOL installed =
        report.result == CNDIconServicesConsumerHookInstalled ||
        report.result == CNDIconServicesConsumerHookAlreadyInstalled;
    BOOL ok = installed && report.methodsReadbackVerified &&
        report.transportClean && remoteOK && closed && !abandoned;
    [result addEntriesFromDictionary:@{
        @"ok": @(ok),
        @"remoteOK": @(remoteOK),
        @"closed": @(closed),
        @"abandoned": @(abandoned),
        @"hook": hook,
        @"reason": hook[@"reason"] ?: result[@"reason"] ?: @"",
    }];
    return result;
}

static NSString *cnd_intercept_ebay_bundle_path(void)
{
    (void)dlopen(
        "/System/Library/Frameworks/MobileCoreServices.framework/"
        "MobileCoreServices", RTLD_NOW | RTLD_LOCAL);
    Class cls = NSClassFromString(@"LSApplicationProxy");
    SEL proxySelector = NSSelectorFromString(@"applicationProxyForIdentifier:");
    NSString *path = nil;
    if (cls && [cls respondsToSelector:proxySelector]) {
        id (*sendProxy)(id, SEL, id) = (void *)objc_msgSend;
        id proxy = sendProxy(cls, proxySelector, CNDInterceptTarget);
        SEL urlSelector = NSSelectorFromString(@"bundleURL");
        if (proxy && [proxy respondsToSelector:urlSelector]) {
            id (*sendObject)(id, SEL) = (void *)objc_msgSend;
            NSURL *url = sendObject(proxy, urlSelector);
            path = [url isKindOfClass:NSURL.class] ? url.path : nil;
        }
    }

    // Sandboxed Cyanide can receive a proxy whose bundleURL is redacted on
    // the VM. The explicit root harness therefore records the one target path
    // it resolved while arming this proof. Treat it only as a discovery hint;
    // the strict shape and on-disk target checks below remain authoritative.
    if (path.length == 0 && remote_call_lab_backend_opted_in()) {
        char labPath[PATH_MAX] = {0};
        if (remote_call_lab_copy_target_bundle_path(
                labPath, sizeof(labPath))) {
            path = [NSString stringWithUTF8String:labPath];
        }
    }
    if (path.length == 0) return nil;

    NSString *standard = path.stringByStandardizingPath;
    NSString *root = @"/var/containers/Bundle/Application";
    NSString *privateRoot = @"/private/var/containers/Bundle/Application";
    NSString *relative = nil;
    for (NSString *candidate in @[ root, privateRoot ]) {
        NSString *prefix = [candidate stringByAppendingString:@"/"];
        if ([standard hasPrefix:prefix]) {
            relative = [standard substringFromIndex:prefix.length];
            break;
        }
    }
    NSArray<NSString *> *components = relative.pathComponents;
    if (components.count != 2 ||
        ![components[1] isEqualToString:@"eBay.app"] ||
        ![[NSUUID alloc] initWithUUIDString:components[0]]) {
        return nil;
    }
    return standard;
}

static NSDictionary *cnd_intercept_bundle_snapshot(NSString **failureOut)
{
    if (failureOut) *failureOut = nil;
    NSString *bundlePath = cnd_intercept_ebay_bundle_path();
    struct stat bundleStat = {0};
    if (bundlePath.length == 0 ||
        lstat(bundlePath.fileSystemRepresentation, &bundleStat) != 0 ||
        !S_ISDIR(bundleStat.st_mode) || S_ISLNK(bundleStat.st_mode)) {
        if (failureOut) *failureOut = @"eBay bundle path unavailable";
        return nil;
    }
    NSError *listError = nil;
    NSArray<NSString *> *entries = [NSFileManager.defaultManager
        contentsOfDirectoryAtPath:bundlePath error:&listError];
    if (!entries || entries.count > 2048) {
        if (failureOut) *failureOut = listError.localizedDescription ?:
            @"eBay bundle inventory is unavailable or unbounded";
        return nil;
    }
    NSMutableDictionary *files = [NSMutableDictionary dictionary];
    for (NSString *name in entries) {
        NSString *extension = name.pathExtension.lowercaseString;
        if (![name isEqualToString:@"Info.plist"] &&
            ![name isEqualToString:@"Assets.car"] &&
            ![extension isEqualToString:@"png"]) continue;
        if ([name containsString:@"/"] || [name isEqualToString:@"."] ||
            [name isEqualToString:@".."]) continue;
        NSString *path = [bundlePath stringByAppendingPathComponent:name];
        struct stat st = {0};
        if (lstat(path.fileSystemRepresentation, &st) != 0 ||
            !S_ISREG(st.st_mode) || S_ISLNK(st.st_mode) ||
            st.st_size < 0 || st.st_size > (64LL << 20)) {
            if (failureOut) *failureOut = [NSString stringWithFormat:
                @"unsafe or unreadable eBay icon source: %@", name];
            return nil;
        }
        NSData *data = [NSData dataWithContentsOfFile:path
                                             options:NSDataReadingMappedIfSafe
                                               error:&listError];
        NSString *hash = cnd_intercept_sha256(data);
        if (!data || hash.length != 64) {
            if (failureOut) *failureOut = listError.localizedDescription ?:
                [NSString stringWithFormat:@"could not hash %@", name];
            return nil;
        }
        files[name] = @{ @"length": @(data.length), @"sha256": hash };
    }
    if (!files[@"Info.plist"] || !files[@"Assets.car"]) {
        if (failureOut) *failureOut =
            @"eBay Info.plist or Assets.car was not captured";
        return nil;
    }
    return @{ @"bundlePath": bundlePath, @"files": files };
}

#if 0
// Retained temporarily as source-level research only. The former provider
// implementation opened a RemoteCall session in a consumer process and is
// deliberately excluded from the product binary during the transition.
static NSDictionary *cnd_intercept_report_dictionary(
    const ThemerIconProviderInterceptReport *report,
    BOOL remoteOK, BOOL closed, BOOL abandoned)
{
    if (!report) return @{};
#define CND_TEXT(field) ([NSString stringWithUTF8String:(field)] ?: @"")
    NSDictionary *result = @{
        @"remoteResult": @((int)report->result),
        @"remoteOK": @(remoteOK),
        @"closed": @(closed),
        @"abandoned": @(abandoned),
        @"transportClean": @(report->transportClean),
        @"stockProviderCaptured": @(report->stockProviderCaptured),
        @"themedProviderConstructed": @(report->themedProviderConstructed),
        @"providerResourcesReplaced": @(report->providerResourcesReplaced),
        @"providerResourcesRestored": @(report->providerResourcesRestored),
        @"canonicalIconSelected": @(report->canonicalIconSelected),
        @"providerReplacementInstalled":
            @(report->providerReplacementInstalled),
        @"providerReplacementRestored":
            @(report->providerReplacementRestored),
        @"agentRestartDiscardedReplacement":
            @(report->agentRestartDiscardedReplacement),
        @"providerBoundaryIntercepted": @(report->providerBoundaryIntercepted),
        @"controlProviderStayedStock": @(report->controlProviderStayedStock),
        @"generationInvoked": @(report->generationInvoked),
        @"recordIdentifiersObserved":
            @(report->recordIdentifiersObserved),
        @"recordIdentifiersOwnershipVerified":
            @(report->recordIdentifiersOwnershipVerified),
        @"generationReturnedImage": @(report->generationReturnedImage),
        @"generatedPixelsCaptured": @(report->generatedPixelsCaptured),
        @"generatedPixelsDifferFromStock":
            @(report->generatedPixelsDifferFromStock),
        @"canonicalCachePublished": @(report->canonicalCachePublished),
        @"canonicalCacheReadbackVerified":
            @(report->canonicalCacheReadbackVerified),
        @"consumerIconLocated": @(report->consumerIconLocated),
        @"consumerBridgeInstalled": @(report->consumerBridgeInstalled),
        @"consumerBridgeReadbackVerified":
            @(report->consumerBridgeReadbackVerified),
        @"consumerRefreshIssued": @(report->consumerRefreshIssued),
        @"consumerBridgeRestored": @(report->consumerBridgeRestored),
        @"consumerIconClass": CND_TEXT(report->consumerIconClass),
        @"objectClassRestored": @(report->objectClassRestored),
        @"associationCleared": @(report->associationCleared),
        @"generatedImageLength": @(report->generatedImageLength),
        @"stockProviderClass": CND_TEXT(report->stockProviderClass),
        @"themedProviderClass": CND_TEXT(report->themedProviderClass),
        @"resolvedResourceClass": CND_TEXT(report->resolvedResourceClass),
        @"generatedImageClass": CND_TEXT(report->generatedImageClass),
        @"stockPixelSHA256": CND_TEXT(report->stockPixelSHA256),
        @"generatedPixelSHA256": CND_TEXT(report->generatedPixelSHA256),
        @"reason": CND_TEXT(report->reason),
    };
#undef CND_TEXT
    return result;
}

static NSDictionary *cnd_intercept_run(BOOL applying)
{
    if (!remote_call_lab_backend_opted_in()) {
        return cnd_intercept_result(NO, @"vm-only",
            @"The provider interception proof is enabled only by the explicit vPhone RemoteCall lab harness.", nil);
    }
    if (CNDIconDeclarationRedirectIsActive()) {
        return cnd_intercept_result(NO, @"filesystem-recovery-pending",
            @"Restore the pending filesystem icon transaction before running the provider-only proof.", nil);
    }
    NSDictionary *existing = cnd_intercept_journal();
    if (applying && CNDIconServicesInterceptProofIsActive()) {
        return cnd_intercept_result(NO, @"already-active",
            @"Restore the current provider interception proof before applying it again.", nil);
    }
    if (!applying && !CNDIconServicesInterceptProofIsActive()) {
        return cnd_intercept_result(YES, @"already-restored",
            @"No provider interception proof is active.", nil);
    }
    NSString *snapshotFailure = nil;
    NSDictionary *before = cnd_intercept_bundle_snapshot(&snapshotFailure);
    if (!before && remote_call_lab_prepare_bundle_access()) {
        snapshotFailure = nil;
        before = cnd_intercept_bundle_snapshot(&snapshotFailure);
    }
    if (!before) {
        return cnd_intercept_result(NO, @"lab-bundle-access",
            snapshotFailure ?:
                @"Re-enable the Spotlight lab harness so kslop and Spotlight receive fresh read-only bundle extensions.", nil);
    }
    NSString *savedPath = existing[@"bundlePath"];
    if (!applying && savedPath.length > 0 &&
        ![savedPath isEqualToString:before[@"bundlePath"]]) {
        return cnd_intercept_result(NO, @"bundle-path-drift",
            @"eBay's installed bundle path changed; refusing to apply recovery to a different installation.",
            @{ @"before": before });
    }
    NSDictionary *savedBaseline = existing[@"baseline"];
    if (!applying && savedBaseline &&
        ![savedBaseline isEqualToDictionary:before]) {
        return cnd_intercept_result(NO, @"bundle-source-drift",
            @"An eBay source file changed after the proof; refusing to call that immutable control restored.",
            @{ @"savedBaseline": savedBaseline, @"before": before });
    }

    // Every proof mutation is process-local Objective-C state. If the exact
    // recorded host PID exited, neither the consumer graft nor its associated
    // provider can still exist. Complete recovery locally instead of asking
    // the user to arm a replacement process solely to prove the old address
    // space is gone.
    if (!applying) {
        int savedPID = [existing[@"pid"] intValue];
        errno = 0;
        if (savedPID > 1 && kill(savedPID, 0) != 0 && errno == ESRCH) {
            BOOL invalidated = cnd_intercept_invalidate();
            BOOL cleared = invalidated && cnd_intercept_store_journal(nil);
            return cnd_intercept_result(
                cleared,
                cleared ? @"restored-after-agent-restart"
                        : @"restart-recovery",
                cleared
                    ? @"The recorded icon host exited, so its process-local consumer/provider replacement was already gone; cache invalidation succeeded and the recovery journal was cleared."
                    : @"The recorded icon host exited, but cache invalidation or journal cleanup failed.",
                @{
                    @"filesUnchanged": @YES,
                    @"agentRestartDiscardedReplacement": @YES,
                    @"providerReplacementRestored": @YES,
                    @"objectClassRestored": @YES,
                    @"associationCleared": @YES,
                });
        }
    }

    NSString *themePath = [NSBundle.mainBundle
        pathForResource:CNDInterceptThemeName ofType:@"png"];
    NSData *themeData = applying
        ? [NSData dataWithContentsOfFile:themePath ?: @""] : nil;
    NSString *themeHash = applying ? cnd_intercept_sha256(themeData) : nil;
    if (applying && (![themeHash isEqualToString:CNDInterceptThemeHash] ||
                     themeData.length == 0)) {
        return cnd_intercept_result(NO, @"theme-payload",
            @"The exact kslop theme payload is missing or has the wrong hash.",
            @{ @"observedHash": themeHash ?: @"" });
    }
    if (!cnd_intercept_invalidate()) {
        return cnd_intercept_result(NO, @"cache-invalidation",
            @"The per-bundle IconServices invalidation entry point is unavailable.", nil);
    }

    NSString *remoteHost = applying
        ? @"Spotlight"
        : ([existing[@"host"] isKindOfClass:NSString.class]
            ? existing[@"host"] : @"iconservicesagent");
    NSMutableDictionary *journal = [@{
        @"version": @2,
        @"phase": @"dispatch-possible",
        @"target": CNDInterceptTarget,
        @"host": remoteHost,
        @"bundlePath": before[@"bundlePath"],
        @"baseline": before,
        @"themeSHA256": themeHash ?: existing[@"themeSHA256"] ?: @"",
        @"createdAt": @([NSDate.date timeIntervalSince1970]),
    } mutableCopy];
    if (!cnd_intercept_store_journal(journal)) {
        return cnd_intercept_result(NO, @"journal",
            @"The provider proof journal did not survive exact readback.", nil);
    }

    RemoteCallSession *session = [[RemoteCallSession alloc]
        initWithProcess:remoteHost
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    if (!session) {
        if (applying) (void)cnd_intercept_store_journal(nil);
        else (void)cnd_intercept_store_journal(existing);
        return cnd_intercept_result(NO, @"remote-session",
            applying
                ? @"Could not open the Spotlight lab session. Open Spotlight with an eBay result visible, re-arm the Spotlight VM harness, and try again."
                : @"Could not reopen the exact process recorded by this proof.", nil);
    }
    int pid = session.pid;
    journal[@"pid"] = @(pid);
    if (!cnd_intercept_store_journal(journal)) {
        [session abandonRemoteCall];
        return cnd_intercept_result(NO, @"journal",
            @"The host identity could not be committed before the consumer mutation.", nil);
    }
    __block ThemerIconProviderInterceptReport report = {0};
    __block BOOL remoteOK = NO;
    @try {
        remote_call_with_session(session, ^{
            uint64_t pool = themer_spotlight_remote_autorelease_pool_push();
            if (!pool) return;
            if (applying) {
                NSDictionary *images = @{ CNDInterceptTarget: themeData };
                (void)themer_iconservices_provider_intercept_apply_in_session(
                    images, CNDInterceptTarget.UTF8String,
                    NSBundle.mainBundle.bundlePath.UTF8String,
                    CNDInterceptThemeName.UTF8String, &report);
            } else {
                (void)themer_iconservices_provider_intercept_restore_in_session(
                    CNDInterceptTarget.UTF8String, &report);
            }
            if (remote_call_current_success()) {
                themer_spotlight_remote_autorelease_pool_pop(pool);
            }
            remoteOK = remote_call_current_success();
        });
    } @catch (NSException *exception) {
        NSLog(@"[ICONINTERCEPT] remote exception %@: %@",
              exception.name, exception.reason);
        remoteOK = NO;
    }
    BOOL closed = NO;
    BOOL abandoned = NO;
    if ([session hasLocalState] && remoteOK) {
        (void)[session destroyRemoteCall];
        closed = ![session hasLocalState];
    }
    if ([session hasLocalState]) {
        [session abandonRemoteCall];
        abandoned = YES;
    } else {
        closed = YES;
    }

    snapshotFailure = nil;
    NSDictionary *after = cnd_intercept_bundle_snapshot(&snapshotFailure);
    BOOL filesUnchanged = before && after && [before isEqualToDictionary:after];
    NSDictionary *reportDictionary = cnd_intercept_report_dictionary(
        &report, remoteOK, closed, abandoned);
    BOOL postMutationInvalidation = remoteOK && closed && !abandoned
        ? cnd_intercept_invalidate() : NO;
    BOOL success = report.result == ThemerIconProviderInterceptReady &&
        remoteOK && closed && !abandoned && filesUnchanged &&
        postMutationInvalidation;
    if (success) {
        journal[@"phase"] = applying ? @"active" : @"restored";
        journal[@"pid"] = @(pid);
        journal[@"host"] = remoteHost;
        journal[@"report"] = reportDictionary;
        journal[@"completedAt"] = @([NSDate.date timeIntervalSince1970]);
        if (applying) success = cnd_intercept_store_journal(journal);
        else success = cnd_intercept_store_journal(nil);
    } else if (!report.generationInvoked && filesUnchanged) {
        // No request crossed the generation boundary, so there is no remote
        // cache/store effect to recover. The in-session routine independently
        // restores any temporary class/association before it reports.
        (void)cnd_intercept_store_journal(nil);
    } else {
        journal[@"phase"] = @"recovery-required";
        journal[@"pid"] = @(pid);
        journal[@"host"] = remoteHost;
        journal[@"report"] = reportDictionary;
        (void)cnd_intercept_store_journal(journal);
    }

    NSMutableDictionary *details = [reportDictionary mutableCopy];
    details[@"filesUnchanged"] = @(filesUnchanged);
    details[@"bundleBefore"] = before ?: @{};
    details[@"bundleAfter"] = after ?: @{};
    details[@"snapshotFailure"] = snapshotFailure ?: @"";
    details[@"cacheInvalidationIssued"] = @(postMutationInvalidation);
    return cnd_intercept_result(
        success,
        success ? (applying ? @"active" : @"restored")
                : @"provider-intercept",
        success
            ? (applying
                ? @"Spotlight's real eBay SBHApplicationIcon now returns the exact themed IconServices object; eBay's bundle and registration were untouched."
                : @"The Spotlight consumer bridge and canonical provider replacement were removed and the recovery journal was cleared.")
            : @"The provider-boundary proof did not satisfy every generation, cleanup, teardown, and immutable-bundle check.",
        details);
}
#endif

NSDictionary<NSString *, id> *CNDIconServicesInterceptProofInspectVisibleResponse(void)
{
    return cnd_intercept_result(
        NO, @"retired-spotlight-inspection",
        @"The Spotlight RemoteCall inspection path is retired. Phase 2 will resolve the persistent IconServices record independently of SpringBoard and Spotlight.",
        @{ @"consumerRemoteCallAttempted": @NO });
#if 0
    // Historical implementation retained as research only. It is not built.
    if (!remote_call_lab_backend_opted_in()) {
        return cnd_intercept_result(NO, @"vm-only",
            @"Visible indexed-response inspection requires the explicit vPhone RemoteCall lab harness.", nil);
    }
    if (CNDIconDeclarationRedirectIsActive() ||
        CNDIconServicesInterceptProofIsActive()) {
        return cnd_intercept_result(NO, @"recovery-pending",
            @"Restore the pending icon experiment before inspecting Spotlight's stock indexed response.", nil);
    }

    RemoteCallSession *session = [[RemoteCallSession alloc]
        initWithProcess:@"Spotlight"
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    if (!session) {
        return cnd_intercept_result(NO, @"remote-session",
            @"Could not open Spotlight. Leave exactly one visible eBay result on screen and re-arm the VM lab backend.", nil);
    }

    __block ThemerSpotlightIndexedResponseReport report = {0};
    __block BOOL remoteOK = NO;
    @try {
        remote_call_with_session(session, ^{
            uint64_t pool = themer_spotlight_remote_autorelease_pool_push();
            if (!pool) return;
            (void)themer_spotlight_identify_visible_indexed_response_in_session(
                CNDInterceptTarget.UTF8String, &report);
            if (remote_call_current_success()) {
                themer_spotlight_remote_autorelease_pool_pop(pool);
            }
            remoteOK = remote_call_current_success();
        });
    } @catch (NSException *exception) {
        NSLog(@"[ICONINDEX] remote exception %@: %@",
              exception.name, exception.reason);
        remoteOK = NO;
    }

    BOOL closed = NO;
    BOOL abandoned = NO;
    if ([session hasLocalState] && remoteOK) {
        (void)[session destroyRemoteCall];
        closed = ![session hasLocalState];
    }
    if ([session hasLocalState]) {
        [session abandonRemoteCall];
        abandoned = YES;
    } else {
        closed = YES;
    }

#define CND_INDEX_TEXT(field) ([NSString stringWithUTF8String:(field)] ?: @"")
    NSDictionary *details = @{
        @"remoteResult": @((int)report.result),
        @"remoteOK": @(remoteOK),
        @"closed": @(closed),
        @"abandoned": @(abandoned),
        @"transportClean": @(report.transportClean),
        @"noMutation": @(report.noMutation),
        @"visibleRowFound": @(report.visibleRowFound),
        @"consumerIconFound": @(report.consumerIconFound),
        @"iconServicesIconFound": @(report.iconServicesIconFound),
        @"existingCacheFound": @(report.existingCacheFound),
        @"visiblePixelsCaptured": @(report.visiblePixelsCaptured),
        @"exactPixelMatch": @(report.exactPixelMatch),
        @"storeIndexMatch": @(report.storeIndexMatch),
        @"storeFileVerified": @(report.storeFileVerified),
        @"unitDataMatchesFile": @(report.unitDataMatchesFile),
        @"visibleTargetRowCount": @(report.visibleTargetRowCount),
        @"descriptorKeyCount": @(report.descriptorKeyCount),
        @"cacheImageCount": @(report.cacheImageCount),
        @"indexedCandidateCount": @(report.indexedCandidateCount),
        @"exactPixelMatchCount": @(report.exactPixelMatchCount),
        @"visiblePixelWidth": @(report.visiblePixelWidth),
        @"visiblePixelHeight": @(report.visiblePixelHeight),
        @"storeFileLength": @(report.storeFileLength),
        @"visiblePointWidth": @(report.visiblePointWidth),
        @"visiblePointHeight": @(report.visiblePointHeight),
        @"visibleScale": @(report.visibleScale),
        @"responsePointWidth": @(report.responsePointWidth),
        @"responsePointHeight": @(report.responsePointHeight),
        @"responseScale": @(report.responseScale),
        @"rowClass": CND_INDEX_TEXT(report.rowClass),
        @"consumerIconClass": CND_INDEX_TEXT(report.consumerIconClass),
        @"iconServicesIconClass": CND_INDEX_TEXT(report.iconServicesIconClass),
        @"cacheClass": CND_INDEX_TEXT(report.cacheClass),
        @"descriptorKeyClass": CND_INDEX_TEXT(report.descriptorKeyClass),
        @"descriptorKeyText": CND_INDEX_TEXT(report.descriptorKeyText),
        @"responseClass": CND_INDEX_TEXT(report.responseClass),
        @"uuid": CND_INDEX_TEXT(report.uuid),
        @"validationTokenSHA256":
            CND_INDEX_TEXT(report.validationTokenSHA256),
        @"visiblePixelSHA256": CND_INDEX_TEXT(report.visiblePixelSHA256),
        @"responsePixelSHA256": CND_INDEX_TEXT(report.responsePixelSHA256),
        @"storeFileSHA256": CND_INDEX_TEXT(report.storeFileSHA256),
        @"storePath": CND_INDEX_TEXT(report.storePath),
        @"rowSource": CND_INDEX_TEXT(report.rowSource),
        @"reason": CND_INDEX_TEXT(report.reason),
    };
#undef CND_INDEX_TEXT

    BOOL success =
        report.result == ThemerSpotlightIndexedResponseIdentified &&
        remoteOK && closed && !abandoned && report.noMutation &&
        report.exactPixelMatch && report.storeIndexMatch &&
        report.storeFileVerified && report.unitDataMatchesFile;
    return cnd_intercept_result(
        success,
        success ? @"indexed-response-identified"
                : @"indexed-response-inspection",
        success
            ? @"The visible eBay row was bound to one existing indexed IFCacheImage, UUID, store unit, and .isdata file without changing Spotlight or the store."
            : @"The read-only inspection did not prove one exact visible-row-to-indexed-file binding; review the per-candidate ICONINDEX log.",
        details);
#endif
}

NSDictionary<NSString *, id> *CNDIconServicesInterceptProofApply(void)
{
    NSDictionary *existingConsumers = nil;
    if (!cnd_intercept_prune_exited_retired_consumers(
            &existingConsumers)) {
        return cnd_intercept_result(NO, @"consumer-journal",
            @"The presentation-mapping journal did not survive exact readback; no publication was attempted.", nil);
    }
    for (NSDictionary *mapping in existingConsumers.allValues) {
        uint64_t version = [mapping[@"version"] unsignedLongLongValue];
        if (version != CND_ICON_CONSUMER_PAYLOAD_VERSION) {
            return cnd_intercept_result(
                NO, @"consumer-mapping-upgrade-restart-required",
                @"A live presentation mapping belongs to an older payload version. Restart the recorded SpringBoard/Spotlight process before publishing so kslop cannot stack hooks.",
                @{
                    @"consumerMappings": existingConsumers,
                    @"requiredPayloadVersion":
                        @(CND_ICON_CONSUMER_PAYLOAD_VERSION),
                    @"consumerRemoteCallAttempted": @NO,
                });
        }
    }
    if (CNDIconDeclarationRedirectIsActive()) {
        return cnd_intercept_result(NO, @"filesystem-recovery-pending",
            @"Restore the pending app-bundle icon transaction before publishing an IconServices response.", nil);
    }
    if (CNDIconServicesInterceptProofIsActive()) {
        return cnd_intercept_result(NO, @"already-active",
            @"Restore the current IconServices publication before applying another one.", nil);
    }

    NSString *snapshotFailure = nil;
    NSDictionary *before = cnd_intercept_bundle_snapshot(&snapshotFailure);
    if (!before && remote_call_lab_prepare_bundle_access()) {
        snapshotFailure = nil;
        before = cnd_intercept_bundle_snapshot(&snapshotFailure);
    }
    if (!before) {
        return cnd_intercept_result(NO, @"immutable-control",
            snapshotFailure ?: @"The eBay immutable-control snapshot is unavailable.", nil);
    }

    NSString *themePath = [NSBundle.mainBundle
        pathForResource:CNDInterceptThemeName ofType:@"png"];
    NSData *themeData = [NSData dataWithContentsOfFile:themePath ?: @""];
    NSString *themeHash = cnd_intercept_sha256(themeData);
    if (![themeHash isEqualToString:CNDInterceptThemeHash] ||
        themeData.length == 0) {
        return cnd_intercept_result(NO, @"theme-payload",
            @"The exact kslop theme payload is missing or has the wrong hash.",
            @{ @"observedHash": themeHash ?: @"" });
    }

    NSError *processingError = nil;
    NSDictionary *processed = CNDProcessIconThemePNG(
        themeData, 204, 204, 0, &processingError);
    NSData *scaledPNG = [processed[@"unpaddedBytes"]
        isKindOfClass:NSData.class] ? processed[@"unpaddedBytes"] : nil;
    if (!scaledPNG.length ||
        ![processed[@"completeDecodeVerified"] boolValue] ||
        ![processed[@"alphaClassesPreserved"] boolValue]) {
        return cnd_intercept_result(NO, @"theme-render",
            processingError.localizedDescription ?:
                @"The theme could not be rendered as exact transparent 204x204 PNG data.",
            @{ @"processor": processed ?: @{} });
    }

    NSDictionary *structuredDiagnostics = nil;
    NSError *structuredError = nil;
    NSData *structuredImageData =
        CNDIconServicesCreateStructuredImageData(
            scaledPNG, CGSizeMake(68.0, 68.0), 3.0,
            &structuredDiagnostics, &structuredError);
    NSString *structuredHash = cnd_intercept_sha256(structuredImageData);
    if (!structuredImageData.length || structuredHash.length != 64) {
        return cnd_intercept_result(NO, @"structured-payload",
            structuredError.localizedDescription ?:
                @"The transparent structured IFImage response could not be serialized.",
            @{ @"structured": structuredDiagnostics ?: @{} });
    }

    NSMutableDictionary *journal = [@{
        @"version": @6,
        @"phase": @"prepared",
        @"mode": @"iconservices-store-plus-consumer-mappings",
        @"target": CNDInterceptTarget,
        @"bundlePath": before[@"bundlePath"],
        @"baseline": before,
        @"themeSHA256": themeHash,
        @"structuredImageSHA256": structuredHash,
        @"structuredImageLength": @(structuredImageData.length),
        @"createdAt": @([NSDate.date timeIntervalSince1970]),
    } mutableCopy];
    if (!cnd_intercept_store_journal(journal)) {
        return cnd_intercept_result(NO, @"journal",
            @"The pre-publication recovery journal did not survive exact readback.", nil);
    }

    NSDictionary *publication = CNDIconServicesPublisherPublish(
        CNDInterceptTarget, structuredImageData);
    NSDictionary *stock =
        [publication[@"stockResponse"] isKindOfClass:NSDictionary.class]
            ? publication[@"stockResponse"] : @{};
    snapshotFailure = nil;
    NSDictionary *after = cnd_intercept_bundle_snapshot(&snapshotFailure);
    BOOL filesUnchanged = after && [before isEqualToDictionary:after];
    BOOL storePublished = [publication[@"ok"] boolValue] &&
        [publication[@"persistentStoreReadbackVerified"] boolValue] &&
        filesUnchanged;
    journal[@"phase"] = storePublished
        ? @"store-published" : @"recovery-required";
    journal[@"publication"] = publication ?: @{};
    journal[@"stockResponse"] = stock;
    journal[@"filesUnchanged"] = @(filesUnchanged);
    BOOL journalSaved = cnd_intercept_store_journal(journal);

    NSDictionary *springBoardPresentation = @{
        @"ok": @NO, @"attempted": @NO, @"process": @"SpringBoard"
    };
    NSDictionary *spotlightPresentation = @{
        @"ok": @NO, @"attempted": @NO, @"process": @"Spotlight"
    };
    if (storePublished && journalSaved) {
        double displayScale = UIScreen.mainScreen.scale;
        springBoardPresentation = cnd_intercept_install_consumer_mapping(
            @"SpringBoard", displayScale);
        if ([springBoardPresentation[@"ok"] boolValue]) {
            spotlightPresentation = cnd_intercept_install_consumer_mapping(
                @"Spotlight", displayScale);
        }
    }
    BOOL presentationReady =
        [springBoardPresentation[@"ok"] boolValue] &&
        [spotlightPresentation[@"ok"] boolValue];
    /* Install the marker-aware presentation path before evicting stale
     * consumer entries. The invalidation then makes the next Home/Spotlight
     * fetch deserialize the already-verified marked store response through
     * those mappings. */
    BOOL invalidated = storePublished && presentationReady &&
        cnd_intercept_invalidate();
    BOOL published = storePublished && presentationReady && invalidated;
    journal[@"phase"] = published ? @"active" : @"recovery-required";
    journal[@"springBoardPresentation"] = springBoardPresentation;
    journal[@"spotlightPresentation"] = spotlightPresentation;
    journal[@"cacheInvalidationIssued"] = @(invalidated);
    journal[@"completedAt"] = @([NSDate.date timeIntervalSince1970]);
    journalSaved = cnd_intercept_store_journal(journal);
    BOOL possibleThemedMutation =
        [publication[@"replacementCreated"] boolValue] ||
        [publication[@"replacementReturned"] boolValue] ||
        [publication[@"persistentStoreDataLength"] unsignedLongLongValue] > 0;
    BOOL cleanPublicationExit =
        [publication[@"mappingCleaned"] boolValue] &&
        [publication[@"closed"] boolValue] &&
        ![publication[@"abandoned"] boolValue] &&
        ![publication[@"hookStillInstalledAtCleanup"] boolValue];
    if (!storePublished && !possibleThemedMutation &&
        cleanPublicationExit) {
        journalSaved = cnd_intercept_store_journal(nil);
    }

    NSMutableDictionary *details = [publication mutableCopy] ?:
        [NSMutableDictionary dictionary];
    details[@"processor"] = processed ?: @{};
    details[@"structured"] = structuredDiagnostics ?: @{};
    details[@"structuredImageSHA256"] = structuredHash;
    details[@"stockResponseSHA256"] = stock[@"dataSHA256"] ?: @"";
    details[@"filesUnchanged"] = @(filesUnchanged);
    details[@"journalSaved"] = @(journalSaved);
    details[@"storePublished"] = @(storePublished);
    details[@"presentationReady"] = @(presentationReady);
    details[@"cacheInvalidationIssued"] = @(invalidated);
    details[@"springBoardPresentation"] = springBoardPresentation;
    details[@"spotlightPresentation"] = spotlightPresentation;
    details[@"previousConsumerMappings"] = existingConsumers ?: @{};
    details[@"consumerRemoteCallAttempted"] =
        @([springBoardPresentation[@"attempted"] boolValue] ||
          [spotlightPresentation[@"attempted"] boolValue]);
    details[@"springBoardRemoteCallAttempted"] =
        @([springBoardPresentation[@"attempted"] boolValue]);
    details[@"spotlightRemoteCallAttempted"] =
        @([spotlightPresentation[@"attempted"] boolValue]);
    details[@"applicationBundleMutationAttempted"] = @NO;

    BOOL success = published && journalSaved;
    return cnd_intercept_result(
        success,
        success ? @"active" :
            (storePublished ? @"consumer-presentation"
                            : publication[@"stage"] ?: @"publication"),
        success
            ? @"The exact IconServices store unit persisted, marker-aware presentation mappings were verified in SpringBoard and Spotlight, and stale icon caches were invalidated."
            : (storePublished
                ? (presentationReady
                    ? @"The IconServices store and presentation mappings verified, but cache invalidation could not be issued; recovery remains armed."
                    : @"The IconServices store publication is durable, but one consumer presentation mapping did not verify; recovery remains armed.")
                : publication[@"message"] ?:
                    @"IconServices publication did not verify; recovery state was retained if stock regeneration may be required."),
        details);
#if 0
    // Historical implementation retained as research only. It is not built.
    if (!remote_call_lab_backend_opted_in()) {
        return cnd_intercept_result(NO, @"vm-only",
            @"The persistent IconServices store proof is enabled only by the explicit vPhone RemoteCall lab harness.", nil);
    }
    if (CNDIconDeclarationRedirectIsActive()) {
        return cnd_intercept_result(NO, @"filesystem-recovery-pending",
            @"Restore the pending filesystem icon transaction before running the persistent-store proof.", nil);
    }
    if (CNDIconServicesInterceptProofIsActive()) {
        return cnd_intercept_result(NO, @"already-active",
            @"Restore the current IconServices proof before applying another one.", nil);
    }

    NSString *snapshotFailure = nil;
    NSDictionary *before = cnd_intercept_bundle_snapshot(&snapshotFailure);
    if (!before && remote_call_lab_prepare_bundle_access()) {
        snapshotFailure = nil;
        before = cnd_intercept_bundle_snapshot(&snapshotFailure);
    }
    if (!before) {
        return cnd_intercept_result(NO, @"lab-bundle-access",
            snapshotFailure ?: @"Could not capture eBay's immutable control files.", nil);
    }

    NSString *themePath = [NSBundle.mainBundle
        pathForResource:CNDInterceptThemeName ofType:@"png"];
    NSData *themeData = [NSData dataWithContentsOfFile:themePath ?: @""];
    NSString *themeHash = cnd_intercept_sha256(themeData);
    if (![themeHash isEqualToString:CNDInterceptThemeHash] ||
        themeData.length == 0) {
        return cnd_intercept_result(NO, @"theme-payload",
            @"The exact kslop theme payload is missing or has the wrong hash.",
            @{ @"observedHash": themeHash ?: @"" });
    }

    NSMutableDictionary *journal = [@{
        @"version": @3,
        @"phase": @"prepared",
        @"mode": @"persistent-indexed-store-unit",
        @"target": CNDInterceptTarget,
        @"bundlePath": before[@"bundlePath"],
        @"baseline": before,
        @"themeSHA256": themeHash,
        @"createdAt": @([NSDate.date timeIntervalSince1970]),
    } mutableCopy];
    if (!cnd_intercept_store_journal(journal)) {
        return cnd_intercept_result(NO, @"journal",
            @"The persistent-store proof journal did not survive exact readback.", nil);
    }

    double displayScale = UIScreen.mainScreen.scale;
    __block CNDIconServicesConsumerHookReport springBoardHook = {0};
    __block BOOL springBoardRemoteOK = NO;
    BOOL springBoardClosed = NO;
    BOOL springBoardAbandoned = NO;
    RemoteCallSession *springBoardSession = [[RemoteCallSession alloc]
        initWithProcess:@"SpringBoard"
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    if (springBoardSession) {
        @try {
            remote_call_with_session(springBoardSession, ^{
                (void)CNDIconServicesConsumerHookInstallInCurrentSession(
                    "SpringBoard", displayScale, &springBoardHook);
                springBoardRemoteOK = remote_call_current_success();
            });
        } @catch (NSException *exception) {
            NSLog(@"[ICONCONSUMER] SpringBoard exception %@: %@",
                  exception.name, exception.reason);
            springBoardRemoteOK = NO;
        }
        if ([springBoardSession hasLocalState] && springBoardRemoteOK) {
            (void)[springBoardSession destroyRemoteCall];
            springBoardClosed = ![springBoardSession hasLocalState];
        }
        if ([springBoardSession hasLocalState]) {
            [springBoardSession abandonRemoteCall];
            springBoardAbandoned = YES;
        } else {
            springBoardClosed = YES;
        }
    }
    BOOL springBoardHookReady = springBoardSession &&
        (springBoardHook.result == CNDIconServicesConsumerHookInstalled ||
         springBoardHook.result ==
            CNDIconServicesConsumerHookAlreadyInstalled) &&
        springBoardRemoteOK && springBoardClosed &&
        !springBoardAbandoned && springBoardHook.methodsReadbackVerified;
    journal[@"springBoardConsumer"] =
        CNDIconServicesConsumerHookReportDictionary(&springBoardHook);
    if (!springBoardHookReady) {
        (void)cnd_intercept_store_journal(nil);
        return cnd_intercept_result(
            NO, @"springboard-consumer",
            @"The marker-aware SpringBoard consumer could not be installed and verified; the persistent store was not changed.",
            @{
                @"springBoardConsumer":
                    CNDIconServicesConsumerHookReportDictionary(
                        &springBoardHook),
                @"springBoardRemoteOK": @(springBoardRemoteOK),
                @"springBoardClosed": @(springBoardClosed),
                @"springBoardAbandoned": @(springBoardAbandoned),
            });
    }
    if (!cnd_intercept_store_journal(journal)) {
        return cnd_intercept_result(NO, @"journal",
            @"The verified SpringBoard consumer state could not be journaled before the store write.", nil);
    }

    RemoteCallSession *session = [[RemoteCallSession alloc]
        initWithProcess:@"Spotlight"
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:10000];
    if (!session) {
        (void)cnd_intercept_store_journal(nil);
        return cnd_intercept_result(NO, @"remote-session",
            @"Could not open Spotlight. Open Spotlight with an eBay result once, re-arm the VM lab backend, and retry.", nil);
    }
    journal[@"sourcePID"] = @(session.pid);
    if (!cnd_intercept_store_journal(journal)) {
        [session abandonRemoteCall];
        return cnd_intercept_result(NO, @"journal",
            @"The source Spotlight identity could not be journaled before the store write.", nil);
    }

    __block ThemerSpotlightPersistentStoreReport report = {0};
    __block CNDIconServicesConsumerHookReport spotlightHook = {0};
    __block BOOL remoteOK = NO;
    @try {
        remote_call_with_session(session, ^{
            CNDIconServicesConsumerHookResult hookResult =
                CNDIconServicesConsumerHookInstallInCurrentSession(
                    "Spotlight", displayScale, &spotlightHook);
            if ((hookResult == CNDIconServicesConsumerHookInstalled ||
                 hookResult ==
                    CNDIconServicesConsumerHookAlreadyInstalled) &&
                spotlightHook.methodsReadbackVerified &&
                remote_call_current_success()) {
                uint64_t pool =
                    themer_spotlight_remote_autorelease_pool_push();
                if (pool) {
                    NSDictionary *images = @{
                        CNDInterceptTarget: themeData
                    };
                    (void)
                        themer_spotlight_persistent_store_publish_in_session(
                            images, CNDInterceptTarget.UTF8String, &report);
                    if (remote_call_current_success()) {
                        themer_spotlight_remote_autorelease_pool_pop(pool);
                    }
                }
            }
            remoteOK = remote_call_current_success();
        });
    } @catch (NSException *exception) {
        NSLog(@"[ICONSTORE] remote exception %@: %@",
              exception.name, exception.reason);
        remoteOK = NO;
    }
    BOOL closed = NO;
    BOOL abandoned = NO;
    if ([session hasLocalState] && remoteOK) {
        (void)[session destroyRemoteCall];
        closed = ![session hasLocalState];
    }
    if ([session hasLocalState]) {
        [session abandonRemoteCall];
        abandoned = YES;
    } else {
        closed = YES;
    }

    snapshotFailure = nil;
    NSDictionary *after = cnd_intercept_bundle_snapshot(&snapshotFailure);
    BOOL filesUnchanged = before && after && [before isEqualToDictionary:after];
#define CND_STORE_TEXT(field) ([NSString stringWithUTF8String:(field)] ?: @"")
    NSDictionary *details = @{
        @"remoteResult": @((int)report.result),
        @"remoteOK": @(remoteOK),
        @"closed": @(closed),
        @"abandoned": @(abandoned),
        @"transportClean": @(report.transportClean),
        @"indexedRecordFound": @(report.indexedRecordFound),
        @"exactGeometry": @(report.exactGeometry),
        @"structuredMarkerSerialized":
            @(report.structuredMarkerSerialized),
        @"backupPersisted": @(report.backupPersisted),
        @"overwriteVerified": @(report.overwriteVerified),
        @"noThemedProcessMutation": @(report.noThemedProcessMutation),
        @"stockLength": @(report.stockLength),
        @"themedLength": @(report.themedLength),
        @"uuid": CND_STORE_TEXT(report.uuid),
        @"storePath": CND_STORE_TEXT(report.storePath),
        @"stockSHA256": CND_STORE_TEXT(report.stockSHA256),
        @"themedSHA256": CND_STORE_TEXT(report.themedSHA256),
        @"reason": CND_STORE_TEXT(report.reason),
        @"filesUnchanged": @(filesUnchanged),
        @"bundleBefore": before ?: @{},
        @"bundleAfter": after ?: @{},
        @"snapshotFailure": snapshotFailure ?: @"",
        @"cacheInvalidationIssued": @NO,
        @"springBoardConsumer":
            CNDIconServicesConsumerHookReportDictionary(&springBoardHook),
        @"springBoardRemoteOK": @(springBoardRemoteOK),
        @"springBoardClosed": @(springBoardClosed),
        @"springBoardAbandoned": @(springBoardAbandoned),
        @"spotlightConsumer":
            CNDIconServicesConsumerHookReportDictionary(&spotlightHook),
    };
#undef CND_STORE_TEXT
    BOOL success = report.result == ThemerSpotlightPersistentStoreReady &&
        remoteOK && closed && !abandoned && filesUnchanged &&
        report.backupPersisted && report.overwriteVerified &&
        report.noThemedProcessMutation && report.structuredMarkerSerialized &&
        springBoardHookReady &&
        (spotlightHook.result == CNDIconServicesConsumerHookInstalled ||
         spotlightHook.result ==
            CNDIconServicesConsumerHookAlreadyInstalled) &&
        spotlightHook.methodsReadbackVerified;
    if (success) {
        journal[@"phase"] = @"active";
        journal[@"report"] = details;
        journal[@"completedAt"] = @([NSDate.date timeIntervalSince1970]);
        success = cnd_intercept_store_journal(journal);
    } else if (themer_spotlight_persistent_store_has_recovery()) {
        journal[@"phase"] = @"recovery-required";
        journal[@"report"] = details;
        (void)cnd_intercept_store_journal(journal);
    } else {
        (void)cnd_intercept_store_journal(nil);
    }
    return cnd_intercept_result(
        success,
        success ? @"active" : @"persistent-store-publish",
        success
            ? @"The marker-aware consumer is installed in SpringBoard and Spotlight, and the exact indexed store unit contains the verified structured icon response. Close and reopen Spotlight for the visual check."
            : @"The consumer install or persistent-store publication did not satisfy every ABI, execution, method-readback, backup, overwrite, immutable-control, and teardown check.",
        details);
#endif
}

NSDictionary<NSString *, id> *CNDIconServicesInterceptProofRestore(void)
{
    NSDictionary *existing = cnd_intercept_journal();
    NSInteger version = [existing[@"version"] integerValue];
    BOOL hadStoreRecovery =
        themer_spotlight_persistent_store_has_recovery();
    NSDictionary *remainingConsumers = nil;
    BOOL consumerJournalChecked =
        cnd_intercept_prune_exited_retired_consumers(
            &remainingConsumers);
    if (!consumerJournalChecked) {
        return cnd_intercept_result(
            NO, @"retired-consumer-journal",
            @"The retired consumer journal could not be read back exactly; no target process was contacted and recovery state was retained.",
            @{ @"consumerRemoteCallAttempted": @NO });
    }

    BOOL retiredConsumerMayStillBeLive = remainingConsumers.count > 0;
    if (version == 4 || version == 5 || version == 6) {
        if (version < 6 && retiredConsumerMayStillBeLive) {
            return cnd_intercept_result(
                NO, @"retired-consumer-restart-required",
                @"A retired SpringBoard or Spotlight payload may still belong to a live process. Restart that process before clearing the independent publisher journal; no consumer RemoteCall was attempted.",
                @{
                    @"retiredConsumerMappings": remainingConsumers,
                    @"consumerRemoteCallAttempted": @NO,
                });
        }

        NSDictionary *publication =
            [existing[@"publication"] isKindOfClass:NSDictionary.class]
                ? existing[@"publication"] : @{};

        /* A publication that never constructed or returned a replacement has
         * no themed state to undo.  A returned replacement is not classified
         * from failed observation alone: it may have reached a consumer- or
         * store-visible path even when our readback could not resolve it. */
        NSString *phase = [existing[@"phase"] isKindOfClass:NSString.class]
            ? existing[@"phase"] : @"";
        BOOL cleanPublicationExit =
            [publication[@"mappingCleaned"] boolValue] &&
            [publication[@"hookRestored"] boolValue] &&
            ![publication[@"hookStillInstalledAtCleanup"] boolValue] &&
            [publication[@"remoteOK"] boolValue] &&
            [publication[@"closed"] boolValue] &&
            ![publication[@"abandoned"] boolValue];
        BOOL stockOnlyNoOp = cleanPublicationExit &&
            ![publication[@"replacementCreated"] boolValue] &&
            ![publication[@"replacementReturned"] boolValue] &&
            [publication[@"persistentStoreDataLength"]
                unsignedLongLongValue] == 0;
        BOOL localOnlyRecovery =
            [phase isEqualToString:@"recovery-required"] &&
            [existing[@"filesUnchanged"] boolValue] &&
            publication.count > 0 &&
            stockOnlyNoOp &&
            !hadStoreRecovery;
        if (localOnlyRecovery) {
            BOOL journalCleared = cnd_intercept_store_journal(nil);
            return cnd_intercept_result(
                journalCleared,
                journalCleared ? @"restored-stock-only-noop"
                               : @"local-only-journal-clear",
                journalCleared
                    ? @"The recorded publication was conclusively stock-only: no replacement was created or returned, no store unit was written, the temporary hook and mapping were removed, the channel closed, and the application files remained unchanged. The obsolete recovery journal was cleared without contacting IconServices, SpringBoard, or Spotlight."
                    : @"The recorded publication had no persistent remote mutation, but kslop could not verify removal of its obsolete local recovery journal.",
                @{
                    @"stockOnlyNoOp": @(stockOnlyNoOp),
                    @"journalCleared": @(journalCleared),
                    @"storeRecoveryWasPresent": @(hadStoreRecovery),
                    @"consumerRemoteCallAttempted": @NO,
                    @"springBoardRemoteCallAttempted": @NO,
                    @"spotlightRemoteCallAttempted": @NO,
                    @"iconServicesRemoteCallAttempted": @NO,
                    @"applicationBundleMutationAttempted": @NO,
                    @"residentPresentationMappings":
                        remainingConsumers ?: @{},
                    @"presentationMappingsInertWithoutMarker":
                        @(version >= 6),
                });
        }

        BOOL mappingCleaned = [publication[@"mappingCleaned"] boolValue];
        int agentPID = [publication[@"agentPID"] intValue];
        errno = 0;
        BOOL recordedAgentExited = agentPID > 1 &&
            kill(agentPID, 0) != 0 && errno == ESRCH;
        uint64_t unrecordedLiveAgent = !mappingCleaned && agentPID <= 1
            ? proc_find_by_name("iconservicesagent") : 0;
        BOOL recordedAgentMayStillBeLive = agentPID > 1 &&
            !recordedAgentExited;
        if (!mappingCleaned &&
            (recordedAgentMayStillBeLive || unrecordedLiveAgent)) {
            return cnd_intercept_result(
                NO, @"publisher-agent-restart-required",
                @"The one-shot publisher mapping was not proven removed and the relevant iconservicesagent may still be live. Let that short-lived agent exit, then run Restore again; SpringBoard and Spotlight will not be contacted.",
                @{
                    @"agentPID": @(agentPID),
                    @"unrecordedLiveAgentProc": @(unrecordedLiveAgent),
                    @"mappingCleaned": @NO,
                    @"consumerRemoteCallAttempted": @NO,
                });
        }

        NSString *snapshotFailure = nil;
        NSDictionary *before = cnd_intercept_bundle_snapshot(
            &snapshotFailure);
        if (!before && remote_call_lab_prepare_bundle_access()) {
            snapshotFailure = nil;
            before = cnd_intercept_bundle_snapshot(&snapshotFailure);
        }
        NSDictionary *baseline =
            [existing[@"baseline"] isKindOfClass:NSDictionary.class]
                ? existing[@"baseline"] : nil;
        NSString *savedPath =
            [existing[@"bundlePath"] isKindOfClass:NSString.class]
                ? existing[@"bundlePath"] : nil;
        if (!before || !baseline ||
            ![savedPath isEqualToString:before[@"bundlePath"]] ||
            ![baseline isEqualToDictionary:before]) {
            return cnd_intercept_result(
                NO, @"immutable-control-drift",
                @"eBay's installation or immutable source files changed; the publisher recovery journal was retained.",
                @{
                    @"snapshotFailure": snapshotFailure ?: @"",
                    @"consumerRemoteCallAttempted": @NO,
                });
        }

        NSDictionary *restoration =
            CNDIconServicesPublisherRestoreStock(CNDInterceptTarget);
        NSDictionary *forced =
            [restoration[@"stockResponse"]
                isKindOfClass:NSDictionary.class]
                ? restoration[@"stockResponse"] : @{};
        NSDictionary *readback =
            [restoration[@"agentCacheResponse"]
                isKindOfClass:NSDictionary.class]
                ? restoration[@"agentCacheResponse"] : @{};
        NSString *themedHash =
            [existing[@"structuredImageSHA256"]
                isKindOfClass:NSString.class]
                ? existing[@"structuredImageSHA256"] : @"";
        BOOL forcedStock = [restoration[@"ok"] boolValue] &&
            [restoration[@"stockCaptured"] boolValue] && forced.count &&
            ![forced[@"themeMarkerPresent"] boolValue] &&
            ![forced[@"dataSHA256"] isEqualToString:themedHash];
        BOOL persistentStock = forcedStock &&
            [restoration[@"agentCacheReadbackVerified"] boolValue] &&
            [restoration[@"persistentStoreReadbackVerified"] boolValue] &&
            readback.count &&
            ![readback[@"themeMarkerPresent"] boolValue] &&
            [readback[@"uuid"] isEqualToString:forced[@"uuid"]] &&
            [readback[@"dataSHA256"]
                isEqualToString:forced[@"dataSHA256"]] &&
            [readback[@"validationTokenSHA256"]
                isEqualToString:forced[@"validationTokenSHA256"]] &&
            [readback[@"dataLength"] isEqual:forced[@"dataLength"]];
        BOOL invalidated = persistentStock && cnd_intercept_invalidate();
        BOOL journalCleared = invalidated &&
            cnd_intercept_store_journal(nil);
        NSDictionary *details = @{
            @"stockRegenerated": @(forcedStock),
            @"persistentStockReadbackVerified": @(persistentStock),
            @"forcedResponse": forced ?: @{},
            @"readbackResponse": readback ?: @{},
            @"publisherRestore": restoration ?: @{},
            @"cacheInvalidationIssued": @(invalidated),
            @"journalCleared": @(journalCleared),
            @"storeRestored": @(persistentStock),
            @"recoveryCleared": @(journalCleared),
            @"consumerRemoteCallAttempted": @NO,
            @"springBoardRemoteCallAttempted": @NO,
            @"spotlightRemoteCallAttempted": @NO,
            @"applicationBundleMutationAttempted": @NO,
            @"residentPresentationMappings": remainingConsumers ?: @{},
            @"presentationMappingsInertWithoutMarker": @(version >= 6),
        };
        return cnd_intercept_result(
            journalCleared,
            journalCleared ? @"restored" : @"stock-regeneration",
            journalCleared
                ? (version >= 6
                    ? @"Stock IconServices generation, agent-cache readback, and exact indexed .isdata readback matched. Cache invalidation was issued; any live marker-aware presentation mappings are now inert and may remain until those processes exit."
                    : @"Stock IconServices generation, agent-cache readback, and exact indexed .isdata readback matched; cache invalidation was issued and the publisher journal was cleared.")
                : restoration[@"message"] ?:
                  @"Stock regeneration or its agent-cache/.isdata readback did not verify; the recovery journal was retained.",
            details);
    }
    if (version < 3) {
        BOOL storeRestored = !hadStoreRecovery ||
            themer_spotlight_persistent_store_restore();
        BOOL storeRecoveryCleared =
            !themer_spotlight_persistent_store_has_recovery();
        if (retiredConsumerMayStillBeLive) {
            return cnd_intercept_result(
                NO, @"retired-consumer-restart-required",
                @"Stock store recovery was attempted, but a retired SpringBoard or Spotlight consumer mapping may still belong to a live process. Restart the recorded process and run Restore again; kslop will not reopen it with RemoteCall.",
                @{
                    @"storeRestored": @(storeRestored),
                    @"recoveryCleared": @(storeRecoveryCleared),
                    @"retiredConsumerMappings": remainingConsumers,
                    @"consumerRemoteCallAttempted": @NO,
                });
        }

        if (version == 0) {
            BOOL restored = storeRestored && storeRecoveryCleared;
            return cnd_intercept_result(
                restored,
                restored ? @"restored-orphaned-store-journal"
                         : @"persistent-store-restore",
                restored
                    ? @"Any orphaned stock store-unit backup was restored without contacting SpringBoard or Spotlight."
                    : @"The orphaned persistent-store recovery metadata was retained because exact restoration did not verify.",
                @{
                    @"storeRestored": @(storeRestored),
                    @"recoveryCleared": @(storeRecoveryCleared),
                    @"consumerRemoteCallAttempted": @NO,
                });
        }

        int savedPID = [existing[@"pid"] intValue];
        errno = 0;
        BOOL recordedProcessExited = savedPID > 1 &&
            kill(savedPID, 0) != 0 && errno == ESRCH;
        if (!recordedProcessExited) {
            return cnd_intercept_result(
                NO, @"legacy-process-restart-required",
                @"The legacy process-local proof cannot be safely removed from a possibly live process without its missing process-birth identity. Restart that process and run Restore again; no RemoteCall was attempted.",
                @{
                    @"pid": @(savedPID),
                    @"host": existing[@"host"] ?: @"unknown",
                    @"storeRestored": @(storeRestored),
                    @"consumerRemoteCallAttempted": @NO,
                });
        }

        BOOL invalidated = storeRestored && storeRecoveryCleared &&
            cnd_intercept_invalidate();
        BOOL journalCleared = invalidated &&
            cnd_intercept_store_journal(nil);
        return cnd_intercept_result(
            journalCleared,
            journalCleared ? @"restored-after-process-exit"
                           : @"legacy-process-recovery",
            journalCleared
                ? @"The recorded legacy process exited, stock store recovery verified, cache invalidation was issued, and the old journal was cleared without RemoteCall."
                : @"Legacy recovery could not be completed exactly; its journal was retained.",
            @{
                @"storeRestored": @(storeRestored),
                @"recoveryCleared": @(storeRecoveryCleared),
                @"cacheInvalidationIssued": @(invalidated),
                @"journalCleared": @(journalCleared),
                @"consumerRemoteCallAttempted": @NO,
            });
    }
    if (!CNDIconServicesInterceptProofIsActive() &&
        !hadStoreRecovery) {
        return cnd_intercept_result(YES, @"already-restored",
            @"No persistent IconServices store proof is active.", nil);
    }

    NSString *snapshotFailure = nil;
    NSDictionary *before = cnd_intercept_bundle_snapshot(&snapshotFailure);
    NSString *savedPath = [existing[@"bundlePath"] isKindOfClass:NSString.class]
        ? existing[@"bundlePath"] : nil;
    if (!before || savedPath.length == 0 ||
        ![savedPath isEqualToString:before[@"bundlePath"]]) {
        return cnd_intercept_result(NO, @"bundle-path-drift",
            @"eBay's installation identity changed; the store backup was retained.",
            @{ @"snapshotFailure": snapshotFailure ?: @"" });
    }

    BOOL restored = !hadStoreRecovery ||
        themer_spotlight_persistent_store_restore();
    BOOL recoveryCleared =
        !themer_spotlight_persistent_store_has_recovery();
    BOOL invalidated = restored && recoveryCleared &&
        cnd_intercept_invalidate();
    if (retiredConsumerMayStillBeLive) {
        return cnd_intercept_result(
            NO, @"retired-consumer-restart-required",
            @"The exact stock store bytes are restored, but a retired SpringBoard or Spotlight consumer mapping may still belong to a live process. Restart the recorded process and run Restore again; kslop will not reopen it with RemoteCall.",
            @{
                @"storeRestored": @(restored),
                @"recoveryCleared": @(recoveryCleared),
                @"cacheInvalidationIssued": @(invalidated),
                @"retiredConsumerMappings": remainingConsumers,
                @"consumerRemoteCallAttempted": @NO,
            });
    }

    BOOL journalCleared = restored && recoveryCleared && invalidated &&
        cnd_intercept_store_journal(nil);
    NSDictionary *details = @{
        @"storeRestored": @(restored),
        @"recoveryCleared": @(recoveryCleared),
        @"journalCleared": @(journalCleared),
        @"filesUnchanged": @YES,
        @"cacheInvalidationIssued": @(invalidated),
        @"consumerRemoteCallAttempted": @NO,
    };
    return cnd_intercept_result(
        journalCleared,
        journalCleared ? @"restored" : @"persistent-store-restore",
        journalCleared
            ? @"The exact stock IconServices store-unit bytes were restored, cache invalidation was issued, and all persistent proof recovery metadata was cleared without contacting SpringBoard or Spotlight."
            : @"The stock store-unit restore did not verify; the recovery journal was retained.",
        details);
}
