#import "CNDLaunchServicesRegistration.h"

#import "../TaskRop/RemoteCall.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/kutils.h"
#import "../tweaks/remote_objc.h"
#import "../utils/sandbox.h"

#import <dlfcn.h>
#import <fcntl.h>
#import <xpc/xpc.h>
#import <unistd.h>

static NSString * const CNDLSInstalldProcess = @"installd";
static const char * const CNDLSInstalldService = "com.apple.mobile.installd";
static const char * const CNDLSMachLookupClass =
    "com.apple.security.exception.mach-lookup.global-name";
static const char * const CNDLSRootFileClass =
    "com.apple.app-sandbox.read-write";
static const char * const CNDLSRootFilePath = "/";
static const NSUInteger CNDLSMaxRegistrationPlistBytes = 4 * 1024 * 1024;
static const NSUInteger CNDLSMaxInstalledApplicationArchiveBytes = 32 * 1024 * 1024;
// Keep the RemoteCall operation finite even on a malformed or unexpectedly
// broad LaunchServices result. A normal iPhone installation is far below this
// bound, while the archive-size check below provides a second hard limit.
static const NSUInteger CNDLSMaxInstalledApplicationProxies = 2048;
static const int CNDLSInstalldBootstrapTimeoutMS = 20000;
static NSString * const CNDLSRetainedSessionKey =
    @"com.zeroxjf.cyanide.installd-retained-session";
static NSString * const CNDLSRetainedWakeKey =
    @"com.zeroxjf.cyanide.installd-retained-wake";
static NSString * const CNDLSBatchSessionKey =
    @"com.zeroxjf.cyanide.installd-batch-session";
static NSString * const CNDLSPendingInstalldRootTokenKey =
    @"com.zeroxjf.cyanide.installd-pending-root-token";

typedef xpc_connection_t (*CNDXPCMachServiceCreate)(
    const char *, dispatch_queue_t, uint64_t);

static NSDictionary<NSString *, id> *cnd_ls_result(BOOL ok,
                                                    NSString *stage,
                                                    NSString *message,
                                                    NSDictionary *details)
{
    NSMutableDictionary<NSString *, id> *result = details
        ? [details mutableCopy] : [NSMutableDictionary dictionary];
    // Set these last so nested operation details can never replace the result
    // envelope's authoritative status.
    result[@"ok"] = @(ok);
    result[@"stage"] = stage ?: @"unknown";
    result[@"message"] = message ?: @"";
    return result;
}

static uint64_t cnd_ls_installd_proc(void)
{
    uint64_t proc = proc_find_by_name(CNDLSInstalldProcess.UTF8String);
    return (proc == 0 || proc == UINT64_MAX) ? 0 : proc;
}

static BOOL cnd_ls_session_healthy(RemoteCallSession *session)
{
    if (!session) return NO;
    __block BOOL healthy = NO;
    remote_call_with_session(session, ^{
        healthy = remote_call_current_success();
    });
    return healthy;
}

static NSDictionary<NSString *, id> *cnd_ls_finalize_session(
    RemoteCallSession *session)
{
    if (!session) {
        return @{
            @"pid": @0,
            @"transport": @"not-created",
            @"teardown": @0,
            @"teardownMode": @"none",
            @"localStateRemaining": @NO,
        };
    }

    int pid = session.pid;
    BOOL transportHealthy = cnd_ls_session_healthy(session);
    int teardown = 0;
    NSString *teardownMode = @"none";

    if ([session hasLocalState]) {
        if (transportHealthy) {
            teardownMode = @"destroy";
            teardown = [session destroyRemoteCall];
        } else {
            // A failed transport can represent a vanished remote task. Avoid
            // making another remote call during teardown, but discard every
            // local exception-port/session resource.
            teardownMode = @"abandon";
            teardown = -1;
            [session abandonRemoteCall];
        }
    }

    BOOL localStateRemaining = [session hasLocalState];
    if (localStateRemaining) {
        [session abandonRemoteCall];
        localStateRemaining = [session hasLocalState];
        if (teardown == 0) teardown = -2;
        teardownMode = @"abandon-after-destroy";
    }

    return @{
        @"pid": @(pid),
        @"transport": transportHealthy ? @"healthy" : @"failed",
        @"teardown": @(teardown),
        @"teardownMode": teardownMode,
        @"localStateRemaining": @(localStateRemaining),
    };
}

static BOOL cnd_ls_finalization_succeeded(NSDictionary<NSString *, id> *details)
{
    return [details[@"transport"] isEqual:@"healthy"] &&
        [details[@"teardown"] intValue] == 0 &&
        ![details[@"localStateRemaining"] boolValue];
}

static void cnd_ls_clear_pending_installd_root_token(void)
{
    [NSThread.currentThread.threadDictionary
        removeObjectForKey:CNDLSPendingInstalldRootTokenKey];
}

static BOOL cnd_ls_consume_pending_root_token_in_installd(
    RemoteCallSession *installd, NSDictionary<NSString *, id> **detailsOut)
{
    NSMutableDictionary *threadState = NSThread.currentThread.threadDictionary;
    NSData *token = threadState[CNDLSPendingInstalldRootTokenKey];
    [threadState removeObjectForKey:CNDLSPendingInstalldRootTokenKey];

    NSMutableDictionary *details = [@{
        @"installdRootFileTokenIssued": @([token isKindOfClass:NSData.class] &&
                                            token.length > 1),
        @"installdRootFileTokenConsumed": @NO,
        @"installdRootFileTokenHandle": @(-1),
    } mutableCopy];
    if (![token isKindOfClass:NSData.class] || token.length < 2 ||
        ((const uint8_t *)token.bytes)[token.length - 1] != 0) {
        details[@"installdRootFileTokenFailure"] =
            @"no fresh launchd-issued token was pending for this session";
        if (detailsOut) *detailsOut = cnd_ls_result(NO,
            @"token-unavailable",
            details[@"installdRootFileTokenFailure"], details);
        return NO;
    }

    uint64_t remoteToken = r_session_alloc_str(
        installd, (const char *)token.bytes);
    if (!remoteToken || !cnd_ls_session_healthy(installd)) {
        details[@"installdRootFileTokenFailure"] =
            @"could not copy the fresh file token into installd";
        if (detailsOut) *detailsOut = cnd_ls_result(NO,
            @"remote-token-copy",
            details[@"installdRootFileTokenFailure"], details);
        return NO;
    }

    int64_t handle = (int64_t)r_session_dlsym_call(
        installd, 5, "sandbox_extension_consume",
        remoteToken, 0, 0, 0, 0, 0, 0, 0);
    BOOL healthy = cnd_ls_session_healthy(installd);
    if (healthy) r_session_free(installd, remoteToken);
    BOOL consumed = handle >= 0 && healthy;
    details[@"installdRootFileTokenConsumed"] = @(consumed);
    details[@"installdRootFileTokenHandle"] = @(handle);
    if (!consumed) {
        details[@"installdRootFileTokenFailure"] = healthy
            ? [NSString stringWithFormat:
                @"sandbox_extension_consume inside installd returned %lld",
                (long long)handle]
            : @"installd transport failed while consuming the file token";
    }
    if (detailsOut) *detailsOut = cnd_ls_result(consumed,
        consumed ? @"consumed" : @"remote-token-consume",
        consumed
            ? @"installd consumed its separately issued fresh root file token"
            : details[@"installdRootFileTokenFailure"],
        details);
    return consumed;
}

static RemoteCallSession *cnd_ls_current_retained_session(void)
{
    id value = NSThread.currentThread.threadDictionary[CNDLSRetainedSessionKey];
    return [value isKindOfClass:RemoteCallSession.class] ? value : nil;
}

static NSDictionary<NSString *, id> *cnd_ls_current_retained_wake(void)
{
    id value = NSThread.currentThread.threadDictionary[CNDLSRetainedWakeKey];
    return [value isKindOfClass:NSDictionary.class] ? value : @{};
}

static BOOL cnd_ls_retain_session_for_current_thread(
    RemoteCallSession *session, NSDictionary<NSString *, id> *wake)
{
    if (!session || cnd_ls_current_retained_session()) return NO;
    NSMutableDictionary *threadState = NSThread.currentThread.threadDictionary;
    threadState[CNDLSRetainedSessionKey] = session;
    threadState[CNDLSRetainedWakeKey] = wake ?: @{};
    return YES;
}

NSDictionary<NSString *, id> *CNDLaunchServicesFinishRetainedInstalldSession(void)
{
    cnd_ls_clear_pending_installd_root_token();
    NSMutableDictionary *threadState = NSThread.currentThread.threadDictionary;
    RemoteCallSession *session = cnd_ls_current_retained_session();
    if (session && [threadState[CNDLSBatchSessionKey] boolValue]) {
        BOOL healthy = cnd_ls_session_healthy(session);
        return cnd_ls_result(healthy,
            healthy ? @"batch-session-retained" : @"batch-session-unhealthy",
            healthy
                ? @"the bounded batch still owns the healthy installd session"
                : @"the bounded batch installd session became unhealthy", @{
                    @"pid": @(session.pid),
                    @"transport": healthy ? @"healthy" : @"failed",
                    @"teardown": @0,
                    @"teardownMode": @"batch-retained",
                    @"localStateRemaining": @YES,
                });
    }
    [threadState removeObjectForKey:CNDLSRetainedSessionKey];
    [threadState removeObjectForKey:CNDLSRetainedWakeKey];
    if (!session) {
        return cnd_ls_result(YES, @"no-retained-session",
            @"no retained installd session needed finalization", @{
                @"pid": @0,
                @"transport": @"not-created",
                @"teardown": @0,
                @"teardownMode": @"none",
                @"localStateRemaining": @NO,
            });
    }
    NSDictionary<NSString *, id> *finalization =
        cnd_ls_finalize_session(session);
    BOOL ok = cnd_ls_finalization_succeeded(finalization);
    return cnd_ls_result(ok,
        ok ? @"retained-session-finished" : @"retained-session-finalization",
        ok
            ? @"the retained installd RemoteCall session closed cleanly"
            : @"the retained installd RemoteCall session did not close cleanly",
        finalization);
}

BOOL CNDLaunchServicesBatchInstalldSessionIsHealthy(void)
{
    RemoteCallSession *session = cnd_ls_current_retained_session();
    return [NSThread.currentThread.threadDictionary[CNDLSBatchSessionKey] boolValue] &&
        cnd_ls_session_healthy(session);
}

NSDictionary<NSString *, id> *
CNDLaunchServicesFinishBatchInstalldSession(void)
{
    [NSThread.currentThread.threadDictionary removeObjectForKey:CNDLSBatchSessionKey];
    return CNDLaunchServicesFinishRetainedInstalldSession();
}

static BOOL cnd_ls_is_direct_bundle_icon_path(NSString *path)
{
    unichar nul = 0;
    NSString *nulString = [NSString stringWithCharacters:&nul length:1];
    if (![path isKindOfClass:NSString.class] || path.length == 0 ||
        [path rangeOfString:nulString].location != NSNotFound) return NO;

    NSString *standardized = path.stringByStandardizingPath;
    if (![standardized isEqual:path]) return NO;
    NSArray<NSString *> *roots = @[
        @"/var/containers/Bundle/Application/",
        @"/private/var/containers/Bundle/Application/",
    ];
    NSString *relative = nil;
    for (NSString *root in roots) {
        if ([standardized hasPrefix:root]) {
            relative = [standardized substringFromIndex:root.length];
            break;
        }
    }
    NSArray<NSString *> *components = relative.pathComponents;
    if (components.count != 3) return NO;
    NSString *uuid = components[0];
    NSString *bundle = components[1];
    NSString *leaf = components[2];
    return uuid.length > 0 &&
        [bundle.pathExtension.lowercaseString isEqual:@"app"] &&
        leaf.length > 4 &&
        [leaf.pathExtension.lowercaseString isEqual:@"png"] &&
        ![leaf isEqual:@"."] && ![leaf isEqual:@".."] &&
        [leaf rangeOfString:@"/"].location == NSNotFound;
}

static NSDictionary<NSString *, id> *
cnd_ls_consume_installd_lookup_extension(void)
{
    // A token is valid for one attempted installd session only. Never let a
    // failed or interrupted bootstrap leak a token into a later session.
    cnd_ls_clear_pending_installd_root_token();

    RemoteCallSession *launchd = [[RemoteCallSession alloc]
        initWithProcess:@"launchd"
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:15000];
    if (!launchd) {
        RemoteCallInitFailure failure = remote_call_last_init_failure();
        return cnd_ls_result(NO, @"launchd-session",
            [NSString stringWithFormat:@"launchd RemoteCall failed: %s",
             remote_call_init_failure_description(failure)], @{
                @"pid": @(remote_call_last_init_failure_pid()),
                @"transport": @"not-created",
                @"teardown": @0,
                @"teardownMode": @"init-cleanup",
                @"localStateRemaining": @NO,
            });
    }

    NSString *operationStage = nil;
    NSString *operationMessage = nil;
    BOOL consumed = NO;
    BOOL rootFileConsumed = NO;
    BOOL installdRootFileTokenIssued = NO;
    NSData *installdRootFileToken = nil;
    uint64_t className = r_session_alloc_str(launchd, CNDLSMachLookupClass);
    uint64_t serviceName = r_session_alloc_str(launchd, CNDLSInstalldService);
    uint64_t tokenRemote = 0;
    if (!className || !serviceName) {
        operationStage = @"lookup-token-arguments";
        operationMessage = @"could not allocate the launchd token arguments";
    } else {
        tokenRemote = r_session_dlsym_call(
            launchd, 5, "sandbox_extension_issue_mach",
            className, serviceName, 0, 0, 0, 0, 0, 0);
    }
    if (className) r_session_free(launchd, className);
    if (serviceName) r_session_free(launchd, serviceName);

    if (!operationStage) {
        if (!tokenRemote || !cnd_ls_session_healthy(launchd)) {
            operationStage = @"lookup-token-issue";
            operationMessage = @"launchd could not issue an installd Mach lookup token";
        } else {
            uint64_t tokenLength = r_session_dlsym_call(
                launchd, 5, "strlen", tokenRemote, 0, 0, 0, 0, 0, 0, 0);
            if (tokenLength == 0 || tokenLength >= 0x4000) {
                operationStage = @"lookup-token-length";
                operationMessage = [NSString stringWithFormat:
                    @"launchd returned an invalid token length (%llu)", tokenLength];
            } else {
                NSMutableData *tokenData =
                    [NSMutableData dataWithLength:(NSUInteger)tokenLength + 1];
                if (![launchd remoteRead:tokenRemote
                                      to:tokenData.mutableBytes
                                    size:tokenData.length]) {
                    operationStage = @"lookup-token-copy";
                    operationMessage =
                        @"could not copy the launchd-issued Mach lookup token";
                } else {
                    int64_t handle = sandbox_extension_consume(tokenData.bytes);
                    consumed = handle >= 0;
                    if (!consumed) {
                        operationStage = @"lookup-token-consume";
                        operationMessage = [NSString stringWithFormat:
                            @"sandbox_extension_consume returned %lld",
                            (long long)handle];
                    }
                }
            }
        }
    }

    if (tokenRemote && cnd_ls_session_healthy(launchd)) {
        r_session_free(launchd, tokenRemote);
    }

    /*
     * A saved file-extension token is scoped to the boot/session that issued
     * it.  Icon recovery can legitimately run after a userspace reboot, so
     * acquire a fresh root file token from the same live launchd session used
     * for installd lookup instead of depending on a stale saved token or on a
     * best-effort sandbox structure patch.  This adds no second launchd trap.
     */
    uint64_t rootClassName = 0;
    uint64_t rootPath = 0;
    uint64_t rootTokenRemote = 0;
    uint64_t installdRootTokenRemote = 0;
    if (!operationStage) {
        rootClassName = r_session_alloc_str(launchd, CNDLSRootFileClass);
        rootPath = r_session_alloc_str(launchd, CNDLSRootFilePath);
        if (!rootClassName || !rootPath) {
            operationStage = @"root-file-token-arguments";
            operationMessage = @"could not allocate the launchd root file token arguments";
        } else {
            rootTokenRemote = r_session_dlsym_call(
                launchd, 5, "sandbox_extension_issue_file",
                rootClassName, rootPath, 0, 0, 0, 0, 0, 0);
            if (rootTokenRemote && cnd_ls_session_healthy(launchd)) {
                installdRootTokenRemote = r_session_dlsym_call(
                    launchd, 5, "sandbox_extension_issue_file",
                    rootClassName, rootPath, 0, 0, 0, 0, 0, 0);
            }
        }
    }
    if (rootClassName && cnd_ls_session_healthy(launchd)) {
        r_session_free(launchd, rootClassName);
    }
    if (rootPath && cnd_ls_session_healthy(launchd)) {
        r_session_free(launchd, rootPath);
    }
    if (!operationStage) {
        if (!rootTokenRemote || !installdRootTokenRemote ||
            !cnd_ls_session_healthy(launchd)) {
            operationStage = @"root-file-token-issue";
            operationMessage =
                @"launchd could not issue separate fresh root file tokens for kslop and installd";
        } else {
            uint64_t rootTokenLength = r_session_dlsym_call(
                launchd, 5, "strlen", rootTokenRemote,
                0, 0, 0, 0, 0, 0, 0);
            if (rootTokenLength == 0 || rootTokenLength >= 0x4000) {
                operationStage = @"root-file-token-length";
                operationMessage = [NSString stringWithFormat:
                    @"launchd returned an invalid root file token length (%llu)",
                    rootTokenLength];
            } else {
                NSMutableData *rootTokenData = [NSMutableData
                    dataWithLength:(NSUInteger)rootTokenLength + 1];
                if (![launchd remoteRead:rootTokenRemote
                                      to:rootTokenData.mutableBytes
                                    size:rootTokenData.length]) {
                    operationStage = @"root-file-token-copy";
                    operationMessage =
                        @"could not copy the launchd-issued root file token";
                } else {
                    int64_t rootHandle =
                        sandbox_extension_consume(rootTokenData.bytes);
                    rootFileConsumed = rootHandle >= 0;
                    if (!rootFileConsumed) {
                        operationStage = @"root-file-token-consume";
                        operationMessage = [NSString stringWithFormat:
                            @"consuming the fresh root file token returned %lld",
                            (long long)rootHandle];
                    }
                }
            }
        }
    }
    if (!operationStage) {
        uint64_t installdTokenLength = r_session_dlsym_call(
            launchd, 5, "strlen", installdRootTokenRemote,
            0, 0, 0, 0, 0, 0, 0);
        if (installdTokenLength == 0 || installdTokenLength >= 0x4000) {
            operationStage = @"installd-root-file-token-length";
            operationMessage = [NSString stringWithFormat:
                @"launchd returned an invalid installd file token length (%llu)",
                installdTokenLength];
        } else {
            NSMutableData *tokenData = [NSMutableData
                dataWithLength:(NSUInteger)installdTokenLength + 1];
            if (![launchd remoteRead:installdRootTokenRemote
                                  to:tokenData.mutableBytes
                                size:tokenData.length]) {
                operationStage = @"installd-root-file-token-copy";
                operationMessage =
                    @"could not copy the fresh installd file token from launchd";
            } else {
                installdRootFileToken = [tokenData copy];
                installdRootFileTokenIssued = YES;
            }
        }
    }
    if (rootTokenRemote && cnd_ls_session_healthy(launchd)) {
        r_session_free(launchd, rootTokenRemote);
    }
    if (installdRootTokenRemote && cnd_ls_session_healthy(launchd)) {
        r_session_free(launchd, installdRootTokenRemote);
    }

    NSDictionary<NSString *, id> *finalization =
        cnd_ls_finalize_session(launchd);
    NSMutableDictionary<NSString *, id> *details = [finalization mutableCopy];
    details[@"tokenConsumed"] = @(consumed);
    details[@"rootFileTokenConsumed"] = @(rootFileConsumed);
    details[@"installdRootFileTokenIssued"] =
        @(installdRootFileTokenIssued);

    if (operationStage) {
        return cnd_ls_result(NO, operationStage,
            operationMessage ?: @"could not acquire installd Mach lookup access",
            details);
    }
    if (!cnd_ls_finalization_succeeded(finalization)) {
        return cnd_ls_result(NO, @"lookup-session-finalization",
            @"the Mach lookup/root file tokens were consumed, but the launchd RemoteCall session did not close cleanly",
            details);
    }
    if (!installdRootFileTokenIssued || installdRootFileToken.length < 2) {
        return cnd_ls_result(NO, @"installd-root-file-token-unavailable",
            @"the launchd session closed without a usable fresh file token for installd",
            details);
    }
    NSThread.currentThread.threadDictionary[
        CNDLSPendingInstalldRootTokenKey] = installdRootFileToken;
    return cnd_ls_result(YES, @"lookup-ready",
        @"the installd Mach lookup and kslop root file extension were consumed, and a separate fresh file token is pending for installd",
        details);
}

static uint64_t cnd_ls_wait_for_installd(unsigned int timeoutMilliseconds)
{
    const useconds_t interval = 50000;
    unsigned int remaining = timeoutMilliseconds;
    do {
        uint64_t proc = cnd_ls_installd_proc();
        if (proc) return proc;
        if (remaining == 0) break;
        usleep(interval);
        remaining = remaining > interval / 1000
            ? remaining - (unsigned int)(interval / 1000) : 0;
    } while (YES);
    return 0;
}

NSDictionary<NSString *, id> *CNDLaunchServicesEnsureInstalldRunning(void)
{
    if (remote_call_lab_backend_opted_in()) {
        cnd_ls_clear_pending_installd_root_token();
        return cnd_ls_result(YES, @"lab-direct-ready",
            @"the explicit vPhone lab backend will connect directly to the root-injected installd endpoint",
            @{
                @"proc": @0,
                @"wakeMethod": @"root-harness",
                @"lookup": cnd_ls_result(YES, @"lab-bypass",
                    @"launchd Mach lookup and sandbox-extension minting are unnecessary for the authenticated root-harness endpoint",
                    @{
                        @"tokenConsumed": @NO,
                        @"rootFileTokenConsumed": @NO,
                        @"installdRootFileTokenIssued": @NO,
                    }),
            });
    }

    // No process traversal or RemoteCall initialization is allowed before this
    // succeeds. The production path never supplies a synthetic/lab KRW source.
    if (!kexploit_krw_ready()) {
        return cnd_ls_result(NO, @"krw-prerequisite",
            @"kslop must establish a live kernel read/write session before contacting installd",
            nil);
    }

    uint64_t existing = cnd_ls_installd_proc();

    // The lookup extension is also required when installd is already resident:
    // the registration path keeps an empty XPC prompt active while RemoteCall
    // waits for an idle daemon thread to return from its kernel wait.
    NSDictionary<NSString *, id> *lookup =
        cnd_ls_consume_installd_lookup_extension();
    if (![lookup[@"ok"] boolValue]) {
        return cnd_ls_result(NO, @"mach-lookup",
            @"could not acquire installd Mach lookup access", @{
                @"lookup": lookup,
            });
    }

    __block xpc_object_t firstEvent = nil;
    dispatch_semaphore_t eventSemaphore = dispatch_semaphore_create(0);
    CNDXPCMachServiceCreate createMachService =
        (CNDXPCMachServiceCreate)dlsym(
            RTLD_DEFAULT, "xpc_connection_create_mach_service");
    xpc_connection_t connection = createMachService
        ? createMachService(CNDLSInstalldService,
            dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), 0)
        : nil;
    if (!connection) {
        return cnd_ls_result(NO, @"wake-connection",
            createMachService
                ? @"xpc_connection_create_mach_service returned null"
                : @"xpc_connection_create_mach_service is unavailable", @{
                    @"lookup": lookup,
                });
    }

    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        firstEvent = event;
        dispatch_semaphore_signal(eventSemaphore);
    });
    xpc_connection_resume(connection);
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_connection_send_message(connection, message);

    uint64_t proc = existing ?: cnd_ls_wait_for_installd(3000);
    if (!proc) {
        (void)dispatch_semaphore_wait(eventSemaphore,
            dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC));
        proc = cnd_ls_installd_proc();
    }
    xpc_connection_cancel(connection);

    if (!proc) {
        char *eventDescription = firstEvent
            ? xpc_copy_description(firstEvent) : NULL;
        NSString *messageText = eventDescription
            ? [NSString stringWithFormat:@"installd did not become resident: %s",
                                         eventDescription]
            : @"installd did not become resident after the wake message";
        free(eventDescription);
        return cnd_ls_result(NO, @"wake-timeout", messageText, @{
            @"lookup": lookup,
        });
    }

    return cnd_ls_result(YES, existing ? @"resident-ready" : @"woken",
        existing
            ? @"stock installd is resident and its Mach lookup access is ready"
            : @"stock installd is running", @{
        @"proc": @(proc),
        @"wakeMethod": existing ? @"xpc-prompt" : @"xpc",
        @"lookup": lookup,
    });
}

static BOOL cnd_ls_remote_load_coreservices(RemoteCallSession *session)
{
    static const char * const candidates[] = {
        "/System/Library/Frameworks/CoreServices.framework/CoreServices",
        "/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices",
    };
    if (r_session_class(session, "LSApplicationWorkspace")) return YES;

    for (NSUInteger i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        uint64_t path = r_session_alloc_str(session, candidates[i]);
        uint64_t handle = path ? r_session_dlsym_call(
            session, 5, "dlopen", path, RTLD_NOW | RTLD_LOCAL,
            0, 0, 0, 0, 0, 0) : 0;
        if (path) r_session_free(session, path);
        if (handle && r_session_class(session, "LSApplicationWorkspace")) return YES;
    }
    return NO;
}

static RemoteCallSession *cnd_ls_open_prompted_installd_session(
    NSDictionary<NSString *, id> **wakeOut,
    NSDictionary<NSString *, id> **failureOut)
{
    if (remote_call_lab_backend_opted_in()) {
        cnd_ls_clear_pending_installd_root_token();
        NSDictionary<NSString *, id> *wake =
            CNDLaunchServicesEnsureInstalldRunning();
        RemoteCallSession *installd = [[RemoteCallSession alloc]
            initWithProcess:CNDLSInstalldProcess
            useMigFilterBypass:NO
            firstExceptionTimeoutMS:CNDLSInstalldBootstrapTimeoutMS
            originalThreadOnly:NO
            bootstrapThreadCount:1
            bootstrapProvoker:nil];
        if (wakeOut) *wakeOut = wake;
        if (!installd && failureOut) {
            RemoteCallInitFailure failure = remote_call_last_init_failure();
            *failureOut = cnd_ls_result(NO, @"lab-remote-session",
                [NSString stringWithFormat:
                    @"the vPhone root-harness installd endpoint is unavailable: %s",
                    remote_call_init_failure_description(failure)], @{
                        @"pid": @(remote_call_last_init_failure_pid()),
                        @"transport": @"not-created",
                        @"teardown": @0,
                        @"teardownMode": @"init-cleanup",
                        @"localStateRemaining": @NO,
                        @"promptMessages": @0,
                        @"promptReplies": @0,
                        @"promptLastEvent": @"root-harness",
                        @"wake": wake ?: @{},
                    });
        }
        return installd;
    }

    NSDictionary<NSString *, id> *wake =
        CNDLaunchServicesEnsureInstalldRunning();
    if (![wake[@"ok"] boolValue]) {
        cnd_ls_clear_pending_installd_root_token();
        if (wakeOut) *wakeOut = wake;
        if (failureOut) *failureOut = wake;
        return nil;
    }
    if (!remote_call_lab_backend_opted_in() && !kexploit_krw_ready()) {
        cnd_ls_clear_pending_installd_root_token();
        if (wakeOut) *wakeOut = wake;
        if (failureOut) {
            *failureOut = cnd_ls_result(NO, @"krw-prerequisite",
                @"kernel read/write became unavailable before the installd capture session was created",
                @{ @"wake": wake });
        }
        return nil;
    }

    CNDXPCMachServiceCreate createMachService =
        (CNDXPCMachServiceCreate)dlsym(
            RTLD_DEFAULT, "xpc_connection_create_mach_service");
    dispatch_queue_t promptQueue = dispatch_queue_create(
        "com.zeroxjf.cyanide.installd-capture-prompt",
        DISPATCH_QUEUE_SERIAL);
    xpc_connection_t promptConnection = createMachService
        ? createMachService(CNDLSInstalldService, promptQueue, 0) : nil;
    if (!promptConnection) {
        cnd_ls_clear_pending_installd_root_token();
        if (wakeOut) *wakeOut = wake;
        if (failureOut) {
            *failureOut = cnd_ls_result(NO, @"prompt-connection",
                @"could not create the concurrent installd capture prompt",
                @{ @"wake": wake });
        }
        return nil;
    }

    __block NSUInteger promptMessages = 0;
    __block NSUInteger promptReplies = 0;
    __block NSString *promptLastEvent = @"none";
    xpc_connection_set_event_handler(promptConnection, ^(xpc_object_t event) {
        char *description = event ? xpc_copy_description(event) : NULL;
        promptLastEvent = description
            ? [NSString stringWithUTF8String:description] : @"unknown event";
        free(description);
    });
    xpc_connection_resume(promptConnection);

    dispatch_block_t bootstrapProvoker = ^{
        xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(message, "CyanideBootstrapProbe", "1");
        promptMessages++;
        xpc_connection_send_message_with_reply(
            promptConnection, message, promptQueue, ^(xpc_object_t reply) {
                promptReplies++;
                char *description = reply
                    ? xpc_copy_description(reply) : NULL;
                promptLastEvent = description
                    ? [NSString stringWithUTF8String:description]
                    : @"unknown bootstrap reply";
                free(description);
            });
    };

    RemoteCallSession *installd = [[RemoteCallSession alloc]
        initWithProcess:CNDLSInstalldProcess
        useMigFilterBypass:NO
        firstExceptionTimeoutMS:CNDLSInstalldBootstrapTimeoutMS
        originalThreadOnly:NO
        bootstrapThreadCount:8
        bootstrapProvoker:bootstrapProvoker];

    __block NSUInteger promptMessageSnapshot = 0;
    __block NSUInteger promptReplySnapshot = 0;
    __block NSString *promptEventSnapshot = @"none";
    dispatch_sync(promptQueue, ^{
        promptMessageSnapshot = promptMessages;
        promptReplySnapshot = promptReplies;
        promptEventSnapshot = promptLastEvent ?: @"none";
        xpc_connection_cancel(promptConnection);
    });
    if (!installd && failureOut) {
        cnd_ls_clear_pending_installd_root_token();
        RemoteCallInitFailure failure = remote_call_last_init_failure();
        *failureOut = cnd_ls_result(NO, @"remote-session",
            [NSString stringWithFormat:@"installd RemoteCall failed: %s",
             remote_call_init_failure_description(failure)], @{
                @"pid": @(remote_call_last_init_failure_pid()),
                @"transport": @"not-created",
                @"teardown": @0,
                @"teardownMode": @"init-cleanup",
                @"localStateRemaining": @NO,
                @"promptMessages": @(promptMessageSnapshot),
                @"promptReplies": @(promptReplySnapshot),
                @"promptLastEvent": promptEventSnapshot,
                @"wake": wake,
            });
    }
    if (!installd) {
        cnd_ls_clear_pending_installd_root_token();
        if (wakeOut) *wakeOut = wake;
        return nil;
    }

    NSDictionary<NSString *, id> *fileGrant = nil;
    BOOL fileGrantOK = cnd_ls_consume_pending_root_token_in_installd(
        installd, &fileGrant);
    NSMutableDictionary *wakeWithGrant = [wake mutableCopy];
    wakeWithGrant[@"installdFileGrant"] = fileGrant ?: @{};
    wake = wakeWithGrant;
    if (wakeOut) *wakeOut = wake;
    if (!fileGrantOK) {
        NSDictionary *finalization = cnd_ls_finalize_session(installd);
        if (failureOut) {
            *failureOut = cnd_ls_result(NO,
                @"installd-root-file-token-consume",
                fileGrant[@"installdRootFileTokenFailure"] ?:
                    @"installd could not consume its fresh root file token",
                @{
                    @"wake": wake,
                    @"fileGrant": fileGrant ?: @{},
                    @"pid": @(installd.pid),
                    @"transport": finalization[@"transport"] ?: @"failed",
                    @"teardown": finalization[@"teardown"] ?: @(-1),
                    @"teardownMode": finalization[@"teardownMode"] ?: @"unknown",
                    @"localStateRemaining":
                        finalization[@"localStateRemaining"] ?: @NO,
                    @"promptMessages": @(promptMessageSnapshot),
                    @"promptReplies": @(promptReplySnapshot),
                    @"promptLastEvent": promptEventSnapshot,
                });
        }
        return nil;
    }
    return installd;
}

static NSDictionary<NSString *, id> *
cnd_ls_copy_application_proxy_archive_via_installd(
    NSString *bundleIdentifier, BOOL retainSession)
{
    if (![bundleIdentifier isKindOfClass:NSString.class] ||
        bundleIdentifier.length == 0) {
        return cnd_ls_result(NO, @"validation",
            @"bundleIdentifier is required for the installd capture", nil);
    }
    RemoteCallSession *installd = cnd_ls_current_retained_session();
    BOOL borrowedSession = installd != nil;
    NSDictionary<NSString *, id> *wake = borrowedSession
        ? cnd_ls_current_retained_wake() : nil;
    NSDictionary<NSString *, id> *openFailure = nil;
    if (!installd) {
        installd = cnd_ls_open_prompted_installd_session(&wake, &openFailure);
    }
    if (!installd) return openFailure ?: cnd_ls_result(
        NO, @"remote-session", @"could not open installd", nil);

    NSString *failureStage = nil;
    NSMutableData *archiveData = nil;
    uint64_t archiveLength = 0;
    uint64_t pool = r_session_dlsym_call(
        installd, 5, "objc_autoreleasePoolPush", 0, 0, 0, 0, 0, 0, 0, 0);
    if (!pool) {
        failureStage = @"remote-autorelease-pool";
    } else if (!cnd_ls_remote_load_coreservices(installd)) {
        failureStage = @"coreservices";
    }

    uint64_t identifier = 0;
    uint64_t proxy = 0;
    uint64_t plugins = 0;
    uint64_t envelope = 0;
    uint64_t applicationKey = 0;
    uint64_t pluginsKey = 0;
    uint64_t archive = 0;
    if (!failureStage) {
        identifier = r_session_nsstr_retained(
            installd, bundleIdentifier.UTF8String);
        uint64_t proxyClass = r_session_class(installd, "LSApplicationProxy");
        proxy = r_is_objc_ptr(proxyClass) && r_is_objc_ptr(identifier)
            ? r_session_msg2(installd, proxyClass,
                "applicationProxyForIdentifier:", identifier, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(proxy)) {
            failureStage = @"installd-proxy";
        }
    }
    if (!failureStage) {
        uint64_t installed = r_session_responds(
            installd, proxy, "isInstalled")
            ? r_session_msg2(installd, proxy, "isInstalled", 0, 0, 0, 0) : 1;
        uint64_t placeholder = r_session_responds(
            installd, proxy, "isPlaceholder")
            ? r_session_msg2(installd, proxy, "isPlaceholder", 0, 0, 0, 0) : 0;
        if ((installed & 0xff) == 0 || (placeholder & 0xff) != 0) {
            failureStage = @"installd-target-state";
        }
    }
    if (!failureStage) {
        plugins = r_session_responds(installd, proxy, "plugInKitPlugins")
            ? r_session_msg2(installd, proxy,
                "plugInKitPlugins", 0, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(plugins)) {
            uint64_t arrayClass = r_session_class(installd, "NSArray");
            plugins = r_is_objc_ptr(arrayClass)
                ? r_session_msg2(installd, arrayClass,
                    "array", 0, 0, 0, 0) : 0;
        }
        if (!r_is_objc_ptr(plugins)) {
            failureStage = @"installd-plugin-list";
        }
    }
    if (!failureStage) {
        uint64_t pluginCount = r_session_msg2(
            installd, plugins, "count", 0, 0, 0, 0);
        if (pluginCount > 128) {
            failureStage = @"installd-plugin-count";
        } else {
            for (uint64_t index = 0; index < pluginCount; index++) {
                uint64_t plugin = r_session_msg2(installd, plugins,
                    "objectAtIndex:", index, 0, 0, 0);
                if (!r_is_objc_ptr(plugin)) {
                    failureStage = @"installd-plugin-proxy";
                    break;
                }
                if (r_session_responds(installd, plugin, "detach")) {
                    (void)r_session_msg2(installd, plugin,
                        "detach", 0, 0, 0, 0);
                }
            }
        }
    }
    if (!failureStage && r_session_responds(installd, proxy, "detach")) {
        (void)r_session_msg2(installd, proxy, "detach", 0, 0, 0, 0);
    }
    if (!failureStage) {
        uint64_t dictionaryClass = r_session_class(
            installd, "NSMutableDictionary");
        envelope = r_is_objc_ptr(dictionaryClass)
            ? r_session_msg2(installd, dictionaryClass,
                "dictionary", 0, 0, 0, 0) : 0;
        applicationKey = r_session_nsstr_retained(installd, "application");
        pluginsKey = r_session_nsstr_retained(installd, "plugins");
        if (!r_is_objc_ptr(envelope) ||
            !r_is_objc_ptr(applicationKey) || !r_is_objc_ptr(pluginsKey)) {
            failureStage = @"installd-archive-envelope";
        } else {
            (void)r_session_msg2(installd, envelope,
                "setObject:forKey:", proxy, applicationKey, 0, 0);
            (void)r_session_msg2(installd, envelope,
                "setObject:forKey:", plugins, pluginsKey, 0, 0);
        }
    }
    if (!failureStage) {
        uint64_t archiverClass = r_session_class(installd, "NSKeyedArchiver");
        archive = r_is_objc_ptr(archiverClass) &&
            r_session_responds(installd, archiverClass,
                               "archivedDataWithRootObject:")
            ? r_session_msg2(installd, archiverClass,
                "archivedDataWithRootObject:", envelope, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(archive)) {
            failureStage = @"installd-proxy-archive";
        }
    }
    if (!failureStage) {
        archiveLength = r_session_msg2(
            installd, archive, "length", 0, 0, 0, 0);
        uint64_t archiveBytes = r_session_msg2(
            installd, archive, "bytes", 0, 0, 0, 0);
        if (archiveLength == 0 ||
            archiveLength > CNDLSMaxInstalledApplicationArchiveBytes ||
            archiveBytes == 0) {
            failureStage = @"installd-proxy-archive-size";
        } else {
            archiveData = [NSMutableData dataWithLength:(NSUInteger)archiveLength];
            if (![installd remoteRead:archiveBytes
                                   to:archiveData.mutableBytes
                                 size:archiveData.length]) {
                archiveData = nil;
                failureStage = @"installd-proxy-archive-copy";
            }
        }
    }

    if (applicationKey && cnd_ls_session_healthy(installd)) {
        (void)r_session_msg2(installd, applicationKey,
                             "release", 0, 0, 0, 0);
    }
    if (pluginsKey && cnd_ls_session_healthy(installd)) {
        (void)r_session_msg2(installd, pluginsKey,
                             "release", 0, 0, 0, 0);
    }
    if (identifier && cnd_ls_session_healthy(installd)) {
        (void)r_session_msg2(installd, identifier,
                             "release", 0, 0, 0, 0);
    }
    if (pool && cnd_ls_session_healthy(installd)) {
        (void)r_session_dlsym_call(installd, 5,
            "objc_autoreleasePoolPop", pool, 0, 0, 0, 0, 0, 0, 0);
    }

    BOOL sessionRetained = borrowedSession && cnd_ls_session_healthy(installd);
    if (!failureStage && retainSession && !borrowedSession &&
        cnd_ls_session_healthy(installd)) {
        sessionRetained = cnd_ls_retain_session_for_current_thread(
            installd, wake ?: @{});
        if (!sessionRetained) failureStage = @"retain-session";
    }
    NSDictionary<NSString *, id> *finalization = sessionRetained
        ? @{
            @"pid": @(installd.pid),
            @"transport": @"healthy",
            @"teardown": @0,
            @"teardownMode": @"retained",
            @"localStateRemaining": @YES,
        }
        : cnd_ls_finalize_session(installd);
    NSMutableDictionary<NSString *, id> *details = [finalization mutableCopy];
    details[@"bundleIdentifier"] = bundleIdentifier;
    details[@"archiveBytes"] = @(archiveLength);
    details[@"wake"] = wake ?: @{};
    details[@"sessionRetained"] = @(sessionRetained);
    if (archiveData.length > 0) details[@"proxyArchive"] = archiveData;
    if (failureStage) {
        return cnd_ls_result(NO, failureStage,
            @"stock installd could not capture the target LaunchServices proxy",
            details);
    }
    if (!sessionRetained && !cnd_ls_finalization_succeeded(finalization)) {
        return cnd_ls_result(NO, @"capture-finalization",
            @"installd captured the proxy, but the RemoteCall session did not close cleanly",
            details);
    }
    return cnd_ls_result(YES, @"proxy-captured",
        @"stock installd archived the detached target and plug-in LaunchServices proxies",
        details);
}

static NSDictionary<NSString *, id> *
cnd_ls_copy_installed_bundle_identifiers_via_installd(BOOL retainSession)
{
    RemoteCallSession *retainedSession = cnd_ls_current_retained_session();
    if (!retainedSession && !remote_call_lab_backend_opted_in() &&
        !kexploit_krw_ready()) {
        return cnd_ls_result(NO, @"krw-prerequisite",
            @"installed-app matching requires an active RemoteCall backend", nil);
    }

    BOOL borrowedSession = retainedSession != nil;
    NSDictionary<NSString *, id> *wake = borrowedSession
        ? cnd_ls_current_retained_wake() : nil;
    NSDictionary<NSString *, id> *openFailure = nil;
    RemoteCallSession *installd = retainedSession;
    if (!installd) {
        installd = cnd_ls_open_prompted_installd_session(&wake, &openFailure);
    }
    if (!installd) return openFailure ?: cnd_ls_result(
        NO, @"remote-session", @"could not open installd", nil);

    NSString *failureStage = nil;
    uint64_t pool = r_session_dlsym_call(
        installd, 5, "objc_autoreleasePoolPush", 0, 0, 0, 0, 0, 0, 0, 0);
    uint64_t workspace = 0;
    uint64_t applications = 0;
    uint64_t bundleIdentifierKey = 0;
    uint64_t bundleIdentifiers = 0;
    uint64_t archive = 0;
    uint64_t archiveLength = 0;
    NSMutableData *archiveData = nil;

    if (!pool) {
        failureStage = @"remote-autorelease-pool";
    } else if (!cnd_ls_remote_load_coreservices(installd)) {
        failureStage = @"coreservices";
    }
    if (!failureStage) {
        uint64_t workspaceClass = r_session_class(
            installd, "LSApplicationWorkspace");
        workspace = r_is_objc_ptr(workspaceClass)
            ? r_session_msg2(installd, workspaceClass,
                "defaultWorkspace", 0, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(workspace)) failureStage = @"workspace";
    }
    if (!failureStage) {
        for (NSString *selectorName in @[
            @"allApplications", @"allInstalledApplications"
        ]) {
            if (!r_session_responds(installd, workspace,
                                    selectorName.UTF8String)) continue;
            uint64_t candidate = r_session_msg2(
                installd, workspace, selectorName.UTF8String, 0, 0, 0, 0);
            if (r_is_objc_ptr(candidate)) {
                applications = candidate;
                break;
            }
        }
        if (!r_is_objc_ptr(applications)) failureStage = @"applications";
    }
    if (!failureStage) {
        uint64_t applicationCount = r_session_msg2(
            installd, applications, "count", 0, 0, 0, 0);
        if (applicationCount == 0 ||
            applicationCount > CNDLSMaxInstalledApplicationProxies) {
            failureStage = @"application-count";
        }
    }
    if (!failureStage) {
        bundleIdentifierKey = r_session_nsstr_retained(
            installd, "bundleIdentifier");
        bundleIdentifiers = r_is_objc_ptr(bundleIdentifierKey) &&
            r_session_responds(installd, applications, "valueForKey:")
            ? r_session_msg2(installd, applications, "valueForKey:",
                bundleIdentifierKey, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(bundleIdentifiers)) {
            failureStage = @"bundle-identifiers";
        }
    }
    if (!failureStage) {
        uint64_t archiverClass = r_session_class(installd, "NSKeyedArchiver");
        archive = r_is_objc_ptr(archiverClass) &&
            r_session_responds(installd, archiverClass,
                               "archivedDataWithRootObject:")
            ? r_session_msg2(installd, archiverClass,
                "archivedDataWithRootObject:", bundleIdentifiers, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(archive)) failureStage = @"identifier-archive";
    }
    if (!failureStage) {
        archiveLength = r_session_msg2(
            installd, archive, "length", 0, 0, 0, 0);
        uint64_t archiveBytes = r_session_msg2(
            installd, archive, "bytes", 0, 0, 0, 0);
        if (archiveLength == 0 ||
            archiveLength > CNDLSMaxRegistrationPlistBytes ||
            archiveBytes == 0) {
            failureStage = @"identifier-archive-size";
        } else {
            archiveData = [NSMutableData dataWithLength:(NSUInteger)archiveLength];
            if (![installd remoteRead:archiveBytes
                                   to:archiveData.mutableBytes
                                 size:archiveData.length]) {
                archiveData = nil;
                failureStage = @"identifier-archive-copy";
            }
        }
    }

    if (bundleIdentifierKey && cnd_ls_session_healthy(installd)) {
        (void)r_session_msg2(installd, bundleIdentifierKey,
                             "release", 0, 0, 0, 0);
    }
    if (pool && cnd_ls_session_healthy(installd)) {
        (void)r_session_dlsym_call(installd, 5,
            "objc_autoreleasePoolPop", pool, 0, 0, 0, 0, 0, 0, 0);
    }

    BOOL sessionRetained = borrowedSession && cnd_ls_session_healthy(installd);
    if (!failureStage && retainSession && !borrowedSession &&
        cnd_ls_session_healthy(installd)) {
        sessionRetained = cnd_ls_retain_session_for_current_thread(
            installd, wake ?: @{});
        if (!sessionRetained) failureStage = @"retain-session";
    }
    NSDictionary<NSString *, id> *finalization = sessionRetained
        ? @{
            @"pid": @(installd.pid), @"transport": @"healthy",
            @"teardown": @0, @"teardownMode": @"retained",
            @"localStateRemaining": @YES,
        }
        : cnd_ls_finalize_session(installd);
    NSMutableDictionary<NSString *, id> *details = [finalization mutableCopy];
    details[@"archiveBytes"] = @(archiveLength);
    details[@"sessionRetained"] = @(sessionRetained);
    details[@"wake"] = wake ?: @{};

    if (failureStage) {
        return cnd_ls_result(NO, failureStage,
            @"stock installd could not return its compact application identifier list",
            details);
    }
    if (!sessionRetained && !cnd_ls_finalization_succeeded(finalization)) {
        return cnd_ls_result(NO, @"identifier-finalization",
            @"installd returned application identifiers, but the session did not close cleanly",
            details);
    }

    id decoded = nil;
    @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        decoded = [NSKeyedUnarchiver unarchiveObjectWithData:archiveData];
#pragma clang diagnostic pop
    } @catch (__unused NSException *exception) {
        decoded = nil;
    }
    if (![decoded isKindOfClass:NSArray.class]) {
        return cnd_ls_result(NO, @"identifier-decode",
            @"the compact installd application identifier list was invalid", details);
    }
    NSMutableOrderedSet<NSString *> *unique = [NSMutableOrderedSet orderedSet];
    for (id value in (NSArray *)decoded) {
        if ([value isKindOfClass:NSString.class] && [(NSString *)value length] > 0) {
            [unique addObject:value];
        }
    }
    NSArray<NSString *> *identifiers = [unique.array
        sortedArrayUsingSelector:@selector(compare:)];
    if (identifiers.count == 0) {
        return cnd_ls_result(NO, @"identifier-empty",
            @"installd returned no valid application bundle identifiers", details);
    }
    details[@"bundleIdentifiers"] = identifiers;
    details[@"applicationCount"] = @(identifiers.count);
    return cnd_ls_result(YES, @"identifiers-captured",
        @"stock installd returned its compact application identifier list", details);
}

static NSDictionary<NSString *, id> *
cnd_ls_copy_installed_application_proxy_archive_via_installd(void)
{
    // Do not wake installd merely because an ordinary jailed caller opened the
    // dock picker. The privileged path is meaningful only after the existing
    // kernel/RemoteCall setup is live (or on the explicit vPhone lab backend).
    RemoteCallSession *retainedSession = cnd_ls_current_retained_session();
    if (!retainedSession && !remote_call_lab_backend_opted_in() &&
        !kexploit_krw_ready()) {
        return cnd_ls_result(NO, @"krw-prerequisite",
            @"privileged application enumeration requires an active RemoteCall backend",
            nil);
    }

    BOOL borrowedSession = retainedSession != nil;
    NSDictionary<NSString *, id> *wake = borrowedSession
        ? cnd_ls_current_retained_wake() : nil;
    NSDictionary<NSString *, id> *openFailure = nil;
    RemoteCallSession *installd = retainedSession;
    if (!installd) {
        installd = cnd_ls_open_prompted_installd_session(&wake, &openFailure);
    }
    if (!installd) return openFailure ?: cnd_ls_result(
        NO, @"remote-session", @"could not open installd", nil);

    NSString *failureStage = nil;
    uint64_t pool = r_session_dlsym_call(
        installd, 5, "objc_autoreleasePoolPush", 0, 0, 0, 0, 0, 0, 0, 0);
    uint64_t workspace = 0;
    uint64_t applications = 0;
    uint64_t archive = 0;
    uint64_t archiveBytes = 0;
    uint64_t applicationCount = 0;
    uint64_t detachedCount = 0;
    uint64_t archiveLength = 0;
    NSMutableData *archiveData = nil;

    if (!pool) {
        failureStage = @"remote-autorelease-pool";
    } else if (!cnd_ls_remote_load_coreservices(installd)) {
        failureStage = @"coreservices";
    }

    if (!failureStage) {
        uint64_t workspaceClass = r_session_class(
            installd, "LSApplicationWorkspace");
        workspace = r_is_objc_ptr(workspaceClass)
            ? r_session_msg2(installd, workspaceClass,
                "defaultWorkspace", 0, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(workspace)) {
            failureStage = @"workspace";
        }
    }

    if (!failureStage) {
        // `allApplications` is the broad LaunchServices membership query. A
        // few OS builds expose only the older allInstalledApplications name,
        // so retain the same bounded fallback used by the jailed catalog.
        for (NSString *selectorName in @[
            @"allApplications", @"allInstalledApplications"
        ]) {
            if (!r_session_responds(installd, workspace,
                                    selectorName.UTF8String)) continue;
            uint64_t candidate = r_session_msg2(
                installd, workspace, selectorName.UTF8String, 0, 0, 0, 0);
            if (!r_is_objc_ptr(candidate) ||
                !r_session_responds(installd, candidate, "count") ||
                !r_session_responds(installd, candidate, "objectAtIndex:")) {
                continue;
            }
            applications = candidate;
            break;
        }
        if (!r_is_objc_ptr(applications)) {
            failureStage = @"applications";
        }
    }

    if (!failureStage) {
        applicationCount = r_session_msg2(
            installd, applications, "count", 0, 0, 0, 0);
        if (applicationCount > CNDLSMaxInstalledApplicationProxies) {
            failureStage = @"application-count";
        }
    }

    if (!failureStage) {
        for (uint64_t index = 0; index < applicationCount; index++) {
            uint64_t proxy = r_session_msg2(
                installd, applications, "objectAtIndex:", index, 0, 0, 0);
            if (!r_is_objc_ptr(proxy)) {
                failureStage = @"application-proxy";
                break;
            }
            // Detached proxies are self-contained enough for NSKeyedArchiver
            // and do not retain a live daemon-side transaction while the
            // archive is being copied out. This is observation-only.
            if (r_session_responds(installd, proxy, "detach")) {
                (void)r_session_msg2(installd, proxy,
                                      "detach", 0, 0, 0, 0);
                if (!cnd_ls_session_healthy(installd)) {
                    failureStage = @"application-detach";
                    break;
                }
                detachedCount++;
            }
        }
    }

    if (!failureStage) {
        uint64_t archiverClass = r_session_class(installd, "NSKeyedArchiver");
        archive = r_is_objc_ptr(archiverClass) &&
            r_session_responds(installd, archiverClass,
                               "archivedDataWithRootObject:")
            ? r_session_msg2(installd, archiverClass,
                "archivedDataWithRootObject:", applications, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(archive)) {
            failureStage = @"application-archive";
        }
    }

    if (!failureStage) {
        archiveLength = r_session_msg2(
            installd, archive, "length", 0, 0, 0, 0);
        archiveBytes = r_session_msg2(
            installd, archive, "bytes", 0, 0, 0, 0);
        if (archiveLength == 0 ||
            archiveLength > CNDLSMaxRegistrationPlistBytes ||
            archiveBytes == 0) {
            failureStage = @"application-archive-size";
        } else {
            archiveData = [NSMutableData dataWithLength:(NSUInteger)archiveLength];
            if (![installd remoteRead:archiveBytes
                                   to:archiveData.mutableBytes
                                 size:archiveData.length]) {
                archiveData = nil;
                failureStage = @"application-archive-copy";
            }
        }
    }

    if (pool && cnd_ls_session_healthy(installd)) {
        (void)r_session_dlsym_call(installd, 5,
            "objc_autoreleasePoolPop", pool, 0, 0, 0, 0, 0, 0, 0);
    }

    BOOL sessionRetained = borrowedSession && cnd_ls_session_healthy(installd);
    NSDictionary<NSString *, id> *finalization = sessionRetained
        ? @{
            @"pid": @(installd.pid),
            @"transport": @"healthy",
            @"teardown": @0,
            @"teardownMode": @"retained",
            @"localStateRemaining": @YES,
        }
        : cnd_ls_finalize_session(installd);
    NSMutableDictionary<NSString *, id> *details = [finalization mutableCopy];
    details[@"applicationCount"] = @(applicationCount);
    details[@"detachedCount"] = @(detachedCount);
    details[@"archiveBytes"] = @(archiveLength);
    details[@"sessionRetained"] = @(sessionRetained);
    details[@"wake"] = wake ?: @{};
    if (archiveData.length > 0) details[@"proxyArchive"] = archiveData;

    if (failureStage) {
        return cnd_ls_result(NO, failureStage,
            @"stock installd could not capture its bounded installed-application snapshot",
            details);
    }
    if (!sessionRetained && !cnd_ls_finalization_succeeded(finalization)) {
        return cnd_ls_result(NO, @"capture-finalization",
            @"installd captured installed applications, but the RemoteCall session did not close cleanly",
            details);
    }
    return cnd_ls_result(YES, @"applications-captured",
        @"stock installd archived the bounded installed-application snapshot",
        details);
}

NSDictionary<NSString *, id> *
CNDLaunchServicesBeginBatchInstalldSession(NSString *bundleIdentifier)
{
    NSMutableDictionary *threadState = NSThread.currentThread.threadDictionary;
    if ([threadState[CNDLSBatchSessionKey] boolValue]) {
        BOOL healthy = CNDLaunchServicesBatchInstalldSessionIsHealthy();
        return cnd_ls_result(healthy,
            healthy ? @"batch-session-ready" : @"batch-session-unhealthy",
            healthy ? @"the bounded installd batch session is already ready" :
                @"the existing bounded installd batch session is unhealthy", nil);
    }
    if (cnd_ls_current_retained_session()) {
        BOOL healthy = cnd_ls_session_healthy(
            cnd_ls_current_retained_session());
        if (!healthy) {
            return cnd_ls_result(NO, @"retained-session-unhealthy",
                @"the retained catalog session became unhealthy before batch promotion",
                nil);
        }
        threadState[CNDLSBatchSessionKey] = @YES;
        return cnd_ls_result(YES, @"batch-session-ready",
            @"the retained catalog session was promoted to the bounded batch", @{
                @"pid": @(cnd_ls_current_retained_session().pid),
                @"transport": @"healthy",
                @"teardownMode": @"batch-retained",
                @"localStateRemaining": @YES,
            });
    }
    // A batch needs a retained transport, not an archived copy of its first
    // application. The first transaction captures that app's recovery
    // identity normally; doing it here as well doubled its proxy work.
    (void)bundleIdentifier;
    NSDictionary<NSString *, id> *wake = nil;
    NSDictionary<NSString *, id> *openFailure = nil;
    RemoteCallSession *installd =
        cnd_ls_open_prompted_installd_session(&wake, &openFailure);
    if (!installd) {
        return openFailure ?: cnd_ls_result(
            NO, @"remote-session", @"could not open installd batch session", nil);
    }
    if (!cnd_ls_retain_session_for_current_thread(installd, wake ?: @{})) {
        NSDictionary *finalization = cnd_ls_finalize_session(installd);
        return cnd_ls_result(NO, @"retain-session",
            @"the installd batch session could not be retained on its worker thread",
            finalization);
    }
    threadState[CNDLSBatchSessionKey] = @YES;
    return cnd_ls_result(YES, @"batch-session-ready",
        @"one bounded installd session is retained for this sequential batch", @{
            @"pid": @(cnd_ls_current_retained_session().pid),
            @"transport": @"healthy",
            @"teardownMode": @"batch-retained",
            @"localStateRemaining": @YES,
        });
}

NSDictionary<NSString *, id> *
CNDLaunchServicesCopyApplicationProxyArchiveViaInstalld(
    NSString *bundleIdentifier)
{
    return cnd_ls_copy_application_proxy_archive_via_installd(
        bundleIdentifier, NO);
}

NSDictionary<NSString *, id> *
CNDLaunchServicesCopyInstalledBundleIdentifiersViaInstalld(void)
{
    return cnd_ls_copy_installed_bundle_identifiers_via_installd(NO);
}

NSDictionary<NSString *, id> *
CNDLaunchServicesCopyInstalledBundleIdentifiersViaInstalldRetainingSession(void)
{
    return cnd_ls_copy_installed_bundle_identifiers_via_installd(YES);
}

NSDictionary<NSString *, id> *
CNDLaunchServicesCopyApplicationProxyArchiveViaInstalldRetainingSession(
    NSString *bundleIdentifier)
{
    return cnd_ls_copy_application_proxy_archive_via_installd(
        bundleIdentifier, YES);
}

static NSDictionary<NSString *, id> *cnd_ls_register_dictionary_on_retained_session(
    RemoteCallSession *installd,
    NSDictionary<NSString *, id> *registrationDictionary,
    NSData *plist)
{
    NSString *bundleIdentifier = registrationDictionary[@"CFBundleIdentifier"];
    NSString *path = registrationDictionary[@"Path"];
    NSString *failureStage = nil;
    uint64_t registrationReturn = 0;
    uint64_t pool = r_session_dlsym_call(
        installd, 5, "objc_autoreleasePoolPush", 0, 0, 0, 0, 0, 0, 0, 0);
    uint64_t remoteBytes = 0;
    if (!pool) {
        failureStage = @"remote-autorelease-pool";
    } else {
        remoteBytes = r_session_dlsym_call(
            installd, 5, "malloc", plist.length, 0, 0, 0, 0, 0, 0, 0);
        if (!remoteBytes ||
            ![installd remoteWrite:remoteBytes from:plist.bytes size:plist.length]) {
            failureStage = @"remote-transfer";
        }
    }

    uint64_t remoteData = 0;
    uint64_t remoteDictionary = 0;
    if (!failureStage) {
        uint64_t dataClass = r_session_class(installd, "NSData");
        remoteData = r_session_msg2(installd, dataClass,
            "dataWithBytes:length:", remoteBytes, plist.length, 0, 0);
        if (!r_is_objc_ptr(remoteData)) failureStage = @"remote-data";
    }
    if (remoteBytes && cnd_ls_session_healthy(installd)) {
        (void)r_session_dlsym_call(installd, 5, "free", remoteBytes,
                                   0, 0, 0, 0, 0, 0, 0);
    }
    if (!failureStage) {
        uint64_t plistClass = r_session_class(
            installd, "NSPropertyListSerialization");
        remoteDictionary = r_session_msg2(
            installd, plistClass,
            "propertyListWithData:options:format:error:",
            remoteData, 0, 0, 0);
        if (!r_is_objc_ptr(remoteDictionary)) {
            failureStage = @"remote-deserialization";
        }
    }

    uint64_t workspace = 0;
    if (!failureStage && !cnd_ls_remote_load_coreservices(installd)) {
        failureStage = @"coreservices";
    }
    if (!failureStage) {
        uint64_t workspaceClass = r_session_class(
            installd, "LSApplicationWorkspace");
        workspace = r_session_msg2(installd, workspaceClass,
                                   "defaultWorkspace", 0, 0, 0, 0);
        if (!r_is_objc_ptr(workspace) ||
            !r_session_responds(installd, workspace,
                                "registerApplicationDictionary:")) {
            failureStage = @"workspace";
        }
    }
    if (!failureStage) {
        registrationReturn = r_session_msg2(
            installd, workspace, "registerApplicationDictionary:",
            remoteDictionary, 0, 0, 0);
        if (!cnd_ls_session_healthy(installd)) {
            failureStage = @"registration-transport";
        }
    }
    if (pool && cnd_ls_session_healthy(installd)) {
        (void)r_session_dlsym_call(installd, 5,
            "objc_autoreleasePoolPop", pool, 0, 0, 0, 0, 0, 0, 0);
    }

    BOOL transportHealthy = cnd_ls_session_healthy(installd);
    NSDictionary *details = @{
        @"pid": @(installd.pid),
        @"transport": transportHealthy ? @"healthy" : @"failed",
        @"teardown": @0,
        @"teardownMode": @"retained",
        @"localStateRemaining": @YES,
        @"bundleIdentifier": bundleIdentifier ?: @"",
        @"path": path ?: @"",
        @"registrationMode": @"dictionary",
        @"plistBytes": @(plist.length),
        @"registrationAccepted": @(registrationReturn != 0),
        @"promptMessages": @0,
        @"promptReplies": @0,
        @"promptLastEvent": @"retained-capture-session",
        @"wake": cnd_ls_current_retained_wake(),
    };
    if (failureStage) {
        return cnd_ls_result(NO, failureStage,
            @"the retained installd registration operation did not complete",
            details);
    }
    if (registrationReturn == 0) {
        return cnd_ls_result(NO, @"registration-rejected",
            @"LaunchServices rejected the registration dictionary", details);
    }
    return cnd_ls_result(transportHealthy, @"registered-retained",
        transportHealthy
            ? @"LaunchServices accepted the registration on the retained installd session"
            : @"LaunchServices accepted the registration, but the retained transport failed",
        details);
}

static NSDictionary<NSString *, id> *cnd_ls_register_via_installd(
    NSDictionary<NSString *, id> *registrationDictionary,
    NSString *bundlePath)
{
    BOOL dictionaryMode = [registrationDictionary isKindOfClass:NSDictionary.class];
    NSString *bundleIdentifier = dictionaryMode
        ? registrationDictionary[@"CFBundleIdentifier"] : nil;
    NSString *path = dictionaryMode
        ? registrationDictionary[@"Path"] : bundlePath;
    if (dictionaryMode) {
        if (registrationDictionary.count == 0 ||
            ![bundleIdentifier isKindOfClass:NSString.class] ||
            bundleIdentifier.length == 0 ||
            ![path isKindOfClass:NSString.class] || path.length == 0) {
            return cnd_ls_result(NO, @"validation",
                @"registrationDictionary requires CFBundleIdentifier and Path", nil);
        }
    } else if (![path isKindOfClass:NSString.class] || path.length == 0 ||
               ![path.pathExtension.lowercaseString isEqual:@"app"]) {
        return cnd_ls_result(NO, @"validation",
            @"bundlePath must identify an existing .app bundle", nil);
    }

    NSError *serializationError = nil;
    NSData *plist = dictionaryMode ? [NSPropertyListSerialization
        dataWithPropertyList:registrationDictionary
                      format:NSPropertyListBinaryFormat_v1_0
                     options:0
                       error:&serializationError] : nil;
    if (dictionaryMode &&
        (!plist || plist.length == 0 || plist.length > CNDLSMaxRegistrationPlistBytes)) {
        return cnd_ls_result(NO, @"serialization",
            serializationError.localizedDescription ?: @"registration plist size is invalid",
            @{ @"bytes": @(plist.length) });
    }

    RemoteCallSession *retainedSession = cnd_ls_current_retained_session();
    if (dictionaryMode && retainedSession) {
        return cnd_ls_register_dictionary_on_retained_session(
            retainedSession, registrationDictionary, plist);
    }

    NSDictionary<NSString *, id> *wake =
        CNDLaunchServicesEnsureInstalldRunning();
    if (![wake[@"ok"] boolValue]) return wake;

    // Recheck immediately before process targeting in case KRW was invalidated
    // while installd was being woken. The explicit VM lab transport has no
    // kernel state by design and authenticates to a root-injected endpoint.
    if (!remote_call_lab_backend_opted_in() && !kexploit_krw_ready()) {
        return cnd_ls_result(NO, @"krw-prerequisite",
            @"kernel read/write became unavailable before the installd session was created",
            @{ @"wake": wake });
    }

    __block NSUInteger promptMessages = 0;
    __block NSUInteger promptReplies = 0;
    __block NSString *promptLastEvent = @"none";
    __block NSUInteger promptMessageSnapshot = 0;
    __block NSUInteger promptReplySnapshot = 0;
    __block NSString *promptEventSnapshot = @"none";
    RemoteCallSession *installd = nil;
    if (remote_call_lab_backend_opted_in()) {
        NSDictionary<NSString *, id> *openFailure = nil;
        installd = cnd_ls_open_prompted_installd_session(
            &wake, &openFailure);
        promptEventSnapshot = @"root-harness";
        if (!installd) return openFailure ?: cnd_ls_result(
            NO, @"lab-remote-session",
            @"could not connect to the vPhone root-harness installd endpoint",
            @{ @"wake": wake ?: @{} });
    } else {
        CNDXPCMachServiceCreate createMachService =
            (CNDXPCMachServiceCreate)dlsym(
                RTLD_DEFAULT, "xpc_connection_create_mach_service");
        dispatch_queue_t promptQueue = dispatch_queue_create(
            "com.zeroxjf.cyanide.installd-prompt", DISPATCH_QUEUE_SERIAL);
        xpc_connection_t promptConnection = createMachService
            ? createMachService(CNDLSInstalldService, promptQueue, 0)
            : nil;
        if (!promptConnection) {
            return cnd_ls_result(NO, @"prompt-connection",
                createMachService
                    ? @"could not create the concurrent installd XPC prompt"
                    : @"xpc_connection_create_mach_service is unavailable", @{
                        @"wake": wake,
                        @"promptMessages": @0,
                    });
        }

        xpc_connection_set_event_handler(promptConnection,
            ^(xpc_object_t event) {
                char *description = event
                    ? xpc_copy_description(event) : NULL;
                promptLastEvent = description
                    ? [NSString stringWithUTF8String:description]
                    : @"unknown event";
                free(description);
            });
        xpc_connection_resume(promptConnection);

        dispatch_block_t bootstrapProvoker = ^{
            xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
            xpc_dictionary_set_string(message, "CyanideBootstrapProbe", "1");
            promptMessages++;
            xpc_connection_send_message_with_reply(
                promptConnection, message, promptQueue,
                ^(xpc_object_t reply) {
                    promptReplies++;
                    char *description = reply
                        ? xpc_copy_description(reply) : NULL;
                    promptLastEvent = description
                        ? [NSString stringWithUTF8String:description]
                        : @"unknown bootstrap reply";
                    free(description);
                });
        };

        installd = [[RemoteCallSession alloc]
            initWithProcess:CNDLSInstalldProcess
            useMigFilterBypass:NO
            firstExceptionTimeoutMS:CNDLSInstalldBootstrapTimeoutMS
            originalThreadOnly:NO
            bootstrapThreadCount:8
            bootstrapProvoker:bootstrapProvoker];

        dispatch_sync(promptQueue, ^{
            promptMessageSnapshot = promptMessages;
            promptReplySnapshot = promptReplies;
            promptEventSnapshot = promptLastEvent ?: @"none";
            xpc_connection_cancel(promptConnection);
        });
    }
    if (!installd) {
        RemoteCallInitFailure failure = remote_call_last_init_failure();
        return cnd_ls_result(NO, @"remote-session",
            [NSString stringWithFormat:@"installd RemoteCall failed: %s",
             remote_call_init_failure_description(failure)], @{
                @"pid": @(remote_call_last_init_failure_pid()),
                @"transport": @"not-created",
                @"teardown": @0,
                @"teardownMode": @"init-cleanup",
                @"localStateRemaining": @NO,
                @"promptMessages": @(promptMessageSnapshot),
                @"promptReplies": @(promptReplySnapshot),
                @"promptLastEvent": promptEventSnapshot,
                @"wake": wake,
            });
    }

    NSString *failureStage = nil;
    uint64_t registrationReturn = 0;
    uint64_t pool = r_session_dlsym_call(
        installd, 5, "objc_autoreleasePoolPush", 0, 0, 0, 0, 0, 0, 0, 0);
    uint64_t remoteBytes = 0;
    uint64_t remotePathBytes = 0;
    uint64_t remotePathString = 0;
    uint64_t remoteBundleURL = 0;
    if (!pool) {
        failureStage = @"remote-autorelease-pool";
    } else if (dictionaryMode) {
        remoteBytes = r_session_dlsym_call(
            installd, 5, "malloc", plist.length, 0, 0, 0, 0, 0, 0, 0);
        if (!remoteBytes ||
            ![installd remoteWrite:remoteBytes from:plist.bytes size:plist.length]) {
            failureStage = @"remote-transfer";
        }
    }

    uint64_t remoteData = 0;
    uint64_t remoteDictionary = 0;
    if (!failureStage && dictionaryMode) {
        uint64_t dataClass = r_session_class(installd, "NSData");
        remoteData = r_session_msg2(installd, dataClass, "dataWithBytes:length:",
                                    remoteBytes, plist.length, 0, 0);
        if (!r_is_objc_ptr(remoteData)) failureStage = @"remote-data";
    }
    if (remoteBytes && cnd_ls_session_healthy(installd)) {
        (void)r_session_dlsym_call(installd, 5, "free", remoteBytes,
                                   0, 0, 0, 0, 0, 0, 0);
    }

    if (!failureStage && dictionaryMode) {
        uint64_t plistClass = r_session_class(installd, "NSPropertyListSerialization");
        remoteDictionary = r_session_msg2(
            installd, plistClass, "propertyListWithData:options:format:error:",
            remoteData, 0, 0, 0);
        if (!r_is_objc_ptr(remoteDictionary)) {
            failureStage = @"remote-deserialization";
        }
    }

    if (!failureStage && !dictionaryMode) {
        remotePathBytes = r_session_alloc_str(installd, path.fileSystemRepresentation);
        uint64_t stringClass = r_session_class(installd, "NSString");
        remotePathString = remotePathBytes ? r_session_msg2(
            installd, stringClass, "stringWithUTF8String:",
            remotePathBytes, 0, 0, 0) : 0;
        if (!r_is_objc_ptr(remotePathString)) {
            failureStage = @"remote-path";
        }
    }
    if (remotePathBytes && cnd_ls_session_healthy(installd)) {
        r_session_free(installd, remotePathBytes);
    }
    if (!failureStage && !dictionaryMode) {
        uint64_t urlClass = r_session_class(installd, "NSURL");
        remoteBundleURL = r_session_msg2(
            installd, urlClass, "fileURLWithPath:isDirectory:",
            remotePathString, 1, 0, 0);
        if (!r_is_objc_ptr(remoteBundleURL)) {
            failureStage = @"remote-bundle-url";
        }
    }

    uint64_t workspace = 0;
    if (!failureStage && !cnd_ls_remote_load_coreservices(installd)) {
        failureStage = @"coreservices";
    }
    if (!failureStage) {
        uint64_t workspaceClass = r_session_class(installd, "LSApplicationWorkspace");
        workspace = r_session_msg2(installd, workspaceClass,
                                   "defaultWorkspace", 0, 0, 0, 0);
        if (!r_is_objc_ptr(workspace) ||
            !r_session_responds(installd, workspace,
                dictionaryMode ? "registerApplicationDictionary:"
                               : "registerApplication:")) {
            failureStage = @"workspace";
        }
    }
    if (!failureStage) {
        registrationReturn = r_session_msg2(
            installd, workspace,
            dictionaryMode ? "registerApplicationDictionary:"
                           : "registerApplication:",
            dictionaryMode ? remoteDictionary : remoteBundleURL,
            0, 0, 0);
        if (!cnd_ls_session_healthy(installd)) {
            failureStage = @"registration-transport";
        }
    }

    if (pool && cnd_ls_session_healthy(installd)) {
        (void)r_session_dlsym_call(installd, 5, "objc_autoreleasePoolPop",
                                   pool, 0, 0, 0, 0, 0, 0, 0);
    }

    NSDictionary<NSString *, id> *finalization =
        cnd_ls_finalize_session(installd);
    NSMutableDictionary<NSString *, id> *details = [finalization mutableCopy];
    if (bundleIdentifier.length > 0) {
        details[@"bundleIdentifier"] = bundleIdentifier;
    }
    details[@"path"] = path;
    details[@"registrationMode"] = dictionaryMode ? @"dictionary" : @"bundle-url";
    if (dictionaryMode) details[@"plistBytes"] = @(plist.length);
    details[@"registrationAccepted"] = @(registrationReturn != 0);
    details[@"promptMessages"] = @(promptMessageSnapshot);
    details[@"promptReplies"] = @(promptReplySnapshot);
    details[@"promptLastEvent"] = promptEventSnapshot;
    details[@"wake"] = wake;

    if (failureStage) {
        return cnd_ls_result(NO, failureStage,
            @"the installd registration operation did not complete", details);
    }
    if (registrationReturn == 0) {
        return cnd_ls_result(NO, @"registration-rejected",
            dictionaryMode
                ? @"LaunchServices rejected the registration dictionary"
                : @"LaunchServices rejected the installed application bundle URL",
            details);
    }
    if (!cnd_ls_finalization_succeeded(finalization)) {
        return cnd_ls_result(NO, @"transport-finalization",
            @"LaunchServices accepted the registration, but the installd RemoteCall session did not close cleanly",
            details);
    }

    return cnd_ls_result(YES, @"registered",
        dictionaryMode
            ? @"LaunchServices accepted the registration from stock installd"
            : @"LaunchServices rebuilt the installed application registration from its bundle URL",
        details);
}

NSDictionary<NSString *, id> *CNDLaunchServicesRegisterViaInstalld(
    NSDictionary<NSString *, id> *registrationDictionary)
{
    return cnd_ls_register_via_installd(registrationDictionary, nil);
}

NSDictionary<NSString *, id> *
CNDLaunchServicesRegisterBundleURLViaInstalld(NSString *bundlePath)
{
    return cnd_ls_register_via_installd(nil, bundlePath);
}

static BOOL cnd_ls_is_direct_bundle_leaf(NSString *path)
{
    if (![path isKindOfClass:NSString.class] || path.length == 0 ||
        ![path isAbsolutePath] ||
        ![path.stringByStandardizingPath isEqual:path]) return NO;
    NSString *leaf = path.lastPathComponent;
    NSString *bundle = path.stringByDeletingLastPathComponent;
    if (leaf.length == 0 || [leaf isEqual:@"."] || [leaf isEqual:@".."] ||
        [leaf rangeOfString:@"/"].location != NSNotFound ||
        ![bundle.pathExtension.lowercaseString isEqual:@"app"]) return NO;
    NSString *extension = leaf.pathExtension.lowercaseString;
    return [extension isEqual:@"png"] || [extension isEqual:@"plist"];
}

NSDictionary<NSString *, id> *
CNDLaunchServicesOverwriteExistingBundleFileViaInstalld(
    NSString *targetPath, NSData *contents)
{
    if (!remote_call_lab_backend_opted_in()) {
        return cnd_ls_result(NO, @"lab-only",
            @"the direct installd existing-file writer is restricted to the explicit vPhone lab backend",
            nil);
    }
    if (!cnd_ls_is_direct_bundle_leaf(targetPath) ||
        ![contents isKindOfClass:NSData.class] || contents.length == 0 ||
        contents.length > CNDLSMaxRegistrationPlistBytes) {
        return cnd_ls_result(NO, @"validation",
            @"the vPhone existing-file target or payload is invalid", nil);
    }

    RemoteCallSession *installd = cnd_ls_current_retained_session();
    BOOL usesRetainedSession = installd != nil;
    NSDictionary<NSString *, id> *wake = usesRetainedSession
        ? cnd_ls_current_retained_wake() : nil;
    if (!installd) {
        NSDictionary<NSString *, id> *openFailure = nil;
        installd = cnd_ls_open_prompted_installd_session(&wake, &openFailure);
        if (!installd) return openFailure ?: cnd_ls_result(
            NO, @"remote-session", @"could not open installd", nil);
    }

    NSString *failureStage = nil;
    uint64_t remotePath = r_session_alloc_str(
        installd, targetPath.fileSystemRepresentation);
    uint64_t remoteBytes = 0;
    int fileDescriptor = -1;
    NSUInteger bytesWritten = 0;
    NSUInteger bytesRead = 0;
    int64_t observedLength = -1;
    NSMutableData *readback = nil;

    if (!remotePath) {
        failureStage = @"remote-path";
    } else {
        fileDescriptor = (int32_t)r_session_dlsym_call(
            installd, 5, "open", remotePath, O_RDWR | O_NOFOLLOW,
            0, 0, 0, 0, 0, 0);
        if (fileDescriptor < 0 || !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-open";
        }
    }
    if (!failureStage) {
        observedLength = (int64_t)r_session_dlsym_call(
            installd, 5, "lseek", (uint64_t)fileDescriptor, 0, SEEK_END,
            0, 0, 0, 0, 0);
        if (observedLength != (int64_t)contents.length ||
            !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-length";
        }
    }
    if (!failureStage) {
        remoteBytes = r_session_dlsym_call(
            installd, 5, "malloc", contents.length,
            0, 0, 0, 0, 0, 0, 0);
        if (!remoteBytes ||
            ![installd remoteWrite:remoteBytes
                              from:contents.bytes
                              size:contents.length]) {
            failureStage = @"remote-transfer";
        }
    }
    if (!failureStage) {
        int64_t seekResult = (int64_t)r_session_dlsym_call(
            installd, 5, "lseek", (uint64_t)fileDescriptor, 0, SEEK_SET,
            0, 0, 0, 0, 0);
        if (seekResult != 0 || !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-seek";
        }
    }
    while (!failureStage && bytesWritten < contents.length) {
        uint64_t remaining = contents.length - bytesWritten;
        int64_t amount = (int64_t)r_session_dlsym_call(
            installd, 5, "write", (uint64_t)fileDescriptor,
            remoteBytes + bytesWritten, remaining, 0, 0, 0, 0, 0);
        if (amount <= 0 || (uint64_t)amount > remaining ||
            !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-write";
        } else {
            bytesWritten += (NSUInteger)amount;
        }
    }
    if (!failureStage) {
        int fsyncResult = (int32_t)r_session_dlsym_call(
            installd, 5, "fsync", (uint64_t)fileDescriptor,
            0, 0, 0, 0, 0, 0, 0);
        if (fsyncResult != 0 || !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-fsync";
        }
    }
    if (!failureStage) {
        int64_t seekResult = (int64_t)r_session_dlsym_call(
            installd, 5, "lseek", (uint64_t)fileDescriptor, 0, SEEK_SET,
            0, 0, 0, 0, 0);
        if (seekResult != 0 || !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-readback-seek";
        }
    }
    while (!failureStage && bytesRead < contents.length) {
        uint64_t remaining = contents.length - bytesRead;
        int64_t amount = (int64_t)r_session_dlsym_call(
            installd, 5, "read", (uint64_t)fileDescriptor,
            remoteBytes + bytesRead, remaining, 0, 0, 0, 0, 0);
        if (amount <= 0 || (uint64_t)amount > remaining ||
            !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-readback-read";
        } else {
            bytesRead += (NSUInteger)amount;
        }
    }
    if (!failureStage) {
        readback = [NSMutableData dataWithLength:contents.length];
        if (![installd remoteRead:remoteBytes
                              to:readback.mutableBytes
                            size:readback.length] ||
            ![readback isEqualToData:contents]) {
            failureStage = @"remote-readback-compare";
        }
    }

    if (fileDescriptor >= 0 && cnd_ls_session_healthy(installd)) {
        int closeResult = (int32_t)r_session_dlsym_call(
            installd, 5, "close", (uint64_t)fileDescriptor,
            0, 0, 0, 0, 0, 0, 0);
        if (!failureStage && closeResult != 0) failureStage = @"remote-close";
    }
    if (remoteBytes && cnd_ls_session_healthy(installd)) {
        (void)r_session_dlsym_call(
            installd, 5, "free", remoteBytes, 0, 0, 0, 0, 0, 0, 0);
    }
    if (remotePath && cnd_ls_session_healthy(installd)) {
        r_session_free(installd, remotePath);
    }

    BOOL retainedHealthy = usesRetainedSession
        ? cnd_ls_session_healthy(installd) : NO;
    NSDictionary<NSString *, id> *finalization = usesRetainedSession
        ? @{
            @"pid": @(installd.pid),
            @"transport": retainedHealthy ? @"healthy" : @"failed",
            @"teardown": @0,
            @"teardownMode": @"retained",
            @"localStateRemaining": @YES,
        }
        : cnd_ls_finalize_session(installd);
    NSMutableDictionary<NSString *, id> *details = [finalization mutableCopy];
    details[@"path"] = targetPath;
    details[@"bytes"] = @(contents.length);
    details[@"bytesWritten"] = @(bytesWritten);
    details[@"bytesRead"] = @(bytesRead);
    details[@"observedLength"] = @(observedLength);
    details[@"wake"] = wake ?: @{};
    if (readback) details[@"data"] = readback;

    if (failureStage) {
        return cnd_ls_result(NO, failureStage,
            @"the vPhone installd endpoint could not overwrite and verify the existing vnode",
            details);
    }
    if ((!usesRetainedSession &&
         !cnd_ls_finalization_succeeded(finalization)) ||
        (usesRetainedSession && !retainedHealthy)) {
        return cnd_ls_result(NO, @"transport-finalization",
            @"the existing vnode was overwritten, but the vPhone installd transport did not remain healthy",
            details);
    }
    return cnd_ls_result(YES, @"existing-vnode-overwritten",
        @"the vPhone installd endpoint overwrote and exactly read back the existing vnode",
        details);
}

static NSDictionary<NSString *, id> *cnd_ls_mutate_absent_icon_via_installd(
    NSString *targetPath, NSData * _Nullable contents, BOOL remove)
{
    if (!cnd_ls_is_direct_bundle_icon_path(targetPath)) {
        return cnd_ls_result(NO, @"validation",
            @"the installd icon path is not a direct PNG child of an application bundle",
            nil);
    }
    if (!remove &&
        (![contents isKindOfClass:NSData.class] || contents.length == 0 ||
         contents.length > CNDLSMaxRegistrationPlistBytes)) {
        return cnd_ls_result(NO, @"validation",
            @"the absent icon payload is empty or too large", nil);
    }

    RemoteCallSession *installd = cnd_ls_current_retained_session();
    BOOL usesRetainedSession = installd != nil;
    NSDictionary<NSString *, id> *wake = usesRetainedSession
        ? cnd_ls_current_retained_wake() : nil;
    if (!installd) {
        NSDictionary<NSString *, id> *openFailure = nil;
        installd = cnd_ls_open_prompted_installd_session(
            &wake, &openFailure);
        if (!installd) return openFailure ?: cnd_ls_result(
            NO, @"remote-session", @"could not open installd", nil);
    }

    NSString *failureStage = nil;
    uint64_t remotePath = r_session_alloc_str(
        installd, targetPath.fileSystemRepresentation);
    uint64_t remoteBytes = 0;
    int fileDescriptor = -1;
    NSUInteger bytesWritten = 0;
    NSUInteger bytesRead = 0;
    int64_t observedLength = -1;
    int operationReturn = -1;
    NSMutableData *readback = nil;

    if (!remotePath) {
        failureStage = @"remote-path";
    } else if (remove) {
        operationReturn = (int32_t)r_session_dlsym_call(
            installd, 5, "unlink", remotePath, 0, 0, 0, 0, 0, 0, 0);
        if (operationReturn != 0 || !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-unlink";
        }
    } else {
        remoteBytes = r_session_dlsym_call(
            installd, 5, "malloc", contents.length + 1,
            0, 0, 0, 0, 0, 0, 0);
        if (!remoteBytes ||
            ![installd remoteWrite:remoteBytes
                              from:contents.bytes
                              size:contents.length]) {
            failureStage = @"remote-transfer";
        }
        if (!failureStage) {
            fileDescriptor = (int32_t)r_session_dlsym_call(
                installd, 5, "open", remotePath,
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0644,
                0, 0, 0, 0, 0);
            if (fileDescriptor < 0 || !cnd_ls_session_healthy(installd)) {
                failureStage = @"remote-open";
            }
        }
        while (!failureStage && bytesWritten < contents.length) {
            uint64_t remaining = contents.length - bytesWritten;
            int64_t amount = (int64_t)r_session_dlsym_call(
                installd, 5, "write", (uint64_t)fileDescriptor,
                remoteBytes + bytesWritten, remaining, 0, 0, 0, 0, 0);
            if (amount <= 0 || (uint64_t)amount > remaining ||
                !cnd_ls_session_healthy(installd)) {
                failureStage = @"remote-write";
            } else {
                bytesWritten += (NSUInteger)amount;
            }
        }
        if (!failureStage) {
            operationReturn = (int32_t)r_session_dlsym_call(
                installd, 5, "fsync", (uint64_t)fileDescriptor,
                0, 0, 0, 0, 0, 0, 0);
            if (operationReturn != 0 || !cnd_ls_session_healthy(installd)) {
                failureStage = @"remote-fsync";
            }
        }
        if (!failureStage) {
            observedLength = (int64_t)r_session_dlsym_call(
                installd, 5, "lseek", (uint64_t)fileDescriptor,
                0, SEEK_END, 0, 0, 0, 0, 0);
            if (observedLength != (int64_t)contents.length ||
                !cnd_ls_session_healthy(installd)) {
                failureStage = @"remote-readback-length";
            }
        }
        if (!failureStage) {
            int64_t seekResult = (int64_t)r_session_dlsym_call(
                installd, 5, "lseek", (uint64_t)fileDescriptor,
                0, SEEK_SET, 0, 0, 0, 0, 0);
            if (seekResult != 0 || !cnd_ls_session_healthy(installd)) {
                failureStage = @"remote-readback-seek";
            }
        }
        while (!failureStage && bytesRead < contents.length) {
            uint64_t remaining = contents.length - bytesRead;
            int64_t amount = (int64_t)r_session_dlsym_call(
                installd, 5, "read", (uint64_t)fileDescriptor,
                remoteBytes + bytesRead, remaining, 0, 0, 0, 0, 0);
            if (amount <= 0 || (uint64_t)amount > remaining ||
                !cnd_ls_session_healthy(installd)) {
                failureStage = @"remote-readback-read";
            } else {
                bytesRead += (NSUInteger)amount;
            }
        }
        if (!failureStage) {
            int64_t trailing = (int64_t)r_session_dlsym_call(
                installd, 5, "read", (uint64_t)fileDescriptor,
                remoteBytes + contents.length, 1, 0, 0, 0, 0, 0);
            if (trailing != 0 || !cnd_ls_session_healthy(installd)) {
                failureStage = @"remote-readback-eof";
            }
        }
        if (!failureStage) {
            readback = [NSMutableData dataWithLength:contents.length];
            if (![installd remoteRead:remoteBytes
                                  to:readback.mutableBytes
                                size:readback.length]) {
                readback = nil;
                failureStage = @"remote-readback-transfer";
            } else if (![readback isEqualToData:contents]) {
                failureStage = @"remote-readback-compare";
            }
        }
        if (fileDescriptor >= 0 && cnd_ls_session_healthy(installd)) {
            int closeReturn = (int32_t)r_session_dlsym_call(
                installd, 5, "close", (uint64_t)fileDescriptor,
                0, 0, 0, 0, 0, 0, 0);
            if (!failureStage && closeReturn != 0) {
                failureStage = @"remote-close";
            }
        }
        if (failureStage && fileDescriptor >= 0 &&
            cnd_ls_session_healthy(installd)) {
            // O_EXCL proves this session created the leaf. Best-effort cleanup
            // prevents a short write from becoming a valid transaction file.
            (void)r_session_dlsym_call(
                installd, 5, "unlink", remotePath, 0, 0, 0, 0, 0, 0, 0);
        }
    }

    if (remoteBytes && cnd_ls_session_healthy(installd)) {
        (void)r_session_dlsym_call(
            installd, 5, "free", remoteBytes, 0, 0, 0, 0, 0, 0, 0);
    }
    if (remotePath && cnd_ls_session_healthy(installd)) {
        r_session_free(installd, remotePath);
    }

    BOOL retainedTransportHealthy = usesRetainedSession
        ? cnd_ls_session_healthy(installd) : NO;
    NSDictionary<NSString *, id> *finalization = usesRetainedSession
        ? @{
            @"pid": @(installd.pid),
            @"transport": retainedTransportHealthy ? @"healthy" : @"failed",
            @"teardown": @0,
            @"teardownMode": @"retained",
            @"localStateRemaining": @YES,
        }
        : cnd_ls_finalize_session(installd);
    NSMutableDictionary<NSString *, id> *details = [finalization mutableCopy];
    details[@"path"] = targetPath;
    details[@"operation"] = remove ? @"remove-created-icon" : @"create-absent-icon";
    details[@"bytes"] = @(remove ? 0 : contents.length);
    details[@"bytesWritten"] = @(bytesWritten);
    details[@"observedLength"] = @(observedLength);
    details[@"bytesRead"] = @(bytesRead);
    if (readback) details[@"data"] = readback;
    details[@"wake"] = wake ?: @{};

    if (failureStage) {
        return cnd_ls_result(NO, failureStage,
            remove
                ? @"stock installd could not remove the transaction-created icon"
                : @"stock installd could not create the absent icon",
            details);
    }
    if ((!usesRetainedSession &&
         !cnd_ls_finalization_succeeded(finalization)) ||
        (usesRetainedSession && !retainedTransportHealthy)) {
        return cnd_ls_result(NO, @"transport-finalization",
            remove
                ? @"installd removed the icon, but its RemoteCall session did not close cleanly"
                : @"installd created the icon, but its RemoteCall session did not close cleanly",
            details);
    }
    return cnd_ls_result(YES, remove ? @"icon-removed" : @"icon-created",
        remove
            ? @"stock installd removed the transaction-created icon"
            : @"stock installd created, fsynced, and exactly read back the absent icon on one descriptor",
        details);
}

NSDictionary<NSString *, id> *
CNDLaunchServicesCreateAbsentBundleIconViaInstalld(
    NSString *targetPath, NSData *contents)
{
    return cnd_ls_mutate_absent_icon_via_installd(
        targetPath, contents, NO);
}

NSDictionary<NSString *, id> *
CNDLaunchServicesReadBundleIconViaInstalld(
    NSString *targetPath, NSUInteger expectedLength)
{
    if (!cnd_ls_is_direct_bundle_icon_path(targetPath) ||
        expectedLength == 0 || expectedLength > CNDLSMaxRegistrationPlistBytes) {
        return cnd_ls_result(NO, @"validation",
            @"the installd icon read path or expected length is invalid", nil);
    }

    RemoteCallSession *installd = cnd_ls_current_retained_session();
    BOOL usesRetainedSession = installd != nil;
    NSDictionary<NSString *, id> *wake = usesRetainedSession
        ? cnd_ls_current_retained_wake() : nil;
    if (!installd) {
        NSDictionary<NSString *, id> *openFailure = nil;
        installd = cnd_ls_open_prompted_installd_session(&wake, &openFailure);
        if (!installd) return openFailure ?: cnd_ls_result(
            NO, @"remote-session", @"could not open installd", nil);
    }

    NSString *failureStage = nil;
    uint64_t remotePath = r_session_alloc_str(
        installd, targetPath.fileSystemRepresentation);
    uint64_t remoteBytes = 0;
    int fileDescriptor = -1;
    NSUInteger bytesRead = 0;
    int64_t observedLength = -1;
    NSMutableData *data = nil;

    if (!remotePath) {
        failureStage = @"remote-path";
    } else {
        fileDescriptor = (int32_t)r_session_dlsym_call(
            installd, 5, "open", remotePath, O_RDONLY | O_NOFOLLOW,
            0, 0, 0, 0, 0, 0);
        if (fileDescriptor < 0 || !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-open";
        }
    }
    if (!failureStage) {
        observedLength = (int64_t)r_session_dlsym_call(
            installd, 5, "lseek", (uint64_t)fileDescriptor, 0, SEEK_END,
            0, 0, 0, 0, 0);
        if (observedLength != (int64_t)expectedLength ||
            !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-length";
        }
    }
    if (!failureStage) {
        int64_t seekResult = (int64_t)r_session_dlsym_call(
            installd, 5, "lseek", (uint64_t)fileDescriptor, 0, SEEK_SET,
            0, 0, 0, 0, 0);
        if (seekResult != 0 || !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-seek";
        }
    }
    if (!failureStage) {
        remoteBytes = r_session_dlsym_call(
            installd, 5, "malloc", expectedLength + 1,
            0, 0, 0, 0, 0, 0, 0);
        if (!remoteBytes || !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-buffer";
        }
    }
    while (!failureStage && bytesRead < expectedLength) {
        uint64_t remaining = expectedLength - bytesRead;
        int64_t amount = (int64_t)r_session_dlsym_call(
            installd, 5, "read", (uint64_t)fileDescriptor,
            remoteBytes + bytesRead, remaining, 0, 0, 0, 0, 0);
        if (amount <= 0 || (uint64_t)amount > remaining ||
            !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-read";
        } else {
            bytesRead += (NSUInteger)amount;
        }
    }
    if (!failureStage) {
        int64_t trailing = (int64_t)r_session_dlsym_call(
            installd, 5, "read", (uint64_t)fileDescriptor,
            remoteBytes + expectedLength, 1, 0, 0, 0, 0, 0);
        if (trailing != 0 || !cnd_ls_session_healthy(installd)) {
            failureStage = @"remote-eof";
        }
    }
    if (!failureStage) {
        data = [NSMutableData dataWithLength:expectedLength];
        if (![installd remoteRead:remoteBytes
                              to:data.mutableBytes
                            size:data.length]) {
            data = nil;
            failureStage = @"remote-transfer";
        }
    }

    if (fileDescriptor >= 0 && cnd_ls_session_healthy(installd)) {
        int closeReturn = (int32_t)r_session_dlsym_call(
            installd, 5, "close", (uint64_t)fileDescriptor,
            0, 0, 0, 0, 0, 0, 0);
        if (!failureStage && closeReturn != 0) failureStage = @"remote-close";
    }
    if (remoteBytes && cnd_ls_session_healthy(installd)) {
        (void)r_session_dlsym_call(
            installd, 5, "free", remoteBytes, 0, 0, 0, 0, 0, 0, 0);
    }
    if (remotePath && cnd_ls_session_healthy(installd)) {
        r_session_free(installd, remotePath);
    }

    BOOL retainedTransportHealthy = usesRetainedSession
        ? cnd_ls_session_healthy(installd) : NO;
    NSDictionary<NSString *, id> *finalization = usesRetainedSession
        ? @{
            @"pid": @(installd.pid),
            @"transport": retainedTransportHealthy ? @"healthy" : @"failed",
            @"teardown": @0,
            @"teardownMode": @"retained",
            @"localStateRemaining": @YES,
        }
        : cnd_ls_finalize_session(installd);
    NSMutableDictionary<NSString *, id> *details = [finalization mutableCopy];
    details[@"path"] = targetPath;
    details[@"operation"] = @"read-created-icon";
    details[@"expectedLength"] = @(expectedLength);
    details[@"observedLength"] = @(observedLength);
    details[@"bytesRead"] = @(bytesRead);
    details[@"wake"] = wake ?: @{};

    if (failureStage) {
        return cnd_ls_result(NO, failureStage,
            @"stock installd could not read back the created icon", details);
    }
    if ((!usesRetainedSession &&
         !cnd_ls_finalization_succeeded(finalization)) ||
        (usesRetainedSession && !retainedTransportHealthy)) {
        return cnd_ls_result(NO, @"transport-finalization",
            @"installd read the icon, but its RemoteCall session did not close cleanly",
            details);
    }
    details[@"data"] = data;
    return cnd_ls_result(YES, @"icon-read",
        @"stock installd read back the created icon exactly", details);
}

NSDictionary<NSString *, id> *
CNDLaunchServicesRemoveCreatedBundleIconViaInstalld(NSString *targetPath)
{
    return cnd_ls_mutate_absent_icon_via_installd(
        targetPath, nil, YES);
}
