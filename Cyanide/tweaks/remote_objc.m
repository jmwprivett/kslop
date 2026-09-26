//
//  remote_objc.m
//

#import "remote_objc.h"
#import "../TaskRop/RemoteCall.h"
#import <dlfcn.h>
#import <pthread.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

extern uint64_t remote_read64(uint64_t src);

// Settle policy belongs to the local caller. Long-running SpringBoard loops
// and a fast, synchronous installd batch may execute concurrently; one must
// not silently change the other's pacing.
static __thread useconds_t gSettleUS = 50000;

#define R_OBJC_CACHE_CAP 192
#define R_OBJC_CACHE_NAME_MAX 96

typedef struct {
    int pid;
    char name[R_OBJC_CACHE_NAME_MAX];
    uint64_t value;
} RemoteObjCCacheEntry;

static pthread_mutex_t gObjCCacheLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t gRemoteCallLock = PTHREAD_MUTEX_INITIALIZER;
static RemoteObjCCacheEntry gSelCache[R_OBJC_CACHE_CAP];
static RemoteObjCCacheEntry gClassCache[R_OBJC_CACHE_CAP];
static int gSelCacheNext = 0;
static int gClassCacheNext = 0;

static bool r_cacheable_name(const char *name)
{
    return name && name[0] && strlen(name) < R_OBJC_CACHE_NAME_MAX;
}

static uint64_t r_cache_lookup(RemoteObjCCacheEntry *cache, int pid, const char *name)
{
    if (pid <= 0 || !r_cacheable_name(name)) return 0;

    uint64_t value = 0;
    pthread_mutex_lock(&gObjCCacheLock);
    for (int i = 0; i < R_OBJC_CACHE_CAP; i++) {
        if (cache[i].pid == pid && cache[i].value && strcmp(cache[i].name, name) == 0) {
            value = cache[i].value;
            break;
        }
    }
    pthread_mutex_unlock(&gObjCCacheLock);
    return value;
}

static void r_cache_store(RemoteObjCCacheEntry *cache, int *nextSlot, int pid, const char *name, uint64_t value)
{
    if (pid <= 0 || !value || !r_cacheable_name(name)) return;

    pthread_mutex_lock(&gObjCCacheLock);
    for (int i = 0; i < R_OBJC_CACHE_CAP; i++) {
        if (cache[i].pid == pid && strcmp(cache[i].name, name) == 0) {
            cache[i].value = value;
            pthread_mutex_unlock(&gObjCCacheLock);
            return;
        }
    }

    int slot = -1;
    for (int i = 0; i < R_OBJC_CACHE_CAP; i++) {
        if (cache[i].pid == 0 || cache[i].value == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        slot = *nextSlot;
        *nextSlot = (*nextSlot + 1) % R_OBJC_CACHE_CAP;
    }

    cache[slot].pid = pid;
    strncpy(cache[slot].name, name, sizeof(cache[slot].name) - 1);
    cache[slot].name[sizeof(cache[slot].name) - 1] = '\0';
    cache[slot].value = value;
    pthread_mutex_unlock(&gObjCCacheLock);
}

static void r_settle(void)
{
    if (gSettleUS) usleep(gSettleUS);
}

static uint64_t r_call_stable(int timeout, const char *fnName,
                              uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                              uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
    // Once a stable call times out, the synthetic thread's exception state is
    // no longer trustworthy.  Continuing to feed it calls is much more likely
    // to destabilize the target than to recover the operation.
    if (!remote_call_current_success()) return 0;

    pthread_mutex_lock(&gRemoteCallLock);
    uint64_t ret = 0;
    if (remote_call_current_success()) {
        ret = do_remote_call_stable(timeout, fnName,
                                    a0, a1, a2, a3,
                                    a4, a5, a6, a7);
    }
    pthread_mutex_unlock(&gRemoteCallLock);
    return ret;
}

static uint64_t r_call_stable_addr(int timeout, uint64_t address,
                                   const char *diagnosticName,
                                   uint64_t a0, uint64_t a1, uint64_t a2,
                                   uint64_t a3, uint64_t a4, uint64_t a5,
                                   uint64_t a6, uint64_t a7)
{
    if (!remote_call_current_success() || !address) return 0;

    pthread_mutex_lock(&gRemoteCallLock);
    uint64_t ret = 0;
    if (remote_call_current_success()) {
        ret = do_remote_call_stable_addr(
            timeout, address, diagnosticName,
            a0, a1, a2, a3, a4, a5, a6, a7);
    }
    pthread_mutex_unlock(&gRemoteCallLock);
    return ret;
}

uint32_t r_settle_us(uint32_t usec)
{
    uint32_t old = (uint32_t)gSettleUS;
    gSettleUS = (useconds_t)usec;
    return old;
}

bool r_is_objc_ptr(uint64_t ptr)
{
    return ptr >= 0x100000000ULL;
}

uint64_t r_dlsym_call(int timeout, const char *fnName,
                      uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                      uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
    return r_call_stable(timeout, fnName, a0, a1, a2, a3, a4, a5, a6, a7);
}

uint64_t r_autorelease_pool_push(void)
{
    return r_dlsym_call(R_TIMEOUT, "objc_autoreleasePoolPush",
                        0, 0, 0, 0, 0, 0, 0, 0);
}

bool r_autorelease_pool_pop(uint64_t token)
{
    if (!token || !remote_call_current_success()) return false;
    (void)r_dlsym_call(R_TIMEOUT, "objc_autoreleasePoolPop",
                       token, 0, 0, 0, 0, 0, 0, 0);
    return remote_call_current_success();
}

uint64_t r_alloc_str(const char *s)
{
    if (!s) return 0;
    uint64_t len = strlen(s) + 1;
    uint64_t buf = r_call_stable(R_TIMEOUT, "malloc", len, 0, 0, 0, 0, 0, 0, 0);
    if (buf && !remote_writeStr(buf, s)) {
        (void)r_call_stable(R_TIMEOUT, "free", buf, 0, 0, 0, 0, 0, 0, 0);
        return 0;
    }
    return buf;
}

void r_free(uint64_t ptr)
{
    if (!ptr) return;
    r_call_stable(R_TIMEOUT, "free", ptr, 0, 0, 0, 0, 0, 0, 0);
}

uint64_t r_sel(const char *name)
{
    int pid = remote_call_current_pid();
    uint64_t cached = r_cache_lookup(gSelCache, pid, name);
    if (cached) return cached;

    uint64_t s = r_alloc_str(name);
    if (!s) return 0;
    uint64_t sel = r_call_stable(R_TIMEOUT, "sel_registerName", s, 0, 0, 0, 0, 0, 0, 0);
    r_free(s);
    r_cache_store(gSelCache, &gSelCacheNext, pid, name, sel);
    return sel;
}

uint64_t r_class(const char *name)
{
    int pid = remote_call_current_pid();
    uint64_t cached = r_cache_lookup(gClassCache, pid, name);
    if (cached) return cached;

    uint64_t s = r_alloc_str(name);
    if (!s) return 0;
    uint64_t c = r_call_stable(R_TIMEOUT, "objc_getClass", s, 0, 0, 0, 0, 0, 0, 0);
    r_free(s);
    r_cache_store(gClassCache, &gClassCacheNext, pid, name, c);
    return c;
}

uint64_t r_msg(uint64_t obj, uint64_t sel,
               uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    if (!obj || !sel) return 0;
    return r_call_stable(R_TIMEOUT, "objc_msgSend",
                         obj, sel, a0, a1, a2, a3, 0, 0);
}

static uint64_t r_msg_named(uint64_t obj, uint64_t sel,
                            const char *selectorName,
                            uint64_t a0, uint64_t a1,
                            uint64_t a2, uint64_t a3)
{
    if (!obj || !sel) return 0;
    if (remote_call_uses_lab_backend() || !selectorName) {
        return r_msg(obj, sel, a0, a1, a2, a3);
    }

    uint64_t address = (uint64_t)dlsym(RTLD_DEFAULT, "objc_msgSend");
    if (!address) return 0;
    char diagnostic[192] = {0};
    snprintf(diagnostic, sizeof(diagnostic),
             "objc_msgSend:%s", selectorName);
    return r_call_stable_addr(
        R_TIMEOUT, address, diagnostic,
        obj, sel, a0, a1, a2, a3, 0, 0);
}

uint64_t r_msg2(uint64_t obj, const char *selName,
                uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    if (!obj || !selName) return 0;
    uint64_t sel = r_sel(selName);
    if (!sel) return 0;
    r_settle();
    return r_msg_named(obj, sel, selName, a0, a1, a2, a3);
}

static uint64_t r_method_signature(uint64_t obj, uint64_t sel)
{
    if (!r_is_objc_ptr(obj) || !sel) return 0;

    uint64_t sigSel = r_sel("methodSignatureForSelector:");
    uint64_t sig = r_msg(obj, sigSel, sel, 0, 0, 0);
    if (r_is_objc_ptr(sig)) return sig;

    uint64_t cls = r_call_stable(R_TIMEOUT, "object_getClass",
                                 obj, 0, 0, 0, 0, 0, 0, 0);
    if (!r_is_objc_ptr(cls)) return 0;

    uint64_t method = r_call_stable(R_TIMEOUT, "class_getInstanceMethod",
                                    cls, sel, 0, 0, 0, 0, 0, 0);
    if (!method) return 0;

    uint64_t types = r_call_stable(R_TIMEOUT, "method_getTypeEncoding",
                                   method, 0, 0, 0, 0, 0, 0, 0);
    if (!types) return 0;

    uint64_t NSMethodSignature = r_class("NSMethodSignature");
    if (!r_is_objc_ptr(NSMethodSignature)) return 0;
    return r_msg2(NSMethodSignature, "signatureWithObjCTypes:", types, 0, 0, 0);
}

static bool r_write_remote_arg(uint64_t remoteBuf, const void *arg, size_t argSize, size_t remoteSize)
{
    if (!remoteBuf || remoteSize == 0) return false;

    uint8_t stackBuf[64];
    void *localBuf = stackBuf;
    if (remoteSize > sizeof(stackBuf)) {
        localBuf = calloc(1, remoteSize);
        if (!localBuf) return false;
    } else {
        memset(stackBuf, 0, remoteSize);
    }

    if (arg && argSize) {
        size_t copySize = (argSize < remoteSize) ? argSize : remoteSize;
        memcpy(localBuf, arg, copySize);
    }

    bool ok = remote_write(remoteBuf, localBuf, remoteSize);
    if (localBuf != stackBuf) free(localBuf);
    return ok;
}

static uint64_t r_msg_main_raw_internal(uint64_t obj, uint64_t sel,
                                        const void *a0, size_t a0Size,
                                        const void *a1, size_t a1Size,
                                        const void *a2, size_t a2Size,
                                        const void *a3, size_t a3Size,
                                        bool retainObjectReturn,
                                        bool forceTargetMainThread,
                                        bool forceCurrentThread)
{
    if (!r_is_objc_ptr(obj) || !sel) return 0;

    uint64_t sig = r_method_signature(obj, sel);
    if (!r_is_objc_ptr(sig)) return 0;

    uint64_t NSInvocation = r_class("NSInvocation");
    if (!r_is_objc_ptr(NSInvocation)) return 0;

    uint64_t inv = r_msg2(NSInvocation, "invocationWithMethodSignature:", sig, 0, 0, 0);
    if (!r_is_objc_ptr(inv)) return 0;

    uint64_t retainedInv = r_msg2(inv, "retain", 0, 0, 0, 0);
    if (r_is_objc_ptr(retainedInv)) inv = retainedInv;

    uint64_t retLen = r_msg2(sig, "methodReturnLength", 0, 0, 0, 0);
    if (!remote_call_current_success()) {
        r_msg2(inv, "release", 0, 0, 0, 0);
        return 0;
    }
    if (retainObjectReturn) {
        // This mode is only valid for a pointer-sized Objective-C object
        // return. Compare the encoding inside the target process so shared
        // cache type strings never have to be mapped into Cyanide.
        uint64_t encodedType = r_msg2(sig, "methodReturnType", 0, 0, 0, 0);
        uint64_t expectedType = r_alloc_str("@");
        bool isObjectReturn = retLen == sizeof(uint64_t) && encodedType &&
            expectedType &&
            r_call_stable(R_TIMEOUT, "strcmp", encodedType, expectedType,
                          0, 0, 0, 0, 0, 0) == 0 &&
            remote_call_current_success();
        if (expectedType) r_free(expectedType);
        if (!isObjectReturn || !remote_call_current_success()) {
            r_msg2(inv, "release", 0, 0, 0, 0);
            return 0;
        }
    }

    uint64_t numArgs = r_msg2(sig, "numberOfArguments", 0, 0, 0, 0);
    uint64_t maxUserArgs = (numArgs > 2) ? (numArgs - 2) : 0;
    if (maxUserArgs > 4) maxUserArgs = 4;

    r_msg2(inv, "setTarget:", obj, 0, 0, 0);
    r_msg2(inv, "setSelector:", sel, 0, 0, 0);

    bool argsOK = true;
    const void *argData[4] = { a0, a1, a2, a3 };
    size_t argSizes[4] = { a0Size, a1Size, a2Size, a3Size };
    for (uint64_t i = 0; i < maxUserArgs; i++) {
        size_t argBufLen = (argSizes[i] > 8) ? argSizes[i] : 8;
        uint64_t argBuf = r_call_stable(R_TIMEOUT, "malloc",
                                        argBufLen, 0, 0, 0, 0, 0, 0, 0);
        if (!argBuf) {
            argsOK = false;
            continue;
        }
        if (r_write_remote_arg(argBuf, argData[i], argSizes[i], argBufLen)) {
            r_msg2(inv, "setArgument:atIndex:", argBuf, i + 2, 0, 0);
        } else {
            argsOK = false;
        }
        r_free(argBuf);
    }

    if (!argsOK) {
        r_msg2(inv, "release", 0, 0, 0, 0);
        return 0;
    }

    r_msg2(inv, "retainArguments", 0, 0, 0, 0);

    uint64_t invokeSel = r_sel("invoke");
    bool invokeDirectly = forceCurrentThread ||
        (remote_call_uses_lab_backend() && !forceTargetMainThread);
    uint64_t performSel = invokeDirectly ? 0 :
        r_sel("performSelectorOnMainThread:withObject:waitUntilDone:");
    if (!invokeSel || (!invokeDirectly && !performSel)) {
        r_msg2(inv, "release", 0, 0, 0, 0);
        return 0;
    }

    if (invokeDirectly) {
        // iconservicesagent does not pump either Foundation's main-thread run
        // loop or the main dispatch queue in this lab configuration. The lab
        // server is a single serialized worker, so invoke the prepared object
        // there. The physical RemoteCall path continues to marshal to main.
        r_msg(inv, invokeSel, 0, 0, 0, 0);
    } else {
        r_msg_named(
            inv, performSel,
            "performSelectorOnMainThread:withObject:waitUntilDone:",
            invokeSel, 0, 1, 0);
    }

    uint64_t ret = 0;
    if (retLen > 0) {
        uint64_t retBufLen = (retLen > 8) ? retLen : 8;
        uint64_t retBuf = r_call_stable(R_TIMEOUT, "malloc",
                                        retBufLen, 0, 0, 0, 0, 0, 0, 0);
        if (retBuf) {
            remote_write64(retBuf, 0);
            r_msg2(inv, "getReturnValue:", retBuf, 0, 0, 0);
            ret = remote_read64(retBuf);
            r_free(retBuf);
        }
    }

    if (retainObjectReturn && r_is_objc_ptr(ret)) {
        uint64_t retained = r_msg2(ret, "retain", 0, 0, 0, 0);
        if (retained != ret || !remote_call_current_success()) ret = 0;
    }
    r_msg2(inv, "release", 0, 0, 0, 0);
    return ret;
}

uint64_t r_msg_main_raw(uint64_t obj, uint64_t sel,
                        const void *a0, size_t a0Size,
                        const void *a1, size_t a1Size,
                        const void *a2, size_t a2Size,
                        const void *a3, size_t a3Size)
{
    return r_msg_main_raw_internal(obj, sel,
                                   a0, a0Size, a1, a1Size,
                                   a2, a2Size, a3, a3Size,
                                   false, false, false);
}

uint64_t r_msg_main(uint64_t obj, uint64_t sel,
                    uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    if (remote_call_uses_lab_backend()) {
        // The VM mailbox payload already executes every call on its one
        // serialized worker.  Building an NSInvocation and then invoking it
        // on that same worker adds roughly a dozen mailbox round trips per
        // getter without changing the execution context.  Pointer/integer
        // calls can therefore use objc_msgSend directly; struct/FP callers
        // continue to use the raw and struct-return entry points below.
        return r_msg(obj, sel, a0, a1, a2, a3);
    }
    uint64_t args[4] = { a0, a1, a2, a3 };
    return r_msg_main_raw(obj, sel,
                          &args[0], sizeof(args[0]),
                          &args[1], sizeof(args[1]),
                          &args[2], sizeof(args[2]),
                          &args[3], sizeof(args[3]));
}

uint64_t r_msg2_main(uint64_t obj, const char *selName,
                     uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    if (!obj || !selName) return 0;
    uint64_t sel = r_sel(selName);
    if (!sel) return 0;
    r_settle();
    return r_msg_main(obj, sel, a0, a1, a2, a3);
}

uint64_t r_msg2_main_retained_object(uint64_t obj, const char *selName,
                                     uint64_t a0, uint64_t a1,
                                     uint64_t a2, uint64_t a3)
{
    if (!obj || !selName) return 0;
    uint64_t sel = r_sel(selName);
    if (!sel) return 0;
    r_settle();
    if (remote_call_uses_lab_backend()) {
        uint64_t value = r_msg(obj, sel, a0, a1, a2, a3);
        if (!r_is_objc_ptr(value) || !remote_call_current_success()) return 0;
        uint64_t retained = r_msg(value, r_sel("retain"), 0, 0, 0, 0);
        return retained == value && remote_call_current_success() ? value : 0;
    }
    uint64_t args[4] = { a0, a1, a2, a3 };
    return r_msg_main_raw_internal(obj, sel,
                                   &args[0], sizeof(args[0]),
                                   &args[1], sizeof(args[1]),
                                   &args[2], sizeof(args[2]),
                                   &args[3], sizeof(args[3]),
                                   true, false, false);
}

uint64_t r_msg2_target_main_retained_object(uint64_t obj,
                                            const char *selName,
                                            uint64_t a0, uint64_t a1,
                                            uint64_t a2, uint64_t a3)
{
    if (!obj || !selName) return 0;
    uint64_t sel = r_sel(selName);
    if (!sel) return 0;
    r_settle();
    uint64_t args[4] = { a0, a1, a2, a3 };
    return r_msg_main_raw_internal(obj, sel,
                                   &args[0], sizeof(args[0]),
                                   &args[1], sizeof(args[1]),
                                   &args[2], sizeof(args[2]),
                                   &args[3], sizeof(args[3]),
                                   true, true, false);
}

static bool r_method_encoding_exact(uint64_t object,
                                    const char *selectorName,
                                    const char *expectedTypes)
{
    if (!r_is_objc_ptr(object) || !selectorName || !expectedTypes ||
        !remote_call_current_success()) {
        return false;
    }
    uint64_t cls = r_dlsym_call(R_TIMEOUT, "object_getClass", object,
                                0, 0, 0, 0, 0, 0, 0);
    uint64_t sel = r_sel(selectorName);
    if (!r_is_objc_ptr(cls) || !sel || !remote_call_current_success()) {
        return false;
    }
    uint64_t method = r_dlsym_call(R_TIMEOUT, "class_getInstanceMethod",
                                   cls, sel, 0, 0, 0, 0, 0, 0);
    uint64_t typeString = method
        ? r_dlsym_call(R_TIMEOUT, "method_getTypeEncoding", method,
                       0, 0, 0, 0, 0, 0, 0)
        : 0;
    char actual[96] = {0};
    return method && typeString && r_read_cstring(typeString, actual,
                                                  sizeof(actual)) &&
        strcmp(actual, expectedTypes) == 0 && remote_call_current_success();
}

static uint64_t r_owned_invocation(uint64_t signature)
{
    if (!r_is_objc_ptr(signature) || !remote_call_current_success()) return 0;
    uint64_t invocationClass = r_class("NSInvocation");
    if (!r_is_objc_ptr(invocationClass)) return 0;
    uint64_t invocation = r_msg2(invocationClass,
                                 "invocationWithMethodSignature:",
                                 signature, 0, 0, 0);
    if (!r_is_objc_ptr(invocation) || !remote_call_current_success()) {
        return 0;
    }
    uint64_t retained = r_msg2(invocation, "retain", 0, 0, 0, 0);
    if (!r_is_objc_ptr(retained) || !remote_call_current_success()) {
        if (remote_call_current_success()) {
            r_msg2(invocation, "release", 0, 0, 0, 0);
        }
        return 0;
    }
    return retained;
}

static bool r_configure_invocation(uint64_t invocation,
                                   uint64_t target,
                                   uint64_t selector,
                                   bool setTargetABI,
                                   bool setSelectorABI)
{
    if (!r_is_objc_ptr(invocation) || !r_is_objc_ptr(target) || !selector ||
        !setTargetABI || !setSelectorABI || !remote_call_current_success()) {
        return false;
    }
    r_msg2(invocation, "setTarget:", target, 0, 0, 0);
    r_msg2(invocation, "setSelector:", selector, 0, 0, 0);
    return remote_call_current_success();
}

uint64_t r_msg2_main_prepared_out_object_batch(
    uint64_t target,
    const char *selectorName,
    const char *expectedTypes,
    RMainDispatchMarker dispatchMarker,
    void *dispatchMarkerContext,
    RMainPreparedOutObjectCapture *capture)
{
    if (capture) memset(capture, 0, sizeof(*capture));
    if (!capture || !r_is_objc_ptr(target) || !selectorName ||
        !expectedTypes || !remote_call_current_success()) {
        return 0;
    }

    // The caller supplies the on-device ABI string because this helper is
    // intentionally limited to one known id * generation method.
    uint64_t selector = r_sel(selectorName);
    bool generationABI = selector && r_method_encoding_exact(
        target, selectorName, expectedTypes);
    if (!generationABI) return 0;

    if (remote_call_uses_lab_backend()) {
        // The vPhone harness already serializes calls on one persistent
        // in-process worker and the enclosing proof holds an autorelease
        // pool on that worker. Do not route this one synchronous generation
        // call through performSelectorOnMainThread (iconservicesagent has no
        // serviced Foundation main run loop here), nor through the physical
        // NSInvocation ownership batch. Invoke the exact checked ABI directly
        // and retain both object results before returning to Cyanide.
        uint64_t outSlot = r_call_stable(
            R_TIMEOUT, "malloc", sizeof(uint64_t), 0, 0, 0, 0, 0, 0, 0);
        if (!outSlot || !remote_write64(outSlot, 0)) {
            if (outSlot && remote_call_current_success()) r_free(outSlot);
            return 0;
        }

        bool dispatchPossible = !dispatchMarker ||
            dispatchMarker(dispatchMarkerContext);
        capture->exactABI = true;
        capture->dispatchPossible = dispatchPossible;
        capture->outSlot = outSlot;
        if (!dispatchPossible || !remote_call_current_success()) {
            if (remote_call_current_success()) r_free(outSlot);
            return 0;
        }

        uint64_t failuresBefore = remote_call_current_io_failure_count();
        capture->generationInvoked = true;
        uint64_t result = r_msg(target, selector, outSlot, 0, 0, 0);
        capture->transportClean = remote_call_current_success() &&
            remote_call_current_io_failure_count() == failuresBefore;
        if (capture->transportClean) {
            capture->observed = remote_read(
                outSlot, &capture->raw, sizeof(capture->raw));
            capture->transportClean = capture->observed &&
                remote_call_current_success();
        }

        if (capture->transportClean && r_is_objc_ptr(capture->raw)) {
            uint64_t retainedIdentifiers = r_msg2(
                capture->raw, "retain", 0, 0, 0, 0);
            capture->holderArgumentMatches =
                retainedIdentifiers == capture->raw;
            capture->argumentsRetained =
                capture->holderArgumentMatches &&
                remote_call_current_success();
            capture->binderInvoked = capture->holderArgumentMatches;
            capture->retainerInvoked = capture->argumentsRetained;
        }
        if (capture->transportClean && r_is_objc_ptr(result)) {
            uint64_t retainedResult = r_msg2(
                result, "retain", 0, 0, 0, 0);
            capture->directRaw = result;
            capture->directArgumentMatches = retainedResult == result;
            capture->directArgumentsRetained =
                capture->directArgumentMatches &&
                remote_call_current_success();
        }
        capture->transportClean = capture->transportClean &&
            capture->argumentsRetained &&
            capture->directArgumentsRetained &&
            remote_call_current_success() &&
            remote_call_current_io_failure_count() == failuresBefore;
        if (remote_call_current_success()) r_free(outSlot);
        capture->outSlot = 0;
        return capture->transportClean ? result : 0;
    }

    uint64_t outSlot = r_call_stable(R_TIMEOUT, "malloc", sizeof(uint64_t),
                                     0, 0, 0, 0, 0, 0, 0);
    uint64_t outArgument = outSlot
        ? r_call_stable(R_TIMEOUT, "malloc", sizeof(uint64_t),
                        0, 0, 0, 0, 0, 0, 0)
        : 0;
    if (!outSlot || !outArgument || !remote_write64(outSlot, 0) ||
        !remote_write64(outArgument, outSlot)) {
        if (outArgument && remote_call_current_success()) r_free(outArgument);
        if (outSlot && remote_call_current_success()) r_free(outSlot);
        return 0;
    }

    static const char *setTargetTypes = "v24@0:8@16";
    static const char *setSelectorTypes = "v24@0:8:16";
    static const char *setArgumentTypes = "v32@0:8^v16q24";
    static const char *getArgumentTypes = "v32@0:8^v16q24";
    static const char *retainArgumentsTypes = "v16@0:8";
    static const char *argumentsRetainedTypes = "B16@0:8";
    static const char *getReturnValueTypes = "v24@0:8^v16";
    static const char *makeObjectsTypes = "v24@0:8:16";
    bool invocationABIs =
        r_method_encoding_exact(target, "methodSignatureForSelector:",
                                "@24@0:8:16");
    uint64_t targetSignature = invocationABIs
        ? r_method_signature(target, selector) : 0;
    bool targetSignatureReady = r_is_objc_ptr(targetSignature) &&
        remote_call_current_success();
    uint64_t generationInvocation = targetSignatureReady
        ? r_owned_invocation(targetSignature) : 0;
    bool generationMethods = r_is_objc_ptr(generationInvocation) &&
        r_method_encoding_exact(generationInvocation, "setTarget:",
                                setTargetTypes) &&
        r_method_encoding_exact(generationInvocation, "setSelector:",
                                setSelectorTypes) &&
        r_method_encoding_exact(generationInvocation, "setArgument:atIndex:",
                                setArgumentTypes) &&
        r_method_encoding_exact(generationInvocation, "retainArguments",
                                retainArgumentsTypes) &&
        r_method_encoding_exact(generationInvocation, "getReturnValue:",
                                getReturnValueTypes);
    uint64_t holderInvocation = 0;
    uint64_t binderInvocation = 0;
    uint64_t retainerInvocation = 0;
    uint64_t directSlot = 0;
    uint64_t returnReaderInvocation = 0;
    uint64_t directHolderInvocation = 0;
    uint64_t directBinderInvocation = 0;
    uint64_t directRetainerInvocation = 0;
    uint64_t array = 0;
    bool prepared = false;
    if (generationMethods) {
        prepared = r_configure_invocation(
            generationInvocation, target, selector,
            true, true);
        if (prepared) {
            // The generation method's only user argument is the id * slot.
            // The slot itself remains remote memory for the process lifetime.
            // NSInvocation copies the bytes at the argument location. The
            // generation argument is itself an id * pointer, so the slot
            // address must first live in a remote pointer-sized cell.
            r_msg2(generationInvocation, "setArgument:atIndex:",
                   outArgument, 2, 0, 0);
            r_msg2(generationInvocation, "retainArguments", 0, 0, 0, 0);
            prepared = remote_call_current_success();
        }
    }
    if (outArgument && remote_call_current_success()) {
        r_free(outArgument);
        outArgument = 0;
    }

    uint64_t setTargetSelector = prepared ? r_sel("setTarget:") : 0;
    uint64_t setArgumentSelector = prepared ? r_sel("setArgument:atIndex:") : 0;
    uint64_t retainArgumentsSelector = prepared ? r_sel("retainArguments") : 0;
    bool holderABIs = prepared && setTargetSelector && setArgumentSelector &&
        retainArgumentsSelector &&
        r_method_encoding_exact(generationInvocation, "setTarget:",
                                setTargetTypes) &&
        r_method_encoding_exact(generationInvocation, "setArgument:atIndex:",
                                setArgumentTypes) &&
        r_method_encoding_exact(generationInvocation, "retainArguments",
                                retainArgumentsTypes) &&
        r_method_encoding_exact(generationInvocation, "argumentsRetained",
                                argumentsRetainedTypes) &&
        r_method_encoding_exact(generationInvocation, "getArgument:atIndex:",
                                getArgumentTypes);
    if (holderABIs) {
        uint64_t holderSignature = r_method_signature(
            generationInvocation, setTargetSelector);
        holderInvocation = r_owned_invocation(holderSignature);
        holderABIs = r_is_objc_ptr(holderInvocation) &&
            r_method_encoding_exact(holderInvocation, "setTarget:",
                                    setTargetTypes) &&
            r_method_encoding_exact(holderInvocation, "setSelector:",
                                    setSelectorTypes) &&
            r_method_encoding_exact(holderInvocation, "setArgument:atIndex:",
                                    setArgumentTypes) &&
            r_method_encoding_exact(holderInvocation, "retainArguments",
                                    retainArgumentsTypes) &&
            r_method_encoding_exact(holderInvocation, "argumentsRetained",
                                    argumentsRetainedTypes) &&
            r_method_encoding_exact(holderInvocation, "getArgument:atIndex:",
                                    getArgumentTypes) &&
            r_configure_invocation(holderInvocation, generationInvocation,
                                   setTargetSelector, true, true);
        if (holderABIs) {
            uint64_t nilSlot = r_call_stable(R_TIMEOUT, "malloc",
                                              sizeof(uint64_t), 0, 0, 0, 0,
                                              0, 0, 0);
            bool nilReady = nilSlot && remote_write64(nilSlot, 0);
            if (nilReady) {
                r_msg2(holderInvocation, "setArgument:atIndex:", nilSlot,
                       2, 0, 0);
            }
            if (nilSlot && remote_call_current_success()) r_free(nilSlot);
            bool holderInitiallyUnretained =
                (r_msg2(holderInvocation, "argumentsRetained", 0, 0, 0, 0) & 1) == 0 &&
                remote_call_current_success();
            holderABIs = nilReady && holderInitiallyUnretained &&
                remote_call_current_success();
        }
    }

    bool binderABIs = holderABIs;
    if (binderABIs) {
        uint64_t binderSignature = r_method_signature(
            holderInvocation, setArgumentSelector);
        binderInvocation = r_owned_invocation(binderSignature);
        binderABIs = r_is_objc_ptr(binderInvocation) &&
            r_method_encoding_exact(binderInvocation, "setTarget:",
                                    setTargetTypes) &&
            r_method_encoding_exact(binderInvocation, "setSelector:",
                                    setSelectorTypes) &&
            r_method_encoding_exact(binderInvocation, "setArgument:atIndex:",
                                    setArgumentTypes) &&
            r_configure_invocation(binderInvocation, holderInvocation,
                                   setArgumentSelector, true, true) &&
            remote_call_current_success();
        if (binderABIs) {
            uint64_t pointerArg = r_call_stable(R_TIMEOUT, "malloc",
                                                sizeof(uint64_t), 0, 0, 0, 0,
                                                0, 0, 0);
            uint64_t indexArg = r_call_stable(R_TIMEOUT, "malloc",
                                              sizeof(uint64_t), 0, 0, 0, 0,
                                              0, 0, 0);
            bool argsReady = pointerArg && indexArg &&
                remote_write64(pointerArg, outSlot) &&
                remote_write64(indexArg, 2);
            if (argsReady) {
                r_msg2(binderInvocation, "setArgument:atIndex:",
                       pointerArg, 2, 0, 0);
                r_msg2(binderInvocation, "setArgument:atIndex:",
                       indexArg, 3, 0, 0);
            }
            if (pointerArg && remote_call_current_success()) r_free(pointerArg);
            if (indexArg && remote_call_current_success()) r_free(indexArg);
            binderABIs = argsReady && remote_call_current_success();
        }
    }

    bool retainerABIs = binderABIs;
    if (retainerABIs) {
        uint64_t retainerSignature = r_method_signature(
            holderInvocation, retainArgumentsSelector);
        retainerInvocation = r_owned_invocation(retainerSignature);
        retainerABIs = r_is_objc_ptr(retainerInvocation) &&
            r_method_encoding_exact(retainerInvocation, "setTarget:",
                                    setTargetTypes) &&
            r_method_encoding_exact(retainerInvocation, "setSelector:",
                                    setSelectorTypes) &&
            r_method_encoding_exact(retainerInvocation, "retainArguments",
                                    retainArgumentsTypes) &&
            r_configure_invocation(retainerInvocation, holderInvocation,
                                   retainArgumentsSelector, true, true) &&
            remote_call_current_success();
    }

    // retainArguments does not own an invocation's return value. Capture the
    // direct IFImage result in the same main-thread batch using a second
    // never-invoked holder, so neither returned object crosses an autorelease
    // boundary unowned.
    bool directCaptureABIs = retainerABIs;
    uint64_t getReturnValueSelector = directCaptureABIs
        ? r_sel("getReturnValue:") : 0;
    if (directCaptureABIs) {
        directSlot = r_call_stable(R_TIMEOUT, "malloc", sizeof(uint64_t),
                                   0, 0, 0, 0, 0, 0, 0);
        directCaptureABIs = directSlot && remote_write64(directSlot, 0) &&
            getReturnValueSelector;
    }
    if (directCaptureABIs) {
        uint64_t readerSignature = r_method_signature(
            generationInvocation, getReturnValueSelector);
        returnReaderInvocation = r_owned_invocation(readerSignature);
        directCaptureABIs = r_is_objc_ptr(returnReaderInvocation) &&
            r_method_encoding_exact(returnReaderInvocation, "setTarget:",
                                    setTargetTypes) &&
            r_method_encoding_exact(returnReaderInvocation, "setSelector:",
                                    setSelectorTypes) &&
            r_method_encoding_exact(returnReaderInvocation,
                                    "setArgument:atIndex:",
                                    setArgumentTypes) &&
            r_configure_invocation(returnReaderInvocation,
                                   generationInvocation,
                                   getReturnValueSelector, true, true);
        uint64_t directPointerArgument = directCaptureABIs
            ? r_call_stable(R_TIMEOUT, "malloc", sizeof(uint64_t),
                            0, 0, 0, 0, 0, 0, 0)
            : 0;
        directCaptureABIs = directCaptureABIs && directPointerArgument &&
            remote_write64(directPointerArgument, directSlot);
        if (directCaptureABIs) {
            r_msg2(returnReaderInvocation, "setArgument:atIndex:",
                   directPointerArgument, 2, 0, 0);
            directCaptureABIs = remote_call_current_success();
        }
        if (directPointerArgument && remote_call_current_success()) {
            r_free(directPointerArgument);
        }
    }
    if (directCaptureABIs) {
        uint64_t directHolderSignature = r_method_signature(
            generationInvocation, setTargetSelector);
        directHolderInvocation = r_owned_invocation(directHolderSignature);
        directCaptureABIs = r_is_objc_ptr(directHolderInvocation) &&
            r_method_encoding_exact(directHolderInvocation, "setTarget:",
                                    setTargetTypes) &&
            r_method_encoding_exact(directHolderInvocation, "setSelector:",
                                    setSelectorTypes) &&
            r_method_encoding_exact(directHolderInvocation,
                                    "setArgument:atIndex:",
                                    setArgumentTypes) &&
            r_method_encoding_exact(directHolderInvocation,
                                    "retainArguments",
                                    retainArgumentsTypes) &&
            r_method_encoding_exact(directHolderInvocation,
                                    "argumentsRetained",
                                    argumentsRetainedTypes) &&
            r_method_encoding_exact(directHolderInvocation,
                                    "getArgument:atIndex:",
                                    getArgumentTypes) &&
            r_configure_invocation(directHolderInvocation,
                                   generationInvocation,
                                   setTargetSelector, true, true);
        uint64_t nilSlot = directCaptureABIs
            ? r_call_stable(R_TIMEOUT, "malloc", sizeof(uint64_t),
                            0, 0, 0, 0, 0, 0, 0)
            : 0;
        bool nilReady = nilSlot && remote_write64(nilSlot, 0);
        if (nilReady) {
            r_msg2(directHolderInvocation, "setArgument:atIndex:", nilSlot,
                   2, 0, 0);
        }
        if (nilSlot && remote_call_current_success()) r_free(nilSlot);
        bool initiallyUnretained = directCaptureABIs && nilReady &&
            (r_msg2(directHolderInvocation, "argumentsRetained",
                    0, 0, 0, 0) & 1) == 0 &&
            remote_call_current_success();
        directCaptureABIs = initiallyUnretained;
    }
    if (directCaptureABIs) {
        uint64_t directBinderSignature = r_method_signature(
            directHolderInvocation, setArgumentSelector);
        directBinderInvocation = r_owned_invocation(directBinderSignature);
        directCaptureABIs = r_is_objc_ptr(directBinderInvocation) &&
            r_method_encoding_exact(directBinderInvocation, "setTarget:",
                                    setTargetTypes) &&
            r_method_encoding_exact(directBinderInvocation, "setSelector:",
                                    setSelectorTypes) &&
            r_method_encoding_exact(directBinderInvocation,
                                    "setArgument:atIndex:",
                                    setArgumentTypes) &&
            r_configure_invocation(directBinderInvocation,
                                   directHolderInvocation,
                                   setArgumentSelector, true, true);
        uint64_t pointerArg = directCaptureABIs
            ? r_call_stable(R_TIMEOUT, "malloc", sizeof(uint64_t),
                            0, 0, 0, 0, 0, 0, 0)
            : 0;
        uint64_t indexArg = directCaptureABIs
            ? r_call_stable(R_TIMEOUT, "malloc", sizeof(uint64_t),
                            0, 0, 0, 0, 0, 0, 0)
            : 0;
        bool argsReady = pointerArg && indexArg &&
            remote_write64(pointerArg, directSlot) &&
            remote_write64(indexArg, 2);
        if (argsReady) {
            r_msg2(directBinderInvocation, "setArgument:atIndex:",
                   pointerArg, 2, 0, 0);
            r_msg2(directBinderInvocation, "setArgument:atIndex:",
                   indexArg, 3, 0, 0);
        }
        if (pointerArg && remote_call_current_success()) r_free(pointerArg);
        if (indexArg && remote_call_current_success()) r_free(indexArg);
        directCaptureABIs = argsReady && remote_call_current_success();
    }
    if (directCaptureABIs) {
        uint64_t directRetainerSignature = r_method_signature(
            directHolderInvocation, retainArgumentsSelector);
        directRetainerInvocation = r_owned_invocation(
            directRetainerSignature);
        directCaptureABIs = r_is_objc_ptr(directRetainerInvocation) &&
            r_method_encoding_exact(directRetainerInvocation, "setTarget:",
                                    setTargetTypes) &&
            r_method_encoding_exact(directRetainerInvocation, "setSelector:",
                                    setSelectorTypes) &&
            r_method_encoding_exact(directRetainerInvocation,
                                    "retainArguments",
                                    retainArgumentsTypes) &&
            r_configure_invocation(directRetainerInvocation,
                                   directHolderInvocation,
                                   retainArgumentsSelector, true, true);
    }

    uint64_t invokeSelector = directCaptureABIs ? r_sel("invoke") : 0;
    uint64_t arrayClass = directCaptureABIs ? r_class("NSMutableArray") : 0;
    uint64_t arrayAlloc = r_is_objc_ptr(arrayClass)
        ? r_msg2(arrayClass, "alloc", 0, 0, 0, 0) : 0;
    if (directCaptureABIs && r_is_objc_ptr(arrayAlloc) && invokeSelector) {
        array = r_msg2(arrayAlloc, "init", 0, 0, 0, 0);
        if (r_is_objc_ptr(array) &&
            r_method_encoding_exact(array, "addObject:", "v24@0:8@16") &&
            r_method_encoding_exact(array, "makeObjectsPerformSelector:",
                                    makeObjectsTypes)) {
            r_msg2(array, "addObject:", generationInvocation, 0, 0, 0);
            r_msg2(array, "addObject:", binderInvocation, 0, 0, 0);
            r_msg2(array, "addObject:", retainerInvocation, 0, 0, 0);
            r_msg2(array, "addObject:", returnReaderInvocation, 0, 0, 0);
            r_msg2(array, "addObject:", directBinderInvocation, 0, 0, 0);
            r_msg2(array, "addObject:", directRetainerInvocation, 0, 0, 0);
            prepared = remote_call_current_success();
        } else {
            prepared = false;
        }
    } else {
        prepared = false;
    }
    if (arrayAlloc && arrayAlloc != array && remote_call_current_success()) {
        r_msg2(arrayAlloc, "release", 0, 0, 0, 0);
    }

    capture->exactABI = generationABI && prepared &&
        remote_call_current_success();
    if (!capture->exactABI) {
        if (remote_call_current_success()) {
            if (array) r_msg2(array, "release", 0, 0, 0, 0);
            if (directRetainerInvocation) r_msg2(directRetainerInvocation, "release", 0, 0, 0, 0);
            if (directBinderInvocation) r_msg2(directBinderInvocation, "release", 0, 0, 0, 0);
            if (directHolderInvocation) r_msg2(directHolderInvocation, "release", 0, 0, 0, 0);
            if (returnReaderInvocation) r_msg2(returnReaderInvocation, "release", 0, 0, 0, 0);
            if (retainerInvocation) r_msg2(retainerInvocation, "release", 0, 0, 0, 0);
            if (binderInvocation) r_msg2(binderInvocation, "release", 0, 0, 0, 0);
            if (holderInvocation) r_msg2(holderInvocation, "release", 0, 0, 0, 0);
            if (generationInvocation) r_msg2(generationInvocation, "release", 0, 0, 0, 0);
            if (outArgument) r_free(outArgument);
            if (directSlot) r_free(directSlot);
            if (outSlot) r_free(outSlot);
        }
        return 0;
    }

    bool dispatchPossible = !dispatchMarker ||
        dispatchMarker(dispatchMarkerContext);
    capture->dispatchPossible = dispatchPossible;
    if (!dispatchPossible) {
        if (remote_call_current_success()) {
            r_msg2(array, "release", 0, 0, 0, 0);
            r_msg2(directRetainerInvocation, "release", 0, 0, 0, 0);
            r_msg2(directBinderInvocation, "release", 0, 0, 0, 0);
            r_msg2(directHolderInvocation, "release", 0, 0, 0, 0);
            r_msg2(returnReaderInvocation, "release", 0, 0, 0, 0);
            r_msg2(retainerInvocation, "release", 0, 0, 0, 0);
            r_msg2(binderInvocation, "release", 0, 0, 0, 0);
            r_msg2(holderInvocation, "release", 0, 0, 0, 0);
            r_msg2(generationInvocation, "release", 0, 0, 0, 0);
            if (outArgument) r_free(outArgument);
            r_free(directSlot);
            r_free(outSlot);
        }
        return 0;
    }

    capture->generationInvocation = generationInvocation;
    capture->holderInvocation = holderInvocation;
    capture->directHolderInvocation = directHolderInvocation;
    capture->outSlot = outSlot;
    capture->directSlot = directSlot;
    capture->generationInvoked = true;
    uint64_t ioFailuresBeforeDispatch =
        remote_call_current_io_failure_count();
    r_msg2_main(array, "makeObjectsPerformSelector:", invokeSelector, 0, 0, 0);
    capture->transportClean = remote_call_current_success() &&
        remote_call_current_io_failure_count() == ioFailuresBeforeDispatch;
    if (capture->transportClean) {
        capture->observed = remote_read(outSlot, &capture->raw,
                                        sizeof(capture->raw));
        capture->transportClean = capture->observed &&
            remote_call_current_success();
    }
    if (capture->transportClean) {
        uint64_t argumentBuffer = r_call_stable(R_TIMEOUT, "malloc",
                                                 sizeof(uint64_t), 0, 0, 0,
                                                 0, 0, 0, 0);
        bool argumentRead = argumentBuffer && remote_write64(argumentBuffer, 0);
        if (argumentRead) {
            r_msg2(holderInvocation, "getArgument:atIndex:",
                   argumentBuffer, 2, 0, 0);
            argumentRead = remote_call_current_success() &&
                remote_read64(argumentBuffer) == capture->raw;
        }
        if (argumentBuffer && remote_call_current_success()) r_free(argumentBuffer);
        capture->holderArgumentMatches = argumentRead;
        if (remote_call_current_success()) {
            capture->argumentsRetained =
                (r_msg2(holderInvocation, "argumentsRetained",
                        0, 0, 0, 0) & 1) != 0 &&
                remote_call_current_success();
        }
        capture->binderInvoked = capture->holderArgumentMatches;
        capture->retainerInvoked = capture->argumentsRetained;
        capture->transportClean = remote_call_current_success();
    }
    if (capture->transportClean) {
        capture->directRaw = remote_read64(directSlot);
        uint64_t directArgumentBuffer = r_call_stable(
            R_TIMEOUT, "malloc", sizeof(uint64_t), 0, 0, 0, 0, 0, 0, 0);
        bool directArgumentRead = directArgumentBuffer &&
            remote_write64(directArgumentBuffer, 0);
        if (directArgumentRead) {
            r_msg2(directHolderInvocation, "getArgument:atIndex:",
                   directArgumentBuffer, 2, 0, 0);
            directArgumentRead = remote_call_current_success() &&
                remote_read64(directArgumentBuffer) == capture->directRaw;
        }
        if (directArgumentBuffer && remote_call_current_success()) {
            r_free(directArgumentBuffer);
        }
        capture->directArgumentMatches = directArgumentRead;
        if (remote_call_current_success()) {
            capture->directArgumentsRetained =
                (r_msg2(directHolderInvocation, "argumentsRetained",
                        0, 0, 0, 0) & 1) != 0 &&
                remote_call_current_success();
        }
        capture->transportClean = remote_call_current_success();
    }
    // The array, binder, and retainer have completed their synchronous work.
    // The generation invocation, holder, and slot are intentionally retained
    // for the target process, including when transport health is uncertain.
    if (capture->transportClean) {
        r_msg2(array, "release", 0, 0, 0, 0);
        if (remote_call_current_success())
            r_msg2(directRetainerInvocation, "release", 0, 0, 0, 0);
        if (remote_call_current_success())
            r_msg2(directBinderInvocation, "release", 0, 0, 0, 0);
        if (remote_call_current_success())
            r_msg2(returnReaderInvocation, "release", 0, 0, 0, 0);
        if (remote_call_current_success())
            r_msg2(retainerInvocation, "release", 0, 0, 0, 0);
        if (remote_call_current_success())
            r_msg2(binderInvocation, "release", 0, 0, 0, 0);
    }
    capture->transportClean = capture->transportClean &&
        remote_call_current_success() &&
        remote_call_current_io_failure_count() == ioFailuresBeforeDispatch;
    bool directOwned = capture->transportClean &&
        capture->directArgumentMatches && capture->directArgumentsRetained;
    return directOwned ? capture->directRaw : 0;
}

// Fire-and-forget variant: dispatches the call to main thread with
// waitUntilDone:NO and skips the return-value plumbing. Use this when the
// selector returns void and we don't need to wait — main thread retains the
// NSInvocation for the duration of the call, so it's safe to release here.
void r_msg2_main_async(uint64_t obj, const char *selName,
                       uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    if (!r_is_objc_ptr(obj) || !selName) return;
    uint64_t sel = r_sel(selName);
    if (!sel) return;
    r_settle();

    uint64_t sig = 0;
    {
        uint64_t sigSel = r_sel("methodSignatureForSelector:");
        sig = r_msg(obj, sigSel, sel, 0, 0, 0);
    }
    if (!r_is_objc_ptr(sig)) return;

    uint64_t NSInvocation = r_class("NSInvocation");
    if (!r_is_objc_ptr(NSInvocation)) return;
    uint64_t inv = r_msg2(NSInvocation, "invocationWithMethodSignature:", sig, 0, 0, 0);
    if (!r_is_objc_ptr(inv)) return;

    uint64_t numArgs = r_msg2(sig, "numberOfArguments", 0, 0, 0, 0);
    uint64_t maxUserArgs = (numArgs > 2) ? (numArgs - 2) : 0;
    if (maxUserArgs > 4) maxUserArgs = 4;

    r_msg2(inv, "setTarget:", obj, 0, 0, 0);
    r_msg2(inv, "setSelector:", sel, 0, 0, 0);

    bool argsOK = true;
    uint64_t userArgs[4] = { a0, a1, a2, a3 };
    for (uint64_t i = 0; i < maxUserArgs; i++) {
        uint64_t argBuf = r_call_stable(R_TIMEOUT, "malloc",
                                        8, 0, 0, 0, 0, 0, 0, 0);
        if (!argBuf) {
            argsOK = false;
            continue;
        }
        if (remote_write64(argBuf, userArgs[i])) {
            r_msg2(inv, "setArgument:atIndex:", argBuf, i + 2, 0, 0);
        } else {
            argsOK = false;
        }
        r_free(argBuf);
    }

    if (!argsOK) return;

    r_msg2(inv, "retainArguments", 0, 0, 0, 0);

    uint64_t performSel = r_sel("performSelectorOnMainThread:withObject:waitUntilDone:");
    uint64_t invokeSel = r_sel("invoke");
    if (performSel && invokeSel) r_msg(inv, performSel, invokeSel, 0, 0, 0);
}

uint64_t r_msg2_main_raw(uint64_t obj, const char *selName,
                         const void *a0, size_t a0Size,
                         const void *a1, size_t a1Size,
                         const void *a2, size_t a2Size,
                         const void *a3, size_t a3Size)
{
    if (!obj || !selName) return 0;
    uint64_t sel = r_sel(selName);
    if (!sel) return 0;
    r_settle();
    return r_msg_main_raw(obj, sel, a0, a0Size, a1, a1Size, a2, a2Size, a3, a3Size);
}

uint64_t r_msg2_raw(uint64_t obj, const char *selName,
                    const void *a0, size_t a0Size,
                    const void *a1, size_t a1Size,
                    const void *a2, size_t a2Size,
                    const void *a3, size_t a3Size)
{
    if (!obj || !selName) return 0;
    uint64_t sel = r_sel(selName);
    if (!sel) return 0;
    r_settle();
    return r_msg_main_raw_internal(obj, sel,
                                   a0, a0Size, a1, a1Size,
                                   a2, a2Size, a3, a3Size,
                                   false, false, true);
}

// Same flow as r_msg_main_raw, but copies the full method return buffer back
// into outBuf instead of truncating to 8 bytes. Used for selectors that return
// a struct larger than a register pair (e.g. CGRect from -convertRect:toView:).
static bool r_msg2_struct_ret_internal(uint64_t obj, const char *selName,
                                       void *outBuf, size_t outSize,
                                       const void *a0, size_t a0Size,
                                       const void *a1, size_t a1Size,
                                       const void *a2, size_t a2Size,
                                       const void *a3, size_t a3Size,
                                       bool forceCurrentThread)
{
    if (!r_is_objc_ptr(obj) || !selName || !outBuf || outSize == 0) return false;
    uint64_t sel = r_sel(selName);
    if (!sel) return false;
    r_settle();

    uint64_t sig = r_method_signature(obj, sel);
    if (!r_is_objc_ptr(sig)) return false;

    uint64_t NSInvocation = r_class("NSInvocation");
    if (!r_is_objc_ptr(NSInvocation)) return false;

    uint64_t inv = r_msg2(NSInvocation, "invocationWithMethodSignature:", sig, 0, 0, 0);
    if (!r_is_objc_ptr(inv)) return false;

    uint64_t retainedInv = r_msg2(inv, "retain", 0, 0, 0, 0);
    if (r_is_objc_ptr(retainedInv)) inv = retainedInv;

    uint64_t numArgs = r_msg2(sig, "numberOfArguments", 0, 0, 0, 0);
    uint64_t maxUserArgs = (numArgs > 2) ? (numArgs - 2) : 0;
    if (maxUserArgs > 4) maxUserArgs = 4;

    r_msg2(inv, "setTarget:", obj, 0, 0, 0);
    r_msg2(inv, "setSelector:", sel, 0, 0, 0);

    bool argsOK = true;
    const void *argData[4] = { a0, a1, a2, a3 };
    size_t argSizes[4] = { a0Size, a1Size, a2Size, a3Size };
    for (uint64_t i = 0; i < maxUserArgs; i++) {
        size_t argBufLen = (argSizes[i] > 8) ? argSizes[i] : 8;
        uint64_t argBuf = r_call_stable(R_TIMEOUT, "malloc",
                                        argBufLen, 0, 0, 0, 0, 0, 0, 0);
        if (!argBuf) {
            argsOK = false;
            continue;
        }
        if (r_write_remote_arg(argBuf, argData[i], argSizes[i], argBufLen)) {
            r_msg2(inv, "setArgument:atIndex:", argBuf, i + 2, 0, 0);
        } else {
            argsOK = false;
        }
        r_free(argBuf);
    }

    if (!argsOK) {
        r_msg2(inv, "release", 0, 0, 0, 0);
        return false;
    }

    r_msg2(inv, "retainArguments", 0, 0, 0, 0);

    uint64_t invokeSel = r_sel("invoke");
    bool invokeDirectly = forceCurrentThread || remote_call_uses_lab_backend();
    uint64_t performSel = invokeDirectly ? 0 :
        r_sel("performSelectorOnMainThread:withObject:waitUntilDone:");
    if (!invokeSel || (!invokeDirectly && !performSel)) {
        r_msg2(inv, "release", 0, 0, 0, 0);
        return false;
    }
    if (invokeDirectly) {
        // The vPhone worker and explicit current-thread callers already have a
        // serialized execution context. Some physical daemons do not service
        // Foundation main-thread selectors, so those callers must invoke the
        // prepared NSInvocation on the live synthetic thread instead.
        r_msg(inv, invokeSel, 0, 0, 0, 0);
    } else {
        r_msg(inv, performSel, invokeSel, 0, 1, 0);
    }

    bool ok = false;
    uint64_t retLen = r_msg2(sig, "methodReturnLength", 0, 0, 0, 0);
    if (retLen >= outSize) {
        uint64_t retBuf = r_call_stable(R_TIMEOUT, "malloc",
                                        retLen, 0, 0, 0, 0, 0, 0, 0);
        if (retBuf) {
            r_msg2(inv, "getReturnValue:", retBuf, 0, 0, 0);
            ok = remote_read(retBuf, outBuf, outSize);
            r_free(retBuf);
        }
    }

    r_msg2(inv, "release", 0, 0, 0, 0);
    return ok;
}

bool r_msg2_main_struct_ret(uint64_t obj, const char *selName,
                            void *outBuf, size_t outSize,
                            const void *a0, size_t a0Size,
                            const void *a1, size_t a1Size,
                            const void *a2, size_t a2Size,
                            const void *a3, size_t a3Size)
{
    return r_msg2_struct_ret_internal(
        obj, selName, outBuf, outSize,
        a0, a0Size, a1, a1Size, a2, a2Size, a3, a3Size, false);
}

bool r_msg2_struct_ret(uint64_t obj, const char *selName,
                       void *outBuf, size_t outSize,
                       const void *a0, size_t a0Size,
                       const void *a1, size_t a1Size,
                       const void *a2, size_t a2Size,
                       const void *a3, size_t a3Size)
{
    return r_msg2_struct_ret_internal(
        obj, selName, outBuf, outSize,
        a0, a0Size, a1, a1Size, a2, a2Size, a3, a3Size, true);
}

uint64_t r_perform_main(uint64_t obj, uint64_t sel, uint64_t object, bool wait)
{
    if (!r_is_objc_ptr(obj) || !sel) return 0;
    if (remote_call_uses_lab_backend()) {
        (void)wait;
        return r_msg(obj, sel, object, 0, 0, 0);
    }
    uint64_t performSel = r_sel("performSelectorOnMainThread:withObject:waitUntilDone:");
    if (!performSel) return 0;
    return r_msg(obj, performSel, sel, object, wait ? 1 : 0, 0);
}

uint64_t r_cfstr(const char *s)
{
    if (!s) return 0;
    uint64_t buf = r_alloc_str(s);
    if (!buf) return 0;
    // CFStringCreateWithCString(alloc=NULL, cstr, encoding=kCFStringEncodingUTF8=0x08000100)
    uint64_t cf = r_call_stable(R_TIMEOUT, "CFStringCreateWithCString",
                                0, buf, 0x08000100, 0, 0, 0, 0, 0);
    r_free(buf);
    return cf;
}

uint64_t r_nsstr_retained(const char *s)
{
    if (!s) return 0;
    uint64_t buf = r_alloc_str(s);
    if (!buf) return 0;
    uint64_t NSString = r_class("NSString");
    if (!r_is_objc_ptr(NSString)) { r_free(buf); return 0; }
    uint64_t allocated = r_msg2(NSString, "alloc", 0, 0, 0, 0);
    if (!r_is_objc_ptr(allocated)) { r_free(buf); return 0; }
    uint64_t ns = r_msg2(allocated, "initWithUTF8String:", buf, 0, 0, 0);
    r_free(buf);
    return ns;
}

bool r_responds(uint64_t obj, const char *selName)
{
    if (!r_is_objc_ptr(obj)) return false;
    uint64_t sel = r_sel(selName);
    if (!sel) return false;
    uint64_t respondsSel = r_sel("respondsToSelector:");
    if (!respondsSel) return false;
    r_settle();
    uint64_t r = r_msg(obj, respondsSel, sel, 0, 0, 0);
    return (r & 0xff) != 0;
}

bool r_responds_main(uint64_t obj, const char *selName)
{
    if (!r_is_objc_ptr(obj)) return false;
    uint64_t sel = r_sel(selName);
    if (!sel) return false;
    uint64_t respondsSel = r_sel("respondsToSelector:");
    if (!respondsSel) return false;
    r_settle();
    uint64_t r = r_msg_main(obj, respondsSel, sel, 0, 0, 0);
    return (r & 0xff) != 0;
}

uint64_t r_ivar_value(uint64_t obj, const char *ivarName)
{
    if (!r_is_objc_ptr(obj)) return 0;
    uint64_t cls = r_call_stable(R_TIMEOUT, "object_getClass", obj, 0, 0, 0, 0, 0, 0, 0);
    if (!cls) return 0;
    uint64_t nameBuf = r_alloc_str(ivarName);
    if (!nameBuf) return 0;
    uint64_t ivar = r_call_stable(R_TIMEOUT, "class_getInstanceVariable",
                                  cls, nameBuf, 0, 0, 0, 0, 0, 0);
    r_free(nameBuf);
    if (!ivar) return 0;
    uint64_t offset = r_call_stable(R_TIMEOUT, "ivar_getOffset",
                                    ivar, 0, 0, 0, 0, 0, 0, 0);
    return remote_read64(obj + offset);
}

bool r_read_cstring(uint64_t cstr, char *out, size_t outLen)
{
    if (!out || outLen == 0) return false;
    memset(out, 0, outLen);
    if (!cstr || !remote_call_current_success()) return false;

    uint64_t heap = r_dlsym_call(R_TIMEOUT, "strdup",
                                 cstr, 0, 0, 0, 0, 0, 0, 0);
    if (!heap) return false;

    uint64_t maxLen = outLen - 1;
    uint64_t len = r_dlsym_call(R_TIMEOUT, "strnlen",
                                heap, maxLen, 0, 0, 0, 0, 0, 0);
    bool ok = remote_call_current_success() && len <= maxLen &&
              remote_read(heap, out, len + 1);
    if (!ok) memset(out, 0, outLen);
    else out[outLen - 1] = '\0';

    r_free(heap);
    return ok;
}

bool r_read_nsstring(uint64_t str, char *out, size_t outLen)
{
    if (!r_is_objc_ptr(str) || !out || outLen == 0) return false;
    memset(out, 0, outLen);

    uint64_t buf = r_dlsym_call(R_TIMEOUT, "malloc", outLen, 0, 0, 0, 0, 0, 0, 0);
    if (!buf) return false;
    r_dlsym_call(R_TIMEOUT, "memset", buf, 0, outLen, 0, 0, 0, 0, 0);

    bool copied = false;
    if (r_responds(str, "getCString:maxLength:encoding:")) {
        uint64_t ok = r_msg2(str, "getCString:maxLength:encoding:", buf, outLen, 4, 0);
        if ((ok & 0xff) && remote_read(buf, out, outLen - 1)) {
            out[outLen - 1] = '\0';
            copied = out[0] != '\0';
        }
    }

    r_free(buf);
    return copied;
}

#ifdef __OBJC__
#define R_SESSION_RETURN(session, type, fallback, expr) do { \
    if (!(session)) return (expr); \
    __block type result = (fallback); \
    remote_call_with_session((session), ^{ result = (expr); }); \
    return result; \
} while (0)

#define R_SESSION_VOID(session, expr) do { \
    if (!(session)) { expr; return; } \
    remote_call_with_session((session), ^{ expr; }); \
} while (0)

uint64_t r_session_dlsym_call(RemoteCallSession *session, int timeout, const char *fnName,
                              uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                              uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
    R_SESSION_RETURN(session, uint64_t, 0,
                     r_dlsym_call(timeout, fnName, a0, a1, a2, a3, a4, a5, a6, a7));
}

uint64_t r_session_alloc_str(RemoteCallSession *session, const char *s)
{
    R_SESSION_RETURN(session, uint64_t, 0, r_alloc_str(s));
}

void r_session_free(RemoteCallSession *session, uint64_t ptr)
{
    R_SESSION_VOID(session, r_free(ptr));
}

uint64_t r_session_sel(RemoteCallSession *session, const char *name)
{
    R_SESSION_RETURN(session, uint64_t, 0, r_sel(name));
}

uint64_t r_session_class(RemoteCallSession *session, const char *name)
{
    R_SESSION_RETURN(session, uint64_t, 0, r_class(name));
}

uint64_t r_session_msg(RemoteCallSession *session, uint64_t obj, uint64_t sel,
                       uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    R_SESSION_RETURN(session, uint64_t, 0, r_msg(obj, sel, a0, a1, a2, a3));
}

uint64_t r_session_msg2(RemoteCallSession *session, uint64_t obj, const char *selName,
                        uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    R_SESSION_RETURN(session, uint64_t, 0, r_msg2(obj, selName, a0, a1, a2, a3));
}

uint64_t r_session_msg_main(RemoteCallSession *session, uint64_t obj, uint64_t sel,
                            uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    R_SESSION_RETURN(session, uint64_t, 0, r_msg_main(obj, sel, a0, a1, a2, a3));
}

uint64_t r_session_msg2_main(RemoteCallSession *session, uint64_t obj, const char *selName,
                             uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    R_SESSION_RETURN(session, uint64_t, 0, r_msg2_main(obj, selName, a0, a1, a2, a3));
}

void r_session_msg2_main_async(RemoteCallSession *session, uint64_t obj, const char *selName,
                               uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
    R_SESSION_VOID(session, r_msg2_main_async(obj, selName, a0, a1, a2, a3));
}

uint64_t r_session_msg_main_raw(RemoteCallSession *session, uint64_t obj, uint64_t sel,
                                const void *a0, size_t a0Size,
                                const void *a1, size_t a1Size,
                                const void *a2, size_t a2Size,
                                const void *a3, size_t a3Size)
{
    R_SESSION_RETURN(session, uint64_t, 0,
                     r_msg_main_raw(obj, sel, a0, a0Size, a1, a1Size, a2, a2Size, a3, a3Size));
}

uint64_t r_session_msg2_main_raw(RemoteCallSession *session, uint64_t obj, const char *selName,
                                 const void *a0, size_t a0Size,
                                 const void *a1, size_t a1Size,
                                 const void *a2, size_t a2Size,
                                 const void *a3, size_t a3Size)
{
    R_SESSION_RETURN(session, uint64_t, 0,
                     r_msg2_main_raw(obj, selName, a0, a0Size, a1, a1Size, a2, a2Size, a3, a3Size));
}

bool r_session_msg2_main_struct_ret(RemoteCallSession *session, uint64_t obj, const char *selName,
                                    void *outBuf, size_t outSize,
                                    const void *a0, size_t a0Size,
                                    const void *a1, size_t a1Size,
                                    const void *a2, size_t a2Size,
                                    const void *a3, size_t a3Size)
{
    R_SESSION_RETURN(session, bool, false,
                     r_msg2_main_struct_ret(obj, selName, outBuf, outSize,
                                            a0, a0Size, a1, a1Size, a2, a2Size, a3, a3Size));
}

uint64_t r_session_perform_main(RemoteCallSession *session, uint64_t obj, uint64_t sel, uint64_t object, bool wait)
{
    R_SESSION_RETURN(session, uint64_t, 0, r_perform_main(obj, sel, object, wait));
}

uint64_t r_session_cfstr(RemoteCallSession *session, const char *s)
{
    R_SESSION_RETURN(session, uint64_t, 0, r_cfstr(s));
}

uint64_t r_session_nsstr_retained(RemoteCallSession *session, const char *s)
{
    R_SESSION_RETURN(session, uint64_t, 0, r_nsstr_retained(s));
}

bool r_session_responds(RemoteCallSession *session, uint64_t obj, const char *selName)
{
    R_SESSION_RETURN(session, bool, false, r_responds(obj, selName));
}

bool r_session_responds_main(RemoteCallSession *session, uint64_t obj, const char *selName)
{
    R_SESSION_RETURN(session, bool, false, r_responds_main(obj, selName));
}

uint64_t r_session_ivar_value(RemoteCallSession *session, uint64_t obj, const char *ivarName)
{
    R_SESSION_RETURN(session, uint64_t, 0, r_ivar_value(obj, ivarName));
}

#undef R_SESSION_VOID
#undef R_SESSION_RETURN
#endif
