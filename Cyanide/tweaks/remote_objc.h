//
//  remote_objc.h
//  Thin Objective-C runtime helpers built on do_remote_call_stable.
//

#ifndef remote_objc_h
#define remote_objc_h

#import <stdint.h>
#import <stdbool.h>
#import <stddef.h>
#ifdef __OBJC__
#import "../TaskRop/RemoteCall.h"
#endif

#define R_TIMEOUT 5

uint64_t r_alloc_str(const char *s);
void     r_free(uint64_t ptr);
uint64_t r_sel(const char *name);
uint64_t r_class(const char *name);
uint64_t r_msg(uint64_t obj, uint64_t sel,
               uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t r_msg2(uint64_t obj, const char *selName,
                uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t r_msg_main(uint64_t obj, uint64_t sel,
                    uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t r_msg2_main(uint64_t obj, const char *selName,
                     uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
// Invokes an object-returning selector on the target main thread and retains
// the returned object before releasing the backing NSInvocation. The caller
// owns the returned +1 object and must release it.
uint64_t r_msg2_main_retained_object(uint64_t obj, const char *selName,
                                     uint64_t a0, uint64_t a1,
                                     uint64_t a2, uint64_t a3);
// Forces NSInvocation delivery through the target process's actual main
// thread even when the vPhone mailbox backend normally executes getters on
// its serialized worker. The returned Objective-C object is owned (+1).
uint64_t r_msg2_target_main_retained_object(uint64_t obj,
                                            const char *selName,
                                            uint64_t a0, uint64_t a1,
                                            uint64_t a2, uint64_t a3);

typedef struct {
    uint64_t generationInvocation;
    uint64_t holderInvocation;
    uint64_t directHolderInvocation;
    uint64_t outSlot;
    uint64_t directSlot;
    uint64_t directRaw;
    uint64_t raw;
    bool exactABI;
    bool dispatchPossible;
    bool generationInvoked;
    bool observed;
    bool binderInvoked;
    bool retainerInvoked;
    bool holderArgumentMatches;
    bool argumentsRetained;
    bool directArgumentMatches;
    bool directArgumentsRetained;
    bool transportClean;
} RMainPreparedOutObjectCapture;

typedef bool (*RMainDispatchMarker)(void *context);

// Perform one known object-returning generation request whose sole argument is
// an id * out slot. Ownership is established entirely on the target main
// thread: a never-invoked holder invocation receives the generated slot via a
// binder invocation, then a retainer invocation calls retainArguments on that
// holder. The generation and holder invocations, plus the slot, intentionally
// remain alive after return. A marker is called immediately before the one
// synchronous makeObjectsPerformSelector:@selector(invoke) dispatch; returning
// false prevents the request from being dispatched.
uint64_t r_msg2_main_prepared_out_object_batch(
    uint64_t target,
    const char *selectorName,
    const char *expectedTypes,
    RMainDispatchMarker dispatchMarker,
    void *dispatchMarkerContext,
    RMainPreparedOutObjectCapture *capture);
void     r_msg2_main_async(uint64_t obj, const char *selName,
                           uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t r_msg_main_raw(uint64_t obj, uint64_t sel,
                        const void *a0, size_t a0Size,
                        const void *a1, size_t a1Size,
                        const void *a2, size_t a2Size,
                        const void *a3, size_t a3Size);
uint64_t r_msg2_main_raw(uint64_t obj, const char *selName,
                         const void *a0, size_t a0Size,
                         const void *a1, size_t a1Size,
                         const void *a2, size_t a2Size,
                         const void *a3, size_t a3Size);
// Typed NSInvocation delivery on the current synthetic RemoteCall thread.
// These variants never enqueue work on the target process's main thread.
uint64_t r_msg2_raw(uint64_t obj, const char *selName,
                    const void *a0, size_t a0Size,
                    const void *a1, size_t a1Size,
                    const void *a2, size_t a2Size,
                    const void *a3, size_t a3Size);
bool     r_msg2_main_struct_ret(uint64_t obj, const char *selName,
                                void *outBuf, size_t outSize,
                                const void *a0, size_t a0Size,
                                const void *a1, size_t a1Size,
                                const void *a2, size_t a2Size,
                                const void *a3, size_t a3Size);
bool     r_msg2_struct_ret(uint64_t obj, const char *selName,
                           void *outBuf, size_t outSize,
                           const void *a0, size_t a0Size,
                           const void *a1, size_t a1Size,
                           const void *a2, size_t a2Size,
                           const void *a3, size_t a3Size);
uint32_t r_settle_us(uint32_t usec);
uint64_t r_perform_main(uint64_t obj, uint64_t sel, uint64_t object, bool wait);
uint64_t r_cfstr(const char *s);
uint64_t r_nsstr_retained(const char *s);
bool     r_responds(uint64_t obj, const char *selName);
bool     r_responds_main(uint64_t obj, const char *selName);
bool     r_is_objc_ptr(uint64_t ptr);
uint64_t r_ivar_value(uint64_t obj, const char *ivarName);
uint64_t r_dlsym_call(int timeout, const char *fnName,
                      uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                      uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7);
// Scope autoreleased Objective-C objects created on the persistent synthetic
// call thread.  The token must be popped on that same RemoteCall session.
uint64_t r_autorelease_pool_push(void);
bool     r_autorelease_pool_pop(uint64_t token);

// Copies a remote NUL-terminated C string without reading beyond its actual
// allocation. The output is always initialized and NUL-terminated.
bool     r_read_cstring(uint64_t cstr, char *out, size_t outLen);

// Copies the UTF-8 bytes of a remote NSString into a local C buffer (NUL
// terminated, truncated to outLen-1). Returns true only if at least one
// byte was copied.
bool     r_read_nsstring(uint64_t str, char *out, size_t outLen);

#ifdef __OBJC__
uint64_t r_session_alloc_str(RemoteCallSession *session, const char *s);
void     r_session_free(RemoteCallSession *session, uint64_t ptr);
uint64_t r_session_sel(RemoteCallSession *session, const char *name);
uint64_t r_session_class(RemoteCallSession *session, const char *name);
uint64_t r_session_msg(RemoteCallSession *session, uint64_t obj, uint64_t sel,
                       uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t r_session_msg2(RemoteCallSession *session, uint64_t obj, const char *selName,
                        uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t r_session_msg_main(RemoteCallSession *session, uint64_t obj, uint64_t sel,
                            uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t r_session_msg2_main(RemoteCallSession *session, uint64_t obj, const char *selName,
                             uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
void     r_session_msg2_main_async(RemoteCallSession *session, uint64_t obj, const char *selName,
                                   uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t r_session_msg_main_raw(RemoteCallSession *session, uint64_t obj, uint64_t sel,
                                const void *a0, size_t a0Size,
                                const void *a1, size_t a1Size,
                                const void *a2, size_t a2Size,
                                const void *a3, size_t a3Size);
uint64_t r_session_msg2_main_raw(RemoteCallSession *session, uint64_t obj, const char *selName,
                                 const void *a0, size_t a0Size,
                                 const void *a1, size_t a1Size,
                                 const void *a2, size_t a2Size,
                                 const void *a3, size_t a3Size);
bool     r_session_msg2_main_struct_ret(RemoteCallSession *session, uint64_t obj, const char *selName,
                                        void *outBuf, size_t outSize,
                                        const void *a0, size_t a0Size,
                                        const void *a1, size_t a1Size,
                                        const void *a2, size_t a2Size,
                                        const void *a3, size_t a3Size);
uint64_t r_session_perform_main(RemoteCallSession *session, uint64_t obj, uint64_t sel, uint64_t object, bool wait);
uint64_t r_session_cfstr(RemoteCallSession *session, const char *s);
uint64_t r_session_nsstr_retained(RemoteCallSession *session, const char *s);
bool     r_session_responds(RemoteCallSession *session, uint64_t obj, const char *selName);
bool     r_session_responds_main(RemoteCallSession *session, uint64_t obj, const char *selName);
uint64_t r_session_ivar_value(RemoteCallSession *session, uint64_t obj, const char *ivarName);
uint64_t r_session_dlsym_call(RemoteCallSession *session, int timeout, const char *fnName,
                              uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                              uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7);
#endif

#endif
