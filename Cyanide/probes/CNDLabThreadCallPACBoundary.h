#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDLabThreadCallPACBoundaryCompletion)(
    NSDictionary<NSString *, id> *report);

/// This diagnostic is pinned to the REA-verified iOS 26.0 / 23A341 vPhone
/// kernel.  Physical devices and non-matching VM kernels are refused.
BOOL CNDLabThreadCallPACBoundaryIsSupported(NSString **reasonOut);
BOOL CNDLabThreadCallPACBoundaryIsRunning(void);

/// Create one ordinary Mach timer and inspect its kernel-owned port label and
/// embedded thread_call through the read-only VM KRW provider.  The probe
/// never arms the timer and performs no kernel write or kcall.
void CNDLabThreadCallPACBoundaryRun(
    CNDLabThreadCallPACBoundaryCompletion completion);

/// Repeat the exact idle-boundary validation, then write one fixed canary to
/// the unsigned thread_call param1 field, read it back, restore the original
/// value, and verify the restoration before destroying the timer.  The timer
/// is never armed and the signed callback is never changed or dispatched.
void CNDLabThreadCallPACBoundaryRunReversibleMutation(
    CNDLabThreadCallPACBoundaryCompletion completion);

/// Arm the ordinary Mach timer once, verify mk_timer_arm produced the exact
/// queued state and normalized param1 to zero, then write the fixed canary to
/// that queued call without changing its signed callback or param0.
/// Exact-build instruction evidence proves mk_timer_expire ignores incoming
/// x1.  The probe requires the real expiration Mach message, restores param1,
/// and cancels the timer on every incomplete path.  It performs no kcall.
void CNDLabThreadCallPACBoundaryRunOriginalCallbackDispatch(
    CNDLabThreadCallPACBoundaryCompletion completion);

/// Reuse two exact-build kernel-owned PAC-valid pointers: an IA/0x73d8
/// thread_call callback that performs `braaz x1`, and an IA-zero-signed target
/// whose current three-byte gate state selects a read-only early return.  The
/// probe dispatches that target once with a fixed x0 canary, restores all three
/// transplanted thread_call fields, and repairs the ordinary Mach timer's
/// unsigned owner state before destruction.  It uses KRW but no kcall.
void CNDLabThreadCallPACBoundaryRunPACReuseDispatch(
    CNDLabThreadCallPACBoundaryCompletion completion);

/// Reuse the exact root-domain PM thread_call's kernel-owned PAC-valid
/// pmDriverCallout callback in an idle sacrificial Mach timer.  The VM-only
/// probe stages one same-state setPowerState request, requires the PM
/// action-done busy-bit clear, then restores the PM state and all timer fields
/// before destruction.  It uses KRW and performs no provider kcall.
void CNDLabThreadCallPACBoundaryRunPMCalloutHarvest(
    CNDLabThreadCallPACBoundaryCompletion completion);

/// Temporarily select one live IOUserServer as the root domain's controlling
/// driver, then run the same harvested pmDriverCallout.  The exact-build PM
/// path authenticates that real object's vtable and its +0x4d8 method before
/// calling IOUserServer::setPowerState with the IOUserServer as x0.  The
/// target is accepted only while its debug-only body is disabled.  The
/// controlling-driver field and all timer/PM fields are restored.  No
/// provider kcall is used.
void CNDLabThreadCallPACBoundaryRunPMCrossClassDispatch(
    CNDLabThreadCallPACBoundaryCompletion completion);

/// Resolve the exact live AppleM68Buttons service, temporarily select it as
/// the root domain's controlling driver, and autonomously invoke its signed
/// setPowerState override through the harvested PM callback.  This is the
/// no-provider trigger used by the UPA carrier experiment; the caller owns
/// any reversible UPA/M68 field staging around it.
void CNDLabThreadCallPACBoundaryRunPMM68Dispatch(
    CNDLabThreadCallPACBoundaryCompletion completion);

NS_ASSUME_NONNULL_END
