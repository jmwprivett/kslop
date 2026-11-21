//
//  CNDUatContextProbe.h
//
//  E1 of PLAN-2026-10-26: read the IOUAT/gart context table through the app's
//  KRW lease, snapshot it, perform one named app action at a time, and report
//  which 16-byte entry changed.  Read-only: this probe performs no kernel write
//  of any kind.
//
//  Why it does not read `uat_instance`: that address is in SPTM's own address
//  space, so XNU (and therefore any task-based KRW lease) cannot dereference it.
//  The IOUAT layer is reachable instead: the XNU global `gIOUAT` carries the
//  table pointer that AGX writes through, and that is the same array whose
//  entries `sptm_uat_set_ctx_id` produces.  Reading it is the identity join.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// True when the kexploit API needed by the probe resolves on this device.
bool CNDUatContextProbeIsSupported(NSString *_Nullable *_Nullable reason);

/// Snapshot the context table, run the action matrix, report the per-action diff.
void CNDUatContextProbeRun(void (^completion)(NSDictionary<NSString *, id> *report));

NS_ASSUME_NONNULL_END
