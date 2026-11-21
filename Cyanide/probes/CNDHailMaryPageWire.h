#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDHailMaryPageWireCompletion)(
    NSDictionary<NSString *, id> *report);

/// Exact iPhone17,2 / 23A341 gate, identical to the Hail Mary proof.
BOOL CNDHailMaryPageWireIsSupported(
    NSString * _Nullable * _Nullable reasonOut);
BOOL CNDHailMaryPageWireIsRunning(void);

/// SpringBoard `mlock` feasibility probe for the .34 read-only-data page that
/// carries SBIconImageView's preoptimized dispatch entry.
///
/// The probe is read-only with respect to kernel memory and to the page: it
/// calls no kernel write primitive and does not change a byte. It re-proves the
/// exact .34 page identity through SpringBoard's own live pmap walk (no second
/// process is resolved, opened, or consulted), records a durable journal, and
/// then runs one bounded RemoteCall session in SpringBoard that:
///
///   1. mlock()s a freshly mapped anonymous writable 16 KiB page (control:
///      proves the caller, the session, and the mlock path work at all);
///   2. mlock()s a freshly mapped anonymous read-only 16 KiB page (control:
///      isolates "a read-only mapping cannot be mlocked" from anything
///      specific to the dyld shared cache);
///   3. mlock()s the exact 16 KiB shared-cache frame that contains the .34
///      dispatch entry (the experiment).
///
/// A successful target wire is retained on purpose: the question is whether a
/// SpringBoard-owned wire can hold that page against the silent clean-page
/// purge. The report records the inverse (`munlock` of the same range in
/// SpringBoard), notes that the wire is released when SpringBoard exits, and
/// states the longitudinal guard check that would prove it held.
void CNDHailMaryPageWireRun(
    CNDHailMaryPageWireCompletion completion);

NS_ASSUME_NONNULL_END
