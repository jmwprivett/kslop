#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDPhysicalEntitlementAuditProbeCompletion)(
    NSDictionary<NSString *, id> *report);

/// Exact iPhone17,2 / 23A341 gate, evaluated in-process from
/// `hw.machine` / `kern.osversion`.
BOOL CNDPhysicalEntitlementAuditProbeIsSupported(NSString **reasonOut);
BOOL CNDPhysicalEntitlementAuditProbeIsRunning(void);

/// Read-only audit of the AMFI entitlement data of the candidate IOUserEthernet
/// holders (bluetoothd first), run entirely on the app's own kexploit KRW.  It
/// never writes kernel memory, never borrows a label and never issues a kernel
/// call: it resolves each process's credential label, reads the AMFI slot value
/// out of it, then follows the typed OSEntitlements chain (read-only data ->
/// DER range) and reports whether `com.apple.networking.ethernet.user-access`
/// is in that process's entitlement blob.  Every hop is validated before the
/// next is read, and a failed check aborts the chain instead of reporting a
/// negative verdict.
///
/// The report is written to `CNDPhysicalEntitlementAuditProbe.json` in the app
/// container.
void CNDPhysicalEntitlementAuditProbeRun(
    CNDPhysicalEntitlementAuditProbeCompletion completion);

NS_ASSUME_NONNULL_END
