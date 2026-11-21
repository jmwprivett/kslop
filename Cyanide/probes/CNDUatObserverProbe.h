//
// CNDUatObserverProbe.h
//
// Kernel-side observability for the UAT/IOUAT path, driven by the app's own
// kexploit KRW lease.  It flips the IOUAT debug byte that gates the driver's
// own log statements, so the kernel reports which unmap path a teardown takes.
//
// Nothing here touches SPTM memory and nothing is patched: one debug byte in
// kernel data is read, modified with its other bits preserved, and written
// back.  The inverse operation is `CNDUatObserverProbeRestoreRun`.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// True when the kexploit API needed by the probe resolves on this device.
bool CNDUatObserverProbeIsSupported(NSString *_Nullable *_Nullable reason);

/// Enable IOUAT logging (bit 1 of the driver's debug byte).
void CNDUatObserverProbeRun(void (^completion)(NSDictionary<NSString *, id> *report));

/// Restore the debug byte to the value observed before enabling.
void CNDUatObserverProbeRestoreRun(void (^completion)(NSDictionary<NSString *, id> *report));

NS_ASSUME_NONNULL_END
