#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDPhysicalKCall1ProbeCompletion)(
    NSDictionary<NSString *, id> *report);

/// Exact iPhone17,2 / 23A341 gate, evaluated in-process from
/// `hw.machine` / `kern.osversion`.
BOOL CNDPhysicalKCall1ProbeIsSupported(NSString **reasonOut);
BOOL CNDPhysicalKCall1ProbeIsRunning(void);

/// Run the kcall1 chosen-PC/chosen-X0 canary entirely on the device, on the
/// app's own kexploit KRW (`kreadbuf`/`kwrite64`, base from
/// `g_kernel_base`/`g_kernel_slide`) - no provider, socket, root or host
/// process.  The report is the verdict and is written to
/// `CNDPhysicalKCall1Probe.json` in the app container.
void CNDPhysicalKCall1ProbeRun(CNDPhysicalKCall1ProbeCompletion completion);

NS_ASSUME_NONNULL_END
