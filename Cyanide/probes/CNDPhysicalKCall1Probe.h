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

/// Read one live Metal-buffer translation through IOUAT::getPageTableEntry.
/// The call is mediated entirely by kernel-owned, byte-pinned call adapters;
/// no physical alias is derived or dereferenced.  Every temporary callback,
/// ifnet field and global slot is restored and verified before completion.
void CNDPhysicalKCall1UatPTEProbeRun(
    CNDPhysicalKCall1ProbeCompletion completion);

/// Ask the pinned IOUserEthernet initializer to sign one ENOEXEC callback at
/// the hardware-validated ifnet+0x2a8 field, then tear that interface down.
/// This requires an existing KRW generation and never acquires or cleans it;
/// it does not mutate an ifnet field or invoke the resulting callback.
void CNDPhysicalKCall1UatSignerOracleRun(
    CNDPhysicalKCall1ProbeCompletion completion);

/// Inventory already-live ifnet check_multi signatures for the pinned UAT
/// adapter targets.  This consumes an existing KRW generation for reads only:
/// it does not acquire or clean up KRW, open a user client, invoke a selector,
/// issue an ioctl/callback, or write any kernel field/global slot.
void CNDPhysicalKCall1UatSignerInventoryRun(
    CNDPhysicalKCall1ProbeCompletion completion);

/// Scratch-write oracle: can the live (recovered, parked) KRW pair write at
/// all?  Writes one 32-byte block to the app's own proc->p_pid (expected value
/// known from getpid()), reads it back, then restores and verifies.  This
/// separates "write direction dead on the recovered pair" from "the MAC label
/// is in a region the write path cannot reach".  Never acquires or cleans up
/// KRW; refuses rather than acquire.
void CNDPhysicalKCall1ScratchWriteOracleRun(
    CNDPhysicalKCall1ProbeCompletion completion);

NS_ASSUME_NONNULL_END
