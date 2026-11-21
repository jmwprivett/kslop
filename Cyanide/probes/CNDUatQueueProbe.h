//
//  CNDUatQueueProbe.h
//
//  Diagnose why selector 45 rejects a submit: read the AGX user-client object and
//  the queue object it publishes, instead of inferring the cause from return codes.
//
//  The static audit (tools/iogpu_submit_audit.py) shows the submit callee returns
//  kIOReturnError from two `cbz` checks on `queue+0x78` and `queue+0x28` before it
//  ever looks at the records.  The device run shows those fields stay NULL across
//  every queue-creation shape, so the next question is "what is the object we are
//  submitting to, and which fields are actually set".
//
//  This probe answers that with kslop's own KRW: the client port we opened is
//  resolved to its kernel object with task_get_ipc_port_kobject(), then the tables
//  at client+0x110 / client+0x120 and the queue slot are dumped.
//
//  Read-only: no kernel writes.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

bool CNDUatQueueProbeIsSupported(NSString *_Nullable *_Nullable reason);
// enableWalk gates the page-table walk.  Pass NO to only read the pinned
// physmap/root slots: a walk follows values that a bad root makes arbitrary, so
// it must stay off until those values have been inspected on their own.
void CNDUatQueueProbeRun(BOOL enableWalk,
                         void (^completion)(NSDictionary<NSString *, id> *report));

// Reads only statically known kernel-image addresses (physmap globals plus the
// physical-aperture descriptor windows).  No user client and no pointer taken
// from a kernel object ever reaches the read primitive, because a read of an
// unmapped page inside the physical aperture panics the machine.
void CNDUatImageProbeRun(void (^completion)(NSDictionary<NSString *, id> *report));

// Shortest possible run: the three physmap globals and two aperture control
// reads.  Use this when the question is only whether an aperture VA is mapped,
// because a wedged socket primitive can stall a longer probe indefinitely.
void CNDUatPhysControlRun(void (^completion)(NSDictionary<NSString *, id> *report));

NS_ASSUME_NONNULL_END
