#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Observes the boot-owned IOUAT record binding through image-anchored globals.
// When allowSameValueWrite is YES, the probe performs one same-value store to
// the live IOUAT +0x20 field and verifies that the object and field remained
// stable. It never substitutes a pointer or scans kernel memory.
void CNDUatHardwareBindingProbeRun(
    BOOL allowSameValueWrite,
    void (^completion)(NSDictionary<NSString *, id> *report));

// Extends the live owner join through the bound 0x28-byte record and its
// physical state-page handle. Read-only: validates the record tag/geometry and
// verifies that the aligned PA is inside the pinned physical range. It never
// derives or dereferences a physmap VA; range membership is not mapping proof.
void CNDUatHardwareRecordStateProbeRun(
    void (^completion)(NSDictionary<NSString *, id> *report));

NS_ASSUME_NONNULL_END
