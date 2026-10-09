#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDHailMaryDataPageCompletion)(
    NSDictionary<NSString *, id> *report);

/// Exact iPhone17,2 / 23A341 gate, identical to the Hail Mary proof.
BOOL CNDHailMaryDataPageIsSupported(NSString * _Nullable * _Nullable reasonOut);
BOOL CNDHailMaryDataPageIsRunning(void);

/// Hail Mary data-page aperture-writability experiment.
///
/// Runs the full read-only Hail Mary proof first, then decodes the guarded
/// method's adrp/ldr pair from the exact 188-byte original guard bytes to
/// derive the unslid address of the global object slot that method loads.
/// The derived runtime address is translated through both proven live
/// pmaps and must resolve to one terminal shared physical frame that
/// differs from the guarded text frame.
///
/// The single experiment beat writes the exact identical 32-byte transport
/// window back over that data-page slot through one original kwrite32
/// read/merge dispatch. Identical bytes exercise the physical-aperture
/// mapping's write permission without any semantic change; the dispatch
/// may still panic if the aperture maps this data page read-only, which
/// is precisely the open question. If the system remains alive, the 32
/// bytes are read back, required to be identical, and both translations
/// are repeated. The report and its durable prewrite journal live in
/// Documents/CNDHailMaryDataPage.json.
void CNDHailMaryDataPageRun(CNDHailMaryDataPageCompletion completion);

NS_ASSUME_NONNULL_END