#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDHailMaryReadOnlyDataPageCompletion)(
    NSDictionary<NSString *, id> *report);

/// Exact iPhone17,2 / 23A341 gate, identical to the Hail Mary proof.
BOOL CNDHailMaryReadOnlyDataPageIsSupported(
    NSString * _Nullable * _Nullable reasonOut);
BOOL CNDHailMaryReadOnlyDataPageIsRunning(void);

/// Read-only resolver for the exact .34 preoptimized dispatch entry. The
/// supplied report must be a completed Hail Mary physical proof from the
/// current live SpringBoard and Spotlight identities. All live slide anchors
/// are deduplicated and translated; exactly one candidate must expose either
/// the pinned original or redirected 32-byte guard. The winning translation
/// and bytes are re-read before returning. This helper never writes memory.
BOOL CNDHailMaryReadOnlyDataPageResolveDispatchEntry(
    NSDictionary<NSString *, id> *probeReport,
    BOOL expectRedirected,
    NSDictionary<NSString *, id> * _Nullable * _Nullable contextOut,
    NSData * _Nullable * _Nullable guardDataOut,
    NSString * _Nullable * _Nullable errorOut);

/// Identical-bytes writability probe for the .34 dyldreadonly page that
/// contains SBIconImageView's preoptimized dispatch-cache entry.
///
/// Runs the complete read-only physical proof, gathers the live cache-slide
/// candidates recorded independently for SpringBoard and Spotlight, and
/// translates the offline entry address through both live pmaps for every
/// unique candidate. Exactly one candidate must expose the exact offline
/// 32-byte guard before the experiment arms.
///
/// The only mutation beat is one original kwrite32 transport dispatch whose
/// input word is identical to the existing first word, so all 32 transport
/// bytes are written back unchanged. A durable journal is synced before that
/// dispatch. If the system survives, the bytes and both translations are
/// verified again. The dispatch can still panic if maxProt=r-- governs the
/// physical aperture. No redirect or fallback is implemented here.
void CNDHailMaryReadOnlyDataPageRun(
    CNDHailMaryReadOnlyDataPageCompletion completion);

NS_ASSUME_NONNULL_END
