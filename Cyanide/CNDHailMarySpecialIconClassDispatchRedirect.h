#import <Foundation/Foundation.h>

#import "CNDHailMaryProbe.h"

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDHailMarySpecialIconClassDispatchCompletion)(
    NSDictionary<NSString *, id> *report);

typedef NS_ENUM(NSUInteger, CNDHailMarySpecialIconClassDispatchOperation) {
    CNDHailMarySpecialIconClassDispatchOperationApply = 0,
    CNDHailMarySpecialIconClassDispatchOperationRestore = 1,
    CNDHailMarySpecialIconClassDispatchOperationVerifyRedirected = 2,
    CNDHailMarySpecialIconClassDispatchOperationVerifyOriginal = 3,
};

/// Exact iPhone17,2 / 23A341 gate, identical to the Hail Mary proof.
BOOL CNDHailMarySpecialIconClassDispatchRedirectIsSupported(
    NSString * _Nullable * _Nullable reasonOut);
BOOL CNDHailMarySpecialIconClassDispatchPermissionIsRunning(void);
BOOL CNDHailMarySpecialIconClassDispatchRedirectIsRunning(void);

/// Per-boot `.34.dyldreadonly` permission probe for the two preoptimized
/// Objective-C dispatch entries that resolve
/// `-iconClassForApplicationWithBundleIdentifier:`.
///
/// `SBHIconModel` (SpringBoardHome, class 0x1eda01028) owns the method.
/// SpringBoard's live model is the `SBIconModel` subclass (SpringBoard
/// framework, class 0x281548678). dyld flattens the inherited selector into
/// each class's preoptimized cache, so there are two packed entries in the
/// shared `.34.dyldreadonly` subcache:
///
///   SBHIconModel  slot 68  0x1ffc330a8  frame 0x1ffc30000
///   SBIconModel   slot 68  0x1ffd52eb8  frame 0x1ffd50000
///
/// Each entry packs a 26-bit selector offset and a signed 38-bit
/// class-relative IMP offset; no pointer or PAC bits are stored. Both entries
/// decode to the same IMP (0x1be19db3c). The earlier physical run redirected
/// only the `SBHIconModel` entry and changed nothing because the live
/// receiver is `SBIconModel`, whose own cache entry still resolved the
/// original method.
///
/// The probe runs the complete read-only physical proof, resolves both
/// entries through the live pmaps, requires each 32-byte guard to be exactly
/// the offline original or redirected bytes, and then performs one
/// identical-bytes `kwrite32` per entry (the existing low word written back
/// unchanged) with readback and post-write translation. Its confirmed report
/// is the same-boot ticket for the semantic redirect.
void CNDHailMarySpecialIconClassDispatchPermissionRunWithMode(
    CNDHailMaryProofMode mode,
    CNDHailMarySpecialIconClassDispatchCompletion completion);
void CNDHailMarySpecialIconClassDispatchPermissionRun(
    CNDHailMarySpecialIconClassDispatchCompletion completion);

/// Guarded, reversible redirect of both packed dispatch entries to
/// `+[SBHIconModel applicationIconClass]` (0x1be19d9e8), which returns the
/// ordinary application icon class for every bundle identifier.
///
/// Unlike the `.33` `__got` route, this target is the shared read-only-data
/// subcache that the transparency fix already writes per boot: the frames are
/// shared by every process that maps the cache and are expected not to be
/// re-created on a respring. The base-class entry survived the earlier
/// physical respring, but the two-entry route still needs one complete
/// physical acceptance run before respring persistence can be claimed for
/// the pair. The helper's per-process class cache is irrelevant because the
/// helper is no longer reached.
///
/// Mutation requires a confirmed same-boot permission ticket whose slide,
/// frames, physical addresses, and aperture KVAs match the fresh preflight.
/// Apply requires both entries original; Restore requires both redirected;
/// mixed state is refused. The exact inverse is journaled durably before the
/// first store. One `kwrite32` changes only each entry's low word; the upper
/// word and the 28 neighbouring bytes are preserved. Exact 32-byte readback
/// and stable translations are the terminal automated checks. No automatic
/// rollback, respring, or process restart is installed. Existing Clock and
/// Calendar icon objects are not reclassified. Physical validation showed
/// that their archived canonical objects survive a respring, so Apply/Restore
/// must be followed by the separate bounded two-bundle canonical-object
/// migration in SpringBoard and Spotlight.
void CNDHailMarySpecialIconClassDispatchRedirectRunWithMode(
    CNDHailMaryProofMode mode,
    CNDHailMarySpecialIconClassDispatchOperation operation,
    CNDHailMarySpecialIconClassDispatchCompletion completion);
void CNDHailMarySpecialIconClassDispatchRedirectRun(
    CNDHailMarySpecialIconClassDispatchOperation operation,
    CNDHailMarySpecialIconClassDispatchCompletion completion);

NS_ASSUME_NONNULL_END
