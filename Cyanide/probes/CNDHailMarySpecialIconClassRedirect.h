#import <Foundation/Foundation.h>

#import "CNDHailMaryProbe.h"

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDHailMarySpecialIconClassCompletion)(
    NSDictionary<NSString *, id> *report);

typedef NS_ENUM(NSUInteger, CNDHailMarySpecialIconClassOperation) {
    CNDHailMarySpecialIconClassOperationApply = 0,
    CNDHailMarySpecialIconClassOperationRestore = 1,
    CNDHailMarySpecialIconClassOperationVerifyRedirected = 2,
    CNDHailMarySpecialIconClassOperationVerifyOriginal = 3,
};

/// Exact iPhone17,2 / 23A341 gate, identical to the Hail Mary proof.
BOOL CNDHailMarySpecialIconClassRedirectIsSupported(
    NSString * _Nullable * _Nullable reasonOut);
BOOL CNDHailMarySpecialIconClassPermissionIsRunning(void);
BOOL CNDHailMarySpecialIconClassRedirectIsRunning(void);

/// Read-only probe of the two SpringBoardHome `__got` slots that
/// `SBHIconModel -iconClassForApplicationWithBundleIdentifier:` uses for
/// `com.apple.mobiletimer` and `com.apple.mobilecal`.
///
/// The helper is a tiny Swift thunk that compares the bundle identifier
/// against the literal strings in `.19` text. On a match it loads the special
/// class pointer from
/// `__got._OBJC_CLASS_$_SBHClockApplicationIcon` (0x1e8278298) or
/// `__got._OBJC_CLASS_$_SBHCalendarApplicationIcon` (0x1e8278270). Both slots
/// are in the `.33.dylddata` subcache, a non-executable shared-cache data
/// mapping with `maxProt=rw-`; the Hail Mary data-page experiment already
/// proved that this subcache family accepts an identical-bytes aperture write.
///
/// The probe proves both slots through SpringBoard and Spotlight, reads their
/// exact 8-byte values, and writes a ticket for the current boot/process. It
/// changes no byte and launches no write primitive.
void CNDHailMarySpecialIconClassPermissionRunWithMode(
    CNDHailMaryProofMode mode,
    CNDHailMarySpecialIconClassCompletion completion);
void CNDHailMarySpecialIconClassPermissionRun(
    CNDHailMarySpecialIconClassCompletion completion);

/// Guarded, reversible redirect of the two SpringBoardHome `__got` class
/// pointers to `_OBJC_CLASS_$_SBHApplicationIcon` (0x1eda021a8).
///
/// This is the data-only route. It does not write the `.19` method-list IMP
/// field, the helper's text, or any executable page. Applying it changes two
/// 8-byte class pointers in the same `.33.dylddata` page family that already
/// accepted an aperture write; Clock and Calendar then take the helper's
/// ordinary application-icon tail and use the persistent SnowBoard
/// IconServices records for those bundle identifiers.
///
/// Mutation requires a successful read-only probe ticket from the current
/// boot. Each operation re-proves the slots through both live pmaps, journals
/// the exact inverse before the first store, writes both slots with one
/// `kwrite64` each, requires exact 8-byte readback, and re-translates both
/// slots. No automatic rollback, respring, or process restart is installed.
///
/// The helper caches the selected class per process. The GOT write is
/// per-process, not per-boot: a controlled respring starts fresh
/// SpringBoard/Spotlight processes with a fresh `.33` GOT page and restores
/// the original class pointers. The helper's class-cache slots are also warm
/// in the live process, so reapplying the GOT pointer alone does not change
/// the live icons after a respring. The persistent themed icon records are
/// never modified. Clock hands and the Calendar date intentionally stop
/// updating while the static art is shown.
void CNDHailMarySpecialIconClassRedirectRunWithMode(
    CNDHailMaryProofMode mode,
    CNDHailMarySpecialIconClassOperation operation,
    CNDHailMarySpecialIconClassCompletion completion);
void CNDHailMarySpecialIconClassRedirectRun(
    CNDHailMarySpecialIconClassOperation operation,
    CNDHailMarySpecialIconClassCompletion completion);

NS_ASSUME_NONNULL_END
