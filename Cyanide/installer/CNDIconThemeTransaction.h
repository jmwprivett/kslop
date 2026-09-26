#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class CNDDockApplication;

typedef NS_ENUM(NSInteger, CNDIconThemeTransactionDisposition) {
    CNDIconThemeTransactionDispositionPrepared,
    CNDIconThemeTransactionDispositionActive,
    CNDIconThemeTransactionDispositionRestored,
    CNDIconThemeTransactionDispositionPartial,
    CNDIconThemeTransactionDispositionDrift,
    CNDIconThemeTransactionDispositionSuperseded,
    CNDIconThemeTransactionDispositionInvalid,
};

/// One independent, durable application-icon recovery unit.
@interface CNDIconThemeTransaction : NSObject

@property (nonatomic, copy, readonly) NSString *bundleIdentifier;
@property (nonatomic, strong, readonly) NSURL *journalURL;

- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier;

- (NSDictionary<NSString *, id> *)preflightSourcePNGData:(NSData *)sourcePNGData;
- (NSDictionary<NSString *, id> *)applySourcePNGData:(NSData *)sourcePNGData;
- (NSDictionary<NSString *, id> *)restore;
- (NSDictionary<NSString *, id> *)status;
/// Classifies this journal against a caller-owned installed-app snapshot.
/// The snapshot is read-only and is used only for path/version supersession
/// checks; the restore/apply paths still revalidate the exact target before
/// mutating it.  Passing one snapshot lets a status list avoid repeating the
/// full LaunchServices/catalog walk once per journal.
- (NSDictionary<NSString *, id> *)statusWithInstalledApplications:
    (NSArray<CNDDockApplication *> *)applications;

+ (NSURL *)transactionsDirectoryURL;
+ (NSArray<CNDIconThemeTransaction *> *)journaledTransactions;

/// Journals completed inside a shared installd batch remain pending until the
/// coordinator closes that session cleanly. These helpers promote or finalize
/// only the already verified pending journals after that close.
+ (NSDictionary<NSString *, id> *)promotePendingBatchTransactions;
+ (NSDictionary<NSString *, id> *)finalizePendingRestoreTransactions;

@end

NS_ASSUME_NONNULL_END
