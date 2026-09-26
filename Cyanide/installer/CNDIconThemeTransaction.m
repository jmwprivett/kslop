#import "CNDIconThemeTransaction.h"

#import "CNDIconDeclarationRedirect.h"
#import "CNDDockAppCatalog.h"
#import <CommonCrypto/CommonDigest.h>
#import <ImageIO/ImageIO.h>
#import <errno.h>
#import <sys/stat.h>

static const NSUInteger CNDRemixJournalSchemaVersion = 1;
static const NSUInteger CNDRemixTargetSelectionRecipeVersion = 1;
static const uint64_t CNDRemixMaximumSourcePixels = 64ULL * 1024ULL * 1024ULL;
static const NSUInteger CNDRemixMaximumSourceBytes = 64U * 1024U * 1024U;

static NSString *CNDRemixSHA256(NSData *data)
{
    if (![data isKindOfClass:NSData.class]) return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *value = [NSMutableString stringWithCapacity:64];
    for (NSUInteger index = 0; index < sizeof(digest); index++) {
        [value appendFormat:@"%02x", digest[index]];
    }
    return value;
}

static NSString *CNDRemixSafeBundleIdentifier(NSString *value)
{
    if (![value isKindOfClass:NSString.class] || value.length == 0 ||
        value.length > 255 || [value containsString:@"/"] ||
        [value containsString:@"\\"] || [value containsString:@".."] ||
        [value hasPrefix:@"."] || [value hasSuffix:@"."]) return nil;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
        @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"];
    return [value rangeOfCharacterFromSet:allowed.invertedSet].location == NSNotFound
        ? value : nil;
}

static NSDictionary *CNDRemixResult(BOOL ok, NSString *stage,
                                     NSString *message, NSDictionary *details)
{
    NSMutableDictionary *result = details ? [details mutableCopy] :
        [NSMutableDictionary dictionary];
    result[@"ok"] = @(ok);
    result[@"stage"] = stage ?: @"unknown";
    result[@"message"] = message ?: @"";
    return result;
}

static BOOL CNDRemixWriteJournal(NSURL *url, NSDictionary *journal,
                                 NSError **errorOut)
{
    if (![url isKindOfClass:NSURL.class] || !url.isFileURL ||
        ![journal isKindOfClass:NSDictionary.class]) return NO;
    NSData *encoded = [NSPropertyListSerialization dataWithPropertyList:journal
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:errorOut];
    if (!encoded || ![encoded writeToURL:url options:NSDataWritingAtomic
                                   error:errorOut]) return NO;
    NSDictionary *readback = [NSDictionary dictionaryWithContentsOfURL:url];
    if (![readback isEqual:journal]) {
        if (errorOut && !*errorOut) *errorOut = [NSError errorWithDomain:
            @"CNDSnowBoardRemix" code:3 userInfo:@{NSLocalizedDescriptionKey:
                @"The recovery journal failed readback after a durable update."}];
        return NO;
    }
    return YES;
}

static BOOL CNDRemixRecipeCompatible(NSDictionary *journal,
                                     NSString **reasonOut)
{
    NSNumber *schemaVersion = journal[@"schemaVersion"];
    NSDictionary *recipe = journal[@"targetSelectionRecipe"];
    NSNumber *recipeVersion = [recipe isKindOfClass:NSDictionary.class]
        ? recipe[@"version"] : nil;
    NSString *name = [recipe isKindOfClass:NSDictionary.class]
        ? recipe[@"name"] : nil;
    NSDictionary *file = journal[@"fileMutation"];
    NSUInteger schema = [schemaVersion isKindOfClass:NSNumber.class]
        ? schemaVersion.unsignedIntegerValue : 0;
    NSUInteger recipeVersionValue = [recipeVersion isKindOfClass:NSNumber.class]
        ? recipeVersion.unsignedIntegerValue : 0;
    NSUInteger deviceScale = [recipe[@"deviceScale"] isKindOfClass:NSNumber.class]
        ? [recipe[@"deviceScale"] unsignedIntegerValue] : 0;
    NSUInteger selectedScale = [recipe[@"selectedScale"] isKindOfClass:NSNumber.class]
        ? [recipe[@"selectedScale"] unsignedIntegerValue] : 0;
    NSUInteger fileScale = [file[@"scale"] isKindOfClass:NSNumber.class]
        ? [file[@"scale"] unsignedIntegerValue] : 0;
    BOOL valid = schema == CNDRemixJournalSchemaVersion &&
        [recipe isKindOfClass:NSDictionary.class] &&
        recipeVersionValue == CNDRemixTargetSelectionRecipeVersion &&
        [name isEqual:@"legacy-phone-fallback"] &&
        deviceScale == 2 &&
        selectedScale > 0 &&
        selectedScale == fileScale &&
        [recipe[@"selectedRelativePath"] isEqual:file[@"relativePath"]] &&
        [recipe[@"selectedDeclaration"] isEqual:file[@"declaredBaseName"]] &&
        [recipe[@"declaredFilesBefore"] isEqual:file[@"declaredFilesBefore"]] &&
        [recipe[@"declaredFilesBeforePresent"] boolValue] ==
            [file[@"declaredFilesBeforePresent"] boolValue] &&
        [recipe[@"addsDeclaration"] boolValue] == [file[@"addsDeclaration"] boolValue];
    if (!valid && reasonOut) {
        if (schema != CNDRemixJournalSchemaVersion) {
            *reasonOut = @"the Remix journal schema is legacy or unsupported";
        } else if (![recipe isKindOfClass:NSDictionary.class]) {
            *reasonOut = @"the journal predates the versioned target-selection recipe";
        } else if (recipeVersionValue != CNDRemixTargetSelectionRecipeVersion) {
            *reasonOut = @"the target-selection recipe version is unsupported";
        } else {
            *reasonOut = @"the journal target-selection recipe does not match its saved target";
        }
    }
    return valid;
}

/* Read-only launch classification.  Recovery journals are deliberately kept
 * after a successful write, so a process restart must inspect both vnodes
 * instead of trusting the last recorded phase.  In particular, a third-party
 * replacement must be reported as drift and never treated as an active Remix
 * icon. */
static NSDictionary *CNDRemixClassifyMutation(NSDictionary *mutation)
{
    if (![mutation isKindOfClass:NSDictionary.class]) {
        return @{ @"state": @"invalid" };
    }
    NSString *path = mutation[@"targetPath"];
    NSString *mode = mutation[@"mode"];
    NSString *originalHash = mutation[@"originalHash"];
    NSString *replacementHash = mutation[@"replacementHash"];
    if (![path isKindOfClass:NSString.class] || path.length == 0 ||
        ![mode isKindOfClass:NSString.class]) {
        return @{ @"state": @"invalid" };
    }
    struct stat st = {0};
    if (lstat(path.fileSystemRepresentation, &st) != 0) {
        if (errno == ENOENT && [mode isEqual:@"create"]) {
            return @{ @"state": @"restored", @"absent": @YES };
        }
        return @{ @"state": @"unavailable", @"error": @(errno) };
    }
    if (S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode)) {
        return @{ @"state": @"drift", @"reason": @"not-regular" };
    }
    NSData *bytes = [NSData dataWithContentsOfFile:path options:0 error:nil];
    NSString *hash = CNDRemixSHA256(bytes);
    if (hash.length == 0) {
        return @{ @"state": @"unavailable" };
    }
    if ([mode isEqual:@"create"]) {
        return [hash isEqual:replacementHash]
            ? @{ @"state": @"themed", @"hash": hash }
            : @{ @"state": @"drift", @"hash": hash };
    }
    if ([hash isEqual:replacementHash]) {
        return @{ @"state": @"themed", @"hash": hash };
    }
    if ([hash isEqual:originalHash]) {
        return @{ @"state": @"original", @"hash": hash };
    }
    return @{ @"state": @"drift", @"hash": hash };
}

@interface CNDIconThemeTransaction ()
@property (nonatomic, copy, readwrite) NSString *bundleIdentifier;
@property (nonatomic, strong, readwrite) NSURL *journalURL;
- (NSDictionary<NSString *, id> *)promotePendingBatchTransaction;
- (NSDictionary<NSString *, id> *)finalizePendingRestoreTransaction;
@end

@implementation CNDIconThemeTransaction

+ (NSURL *)transactionsDirectoryURL
{
    NSURL *support = [NSFileManager.defaultManager
        URLsForDirectory:NSApplicationSupportDirectory
        inDomains:NSUserDomainMask].firstObject;
    return [[support URLByAppendingPathComponent:@"SnowBoardRemix" isDirectory:YES]
        URLByAppendingPathComponent:@"Transactions" isDirectory:YES];
}

- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier
{
    NSString *safe = CNDRemixSafeBundleIdentifier(bundleIdentifier);
    if (!safe) return nil;
    self = [super init];
    if (self) {
        _bundleIdentifier = [safe copy];
        _journalURL = [[[self.class transactionsDirectoryURL]
            URLByAppendingPathComponent:safe isDirectory:NO]
            URLByAppendingPathExtension:@"plist"];
    }
    return self;
}

+ (NSArray<CNDIconThemeTransaction *> *)journaledTransactions
{
    NSArray<NSURL *> *urls = [NSFileManager.defaultManager
        contentsOfDirectoryAtURL:self.transactionsDirectoryURL
        includingPropertiesForKeys:nil options:0 error:nil] ?: @[];
    NSMutableArray *transactions = [NSMutableArray array];
    for (NSURL *url in urls) {
        if (![url.pathExtension.lowercaseString isEqual:@"plist"]) continue;
        NSString *identifier = url.URLByDeletingPathExtension.lastPathComponent;
        CNDIconThemeTransaction *transaction =
            [[self alloc] initWithBundleIdentifier:identifier];
        if (transaction) [transactions addObject:transaction];
    }
    return [transactions sortedArrayUsingComparator:^NSComparisonResult(id left, id right) {
        return [[left bundleIdentifier] compare:[right bundleIdentifier]];
    }];
}

- (NSDictionary<NSString *, id> *)promotePendingBatchTransaction
{
    NSDictionary *journal = [NSDictionary dictionaryWithContentsOfURL:self.journalURL];
    NSString *state = journal[@"transactionState"];
    BOOL pending = [state isEqual:@"pending"] ||
        [journal[@"batchCommitState"] isEqual:@"pending"];
    if (!pending) {
        return CNDRemixResult(YES,
            [state isEqual:@"active"] ? @"already-active" : @"not-pending",
            [state isEqual:@"active"]
                ? @"The verified transaction is already active."
                : @"The journal was not pending shared batch promotion.",
            @{ @"bundleIdentifier": self.bundleIdentifier,
               @"transactionState": state ?: @"missing" });
    }
    NSDictionary *status = [self status];
    if (![status[@"stage"] isEqual:@"pending"] ||
        ![status[@"componentStates"][@"icon"] isEqual:@"themed"] ||
        ![status[@"componentStates"][@"infoPlist"] isEqual:@"themed"] ||
        !CNDRemixRecipeCompatible(journal, NULL)) {
        return CNDRemixResult(NO, @"batch-promotion-verification",
            @"The pending transaction failed verification and remains recoverable.",
            @{ @"bundleIdentifier": self.bundleIdentifier,
               @"status": status ?: @{},
               @"transactionState": state ?: @"unknown" });
    }
    NSMutableDictionary *promoted = [journal mutableCopy];
    promoted[@"transactionState"] = @"active";
    promoted[@"batchCommitState"] = @"committed";
    promoted[@"batchCommittedAt"] = NSDate.date;
    NSError *error = nil;
    if (!CNDRemixWriteJournal(self.journalURL, promoted, &error)) {
        return CNDRemixResult(NO, @"batch-promotion-journal",
            error.localizedDescription ?: @"The verified transaction could not be promoted.",
            @{ @"bundleIdentifier": self.bundleIdentifier,
               @"transactionState": state ?: @"pending" });
    }
    return CNDRemixResult(YES, @"active",
        @"The verified transaction was promoted after clean shared installd finalization.",
        @{ @"bundleIdentifier": self.bundleIdentifier,
           @"transactionState": @"active",
           @"batchCommitState": @"committed" });
}

- (NSDictionary<NSString *, id> *)finalizePendingRestoreTransaction
{
    NSDictionary *journal = [NSDictionary dictionaryWithContentsOfURL:self.journalURL];
    NSString *state = journal[@"transactionState"];
    if (![state isEqual:@"restore-pending"]) {
        return CNDRemixResult(YES,
            [state isEqual:@"restored"] ? @"already-restored" : @"not-pending",
            [state isEqual:@"restored"]
                ? @"The restoration journal is already finalized."
                : @"The journal was not pending shared batch restore finalization.",
            @{ @"bundleIdentifier": self.bundleIdentifier,
               @"transactionState": state ?: @"missing" });
    }
    NSDictionary *status = [self status];
    if (![status[@"stage"] isEqual:@"restored"] &&
        ![status[@"stage"] isEqual:@"restore-pending"]) {
        return CNDRemixResult(NO, @"restore-promotion-verification",
            @"The pending restoration failed verification and remains recoverable.",
            @{ @"bundleIdentifier": self.bundleIdentifier,
               @"status": status ?: @{},
               @"transactionState": state });
    }
    NSError *error = nil;
    if (![NSFileManager.defaultManager removeItemAtURL:self.journalURL error:&error] &&
        [NSFileManager.defaultManager fileExistsAtPath:self.journalURL.path]) {
        return CNDRemixResult(NO, @"restore-promotion-cleanup",
            error.localizedDescription ?: @"The pending restoration journal could not be removed.",
            @{ @"bundleIdentifier": self.bundleIdentifier,
               @"transactionState": state });
    }
    return CNDRemixResult(YES, @"restored",
        @"The verified restoration journal was cleared after clean shared installd finalization.",
        @{ @"bundleIdentifier": self.bundleIdentifier,
           @"transactionState": @"restored" });
}

+ (NSDictionary<NSString *, id> *)promotePendingBatchTransactions
{
    NSMutableArray *results = [NSMutableArray array];
    NSUInteger promoted = 0;
    NSUInteger failed = 0;
    for (CNDIconThemeTransaction *transaction in self.journaledTransactions) {
        NSDictionary *journal = [NSDictionary dictionaryWithContentsOfURL:
            transaction.journalURL];
        NSString *state = journal[@"transactionState"];
        if (![state isEqual:@"pending"] &&
            ![journal[@"batchCommitState"] isEqual:@"pending"]) continue;
        NSDictionary *result = [transaction promotePendingBatchTransaction];
        [results addObject:result ?: @{}];
        if ([result[@"ok"] boolValue]) promoted++; else failed++;
    }
    return CNDRemixResult(failed == 0,
        failed == 0 ? @"batch-promoted" : @"batch-promotion-failed",
        failed == 0
            ? @"Verified pending Remix transactions were promoted after clean batch finalization."
            : @"Some verified Remix transactions remain pending and require recovery.",
        @{ @"promoted": @(promoted), @"failed": @(failed),
           @"results": results });
}

+ (NSDictionary<NSString *, id> *)finalizePendingRestoreTransactions
{
    NSMutableArray *results = [NSMutableArray array];
    NSUInteger finalized = 0;
    NSUInteger failed = 0;
    for (CNDIconThemeTransaction *transaction in self.journaledTransactions) {
        NSDictionary *journal = [NSDictionary dictionaryWithContentsOfURL:
            transaction.journalURL];
        if (![journal[@"transactionState"] isEqual:@"restore-pending"]) continue;
        NSDictionary *result = [transaction finalizePendingRestoreTransaction];
        [results addObject:result ?: @{}];
        if ([result[@"ok"] boolValue]) finalized++; else failed++;
    }
    return CNDRemixResult(failed == 0,
        failed == 0 ? @"restore-promoted" : @"restore-promotion-failed",
        failed == 0
            ? @"Verified pending restorations were finalized after clean batch teardown."
            : @"Some restorations remain journaled and require recovery.",
        @{ @"finalized": @(finalized), @"failed": @(failed),
           @"results": results });
}

- (NSDictionary<NSString *, id> *)preflightSourcePNGData:(NSData *)data
{
    if (![data isKindOfClass:NSData.class] || data.length == 0) {
        return CNDRemixResult(NO, @"empty-png", @"The theme icon is empty.", nil);
    }
    if (data.length > CNDRemixMaximumSourceBytes) {
        return CNDRemixResult(NO, @"source-too-large",
            @"The theme icon exceeds the safe encoded-size limit.", nil);
    }
    CGImageSourceRef source = CGImageSourceCreateWithData((__bridge CFDataRef)data, NULL);
    if (!source || CGImageSourceGetCount(source) != 1 ||
        CGImageSourceGetStatusAtIndex(source, 0) != kCGImageStatusComplete) {
        if (source) CFRelease(source);
        return CNDRemixResult(NO, @"corrupt-png",
            @"The theme icon is not one complete PNG image.", nil);
    }
    CFStringRef type = CGImageSourceGetType(source);
    NSDictionary *properties = CFBridgingRelease(
        CGImageSourceCopyPropertiesAtIndex(source, 0, NULL));
    uint64_t width = [properties[(NSString *)kCGImagePropertyPixelWidth]
        unsignedLongLongValue];
    uint64_t height = [properties[(NSString *)kCGImagePropertyPixelHeight]
        unsignedLongLongValue];
    BOOL png = type && [(__bridge NSString *)type isEqualToString:@"public.png"];
    CFRelease(source);
    if (!png || width == 0 || height == 0 ||
        width > CNDRemixMaximumSourcePixels / height ||
        width * height > CNDRemixMaximumSourcePixels) {
        return CNDRemixResult(NO, @"png-dimensions",
            @"The theme icon has unsupported or excessive dimensions.", nil);
    }
    BOOL alreadyActive = [NSFileManager.defaultManager
        fileExistsAtPath:self.journalURL.path];
    return CNDRemixResult(!alreadyActive,
        alreadyActive ? @"already-active" : @"source-ready",
        alreadyActive ? @"A recovery transaction already exists for this app." :
            @"The source PNG passed bounded decode preflight.", @{
                @"bundleIdentifier": self.bundleIdentifier,
                @"sourceWidth": @(width), @"sourceHeight": @(height),
                @"sourceLength": @(data.length),
                @"sourceHash": CNDRemixSHA256(data) ?: @"",
            });
}

- (NSDictionary<NSString *, id> *)applySourcePNGData:(NSData *)sourcePNGData
{
    NSDictionary *preflight = [self preflightSourcePNGData:sourcePNGData];
    if (![preflight[@"ok"] boolValue]) return preflight;
    NSError *directoryError = nil;
    if (![NSFileManager.defaultManager createDirectoryAtURL:
            self.journalURL.URLByDeletingLastPathComponent
            withIntermediateDirectories:YES
            attributes:@{NSFileProtectionKey: NSFileProtectionNone}
            error:&directoryError]) {
        return CNDRemixResult(NO, @"journal-directory",
            directoryError.localizedDescription, nil);
    }
    NSDictionary *result = CNDIconDeclarationRedirectApplyThemeData(
        self.bundleIdentifier, sourcePNGData, self.journalURL);
    if (![NSFileManager.defaultManager fileExistsAtPath:self.journalURL.path]) {
        return result;
    }

    NSMutableDictionary *journal = [[NSDictionary
        dictionaryWithContentsOfURL:self.journalURL] mutableCopy];
    if (journal) {
        journal[@"schemaVersion"] = @(CNDRemixJournalSchemaVersion);
        journal[@"sourceThemePNGHash"] = CNDRemixSHA256(sourcePNGData) ?: @"";
        journal[@"sourceThemePNGBytes"] = @(sourcePNGData.length);
        journal[@"lastFailure"] = [result[@"ok"] boolValue] ? @{} : @{
            @"stage": result[@"stage"] ?: @"unknown",
            @"message": result[@"message"] ?: @"",
            @"at": NSDate.date,
        };
        journal[@"updatedAt"] = NSDate.date;
        NSError *writeError = nil;
        NSData *encoded = [NSPropertyListSerialization dataWithPropertyList:journal
            format:NSPropertyListBinaryFormat_v1_0 options:0 error:&writeError];
        if (encoded && [encoded writeToURL:self.journalURL
                   options:NSDataWritingAtomic error:&writeError]) {
            NSDictionary *readback = [NSDictionary dictionaryWithContentsOfURL:self.journalURL];
            if (![readback isEqual:journal]) writeError = [NSError errorWithDomain:
                @"CNDSnowBoardRemix" code:2 userInfo:@{NSLocalizedDescriptionKey:
                    @"The enriched recovery journal failed readback."}];
        }
        if (writeError) {
            NSMutableDictionary *warning = [result mutableCopy];
            warning[@"journalMetadataWarning"] = writeError.localizedDescription;
            result = warning;
        }
    }
    return result;
}

- (NSDictionary<NSString *, id> *)restore
{
    if (![NSFileManager.defaultManager fileExistsAtPath:self.journalURL.path]) {
        return CNDRemixResult(YES, @"already-restored",
            @"No recovery journal remains for this application.",
            @{@"bundleIdentifier": self.bundleIdentifier});
    }
    return CNDIconDeclarationRedirectRestoreJournal(
        self.bundleIdentifier, self.journalURL);
}

- (NSDictionary<NSString *, id> *)status
{
    return [self statusWithInstalledApplications:
        [CNDDockAppCatalog installedApplications]];
}

- (NSDictionary<NSString *, id> *)statusWithInstalledApplications:
    (NSArray<CNDDockApplication *> *)applications
{
    NSDictionary *journal = [NSDictionary dictionaryWithContentsOfURL:self.journalURL];
    if (!journal) return CNDRemixResult(YES, @"restored",
        @"No active transaction.", @{@"bundleIdentifier": self.bundleIdentifier});
    if (![journal[@"bundleIdentifier"] isEqual:self.bundleIdentifier] ||
        ![journal[@"bundlePath"] isKindOfClass:NSString.class]) {
        return CNDRemixResult(NO, @"invalid-journal",
            @"The recovery journal is invalid.", nil);
    }
    NSString *state = journal[@"transactionState"] ?: @"unknown";
    NSString *savedPath = [journal[@"bundlePath"] stringByStandardizingPath];
    CNDDockApplication *installed = nil;
    for (CNDDockApplication *candidate in applications ?: @[]) {
        if ([candidate.bundleIdentifier isEqual:self.bundleIdentifier]) {
            installed = candidate;
            break;
        }
    }
    NSString *installedPath = installed.bundleURL.path.stringByStandardizingPath;
    if (installedPath.length > 0 && ![installedPath isEqual:savedPath]) {
        return CNDRemixResult(NO, @"superseded",
            @"The installed app now has a different bundle path. The saved transaction will not follow it.", @{
                @"bundleIdentifier": self.bundleIdentifier,
                @"savedBundlePath": savedPath ?: @"",
                @"installedBundlePath": installedPath,
                @"transactionState": state,
            });
    }
    if (![NSFileManager.defaultManager fileExistsAtPath:savedPath]) {
        return CNDRemixResult(NO, @"bundle-missing",
            @"The saved exact application bundle no longer exists.", @{
                @"bundleIdentifier": self.bundleIdentifier,
                @"savedBundlePath": savedPath ?: @"",
                @"transactionState": state,
            });
    }
    NSDictionary *savedRegistration = journal[@"registrationDictionary"];
    NSString *infoPath = [journal[@"plistMutation"][@"targetPath"]
        isKindOfClass:NSString.class] ? journal[@"plistMutation"][@"targetPath"] : nil;
    NSDictionary *currentInfo = infoPath.length > 0
        ? [NSDictionary dictionaryWithContentsOfFile:infoPath] : nil;
    for (NSString *key in @[@"CFBundleVersion", @"CFBundleShortVersionString",
                             @"CFBundleExecutable"]) {
        id savedValue = savedRegistration[key];
        id currentValue = currentInfo[key];
        if (!((savedValue == nil && currentValue == nil) ||
              [savedValue isEqual:currentValue])) {
            return CNDRemixResult(NO, @"superseded",
                @"The application version/update identity changed. The saved transaction will not be applied to it.", @{
                    @"bundleIdentifier": self.bundleIdentifier,
                    @"savedBundlePath": savedPath ?: @"",
                    @"transactionState": state,
                });
        }
    }
    NSDictionary *iconStatus = CNDRemixClassifyMutation(journal[@"fileMutation"]);
    NSDictionary *plistStatus = CNDRemixClassifyMutation(journal[@"plistMutation"]);
    NSString *iconState = iconStatus[@"state"] ?: @"invalid";
    NSString *plistState = plistStatus[@"state"] ?: @"invalid";
    NSDictionary *componentStates = @{
        @"icon": iconState,
        @"infoPlist": plistState,
    };
    NSString *recipeFailure = nil;
    BOOL recipeCompatible = CNDRemixRecipeCompatible(journal, &recipeFailure);
    if ([iconState isEqual:@"drift"] || [iconState isEqual:@"invalid"] ||
        [plistState isEqual:@"drift"] || [plistState isEqual:@"invalid"] ||
        [iconState isEqual:@"unavailable"] || [plistState isEqual:@"unavailable"]) {
        return CNDRemixResult(NO, @"drift",
            @"A saved icon or Info.plist component no longer matches its known transaction bytes; automatic overwrite is refused.", @{
                @"bundleIdentifier": self.bundleIdentifier,
                @"bundlePath": journal[@"bundlePath"],
                @"transactionState": state,
                @"componentStates": componentStates,
                @"iconStatus": iconStatus,
                @"infoPlistStatus": plistStatus,
            });
    }
    BOOL iconThemed = [iconState isEqual:@"themed"];
    BOOL plistThemed = [plistState isEqual:@"themed"];
    BOOL iconOriginal = [iconState isEqual:@"original"] ||
        [iconState isEqual:@"restored"];
    BOOL plistOriginal = [plistState isEqual:@"original"] ||
        [plistState isEqual:@"restored"];
    NSString *classifiedState = nil;
    NSString *classifiedMessage = nil;
    BOOL classifiedOK = YES;
    BOOL batchPending = [state isEqual:@"pending"] ||
        [journal[@"batchCommitState"] isEqual:@"pending"];
    BOOL restorePending = [state isEqual:@"restore-pending"];
    // Once both original components are verified, a pending restore may be
    // finalized even when an older journal's target-selection recipe is no
    // longer accepted for new mutations. Recipe compatibility protects apply
    // and partial recovery; it must not strand an exact completed restore.
    if (restorePending && iconOriginal && plistOriginal) {
        classifiedState = @"restore-pending";
        classifiedMessage = @"The original files are verified; shared installd batch cleanup is still pending.";
        classifiedOK = NO;
    } else if (!recipeCompatible) {
        classifiedState = @"restore-required";
        classifiedMessage = recipeFailure ?: @"The target-selection recipe is legacy or incompatible; restore is required.";
        classifiedOK = NO;
    } else if (batchPending && iconThemed && plistThemed) {
        classifiedState = @"pending";
        classifiedMessage = @"The themed files are verified, but the shared installd batch has not closed cleanly.";
        classifiedOK = NO;
    } else if (iconThemed && plistThemed && [state isEqual:@"active"]) {
        classifiedState = @"active";
        classifiedMessage = @"The saved icon and Info.plist replacement hashes are present.";
    } else if (iconOriginal && plistOriginal) {
        classifiedState = @"restored";
        classifiedMessage = @"Both saved components are already restored; registration cleanup may still be pending.";
    } else if (iconThemed || plistThemed) {
        classifiedState = @"partial";
        classifiedMessage = @"Only one saved component currently contains the themed replacement; recovery remains required.";
    } else {
        classifiedState = state;
        classifiedMessage = @"Recovery data is present.";
        classifiedOK = NO;
    }
    return CNDRemixResult(classifiedOK, classifiedState, classifiedMessage, @{
        @"bundleIdentifier": self.bundleIdentifier,
        @"bundlePath": journal[@"bundlePath"],
        @"transactionState": state,
        @"targetSelectionRecipe": journal[@"targetSelectionRecipe"] ?: @{},
        @"targetSelectionRecipeCompatible": @(recipeCompatible),
        @"targetSelectionRecipeFailure": recipeFailure ?: @"",
        @"lastFailure": journal[@"lastFailure"] ?: @{},
        @"componentStates": componentStates,
        @"iconStatus": iconStatus,
        @"infoPlistStatus": plistStatus,
    });
}

@end
