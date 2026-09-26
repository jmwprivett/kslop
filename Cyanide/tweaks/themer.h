//
//  themer.h
//  Per-bundle icon swap. Walks every SBIconView in SpringBoard and replaces
//  its image with a PNG from `themePath/<bundleID>.png`.
//

#ifndef themer_h
#define themer_h

#import <stdbool.h>
#ifdef __OBJC__
#import <Foundation/Foundation.h>
#endif

// Apply the theme rooted at `themePath` — a local-process directory of
// `<bundleID>.png` files. Builds an in-memory dictionary and forwards to
// themer_apply_data_in_session.
bool themer_apply_in_session(const char *themePath);

#ifdef __OBJC__
// Apply a theme provided in-memory. Keys are bundle identifiers
// (NSString *), values are raw PNG bytes (NSData *). Caller can free the
// dictionary as soon as the call returns. Idempotent within a session —
// per-bundle SB UIImages are cached and reused. Must run under
// settings_rc_lock with the SpringBoard RemoteCall session open.
bool themer_apply_data_in_session(NSDictionary<NSString *, NSData *> *imageDataByBundle);

// Apply only the requested bundle IDs from a theme dictionary. Bundle IDs are
// alias-expanded before filtering. When forceRefresh is true, IconServices is
// reseeded even if the bundle was already seeded in this RemoteCall session.
bool themer_apply_data_for_bundle_ids_in_session(NSDictionary<NSString *, NSData *> *imageDataByBundle,
                                                 NSSet<NSString *> *bundleIDs,
                                                 bool forceRefresh);

// Replaces the exact bundle set used by the next SpringBoardHome refresh.
// The lifecycle coordinator updates this from the durable IconServices
// journals before opening SpringBoard. Only canonical and live leaf
// SBApplicationIcon objects for these identifiers are allowed to advance their
// image generation.
void themer_set_springboard_iconservices_refresh_bundle_identifiers(
    NSArray<NSString *> *bundleIdentifiers);

// One-shot SpringBoardHome refresh for persistent IconServices publications.
// Resolves the configured themed identifiers through the canonical SBIconModel
// lookup and its live leaf set, advances each distinct matching
// SBApplicationIcon generation once, and then performs the separately bounded
// notification/folder/library/switcher refreshes.
// The caller must already have the presentation install's SpringBoard
// RemoteCall session open. No icon bytes or model objects are replaced.
bool themer_refresh_springboard_iconservices_cache_in_session(void);

// Read-only snapshot of SpringBoard's current icon identities for the supplied
// journaled bundles. Reports canonical and live leaf SBApplicationIcon
// pointers/generations plus materialized app-switcher display-item icon
// mappings. It invokes no reload, purge, relayout, update handler, or setter.
// The caller must already own one SpringBoard RemoteCall session.
NSDictionary<NSString *, id> *
themer_audit_springboard_iconservices_consumers_in_session(
    NSArray<NSString *> *bundleIdentifiers);

// Repaint currently visible icon views from the in-session UIImage cache only.
// This is for SpringBoard re-entry paths where views keep our overrideImage
// pointer but their inner image contents/layer were reset.
bool themer_repaint_cached_views_in_session(void);

// Same cache-only repaint, but does not trust SBIconImageView.displayedImage
// as proof that the visible layer is still intact.
bool themer_force_repaint_cached_views_in_session(void);

// Forced repaint for home-screen icons only. Used by the live repair loop so
// it does not keep walking notification views every few seconds.
bool themer_force_repaint_cached_icon_views_in_session(void);

// Re-pin only dynamic icons (Clock/Calendar). This is intentionally narrower
// than a cached repaint so wake/unlock repairs don't touch normal app icons.
bool themer_repaint_dynamic_cached_views_in_session(void);

// Diagnostic/static Clock+Calendar repair. Uses the in-session image cache
// from the last SnowBoard Lite apply and only attempts currently collected
// Clock/Calendar icon views.
bool themer_repair_static_dynamic_visible_icons_in_session(void);

// Configures the process-local Clock and Calendar sources in the caller's one
// existing RemoteCall session. SpringBoard uses the measured live clock.base
// source; Spotlight can instead select the ordinary static Clock image-view
// class before any result row exists. Both processes replace Calendar only at
// SBCalendarIconImageProvider's exact preparedISIcon source boundary.
NSDictionary<NSString *, id> *
themer_set_static_dynamic_icon_overlays_in_session(
    NSDictionary<NSString *, NSData *> *imageDataByBundle,
    bool useStaticClockPresentation);

// Spotlight/Siri Suggestions probe for the currently active RemoteCall host.
bool themer_diagnose_spotlight_icons_in_session(void);

// Returns the number of live SearchUI app-icon views in the current host.
int themer_spotlight_visible_view_count_in_session(void);

// Resolves SearchUI's canonical application icons by bundle identifier,
// grafts themed model images before rows exist, and bulk-warms an existing
// Spotlight icon cache when one is reachable. No live row is required.
bool themer_apply_spotlight_data_in_session(NSDictionary<NSString *, NSData *> *imageDataByBundle,
                                            volatile int *stopRequested);

// Diagnostic repair pass for already-materialized SearchUI rows. The
// canonical preload remains the primary path; this entry lets the caller
// explicitly exercise the existing live-row repair/follow-up path.
bool themer_apply_spotlight_rows_in_session(
    NSDictionary<NSString *, NSData *> *imageDataByBundle);
bool themer_apply_spotlight_rows_diagnostic_in_session(
    NSDictionary<NSString *, NSData *> *imageDataByBundle);

// Restore canonical Spotlight icons retained by the last successful source
// installation. This removes renderer associations/classes, invalidates stock
// rendering, refreshes current rows, and clears process-resident theme state.
// A missing state bundle is treated as an already-restored success.
bool themer_restore_spotlight_theme_in_session(void);

// Lightweight health check for the provider/icon/cache bindings captured by
// the last successful Spotlight preload. Polling uses only the exact optioned
// cache getter and never mutates an image. A reseed result first permits the
// bounded current-binding repair below; graph/PID drift requires the complete
// provider materialization + graft + cache preload again.
typedef enum {
    ThemerSpotlightMonitorResultUnchanged = 0,
    ThemerSpotlightMonitorResultReseedNeeded = 1,
    ThemerSpotlightMonitorResultUnavailable = 2,
} ThemerSpotlightMonitorResult;
ThemerSpotlightMonitorResult themer_spotlight_monitor_poll_in_session(void);
// Repairs only currently visible themed bindings using the process-resident
// expected-image repository committed by the last successful preload.
bool themer_spotlight_monitor_repair_in_session(void);
void themer_spotlight_monitor_reset(void);

// Read-only lifecycle trace armed for the representative row. Each sample
// rediscovers the current SearchUI view and records owner/model/icon/cache
// identities without asking an image cache to render or recache anything.
bool themer_spotlight_lifecycle_trace_is_armed(void);
bool themer_spotlight_lifecycle_trace_sample_in_session(const char *phase,
                                                        bool forceLog);
// Compact follow-up used after the full baseline. It captures only the fields
// needed to classify provider/cache/carrier/presentation transitions.
bool themer_spotlight_lifecycle_trace_sentinel_in_session(const char *phase,
                                                          bool forceLog);
uint64_t themer_spotlight_remote_autorelease_pool_push(void);
void themer_spotlight_remote_autorelease_pool_pop(uint64_t token);
void themer_spotlight_lifecycle_trace_forget(void);

// ---- Spotlight SearchUIIconImageCache one-app proof (experimental) ----
//
// Bounded proof that exactly one installed themed app can be seeded into the
// process-lifetime per-variant SearchUIIconImageCache of
// SearchUIHomeScreenAppIconView and later verified from a new RemoteCall
// session in the same target PID. Phase 1 materializes the app through
// SearchUIHomeScreenModel, creates the normal device cache directly (variant
// 5 on iPhone, 4 on iPad), and seeds light/dark appearances before any result
// row is required. Phase 2 reads the same static cache back and restores the
// captured stock light/dark images. Never a broad cache clear, resident
// thread, visible-row graft, or image-generation notification.

// Phase 1 deterministically selects exactly one installed themed app, with a
// second installed app retained as the untouched negative control when one is
// available. All cache/icon/appearance/stock objects needed by a later
// same-PID session are retained under NSProcessInfo key
// "cndSpotlightCacheProofStateV1".
typedef enum {
    ThemerSpotlightProofBeginResultSeeded = 0,
    ThemerSpotlightProofBeginResultNoEligibleThemedIcon = 1,
    // Compatibility name retained for the disabled row-based diagnostic.
    ThemerSpotlightProofBeginResultNoVisibleThemedIcon =
        ThemerSpotlightProofBeginResultNoEligibleThemedIcon,
    ThemerSpotlightProofBeginResultSeedFailed = 2,
    ThemerSpotlightProofBeginResultStateFailed = 3,
} ThemerSpotlightProofBeginResult;
ThemerSpotlightProofBeginResult themer_spotlight_proof_begin_in_session(
    NSDictionary<NSString *, NSData *> *imageDataByBundle,
    volatile int *stopRequested);

// Phase 2: verify the seed from a later RemoteCall session in the same
// target PID, then clean up. Verification distinguishes a themed light/dark
// cache hit, a stock/miss readback, a host/state mismatch, an inconclusive
// readback, and the absence of seed state. Cleanup overwrites only the proof
// bundle's light/dark cache identities with the captured stock images. If
// targeted restoration does not verify, state is retained and CleanupFailed
// is returned so the caller can retry or fall back to a respring.
typedef enum {
    ThemerSpotlightProofVerifyResultThemedHit = 0,
    ThemerSpotlightProofVerifyResultStockOrMiss = 1,
    ThemerSpotlightProofVerifyResultHostStateMismatch = 2,
    ThemerSpotlightProofVerifyResultInconclusive = 3,
    ThemerSpotlightProofVerifyResultNoState = 4,
    ThemerSpotlightProofVerifyResultCleanupFailed = 5,
} ThemerSpotlightProofVerifyResult;
ThemerSpotlightProofVerifyResult
themer_spotlight_proof_verify_and_cleanup_in_session(void);

// ---- Spotlight IconServices-only lab API (experimental) ----
//
// IconServices-only experimental seeding for iOS 26 Spotlight icons. Exactly
// one candidate is exercised per run; run state is process-resident for the
// current RemoteCall session. This API never touches SearchUI caches, views,
// or models, and never touches SpringBoard.

// Strategy exercised by a run. The direct and factory/init IDs remain for
// defaults/API compatibility but are not promoted. Probe compares image-bag
// topology before descriptor resolution, before named-Spotlight preparation,
// after target preparation, and after all preparation. The promoted mixed-bag
// candidate preserves every genuine stock entry, replaces only the genuine
// 68-point entry with a store-backed themed IFCacheImage, and records the new
// store UUID before live mutation. Verify/Emergency Restore reinstate the exact
// copied pre-prepare dictionary and remove the temporary store unit.
typedef enum {
    ThemerSpotlightIconServicesCandidateLocalExistingDescriptor = 0,
    ThemerSpotlightIconServicesCandidateCanonicalExistingDescriptor = 1,
    ThemerSpotlightIconServicesCandidateCanonicalFactoryClone = 2,
    ThemerSpotlightIconServicesCandidateCanonicalInitClone = 3,
    ThemerSpotlightIconServicesCandidateCanonicalBagSwap = 4,
    ThemerSpotlightIconServicesCandidateCanonicalDescriptorClear = 5,
    ThemerSpotlightIconServicesCandidateCanonicalIconInvalidator = 6,
    ThemerSpotlightIconServicesCandidateCanonicalCacheClear = 7,
    ThemerSpotlightIconServicesCandidateManagerCache = 8,
    ThemerSpotlightIconServicesCandidateCanonicalMixedBag = 9,
    ThemerSpotlightIconServicesCandidateCount = 10,
} ThemerSpotlightIconServicesCandidate;

// Probe outcome for the IconServices environment of the current host.
typedef enum {
    ThemerSpotlightIconServicesProbeResultReady = 0,
    ThemerSpotlightIconServicesProbeResultNoEligibleIcon = 1,
    ThemerSpotlightIconServicesProbeResultUnsupported = 2,
    ThemerSpotlightIconServicesProbeResultStatePresent = 3,
    ThemerSpotlightIconServicesProbeResultFailed = 4,
} ThemerSpotlightIconServicesProbeResult;

// Stock-only one-target generation diagnostic. It never receives themed image
// bytes. Its optional store diagnostic uses only journaled ISStore operations.
// A successful Materialized/AlreadyPresent
// result still requires a later fresh-session verification before Seed can run.
typedef enum {
    ThemerSpotlightStock68MaterializationResultMaterialized = 0,
    ThemerSpotlightStock68MaterializationResultAlreadyPresent = 1,
    ThemerSpotlightStock68MaterializationResultUnchanged = 2,
    ThemerSpotlightStock68MaterializationResultWrongDescriptorRolledBack = 3,
    ThemerSpotlightStock68MaterializationResultAmbiguousRolledBack = 4,
    ThemerSpotlightStock68MaterializationResultNoEligibleTarget = 5,
    ThemerSpotlightStock68MaterializationResultUnsupportedABI = 6,
    ThemerSpotlightStock68MaterializationResultStatePresent = 7,
    ThemerSpotlightStock68MaterializationResultCancelled = 8,
    ThemerSpotlightStock68MaterializationResultRollbackFailed = 9,
    ThemerSpotlightStock68MaterializationResultTransportFailed = 10,
    ThemerSpotlightStock68MaterializationResultVerificationFailed = 11,
    // A coherent direct image was returned while the exact original empty
    // dictionary remained unchanged. The generation may have produced an
    // unmaterialized record; cleanup is still required because store removal
    // was not proven.
    ThemerSpotlightStock68MaterializationResultIssuedUnmaterializedRecoveryRequired = 12,
    ThemerSpotlightStock68MaterializationResultStoreRoundTripVerified = 13,
    ThemerSpotlightStock68MaterializationResultStoreRegisteredRecoveryRequired = 14,
} ThemerSpotlightStock68MaterializationResult;

typedef enum {
    ThemerSpotlightStock68RecordIdentifiersDecodeNotAttempted = 0,
    ThemerSpotlightStock68RecordIdentifiersDecodeNil = 1,
    ThemerSpotlightStock68RecordIdentifiersDecodeDecoded = 2,
    ThemerSpotlightStock68RecordIdentifiersDecodeTruncated = 3,
    ThemerSpotlightStock68RecordIdentifiersDecodeUnsupportedClass = 4,
    ThemerSpotlightStock68RecordIdentifiersDecodeMalformed = 5,
    ThemerSpotlightStock68RecordIdentifiersDecodeTransportFailed = 6,
} ThemerSpotlightStock68RecordIdentifiersDecodeStatus;

typedef struct {
    char targetBundle[192];
    char controlBundle[192];
    char themeFingerprint[65];
    char namedDigest[160];
    char generatedDigest[160];
    char uuid[80];
    char storePath[512];
    uint64_t fileSize;
    int requestCount;
    int baselineKeyCount;
    int finalKeyCount;
    int baselineNamedEntryCount;
    int finalNamedEntryCount;
    int newNamed68Count;
    int wrongKey68Count;
    bool baselineHad68;
    bool uuidValid;
    bool tokenValid;
    bool fileValid;
    bool reconstructionValid;
    bool dictionaryChanged;
    bool rollbackAttempted;
    bool rollbackVerified;
    bool freshVerification;
    ThemerSpotlightStock68RecordIdentifiersDecodeStatus
        recordIdentifiersDecodeStatus;
    int recordIdentifiersDecodeNodes;
    int recordIdentifiersDecodeMetadata;
    bool recordIdentifiersOwnershipVerified;
    // Observation-only capture of the first Foundation NSData leaf returned
    // through recordIdentifiers.  This data is never used for identity,
    // persistence, cache mutation, or recovery clearance.
    uint64_t recordIdentifiersBlobTotalLength;
    uint64_t recordIdentifiersBlobCapturedLength;
    bool recordIdentifiersBlobTruncated;
    bool recordIdentifiersBlobCaptured;
    char recordIdentifiersBlobFormat[96];
    char recordIdentifiersBlobSHA256[65]; // SHA-256 of captured bytes.
    char recordIdentifiersBlobPrefixHex[129];
    char recordIdentifiersBlobHex[1025];
    bool recordIdentifiersBlobEqualsToken;
    bool recordIdentifiersBlobContainsToken;
    bool recordIdentifiersTokenContainsBlob;
    uint64_t recordIdentifiersTokenLength;
    bool recordIdentifiersTokenTruncated;
    // Strict observation-only correlation of the exact 36-byte
    // recordIdentifiers candidate.  None of these fields participate in V2
    // identity persistence, cache mutation, or recovery clearance.
    bool recordIdentifiersCandidateParsed;
    bool recordIdentifiersCandidateTokenBound;
    bool recordIdentifiersCandidateClassified;
    uint32_t recordIdentifiersCandidateWord0;
    uint32_t recordIdentifiersCandidateWord4;
    uint32_t recordIdentifiersCandidateWord8;
    uint64_t recordIdentifiersCandidateTail;
    char recordIdentifiersCandidateUUID[80];
    char recordIdentifiersCandidatePath[512];
    bool recordIdentifiersCandidateFileExists;
    bool recordIdentifiersCandidateFileRegular;
    bool recordIdentifiersCandidateFileReadable;
    bool recordIdentifiersCandidateFileNonempty;
    bool recordIdentifiersCandidateFileExactSize;
    uint64_t recordIdentifiersCandidateFileSize;
    bool recordIdentifiersCandidateStoreLookupABI;
    bool recordIdentifiersCandidateStoreLookupAttempted;
    bool recordIdentifiersCandidateStoreUnitFound;
    char recordIdentifiersCandidateStoreUnitClass[96];
    bool recordIdentifiersCandidateStoreUnitABI;
    bool recordIdentifiersCandidateStoreUnitUUIDEqual;
    bool recordIdentifiersCandidateStoreUnitDataEqual;
    bool recordIdentifiersCandidateStoreUnitValidKnown;
    bool recordIdentifiersCandidateStoreUnitValid;
    uint64_t recordIdentifiersCandidateIndexUUIDOccurrences;
    int64_t recordIdentifiersCandidateIndexUUIDFirstOffset;
    uint64_t recordIdentifiersCandidateIndexTokenOccurrences;
    int64_t recordIdentifiersCandidateIndexTokenFirstOffset;
    bool recordIdentifiersCandidateReconstructionAttempted;
    bool recordIdentifiersCandidateReconstructionClass;
    bool recordIdentifiersCandidateReconstructionUUIDEqual;
    bool recordIdentifiersCandidateReconstructionTokenEqual;
    bool recordIdentifiersCandidateReconstructionGeometry;
    bool recordIdentifiersCandidateReconstructionFileEqual;
} ThemerSpotlightStock68MaterializationReport;

// Durable stock68 generation journal classification.  V1 records predate the
// dispatch transaction bit; an issued V1 record is consequently ambiguous and
// must remain armed until a full emergency restore can prove its owner.
typedef enum {
    ThemerSpotlightStock68JournalAbsent = 0,
    ThemerSpotlightStock68JournalInvalid = 1,
    ThemerSpotlightStock68JournalLegacyUnissued = 2,
    ThemerSpotlightStock68JournalNoDispatchProven = 3,
    ThemerSpotlightStock68JournalDispatchPossible = 4,
    ThemerSpotlightStock68JournalLegacyIssuedAmbiguous = 5,
} ThemerSpotlightStock68JournalClassification;

typedef struct {
    ThemerSpotlightStock68JournalClassification classification;
    int version;
    int pid;
    bool present;
    bool valid;
    bool issuedKnown;
    bool issued;
    bool dispatchPossibleKnown;
    bool dispatchPossible;
    bool transactionBound;
    char targetBundle[192];
    char themeFingerprint[65];
    char namedDigest[160];
    char generatedDigest[160];
    char phase[48];
    bool storeRegistrationPresent;
    bool storeRegistrationValid;
    char rawJournalSHA256[65];
} ThemerSpotlightStock68JournalSnapshot;

// Read-only: this never synchronizes defaults and never changes any recovery
// marker.  Callers use classification plus the complete identity fields when
// deciding whether a generation transaction can be recovered.
ThemerSpotlightStock68JournalSnapshot
themer_spotlight_stock68_journal_snapshot(void);

typedef enum {
    ThemerSpotlightStock68RecoveryInspectionRejected = 0,
    ThemerSpotlightStock68RecoveryInspectionNoCandidate = 1,
    ThemerSpotlightStock68RecoveryInspectionAmbiguous = 2,
    ThemerSpotlightStock68RecoveryInspectionCandidateValidated = 3,
    ThemerSpotlightStock68RecoveryInspectionTransportFailed = 4,
} ThemerSpotlightStock68RecoveryInspectionResult;

typedef enum {
    ThemerStock68V2IdentityAbsent = 0,
    ThemerStock68V2IdentityBound = 1,
    ThemerStock68V2IdentityRejected = 2,
} ThemerStock68V2IdentityClassification;

typedef struct {
    ThemerStock68V2IdentityClassification classification;
    uint32_t presenceMask;
    int savedPID;
    bool certificatePresent;
    bool certificateBound;
    bool snapshotKnown;
    // Fingerprint of every raw identity/certificate value and the raw journal.
    char snapshotSHA256[65];
    char uuid[80];
    char canonicalPath[512];
    uint64_t tokenLength;
    uint64_t fileSize;
} ThemerStock68V2IdentitySnapshot;

typedef struct {
    ThemerStock68V2IdentitySnapshot identity;
    bool fileAbsent;
    int fileResult;
    int fileErrno;
    bool storeABI;
    bool storeDispatched;
    bool storeHealthyNil;
    uint64_t storeReceiver;
    char storeClass[96];
    char storeTypes[192];
} ThemerStock68V2AbsenceEvidence;

// Local read-only durable identity classification. No defaults synchronization.
ThemerStock68V2IdentitySnapshot themer_spotlight_stock68_v2_identity_snapshot(
    const ThemerSpotlightStock68JournalSnapshot *journal,
    int currentPID, const char *managerCachePath);

typedef struct {
    ThemerSpotlightStock68RecoveryInspectionResult result;
    ThemerStock68V2AbsenceEvidence emptyIdentity;
    uint64_t currentProc;
    uint64_t currentTask;
    uint64_t retiredProc;
    uint64_t retiredTask;
    bool journalBinding;
    bool expectedOwnerBinding;
    bool currentPIDHealthy;
    bool ownerExitProven;
    bool stateAbsenceKnown;
    bool stateAbsent;
    bool topologyComplete;
    bool digestMatch;
    bool candidateIdentityProven;
    // A candidate is eligible for forward adoption only after every strict
    // topology, file, reconstruction, and store-record check succeeds.
    bool adoptionEligible;
    // Set only by the resolver after both the V2 identity and the separate
    // adoption certificate synchronize and read back exactly.
    bool adoptionPersisted;
    // Always false for this inspector: a V1 issued record has no incident
    // bound store UUID that could establish transaction ownership.
    bool transactionOwnershipProven;
    // Raw strict-topology evidence.  These fields are populated even when
    // the topology contains no candidate, so a later local finalizer can
    // distinguish an exact empty cache from an incomplete observation.
    bool actualKeyCountKnown;
    bool totalEntryCountKnown;
    bool topologyExactlyEmpty;
    bool descriptorScaleKnown;
    bool uuidValid;
    bool tokenValid;
    bool fileRegular;
    bool fileReadable;
    bool fileNonempty;
    bool fileBounded;
    bool fileHashKnown;
    bool reconstructionValid;
    bool storeIntegrity;
    int journalVersion;
    int journalPID;
    int currentPID;
    int dictionaryCount;
    int keyCount;
    int actualKeyCount;
    int totalEntryCount;
    int candidateCount;
    int named68Count;
    int wrongKey68Count;
    uint64_t fileSize;
    char targetBundle[192];
    char themeFingerprint[65];
    char namedDigest[160];
    char generatedDigest[160];
    char authoritativeDigest[160];
    double descriptorScale;
    char managerCachePath[512];
    char uuid[80];
    char storePath[512];
    char fileSHA256[65];
    char tokenSHA256[65];
    char reason[192];
} ThemerSpotlightStock68RecoveryInspectionReport;

ThemerSpotlightStock68RecoveryInspectionResult
themer_spotlight_stock68_inspect_recovery_in_session(
    const ThemerSpotlightStock68JournalSnapshot *expectedJournal,
    int expectedPID,
    uint64_t expectedProc,
    uint64_t expectedTask,
    bool ownerExitProven,
    ThemerSpotlightStock68RecoveryInspectionReport *reportOut);

// Pure validation of two independent read-only reports.  It performs no
// RemoteCall activity and does not read or write Settings defaults.
bool themer_spotlight_stock68_empty_recovery_reports_match(
    const ThemerSpotlightStock68JournalSnapshot *expectedJournal,
    const ThemerSpotlightStock68RecoveryInspectionReport *first,
    const ThemerSpotlightStock68RecoveryInspectionReport *second);

// Forward-only recovery of a proven issued generation.  It repeats the
// inspector's read-only evidence collection, then records an exact V2
// identity and adoption certificate bound to this healthy process.  The
// generation journal deliberately remains armed for the clean-close finalizer.
ThemerSpotlightStock68RecoveryInspectionResult
themer_spotlight_stock68_resolve_issued_generation_in_session(
    const ThemerSpotlightStock68JournalSnapshot *expectedJournal,
    int expectedPID,
    uint64_t expectedProc,
    uint64_t expectedTask,
    bool ownerExitProven,
    ThemerSpotlightStock68RecoveryInspectionReport *reportOut);

// Local-only finalizer invoked after Settings proves that the recovery session
// closed cleanly.  It removes the adoption certificate first and the original
// issued generation journal last; any mismatch keeps the journal armed.
bool themer_spotlight_stock68_finalize_resolved_generation_after_clean_close(
    const ThemerSpotlightStock68JournalSnapshot *expectedJournal,
    int expectedCurrentPID);

// Emergency Restore only: recover an interrupted exact identity deletion.
// Restores the exact journal if an interrupted clear removed it, and refuses
// to overwrite unrelated durable state.
bool themer_spotlight_stock68_restore_interrupted_identity_retirement(void);

// Local-only retirement of an issued generation dispatch barrier after two
// independent healthy sessions proved the target topology exactly empty.
// Reconciles only the exact proven-absent V2 identity/certificate, then clears
// the generation journal last after all evidence and durable state rechecks.
bool themer_spotlight_stock68_finalize_empty_issued_after_clean_sessions(
    const ThemerSpotlightStock68JournalSnapshot *expectedJournal,
    const ThemerSpotlightStock68RecoveryInspectionReport *first,
    const ThemerSpotlightStock68RecoveryInspectionReport *second,
    int expectedCurrentPID);

bool themer_spotlight_stock68_select_target(
    NSDictionary<NSString *, NSData *> *imageDataByBundle,
    char *targetOut, size_t targetLen,
    char *controlOut, size_t controlLen,
    char fingerprintOut[65]);

ThemerSpotlightStock68MaterializationResult
themer_spotlight_stock68_materialize_in_session(
    const char *targetBundle,
    const char *themeFingerprint,
    volatile int *stopRequested,
    ThemerSpotlightStock68MaterializationReport *reportOut);

ThemerSpotlightStock68MaterializationResult
themer_spotlight_stock68_verify_in_session(
    const char *targetBundle,
    const char *themeFingerprint,
    ThemerSpotlightStock68MaterializationReport *reportOut);

bool themer_spotlight_stock68_materialization_has_state_in_session(void);

typedef enum {
    ThemerSpotlightStock68LiveOwnerRetirementRejected = 0,
    ThemerSpotlightStock68LiveOwnerRetirementRequired = 1,
    ThemerSpotlightStock68LiveOwnerRetirementTransportFailed = 2,
} ThemerSpotlightStock68LiveOwnerRetirementResult;

typedef struct {
    bool journalExact;
    bool journalDispatchPossible;
    bool stateIdentityBound;
    bool ownerIdentityBound;
    bool requestIssued;
    bool originalTopologyExactlyEmpty;
    bool dictionaryRestored;
    bool restoredTopologyExactlyEmpty;
    bool themedStateAbsent;
    bool pendingRecoveryAbsent;
    bool stateRetained;
    bool journalRetained;
} ThemerSpotlightStock68LiveOwnerRetirementReport;

// Restores and verifies the exact original empty dictionary for a live V2
// dispatch-possible owner. It deliberately leaves the process association,
// generation invocation/out slot, and journal armed. A Required result only
// authorizes Settings to request exit of the exact bound owner incarnation.
ThemerSpotlightStock68LiveOwnerRetirementResult
themer_spotlight_stock68_prepare_live_owner_retirement_in_session(
    const ThemerSpotlightStock68JournalSnapshot *expectedJournal,
    int expectedPID,
    uint64_t expectedProc,
    uint64_t expectedTask,
    ThemerSpotlightStock68LiveOwnerRetirementReport *reportOut);

bool themer_spotlight_stock68_materialization_emergency_restore_in_session(void);

// Recover a valid unissued generation journal after Settings has bound the
// recorded PID/proc/task owner.  The core rechecks the journal identity and
// remote state.  ownerExitProven permits the no-state branch only when the
// old owner has positively exited and healthyAbsenceRead confirms a clean,
// transport-healthy readback of the absent remote dictionary.
bool themer_spotlight_stock68_recover_no_state_unissued_in_session(
    const char *expectedTargetBundle,
    const char *expectedThemeFingerprint,
    int expectedPID,
    uint64_t expectedProc,
    uint64_t expectedTask,
    bool ownerExitProven,
    bool healthyAbsenceRead);

// Durable local recovery markers. These do not require an active RemoteCall
// session and fail closed when an incomplete cache/store journal is present.
bool themer_spotlight_stock68_has_unresolved_generation(void);
bool themer_spotlight_iconservices_has_pending_recovery(void);

// Read-only runtime metadata inventory of the manager icon-cache store
// registration surface. The inventory calls only the ABI-gated getters needed
// to reach the manager cache, store, storeIndex, and registry; it never generates,
// materializes, registers, mutates, or reads cache files.
typedef enum {
    ThemerSpotlightStoreSurfaceInventoryComplete = 0,
    ThemerSpotlightStoreSurfaceInventoryPartial = 1,
    ThemerSpotlightStoreSurfaceInventoryABIRejected = 2,
    ThemerSpotlightStoreSurfaceInventoryTransportFailed = 3,
    ThemerSpotlightStoreSurfaceInventoryUnavailable = 4,
} ThemerSpotlightStoreSurfaceInventoryResult;

typedef struct {
    ThemerSpotlightStoreSurfaceInventoryResult result;
    bool managerABI;
    bool iconCacheABI;
    bool storeABI;
    bool storeIndexABI;
    bool transportClean;
    bool methodListTruncated;
    bool candidateTruncated;
    bool overflowDetected;
    int classesScanned;
    int methodListsScanned;
    int methodsScanned;
    int candidateCount;
    char managerClass[96];
    char managerCacheClass[96];
    char storeClass[96];
    char storeIndexClass[96];
    char reason[160];
} ThemerSpotlightStoreSurfaceInventoryReport;

ThemerSpotlightStoreSurfaceInventoryResult
themer_spotlight_iconservices_inspect_store_surface_in_session(
    ThemerSpotlightStoreSurfaceInventoryReport *reportOut);

// Read-only, bounded live object/data metadata; never accesses recovery journals.
ThemerSpotlightStoreSurfaceInventoryResult
themer_spotlight_iconservices_inspect_live_store_state_in_session(
    ThemerSpotlightStoreSurfaceInventoryReport *reportOut);

// Read-only inspection of iconservicesagent's actual mutable writer. The
// caller must provide a RemoteCall session bound to iconservicesagent. The
// observer discovers the daemon's sole IconCacheService, then reads only its
// ISMutableIconCache/store/index and candidate files; it performs no service,
// store, index, file, or recovery mutation.
ThemerSpotlightStoreSurfaceInventoryResult
themer_iconservices_inspect_agent_writer_state_in_session(
    ThemerSpotlightStoreSurfaceInventoryReport *reportOut);

// Read-only publication preflight. It constructs a scratch _ISImageIcon and
// ISGenerationRequest, substitutes only the scratch icon's inherited digest,
// sets ignoreCache on a copied descriptor, and secure-coding round-trips the
// request. It never calls the IconServices service or a store/index mutator.
typedef enum {
    ThemerSpotlightAgentPreflightReady = 0,
    ThemerSpotlightAgentPreflightNoEligibleTarget = 1,
    ThemerSpotlightAgentPreflightUnsupportedABI = 2,
    ThemerSpotlightAgentPreflightVerificationFailed = 3,
    ThemerSpotlightAgentPreflightTransportFailed = 4,
} ThemerSpotlightAgentPreflightResult;

typedef struct {
    ThemerSpotlightAgentPreflightResult result;
    bool transportClean;
    bool targetDigestKnown;
    bool scratchDigestReplaced;
    bool descriptorDigestPreserved;
    bool ignoreCacheEnabled;
    bool requestInputsBound;
    bool secureCodingSupported;
    bool archiveCreated;
    bool decodedRequestVerified;
    bool decodedIconVerified;
    bool decodedDescriptorVerified;
    bool imageDataExact;
    bool serviceDispatchPossible;
    bool serviceResponseVerified;
    bool canonicalIconRegistered;
    bool canonicalIconRetained;
    bool responseGeometryVerified;
    bool responsePixelsExact;
    bool cachePublished;
    bool cacheReadbackVerified;
    uint64_t imageDataLength;
    uint64_t archiveLength;
    uint64_t serviceResponseLength;
    char targetBundle[192];
    char themeFingerprint[65];
    char targetDigest[160];
    char descriptorDigest[160];
    char scratchClass[96];
    char decodedIconClass[96];
    char serviceResponseClass[96];
    char imageDataSHA256[65];
    char serviceResponseSHA256[65];
    char sourcePixelSHA256[65];
    char responsePixelSHA256[65];
    char transaction[80];
    char reason[192];
} ThemerSpotlightAgentPreflightReport;

ThemerSpotlightAgentPreflightResult
themer_spotlight_iconservices_agent_preflight_in_session(
    NSDictionary<NSString *, NSData *> *imageDataByBundle,
    const char *targetBundle,
    const char *themeFingerprint,
    ThemerSpotlightAgentPreflightReport *reportOut);

// Read-only proof using an already-cached Spotlight image as the donor.  It
// discovers an already-initialized ISIconManager without invoking
// +sharedInstance, performs one statically-vetted image-cache lookup, then
// reconstructs only scratch ISGenerationResponse/IFImage objects.  It never
// generates, dispatches, or accesses a store, index, file, or recovery state.
typedef enum {
    ThemerSpotlightAgentResponseContractReady = 0,
    ThemerSpotlightAgentResponseContractUnsupportedABI = 1,
    ThemerSpotlightAgentResponseContractVerificationFailed = 2,
    ThemerSpotlightAgentResponseContractTransportFailed = 3,
    ThemerSpotlightAgentResponseContractSourceUnavailable = 4,
} ThemerSpotlightAgentResponseContractResult;

typedef struct {
    ThemerSpotlightAgentResponseContractResult result;
    bool transportClean;
    bool clientSyncABI;
    bool clientCompletionABI;
    bool abiMismatch;
    bool managerProvenInitialized;
    bool cacheLookupStaticProof;
    bool donorFound;
    bool donorDataIvarStable;
    bool donorDataMemoized;
    bool sourceHeaderVerified;
    bool responseConstructed;
    bool responseFieldsVerified;
    bool returnedImageConstructed;
    bool returnedImageFieldsVerified;
    bool geometryVerified;
    bool cgImageVerified;
    uint64_t sourceDataLength;
    uint64_t logicalDataLength;
    uint64_t responseDataLength;
    uint64_t validationTokenLength;
    uint64_t responsePaddingLength;
    uint64_t bitmapLength;
    uint64_t layerLength;
    char donorClass[96];
    char responseClass[96];
    char returnedImageClass[96];
    char responseUUID[80];
    char logicalDataSHA256[65];
    char paddedDataSHA256[65];
    char validationTokenSHA256[65];
    char firstFailureStage[96];
    char reason[192];
} ThemerSpotlightAgentResponseContractReport;

ThemerSpotlightAgentResponseContractResult
themer_spotlight_iconservices_agent_response_contract_in_session(
    ThemerSpotlightAgentResponseContractReport *reportOut);

// One agent-backed, process-resident publication. The decoded themed icon is
// registered as the target digest's canonical icon and strongly retained in
// Spotlight. A durable dispatch-possible transaction is persisted before the
// sole generateImageWithDescriptor: invocation; the verified response is then
// inserted into that icon's ISImageCache through the same final cache boundary
// used by IconServices' getImageForImageDescriptor:completion: wrapper. No
// store, index, or file method is used.
ThemerSpotlightAgentPreflightResult
themer_spotlight_iconservices_agent_publish_in_session(
    NSDictionary<NSString *, NSData *> *imageDataByBundle,
    const char *targetBundle,
    const char *themeFingerprint,
    ThemerSpotlightAgentPreflightReport *reportOut);

bool themer_spotlight_agent_publication_has_state(void);
bool themer_spotlight_agent_publication_is_published(void);
bool themer_spotlight_agent_publication_finalize_after_clean_close(
    const char *transaction,
    bool cleanClose);

// Restores the live retained canonical icon with a stock response from the
// same agent service, then releases the process association. It never calls
// ISStore directly. Journal clearance is deferred until the caller proves a
// clean stable session close.
ThemerSpotlightAgentPreflightResult
themer_spotlight_iconservices_agent_restore_in_session(
    ThemerSpotlightAgentPreflightReport *reportOut);
bool themer_spotlight_agent_restore_finalize_after_clean_close(
    const char *transaction,
    bool cleanClose);

// ---- VM-only persistent IconServices store proof ----
//
// Warms the authoritative named Spotlight descriptor for one target, locates
// its genuine indexed 68-point IFCacheImage, and overwrites only that UUID's
// existing disk-backed .isdata vnode with a byte-verified themed IFImage
// payload.  The existing store-index binding, UUID, and validation token are
// preserved.  No Spotlight cache, image bag, model, view, provider, or object
// class is mutated.  A fresh Spotlight process is therefore required for the
// visual check.
typedef enum {
    ThemerSpotlightPersistentStoreReady = 0,
    ThemerSpotlightPersistentStoreNoIndexedRecord = 1,
    ThemerSpotlightPersistentStoreThemeDoesNotFit = 2,
    ThemerSpotlightPersistentStoreRecoveryPending = 3,
    ThemerSpotlightPersistentStoreVerificationFailed = 4,
    ThemerSpotlightPersistentStoreTransportFailed = 5,
} ThemerSpotlightPersistentStoreResult;

typedef struct {
    ThemerSpotlightPersistentStoreResult result;
    bool transportClean;
    bool indexedRecordFound;
    bool exactGeometry;
    bool structuredMarkerSerialized;
    bool backupPersisted;
    bool overwriteVerified;
    bool noThemedProcessMutation;
    uint64_t stockLength;
    uint64_t themedLength;
    char targetBundle[192];
    char uuid[80];
    char storePath[512];
    char stockSHA256[65];
    char themedSHA256[65];
    char reason[192];
} ThemerSpotlightPersistentStoreReport;

ThemerSpotlightPersistentStoreResult
themer_spotlight_persistent_store_publish_in_session(
    NSDictionary<NSString *, NSData *> *imageDataByBundle,
    const char *targetBundle,
    ThemerSpotlightPersistentStoreReport *reportOut);

// These recovery operations are local and PID-independent.  Restore uses the
// same existing-vnode overwrite primitive and clears its durable metadata only
// after the target exactly matches the saved stock bytes.
bool themer_spotlight_persistent_store_has_recovery(void);
bool themer_spotlight_persistent_store_restore(void);
// Deletes only Cyanide's local backup/temp files and their defaults keys. It
// never opens or writes the journaled IconServices target file.
bool themer_spotlight_persistent_store_discard_recovery(void);

// ---- VM-only visible Spotlight indexed-response inspection ----
//
// Read-only diagnostic. Starting from an already-visible SearchUI application
// row, follows its SBHApplicationIcon to the exact IconServices icon/cache,
// enumerates only the cache bags that already exist, and correlates their
// IFCacheImage pixels with the row's displayed image. A response is accepted
// only when its UUID also resolves through the existing ISStore index and its
// UUID.isdata file. No descriptor request, generation, registration, cache
// setter, store writer, file write, association, or recovery-state change is
// performed.
typedef enum {
    ThemerSpotlightIndexedResponseIdentified = 0,
    ThemerSpotlightIndexedResponseNoVisibleRow = 1,
    ThemerSpotlightIndexedResponseNoConsumerIcon = 2,
    ThemerSpotlightIndexedResponseNoExistingCache = 3,
    ThemerSpotlightIndexedResponseNoIndexedMatch = 4,
    ThemerSpotlightIndexedResponseAmbiguous = 5,
    ThemerSpotlightIndexedResponseUnsupportedABI = 6,
    ThemerSpotlightIndexedResponseTransportFailed = 7,
} ThemerSpotlightIndexedResponseResult;

typedef struct {
    ThemerSpotlightIndexedResponseResult result;
    bool transportClean;
    bool noMutation;
    bool visibleRowFound;
    bool consumerIconFound;
    bool iconServicesIconFound;
    bool existingCacheFound;
    bool visiblePixelsCaptured;
    bool exactPixelMatch;
    bool storeIndexMatch;
    bool storeFileVerified;
    bool unitDataMatchesFile;
    int visibleTargetRowCount;
    int descriptorKeyCount;
    int cacheImageCount;
    int indexedCandidateCount;
    int exactPixelMatchCount;
    uint64_t visiblePixelWidth;
    uint64_t visiblePixelHeight;
    uint64_t storeFileLength;
    double visiblePointWidth;
    double visiblePointHeight;
    double visibleScale;
    double responsePointWidth;
    double responsePointHeight;
    double responseScale;
    char targetBundle[192];
    char rowClass[96];
    char consumerIconClass[96];
    char iconServicesIconClass[96];
    char cacheClass[96];
    char descriptorKeyClass[96];
    char descriptorKeyText[256];
    char responseClass[96];
    char uuid[80];
    char validationTokenSHA256[65];
    char visiblePixelSHA256[65];
    char responsePixelSHA256[65];
    char storeFileSHA256[65];
    char storePath[512];
    char rowSource[160];
    char reason[192];
} ThemerSpotlightIndexedResponseReport;

ThemerSpotlightIndexedResponseResult
themer_spotlight_identify_visible_indexed_response_in_session(
    const char *targetBundle,
    ThemerSpotlightIndexedResponseReport *reportOut);

// ---- VM-only IconServices provider-boundary proof ----
//
// Changes the manager-owned canonical ISBundleIdentifierIcon so that only its
// _makeResourceProviderAllowIconResourceFallback: call returns a provider
// backed by Cyanide's packaged PNG, then makes the live consumer's exact
// SBHApplicationIcon return that ISIcon from iconServicesIconForImage. The
// target-only Objective-C associations and subclasses remain installed until
// restore; no injected IMP, executable payload, or app-bundle mutation is
// retained.
typedef enum {
    ThemerIconProviderInterceptReady = 0,
    ThemerIconProviderInterceptUnsupportedABI = 1,
    ThemerIconProviderInterceptVerificationFailed = 2,
    ThemerIconProviderInterceptTransportFailed = 3,
    ThemerIconProviderInterceptStatePresent = 4,
} ThemerIconProviderInterceptResult;

typedef struct {
    ThemerIconProviderInterceptResult result;
    bool transportClean;
    bool stockProviderCaptured;
    bool themedProviderConstructed;
    bool providerResourcesReplaced;
    bool providerResourcesRestored;
    bool canonicalIconSelected;
    bool providerReplacementInstalled;
    bool providerReplacementRestored;
    bool agentRestartDiscardedReplacement;
    bool providerBoundaryIntercepted;
    bool controlProviderStayedStock;
    bool generationInvoked;
    bool recordIdentifiersObserved;
    bool recordIdentifiersOwnershipVerified;
    bool generationReturnedImage;
    bool generatedPixelsCaptured;
    bool generatedPixelsDifferFromStock;
    bool canonicalCachePublished;
    bool canonicalCacheReadbackVerified;
    bool consumerIconLocated;
    bool consumerBridgeInstalled;
    bool consumerBridgeReadbackVerified;
    bool consumerRefreshIssued;
    bool consumerBridgeRestored;
    bool objectClassRestored;
    bool associationCleared;
    uint64_t generatedImageLength;
    char targetBundle[192];
    char stockProviderClass[96];
    char themedProviderClass[96];
    char resolvedResourceClass[96];
    char generatedImageClass[96];
    char consumerIconClass[96];
    char stockPixelSHA256[65];
    char generatedPixelSHA256[65];
    char reason[192];
} ThemerIconProviderInterceptReport;

ThemerIconProviderInterceptResult
themer_iconservices_provider_intercept_apply_in_session(
    NSDictionary<NSString *, NSData *> *imageDataByBundle,
    const char *targetBundle,
    const char *themeBundlePath,
    const char *themeResourceBaseName,
    ThemerIconProviderInterceptReport *reportOut);

ThemerIconProviderInterceptResult
themer_iconservices_provider_intercept_restore_in_session(
    const char *targetBundle,
    ThemerIconProviderInterceptReport *reportOut);

// Outcome of beginning a single-candidate run.
typedef enum {
    ThemerSpotlightIconServicesBeginResultSeeded = 0,
    ThemerSpotlightIconServicesBeginResultUnsupported = 1,
    ThemerSpotlightIconServicesBeginResultNoEligibleIcon = 2,
    ThemerSpotlightIconServicesBeginResultImmediateReadbackMiss = 3,
    ThemerSpotlightIconServicesBeginResultControlChanged = 4,
    ThemerSpotlightIconServicesBeginResultStateFailed = 5,
} ThemerSpotlightIconServicesBeginResult;

// Outcome of verifying a begun run from a later session and cleaning it up.
typedef enum {
    ThemerSpotlightIconServicesVerifyResultPersistentHit = 0,
    ThemerSpotlightIconServicesVerifyResultStockOrMiss = 1,
    ThemerSpotlightIconServicesVerifyResultHostStateMismatch = 2,
    ThemerSpotlightIconServicesVerifyResultInconclusive = 3,
    ThemerSpotlightIconServicesVerifyResultNoState = 4,
    ThemerSpotlightIconServicesVerifyResultCleanupFailed = 5,
} ThemerSpotlightIconServicesVerifyResult;

const char *themer_spotlight_iconservices_candidate_name(
    ThemerSpotlightIconServicesCandidate candidate);

// IconServices-only environment probe for the current RemoteCall host. On
// Ready, writes the supported-candidate bitmask to supportedCandidateMaskOut.
ThemerSpotlightIconServicesProbeResult
themer_spotlight_iconservices_probe_in_session(
    NSDictionary<NSString *, NSData *> *imageDataByBundle,
    volatile int *stopRequested,
    uint64_t *supportedCandidateMaskOut);

// Begin a run exercising exactly one candidate with the given theme data.
ThemerSpotlightIconServicesBeginResult
themer_spotlight_iconservices_begin_in_session(
    ThemerSpotlightIconServicesCandidate candidate,
    NSDictionary<NSString *, NSData *> *imageDataByBundle,
    volatile int *stopRequested);

// Verify the run from a later RemoteCall session in the same target PID,
// then clean up the seed state.
ThemerSpotlightIconServicesVerifyResult
themer_spotlight_iconservices_verify_and_cleanup_in_session(void);

// Whether a begun IconServices run's state is present in this session.
bool themer_spotlight_iconservices_has_state_in_session(void);

// Emergency restore of IconServices seed state without a verify pass.
bool themer_spotlight_iconservices_emergency_restore_in_session(void);
#endif

// Release the in-SB UIImage cache. SB will re-render native icons on its
// next layout pass.
bool themer_stop_in_session(void);

// Current lifecycle linkage. The detach balances cache-owned remote +1 retains
// without clearing associations, changing classes, or altering native caches.
bool themer_has_remote_state(void);
bool themer_detach_remote_state_preserving_grafts(void);

// Drop local pointer cache without touching SpringBoard. Call from the
// SpringBoard-restart handler so we don't release dangling pointers under
// the next SB incarnation.
void themer_forget_remote_state(void);

// Store cleanup remains journaled until the caller proves a clean session close.
bool themer_spotlight_stock68_recover_store_registration_in_session(
    bool oldOwnerExitProven, int expectedPID, uint64_t expectedProc, uint64_t expectedTask);
bool themer_spotlight_stock68_finalize_store_registration_after_clean_close(
    bool cleanClose, int pid, uint64_t proc, uint64_t task);

#endif /* themer_h */
