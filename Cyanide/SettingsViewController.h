//
//  SettingsViewController.h
//  Cyanide
//

#import <UIKit/UIKit.h>
#import "kexploit/kexploit_opa334.h"
#import "kexploit/CNDKRWLifecycleSnapshot.h"
#import <sys/types.h>

extern NSString * const kSettingsAutoRunKexploit;
extern NSString * const kSettingsRunSandboxEscape;
extern NSString * const kSettingsRunPatchSandboxExt;
/// Backward-compatible preference key now presented as SnowBoard Automatic
/// Repair. Enabling it also owns the background audio lifetime.
extern NSString * const kSettingsKeepAlive;

extern NSString * const kSettingsSBCEnabled;
extern NSString * const kSettingsSBCDockIcons;
extern NSString * const kSettingsSBCDockAutofillBundleIDs;
extern NSString * const kSettingsSBCCols;
extern NSString * const kSettingsSBCRows;
extern NSString * const kSettingsSBCHideLabels;

extern NSString * const kSettingsPowercuffEnabled;
extern NSString * const kSettingsPowercuffLevel;

extern NSString * const kSettingsDSDisableAppLibrary;
extern NSString * const kSettingsDSDisableIconFlyIn;
extern NSString * const kSettingsDSZeroWakeAnimation;
extern NSString * const kSettingsDSZeroBacklightFade;
extern NSString * const kSettingsDSDoubleTapToLock;

extern NSString * const kSettingsDSDragCoefficientEnabled;
extern NSString * const kSettingsDSDragCoefficientValue;

extern NSString * const kSettingsLayoutExtrasEnabled;
extern NSString * const kSettingsLayoutHomeExtraLeft;
extern NSString * const kSettingsLayoutHomeExtraRight;
extern NSString * const kSettingsLayoutHomeExtraTop;
extern NSString * const kSettingsLayoutHomeExtraBottom;
extern NSString * const kSettingsLayoutDockExtraHorizontal;
extern NSString * const kSettingsLayoutHomeScalePct;
extern NSString * const kSettingsLayoutDockScalePct;

extern NSString * const kSettingsStatBarEnabled;
extern NSString * const kSettingsStatBarCelsius;
extern NSString * const kSettingsStatBarShowNet;
extern NSString * const kSettingsStatBarShowCPU;
extern NSString * const kSettingsStatBarShowLabels;
extern NSString * const kSettingsStatBarNetworkOnly;
extern NSString * const kSettingsStatBarRefreshRateSec;

extern NSString * const kSettingsNSBarEnabled;
extern NSString * const kSettingsNSBarPosition;

extern NSString * const kSettingsNiceBarLiteEnabled;

extern NSString * const kSettingsRSSIDisplayEnabled;
extern NSString * const kSettingsRSSIDisplayWifi;
extern NSString * const kSettingsRSSIDisplayCell;

extern NSString * const kSettingsAxonLiteEnabled;

extern NSString * const kSettingsTypeBannerEnabled;
extern NSString * const kSettingsNotificationIslandEnabled;
extern NSString * const kSettingsAppSwitcherGridEnabled;

extern NSString * const kSettingsGravityLiteEnabled;
extern NSString * const kSettingsGravityLiteDockEnabled;
extern NSString * const kSettingsGravityLiteMagnitudePct;
extern NSString * const kSettingsGravityLiteBouncePct;
extern NSString * const kSettingsGravityLiteFrictionPct;
extern NSString * const kSettingsGravityLiteResistancePct;

extern NSString * const kSettingsStageStripEnabled;

extern NSString * const kSettingsLocationSimLatitude;
extern NSString * const kSettingsLocationSimLongitude;
extern NSString * const kSettingsLocationSimAltitude;
extern NSString * const kSettingsLocationSimHorizontalAccuracy;
extern NSString * const kSettingsLocationSimHostProcess;

extern NSString * const kSettingsThemerEnabled;
extern NSString * const kSettingsThemerThemeID;
extern NSString * const kSettingsThemerCustomThemePath;
extern NSString * const kSettingsThemerCustomThemeName;

extern NSString * const kSettingsSnowBoardLiteEnabled;
extern NSString * const kSettingsSnowBoardLiteSelectedThemeID;
/// Versioned SnowBoard Remix selection key. The legacy Lite key remains
/// readable for one-time migration and for older builds.
extern NSString * const kSettingsSnowBoardRemixSelectedThemeID;

extern NSString * const kSettingsLiveWPEnabled;
extern NSString * const kSettingsLiveWPVideoPath;

extern NSString * const kSettingsExperimentalTweaksEnabled;

extern NSString * const kSettingsLogUploadEnabled;

extern NSString * const kSettingsActionsDidCompleteNotification;
extern NSString * const kSettingsActionsDidCompleteSuccessKey;
extern NSString * const kSettingsActionsDidCompleteMessageKey;
/// Background repair results use the same success/message keys without
/// completing a foreground settings action or its progress sheet.
extern NSString * const kSettingsSnowBoardAutomaticRepairDidCompleteNotification;
/// Private completion channel for a specific PackageQueue-owned settings run.
/// Consumers must require an exact token match; generic settings notifications
/// are intentionally not valid queue acknowledgements.
extern NSString * const kSettingsQueuedRunDidCompleteNotification;
extern NSString * const kSettingsQueuedRunCompletionTokenKey;

// Returns YES if the tweak whose master enable lives at `key` was successfully
// applied in this app session. Cleared on launch, on cleanup, and whenever the
// SpringBoard RemoteCall session goes away.
BOOL settings_tweak_is_applied(NSString *key);

void settings_register_defaults(void);
BOOL settings_device_supported(void);
/// Reconciles Automatic Repair and audio against the preference, durable
/// SnowBoard ACTIVE marker, and retained recovery data. Main-thread serialized.
void settings_reconcile_snowboard_automatic_repair_lifetime(void);
/// Starts/stops SnowBoard Automatic Repair and its background audio lifetime.
/// Safe to call repeatedly, including once during application launch.
void settings_apply_snowboard_automatic_repair_enabled(BOOL enabled);
/// Shared ownership for automatic repair and queued SnowBoard Apply/Restore.
/// Automatic repair tries without waiting; queue workers wait off-main.
BOOL settings_begin_snowboard_mutation(BOOL wait);
void settings_end_snowboard_mutation(void);
/// Coalesces a post-operation Automatic Repair request. The request is ignored
/// when the mode is disabled and never acquires KRW on its own.
void settings_request_snowboard_automatic_repair(NSString *reason);
// Opens the Contact email composer (MFMailComposeViewController if Mail is
// configured, else mailto: fallback) prefilled with the latest diagnostic log
// inline. Presented from `host`.
void cyanide_present_contact(UIViewController *host);
BOOL settings_apply_ota_disabled(BOOL disabled);
BOOL settings_themer_has_selected_theme(void);
NSString *settings_themer_selected_theme_display_name(void);
BOOL settings_snowboardlite_has_selected_theme(void);
NSString *settings_snowboardlite_selected_theme_display_name(void);
BOOL settings_font_changer_has_regular_font(void);

// Synchronously runs kexploit and writes/clears the NanoRegistry pairing-
// compatibility override using the four numbers currently in NSUserDefaults
// (kSettingsNanoMaxPairing, etc.). Returns YES on success.
BOOL settings_apply_nano_registry_now(BOOL apply);
BOOL settings_apply_call_recording_sound_disabled(BOOL disabled);
BOOL settings_apply_hide_home_bar_hidden(BOOL hidden);
BOOL settings_apply_font_changer_now(BOOL apply);
/// Applies or restores the validated file-backed Control Center resources.
/// PackageQueue invokes this synchronously before its automatic respring.
BOOL settings_apply_cc_theming_now(BOOL apply);
/// Applies the embedded original Pulsar camera/flashlight artwork directly to
/// the two live SpringBoard quick-action glyph objects, or asks CoverSheet to
/// rebuild both native glyphs when apply is NO. No system file is written.
BOOL settings_apply_lockscreen_pulsar_runtime(
    BOOL apply,
    NSError * _Nullable * _Nullable error);
BOOL settings_hide_home_bar_respring_pending(void);
/// Acquires and validates the current KRW generation for a durable queued
/// system action. The queue persists its checkpoint before invoking this.
BOOL settings_prepare_queued_system_actions(
    NSString * _Nullable * _Nullable failureReason);
/// Runs exactly once for a newly launched Cyanide process. It attempts only
/// recovery of the previously parked KRW generation, then reconciles durable
/// ACTIVE markers against SpringBoard and Spotlight process identities.
/// It never launches a fresh exploit.
void settings_reconcile_persisted_applied_state_on_launch(void);
/// Returns the currently bound SpringBoard process identity, or zero when it
/// cannot be proven from the active KRW/lab provider.
pid_t settings_current_springboard_pid(void);
NSTimeInterval settings_current_boot_epoch(void);
void settings_begin_system_edit_respring(UIViewController *host);
void settings_begin_system_edit_respring_with_completion(
    UIViewController *host,
    void (^ _Nullable completion)(BOOL started, NSString *message));
void settings_present_hide_home_bar_respring_prompt(UIViewController *host);
void settings_present_system_edit_respring_prompt(UIViewController *host,
                                                  NSString *title,
                                                  NSString *message);

// Probe-facing wrapper around the app's guarded acquisition.  Probes must never
// call kexploit() directly: that bypasses the stale-state/recovery logic here and
// crashes inside the page exploit's OOB read.
bool settings_ensure_krw_for_probe(void);
// Strict shared-lifecycle variant for probes that are authorized to consume
// only an already-live or parked generation. It may validate or recover the
// saved generation, but it never falls through to fresh exploit acquisition.
bool settings_ensure_existing_krw_for_probe(void);
/// Serializes a host-driven KRW command with UI Apply, recovery, cleanup,
/// respring, and update preparation. The caller must release exactly once
/// after its asynchronous completion callback fires.
bool settings_begin_external_krw_action(const char *owner);
void settings_end_external_krw_action(const char *owner);

FOUNDATION_EXPORT NSString * const kSettingsKRWLifecycleDidChangeNotification;
/// Latest immutable observation published at lifecycle ownership/result
/// boundaries. Readiness is initially unknown; this never polls locked KRW
/// helpers and never acquires, recovers, parks, or terminates a primitive.
CNDKRWLifecycleSnapshot *settings_current_krw_lifecycle_snapshot(void);

void settings_run_actions(void);
void settings_run_pending_actions(void);
void settings_run_pending_actions_for_queue_token(NSString *completionToken);
/// Runs the exact-build SpringBoard identity-bound self-trace/dylib probe.
/// This is exported for the one-shot `--springboard-rx-probe` physical launch
/// path; after persisting its marker result the probe replaces SpringBoard to
/// clear its temporary exception and tracing state.
void settings_run_physical_rx_probe_action(void);
/// VM-only REA/KRW boundary probe. Exposed for the lab Darwin-notification
/// trigger so KDP can observe the authenticated IOUserServer method entry
/// without UI automation.
void settings_run_lab_pm_cross_class_action(void);
/// VM-only no-provider trigger for the AppleM68Buttons/UPA carrier test.
/// Invoked through a Darwin notification; it has no Settings UI dependency.
void settings_run_lab_pm_m68_action(void);
/// Exact iPhone17,2 / 23A341 physical validator-consumption canary.  It
/// acquires validated KRW, resumes one sacrificial worker through the stock
/// exception-state path, and records before/after saved-state reads.  Exposed
/// for the `--physical-pac-validator` launch path; no button is required.
void settings_run_physical_pac_identity_canary_action(void);
/// Exact physical cross-process boundary probe. Targets only the stock
/// Calculator process, executes getpid through an identity-delivered,
/// converter-signed original thread, and restores that thread before return.
/// Exposed for the `--calculator-pac-probe` launch path.
void settings_run_physical_calculator_pac_probe_action(void);
/// Exact physical SpringBoard execution boundary. Executes only getpid with
/// the identity/KRW PAC signer, then terminates that exact SpringBoard
/// incarnation and proves its replacement so the retained exception policy
/// cannot survive the experiment.
void settings_run_physical_springboard_pac_probe_action(void);
/// Runs the same exact-device, observation-only diagnostic as the Settings
/// quick action. Exposed so a physical lab launch can pass
/// `--hail-mary-probe` and retrieve the JSON report without UI automation.
void settings_run_hail_mary_probe_action(void);
/// Runs the exact guarded shared-page mutation/restore experiment. Apply and
/// Restore respring only after the postwrite pmap and byte proof succeeds.
void settings_run_hail_mary_patch_apply_action(void);
void settings_run_hail_mary_patch_restore_action(void);
void settings_run_hail_mary_patch_verify_patched_action(void);
void settings_run_hail_mary_patch_verify_original_action(void);
/// Runs the identical-bytes Hail Mary data-page aperture-writability
/// experiment: full read-only proof, adrp/ldr slot decode, one single
/// identical 32-byte kwrite32 dispatch over the shared data-page slot,
/// readback, and repeated translations. The dispatch may panic when the
/// aperture maps shared-cache pages read-only.
void settings_run_hail_mary_data_page_action(void);
/// Runs the identical-bytes .34 dyldreadonly aperture check. It scans the
/// live slide anchors from the full proof, requires one exact 32-byte offline
/// guard match in SpringBoard and Spotlight, then performs one no-op write.
/// It never performs the dispatch-cache redirect or fallback.
void settings_run_hail_mary_read_only_data_page_action(void);
/// Runs the read-only SpringBoard `mlock` feasibility probe against the exact
/// .34 read-only-data frame that carries the dispatch entry. It first proves
/// the page identity in both processes, then mlocks that frame inside
/// SpringBoard together with two self-owned control pages. It never calls a
/// kernel write primitive and never changes a page byte.
void settings_run_hail_mary_page_wire_action(void);
/// Applies or restores the packed preoptimized dispatch-cache redirect with
/// one low-word write after a same-boot .34 permission proof. Exact readback
/// and stable translations are followed only by manual visual observation;
/// no process is restarted after the write.
void settings_run_hail_mary_imp_redirect_apply_action(void);
void settings_run_hail_mary_imp_redirect_restore_action(void);
/// Runs the special-icon-class `.34` identical-bytes permission probe. Its
/// confirmed report is the same-boot ticket for the Clock/Calendar class
/// selection redirect; it never performs the semantic write.
void settings_run_hail_mary_special_icon_class_probe_action(void);
/// Applies or restores the SBHIconModel special-class dispatch redirect with
/// one low-word write after the special-icon-class permission proof. It leaves
/// both consumers alive: a controlled respring is required before judging the
/// static Clock/Calendar result. Verification operations never write.
void settings_run_hail_mary_special_icon_class_apply_action(void);
void settings_run_hail_mary_special_icon_class_restore_action(void);
void settings_run_hail_mary_special_icon_class_verify_redirected_action(void);
void settings_run_hail_mary_special_icon_class_verify_original_action(void);
/// Runs the per-boot `.34.dyldreadonly` dispatch route for static Clock and
/// Calendar icons. The permission action performs two identical low-word
/// writes; Apply/Restore require its matching same-boot ticket and mutate only
/// the packed low words. Verification operations are read-only.
void settings_run_hail_mary_special_icon_class_dispatch_probe_action(void);
void settings_run_hail_mary_special_icon_class_dispatch_apply_action(void);
void settings_run_hail_mary_special_icon_class_dispatch_restore_action(void);
void settings_run_hail_mary_special_icon_class_dispatch_verify_redirected_action(
    void);
void settings_run_hail_mary_special_icon_class_dispatch_verify_original_action(
    void);
/// Proves all three exact Clock/Calendar presentation dispatch entries through
/// SpringBoard only, then writes each existing low word back unchanged. The
/// resulting same-boot ticket is required by both semantic routes.
void settings_run_special_icon_presentation_probe_action(void);
void settings_run_clock_static_presentation_apply_action(void);
void settings_run_clock_static_presentation_restore_action(void);
void settings_run_clock_static_presentation_verify_redirected_action(void);
void settings_run_clock_static_presentation_verify_original_action(void);
void settings_run_calendar_static_presentation_apply_action(void);
void settings_run_calendar_static_presentation_restore_action(void);
void settings_run_calendar_static_presentation_verify_redirected_action(void);
void settings_run_calendar_static_presentation_verify_original_action(void);
void settings_run_switcher_presentation_probe_action(void);
void settings_run_switcher_static_presentation_apply_action(void);
void settings_run_switcher_static_presentation_restore_action(void);
void settings_run_switcher_static_presentation_verify_redirected_action(void);
void settings_run_switcher_static_presentation_verify_original_action(void);
void settings_run_app_library_miniature_presentation_probe_action(void);
void settings_run_app_library_miniature_static_presentation_apply_action(void);
void settings_run_app_library_miniature_static_presentation_restore_action(
    void);
void settings_run_app_library_miniature_static_presentation_verify_redirected_action(
    void);
void settings_run_app_library_miniature_static_presentation_verify_original_action(
    void);
/// Runs the read-only Clock/Calendar consumer audit from a launch argument.
/// It reports the live model class, the inherited Method entry and IMP for
/// `iconClassForApplicationWithBundleIdentifier:`, and the canonical/leaf
/// icon classes. It never writes shared-cache memory.
void settings_run_icon_class_audit_action(void);
/// Reapplies the currently selected SnowBoard Remix theme through the same
/// durable IconServices path used by the explicit Apply action. It does not
/// rebuild, remove, or reclassify SpringBoard icon objects.
void settings_run_snowboard_remix_reapply_action(void);
/// Runs the zero-mutation two-consumer ABI/class/layout preflight for the
/// static canonical-object migration selected by the dispatch redirect.
void settings_run_special_icon_object_preflight_action(void);
/// Rebuilds exactly Clock and Calendar in SpringBoard and Spotlight after the
/// static dispatch redirect has been verified. SpringBoard positions must be
/// equal before and after each replacement.
void settings_run_special_icon_object_rebuild_static_action(void);
/// Symmetric canonical-object rebuild after restoring Apple's original live
/// Clock/Calendar class dispatch.
void settings_run_special_icon_object_rebuild_live_action(void);
/// Purges and rebuilds only the App Library category-miniature cache graph in
/// one PID-bound SpringBoard session. It never changes the dispatch redirect
/// or performs a process-lifecycle action.
void settings_run_hail_mary_app_library_miniature_refresh_action(void);
void settings_destroy_springboard_remote_call(void);
void settings_destroy_springboard_remote_call_sync(void);
/// Last-chance teardown before process exit. Returns the explicit KRW
/// termination disposition so the caller can record it instead of
/// treating process exit as success.
CNDKRWTerminationDisposition settings_best_effort_termination_cleanup(const char *reason);
void settings_application_did_enter_background(void);
void settings_application_will_enter_foreground(void);
void settings_application_did_become_active(void);

@interface SettingsViewController : UITableViewController

// Detail-mode init: renders a single underlying section (one tweak bundle).
// Pass underlyingSection == NSIntegerMax for root-mode (default storyboard path).
- (instancetype)initWithUnderlyingSection:(NSInteger)underlyingSection
                              bundleTitle:(nullable NSString *)bundleTitle NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithStyle:(UITableViewStyle)style NS_UNAVAILABLE;
- (instancetype)initWithCoder:(NSCoder *)coder;
- (instancetype)initWithNibName:(nullable NSString *)nibNameOrNil bundle:(nullable NSBundle *)nibBundleOrNil NS_UNAVAILABLE;

// When set on a bundle-detail SettingsViewController launched from the
// Installer's "Customize" row, the nav bar shows a left-side back button
// ("← <package name>") that pops Settings to root and switches the user
// back to the Installer tab — so the install action stays one tap away
// after customizing.
@property (nonatomic, copy, nullable) NSString *installerReturnPackageName;

// Current values for each configurable row in a settings section.
// Each entry: @{@"title": <label string>, @"value": <current value string>}.
// Returns empty array when the section has no configurable rows.
+ (NSArray<NSDictionary<NSString *, NSString *> *> *)settingsSummaryForSection:(NSInteger)section;
+ (BOOL)liveWPHasSelectedVideo;
@end
