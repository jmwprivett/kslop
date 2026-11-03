"""Static coverage for the bounded iOS 26 Share-sheet IconServices targets."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REMIX = ROOT / "Cyanide/installer/CNDSnowBoardRemix.m"
CONSUMER_HOOK = ROOT / "Cyanide/installer/CNDIconServicesConsumerHook.m"
CONSUMER_HOOK_HEADER = ROOT / "Cyanide/installer/CNDIconServicesConsumerHook.h"
DESCRIPTORS = ROOT / "Cyanide/installer/CNDIconServicesDescriptorSpec.m"
SNOWBOARD = ROOT / "Cyanide/tweaks/snowboardlite.m"
PUBLISHER_TRANSPORT = (
    ROOT / "Cyanide/installer/CNDIconServicesPublisherRemoteTransport.m"
)
REMIX_HEADER = ROOT / "Cyanide/installer/CNDSnowBoardRemix.h"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"
TELEMETRY = ROOT / "Cyanide/installer/CNDShareSheetTelemetry.m"
REMOTE_CALL = ROOT / "Cyanide/TaskRop/RemoteCall.m"
REMOTE_CALL_HEADER = ROOT / "Cyanide/TaskRop/RemoteCall.h"
REMOTE_OBJC = ROOT / "Cyanide/tweaks/remote_objc.m"


class ShareSheetIconServicesTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.remix = REMIX.read_text(encoding="utf-8")
        cls.consumer_hook = CONSUMER_HOOK.read_text(encoding="utf-8")
        cls.consumer_hook_header = CONSUMER_HOOK_HEADER.read_text(
            encoding="utf-8"
        )
        cls.descriptors = DESCRIPTORS.read_text(encoding="utf-8")
        cls.snowboard = SNOWBOARD.read_text(encoding="utf-8")
        cls.publisher_transport = PUBLISHER_TRANSPORT.read_text(
            encoding="utf-8"
        )
        cls.remix_header = REMIX_HEADER.read_text(encoding="utf-8")
        cls.settings = SETTINGS.read_text(encoding="utf-8")
        cls.telemetry = TELEMETRY.read_text(encoding="utf-8")
        cls.remote_call = REMOTE_CALL.read_text(encoding="utf-8")
        cls.remote_call_header = REMOTE_CALL_HEADER.read_text(encoding="utf-8")
        cls.remote_objc = REMOTE_OBJC.read_text(encoding="utf-8")

    def test_bordered_more_list_descriptor_is_in_every_app_profile(self) -> None:
        profile_start = self.descriptors.index(
            "+ (NSArray<CNDIconServicesDescriptorSpec *> *)coreIPhoneIOS26SpecsAt3x"
        )
        profile_end = self.descriptors.index(
            "+ (NSArray<CNDIconServicesDescriptorSpec *> *)specsForIPhoneIOS26At3xWithConditionalExtras:",
            profile_start,
        )
        profile = self.descriptors[profile_start:profile_end]
        self.assertIn("@[@28, @28, @3, @0, @0, @0]", profile)
        self.assertIn(
            "@(CNDIconServicesShareSheetBorderVariantOptions)", profile
        )
        self.assertIn(
            "CNDIconServicesShareSheetBorderVariantOptions = 0x4u",
            self.descriptors,
        )

    def test_airdrop_is_one_exact_allowlisted_pseudo_bundle(self) -> None:
        self.assertIn(
            '@"com.apple.Sharing.AirDrop"',
            self.remix,
        )
        allowlist_start = self.remix.index(
            "static NSArray<NSString *> *CNDRemixSupportedPseudoBundleIdentifiers(void)"
        )
        allowlist_end = self.remix.index(
            "static BOOL CNDRemixIsSupportedPseudoBundleIdentifier(",
            allowlist_start,
        )
        allowlist = self.remix[allowlist_start:allowlist_end]
        self.assertIn("CNDRemixAirDropPseudoBundleIdentifier", allowlist)
        self.assertNotIn("themeLookup", allowlist)

    def test_airdrop_publishes_only_two_measured_share_records(self) -> None:
        start = self.remix.index(
            "CNDRemixDescriptorSpecificationsForBundleIdentifier("
        )
        end = self.remix.index(
            "static NSString *CNDRemixDescriptorProfileIdentity(", start
        )
        selector = self.remix[start:end]
        self.assertIn("CNDRemixIsSupportedPseudoBundleIdentifier", selector)
        self.assertIn("specWithPointWidth:64", selector)
        self.assertIn("pointHeight:64 scale:3 appearance:0", selector)
        self.assertIn("specWithPointWidth:28", selector)
        self.assertIn("pointHeight:28 scale:3 appearance:0", selector)
        self.assertIn("iconVariant:0x4 options:0", selector)
        self.assertIn("? @[activityStrip, moreList] : @[];", selector)

    def test_apply_requires_explicit_airdrop_theme_asset(self) -> None:
        apply_start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        apply_end = self.remix.index(
            "CNDRemixDeferredSpringBoardPresentationRestore(", apply_start
        )
        apply = self.remix[apply_start:apply_end]
        admission = apply.index(
            "Pseudo-bundles are not part of the installed-app debug count."
        )
        publication = apply.index(
            "CNDIconServicesPublisherPublishVariantInBatch(", admission
        )
        bounded = apply[admission:publication]
        self.assertIn("CNDRemixSupportedPseudoBundleIdentifiers()", bounded)
        self.assertIn("if (!repairLivePersistentRecords && themeLookup[folded]", bounded)
        self.assertIn("[matched addObject:pseudoBundleIdentifier]", bounded)
        self.assertNotIn("CNDIconServicesPublisherBeginBatch(", bounded)

    def test_base_apply_excludes_airdrop_without_an_explicit_filter(self) -> None:
        start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        end = self.remix.index(
            "CNDRemixDeferredSpringBoardPresentationRestore(", start
        )
        apply = self.remix[start:end]
        installed_start = apply.index("for (NSString *bundleIdentifier in installed)")
        installed_end = apply.index("BOOL debugApplicationLimit", installed_start)
        self.assertIn(
            "CNDRemixIsSupportedPseudoBundleIdentifier(bundleIdentifier) &&\n"
            "                    (repairLivePersistentRecords ||\n"
            "                     ![foldedBundleFilter containsObject:folded])) continue;",
            apply[installed_start:installed_end],
        )
        admission = apply[apply.index("Pseudo-bundles are not part of"):]
        admission = admission[:admission.index("[SBR_SHARE] airdrop asset=")]
        self.assertIn("[foldedBundleFilter containsObject:folded] &&", admission)
        self.assertNotIn("!foldedBundleFilter", admission)

    def test_base_restore_skips_airdrop_before_journal_cleanup(self) -> None:
        start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals("
        )
        end = self.remix.index("\n@implementation CNDSnowBoardRemix", start)
        restore = self.remix[start:end]
        selection = restore[:restore.index("if (journals.count == 0)")]
        skip = selection.index(
            "if (!bundleFilter &&\n"
            "            CNDRemixIsSupportedPseudoBundleIdentifier(bundleIdentifier)) continue;"
        )
        self.assertLess(skip, selection.index("selectedJournalCount++;"))
        self.assertLess(skip, selection.index("CNDRemixJournalProvesNoIconServicesMutation(journal)"))
        self.assertLess(skip, selection.index("CNDRemixRemoveIconServicesJournal(bundleIdentifier)"))
        self.assertIn(
            "BOOL airDropRefreshRequested = refreshAirDropConsumer &&\n"
            "        [bundleFilter containsObject:CNDRemixAirDropPseudoBundleIdentifier];",
            restore,
        )

    def test_isolated_actions_keep_explicit_airdrop_filters(self) -> None:
        start = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)applyIsolatedAirDropTest"
        )
        end = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)auditIsolatedAirDropTest", start
        )
        isolated_apply = self.remix[start:end]
        self.assertIn(
            "NSSet<NSString *> *target = [NSSet setWithObject:\n"
            "        CNDRemixAirDropPseudoBundleIdentifier];", isolated_apply
        )
        self.assertIn(
            "CNDRemixApplyIconServicesTheme(\n"
            "            target, NO, YES, NO, nil, nil);", isolated_apply
        )
        start = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)restoreIsolatedAirDropTest"
        )
        end = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)scanInstalledApplications", start
        )
        self.assertIn(
            "CNDRemixRestoreIconServicesJournals(\n"
            "            [NSSet setWithObject:CNDRemixAirDropPseudoBundleIdentifier],\n"
            "            YES, nil, nil);", self.remix[start:end]
        )

    def test_apply_reports_airdrop_admission_and_final_verification(self) -> None:
        apply_start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        apply_end = self.remix.index(
            "CNDRemixDeferredSpringBoardPresentationRestore(", apply_start
        )
        apply = self.remix[apply_start:apply_end]
        admission = apply.index("[SBR_SHARE] airdrop asset=")
        publication = apply.index(
            "CNDIconServicesPublisherPublishVariantInBatch(", admission
        )
        final = apply.index("[SBR_SHARE] airdrop active=", publication)
        self.assertLess(admission, publication)
        self.assertLess(publication, final)
        self.assertIn('filename=com.apple.Sharing.AirDrop.png', apply)
        self.assertIn('@"airDropThemeAssetPresent"', apply)
        self.assertIn('@"airDropTargetActive"', apply)
        self.assertIn('@"airDropVerifiedVariants"', apply)
        self.assertIn('source=%lu/%lu registry=%lu->%lu write=%d', apply)
        self.assertIn('sourceRegistryFreshReadbackVerified', apply)

    def test_airdrop_recovery_baseline_is_os_bound(self) -> None:
        start = self.remix.index(
            "static NSDictionary *CNDRemixPseudoBundleFingerprint("
        )
        end = self.remix.index(
            "static NSDictionary *CNDRemixApplicationFingerprint(", start
        )
        fingerprint = self.remix[start:end]
        self.assertIn("operatingSystemVersion", fingerprint)
        self.assertIn("operatingSystemVersionString", fingerprint)
        self.assertIn("CNDRemixSHA256", fingerprint)
        self.assertIn('@"pseudoBundle": @YES', fingerprint)

    def test_restore_allows_only_supported_noninstalled_pseudo_target(self) -> None:
        restore_start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals("
        )
        restore_end = self.remix.index("\n@implementation CNDSnowBoardRemix", restore_start)
        restore = self.remix[restore_start:restore_end]
        self.assertIn("BOOL targetAvailable =", restore)
        self.assertIn("CNDRemixIsSupportedPseudoBundleIdentifier(", restore)
        self.assertIn("if (!targetAvailable)", restore)
        self.assertIn("CNDIconServicesPublisherRestoreStockVariantInBatch(", restore)

    def test_exact_airdrop_filename_is_accepted_by_theme_importer(self) -> None:
        self.assertIn("CNDMappedIOSBundleIDsForIconName(fileURL.lastPathComponent", self.snowboard)
        self.assertIn("[bundleID stringByAppendingPathExtension:@\"png\"]", self.snowboard)

    def test_live_sharing_ui_cache_owner_has_one_bounded_retirement(self) -> None:
        symbol = "CNDIconServicesConsumerHookRetireSharingUIService"
        self.assertIn(symbol, self.consumer_hook_header)
        start = self.consumer_hook.index(f"{symbol}(void)")
        end = self.consumer_hook.index(
            "CNDIconServicesConsumerHookAuditSpringBoard(", start
        )
        retirement = self.consumer_hook[start:end]
        self.assertIn('@"SharingUIService"', retirement)
        self.assertEqual(retirement.count("RemoteCallSession *session"), 1)
        self.assertIn("g_RC_targetProcOverride = expectedProc", retirement)
        self.assertIn("session.pid == expectedPID", retirement)
        self.assertIn("session.taskAddr == expectedTask", retirement)
        self.assertIn("dispatchSelfSIGKILLForExpectedPID", retirement)
        self.assertIn("proc_find(expectedPID)", retirement)
        self.assertIn("attempt < 20", retirement)
        self.assertIn("usleep(50000)", retirement)
        self.assertNotIn("UIApplication", retirement)
        self.assertNotIn("recursive", retirement.lower())
        self.assertNotIn("killall", retirement.lower())

    def test_airdrop_consumer_refresh_runs_once_after_apply_publication(self) -> None:
        apply_start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        apply_end = self.remix.index(
            "CNDRemixDeferredSpringBoardPresentationRestore(", apply_start
        )
        apply = self.remix[apply_start:apply_end]
        persistent = apply.index("[SBR_SHARE] airdrop active=")
        refresh = apply.index(
            "CNDRemixRefreshAirDropPresentationIfNeeded(", persistent
        )
        springboard = apply.index("CNDRemixRunInitialCacheRefresh()", refresh)
        self.assertLess(persistent, refresh)
        self.assertLess(refresh, springboard)
        self.assertEqual(
            apply.count("CNDRemixRefreshAirDropPresentationIfNeeded("), 1
        )
        self.assertIn("airDropActive && sessionClosed", apply)

    def test_restore_refresh_is_optional_to_persistent_recovery(self) -> None:
        restore_start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals("
        )
        restore_end = self.remix.index("\n@implementation CNDSnowBoardRemix", restore_start)
        restore = self.remix[restore_start:restore_end]
        self.assertGreaterEqual(
            restore.count("CNDRemixRefreshAirDropPresentationIfNeeded("), 2
        )
        self.assertIn(
            "BOOL presentationOK = [restorePresentation[@\"ok\"] boolValue] &&",
            restore,
        )
        self.assertIn(
            "return CNDRemixCoordinatorResult(persistentRecoveryOK,", restore
        )
        self.assertIn("BOOL cleanupOK = sessionClosed && presentationOK", restore)

    def test_airdrop_source_repair_is_exact_and_precedes_store_removal(self) -> None:
        transport = self.publisher_transport
        run_start = transport.index(
            "cnd_publisher_run_stock_store(NSString *bundleIdentifier,"
        )
        run_end = transport.index(
            "\nstatic NSDictionary<NSString *, id> *\ncnd_publisher_run(",
            run_start,
        )
        run = transport[run_start:run_end]
        self.assertIn(
            "CNDIconServicesPublisherAirDropPseudoBundleIdentifier",
            run,
        )
        repair = run.index("cnd_publisher_repair_airdrop_source_registry(")
        removal = run.index('store, "removeUnitForUUID:"')
        self.assertLess(repair, removal)
        self.assertIn("if (sourceRegistrationRequired)", run)
        self.assertIn(
            "BOOL sourceRegistrationRequired = replacing &&",
            run,
        )
        self.assertIn(
            "sourceRegistryRepairResult.freshReadbackVerified",
            run,
        )

    def test_existing_airdrop_journal_is_upgraded_instead_of_skipped(self) -> None:
        remix = self.remix
        helper_start = remix.index(
            "static BOOL CNDRemixAirDropJournalHasVerifiedSourceRegistry("
        )
        helper_end = remix.index(
            "static BOOL CNDRemixJournalProvesNoIconServicesMutation(",
            helper_start,
        )
        helper = remix[helper_start:helper_end]
        for proof in (
            'publication[@"sourceRegistrationRequired"]',
            'publication[@"sourceIdentifiersResolved"]',
            'publication[@"sourceIdentifierCount"]',
            'publication[@"sourceRegistryFreshReadbackVerified"]',
        ):
            self.assertIn(proof, helper)

        apply_start = remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        apply_end = remix.index(
            "CNDRemixDeferredSpringBoardPresentationRestore(", apply_start
        )
        apply = remix[apply_start:apply_end]
        upgrade = apply.index("airDropSourceRegistryUpgradeRequired")
        fast_path = apply.index(
            "CNDRemixJournalMatchesCurrentApplication(", upgrade
        )
        rebase = apply.index(
            '@"airdrop-source-registry-upgrade"', fast_path
        )
        self.assertLess(upgrade, fast_path)
        self.assertLess(fast_path, rebase)
        self.assertIn("!airDropSourceRegistryUpgradeRequired", apply)

    def test_airdrop_source_repair_uses_native_provider_and_exact_map_abi(self) -> None:
        transport = self.publisher_transport
        resolve_start = transport.index(
            "static uint64_t cnd_publisher_resolve_airdrop_source_identifiers(\n",
            transport.index("cnd_publisher_source_registry_map("),
        )
        repair_start = transport.index(
            "static BOOL cnd_publisher_repair_airdrop_source_registry(\n",
            resolve_start,
        )
        resolve = transport[resolve_start:repair_start]
        self.assertIn('"makeResourceProvider", "@16@0:8"', resolve)
        self.assertIn(
            '"sourceRecordIdentifiers", "@16@0:8"', resolve
        )
        self.assertIn(
            "CNDIconServicesPublisherAirDropMaximumSourceIdentifiers",
            resolve,
        )
        self.assertIn(
            "CNDIconServicesPublisherMaximumPersistentIdentifierLength",
            resolve,
        )
        self.assertIn(
            "CNDIconServicesSourceRegistryNodeHeader23A341", resolve
        )
        self.assertIn("bucketReferenceOffset", resolve)
        self.assertIn("uuidWords[0] ^ uuidWords[1]", resolve)
        self.assertNotIn('r_msg2(\n        registry, "dataForUUID:"', resolve)

        audit_start = transport.index(
            "static NSDictionary<NSString *, id> *cnd_publisher_audit_variant(",
            repair_start,
        )
        repair = transport[repair_start:audit_start]
        self.assertIn(
            '"addData:forUUID:",\n            "v32@0:8@16@24"',
            repair,
        )
        self.assertNotIn('"dataForUUID:"', repair)
        self.assertIn("cnd_publisher_source_registry_entries(", repair)
        self.assertIn('"msync", writeExtent.mappedBytes', repair)
        self.assertIn("writeExtent.mappedLength, MS_SYNC", repair)
        self.assertIn("writeMapData, -1, scratch", repair)
        self.assertNotIn('"mmap"', repair)
        self.assertIn('r_msg2(registry, "release"', repair)
        self.assertIn("batch.auditSourceRegistry = 0;", repair)
        self.assertIn('"fsync", (uint64_t)syncDescriptor', repair)
        self.assertGreaterEqual(
            repair.count("cnd_publisher_source_registry_map("), 2
        )
        self.assertIn("result.freshReadbackVerified", repair)

    def test_airdrop_source_repair_accepts_a_missing_registry_entry(self) -> None:
        transport = self.publisher_transport
        contains_start = transport.index(
            "static BOOL cnd_publisher_source_array_contains_all("
        )
        repair_start = transport.index(
            "static BOOL cnd_publisher_repair_airdrop_source_registry(",
            contains_start,
        )
        contains = transport[contains_start:repair_start]
        self.assertIn("registered.count >", contains)
        self.assertIn("![registered containsObject:identifier]", contains)
        self.assertIn(
            "if (failureOut) *failureOut = nil;", contains
        )

        audit_start = transport.index(
            "static NSDictionary<NSString *, id> *cnd_publisher_audit_variant(",
            repair_start,
        )
        repair = transport[repair_start:audit_start]
        missing = repair.index(
            "BOOL containsAll = cnd_publisher_source_array_contains_all("
        )
        write = repair.index('registry, "addData:forUUID:"', missing)
        self.assertLess(missing, write)

    def test_airdrop_publication_reports_source_registration_proof(self) -> None:
        for field in (
            "sourceRegistrationRequired",
            "sourceIdentifiersResolved",
            "sourceIdentifierCount",
            "sourceRegistryEntryCountBefore",
            "sourceRegistryEntryCountAfter",
            "sourceRegistryAlreadyRegistered",
            "sourceRegistryWriteIssued",
            "sourceRegistryWriteFlushed",
            "sourceRegistryWriteVerified",
            "sourceRegistryFreshReadbackVerified",
        ):
            self.assertIn(f'report[@"{field}"]', self.publisher_transport)

    def test_airdrop_audit_uses_provider_identity_instead_of_app_record(self) -> None:
        transport = self.publisher_transport
        audit_start = transport.index(
            "static NSDictionary<NSString *, id> *cnd_publisher_audit_variant("
        )
        audit_end = transport.index(
            "\n@implementation CNDIconServicesPublisherRemoteTransport",
            audit_start,
        )
        audit = transport[audit_start:audit_end]
        pseudo = audit.index("BOOL airDropPseudoBundle")
        provider = audit.index(
            "cnd_publisher_resolve_airdrop_source_identifiers(", pseudo
        )
        app_record = audit.index('r_class("LSApplicationRecord")', provider)
        self.assertLess(pseudo, provider)
        self.assertLess(provider, app_record)
        self.assertIn('@"resource-provider"', audit)
        self.assertIn('@"audit-current-source-provider"', audit)
        self.assertIn('@"currentSourceIdentifierResolution"', audit)

    def test_isolated_airdrop_test_has_separate_four_step_api(self) -> None:
        for selector in (
            "applyIsolatedAirDropTest",
            "auditIsolatedAirDropTest",
            "captureIsolatedAirDropPresentation",
            "restoreIsolatedAirDropTest",
        ):
            self.assertIn(selector, self.remix_header)
            self.assertIn(selector, self.remix)

        self.assertIn('sbl-airdrop-test-apply', self.settings)
        self.assertIn('sbl-airdrop-test-audit', self.settings)
        self.assertIn('sbl-airdrop-test-live', self.settings)
        self.assertIn('sbl-airdrop-test-restore', self.settings)
        self.assertIn(
            'IconBundles/com.apple.Sharing.AirDrop.png', self.settings
        )

    def test_isolated_apply_filters_every_ordinary_application(self) -> None:
        apply_start = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)applyIsolatedAirDropTest"
        )
        apply_end = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)auditIsolatedAirDropTest",
            apply_start,
        )
        isolated_apply = self.remix[apply_start:apply_end]
        self.assertIn("NSSet<NSString *> *target = [NSSet setWithObject:", isolated_apply)
        self.assertIn("CNDRemixAirDropPseudoBundleIdentifier];", isolated_apply)
        self.assertIn("NO, YES, NO, nil, nil", isolated_apply)
        self.assertIn('@"ordinaryApplicationTargets"] = @0', isolated_apply)
        self.assertIn('@"expectedDescriptorCount"] = @2', isolated_apply)
        self.assertIn('@"airDropVerifiedSourceVariants"', isolated_apply)

        core_start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        core_end = self.remix.index(
            "static NSDictionary<NSString *, id> *\nCNDRemixDeferredSpringBoardPresentationRestore(",
            core_start,
        )
        core = self.remix[core_start:core_end]
        self.assertGreaterEqual(
            core.count("[foldedBundleFilter containsObject:folded]"), 2
        )
        self.assertIn("if (refreshSpringBoardConsumers)", core)
        self.assertIn('@"isolated-share-sheet-only"', core)
        self.assertIn('@"isolated-target-republish"', core)

    def test_isolated_apply_recovers_only_airdrop_before_republishing(self) -> None:
        apply_start = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)applyIsolatedAirDropTest"
        )
        apply_end = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)auditIsolatedAirDropTest",
            apply_start,
        )
        isolated_apply = self.remix[apply_start:apply_end]
        self.assertIn("existingJournal.count > 0", isolated_apply)
        self.assertIn(
            "CNDRemixRestoreIconServicesJournals(\n                target, NO",
            isolated_apply,
        )
        self.assertIn('@"airdrop-test-preflight-restore"', isolated_apply)
        self.assertLess(
            isolated_apply.index("CNDRemixRestoreIconServicesJournals("),
            isolated_apply.index("CNDRemixApplyIconServicesTheme("),
        )
        self.assertIn("BOOL sharingUIVerified = exactTarget &&", isolated_apply)
        self.assertIn("sharing-ui-remote=%d", isolated_apply)

    def test_isolated_audit_reads_exactly_the_two_journaled_records(self) -> None:
        audit_start = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)auditIsolatedAirDropTest"
        )
        audit_end = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)captureIsolatedAirDropPresentation",
            audit_start,
        )
        audit = self.remix[audit_start:audit_end]
        self.assertIn("specifications.count != 2 || variants.count != 2", audit)
        self.assertIn("CNDIconServicesPublisherAuditVariantsInBatch(", audit)
        self.assertIn('@"applicationContextSetupCount"', audit)
        self.assertIn('@"applicationContextReuseCount"', audit)
        self.assertIn(
            "CNDRemixAppliedAuditRecordProvesThemedPersistence(record)", audit
        )
        self.assertIn('@"mutationsIssued": @NO', audit)
        self.assertNotIn("CNDRemixRefreshAirDropPresentationIfNeeded", audit)
        self.assertNotIn("CNDRemixRunInitialCacheRefresh", audit)

    def test_live_capture_uses_exact_data_only_airdrop_descriptor_probes(self) -> None:
        capture_start = self.telemetry.index(
            "NSDictionary<NSString *, id> *CNDShareSheetTelemetryCapture(void)"
        )
        capture = self.telemetry[capture_start:]
        self.assertIn(
            'r_cfstr_register_only(\n                        "com.apple.Sharing.AirDrop")',
            capture,
        )
        self.assertNotIn(
            'r_nsstr_retained("com.apple.Sharing.AirDrop")', capture
        )
        self.assertIn("CNDShareTelemetryProbeDescriptor", capture)
        self.assertIn("{64U, 64U, 3U, 0U, 0U, 0U}", capture)
        self.assertIn("{28U, 28U, 3U, 0U, 4U, 0U}", capture)
        self.assertIn('"imageForDescriptor:"', capture)
        construction_start = capture.index("targetIdentifier =")
        construction_end = capture.index(
            "static const CNDShareTelemetryDescriptorSpec specs[]",
            construction_start,
        )
        construction = capture[construction_start:construction_end]
        self.assertIn('R_TIMEOUT, "objc_alloc", iconClass', construction)
        self.assertNotIn('r_msg2(iconClass, "alloc"', construction)
        self.assertIn('R_TIMEOUT, "method_getImplementation"', construction)
        self.assertIn('"ISBundleIdentifierIcon.initWithBundleIdentifier:"', construction)
        self.assertIn("r_call_address(", construction)
        self.assertNotIn('r_msg2(\n                        allocation, "initWithBundleIdentifier:"', construction)
        self.assertIn('r_msg2(\n                        manager, "findOrRegisterIcon:"', construction)
        self.assertNotIn("r_msg2_main", construction)
        self.assertIn('capture[@"iconConstruction"]', construction)
        self.assertIn('@"allocationTransport": @"objc_alloc"', construction)
        self.assertIn(
            '@"initializerTransport": @"direct-verified-imp"', construction
        )
        self.assertIn('capture[@"captureMode"] = @"data-only-existing-signed-code"', capture)
        self.assertIn('capture[@"temporaryMethodInterpositionUsed"] = @NO', capture)
        self.assertIn('capture[@"payloadMapped"] = @NO', capture)
        self.assertNotIn("CNDSignedRemotePayloadMapCurrentSession", capture)
        self.assertNotIn("method_setImplementation", capture)
        self.assertNotIn('"mmap"', capture)
        self.assertNotIn('"munmap"', capture)

    def test_airdrop_identifier_transfer_uses_register_arguments_only(self) -> None:
        helper_start = self.remote_objc.index(
            "uint64_t r_cfstr_register_only(const char *s)"
        )
        helper_end = self.remote_objc.index(
            "uint64_t r_nsstr_retained(const char *s)", helper_start
        )
        helper = self.remote_objc[helper_start:helper_end]
        self.assertIn('R_TIMEOUT, "calloc"', helper)
        self.assertIn('R_TIMEOUT, "memset"', helper)
        self.assertIn('R_TIMEOUT, "CFStringCreateWithBytes"', helper)
        self.assertIn("kMaximumUTF8Length = 512", helper)
        self.assertNotIn("remote_write(", helper)
        self.assertNotIn("remote_writeStr", helper)
        self.assertNotIn("vm_map_remote_page", helper)

    def test_live_capture_hashes_remote_images_without_executable_payload(self) -> None:
        snapshot_start = self.telemetry.index(
            "CNDShareTelemetrySnapshotRemoteImage("
        )
        snapshot_end = self.telemetry.index(
            "static BOOL CNDShareTelemetryDescriptorABI", snapshot_start
        )
        snapshot = self.telemetry[snapshot_start:snapshot_end]
        self.assertIn('"UIImagePNGRepresentation"', snapshot)
        self.assertIn("remote_read(", snapshot)
        self.assertIn("CGBitmapContextCreate(", snapshot)
        self.assertIn("CC_SHA256(", snapshot)
        self.assertNotIn("do_remote_call_stable_addr", snapshot)

    def test_signed_payload_uses_fileport_handoff_not_target_path_open(self) -> None:
        mapper_start = self.consumer_hook.index(
            "static bool cnd_consumer_map_physical_payload("
        )
        mapper_end = self.consumer_hook.index(
            "BOOL CNDSignedRemotePayloadMapCurrentSession(", mapper_start
        )
        mapper = self.consumer_hook[mapper_start:mapper_end]
        self.assertIn("fileport_makeport(localFD, &localFileport)", mapper)
        self.assertIn("remote_call_transfer_send_right_to_target", mapper)
        self.assertIn('"fileport_makefd"', mapper)
        self.assertIn("remote_call_deallocate_target_send_right", mapper)
        lab_branch = mapper.index("if (usesLabTransport)")
        lab_open = mapper.index('R_TIMEOUT, "open"', lab_branch)
        physical_branch = mapper.index("} else {", lab_open)
        transfer = mapper.index(
            "remote_call_transfer_send_right_to_target", physical_branch
        )
        self.assertLess(lab_branch, lab_open)
        self.assertLess(lab_open, physical_branch)
        self.assertLess(physical_branch, transfer)

    def test_fileport_handoff_uses_kernel_named_descriptor_delivery(self) -> None:
        transfer_start = self.remote_call.index(
            "bool remote_call_transfer_send_right_to_target("
        )
        transfer_end = self.remote_call.index(
            "kern_return_t remote_call_deallocate_target_send_right(",
            transfer_start,
        )
        transfer = self.remote_call[transfer_start:transfer_end]
        self.assertIn("mach_port_allocate(", transfer)
        self.assertIn("MACH_PORT_RIGHT_RECEIVE", transfer)
        self.assertIn("mach_port_extract_right(", transfer)
        self.assertIn("MACH_MSGH_BITS_COMPLEX", transfer)
        self.assertIn("mach_msg_port_descriptor_t", self.remote_call)
        self.assertIn('"mach_msg"', transfer)
        self.assertNotIn("mach_port_insert_right", transfer)
        self.assertIn("mailboxCleanupResult == KERN_SUCCESS", transfer)

    def test_live_capture_uses_identity_bootstrap_for_data_only_calls(self) -> None:
        capture_start = self.telemetry.index(
            "NSDictionary<NSString *, id> *CNDShareSheetTelemetryCapture(void)"
        )
        capture = self.telemetry[capture_start:]
        self.assertIn(
            'initWithIdentityBootstrapProcess:@"SharingUIService"', capture
        )
        self.assertNotIn(
            'initWithProcess:@"SharingUIService"', capture
        )

    def test_identity_task_right_is_session_scoped(self) -> None:
        self.assertIn("mach_port_t identityTaskPort;", self.remote_call)
        self.assertIn(
            "g_RC_identityTaskPort = identityRequest.task.name;",
            self.remote_call,
        )
        release_start = self.remote_call.index(
            "static void remote_call_release_identity_rights(void)"
        )
        release_end = self.remote_call.index(
            "static void remote_call_release_identity_request_rights(",
            release_start,
        )
        release = self.remote_call[release_start:release_end]
        self.assertIn("g_RC_identityThreadPort", release)
        self.assertIn("g_RC_identityTaskPort", release)
        self.assertGreaterEqual(
            self.remote_call.count("remote_call_release_identity_rights();"),
            4,
        )
        self.assertIn(
            "RemoteCallSendRightTransferReport", self.remote_call_header
        )

    def test_data_only_capture_never_retires_the_service_for_cleanup(self) -> None:
        capture_start = self.telemetry.index(
            "NSDictionary<NSString *, id> *CNDShareSheetTelemetryCapture(void)"
        )
        capture = self.telemetry[capture_start:]
        self.assertNotIn(
            "CNDIconServicesConsumerHookRetireSharingUIService", capture
        )
        self.assertIn('capture[@"failedRestoreCleanup"] = @{}', capture)
        self.assertIn('capture[@"mappingCleanupRequired"] = @NO', capture)

    def test_live_capture_bounds_provider_and_visible_cell_evidence(self) -> None:
        self.assertIn("UIAirDropActivity", self.telemetry)
        self.assertIn("_bundleIdentifierForActivityImageCreation", self.telemetry)
        self.assertIn("_activityImage", self.telemetry)
        self.assertIn("UIActivityContentViewController", self.telemetry)
        self.assertIn("UIShareGroupActivityCell", self.telemetry)
        self.assertIn("VIEW_CAPACITY = 2048", self.telemetry)
        self.assertIn("CONTROLLER_CAPACITY = 128", self.telemetry)
        self.assertIn("windows.count < 16", self.telemetry)
        self.assertIn("fabs(frame.size.width - 72.0)", self.telemetry)

    def test_live_capture_compares_all_three_pixel_boundaries(self) -> None:
        capture_start = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)captureIsolatedAirDropPresentation"
        )
        capture_end = self.remix.index(
            "+ (NSDictionary<NSString *, id> *)restoreIsolatedAirDropTest",
            capture_start,
        )
        capture = self.remix[capture_start:capture_end]
        self.assertIn("CNDRemixCanonicalRGBAHashForPNG", capture)
        self.assertIn("CNDShareSheetTelemetryCapture()", capture)
        self.assertIn('result[@"requestThemed"]', capture)
        self.assertIn('result[@"activityImageThemed"]', capture)
        self.assertIn('result[@"displayedImageThemed"]', capture)
        self.assertIn(
            '@"explicit-iconservices-probe-returned-nonthemed-pixels"', capture
        )
        self.assertIn(
            '@"activity-provider-returned-nonthemed-pixels"', capture
        )
        self.assertIn(
            '@"materialized-airdrop-cell-retained-nonthemed-pixels"',
            capture,
        )
        self.assertIn('result[@"mutationsIssued"] = @NO', capture)

    def test_live_capture_ui_keeps_share_sheet_alive_until_completion(self) -> None:
        live_start = self.settings.index("- (void)runAirDropLiveTelemetry")
        live_end = self.settings.index("- (void)toggleChanged:", live_start)
        live = self.settings[live_start:live_end]
        self.assertIn("UIActivityViewController", live)
        self.assertIn("500 * NSEC_PER_MSEC", live)
        self.assertIn(
            "settings_run_snowboard_remix_operation_with_completion", live
        )
        self.assertIn(
            '@"Isolated AirDrop Live Capture", YES, YES', live
        )
        self.assertIn("captureIsolatedAirDropPresentation", live)
        self.assertIn("dismissViewControllerAnimated:YES", live)

    def test_isolated_restore_skips_broad_springboard_presentation(self) -> None:
        restore_start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals("
        )
        restore_end = self.remix.index(
            "\n@implementation CNDSnowBoardRemix", restore_start
        )
        restore = self.remix[restore_start:restore_end]
        self.assertIn("BOOL isolatedAirDropOnly = bundleFilter.count == 1", restore)
        self.assertNotIn("persistentThemeMutationWasRestored", restore)
        self.assertIn(
            "NSDictionary *restorePresentation = isolatedAirDropOnly",
            restore,
        )
        self.assertIn('@"stage": @"isolated-airdrop-not-required"', restore)
        self.assertIn(
            "CNDRemixRefreshAirDropPresentationIfNeeded(", restore
        )
        self.assertIn("CNDRemixDeferredSpringBoardPresentationRestore()", restore)
        self.assertIn('@"springBoardPresentationSkipped": @YES', restore)
        self.assertNotIn("CNDIconServicesConsumerLifecycleRepair", restore)

    def test_airdrop_recovery_accepts_only_byte_exact_stock_readback(self) -> None:
        proof_start = self.remix.index(
            "static BOOL CNDRemixAuditProvesSavedStock("
        )
        proof_end = self.remix.index(
            "static NSDictionary *CNDRemixCompactStockReadbackAudit(",
            proof_start,
        )
        proof = self.remix[proof_start:proof_end]
        for required in (
            '@"cacheStoreEqual"',
            '@"cacheStoreIdentifierEqual"',
            '@"cacheStoreValidationTokenEqual"',
            '@"storeIndexUnitIdentifierEqual"',
            '@"persistentMutationsIssued"',
            '@"generationIssued"',
            "expectedStockHash",
            "expectedThemedHash",
            "themedTokenHash",
        ):
            self.assertIn(required, proof)
        self.assertNotIn('@"sourceIdentityMatchesCurrentRecord"', proof)

        restore_start = self.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals("
        )
        restore_end = self.remix.index("\n@implementation CNDSnowBoardRemix", restore_start)
        restore = self.remix[restore_start:restore_end]
        audit = restore.index("CNDIconServicesPublisherAuditVariantInBatch(")
        mutate = restore.index("CNDIconServicesPublisherRestoreStockVariantInBatch(")
        self.assertLess(audit, mutate)
        self.assertIn('@"stage": @"already-stock-readback"', restore)
        self.assertIn('@"alreadyStockVariants"', restore)


if __name__ == "__main__":
    unittest.main()
