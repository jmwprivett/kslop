"""Host/static checks for the IconServices publisher transport boundary."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "Cyanide/installer"
FACADE = INSTALLER / "CNDIconServicesPublisher.m"
TRANSPORT = INSTALLER / "CNDIconServicesPublisherTransport.h"
ADAPTER = INSTALLER / "CNDIconServicesPublisherRemoteTransport.m"
REMOTE_CALL = ROOT / "Cyanide/TaskRop/RemoteCall.m"
REMOTE_CALL_HEADER = ROOT / "Cyanide/TaskRop/RemoteCall.h"
SETTINGS = ROOT / "Cyanide/SettingsViewController.m"
REMIX = INSTALLER / "CNDSnowBoardRemix.m"
PAYLOAD_HEADER = INSTALLER / "CNDIconServicesPublisherPayload.h"
PAYLOAD_SOURCE = INSTALLER / "CNDIconServicesPublisherPayload.c"
PAYLOAD_ASSEMBLY = INSTALLER / "CNDIconServicesPublisherPayload.S"


class IconServicesPublisherTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.facade = FACADE.read_text(encoding="utf-8")
        cls.transport = TRANSPORT.read_text(encoding="utf-8")
        cls.adapter = ADAPTER.read_text(encoding="utf-8")

    def test_facade_is_transport_neutral(self) -> None:
        self.assertNotIn("RemoteCall", self.facade)
        self.assertNotIn("remote_objc", self.facade)
        self.assertNotIn("r_msg2", self.facade)
        self.assertNotIn("remote_call_with_session", self.facade)

    def test_protocol_covers_complete_publisher_lifecycle(self) -> None:
        normalized = "".join(self.transport.split())
        for selector in (
            "beginBatch:",
            "copyInstalledBundleIdentifiersInBatch",
            "restoreStockForBundleIdentifier:",
            "isHealthy",
            "finishBatch",
        ):
            self.assertIn(selector, normalized)
        self.assertIn("publishBundleIdentifier:", normalized)
        self.assertIn("structuredImageData:", normalized)

    def test_bundle_identifier_validation_accepts_single_component_ids(self) -> None:
        start = self.adapter.index(
            "static BOOL cnd_publisher_valid_bundle_identifier(id value)"
        )
        end = self.adapter.index("\nstatic NSDictionary", start)
        validator = self.adapter[start:end]
        self.assertNotIn(
            '[identifier rangeOfString:@"."].location == NSNotFound', validator
        )
        for check in (
            "identifier.length == 0",
            "identifier.length > 255",
            '[identifier hasPrefix:@"."]',
            '[identifier hasSuffix:@"."]',
            '[identifier containsString:@".."]',
            'characterSetWithCharactersInString:',
            'rangeOfCharacterFromSet:invalid',
        ):
            self.assertIn(check, validator)

    def test_facade_forwards_every_public_operation(self) -> None:
        self.assertIn("[transport beginBatch:wakeBundleIdentifier]", self.facade)
        self.assertIn("[batch.transport copyInstalledBundleIdentifiersInBatch]", self.facade)
        self.assertIn("[batch.transport publishBundleIdentifier:bundleIdentifier", self.facade)
        self.assertIn("[batch.transport restoreStockForBundleIdentifier:bundleIdentifier]", self.facade)
        self.assertIn("[batch.transport finishBatch]", self.facade)
        self.assertIn("[transport publishBundleIdentifier:bundleIdentifier", self.facade)
        self.assertIn("[transport restoreStockForBundleIdentifier:bundleIdentifier]", self.facade)

    def test_applied_state_audit_is_getter_only(self) -> None:
        start = self.adapter.index(
            "static NSDictionary<NSString *, id> *cnd_publisher_audit_variant("
        )
        end = self.adapter.index("\n@implementation CNDIconServicesPublisherRemoteTransport", start)
        audit = self.adapter[start:end]
        self.assertIn('"imageForDescriptor:"', audit)
        self.assertIn(
            'r_msg2(\n                    canonicalCache, "imageForDescriptor:"',
            audit,
        )
        self.assertNotIn(
            'r_msg2(\n                    canonicalIcon, "imageForDescriptor:"',
            audit,
        )
        self.assertIn('"storeUnitWithStoreURL:UUID:"', audit)
        self.assertNotIn('r_msg2(store, "unitForUUID:"', audit)
        self.assertIn(
            '"findStoreUnitForIcon:descriptor:UUID:validationToken:"', audit
        )
        self.assertIn(
            'localIcon, descriptor, auditScratch,', audit
        )
        for direct_ivar, offset in (
            ('"_iconCache"', "0x10"),
            ('"_store"', "0x10"),
            ('"_imageCache"', "0x20"),
            ('"_data"', "0x18"),
            ('"_uuid"', "0x90"),
            ('"_validationToken"', "0x98"),
            ('"_storeURL"', "0x10"),
            ('"_UUID"', "0x8"),
        ):
            self.assertIn(direct_ivar, audit)
            self.assertIn(offset, audit)
        self.assertNotIn('r_msg2(store, "storeURL"', audit)
        self.assertNotIn('r_msg2(storeUnit, "data"', audit)
        self.assertNotIn('r_msg2(storeUnit, "UUID"', audit)
        self.assertNotIn('r_msg2(response, "data"', audit)
        self.assertNotIn('r_msg2(response, "uuid"', audit)
        self.assertNotIn('r_msg2(response, "validationToken"', audit)
        self.assertIn('@"cacheDataSHA256"', audit)
        self.assertIn('@"cacheIdentifier"', audit)
        self.assertIn('@"validationTokenLength"', audit)
        self.assertIn('@"validationTokenSHA256"', audit)
        self.assertIn('@"storeDataSHA256"', audit)
        self.assertIn('@"storeIdentifier"', audit)
        self.assertIn('@"indexedIdentifier"', audit)
        self.assertIn('@"storeValidationTokenSHA256"', audit)
        self.assertIn('@"cacheStoreEqual"', audit)
        self.assertIn('@"cacheStoreIdentifierEqual"', audit)
        self.assertIn("cnd_publisher_source_registry_map(", audit)
        self.assertIn("cnd_publisher_source_registry_entries(", audit)
        self.assertNotIn('sourceRegistry, "dataForUUID:"', audit)
        self.assertIn(
            '"initWithBundleIdentifier:allowPlaceholder:error:"', audit
        )
        self.assertIn('@"sourceRegistryDataSHA256"', audit)
        self.assertIn('@"currentSourceIdentifierSHA256"', audit)
        self.assertIn('@"sourceIdentityMatchesCurrentRecord"', audit)
        self.assertIn('@"transientWeakRegistryProbeIssued": @YES', audit)
        self.assertIn('@"persistentMutationsIssued": @NO', audit)
        self.assertIn('@"presentationMutationsIssued": @NO', audit)
        self.assertIn('@"mutationsIssued": @NO', audit)
        self.assertIn('@"generationIssued": @NO', audit)
        self.assertIn('@"cachePurgeIssued": @NO', audit)
        self.assertIn('@"storeWriteIssued": @NO', audit)
        self.assertNotIn('r_msg2(store, "removeUnitForUUID:"', audit)
        self.assertNotIn('r_msg2(store, "writeStoreUnit:"', audit)
        self.assertNotIn('r_msg2(canonicalCache, "setImage:forDescriptor:"', audit)
        self.assertNotIn('r_msg2(canonicalIcon, "generateImageWithDescriptor:"', audit)
        self.assertNotIn('"setIgnoreCache:", 1', audit)

    def test_source_identity_audit_opens_verified_persistent_registry_map(self) -> None:
        helper_start = self.adapter.index(
            "static uint64_t cnd_publisher_source_registry_map("
        )
        audit_start = self.adapter.index(
            "static NSDictionary<NSString *, id> *cnd_publisher_audit_variant("
        )
        helper = self.adapter[helper_start:audit_start]
        self.assertIn('managerCache, "_cacheURL", 0x18, scratch', helper)
        self.assertNotIn('r_msg2(managerCache, "cacheURL"', helper)
        self.assertIn('"store-source-registry.map"', helper)
        self.assertIn('"initWithURL:capacity:"', helper)
        self.assertIn('"@32@0:8@16Q24"', helper)
        self.assertIn("registryURL, 4000", helper)
        self.assertIn('"fileExistsAtPath:"', helper)
        self.assertIn(
            "CNDIconServicesSourceRegistryNodeHeader23A341", helper
        )
        self.assertIn(
            "CNDIconServicesPublisherAuditMaximumSourceIdentifiers", helper
        )
        self.assertIn("bucketReferenceAddress", helper)
        self.assertIn("uuidWords[0] ^ uuidWords[1]", helper)
        self.assertNotIn('"dataForUUID:", "@24@0:8@16"', helper)
        self.assertIn('"_ISMutableStoreIndex_mappedDataWithURL:"', helper)
        self.assertIn('"_ISStoreIndex_isValid"', helper)
        self.assertIn('map, "_data", 0x10, scratch', helper)
        self.assertIn('R_TIMEOUT, "object_setIvar"', helper)
        self.assertNotIn('"unitSourceRegistry"', helper)
        self.assertIn("batch.auditSourceRegistry = map;", helper)

        audit_end = self.adapter.index(
            "\n@implementation CNDIconServicesPublisherRemoteTransport",
            audit_start,
        )
        audit = self.adapter[audit_start:audit_end]
        self.assertIn('"@36@0:8@16B24^@28"', audit)
        self.assertIn('"objectAtIndex:",', audit)
        self.assertIn("sourceIdentifiers.count", audit)
        self.assertIn(
            "isEqualToData:currentSourceIdentifierData", audit
        )

        batch_state = self.adapter[
            self.adapter.index("@interface CNDIconServicesPublisherBatchState"):
            self.adapter.index("@end", self.adapter.index(
                "@interface CNDIconServicesPublisherBatchState"))
        ]
        self.assertIn("auditSourceRegistry", batch_state)

        finish_start = self.adapter.index(
            "- (NSDictionary<NSString *, id> *)finishBatch"
        )
        finish = self.adapter[finish_start:]
        self.assertIn('r_msg2(state.auditSourceRegistry,\n'
                      '                                 "release"', finish)
        self.assertIn("state.auditSourceRegistry = 0;", finish)

    def test_applied_state_audit_uses_pinned_scratch_for_small_remote_reads(self) -> None:
        helper_start = self.adapter.index(
            "static NSString *cnd_publisher_audit_copy_indexed_identifier("
        )
        audit_start = self.adapter.index(
            "static NSDictionary<NSString *, id> *cnd_publisher_audit_variant("
        )
        helpers = self.adapter[helper_start:audit_start]
        self.assertIn('"getUUIDBytes:"', helpers)
        self.assertIn('"v24@0:8*16"', helpers)
        self.assertIn('r_dlsym_call(R_TIMEOUT, "memcpy", scratch', helpers)
        self.assertIn("remote_read(scratch", helpers)
        self.assertNotIn('R_TIMEOUT, "malloc"', helpers)
        self.assertIn("cnd_publisher_audit_copy_remote_data(", helpers)
        self.assertIn("CNDIconServicesPublisherAuditCopyChunkLength", helpers)

        audit_end = self.adapter.index(
            "\n@implementation CNDIconServicesPublisherRemoteTransport",
            audit_start,
        )
        audit = self.adapter[audit_start:audit_end]
        self.assertIn("uint64_t auditScratch = session.trojanMem;", audit)
        self.assertIn("cnd_publisher_audit_copy_indexed_identifier(", audit)
        self.assertIn("cnd_publisher_audit_copy_small_remote_data(", audit)
        self.assertNotIn(
            "cnd_publisher_copy_remote_indexed_identifier(responseUUID)",
            audit,
        )

        generic_start = self.adapter.index(
            "static NSString *cnd_publisher_copy_remote_indexed_identifier(\n"
            "    uint64_t identifier)\n{"
        )
        generic = self.adapter[generic_start:helper_start]
        self.assertNotIn('"v24@0:8*16"', generic)
        self.assertIn('"audit-stage=%s "', REMIX.read_text(encoding="utf-8"))

    def test_debug_apply_uses_the_four_named_applications(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        self.assertIn("CNDRemixTestApplicationLimit = 4", remix)
        selection_start = remix.index(
            "static NSArray<NSString *> *CNDRemixDebugApplicationBundleIdentifiers(void)"
        )
        selection_end = remix.index(
            "\nstatic NSArray<NSString *> *CNDRemixDebugSelectionFromBundleIdentifiers(",
            selection_start,
        )
        selection = remix[selection_start:selection_end]
        expected_identifiers = (
            "com.toyopagroup.picaboo",
            "com.apple.MobileSMS",
            "com.zhiliaoapp.musically",
            "com.8bit.bitwarden",
        )
        for bundle_identifier in expected_identifiers:
            self.assertIn(f'@"{bundle_identifier}"', selection)
        self.assertEqual(
            remix.count("CNDRemixDebugSelectionFromBundleIdentifiers("),
            3,
        )
        self.assertNotIn("NSMakeRange(CNDRemixTestApplicationLimit", remix)

    def test_publisher_bootstrap_never_forces_iconservices_gc(self) -> None:
        self.assertIn(
            "cnd_publisher_submit_read_only_agent_request", self.adapter
        )
        self.assertIn('NSSelectorFromString(@"fetchCacheConfigurationWithReply:")', self.adapter)
        self.assertIn('@"garbageCollectionTriggerAvoided": @YES', self.adapter)
        self.assertNotIn(
            "_ISInvalidateCacheEntriesForBundleIdentifier", self.adapter
        )

    def test_vphone_resolver_prevents_false_agent_wake(self) -> None:
        helper_start = self.adapter.index(
            "static uint64_t cnd_publisher_resident_agent_identity("
        )
        wake_start = self.adapter.index(
            "cnd_publisher_wake_agent_without_generation(", helper_start
        )
        helper = self.adapter[helper_start:wake_start]
        self.assertIn("cnd_lab_process_resolve_active()", helper)
        self.assertIn(
            'cnd_lab_resolve_process_pid(\n            "iconservicesagent", &pid)',
            helper,
        )
        self.assertLess(
            helper.index("cnd_lab_process_resolve_active()"),
            helper.index('proc_find_by_name("iconservicesagent")'),
        )

        wake_end = self.adapter.index(
            "\n/*\n * A resident iconservicesagent", wake_start
        )
        wake = self.adapter[wake_start:wake_end]
        self.assertEqual(
            wake.count("cnd_publisher_resident_agent_identity("), 2
        )
        self.assertNotIn('proc_find_by_name("iconservicesagent")', wake)

    def test_publication_journals_real_indexed_identifier_and_token_hash(self) -> None:
        start = self.adapter.index(
            "cnd_publisher_run_stock_store(NSString *bundleIdentifier"
        )
        end = self.adapter.index(
            "\nstatic NSDictionary<NSString *, id> *\ncnd_publisher_run(", start
        )
        publication = self.adapter[start:end]
        self.assertIn(
            "cnd_publisher_audit_copy_indexed_identifier(\n"
            "                    stockUUID, persistentIndexScratch)",
            publication,
        )
        self.assertIn('report[@"stockResponse"] = stockResponse', publication)
        self.assertIn('@"validationTokenSHA256"', publication)
        self.assertNotIn('@"opaque-indexed-identifier"', publication)

    def test_themed_publication_uses_iconservices_always_valid_token(self) -> None:
        start = self.adapter.index(
            "cnd_publisher_run_stock_store(NSString *bundleIdentifier"
        )
        end = self.adapter.index(
            "\nstatic NSDictionary<NSString *, id> *\ncnd_publisher_run(", start
        )
        publication = self.adapter[start:end]
        self.assertIn(
            'cnd_publisher_remote_class_method_has_types(\n'
            '                              dataClass, "_is_validToken",\n'
            '                              "@16@0:8", NULL)',
            publication,
        )
        self.assertIn(
            'publishedToken = r_msg2(\n'
            '                        dataClass, "_is_validToken", 0, 0, 0, 0);',
            publication,
        )
        self.assertIn("publishedTokenLength != 40U", publication)
        self.assertIn(
            '"initWithData:uuid:validationToken:",\n'
            "                                 themedData, stockUUID, publishedToken, 0)",
            publication,
        )
        self.assertNotIn(
            '"initWithData:uuid:validationToken:",\n'
            "                                 themedData, stockUUID, stockToken, 0)",
            publication,
        )
        self.assertIn("cacheToken, publishedToken", publication)
        self.assertIn('@"iconservices-always-valid"', publication)
        self.assertIn(
            '@"validationTokenSHA256": publishedValidationTokenHash ?: @""',
            publication,
        )

    def test_themed_publication_commits_and_rechecks_persistent_index_token(self) -> None:
        helper_start = self.adapter.index(
            "static BOOL cnd_publisher_rewrite_persistent_index_token("
        )
        publication_start = self.adapter.index(
            "cnd_publisher_run_stock_store(NSString *bundleIdentifier"
        )
        helper = self.adapter[helper_start:publication_start]
        publication_end = self.adapter.index(
            "\nstatic NSDictionary<NSString *, id> *\ncnd_publisher_run(",
            publication_start,
        )
        publication = self.adapter[publication_start:publication_end]

        for layout_proof in (
            "sizeof(CNDIconServicesStoreIndexValue23A341) == 0x74",
            "storeUnitUUID) ==\n                   0x3c",
            "validationToken) == 0x4c",
        ):
            self.assertIn(layout_proof, self.adapter)
        for proof in (
            '"_ISMutableStoreIndex_mappedDataWithURL:"',
            '"initWithStoreFileURL:capacity:"',
            "indexURL, 0xFA0",
            '"_ISStoreIndex_isValid"',
            'R_TIMEOUT, "memmem"',
            'R_TIMEOUT, "msync"',
            'r_msg2(managerIndex, "invalidate"',
            "cnd_publisher_wait_for_persistent_index_identity(",
            "result.rollbackAttempted",
            "result.rollbackVerified",
        ):
            self.assertIn(proof, helper)
        self.assertIn('canonicalIcon, "digest"', helper)
        self.assertIn('descriptor, "digest"', helper)
        self.assertIn('requestedPointSize >= record.minimumSize', helper)
        self.assertIn('requestedPointSize <= record.maximumSize', helper)
        self.assertNotIn('descriptor, "digest:size:"', helper)
        settle_helper_start = self.adapter.index(
            "static BOOL cnd_publisher_wait_for_persistent_index_identity("
        )
        settle_helper = self.adapter[settle_helper_start:helper_start]
        self.assertIn('managerCache, "_storeIndex", 0x8, scratch', settle_helper)
        self.assertIn('if (attempt > 1U)', settle_helper)
        self.assertIn('r_msg2(managerIndex, "invalidate"', settle_helper)

        settle = publication.index(
            "persistentIndexIdentitySettled = persistentIndexScratch"
        )
        remove = publication.index("directStoreRemoveIssued = YES")
        write_verified = publication.index("directStoreWriteVerified =")
        rewrite = publication.index(
            "cnd_publisher_rewrite_persistent_index_token("
        )
        cache_publish = publication.index(
            'r_msg2(canonicalCache, "setImage:forDescriptor:"'
        )
        self.assertLess(settle, remove)
        self.assertLess(write_verified, rewrite)
        self.assertLess(rewrite, cache_publish)
        for field in (
            "persistentIndexIdentitySettled",
            "persistentIndexTokenWriteIssued",
            "persistentIndexTokenWriteFlushed",
            "persistentIndexTokenWriteVerified",
            "persistentIndexTokenLookupVerified",
            "persistentIndexTokenRollbackAttempted",
            "persistentIndexTokenRollbackVerified",
        ):
            self.assertIn(f'@"{field}"', publication)

    def test_indexed_identifier_copy_avoids_uuid_string_remote_call(self) -> None:
        start = self.adapter.index(
            "static NSString *cnd_publisher_copy_remote_indexed_identifier(\n"
            "    uint64_t identifier)\n{"
        )
        end = self.adapter.index(
            "\n/* Observation-only state classifier", start
        )
        helper = self.adapter[start:end]
        self.assertIn('"getUUIDBytes:"', helper)
        self.assertIn('"v24@0:8[16C]16"', helper)
        self.assertIn("remote_read(remoteBytes, bytes, sizeof(bytes))", helper)
        self.assertNotIn('r_msg2(identifier, "UUIDString"', helper)

    def test_applied_state_audit_reuses_one_batch_and_does_not_edit_journals(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        start = remix.index("+ (NSDictionary<NSString *, id> *)auditAppliedIconState")
        end = remix.index("\n+ (BOOL)hasRecoveryData", start)
        audit = remix[start:end]
        self.assertEqual(audit.count("CNDIconServicesPublisherBeginBatch("), 1)
        self.assertEqual(audit.count("CNDIconServicesPublisherFinishBatch()"), 1)
        self.assertIn("CNDIconServicesPublisherAuditVariantInBatch(", audit)
        self.assertIn("CNDIconServicesConsumerHookAuditSpringBoard(", audit)
        self.assertNotIn("CNDRemixWriteJournal", audit)
        self.assertNotIn("CNDRemixRemoveJournal", audit)
        self.assertNotIn("CNDIconServicesPublisherPublish", audit)
        self.assertNotIn("CNDIconServicesPublisherRestore", audit)
        self.assertNotIn("CNDRemixReconcileAndRefreshSpringBoardCaches", audit)

    def test_snowboard_operations_persist_their_diagnostic_log(self) -> None:
        settings = SETTINGS.read_text(encoding="utf-8")
        start = settings.index("static void settings_run_snowboard_remix_operation(")
        end = settings.index("\n@interface SettingsViewController", start)
        operation = settings[start:end]
        self.assertIn("log_session_begin();", operation)
        self.assertIn("log_session_end();", operation)
        self.assertLess(
            operation.index("log_session_begin();"),
            operation.index("if (!result) result = operation();"),
        )
        self.assertLess(
            operation.index('log_user("%s %s: %s\\n"'),
            operation.index("log_session_end();"),
        )
    def test_applied_state_audit_covers_every_journaled_descriptor_surface(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        helper_start = remix.index("static NSString *CNDRemixAppliedAuditSurface(")
        helper_end = remix.index("\nstatic NSString *CNDRemixAppliedAuditRecordKey", helper_start)
        helper = remix[helper_start:helper_end]
        for surface in (
            "home-folder-preview-child",
            "spotlight-snippet-badge",
            "app-library-miniature",
            "switcher-transition",
            "notification",
            "app-library-list",
            "spotlight-apps-list",
            "launch-return-transition",
            "home-app-library-large",
        ):
            self.assertIn(f'@"{surface}"', helper)

        start = remix.index("+ (NSDictionary<NSString *, id> *)auditAppliedIconState")
        end = remix.index("\n+ (BOOL)hasRecoveryData", start)
        audit = remix[start:end]
        self.assertIn("CNDRemixAppliedAuditSurface(specification)", audit)
        self.assertNotIn("appearance != 0", audit)
        self.assertNotIn("(width != 68 && width != 28)", audit)

    def test_applied_state_audit_persists_bounded_rolling_reinstall_snapshot(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        start = remix.index("static NSURL *CNDRemixAppliedAuditSnapshotURL")
        end = remix.index("\n+ (BOOL)hasRecoveryData", start)
        audit_support = remix[start:end]
        for evidence in (
            'URLByAppendingPathComponent:@"AppliedIconState.plist"',
            "CNDRemixAppliedAuditMaximumTargets",
            "CNDRemixReadAppliedAuditSnapshot",
            "CNDRemixWriteAppliedAuditSnapshot",
            "NSDataWritingAtomic",
            "NSFileProtectionNone",
            '@"missing-after-reinstall"',
            '@"themed-to-stock"',
            '@"reindexed-data-unchanged"',
            '@"unchanged"',
            'log_user("[SBR_AUDIT_REINSTALL]',
            '"before-index-id=%s after-index-id=%s "',
            '"before-store-id=%s after-store-id=%s before-token=%s "',
            '"after-source=%s before-source-match=%s "',
            '@"indexedIdentifier"',
            '@"storeValidationTokenSHA256"',
            '@"sourceRegistryDataSHA256"',
            '@"currentSourceIdentifierSHA256"',
            '@"sourceIdentityMatchesCurrentRecord"',
            '@"source-identity-mismatch"',
            '@"audit-baseline-captured"',
            '@"audit-reinstall-difference-detected"',
            "CNDRemixAppliedAuditRecordProvesThemedPersistence",
            "currentThemedEvidenceComplete",
            "snapshotAdvanceEligible",
        ):
            self.assertIn(evidence, audit_support)

        method_start = audit_support.index(
            "+ (NSDictionary<NSString *, id> *)auditAppliedIconState"
        )
        audit = audit_support[method_start:]
        self.assertIn(
            "BOOL snapshotWriteAttempted = iconServicesOK && springBoardOK &&\n"
            "        snapshotAdvanceEligible;",
            audit,
        )
        self.assertIn(
            "BOOL snapshotWritten = snapshotWriteAttempted &&\n"
            "        CNDRemixWriteAppliedAuditSnapshot(currentSnapshot);",
            audit,
        )
        self.assertIn('@"localSnapshotWritten": @(snapshotWritten)', audit)
        self.assertIn('@"mutationsIssued": @NO', audit)

    def test_themed_persistence_proof_does_not_require_process_cache(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        start = remix.index(
            "static BOOL CNDRemixAppliedAuditRecordHasValidPersistentStoreEvidence("
        )
        end = remix.index(
            "\nstatic NSDictionary *CNDRemixCompareAppliedAuditRecords", start
        )
        proof = remix[start:end]
        for evidence in (
            '@"storeIndexLookupReady"',
            '@"storeIndexEntryPresent"',
            '@"storeUnitPresent"',
            '@"storeUnitValid"',
            '@"storeIndexUnitIdentifierEqual"',
            '@"indexedIdentifier"',
            '@"storeIdentifier"',
            '@"storeValidationTokenSHA256"',
            '@"sourceIdentityMatchesCurrentRecord"',
        ):
            self.assertIn(evidence, proof)
        for cache_evidence in (
            '@"cacheResponsePresent"',
            '@"cacheStoreEqual"',
            '@"cacheIdentifier"',
            '@"cacheDataSHA256"',
            '@"validationTokenSHA256"',
        ):
            self.assertNotIn(cache_evidence, proof)

    def test_applied_state_audit_resolves_only_verified_same_unit_theme_aliases(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        self.assertIn(
            "CNDRemixAppliedAuditSnapshotSchemaVersion = 4", remix
        )
        helper_start = remix.index(
            "static NSString *CNDRemixAppliedAuditStoreAliasKey("
        )
        helper_end = remix.index(
            "\nstatic NSDictionary *CNDRemixCompareAppliedAuditRecords",
            helper_start,
        )
        helpers = remix[helper_start:helper_end]
        for evidence in (
            "CNDRemixAppliedAuditRecordHasValidPersistentStoreEvidence(record)",
            '@"bundleIdentifier"',
            '@"indexedIdentifier"',
            'isEqualToString:@"other"',
            'isEqualToString:@"themed"',
            "CNDRemixAppliedAuditRecordHasValidPersistentStoreEvidence(\n"
            "                        peer)",
            "caseInsensitiveCompare:peerExpectedHash",
            "caseInsensitiveCompare:storeHash",
            'record[@"storeState"] = @"themed-alias"',
            '@"storeAliasDescriptorIdentity"',
            '@"storeAliasExpectedThemedSHA256"',
        ):
            self.assertIn(evidence, helpers)

        audit_start = remix.index(
            "+ (NSDictionary<NSString *, id> *)auditAppliedIconState"
        )
        audit_end = remix.index("\n+ (BOOL)hasRecoveryData", audit_start)
        audit = remix[audit_start:audit_end]
        resolve = audit.index("CNDRemixResolveAppliedAuditStoreAliases(records)")
        proof = audit.index(
            "CNDRemixAppliedAuditRecordProvesThemedPersistence(record)"
        )
        self.assertLess(resolve, proof)
        self.assertIn('"aliased-store=%lu non-themed-store=%lu', audit)
        self.assertIn(
            '@"aliasedThemedStoreCount": @(aliasedThemedStoreCount)', audit
        )
        self.assertIn(
            'if ([storeState isEqualToString:@"themed"]) themedStoreCount++',
            audit,
        )
        self.assertNotIn(
            "CNDRemixAppliedAuditStoreStateIsThemed(record)) themedStoreCount++",
            audit,
        )

    def test_reinstall_stability_does_not_depend_on_process_cache_population(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        start = remix.index(
            "static NSDictionary *CNDRemixCompareAppliedAuditRecords("
        )
        end = remix.index(
            "\n+ (NSDictionary<NSString *, id> *)auditAppliedIconState", start
        )
        comparison = remix[start:end]
        unchanged_start = comparison.index(
            "else if (storeHashUnchanged && storeIdentifierUnchanged"
        )
        unchanged_end = comparison.index(
            'classification = @"unchanged";', unchanged_start
        )
        unchanged_condition = comparison[unchanged_start:unchanged_end]
        self.assertNotIn("cacheHashUnchanged", unchanged_condition)
        self.assertNotIn("cacheIdentifierUnchanged", unchanged_condition)
        self.assertIn("indexIdentifierUnchanged", unchanged_condition)
        self.assertIn("tokenUnchanged", unchanged_condition)
        self.assertIn("sourceIdentityUnchanged", unchanged_condition)
        self.assertIn(
            "else if (storeHashUnchanged && sourceIdentityUnchanged)",
            comparison,
        )

    def test_invalid_batch_lifecycle_is_rejected_by_facade(self) -> None:
        self.assertIn('stage": @"batch-already-open"', self.facade)
        self.assertIn('stage": @"batch-session"', self.facade)
        self.assertIn("CNDIconServicesPublisherBatchThreadKey", self.facade)
        self.assertIn("removeObjectForKey:CNDIconServicesPublisherBatchThreadKey", self.facade)

    def test_adapter_owns_legacy_dependencies_and_normalized_report(self) -> None:
        self.assertIn('#import "../TaskRop/RemoteCall.h"', self.adapter)
        self.assertIn('#import "../tweaks/remote_objc.h"', self.adapter)
        for field in (
            "transportHealthy",
            "transportLifecycleVerified",
            "batchTransportBorrowed",
            "transportRetained",
            "transportClosed",
            "transportAbandoned",
            "transportLocalStateRemaining",
            "payloadLifecycleVerified",
        ):
            self.assertIn(f'@"{field}"', self.adapter)
        self.assertIn(
            'report[@"acceptancePolicy"] = @"legacy-remote-call-provisional"',
            self.adapter,
        )
        self.assertIn(
            'report[@"legacyAcceptanceEligible"] = @(ok)', self.adapter
        )

    def test_publisher_scopes_quiet_returns_to_every_session_block(self) -> None:
        wrapper = "remote_call_with_session_suppressing_result_logs("
        self.assertEqual(self.adapter.count(wrapper), 7)
        self.assertNotIn("remote_call_with_session(", self.adapter)
        self.assertIn(wrapper, REMOTE_CALL_HEADER.read_text(encoding="utf-8"))

    def test_quiet_scope_restores_thread_local_policy_and_keeps_diagnostics(self) -> None:
        source = REMOTE_CALL.read_text(encoding="utf-8")
        result_policy = source.split(
            "static bool remote_call_should_log_result(", 1
        )[1].split("\nstatic void release_shmem_slot", 1)[0]
        self.assertLess(
            result_policy.index("remote_call_verbose_logging()"),
            result_policy.index("g_RC_suppressResultLogs"),
        )
        self.assertEqual(source.count("remote_call_should_log_result(name,"), 2)
        wrapper = source.split(
            "void remote_call_with_session_suppressing_result_logs(", 1
        )[1].split("\n}", 1)[0]
        self.assertIn("static __thread bool g_RC_suppressResultLogs;", source)
        self.assertIn("bool previous = g_RC_suppressResultLogs;", wrapper)
        self.assertIn("remote_call_with_session(session, block);", wrapper)
        self.assertIn("} @finally {\n        g_RC_suppressResultLogs = previous;", wrapper)
        for diagnostic in (
            "Don't receive first exception on original thread",
            "Don't receive second exception on original thread",
            "unexpected original-thread completion",
            "unexpected synthetic completion",
        ):
            self.assertIn(diagnostic, source)

    def test_remix_restores_explicit_legacy_acceptance_policy(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        self.assertIn("CNDRemixPublisherResultIsLegacyAcceptable", remix)
        self.assertIn('@"legacy-remote-call-provisional"', remix)
        self.assertIn('publication, @"replace"', remix)
        self.assertIn('restoration, @"stock"', remix)
        self.assertIn(
            "CNDIconServicesPublisherPublicationResultIsVerified(", remix
        )
        self.assertIn(
            "CNDIconServicesPublisherRestorationResultIsVerified(", remix
        )

    def test_remix_does_not_alias_distinct_point_geometry_by_raster(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        self.assertIn("CNDRemixStructuredPayloadIdentity", remix)
        helper_start = remix.index(
            "static NSString *CNDRemixStructuredPayloadIdentity("
        )
        helper_end = remix.index("\n}\n", helper_start)
        helper = remix[helper_start:helper_end]
        self.assertIn("specification.pointWidth", helper)
        self.assertIn("specification.pointHeight", helper)
        self.assertIn("specification.scale", helper)
        self.assertIn("CNDRemixRasterIdentity(specification)", helper)
        self.assertNotIn("structuredByRaster", remix)

    def test_recovery_required_skip_cannot_report_apply_success(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        start = remix.index("if (existing.count > 0)")
        end = remix.index("continue;", start)
        blocked = remix[start:end]
        self.assertIn("failed++;", blocked)
        self.assertIn("skipped++;", blocked)

    def test_remix_preserves_store_without_autostarting_presentation(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        self.assertNotIn("CNDRemixInvalidateBundleIdentifiers", remix)
        apply_tail_start = remix.index(
            "NSArray<NSString *> *presentationBundleIdentifiers ="
        )
        summary_start = remix.index("NSDictionary *summary = @{", apply_tail_start)
        apply_tail = remix[apply_tail_start:summary_start]
        self.assertNotIn("CNDIconServicesConsumerLifecycleStart", apply_tail)
        self.assertNotIn("RefreshSpringBoardCaches", apply_tail)
        self.assertNotIn("RequestSpringBoardCacheRefresh", apply_tail)
        self.assertIn("CNDRemixRunInitialCacheRefresh()", apply_tail)
        self.assertNotIn("CNDIconServicesConsumerLifecycleSetStaticDynamicIconData", apply_tail)
        self.assertIn('presentationAutoStart', remix)
        self.assertIn('@"cacheInvalidationIssued": @NO', remix)
        self.assertIn('@"iconServicesStorePreserved": @YES', remix)
        self.assertIn("CNDRemixStorePreservationPolicyVersion", remix)
        self.assertIn('@"legacy-store-invalidation-recovery"', remix)
        self.assertIn("CNDRemixIconServicesWakeIdentifier", remix)
        self.assertNotIn(
            "CNDIconServicesPublisherBeginBatch(wakeIdentifier)", remix
        )

    def test_static_clock_calendar_data_tracks_manual_repair_and_restore_direction(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        self.assertIn("CNDRemixStaticDynamicIconDataFromThemeLookup(", remix)
        self.assertNotIn('@"__cnd_calendar_background"', remix)
        self.assertIn(
            'result[@"com.apple.mobilecal"] =\n'
            '            themeLookup[@"com.apple.mobilecal"]',
            remix,
        )
        self.assertIn(
            "CNDRemixActiveCalendar68StructuredResponse(0)", remix
        )
        self.assertIn(
            "CNDRemixActiveCalendar68StructuredResponse(1)", remix
        )
        self.assertIn(
            'result[@"__cnd_calendar_68_structured"] =',
            remix,
        )
        self.assertIn(
            'result[@"__cnd_calendar_68_structured_a1"] =',
            remix,
        )
        lifecycle = (
            INSTALLER / "CNDIconServicesConsumerLifecycleCoordinator.m"
        ).read_text(encoding="utf-8")
        self.assertIn('@"__cnd_calendar_68_structured"', lifecycle)
        self.assertIn('@"__cnd_calendar_68_structured_a1"', lifecycle)
        self.assertIn("exact Calendar provider bridge", remix)
        self.assertIn("llround(68.0 * scale)", remix)
        self.assertIn("CNDProcessIconThemePNG(", remix)
        self.assertIn(
            "CNDIconServicesConsumerLifecycleSetStaticDynamicIconData(",
            remix,
        )
        self.assertIn(
            "themeLookup, active", remix
        )
        self.assertIn("SetStaticDynamicIconData(@{});", remix)
        reconcile_start = remix.index(
            "CNDRemixReconcilePresentationLifecycle(void)"
        )
        reconcile_end = remix.index(
            "static NSURL *CNDRemixIndexURL(void)",
            reconcile_start,
        )
        reconcile = remix[reconcile_start:reconcile_end]
        self.assertNotIn("settings_sbl_selected_theme_data", reconcile)
        self.assertNotIn(
            "CNDIconServicesConsumerLifecycleSetStaticDynamicIconData",
            reconcile,
        )
        self.assertNotIn("systemUptime + 60.0", reconcile)
        self.assertNotIn("usleep(50000)", reconcile)
        self.assertNotIn("CNDIconServicesConsumerLifecycleStart", reconcile)
        self.assertNotIn("RequestSpringBoardCacheRefresh", remix)

    def test_clock_face_source_is_isolated_from_global_transition_records(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        profile_start = remix.index(
            "CNDRemixDescriptorSpecificationsForBundleIdentifier("
        )
        profile_end = remix.index(
            "static NSString *CNDRemixDescriptorProfileIdentity(",
            profile_start,
        )
        profile = remix[profile_start:profile_end]
        self.assertIn(
            "specsForIPhoneIOS26At3xIncludingSnippetExtras", profile
        )
        self.assertNotIn("com.apple.mobiletimer", profile)
        self.assertNotIn("CNDRemixDescriptorUsesClockFace(", remix)
        self.assertNotIn("CNDRemixMatrixSourceHash(", remix)
        self.assertNotIn('@"clock-matrix-v1\\nordinary=%@\\nface=%@\\n"', remix)
        self.assertIn("NSData *variantSource = source;", remix)
        self.assertIn("NSString *sourceHash = CNDRemixSHA256(source);", remix)
        self.assertIn(
            "separate com.apple.application-icon.clock.base graphic", remix
        )
        self.assertIn(
            "consumes __cnd_clock_background independently", remix
        )
        self.assertIn('result[@"__cnd_clock_background"] = scaledPNG;', remix)

    def test_descriptor_profile_expansion_publishes_only_missing_records(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        helper_start = remix.index(
            "static BOOL CNDRemixJournalIsExpandableActiveMatrixSubset("
        )
        helper_end = remix.index(
            "\nstatic BOOL CNDRemixJournalMatchesCurrentApplication(",
            helper_start,
        )
        helper = remix[helper_start:helper_end]
        self.assertIn('isEqualToString:@"active"', helper)
        self.assertIn("variants.count >= specifications.count", helper)
        self.assertIn("![requested containsObject:identity]", helper)
        self.assertIn("[active containsObject:identity]", helper)

        apply_start = remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixApplyIconServicesTheme("
        )
        apply_end = remix.index(
            "\nstatic NSDictionary<NSString *, id> *\nCNDRemixRestoreSpringBoardPresentationIfNeeded(",
            apply_start,
        )
        apply = remix[apply_start:apply_end]
        self.assertIn("needsProfileExpansion", apply)
        self.assertIn("publicationSpecifications = missing;", apply)
        self.assertIn('preparedTarget[@"profileExpansionJournal"] = existing;', apply)
        self.assertIn("CNDRemixJournalVariants(\n                                profileExpansionJournal)", apply)
        self.assertIn("NSUInteger newVariantOffset = journalVariants.count;", apply)
        self.assertIn("newVariantOffset + variantIndex", apply)
        self.assertIn("} else if (needsProfileExpansion) {", apply)

    def test_restore_clears_each_verified_persistent_journal_before_finish(self) -> None:
        remix = REMIX.read_text(encoding="utf-8")
        start = remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals("
        )
        end = remix.index("\n@implementation CNDSnowBoardRemix", start)
        restore = remix[start:end]
        clear = restore.index("BOOL journalCleared = appVerified &&")
        finish = restore.index("CNDIconServicesPublisherFinishBatch()")
        self.assertLess(clear, finish)
        self.assertIn('appVerified &&', restore)
        self.assertIn('@"persistentDataVerified": @(appVerified)', restore)
        self.assertIn('@"persistentRestoreCommittedBeforeBatchFinalization": @YES', restore)
        self.assertNotIn("springBoardCacheRefresh", restore)

    def test_vm_descriptor_setup_retains_typed_payload(self) -> None:
        header = PAYLOAD_HEADER.read_text(encoding="utf-8")
        source = PAYLOAD_SOURCE.read_text(encoding="utf-8")
        assembly = PAYLOAD_ASSEMBLY.read_text(encoding="utf-8")
        self.assertIn("CND_ICON_PUBLISHER_PAYLOAD_VERSION 15ULL", header)
        self.assertIn("descriptorPreparationBits", header)
        self.assertIn("cnd_icon_publisher_payload_prepare_descriptor", assembly)
        self.assertIn(
            "cnd_icon_publisher_payload_prepare_descriptor_body", source
        )
        self.assertIn(
            '"cnd_icon_publisher_payload_prepare_descriptor"', self.adapter
        )
        self.assertIn("descriptorPreparedInPayload", self.adapter)

    def test_arm64e_payload_entries_call_c_bodies_with_normal_link_registers(self) -> None:
        assembly = PAYLOAD_ASSEMBLY.read_text(encoding="utf-8")
        bodies = (
            "probe",
            "prepare_descriptor",
            "install",
            "generate",
            "trigger",
            "execute",
            "cleanup",
        )
        for name in bodies:
            label = f"_cnd_icon_publisher_payload_{name}:"
            start = assembly.index(label)
            next_global = assembly.find("\n.globl ", start + len(label))
            block = assembly[start : next_global if next_global >= 0 else None]
            self.assertIn("bti c", block)
            self.assertIn("stp x29, x30", block)
            self.assertIn(f"bl _cnd_icon_publisher_payload_{name}_body", block)
            self.assertIn("ldp x29, x30", block)
            self.assertIn("\n    ret", block)
            self.assertNotIn(f"\n    b _cnd_icon_publisher_payload_{name}_body", block)

    def test_physical_path_uses_only_stock_iconservices_store_calls(self) -> None:
        self.assertIn("cnd_publisher_run_stock_store(", self.adapter)
        self.assertIn("if (!remote_call_lab_backend_opted_in())", self.adapter)
        self.assertIn(
            "return cnd_publisher_run_stock_store(\n"
            "            bundleIdentifier, structuredImageData, specification);",
            self.adapter,
        )
        direct_start = self.adapter.index(
            "cnd_publisher_run_stock_store(NSString *bundleIdentifier"
        )
        legacy_start = self.adapter.index(
            "cnd_publisher_run(NSString *bundleIdentifier", direct_start
        )
        direct = self.adapter[direct_start:legacy_start]
        self.assertIn('"generateImageWithDescriptor:"', direct)
        self.assertIn('"writeStoreUnit:"', direct)
        self.assertIn('"unitForUUID:"', direct)
        self.assertIn('"removeUnitForUUID:"', direct)
        self.assertIn('"setImage:forDescriptor:"', direct)
        self.assertIn('@"customExecutablePayloadUsed": @NO', direct)
        self.assertIn('@"methodInterpositionUsed": @NO', direct)
        self.assertNotIn("do_remote_call_stable_addr(", direct)
        self.assertNotIn("method_setImplementation", direct)
        self.assertNotIn('r_msg2(stockUUID, "UUIDString"', direct)
        self.assertIn(
            "cnd_publisher_audit_copy_indexed_identifier(\n"
            "                    stockUUID, persistentIndexScratch)", direct
        )
        self.assertNotIn('@"opaque-indexed-identifier"', direct)
        self.assertLess(
            direct.index("directStoreRemoveIssued = YES"),
            direct.index("directStoreWriteIssued = YES"),
        )
        for field in (
            "directStoreRemoveVerified",
            "immediateStoreRollbackAttempted",
            "immediateStoreRollbackSucceeded",
            "stockGenerationInitiallyPersisted",
        ):
            self.assertIn(f'@"{field}"', direct)

        remove = direct.index("directStoreRemoveIssued = YES")
        write = direct.index("directStoreWriteIssued = YES")
        self.assertLess(remove, write)
        self.assertNotIn("directStoreWriteSkippedAlreadyStock", direct)
        self.assertIn("directStoreWriteIssued &&", direct)
        self.assertIn('@"copiedToHost": @YES', direct)
        self.assertIn('@"generated-stock-response"', direct)

        descriptor_start = self.adapter.index(
            "cnd_publisher_stock_descriptor("
        )
        descriptor = self.adapter[descriptor_start:direct_start]
        self.assertIn("r_msg2_raw(", descriptor)
        self.assertIn("r_msg2_struct_ret(", descriptor)
        self.assertNotIn("r_msg2_main_raw(", descriptor)
        self.assertNotIn("r_msg2_main_struct_ret(", descriptor)

    def test_remotecall_bootstrap_worker_uses_one_second_window(self) -> None:
        source = REMOTE_CALL.read_text(encoding="utf-8")
        self.assertIn("uint64_t bootstrapArgument = 1000000;", source)
        self.assertNotIn("uint64_t bootstrapArgument = 8000000;", source)

    def test_physical_descriptor_factory_matches_ios26_binary_abi(self) -> None:
        direct_start = self.adapter.index(
            "cnd_publisher_run_stock_store(NSString *bundleIdentifier"
        )
        descriptor_start = self.adapter.index(
            "cnd_publisher_stock_descriptor("
        )
        descriptor = self.adapter[descriptor_start:direct_start]
        self.assertIn('"@24@0:8i16i20"', descriptor)
        self.assertNotIn('"@32@0:8Q16Q24"', descriptor)
        self.assertNotIn('"@32@0:8q16Q24"', descriptor)
        for encoding in (
            '"v32@0:8{CGSize=dd}16"',
            '"v24@0:8d16"',
            '"v24@0:8q16"',
            '"v24@0:8Q16"',
            '"v20@0:8B16"',
            '"{CGSize=dd}16@0:8"',
            '"d16@0:8"',
            '"q16@0:8"',
            '"Q16@0:8"',
            '"B16@0:8"',
        ):
            self.assertIn(encoding, descriptor)
        self.assertIn("uint64_t requestedIconVariant", descriptor)
        self.assertIn("int32_t descriptorPreset = 0", descriptor)
        self.assertIn("int32_t requestedOptions", descriptor)
        self.assertIn('"setVariantOptions:"', descriptor)
        self.assertIn('"variantOptions"', descriptor)
        self.assertIn(
            "observedIconVariant == requestedIconVariant", descriptor
        )
        self.assertIn("r_msg2_raw(\n        descriptorClass", descriptor)

        payload = PAYLOAD_SOURCE.read_text(encoding="utf-8")
        self.assertIn("CNDMessageObjectInt2", payload)
        self.assertIn("CNDMessageVoidInt641", payload)
        self.assertIn("CNDMessageVoidBool1", payload)
        self.assertIn("context->selSetVariantOptions", payload)
        self.assertIn(
            "int640(descriptor, context->selVariantOptions)", payload
        )

    def test_vm_payload_mapping_remains_lab_only_and_prefaults_data(self) -> None:
        self.assertIn(
            "cnd_publisher_prefault_remote_write_range(", self.adapter
        )
        staging_prefault = self.adapter.index(
            "cnd_publisher_prefault_remote_write_range(\n"
            "                        stagingRemoteBase, stagingTransfer.length)"
        )
        staging_write = self.adapter.index(
            "remote_write(stagingRemoteBase,", staging_prefault
        )
        self.assertLess(staging_prefault, staging_write)
        self.assertIn("cnd_publisher_map_physical_payload(", self.adapter)
        self.assertIn("cnd_publisher_resolve_payload_vnode(", self.adapter)
        self.assertIn('"__cndpub"', self.adapter)
        self.assertIn('"open", remotePath', self.adapter)
        self.assertIn("MAP_PRIVATE | MAP_FIXED", self.adapter)
        self.assertIn("payloadFileOffset", self.adapter)
        self.assertNotIn("remapExecutableFromLocalAddress:", self.adapter)
        self.assertNotIn("CNDKernelTaskBridge", self.adapter)
        self.assertIn("if (remote_call_uses_lab_backend())", self.adapter)
        self.assertIn('publisher-payload-lab-mmap', self.adapter)
        self.assertNotIn('publisher-payload-mmap', self.adapter)


if __name__ == "__main__":
    unittest.main()
